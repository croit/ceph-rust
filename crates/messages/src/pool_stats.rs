// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Pool statistics pinned wire and public counter mapping, RC180.
use crate::msg::{end, get_psm, put_psm};
use crate::{Message, Segments, StoreStatfs, meta};
use denc::types::Uuid;
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error, Result};
use std::collections::BTreeMap;
/// Checked wire-front accounting. Counts describe occurrences, not unique names.
fn front_len(
    fixed: usize,
    count: usize,
    entries: impl IntoIterator<Item = Result<(usize, usize)>>,
) -> Result<usize> {
    u32::try_from(count).map_err(|_| Error::TooLong)?;
    let minimum = count
        .checked_mul(4)
        .and_then(|n| n.checked_add(fixed))
        .ok_or(Error::TooLong)?;
    u32::try_from(minimum).map_err(|_| Error::TooLong)?;
    let mut total = fixed;
    let mut seen = 0usize;
    for entry in entries {
        let (name, stat) = entry?;
        u32::try_from(name).map_err(|_| Error::TooLong)?;
        u32::try_from(stat).map_err(|_| Error::TooLong)?;
        total = total
            .checked_add(4)
            .and_then(|n| n.checked_add(name))
            .and_then(|n| n.checked_add(stat))
            .ok_or(Error::TooLong)?;
        u32::try_from(total).map_err(|_| Error::TooLong)?;
        seen = seen.checked_add(1).ok_or(Error::TooLong)?;
    }
    if seen != count {
        return Err(Error::BadValue("pool statistics count mismatch"));
    }
    Ok(total)
}
fn front_encoder(bytes: usize, features: u64) -> Result<Encoder> {
    let mut front = Vec::new();
    front.try_reserve_exact(bytes).map_err(|_| Error::NoSpace)?;
    Ok(Encoder::from_buf(front).with_features(features))
}
/// Sizing sink for the actual feature-selected stat encoder; patching does not
/// change the byte count. No guessed per-entry stat size or temporary payload.
struct EncodedSize(usize);
impl BufMut for EncodedSize {
    fn len(&self) -> usize {
        self.0
    }
    fn put_slice(&mut self, bytes: &[u8]) -> Result<()> {
        self.0 = self.0.checked_add(bytes.len()).ok_or(Error::TooLong)?;
        u32::try_from(self.0).map_err(|_| Error::TooLong)?;
        Ok(())
    }
    fn patch(&mut self, pos: usize, bytes: &[u8]) {
        debug_assert!(
            pos.checked_add(bytes.len())
                .is_some_and(|end| end <= self.0)
        );
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStatistics {
    pub num_bytes: u64,
    pub num_kb: u64,
    pub num_objects: u64,
    pub num_object_clones: u64,
    pub num_object_copies: u64,
    pub num_objects_missing_on_primary: u64,
    pub num_objects_unfound: u64,
    pub num_objects_degraded: u64,
    pub num_rd: u64,
    pub num_rd_kb: u64,
    pub num_wr: u64,
    pub num_wr_kb: u64,
    pub num_user_bytes: u64,
    pub compressed_bytes_orig: u64,
    pub compressed_bytes: u64,
    pub compressed_bytes_alloc: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawPoolStatistics {
    pub counters: [i64; 40],
    pub log_size: i64,
    pub ondisk_log_size: i64,
    pub up: i32,
    pub acting: i32,
    pub store: StoreStatfs,
    pub num_store_stats: i32,
}
impl Default for RawPoolStatistics {
    fn default() -> Self {
        Self {
            counters: [0; 40],
            log_size: 0,
            ondisk_log_size: 0,
            up: 0,
            acting: 0,
            store: StoreStatfs::default(),
            num_store_stats: 0,
        }
    }
}
impl RawPoolStatistics {
    /// Size of this value under the actual negotiated encoder features.
    pub fn encoded_len(&self, features: u64) -> Result<usize> {
        let mut encoder = Encoder::from_buf(EncodedSize(0)).with_features(features);
        self.encode(&mut encoder)?;
        Ok(encoder.len())
    }
    pub fn public(&self, per_pool: bool) -> PoolStatistics {
        let s = &self.counters;
        let legacy = (s[0] as u64)
            .wrapping_add(s[22] as u64)
            .wrapping_add(s[37] as u64);
        let bytes = if per_pool {
            (self.store.allocated as u64).wrapping_add(self.store.omap_allocated as u64)
        } else {
            legacy
        };
        let user = if per_pool {
            // exact integer sum: librados divides by a float raw_used_rate (1.0) and loses the low bits at
            // >= 16 MiB; adr 0256 allows the exact value (application-compatible, no reference-bug parity)
            (self.store.data_stored as u64).wrapping_add(self.store.omap_allocated as u64)
        } else {
            legacy
        };
        PoolStatistics {
            num_bytes: bytes,
            num_kb: (bytes >> 10) + u64::from(bytes & 1023 != 0),
            num_objects: s[1] as u64,
            num_object_clones: s[2] as u64,
            num_object_copies: s[3] as u64,
            num_objects_missing_on_primary: s[4] as u64,
            num_objects_unfound: s[6] as u64,
            num_objects_degraded: (s[5] as u64).wrapping_add(s[21] as u64),
            num_rd: s[7] as u64,
            num_rd_kb: s[8] as u64,
            num_wr: s[9] as u64,
            num_wr_kb: s[10] as u64,
            num_user_bytes: user,
            compressed_bytes_orig: self.store.data_compressed_original as u64,
            compressed_bytes: self.store.data_compressed as u64,
            compressed_bytes_alloc: self.store.data_compressed_allocated as u64,
        }
    }
}
impl Encode for RawPoolStatistics {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(7, 5, |e| {
            e.versioned(2, 2, |e| {
                e.versioned(20, 14, |e| {
                    for (index, c) in self.counters.into_iter().enumerate() {
                        if (28..32).contains(&index) {
                            e.i32(
                                i32::try_from(c).map_err(|_| {
                                    Error::BadValue("pool statistics narrow counter")
                                })?,
                            )?;
                        } else {
                            e.i64(c)?;
                        }
                    }
                    Ok(())
                })?;
                e.u32(0)
            })?;
            e.i64(self.log_size)?;
            e.i64(self.ondisk_log_size)?;
            e.i32(self.up)?;
            e.i32(self.acting)?;
            self.store.encode(e)?;
            e.i32(self.num_store_stats)
        })
    }
}
impl<'a> Decode<'a> for RawPoolStatistics {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(7, 7, |d, v| {
            if v != 7 {
                return Err(Error::BadValue("pool statistics envelope"));
            }
            let counters = d.versioned_min(2, 2, |d, v| {
                if v != 2 {
                    return Err(Error::BadValue("object statistics collection"));
                }
                let counters = d.versioned_min(20, 20, |d, v| {
                    if v != 20 {
                        return Err(Error::BadValue("object statistics sum"));
                    }
                    let mut counters = [0; 40];
                    for (index, c) in counters.iter_mut().enumerate() {
                        *c = if (28..32).contains(&index) {
                            i64::from(d.i32()?)
                        } else {
                            d.i64()?
                        };
                    }
                    end(d)?;
                    Ok(counters)
                })?;
                if d.u32()? != 0 {
                    return Err(Error::BadValue("pinned statistics categories"));
                }
                end(d)?;
                Ok(counters)
            })?;
            let value = Self {
                counters,
                log_size: d.i64()?,
                ondisk_log_size: d.i64()?,
                up: d.i32()?,
                acting: d.i32()?,
                store: StoreStatfs::decode(d)?,
                num_store_stats: d.i32()?,
            };
            end(d)?;
            Ok(value)
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MGetPoolStats {
    pub version: u64,
    pub fsid: Uuid,
    pub pools: Vec<Vec<u8>>,
}
impl MGetPoolStats {
    /// Lossless request-front size, including all duplicate name occurrences.
    /// Metadata only; selecting the u32 domain never reserves maximum memory.
    pub fn front_len(count: usize, names: impl IntoIterator<Item = usize>) -> Result<usize> {
        front_len(38, count, names.into_iter().map(|name| Ok((name, 0))))
    }
}
fn check(version: u16, max: u16, middle: &[u8], data: &[u8]) -> Result<()> {
    if version == 0 || version > max || !middle.is_empty() || !data.is_empty() {
        return Err(Error::BadValue("pool statistics message framing"));
    }
    Ok(())
}
fn name(d: &mut Decoder<'_>) -> Result<Vec<u8>> {
    let name = d.bytes()?;
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(name.len())
        .map_err(|_| Error::NoSpace)?;
    owned.extend_from_slice(name);
    Ok(owned)
}
impl Message for MGetPoolStats {
    meta!(58,1,0,oldest 1);
    fn encode(&self, features: u64) -> Result<Segments> {
        let bytes = Self::front_len(self.pools.len(), self.pools.iter().map(Vec::len))?;
        let mut e = front_encoder(bytes, features)?;
        put_psm(&mut e, self.version)?;
        self.fsid.encode(&mut e)?;
        self.pools.encode(&mut e)?;
        Ok(Segments::front(e.into_vec()))
    }
    fn decode(v: u16, front: &[u8], middle: &[u8], data: &[u8]) -> Result<Self> {
        check(v, 1, middle, data)?;
        u32::try_from(front.len()).map_err(|_| Error::TooLong)?;
        let mut d = Decoder::new(front);
        let version = get_psm(&mut d)?;
        let fsid = Uuid::decode(&mut d)?;
        let count = d.u32()? as usize;
        if count > d.remaining() / 4 {
            return Err(Error::BadValue(
                "pool statistics count exceeds remaining front",
            ));
        }
        let mut pools = Vec::new();
        // A bounded first reservation: the declared count is attacker-chosen (an empty name costs 4 wire bytes but 24
        // bytes of Vec<u8>), so never reserve `count` elements up front. The accepted count stays unbounded (RC180);
        // growth is amortized as the names actually arrive.
        pools
            .try_reserve_exact(count.min(4096))
            .map_err(|_| Error::NoSpace)?;
        for _ in 0..count {
            pools.push(name(&mut d)?);
        }
        end(&d)?;
        Ok(Self {
            version,
            fsid,
            pools,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MGetPoolStatsReply {
    pub version: u64,
    pub fsid: Uuid,
    pub pools: BTreeMap<Vec<u8>, RawPoolStatistics>,
    pub per_pool: bool,
}
impl Message for MGetPoolStatsReply {
    meta!(59,2,1,oldest 1);
    fn encode(&self, features: u64) -> Result<Segments> {
        let bytes = front_len(
            39,
            self.pools.len(),
            self.pools
                .iter()
                .map(|(name, stat)| stat.encoded_len(features).map(|bytes| (name.len(), bytes))),
        )?;
        let mut e = front_encoder(bytes, features)?;
        put_psm(&mut e, self.version)?;
        self.fsid.encode(&mut e)?;
        self.pools.encode(&mut e)?;
        e.u8(u8::from(self.per_pool))?;
        Ok(Segments::front(e.into_vec()))
    }
    fn decode(v: u16, front: &[u8], middle: &[u8], data: &[u8]) -> Result<Self> {
        check(v, 2, middle, data)?;
        u32::try_from(front.len()).map_err(|_| Error::TooLong)?;
        let mut d = Decoder::new(front);
        let version = get_psm(&mut d)?;
        let fsid = Uuid::decode(&mut d)?;
        let count = d.u32()? as usize;
        // Every entry needs a name prefix and at least the outer stat ENV.
        // Decode the actual nested stats below; v2 also reserves its flag byte.
        let remaining = d
            .remaining()
            .checked_sub(usize::from(v >= 2))
            .ok_or(Error::Eof {
                needed: 1,
                remaining: 0,
            })?;
        if count > remaining / (4 + 6) {
            return Err(Error::BadValue(
                "pool statistics count exceeds remaining front",
            ));
        }
        let mut pools = BTreeMap::new();
        for _ in 0..count {
            let key = name(&mut d)?;
            let value = RawPoolStatistics::decode(&mut d)?;
            if pools.insert(key, value).is_some() {
                return Err(Error::BadValue("duplicate pool statistics"));
            }
        }
        let per_pool = if v == 1 {
            false
        } else {
            match d.u8()? {
                0 => false,
                1 => true,
                tag => return Err(Error::BadMarker(tag)),
            }
        };
        end(&d)?;
        Ok(Self {
            version,
            fsid,
            pools,
            per_pool,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compatible_wire_collections_exceed_former_limits_and_preserve_occurrences() {
        let mut names = vec![vec![]; 4097];
        names.extend([vec![255; 4097], b"unknown".to_vec(), b"unknown".to_vec()]);
        let request = MGetPoolStats {
            version: 19,
            fsid: Uuid([7; 16]),
            pools: names.clone(),
        };
        let encoded = request.encode(0).unwrap();
        assert_eq!(
            encoded.front.len(),
            38 + names.iter().map(|n| 4 + n.len()).sum::<usize>()
        );
        assert_eq!(
            MGetPoolStats::decode(1, &encoded.front, &[], &[]).unwrap(),
            request
        );
        let empty = MGetPoolStats {
            pools: vec![],
            ..request
        };
        assert_eq!(empty.encode(0).unwrap().front.len(), 38);
        assert!(
            MGetPoolStats::decode(1, &empty.encode(0).unwrap().front, &[], &[])
                .unwrap()
                .pools
                .is_empty()
        );

        let mut pools = BTreeMap::new();
        for index in 0..4097u32 {
            pools.insert(index.to_le_bytes().to_vec(), RawPoolStatistics::default());
        }
        pools.insert(vec![0xff; 4097], RawPoolStatistics::default());
        let reply = MGetPoolStatsReply {
            version: 20,
            fsid: Uuid([7; 16]),
            pools,
            per_pool: true,
        };
        for features in [0, u64::MAX] {
            let encoded = reply.encode(features).unwrap();
            let actual = reply
                .pools
                .iter()
                .map(|(name, raw)| {
                    let mut stat = Encoder::new().with_features(features);
                    raw.encode(&mut stat).map(|()| (name.len(), stat.len()))
                })
                .collect::<Result<Vec<_>>>()
                .unwrap();
            assert_eq!(
                encoded.front.len(),
                39 + actual
                    .iter()
                    .map(|(name, stat)| 4 + name + stat)
                    .sum::<usize>()
            );
            assert_eq!(
                MGetPoolStatsReply::decode(2, &encoded.front, &[], &[]).unwrap(),
                reply
            );
            let legacy =
                MGetPoolStatsReply::decode(1, &encoded.front[..encoded.front.len() - 1], &[], &[])
                    .unwrap();
            assert!(!legacy.per_pool);
            assert_eq!(legacy.pools, reply.pools);
        }
    }
    #[test]
    fn front_bounds_are_metadata_only_and_include_actual_stat_bytes() {
        let max = u32::MAX as usize;
        assert_eq!(MGetPoolStats::front_len(1, [max - 42]), Ok(max));
        assert_eq!(MGetPoolStats::front_len(1, [max - 41]), Err(Error::TooLong));
        assert_eq!(
            MGetPoolStats::front_len((max - 38) / 4 + 1, []),
            Err(Error::TooLong)
        );
        assert_eq!(
            MGetPoolStats::front_len(usize::MAX, []),
            Err(Error::TooLong)
        );
        assert_eq!(
            MGetPoolStats::front_len(1, [usize::MAX]),
            Err(Error::TooLong)
        );
        assert_eq!(
            MGetPoolStats::front_len(2, [max / 2, max / 2]),
            Err(Error::TooLong)
        );
        assert!(MGetPoolStats::front_len(2, [0]).is_err());
        let raw = RawPoolStatistics::default();
        let stat = raw.encoded_len(0).unwrap();
        assert_eq!(stat, denc::to_vec(&raw).unwrap().len());
        assert_eq!(front_len(39, 1, [Ok((max - 43 - stat, stat))]), Ok(max));
        assert_eq!(
            front_len(39, 1, [Ok((max - 42 - stat, stat))]),
            Err(Error::TooLong)
        );
        assert_eq!(front_len(39, 1, [Ok((0, usize::MAX))]), Err(Error::TooLong));
        // A declared count cannot cause a large reserve without bytes for even
        // its prefixes/envelopes. No fictitious multi-GiB front is constructed.
        let mut request = MGetPoolStats {
            version: 0,
            fsid: Uuid([7; 16]),
            pools: vec![],
        }
        .encode(0)
        .unwrap()
        .front;
        request[34..38].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(MGetPoolStats::decode(1, &request, &[], &[]).is_err());
        request.push(0);
        assert!(MGetPoolStatsReply::decode(2, &request, &[], &[]).is_err());
    }
    fn envelope(v: u8, c: u8, body: Vec<u8>) -> Vec<u8> {
        let mut out = vec![v, c];
        out.extend((body.len() as u32).to_le_bytes());
        out.extend(body);
        out
    }
    fn raw_vector() -> Vec<u8> {
        let mut sum = Vec::new();
        for index in 0..40 {
            let n = 100 + index as i64;
            if (28..32).contains(&index) {
                sum.extend((n as i32).to_le_bytes());
            } else {
                sum.extend(n.to_le_bytes());
            }
        }
        assert_eq!(sum.len(), 304);
        let mut collection = envelope(20, 14, sum);
        collection.extend(0u32.to_le_bytes());
        let mut body = envelope(2, 2, collection);
        for n in [17i64, 19] {
            body.extend(n.to_le_bytes());
        }
        for n in [3i32, 3] {
            body.extend(n.to_le_bytes());
        }
        let mut store = Vec::new();
        for n in 1000..1010u64 {
            store.extend(n.to_le_bytes());
        }
        body.extend(envelope(1, 1, store));
        body.extend(3i32.to_le_bytes());
        envelope(7, 5, body)
    }
    #[test]
    fn independent_nested_vector_decodes_and_encodes_exactly() {
        let bytes = raw_vector();
        assert_eq!(bytes.len(), 440);
        let raw = denc::from_slice::<RawPoolStatistics>(&bytes).unwrap();
        assert_eq!(raw.counters[0], 100);
        assert_eq!(raw.counters[39], 139);
        assert_eq!(raw.up, 3);
        assert_eq!(raw.log_size, 17);
        assert_eq!(raw.store.data_stored, 1004);
        assert_eq!(raw.store.omap_allocated, 1008);
        assert_eq!(denc::to_vec(&raw).unwrap(), bytes);
        for n in 0..bytes.len() {
            assert!(denc::from_slice::<RawPoolStatistics>(&bytes[..n]).is_err());
        }
        let mut bad = bytes;
        bad[12] = 19;
        assert!(denc::from_slice::<RawPoolStatistics>(&bad).is_err());
    }
    #[test]
    fn narrow_control_counters_are_signed32_and_reject_overflow() {
        let mut raw = RawPoolStatistics::default();
        raw.counters[28] = i64::from(i32::MIN);
        raw.counters[31] = i64::from(i32::MAX);
        let bytes = denc::to_vec(&raw).unwrap();
        assert_eq!(bytes.len(), 440);
        assert_eq!(denc::from_slice::<RawPoolStatistics>(&bytes).unwrap(), raw);
        raw.counters[28] = i64::from(i32::MAX) + 1;
        assert!(denc::to_vec(&raw).is_err());
    }
    #[test]
    fn request_reply_full_headers_framing_legacy_and_bounds() {
        let mut prefix = vec![9, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0];
        prefix.extend([7; 16]);
        let mut request = prefix.clone();
        request.extend([1, 0, 0, 0, 1, 0, 0, 0, 255]);
        let req = MGetPoolStats {
            version: 9,
            fsid: Uuid([7; 16]),
            pools: vec![vec![255]],
        };
        assert_eq!(req.encode(0).unwrap().front, request);
        assert_eq!(
            crate::decode_with_header(&crate::Header2::new(19, 58, 1, 0), &request, &[], &[])
                .unwrap(),
            req.into()
        );
        let mut front = prefix;
        front.extend([1, 0, 0, 0, 1, 0, 0, 0, 255]);
        front.extend(raw_vector());
        let legacy = front.clone();
        front.push(1);
        let reply = MGetPoolStatsReply::decode(2, &front, &[], &[]).unwrap();
        assert!(reply.per_pool);
        assert_eq!(reply.pools.len(), 1);
        assert_eq!(reply.encode(0).unwrap().front, front);
        assert_eq!(
            crate::decode_with_header(&crate::Header2::new(19, 59, 2, 1), &front, &[], &[])
                .unwrap(),
            reply.into()
        );
        assert!(
            !MGetPoolStatsReply::decode(1, &legacy, &[], &[])
                .unwrap()
                .per_pool
        );
        for n in 0..front.len() {
            assert!(MGetPoolStatsReply::decode(2, &front[..n], &[], &[]).is_err());
        }
        assert!(MGetPoolStatsReply::decode(2, &front, &[0], &[]).is_err());
        *front.last_mut().unwrap() = 2;
        assert!(MGetPoolStatsReply::decode(2, &front, &[], &[]).is_err());
        request[34..38].copy_from_slice(&4097u32.to_le_bytes());
        assert!(MGetPoolStats::decode(1, &request, &[], &[]).is_err());
    }
    #[test]
    fn public_counters_use_store_flag_legacy_omap_and_pinned_rounding() {
        let mut raw = RawPoolStatistics::default();
        for (i, v) in [
            (0, 1011),
            (1, 7),
            (2, 2),
            (3, 21),
            (4, 1),
            (5, 3),
            (6, 2),
            (7, 8),
            (8, 9),
            (9, 10),
            (10, 11),
            (21, 4),
            (22, 21),
            (37, 7),
        ] {
            raw.counters[i] = v;
        }
        raw.store = StoreStatfs {
            allocated: 4096,
            data_stored: 16_777_217,
            omap_allocated: 5,
            data_compressed_original: 10000,
            data_compressed: 5000,
            data_compressed_allocated: 8192,
            ..Default::default()
        };
        let legacy = raw.public(false);
        let store = raw.public(true);
        assert_eq!(
            (legacy.num_bytes, legacy.num_kb, legacy.num_user_bytes),
            (1039, 2, 1039)
        );
        assert_eq!(
            (store.num_bytes, store.num_kb, store.num_user_bytes),
            (4101, 5, 16_777_222)
        );
        assert_eq!(store.num_objects_degraded, 7);
        assert_eq!(store.num_objects_unfound, 2);
        assert_eq!(
            (store.num_rd, store.num_rd_kb, store.num_wr, store.num_wr_kb),
            (8, 9, 10, 11)
        );
        assert_eq!(
            (
                store.compressed_bytes_orig,
                store.compressed_bytes,
                store.compressed_bytes_alloc
            ),
            (10000, 5000, 8192)
        );
        raw.counters[0] = -1;
        raw.counters[22] = 0;
        raw.counters[37] = 0;
        assert_eq!(raw.public(false).num_kb, (u64::MAX >> 10) + 1);
    }
}
