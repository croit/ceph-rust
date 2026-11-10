// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Scrub messages and ScrubMap (spec scrub.md 1, 2) plus the digest helpers shared by every store
//! implementation (spec 3.3, 3.4).

use denc::types::{Eversion, Hobject, PgShard, PgT, ShardId, SpgT};
use denc::{Decode, Decoder, Encode, Encoder, Result};
use messages::{Message, Segments, front_with as front, meta};
use std::collections::BTreeMap;

/// Message type ids.
pub mod ty {
    pub const SCRUB_RESERVE: u16 = 92;
    pub const REP_SCRUB: u16 = 93;
    pub const REP_SCRUB_MAP: u16 = 117;
    pub const SCRUB2: u16 = 121;
}

/// Seed of every scrub digest (spec 3.3).
pub const DIGEST_SEED: u32 = 0xFFFF_FFFF;

/// Data digest: raw crc32c chained over the object bytes (spec 3.3). Start with [`DIGEST_SEED`].
pub fn data_digest_update(crc: u32, data: &[u8]) -> u32 {
    crc::crc32c(crc, data)
}

/// Omap digest accumulator (spec 3.4): header raw, then len-prefixed key and value per entry.
#[derive(Debug, Clone)]
pub struct OmapDigest {
    crc: u32,
    pub keys: u64,
    /// Sum of user key lengths, excluding their encoding prefixes.
    pub key_bytes: u64,
    /// Sum of value lengths.
    pub bytes: u64,
}
impl Default for OmapDigest {
    fn default() -> Self {
        OmapDigest {
            crc: DIGEST_SEED,
            keys: 0,
            key_bytes: 0,
            bytes: 0,
        }
    }
}
impl OmapDigest {
    pub fn header(&mut self, h: &[u8]) {
        if !h.is_empty() {
            self.crc = crc::crc32c(self.crc, h);
        }
    }
    pub fn entry(&mut self, k: &[u8], v: &[u8]) {
        self.crc = crc::crc32c(self.crc, &(k.len() as u32).to_le_bytes());
        self.crc = crc::crc32c(self.crc, k);
        self.crc = crc::crc32c(self.crc, &(v.len() as u32).to_le_bytes());
        self.crc = crc::crc32c(self.crc, v);
        self.keys += 1;
        self.key_bytes += k.len() as u64;
        self.bytes += v.len() as u64;
    }
    /// `n` entries already in their digest encoding (`le32 key length, key, le32 value length, value` each: the body of
    /// a denc `map<string, bufferlist>`, as the store's listing encoder writes it): the same digest as [`Self::entry`]
    /// per entry, in one crc pass over the buffer and without per-entry copies. Returns the last key (`Some(None)` for
    /// `n == 0`); `None` = `b` is not exactly `n` such entries (nothing is added then).
    pub fn entries_enc<'a>(&mut self, b: &'a [u8], n: usize) -> Option<Option<&'a [u8]>> {
        let le = |p: usize| -> Option<usize> {
            Some(u32::from_le_bytes(b.get(p..p + 4)?.try_into().ok()?) as usize)
        };
        let (mut p, mut last, mut kbytes, mut vbytes) = (0usize, None, 0u64, 0u64);
        for _ in 0..n {
            let kl = le(p)?;
            last = Some(b.get(p + 4..(p + 4).checked_add(kl)?)?);
            p += 4 + kl;
            let vl = le(p)?;
            b.get(p + 4..(p + 4).checked_add(vl)?)?;
            p += 4 + vl;
            kbytes += kl as u64;
            vbytes += vl as u64;
        }
        if p != b.len() {
            return None;
        }
        self.crc = crc::crc32c(self.crc, b);
        self.keys += n as u64;
        self.key_bytes += kbytes;
        self.bytes += vbytes;
        Some(last)
    }
    pub fn finish(&self) -> u32 {
        self.crc
    }
}

/// Default `osd_deep_scrub_large_omap_object_key_threshold` / `_value_sum_threshold` (both strictly greater).
pub const LARGE_OMAP_KEYS: u64 = 200_000;
pub const LARGE_OMAP_BYTES: u64 = 1 << 30;

/// ScrubMap::object (ENV 10/7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrubObject {
    pub size: u64,
    pub negative: bool,
    pub attrs: BTreeMap<Vec<u8>, Vec<u8>>,
    pub digest: u32,
    pub digest_present: bool,
    pub omap_digest: u32,
    pub omap_digest_present: bool,
    pub read_error: bool,
    pub stat_error: bool,
    pub ec_hash_mismatch: bool,
    pub ec_size_mismatch: bool,
    pub large_omap_object_found: bool,
    pub large_omap_object_key_count: u64,
    pub large_omap_object_value_size: u64,
    pub object_omap_bytes: u64,
    pub object_omap_keys: u64,
    /// User key bytes from a completed local OMAP scan. Not encoded in the ScrubMap wire format;
    /// decoded peer maps and objects without a completed local scan leave this unknown.
    pub object_omap_key_bytes: Option<u64>,
}
impl Default for ScrubObject {
    fn default() -> Self {
        ScrubObject {
            size: u64::MAX,
            negative: false,
            attrs: BTreeMap::new(),
            digest: 0,
            digest_present: false,
            omap_digest: 0,
            omap_digest_present: false,
            read_error: false,
            stat_error: false,
            ec_hash_mismatch: false,
            ec_size_mismatch: false,
            large_omap_object_found: false,
            large_omap_object_key_count: 0,
            large_omap_object_value_size: 0,
            object_omap_bytes: 0,
            object_omap_keys: 0,
            object_omap_key_bytes: None,
        }
    }
}

impl Encode for ScrubObject {
    fn encode<B: denc::BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(10, 7, |e| {
            e.u64(self.size)?;
            e.bool(self.negative)?;
            e.count(self.attrs.len())?;
            for (k, v) in &self.attrs {
                e.bytes(k)?;
                e.bytes(v)?;
            }
            e.u32(self.digest)?;
            e.bool(self.digest_present)?;
            e.u32(0)?; // nlinks
            e.u32(0)?; // snapcolls
            e.u32(self.omap_digest)?;
            e.bool(self.omap_digest_present)?;
            e.bool(self.read_error || self.ec_hash_mismatch || self.ec_size_mismatch)?;
            e.bool(self.stat_error)?;
            e.bool(self.read_error)?;
            e.bool(self.ec_hash_mismatch)?;
            e.bool(self.ec_size_mismatch)?;
            e.bool(self.large_omap_object_found)?;
            e.u64(self.large_omap_object_key_count)?;
            e.u64(self.large_omap_object_value_size)?;
            e.u64(self.object_omap_bytes)?;
            e.u64(self.object_omap_keys)
        })
    }
}
impl<'a> Decode<'a> for ScrubObject {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(7, 7, |d, v| {
            let mut o = ScrubObject {
                size: d.u64()?,
                negative: d.bool()?,
                ..Default::default()
            };
            let n = d.count()?;
            for _ in 0..n {
                let k = d.bytes()?.to_vec();
                o.attrs.insert(k, d.bytes()?.to_vec());
            }
            o.digest = d.u32()?;
            o.digest_present = d.bool()?;
            d.u32()?;
            let ns = d.count()?;
            for _ in 0..ns {
                d.u64()?;
            }
            o.omap_digest = d.u32()?;
            o.omap_digest_present = d.bool()?;
            let compat_err = d.bool()?;
            o.stat_error = d.bool()?;
            o.read_error = compat_err;
            if v >= 8 {
                o.read_error = d.bool()?;
                o.ec_hash_mismatch = d.bool()?;
                o.ec_size_mismatch = d.bool()?;
            }
            if v >= 9 {
                o.large_omap_object_found = d.bool()?;
                o.large_omap_object_key_count = d.u64()?;
                o.large_omap_object_value_size = d.u64()?;
            }
            if v >= 10 {
                o.object_omap_bytes = d.u64()?;
                o.object_omap_keys = d.u64()?;
            }
            Ok(o)
        })
    }
}

/// ScrubMap (ENV 3/2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScrubMap {
    pub objects: BTreeMap<Hobject, ScrubObject>,
    pub valid_through: Eversion,
    pub incr_since: Eversion,
}

impl Encode for ScrubMap {
    fn encode<B: denc::BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(3, 2, |e| {
            e.count(self.objects.len())?;
            for (h, o) in &self.objects {
                h.encode(e)?;
                o.encode(e)?;
            }
            e.u32(0)?; // deprecated attrs
            e.u32(0)?; // deprecated log bufferlist
            self.valid_through.encode(e)?;
            self.incr_since.encode(e)
        })
    }
}
impl<'a> Decode<'a> for ScrubMap {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(3, 3, |d, _| {
            let n = d.count()?;
            let mut objects = BTreeMap::new();
            for _ in 0..n {
                let h = Hobject::decode(d)?;
                objects.insert(h, ScrubObject::decode(d)?);
            }
            let na = d.count()?;
            for _ in 0..na {
                d.bytes()?;
                d.bytes()?;
            }
            d.bytes()?; // log bufferlist
            Ok(ScrubMap {
                objects,
                valid_through: Eversion::decode(d)?,
                incr_since: Eversion::decode(d)?,
            })
        })
    }
}

/// MOSDScrubReserve (92, hv3 hc1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDScrubReserve {
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub ty: i32,
    pub from: PgShard,
    pub nonce: u32,
    pub wait_for_resources: bool,
}
impl MOSDScrubReserve {
    pub const REQUEST: i32 = 0;
    pub const GRANT: i32 = 1;
    pub const RELEASE: i32 = 2;
    pub const REJECT: i32 = 3;
}
impl Message for MOSDScrubReserve {
    meta!(92, 3, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            self.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            e.i32(self.ty)?;
            self.from.encode(e)?;
            e.u32(self.nonce)?;
            e.bool(self.wait_for_resources)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let mut m = MOSDScrubReserve {
            pgid: SpgT::decode(&mut d)?,
            map_epoch: d.u32()?,
            ty: d.i32()?,
            from: PgShard::decode(&mut d)?,
            ..Default::default()
        };
        if v >= 2 {
            m.nonce = d.u32()?;
        }
        if v >= 3 {
            m.wait_for_resources = d.bool()?;
        }
        Ok(m)
    }
}

/// MOSDRepScrub (93, hv9 hc6).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDRepScrub {
    pub pgid: SpgT,
    pub scrub_from: Eversion,
    pub scrub_to: Eversion,
    pub map_epoch: u32,
    pub chunky: bool,
    pub start: Hobject,
    pub end: Hobject,
    pub deep: bool,
    pub seed: u32,
    pub min_epoch: u32,
    pub allow_preemption: bool,
    pub priority: i32,
    pub high_priority: bool,
}
impl Message for MOSDRepScrub {
    meta!(93, 9, 6, oldest 6);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            self.pgid.pgid.encode(e)?;
            self.scrub_from.encode(e)?;
            self.scrub_to.encode(e)?;
            e.u32(self.map_epoch)?;
            e.bool(self.chunky)?;
            self.start.encode(e)?;
            self.end.encode(e)?;
            e.bool(self.deep)?;
            self.pgid.shard.encode(e)?;
            e.u32(self.seed)?;
            e.u32(self.min_epoch)?;
            e.bool(self.allow_preemption)?;
            e.i32(self.priority)?;
            e.bool(self.high_priority)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        Self::check_version(v)?;
        let mut d = Decoder::new(front);
        let pg = PgT::decode(&mut d)?;
        let mut m = MOSDRepScrub {
            scrub_from: Eversion::decode(&mut d)?,
            scrub_to: Eversion::decode(&mut d)?,
            map_epoch: d.u32()?,
            chunky: d.bool()?,
            start: Hobject::decode(&mut d)?,
            end: Hobject::decode(&mut d)?,
            deep: d.bool()?,
            ..Default::default()
        };
        m.pgid = SpgT {
            pgid: pg,
            shard: ShardId::decode(&mut d)?,
        };
        m.seed = d.u32()?;
        m.min_epoch = if v >= 7 { d.u32()? } else { m.map_epoch };
        if v >= 8 {
            m.allow_preemption = d.bool()?;
        }
        if v >= 9 {
            m.priority = d.i32()?;
            m.high_priority = d.bool()?;
        }
        Ok(m)
    }
}

/// MOSDRepScrubMap (117, hv2 hc1); the ScrubMap is the DATA segment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDRepScrubMap {
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub from: PgShard,
    pub preempted: bool,
    pub map: ScrubMap,
}
impl Message for MOSDRepScrubMap {
    meta!(117, 2, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        let fr = front(f, |e| {
            self.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            self.from.encode(e)?;
            e.bool(self.preempted)
        })?;
        let mut e = Encoder::new().with_features(f);
        self.map.encode(&mut e)?;
        Ok(Segments {
            front_zc: Vec::new(),
            front_hints: Default::default(),
            front: fr,
            middle: vec![],
            data: e.into_vec().into(),
        })
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], data: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let mut m = MOSDRepScrubMap {
            pgid: SpgT::decode(&mut d)?,
            map_epoch: d.u32()?,
            from: PgShard::decode(&mut d)?,
            ..Default::default()
        };
        if v >= 2 {
            m.preempted = d.bool()?;
        }
        m.map = denc::from_slice(data)?;
        Ok(m)
    }
}

/// MOSDScrub2 (121, hv1 hc1): mgr -> primary scrub command.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDScrub2 {
    pub fsid: [u8; 16],
    pub epoch: u32,
    pub scrub_pgs: Vec<SpgT>,
    pub repair: bool,
    pub deep: bool,
}
impl Message for MOSDScrub2 {
    meta!(121, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            e.raw(&self.fsid)?;
            e.u32(self.epoch)?;
            self.scrub_pgs.encode(e)?;
            e.bool(self.repair)?;
            e.bool(self.deep)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDScrub2 {
            fsid: d.array::<16>()?,
            epoch: d.u32()?,
            scrub_pgs: Vec::<SpgT>::decode(&mut d)?,
            repair: d.bool()?,
            deep: d.bool()?,
        })
    }
}

/// Is a stored xattr name visible to scrub (`_`, `snapset`, `_<user>`)? Internal bookkeeping
/// attrs of a store must never leak into the map (spec 3.2, U2).
pub fn attr_visible(name: &[u8]) -> bool {
    name == b"snapset" || name.first() == Some(&b'_')
}

impl ScrubObject {
    /// Fill the omap digest and counters from a finished accumulator (spec 3.4).
    pub fn set_omap(&mut self, d: &OmapDigest) {
        self.set_omap_stats(d);
        self.omap_digest = d.finish();
        self.omap_digest_present = true;
    }
    /// Fill counters from a completed local OMAP scan without changing digests. Optimized EC
    /// accounts for OMAP payload while retaining its shard wire digest convention.
    pub fn set_omap_stats(&mut self, d: &OmapDigest) {
        self.object_omap_key_bytes = Some(d.key_bytes);
        self.object_omap_keys = d.keys;
        self.object_omap_bytes = d.bytes;
        let large = d.keys > LARGE_OMAP_KEYS || d.bytes > LARGE_OMAP_BYTES;
        self.large_omap_object_found = large;
        self.large_omap_object_key_count = if large { d.keys } else { 0 };
        self.large_omap_object_value_size = if large { d.bytes } else { 0 };
    }
    /// Re-judge "large omap" with the configured thresholds (`osd_deep_scrub_large_omap_object_key_threshold` /
    /// `_value_sum_threshold`, strictly greater) from the digest counters; the store layer only knows the defaults.
    pub fn apply_large_omap(&mut self, key_thr: u64, bytes_thr: u64) {
        if !self.omap_digest_present {
            return;
        }
        let (k, b) = (self.object_omap_keys, self.object_omap_bytes);
        let large = k > key_thr || b > bytes_thr;
        self.large_omap_object_found = large;
        self.large_omap_object_key_count = if large { k } else { 0 };
        self.large_omap_object_value_size = if large { b } else { 0 };
    }
    /// Deep read failed: digests absent, error flagged.
    pub fn set_read_error(&mut self) {
        self.read_error = true;
        self.digest_present = false;
        self.omap_digest_present = false;
        self.object_omap_key_bytes = None;
    }
}
