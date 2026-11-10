// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Dedup info listing (croit fork `wip-ifed-dedup`, doc/spec/dedup-listing.md 3; adr 0593-dedup-deep-scrub-reformat):
//! `MOSDDedupList` (137) asks one OSD for the records of a digest shard of a pool, `MOSDDedupListReply` (138) answers with
//! up to `max` records sorted by digest and an opaque cursor. Both v1 / compat 1, front segment only. Served only by OSDs
//! advertising [`FEATURE_OSD_DEDUP_LIST`].

use crate::meta;
use crate::msg::{Message, Segments, front_with};
use denc::types::Uuid;
use denc::{Decode, Decoder, Encode, Result};

/// `CEPH_FEATURE_OSD_DEDUP_LIST`: bit 51, incarnation 2 (the fork reuses the retired OSD_BITWISE_HOBJ_SORT bit).
pub const FEATURE_OSD_DEDUP_LIST: u64 = 1 << 51;
/// `CEPH_FEATUREMASK_OSD_DEDUP_LIST`: bit 51 plus the incarnation-2 bit 57; a peer has the feature only with both.
pub const FEATUREMASK_OSD_DEDUP_LIST: u64 = 1 << 51 | 1 << 57;

/// MOSDDedupList (137, hv=1 hc=1): records of digest shard `shard` of `2^shard_bits` of `pool`, after the opaque cursor
/// `after` (empty = from the start), at most `max`; `newer_than` / `prune_older_than` are ages in seconds (0 = no limit /
/// prune nothing). `epoch` is informational.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDDedupList {
    pub fsid: Uuid,
    pub epoch: u32,
    pub pool: i64,
    pub shard: u64,
    pub shard_bits: u8,
    pub after: Vec<u8>,
    pub max: u32,
    pub newer_than: u32,
    pub prune_older_than: u32,
}

impl Message for MOSDDedupList {
    meta!(137, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            self.fsid.encode(e)?;
            e.u32(self.epoch)?;
            e.i64(self.pool)?;
            e.u64(self.shard)?;
            e.u8(self.shard_bits)?;
            e.bytes(&self.after)?;
            e.u32(self.max)?;
            e.u32(self.newer_than)?;
            e.u32(self.prune_older_than)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDDedupList {
            fsid: Uuid::decode(&mut d)?,
            epoch: d.u32()?,
            pool: d.i64()?,
            shard: d.u64()?,
            shard_bits: d.u8()?,
            after: d.bytes()?.to_vec(),
            max: d.u32()?,
            newer_than: d.u32()?,
            prune_older_than: d.u32()?,
        })
    }
}

/// One record: raw digest, creation time (recording OSD's wall clock, ns since the epoch), object hash in bitwise-key form
/// (bit-reversed; the client reverses it again).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DedupListEntry {
    pub digest: Vec<u8>,
    pub timestamp: u64,
    pub oid_hash: u32,
}

/// `osd_dedup_list_result_t` (v1 / compat 1): `completed` = nothing more in the shard after `next`; `now` = the OSD's wall
/// clock at the request (ns), 0 on error.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DedupListResult {
    pub completed: bool,
    pub next: Vec<u8>,
    pub now: u64,
    pub entries: Vec<DedupListEntry>,
}

impl Encode for DedupListResult {
    fn encode<B: denc::BufMut>(&self, e: &mut denc::Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            e.bool(self.completed)?;
            e.bytes(&self.next)?;
            e.u64(self.now)?;
            e.count(self.entries.len())?;
            for x in &self.entries {
                e.bytes(&x.digest)?;
                e.u64(x.timestamp)?;
                e.u32(x.oid_hash)?;
            }
            Ok(())
        })
    }
}

impl<'a> Decode<'a> for DedupListResult {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(1, |d, _v| {
            let completed = d.bool()?;
            let next = d.bytes()?.to_vec();
            let now = d.u64()?;
            let n = d.u32()? as usize;
            // an entry is at least 16 bytes (empty digest length, timestamp, hash): never size from a larger count
            if n > d.remaining() / 16 {
                return Err(denc::Error::BadLength {
                    len: n as u64,
                    remaining: d.remaining(),
                });
            }
            let mut entries = Vec::with_capacity(n);
            for _ in 0..n {
                entries.push(DedupListEntry {
                    digest: d.bytes()?.to_vec(),
                    timestamp: d.u64()?,
                    oid_hash: d.u32()?,
                });
            }
            Ok(DedupListResult {
                completed,
                next,
                now,
                entries,
            })
        })
    }
}

/// MOSDDedupListReply (138, hv=1 hc=1): `r` = 0 or a negative errno; the result is always present (default on error).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDDedupListReply {
    pub r: i32,
    pub result: DedupListResult,
}

impl Message for MOSDDedupListReply {
    meta!(138, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            e.i32(self.r)?;
            self.result.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDDedupListReply {
            r: d.i32()?,
            result: DedupListResult::decode(&mut d)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn front<M: Message>(m: &M) -> Vec<u8> {
        m.encode(u64::MAX).unwrap().front.to_vec()
    }

    fn req() -> MOSDDedupList {
        MOSDDedupList {
            fsid: Uuid((1..=16).collect::<Vec<u8>>().try_into().unwrap()),
            epoch: 42,
            pool: 3,
            shard: 5,
            shard_bits: 4,
            after: vec![],
            max: 1000,
            newer_than: 3600,
            prune_older_than: 0,
        }
    }

    /// Hand-computed vectors of dedup-listing.md 6.1.
    #[test]
    fn request_vectors() {
        let m = req();
        let b = front(&m);
        assert_eq!(
            b,
            hex(
                "0102030405060708090a0b0c0d0e0f10 2a000000 0300000000000000 0500000000000000 04 00000000 e8030000 100e0000 00000000"
            )
        );
        assert_eq!(b.len(), 53);
        assert_eq!(MOSDDedupList::decode(1, &b, &[], &[]).unwrap(), m);
        let m2 = MOSDDedupList {
            after: vec![1, 2],
            prune_older_than: 86400,
            ..req()
        };
        let b2 = front(&m2);
        assert_eq!(b2.len(), 55);
        assert_eq!(
            &b2[36..],
            &hex("04 02000000 0102 e8030000 100e0000 80510100")[..]
        );
        assert_eq!(MOSDDedupList::decode(1, &b2, &[], &[]).unwrap(), m2);
    }

    #[test]
    fn reply_vectors() {
        let m = MOSDDedupListReply {
            r: 0,
            result: DedupListResult {
                completed: false,
                next: vec![1, 2],
                now: 1_700_000_000_000_000_000,
                entries: vec![DedupListEntry {
                    digest: vec![0xaa; 16],
                    timestamp: 1_699_999_999_000_000_000,
                    oid_hash: 0x1234_5678,
                }],
            },
        };
        let b = front(&m);
        let want = hex(&format!(
            "00000000 01 01 33000000 00 02000000 0102 00002a36fe9c9717 01000000 10000000 {} 00368ffafd9c9717 78563412",
            "aa".repeat(16)
        ));
        assert_eq!(b, want);
        assert_eq!(b.len(), 61);
        assert_eq!(MOSDDedupListReply::decode(1, &b, &[], &[]).unwrap(), m);
        // the client view of the hash: bit-reversed back
        assert_eq!(0x1234_5678u32.reverse_bits(), 0x1E6A_2C48);
        // error reply with the default result
        let e = MOSDDedupListReply {
            r: -1,
            result: DedupListResult::default(),
        };
        let b = front(&e);
        assert_eq!(
            b,
            hex("ffffffff 01 01 11000000 00 00000000 0000000000000000 00000000")
        );
        assert_eq!(b.len(), 27);
        // a newer result version: unknown trailing fields are skipped
        let mut v2 = front(&m);
        v2[4] = 2; // struct_v 2
        let body_len = u32::from_le_bytes(v2[6..10].try_into().unwrap());
        v2[6..10].copy_from_slice(&(body_len + 3).to_le_bytes());
        v2.extend_from_slice(&[7, 7, 7]);
        assert_eq!(MOSDDedupListReply::decode(1, &v2, &[], &[]).unwrap(), m);
        // compat 2 is refused
        let mut c2 = front(&m);
        c2[5] = 2;
        assert!(MOSDDedupListReply::decode(1, &c2, &[], &[]).is_err());
    }

    #[test]
    fn feature_mask() {
        assert_eq!(FEATUREMASK_OSD_DEDUP_LIST, 0x0208_0000_0000_0000);
        assert_eq!(FEATURE_OSD_DEDUP_LIST, 0x0008_0000_0000_0000);
    }
}
