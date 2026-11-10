// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Dedup info records (adr 0593-dedup-deep-scrub-reformat, doc/spec/dedup-collection.md 4): one record per content digest
//! taken by a deep scrub, in the shard KV under tag `D`. The key after the tag is the fork's record key: pool (u64 BE,
//! i64 + 2^63), `:`, raw digest, `:`, wall clock ns (u64 BE), `:`, the object hash in bitwise-key form (u32 BE); a pool's
//! records sort by digest (duplicates adjacent), then time, then hash. The digest length is the key length minus 24
//! (16 = MD5, 32 = SHA-256). The value is croit-flashstore-osd's own: what the record was taken of.

use denc::types::Ghobject;

pub const T_DEDUP: u8 = b'D';
const SEP: u8 = b':';
/// Key bytes besides the digest: tag, pool, three separators, time, hash.
pub const KEY_FIXED: usize = 1 + 8 + 1 + 1 + 8 + 1 + 4;
/// Value format version.
const VAL_V1: u8 = 1;

/// Content digest algorithm (`flashstore_dedup_digest`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestAlg {
    Md5 = 1,
    Sha256 = 2,
}

impl DigestAlg {
    pub fn parse(s: &str) -> Option<DigestAlg> {
        match s {
            "md5" => Some(DigestAlg::Md5),
            "sha256" => Some(DigestAlg::Sha256),
            _ => None,
        }
    }
    /// Digest bytes.
    pub fn digest_len(self) -> usize {
        match self {
            DigestAlg::Md5 => 16,
            DigestAlg::Sha256 => 32,
        }
    }
    pub fn from_u8(v: u8) -> Option<DigestAlg> {
        match v {
            1 => Some(DigestAlg::Md5),
            2 => Some(DigestAlg::Sha256),
            _ => None,
        }
    }
}

/// Pool prefix of the record keys: tag + pool + `:`.
pub fn pool_prefix(pool: i64) -> [u8; 10] {
    let mut k = [0u8; 10];
    k[0] = T_DEDUP;
    k[1..9].copy_from_slice(&((pool as u64) ^ (1 << 63)).to_be_bytes());
    k[9] = SEP;
    k
}

/// Record key.
pub fn key(pool: i64, digest: &[u8], ts_ns: u64, hash_key: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(KEY_FIXED + digest.len());
    k.extend_from_slice(&pool_prefix(pool));
    k.extend_from_slice(digest);
    k.push(SEP);
    k.extend_from_slice(&ts_ns.to_be_bytes());
    k.push(SEP);
    k.extend_from_slice(&hash_key.to_be_bytes());
    k
}

/// Fields of a record key (with the tag).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyParts<'a> {
    pub pool: i64,
    pub digest: &'a [u8],
    pub ts_ns: u64,
    /// Object hash in bitwise-key form (bit-reversed).
    pub hash_key: u32,
}

pub fn parse_key(k: &[u8]) -> Option<KeyParts<'_>> {
    let d = k.len().checked_sub(KEY_FIXED).filter(|d| *d > 0)?;
    let n = k.len();
    (k[0] == T_DEDUP && k[9] == SEP && k[10 + d] == SEP && k[n - 5] == SEP).then(|| KeyParts {
        pool: (u64::from_be_bytes(k[1..9].try_into().unwrap()) ^ (1 << 63)) as i64,
        digest: &k[10..10 + d],
        ts_ns: u64::from_be_bytes(k[11 + d..19 + d].try_into().unwrap()),
        hash_key: u32::from_be_bytes(k[n - 4..].try_into().unwrap()),
    })
}

/// What a record was taken of: the object, its data state on this store (onode id, tracking generation, data version) and
/// the digest algorithm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordValue {
    pub alg: DigestAlg,
    pub id: u64,
    pub dv_gen: u64,
    pub dv: u64,
    pub oid: Ghobject,
}

impl RecordValue {
    /// `[1][alg][id u64 LE][dv_gen u64 LE][dv u64 LE][ghobject encoding]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![VAL_V1, self.alg as u8];
        v.extend_from_slice(&self.id.to_le_bytes());
        v.extend_from_slice(&self.dv_gen.to_le_bytes());
        v.extend_from_slice(&self.dv.to_le_bytes());
        v.extend_from_slice(&denc::to_vec(&self.oid).expect("ghobject encodes"));
        v
    }
    pub fn decode(b: &[u8]) -> Option<RecordValue> {
        if b.len() < 26 || b[0] != VAL_V1 {
            return None;
        }
        let g = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let oid: Ghobject = denc::from_slice(&b[26..]).ok()?;
        Some(RecordValue {
            alg: DigestAlg::from_u8(b[1])?,
            id: g(2),
            dv_gen: g(10),
            dv: g(18),
            oid,
        })
    }
}

/// Key range of digest shard `shard` of `2^bits` (most significant digest bits; `bits` <= 32) of `pool`'s records with
/// digests of `dlen` bytes: `[lo, hi)`.
pub fn shard_range(pool: i64, shard: u32, bits: u32, dlen: usize) -> (Vec<u8>, Vec<u8>) {
    debug_assert!(bits <= 32 && (bits == 32 || shard < 1 << bits));
    let p = pool_prefix(pool);
    let mut lo = p.to_vec();
    let mut hi = p.to_vec();
    if bits == 0 {
        hi[9] = SEP + 1;
        return (lo, hi);
    }
    // digest prefix bytes covering `bits`, left-aligned
    let nb = bits.div_ceil(8) as usize;
    let first = (shard as u64) << (64 - bits);
    let last = first | (u64::MAX >> bits);
    lo.extend_from_slice(&first.to_be_bytes()[..nb]);
    hi.extend_from_slice(&last.to_be_bytes()[..nb]);
    // every key whose digest starts with a prefix up to `last`'s prefix: the end bound is that prefix + 1
    increment(&mut hi);
    debug_assert!(dlen >= nb);
    (lo, hi)
}

/// Lexicographic successor of the shortest string greater than every key with prefix `b`.
fn increment(b: &mut Vec<u8>) {
    while let Some(x) = b.pop() {
        if x < 0xFF {
            b.push(x + 1);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::types::{Hobject, ShardId, SnapId};

    #[test]
    fn key_layout_and_order() {
        let d = [0xABu8; 16];
        let k = key(3, &d, 0x0102_0304_0506_0708, 0xDEAD_BEEF);
        assert_eq!(k.len(), 1 + 39, "tag + the fork's 39-byte MD5 key");
        assert_eq!(&k[1..9], &(3u64 | 1 << 63).to_be_bytes());
        assert_eq!((k[9], k[26], k[35]), (b':', b':', b':'));
        let p = parse_key(&k).unwrap();
        assert_eq!(
            (p.pool, p.digest, p.ts_ns, p.hash_key),
            (3, &d[..], 0x0102_0304_0506_0708, 0xDEAD_BEEF)
        );
        // negative pools sort first, then digest, then time
        assert!(key(-1, &d, 9, 0) < key(0, &[0; 16], 0, 0));
        assert!(key(1, &[1; 16], 9, 0) < key(1, &[2; 16], 0, 0));
        assert!(key(1, &[1; 16], 1, 9) < key(1, &[1; 16], 2, 0));
        // SHA-256 digests
        let s = key(1, &[7; 32], 1, 2);
        assert_eq!(parse_key(&s).unwrap().digest.len(), 32);
        assert!(parse_key(&s[..20]).is_none());
        assert!(parse_key(b"Dshort").is_none());
    }

    #[test]
    fn shard_ranges_partition_the_pool() {
        for bits in [0u32, 1, 3, 5, 8, 9, 16, 32] {
            let shards: Vec<u64> = if bits == 0 {
                vec![0]
            } else {
                // first, middle and last shard
                vec![0, (1u64 << bits) / 2, (1u64 << bits) - 1]
            };
            for shard in shards {
                let (lo, hi) = shard_range(5, shard as u32, bits, 16);
                let low_mask = if bits == 0 {
                    u64::MAX
                } else {
                    u64::MAX >> bits
                };
                for fill in [0u64, 0x5A5A_5A5A_5A5A_5A5A, u64::MAX] {
                    let top = if bits == 0 { 0 } else { shard << (64 - bits) };
                    let mut d = [fill as u8; 16];
                    d[..8].copy_from_slice(&(top | (fill & low_mask)).to_be_bytes());
                    let k = key(5, &d, 77, 1);
                    assert!(
                        lo <= k && k < hi,
                        "bits {bits} shard {shard} fill {fill:#x}"
                    );
                    // the neighbouring pools are outside
                    assert!(key(4, &d, 77, 1) < lo && key(6, &d, 77, 1) >= hi);
                    // the neighbouring shards are outside
                    if bits > 0 && shard > 0 {
                        let mut e = d;
                        e[..8].copy_from_slice(
                            &(((shard - 1) << (64 - bits)) | low_mask).to_be_bytes(),
                        );
                        assert!(key(5, &e, 77, 1) < lo);
                    }
                    if bits > 0 && shard + 1 < 1 << bits {
                        let mut e = d;
                        e[..8].copy_from_slice(&((shard + 1) << (64 - bits)).to_be_bytes());
                        assert!(key(5, &e, 0, 0) >= hi);
                    }
                }
            }
        }
    }

    #[test]
    fn value_roundtrip() {
        let v = RecordValue {
            alg: DigestAlg::Sha256,
            id: 42,
            dv_gen: 2,
            dv: 9,
            oid: Ghobject::new(
                Hobject::new(b"obj", SnapId::NOSNAP, 0x1234, 3, b"ns"),
                Ghobject::NO_GEN,
                ShardId::NO_SHARD,
            ),
        };
        let b = v.encode();
        assert_eq!(RecordValue::decode(&b), Some(v));
        assert!(RecordValue::decode(&b[..b.len() - 1]).is_none());
        let mut x = b.clone();
        x[0] = 2;
        assert!(RecordValue::decode(&x).is_none());
        let mut x = b;
        x[1] = 9;
        assert!(RecordValue::decode(&x).is_none());
    }
}
