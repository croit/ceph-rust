// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `hinfo_key` xattr (ec.md 4.6): ENCODE(1,1) { u64 total_chunk_size, vec<u32> cumulative_shard_hashes }.

use denc::{Decoder, Encoder, Error};

/// Name of the backend-private xattr.
pub const HINFO_KEY: &str = "hinfo_key";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashInfo {
    pub total_chunk_size: u64,
    /// One crc32c per shard; EMPTY after an overwrite cleared them (mode L1).
    pub hashes: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HinfoError {
    Decode(String),
    /// `append` at an offset that is not the current end, per-shard buffers of unequal length / wrong count, or a
    /// total size that would overflow `u64`.
    BadAppend(&'static str),
}

impl std::fmt::Display for HinfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HinfoError::Decode(e) => write!(f, "hinfo decode: {e}"),
            HinfoError::BadAppend(e) => write!(f, "hinfo append: {e}"),
        }
    }
}
impl std::error::Error for HinfoError {}

impl HashInfo {
    /// Fresh object: size 0, every hash at the crc seed `0xFFFFFFFF`.
    pub fn new(n_shards: usize) -> HashInfo {
        HashInfo {
            total_chunk_size: 0,
            hashes: vec![u32::MAX; n_shards],
        }
    }

    pub fn has_hashes(&self) -> bool {
        !self.hashes.is_empty()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        let r: Result<(), Error> = e.versioned(1, 1, |e| {
            e.u64(self.total_chunk_size)?;
            e.count(self.hashes.len())?;
            for h in &self.hashes {
                e.u32(*h)?;
            }
            Ok(())
        });
        r.expect("encode into Vec cannot fail");
        e.into_vec()
    }

    pub fn decode(b: &[u8]) -> Result<HashInfo, HinfoError> {
        let mut d = Decoder::new(b);
        let h = d
            .versioned(1, |d, _v| {
                let total_chunk_size = d.u64()?;
                let n = d.count()?;
                // each hash is 4 bytes: bound the allocation by the bytes that remain
                if n > d.remaining() / 4 {
                    return Err(Error::BadLength {
                        len: n as u64,
                        remaining: d.remaining(),
                    });
                }
                let mut hashes = Vec::with_capacity(n);
                for _ in 0..n {
                    hashes.push(d.u32()?);
                }
                Ok(HashInfo {
                    total_chunk_size,
                    hashes,
                })
            })
            .map_err(|e| HinfoError::Decode(e.to_string()))?;
        if !d.is_empty() {
            return Err(HinfoError::Decode("trailing bytes".into()));
        }
        Ok(h)
    }

    /// Append the per-shard chunk bytes `bufs` (all the same length) at `old_size == total_chunk_size`: each hash
    /// advances by crc32c (raw, seed = previous hash), the total by the buffer length. With cleared hashes only the
    /// total advances.
    pub fn append(&mut self, old_size: u64, bufs: &[&[u8]]) -> Result<(), HinfoError> {
        if old_size != self.total_chunk_size {
            return Err(HinfoError::BadAppend("offset is not the current end"));
        }
        let len = bufs.first().map_or(0, |b| b.len());
        if bufs.iter().any(|b| b.len() != len) {
            return Err(HinfoError::BadAppend("unequal shard buffers"));
        }
        if self.has_hashes() && bufs.len() != self.hashes.len() {
            return Err(HinfoError::BadAppend("shard count mismatch"));
        }
        // the size comes from the on-disk xattr: a wrapped total would hide the (only) check that later appends are
        // contiguous, so refuse before the hashes change
        let total = self
            .total_chunk_size
            .checked_add(len as u64)
            .ok_or(HinfoError::BadAppend("size overflow"))?;
        if self.has_hashes() {
            for (h, b) in self.hashes.iter_mut().zip(bufs) {
                *h = crc::crc32c(*h, b);
            }
        }
        self.total_chunk_size = total;
        Ok(())
    }

    /// [`Self::append`] from the shard buffers' crc32c (seed 0) instead of their bytes (`len` bytes per shard):
    /// identical result, joined with `crc32c_combine`.
    pub fn append_crcs(&mut self, old_size: u64, len: u64, crcs: &[u32]) -> Result<(), HinfoError> {
        if old_size != self.total_chunk_size {
            return Err(HinfoError::BadAppend("offset is not the current end"));
        }
        if self.has_hashes() && crcs.len() != self.hashes.len() {
            return Err(HinfoError::BadAppend("shard count mismatch"));
        }
        let total = self
            .total_chunk_size
            .checked_add(len)
            .ok_or(HinfoError::BadAppend("size overflow"))?;
        if self.has_hashes() {
            for (h, c) in self.hashes.iter_mut().zip(crcs) {
                *h = crc::crc32c_combine(*h, *c, len);
            }
        }
        self.total_chunk_size = total;
        Ok(())
    }

    /// Overwrite semantics (L1): drop the hashes, keep `total` as the new shard size.
    pub fn clear_hashes(&mut self, total: u64) {
        self.hashes.clear();
        self.total_chunk_size = total;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_fresh() {
        let h = HashInfo::new(3);
        let mut want = vec![1u8, 1, 24, 0, 0, 0];
        want.extend([0u8; 8]);
        want.extend([3, 0, 0, 0]);
        want.extend([0xff; 12]);
        assert_eq!(h.encode(), want);
        assert_eq!(HashInfo::decode(&want).unwrap(), h);
    }

    #[test]
    fn golden_cleared() {
        let mut h = HashInfo::new(2);
        h.clear_hashes(0x1000);
        let want = [1u8, 1, 12, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(h.encode(), want);
        assert_eq!(HashInfo::decode(&want).unwrap(), h);
        assert!(!h.has_hashes());
    }

    #[test]
    fn crc_chain() {
        let mut h = HashInfo::new(2);
        let (a0, a1) = (vec![1u8; 100], vec![2u8; 100]);
        let (b0, b1) = (vec![3u8; 50], vec![4u8; 50]);
        h.append(0, &[&a0, &a1]).unwrap();
        h.append(100, &[&b0, &b1]).unwrap();
        assert_eq!(h.total_chunk_size, 150);
        let whole0: Vec<u8> = a0.iter().chain(&b0).copied().collect();
        assert_eq!(h.hashes[0], crc::soft(u32::MAX, &whole0));
        assert_ne!(h.hashes[0], h.hashes[1]);
        // known answer: crc32c (raw, no xors) of nothing is the seed
        let mut e = HashInfo::new(1);
        e.append(0, &[&[]]).unwrap();
        assert_eq!(e.hashes, vec![u32::MAX]);
        assert_eq!(e.total_chunk_size, 0);
    }

    #[test]
    fn append_errors() {
        let mut h = HashInfo::new(2);
        assert!(h.append(5, &[&[1], &[2]]).is_err());
        assert!(h.append(0, &[&[1], &[2, 3]]).is_err());
        assert!(h.append(0, &[&[1]]).is_err());
        let mut c = HashInfo::new(2);
        c.clear_hashes(8);
        c.append(8, &[&[1, 2], &[3, 4]]).unwrap();
        assert_eq!(c.total_chunk_size, 10);
        assert!(!c.has_hashes());
    }

    /// A decoded `total_chunk_size` near `u64::MAX` must fail the append, not overflow (debug panic / release wrap);
    /// the hash info stays unchanged.
    #[test]
    fn append_rejects_overflow() {
        let mut b = vec![1u8, 1, 12, 0, 0, 0];
        b.extend([0xff; 8]);
        b.extend([0, 0, 0, 0]);
        let mut h = HashInfo::decode(&b).unwrap();
        assert_eq!(h.total_chunk_size, u64::MAX);
        assert_eq!(
            h.append(u64::MAX, &[&[1, 2]]),
            Err(HinfoError::BadAppend("size overflow"))
        );
        assert_eq!(h.total_chunk_size, u64::MAX);
        assert_eq!(
            h.append_crcs(u64::MAX, 2, &[]),
            Err(HinfoError::BadAppend("size overflow"))
        );
        assert_eq!(h.total_chunk_size, u64::MAX);
        // the hashes are not touched by a refused append
        let mut c = HashInfo::new(1);
        c.total_chunk_size = u64::MAX;
        let before = c.hashes.clone();
        assert!(c.append(u64::MAX, &[&[1]]).is_err());
        assert_eq!(c.hashes, before);
    }

    #[test]
    fn garbage_never_panics() {
        let good = HashInfo::new(4).encode();
        for n in 0..good.len() {
            assert!(HashInfo::decode(&good[..n]).is_err());
        }
        let mut t = good.clone();
        t.push(0);
        assert!(HashInfo::decode(&t).is_err());
        // huge count
        let mut bad = vec![1u8, 1, 12, 0, 0, 0];
        bad.extend([0u8; 8]);
        bad.extend([0xff, 0xff, 0xff, 0x7f]);
        assert!(HashInfo::decode(&bad).is_err());
        let mut s: u64 = 7;
        for _ in 0..5000 {
            let v: Vec<u8> = (0..(s % 40))
                .map(|_| {
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    s as u8
                })
                .collect();
            s ^= s << 13;
            let _ = HashInfo::decode(&v);
        }
    }
}

#[cfg(test)]
mod crc_tests {
    use super::*;

    /// Appending by crc equals appending by bytes, for fresh and continued hashes.
    #[test]
    fn append_crcs_equals_append() {
        let a: Vec<Vec<u8>> = (0..3)
            .map(|s| (0..8192).map(|i| (i * 7 + s) as u8).collect())
            .collect();
        let b: Vec<Vec<u8>> = (0..3)
            .map(|s| (0..4096).map(|i| (i * 3 + s) as u8).collect())
            .collect();
        let (mut x, mut y) = (HashInfo::new(3), HashInfo::new(3));
        for bufs in [&a, &b] {
            let refs: Vec<&[u8]> = bufs.iter().map(Vec::as_slice).collect();
            x.append(x.total_chunk_size, &refs).unwrap();
            let crcs: Vec<u32> = bufs.iter().map(|v| crc::crc32c(0, v)).collect();
            y.append_crcs(y.total_chunk_size, bufs[0].len() as u64, &crcs)
                .unwrap();
        }
        assert_eq!(x, y);
        assert!(y.append_crcs(1, 1, &[0, 0, 0]).is_err());
        assert!(y.append_crcs(y.total_chunk_size, 1, &[0]).is_err());
    }
}
