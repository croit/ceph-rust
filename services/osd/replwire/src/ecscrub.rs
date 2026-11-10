// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! EC shard scrub digests (ec.md 4.6, 7.7): hinfo parsing and the deep-scrub digest rules of a shard object.

use crate::scrubmsgs::{OmapDigest, ScrubObject};

/// Name of the EC backend xattr holding the cumulative per-shard hashes.
pub const HINFO_KEY: &[u8] = b"hinfo_key";

/// Decoded `hinfo_key`: `ENCODE(1,1) { u64 total_chunk_size, vec<u32> cumulative_shard_hashes }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcHinfo {
    pub total_chunk_size: u64,
    /// Empty after an overwrite cleared the hashes (mode L1).
    pub hashes: Vec<u32>,
}

/// Parse a `hinfo_key` blob; `None` = undecodable. Like classic, bytes after the envelope are ignored.
pub fn parse_hinfo(b: &[u8]) -> Option<EcHinfo> {
    denc::Decoder::new(b)
        .versioned_min(1, 1, |d, _| {
            let total_chunk_size = d.u64()?;
            let n = d.count()?;
            // Validate the entire vector before allocating its storage.
            let raw = d.take(n.checked_mul(4).ok_or(denc::Error::TooLong)?)?;
            let hashes = raw
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c))
                .collect();
            Ok(EcHinfo {
                total_chunk_size,
                hashes,
            })
        })
        .ok()
}

/// Encode a hinfo blob (tests, tools).
pub fn encode_hinfo(total_chunk_size: u64, hashes: &[u32]) -> Vec<u8> {
    let mut body = total_chunk_size.to_le_bytes().to_vec();
    body.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
    for h in hashes {
        body.extend_from_slice(&h.to_le_bytes());
    }
    let mut v = vec![1, 1];
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(&body);
    v
}

/// Shard data layout for the deep-scrub digest rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcScrubMode {
    /// L0: digest verified against `hinfo_key`.
    Append,
    /// L1: digest 0 (no hinfo hashes).
    Overwrites,
    /// Mode O (ec-optimized.md 11): crc32c of the whole shard file, never hinfo, sizes 4 KiB aligned.
    Optimized,
}

impl From<bool> for EcScrubMode {
    /// `allow_ec_overwrites` flag of a legacy pool.
    fn from(overwrites: bool) -> Self {
        if overwrites {
            EcScrubMode::Overwrites
        } else {
            EcScrubMode::Append
        }
    }
}

/// Finish the deep-scrub digest of an EC shard object whose whole shard file was read (`crc` over `bytes_read`
/// bytes, seed `DIGEST_SEED`). `o.size` is the stored size, `o.attrs` holds all xattrs. `chunk` = chunk size (0 =
/// unknown: skip the stride check). The omap digest is always -1. Successful L0/L1 objects have
/// known-zero OMAP counters; optimized objects require a separate OMAP scan to fill counters.
pub fn ec_deep_finish(
    o: &mut ScrubObject,
    shard: usize,
    mode: impl Into<EcScrubMode>,
    chunk: u32,
    crc: u32,
    bytes_read: u64,
) {
    o.omap_digest = u32::MAX;
    o.omap_digest_present = true;
    let mode = mode.into();
    if mode == EcScrubMode::Optimized {
        // omap of optimized pools is not digested by the shard (classic reports -1 too)
        o.digest = crc;
        o.digest_present = true;
        return;
    }
    let legacy_overwrites = mode == EcScrubMode::Overwrites;
    if chunk > 0 && !bytes_read.is_multiple_of(u64::from(chunk)) {
        o.set_read_error();
        return;
    }
    if legacy_overwrites {
        o.digest = 0;
        o.digest_present = true;
        o.set_omap_stats(&OmapDigest::default());
        return;
    }
    let hi = match o.attrs.get(HINFO_KEY).filter(|b| !b.is_empty()) {
        Some(b) => parse_hinfo(b),
        // an empty shard object without hinfo is valid: a fresh hinfo (size 0, every hash -1), as the classic backend
        // assumes (else every empty object is a scrub error on our shard only)
        None if o.size == 0 => Some(EcHinfo {
            total_chunk_size: 0,
            hashes: vec![u32::MAX; shard + 1],
        }),
        None => None,
    };
    let Some(hi) = hi.filter(|h| h.total_chunk_size == o.size) else {
        o.set_read_error();
        return;
    };
    if hi.hashes.is_empty() || hi.total_chunk_size != bytes_read {
        o.ec_size_mismatch = true;
        return;
    }
    if hi.hashes.get(shard) != Some(&crc) {
        o.ec_hash_mismatch = true;
        return;
    }
    o.digest = hi.hashes[0];
    o.digest_present = true;
    o.set_omap_stats(&OmapDigest::default());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty shard object without `hinfo_key` is valid (a fresh hinfo: size 0, hashes -1), a non-empty one is a
    /// read error, as in the classic backend.
    #[test]
    fn empty_object_without_hinfo_is_clean() {
        let mut o = ScrubObject {
            size: 0,
            ..Default::default()
        };
        ec_deep_finish(&mut o, 1, false, 4096, u32::MAX, 0);
        assert!(!o.read_error && !o.ec_size_mismatch && !o.ec_hash_mismatch);
        assert!(o.digest_present);
        assert_eq!(o.digest, u32::MAX);
        assert_eq!(o.object_omap_key_bytes, Some(0));

        let mut o = ScrubObject {
            size: 4096,
            ..Default::default()
        };
        ec_deep_finish(&mut o, 1, false, 4096, 7, 4096);
        assert!(o.read_error);
        assert_eq!(o.object_omap_key_bytes, None);
    }

    #[test]
    fn legacy_omap_is_known_empty_and_optimized_omap_needs_a_scan() {
        let mut legacy = ScrubObject {
            size: 4096,
            ..Default::default()
        };
        ec_deep_finish(&mut legacy, 1, EcScrubMode::Overwrites, 4096, 7, 4096);
        assert_eq!(legacy.object_omap_key_bytes, Some(0));
        assert_eq!((legacy.object_omap_keys, legacy.object_omap_bytes), (0, 0));
        assert_eq!((legacy.digest, legacy.omap_digest), (0, u32::MAX));

        let mut optimized = ScrubObject {
            size: 4096,
            ..Default::default()
        };
        ec_deep_finish(&mut optimized, 1, EcScrubMode::Optimized, 4096, 7, 4096);
        assert_eq!(optimized.object_omap_key_bytes, None);
        assert_eq!((optimized.digest, optimized.omap_digest), (7, u32::MAX));
    }
}
