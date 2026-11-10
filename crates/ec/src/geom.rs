// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Shard geometry (ec.md 3, L0/L1): stripe `s` occupies `[s*C, (s+1)*C)` on EVERY shard.

use crate::gate::EcFacts;

impl EcFacts {
    /// Shard holding raw chunk `raw` (`raw < k+m`; out of range maps to itself).
    pub fn shard_of_raw(&self, raw: u32) -> u32 {
        self.chunk_mapping.get(raw as usize).copied().unwrap_or(raw)
    }

    /// Raw chunk index held by `shard`, `None` if the shard does not exist.
    pub fn raw_of_shard(&self, shard: u32) -> Option<u32> {
        self.chunk_mapping
            .iter()
            .position(|s| *s == shard)
            .map(|r| r as u32)
    }

    /// Size of every shard file for logical object size `logical` (zero padded to the stripe end).
    pub fn shard_size(&self, logical: u64) -> u64 {
        let s = u64::from(self.stripe_width);
        logical.div_ceil(s) * u64::from(self.chunk_size)
    }

    /// Coding (parity) shard: raw index >= k.
    pub fn is_parity_shard(&self, shard: u32) -> bool {
        self.raw_of_shard(shard).is_some_and(|r| r >= self.k)
    }

    /// Logical offset -> (data shard, offset inside the shard file).
    pub fn ro_to_shard(&self, off: u64) -> (u32, u64) {
        let (s, c) = (u64::from(self.stripe_width), u64::from(self.chunk_size));
        let stripe = off / s;
        let raw = ((off % s) / c) as u32;
        (self.shard_of_raw(raw), stripe * c + off % c)
    }

    /// Mode O nonprimary data shard (raw 1..k-1, `nonprimary` from the pool): never leads, sparse log, only `_`.
    pub fn is_nonprimary(&self, shard: u32) -> bool {
        self.nonprimary.binary_search(&shard).is_ok()
    }

    /// Mode O shard file size (ec-optimized.md 2.2) of `shard` for logical size `logical`.
    pub fn shard_size_opt(&self, logical: u64, shard: u32) -> u64 {
        let raw = self.raw_of_shard(shard).unwrap_or(0);
        opt_shard_size(
            logical,
            u64::from(self.stripe_width),
            u64::from(self.chunk_size),
            self.k,
            raw,
        )
    }

    /// Mode O: first shard offset of raw shard `raw` at or after logical offset `ro` (Ceph `ro_offset_to_shard_offset`).
    pub fn ro_to_shard_bound(&self, ro: u64, raw: u32) -> u64 {
        let (s, c) = (u64::from(self.stripe_width), u64::from(self.chunk_size));
        let full = (ro / s) * c;
        let at = ((ro % s) / c) as u32;
        match raw.cmp(&at) {
            std::cmp::Ordering::Equal => full + ro % c,
            std::cmp::Ordering::Less => full + c,
            std::cmp::Ordering::Greater => full,
        }
    }

    /// Logical range `[off, off+len)` -> per data shard the touched shard range `(shard, shard_off, shard_len)`
    /// (one contiguous range per shard), shards in raw order, empty ranges omitted.
    pub fn ro_range_to_shard_extents(&self, off: u64, len: u64) -> Vec<(u32, u64, u64)> {
        let end = off.saturating_add(len);
        (0..self.k)
            .filter_map(|raw| {
                let a = self.ro_to_shard_bound(off, raw);
                let b = self.ro_to_shard_bound(end, raw);
                (b > a).then(|| (self.shard_of_raw(raw), a, b - a))
            })
            .collect()
    }

    /// Inverse of [`Self::ro_to_shard`] for data shards (`None` for parity / unknown shards).
    pub fn shard_to_ro(&self, shard: u32, shard_off: u64) -> Option<u64> {
        let raw = self.raw_of_shard(shard)?;
        if raw >= self.k {
            return None;
        }
        let c = u64::from(self.chunk_size);
        Some((shard_off / c) * u64::from(self.stripe_width) + u64::from(raw) * c + shard_off % c)
    }
}

/// Shard extents of optimized pools are 4 KiB aligned (`EC_ALIGN_SIZE`).
pub const OPT_ALIGN: u64 = 4096;

/// Mode O shard file size (ec-optimized.md 2.2): full stripes contribute `C` to every shard; the partial stripe
/// remainder fills raw data shards in order (`C` each); parity shards size like raw 0; rounded up to 4 KiB.
pub fn opt_shard_size(logical: u64, stripe_width: u64, chunk: u64, k: u32, raw: u32) -> u64 {
    if stripe_width == 0 || k == 0 {
        return 0;
    }
    let rem = logical % stripe_width;
    let mut size = (logical - rem) / u64::from(k);
    let raw = if raw >= k { 0 } else { u64::from(raw) };
    if rem > raw * chunk {
        size += (rem - raw * chunk).min(chunk);
    }
    size.next_multiple_of(OPT_ALIGN)
}

#[cfg(test)]
mod tests {
    use crate::gate::{EcMode, PoolEcInput, Verdict, evaluate};
    use std::collections::BTreeMap;

    fn facts(k: u32, m: u32, mapping: Option<&str>, chunk: u32) -> crate::EcFacts {
        let mut p: BTreeMap<String, String> = BTreeMap::new();
        p.insert("plugin".into(), "isa".into());
        p.insert("k".into(), k.to_string());
        p.insert("m".into(), m.to_string());
        if let Some(x) = mapping {
            p.insert("mapping".into(), x.into());
        }
        match evaluate(&PoolEcInput {
            size: k + m,
            min_size: k,
            stripe_width: k * chunk,
            flag_overwrites: false,
            flag_optimizations: false,
            flag_omap: false,
            profile: Some(&p),
            ..Default::default()
        }) {
            Verdict::Supported(f) => f,
            Verdict::Unsupported(r) => panic!("{r}"),
        }
    }

    #[test]
    fn shard_size_table() {
        let f = facts(2, 2, None, 4096);
        assert_eq!(f.mode, EcMode::L0);
        assert_eq!(f.shard_size(0), 0);
        assert_eq!(f.shard_size(1), 4096);
        assert_eq!(f.shard_size(8192), 4096);
        assert_eq!(f.shard_size(8193), 8192);
        assert_eq!(f.shard_size(5 * 8192 + 17), 6 * 4096);
    }

    #[test]
    fn ro_shard_examples() {
        let f = facts(4, 2, None, 4096);
        assert_eq!(f.ro_to_shard(0), (0, 0));
        assert_eq!(f.ro_to_shard(4096), (1, 0));
        assert_eq!(f.ro_to_shard(16384), (0, 4096));
        assert_eq!(f.ro_to_shard(16384 + 3 * 4096 + 5), (3, 4096 + 5));
        assert!(!f.is_parity_shard(3));
        assert!(f.is_parity_shard(4));
        assert!(!f.is_parity_shard(9));
    }

    #[test]
    fn bijection_property() {
        for (k, m, map) in [
            (2, 1, None),
            (4, 2, None),
            (2, 1, Some("_DD")),
            (3, 2, Some("D_DD_")),
        ] {
            let f = facts(k, m, map, 64);
            for raw in 0..k + m {
                assert_eq!(f.raw_of_shard(f.shard_of_raw(raw)), Some(raw));
            }
            let mut seen = std::collections::BTreeSet::new();
            for off in 0..(f.stripe_width as u64 * 6) {
                let (sh, so) = f.ro_to_shard(off);
                assert!(!f.is_parity_shard(sh));
                assert_eq!(f.shard_to_ro(sh, so), Some(off));
                assert!(seen.insert((sh, so)), "collision at {off}");
                assert!(so < f.shard_size(off + 1));
            }
            assert_eq!(f.shard_to_ro(f.shard_of_raw(k), 0), None);
        }
    }
}

#[cfg(test)]
mod opt_tests {
    use super::opt_shard_size;
    use crate::gate::{EcMode, PoolEcInput, Verdict, evaluate};
    use std::collections::BTreeMap;

    fn facts(k: u32, m: u32, mapping: Option<&str>, chunk: u32) -> crate::EcFacts {
        let mut p: BTreeMap<String, String> = BTreeMap::new();
        p.insert("plugin".into(), "isa".into());
        p.insert("k".into(), k.to_string());
        p.insert("m".into(), m.to_string());
        if let Some(x) = mapping {
            p.insert("mapping".into(), x.into());
        }
        let data: Vec<u32> = match mapping {
            None => (0..k).collect(),
            Some(s) => s
                .bytes()
                .enumerate()
                .filter(|(_, c)| *c == b'D')
                .map(|(i, _)| i as u32)
                .collect(),
        };
        match evaluate(&PoolEcInput {
            size: k + m,
            min_size: k,
            stripe_width: k * chunk,
            flag_optimizations: true,
            profile: Some(&p),
            nonprimary_shards: data[1..].to_vec(),
            ..Default::default()
        }) {
            Verdict::Supported(f) => f,
            Verdict::Unsupported(r) => panic!("{r}"),
        }
    }

    /// Frozen vectors (hand computed from spec 2.2), k=4 m=2 C=16K.
    #[test]
    fn shard_size_vectors() {
        let f = facts(4, 2, None, 16384);
        assert_eq!(f.mode, EcMode::Optimized);
        let rows: &[(u64, [u64; 6])] = &[
            (0, [0, 0, 0, 0, 0, 0]),
            (1, [4096, 0, 0, 0, 4096, 4096]),
            (4096, [4096, 0, 0, 0, 4096, 4096]),
            (4097, [8192, 0, 0, 0, 8192, 8192]),
            (16385, [16384, 4096, 0, 0, 16384, 16384]),
            (65536, [16384; 6]),
            (65536 + 40000, [32768, 32768, 24576, 16384, 32768, 32768]),
        ];
        for (n, want) in rows {
            let got: Vec<u64> = (0..6).map(|s| f.shard_size_opt(*n, s)).collect();
            assert_eq!(got, want.to_vec(), "n={n}");
        }
        assert!(f.is_nonprimary(1) && f.is_nonprimary(3));
        assert!(!f.is_nonprimary(0) && !f.is_nonprimary(4));
        // mapping "_DD": shard 0 = parity (sizes like raw 0 = shard 1), raw 1 = shard 2 nonprimary
        let f = facts(2, 1, Some("_DD"), 4096);
        assert_eq!(f.nonprimary, vec![2]);
        assert_eq!(
            [0, 1, 2].map(|s| f.shard_size_opt(4097, s)),
            [4096, 4096, 4096]
        );
        assert_eq!([0, 1, 2].map(|s| f.shard_size_opt(100, s)), [4096, 4096, 0]);
        assert_eq!(opt_shard_size(5, 0, 4096, 2, 0), 0);
    }

    #[test]
    fn extent_vectors() {
        let f = facts(4, 2, None, 4096);
        assert_eq!(
            f.ro_range_to_shard_extents(4196, 8192),
            vec![(1, 100, 3996), (2, 0, 4096), (3, 0, 100)]
        );
        assert_eq!(
            f.ro_range_to_shard_extents(0, 20480),
            vec![(0, 0, 8192), (1, 0, 4096), (2, 0, 4096), (3, 0, 4096)]
        );
        assert!(f.ro_range_to_shard_extents(7, 0).is_empty());
    }

    /// Every logical byte of a range lands in exactly the extent of its shard (k=3, C=64 via chunk 4096 scaled).
    #[test]
    fn extents_cover_bytes() {
        let f = facts(3, 1, Some("D_DD"), 4096);
        let s = u64::from(f.stripe_width);
        let mut x: u64 = 0x1234_5678;
        for _ in 0..300 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let off = (x >> 20) % (4 * s);
            let len = (x >> 40) % (3 * s);
            let ext = f.ro_range_to_shard_extents(off, len);
            assert_eq!(ext.iter().map(|e| e.2).sum::<u64>(), len);
            for b in [off, off + len / 2, (off + len).saturating_sub(1)] {
                if len == 0 {
                    break;
                }
                let (sh, so) = f.ro_to_shard(b);
                assert!(
                    ext.iter()
                        .any(|&(es, eo, el)| es == sh && so >= eo && so < eo + el),
                    "byte {b} off {off} len {len}"
                );
            }
            // the shard size formula covers every byte below the logical size
            let n = off + len;
            if n > 0 {
                let (sh, so) = f.ro_to_shard(n - 1);
                assert!(so < f.shard_size_opt(n, sh));
            }
        }
    }
}
