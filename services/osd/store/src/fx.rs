// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Fast non-cryptographic hasher (multiply/rotate, 8 bytes per step) for the engine's internal maps. Keys are
//! engine-generated (no adversarial input), so SipHash's DoS resistance is not needed on the hot path.

use std::hash::{BuildHasherDefault, Hasher};

const K: u64 = 0x517c_c1b7_2722_0a95;

#[derive(Default, Clone, Copy, Debug)]
pub struct FxHasher(u64);

impl FxHasher {
    #[inline]
    fn add(&mut self, w: u64) {
        self.0 = (self.0.rotate_left(5) ^ w).wrapping_mul(K);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn finish(&self) -> u64 {
        // hashbrown uses the top 7 bits for tags and the low bits for buckets: fold the high half down
        self.0 ^ (self.0 >> 32)
    }
    #[inline]
    fn write(&mut self, b: &[u8]) {
        let (cs, r) = b.as_chunks::<8>();
        for w in cs {
            self.add(u64::from_le_bytes(*w));
        }
        if !r.is_empty() {
            let mut t = [0u8; 8];
            t[..r.len()].copy_from_slice(r);
            self.add(u64::from_le_bytes(t) ^ ((r.len() as u64) << 56));
        }
    }
    #[inline]
    fn write_u8(&mut self, v: u8) {
        self.add(v as u64);
    }
    #[inline]
    fn write_u32(&mut self, v: u32) {
        self.add(v as u64);
    }
    #[inline]
    fn write_u64(&mut self, v: u64) {
        self.add(v);
    }
    #[inline]
    fn write_usize(&mut self, v: usize) {
        self.add(v as u64);
    }
}

pub type FxBuild = BuildHasherDefault<FxHasher>;
pub type FxMap<K, V> = std::collections::HashMap<K, V, FxBuild>;
pub type FxSet<K> = std::collections::HashSet<K, FxBuild>;
