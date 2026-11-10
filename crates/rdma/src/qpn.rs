// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Map keyed by QP number for the per-completion lookups: the QPN is a small integer handed out by the device, so a
//! multiplicative hash replaces SipHash (a few cycles instead of ~20 ns per completion). Not for untrusted keys; the
//! QPNs are the local device's own.
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

#[derive(Debug, Default, Clone, Copy)]
pub struct QpnHasher(u64);

impl Hasher for QpnHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0.rotate_left(8) ^ u64::from(b)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
    }

    fn write_u32(&mut self, n: u32) {
        self.0 = u64::from(n).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    fn finish(&self) -> u64 {
        self.0 ^ (self.0 >> 32)
    }
}

/// `HashMap` keyed by QPN with [`QpnHasher`].
pub type QpnMap<V> = HashMap<u32, V, BuildHasherDefault<QpnHasher>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_and_strided_qpns_spread_over_buckets() {
        for stride in [1u32, 2, 4, 64, 256] {
            let mut buckets = [0u32; 256];
            for i in 0..4096u32 {
                let mut h = QpnHasher::default();
                h.write_u32(0x100 + i * stride);
                buckets[(h.finish() & 255) as usize] += 1;
            }
            let max = *buckets.iter().max().unwrap();
            assert!(max <= 64, "stride {stride}: worst bucket {max} of 4096/256");
        }
    }

    #[test]
    fn works_as_a_map() {
        let mut m: QpnMap<u64> = QpnMap::default();
        for q in 0..1000u32 {
            m.insert(q * 3 + 7, u64::from(q));
        }
        assert_eq!(m.get(&(500 * 3 + 7)), Some(&500));
        assert_eq!(m.remove(&7), Some(0));
        assert_eq!(m.len(), 999);
    }
}
