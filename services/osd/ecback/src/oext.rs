// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Extent sets and optimized-EC geometry helpers (ec-optimized.md 2.1/2.2): pure functions of (k, C).

/// Sorted, disjoint, non-adjacent `[off, end)` intervals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ext(Vec<(u64, u64)>);

impl Ext {
    pub fn new() -> Ext {
        Ext(Vec::new())
    }

    pub fn of(off: u64, end: u64) -> Ext {
        let mut e = Ext::new();
        e.insert(off, end);
        e
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `(off, end)` intervals ascending.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.0.iter().copied()
    }

    pub fn first(&self) -> Option<u64> {
        self.0.first().map(|x| x.0)
    }

    pub fn last_end(&self) -> Option<u64> {
        self.0.last().map(|x| x.1)
    }

    /// Test helper: bytes asked of the shards (allocation checks).
    #[cfg(test)]
    pub fn bytes(&self) -> u64 {
        self.0.iter().map(|(a, b)| b - a).sum()
    }

    /// Add `[off, end)` (merging overlapping or adjacent intervals).
    pub fn insert(&mut self, off: u64, end: u64) {
        if off >= end {
            return;
        }
        let (mut lo, mut hi) = (off, end);
        // first interval that could touch: end >= lo
        let i = self.0.partition_point(|x| x.1 < lo);
        let mut j = i;
        while j < self.0.len() && self.0[j].0 <= hi {
            lo = lo.min(self.0[j].0);
            hi = hi.max(self.0[j].1);
            j += 1;
        }
        self.0.splice(i..j, [(lo, hi)]);
    }

    pub fn union(&mut self, o: &Ext) {
        for (a, b) in o.iter() {
            self.insert(a, b);
        }
    }

    /// Remove `[off, end)`.
    pub fn erase(&mut self, off: u64, end: u64) {
        if off >= end {
            return;
        }
        // in place: the intervals [i, j) overlap, at most the two cut ends survive (no allocation unless one interval
        // splits in two)
        let i = self.0.partition_point(|x| x.1 <= off);
        let j = i + self.0[i..].partition_point(|x| x.0 < end);
        if i == j {
            return;
        }
        let (a, b) = (self.0[i].0, self.0[j - 1].1);
        let left = (a < off).then_some((a, off));
        let right = (b > end).then_some((end, b));
        self.0.splice(i..j, left.into_iter().chain(right));
    }

    pub fn subtract(&mut self, o: &Ext) {
        for (a, b) in o.iter() {
            self.erase(a, b);
        }
    }

    /// Keep only `[off, end)`.
    pub fn clip(&mut self, off: u64, end: u64) {
        self.erase(0, off);
        self.erase(end, u64::MAX);
    }

    /// Every interval widened to multiples of `a` (a power of two).
    pub fn align_out(&self, a: u64) -> Ext {
        let mut out = Ext::new();
        for (x, y) in self.iter() {
            out.insert(x & !(a - 1), y.next_multiple_of(a));
        }
        out
    }

    pub fn contains_range(&self, off: u64, end: u64) -> bool {
        off >= end || self.0.iter().any(|(a, b)| *a <= off && end <= *b)
    }

    pub fn intersects(&self, off: u64, end: u64) -> bool {
        self.0.iter().any(|(a, b)| *a < end && off < *b)
    }
}

/// Optimized-EC geometry over RAW shard indices (0..k data, k..k+m parity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geo {
    pub k: u64,
    pub c: u64,
}

impl Geo {
    pub fn s(&self) -> u64 {
        self.k * self.c
    }

    /// Shard size of raw shard `raw` for logical size `n`.
    pub fn shard_size(&self, n: u64, raw: usize) -> u64 {
        ec::geom::opt_shard_size(n, self.k * self.c, self.c, self.k as u32, raw as u32)
    }

    /// Shard size WITHOUT 4096 rounding (bytes of real data in the column).
    pub fn shard_data_len(&self, n: u64, raw: usize) -> u64 {
        let s = self.s();
        let rem = n % s;
        let r = if raw as u64 >= self.k { 0 } else { raw as u64 };
        let mut z = (n - rem) / self.k;
        if rem > r * self.c {
            z += (rem - r * self.c).min(self.c);
        }
        z
    }

    /// Logical range `[off, end)` -> per raw data shard extents at shard offsets (`out[raw]`, len k).
    pub fn ro_to_shards(&self, off: u64, end: u64, out: &mut [Ext]) {
        let (s, c) = (self.s(), self.c);
        let mut pos = off;
        while pos < end {
            let stripe = pos / s;
            let in_s = pos % s;
            let raw = (in_s / c) as usize;
            let in_c = in_s % c;
            let n = (c - in_c).min(end - pos);
            let so = stripe * c + in_c;
            out[raw].insert(so, so + n);
            pos += n;
        }
    }

    /// Logical offset of shard offset `so` on raw data shard `raw`.
    pub fn shard_to_ro(&self, raw: usize, so: u64) -> u64 {
        (so / self.c) * self.s() + raw as u64 * self.c + so % self.c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_ops() {
        let mut e = Ext::new();
        e.insert(10, 20);
        e.insert(30, 40);
        e.insert(20, 25);
        assert_eq!(e.0, vec![(10, 25), (30, 40)]);
        e.insert(0, 100);
        assert_eq!(e.0, vec![(0, 100)]);
        e.erase(10, 20);
        assert_eq!(e.0, vec![(0, 10), (20, 100)]);
        let o = Ext::of(5, 25);
        let mut x = e.clone();
        x.subtract(&o);
        assert_eq!(x.0, vec![(0, 5), (25, 100)]);
        assert_eq!(Ext::of(1, 4097).align_out(4096).0, vec![(0, 8192)]);
        assert!(e.contains_range(20, 100) && !e.contains_range(9, 11));
        e.clip(8, 30);
        assert_eq!(e.0, vec![(8, 10), (20, 30)]);
    }

    #[test]
    fn erase_matches_a_byte_model() {
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut r = |n: u64| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s % n
        };
        for _ in 0..2000 {
            let (mut e, mut m) = (Ext::new(), [false; 64]);
            for _ in 0..r(6) {
                let (a, l) = (r(60), 1 + r(10));
                e.insert(a, (a + l).min(64));
                m[a as usize..(a + l).min(64) as usize].fill(true);
            }
            let (a, l) = (r(64), r(30));
            e.erase(a, a + l);
            m[a as usize..(a + l).min(64) as usize].fill(false);
            let mut want = Ext::new();
            for (i, _) in m.iter().enumerate().filter(|x| *x.1) {
                want.insert(i as u64, i as u64 + 1);
            }
            assert_eq!(e, want, "erase [{a}, {})", a + l);
        }
    }

    #[test]
    fn ro_map() {
        let g = Geo { k: 4, c: 16384 };
        let mut v = vec![Ext::new(); 4];
        // 20000 bytes at 10000: raw0 [10000,16384), raw1 [0, 13616)
        g.ro_to_shards(10000, 30000, &mut v);
        assert_eq!(v[0].0, vec![(10000, 16384)]);
        assert_eq!(v[1].0, vec![(0, 13616)]);
        assert!(v[2].is_empty());
        let mut v = vec![Ext::new(); 4];
        g.ro_to_shards(0, 2 * 65536 + 1, &mut v);
        assert_eq!(v[0].0, vec![(0, 32769)]);
        assert_eq!(v[3].0, vec![(0, 32768)]);
        for raw in 0..4 {
            for so in [0u64, 5, 16383, 16384, 40000] {
                let ro = g.shard_to_ro(raw, so);
                let mut w = vec![Ext::new(); 4];
                g.ro_to_shards(ro, ro + 1, &mut w);
                assert_eq!(w[raw].0, vec![(so, so + 1)]);
            }
        }
        assert_eq!(g.shard_data_len(65536 + 20000, 1), 16384 + 3616);
    }
}
