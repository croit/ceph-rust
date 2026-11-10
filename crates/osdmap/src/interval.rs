// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! interval_set<snapid>: wire = u32 n + n * (u64 start, u64 len).

use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::BTreeMap;

/// Disjoint, non-adjacent-merged `[start, start+len)` ranges keyed by start.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntervalSet(pub BTreeMap<u64, u64>);

impl IntervalSet {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn contains(&self, v: u64) -> bool {
        self.0
            .range(..=v)
            .next_back()
            .is_some_and(|(s, l)| v < s.saturating_add(*l))
    }
    /// Insert a range, merging overlapping/adjacent neighbours.
    pub fn insert(&mut self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        let mut s = start;
        let mut e = start.saturating_add(len);
        if let Some((&ps, &pl)) = self.0.range(..=s).next_back() {
            let pe = ps.saturating_add(pl);
            if pe >= s {
                s = ps;
                e = e.max(pe);
            }
        }
        let overl: Vec<u64> = self.0.range(s..=e).map(|(k, _)| *k).collect();
        for k in overl {
            let l = self.0.remove(&k).unwrap_or(0);
            e = e.max(k.saturating_add(l));
        }
        self.0.insert(s, e - s);
    }
    pub fn union_with(&mut self, o: &IntervalSet) {
        for (s, l) in &o.0 {
            self.insert(*s, *l);
        }
    }
    /// Remove a range.
    pub fn erase(&mut self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        let e = start.saturating_add(len);
        let hit: Vec<(u64, u64)> = self
            .erase_candidates(start, e)
            .filter(|(s, l)| s.saturating_add(**l) > start)
            .map(|(s, l)| (*s, *l))
            .collect();
        for (s, l) in hit {
            self.0.remove(&s);
            let se = s.saturating_add(l);
            if s < start {
                self.0.insert(s, start - s);
            }
            if se > e {
                self.0.insert(e, se - e);
            }
        }
    }
    fn erase_candidates(
        &self,
        start: u64,
        end: u64,
    ) -> std::collections::btree_map::Range<'_, u64, u64> {
        // Only the predecessor can begin before `start` and still overlap it.
        // Seeking it avoids re-scanning untouched prefixes for every purge.
        let first = self
            .0
            .range(..=start)
            .next_back()
            .map_or(start, |(&s, _)| s);
        self.0.range(first..end)
    }
    pub fn subtract(&mut self, o: &IntervalSet) {
        for (s, l) in &o.0 {
            self.erase(*s, *l);
        }
    }
}

impl Encode for IntervalSet {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.count(self.0.len())?;
        for (s, l) in &self.0 {
            e.u64(*s)?;
            e.u64(*l)?;
        }
        Ok(())
    }
}
impl<'a> Decode<'a> for IntervalSet {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        let n = d.count()?;
        let mut m = BTreeMap::new();
        for _ in 0..n {
            let s = d.u64()?;
            let l = d.u64()?;
            m.insert(s, l);
        }
        Ok(IntervalSet(m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erase_does_not_scan_unrelated_prefix() {
        let mut s = IntervalSet::default();
        for i in 0..4096 {
            s.insert(i * 4, 2);
        }
        let start = 4095 * 4 + 1;
        // A suffix deletion intersects one interval; its cost must not grow
        // with the number of untouched earlier removed-snapshot ranges.
        assert_eq!(s.erase_candidates(start, start + 1).count(), 1);
        s.erase(start, 1);
        assert_eq!(s.0.len(), 4096);
        assert_eq!(s.0[&(4095 * 4)], 1);
        assert!(s.contains(4095 * 4));
        assert!(!s.contains(start));
        assert_eq!(s.0[&0], 2);
    }

    #[test]
    fn erase_preserves_exact_membership_across_gaps_and_splits() {
        let mut original = IntervalSet::default();
        for (start, len) in [(2, 4), (9, 2), (14, 7)] {
            original.insert(start, len);
        }
        for start in 0..24 {
            for len in 0..24 {
                let mut erased = original.clone();
                erased.erase(start, len);
                for point in 0..24 {
                    assert_eq!(
                        erased.contains(point),
                        original.contains(point) && !(start..start + len).contains(&point),
                        "erase [{start}, {}), point {point}",
                        start + len
                    );
                }
            }
        }
    }

    #[test]
    fn merge_and_erase() {
        let mut s = IntervalSet::default();
        s.insert(1, 2);
        s.insert(5, 2);
        s.insert(3, 2);
        assert_eq!(s.0.len(), 1);
        assert_eq!(s.0[&1], 6);
        s.erase(3, 1);
        assert_eq!(s.0.iter().collect::<Vec<_>>(), vec![(&1, &2), (&4, &3)]);
        assert!(s.contains(4) && !s.contains(3));
        let mut o = IntervalSet::default();
        o.insert(1, 2);
        o.insert(4, 3);
        s.subtract(&o);
        assert!(s.is_empty());
    }
}
