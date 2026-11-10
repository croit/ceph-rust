// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `interval_set<u64>` = map<start, len> (spec replication.md 6.2) plus the few set operations the
//! recovery paths need.

use std::collections::BTreeMap;

pub type IntervalSet = BTreeMap<u64, u64>;

/// End (exclusive) of the last interval, 0 if empty (saturating: an end past `u64::MAX` is `u64::MAX`).
pub fn range_end(s: &IntervalSet) -> u64 {
    s.iter()
        .next_back()
        .map_or(0, |(&a, &l)| a.saturating_add(l))
}

/// Sum of lengths (saturating).
pub fn total(s: &IntervalSet) -> u64 {
    s.values().fold(0u64, |t, &l| t.saturating_add(l))
}

/// Wire acceptance (spec replication.md 6.2): every `start + len` fits `u64` and each interval starts at or after the
/// end of the previous one (no overlap; touching is allowed, zero lengths are harmless). Returns the exact sum of the
/// lengths, `None` = malformed set.
pub fn checked_total(s: &IntervalSet) -> Option<u64> {
    let (mut end, mut sum) = (0u64, 0u64);
    for (&a, &l) in s {
        if a < end {
            return None;
        }
        end = a.checked_add(l)?;
        sum = sum.checked_add(l)?;
    }
    Some(sum)
}

/// Decode an interval set from a peer and reject a malformed one ([`checked_total`]).
pub fn decode_checked(d: &mut denc::Decoder<'_>) -> denc::Result<IntervalSet> {
    let s: IntervalSet = denc::Decode::decode(d)?;
    checked_total(&s).ok_or(denc::Error::BadValue(
        "interval_set: overlapping or overflowing intervals",
    ))?;
    Ok(s)
}

/// Insert `[off, off+len)` merging neighbours/overlaps.
pub fn insert(s: &mut IntervalSet, off: u64, len: u64) {
    if len == 0 {
        return;
    }
    let (mut a, mut b) = (off, off.saturating_add(len));
    let hits: Vec<u64> = insert_candidates(s, a, b)
        .filter(|&(&st, &l)| st.saturating_add(l) >= a)
        .map(|(&st, _)| st)
        .collect();
    for st in hits {
        let l = s.remove(&st).unwrap_or(0);
        a = a.min(st);
        b = b.max(st.saturating_add(l));
    }
    s.insert(a, b - a);
}

fn insert_candidates(
    s: &IntervalSet,
    start: u64,
    end: u64,
) -> std::collections::btree_map::Range<'_, u64, u64> {
    let first = s.range(..=start).next_back().map_or(start, |(&a, _)| a);
    s.range(first..=end)
}

/// `s ∩ [lo, hi)` for disjoint intervals.
pub fn intersect_range(s: &IntervalSet, lo: u64, hi: u64) -> IntervalSet {
    let mut r = IntervalSet::new();
    if lo >= hi {
        return r;
    }
    for (&a, &l) in intersect_candidates(s, lo, hi) {
        let (x, y) = (a.max(lo), a.saturating_add(l).min(hi));
        if x < y {
            r.insert(x, y - x);
        }
    }
    r
}

fn intersect_candidates(
    s: &IntervalSet,
    lo: u64,
    hi: u64,
) -> std::collections::btree_map::Range<'_, u64, u64> {
    // Disjoint intervals: only the predecessor can start before lo and
    // intersect it. Do not revisit unrelated fragments for every range in
    // an overlap-chain intersection (rollback and recovery).
    let first = s.range(..=lo).next_back().map_or(lo, |(&a, _)| a);
    s.range(first..hi)
}

/// `[lo, hi) \ s` as a set.
pub fn complement_in(s: &IntervalSet, lo: u64, hi: u64) -> IntervalSet {
    let mut r = IntervalSet::new();
    let mut cur = lo;
    for (&a, &l) in s {
        let e = a.saturating_add(l);
        if e <= cur {
            continue;
        }
        if a >= hi {
            break;
        }
        if a > cur {
            r.insert(cur, a - cur);
        }
        cur = cur.max(e);
    }
    if cur < hi {
        r.insert(cur, hi - cur);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_overlap_intersection_has_bounded_visits() {
        let s: IntervalSet = (0..4096).map(|i| (i * 4, 2)).collect();
        let mut visits = 0;
        let mut result = IntervalSet::new();
        for (&a, &l) in &s {
            visits += intersect_candidates(&s, a, a + l).count();
            result.extend(intersect_range(&s, a, a + l));
        }
        assert_eq!(result, s, "rollback/recovery overlap intersection is exact");
        assert_eq!(visits, s.len(), "one relevant fragment per range");
        assert_eq!(
            intersect_range(&s, 1, 5),
            IntervalSet::from([(1, 1), (4, 1)])
        );
        assert!(intersect_range(&s, 2, 4).is_empty());
        assert!(intersect_range(&s, 8, 8).is_empty());
        assert!(intersect_range(&s, 9, 8).is_empty());
        assert!(intersect_range(&s, 20000, 20010).is_empty());
    }
    #[test]
    fn insert_does_not_scan_unrelated_prefix() {
        let mut s: IntervalSet = (0..4096).map(|i| (i * 4, 2)).collect();
        assert!(insert_candidates(&s, 16384, 16386).count() <= 1);
        insert(&mut s, 16384, 2);
        assert_eq!(s.len(), 4097);
        insert(&mut s, 16381, 3);
        assert_eq!(s[&16380], 6);
        assert_eq!(s.len(), 4096);
    }
    #[test]
    fn ops() {
        let mut s = IntervalSet::new();
        insert(&mut s, 10, 5);
        insert(&mut s, 15, 5);
        insert(&mut s, 30, 5);
        assert_eq!(
            s.iter().map(|(a, l)| (*a, *l)).collect::<Vec<_>>(),
            [(10, 10), (30, 5)]
        );
        assert_eq!(range_end(&s), 35);
        assert_eq!(total(&s), 15);
        let c = complement_in(&s, 0, 40);
        assert_eq!(
            c.iter().map(|(a, l)| (*a, *l)).collect::<Vec<_>>(),
            [(0, 10), (20, 10), (35, 5)]
        );
        let i = intersect_range(&s, 12, 32);
        assert_eq!(
            i.iter().map(|(a, l)| (*a, *l)).collect::<Vec<_>>(),
            [(12, 8), (30, 2)]
        );
    }

    /// E1 regression: overflowing / overlapping sets are rejected, the helpers never overflow.
    #[test]
    fn malformed_sets() {
        let wrap = IntervalSet::from([(0, 1), (1, u64::MAX)]);
        assert_eq!(checked_total(&wrap), None);
        assert_eq!(total(&wrap), u64::MAX);
        assert_eq!(range_end(&wrap), u64::MAX);
        assert_eq!(checked_total(&IntervalSet::from([(0, 10), (5, 1)])), None);
        assert_eq!(
            checked_total(&IntervalSet::from([(0, 10), (10, 1)])),
            Some(11)
        );
        assert_eq!(
            checked_total(&IntervalSet::from([(0, u64::MAX)])),
            Some(u64::MAX)
        );
        let mut s = IntervalSet::from([(u64::MAX - 1, 1)]);
        insert(&mut s, u64::MAX - 4, u64::MAX);
        assert_eq!(range_end(&s), u64::MAX);
        let _ = complement_in(&wrap, 0, u64::MAX);
        let _ = intersect_range(&wrap, 0, u64::MAX);
        let bytes = denc::to_vec(&wrap).expect("encode");
        assert!(decode_checked(&mut denc::Decoder::new(&bytes)).is_err());
    }
}
