// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Replicated acting choice of a stretch pool (doc/spec/stretch.md 4): `calc_replicated_acting` with bucket diversity.
//! Usable up members first (no cap), then the mandatory bucket, then the bucket with the fewest selected members, each
//! bucket capped at `ceil(size / peering_crush_bucket_target)`. Pure: the caller classifies the peers.

use denc::types::Eversion;
use pgwire::{NONE_OSD, OsdMapView, PoolParams};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// What the acting choice needs of one peer with an info (peer infos + own).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fit {
    /// Info complete and `last_update >= oldest_auth_log_entry` (stretch.md 4.2).
    pub usable: bool,
    pub last_update: Eversion,
}

/// Result of [`calc_replicated_acting_stretch`]: `want` in choice order (primary first; may be short or exceed
/// `size` by nothing; can_peer not guaranteed), plus the members to recover / backfill.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Pick {
    pub want: Vec<i32>,
    pub acting_backfill: BTreeSet<i32>,
    pub backfill: BTreeSet<i32>,
}

/// Candidate sort key (stretch.md 4.4): current acting members (`tag` 0) before other peers (1), then the OLDEST
/// `last_update` first, then osd id.
type Key = (u8, Eversion, i32);

/// stretch.md 4.3-4.6. `infos`: every peer with an info (absent = no info: an up member without one is skipped, like
/// the plain path). `restrict` = restrict_to_up_acting (no other peers). Other peers must be up in `map`.
pub(crate) fn calc_replicated_acting_stretch(
    pool: &PoolParams,
    map: &dyn OsdMapView,
    primary: i32,
    up: &[i32],
    acting: &[i32],
    infos: &BTreeMap<i32, Fit>,
    restrict: bool,
) -> Pick {
    let size = pool.size as usize;
    let bucket = |o: i32| map.barrier_bucket(o, pool.peering_crush_bucket_barrier, pool.crush_rule);
    let mut r = Pick {
        want: vec![primary],
        acting_backfill: BTreeSet::from([primary]),
        backfill: BTreeSet::new(),
    };
    let mut selected: BTreeMap<i32, usize> = BTreeMap::new();
    *selected.entry(bucket(primary)).or_default() += 1;
    // 4.3 phase 1: usable up members in up order, no cap
    for &o in up {
        if o == primary || o < 0 || o == NONE_OSD {
            continue;
        }
        let Some(f) = infos.get(&o) else { continue };
        if !f.usable {
            r.backfill.insert(o);
            r.acting_backfill.insert(o);
        } else if !r.want.contains(&o) {
            r.want.push(o);
            r.acting_backfill.insert(o);
            *selected.entry(bucket(o)).or_default() += 1;
        }
    }
    if r.want.len() >= size {
        return r;
    }
    // 4.4 phase 2 candidates, distributed into per-bucket queues in sort order
    let mut cands: Vec<Key> = Vec::new();
    for &o in acting {
        if o < 0 || o == NONE_OSD || r.want.contains(&o) {
            continue;
        }
        if let Some(f) = infos.get(&o).filter(|f| f.usable) {
            cands.push((0, f.last_update, o));
        }
    }
    if !restrict {
        for (&o, f) in infos {
            if f.usable && !r.want.contains(&o) && !acting.contains(&o) && map.is_up(o) {
                cands.push((1, f.last_update, o));
            }
        }
    }
    cands.sort_unstable();
    let mut queues: BTreeMap<i32, VecDeque<Key>> = BTreeMap::new();
    for c in cands {
        queues.entry(bucket(c.2)).or_default().push_back(c);
    }
    // 4.5 mandatory member first
    let m = pool.peering_crush_mandatory_member;
    if m != NONE_OSD && selected.get(&m).copied().unwrap_or(0) == 0 {
        take(&mut queues, m, &mut r, &mut selected);
    }
    // 4.6 fill: fewest selected first, capped; tie -> the bucket whose head sorts last
    let cap = match pool.peering_crush_bucket_target {
        0 => usize::MAX,
        t => size.div_ceil(t as usize),
    };
    while r.want.len() < size {
        let best = queues
            .iter()
            .filter_map(|(b, q)| {
                let n = selected.get(b).copied().unwrap_or(0);
                q.front()
                    .filter(|_| n < cap)
                    .map(|h| (std::cmp::Reverse(n), *h, *b))
            })
            .max();
        let Some((_, _, b)) = best else { break };
        take(&mut queues, b, &mut r, &mut selected);
    }
    r
}

/// Move the head candidate of bucket `b` into `want`.
fn take(
    queues: &mut BTreeMap<i32, VecDeque<Key>>,
    b: i32,
    r: &mut Pick,
    selected: &mut BTreeMap<i32, usize>,
) {
    if let Some((_, _, o)) = queues.get_mut(&b).and_then(|q| q.pop_front()) {
        r.want.push(o);
        r.acting_backfill.insert(o);
        *selected.entry(b).or_default() += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth::SynthMap;

    const A: i32 = -3;
    const B: i32 = -10;
    const C: i32 = -20;

    fn ev(v: u64) -> Eversion {
        Eversion::new(5, v)
    }

    /// osd -> site; every osd up.
    fn map(sites: &[(i32, i32)]) -> SynthMap {
        let mut m = SynthMap::new(10);
        for (o, s) in sites {
            m = m.with_osd(*o, 1);
            m.barrier.insert(*o, *s);
        }
        m
    }

    fn pool(size: u32, count: u32, target: u32, member: i32) -> PoolParams {
        PoolParams {
            size,
            min_size: 1,
            crush_rule: 1,
            peering_crush_bucket_count: count,
            peering_crush_bucket_target: target,
            peering_crush_bucket_barrier: 8,
            peering_crush_mandatory_member: member,
            ..Default::default()
        }
    }

    fn fits(v: &[(i32, bool, u64)]) -> BTreeMap<i32, Fit> {
        v.iter()
            .map(|(o, u, lu)| {
                (
                    *o,
                    Fit {
                        usable: *u,
                        last_update: ev(*lu),
                    },
                )
            })
            .collect()
    }

    fn set(v: &[i32]) -> BTreeSet<i32> {
        v.iter().copied().collect()
    }

    #[test]
    fn up_members_first_without_cap() {
        let m = map(&[(0, A), (1, A), (2, A), (3, B)]);
        let p = pool(4, 2, 2, NONE_OSD);
        let i = fits(&[(0, true, 9), (1, true, 9), (2, true, 9), (3, true, 9)]);
        let r = calc_replicated_acting_stretch(&p, &m, 1, &[0, 1, 2, 3], &[0, 1, 2, 3], &i, false);
        // three in site A although the cap is 2: phase 1 ignores it
        assert_eq!(r.want, vec![1, 0, 2, 3]);
        assert_eq!(r.acting_backfill, set(&[0, 1, 2, 3]));
        assert!(r.backfill.is_empty());
    }

    #[test]
    fn cap_and_fewest_bucket_first() {
        // oracle-like: sites A = {0,1,2}, B = {3,4,5}; up [0,4], 4 needs backfill; strays 1,2,3 hold the PG
        let m = map(&[(0, A), (1, A), (2, A), (3, B), (4, B), (5, B)]);
        let p = pool(4, 2, 2, NONE_OSD);
        let i = fits(&[
            (0, true, 9),
            (1, true, 9),
            (2, true, 9),
            (3, true, 9),
            (4, false, 0),
        ]);
        let r = calc_replicated_acting_stretch(&p, &m, 0, &[0, 4], &[0, 4], &i, false);
        // B (0 selected) first, then A up to its cap 2; 2 stays out although size is not reached
        assert_eq!(r.want, vec![0, 3, 1]);
        assert_eq!(r.backfill, set(&[4]));
        assert_eq!(r.acting_backfill, set(&[0, 1, 3, 4]));
        // restrict_to_up_acting: no other peers
        let r = calc_replicated_acting_stretch(&p, &m, 0, &[0, 4], &[0, 4], &i, true);
        assert_eq!(r.want, vec![0]);
        // no target = no cap
        let p0 = pool(4, 2, 0, NONE_OSD);
        let r = calc_replicated_acting_stretch(&p0, &m, 0, &[0, 4], &[0, 4], &i, false);
        assert_eq!(r.want, vec![0, 3, 1, 2]);
    }

    #[test]
    fn candidate_order_is_literal() {
        // A = {0,1,2}, B = {3,4}; primary 0 alone in up; acting members 1 (A) and 3 (B), other peers 2 (A), 4 (B)
        let m = map(&[(0, A), (1, A), (2, A), (3, B), (4, B)]);
        let p = pool(3, 2, 1, NONE_OSD); // cap 3: only the fewest/tie rules decide
        // within a bucket: acting before other, then oldest last_update first
        let i = fits(&[
            (0, true, 9),
            (1, true, 9),
            (2, true, 9),
            (3, true, 7),
            (4, true, 8),
        ]);
        let r = calc_replicated_acting_stretch(&p, &m, 0, &[0], &[0, 1, 3], &i, false);
        // B has 0 selected -> head 3 (acting); tie A 1 / B 1: heads 1 (acting, 9) vs 4 (other, 8): other sorts last
        assert_eq!(r.want, vec![0, 3, 4]);
        // equal tags: the newer head sorts last
        let i = fits(&[
            (0, true, 9),
            (1, true, 9),
            (2, true, 9),
            (3, true, 5),
            (4, true, 6),
        ]);
        let r = calc_replicated_acting_stretch(&p, &m, 0, &[0], &[0, 1, 3, 4], &i, false);
        // B: [3 (5), 4 (6)] -> 3 first (oldest); tie A 1 [1 (9)] vs B 1 [4 (6)]: 1 is newer -> A
        assert_eq!(r.want, vec![0, 3, 1]);
    }

    #[test]
    fn mandatory_bucket_first() {
        let m = map(&[(0, A), (1, B), (2, C)]);
        let i = fits(&[(0, true, 9), (1, true, 9), (2, true, 9)]);
        // without a mandatory member B wins the tie (other peer 1 sorts after acting member 2)
        let p = pool(2, 2, 2, NONE_OSD);
        let r = calc_replicated_acting_stretch(&p, &m, 0, &[0], &[0, 2], &i, false);
        assert_eq!(r.want, vec![0, 1]);
        let p = pool(2, 2, 2, C);
        let r = calc_replicated_acting_stretch(&p, &m, 0, &[0], &[0, 2], &i, false);
        assert_eq!(r.want, vec![0, 2]);
        // mandatory bucket already selected: no extra pick
        let p = pool(2, 2, 2, A);
        let r = calc_replicated_acting_stretch(&p, &m, 0, &[0], &[0, 2], &i, false);
        assert_eq!(r.want, vec![0, 1]);
    }

    #[test]
    fn unusable_and_down_peers_stay_out() {
        let mut m = map(&[(0, A), (1, A), (2, B), (3, B)]);
        m.osds.get_mut(&3).unwrap().up = false;
        let p = pool(4, 2, 2, NONE_OSD);
        // 1: up but behind the auth log -> backfill; 2: acting, incomplete -> out; 3: down other peer -> out
        let i = fits(&[(0, true, 9), (1, false, 1), (2, false, 1), (3, true, 9)]);
        let r = calc_replicated_acting_stretch(&p, &m, 0, &[0, 1], &[0, 2], &i, false);
        assert_eq!(r.want, vec![0]);
        assert_eq!(r.backfill, set(&[1]));
        assert_eq!(r.acting_backfill, set(&[0, 1]));
    }
}
