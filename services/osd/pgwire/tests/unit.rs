// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Spec hex vectors, builders, interval logic over synthetic map histories, missing/log rules.

use denc::types::{Eversion, Hobject, OsdReqId, PgT, ShardId, SnapId, SpgT, Timespan, UTime};
use denc::{Encode, from_slice};
use pgwire::intervals::{NONE_OSD, is_split, stable_mod};
use pgwire::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

fn td(p: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../testdata/pgwire")
            .join(p),
    )
    .unwrap()
}
fn ev(e: u32, v: u64) -> Eversion {
    Eversion::new(e, v)
}
fn obj(name: &str) -> Hobject {
    Hobject::new(
        name.as_bytes(),
        SnapId::NOSNAP,
        name.len() as u32 * 77,
        1,
        b"",
    )
}

// ---- spec hex vectors (test-vectors-m2.md 4) ----------------------------------------------

#[test]
fn spec_hex_vectors() {
    // 2. unrollbackable mod_desc
    assert_eq!(
        ObjectModDesc::unrollbackable().encode_to_vec().unwrap(),
        [1, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    // 3. default clean regions (28 B) and fully dirty (12 B)
    let mut d = vec![1, 1, 0x16, 0, 0, 0, 1, 0, 0, 0];
    d.extend([0u8; 8]);
    d.extend([0xffu8; 8]);
    d.extend([1, 0]);
    assert_eq!(ObjectCleanRegions::default().encode_to_vec().unwrap(), d);
    assert_eq!(d.len(), 28);
    assert_eq!(
        ObjectCleanRegions::fully_dirty().encode_to_vec().unwrap(),
        [1, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    // 4. pg_missing_item need=5'6 have=5'1 (61 B)
    let mut item = vec![0u8; 12];
    item.extend([0xffu8; 12]);
    item.extend([6, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0]);
    item.extend([1, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0]);
    item.push(0);
    item.extend([1, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let mi = MissingItem::new(ev(5, 6), ev(5, 1), false);
    assert_eq!(mi.encode_to_vec().unwrap(), item);
    assert_eq!(item.len(), 61);
    assert_eq!(from_slice::<MissingItem>(&item).unwrap(), mi);
    // 5. hit set default (65 B)
    let mut hs = vec![1, 1, 0x3b, 0, 0, 0];
    hs.extend([0u8; 12 + 8]);
    hs.extend([2, 1, 0x1d, 0, 0, 0]);
    hs.extend([0u8; 8 + 8 + 12]);
    hs.push(1);
    hs.extend([0u8; 4]);
    assert_eq!(PgHitSetHistory::default().encode_to_vec().unwrap(), hs);
    // 7. shard_id_set empty
    assert_eq!(ShardIdSet::default().encode_to_vec().unwrap(), [0, 0]);
    // pg_lease_t: 1.5 s = i32 sec, i32 nsec
    let l = PgLease {
        interval: Timespan {
            sec: 1,
            nsec: 500_000_000,
        },
        ..Default::default()
    };
    let b = l.encode_to_vec().unwrap();
    assert_eq!(b.len(), 30);
    assert_eq!(&b[22..30], &[1, 0, 0, 0, 0x00, 0x65, 0xcd, 0x1d]);
}

// ---- version gates / robustness -----------------------------------------------------------

#[test]
fn unknown_trailing_bytes_inside_envelope_are_skipped() {
    // bump struct_len and append junk: decoder must ignore it (peering.md / test-vectors-m2 5.5)
    fn grow(mut b: Vec<u8>, extra: usize) -> Vec<u8> {
        let l = u32::from_le_bytes(b[2..6].try_into().unwrap()) + extra as u32;
        b[2..6].copy_from_slice(&l.to_le_bytes());
        b.extend(std::iter::repeat_n(0xab, extra));
        b
    }
    for (dir, n) in [
        ("pg_info_t", 2),
        ("pg_stat_t", 3),
        ("pg_history_t", 2),
        ("pg_notify_t", 3),
    ] {
        let g = td(&format!("{dir}/{n}.bin"));
        let g2 = grow(g.clone(), 7);
        match dir {
            "pg_info_t" => assert_eq!(
                from_slice::<PgInfo>(&g2).unwrap().encode_to_vec().unwrap(),
                g
            ),
            "pg_stat_t" => assert_eq!(
                from_slice::<PgStat>(&g2).unwrap().encode_to_vec().unwrap(),
                g
            ),
            "pg_history_t" => assert_eq!(
                from_slice::<PgHistory>(&g2)
                    .unwrap()
                    .encode_to_vec()
                    .unwrap(),
                g
            ),
            _ => assert_eq!(
                from_slice::<PgNotify>(&g2)
                    .unwrap()
                    .encode_to_vec()
                    .unwrap(),
                g
            ),
        }
    }
    // compat too new is rejected
    let mut g = td("pg_info_t/2.bin");
    g[1] = 99;
    assert!(from_slice::<PgInfo>(&g).is_err());
}

#[test]
fn truncated_input_never_panics() {
    macro_rules! prefixes {
        ($t:ty, $f:expr) => {{
            let g = td($f);
            for n in 0..g.len() {
                assert!(from_slice::<$t>(&g[..n]).is_err(), "{} prefix {n}", $f);
            }
        }};
    }
    prefixes!(PgInfo, "pg_info_t/2.bin");
    prefixes!(PgStat, "pg_stat_t/3.bin");
    prefixes!(PgLog, "pg_log_t/2.bin");
    prefixes!(PgMissing, "pg_missing_t/3.bin");
    prefixes!(PastIntervals, "PastIntervals/1.bin");
    prefixes!(PgNotify, "pg_notify_t/1.bin");
}

#[test]
fn older_struct_versions_decode() {
    // pg_info v31 (no partial_writes_*): drop the last 8 bytes and rewrite v/len
    let g = td("pg_info_t/2.bin");
    let mut b = g[..g.len() - 8].to_vec();
    b[0] = 31;
    let l = (b.len() - 6) as u32;
    b[2..6].copy_from_slice(&l.to_le_bytes());
    let i: PgInfo = from_slice(&b).unwrap();
    assert!(i.partial_writes_last_complete.is_empty());
    assert_eq!(i.last_interval_started, i.last_epoch_started);
    // type-0 (null) PastIntervals decodes as empty
    let p: PastIntervals = from_slice(&[1, 1, 1, 0, 0, 0, 0]).unwrap();
    assert!(p.is_empty());
    // removed pi_simple_rep (type 1) is rejected
    assert!(from_slice::<PastIntervals>(&[1, 1, 1, 0, 0, 0, 1]).is_err());
}

// ---- PastIntervals builder -----------------------------------------------------------------

fn iv(first: u32, last: u32, acting: &[i32], rw: bool) -> PgInterval {
    PgInterval {
        first,
        last,
        up: acting.to_vec(),
        acting: acting.to_vec(),
        maybe_went_rw: rw,
        primary: acting.first().copied().unwrap_or(-1),
        up_primary: acting.first().copied().unwrap_or(-1),
    }
}

#[test]
fn builder_matches_dencoder_instances() {
    // replicated: instance 2 (rw pattern true,true,false,true): older {0,1,2} dropped (superset of {1,2})
    let mut p = PastIntervals::default();
    for i in [
        iv(10, 20, &[0, 1, 2], true),
        iv(21, 30, &[1, 2], true),
        iv(31, 35, &[0, 1], false),
        iv(36, 50, &[0, 2], true),
    ] {
        assert!(p.add_interval(false, &i));
    }
    assert_eq!(p.encode_to_vec().unwrap(), td("PastIntervals/2.bin"));
    // EC instance 1: shards = positions, nothing is a subset because shards differ
    let mut p = PastIntervals::default();
    for i in [
        iv(10, 20, &[0, 1, 2], true),
        iv(21, 30, &[1, 2], true),
        iv(31, 35, &[2, 1], false),
        iv(36, 50, &[0, 2], true),
    ] {
        assert!(p.add_interval(true, &i));
    }
    assert_eq!(p.encode_to_vec().unwrap(), td("PastIntervals/1.bin"));
    // EC instance 3
    let mut p = PastIntervals::default();
    for i in [
        iv(10, 20, &[2, 1, 0], true),
        iv(21, 30, &[2, 0], false),
        iv(31, 35, &[2, 0], true),
        iv(36, 50, &[0, 2], true),
    ] {
        assert!(p.add_interval(true, &i));
    }
    assert_eq!(p.encode_to_vec().unwrap(), td("PastIntervals/3.bin"));
    assert_eq!(p.bounds(), (10, 51));
    // NONE osds skipped, non-extending interval refused
    let mut p = PastIntervals::default();
    assert!(p.add_interval(false, &iv(5, 6, &[1, NONE_OSD], true)));
    assert_eq!(p.all_participants.len(), 1);
    assert!(!p.add_interval(false, &iv(3, 4, &[1], true)));
    assert_eq!(p.intervals_since(7).count(), 0);
    assert_eq!(p.intervals_since(6).count(), 1);
}

#[test]
fn past_intervals_reject_non_growing_or_unrepresentable_end() {
    // the covered range is [first, last] inclusive but compared as [first, last + 1): a wire
    // `last == u32::MAX` would wrap bounds().1 to 0 and accept every create epoch
    let wire = |last: u32| PastIntervals {
        first: 1,
        last,
        all_participants: BTreeSet::new(),
        intervals: vec![],
    };
    assert!(wire(u32::MAX).check_wire().is_err());
    assert!(from_slice::<PastIntervals>(&wire(u32::MAX).encode_to_vec().unwrap()).is_err());
    let mut with_iv = wire(u32::MAX);
    with_iv.intervals.push(CompactInterval {
        first: 1,
        last: u32::MAX,
        acting: BTreeSet::new(),
    });
    assert!(with_iv.check_wire().is_err());
    // the highest representable end still decodes
    let ok = wire(u32::MAX - 1);
    assert_eq!(
        from_slice::<PastIntervals>(&ok.encode_to_vec().unwrap()).unwrap(),
        ok
    );
    assert_eq!(ok.bounds(), (1, u32::MAX));
    // the builder refuses it too, and it never changes the set
    let mut p = PastIntervals::default();
    assert!(!p.add_interval(false, &iv(1, u32::MAX, &[0], true)));
    assert_eq!(p, PastIntervals::default());
    // `last` must grow (peering 3.3): an interval reusing the current `last` overlaps the stored one
    let mut p = PastIntervals::default();
    assert!(p.add_interval(false, &iv(10, 20, &[0], true)));
    let before = p.clone();
    assert!(!p.add_interval(false, &iv(15, 20, &[1], true)));
    assert_eq!(p, before);
    assert_eq!(p.intervals.len(), 1);
    assert!(p.add_interval(false, &iv(21, 30, &[1], true)));
}

// ---- synthetic maps ------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Osd {
    exists: bool,
    up: bool,
    up_from: u32,
    up_thru: u32,
    lost_at: u32,
}
#[derive(Clone, Default)]
struct TMap {
    epoch: u32,
    pools: HashMap<u64, PoolParams>,
    flags: MapFlags,
    osds: HashMap<i32, Osd>,
    /// osd -> stretch barrier bucket (absent = 0).
    barrier: HashMap<i32, i32>,
}
impl OsdMapView for TMap {
    fn epoch(&self) -> u32 {
        self.epoch
    }
    fn pool(&self, p: u64) -> Option<PoolParams> {
        self.pools.get(&p).cloned()
    }
    fn flags(&self) -> MapFlags {
        self.flags
    }
    fn exists(&self, o: i32) -> bool {
        self.osds.get(&o).is_some_and(|x| x.exists)
    }
    fn is_up(&self, o: i32) -> bool {
        self.osds.get(&o).is_some_and(|x| x.exists && x.up)
    }
    fn up_from(&self, o: i32) -> u32 {
        self.osds.get(&o).map_or(0, |x| x.up_from)
    }
    fn up_thru(&self, o: i32) -> u32 {
        self.osds.get(&o).map_or(0, |x| x.up_thru)
    }
    fn is_dead(&self, _o: i32) -> bool {
        false // interval tests never mark an OSD dead
    }
    fn lost_at(&self, o: i32) -> u32 {
        self.osds.get(&o).map_or(0, |x| x.lost_at)
    }
    fn barrier_bucket(&self, o: i32, _barrier: u32, _rule: i32) -> i32 {
        self.barrier.get(&o).copied().unwrap_or(0)
    }
}

fn pool(size: u32, min_size: u32, pg_num: u32) -> PoolParams {
    PoolParams {
        size,
        min_size,
        pg_num,
        pg_num_pending: pg_num,
        ..Default::default()
    }
}
fn tmap(epoch: u32, pg_num: u32, osds: &[(i32, u32, u32)]) -> TMap {
    let mut m = TMap {
        epoch,
        ..Default::default()
    };
    m.pools.insert(1, pool(3, 2, pg_num));
    for (o, up_from, up_thru) in osds {
        m.osds.insert(
            *o,
            Osd {
                exists: true,
                up: true,
                up_from: *up_from,
                up_thru: *up_thru,
                lost_at: 0,
            },
        );
    }
    m
}
fn mapping(up: &[i32], acting: &[i32]) -> Mapping {
    Mapping {
        up: up.to_vec(),
        up_primary: up.first().copied().unwrap_or(-1),
        acting: acting.to_vec(),
        acting_primary: acting.first().copied().unwrap_or(-1),
    }
}
const PG: PgT = PgT { pool: 1, seed: 0 };

fn step(
    past: &mut PastIntervals,
    since: u32,
    lec: u32,
    last: &TMap,
    new: &TMap,
    old: &Mapping,
    nw: &Mapping,
) -> Option<PgInterval> {
    check_new_interval(
        past,
        &IntervalInput {
            pgid: PG,
            same_interval_since: since,
            last_epoch_clean: lec,
            old,
            new: nw,
            lastmap: last,
            newmap: new,
        },
    )
}

#[test]
fn check_new_interval_history() {
    let mut past = PastIntervals::default();
    let abc = mapping(&[0, 1, 2], &[0, 1, 2]);
    // epoch 9 -> 10: osd0 died, acting [1,2]; osd0 had up_thru 3 >= interval start 3 -> maybe_went_rw
    let m9 = tmap(9, 8, &[(0, 1, 3), (1, 1, 0), (2, 1, 0)]);
    let m10 = tmap(10, 8, &[(0, 1, 3), (1, 1, 0), (2, 1, 0)]);
    let b = mapping(&[1, 2], &[1, 2]);
    let i = step(&mut past, 3, 0, &m9, &m10, &abc, &b).unwrap();
    assert_eq!((i.first, i.last, i.maybe_went_rw), (3, 9, true));
    assert_eq!(past.intervals.len(), 1);
    // no change -> none
    assert!(
        step(
            &mut past,
            10,
            0,
            &m10,
            &tmap(11, 8, &[(0, 1, 3), (1, 1, 0), (2, 1, 0)]),
            &b,
            &b
        )
        .is_none()
    );
    // epoch 19 -> 20: new primary 1 has up_thru 0 < 10 and lec elsewhere -> not rw
    let m19 = tmap(19, 8, &[(0, 1, 3), (1, 1, 0), (2, 1, 0)]);
    let m20 = tmap(20, 8, &[(0, 1, 3), (1, 1, 0), (2, 1, 0)]);
    let c = mapping(&[1, 2, 0], &[1, 2, 0]);
    let i = step(&mut past, 10, 4, &m19, &m20, &b, &c).unwrap();
    assert_eq!((i.first, i.last, i.maybe_went_rw), (10, 19, false));
    assert_eq!(past.intervals.len(), 1);
    assert_eq!(past.bounds(), (3, 20));
    // lec inside the interval makes it writable even without up_thru
    let m29 = tmap(29, 8, &[(0, 1, 3), (1, 1, 0), (2, 1, 0)]);
    let m30 = tmap(30, 8, &[(0, 1, 3), (1, 1, 0), (2, 1, 0)]);
    let d = mapping(&[2, 1, 0], &[2, 1, 0]);
    let i = step(&mut past, 20, 25, &m29, &m30, &c, &d).unwrap();
    assert!(i.maybe_went_rw);
    // new acting {0,1,2} is a superset of nothing newer; the older {0,1,2} interval (3-9) is
    // redundant (its acting set is a superset of the new one) and is dropped
    let sets: Vec<Vec<i32>> = past
        .intervals
        .iter()
        .map(|x| x.acting.iter().map(|s| s.osd).collect())
        .collect();
    assert_eq!(sets, vec![vec![0, 1, 2]]);
    assert_eq!(past.intervals[0].first, 20);
    assert_eq!(past.bounds(), (3, 30));
}

#[test]
fn maybe_went_rw_rules() {
    let m_old = { tmap(9, 8, &[(0, 1, 5), (1, 1, 0), (2, 1, 0)]) };
    let m_new = tmap(10, 8, &[(0, 1, 5), (1, 1, 0), (2, 1, 0)]);
    // |acting| < min_size (2): never rw even with up_thru
    let mut past = PastIntervals::default();
    let i = step(
        &mut past,
        3,
        0,
        &m_old,
        &m_new,
        &mapping(&[0], &[0]),
        &mapping(&[0, 1], &[0, 1]),
    )
    .unwrap();
    assert!(!i.maybe_went_rw);
    // empty acting
    let mut past = PastIntervals::default();
    let i = step(
        &mut past,
        3,
        0,
        &m_old,
        &m_new,
        &mapping(&[], &[]),
        &mapping(&[0, 1], &[0, 1]),
    )
    .unwrap();
    assert!(!i.maybe_went_rw);
    // up_from after interval start: primary came up later, not rw
    let mut m_late = m_old.clone();
    m_late.osds.get_mut(&0).unwrap().up_from = 4;
    let mut past = PastIntervals::default();
    let i = step(
        &mut past,
        3,
        0,
        &m_late,
        &m_new,
        &mapping(&[0, 1], &[0, 1]),
        &mapping(&[1], &[1]),
    )
    .unwrap();
    assert!(!i.maybe_went_rw);
    // pool absent in the old map: never a new interval; absent in new: final interval
    let mut no_pool = m_old.clone();
    no_pool.pools.clear();
    let mut past = PastIntervals::default();
    assert!(
        step(
            &mut past,
            3,
            0,
            &no_pool,
            &m_new,
            &mapping(&[0], &[0]),
            &mapping(&[1], &[1])
        )
        .is_none()
    );
    let i = step(
        &mut past,
        3,
        0,
        &m_old,
        &no_pool,
        &mapping(&[0, 1], &[0, 1]),
        &mapping(&[0, 1], &[0, 1]),
    )
    .unwrap();
    assert!(i.maybe_went_rw);
    // EC with k=2: only 1 live shard cannot have gone active
    let mut ec_old = m_old.clone();
    ec_old.pools.insert(
        1,
        PoolParams {
            is_erasure: true,
            ec_k: 2,
            size: 3,
            min_size: 1,
            pg_num: 8,
            pg_num_pending: 8,
            ..Default::default()
        },
    );
    let mut past = PastIntervals::default();
    let i = step(
        &mut past,
        3,
        0,
        &ec_old,
        &m_new,
        &mapping(&[0, NONE_OSD, NONE_OSD], &[0, NONE_OSD, NONE_OSD]),
        &mapping(&[0, 1, 2], &[0, 1, 2]),
    )
    .unwrap();
    assert!(!i.maybe_went_rw);
}

#[test]
fn is_new_interval_triggers() {
    let p = pool(3, 2, 8);
    let f = MapFlags {
        sortbitwise: true,
        recovery_deletes: true,
    };
    let a = mapping(&[0, 1, 2], &[0, 1, 2]);
    let nw = |m: &Mapping, p2: &PoolParams, f2: MapFlags| is_new_interval(PG, &a, m, &p, p2, f, f2);
    assert!(!nw(&a, &p, f));
    assert!(nw(&mapping(&[0, 1, 2], &[0, 2, 1]), &p, f)); // order matters
    assert!(nw(&mapping(&[0, 1, 2], &[0, 1, NONE_OSD]), &p, f));
    assert!(nw(&mapping(&[0, 2, 1], &[0, 1, 2]), &p, f)); // up changed
    assert!(nw(&a, &pool(2, 2, 8), f));
    assert!(nw(&a, &pool(3, 1, 8), f));
    assert!(nw(
        &a,
        &p,
        MapFlags {
            sortbitwise: false,
            ..f
        }
    ));
    assert!(nw(
        &a,
        &p,
        MapFlags {
            recovery_deletes: false,
            ..f
        }
    ));
    let mut st = p.clone();
    st.peering_crush_bucket_count = 2;
    assert!(nw(&a, &st, f));
    // split: pg 0 of an 8 -> 16 pool has child 8 (stable_mod(8, 8, 15) == 0)
    assert!(nw(&a, &pool(3, 2, 16), f));
    // pg 3 splits too (child 11); but with pg_num 8 -> 8 nothing
    assert!(is_split(3, 8, 16) && !is_split(3, 8, 8) && !is_split(9, 8, 16));
    // non power of two: 6 -> 7 only seed 6's parent (6 & 3 = 2) splits
    assert!(is_split(2, 6, 7) && !is_split(0, 6, 7));
    // merge: pg_num_pending 8 -> 4: seeds 4..8 are sources, 0..4 targets of those
    let mut pend = p.clone();
    pend.pg_num_pending = 4;
    for seed in 0..8 {
        let pg = PgT::new(1, seed);
        assert!(is_new_interval(pg, &a, &a, &p, &pend, f, f), "seed {seed}");
    }
    // pg_num 8 -> 6: sources 6,7; targets 6&3.. = ancestors 2 and 3
    let (p6, f0) = (pool(3, 2, 6), f);
    let hits: Vec<u32> = (0..8)
        .filter(|s| is_new_interval(PgT::new(1, *s), &a, &a, &p, &p6, f0, f0))
        .collect();
    assert_eq!(hits, vec![2, 3, 6, 7]);
    // a pool unrelated change: pg_num_pending raise alone elsewhere
    assert_eq!(stable_mod(8, 8, 15), 0);
    assert_eq!(stable_mod(13, 12, 15), 5);
}

#[test]
fn prior_set() {
    // intervals: [1,9] {0,1} rw ; [10,19] {1,2} rw ; les = 10 -> only the second counts
    let mut past = PastIntervals::default();
    past.add_interval(false, &iv(1, 9, &[0, 1], true));
    past.add_interval(false, &iv(10, 19, &[1, 2], true));
    let mut m = tmap(25, 8, &[(0, 1, 0), (1, 1, 0), (2, 1, 0), (3, 1, 0)]);
    let ps = PriorSet::build(&past, false, 1, 10, &[3, 1], &[3, 1], &m);
    let probe: BTreeSet<i32> = ps.probe.iter().map(|s| s.osd).collect();
    assert_eq!(probe, BTreeSet::from([0, 1, 2, 3]));
    assert!(!ps.pg_down && ps.down.is_empty());
    // 1 and 2 down: nobody of the [10,19] interval present -> PG down, blocked by both
    m.osds.get_mut(&1).unwrap().up = false;
    m.osds.get_mut(&2).unwrap().up = false;
    let ps = PriorSet::build(&past, false, 1, 10, &[3], &[3], &m);
    assert!(ps.pg_down);
    assert_eq!(
        ps.blocked_by.keys().copied().collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(ps.down, BTreeSet::from([1, 2]));
    // with les = 20 no interval needs to be considered
    assert!(!PriorSet::build(&past, false, 1, 20, &[3], &[3], &m).pg_down);
    // osd 1 declared lost after the interval started: counts as present
    let mut lost = m.clone();
    lost.osds.get_mut(&1).unwrap().lost_at = 15;
    assert!(!PriorSet::build(&past, false, 1, 10, &[3], &[3], &lost).pg_down);
    // osd 2 gone from the map: ignored (DNE) -> the other one (down osd 1) alone still blocks
    let mut dne = m.clone();
    dne.osds.get_mut(&2).unwrap().exists = false;
    let ps = PriorSet::build(&past, false, 1, 10, &[3], &[3], &dne);
    assert!(ps.pg_down && ps.blocked_by.keys().copied().collect::<Vec<_>>() == vec![1]);
    // affected_by_map
    let ps = PriorSet::build(&past, false, 1, 10, &[3], &[3], &m);
    assert!(!ps.affected_by_map(&m));
    let mut up1 = m.clone();
    up1.osds.get_mut(&1).unwrap().up = true;
    assert!(ps.affected_by_map(&up1)); // a down OSD came up
    let mut l1 = m.clone();
    l1.osds.get_mut(&2).unwrap().lost_at = 22;
    assert!(ps.affected_by_map(&l1)); // lost_at changed
    let mut d3 = m.clone();
    d3.osds.get_mut(&3).unwrap().up = false;
    assert!(ps.affected_by_map(&d3)); // a probed OSD went down
    // EC: need k present
    let mut ecp = PastIntervals::default();
    ecp.add_interval(true, &iv(1, 9, &[0, 1, 2], true));
    let mut mm = tmap(25, 8, &[(0, 1, 0), (1, 1, 0), (2, 1, 0)]);
    mm.osds.get_mut(&2).unwrap().up = false;
    assert!(!PriorSet::build(&ecp, true, 2, 1, &[0, 1], &[0, 1], &mm).pg_down);
    mm.osds.get_mut(&1).unwrap().up = false;
    assert!(PriorSet::build(&ecp, true, 2, 1, &[0], &[0], &mm).pg_down);
}

// ---- clean regions / missing / log ---------------------------------------------------------

#[test]
fn clean_regions_ops() {
    // dencoder instance 2: [0~4096, 12288~..], omap dirty
    let c: ObjectCleanRegions = from_slice(&td("ObjectCleanRegions/2.bin")).unwrap();
    assert!(!c.clean_omap && c.clean_offsets.len() == 2 && c.clean_offsets[&0] == 4096);
    let mut c = ObjectCleanRegions::default();
    c.mark_data_region_dirty(4096, 8192);
    assert_eq!(c.clean_offsets.get(&0), Some(&4096));
    assert_eq!(c.clean_offsets.get(&12288), Some(&(u64::MAX - 12288)));
    assert!(
        c.is_clean_range(0, 4096) && !c.is_clean_range(4000, 200) && c.is_clean_range(20000, 5)
    );
    // dencoder instance 2 = dirty [4096, 45056) + omap + new object
    let mut d = ObjectCleanRegions::default();
    d.mark_data_region_dirty(4096, 40960);
    d.mark_omap_dirty();
    d.mark_new_object();
    assert_eq!(d.encode_to_vec().unwrap(), td("ObjectCleanRegions/2.bin"));
    // trim to 10 intervals dropping the shortest
    let mut c = ObjectCleanRegions::default();
    for i in 0..15u64 {
        c.mark_data_region_dirty(i * 100 + 50, 10 + i);
    }
    assert!(c.clean_offsets.len() <= 10);
    // merge = intersection
    let mut a = ObjectCleanRegions::default();
    a.mark_data_region_dirty(0, 100);
    let mut b = ObjectCleanRegions::default();
    b.mark_data_region_dirty(50, 100);
    b.mark_omap_dirty();
    a.merge(&b);
    assert_eq!(a.clean_offsets.keys().next(), Some(&150));
    assert!(!a.clean_omap && !a.new_object);
}

fn entry(op: LogOp, name: &str, v: Eversion, prior: Eversion) -> LogEntry {
    LogEntry::new(op, obj(name), v, prior)
}

#[test]
fn missing_rules() {
    let mut m = PgMissing {
        may_include_deletes: true,
        ..Default::default()
    };
    // new object
    m.add_next_event(&entry(LogOp::MODIFY, "a", ev(1, 1), Eversion::default()));
    assert_eq!(m.missing[&obj("a")].need, ev(1, 1));
    assert_eq!(m.missing[&obj("a")].have, Eversion::default());
    // later write keeps have
    let mut e2 = entry(LogOp::MODIFY, "a", ev(1, 2), ev(1, 1));
    e2.clean_regions.mark_data_region_dirty(0, 10);
    m.add_next_event(&e2);
    assert_eq!(
        (m.missing[&obj("a")].need, m.missing[&obj("a")].have),
        (ev(1, 2), Eversion::default())
    );
    // object not missing: have = prior
    m.add_next_event(&entry(LogOp::MODIFY, "b", ev(1, 3), ev(0, 9)));
    assert_eq!(m.missing[&obj("b")].have, ev(0, 9));
    // delete with may_include_deletes -> DELETE item
    m.add_next_event(&entry(LogOp::DELETE, "b", ev(1, 4), ev(1, 3)));
    assert!(m.missing[&obj("b")].is_delete());
    // error entries never touch missing
    let n = m.len();
    m.add_next_event(&entry(LogOp::ERROR, "z", ev(1, 5), ev(1, 4)));
    assert_eq!(m.len(), n);
    // CLONE of an already-missing object replaces the item
    m.add_next_event(&entry(LogOp::CLONE, "a", ev(1, 6), ev(1, 2)));
    assert_eq!(
        (m.missing[&obj("a")].need, m.missing[&obj("a")].have),
        (ev(1, 6), Eversion::default())
    );
    assert_eq!(m.oldest_need(), Some(ev(1, 4)));
    // got
    assert!(!m.got(&obj("a"), ev(1, 5)));
    assert!(m.got(&obj("a"), ev(1, 6)));
    assert!(m.got(&obj("b"), ev(0, 0))); // delete item needs no version
    assert!(m.is_empty());
    // without may_include_deletes a delete removes the item
    let mut m = PgMissing::default();
    m.add_next_event(&entry(LogOp::MODIFY, "a", ev(1, 1), Eversion::default()));
    m.add_next_event(&entry(LogOp::DELETE, "a", ev(1, 2), ev(1, 1)));
    assert!(m.is_empty());
    // revise_need creates with have 0'0
    m.revise_need(obj("q"), ev(2, 2), false);
    m.revise_have(&obj("q"), ev(1, 1));
    assert_eq!(m.missing[&obj("q")].have, ev(1, 1));
    // wire round trip incl. deletes flag
    let mut m = PgMissing {
        may_include_deletes: true,
        ..Default::default()
    };
    m.add(obj("x"), ev(3, 3), ev(2, 2), true);
    let b = m.encode_to_vec().unwrap();
    assert_eq!(from_slice::<PgMissing>(&b).unwrap(), m);
}

#[test]
fn log_entry_variants() {
    // LOST_REVERT field order (#4 reverting_to, #7 prior_version), extra_reqids, op_returns, EC shards
    let mut e = entry(LogOp::LOST_REVERT, "a", ev(5, 5), ev(4, 4));
    e.reverting_to = ev(3, 3);
    let b = e.encode_to_vec().unwrap();
    assert_eq!(from_slice::<LogEntry>(&b).unwrap(), e);
    let mut e = entry(LogOp::MODIFY, "a", ev(5, 6), ev(5, 5));
    e.reqid = OsdReqId {
        tid: 7,
        inc: 1,
        ..Default::default()
    };
    e.extra_reqids = vec![(
        OsdReqId {
            tid: 8,
            ..Default::default()
        },
        3,
    )];
    e.extra_reqid_return_codes = BTreeMap::from([(0, -5)]);
    e.op_returns = vec![LogOpReturnItem {
        rval: 1,
        outdata: b"hi".to_vec(),
    }];
    e.written_shards = ShardIdSet([5, 1 << 40]);
    e.snaps = vec![1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0];
    e.return_code = -2;
    e.mod_desc = ObjectModDesc {
        version: 2,
        can_local_rollback: true,
        rollback_info_completed: false,
        bl: vec![9, 8, 7],
    };
    let b = e.encode_to_vec().unwrap();
    assert_eq!(from_slice::<LogEntry>(&b).unwrap(), e);
    assert!(
        e.reqid_is_indexed() && !entry(LogOp::CLONE, "a", ev(1, 1), ev(0, 0)).reqid_is_indexed()
    );
    // ERROR: return code before extra_reqid_return_codes
    let mut er = e.clone();
    er.op = LogOp::ERROR;
    let b = er.encode_to_vec().unwrap();
    assert_eq!(from_slice::<LogEntry>(&b).unwrap(), er);
    // dups
    let d = LogDup::from_entry(&e);
    assert_eq!(
        from_slice::<LogDup>(&d.encode_to_vec().unwrap()).unwrap(),
        d
    );
    assert!(LogOp::MODIFY.is_update() && LogOp::DELETE.is_delete() && !LogOp(4).is_known());
}

#[test]
fn dups_carry_extra_reqid_return_codes() {
    // pglog 6.3: each extra reqid also becomes a dup with its own user_version and return code
    let mut e = entry(LogOp::MODIFY, "a", ev(5, 6), ev(5, 5));
    e.return_code = -2;
    e.extra_reqids = vec![
        (
            OsdReqId {
                tid: 8,
                ..Default::default()
            },
            3,
        ),
        (
            OsdReqId {
                tid: 9,
                ..Default::default()
            },
            4,
        ),
    ];
    e.extra_reqid_return_codes = BTreeMap::from([(0, -5)]);
    let d: Vec<LogDup> = e.dups().collect();
    assert_eq!(d.len(), 3);
    assert_eq!(
        (d[0].reqid, d[0].user_version, d[0].return_code),
        (e.reqid, 0, -2)
    );
    // a failed parent: every extra reqid keeps the parent's error, an indexed override does not replace it
    assert_eq!(
        (d[1].reqid, d[1].user_version, d[1].return_code),
        (e.extra_reqids[0].0, 3, -2)
    );
    assert_eq!(
        (d[2].reqid, d[2].user_version, d[2].return_code),
        (e.extra_reqids[1].0, 4, -2)
    );
    // a successful parent: index 0 recorded a failure, index 1 has no entry (the parent's result)
    e.return_code = 0;
    let d: Vec<LogDup> = e.dups().collect();
    assert_eq!((d[1].return_code, d[2].return_code), (-5, 0));
}

#[test]
fn log_slices() {
    let mut l = PgLog::empty_at(ev(1, 10));
    for v in 11..=20u64 {
        l.log
            .push_back(entry(LogOp::MODIFY, "a", ev(2, v), ev(2, v - 1)));
    }
    l.head = ev(2, 20);
    l.can_rollback_to = l.head;
    l.rollback_info_trimmed_to = l.head;
    let s = l.copy_after(ev(2, 15));
    assert_eq!((s.log.len(), s.tail, s.head), (5, ev(2, 15), ev(2, 20)));
    let s = l.copy_up_to(3);
    assert_eq!(
        (s.log.len(), s.tail, s.log[0].version),
        (3, ev(2, 17), ev(2, 18))
    );
    // since older than our tail: full log; since == 0'0: everything
    assert_eq!(l.answer_log_query(ev(0, 5)), l);
    assert_eq!(l.answer_log_query(Eversion::default()).log.len(), 10);
    assert_eq!(l.answer_log_query(ev(2, 20)).log.len(), 0);
    let b = l.encode_to_vec().unwrap();
    assert_eq!(from_slice::<PgLog>(&b).unwrap(), l);
}

#[test]
fn history_merge() {
    let a = PgHistory {
        last_epoch_started: 5,
        last_interval_started: 4,
        prior_readable_until_ub: Timespan { sec: 9, nsec: 0 },
        ..Default::default()
    };
    let mut x = a.clone();
    assert!(!x.merge(&a));
    // newer interval takes the other's bound
    let b = PgHistory {
        last_epoch_started: 6,
        last_interval_started: 6,
        prior_readable_until_ub: Timespan { sec: 20, nsec: 0 },
        ..Default::default()
    };
    assert!(x.merge(&b));
    assert_eq!(
        (x.last_epoch_started, x.prior_readable_until_ub.sec),
        (6, 20)
    );
    // same interval: smaller bound wins
    let c = PgHistory {
        last_interval_started: 6,
        prior_readable_until_ub: Timespan { sec: 3, nsec: 0 },
        ..Default::default()
    };
    assert!(x.merge(&c));
    assert_eq!(x.prior_readable_until_ub.sec, 3);
    // never decreases
    let old = PgHistory {
        last_epoch_started: 1,
        ..Default::default()
    };
    assert!(!x.merge(&old) || x.last_epoch_started == 6);
    assert_eq!(x.last_epoch_started, 6);
    let h = PgHistory::new_pg(7, UTime::new(100, 0));
    assert_eq!(
        (
            h.epoch_created,
            h.epoch_pool_created,
            h.same_interval_since,
            h.last_scrub_stamp.sec
        ),
        (7, 7, 7, 100)
    );
}

#[test]
fn info_helpers() {
    let spg = SpgT {
        pgid: PgT::new(2, 3),
        shard: ShardId(1),
    };
    let mut i = PgInfo::new(spg);
    assert!(i.is_empty() && i.dne_flag() && !i.has_missing() && !i.is_incomplete());
    i.last_update = ev(2, 5);
    assert!(i.has_missing());
    i.last_backfill = Hobject::MIN();
    assert!(i.is_incomplete());
    let b = i.encode_to_vec().unwrap();
    let r: PgInfo = from_slice(&b).unwrap();
    assert_eq!(r, i);
    assert_eq!(r.pgid, spg);
    // pg_stat default carries -1 primaries
    assert_eq!(PgStat::default().acting_primary, -1);
}

/// Writes our own encodings for the lab check `testdata/pgwire/verify-ours.sh`
/// (ceph-dencoder must decode them). Run: PGWIRE_OUT=dir cargo test -p pgwire --test unit -- --ignored emit
#[test]
#[ignore]
fn emit_our_vectors() {
    let Ok(out) = std::env::var("PGWIRE_OUT") else {
        return;
    };
    let w = |name: &str, b: Vec<u8>| std::fs::write(format!("{out}/{name}"), b).unwrap();
    let mut e = entry(LogOp::LOST_REVERT, "a", ev(5, 5), ev(4, 4));
    e.reverting_to = ev(3, 3);
    w("pg_log_entry_t.revert.bin", e.encode_to_vec().unwrap());
    let mut e = entry(LogOp::MODIFY, "obj", ev(5, 6), ev(5, 5));
    e.reqid = OsdReqId {
        tid: 7,
        inc: 1,
        ..Default::default()
    };
    e.extra_reqids = vec![(
        OsdReqId {
            tid: 8,
            ..Default::default()
        },
        3,
    )];
    e.extra_reqid_return_codes = BTreeMap::from([(0, -5)]);
    e.op_returns = vec![LogOpReturnItem {
        rval: 1,
        outdata: b"hi".to_vec(),
    }];
    e.snaps = vec![1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0];
    e.clean_regions = ObjectCleanRegions::fully_dirty();
    w("pg_log_entry_t.extra.bin", e.encode_to_vec().unwrap());
    let mut er = e.clone();
    er.op = LogOp::ERROR;
    er.return_code = -2;
    w("pg_log_entry_t.error.bin", er.encode_to_vec().unwrap());
    let mut l = PgLog::empty_at(ev(1, 10));
    l.log.push_back(e.clone());
    l.dups.push_back(LogDup::from_entry(&e));
    w("pg_log_t.bin", l.encode_to_vec().unwrap());
    let mut m = PgMissing {
        may_include_deletes: true,
        ..Default::default()
    };
    m.add(obj("x"), ev(3, 3), ev(2, 2), true);
    m.add_next_event(&e);
    w("pg_missing_t.bin", m.encode_to_vec().unwrap());
    let mut p = PastIntervals::default();
    p.add_interval(false, &iv(10, 20, &[0, 1, 2], true));
    p.add_interval(false, &iv(21, 30, &[1, 2], true));
    w("PastIntervals.bin", p.encode_to_vec().unwrap());
    let spg = SpgT {
        pgid: PgT::new(3, 0x1f),
        shard: ShardId::NO_SHARD,
    };
    let mut i = PgInfo::new(spg);
    i.last_update = ev(7, 100);
    i.last_complete = ev(7, 99);
    i.log_tail = ev(5, 50);
    i.history = PgHistory::new_pg(4, UTime::new(1000, 5));
    i.history.last_epoch_started = 6;
    // v11 latch fields (21.2.0): an open vulnerability window and a paused rebuild episode
    i.history.last_degraded = UTime::new(1100, 1);
    i.history.last_clean = UTime::new(1050, 2);
    i.history.vuln_window_reported = UTime::new(1050, 2);
    i.history.last_rebuild_active_start = UTime::new(1110, 3);
    i.history.rebuild_span_reported = UTime::new(1120, 4);
    i.history.rebuild_active_accum = UTime::new(9, 5);
    i.last_epoch_started = 7;
    i.last_interval_started = 7;
    i.last_user_version = 12345;
    i.purged_snaps = BTreeMap::from([(2, 3)]);
    i.stats.state = state::ACTIVE | state::CLEAN | (1 << 33);
    i.stats.stats.sum.num_bytes = 4096;
    i.stats.up = vec![1, 2, 3];
    i.stats.acting = vec![1, 2, 3];
    i.partial_writes_last_complete_epoch = 7;
    w("pg_info_t.bin", i.encode_to_vec().unwrap());
    let n = PgNotify {
        query_epoch: 9,
        epoch_sent: 10,
        info: i,
        to: ShardId::NO_SHARD,
        from: ShardId::NO_SHARD,
        past_intervals: p,
        pg_features: 1,
    };
    w("pg_notify_t.bin", n.encode_to_vec().unwrap());
    w(
        "pg_query_t.bin",
        PgQuery {
            ty: QueryType::LOG,
            since: ev(3, 4),
            epoch_sent: 5,
            ..Default::default()
        }
        .encode_to_vec()
        .unwrap(),
    );
    w(
        "pg_lease_t.bin",
        PgLease {
            readable_until: Timespan { sec: 5, nsec: 1 },
            readable_until_ub: Timespan { sec: 6, nsec: 2 },
            interval: Timespan { sec: 16, nsec: 0 },
        }
        .encode_to_vec()
        .unwrap(),
    );
}

// ---- stretch (doc/spec/stretch.md) ---------------------------------------------------------------

const DC1: i32 = -3;
const DC2: i32 = -10;

/// Oracle layout: osd.0/1 in dc1, osd.2/3 in dc2; pool 1 = size 4 / min 2 / C 2 / Tg 2 / datacenter (8).
fn stretch_map(epoch: u32, count: u32, member: i32) -> TMap {
    let mut m = tmap(epoch, 8, &[(0, 1, 0), (1, 1, 0), (2, 1, 0), (3, 1, 0)]);
    m.barrier = HashMap::from([(0, DC1), (1, DC1), (2, DC2), (3, DC2)]);
    let p = m.pools.get_mut(&1).unwrap();
    p.size = 4;
    p.min_size = 2;
    p.crush_rule = 1;
    p.peering_crush_bucket_count = count;
    p.peering_crush_bucket_target = 2;
    p.peering_crush_bucket_barrier = 8;
    p.peering_crush_mandatory_member = member;
    m
}

#[test]
fn can_peer_rules() {
    let m = stretch_map(10, 2, NONE_OSD);
    let p = m.pools[&1].clone();
    // P0: both sites
    assert!(can_peer(&m, &p, &[2, 3, 0, 1]));
    // P1: one site only
    assert!(!can_peer(&m, &p, &[0, 1]));
    assert!(!can_peer(&m, &p, &[]));
    // a NONE hole / an OSD outside the rule = the pseudo bucket 0: counts as one extra bucket
    assert!(can_peer(&m, &p, &[0, NONE_OSD]));
    assert!(can_peer(&m, &p, &[0, 1, 7]));
    assert!(!can_peer(&m, &p, &[7, NONE_OSD]));
    // P3: C 3 > 2 sites, all up: never
    let p3 = PoolParams {
        peering_crush_bucket_count: 3,
        ..p.clone()
    };
    assert!(!can_peer(&m, &p3, &[0, 1, 2, 3]));
    // M2: degraded stretch mode = C 1 + mandatory surviving site
    let m2 = stretch_map(10, 1, DC1);
    let p2 = m2.pools[&1].clone();
    assert!(can_peer(&m2, &p2, &[1, 0]));
    assert!(!can_peer(&m2, &p2, &[2, 3]));
    assert!(can_peer(&m2, &p2, &[2, 0]));
    // not a stretch pool: always
    let plain = PoolParams {
        peering_crush_bucket_count: 0,
        ..p
    };
    assert!(!plain.is_stretch() && can_peer(&m, &plain, &[0]));
}

/// maybe_went_rw of a closed stretch interval needs can_peer of the old acting set under the OLD pool and the OLD map's
/// buckets (stretch.md 6).
#[test]
fn stretch_past_interval_needs_can_peer() {
    let mut past = PastIntervals::default();
    // old interval [3, 9]: acting [0,1] (dc1 only), primary up_thru 3 = interval start -> rw unless stretch says no
    let one_site = mapping(&[0, 1], &[0, 1]);
    let all = mapping(&[0, 1, 2, 3], &[0, 1, 2, 3]);
    let mut m9 = stretch_map(9, 2, NONE_OSD);
    m9.osds.get_mut(&0).unwrap().up_thru = 3;
    let m10 = stretch_map(10, 2, NONE_OSD);
    let i = step(&mut past, 3, 0, &m9, &m10, &one_site, &all).unwrap();
    assert!(!i.maybe_went_rw, "one site under C 2 never went rw");
    // the same with C 1 in the old pool: rw (new pool C 2 does not matter)
    let mut past = PastIntervals::default();
    let mut m9c1 = stretch_map(9, 1, NONE_OSD);
    m9c1.osds.get_mut(&0).unwrap().up_thru = 3;
    let i = step(&mut past, 3, 0, &m9c1, &m10, &one_site, &all).unwrap();
    assert!(i.maybe_went_rw);
    // the old map's buckets decide: osd.1 was in dc2 then (it moved since)
    let mut past = PastIntervals::default();
    let mut m9mv = m9.clone();
    m9mv.barrier.insert(1, DC2);
    let i = step(&mut past, 3, 0, &m9mv, &m10, &one_site, &all).unwrap();
    assert!(i.maybe_went_rw, "old map: two sites");
    let mut past = PastIntervals::default();
    let mut m10mv = m10.clone();
    m10mv.barrier.insert(1, DC2);
    let i = step(&mut past, 3, 0, &m9, &m10mv, &one_site, &all).unwrap();
    assert!(!i.maybe_went_rw, "new map's buckets are irrelevant");
    // old mandatory member missing: not rw
    let mut past = PastIntervals::default();
    let mut m9m = stretch_map(9, 1, DC2);
    m9m.osds.get_mut(&0).unwrap().up_thru = 3;
    let i = step(&mut past, 3, 0, &m9m, &m10, &one_site, &all).unwrap();
    assert!(!i.maybe_went_rw);
    // lec inside the interval does not override the stretch check
    let mut past = PastIntervals::default();
    let i = step(
        &mut past,
        3,
        5,
        &stretch_map(9, 2, NONE_OSD),
        &m10,
        &one_site,
        &all,
    )
    .unwrap();
    assert!(!i.maybe_went_rw);
}
