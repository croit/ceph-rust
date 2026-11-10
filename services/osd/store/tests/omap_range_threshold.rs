// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Range policy changes physical tombstones only; these vectors verify visible contents, compound
//! ordering, cold queued reads, existing WAL capacity and replay independently of the estimate.
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use std::collections::BTreeMap;
use store::dev::{CrashPolicy, SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::txn::Bytes;
use store::obj::{OTxn, Store, StoreCfg, TOp};

type St = Store<SimDev, SimClock>;

fn identity(name: &[u8]) -> (CollT, Ghobject) {
    (
        CollT::Pg(SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        }),
        Ghobject::new(
            Hobject::new(name, SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        ),
    )
}
fn mount(disk: &SimDisk, cfg: &StoreCfg) -> St {
    let d = disk.clone();
    Store::mount(move || d.queue(), SimClock::default(), cfg.clone())
        .unwrap()
        .0
}
fn fixture(threshold: u64, wal: u64) -> (SimDisk, StoreCfg, St) {
    let disk = SimDisk::new(SimConfig::new(64 << 20));
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
            wal_blocks: wal,
            align_blocks: 1,
            omap_lsm: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut cfg = StoreCfg::default();
    cfg.shard.max_unit_blocks = 4;
    cfg.shard.omap_delete_range_threshold = threshold;
    let mut st = mount(&disk, &cfg);
    let (cid, oid) = identity(b"range-threshold");
    let mut t = OTxn::new();
    t.mkcoll(cid);
    t.touch(cid, &oid);
    st.commit(&t).unwrap();
    (disk, cfg, st)
}
fn put(t: &mut OTxn<'static>, oid: &Ghobject, pairs: Vec<(Vec<u8>, Vec<u8>)>) {
    t.push(TOp::OmapSetKeys {
        cid: identity(b"").0,
        oid: oid.clone(),
        pairs: pairs
            .into_iter()
            .map(|(k, v)| (Bytes::Owned(k), Bytes::Owned(v)))
            .collect(),
    });
}
fn range(t: &mut OTxn<'static>, oid: &Ghobject, first: &[u8], last: &[u8]) {
    t.push(TOp::OmapRmKeyRange {
        cid: identity(b"").0,
        oid: oid.clone(),
        first: Bytes::Owned(first.to_vec()),
        last: Bytes::Owned(last.to_vec()),
    });
}
fn contents(st: &mut St, oid: &Ghobject) -> BTreeMap<Vec<u8>, Vec<u8>> {
    st.omap_all(&identity(b"").0, oid).unwrap()
}
fn shape(st: &St) -> (usize, usize) {
    let o = st.shards[0].sh.state().olsm.as_ref().unwrap();
    let mut points = 0;
    let mut ranges = 0;
    for m in std::iter::once(&o.active).chain(o.frozen.as_deref()) {
        for id in m.sorted_ids() {
            let obj = m.obj(id).unwrap();
            points += obj.map.values().filter(|v| v.is_none()).count();
            ranges += obj.ranges.len();
        }
    }
    (points, ranges)
}
fn queued(st: &mut St, t: &OTxn, token: u64) -> bool {
    st.queue(t, token).unwrap();
    let mut saw_range = false;
    for _ in 0..100_000 {
        saw_range |= shape(st).1 != 0;
        let mut done = Vec::new();
        st.poll(&mut done).unwrap();
        let mut errors = Vec::new();
        st.take_queue_errors(&mut errors);
        assert!(errors.is_empty(), "queued errors: {errors:?}");
        if done.contains(&token) {
            return saw_range;
        }
        st.idle();
    }
    panic!("WARNING TIMEOUT queued range removal exceeded100000 polls");
}
fn reopened(disk: &SimDisk, st: St, cfg: &StoreCfg) -> St {
    remount(disk, st, cfg).1
}
/// Remount a crash image of `disk` with every write persisted, returning the new disk: a later remount must start
/// from it, or it would lose the writes made after this one.
fn remount(disk: &SimDisk, st: St, cfg: &StoreCfg) -> (SimDisk, St) {
    drop(st);
    let disk = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::PERSIST_ALL),
        SimConfig::new(64 << 20),
    );
    let st = mount(&disk, cfg);
    (disk, st)
}

#[test]
fn zero_and_equal_upper_bound_keep_native_range_small_bound_uses_points() {
    // The memtable holds a, b, c; only a and b lie in [a, c), so the bound is 2: zero, below and equal keep the native
    // range, any larger threshold enumerates the two live keys (c outside the range no longer counts).
    for (threshold, points, ranges) in [(0, 0, 1), (1, 0, 1), (2, 0, 1), (3, 2, 0), (4, 2, 0)] {
        let (_disk, _cfg, mut st) = fixture(threshold, 8192);
        let (_, oid) = identity(b"range-threshold");
        let mut t = OTxn::new();
        put(
            &mut t,
            &oid,
            vec![
                (b"a".to_vec(), vec![1]),
                (b"b".to_vec(), vec![2]),
                (b"c".to_vec(), vec![3]),
            ],
        );
        st.commit(&t).unwrap();
        let mut t = OTxn::new();
        range(&mut t, &oid, b"a", b"c");
        st.commit(&t).unwrap();
        assert_eq!(shape(&st), (points, ranges), "threshold {threshold}");
        assert_eq!(
            contents(&mut st, &oid),
            BTreeMap::from([(b"c".to_vec(), vec![3])])
        );
    }
}

#[test]
fn compound_range_sees_earlier_puts_and_preserves_later_puts_after_reopen() {
    let (disk, cfg, mut st) = fixture(100, 8192);
    let (_, oid) = identity(b"range-threshold");
    let (_, other) = identity(b"other-object");
    let mut init = OTxn::new();
    put(
        &mut init,
        &oid,
        vec![
            (b"a".to_vec(), vec![1]),
            (b"b".to_vec(), vec![2]),
            (b"c".to_vec(), vec![3]),
        ],
    );
    put(&mut init, &other, vec![(b"b".to_vec(), vec![99])]);
    st.commit(&init).unwrap();
    let mut t = OTxn::new();
    put(
        &mut t,
        &oid,
        vec![
            (b"b".to_vec(), vec![4]),
            (b"b\0".to_vec(), vec![5]),
            (b"d".to_vec(), vec![6]),
        ],
    );
    range(&mut t, &oid, b"b", b"d");
    put(&mut t, &oid, vec![(b"c".to_vec(), vec![7])]);
    range(&mut t, &oid, b"a", b"b");
    st.commit(&t).unwrap();
    assert_eq!(shape(&st).1, 0);
    let want = BTreeMap::from([(b"c".to_vec(), vec![7]), (b"d".to_vec(), vec![6])]);
    assert_eq!(contents(&mut st, &oid), want);
    assert_eq!(
        contents(&mut st, &other),
        BTreeMap::from([(b"b".to_vec(), vec![99])])
    );
    let mut st = reopened(&disk, st, &cfg);
    assert_eq!(contents(&mut st, &oid), want);
}

#[test]
fn binary_half_open_ranges_clear_and_reinsert_preserve_transaction_order() {
    let (_disk, _cfg, mut st) = fixture(100, 8192);
    let (cid, oid) = identity(b"range-threshold");
    let keys = [b"".as_slice(), b"\0", b"\0\xff", b"a", b"a\0", b"z"];
    let mut t = OTxn::new();
    put(
        &mut t,
        &oid,
        keys.iter()
            .enumerate()
            .map(|(i, k)| (k.to_vec(), vec![i as u8]))
            .collect(),
    );
    st.commit(&t).unwrap();
    let mut t = OTxn::new();
    range(&mut t, &oid, b"\0", b"a\0");
    st.commit(&t).unwrap();
    assert_eq!(
        contents(&mut st, &oid),
        BTreeMap::from([
            (vec![], vec![0]),
            (b"a\0".to_vec(), vec![4]),
            (b"z".to_vec(), vec![5])
        ])
    );
    let mut t = OTxn::new();
    t.push(TOp::OmapClear {
        cid,
        oid: oid.clone(),
    });
    put(&mut t, &oid, vec![(b"x".to_vec(), vec![9])]);
    range(&mut t, &oid, b"x", b"z");
    put(&mut t, &oid, vec![(b"y".to_vec(), vec![10])]);
    st.commit(&t).unwrap();
    assert_eq!(
        contents(&mut st, &oid),
        BTreeMap::from([(b"y".to_vec(), vec![10])])
    );
}

#[test]
fn empty_reversed_absent_spans_and_missing_objects_do_not_remove_survivors() {
    let (_disk, _cfg, mut st) = fixture(100, 8192);
    let (cid, oid) = identity(b"range-threshold");
    let (_, missing) = identity(b"missing");
    let want = BTreeMap::from([(b"a".to_vec(), vec![1]), (b"z".to_vec(), vec![2])]);
    let mut t = OTxn::new();
    put(&mut t, &oid, want.clone().into_iter().collect());
    st.commit(&t).unwrap();
    let mut t = OTxn::new();
    range(&mut t, &oid, b"b", b"b");
    range(&mut t, &oid, b"z", b"a");
    range(&mut t, &oid, b"b", b"c");
    range(&mut t, &missing, b"", b"zz");
    st.commit(&t).unwrap();
    assert_eq!(contents(&mut st, &oid), want);
    assert!(st.stat(&cid, &missing).unwrap().is_none());
    assert_eq!(shape(&st), (0, 0));
}

#[test]
fn queued_cold_run_range_finishes_and_keeps_both_boundaries() {
    let (disk, cfg, mut st) = fixture(100_000, 256);
    let (_, oid) = identity(b"range-threshold");
    let mut want = BTreeMap::new();
    for batch in 0..16u32 {
        let kv: Vec<_> = (batch * 64..(batch + 1) * 64)
            .map(|i| (format!("{i:06}").into_bytes(), vec![i as u8; 512]))
            .collect();
        want.extend(kv.clone());
        let mut t = OTxn::new();
        put(&mut t, &oid, kv);
        st.commit(&t).unwrap();
    }
    for _ in 0..20_000 {
        if st.shards[0].sh.olsm_stats().unwrap().runs > 0
            && st.shards[0]
                .sh
                .state()
                .olsm
                .as_ref()
                .unwrap()
                .frozen
                .is_none()
        {
            break;
        }
        let mut done = Vec::new();
        st.poll(&mut done).unwrap();
        st.idle();
    }
    assert!(st.shards[0].sh.olsm_stats().unwrap().runs > 0);
    st.shards[0].sh.olsm_drop_cache();
    let before = st.shards[0].sh.olsm_stats().unwrap().reads;
    let mut t = OTxn::new();
    range(&mut t, &oid, b"000100", b"000900");
    assert!(
        !queued(&mut st, &t, 9001),
        "small bound should stage point tombstones"
    );
    assert!(
        st.shards[0].sh.olsm_stats().unwrap().reads > before,
        "cold point enumeration reads run chunks"
    );
    want.retain(|k, _| k.as_slice() < b"000100".as_slice() || k.as_slice() >= b"000900".as_slice());
    assert_eq!(contents(&mut st, &oid), want);
    let mut st = reopened(&disk, st, &cfg);
    assert_eq!(contents(&mut st, &oid), want);
}

/// 1024 keys with 512-byte values flushed into runs, remounted without scan read-ahead and with a cold run cache:
/// every run chunk a non-blocking staging run touches refuses it once.
fn cold_store() -> (SimDisk, StoreCfg, St, Ghobject, BTreeMap<Vec<u8>, Vec<u8>>) {
    let (disk, mut cfg, mut st) = fixture(100_000, 256);
    let (_, oid) = identity(b"range-threshold");
    let mut want = BTreeMap::new();
    for batch in 0..16u32 {
        let kv: Vec<_> = (batch * 64..(batch + 1) * 64)
            .map(|i| (format!("{i:06}").into_bytes(), vec![i as u8; 512]))
            .collect();
        want.extend(kv.clone());
        let mut t = OTxn::new();
        put(&mut t, &oid, kv);
        st.commit(&t).unwrap();
    }
    for _ in 0..20_000 {
        let o = st.shards[0].sh.state().olsm.as_ref().unwrap();
        if o.frozen.is_none()
            && o.active.is_empty()
            && st.shards[0].sh.olsm_stats().unwrap().runs > 0
        {
            break;
        }
        let mut done = Vec::new();
        st.poll(&mut done).unwrap();
        st.idle();
    }
    cfg.shard.omap_scan_prefetch = false;
    let (disk, mut st) = remount(&disk, st, &cfg);
    st.shards[0].sh.olsm_drop_cache();
    (disk, cfg, st, oid, want)
}

/// Without read-ahead every cold run chunk refuses the non-blocking staging run. Each retry continues the enumeration
/// from the saved position (`scan_resumes`) instead of rescanning the range, and the result is exact.
#[test]
fn cold_point_range_enumeration_resumes_across_refused_runs() {
    let (disk, cfg, mut st, oid, mut want) = cold_store();
    let resumes = st.shards[0].stats.scan_resumes;
    let mut t = OTxn::new();
    range(&mut t, &oid, b"000100", b"000900");
    assert!(
        !queued(&mut st, &t, 9002),
        "small bound should stage point tombstones"
    );
    assert!(
        st.shards[0].stats.scan_resumes >= resumes + 2,
        "the cold multi-chunk enumeration continues across refused runs"
    );
    want.retain(|k, _| k.as_slice() < b"000100".as_slice() || k.as_slice() >= b"000900".as_slice());
    assert_eq!(contents(&mut st, &oid), want);
    // Two removals of the same cold span in one transaction: each continues only its own enumeration (operation
    // index), and the second sees the first's deletions in the transaction overlay.
    let (disk, mut st) = remount(&disk, st, &cfg);
    st.shards[0].sh.olsm_drop_cache();
    let mut t = OTxn::new();
    range(&mut t, &oid, b"000900", b"001000");
    range(&mut t, &oid, b"000900", b"001000");
    queued(&mut st, &t, 9003);
    want.retain(|k, _| k.as_slice() < b"000900".as_slice() || k.as_slice() >= b"001000".as_slice());
    assert_eq!(contents(&mut st, &oid), want);
    let (_, mut st) = remount(&disk, st, &cfg);
    assert_eq!(contents(&mut st, &oid), want);
}

/// A transaction removes a small range A and then a large cold range B. Every retry re-applies A first; A must not
/// discard B's saved enumeration, so B continues across all its refused runs instead of restarting each time.
#[test]
fn earlier_range_keeps_a_later_ranges_saved_enumeration() {
    let (disk, cfg, mut st, oid, mut want) = cold_store();
    let a: Vec<_> = (0..8u32)
        .map(|i| (format!("a{i:03}").into_bytes(), vec![1u8; 16]))
        .collect();
    let mut t = OTxn::new();
    put(&mut t, &oid, a);
    st.commit(&t).unwrap();
    let resumes = st.shards[0].stats.scan_resumes;
    let mut t = OTxn::new();
    range(&mut t, &oid, b"a000", b"a100");
    range(&mut t, &oid, b"000100", b"000900");
    assert!(
        !queued(&mut st, &t, 9004),
        "both small bounds should stage point tombstones"
    );
    assert!(
        st.shards[0].stats.scan_resumes >= resumes + 3,
        "B continues across its refused runs although A is re-applied first"
    );
    want.retain(|k, _| k.as_slice() < b"000100".as_slice() || k.as_slice() >= b"000900".as_slice());
    assert_eq!(contents(&mut st, &oid), want);
    let (_, mut st) = remount(&disk, st, &cfg);
    assert_eq!(contents(&mut st, &oid), want);
}

fn long_key(prefix: u8, n: u32) -> Vec<u8> {
    let mut k = vec![prefix; 400];
    k[1..9].copy_from_slice(format!("{n:08x}").as_bytes());
    k
}

#[test]
fn tiny_wal_later_compound_put_uses_native_range_when_point_expansion_would_not_fit() {
    let (disk, cfg, mut st) = fixture(10_000, 256);
    let (_, oid) = identity(b"range-threshold");
    for batch in 0..10u32 {
        let mut t = OTxn::new();
        put(
            &mut t,
            &oid,
            (batch * 80..(batch + 1) * 80)
                .map(|i| (long_key(b'a', i), vec![1]))
                .collect(),
        );
        st.commit(&t).unwrap();
    }
    // Point tombstones need ~320KiB; the later put needs another ~328KiB. Each original
    // operation fits the tiny ring, but their expanded compound record cannot fit its half-ring cap.
    let after: Vec<_> = (0..500)
        .map(|i| (long_key(b'z', i), vec![2; 256]))
        .collect();
    let mut t = OTxn::new();
    range(&mut t, &oid, b"a", b"b");
    put(&mut t, &oid, after.clone());
    assert!(
        queued(&mut st, &t, 9002),
        "WAL expansion must revert to a native range"
    );
    let want: BTreeMap<_, _> = after.into_iter().collect();
    assert_eq!(contents(&mut st, &oid), want);
    let mut st = reopened(&disk, st, &cfg);
    assert_eq!(contents(&mut st, &oid), want);
}

#[test]
fn runtime_threshold_switches_on_the_same_object_without_remounting() {
    let (_disk, _cfg, mut st) = fixture(0, 8192);
    let (_, oid) = identity(b"range-threshold");
    let mut want: BTreeMap<_, _> = (0..384u32)
        .map(|i| (format!("k{i:04}").into_bytes(), i.to_le_bytes().to_vec()))
        .collect();
    let mut init = OTxn::new();
    put(&mut init, &oid, want.clone().into_iter().collect());
    st.commit(&init).unwrap();
    let initial_runs = st.shards[0].sh.olsm_stats().unwrap().runs;

    for (threshold, first, last, expected_shape, token) in [
        (
            1_048_576,
            b"k0000".as_slice(),
            b"k0064".as_slice(),
            (64, 0),
            9101,
        ),
        (32, b"k0128".as_slice(), b"k0192".as_slice(), (64, 1), 9102),
        (0, b"k0256".as_slice(), b"k0320".as_slice(), (64, 2), 9103),
    ] {
        st.set_omap_delete_range_threshold(threshold);
        assert!(
            st.shards
                .iter()
                .all(|s| s.sh.omap_delete_range_threshold() == threshold)
        );
        let mut t = OTxn::new();
        range(&mut t, &oid, first, last);
        let saw_range = queued(&mut st, &t, token);
        assert_eq!(saw_range, threshold != 1_048_576);
        want.retain(|k, _| k.as_slice() < first || k.as_slice() >= last);
        assert_eq!(shape(&st), expected_shape, "threshold {threshold}");
        assert_eq!(contents(&mut st, &oid), want);
        assert_eq!(st.shards[0].sh.olsm_stats().unwrap().runs, initial_runs);
    }
    assert_eq!(want.len(), 192);
}

#[test]
fn runtime_threshold_updates_only_the_mounted_owner_shards() {
    let disk = SimDisk::new(SimConfig::new(64 << 20));
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 4,
            wal_blocks: 1024,
            align_blocks: 1,
            omap_lsm: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut even = Store::mount_shards(
        || disk.queue(),
        SimClock::default(),
        StoreCfg::default(),
        |id| id % 2 == 0,
    )
    .unwrap()
    .0;
    let odd = Store::mount_shards(
        || disk.queue(),
        SimClock::default(),
        StoreCfg::default(),
        |id| id % 2 == 1,
    )
    .unwrap()
    .0;
    assert_eq!(
        even.shards.iter().map(|s| s.idx).collect::<Vec<_>>(),
        vec![0, 2]
    );
    assert_eq!(
        odd.shards.iter().map(|s| s.idx).collect::<Vec<_>>(),
        vec![1, 3]
    );
    for threshold in [1_048_576, 32, 0] {
        even.set_omap_delete_range_threshold(threshold);
        assert!(
            even.shards
                .iter()
                .all(|s| s.sh.omap_delete_range_threshold() == threshold)
        );
        assert!(
            odd.shards
                .iter()
                .all(|s| s.sh.omap_delete_range_threshold() == 0)
        );
    }
}
