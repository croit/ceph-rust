// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Omap batch runs (adr 0476) at shard level: runs overlay the tree for point reads and scans, tree ops
//! on run keys kill their entries, merges move the newest entries into the tree, the WAL floor keeps the records of live
//! runs across checkpoints and crashes (the replay window rebuilds the runs).
mod common;
use common::*;
use std::collections::BTreeMap;
use store::StoreError;
use store::dev::{BlockDev, Clock, CrashPolicy, SimDisk};
use store::obj::keys::omap_key;
use store::runs::{RunBuilder, omap_id};
use store::shard::{ShardCfg, Txn};
use store::state::Op;

fn env() -> Env {
    let cfg = ShardCfg {
        cache_pages: 256,
        dirty_soft_pages: 48,
        dirty_hard_pages: 400,
        ..Default::default()
    };
    make_env(64, 512, 1, cfg)
}

fn ok(id: u64, i: u64) -> Vec<u8> {
    omap_key(id, format!("key{i:06}").as_bytes())
}

/// Inline value record (form 0).
fn val(i: u64, g: u64) -> Vec<u8> {
    let mut v = vec![0u8];
    v.extend_from_slice(format!("v{i}-{g}-{:x<40}", "").as_bytes());
    v
}

fn omap_range(id: u64) -> (Vec<u8>, Vec<u8>) {
    (omap_key(id, b""), omap_key(id + 1, b""))
}

/// A run of object `id` with the entries `(i, generation)` (sorted, last generation of a repeated key wins).
fn run(id: u64, ents: impl IntoIterator<Item = (u64, u64)>) -> Op {
    let m: BTreeMap<Vec<u8>, Vec<u8>> = ents
        .into_iter()
        .map(|(i, g)| (ok(id, i), val(i, g)))
        .collect();
    let mut b = RunBuilder::default();
    for (k, v) in &m {
        b.push(k, &[], v, &[]);
    }
    Op::RunPut(b.finish(id).expect("non-empty run"))
}

/// A run of object `id` removing the keys `is` (adr 0647-omap-blind-removals D1: entries with an empty value).
fn rm_run(id: u64, is: impl IntoIterator<Item = u64>) -> Op {
    let ks: std::collections::BTreeSet<Vec<u8>> = is.into_iter().map(|i| ok(id, i)).collect();
    let mut b = RunBuilder::default();
    for k in &ks {
        b.push(k, &[], &[], &[]);
    }
    Op::RunPut(b.finish(id).expect("non-empty run"))
}

fn merge(id: u64, fin: bool, a: Vec<u8>, b: Vec<u8>) -> Op {
    Op::RunMerge {
        id,
        upto: u64::MAX,
        a,
        b,
        fin,
    }
}

/// Merge every run of `id` into the tree in one txn.
fn merge_obj(r: &mut Rig, id: u64) {
    let mut hi = omap_key(id, b"");
    *hi.last_mut().unwrap() += 1;
    r.txn(vec![merge(id, true, omap_key(id, b""), hi)]);
    r.sync();
}

/// The shard's own sliced merges (idle trigger) empty the runs.
fn idle_drain(r: &mut Rig) {
    let mut guard = 0;
    while !r.shard.state().runs.is_empty() {
        r.clk.t += 1_000_000;
        r.pump();
        guard += 1;
        assert!(guard < 100_000, "idle drain never emptied the runs");
    }
}

fn merge_all(r: &mut Rig) {
    let ids: Vec<u64> = r.shard.state().runs.ids().collect();
    for id in ids {
        merge_obj(r, id);
    }
    assert!(r.shard.state().runs.is_empty());
}

/// Shard content == model; point reads and a small-budget scan agree.
fn check(r: &mut Rig) {
    let got: BTreeMap<Vec<u8>, Vec<u8>> = r
        .shard
        .dump_blocking(&mut r.clk)
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(got.len(), r.model.len(), "key count");
    assert!(got == r.model, "content differs from model");
    for (k, v) in r.model.clone() {
        assert_eq!(r.get(&k), Some(v));
    }
    let (a, b) = (b"o".to_vec(), b"p".to_vec());
    assert_eq!(r.scan(&a, &b, 7), r.model_range(&a, &b), "budgeted scan");
}

fn crash_remount(r: &mut Rig) -> store::wal::ReplayStats {
    r.sync();
    let img = r.disk.crash_image(CrashPolicy::DROP_ALL);
    r.disk = SimDisk::from_image(&img, r.env.sim.clone());
    let (shard, stats) = mount(&r.env, &r.disk, &mut r.clk).unwrap();
    r.shard = shard;
    r.submitted = 0;
    r.acked = 0;
    stats
}

#[test]
fn runs_overlay_the_tree_and_merge_exactly() {
    let env = env();
    let mut r = Rig::new(&env, 1);
    let id = 7;
    r.apply((0..300).map(|i| Op::Put(ok(id, i), val(i, 0))).collect());
    // overwrite odd keys and add new keys in two runs (the second shadows the first where they overlap)
    r.apply(vec![run(
        id,
        (0..400).filter(|i| i % 2 == 1 || *i >= 300).map(|i| (i, 1)),
    )]);
    r.apply(vec![run(id, (250..350).map(|i| (i, 2)))]);
    assert_eq!(r.shard.state().runs.n_runs(), 2);
    check(&mut r);
    merge_all(&mut r);
    check(&mut r);
    r.remount_clean();
    check(&mut r);
}

#[test]
fn tree_ops_on_run_keys_kill_them() {
    let env = env();
    let mut r = Rig::new(&env, 2);
    let id = 3;
    r.apply(vec![run(id, (0..50).map(|i| (i, 1)))]);
    // tree put / del of run keys, a range delete over run and absent keys
    r.apply(vec![Op::Put(ok(id, 1), val(1, 2)), Op::Del(ok(id, 2))]);
    r.delrange(&ok(id, 10), &ok(id, 20));
    check(&mut r);
    // a later run brings a killed key back: the newest run decides
    r.apply(vec![run(id, [(2, 3), (15, 3)])]);
    check(&mut r);
    merge_all(&mut r);
    check(&mut r);
    // a clear of the whole object space drops the runs
    r.apply(vec![run(id, (100..120).map(|i| (i, 4)))]);
    r.apply(vec![Op::DelRange(omap_range(id).0, omap_range(id).1)]);
    assert!(
        r.shard.state().runs.is_empty(),
        "the clear dropped the runs"
    );
    check(&mut r);
}

/// Blind omap removals and puts (a record's ascending stretch of tree ops, adr 0476 am. 5) kill the run entries of
/// their keys unread: tree-only, tree + run, run-only and absent keys; WAL replay kills the same; the merge moves only
/// what is left.
#[test]
fn blind_tree_ops_kill_run_entries() {
    let env = env();
    let mut r = Rig::new(&env, 5);
    let (d, p) = (11, 12);
    for id in [d, p] {
        r.apply((0..300).map(|i| Op::Put(ok(id, i), val(i, 0))).collect());
        r.apply(vec![run(id, (250..400).map(|i| (i, 1)))]);
    }
    // tree-only key, tree + run key, run-only key, absent key (sorted: the stage emits ascending keys)
    let mut ops: Vec<Op> = [0u64, 5, 260, 310, 500]
        .iter()
        .map(|&i| Op::Del(ok(d, i)))
        .collect();
    ops.extend(
        [0u64, 260, 310, 500]
            .iter()
            .map(|&i| Op::Put(ok(p, i), val(i, 12345))),
    );
    r.apply(ops);
    check(&mut r);
    let st = crash_remount(&mut r);
    assert!(st.txns > 0, "replayed the blind ops: {st:?}");
    check(&mut r);
    merge_all(&mut r);
    check(&mut r);
    // a blind op in the record that clears the object
    r.apply(vec![
        Op::Del(ok(d, 1)),
        Op::DelRange(omap_range(d).0, omap_range(d).1),
        Op::Put(ok(d, 2), val(2, 3)),
    ]);
    check(&mut r);
}

/// Runs of removals (adr 0647-omap-blind-removals D1) shadow the tree and older runs for point reads and scans:
/// tree-only, tree + run, run-only and absent keys; a newer run or a tree put brings a removed key back; tree removals
/// and range removals over removed keys change nothing visible; the replay window rebuilds the removals after a power
/// cut; the merge deletes the keys that exist and empties the runs.
#[test]
fn removal_runs_shadow_the_tree_and_merge_exactly() {
    let env = env();
    let mut r = Rig::new(&env, 21);
    let id = 9;
    r.apply((0..300).map(|i| Op::Put(ok(id, i), val(i, 0))).collect());
    r.apply(vec![run(id, (250..400).map(|i| (i, 1)))]);
    r.apply(vec![rm_run(
        id,
        (0..50).chain(260..270).chain(320..330).chain(500..510),
    )]);
    for i in [0u64, 49, 260, 269, 320, 329, 500] {
        assert_eq!(r.get(&ok(id, i)), None, "key {i} removed");
    }
    assert!(r.get(&ok(id, 50)).is_some() && r.get(&ok(id, 330)).is_some());
    check(&mut r);
    // delete then reinsert: a newer run and a tree put; a tree removal of a removed key, a range removal over removed
    // and live keys
    r.apply(vec![run(id, (0..10).map(|i| (i, 2)))]);
    r.apply(vec![Op::Put(ok(id, 20), val(20, 3)), Op::Del(ok(id, 30))]);
    r.delrange(&ok(id, 40), &ok(id, 60));
    check(&mut r);
    // a checkpoint: the records of the live runs stay in the floor window (replayed into the runs only)
    r.checkpoint();
    // a newer removal run over keys brought back and keys removed already
    r.apply(vec![rm_run(id, (5..25).chain(320..340))]);
    check(&mut r);
    let st = crash_remount(&mut r);
    assert!(
        st.run_txns > 0 && st.txns > 0,
        "replayed the run window and the newer records: {st:?}"
    );
    check(&mut r);
    merge_all(&mut r);
    check(&mut r);
    r.remount_clean();
    check(&mut r);
}

/// Merges of removal runs leaf by leaf (`Tree::write_sorted_batch`): removals that empty whole leaves (pruned), thin
/// them (merge candidates), mix with puts in one leaf, or find no key (the leaf stays clean); content and scans match
/// the model after every merge, the tree shrinks back when every key is gone, a remount agrees.
#[test]
fn removal_merges_empty_and_thin_leaves() {
    let env = env();
    let mut r = Rig::new(&env, 22);
    let id = 4;
    r.apply(vec![run(id, (0..3000).map(|i| (i, 0)))]);
    merge_obj(&mut r, id);
    let h0 = r.shard.state().tree.height();
    assert!(h0 >= 2, "a tree of several leaves");
    check(&mut r);
    // removals of absent keys only: no leaf changes
    r.checkpoint();
    r.apply(vec![rm_run(
        id,
        (5000..5200).chain((0..3000).map(|i| 100_000 + i * 7)),
    )]);
    merge_obj(&mut r, id);
    assert_eq!(
        r.shard.state().tree.dirty_pages(),
        0,
        "removals of absent keys dirtied pages"
    );
    check(&mut r);
    let pruned = r.shard.state().tree.stats.pruned;
    // whole leaves: a contiguous block
    r.apply(vec![rm_run(id, 500..1500)]);
    merge_obj(&mut r, id);
    check(&mut r);
    assert!(
        r.shard.state().tree.stats.pruned > pruned,
        "emptied leaves pruned"
    );
    // thinned leaves: three of every four keys, with absent keys between; a single removal in a leaf
    let merged = r.shard.state().tree.stats.merged;
    r.apply(vec![rm_run(
        id,
        (1500..2500)
            .filter(|i| i % 4 != 0)
            .chain(2500..2501)
            .chain(9000..9010),
    )]);
    idle_drain(&mut r);
    check(&mut r);
    assert!(
        r.shard.state().tree.stats.merged > merged,
        "thinned leaves merged"
    );
    // puts and removals in the same leaves (a newer put run over removed keys, an older removal of put keys)
    r.apply(vec![rm_run(id, (2600..2800).filter(|i| i % 3 != 0))]);
    r.apply(vec![run(id, (2600..2700).map(|i| (i, 1)))]);
    merge_obj(&mut r, id);
    check(&mut r);
    // everything goes: the tree shrinks
    r.apply(vec![rm_run(id, 0..3000)]);
    idle_drain(&mut r);
    check(&mut r);
    assert!(r.model.is_empty());
    assert!(
        r.shard.state().tree.height() < h0,
        "the emptied tree collapsed: height {} (was {h0})",
        r.shard.state().tree.height()
    );
    r.remount_clean();
    check(&mut r);
}

#[test]
fn floor_keeps_run_records_across_checkpoints_and_crashes() {
    let env = env();
    let mut r = Rig::new(&env, 3);
    let id = 9;
    r.apply((0..200).map(|i| Op::Put(ok(id, i), val(i, 0))).collect());
    r.checkpoint();
    for g in 1..=3 {
        r.apply(vec![run(
            id,
            (0..200).filter(|i| i % 3 == g % 3).map(|i| (i, g)),
        )]);
        // unrelated tree traffic moves the checkpoint past the run records
        r.apply(
            (0..20)
                .map(|i| Op::Put(format!("x/{g}/{i}").into_bytes(), val(i, g)))
                .collect(),
        );
        r.checkpoint();
        assert!(r.shard.floor_blocks() > 0, "the floor holds ring units");
    }
    let st = crash_remount(&mut r);
    assert!(st.run_txns > 0, "replay window rebuilt the runs");
    assert_eq!(st.txns, 0, "everything was checkpointed");
    assert_eq!(r.shard.state().runs.n_runs(), 3);
    check(&mut r);
    // merge half, crash before its checkpoint
    r.txn(vec![merge(id, false, ok(id, 0), ok(id, 100))]);
    crash_remount(&mut r);
    check(&mut r);
    // merge half, checkpoint, crash
    r.txn(vec![merge(id, false, ok(id, 0), ok(id, 100))]);
    r.checkpoint();
    crash_remount(&mut r);
    check(&mut r);
    merge_all(&mut r);
    r.checkpoint();
    assert_eq!(r.shard.floor_blocks(), 0);
    let st = crash_remount(&mut r);
    assert_eq!(st.run_txns, 0, "no runs: plain root");
    check(&mut r);
}

#[test]
fn record_rules() {
    let env = env();
    let mut r = Rig::new(&env, 4);
    let submit = |r: &mut Rig, ops: Vec<Op>| {
        let mut t: Txn<Vec<u8>> = Txn::new(1);
        t.ops = ops;
        r.shard.submit(t).map(|_| ()).map_err(|e| e.0)
    };
    // a tree op after a run in one record
    assert!(matches!(
        submit(&mut r, vec![run(1, [(1, 1)]), Op::Put(ok(1, 1), val(1, 2))]),
        Err(StoreError::Invalid(_))
    ));
    // a merge mixed with other ops
    assert!(matches!(
        submit(
            &mut r,
            vec![
                Op::Put(ok(1, 1), val(1, 2)),
                merge(1, true, ok(1, 0), ok(1, 9))
            ]
        ),
        Err(StoreError::Invalid(_))
    ));
    // a merge range of another object
    assert!(matches!(
        submit(&mut r, vec![merge(1, true, ok(2, 0), ok(2, 9))]),
        Err(StoreError::Invalid(_))
    ));
    // tree ops first, then runs: fine
    assert!(
        submit(
            &mut r,
            vec![
                Op::Put(ok(1, 5), val(5, 1)),
                run(1, [(1, 1)]),
                run(2, [(1, 1)])
            ]
        )
        .is_ok()
    );
    // a logged run must decode only as a valid run of its object
    let b = {
        let mut b = RunBuilder::default();
        b.push(&ok(1, 1), &[], &val(1, 1), &[]);
        b.finish(1).unwrap()
    };
    assert!(store::runs::RunBlob::decode(2, 1, bytes::Bytes::copy_from_slice(b.raw())).is_none());
}

#[test]
fn merges_drain_the_runs_and_survive_crashes() {
    let cfg = ShardCfg {
        cache_pages: 256,
        dirty_soft_pages: 48,
        dirty_hard_pages: 400,
        ckpt_interval_ns: 300_000,
        run_soft_bytes: 16 << 10,
        run_max: 4,
        ..Default::default()
    };
    let env = make_env(64, 512, 1, cfg);
    let mut r = Rig::new(&env, 5);
    let id = 11;
    let mut merges = 0;
    for round in 0..30u64 {
        let mut ents = Vec::new();
        for _ in 0..100 {
            ents.push((r.rng.next_u64() % 3000, round));
        }
        r.apply(vec![run(id, ents)]);
        // a tree removal of a random key now and then
        if round % 3 == 0 {
            let i = r.rng.next_u64() % 3000;
            r.apply(vec![Op::Del(ok(id, i))]);
        }
        // polls run the merges
        r.sync();
        if round % 10 == 9 {
            merges += r.shard.stats.run_merges;
            crash_remount(&mut r);
        }
        check(&mut r);
    }
    assert!(merges > 0, "soft size merges ran");
    idle_drain(&mut r);
    r.checkpoint();
    assert_eq!(r.shard.floor_blocks(), 0);
    check(&mut r);
    crash_remount(&mut r);
    check(&mut r);
}

/// A merge slice retires its entries from the runs at once (OQ 103): live entries fall slice by slice, runs newer than
/// the merge keep theirs, reads stay exact, the floor leaves the parts merged, and a crash in the middle of the merge
/// (checkpoint between slices, replay of the rest) rebuilds the same state.
#[test]
fn merge_slices_retire_their_entries() {
    let env = env();
    let mut r = Rig::new(&env, 21);
    let id = 9;
    // three old runs (the merge's), then one newer run over the same keys
    for g in 0..3u64 {
        r.apply(vec![run(id, (0..400).map(|i| (i * 3 + g, g)))]);
    }
    r.sync();
    let upto = r.shard.state().runs.newest(id).unwrap();
    r.apply(vec![run(id, (0..200).map(|i| (i * 6, 9)))]);
    r.sync();
    let e0 = r.shard.state().runs.entries();
    let cut = |i: u64| ok(id, i);
    let (lo, hi) = omap_range(id);
    let slice = |a: Vec<u8>, b: Vec<u8>, fin: bool| Op::RunMerge {
        id,
        upto,
        a,
        b,
        fin,
    };
    // first quarter: live entries fall by the old runs' share
    r.txn(vec![slice(lo.clone(), cut(300), false)]);
    r.sync();
    let st = r.shard.state();
    assert_eq!(
        st.runs.entries() - st.runs.dead_ents(),
        e0 - 300,
        "the old runs' entries below the cut left"
    );
    check(&mut r);
    // second quarter
    r.txn(vec![slice(cut(300), cut(600), false)]);
    r.sync();
    let st = r.shard.state();
    assert_eq!(
        st.runs.entries() - st.runs.dead_ents(),
        e0 - 600,
        "the old runs' entries below the cut left"
    );
    check(&mut r);
    r.checkpoint();
    // a crash after a further slice: replay retires it again from the logged runs
    r.txn(vec![slice(cut(600), cut(900), false)]);
    r.sync();
    // (compactions may regroup the runs after the remount: compare the overlay's keys)
    let (a, b) = omap_range(id);
    let keys = |r: &Rig| r.shard.state().runs.scan(&a, &b).count();
    let k3 = keys(&r);
    crash_remount(&mut r);
    assert_eq!(keys(&r), k3, "replay retires the same entries");
    check(&mut r);
    r.txn(vec![slice(cut(900), hi, true)]);
    r.sync();
    // only runs newer than the merge are left (after the remount a compaction may have taken the old runs' rest into one)
    assert!(
        r.shard
            .state()
            .runs
            .obj(id)
            .unwrap()
            .runs
            .iter()
            .all(|x| x.lsn > upto)
    );
    check(&mut r);
    crash_remount(&mut r);
    check(&mut r);
}

/// The run budget of an object (`run_max`) counts its runs above the barrier of a tree merge of it in progress: the
/// merge's inputs never hold back new runs (counted, they left a few slots for the whole merge and every new run waited
/// for a forced compaction or the merge's end, doc/perf/bfill-rate-20261026.md).
#[test]
fn runs_under_a_merge_leave_the_run_budget_to_new_runs() {
    let pool = std::sync::Arc::new(store::runs::RunPool::default());
    let cfg = ShardCfg {
        cache_pages: 256,
        dirty_soft_pages: 48,
        dirty_hard_pages: 400,
        run_soft_bytes: 64 << 10,
        run_max: 6,
        run_pool: Some(pool),
        ..Default::default()
    };
    let env = make_env(64, 512, 1, cfg);
    let mut r = Rig::new(&env, 9);
    let id = 12;
    let runs = |r: &Rig| r.shard.state().runs.obj(id).map_or(0, |o| o.runs.len());
    let above = |r: &Rig, b: u64| {
        r.shard
            .state()
            .runs
            .obj(id)
            .map_or(0, |o| o.runs.iter().filter(|x| x.lsn > b).count())
    };
    let (mut barrier, mut checked, mut over) = (None, 0, 0);
    for round in 0..3000u64 {
        r.apply(vec![run(id, (0..20).map(|j| (j * 5000 + round, round)))]);
        r.clk.t += 50_000;
        r.sync();
        if r.shard.run_gauges()[4] == 0 {
            barrier = None;
            continue;
        }
        // a merge started in this pump: it took every run up to the newest one before this round's
        let b = *barrier.get_or_insert_with(|| r.shard.state().runs.newest(id).unwrap_or(0));
        if above(&r, b) < 6 {
            assert!(
                r.shard.run_room_obj(id),
                "a new run waits behind the merge's inputs"
            );
            checked += 1;
            over += usize::from(runs(&r) >= 6);
        }
    }
    assert!(
        checked > 0 && over > 0,
        "no merge held {over}/{checked} the budget's worth of runs"
    );
    check(&mut r);
}

/// Merged value compression samples its attempts per value class across merge records (adr 0476, the stage's
/// `VcAdapt` rule): incompressible values merged in many small slices are mostly not tried (a per-record reset tried
/// every class again in each slice: one zstd call per value of a short slice for nothing, the PG core's largest cost of
/// a 1M-key populate, doc/perf/bfill-rate-20261026.md), and a compressible kind of the same class afterwards is picked
/// up again at once.
#[test]
fn merge_compression_samples_across_slices() {
    let env = env();
    let mut r = Rig::new(&env, 23);
    let id = 9;
    let mut rng = store::rng::Rng::new(3);
    let mut rand_val = |len: usize| {
        let mut v = vec![0u8; len + 1];
        rng.fill(&mut v[1..]);
        v[0] = 0; // inline value record
        v[1] = b'r'; // one value class
        v
    };
    // a dictionary of that class, trained on random bytes: attempts on random values fail
    let samples: Vec<Vec<u8>> = (0..64).map(|_| rand_val(300)[1..].to_vec()).collect();
    let cls = store::obj::onode::dict_class(&samples[0]);
    let zd = store::obj::onode::ZDict::train(&samples).expect("dictionary");
    r.shard.state().dicts.slots[cls]
        .set(std::sync::Arc::new(zd))
        .expect("fresh slot");
    r.shard.state_mut().vc_min = 64;
    let put = |r: &mut Rig, lo: u64, n: u64, val: &mut dyn FnMut() -> Vec<u8>| {
        let mut b = RunBuilder::default();
        for i in lo..lo + n {
            b.push(&ok(id, i), &[], &val(), &[]);
        }
        r.apply(vec![Op::RunPut(b.finish(id).expect("run"))]);
        r.sync();
    };
    let slices = |r: &mut Rig, lo: u64, n: u64| {
        let upto = r.shard.state().runs.newest(id).unwrap();
        for s in 0..n / 10 {
            let a = ok(id, lo + s * 10);
            let fin = s + 1 == n / 10;
            let b = if fin {
                omap_range(id).1
            } else {
                ok(id, lo + s * 10 + 10)
            };
            r.txn(vec![Op::RunMerge {
                id,
                upto,
                a,
                b,
                fin,
            }]);
            r.sync();
        }
        assert!(r.shard.state().runs.is_empty());
    };
    put(&mut r, 0, 400, &mut || rand_val(300));
    slices(&mut r, 0, 400);
    let (hits, tries) = r.shard.state().run_vcomp;
    assert_eq!(hits, 0);
    assert!(
        tries <= 16,
        "{tries} compressions tried for 400 incompressible values in 40 slices"
    );
    check(&mut r);
    // a compressible kind of the same class: compressed from the next attempt on
    let mut i = 0u64;
    put(&mut r, 1000, 400, &mut || {
        i += 1;
        let mut v = vec![0u8, b'r'];
        v.extend_from_slice(format!("{:0>299}", i % 7).as_bytes());
        v
    });
    slices(&mut r, 1000, 400);
    let (hits2, _) = r.shard.state().run_vcomp;
    assert!(
        hits2 >= 400 - 64,
        "only {hits2} of 400 compressible values compressed"
    );
}

/// Per-object idle merge: an object without a new run for one to two checkpoint intervals merges into the tree while
/// another object keeps logging runs (a shard-wide idle condition would never fire); the writing object keeps its runs.
#[test]
fn an_idle_object_merges_while_another_writes() {
    let cfg = ShardCfg {
        cache_pages: 256,
        dirty_soft_pages: 48,
        dirty_hard_pages: 400,
        ckpt_interval_ns: 300_000,
        ..Default::default()
    };
    let env = make_env(64, 512, 1, cfg);
    let mut r = Rig::new(&env, 9);
    let (a, b) = (21, 22);
    r.apply(vec![run(a, (0..200).map(|i| (i, 0)))]);
    r.sync();
    let mut rounds = 0u64;
    while r.shard.state().runs.has_obj(a) {
        // b logs a run every third of an interval: never idle
        r.apply(vec![run(b, [(rounds % 50, rounds)])]);
        r.sync();
        r.clk.t += 100_000;
        r.pump();
        rounds += 1;
        assert!(
            rounds <= 20,
            "the idle object did not merge within its idle window"
        );
    }
    assert!(
        r.shard.state().runs.has_obj(b),
        "the writing object keeps its runs"
    );
    assert!(
        r.shard.stats.run_merge_starts[3] > 0,
        "merged by the idle trigger"
    );
    check(&mut r);
    idle_drain(&mut r);
    check(&mut r);
}

/// Runs refused at the checkpoint ring threshold (memory, below the soft size) press a merge at once: a writer waiting
/// for run room never depends on the idle trigger.
#[test]
fn a_run_refused_at_the_ring_threshold_presses_a_merge() {
    let env = env();
    let mut r = Rig::new(&env, 13);
    let id = 31;
    let mut round = 0u64;
    // large runs of tiny values: a compaction under way holds its output beside its inputs (memory above the logged
    // bytes, the floor below the threshold)
    while r.shard.run_room() {
        let mut b = RunBuilder::default();
        for j in 0..3000 {
            b.push(&ok(id, round * 3000 + j), &[], &[0, 7], &[]);
            r.model.insert(ok(id, round * 3000 + j), vec![0, 7]);
        }
        r.txn(vec![Op::RunPut(b.finish(id).unwrap())]);
        r.sync();
        round += 1;
        assert!(round < 1000, "the ring threshold never refused a run");
    }
    assert!(
        r.shard.state().runs.mem() < 16 << 20,
        "refused below the soft size"
    );
    let mut polls = 0;
    while !r.shard.run_room() {
        r.pump();
        polls += 1;
        assert!(
            polls < 10_000,
            "no merge made run room without the idle trigger"
        );
    }
    assert!(
        r.shard.stats.run_merge_starts[2] > 0,
        "merge pressed by the ring"
    );
    assert_eq!(
        r.shard.stats.run_merge_starts[3], 0,
        "not by the idle trigger"
    );
    check(&mut r);
}

/// Elastic meta, small base area, sliced freezes: runs whose page charge outgrows the meta space while a freeze holds
/// back the growth are admitted against a data-region claim (no refusal); content, crash replay and fsck hold, and the
/// claim is gone once a growth covered the charge.
#[test]
fn a_run_page_charge_during_a_freeze_grows_the_meta_space() {
    let cfg = ShardCfg {
        cache_pages: 4096,
        dirty_soft_pages: 64,
        dirty_hard_pages: 2000,
        ckpt_slice: 4,
        ckpt_interval_ns: 200_000,
        meta_slack_cells: 0,
        run_max: 64,
        ..Default::default()
    };
    let env = make_env_full(64, 4096, 1, cfg, 3, 4096, true, 64);
    let mut r = Rig::new(&env, 17);
    let id = 41;
    // tree puts spread over another object dirty many leaves: the sliced freezes span many polls; the runs' page charge
    // grows the meta space while they run (the cells join it at each freeze's end)
    let mut grown_in_freeze = 0;
    for round in 0..400u64 {
        let before = (
            r.shard.freeze_active(),
            r.shard.stats.ckpt_begins,
            r.shard.stats.cells_added,
        );
        let puts = (0..40u64)
            .map(|j| {
                let i = (j * 7919 + round * 104_729) % 20_000;
                Op::Put(ok(id + 1, i), val(i, round))
            })
            .collect();
        r.apply(puts);
        r.apply(vec![run(id, (0..200).map(|j| (round * 200 + j, round)))]);
        if before.0
            && r.shard.freeze_active()
            && r.shard.stats.ckpt_begins == before.1
            && r.shard.stats.cells_added > before.2
        {
            grown_in_freeze += 1;
        }
        r.clk.t += 50_000;
        r.pump();
    }
    r.sync();
    assert!(
        grown_in_freeze > 0,
        "no meta growth during a freeze (cells added {}, run refusals {})",
        r.shard.stats.cells_added,
        r.shard.stats.busy_meta_run
    );
    check(&mut r);
    idle_drain(&mut r);
    r.checkpoint();
    check(&mut r);
    let img = r.disk.image();
    let rep = r.fsck(&img);
    assert!(rep.meta_pages_used > 0, "fsck after the drain");
    crash_remount(&mut r);
    check(&mut r);
}

#[test]
fn a_shared_pool_lends_idle_shares_to_a_hot_shard() {
    let pool = std::sync::Arc::new(store::runs::RunPool::default());
    // an idle member: its soft share is room for the hot shard
    let idle = store::runs::PoolShare::join(pool.clone(), 1 << 20);
    let cfg = ShardCfg {
        cache_pages: 256,
        dirty_soft_pages: 48,
        dirty_hard_pages: 400,
        run_soft_bytes: 16 << 10,
        run_max: 64,
        run_pool: Some(pool.clone()),
        ..Default::default()
    };
    let env = make_env(64, 512, 1, cfg);
    let mut r = Rig::new(&env, 7);
    let id = 12;
    for round in 0..20u64 {
        r.apply(vec![run(id, (0..100).map(|j| (round * 100 + j, round)))]);
        r.sync();
    }
    let b = r.shard.state().runs.mem();
    assert!(
        b > 4 * (16 << 10),
        "runs {b} stay far below the hard size of their own share"
    );
    assert_eq!(pool.bytes(), b, "the shard publishes its runs");
    assert!(r.shard.run_room(), "pool below its hard size");
    assert_eq!(
        r.shard.stats.run_merges, 0,
        "pool below its soft size and few runs: no merge"
    );
    check(&mut r);
    // the idle member leaves: the pool is over its soft size, the shard over its own: merges drain to it
    drop(idle);
    assert!(!r.shard.run_room());
    r.apply(vec![run(id, [(1_000_000, 0)])]);
    r.sync();
    assert!(r.shard.stats.run_merges > 0, "merges ran");
    check(&mut r);
}

/// A background merge (pool over its soft size, below the hard size) keeps pace with the writes it holds back: while
/// client txns are in flight it moves nothing ahead of the entries admitted, with none in flight it takes whole slices
/// (the core's idle time; a merge whose writes stopped completes without waiting for the idle marks), and it is complete
/// before new runs would wait for room (adr 0476 am. 8).
#[test]
fn a_background_merge_keeps_pace_with_the_writes() {
    let pool = std::sync::Arc::new(store::runs::RunPool::default());
    let cfg = ShardCfg {
        cache_pages: 256,
        dirty_soft_pages: 48,
        dirty_hard_pages: 400,
        run_soft_bytes: 64 << 10,
        run_max: 64,
        run_pool: Some(pool.clone()),
        ..Default::default()
    };
    let idle_ns = cfg.ckpt_interval_ns;
    let env = make_env(64, 512, 1, cfg);
    let mut r = Rig::new(&env, 7);
    // a loaded host: the core is descheduled for 50 ms between any two reads of the wall clock; the merge slice cost
    // is core time, so the pace holds (the learned cost was wall time and shrank the slices to one entry)
    r.shard.lab_stall_dev_clock(50_000_000);
    // a merge entry costs 2 us of core time, whatever the host: the learned cost sizes the slices (a loaded runner
    // runs the debug build 10x slower per entry and the slices fall below the writes' pace by design: the pool
    // pressure then takes the merge at full speed, which this test must not reach)
    r.shard.lab_fix_merge_cost(2_000_000);
    let id = 12;
    let mut round = 0u64;
    let write = |r: &mut Rig, round: &mut u64| {
        r.apply(vec![run(id, (0..20).map(|j| (j * 5000 + *round, *round)))]);
        r.clk.t += 50_000;
        r.sync();
        *round += 1;
    };
    while r.shard.stats.run_merges == 0 {
        write(&mut r, &mut round);
        assert!(round < 1000, "no merge started");
    }
    // a client txn in flight (the device does not complete it: the clock stands): the merge stays within its pace
    let (m, paced) = (
        r.shard.stats.run_merged_ents,
        r.shard.stats.run_merge_skips[3],
    );
    r.put(&ok(id + 1, 1), &val(1, 1));
    let mut ev = Vec::new();
    for _ in 0..50 {
        r.shard.poll(r.clk.t, &mut ev);
    }
    let acks = ev
        .iter()
        .filter(|e| matches!(e, store::shard::Event::Acked(_)))
        .count();
    assert_eq!(acks, 0, "the device completed with the clock standing");
    assert!(
        r.shard.stats.run_merged_ents - m <= 4096,
        "a paced merge ran ahead of the writes with a client txn in flight"
    );
    assert!(
        r.shard.stats.run_merge_skips[3] > paced,
        "the merge never waited for writes"
    );
    // nothing in flight, no new run: the merge completes in the idle time, long before the idle marks
    let (t0, starts) = (r.clk.t, r.shard.stats.run_merge_starts);
    let set = |r: &Rig| r.shard.run_gauges()[4];
    let mut n = 0;
    while set(&r) == 1 {
        assert!(
            !r.shard.quiet(),
            "a merge that can go let the shard go quiet"
        );
        r.clk.t += 50_000;
        r.pump();
        n += 1;
        assert!(n < 10_000, "the merge did not complete");
    }
    assert!(
        r.clk.t - t0 < idle_ns,
        "the merge waited for the idle marks"
    );
    assert_eq!(
        r.shard.stats.run_merge_starts, starts,
        "no other merge started"
    );
    // writes: no write waits for room, merges complete while the writes go on, whole slices
    let fins = |r: &Rig| r.shard.state().runs.entries();
    let mut shrank = false;
    for _ in 0..400 {
        assert!(
            r.shard.run_room(),
            "a write would wait for room at {} pool bytes",
            pool.bytes()
        );
        let before = fins(&r);
        write(&mut r, &mut round);
        shrank |= fins(&r) < before;
    }
    assert!(shrank, "no merge completed while the writes went on");
    let (n, e) = (r.shard.stats.run_merges, r.shard.stats.run_merged_ents);
    assert!(e >= 32 * n, "slices of {e}/{n} entries: not whole slices");
    check(&mut r);
    idle_drain(&mut r);
    check(&mut r);
}

/// Crash matrix workload: object `CA` only sees runs and blind puts / removals, object `CB` mixes runs, tree puts /
/// removes / range removes of run keys and explicit merge slices.
const CA: u64 = 21;
const CB: u64 = 22;

/// `rm_pct`: percent of the runs that remove their keys (adr 0647-omap-blind-removals D1); 0 draws no extra numbers (the
/// workload of a seed stays the same).
fn crash_workload(seed: u64, n: usize, rm_pct: u8) -> Vec<Vec<Op>> {
    let mut rng = store::rng::Rng::new(seed);
    let mut out = Vec::with_capacity(n + 1);
    let mut t = 0u64;
    while out.len() < n {
        t += 1;
        let p = rng.below(100);
        if p < 3 {
            let a = rng.below(3980);
            out.push(vec![Op::DelRange(ok(CB, a), ok(CB, a + 20))]);
            continue;
        }
        if p < 8 {
            let a = rng.below(3950);
            out.push(vec![merge(CB, false, ok(CB, a), ok(CB, a + 50))]);
            continue;
        }
        let (mut runs, mut tree) = (Vec::new(), Vec::new());
        for id in [CA, CB] {
            if rng.pct(70) {
                let ents: Vec<(u64, u64)> = (0..rng.range(1, 24))
                    .map(|_| (rng.below(4000), t))
                    .collect();
                if rm_pct > 0 && rng.pct(rm_pct) {
                    runs.push(rm_run(id, ents.into_iter().map(|(i, _)| i)));
                } else {
                    runs.push(run(id, ents));
                }
            }
        }
        for _ in 0..rng.range(0, 4) {
            let i = rng.below(4000);
            if rng.pct(60) {
                tree.push(Op::Put(ok(CB, i), val(i, t)));
            } else {
                tree.push(Op::Del(ok(CB, i)));
            }
        }
        if rng.pct(30) {
            // a blind removal or put of a CA key (adr 0476 am. 5)
            let i = rng.below(4000);
            tree.push(if rng.pct(50) {
                Op::Del(ok(CA, i))
            } else {
                Op::Put(ok(CA, i), val(i, t))
            });
        }
        tree.sort_by(|a, b| match (a, b) {
            (Op::Put(x, _) | Op::Del(x), Op::Put(y, _) | Op::Del(y)) => x.cmp(y),
            _ => std::cmp::Ordering::Equal,
        });
        tree.dedup_by(|a, b| match (a, b) {
            (Op::Put(x, _) | Op::Del(x), Op::Put(y, _) | Op::Del(y)) => x == y,
            _ => false,
        });
        // tree ops first, runs last: one record (the stage's order)
        tree.extend(runs);
        if !tree.is_empty() {
            out.push(tree);
        }
    }
    out.truncate(n);
    out
}

fn model_apply(m: &mut BTreeMap<Vec<u8>, Vec<u8>>, ops: &[Op]) {
    for op in ops {
        match op {
            Op::Put(k, v) => {
                m.insert(k.clone(), v.clone());
            }
            Op::Del(k) => {
                m.remove(k);
            }
            Op::DelRange(a, b) => m.retain(|k, _| !(k >= a && k < b)),
            Op::RunPut(r) => {
                for i in 0..r.len() {
                    let (k, v) = r.entry(i);
                    // an empty value is a removal (FEAT_OMAP_TOMBS)
                    if v.is_empty() {
                        m.remove(k);
                    } else {
                        m.insert(k.to_vec(), v.to_vec());
                    }
                }
            }
            Op::RunMerge { .. } => {}
            Op::Omap(_) => unreachable!("KV workloads log no omap LSM ops"),
        }
    }
}

/// Non-blocking pump (`acked` = last acked token: the txn's 1-based index); false once the device froze.
fn crash_pump(r: &mut Rig, acked: &mut u64) -> bool {
    let mut ev = Vec::new();
    r.shard.poll(r.clk.t, &mut ev);
    for e in ev {
        match e {
            store::shard::Event::Acked(l) => *acked = l,
            store::shard::Event::Failed(f) => {
                assert!(r.disk.crashed(), "shard failed without crash: {f:?}");
                return false;
            }
            _ => {}
        }
    }
    let h = r.shard.dev().next_deadline();
    r.clk.idle(h);
    !r.disk.crashed()
}

/// Submit `txns` (lsns appended), then drain; false when the device froze on the way.
fn crash_drive(r: &mut Rig, txns: &[Vec<Op>], lsns: &mut Vec<u64>, acked: &mut u64) -> bool {
    for ops in txns {
        let mut t: Txn<Vec<u8>> = Txn::new(lsns.len() as u64 + 1);
        t.ops = ops.clone();
        loop {
            match r.shard.submit(t) {
                Ok(l) => {
                    lsns.push(l);
                    break;
                }
                Err((StoreError::Busy | StoreError::Miss | StoreError::WalFull, back)) => {
                    t = back;
                    if !crash_pump(r, acked) {
                        return false;
                    }
                }
                Err((e, _)) => {
                    assert!(r.disk.crashed(), "submit failed: {e:?}");
                    return false;
                }
            }
        }
        if !crash_pump(r, acked) {
            return false;
        }
    }
    let mut guard = 0u64;
    while *acked < lsns.len() as u64 {
        if !crash_pump(r, acked) {
            return false;
        }
        guard += 1;
        assert!(guard < 10_000_000, "ack livelock");
    }
    true
}

fn crash_env() -> Env {
    let cfg = ShardCfg {
        cache_pages: 32,
        dirty_soft_pages: 16,
        dirty_hard_pages: 40,
        ckpt_interval_ns: 300_000,
        run_soft_bytes: 64 << 10,
        run_max: 6,
        ..Default::default()
    };
    make_env(64, 96, 1, cfg)
}

/// One cut: run `txns` with the device frozen at event `k` (None: no cut), cut with `policy`, fsck, remount; the
/// recovered state must be the model of a txn prefix covering every ack. Then the tail of the workload on the recovered
/// runs, a full merge and a clean crash cycle. Returns the run records replayed.
fn crash_case(env: &Env, txns: &[Vec<Op>], k: Option<u64>, policy: CrashPolicy) -> u64 {
    let mut r = Rig::new(env, 31);
    if let Some(k) = k {
        r.disk.arm_crash(r.disk.events() + k);
    }
    let (mut lsns, mut acked) = (Vec::new(), 0u64);
    crash_drive(&mut r, txns, &mut lsns, &mut acked);
    r.disk.crash_now();
    let img = r.disk.crash_image(policy);
    r.fsck(&img);
    let mut cfg = env.sim.clone();
    cfg.seed = 77;
    r.disk = SimDisk::from_image(&img, cfg);
    let (shard, st) =
        mount(env, &r.disk, &mut r.clk).unwrap_or_else(|e| panic!("mount k={k:?}: {e:?}"));
    r.shard = shard;
    // the replay's end: the mount may log merges / re-logs of its own afterwards
    let last = st.last_lsn;
    let n = lsns.iter().take_while(|&&l| l <= last).count();
    assert!(
        n as u64 >= acked,
        "k={k:?}: acked txn {acked} lost (recovered {n})"
    );
    r.model.clear();
    for ops in &txns[..n] {
        model_apply(&mut r.model, ops);
    }
    check(&mut r);
    r.submitted = 0;
    r.acked = 0;
    for ops in &txns[n..] {
        r.apply(ops.clone());
    }
    r.sync();
    check(&mut r);
    idle_drain(&mut r);
    check(&mut r);
    crash_remount(&mut r);
    check(&mut r);
    st.run_txns
}

/// Names the cut of a failing case (printed while unwinding).
struct CutNote(u64, CrashPolicy);

impl Drop for CutNote {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "runs crash matrix: cut at event {} (full {} % torn {} %) failed",
                self.0, self.1.full_pct, self.1.tear_pct
            );
        }
    }
}

/// Repro of a stall the stride-1 matrix found (adr 0021 am. 66): after this cut the remounted shard's ring led with a PAD
/// written after the checkpoint that released the unit before it, and the floor unit behind it kept it there; the ring
/// stayed one block short of a merge's reserve, client txns and merges were refused `WalFull` forever (nothing logged,
/// no checkpoint). Every checkpoint (idle ones too) now releases PADs at the released end. The cut index is specific
/// to this workload and code; the stride-1 matrix (`lab/omap-runs-crash.sh 1`) is the general check.
#[test]
fn leading_pad_is_released_after_a_power_cut() {
    let env = crash_env();
    let txns = crash_workload(5, 600, 0);
    crash_case(&env, &txns, Some(1727), CrashPolicy::PERSIST_ALL);
}

/// Power cuts between logging runs and merging them: every `RUNS_CRASH_STRIDE`th device event (default 397; stride 1: lab/omap-runs-crash.sh) of a run
/// workload with soft-size merges, explicit merge slices, compactions, runs of removals (a third) and tree ops on run
/// keys; fates drop all, persist all, mixed. `lab/omap-runs-crash.sh` runs it with stride 1.
#[test]
fn crash_matrix_runs() {
    let stride: u64 = std::env::var("RUNS_CRASH_STRIDE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(397);
    let env = crash_env();
    let txns = crash_workload(5, 600, 35);
    let rms = txns
        .iter()
        .flatten()
        .filter(|op| matches!(op, Op::RunPut(r) if r.entry(0).1.is_empty()))
        .count();
    assert!(rms > 100, "the workload logs runs of removals: {rms}");
    // dry run: event count; the workload must merge
    let mut r = Rig::new(&env, 31);
    let e0 = r.disk.events();
    let (mut lsns, mut acked) = (Vec::new(), 0u64);
    assert!(crash_drive(&mut r, &txns, &mut lsns, &mut acked));
    let events = r.disk.events() - e0;
    let (m, rl) = (r.shard.stats.run_merges, r.shard.stats.run_relogs);
    let cp = r.shard.stats.run_compactions;
    let pm = r.shard.state().runs.part_moves();
    eprintln!(
        "runs crash matrix: {} txns, {events} events, merges {m}, re-logs {rl}, compactions {cp}, compacted parts re-logged {pm}, stride {stride}",
        txns.len()
    );
    assert!(m > 0, "the workload merges");
    assert!(
        cp > 0 && pm > 0,
        "the workload compacts runs and re-logs their parts"
    );
    assert!(rl > 0, "the workload re-logs (ring liveness)");
    let pols = [
        CrashPolicy::DROP_ALL,
        CrashPolicy::PERSIST_ALL,
        CrashPolicy::MIXED,
    ];
    let (mut cuts, mut replayed) = (0u64, 0u64);
    // RUNS_CRASH_AT=k: that one cut only (repro of a failed cut)
    let mut k = std::env::var("RUNS_CRASH_AT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let end = if k > 0 { k + 1 } else { events };
    while k < end {
        let pol = pols[(k / stride % 3) as usize];
        let _cut = CutNote(k, pol);
        replayed += crash_case(&env, &txns, Some(k), pol);
        cuts += 1;
        k += stride;
    }
    crash_case(&env, &txns, None, CrashPolicy::MIXED);
    eprintln!("runs crash matrix: {cuts} cuts, run records replayed {replayed}");
    assert!(replayed > 0, "cuts hit a non-empty run window");
}

/// Merge apply leaf by leaf (adr 0476 am. 4): runs of every shape merged into the tree (appends at the right end into
/// an empty and a deep tree, dense and sparse inserts between existing keys, overwrites with longer and shorter values,
/// one-entry leaves, values up to a third of a page: leaves cut into many pages, interior splits, root growth); the
/// content and scans match the model after every merge and after a remount.
#[test]
fn merges_apply_leaf_by_leaf_for_every_shape() {
    let env = env();
    let mut r = Rig::new(&env, 13);
    let id = 5;
    let mut rng = store::rng::Rng::new(77);
    let k = |i: u64| omap_key(id, format!("k{i:08}").as_bytes());
    let v = |rng: &mut store::rng::Rng, big: bool| {
        let n = if big {
            rng.range(200, 2000)
        } else {
            rng.range(1, 120)
        } as usize;
        let mut x = vec![0u8];
        x.extend((0..n).map(|_| b'a' + rng.below(26) as u8));
        x
    };
    let put_run = |r: &mut Rig, rng: &mut store::rng::Rng, keys: Vec<u64>, big: bool| {
        // one record holds the run: big values take every third key
        let m: BTreeMap<Vec<u8>, Vec<u8>> = keys
            .into_iter()
            .enumerate()
            .filter(|(n, _)| !big || n % 3 == 0)
            .map(|(_, i)| (k(i), v(rng, big)))
            .collect();
        let mut b = RunBuilder::default();
        for (kk, vv) in &m {
            b.push(kk, &[], vv, &[]);
        }
        r.apply(vec![Op::RunPut(b.finish(id).expect("non-empty run"))]);
    };
    for round in 0..40u64 {
        let big = round % 3 == 2;
        match round % 4 {
            // append at the right end
            0 => {
                let n = rng.range(50, 3000);
                let keys = (0..n)
                    .map(|i| 10_000_000 + round * 100_000 + i * 7)
                    .collect();
                put_run(&mut r, &mut rng, keys, big)
            }
            // dense between existing keys (even keys first time round, odd later)
            1 => put_run(
                &mut r,
                &mut rng,
                (0..2000).map(|i| round * 10 + i * 3).collect(),
                big,
            ),
            // sparse: about one key per leaf
            2 => {
                let keys = (0..40).map(|_| rng.below(12_000_000)).collect();
                put_run(&mut r, &mut rng, keys, big)
            }
            // overwrites of existing keys with new sizes
            _ => {
                let have: Vec<u64> = r
                    .model
                    .keys()
                    .filter(|kk| omap_id(kk) == Some(id))
                    .map(|kk| std::str::from_utf8(&kk[11..]).unwrap().parse().unwrap())
                    .collect();
                let pick = (0..300)
                    .map(|_| have[rng.below(have.len() as u64) as usize])
                    .collect();
                put_run(&mut r, &mut rng, pick, big);
            }
        }
        // small runs in one merge txn, larger ones in the shard's own slices
        if round % 4 == 2 {
            merge_obj(&mut r, id);
        } else {
            idle_drain(&mut r);
        }
        check(&mut r);
    }
    let (h, n) = (r.shard.state().tree.height(), r.model.len());
    eprintln!("tree height {h}, {n} keys");
    assert!(h >= 3, "interior splits happened");
    r.remount_clean();
    check(&mut r);
}

/// Read cost of the run overlay (adr 0476, OQ 103; release: `cargo test -p store --release --test runs
/// overlay_read_cost -- --ignored --nocapture`): a tree of `OV_TREE` keys (default 200k) of one object, then `OV_LIVE`
/// (default 50k) run entries in client-sized runs (`OV_BATCH` random keys, default 1024, half overwrites; `OV_RM=1`:
/// runs of removals of tree keys instead, adr 0647-omap-blind-removals D1), `OV_PUMPS` polls after (default 1000:
/// compactions settle; 0: the run count of an ingest); full scans in pages of 1000 and
/// random point gets, ns per entry / get, with the runs and after they merged. Prints one line per state.
#[test]
#[ignore]
fn overlay_read_cost() {
    use std::time::Instant;
    use store::tree::{ScanCursor, ScanStatus};
    let n_tree: u64 = std::env::var("OV_TREE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let n_live: u64 = std::env::var("OV_LIVE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);
    let batch: u64 = std::env::var("OV_BATCH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024);
    let rm = std::env::var("OV_RM").is_ok_and(|s| s == "1");
    let cfg = ShardCfg {
        cache_pages: 65536,
        dirty_soft_pages: 8192,
        dirty_hard_pages: 32768,
        run_soft_bytes: 256 << 20,
        ckpt_interval_ns: u64::MAX / 4,
        ..Default::default()
    };
    let env = make_env(1024, 32768, 1, cfg);
    let mut r = Rig::new(&env, 7);
    let id = 5u64;
    let mut rng = store::rng::Rng::new(11);
    let add =
        |r: &mut Rig, rng: &mut store::rng::Rng, n: u64, space: u64, g: u64, b: u64, rm: bool| {
            let mut left = n;
            while left > 0 {
                let k = left.min(b);
                r.apply(vec![if rm {
                    rm_run(id, (0..k).map(|_| rng.below(space)))
                } else {
                    run(id, (0..k).map(|_| (rng.below(space), g)))
                }]);
                left -= k;
            }
            r.sync();
        };
    add(&mut r, &mut rng, n_tree, n_tree, 0, 1024, false);
    merge_all(&mut r);
    r.checkpoint();
    let space = if rm { n_tree } else { 2 * n_tree };
    add(&mut r, &mut rng, n_live, space, 1, batch, rm);
    let pumps: usize = std::env::var("OV_PUMPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    for _ in 0..pumps {
        r.pump();
    }
    let keys: Vec<Vec<u8>> = (0..100_000)
        .map(|_| ok(id, rng.below(2 * n_tree)))
        .collect();
    let (a, b) = omap_range(id);
    let measure = |r: &mut Rig, what: &str| {
        let st = r.shard.state();
        let (nruns, ents) = (st.runs.n_runs(), st.runs.entries());
        let mut best = (f64::MAX, f64::MAX);
        let mut n_ent = 0u64;
        for _ in 0..3 {
            let t0 = Instant::now();
            let mut cur = ScanCursor::new(&a, &b);
            let (mut n, mut sum) = (0u64, 0usize);
            loop {
                match r.shard.scan(&mut cur, 1000, usize::MAX, &mut |k, v| {
                    n += 1;
                    sum += k.len() + v.len();
                }) {
                    Ok(ScanStatus::Done) => break,
                    Ok(ScanStatus::More) => {}
                    Err(e) => panic!("scan: {e:?}"),
                }
            }
            std::hint::black_box(sum);
            best.0 = best.0.min(t0.elapsed().as_nanos() as f64 / n as f64);
            n_ent = n;
            let t0 = Instant::now();
            let mut out = Vec::new();
            for k in &keys {
                out.clear();
                std::hint::black_box(r.shard.get(k, &mut out).unwrap());
            }
            best.1 = best
                .1
                .min(t0.elapsed().as_nanos() as f64 / keys.len() as f64);
        }
        let t0 = Instant::now();
        let nr = r.shard.state().runs.scan(&a, &b).count();
        let rs = t0.elapsed().as_nanos() as f64 / nr.max(1) as f64;
        eprintln!(
            "overlay {what}: runs {nruns} run entries {ents} listed {n_ent}: scan {:.1} ns/entry, get {:.1} ns, run merge alone {rs:.1} ns/run entry",
            best.0, best.1
        );
    };
    measure(&mut r, "with runs");
    merge_all(&mut r);
    r.checkpoint();
    measure(&mut r, "merged");
}
