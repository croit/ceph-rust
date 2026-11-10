// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Logical metadata cells keep their page count while their physical pages occupy fragmented data holes.
//! Exercises the public shard API, durable allocator ownership, sliced freezes, and crash images.
mod common;
use common::*;
use store::StoreError;
use store::dev::{CrashPolicy, SimClock, SimDisk};
use store::shard::ShardCfg;

const POLICIES: [CrashPolicy; 3] = [
    CrashPolicy::DROP_ALL,
    CrashPolicy::PERSIST_ALL,
    CrashPolicy::MIXED,
];

fn environment() -> Env {
    make_env_full(
        16,
        1024,
        1,
        ShardCfg {
            dirty_soft_pages: 100_000,
            dirty_hard_pages: 200_000,
            ckpt_interval_ns: u64::MAX / 4,
            ckpt_slice: 1,
            ckpt_fz_polls: 0,
            meta_slack_cells: 0,
            keep_windows: 0,
            ..Default::default()
        },
        3,
        8192,
        true,
        128,
    )
}

/// Reserve all remaining blocks, then expose holes separated by unavailable blocks. Width 2 leaves exactly
/// one 8 KiB page per hole; width 0 leaves only 32 complete pages and otherwise isolated blocks.
/// Reservations are not durable allocations.
fn fragment_free_space(r: &mut Rig, width: u64) -> Vec<u64> {
    r.drain_trim();
    let mut reserved = Vec::new();
    loop {
        match r.shard.alloc_priv(1) {
            Ok(b) => reserved.push(b),
            Err(StoreError::NoSpace) => break,
            Err(e) => panic!("reserving fragmentation fixture: {e:?}"),
        }
    }
    let first_window = reserved.iter().min().copied().unwrap() / 4;
    let mut held = Vec::new();
    for b in reserved {
        let expose = if width == 0 {
            b % 4 == 0 || (b % 4 == 1 && b / 4 < first_window + 32)
        } else {
            b % 4 < width
        };
        if expose {
            r.shard.unreserve(b, 1);
        } else {
            held.push(b);
        }
    }
    assert!(r.shard.statfs().data_free > r.shard.cell_blocks());
    assert!(matches!(
        r.shard.alloc_priv(r.shard.cell_blocks() as u32),
        Err(StoreError::NoSpace)
    ));
    held
}

fn release_fixture(r: &mut Rig, held: Vec<u64>) {
    for b in held {
        r.shard.unreserve(b, 1);
    }
}

fn fragmented_rig() -> Rig {
    let mut r = Rig::new(&environment(), 71);
    let held = fragment_free_space(&mut r, 2);
    let before = r.shard.statfs();
    assert!(
        r.shard.grow_meta_cell(),
        "page-sized holes must permit growth"
    );
    let after = r.shard.statfs();
    assert_eq!(after.meta_pages - before.meta_pages, 128);
    let extents = r.shard.meta_cells();
    assert_eq!(extents.len(), 128, "one logical cell in 128 separate holes");
    assert!(
        extents
            .iter()
            .all(|&(start, blocks)| start % 2 == 0 && blocks == 2)
    );
    assert_eq!(after.data_reserved - before.data_reserved, 256);
    // Populate enough metadata to use all three fragmented cells. The 4 MiB WAL keeps this initial fill
    // below its checkpoint watermark, so none is returned while it is still empty.
    for _ in 0..2 {
        assert!(r.shard.grow_meta_cell());
    }
    assert_eq!(r.shard.statfs().meta_cells, 3);
    assert_eq!(r.shard.meta_cells().len(), 3 * 128);
    release_fixture(&mut r, held);
    for i in 0..2600 {
        r.put(format!("k/{i:05}").as_bytes(), &[0x5a; 1000]);
    }
    r.sync();
    assert!(r.shard.meta_cells().iter().any(|&(_, blocks)| blocks == 2));
    r
}

#[test]
fn fragmented_growth_survives_checkpoint_and_remount_and_reclaims_all_extents() {
    let mut r = fragmented_rig();
    r.checkpoint();
    let allocated = r.shard.statfs();
    assert_eq!(
        allocated.meta_cells, 3,
        "fixture must persist surplus cells: {allocated:?}"
    );
    let physical = r.shard.meta_cells();
    assert!(physical.len() > allocated.meta_cells as usize);
    assert_eq!(
        physical.iter().map(|e| e.1).sum::<u64>(),
        allocated.meta_cell_blocks
    );
    r.fsck(&r.disk.image());
    r.remount_clean();
    r.verify();
    assert_eq!(r.shard.meta_cells(), physical);
    r.delrange(b"k/", b"k0");
    for i in 0..4 {
        r.put(b"z", &[i]);
        r.checkpoint();
    }
    assert!(r.shard.stats.cells_released > 0);
    assert!(r.shard.statfs().meta_cells < allocated.meta_cells);
    let reclaimed = r.shard.statfs();
    let returned_blocks = allocated.meta_cell_blocks - reclaimed.meta_cell_blocks;
    assert!(
        returned_blocks >= 256,
        "at least one entire fragmented cell must return"
    );
    assert_eq!(reclaimed.data_free - allocated.data_free, returned_blocks);
    assert_eq!(
        physical.len() - r.shard.meta_cells().len(),
        (returned_blocks / 2) as usize
    );
    r.fsck(&r.disk.image());
    r.remount_clean();
    r.verify();
}

#[test]
fn incomplete_fragmented_reservation_rolls_back_every_extent() {
    let mut r = Rig::new(&environment(), 73);
    let held = fragment_free_space(&mut r, 0);
    let before = r.shard.statfs();
    assert!(
        !r.shard.grow_meta_cell(),
        "32 complete pages cannot fill a 128-page logical cell"
    );
    let after = r.shard.statfs();
    assert_eq!(after.data_reserved, before.data_reserved);
    assert_eq!(after.data_free, before.data_free);
    assert_eq!(after.meta_pages, before.meta_pages);
    assert!(r.shard.meta_cells().is_empty());
    release_fixture(&mut r, held);
    assert!(
        r.shard.grow_meta_cell(),
        "failed fallback must not leak reservations"
    );
}

/// Every distinct device-poll boundary of this checkpoint is recovered under each persistence policy. The
/// transactions were acknowledged before these snapshots, so their complete KV state must survive every cut.
fn checkpoint_crash_images(r: &mut Rig) -> usize {
    r.sync();
    let want = r.shard.next_lsn() - 1;
    let mut snapshots = 0;
    let mut previous = None;
    for step in 0..100_000 {
        r.shard.request_checkpoint();
        r.pump();
        let events = r.disk.events();
        if previous != Some(events) {
            previous = Some(events);
            for policy in POLICIES {
                let image = r.disk.crash_image(policy);
                r.fsck(&image);
                let recovered = SimDisk::from_image(&image, r.env.sim.clone());
                let mut clock = SimClock::default();
                let (mut shard, _) = mount(&r.env, &recovered, &mut clock)
                    .unwrap_or_else(|e| panic!("checkpoint cut {step}, {policy:?}: {e:?}"));
                assert_eq!(
                    dump(&mut shard, &mut clock),
                    r.model,
                    "checkpoint cut {step}, {policy:?}"
                );
                snapshots += 1;
            }
        }
        if r.shard.ckpt_lsn() >= want && !r.shard.ckpt_active() {
            return snapshots;
        }
    }
    panic!("fragmented checkpoint failed to finish");
}

#[test]
fn fragmented_growth_and_reclaim_checkpoint_crash_images() {
    let mut r = fragmented_rig();
    let grown = checkpoint_crash_images(&mut r);
    assert_eq!(
        r.shard.statfs().meta_cells,
        3,
        "fixture must persist surplus cells"
    );
    assert!(grown >= 9, "too few growth checkpoint cuts: {grown}");
    r.remount_clean();
    r.verify();
    r.delrange(b"k/", b"k0");
    let before = r.shard.statfs().meta_cells;
    let mut reclaimed = 0;
    for i in 0..3 {
        r.put(b"z", &[i]);
        reclaimed += checkpoint_crash_images(&mut r);
    }
    assert!(reclaimed >= 9);
    assert!(r.shard.statfs().meta_cells < before);
    r.remount_clean();
    r.verify();
}

#[test]
fn fragmented_growth_during_sliced_freeze_is_published_only_after_freeze() {
    let mut r = Rig::new(&environment(), 79);
    for i in 0..80 {
        r.put(format!("k/{i:05}").as_bytes(), &[0x33; 600]);
    }
    r.sync();
    r.shard.request_checkpoint();
    for _ in 0..100_000 {
        r.pump();
        if r.shard.freeze_active() {
            break;
        }
    }
    assert!(
        r.shard.freeze_active(),
        "fixture must reach a sliced freeze"
    );
    let held = fragment_free_space(&mut r, 2);
    let before = r.shard.statfs();
    let added = r.shard.stats.cells_added;
    assert!(r.shard.grow_meta_cell());
    assert_eq!(r.shard.statfs().meta_cells, before.meta_cells);
    assert_eq!(r.shard.stats.cells_added, added + 1);
    release_fixture(&mut r, held);
    for _ in 0..100_000 {
        r.pump();
        if !r.shard.freeze_active() {
            break;
        }
    }
    assert!(!r.shard.freeze_active());
    assert_eq!(r.shard.statfs().meta_cells, before.meta_cells + 1);
    assert!(r.shard.meta_cells().iter().any(|&(_, blocks)| blocks == 2));
    // Make that new mapping durable and let fsck check every physical segment's bitmap ownership.
    r.put(b"z", b"after-freeze");
    r.checkpoint();
    r.fsck(&r.disk.image());
    r.remount_clean();
    r.verify();
}

// ---- growth misses the next checkpoint cures (adr 0021 S13, doc/perf/fill-stall-20261102.md)

/// Submit `t` (retrying on Busy / Miss / WalFull like `Rig::txn`); returns its lsn.
fn submit(r: &mut Rig, mut t: store::shard::Txn<Vec<u8>>) -> u64 {
    for _ in 0..1_000_000 {
        match r.shard.submit(t) {
            Ok(lsn) => {
                r.submitted += 1;
                return lsn;
            }
            Err((StoreError::Busy | StoreError::Miss | StoreError::WalFull, back)) => {
                t = back;
                r.pump();
            }
            Err((e, _)) => panic!("submit {e:?}"),
        }
    }
    panic!("never admitted")
}

/// A durable `n`-block data run (written in device-sized pieces) under key `k`, taken before a fragmentation fixture.
fn put_run(r: &mut Rig, k: &[u8], n: u32) -> u64 {
    let blk = r.shard.alloc(n).unwrap();
    let mut t = store::shard::Txn::new(r.submitted + 1);
    t.ops.push(store::state::Op::Put(
        k.to_vec(),
        blk.to_le_bytes().to_vec(),
    ));
    for off in (0..n).step_by(8) {
        t.data.push((blk + u64::from(off), r.shard.alloc_buf(8)));
    }
    r.model.insert(k.to_vec(), blk.to_le_bytes().to_vec());
    submit(r, t);
    r.checkpoint();
    blk
}

/// Remove key `k` and free `frees` in one txn, acked but not checkpointed: the blocks wait for the next checkpoint.
fn free_run(r: &mut Rig, k: &[u8], frees: Vec<(u64, u32)>) -> u64 {
    let mut t = store::shard::Txn::new(r.submitted + 1);
    t.ops.push(store::state::Op::Del(k.to_vec()));
    t.frees = frees;
    r.model.remove(k);
    let lsn = submit(r, t);
    r.sync();
    lsn
}

/// Pump (never asking for a checkpoint) until one covering `lsn` completed: only a checkpoint the shard requested
/// itself can run in this environment (no interval, dirty or WAL trigger is reachable).
fn await_own_checkpoint(r: &mut Rig, lsn: u64) {
    for _ in 0..100_000 {
        if r.shard.ckpt_lsn() >= lsn && !r.shard.ckpt_active() {
            return;
        }
        r.pump();
    }
    panic!("no checkpoint was requested for the waiting growth");
}

/// 4 MiB overwrites on a nearly full shard: the free space left is isolated blocks, the overwritten run waits for the
/// next checkpoint. A growth miss then waits for that checkpoint instead of turning the shard meta-bound (statfs full),
/// requests it, and the growth after it takes a cell out of the released run.
#[test]
fn growth_miss_waits_for_the_checkpoint_that_releases_the_frees() {
    let mut r = Rig::new(&environment(), 83);
    let run = put_run(&mut r, b"d/a", 512);
    let held = fragment_free_space(&mut r, 0);
    let lsn = free_run(&mut r, b"d/a", vec![(run, 512)]);
    assert!(r.shard.statfs().data_held >= 512);
    assert!(
        !r.shard.grow_meta_cell(),
        "fixture: no cell before the checkpoint"
    );
    let st = r.shard.statfs();
    assert!(
        !st.meta_grow_blocked,
        "a curable miss must not report meta-bound: {st:?}"
    );
    assert!(!r.shard.meta_growth_blocked());
    assert_eq!(r.shard.stats.meta_grow_waits, 1);
    assert_eq!(r.shard.stats.meta_grow_bound, 0);
    assert_eq!(r.shard.last_meta_growth_failure(), None);
    await_own_checkpoint(&mut r, lsn);
    assert!(!r.shard.statfs().meta_grow_blocked);
    // the released blocks are deallocated first: their runs are held until that completion (adr 0642)
    r.settle_trims();
    assert!(r.shard.grow_meta_cell(), "the released run backs a cell");
    assert_eq!(r.shard.stats.meta_grow_bound, 0);
    release_fixture(&mut r, held);
    r.checkpoint();
    r.fsck(&r.disk.image());
    r.remount_clean();
    r.verify();
}

/// The frees the checkpoint releases are isolated blocks (4K overwrites): the wait ends with that checkpoint, the retry
/// misses again and the shard is meta-bound as before (statfs full, cell sweeps may run); no second wait.
#[test]
fn growth_miss_after_its_checkpoint_is_a_real_failure() {
    let mut r = Rig::new(&environment(), 89);
    let run = put_run(&mut r, b"d/b", 512);
    let held = fragment_free_space(&mut r, 0);
    let singles = (0..256u64).map(|i| (run + 2 * i + 1, 1)).collect();
    let lsn = free_run(&mut r, b"d/b", singles);
    assert!(!r.shard.grow_meta_cell());
    assert_eq!(r.shard.stats.meta_grow_waits, 1);
    assert!(!r.shard.statfs().meta_grow_blocked);
    await_own_checkpoint(&mut r, lsn);
    // the released blocks are deallocated first: their runs are held until that completion (adr 0642)
    r.settle_trims();
    assert!(!r.shard.grow_meta_cell());
    let st = r.shard.statfs();
    assert!(
        st.meta_grow_blocked,
        "a miss the checkpoint did not cure is meta-bound: {st:?}"
    );
    assert!(r.shard.meta_growth_blocked());
    assert_eq!(r.shard.stats.meta_grow_waits, 1);
    assert_eq!(r.shard.stats.meta_grow_bound, 1);
    assert_eq!(
        r.shard.last_meta_growth_failure().unwrap().reason,
        store::shard::MetaGrowthFailureReason::NoContiguousRun
    );
    release_fixture(&mut r, held);
}

/// A meta-bound shard (miss with nothing waiting for a checkpoint) is growable again at the end of the checkpoint that
/// released a whole window, judged after that checkpoint's releases: no admission needs to retry first (an OSD at its
/// failsafe ratio drops the client ops that would).
#[test]
fn bound_shard_unblocks_with_the_checkpoint_that_releases_a_window() {
    let mut r = Rig::new(&environment(), 97);
    let run = put_run(&mut r, b"d/c", 512);
    let held = fragment_free_space(&mut r, 0);
    assert!(!r.shard.grow_meta_cell());
    assert!(
        r.shard.statfs().meta_grow_blocked,
        "nothing waits for a checkpoint: bound"
    );
    assert_eq!(r.shard.stats.meta_grow_waits, 0);
    free_run(&mut r, b"d/c", vec![(run, 512)]);
    assert!(
        r.shard.statfs().meta_grow_blocked,
        "a bound shard does not start waiting"
    );
    r.checkpoint();
    let st = r.shard.statfs();
    assert!(
        !st.meta_grow_blocked,
        "released window: growable again: {st:?}"
    );
    // the released blocks are deallocated first: their runs are held until that completion (adr 0642)
    r.settle_trims();
    assert!(r.shard.grow_meta_cell());
    release_fixture(&mut r, held);
}
