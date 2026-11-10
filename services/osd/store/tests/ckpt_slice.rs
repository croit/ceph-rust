// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Sliced checkpoint start and freeze end (adr 0021 am. 80): the bitmap chunk flush before the freeze and the end
//! steps after its pages (address fix-up, unalias, delta relog) run in slices of the core's checkpoint budget with txns
//! between them; the meta space keeps the size a checkpoint cycle asked for instead of giving cells back and regrowing
//! them every checkpoint. Crash matrices over both: crash.rs (`crash_matrix_sliced_ckpt_steps`).
mod common;
use common::*;
use store::BLK;
use store::StoreError;
use store::dev::{SimClock, SimConfig, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::shard::{ShardCfg, Txn};
use store::state::Op;

fn key(i: u64) -> Vec<u8> {
    format!("k/{i:08}/{:x<40}", "").into_bytes()
}

/// Object `id` = one block in a bitmap chunk of its own: reserve a whole chunk's worth, keep its first block (frees the
/// object's `old` block). Returns the block.
fn spread_block(r: &mut Rig, id: u64, old: Option<u64>, seed: u64) -> u64 {
    let blk = r.shard.alloc(4096).expect("a free chunk");
    r.shard.unreserve(blk + 1, 4095);
    let mut t: Txn<Vec<u8>> = Txn::new(r.submitted + 1);
    t.ops.push(Op::Put(obj_key(id), enc_obj(blk, 1, seed)));
    t.data.push((blk, vec![0x5a; BLK]));
    t.frees.extend(old.map(|b| (b, 1)));
    let mut t = Some(t);
    for _ in 0..1_000_000 {
        match r.shard.submit(t.take().unwrap()) {
            Ok(_) => break,
            Err((StoreError::Busy | StoreError::Miss | StoreError::WalFull, back)) => {
                t = Some(back);
                r.pump();
            }
            Err((e, _)) => panic!("submit: {e:?}"),
        }
    }
    assert!(t.is_none(), "txn never admitted");
    r.submitted += 1;
    blk
}

/// `n` objects of [`spread_block`]: one block in each of `n` bitmap chunks.
fn spread_blocks(r: &mut Rig, n: u64, seed: u64) -> Vec<u64> {
    let blks = (0..n)
        .map(|i| spread_block(r, seed + i, None, seed))
        .collect();
    r.sync();
    blks
}

/// The allocator holds exactly the blocks of `live` (elastic meta cells aside).
fn assert_alloc_is(r: &Rig, live: &[u64], what: &str) {
    let ds = r.env.dir.data_start;
    let mut a = r.shard.state().alloc.snapshot();
    for (s, n) in r.shard.meta_cells() {
        for b in s..s + n {
            a.clear(b - ds);
        }
    }
    for &b in live {
        assert!(a.get(b - ds), "{what}: live block {b} free");
    }
    assert_eq!(
        a.count(),
        live.len() as u64,
        "{what}: blocks allocated beyond the live ones"
    );
}

/// The bitmap chunks a cycle dirtied go into the tree in slices of the core's budget (one chunk per poll here), not all
/// in the poll that starts the checkpoint (3.3 ms, at most 29 ms on a 96 % full OSD: doc/perf/p99-64k-20261102.md); the
/// begin writes what is left. Between slices txns free blocks in chunks already written and allocate in new ones: the
/// checkpoint and a mount that replays the txns since hold exactly the live blocks. Kill switch `ckpt_slice` 0: the
/// whole start in one poll.
#[test]
fn checkpoint_start_writes_bitmap_chunks_in_slices() {
    for slice in [1usize, 3, 0] {
        let cfg = ShardCfg {
            ckpt_slice: slice,
            ckpt_fz_polls: usize::MAX,
            ckpt_interval_ns: u64::MAX,
            dirty_soft_pages: 1 << 16,
            dirty_hard_pages: 1 << 17,
            ..Default::default()
        };
        let env = make_env_ext(1024, 512, 1, cfg, 3, 8192);
        let mut r = Rig::new(&env, 1);
        let mut live = spread_blocks(&mut r, 40, 100);
        let chunks = r.shard.state().dirty_chunks();
        assert!(chunks >= 36, "{chunks} dirty chunks");
        r.shard.request_checkpoint();
        let (mut polls, mut moved) = (0, 0usize);
        while !r.shard.ckpt_active() {
            let before = r.shard.state().dirty_chunks();
            r.pump();
            polls += 1;
            assert!(polls < 10_000, "slice {slice}: checkpoint never began");
            if r.shard.ckpt_active() {
                break;
            }
            let done = before.saturating_sub(r.shard.state().dirty_chunks());
            assert!(done <= slice, "slice {slice}: {done} chunks in one poll");
            // object `moved` to a new chunk: frees a block in a chunk the start may have written already
            let i = moved % live.len();
            live[i] = spread_block(&mut r, 100 + i as u64, Some(live[i]), 200 + moved as u64);
            moved += 1;
        }
        match chunks.checked_div(slice) {
            Some(min) => assert!(
                polls >= min,
                "slice {slice}: start of {chunks} chunks took {polls} polls"
            ),
            None => assert_eq!(polls, 1, "kill switch: the start in one poll"),
        }
        let lsn = r.shard.next_lsn() - 1;
        while r.shard.ckpt_lsn() < lsn || r.shard.ckpt_active() {
            r.pump();
        }
        assert_alloc_is(&r, &live, "after the checkpoint");
        // txns after it: a mount from the image replays them over the checkpointed bitmap
        for (i, b) in live.iter_mut().enumerate().take(5) {
            *b = spread_block(&mut r, 100 + i as u64, Some(*b), 900);
        }
        r.sync();
        let img = r.disk.image();
        r.fsck(&img);
        let d = SimDisk::from_image(&img, env.sim.clone());
        let (s2, stats) = mount(&env, &d, &mut r.clk).unwrap();
        assert!(stats.txns > 0, "slice {slice}: nothing replayed");
        r.shard = s2;
        r.disk = d;
        assert_alloc_is(&r, &live, "after a replaying mount");
        r.remount_clean();
        assert_alloc_is(&r, &live, "after a clean remount");
        assert_eq!(r.shard.state().dirty_chunks(), 0);
    }
}

/// Convergence: txns dirty bitmap chunks between the start's slices slower than, as fast as and faster than the core's
/// budget writes them (each moved object frees its block in a chunk of its own, clean since the last checkpoint). With
/// a budget window that moved with each poll the slices trailed a writer at least as fast and the begin, which needs
/// room for all the rest, came only when admission held the writer back (here the device queue, on a 96 % full OSD the
/// dirty hard limit; 71590a232d: 44 and 97 polls); the start's fixed window of `ckpt_fz_polls` polls begins the freeze
/// within it, admission never refusing a txn meanwhile. Writes go on through the whole checkpoint; it and a replaying
/// mount hold exactly the live blocks.
#[test]
fn checkpoint_start_begins_within_its_window_while_txns_dirty_chunks() {
    const WINDOW: usize = 16;
    const SLICE: usize = 2;
    const OBJS: usize = 200;
    const BACKLOG: usize = 40;
    for per_poll in [0usize, 1, 2, 4] {
        let cfg = ShardCfg {
            ckpt_slice: SLICE,
            ckpt_fz_polls: WINDOW,
            ckpt_interval_ns: u64::MAX,
            ..Default::default()
        };
        // 4 GiB: 256 bitmap chunks
        let env = make_env_ext(4096, 512, 1, cfg, 3, 8192);
        let mut r = Rig::new(&env, 1);
        let mut live = spread_blocks(&mut r, OBJS as u64, 100);
        checkpoint_once(&mut r);
        assert_eq!(r.shard.state().dirty_chunks(), 0);
        // the start's backlog: the first objects move
        for (i, b) in live.iter_mut().enumerate().take(BACKLOG) {
            *b = spread_block(&mut r, 100 + i as u64, Some(*b), 300);
        }
        r.sync();
        assert!(r.shard.state().dirty_chunks() >= BACKLOG);
        r.shard.request_checkpoint();
        let lsn = r.shard.next_lsn() - 1;
        let (mut polls, mut moved, mut dirtied) = (0usize, 0usize, 0usize);
        let (mut began, busy0) = (None, r.shard.stats.busy);
        let mut held = 0;
        while r.shard.ckpt_lsn() < lsn || r.shard.ckpt_active() {
            r.pump();
            polls += 1;
            assert!(polls < 100_000, "{per_poll}/poll: checkpoint never ended");
            if began.is_none() && r.shard.ckpt_active() {
                began = Some(polls);
                held = (r.shard.stats.busy.iter().sum::<u64>()) - busy0.iter().sum::<u64>();
            }
            // the objects not moved yet first: chunks clean since the last checkpoint
            let d = r.shard.state().dirty_chunks();
            for _ in 0..per_poll {
                let i = BACKLOG + moved % (OBJS - BACKLOG);
                live[i] = spread_block(&mut r, 100 + i as u64, Some(live[i]), 400 + moved as u64);
                moved += 1;
            }
            if began.is_none() {
                // (a writer held back by admission pumps the shard: slices meanwhile)
                dirtied += r.shard.state().dirty_chunks().saturating_sub(d);
            }
        }
        let began = began.expect("began");
        // the window, plus the poll the begin may be held back to (a fresh core budget: the next poll, one shard here)
        assert!(
            began <= WINDOW + 1,
            "{per_poll}/poll: the start took {began} polls ({dirtied} chunks dirtied meanwhile, busy {:?} before {busy0:?})",
            r.shard.stats.busy
        );
        assert_eq!(
            held, 0,
            "{per_poll}/poll: admission held the writer back during the start"
        );
        assert!(
            dirtied >= per_poll * (began - 1),
            "{per_poll}/poll: {dirtied} chunks dirtied in {began} polls: fewer than one per moved object"
        );
        assert_eq!(
            r.shard.stats.busy[2], 0,
            "{per_poll}/poll: the dirty hard limit was hit"
        );
        r.sync();
        assert_alloc_is(&r, &live, "after the checkpoint");
        let img = r.disk.image();
        r.fsck(&img);
        let d = SimDisk::from_image(&img, env.sim.clone());
        let (s2, stats) = mount(&env, &d, &mut r.clk).unwrap();
        assert!(
            per_poll == 0 || stats.txns > 0,
            "{per_poll}/poll: nothing replayed"
        );
        r.shard = s2;
        r.disk = d;
        assert_alloc_is(&r, &live, "after a replaying mount");
    }
}

/// After its pages, the freeze's end steps (fix-up of interior pages changed meanwhile, unalias, relog) run one budget
/// unit per poll here, txns between any two of them: new keys split leaves and interior pages that still refer to
/// children by their addresses before the freeze (2 ms, at most 14 ms in one piece on a 96 % full OSD). The image is
/// complete: a mount from it right after the checkpoint replays the txns since and reads everything back.
#[test]
fn freeze_end_steps_run_in_slices_with_txns_between() {
    let cfg = ShardCfg {
        ckpt_slice: 1,
        ckpt_fz_polls: usize::MAX,
        ckpt_interval_ns: u64::MAX,
        dirty_soft_pages: 1 << 16,
        dirty_hard_pages: 1 << 17,
        ..Default::default()
    };
    let env = make_env_ext(64, 1024, 1, cfg, 8, 4096);
    let mut r = Rig::new(&env, 2);
    let n = 20_000u64;
    for i in 0..n {
        r.put(&key(i * 2), &[1u8; 30]);
    }
    r.sync();
    let lsn = r.shard.next_lsn() - 1;
    r.shard.request_checkpoint();
    while !r.shard.freeze_active() {
        r.pump();
    }
    let pages = r.shard.state().tree.fz_left();
    assert!(pages > 200, "{pages} pages frozen");
    let (mut polls, mut i) = (0usize, 0u64);
    while r.shard.freeze_active() {
        let k = r.rng.below(n) * 2;
        r.put(&key(k), &[2u8; 30]);
        r.put(&key(i * 2 + 1), &[3u8; 30]);
        i += 1;
        r.pump();
        polls += 1;
        assert!(polls < 1_000_000, "freeze never ended");
    }
    // one unit per poll: the pages, then (at least) every frozen page again to unalias it
    assert!(
        polls >= 2 * pages,
        "{polls} polls for {pages} frozen pages: the end steps ran in one piece"
    );
    while r.shard.ckpt_lsn() < lsn || r.shard.ckpt_active() {
        r.pump();
    }
    r.sync();
    r.verify();
    let img = r.disk.image();
    r.fsck(&img);
    let d = SimDisk::from_image(&img, env.sim.clone());
    let (mut s2, stats) = mount(&env, &d, &mut r.clk).unwrap();
    assert!(stats.txns > 0, "txns of the sliced end replayed");
    let got = s2.dump_blocking(&mut r.clk).unwrap();
    assert!(got == r.model, "mount from the image: content differs");
    r.remount_clean();
    r.verify();
}

/// Elastic meta (adr 0021 am. 80): a steady workload asks for the same meta space every checkpoint cycle; the
/// checkpoint start keeps what the last two cycles asked for. Random overwrites on a full OSD dirty bitmap chunks all
/// over the device: here each write frees a block in one chunk and allocates one in another, the chunk trigger starts a
/// checkpoint about every 50 writes, writes go on while it runs. Admission charges the pages the chunks' flush may
/// dirty, the start finds them still pending: a fixed slack of two cells gave the difference back at every start and
/// regrew it right after (about 45 cells per checkpoint on a 96 % full OSD: doc/perf/p99-64k-20261102.md).
#[test]
fn steady_workload_keeps_its_meta_cells() {
    let cfg = ShardCfg {
        ckpt_interval_ns: u64::MAX,
        dirty_soft_pages: 200,
        dirty_hard_pages: 1 << 17,
        ..Default::default()
    };
    // 256 chunks, a 1 MiB base meta area and 64-page cells (256 KiB): the chunk flush needs cells
    let mut sim = SimConfig::new(4 << 30);
    sim.awupf_lbas = 1;
    sim.awun_lbas = 1;
    let disk = SimDisk::new(sim.clone());
    let p = MkfsParams {
        shards: 1,
        wal_blocks: 1024,
        align_blocks: 1,
        meta_pct: 3,
        meta_max_blocks: 256,
        node_size: 4096,
        elastic_meta: true,
        cell_pages: 64,
        ..Default::default()
    };
    let (sb, dirs) = mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    let env = Env {
        img: disk.image(),
        sim,
        sb,
        dir: dirs[0].clone(),
        scfg: cfg,
        nobj: NOBJ,
        obj_scale: 1,
        big_pct: 0,
        storm_pct: 0,
        spread_pct: 0,
        idle_pct: 0,
    };
    let mut r = Rig::new(&env, 3);
    let slots = 100u64;
    let mut cur = spread_blocks(&mut r, slots, 7);
    let (mut i, mut c0) = (0u64, None);
    while r.shard.stats.ckpt_begins < 40 {
        let k = (i % slots) as usize;
        cur[k] = spread_block(&mut r, 7 + k as u64, Some(cur[k]), i / slots + 1);
        r.pump();
        i += 1;
        assert!(i < 100_000, "no checkpoints");
        if c0.is_none() && r.shard.stats.ckpt_begins >= 10 {
            c0 = Some((r.shard.stats.cells_added, r.shard.stats.cells_released));
        }
    }
    let c0 = c0.unwrap();
    let (added, released) = (
        r.shard.stats.cells_added - c0.0,
        r.shard.stats.cells_released - c0.1,
    );
    eprintln!("30 checkpoints in {i} writes: {added} cells added, {released} released");
    assert!(
        added + released < 30,
        "meta cells churn in a steady workload: {added} added, {released} released over 30 checkpoints"
    );
    r.sync();
    r.remount_clean();
    assert_alloc_is(&r, &cur, "after a clean remount");
}

/// One checkpoint covering everything submitted, requested once (no idle checkpoint after it).
fn checkpoint_once(r: &mut Rig) {
    r.sync();
    let want = r.shard.next_lsn() - 1;
    r.shard.request_checkpoint();
    for _ in 0..1_000_000 {
        if r.shard.ckpt_lsn() >= want && !r.shard.ckpt_active() && !r.shard.ckpt_starting() {
            return;
        }
        r.pump();
    }
    panic!("checkpoint never ended");
}

/// The meta peak (adr 0021 am. 80) is a soft hold: the empty cells it keeps after the tree shrank count as free data
/// space (`data_reclaim`), and an allocation that needs them gets `Busy` once while the checkpoint it forces gives them
/// back, never `NoSpace` (adr 0021 am. 21: empty cells held most of a full OSD's data region). An idle checkpoint gives
/// them back by itself.
#[test]
fn cells_the_meta_peak_holds_yield_to_data() {
    for idle in [false, true] {
        let env = make_env_full(64, 256, 1, ShardCfg::default(), 3, 4096, true, 64);
        let mut r = Rig::new(&env, 4);
        for i in 0..20_000u64 {
            r.put(&key(i), &[9u8; 200]);
        }
        for i in 0..64u64 {
            r.put(format!("y/{i}").as_bytes(), b"y");
        }
        checkpoint_once(&mut r);
        let grown = r.shard.statfs().meta_cells;
        assert!(grown >= 4, "{grown} cells");
        // the tree shrinks under load: the next starts still see the peak of the cycle that deleted
        r.delrange(b"k/", b"k0");
        checkpoint_once(&mut r);
        r.put(b"x/1", b"1");
        checkpoint_once(&mut r);
        let st = r.shard.statfs();
        assert!(
            st.meta_cells >= grown - 1,
            "cells given back under load: {st:?}"
        );
        assert!(st.data_reclaim > 0, "held cells not counted free: {st:?}");
        if idle {
            // nothing logged since: the checkpoints the held cells ask for (`reclaim`) are idle
            for _ in 0..4 {
                if r.shard.statfs().data_reclaim == 0 {
                    break;
                }
                let b0 = r.shard.stats.ckpt_begins;
                r.shard.request_checkpoint();
                while r.shard.stats.ckpt_begins == b0 || r.shard.ckpt_active() {
                    r.pump();
                }
            }
            let st = r.shard.statfs();
            assert!(
                st.meta_cells < grown / 2 && st.data_reclaim == 0,
                "idle checkpoints kept the cells: {st:?}"
            );
            continue;
        }
        // take every data block the shard offers: the held cells come back on the way. A client keeps logging (pure
        // shrinks, always admitted), so the checkpoint the allocation forces is not idle: the failed allocation itself
        // makes the hold yield, one checkpoint gives the cells back
        let (released0, begins0) = (r.shard.stats.cells_released, r.shard.stats.ckpt_begins);
        let (mut busy, mut got, mut y) = (0u64, 0u64, 0u64);
        loop {
            match r.shard.alloc(1) {
                Ok(_) => got += 1,
                Err(StoreError::Busy) => {
                    busy += 1;
                    assert!(busy < 100_000, "Busy without end: {:?}", r.shard.statfs());
                    if y < 64 {
                        r.del(format!("y/{y}").as_bytes());
                        y += 1;
                    }
                    r.pump();
                }
                Err(StoreError::NoSpace) => break,
                Err(e) => panic!("alloc: {e:?}"),
            }
        }
        let st = r.shard.statfs();
        assert!(busy > 0, "allocations never reached the held cells: {st:?}");
        // within two checkpoints (three when the hold waits until the peak ages out)
        let begins = r.shard.stats.ckpt_begins - begins0;
        assert!(
            begins <= 2,
            "the hold did not yield to the failed allocation: {begins} checkpoints, {busy} Busy, {st:?}"
        );
        assert!(
            r.shard.stats.cells_released > released0 && st.meta_cells < grown / 2,
            "the cells stayed with the meta space: {got} blocks taken, {st:?}"
        );
    }
}
