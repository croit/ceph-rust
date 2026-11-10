// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Targeted WAL / commit-protocol tests (the crash matrix lives in crash.rs).
mod common;
use common::*;

use store::BLK;
use store::StoreError;
use store::codec::{Enc, blk_crc, crc};
use store::dev::{BlockDev, Clock, CrashPolicy, IoError, Persist, SimClock, SimDisk};
use store::shard::{Event, Shard, ShardCfg, Txn};
use store::sio::Sio;
use store::state::{Extent, Op, Record};
use store::wal::{HDR_LEN, TailDropped, UnitHeader, encode_record};

fn fresh(env: &Env, seed: u64) -> (SimDisk, SimClock, Shard<store::dev::SimDev>) {
    let mut cfg = env.sim.clone();
    cfg.seed = seed;
    let disk = SimDisk::from_image(&env.img, cfg);
    let mut clk = SimClock::default();
    let (mut s, _) = mount(env, &disk, &mut clk).unwrap();
    settle_trims(&mut s, &mut clk);
    (disk, clk, s)
}

fn remount(
    env: &Env,
    img: &store::dev::SimImage,
    seed: u64,
) -> (SimDisk, SimClock, Shard<store::dev::SimDev>) {
    let mut cfg = env.sim.clone();
    cfg.seed = seed;
    let disk = SimDisk::from_image(img, cfg);
    let mut clk = SimClock::default();
    let (mut s, _) = mount(env, &disk, &mut clk).unwrap();
    settle_trims(&mut s, &mut clk);
    (disk, clk, s)
}

fn kv_txn(token: u64, k: &str, v: &str) -> Txn<Vec<u8>> {
    let mut t = Txn::new(token);
    t.ops
        .push(Op::Put(k.as_bytes().to_vec(), v.as_bytes().to_vec()));
    t
}

/// Poll until `n` acks (returns tokens) or no progress.
fn run_acks(s: &mut Shard<store::dev::SimDev>, clk: &mut SimClock, n: usize) -> Vec<u64> {
    let mut got = Vec::new();
    for _ in 0..100_000 {
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev);
        for e in ev {
            if let Event::Acked(t) = e {
                got.push(t);
            }
        }
        if got.len() >= n {
            break;
        }
        let h = s.dev().next_deadline();
        clk.idle(h);
    }
    got
}

#[test]
fn parallel_commit_data_and_wal_in_flight_together() {
    let mut env = make_env(16, 128, 1, ShardCfg::default());
    env.sim.jitter_ns = 0;
    let (disk, mut clk, mut s) = fresh(&env, 1);
    let t0 = clk.t;
    let blk = s.alloc(1).unwrap();
    let mut buf = s.alloc_buf(1);
    pattern(7, 0, &mut buf);
    let mut t = kv_txn(1, "obj", "x");
    t.data.push((blk, buf));
    s.submit(t).unwrap();
    let mut ev = Vec::new();
    s.poll(clk.t, &mut ev);
    assert_eq!(
        disk.inflight(),
        2,
        "data write and WAL unit must be submitted concurrently"
    );
    assert_eq!(run_acks(&mut s, &mut clk, 1), vec![1]);
    let dt = clk.t - t0;
    // serial would be >= 2 * write_ns (+ xfer); parallel ~ write_ns + 2 * xfer
    assert!(
        dt < 2 * env.sim.write_ns,
        "ack latency {dt} ns not parallel"
    );
    assert!(dt >= env.sim.write_ns);
}

#[test]
fn group_commit_shares_units_and_acks_in_order() {
    let env = make_env(16, 128, 1, ShardCfg::default());
    let (_d, mut clk, mut s) = fresh(&env, 2);
    for i in 0..40u64 {
        s.submit(kv_txn(i + 1, &format!("k{i}"), "v")).unwrap();
    }
    let acks = run_acks(&mut s, &mut clk, 40);
    assert_eq!(acks, (1..=40).collect::<Vec<_>>());
    assert_eq!(s.stats.txns, 40);
    assert!(
        s.stats.units <= 2,
        "40 tiny txns should share 1-2 units, got {}",
        s.stats.units
    );
    assert_eq!(s.durable_lsn(), 40);
}

/// QD1 4 KiB commit latency, measured on the deterministic device clock (not host CPU time).
/// Both submission policies must overlap data and WAL even with only two device slots.
#[test]
fn qd1_commit_latency_uses_the_last_queue_slot() {
    let mut serial = Vec::new();
    for at_flush in [false, true] {
        for depth in [2, 128] {
            let mut env = make_env(16, 512, 1, ShardCfg::default());
            env.sim.queue_depth = depth;
            env.sim.submit_at_flush = at_flush;
            env.sim.jitter_ns = 0;
            let (disk, mut clk, mut s) = fresh(&env, 1);
            let writes = disk.stats().writes;
            let mut latencies = Vec::new();
            for token in 1..=64 {
                let blk = s.alloc(1).unwrap();
                let mut txn = kv_txn(token, "obj", "x");
                txn.data.push((blk, s.alloc_buf(1)));
                let start = clk.t;
                s.submit(txn).unwrap();
                s.end_pass();
                let overlapping = disk.inflight() == 2;
                assert_eq!(run_acks(&mut s, &mut clk, 1), vec![token]);
                latencies.push(clk.t - start);
                if !overlapping {
                    serial.push((at_flush, depth, token));
                }
            }
            latencies.sort_unstable();
            let p50 = latencies[31];
            let p99 = latencies[63];
            eprintln!("QD1 commit at_flush={at_flush} depth={depth} p50_ns={p50} p99_ns={p99}");
            assert_eq!(
                disk.stats().writes - writes,
                128,
                "one data + one WAL write per op"
            );
            // One write service time, plus the two blocks' serialized bus transfers.
            let parallel_ns = env.sim.write_ns + 2 * env.sim.xfer_ns_per_lba;
            if p50 != parallel_ns || p99 != parallel_ns {
                serial.push((at_flush, depth, 0));
            }
        }
    }
    assert!(serial.is_empty(), "serialized data/WAL cells: {serial:?}");
}

#[test]
fn depth_two_wrap_keeps_pad_and_wal_admission_atomic() {
    for at_flush in [false, true] {
        let mut env = make_env(
            16,
            64,
            1,
            ShardCfg {
                auto_ckpt: false,
                ..Default::default()
            },
        );
        env.sim.queue_depth = 2;
        env.sim.submit_at_flush = at_flush;
        let (disk, mut clk, mut s) = fresh(&env, 1);
        // Odd head position, then two-block units: eventually a unit needs a PAD at the ring end.
        s.submit(kv_txn(1, "obj", "x")).unwrap();
        s.end_pass();
        assert_eq!(run_acks(&mut s, &mut clk, 1), vec![1]);
        let value = "v".repeat(2500);
        for token in 2..=65 {
            let blk = s.alloc(1).unwrap();
            let mut txn = kv_txn(token, "obj", &value);
            txn.ops
                .push(Op::Put(b"obj".to_vec(), value.as_bytes().to_vec()));
            txn.data.push((blk, s.alloc_buf(1)));
            s.submit(txn).unwrap();
            s.end_pass();
            assert_eq!(run_acks(&mut s, &mut clk, 1), vec![token]);
            s.request_checkpoint();
            assert!(run_until_released(&mut s, &mut clk, token).is_empty());
        }
        assert!(s.stats.pads > 0);
        let (mut recovered, _) =
            mount_img(&env, &disk.crash_image(CrashPolicy::DROP_ALL), 2).unwrap();
        let mut clock = SimClock::default();
        assert_eq!(
            dump(&mut recovered, &mut clock).get(b"obj".as_slice()),
            Some(&value.into_bytes())
        );
    }
}

#[test]
fn txn_visible_only_if_data_and_wal_both_landed() {
    let env = make_env(16, 128, 1, ShardCfg::default());
    let wal0 = env.dir.wal_start;
    for (name, wal_fate, data_fate, expect_present) in [
        ("both", Persist::Full, Persist::Full, true),
        ("wal only", Persist::Full, Persist::Drop, false),
        ("data only", Persist::Drop, Persist::Full, false),
        (
            "wal + torn data",
            Persist::Full,
            Persist::Tear(vec![true, false, true, true]),
            false,
        ),
        (
            "wal + data missing last blk",
            Persist::Full,
            Persist::Tear(vec![true, true, true, false]),
            false,
        ),
    ] {
        let (disk, clk, mut s) = fresh(&env, 3);
        let blk = s.alloc(4).unwrap();
        let mut buf = s.alloc_buf(4);
        for i in 0..4 {
            pattern(9, i, &mut buf[i as usize * BLK..(i as usize + 1) * BLK]);
        }
        let mut t = kv_txn(1, "obj/00", "v");
        t.data.push((blk, buf));
        s.submit(t).unwrap();
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev);
        assert_eq!(disk.inflight(), 2);
        let img = disk.crash_image_with(|f, _| {
            if f.lba >= wal0 && f.lba < wal0 + 128 {
                wal_fate.clone()
            } else {
                data_fate.clone()
            }
        });
        let (_d2, mut c2, mut s2) = remount(&env, &img, 4);
        assert_eq!(s2.state().lsn == 1, expect_present, "{name}");
        assert_eq!(
            has_key(&mut s2, &mut c2, b"obj/00"),
            expect_present,
            "{name}"
        );
        assert_eq!(
            s2.state().alloc.n_alloc(),
            if expect_present { 4 } else { 0 },
            "{name}"
        );
    }
}

#[test]
fn stale_unit_behind_a_gap_is_not_resurrected() {
    // eager seal (`wal_coalesce` 0): three units in flight at once
    let env = make_env(
        16,
        128,
        1,
        ShardCfg {
            wal_coalesce: 0,
            ..ShardCfg::default()
        },
    );
    let wal0 = env.dir.wal_start;
    let (disk, clk, mut s) = fresh(&env, 5);
    // three units in flight at once (one txn each: poll between submits at the same instant)
    for i in 1..=3u64 {
        s.submit(kv_txn(i, &format!("gen1/{i}"), "v")).unwrap();
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev);
    }
    assert_eq!(disk.inflight(), 3);
    // power loss: unit 2 never landed, unit 3 did (writes complete out of order)
    let img = disk.crash_image_with(|f, _| {
        if f.lba == wal0 + 1 {
            Persist::Drop
        } else {
            Persist::Full
        }
    });
    let (disk2, mut clk2, mut s2) = remount(&env, &img, 6);
    assert_eq!(s2.state().lsn, 1, "log ends at the gap");
    assert!(!has_key(&mut s2, &mut clk2, b"gen1/3"));
    // new incarnation reuses the gap position (lsn 2) and is made durable
    s2.submit(kv_txn(10, "gen2/a", "v")).unwrap();
    assert_eq!(run_acks(&mut s2, &mut clk2, 1), vec![10]);
    let img2 = disk2.crash_image(CrashPolicy::PERSIST_ALL);
    let (_d3, mut c3, mut s3) = remount(&env, &img2, 7);
    assert_eq!(s3.state().lsn, 2);
    let kv = dump(&mut s3, &mut c3);
    assert!(kv.contains_key(b"gen2/a".as_slice()));
    assert!(
        !kv.contains_key(b"gen1/3".as_slice()),
        "stale unit 3 must not be replayed"
    );
    assert_eq!(kv.len(), 2);
}

/// Forge a syntactically perfect unit (valid crcs, right lsn and chain crc) at ring position `pos`.
fn forge_unit(
    img: &mut store::dev::SimImage,
    env: &Env,
    pos: u64,
    epoch: u32,
    first_lsn: u64,
    prev_crc: u32,
    key: &str,
) -> u32 {
    let rec = Record {
        lsn: first_lsn,
        ops: vec![Op::Put(key.as_bytes().to_vec(), b"zforged".to_vec())],
        ..Default::default()
    };
    let mut e = Enc::new();
    encode_record(&rec, &mut e);
    let h = UnitHeader {
        epoch,
        first_lsn,
        ntxn: 1,
        nblocks: 1,
        flags: 0,
        shard: 0,
        payload_len: e.b.len() as u32,
        prev_crc,
        payload_crc: crc(&e.b),
        acked_lsn: 0,
        store_id: 0,
    };
    let mut b = vec![0u8; BLK];
    b[HDR_LEN..HDR_LEN + e.b.len()].copy_from_slice(&e.b);
    let c = h.write(&mut b);
    let disk = SimDisk::from_image(img, env.sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    Sio::new(&mut dev, &mut clk)
        .write_one(env.dir.wal_start + pos, &b)
        .unwrap();
    *img = disk.image();
    c
}

/// Write a unit with the given flags and payload at ring position `pos`; `payload_crc` = None: the right crc.
#[allow(clippy::too_many_arguments)]
fn forge_raw(
    img: &mut store::dev::SimImage,
    env: &Env,
    pos: u64,
    epoch: u32,
    first_lsn: u64,
    prev_crc: u32,
    flags: u16,
    payload: &[u8],
    payload_crc: Option<u32>,
) {
    let h = UnitHeader {
        epoch,
        first_lsn,
        ntxn: 1,
        nblocks: 1,
        flags,
        shard: 0,
        payload_len: payload.len() as u32,
        prev_crc,
        payload_crc: payload_crc.unwrap_or_else(|| crc(payload)),
        acked_lsn: 0,
        store_id: 0,
    };
    let mut b = vec![0u8; BLK];
    b[HDR_LEN..HDR_LEN + payload.len()].copy_from_slice(payload);
    h.write(&mut b);
    let disk = SimDisk::from_image(img, env.sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    Sio::new(&mut dev, &mut clk)
        .write_one(env.dir.wal_start + pos, &b)
        .unwrap();
    *img = disk.image();
}

/// Downgrade safety (adr 0021): a unit written whole (header and payload crcs verify, current chain) whose record carries
/// an op tag or header flag this build does not know came from a newer build. Replay refuses the mount loudly; reading it
/// as the torn end of the log would silently drop it and every acked txn behind it. A real torn unit (payload crc
/// mismatch) still ends the log.
#[test]
fn crc_valid_unit_from_a_newer_build_refuses_replay() {
    let env = make_env(16, 128, 1, ShardCfg::default());
    let (disk, mut clk, mut s) = fresh(&env, 31);
    s.submit(kv_txn(1, "a", "1")).unwrap();
    run_acks(&mut s, &mut clk, 1);
    let img = disk.crash_image(CrashPolicy::DROP_ALL);
    let (disk2, mut clk2, mut s2) = remount(&env, &img, 32);
    s2.submit(kv_txn(2, "b", "2")).unwrap();
    run_acks(&mut s2, &mut clk2, 1);
    let img2 = disk2.crash_image(CrashPolicy::DROP_ALL);
    let n_crc = header_crc_at(&img2, &env, 1);
    let rec = Record {
        lsn: 3,
        ops: vec![Op::Put(b"z".to_vec(), b"v".to_vec())],
        ..Default::default()
    };
    let mut e = Enc::new();
    encode_record(&rec, &mut e);
    let good = e.b.clone();
    let mut new_tag = good.clone();
    new_tag[store::wal::REC_HDR_LEN] = 0xee; // op tag of a newer build
    let refused =
        |img: &store::dev::SimImage, seed: u64, what: &str| match mount_img(&env, img, seed) {
            Err(StoreError::Corrupt(m)) => {
                assert!(
                    m.contains("newer build") && m.contains(what) && m.contains("lsn 3"),
                    "{m}"
                );
            }
            r => panic!("{what}: expected Corrupt, got {:?}", r.map(|(_, s)| s)),
        };
    // control: the same unit with a known tag replays
    let mut ok = img2.clone();
    forge_raw(&mut ok, &env, 2, 2, 3, n_crc, 0, &good, None);
    assert_eq!(remount(&env, &ok, 33).2.state().lsn, 3);
    // unknown op tag, crcs valid: refused
    let mut bad = img2.clone();
    forge_raw(&mut bad, &env, 2, 2, 3, n_crc, 0, &new_tag, None);
    refused(&bad, 34, "undecodable record");
    // unknown header flag, crcs valid: refused
    let mut flag = img2.clone();
    forge_raw(&mut flag, &env, 2, 2, 3, n_crc, 0x80, &good, None);
    refused(&flag, 35, "unknown header flags 0x80");
    // torn: the payload crc does not verify -> the log ends at lsn 2 (unacked tail), as before
    let mut torn = img2.clone();
    forge_raw(
        &mut torn,
        &env,
        2,
        2,
        3,
        n_crc,
        0,
        &new_tag,
        Some(crc(&good)),
    );
    assert_eq!(remount(&env, &torn, 36).2.state().lsn, 2);
}

fn header_crc_at(img: &store::dev::SimImage, env: &Env, pos: u64) -> u32 {
    let disk = SimDisk::from_image(img, env.sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let b = Sio::new(&mut dev, &mut clk)
        .read_one(env.dir.wal_start + pos, 1)
        .unwrap();
    UnitHeader::read(&b).unwrap().1
}

#[test]
fn epoch_rule_rejects_lower_epoch_unit_with_valid_chain() {
    let env = make_env(16, 128, 1, ShardCfg::default());
    // incarnation 1 writes lsn 1; incarnation 2 (epoch 2) writes lsn 2; both durable
    let (disk, mut clk, mut s) = fresh(&env, 11);
    s.submit(kv_txn(1, "a", "1")).unwrap();
    run_acks(&mut s, &mut clk, 1);
    let img = disk.crash_image(CrashPolicy::DROP_ALL);
    let (disk2, mut clk2, mut s2) = remount(&env, &img, 12);
    assert_eq!(s2.epoch(), 2);
    s2.submit(kv_txn(2, "b", "2")).unwrap();
    run_acks(&mut s2, &mut clk2, 1);
    let img2 = disk2.crash_image(CrashPolicy::DROP_ALL);
    let n_crc = header_crc_at(&img2, &env, 1);
    // control: a unit at pos 2 with the current epoch and a correct chain is accepted ...
    let mut ok = img2.clone();
    forge_unit(&mut ok, &env, 2, 2, 3, n_crc, "zforged");
    let (_d, _c, s_ok) = remount(&env, &ok, 13);
    assert_eq!(s_ok.state().lsn, 3);
    // ... and the same unit stamped with the older epoch 1 is rejected (non-decreasing epoch rule)
    let mut bad = img2.clone();
    forge_unit(&mut bad, &env, 2, 1, 3, n_crc, "zforged");
    let (_d, mut c, mut s_bad) = remount(&env, &bad, 14);
    assert_eq!(s_bad.state().lsn, 2);
    assert!(!has_key(&mut s_bad, &mut c, b"zforged"));
    // wrong chain crc rejected too
    let mut bad2 = img2.clone();
    forge_unit(&mut bad2, &env, 2, 2, 3, n_crc ^ 1, "zforged");
    let (_d, _c, s_bad2) = remount(&env, &bad2, 15);
    assert_eq!(s_bad2.state().lsn, 2);
}

/// A unit beyond the checkpoint whose record names blocks outside the data region ends the log like a bad data crc (a
/// torn tail whose borrowed chunk was returned after the mount that cut the log there, adr 0021 am. 49); it never
/// refuses the mount. Control: the same unit naming a block inside the region with a wrong crc.
#[test]
fn unit_naming_blocks_outside_the_data_region_ends_the_log() {
    let env = make_env(16, 128, 1, ShardCfg::default());
    let (disk, mut clk, mut s) = fresh(&env, 41);
    let epoch = s.epoch();
    s.submit(kv_txn(1, "a", "1")).unwrap();
    assert_eq!(run_acks(&mut s, &mut clk, 1), vec![1]);
    let img = disk.crash_image(CrashPolicy::DROP_ALL);
    let c1 = header_crc_at(&img, &env, 0);
    let past = env.dir.data_start + env.dir.data_blocks;
    for (blk, what) in [
        (past, "outside the region"),
        (env.dir.data_start, "bad data crc"),
    ] {
        let rec = Record {
            lsn: 2,
            ops: vec![Op::Put(b"zforged".to_vec(), b"v".to_vec())],
            data: vec![Extent {
                blk,
                nblk: 1,
                crcs: vec![0],
            }],
            ..Default::default()
        };
        let mut e = Enc::new();
        encode_record(&rec, &mut e);
        let mut torn = img.clone();
        forge_raw(&mut torn, &env, 1, epoch, 2, c1, 0, &e.b, None);
        let (s2, st) = mount_img(&env, &torn, 42).unwrap_or_else(|e| panic!("{what}: {e:?}"));
        assert_eq!(s2.state().lsn, 1, "{what}: the log ends before the unit");
        assert_eq!(st.data_invalid_units, 1, "{what}");
    }
}

#[test]
fn units_from_a_previous_mkfs_never_validate() {
    let env = make_env(16, 128, 1, ShardCfg::default());
    let (disk, mut clk, mut s) = fresh(&env, 21);
    for i in 1..=5 {
        s.submit(kv_txn(i, &format!("old{i}"), "v")).unwrap();
        run_acks(&mut s, &mut clk, 1);
    }
    let old = disk.crash_image(CrashPolicy::DROP_ALL);
    // re-mkfs with a different fs uuid over the old content (only roots + WAL head are rewritten)
    let d = SimDisk::from_image(&old, env.sim.clone());
    let mut dev = d.queue();
    let mut c = SimClock::default();
    let p = store::layout::MkfsParams {
        shards: 1,
        wal_blocks: 128,
        align_blocks: 1,
        meta_pct: 6,
        osd_fsid: [7; 16],
        ..Default::default()
    };
    store::layout::mkfs(&mut dev, &mut c, &p).unwrap();
    let mut env2 = env.clone();
    env2.img = d.image();
    env2.sb.osd_fsid = [7; 16];
    let disk2 = SimDisk::from_image(&env2.img, env2.sim.clone());
    let mut dev = disk2.queue();
    let (sb, dirs) = store::layout::read_super(&mut dev, &mut c).unwrap();
    let (s2, stats) = Shard::mount(dev, &mut c, &sb, &dirs[0], ShardCfg::default(), false).unwrap();
    assert_eq!(s2.state().lsn, 0);
    assert_eq!(stats.units, 0);
}

#[test]
fn freed_blocks_not_reusable_until_checkpoint_passes_freeing_txn() {
    let env = make_env(4, 64, 1, ShardCfg::default());
    let (_disk, mut clk, mut s) = fresh(&env, 31);
    let a = s.alloc(1).unwrap();
    let mut buf = s.alloc_buf(1);
    pattern(1, 0, &mut buf);
    let mut t1 = kv_txn(1, "obj", "a");
    t1.data.push((a, buf));
    s.submit(t1).unwrap();
    run_acks(&mut s, &mut clk, 1);
    // txn 2 replaces the object: new block b, frees a
    let b = s.alloc(1).unwrap();
    let mut buf = s.alloc_buf(1);
    pattern(2, 0, &mut buf);
    let mut t2 = kv_txn(2, "obj", "b");
    t2.data.push((b, buf));
    t2.frees.push((a, 1));
    s.submit(t2).unwrap();
    // exhaust the free space while txn 2 is unacked: `a` must never be handed out
    let mut got = Vec::new();
    while let Ok(x) = s.alloc(1) {
        got.push(x);
    }
    assert!(
        !got.contains(&a),
        "block freed by an unacked txn was reused"
    );
    got.iter().for_each(|&x| s.unreserve(x, 1));
    assert_eq!(run_acks(&mut s, &mut clk, 1), vec![2]);
    // acked is not enough: replay validates data crcs of the whole WAL window, so `a` stays unusable ...
    let mut got = Vec::new();
    while let Ok(x) = s.alloc(1) {
        got.push(x);
    }
    assert!(
        !got.contains(&a),
        "block recycled while its freeing txn is still inside the WAL window"
    );
    got.iter().for_each(|&x| s.unreserve(x, 1));
    // ... until a checkpoint passes the freeing txn
    s.request_checkpoint();
    run_until_released(&mut s, &mut clk, 2);
    // (and the deallocate of the released run completed: it holds the run while in flight, adr 0642)
    settle_trims(&mut s, &mut clk);
    let mut got = Vec::new();
    while let Ok(x) = s.alloc(1) {
        got.push(x);
    }
    assert!(got.contains(&a));
}

#[test]
fn overlapping_data_extents_are_rejected_before_io_and_replay() {
    // Duplicate and partially overlapping ranges, in either order. The checkpoint and crash verify
    // rejection never leaves a tree edit, an allocation, or a WAL record behind.
    for (first, second, deferred) in [(0, 0, false), (0, 1, false), (1, 0, false), (0, 1, true)] {
        let env = make_env(16, 128, 1, ShardCfg::default());
        let (disk, mut clk, mut s) = fresh(&env, 41);
        let blk = s.alloc(3).unwrap();
        let before = s.statfs();
        let mut t = kv_txn(1, "rejected", "must not survive");
        t.data.push((blk + first, vec![0x11; 2 * BLK]));
        let src = vec![0x22; 2 * BLK];
        if deferred {
            t.copies.push(store::shard::CopyRun {
                blk: blk + second,
                crcs: src
                    .chunks(BLK)
                    .enumerate()
                    .map(|(i, b)| blk_crc(blk + second + i as u64, b))
                    .collect(),
                src: src.into(),
                tail: false,
            });
        } else {
            t.data.push((blk + second, src));
        }
        assert!(matches!(
            s.submit(t),
            Err((StoreError::Invalid("overlapping data extents"), _))
        ));
        assert_eq!(s.next_lsn(), 1);
        assert_eq!(disk.inflight(), 0);
        assert_eq!(s.statfs().data_reserved, before.data_reserved);
        assert_eq!(s.statfs().data_used, before.data_used);
        assert!(dump(&mut s, &mut clk).is_empty());

        // The same reservation remains usable. Adjacent ranges in descending order are valid.
        let mut t = kv_txn(2, "accepted", "survives");
        t.data.push((blk + 1, vec![0x33; 2 * BLK]));
        t.data.push((blk, vec![0x44; BLK]));
        s.submit(t).unwrap();
        assert_eq!(run_acks(&mut s, &mut clk, 1), vec![2]);
        let img = disk.crash_image(CrashPolicy::DROP_ALL);
        let (_, mut clk2, mut s2) = remount(&env, &img, 42);
        assert_eq!(
            dump(&mut s2, &mut clk2).into_iter().collect::<Vec<_>>(),
            vec![(b"accepted".to_vec(), b"survives".to_vec())]
        );
    }
}

#[test]
fn overlapping_data_extents_in_crc_valid_wal_refuse_mount() {
    let env = make_env(16, 128, 1, ShardCfg::default());
    let (disk, mut clk, mut s) = fresh(&env, 43);
    let blk = env.dir.data_start;
    let data = vec![0x55; BLK];
    Sio::new(s.dev(), &mut clk).write_one(blk, &data).unwrap();
    let root = store::layout::read_root(s.dev(), &mut clk, &env.dir).unwrap();
    let extent = Extent {
        blk,
        nblk: 1,
        crcs: vec![blk_crc(blk, &data)],
    };
    let rec = Record {
        lsn: root.ckpt_lsn + 1,
        ops: vec![Op::Put(b"bad".to_vec(), b"mapping".to_vec())],
        // Equal data/checksums pass the WAL data check: the allocator contract must catch the overlap.
        data: vec![extent.clone(), extent],
        ..Default::default()
    };
    let mut encoded = Enc::new();
    encode_record(&rec, &mut encoded);
    let mut img = disk.image();
    forge_raw(
        &mut img,
        &env,
        root.wal_tail_pos,
        root.epoch,
        rec.lsn,
        root.wal_tail_prev_crc,
        0,
        &encoded.b,
        None,
    );
    assert!(matches!(mount_img(&env, &img, 44),
        Err(StoreError::Corrupt(m)) if m.contains("overlapping data extents")));
}

#[test]
fn submit_validation_is_side_effect_free() {
    let env = make_env(4, 64, 1, ShardCfg::default());
    let (_d, mut clk, mut s) = fresh(&env, 41);
    // data block that was never reserved
    let mut t = kv_txn(1, "x", "y");
    t.data.push((env.dir.data_start + 3, s.alloc_buf(1)));
    assert!(matches!(s.submit(t), Err((StoreError::Invalid(_), _))));
    // free of a block that is not allocated
    let mut t = kv_txn(1, "x", "y");
    t.frees.push((env.dir.data_start + 5, 1));
    assert!(matches!(s.submit(t), Err((StoreError::Invalid(_), _))));
    // misaligned buffer
    let b = s.alloc(1).unwrap();
    let mut t = kv_txn(1, "x", "y");
    t.data.push((b, vec![0; 100]));
    assert!(matches!(s.submit(t), Err((StoreError::Invalid(_), _))));
    s.unreserve(b, 1);
    // too large for one WAL unit
    let t = kv_txn(1, "x", &"z".repeat(70_000));
    assert!(matches!(s.submit(t), Err((StoreError::TxnTooLarge, _))));
    assert_eq!(s.next_lsn(), 1);
    assert_eq!(dump(&mut s, &mut clk).len(), 0);
    // double free within the pipeline
    let a = s.alloc(1).unwrap();
    let mut t = kv_txn(1, "o", "1");
    t.data.push((a, s.alloc_buf(1)));
    s.submit(t).unwrap();
    let mut t = kv_txn(2, "o", "2");
    t.frees.push((a, 1));
    s.submit(t).unwrap();
    let mut t = kv_txn(3, "o", "3");
    t.frees.push((a, 1));
    assert!(matches!(s.submit(t), Err((StoreError::Invalid(_), _))));
    assert_eq!(run_acks(&mut s, &mut clk, 2), vec![1, 2]);
}

#[test]
fn ring_wraps_pads_and_releases() {
    let cfg = ShardCfg {
        max_unit_blocks: 4,
        ckpt_wal_pct: 60,
        ..Default::default()
    };
    let env = make_env(64, 64, 1, cfg);
    let mut h = Harness::new(&env, 77);
    let mut pads = 0;
    for seed in 77..90 {
        h = Harness::new(&env, seed);
        assert!(h.run(1500, 5));
        pads += h.shard.stats.pads;
        if pads > 0 && h.wal_full_hits > 0 {
            break;
        }
    }
    assert!(pads > 0, "ring never wrapped with a PAD");
    assert!(
        h.releases > 0 && h.wal_full_hits > 0,
        "releases {} walfull {}",
        h.releases,
        h.wal_full_hits
    );
    let before = (
        dump(&mut h.shard, &mut h.clk),
        h.shard.state().alloc.snapshot(),
    );
    h.crash_and_remount(CrashPolicy::PERSIST_ALL, None).unwrap();
    assert_eq!(
        (
            dump(&mut h.shard, &mut h.clk),
            h.shard.state().alloc.snapshot()
        ),
        before
    );
}

#[test]
fn checkpoint_waits_for_ack_and_frees_ring_space() {
    let env = make_env(
        16,
        128,
        1,
        ShardCfg {
            auto_ckpt: false,
            ..Default::default()
        },
    );
    let (_d, mut clk, mut s) = fresh(&env, 51);
    for i in 1..=3u64 {
        s.submit(kv_txn(i, &format!("k{i}"), "v")).unwrap();
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev);
    }
    let free0 = s.ring_free_blocks();
    // requested before anything is acked: freezes at lsn 3 but the root slot waits for durability
    s.request_checkpoint();
    let acks = run_until_released(&mut s, &mut clk, 3);
    assert_eq!(acks, vec![1, 2, 3], "root slot only after all acks");
    assert_eq!(s.ckpt_lsn(), 3);
    assert!(s.ring_free_blocks() > free0, "ring space not released");
    assert!(!s.ckpt_active());
    // nothing changed: a further request is a no-op
    s.request_checkpoint();
    let mut ev = Vec::new();
    s.poll(clk.t, &mut ev);
    assert!(!s.ckpt_active());
}

// ------------------------------------------------------------------ the checker itself must not be vacuous

#[test]
fn checker_detects_lost_acked_wal_unit() {
    let env = make_env(
        16,
        128,
        1,
        ShardCfg {
            auto_ckpt: false,
            ..Default::default()
        },
    );
    let mut h = Harness::new(&env, 61);
    assert!(h.run(40, 3));
    // silent corruption of the first acked WAL unit (media bit flip): replay must stop there => acked txns lost
    let mut dev = h.disk.queue();
    let mut clk = SimClock::default();
    let tail = store::layout::read_root(&mut dev, &mut clk, &env.dir)
        .unwrap()
        .wal_tail_pos;
    h.disk.corrupt(env.dir.wal_start + tail, 9, 0x10); // header byte (epoch field): crc must catch it
    let r = h.crash_and_remount(CrashPolicy::PERSIST_ALL, None);
    let e = r.unwrap_err();
    assert!(e.contains("WalLost") || e.contains("acked txn lost"), "{e}");
}

#[test]
fn replay_detects_corrupted_data_block() {
    let env = make_env(16, 128, 1, ShardCfg::default());
    let (disk, mut clk, mut s) = fresh(&env, 71);
    let blk = s.alloc(2).unwrap();
    let mut buf = s.alloc_buf(2);
    pattern(5, 0, &mut buf[..BLK]);
    pattern(5, 1, &mut buf[BLK..]);
    let mut t = kv_txn(1, "obj/00", "v");
    t.data.push((blk, buf));
    s.submit(t).unwrap();
    run_acks(&mut s, &mut clk, 1);
    disk.corrupt(blk + 1, 7, 1); // flip one bit in the second data block
    let img = disk.crash_image(CrashPolicy::DROP_ALL);
    let disk2 = SimDisk::from_image(&img, env.sim.clone());
    let mut c = SimClock::default();
    let (_s2, stats) = mount(&env, &disk2, &mut c).unwrap();
    assert_eq!(stats.data_invalid_units, 1);
    assert_eq!(_s2.state().lsn, 0);
    // acked txn 1 rolled back (adr 0021 S2 residual, accepted by design): never silently
    assert_eq!(
        stats.tail_dropped,
        Some(TailDropped {
            shard: env.dir.shard,
            first_lsn: 1,
            last_lsn: 1,
            txns: 1,
            blk: blk + 1,
            reason: "data crc mismatch",
        })
    );
    let _ = blk_crc(0, &[]);
    let _ = Extent {
        blk: 0,
        nblk: 0,
        crcs: vec![],
    };
}

#[test]
fn checker_detects_silently_lost_writes() {
    let env = make_env(16, 128, 1, ShardCfg::default());
    let mut caught = 0;
    for seed in 0..20 {
        let mut h = Harness::new(&env, 80 + seed);
        h.disk.lose_writes(15);
        h.run(40, 4);
        if h.crash_and_remount(CrashPolicy::PERSIST_ALL, None).is_err() {
            caught += 1;
        }
    }
    assert!(
        caught > 10,
        "only {caught}/20 lost-write runs flagged: checker too weak"
    );
}

#[test]
fn mount_fails_on_unreadable_wal() {
    let env = make_env(16, 128, 1, ShardCfg::default());
    let (disk, mut clk, mut s) = fresh(&env, 91);
    s.submit(kv_txn(1, "a", "b")).unwrap();
    run_acks(&mut s, &mut clk, 1);
    let img = disk.crash_image(CrashPolicy::DROP_ALL);
    let d2 = SimDisk::from_image(&img, env.sim.clone());
    d2.fail_reads(env.dir.wal_start, 1);
    let mut c = SimClock::default();
    let r = mount(&env, &d2, &mut c);
    assert!(matches!(r, Err(StoreError::Io(IoError::Media))));
}

#[test]
fn works_with_512_byte_lbas_and_crash() {
    let mut env = make_env(16, 128, 1, ShardCfg::default());
    // rebuild env on a 512e device
    env.sim.lba_size = 512;
    env.sim.lba_count = (16 << 20) / 512;
    env.sim.max_xfer_lbas = 256;
    let disk = SimDisk::new(env.sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = store::layout::MkfsParams {
        shards: 1,
        wal_blocks: 128,
        align_blocks: 1,
        meta_pct: 6,
        ..Default::default()
    };
    let (sb, dirs) = store::layout::mkfs(&mut dev, &mut clk, &p).unwrap();
    env.img = disk.image();
    env.sb = sb;
    env.dir = dirs[0].clone();
    let mut h = Harness::new(&env, 5);
    h.run(60, 4);
    h.crash_and_remount(CrashPolicy::MIXED, None).unwrap();
}

/// A txn with `n` one-block data extents (fully fragmented free space), each block patterned with `(seed, i)`.
fn many_extents_txn(
    s: &mut Shard<store::dev::SimDev>,
    token: u64,
    n: u32,
    seed: u64,
) -> Txn<Vec<u8>> {
    let mut t = kv_txn(token, "obj/frag", "v");
    for i in 0..n {
        let b = s.alloc(1).unwrap();
        let mut buf = s.alloc_buf(1);
        pattern(seed, i, &mut buf);
        t.data.push((b, buf));
    }
    t
}

#[test]
fn txn_with_more_extents_than_queue_depth_goes_out_in_waves() {
    // adr 0066: more data extents than the device queue holds at once (a replica with fragmented free space) is
    // applied, not refused: the data goes out in waves, the txn is acked once all of it landed and survives a remount
    let env = make_env(4, 64, 1, ShardCfg::default());
    let (disk, mut clk, mut s) = fresh(&env, 77);
    let depth = s.dev().queue_depth();
    let n = 3 * depth as u32;
    let t = many_extents_txn(&mut s, 1, n, 5);
    s.submit(t).unwrap();
    assert!(
        s.stats.backlog_writes > 0,
        "part of the data waited for queue room"
    );
    // a second txn with data waits behind the backlog (Busy, nothing changed), a pure KV txn does not
    let mut t2 = kv_txn(2, "obj/later", "x");
    let b = s.alloc(1).unwrap();
    t2.data.push((b, s.alloc_buf(1)));
    let t2 = match s.submit(t2) {
        Err((StoreError::Busy, t2)) => t2,
        other => panic!("expected Busy, got {:?}", other.map_err(|e| e.0)),
    };
    s.submit(kv_txn(3, "obj/kv", "y")).unwrap();
    assert_eq!(run_acks(&mut s, &mut clk, 2), vec![1, 3]);
    s.submit(t2).unwrap();
    assert_eq!(run_acks(&mut s, &mut clk, 1), vec![2]);
    assert!(disk.inflight() == 0);
    // remount: replay validates every data crc of the big record
    let img = disk.crash_image(CrashPolicy::MIXED);
    let (_d2, mut c2, mut s2) = remount(&env, &img, 78);
    assert!(has_key(&mut s2, &mut c2, b"obj/frag"));
    assert!(has_key(&mut s2, &mut c2, b"obj/later"));
    assert_eq!(s2.state().alloc.n_alloc(), u64::from(n) + 1);
}

#[test]
fn crash_while_data_waits_in_the_backlog_loses_only_the_unacked_txn() {
    // the WAL unit of a backlogged txn may land before its data: replay must cut there (nothing of it was acked)
    let env = make_env(4, 64, 1, ShardCfg::default());
    let (disk, mut clk, mut s) = fresh(&env, 79);
    s.submit(kv_txn(1, "obj/before", "v")).unwrap();
    assert_eq!(run_acks(&mut s, &mut clk, 1), vec![1]);
    let depth = s.dev().queue_depth();
    let t = many_extents_txn(&mut s, 2, 3 * depth as u32, 6);
    s.submit(t).unwrap();
    assert!(s.stats.backlog_writes > 0);
    let mut ev = Vec::new();
    s.poll(clk.t, &mut ev);
    assert!(!ev.iter().any(|e| matches!(e, Event::Acked(2))));
    // everything in flight lands (the WAL unit too), the backlog never left the host
    let img = disk.crash_image_with(|_, _| Persist::Full);
    let (_d2, mut c2, mut s2) = remount(&env, &img, 80);
    assert!(has_key(&mut s2, &mut c2, b"obj/before"));
    assert!(!has_key(&mut s2, &mut c2, b"obj/frag"));
    assert_eq!(s2.state().alloc.n_alloc(), 0);
}

// ------------------------------------------------------------------ ADR 0021 am. 9: torn tail vs media corruption

/// `n` txns, each in its own unit, acked one by one (so unit k carries acked_lsn = k-1). With `data`, every txn
/// also writes one data block. Returns the disk and the data blocks.
fn acked_chain(env: &Env, seed: u64, n: u64, data: bool) -> (SimDisk, SimClock, Vec<u64>) {
    let (disk, mut clk, mut s) = fresh(env, seed);
    let mut blks = Vec::new();
    for i in 1..=n {
        let mut t = kv_txn(i, &format!("k{i:02}"), "v");
        if data {
            let b = s.alloc(1).unwrap();
            let mut buf = s.alloc_buf(1);
            pattern(i, 0, &mut buf);
            t.data.push((b, buf));
            blks.push(b);
        }
        s.submit(t).unwrap();
        assert_eq!(run_acks(&mut s, &mut clk, 1), vec![i]);
    }
    (disk, clk, blks)
}

fn tail_pos(env: &Env, disk: &SimDisk) -> u64 {
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    store::layout::read_root(&mut dev, &mut clk, &env.dir)
        .unwrap()
        .wal_tail_pos
}

fn mount_img(env: &Env, img: &store::dev::SimImage, seed: u64) -> MountRes {
    let mut cfg = env.sim.clone();
    cfg.seed = seed;
    let disk = SimDisk::from_image(img, cfg);
    mount(env, &disk, &mut SimClock::default())
}

fn no_ckpt() -> ShardCfg {
    ShardCfg {
        auto_ckpt: false,
        ..Default::default()
    }
}

#[test]
fn acked_wal_header_corruption_refuses_mount_override_reports_loss() {
    let env = make_env(16, 128, 1, no_ckpt());
    let (disk, _clk, _) = acked_chain(&env, 101, 4, false);
    let tail = tail_pos(&env, &disk);
    disk.corrupt(env.dir.wal_start + tail, 9, 0x10); // unit of txn 1
    let img = disk.image();
    match mount_img(&env, &img, 1) {
        Err(StoreError::WalLost {
            lsn: 1,
            acked_lsn: 3,
            ..
        }) => {}
        r => panic!("expected WalLost{{1,3}}, got {:?}", r.map(|(_, s)| s)),
    }
    let msg = StoreError::WalLost {
        shard: 0,
        lsn: 1,
        acked_lsn: 3,
    }
    .to_string();
    assert!(msg.contains("--accept-wal-loss") && msg.contains("1..=3"));
    // operator override: mounts at the last good point and reports the loss
    let mut env2 = env.clone();
    env2.scfg.replay.accept_loss = true;
    let (disk2, mut clk, mut s) = {
        let mut cfg = env.sim.clone();
        cfg.seed = 2;
        let d = SimDisk::from_image(&img, cfg);
        let mut c = SimClock::default();
        let (s, st) = mount(&env2, &d, &mut c).unwrap();
        assert_eq!(st.lost, Some((1, 3)));
        assert_eq!(st.tail_dropped, None, "a lost acked range is no torn tail");
        (d, c, s)
    };
    assert_eq!(s.state().lsn, 0);
    // the old units beyond the cut are leftovers of an older epoch: they must not condemn later mounts
    for i in 1..=3u64 {
        s.submit(kv_txn(i, &format!("n{i}"), "v")).unwrap();
        assert_eq!(run_acks(&mut s, &mut clk, 1), vec![i]);
    }
    let img2 = disk2.crash_image(CrashPolicy::DROP_ALL);
    let (_s3, st3) =
        mount_img(&env, &img2, 3).expect("default cfg must accept the post-override log");
    assert_eq!(st3.lost, None);
    assert_eq!(st3.tail_dropped, None, "clean replay reports nothing");
    assert_eq!(_s3.state().lsn, 3);
}

#[test]
fn acked_data_block_corruption_in_non_tail_unit_refuses_mount() {
    let env = make_env(16, 128, 1, no_ckpt());
    let (disk, _clk, blks) = acked_chain(&env, 102, 5, true);
    disk.corrupt(blks[1], 100, 0x01); // data of txn 2
    let img = disk.image();
    assert!(matches!(
        mount_img(&env, &img, 1),
        Err(StoreError::WalLost {
            lsn: 2,
            acked_lsn: 4,
            ..
        })
    ));
    // the very last unit has no later witness: indistinguishable from a torn tail (documented residual)
    let (disk, _clk, blks) = acked_chain(&env, 103, 5, true);
    disk.corrupt(blks[4], 100, 0x01);
    let (s, st) = mount_img(&env, &disk.image(), 2).unwrap();
    assert_eq!((st.data_invalid_units, s.state().lsn), (1, 4));
    let t = st.tail_dropped.expect("dropped acked tail is reported");
    assert_eq!((t.first_lsn, t.last_lsn, t.txns, t.blk), (5, 5, 1, blks[4]));
}

#[test]
fn torn_tail_with_later_valid_unit_is_still_accepted() {
    // txns 4 and 5 in flight together (both sealed while acked_lsn = 3); power loss persists unit 5 + its data but
    // loses txn 4's data: unit 4 is invalid, unit 5 valid behind it. Nothing was acked => plain torn tail.
    let env = make_env(16, 128, 1, no_ckpt());
    let (disk, mut clk, mut s) = fresh(&env, 104);
    for i in 1..=3u64 {
        s.submit(kv_txn(i, &format!("k{i}"), "v")).unwrap();
        run_acks(&mut s, &mut clk, 1);
    }
    let mut blks = Vec::new();
    for i in 4..=5u64 {
        let b = s.alloc(1).unwrap();
        let mut buf = s.alloc_buf(1);
        pattern(i, 0, &mut buf);
        let mut t = kv_txn(i, &format!("k{i}"), "v");
        t.data.push((b, buf));
        s.submit(t).unwrap();
        blks.push(b);
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev); // seal + submit unit 5 while 4 is unacked
    }
    assert_eq!(s.durable_lsn(), 3);
    let lost = blks[0];
    let img = disk.crash_image_with(|f, _| {
        if f.lba <= lost && lost < f.lba + f.nlba as u64 {
            Persist::Drop
        } else {
            Persist::Full
        }
    });
    let (s2, st) = mount_img(&env, &img, 5).expect("torn tail must mount");
    assert_eq!(
        (st.data_invalid_units, st.lost, s2.state().lsn),
        (1, None, 3)
    );
    // everything from lsn 4 on is gone; unit 5 lies behind the validation batch that ended the log (not read)
    let t = st.tail_dropped.expect("torn tail is reported");
    assert_eq!(
        (t.first_lsn, t.last_lsn, t.txns, t.blk, t.reason),
        (4, 4, 1, lost, "data crc mismatch")
    );
}

#[test]
fn fuzz_single_bit_flips_in_wal_never_silently_roll_back_acked_txns() {
    const N: u64 = 12;
    let env = make_env(16, 128, 1, no_ckpt());
    let (disk, _clk, _) = acked_chain(&env, 105, N, false);
    let tail = tail_pos(&env, &disk);
    let base = disk.image();
    let (mut refused, mut harmless, mut last_unit) = (0, 0, 0);
    for k in 0..N {
        for byte in (0..96usize).chain([500, 2000, 4095]) {
            let mut img = base.clone();
            img.corrupt(env.dir.wal_start + tail + k, byte, 1 << (byte % 8));
            match mount_img(&env, &img, 7) {
                Err(StoreError::WalLost { lsn, acked_lsn, .. }) => {
                    assert!(lsn <= acked_lsn && acked_lsn < N + 1);
                    refused += 1;
                }
                Ok((s, st)) if s.state().lsn == N => {
                    assert_eq!(st.lost, None);
                    harmless += 1;
                }
                // only the newest unit has no later witness (documented residual)
                Ok((s, _)) => {
                    assert_eq!(
                        (k, s.state().lsn),
                        (N - 1, N - 1),
                        "silent rollback of acked txns"
                    );
                    last_unit += 1;
                }
                Err(e) => panic!("unexpected mount error {e:?}"),
            }
        }
    }
    assert!(
        refused > 500 && harmless > 0 && last_unit > 0,
        "{refused} {harmless} {last_unit}"
    );
}

#[test]
fn witness_ignores_units_of_an_earlier_mkfs_with_same_fsid() {
    // re-mkfs (same osd fsid, new mkfs_time) over a used WAL ring: leftover units carry epoch + acked_lsn that
    // would satisfy the witness scan once the new store's epoch catches up. Must mount fine (no false WalLost).
    let env = make_env(16, 128, 1, no_ckpt());
    let (disk, mut clk, mut s) = fresh(&env, 31);
    for i in 1..=8 {
        s.submit(kv_txn(i, &format!("old{i}"), "v")).unwrap();
        assert_eq!(run_acks(&mut s, &mut clk, 1), vec![i]);
    }
    let old = disk.crash_image(CrashPolicy::DROP_ALL);
    let d = SimDisk::from_image(&old, env.sim.clone());
    let mut dev = d.queue();
    let mut c = SimClock::default();
    let p = store::layout::MkfsParams {
        shards: 1,
        wal_blocks: 128,
        align_blocks: 1,
        meta_pct: 6,
        mkfs_time: 12345,
        ..Default::default()
    };
    let (sb, dirs) = store::layout::mkfs(&mut dev, &mut c, &p).unwrap();
    let mut env2 = env.clone();
    env2.img = d.image();
    env2.sb = sb;
    env2.dir = dirs[0].clone();
    let mut img = env2.img.clone();
    for k in 0..4u64 {
        let (disk2, _clk, _s) = remount(&env2, &img, 40 + k);
        img = disk2.crash_image(CrashPolicy::DROP_ALL);
    }
    let (_d, _c, s2) = remount(&env2, &img, 50);
    assert_eq!(s2.state().lsn, 0);
}

/// Review 2026-11-03 #3: the newest root slot (here the mount's epoch bump) is lost to bit rot, so the mount falls back
/// to the older slot of the previous incarnation and every unit since carries `epoch > root.epoch`. A unit of that newer
/// incarnation that continues the chain proves the lost root: refuse, never end the log there. With that first unit also
/// corrupt, the later units of the newer incarnation still prove the acked txns (witness `epoch >= root.epoch`).
#[test]
fn lost_newest_root_slot_never_ends_the_log_silently() {
    let env = make_env(16, 128, 1, no_ckpt());
    let (disk, _clk, _) = acked_chain(&env, 111, 4, false);
    let tail = tail_pos(&env, &disk);
    let mut img = disk.image();
    img.corrupt(newest_root_blk(&env.dir, &img), 12, 0x01); // seq field: the slot's crc must catch it
    let fallback = {
        let d = SimDisk::from_image(&img, env.sim.clone());
        store::layout::read_root(&mut d.queue(), &mut SimClock::default(), &env.dir).unwrap()
    };
    assert_eq!(fallback.epoch, 0, "fell back to the mkfs root");
    match mount_img(&env, &img, 1) {
        Err(StoreError::Corrupt(m)) if m.contains("newest root slot is lost") => {}
        r => panic!(
            "newer-incarnation unit must refuse the mount, got {:?}",
            r.map(|(s, st)| (s.state().lsn, st))
        ),
    }
    // the operator override covers a WAL cut, not a lost root: still refused
    let mut env2 = env.clone();
    env2.scfg.replay.accept_loss = true;
    assert!(matches!(
        mount_img(&env2, &img, 2),
        Err(StoreError::Corrupt(_))
    ));
    // the first unit of the newer incarnation is unreadable too: the later ones are the witness
    img.corrupt(env.dir.wal_start + tail, 9, 0x10);
    match mount_img(&env, &img, 3) {
        Err(StoreError::WalLost {
            lsn: 1,
            acked_lsn: 3,
            ..
        }) => {}
        r => panic!(
            "expected WalLost{{1,3}}, got {:?}",
            r.map(|(s, st)| (s.state().lsn, st))
        ),
    }
}

/// Poll until the shard has nothing left to do (mount trims included).
fn settle(s: &mut Shard<store::dev::SimDev>, clk: &mut SimClock) {
    for _ in 0..100_000 {
        if s.quiet() {
            return;
        }
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev);
        let h = s.dev().next_deadline();
        clk.idle(h);
    }
    panic!("shard never went quiet");
}

/// Data of `n` blocks at `blk` filled with `fill`, one device transfer per piece (`Shard::pre_piece`).
fn push_data(s: &mut Shard<store::dev::SimDev>, t: &mut Txn<Vec<u8>>, blk: u64, n: u32, fill: u8) {
    let piece = (s.pre_piece() / BLK) as u32;
    for o in (0..n).step_by(piece as usize) {
        let mut b = s.alloc_buf(piece.min(n - o) as usize);
        b.fill(fill);
        t.data.push((blk + u64::from(o), b));
    }
}

/// Write object `key` of `n` blocks in one txn that also frees `old` (the previous version's blocks); a refused
/// allocation or submit (Busy) is retried after `later` polls, like a parked txn the store retries in a later round.
/// `Ok((first block, refusals))`, or the first other error.
fn write_obj_retrying(
    s: &mut Shard<store::dev::SimDev>,
    clk: &mut SimClock,
    tok: &mut u64,
    key: &str,
    (n, old): (u32, Option<u64>),
    later: usize,
) -> Result<(u64, u64), StoreError> {
    let mut busy = 0;
    let pump = |s: &mut Shard<store::dev::SimDev>, clk: &mut SimClock| {
        for _ in 0..later {
            let mut ev = Vec::new();
            s.poll(clk.t, &mut ev);
            let h = s.dev().next_deadline();
            clk.idle(h);
        }
    };
    for _ in 0..10_000 {
        let blk = match s.alloc(n) {
            Ok(b) => b,
            Err(StoreError::Busy) => {
                busy += 1;
                pump(s, clk);
                continue;
            }
            Err(e) => return Err(e),
        };
        let mut t = kv_txn(*tok + 1, key, "v");
        t.frees.extend(old.map(|b| (b, n)));
        push_data(s, &mut t, blk, n, 0x5c);
        match s.submit(t) {
            Ok(_) => {
                *tok += 1;
                assert_eq!(run_acks(s, clk, 1), vec![*tok]);
                return Ok((blk, busy));
            }
            Err((StoreError::Busy, _)) => {
                s.unreserve(blk, n);
                busy += 1;
                pump(s, clk);
            }
            Err((e, _)) => {
                s.unreserve(blk, n);
                return Err(e);
            }
        }
    }
    panic!("{key}: never committed ({busy} refusals)");
}

/// A device idle gap of up to `gap` ns, polled as a store core polls through it (`Store::poll`, the core's idle loop): an
/// active shard ([`Shard::quiet`] false: a checkpoint requested, in its sliced steps or writing, IO in flight) every pass,
/// at its device's next completion; a quiet shard at every store sweep (1 ms), its device at the clock (a real device's
/// clock runs while nothing is in flight). Only a quiet shard's poll may start a deallocate. The gap ends right after one
/// went out (the next write meets it in flight), else after `gap` ns. True = a deallocate went out.
fn core_gap(s: &mut Shard<store::dev::SimDev>, clk: &mut SimClock, gap: u64) -> bool {
    const SWEEP_NS: u64 = 1_000_000;
    let (end, cmds) = (clk.t + gap, s.stats.trim_cmds);
    let mut ev = Vec::new();
    while clk.t < end && s.stats.trim_cmds == cmds {
        if s.quiet() {
            clk.idle(Some((clk.t + SWEEP_NS).min(end)));
            sync_dev_clock(s.dev(), clk.t);
        } else {
            let h = s.dev().next_deadline();
            clk.idle(h.map(|h| h.min(end)));
        }
        s.poll(clk.t, &mut ev);
    }
    s.stats.trim_cmds > cmds
}

/// Runtime deallocate (adr 0642), the mechanism of the 2026-11-02 tsrv2 stall (495 s): a shard filled to its floor, three
/// objects freed again, then overwrites (each version on new blocks, the old ones released by the next checkpoint: a
/// deallocate backlog that keeps refilling), a slow device deallocate (2 ms per command) and a device idle gap after
/// each write, polled as a core polls through it ([`core_gap`]: the sliced checkpoint a request starts runs to its end,
/// then a deallocate goes out and the next write meets it in flight). A write that misses while a command holds free
/// windows waits for that one command only, however late its retry comes: no new command starts before the retry. The
/// first version failed here (a retry three polls later met a new command: one write refused twice; on tsrv2 the backlog
/// was 154k windows and the store stalled). Periodic checkpoint requests never keep the deallocates out of the gaps.
#[test]
fn near_full_shard_keeps_committing_while_deallocates_run() {
    const N: u32 = 512;
    let mut env = make_env(32, 128, 1, ShardCfg::default());
    env.sim.dealloc_ns = 2_000_000;
    let (_disk, mut clk, mut s) = fresh(&env, 11);
    let mut tok = 0;
    // fill with objects of two windows (each holds at least one whole window) up to the user floor
    let mut objs = Vec::new();
    while let Ok((blk, _)) = write_obj_retrying(
        &mut s,
        &mut clk,
        &mut tok,
        &format!("o/{:04}", objs.len()),
        (N, None),
        1,
    ) {
        objs.push((format!("o/{:04}", objs.len()), blk));
    }
    assert!(objs.len() >= 10, "filled {} objects", objs.len());
    // free three objects: room above the floor for about three versions in flight
    for (key, blk) in objs.iter().step_by(2).take(3) {
        tok += 1;
        let mut t = Txn::new(tok);
        t.ops.push(Op::Del(key.clone().into_bytes()));
        t.frees.push((*blk, N));
        s.submit(t).unwrap();
        assert_eq!(run_acks(&mut s, &mut clk, 1), vec![tok]);
    }
    let mut live: Vec<(String, u64)> = objs.into_iter().skip(1).step_by(2).collect();
    let cmds0 = s.stats.trim_cmds;
    // overwrite the rest, a checkpoint every second write, a device idle gap (a deallocate goes out) after each write,
    // the retry of a refused write three polls later
    let (mut worst, mut refused, mut trimmed, mut met) = (0, 0, 0, 0);
    let rounds = 8 * live.len();
    for r in 0..rounds {
        let j = r % live.len();
        let (key, old) = live[j].clone();
        met += u64::from(s.gauges().trim_held > 0);
        let (blk, busy) = write_obj_retrying(&mut s, &mut clk, &mut tok, &key, (N, Some(old)), 3)
            .unwrap_or_else(|e| panic!("overwrite {r}: {e:?}"));
        live[j].1 = blk;
        worst = worst.max(busy);
        refused += busy;
        if r % 2 == 1 {
            s.request_checkpoint();
        }
        trimmed += u64::from(core_gap(&mut s, &mut clk, 20_000_000));
    }
    eprintln!(
        "{rounds} overwrites, {} deallocates ({trimmed} gaps sent one, {met} writes met one in flight), {refused} \
         refusals, at most {worst} for one write, {} trim waits",
        s.stats.trim_cmds - cmds0,
        s.stats.trim_waits
    );
    assert!(
        s.stats.trim_cmds > cmds0,
        "deallocates ran between the writes"
    );
    assert!(
        2 * trimmed >= rounds as u64 && met > 0,
        "a deallocate went out in {trimmed} of {rounds} gaps, {met} writes met one in flight"
    );
    assert!(
        worst <= 1,
        "a write waited for more than the one command in flight: {worst} refusals"
    );
}

/// Runtime deallocate (adr 0642): an allocation that misses while a command holds free windows is refused once
/// (`trim_waits`); no command starts before the next allocation, however many idle gaps pass, and the retry after the
/// completion takes the released windows.
#[test]
fn a_miss_waits_for_the_one_deallocate_in_flight() {
    const WIN: u32 = 256;
    let mut env = make_env(32, 128, 1, ShardCfg::default());
    // slower than one gap: every command takes one window (adr 0642 budget), candidates stay for the next ones
    env.sim.dealloc_ns = 30_000_000;
    let (_disk, mut clk, mut s) = fresh(&env, 13);
    settle(&mut s, &mut clk);
    settle_trims(&mut s, &mut clk);
    // an object of eight windows, freed again: its whole windows are candidates once a checkpoint passed the free
    let mut tok = 0;
    let (blk, _) = write_obj_retrying(&mut s, &mut clk, &mut tok, "a", (8 * WIN, None), 1).unwrap();
    tok += 1;
    let mut t = Txn::new(tok);
    t.ops.push(Op::Del(b"a".to_vec()));
    t.frees.push((blk, 8 * WIN));
    s.submit(t).unwrap();
    assert_eq!(run_acks(&mut s, &mut clk, 1), vec![tok]);
    s.request_checkpoint();
    settle(&mut s, &mut clk);
    assert!(s.gauges().trim_cand_windows >= 7);
    // a device idle gap past the pause: one command takes one window
    let cmds = s.stats.trim_cmds;
    clk.idle(Some(s.trim_due().max(clk.t) + 20_000_000));
    let mut ev = Vec::new();
    s.poll(clk.t, &mut ev);
    assert_eq!(s.stats.trim_cmds, cmds + 1);
    assert_eq!(s.gauges().trim_held, u64::from(WIN));
    // a run longer than any free run outside the held window (no floor: only the shape misses)
    let want = s.state().alloc.longest_run() as u32 + 1;
    assert_eq!(s.alloc_priv(want), Err(StoreError::Busy));
    assert_eq!(s.stats.trim_waits, 1);
    // idle gaps past the pause: the completion is reaped, candidates remain, no new command starts before the retry
    for _ in 0..10 {
        clk.idle(Some(clk.t + 50_000_000));
        s.poll(clk.t, &mut ev);
    }
    assert_eq!(s.gauges().trim_held, 0);
    assert!(s.gauges().trim_cand_windows >= 6);
    assert_eq!(s.stats.trim_cmds, cmds + 1);
    let b = s.alloc_priv(want).unwrap();
    s.unreserve(b, want);
    assert_eq!(s.stats.trim_waits, 1);
    // the next idle gap sends the next command
    clk.idle(Some(clk.t + 20_000_000));
    s.poll(clk.t, &mut ev);
    assert_eq!(s.stats.trim_cmds, cmds + 2);
}

/// Runtime deallocate (adr 0642): the mount trims the whole free windows once; a whole window freed by an acked txn is
/// deallocated once a checkpoint passed the free, never before; a device without runtime deallocate gets none and the
/// bytes count as skipped.
#[test]
fn freed_blocks_are_deallocated_after_checkpoint() {
    const WIN: u64 = 256;
    for on in [false, true] {
        let mut env = make_env(16, 128, 1, ShardCfg::default());
        if !on {
            env.sim.dealloc = store::dev::DeallocLimits::off("off(test)");
        }
        let lpb = store::BLK as u64 / u64::from(env.sim.lba_size);
        let (disk, mut clk, mut s) = fresh(&env, 5);
        settle(&mut s, &mut clk);
        assert_eq!(disk.stats().deallocs > 0, on, "mount trim, on={on}");
        assert_eq!(s.gauges().trim_cand_windows, 0);
        let free0 = s.state().alloc.n_free();
        // two windows: the window of block `blk + WIN` lies inside the run
        let blk = s.alloc(2 * WIN as u32).unwrap();
        let mut t = kv_txn(1, "obj", "x");
        push_data(&mut s, &mut t, blk, 2 * WIN as u32, 0xa5);
        s.submit(t).unwrap();
        assert_eq!(run_acks(&mut s, &mut clk, 1), vec![1]);
        let mapped = |d: &SimDisk| d.image().read_lba((blk + WIN) * lpb)[0] == 0xa5;
        assert!(mapped(&disk));
        let mut t = kv_txn(2, "obj", "y");
        t.frees.push((blk, 2 * WIN as u32));
        s.submit(t).unwrap();
        assert_eq!(run_acks(&mut s, &mut clk, 1), vec![2]);
        let d1 = disk.stats().deallocs;
        assert!(mapped(&disk), "no trim before the checkpoint");
        s.request_checkpoint();
        settle(&mut s, &mut clk);
        settle_trims(&mut s, &mut clk);
        assert_eq!(mapped(&disk), !on, "on={on}");
        assert_eq!(disk.stats().deallocs > d1, on);
        assert_eq!(s.stats.trim_skipped_bytes > 0, !on);
        assert_eq!(s.stats.trim_errors, 0);
        // nothing stays held: every block is allocatable again
        assert_eq!(s.state().alloc.n_held(), 0);
        assert_eq!(s.gauges().trim_held, 0);
        assert!(s.state().alloc.n_free() >= free0);
    }
}

/// Mount trim (adr 0642): blocks freed while the device had no runtime deallocate stay mapped; the next mount on a device
/// that deallocates unmaps the whole free windows (the free map is durable, what was trimmed is not), and the live data
/// stays readable.
#[test]
fn mount_deallocates_blocks_freed_without_runtime_deallocate() {
    const WIN: u64 = 256;
    let mut env = make_env(16, 128, 1, ShardCfg::default());
    env.sim.dealloc = store::dev::DeallocLimits::off("off(test)");
    let lpb = store::BLK as u64 / u64::from(env.sim.lba_size);
    let (disk, mut clk, mut s) = fresh(&env, 7);
    settle(&mut s, &mut clk);
    let write =
        |s: &mut Shard<store::dev::SimDev>, clk: &mut SimClock, tok: u64, fill: u8, n: u32| {
            let blk = s.alloc(n).unwrap();
            let mut t = kv_txn(tok, "obj", &format!("{tok}"));
            push_data(s, &mut t, blk, n, fill);
            s.submit(t).unwrap();
            assert_eq!(run_acks(s, clk, 1), vec![tok]);
            blk
        };
    // the dead object spans two windows (the window of `dead + WIN` lies inside it)
    let dead = write(&mut s, &mut clk, 1, 0x5a, 2 * WIN as u32);
    let live = write(&mut s, &mut clk, 2, 0xc3, 4);
    let mut t = kv_txn(3, "obj", "3");
    t.frees.push((dead, 2 * WIN as u32));
    s.submit(t).unwrap();
    assert_eq!(run_acks(&mut s, &mut clk, 1), vec![3]);
    s.request_checkpoint();
    settle(&mut s, &mut clk);
    assert!(s.stats.trim_skipped_bytes > 0);
    let at = |img: &store::dev::SimImage, blk: u64| img.read_lba(blk * lpb)[0];
    let img = disk.image();
    assert_eq!(
        at(&img, dead + WIN),
        0x5a,
        "no runtime deallocate: the freed blocks stay mapped"
    );
    let used0 = img.used_lbas();
    drop(s);
    env.sim.dealloc = store::dev::SimConfig::new(4096).dealloc;
    let (disk, mut clk, mut s) = remount(&env, &img, 8);
    settle(&mut s, &mut clk);
    assert!(disk.stats().deallocs > 0);
    assert_eq!(s.stats.trim_errors, 0);
    let img = disk.image();
    assert_ne!(
        at(&img, dead + WIN),
        0x5a,
        "the mount trim unmapped the freed whole window"
    );
    assert_eq!(at(&img, live), 0xc3, "live data is never deallocated");
    assert!(
        img.used_lbas() + (WIN * lpb) as usize <= used0,
        "{} vs {used0}",
        img.used_lbas()
    );
    assert_eq!(s.state().alloc.n_held(), 0);
    assert_eq!(s.gauges().trim_held, 0);
}

/// Group commit (adr 0021 am. 37): units sealed while `n` txns are submitted around one unit in flight.
fn coalesce_units(k: usize, val: usize) -> (u64, Vec<u64>, u64) {
    let mut env = make_env(
        16,
        256,
        1,
        ShardCfg {
            wal_coalesce: k,
            ..ShardCfg::default()
        },
    );
    env.sim.jitter_ns = 0;
    env.sim.submit_at_flush = true;
    let (disk, mut clk, mut s) = fresh(&env, 3);
    let v = "v".repeat(val);
    // idle WAL of a flush-issued device: the first txn is sealed and submitted at the end of the core loop's pass
    // (QD1 path, adr 0021 am. 67)
    s.submit(kv_txn(1, "k0", &v)).unwrap();
    assert_eq!(s.stats.units, 0, "no seal at submit");
    s.end_pass();
    assert_eq!(
        (s.stats.units, disk.inflight()),
        (1, 1),
        "idle WAL seals at the end of the pass"
    );
    let mut ev = Vec::new();
    for round in 0..2u64 {
        for j in 0..2u64 {
            let i = 2 + round * 2 + j;
            s.submit(kv_txn(i, &format!("k{i}"), &v)).unwrap();
        }
        s.poll(clk.t, &mut ev); // no completion yet: same instant
    }
    assert!(ev.is_empty());
    let before = s.stats.units;
    let acks = run_acks(&mut s, &mut clk, 5);
    (before, acks, s.stats.units)
}

#[test]
fn idle_wal_seals_at_submit_on_a_device_that_issues_at_submit() {
    // SPDK-like device: a lone txn's unit goes out with its data writes, no wait for the end of the pass (adr 0021 am. 8)
    let env = make_env(16, 256, 1, ShardCfg::default());
    let (disk, mut clk, mut s) = fresh(&env, 3);
    s.submit(kv_txn(1, "k1", "v")).unwrap();
    assert_eq!((s.stats.units, disk.inflight()), (1, 1), "sealed at submit");
    s.submit(kv_txn(2, "k2", "v")).unwrap();
    s.end_pass();
    assert_eq!(
        s.stats.units, 1,
        "busy WAL: the second txn waits for the group commit"
    );
    assert_eq!(run_acks(&mut s, &mut clk, 2), vec![1, 2]);
}

#[test]
fn idle_wal_seals_one_unit_per_pass() {
    // flush-issued device (kernel tier): the txns one pass submits to an idle WAL share one unit, sealed and written
    // at the end of the pass, where the thread flushes its device queue anyway
    let mut env = make_env(16, 256, 1, ShardCfg::default());
    env.sim.submit_at_flush = true;
    let (disk, mut clk, mut s) = fresh(&env, 3);
    for i in 1..=3u64 {
        s.submit(kv_txn(i, &format!("k{i}"), "v")).unwrap();
    }
    assert_eq!(
        (s.stats.units, disk.inflight()),
        (0, 0),
        "no seal at submit"
    );
    s.end_pass();
    assert_eq!(
        (s.stats.units, disk.inflight()),
        (1, 1),
        "one unit for the pass"
    );
    s.end_pass();
    assert_eq!(s.stats.units, 1, "an empty pass seals nothing");
    assert_eq!(run_acks(&mut s, &mut clk, 3), vec![1, 2, 3]);
}

#[test]
fn coalesce_waits_for_the_unit_in_flight() {
    // off: every poll seals what was queued since (3 units); on: the 4 txns behind the busy unit share one
    let (b0, a0, u0) = coalesce_units(0, 8);
    assert_eq!((b0, u0), (3, 3));
    let (b1, a1, u1) = coalesce_units(1, 8);
    assert_eq!((b1, u1), (1, 2));
    assert_eq!(a0, (1..=5).collect::<Vec<_>>());
    assert_eq!(a1, a0, "acks in lsn order");
    // K = 2: one more unit may go out while the first is in flight
    let (b2, _, u2) = coalesce_units(2, 8);
    assert_eq!((b2, u2), (2, 3));
}

#[test]
fn coalesce_seals_a_full_block_without_waiting() {
    // records of ~2 KiB: two of them fill a block (no room for a third), sealed at the poll although a unit is in flight
    let (b, a, u) = coalesce_units(1, 1950);
    assert_eq!(b, 3, "full units do not wait");
    assert_eq!(u, 3);
    assert_eq!(a, (1..=5).collect::<Vec<_>>());
}

#[test]
fn coalesce_waits_while_the_last_block_has_room() {
    // records of ~2.5 KiB: two spill into a second block with room for one more, so the unit keeps collecting; four
    // leave less than a record in their last block (3 blocks): sealed. The rule pads less than one mean record.
    let (b, a, u) = coalesce_units(1, 2500);
    assert_eq!((b, u), (2, 2));
    assert_eq!(a, (1..=5).collect::<Vec<_>>());
}

#[test]
fn coalesce_survives_crash_and_replays_every_acked_txn() {
    // coalesced units replay like any group-committed unit: crash after the acks, remount, all keys back
    let mut env = make_env(
        16,
        256,
        1,
        ShardCfg {
            wal_coalesce: 1,
            ..ShardCfg::default()
        },
    );
    env.sim.jitter_ns = 0;
    let (disk, mut clk, mut s) = fresh(&env, 4);
    for i in 1..=30u64 {
        s.submit(kv_txn(i, &format!("k{i}"), "val")).unwrap();
        if i % 3 == 0 {
            let mut ev = Vec::new();
            s.poll(clk.t, &mut ev);
        }
    }
    let acks = run_acks(&mut s, &mut clk, 30);
    assert_eq!(acks, (1..=30).collect::<Vec<_>>());
    assert!(s.stats.units < 30, "txns grouped: {} units", s.stats.units);
    disk.crash_now();
    let img = disk.crash_image(CrashPolicy::DROP_ALL);
    let (_d, _c, mut s2) = remount(&env, &img, 5);
    let mut out = Vec::new();
    for i in 1..=30u64 {
        out.clear();
        assert!(
            s2.get(format!("k{i}").as_bytes(), &mut out).unwrap(),
            "k{i}"
        );
        assert_eq!(out, b"val");
    }
}

/// Poll until the device queue is empty (bounded).
fn drain_dev(s: &mut Shard<store::dev::SimDev>, clk: &mut SimClock) {
    for _ in 0..100_000 {
        if s.dev().queue_space() == s.dev().queue_depth() {
            return;
        }
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev);
        let h = s.dev().next_deadline();
        clk.idle(h);
    }
    panic!("device queue did not drain");
}

#[test]
fn dev_busy_counts_wall_time_with_commands_in_flight_only() {
    // adr 0474: busy = wall time with >= 1 command in flight (read at the idle/busy edges); idle time is not counted,
    // an open busy period is visible before it closes; completed write bytes are counted
    let env = make_env(4, 64, 1, ShardCfg::default());
    let (_disk, mut clk, mut s) = fresh(&env, 91);
    drain_dev(&mut s, &mut clk);
    let idle0 = s.dev_busy_ns();
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert_eq!(s.dev_busy_ns(), idle0, "idle time is not busy");
    let (c0, w0) = (s.stats.io_completions, s.stats.dev_write_bytes);
    s.submit(kv_txn(1, "obj/busy", "v")).unwrap();
    let mut ev = Vec::new();
    s.poll(clk.t, &mut ev); // the group commit puts the WAL unit on the device
    assert!(s.dev().queue_space() < s.dev().queue_depth());
    std::thread::sleep(std::time::Duration::from_millis(5));
    let open = s.dev_busy_ns() - idle0;
    assert!(open >= 5_000_000, "open busy period visible: {open} ns");
    assert_eq!(run_acks(&mut s, &mut clk, 1), vec![1]);
    drain_dev(&mut s, &mut clk);
    let busy = s.stats.dev_busy_ns - idle0;
    assert!(busy >= 5_000_000, "closed busy period counted: {busy} ns");
    assert!(s.stats.io_completions > c0);
    let wb = s.stats.dev_write_bytes - w0;
    assert!(
        wb >= BLK as u64 && wb % BLK as u64 == 0,
        "WAL unit bytes: {wb}"
    );
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert_eq!(s.dev_busy_ns() - idle0, busy, "no growth while idle");
}

/// D1 (store-durability review): a single tree mutation that misses in `commit` must not leave an empty open unit
/// behind; a following multi-part txn (adr 0028) would seal it as a real `ntxn 0` unit, which replay rejects, and every
/// acked txn after it would be lost (or the mount would fail with `WalLost`/`Corrupt`).
#[test]
fn single_op_miss_then_multi_part_txn_replays() {
    let env = make_env_ext(64, 1024, 1, ShardCfg::default(), 10, 4096);
    let mut r = Rig::new(&env, 91);
    for i in 0..3000u64 {
        r.put(format!("k{i:06}").as_bytes(), &[4u8; 30]);
    }
    // cold cache: the leaf of a single put is not resident
    r.remount_clean();
    assert!(r.shard.state().tree.height() >= 2);
    let mut t = Txn::<Vec<u8>>::new(1);
    t.ops.push(Op::Put(b"k001500".to_vec(), b"lost".to_vec()));
    let lsn = r.shard.next_lsn();
    match r.shard.submit(t) {
        Err((StoreError::Miss, _)) => {}
        other => panic!(
            "single put must miss on a cold cache: {:?}",
            other.map(|_| ())
        ),
    }
    assert_eq!(r.shard.next_lsn(), lsn);
    // the missed txn is dropped (not retried); the queued page reads complete
    for _ in 0..100 {
        r.pump();
    }
    // a multi-part txn: values well beyond one 64 KiB unit
    let ops: Vec<Op> = (0..160u64)
        .map(|i| Op::Put(format!("m{i:04}").into_bytes(), vec![i as u8; 800]))
        .collect();
    let units_before = r.shard.stats.multi_txns;
    r.apply(ops);
    assert_eq!(r.shard.stats.multi_txns, units_before + 1);
    r.put(b"after", b"1");
    r.sync();
    // crash: every acked txn must replay
    let img = r.disk.crash_image(CrashPolicy::DROP_ALL);
    let (_d, mut clk, mut s) = remount(&env, &img, 92);
    let got = dump(&mut s, &mut clk);
    assert_eq!(got.get(b"k001500".as_slice()), Some(&vec![4u8; 30]));
    for i in 0..160u64 {
        assert!(
            got.get(format!("m{i:04}").as_bytes()) == Some(&vec![i as u8; 800]),
            "multi-part txn lost (key m{i:04})"
        );
    }
    assert_eq!(got.get(b"after".as_slice()), Some(&b"1".to_vec()));
}

/// D2 (store-durability review): the acked-lsn witness scan behind the end of the valid log must reach past a
/// multi-part chain sealed before the cut unit's ack. Chain parts are sealed all at once (adr 0028) and may be far
/// longer than the scan budget; the first unit written after the ack lies behind the whole chain.
#[test]
fn lost_acked_unit_before_a_long_chain_is_detected() {
    let env = make_env(
        64,
        1024,
        1,
        ShardCfg {
            auto_ckpt: false,
            replay: store::wal::ReplayCfg {
                scan_blocks: 64,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let (disk, mut clk, mut s) = fresh(&env, 93);
    let tail = {
        let mut dev = disk.queue();
        let mut c = SimClock::default();
        store::layout::read_root(&mut dev, &mut c, &env.dir)
            .unwrap()
            .wal_tail_pos
    };
    // A: its unit is sealed and submitted at once
    s.submit(kv_txn(1, "a", "1")).unwrap();
    // M: a chain of ~100 ring blocks, sealed before A's ack (its headers carry acked_lsn < A)
    let mut m = Txn::<Vec<u8>>::new(2);
    for i in 0..400u64 {
        m.ops.push(Op::Put(
            format!("m{i:04}").into_bytes(),
            vec![i as u8; 1000],
        ));
    }
    s.submit(m).unwrap();
    assert_eq!(s.stats.multi_txns, 1);
    assert_eq!(run_acks(&mut s, &mut clk, 2), vec![1, 2]);
    // B: written after A's ack, beyond the chain
    s.submit(kv_txn(3, "b", "1")).unwrap();
    assert_eq!(run_acks(&mut s, &mut clk, 1), vec![3]);
    // A's unit is lost to media corruption: the mount must not call it a torn tail
    disk.corrupt(env.dir.wal_start + tail, 9, 0x10);
    let img = disk.crash_image(CrashPolicy::PERSIST_ALL);
    let d2 = SimDisk::from_image(&img, env.sim.clone());
    let mut c = SimClock::default();
    match mount(&env, &d2, &mut c) {
        Err(StoreError::WalLost { lsn, acked_lsn, .. }) => {
            assert_eq!(lsn, 1);
            assert!(acked_lsn >= 2, "{acked_lsn}");
        }
        Err(e) => panic!("expected WalLost, got {e:?}"),
        Ok(_) => panic!("acked txns lost silently"),
    }
}

/// W1 (store-durability review): a check mounts through a read-only view (`CowDev`): replay, the post-replay
/// checkpoint and an operator WAL-loss override happen in memory only. The media stays as it was, so a later mount
/// still sees the replay window and still reports the loss.
#[test]
fn read_only_view_mount_changes_nothing_on_the_media() {
    use store::dev::{CowDev, Overlay};
    let env = make_env(
        16,
        128,
        1,
        ShardCfg {
            auto_ckpt: false,
            ..Default::default()
        },
    );
    let (disk, mut clk, mut s) = fresh(&env, 95);
    let tail = {
        let mut dev = disk.queue();
        let mut c = SimClock::default();
        store::layout::read_root(&mut dev, &mut c, &env.dir)
            .unwrap()
            .wal_tail_pos
    };
    for i in 1..=3u64 {
        s.submit(kv_txn(i, &format!("k{i}"), "v")).unwrap();
        assert_eq!(run_acks(&mut s, &mut clk, 1), vec![i]);
    }
    drop(s);
    let ro_mount = |img: &store::dev::SimImage, accept_loss: bool| {
        let d = SimDisk::from_image(img, env.sim.clone());
        let over = Overlay::default();
        let mut c = SimClock::default();
        let mut q = CowDev::new(d.queue(), over.clone());
        let (sb, dirs) = store::layout::read_super(&mut q, &mut c).unwrap();
        let mut cfg = env.scfg.clone();
        cfg.replay.accept_loss = accept_loss;
        let r = Shard::mount(
            CowDev::new(d.queue(), over.clone()),
            &mut c,
            &sb,
            &dirs[0],
            cfg,
            false,
        )
        .map(|(mut sh, st)| (sh.dump_blocking(&mut c).unwrap(), st));
        assert!(
            !over.borrow().is_empty() || r.is_err(),
            "the mount wrote nothing at all?"
        );
        (r, d.stats().writes, d.image())
    };
    // replay pending: the view replays and checkpoints in memory; the media is untouched
    let img = disk.crash_image(CrashPolicy::PERSIST_ALL);
    let (r, writes, _) = ro_mount(&img, false);
    let (kv, st) = r.unwrap();
    assert_eq!((kv.len(), st.txns, writes), (3, 3, 0));
    // lost acked unit: refused; with the override the cut is visible in the view, but never committed
    disk.corrupt(env.dir.wal_start + tail, 9, 0x10);
    let img = disk.crash_image(CrashPolicy::PERSIST_ALL);
    assert!(matches!(
        ro_mount(&img, false).0,
        Err(StoreError::WalLost { .. })
    ));
    let (r, writes, img2) = ro_mount(&img, true);
    let (kv, st) = r.unwrap();
    assert_eq!((kv.len(), writes), (0, 0));
    assert!(st.lost.is_some());
    let d = SimDisk::from_image(&img2, env.sim.clone());
    let mut c = SimClock::default();
    assert!(matches!(
        mount(&env, &d, &mut c),
        Err(StoreError::WalLost { .. })
    ));
}

/// A mount that replayed persists its new epoch before anything else lands (`wal.rs` epoch rule): units the mount's
/// checkpoint seals (merges, relogs) belong to an epoch the root already carries, so a crash inside that checkpoint
/// cannot let the next mount reuse the epoch. Crash at every event of the mount: once any write landed, the root on
/// the media has the bumped epoch, and the store remounts with every acked txn.
#[test]
fn replaying_mount_persists_its_epoch_before_any_other_write() {
    let env = make_env(
        16,
        128,
        1,
        ShardCfg {
            auto_ckpt: false,
            ..Default::default()
        },
    );
    let (disk, mut clk, mut s) = fresh(&env, 96);
    for i in 1..=3u64 {
        s.submit(kv_txn(i, &format!("k{i}"), "v")).unwrap();
        assert_eq!(run_acks(&mut s, &mut clk, 1), vec![i]);
    }
    drop(s);
    let img = disk.image();
    let root = |img: &store::dev::SimImage| {
        let d = SimDisk::from_image(img, env.sim.clone());
        store::layout::read_root(&mut d.queue(), &mut SimClock::default(), &env.dir).unwrap()
    };
    let e0 = root(&img).epoch;
    let mut k = 1;
    loop {
        let d = SimDisk::from_image(&img, env.sim.clone());
        d.arm_crash(k);
        let mut c = SimClock::default();
        let r = mount(&env, &d, &mut c);
        if !d.crashed() {
            assert!(r.is_ok());
            break;
        }
        let cut = d.image();
        if d.stats().writes > 0 {
            assert!(
                root(&cut).epoch > e0,
                "crash at event {k}: a write landed before the new epoch"
            );
        }
        let (_d2, mut c2, mut s2) = remount(&env, &cut, 97);
        let all = s2.dump_blocking(&mut c2).unwrap();
        for i in 1..=3u64 {
            assert_eq!(
                all.get(format!("k{i}").as_bytes()).map(Vec::as_slice),
                Some(&b"v"[..]),
                "crash at event {k}: k{i}"
            );
        }
        k += 1;
    }
}

// -------------------------------------------------- read-only WAL inspection (croit-flashstore-tool wal-inspect)

/// Run [`store::wal::inspect`] over an image's single shard and prove it read-only: no write reached the device and
/// the image is byte-for-byte unchanged.
fn inspect_img(env: &Env, img: &store::dev::SimImage) -> store::wal::WalInspect {
    let disk = SimDisk::from_image(img, env.sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let (sb, dirs) = store::layout::read_super(&mut dev, &mut clk).unwrap();
    let d = &dirs[0];
    let root = store::layout::read_root(&mut dev, &mut clk, d).unwrap();
    let store_id = store::layout::wal_store_id(&sb, d.shard);
    let rep = {
        let mut io = Sio::new(&mut dev, &mut clk);
        store::wal::inspect(
            &mut io,
            d,
            &root,
            store_id,
            &store::wal::ReplayCfg::default(),
        )
        .unwrap()
    };
    drop(dev);
    assert_eq!(disk.stats().writes, 0, "wal inspect wrote to the device");
    let after = disk.image();
    assert_eq!(after.lba_count, img.lba_count);
    for lba in 0..img.lba_count {
        assert_eq!(
            after.read_lba(lba),
            img.read_lba(lba),
            "wal inspect changed lba {lba}"
        );
    }
    rep
}

fn unit_lsns(rep: &store::wal::WalInspect) -> Vec<u64> {
    rep.units
        .iter()
        .filter(|u| u.validity == store::wal::UnitValidity::Ok)
        .flat_map(|u| u.records.iter().map(|r| r.lsn))
        .collect()
}

/// The preview matches a real `--accept-wal-loss` mount of the same image: the loss range it reports, the cut, the
/// records it keeps (present after the mount) and the records it lists as dropped (absent after the mount).
fn assert_preview_matches_accept_loss(
    env: &Env,
    img: &store::dev::SimImage,
    rep: &store::wal::WalInspect,
) {
    let mut env2 = env.clone();
    env2.scfg.replay.accept_loss = true;
    let disk = SimDisk::from_image(img, env.sim.clone());
    let mut clk = SimClock::default();
    let (mut s, st) = mount(&env2, &disk, &mut clk).unwrap();
    let wal_lost = rep.stop.reason == store::wal::StopReason::WalLost;
    assert_eq!(
        st.lost,
        wal_lost.then(|| (rep.stop.lsn, rep.stop.acked_lsn.unwrap())),
        "{:?}",
        rep.stop
    );
    assert_eq!(s.state().lsn, rep.stop.lsn - 1, "the cut");
    let kv = s.dump_blocking(&mut clk).unwrap();
    for r in rep.units.iter().flat_map(|u| &u.records) {
        assert!(r.lsn < rep.stop.lsn);
        assert!(
            kv.contains_key(&r.ops[0].key),
            "kept txn {} missing after the mount",
            r.lsn
        );
    }
    for r in &rep.dropped {
        assert!(r.lsn >= rep.stop.lsn);
        assert!(
            !kv.contains_key(&r.ops[0].key),
            "dropped txn {} present after the mount",
            r.lsn
        );
    }
}

/// A fresh store with acked (but not checkpointed) txns decodes every record and drops nothing.
#[test]
fn wal_inspect_clean_store_drops_nothing() {
    let env = make_env(16, 128, 1, no_ckpt());
    let (disk, mut clk, mut s) = fresh(&env, 200);
    for i in 1..=3u64 {
        s.submit(kv_txn(i, &format!("k{i}"), "v")).unwrap();
        assert_eq!(run_acks(&mut s, &mut clk, 1), vec![i]);
    }
    drop(s);
    let img = disk.image();
    let rep = inspect_img(&env, &img);
    assert!(rep.dropped.is_empty(), "clean store must drop nothing");
    assert_ne!(rep.stop.reason, store::wal::StopReason::WalLost);
    assert_eq!(unit_lsns(&rep), vec![1, 2, 3]);
    assert_eq!(rep.stop.lsn, 4);
    assert_preview_matches_accept_loss(&env, &img, &rep);
}

/// A torn tail (a unit whose payload crc does not verify) is reported as `torn` and drops nothing.
#[test]
fn wal_inspect_reports_a_torn_tail() {
    let env = make_env(16, 128, 1, no_ckpt());
    let (disk, mut clk, mut s) = fresh(&env, 201);
    let epoch = s.epoch();
    s.submit(kv_txn(1, "a", "1")).unwrap();
    assert_eq!(run_acks(&mut s, &mut clk, 1), vec![1]);
    let img0 = disk.crash_image(CrashPolicy::PERSIST_ALL);
    let c1 = header_crc_at(&img0, &env, 0);
    let rec = Record {
        lsn: 2,
        ops: vec![Op::Put(b"torn".to_vec(), b"v".to_vec())],
        ..Default::default()
    };
    let mut e = Enc::new();
    encode_record(&rec, &mut e);
    let mut img = img0;
    // a unit with the right chain but a payload crc that does not verify: replay ends here
    forge_raw(
        &mut img,
        &env,
        1,
        epoch,
        2,
        c1,
        0,
        &e.b,
        Some(crc(&e.b) ^ 1),
    );
    let rep = inspect_img(&env, &img);
    assert_eq!(rep.stop.reason, store::wal::StopReason::Torn);
    assert_eq!((rep.stop.pos, rep.stop.lsn), (1, 2));
    assert!(rep.dropped.is_empty(), "a torn tail is not data loss");
    assert_eq!(unit_lsns(&rep), vec![1]);
    assert_eq!(
        rep.units.last().unwrap().validity,
        store::wal::UnitValidity::Torn
    );
    assert_preview_matches_accept_loss(&env, &img, &rep);
}

/// A data crc mismatch in the last unit (no later witness) is a torn tail: replay drops the unit, nothing acked lost.
#[test]
fn wal_inspect_data_crc_tail_is_not_loss() {
    let env = make_env(16, 128, 1, no_ckpt());
    let (disk, _clk, blks) = acked_chain(&env, 204, 5, true);
    disk.corrupt(blks[4], 100, 0x01);
    let img = disk.image();
    let rep = inspect_img(&env, &img);
    assert_eq!(rep.stop.reason, store::wal::StopReason::DataCrc);
    assert_eq!((rep.stop.lsn, rep.stop.blk), (5, Some(blks[4])));
    assert!(rep.dropped.is_empty());
    assert_eq!(unit_lsns(&rep), vec![1, 2, 3, 4]);
    assert_preview_matches_accept_loss(&env, &img, &rep);
}

/// A corrupt middle unit turns the cut into a `WalLost`: the preview lists the decodable dropped txns behind the cut,
/// and they are exactly what a real `--accept-wal-loss` mount drops.
#[test]
fn wal_inspect_preview_lists_the_dropped_txns() {
    let env = make_env(16, 128, 1, no_ckpt());
    let (disk, _clk, _) = acked_chain(&env, 202, 4, false);
    let tail = tail_pos(&env, &disk);
    disk.corrupt(env.dir.wal_start + tail + 1, 9, 0x10); // the middle unit (txn 2)
    let img = disk.image();
    let rep = inspect_img(&env, &img);
    assert_eq!(rep.stop.reason, store::wal::StopReason::WalLost);
    assert_eq!((rep.stop.pos, rep.stop.lsn), (tail + 1, 2));
    assert_eq!(rep.stop.acked_lsn, Some(3));
    let dropped: Vec<(u64, String)> = rep
        .dropped
        .iter()
        .map(|r| (r.lsn, String::from_utf8_lossy(&r.ops[0].key).into_owned()))
        .collect();
    // the corrupt unit (lsn 2) is unreadable; the valid units behind it list the lost txns 3 and 4
    assert_eq!(dropped, vec![(3, "k03".into()), (4, "k04".into())]);
    assert_preview_matches_accept_loss(&env, &img, &rep);
}

/// Bad data in a non-tail unit with a later witness: `WalLost` from the data unit on; its own records decode (the
/// header and payload are intact), so the preview lists them too.
#[test]
fn wal_inspect_preview_data_crc_loss_matches_accept_loss() {
    let env = make_env(16, 128, 1, no_ckpt());
    let (disk, _clk, blks) = acked_chain(&env, 203, 5, true);
    disk.corrupt(blks[1], 100, 0x01); // data of txn 2
    let img = disk.image();
    let rep = inspect_img(&env, &img);
    assert_eq!(rep.stop.reason, store::wal::StopReason::WalLost);
    assert_eq!((rep.stop.lsn, rep.stop.acked_lsn), (2, Some(4)));
    assert_eq!(rep.stop.blk, Some(blks[1]));
    assert_eq!(
        rep.dropped.iter().map(|r| r.lsn).collect::<Vec<_>>(),
        vec![2, 3, 4, 5]
    );
    assert_preview_matches_accept_loss(&env, &img, &rep);
}

/// A multi-part chain behind the cut: the witness scan steps over its parts free of charge and the preview assembles
/// the chain into its one record (lsn 2), next to the txn written after it (lsn 3); both are what the cut drops.
#[test]
fn wal_inspect_preview_assembles_a_multi_part_chain() {
    let env = make_env(
        64,
        1024,
        1,
        ShardCfg {
            auto_ckpt: false,
            replay: store::wal::ReplayCfg {
                scan_blocks: 64,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let (disk, mut clk, mut s) = fresh(&env, 205);
    let tail = tail_pos(&env, &disk);
    s.submit(kv_txn(1, "a", "1")).unwrap();
    let mut m = Txn::<Vec<u8>>::new(2);
    for i in 0..400u64 {
        m.ops.push(Op::Put(
            format!("m{i:04}").into_bytes(),
            vec![i as u8; 1000],
        ));
    }
    s.submit(m).unwrap();
    assert_eq!(s.stats.multi_txns, 1);
    assert_eq!(run_acks(&mut s, &mut clk, 2), vec![1, 2]);
    s.submit(kv_txn(3, "b", "1")).unwrap();
    assert_eq!(run_acks(&mut s, &mut clk, 1), vec![3]);
    disk.corrupt(env.dir.wal_start + tail, 9, 0x10); // A's unit
    let img = disk.crash_image(CrashPolicy::PERSIST_ALL);
    let rep = inspect_img(&env, &img);
    assert_eq!(rep.stop.reason, store::wal::StopReason::WalLost);
    assert_eq!(rep.stop.lsn, 1);
    let dropped: Vec<(u64, usize)> = rep.dropped.iter().map(|r| (r.lsn, r.ops.len())).collect();
    assert_eq!(dropped, vec![(2, 400), (3, 1)]);
    assert_preview_matches_accept_loss(&env, &img, &rep);
}

/// A wrapped ring (PAD units, released space, mixed data txns): the inspection walks the same chain replay applies.
#[test]
fn wal_inspect_wrapped_ring_matches_replay() {
    let cfg = ShardCfg {
        max_unit_blocks: 4,
        ckpt_wal_pct: 60,
        ..Default::default()
    };
    let env = make_env(64, 64, 1, cfg);
    let mut h = Harness::new(&env, 77);
    let mut pads = 0;
    for seed in 77..90 {
        h = Harness::new(&env, seed);
        assert!(h.run(1500, 5));
        pads += h.shard.stats.pads;
        if pads > 0 {
            break;
        }
    }
    assert!(pads > 0, "ring never wrapped with a PAD");
    let img = h.disk.crash_image(CrashPolicy::PERSIST_ALL);
    let rep = inspect_img(&env, &img);
    assert!(
        matches!(
            rep.stop.reason,
            store::wal::StopReason::End
                | store::wal::StopReason::Foreign
                | store::wal::StopReason::Torn
        ),
        "{:?}",
        rep.stop
    );
    let (_s, st) = mount_img(&env, &img, 1).unwrap();
    assert_eq!(rep.stop.lsn, st.last_lsn + 1);
    let ckpt = st.last_lsn - st.txns;
    let replayed = unit_lsns(&rep).into_iter().filter(|&l| l > ckpt).count() as u64;
    assert_eq!(replayed, st.txns);
}

/// Zero batch limits used to spin forever without issuing IO, even on an empty WAL.
/// Run the API calls in a child so the fail-before case has a bounded lifetime.
#[test]
fn zero_replay_batch_limits_are_rejected() {
    const CHILD: &str = "FLASHSTORE_TEST_ZERO_REPLAY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "zero_replay_batch_limits_are_rejected",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        let limit = std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "replay child failed: {status}");
                return;
            }
            if start.elapsed() >= limit {
                eprintln!(
                    "WARNING TIMEOUT zero replay batch regression exceeded 10s (child PID {})",
                    child.id()
                );
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("zero batch limits must be rejected, never hang replay");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    for units_zero in [true, false] {
        let mut env = make_env(16, 128, 1, ShardCfg::default());
        if units_zero {
            env.scfg.replay.batch_units = 0;
        } else {
            env.scfg.replay.batch_data_blocks = 0;
        }
        let disk = SimDisk::from_image(&env.img, env.sim.clone());
        let mut clk = SimClock::default();
        assert!(matches!(
            mount(&env, &disk, &mut clk),
            Err(StoreError::Invalid(_))
        ));
        let mut dev = disk.queue();
        let root = store::layout::read_root(&mut dev, &mut clk, &env.dir).unwrap();
        let mut io = Sio::new(&mut dev, &mut clk);
        assert!(matches!(
            store::wal::inspect(&mut io, &env.dir, &root, 0, &env.scfg.replay),
            Err(StoreError::Invalid(_))
        ));
    }
}

/// A CRC-valid root must not let mount treat live tree pages as free metadata.
#[test]
fn checkpoint_tree_without_bitmap_is_refused_before_mount_writes() {
    for elastic in [false, true] {
        let env = make_env_full(32, 128, 1, ShardCfg::default(), 6, 8192, elastic, 0);
        let mut rig = Rig::new(&env, 1);
        rig.put(b"key", b"durable value");
        rig.checkpoint();
        let disk = rig.disk.clone();
        drop(rig);
        let mut clk = SimClock::default();
        let mut dev = disk.queue();
        let mut root = store::layout::read_root(&mut dev, &mut clk, &env.dir).unwrap();
        assert_ne!(root.tree_root, 0);
        assert_ne!(root.meta_pages_used, 0);
        root.meta_bitmap_len = 0;
        // Keep the root's checksum valid: exercise structural validation, not CRC rejection.
        let slot = newest_root_blk(&env.dir, &disk.image());
        Sio::new(&mut dev, &mut clk)
            .write_one(slot, &root.encode())
            .unwrap();
        assert!(store::fsck::fsck(&mut dev, &mut clk, None).is_err());
        let writes = disk.stats().writes;
        for repair_counters in [false, true] {
            for read_only in [true, false] {
                let cfg = ShardCfg {
                    repair_counters,
                    ..env.scfg.clone()
                };
                assert!(
                    matches!(
                        Shard::mount(disk.queue(), &mut clk, &env.sb, &env.dir, cfg, read_only),
                        Err(StoreError::Corrupt(_))
                    ),
                    "tree without bitmap must never mount"
                );
            }
        }
        assert_eq!(disk.stats().writes, writes);
    }
}
