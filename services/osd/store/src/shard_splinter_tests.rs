// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
use super::*;
use crate::dev::{CrashPolicy, SimClock, SimConfig, SimDev, SimDisk};
use crate::layout::{MkfsParams, mkfs};
use crate::olsm::wire::OOp;
use std::time::{Duration, Instant};
struct Temp(std::path::PathBuf);

#[test]
fn unselected_splinter_does_not_retain_a_replay_copy() {
    let replay = Some(vec![(
        7,
        OOp::Put {
            id: 19,
            n: 1,
            blob: Bytes::from(vec![1u8, 2, 3, 4]),
        },
    )]);
    assert!(splinter_replay_ops(false, &replay).is_none());
    let Some((_, OOp::Put { blob, .. })) = replay.as_ref().unwrap().first() else {
        panic!("fixture");
    };
    assert!(
        blob.is_unique(),
        "unselected engine must not retain replay payloads"
    );
    let selected = splinter_replay_ops(true, &replay).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].0, 7);
    assert!(
        !blob.is_unique(),
        "selected engine keeps its immutable replay copy"
    );
    drop(selected);
    assert!(blob.is_unique());
    assert!(splinter_replay_ops(true, &None).unwrap().is_empty());
}

impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn fixture() -> (Temp, SimDisk, Superblock, ShardDir, ShardCfg) {
    fixture_with_wal(512)
}
fn fixture_with_wal(wal_blocks: u64) -> (Temp, SimDisk, Superblock, ShardDir, ShardCfg) {
    fixture_with_io(wal_blocks, crate::splinter_omap::IoMode::Direct)
}
fn fixture_with_io(
    wal_blocks: u64,
    io: crate::splinter_omap::IoMode,
) -> (Temp, SimDisk, Superblock, ShardDir, ShardCfg) {
    fixture_with_mode(wal_blocks, io, false)
}
fn fixture_with_mode(
    wal_blocks: u64,
    io: crate::splinter_omap::IoMode,
    no_log: bool,
) -> (Temp, SimDisk, Superblock, ShardDir, ShardCfg) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "shard-splinter-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let disk = SimDisk::new(SimConfig::new(64 << 20));
    let (sb, dirs) = mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
            wal_blocks,
            align_blocks: 1,
            omap_splinterdb: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut cfg = crate::splinter_omap::Config::new(root.clone(), 128 << 20);
    cfg.io = io;
    cfg.allow_non_nvme = true;
    cfg.no_log = no_log;
    crate::splinter_omap::create(&cfg, &sb, 64 << 20).unwrap();
    (
        Temp(root),
        disk,
        sb,
        dirs[0].clone(),
        ShardCfg {
            splinterdb: Some(cfg),
            cache_pages: 32768,
            auto_ckpt: false,
            ..Default::default()
        },
    )
}

#[test]
fn splinter_batches_until_threshold_or_oldest_age_and_does_not_spin_buffered() {
    let (_t, disk, sb, dir, mut cfg) = fixture_with_io(512, crate::splinter_omap::IoMode::Buffered);
    cfg.ckpt_interval_ns = 1000;
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    sh.state.splinter_mem.as_mut().unwrap().active.put(
        0,
        19,
        Bytes::from_static(b"a"),
        Bytes::from_static(b"first"),
    );
    let bytes = sh.state.splinter_mem.as_ref().unwrap().active.bytes();
    sh.ol.as_mut().unwrap().mt_soft = bytes + 1;
    sh.poll(100, &mut Vec::new());
    assert!(sh.state.splinter_mem.as_ref().unwrap().frozen.is_none());
    assert_eq!(sh.splinter.as_ref().unwrap().buffered_since, Some(100));
    assert!(
        sh.quiet(),
        "only an unexpired buffered batch may sleep until the sweep"
    );
    sh.state.splinter_mem.as_mut().unwrap().active.put(
        0,
        19,
        Bytes::from_static(b"b"),
        Bytes::from_static(b"later"),
    );
    sh.ol.as_mut().unwrap().mt_soft = usize::MAX;
    sh.poll(1099, &mut Vec::new());
    assert!(sh.state.splinter_mem.as_ref().unwrap().frozen.is_none());
    assert_eq!(sh.splinter.as_ref().unwrap().buffered_since, Some(100));
    sh.poll(1100, &mut Vec::new());
    assert!(
        sh.state.splinter_mem.as_ref().unwrap().frozen.is_some(),
        "later writes must not postpone age"
    );
    pump(&mut sh, |s, _| s.olsm_flushed());
    sh.state.splinter_mem.as_mut().unwrap().active.put(
        0,
        19,
        Bytes::from_static(b"threshold"),
        Bytes::from_static(b"value"),
    );
    sh.ol.as_mut().unwrap().mt_soft = sh.state.splinter_mem.as_ref().unwrap().active.bytes();
    sh.poll(sh.poll_now + 1, &mut Vec::new());
    assert!(
        sh.state.splinter_mem.as_ref().unwrap().frozen.is_some(),
        "threshold bypasses batch age"
    );
}

#[test]
fn splinter_force_survives_an_inflight_flush_and_clears_after_actual_freeze() {
    let (_t, disk, sb, dir, mut cfg) = fixture_with_io(512, crate::splinter_omap::IoMode::Buffered);
    cfg.ckpt_interval_ns = u64::MAX;
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    sh.state.splinter_mem.as_mut().unwrap().active.put(
        0,
        19,
        Bytes::from_static(b"first"),
        Bytes::new(),
    );
    sh.request_omap_flush();
    sh.splinter_hold_completions(true);
    sh.poll(1, &mut Vec::new());
    assert!(sh.state.splinter_mem.as_ref().unwrap().frozen.is_some());
    sh.state.splinter_mem.as_mut().unwrap().active.put(
        0,
        19,
        Bytes::from_static(b"second"),
        Bytes::new(),
    );
    sh.request_omap_flush();
    sh.poll(2, &mut Vec::new());
    assert!(
        sh.ol.as_ref().unwrap().want_freeze,
        "force remains latched behind frozen work"
    );
    sh.splinter_hold_completions(false);
    pump(&mut sh, |s, _| s.olsm_flushed());
    assert!(!sh.ol.as_ref().unwrap().want_freeze);
    sh.state.splinter_mem.as_mut().unwrap().active.put(
        0,
        19,
        Bytes::from_static(b"third"),
        Bytes::new(),
    );
    sh.poll(sh.poll_now + 1, &mut Vec::new());
    assert!(
        sh.state.splinter_mem.as_ref().unwrap().frozen.is_none(),
        "consumed force must not defeat batching"
    );
    sh.request_checkpoint();
    sh.poll(sh.poll_now + 1, &mut Vec::new());
    assert!(
        sh.state.splinter_mem.as_ref().unwrap().frozen.is_some(),
        "explicit checkpoint forces the pending active batch"
    );
}

#[test]
fn splinter_wal_pressure_forces_a_small_batch_before_its_age() {
    let (_t, disk, sb, dir, mut cfg) = fixture_with_io(512, crate::splinter_omap::IoMode::Buffered);
    cfg.ckpt_interval_ns = u64::MAX;
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    let mut t = Txn::new(81);
    t.ops.push(put(b"pressure", b"native-durable"));
    sh.submit(t).unwrap();
    pump(&mut sh, |_, es| {
        es.iter().any(|e| matches!(e, Event::Acked(81)))
    });
    assert!(!sh.olsm_flushed());
    assert!(sh.state.splinter_mem.as_ref().unwrap().frozen.is_none());
    sh.olsm_ring_pressure();
    sh.poll(sh.poll_now + 1, &mut Vec::new());
    assert!(sh.state.splinter_mem.as_ref().unwrap().frozen.is_some());
    pump(&mut sh, |s, _| s.olsm_flushed());
    assert_eq!(get(&mut sh, b"pressure").unwrap(), b"native-durable"[..]);
}

#[test]
fn splinter_buffered_native_ack_replay_and_publication_preserve_data() {
    let (_t, disk, sb, dir, cfg) = fixture_with_io(512, crate::splinter_omap::IoMode::Buffered);
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg.clone(),
        false,
    )
    .unwrap()
    .0;
    sh.splinter.as_mut().unwrap().hold = true;
    let mut t = Txn::new(9);
    t.ops.push(put(b"buffered", b"native-ack"));
    sh.submit(t).unwrap();
    pump(&mut sh, |_, es| {
        es.iter().any(|e| matches!(e, Event::Acked(9)))
    });
    assert_eq!(sh.splinter.as_ref().unwrap().client.watermark, 0);
    drop(sh);
    let disk = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg.clone(),
        false,
    )
    .unwrap()
    .0;
    assert_eq!(get(&mut sh, b"buffered").unwrap(), b"native-ack"[..]);
    pump(&mut sh, |s, _| s.olsm_flushed());
    let gauges = sh.splinter.as_ref().unwrap().client.read_gauges();
    assert_eq!(gauges[15], 0);
    assert_eq!(gauges[19], 1);
    drop(sh);
    let disk = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    assert_eq!(get(&mut sh, b"buffered").unwrap(), b"native-ack"[..]);
}

#[test]
fn splinter_large_acknowledged_value_remains_readable_after_flush_and_restart() {
    let (_t, disk, sb, dir, cfg) = fixture_with_wal(8192);
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg.clone(),
        false,
    )
    .unwrap()
    .0;
    sh.splinter.as_mut().unwrap().hold = true;
    let value: Vec<u8> = (0usize..9 << 20)
        .map(|i| ((i * 7919) ^ (i >> 11)) as u8)
        .collect();
    let mut t = Txn::new(5);
    t.ops.push(put(b"large", &value));
    sh.submit(t).unwrap();
    pump(&mut sh, |_, e| {
        e.iter().any(|e| matches!(e, Event::Acked(5)))
    });
    assert_eq!(&get(&mut sh, b"large").unwrap()[..], &value);
    sh.splinter.as_mut().unwrap().hold = false;
    pump(&mut sh, |s, _| s.olsm_flushed());
    assert_eq!(&get(&mut sh, b"large").unwrap()[..], &value);
    drop(sh);
    let disk = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    assert_eq!(&get(&mut sh, b"large").unwrap()[..], &value);
}
fn put(k: &[u8], v: &[u8]) -> Op {
    let mut b = Vec::new();
    b.extend_from_slice(&(k.len() as u32).to_le_bytes());
    b.extend_from_slice(k);
    b.extend_from_slice(&(v.len() as u32).to_le_bytes());
    b.extend_from_slice(v);
    Op::Omap(OOp::Put {
        id: 19,
        n: 1,
        blob: Bytes::from(b),
    })
}
fn pump(sh: &mut Shard<SimDev>, mut done: impl FnMut(&Shard<SimDev>, &[Event<Vec<u8>>]) -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    let mut events = Vec::new();
    let mut now = sh.poll_now;
    loop {
        events.clear();
        sh.poll(now, &mut events);
        assert!(
            !events.iter().any(|e| matches!(e, Event::Failed(_))),
            "{events:?}"
        );
        if done(sh, &events) {
            return;
        }
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT SplinterDB native regression exceeded 10s"
        );
        now += 1000000;
        std::thread::yield_now();
    }
}
fn get(sh: &mut Shard<SimDev>, k: &[u8]) -> Option<Bytes> {
    loop {
        match sh.olsm_get(None, 19, k) {
            Err(StoreError::Miss) => pump(sh, |_, es| es.iter().any(|e| matches!(e, Event::Wake))),
            r => return r.unwrap(),
        }
    }
}
#[test]
fn splinter_native_ack_and_redo_without_foreign_materialization() {
    let (_t, disk, sb, dir, cfg) = fixture();
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg.clone(),
        false,
    )
    .unwrap()
    .0;
    sh.splinter.as_mut().unwrap().hold = true;
    let mut tx = Txn::new(41);
    tx.put(b"native", b"durable");
    tx.ops.push(put(b"binary\0", b"value"));
    sh.submit(tx).unwrap();
    pump(&mut sh, |_, es| {
        es.iter().any(|e| matches!(e, Event::Acked(41)))
    });
    assert_eq!(sh.splinter.as_ref().unwrap().client.watermark, 0);
    assert_eq!(get(&mut sh, b"binary\0").unwrap(), b"value"[..]);
    drop(sh);
    let recovered = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut sh = Shard::mount(
        recovered.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg.clone(),
        false,
    )
    .unwrap()
    .0;
    assert_eq!(get(&mut sh, b"binary\0").unwrap(), b"value"[..]);
    let mut native = Vec::new();
    loop {
        match sh.get(b"native", &mut native) {
            Err(StoreError::Miss) => pump(&mut sh, |_, e| !e.is_empty()),
            r => {
                assert!(r.unwrap());
                break;
            }
        }
    }
    assert_eq!(native, b"durable");
    pump(&mut sh, |s, _| s.olsm_flushed());
    let mut tx = Txn::new(42);
    tx.ops.push(Op::Omap(OOp::Range {
        id: 19,
        first: Bytes::new(),
        end: None,
    }));
    tx.ops.push(put(b"new", b"after-clear"));
    sh.submit(tx).unwrap();
    pump(&mut sh, |_, es| {
        es.iter().any(|e| matches!(e, Event::Acked(42)))
    });
    pump(&mut sh, |s, _| s.olsm_flushed());
    drop(sh);
    let image = recovered.crash_image(CrashPolicy::DROP_ALL);
    let disk = SimDisk::from_image(&image, SimConfig::new(64 << 20));
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    assert!(get(&mut sh, b"binary\0").is_none());
    assert_eq!(get(&mut sh, b"new").unwrap(), b"after-clear"[..]);
    assert!(sh.state.olsm.as_ref().unwrap().man.top().is_empty());
}

#[test]
fn splinter_full_capacity_refuses_incoming_record_before_native_acceptance() {
    let (_t, disk, sb, dir, cfg) = fixture();
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    let cap = sh.splinter.as_ref().unwrap().client.capacity();
    sh.splinter.as_ref().unwrap().client.test_logical_used(cap);
    let before = sh.next_lsn;
    let mut t = Txn::new(99);
    t.ops.push(put(b"k", b"value"));
    let (e, _) = sh.submit(t).unwrap_err();
    assert_eq!(e, StoreError::NoSpace);
    assert_eq!(sh.next_lsn, before);
    assert!(sh.state.splinter_mem.as_ref().unwrap().active.is_empty());
    sh.splinter.as_ref().unwrap().client.test_logical_used(0);
}

#[test]
fn splinter_new_watermark_before_native_publication_recovers_prefix() {
    let (_t, disk, sb, dir, cfg) = fixture();
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg.clone(),
        false,
    )
    .unwrap()
    .0;
    sh.splinter.as_mut().unwrap().hold = true;
    let mut t = Txn::new(1);
    t.ops.push(put(b"a", b"committed"));
    let lsn = sh.submit(t).unwrap();
    pump(&mut sh, |_, e| {
        e.iter().any(|e| matches!(e, Event::Acked(1)))
    });
    sh.splinter.as_mut().unwrap().hold = false;
    sh.request_omap_flush();
    sh.splinter_step();
    let end = Instant::now() + Duration::from_secs(10);
    while sh.splinter.as_ref().unwrap().client.flushed.is_none() {
        sh.splinter.as_mut().unwrap().client.poll();
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT SplinterDB publication cut exceeded 10s"
        );
        std::thread::yield_now();
    }
    assert_eq!(sh.state.olsm.as_ref().unwrap().man.flushed_lsn, 0);
    assert_eq!(sh.splinter.as_ref().unwrap().client.watermark, lsn);
    drop(sh);
    let recovered = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut sh = Shard::mount(
        recovered.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    assert_eq!(get(&mut sh, b"a").unwrap(), b"committed"[..]);
    pump(&mut sh, |s, _| s.olsm_flushed());
    assert!(sh.state.olsm.as_ref().unwrap().man.flushed_lsn >= lsn);
}

// The backing filesystem has ample space in these tests. Only the sampled
// per-image headroom is restricted; filesystem leases must not hide a missing
// logical charge for acknowledged but not yet materialized overlays.
fn logical_headroom(sh: &Shard<SimDev>, bytes: u64) {
    let client = &sh.splinter.as_ref().unwrap().client;
    let cap = client.capacity();
    client.test_logical_used(cap - cap / 8 - bytes);
    assert_eq!(client.logical_available(), bytes);
}

fn pending_put(sh: &mut Shard<SimDev>, token: u64, key: &[u8]) {
    let mut t = Txn::new(token);
    t.ops.push(put(key, &[7; 4096]));
    sh.submit(t).unwrap();
    pump(sh, |_, es| {
        es.iter()
            .any(|e| matches!(e, Event::Acked(t) if *t == token))
    });
}

fn assert_pending_refusal(sh: &mut Shard<SimDev>, key: &[u8; 4], headroom: u64) {
    let native = sh.state.olsm.as_ref().unwrap();
    assert!(native.active.is_empty() && native.frozen.is_none());
    let pending = sh.state.splinter_mem.as_ref().unwrap().bytes();
    let before = sh.next_lsn;
    logical_headroom(sh, headroom);
    let mut t = Txn::new(99);
    t.ops.push(put(key, &[8; 4096]));
    // This incoming record alone fits: (4 key + 4096 value + 8 framing +
    // 64 per-point allowance) * 4 = 16688. It must fail only with pending debt.
    assert!(headroom >= 16688);
    let (e, t) = sh.submit(t).unwrap_err();
    assert_eq!(e, StoreError::NoSpace);
    assert_eq!(t.ops.len(), 1, "refusal hands the untouched record back");
    assert_eq!(sh.next_lsn, before);
    assert_eq!(sh.state.splinter_mem.as_ref().unwrap().bytes(), pending);
    assert!(get(sh, key).is_none());
    // Refused attempts must not prevent a subsequent independently admitted
    // retry. Native state/LSN must advance only on that successful submission.
    sh.splinter.as_ref().unwrap().client.test_logical_used(0);
    assert_eq!(sh.submit(t).unwrap(), before);
}

#[test]
fn splinter_capacity_accounts_active_and_frozen_pending_debt() {
    let (_t, disk, sb, dir, mut cfg) = fixture();
    cfg.ckpt_interval_ns = u64::MAX;
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    sh.splinter.as_mut().unwrap().hold = true;
    pending_put(&mut sh, 1, b"held");
    assert_pending_refusal(&mut sh, b"next", 24 << 10);
    pump(&mut sh, |_, es| {
        es.iter().any(|e| matches!(e, Event::Acked(99)))
    });
    sh.state.splinter_mem.as_mut().unwrap().freeze();
    pending_put(&mut sh, 2, b"live");
    let mem = sh.state.splinter_mem.as_ref().unwrap();
    let a = mem.active.bytes() as u64;
    let f = mem.frozen.as_ref().unwrap().bytes() as u64;
    assert!(a > 0 && f > 0);
    // Either buffer on its own plus the incoming record fits exactly or below;
    // only their sum exceeds headroom. Catches dropping either half of debt.
    assert_pending_refusal(&mut sh, b"more", 16688 + 4 * a.max(f));
    sh.splinter.as_mut().unwrap().hold = false;
    sh.request_omap_flush();
    pump(&mut sh, |s, _| s.olsm_flushed());
    assert_eq!(get(&mut sh, b"held").unwrap(), &[7; 4096][..]);
    assert_eq!(get(&mut sh, b"live").unwrap(), &[7; 4096][..]);
    assert_eq!(get(&mut sh, b"next").unwrap(), &[8; 4096][..]);
    assert_eq!(get(&mut sh, b"more").unwrap(), &[8; 4096][..]);
}

#[test]
fn splinter_capacity_accounts_replay_debt_and_allows_zero_growth_progress() {
    let (_t, disk, sb, dir, mut cfg) = fixture();
    cfg.ckpt_interval_ns = u64::MAX;
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg.clone(),
        false,
    )
    .unwrap()
    .0;
    sh.splinter.as_mut().unwrap().hold = true;
    pending_put(&mut sh, 1, b"held");
    assert_eq!(sh.splinter.as_ref().unwrap().client.watermark, 0);
    drop(sh);
    let recovered = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut sh = Shard::mount(
        recovered.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    sh.splinter.as_mut().unwrap().hold = true;
    assert_pending_refusal(&mut sh, b"next", 24 << 10);
    pump(&mut sh, |_, es| {
        es.iter().any(|e| matches!(e, Event::Acked(99)))
    });
    logical_headroom(&sh, 0);
    let mut t = Txn::new(100);
    t.ops.push(Op::Omap(OOp::Range {
        id: 19,
        first: Bytes::new(),
        end: None,
    }));
    sh.submit(t).unwrap();
    pump(&mut sh, |_, es| {
        es.iter().any(|e| matches!(e, Event::Acked(100)))
    });
    // Publication/checkpoint remain possible even with no incoming-growth credit.
    sh.splinter.as_mut().unwrap().hold = false;
    sh.request_omap_flush();
    pump(&mut sh, |s, _| s.olsm_flushed());
    assert!(get(&mut sh, b"held").is_none());
    assert!(get(&mut sh, b"next").is_none());
    assert_eq!(sh.splinter.as_ref().unwrap().client.logical_available(), 0);
}

#[test]
fn splinter_checkpoint_after_checkpoint_covered_recovery_publishes_the_foreign_frontier() {
    let (_t, disk, sb, dir, mut cfg) = fixture_with_io(512, crate::splinter_omap::IoMode::Buffered);
    cfg.ckpt_interval_ns = u64::MAX;
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg.clone(),
        false,
    )
    .unwrap()
    .0;
    sh.splinter.as_mut().unwrap().hold = true;
    let mut t = Txn::new(91);
    t.ops.push(put(b"recovered", b"foreign-durable"));
    let lsn = sh.submit(t).unwrap();
    pump(&mut sh, |_, es| {
        es.iter().any(|e| matches!(e, Event::Acked(91)))
    });
    sh.request_checkpoint();
    pump(&mut sh, |s, _| s.ckpt_lsn() >= lsn);
    sh.splinter.as_mut().unwrap().hold = false;
    sh.request_omap_flush();
    sh.splinter_step();
    let end = Instant::now() + Duration::from_secs(10);
    while sh.splinter.as_ref().unwrap().client.flushed.is_none() {
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT checkpoint-covered publication cut"
        );
        sh.splinter.as_mut().unwrap().client.poll();
        std::thread::yield_now();
    }
    assert_eq!(sh.state.olsm.as_ref().unwrap().man.flushed_lsn, 0);
    drop(sh);
    let recovered = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let store_cfg = crate::obj::StoreCfg { shard: cfg };
    let (mut st, _) =
        crate::obj::Store::mount(|| recovered.queue(), SimClock::default(), store_cfg).unwrap();
    assert!(
        st.shards[0].sh.olsm_flushed(),
        "recovery overlays are already empty"
    );
    assert_eq!(
        st.shards[0].sh.splinter.as_ref().unwrap().client.flushed,
        Some(lsn),
        "publication is still pending at mount"
    );
    st.checkpoint().unwrap();
    let sh = &st.shards[0].sh;
    assert!(sh.splinter_drained());
    assert!(sh.state.olsm.as_ref().unwrap().man.flushed_lsn >= lsn);
    assert!(sh.durable_lsn() >= sh.next_lsn() - 1);
    assert!(sh.ckpt_lsn() >= sh.next_lsn() - 1);
}

#[test]
fn splinter_old_watermark_partial_foreign_effect_is_covered_before_service() {
    let (_t, disk, sb, dir, cfg) = fixture();
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg.clone(),
        false,
    )
    .unwrap()
    .0;
    sh.splinter.as_mut().unwrap().hold = true;
    let mut t = Txn::new(1);
    t.ops.push(put(b"a", b"first"));
    t.ops.push(put(b"b", b"second"));
    sh.submit(t).unwrap();
    pump(&mut sh, |_, e| {
        e.iter().any(|e| matches!(e, Event::Acked(1)))
    });
    drop(sh);
    // A real prefix of the transaction persisted, but watermark remains zero.
    let fcfg = cfg.splinterdb.as_ref().unwrap();
    let mut db =
        splinterdb_lib::Database::open(&fcfg.path(&sb, 0).unwrap(), 64 << 20, 0, false).unwrap();
    let mut k = vec![1];
    k.extend_from_slice(&19u64.to_be_bytes());
    k.push(b'a');
    db.put(&k, b"first").unwrap();
    db.durable_barrier().unwrap();
    db.close().unwrap();
    let recovered = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut sh = Shard::mount(
        recovered.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    // Hold materialization: these reads specifically prove mount's native overlay.
    sh.splinter.as_mut().unwrap().hold = true;
    assert_eq!(get(&mut sh, b"a").unwrap(), b"first"[..]);
    assert_eq!(get(&mut sh, b"b").unwrap(), b"second"[..]);
}

#[test]
fn splinter_pipelined_barrier_publishes_after_durability_and_survives_crash() {
    let (_t, disk, sb, dir, mut cfg) = fixture_with_io(512, crate::splinter_omap::IoMode::Buffered);
    cfg.splinterdb.as_mut().unwrap().pipelined_barrier = true;
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg.clone(),
        false,
    )
    .unwrap()
    .0;
    // Every buffered batch is due at once: many small flushes overlap their
    // durability with the next apply.
    sh.set_splinter_age_for_test(0);
    let key = |round: u64, i: u32| format!("k{round}-{i:03}").into_bytes();
    for round in 0..5u64 {
        let mut t = Txn::new(100 + round);
        for i in 0..64u32 {
            t.ops.push(put(&key(round, i), &round.to_le_bytes()));
        }
        sh.submit(t).unwrap();
        pump(&mut sh, |_, es| {
            es.iter()
                .any(|e| matches!(e, Event::Acked(x) if *x == 100 + round))
        });
    }
    pump(&mut sh, |s, _| {
        s.olsm_flushed() && !s.splinter.as_ref().unwrap().client.busy()
    });
    assert!(sh.splinter.as_ref().unwrap().client.watermark > 0);
    for round in 0..5u64 {
        for i in (0..64u32).step_by(7) {
            assert_eq!(
                get(&mut sh, &key(round, i)).unwrap(),
                round.to_le_bytes()[..]
            );
        }
    }
    drop(sh);
    let disk = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    for round in 0..5u64 {
        for i in 0..64u32 {
            assert_eq!(
                get(&mut sh, &key(round, i)).unwrap(),
                round.to_le_bytes()[..]
            );
        }
    }
}

#[test]
fn splinter_no_log_pipelined_publication_survives_crash_through_native_replay() {
    let (_t, disk, sb, dir, mut cfg) =
        fixture_with_mode(512, crate::splinter_omap::IoMode::Buffered, true);
    cfg.splinterdb.as_mut().unwrap().pipelined_barrier = true;
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg.clone(),
        false,
    )
    .unwrap()
    .0;
    // Every buffered batch is due at once: many small flushes overlap their
    // durability with the next apply.
    sh.set_splinter_age_for_test(0);
    let key = |round: u64, i: u32| format!("k{round}-{i:03}").into_bytes();
    for round in 0..5u64 {
        let mut t = Txn::new(100 + round);
        for i in 0..64u32 {
            t.ops.push(put(&key(round, i), &round.to_le_bytes()));
        }
        sh.submit(t).unwrap();
        pump(&mut sh, |_, es| {
            es.iter()
                .any(|e| matches!(e, Event::Acked(x) if *x == 100 + round))
        });
    }
    pump(&mut sh, |s, _| {
        s.olsm_flushed() && !s.splinter.as_ref().unwrap().client.busy()
    });
    assert!(sh.splinter.as_ref().unwrap().client.watermark > 0);
    for round in 0..5u64 {
        for i in (0..64u32).step_by(7) {
            assert_eq!(
                get(&mut sh, &key(round, i)).unwrap(),
                round.to_le_bytes()[..]
            );
        }
    }
    drop(sh);
    let disk = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut sh = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    )
    .unwrap()
    .0;
    for round in 0..5u64 {
        for i in 0..64u32 {
            assert_eq!(
                get(&mut sh, &key(round, i)).unwrap(),
                round.to_le_bytes()[..]
            );
        }
    }
}
