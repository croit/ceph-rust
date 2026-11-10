// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Device admission window at the shard level (adr 0643-device-admission-fifo): two shards of one simulated device.
use super::*;
use crate::dev::SimDev;
use crate::dev::{Clock, SimClock, SimConfig, SimDisk};
use crate::layout::{MkfsParams, mkfs};

const KIB: u64 = 1024;

/// Two mounted shards of one device; `win` > 0 starts the device window at that many bytes (else the mounts start it at
/// its upper bound).
fn two(
    win: u64,
) -> (
    SimClock,
    Vec<Shard<SimDev>>,
    std::sync::Arc<crate::devidle::DevIdle>,
) {
    let mut sim = SimConfig::new(256 << 20);
    sim.jitter_ns = 0;
    let disk = SimDisk::new(sim);
    let mut clk = SimClock::default();
    let params = MkfsParams {
        shards: 2,
        wal_blocks: 2048,
        align_blocks: 1,
        cell_pages: 128,
        ..Default::default()
    };
    let (sb, dirs) = mkfs(&mut disk.queue(), &mut clk, &params).unwrap();
    let dev_idle = std::sync::Arc::new(crate::devidle::DevIdle::default());
    assert!(dev_idle.init(2));
    if win > 0 {
        dev_idle.admit.start(win);
    }
    let cfg = ShardCfg {
        ckpt_interval_ns: u64::MAX,
        dev_idle: Some(dev_idle.clone()),
        ..ShardCfg::default()
    };
    let sh = dirs
        .iter()
        .map(|d| {
            Shard::mount(disk.queue(), &mut clk, &sb, d, cfg.clone(), false)
                .unwrap()
                .0
        })
        .collect();
    (clk, sh, dev_idle)
}

/// A txn with `kib` KiB of new data in largest-write extents.
fn data_txn(s: &mut Shard<SimDev>, tok: u64, kib: u64) -> Txn<Vec<u8>> {
    let mut t: Txn<Vec<u8>> = Txn::new(tok);
    t.ops
        .push(Op::Put(format!("obj/{tok:08}").into_bytes(), vec![1; 16]));
    let mut left = (kib * KIB) as usize / BLK;
    while left > 0 {
        let n = left.min(s.max_xfer_blk);
        let blk = s.alloc(n as u32).unwrap();
        let buf = s.alloc_buf(n);
        t.data.push((blk, buf));
        left -= n;
    }
    t
}

fn acked(out: &[Event<Vec<u8>>], tok: u64) -> bool {
    out.iter()
        .any(|e| matches!(e, Event::Acked(t) if *t == tok))
}

/// The mounts start the device window at its upper bound (every shard's queue slots above the WAL floor filled with
/// largest writes): a device behaves as without the window until a probe measures a fetch limit.
#[test]
fn the_window_starts_at_the_upper_bound() {
    let (_clk, mut sh, dev_idle) = two(0);
    let xfer = (sh[0].max_xfer_blk * BLK) as u64;
    let depth = sh[0].dev().queue_depth();
    let slots = (depth - wal_floor(sh[0].cfg.max_inflight_units, depth)) as u64;
    assert_eq!(dev_idle.admit.window(), 2 * slots * xfer);
}

/// Shard 0's large txn holds the window; a pre-write of shard 1 would pass its waiting tickets and is refused; shard
/// 1's later txn is admitted (not Busy) and its data waits in arrival order, while its read and its WAL unit go to the
/// device at once and complete without shard 0 being polled. Shard 1's data goes out only after all of shard 0's.
#[test]
fn later_data_waits_in_arrival_order_and_reads_and_wal_bypass_the_window() {
    let (mut clk, mut sh, dev_idle) = two(2 * 256 * KIB);
    let xfer = (sh[0].max_xfer_blk * BLK) as u64;
    let w = dev_idle.admit.window();
    assert_eq!(w, 2 * xfer, "a window started before the mounts is kept");
    let mut out = Vec::new();
    let t0 = data_txn(&mut sh[0], 1, 8 * xfer / KIB);
    sh[0].submit(t0).unwrap();
    assert_eq!(sh[0].adm.inflight, w, "the window's worth went out");
    assert_eq!(sh[0].data_backlog.1, Stop::Window);
    let piece = bytes::Bytes::from(vec![7u8; BLK]);
    assert!(
        sh[1].pre_write(&piece).is_none(),
        "a pre-write passed waiting tickets"
    );
    let t1 = data_txn(&mut sh[1], 2, xfer / KIB);
    sh[1].submit(t1).unwrap();
    assert_eq!(
        (sh[1].data_backlog.0.len(), sh[1].adm.inflight),
        (1, 0),
        "behind shard 0's ticket"
    );
    assert_eq!(sh[1].data_backlog.1, Stop::Window);
    assert_eq!(sh[1].adm.stats.waits, 1);
    // bypass: a read of shard 1 and its WAL unit complete while only shard 1 is polled
    let rb = sh[1].alloc(1).unwrap();
    sh[1].submit_read(rb, 1, 77, false).unwrap();
    sh[1].end_pass();
    let mut read = false;
    for _ in 0..10_000 {
        sh[1].poll(clk.t, &mut out);
        read |= out
            .iter()
            .any(|e| matches!(e, Event::Read { token: 77, .. }));
        let wal = sh[1].pipeline.front().is_some_and(|u| u.wal_done);
        if read && wal {
            break;
        }
        let h = sh[1].dev().next_deadline();
        clk.idle(h);
    }
    assert!(read, "the read waited for the window");
    assert!(
        sh[1]
            .pipeline
            .front()
            .is_some_and(|u| u.wal_done && u.pending_data == 1),
        "the WAL unit waited for the window"
    );
    assert_eq!(sh[1].adm.inflight, 0, "data passed shard 0's ticket");
    // both polled: shard 1's data goes out only once all of shard 0's went out
    for _ in 0..100_000 {
        for s in &mut sh {
            s.poll(clk.t, &mut out);
        }
        if sh[1].adm.inflight > 0 {
            assert!(
                sh[0].data_backlog.0.is_empty(),
                "shard 1 passed shard 0's waiting data"
            );
        }
        if acked(&out, 1) && acked(&out, 2) {
            break;
        }
        let h = sh.iter_mut().filter_map(|s| s.dev().next_deadline()).min();
        clk.idle(h);
    }
    assert!(acked(&out, 1) && acked(&out, 2));
    assert_eq!(dev_idle.admit.outstanding(), 0);
    assert!(sh.iter().all(|s| s.failed.is_none()));
}

/// A pre-write the window refuses never touches the allocator: blocks reserved first and given back would stay a hole
/// behind the next-fit cursor, and a saturated large-write stream (every piece refused) would spread its data over such
/// holes (more bitmap and extent pages per checkpoint later, doc/perf/w4m-p99-20261102.md).
#[test]
fn a_pre_write_the_window_refuses_leaves_no_hole() {
    let (_clk, mut sh, _dev_idle) = two(2 * 256 * KIB);
    let xfer = (sh[0].max_xfer_blk * BLK) as u64;
    let t0 = data_txn(&mut sh[0], 1, 8 * xfer / KIB);
    sh[0].submit(t0).unwrap();
    assert_eq!(sh[0].data_backlog.1, Stop::Window);
    let a = sh[1].alloc(1).unwrap();
    let piece = bytes::Bytes::from(vec![7u8; BLK]);
    assert!(sh[1].pre_write(&piece).is_none());
    assert_eq!(
        sh[1].alloc(1).unwrap(),
        a + 1,
        "the refused pre-write left a hole"
    );
}

/// Uncontended path: a lone txn of one largest write on an idle device takes no ticket and is no probe (its data goes
/// out at once, outside the window); the shard's next txn while it is out takes one; the other shard's txn then goes
/// behind that ticket. All complete, nothing stays counted.
#[test]
fn a_lone_txn_on_an_idle_device_takes_no_ticket() {
    let (mut clk, mut sh, dev_idle) = two(0);
    let xfer = (sh[0].max_xfer_blk * BLK) as u64;
    let w = dev_idle.admit.window();
    let mut out = Vec::new();
    let t = data_txn(&mut sh[0], 1, xfer / KIB);
    sh[0].submit(t).unwrap();
    assert_eq!(
        (sh[0].adm.off, sh[0].adm.inflight, sh[0].adm.stats.free),
        (xfer, 0, 1)
    );
    assert!(sh[0].data_backlog.0.is_empty(), "went out at its commit");
    assert_eq!(dev_idle.admit.outstanding(), 0, "no ticket");
    let t = data_txn(&mut sh[0], 2, xfer / KIB);
    sh[0].submit(t).unwrap();
    assert_eq!(
        (sh[0].adm.inflight, dev_idle.admit.outstanding()),
        (xfer, xfer),
        "the shard's next txn takes a ticket"
    );
    let t = data_txn(&mut sh[1], 3, xfer / KIB);
    sh[1].submit(t).unwrap();
    assert_eq!(
        (sh[1].adm.off, sh[1].adm.inflight),
        (0, xfer),
        "behind an outstanding ticket: in the window"
    );
    for _ in 0..100_000 {
        for s in &mut sh {
            s.poll(clk.t, &mut out);
        }
        if [1, 2, 3].iter().all(|&t| acked(&out, t)) {
            break;
        }
        let h = sh.iter_mut().filter_map(|s| s.dev().next_deadline()).min();
        clk.idle(h);
    }
    assert!([1, 2, 3].iter().all(|&t| acked(&out, t)));
    assert_eq!(
        (sh[0].adm.stats.probes, sh[1].adm.stats.probes),
        (1, 1),
        "the uncontended txn is no probe, the ticketed ones are"
    );
    assert_eq!((sh[0].adm.off, dev_idle.admit.outstanding()), (0, 0));
    assert_eq!(
        dev_idle.admit.window(),
        w,
        "everything ahead completed first: kept"
    );
    assert!(sh.iter().all(|s| s.failed.is_none()));
}

/// Shard 0 takes the head of the stream and is never polled again (its core does not run): shard 1's later txns
/// complete, beside shard 0's bytes, whatever the window does meanwhile. Shard 0 fails later: its bytes come back,
/// its late completions give nothing twice. (Shard 0's first txn takes the uncontended path, its second the head of
/// the stream.)
#[test]
fn a_shard_that_is_not_polled_holds_only_its_own_bytes() {
    let (mut clk, mut sh, dev_idle) = two(8 * 256 * KIB);
    let xfer = (sh[0].max_xfer_blk * BLK) as u64;
    let mut out = Vec::new();
    for tok in [1, 2] {
        let t0 = data_txn(&mut sh[0], tok, xfer / KIB);
        sh[0].submit(t0).unwrap();
    }
    sh[0].end_pass();
    assert_eq!((sh[0].adm.off, sh[0].adm.inflight), (xfer, xfer));
    let (s0, rest) = sh.split_at_mut(1);
    let s1 = &mut rest[0];
    let mut tok = 100;
    let mut wmax = dev_idle.admit.window();
    for _ in 0..40 {
        tok += 1;
        let t = data_txn(s1, tok, xfer / KIB);
        s1.submit(t).unwrap();
        for _ in 0..100_000 {
            s1.poll(clk.t, &mut out);
            wmax = wmax.max(dev_idle.admit.window());
            assert!(
                s1.adm.inflight + xfer <= wmax,
                "{} in flight beside shard 0's {xfer} in a window of at most {wmax}",
                s1.adm.inflight
            );
            if acked(&out, tok) {
                break;
            }
            let h = s1.dev().next_deadline();
            clk.idle(h);
        }
        assert!(acked(&out, tok), "txn {tok} waited for shard 0");
    }
    assert_eq!(dev_idle.admit.outstanding(), xfer, "only shard 0's bytes");
    s0[0].fail(StoreError::Failed);
    assert_eq!(
        dev_idle.admit.outstanding(),
        0,
        "the failed shard's bytes came back"
    );
    for _ in 0..1_000 {
        s0[0].poll(clk.t, &mut out);
        let h = s0[0].dev().next_deadline();
        if h.is_none() {
            break;
        }
        clk.idle(h);
    }
    assert_eq!(dev_idle.admit.outstanding(), 0);
}

/// A failed shard whose data waits for the window gives it back: the other shard's later txn is admitted at once
/// (two largest writes: one would take the uncontended path).
#[test]
fn a_failed_shard_with_waiting_data_frees_the_window() {
    let (mut clk, mut sh, dev_idle) = two(4 * 256 * KIB);
    let xfer = (sh[0].max_xfer_blk * BLK) as u64;
    let mut out = Vec::new();
    let t0 = data_txn(&mut sh[0], 1, 12 * 256);
    sh[0].submit(t0).unwrap();
    assert_eq!(sh[0].data_backlog.1, Stop::Window);
    sh[0].fail(StoreError::Failed);
    let t1 = data_txn(&mut sh[1], 2, 2 * xfer / KIB);
    sh[1].submit(t1).unwrap();
    assert_eq!(sh[1].adm.inflight, 2 * xfer, "admitted at once");
    for _ in 0..100_000 {
        sh[1].poll(clk.t, &mut out);
        if acked(&out, 2) {
            break;
        }
        let h = sh[1].dev().next_deadline();
        clk.idle(h);
    }
    assert!(acked(&out, 2));
    assert_eq!(dev_idle.admit.outstanding(), 0);
}
