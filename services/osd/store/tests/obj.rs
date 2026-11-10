// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! L2 object layer: functional tests, model-based property test (multi-shard), crash matrix with object
//! workloads, hobject-order listing, corruption/scrub, ENOSPC, microbenchmarks (ignored).
#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::for_kv_map,
    clippy::collapsible_if
)]
#[path = "common/objmodel.rs"]
mod objmodel;
#[path = "common/shared_ownership.rs"]
mod shared_ownership;

use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use objmodel::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Instant;
use store::dev::{
    BlockDev, Clock, CrashPolicy, DeallocLimits, SimClock, SimConfig, SimDev, SimDisk, SimImage,
};
use store::fsck::fsck;
use store::layout::{MkfsParams, mkfs, read_super};
use store::obj::keys::*;
use store::obj::onode::fsck_refs;
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{DATA_FLOOR_BYTES, OTxn, ObjError, Store, StoreCfg, TOp};
use store::rng::Rng;
use store::shard::ShardCfg;

type St = Store<SimDev, SimClock>;

struct BudgetInput {
    cid: CollT,
    oid: Ghobject,
    bytes: bytes::Bytes,
    builds: std::rc::Rc<std::cell::Cell<usize>>,
}
impl store::obj::QueueBuilder<SimDev, SimClock> for BudgetInput {
    fn build(&mut self, _: &mut St) -> store::obj::Result<Option<OTxn<'_>>> {
        self.builds.set(self.builds.get() + 1);
        let mut t = OTxn::new();
        t.comp = Some(cspec(Alg::Lz4));
        t.write(self.cid, &self.oid, 0, &self.bytes);
        Ok(Some(t))
    }
    fn retained_bytes(&self) -> usize {
        self.bytes.len() + 1024
    }
    fn payload_owners(&self) -> Vec<bytes::Bytes> {
        vec![self.bytes.clone()]
    }
}

#[test]
#[ignore = "local four-shard preparation budget benchmark"]
fn perf_prepare_core_budget() {
    let (max_ns, max_chunks, polls, chunks) = prepare_core_budget_measurement();
    eprintln!(
        "prepare_core_budget max_poll_ns={max_ns} max_compressed_chunks_per_poll={max_chunks} polls={polls} total_chunks={chunks}"
    );
}

#[test]
fn compressed_preparation_has_one_budget_across_four_shards() {
    let (_, max_chunks, polls, chunks) = prepare_core_budget_measurement();
    assert!(
        max_chunks <= 128,
        "each shard must share the core's work allowance: {max_chunks}"
    );
    assert!(polls > 4, "large preparations must return to the driver");
    assert_eq!(chunks, 256, "completed chunks must not be compressed again");
}

#[test]
fn rejected_tail_keeps_the_partial_fifo_head() {
    let mut r = rig(32, 1);
    // Zero allowance: the first poll deterministically stops after one data quantum (partial prefix).
    r.st.set_prep_allowance(Some(std::time::Duration::ZERO));
    let (c, o) = (c1(), g(b"capacity-partial", 2));
    let payload = bytes::Bytes::from(cdata(4 << 20, 8));
    let mut init = OTxn::new();
    init.mkcoll(c);
    init.comp = Some(cspec(Alg::Lz4));
    init.write(c, &o, 0, &payload[..64 << 10]);
    r.st.commit(&init).unwrap();
    r.st.set_queue_limits(1, 16 << 20);
    r.st.queue_builder(
        &[c],
        9904,
        Box::new(BudgetInput {
            cid: c,
            oid: o.clone(),
            bytes: payload.clone(),
            builds: Default::default(),
        }),
        false,
    )
    .unwrap();
    let mut acked = Vec::new();
    r.st.poll(&mut acked).unwrap();
    let reserved = r.st.shards[0].sh.state().alloc.n_reserved();
    assert!(reserved > 0);
    let mut tail = OTxn::new();
    tail.write(c, &o, 0, &[0x33; 4096]);
    assert_eq!(r.st.queue(&tail, 9905), Err(ObjError::WouldBlock));
    assert_eq!(r.st.shards[0].sh.state().alloc.n_reserved(), reserved);
    let (acks, errors) = drive_parked(&mut r.st, 1);
    assert_eq!(acks, [9904]);
    assert!(errors.is_empty());
    assert_eq!(r.st.read(&c, &o, 0, payload.len() as u64).unwrap(), payload);
}

#[test]
fn partial_preparation_crash_keeps_only_the_durable_prefix() {
    let mut r = rig(32, 1);
    // Zero allowance: the first poll deterministically stops after one data quantum (partial prefix).
    r.st.set_prep_allowance(Some(std::time::Duration::ZERO));
    let (c, o) = (c1(), g(b"crash-partial", 2));
    let old = cdata(64 << 10, 1);
    let mut init = OTxn::new();
    init.mkcoll(c);
    init.comp = Some(cspec(Alg::Lz4));
    init.write(c, &o, 0, &old);
    r.st.commit(&init).unwrap();
    r.st.queue_builder(
        &[c],
        9903,
        Box::new(BudgetInput {
            cid: c,
            oid: o.clone(),
            bytes: bytes::Bytes::from(cdata(4 << 20, 7)),
            builds: Default::default(),
        }),
        false,
    )
    .unwrap();
    let mut acked = Vec::new();
    r.st.poll(&mut acked).unwrap();
    assert!(acked.is_empty());
    assert!(r.st.shards[0].sh.state().alloc.n_reserved() > 0);
    for policy in [
        CrashPolicy::DROP_ALL,
        CrashPolicy::MIXED,
        CrashPolicy::PERSIST_ALL,
    ] {
        let image = r.disk.crash_image(policy);
        let (_, mut recovered) = open(&image, &r.sim, &r.cfg);
        assert_eq!(recovered.read(&c, &o, 0, 4 << 20).unwrap(), old);
        assert_eq!(recovered.shards[0].sh.state().alloc.n_reserved(), 0);
        assert!(recovered.check(true).unwrap().errors.is_empty());
    }
}

/// A clock jump of more than the parked deadline in the middle of a partial preparation (the process was stopped): the
/// preparation is progress (it yielded, it was not stuck), so it continues and applies; every reservation ends with it.
#[test]
fn partial_preparation_survives_a_clock_jump_and_releases_every_reservation() {
    let mut r = rig(32, 1);
    // Zero allowance: the first poll deterministically stops after one data quantum (partial prefix).
    r.st.set_prep_allowance(Some(std::time::Duration::ZERO));
    let c = c1();
    let payload = bytes::Bytes::from(cdata(4 << 20, 4));
    let mut init = OTxn::new();
    init.mkcoll(c);
    init.comp = Some(cspec(Alg::Lz4));
    init.write(c, &g(b"timeout-feature", 1), 0, &payload[..64 << 10]);
    r.st.commit(&init).unwrap();
    let o = g(b"timeout-partial", 2);
    r.st.queue_builder(
        &[c],
        9900,
        Box::new(BudgetInput {
            cid: c,
            oid: o.clone(),
            bytes: payload.clone(),
            builds: Default::default(),
        }),
        false,
    )
    .unwrap();
    let mut acked = Vec::new();
    r.st.poll(&mut acked).unwrap();
    assert!(acked.is_empty());
    assert!(
        r.st.shards[0].sh.state().alloc.n_reserved() > 0,
        "fixture must retain a materialized prefix"
    );
    r.st.clk.t += 30_000_000_001;
    let (acked, errors) = drive_parked(&mut r.st, 1);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(acked, [9900]);
    assert_eq!(r.st.shards[0].sh.state().alloc.n_reserved(), 0);
    assert_eq!(
        r.st.stat(&c, &o).unwrap().map(|s| s.size),
        Some(payload.len() as u64)
    );
    r.st.checkpoint().unwrap();
    assert!(r.st.check(true).unwrap().errors.is_empty());
}

#[test]
fn partial_preparation_keeps_the_shard_fifo_and_read_fence() {
    // the tail's block overwrite inside the compressed chunk reads nothing (chunk windows, adr 0059 am. 4): it is
    // submitted after the first write (LSN order), acked and applied after it; a read still waits for durability
    let mut r = rig(32, 1);
    let c = c1();
    let payload = bytes::Bytes::from(cdata(4 << 20, 6));
    let o = g(b"fifo-partial", 2);
    let mut init = OTxn::new();
    init.mkcoll(c);
    init.comp = Some(cspec(Alg::Lz4));
    init.write(c, &o, 0, &payload[..64 << 10]);
    r.st.commit(&init).unwrap();
    r.st.queue_builder(
        &[c],
        9901,
        Box::new(BudgetInput {
            cid: c,
            oid: o.clone(),
            bytes: payload.clone(),
            builds: Default::default(),
        }),
        false,
    )
    .unwrap();
    let mut acked = Vec::new();
    r.st.poll(&mut acked).unwrap();
    assert!(acked.is_empty());
    let mut tail = OTxn::new();
    tail.write(c, &o, 0, &[0xe3; 4096]);
    let q = r.st.queue(&tail, 9902).unwrap();
    assert!(matches!(q, store::obj::Queued::Submitted(_)), "{q:?}");
    let mode = r.st.begin_nonblock();
    assert_eq!(r.st.read(&c, &o, 0, 4096), Err(ObjError::WouldBlock));
    r.st.end_nonblock(mode);
    let (acks, errors) = drive_parked(&mut r.st, 2);
    assert_eq!(acks, [9901, 9902]);
    assert!(errors.is_empty());
    let actual = r.st.read(&c, &o, 0, payload.len() as u64).unwrap();
    assert_eq!(&actual[..4096], &[0xe3; 4096]);
    assert_eq!(&actual[4096..], &payload[4096..]);
}

#[test]
fn compressed_encoding_survives_allocation_backpressure() {
    let cfg = StoreCfg::default();
    let (mut r, _) = rig_with(16, 1, 1024, 881, cfg);
    let (c, old, new) = (c1(), g(b"encoded-old", 1), g(b"encoded-new", 2));
    let mut init = OTxn::new();
    init.mkcoll(c);
    let old_data = vec![0x51; 8 << 20];
    init.write(c, &old, 0, &old_data);
    r.st.commit(&init).unwrap();
    let bytes = cdata(64 << 10, 3);
    let mut warm = OTxn::new();
    warm.comp = Some(cspec(Alg::Lz4));
    warm.write(c, &g(b"codec-warm", 3), 0, &bytes);
    r.st.commit(&warm).unwrap();
    let mut remove = OTxn::new();
    remove.remove(c, &old);
    r.st.queue_blocking(&remove, 1).unwrap();
    assert!(r.st.shards[0].sh.state().alloc.n_held() > 0);
    let mut held = Vec::new();
    for _ in 0..100_000 {
        match r.st.shards[0].sh.alloc_priv(1) {
            Ok(pba) => held.push(pba),
            Err(store::error::StoreError::Busy | store::error::StoreError::NoSpace) => break,
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(!held.is_empty());
    let mut t = OTxn::new();
    t.comp = Some(cspec(Alg::Lz4));
    t.write(c, &new, 0, &bytes);
    let now = r.st.clk.t;
    let before = r.st.shards[0].stats.comp_ns;
    assert_eq!(r.st.queue(&t, 2).unwrap(), store::obj::Queued::Pending(2));
    assert_eq!(r.st.clk.t, now, "allocation stall must not wait for IO");
    let encoded = r.st.shards[0].stats.comp_ns;
    assert!(
        encoded > before,
        "fixture must finish encoding before allocation blocks"
    );
    for pba in held {
        r.st.shards[0].sh.unreserve(pba, 1);
    }
    let (acks, errors) = drive_parked(&mut r.st, 2);
    assert_eq!(acks, [1, 2]);
    assert!(errors.is_empty());
    assert_eq!(
        r.st.shards[0].stats.comp_ns, encoded,
        "retry must reuse the encoded chunk"
    );
    assert_eq!(r.st.shards[0].sh.state().alloc.n_reserved(), 0);
    assert_eq!(r.st.read(&c, &new, 0, bytes.len() as u64).unwrap(), bytes);
    r.st.checkpoint().unwrap();
    assert!(r.st.check(true).unwrap().errors.is_empty());
}

fn prepare_core_budget_measurement() -> (u128, u64, usize, u64) {
    let mut r = rig(128, 4);
    // Production allowance (SimClock defaults to step bounds only).
    r.st.set_prep_allowance(Some(std::time::Duration::from_micros(100)));
    let payload = bytes::Bytes::from(cdata(4 << 20, 2));
    for shard in 0..4 {
        let cid = pgc(1, shard);
        let mut init = OTxn::new();
        init.mkcoll(cid);
        init.comp = Some(cspec(Alg::Lz4));
        init.write(cid, &g(b"feature-warm", 1), 0, &payload[..64 << 10]);
        r.st.commit(&init).unwrap();
    }
    let before: u64 = r.st.shards.iter().map(|s| s.stats.comp_ok).sum();
    let baseline: Vec<_> = r.st.shards.iter().map(|s| s.stats.comp_ok).collect();
    let builds: Vec<_> = (0..4)
        .map(|_| std::rc::Rc::new(std::cell::Cell::new(0)))
        .collect();
    for shard in 0..4 {
        let cid = pgc(1, shard);
        r.st.queue_builder(
            &[cid],
            9000 + shard as u64,
            Box::new(BudgetInput {
                cid,
                oid: g(b"budget-large", 2),
                bytes: payload.clone(),
                builds: builds[shard as usize].clone(),
            }),
            false,
        )
        .unwrap();
    }
    let (mut max_ns, mut max_chunks, mut polls) = (0, 0, 0);
    let (mut acked, mut errors) = (Vec::new(), Vec::new());
    let deadline = Instant::now() + std::time::Duration::from_secs(60);
    for _ in 0..100_000 {
        let was: u64 = r.st.shards.iter().map(|s| s.stats.comp_ok).sum();
        let start = Instant::now();
        r.st.poll(&mut acked).unwrap();
        max_ns = max_ns.max(start.elapsed().as_nanos());
        let now: u64 = r.st.shards.iter().map(|s| s.stats.comp_ok).sum();
        max_chunks = max_chunks.max(now - was);
        polls += 1;
        if polls == 4 {
            assert!(
                r.st.shards
                    .iter()
                    .zip(&baseline)
                    .all(|(s, b)| s.stats.comp_ok > *b),
                "round robin must advance every shard before repeatedly serving one"
            );
        }
        r.st.take_queue_errors(&mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        if acked.len() == 4 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "WARNING TIMEOUT preparation exceeded 60s (compressed-window fixture)"
        );
        r.st.idle();
    }
    acked.sort_unstable();
    assert_eq!(acked, [9000, 9001, 9002, 9003]);
    assert!(
        builds.iter().all(|b| b.get() == 1),
        "translation must be retained after it succeeds"
    );
    let total: u64 = r.st.shards.iter().map(|s| s.stats.comp_ok).sum();
    for shard in 0..4 {
        assert_eq!(
            r.st.read(
                &pgc(1, shard),
                &g(b"budget-large", 2),
                0,
                payload.len() as u64
            )
            .unwrap(),
            payload.as_ref()
        );
    }
    (max_ns, max_chunks, polls, total - before)
}

#[test]
#[ignore = "local late preparation miss benchmark"]
fn perf_prepare_late_miss() {
    let (first, total, ns) = prepare_late_miss_measurement();
    eprintln!("prepare_late_miss first_staged={first} total_staged={total} wall_ns={ns}");
}

#[test]
fn preparation_discovers_late_extents_before_materializing_data() {
    let (first, total, _) = prepare_late_miss_measurement();
    assert_eq!(
        first, 0,
        "late extent miss must precede all DMA copies/CRCs"
    );
    assert_eq!(total, 512 << 10, "each physical payload is staged once");
}

fn prepare_late_miss_measurement() -> (u64, u64, u128) {
    let mut r = parked_write_fixture();
    let c = c1();
    let (a, b) = (g(b"obj-1", 1), g(b"obj-500", 500));
    // The middle of b's extent range lies in a different leaf from its onode.
    let mut initial = OTxn::new();
    initial.write(c, &a, 0, &[0x31; 8192]);
    let old_b = vec![0x31; 8 << 20];
    initial.write(c, &b, 0, &old_b);
    r.st.commit(&initial).unwrap();
    r.st.checkpoint().unwrap();
    r.cfg.shard.cache_pages = 16;
    r.cfg.shard.point_cache = 0;
    r.clean_remount();
    for i in 0..1000 {
        r.st.stat(&c, &g(format!("obj-{i}").as_bytes(), i)).unwrap();
        r.st.poll(&mut Vec::new()).unwrap();
        r.st.idle();
    }
    r.st.stat(&c, &a).unwrap();
    r.st.stat(&c, &b).unwrap();
    r.st.read(&c, &a, 0, 4096).unwrap();
    let data = vec![0x73; 256 << 10];
    let mut t = OTxn::new();
    t.write(c, &a, 0, &data);
    t.write(c, &b, 4 << 20, &data);
    let before: u64 = r.st.shards.iter().map(|s| s.stats.staged_data_bytes).sum();
    let started = Instant::now();
    let q = r.st.queue(&t, 9191).unwrap();
    assert_eq!(
        q,
        store::obj::Queued::Pending(9191),
        "fixture must have a cold dependency"
    );
    let first: u64 = r.st.shards.iter().map(|s| s.stats.staged_data_bytes).sum();
    let (acks, errors) = drive_parked(&mut r.st, 1);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(acks, vec![9191]);
    let after: u64 = r.st.shards.iter().map(|s| s.stats.staged_data_bytes).sum();
    let ns = started.elapsed().as_nanos();
    assert_eq!(r.st.read(&c, &a, 0, data.len() as u64).unwrap(), data);
    assert_eq!(r.st.read(&c, &b, 4 << 20, data.len() as u64).unwrap(), data);
    (first - before, after - before, ns)
}

#[test]
#[ignore = "local cold write core-stall measurement"]
fn perf_parked_write_stall() {
    let r = parked_write_fixture();
    let (_, mut old) = open(&r.disk.image(), &r.sim, &r.cfg);
    let (_, mut st) = open(&r.disk.image(), &r.sim, &r.cfg);
    let mut t = OTxn::new();
    t.write(c1(), &g(b"obj-500", 500), 0, &[0x42; 4096]);
    let before = st.clk.t;
    let old_before = old.clk.t;
    old.queue_blocking(&t, 919).unwrap();
    let old_wait = old.clk.t - old_before;
    st.queue(&t, 919).unwrap();
    eprintln!(
        "cold write queue: {} -> {} ns device wait",
        old_wait,
        st.clk.t - before
    );
    assert!(old_wait > 0);
    assert_eq!(st.clk.t, before);
}

fn parked_write_fixture() -> Rig {
    let mut r = rig(64, 2);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.st.commit(&t).unwrap();
    for batch in 0..20 {
        let mut t = OTxn::new();
        for i in batch * 50..(batch + 1) * 50 {
            let name = format!("obj-{i}");
            t.write(c, &g(name.as_bytes(), i), 0, &[0x31; 4096]);
        }
        r.st.commit(&t).unwrap();
    }
    r.st.checkpoint().unwrap();
    r.clean_remount();
    r
}

fn drive_parked(st: &mut St, tokens: usize) -> (Vec<u64>, Vec<(u64, ObjError)>) {
    let mut acked = Vec::new();
    let mut errors = Vec::new();
    let deadline = st.clk.t + 30_000_000_000;
    for _ in 0..100_000 {
        let polled = st.poll(&mut acked);
        let was = errors.len();
        st.take_queue_errors(&mut errors);
        if let Err(e) = polled {
            assert!(
                errors[was..].iter().any(|(_, err)| err == &e),
                "unreported queue error {e:?}"
            );
        }
        if acked.len() + errors.len() == tokens {
            return (acked, errors);
        }
        assert!(st.clk.t < deadline, "queue timed out");
        st.idle();
    }
    panic!("queue failed to progress: {}", st.diag());
}

#[test]
fn parked_write_yields_and_fifo_blocks_reads_until_apply() {
    use store::obj::Queued;
    let mut r = parked_write_fixture();
    let (c, o) = (c1(), g(b"obj-500", 500));
    let si = r.st.shard_of(&c);
    let first = r.st.shards[si].sh.next_lsn();
    let now = r.st.clk.t;
    for (tok, val) in [(1, 0x41), (2, 0x42), (3, 0x43)] {
        let data = [val; 4096];
        let mut t = OTxn::new();
        t.write(c, &o, 0, &data);
        assert_eq!(r.st.queue(&t, tok).unwrap(), Queued::Pending(tok));
        assert_eq!(r.st.clk.t, now, "queue must never wait for IO");
    }
    r.st.set_nonblock_reads(true);
    assert_eq!(r.st.read(&c, &o, 0, 4096), Err(ObjError::WouldBlock));
    assert!(r.st.take_blocked());
    r.st.set_nonblock_reads(false);
    let attempts = r.st.queue_attempts;
    for _ in 0..100 {
        r.st.poll(&mut Vec::new()).unwrap();
    }
    assert_eq!(
        r.st.queue_attempts, attempts,
        "no retries without an IO completion"
    );
    let (acked, errors) = drive_parked(&mut r.st, 3);
    assert_eq!(acked, vec![1, 2, 3]);
    assert!(errors.is_empty());
    assert_eq!(r.st.shards[si].sh.next_lsn(), first + 3);
    assert_eq!(r.st.read(&c, &o, 0, 4096).unwrap(), vec![0x43; 4096]);
    assert_eq!(r.st.shards[si].sh.state().alloc.n_reserved(), 0);
}

/// adr 0021 am. 44: txns parked behind a cold FIFO head get their name-index pages loaded ahead (reads overlap); the
/// FIFO order, the results and the reservations are unchanged, and the queue drains in a fraction of the serial time.
#[test]
fn parked_lookahead_overlaps_name_loads_and_keeps_fifo_order() {
    use store::obj::Queued;
    let run = |lookahead: usize| {
        let mut r = parked_write_fixture();
        r.cfg.shard.park_lookahead = lookahead;
        r.clean_remount();
        let c = c1();
        let si = r.st.shard_of(&c);
        let t0 = r.st.clk.t;
        let n = 64u64;
        for tok in 1..=n {
            // spread over the name index: existing (cold) objects and new names between them
            let i = (tok * 397) % 1000;
            let name = if tok % 2 == 0 {
                format!("obj-{i}")
            } else {
                format!("new-{i}")
            };
            let data = [tok as u8; 4096];
            let mut t = OTxn::new();
            t.write(c, &g(name.as_bytes(), i as u32), 0, &data);
            assert!(matches!(
                r.st.queue(&t, tok).unwrap(),
                Queued::Pending(_) | Queued::Submitted(_)
            ));
        }
        // the FIFO drain time: until every txn left the shard queue
        let mut acked = Vec::new();
        while r.st.queued_count() > 0 {
            r.st.poll(&mut acked).unwrap();
            r.st.idle();
        }
        let drained = r.st.clk.t - t0;
        let (rest, errors) = drive_parked(&mut r.st, n as usize - acked.len());
        acked.extend(rest);
        assert!(errors.is_empty());
        let in_order = acked.windows(2).all(|w| w[0] < w[1]);
        acked.sort_unstable();
        assert_eq!(acked, (1..=n).collect::<Vec<_>>());
        assert!(in_order, "FIFO order changed");
        for tok in 1..=n {
            let i = (tok * 397) % 1000;
            let name = if tok % 2 == 0 {
                format!("obj-{i}")
            } else {
                format!("new-{i}")
            };
            assert_eq!(
                r.st.read(&c, &g(name.as_bytes(), i as u32), 0, 4096)
                    .unwrap(),
                vec![tok as u8; 4096]
            );
        }
        assert_eq!(r.st.shards[si].sh.state().alloc.n_reserved(), 0);
        check_no_leaks(&mut r);
        (drained, r.st.lookahead_loads)
    };
    let (serial, none) = run(0);
    let (ahead, loads) = run(32);
    eprintln!("lookahead: serial {serial} ns, ahead {ahead} ns, {loads} loads");
    assert_eq!(none, 0);
    assert!(loads > 0, "no lookahead load");
    assert!(
        ahead * 2 < serial,
        "lookahead {ahead} ns vs serial {serial} ns"
    );
}

/// adr 0043 am. 8: the warm probes of an op gated behind a parked write say "not ready" without latching the run
/// flag; a stale `blocked` made the next (successful) nonblocking run look refused, and its op waited for a store
/// wake that had already been consumed (hang behind a > 256 KiB write).
#[test]
fn warm_probe_behind_parked_write_latches_no_refusal() {
    use store::obj::Queued;
    let mut r = parked_write_fixture();
    let (c, o) = (c1(), g(b"obj-500", 500));
    let big = vec![0x51; 300 << 10];
    let mut t = OTxn::new();
    t.write(c, &o, 0, &big);
    assert_eq!(r.st.queue(&t, 1).unwrap(), Queued::Pending(1));
    assert!(!r.st.warm(&c, &o, 0, 4096).unwrap(), "parked: not ready");
    assert!(!r.st.warm_data(&c, &o, 0, 4096).unwrap());
    assert!(!r.st.warm_rm(&c, &o).unwrap());
    assert!(!r.st.warm_omap(&c, &o, &[b"k"]).unwrap());
    assert!(!r.st.warm_clone_src(&c, &o, 0, 4096).unwrap());
    assert!(!r.st.take_blocked(), "a probe latched the run refusal");
    assert!(!r.st.take_rm_progress(), "a probe latched run progress");
    let (acked, errors) = drive_parked(&mut r.st, 1);
    assert_eq!((acked, errors.len()), (vec![1], 0));
    assert!(r.st.take_wake(), "the parked write's apply wakes");
    while !r.st.warm(&c, &o, 0, 4096).unwrap() {
        r.st.wait_loads().unwrap();
    }
    r.st.set_nonblock_reads(true);
    let got = r.st.read(&c, &o, 0, 4096);
    r.st.set_nonblock_reads(false);
    if let Ok(got) = got {
        assert!(!r.st.take_blocked(), "a successful run reports no refusal");
        assert_eq!(got, vec![0x51; 4096]);
    }
}

#[test]
fn parked_shard_does_not_delay_another_shards_write() {
    let mut r = parked_write_fixture();
    let a = c1();
    let b = (1..100)
        .map(|seed| pgc(1, seed))
        .find(|c| r.st.shard_of(c) != r.st.shard_of(&a))
        .unwrap();
    let o = g(b"hot", 17);
    let mut t = OTxn::new();
    t.mkcoll(b).write(b, &o, 0, &[1; 4096]);
    r.st.commit(&t).unwrap();
    let mut t = OTxn::new();
    t.write(a, &g(b"obj-500", 500), 0, &[2; 4096]);
    let now = r.st.clk.t;
    assert!(matches!(
        r.st.queue(&t, 1).unwrap(),
        store::obj::Queued::Pending(1)
    ));
    let mut t = OTxn::new();
    t.write(b, &o, 0, &[3; 4096]);
    assert!(matches!(
        r.st.queue(&t, 2).unwrap(),
        store::obj::Queued::Submitted(_)
    ));
    assert_eq!(r.st.clk.t, now);
    let (_, e) = drive_parked(&mut r.st, 2);
    assert!(e.is_empty());
}

#[test]
fn failed_parked_allocation_releases_reservations_and_fifo_continues() {
    let mut r = parked_write_fixture();
    let c = c1();
    let o = g(b"obj-500", 500);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &[0x41; 4096]);
    r.st.queue(&t, 1).unwrap();
    let mut t = OTxn::new();
    let oversized = vec![0x7F; 64 << 20];
    t.write(c, &g(b"too-large", 991), 0, &oversized);
    r.st.queue(&t, 2).unwrap();
    let mut t = OTxn::new();
    t.write(c, &o, 0, &[0x43; 4096]);
    r.st.queue(&t, 3).unwrap();
    let (acked, errors) = drive_parked(&mut r.st, 3);
    assert_eq!(acked, vec![1, 3]);
    assert_eq!(errors, vec![(2, ObjError::NoSpace)]);
    assert_eq!(r.st.read(&c, &o, 0, 4096).unwrap(), vec![0x43; 4096]);
    assert!(r.st.stat(&c, &g(b"too-large", 991)).unwrap().is_none());
    assert_eq!(
        r.st.shards[r.st.shard_of(&c)].sh.state().alloc.n_reserved(),
        0
    );
    r.st.checkpoint().unwrap();
    assert!(r.st.check(true).unwrap().errors.is_empty());
}

#[test]
fn parked_queue_caps_throttle_without_waiting_and_release_on_progress() {
    let mut r = parked_write_fixture();
    r.st.set_queue_limits(2, 1 << 20);
    let (c, o) = (c1(), g(b"obj-500", 500));
    let now = r.st.clk.t;
    for tok in 1..=2 {
        let mut t = OTxn::new();
        t.write(c, &o, 0, &[4; 4096]);
        r.st.queue(&t, tok).unwrap();
    }
    assert!(!r.st.admission_ready());
    let mut t = OTxn::new();
    t.write(c, &o, 0, &[5; 4096]);
    assert_eq!(r.st.queue(&t, 3), Err(ObjError::WouldBlock));
    assert_eq!(r.st.clk.t, now);
    assert_eq!(r.st.queued_count(), 2);
    let (_, e) = drive_parked(&mut r.st, 2);
    assert!(e.is_empty());
    assert!(r.st.admission_ready());
    r.st.queue(&t, 3).unwrap();
    let (a, e) = drive_parked(&mut r.st, 1);
    assert_eq!(a, vec![3]);
    assert!(e.is_empty());
}

#[test]
fn parked_wal_pressure_progresses_in_fifo_without_repeated_staging() {
    let cfg = StoreCfg {
        shard: ShardCfg {
            max_unit_blocks: 8,
            ready_cap: 2,
            ckpt_wal_pct: 100,
            ckpt_interval_ns: u64::MAX / 2,
            dirty_soft_pages: usize::MAX / 2,
            dirty_hard_pages: usize::MAX / 2,
            val_ext_min: 0, // WAL pressure from large tree values (am. 46 would put them in data blocks)
            ..ShardCfg::default()
        },
    };
    let (mut r, _) = rig_with(32, 1, 128, 700, cfg);
    let c = c1();
    let o = g(b"wal-pressure", 3);
    let mut t = OTxn::new();
    t.mkcoll(c).write(c, &o, 0, &[1; 4096]);
    r.st.commit(&t).unwrap();
    let now = r.st.clk.t;
    for token in 1..=100 {
        let mut t = OTxn::new();
        let data = vec![token as u8; 8192];
        t.setattr(c, &o, b"large", &data);
        r.st.queue(&t, token).unwrap();
        assert_eq!(r.st.clk.t, now);
    }
    let attempts = r.st.queue_attempts;
    for _ in 0..100 {
        r.st.poll(&mut Vec::new()).unwrap();
    }
    assert_eq!(r.st.queue_attempts, attempts);
    let (acks, errors) = drive_parked(&mut r.st, 100);
    assert_eq!(acks, (1..=100).collect::<Vec<_>>());
    assert!(errors.is_empty());
    assert!(r.st.shards[0].sh.stats.forced_ckpts > 0);
    assert_eq!(
        r.st.getattr(&c, &o, b"large").unwrap(),
        Some(vec![100; 8192])
    );
}

#[test]
fn parked_allocation_waits_for_checkpoint_and_releases_once() {
    let cfg = StoreCfg::default();
    let (mut r, _) = rig_with(16, 1, 1024, 701, cfg);
    let (c, old, new) = (c1(), g(b"old", 1), g(b"new", 2));
    let data = vec![0x31; 8 << 20];
    let mut t = OTxn::new();
    t.mkcoll(c).write(c, &old, 0, &data);
    r.st.commit(&t).unwrap();
    let mut t = OTxn::new();
    t.remove(c, &old);
    r.st.queue_blocking(&t, 1).unwrap();
    let before = r.st.clk.t;
    let mut t = OTxn::new();
    t.write(c, &new, 0, &data);
    assert_eq!(r.st.queue(&t, 2).unwrap(), store::obj::Queued::Pending(2));
    assert_eq!(r.st.clk.t, before);
    let (a, e) = drive_parked(&mut r.st, 2);
    assert_eq!(a, vec![1, 2]);
    assert!(e.is_empty());
    assert!(r.st.shards[0].sh.stats.forced_ckpts > 0);
    assert_eq!(r.st.shards[0].sh.state().alloc.n_reserved(), 0);
    assert_eq!(r.st.read(&c, &new, 0, data.len() as u64).unwrap(), data);
}

/// A stopped process (SIGSTOP, a paused VM) resumes 30 s later with the IO of its parked write completed: that is
/// progress, not a stuck store. The write applies, no error (fault campaign case b: the OSD exited on SIGCONT).
#[test]
fn parked_write_survives_a_clock_jump_when_its_io_completed() {
    let mut r = parked_write_fixture();
    let mut t = OTxn::new();
    t.write(c1(), &g(b"obj-500", 500), 0, &[0x66; 4096]);
    r.st.queue(&t, 77).unwrap();
    assert_eq!(r.st.queued_count(), 1, "the write parks on its page loads");
    r.st.clk.t += 30_000_000_001;
    let (acked, errors) = drive_parked(&mut r.st, 1);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(acked, [77]);
    assert_eq!(
        r.st.read(&c1(), &g(b"obj-500", 500), 0, 4096).unwrap(),
        vec![0x66; 4096]
    );
}

/// A device that completes nothing for 30 s: the parked write fails loudly (Eio, its token reported), nothing applied
/// or leaked.
#[test]
fn parked_deadline_reports_the_token_without_applying_or_leaking() {
    let mut r = parked_write_fixture();
    // every IO takes 120 s: between two completions the parked write sees more than 30 s without progress
    r.sim.read_ns = 120_000_000_000;
    r.sim.write_ns = 120_000_000_000;
    r.clean_remount();
    let mut t = OTxn::new();
    t.write(c1(), &g(b"obj-500", 500), 0, &[0x66; 4096]);
    r.st.queue(&t, 77).unwrap();
    let mut a = Vec::new();
    // 30 s steps: a step with completions retries the write and restarts its deadline; the first 30 s without any fail it
    let mut failed = false;
    for _ in 0..16 {
        r.st.clk.t += 30_000_000_001;
        match r.st.poll(&mut a) {
            Ok(()) => assert_eq!(r.st.queued_count(), 1, "applied: {a:?}"),
            Err(e) => {
                assert!(matches!(e, ObjError::Eio(_)), "{e:?}");
                failed = true;
                break;
            }
        }
    }
    assert!(failed, "no Eio after 16 steps of 30 s");
    let mut e = Vec::new();
    r.st.take_queue_errors(&mut e);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].0, 77);
    assert!(a.is_empty());
    assert_eq!(r.st.queued_count(), 0);
    assert_eq!(
        r.st.shards[r.st.shard_of(&c1())]
            .sh
            .state()
            .alloc
            .n_reserved(),
        0
    );
    assert_eq!(
        r.st.read(&c1(), &g(b"obj-500", 500), 0, 4096).unwrap(),
        vec![0x31; 4096]
    );
}

/// A translation that never gets ready: its head makes no progress of its own.
struct NeverReady;

impl store::obj::QueueBuilder<SimDev, SimClock> for NeverReady {
    fn build(&mut self, _: &mut St) -> store::obj::Result<Option<OTxn<'_>>> {
        Err(ObjError::WouldBlock)
    }
    fn retained_bytes(&self) -> usize {
        0
    }
}

/// A parked head without progress of its own fails loudly after 30 s although reads of other requests keep completing
/// (every completion retries it): such unrelated progress restarted its deadline on every try, so it never fired.
#[test]
fn parked_head_without_own_progress_fails_despite_unrelated_reads() {
    let mut r = parked_write_fixture();
    let c = c1();
    // the head's collection shares the shard, not the visibility fence of the reads
    let hc = (1..64)
        .map(|ps| pgc(1, ps))
        .find(|h| r.st.shard_of(h) == r.st.shard_of(&c))
        .unwrap();
    let mut t = OTxn::new();
    t.mkcoll(hc);
    r.st.commit(&t).unwrap();
    let mut acked = Vec::new();
    r.st.queue_builder(&[hc], 77, Box::new(NeverReady), true)
        .unwrap();
    r.st.set_nonblock_reads(true);
    let mut failed = None;
    'secs: for i in 0..120u32 {
        // another request reads a cold object: its device IO completes, the head is retried
        let name = format!("obj-{i}");
        loop {
            r.st.read_session(Some((900, u64::from(i))), true);
            let res = r.st.read(&c, &g(name.as_bytes(), i), 0, 4096);
            let blocked = matches!(res, Err(ObjError::WouldBlock));
            r.st.read_session(None, blocked);
            if let Err(e) = r.st.poll(&mut acked) {
                failed = Some((i, e));
                break 'secs;
            }
            match res {
                Ok(d) => {
                    assert_eq!(d, vec![0x31; 4096]);
                    break;
                }
                Err(ObjError::WouldBlock) => r.st.idle(),
                Err(e) => panic!("{e:?}"),
            }
        }
        r.st.clk.t += 1_000_000_000;
    }
    let (i, e) = failed.expect("no error after 120 s");
    assert!(matches!(e, ObjError::Eio(_)), "{e:?}");
    assert!((30..=31).contains(&i), "failed after {i} s");
    let mut errors = Vec::new();
    r.st.take_queue_errors(&mut errors);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].0, 77);
    assert!(acked.is_empty());
    assert_eq!(r.st.queued_count(), 0);
}

#[test]
fn parked_write_crash_matrix_covers_every_workload_io_event() {
    let r = parked_write_fixture();
    let img = r.disk.image();
    // Both preparation schedules (adr 0093): no wall deadline (virtual time default) and a zero allowance (every
    // poll prepares one FIFO head / data quantum: the schedule a loaded host produces under the 100 us deadline).
    let run = |allow: Option<std::time::Duration>, cut: Option<u64>, policy: CrashPolicy| {
        let (disk, mut st) = open(&img, &r.sim, &r.cfg);
        st.set_prep_allowance(allow);
        let start = disk.events();
        if let Some(cut) = cut {
            disk.arm_crash(start + cut);
        }
        let mut acked = Vec::new();
        let mut failed = false;
        for (tok, val) in [(1, 0x41), (2, 0x42), (3, 0x43)] {
            let mut t = OTxn::new();
            let data = [val; 4096];
            t.write(c1(), &g(b"obj-500", 500), 0, &data);
            if st.queue(&t, tok).is_err() {
                failed = true;
                break;
            }
        }
        let deadline = st.clk.t + 30_000_000_000;
        for _ in 0..100_000 {
            if failed || acked.len() == 3 {
                break;
            }
            if st.poll(&mut acked).is_err() {
                break;
            }
            assert!(st.clk.t < deadline);
            st.idle();
        }
        assert!(disk.crashed() || acked.len() == 3);
        let events = disk.events() - start;
        let crashed = disk.crashed();
        disk.crash_now();
        let recovered = disk.crash_image(policy);
        drop(st);
        let (_, mut st) = open(&recovered, &r.sim, &r.cfg);
        let got = st.read(&c1(), &g(b"obj-500", 500), 0, 4096).unwrap();
        let prefix = match got[0] {
            0x31 => 0,
            0x41 => 1,
            0x42 => 2,
            0x43 => 3,
            v => panic!("torn value {v}"),
        };
        assert!(prefix >= acked.len());
        assert!(got.iter().all(|b| *b == got[0]));
        assert!(st.check(true).unwrap().errors.is_empty());
        (events, crashed)
    };
    for allow in [None, Some(std::time::Duration::ZERO)] {
        let (events, _) = run(allow, None, CrashPolicy::MIXED);
        assert!(events > 0);
        // The schedule is deterministic: a repeat issues the same IO sequence.
        assert_eq!(run(allow, None, CrashPolicy::MIXED).0, events, "{allow:?}");
        for cut in 0..events {
            for policy in [
                CrashPolicy::DROP_ALL,
                CrashPolicy::PERSIST_ALL,
                CrashPolicy::MIXED,
            ] {
                assert!(
                    run(allow, Some(cut), policy).1,
                    "uncovered IO event {cut} ({allow:?})"
                );
            }
        }
    }
}

#[test]
fn collection_barrier_drains_the_parked_fifo_first() {
    let mut r = parked_write_fixture();
    let c = c1();
    let o = g(b"obj-500", 500);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &[0x45; 4096]);
    r.st.queue(&t, 1).unwrap();
    let mut barrier = OTxn::new();
    barrier.push(TOp::SetCollBits { cid: c, bits: 1 });
    r.st.queue(&barrier, 2).unwrap();
    assert_eq!(r.st.queued_count(), 0);
    let (a, e) = drive_parked(&mut r.st, 2);
    assert_eq!(a, vec![1, 2]);
    assert!(e.is_empty());
    assert_eq!(r.st.coll_stats(&c).unwrap().unwrap().bits, 1);
}

/// A blocking queue barrier never waits for run room (adr 0476 am. 4): omap batches queued while the runs are full park
/// on run room; a barrier (`sync`) drains them on the tree path instead of waiting for merges, and the content matches.
#[test]
fn a_barrier_does_not_wait_for_run_room() {
    let mut cfg = StoreCfg::default();
    cfg.shard.run_soft_bytes = 16 << 10;
    let (mut r, _) = rig_with(64, 1, 1024, 3, cfg);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.st.commit(&t).unwrap();
    let o = g(b"omap-obj", 7);
    let batch = |b: usize| {
        let mut enc = Vec::new();
        let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..128)
            .map(|i| (format!("k{b:03}.{i:04}").into_bytes(), vec![b as u8; 24]))
            .collect();
        denc::SortedKv::encode_into(
            &mut enc,
            keys.len(),
            keys.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        );
        store::obj::KvRunData::from_encoding(enc.into()).unwrap()
    };
    let n = 40;
    for b in 0..n {
        let mut t = OTxn::new();
        t.push(TOp::OmapSetRun {
            cid: c,
            oid: o.clone(),
            run: batch(b),
        });
        r.st.queue(&t, 100 + b as u64).unwrap();
    }
    let waits = |st: &St| st.shards.iter().map(|s| s.stats.run_waits).sum::<u64>();
    let puts = |st: &St| st.shards.iter().map(|s| s.stats.run_puts).sum::<u64>();
    assert!(r.st.queued_count() > 0, "batches park on run room");
    assert!(
        waits(&r.st) > 0 && puts(&r.st) > 0,
        "runs staged, then run room gone"
    );
    let w0 = waits(&r.st);
    r.st.sync().unwrap();
    assert_eq!(r.st.queued_count(), 0);
    assert_eq!(waits(&r.st), w0, "the barrier never waits for run room");
    for b in [0, n / 2, n - 1] {
        let k = format!("k{b:03}.0127").into_bytes();
        let m = r.st.omap_get(&c, &o, &[k.as_slice()]).unwrap();
        assert_eq!(m.get(&k).map(|v| v.as_slice()), Some(&[b as u8; 24][..]));
    }
}

/// Run room is the device's run pool (adr 0476): the per-core stores of the other cores are members too. A batch parked
/// because the pool was over its hard size is retried as soon as another member releases run memory, not at the next
/// store progress of its own shard (the timed checkpoint, `ckpt_interval_ns` later: the lab's deterministic ~4.9 s
/// populate stall, doc/perf/omap-combo-stall-20261030.md).
#[test]
fn run_room_released_by_another_pool_member_resumes_a_parked_batch() {
    let pool = std::sync::Arc::new(store::runs::RunPool::default());
    let mut cfg = StoreCfg::default();
    cfg.shard.run_soft_bytes = 16 << 10;
    cfg.shard.run_pool = Some(pool.clone());
    let ckpt_ns = cfg.shard.ckpt_interval_ns;
    let (mut r, _) = rig_with(64, 1, 1024, 3, cfg);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.st.commit(&t).unwrap();
    let o = g(b"omap-obj", 7);
    let batch = |b: usize| {
        let mut enc = Vec::new();
        let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..128)
            .map(|i| (format!("k{b:03}.{i:04}").into_bytes(), vec![b as u8; 24]))
            .collect();
        denc::SortedKv::encode_into(
            &mut enc,
            keys.len(),
            keys.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        );
        let mut t = OTxn::new();
        t.push(TOp::OmapSetRun {
            cid: c,
            oid: o.clone(),
            run: store::obj::KvRunData::from_encoding(enc.into()).unwrap(),
        });
        t
    };
    let puts = |st: &St| st.shards[0].stats.run_puts;
    let waits = |st: &St| st.shards[0].stats.run_waits;
    // one run of the object, far below the shard's own soft size (no merge of its own is pressed)
    r.st.commit(&batch(0)).unwrap();
    assert_eq!(puts(&r.st), 1);
    assert!(!r.st.shards[0].sh.state().runs.is_empty());
    // another core's store holds the pool at its hard size
    let mut other = store::runs::PoolShare::join(pool.clone(), 0);
    other.publish(2 * pool.soft());
    assert_eq!(
        r.st.queue(&batch(1), 101).unwrap(),
        store::obj::Queued::Pending(101)
    );
    assert_eq!(waits(&r.st), 1, "the batch waits for run room");
    let mut acked = Vec::new();
    let poll_for = |st: &mut St, acked: &mut Vec<u64>, ns: u64| {
        let end = st.clk.t + ns;
        while st.clk.t < end && !acked.contains(&101) {
            st.poll(acked).unwrap();
            st.clk.t += 100_000;
        }
    };
    poll_for(&mut r.st, &mut acked, 10_000_000);
    assert!(acked.is_empty(), "no run room while the pool is full");
    // the other core's merges release its runs: the parked batch runs now
    other.publish(0);
    let t0 = r.st.clk.t;
    poll_for(&mut r.st, &mut acked, ckpt_ns);
    assert_eq!(acked, [101]);
    assert!(
        r.st.clk.t - t0 < 10_000_000,
        "the parked batch waited {} ms for its shard's own progress",
        (r.st.clk.t - t0) / 1_000_000
    );
    assert_eq!(puts(&r.st), 2, "staged as a run");
    let k = b"k001.0127".to_vec();
    let m = r.st.omap_get(&c, &o, &[k.as_slice()]).unwrap();
    assert_eq!(m.get(&k).map(|v| v.as_slice()), Some(&[1u8; 24][..]));
}

/// A blocking queue barrier re-prepares a head that already parked on run room (adr 0476 am. 4): the barrier does
/// not wait for merges, so the head takes the tree path instead of stopping at the same admission again.
#[test]
fn drain_barrier_reprepares_a_head_parked_on_run_room() {
    let pool = std::sync::Arc::new(store::runs::RunPool::default());
    let mut cfg = StoreCfg::default();
    cfg.shard.run_soft_bytes = 16 << 10;
    cfg.shard.run_pool = Some(pool.clone());
    let (mut r, _) = rig_with(64, 1, 1024, 3, cfg);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let o = g(b"omap-barrier", 7);
    let batch = |b: usize| {
        let mut enc = Vec::new();
        let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..128)
            .map(|i| (format!("k{b:03}.{i:04}").into_bytes(), vec![b as u8; 24]))
            .collect();
        denc::SortedKv::encode_into(
            &mut enc,
            keys.len(),
            keys.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        );
        let mut t = OTxn::new();
        t.push(TOp::OmapSetRun {
            cid: c,
            oid: o.clone(),
            run: store::obj::KvRunData::from_encoding(enc.into()).unwrap(),
        });
        t
    };
    let puts = |st: &St| st.shards[0].stats.run_puts;
    let waits = |st: &St| st.shards[0].stats.run_waits;
    commit(&mut r.st, &batch(0));
    assert_eq!(puts(&r.st), 1);
    // another core's store holds the pool at its hard size: no run room
    let mut other = store::runs::PoolShare::join(pool.clone(), 0);
    other.publish(2 * pool.soft());
    assert_eq!(
        r.st.queue(&batch(1), 101).unwrap(),
        store::obj::Queued::Pending(101)
    );
    let w0 = waits(&r.st);
    let mut acked = Vec::new();
    // retry the parked head once on the admission (it then holds `run_wait`)
    for _ in 0..1000 {
        r.st.poll(&mut acked).unwrap();
        if waits(&r.st) > w0 {
            break;
        }
        r.st.clk.t += 100_000;
    }
    assert!(waits(&r.st) > w0, "the head parked on run room");
    let runs = |st: &St| st.shards[0].sh.state().runs.entries();
    let merges = |st: &St| st.shards[0].sh.stats.run_merges;
    let (runs0, merges0) = (runs(&r.st), merges(&r.st));
    assert!(runs0 > 0 && merges0 == 0, "the run is still unmerged");
    // the blocking barrier must take the tree path, not wait for the run to leave (a merge or the checkpoint)
    r.st.drain_queued().unwrap();
    assert_eq!(r.st.queued_count(), 0);
    assert_eq!(puts(&r.st), 1, "the barrier staged no run");
    assert_eq!(
        (runs(&r.st), merges(&r.st)),
        (runs0, merges0),
        "the barrier waited for run room instead of taking the tree path"
    );
    let k = b"k001.0127".to_vec();
    let m = r.st.omap_get(&c, &o, &[k.as_slice()]).unwrap();
    assert_eq!(m.get(&k).map(|v| v.as_slice()), Some(&[1u8; 24][..]));
}

/// Omap removal batches of at least `run_min` keys are staged as runs of removals (adr 0647-omap-blind-removals D1):
/// the commit reads no omap leaf; reads and listings see the keys gone, also with later ops of the same txn on them (a
/// point put, a put batch before or after, a clone, a range removal, the object's removal); smaller batches and second
/// batches of a txn take the tree path; a power cut, a clean remount and the merge keep the result.
#[test]
fn omap_removal_batches_stage_as_runs() {
    let (mut r, _) = rig_with(64, 1, 1024, 3, StoreCfg::default());
    let c = c1();
    let (o, o2, o3) = (g(b"rm-obj", 7), g(b"rm-clone", 8), g(b"rm-gone", 9));
    let key = |i: u32| format!("k{i:05}").into_bytes();
    let val = |i: u32, gn: u8| vec![gn; 30 + (i % 9) as usize];
    let rmkeys = |o: &Ghobject, ks: Vec<u32>| TOp::OmapRmKeys {
        cid: c,
        oid: o.clone(),
        keys: ks.into_iter().map(|i| TxnBytes::Owned(key(i))).collect(),
    };
    let setrun = |o: &Ghobject, ks: std::ops::Range<u32>, gn: u8| {
        let kv: Vec<(Vec<u8>, Vec<u8>)> = ks.map(|i| (key(i), val(i, gn))).collect();
        let mut enc = Vec::new();
        denc::SortedKv::encode_into(
            &mut enc,
            kv.len(),
            kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        );
        TOp::OmapSetRun {
            cid: c,
            oid: o.clone(),
            run: store::obj::KvRunData::from_encoding(enc.into()).unwrap(),
        }
    };
    let one = |r: &mut Rig, ops: Vec<TOp<'static>>| {
        let mut t = OTxn::new();
        for op in ops {
            t.push(op);
        }
        commit(&mut r.st, &t);
    };
    let rms = |st: &St| st.shards.iter().map(|s| s.stats.run_rms).sum::<u64>();
    let puts = |st: &St| st.shards.iter().map(|s| s.stats.run_puts).sum::<u64>();
    let loads = |st: &St| {
        st.shards
            .iter()
            .map(|s| s.sh.tree_stats().loads)
            .sum::<u64>()
    };
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let mut want: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for b in 0..8 {
        one(&mut r, vec![setrun(&o, b * 500..(b + 1) * 500, 1)]);
        want.extend((b * 500..(b + 1) * 500).map(|i| (key(i), val(i, 1))));
    }
    one(&mut r, vec![setrun(&o3, 0..200, 5)]);
    // the omap in the tree, the cache cold
    r.merge_runs();
    r.clean_remount();
    assert_eq!(r.st.omap_all(&c, &o).unwrap(), want);
    r.clean_remount();
    // keys spread over every leaf: staged blind, the commit reads the onode's path only
    let (l0, rm0, p0) = (loads(&r.st), rms(&r.st), puts(&r.st));
    one(&mut r, vec![rmkeys(&o, (0..4000).step_by(40).collect())]);
    let l = loads(&r.st) - l0;
    for i in (0..4000).step_by(40) {
        want.remove(&key(i));
    }
    assert_eq!(rms(&r.st), rm0 + 1, "staged as a run of removals");
    assert_eq!(puts(&r.st), p0 + 1, "a run");
    // the tree path for comparison: a batch below `run_min` over the same leaves
    let l1 = loads(&r.st);
    one(&mut r, vec![rmkeys(&o, (20..4000).step_by(64).collect())]);
    let lt = loads(&r.st) - l1;
    for i in (20..4000).step_by(64) {
        want.remove(&key(i));
    }
    assert_eq!(rms(&r.st), rm0 + 1, "a small batch in the tree");
    eprintln!("commit page loads: run of removals {l}, tree removals {lt}");
    assert!(
        l < 8 && lt > 3 * l,
        "the commit read {l} pages (tree path {lt})"
    );
    let got =
        r.st.omap_get(
            &c,
            &o,
            &[key(0).as_slice(), key(1).as_slice(), key(40).as_slice()],
        )
        .unwrap();
    assert_eq!(got.keys().cloned().collect::<Vec<_>>(), vec![key(1)]);
    assert_eq!(r.st.omap_all(&c, &o).unwrap(), want);
    // out of order, a repeat, absent keys
    let mut ks: Vec<u32> = (100..180).rev().collect();
    ks.push(150);
    ks.extend(90_000..90_010);
    one(&mut r, vec![rmkeys(&o, ks)]);
    for i in 100..180 {
        want.remove(&key(i));
    }
    assert_eq!(rms(&r.st), rm0 + 2);
    // a point put of a removed key later in the txn
    let (k250, v250) = (key(250), val(250, 2));
    let mut t = OTxn::new();
    t.push(rmkeys(&o, (200..300).collect()));
    t.omap_set(c, &o, &k250, &v250);
    commit(&mut r.st, &t);
    for i in 200..300 {
        want.remove(&key(i));
    }
    want.insert(k250.clone(), v250.clone());
    assert_eq!(rms(&r.st), rm0 + 3);
    // a put batch, then a removal batch of the same object: the second batch takes the tree path
    one(
        &mut r,
        vec![
            setrun(&o, 5000..5100, 3),
            rmkeys(&o, (5000..5070).collect()),
        ],
    );
    want.extend((5070..5100).map(|i| (key(i), val(i, 3))));
    assert_eq!(
        rms(&r.st),
        rm0 + 3,
        "the second batch of the object in the tree"
    );
    // a removal batch, then a put batch over half of its keys
    one(
        &mut r,
        vec![rmkeys(&o, (300..400).collect()), setrun(&o, 350..450, 4)],
    );
    for i in 300..400 {
        want.remove(&key(i));
    }
    want.extend((350..450).map(|i| (key(i), val(i, 4))));
    assert_eq!(rms(&r.st), rm0 + 4);
    // a removal batch, then a clone of the object
    one(
        &mut r,
        vec![
            rmkeys(&o, (450..550).collect()),
            TOp::Clone {
                cid: c,
                src: o.clone(),
                dst: o2.clone(),
            },
        ],
    );
    for i in 450..550 {
        want.remove(&key(i));
    }
    let want2 = want.clone();
    // a removal batch, then a range removal over part of it and beyond
    one(
        &mut r,
        vec![
            rmkeys(&o, (550..650).collect()),
            TOp::OmapRmKeyRange {
                cid: c,
                oid: o.clone(),
                first: TxnBytes::Owned(key(600)),
                last: TxnBytes::Owned(key(700)),
            },
        ],
    );
    for i in 550..700 {
        want.remove(&key(i));
    }
    // a removal batch, then the object's removal
    let mut t = OTxn::new();
    t.push(rmkeys(&o3, (0..100).collect()));
    t.remove(c, &o3);
    commit(&mut r.st, &t);
    assert_eq!(rms(&r.st), rm0 + 7);
    // below `run_min`: the tree path
    one(&mut r, vec![rmkeys(&o, (700..763).collect())]);
    for i in 700..763 {
        want.remove(&key(i));
    }
    assert_eq!(rms(&r.st), rm0 + 7, "a small batch in the tree");
    let verify = |r: &mut Rig, what: &str| {
        assert!(r.st.omap_all(&c, &o).unwrap() == want, "{what}: object");
        assert!(r.st.omap_all(&c, &o2).unwrap() == want2, "{what}: clone");
        assert!(
            r.st.stat(&c, &o3).unwrap().is_none(),
            "{what}: removed object"
        );
        let got =
            r.st.omap_get(
                &c,
                &o,
                &[
                    key(250).as_slice(),
                    key(260).as_slice(),
                    key(400).as_slice(),
                ],
            )
            .unwrap();
        assert_eq!(
            got.keys().cloned().collect::<Vec<_>>(),
            vec![key(250), key(400)],
            "{what}"
        );
    };
    verify(&mut r, "staged");
    // a power cut: the replay window rebuilds the runs of removals
    r.st.sync().unwrap();
    let img = r.disk.crash_image(CrashPolicy::DROP_ALL);
    r.fsck_img(&img);
    (r.disk, r.st) = open(&img, &r.sim, &r.cfg);
    assert!(
        !r.st.shards[0].sh.state().runs.is_empty(),
        "the runs replayed"
    );
    verify(&mut r, "after a power cut");
    r.clean_remount();
    verify(&mut r, "after a clean remount");
    r.merge_runs();
    verify(&mut r, "merged");
    r.clean_remount();
    verify(&mut r, "merged, remounted");
    check_no_leaks(&mut r);
}

struct Rig {
    ev: u64,
    disk: SimDisk,
    st: St,
    sim: SimConfig,
    cfg: StoreCfg,
}

thread_local! {
    /// Percent of data ops around the inline threshold (adr 0021 am. 14) and the inline writes / promotions the store saw (summed at every clean remount).
    static SMALL_PCT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static INLINE_SEEN: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
    /// Percent of txns with compression enabled in the generators of this test thread (adr 0059 am. 1), and the chunks the store compressed (summed at clean remounts).
    static COMP_PCT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static COMP_SEEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Compressed records cut into windows (adr 0059 am. 4), summed at clean remounts.
    static WIN_SEEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Percent of omap / xattr values sized for data blocks (adr 0021 am. 46) and the ext values the store wrote (clean remounts,
    /// crash matrix dry runs).
    static BIGVAL_PCT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    /// Percent of structured compressible values in the generators (adr 0021 am. 58) and the values the store compressed.
    static COMPVAL_PCT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static COMPVAL_KINDS: std::cell::Cell<u8> = const { std::cell::Cell::new(3) };
    static VCOMP_SEEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static EXT_SEEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

thread_local! {
    /// Percent of PG-log-like omap ops on PG metadata objects (log appends, range trims, dup drops, info rewrites) in
    /// the generators of this test thread; 0 = none.
    static PGMETA_PCT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

/// Put PG metadata objects with PG-log-shaped traffic into the generator's universe (`PGMETA_PCT`).
fn pgmeta_gen(g: &mut Gen) {
    let pct = PGMETA_PCT.get();
    if pct == 0 {
        return;
    }
    g.pgmeta = (0..3)
        .map(|s| Ghobject::pgmeta(1, s, ShardId::NO_SHARD))
        .collect();
    g.objs.extend(g.pgmeta.iter().cloned());
    g.pgmeta_pct = pct;
}

/// Run `f` with `PGMETA_PCT` = `pct` on this thread.
fn with_pgmeta(pct: u8, f: impl FnOnce()) {
    with_pgmeta_ret(pct, f)
}

fn with_pgmeta_ret<T>(pct: u8, f: impl FnOnce() -> T) -> T {
    PGMETA_PCT.set(pct);
    let r = f();
    PGMETA_PCT.set(0);
    r
}

thread_local! {
    /// Format new test images with the omap LSM engine (`FEAT_OMAP_LSM`, adr 0610), and its flushes / merges the
    /// stores saw (summed by the model and crash drivers at clean remounts).
    static OMAP_LSM: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LSM_SEEN: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
}

fn note_lsm(st: &St) {
    let (f, m) = LSM_SEEN.get();
    let s = st.shards.iter().filter_map(|s| s.sh.olsm_stats());
    let (df, dm) = s.fold((0, 0), |a, x| (a.0 + x.flushes, a.1 + x.merges));
    LSM_SEEN.set((f + df, m + dm));
}

thread_local! {
    /// Format new test images with the lazy subtree free (adr 0021 am. 18); `false` = the eager free of older stores.
    static LAZY_FREE: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

thread_local! {
    /// `meta_pct` (initial meta base area) of the images this test thread formats; 1 = tiny base, the elastic meta
    /// space (adr 0021 am. 12) must grow on demand.
    static META_PCT: std::cell::Cell<u32> = const { std::cell::Cell::new(8) };
}

thread_local! {
    /// Omap batch runs (adr 0476) stressed on this test thread: a small run budget and run count (`runs_cfg`), the percent
    /// of generated omap set ops that are sorted batches (`Gen::run_pct`), and the run puts / merges / compactions / runs
    /// of removals the stores saw (summed by the model and crash drivers).
    static RUNS_STRESS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static RUN_PCT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static RUNS_SEEN: std::cell::Cell<(u64, u64, u64, u64)> = const { std::cell::Cell::new((0, 0, 0, 0)) };
    static RUN_VCOMP_SEEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Small run budget, run count per object and compaction fan-in for the runs tests: merges (soft size, `run_max`) and
/// compactions run often.
fn runs_cfg(mut c: StoreCfg) -> StoreCfg {
    if OMAP_LSM.get() {
        // a small cache: the omap engine's memtables (a quarter of its half) flush and merge every few dozen txns
        c.shard.cache_pages = 96;
    }
    if RUNS_STRESS.get() {
        c.shard.run_soft_bytes = 48 << 10;
        c.shard.run_max = 4;
        c.shard.run_fan = 2;
    }
    c
}

fn note_runs(st: &St) {
    let (p, m, c, rm) = RUNS_SEEN.get();
    RUNS_SEEN.set((
        p + st.shards.iter().map(|s| s.stats.run_puts).sum::<u64>(),
        m + st.shards.iter().map(|s| s.sh.stats.run_merges).sum::<u64>(),
        c + st
            .shards
            .iter()
            .map(|s| s.sh.stats.run_compactions)
            .sum::<u64>(),
        rm + st.shards.iter().map(|s| s.stats.run_rms).sum::<u64>(),
    ));
    RUN_VCOMP_SEEN.set(
        RUN_VCOMP_SEEN.get()
            + st.shards
                .iter()
                .map(|s| s.sh.state().run_vcomp.0)
                .sum::<u64>(),
    );
}

fn fresh_image(cap_mib: u64, shards: u32, wal_blocks: u64, cfg_sim: &SimConfig) -> SimImage {
    fresh_image_ns(cap_mib, shards, wal_blocks, cfg_sim, 8192)
}

fn fresh_image_ns(
    cap_mib: u64,
    shards: u32,
    wal_blocks: u64,
    cfg_sim: &SimConfig,
    node_size: u32,
) -> SimImage {
    let disk = SimDisk::new(cfg_sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards,
        wal_blocks,
        align_blocks: 1,
        meta_pct: META_PCT.get(),
        node_size,
        lazy_free: LAZY_FREE.get(),
        omap_lsm: OMAP_LSM.get(),
        ..Default::default()
    };
    let _ = cap_mib;
    mkfs(&mut dev, &mut clk, &p).unwrap();
    disk.image()
}

fn open(img: &SimImage, sim: &SimConfig, cfg: &StoreCfg) -> (SimDisk, St) {
    let disk = SimDisk::from_image(img, sim.clone());
    let d2 = disk.clone();
    let (st, _) = Store::mount(move || d2.queue(), SimClock::default(), cfg.clone()).unwrap();
    (disk, st)
}

fn rig_with(
    cap_mib: u64,
    shards: u32,
    wal_blocks: u64,
    seed: u64,
    cfg: StoreCfg,
) -> (Rig, SimImage) {
    rig_ns(cap_mib, shards, wal_blocks, seed, cfg, 8192)
}

fn rig_ns(
    cap_mib: u64,
    shards: u32,
    wal_blocks: u64,
    seed: u64,
    cfg: StoreCfg,
    node_size: u32,
) -> (Rig, SimImage) {
    rig_sim(cap_mib, shards, wal_blocks, seed, cfg, node_size, true)
}

/// `trims` false: a device without runtime deallocate (adr 0642), for layout fixtures that count runs exactly (a
/// deallocate in flight holds free runs, the allocator places around them).
fn rig_sim(
    cap_mib: u64,
    shards: u32,
    wal_blocks: u64,
    seed: u64,
    cfg: StoreCfg,
    node_size: u32,
    trims: bool,
) -> (Rig, SimImage) {
    let mut sim = SimConfig::new(cap_mib << 20);
    sim.seed = seed;
    if !trims {
        sim.dealloc = DeallocLimits::off("layout fixture");
    }
    let img = fresh_image_ns(cap_mib, shards, wal_blocks, &sim, node_size);
    let (disk, st) = open(&img, &sim, &cfg);
    (
        Rig {
            ev: 0,
            disk,
            st,
            sim,
            cfg,
        },
        img,
    )
}

/// A device idle gap of `gap` ns, polled as a store core polls through it (the core's idle loop): an active store
/// ([`Store::quiet`] false: a shard with IO in flight, a checkpoint requested or in its sliced steps) every pass, at the
/// next device completion; a quiet store at every sweep (1 ms, `Store::poll` polls every shard then), its devices at the
/// clock (a real device's clock runs while nothing is in flight). Only a quiet shard's poll may start a deallocate, after
/// the device idle table saw its device quiet for one gap.
fn core_gap(r: &mut Rig, gap: u64) {
    const SWEEP_NS: u64 = 1_000_000;
    let end = r.st.clk.t + gap;
    while r.st.clk.t < end {
        if r.st.quiet() {
            let t = (r.st.clk.t + SWEEP_NS).min(end);
            r.st.clk.idle(Some(t));
            for s in r.st.shards.iter_mut() {
                let mut c = Vec::new();
                s.sh.dev().poll(t, &mut c);
                assert!(c.is_empty());
            }
        } else {
            r.st.idle();
        }
        r.st.poll(&mut Vec::new()).unwrap();
    }
}

/// Deallocates submitted, all shards.
fn trim_cmds(r: &Rig) -> u64 {
    r.st.shards.iter().map(|s| s.sh.stats.trim_cmds).sum()
}

/// Poll until no deallocate is in flight on any shard and no candidate is left, or none starts while a core polls the
/// store through a device idle gap past the pauses (adr 0642; [`core_gap`]: the device idle table needs two looks of a
/// quiet shard one gap apart).
fn settle_trims(r: &mut Rig) {
    for _ in 0..10_000 {
        if r.st.shards.iter().all(|s| {
            let g = s.sh.gauges();
            g.trim_held == 0 && g.trim_cand_windows == 0
        }) {
            return;
        }
        let c = trim_cmds(r);
        let due =
            r.st.shards
                .iter()
                .map(|s| s.sh.trim_due())
                .max()
                .unwrap_or(0);
        core_gap(
            r,
            due.saturating_sub(r.st.clk.t) + 3 * store::shard::BG_BUSY_GAP_NS,
        );
        if trim_cmds(r) == c
            && r.st.quiet()
            && r.st.shards.iter().all(|s| s.sh.gauges().trim_held == 0)
        {
            return;
        }
    }
    panic!("deallocates never settled");
}

fn rig(cap_mib: u64, shards: u32) -> Rig {
    rig_with(cap_mib, shards, 1024, 1, StoreCfg::default()).0
}

/// Config without value compression: for tests whose sizes (tree entries, data blocks) assume plain values.
fn nvc_cfg() -> StoreCfg {
    let mut c = StoreCfg::default();
    c.shard.val_comp_min = 0;
    c
}

fn rig_nvc(cap_mib: u64, shards: u32) -> Rig {
    rig_with(cap_mib, shards, 1024, 1, nvc_cfg()).0
}

impl Rig {
    /// Merge every run into the tree now (`Shard::drain_runs`), polling with 100 us of virtual time per poll;
    /// returns the polls taken.
    fn merge_runs(&mut self) -> u64 {
        for s in self.st.shards.iter_mut() {
            s.sh.drain_runs();
        }
        let mut acked = Vec::new();
        for n in 0..1_000_000 {
            if self.st.shards.iter().all(|s| s.sh.state().runs.is_empty()) {
                return n;
            }
            self.st.poll(&mut acked).unwrap();
            self.st.clk.t += 100_000;
        }
        panic!("the runs never merged");
    }
    fn clean_remount(&mut self) {
        self.ev += self
            .st
            .shards
            .iter()
            .map(|s| s.sh.tree_stats().evictions)
            .sum::<u64>();
        for s in &self.st.shards {
            INLINE_SEEN.with(|c| {
                let (w, p) = c.get();
                c.set((w + s.stats.inline_writes, p + s.stats.inline_promotions));
                COMP_SEEN.set(COMP_SEEN.get() + s.stats.comp_ok);
                WIN_SEEN.set(WIN_SEEN.get() + s.stats.comp_windows);
                EXT_SEEN.set(EXT_SEEN.get() + s.stats.ext_values);
                VCOMP_SEEN.set(VCOMP_SEEN.get() + s.stats.val_comp);
            });
        }
        self.st.checkpoint().unwrap();
        let img = self.disk.image();
        self.fsck_img(&img);
        let (d, s) = open(&img, &self.sim, &self.cfg);
        self.disk = d;
        self.st = s;
    }
    fn fsck_img(&self, img: &SimImage) {
        let d = SimDisk::from_image(img, self.sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        fsck(&mut dev, &mut clk, Some(&fsck_refs)).unwrap();
    }
}

fn g(oid: &[u8], hash: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(oid, SnapId::NOSNAP, hash, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn c1() -> CollT {
    pgc(1, 0)
}

fn commit(st: &mut St, t: &OTxn) {
    st.commit(t)
        .unwrap_or_else(|e| panic!("commit failed: {e:?}"));
}

/// Every key belongs to a live onode, every onode has exactly one name; returns number of onodes.
fn check_no_leaks(r: &mut Rig) -> usize {
    let rep = r.st.check(true).unwrap();
    assert!(
        rep.errors.is_empty(),
        "object layer check: {:?}",
        rep.errors
    );
    let mut total = 0;
    for i in 0..r.st.shards.len() {
        let kv = r.st.shards[i].sh.dump_blocking(&mut r.st.clk).unwrap();
        let mut onodes = BTreeSet::new();
        let mut names = BTreeMap::new();
        for (k, v) in &kv {
            match k[0] {
                T_ONODE => {
                    onodes.insert(u64::from_be_bytes(k[1..9].try_into().unwrap()));
                }
                T_NAME | T_LNAME => {
                    *names
                        .entry(u64::from_le_bytes(v[..8].try_into().unwrap()))
                        .or_insert(0) += 1;
                }
                _ => {}
            }
        }
        for (k, _) in &kv {
            if matches!(k[0], T_ATTR | T_HDR | T_EXT | T_OMAP | T_FRAG | T_INL) {
                let id = u64::from_be_bytes(k[1..9].try_into().unwrap());
                assert!(
                    onodes.contains(&id),
                    "leaked key {:?} of dead onode {id}",
                    &k[..9]
                );
            }
        }
        assert_eq!(onodes.len(), names.len(), "onodes vs names");
        assert!(names.values().all(|&n| n == 1));
        assert!(names.keys().all(|id| onodes.contains(id)));
        total += onodes.len();
    }
    total
}

// ---------------------------------------------------------------------------------------------- basics

#[test]
fn basic_object_lifecycle() {
    let mut r = rig(32, 1);
    let c = c1();
    let o = g(b"obj1", 0x1234);
    let mut t = OTxn::new();
    t.mkcoll(c);
    let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    t.write(c, &o, 100, &data);
    t.setattr(c, &o, b"_", b"oi");
    t.omap_set(c, &o, b"k1", b"v1");
    commit(&mut r.st, &t);
    assert_eq!(r.st.stat(&c, &o).unwrap().unwrap().size, 10_100);
    let d = r.st.read(&c, &o, 0, 20_000).unwrap();
    assert_eq!(&d[..100], &[0u8; 100][..]);
    assert_eq!(&d[100..], &data[..]);
    assert_eq!(r.st.getattr(&c, &o, b"_").unwrap().unwrap(), b"oi");
    assert_eq!(r.st.omap_all(&c, &o).unwrap().len(), 1);
    // sub-4k overwrite in the middle + zero + truncate
    let mut t = OTxn::new();
    t.write(c, &o, 5000, b"HELLO");
    t.zero(c, &o, 8000, 500);
    t.truncate(c, &o, 9000);
    commit(&mut r.st, &t);
    let d = r.st.read(&c, &o, 0, 20_000).unwrap();
    assert_eq!(d.len(), 9000);
    assert_eq!(&d[5000..5005], b"HELLO");
    assert!(d[8000..8500].iter().all(|b| *b == 0));
    assert_eq!(&d[100..5000], &data[..4900]);
    // grow after shrink reads zeros
    let mut t = OTxn::new();
    t.truncate(c, &o, 12_000);
    commit(&mut r.st, &t);
    let d = r.st.read(&c, &o, 8500, 5000).unwrap();
    assert_eq!(d.len(), 3500);
    assert_eq!(&d[..500], &data[8400..8900][..]);
    assert!(d[500..].iter().all(|b| *b == 0));
    r.clean_remount();
    assert_eq!(r.st.read(&c, &o, 5000, 5).unwrap(), b"HELLO");
    let mut t = OTxn::new();
    t.remove(c, &o);
    commit(&mut r.st, &t);
    assert!(r.st.stat(&c, &o).unwrap().is_none());
    assert_eq!(r.st.read(&c, &o, 0, 1), Err(ObjError::NoEnt));
    assert_eq!(check_no_leaks(&mut r), 0);
    let s = r.st.coll_stats(&c).unwrap().unwrap();
    assert_eq!((s.nobj, s.nbytes), (0, 0));
}

#[test]
fn atomic_failure_changes_nothing() {
    let mut r = rig(32, 1);
    let c = c1();
    let o = g(b"a", 1);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.write(c, &o, 0, &[7u8; 9000]);
    commit(&mut r.st, &t);
    let free0 = r.st.statfs().avail_bytes;
    // second op fails (clone of missing source) -> first op must not be visible, no space leaked
    let mut t = OTxn::new();
    t.write(c, &o, 0, &[9u8; 9000]);
    t.push(TOp::Clone {
        cid: c,
        src: g(b"missing", 2),
        dst: g(b"x", 3),
    });
    assert_eq!(r.st.commit(&t), Err(ObjError::NoEnt));
    assert_eq!(
        r.st.read(&c, &o, 0, 10).unwrap(),
        vec![7u8; 9000][..10].to_vec()
    );
    assert_eq!(r.st.statfs().avail_bytes, free0);
    // unknown collection
    let mut t = OTxn::new();
    t.touch(pgc(1, 99), &o);
    assert_eq!(r.st.commit(&t), Err(ObjError::NoColl));
    // cross shard
    let mut r4 = rig(64, 4);
    let mut t = OTxn::new();
    t.push(TOp::MkColl {
        cid: pgc(1, 0),
        bits: 0,
        exist_ok: false,
    });
    t.push(TOp::MkColl {
        cid: pgc(1, 1),
        bits: 0,
        exist_ok: false,
    });
    assert_eq!(r4.st.commit(&t), Err(ObjError::CrossShard));
}

#[test]
fn collection_ops() {
    let mut r = rig(32, 2);
    let c = pgc(2, 4);
    let tmp = tmpc(2, 4);
    let o = g(b"a", 1);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.push(TOp::MkColl {
        cid: tmp,
        bits: 3,
        exist_ok: false,
    });
    commit(&mut r.st, &t);
    assert_eq!(
        r.st.commit(&{
            let mut t = OTxn::new();
            t.mkcoll(c);
            t
        }),
        Err(ObjError::Exists)
    );
    let mut t = OTxn::new();
    t.write(c, &o, 0, b"x");
    commit(&mut r.st, &t);
    let mut t = OTxn::new();
    t.push(TOp::RmColl { cid: c });
    assert_eq!(r.st.commit(&t), Err(ObjError::NotEmpty));
    // move to temp collection and back; rename keeps data
    let o2 = g(b"b", 2);
    let mut t = OTxn::new();
    t.push(TOp::MoveRename {
        cid: c,
        oid: o.clone(),
        dcid: tmp,
        doid: o2.clone(),
    });
    commit(&mut r.st, &t);
    assert!(r.st.stat(&c, &o).unwrap().is_none());
    assert_eq!(r.st.read(&tmp, &o2, 0, 10).unwrap(), b"x");
    assert_eq!(r.st.coll_stats(&c).unwrap().unwrap().nobj, 0);
    assert_eq!(r.st.coll_stats(&tmp).unwrap().unwrap().nobj, 1);
    assert_eq!(r.st.coll_stats(&tmp).unwrap().unwrap().bits, 3);
    // remove empty collection, list_colls
    let mut t = OTxn::new();
    t.push(TOp::RmColl { cid: c });
    commit(&mut r.st, &t);
    assert!(!r.st.coll_exists(&c).unwrap());
    let l = r.st.list_colls().unwrap();
    assert_eq!(l, vec![tmp]);
    r.clean_remount();
    assert_eq!(r.st.list_colls().unwrap(), vec![tmp]);
    // sub-4k clone and rename over existing destination
    let mut t = OTxn::new();
    t.write(tmp, &g(b"s", 5), 0, &[1u8; 5000]);
    t.write(tmp, &g(b"d", 6), 0, &[2u8; 100]);
    t.push(TOp::Clone {
        cid: tmp,
        src: g(b"s", 5),
        dst: g(b"d", 6),
    });
    commit(&mut r.st, &t);
    assert_eq!(
        r.st.read(&tmp, &g(b"d", 6), 0, 6000).unwrap(),
        vec![1u8; 5000]
    );
}

#[test]
fn fragmented_values_and_limits() {
    let mut r = rig(32, 1);
    let c = c1();
    let o = g(b"frag", 9);
    let big: Vec<u8> = (0..70_000u32).map(|i| (i * 7 % 256) as u8).collect();
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.setattr(c, &o, b"snapset", &big);
    t.omap_set(c, &o, b"bigkey", &big[..20_000]);
    t.omap_set(c, &o, b"small", b"s");
    t.push(TOp::OmapSetHeader {
        cid: c,
        oid: o.clone(),
        header: big[..9000].to_vec().into(),
    });
    commit(&mut r.st, &t);
    r.clean_remount();
    assert_eq!(r.st.getattr(&c, &o, b"snapset").unwrap().unwrap(), big);
    assert_eq!(
        r.st.omap_get(&c, &o, &[b"bigkey"]).unwrap()[&b"bigkey".to_vec()],
        big[..20_000]
    );
    assert_eq!(r.st.omap_header(&c, &o).unwrap(), big[..9000]);
    // overwrite fragmented by small and by other fragmented: old fragments must go
    let mut t = OTxn::new();
    t.setattr(c, &o, b"snapset", b"tiny");
    t.omap_set(c, &o, b"bigkey", &big[..5000]);
    commit(&mut r.st, &t);
    assert_eq!(r.st.getattr(&c, &o, b"snapset").unwrap().unwrap(), b"tiny");
    assert_eq!(
        r.st.omap_get(&c, &o, &[b"bigkey"]).unwrap()[&b"bigkey".to_vec()],
        big[..5000]
    );
    let mut t = OTxn::new();
    t.remove(c, &o);
    commit(&mut r.st, &t);
    assert_eq!(check_no_leaks(&mut r), 0);
    // name too long (adr 0021 am. 10: limit = tree key limit - 15; 600 B keys are fine now)
    let lim = r.st.max_item_key();
    assert_eq!(lim, store::tree::max_key_for(8192) - 15);
    let (k_bad, k_ok) = (vec![b'k'; lim + 1], vec![b'k'; lim]);
    let mut t = OTxn::new();
    t.omap_set(c, &o, &k_bad, b"v");
    assert_eq!(r.st.commit(&t), Err(ObjError::NameTooLong));
    let mut t = OTxn::new();
    t.omap_set(c, &o, &k_ok, b"v");
    commit(&mut r.st, &t);
}

#[test]
fn clone_is_independent_copy() {
    let mut r = rig(32, 1);
    let c = c1();
    let (a, b) = (g(b"a", 1), g(b"b", 2));
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.write(c, &a, 0, &[1u8; 40_000]);
    t.write(c, &a, 100_000, &[3u8; 10]);
    t.setattr(c, &a, b"x", b"y");
    t.omap_set(c, &a, b"o", b"p");
    t.push(TOp::Clone {
        cid: c,
        src: a.clone(),
        dst: b.clone(),
    });
    t.write(c, &a, 0, &[9u8; 10]);
    commit(&mut r.st, &t);
    assert_eq!(r.st.read(&c, &b, 0, 10).unwrap(), vec![1u8; 10]);
    assert_eq!(r.st.read(&c, &a, 0, 10).unwrap(), vec![9u8; 10]);
    assert_eq!(r.st.stat(&c, &b).unwrap().unwrap().size, 100_010);
    assert_eq!(r.st.getattr(&c, &b, b"x").unwrap().unwrap(), b"y");
    assert_eq!(r.st.omap_all(&c, &b).unwrap().len(), 1);
    // sparseness preserved: hole in the middle takes no blocks
    let used = r.st.statfs().used_bytes;
    let mut t = OTxn::new();
    t.push(TOp::Clone {
        cid: c,
        src: a.clone(),
        dst: g(b"c", 3),
    });
    commit(&mut r.st, &t);
    assert!(r.st.statfs().used_bytes - used <= 11 * 4096);
    let mut t = OTxn::new();
    t.remove(c, &a);
    t.remove(c, &b);
    commit(&mut r.st, &t);
    assert_eq!(r.st.read(&c, &g(b"c", 3), 0, 10).unwrap(), vec![9u8; 10]);
    r.clean_remount();
    check_no_leaks(&mut r);
}

/// A snapshot made after many writes/holes in the same transaction resolves each interval once.
#[test]
fn clone_after_fragmented_overlay_preserves_sparse_data() {
    let mut r = rig(32, 1);
    let c = c1();
    let (src, dst) = (g(b"range-source", 1), g(b"range-clone", 2));
    let mut expected = vec![0x47; 128 * 4096];
    let mut init = OTxn::new();
    init.mkcoll(c);
    init.write(c, &src, 0, &expected);
    commit(&mut r.st, &init);
    let replacement = [0x91; 4096];
    let mut t = OTxn::new();
    for block in (0..128).step_by(4) {
        t.zero(c, &src, (block + 1) as u64 * 4096, 4096);
        expected[(block + 1) * 4096..(block + 2) * 4096].fill(0);
        t.write(c, &src, (block + 2) as u64 * 4096, &replacement);
        expected[(block + 2) * 4096..(block + 3) * 4096].fill(0x91);
    }
    t.push(TOp::Clone {
        cid: c,
        src: src.clone(),
        dst: dst.clone(),
    });
    t.remove(c, &src);
    commit(&mut r.st, &t);
    for _ in 0..2 {
        assert_eq!(
            r.st.read(&c, &dst, 0, expected.len() as u64).unwrap(),
            expected
        );
        r.clean_remount();
    }
    check_no_leaks(&mut r);
}

/// `used_bytes` must charge every tree (meta) page the store allocates, base area and elastic cells alike
/// (doc/perf spike used_bytes): omap keys that fit in the fixed base meta region used to read 0 / far too low.
#[test]
fn statfs_used_bytes_counts_all_meta_pages() {
    for shards in [1u32, 4] {
        let mut r = rig_nvc(256, shards);
        let c = c1();
        let o = g(b"omap-meta", 7);
        let mut t = OTxn::new();
        t.mkcoll(c);
        commit(&mut r.st, &t);
        let base = r.st.statfs();
        let val = vec![0x5au8; 128];
        for ch in (0..2000u32).collect::<Vec<_>>().chunks(200) {
            let mut t = OTxn::new();
            let keys: Vec<String> = ch.iter().map(|&i| format!("key-{i:06}")).collect();
            for k in &keys {
                t.omap_set(c, &o, k.as_bytes(), &val);
            }
            commit(&mut r.st, &t);
        }
        r.st.checkpoint().unwrap(); // clear the dirty pages so the fill sees the settled tree
        let s = r.st.statfs();
        assert!(
            s.meta_used_pages > 20,
            "shards {shards}: expected a substantial tree, got {} meta pages",
            s.meta_used_pages
        );
        // every used meta page (base + cells) is one 8192 B tree page and must show up in used_bytes
        assert!(
            s.used_bytes >= s.meta_used_pages * 8192,
            "shards {shards}: used_bytes {used} < {pages} meta pages x 8192 (base meta not counted)",
            used = s.used_bytes,
            pages = s.meta_used_pages
        );
        assert!(
            s.used_bytes > base.used_bytes,
            "shards {shards}: used_bytes did not grow after 2000 omap keys"
        );
        // the base meta area is capacity too: total grows by it, used + avail stays total
        assert_eq!(
            s.total_bytes, base.total_bytes,
            "shards {shards}: total changed by omap keys"
        );
        assert_eq!(
            s.used_bytes + s.avail_bytes,
            s.total_bytes,
            "shards {shards}: used + avail != total"
        );
    }
}

// ---------------------------------------------------------------------------------------------- listing

#[test]
fn listing_order_special_names_namespaces_hash() {
    let mut r = rig(32, 1);
    let c = c1();
    let mut all: Vec<Ghobject> = Vec::new();
    let names: [&[u8]; 9] = [
        b"", b"a", b"a\0", b"a\0b", b"ab", b"b", b"\x01", b"\xff", b"a b/c%d",
    ];
    let mut rng = Rng::new(77);
    for (i, n) in names.iter().enumerate() {
        for ns in [&b""[..], b"ns", b"\0", b"n\0s"] {
            for key in [&b""[..], b"loc", b"a\0"] {
                let mut h = Hobject::new(
                    n,
                    if i % 3 == 0 {
                        SnapId::NOSNAP
                    } else {
                        SnapId(i as u64)
                    },
                    rng.next_u64() as u32 & if i % 2 == 0 { 0xff } else { u32::MAX },
                    1,
                    ns,
                );
                h.set_key(key);
                let gh = Ghobject::new(
                    h,
                    if i % 4 == 0 { 5 } else { Ghobject::NO_GEN },
                    ShardId::NO_SHARD,
                );
                if !all.contains(&gh) {
                    all.push(gh);
                }
            }
        }
    }
    // other pool, temp pool, meta pool, pgmeta
    all.push(Ghobject::new(
        Hobject::new(b"x", SnapId::NOSNAP, 1, 2, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    ));
    all.push(Ghobject::new(
        Hobject::new(b"x", SnapId::NOSNAP, 1, Hobject::temp_pool(1), b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    ));
    all.push(Ghobject::new(
        Hobject::new(b"x", SnapId::NOSNAP, 1, Hobject::POOL_META, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    ));
    all.push(Ghobject::pgmeta(1, 0, ShardId::NO_SHARD));
    all.push(Ghobject::new(
        Hobject::new(b"x", SnapId::NOSNAP, 1, 1, b""),
        Ghobject::NO_GEN,
        ShardId(2),
    ));
    let mut t = OTxn::new();
    t.mkcoll(c);
    for (i, o) in all.iter().enumerate() {
        t.touch(c, o);
        if i % 40 == 39 {
            commit(&mut r.st, &t);
            t = OTxn::new();
        }
    }
    commit(&mut r.st, &t);
    all.sort();
    // full listing, paged by 7, from MIN
    let mut got = vec![];
    let mut cur = Ghobject::MIN();
    loop {
        let (v, n) = r.st.list(&c, &cur, None, 7).unwrap();
        got.extend(v);
        match n {
            Some(x) => cur = x,
            None => break,
        }
    }
    assert_eq!(got, all);
    // bounded range [begin, end)
    let (b, e) = (&all[10], &all[30]);
    let (v, n) = r.st.list(&c, b, Some(e), 1000).unwrap();
    assert_eq!(v, all[10..30].to_vec());
    assert!(n.is_none());
    let (v, n) = r.st.list(&c, b, Some(e), 5).unwrap();
    assert_eq!(v, all[10..15].to_vec());
    assert_eq!(n.as_ref(), Some(&all[15]));
    // begin between objects
    let mut mid = all[20].clone();
    mid.generation = mid.generation.wrapping_sub(0); // same
    let (v, _) = r.st.list(&c, &mid, None, 3).unwrap();
    assert_eq!(v, all[20..23].to_vec());
    r.clean_remount();
    let (v, _) = r.st.list(&c, &Ghobject::MIN(), None, 1000).unwrap();
    assert_eq!(v, all);
}

// ---------------------------------------------------------------------------------------------- integrity

#[test]
fn corruption_gives_eio_and_scrub_reports_it() {
    let mut r = rig(32, 1);
    let c = c1();
    let o = g(b"a", 1);
    let data: Vec<u8> = (0..16 * 4096u32).map(|i| (i % 253) as u8).collect();
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.write(c, &o, 0, &data);
    t.omap_set(c, &o, b"k", b"v");
    t.push(TOp::OmapSetHeader {
        cid: c,
        oid: o.clone(),
        header: b"hdr".to_vec().into(),
    });
    commit(&mut r.st, &t);
    r.clean_remount();
    let ok = r.st.scrub(&c, &o, 0xFFFF_FFFF).unwrap();
    assert!(ok.bad_blocks.is_empty());
    assert_eq!(ok.size, data.len() as u64);
    assert_eq!(ok.data_crc, crc::crc32c(0xFFFF_FFFF, &data));
    assert_eq!(ok.omap_keys, 1);
    // locate the data blocks via a read of the first extent: corrupt the block that holds logical block 5
    let kv = r.st.shards[0].sh.dump_blocking(&mut r.st.clk).unwrap();
    let (_, v) = kv
        .iter()
        .find(|(k, _)| k[0] == T_EXT && k[10..14] == [0, 0, 0, 0])
        .unwrap();
    let ext = store::obj::onode::Ext::decode(v).unwrap();
    let pba = ext.pba + 5;
    r.disk.corrupt(pba, 100, 0x40);
    // device blocks == engine blocks here (4k lba)
    r.st.shards[0].sh.state(); // keep borrowck honest
    assert!(matches!(
        r.st.read(&c, &o, 5 * 4096, 10),
        Err(ObjError::Eio(_))
    ));
    assert!(
        r.st.read(&c, &o, 0, 4096).is_ok(),
        "other blocks still readable"
    );
    let s = r.st.scrub(&c, &o, 0xFFFF_FFFF).unwrap();
    assert_eq!(s.bad_blocks, vec![5]);
    assert_ne!(s.data_crc, ok.data_crc);
    let rep = r.st.check(true).unwrap();
    assert_eq!(rep.errors.len(), 1, "{:?}", rep.errors);
    assert!(rep.errors[0].contains("checksum mismatch"));
    // a stray key of a dead onode is reported (checker is not vacuous)
    let mut t: store::shard::Txn<Vec<u8>> = store::shard::Txn::new(0);
    t.put(&attr_key(0xdead_beef, b"x"), b"\0v");
    r.st.shards[0].sh.submit(t).unwrap();
    let rep = r.st.check(false).unwrap();
    assert!(
        rep.errors.iter().any(|e| e.contains("dead onode")),
        "{:?}",
        rep.errors
    );
}

#[test]
fn enospc_is_clean_and_recoverable() {
    let mut r = rig_with(48, 1, 256, 3, StoreCfg::default()).0;
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let blob = vec![0xA5u8; 200_000];
    let mut n = 0;
    let err = loop {
        let mut t = OTxn::new();
        t.write(c, &g(format!("o{n}").as_bytes(), n as u32), 0, &blob);
        match r.st.commit(&t) {
            Ok(()) => n += 1,
            Err(e) => break e,
        }
        assert!(n < 1000);
    };
    assert_eq!(err, ObjError::NoSpace);
    assert!(n > 5);
    // everything written before is intact; the failed txn left no trace
    for i in 0..n {
        assert_eq!(
            r.st.read(&c, &g(format!("o{i}").as_bytes(), i as u32), 199_990, 10)
                .unwrap(),
            vec![0xA5; 10]
        );
    }
    assert!(
        r.st.stat(&c, &g(format!("o{n}").as_bytes(), n as u32))
            .unwrap()
            .is_none()
    );
    // removing frees space (privileged alloc/frees), then writing works again
    for ch in (0..n / 2).collect::<Vec<_>>().chunks(3) {
        let mut t = OTxn::new();
        for i in ch {
            t.remove(c, &g(format!("o{i}").as_bytes(), *i as u32));
        }
        commit(&mut r.st, &t);
    }
    let mut t = OTxn::new();
    t.write(c, &g(b"after", 1), 0, &blob);
    commit(&mut r.st, &t);
    r.clean_remount();
    check_no_leaks(&mut r);
}

#[test]
fn read_waits_for_durability_of_unacked_data() {
    let mut r = rig(32, 1);
    let c = c1();
    let o = g(b"a", 1);
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    for i in 0..20u8 {
        let mut t = OTxn::new();
        let buf = [i; 9000];
        t.write(c, &o, 0, &buf);
        r.st.queue(&t, i as u64).unwrap();
        // read right after queue (data not yet on media)
        assert_eq!(r.st.read(&c, &o, 4090, 20).unwrap(), vec![i; 20]);
    }
    r.st.sync().unwrap();
}

// ---------------------------------------------------------------------------------------------- model

fn run_model(seed: u64, shards: u32, ntxn: usize, remount_every: usize) {
    run_model_cfg(
        seed,
        shards,
        ntxn,
        remount_every,
        StoreCfg::default(),
        8192,
        0,
    );
}

fn run_model_cfg(
    seed: u64,
    shards: u32,
    ntxn: usize,
    remount_every: usize,
    cfg: StoreCfg,
    node_size: u32,
    storm: u8,
) -> u64 {
    let (mut r, _) = rig_ns(256, shards, 1024, seed, runs_cfg(cfg), node_size);
    let mut gn = if storm > 0 {
        Gen::with_storm(seed, 1, storm, Vec::new())
    } else {
        Gen::new(seed, 1)
    };
    gn.long_key = if node_size < 8192 { 200 } else { 300 };
    gn.small_pct = SMALL_PCT.get();
    gn.big_val_pct = BIGVAL_PCT.get();
    gn.comp_val_pct = COMPVAL_PCT.get();
    gn.comp_val_kinds = COMPVAL_KINDS.get();
    gn.comp_pct = COMP_PCT.get();
    gn.run_pct = RUN_PCT.get();
    gn.big_key = if node_size < 8192 { 1200 } else { 2500 };
    pgmeta_gen(&mut gn);
    longname_gen(&mut gn);
    let mut m = Model::default();
    // groups = one per shard to stay single-shard per txn
    let groups: Vec<Vec<CollT>> = vec![
        vec![pgc(1, 0), tmpc(1, 0)],
        vec![pgc(1, 1)],
        vec![CollT::Meta],
        vec![pgc(1, 2), pgc(1, 6)],
    ];
    for grp in &groups {
        let mut t = OTxn::new();
        for c in grp {
            t.push(TOp::MkColl {
                cid: *c,
                bits: 0,
                exist_ok: false,
            });
        }
        let first = r.st.shard_of(&grp[0]);
        assert!(grp.iter().all(|c| r.st.shard_of(c) == first || shards == 1) || shards != 4);
        if grp.iter().any(|c| r.st.shard_of(c) != first) {
            continue;
        }
        commit(&mut r.st, &t);
        m.apply_txn(&t).unwrap();
    }
    let live: Vec<Vec<CollT>> = groups
        .into_iter()
        .filter(|g| m.colls.contains_key(&g[0]))
        .collect();
    let spare: Vec<Vec<CollT>> = live
        .iter()
        .map(|g| {
            if storm == 0 || g[0] == CollT::Meta {
                return Vec::new();
            }
            let s = r.st.shard_of(&g[0]);
            (0..24)
                .map(|i| pgc(1, 200 + i))
                .filter(|c| r.st.shard_of(c) == s)
                .collect()
        })
        .collect();
    let mut vr = Rng::new(seed ^ 77);
    for i in 0..ntxn {
        let gi = gn.rng.below(live.len() as u64) as usize;
        let grp = &live[gi];
        gn.storm_colls = spare[gi].clone();
        let t = gn.txn(&m, grp);
        if t.is_empty() {
            continue;
        }
        match r.st.commit(&t) {
            Err(ObjError::TooLarge | ObjError::NoSpace) if storm > 0 => continue,
            Err(e) => panic!("seed {seed} txn {i}: {e:?} ({} ops)", t.ops.len()),
            Ok(()) => {}
        }
        m.apply_txn(&t).unwrap();
        if i % 20 == 19 {
            verify(&mut r.st, &m, &gn, &mut vr)
                .unwrap_or_else(|e| panic!("seed {seed} after txn {i}: {e}"));
            // also checks the shard caches (point cache) against the tree mid-stream
            if i % 100 == 99 {
                let rep = r.st.check(false).unwrap();
                assert!(
                    rep.errors.is_empty(),
                    "seed {seed} after txn {i}: {:?}",
                    rep.errors
                );
            }
        }
        if remount_every > 0 && i % remount_every == remount_every - 1 {
            note_runs(&r.st);
            note_lsm(&r.st);
            r.clean_remount();
            verify(&mut r.st, &m, &gn, &mut vr)
                .unwrap_or_else(|e| panic!("seed {seed} after remount at {i}: {e}"));
        }
    }
    verify(&mut r.st, &m, &gn, &mut vr).unwrap_or_else(|e| panic!("seed {seed} final: {e}"));
    note_runs(&r.st);
    note_lsm(&r.st);
    let n = check_no_leaks(&mut r);
    let live_objs: usize = m.colls.values().map(|v| v.len()).sum();
    assert_eq!(n, live_objs);
    r.clean_remount();
    verify(&mut r.st, &m, &gn, &mut vr)
        .unwrap_or_else(|e| panic!("seed {seed} after final remount: {e}"));
    r.ev + r
        .st
        .shards
        .iter()
        .map(|s| s.sh.tree_stats().evictions)
        .sum::<u64>()
}

#[test]
fn model_single_shard() {
    for seed in 1..=3 {
        run_model(seed, 1, 150, 60);
    }
}

#[test]
fn model_four_shards() {
    for seed in 10..=12 {
        run_model(seed, 4, 200, 90);
    }
}

#[test]
#[ignore = "soak"]
fn model_soak() {
    for seed in 100..140 {
        run_model(seed, if seed % 2 == 0 { 4 } else { 1 }, 600, 150);
    }
}

// ---------------------------------------------------------------------------------------------- crash

struct CrashRun {
    workload_events: u64,
    disk: SimDisk,
    st: St,
    /// fingerprints of the model after each submitted txn (index 0 = before any workload txn)
    fps: Vec<u64>,
    /// txn index (1-based) of each queued token
    acked: usize,
    queued: usize,
}

thread_local! {
    /// Storm percent for the crash generators of the current test thread (0 = off).
    static STORM: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    /// `ShardCfg::wal_coalesce` of the object crash matrix on this thread (`usize::MAX` = default).
    static COALESCE: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
    /// `ShardCfg::ckpt_slice` of the object crash matrix on this thread (`usize::MAX` = default).
    static SLICE: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
}

fn mkgen(seed: u64) -> Gen {
    let mut g = match STORM.get() {
        0 => Gen::new(seed, 1),
        p => {
            let mut g = Gen::with_storm(seed, 1, p, (0..12).map(|i| pgc(1, 200 + i)).collect());
            g.storm_budget = 150_000;
            g
        }
    };
    // adr 0021 am. 10: long omap keys in every crash/replay scenario; odd generator seeds use keys at the limit (3308 B
    // at 8 KiB pages: entries above psz/4, the split fallback, 512 B value chunks), even seeds keys of ~1.1 KB
    g.big_key = if seed % 2 == 1 { 3300 } else { 1100 };
    g.small_pct = SMALL_PCT.get();
    g.big_val_pct = BIGVAL_PCT.get();
    g.comp_val_pct = COMPVAL_PCT.get();
    g.comp_val_kinds = COMPVAL_KINDS.get();
    g.comp_pct = COMP_PCT.get();
    g.run_pct = RUN_PCT.get();
    pgmeta_gen(&mut g);
    longname_gen(&mut g);
    g
}

fn crash_workload(
    img: &SimImage,
    sim: &SimConfig,
    cfg: &StoreCfg,
    seed: u64,
    ntxn: usize,
    crash_at: Option<u64>,
    gen_seed: u64,
    lose: u8,
) -> CrashRun {
    let mut s2 = sim.clone();
    s2.seed = seed;
    let (disk, mut st) = open(img, &s2, cfg);
    let mut gn = mkgen(gen_seed);
    let c = c1();
    let mut model = Model::default();
    let mut t0 = OTxn::new();
    t0.mkcoll(c);
    t0.push(TOp::MkColl {
        cid: tmpc(1, 0),
        bits: 0,
        exist_ok: false,
    });
    st.commit(&t0).unwrap();
    model.apply_txn(&t0).unwrap();
    let mut fps = vec![model.fingerprint()];
    let started = disk.events();
    if lose > 0 {
        disk.lose_writes(lose);
    }
    if let Some(k) = crash_at {
        disk.arm_crash(disk.events() + k);
    }
    let (mut queued, mut acked) = (0usize, 0usize);
    let colls = [c, tmpc(1, 0)];
    let mut ackv = Vec::new();
    let mut pr = Rng::new(seed ^ 0xfeed);
    for i in 0..ntxn {
        let t = gn.txn(&model, &colls);
        if t.is_empty() {
            continue;
        }
        match st.queue(&t, i as u64 + 1) {
            Ok(_) => {
                model.apply_txn(&t).unwrap();
                fps.push(model.fingerprint());
                queued += 1;
                // map token -> queued index
                ackv.push(i as u64 + 1);
            }
            Err(_) if disk.crashed() => break,
            Err(e) => panic!("queue: {e:?}"),
        }
        if pr.pct(50) {
            let mut a = Vec::new();
            if st.poll(&mut a).is_err() {
                break;
            }
            acked += a.len();
        }
        if pr.pct(8) {
            st.shards[0].sh.request_checkpoint();
        }
        if pr.pct(10) {
            st.idle();
        }
    }
    if !disk.crashed() {
        let mut a = Vec::new();
        for _ in 0..200 {
            if st.poll(&mut a).is_err() {
                break;
            }
            st.idle();
        }
        acked += a.len();
    }
    CrashRun {
        workload_events: disk.events() - started,
        disk,
        st,
        fps,
        acked,
        queued,
    }
}

fn crash_check(
    img: &SimImage,
    sim: &SimConfig,
    cfg: &StoreCfg,
    seed: u64,
    ntxn: usize,
    k: Option<u64>,
    pol: CrashPolicy,
    gen_seed: u64,
    lose: u8,
) -> Result<(u64, bool), String> {
    let run = crash_workload(img, sim, cfg, seed, ntxn, k, gen_seed, lose);
    let crashed = run.disk.crashed();
    // acks counted include the setup txn? no: setup was committed before arming
    let (acked, queued) = (run.acked, run.queued);
    run.disk.crash_now();
    let cimg = run.disk.crash_image(pol);
    let fps = run.fps.clone();
    drop(run.st);
    // whatever root survived must be a consistent tree
    {
        let d = SimDisk::from_image(&cimg, sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        fsck(&mut dev, &mut clk, Some(&fsck_refs)).map_err(|e| format!("fsck crash image: {e}"))?;
    }
    let mut s2 = sim.clone();
    s2.seed = seed ^ 0x5a5a;
    let disk = SimDisk::from_image(&cimg, s2.clone());
    let d2 = disk.clone();
    let (mut st, _) = Store::mount(move || d2.queue(), SimClock::default(), cfg.clone())
        .map_err(|e| format!("mount: {e:?}"))?;
    // find which model prefix we recovered: replay the generator's model to compare
    let mut gn = mkgen(gen_seed);
    let mut m = Model::default();
    let c = c1();
    let mut t0 = OTxn::new();
    t0.mkcoll(c);
    t0.push(TOp::MkColl {
        cid: tmpc(1, 0),
        bits: 0,
        exist_ok: false,
    });
    m.apply_txn(&t0).unwrap();
    let colls = [c, tmpc(1, 0)];
    let mut prefixes: Vec<Model> = vec![m.clone()];
    let mut n = 0;
    while prefixes.len() <= queued {
        let t = gn.txn(&m, &colls);
        n += 1;
        if t.is_empty() {
            continue;
        }
        if m.apply_txn(&t).is_ok() {
            prefixes.push(m.clone());
        }
        assert!(n < 10_000);
    }
    debug_assert_eq!(
        prefixes.iter().map(|p| p.fingerprint()).collect::<Vec<_>>()
            [..fps.len().min(prefixes.len())],
        fps[..fps.len().min(prefixes.len())]
    );
    // candidate prefixes: setup + [acked, queued]
    let mut vr = Rng::new(seed);
    let mut found = None;
    for j in acked..=queued {
        if verify(&mut st, &prefixes[j], &mkgen(gen_seed), &mut vr).is_ok() {
            found = Some(j);
            break;
        }
    }
    let Some(j) = found else {
        let e = verify(&mut st, &prefixes[acked], &mkgen(gen_seed), &mut vr).unwrap_err();
        return Err(format!(
            "recovered state is no model prefix in [{acked},{queued}] (vs prefix {acked}: {e}) crashed={crashed}"
        ));
    };
    let _ = j;
    {
        let rep = st.check(true).map_err(|e| format!("check: {e:?}"))?;
        if !rep.errors.is_empty() {
            return Err(format!(
                "object layer check after recovery: {:?}",
                rep.errors
            ));
        }
    }
    // post-recovery: fsck after a checkpoint, no leaks, and the store keeps working
    st.checkpoint().map_err(|e| format!("ckpt: {e:?}"))?;
    let img2 = disk.image();
    {
        let d = SimDisk::from_image(&img2, sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        fsck(&mut dev, &mut clk, Some(&fsck_refs)).map_err(|e| format!("fsck after mount: {e}"))?;
    }
    let mut t = OTxn::new();
    t.write(c, &g(b"post", 1), 0, &[5u8; 6000]);
    st.commit(&t)
        .map_err(|e| format!("post-recovery commit: {e:?}"))?;
    Ok((j as u64, crashed))
}

fn crash_matrix(
    ntxn: usize,
    gen_seed: u64,
    policies: &[CrashPolicy],
    max_points: u64,
    stride: u64,
) -> (u64, u64) {
    let mut cfg = StoreCfg {
        shard: ShardCfg {
            ckpt_wal_pct: 4,
            ..StoreCfg::default().shard
        },
    };
    if COALESCE.get() != usize::MAX {
        cfg.shard.wal_coalesce = COALESCE.get();
    }
    if SLICE.get() != usize::MAX {
        cfg.shard.ckpt_slice = SLICE.get();
    }
    if COMPVAL_PCT.get() > 0 {
        cfg.shard.val_dict_samples = 8;
    }
    let cfg = runs_cfg(cfg);
    let cap = if STORM.get() > 0 { 128 } else { 24 };
    let mut sim = SimConfig::new(cap << 20);
    sim.seed = gen_seed;
    let img = fresh_image(cap, 1, 512, &sim);
    // dry run: number of device events of the workload
    let run = crash_workload(&img, &sim, &cfg, 1, ntxn, None, gen_seed, 0);
    let events = run.workload_events;
    EXT_SEEN.set(
        EXT_SEEN.get()
            + run
                .st
                .shards
                .iter()
                .map(|s| s.stats.ext_values)
                .sum::<u64>(),
    );
    VCOMP_SEEN.set(VCOMP_SEEN.get() + run.st.shards.iter().map(|s| s.stats.val_comp).sum::<u64>());
    note_runs(&run.st);
    note_lsm(&run.st);
    eprintln!(
        "crash matrix gen_seed {gen_seed}: workload = {events} device events, {} queued, {} acked",
        run.queued, run.acked
    );
    drop(run);
    let (mut scen, mut crashed_n) = (0, 0);
    let mut k = 0;
    while k < events.min(max_points) {
        for (pi, pol) in policies.iter().enumerate() {
            let seed = k * 7 + pi as u64 + 1;
            match crash_check(&img, &sim, &cfg, seed, ntxn, Some(k), *pol, gen_seed, 0) {
                Ok((_, c)) => {
                    scen += 1;
                    crashed_n += c as u64;
                }
                Err(e) => panic!("gen_seed {gen_seed} k={k} policy#{pi}: {e}"),
            }
        }
        k += stride;
    }
    (scen, crashed_n)
}

#[test]
fn crash_matrix_objects_every_io_boundary() {
    let (n, c) = crash_matrix(
        22,
        5,
        &[
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ],
        600,
        1,
    );
    assert!(n > 100 && c * 2 > n, "scenarios {n}, crashed {c}");
}

#[test]
fn crash_matrix_objects_more_seeds() {
    for gs in 6..9 {
        crash_matrix(18, gs, &[CrashPolicy::MIXED, CrashPolicy::DROP_ALL], 400, 3);
    }
}

#[test]
#[ignore = "soak"]
fn crash_matrix_objects_soak() {
    let mut tot = 0;
    for gs in 20..40 {
        tot += crash_matrix(
            14,
            gs,
            &[
                CrashPolicy::MIXED,
                CrashPolicy::DROP_ALL,
                CrashPolicy::PERSIST_ALL,
            ],
            1000,
            1,
        )
        .0;
    }
    println!("scenarios {tot}");
}

// ---------------------------------------------------------------------------------------------- perf

fn mib(b: f64, s: f64) -> f64 {
    b / s / (1 << 20) as f64
}

#[test]
#[ignore = "microbench: cargo test --release -p store --test obj perf -- --ignored --nocapture"]
fn perf_object_layer() {
    let cfg = StoreCfg::default();
    let mut sim = SimConfig::new(2 << 30);
    sim.seed = 5;
    let img = fresh_image(2048, 1, 16384, &sim);
    let (disk, mut st) = open(&img, &sim, &cfg);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut st, &t);
    // --- 4 MiB full writes
    let nobj: u32 = std::env::var("NOBJ")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(128);
    let blob = vec![0x5Au8; 4 << 20];
    let mut acked = Vec::new();
    let w = Instant::now();
    let v0 = st.clk.t;
    for i in 0..nobj {
        let mut t = OTxn::new();
        t.write(c, &g(format!("rbd_data.{i}").as_bytes(), i), 0, &blob);
        st.queue(&t, i as u64 + 1).unwrap();
        st.poll(&mut acked).unwrap();
        if i % 4 == 3 {
            st.idle();
        }
    }
    st.sync().unwrap();
    st.poll(&mut acked).unwrap();
    acked.clear();
    let (wall, virt) = (w.elapsed().as_secs_f64(), (st.clk.t - v0) as f64 / 1e9);
    println!(
        "4MiB full writes: {nobj} objs, wall {:.3}s ({:.0} MB/s), virtual device {:.3}s ({:.0} MB/s)",
        wall,
        mib(nobj as f64 * 4.0 * 1048576.0, wall),
        virt,
        mib(nobj as f64 * 4.0 * 1048576.0, virt)
    );
    // --- 4k random overwrites, 1 txn each, QD up to 16
    let n: u64 = std::env::var("NRW")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40_000);
    let mut rng = Rng::new(9);
    let w = Instant::now();
    let v0 = st.clk.t;
    let mut done = 0usize;
    let page = vec![0xC3u8; 4096];
    let mut inflight: usize = 0;
    for i in 0..n {
        let oi = rng.below(nobj as u64) as u32;
        let blk = rng.below(1024);
        let mut t = OTxn::new();
        t.write(
            c,
            &g(format!("rbd_data.{oi}").as_bytes(), oi),
            blk * 4096,
            &page,
        );
        st.queue(&t, 1_000_000 + i).unwrap();
        inflight += 1;
        acked.clear();
        st.poll(&mut acked).unwrap();
        done += acked.len();
        inflight -= acked.len();
        while inflight > 64 {
            st.idle();
            acked.clear();
            st.poll(&mut acked).unwrap();
            done += acked.len();
            inflight -= acked.len();
        }
    }
    st.sync().unwrap();
    st.poll(&mut acked).unwrap();
    acked.clear();
    let _ = done;
    let (wall, virt) = (w.elapsed().as_secs_f64(), (st.clk.t - v0) as f64 / 1e9);
    println!(
        "4k random overwrite txns: {n}, wall {:.3}s ({:.0} txn/s CPU-bound incl. sim), virtual {:.3}s ({:.0} txn/s)",
        wall,
        n as f64 / wall,
        virt,
        n as f64 / virt
    );
    // --- 64k random reads (cold-ish: object cache none; each read = lookup + extents + device read + crc)
    let nr: u64 = std::env::var("NRD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let w = Instant::now();
    let v0 = st.clk.t;
    for _ in 0..nr {
        let oi = rng.below(nobj as u64) as u32;
        let blk = rng.below(1024 - 16);
        let d = st
            .read(
                &c,
                &g(format!("rbd_data.{oi}").as_bytes(), oi),
                blk * 4096,
                65536,
            )
            .unwrap();
        assert_eq!(d.len(), 65536);
    }
    let (wall, virt) = (w.elapsed().as_secs_f64(), (st.clk.t - v0) as f64 / 1e9);
    println!(
        "64k random reads (QD1): {nr}, wall {:.3}s ({:.0} read/s), virtual {:.3}s ({:.0} read/s, {:.0} MB/s)",
        wall,
        nr as f64 / wall,
        virt,
        nr as f64 / virt,
        mib(nr as f64 * 65536.0, virt)
    );
    // --- typical replica write: new object, 4 KiB data + 2 xattrs (object_info, snapset) + pgmeta omap (log + info)
    let nn = 20_000u64;
    let (oi, ss) = (vec![7u8; 300], vec![8u8; 60]);
    let (logv, infov) = (vec![1u8; 200], vec![2u8; 600]);
    let pm = Ghobject::pgmeta(1, 0, ShardId::NO_SHARD);
    let w = Instant::now();
    let v0 = st.clk.t;
    inflight = 0;
    for i in 0..nn {
        let o = g(format!("new.{i}").as_bytes(), i as u32 * 2654435761);
        let mut t = OTxn::new();
        t.write(c, &o, 0, &page);
        t.setattr(c, &o, b"_", &oi);
        t.setattr(c, &o, b"snapset", &ss);
        let lk = format!("{:010}.{:020}", 5, i);
        t.omap_set(c, &pm, lk.as_bytes(), &logv);
        t.omap_set(c, &pm, b"_info", &infov);
        st.queue(&t, 2_000_000 + i).unwrap();
        inflight += 1;
        acked.clear();
        st.poll(&mut acked).unwrap();
        inflight -= acked.len();
        while inflight > 64 {
            st.idle();
            acked.clear();
            st.poll(&mut acked).unwrap();
            inflight -= acked.len();
        }
    }
    st.sync().unwrap();
    st.poll(&mut acked).unwrap();
    acked.clear();
    let (wall, virt) = (w.elapsed().as_secs_f64(), (st.clk.t - v0) as f64 / 1e9);
    println!(
        "replica-style txn (new obj: 4k + 2 attrs + log + info): {nn}, wall {:.3}s ({:.0} txn/s), virtual {:.3}s ({:.0} txn/s)",
        wall,
        nn as f64 / wall,
        virt,
        nn as f64 / virt
    );
    // --- listing
    let w = Instant::now();
    let mut cur = Ghobject::MIN();
    let mut total = 0;
    loop {
        let (v, n) = st.list(&c, &cur, None, 1000).unwrap();
        total += v.len();
        match n {
            Some(x) => cur = x,
            None => break,
        }
    }
    let wall = w.elapsed().as_secs_f64();
    println!(
        "list {total} objects (pages of 1000): {:.3}s ({:.0} obj/s)",
        wall,
        total as f64 / wall
    );
    // --- clone of a full 4 MiB object (copy based)
    let w = Instant::now();
    let v0 = st.clk.t;
    for i in 0..16u32 {
        let mut t = OTxn::new();
        t.push(TOp::Clone {
            cid: c,
            src: g(b"rbd_data.0", 0),
            dst: g(format!("clone.{i}").as_bytes(), i),
        });
        st.commit(&t).unwrap();
    }
    let (wall, virt) = (w.elapsed().as_secs_f64(), (st.clk.t - v0) as f64 / 1e9);
    println!(
        "clone 4 MiB (copy, read+write): 16 clones, wall {:.1} ms/clone, virtual {:.1} ms/clone",
        wall * 1e3 / 16.0,
        virt * 1e3 / 16.0
    );
    let _ = disk;
}

#[test]
fn crash_checker_is_not_vacuous_lost_writes() {
    let cfg = StoreCfg {
        shard: ShardCfg {
            ckpt_wal_pct: 4,
            ..StoreCfg::default().shard
        },
    };
    let mut sim = SimConfig::new(24 << 20);
    sim.seed = 3;
    let img = fresh_image(24, 1, 512, &sim);
    let mut flagged = 0;
    for s in 0..24u64 {
        // device acks writes it never persisted: acked txns vanish; the checker must notice (usually)
        if crash_check(
            &img,
            &sim,
            &cfg,
            100 + s,
            16,
            None,
            CrashPolicy::DROP_ALL,
            9,
            25,
        )
        .is_err()
        {
            flagged += 1;
        }
    }
    assert!(flagged >= 12, "only {flagged}/24 lost-write runs flagged");
}

#[test]
fn verify_detects_divergence() {
    let mut r = rig(32, 1);
    let c = c1();
    let mut m = Model::default();
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.write(c, &g(b"a", 1), 0, &[1u8; 5000]);
    commit(&mut r.st, &t);
    m.apply_txn(&t).unwrap();
    let gn = Gen::new(1, 1);
    let mut vr = Rng::new(1);
    // Gen's universe does not contain "a": add it to the checked set via a custom Gen
    let mut gn2 = gn;
    gn2.objs.push(g(b"a", 1));
    verify(&mut r.st, &m, &gn2, &mut vr).unwrap();
    m.colls
        .get_mut(&c)
        .unwrap()
        .get_mut(&g(b"a", 1))
        .unwrap()
        .data[4999] = 2;
    assert!(verify(&mut r.st, &m, &gn2, &mut vr).is_err());
}

#[test]
fn txn_size_limits() {
    let mut r = rig_nvc(64, 1);
    let c = c1();
    let o = g(b"big", 1);
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    // 8 MiB write in ONE txn (2048 blocks: ~16 KiB of crcs in the record)
    let blob: Vec<u8> = (0..8u32 << 20).map(|i| (i / 4096 + i) as u8).collect();
    let mut t = OTxn::new();
    t.write(c, &o, 0, &blob);
    commit(&mut r.st, &t);
    assert_eq!(
        r.st.read(&c, &o, 4_000_000, 100_000).unwrap(),
        blob[4_000_000..4_100_000]
    );
    // ~200 KiB of omap in one txn fits one WAL record (max_unit_blocks 64); 600 KiB is a multi-part txn
    // (ADR 0028); only a txn beyond ~ring/2 is TooLarge
    let vals: Vec<Vec<u8>> = (0..100u32).map(|i| vec![i as u8; 2000]).collect();
    let keys: Vec<Vec<u8>> = (0..100u32)
        .map(|i| format!("k{i:03}").into_bytes())
        .collect();
    let mut t = OTxn::new();
    for (k, v) in keys.iter().zip(&vals) {
        t.omap_set(c, &o, k, v);
    }
    commit(&mut r.st, &t);
    let vals2: Vec<Vec<u8>> = (0..300u32).map(|i| vec![i as u8; 2000]).collect();
    let keys2: Vec<Vec<u8>> = (0..300u32)
        .map(|i| format!("z{i:03}").into_bytes())
        .collect();
    let mut t = OTxn::new();
    for (k, v) in keys2.iter().zip(&vals2) {
        t.omap_set(c, &o, k, v);
    }
    r.st.commit(&t).unwrap();
    assert_eq!(r.st.omap_all(&c, &o).unwrap().len(), 400);
    let keys3: Vec<Vec<u8>> = (0..2000u32)
        .map(|i| format!("y{i:04}").into_bytes())
        .collect();
    let mut t = OTxn::new();
    for k in &keys3 {
        t.omap_set(c, &o, k, &vals2[0]);
    }
    let free = r.st.statfs().avail_bytes;
    assert_eq!(r.st.commit(&t), Err(ObjError::TooLarge));
    assert_eq!(r.st.statfs().avail_bytes, free);
    assert_eq!(r.st.omap_all(&c, &o).unwrap().len(), 400);
    assert_eq!(check_no_leaks(&mut r), 1);
}

#[test]
fn big_omap_small_cache_with_misses() {
    // 4 KiB tree nodes, 128-page cache: a 30000-key keyspace omap spans several times the cache; point gets, scans, key and range
    // removals run against constant evictions and page-load misses (inside staging and at submit).
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: 96,
            ..StoreCfg::default().shard
        },
    };
    let (mut r, _) = rig_ns(64, 1, 1024, 77, cfg, 4096);
    let c = c1();
    let o = g(b"idx", 5);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.touch(c, &o);
    commit(&mut r.st, &t);
    let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut rng = Rng::new(5);
    let key = |i: u64| format!("key/{i:08}").into_bytes();
    let mut ops = 0;
    for round in 0..1600u64 {
        let mut t = OTxn::new();
        match rng.below(10) {
            0..=6 => {
                let mut pairs = vec![];
                for _ in 0..6 {
                    let k = key(rng.below(30_000));
                    let mut v = vec![0u8; rng.range(10, 120) as usize];
                    rng.fill(&mut v);
                    model.insert(k.clone(), v.clone());
                    pairs.push((TxnBytes::Owned(k), TxnBytes::Owned(v)));
                }
                t.push(TOp::OmapSetKeys {
                    cid: c,
                    oid: o.clone(),
                    pairs,
                });
            }
            7..=8 => {
                let ks: Vec<_> = (0..3).map(|_| key(rng.below(30_000))).collect();
                ks.iter().for_each(|k| {
                    model.remove(k);
                });
                t.push(TOp::OmapRmKeys {
                    cid: c,
                    oid: o.clone(),
                    keys: ks.into_iter().map(Into::into).collect(),
                });
            }
            _ => {
                let a = rng.below(29_900);
                let (f, l) = (key(a), key(a + rng.range(1, 60)));
                model.retain(|k, _| !(k >= &f && k < &l));
                t.push(TOp::OmapRmKeyRange {
                    cid: c,
                    oid: o.clone(),
                    first: f.into(),
                    last: l.into(),
                });
            }
        }
        r.st.commit(&t)
            .unwrap_or_else(|e| panic!("round {round}: {e:?}"));
        ops += 1;
        if round % 50 == 49 {
            let got = r.st.omap_all(&c, &o).unwrap();
            assert_eq!(got, model, "round {round}");
            let probe: Vec<Vec<u8>> = (0..20).map(|_| key(rng.below(30_000))).collect();
            let refs: Vec<&[u8]> = probe.iter().map(|k| k.as_slice()).collect();
            let got = r.st.omap_get(&c, &o, &refs).unwrap();
            for k in &probe {
                assert_eq!(got.get(k), model.get(k));
            }
        }
        if round % 60 == 59 {
            r.st.checkpoint().unwrap();
        }
        if round == 800 {
            r.clean_remount();
        }
    }
    let ev: u64 = r.ev + r.st.shards[0].sh.tree_stats().evictions;
    assert!(ev > 200, "only {ev} evictions");
    assert!(ops > 1500);
    let rep = r.st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}

#[test]
#[ignore = "microbench"]
fn perf_mount_32_shards() {
    let cfg = StoreCfg::default();
    let mut sim = SimConfig::new(4u64 << 30);
    sim.seed = 2;
    let img = fresh_image(4096, 32, 16384, &sim);
    let (disk, mut st) = open(&img, &sim, &cfg);
    // PGs spread over all shards, a few thousand objects each with attrs/omap
    let mut n = 0u64;
    for pg in 0..64u32 {
        let c = pgc(1, pg);
        let mut t = OTxn::new();
        t.mkcoll(c);
        st.commit(&t).unwrap();
        for i in 0..150u32 {
            let mut t = OTxn::new();
            let o = g(format!("o{pg}.{i}").as_bytes(), i * 977 + pg);
            t.write(c, &o, 0, &[3u8; 4096]);
            t.setattr(c, &o, b"_", &[1u8; 300]);
            t.omap_set(c, &o, b"k", b"v");
            st.queue(&t, n + 1).unwrap();
            n += 1;
        }
    }
    st.sync().unwrap();
    // crash right now (WAL replay on every shard), then mount
    disk.crash_now();
    let img2 = disk.crash_image(CrashPolicy::PERSIST_ALL);
    let d2 = SimDisk::from_image(&img2, sim.clone());
    let d3 = d2.clone();
    let w = Instant::now();
    let (st2, stats) = Store::mount(move || d3.queue(), SimClock::default(), cfg.clone()).unwrap();
    let wall = w.elapsed().as_secs_f64();
    let replayed: u64 = stats.iter().map(|s| s.txns).sum();
    println!(
        "mount 32 shards after crash: {n} objects, {replayed} txns replayed, wall {:.1} ms, virtual device {:.1} ms",
        wall * 1e3,
        st2.clk.t as f64 / 1e6
    );
    drop(st2);
}

// ---------------------------------------------------------------------------------------------- storms

#[test]
fn model_many_op_storms_single_shard() {
    for seed in 300..304 {
        run_model_cfg(seed, 1, 250, 80, StoreCfg::default(), 8192, 25);
    }
}

#[test]
fn model_many_op_storms_small_pages_four_shards() {
    for seed in 310..313 {
        run_model_cfg(seed, 4, 250, 90, StoreCfg::default(), 4096, 25);
    }
}

#[test]
#[ignore = "soak"]
fn model_storm_soak() {
    for seed in 400..440 {
        let node = if seed % 3 == 0 { 4096 } else { 8192 };
        run_model_cfg(
            seed,
            if seed % 2 == 0 { 4 } else { 1 },
            500,
            120,
            StoreCfg::default(),
            node,
            20 + (seed % 5) as u8 * 8,
        );
    }
}

#[test]
fn crash_matrix_objects_many_op_storms() {
    STORM.set(30);
    let (n, c) = crash_matrix(
        14,
        50,
        &[
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ],
        500,
        2,
    );
    assert!(n > 100 && c * 2 > n, "scenarios {n}, crashed {c}");
    STORM.set(0);
}

/// Elastic meta space (adr 0021 am. 12) under object-level crash workloads: a 1% base area, tree pages come from
/// cells carved out of the data region (and go back when the storms wipe them).
#[test]
fn crash_matrix_objects_elastic_meta() {
    META_PCT.set(1);
    STORM.set(25);
    let (n, c) = crash_matrix(
        16,
        90,
        &[
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ],
        500,
        2,
    );
    assert!(n > 100 && c * 2 > n, "scenarios {n}, crashed {c}");
    STORM.set(0);
    crash_matrix(14, 91, &[CrashPolicy::MIXED, CrashPolicy::DROP_ALL], 400, 3);
    META_PCT.set(8);
}

#[test]
fn model_elastic_meta_small_base() {
    META_PCT.set(1);
    for seed in 20..=22 {
        run_model_cfg(seed, 4, 200, 60, StoreCfg::default(), 4096, 25);
    }
    META_PCT.set(8);
}

#[test]
fn crash_matrix_objects_many_op_storms_more_seeds() {
    STORM.set(35);
    for gs in 51..54 {
        crash_matrix(12, gs, &[CrashPolicy::MIXED, CrashPolicy::DROP_ALL], 400, 3);
    }
    STORM.set(0);
}

#[test]
#[ignore = "soak"]
fn crash_matrix_objects_storm_soak() {
    STORM.set(30);
    let mut tot = 0;
    for gs in 60..80 {
        tot += crash_matrix(
            14,
            gs,
            &[
                CrashPolicy::MIXED,
                CrashPolicy::DROP_ALL,
                CrashPolicy::PERSIST_ALL,
            ],
            1000,
            2,
        )
        .0;
    }
    println!("scenarios {tot}");
    STORM.set(0);
}

#[test]
fn warm_is_nonblocking_and_covers_the_op_path() {
    // ADR 0021 am. 8: `warm` never waits; once it says ready, stat/getattr/read of the object load no tree page.
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: 96,
            ..StoreCfg::default().shard
        },
    };
    let (mut r, _) = rig_ns(64, 1, 1024, 91, cfg, 4096);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let n = 2500u32;
    for i in 0..n {
        let mut t = OTxn::new();
        let o = g(format!("obj-{i:06}").as_bytes(), i);
        let (data, oi) = (vec![(i % 251) as u8; 4096], format!("oi{i}"));
        t.write(c, &o, 0, &data);
        t.setattr(c, &o, b"_", oi.as_bytes());
        commit(&mut r.st, &t);
    }
    r.clean_remount(); // cold cache
    let mut rng = Rng::new(3);
    let (mut cold, mut loads_in_op) = (0, 0);
    for _ in 0..300 {
        let i = rng.below(n as u64 + 200) as u32; // some names do not exist
        let o = g(format!("obj-{i:06}").as_bytes(), i);
        let mut spins = 0;
        while !r.st.warm(&c, &o, 0, 4096).unwrap() {
            cold += 1;
            spins += 1;
            assert!(spins < 100_000, "page load never completed");
            let mut acked = vec![];
            r.st.poll(&mut acked).unwrap();
            if !r.st.take_wake() {
                r.st.idle();
            }
        }
        let before = r.st.shards[0].sh.tree_stats().loads;
        let st = r.st.stat(&c, &o).unwrap();
        let at = r.st.getattr(&c, &o, b"_");
        let rd = r.st.read(&c, &o, 0, 4096);
        loads_in_op += r.st.shards[0].sh.tree_stats().loads - before;
        if i < n {
            assert_eq!(st.unwrap().size, 4096);
            assert_eq!(at.unwrap().unwrap(), format!("oi{i}").into_bytes());
            assert_eq!(rd.unwrap(), vec![(i % 251) as u8; 4096]);
        } else {
            assert!(st.is_none());
        }
    }
    assert!(cold > 50, "cache was not cold ({cold})");
    assert_eq!(
        loads_in_op, 0,
        "op blocked on a page that warm had reported ready"
    );
}

#[test]
fn warm_rm_covers_every_page_of_a_removal() {
    // adr 0021 am. 33: once `warm_rm` says ready, the remove txn (stage + submit) loads no tree page; it never waits.
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: 96,
            ..StoreCfg::default().shard
        },
    };
    let (mut r, _) = rig_ns(64, 1, 1024, 93, cfg, 4096);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let n = 1500u32;
    let data = vec![7u8; 3 * 4096];
    for i in 0..n {
        let mut t = OTxn::new();
        let o = g(format!("obj-{i:06}").as_bytes(), i);
        t.write(c, &o, 0, &data[..(1 + i as usize % 3) * 4096]);
        t.setattr(c, &o, b"_", &[1u8; 250]);
        t.setattr(c, &o, b"snapset", &[2u8; 32]);
        if i % 4 == 0 {
            t.omap_set(c, &o, b"k1", b"v1");
            t.omap_set(c, &o, b"k2", &[3u8; 600]);
        }
        commit(&mut r.st, &t);
    }
    // every 7th object also has a clone sharing its extents (am. 32): its removal rewrites refcount records
    for i in (0..n).step_by(7) {
        let mut t = OTxn::new();
        let (o, cl) = (
            g(format!("obj-{i:06}").as_bytes(), i),
            g(format!("cln-{i:06}").as_bytes(), i),
        );
        t.push(TOp::Clone {
            cid: c,
            src: o,
            dst: cl,
        });
        commit(&mut r.st, &t);
    }
    r.clean_remount(); // cold cache
    let mut rng = Rng::new(5);
    let (mut cold, mut loads_in_op, mut max_spins) = (0, 0, 0);
    let mut gone = std::collections::BTreeSet::new();
    for _ in 0..400 {
        let i = rng.below(n as u64 + 100) as u32; // some names do not exist, some are removed already
        let pfx: &[&str] = if i.is_multiple_of(7) {
            &["obj", "cln"]
        } else {
            &["obj"]
        };
        for p in pfx {
            let o = g(format!("{p}-{i:06}").as_bytes(), i);
            let mut spins = 0;
            while !r.st.warm_rm(&c, &o).unwrap() {
                cold += 1;
                spins += 1; // one probe round: wait until every read it queued is in
                let mut polls = 0;
                loop {
                    let mut acked = vec![];
                    r.st.poll(&mut acked).unwrap();
                    if !r.st.loads_pending() {
                        break;
                    }
                    polls += 1;
                    assert!(polls < 100_000, "page load never completed");
                    r.st.idle();
                }
            }
            max_spins = max_spins.max(spins);
            let before = r.st.shards[0].sh.tree_stats().loads;
            let mut t = OTxn::new();
            t.remove(c, &o);
            commit(&mut r.st, &t);
            loads_in_op += r.st.shards[0].sh.tree_stats().loads - before;
            assert!(!r.st.exists(&c, &o).unwrap());
        }
        if i < n {
            gone.insert(i);
        }
    }
    assert!(cold > 50, "cache was not cold ({cold})");
    // name, then the object's pages in parallel: one round per tree level for each
    assert!(max_spins <= 8, "warm_rm needed {max_spins} rounds");
    assert_eq!(
        loads_in_op, 0,
        "a removal blocked on a page warm_rm reported ready"
    );
    for i in 0..n {
        let o = g(format!("obj-{i:06}").as_bytes(), i);
        assert_eq!(r.st.exists(&c, &o).unwrap(), !gone.contains(&i), "obj {i}");
    }
}

/// Poll an idle store until the background compaction queue is empty (adr 0021 am. 33); returns the merges it made.
fn drain_compaction(st: &mut St) -> u64 {
    let m0: u64 = st.shards.iter().map(|s| s.sh.tree_stats().compacted).sum();
    for _ in 0..1_000_000 {
        if st
            .shards
            .iter()
            .all(|s| s.sh.state().tree.compact_pending() == 0)
        {
            break;
        }
        let mut acked = vec![];
        st.poll(&mut acked).unwrap();
        st.idle();
    }
    st.shards
        .iter()
        .map(|s| s.sh.tree_stats().compacted)
        .sum::<u64>()
        - m0
}

fn leaves_of(img: &SimImage, sim: &SimConfig) -> u64 {
    let d = SimDisk::from_image(img, sim.clone());
    let mut dev = d.queue();
    let mut clk = SimClock::default();
    let reps = fsck(&mut dev, &mut clk, Some(&fsck_refs)).unwrap();
    reps.iter().map(|r| r.leaves).sum()
}

/// Sparse-leaf workload for the compaction tests: `n` objects (1 block + `_` attr), cold remount, then 75 % removed in
/// random order one per txn with a tiny cache, so most thinned leaves have cold neighbours. Returns the survivors.
fn sparse_after_random_removes(r: &mut Rig, n: u32, seed: u64) -> Vec<u32> {
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    for i in 0..n {
        let mut t = OTxn::new();
        let o = g(format!("obj-{i:06}").as_bytes(), i);
        let (d, a) = ([(i % 251) as u8; 4096], [(i % 13) as u8; 250]);
        t.write(c, &o, 0, &d);
        t.setattr(c, &o, b"_", &a);
        commit(&mut r.st, &t);
    }
    r.clean_remount();
    let mut ids: Vec<u32> = (0..n).collect();
    let mut rng = Rng::new(seed);
    for i in (1..ids.len()).rev() {
        ids.swap(i, rng.below(i as u64 + 1) as usize);
    }
    let (rm, keep) = ids.split_at(n as usize * 3 / 4);
    for &i in rm {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("obj-{i:06}").as_bytes(), i));
        commit(&mut r.st, &t);
    }
    let mut keep = keep.to_vec();
    keep.sort_unstable();
    keep
}

fn check_survivors(st: &mut St, n: u32, keep: &[u32]) -> Result<(), String> {
    let c = c1();
    for i in 0..n {
        let o = g(format!("obj-{i:06}").as_bytes(), i);
        let live = keep.binary_search(&i).is_ok();
        let ex = st
            .exists(&c, &o)
            .map_err(|e| format!("exists {i}: {e:?}"))?;
        if ex != live {
            return Err(format!("obj {i}: exists {ex}, expected {live}"));
        }
        if live {
            let at = st.getattr(&c, &o, b"_").map_err(|e| format!("{e:?}"))?;
            if at != Some(vec![(i % 13) as u8; 250]) {
                return Err(format!("obj {i}: attr"));
            }
            let d = st.read(&c, &o, 0, 4096).map_err(|e| format!("{e:?}"))?;
            if d != vec![(i % 251) as u8; 4096] {
                return Err(format!("obj {i}: data"));
            }
        }
    }
    Ok(())
}

fn compaction_cfg() -> StoreCfg {
    StoreCfg {
        shard: ShardCfg {
            cache_pages: 48,
            ..StoreCfg::default().shard
        },
    }
}

#[test]
fn background_compaction_merges_sparse_leaves_with_cold_neighbours() {
    // adr 0021 am. 33: random removals with a cold cache leave thinned leaves the txn-time merge (am. 29, resident
    // neighbours only) cannot take; the background step reads the neighbours and merges them, content unchanged.
    let (mut r, _) = rig_ns(64, 1, 1024, 95, compaction_cfg(), 4096);
    let n = 12000;
    let keep = sparse_after_random_removes(&mut r, n, 7);
    r.st.checkpoint().unwrap();
    let before = leaves_of(&r.disk.image(), &r.sim);
    let queued = r.st.shards[0].sh.state().tree.compact_pending();
    assert!(queued > 20, "candidates queued {queued}");
    let merged = drain_compaction(&mut r.st);
    assert!(merged > 20, "background merges {merged}");
    r.st.checkpoint().unwrap();
    let after = leaves_of(&r.disk.image(), &r.sim);
    assert!(
        after * 10 < before * 8,
        "leaves {before} -> {after} after {merged} merges"
    );
    check_survivors(&mut r.st, n, &keep).unwrap();
    check_no_leaks(&mut r);
    r.clean_remount();
    check_survivors(&mut r.st, n, &keep).unwrap();
}

#[test]
fn background_compaction_crash_matrix() {
    // adr 0021 am. 33: a crash at any device event of the compaction phase (reads, merges, the checkpoints that persist
    // them) recovers the same content under every crash policy, fsck clean, and compaction then finishes. The queue is
    // RAM state, so every run rebuilds the same sparse store (deterministic) and crashes it k events into the phase.
    let n = 5000;
    let sparse = || {
        let (mut r, _) = rig_ns(64, 1, 1024, 96, compaction_cfg(), 4096);
        let keep = sparse_after_random_removes(&mut r, n, 9);
        r.st.sync().unwrap();
        (r, keep)
    };
    let (mut r, keep) = sparse();
    let e0 = r.disk.events();
    assert!(drain_compaction(&mut r.st) > 5);
    r.st.checkpoint().unwrap();
    let total = r.disk.events() - e0;
    assert!(total > 10, "events {total}");
    let mut runs = 0;
    for k in (0..total).step_by((total as usize / 12).max(1)) {
        for pol in [
            CrashPolicy::MIXED,
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
        ] {
            let (mut r2, keep2) = sparse();
            assert_eq!(keep2, keep);
            r2.disk.arm_crash(r2.disk.events() + k);
            // the device dies under the running compaction: errors are expected from here on
            for _ in 0..200_000 {
                let mut acked = vec![];
                if r2.st.poll(&mut acked).is_err() || r2.disk.crashed() {
                    break;
                }
                if r2.st.shards[0].sh.state().tree.compact_pending() == 0 {
                    let _ = r2.st.checkpoint();
                    break;
                }
                r2.st.idle();
            }
            r2.disk.crash_now();
            let img = r2.disk.crash_image(pol);
            r2.fsck_img(&img);
            let (_, mut st) = open(&img, &r2.sim, &r2.cfg);
            check_survivors(&mut st, n, &keep).unwrap_or_else(|e| panic!("k {k} {pol:?}: {e}"));
            st.checkpoint().unwrap();
            runs += 1;
        }
    }
    assert!(runs >= 36, "runs {runs}");
}

/// Aged data region for the defrag tests: `n` one-block objects written back to back, then all but every 10th removed
/// (windows ~10 % live), checkpointed so the freed blocks are free. Returns the survivors.
fn fragmented_store(r: &mut Rig, n: u32) -> Vec<u32> {
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    for i in 0..n {
        let mut t = OTxn::new();
        let o = g(format!("obj-{i:06}").as_bytes(), i);
        let (d, a) = ([(i % 251) as u8; 4096], [(i % 13) as u8; 250]);
        t.write(c, &o, 0, &d);
        t.setattr(c, &o, b"_", &a);
        commit(&mut r.st, &t);
    }
    let keep: Vec<u32> = (0..n).filter(|i| i % 10 == 3).collect();
    for i in (0..n).filter(|i| i % 10 != 3) {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("obj-{i:06}").as_bytes(), i));
        commit(&mut r.st, &t);
    }
    r.st.checkpoint().unwrap();
    r.st.checkpoint().unwrap();
    keep
}

/// Run defrag on an otherwise idle store until it stops starting sweeps (or `max` sweeps ran): sim time jumps over the
/// check interval between sweeps, a checkpoint first releases the blocks the last sweep freed. Returns the sweeps run.
fn run_defrag(st: &mut St, max: u64) -> Result<u64, ObjError> {
    let s0 = st.shards[0].defrag_stats().sweeps;
    let mut idle_checks = 0;
    for _ in 0..2_000_000 {
        let mut acked = vec![];
        st.poll(&mut acked)?;
        let done = st.shards[0].defrag_stats().sweeps - s0;
        if done >= max || idle_checks > 3 {
            return Ok(done);
        }
        if st.shards[0].defrag_active() {
            idle_checks = 0;
        } else {
            st.checkpoint()?;
            st.clk.t += 2_000_000_000;
            idle_checks += 1;
        }
        st.idle();
    }
    panic!("defrag sweeps never finished");
}

fn defrag_cfg() -> StoreCfg {
    StoreCfg {
        shard: ShardCfg {
            bg_compact: false,
            ..StoreCfg::default().shard
        },
    }
}

/// Sparse windows that hold only xattr values in data blocks (am. 46: no extent record, nothing the data mover moves):
/// `n` one-block objects written back to back, every 10th an xattr-only object with a one-block value, the rest removed
/// and checkpointed. Returns the survivors.
fn sparse_xattr_values(r: &mut Rig, n: u32) -> Vec<u32> {
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let keep: Vec<u32> = (0..n).filter(|i| i % 10 == 3).collect();
    for i in 0..n {
        let o = g(format!("obj-{i:06}").as_bytes(), i);
        let d = [(i % 251) as u8; 4096];
        let mut t = OTxn::new();
        if i % 10 == 3 {
            t.touch(c, &o);
            t.setattr(c, &o, b"_", &d);
        } else {
            t.write(c, &o, 0, &d);
        }
        commit(&mut r.st, &t);
    }
    for i in (0..n).filter(|i| i % 10 != 3) {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("obj-{i:06}").as_bytes(), i));
        commit(&mut r.st, &t);
    }
    r.st.checkpoint().unwrap();
    r.st.checkpoint().unwrap();
    keep
}

/// Polls of an otherwise idle store over `secs` sim seconds (2 s steps): the mover's checks run, nothing else does.
fn idle_secs(st: &mut St, secs: u64) -> store::obj::DefragStats {
    for _ in 0..secs / 2 {
        let mut acked = vec![];
        st.poll(&mut acked).unwrap();
        st.clk.t += 2_000_000_000;
        st.idle();
    }
    st.shards[0].defrag_stats()
}

/// [`idle_secs`] until no mover pass runs and none started or ended for 60 s (every candidate tried); the stats then.
/// Fails after `max_secs`.
fn idle_until_quiet(st: &mut St, max_secs: u64) -> store::obj::DefragStats {
    let mut last = st.shards[0].defrag_stats();
    for _ in 0..max_secs / 60 {
        let d = idle_secs(st, 60);
        let ev = |d: &store::obj::DefragStats| (d.sweeps, d.cell_sweeps, d.evacs);
        if !st.shards[0].defrag_active() && ev(&d) == ev(&last) {
            return d;
        }
        last = d;
    }
    panic!("mover not quiet after {max_secs} idle s: {last:?}");
}

#[test]
fn idle_fragmented_shard_without_movable_blocks_stops_its_sweeps() {
    // adr 0021 am. 79: free space spread over windows about a tenth used by xattr values (no extent record: nothing to
    // move), few whole windows. Each window is tried once and stays given up while its blocks stay (before: picked again
    // at every check, each time a whole extent pass; tsrv2 at 96 % fill: 218 passes, 30 GB read in 900 idle seconds).
    let (mut r, _) = rig_ns(64, 1, 1024, 97, defrag_cfg(), 4096);
    let keep = sparse_xattr_values(&mut r, 9000);
    let a = &r.st.shards[0].sh.state().alloc;
    let sparse = (0..a.n_windows())
        .filter(|&w| (1..=store::alloc::WIN / 8).contains(&a.window_busy(w)))
        .count() as u64;
    assert!(
        sparse >= 20 && a.free_windows() < 64,
        "fixture: {sparse} sparse windows, {} whole",
        a.free_windows()
    );
    let s1 = idle_until_quiet(&mut r.st, 3600);
    assert!((1..=sparse).contains(&s1.sweeps), "{sparse} sparse: {s1:?}");
    assert_eq!(s1.moved_extents, 0, "{s1:?}");
    let d0 = r.disk.stats();
    let s2 = idle_secs(&mut r.st, 600);
    assert_eq!(s2.sweeps, s1.sweeps, "idle retries: {s2:?}");
    assert_eq!(r.disk.stats().read_lbas, d0.read_lbas, "blocks read idle");
    let c = c1();
    for &i in &keep {
        let o = g(format!("obj-{i:06}").as_bytes(), i);
        let v = r.st.getattr(&c, &o, b"_").unwrap();
        assert_eq!(v, Some(vec![(i % 251) as u8; 4096]), "obj {i}");
    }
    check_no_leaks(&mut r);
}

#[test]
fn defrag_moves_live_blocks_out_of_sparse_windows() {
    // adr 0021 am. 33: after random-ish removals the free space is spread over windows that each keep a few live blocks
    // (no whole 1 MiB run left for a meta cell or a 64-block extent); sweeps move those blocks out, content unchanged.
    let (mut r, _) = rig_ns(64, 1, 1024, 97, defrag_cfg(), 4096);
    let n = 9000;
    let keep = fragmented_store(&mut r, n);
    // the survivors of the first windows share their block with a clone (am. 32): those windows stay pinned
    let c = c1();
    let cloned: Vec<u32> = keep.iter().copied().filter(|&i| i < 1500).collect();
    for &i in &cloned {
        let mut t = OTxn::new();
        t.push(TOp::Clone {
            cid: c,
            src: g(format!("obj-{i:06}").as_bytes(), i),
            dst: g(format!("cln-{i:06}").as_bytes(), i),
        });
        commit(&mut r.st, &t);
    }
    let w0 = r.st.shards[0].sh.state().alloc.free_windows();
    let sweeps = run_defrag(&mut r.st, 10).unwrap();
    assert!(sweeps >= 2, "sweeps {sweeps}");
    r.st.checkpoint().unwrap();
    r.st.checkpoint().unwrap();
    let w1 = r.st.shards[0].sh.state().alloc.free_windows();
    let ds = r.st.shards[0].defrag_stats();
    assert!(ds.moved_extents > 100, "{ds:?}");
    assert!(w1 >= w0 + 10, "whole free windows {w0} -> {w1}, {ds:?}");
    check_survivors(&mut r.st, n, &keep).unwrap();
    for &i in &cloned {
        let o = g(format!("cln-{i:06}").as_bytes(), i);
        assert_eq!(
            r.st.read(&c, &o, 0, 4096).unwrap(),
            vec![(i % 251) as u8; 4096]
        );
    }
    check_no_leaks(&mut r);
    r.clean_remount();
    check_survivors(&mut r.st, n, &keep).unwrap();
    // a dense store is left alone
    let (mut r2, _) = rig_ns(64, 1, 1024, 97, defrag_cfg(), 4096);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r2.st, &t);
    let mut t = OTxn::new();
    let d = vec![1u8; 1 << 20];
    t.write(c, &g(b"big", 1), 0, &d);
    commit(&mut r2.st, &t);
    run_defrag(&mut r2.st, 0).unwrap();
    for _ in 0..100 {
        let mut acked = vec![];
        r2.st.poll(&mut acked).unwrap();
        r2.st.clk.t += 2_000_000_000;
    }
    assert_eq!(r2.st.shards[0].defrag_stats().sweeps, 0);
    // kill switch
    let mut cfg = defrag_cfg();
    cfg.shard.defrag = false;
    let (mut r3, _) = rig_ns(64, 1, 1024, 97, cfg, 4096);
    fragmented_store(&mut r3, 3000);
    for _ in 0..1000 {
        let mut acked = vec![];
        r3.st.poll(&mut acked).unwrap();
        r3.st.clk.t += 2_000_000_000;
    }
    assert_eq!(r3.st.shards[0].defrag_stats().moved_extents, 0);
}

#[test]
fn defrag_never_moves_a_record_that_changed_meanwhile() {
    // client txns between the read of an extent and its move (overwrite, remove) win: the move is skipped, the new data stays.
    // The race below is tuned to the synchronous checkpoint start (its page writes delay the sweep's reads).
    let mut cfg = defrag_cfg();
    cfg.shard.ckpt_slice = 0;
    let (mut r, _) = rig_ns(64, 1, 1024, 98, cfg, 4096);
    let n = 9000;
    let keep = fragmented_store(&mut r, n);
    let c = c1();
    // start a sweep, then race it with client writes on the survivors
    let mut acked = vec![];
    r.st.poll(&mut acked).unwrap();
    assert!(r.st.shards[0].defrag_active(), "sweep started");
    let mut rewritten = BTreeSet::new();
    for (k, &i) in keep.iter().enumerate() {
        if k % 3 == 0 {
            let mut t = OTxn::new();
            let o = g(format!("obj-{i:06}").as_bytes(), i);
            let d = [0xEEu8; 4096];
            t.write(c, &o, 0, &d);
            r.st.queue(&t, 1_000_000 + k as u64).unwrap();
            rewritten.insert(i);
        }
        r.st.poll(&mut acked).unwrap();
        r.st.idle();
    }
    run_defrag(&mut r.st, 2).unwrap();
    let ds = r.st.shards[0].defrag_stats();
    assert!(ds.moved_extents > 0 && ds.skipped > 0, "{ds:?}");
    r.st.sync().unwrap();
    for &i in &keep {
        let o = g(format!("obj-{i:06}").as_bytes(), i);
        let want = if rewritten.contains(&i) {
            0xEE
        } else {
            (i % 251) as u8
        };
        assert_eq!(
            r.st.read(&c, &o, 0, 4096).unwrap(),
            vec![want; 4096],
            "obj {i}"
        );
    }
    check_no_leaks(&mut r);
    r.clean_remount();
}

#[test]
fn defrag_crash_matrix() {
    // adr 0021 am. 33: a crash at any device event of a defrag sweep (reads, move txns, checkpoints) recovers every object
    // with its data under every crash policy, fsck clean (no leaked or doubly referenced block).
    let n = 9000;
    let (mut r, _) = rig_ns(64, 1, 1024, 99, defrag_cfg(), 4096);
    let keep = fragmented_store(&mut r, n);
    let e0 = r.disk.events();
    run_defrag(&mut r.st, 1).unwrap();
    r.st.checkpoint().unwrap();
    let total = r.disk.events() - e0;
    assert!(r.st.shards[0].defrag_stats().moved_extents > 20);
    let mut runs = 0;
    for k in (0..total).step_by((total as usize / 12).max(1)) {
        for pol in [
            CrashPolicy::MIXED,
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
        ] {
            let (mut r2, _) = rig_ns(64, 1, 1024, 99, defrag_cfg(), 4096);
            assert_eq!(fragmented_store(&mut r2, n), keep);
            r2.disk.arm_crash(r2.disk.events() + k);
            let _ = run_defrag_until_dead(&mut r2.st, &r2.disk);
            r2.disk.crash_now();
            let img = r2.disk.crash_image(pol);
            r2.fsck_img(&img);
            let (_, mut st) = open(&img, &r2.sim, &r2.cfg);
            check_survivors(&mut st, n, &keep).unwrap_or_else(|e| panic!("k {k} {pol:?}: {e}"));
            st.checkpoint().unwrap();
            runs += 1;
        }
    }
    assert!(runs >= 36, "runs {runs}");
}

/// `run_defrag` for one sweep that stops at the first store error (the armed crash).
fn run_defrag_until_dead(st: &mut St, disk: &SimDisk) -> Result<(), ObjError> {
    let s0 = st.shards[0].defrag_stats().sweeps;
    for _ in 0..2_000_000 {
        let mut acked = vec![];
        st.poll(&mut acked)?;
        if disk.crashed() {
            return Ok(());
        }
        if st.shards[0].defrag_stats().sweeps > s0 {
            return st.checkpoint();
        }
        st.idle();
    }
    Ok(())
}

// ---------------------------------------------------------------- meta cells on a fragmented store (adr 0021 am. 51)

fn big_data(i: u32) -> Vec<u8> {
    (0..3 * 4096u32)
        .map(|x| ((x / 4096 * 7 + i) % 251) as u8)
        .collect()
}

/// am. 51 fixture: the data region filled with 3-block objects separated by 1-block fillers, then the fillers removed
/// and checkpointed: the free space is 1-block holes only (no whole free window, no 2-block run). Returns the number of
/// 3-block objects (`big-*`).
fn aged_holes(r: &mut Rig) -> u32 {
    aged_holes_with(r, false)
}

/// [`aged_holes`]; `cloned`: every `big-i` is cloned to `cln-i` at once (am. 32), so every data extent is shared and
/// never moved by defrag.
fn aged_holes_with(r: &mut Rig, cloned: bool) -> u32 {
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let mut n = 0u32;
    while r.st.write_room(&c, 4 * 4096, 0) {
        let (o, d) = (g(format!("big-{n:06}").as_bytes(), n), big_data(n));
        let mut t = OTxn::new();
        t.write(c, &o, 0, &d);
        commit(&mut r.st, &t);
        if cloned {
            let mut t = OTxn::new();
            t.push(TOp::Clone {
                cid: c,
                src: o,
                dst: g(format!("cln-{n:06}").as_bytes(), n),
            });
            commit(&mut r.st, &t);
        }
        let o = g(format!("fil-{n:06}").as_bytes(), n);
        let mut t = OTxn::new();
        t.write(c, &o, 0, &[0x5Au8; 4096]);
        commit(&mut r.st, &t);
        n += 1;
    }
    for i in 0..n {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("fil-{i:06}").as_bytes(), i));
        commit(&mut r.st, &t);
    }
    r.st.checkpoint().unwrap();
    r.st.checkpoint().unwrap();
    n
}

/// Omap-only objects `om-*` (8 keys x 200 B, applied as sys like replica txns) from `from` while `write_room` admits them,
/// at most `cap`, stopping early once `stop` says so. Returns the number written.
fn fill_omap(st: &mut St, from: u32, cap: u32, stop: impl Fn(&St) -> bool) -> u32 {
    let c = c1();
    let val = vec![7u8; 200];
    let mut m = 0;
    while m < cap && !stop(st) && st.write_room(&c, 2048, 0) {
        let i = from + m;
        let o = g(format!("om-{i:06}").as_bytes(), i);
        let keys: Vec<String> = (0..8u32).map(|k| format!("k{k:04}")).collect();
        let mut t = OTxn::new();
        t.sys = true;
        for k in &keys {
            t.omap_set(c, &o, k.as_bytes(), &val);
        }
        commit(st, &t);
        m += 1;
    }
    m
}

fn check_aged(st: &mut St, n: u32, omaps: u32) {
    let c = c1();
    for i in 0..n {
        let o = g(format!("big-{i:06}").as_bytes(), i);
        assert_eq!(
            st.read(&c, &o, 0, 3 * 4096).unwrap(),
            big_data(i),
            "big {i}"
        );
        assert!(
            !st.exists(&c, &g(format!("fil-{i:06}").as_bytes(), i))
                .unwrap()
        );
    }
    for i in (0..omaps).step_by(7) {
        let o = g(format!("om-{i:06}").as_bytes(), i);
        let got = st.omap_get(&c, &o, &[b"k0000", b"k0007"]).unwrap();
        assert_eq!(got.len(), 2, "om {i}");
        assert!(got.values().all(|v| v == &vec![7u8; 200]));
    }
}

/// Drive polls (sim time jumps between sweep checks) until `want` cell sweeps ended (cell made or given up).
fn run_cells(st: &mut St, want: u64) -> store::obj::DefragStats {
    for _ in 0..2_000_000 {
        let mut acked = vec![];
        st.poll(&mut acked).unwrap();
        let ds = st.shards[0].defrag_stats();
        if ds.cells_made + ds.cell_fails >= want {
            return ds;
        }
        if !st.shards[0].defrag_active() {
            st.clk.t += 2_000_000_000;
        }
        st.idle();
    }
    panic!("cell sweep never ended: {:?}", st.shards[0].defrag_stats());
}

fn cells_cfg(cells: bool, keep: u32) -> StoreCfg {
    let mut cfg = defrag_cfg();
    cfg.shard.defrag_cells = cells;
    cfg.shard.keep_windows = keep;
    cfg
}

/// The am. 51 fixture up to a meta-bound shard with cell sweeps on: aged holes and omap growth with cell sweeps off
/// (blocked), a remount with them on, omap growth until blocked again. Returns (rig, big objects, omap objects).
fn meta_bound_rig(cap_mib: u64, seed: u64) -> (Rig, u32, u32) {
    let (mut r, _) = rig_ns(cap_mib, 1, 1024, seed, cells_cfg(false, 0), 8192);
    let n = aged_holes(&mut r);
    let m1 = fill_omap(&mut r.st, 0, 100_000, |_| false);
    assert!(
        r.st.shards[0].sh.meta_growth_blocked(),
        "fixture not meta-bound: {:?}",
        r.st.shards[0].sh.statfs()
    );
    r.cfg.shard.defrag_cells = true;
    r.clean_remount();
    let m2 = fill_omap(&mut r.st, m1, 100_000, |st| {
        st.shards[0].defrag_stats().cell_sweeps > 0
    });
    (r, n, m1 + m2)
}

#[test]
fn cell_sweep_unblocks_meta_growth_on_a_uniformly_fragmented_store() {
    // adr 0021 am. 51: 3-block extents with only 1-block holes between them: no whole window, no 2-block run. Elastic
    // meta growth needs a contiguous cell: with cell sweeps off the shard stays meta-bound (reads full) with a sixth of the
    // data free and no plain sweep helps (no window below WIN / 8 live); with them on, a sweep splits the extents of the
    // cheapest window over the holes, empties it, takes the cell, and omap growth goes on. Content, fsck, remount.
    let (mut r, _) = rig_ns(24, 1, 1024, 147, cells_cfg(false, 0), 8192);
    let n = aged_holes(&mut r);
    let m1 = fill_omap(&mut r.st, 0, 100_000, |_| false);
    let f = r.st.shards[0].sh.statfs();
    assert!(r.st.shards[0].sh.meta_growth_blocked(), "{f:?}");
    assert!(f.data_free * 6 > f.data_blocks, "{f:?}");
    assert!(r.st.statfs().fullest_shard_pct >= 95.0);
    assert_eq!(r.st.shards[0].sh.state().alloc.free_windows(), 0);
    // cell sweeps off: polling for a while changes nothing
    for _ in 0..200 {
        let mut acked = vec![];
        r.st.poll(&mut acked).unwrap();
        r.st.clk.t += 2_000_000_000;
    }
    let ds = r.st.shards[0].defrag_stats();
    assert_eq!((ds.cell_sweeps, ds.moved_extents), (0, 0), "{ds:?}");
    assert!(r.st.shards[0].sh.meta_growth_blocked());
    // cell sweeps on
    r.cfg.shard.defrag_cells = true;
    r.clean_remount();
    let m2 = fill_omap(&mut r.st, m1, 100_000, |st| {
        st.shards[0].defrag_stats().cell_sweeps > 0
    });
    let ds = run_cells(&mut r.st, 1);
    assert!(ds.cells_made >= 1, "{ds:?}");
    assert!(
        ds.split_moves > 0,
        "3-block extents need splitting over 1-block holes: {ds:?}"
    );
    assert!(!r.st.shards[0].sh.meta_growth_blocked());
    let m3 = fill_omap(&mut r.st, m1 + m2, 200, |_| false);
    assert!(m3 >= 50, "omap objects after the sweep: {m3}, {ds:?}");
    check_aged(&mut r.st, n, m1 + m2 + m3);
    check_no_leaks(&mut r);
    r.clean_remount();
    check_aged(&mut r.st, n, m1 + m2 + m3);
}

/// A cell sweep run under client load (adr 0021 am. 70): a sys omap txn queued before every poll (one per 10 ms
/// step), until `want` cell sweeps ended. The drain = the steps after the last move.
struct LoadedSweep {
    ds: store::obj::DefragStats,
    /// Whole run, from the call to the end of the sweep.
    ns: u64,
    /// From the last move to the end of the sweep (the whole run without moves).
    drain_ns: u64,
    /// Checkpoints started during the drain: on request (`ShardStats::ckpt_why[0]`), automatic (the other reasons).
    drain_asked: u64,
    drain_auto: u64,
}

fn run_cells_loaded(st: &mut St, want: u64, max_ns: u64) -> LoadedSweep {
    let (c, o, val) = (c1(), g(b"om-000000", 0), vec![7u8; 200]);
    let t0 = st.clk.t;
    let mut tok = 1u64 << 40;
    let mut last = (0u64, t0, st.shards[0].sh.stats.ckpt_why);
    while st.clk.t - t0 <= max_ns {
        let mut t = OTxn::new();
        t.sys = true;
        t.omap_set(c, &o, b"k0000", &val);
        tok += 1;
        match st.queue(&t, tok) {
            // the shard's queue is full (txns parked behind the WAL): they stay in flight, this step adds none
            Ok(_) | Err(ObjError::WouldBlock) => {}
            Err(e) => panic!("load txn refused: {e:?}"),
        }
        let mut acked = vec![];
        st.poll(&mut acked).unwrap();
        let mut errs = vec![];
        st.take_queue_errors(&mut errs);
        assert!(errs.is_empty(), "load txn failed: {errs:?}");
        let ds = st.shards[0].defrag_stats();
        if ds.moved_extents > last.0 {
            last = (ds.moved_extents, st.clk.t, st.shards[0].sh.stats.ckpt_why);
        }
        if ds.cells_made + ds.cell_fails >= want {
            let why = st.shards[0].sh.stats.ckpt_why;
            return LoadedSweep {
                ds,
                ns: st.clk.t - t0,
                drain_ns: st.clk.t - last.1,
                drain_asked: why[0] - last.2[0],
                drain_auto: (1..why.len()).map(|i| why[i] - last.2[i]).sum(),
            };
        }
        st.clk.t += 10_000_000;
    }
    panic!(
        "cell sweep did not end within {max_ns} ns under client load: {:?}",
        st.shards[0].defrag_stats()
    );
}

#[test]
fn cell_sweep_gives_up_on_pinned_victims_at_once_under_client_load() {
    // adr 0021 am. 70: every data extent shares its blocks with a clone (never moved), so the victims keep allocated
    // blocks after the moves. Frees apply at submit: nothing in flight can still free them, the drain gives up at its
    // first step although client txns are in flight at every step (before: it waited for an idle shard and gave up
    // only at a 30 s deadline with a WARNING TIMEOUT).
    let (mut r, _) = rig_ns(16, 1, 1024, 149, cells_cfg(false, 0), 8192);
    let n = aged_holes_with(&mut r, true);
    let m1 = fill_omap(&mut r.st, 0, 100_000, |_| false);
    assert!(
        r.st.shards[0].sh.meta_growth_blocked(),
        "fixture not meta-bound: {:?}",
        r.st.shards[0].sh.statfs()
    );
    r.cfg.shard.defrag_cells = true;
    r.clean_remount();
    let m2 = fill_omap(&mut r.st, m1, 100_000, |st| {
        st.shards[0].defrag_stats().cell_sweeps > 0
    });
    let LoadedSweep { ds, ns, .. } = run_cells_loaded(&mut r.st, 1, 20_000_000_000);
    assert_eq!(
        (ds.cells_made, ds.cell_fails, ds.moved_extents),
        (0, 1, 0),
        "{ds:?}"
    );
    assert!(
        ns < 2_000_000_000,
        "pinned sweep ended after {ns} ns: {ds:?}"
    );
    check_aged(&mut r.st, n, m1 + m2);
    let c = c1();
    for i in 0..n {
        let o = g(format!("cln-{i:06}").as_bytes(), i);
        assert_eq!(
            r.st.read(&c, &o, 0, 3 * 4096).unwrap(),
            big_data(i),
            "cln {i}"
        );
    }
    check_no_leaks(&mut r);
}

#[test]
fn cell_sweep_given_up_waits_for_a_freed_pin() {
    // adr 0021 am. 79: every data extent shares its blocks with a clone, so every sweep gives up on its victims. Each
    // window is tried once, then the idle shard runs no pass and reads nothing (before: the given-up windows were retried
    // every 60 checks, each retry a whole extent pass). Removing objects frees pinning blocks: their windows are tried
    // once more.
    let (mut r, _) = rig_ns(128, 1, 1024, 150, cells_cfg(false, 0), 8192);
    let n = aged_holes_with(&mut r, true);
    let m1 = fill_omap(&mut r.st, 0, 100_000, |_| false);
    assert!(
        r.st.shards[0].sh.meta_growth_blocked(),
        "fixture not meta-bound: {:?}",
        r.st.shards[0].sh.statfs()
    );
    r.cfg.shard.defrag_cells = true;
    r.clean_remount();
    fill_omap(&mut r.st, m1, 100_000, |st| {
        st.shards[0].defrag_stats().cell_sweeps > 0
    });
    let ds = idle_until_quiet(&mut r.st, 36_000);
    assert!(ds.cell_sweeps >= 2, "{ds:?}");
    assert_eq!(
        (ds.cell_fails, ds.cells_made, ds.moved_extents),
        (ds.cell_sweeps, 0, 0),
        "{ds:?}"
    );
    assert!(r.st.shards[0].sh.meta_growth_blocked());
    let d0 = r.disk.stats();
    let ds1 = idle_secs(&mut r.st, 600);
    assert_eq!(ds1.sweeps, ds.sweeps, "idle retries: {ds1:?}");
    assert_eq!(r.disk.stats().read_lbas, d0.read_lbas, "blocks read idle");
    // free pinning blocks (both owners of every 50th run): those windows are candidates again, given up again
    let c = c1();
    for i in (0..n).step_by(50) {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("big-{i:06}").as_bytes(), i));
        t.remove(c, &g(format!("cln-{i:06}").as_bytes(), i));
        commit(&mut r.st, &t);
    }
    r.st.checkpoint().unwrap();
    assert!(r.st.shards[0].sh.meta_growth_blocked());
    let ds2 = idle_until_quiet(&mut r.st, 36_000);
    assert!(
        ds2.cell_sweeps > ds1.cell_sweeps,
        "freed pins re-arm: {ds2:?}"
    );
    let ds3 = idle_secs(&mut r.st, 600);
    assert_eq!(ds3.sweeps, ds2.sweeps, "idle retries: {ds3:?}");
    for i in 0..n {
        let want = (i % 50 != 0).then(|| big_data(i));
        for p in ["big", "cln"] {
            let o = g(format!("{p}-{i:06}").as_bytes(), i);
            match &want {
                Some(d) => assert_eq!(&r.st.read(&c, &o, 0, 3 * 4096).unwrap(), d, "{p} {i}"),
                None => assert!(!r.st.exists(&c, &o).unwrap(), "{p} {i}"),
            }
        }
    }
    check_no_leaks(&mut r);
}

#[test]
fn cell_sweep_drain_asks_for_its_checkpoint_under_client_load() {
    // adr 0021 am. 70: client txns in flight at every defrag step, no interval checkpoint due. The moved-out blocks are
    // held until a checkpoint passes their frees: the drain asks for it as soon as its moves are submitted and takes
    // the cell within a few steps (before: it asked only on an idle shard and waited for an automatic checkpoint, or
    // gave the cell up at a 30 s deadline).
    let mut cfg = cells_cfg(false, 0);
    cfg.shard.ckpt_interval_ns = 3_600_000_000_000;
    let (mut r, _) = rig_ns(16, 1, 1024, 149, cfg, 8192);
    let n = aged_holes(&mut r);
    let m1 = fill_omap(&mut r.st, 0, 100_000, |_| false);
    assert!(
        r.st.shards[0].sh.meta_growth_blocked(),
        "fixture not meta-bound: {:?}",
        r.st.shards[0].sh.statfs()
    );
    r.cfg.shard.defrag_cells = true;
    r.clean_remount();
    let m2 = fill_omap(&mut r.st, m1, 100_000, |st| {
        st.shards[0].defrag_stats().cell_sweeps > 0
    });
    let sw = run_cells_loaded(&mut r.st, 1, 20_000_000_000);
    let ds = sw.ds;
    eprintln!(
        "loaded cell sweep: {} ns, drain {} ns, drain checkpoints asked {} automatic {}",
        sw.ns, sw.drain_ns, sw.drain_asked, sw.drain_auto
    );
    assert_eq!((ds.cells_made, ds.cell_fails), (1, 0), "{ds:?}");
    assert!(ds.moved_extents > 0 && ds.split_moves > 0, "{ds:?}");
    assert!(
        sw.drain_asked >= 1 && sw.drain_asked + sw.drain_auto <= 3,
        "checkpoints during the drain: asked {}, automatic {}, {ds:?}",
        sw.drain_asked,
        sw.drain_auto
    );
    assert!(
        sw.drain_ns < 500_000_000,
        "drain took {} ns (sweep {} ns): {ds:?}",
        sw.drain_ns,
        sw.ns
    );
    assert!(!r.st.shards[0].sh.meta_growth_blocked());
    check_aged(&mut r.st, n, m1 + m2);
    check_no_leaks(&mut r);
    r.clean_remount();
    check_aged(&mut r.st, n, m1 + m2);
}

/// Client txns before every 10 ms step until `until` holds (true) or for `max_ns` (false).
fn load_until(st: &mut St, max_ns: u64, until: impl Fn(&St) -> bool) -> bool {
    let (c, o, val) = (c1(), g(b"om-000000", 0), vec![7u8; 200]);
    let t0 = st.clk.t;
    let mut tok = 1u64 << 41;
    while st.clk.t - t0 < max_ns {
        if until(st) {
            return true;
        }
        let mut t = OTxn::new();
        t.sys = true;
        t.omap_set(c, &o, b"k0000", &val);
        tok += 1;
        match st.queue(&t, tok) {
            Ok(_) | Err(ObjError::WouldBlock) => {}
            Err(e) => panic!("load txn refused: {e:?}"),
        }
        let mut acked = vec![];
        st.poll(&mut acked).unwrap();
        let mut errs = vec![];
        st.take_queue_errors(&mut errs);
        assert!(errs.is_empty(), "load txn failed: {errs:?}");
        st.clk.t += 10_000_000;
    }
    false
}

#[test]
fn cell_sweep_drain_held_by_a_reader_shows_its_state_and_age() {
    // adr 0021 am. 70: the drain has no deadline. A reader that keeps an old epoch pinned holds the moved-out blocks in
    // limbo after the drain's checkpoint: the drain waits (no give-up, no timer) and the stats say so, with an age that
    // grows; once the reader ends the cell is taken and the drain fields are back to 0.
    let mut cfg = cells_cfg(false, 0);
    cfg.shard.ckpt_interval_ns = 3_600_000_000_000;
    let (mut r, _) = rig_ns(16, 1, 1024, 149, cfg, 8192);
    let n = aged_holes(&mut r);
    let m1 = fill_omap(&mut r.st, 0, 100_000, |_| false);
    assert!(
        r.st.shards[0].sh.meta_growth_blocked(),
        "fixture not meta-bound: {:?}",
        r.st.shards[0].sh.statfs()
    );
    r.cfg.shard.defrag_cells = true;
    r.clean_remount();
    let m2 = fill_omap(&mut r.st, m1, 100_000, |st| {
        st.shards[0].defrag_stats().cell_sweeps > 0
    });
    let pin = r.st.shards[0].sh.read_pin();
    assert!(
        load_until(&mut r.st, 20_000_000_000, |st| st.shards[0]
            .defrag_stats()
            .drain_readers
            == 1),
        "the drain never waited on the reader: {:?}",
        r.st.shards[0].defrag_stats()
    );
    let w1 = r.st.shards[0].defrag_stats();
    assert_eq!(
        (w1.drain_waiting, w1.cells_made, w1.cell_fails),
        (1, 0, 0),
        "{w1:?}"
    );
    assert!(w1.drain_held > 0, "{w1:?}");
    assert!(
        !load_until(&mut r.st, 1_000_000_000, |st| st.shards[0]
            .defrag_stats()
            .drain_waiting
            == 0),
        "the drain waits as long as the reader: {:?}",
        r.st.shards[0].defrag_stats()
    );
    let w2 = r.st.defrag_stats();
    assert_eq!((w2.drain_waiting, w2.drain_readers), (1, 1), "{w2:?}");
    assert!(
        w2.drain_wait_ns >= w1.drain_wait_ns + 900_000_000,
        "the wait grows: {} -> {} ns",
        w1.drain_wait_ns,
        w2.drain_wait_ns
    );
    let perf = |st: &St, n: &str| {
        st.perf_counters()
            .into_iter()
            .find(|c| c.0 == n)
            .map(|c| (c.1, c.2))
    };
    assert_eq!(perf(&r.st, "defrag_drains_on_readers"), Some((true, 1)));
    assert_eq!(
        perf(&r.st, "defrag_drain_wait_max_ms"),
        Some((true, w2.drain_wait_ns / 1_000_000))
    );
    r.st.shards[0].sh.read_unpin(pin);
    let sw = run_cells_loaded(&mut r.st, 1, 20_000_000_000);
    let ds = sw.ds;
    assert_eq!((ds.cells_made, ds.cell_fails), (1, 0), "{ds:?}");
    assert_eq!(
        (
            ds.drain_waiting,
            ds.drain_readers,
            ds.drain_held,
            ds.drain_wait_ns
        ),
        (0, 0, 0, 0),
        "{ds:?}"
    );
    assert_eq!(perf(&r.st, "defrag_drains_waiting"), Some((true, 0)));
    check_aged(&mut r.st, n, m1 + m2);
    check_no_leaks(&mut r);
}

/// adr 0475 fixture: 4K objects until at most `left` whole windows remain, every other one removed and checkpointed
/// (1-block holes), then `held` more removals not yet passed by a checkpoint. Returns the rig and the object count.
fn holes_rig(cfg: StoreCfg, left: u64, held: u32) -> (Rig, u32) {
    let (mut r, _) = rig_ns(48, 1, 1024, 149, cfg, 8192);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let mut i = 0u32;
    while r.st.shards[0].sh.state().alloc.free_windows() > left {
        let (o, d) = (
            g(format!("obj-{i:06}").as_bytes(), i),
            [(i % 251) as u8; 4096],
        );
        let mut t = OTxn::new();
        t.write(c, &o, 0, &d);
        match r.st.commit(&t) {
            Ok(_) => i += 1,
            Err(ObjError::NoSpace) => break, // the floors keep the rest
            Err(e) => panic!("commit failed: {e:?}"),
        }
    }
    for j in (0..i).step_by(2) {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("obj-{j:06}").as_bytes(), j));
        commit(&mut r.st, &t);
    }
    r.st.checkpoint().unwrap();
    r.st.checkpoint().unwrap();
    for j in (1..i).step_by(2).take(held as usize) {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("obj-{j:06}").as_bytes(), j));
        commit(&mut r.st, &t);
    }
    (r, i)
}

#[test]
fn fragmented_shard_cuts_data_runs_without_forcing_checkpoints() {
    // adr 0475 `frag_cut` (am. 3): at most one whole window, 1-block holes, freed blocks held: a 4 MiB write is cut into
    // the free runs there are (counted), no checkpoint forced
    fn run() -> (u64, u64, u64) {
        let mut cfg = cells_cfg(false, 0);
        cfg.shard.defrag = false;
        let (mut r, _) = holes_rig(cfg, 0, 3);
        let c = c1();
        let o = g(b"big", 7);
        let d: Vec<u8> = (0..4 << 20).map(|x| (x % 253) as u8).collect();
        let s0 = r.st.shards[0].sh.stats;
        let mut t = OTxn::new();
        t.write(c, &o, 0, &d);
        commit(&mut r.st, &t);
        let s = r.st.shards[0].sh.stats;
        assert_eq!(r.st.read(&c, &o, 0, d.len() as u64).unwrap(), d);
        check_no_leaks(&mut r);
        r.clean_remount();
        assert_eq!(r.st.read(&c, &o, 0, d.len() as u64).unwrap(), d);
        (
            s.frag_cuts - s0.frag_cuts,
            s.forced_ckpts - s0.forced_ckpts,
            s.data_runs - s0.data_runs,
        )
    }
    let (cuts, forced, runs) = run();
    assert!(cuts >= 6, "runs cut to the free runs: {cuts}");
    assert_eq!(
        forced, 0,
        "a fragmented shard is not full: no forced checkpoint"
    );
    assert!(runs >= 256, "1-block holes: {runs} runs for 1024 blocks");
}

#[test]
fn fragmented_shard_takes_whole_free_runs() {
    // adr 0475 am. 3: free space = runs of 24 blocks (every other 96 KiB object removed, no reserve floor, the rest
    // filled): a 4 MiB write takes them whole, ceil(1024 / 24) = 43 runs. Halving (64 -> 32 -> 16) took 16 of a run and
    // left its 8 to a later request: 63 runs, 2-3 failed requests per run.
    let mut cfg = cells_cfg(false, 0);
    cfg.shard.defrag = false;
    cfg.shard.data_reserve_pct = 0;
    let (mut r, _) = rig_sim(48, 1, 1024, 151, cfg, 8192, false);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let fill = |r: &mut Rig, name: &str, len: usize| {
        let mut i = 0u32;
        loop {
            let d = vec![(i % 251) as u8; len];
            let mut t = OTxn::new();
            t.write(c, &g(format!("{name}-{i:06}").as_bytes(), i), 0, &d);
            match r.st.commit(&t) {
                Ok(_) => i += 1,
                Err(ObjError::NoSpace) => return i,
                Err(e) => panic!("commit failed: {e:?}"),
            }
        }
    };
    let n = fill(&mut r, "mid", 24 * 4096);
    fill(&mut r, "small", 4096);
    for j in (0..n).step_by(2) {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("mid-{j:06}").as_bytes(), j));
        commit(&mut r.st, &t);
    }
    r.st.checkpoint().unwrap();
    r.st.checkpoint().unwrap();
    let longest = r.st.shards[0].sh.state().alloc.frag_full()[2];
    assert_eq!(longest, 24, "fixture: free runs of 24 blocks");
    let o = g(b"big", 7);
    let d: Vec<u8> = (0..4 << 20).map(|x| (x % 253) as u8).collect();
    let s0 = r.st.shards[0].sh.stats;
    let mut t = OTxn::new();
    t.write(c, &o, 0, &d);
    commit(&mut r.st, &t);
    let s = r.st.shards[0].sh.stats;
    let (runs, blocks) = (
        s.data_runs - s0.data_runs,
        s.data_run_blocks - s0.data_run_blocks,
    );
    assert_eq!(blocks, 1024);
    assert_eq!(runs, 1024u64.div_ceil(24), "whole 24-block runs");
    assert_eq!(
        s.frag_cuts - s0.frag_cuts,
        runs - 1,
        "every run but the last 16 blocks cut to 24"
    );
    assert_eq!(r.st.read(&c, &o, 0, d.len() as u64).unwrap(), d);
    check_no_leaks(&mut r);
    r.clean_remount();
    assert_eq!(r.st.read(&c, &o, 0, d.len() as u64).unwrap(), d);
}

#[test]
fn small_dense_runs_fill_holes_and_keep_whole_windows() {
    // adr 0475 `small_dense`: 4K writes go into holes of partly used windows, whole windows stay whole (keep_windows off)
    let mut cfg = cells_cfg(false, 0);
    cfg.shard.defrag = false;
    cfg.shard.small_dense = 1;
    let (mut r, _) = holes_rig(cfg, 5, 0);
    let c = c1();
    let (w0, d0) = {
        let sh = &r.st.shards[0].sh;
        (sh.state().alloc.free_windows(), sh.stats.small_dense_allocs)
    };
    assert!(w0 > 0);
    for k in 0..300u32 {
        let o = g(format!("new-{k:06}").as_bytes(), k);
        let mut t = OTxn::new();
        t.write(c, &o, 0, &[0xA5u8; 4096]);
        commit(&mut r.st, &t);
    }
    r.st.checkpoint().unwrap();
    let sh = &r.st.shards[0].sh;
    assert!(sh.stats.small_dense_allocs - d0 >= 300);
    assert!(sh.state().alloc.free_windows() + sh.stats.cells_added >= w0);
    for k in 0..300u32 {
        let o = g(format!("new-{k:06}").as_bytes(), k);
        assert_eq!(r.st.read(&c, &o, 0, 4096).unwrap(), vec![0xA5u8; 4096]);
    }
    check_no_leaks(&mut r);
}

#[test]
fn hole_first_allocation_keeps_the_last_whole_windows() {
    // adr 0021 am. 51: with at most `keep_windows` whole windows left (on a shard of at least 4 x that many windows),
    // short data runs fill holes in partly used windows instead of breaking a whole one (kept for meta cells). Kill switch (0): plain next-fit runs into the whole windows
    // ahead of its cursor.
    fn run(keep: u32) -> (u64, u64, u64, u64) {
        let mut cfg = cells_cfg(false, keep);
        cfg.shard.defrag = false;
        cfg.shard.small_dense = 0; // adr 0475 hole-first for all short data runs would keep the windows too
        let (mut r, _) = rig_ns(48, 1, 1024, 148, cfg, 8192);
        let c = c1();
        let mut t = OTxn::new();
        t.mkcoll(c);
        commit(&mut r.st, &t);
        let wins = |r: &Rig| r.st.shards[0].sh.state().alloc.free_windows();
        let mut i = 0u32;
        while wins(&r) > 5 {
            let (o, d) = (
                g(format!("obj-{i:06}").as_bytes(), i),
                [(i % 251) as u8; 4096],
            );
            let mut t = OTxn::new();
            t.write(c, &o, 0, &d);
            commit(&mut r.st, &t);
            i += 1;
        }
        for j in (0..i).step_by(2) {
            let mut t = OTxn::new();
            t.remove(c, &g(format!("obj-{j:06}").as_bytes(), j));
            commit(&mut r.st, &t);
        }
        r.st.checkpoint().unwrap();
        r.st.checkpoint().unwrap();
        let (w0, cells0, dense0) = {
            let sh = &r.st.shards[0].sh;
            (wins(&r), sh.stats.cells_added, sh.stats.dense_allocs)
        };
        for k in 0..300u32 {
            let o = g(format!("new-{k:06}").as_bytes(), k);
            let mut t = OTxn::new();
            t.write(c, &o, 0, &[0xA5u8; 4096]);
            commit(&mut r.st, &t);
        }
        r.st.checkpoint().unwrap();
        let sh = &r.st.shards[0].sh;
        let cell_wins = (sh.stats.cells_added - cells0) * sh.cell_blocks().div_ceil(256);
        let (w1, dense) = (wins(&r), sh.stats.dense_allocs - dense0);
        for k in 0..300u32 {
            let o = g(format!("new-{k:06}").as_bytes(), k);
            assert_eq!(r.st.read(&c, &o, 0, 4096).unwrap(), vec![0xA5u8; 4096]);
        }
        for j in (1..i).step_by(2) {
            let o = g(format!("obj-{j:06}").as_bytes(), j);
            assert_eq!(
                r.st.read(&c, &o, 0, 4096).unwrap(),
                vec![(j % 251) as u8; 4096]
            );
        }
        check_no_leaks(&mut r);
        r.clean_remount();
        (w0, w1, cell_wins, dense)
    }
    let (w0, w1, cell_wins, dense) = run(8);
    // removals may give an empty meta cell back (one more whole window): still at most `keep_windows`
    assert!(w0 > 0 && w0 <= 8, "fixture: {w0} whole windows");
    assert!(dense >= 300, "hole-first runs: {dense}");
    assert_eq!(
        w1 + cell_wins,
        w0,
        "data broke a whole window: {w0} -> {w1} (+{cell_wins} for cells)"
    );
    let (k0, k1, kcells, kdense) = run(0);
    assert_eq!(kdense, 0);
    assert!(
        k1 + kcells < k0,
        "kill switch: next-fit kept the windows {k0} -> {k1}"
    );
}

#[test]
fn cell_sweep_crash_matrix() {
    // adr 0021 am. 51: a crash at any device event of a cell sweep (raw reads, split and plain move txns, drain
    // checkpoints, the cell's checkpoint) recovers every object with its data and omap under every crash policy, fsck
    // clean (no leaked or doubly referenced block, split records consistent).
    let (mut r, n, m) = meta_bound_rig(16, 149);
    let e0 = r.disk.events();
    let ds = run_cells(&mut r.st, 1);
    r.st.checkpoint().unwrap();
    assert!(ds.cells_made >= 1 && ds.split_moves > 0, "{ds:?}");
    let total = r.disk.events() - e0;
    let mut runs = 0;
    for k in (0..total).step_by((total as usize / 8).max(1)) {
        for pol in [
            CrashPolicy::MIXED,
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
        ] {
            let (mut r2, n2, m2) = meta_bound_rig(16, 149);
            assert_eq!((n2, m2), (n, m), "fixture not deterministic");
            r2.disk.arm_crash(r2.disk.events() + k);
            let _ = run_cells_until_dead(&mut r2.st, &r2.disk);
            r2.disk.crash_now();
            let img = r2.disk.crash_image(pol);
            r2.fsck_img(&img);
            let (_, mut st) = open(&img, &r2.sim, &r2.cfg);
            check_aged(&mut st, n, m);
            st.checkpoint().unwrap();
            runs += 1;
        }
    }
    assert!(runs >= 24, "runs {runs}");
}

/// Omap churn on a meta-bound shard: remove `om-i` (freeing) and write it again with its 8 keys (sys) when `write_room`
/// admits it (as the OSD would), round robin over the first `m` omap objects. Many distinct leaves dirty per checkpoint
/// interval; stops at the first store error.
fn omap_churn(st: &mut St, m: u32, rounds: u32) -> Result<(), ObjError> {
    let c = c1();
    let val = vec![9u8; 200];
    let keys: Vec<String> = (0..8u32).map(|k| format!("k{k:04}")).collect();
    for r in 0..rounds {
        let i = (r * 7) % m;
        let o = g(format!("om-{i:06}").as_bytes(), i);
        let mut t = OTxn::new();
        t.remove(c, &o);
        st.commit(&t)?;
        if !st.write_room(&c, 2048, 0) {
            continue;
        }
        let mut t = OTxn::new();
        t.sys = true;
        for k in &keys {
            t.omap_set(c, &o, k.as_bytes(), &val);
        }
        st.commit(&t)?;
    }
    Ok(())
}

#[test]
fn meta_bound_fragmented_shard_mounts_after_a_crash_anywhere() {
    // adr 0021 am. 51: a crash while a fragmented shard is meta-bound (no contiguous cell left) must never leave a store
    // whose first checkpoint after replay needs a cell it cannot get: the mount would fail on every restart (OSD down for
    // good). Omap churn with automatic checkpoints, crash at points x 3 policies: mount succeeds, fsck clean, the
    // untouched objects intact.
    fn build() -> (Rig, u32, u32) {
        let (mut r, _) = rig_ns(16, 1, 1024, 150, cells_cfg(false, 0), 8192);
        let n = aged_holes(&mut r);
        let m = fill_omap(&mut r.st, 0, 100_000, |_| false);
        assert!(r.st.shards[0].sh.meta_growth_blocked());
        (r, n, m)
    }
    let (mut r, n, m) = build();
    let e0 = r.disk.events();
    omap_churn(&mut r.st, m, 400).unwrap();
    let total = r.disk.events() - e0;
    let mut runs = 0;
    for k in (0..total).step_by((total as usize / 10).max(1)) {
        for pol in [
            CrashPolicy::MIXED,
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
        ] {
            let (mut r2, n2, m2) = build();
            assert_eq!((n2, m2), (n, m), "fixture not deterministic");
            r2.disk.arm_crash(r2.disk.events() + k);
            let _ = omap_churn(&mut r2.st, m, 400);
            r2.disk.crash_now();
            let img = r2.disk.crash_image(pol);
            r2.fsck_img(&img);
            let disk = SimDisk::from_image(&img, r2.sim.clone());
            let d2 = disk.clone();
            let mounted = Store::mount(move || d2.queue(), SimClock::default(), r2.cfg.clone());
            let (mut st, _) =
                mounted.unwrap_or_else(|e| panic!("mount after crash at {k} ({pol:?}): {e:?}"));
            check_aged(&mut st, n, 0);
            st.checkpoint().unwrap();
            runs += 1;
        }
    }
    assert!(runs >= 30, "runs {runs}");
}

#[test]
fn delta_folds_never_need_a_cell_on_a_meta_bound_shard() {
    // adr 0021 am. 51: a checkpoint folds old leaf-delta chains back into whole leaves (each one a dirty root-to-leaf
    // path no admission counted). On a fragmented meta-bound shard the housekeeping could not grow a cell for those
    // pages and failed the store: at any checkpoint, and after a crash at the first checkpoint of the replay, i.e. the
    // mount, on every restart. Folding is now paid from the meta headroom only. Small value updates (leaf deltas) with
    // checkpoints until the delta segments are over their bound: the shard keeps running, a crash image mounts.
    let (mut r, _) = rig_ns(16, 1, 1024, 151, cells_cfg(false, 0), 8192);
    let n = aged_holes(&mut r);
    let m = fill_omap(&mut r.st, 0, 100_000, |_| false);
    assert!(r.st.shards[0].sh.meta_growth_blocked());
    let c = c1();
    let mut writes = 0u32;
    for round in 0..40u32 {
        let val = vec![(round % 251) as u8; 200];
        // replica applies (sys): never gated by write_room; a txn the store refuses outright is skipped
        for i in (round % 3..m).step_by(3) {
            let o = g(format!("om-{i:06}").as_bytes(), i);
            let mut t = OTxn::new();
            t.sys = true;
            t.omap_set(c, &o, b"k0003", &val);
            if r.st.commit(&t).is_ok() {
                writes += 1;
            }
        }
        r.st.checkpoint()
            .unwrap_or_else(|e| panic!("checkpoint round {round}: {e:?}"));
        assert!(!r.st.shards[0].sh.is_failed(), "round {round}");
    }
    let ts = r.st.shards[0].sh.tree_stats();
    assert!(writes > 2000, "writes {writes}");
    assert!(ts.delta_entries > 0, "{ts:?}");
    // crash with a dirty set behind the last checkpoint: the replaying mount checkpoints and must not fail
    for i in (0..m).step_by(5) {
        if !r.st.write_room(&c, 512, 0) {
            break;
        }
        let o = g(format!("om-{i:06}").as_bytes(), i);
        let mut t = OTxn::new();
        t.sys = true;
        t.omap_set(c, &o, b"k0005", &[0xEEu8; 200]);
        commit(&mut r.st, &t);
    }
    r.disk.crash_now();
    let img = r.disk.crash_image(CrashPolicy::PERSIST_ALL);
    r.fsck_img(&img);
    let (_, mut st) = open(&img, &r.sim, &r.cfg);
    check_aged(&mut st, n, m);
    st.checkpoint().unwrap();
}

#[test]
fn delta_page_bound_counts_the_meta_space_growth_can_still_add() {
    // adr 0021 am. 66: on an elastic store the delta page bound is a sixteenth of the meta pages plus what growth can
    // still take from the data region (a sixteenth of only the young meta area made relog copy live chains ~3x per
    // create); once growth is blocked it falls back to the meta pages themselves (am. 51: never starve tree pages).
    let bound = |r: &Rig| r.st.shards[0].sh.state().tree.delta_max_pages();
    let meta16 = |r: &Rig| (r.st.shards[0].sh.state().tree.meta.len() as usize / 16).max(4);
    let (mut r, _) = rig_ns(16, 1, 1024, 151, cells_cfg(false, 0), 8192);
    aged_holes(&mut r);
    r.st.checkpoint().unwrap();
    assert!(
        bound(&r) > meta16(&r),
        "growable store: {} vs meta/16 {}",
        bound(&r),
        meta16(&r)
    );
    fill_omap(&mut r.st, 0, 100_000, |_| false);
    assert!(r.st.shards[0].sh.meta_growth_blocked());
    r.st.checkpoint().unwrap();
    assert_eq!(bound(&r), meta16(&r), "meta-bound store");
}

/// `run_cells` for one cell sweep that stops at the first store error (the armed crash).
fn run_cells_until_dead(st: &mut St, disk: &SimDisk) -> Result<(), ObjError> {
    for _ in 0..2_000_000 {
        let mut acked = vec![];
        st.poll(&mut acked)?;
        if disk.crashed() {
            return Ok(());
        }
        let ds = st.shards[0].defrag_stats();
        if ds.cells_made + ds.cell_fails > 0 {
            return st.checkpoint();
        }
        if !st.shards[0].defrag_active() {
            st.clk.t += 2_000_000_000;
        }
        st.idle();
    }
    Ok(())
}

/// Drive a store until `warm` + `warm_data` of `o` report ready (never blocks in the store).
fn warm_all(r: &mut Rig, c: &CollT, o: &Ghobject, len: u64) {
    let mut spins = 0;
    while !(r.st.warm(c, o, 0, len).unwrap() && r.st.warm_data(c, o, 0, len).unwrap()) {
        spins += 1;
        assert!(spins < 100_000, "prefetch never completed");
        let mut acked = vec![];
        r.st.poll(&mut acked).unwrap();
        if !r.st.take_wake() {
            r.st.idle();
        }
    }
}

#[test]
fn warm_data_serves_the_read_without_a_device_wait() {
    // ADR 0043: after warm_data says ready, read() issues no device read and returns the right bytes.
    let (mut r, _) = rig_with(64, 1, 1024, 5, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let big: Vec<u8> = (0..(1 << 20)).map(|i| (i * 7 % 251) as u8).collect();
    let o = g(b"pf", 1);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &big);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    warm_all(&mut r, &c, &o, big.len() as u64);
    let before = r.st.shards[0].stats.read_ios;
    let got = r.st.read(&c, &o, 0, big.len() as u64).unwrap();
    assert_eq!(got, big);
    assert_eq!(r.st.shards[0].stats.read_ios, before, "read hit the device");
    // data cache (adr 0043 "Data cache"): a re-read of the same blocks (EC stash, hot object) is served from memory,
    // exact, also long after the first read (no pin, no expiry)
    assert!(
        r.st.warm_data(&c, &o, 0, big.len() as u64).unwrap(),
        "cached run not ready"
    );
    assert_eq!(r.st.read(&c, &o, 0, big.len() as u64).unwrap(), big);
    r.st.clk.t += 50_000_000;
    let mut acked = vec![];
    r.st.poll(&mut acked).unwrap();
    assert_eq!(r.st.read(&c, &o, 0, big.len() as u64).unwrap(), big);
    assert_eq!(
        r.st.shards[0].stats.read_ios, before,
        "cached re-read hit the device"
    );
    // an overwrite frees the old blocks: the cache drops them, the next read sees the new bytes from the device
    let mut t = OTxn::new();
    t.write(c, &o, 0, &[0x5a; 8192]);
    commit(&mut r.st, &t);
    r.st.poll(&mut acked).unwrap();
    let mut want = big.clone();
    want[..8192].fill(0x5a);
    assert_eq!(r.st.read(&c, &o, 0, big.len() as u64).unwrap(), want);
    // sub-range of a prefetched run (unaligned tail): content still exact
    warm_all(&mut r, &c, &o, big.len() as u64);
    assert_eq!(r.st.read(&c, &o, 5000, 70_000).unwrap(), want[5000..75_000]);
}

/// Operator cache drop: the data cache and the clean tree pages go, dirty pages stay, the store stays consistent, the
/// next read is a miss (device IO) with the right bytes, and the drop frees the memory it reports.
#[test]
fn cache_drop_releases_clean_caches_and_keeps_the_store_consistent() {
    let (mut r, _) = rig_with(64, 1, 1024, 5, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let big: Vec<u8> = (0..(1 << 20)).map(|i| (i * 7 % 251) as u8).collect();
    let o = g(b"cd", 1);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &big);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    warm_all(&mut r, &c, &o, big.len() as u64);
    assert_eq!(r.st.read(&c, &o, 0, big.len() as u64).unwrap(), big);
    assert!(r.st.warm_data(&c, &o, 0, big.len() as u64).unwrap());
    let cached = r.st.shards[0].data_cache_usage();
    assert!(cached.1 > 0);
    let hot = r.st.shards[0].stats.read_ios;
    assert_eq!(r.st.read(&c, &o, 0, big.len() as u64).unwrap(), big);
    assert_eq!(
        r.st.shards[0].stats.read_ios, hot,
        "warm read hit the device"
    );

    // a dirty page (an uncheckpointed write) must survive the drop
    let o2 = g(b"cd-dirty", 2);
    let mut t = OTxn::new();
    t.write(c, &o2, 0, &[0x33; 4096]);
    t.setattr(c, &o2, b"_", b"oi2");
    commit(&mut r.st, &t);
    let pages =
        r.st.cache_status()
            .into_iter()
            .find(|k| k.0 == "tree_pages")
            .unwrap()
            .1;
    assert!(pages > 0);
    let d = r.st.drop_caches();
    assert_eq!(d.data_bytes, cached.1 * store::BLK as u64);
    assert!(d.tree_kept > 0, "dirty tree pages must stay: {d:?}");
    assert_eq!(r.st.shards[0].data_cache_usage(), (0, 0));
    let st: std::collections::HashMap<_, _> = r.st.cache_status().into_iter().collect();
    assert_eq!(st["cache_drops"], 1);
    assert_eq!(st["dropped_data_bytes"], d.data_bytes);
    assert_eq!(st["data_cache_bytes"], 0);
    // dirty data intact
    assert_eq!(r.st.read(&c, &o2, 0, 4096).unwrap(), vec![0x33; 4096]);

    // after a checkpoint the clean pages go too, and the tree reloads on demand
    let mut acked = vec![];
    r.st.request_checkpoint();
    for _ in 0..10_000 {
        r.st.poll(&mut acked).unwrap();
        r.st.clk.t += 1_000_000;
        r.st.idle();
    }
    let d = r.st.drop_caches();
    assert!(d.tree_pages > 0, "{d:?}");
    assert!(d.tree_bytes > 0);
    let st: std::collections::HashMap<_, _> = r.st.cache_status().into_iter().collect();
    assert!(st["tree_pages"] < pages, "{st:?}");
    let loads = r.st.shards[0].sh.tree_stats().loads;
    let ios = r.st.shards[0].stats.read_ios;
    warm_all(&mut r, &c, &o, big.len() as u64);
    assert_eq!(r.st.read(&c, &o, 0, big.len() as u64).unwrap(), big);
    assert!(
        r.st.shards[0].sh.tree_stats().loads > loads,
        "tree pages were not reloaded"
    );
    assert!(
        r.st.shards[0].stats.read_ios > ios,
        "cold read did not touch the device"
    );
    assert_eq!(r.st.read(&c, &o2, 0, 4096).unwrap(), vec![0x33; 4096]);
    // a second drop of an already dropped store is harmless
    r.st.drop_caches();
    r.st.drop_caches();
    assert_eq!(r.st.read(&c, &o, 0, big.len() as u64).unwrap(), big);
}

/// A non-blocking read of a range whose prefetch is still in flight waits for it (an executor run woken by a part of its
/// causes): it never reads the same blocks a second time through a rolling read.
#[test]
fn a_nonblocking_read_waits_for_its_prefetch_in_flight() {
    let (mut r, _) = rig_with(64, 1, 1024, 5, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let data: Vec<u8> = (0..65536).map(|i| (i * 13 % 251) as u8).collect();
    let o = g(b"pf-inflight", 1);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &data);
    commit(&mut r.st, &t);
    r.clean_remount();
    let mut spins = 0;
    while !r.st.warm(&c, &o, 0, data.len() as u64).unwrap() {
        spins += 1;
        assert!(spins < 100_000, "tree pages never loaded");
        r.st.poll(&mut Vec::new()).unwrap();
        if !r.st.take_wake() {
            r.st.idle();
        }
    }
    assert!(
        !r.st.warm_data(&c, &o, 0, data.len() as u64).unwrap(),
        "prefetch in flight"
    );
    let ios = r.st.shards[0].stats.read_ios;
    r.st.set_nonblock_reads(true);
    assert_eq!(
        r.st.read(&c, &o, 0, data.len() as u64),
        Err(ObjError::WouldBlock)
    );
    assert!(r.st.take_blocked());
    assert_eq!(
        r.st.shards[0].stats.read_ios, ios,
        "the in-flight range was read again"
    );
    assert_eq!(r.st.shards[0].rolling_usage(), (0, 0));
    let mut got = None;
    for _ in 0..100_000 {
        r.st.poll(&mut Vec::new()).unwrap();
        match r.st.read(&c, &o, 0, data.len() as u64) {
            Ok(d) => {
                got = Some(d);
                break;
            }
            Err(ObjError::WouldBlock) => {
                r.st.take_blocked();
                r.st.idle();
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    assert_eq!(got.expect("prefetch never completed"), data);
    assert_eq!(
        r.st.shards[0].stats.read_ios, ios,
        "served from the prefetch"
    );
}

/// A non-blocking multi-key omap get (OMAP_GET_VALS_BY_KEYS on the PG core) over cold leaves queues the loads of every
/// cold key in one pass: the op is refused once per tree level, not once per cold leaf.
#[test]
fn a_nonblocking_omap_get_queues_every_cold_leaf_in_one_pass() {
    // 4 KiB tree nodes: the 4000 keys span a few hundred leaves
    let (mut r, _) = rig_ns(64, 1, 1024, 3, nvc_cfg(), 4096);
    let c = c1();
    let o = g(b"omap-by-keys", 3);
    let key = |i: u64| format!("{:064x}", i.wrapping_mul(0x9e37_79b9_7f4a_7c15)).into_bytes();
    let val = |i: u64| vec![(i % 251) as u8; 200];
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.touch(c, &o);
    commit(&mut r.st, &t);
    // batches below `run_min`: tree puts, no omap runs (adr 0476)
    for b in 0..80u64 {
        let ks: Vec<_> = (b * 50..(b + 1) * 50).map(|i| (key(i), val(i))).collect();
        let mut t = OTxn::new();
        for (k, v) in &ks {
            t.omap_set(c, &o, k, v);
        }
        commit(&mut r.st, &t);
    }
    r.clean_remount();
    // warm the object and one root-to-leaf path; the other leaves stay cold
    assert_eq!(r.st.omap_get(&c, &o, &[&key(0)]).unwrap().len(), 1);
    // every 62nd key in key order: about 12 entries per leaf, so each key is on its own leaf
    let mut want: Vec<u64> = (0..4000).collect();
    want.sort_by_key(|&i| key(i));
    let want: Vec<u64> = want.into_iter().skip(31).step_by(62).take(64).collect();
    let keys: Vec<Vec<u8>> = want.iter().map(|&i| key(i)).collect();
    let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
    let loads = r.st.shards[0].sh.tree_stats().loads;
    r.st.set_nonblock_reads(true);
    let mut passes = 0;
    let got = loop {
        passes += 1;
        assert!(passes < 1000, "never completed");
        match r.st.omap_get(&c, &o, &refs) {
            Ok(m) => break m,
            Err(ObjError::WouldBlock) => {
                assert!(r.st.take_blocked());
                r.st.wait_loads().unwrap();
            }
            Err(e) => panic!("{e:?}"),
        }
    };
    r.st.set_nonblock_reads(false);
    let loaded = r.st.shards[0].sh.tree_stats().loads - loads;
    assert_eq!(got.len(), 64);
    for &i in &want {
        assert_eq!(got[&key(i)], val(i));
    }
    assert!(loaded >= 32, "{loaded} page loads: the keys were not cold");
    assert!(
        passes <= 3,
        "{passes} passes for {loaded} page loads: one refusal per cold leaf"
    );
}

/// Virtual time advanced inside a client read is time stolen from every other PG on its core.
fn rolling_read_measurement() -> u64 {
    let (mut r, _) = rig_with(128, 1, 1024, 5, StoreCfg::default());
    let c = c1();
    let o = g(b"rolling-read", 1);
    let data: Vec<u8> = (0..12 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.write(c, &o, 0, &data);
    commit(&mut r.st, &t);
    warm_all(&mut r, &c, &o, 4 << 20);
    let blocks_before = r.st.shards[0].stats.read_blocks;
    r.st.set_nonblock_reads(true);
    let mut stall = 0;
    for _ in 0..100_000 {
        assert!(r.st.warm_data(&c, &o, 0, 4 << 20).unwrap());
        let before = r.st.clk.t;
        let got = r.st.read_crc(&c, &o, 0, data.len() as u64);
        stall += r.st.clk.t - before;
        let (results, dma) = r.st.shards[0].rolling_usage();
        assert!(results <= data.len());
        assert!(dma <= 8192, "rolling DMA exceeds 32 MiB");
        match got {
            Ok((got, hint)) => {
                assert_eq!(got, data);
                assert_eq!(hint, Some(crc::crc32c(!0, &data)));
                assert_eq!(
                    r.st.shards[0].stats.read_blocks - blocks_before,
                    (8 << 20) / 4096,
                    "the prefetched prefix or a rolling window was reread"
                );
                return stall;
            }
            Err(ObjError::WouldBlock) => {
                r.st.take_blocked();
                r.st.poll(&mut Vec::new()).unwrap();
                r.st.idle();
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    panic!("rolling read never completed");
}

#[test]
#[ignore = "local debug performance measurement"]
fn perf_rolling_read_stall() {
    println!(
        "12 MiB read: {} ns core device stall",
        rolling_read_measurement()
    );
}

#[test]
fn a_large_read_yields_without_waiting_for_a_batch() {
    assert_eq!(rolling_read_measurement(), 0);
}

#[test]
fn rolling_ranges_survive_a_multi_read_request_retry_and_expire_after_cancellation() {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"ranges", 1));
    let data: Vec<u8> = (0..6 * 65536).map(|i| (i % 251) as u8).collect();
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.write(c, &o, 0, &data);
    commit(&mut r.st, &t);
    r.st.set_nonblock_reads(true);
    let mut done = false;
    for _ in 0..100_000 {
        r.st.read_session(Some((7, 11)), true);
        let before = r.st.clk.t;
        done = true;
        // More ranges than the session limit: earlier successes must remain available.
        for i in 0..6 {
            match r.st.read(&c, &o, i * 65536, 65536) {
                Ok(got) => assert_eq!(got, data[i as usize * 65536..(i as usize + 1) * 65536]),
                Err(ObjError::WouldBlock) => {
                    done = false;
                    break;
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        assert_eq!(r.st.clk.t, before, "a range blocked the core");
        r.st.read_session(None, !done);
        r.st.take_blocked();
        if done {
            break;
        }
        r.st.poll(&mut Vec::new()).unwrap();
        r.st.idle();
    }
    assert!(done, "multi-range request never finished");
    assert_eq!(r.st.shards[0].rolling_usage(), (0, 0));
    r.st.read_session(Some((7, 12)), true);
    assert_eq!(
        r.st.read(&c, &o, 0, data.len() as u64),
        Err(ObjError::WouldBlock)
    );
    r.st.read_session(None, true); // cancelled request: no caller retries it
    r.st.take_blocked();
    for _ in 0..100_000 {
        r.st.poll(&mut Vec::new()).unwrap();
        if r.st.shards[0].rolling_usage() == (0, 0) {
            return;
        }
        r.st.clk.t += 10_000;
        r.st.idle();
    }
    panic!("cancelled read did not release its result and DMA");
}

#[test]
fn warm_data_never_serves_stale_data_after_an_overwrite() {
    let (mut r, _) = rig_with(64, 1, 1024, 6, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let o = g(b"stale", 2);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &[1u8; 8192]);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    warm_all(&mut r, &c, &o, 8192);
    // overwrite + churn while the prefetched run sits unclaimed: the old blocks stay pinned (not reusable)
    for i in 0..40u8 {
        let mut t = OTxn::new();
        let d = [i + 2; 8192];
        t.write(c, &o, 0, &d);
        commit(&mut r.st, &t);
        let o2 = g(format!("churn{i}").as_bytes(), 3);
        let mut t = OTxn::new();
        let d2 = [0xEE; 8192];
        t.write(c, &o2, 0, &d2);
        commit(&mut r.st, &t);
    }
    assert_eq!(r.st.read(&c, &o, 0, 8192).unwrap(), vec![41u8; 8192]);
    // unclaimed entries expire and release their pin
    for _ in 0..250_000 {
        let mut a = vec![];
        r.st.poll(&mut a).unwrap();
        r.st.idle();
    }
    r.st.checkpoint().unwrap();
    assert_eq!(r.st.shards[0].sh.statfs().data_held, 0);
}

#[test]
fn read_crc_matches_the_returned_bytes() {
    // the msgr2 data crc (seed !0) is derived from the stored block crcs; it must equal a pass over the bytes
    let (mut r, _) = rig_with(64, 1, 1024, 8, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let o = g(b"crc", 5);
    // several extents (separate txns, interleaved with another object so they are not device-contiguous)
    for (i, off) in [0u64, 65536, 16384, 40960].iter().enumerate() {
        let d: Vec<u8> = (0..16384).map(|k| (k * 3 + i * 17) as u8).collect();
        let mut t = OTxn::new();
        t.write(c, &o, *off, &d);
        t.setattr(c, &o, b"_", b"oi");
        commit(&mut r.st, &t);
        let o2 = g(format!("pad{i}").as_bytes(), 6);
        let mut t = OTxn::new();
        t.write(c, &o2, 0, &[9u8; 8192]);
        commit(&mut r.st, &t);
    }
    r.clean_remount();
    let want = |d: &[u8]| crc::crc32c(!0, d);
    let (d, crc) = r.st.read_crc(&c, &o, 0, 81920).unwrap();
    assert_eq!(crc, Some(want(&d)), "holes count as zero blocks");
    assert_eq!(d.len(), 81920);
    // fully written ranges spanning two extents (0..16384 and 16384..32768) and one extent
    let (d, crc) = r.st.read_crc(&c, &o, 0, 32768).unwrap();
    assert_eq!(crc, Some(want(&d)));
    let (d, crc) = r.st.read_crc(&c, &o, 40960, 16384).unwrap();
    assert_eq!(crc, Some(want(&d)));
    let (d, crc) = r.st.read_crc(&c, &o, 16384, 24576).unwrap();
    assert_eq!(d.len(), 24576);
    assert_eq!(crc, Some(want(&d)), "hole inside");
    // unaligned: no hint
    let (d, crc) = r.st.read_crc(&c, &o, 100, 8192).unwrap();
    assert_eq!((d.len(), crc), (8192, None));
    // pending (unflushed overlay is impossible for a plain read, but a size-clamped tail is not whole blocks)
    let (d, crc) = r.st.read_crc(&c, &o, 65536, 1 << 20).unwrap();
    assert_eq!(d.len(), 16384);
    assert_eq!(crc, Some(want(&d)));
}

#[test]
fn failed_prefetch_is_not_retried_by_client_reads() {
    for compressed in [false, true] {
        for leased in [false, true] {
            for nonblock in [false, true] {
                for mode in 0..3 {
                    for (off, len) in [(0, 4096), (100, 1000), (0, 256 << 10)] {
                        let (mut r, c, o, data) = if compressed {
                            compressed_window_fixture(4)
                        } else {
                            shared_rig(b"prefetch-eio", 256 << 10)
                        };
                        for _ in 0..100_000 {
                            if r.st.warm(&c, &o, 0, data.len() as u64).unwrap() {
                                break;
                            }
                            r.st.poll(&mut Vec::new()).unwrap();
                            r.st.idle();
                        }
                        assert!(r.st.warm(&c, &o, 0, data.len() as u64).unwrap());
                        let lease = leased.then(|| r.st.lease_open(&c).unwrap());
                        if let Some(lease) = lease {
                            r.st.lease_use(lease);
                        }
                        r.disk.fail_reads(0, u64::MAX / 2);
                        warm_all(&mut r, &c, &o, 4096);
                        // The failed command completed. A second command would now succeed,
                        // but must not hide the original error from repair/client handling.
                        r.disk.clear_faults();
                        if leased {
                            r.st.clk.t += 1_000_000_000;
                            r.st.poll(&mut Vec::new()).unwrap();
                            assert!(r.st.shards[0].pf_leased_usage().0 > 0);
                        }
                        let ios = r.st.shards[0].stats.read_ios;
                        r.st.set_nonblock_reads(nonblock);
                        let result = match mode {
                            0 => r.st.read(&c, &o, off, len).map(|_| ()),
                            1 => r.st.read_shared(&c, &o, off, len).map(|_| ()),
                            _ => r.st.read_shared_verified(&c, &o, off, len).map(|_| ()),
                        };
                        assert!(
                            matches!(result, Err(ObjError::Eio(_))),
                            "compressed={compressed} leased={leased} nonblock={nonblock} mode={mode} off={off} len={len}: {result:?}"
                        );
                        assert_eq!(r.st.shards[0].stats.read_ios, ios, "retried a failed read");
                        if let Some(lease) = lease {
                            r.st.lease_release(lease);
                            assert_eq!(r.st.shards[0].pf_leased_usage(), (0, 0));
                        }
                        r.st.set_nonblock_reads(false);
                        assert_eq!(r.st.read(&c, &o, 0, data.len() as u64).unwrap(), data);
                    }
                }
            }
        }
    }
}

#[test]
fn warm_data_read_error_is_reported_by_the_read() {
    let (mut r, _) = rig_with(64, 1, 1024, 7, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let o = g(b"bad", 4);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &[3u8; 4096]);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    while !r.st.warm(&c, &o, 0, 4096).unwrap() {
        let mut a = vec![];
        r.st.poll(&mut a).unwrap();
        if !r.st.take_wake() {
            r.st.idle();
        }
    }
    r.disk.fail_reads(0, u64::MAX / 2);
    warm_all(&mut r, &c, &o, 4096); // the read consumes the failed prefetch entry
    assert!(r.st.read(&c, &o, 0, 4096).is_err());
    r.disk.clear_faults();
    assert_eq!(r.st.read(&c, &o, 0, 4096).unwrap(), vec![3u8; 4096]);
}

/// The block crcs of a prefetched piece are computed when its device read completes and served as they are: a corrupt block
/// is still reported (shared result, a cut sub-range and a copied read), and an intact object returns the right bytes and
/// the right crc of the whole.
#[test]
fn prefetched_pieces_carry_their_crcs_from_completion() {
    let (mut r, _) = rig_with(64, 1, 1024, 11, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let big: Vec<u8> = (0..(1 << 20)).map(|i| (i * 13 % 251) as u8).collect();
    let o = g(b"pfcrc", 1);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &big);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    let len = big.len() as u64;
    warm_all(&mut r, &c, &o, len);
    let pieces = r.st.read_shared(&c, &o, 0, len).unwrap();
    let got: Vec<u8> = pieces.iter().flat_map(|(b, _)| b.iter().copied()).collect();
    assert_eq!(got, big);
    for (b, c) in &pieces {
        assert_eq!(*c, Some(crc::crc32c(!0, b)), "piece crc");
    }
    // one corrupt block: every way of reading the prefetched pieces reports it
    let kv = r.st.shards[0].sh.dump_blocking(&mut r.st.clk).unwrap();
    let (_, v) = kv
        .iter()
        .find(|(k, _)| k[0] == T_EXT && k[10..14] == [0, 0, 0, 0])
        .unwrap();
    let ext = store::obj::onode::Ext::decode(v).unwrap();
    r.disk.corrupt(ext.pba + 100, 100, 0x40);
    r.clean_remount(); // the data cache holds the intact bytes read before the corruption
    let mut acked = vec![];
    warm_all(&mut r, &c, &o, len);
    assert!(matches!(
        r.st.read_shared(&c, &o, 0, len),
        Err(ObjError::Eio(_))
    ));
    r.st.clk.t += 50_000_000;
    r.st.poll(&mut acked).unwrap();
    warm_all(&mut r, &c, &o, len);
    assert!(matches!(r.st.read(&c, &o, 0, len), Err(ObjError::Eio(_))));
}

#[test]
fn warm_data_ttl_runs_from_completion() {
    // a device slower than the prefetch TTL (queueing): a run that just completed must survive the next sweeps
    // until its op claims it (TTL from submit expired it at once -> device read again, multi-run ops re-read forever)
    let mut sim = SimConfig::new(64 << 20);
    sim.seed = 9;
    sim.read_ns = 30_000_000;
    let cfg = StoreCfg::default();
    let img = fresh_image_ns(64, 1, 1024, &sim, 8192);
    let (disk, st) = open(&img, &sim, &cfg);
    let mut r = Rig {
        ev: 0,
        disk,
        st,
        sim,
        cfg,
    };
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let o = g(b"slow", 1);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &[4u8; 8192]);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    warm_all(&mut r, &c, &o, 8192);
    // 3 ms of polling (several 1 ms sweeps), well inside the TTL counted from the completion
    for _ in 0..3000 {
        let mut a = vec![];
        r.st.poll(&mut a).unwrap();
        r.st.idle();
    }
    let before = r.st.shards[0].stats.read_ios;
    assert_eq!(r.st.read(&c, &o, 0, 8192).unwrap(), vec![4u8; 8192]);
    assert_eq!(
        r.st.shards[0].stats.read_ios, before,
        "ready run expired before its op ran"
    );
}

#[test]
fn warm_data_admits_in_arrival_order_and_never_falls_back_to_a_blocking_read() {
    // adr 0043 am. 2: 9 x 4 MiB reads (16 device commands each, queue depth 128 minus the WAL share = 7 reads fit). The two that do not fit wait (no blocking read,
    // nothing submitted); freed capacity goes to the OLDEST waiter even if a younger op probes first.
    let (mut r, _) = rig_with(128, 1, 1024, 11, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let len = 4u64 << 20;
    let data: Vec<Vec<u8>> = (0..9u8).map(|i| vec![i + 1; len as usize]).collect();
    let objs: Vec<Ghobject> = (0..9u8).map(|i| g(&[b'a' + i], 1)).collect();
    for (o, d) in objs.iter().zip(&data) {
        let mut t = OTxn::new();
        t.write(c, o, 0, d);
        t.setattr(c, o, b"_", b"oi");
        commit(&mut r.st, &t);
    }
    r.clean_remount();
    let poll = |r: &mut Rig| {
        let mut a = vec![];
        r.st.poll(&mut a).unwrap();
        r.st.idle();
    };
    for o in &objs {
        while !r.st.warm(&c, o, 0, len).unwrap() {
            poll(&mut r);
        }
    }
    for o in &objs[..7] {
        assert!(!r.st.warm_data(&c, o, 0, len).unwrap(), "fits: in flight");
    }
    let ios = r.st.shards[0].stats.read_ios;
    // 7 (older) and 8 (younger) do not fit: both wait, nothing is read for them
    assert!(!r.st.warm_data(&c, &objs[7], 0, len).unwrap());
    assert!(!r.st.warm_data(&c, &objs[8], 0, len).unwrap());
    assert_eq!(
        r.st.shards[0].stats.read_ios, ios,
        "denied ops submit nothing"
    );
    // object 0 completes and is consumed: one object's capacity is free
    for _ in 0..100_000 {
        if r.st.warm_data(&c, &objs[0], 0, len).unwrap() {
            break;
        }
        poll(&mut r);
    }
    assert_eq!(r.st.read(&c, &objs[0], 0, len).unwrap(), data[0]);
    // the younger op probes first and is refused; the oldest waiter gets the capacity
    assert!(!r.st.warm_data(&c, &objs[8], 0, len).unwrap());
    assert_eq!(r.st.shards[0].stats.read_ios, ios, "younger op overtook");
    assert!(!r.st.warm_data(&c, &objs[7], 0, len).unwrap());
    assert!(
        r.st.shards[0].stats.read_ios > ios,
        "oldest waiter not admitted"
    );
    // everything completes with the right bytes, by prefetch only
    for i in 1..9 {
        let mut spins = 0;
        while !r.st.warm_data(&c, &objs[i], 0, len).unwrap() {
            spins += 1;
            assert!(spins < 200_000, "op {i} starved");
            poll(&mut r);
        }
        let before = r.st.shards[0].stats.read_ios;
        assert_eq!(r.st.read(&c, &objs[i], 0, len).unwrap(), data[i]);
        assert_eq!(
            r.st.shards[0].stats.read_ios, before,
            "op {i} read the device"
        );
    }
}

/// CephFS dirfrag shape (cephfs-gap G3): one object, tens of thousands of `<name>_head` omap keys inserted in random
/// order with 0.5-5 KB values (> 2 KiB inline limit -> fragments), a ~8 MiB batch (`rm-keys` + `set` + header last)
/// in ONE txn, paged scans (1024/page), by-key gets, remount, then deleting the whole object leaves nothing behind.
#[test]
fn cephfs_dirfrag_object_shape() {
    let (mut r, _) = rig_with(3072, 1, 16_384, 91, StoreCfg::default());
    let c = c1();
    let o = g(b"10000000fff.00000000", 0x77);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.touch(c, &o);
    t.setattr(c, &o, b"parent", &[7u8; 300]);
    commit(&mut r.st, &t);
    let mut rng = Rng::new(9);
    let key = |i: u64| format!("file-{i:07}-name_head").into_bytes();
    let val = |rng: &mut Rng| {
        let mut v = vec![0u8; rng.range(500, 3000) as usize];
        rng.fill(&mut v);
        v
    };
    let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let n = 10_000u64;
    let mut order: Vec<u64> = (0..n).collect();
    for i in (1..order.len()).rev() {
        order.swap(i, rng.below(i as u64 + 1) as usize);
    }
    let t0 = Instant::now();
    for chunk in order.chunks(1500) {
        let mut t = OTxn::new();
        let mut pairs = vec![];
        for &i in chunk {
            let v = val(&mut rng);
            model.insert(key(i), v.clone());
            pairs.push((key(i).into(), v.into()));
        }
        t.push(TOp::OmapSetKeys {
            cid: c,
            oid: o.clone(),
            pairs,
        });
        commit(&mut r.st, &t);
    }
    eprintln!("dirfrag: {n} keys inserted in {:?}", t0.elapsed());
    // the commit batch of CDir::_omap_commit_ops: removes first, then sets, header last, one message
    let mut t = OTxn::new();
    let rm: Vec<Vec<u8>> = (0..1500).map(|_| key(rng.below(n))).collect();
    for k in &rm {
        model.remove(k);
    }
    t.push(TOp::OmapRmKeys {
        cid: c,
        oid: o.clone(),
        keys: rm.into_iter().map(Into::into).collect(),
    });
    let mut pairs = vec![];
    let mut bytes = 0usize;
    while bytes < 8 << 20 {
        let k = key(rng.below(2 * n));
        let v = val(&mut rng);
        bytes += k.len() + v.len();
        model.insert(k.clone(), v.clone());
        pairs.push((k.into(), v.into()));
    }
    // duplicates inside one batch: the later value wins (model inserted in the same order)
    t.push(TOp::OmapSetKeys {
        cid: c,
        oid: o.clone(),
        pairs,
    });
    t.push(TOp::OmapSetHeader {
        cid: c,
        oid: o.clone(),
        header: vec![9u8; 350].into(),
    });
    let t1 = Instant::now();
    commit(&mut r.st, &t);
    eprintln!(
        "dirfrag: {} MiB batch txn in {:?}",
        bytes >> 20,
        t1.elapsed()
    );
    r.clean_remount();
    // paged scan like the MDS fetch (1024 per request, continue after the last key)
    let (mut from, mut got, mut pages) = (Vec::new(), BTreeMap::new(), 0);
    loop {
        let (kv, more) = r.st.omap_iter(&c, &o, &from, 1024).unwrap();
        pages += 1;
        if let Some((k, _)) = kv.last() {
            from = [k.as_slice(), &[0]].concat();
        }
        got.extend(kv);
        if !more {
            break;
        }
    }
    assert_eq!(got, model);
    assert!(pages >= model.len() / 1024);
    assert_eq!(r.st.omap_header(&c, &o).unwrap(), vec![9u8; 350]);
    assert_eq!(
        r.st.getattr(&c, &o, b"parent").unwrap().unwrap(),
        [7u8; 300]
    );
    let probe: Vec<Vec<u8>> = (0..200).map(|_| key(rng.below(2 * n))).collect();
    let refs: Vec<&[u8]> = probe.iter().map(|k| k.as_slice()).collect();
    let by = r.st.omap_get(&c, &o, &refs).unwrap();
    for k in &probe {
        assert_eq!(by.get(k), model.get(k));
    }
    // object delete = one txn however big the omap (range delete), no leaked keys
    let mut t = OTxn::new();
    t.remove(c, &o);
    let t2 = Instant::now();
    commit(&mut r.st, &t);
    eprintln!(
        "dirfrag: delete of {} keys in {:?}",
        model.len(),
        t2.elapsed()
    );
    assert_eq!(check_no_leaks(&mut r), 0);
}

/// Deleting an object whose omap is far larger than the per-txn page budget (a 100k-key dirfrag): leaves that lie
/// completely inside the deleted range are freed by address, never read, so the txn needs only the interior pages
/// and the two boundary leaves (was `TooLarge`, which killed the OSD). Same for `omap-rm-key-range` / `omap-clear`.
#[test]
fn big_omap_delete_needs_no_leaf_reads() {
    // 4 KiB pages + a 96-page cache: the 30000-key omap is ~15x the cache and its leaves are never resident
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: 96,
            ..StoreCfg::default().shard
        },
    };
    let (mut r, _) = rig_ns(256, 1, 4096, 3, cfg, 4096);
    let c = c1();
    let (o, keep) = (g(b"big", 5), g(b"keep", 6));
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.touch(c, &o);
    t.omap_set(c, &keep, b"k", b"v");
    commit(&mut r.st, &t);
    let val = vec![7u8; 100];
    for chunk in 0..30u32 {
        let mut t = OTxn::new();
        push_keys(&mut t, c, &o, chunk * 1000, 1000, &val);
        commit(&mut r.st, &t);
        if chunk % 6 == 5 {
            r.st.checkpoint().unwrap();
        }
    }
    r.st.checkpoint().unwrap();
    assert!(r.st.shards[0].sh.tree_stats().evictions > 0);
    // range delete in the middle: far beyond the walk limit (cache/4 = 24 pages) in one txn
    let mut t = OTxn::new();
    t.push(TOp::OmapRmKeyRange {
        cid: c,
        oid: o.clone(),
        first: b"key-005000".to_vec().into(),
        last: b"key-025000".to_vec().into(),
    });
    commit(&mut r.st, &t);
    let left = r.st.omap_all(&c, &o).unwrap();
    assert_eq!(left.len(), 10_000);
    assert!(left.keys().all(
        |k| k.as_slice() < b"key-005000".as_slice() || k.as_slice() >= b"key-025000".as_slice()
    ));
    r.clean_remount();
    assert_eq!(r.st.omap_all(&c, &o).unwrap(), left);
    // whole-object remove, then fsck + leak check
    let mut t = OTxn::new();
    t.remove(c, &o);
    commit(&mut r.st, &t);
    r.clean_remount();
    assert_eq!(check_no_leaks(&mut r), 1);
    assert_eq!(
        r.st.omap_get(&c, &keep, &[b"k"]).unwrap()[&b"k".to_vec()],
        b"v"
    );
}

/// Crash at every device event around a huge range delete (non-resident leaves freed by address): the recovered
/// store is exactly "before" or "after", fsck is clean (no leaked / double-freed meta pages) and keeps working.
#[test]
fn big_omap_delete_crash_matrix() {
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: 96,
            ckpt_wal_pct: 6,
            ..StoreCfg::default().shard
        },
    };
    let mut sim = SimConfig::new(64 << 20);
    sim.seed = 17;
    let img = fresh_image_ns(64, 1, 512, &sim, 4096);
    let c = c1();
    let o = g(b"big", 5);
    let val = vec![7u8; 100];
    let range = |t: &mut OTxn<'_>| {
        t.push(TOp::OmapRmKeyRange {
            cid: c,
            oid: o.clone(),
            first: b"key-001000".to_vec().into(),
            last: b"key-005000".to_vec().into(),
        });
    };
    // a base image with the omap checkpointed and mostly evicted
    let base = {
        let (disk, mut st) = open(&img, &sim, &cfg);
        let mut t = OTxn::new();
        t.mkcoll(c);
        t.touch(c, &o);
        st.commit(&t).unwrap();
        for chunk in 0..6u32 {
            let mut t = OTxn::new();
            push_keys(&mut t, c, &o, chunk * 1000, 1000, &val);
            st.commit(&t).unwrap();
        }
        st.checkpoint().unwrap();
        drop(st);
        disk.image()
    };
    let run = |k: Option<u64>, pol: CrashPolicy| -> Result<(u64, bool), String> {
        let (disk, mut st) = open(&base, &sim, &cfg);
        if let Some(k) = k {
            disk.arm_crash(disk.events() + k);
        }
        let mut t = OTxn::new();
        range(&mut t);
        let mut acked = false;
        if st.queue(&t, 1).is_ok() {
            for _ in 0..100 {
                let mut a = Vec::new();
                if st.poll(&mut a).is_err() {
                    break;
                }
                acked |= !a.is_empty();
                st.idle();
            }
            st.shards[0].sh.request_checkpoint();
            for _ in 0..100 {
                let mut a = Vec::new();
                if st.poll(&mut a).is_err() {
                    break;
                }
                st.idle();
            }
        }
        let n = disk.events();
        let crashed = disk.crashed();
        disk.crash_now();
        let cimg = disk.crash_image(pol);
        drop(st);
        {
            let d = SimDisk::from_image(&cimg, sim.clone());
            let mut dev = d.queue();
            fsck(&mut dev, &mut SimClock::default(), Some(&fsck_refs))
                .map_err(|e| format!("fsck crash image: {e}"))?;
        }
        let (d2, mut st) = open(&cimg, &sim, &cfg);
        let got = st.omap_all(&c, &o).map_err(|e| format!("{e:?}"))?.len();
        if got != 6000 && got != 2000 {
            return Err(format!("recovered {got} keys, expected 6000 or 2000"));
        }
        if acked && got != 2000 {
            return Err("acked delete lost".into());
        }
        let rep = st.check(true).map_err(|e| format!("{e:?}"))?;
        if !rep.errors.is_empty() {
            return Err(format!("check: {:?}", rep.errors));
        }
        st.checkpoint().map_err(|e| format!("{e:?}"))?;
        {
            let d = SimDisk::from_image(&d2.image(), sim.clone());
            let mut dev = d.queue();
            fsck(&mut dev, &mut SimClock::default(), Some(&fsck_refs))
                .map_err(|e| format!("fsck after recovery: {e}"))?;
        }
        Ok((n, crashed))
    };
    let (events, _) = run(None, CrashPolicy::PERSIST_ALL).unwrap();
    assert!(events > 3);
    let mut crashed = 0;
    for k in 0..events + 2 {
        for pol in [
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ] {
            match run(Some(k), pol) {
                Ok((_, c)) => crashed += c as u32,
                Err(e) => panic!("crash at event {k}: {e}"),
            }
        }
    }
    assert!(crashed > 10);
}

fn push_keys(t: &mut OTxn<'_>, c: CollT, o: &Ghobject, from: u32, n: u32, val: &[u8]) {
    t.push(TOp::OmapSetKeys {
        cid: c,
        oid: o.clone(),
        pairs: (from..from + n)
            .map(|i| {
                (
                    format!("key-{i:06}").into_bytes().into(),
                    val.to_vec().into(),
                )
            })
            .collect(),
    });
}

/// `check_txn` judges the SIZE limits like `queue` would, without applying anything: a batch spread over more
/// distinct tree pages than half the txn budget is `TooLarge` (cold cache, so the budget rule bites), a compact one of
/// the same size passes, and nothing was changed either way.
#[test]
fn check_txn_matches_queue_on_page_budget() {
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: 96,
            val_comp_min: 0,
            ..StoreCfg::default().shard
        },
    };
    let (mut r, _) = rig_ns(256, 1, 4096, 5, cfg, 4096);
    let c = c1();
    let o = g(b"idx", 5);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.touch(c, &o);
    commit(&mut r.st, &t);
    let val = vec![3u8; 100];
    for chunk in 0..20u32 {
        let mut t = OTxn::new();
        push_keys(&mut t, c, &o, chunk * 1000, 1000, &val);
        commit(&mut r.st, &t);
    }
    r.clean_remount(); // cold
    let before = r.st.omap_all(&c, &o).unwrap();
    // 400 keys, one in every 50th position: ~400 distinct leaves of 4 KiB >> budget/2 = 24 pages
    let spread = |tag: u8| {
        let mut t = OTxn::new();
        t.push(TOp::OmapSetKeys {
            cid: c,
            oid: o.clone(),
            pairs: (0..400u32)
                .map(|i| {
                    (
                        format!("key-{:06}", i * 50).into_bytes().into(),
                        vec![tag; 100].into(),
                    )
                })
                .collect(),
        });
        t
    };
    let t = spread(9);
    assert!(r.st.txn_needs_check(&t));
    assert_eq!(r.st.check_txn(&t), Err(ObjError::TooLarge));
    assert_eq!(
        r.st.queue_blocking(&t, 1),
        Err(ObjError::TooLarge),
        "blocking apply agrees"
    );
    assert_eq!(r.st.omap_all(&c, &o).unwrap(), before, "nothing applied");
    // 400 neighbouring keys: a handful of leaves
    let mut t = OTxn::new();
    push_keys(&mut t, c, &o, 7000, 400, &[8u8; 100]);
    assert_eq!(r.st.check_txn(&t), Ok(()));
    commit(&mut r.st, &t);
    // a tiny txn is not even staged
    let mut t = OTxn::new();
    push_keys(&mut t, c, &o, 1, 2, b"x");
    assert!(!r.st.txn_needs_check(&t));
    // the store is fine afterwards
    let rep = r.st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}

#[test]
fn warm_data_with_a_full_device_queue_waits_instead_of_reading_synchronously() {
    // 8 MiB = 32 device commands per object; queue depth 64 (8 kept for the WAL): the second object does not fit the
    // queue. The op must wait for a completion (never report ready and block the core in a synchronous read).
    let (mut r, _) = rig_with(128, 1, 1024, 5, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let len = 8u64 << 20; // 32 device commands
    let data: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i + 1; len as usize]).collect();
    let objs: Vec<Ghobject> = (0..3u8).map(|i| g(&[b'a' + i], 1)).collect();
    for (o, d) in objs.iter().zip(&data) {
        let mut t = OTxn::new();
        t.write(c, o, 0, d);
        t.setattr(c, o, b"_", b"oi");
        commit(&mut r.st, &t);
    }
    r.st.checkpoint().unwrap();
    let img = r.disk.image();
    r.sim.queue_depth = 64;
    let (d, s) = open(&img, &r.sim, &r.cfg);
    r.disk = d;
    r.st = s;
    let poll = |r: &mut Rig| {
        let mut a = vec![];
        r.st.poll(&mut a).unwrap();
        r.st.idle();
    };
    for o in &objs {
        while !r.st.warm(&c, o, 0, len).unwrap() {
            poll(&mut r);
        }
    }
    assert!(!r.st.warm_data(&c, &objs[0], 0, len).unwrap());
    assert!(!r.st.warm_data(&c, &objs[1], 0, len).unwrap());
    assert!(
        !r.st.warm_data(&c, &objs[2], 0, len).unwrap(),
        "refused submit reported ready: the real read would block the core"
    );
    for (i, o) in objs.iter().enumerate() {
        let mut spins = 0;
        while !r.st.warm_data(&c, o, 0, len).unwrap() {
            spins += 1;
            assert!(spins < 200_000, "op {i} starved");
            poll(&mut r);
        }
        let before = r.st.shards[0].stats.read_ios;
        assert_eq!(r.st.read(&c, o, 0, len).unwrap(), data[i]);
        assert_eq!(
            r.st.shards[0].stats.read_ios, before,
            "op {i} read the device synchronously"
        );
    }
}

// ---------------------------------------------------------------------------------------------------------------
// ADR 0021 am. 10: omap / xattr keys up to the tree key limit (3308 B with 8 KiB pages, was 497)

/// Key generator: short keys, and long keys over shared long prefixes (so many long keys differ only in the last
/// bytes, are prefixes of each other, or sit at exactly the limit); alphabet incl. 0x00 / 0xff.
fn long_key(rng: &mut Rng, lim: usize) -> Vec<u8> {
    let alpha = [0u8, 1, 0xfe, 0xff, b'a', b'b'];
    match rng.below(100) {
        0..=29 => format!("k{:03}", rng.below(60)).into_bytes(),
        30..=39 => {
            // around the old 497 B limit
            let mut v = vec![b'o'; rng.range(480, 520) as usize];
            v.push(alpha[rng.below(6) as usize]);
            v.truncate(lim);
            v
        }
        40..=44 => {
            let mut v = vec![b'z'; lim];
            let n = rng.below(3) as usize;
            for i in 0..n {
                v[lim - 1 - i] = alpha[rng.below(6) as usize];
            }
            v
        }
        _ => {
            let b = rng.below(4);
            let mut v = vec![0u8; (lim as u64 * (b + 1) / 5).max(2) as usize];
            let mut base = Rng::new(0x77_0000 + b);
            base.fill(&mut v);
            v.iter_mut().for_each(|x| *x = alpha[(*x % 6) as usize]);
            if rng.pct(30) {
                let cut = rng.range(1, v.len() as u64) as usize;
                v.truncate(cut);
            }
            for _ in 0..rng.range(0, 6) {
                v.push(alpha[rng.below(6) as usize]);
            }
            v.truncate(lim);
            v
        }
    }
}

fn long_val(rng: &mut Rng) -> Vec<u8> {
    let n = match rng.below(100) {
        0..=59 => rng.below(40),
        60..=84 => rng.range(100, 900),
        85..=96 => rng.range(1500, 4000), // over the inline limit of short keys: fragments
        _ => rng.range(9000, 30_000),
    } as usize;
    let mut v = vec![0u8; n];
    rng.fill(&mut v);
    v
}

fn omap_model_check(
    r: &mut Rig,
    c: &CollT,
    o: &Ghobject,
    m: &BTreeMap<Vec<u8>, Vec<u8>>,
    rng: &mut Rng,
    lim: usize,
) {
    assert_eq!(&r.st.omap_all(c, o).unwrap(), m, "omap_all");
    for _ in 0..12 {
        // start_after / max scans: omap_iter(from = after + 0x00, max)
        let from = if rng.pct(30) {
            Vec::new()
        } else if rng.pct(50) && !m.is_empty() {
            let i = rng.below(m.len() as u64) as usize;
            m.keys().nth(i).unwrap().clone()
        } else {
            long_key(rng, lim)
        };
        let max = rng.range(1, 30) as usize;
        let (got, more) = r.st.omap_iter(c, o, &from, max).unwrap();
        let want: Vec<(Vec<u8>, Vec<u8>)> = m
            .range(from.clone()..)
            .take(max)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        assert_eq!(got, want, "omap_iter from {} B max {max}", from.len());
        assert_eq!(more, m.range(from.clone()..).nth(max).is_some(), "more");
        // filter_prefix scan: walk the whole prefix range page by page
        let p = if rng.pct(50) && !m.is_empty() {
            let i = rng.below(m.len() as u64) as usize;
            let k = m.keys().nth(i).unwrap();
            k[..rng.range(0, k.len() as u64) as usize].to_vec()
        } else {
            vec![b'o'; rng.range(0, 40) as usize]
        };
        let mut cur = p.clone();
        let mut walked = Vec::new();
        loop {
            let (kv, more) = r.st.omap_iter(c, o, &cur, 7).unwrap();
            let mut last = None;
            for (k, v) in kv {
                if !k.starts_with(&p) {
                    break;
                }
                last = Some(k.clone());
                walked.push((k, v));
            }
            match (more, last) {
                (true, Some(mut l)) => {
                    l.push(0);
                    cur = l;
                }
                _ => break,
            }
        }
        let want: Vec<(Vec<u8>, Vec<u8>)> = m
            .range(p.clone()..)
            .take_while(|(k, _)| k.starts_with(&p))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        assert_eq!(walked, want, "prefix scan {} B", p.len());
    }
    // point gets: present, absent, and a present key with one byte appended / chopped
    let mut probe: Vec<Vec<u8>> = Vec::new();
    for k in m.keys().take(4) {
        probe.push(k.clone());
        let mut x = k.clone();
        x.push(0);
        probe.push(x);
        probe.push(k[..k.len() - 1].to_vec());
    }
    if let Some(k) = m.keys().next_back() {
        probe.push(k.clone());
    }
    probe.retain(|k| !k.is_empty());
    let refs: Vec<&[u8]> = probe.iter().map(|k| k.as_slice()).collect();
    let got = r.st.omap_get(c, o, &refs).unwrap();
    for k in &probe {
        assert_eq!(got.get(k), m.get(k), "omap_get {} B", k.len());
    }
}

fn omap_long_key_model(node_size: u32, seed: u64, rounds: usize, cache_pages: usize) {
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages,
            ..StoreCfg::default().shard
        },
    };
    let (mut r, _) = rig_ns(256, 1, 1024, seed, cfg, node_size);
    let lim = r.st.max_item_key();
    assert_eq!(lim, store::tree::max_key_for(node_size as usize) - 15);
    let (c, o) = (c1(), g(b"index.0", 5));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let mut rng = Rng::new(seed);
    let mut m: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for round in 0..rounds {
        let mut t = OTxn::new();
        let mut mm = m.clone();
        for _ in 0..rng.range(1, 4) {
            match rng.below(100) {
                0..=64 => {
                    let n = rng.range(1, 12);
                    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
                        .map(|_| (long_key(&mut rng, lim), long_val(&mut rng)))
                        .collect();
                    for (k, v) in &pairs {
                        mm.insert(k.clone(), v.clone());
                    }
                    t.push(TOp::OmapSetKeys {
                        cid: c,
                        oid: o.clone(),
                        pairs: pairs
                            .into_iter()
                            .map(|(k, v)| (TxnBytes::Owned(k), TxnBytes::Owned(v)))
                            .collect(),
                    });
                }
                65..=84 => {
                    let n = rng.range(1, 10);
                    let keys: Vec<Vec<u8>> = (0..n)
                        .map(|_| {
                            if !mm.is_empty() && rng.pct(70) {
                                let i = rng.below(mm.len() as u64) as usize;
                                mm.keys().nth(i).unwrap().clone()
                            } else {
                                long_key(&mut rng, lim)
                            }
                        })
                        .collect();
                    for k in &keys {
                        mm.remove(k);
                    }
                    t.push(TOp::OmapRmKeys {
                        cid: c,
                        oid: o.clone(),
                        keys: keys.into_iter().map(TxnBytes::Owned).collect(),
                    });
                }
                85..=95 => {
                    let (a, b) = if !mm.is_empty() && rng.pct(60) {
                        let i = rng.below(mm.len() as u64) as usize;
                        let j = (i + rng.range(0, 25) as usize).min(mm.len() - 1);
                        (
                            mm.keys().nth(i).unwrap().clone(),
                            mm.keys().nth(j).unwrap().clone(),
                        )
                    } else {
                        let (a, b) = (long_key(&mut rng, lim), long_key(&mut rng, lim));
                        if a <= b { (a, b) } else { (b, a) }
                    };
                    let dead: Vec<Vec<u8>> = mm
                        .range(a.clone()..b.clone())
                        .map(|(k, _)| k.clone())
                        .collect();
                    for k in dead {
                        mm.remove(&k);
                    }
                    t.push(TOp::OmapRmKeyRange {
                        cid: c,
                        oid: o.clone(),
                        first: TxnBytes::Owned(a),
                        last: TxnBytes::Owned(b),
                    });
                }
                96..=97 => {
                    mm.clear();
                    t.push(TOp::OmapClear {
                        cid: c,
                        oid: o.clone(),
                    });
                }
                _ => {
                    t.push(TOp::OmapSetHeader {
                        cid: c,
                        oid: o.clone(),
                        header: TxnBytes::Owned(vec![round as u8; 100]),
                    });
                }
            }
        }
        commit(&mut r.st, &t);
        m = mm;
        if round % 5 == 4 {
            omap_model_check(&mut r, &c, &o, &m, &mut rng, lim);
        }
        if round % 40 == 39 {
            r.clean_remount(); // cold cache, checkpointed tree
            omap_model_check(&mut r, &c, &o, &m, &mut rng, lim);
        }
    }
    omap_model_check(&mut r, &c, &o, &m, &mut rng, lim);
    assert!(m.len() > 5, "workload ended nearly empty");
    check_no_leaks(&mut r);
}

#[test]
fn omap_long_keys_ordering_vs_model_8k_pages() {
    omap_long_key_model(8192, 101, 240, 8192);
}

#[test]
fn omap_long_keys_ordering_vs_model_4k_pages_small_cache() {
    omap_long_key_model(4096, 102, 240, 160);
}

#[test]
fn omap_key_limit_boundaries() {
    // adr 0021 am. 10: exactly the limit works, one more is NameTooLong; values of every size under the longest keys
    for node in [4096u32, 8192] {
        let mut r = rig_ns(64, 1, 1024, 7, StoreCfg::default(), node).0;
        let lim = r.st.max_item_key();
        let (c, o) = (c1(), g(b"o", 1));
        let mut t = OTxn::new();
        t.mkcoll(c);
        commit(&mut r.st, &t);
        for klen in [lim - 1, lim] {
            for vlen in [0usize, 1, 511, 512, 513, 3000, 70_000] {
                let k = vec![b'q'; klen];
                let v = vec![vlen as u8; vlen];
                let mut t = OTxn::new();
                t.omap_set(c, &o, &k, &v);
                commit(&mut r.st, &t);
                assert_eq!(
                    r.st.omap_get(&c, &o, &[&k]).unwrap()[&k],
                    v,
                    "{klen}/{vlen}"
                );
            }
        }
        r.clean_remount();
        let k = vec![b'q'; lim];
        assert_eq!(r.st.omap_get(&c, &o, &[&k]).unwrap()[&k].len(), 70_000);
        let (long, v) = (vec![b'q'; lim + 1], b"v");
        let mut t = OTxn::new();
        t.omap_set(c, &o, &long, v);
        assert_eq!(r.st.commit(&t), Err(ObjError::NameTooLong));
        // xattr names share the limit rule (store key = "_" + name)
        let (a_ok, a_bad) = (vec![b'a'; lim], vec![b'a'; lim + 1]);
        let mut t = OTxn::new();
        t.setattr(c, &o, &a_ok, b"x");
        commit(&mut r.st, &t);
        let mut t = OTxn::new();
        t.setattr(c, &o, &a_bad, b"x");
        assert_eq!(r.st.commit(&t), Err(ObjError::NameTooLong));
        check_no_leaks(&mut r);
    }
}

#[test]
fn short_key_values_keep_the_pre_am10_inline_limit() {
    // compat: values of short keys stay inline up to psz/4 - 4 - key - 1 and fragments are cut at the same size as
    // before am. 10, so a workload without long keys builds the same tree as an old store
    let (mut r, _) = rig_ns(64, 1, 1024, 8, nvc_cfg(), 8192);
    let (c, o) = (c1(), g(b"o", 1));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let (small, big) = (vec![1u8; 2032], vec![2u8; 2033]); // key "k" = 11 B tree key
    let mut t = OTxn::new();
    t.omap_set(c, &o, b"k", &small);
    commit(&mut r.st, &t);
    let frags = |r: &mut Rig| {
        let kv = r.st.shards[0].sh.dump_blocking(&mut r.st.clk).unwrap();
        kv.iter().filter(|(k, _)| k[0] == T_FRAG).count()
    };
    assert_eq!(frags(&mut r), 0);
    let mut t = OTxn::new();
    t.omap_set(c, &o, b"k", &big);
    commit(&mut r.st, &t);
    assert!(frags(&mut r) >= 2);
    let kv = r.st.shards[0].sh.dump_blocking(&mut r.st.clk).unwrap();
    for (k, v) in &kv {
        if k[0] == T_OMAP || k[0] == T_FRAG {
            assert!(4 + k.len() + v.len() <= 2048, "short-key entry over psz/4");
        }
    }
    assert_eq!(r.st.omap_get(&c, &o, &[b"k"]).unwrap()[&b"k".to_vec()], big);
}

// ---------------------------------------------------------------------------------------------------------------
// ADR 0021 am. 11: non-blocking reads (cold omap scans must not spin the PG core)

/// Drive the store until a refused read's page loads finished (what the OSD loop does between engine retries).
fn pump_until_wake(r: &mut Rig) {
    for _ in 0..200_000 {
        let mut acked = vec![];
        r.st.poll(&mut acked).unwrap();
        if r.st.take_wake() {
            return;
        }
        r.st.idle();
    }
    panic!("page load never completed");
}

/// Fill `n` omap keys (RGW-index-like: `key` ~64 B, 300 B values) into one object, remount cold.
fn omap_fixture(r: &mut Rig, c: CollT, o: &Ghobject, n: u32) {
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    for chunk in 0..n.div_ceil(500) {
        let pairs: Vec<_> = (chunk * 500..((chunk + 1) * 500).min(n))
            .map(|i| {
                (
                    TxnBytes::Owned(
                        format!("{:08}/some/prefix/with/a/typical/s3/key/name.{i}", i * 7)
                            .into_bytes(),
                    ),
                    TxnBytes::Owned(vec![(i % 251) as u8; 300]),
                )
            })
            .collect();
        let mut t = OTxn::new();
        t.push(TOp::OmapSetKeys {
            cid: c,
            oid: o.clone(),
            pairs,
        });
        commit(&mut r.st, &t);
    }
    r.clean_remount();
}

#[test]
fn nonblocking_reads_refuse_cold_pages_and_rerun_to_the_same_answer() {
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: 96,
            ..StoreCfg::default().shard
        },
    };
    let (mut r, _) = rig_ns(256, 1, 1024, 92, cfg, 4096);
    let (c, o) = (c1(), g(b"index.0", 3));
    omap_fixture(&mut r, c, &o, 6000);
    // reference answers (blocking mode)
    let from: &[u8] = b"00010000";
    let want = r.st.omap_iter(&c, &o, from, 300).unwrap();
    assert_eq!(want.0.len(), 300);
    let wantk =
        r.st.omap_get(&c, &o, &[&want.0[7].0[..], b"absent"])
            .unwrap();
    r.clean_remount();
    r.st.set_nonblock_reads(true);
    let (mut refused, mut rounds) = (0, 0);
    let got = loop {
        match r.st.omap_iter(&c, &o, from, 300) {
            Ok(v) => break v,
            Err(ObjError::WouldBlock) => {
                refused += 1;
                assert!(r.st.take_blocked(), "refusal not reported");
                pump_until_wake(&mut r);
                rounds += 1;
                assert!(rounds < 1000);
            }
            Err(e) => panic!("{e:?}"),
        }
    };
    assert!(refused >= 2, "scan was not cold ({refused})");
    assert!(!r.st.take_blocked(), "flag set by a successful read");
    assert_eq!(got, want);
    // the finished scan loads nothing more: all its pages are resident
    let loads = r.st.shards[0].sh.tree_stats().loads;
    assert_eq!(r.st.omap_iter(&c, &o, from, 300).unwrap(), want);
    assert_eq!(r.st.shards[0].sh.tree_stats().loads, loads);
    // point reads of cold keys: same contract
    r.clean_remount();
    r.st.set_nonblock_reads(true);
    let k = want.0[7].0.clone();
    let got = loop {
        match r.st.omap_get(&c, &o, &[&k, b"absent"]) {
            Ok(v) => break v,
            Err(ObjError::WouldBlock) => pump_until_wake(&mut r),
            Err(e) => panic!("{e:?}"),
        }
    };
    assert_eq!(got, wantk);
    // blocking mode (flag off) still works and never reports a refusal
    r.st.set_nonblock_reads(false);
    r.clean_remount();
    assert_eq!(r.st.omap_iter(&c, &o, from, 300).unwrap(), want);
    assert!(!r.st.take_blocked());
}

#[test]
#[ignore = "microbench: cargo test --release -p store --test obj perf_cold_omap -- --ignored --nocapture"]
fn perf_cold_omap_scan() {
    // omap scan latency, cold and warm, blocking (before am. 11: the core spins for the whole scan) vs non-blocking
    // (the core is free while pages load; numbers are the time until the answer exists). Virtual device time of the
    // simulated PM1743-like device (80 us read, ~3 GB/s) + host wall time for the CPU cost.
    let keys: u32 = std::env::var("NKEYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: 8192,
            ..StoreCfg::default().shard
        },
    };
    let mut sim = SimConfig::new(2 << 30);
    sim.seed = 9;
    let img = fresh_image_ns(2048, 1, 16384, &sim, 8192);
    let (disk, st) = open(&img, &sim, &cfg);
    let mut r = Rig {
        ev: 0,
        disk,
        st,
        sim,
        cfg,
    };
    let (c, o) = (c1(), g(b"index.0", 3));
    omap_fixture(&mut r, c, &o, keys);
    let mut rng = Rng::new(5);
    let pct = |v: &mut Vec<f64>, p: f64| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[((v.len() as f64 * p) as usize).min(v.len() - 1)]
    };
    println!(
        "omap scan, {keys} keys x 300 B values, 8 KiB pages, 1024-entry pages (RGW list page)"
    );
    for (mode, nb) in [
        ("blocking (core spins)", false),
        ("non-blocking (am. 11)", true),
    ] {
        for cold in [true, false] {
            let n = if cold { 40 } else { 400 };
            let (mut lat, mut blocked, mut wall) = (vec![], vec![], vec![]);
            let (mut rounds, mut loads) = (vec![], vec![]);
            r.st.set_nonblock_reads(nb);
            for _ in 0..n {
                if cold {
                    r.clean_remount();
                    r.st.set_nonblock_reads(nb);
                }
                let i = rng.below(keys as u64 - 1100) as u32;
                let from = format!("{:08}", i * 7).into_bytes();
                let l0 = r.st.shards[0].sh.tree_stats().loads;
                let (v0, w0) = (r.st.clk.t, Instant::now());
                let mut rd = 0u32;
                let mut spin_virt = 0u64;
                let got = loop {
                    let t0 = r.st.clk.t;
                    let res = r.st.omap_iter(&c, &o, &from, 1024);
                    match res {
                        Ok(v) => {
                            // virtual time the call itself spent waiting on the device (blocking mode only)
                            spin_virt += r.st.clk.t - t0;
                            break v;
                        }
                        Err(ObjError::WouldBlock) => {
                            rd += 1;
                            // as the engine: re-run once the batch of loads is in (or after 8 wakes)
                            for _ in 0..8 {
                                pump_until_wake(&mut r);
                                if !r.st.loads_pending() {
                                    break;
                                }
                            }
                        }
                        Err(e) => panic!("{e:?}"),
                    }
                };
                assert!(got.0.len() >= 1000);
                lat.push((r.st.clk.t - v0) as f64 / 1e3);
                blocked.push(spin_virt as f64 / 1e3);
                wall.push(w0.elapsed().as_secs_f64() * 1e6);
                rounds.push(rd as f64);
                loads.push((r.st.shards[0].sh.tree_stats().loads - l0) as f64);
            }
            println!(
                "{mode:22} {:5}: latency p50 {:8.0} us p99 {:8.0} us | core blocked in store p50 {:8.0} us | refused rounds p50 {:3.0} | page loads p50 {:4.0} | host cpu+sim wall p50 {:7.0} us",
                if cold { "cold" } else { "warm" },
                pct(&mut lat, 0.5),
                pct(&mut lat, 0.99),
                pct(&mut blocked, 0.5),
                pct(&mut rounds, 0.5),
                pct(&mut loads, 0.5),
                pct(&mut wall, 0.5),
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// rgw-gap G22 / rgw-osd-surface S4: huge-omap lifecycle and the gc-queue object shape

#[test]
fn gc_queue_object_sparse_128mib_partial_writes_zero_and_remove() {
    // rgw_gc queue: one ~128 MiB object, header at 0, entries appended in small writes at arbitrary offsets (ring
    // wrap), `write_zero` of freed ranges, never fully written. Against a sparse page model.
    const SIZE: u64 = (128 << 20) - 1024;
    let (mut r, _) = rig_ns(512, 1, 2048, 61, StoreCfg::default(), 8192);
    let (c, o) = (c1(), g(b"gc.7", 7));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let mut rng = Rng::new(61);
    let mut model: BTreeMap<u64, Vec<u8>> = BTreeMap::new(); // 4 KiB page index -> bytes
    let mut size = 0u64;
    fn page(m: &mut BTreeMap<u64, Vec<u8>>, p: u64) -> &mut Vec<u8> {
        m.entry(p).or_insert_with(|| vec![0u8; 4096])
    }
    let apply_write = |m: &mut BTreeMap<u64, Vec<u8>>, off: u64, data: &[u8]| {
        for (i, b) in data.iter().enumerate() {
            let pos = off + i as u64;
            page(m, pos / 4096)[(pos % 4096) as usize] = *b;
        }
    };
    let apply_zero = |m: &mut BTreeMap<u64, Vec<u8>>, off: u64, len: u64| {
        let (a, b) = (off / 4096, (off + len).div_ceil(4096));
        for p in a..b {
            if let Some(pg) = m.get_mut(&p) {
                let lo = off.max(p * 4096) - p * 4096;
                let hi = (off + len).min((p + 1) * 4096) - p * 4096;
                pg[lo as usize..hi as usize].fill(0);
            }
        }
    };
    let model_read = |m: &BTreeMap<u64, Vec<u8>>, size: u64, off: u64, len: u64| -> Vec<u8> {
        let end = (off + len).min(size);
        let mut out = Vec::new();
        for pos in off..end.max(off) {
            out.push(m.get(&(pos / 4096)).map_or(0, |p| p[(pos % 4096) as usize]));
        }
        out
    };
    let mut head = 0u64; // ring write position
    for step in 0..1500u32 {
        let mut t = OTxn::new();
        let mut keep: Vec<Vec<u8>> = Vec::new();
        match rng.below(100) {
            0..=69 => {
                // append an entry (50..9000 B) at the ring head; sometimes a random arbitrary offset
                let len = rng.range(50, 9000) as usize;
                let off = if rng.pct(75) {
                    head
                } else {
                    rng.below(SIZE - len as u64)
                };
                if off + len as u64 > SIZE {
                    head = 4096;
                    continue;
                }
                let mut d = vec![0u8; len];
                rng.fill(&mut d);
                keep.push(d);
                t.write(c, &o, off, &keep[0]);
                apply_write(&mut model, off, &keep[0]);
                size = size.max(off + len as u64);
                if off == head {
                    head += len as u64 + rng.below(300);
                }
            }
            70..=89 => {
                // write_zero over a consumed range (unaligned)
                let len = rng.range(1, 200_000);
                let off = rng.below(SIZE.saturating_sub(len).max(1));
                t.zero(c, &o, off, len);
                apply_zero(&mut model, off, len);
                size = size.max(off + len);
            }
            _ => {
                // header rewrite at 0 (every push/pop updates the queue header)
                let mut d = vec![0u8; 64];
                rng.fill(&mut d);
                keep.push(d);
                t.write(c, &o, 0, &keep[0]);
                apply_write(&mut model, 0, &keep[0]);
                size = size.max(64);
            }
        }
        commit(&mut r.st, &t);
        if step % 100 == 99 {
            assert_eq!(r.st.stat(&c, &o).unwrap().unwrap().size, size, "size");
            for _ in 0..20 {
                let len = rng.range(1, 70_000);
                let off = rng.below(size.max(1));
                assert_eq!(
                    r.st.read(&c, &o, off, len).unwrap(),
                    model_read(&model, size, off, len),
                    "read {off}+{len} at step {step}"
                );
            }
        }
        if step == 700 {
            r.clean_remount();
        }
    }
    r.clean_remount();
    let used = r.st.statfs().used_bytes;
    assert!(
        used <= (model.len() as u64 + 64) * 4096 + (8 << 20),
        "sparse object uses {used} B for {} touched pages",
        model.len()
    );
    for _ in 0..50 {
        let len = rng.range(1, 300_000);
        let off = rng.below(size);
        assert_eq!(
            r.st.read(&c, &o, off, len).unwrap(),
            model_read(&model, size, off, len)
        );
    }
    check_no_leaks(&mut r);
    let mut t = OTxn::new();
    t.remove(c, &o);
    commit(&mut r.st, &t);
    r.clean_remount();
    assert_eq!(check_no_leaks(&mut r), 0);
    assert!(r.st.statfs().used_bytes < used / 4 + (1 << 20));
}

#[test]
fn huge_omap_clear_is_a_range_delete_not_per_key_work() {
    // omap_clear / remove of an object with N keys: DELRANGE over the omap key range. Cold, it loads interior pages and the
    // two boundary leaves only (never the leaves), the txn is one record, and the store keeps working. N via NKEYS.
    let n: u32 = std::env::var("NKEYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(150_000);
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: 2048,
            ..StoreCfg::default().shard
        },
    };
    let mut sim = SimConfig::new(2 << 30);
    sim.seed = 62;
    let img = fresh_image_ns(2048, 1, 16384, &sim, 8192);
    let (disk, st) = open(&img, &sim, &cfg);
    let mut r = Rig {
        ev: 0,
        disk,
        st,
        sim,
        cfg,
    };
    let (c, o) = (c1(), g(b"index.0", 3));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let val = vec![5u8; 40];
    for chunk in 0..n.div_ceil(2000) {
        let mut t = OTxn::new();
        push_keys(
            &mut t,
            c,
            &o,
            chunk * 2000,
            2000.min(n - chunk * 2000),
            &val,
        );
        commit(&mut r.st, &t);
    }
    r.clean_remount();
    let leaves_before = r.st.shards[0].sh.statfs().meta_used;
    let l0 = r.st.shards[0].sh.tree_stats().loads;
    let (v0, w0) = (r.st.clk.t, Instant::now());
    let mut t = OTxn::new();
    t.push(TOp::OmapClear {
        cid: c,
        oid: o.clone(),
    });
    commit(&mut r.st, &t);
    let loads = r.st.shards[0].sh.tree_stats().loads - l0;
    let virt_us = (r.st.clk.t - v0) as f64 / 1e3;
    println!(
        "omap_clear of {n} keys (cold, {leaves_before} meta pages): {loads} page loads, blocking virtual {virt_us:.0} us, host wall {:.2} ms",
        w0.elapsed().as_secs_f64() * 1e3
    );
    assert!(
        loads < leaves_before / 20 + 50,
        "range delete loaded {loads} of {leaves_before} pages"
    );
    assert!(r.st.omap_all(&c, &o).unwrap().is_empty());
    r.st.checkpoint().unwrap();
    // freed tree pages are reusable: write again
    let mut t = OTxn::new();
    push_keys(&mut t, c, &o, 0, 1000, &val);
    commit(&mut r.st, &t);
    assert_eq!(r.st.omap_all(&c, &o).unwrap().len(), 1000);
    // whole-object remove of the same shape
    let mut t = OTxn::new();
    t.remove(c, &o);
    commit(&mut r.st, &t);
    r.clean_remount();
    check_no_leaks(&mut r);
}

// ---------------------------------------------------------------------------------------------- inline data (adr 0021 am. 14)

fn inline_of(r: &mut Rig) -> (u64, u64) {
    let rep = r.st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    (
        rep.inline_objects,
        r.st.shards.iter().map(|s| s.sh.statfs().data_used).sum(),
    )
}

/// Objects up to the threshold keep their data in the tree: no device block, no extent; every operation on them
/// (partial overwrite, zero, truncate both ways, clone, clone_range, rename, remove) behaves like on a block object,
/// objects leave the inline form when they outgrow the threshold (promotion keeps the bytes) and survive remounts.
#[test]
fn inline_small_objects_lifecycle() {
    let mut r = rig(32, 1);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let (_, used0) = inline_of(&mut r);
    let cap = r.st.shards[0].inline_max;
    assert!(cap >= 1000, "inline threshold {cap}");
    let pat = |n: usize, seed: u8| {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
            .collect::<Vec<u8>>()
    };
    type Bytes2 = BTreeMap<Vec<u8>, Vec<u8>>;
    let mut model: Bytes2 = BTreeMap::new();
    let names: Vec<Ghobject> = (0..12)
        .map(|i| g(format!("small{i}").as_bytes(), i))
        .collect();
    let apply = |r: &mut Rig, m: &mut Bytes2, t: &OTxn, f: &dyn Fn(&mut Bytes2)| {
        commit(&mut r.st, t);
        f(m);
    };
    // create with sizes 1, 100, cap, cap + 1 (extent form), 4096, 4097 ...
    for (i, n) in [
        1usize,
        100,
        cap,
        cap + 1,
        4096,
        4097,
        3000,
        5,
        0,
        700,
        1500,
        64,
    ]
    .iter()
    .enumerate()
    {
        let d = pat(*n, i as u8);
        let mut t = OTxn::new();
        if *n == 0 {
            t.touch(c, &names[i]);
        } else {
            t.write(c, &names[i], 0, &d);
        }
        let k = names[i].clone();
        apply(&mut r, &mut model, &t, &|m| {
            m.insert(format!("{k:?}").into_bytes(), d.clone());
        });
    }
    let key = |i: usize| format!("{:?}", names[i]).into_bytes();
    let (inl, used1) = inline_of(&mut r);
    // inline: sizes <= cap (1, 100, cap, 3000? no: 3000 > cap=2032?) - count what the model says
    let want_inline = [1usize, 100, cap, 3000, 5, 700, 1500, 64]
        .iter()
        .filter(|&&n| n <= cap && n > 0)
        .count() as u64;
    assert_eq!(inl, want_inline, "inline objects");
    // data blocks only for the big ones: cap+1, 4096, 4097 (2 blocks), 3000 if above cap
    let blocks: u64 = [cap + 1, 4096, 4097, 3000]
        .iter()
        .filter(|&&n| n > cap)
        .map(|&n| n.div_ceil(4096) as u64)
        .sum();
    assert_eq!(used1 - used0, blocks, "device blocks");
    let verify = |r: &mut Rig, m: &BTreeMap<Vec<u8>, Vec<u8>>| {
        for (i, n) in names.iter().enumerate() {
            let want = &m[&key(i)];
            let st = r.st.stat(&c, n).unwrap().expect("exists");
            assert_eq!(st.size as usize, want.len(), "size of {i}");
            let got = r.st.read(&c, n, 0, want.len() as u64 + 10).unwrap();
            assert_eq!(&got[..want.len().min(got.len())], &want[..], "data of {i}");
            // reads inside / past the end / in the middle
            if want.len() > 3 {
                assert_eq!(r.st.read(&c, n, 2, 1).unwrap(), want[2..3]);
            }
        }
    };
    verify(&mut r, &model);
    r.clean_remount();
    verify(&mut r, &model);
    // partial overwrite, zero, truncate shrink / grow, clone_range, clone, rename on inline objects
    let mut t = OTxn::new();
    t.write(c, &names[1], 10, &[0xee; 20]);
    t.zero(c, &names[2], 3, 50);
    t.truncate(c, &names[9], 100);
    t.truncate(c, &names[10], 3000);
    t.write(c, &names[11], 100, &[7; 30]); // inside the threshold, behind the end
    apply(&mut r, &mut model, &t, &|m| {
        let d = m.get_mut(&key(1)).unwrap();
        d[10..30].fill(0xee);
        m.get_mut(&key(2)).unwrap()[3..53].fill(0);
        m.get_mut(&key(9)).unwrap().truncate(100);
        m.get_mut(&key(10)).unwrap().resize(3000, 0);
        let d = m.get_mut(&key(11)).unwrap();
        d.resize(130, 0);
        d[100..130].fill(7);
    });
    verify(&mut r, &model);
    let mut t = OTxn::new();
    t.push(TOp::Clone {
        cid: c,
        src: names[0].clone(),
        dst: g(b"clone-a", 100),
    });
    t.push(TOp::Clone {
        cid: c,
        src: names[6].clone(),
        dst: g(b"clone-b", 101),
    });
    commit(&mut r.st, &t);
    for (n, src) in [(g(b"clone-a", 100), 0usize), (g(b"clone-b", 101), 6)] {
        assert_eq!(r.st.read(&c, &n, 0, 5000).unwrap(), model[&key(src)]);
    }
    // grow an inline object beyond the threshold: it moves to a block, bytes preserved
    let before = r.st.shards[0].stats.inline_promotions;
    let mut t = OTxn::new();
    t.write(c, &names[1], 4090, &[9; 20]);
    apply(&mut r, &mut model, &t, &|m| {
        let d = m.get_mut(&key(1)).unwrap();
        d.resize(4110, 0);
        d[4090..].fill(9);
    });
    assert_eq!(r.st.shards[0].stats.inline_promotions, before + 1);
    verify(&mut r, &model);
    // truncate to 0 drops the inline data, a later small write is inline again
    let mut t = OTxn::new();
    t.truncate(c, &names[2], 0);
    t.truncate(c, &names[3], 0); // block object -> empty
    apply(&mut r, &mut model, &t, &|m| {
        m.get_mut(&key(2)).unwrap().clear();
        m.get_mut(&key(3)).unwrap().clear();
    });
    let mut t = OTxn::new();
    t.write(c, &names[3], 0, &[5; 400]);
    t.write(c, &names[2], 0, &[6; 400]);
    apply(&mut r, &mut model, &t, &|m| {
        m.insert(key(3), vec![5; 400]);
        m.insert(key(2), vec![6; 400]);
    });
    verify(&mut r, &model);
    r.clean_remount();
    verify(&mut r, &model);
    // remove everything: no leaked inline keys, no blocks
    for n in &names {
        let mut t = OTxn::new();
        t.remove(c, n);
        commit(&mut r.st, &t);
    }
    for n in [g(b"clone-a", 100), g(b"clone-b", 101)] {
        let mut t = OTxn::new();
        t.remove(c, &n);
        commit(&mut r.st, &t);
    }
    let (inl, used) = inline_of(&mut r);
    assert_eq!((inl, used), (0, used0));
    assert_eq!(check_no_leaks(&mut r), 0);
}

/// The threshold can be switched off per mount (`inline_max` 0): existing inline objects stay readable and are
/// converted when written, new objects use blocks.
#[test]
fn inline_threshold_is_a_runtime_setting() {
    let (mut r, _) = rig_with(32, 1, 1024, 3, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    for i in 0..5u32 {
        let mut t = OTxn::new();
        let data = vec![i as u8 + 1; 300];
        t.write(c, &g(format!("o{i}").as_bytes(), i), 0, &data);
        commit(&mut r.st, &t);
    }
    assert_eq!(inline_of(&mut r).0, 5);
    r.cfg.shard.inline_max = 0;
    r.clean_remount();
    assert_eq!(r.st.shards[0].inline_max, 0);
    assert_eq!(
        r.st.read(&c, &g(b"o3", 3), 0, 1000).unwrap(),
        vec![4u8; 300]
    );
    let mut t = OTxn::new();
    t.write(c, &g(b"o3", 3), 100, &[0xaa; 10]); // not inline-eligible any more: block form
    t.write(c, &g(b"new", 9), 0, &[1; 50]);
    commit(&mut r.st, &t);
    let (inl, _) = inline_of(&mut r);
    assert_eq!(
        inl, 4,
        "o3 left the inline form, the new object never entered it"
    );
    let mut want = vec![4u8; 300];
    want[100..110].fill(0xaa);
    assert_eq!(r.st.read(&c, &g(b"o3", 3), 0, 1000).unwrap(), want);
    r.clean_remount();
    assert_eq!(r.st.read(&c, &g(b"o3", 3), 0, 1000).unwrap(), want);
    check_no_leaks(&mut r);
}

#[test]
fn model_small_objects_inline_data() {
    SMALL_PCT.set(85);
    INLINE_SEEN.set((0, 0));
    for seed in 30..=33u64 {
        let nodes = if seed % 2 == 0 { 8192 } else { 4096 };
        run_model_cfg(
            seed,
            if seed < 32 { 1 } else { 4 },
            260,
            70,
            StoreCfg::default(),
            nodes,
            0,
        );
    }
    let (writes, promotions) = INLINE_SEEN.get();
    assert!(
        writes > 150 && promotions > 20,
        "inline writes {writes}, promotions {promotions}"
    );
    // same streams with the feature off must give the same model-visible results
    for seed in 30..=31u64 {
        let mut cfg = StoreCfg::default();
        cfg.shard.inline_max = 0;
        run_model_cfg(seed, 1, 260, 70, cfg, 8192, 0);
    }
    SMALL_PCT.set(0);
}

#[test]
fn crash_matrix_objects_small_inline() {
    SMALL_PCT.set(85);
    let (n, c) = crash_matrix(
        40,
        120,
        &[
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ],
        500,
        1,
    );
    assert!(n > 100 && c * 2 > n, "scenarios {n}, crashed {c}");
    SMALL_PCT.set(0);
}

/// Tree metadata and device blocks per small RADOS-like object (name + onode + `_` attr 260 B + `snapset` 31 B + data),
/// with the data inline (adr 0021 am. 14) and as blocks. Release: `cargo test --release -p store --test obj
/// perf_small_object_metadata -- --ignored --nocapture`.
#[test]
#[ignore = "measurement"]
fn perf_small_object_metadata() {
    let n: u32 = std::env::var("SMALL_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30_000);
    eprintln!(
        "{n} objects per run, 8 KiB tree pages; tree = leaf + interior pages (fill included), meta = tree bytes in use without the inline data"
    );
    eprintln!(
        "{:>8} {:>8} {:>12} {:>12} {:>12} {:>10} {:>10}",
        "data B",
        "inline",
        "tree pg B/obj",
        "tree used B",
        "meta B/obj",
        "blocks/obj",
        "dev KiB/obj"
    );
    for (dlen, inline_max) in [
        (0usize, 0u32),
        (300, 0),
        (300, 2048),
        (1000, 0),
        (1000, 2048),
        (2000, 0),
        (2000, 2048),
    ] {
        let mut cfg = StoreCfg::default();
        cfg.shard.inline_max = inline_max;
        let (mut r, _) = rig_with(1024, 1, 4096, 9, cfg);
        let c = pgc(1, 0);
        let mut t = OTxn::new();
        t.mkcoll(c);
        commit(&mut r.st, &t);
        let mut rng = Rng::new(3);
        let mut attr = vec![0u8; 260];
        rng.fill(&mut attr);
        let snap = vec![1u8; 31];
        let data = vec![0x5au8; dlen];
        let dblocks = |sh: &store::shard::Shard<store::dev::SimDev>| {
            let f = sh.statfs();
            f.data_used - f.meta_cell_blocks
        };
        let u0 = dblocks(&r.st.shards[0].sh);
        for i in 0..n {
            let mut t = OTxn::new();
            let o = g(
                format!("obj_{i:010}").as_bytes(),
                i.wrapping_mul(2654435761),
            );
            if dlen > 0 {
                t.write(c, &o, 0, &data);
            } else {
                t.touch(c, &o);
            }
            t.setattr(c, &o, b"_", &attr);
            t.setattr(c, &o, b"snapset", &snap);
            commit(&mut r.st, &t);
        }
        r.st.checkpoint().unwrap();
        let sh = &r.st.shards[0].sh;
        let s = sh.state().tree.shape();
        let used_blocks = dblocks(sh) - u0;
        let pages = (s.leaves + s.interior) as f64 * 8192.0 / n as f64;
        let used = (s.leaf_used + s.int_used) as f64 / n as f64;
        let inl = if inline_max > 0 && dlen > 0 && dlen <= inline_max as usize {
            dlen as f64
        } else {
            0.0
        };
        eprintln!(
            "{:>8} {:>8} {:>12.0} {:>12.0} {:>12.0} {:>10.2} {:>10.2}",
            dlen,
            if inline_max > 0 { "on" } else { "off" },
            pages,
            used,
            used - inl,
            used_blocks as f64 / n as f64,
            used_blocks as f64 * 4.0 / n as f64,
        );
    }
}

#[test]
#[ignore = "soak"]
fn crash_matrix_objects_small_inline_soak() {
    SMALL_PCT.set(85);
    let mut tot = 0;
    for gs in 140..170 {
        tot += crash_matrix(
            16,
            gs,
            &[
                CrashPolicy::MIXED,
                CrashPolicy::DROP_ALL,
                CrashPolicy::PERSIST_ALL,
            ],
            1000,
            1,
        )
        .0;
    }
    println!("scenarios {tot}");
    SMALL_PCT.set(0);
}

#[test]
#[ignore = "soak"]
fn model_small_inline_soak() {
    SMALL_PCT.set(90);
    for seed in 200..240u64 {
        let nodes = if seed % 2 == 0 { 8192 } else { 4096 };
        run_model_cfg(
            seed,
            if seed % 3 == 0 { 4 } else { 1 },
            500,
            120,
            StoreCfg::default(),
            nodes,
            if seed % 4 == 0 { 25 } else { 0 },
        );
    }
    SMALL_PCT.set(0);
}

// ---------------------------------------------------------------------------------------------- omap contents

/// `(keys, user key + value bytes)` of an object's omap, recounted from the stored entries (the deep scrub path, adr
/// 0614).
fn ostats(r: &mut Rig, c: &CollT, o: &Ghobject) -> (u64, u64) {
    let sc = r.st.scrub(c, o, 0).unwrap();
    (sc.omap_keys, sc.omap_bytes)
}

/// Exact `(keys, user key + value bytes)` per object under every omap operation, in one txn and across txns, with
/// inline and fragmented values, duplicates, missing keys, range removal, clear, clone, and across remounts.
#[test]
fn omap_contents_are_exact_under_all_ops() {
    let mut r = rig(64, 1);
    let c = c1();
    let o = g(b"idx", 1);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.touch(c, &o);
    commit(&mut r.st, &t);
    assert_eq!(ostats(&mut r, &c, &o), (0, 0));
    let big = vec![7u8; 5000]; // fragmented value
    let mid = vec![3u8; 900];
    let mut t = OTxn::new();
    t.omap_set(c, &o, b"a", b"1");
    t.omap_set(c, &o, b"b", &mid);
    t.omap_set(c, &o, b"c", &big);
    t.omap_set(c, &o, b"a", b"22"); // same key twice in one txn: replaced
    commit(&mut r.st, &t);
    assert_eq!(
        ostats(&mut r, &c, &o),
        (3, (1 + 2) + (1 + 900) + (1 + 5000))
    );
    // overwrite changing size (inline -> fragmented -> inline), set of an existing key with the same value
    let mut t = OTxn::new();
    t.omap_set(c, &o, b"b", &big);
    t.omap_set(c, &o, b"c", b"x");
    t.omap_set(c, &o, b"a", b"22");
    commit(&mut r.st, &t);
    assert_eq!(ostats(&mut r, &c, &o), (3, (1 + 2) + (1 + 5000) + (1 + 1)));
    // removal: existing, missing, duplicate in one list
    let mut t = OTxn::new();
    t.push(TOp::OmapRmKeys {
        cid: c,
        oid: o.clone(),
        keys: vec![
            TxnBytes::Borrowed(&b"a"[..]),
            TxnBytes::Borrowed(&b"zz"[..]),
            TxnBytes::Borrowed(&b"a"[..]),
        ],
    });
    commit(&mut r.st, &t);
    assert_eq!(ostats(&mut r, &c, &o), (2, (1 + 5000) + (1 + 1)));
    r.clean_remount();
    assert_eq!(ostats(&mut r, &c, &o), (2, (1 + 5000) + (1 + 1)));
    // many keys, then range removal (committed keys + keys set in the same txn + fragmented values)
    let keys: Vec<Vec<u8>> = (0..600u32)
        .map(|i| format!("k{i:04}").into_bytes())
        .collect();
    let vals: Vec<Vec<u8>> = (0..600u32)
        .map(|i| vec![i as u8; (i as usize * 13) % 3000])
        .collect();
    let mut t = OTxn::new();
    for (k, v) in keys.iter().zip(&vals) {
        t.omap_set(c, &o, k, v);
    }
    commit(&mut r.st, &t);
    let mut keys_n = 2 + 600u64;
    let mut bytes_n = (1 + 5000)
        + (1 + 1)
        + keys
            .iter()
            .zip(&vals)
            .map(|(k, v)| (k.len() + v.len()) as u64)
            .sum::<u64>();
    assert_eq!(ostats(&mut r, &c, &o), (keys_n, bytes_n));
    let mut t = OTxn::new();
    t.omap_set(c, &o, b"k0100x", b"new"); // inside the range, committed in the same txn
    t.push(TOp::OmapRmKeyRange {
        cid: c,
        oid: o.clone(),
        first: TxnBytes::Borrowed(&b"k0100"[..]),
        last: TxnBytes::Borrowed(&b"k0200"[..]),
    });
    t.omap_set(c, &o, b"k0150", b"after"); // re-added after the removal
    commit(&mut r.st, &t);
    let gone = &keys[100..200];
    keys_n = keys_n - 100 + 1;
    bytes_n = bytes_n
        - gone
            .iter()
            .zip(&vals[100..200])
            .map(|(k, v)| (k.len() + v.len()) as u64)
            .sum::<u64>()
        + (5 + 5);
    assert_eq!(ostats(&mut r, &c, &o), (keys_n, bytes_n));
    assert_eq!(check_no_leaks(&mut r), 1);
    // clone copies the omap, clear removes it
    let o2 = g(b"idx2", 2);
    let mut t = OTxn::new();
    t.push(TOp::Clone {
        cid: c,
        src: o.clone(),
        dst: o2.clone(),
    });
    commit(&mut r.st, &t);
    assert_eq!(ostats(&mut r, &c, &o2), (keys_n, bytes_n));
    let mut t = OTxn::new();
    t.push(TOp::OmapClear {
        cid: c,
        oid: o.clone(),
    });
    commit(&mut r.st, &t);
    assert_eq!(ostats(&mut r, &c, &o), (0, 0));
    assert_eq!(ostats(&mut r, &c, &o2), (keys_n, bytes_n));
    let mut t = OTxn::new();
    t.omap_set(c, &o, b"again", b"v");
    commit(&mut r.st, &t);
    assert_eq!(ostats(&mut r, &c, &o), (1, 5 + 1));
    r.clean_remount();
    assert_eq!(ostats(&mut r, &c, &o), (1, 6));
    assert_eq!(ostats(&mut r, &c, &o2), (keys_n, bytes_n));
    // an empty key list; a missing object is NoEnt
    let o3 = g(b"empty", 3);
    let mut t = OTxn::new();
    t.push(TOp::OmapSetKeys {
        cid: c,
        oid: o3.clone(),
        pairs: vec![],
    });
    commit(&mut r.st, &t);
    assert_eq!(ostats(&mut r, &c, &o3), (0, 0));
    assert_eq!(
        r.st.scrub(&c, &g(b"nope", 9), 0).map(|_| ()),
        Err(ObjError::NoEnt)
    );
    let rep = r.st.check(false).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}

/// Blind omap puts and removals (adr 0476 am. 5) mixed in one txn with every other omap op (repeated puts, a value
/// leaving the tree entry, runs, removals, range removals, clear, clone): contents stay exact against a model, across
/// remounts; fsck clean.
#[test]
fn blind_omap_ops_stay_exact_in_mixed_txns() {
    let mut r = rig(64, 1);
    let c = c1();
    let objs = [g(b"blind-a", 1), g(b"blind-b", 2), g(b"blind-c", 3)];
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.touch(c, &objs[0]);
    t.touch(c, &objs[1]);
    commit(&mut r.st, &t);
    let mut model: Vec<Option<BTreeMap<Vec<u8>, Vec<u8>>>> =
        vec![Some(BTreeMap::new()), Some(BTreeMap::new()), None];
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut rnd = |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let key = |i: u64| format!("k{i:02}").into_bytes();
    for round in 0..400u64 {
        let mut t = OTxn::new();
        for _ in 0..1 + rnd(6) {
            let oi = rnd(2) as usize;
            let (o, m) = (&objs[oi], model[oi].as_mut().unwrap());
            match rnd(100) {
                0..40 => {
                    let k = key(rnd(40));
                    // object b sometimes takes a value that leaves the tree entry (data block)
                    let n = if oi == 1 && rnd(10) == 0 {
                        3000
                    } else {
                        rnd(200) as usize
                    };
                    let v = vec![(round % 251) as u8; n];
                    m.insert(k.clone(), v.clone());
                    t.push(TOp::OmapSetKeys {
                        cid: c,
                        oid: o.clone(),
                        pairs: vec![(k.into(), v.into())],
                    });
                }
                40..55 => {
                    let mut kv: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
                    for _ in 0..1 + rnd(8) {
                        kv.insert(key(rnd(40)), vec![7; rnd(100) as usize]);
                    }
                    let mut enc = Vec::new();
                    denc::SortedKv::encode_into(
                        &mut enc,
                        kv.len(),
                        kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
                    );
                    m.extend(kv);
                    t.push(TOp::OmapSetRun {
                        cid: c,
                        oid: o.clone(),
                        run: store::obj::KvRunData::from_encoding(enc.into()).unwrap(),
                    });
                }
                55..78 => {
                    let ks: Vec<Vec<u8>> = (0..1 + rnd(4)).map(|_| key(rnd(44))).collect();
                    for k in &ks {
                        m.remove(k);
                    }
                    t.push(TOp::OmapRmKeys {
                        cid: c,
                        oid: o.clone(),
                        keys: ks.into_iter().map(Into::into).collect(),
                    });
                }
                78..90 => {
                    let (a, b) = (key(rnd(40)), key(rnd(40)));
                    m.retain(|k, _| !(k >= &a && k < &b));
                    t.push(TOp::OmapRmKeyRange {
                        cid: c,
                        oid: o.clone(),
                        first: a.into(),
                        last: b.into(),
                    });
                }
                90..93 => {
                    m.clear();
                    t.push(TOp::OmapClear {
                        cid: c,
                        oid: o.clone(),
                    });
                }
                _ => {
                    let src = m.clone();
                    model[2] = Some(src);
                    t.push(TOp::Clone {
                        cid: c,
                        src: o.clone(),
                        dst: objs[2].clone(),
                    });
                }
            }
        }
        commit(&mut r.st, &t);
        if round % 97 == 96 {
            r.clean_remount();
        }
        for (o, m) in objs.iter().zip(&model) {
            let Some(m) = m else { continue };
            let want = (
                m.len() as u64,
                m.iter().map(|(k, v)| (k.len() + v.len()) as u64).sum(),
            );
            assert_eq!(ostats(&mut r, &c, o), want, "round {round} {o:?}");
            let (kv, more) = r.st.omap_iter(&c, o, b"", 1000).unwrap();
            assert!(!more);
            let got: BTreeMap<Vec<u8>, Vec<u8>> =
                kv.iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
            assert_eq!(&got, m, "round {round} {o:?}");
        }
    }
    let rep = r.st.check(false).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}

/// Removal batches staged as one sorted list (adr 0476 am. 13) hold the model's contents (listing and scrub recount)
/// after every txn, for batches in any order with repeats and absent keys, several per object and txn, on objects in
/// both id orders, mixed with puts, runs, values leaving the tree entry, range removals, clears, clones and object
/// re-creation; across remounts; fsck clean.
#[test]
fn removal_batches_match_the_model() {
    let mut r = rig(64, 1);
    let c = c1();
    let objs = [
        g(b"rmb-a", 1),
        g(b"rmb-b", 2),
        g(b"rmb-c", 3),
        g(b"rmb-d", 4),
    ];
    let mut t = OTxn::new();
    t.mkcoll(c);
    for o in &objs[..3] {
        t.touch(c, o);
    }
    commit(&mut r.st, &t);
    type M = BTreeMap<Vec<u8>, Vec<u8>>;
    let mut model: Vec<Option<M>> = vec![Some(M::new()), Some(M::new()), Some(M::new()), None];
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let key = |i: u64| format!("key{i:03}").into_bytes();
    for round in 0..300u64 {
        let mut t = OTxn::new();
        for _ in 0..1 + rnd(8) {
            let oi = rnd(3) as usize;
            let (o, m) = (&objs[oi], model[oi].as_mut().unwrap());
            match rnd(100) {
                0..30 => {
                    // object c sometimes takes a value that leaves the tree entry (data block): no blind ops on it
                    let mut kv = M::new();
                    for _ in 0..1 + rnd(12) {
                        let n = if oi == 2 && rnd(20) == 0 {
                            3000
                        } else {
                            rnd(120) as usize
                        };
                        kv.insert(key(rnd(80)), vec![(round % 251) as u8; n]);
                    }
                    m.extend(kv.clone());
                    t.push(TOp::OmapSetKeys {
                        cid: c,
                        oid: o.clone(),
                        pairs: kv.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
                    });
                }
                30..42 => {
                    let mut kv = M::new();
                    for _ in 0..1 + rnd(16) {
                        kv.insert(key(rnd(80)), vec![7; rnd(100) as usize]);
                    }
                    let mut enc = Vec::new();
                    denc::SortedKv::encode_into(
                        &mut enc,
                        kv.len(),
                        kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
                    );
                    m.extend(kv);
                    t.push(TOp::OmapSetRun {
                        cid: c,
                        oid: o.clone(),
                        run: store::obj::KvRunData::from_encoding(enc.into()).unwrap(),
                    });
                }
                42..80 => {
                    // keys 80.. were never put: absent in every state
                    let most = if rnd(4) == 0 { 60 } else { 12 };
                    let n = 1 + rnd(most);
                    let mut ks: Vec<Vec<u8>> = (0..n).map(|_| key(rnd(100))).collect();
                    match rnd(3) {
                        0 => ks.sort(),
                        1 => ks.sort_by(|a, b| b.cmp(a)),
                        _ => {}
                    }
                    for k in &ks {
                        m.remove(k);
                    }
                    t.push(TOp::OmapRmKeys {
                        cid: c,
                        oid: o.clone(),
                        keys: ks.into_iter().map(Into::into).collect(),
                    });
                }
                80..90 => {
                    let (a, b) = (key(rnd(100)), key(rnd(100)));
                    m.retain(|k, _| !(k >= &a && k < &b));
                    t.push(TOp::OmapRmKeyRange {
                        cid: c,
                        oid: o.clone(),
                        first: a.into(),
                        last: b.into(),
                    });
                }
                90..93 => {
                    m.clear();
                    t.push(TOp::OmapClear {
                        cid: c,
                        oid: o.clone(),
                    });
                }
                93..97 => {
                    let src = m.clone();
                    model[3] = Some(src);
                    t.push(TOp::Clone {
                        cid: c,
                        src: o.clone(),
                        dst: objs[3].clone(),
                    });
                }
                _ => {
                    m.clear();
                    t.remove(c, o);
                    t.touch(c, o);
                }
            }
        }
        commit(&mut r.st, &t);
        if round % 61 == 60 {
            r.clean_remount();
        }
        for (o, m) in objs.iter().zip(&model) {
            let Some(m) = m else { continue };
            let want = (
                m.len() as u64,
                m.iter().map(|(k, v)| (k.len() + v.len()) as u64).sum(),
            );
            assert_eq!(ostats(&mut r, &c, o), want, "round {round} {o:?}");
            let (kv, more) = r.st.omap_iter(&c, o, b"", 1000).unwrap();
            assert!(!more);
            let got: M = kv.iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
            assert_eq!(&got, m, "round {round} {o:?}");
        }
    }
    let rep = r.st.check(false).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    r.clean_remount(); // fsck of the image
}

/// Blind removal batches on an object whose keys fill a tree of height >= 3 (4 KiB pages), most removed keys absent:
/// between two present keys, before the first and after the last. The probes of the record's ascending removals route
/// from the previous key's path, no fence key copied and no root descent per key (every route is checked against a full
/// descent in debug builds); contents and counters equal the model; fsck clean.
#[test]
fn sorted_removals_route_in_deep_trees() {
    let (mut r, _) = rig_ns(256, 1, 4096, 5, nvc_cfg(), 4096);
    let c = c1();
    let o = g(b"deep", 1);
    // even indexes present: an odd one is absent between two present keys; 0 and >= 40000 lie outside them
    let key = |i: u64| format!("dk/{:08}", i + 1).into_bytes();
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.touch(c, &o);
    commit(&mut r.st, &t);
    let mut model = BTreeMap::new();
    let present: Vec<u64> = (2..40_000u64).step_by(2).collect();
    for ch in present.chunks(500) {
        let mut t = OTxn::new();
        let mut pairs = Vec::new();
        for &i in ch {
            let v = vec![(i % 251) as u8; 100];
            model.insert(key(i), v.clone());
            pairs.push((key(i).into(), v.into()));
        }
        t.push(TOp::OmapSetKeys {
            cid: c,
            oid: o.clone(),
            pairs,
        });
        commit(&mut r.st, &t);
    }
    r.clean_remount(); // every key in the tree, cold cache
    let h = r.st.shards[0].sh.state().tree.height();
    assert!(h >= 3, "tree height {h}");
    let mut x = 0x1234_5678_9abc_def1u64;
    let mut rnd = |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let s0 = r.st.shards[0].sh.tree_stats();
    let mut keys = 0u64;
    for _ in 0..40 {
        let ks: Vec<Vec<u8>> = (0..200).map(|_| key(rnd(40_200))).collect();
        for k in &ks {
            model.remove(k);
        }
        keys += ks.len() as u64;
        let mut t = OTxn::new();
        t.push(TOp::OmapRmKeys {
            cid: c,
            oid: o.clone(),
            keys: ks.into_iter().map(Into::into).collect(),
        });
        commit(&mut r.st, &t);
    }
    let s1 = r.st.shards[0].sh.tree_stats();
    // a probe that leaves its leaf routes from the leaf's parent (a hint hit) unless the key passed the parent's range
    let desc = s1.descents - s0.descents;
    println!("deep removals h{h}: descents {desc} for {keys} keys");
    assert!(
        (desc as f64) < 0.3 * keys as f64,
        "descents {desc} for {keys} removed keys"
    );
    let want = (
        model.len() as u64,
        model.iter().map(|(k, v)| (k.len() + v.len()) as u64).sum(),
    );
    assert_eq!(ostats(&mut r, &c, &o), want);
    let mut got = BTreeMap::new();
    let mut from = Vec::new();
    loop {
        let (kv, more) = r.st.omap_iter(&c, &o, &from, 4096).unwrap();
        for (k, v) in &kv {
            got.insert(k.to_vec(), v.to_vec());
        }
        if !more {
            break;
        }
        from = kv.last().unwrap().0.to_vec();
        from.push(0);
    }
    assert_eq!(got, model);
    r.clean_remount();
}

/// Range removal costs the pages of the range, not of the object; clear costs nothing extra (no whole-object scan).
#[test]
fn omap_range_removal_scales_with_the_range() {
    let mut r = rig(256, 1);
    let c = c1();
    let o = g(b"big", 1);
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let val = vec![9u8; 200];
    let keys: Vec<Vec<u8>> = (0..60_000u32)
        .map(|i| format!("key/{i:08}").into_bytes())
        .collect();
    for ch in keys.chunks(1000) {
        let mut t = OTxn::new();
        for k in ch {
            t.omap_set(c, &o, k, &val);
        }
        commit(&mut r.st, &t);
    }
    let per = (12 + 200) as u64;
    assert_eq!(ostats(&mut r, &c, &o), (60_000, 60_000 * per));
    r.clean_remount(); // cold cache
    let l0 = r.st.shards[0].sh.tree_stats().loads;
    let mut t = OTxn::new();
    t.push(TOp::OmapRmKeyRange {
        cid: c,
        oid: o.clone(),
        first: TxnBytes::Borrowed(&keys[1000][..]),
        last: TxnBytes::Borrowed(&keys[1500][..]),
    });
    commit(&mut r.st, &t);
    let loads = r.st.shards[0].sh.tree_stats().loads - l0;
    assert_eq!(ostats(&mut r, &c, &o), (59_500, 59_500 * per));
    // 500 keys x 211 B = ~13 leaves + the path + onode/name lookups; never anywhere near the 60000-key object
    assert!(loads < 80, "{loads} page loads for a 500-key range");
    let l1 = r.st.shards[0].sh.tree_stats().loads;
    let mut t = OTxn::new();
    t.push(TOp::OmapClear {
        cid: c,
        oid: o.clone(),
    });
    commit(&mut r.st, &t);
    assert_eq!(ostats(&mut r, &c, &o), (0, 0));
    let loads = r.st.shards[0].sh.tree_stats().loads - l1;
    assert!(loads < 40, "{loads} page loads for omap_clear");
}

fn rm_range_txn(c: CollT, o: &Ghobject, first: &[u8], last: &[u8]) -> OTxn<'static> {
    let mut t = OTxn::new();
    t.push(TOp::OmapRmKeyRange {
        cid: c,
        oid: o.clone(),
        first: TxnBytes::Owned(first.to_vec()),
        last: TxnBytes::Owned(last.to_vec()),
    });
    t
}

/// Random interleaving of puts, key removals, range removals (blind, adr 0476 am. 5), clears and remounts vs a model:
/// content and the scrub recount always exact.
#[test]
fn omap_rm_range_random_vs_model() {
    for seed in 0..6u64 {
        let cfg = StoreCfg {
            shard: ShardCfg {
                cache_pages: 64,
                ..StoreCfg::default().shard
            },
        };
        let (mut r, _) = rig_ns(64, 1, 1024, 50 + seed, cfg, 4096);
        let mut rng = Rng::new(900 + seed);
        let c = c1();
        let o = g(b"idx", 1);
        let mut t = OTxn::new();
        t.mkcoll(c);
        t.touch(c, &o);
        commit(&mut r.st, &t);
        let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let key = |i: u64| format!("k{i:06}").into_bytes();
        for step in 0..260 {
            match rng.below(10) {
                0..=2 => {
                    let mut t = OTxn::new();
                    // within the txn page budget (cache / 2 = 32 pages): blind puts (adr 0476 am. 5) load their leaves
                    // in the record's prepare, where a set beyond the budget is refused
                    for _ in 0..rng.range(1, 40) {
                        let k = key(rng.below(3000));
                        let mut v = vec![0u8; rng.range(0, 400) as usize];
                        rng.fill(&mut v);
                        oset(&mut t, c, &o, k.clone(), v.clone());
                        model.insert(k, v);
                    }
                    commit(&mut r.st, &t);
                }
                3 => {
                    let mut t = OTxn::new();
                    let ks: Vec<Vec<u8>> = (0..rng.range(1, 30))
                        .map(|_| key(rng.below(3000)))
                        .collect();
                    orm(&mut t, c, &o, ks.clone());
                    for k in &ks {
                        model.remove(k);
                    }
                    commit(&mut r.st, &t);
                }
                4..=7 => {
                    let a = rng.below(3000);
                    let (first, last) = (key(a), key(a + rng.range(0, 1500)));
                    let mut t = OTxn::new();
                    if rng.pct(30) {
                        let k = key(rng.below(3000));
                        oset(&mut t, c, &o, k.clone(), b"in-txn".to_vec());
                        model.insert(k, b"in-txn".to_vec());
                    }
                    t.push(TOp::OmapRmKeyRange {
                        cid: c,
                        oid: o.clone(),
                        first: TxnBytes::Owned(first.clone()),
                        last: TxnBytes::Owned(last.clone()),
                    });
                    model.retain(|k, _| !(*k >= first && *k < last));
                    commit(&mut r.st, &t);
                }
                8 => r.clean_remount(),
                _ => {
                    if rng.pct(15) {
                        let mut t = OTxn::new();
                        t.push(TOp::OmapClear {
                            cid: c,
                            oid: o.clone(),
                        });
                        model.clear();
                        commit(&mut r.st, &t);
                    }
                }
            }
            if step % 7 == 0 {
                let all = r.st.omap_all(&c, &o).unwrap();
                assert_eq!(all, model, "seed {seed} step {step}: content");
                let bytes: u64 = model.iter().map(|(k, v)| (k.len() + v.len()) as u64).sum();
                assert_eq!(
                    ostats(&mut r, &c, &o),
                    (model.len() as u64, bytes),
                    "seed {seed} step {step}: recount"
                );
            }
        }
        check_no_leaks(&mut r);
    }
}

fn oset(t: &mut OTxn<'_>, c: CollT, o: &Ghobject, k: Vec<u8>, v: Vec<u8>) {
    t.push(TOp::OmapSetKeys {
        cid: c,
        oid: o.clone(),
        pairs: vec![(TxnBytes::Owned(k), TxnBytes::Owned(v))],
    });
}

fn orm(t: &mut OTxn<'_>, c: CollT, o: &Ghobject, ks: Vec<Vec<u8>>) {
    t.push(TOp::OmapRmKeys {
        cid: c,
        oid: o.clone(),
        keys: ks.into_iter().map(TxnBytes::Owned).collect(),
    });
}

#[test]
#[ignore = "microbench: cargo test --release -p store --test obj perf_cold_omap_rm_range -- --ignored --nocapture"]
fn perf_cold_omap_rm_range() {
    // cold omap range removal: a blind range delete (adr 0476 am. 5), no leaf of the range is read
    let keys: u32 = std::env::var("NKEYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    {
        let env = |k: &str, d: u64| -> u64 {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        let cfg = StoreCfg {
            shard: ShardCfg {
                cache_pages: env("CACHE", 8192) as usize,
                ..StoreCfg::default().shard
            },
        };
        let mut sim = SimConfig::new(2 << 30);
        sim.seed = 9;
        // device profile knobs: default PM1743-like (80 us read, ~3 GB/s); file-like e.g. READ_NS=400000 XFER_NS=400
        sim.read_ns = env("READ_NS", sim.read_ns);
        sim.xfer_ns_per_lba = env("XFER_NS", sim.xfer_ns_per_lba);
        sim.jitter_ns = env("JITTER_NS", sim.jitter_ns);
        let img = fresh_image_ns(2048, 1, 16384, &sim, 8192);
        let (disk, st) = open(&img, &sim, &cfg);
        let mut r = Rig {
            ev: 0,
            disk,
            st,
            sim,
            cfg,
        };
        let (c, o) = (c1(), g(b"index.0", 3));
        omap_fixture(&mut r, c, &o, keys);
        r.clean_remount();
        let key = |i: u32| format!("{:08}", i * 7).into_bytes();
        let (first, last) = (key(keys / 10), key(keys - keys / 10));
        let removed = (keys - 2 * (keys / 10)) as u64;
        let l0 = r.st.shards[0].sh.tree_stats().loads;
        let (t0, w) = (r.st.clk.t, Instant::now());
        commit(&mut r.st, &rm_range_txn(c, &o, &first, &last));
        let blocked_virt = r.st.clk.t - t0;
        let blocked_wall = w.elapsed().as_secs_f64() * 1e6;
        let loads = r.st.shards[0].sh.tree_stats().loads - l0;
        let left = ostats(&mut r, &c, &o);
        assert_eq!(left.0, keys as u64 - removed);
        println!(
            "{keys} keys, {removed} removed: core blocked in store: device wait {:8.0} us + host {blocked_wall:8.0} us | page loads {loads:5}",
            blocked_virt as f64 / 1e3,
        );
    }
}

/// Cold omap removal batches (adr 0647-omap-blind-removals D1): `NKEYS` keys in one object, merged into the tree and
/// remounted (cold cache), then `OPS` txns removing `BATCH` keys each, spread over the object (no two keys in one
/// leaf). A batch of at least `run_min` keys is staged as one run of removals; `RM_TREE=1` splits every batch into two
/// removal ops below `run_min`, the tree path (blind removals: each key's leaf loaded and dirtied at commit). Prints
/// per txn the core's block in the store (virtual device wait + host) and the page loads at commit, then the merge
/// that takes the runs into the tree (page loads, polls).
#[test]
#[ignore = "microbench: cargo test --release -p store --features lab --test obj perf_cold_omap_rm_keys -- --ignored --nocapture"]
fn perf_cold_omap_rm_keys() {
    let env = |k: &str, d: u64| -> u64 {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let (keys, batch, ops) = (
        env("NKEYS", 200_000) as u32,
        env("BATCH", 64) as u32,
        env("OPS", 16) as u32,
    );
    let tree = env("RM_TREE", 0) != 0;
    // keys `stride` apart, more than the entries of one leaf of the fixture (its values compress: about 130 per leaf)
    let stride = keys / (batch * ops);
    assert!(
        stride >= 160,
        "NKEYS too small for BATCH x OPS keys in distinct leaves"
    );
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: env("CACHE", 8192) as usize,
            ..StoreCfg::default().shard
        },
    };
    let mut sim = SimConfig::new(2 << 30);
    sim.seed = 9;
    sim.read_ns = env("READ_NS", sim.read_ns);
    let img = fresh_image_ns(2048, 1, 16384, &sim, 8192);
    let (disk, st) = open(&img, &sim, &cfg);
    let mut r = Rig {
        ev: 0,
        disk,
        st,
        sim,
        cfg,
    };
    let (c, o) = (c1(), g(b"index.0", 3));
    omap_fixture(&mut r, c, &o, keys);
    // the fixture's batches are runs: into the tree, then a cold cache
    r.merge_runs();
    r.clean_remount();
    let name =
        |i: u32| format!("{:08}/some/prefix/with/a/typical/s3/key/name.{i}", i * 7).into_bytes();
    let loads = |r: &Rig| r.st.shards[0].sh.tree_stats().loads;
    let (mut virt, mut wall, mut cl) = (0u64, 0f64, 0u64);
    for op in 0..ops {
        // key j of txn `op`: every txn spreads over the whole object, the txns interleave
        let ks: Vec<Vec<u8>> = (0..batch).map(|j| name((j * ops + op) * stride)).collect();
        let mut t = OTxn::new();
        if tree {
            let (a, b) = ks.split_at(ks.len() / 2);
            orm(&mut t, c, &o, a.to_vec());
            orm(&mut t, c, &o, b.to_vec());
        } else {
            orm(&mut t, c, &o, ks);
        }
        let (l0, t0, w) = (loads(&r), r.st.clk.t, Instant::now());
        commit(&mut r.st, &t);
        (virt, wall, cl) = (
            virt + (r.st.clk.t - t0),
            wall + w.elapsed().as_secs_f64() * 1e6,
            cl + loads(&r) - l0,
        );
    }
    let rms = r.st.shards[0].stats.run_rms;
    assert_eq!(
        rms,
        if tree { 0 } else { ops as u64 },
        "removal runs staged"
    );
    let (l0, w) = (loads(&r), Instant::now());
    let polls = r.merge_runs();
    let (ml, mw) = (loads(&r) - l0, w.elapsed().as_secs_f64() * 1e3);
    assert_eq!(
        ostats(&mut r, &c, &o).0,
        (keys - batch * ops) as u64,
        "every removed key gone"
    );
    let n = ops as f64;
    println!(
        "{} {keys} keys, {ops} txns x {batch} keys: commit blocked: device wait {:6.0} us + host {:6.0} us, page loads {:5.1} per txn | merge of the runs: {ml} page loads, {polls} polls, {mw:.1} ms host",
        if tree { "tree path  " } else { "removal run" },
        virt as f64 / 1e3 / n,
        wall / n,
        cl as f64 / n,
    );
}

/// Write amplification of random small omap updates (RGW-index-like): `NKEYS` keys (60 B key, `VLEN` B value) in one object,
/// then `OPS` random single-key updates at queue depth `QD` (+ optionally an OSD-like pg-log set/trim per op).
/// Prints device bytes per op split WAL / checkpoint pages, latency (virtual, ack - submit), RAM.
#[test]
#[ignore = "microbench: NKEYS=10000000 cargo test --release -p store --test obj perf_omap_random_update_wa -- --ignored --nocapture"]
fn perf_omap_random_update_wa() {
    let env = |k: &str, d: u64| -> u64 {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let nkeys = env("NKEYS", 5_000_000) as u32;
    let ops = env("OPS", 300_000);
    let qd = env("QD", 32) as usize;
    let vlen = env("VLEN", 300) as usize;
    let cache = env("CACHE", 16384) as usize;
    let pglog = env("PGLOG", 1) != 0;
    let mut cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: cache,
            ..StoreCfg::default().shard
        },
    };
    if let Ok(v) = std::env::var("DELTA_CAP") {
        cfg.shard.delta_cap_bytes = v.parse().unwrap(); // 0 = no deltas (baseline)
    }
    if let Ok(v) = std::env::var("DIRTY_SOFT") {
        cfg.shard.dirty_soft_pages = v.parse().unwrap();
        cfg.shard.dirty_hard_pages = cfg.shard.dirty_soft_pages * 3;
    }
    if let Ok(v) = std::env::var("CKPT_NS") {
        cfg.shard.ckpt_interval_ns = v.parse().unwrap();
    }
    let cap = (nkeys as u64 * (vlen as u64 + 80) * 13 / 10).max(1 << 30) + (2 << 30);
    let mut sim = SimConfig::new(cap);
    sim.seed = 11;
    let img = fresh_image_ns(cap >> 20, 1, 262_144, &sim, 8192);
    let (disk, st) = open(&img, &sim, &cfg);
    let mut r = Rig {
        ev: 0,
        disk,
        st,
        sim,
        cfg,
    };
    let (c, o, pgm) = (c1(), g(b"index.0", 3), g(b"pgmeta", 4));
    let key =
        |i: u32| format!("{:08}/some/prefix/with/a/typical/s3/key/name.{i}", i * 7).into_bytes();
    let t0 = Instant::now();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let val = vec![0x5au8; vlen];
    for ch in (0..nkeys).collect::<Vec<_>>().chunks(500) {
        let mut t = OTxn::new();
        for &i in ch {
            oset(&mut t, c, &o, key(i), val.clone());
        }
        commit(&mut r.st, &t);
    }
    r.st.checkpoint().unwrap();
    println!(
        "fill {nkeys} keys x {vlen} B: {:.1} s wall; tree pages resident {}",
        t0.elapsed().as_secs_f64(),
        r.st.shards[0].sh.state().tree.resident_pages()
    );
    // cold start for the update phase: fresh mount (cache empty), as after a restart
    r.clean_remount();
    let s0 = r.st.shards[0].sh.stats;
    let d0 = r.disk.stats();
    let l0 = r.st.shards[0].sh.tree_stats().loads;
    let mut rng = Rng::new(77);
    let mut lat: Vec<f64> = Vec::with_capacity(ops as usize);
    let mut inflight: std::collections::HashMap<u64, u64> = Default::default();
    let (mut issued, mut done) = (0u64, 0u64);
    let v0 = r.st.clk.t;
    let w0 = Instant::now();
    let mut acked = Vec::new();
    while done < ops {
        while issued < ops && inflight.len() < qd {
            let mut t = OTxn::new();
            let i = rng.below(nkeys as u64) as u32;
            let mut v = val.clone();
            v[0] = issued as u8;
            oset(&mut t, c, &o, key(i), v);
            if pglog {
                oset(
                    &mut t,
                    c,
                    &pgm,
                    format!("log.{issued:016}").into_bytes(),
                    vec![7u8; 150],
                );
                if issued >= 3000 {
                    orm(
                        &mut t,
                        c,
                        &pgm,
                        vec![format!("log.{:016}", issued - 3000).into_bytes()],
                    );
                }
            }
            issued += 1;
            let tok = issued;
            let ts = r.st.clk.t;
            match r.st.queue(&t, tok) {
                Ok(_) => {
                    inflight.insert(tok, ts);
                }
                Err(ObjError::Store(store::StoreError::Busy)) => {
                    issued -= 1;
                    break;
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        acked.clear();
        r.st.poll(&mut acked).unwrap();
        for tok in acked.drain(..) {
            let ts = inflight.remove(&tok).unwrap();
            lat.push((r.st.clk.t - ts) as f64 / 1e3);
            done += 1;
        }
        if inflight.len() >= qd || issued >= ops {
            r.st.idle();
        }
    }
    let virt = (r.st.clk.t - v0) as f64 / 1e9;
    let wall = w0.elapsed().as_secs_f64();
    let s1 = r.st.shards[0].sh.stats;
    let d1 = r.disk.stats();
    let lb = r.sim.lba_size as u64;
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| lat[((lat.len() as f64 * q) as usize).min(lat.len() - 1)];
    let n = ops as f64;
    let wal = (s1.wal_bytes - s0.wal_bytes) as f64 / n;
    let ck = (s1.ckpt_pages - s0.ckpt_pages) as f64 * 8192.0 / n;
    let tot = (d1.write_lbas - d0.write_lbas) as f64 * lb as f64 / n;
    let payload = (vlen + 60 + if pglog { 150 + 28 } else { 0 }) as f64;
    let ts = r.st.shards[0].sh.tree_stats();
    println!(
        "delta: entries {} declined {} folded {} pages {} | chain RAM {} KiB",
        ts.delta_entries,
        ts.delta_declined,
        ts.delta_folded,
        ts.delta_pages,
        r.st.shards[0].sh.state().tree.delta_chain_bytes() / 1024
    );
    println!(
        "{nkeys} keys, {ops} random updates ({} B payload/op, QD{qd}, cache {cache} pages, pglog {pglog}):\n  device bytes/op: total {tot:.0} = WAL {wal:.0} + checkpoint pages {ck:.0} + other {:.0}  => WA {:.1}x of payload\n  checkpoints {}, ckpt pages {}, page loads/op {:.2}, forced ckpts {}\n  latency (virtual, ack-submit) p50 {:.0} us p99 {:.0} us; throughput {:.0} ops/s virtual, {:.0} ops/s wall\n  RAM: resident tree pages {} ({} MiB)",
        payload as u64,
        tot - wal - ck,
        tot / payload,
        s1.checkpoints - s0.checkpoints,
        s1.ckpt_pages - s0.ckpt_pages,
        (r.st.shards[0].sh.tree_stats().loads - l0) as f64 / n,
        s1.forced_ckpts - s0.forced_ckpts,
        p(0.5),
        p(0.99),
        n / virt,
        n / wall,
        r.st.shards[0].sh.state().tree.resident_pages(),
        r.st.shards[0].sh.state().tree.resident_pages() * 8 / 1024,
    );
}

/// Pump the store until the lazy subtree free of every shard has drained and its progress is checkpointed.
fn drain_dead(r: &mut Rig) {
    for _ in 0..20_000_000 {
        let busy = r.st.shards.iter().any(|s| {
            let t = &s.sh.state().tree;
            t.dead_len() > 0 || t.dead_dirty() || s.sh.ckpt_active()
        });
        if !busy {
            return;
        }
        let mut acked = vec![];
        r.st.poll(&mut acked).unwrap();
        r.st.idle();
    }
    panic!("lazy free never drained");
}

/// adr 0021 am. 18: clearing / deleting an object whose omap covers more interior pages than the per-txn walk limit
/// (`cache_pages / 4`) used to fail with `TooLarge`; the covered subtrees are detached unread and freed in the background.
#[test]
fn huge_omap_clear_and_remove_beyond_the_walk_limit() {
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: 64, // walk limit 16 interior pages
            ..StoreCfg::default().shard
        },
    };
    let (mut r, _) = rig_ns(256, 1, 4096, 77, cfg, 4096);
    let (c, o) = (c1(), g(b"bucket.index.0", 3));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let val = vec![7u8; 100];
    let key = |i: u32| format!("{:08}/some/key/name", i).into_bytes();
    let n = 90_000u32;
    for ch in (0..n).collect::<Vec<_>>().chunks(100) {
        let mut t = OTxn::new();
        for &i in ch {
            oset(&mut t, c, &o, key(i), val.clone());
        }
        commit(&mut r.st, &t);
    }
    assert_eq!(ostats(&mut r, &c, &o).0, n as u64);
    for remove in [false, true] {
        r.clean_remount();
        let det0 = r.st.shards[0].sh.tree_stats().dead_detached;
        let mut t = OTxn::new();
        if remove {
            t.push(TOp::Remove {
                cid: c,
                oid: o.clone(),
            });
        } else {
            t.push(TOp::OmapClear {
                cid: c,
                oid: o.clone(),
            });
        }
        let (v0, w0) = (r.st.clk.t, Instant::now());
        commit(&mut r.st, &t);
        println!(
            "{} of a {n}-key omap object: {} us device time, {:.0} us host, {} subtrees detached",
            if remove { "remove" } else { "omap_clear" },
            (r.st.clk.t - v0) / 1000,
            w0.elapsed().as_secs_f64() * 1e6,
            r.st.shards[0].sh.tree_stats().dead_detached - det0
        );
        assert!(r.st.shards[0].sh.tree_stats().dead_detached > det0);
        drain_dead(&mut r);
        if remove {
            assert!(!r.st.exists(&c, &o).unwrap());
        } else {
            assert_eq!(ostats(&mut r, &c, &o), (0, 0));
            // the object is usable again and the freed space is reusable
            for ch in (0..30_000u32).collect::<Vec<_>>().chunks(100) {
                let mut t = OTxn::new();
                for &i in ch {
                    oset(&mut t, c, &o, key(i), val.clone());
                }
                commit(&mut r.st, &t);
            }
            assert_eq!(ostats(&mut r, &c, &o).0, 30_000);
            // back to a big one for the removal round
            for ch in (30_000..n).collect::<Vec<_>>().chunks(100) {
                let mut t = OTxn::new();
                for &i in ch {
                    oset(&mut t, c, &o, key(i), val.clone());
                }
                commit(&mut r.st, &t);
            }
        }
        check_no_leaks(&mut r);
    }
    r.clean_remount();
    check_no_leaks(&mut r);
}

#[test]
#[ignore = "microbench: NKEYS=5000000 cargo test --release -p store --test obj perf_cold_omap_object_delete -- --ignored --nocapture"]
fn perf_cold_omap_object_delete() {
    // adr 0021 am. 18: delete of a huge omap object (cold cache), eager free (reads every interior page of the range in
    // the txn, limited to the walk budget) vs the lazy detach + background drain. Simulated PM1743-like device.
    let keys: u32 = std::env::var("NKEYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);
    for lazy in [false, true] {
        LAZY_FREE.set(lazy);
        let cfg = StoreCfg {
            shard: ShardCfg {
                cache_pages: 16384,
                max_walk_pages: 1 << 20, // let the eager path try (its default budget is 2048 interior pages)
                ..StoreCfg::default().shard
            },
        };
        let cap = (keys as u64 * 420).max(1 << 30) + (1 << 30);
        let mut sim = SimConfig::new(cap);
        sim.seed = 9;
        let img = fresh_image_ns(cap >> 20, 1, 16384, &sim, 8192);
        let (disk, st) = open(&img, &sim, &cfg);
        let mut r = Rig {
            ev: 0,
            disk,
            st,
            sim,
            cfg,
        };
        let (c, o) = (c1(), g(b"index.0", 3));
        omap_fixture(&mut r, c, &o, keys);
        r.clean_remount();
        let used0 = r.st.shards[0].sh.statfs().meta_used;
        let l0 = r.st.shards[0].sh.tree_stats().loads;
        let mut t = OTxn::new();
        t.push(TOp::OmapClear {
            cid: c,
            oid: o.clone(),
        });
        let (v0, w0) = (r.st.clk.t, Instant::now());
        commit(&mut r.st, &t);
        let (blocked_virt, blocked_wall) = (
            (r.st.clk.t - v0) as f64 / 1e3,
            w0.elapsed().as_secs_f64() * 1e6,
        );
        let loads = r.st.shards[0].sh.tree_stats().loads - l0;
        let det = r.st.shards[0].sh.tree_stats().dead_detached;
        let v1 = r.st.clk.t;
        while r.st.shards[0].sh.state().tree.dead_len() > 0 {
            let mut acked = vec![];
            r.st.poll(&mut acked).unwrap();
            r.st.idle();
        }
        let drain_virt = (r.st.clk.t - v1) as f64 / 1e6;
        drain_dead(&mut r);
        let st = r.st.shards[0].sh.tree_stats();
        println!(
            "{:5} free, {keys} keys ({:.0} MiB of tree pages): delete txn blocks the core {blocked_virt:9.0} us device wait + {blocked_wall:9.0} us host, {loads:5} page loads, {det} subtrees detached | drain {drain_virt:7.1} ms device time ({} detached pages freed in the background) | meta pages in use {} -> {}",
            if lazy { "lazy" } else { "eager" },
            used0 as f64 * 8.0 / 1024.0,
            st.dead_freed,
            used0,
            r.st.shards[0].sh.statfs().meta_used
        );
    }
    LAZY_FREE.set(true);
}

#[test]
fn size_mismatch_flags_only_a_shrunk_device() {
    let mut r = rig(16, 2);
    assert_eq!(r.st.size_mismatch(), None);
    let label = r.st.sb.size_bytes;
    // mkfs recorded a bigger device than the one now open (the namespace was shrunk)
    r.st.sb.size_bytes = label + (4 << 20);
    assert_eq!(r.st.size_mismatch(), Some((label + (4 << 20), label)));
    // device grew since mkfs: fine
    r.st.sb.size_bytes = label - (4 << 20);
    assert_eq!(r.st.size_mismatch(), None);
}

// ---- legacy format variants (mkfs params with bits off): a mount keeps exactly the bits the store has

fn legacy_params(elastic_only: bool) -> MkfsParams {
    MkfsParams {
        shards: 1,
        wal_blocks: 1024,
        align_blocks: 1,
        meta_pct: 8,
        // `elastic_only`: a store of an intermediate age (am. 12/13 but not 14-19)
        elastic_meta: elastic_only,
        compact_int: elastic_only,
        inline_data: false,
        omap_runs: false,
        lazy_free: false,
        leaf_delta: false,
        lazy_pginfo: false,
        long_names: false,
        shared_ext: false,
        ext_values: false,
        ..Default::default()
    }
}

fn sb_features(img: &SimImage, sim: &SimConfig) -> u64 {
    let d = SimDisk::from_image(img, sim.clone());
    read_super(&mut d.queue(), &mut SimClock::default())
        .unwrap()
        .0
        .features
}

/// Default mount: the store keeps exactly the feature bits it has through restarts, writes, checkpoints and deletes, so the
/// build that made it (the "old mask") can still mount it; the only bit a mount adds is `FEAT_LOG_DUPS` (adr 0634).
#[test]
fn mount_keeps_the_features_of_an_old_store() {
    for elastic_only in [false, true] {
        let mut sim = SimConfig::new(32 << 20);
        sim.seed = 6;
        let disk = SimDisk::new(sim.clone());
        mkfs(
            &mut disk.queue(),
            &mut SimClock::default(),
            &legacy_params(elastic_only),
        )
        .unwrap();
        let mut img = disk.image();
        let old = sb_features(&img, &sim) | store::layout::FEAT_LOG_DUPS;
        let c = c1();
        let cfg = StoreCfg::default();
        let big = vec![0x5au8; 3000];
        for round in 0..3u32 {
            let (d, mut st) = open(&img, &sim, &cfg);
            assert_eq!(st.features(), old);
            // features off: no inline data, no omap counters
            assert_eq!(st.shards[0].inline_max, 0);
            let mut t = OTxn::new();
            if round == 0 {
                t.mkcoll(c);
            }
            let keys: Vec<String> = (0..20u32).map(|k| format!("k{k:03}")).collect();
            for i in 0..40u32 {
                let o = g(format!("r{round}o{i}").as_bytes(), i);
                t.write(c, &o, 0, &big[..(100 + i as usize * 70)]);
                for k in &keys {
                    t.omap_set(c, &o, k.as_bytes(), &big[..64]);
                }
            }
            commit(&mut st, &t);
            // delete one object with omap of the previous round (eager free path of a store without lazy free)
            if round > 0 {
                let mut t = OTxn::new();
                t.remove(c, &g(format!("r{}o3", round - 1).as_bytes(), 3));
                commit(&mut st, &t);
            }
            st.checkpoint().unwrap();
            let rep = st.check(true).unwrap();
            assert!(rep.errors.is_empty(), "{:?}", rep.errors);
            assert_eq!(rep.inline_objects, 0);
            img = d.image();
            assert_eq!(sb_features(&img, &sim), old, "round {round}");
        }
        // everything written is readable
        let (_, mut st) = open(&img, &sim, &cfg);
        assert_eq!(
            st.read(&c, &g(b"r1o5", 5), 0, 1 << 20).unwrap(),
            &big[..(100 + 5 * 70)]
        );
        assert!(st.read(&c, &g(b"r0o3", 3), 0, 10).is_err());
    }
}

/// No in-place upgrade: a store of an older format (a legacy feature mask when the daemon requires the current one; other `FORMAT_VERSION`s: `layout` unit test) is refused at mount with a "re-mkfs" error, never misread.
#[test]
fn old_format_store_is_refused_with_remkfs() {
    let mut sim = SimConfig::new(32 << 20);
    sim.seed = 8;
    let disk = SimDisk::new(sim.clone());
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &legacy_params(false),
    )
    .unwrap();
    let mount = |img: &SimImage, require: bool| {
        let d = SimDisk::from_image(img, sim.clone());
        let mut cfg = StoreCfg::default();
        cfg.shard.require_current = require;
        Store::mount(|| d.queue(), SimClock::default(), cfg).map(|_| ())
    };
    let img = disk.image();
    // legacy feature mask: mounts for tests/lab, refused when the current format is required
    mount(&img, false).unwrap();
    match mount(&img, true) {
        Err(e) => assert!(e.to_string().contains("re-mkfs"), "{e}"),
        Ok(()) => panic!("legacy store mounted"),
    }
}

// ------------------------------------------------------------------------------- memory accounting (adr 0062)

#[test]
fn mem_accounting_tracks_resident_pages_and_stays_in_budget() {
    // plain values: a value class installing its dictionary dirties one more leaf (touch log), the test counts those buffers
    let mut r = rig_nvc(64, 2);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let m0 = r.st.mem();
    for i in 0..200u32 {
        let name = format!("o{i}");
        let o = g(name.as_bytes(), i);
        let mut t = OTxn::new();
        t.write(c, &o, 0, &[7u8; 100]);
        let keys: Vec<String> = (0..20u32).map(|k| format!("key{k:04}")).collect();
        for key in &keys {
            t.omap_set(c, &o, key.as_bytes(), &[1u8; 64]);
        }
        commit(&mut r.st, &t);
    }
    let m = r.st.mem();
    assert!(m.tree.pages > m0.tree.pages && m.tree.page_bytes >= m.tree.pages * 4096);
    assert!(m.point_entries > 0 && m.point_bytes > m.point_entries * 80);
    assert!(m.alloc_bytes > 0 && m.alloc_chunks > 0);
    // allocator chunks come from the pre-filled pool: no heap allocation on the write path
    assert_eq!(m.alloc_pool_misses, 0);
    // resident pages never exceed the configured per-shard cache (+ the transient txn working set)
    let cap = r.cfg.shard.cache_pages as u64 * 2;
    assert!(
        m.tree.pages <= cap + 64,
        "{} pages > cap {cap}",
        m.tree.pages
    );
    // the point cache is bounded by its entry cap
    assert!(m.point_entries <= r.cfg.shard.point_cache as u64 * 2);
    r.st.checkpoint().unwrap();
    for i in 0..200u32 {
        let name = format!("o{i}");
        let o = g(name.as_bytes(), i);
        let mut t = OTxn::new();
        t.omap_set(c, &o, b"key0003", &[2u8; 64]);
        commit(&mut r.st, &t);
    }
    let hot = r.st.mem();
    assert!(
        hot.tree.touched_bytes > 0,
        "delta tracking is on: dirty leaves carry touch logs"
    );
    // after a checkpoint clean pages hold no delta touch log (it would sit outside the cache budget): the buffers went
    // back to the pool (bounded: cache_pages / 8 per shard) for the next dirty leaves
    r.st.checkpoint().unwrap();
    let m = r.st.mem();
    assert_eq!(m.tree.touched_bytes, m.tree.touch_pool_bytes);
    assert!(m.tree.touch_pool_bytes > 0 && m.tree.touch_pool_bytes <= hot.tree.touched_bytes);
    // re-dirtying the same leaves takes the pooled buffers: no new allocation
    for i in 0..200u32 {
        let name = format!("o{i}");
        let o = g(name.as_bytes(), i);
        let mut t = OTxn::new();
        t.omap_set(c, &o, b"key0004", &[3u8; 64]);
        commit(&mut r.st, &t);
    }
    assert_eq!(r.st.mem().tree.touched_bytes, m.tree.touched_bytes);
    r.st.checkpoint().unwrap();
    let m = r.st.mem();
    // no checkpoint copy outlives its checkpoint but the arena kept for the next freeze: reused, not accumulated
    assert!(
        m.ckpt_bytes > 0,
        "the arena is kept for the next checkpoint"
    );
    for i in 0..200u32 {
        let name = format!("o{i}");
        let o = g(name.as_bytes(), i);
        let mut t = OTxn::new();
        t.omap_set(c, &o, b"key0004", &[4u8; 64]);
        commit(&mut r.st, &t);
    }
    r.st.checkpoint().unwrap();
    assert_eq!(r.st.mem().ckpt_bytes, m.ckpt_bytes, "the same arena again");
    assert_eq!(
        m.tree.free_slots + m.tree.pages,
        m.tree.slab_slots,
        "every slab slot is live or free"
    );
}

#[test]
fn a_write_with_more_extents_than_the_device_queue_is_applied_not_refused() {
    // adr 0066: 16 MiB = 64 device extents against a queue of 48 (a replica with fragmented free space or a small
    // SPDK qpair): check_txn passes, the commit lands in waves, the data reads back and survives a remount
    let (mut r, _) = rig_with(128, 1, 1024, 9, StoreCfg::default());
    let img = r.disk.image();
    r.sim.queue_depth = 48;
    let (d, s) = open(&img, &r.sim, &r.cfg);
    r.disk = d;
    r.st = s;
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let o = g(b"big", 1);
    let data: Vec<u8> = (0..16u32 << 20).map(|i| (i % 253) as u8).collect();
    let mut t = OTxn::new();
    t.write(c, &o, 0, &data);
    t.setattr(c, &o, b"_", b"oi");
    assert_eq!(r.st.check_txn(&t), Ok(()));
    commit(&mut r.st, &t);
    // waves: for queue room (adr 0066) or for the device window (adr 0643-device-admission-fifo)
    let sh = &r.st.shards[0].sh;
    assert!(
        sh.stats.backlog_writes + sh.admit_gauges().2.waits > 0,
        "data went out in waves"
    );
    assert!(r.st.read(&c, &o, 0, data.len() as u64).unwrap() == data);
    r.st.checkpoint().unwrap();
    let img = r.disk.image();
    let (_d, mut s2) = open(&img, &r.sim, &r.cfg);
    assert!(s2.read(&c, &o, 0, data.len() as u64).unwrap() == data);
    let rep = s2.check(true).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}

#[test]
fn warm_data_parks_on_an_undurable_write_and_wakes_when_durable() {
    // a read of an object whose newest write is not durable yet must not spin in `wait_durable`: warm_data refuses
    // (WouldBlock), the durable advance raises the wake, then the read runs without any durable wait
    let (mut r, _) = rig_with(64, 1, 1024, 21, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let o = g(b"racy", 3);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &[1u8; 16384]);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    let mut t = OTxn::new();
    t.write(c, &o, 4096, &[9u8; 4096]);
    r.st.queue(&t, 77).unwrap();
    assert!(!r.st.warm_data(&c, &o, 0, 16384).unwrap(), "must park");
    let waits = r.st.shards[0].stats.durable_waits;
    let mut acked = vec![];
    let mut woke = false;
    for _ in 0..100_000 {
        r.st.poll(&mut acked).unwrap();
        woke |= r.st.take_wake();
        if acked.contains(&77) {
            break;
        }
        r.st.idle();
    }
    assert!(acked.contains(&77), "write never became durable");
    assert!(woke, "durable advance did not wake the parked op");
    warm_all(&mut r, &c, &o, 16384);
    let got = r.st.read(&c, &o, 0, 16384).unwrap();
    assert_eq!(&got[..4096], &[1u8; 4096][..]);
    assert_eq!(&got[4096..8192], &[9u8; 4096][..]);
    assert_eq!(&got[8192..], &[1u8; 8192][..]);
    assert_eq!(
        r.st.shards[0].stats.durable_waits, waits,
        "the read spun in wait_durable"
    );
}

#[test]
fn warm_data_of_the_boundary_block_serves_a_partial_write_without_a_device_wait() {
    // read-modify-write: the engine probes the partial head block with warm_data; the write's staging then finds the
    // block in the prefetch table (no device read, no spin) and the result keeps the untouched bytes
    let (mut r, _) = rig_with(64, 1, 1024, 22, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let o = g(b"rmw", 4);
    let base: Vec<u8> = (0..16384).map(|i| (i * 13 % 251) as u8).collect();
    let mut t = OTxn::new();
    t.write(c, &o, 0, &base);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    let mut spins = 0;
    while !(r.st.warm(&c, &o, 100, 1).unwrap() && r.st.warm_data(&c, &o, 100, 1).unwrap()) {
        spins += 1;
        assert!(spins < 100_000);
        let mut acked = vec![];
        r.st.poll(&mut acked).unwrap();
        if !r.st.take_wake() {
            r.st.idle();
        }
    }
    let before = r.st.shards[0].stats.read_ios;
    let mut t = OTxn::new();
    t.write(c, &o, 100, &[0xEEu8; 50]);
    commit(&mut r.st, &t);
    assert_eq!(
        r.st.shards[0].stats.read_ios, before,
        "the partial write read the device"
    );
    let mut want = base.clone();
    want[100..150].fill(0xEE);
    assert_eq!(r.st.read(&c, &o, 0, 16384).unwrap(), want);
}

/// Drive the store until the boundary block of `off` is probed ready (`warm` + `warm_data(off, 1)`, like the opexec
/// gate does for a read-modify-write).
fn probe_blk(r: &mut Rig, c: &CollT, o: &Ghobject, off: u64) {
    let mut spins = 0;
    while !(r.st.warm(c, o, off, 1).unwrap() && r.st.warm_data(c, o, off, 1).unwrap()) {
        spins += 1;
        assert!(spins < 100_000, "probe never completed");
        let mut acked = vec![];
        r.st.poll(&mut acked).unwrap();
        if !r.st.take_wake() {
            r.st.idle();
        }
    }
}

#[test]
fn rmw_probe_is_never_served_after_its_block_was_rewritten() {
    // adr 0043 am. 4: the gate probes a partial write's boundary block, then ops ordered before it (or earlier ops of
    // its own txn) may rewrite that block before its staging runs. The prefetch is keyed by device address (COW: a
    // rewrite lands elsewhere, the old address stays pinned), so the staging must never merge into the old content.
    let (mut r, _) = rig_with(64, 1, 1024, 23, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let o = g(b"rmw-stale", 4);
    let base: Vec<u8> = (0..16384).map(|i| (i * 31 % 251) as u8).collect();
    let mut t = OTxn::new();
    t.write(c, &o, 0, &base);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    let patch = [0xEEu8; 50];
    let mut want = base.clone();
    let wr = |r: &mut Rig, off: u64, d: &[u8]| {
        let mut t = OTxn::new();
        t.write(c, &o, off, d);
        commit(&mut r.st, &t);
    };
    // full rewrite of block 0 between probe and staging
    probe_blk(&mut r, &c, &o, 100);
    wr(&mut r, 0, &[0x11; 4096]);
    wr(&mut r, 100, &patch);
    want[..4096].fill(0x11);
    want[100..150].copy_from_slice(&patch);
    assert_eq!(r.st.read(&c, &o, 0, 16384).unwrap(), want, "rewrite");
    // clone, then the head's block 1 rewritten: the clone keeps the old block, the head merges into the new one
    let oc = g(b"rmw-stale-clone", 4);
    probe_blk(&mut r, &c, &o, 4196);
    let mut t = OTxn::new();
    t.push(TOp::Clone {
        cid: c,
        src: o.clone(),
        dst: oc.clone(),
    });
    commit(&mut r.st, &t);
    let snap = want.clone();
    wr(&mut r, 4096, &[0x22; 4096]);
    wr(&mut r, 4196, &patch);
    want[4096..8192].fill(0x22);
    want[4196..4246].copy_from_slice(&patch);
    assert_eq!(r.st.read(&c, &o, 0, 16384).unwrap(), want, "clone: head");
    assert_eq!(r.st.read(&c, &oc, 0, 16384).unwrap(), snap, "clone: clone");
    // zero of block 0
    probe_blk(&mut r, &c, &o, 100);
    let mut t = OTxn::new();
    t.zero(c, &o, 0, 4096);
    commit(&mut r.st, &t);
    wr(&mut r, 100, &patch);
    want[..4096].fill(0);
    want[100..150].copy_from_slice(&patch);
    assert_eq!(r.st.read(&c, &o, 0, 16384).unwrap(), want, "zero");
    // truncate into block 2, then block 2 rewritten
    probe_blk(&mut r, &c, &o, 8292);
    let mut t = OTxn::new();
    t.truncate(c, &o, 8192);
    commit(&mut r.st, &t);
    wr(&mut r, 8192, &[0x33; 4096]);
    wr(&mut r, 8292, &patch);
    want.truncate(8192);
    want.extend_from_slice(&[0x33; 4096]);
    want[8292..8342].copy_from_slice(&patch);
    assert_eq!(r.st.read(&c, &o, 0, 16384).unwrap(), want, "truncate");
    // one txn: an earlier op rewrites the block a later partial write merges into
    probe_blk(&mut r, &c, &o, 4196);
    let mut t = OTxn::new();
    t.write(c, &o, 4096, &[0x44; 4096]);
    t.write(c, &o, 4196, &patch);
    commit(&mut r.st, &t);
    want[4096..8192].fill(0x44);
    want[4196..4246].copy_from_slice(&patch);
    assert_eq!(r.st.read(&c, &o, 0, 16384).unwrap(), want, "same txn");
    // probes whose op never ran (PG torn down / op dropped while parked): expire, pins released, nothing held
    for off in [100, 4196, 8292] {
        probe_blk(&mut r, &c, &oc, off);
    }
    assert!(r.st.shards[0].pf_usage().0 > 0);
    for _ in 0..250_000 {
        let mut a = vec![];
        r.st.poll(&mut a).unwrap();
        r.st.idle();
    }
    assert_eq!(r.st.shards[0].pf_usage(), (0, 0));
    r.st.checkpoint().unwrap();
    assert_eq!(r.st.shards[0].sh.statfs().data_held, 0);
    let rep = r.st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}

#[test]
fn many_parked_rmw_ops_stay_within_the_prefetch_caps_and_all_complete() {
    // adr 0043 am. 4 memory bound: more parked read-modify-writes (head + tail block each, admitted separately) than
    // the table holds (1024 entries per shard; 700 ops x 2): the table never exceeds its caps, no op holds half its blocks forever
    // (arrival-order admission), every op completes and merges into the right content
    let (mut r, _) = rig_with(128, 1, 1024, 24, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let n = 700u32;
    let objs: Vec<Ghobject> = (0..n).map(|i| g(format!("m{i}").as_bytes(), i)).collect();
    for (i, o) in objs.iter().enumerate() {
        let d = [(i % 251) as u8; 8192];
        let mut t = OTxn::new();
        t.write(c, o, 0, &d);
        t.setattr(c, o, b"_", b"oi");
        commit(&mut r.st, &t);
    }
    r.clean_remount();
    let patch = [0xABu8; 5000];
    let mut pending: VecDeque<usize> = (0..n as usize).collect();
    let (mut acked, mut done, mut rounds, mut peak) = (vec![], 0usize, 0u32, (0usize, 0u64));
    while done < n as usize {
        rounds += 1;
        assert!(
            rounds < 200_000,
            "parked rmw ops starved: {done} of {n} done"
        );
        let hold = peak.0 < 1024 && rounds < 20_000;
        let mut left = VecDeque::new();
        while let Some(i) = pending.pop_front() {
            let o = &objs[i];
            // both boundary probes in one pass, like `Engine::cold`
            let ready = r.st.warm(&c, o, 100, 5000).unwrap()
                && r.st.warm_data(&c, o, 100, 1).unwrap() & r.st.warm_data(&c, o, 5099, 1).unwrap();
            let u = r.st.shards[0].pf_usage();
            peak = (peak.0.max(u.0), peak.1.max(u.1));
            assert!(
                u.0 <= 1024 && u.1 <= 8192,
                "prefetch table over its caps: {u:?}"
            );
            // the first rounds hold every op (parked behind other work): the table fills up to its caps
            if ready && !hold && r.st.admission_ready() {
                let mut t = OTxn::new();
                t.write(c, o, 100, &patch);
                r.st.queue(&t, 1000 + i as u64).unwrap();
            } else {
                left.push_back(i);
            }
        }
        pending = left;
        r.st.poll(&mut acked).unwrap();
        done += acked.drain(..).count();
        if !r.st.take_wake() {
            r.st.idle();
        }
    }
    assert!(
        peak.0 == 1024,
        "the caps were never reached ({peak:?}): test too small"
    );
    for i in [0usize, 345, n as usize - 1] {
        let mut want = vec![(i % 251) as u8; 8192];
        want[100..5100].copy_from_slice(&patch);
        assert_eq!(r.st.read(&c, &objs[i], 0, 8192).unwrap(), want);
    }
}

// ---------------------------------------------------------------------------------------------- PG-log-shaped omap traffic

#[test]
fn model_pgmeta_log_traffic() {
    // PG-log-like omap traffic on PG metadata objects (rising keys, range trims, dup drops) next to every other op kind
    // on them and on regular objects (writes, clones, renames, removes, clears, headers, attrs, big values): content,
    // listing and counters vs the model, with remounts; 8 KiB pages one shard, 4 KiB pages four shards with storms
    with_pgmeta(40, || {
        for seed in 1..7 {
            run_model_cfg(seed, 1, 250, 80, StoreCfg::default(), 8192, 0);
        }
    });
    with_pgmeta(30, || {
        for seed in 20..22 {
            run_model_cfg(seed, 4, 160, 70, StoreCfg::default(), 4096, 20);
        }
    });
}

#[test]
fn crash_matrix_objects_pgmeta_log_traffic() {
    with_pgmeta(50, || {
        let (n, c) = crash_matrix(
            22,
            5,
            &[
                CrashPolicy::DROP_ALL,
                CrashPolicy::PERSIST_ALL,
                CrashPolicy::MIXED,
            ],
            700,
            1,
        );
        assert!(n > 100 && c * 2 > n, "scenarios {n}, crashed {c}");
    });
}

#[test]
#[ignore = "soak"]
fn crash_matrix_objects_pgmeta_log_traffic_soak() {
    for pct in [50u8, 80] {
        with_pgmeta(pct, || {
            for gs in 30..60 {
                crash_matrix(
                    28,
                    gs,
                    &[
                        CrashPolicy::MIXED,
                        CrashPolicy::DROP_ALL,
                        CrashPolicy::PERSIST_ALL,
                    ],
                    900,
                    1,
                );
            }
            for seed in 200..240 {
                run_model_cfg(
                    seed,
                    if seed % 2 == 0 { 4 } else { 1 },
                    500,
                    120,
                    StoreCfg::default(),
                    8192,
                    15,
                );
            }
        });
    }
}

#[test]
fn removing_the_first_child_of_a_full_compact_interior_page() {
    // regression (adr 0021 am. 28): PG-log-like omap traffic (rising keys, range trims) emptied the first child of a
    // full compact interior page; its removal rebuilt the page without slot 0 and the rebuild overflowed (assert in
    // `Tree::int_remove_child`, during txn apply = OSD crash)
    with_pgmeta(80, || {
        run_model_cfg(230, 4, 500, 120, StoreCfg::default(), 8192, 15);
    });
}

// ------------------------------------------------------------------------------------ long names (adr 0021 am. 30)

thread_local! {
    /// Add the long-name universe (`long_universe`) to the generators of this test thread.
    static LONGNAME_GEN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn lo(oid: &[u8], key: &[u8], ns: &[u8], hash: u32, snap: u64) -> Ghobject {
    let mut h = Hobject::new(oid, SnapId(snap), hash, 1, ns);
    h.set_key(key);
    Ghobject::new(h, Ghobject::NO_GEN, ShardId::NO_SHARD)
}

/// Names around the `N`/`L` boundary (8 KiB pages: `N` key limit 3323 = locator-less name ~1640 bytes), all of them
/// storable: locator-less 1600..2048, with NUL bytes, clones, a long namespace, long locators with short oids, and
/// short names of the same hash and effective keys (merge order between the two indexes).
fn long_universe() -> Vec<Ghobject> {
    const H: u32 = 0x1234_5678;
    let a = |n: usize| vec![b'a'; n];
    let mut nul = a(1700);
    for i in (0..nul.len()).step_by(17) {
        nul[i] = 0;
    }
    let k1700 = vec![b'k'; 1700];
    let mut v = vec![
        lo(&a(1600), b"", b"", H, u64::MAX - 1), // N
        lo(&a(1700), b"", b"", H, u64::MAX - 1), // L
        lo(&a(1700), b"", b"", H, 3),            // clone, L
        lo(&a(2047), b"", b"", H, u64::MAX - 1),
        lo(&a(2048), b"", b"", H, u64::MAX - 1),
        lo(&a(2048), b"", b"", H, 1),
        lo(&nul, b"", b"", H, u64::MAX - 1),
        lo(&k1700, b"", b"", H, u64::MAX - 1), // L, same effective key as the next two (N)
        lo(b"a", &k1700, b"", H, u64::MAX - 1),
        lo(b"z", &k1700, b"", H, u64::MAX - 1),
        lo(b"a", &vec![b'k'; 2048], b"", H, u64::MAX - 1),
        lo(&a(1700), b"", &vec![b'n'; 256], H, u64::MAX - 1), // L
        lo(&a(1500), b"", &vec![b'n'; 256], H, u64::MAX - 1), // N
        lo(b"x", b"", &vec![b'n'; 256], H, u64::MAX - 1),
        lo(&a(1700), b"", b"ns", H, u64::MAX - 1),
        lo(b"short", b"", b"", H, u64::MAX - 1),
        lo(&a(1700), b"", b"", H ^ 1, u64::MAX - 1),
    ];
    v.sort();
    v.dedup();
    v
}

fn longname_gen(g: &mut Gen) {
    if LONGNAME_GEN.get() {
        g.objs.extend(long_universe());
    }
}

fn list_all(
    st: &mut St,
    c: &CollT,
    begin: &Ghobject,
    end: Option<&Ghobject>,
    page: usize,
) -> Vec<Ghobject> {
    let (mut got, mut cur) = (Vec::new(), begin.clone());
    loop {
        let (v, next) = st.list(c, &cur, end, page).unwrap();
        assert!(v.len() <= page);
        got.extend(v);
        match next {
            Some(n) => cur = n,
            None => return got,
        }
    }
}

/// Lists in hobject order (all page sizes, sub ranges), stats and data, across both indexes.
fn long_verify(r: &mut Rig, c: &CollT, want: &[Ghobject]) {
    for page in [1usize, 2, 5, 1000] {
        assert_eq!(
            list_all(&mut r.st, c, &Ghobject::MIN(), None, page),
            want,
            "page {page}"
        );
    }
    for i in 0..want.len() {
        for j in i..=want.len() {
            let end = want.get(j);
            assert_eq!(
                list_all(&mut r.st, c, &want[i], end, 3),
                want[i..j],
                "range {i}..{j}"
            );
        }
    }
    for (i, o) in want.iter().enumerate() {
        let d = r.st.read(c, o, 0, 1 << 20).unwrap();
        assert_eq!(d.len(), 50 + o.hobj.oid.len() % 97, "data of #{i}");
        assert!(d.iter().all(|b| *b == (o.hobj.oid.len() as u8)));
    }
}

fn long_write(r: &mut Rig, c: CollT, o: &Ghobject) {
    let d = vec![o.hobj.oid.len() as u8; 50 + o.hobj.oid.len() % 97];
    let mut t = OTxn::new();
    t.write(c, o, 0, &d);
    t.omap_set(c, o, b"k", b"v");
    commit(&mut r.st, &t);
}

#[test]
fn long_names_list_lookup_rename_remove() {
    let mut r = rig(64, 1);
    assert_ne!(r.st.features() & store::layout::FEAT_LONG_NAME, 0);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let u = long_universe();
    for o in &u {
        long_write(&mut r, c, o);
    }
    let nl = r.st.shards[0]
        .sh
        .dump_blocking(&mut r.st.clk)
        .unwrap()
        .iter()
        .filter(|(k, _)| k[0] == T_LNAME)
        .count();
    assert!(nl >= 10 && nl < u.len(), "{nl} of {} names in L", u.len());
    long_verify(&mut r, &c, &u);
    assert_eq!(check_no_leaks(&mut r), u.len());
    r.clean_remount();
    long_verify(&mut r, &c, &u);
    // a collection holding only long names is not empty
    let c2 = pgc(1, 4);
    let mut t = OTxn::new();
    t.mkcoll(c2);
    commit(&mut r.st, &t);
    let only = lo(&vec![b'q'; 2000], b"", b"", 9, u64::MAX - 1);
    long_write(&mut r, c2, &only);
    let mut t = OTxn::new();
    t.push(TOp::RmColl { cid: c2 });
    assert_eq!(r.st.commit(&t), Err(ObjError::NotEmpty));
    // rename across the indexes and collections: long -> short (N), short -> long (L), long -> long
    let mut t = OTxn::new();
    t.push(TOp::MoveRename {
        cid: c2,
        oid: only.clone(),
        dcid: c2,
        doid: g(b"now-short", 9),
    });
    commit(&mut r.st, &t);
    assert_eq!(
        list_all(&mut r.st, &c2, &Ghobject::MIN(), None, 4),
        [g(b"now-short", 9)]
    );
    let long2 = lo(&vec![b'r'; 2048], b"", b"", 9, u64::MAX - 1);
    let mut t = OTxn::new();
    t.push(TOp::MoveRename {
        cid: c2,
        oid: g(b"now-short", 9),
        dcid: c2,
        doid: long2.clone(),
    });
    commit(&mut r.st, &t);
    assert_eq!(
        list_all(&mut r.st, &c2, &Ghobject::MIN(), None, 4),
        std::slice::from_ref(&long2)
    );
    let mut t = OTxn::new();
    t.push(TOp::MoveRename {
        cid: c2,
        oid: long2.clone(),
        dcid: c,
        doid: lo(&vec![b's'; 1900], b"", b"", 9, u64::MAX - 1),
    });
    commit(&mut r.st, &t);
    let mut t = OTxn::new();
    t.push(TOp::RmColl { cid: c2 });
    commit(&mut r.st, &t);
    let mut want = u.clone();
    want.push(lo(&vec![b's'; 1900], b"", b"", 9, u64::MAX - 1));
    want.sort();
    assert_eq!(list_all(&mut r.st, &c, &Ghobject::MIN(), None, 3), want);
    // remove every other object; recreate one; listing and leaks stay exact
    let mut keep = Vec::new();
    let mut t = OTxn::new();
    for (i, o) in want.iter().enumerate() {
        if i % 2 == 0 {
            t.remove(c, o);
        } else {
            keep.push(o.clone());
        }
    }
    commit(&mut r.st, &t);
    assert_eq!(list_all(&mut r.st, &c, &Ghobject::MIN(), None, 2), keep);
    assert!(r.st.stat(&c, &want[0]).unwrap().is_none());
    assert_eq!(check_no_leaks(&mut r), keep.len());
    r.clean_remount();
    assert_eq!(list_all(&mut r.st, &c, &Ghobject::MIN(), None, 2), keep);
    let mut t = OTxn::new();
    for o in &keep {
        t.remove(c, o);
    }
    commit(&mut r.st, &t);
    assert!(list_all(&mut r.st, &c, &Ghobject::MIN(), None, 2).is_empty());
    let mut t = OTxn::new();
    t.push(TOp::RmColl { cid: c });
    commit(&mut r.st, &t);
    check_no_leaks(&mut r);
}

#[test]
fn long_names_limits_and_error_codes() {
    let mut r = rig(32, 1);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let a = |n: usize| vec![b'a'; n];
    // classic limits: oid 2048 and locator 2048 and namespace 256 each pass alone
    for o in [
        lo(&a(2048), b"", b"", 1, u64::MAX - 1),
        lo(&a(2047), b"", b"", 1, u64::MAX - 1),
        lo(b"a", &a(2048), b"", 1, u64::MAX - 1),
        lo(b"a", b"", &a(256), 1, u64::MAX - 1),
        lo(&a(2048), b"", &a(256), 1, u64::MAX - 1),
        // NUL bytes double in the key (escaping): 1600 of them still fit, 2048 do not (below)
        lo(&[0u8; 1600], b"", b"", 1, u64::MAX - 1),
    ] {
        assert!(r.st.name_fits(&o), "{}", o.hobj.oid.len());
        long_write(&mut r, c, &o);
        assert!(r.st.stat(&c, &o).unwrap().is_some());
    }
    // locator and oid both long: the class form saves nothing, over the tree key limit (documented deviation)
    let o = lo(&a(2048), &a(2047), b"", 1, u64::MAX - 1);
    assert!(!r.st.name_fits(&o));
    let mut t = OTxn::new();
    t.write(c, &o, 0, b"x");
    assert_eq!(r.st.commit(&t), Err(ObjError::NameTooLong));
    assert_eq!(r.st.stat(&c, &o).err(), Some(ObjError::NameTooLong));
    assert!(!r.st.name_fits(&lo(&[0u8; 2048], b"", b"", 1, u64::MAX - 1)));
    // nothing of the failed txn exists
    assert_eq!(
        list_all(&mut r.st, &c, &Ghobject::MIN(), None, 100).len(),
        6
    );
    check_no_leaks(&mut r);
}

#[test]
fn model_with_long_names() {
    LONGNAME_GEN.set(true);
    for seed in [31, 32] {
        run_model(seed, 1, 250, 80);
    }
    LONGNAME_GEN.set(false);
}

#[test]
fn crash_matrix_with_long_names() {
    LONGNAME_GEN.set(true);
    let (n, c) = crash_matrix(
        20,
        41,
        &[
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ],
        500,
        2,
    );
    assert!(n > 100 && c * 2 > n, "scenarios {n}, crashed {c}");
    LONGNAME_GEN.set(false);
}

#[test]
#[ignore = "soak"]
fn crash_matrix_with_long_names_soak() {
    LONGNAME_GEN.set(true);
    for gs in 50..60 {
        crash_matrix(
            16,
            gs,
            &[
                CrashPolicy::MIXED,
                CrashPolicy::DROP_ALL,
                CrashPolicy::PERSIST_ALL,
            ],
            1000,
            1,
        );
    }
    LONGNAME_GEN.set(false);
}

/// The "`L` index empty" cache must not learn from a txn that never lands: a dry run (`check_txn`) or a failed txn that
/// removes the shard's last long names and then probes (`RmColl`) saw the overlay's deletes; caching that answer hid
/// the still existing long names from `list` and let `RmColl` drop a collection that holds them (orphan onodes).
#[test]
fn long_names_empty_cache_ignores_unapplied_deletes() {
    let mut r = rig(32, 1);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let x = lo(&vec![b'x'; 2000], b"", b"", 7, u64::MAX - 1);
    long_write(&mut r, c, &x);
    assert_eq!(
        list_all(&mut r.st, &c, &Ghobject::MIN(), None, 4),
        std::slice::from_ref(&x)
    );
    // dry run of "remove the only long name + drop the collection": fits, nothing applied
    let mut t = OTxn::new();
    t.remove(c, &x);
    t.push(TOp::RmColl { cid: c });
    assert_eq!(r.st.check_txn(&t), Ok(()));
    assert_eq!(
        list_all(&mut r.st, &c, &Ghobject::MIN(), None, 4),
        std::slice::from_ref(&x)
    );
    // the same prefix in a txn that fails at a later op
    let mut t = OTxn::new();
    t.remove(c, &x);
    t.push(TOp::RmColl { cid: c });
    t.touch(pgc(1, 9), &g(b"nocoll", 1));
    assert!(r.st.commit(&t).is_err());
    assert_eq!(
        list_all(&mut r.st, &c, &Ghobject::MIN(), None, 4),
        std::slice::from_ref(&x)
    );
    let mut t = OTxn::new();
    t.push(TOp::RmColl { cid: c });
    assert_eq!(r.st.commit(&t), Err(ObjError::NotEmpty));
    // the real thing still works
    let mut t = OTxn::new();
    t.remove(c, &x);
    t.push(TOp::RmColl { cid: c });
    commit(&mut r.st, &t);
    check_no_leaks(&mut r);
}

#[test]
fn getattr_pair_answers_both_attrs_of_one_lookup() {
    // the op executor loads `_` and `snapset` in one call: inline values, an absent attr, a fragmented value and a missing
    // object answer exactly like two `getattr` calls
    let mut r = rig(32, 1);
    let c = c1();
    let o = g(b"pair", 5);
    let big: Vec<u8> = (0..70_000u32).map(|i| (i * 13 % 256) as u8).collect();
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.setattr(c, &o, b"_", b"oi");
    t.setattr(c, &o, b"snapset", b"ss");
    t.setattr(c, &o, b"frag", &big);
    commit(&mut r.st, &t);
    let both = |r: &mut Rig, a: &[u8], b: &[u8]| r.st.getattr_pair(&c, &o, a, b);
    assert_eq!(
        both(&mut r, b"_", b"snapset").unwrap(),
        (Some(b"oi".to_vec()), Some(b"ss".to_vec()))
    );
    assert_eq!(
        both(&mut r, b"_", b"missing").unwrap(),
        (Some(b"oi".to_vec()), None)
    );
    assert_eq!(
        both(&mut r, b"frag", b"snapset").unwrap(),
        (Some(big.clone()), Some(b"ss".to_vec()))
    );
    r.clean_remount();
    assert_eq!(
        both(&mut r, b"snapset", b"frag").unwrap(),
        (Some(b"ss".to_vec()), Some(big))
    );
    let nobody = g(b"nobody", 5);
    assert!(matches!(
        r.st.getattr_pair(&c, &nobody, b"_", b"snapset"),
        Err(ObjError::NoEnt)
    ));
}

#[test]
fn warm_omap_loads_the_leaf_of_a_log_key_before_the_put() {
    // adr 0021 am. 30: the PG layer probes the pgmeta log keys a write appends; once `warm_omap` says ready the put of that
    // key loads no tree page (a cold log head leaf would otherwise spin the core on the device read)
    let cfg = StoreCfg {
        shard: ShardCfg {
            cache_pages: 96,
            ..StoreCfg::default().shard
        },
    };
    let (mut r, _) = rig_ns(64, 1, 1024, 92, cfg, 4096);
    let c = c1();
    let pm = Ghobject::pgmeta(1, 0, ShardId::NO_SHARD);
    let key = |n: u32| format!("log.{n:010}").into_bytes();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    for i in 0..3000u32 {
        let mut t = OTxn::new();
        let ki = key(i);
        t.omap_set(c, &pm, &ki, &[7u8; 200]);
        commit(&mut r.st, &t);
    }
    r.clean_remount(); // cold cache
    let k = key(3000);
    let keys: [&[u8]; 1] = [&k];
    let mut spins = 0;
    let mut cold = 0;
    while !r.st.warm_omap(&c, &pm, &keys).unwrap() {
        cold += 1;
        spins += 1;
        assert!(spins < 100_000, "page load never completed");
        let mut acked = vec![];
        r.st.poll(&mut acked).unwrap();
        if !r.st.take_wake() {
            r.st.idle();
        }
    }
    assert!(cold > 0, "cache was not cold");
    let before = r.st.shards[0].sh.tree_stats().loads;
    let mut t = OTxn::new();
    t.omap_set(c, &pm, &k, &[9u8; 200]);
    commit(&mut r.st, &t);
    assert_eq!(
        r.st.shards[0].sh.tree_stats().loads - before,
        0,
        "the put blocked on a page that warm_omap reported ready"
    );
    // an absent object is ready (the real op reports it)
    let nobody = Ghobject::pgmeta(1, 5, ShardId::NO_SHARD);
    assert!(r.st.warm_omap(&c, &nobody, &keys).unwrap());
}

// ------------------------------------------------------------------------------- runtime deallocate (adr 0642)

/// Deallocates between sliced checkpoints (adr 0642, adr 0021 am. 80) on the store's own poll loop: 2 MiB objects
/// overwritten in turn (each version on new blocks: the old one's whole windows are released by the next checkpoint), a
/// checkpoint requested after every second write, a 20 ms device idle gap after each write polled as a core polls the
/// store ([`core_gap`]); the default slice and one unit per poll (every start and freeze over many polls). The
/// checkpoint's sliced start, freeze and end keep the shard active until the root is durable; then the shard is quiet,
/// the device idle table sees one quiet gap and a deallocate goes out: in every gap after a checkpoint that released
/// whole windows.
#[test]
fn deallocates_go_out_in_idle_gaps_between_sliced_checkpoints() {
    for slice in [StoreCfg::default().shard.ckpt_slice, 1] {
        let mut cfg = StoreCfg::default();
        cfg.shard.ckpt_slice = slice;
        let (mut r, _) = rig_with(64, 1, 1024, 1, cfg);
        settle_trims(&mut r);
        let c = c1();
        let mut t = OTxn::new();
        t.mkcoll(c);
        r.st.commit(&t).unwrap();
        let objs: Vec<Ghobject> = (0..4u32)
            .map(|i| g(format!("trim-{i}").as_bytes(), i))
            .collect();
        let data = cdata(2 << 20, 5);
        let (mut gaps, mut sent) = (0, 0);
        for k in 0..6 * objs.len() {
            let mut t = OTxn::new();
            t.write(c, &objs[k % objs.len()], 0, &data);
            r.st.commit(&t).unwrap();
            let ckpt = k % 2 == 1;
            if ckpt {
                r.st.shards[0].sh.request_checkpoint();
            }
            let c0 = trim_cmds(&r);
            core_gap(&mut r, 20_000_000);
            // from the second round on every write frees the previous version
            if ckpt && k >= objs.len() {
                gaps += 1;
                sent += u64::from(trim_cmds(&r) > c0);
            }
        }
        let st = &r.st.shards[0].sh.stats;
        eprintln!(
            "slice {slice}: {gaps} gaps after a checkpoint that released windows, {sent} sent a deallocate; {} \
             checkpoints, {} start slices, {} freeze slices, {} deallocates",
            st.checkpoints,
            st.ckpt_start_slices,
            st.ckpt_slices,
            trim_cmds(&r)
        );
        assert!(
            gaps > 0 && sent == gaps,
            "slice {slice}: {sent} of {gaps} gaps sent a deallocate"
        );
        settle_trims(&mut r);
        for (k, o) in objs.iter().enumerate() {
            assert_eq!(
                r.st.read(&c, o, 0, data.len() as u64).unwrap(),
                data,
                "slice {slice}: object {k}"
            );
        }
    }
}

// ------------------------------------------------------------------------------- compression (adr 0059 am. 1)

use store::compress::{Alg, CompSpec};

fn cspec(alg: Alg) -> CompSpec {
    CompSpec {
        alg,
        ratio_permille: 875,
        min_bytes: 8192,
        chunk_blks: 16,
    }
}

fn compressed_window_fixture(chunks: usize) -> (Rig, CollT, Ghobject, Vec<u8>) {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"compressed-window", 7));
    let data = cdata(chunks * (64 << 10), 99);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.comp = Some(cspec(Alg::Lz4));
    t.write(c, &o, 0, &data);
    r.st.commit(&t).unwrap();
    r.st.checkpoint().unwrap();
    // the read windows count the device's in-flight ops: no deallocate among them
    settle_trims(&mut r);
    r.st.stat(&c, &o).unwrap();
    assert_eq!(r.st.shards[0].stats.comp_ok, chunks as u64);
    (r, c, o, data)
}

#[test]
fn compressed_cold_read_submits_a_window_without_waiting() {
    let (mut r, c, o, data) = compressed_window_fixture(16);
    r.st.set_nonblock_reads(true);
    r.st.read_session(Some((77, 1)), true);
    let before = r.st.clk.t;
    let result = r.st.read(&c, &o, 0, data.len() as u64);
    assert!(matches!(result, Err(ObjError::WouldBlock)));
    assert_eq!(r.st.clk.t, before, "no device wait in an asynchronous read");
    assert!(
        r.disk.inflight() >= 4,
        "only {} media reads submitted",
        r.disk.inflight()
    );
    r.st.read_session(None, false);
}

#[test]
#[ignore = "local simulated compressed read window benchmark"]
fn perf_compressed_cold_read_window() {
    for chunks in [4, 16] {
        let (mut r, c, o, data) = compressed_window_fixture(chunks);
        r.st.set_nonblock_reads(true);
        let before = r.st.clk.t;
        let before_dec = r.st.shards[0].stats.decomp;
        let wall = std::time::Instant::now();
        let deadline = before + 30_000_000_000;
        let mut rounds = 0;
        loop {
            rounds += 1;
            assert!(
                rounds < 100_000 && r.st.clk.t < deadline && wall.elapsed().as_secs() < 10,
                "WARNING TIMEOUT cold read window exceeded 10s wall (rounds {rounds} of 100000, chunks {chunks}, sim-time bound 30s)"
            );
            r.st.read_session(Some((77, 1)), true);
            let result = r.st.read(&c, &o, 0, data.len() as u64);
            let blocked = matches!(result, Err(ObjError::WouldBlock));
            r.st.read_session(None, blocked);
            match result {
                Ok(got) => {
                    assert_eq!(got, data);
                    break;
                }
                Err(ObjError::WouldBlock) => {}
                Err(e) => panic!("{e:?}"),
            }
            r.st.poll(&mut Vec::new()).unwrap();
            r.st.idle();
        }
        println!(
            "compressed bytes={} chunks={chunks} virtual_ns={} wall_ns={} decompressions={} retries={rounds}",
            data.len(),
            r.st.clk.t - before,
            wall.elapsed().as_nanos(),
            r.st.shards[0].stats.decomp - before_dec
        );
        assert_eq!(r.st.shards[0].stats.decomp - before_dec, chunks as u64);
    }
}

/// A read of compressed data carries the msgr2 data crc without a pass over the returned bytes (whole chunks: their
/// logical crc; windows, cuts: only the cut part is hashed; plain pieces and holes: block crcs / zeros).
#[test]
fn compressed_read_crc_matches_the_returned_bytes() {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"ccrc", 3));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let mut m = vec![0u8; 8 * (64 << 10)];
    let blk = |seed: u64| {
        let mut b = rnd(4096, seed);
        b[2048..].fill(0);
        b
    };
    // chunks 0-1 and 4-6 compressed (half random blocks), chunks 2-3 a hole, chunk 7 a raw 4 KiB piece
    for (i, off) in (0..2).chain(4..7).map(|k| k * (64usize << 10)).enumerate() {
        for b in 0..16 {
            m[off + b * 4096..off + (b + 1) * 4096]
                .copy_from_slice(&blk(100 + (i * 16 + b) as u64));
        }
        let mut t = OTxn::new();
        t.comp = Some(cspec(Alg::Lz4));
        t.write(c, &o, off as u64, &m[off..off + (64 << 10)]);
        commit(&mut r.st, &t);
    }
    let raw = rnd(4096, 7);
    m[7 * (64 << 10)..7 * (64 << 10) + 4096].copy_from_slice(&raw);
    let mut t = OTxn::new();
    t.write(c, &o, 7 * (64 << 10) as u64, &raw);
    commit(&mut r.st, &t);
    // a window cut inside chunk 4: overwrite block 3 and block 9 (4 KiB each, stored raw beside the chunk)
    for b in [3usize, 9] {
        let d = rnd(4096, 900 + b as u64);
        m[4 * (64 << 10) + b * 4096..4 * (64 << 10) + (b + 1) * 4096].copy_from_slice(&d);
        let mut t = OTxn::new();
        t.comp = Some(cspec(Alg::Lz4));
        t.write(c, &o, (4 * (64 << 10) + b * 4096) as u64, &d);
        commit(&mut r.st, &t);
    }
    m.truncate(7 * (64 << 10) + 4096); // the object ends after the raw piece
    r.clean_remount();
    let want = |d: &[u8]| crc::crc32c(!0, d);
    let ranges: [(u64, u64); 9] = [
        (0, 8 * 65536),
        (0, 65536),
        (65536, 65536),
        (0, 4 * 65536),
        (4 * 65536, 3 * 65536),
        (4 * 65536 + 8192, 40960),
        (3 * 65536 + 4096, 3 * 65536),
        (4096, 8192),
        (7 * 65536, 65536),
    ];
    for pass in 0..2 {
        // pass 1 reads again with the decoded chunks cached
        for &(off, len) in &ranges {
            let (d, crc) = r.st.read_crc(&c, &o, off, len).unwrap();
            let end = ((off + len) as usize).min(m.len());
            assert!(d == m[off as usize..end], "bytes {off}+{len} pass {pass}");
            assert_eq!(crc, Some(want(&d)), "crc {off}+{len} pass {pass}");
        }
    }
}

/// A shared read (`read_shared`, what the OSD replies with) of compressed chunks hands out the decoded chunks by reference:
/// one piece per chunk, holes as zero pieces, each piece's crc right, head / tail cuts correct; the same bytes with the
/// decoded chunks cached; a mixed object (raw blocks between windows) still reads right.
#[test]
fn compressed_shared_read_hands_out_decoded_chunks() {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"cshared", 3));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let chunk = 64usize << 10;
    let mut m = vec![0u8; 6 * chunk];
    for k in [0usize, 1, 2, 4, 5] {
        for b in 0..16 {
            let mut d = rnd(4096, 50 + (k * 16 + b) as u64);
            d[2048..].fill(0);
            m[k * chunk + b * 4096..k * chunk + (b + 1) * 4096].copy_from_slice(&d);
        }
        let mut t = OTxn::new();
        t.comp = Some(cspec(Alg::Lz4));
        t.write(c, &o, (k * chunk) as u64, &m[k * chunk..(k + 1) * chunk]);
        commit(&mut r.st, &t);
    }
    r.clean_remount();
    let check = |r: &mut Rig, m: &[u8], off: usize, len: usize| {
        let v = r.st.read_shared(&c, &o, off as u64, len as u64).unwrap();
        let got: Vec<u8> = v.iter().flat_map(|p| p.0.iter().copied()).collect();
        assert!(got == m[off..off + len], "bytes {off}+{len}");
        for (b, crc) in &v {
            assert_eq!(*crc, Some(crc::crc32c(!0, b)), "piece crc {off}+{len}");
        }
        v
    };
    // whole object: chunks 0-2 as three pieces, the hole of chunk 3 as one zero piece, chunks 4-5 as two
    let v = check(&mut r, &m, 0, 6 * chunk);
    assert_eq!(v.len(), 6);
    assert!(v.iter().all(|p| p.0.len() == chunk));
    assert!(v[3].0.iter().all(|&b| b == 0));
    // cached chunks, cuts, a read inside one chunk, a read across the hole
    for (off, len) in [
        (0, 6 * chunk),
        (4096, 5 * chunk),
        (chunk + 8192, 3 * chunk),
        (2 * chunk + 4096, 2 * chunk + 8192),
        (4 * chunk, chunk),
        (5 * chunk + 4096, chunk - 4096),
    ] {
        check(&mut r, &m, off, len);
    }
    // the chunk of the last read is not decoded again by a read of the whole chunk
    let before = r.st.shards[0].stats.decomp;
    check(&mut r, &m, 5 * chunk, chunk);
    assert_eq!(
        r.st.shards[0].stats.decomp, before,
        "decoded chunk served from the cache"
    );
    // a raw 4 KiB overwrite inside chunk 1 makes the object mixed (plain part between windows): falls back to one copy
    let d = rnd(4096, 777);
    m[chunk + 4 * 4096..chunk + 5 * 4096].copy_from_slice(&d);
    let mut t = OTxn::new();
    t.write(c, &o, (chunk + 4 * 4096) as u64, &d);
    commit(&mut r.st, &t);
    r.clean_remount();
    check(&mut r, &m, 0, 3 * chunk);
    check(&mut r, &m, chunk, chunk);
    assert_clean(&mut r);
}

#[test]
fn compressed_cold_read_retains_decoded_prefix() {
    let (mut r, c, o, data) = compressed_window_fixture(16);
    r.st.set_nonblock_reads(true);
    let start = r.st.shards[0].stats.decomp;
    let before = r.st.clk.t;
    let mut overlapped = false;
    for _ in 0..1000 {
        r.st.read_session(Some((78, 1)), true);
        let result = r.st.read(&c, &o, 0, data.len() as u64);
        let blocked = matches!(result, Err(ObjError::WouldBlock));
        assert!(
            r.disk.inflight() <= 4,
            "compressed window exceeded four physical runs"
        );
        overlapped |= r.st.shards[0].stats.decomp > start && r.disk.inflight() > 0;
        r.st.read_session(None, blocked);
        match result {
            Ok(got) => {
                assert_eq!(got, data);
                assert_eq!(r.st.shards[0].stats.decomp - start, 16);
                assert!(
                    overlapped,
                    "decompression waited for the entire media window"
                );
                return;
            }
            Err(ObjError::WouldBlock) => {}
            Err(e) => panic!("{e:?}"),
        }
        assert!(r.st.clk.t - before < 30_000_000_000);
        r.st.poll(&mut Vec::new()).unwrap();
        r.st.idle();
    }
    panic!("compressed read cycled its completed prefix");
}

#[test]
fn compressed_window_blocking_and_sessionless_callers() {
    for nonblock in [false, true] {
        let (mut r, c, o, data) = compressed_window_fixture(16);
        r.st.set_nonblock_reads(nonblock);
        let wall = std::time::Instant::now();
        let start = r.st.shards[0].stats.decomp;
        let mut done = false;
        for _ in 0..1000 {
            assert!(wall.elapsed().as_secs() < 10);
            match r.st.read(&c, &o, 0, data.len() as u64) {
                Ok(got) => {
                    assert_eq!(got, data);
                    done = true;
                    break;
                }
                Err(ObjError::WouldBlock) if nonblock => {}
                Err(e) => panic!("{e:?}"),
            }
            r.st.poll(&mut Vec::new()).unwrap();
            r.st.idle();
        }
        assert!(done);
        assert_eq!(r.st.shards[0].stats.decomp - start, 16);
        r.st.set_nonblock_reads(false);
        let mut t = OTxn::new();
        t.remove(c, &o);
        r.st.commit(&t).unwrap();
        r.st.checkpoint().unwrap();
        check_no_leaks(&mut r);
    }
}

/// A blocking caller reads a compressed object while four other sessions hold every rolling-read slot of the shard.
/// It must end on its own device completions (never wait for a slot only the blocked event loop could free, which a
/// 30 s timer used to turn into EIO).
#[test]
fn compressed_blocking_read_needs_no_rolling_slot() {
    let (mut r, c, o, data) = compressed_window_fixture(16);
    let mut t = OTxn::new();
    t.comp = Some(cspec(Alg::Lz4));
    let others: Vec<Ghobject> = (0..4)
        .map(|i| g(format!("slot-holder-{i}").as_bytes(), 7))
        .collect();
    let bufs: Vec<Vec<u8>> = (0..4).map(|i| cdata(4 * (64 << 10), 200 + i)).collect();
    for (oo, b) in others.iter().zip(&bufs) {
        t.write(c, oo, 0, b);
    }
    r.st.commit(&t).unwrap();
    r.st.checkpoint().unwrap();
    r.st.set_nonblock_reads(true);
    for (i, oo) in others.iter().enumerate() {
        r.st.read_session(Some((900 + i as u64, 1)), true);
        let res = r.st.read(&c, oo, 0, 4 * (64 << 10));
        assert!(matches!(res, Err(ObjError::WouldBlock)), "{res:?}");
        r.st.read_session(None, true);
    }
    r.st.set_nonblock_reads(false);
    let before = r.st.clk.t;
    let got = r.st.read(&c, &o, 0, data.len() as u64).unwrap();
    assert_eq!(got, data);
    assert!(
        r.st.clk.t - before < 1_000_000_000,
        "blocking read waited on a timer"
    );
}

/// One run of an executor request: re-reads its first object (a retained, completed rolling read), then reads the object
/// the parked FIFO head writes (the visibility fence); keeps its reads while it waits, like `opexec` does.
fn fenced_request(
    r: &mut Rig,
    session: u64,
    first: &Ghobject,
    fenced: &Ghobject,
) -> Option<Vec<u8>> {
    let c = c1();
    r.st.read_session(Some((session, 1)), true);
    let res =
        r.st.read(&c, first, 0, 64 << 10)
            .and_then(|_| r.st.read(&c, fenced, 0, 4096));
    let blocked = matches!(res, Err(ObjError::WouldBlock));
    r.st.read_session(None, blocked);
    match res {
        Ok(d) => Some(d),
        Err(ObjError::WouldBlock) => None,
        Err(e) => panic!("{e:?}"),
    }
}

/// Four executor requests hold every rolling-read session of the shard with completed reads while they wait at the
/// visibility fence of the parked FIFO head. The head's read-modify-write read is admitted anyway: the requests wait
/// for the head, so refusing the head a session slot livelocked the shard (lab case 36: the head was refused 375k
/// times in 300 s; replica writes held behind it timed out).
#[test]
fn fifo_head_read_is_admitted_while_fenced_requests_hold_every_slot() {
    let mut r = rig(64, 1);
    let c = c1();
    let o = g(b"fenced", 1);
    let holders: Vec<Ghobject> = (0..4)
        .map(|i| g(format!("slot-holder-{i}").as_bytes(), 7))
        .collect();
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.write(c, &o, 0, &[0x11; 64 << 10]);
    for h in &holders {
        t.write(c, h, 0, &[0x22; 64 << 10]);
    }
    r.st.commit(&t).unwrap();
    r.clean_remount(); // cold data: the head's sub-block overwrite reads its block
    r.st.set_nonblock_reads(true);
    // the requests' first reads complete and stay retained: every session slot is taken
    for _ in 0..10_000 {
        let mut all = true;
        for (i, h) in holders.iter().enumerate() {
            r.st.read_session(Some((900 + i as u64, 1)), true);
            let res = r.st.read(&c, h, 0, 64 << 10);
            all &= res.is_ok();
            r.st.read_session(None, true);
        }
        if all {
            break;
        }
        r.st.poll(&mut Vec::new()).unwrap();
        r.st.idle();
    }
    assert_eq!(
        r.st.shards[0].rolling_usage().1,
        0,
        "holder reads still in flight"
    );
    let mut w = OTxn::new();
    w.write(c, &o, 100, &[0x33; 100]);
    assert_eq!(
        r.st.queue(&w, 5).unwrap(),
        store::obj::Queued::Pending(5),
        "the overwrite waits for its read"
    );
    let mut acked = Vec::new();
    let mut got = vec![None; holders.len()];
    for _ in 0..10_000 {
        for (i, h) in holders.iter().enumerate() {
            if got[i].is_none() {
                got[i] = fenced_request(&mut r, 900 + i as u64, h, &o);
            }
        }
        r.st.poll(&mut acked).unwrap();
        let mut errors = Vec::new();
        r.st.take_queue_errors(&mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        if acked.contains(&5) && got.iter().all(Option::is_some) {
            break;
        }
        r.st.clk.t += 1_000_000;
        r.st.idle();
    }
    assert_eq!(acked, [5], "FIFO head never prepared: {}", r.st.diag());
    let mut want = vec![0x11; 4096];
    want[100..200].fill(0x33);
    for d in got {
        assert_eq!(d.as_deref(), Some(&want[..]));
    }
}

#[test]
fn compressed_window_retains_a_prefetched_prefix_without_rereading_it() {
    for warmed in [8, 16] {
        let (mut r, c, o, data) = compressed_window_fixture(16);
        warm_all(&mut r, &c, &o, warmed * (64 << 10));
        let ios = r.st.shards[0].stats.read_ios;
        let decompressions = r.st.shards[0].stats.decomp;
        r.st.set_nonblock_reads(true);
        let mut done = false;
        for _ in 0..1000 {
            r.st.read_session(Some((79, 1)), true);
            let result = r.st.read(&c, &o, 0, data.len() as u64);
            let blocked = matches!(result, Err(ObjError::WouldBlock));
            r.st.read_session(None, blocked);
            match result {
                Ok(got) => {
                    assert_eq!(got, data);
                    done = true;
                    break;
                }
                Err(ObjError::WouldBlock) => {}
                Err(e) => panic!("{e:?}"),
            }
            r.st.poll(&mut Vec::new()).unwrap();
            r.st.idle();
        }
        assert!(done);
        assert_eq!(r.st.shards[0].stats.read_ios - ios, 16 - warmed);
        assert_eq!(r.st.shards[0].stats.decomp - decompressions, 16);
    }
}

/// A prefetched compressed chunk is decoded in place and cached decoded (decompressed-chunk cache); the data cache does
/// not keep its physical bytes as well (one cached form per chunk, adr 0043 "Data cache").
#[test]
fn prefetched_compressed_chunks_are_not_data_cached_twice() {
    let (mut r, c, o, data) = compressed_window_fixture(16);
    warm_all(&mut r, &c, &o, data.len() as u64);
    assert_eq!(r.st.read(&c, &o, 0, data.len() as u64).unwrap(), data);
    assert_eq!(r.st.shards[0].data_cache_usage(), (0, 0));
}

#[test]
fn compressed_async_media_window_bypasses_client_cached_bytes() {
    let (mut r, c, o, data) = compressed_window_fixture(16);
    r.st.read(&c, &o, 0, 4096).unwrap();
    warm_all(&mut r, &c, &o, data.len() as u64);
    let kv = r.st.shards[0].sh.dump_blocking(&mut r.st.clk).unwrap();
    let (_, v) = kv
        .iter()
        .find(|(k, _)| k[0] == T_EXT && k[10..14] == 0u32.to_be_bytes())
        .unwrap();
    let ext = store::obj::onode::Ext::decode(v).unwrap();
    r.disk.corrupt(ext.pba, 100, 0x40);
    let wall = std::time::Instant::now();
    let mut failed = false;
    for _ in 0..1000 {
        assert!(wall.elapsed().as_secs() < 10);
        match r.st.read_media_async(&c, &o, 0, data.len() as u64, 123) {
            Err(ObjError::Eio(_)) => {
                failed = true;
                break;
            }
            Err(ObjError::WouldBlock) => {}
            Ok(_) => panic!("media verification returned client cached bytes"),
            Err(e) => panic!("{e:?}"),
        }
        r.st.poll(&mut Vec::new()).unwrap();
        r.st.idle();
    }
    assert!(failed);
    r.st.cancel_media_read(&c, 123).unwrap();
}

/// Compressible bytes: runs of one value.
fn cdata(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng::new(seed);
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        let run = r.range(8, 300) as usize;
        let b = r.below(256) as u8;
        v.resize((v.len() + run).min(n), b);
    }
    v
}

fn rnd(n: usize, seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; n];
    Rng::new(seed).fill(&mut v);
    v
}

fn comp_stats(st: &mut St) -> (u64, u64, u64, u64) {
    let cs = st.coll_stats(&c1()).unwrap().unwrap();
    let ok = st.shards.iter().map(|s| s.stats.comp_ok).sum();
    let rej = st.shards.iter().map(|s| s.stats.comp_rejected).sum();
    let _ = rej;
    (cs.comp, cs.comp_orig, ok, rej)
}

fn assert_clean(r: &mut Rig) {
    let rep = r.st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}

#[test]
fn compression_roundtrip_per_alg_and_accounting() {
    for alg in [Alg::Lz4, Alg::Zstd, Alg::Snappy, Alg::Zlib] {
        let mut r = rig(64, 1);
        let (c, o) = (c1(), g(b"cobj", 0x77));
        let mut t = OTxn::new();
        t.mkcoll(c);
        commit(&mut r.st, &t);
        let data = cdata(256 << 10, 5);
        let mut t = OTxn::new();
        t.comp = Some(cspec(alg));
        t.write(c, &o, 0, &data);
        commit(&mut r.st, &t);
        let (phys, orig, ok, _) = comp_stats(&mut r.st);
        assert_eq!(ok, 4, "{alg:?}");
        assert_eq!(orig, 256 << 10);
        assert!(phys > 0 && phys < orig / 2, "{alg:?} phys {phys}");
        assert_eq!(r.st.read(&c, &o, 0, 256 << 10).unwrap(), data);
        assert_eq!(r.st.read(&c, &o, 5000, 70_000).unwrap(), data[5000..75_000]);
        assert_eq!(
            r.st.read(&c, &o, 65_536 + 4096, 4096).unwrap(),
            data[69_632..73_728]
        );
        let cc = r.st.comp_counters();
        assert_eq!((cc.ok, cc.rejected, cc.sampled_out), (4, 0, 0), "{alg:?}");
        assert!(
            cc.comp_ns > 0 && cc.decomp > 0 && cc.decomp_ns > 0,
            "{alg:?} {cc:?}"
        );
        assert_clean(&mut r);
        r.clean_remount();
        assert_eq!(r.st.read(&c, &o, 0, 256 << 10).unwrap(), data);
        let (p2, o2, _, _) = comp_stats(&mut r.st);
        assert_eq!((p2, o2), (phys, orig), "counters survive remount");
        let mut t = OTxn::new();
        t.remove(c, &o);
        commit(&mut r.st, &t);
        assert_eq!(comp_stats(&mut r.st).0, 0);
        assert_eq!(comp_stats(&mut r.st).1, 0);
        assert_clean(&mut r);
        check_no_leaks(&mut r);
    }
}

#[test]
fn compression_fallback_to_raw_and_ratio_boundary() {
    let (c, o) = (c1(), g(b"cobj", 1));
    let run = |data: &[u8], spec: Option<CompSpec>| -> (u64, u64) {
        let mut r = rig(64, 1);
        let mut t = OTxn::new();
        t.mkcoll(c);
        commit(&mut r.st, &t);
        let mut t = OTxn::new();
        t.comp = spec;
        t.write(c, &o, 0, data);
        commit(&mut r.st, &t);
        assert_eq!(r.st.read(&c, &o, 0, data.len() as u64).unwrap(), data);
        assert_clean(&mut r);
        let (_, _, ok, rej) = comp_stats(&mut r.st);
        (ok, rej)
    };
    let cd = cdata(128 << 10, 9);
    assert_eq!(run(&cd, None), (0, 0), "mode none: untouched");
    // random data: the sample rules both chunks out, no full compress run (counted as sampled out, not rejected)
    assert_eq!(
        run(&rnd(128 << 10, 3), Some(cspec(Alg::Lz4))),
        (0, 0),
        "random data skipped"
    );
    let mut tiny = cspec(Alg::Lz4);
    tiny.ratio_permille = 1;
    assert_eq!(run(&cd, Some(tiny)).0, 0, "ratio too strict");
    let mut big_min = cspec(Alg::Lz4);
    big_min.min_bytes = 1 << 20;
    assert_eq!(run(&cd, Some(big_min)), (0, 0), "write below min blob size");
    // half zeros, half random: 9 physical blocks of 16; accepted from 563 permille, refused at 562
    let mut half = rnd(64 << 10, 4);
    half[32 << 10..].fill(0);
    let mut s = cspec(Alg::Lz4);
    s.ratio_permille = 563;
    assert_eq!(run(&half, Some(s)), (1, 0));
    s.ratio_permille = 562;
    assert_eq!(run(&half, Some(s)), (0, 1));
}

/// Whole-object read and the model compare, plus fsck.
fn same(r: &mut Rig, c: &CollT, o: &Ghobject, m: &[u8]) {
    assert_eq!(r.st.stat(c, o).unwrap().unwrap().size, m.len() as u64);
    assert_eq!(r.st.read(c, o, 0, m.len() as u64 + 10).unwrap(), m);
    assert_clean(r);
}

/// Chunk windows (adr 0059 am. 4): single-block overwrites of a compressed chunk read nothing and keep the chunk until
/// its windows hold fewer blocks than it occupies; then the rest is rewritten and the chunk released (space rule), but
/// never while a clone shares it. Data, fsck, counters and block ownership stay exact throughout.
#[test]
fn compressed_chunk_windows_overwrite_and_space_rule() {
    let mut r = rig(64, 1);
    let (c, o, o2) = (c1(), g(b"wobj", 1), g(b"wclone", 2));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let on = Some(cspec(Alg::Lz4));
    // half random, half zero per block: one 64 KiB chunk in 9 physical blocks
    let mut m = rnd(64 << 10, 5);
    for b in m.chunks_mut(4096) {
        b[2048..].fill(0);
    }
    let mut t = OTxn::new();
    t.comp = on;
    t.write(c, &o, 0, &m);
    commit(&mut r.st, &t);
    let used = |r: &mut Rig| r.st.shards[0].sh.statfs().data_used;
    let base = used(&mut r);
    assert_eq!(comp_stats(&mut r.st).0, 9 * 4096);
    let reads = |r: &mut Rig| r.disk.stats().reads;
    // overwrite blocks 1, 3, .. 13 (7 blocks): 9 left in windows = the chunk's size, it stays; no device read
    r.clean_remount();
    let r0 = reads(&mut r);
    for (i, blk) in (1..14).step_by(2).enumerate() {
        let d = rnd(4096, 100 + i as u64);
        m[blk * 4096..(blk + 1) * 4096].copy_from_slice(&d);
        let mut t = OTxn::new();
        t.comp = on;
        t.write(c, &o, blk as u64 * 4096, &d);
        commit(&mut r.st, &t);
    }
    assert_eq!(
        reads(&mut r),
        r0,
        "overwrites inside a compressed chunk read nothing"
    );
    same(&mut r, &c, &o, &m);
    assert_eq!(comp_stats(&mut r.st).1, 9 * 4096);
    assert_eq!(used(&mut r), base + 7);
    let gc = |r: &mut Rig| r.st.comp_counters().gc_merged;
    assert_eq!(gc(&mut r), 0);
    // a clone shares the chunk: the next overwrite (8 left < 9) must not release it
    let mut t = OTxn::new();
    t.push(TOp::Clone {
        cid: c,
        src: o.clone(),
        dst: o2.clone(),
    });
    commit(&mut r.st, &t);
    let m2 = m.clone();
    let d = rnd(4096, 200);
    m[0..4096].copy_from_slice(&d);
    let mut t = OTxn::new();
    t.comp = on;
    t.write(c, &o, 0, &d);
    commit(&mut r.st, &t);
    same(&mut r, &c, &o, &m);
    same(&mut r, &c, &o2, &m2);
    assert_eq!(gc(&mut r), 0, "shared with a clone: kept");
    // clone gone: the next overwrite rewrites the 7 live blocks raw and releases the chunk
    let mut t = OTxn::new();
    t.remove(c, &o2);
    commit(&mut r.st, &t);
    let d = rnd(4096, 201);
    m[14 * 4096..15 * 4096].copy_from_slice(&d);
    let mut t = OTxn::new();
    t.write(c, &o, 14 * 4096, &d);
    commit(&mut r.st, &t);
    same(&mut r, &c, &o, &m);
    assert_eq!(gc(&mut r), 7 * 4096);
    assert_eq!(comp_stats(&mut r.st).1, 0, "no compressed record left");
    assert_eq!(
        used(&mut r),
        base - 9 + 16,
        "the chunk's 16 logical blocks raw, nothing more"
    );
    r.clean_remount();
    same(&mut r, &c, &o, &m);
    let mut t = OTxn::new();
    t.remove(c, &o);
    commit(&mut r.st, &t);
    assert_eq!(used(&mut r), base - 9);
    check_no_leaks(&mut r);
}

#[test]
fn compressed_chunks_overwrite_zero_truncate_clone_remove() {
    // a mutation inside a chunk keeps the rest as windows (adr 0059 am. 4); expected = logical bytes in compressed records
    let k = |b: u64| b * 4096;
    let mut r = rig(64, 1);
    let (c, o, o2) = (c1(), g(b"cobj", 1), g(b"cclone", 2));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let on = Some(cspec(Alg::Zstd));
    let mut m = cdata(192 << 10, 1);
    let mut t = OTxn::new();
    t.comp = on;
    t.write(c, &o, 0, &m);
    commit(&mut r.st, &t);
    assert_eq!(comp_stats(&mut r.st).1, 192 << 10);
    // block overwrite inside chunk 0, compression on: the block is written raw next to two windows of the chunk
    let d = rnd(4096, 2);
    m[20_480..24_576].copy_from_slice(&d);
    let mut t = OTxn::new();
    t.comp = on;
    t.write(c, &o, 20_480, &d);
    commit(&mut r.st, &t);
    same(&mut r, &c, &o, &m);
    assert_eq!(comp_stats(&mut r.st).1, k(47));
    // unaligned small overwrite without compression: block 17 goes raw
    m[70_000..70_100].fill(0xee);
    let mut t = OTxn::new();
    t.write(c, &o, 70_000, &[0xee; 100]);
    commit(&mut r.st, &t);
    same(&mut r, &c, &o, &m);
    assert_eq!(comp_stats(&mut r.st).1, k(46));
    // zero straddling chunks 1 and 2: blocks 31..=34 leave the windows
    m[130_000..140_000].fill(0);
    let mut t = OTxn::new();
    t.zero(c, &o, 130_000, 10_000);
    commit(&mut r.st, &t);
    same(&mut r, &c, &o, &m);
    assert_eq!(comp_stats(&mut r.st).1, k(42));
    // rewrite chunk 1 and 2 compressed again, then truncate into chunk 2
    let d = cdata(128 << 10, 3);
    m[64 << 10..192 << 10].copy_from_slice(&d);
    let mut t = OTxn::new();
    t.comp = on;
    t.write(c, &o, 64 << 10, &d);
    commit(&mut r.st, &t);
    assert_eq!(comp_stats(&mut r.st).1, k(47));
    m.truncate(150_000);
    let mut t = OTxn::new();
    t.comp = on;
    t.truncate(c, &o, 150_000);
    commit(&mut r.st, &t);
    same(&mut r, &c, &o, &m);
    // blocks 32..36 stay a window of chunk 2, the partial block 36 is raw
    assert_eq!(comp_stats(&mut r.st).1, k(15 + 16 + 4));
    // clone (compressed dst), then overwrite src: dst unchanged
    let mut t = OTxn::new();
    t.comp = on;
    t.push(TOp::Clone {
        cid: c,
        src: o.clone(),
        dst: o2.clone(),
    });
    commit(&mut r.st, &t);
    let mut m2 = m.clone();
    same(&mut r, &c, &o2, &m2);
    let d = cdata(100_000, 4);
    m[1000..101_000].copy_from_slice(&d);
    let mut t = OTxn::new();
    t.write(c, &o, 1000, &d);
    commit(&mut r.st, &t);
    same(&mut r, &c, &o, &m);
    same(&mut r, &c, &o2, &m2);
    // clone_range from the compressed clone into a hole of the source
    let mut t = OTxn::new();
    t.comp = on;
    t.push(TOp::CloneRange {
        cid: c,
        src: o2.clone(),
        dst: o.clone(),
        src_off: 0,
        len: 140_000,
        dst_off: 60_000,
    });
    commit(&mut r.st, &t);
    m.resize(200_000, 0);
    m[60_000..200_000].copy_from_slice(&m2[..140_000]);
    same(&mut r, &c, &o, &m);
    r.clean_remount();
    same(&mut r, &c, &o, &m);
    same(&mut r, &c, &o2, &m2);
    // shrink the clone to nothing and remove both: no counters, no leaked blocks
    m2.clear();
    let mut t = OTxn::new();
    t.truncate(c, &o2, 0);
    t.remove(c, &o);
    commit(&mut r.st, &t);
    same(&mut r, &c, &o2, &m2);
    let mut t = OTxn::new();
    t.remove(c, &o2);
    commit(&mut r.st, &t);
    assert_eq!((comp_stats(&mut r.st).0, comp_stats(&mut r.st).1), (0, 0));
    check_no_leaks(&mut r);
}

#[test]
fn compressed_chunk_corruption_is_eio_and_scrub_reports_it() {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"cobj", 1));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let data = cdata(128 << 10, 5);
    let mut t = OTxn::new();
    t.comp = Some(cspec(Alg::Lz4));
    t.write(c, &o, 0, &data);
    commit(&mut r.st, &t);
    r.st.checkpoint().unwrap();
    let ok = r.st.scrub(&c, &o, 0xFFFF_FFFF).unwrap();
    assert!(ok.bad_blocks.is_empty());
    // corrupt a physical block of chunk 1 (logical block 16)
    let kv = r.st.shards[0].sh.dump_blocking(&mut r.st.clk).unwrap();
    let (_, v) = kv
        .iter()
        .find(|(k, _)| k[0] == T_EXT && k[10..14] == [0, 0, 0, 16])
        .unwrap();
    let ext = store::obj::onode::Ext::decode(v).unwrap();
    assert!(ext.comp.is_some());
    r.disk.corrupt(ext.pba, 100, 0x40);
    assert!(matches!(
        r.st.read(&c, &o, 17 * 4096, 10),
        Err(ObjError::Eio(_))
    ));
    assert!(
        r.st.read(&c, &o, 0, 65_536).is_ok(),
        "chunk 0 still readable"
    );
    let s = r.st.scrub(&c, &o, 0xFFFF_FFFF).unwrap();
    assert_eq!(s.bad_blocks, vec![16]);
    assert_ne!(s.data_crc, ok.data_crc);
    let rep = r.st.check(true).unwrap();
    assert_eq!(rep.errors.len(), 1, "{:?}", rep.errors);
    assert!(rep.errors[0].contains("checksum mismatch"));
}

/// `FEAT_COMPRESSION` appears only with the first compressed chunk (durable before that txn): mkfs, mount, raw writes and incompressible data under a compression spec never add it.
#[test]
fn compression_bit_only_with_first_compressed_write() {
    use store::layout::FEAT_COMPRESSION;
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"cobj", 1));
    let disk_bit = |r: &Rig| sb_features(&r.disk.image(), &r.sim) & FEAT_COMPRESSION;
    assert_eq!(r.st.features() & FEAT_COMPRESSION, 0, "mkfs set the bit");
    let mut t = OTxn::new();
    t.mkcoll(c);
    let d1 = cdata(128 << 10, 1);
    t.write(c, &o, 0, &d1);
    commit(&mut r.st, &t);
    let mut t = OTxn::new();
    t.comp = Some(cspec(Alg::Lz4));
    let d2 = rnd(128 << 10, 2);
    t.write(c, &o, 0, &d2);
    commit(&mut r.st, &t);
    assert_eq!(comp_stats(&mut r.st).2, 0);
    assert_eq!(disk_bit(&r), 0, "incompressible data set the bit");
    // remount: still no bit
    r.st.checkpoint().unwrap();
    let (d, s) = open(&r.disk.image(), &r.sim, &r.cfg);
    (r.disk, r.st) = (d, s);
    assert_eq!(r.st.features() & FEAT_COMPRESSION, 0, "mount added the bit");
    assert_eq!(disk_bit(&r), 0);
    // first compressed chunk: bit durable with (before) the txn; a crash right after the ack keeps both
    let m = cdata(128 << 10, 3);
    let mut t = OTxn::new();
    t.comp = Some(cspec(Alg::Lz4));
    t.write(c, &o, 0, &m);
    commit(&mut r.st, &t);
    assert_eq!(
        comp_stats(&mut r.st).2,
        2,
        "both chunks compressed in the first txn"
    );
    assert_ne!(r.st.features() & FEAT_COMPRESSION, 0);
    for pol in [CrashPolicy::DROP_ALL, CrashPolicy::MIXED] {
        let img = r.disk.crash_image(pol);
        assert_ne!(sb_features(&img, &r.sim) & FEAT_COMPRESSION, 0);
        let (_, mut st) = open(&img, &r.sim, &r.cfg);
        assert_eq!(st.read(&c, &o, 0, 128 << 10).unwrap(), m);
    }
    same(&mut r, &c, &o, &m);
}

/// Several mutations of one compressed chunk in one txn (overwrite, zero, truncate into it, extend again), clones of a
/// compressed object mutated in the same txn, whole-chunk replacement next to partial edits: no data loss, no leaks.
#[test]
fn compressed_chunk_multi_op_txns() {
    fn w(m: &mut Vec<u8>, off: usize, d: &[u8]) {
        if m.len() < off + d.len() {
            m.resize(off + d.len(), 0);
        }
        m[off..off + d.len()].copy_from_slice(d);
    }
    fn z(m: &mut Vec<u8>, off: usize, len: usize) {
        w(m, off, &vec![0; len]);
    }
    let mut r = rig(64, 1);
    let (c, o, o2) = (c1(), g(b"cobj", 1), g(b"cclone", 2));
    let on = Some(cspec(Alg::Zstd));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    for comp in [on, None] {
        let mut m = cdata(192 << 10, 1);
        let mut t = OTxn::new();
        t.comp = on;
        t.write(c, &o, 0, &m);
        commit(&mut r.st, &t);
        let mut t = OTxn::new();
        t.comp = comp;
        let d = rnd(4096, 2);
        t.write(c, &o, 8192, &d);
        w(&mut m, 8192, &d);
        t.zero(c, &o, 12_000, 9000);
        z(&mut m, 12_000, 9000);
        t.truncate(c, &o, 40_000);
        m.truncate(40_000);
        let d = cdata(5000, 3);
        t.write(c, &o, 60_000, &d);
        w(&mut m, 60_000, &d);
        commit(&mut r.st, &t);
        same(&mut r, &c, &o, &m);
        // back to three compressed chunks; clone + edits of both in one txn
        let d = cdata(192 << 10, 4);
        let mut t = OTxn::new();
        t.comp = on;
        t.write(c, &o, 0, &d);
        commit(&mut r.st, &t);
        m = d;
        let mut t = OTxn::new();
        t.comp = comp;
        t.write(c, &o, 65_000, &[0xab; 100]);
        w(&mut m, 65_000, &[0xab; 100]);
        t.push(TOp::Clone {
            cid: c,
            src: o.clone(),
            dst: o2.clone(),
        });
        let mut m2 = m.clone();
        let d = rnd(4096, 5);
        t.write(c, &o2, 130 << 10, &d);
        w(&mut m2, 130 << 10, &d);
        t.truncate(c, &o, 70_000);
        m.truncate(70_000);
        commit(&mut r.st, &t);
        same(&mut r, &c, &o, &m);
        same(&mut r, &c, &o2, &m2);
        // the clone: whole chunk 1 zeroed (aligned), a block written into it again, chunk 0 cut in the middle
        let mut t = OTxn::new();
        t.comp = comp;
        t.zero(c, &o2, 64 << 10, 64 << 10);
        z(&mut m2, 64 << 10, 64 << 10);
        let d = cdata(4096, 6);
        t.write(c, &o2, 100 << 10, &d);
        w(&mut m2, 100 << 10, &d);
        t.zero(c, &o2, 30_000, 3);
        z(&mut m2, 30_000, 3);
        commit(&mut r.st, &t);
        same(&mut r, &c, &o2, &m2);
        same(&mut r, &c, &o, &m);
        r.clean_remount();
        same(&mut r, &c, &o, &m);
        same(&mut r, &c, &o2, &m2);
        let mut t = OTxn::new();
        t.remove(c, &o);
        t.remove(c, &o2);
        commit(&mut r.st, &t);
    }
    assert_eq!((comp_stats(&mut r.st).0, comp_stats(&mut r.st).1), (0, 0));
    check_no_leaks(&mut r);
}

/// Small reads inside one compressed chunk decompress it once; a write or remove of the chunk drops the cached copy
/// (reused blocks never serve stale data); scrub still reads the media.
#[test]
fn decompressed_chunk_cache() {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"cobj", 1));
    let dec = |r: &Rig| r.st.shards[0].stats.decomp;
    let mut m = cdata(128 << 10, 1);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.comp = Some(cspec(Alg::Lz4));
    t.write(c, &o, 0, &m);
    commit(&mut r.st, &t);
    for off in [0usize, 8192, 60_000, 4096] {
        assert_eq!(
            r.st.read(&c, &o, off as u64, 4096).unwrap(),
            m[off..off + 4096]
        );
    }
    assert_eq!(dec(&r), 1, "one decompression for four reads of chunk 0");
    assert_eq!(r.st.read(&c, &o, 70_000, 10).unwrap(), m[70_000..70_010]);
    assert_eq!(dec(&r), 2);
    // overwrite inside chunk 0 (recompressed): the next read sees the new bytes
    let d = rnd(4096, 2);
    m[4096..8192].copy_from_slice(&d);
    let mut t = OTxn::new();
    t.comp = Some(cspec(Alg::Lz4));
    t.write(c, &o, 4096, &d);
    commit(&mut r.st, &t);
    assert_eq!(r.st.read(&c, &o, 0, 8192).unwrap(), m[..8192]);
    // remove + rewrite with other content (freed blocks are reused): never the old copy
    for seed in 3..8 {
        let m = cdata(128 << 10, seed);
        let mut t = OTxn::new();
        t.remove(c, &o);
        commit(&mut r.st, &t);
        let mut t = OTxn::new();
        t.comp = Some(cspec(Alg::Lz4));
        t.write(c, &o, 0, &m);
        commit(&mut r.st, &t);
        for off in [0usize, 40_000, 100_000] {
            assert_eq!(
                r.st.read(&c, &o, off as u64, 4096).unwrap(),
                m[off..off + 4096]
            );
        }
    }
    // scrub bypasses the warm cache
    r.st.checkpoint().unwrap();
    let kv = r.st.shards[0].sh.dump_blocking(&mut r.st.clk).unwrap();
    let (_, v) = kv
        .iter()
        .find(|(k, _)| k[0] == T_EXT && k[10..14] == [0, 0, 0, 0])
        .unwrap();
    let ext = store::obj::onode::Ext::decode(v).unwrap();
    r.disk.corrupt(ext.pba, 100, 0x40);
    assert_eq!(r.st.scrub(&c, &o, 0xFFFF_FFFF).unwrap().bad_blocks, vec![0]);
}

fn cached_warm_measurement(require_hit: bool) -> (u64, u64) {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"warm-compressed", 1));
    let data = cdata(64 << 10, 1);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.comp = Some(cspec(Alg::Lz4));
    t.write(c, &o, 0, &data);
    commit(&mut r.st, &t);
    assert_eq!(r.st.read(&c, &o, 0, 4096).unwrap(), data[..4096]);
    let ios = r.st.shards[0].stats.read_ios;
    let blocks = r.st.shards[0].stats.read_blocks;
    for _ in 0..100 {
        // Expiry must not cause another device read while the decompressed COW chunk is still valid.
        r.st.clk.t += 201_000_000;
        r.st.poll(&mut Vec::new()).unwrap();
        let ready = r.st.warm_data(&c, &o, 8192, 4096).unwrap();
        if require_hit {
            assert!(ready, "cached decompressed chunk parked at the gate");
        }
        let mut done = ready;
        for _ in 0..100_000 {
            if done {
                break;
            }
            r.st.poll(&mut Vec::new()).unwrap();
            r.st.idle();
            done = r.st.warm_data(&c, &o, 8192, 4096).unwrap();
        }
        assert!(done);
        assert_eq!(r.st.read(&c, &o, 8192, 4096).unwrap(), data[8192..12288]);
    }
    (
        r.st.shards[0].stats.read_ios - ios,
        (r.st.shards[0].stats.read_blocks - blocks) * 4096,
    )
}

#[test]
#[ignore = "local cached-warm IO measurement"]
fn perf_cached_decompressed_warm() {
    let (ios, bytes) = cached_warm_measurement(false);
    println!("100 cached chunk warm/read requests: {ios} device IOs, {bytes} device bytes");
}

fn preflight_measurement(require_plan: bool) -> (u64, u128) {
    let mut r = rig(128, 1);
    let (c, o) = (c1(), g(b"preflight-data", 1));
    let mut init = OTxn::new();
    init.mkcoll(c);
    init.touch(c, &o);
    commit(&mut r.st, &init);
    let data = rnd(16 << 20, 4);
    let mut txn = OTxn::new();
    txn.write(c, &o, 0, &data);
    assert!(r.st.txn_needs_check(&txn));
    let bytes = r.st.shards[0].stats.staged_data_bytes;
    let start = Instant::now();
    for _ in 0..8 {
        r.st.check_txn(&txn).unwrap();
        assert_eq!(
            r.st.shards[0].sh.state().alloc.n_reserved(),
            0,
            "preflight leaked reservations"
        );
        assert_eq!(
            r.st.stat(&c, &o).unwrap().unwrap().size,
            0,
            "preflight applied data"
        );
    }
    let ns = start.elapsed().as_nanos() / 8;
    let bytes = (r.st.shards[0].stats.staged_data_bytes - bytes) / 8;
    if require_plan {
        assert_eq!(bytes, 0, "preflight built full device data buffers");
    }
    // The planned size must remain valid for real durable submission.
    commit(&mut r.st, &txn);
    assert_eq!(r.st.read(&c, &o, 0, data.len() as u64).unwrap(), data);
    (bytes, ns)
}

#[test]
#[ignore = "local debug preflight CPU/copy measurement"]
fn perf_preflight_data_plan() {
    let (bytes, ns) = preflight_measurement(false);
    println!("16 MiB preflight: {bytes} DMA copy/CRC bytes, {ns} ns/check");
}

#[test]
fn preflight_plans_data_sizes_without_preparing_device_buffers() {
    preflight_measurement(true);
}

#[test]
fn preflight_failure_returns_partial_planned_reservations() {
    let mut r = rig(64, 1);
    let (c, a, b) = (c1(), g(b"plan-a", 1), g(b"plan-b", 2));
    let mut init = OTxn::new();
    init.mkcoll(c);
    commit(&mut r.st, &init);
    let data = vec![3; 32 << 20];
    let mut txn = OTxn::new();
    txn.write(c, &a, 0, &data);
    txn.write(c, &b, 0, &data);
    // free or held by a deallocate (the preflight's polls may complete one): nothing taken
    let unused = |r: &Rig| {
        let a = &r.st.shards[0].sh.state().alloc;
        a.n_free() + a.n_held()
    };
    let free = unused(&r);
    assert_eq!(r.st.check_txn(&txn), Err(ObjError::NoSpace));
    assert_eq!(r.st.shards[0].sh.state().alloc.n_reserved(), 0);
    assert_eq!(unused(&r), free);
    assert!(!r.st.exists(&c, &a).unwrap() && !r.st.exists(&c, &b).unwrap());
}

#[test]
#[ignore = "local preflight/submission CPU and copy measurements"]
fn perf_preflight_shapes() {
    for shape in ["omap", "shared-clone", "copied-clone", "compressed-write"] {
        let mut cfg = StoreCfg::default();
        cfg.shard.shared_clone = shape != "copied-clone";
        let (mut r, _) = rig_with(128, 1, 1024, 1, cfg);
        let (c, src, dst) = (c1(), g(b"plan-source", 1), g(b"plan-dest", 2));
        let data = vec![0x71; 4 << 20];
        let mut init = OTxn::new();
        init.mkcoll(c);
        init.write(c, &src, 0, &data);
        if shape == "compressed-write" {
            init.comp = Some(cspec(Alg::Lz4));
        }
        commit(&mut r.st, &init);
        let mut txn = OTxn::new();
        match shape {
            "omap" => {
                txn.push(TOp::OmapSetKeys {
                    cid: c,
                    oid: dst.clone(),
                    pairs: (0u32..500)
                        .map(|i| {
                            (
                                TxnBytes::Owned(i.to_be_bytes().to_vec()),
                                TxnBytes::Owned(vec![0x35; 1000]),
                            )
                        })
                        .collect(),
                });
            }
            "compressed-write" => {
                txn.comp = Some(cspec(Alg::Lz4));
                txn.write(c, &dst, 0, &data);
            }
            _ => {
                txn.push(TOp::Clone {
                    cid: c,
                    src: src.clone(),
                    dst: dst.clone(),
                });
            }
        };
        let bytes = r.st.shards[0].stats.staged_data_bytes;
        let read = r.st.shards[0].stats.read_blocks;
        let start = Instant::now();
        for _ in 0..4 {
            r.st.check_txn(&txn).unwrap();
        }
        let ns = start.elapsed().as_nanos() / 4;
        let copied = (r.st.shards[0].stats.staged_data_bytes - bytes) / 4;
        let read = (r.st.shards[0].stats.read_blocks - read) * 4096 / 4;
        let bytes = r.st.shards[0].stats.staged_data_bytes;
        let start = Instant::now();
        commit(&mut r.st, &txn);
        println!(
            "{shape}: preflight {ns} ns, {copied} DMA copy bytes, {} data-read bytes; durable submit {} ns, {} DMA copy bytes",
            read,
            start.elapsed().as_nanos(),
            r.st.shards[0].stats.staged_data_bytes - bytes
        );
        assert_eq!(r.st.shards[0].sh.state().alloc.n_reserved(), 0);
        let submitted = r.st.shards[0].stats.staged_data_bytes - bytes;
        if shape == "copied-clone" {
            assert_eq!(submitted, data.len() as u64);
        }
        if shape == "shared-clone" {
            assert_eq!(submitted, 0);
            assert!(r.st.shards[0].stats.shared_clones > 0);
        }
    }
}

#[test]
fn raw_clone_preflight_does_not_read_payload_or_apply_placeholder_bytes() {
    let mut cfg = StoreCfg::default();
    cfg.shard.shared_clone = false;
    let (mut r, _) = rig_with(64, 1, 1024, 1, cfg);
    let (c, src, dst) = (c1(), g(b"plan-source", 1), g(b"plan-dest", 2));
    let data = rnd(1 << 20, 7);
    let mut init = OTxn::new();
    init.mkcoll(c);
    init.write(c, &src, 0, &data);
    commit(&mut r.st, &init);
    let mut txn = OTxn::new();
    txn.push(TOp::Clone {
        cid: c,
        src: src.clone(),
        dst: dst.clone(),
    });
    let before = r.st.shards[0].stats;
    r.st.check_txn(&txn).unwrap();
    assert_eq!(
        r.st.shards[0].stats.read_ios, before.read_ios,
        "raw planning read payload"
    );
    assert_eq!(
        r.st.shards[0].stats.staged_data_bytes,
        before.staged_data_bytes
    );
    assert!(!r.st.exists(&c, &dst).unwrap());
    assert_eq!(r.st.shards[0].sh.state().alloc.n_reserved(), 0);
    commit(&mut r.st, &txn);
    assert_eq!(r.st.read(&c, &dst, 0, data.len() as u64).unwrap(), data);
    assert!(r.st.shards[0].stats.read_ios > before.read_ios);
}

#[test]
fn warm_data_uses_a_valid_decompressed_chunk_without_media_io() {
    assert_eq!(cached_warm_measurement(true), (0, 0));
}

#[test]
fn scrub_and_fsck_verify_media_even_with_prefetched_compressed_bytes() {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"media-compressed", 1));
    let data = cdata(128 << 10, 2);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.comp = Some(cspec(Alg::Lz4));
    t.write(c, &o, 0, &data);
    commit(&mut r.st, &t);
    // Cache chunk 0 and prefetch chunk 1, then damage the media under those RAM copies.
    r.st.read(&c, &o, 0, 4096).unwrap();
    warm_all(&mut r, &c, &o, data.len() as u64);
    let kv = r.st.shards[0].sh.dump_blocking(&mut r.st.clk).unwrap();
    let (_, v) = kv
        .iter()
        .find(|(k, _)| k[0] == T_EXT && k[10..14] == 16u32.to_be_bytes())
        .unwrap();
    let ext = store::obj::onode::Ext::decode(v).unwrap();
    r.disk.corrupt(ext.pba, 100, 0x40);
    assert_eq!(r.st.scrub(&c, &o, !0).unwrap().bad_blocks, vec![16]);
    assert!(
        !r.st.check(true).unwrap().errors.is_empty(),
        "deep check trusted RAM over media"
    );
}

#[test]
fn model_compression() {
    COMP_PCT.set(70);
    COMP_SEEN.set(0);
    WIN_SEEN.set(0);
    for seed in 40..=44 {
        run_model(seed, 1, 150, 50);
    }
    run_model(45, 4, 150, 60);
    COMP_PCT.set(0);
    assert!(
        COMP_SEEN.get() > 20,
        "compressed chunks seen: {}",
        COMP_SEEN.get()
    );
    assert!(
        WIN_SEEN.get() > 0,
        "no compressed chunk was cut into windows"
    );
}

/// Targeted soak of compressed chunk windows (adr 0059 am. 4; on-disk format + replay): many model seeds with mostly
/// compressed writes, and crash matrices. Run:
/// `cargo test -p store --release --test obj soak_compression_windows -- --ignored --nocapture`.
#[test]
#[ignore]
fn soak_compression_windows() {
    COMP_PCT.set(80);
    WIN_SEEN.set(0);
    for seed in 1000..1060 {
        run_model(seed, 1 + (seed % 4) as u32, 300, 60);
    }
    eprintln!("windows cut in the model runs: {}", WIN_SEEN.get());
    assert!(WIN_SEEN.get() > 0);
    for seed in 100..106 {
        crash_matrix(
            14,
            seed,
            &[CrashPolicy::MIXED, CrashPolicy::DROP_ALL],
            400,
            2,
        );
    }
    COMP_PCT.set(0);
}

/// Omap batch runs (adr 0476) against the object model: sorted batches and removal batches (runs of removals, adr
/// 0647-omap-blind-removals D1) mixed with point / range removals, clears, clones, renames and removals of the same
/// objects in the same txns, verified with reads, listings and stats, fsck mid-stream, clean remounts (replay window
/// rebuilds the runs).
#[test]
fn model_omap_runs() {
    RUNS_STRESS.set(true);
    RUN_PCT.set(60);
    RUNS_SEEN.set((0, 0, 0, 0));
    for seed in 60..=63 {
        run_model(seed, 1, 400, 70);
    }
    run_model(64, 4, 400, 80);
    let (puts, merges, compactions, rms) = RUNS_SEEN.get();
    RUNS_STRESS.set(false);
    RUN_PCT.set(0);
    eprintln!(
        "run puts {puts}, merges {merges}, compactions {compactions}, runs of removals {rms}"
    );
    assert!(
        puts > 50 && merges > 10 && compactions > 5 && rms > 10,
        "run puts {puts}, merges {merges}, compactions {compactions}, runs of removals {rms}"
    );
}

/// Run merges compress structured values with the shard's value dictionaries (the stage's rule on the tree path).
#[test]
fn model_omap_runs_compressed_values() {
    RUNS_STRESS.set(true);
    RUN_PCT.set(60);
    COMPVAL_PCT.set(80);
    COMPVAL_KINDS.set(2);
    RUN_VCOMP_SEEN.set(0);
    for seed in 70..=72 {
        run_model(seed, 1, 400, 90);
    }
    let seen = RUN_VCOMP_SEEN.get();
    RUNS_STRESS.set(false);
    RUN_PCT.set(0);
    COMPVAL_PCT.set(0);
    COMPVAL_KINDS.set(3);
    assert!(seen > 20, "merged values compressed: {seen}");
}

/// Power cuts at device events of an object workload with omap batch runs (merges, re-logs, tree ops on run keys, runs
/// of removals).
#[test]
fn crash_matrix_objects_omap_runs() {
    RUNS_STRESS.set(true);
    RUN_PCT.set(70);
    RUNS_SEEN.set((0, 0, 0, 0));
    let (n, c) = crash_matrix(
        40,
        61,
        &[
            CrashPolicy::MIXED,
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
        ],
        500,
        2,
    );
    crash_matrix(40, 62, &[CrashPolicy::MIXED], 300, 3);
    let (puts, _, _, rms) = RUNS_SEEN.get();
    RUNS_STRESS.set(false);
    RUN_PCT.set(0);
    eprintln!("run puts {puts}, runs of removals {rms}");
    assert!(n > 60 && c * 2 > n, "scenarios {n}, crashed {c}");
    assert!(
        puts > 5 && rms > 5,
        "run puts {puts}, runs of removals {rms}"
    );
}

/// The omap LSM engine (adr 0610) under the object model: every omap op kind (sets, sorted batches, point / range
/// removals, clears, clones, renames, removals) on regular and PG metadata objects, verified with reads, listings and
/// scrub, fsck mid-stream, clean remounts (manifest + memtable replay).
#[test]
fn model_omap_lsm() {
    OMAP_LSM.set(true);
    RUN_PCT.set(50);
    LSM_SEEN.set((0, 0));
    with_pgmeta(30, || {
        for seed in 80..=83 {
            run_model(seed, 1, 400, 70);
        }
        run_model(84, 4, 400, 80);
    });
    let (flushes, merges) = LSM_SEEN.get();
    OMAP_LSM.set(false);
    RUN_PCT.set(0);
    assert!(
        flushes > 4 && merges > 0,
        "flushes {flushes}, merges {merges}"
    );
}

/// Power cuts at device events of an object workload on the omap LSM engine (flush / merge writes, manifest txns).
#[test]
fn crash_matrix_objects_omap_lsm() {
    OMAP_LSM.set(true);
    RUN_PCT.set(50);
    let (n, c) = with_pgmeta_ret(40, || {
        crash_matrix(
            40,
            81,
            &[
                CrashPolicy::MIXED,
                CrashPolicy::DROP_ALL,
                CrashPolicy::PERSIST_ALL,
            ],
            500,
            2,
        )
    });
    OMAP_LSM.set(false);
    RUN_PCT.set(0);
    assert!(n > 60 && c * 2 > n, "scenarios {n}, crashed {c}");
}

#[test]
fn crash_matrix_objects_compression() {
    COMP_PCT.set(80);
    let (n, c) = crash_matrix(
        14,
        31,
        &[
            CrashPolicy::MIXED,
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
        ],
        500,
        2,
    );
    assert!(n > 60 && c * 2 > n, "scenarios {n}, crashed {c}");
    crash_matrix(14, 32, &[CrashPolicy::MIXED], 300, 3);
    COMP_PCT.set(0);
}

/// Text-like data (words from a small random dictionary): compresses to roughly 40-50 %.
fn textish(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng::new(seed);
    let words: Vec<Vec<u8>> = (0..300)
        .map(|_| {
            let l = r.range(2, 10) as usize;
            (0..l).map(|_| b'a' + r.below(26) as u8).collect()
        })
        .collect();
    let mut v = Vec::with_capacity(n + 16);
    while v.len() < n {
        v.extend_from_slice(&words[r.below(300) as usize]);
        v.push(b' ');
    }
    v.truncate(n);
    v
}

/// Cost of compression: codec alone per 64 KiB chunk, and the object layer (1 MiB writes, then reads) per codec on the
/// simulated device. Run: `cargo test -p store --release --test obj perf_compression -- --ignored --nocapture`.
#[test]
#[ignore]
fn perf_compression() {
    use store::compress::{Codec, SoftCodec, bound};
    let text = textish(64 << 10, 1);
    let rand = rnd(64 << 10, 2);
    let runs = cdata(64 << 10, 3);
    eprintln!("codec per 64 KiB chunk (us), ratio");
    for (dn, d) in [("text", &text), ("runs", &runs), ("random", &rand)] {
        for alg in [Alg::Lz4, Alg::Snappy, Alg::Zstd, Alg::Zlib] {
            let mut c = SoftCodec::default();
            let mut z = vec![0u8; bound(d.len())];
            let mut out = vec![0u8; d.len()];
            let n = 300;
            let t = Instant::now();
            let mut zl = 0;
            for _ in 0..n {
                zl = c.compress(alg, d, &mut z).unwrap();
            }
            let tc = t.elapsed().as_secs_f64() / n as f64 * 1e6;
            let t = Instant::now();
            for _ in 0..n {
                c.decompress(alg, &z[..zl], &mut out).unwrap();
            }
            let td = t.elapsed().as_secs_f64() / n as f64 * 1e6;
            eprintln!(
                "  {dn:6} {alg:?}: compress {tc:7.1} us ({:6.0} MB/s) decompress {td:7.1} us ({:6.0} MB/s) ratio {:.3}",
                65536.0 / tc,
                65536.0 / td,
                zl as f64 / d.len() as f64
            );
        }
    }
    eprintln!("object layer, 64 MiB in 1 MiB txns, text-like data (MiB/s write, read; stored %)");
    let data = textish(1 << 20, 7);
    for (name, spec) in [
        ("none", None),
        ("lz4", Some(cspec(Alg::Lz4))),
        ("snappy", Some(cspec(Alg::Snappy))),
        ("zstd", Some(cspec(Alg::Zstd))),
        ("zlib", Some(cspec(Alg::Zlib))),
    ] {
        let mut r = rig(256, 1);
        let (c, o) = (c1(), g(b"perf", 1));
        let mut t = OTxn::new();
        t.mkcoll(c);
        commit(&mut r.st, &t);
        let t0 = Instant::now();
        for i in 0..64u64 {
            let mut t = OTxn::new();
            t.comp = spec;
            t.write(c, &o, i << 20, &data);
            commit(&mut r.st, &t);
        }
        let w = 64.0 / t0.elapsed().as_secs_f64();
        let cs = r.st.coll_stats(&c).unwrap().unwrap();
        let t0 = Instant::now();
        for i in 0..64u64 {
            let d = r.st.read(&c, &o, i << 20, 1 << 20).unwrap();
            assert_eq!(d.len(), 1 << 20);
        }
        let rd = 64.0 / t0.elapsed().as_secs_f64();
        let stored = if cs.comp_orig > 0 {
            100.0 * cs.comp as f64 / cs.comp_orig as f64
        } else {
            100.0
        };
        eprintln!("  {name:7} write {w:7.0}  read {rd:7.0}  stored {stored:5.1} %");
    }
}

/// 4 MiB sequential reads of compressed data, the way the OSD serves them (`read_shared`): per codec and data mix, ns
/// per op (whole op, codec part, other), reply pieces and whether each piece carries a known crc. Data: every 4 KiB
/// block `rand_pct` % random, the rest zeros (fio `buffer_compress_percentage`-like). Run:
/// `cargo test -p store --release --test obj perf_comp_read_4m -- --ignored --nocapture`.
#[test]
#[ignore]
fn perf_comp_read_4m() {
    const OBJ: usize = 64 << 20;
    const PASSES: usize = 10;
    let mix = |n: usize, seed: u64, rand_pct: usize| {
        let mut v = rnd(n, seed);
        for b in v.chunks_mut(4096) {
            b[4096 * rand_pct / 100..].fill(0);
        }
        v
    };
    eprintln!(
        "4 MiB reads of a 64 MiB object (warm_data + nonblocking read_shared), {PASSES} passes, cold decoded cache"
    );
    for (pct_name, rand_pct) in [("p50", 50), ("p80", 20), ("p0", 100)] {
        let data = mix(OBJ, 1, rand_pct);
        for alg in [
            None,
            Some(Alg::Lz4),
            Some(Alg::Snappy),
            Some(Alg::Zstd),
            Some(Alg::Zlib),
        ] {
            let mut r = rig(256, 1);
            let (c, o) = (c1(), g(b"img", 1));
            let mut t = OTxn::new();
            t.mkcoll(c);
            commit(&mut r.st, &t);
            for (i, d) in data.chunks(4 << 20).enumerate() {
                let mut t = OTxn::new();
                t.comp = alg.map(cspec);
                t.write(c, &o, (i << 22) as u64, d);
                commit(&mut r.st, &t);
            }
            r.st.checkpoint().unwrap();
            r.clean_remount();
            let s0 = r.st.shards[0].stats;
            let d0 = r.disk.stats();
            let (mut ns, mut pieces, mut known, mut attempts) = (0u128, 0usize, 0usize, 0usize);
            let mut warm_ns = 0u128;
            let ops = PASSES * (OBJ >> 22);
            for pass in 0..PASSES {
                for i in 0..(OBJ >> 22) {
                    // the op engine's order: prefetch (warm_data), then the nonblocking read inside a read session
                    let off = (i << 22) as u64;
                    let t0 = Instant::now();
                    let mut spins = 0;
                    while !r.st.warm_data(&c, &o, off, 4 << 20).unwrap() {
                        spins += 1;
                        assert!(spins < 100_000, "prefetch never completed");
                        let mut acked = vec![];
                        r.st.poll(&mut acked).unwrap();
                        if !r.st.take_wake() {
                            r.st.idle();
                        }
                    }
                    warm_ns += t0.elapsed().as_nanos();
                    let t1 = Instant::now();
                    let v = loop {
                        r.st.read_session(Some((9, 1)), true);
                        r.st.set_nonblock_reads(true);
                        let v = r.st.read_shared(&c, &o, off, 4 << 20);
                        r.st.set_nonblock_reads(false);
                        let blocked = r.st.take_blocked();
                        r.st.read_session(None, blocked);
                        attempts += 1;
                        match v {
                            Ok(v) => break v,
                            Err(ObjError::WouldBlock) => {
                                let mut acked = vec![];
                                r.st.poll(&mut acked).unwrap();
                                if !r.st.take_wake() {
                                    r.st.idle();
                                }
                            }
                            Err(e) => panic!("read: {e:?}"),
                        }
                    };
                    // the reply's data crc (msgr2 crc mode): taken from the piece when known, else one pass over it
                    let mut sink = 0u32;
                    for p in &v {
                        sink ^= p.1.unwrap_or_else(|| crc::crc32c(!0, &p.0));
                    }
                    std::hint::black_box(sink);
                    ns += t1.elapsed().as_nanos();
                    pieces += v.len();
                    known += v.iter().filter(|p| p.1.is_some()).count();
                    assert_eq!(v.iter().map(|p| p.0.len()).sum::<usize>(), 4 << 20);
                    if pass == 0 {
                        let got: Vec<u8> = v.iter().flat_map(|p| p.0.iter().copied()).collect();
                        assert!(got == data[i << 22..(i + 1) << 22]);
                    }
                }
            }
            let s1 = r.st.shards[0].stats;
            let d1 = r.disk.stats();
            let name = alg.map_or("none".to_string(), |a| format!("{a:?}"));
            eprintln!(
                "  {pct_name:3} {name:7}: read phase {:6.0} us/op (incl. reply crc; prefetch {:5.0} us on the sim device, not counted)  codec {:6.0} us/op  decomp/op {:5.1}  pieces/op {:5.1} with crc {:5.1} read attempts/op {:4.2}  device reads/op {:5.1} blocks/op {:6.1}",
                ns as f64 / ops as f64 / 1e3,
                warm_ns as f64 / ops as f64 / 1e3,
                (s1.decomp_ns - s0.decomp_ns) as f64 / ops as f64 / 1e3,
                (s1.decomp - s0.decomp) as f64 / ops as f64,
                pieces as f64 / ops as f64,
                known as f64 / ops as f64,
                attempts as f64 / ops as f64,
                (d1.reads - d0.reads) as f64 / ops as f64,
                (d1.read_lbas - d0.read_lbas) as f64 / 8.0 / ops as f64,
            );
        }
    }
}

/// 4 KiB random overwrites of a compressed object (RBD 4k randwrite on a compressed pool, adr 0059 am. 4): per codec,
/// chunk windows: ops/s of the object layer, device reads / written blocks per op, codec calls per op,
/// stored bytes per logical byte at the end. Data: every 4 KiB block half random, half zeros (fio
/// `buffer_compress_percentage=50`-like). Run:
/// `cargo test -p store --release --test obj perf_comp_overwrite_4k -- --ignored --nocapture`.
#[test]
#[ignore]
fn perf_comp_overwrite_4k() {
    const OBJ: usize = 16 << 20;
    const OPS: u64 = 2048;
    let half = |n: usize, seed: u64| {
        let mut v = rnd(n, seed);
        for b in v.chunks_mut(4096) {
            b[2048..].fill(0);
        }
        v
    };
    eprintln!("4 KiB overwrites of a 16 MiB compressed object, {OPS} ops");
    for alg in [Alg::Lz4, Alg::Snappy, Alg::Zstd, Alg::Zlib] {
        let mut r = rig(256, 1);
        let (c, o) = (c1(), g(b"img", 1));
        let mut t = OTxn::new();
        t.mkcoll(c);
        commit(&mut r.st, &t);
        let on = Some(cspec(alg));
        for (i, d) in half(OBJ, 1).chunks(1 << 20).enumerate() {
            let mut t = OTxn::new();
            t.comp = on;
            t.write(c, &o, (i << 20) as u64, d);
            commit(&mut r.st, &t);
        }
        r.clean_remount(); // cold: no decoded chunk cached
        let used0 = r.st.shards[0].sh.statfs().data_used;
        let (d0, s0) = (r.disk.stats(), r.st.shards[0].stats);
        let mut rng = Rng::new(7);
        let blks = half(OPS as usize * 4096, 9);
        let t0 = Instant::now();
        for blk in blks.chunks(4096) {
            let off = rng.below((OBJ / 4096) as u64) * 4096;
            let mut t = OTxn::new();
            t.comp = on;
            t.write(c, &o, off, blk);
            commit(&mut r.st, &t);
        }
        let ops = OPS as f64 / t0.elapsed().as_secs_f64();
        let (d1, s1) = (r.disk.stats(), r.st.shards[0].stats);
        let per = |x: u64| x as f64 / OPS as f64;
        let (phys, orig) = {
            let cs = r.st.coll_stats(&c).unwrap().unwrap();
            (cs.comp, cs.comp_orig)
        };
        let used = r.st.shards[0].sh.statfs().data_used;
        assert_clean(&mut r);
        eprintln!(
            "  {alg:?}: {ops:8.0} ops/s  dev reads/op {:.2} read blks/op {:.2} write blks/op {:.2}  \
                 compress/op {:.2} decompress/op {:.2}  comp {phys} / orig {orig}  data used {} -> {}",
            per(d1.reads - d0.reads),
            per(d1.read_lbas - d0.read_lbas),
            per(d1.write_lbas - d0.write_lbas),
            per(s1.comp_ok + s1.comp_rejected - s0.comp_ok - s0.comp_rejected),
            per(s1.decomp - s0.decomp),
            used0 * 4096,
            used * 4096,
        );
    }
}

#[test]
fn incompressible_chunks_are_skipped_by_the_sample() {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"rnd", 3));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let data = rnd(128 << 10, 11);
    let mut t = OTxn::new();
    t.comp = Some(cspec(Alg::Zstd));
    t.write(c, &o, 0, &data);
    commit(&mut r.st, &t);
    let cc = r.st.comp_counters();
    assert_eq!((cc.ok, cc.rejected, cc.sampled_out), (0, 0, 2), "{cc:?}");
    assert!(cc.comp_ns > 0);
    assert_eq!(r.st.read(&c, &o, 0, 128 << 10).unwrap(), data);
    assert_clean(&mut r);
}

#[test]
fn abandoned_prefetch_waiters_do_not_strand_the_ops_behind_them() {
    // Lost wake-up seen live (fsx on a mixed lab, 3 of 8 runs hung): ops denied prefetch admission leave a waiter in the queue;
    // when the op never probes again (it ran another way / keyed on another run) the waiter stays, every other op is denied
    // because of it, and with nothing in flight no wake ever comes. The waiter must expire AND wake the gate.
    let (mut r, _) = rig_with(128, 1, 1024, 11, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let len = 4u64 << 20;
    let objs: Vec<Ghobject> = (0..9u8).map(|i| g(&[b'a' + i], 1)).collect();
    for o in &objs {
        let mut t = OTxn::new();
        let d = vec![7u8; len as usize];
        t.write(c, o, 0, &d);
        t.setattr(c, o, b"_", b"oi");
        commit(&mut r.st, &t);
    }
    r.clean_remount();
    let poll = |r: &mut Rig| {
        let mut a = vec![];
        r.st.poll(&mut a).unwrap();
        r.st.idle();
    };
    for o in &objs {
        while !r.st.warm(&c, o, 0, len).unwrap() {
            poll(&mut r);
        }
    }
    for o in &objs[..7] {
        assert!(!r.st.warm_data(&c, o, 0, len).unwrap());
    }
    // two denied waiters ...
    assert!(!r.st.warm_data(&c, &objs[7], 0, len).unwrap());
    assert!(!r.st.warm_data(&c, &objs[8], 0, len).unwrap());
    // ... then the 7 in-flight reads are served and consumed; objs 7 / 8 are never probed again
    for o in &objs[..7] {
        let mut spins = 0;
        while !r.st.warm_data(&c, o, 0, len).unwrap() {
            spins += 1;
            assert!(spins < 200_000);
            poll(&mut r);
        }
        r.st.read(&c, o, 0, len).unwrap();
    }
    // the table is empty, two ghosts remain: the gate must be woken once they expire
    assert_eq!(r.st.shards[0].pf_waiters(), 2);
    r.st.take_wake();
    let mut woke = false;
    for _ in 0..200_000 {
        poll(&mut r);
        woke |= r.st.take_wake();
        if r.st.shards[0].pf_waiters() == 0 {
            break;
        }
    }
    assert_eq!(
        r.st.shards[0].pf_waiters(),
        0,
        "abandoned waiters never expire"
    );
    assert!(woke, "no wake: ops denied behind abandoned waiters hang");
}

#[test]
fn parked_staging_resumes_when_retained_read_capacity_is_released_without_io() {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"read-slots", 1));
    let data = vec![0x31; 1 << 20];
    let mut t = OTxn::new();
    t.mkcoll(c).write(c, &o, 0, &data);
    r.st.commit(&t).unwrap();
    r.st.set_nonblock_reads(true);
    for session in 1..=4 {
        let deadline = r.st.clk.t + 30_000_000_000;
        let mut done = false;
        for _ in 0..100_000 {
            r.st.read_session(Some((9, session)), true);
            match r.st.read(&c, &o, 0, data.len() as u64) {
                Ok(got) => {
                    assert_eq!(got, data);
                    done = true;
                }
                Err(ObjError::WouldBlock) => {}
                Err(e) => panic!("{e:?}"),
            }
            r.st.read_session(None, true);
            r.st.take_blocked();
            if done {
                break;
            }
            assert!(r.st.clk.t < deadline);
            r.st.poll(&mut Vec::new()).unwrap();
            r.st.idle();
        }
        assert!(done);
    }
    r.st.set_nonblock_reads(false);
    let mut t = OTxn::new();
    t.write(c, &o, 1, &[0x42]);
    assert_eq!(r.st.queue(&t, 91).unwrap(), store::obj::Queued::Pending(91));
    let attempts = r.st.queue_attempts;
    let io = r.st.shards[0].sh.stats.io_completions;
    for _ in 0..10 {
        r.st.poll(&mut Vec::new()).unwrap();
    }
    assert_eq!(r.st.queue_attempts, attempts);
    r.st.read_session(Some((9, 1)), true);
    r.st.read_session(None, false);
    assert_eq!(r.st.shards[0].sh.stats.io_completions, io);
    r.st.poll(&mut Vec::new()).unwrap();
    assert!(
        r.st.queue_attempts > attempts,
        "release must wake staging without another device completion"
    );
    let (a, e) = drive_parked(&mut r.st, 1);
    assert_eq!(a, vec![91]);
    assert!(e.is_empty());
    assert_eq!(r.st.read(&c, &o, 0, 2).unwrap(), vec![0x31, 0x42]);
}

#[test]
fn parked_payload_budget_throttles_before_the_hard_byte_cap() {
    let mut r = parked_write_fixture();
    r.st.set_queue_limits(32, 128 << 10);
    let data = vec![0x42; 40 << 10];
    let mut t = OTxn::new();
    t.write(c1(), &g(b"obj-500", 500), 0, &data);
    assert_eq!(r.st.queue(&t, 94).unwrap(), store::obj::Queued::Pending(94));
    assert_eq!(r.st.queued_count(), 1, "count cap is still far away");
    assert!(
        !r.st.admission_ready(),
        "retained-byte headroom must throttle independently"
    );
    let (a, e) = drive_parked(&mut r.st, 1);
    assert_eq!(a, vec![94]);
    assert!(e.is_empty());
    assert!(r.st.admission_ready());
}

#[test]
fn queued_builder_cannot_discard_an_internal_copy_read_with_the_same_token() {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"copy-session", 1));
    let data = vec![0x31; 1 << 20];
    let mut t = OTxn::new();
    t.mkcoll(c).write(c, &o, 0, &data);
    r.st.commit(&t).unwrap();
    // COPY_CONN in the executor; its tid may equal the adapter's independent store token.
    let session = (u64::MAX - 1, 1);
    r.st.set_nonblock_reads(true);
    let deadline = r.st.clk.t + 30_000_000_000;
    let mut done = false;
    for _ in 0..100_000 {
        r.st.read_session(Some(session), true);
        match r.st.read(&c, &o, 0, data.len() as u64) {
            Ok(got) => {
                assert_eq!(got, data);
                done = true;
            }
            Err(ObjError::WouldBlock) => {}
            Err(e) => panic!("{e:?}"),
        }
        r.st.read_session(None, true);
        r.st.take_blocked();
        if done {
            break;
        }
        assert!(r.st.clk.t < deadline);
        r.st.poll(&mut Vec::new()).unwrap();
        r.st.idle();
    }
    assert!(done);
    let usage = r.st.shards[0].rolling_usage();
    assert_eq!(usage.0, data.len());
    r.st.read_session(Some(session), true);
    let scope = r.st.begin_queue_build(&c, 1).unwrap();
    r.st.end_queue_build(scope, false);
    assert_eq!(r.st.shards[0].rolling_usage(), usage);
    r.st.read_session(None, false);
    assert_eq!(r.st.shards[0].rolling_usage(), (0, 0));
}

#[test]
fn budgeted_omap_scan_projects_keys_without_loading_large_values() {
    let mut r = rig_nvc(64, 1);
    let (c, o) = (c1(), g(b"projected-omap", 78));
    let value = vec![0x51; 64 << 10];
    let mut t = OTxn::new();
    t.mkcoll(c);
    for k in [b"p/a".as_slice(), b"p/b", b"q/a"] {
        t.omap_set(c, &o, k, &value);
    }
    commit(&mut r.st, &t);
    r.st.checkpoint().unwrap();
    let image = r.disk.image();
    let (keys_disk, mut keys_st) = open(&image, &r.sim, &r.cfg);
    let before = keys_disk.stats().read_lbas;
    let (keys, more) = keys_st
        .omap_range(&c, &o, b"", b"p/", 100, 7, false)
        .unwrap();
    let key_reads = keys_disk.stats().read_lbas - before;
    assert_eq!(keys, vec![(b"p/a".to_vec(), Vec::new())]);
    assert!(more);
    assert_eq!(
        keys_st
            .omap_range(&c, &o, b"p/b", b"p/", 100, 7, false)
            .unwrap(),
        (vec![(b"p/b".to_vec(), Vec::new())], false)
    );
    assert_eq!(
        keys_st
            .omap_range(&c, &o, b"", b"p/", 100, 0, false)
            .unwrap(),
        (vec![], true)
    );
    assert_eq!(
        keys_st
            .omap_range(&c, &o, b"", b"p/", 0, 100, false)
            .unwrap(),
        (vec![], true)
    );
    assert_eq!(
        keys_st
            .omap_range(&c, &o, b"", b"missing", 100, 0, false)
            .unwrap(),
        (vec![], false)
    );
    let (values_disk, mut values_st) = open(&image, &r.sim, &r.cfg);
    let before = values_disk.stats().read_lbas;
    let (values, more) = values_st
        .omap_range(&c, &o, b"", b"p/", 100, 1, true)
        .unwrap();
    let value_reads = values_disk.stats().read_lbas - before;
    assert_eq!(values, vec![(b"p/a".to_vec(), value)]);
    assert!(more);
    assert!(
        value_reads > key_reads,
        "key-only scan must avoid fragment pages: {key_reads} versus {value_reads}"
    );
}

#[test]
fn pf_retain_off_makes_served_runs_single_use() {
    // kill switch `pf_retain` (adr 0043 am. 5): a fully served run goes at once, a re-read reads the device
    let mut cfg = StoreCfg::default();
    cfg.shard.pf_retain = false;
    let (mut r, _) = rig_with(64, 1, 1024, 5, cfg);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let big: Vec<u8> = (0..(256 << 10)).map(|i| (i * 13 % 251) as u8).collect();
    let o = g(b"pf-off", 1);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &big);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    warm_all(&mut r, &c, &o, big.len() as u64);
    let before = r.st.shards[0].stats.read_ios;
    assert_eq!(r.st.read(&c, &o, 0, big.len() as u64).unwrap(), big);
    assert_eq!(r.st.shards[0].stats.read_ios, before);
    assert_eq!(
        r.st.shards[0].pf_usage().0,
        0,
        "served run kept with retain off"
    );
    assert_eq!(r.st.read(&c, &o, 0, big.len() as u64).unwrap(), big);
    assert!(r.st.shards[0].stats.read_ios > before);
}

#[test]
fn queue_barrier_waits_for_unsent_page_dma_memory() {
    #[derive(Default)]
    struct PressureClock(SimClock);
    impl Clock for PressureClock {
        fn now(&mut self) -> u64 {
            self.0.now()
        }
        fn wall_time(&self) -> bool {
            false
        }
        fn idle(&mut self, hint: Option<u64>) {
            if hint.is_none() {
                self.0.t += 31_000_000_000;
            } else {
                self.0.idle(hint);
            }
        }
    }
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"dma-barrier-cold", 1));
    let mut init = OTxn::new();
    init.mkcoll(c);
    init.write(c, &o, 0, &[0x35; 4096]);
    commit(&mut r.st, &init);
    r.clean_remount();
    let disk = SimDisk::from_image(&r.disk.image(), r.sim.clone());
    let (mut st, _) =
        Store::mount(|| disk.queue(), PressureClock::default(), r.cfg.clone()).unwrap();
    st.drop_caches();
    disk.refuse_io_bufs(20);
    let mut update = OTxn::new();
    update.write(c, &o, 0, &[0x7b; 4096]);
    assert_eq!(
        st.queue(&update, 8743).unwrap(),
        store::obj::Queued::Pending(8743)
    );
    st.drain_queued()
        .expect("barrier must retain pressure-blocked input");
    assert_eq!(st.queued_count(), 0);
    st.checkpoint().unwrap();
    assert_eq!(st.read(&c, &o, 0, 4096).unwrap(), [0x7b; 4096]);
}

#[test]
fn queued_cold_write_waits_for_dma_memory_beyond_stall_limit() {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"dma-queued-cold", 1));
    let mut init = OTxn::new();
    init.mkcoll(c);
    init.write(c, &o, 0, &[0x35; 4096]);
    commit(&mut r.st, &init);
    r.clean_remount();
    r.st.drop_caches();
    r.disk.refuse_io_bufs(u64::MAX);
    let mut update = OTxn::new();
    update.write(c, &o, 0, &[0x7b; 4096]);
    assert_eq!(
        r.st.queue(&update, 8742).unwrap(),
        store::obj::Queued::Pending(8742)
    );
    let mut acked = Vec::new();
    r.st.poll(&mut acked).unwrap();
    assert!(r.disk.stats().refused_io_bufs > 0);
    assert!(acked.is_empty());
    let dev = r.st.shards[0].sh.dev();
    assert_eq!(
        dev.queue_space(),
        dev.queue_depth(),
        "no device IO was submitted"
    );
    r.st.clk.t += 31_000_000_000;
    r.st.poll(&mut acked)
        .expect("DMA pressure must not fail a parked mutation");
    assert!(
        acked.is_empty(),
        "unsubmitted mutation must not be acknowledged"
    );
    assert_eq!(r.st.queued_count(), 1);
    let image = r.disk.crash_image(CrashPolicy::DROP_ALL);
    let (_, mut replayed) = open(&image, &r.sim, &r.cfg);
    assert_eq!(replayed.read(&c, &o, 0, 4096).unwrap(), [0x35; 4096]);
    r.disk.clear_faults();
    let (done, errors) = drive_parked(&mut r.st, 1);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(done, [8742]);
    let image = r.disk.crash_image(CrashPolicy::DROP_ALL);
    let (_, mut replayed) = open(&image, &r.sim, &r.cfg);
    assert_eq!(replayed.read(&c, &o, 0, 4096).unwrap(), [0x7b; 4096]);
}

/// OQ 151: a queued write whose cold tree page is refused DMA memory waits (loud re-arm) also while unrelated device IO
/// is in flight on its shard: its page was never sent, so no device request of it can be stalled (adr 0175 am. 4).
#[test]
fn queued_cold_write_waits_for_dma_memory_beside_unrelated_io() {
    let mut r = rig(64, 1);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    // enough objects for several tree leaves: the reader's path stays resident, the writer's leaf goes cold
    let bodies: Vec<[u8; 4096]> = (0..1000u32).map(|n| [n as u8; 4096]).collect();
    for batch in 0..10u32 {
        let mut t = OTxn::new();
        for i in 0..100u32 {
            let n = batch * 100 + i;
            t.write(
                c,
                &g(format!("dma-io-{n:04}").as_bytes(), n),
                0,
                &bodies[n as usize],
            );
        }
        commit(&mut r.st, &t);
    }
    r.clean_remount();
    r.st.drop_caches();
    let (a, b) = (g(b"dma-io-0000", 0), g(b"dma-io-0999", 999));
    assert_eq!(r.st.read(&c, &b, 0, 4096).unwrap(), [999u32 as u8; 4096]);
    // unrelated IO in flight far beyond the stall limit: a media read of the reader's object
    r.disk.set_xfer_ns(100_000_000_000);
    assert!(matches!(
        r.st.read_media_async(&c, &b, 0, 4096, 77),
        Err(ObjError::WouldBlock)
    ));
    r.disk.refuse_io_bufs(u64::MAX);
    let mut update = OTxn::new();
    update.write(c, &a, 0, &[0x7b; 4096]);
    assert_eq!(
        r.st.queue(&update, 8744).unwrap(),
        store::obj::Queued::Pending(8744)
    );
    let mut acked = Vec::new();
    r.st.poll(&mut acked).unwrap();
    assert!(
        r.disk.stats().refused_io_bufs > 0,
        "the writer's page was refused"
    );
    let dev = r.st.shards[0].sh.dev();
    assert!(
        dev.queue_space() < dev.queue_depth(),
        "unrelated IO in flight"
    );
    r.st.clk.t += 31_000_000_000;
    r.st.poll(&mut acked)
        .expect("DMA pressure must not fail a parked mutation beside unrelated IO");
    let mut errors = Vec::new();
    r.st.take_queue_errors(&mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    assert!(
        acked.is_empty(),
        "unsubmitted mutation must not be acknowledged"
    );
    assert_eq!(r.st.queued_count(), 1);
    r.disk.clear_faults();
    r.disk.set_xfer_ns(SimConfig::new(0).xfer_ns_per_lba);
    r.st.clk.t += 100_000_000_000;
    let (done, errors) = drive_parked(&mut r.st, 1);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(done, [8744]);
    let image = r.disk.crash_image(CrashPolicy::DROP_ALL);
    let (_, mut replayed) = open(&image, &r.sim, &r.cfg);
    assert_eq!(replayed.read(&c, &a, 0, 4096).unwrap(), [0x7b; 4096]);
}

#[test]
fn refused_dma_buffers_postpone_reads_and_never_fail_them() {
    // a device whose DMA budget has no buffer to spare (adr 0175 am. 4) refuses read buffers: prefetch and rolling
    // reads (deferrable memory) are postponed and resumed (backpressure); a synchronous read (in-flight IO memory)
    // refused in the middle ends its batch early and waits polling completions for the rest (never a wait that does not
    // poll); every read returns the right bytes
    let mut cfg = StoreCfg::default();
    cfg.shard.pf_retain = false; // device buffers on every read path (retained runs are read into RAM on the sim)
    let (mut r, _) = rig_with(64, 1, 1024, 5, cfg);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let big: Vec<u8> = (0..(1 << 20)).map(|i| (i * 13 % 251) as u8).collect();
    let o = g(b"dma-short", 1);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &big);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    let len = big.len() as u64;
    // prefetch: refused, retried until admitted
    r.disk.refuse_bufs(8);
    warm_all(&mut r, &c, &o, len);
    assert_eq!(r.st.read(&c, &o, 0, len).unwrap(), big);
    // rolling (media) read: postponed, resumed by the pumps, completes
    r.clean_remount();
    let refused = r.disk.stats().refused_bufs;
    r.disk.refuse_bufs(8);
    let wall = Instant::now();
    let got = loop {
        assert!(
            wall.elapsed().as_secs() < 10,
            "postponed rolling read never completed"
        );
        match r.st.read_media_async(&c, &o, 0, len, 7) {
            Ok(v) => break v,
            Err(ObjError::WouldBlock) => {}
            Err(e) => panic!("{e:?}"),
        }
        r.st.poll(&mut Vec::new()).unwrap();
        r.st.idle();
    };
    assert_eq!(got, big);
    assert_eq!(
        r.disk.stats().refused_bufs - refused,
        8,
        "every refusal was met and retried"
    );
    // a blocking read (4 device reads of 256 KiB on the sim, in-flight IO memory) refused after its first two buffers:
    // the batch ends after two, the rest goes out once the budget admits it again (a first read loads the tree pages)
    r.clean_remount();
    assert_eq!(r.st.read(&c, &o, 0, len).unwrap(), big);
    let refused = r.disk.stats().refused_io_bufs;
    r.disk.refuse_io_bufs_after(2, 2);
    assert_eq!(r.st.read(&c, &o, 0, len).unwrap(), big);
    assert_eq!(r.disk.stats().refused_io_bufs - refused, 2);
}

#[test]
fn refused_write_copies_are_deferred_to_the_submit() {
    // a staging copy is deferrable memory of the DMA budget (adr 0175 am. 4): refused, the run is staged as a deferred
    // copy (crcs over the source, no buffer held) and copied into in-flight IO memory right before its device write; a
    // refused submit waits in the shard's data backlog, retried at every poll. Nothing is restaged, a txn whose copies
    // all are refused (more than the read gate could ever admit) completes, queued or blocking, and reads back after a
    // remount
    use store::obj::Queued;
    let (mut r, _) = rig_with(64, 1, 1024, 5, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let data: Vec<u8> = (0..(4 << 20) + 5000).map(|i| (i * 7 % 253) as u8).collect();
    let len = data.len() as u64;
    // queued: every staging copy refused, and the first submits of the deferred copies
    let o = g(b"dma-copy-q", 1);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &data);
    t.setattr(c, &o, b"_", b"oi");
    r.disk.refuse_bufs(u64::MAX);
    r.disk.refuse_io_bufs(5);
    assert!(matches!(
        r.st.queue(&t, 4242).unwrap(),
        Queued::Pending(4242) | Queued::Submitted(4242)
    ));
    let (acked, errors) = drive_parked(&mut r.st, 1);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(acked, vec![4242]);
    assert_eq!(r.disk.stats().refused_io_bufs, 5);
    assert!(r.st.shards[0].stats.deferred_copy_bytes >= len - 5000);
    assert!(r.st.shards[0].sh.stats.backlog_dma > 0);
    assert_eq!(r.st.read(&c, &o, 0, len).unwrap(), data);
    // blocking: the commit pumps its own shard, whose polls send the deferred copies
    let o2 = g(b"dma-copy-b", 2);
    let mut t = OTxn::new();
    t.write(c, &o2, 0, &data);
    t.setattr(c, &o2, b"_", b"oi");
    r.disk.refuse_io_bufs(5);
    commit(&mut r.st, &t);
    assert_eq!(r.disk.stats().refused_io_bufs, 10);
    assert_eq!(r.st.shards[0].sh.state().alloc.n_reserved(), 0);
    r.disk.clear_faults();
    assert_eq!(r.st.read(&c, &o2, 0, len).unwrap(), data);
    r.clean_remount();
    assert_eq!(r.st.read(&c, &o, 0, len).unwrap(), data);
    assert_eq!(r.st.read(&c, &o2, 0, len).unwrap(), data);
}

#[test]
fn refused_io_buffers_postpone_wal_pages_checkpoints_and_reads() {
    // in-flight IO buffers (WAL images, tree pages, checkpoint and root, synchronous reads) refused by the DMA budget (adr
    // 0175 am. 4) are postponed and tried again at the next shard poll: commits, checkpoints and cold reads complete,
    // nothing fails
    let (mut r, _) = rig_with(64, 1, 1024, 5, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let data: Vec<u8> = (0..(64 << 10)).map(|i| (i * 11 % 247) as u8).collect();
    let len = data.len() as u64;
    let o = g(b"dma-meta", 1);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &data);
    t.setattr(c, &o, b"_", b"oi");
    let m = r.disk.stats().refused_io_bufs;
    r.disk.refuse_io_bufs(2);
    commit(&mut r.st, &t);
    assert_eq!(r.disk.stats().refused_io_bufs - m, 2, "WAL image");
    r.disk.refuse_io_bufs(4);
    r.st.checkpoint().unwrap();
    assert_eq!(r.disk.stats().refused_io_bufs - m, 6, "checkpoint");
    r.clean_remount();
    let d = r.st.drop_caches();
    assert!(d.tree_pages > 0, "{d:?}");
    let loads = r.st.shards[0].sh.tree_stats().loads;
    let m = r.disk.stats().refused_io_bufs;
    r.disk.refuse_io_bufs(3);
    assert_eq!(r.st.read(&c, &o, 0, len).unwrap(), data);
    assert!(
        r.st.shards[0].sh.tree_stats().loads > loads,
        "tree pages were not reloaded"
    );
    assert_eq!(
        r.disk.stats().refused_io_bufs - m,
        3,
        "tree pages, data reads"
    );
    r.clean_remount();
    assert_eq!(r.st.read(&c, &o, 0, len).unwrap(), data);
}

#[test]
fn small_reads_of_cached_data_go_by_reference() {
    // a 4 KiB read below the share threshold is a slice of the cached run (no copy, no device read) once the data cache
    // holds the run; the bytes and the known crc are those of a copy; an unaligned read is a slice without a known crc
    let (mut r, _) = rig_with(64, 1, 1024, 5, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let big: Vec<u8> = (0..(256 << 10)).map(|i| (i * 13 % 251) as u8).collect();
    let o = g(b"small-ref", 1);
    let mut t = OTxn::new();
    t.write(c, &o, 0, &big);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    warm_all(&mut r, &c, &o, big.len() as u64);
    // the full read fills the data cache
    assert_eq!(r.st.read(&c, &o, 0, big.len() as u64).unwrap(), big);
    let ios = r.st.shards[0].stats.read_ios;
    let a = r.st.read_shared(&c, &o, 8192, 4096).unwrap();
    let b = r.st.read_shared(&c, &o, 8192, 4096).unwrap();
    assert_eq!(
        r.st.shards[0].stats.read_ios, ios,
        "device read of cached data"
    );
    assert_eq!((a.len(), b.len()), (1, 1));
    assert_eq!(&a[0].0[..], &big[8192..12288]);
    assert_eq!(a[0].0.as_ptr(), b[0].0.as_ptr(), "second read copied");
    assert_eq!(a[0].1, Some(crc::crc32c(!0, &big[8192..12288])));
    let cat = |v: &[(bytes::Bytes, Option<u32>)]| -> Vec<u8> {
        v.iter().flat_map(|p| p.0.iter().copied()).collect()
    };
    let u = r.st.read_shared(&c, &o, 100, 3000).unwrap();
    assert_eq!(u.iter().map(|p| p.0.len()).sum::<usize>(), 3000);
    assert_eq!(cat(&u), &big[100..3100]);
    // two blocks in one piece and a read crossing the end of the object
    let e = r.st.read_shared(&c, &o, 4096 * 62, 9000).unwrap();
    assert_eq!(cat(&e), &big[4096 * 62..]);
}

#[test]
fn parked_write_invalidates_hot_probe() {
    for verified in [false, true] {
        let (mut r, _) = rig_with(64, 1, 1024, 5, StoreCfg::default());
        let c = c1();
        let o = g(b"parked-probe", 1);
        let old = vec![0x31; 256 << 10];
        let mut t = OTxn::new();
        t.mkcoll(c);
        t.write(c, &o, 0, &old);
        commit(&mut r.st, &t);
        r.clean_remount();
        warm_all(&mut r, &c, &o, old.len() as u64);
        assert_eq!(r.st.read(&c, &o, 0, old.len() as u64).unwrap(), old);
        assert!(r.st.warm_data(&c, &o, 4096, 8192).unwrap());
        assert!(r.st.shards[0].hot_probe_pending());
        let lsn = r.st.shards[0].sh.next_lsn();
        let replacement = vec![0xa5; 512 << 10];
        let mut t = OTxn::new();
        t.write(c, &o, 0, &replacement);
        assert_eq!(
            r.st.queue(&t, 9199).unwrap(),
            store::obj::Queued::Pending(9199)
        );
        assert_eq!(r.st.shards[0].sh.next_lsn(), lsn);
        let parts = if verified {
            r.st.read_shared_verified(&c, &o, 4096, 8192).unwrap().parts
        } else {
            r.st.read_shared(&c, &o, 4096, 8192).unwrap()
        };
        let got: Vec<u8> = parts.iter().flat_map(|p| p.0.iter().copied()).collect();
        assert_eq!(got, replacement[4096..12288], "verified={verified}");
    }
}

#[test]
fn probe_hand_over_serves_only_its_own_read_on_an_unchanged_shard() {
    // the probe of a read that finds its range cached leaves the resolved extents for the read right after it
    // (single use, valid until the shard submits a txn): same bytes as a read without the hand-over; a write, a remove,
    // another object or other arguments in between never see the old extents
    let (mut r, _) = rig_with(64, 1, 1024, 5, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let big: Vec<u8> = (0..(256 << 10)).map(|i| (i * 13 % 251) as u8).collect();
    let (o, p) = (g(b"hand-a", 1), g(b"hand-b", 2));
    let mut t = OTxn::new();
    for x in [&o, &p] {
        t.write(c, x, 0, &big);
        t.setattr(c, x, b"_", b"oi");
    }
    commit(&mut r.st, &t);
    r.clean_remount();
    let cat = |v: &[(bytes::Bytes, Option<u32>)]| -> Vec<u8> {
        v.iter().flat_map(|p| p.0.iter().copied()).collect()
    };
    for x in [&o, &p] {
        warm_all(&mut r, &c, x, big.len() as u64);
        assert_eq!(r.st.read(&c, x, 0, big.len() as u64).unwrap(), big);
    }
    // 1. probe + read: the bytes, by reference, no device read
    let ios = r.st.shards[0].stats.read_ios;
    assert!(r.st.warm_data(&c, &o, 4096, 8192).unwrap());
    assert!(
        r.st.shards[0].hot_probe_pending(),
        "no hand-over of a cached range"
    );
    let a = r.st.read_shared(&c, &o, 4096, 8192).unwrap();
    assert!(
        !r.st.shards[0].hot_probe_pending(),
        "hand-over not single use"
    );
    assert_eq!(cat(&a), &big[4096..12288]);
    assert_eq!(r.st.shards[0].stats.read_ios, ios);
    // 2. other arguments / another object: the probe's pieces are not used
    assert!(r.st.warm_data(&c, &o, 4096, 8192).unwrap());
    assert_eq!(
        cat(&r.st.read_shared(&c, &o, 8192, 4096).unwrap()),
        &big[8192..12288]
    );
    assert!(r.st.warm_data(&c, &o, 4096, 8192).unwrap());
    assert_eq!(
        cat(&r.st.read_shared(&c, &p, 4096, 8192).unwrap()),
        &big[4096..12288]
    );
    // 3. a write between probe and read: the new bytes win
    assert!(r.st.warm_data(&c, &o, 4096, 8192).unwrap());
    let d = vec![0xa5u8; 8192];
    let mut t = OTxn::new();
    t.write(c, &o, 4096, &d);
    commit(&mut r.st, &t);
    assert_eq!(cat(&r.st.read_shared(&c, &o, 4096, 8192).unwrap()), d);
    // 4. a remove between probe and read: the object is gone
    assert!(r.st.warm_data(&c, &p, 4096, 8192).unwrap());
    let mut t = OTxn::new();
    t.remove(c, &p);
    commit(&mut r.st, &t);
    assert!(matches!(
        r.st.read_shared(&c, &p, 4096, 8192),
        Err(ObjError::NoEnt)
    ));
}

#[test]
fn cached_runs_never_serve_old_bytes_after_overwrite_and_never_block_admission() {
    // differential: cached run of the old blocks, then an overwrite: reads see the new bytes (new blocks, the freed
    // ones left the cache at the submit); cached runs give way when a new prefetch needs the table room. A tree budget of
    // 256 pages lends the data cache at most 2 MiB beyond its 32 MiB floor (adr 0633-data-cache-envelope)
    let mut cfg = StoreCfg::default();
    cfg.shard.cache_pages = 256;
    let (mut r, _) = rig_with(128, 1, 1024, 5, cfg);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let len = 4u64 << 20;
    let objs: Vec<Ghobject> = (0..10u8).map(|i| g(&[b'r', b'0' + i], 1)).collect();
    for (i, o) in objs.iter().enumerate() {
        let d = vec![i as u8; len as usize];
        let mut t = OTxn::new();
        t.write(c, o, 0, &d);
        t.setattr(c, o, b"_", b"oi");
        commit(&mut r.st, &t);
    }
    r.clean_remount();
    // fill the cache (8 x 4 MiB = the whole 32 MiB cap shared with the prefetch table)
    for (i, o) in objs[..8].iter().enumerate() {
        warm_all(&mut r, &c, o, len);
        assert_eq!(
            r.st.read(&c, o, 0, len).unwrap(),
            vec![i as u8; len as usize]
        );
    }
    assert!(
        r.st.shards[0].data_cache_usage().1 >= 7 * 1024,
        "runs not cached"
    );
    // a new op is admitted at once (cached runs evicted), not denied
    let mut acked = vec![];
    for (i, o) in objs[8..].iter().enumerate() {
        warm_all(&mut r, &c, o, len);
        assert_eq!(
            r.st.read(&c, o, 0, len).unwrap(),
            vec![(8 + i) as u8; len as usize]
        );
    }
    assert_eq!(r.st.shards[0].pf_waiters(), 0);
    // overwrite a cached object's middle: the new bytes win
    warm_all(&mut r, &c, &objs[9], len);
    let d = vec![0xee; 8192];
    let mut t = OTxn::new();
    t.write(c, &objs[9], 4096, &d);
    commit(&mut r.st, &t);
    r.st.poll(&mut acked).unwrap();
    let got = r.st.read(&c, &objs[9], 0, 16384).unwrap();
    assert_eq!(&got[..4096], &[9u8; 4096][..]);
    assert_eq!(&got[4096..12288], &[0xee; 8192][..]);
    assert_eq!(&got[12288..], &[9u8; 4096][..]);
}

/// The data cache grows beyond its floor into the tree page budget the tree has not allocated (adr 0633-data-cache-envelope): a
/// working set twice the floor is read once and then served from memory, no device read; with a small tree budget the
/// capacity stays at the floor.
#[test]
fn data_cache_capacity_follows_the_unused_tree_budget() {
    let floor = DATA_FLOOR_BYTES / 4096;
    for (pages, fits) in [(16384usize, true), (256, false)] {
        let mut cfg = StoreCfg::default();
        cfg.shard.cache_pages = pages;
        let (mut r, _) = rig_with(256, 1, 1024, 7, cfg);
        let c = c1();
        let mut t = OTxn::new();
        t.mkcoll(c);
        commit(&mut r.st, &t);
        let len = 4u64 << 20;
        let objs: Vec<Ghobject> = (0..16u8).map(|i| g(&[b'w', b'a' + i], 1)).collect();
        for (i, o) in objs.iter().enumerate() {
            let d = vec![i as u8; len as usize];
            let mut t = OTxn::new();
            t.write(c, o, 0, &d);
            t.setattr(c, o, b"_", b"oi");
            commit(&mut r.st, &t);
        }
        r.clean_remount();
        let cap = r.st.shards[0].dc_cap();
        assert_eq!(
            cap > floor + 16 * 1024,
            fits,
            "cap {cap} blocks, tree budget {pages} pages"
        );
        for pass in 0..2 {
            let ios = r.st.shards[0].stats.read_ios;
            for (i, o) in objs.iter().enumerate() {
                warm_all(&mut r, &c, o, len);
                assert_eq!(
                    r.st.read(&c, o, 0, len).unwrap(),
                    vec![i as u8; len as usize]
                );
                assert!(r.st.shards[0].data_cache_usage().1 <= r.st.shards[0].dc_cap());
            }
            let dev_reads = r.st.shards[0].stats.read_ios - ios;
            if pass == 1 {
                // the second pass: all from memory when the set fits, else the floor cache cycles (no hits on a
                // set twice its size)
                assert_eq!(dev_reads == 0, fits, "pass 2 device reads {dev_reads}");
            }
        }
        if fits {
            assert_eq!(r.st.shards[0].data_cache_usage().1, 16 * 1024);
        }
    }
}

/// WAL group commit (adr 0021 am. 37) under the pipelined object crash workload (model fingerprints, fsck, every
/// acked txn): on (1) and the kill switch (0), plain and storm txns.
#[test]
fn crash_matrix_objects_wal_coalesce() {
    let pols = [
        CrashPolicy::DROP_ALL,
        CrashPolicy::PERSIST_ALL,
        CrashPolicy::MIXED,
    ];
    for k in [1usize, 0] {
        COALESCE.set(k);
        let (n, c) = crash_matrix(22, 61, &pols, 600, 1);
        assert!(
            n > 100 && c * 2 > n,
            "coalesce {k}: scenarios {n}, crashed {c}"
        );
        STORM.set(30);
        crash_matrix(14, 62, &pols, 400, 2);
        STORM.set(0);
    }
    COALESCE.set(usize::MAX);
}

/// Sliced checkpoint start (adr 0021 am. 40) under the pipelined object crash workload: one leaf delta built ahead per
/// poll (checkpoint starts spread over many polls while txns are applied and crashes hit) and the kill switch.
#[test]
fn crash_matrix_objects_ckpt_slice() {
    let pols = [
        CrashPolicy::DROP_ALL,
        CrashPolicy::PERSIST_ALL,
        CrashPolicy::MIXED,
    ];
    for s in [1usize, 0] {
        SLICE.set(s);
        let (n, c) = crash_matrix(22, 63, &pols, 600, 1);
        assert!(
            n > 100 && c * 2 > n,
            "slice {s}: scenarios {n}, crashed {c}"
        );
        STORM.set(30);
        crash_matrix(14, 64, &pols, 400, 2);
        STORM.set(0);
    }
    SLICE.set(usize::MAX);
}

/// Sliced checkpoint start (adr 0021 am. 40): the shards of a `Store` (= one core) share one checkpoint budget per poll,
/// so at most one checkpoint starts per `Store::poll` even when all of them want one at once; the kill switch starts them
/// together. Deltas built ahead are used.
#[test]
fn one_checkpoint_start_per_store_poll() {
    for slice in [4usize, 0] {
        let mut cfg = StoreCfg::default();
        cfg.shard.ckpt_slice = slice;
        let (mut r, _) = rig_ns(64, 4, 1024, 7, cfg, 8192);
        let colls: Vec<CollT> = (0..16).map(|i| pgc(1, i)).collect();
        let d: Vec<Vec<u8>> = (0..200).map(|i| vec![i as u8; 4096]).collect();
        let a: Vec<Vec<u8>> = (0..16).map(|k| vec![k as u8; 40]).collect();
        for c in &colls {
            let mut t = OTxn::new();
            t.mkcoll(*c);
            commit(&mut r.st, &t);
        }
        for c in &colls {
            let mut t = OTxn::new();
            for i in 0..200u32 {
                t.write(*c, &g(format!("o{i}").as_bytes(), i), 0, &d[i as usize]);
            }
            commit(&mut r.st, &t);
        }
        r.st.checkpoint().unwrap();
        // small updates all over: every shard has deltas to build
        for (k, c) in colls.iter().enumerate() {
            for i in (0..200u32).step_by(23) {
                let mut t = OTxn::new();
                t.setattr(*c, &g(format!("o{i}").as_bytes(), i), b"a", &a[k]);
                commit(&mut r.st, &t);
            }
        }
        let starts =
            |r: &Rig| -> Vec<u64> { r.st.shards.iter().map(|s| s.sh.stats.ckpt_begins).collect() };
        for s in r.st.shards.iter_mut() {
            s.sh.request_checkpoint();
        }
        let (mut most, mut started) = (0, 0);
        let mut acked = vec![];
        for _ in 0..100_000 {
            let before = starts(&r);
            r.st.poll(&mut acked).unwrap();
            let n = starts(&r)
                .iter()
                .zip(&before)
                .filter(|(a, b)| a != b)
                .count();
            most = most.max(n);
            started += n;
            if started == 4 {
                break;
            }
            r.st.idle();
        }
        assert_eq!(started, 4, "slice {slice}: every shard checkpointed");
        // freezes spread over more than one slice
        let hits: u64 =
            r.st.shards
                .iter()
                .map(|s| s.sh.stats.ckpt_slices - s.sh.stats.ckpt_begins)
                .sum();
        if slice > 0 {
            assert_eq!(most, 1, "slice {slice}: checkpoint starts in one poll");
            assert!(hits > 4, "freezes in slices: {hits}");
        } else {
            assert!(most > 1, "kill switch: all start in the same poll ({most})");
            assert_eq!(hits, 0);
        }
        r.st.sync().unwrap();
        r.clean_remount();
        for (k, c) in colls.iter().enumerate() {
            for i in (0..200u32).step_by(23) {
                let o = g(format!("o{i}").as_bytes(), i);
                assert_eq!(r.st.getattr(c, &o, b"a").unwrap(), Some(vec![k as u8; 40]));
            }
        }
    }
}

/// Sliced freeze (adr 0021 am. 42): an interior page re-dirtied while pending (`F_AGAIN`) and then written whole (a child
/// moved) must give back the taken copy's dirty count. The leak grew `dirty_pages` by one per such page and checkpoint:
/// back-to-back checkpoints once above `dirty_soft`, then `Busy` at `dirty_hard` (rbd 4K write degraded over minutes,
/// reset by a restart). After a quiet checkpoint nothing is dirty.
#[test]
fn sliced_freeze_dirty_count_returns_to_zero() {
    for slice in [1usize, 3, 0] {
        let mut cfg = StoreCfg::default();
        cfg.shard.ckpt_slice = slice;
        cfg.shard.dirty_soft_pages = 4;
        cfg.shard.ckpt_interval_ns = 20_000;
        let (mut r, _) = rig_ns(64, 1, 1024, 11, cfg, 4096);
        let c = pgc(1, 0);
        let mut t = OTxn::new();
        t.mkcoll(c);
        commit(&mut r.st, &t);
        let d = vec![7u8; 4096];
        let big = vec![9u8; 900];
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for i in 0..3000u32 {
            let mut t = OTxn::new();
            // new objects split leaves (whole-page rewrites: parents see moved children), attrs on old ones re-dirty
            // the paths of pending pages
            t.write(c, &g(format!("n{i:05}").as_bytes(), i), 0, &d);
            let j = (next() % (i as u64 + 1)) as u32;
            let v: &[u8] = if next() % 4 == 0 { &big } else { &big[..16] };
            t.setattr(c, &g(format!("n{j:05}").as_bytes(), j), b"a", v);
            commit(&mut r.st, &t);
        }
        let begins = r.st.shards[0].sh.stats.ckpt_begins;
        let slices = r.st.shards[0].sh.stats.ckpt_slices;
        assert!(begins > 20, "slice {slice}: {begins} checkpoints");
        if slice > 0 {
            assert!(slices > begins, "slice {slice}: freezes in slices");
        }
        r.st.checkpoint().unwrap();
        r.st.checkpoint().unwrap();
        let dirty = r.st.shards[0].sh.state().tree.dirty_pages();
        assert_eq!(
            dirty, 0,
            "slice {slice}: dirty pages after a quiet checkpoint"
        );
        r.clean_remount();
    }
}

/// adr 0021 am. 62: a txn refused for dirty pages (`dirty_hard`) is retried on every store progress; the refusal comes
/// before the record encoding and the path probes of `validate`, so the retries redo none of that work (a 1024-key omap
/// batch: 330 KB encoded + 1024 probes per checkpoint page completion, 58 % of the core in a big-omap populate). Every
/// prepare ends in a commit or a refusal after the prepare; dirty-hard refusals add none.
#[test]
fn dirty_hard_refusal_skips_prepare() {
    let mut cfg = StoreCfg::default();
    cfg.shard.dirty_soft_pages = 8;
    cfg.shard.dirty_hard_pages = 24;
    cfg.shard.ckpt_slice = 2;
    let (mut r, _) = rig_ns(256, 1, 4096, 13, cfg, 8192);
    let (c, o) = (pgc(1, 0), g(b"big-omap", 5));
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.touch(c, &o);
    commit(&mut r.st, &t);
    let mut rng = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..40 {
        let mut t = OTxn::new();
        for _ in 0..256 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            oset(
                &mut t,
                c,
                &o,
                format!("{rng:016x}").into_bytes(),
                vec![(rng >> 8) as u8; 256],
            );
        }
        commit(&mut r.st, &t);
    }
    let s = r.st.shards[0].sh.stats;
    assert!(s.busy[2] > 0, "the fill must hit dirty_hard: {:?}", s.busy);
    let later: u64 = s.busy.iter().sum::<u64>() - s.busy[2];
    assert!(
        s.prepares <= s.txns + later,
        "prepares {} > txns {} + refusals after prepare {later} (dirty-hard refusals {})",
        s.prepares,
        s.txns,
        s.busy[2]
    );
    r.clean_remount();
}

// ---------------------------------------------------------------------------------------------- values in data blocks

/// adr 0021 am. 46: omap / xattr / header values of at least `val_ext_min` bytes live in data blocks. Every form change
/// (ext <-> inline / fragments, same-txn overwrite, removal by key / range / clear / rmattrs / object remove, clone) keeps
/// the content and frees exactly the blocks it no longer references (fsck at every remount: no leaked or doubly owned
/// block; data blocks back to the baseline at the end).
#[test]
fn ext_values_lifecycle_frees_every_block() {
    let mut r = rig_nvc(64, 1);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.st.commit(&t).unwrap();
    r.clean_remount();
    let si = r.st.shard_of(&c);
    let used = |r: &Rig| r.st.shards[si].sh.state().alloc.n_alloc();
    let base = used(&r);
    let v = |n: usize, b: u8| (0..n).map(|i| b ^ (i as u8)).collect::<Vec<u8>>();
    let (a, b) = (g(b"ev-a", 1), g(b"ev-b", 2));
    let sizes = [2047usize, 2048, 4096, 4097, 9000, 65536, 65537];
    // put every size in omap, xattr and header; one txn also overwrites its own staged value
    let mut t = OTxn::new();
    let vals: Vec<Vec<u8>> = sizes.iter().map(|&n| v(n, 1)).collect();
    let keys: Vec<Vec<u8>> = sizes.iter().map(|n| format!("k{n}").into_bytes()).collect();
    let hdr = v(5000, 9);
    let early = v(3000, 7);
    t.touch(c, &a);
    t.omap_set(c, &a, b"same", &early);
    for (k, val) in keys.iter().zip(&vals) {
        t.omap_set(c, &a, k, val);
        t.setattr(c, &a, k, val);
    }
    let same = v(6000, 8);
    t.omap_set(c, &a, b"same", &same);
    t.push(store::obj::TOp::OmapSetHeader {
        cid: c,
        oid: a.clone(),
        header: hdr.as_slice().into(),
    });
    r.st.commit(&t).unwrap();
    assert!(
        r.st.shards[si].stats.ext_values >= 8,
        "{}",
        r.st.shards[si].stats.ext_values
    );
    let check = |r: &mut Rig, o: &Ghobject| {
        for (k, val) in keys.iter().zip(&vals) {
            assert_eq!(
                r.st.omap_get(&c, o, &[k.as_slice()])
                    .unwrap()
                    .into_values()
                    .next()
                    .unwrap(),
                *val
            );
            assert_eq!(r.st.getattr(&c, o, k).unwrap().as_ref(), Some(val));
        }
    };
    check(&mut r, &a);
    assert_eq!(r.st.omap_header(&c, &a).unwrap(), hdr);
    r.clean_remount();
    check(&mut r, &a);
    let grown = used(&r);
    assert!(grown > base + 30, "values not in blocks: {base} -> {grown}");
    // clone copies every value (own blocks), then form changes on the source
    let mut t = OTxn::new();
    t.push(store::obj::TOp::Clone {
        cid: c,
        src: a.clone(),
        dst: b.clone(),
    });
    r.st.commit(&t).unwrap();
    r.clean_remount();
    check(&mut r, &b);
    let huge = v(70_000, 3);
    let mut t = OTxn::new();
    t.omap_set(c, &a, &keys[2], b"small");
    t.setattr(c, &a, &keys[2], &huge);
    t.push(store::obj::TOp::OmapRmKeys {
        cid: c,
        oid: a.clone(),
        keys: vec![keys[3].as_slice().into()],
    });
    t.push(store::obj::TOp::OmapRmKeyRange {
        cid: c,
        oid: a.clone(),
        first: keys[4].as_slice().into(),
        last: keys[6].as_slice().into(),
    });
    r.st.commit(&t).unwrap();
    assert_eq!(
        r.st.omap_get(&c, &a, &[keys[2].as_slice()])
            .unwrap()
            .into_values()
            .next()
            .unwrap(),
        b"small".to_vec()
    );
    assert!(
        r.st.omap_get(&c, &a, &[keys[3].as_slice()])
            .unwrap()
            .is_empty()
    );
    assert_eq!(r.st.getattr(&c, &a, &keys[2]).unwrap(), Some(v(70_000, 3)));
    r.clean_remount();
    check(&mut r, &b);
    // clear omap + header, drop all attrs, remove the clone
    let mut t = OTxn::new();
    t.push(store::obj::TOp::OmapClear {
        cid: c,
        oid: a.clone(),
    });
    t.push(store::obj::TOp::RmAttrs {
        cid: c,
        oid: a.clone(),
    });
    t.remove(c, &b);
    r.st.commit(&t).unwrap();
    r.clean_remount();
    let mut t = OTxn::new();
    t.remove(c, &a);
    r.st.commit(&t).unwrap();
    r.clean_remount();
    r.st.checkpoint().unwrap();
    r.st.checkpoint().unwrap();
    assert_eq!(used(&r), base, "blocks leaked");
    check_no_leaks(&mut r);
}

/// Deep fsck must read external metadata blocks, including the padded last block,
/// even after getters have warmed the data cache.
#[test]
fn deep_check_detects_corrupt_external_metadata_values() {
    use store::obj::onode::vext;
    for tag in [T_ATTR, T_OMAP, T_HDR] {
        for block in [0, 1] {
            let mut r = rig_nvc(32, 1);
            let (c, o) = (c1(), g(b"metadata-bitrot", 1));
            let val = vec![0x53; 5000];
            let mut t = OTxn::new();
            t.mkcoll(c);
            t.touch(c, &o);
            t.setattr(c, &o, b"a", &val);
            t.omap_set(c, &o, b"k", &val);
            t.push(TOp::OmapSetHeader {
                cid: c,
                oid: o.clone(),
                header: val.as_slice().into(),
            });
            commit(&mut r.st, &t);
            r.clean_remount();
            assert_eq!(r.st.getattr(&c, &o, b"a").unwrap(), Some(val.clone()));
            assert_eq!(r.st.omap_header(&c, &o).unwrap(), val);
            assert_eq!(
                r.st.omap_get(&c, &o, &[b"k"]).unwrap()[b"k".as_slice()],
                val
            );
            assert!(r.st.check(true).unwrap().errors.is_empty());
            let kv = r.st.shards[0].sh.dump_blocking(&mut r.st.clk).unwrap();
            let (_, raw) = kv.iter().find(|(k, _)| k[0] == tag).unwrap();
            let (_, e) = vext(raw).expect("test value must live in data blocks");
            // For block 1 this hits padding beyond the 5000 user bytes.
            r.disk.corrupt(e.pba() + block, 1000, 0x40);
            assert!(r.st.check(false).unwrap().errors.is_empty());
            let rep = r.st.check(true).unwrap();
            assert_eq!(
                rep.errors.len(),
                1,
                "tag {tag:#x} block {block}: {:?}",
                rep.errors
            );
            assert!(
                rep.errors[0].contains("value checksum mismatch"),
                "{:?}",
                rep.errors
            );
        }
    }
}

/// With `val_ext_min` 0 (or a store without `FEAT_EXT_VALUE`) values stay in the tree; a store with ext values written
/// before reads them after the setting is turned off and frees them on removal.
#[test]
fn ext_values_setting_off_keeps_reading_and_freeing() {
    let mut r = rig(64, 1);
    let c = c1();
    let o = g(b"ev-off", 1);
    let big = vec![5u8; 8000];
    let mut t = OTxn::new();
    t.mkcoll(c).touch(c, &o).omap_set(c, &o, b"x", &big);
    r.st.commit(&t).unwrap();
    r.cfg.shard.val_ext_min = 0;
    r.clean_remount();
    assert_eq!(
        r.st.omap_get(&c, &o, &[b"x".as_slice()])
            .unwrap()
            .into_values()
            .next()
            .unwrap(),
        big
    );
    let mut t = OTxn::new();
    t.omap_set(c, &o, b"y", &big);
    r.st.commit(&t).unwrap();
    assert_eq!(r.st.shards[0].stats.ext_values, 0);
    let mut t = OTxn::new();
    t.remove(c, &o);
    r.st.commit(&t).unwrap();
    r.clean_remount();
    check_no_leaks(&mut r);
}

/// Random model workload with many omap / xattr values for data blocks (adr 0021 am. 46): same results as the model, with
/// the setting on and off, at 4 / 8 KiB pages and 1 / 4 shards; every remount fscks (blocks owned exactly once).
#[test]
fn model_ext_values() {
    BIGVAL_PCT.set(40);
    EXT_SEEN.set(0);
    for seed in 50..=53u64 {
        let nodes = if seed % 2 == 0 { 8192 } else { 4096 };
        run_model_cfg(
            seed,
            if seed < 52 { 1 } else { 4 },
            220,
            60,
            StoreCfg::default(),
            nodes,
            0,
        );
    }
    assert!(EXT_SEEN.get() > 200, "ext values {}", EXT_SEEN.get());
    for seed in 50..=51u64 {
        let mut cfg = StoreCfg::default();
        cfg.shard.val_ext_min = 0;
        run_model_cfg(seed, 1, 220, 60, cfg, 8192, 0);
    }
    BIGVAL_PCT.set(0);
}

/// Crash at every IO boundary of a workload rich in data-block values (adr 0021 am. 46) x 3 policies, 2 generations: the
/// recovered store equals a model prefix, value blocks are covered by the WAL record's data crcs like object data.
#[test]
fn crash_matrix_objects_ext_values() {
    BIGVAL_PCT.set(50);
    EXT_SEEN.set(0);
    let (n, c) = crash_matrix(
        30,
        150,
        &[
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ],
        600,
        1,
    );
    assert!(n > 100 && c * 2 > n, "scenarios {n}, crashed {c}");
    assert!(EXT_SEEN.get() > 10, "ext values {}", EXT_SEEN.get());
    BIGVAL_PCT.set(0);
}

#[test]
#[ignore = "soak"]
fn crash_matrix_objects_ext_values_soak() {
    BIGVAL_PCT.set(50);
    let mut tot = 0;
    for gs in 300..340 {
        tot += crash_matrix(
            16,
            gs,
            &[
                CrashPolicy::MIXED,
                CrashPolicy::DROP_ALL,
                CrashPolicy::PERSIST_ALL,
            ],
            1000,
            1,
        )
        .0;
    }
    println!("scenarios {tot}");
    BIGVAL_PCT.set(0);
}

#[test]
#[ignore = "soak"]
fn model_ext_values_soak() {
    BIGVAL_PCT.set(50);
    for seed in 400..440u64 {
        let nodes = if seed % 2 == 0 { 8192 } else { 4096 };
        run_model_cfg(
            seed,
            if seed % 3 == 0 { 4 } else { 1 },
            260,
            70,
            StoreCfg::default(),
            nodes,
            0,
        );
    }
    BIGVAL_PCT.set(0);
}

#[test]
fn wake_tokens_name_every_page_and_prefetch_run_a_probe_waits_for() {
    // adr 0043 am. 9: a probe that finds the store cold names what it waits for; a probe the wake batch (page loads,
    // prefetch completions) does not name must still be not ready (no lost wake-up), a named one may become ready.
    use store::toks::Toks;
    let (mut r, _) = rig_with(64, 1, 4096, 31, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let objs: Vec<Ghobject> = (0..24u32)
        .map(|i| g(format!("tok{i}").as_bytes(), i + 100))
        .collect();
    for o in &objs {
        let mut t = OTxn::new();
        t.write(c, o, 0, &[7u8; 12288]);
        t.setattr(c, o, b"_", b"oi");
        commit(&mut r.st, &t);
    }
    r.clean_remount();
    let probe = |r: &mut Rig, o: &Ghobject| -> (bool, Toks<8>) {
        r.st.cause_begin();
        let ready = r.st.warm(&c, o, 0, 12288).unwrap() && r.st.warm_data(&c, o, 0, 12288).unwrap();
        let mut cause = Toks::<8>::new();
        r.st.cause_take(&mut cause);
        (ready, cause)
    };
    let mut blocked: Vec<Option<Toks<8>>> = Vec::new();
    for o in &objs {
        let (ready, cause) = probe(&mut r, o);
        assert!(!ready, "cold after remount");
        assert!(!cause.is_empty(), "a cold probe names its cause");
        blocked.push(Some(cause));
    }
    let (mut named_wakes, mut spins) = (0, 0);
    while blocked.iter().any(Option::is_some) {
        spins += 1;
        assert!(spins < 200_000, "probes never completed");
        let mut acked = vec![];
        r.st.poll(&mut acked).unwrap();
        let mut toks = Toks::<32>::new();
        let mut all = false;
        if !r.st.take_wake_set(&mut toks, &mut all) {
            r.st.idle();
            continue;
        }
        named_wakes += usize::from(!all);
        for (i, o) in objs.iter().enumerate() {
            let Some(cause) = blocked[i] else { continue };
            let hit = all
                || cause.overflowed()
                || cause.is_empty()
                || cause.as_slice().iter().any(|t| toks.as_slice().contains(t));
            if !hit {
                // not named: still not ready, else its wake-up was lost
                let (ready, c2) = probe(&mut r, o);
                assert!(!ready, "object {i} became ready without a wake naming it");
                blocked[i] = Some(c2);
                continue;
            }
            let (ready, c2) = probe(&mut r, o);
            blocked[i] = if ready { None } else { Some(c2) };
        }
    }
    assert!(named_wakes > 0, "every wake was an unnamed one");
}

// ---------------------------------------------------------------------------------------------- shared reads

/// Pieces of a shared read: the concatenation, and every known piece crc checked against the bytes.
fn flat_checked(pieces: &[(bytes::Bytes, Option<u32>)]) -> Vec<u8> {
    for (b, c) in pieces {
        if let Some(c) = c {
            assert_eq!(
                *c,
                crc::crc32c(!0, b),
                "piece crc hint of {} bytes",
                b.len()
            );
        }
    }
    pieces.iter().flat_map(|(b, _)| b.iter().copied()).collect()
}

/// An object of `len` patterned bytes written in one go (one extent; the sim device reads 64 blocks per command).
fn shared_rig(name: &[u8], len: usize) -> (Rig, CollT, Ghobject, Vec<u8>) {
    let (mut r, _) = rig_with(64, 1, 1024, 7, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let o = g(name, 4);
    let data: Vec<u8> = (0..len as u32).map(|i| (i * 31 + 7) as u8).collect();
    let mut t = OTxn::new();
    t.write(c, &o, 0, &data);
    t.setattr(c, &o, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    (r, c, o, data)
}

/// The shared read returns the same bytes as the copying read for every range, and piece crcs that are the crcs of the
/// pieces: device buffers of a synchronous read go by reference (one piece per command), small layouts read as before.
#[test]
fn shared_read_matches_the_copying_read() {
    let (mut r, c, o, data) = shared_rig(b"sh", 1 << 20);
    for (off, len) in [
        (0u64, 1u64 << 20),
        (4096, 8192),
        (100, 5000),
        (5000, 700_000),
        (0, 2 << 20),
        ((1 << 20) - 10, 100),
    ] {
        let (d0, _) = r.st.read_crc(&c, &o, off, len).unwrap();
        let p = r.st.read_shared(&c, &o, off, len).unwrap();
        assert_eq!(flat_checked(&p), d0, "off {off} len {len}");
    }
    // a whole aligned read of a plain object: one piece per device command, every crc known
    let p = r.st.read_shared(&c, &o, 0, 1 << 20).unwrap();
    assert_eq!(p.len(), 4, "1 MiB in 256 KiB commands");
    assert!(p.iter().all(|(b, c)| b.len() == 256 << 10 && c.is_some()));
    assert_eq!(flat_checked(&p), data);
    assert!(
        r.st.read_shared(&c, &o, 1 << 20, 4096).unwrap().is_empty(),
        "past the end"
    );
    // a small object (pieces below the sharing size): one copied piece, crc as the copying read gives it
    let small = g(b"sh-small", 4);
    let mut t = OTxn::new();
    t.write(c, &small, 0, &data[..8192]);
    commit(&mut r.st, &t);
    let (d0, c0) = r.st.read_crc(&c, &small, 0, 8192).unwrap();
    let p = r.st.read_shared(&c, &small, 0, 8192).unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!((flat_checked(&p), p[0].1), (d0, c0));
}

/// Placement candidates reuse verified device block checksums, including
/// holes and a short EOF tail. The ordinary shared read remains unchanged.
#[test]
fn shared_read_verified_blocks_match_returned_bytes() {
    let len = (1usize << 20) - 100;
    let (mut r, c, o, data) = shared_rig(b"sh-verified", len);
    let read = r.st.read_shared_verified(&c, &o, 0, 2 << 20).unwrap();
    assert_eq!(flat_checked(&read.parts), data);
    let expected: Vec<u32> = data.chunks(4096).map(|b| crc::crc32c(0, b)).collect();
    assert_eq!(read.block_crcs.as_deref(), Some(expected.as_slice()));

    for (off, n) in [
        (4096u64, 256 << 10),
        (128 << 10, 700_000),
        (512 << 10, (128 << 10) + 13),
    ] {
        let read = r.st.read_shared_verified(&c, &o, off, n).unwrap();
        let bytes = &data[off as usize..(off as usize + n as usize).min(len)];
        assert_eq!(flat_checked(&read.parts), bytes);
        let expected: Vec<u32> = bytes.chunks(4096).map(|b| crc::crc32c(0, b)).collect();
        assert_eq!(read.block_crcs.as_deref(), Some(expected.as_slice()));
    }

    for off in [1, 17, 2048, 2049, 4095] {
        let before = r.st.comp_counters();
        let read = r.st.read_shared_verified(&c, &o, off, 321_017).unwrap();
        let bytes = &data[off as usize..off as usize + 321_017];
        assert_eq!(flat_checked(&read.parts), bytes);
        let expected: Vec<u32> = bytes.chunks(4096).map(|b| crc::crc32c(0, b)).collect();
        assert_eq!(
            read.block_crcs.as_deref(),
            Some(expected.as_slice()),
            "shifted receipt grid at offset {off}"
        );
        let after = r.st.comp_counters();
        assert_eq!(
            after.placement_crc_reblocked_bytes - before.placement_crc_reblocked_bytes,
            321_017
        );
        let bound = (321_017 / 4096 + 1) * off.min(4096 - off) + 321_017 % 4096;
        assert!(after.placement_crc_hashed_bytes - before.placement_crc_hashed_bytes <= bound);
    }
    let before = r.st.comp_counters();
    let ordinary = r.st.read_shared(&c, &o, 17, 321_017).unwrap();
    assert_eq!(flat_checked(&ordinary), data[17..17 + 321_017]);
    let after = r.st.comp_counters();
    assert_eq!(
        after.placement_crc_reblocked_bytes,
        before.placement_crc_reblocked_bytes
    );
    assert_eq!(
        after.placement_crc_hashed_bytes,
        before.placement_crc_hashed_bytes
    );
    let eof = r.st.read_shared_verified(&c, &o, len as u64, 4096).unwrap();
    assert!(eof.parts.is_empty());
    assert_eq!(eof.block_crcs, Some(Vec::new()));

    let small = g(b"sh-verified-small", 4);
    let mut t = OTxn::new();
    t.write(c, &small, 0, &data[..8192]);
    commit(&mut r.st, &t);
    let read = r.st.read_shared_verified(&c, &small, 0, 8192).unwrap();
    assert_eq!(flat_checked(&read.parts), data[..8192]);
    assert!(
        read.block_crcs.is_none(),
        "small source uses ordinary read path"
    );

    let h = g(b"sh-verified-hole", 4);
    let mut t = OTxn::new();
    t.write(c, &h, 0, &data[..256 << 10]);
    t.write(c, &h, 512 << 10, &data[..256 << 10]);
    t.setattr(c, &h, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    let mut expected_bytes = vec![0u8; 768 << 10];
    expected_bytes[..256 << 10].copy_from_slice(&data[..256 << 10]);
    expected_bytes[512 << 10..].copy_from_slice(&data[..256 << 10]);
    let read =
        r.st.read_shared_verified(&c, &h, 0, expected_bytes.len() as u64)
            .unwrap();
    assert_eq!(flat_checked(&read.parts), expected_bytes);
    let expected: Vec<u32> = expected_bytes
        .chunks(4096)
        .map(|b| crc::crc32c(0, b))
        .collect();
    assert_eq!(read.block_crcs.as_deref(), Some(expected.as_slice()));
    for off in [17, 4095] {
        let read = r.st.read_shared_verified(&c, &h, off, 700_001).unwrap();
        let bytes = &expected_bytes[off as usize..off as usize + 700_001];
        assert_eq!(flat_checked(&read.parts), bytes);
        let expected: Vec<_> = bytes.chunks(4096).map(|b| crc::crc32c(0, b)).collect();
        assert_eq!(read.block_crcs.as_deref(), Some(expected.as_slice()));
    }
    let before = r.st.comp_counters();
    let zeros =
        r.st.read_shared_verified(&c, &h, (300 << 10) + 17, 128 << 10)
            .unwrap();
    assert_eq!(flat_checked(&zeros.parts), vec![0; 128 << 10]);
    assert!(
        zeros
            .block_crcs
            .as_ref()
            .unwrap()
            .iter()
            .all(|&crc| crc == 0)
    );
    let after = r.st.comp_counters();
    assert_eq!(
        after.placement_crc_reblocked_bytes - before.placement_crc_reblocked_bytes,
        128 << 10
    );
    assert_eq!(
        after.placement_crc_hashed_bytes,
        before.placement_crc_hashed_bytes
    );
    let ordinary =
        r.st.read_shared(&c, &h, (300 << 10) + 17, 128 << 10)
            .unwrap();
    assert_eq!(flat_checked(&ordinary), vec![0; 128 << 10]);
    assert_eq!(
        r.st.comp_counters().placement_crc_hashed_bytes,
        after.placement_crc_hashed_bytes
    );
}

/// A known all-hole range has no device data that can race an unacked write
/// elsewhere in the object. Sharing it must preserve the ordinary zero-read
/// path's readiness rather than introduce an object-wide durability wait.
#[test]
fn shared_sparse_read_does_not_wait_for_disjoint_pending_data() {
    for verified in [false, true] {
        let (mut r, _) = rig_with(64, 1, 1024, 21, StoreCfg::default());
        let c = c1();
        let o = g(b"sparse-pending", 3);
        let mut t = OTxn::new();
        t.mkcoll(c);
        t.write(c, &o, 0, &[1; 64 << 10]);
        t.truncate(c, &o, 1 << 20);
        t.setattr(c, &o, b"_", b"oi");
        commit(&mut r.st, &t);
        let mut t = OTxn::new();
        t.write(c, &o, 4096, &[9; 4096]);
        r.st.queue(&t, 77).unwrap();
        assert!(r.st.warm_data(&c, &o, (128 << 10) + 17, 128 << 10).unwrap());
        assert!(
            !r.st.warm_data(&c, &o, 4096, 4096).unwrap(),
            "data write is still pending"
        );
        let waits = r.st.shards[0].stats.durable_waits;
        let parts = if verified {
            r.st.read_shared_verified(&c, &o, (128 << 10) + 17, 128 << 10)
                .unwrap()
                .parts
        } else {
            r.st.read_shared(&c, &o, (128 << 10) + 17, 128 << 10)
                .unwrap()
        };
        assert_eq!(flat_checked(&parts), vec![0; 128 << 10]);
        assert_eq!(
            r.st.shards[0].stats.durable_waits, waits,
            "an all-hole range waited for unrelated physical data, verified={verified}"
        );
    }
}

/// A shared read cut inside blocks (unaligned start, length, size-clamped tail) keeps a crc on every piece, the crc of
/// exactly the cut bytes (derived from the block crcs plus the partial blocks), also over holes.
#[test]
fn shared_read_cut_pieces_keep_their_crc() {
    // size 1 MiB - 100: the last stored block is partial, a read to the end is clamped inside a block
    let len = (1usize << 20) - 100;
    let (mut r, c, o, data) = shared_rig(b"sh-cut", len);
    for (off, n) in [
        (0u64, len as u64),
        (1, 200_000),
        (100, 130_000),
        (4095, 262_144),
        (5000, 700_000),
        (262_144 - 7, 262_144 + 14),
        (3 * 262_144 + 1, 300_000),
        (len as u64 - 150_000, 150_000),
    ] {
        let p = r.st.read_shared(&c, &o, off, n).unwrap();
        let want = &data[off as usize..(off as usize + n as usize).min(len)];
        assert_eq!(flat_checked(&p), want, "off {off} len {n}");
        assert!(
            p.iter().all(|(_, c)| c.is_some()),
            "unknown piece crc, off {off} len {n}"
        );
    }
    // holes: extents at 0..256 KiB and 512 KiB..768 KiB, ranges cut inside the extents and the holes
    let h = g(b"sh-holes", 4);
    let mut t = OTxn::new();
    t.write(c, &h, 0, &data[..256 << 10]);
    t.write(c, &h, 512 << 10, &data[..256 << 10]);
    t.setattr(c, &h, b"_", b"oi");
    commit(&mut r.st, &t);
    r.clean_remount();
    let mut expect = vec![0u8; 768 << 10];
    expect[..256 << 10].copy_from_slice(&data[..256 << 10]);
    expect[512 << 10..].copy_from_slice(&data[..256 << 10]);
    for (off, n) in [
        (0usize, 768 << 10),
        (100, 700_000),
        (200_001, 400_000),
        (131_071, 300_000),
    ] {
        let p = r.st.read_shared(&c, &h, off as u64, n as u64).unwrap();
        assert_eq!(flat_checked(&p), expect[off..off + n], "off {off} len {n}");
        assert!(
            p.iter().all(|(_, c)| c.is_some()),
            "unknown piece crc, off {off} len {n}"
        );
    }
}

/// A partial shared read must retain a slice of the original ready prefetch
/// buffer, including before any whole read has promoted the run to the cache.
/// The verified (RDMA placement) read bypasses the prefetch table and the data
/// cache (`media`, its pieces must be registered device buffers): it reads the
/// device, carries the block crcs and leaves the prefetch entry to the others.
#[test]
fn shared_partial_prefetch_retains_original_backing_and_crc_ownership() {
    for verified in [false, true] {
        for offset in [4 * 4096usize, 4 * 4096 + 17] {
            let (mut r, c, o, data) = shared_rig(b"sh-pf-partial", 1 << 20);
            warm_all(&mut r, &c, &o, data.len() as u64);
            let ios = r.st.shards[0].stats.read_ios;
            let length = 48 * 4096;
            let want = &data[offset..offset + length];
            let part = if verified {
                let read =
                    r.st.read_shared_verified(&c, &o, offset as u64, length as u64)
                        .unwrap();
                let crcs: Vec<_> = want.chunks(4096).map(|b| crc::crc32c(0, b)).collect();
                assert_eq!(read.block_crcs.as_deref(), Some(crcs.as_slice()));
                read.parts
            } else {
                r.st.read_shared(&c, &o, offset as u64, length as u64)
                    .unwrap()
            };
            assert_eq!(flat_checked(&part), want);
            if verified {
                assert!(
                    r.st.shards[0].stats.read_ios > ios,
                    "placement read served from the prefetch table"
                );
            } else {
                assert_eq!(part.len(), 1);
                assert_eq!(r.st.shards[0].stats.read_ios, ios);
            }
            let ios = r.st.shards[0].stats.read_ios;
            // The entry remains usable by both copying and shared consumers.
            assert_eq!(
                r.st.read(&c, &o, offset as u64, length as u64).unwrap(),
                want
            );
            let whole = r.st.read_shared(&c, &o, 0, data.len() as u64).unwrap();
            assert_eq!(flat_checked(&whole), data);
            assert_eq!(r.st.shards[0].stats.read_ios, ios);
            if !verified {
                assert_eq!(
                    part[0].0.as_ptr() as usize,
                    whole[0].0.as_ptr() as usize + offset,
                    "partial prefetch allocated a payload buffer"
                );
            }
            // COW/cache invalidation must not mutate a held transport source.
            let replacement = vec![0x5a; data.len()];
            let mut t = OTxn::new();
            t.write(c, &o, 0, &replacement);
            commit(&mut r.st, &t);
            assert_eq!(flat_checked(&part), want);
            assert_eq!(flat_checked(&whole), data);
            assert_eq!(
                r.st.read(&c, &o, 0, replacement.len() as u64).unwrap(),
                replacement
            );
        }
    }
}

/// Dropping the full prefetch entry (expiry or COW invalidation) cannot return
/// a device buffer to its pool while a transport still holds a partial slice,
/// nor touch a verified (placement) read's own device buffers.
#[test]
fn shared_partial_prefetch_survives_entry_expiry_and_cow() {
    for overwrite in [false, true] {
        let (mut r, c, o, data) = shared_rig(b"sh-pf-retired", 1 << 20);
        warm_all(&mut r, &c, &o, data.len() as u64);
        let offset = 4 * 4096 + 17;
        let length = 48 * 4096;
        let part = r.st.read_shared_verified(&c, &o, offset, length).unwrap();
        let first = r.st.read_shared(&c, &o, offset, length).unwrap();
        let again = r.st.read_shared(&c, &o, offset, length).unwrap();
        assert_eq!(first[0].0.as_ptr(), again[0].0.as_ptr());
        let mut next = data.clone();
        if overwrite {
            next.fill(0x5a);
            let mut t = OTxn::new();
            t.write(c, &o, 0, &next);
            commit(&mut r.st, &t);
        }
        // The full entry can expire independently of outstanding source slices.
        r.st.clk.t += 1_000_000_000;
        r.st.poll(&mut Vec::new()).unwrap();
        assert_eq!(r.st.read(&c, &o, 0, next.len() as u64).unwrap(), next);
        let want = &data[offset as usize..(offset + length) as usize];
        assert_eq!(flat_checked(&part.parts), want);
        assert_eq!(flat_checked(&first), want);
        assert_eq!(flat_checked(&again), want);
        let crcs: Vec<_> = want.chunks(4096).map(|b| crc::crc32c(0, b)).collect();
        assert_eq!(part.block_crcs.as_deref(), Some(crcs.as_slice()));
    }
}

/// Prefetched runs served whole go by reference (no device read, the bytes are the prefetch buffers); a cached run
/// (adr 0043 "Data cache") re-read after the first result was dropped ("reply sent") is unchanged and shared again, a
/// sub-range of it too; the shared bytes cannot be taken back for writing while the cache holds them.
#[test]
fn shared_read_hands_over_prefetch_buffers_and_cached_runs_stay_unchanged() {
    let (mut r, c, o, data) = shared_rig(b"sh-pf", 1 << 20);
    warm_all(&mut r, &c, &o, data.len() as u64);
    let ios = r.st.shards[0].stats.read_ios;
    let p = r.st.read_shared(&c, &o, 0, data.len() as u64).unwrap();
    assert_eq!(r.st.shards[0].stats.read_ios, ios, "read hit the device");
    assert_eq!(p.len(), 4);
    assert_eq!(flat_checked(&p), data);
    let ptrs: Vec<*const u8> = p.iter().map(|(b, _)| b.as_ptr()).collect();
    for (b, _) in &p {
        assert!(b.clone().try_into_mut().is_err(), "retained run writable");
    }
    drop(p); // the reply went out
    assert!(
        r.st.warm_data(&c, &o, 0, data.len() as u64).unwrap(),
        "retained run not ready"
    );
    let again = r.st.read_shared(&c, &o, 0, data.len() as u64).unwrap();
    assert_eq!(
        r.st.shards[0].stats.read_ios, ios,
        "retained re-read hit the device"
    );
    assert_eq!(flat_checked(&again), data, "retained run changed");
    let again_ptrs: Vec<*const u8> = again.iter().map(|(b, _)| b.as_ptr()).collect();
    assert_eq!(
        again_ptrs, ptrs,
        "the retained run is the same shared buffer"
    );
    // the copying read of the retained run (EC stash) sees the same bytes
    assert!(r.st.warm_data(&c, &o, 0, data.len() as u64).unwrap());
    assert_eq!(r.st.read(&c, &o, 0, data.len() as u64).unwrap(), data);
    // a range inside a cached run (blocks 4..52 of run 0..64) is a slice of it: shared, no copy, no device read
    assert!(r.st.warm_data(&c, &o, 4 * 4096, 48 * 4096).unwrap());
    let part = r.st.read_shared(&c, &o, 4 * 4096, 48 * 4096).unwrap();
    assert_eq!(
        r.st.shards[0].stats.read_ios, ios,
        "partial serve hit the device"
    );
    assert_eq!(part.len(), 1);
    assert!(part[0].1.is_some());
    assert_eq!(flat_checked(&part), data[4 * 4096..52 * 4096]);
    let run0 = ptrs[0] as usize;
    assert_eq!(
        part[0].0.as_ptr() as usize,
        run0 + 4 * 4096,
        "partial range not shared"
    );
    drop(again);
    // much later: still cached (no pin, no expiry), the same bytes
    r.st.clk.t += 50_000_000;
    r.st.poll(&mut Vec::new()).unwrap();
    let p = r.st.read_shared(&c, &o, 0, data.len() as u64).unwrap();
    assert_eq!(flat_checked(&p), data);
    assert_eq!(r.st.shards[0].stats.read_ios, ios, "cached run left");
}

/// Non-blocking reads without a prefetch go through the resumable (rolling) read: device buffers by reference too.
#[test]
fn shared_rolling_read_returns_the_bytes() {
    let (mut r, c, o, data) = shared_rig(b"sh-roll", 1 << 20);
    let mut spins = 0;
    while !r.st.warm(&c, &o, 0, data.len() as u64).unwrap() {
        spins += 1;
        assert!(spins < 100_000, "tree pages never loaded");
        r.st.poll(&mut Vec::new()).unwrap();
        if !r.st.take_wake() {
            r.st.idle();
        }
    }
    r.st.set_nonblock_reads(true);
    let mut got = None;
    for _ in 0..100_000 {
        match r.st.read_shared(&c, &o, 0, data.len() as u64) {
            Ok(p) => {
                got = Some(p);
                break;
            }
            Err(ObjError::WouldBlock) => {
                r.st.take_blocked();
                r.st.poll(&mut Vec::new()).unwrap();
                r.st.idle();
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    let p = got.expect("rolling read never completed");
    assert_eq!(p.len(), 4);
    assert_eq!(flat_checked(&p), data);
    r.st.set_nonblock_reads(false);
    assert_eq!(r.st.shards[0].rolling_usage(), (0, 0), "result released");
}

/// A corrupted block is found by the shared read exactly as by the copying one, from the device and from a prefetch run.
#[test]
fn shared_read_detects_a_corrupted_block() {
    let (mut r, c, o, data) = shared_rig(b"sh-bad", 1 << 20);
    let kv = r.st.shards[0].sh.dump_blocking(&mut r.st.clk).unwrap();
    let (_, v) = kv
        .iter()
        .find(|(k, _)| k[0] == T_EXT && k[10..14] == [0, 0, 0, 0])
        .unwrap();
    let ext = store::obj::onode::Ext::decode(v).unwrap();
    r.disk.corrupt(ext.pba + 70, 100, 0x40);
    let errs = r.st.shards[0].stats.crc_errors;
    match r.st.read_shared(&c, &o, 0, data.len() as u64) {
        Err(ObjError::Eio(e)) => assert!(e.contains("checksum mismatch"), "{e}"),
        x => panic!("corrupt block not detected: {:?}", x.map(|p| p.len())),
    }
    assert_eq!(r.st.shards[0].stats.crc_errors, errs + 1);
    assert!(matches!(
        r.st.read_shared_verified(&c, &o, 0, data.len() as u64),
        Err(ObjError::Eio(_))
    ));
    // other commands' blocks still read; the bad one fails from a prefetch run too
    let p = r.st.read_shared(&c, &o, 0, 256 << 10).unwrap();
    assert_eq!(flat_checked(&p), data[..256 << 10]);
    warm_all(&mut r, &c, &o, data.len() as u64);
    assert!(matches!(
        r.st.read_shared(&c, &o, 0, data.len() as u64),
        Err(ObjError::Eio(_))
    ));
}

/// Inline zstd-compressed omap / header values (adr 0021 am. 58, 59): every size / compressibility reads back byte exact
/// (get, scan, header), the omap byte counter counts the plain length, overwrite / remove / clone / remount / fsck stay
/// consistent, incompressible runs are skipped (sampling), and a store opened with the setting off still reads them.
#[test]
fn val_comp_lifecycle() {
    let mut r = rig(64, 1);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.st.commit(&t).unwrap();
    let si = r.st.shard_of(&c);
    let text = |n: usize, s: u8| -> Vec<u8> {
        b"omap value text, repeated for compression "
            .iter()
            .cycle()
            .skip(s as usize)
            .take(n)
            .copied()
            .collect()
    };
    let rnd = |n: usize, seed: u64| {
        let mut v = vec![0u8; n];
        store::rng::Rng::new(seed).fill(&mut v);
        v
    };
    let a = g(b"vc-a", 1);
    // a class trains its dictionary from the first `val_dict_samples` values: 70 values of one class, the last ones compressed
    let mut t = OTxn::new();
    t.touch(c, &a);
    let mut want: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
    for i in 0..70usize {
        want.insert(format!("w{i:02}").into_bytes(), text(100 + i * 3, 0));
    }
    for (k, v) in &want {
        t.omap_set(c, &a, k, v);
    }
    r.st.commit(&t).unwrap();
    assert_eq!(
        r.st.shards[si].stats.dict_installs, 1,
        "class dictionary trained and installed (the shared one is installed when a class without its own needs it)"
    );
    let sizes = [
        1usize, 47, 64, 65, 100, 500, 2047, 2048, 4096, 7000, 65536, 65537,
    ];
    let mut t = OTxn::new();
    t.touch(c, &a);
    for (i, &n) in sizes.iter().enumerate() {
        want.insert(format!("a{i:02}").into_bytes(), text(n, i as u8));
        want.insert(format!("z{i:02}").into_bytes(), rnd(n, i as u64));
    }
    for (k, v) in &want {
        t.omap_set(c, &a, k, v);
    }
    let hdr = text(900, 3);
    t.push(store::obj::TOp::OmapSetHeader {
        cid: c,
        oid: a.clone(),
        header: hdr.as_slice().into(),
    });
    r.st.commit(&t).unwrap();
    let st = &r.st.shards[si].stats;
    assert!(st.val_comp >= 3, "compressed values: {}", st.val_comp);
    assert!(st.val_comp_saved > 500, "saved {}", st.val_comp_saved);
    assert!(st.dict_installs >= 1, "no dictionary installed");
    let verify = |r: &mut Rig, want: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>, hdr: &[u8]| {
        assert_eq!(&r.st.omap_all(&c, &a).unwrap(), want);
        for (k, v) in want {
            let got = r.st.omap_get(&c, &a, &[k.as_slice()]).unwrap();
            assert_eq!(got.get(k), Some(v), "key {:?}", String::from_utf8_lossy(k));
        }
        assert_eq!(r.st.omap_header(&c, &a).unwrap(), hdr);
        let bytes: u64 = want.iter().map(|(k, v)| (k.len() + v.len()) as u64).sum();
        let sc = r.st.scrub(&c, &a, 0).unwrap();
        assert_eq!((sc.omap_keys, sc.omap_bytes), (want.len() as u64, bytes));
        check_no_leaks(r);
    };
    verify(&mut r, &want, &hdr);
    r.clean_remount();
    verify(&mut r, &want, &hdr);
    // overwrite compressible <-> random, remove, same-txn double write
    let mut t = OTxn::new();
    let (n1, n2) = (rnd(300, 91), text(3000, 5));
    want.insert(b"a05".to_vec(), n1.clone());
    want.insert(b"z05".to_vec(), n2.clone());
    want.insert(b"a06".to_vec(), text(2000, 1));
    want.insert(b"a06".to_vec(), text(1500, 2));
    t.omap_set(c, &a, b"a05", &n1);
    t.omap_set(c, &a, b"z05", &n2);
    let (d1, d2) = (text(2000, 1), text(1500, 2));
    t.omap_set(c, &a, b"a06", &d1);
    t.omap_set(c, &a, b"a06", &d2);
    t.push(store::obj::TOp::OmapRmKeys {
        cid: c,
        oid: a.clone(),
        keys: vec![b"a07".as_slice().into(), b"z07".as_slice().into()],
    });
    want.remove(b"a07".as_slice());
    want.remove(b"z07".as_slice());
    r.st.commit(&t).unwrap();
    verify(&mut r, &want, &hdr);
    // clone copies decoded values
    let b = g(b"vc-b", 2);
    let mut t = OTxn::new();
    t.push(store::obj::TOp::Clone {
        cid: c,
        src: a.clone(),
        dst: b.clone(),
    });
    r.st.commit(&t).unwrap();
    assert_eq!(r.st.omap_all(&c, &b).unwrap(), want);
    r.clean_remount();
    verify(&mut r, &want, &hdr);
    // a store opened with the setting off still reads (and rewrites) compressed values
    r.cfg.shard.val_comp_min = 0;
    r.clean_remount();
    verify(&mut r, &want, &hdr);
    let mut t = OTxn::new();
    want.insert(b"a00".to_vec(), text(800, 0));
    let d0 = text(800, 0);
    t.omap_set(c, &a, b"a00", &d0);
    r.st.commit(&t).unwrap();
    verify(&mut r, &want, &hdr);
    // removing the object frees everything
    let mut t = OTxn::new();
    t.remove(c, &a);
    t.remove(c, &b);
    r.st.commit(&t).unwrap();
    check_no_leaks(&mut r);
}

/// Sampling: a run of incompressible values is mostly skipped, a compressible run afterwards is picked up quickly.
#[test]
fn val_comp_sampling_skips_incompressible_runs() {
    let mut r = rig(64, 1);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.st.commit(&t).unwrap();
    let si = r.st.shard_of(&c);
    let a = g(b"vs-a", 1);
    let mut rng = store::rng::Rng::new(5);
    for i in 0..400 {
        let mut v = vec![0u8; 300];
        rng.fill(&mut v);
        v[..2].copy_from_slice(&[8, 3]); // one value class: its dictionary is trained on random bytes, then the attempts fail
        let mut t = OTxn::new();
        let k = format!("r{i:04}");
        t.omap_set(c, &a, k.as_bytes(), &v);
        r.st.commit(&t).unwrap();
    }
    assert_eq!(r.st.shards[si].stats.val_comp, 0);
    let skip = r.st.shards[si].vc.skipping();
    assert!(skip > 0, "sampling backoff not engaged");
    for i in 0..200 {
        let mut t = OTxn::new();
        let k = format!("t{i:04}");
        t.omap_set(c, &a, k.as_bytes(), &[b'x'; 300]);
        r.st.commit(&t).unwrap();
    }
    assert!(
        r.st.shards[si].stats.val_comp >= 120,
        "{}",
        r.st.shards[si].stats.val_comp
    );
}

/// Model runs with a third of the values shaped like structured records: inline compression with shard templates stays
/// byte exact across checkpoints, remounts, clones, range removals (4 / 8 KiB pages, 1 / 4 shards).
#[test]
fn model_val_comp() {
    COMPVAL_PCT.set(90);
    VCOMP_SEEN.set(0);
    let mut cfg = StoreCfg::default();
    cfg.shard.val_dict_samples = 8;
    for seed in 60..=63u64 {
        let nodes = if seed % 2 == 0 { 8192 } else { 4096 };
        run_model_cfg(
            seed,
            if seed < 62 { 1 } else { 4 },
            700,
            350,
            cfg.clone(),
            nodes,
            0,
        );
    }
    assert!(
        VCOMP_SEEN.get() > 30,
        "compressed values {}",
        VCOMP_SEEN.get()
    );
    COMPVAL_PCT.set(0);
}

/// Crash at every IO boundary of a workload with compressible values (templates installed by the same txns that use them):
/// the recovered store equals a model prefix x 3 policies.
#[test]
fn crash_matrix_objects_val_comp() {
    COMPVAL_PCT.set(90);
    COMPVAL_KINDS.set(1);
    VCOMP_SEEN.set(0);
    let (n, c) = crash_matrix(
        80,
        170,
        &[
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ],
        120,
        1,
    );
    assert!(n > 100 && c * 2 > n, "scenarios {n}, crashed {c}");
    assert!(VCOMP_SEEN.get() > 0, "no compressed value in the workload");
    COMPVAL_PCT.set(0);
    COMPVAL_KINDS.set(3);
}

#[test]
#[ignore = "soak"]
fn crash_matrix_objects_val_comp_soak() {
    COMPVAL_PCT.set(90);
    let mut tot = 0;
    for gs in 400..440 {
        tot += crash_matrix(
            16,
            gs,
            &[
                CrashPolicy::MIXED,
                CrashPolicy::DROP_ALL,
                CrashPolicy::PERSIST_ALL,
            ],
            1000,
            1,
        )
        .0;
    }
    println!("scenarios {tot}");
    COMPVAL_PCT.set(0);
}

/// How the 4 MiB objects of [`frag_read_measurement`] were overwritten out of place.
#[derive(Clone, Copy)]
enum Aging {
    /// Every `n`-th block of the object (object alone: the relocated blocks are contiguous).
    Every(u64),
    /// `n` random 4 KiB overwrites spread over 8 objects (like random 4K writes on an RBD image: the relocated blocks of
    /// one object lie between those of the others).
    Scatter(u64),
}

/// OSD-shaped 4 MiB read of an object aged by `aging`: `warm` + `warm_data` until ready, then the non-blocking
/// `read_crc`, retried on WouldBlock. Returns (virtual device-time ns per read, device read commands per read,
/// wake-ups per read, wall us per read = CPU cost of the store path).
fn frag_read_measurement(aging: Aging) -> (u64, u64, u64, u64) {
    let (mut r, _) = rig_with(512, 1, 1024, 5, StoreCfg::default());
    let c = c1();
    let names: Vec<Ghobject> = (1..=8).map(|i| g(b"frag4m", i)).collect();
    let o = names[0].clone();
    let data: Vec<u8> = (0..4 << 20).map(|i| (i % 251) as u8).collect();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    for n in &names {
        let mut t = OTxn::new();
        t.write(c, n, 0, &data);
        t.setattr(c, n, b"_", b"oi");
        commit(&mut r.st, &t);
    }
    let one = |r: &mut Rig, n: &Ghobject, b: u64| {
        let mut t = OTxn::new();
        let at = b as usize * 4096;
        t.write(c, n, b * 4096, &data[at..at + 4096]);
        commit(&mut r.st, &t);
    };
    match aging {
        Aging::Every(e) => (0..1024u64)
            .step_by(e as usize)
            .for_each(|b| one(&mut r, &o, b)),
        Aging::Scatter(k) => {
            let mut x = 0x9e3779b97f4a7c15u64;
            for i in 0..k {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                one(&mut r, &names[(i % 8) as usize], x % 1024);
            }
        }
    }
    r.clean_remount();
    let n = 20;
    let (t0, io0, w0) = (
        r.st.clk.t,
        r.st.shards[0].stats.read_ios,
        std::time::Instant::now(),
    );
    let mut wakes = 0;
    for _ in 0..n {
        r.st.clk.t += 50_000_000; // let the retained prefetch expire: every read goes to the device
        r.st.poll(&mut Vec::new()).unwrap();
        let mut retry = true; // the OSD retries a parked op on a wake only
        loop {
            let ready = retry
                && r.st.warm(&c, &o, 0, 4 << 20).unwrap()
                && r.st.warm_data(&c, &o, 0, 4 << 20).unwrap();
            if ready {
                r.st.set_nonblock_reads(true);
                let got = r.st.read_crc(&c, &o, 0, 4 << 20);
                r.st.set_nonblock_reads(false);
                match got {
                    Ok((got, _)) => {
                        assert_eq!(got, data);
                        break;
                    }
                    Err(ObjError::WouldBlock) => {
                        r.st.take_blocked();
                    }
                    Err(e) => panic!("{e:?}"),
                }
            }
            r.st.poll(&mut Vec::new()).unwrap();
            retry = r.st.take_wake();
            if retry {
                wakes += 1;
            } else {
                r.st.idle();
            }
        }
    }
    (
        (r.st.clk.t - t0 - n * 50_000_000) / n,
        (r.st.shards[0].stats.read_ios - io0) / n,
        wakes / n,
        w0.elapsed().as_micros() as u64 / n,
    )
}

#[test]
#[ignore = "local debug performance measurement"]
fn perf_fragmented_4m_read() {
    let cases = [
        ("none", Aging::Every(2000)),
        ("every 16th", Aging::Every(16)),
        ("every 2nd", Aging::Every(2)),
        ("scatter 8000 (1000 per object)", Aging::Scatter(8000)),
        ("scatter 16000 (2000 per object)", Aging::Scatter(16000)),
        ("scatter 32000 (4000 per object)", Aging::Scatter(32000)),
    ];
    for (name, a) in cases {
        let (ns, ios, wakes, wall) = frag_read_measurement(a);
        println!(
            "{name:30}: {ns} ns device / read, {ios} device reads, {wakes} wakes, {wall} us wall"
        );
    }
}

#[test]
fn a_scattered_4m_read_wakes_its_op_once_per_wait_not_per_command() {
    // random 4K overwrites over 8 objects: ~900 physical runs, more than the device queue room (rolling read path):
    // before, every completion woke the op and every retry probed all runs (quadratic: 780 wakes, 0.3 s CPU per read)
    let (_, ios, wakes, _) = frag_read_measurement(Aging::Scatter(8000));
    assert!(
        ios > 200,
        "{ios} device reads: the object is not fragmented"
    );
    assert!(wakes <= 4, "{wakes} wake-ups for one read");
}

/// Space of pool compression on 4 MiB writefull of the `oprobe fill --cpct 50` pattern (adr 0059 am. 1): physical bytes
/// per logical byte of the compressed extents and the chunks the store rejected.
#[test]
#[ignore = "measurement"]
fn comp_space_cpct50() {
    const T: &[u8] = b"the quick brown fox jumps over the lazy dog 0123456789 ABCDEFGH ";
    for alg in [Alg::Lz4, Alg::Snappy, Alg::Zstd, Alg::Zlib] {
        let mut r = rig(512, 1);
        let c = c1();
        let mut t = OTxn::new();
        t.mkcoll(c);
        r.st.commit(&t).unwrap();
        let mut rng = Rng::new(7);
        for i in 0..40u32 {
            let mut v = Vec::new();
            while v.len() < 4 << 20 {
                let blk = v.len();
                for _ in 0..256 {
                    v.extend_from_slice(&rng.next_u64().to_le_bytes());
                }
                while v.len() < blk + 4096 {
                    let k = (blk + 4096 - v.len()).min(T.len());
                    v.extend_from_slice(&T[..k]);
                }
            }
            let mut t = OTxn::new();
            t.comp = Some(cspec(alg));
            t.write(c, &g(format!("o{i}").as_bytes(), 7), 0, &v);
            r.st.commit(&t).unwrap();
        }
        r.st.checkpoint().unwrap();
        let (p, o, ok, rej) = comp_stats(&mut r.st);
        let sampled: u64 = r.st.shards.iter().map(|s| s.stats.comp_sampled_out).sum();
        let used = r.st.statfs();
        eprintln!(
            "{alg:?}: comp {p}/{o} = {:.4} ok {ok} rejected {rej} sampled_out {sampled} statfs {used:?}",
            p as f64 / o as f64
        );
    }
}

#[test]
#[ignore = "measurement"]
fn comp_space_after_remove() {
    let mut r = rig(512, 1);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.st.commit(&t).unwrap();
    for round in 0..3u32 {
        for i in 0..40u32 {
            let d = cdata(4 << 20, 5 + i as u64);
            let mut t = OTxn::new();
            t.comp = Some(cspec(Alg::Lz4));
            t.write(c, &g(format!("o{round}-{i}").as_bytes(), 7), 0, &d);
            r.st.commit(&t).unwrap();
        }
        let s = r.st.statfs();
        let (p, o, _, _) = comp_stats(&mut r.st);
        eprintln!(
            "round {round} written: used {} comp {p}/{o} held {}",
            s.used_bytes, s.held_bytes
        );
        for i in 0..40u32 {
            let mut t = OTxn::new();
            t.remove(c, &g(format!("o{round}-{i}").as_bytes(), 7));
            r.st.commit(&t).unwrap();
        }
        let s = r.st.statfs();
        eprintln!(
            "round {round} removed: used {} held {}",
            s.used_bytes, s.held_bytes
        );
    }
}

/// Writes shorter than a chunk or off its boundaries are compressed in pieces (head up to the chunk boundary, tail after
/// the last whole chunk), like a BlueStore blob of that size; pieces below `min_bytes` stay raw.
#[test]
fn compression_covers_sub_chunk_pieces() {
    let mut r = rig(64, 1);
    let (c, o) = (c1(), g(b"piece", 1));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let on = Some(cspec(Alg::Lz4));
    let mut m = cdata(32 << 10, 1);
    let mut t = OTxn::new();
    t.comp = on;
    t.write(c, &o, 0, &m);
    commit(&mut r.st, &t);
    same(&mut r, &c, &o, &m);
    assert_eq!(comp_stats(&mut r.st).1, 32 << 10, "32 KiB write alone");
    // blocks 14..22: head piece of 2 blocks (the minimum) up to the chunk boundary, tail piece of 6 blocks
    let off = 14 * 4096;
    let d = cdata(8 * 4096, 2);
    m.resize(22 * 4096, 0);
    m[off..].copy_from_slice(&d);
    let mut t = OTxn::new();
    t.comp = on;
    t.write(c, &o, off as u64, &d);
    commit(&mut r.st, &t);
    same(&mut r, &c, &o, &m);
    assert_eq!(comp_stats(&mut r.st).1, 64 << 10, "head and tail pieces");
    r.clean_remount();
    same(&mut r, &c, &o, &m);
    // a 4 KiB piece is below the minimum: raw
    let before = comp_stats(&mut r.st).1;
    let d4 = cdata(4096, 3);
    let mut t = OTxn::new();
    t.comp = on;
    t.write(c, &o, 200 << 10, &d4);
    commit(&mut r.st, &t);
    assert_eq!(comp_stats(&mut r.st).1, before);
    check_no_leaks(&mut r);
}

/// Closed-loop QD `qd` of OSD-shaped 4 MiB reads (one executor session each) over 8 objects aged by 8000 random 4 KiB
/// overwrites, `total` reads on ONE shard: virtual latency (ns) of every read, sorted.
fn concurrent_aged_read_latencies(shards: u32, qd: usize, total: usize) -> (Vec<u64>, u64, u64) {
    let (mut r, _) = rig_with(512, shards, 1024, 5, StoreCfg::default());
    let c = c1();
    let names: Vec<Ghobject> = (1..=8).map(|i| g(b"frag4m", i)).collect();
    let data: Vec<u8> = (0..4 << 20).map(|i| (i % 251) as u8).collect();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    for n in &names {
        let mut t = OTxn::new();
        t.write(c, n, 0, &data);
        t.setattr(c, n, b"_", b"oi");
        commit(&mut r.st, &t);
    }
    let mut x = 0x9e3779b97f4a7c15u64;
    for i in 0..8000u64 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let (b, mut t) = (x % 1024, OTxn::new());
        t.write(
            c,
            &names[(i % 8) as usize],
            b * 4096,
            &data[b as usize * 4096..][..4096],
        );
        commit(&mut r.st, &t);
    }
    r.clean_remount();
    // (object, session, start time, what it waits for: None = unknown, probed on every wake); like the OSD gate, a parked op
    // is probed again when a wake names its cause (`take_wake_set`), when something unnamed changed, or when it is new
    type Op = (usize, (u64, u64), u64, Option<store::toks::Toks<8>>, bool);
    let mut pending: Vec<Op> = Vec::new();
    let (mut started, mut lat) = (0usize, Vec::new());
    let (mut probes, w0) = (0u64, std::time::Instant::now());
    let (mut woke, mut all) = (store::toks::Toks::<32>::new(), true);
    while lat.len() < total {
        while pending.len() < qd && started < total {
            pending.push((started % 8, (1, started as u64), r.st.clk.t, None, true));
            started += 1;
        }
        let mut i = 0;
        while i < pending.len() {
            let (o, s, t0, ref cause, fresh) = pending[i];
            let hit = match cause {
                Some(c) => c.as_slice().iter().any(|t| woke.as_slice().contains(t)),
                None => true,
            };
            if !(fresh || all || hit) {
                i += 1;
                continue;
            }
            probes += 1;
            r.st.cause_begin();
            r.st.read_session(Some(s), true);
            let ready = r.st.warm(&c, &names[o], 0, 4 << 20).unwrap()
                && r.st.warm_data(&c, &names[o], 0, 4 << 20).unwrap();
            let mut done = false;
            if ready {
                r.st.set_nonblock_reads(true);
                let got = r.st.read_crc(&c, &names[o], 0, 4 << 20);
                r.st.set_nonblock_reads(false);
                match got {
                    Ok((got, _)) => {
                        assert_eq!(got, data);
                        done = true;
                    }
                    Err(ObjError::WouldBlock) => {}
                    Err(e) => panic!("{e:?}"),
                }
            }
            r.st.take_blocked();
            r.st.read_session(None, !done);
            if done {
                lat.push(r.st.clk.t - t0);
                pending.remove(i);
            } else {
                let mut cs = store::toks::Toks::<8>::new();
                r.st.cause_take(&mut cs);
                pending[i].3 = (!cs.is_empty() && !cs.overflowed()).then_some(cs);
                pending[i].4 = false;
                i += 1;
            }
        }
        r.st.poll(&mut Vec::new()).unwrap();
        woke = store::toks::Toks::<32>::new();
        all = false;
        if !r.st.take_wake_set(&mut woke, &mut all) {
            r.st.idle();
        }
    }
    lat.sort_unstable();
    let n = total as u64;
    (lat, probes / n, w0.elapsed().as_micros() as u64 / n)
}

#[test]
#[ignore = "local debug performance measurement"]
fn perf_concurrent_aged_reads() {
    for (shards, qd) in [(1, 1), (1, 4), (8, 4)] {
        let (l, probes, wall) = concurrent_aged_read_latencies(shards, qd, 48);
        let at = |p: usize| l[(l.len() * p / 100).min(l.len() - 1)] / 1000;
        println!(
            "shards {shards} qd {qd}: p50 {} us, p90 {} us, p99 {} us, max {} us; {probes} probes and {wall} us wall (store CPU) per read",
            at(50),
            at(90),
            at(99),
            l[l.len() - 1] / 1000
        );
    }
}

#[test]
fn concurrent_aged_reads_on_one_shard_are_served_in_arrival_order() {
    // four fragmented 4 MiB reads share the device queue room of one shard: the oldest read gets the room first. Before, a
    // finished read was dropped with `swap_remove` and the newest took the front slot: an older read starved behind
    // younger ones (every ~9th read took 4x, one 20x, the typical read time)
    let (l, _, _) = concurrent_aged_read_latencies(1, 4, 48);
    let (p50, max) = (l[l.len() / 2], l[l.len() - 1]);
    assert!(
        max <= p50 + p50 / 4,
        "p50 {p50} ns, max {max} ns: reads are not served in arrival order"
    );
}

#[test]
fn a_waiting_aged_read_is_probed_by_its_own_completion_not_by_every_wake() {
    // every probe of a fragmented 4 MiB read decodes and walks ~900 runs; a wake per finished read re-probed all parked
    // reads (10 probes per read at QD4, QD1: 2), so the probe CPU grew with the square of the readers. Now the read names its
    // wake token (`cause_pf`) and releases wake only a refused slot waiter
    let (_, probes, _) = concurrent_aged_read_latencies(1, 4, 48);
    assert!(probes <= 3, "{probes} probes per read at QD4");
}

/// Checkpoint work is background work: the polls that run it report its time (`ObjStore::bg_ns`, kept out of the core's
/// message-cost learning), never more than the polls took.
#[test]
fn checkpoint_time_is_reported_as_background_work() {
    let mut r = rig(32, 1);
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    for i in 0..256u32 {
        t.write(c, &g(format!("bg-{i}").as_bytes(), i), 0, &[7; 4096]);
    }
    r.st.commit(&t).unwrap();
    r.st.shards[0].sh.request_checkpoint();
    let (mut bg, mut wall, mut a) = (0u64, 0u64, Vec::new());
    for _ in 0..1000 {
        let t0 = std::time::Instant::now();
        r.st.poll(&mut a).unwrap();
        wall += t0.elapsed().as_nanos() as u64;
        bg += r.st.bg_ns();
        if !r.st.shards[0].sh.ckpt_active() && bg > 0 {
            break;
        }
        r.st.idle();
    }
    assert!(
        bg > 0,
        "the checkpoint ran in the polls: its time is background work"
    );
    // two clocks (the shard's fastclock, `Instant` here) over a few short polls: only the magnitude compares
    assert!(bg <= 2 * wall, "bg {bg} ns within the polls' {wall} ns");
}

/// Lab cell "ls" shape on the omap LSM engine through the parked FIFO (G1 2026-10-27: a parked txn was never woken,
/// `WARNING TIMEOUT store parked transaction exceeded 30s`, the OSDs failed): one hot object pre-filled with `pre`
/// keys, `clients` clients at QD1 each alternating a 256-key set of new keys and the removal of its own oldest 256
/// keys, every txn with PG-meta omap (a log entry and info key on the PG meta object, log trim). Returns the shard
/// counters; panics when a queued txn is reported failed or the queue stops progressing.
fn hot_object_queue(
    cap_mib: u64,
    pre: u64,
    clients: u64,
    ops: u64,
    wal: u64,
    helpers: bool,
    cfg: StoreCfg,
) -> store::shard::OlsmStats {
    OMAP_LSM.set(true);
    let (mut r, _) = rig_with(cap_mib, 1, wal, 5, cfg);
    OMAP_LSM.set(false);
    let c = c1();
    let o = g(b"hot", 7);
    let pgm = Ghobject::pgmeta(1, 0, ShardId::NO_SHARD);
    let val = |i: u64| vec![(i % 251) as u8; 300];
    let hk = |c: u64, i: u64| format!("c{c:03}-{i:08}").into_bytes();
    let mut t = OTxn::new();
    t.mkcoll(c).touch(c, &o).touch(c, &pgm);
    r.st.commit(&t).unwrap();
    let pk: Vec<Vec<u8>> = (0..pre)
        .map(|i| format!("pre-{i:08}").into_bytes())
        .collect();
    let pv: Vec<Vec<u8>> = (0..pre).map(val).collect();
    for b in (0..pre as usize).step_by(256) {
        let mut t = OTxn::new();
        t.push(TOp::OmapSetKeys {
            cid: c,
            oid: o.clone(),
            pairs: (b..(b + 256).min(pre as usize))
                .map(|i| (TxnBytes::Borrowed(&pk[i]), TxnBytes::Borrowed(&pv[i])))
                .collect(),
        });
        r.st.commit(&t).unwrap();
    }
    // per client: next key to insert, oldest key still present
    let mut cl: Vec<(u64, u64)> = vec![(0, 0); clients as usize];
    let mut owner: BTreeMap<u64, u64> = BTreeMap::new();
    let (mut tok, mut done, mut issued) = (100u64, 0u64, 0u64);
    let mut ready: Vec<u64> = (0..clients).collect();
    let mut acked = Vec::new();
    let mut errors = Vec::new();
    let mut last_progress = r.st.clk.t;
    while done < ops {
        for cli in ready.drain(..) {
            if issued >= ops {
                break;
            }
            issued += 1;
            tok += 1;
            let (next, old) = &mut cl[cli as usize];
            let mut t = OTxn::new();
            if *old == *next || (*next - *old) / 256 < 2 && tok % 2 == 0 || tok % 2 == 1 {
                t.push(TOp::OmapSetKeys {
                    cid: c,
                    oid: o.clone(),
                    pairs: (*next..*next + 256)
                        .map(|i| (TxnBytes::Owned(hk(cli, i)), TxnBytes::Owned(val(i))))
                        .collect(),
                });
                *next += 256;
            } else {
                t.push(TOp::OmapRmKeys {
                    cid: c,
                    oid: o.clone(),
                    keys: (*old..*old + 256)
                        .map(|i| TxnBytes::Owned(hk(cli, i)))
                        .collect(),
                });
                *old += 256;
            }
            t.push(TOp::OmapSetKeys {
                cid: c,
                oid: pgm.clone(),
                pairs: vec![
                    (
                        TxnBytes::Owned(format!("log-{tok:012}").into_bytes()),
                        TxnBytes::Owned(vec![7; 180]),
                    ),
                    (
                        TxnBytes::Owned(b"info".to_vec()),
                        TxnBytes::Owned(tok.to_le_bytes().to_vec()),
                    ),
                ],
            });
            if tok > 400 {
                t.push(TOp::OmapRmKeys {
                    cid: c,
                    oid: pgm.clone(),
                    keys: vec![TxnBytes::Owned(
                        format!("log-{:012}", tok - 300).into_bytes(),
                    )],
                });
            }
            owner.insert(tok, cli);
            r.st.queue(&t, tok).unwrap();
        }
        if helpers {
            // a helper core that steps every round it is handed to the end before handing it back
            r.st.compaction_helpers(true, 1);
            while let Some(mut j) = r.st.take_compaction() {
                while !j.step(256) {}
                assert!(r.st.return_compaction(j, true));
            }
        }
        let polled = r.st.poll(&mut acked);
        r.st.take_queue_errors(&mut errors);
        assert!(errors.is_empty() && polled.is_ok(), "{errors:?} {polled:?}");
        if !acked.is_empty() {
            last_progress = r.st.clk.t;
        }
        for a in acked.drain(..) {
            ready.push(owner.remove(&a).expect("own token"));
            done += 1;
        }
        assert!(
            r.st.clk.t < last_progress + 30_000_000_000,
            "queue stopped: {} busy {:?} olsm {:?}",
            r.st.diag(),
            r.st.shards[0].sh.stats.busy,
            r.st.shards[0].sh.olsm_stats(),
        );
        r.st.idle();
    }
    // the model: the surviving keys of every client
    let mut want: BTreeMap<Vec<u8>, Vec<u8>> = (0..pre as usize)
        .map(|i| (pk[i].clone(), pv[i].clone()))
        .collect();
    for (cli, (next, old)) in cl.iter().enumerate() {
        want.extend((*old..*next).map(|i| (hk(cli as u64, i), val(i))));
    }
    let mut got = BTreeMap::new();
    let mut from = Vec::new();
    loop {
        let (page, more) = r.st.omap_iter(&c, &o, &from, 1000).unwrap();
        let last = page.last().map(|(k, _)| k.clone());
        got.extend(page);
        match last {
            Some(mut k) if more => {
                k.push(0);
                from = k;
            }
            _ => break,
        }
    }
    assert!(
        got == want,
        "omap differs: {} vs {} keys",
        got.len(),
        want.len()
    );
    r.st.shards[0].sh.olsm_stats().expect("engine on")
}

#[test]
fn hot_object_set_rm_never_strands_a_parked_txn() {
    let mut cfg = StoreCfg::default();
    cfg.shard.cache_pages = 96;
    for helpers in [false, true] {
        let st = hot_object_queue(1024, 20_000, 64, 6_000, 1024, helpers, cfg.clone());
        assert!(
            st.flushes >= 8 && st.merges >= 1,
            "helpers {helpers}: {st:?}"
        );
    }
}

/// The checkpoint arena keeps chunks for the budgeted checkpoint size (the soft dirty mark), not the high-water of the
/// largest checkpoint ever (review M2): after an outsized checkpoint the spare chunks shrink back to the budget.
#[test]
fn outsized_checkpoint_does_not_keep_its_arena() {
    let mut cfg = nvc_cfg();
    cfg.shard.dirty_soft_pages = 16;
    let mut r = rig_with(64, 1, 1024, 1, cfg).0;
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let small = |r: &mut Rig, round: u8| {
        let (o, v) = (g(b"small", 0), [round; 64]);
        let mut t = OTxn::new();
        t.omap_set(c, &o, b"k", &v);
        commit(&mut r.st, &t);
        r.st.checkpoint().unwrap();
        r.st.mem().ckpt_bytes
    };
    let base = small(&mut r, 1);
    // one txn dirtying far more pages than the soft mark: its checkpoint is outsized
    let keys: Vec<String> = (0..40u32).map(|k| format!("key{k:04}")).collect();
    let objs: Vec<_> = (0..400u32)
        .map(|i| g(format!("o{i}").as_bytes(), i))
        .collect();
    let val = [1u8; 64];
    let mut t = OTxn::new();
    for o in &objs {
        for key in &keys {
            t.omap_set(c, o, key.as_bytes(), &val);
        }
    }
    commit(&mut r.st, &t);
    r.st.checkpoint().unwrap();
    let after = small(&mut r, 2);
    assert!(
        after <= base.max(1) * 2,
        "arena kept {after} bytes after an outsized checkpoint (budgeted size {base})"
    );
}

#[test]
fn append_onto_a_partial_tail_block_reads_nothing_from_the_device() {
    // adr 0043: the partial last block an append wrote stays in the data cache, the next append of the same object
    // needs no device read (before: one prefetch round trip per append at QD1)
    let (mut r, _) = rig_with(128, 1, 1024, 5, StoreCfg::default());
    let c = c1();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut r.st, &t);
    let o = g(b"tail", 1);
    let mut want: Vec<u8> = Vec::new();
    let mut warm_reads = 0;
    for i in 0..24u8 {
        let d = vec![i + 1; 1000];
        let size = want.len() as u64;
        let ios = r.st.shards[0].stats.read_ios;
        if size >= 4096 {
            assert!(
                r.st.warm_data(&c, &o, size, 1).unwrap(),
                "append {i}: tail block not resident"
            );
        }
        let mut t = OTxn::new();
        t.write(c, &o, size, &d);
        t.setattr(c, &o, b"_", b"oi");
        commit(&mut r.st, &t);
        want.extend_from_slice(&d);
        if size >= 4096 {
            warm_reads += r.st.shards[0].stats.read_ios - ios;
        }
    }
    assert_eq!(
        warm_reads, 0,
        "device reads on appends past the first extent"
    );
    assert_eq!(r.st.read(&c, &o, 0, want.len() as u64).unwrap(), want);
    // a cold shard (remount) has no tail cached: the append still works and sees the old bytes
    r.clean_remount();
    let mut t = OTxn::new();
    t.write(c, &o, want.len() as u64, &[0xee; 1000]);
    commit(&mut r.st, &t);
    want.extend_from_slice(&[0xee; 1000]);
    assert_eq!(r.st.read(&c, &o, 0, want.len() as u64).unwrap(), want);
}

// Offline repair regression fixtures deliberately create durable corruption through shard txns.
fn repair_raw(st: &mut St, mut t: store::shard::Txn<Vec<u8>>) {
    t.sys = true;
    let s = &mut st.shards[0];
    let lsn = loop {
        match s.sh.submit(t) {
            Ok(lsn) => break lsn,
            Err((
                store::StoreError::Miss | store::StoreError::Busy | store::StoreError::WalFull,
                back,
            )) => {
                t = back;
                s.miss_wait(&mut st.clk).unwrap();
            }
            Err((e, _)) => panic!("damage fixture: {e}"),
        }
    };
    s.wait(&mut st.clk, |s| s.sh.durable_lsn() >= lsn).unwrap();
}

fn repair_fixture() -> Rig {
    let mut r = rig(32, 1);
    let mut t = OTxn::new();
    t.mkcoll(c1());
    let a = vec![0x31; 16384];
    let b = vec![0x42; 8192];
    t.write(c1(), &g(b"repair-a", 1), 0, &a);
    t.write(c1(), &g(b"repair-b", 2), 0, &b);
    r.st.commit(&t).unwrap();
    r.st.checkpoint().unwrap();
    r
}

fn repair_assert_data(st: &mut St) {
    for (name, hash, byte, len) in [(b"repair-a", 1, 0x31, 16384), (b"repair-b", 2, 0x42, 8192)] {
        assert_eq!(
            st.read(&c1(), &g(name, hash), 0, len).unwrap(),
            vec![byte; len as usize]
        );
    }
    assert!(st.check(true).unwrap().errors.is_empty());
    fsck(st.shards[0].sh.dev(), &mut st.clk, Some(&fsck_refs)).unwrap();
}

fn repair_add_leak(st: &mut St) {
    let s = &mut st.shards[0];
    let b = s.sh.alloc(3).unwrap();
    let mut t = store::shard::Txn::new(0);
    t.data.push((b, vec![0x77; 3 * 4096]));
    repair_raw(st, t);
    st.checkpoint().unwrap();
}

#[test]
fn offline_repair_leak_and_collection_counters() {
    let mut r = repair_fixture();
    repair_add_leak(&mut r.st);
    let k = coll_key(&c1());
    let mut v = Vec::new();
    r.st.shards[0].tget(&mut r.st.clk, &k, &mut v).unwrap();
    let mut info = store::obj::onode::CollInfo::decode(&v).unwrap();
    info.nobj = 90;
    info.nbytes = -1;
    info.comp = 555;
    info.comp_orig = 666;
    let mut t = store::shard::Txn::new(0);
    t.put(&k, &info.encode());
    repair_raw(&mut r.st, t);
    r.st.checkpoint().unwrap();
    let report = r.st.repair(true).unwrap();
    assert!(!report.before.is_empty());
    assert!(!report.refused, "{report:?}");
    assert!(report.after.is_empty(), "{report:?}");
    assert!(
        report
            .actions
            .iter()
            .any(|a| a.contains("freed leaked blocks"))
    );
    assert!(
        report
            .actions
            .iter()
            .any(|a| a.contains("rewrote from recount"))
    );
    repair_assert_data(&mut r.st);
    let (_, mut remounted) = open(&r.disk.image(), &r.sim, &r.cfg);
    repair_assert_data(&mut remounted);
    let again = remounted.repair(true).unwrap();
    assert!(
        again.before.is_empty() && again.actions.is_empty() && again.after.is_empty(),
        "{again:?}"
    );
}

#[test]
fn offline_repair_refuses_alias_outside_object_without_reclaim() {
    let mut r = repair_fixture();
    repair_add_leak(&mut r.st);
    let mut extents = Vec::new();
    let mut cur = store::tree::ScanCursor::new(&[T_EXT], &[T_EXT + 1]);
    while !r.st.shards[0]
        .tscan(&mut r.st.clk, &mut cur, 4096, &mut |k, v| {
            extents.push((k.to_vec(), v.to_vec()))
        })
        .unwrap()
    {}
    assert!(extents.len() >= 2);
    let mut t = store::shard::Txn::new(0);
    t.put(&extents[1].0, &extents[0].1);
    repair_raw(&mut r.st, t);
    r.st.checkpoint().unwrap();
    let report = r.st.repair(false).unwrap();
    assert!(report.refused, "{report:?}");
    assert!(report.actions.is_empty());
    assert!(report.after.iter().any(|e| e.contains("outside object")));
    // Check neither mapping was rewritten in an attempt to select an owner.
    let mut v = Vec::new();
    r.st.shards[0]
        .tget(&mut r.st.clk, &extents[1].0, &mut v)
        .unwrap();
    assert_eq!(v, extents[0].1);
}

#[test]
fn offline_repair_crash_at_every_io_event_resumes() {
    let mut r = repair_fixture();
    repair_add_leak(&mut r.st);
    let key = coll_key(&c1());
    let mut value = Vec::new();
    r.st.shards[0]
        .tget(&mut r.st.clk, &key, &mut value)
        .unwrap();
    let mut info = store::obj::onode::CollInfo::decode(&value).unwrap();
    info.nbytes += 42;
    let mut damage = store::shard::Txn::new(0);
    damage.put(&key, &info.encode());
    repair_raw(&mut r.st, damage);
    r.st.checkpoint().unwrap();
    let img = r.disk.image();
    let (disk, mut st) = open(&img, &r.sim, &r.cfg);
    let start = disk.events();
    assert!(st.repair(true).unwrap().after.is_empty());
    let events = disk.events() - start;
    for cut in 1..=events {
        for policy in [
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ] {
            let (disk, mut st) = open(&img, &r.sim, &r.cfg);
            disk.arm_crash(disk.events() + cut);
            let _ = st.repair(true);
            disk.crash_now();
            let recovered = disk.crash_image(policy);
            drop(st);
            let (_, mut st) = open(&recovered, &r.sim, &r.cfg);
            let report = st.repair(true).unwrap();
            assert!(report.after.is_empty(), "cut {cut}: {report:?}");
            repair_assert_data(&mut st);
        }
    }
}

#[test]
fn offline_repair_root_usage_counter() {
    let mut r = repair_fixture();
    let mut dev = r.disk.queue();
    let mut clk = SimClock::default();
    let (_, dirs) = read_super(&mut dev, &mut clk).unwrap();
    let mut root = store::layout::read_root(&mut dev, &mut clk, &dirs[0]).unwrap();
    root.used_blocks += 10;
    root.meta_pages_used += 10;
    let mut io = store::sio::Sio::new(&mut dev, &mut clk);
    io.write_one(dirs[0].root_a, &root.encode()).unwrap();
    io.write_one(dirs[0].root_b, &root.encode()).unwrap();
    let img = r.disk.image();
    drop(r.st);
    r.cfg.shard.repair_counters = true;
    let (disk, mut st) = open(&img, &r.sim, &r.cfg);
    let report = st.repair(true).unwrap();
    assert!(
        report
            .actions
            .iter()
            .any(|a| a.contains("root usage counter")),
        "{report:?}"
    );
    assert!(report.after.is_empty(), "{report:?}");
    repair_assert_data(&mut st);
    r.cfg.shard.repair_counters = false;
    let (_, mut st) = open(&disk.image(), &r.sim, &r.cfg);
    repair_assert_data(&mut st);
}

#[test]
fn offline_repair_onode_compression_counters() {
    let mut r = repair_fixture();
    let payload = vec![0x31; 16384];
    let mut t = OTxn::new();
    t.comp = Some(cspec(Alg::Lz4));
    t.write(c1(), &g(b"repair-a", 1), 0, &payload);
    r.st.commit(&t).unwrap();
    let mut nodes = Vec::new();
    let mut cur = store::tree::ScanCursor::new(&[T_ONODE], &[T_ONODE + 1]);
    while !r.st.shards[0]
        .tscan(&mut r.st.clk, &mut cur, 4096, &mut |k, v| {
            nodes.push((k.to_vec(), v.to_vec()))
        })
        .unwrap()
    {}
    let mut damaged = false;
    for (k, v) in nodes {
        let mut on = store::obj::onode::Onode::decode(&v).unwrap();
        if on.flags & store::obj::onode::F_COMP != 0 {
            on.comp += 42;
            on.comp_orig += 100;
            let mut t = store::shard::Txn::new(0);
            t.put(&k, &on.encode());
            repair_raw(&mut r.st, t);
            damaged = true;
        }
    }
    assert!(damaged);
    r.st.checkpoint().unwrap();
    let report = r.st.repair(true).unwrap();
    assert!(!report.refused && report.after.is_empty(), "{report:?}");
    repair_assert_data(&mut r.st);
}

#[test]
fn offline_repair_corrects_missing_allocation() {
    let mut r = repair_fixture();
    let mut extents = Vec::new();
    let mut cur = store::tree::ScanCursor::new(&[T_EXT], &[T_EXT + 1]);
    while !r.st.shards[0]
        .tscan(&mut r.st.clk, &mut cur, 4096, &mut |_, v| {
            extents.push(store::obj::onode::Ext::decode(v).unwrap());
        })
        .unwrap()
    {}
    let mut t = store::shard::Txn::new(0);
    t.frees.push((extents[0].pba, extents[0].len()));
    repair_raw(&mut r.st, t);
    r.st.checkpoint().unwrap();
    // the repair mount fences the false free before replay; a plain mount does not
    let (b, n) = (extents[0].pba, extents[0].len());
    let img = r.disk.image();
    let (_, st) = open(&img, &r.sim, &r.cfg);
    assert!(!st.shards[0].sh.state().alloc.is_reserved(b, n));
    drop(st);
    r.cfg.shard.repair_counters = true;
    r.cfg.shard.repair_fence = true;
    let (_, st) = open(&img, &r.sim, &r.cfg);
    assert!(st.shards[0].sh.state().alloc.is_reserved(b, n));
    drop(st);
    let report = r.st.repair(false).unwrap();
    assert!(!report.refused && report.after.is_empty(), "{report:?}");
    assert!(
        report
            .before
            .iter()
            .any(|e| e.contains("referenced but unallocated"))
    );
    assert!(
        report
            .actions
            .iter()
            .any(|a| a.contains(&format!("allocated false-free blocks {b}+{n}"))),
        "{report:?}"
    );
    repair_assert_data(&mut r.st);
}

/// False-free extent of the fixture object `repair-a` (`b`, 4 blocks, bytes 0x31) or `repair-b` (2 blocks, 0x42),
/// freed durably and checkpointed.
fn repair_false_free(r: &mut Rig, blocks: u32) -> (u64, u32) {
    let mut extents = Vec::new();
    let mut cur = store::tree::ScanCursor::new(&[T_EXT], &[T_EXT + 1]);
    while !r.st.shards[0]
        .tscan(&mut r.st.clk, &mut cur, 4096, &mut |_, v| {
            extents.push(store::obj::onode::Ext::decode(v).unwrap());
        })
        .unwrap()
    {}
    let e = extents.iter().find(|e| e.len() == blocks).unwrap();
    let (b, n) = (e.pba, e.len());
    let mut t = store::shard::Txn::new(0);
    t.frees.push((b, n));
    repair_raw(&mut r.st, t);
    r.st.checkpoint().unwrap();
    (b, n)
}

/// Repair mount (fence before replay) of the crash image, repair, then the invariants every case shares.
fn repair_fenced_tail(r: &Rig, b: u64, n: u32, gone: Option<(&[u8], u32)>) {
    let img = r.disk.image();
    let mut cfg = r.cfg.clone();
    cfg.shard.repair_counters = true;
    cfg.shard.repair_fence = true;
    let (disk, mut st) = open(&img, &r.sim, &cfg);
    let report = st.repair(true).unwrap();
    assert!(!report.refused && report.after.is_empty(), "{report:?}");
    assert!(!st.shards[0].sh.state().alloc.is_reserved(b, n));
    match gone {
        None => {
            assert!(st.shards[0].sh.state().alloc.is_allocated(b, n));
            repair_assert_data(&mut st);
        }
        Some((name, hash)) => {
            assert!(!st.shards[0].sh.state().alloc.is_allocated(b, n));
            assert!(st.stat(&c1(), &g(name, hash)).unwrap().is_none());
            assert!(st.check(true).unwrap().errors.is_empty());
            fsck(st.shards[0].sh.dev(), &mut st.clk, Some(&fsck_refs)).unwrap();
            assert_eq!(
                st.read(&c1(), &g(b"repair-a", 1), 0, 16384).unwrap(),
                vec![0x31; 16384]
            );
        }
    }
    let used = st.shards[0].sh.state().alloc.n_alloc();
    let again = st.repair(true).unwrap();
    assert!(
        !again.refused && again.before.is_empty() && again.actions.is_empty(),
        "{again:?}"
    );
    assert!(again.after.is_empty());
    assert_eq!(st.shards[0].sh.state().alloc.n_alloc(), used);
    // the repaired image mounts plainly (no fence) and checks clean
    let img2 = disk.image();
    let (_, mut plain) = open(&img2, &r.sim, &r.cfg);
    assert!(plain.check(true).unwrap().errors.is_empty());
    fsck(plain.shards[0].sh.dev(), &mut plain.clk, Some(&fsck_refs)).unwrap();
}

/// An unreplayed WAL tail record allocates the very block the repair mount fenced as a false free: replay must
/// turn the reservation into the allocation, the repair finds nothing left to claim.
#[test]
fn offline_repair_fence_tail_allocates_false_free_block() {
    let mut r = repair_fixture();
    let (b, n) = repair_false_free(&mut r, 4);
    assert!(r.st.shards[0].sh.state_mut().alloc.reserve_named(b, n));
    let mut t = store::shard::Txn::new(0);
    t.data.push((b, vec![0x31; n as usize * 4096]));
    repair_raw(&mut r.st, t);
    repair_fenced_tail(&r, b, n, None);
}

/// An unreplayed WAL tail record frees (removes the object owning) a false-free block.
#[test]
fn offline_repair_fence_tail_frees_false_free_block() {
    let mut r = repair_fixture();
    let (b, n) = repair_false_free(&mut r, 2);
    // the live state held the block allocated when the tail record was written
    r.st.shards[0].sh.state_mut().alloc.apply_alloc_replay(b, n);
    let mut t = OTxn::new();
    t.push(TOp::Remove {
        cid: c1(),
        oid: g(b"repair-b", 2),
    });
    r.st.commit(&t).unwrap();
    repair_fenced_tail(&r, b, n, Some((b"repair-b", 2)));
}

#[test]
fn offline_repair_preserves_shared_and_external_value_references() {
    let mut r = repair_fixture();
    let attr = vec![0x53; 12288];
    let mut t = OTxn::new();
    t.setattr(c1(), &g(b"repair-a", 1), b"large", &attr);
    t.push(TOp::Clone {
        cid: c1(),
        src: g(b"repair-a", 1),
        dst: g(b"repair-c", 3),
    });
    r.st.commit(&t).unwrap();
    r.st.checkpoint().unwrap();
    assert!(r.st.check(true).unwrap().shared_runs > 0);
    repair_add_leak(&mut r.st);
    let report = r.st.repair(true).unwrap();
    assert!(!report.refused && report.after.is_empty(), "{report:?}");
    repair_assert_data(&mut r.st);
    assert_eq!(
        r.st.read(&c1(), &g(b"repair-c", 3), 0, 16384).unwrap(),
        vec![0x31; 16384]
    );
    assert_eq!(
        r.st.getattr(&c1(), &g(b"repair-a", 1), b"large").unwrap(),
        Some(attr.clone())
    );
    assert_eq!(
        r.st.getattr(&c1(), &g(b"repair-c", 3), b"large").unwrap(),
        Some(attr.clone())
    );
}

#[test]
fn offline_repair_refuses_undecodable_header_extent() {
    let mut r = repair_fixture();
    let header = vec![0x51; 12288];
    let mut t = OTxn::new();
    t.push(TOp::OmapSetHeader {
        cid: c1(),
        oid: g(b"repair-a", 1),
        header: TxnBytes::Borrowed(&header),
    });
    r.st.commit(&t).unwrap();
    r.st.checkpoint().unwrap();
    assert!(r.st.check(true).unwrap().errors.is_empty());
    let mut headers = Vec::new();
    let mut cur = store::tree::ScanCursor::new(&[T_HDR], &[T_HDR + 1]);
    while !r.st.shards[0]
        .tscan(&mut r.st.clk, &mut cur, 4096, &mut |k, v| {
            headers.push((k.to_vec(), v.to_vec()));
        })
        .unwrap()
    {}
    let (key, value) = &headers[0];
    let (_, extent) = store::obj::onode::vext(value).expect("external header fixture");
    let (pba, len) = (extent.pba(), extent.len());
    let mut damage = store::shard::Txn::new(0);
    damage.put(key, &value[..5]);
    repair_raw(&mut r.st, damage);
    r.st.checkpoint().unwrap();
    let report = r.st.repair(true).unwrap();
    assert!(report.refused && report.actions.is_empty(), "{report:?}");
    assert!(
        report
            .after
            .iter()
            .any(|e| e.contains("bad header value extent"))
    );
    assert!(r.st.shards[0].sh.state().alloc.is_allocated(pba, len));
    assert_eq!(
        r.st.read(&c1(), &g(b"repair-a", 1), 0, 16384).unwrap(),
        vec![0x31; 16384]
    );
}

/// A data extent record that no longer decodes hides its blocks from the ownership census: repair must refuse instead
/// of reclaiming them as leaked (data loss), and the blocks stay allocated.
#[test]
fn offline_repair_refuses_undecodable_data_extent() {
    let mut r = repair_fixture();
    let mut extents = Vec::new();
    let mut cur = store::tree::ScanCursor::new(&[T_EXT], &[T_EXT + 1]);
    while !r.st.shards[0]
        .tscan(&mut r.st.clk, &mut cur, 4096, &mut |k, v| {
            extents.push((k.to_vec(), v.to_vec()))
        })
        .unwrap()
    {}
    let (key, value) = extents[0].clone();
    let e = store::obj::onode::Ext::decode(&value).unwrap();
    let mut damage = store::shard::Txn::new(0);
    damage.put(&key, &value[..3]);
    repair_raw(&mut r.st, damage);
    r.st.checkpoint().unwrap();
    let report = r.st.repair(false).unwrap();
    assert!(report.refused && report.actions.is_empty(), "{report:?}");
    assert!(
        report.after.iter().any(|e| e.contains("bad extent record")),
        "{report:?}"
    );
    assert!(r.st.shards[0].sh.state().alloc.is_allocated(e.pba, e.len()));
}

/// An omap LSM run record under a key of the wrong length would hide the run's blocks from the census: refused.
#[test]
fn offline_repair_refuses_malformed_lsm_run_key() {
    let mut r = repair_fixture();
    let mut damage = store::shard::Txn::new(0);
    let mut key = store::shard::LSM_RUN_PREFIX.to_vec();
    key.extend_from_slice(&[1, 2, 3]);
    damage.put(&key, &[0; 16]);
    repair_raw(&mut r.st, damage);
    r.st.checkpoint().unwrap();
    let report = r.st.repair(false).unwrap();
    assert!(report.refused && report.actions.is_empty(), "{report:?}");
    assert!(
        report
            .after
            .iter()
            .any(|e| e.contains("malformed omap LSM run key")),
        "{report:?}"
    );
}

/// Damage shared counts in both directions, alias equal-sized exclusive runs, or free a live run.
fn repair_damage_ownership(st: &mut St, case: u8) {
    if case == 1 || case == 3 || case == 4 {
        let mut t = OTxn::new();
        t.push(TOp::Clone {
            cid: c1(),
            src: g(b"repair-a", 1),
            dst: g(b"repair-c", 3),
        });
        st.commit(&t).unwrap();
        st.checkpoint().unwrap();
    }
    let mut entries = Vec::new();
    let mut cur = store::tree::ScanCursor::new(&[T_EXT], &[T_EXT + 1]);
    while !st.shards[0]
        .tscan(&mut st.clk, &mut cur, 4096, &mut |k, v| {
            entries.push((k.to_vec(), v.to_vec()))
        })
        .unwrap()
    {}
    let mut t = store::shard::Txn::new(0);
    if case == 0 || case == 3 {
        let e = store::obj::onode::Ext::decode(&entries[0].1).unwrap();
        t.frees.push((e.pba, e.len()));
    }
    if case == 1 || case == 3 || case == 4 {
        let e = store::obj::onode::Ext::decode(&entries[0].1).unwrap();
        t.put(
            &store::obj::keys::ref_key(e.pba),
            &store::obj::onode::ref_encode(e.len(), 99),
        );
        if case == 4 {
            t.del(&store::obj::keys::ref_key(e.pba));
        }
    }
    if case == 2 || case == 3 {
        let source = store::obj::onode::Ext::decode(&entries[0].1).unwrap();
        let mut dest = store::obj::onode::Ext::decode(&entries[1].1).unwrap();
        dest.pba = source.pba;
        dest.crcs = source.crcs[..dest.len() as usize].to_vec();
        dest.shared = false;
        t.put(&entries[1].0, &dest.encode());
    }
    repair_raw(st, t);
    st.checkpoint().unwrap();
}

fn repair_snapshot(st: &mut St, clone: bool) -> Vec<Vec<u8>> {
    let a = st.stat(&c1(), &g(b"repair-a", 1)).unwrap().unwrap().size;
    let b = st.stat(&c1(), &g(b"repair-b", 2)).unwrap().unwrap().size;
    let mut data = vec![
        st.read(&c1(), &g(b"repair-a", 1), 0, a).unwrap(),
        st.read(&c1(), &g(b"repair-b", 2), 0, b).unwrap(),
    ];
    if clone {
        data.push(st.read(&c1(), &g(b"repair-c", 3), 0, 16384).unwrap());
    }
    data
}

/// Include mount reads, its epoch write and the cell-allocation checkpoint in the IO cut matrix, then the
/// ordinary ownership-repair txns. Odd block offsets also prove classification is not limited to page addresses.
#[test]
fn offline_repair_false_free_meta_and_mixed_crash_matrix() {
    META_PCT.set(1);
    let mut r = repair_fixture();
    META_PCT.set(8);
    let value = vec![0x65; 1000];
    let keys: Vec<_> = (0..300).map(|i| format!("attr{i:04}")).collect();
    let mut t = OTxn::new();
    for key in &keys {
        t.setattr(c1(), &g(b"repair-a", 1), key.as_bytes(), &value);
    }
    r.st.commit(&t).unwrap();
    r.st.checkpoint().unwrap();
    repair_damage_ownership(&mut r.st, 3);
    repair_add_leak(&mut r.st);
    assert!(r.st.shards[0].sh.state().tree.meta.cell_used() > 0);
    let cells = r.st.shards[0].sh.meta_cells();
    assert!(!cells.is_empty());
    let mut t = store::shard::Txn::new(0);
    // Partial and whole false-free extents in the same persisted cell set.
    for (i, &(b, n)) in cells.iter().enumerate() {
        let offset = (i % 2) as u64;
        t.frees.push((b + offset, (n - offset) as u32));
    }
    repair_raw(&mut r.st, t);
    r.st.checkpoint().unwrap();
    assert!(r.st.shards[0].sh.state().tree.meta.cell_used() > 0);
    // A WAL tail the repair mount replays after its fence: one mount checkpoint publishes both.
    let mut t = OTxn::new();
    t.setattr(c1(), &g(b"repair-b", 2), b"tail", &value);
    r.st.commit(&t).unwrap();
    assert!(r.st.shards[0].sh.durable_lsn() > r.st.shards[0].sh.ckpt_lsn());
    let want = repair_snapshot(&mut r.st, true);
    let img = r.disk.image();
    let plan =
        store::fsck::repair_plan(r.st.shards[0].sh.dev(), &mut r.st.clk, &fsck_refs).unwrap();
    assert!(!plan[0].missing_meta.is_empty());
    assert!(!plan[0].missing.is_empty());
    assert!(!plan[0].leaks.is_empty());
    assert!(!plan[0].relocate.is_empty());
    assert!(plan[0].refs.is_some());
    let disk = SimDisk::from_image(&img, r.sim.clone());
    let normal = Store::mount(|| disk.queue(), SimClock::default(), r.cfg.clone());
    assert!(normal.is_err(), "ordinary mount must refuse");
    assert!(
        fsck(
            &mut disk.queue(),
            &mut SimClock::default(),
            Some(&fsck_refs)
        )
        .is_err()
    );
    assert_eq!(disk.stats().writes, 0);
    r.cfg.shard.repair_fence = true;
    r.cfg.shard.repair_counters = true;
    // The same complete mount/repair runs in the CLI's read-only overlay, for success and checksum refusal.
    for corrupt in [false, true] {
        let mut preview_img = img.clone();
        if corrupt {
            let mut entries = Vec::new();
            let mut cur = store::tree::ScanCursor::new(&[T_EXT], &[T_EXT + 1]);
            while !r.st.shards[0]
                .tscan(&mut r.st.clk, &mut cur, 4096, &mut |_, v| {
                    entries.push(v.to_vec())
                })
                .unwrap()
            {}
            let ext = store::obj::onode::Ext::decode(&entries[0]).unwrap();
            preview_img.corrupt(ext.pba * (4096 / u64::from(preview_img.lba_size)), 0, 1);
        }
        let disk = SimDisk::from_image(&preview_img, r.sim.clone());
        let over = store::dev::Overlay::default();
        let (mut preview, _) = Store::mount(
            || store::dev::CowDev::new(disk.queue(), over.clone()),
            SimClock::default(),
            r.cfg.clone(),
        )
        .unwrap();
        let report = preview.repair(true).unwrap();
        assert_eq!(report.refused, corrupt, "{report:?}");
        assert_eq!(disk.stats().writes, 0);
        assert_eq!(disk.stats().deallocs, 0);
        assert!(!over.borrow().is_empty());
    }
    let (disk, mut st) = open(&img, &r.sim, &r.cfg);
    // Mount alone must have durably allocated the cell, even with no WAL suffix to trigger a replay checkpoint.
    let mut ordinary_cfg = r.cfg.clone();
    ordinary_cfg.shard.repair_fence = false;
    ordinary_cfg.shard.repair_counters = false;
    let (_, ordinary) = open(&disk.image(), &r.sim, &ordinary_cfg);
    drop(ordinary);
    let report = st.repair(true).unwrap();
    assert!(!report.refused && report.after.is_empty(), "{report:?}");
    assert!(
        report
            .actions
            .iter()
            .any(|a| a.contains("mount checkpoint allocated metadata blocks")),
        "{report:?}"
    );
    let events = disk.events();
    eprintln!("metadata repair crash matrix: {events} IO events, three policies");
    for cut in 1..=events {
        if cut % 100 == 0 {
            eprintln!("metadata repair crash matrix: cut {cut}/{events}");
        }
        for policy in [
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ] {
            let disk = SimDisk::from_image(&img, r.sim.clone());
            disk.arm_crash(cut);
            if let Ok((mut st, _)) =
                Store::mount(|| disk.queue(), SimClock::default(), r.cfg.clone())
            {
                let _ = st.repair(true);
            }
            disk.crash_now();
            let recovered = disk.crash_image(policy);
            let (_, mut st) = open(&recovered, &r.sim, &r.cfg);
            let report = st.repair(true).unwrap();
            assert!(
                !report.refused && report.after.is_empty(),
                "cut {cut} {policy:?}: {report:?}"
            );
            assert_eq!(repair_snapshot(&mut st, true), want, "cut {cut} {policy:?}");
            for i in 0..300 {
                assert_eq!(
                    st.getattr(&c1(), &g(b"repair-a", 1), format!("attr{i:04}").as_bytes())
                        .unwrap(),
                    Some(value.clone())
                );
            }
            assert_eq!(
                st.getattr(&c1(), &g(b"repair-b", 2), b"tail").unwrap(),
                Some(value.clone())
            );
            fsck(st.shards[0].sh.dev(), &mut st.clk, Some(&fsck_refs)).unwrap();
            let again = st.repair(true).unwrap();
            assert!(again.before.is_empty() && again.actions.is_empty() && again.after.is_empty());
        }
    }
}

#[test]
fn offline_repair_ownership_and_mixed_crash_matrix() {
    for case in 0..5 {
        let mut r = repair_fixture();
        repair_damage_ownership(&mut r.st, case);
        repair_add_leak(&mut r.st);
        let clone = case == 1 || case == 3 || case == 4;
        let want = repair_snapshot(&mut r.st, clone);
        let img = r.disk.image();
        r.cfg.shard.repair_counters = true;
        r.cfg.shard.repair_fence = true;
        let (disk, mut st) = open(&img, &r.sim, &r.cfg);
        let start = disk.events();
        let report = st.repair(true).unwrap();
        assert!(
            !report.refused && report.after.is_empty(),
            "case {case}: {report:?}"
        );
        let events = disk.events() - start;
        assert_eq!(repair_snapshot(&mut st, clone), want);
        for cut in 1..=events {
            for policy in [
                CrashPolicy::DROP_ALL,
                CrashPolicy::PERSIST_ALL,
                CrashPolicy::MIXED,
            ] {
                let (disk, mut st) = open(&img, &r.sim, &r.cfg);
                disk.arm_crash(disk.events() + cut);
                let _ = st.repair(true);
                disk.crash_now();
                let recovered = disk.crash_image(policy);
                drop(st);
                let (_, mut st) = open(&recovered, &r.sim, &r.cfg);
                let report = st.repair(true).unwrap();
                assert!(
                    !report.refused && report.after.is_empty(),
                    "case {case} cut {cut}: {report:?}"
                );
                assert_eq!(
                    repair_snapshot(&mut st, clone),
                    want,
                    "case {case} cut {cut}"
                );
                fsck(st.shards[0].sh.dev(), &mut st.clk, Some(&fsck_refs)).unwrap();
                assert!(st.check(true).unwrap().errors.is_empty());
            }
        }
    }
}

#[test]
fn offline_repair_copies_value_and_compressed_aliases() {
    for compressed in [false, true] {
        let mut r = repair_fixture();
        let a = vec![0x31; 16384];
        let b = vec![0x42; 16384];
        let av = vec![0x51; 12288];
        let bv = vec![0x62; 12288];
        let mut t = OTxn::new();
        if compressed {
            t.comp = Some(cspec(Alg::Lz4));
            t.write(c1(), &g(b"repair-a", 1), 0, &a);
            t.write(c1(), &g(b"repair-b", 2), 0, &b);
        } else {
            t.setattr(c1(), &g(b"repair-a", 1), b"large", &av);
            t.setattr(c1(), &g(b"repair-b", 2), b"large", &bv);
        }
        r.st.commit(&t).unwrap();
        r.st.checkpoint().unwrap();
        let tag = if compressed {
            T_EXT
        } else {
            store::obj::keys::T_ATTR
        };
        let mut entries = Vec::new();
        let mut cur = store::tree::ScanCursor::new(&[tag], &[tag + 1]);
        while !r.st.shards[0]
            .tscan(&mut r.st.clk, &mut cur, 4096, &mut |k, v| {
                entries.push((k.to_vec(), v.to_vec()))
            })
            .unwrap()
        {}
        assert_eq!(entries.len(), 2);
        if compressed {
            assert!(
                store::obj::onode::Ext::decode(&entries[0].1)
                    .unwrap()
                    .comp
                    .is_some()
            );
        }
        let mut damage = store::shard::Txn::new(0);
        damage.put(&entries[1].0, &entries[0].1);
        repair_raw(&mut r.st, damage);
        r.st.checkpoint().unwrap();
        let want = repair_snapshot(&mut r.st, false);
        let attr = if compressed {
            None
        } else {
            r.st.getattr(&c1(), &g(b"repair-b", 2), b"large").unwrap()
        };
        let report = r.st.repair(false).unwrap();
        assert!(!report.refused && report.after.is_empty(), "{report:?}");
        assert_eq!(repair_snapshot(&mut r.st, false), want);
        if !compressed {
            assert_eq!(
                r.st.getattr(&c1(), &g(b"repair-b", 2), b"large").unwrap(),
                attr
            );
        }
        fsck(r.st.shards[0].sh.dev(), &mut r.st.clk, Some(&fsck_refs)).unwrap();
        assert!(r.st.check(true).unwrap().errors.is_empty());
    }
}

#[test]
fn offline_repair_refuses_alias_with_bad_checksum_without_deep() {
    let mut r = repair_fixture();
    repair_damage_ownership(&mut r.st, 2);
    let mut entries = Vec::new();
    let mut cur = store::tree::ScanCursor::new(&[T_EXT], &[T_EXT + 1]);
    while !r.st.shards[0]
        .tscan(&mut r.st.clk, &mut cur, 4096, &mut |k, v| {
            entries.push((k.to_vec(), v.to_vec()))
        })
        .unwrap()
    {}
    let mut ext = store::obj::onode::Ext::decode(&entries[1].1).unwrap();
    ext.crcs[0] ^= 1;
    let mut damage = store::shard::Txn::new(0);
    damage.put(&entries[1].0, &ext.encode());
    repair_raw(&mut r.st, damage);
    r.st.checkpoint().unwrap();
    let before = r.disk.image();
    let report = r.st.repair(false).unwrap();
    assert!(report.refused && report.actions.is_empty(), "{report:?}");
    assert!(report.after.iter().any(|e| e.contains("checksum mismatch")));
    let after = r.disk.image();
    for lba in 0..before.lba_count {
        assert_eq!(after.read_lba(lba), before.read_lba(lba));
    }
}

#[test]
fn offline_repair_relocation_splits_at_device_transfer_limit() {
    let mut r = repair_fixture();
    let bytes = vec![0x42; 16384];
    let mut t = OTxn::new();
    t.write(c1(), &g(b"repair-b", 2), 0, &bytes);
    r.st.commit(&t).unwrap();
    r.st.checkpoint().unwrap();
    repair_damage_ownership(&mut r.st, 2);
    let want = repair_snapshot(&mut r.st, false);
    let img = r.disk.image();
    r.sim.max_xfer_lbas = 2; // 8 KiB transfer; the aliased extent spans 16 KiB.
    let (_, mut st) = open(&img, &r.sim, &r.cfg);
    let report = st.repair(true).unwrap();
    assert!(!report.refused && report.after.is_empty(), "{report:?}");
    assert_eq!(repair_snapshot(&mut st, false), want);
    fsck(st.shards[0].sh.dev(), &mut st.clk, Some(&fsck_refs)).unwrap();
}

/// A consistent refcount layout the daemon produced (runs split by a clone_range that was removed again) differs from
/// the canonical rebuild; repair must leave it alone: no finding, no write.
#[test]
fn offline_repair_keeps_consistent_split_refcounts() {
    let mut r = repair_fixture();
    let mut t = OTxn::new();
    t.push(TOp::Clone {
        cid: c1(),
        src: g(b"repair-a", 1),
        dst: g(b"repair-c", 3),
    });
    t.push(TOp::CloneRange {
        cid: c1(),
        src: g(b"repair-a", 1),
        dst: g(b"repair-d", 4),
        src_off: 8192,
        len: 8192,
        dst_off: 0,
    });
    r.st.commit(&t).unwrap();
    let mut t = OTxn::new();
    t.remove(c1(), &g(b"repair-d", 4));
    r.st.commit(&t).unwrap();
    r.st.checkpoint().unwrap();
    let mut recs = Vec::new();
    let mut cur = store::tree::ScanCursor::new(&[T_REF], &[T_REF + 1]);
    while !r.st.shards[0]
        .tscan(&mut r.st.clk, &mut cur, 4096, &mut |k, v| {
            recs.push((k.to_vec(), v.to_vec()))
        })
        .unwrap()
    {}
    assert!(recs.len() >= 2, "split refcount runs expected: {recs:?}");
    fsck(r.st.shards[0].sh.dev(), &mut r.st.clk, Some(&fsck_refs)).unwrap();
    let report = r.st.repair(true).unwrap();
    assert!(
        report.before.is_empty() && report.actions.is_empty() && report.after.is_empty(),
        "{report:?}"
    );
}
