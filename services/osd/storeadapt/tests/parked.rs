// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Phase A FIFO: retained wire input, shared-store barriers and deferred error ordering.
mod common;
use common::*;
use denc::types::*;
use peering::WriteErr;
use peering::store::{PgStoreOps, Queued, StoreOp, StoreTxn};
use replwire::txn::{Transaction, TxnOp};
use store::obj::{OTxn, ObjError};

fn object(i: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(format!("obj-{i}").as_bytes(), SnapId::NOSNAP, i, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}
fn write(s: SpgT, val: u8) -> StoreTxn {
    let data = [val; 4096];
    let mut wire = Transaction::new();
    let c = wire.coll(&CollT::Pg(s));
    let o = wire.obj(&object(500));
    wire.push(
        c,
        TxnOp::Write {
            oid: o,
            off: 0,
            data: data.as_slice().into(),
        },
    );
    StoreTxn {
        ops: vec![StoreOp::ApplyTxn {
            middle: Default::default(),
            data: wire.encode_v9().unwrap().into(),
        }],
    }
}
fn cold() -> (store::dev::SimDisk, Ad, SpgT) {
    let (disk, ad, sim) = new_adapter(64, 1, 850);
    let s = spg(1, 0);
    ad.submit_create(s);
    ad.with_store(|st| {
        // 2000 objects: more tree pages than the 64-page cache holds even with full run pages (adr 0021 am. 35)
        for batch in 0..40 {
            let mut t = OTxn::new();
            for i in batch * 50..(batch + 1) * 50 {
                t.write(CollT::Pg(s), &object(i), 0, &[0x31; 4096]);
            }
            st.commit(&t).unwrap();
        }
        st.checkpoint().unwrap();
    });
    let img = disk.image();
    drop(ad);
    let (disk, ad) = open(&img, &sim, &Default::default());
    (disk, ad, s)
}

fn congested_shard_fixture() -> (Ad, SpgT, SpgT, Ghobject) {
    let (disk, ad, sim) = new_adapter(128, 2, 851);
    let (a, b) = (spg(1, 0), spg(1, 1));
    ad.submit_create(a);
    ad.submit_create(b);
    let o = object(500);
    ad.with_store(|st| {
        for batch in 0..20 {
            let mut t = OTxn::new();
            for i in batch * 50..(batch + 1) * 50 {
                t.write(CollT::Pg(a), &object(i), 0, &[0x31; 4096]);
            }
            st.commit(&t).unwrap();
        }
        let mut t = OTxn::new();
        t.write(CollT::Pg(b), &o, 0, &[0x32; 4096]);
        st.commit(&t).unwrap();
        st.checkpoint().unwrap();
    });
    let image = disk.image();
    drop(ad);
    let mut cfg = store::obj::StoreCfg::default();
    cfg.shard.cache_pages = 24;
    let (_, mut ad) = open(&image, &sim, &cfg);
    ad.with_store(|st| {
        st.set_queue_limits(16, 1 << 30);
        st.read(&CollT::Pg(b), &o, 0, 4096).unwrap();
    });
    struct Hold;
    impl store::obj::QueueBuilder<store::dev::SimDev, store::dev::SimClock> for Hold {
        fn build(
            &mut self,
            _: &mut store::obj::Store<store::dev::SimDev, store::dev::SimClock>,
        ) -> store::obj::Result<Option<OTxn<'_>>> {
            Err(ObjError::WouldBlock)
        }
        fn retained_bytes(&self) -> usize {
            0
        }
    }
    ad.with_store(|st| {
        st.queue_builder(&[CollT::Pg(a)], u64::MAX, Box::new(Hold), false)
            .unwrap()
    });
    for token in 1..=7 {
        assert_eq!(ad.queue(a, &write(a, 0x41), token), Queued::Pending);
    }
    assert_eq!(ad.with_store(|st| st.queued_count()), 8);
    assert!(!ad.admission_ready());
    (ad, a, b, o)
}

#[test]
fn unrelated_shard_queue_does_not_keep_the_replica_probe_cold() {
    let (adapter, a, b, _) = congested_shard_fixture();
    for _ in 0..300 {
        adapter.probe_cold_for(b);
    }
    assert!(!adapter.probe_cold_for(b));
    assert!(adapter.probe_cold_for(a));
    assert!(!adapter.probe_cold_for(b));
}

#[test]
fn congested_shard_does_not_block_another_shards_warm_read() {
    let (ad, a, b, o) = congested_shard_fixture();
    assert!(!ad.warm(a, &o.hobj, 0, 4096));
    assert!(ad.warm(b, &o.hobj, 0, 4096));
    assert_eq!(ad.with_store(|st| st.queued_count()), 8);
}

fn unrelated_shard_reads_and_durable_writes(n: usize) -> (usize, u128) {
    let (mut ad, a, b, o) = congested_shard_fixture();
    let start = std::time::Instant::now();
    let deadline = start + std::time::Duration::from_secs(10);
    let mut finished = 0;
    let mut done = Vec::new();
    for i in 0..n {
        assert!(
            std::time::Instant::now() < deadline,
            "WARNING TIMEOUT unrelated shard reads and durable writes exceeded 10s ({i}/{n} done)"
        );
        if !ad.warm(b, &o.hobj, 0, 4096) {
            break;
        }
        assert_eq!(
            ad.with_store(|st| st.read(&CollT::Pg(b), &o, 0, 4096).unwrap()),
            vec![0x32; 4096]
        );
        let token = 100 + i as u64;
        assert_eq!(ad.queue(b, &write(b, 0x32), token), Queued::Pending);
        let mut durable = false;
        for _ in 0..10_000 {
            assert!(
                std::time::Instant::now() < deadline,
                "WARNING TIMEOUT unrelated shard reads and durable writes exceeded 10s ({i}/{n} done)"
            );
            ad.poll_store(&mut done);
            if done.iter().any(|&(pg, t)| pg == b && t == token) {
                durable = true;
                break;
            }
            ad.with_store(|st| st.idle());
        }
        assert!(
            durable,
            "B failed to become durable while A remained stalled"
        );
        assert!(!ad.admission_ready_for(a));
        assert_eq!(ad.with_store(|st| st.queued_count()), 8);
        finished += 1;
        done.clear();
    }
    (finished, start.elapsed().as_nanos())
}

#[test]
fn congested_shard_keeps_other_shards_reads_and_writes_running() {
    assert_eq!(unrelated_shard_reads_and_durable_writes(100).0, 100);
}

#[test]
#[ignore = "local destination admission read/write benchmark"]
fn perf_unrelated_shard_reads_and_writes() {
    let (finished, ns) = unrelated_shard_reads_and_durable_writes(1000);
    println!(
        "unrelated_shard_read_write_pairs={finished}/1000 elapsed_ns={ns} pairs_per_sec={}",
        finished as u128 * 1_000_000_000 / ns.max(1)
    );
}

#[test]
#[ignore = "local destination admission benchmark"]
fn perf_unrelated_shard_admission() {
    let (ad, _, b, o) = congested_shard_fixture();
    let start = std::time::Instant::now();
    let mut ready = 0;
    for _ in 0..10_000 {
        ready += usize::from(ad.warm(b, &o.hobj, 0, 4096));
    }
    println!(
        "unrelated_shard_ready={ready}/10000 probe_ns={}",
        start.elapsed().as_nanos() / 10000
    );
}

#[test]
fn shared_metadata_commit_drives_builders_and_preserves_read_context_and_acks() {
    let (_disk, mut ad, s) = cold();
    let st = ad.shared();
    let before = st.borrow().clk.t;
    assert_eq!(ad.queue(s, &write(s, 0x41), 1), Queued::Pending);
    assert_eq!(ad.queue(s, &write(s, 0x42), 2), Queued::Pending);
    assert_eq!(ad.queue(s, &StoreTxn::default(), 3), Queued::Pending);
    assert_eq!(st.borrow().clk.t, before);
    assert!(st.borrow().queued_count() > 0);
    assert!(
        !st.borrow_mut().take_blocked(),
        "builder must not leak WouldBlock into client executor"
    );
    {
        let mut st = st.borrow_mut();
        st.set_nonblock_reads(true);
        assert_eq!(
            st.read(&CollT::Pg(s), &object(500), 0, 4096),
            Err(ObjError::WouldBlock)
        );
        assert!(st.take_blocked());
        st.set_nonblock_reads(false);
        let mut barrier = OTxn::new();
        barrier.write(CollT::Pg(s), &object(500), 0, &[0x43; 4096]);
        st.commit(&barrier).unwrap();
        assert_eq!(st.queued_count(), 0);
        assert_eq!(
            st.read(&CollT::Pg(s), &object(500), 0, 4096).unwrap(),
            vec![0x43; 4096]
        );
    }
    let mut acked = Vec::new();
    ad.poll_commits(&mut acked);
    assert_eq!(acked, vec![(s, 1), (s, 2), (s, 3)]);
    assert_eq!(ad.pending(), 0);
    assert!(ad.failed().is_none());
}

#[test]
fn deferred_bad_input_reports_its_token_before_any_later_pg_apply() {
    let (_disk, mut ad, s) = cold();
    let first = ad.with_store(|st| st.shards[0].sh.next_lsn());
    assert_eq!(ad.queue(s, &write(s, 0x41), 1), Queued::Pending);
    let bad = StoreTxn {
        ops: vec![StoreOp::ApplyTxn {
            middle: Default::default(),
            data: bytes::Bytes::from_static(&[0xFF; 16]),
        }],
    };
    assert_eq!(ad.queue(s, &bad, 2), Queued::Pending);
    assert_eq!(ad.queue(s, &write(s, 0x43), 3), Queued::Pending);
    let deadline = ad.with_store(|st| st.clk.t + 30_000_000_000);
    for _ in 0..100_000 {
        ad.poll_commits(&mut Vec::new());
        if ad.failed().is_some() {
            break;
        }
        ad.with_store(|st| {
            assert!(st.clk.t < deadline);
            st.idle();
        });
    }
    assert!(ad.failed().is_some());
    let errors = ad.queue_errors.borrow();
    assert_eq!(errors.len(), 1);
    assert_eq!((errors[0].0, errors[0].1), (s, 2));
    assert!(Ad::is_input_error(&errors[0].2));
    assert_eq!(ad.with_store(|st| st.shards[0].sh.next_lsn()), first + 1);
    assert_eq!(ad.with_store(|st| st.queued_count()), 1);
}

#[test]
fn collection_creation_drains_pending_input_before_the_barrier() {
    let (_disk, mut ad, s) = cold();
    assert_eq!(ad.queue(s, &write(s, 0x41), 1), Queued::Pending);
    let child = spg(1, 1);
    assert_eq!(
        ad.queue(
            child,
            &StoreTxn {
                ops: vec![StoreOp::CreatePg]
            },
            2
        ),
        Queued::Durable
    );
    assert_eq!(ad.with_store(|st| st.queued_count()), 0);
    assert!(
        ad.with_store(|st| st.coll_exists(&CollT::Pg(child)))
            .unwrap()
    );
    let mut a = Vec::new();
    ad.poll_commits(&mut a);
    assert_eq!(a, vec![(s, 1)]);
}

/// Big txn of `n` omap keys on one object of `s`: over the store's size floors, so `check_write` runs the exact
/// size pre-flight (`Store::check_txn`).
fn big_omap(s: SpgT, n: usize) -> bytes::Bytes {
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(s));
    let o = t.obj(&object(900));
    let ks: Vec<String> = (0..n).map(|i| format!("key-{i:07}")).collect();
    let v = vec![0x5a; 2000];
    t.push(
        c,
        TxnOp::OmapSetKeys {
            oid: o,
            pairs: ks.iter().map(|k| (k.as_bytes(), v.as_slice())).collect(),
        },
    );
    t.encode_v9().unwrap().into()
}

#[test]
fn writes_of_other_pgs_queue_behind_a_pending_shard_fifo() {
    // No shard write gate (adr 0082 am. 2): a txn parked for PG `s` does not hold the writes of PG `b` (same shard) in
    // the op gate; they queue behind it in the FIFO and complete in FIFO order. Only a big txn's exact size pre-flight
    // waits for the empty FIFO, refused non-blocking (`WriteErr::Blocked`, no simulated time passes).
    let (_disk, mut ad, s) = cold();
    let b = spg(1, 1);
    ad.submit_create(b);
    assert!(ad.warm_log(b, Eversion::default()));
    assert_eq!(ad.queue(s, &write(s, 0x41), 1), Queued::Pending);
    assert!(ad.with_store(|st| st.shard_queued(&CollT::Pg(b))).unwrap());
    let now = ad.with_store(|st| st.clk.t);
    opexec::ObjView::ov_cause_begin(&ad);
    assert!(ad.warm_log(b, Eversion::default()));
    assert_eq!(
        opexec::ObjView::ov_refusal(&ad),
        opexec::view::gate_why::STORE,
        "no refusal recorded"
    );
    let big = big_omap(b, 300);
    let empty = bytes::Bytes::new();
    assert_eq!(ad.check_write(b, &empty, &big), Err(WriteErr::Blocked));
    assert_eq!(
        ad.with_store(|st| st.clk.t),
        now,
        "nothing waited on the PG core"
    );
    assert_eq!(ad.queue(b, &write(b, 0x42), 2), Queued::Pending);
    ad.with_store(|st| st.sync()).unwrap();
    let mut a = Vec::new();
    ad.poll_commits(&mut a);
    assert_eq!(a, vec![(s, 1), (b, 2)]);
    assert_eq!(
        ad.with_store(|st| st.read(&CollT::Pg(b), &object(500), 0, 4096))
            .unwrap(),
        vec![0x42; 4096]
    );
    let mut rounds = 0;
    loop {
        match ad.check_write(b, &empty, &big) {
            Ok(()) => break,
            Err(WriteErr::Blocked) => ad.with_store(|st| st.wait_loads()).unwrap(),
            Err(e) => panic!("{e:?}"),
        }
        rounds += 1;
        assert!(
            rounds < 64,
            "the pre-flight passes once the FIFO is empty and its loads are in"
        );
    }
    assert!(ad.failed().is_none());
}

#[test]
fn full_shard_fifo_blocks_instead_of_rejecting_a_logged_pg_txn() {
    // Admission throttles input before the hard cap, but one admitted event (an osdmap from the exempt mon link)
    // can persist many PGs of one shard. Rejected = fail-stop, so the hard cap must drain, never refuse.
    let (_disk, mut ad, s) = cold();
    ad.with_store(|st| st.set_queue_limits(2, 1 << 20));
    assert_eq!(ad.queue(s, &write(s, 0x41), 1), Queued::Pending);
    assert_eq!(ad.queue(s, &write(s, 0x42), 2), Queued::Pending);
    assert!(!ad.with_store(|st| st.admission_ready()));
    assert_eq!(ad.queue(s, &write(s, 0x43), 3), Queued::Pending);
    assert!(ad.failed().is_none());
    ad.with_store(|st| st.sync()).unwrap();
    let mut a = Vec::new();
    ad.poll_commits(&mut a);
    assert_eq!(a, vec![(s, 1), (s, 2), (s, 3)]);
    assert_eq!(
        ad.with_store(|st| st.read(&CollT::Pg(s), &object(500), 0, 4096))
            .unwrap(),
        vec![0x43; 4096]
    );
}

/// Review 2026-11-03 #10: a PG txn whose PG collection does not exist is dropped by the store; the PG already logged it
/// in memory, so it is a local failure (fail-stop), never `Durable`. An empty txn stays durable at once.
#[test]
fn orphan_write_fails_the_store_and_is_never_durable() {
    let (_d, mut ad, _) = new_adapter(32, 1, 1);
    let o = spg(1, 0);
    assert_eq!(ad.queue(o, &StoreTxn::default(), 1), Queued::Durable);
    assert!(ad.failed().is_none());
    let r = ad.queue(o, &write(o, 0x41), 2);
    assert!(
        matches!(r, Queued::Failed(_)),
        "write to a PG the store does not hold: {r:?}"
    );
    assert_eq!(ad.orphan_writes.get(), 1);
    assert!(ad.failed().is_some());
    assert!(ad.load_pg(o).is_none());
}

/// The same orphan write translated later, from the shard FIFO: its token is never acked, the adapter fails.
#[test]
fn parked_orphan_write_fails_the_store_and_is_never_acked() {
    let (_disk, mut ad, s) = cold();
    let o = spg(1, 1);
    assert_eq!(ad.queue(s, &write(s, 0x41), 1), Queued::Pending);
    assert_eq!(ad.queue(o, &write(o, 0x42), 2), Queued::Pending);
    let deadline = ad.with_store(|st| st.clk.t + 30_000_000_000);
    let mut acked = Vec::new();
    while ad.failed().is_none() && !acked.contains(&(o, 2)) {
        ad.poll_commits(&mut acked);
        ad.with_store(|st| {
            assert!(st.clk.t < deadline, "neither acked nor failed");
            st.idle();
        });
    }
    assert!(
        !acked.contains(&(o, 2)),
        "dropped orphan write acked as durable: {acked:?}"
    );
    assert!(ad.failed().is_some());
    assert_eq!(ad.orphan_writes.get(), 1);
}
