// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
//! Sessionless recovery reads must not mistake a suspended client's credit for damage.
#![cfg(all(feature = "splinterdb", feature = "lab"))]
mod common;
use common::*;
use denc::types::*;
use peering::store::{PgStoreOps, StoreOp, StoreTxn};
use replwire::ObjectRecoveryProgress;
use replwire::txn::*;
use std::time::{Duration, Instant};
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, ObjError, QueueBuilder, Queued, Store, StoreCfg, TOp};

struct Temp(std::path::PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture(tag: &str) -> (Temp, Ad) {
    let root =
        std::env::temp_dir().join(format!("sdb-recovery-credit-{tag}-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let temp = Temp(root.clone());
    let disk = SimDisk::new(SimConfig::new(128 << 20));
    let (sb, _) = mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
            wal_blocks: 1024,
            align_blocks: 1,
            omap_splinterdb: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut foreign = store::splinter_omap::Config::new(root, 128 << 20);
    foreign.allow_non_nvme = true;
    store::splinter_omap::create(&foreign, &sb, 64 << 20).unwrap();
    let mut cfg = StoreCfg::default();
    cfg.shard.splinterdb = Some(foreign);
    cfg.shard.cache_pages = 32768;
    let (st, _) = Store::mount(|| disk.queue(), SimClock::default(), cfg).unwrap();
    (temp, Ad::new(st))
}

fn rows(from: u32, to: u32, salt: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
    (from..to)
        .map(|i| (i.to_be_bytes().to_vec(), (i ^ salt).to_le_bytes().to_vec()))
        .collect()
}

fn seed(ad: &Ad, pg: SpgT, h: &Hobject, salt: u32) -> Ghobject {
    ad.submit_create(pg);
    let g = Ghobject::new(h.clone(), Ghobject::NO_GEN, pg.shard);
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(pg));
    let ox = t.obj(&g);
    let oi = oi_bytes(h, Eversion::new(1, 1), 0);
    let kv = rows(0, 1100, salt);
    t.push(cx, TxnOp::Touch { oid: ox });
    t.push(
        cx,
        TxnOp::SetAttr {
            oid: ox,
            name: b"_",
            value: &oi,
        },
    );
    t.push(
        cx,
        TxnOp::OmapSetHeader {
            oid: ox,
            header: b"hdr",
        },
    );
    t.push(
        cx,
        TxnOp::OmapSetKeys {
            oid: ox,
            pairs: kv
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect(),
        },
    );
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        },
    )
    .unwrap();
    g
}

fn gauge(ad: &Ad, name: &str) -> u64 {
    ad.with_store(|st| {
        st.perf_counters()
            .into_iter()
            .find(|(n, _, _)| *n == name)
            .unwrap()
            .2
    })
}

#[test]
fn held_client_scan_survives_replicated_and_ec_recovery_on_the_same_shard() {
    let (_temp, ad) = fixture("direct");
    let pg = spg(1, 0);
    let other = spg(1, 1);
    let h = Hobject::new(b"held", SnapId::NOSNAP, 0, 1, b"");
    let recovered = Hobject::new(b"recovered", SnapId::NOSNAP, 1, 1, b"");
    let g = seed(&ad, pg, &h, 17);
    seed(&ad, other, &recovered, 37);
    ad.with_store(|st| st.checkpoint()).unwrap();
    assert_eq!(gauge(&ad, "splinter_active_bytes"), 0);
    assert_eq!(gauge(&ad, "splinter_frozen_bytes"), 0);
    let ri = ad.recovery_info(other, &recovered).unwrap();
    let owner = (7, 1);
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        let sliced = ad.with_store(|st| {
            st.set_nonblock_reads(true);
            st.read_session(Some(owner), false);
            let r = st.omap_range(&CollT::Pg(pg), &g, b"", b"", 1024, usize::MAX, true);
            assert_eq!(r, Err(ObjError::WouldBlock));
            assert!(st.take_blocked());
            let sliced = st.take_rm_progress();
            st.read_session(None, true);
            st.set_nonblock_reads(false);
            st.poll(&mut Vec::new()).unwrap();
            sliced
        });
        if sliced {
            break;
        }
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT parking real scan owner"
        );
        std::thread::yield_now();
    }
    let charge = gauge(&ad, "splinter_scan_output_charge_bytes");
    let window = gauge(&ad, "splinter_scan_charged_bytes");
    assert!(
        charge > 0 && window > 0,
        "park an actual partially consumed 1024-row answer"
    );

    // A different tagged request must still yield, including blocking fallback.
    let contender = || {
        ad.with_store(|st| {
            st.read_session(Some((7, 2)), false);
            st.set_nonblock_reads(false);
            assert_eq!(
                st.omap_iter(&CollT::Pg(pg), &g, b"", 1),
                Err(ObjError::WouldBlock)
            );
            assert!(st.take_blocked() && st.take_local_wait());
            st.read_session(None, true);
        })
    };
    contender();
    let mut progress = ObjectRecoveryProgress::default();
    for chunk in 0..11u32 {
        let op = ad
            .build_push(other, &ri, &progress, 1 << 20, 100)
            .expect("sessionless recovery must not report credit contention as I/O damage");
        assert_eq!(
            op.omap_entries.into_iter().collect::<Vec<_>>(),
            rows(chunk * 100, (chunk + 1) * 100, 37)
        );
        if chunk == 0 {
            assert_eq!(op.omap_header, b"hdr");
        }
        progress = op.after_progress;
        assert_eq!(progress.omap_complete, chunk == 10);
        assert_eq!(gauge(&ad, "splinter_scan_output_charge_bytes"), charge);
        assert_eq!(gauge(&ad, "splinter_scan_charged_bytes"), window);
    }
    assert!(progress.is_complete());
    let (ec, complete) = ad
        .ec_omap_read(other, &recovered, None, 1 << 20, 100)
        .unwrap();
    assert_eq!(ec, rows(0, 100, 37));
    assert!(!complete);
    let absent = Hobject::new(b"absent", SnapId::NOSNAP, 3, 1, b"");
    assert_eq!(ad.ec_omap_read(other, &absent, None, 1 << 20, 100), Err(-2));
    contender();
    assert_eq!(gauge(&ad, "splinter_scan_output_charge_bytes"), charge);
    assert_eq!(gauge(&ad, "splinter_scan_charged_bytes"), window);

    loop {
        let r = ad.with_store(|st| {
            st.set_nonblock_reads(true);
            st.read_session(Some(owner), true);
            let r = st.omap_range(&CollT::Pg(pg), &g, b"", b"", 1024, usize::MAX, true);
            let blocked = st.take_blocked();
            st.read_session(None, blocked);
            st.set_nonblock_reads(false);
            st.poll(&mut Vec::new()).unwrap();
            r
        });
        match r {
            Err(ObjError::WouldBlock) => {
                assert!(Instant::now() < end, "WARNING TIMEOUT resuming held scan");
                std::thread::yield_now();
            }
            r => {
                assert_eq!(r.unwrap(), (rows(0, 1024, 17), true));
                break;
            }
        }
    }
    assert_eq!(gauge(&ad, "splinter_scan_output_charge_bytes"), 0);
    // The completed window stays charged for the listing's next request; idle
    // expiry or the next non-matching worker turn releases it.
    assert!(gauge(&ad, "splinter_scan_charged_bytes") > 0);
}

#[test]
fn held_client_scan_survives_recovery_visibility_drain_of_a_credit_blocked_clone() {
    queued_clone_visibility(false);
}

#[test]
fn held_client_scan_survives_foreign_reading_queue_builder_and_fifo_follower() {
    queued_clone_visibility(true);
}

struct ReadClone {
    cid: CollT,
    src: Ghobject,
    dst: Ghobject,
    oi: Vec<u8>,
}
impl QueueBuilder<SimDev, SimClock> for ReadClone {
    fn build(&mut self, st: &mut Store<SimDev, SimClock>) -> store::obj::Result<Option<OTxn<'_>>> {
        let mode = st.begin_nonblock();
        assert!(
            mode.0,
            "native read/allocation admission must remain nonblocking"
        );
        st.end_nonblock(mode);
        let point = st.omap_get(&self.cid, &self.src, &[&7u32.to_be_bytes()])?;
        assert_eq!(point.into_iter().collect::<Vec<_>>(), rows(7, 8, 37));
        assert_eq!(
            st.omap_iter(&self.cid, &self.src, b"", 1100)?,
            (rows(0, 1100, 37), false)
        );
        let mut t = OTxn::new();
        t.push(TOp::Clone {
            cid: self.cid,
            src: self.src.clone(),
            dst: self.dst.clone(),
        });
        t.setattr(self.cid, &self.dst, b"_", &self.oi);
        Ok(Some(t))
    }
    fn retained_bytes(&self) -> usize {
        1024 + self.oi.len()
    }
}

fn queued_clone_visibility(builder: bool) {
    let (_temp, ad) = fixture(if builder {
        "queued-builder"
    } else {
        "queued-clone"
    });
    let (pg, other) = (spg(1, 0), spg(1, 1));
    let h = Hobject::new(b"held", SnapId::NOSNAP, 0, 1, b"");
    let source = Hobject::new(b"source", SnapId::NOSNAP, 1, 1, b"");
    let target = Hobject::new(b"target", SnapId::NOSNAP, 2, 1, b"");
    let g = seed(&ad, pg, &h, 17);
    let src = seed(&ad, other, &source, 37);
    let dst = Ghobject::new(target.clone(), Ghobject::NO_GEN, other.shard);
    ad.with_store(|st| st.checkpoint()).unwrap();
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        let sliced = ad.with_store(|st| {
            st.set_nonblock_reads(true);
            st.read_session(Some((7, 1)), false);
            assert_eq!(
                st.omap_range(&CollT::Pg(pg), &g, b"", b"", 1024, usize::MAX, true),
                Err(ObjError::WouldBlock)
            );
            assert!(st.take_blocked());
            let sliced = st.take_rm_progress();
            st.read_session(None, true);
            st.set_nonblock_reads(false);
            st.poll(&mut Vec::new()).unwrap();
            sliced
        });
        if sliced {
            break;
        }
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT queued-clone scan owner"
        );
        std::thread::yield_now();
    }
    let charge = gauge(&ad, "splinter_scan_output_charge_bytes");
    let window = gauge(&ad, "splinter_scan_charged_bytes");
    assert!(charge > 0 && window > 0);
    let oi = oi_bytes(&target, Eversion::new(1, 1), 0);
    let mut clone = OTxn::new();
    clone.push(TOp::Clone {
        cid: CollT::Pg(other),
        src: src.clone(),
        dst: dst.clone(),
    });
    clone.setattr(CollT::Pg(other), &dst, b"_", &oi);
    let mut follower = OTxn::new();
    follower.setattr(CollT::Pg(other), &dst, b"after", b"fifo");
    ad.with_store(|st| {
        if builder {
            assert_eq!(
                st.queue_builder(
                    &[CollT::Pg(other)],
                    9001,
                    Box::new(ReadClone {
                        cid: CollT::Pg(other),
                        src,
                        dst: dst.clone(),
                        oi: oi.clone(),
                    }),
                    false
                )
                .unwrap(),
                Queued::Pending(9001)
            );
            st.poll(&mut Vec::new()).unwrap();
        } else {
            assert_eq!(st.queue(&clone, 9001).unwrap(), Queued::Pending(9001));
        }
        assert!(
            st.take_local_wait(),
            "first try actually refused on A's foreign credit"
        );
        assert_eq!(st.queue(&follower, 9002).unwrap(), Queued::Pending(9002));
        assert_eq!(st.queued_count(), 2);
    });
    // A real metadata/recovery visibility fence must drain B without running or expiring A.
    let started = Instant::now();
    let ri = ad
        .recovery_info(other, &target)
        .expect("queued clone must become visible without false IO damage");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "credit owner must not be expired to drain the FIFO"
    );
    let push = ad
        .build_push(
            other,
            &ri,
            &ObjectRecoveryProgress::default(),
            1 << 20,
            1100,
        )
        .unwrap();
    assert_eq!(
        push.omap_entries.into_iter().collect::<Vec<_>>(),
        rows(0, 1100, 37)
    );
    assert_eq!(
        ad.with_store(|st| st.getattr(&CollT::Pg(other), &dst, b"after"))
            .unwrap(),
        Some(b"fifo".to_vec())
    );
    assert_eq!(gauge(&ad, "splinter_scan_output_charge_bytes"), charge);
    assert_eq!(gauge(&ad, "splinter_scan_charged_bytes"), window);
    let mut acks = Vec::new();
    loop {
        let done = ad.with_store(|st| {
            st.poll(&mut acks).unwrap();
            st.read_session(Some((7, 1)), true);
            st.set_nonblock_reads(true);
            let r = st.omap_range(&CollT::Pg(pg), &g, b"", b"", 1024, usize::MAX, true);
            let blocked = st.take_blocked();
            st.read_session(None, blocked);
            st.set_nonblock_reads(false);
            match r {
                Err(ObjError::WouldBlock) => false,
                r => {
                    assert_eq!(r.unwrap(), (rows(0, 1024, 17), true));
                    true
                }
            }
        });
        if done {
            break;
        }
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT resuming A after queued clone"
        );
    }
    while !acks.contains(&9002) {
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT durable FIFO acknowledgements"
        );
        ad.with_store(|st| {
            st.poll(&mut acks).unwrap();
            st.idle();
        });
    }
    assert_eq!(
        acks.into_iter()
            .filter(|t| *t == 9001 || *t == 9002)
            .collect::<Vec<_>>(),
        vec![9001, 9002]
    );
}

struct RecursiveDrain;
impl QueueBuilder<SimDev, SimClock> for RecursiveDrain {
    fn build(&mut self, st: &mut Store<SimDev, SimClock>) -> store::obj::Result<Option<OTxn<'_>>> {
        st.drain_queued()?;
        Ok(None)
    }
    fn retained_bytes(&self) -> usize {
        1
    }
}

#[test]
fn recursive_builder_drain_cannot_overtake_followers_and_barrier_error_restores_scope() {
    let (_temp, ad) = fixture("recursive");
    let pg = spg(1, 0);
    let h = Hobject::new(b"target", SnapId::NOSNAP, 0, 1, b"");
    let g = seed(&ad, pg, &h, 17);
    ad.with_store(|st| st.checkpoint()).unwrap();
    let mut next = OTxn::new();
    next.setattr(CollT::Pg(pg), &g, b"after", b"fifo");
    ad.with_store(|st| {
        assert_eq!(st.queue_builder(&[CollT::Pg(pg)], 9101, Box::new(RecursiveDrain), false).unwrap(), Queued::Pending(9101));
        assert_eq!(st.queue(&next, 9102).unwrap(), Queued::Pending(9102));
        assert!(matches!(st.drain_queued(), Err(ObjError::Invalid(s)) if s.contains("recursive queue drain")));
        assert_eq!(st.queued_count(), 1, "follower must not execute inside its builder's recursive poll");
        let mut errors = Vec::new();
        st.take_queue_errors(&mut errors);
        assert!(matches!(errors.as_slice(), [(9101, ObjError::Invalid(_))]));
        // An ordinary error must close every loan/expiry scope: a second barrier
        // must be admissible, and the follower still executes only after its head.
        st.drain_queued().unwrap();
        assert_eq!(st.queued_count(), 0);
        assert_eq!(st.getattr(&CollT::Pg(pg), &g, b"after").unwrap(), Some(b"fifo".to_vec()));
    });
}
