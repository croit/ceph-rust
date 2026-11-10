// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Object-layer check of omap on the omap LSM engine (adr 0610, phase 2b): the engine's live keys are counted and
//! reported like tree omap, and an object whose onode lost `F_OMAP` is reported the same way on both formats. A
//! store without the engine is the reference.

use denc::types::{Ghobject, Hobject, SnapId};
use store::dev::{BlockDev, Clock, SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::keys::T_ONODE;
use store::obj::onode::{F_OMAP, Onode};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, Store, StoreCfg, TOp};
use store::shard::{Event, Shard, Txn};
use store::state::Op;

const KEYS: usize = 200;

fn open(lsm: bool) -> Store<SimDev, SimClock> {
    let sim = SimConfig::new(64 << 20);
    let disk = SimDisk::new(sim);
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards: 1,
        wal_blocks: 1024,
        align_blocks: 1,
        meta_pct: 8,
        omap_lsm: lsm,
        ..Default::default()
    };
    mkfs(&mut dev, &mut clk, &p).unwrap();
    let d2 = disk.clone();
    let (st, _) =
        Store::mount(move || d2.queue(), SimClock::default(), StoreCfg::default()).unwrap();
    st
}

/// One collection with one omap object of `KEYS` keys.
fn fill(st: &mut Store<SimDev, SimClock>) -> Ghobject {
    let cid = denc::types::CollT::Pg(denc::types::SpgT {
        pgid: denc::types::PgT::new(1, 0),
        shard: denc::types::ShardId::NO_SHARD,
    });
    let oid = Ghobject::new(
        Hobject::new(b"obj", SnapId::NOSNAP, 0x1234, 1, b""),
        Ghobject::NO_GEN,
        denc::types::ShardId::NO_SHARD,
    );
    let mut t = OTxn::new();
    t.push(TOp::MkColl {
        cid,
        bits: 0,
        exist_ok: true,
    });
    t.push(TOp::Touch {
        cid,
        oid: oid.clone(),
    });
    let pairs: Vec<(TxnBytes, TxnBytes)> = (0..KEYS)
        .map(|i| {
            (
                TxnBytes::Owned(format!("k{i:05}").into_bytes()),
                TxnBytes::Owned(vec![(i % 251) as u8; 40]),
            )
        })
        .collect();
    t.push(TOp::OmapSetKeys {
        cid,
        oid: oid.clone(),
        pairs,
    });
    st.commit(&t).unwrap();
    oid
}

fn poll(s: &mut Shard<SimDev>, clk: &mut SimClock) -> Vec<u64> {
    let mut ev = Vec::new();
    s.poll(clk.t, &mut ev);
    let mut acked = Vec::new();
    for e in ev {
        match e {
            Event::Acked(t) => acked.push(t),
            Event::Failed(f) => panic!("shard failed: {f:?}"),
            _ => {}
        }
    }
    let h = s.dev().next_deadline();
    clk.idle(h);
    acked
}

/// Clear `F_OMAP` on the only onode (a damaged record: the keys are still there).
fn clear_omap_flag(s: &mut Shard<SimDev>, clk: &mut SimClock) {
    let dump = s.dump_blocking(clk).unwrap();
    let (k, v) = dump
        .iter()
        .find(|(k, _)| k[0] == T_ONODE)
        .expect("onode record");
    let mut on = Onode::decode(v).expect("onode");
    on.flags &= !F_OMAP;
    let mut t: Txn<Vec<u8>> = Txn::new(7);
    t.ops.push(Op::Put(k.clone(), on.encode()));
    let lsn = loop {
        match s.submit(t) {
            Ok(lsn) => break lsn,
            Err((store::StoreError::Busy | store::StoreError::WalFull, back)) => {
                poll(s, clk);
                t = back;
            }
            Err((e, _)) => panic!("submit: {e:?}"),
        }
    };
    for _ in 0..100_000 {
        if !poll(s, clk).is_empty() {
            assert!(s.durable_lsn() >= lsn);
            return;
        }
    }
    panic!("onode patch never acked");
}

#[test]
fn object_check_counts_engine_omap_like_tree_omap() {
    let mut engine = open(true);
    let mut tree = open(false);
    assert_eq!(
        fill(&mut engine),
        fill(&mut tree),
        "same object in both stores"
    );
    let e = engine.check(false).unwrap();
    let t = tree.check(false).unwrap();
    assert!(e.errors.is_empty(), "{:?}", e.errors);
    assert!(t.errors.is_empty(), "{:?}", t.errors);
    assert_eq!(e.omap_keys, KEYS as u64, "engine keys are counted");
    assert_eq!(e.omap_keys, t.omap_keys);
}

#[test]
fn object_check_reports_engine_keys_without_the_onode_flag() {
    let mut engine = open(true);
    let mut tree = open(false);
    fill(&mut engine);
    fill(&mut tree);
    clear_omap_flag(&mut engine.shards[0].sh, &mut engine.clk);
    clear_omap_flag(&mut tree.shards[0].sh, &mut tree.clk);
    let e = engine.check(false).unwrap();
    let t = tree.check(false).unwrap();
    assert_eq!(e.errors, t.errors, "same report on both formats");
    assert!(
        e.errors
            .iter()
            .any(|m| m.contains("omap keys without F_OMAP")),
        "{:?}",
        e.errors
    );
    assert_eq!(e.omap_keys, KEYS as u64, "the recount still sees them");
}

/// Engine keys of objects without an onode that live only in a run are found and reported, and the live object's keys
/// still count. Object ids are sparse (`lsn << 12 | seq`): the run's one chunk spans the two orphan ids with 2^30
/// absent ids between them, which the check must not visit one by one (it listed every id of a fence's span before).
#[test]
fn object_check_reports_engine_keys_of_dead_onodes_in_runs() {
    let mut st = open(true);
    let (lo, hi) = (3u64, (1 << 42) | 3);
    let batch = [lo, hi]
        .iter()
        .flat_map(|&id| {
            (0..20u32).map(move |i| {
                (
                    id,
                    bytes::Bytes::from(format!("orphan-{i:03}")),
                    bytes::Bytes::from_static(b"value"),
                )
            })
        })
        .collect();
    let (s, clk) = (&mut st.shards[0].sh, &mut st.clk);
    s.olsm_upgrade_batch(batch).unwrap();
    for _ in 0..100_000 {
        poll(s, clk);
        if s.olsm_flushed() {
            break;
        }
    }
    assert!(s.olsm_flushed(), "orphan batch never flushed");
    fill(&mut st);
    let rep = st.check(false).unwrap();
    for id in [lo, hi] {
        let e = format!("keys of dead onode {id}");
        assert!(
            rep.errors.iter().any(|m| m.ends_with(&e)),
            "{e}: {:?}",
            rep.errors
        );
    }
    assert_eq!(rep.errors.len(), 2, "{:?}", rep.errors);
}
