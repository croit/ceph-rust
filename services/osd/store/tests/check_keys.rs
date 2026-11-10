// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Online object check vs malformed tree keys (OSD data-safety review 2026-11-03 #16): an id-keyed record whose key is
//! shorter than its layout (`keys::idkey`) is reported as an error, never indexed past its end (a panic took the
//! checker down instead of reporting the damage).

use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use store::dev::{BlockDev, Clock, SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::keys::{T_ATTR, T_EXT, T_HDR, T_OMAP, T_ONODE};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, Store, StoreCfg, TOp};
use store::shard::{Event, Shard, Txn};
use store::state::Op;

fn open() -> Store<SimDev, SimClock> {
    let disk = SimDisk::new(SimConfig::new(64 << 20));
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards: 1,
        wal_blocks: 1024,
        align_blocks: 1,
        meta_pct: 8,
        ..Default::default()
    };
    mkfs(&mut dev, &mut clk, &p).unwrap();
    let d2 = disk.clone();
    let (st, _) =
        Store::mount(move || d2.queue(), SimClock::default(), StoreCfg::default()).unwrap();
    st
}

/// One object with data (an extent record) and an omap key.
fn fill(st: &mut Store<SimDev, SimClock>) {
    let cid = CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    });
    let oid = Ghobject::new(
        Hobject::new(b"obj", SnapId::NOSNAP, 0x1234, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    );
    let mut t = OTxn::new();
    t.push(TOp::MkColl {
        cid,
        bits: 0,
        exist_ok: true,
    });
    t.push(TOp::Write {
        cid,
        oid: oid.clone(),
        off: 0,
        data: TxnBytes::Owned(vec![7u8; 64 << 10]),
    });
    t.push(TOp::OmapSetKeys {
        cid,
        oid,
        pairs: vec![(
            TxnBytes::Owned(b"k".to_vec()),
            TxnBytes::Owned(b"v".to_vec()),
        )],
    });
    st.commit(&t).unwrap();
}

fn poll(s: &mut Shard<SimDev>, clk: &mut SimClock) -> bool {
    let mut ev = Vec::new();
    s.poll(clk.t, &mut ev);
    let mut acked = false;
    for e in ev {
        match e {
            Event::Acked(_) => acked = true,
            Event::Failed(f) => panic!("shard failed: {f:?}"),
            _ => {}
        }
    }
    let h = s.dev().next_deadline();
    clk.idle(h);
    acked
}

/// Put raw tree records (damage the store layer above would never write).
fn put_raw(s: &mut Shard<SimDev>, clk: &mut SimClock, recs: Vec<(Vec<u8>, Vec<u8>)>) {
    let mut t: Txn<Vec<u8>> = Txn::new(7);
    for (k, v) in recs {
        t.ops.push(Op::Put(k, v));
    }
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
        if poll(s, clk) {
            assert!(s.durable_lsn() >= lsn);
            return;
        }
    }
    panic!("raw records never acked");
}

/// A key longer than the scan's old scalar upper bound (600 bytes) is still scanned: the bound is derived from the
/// tree's key limit, so every key the tree holds (here an all-`0xFF` key above every tag) is reported.
#[test]
fn key_above_the_old_scan_bound_is_checked() {
    let mut st = open();
    fill(&mut st);
    put_raw(
        &mut st.shards[0].sh,
        &mut st.clk,
        vec![(vec![0xffu8; 601], vec![0u8; 4])],
    );
    let rep = st.check(false).unwrap();
    assert!(
        rep.errors
            .iter()
            .any(|m| m.contains("unknown key tag 0xff")),
        "{:?}",
        rep.errors
    );
}

#[test]
fn short_id_keys_are_reported_not_indexed() {
    let mut st = open();
    fill(&mut st);
    let clean = st.check(false).unwrap();
    assert!(clean.errors.is_empty(), "{:?}", clean.errors);
    // a well-formed extent value under a key without its block number: the decode succeeds, the key is short
    let ext_val = {
        let dump = st.shards[0].sh.dump_blocking(&mut st.clk).unwrap();
        dump.into_iter()
            .find(|(k, _)| k[0] == T_EXT)
            .expect("extent record")
            .1
    };
    let bad = vec![
        (vec![T_ONODE, 0, 0, 1], vec![0u8; 4]),
        (vec![T_EXT, 0, 0, 0, 0, 0, 0, 0, 9, 0], ext_val),
        (vec![T_HDR, 0, 0, 0, 0, 0, 0, 0, 9], vec![0]),
        (vec![T_ATTR, 0, 0, 1], vec![0]),
        (vec![T_OMAP, 0, 0, 0, 0, 0, 0, 0, 9], vec![0, 1]),
    ];
    let n = bad.len();
    put_raw(&mut st.shards[0].sh, &mut st.clk, bad);
    let rep = st.check(false).unwrap();
    let short: Vec<&String> = rep
        .errors
        .iter()
        .filter(|m| m.contains("bad key length"))
        .collect();
    assert_eq!(short.len(), n, "{:?}", rep.errors);
    for t in [T_ONODE, T_EXT, T_HDR, T_ATTR, T_OMAP] {
        let tag = format!("tag {t:#x}");
        assert!(short.iter().any(|m| m.contains(&tag)), "{tag}: {short:?}");
    }
}
