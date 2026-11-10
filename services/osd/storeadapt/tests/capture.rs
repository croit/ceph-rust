// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Real classic-OSD replication frames (testdata/replwire/cap/frames.bin): every captured MOSDRepOp
//! transaction (with its pg log entries) is applied to the NVMe store and to `MemStore`; the PGs must end up
//! identical, also after a clean remount.
mod common;
use common::*;
use denc::types::*;
use messages::Segments;
use peering::store::{MemStore, PgStoreOps, StoreOp, StoreTxn};
use pgwire::LogEntry;
use replwire::{MOSDRepOp, ReplMsg, TxnOp, decode_repl};
use std::collections::BTreeMap;

fn frames() -> Vec<(u16, u16, Segments)> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/replwire/cap/frames.bin");
    let b = std::fs::read(p).unwrap();
    let mut p = 0;
    let mut v = Vec::new();
    while p < b.len() {
        let u16at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let l: Vec<usize> = (0..3)
            .map(|i| {
                u32::from_le_bytes(b[p + 6 + 4 * i..p + 10 + 4 * i].try_into().unwrap()) as usize
            })
            .collect();
        let mut o = p + 18;
        let mut take = |n: usize| {
            let s = b[o..o + n].to_vec();
            o += n;
            s
        };
        let (front, middle, data) = (take(l[0]), take(l[1]), take(l[2]));
        v.push((
            u16at(p),
            u16at(p + 2),
            Segments {
                front_zc: Vec::new(),
                front_hints: Default::default(),
                front,
                middle,
                data: data.into(),
            },
        ));
        p = o;
    }
    v
}

#[test]
fn captured_repops_apply_like_memstore() {
    let (mut disk, mut ad, sim) = new_adapter(512, 4, 3);
    let mut mem = MemStore::new();
    let mut created = BTreeMap::<SpgT, usize>::new();
    let (mut nrep, mut nops, mut nwrites, mut bytes) = (0, 0, 0u64, 0u64);
    let mut kinds = std::collections::BTreeSet::new();
    for (ty, ver, segs) in frames() {
        let Some(ReplMsg::RepOp(op)) = decode_repl(ty, ver, &segs).unwrap() else {
            continue;
        };
        let op: MOSDRepOp = op;
        let spg = op.pgid;
        if created.insert(spg, 0).is_none() {
            let t = StoreTxn {
                ops: vec![StoreOp::CreatePg],
            };
            mem.submit(spg, &t);
            ad.submit(spg, &t);
        }
        let mut t = StoreTxn::default();
        if !op.logbl.is_empty() {
            let es: Vec<LogEntry> = denc::from_slice(&op.logbl).unwrap();
            if !es.is_empty() {
                t.push(StoreOp::LogAppend(es));
            }
        }
        let tx = op.txn(replwire::DEFAULT_PAGE).unwrap();
        for o in &tx.ops {
            nops += 1;
            kinds.insert(o.op.code());
            if let TxnOp::Write { data, .. } = &o.op {
                nwrites += 1;
                bytes += data.len() as u64;
            }
        }
        t.push(StoreOp::ApplyTxn {
            middle: op.txn_middle.clone(),
            data: op.txn_data.clone(),
        });
        mem.submit(spg, &t);
        ad.submit(spg, &t);
        nrep += 1;
        *created.get_mut(&spg).unwrap() += 1;
        if nrep % 25 == 0 {
            assert_same(&mem, &ad, spg, "capture");
            assert_same_objects(&mem, &ad, spg, "capture");
        }
    }
    println!(
        "captured repops applied: {nrep}, ops {nops}, writes {nwrites} ({bytes} bytes), op codes {kinds:?}, pgs {}",
        created.len()
    );
    assert!(nrep > 20 && nwrites > 5);
    for spg in created.keys() {
        assert_same(&mem, &ad, *spg, "capture end");
        assert_same_objects(&mem, &ad, *spg, "capture end");
    }
    ad.with_store(|st| st.checkpoint().unwrap());
    let img = disk.image();
    drop(ad);
    let (d, ad) = open(&img, &sim, &store::obj::StoreCfg::default());
    disk = d;
    let _ = &disk;
    for spg in created.keys() {
        assert_same(&mem, &ad, *spg, "capture remount");
        assert_same_objects(&mem, &ad, *spg, "capture remount");
    }
    let rep = ad.with_store(|st| st.check(true)).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert!(!mem.objects(*created.keys().next().unwrap()).is_empty());
}
