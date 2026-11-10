// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Cost of scrub's mapper check on a PG whose snap mapper holds many entries (doc/perf/snapmap-scan-20261108.md): the
//! per-chunk `snapmap_check` (every scrub) must not read the whole mapper; the unparseable-key walk
//! (`snapmap_key_scan`) runs on the first chunk of a deep scrub only. Prints the wall time of both. Run:
//! `cargo test --release -p storeadapt --test snapmap_scan_cost -- --ignored --nocapture`
mod common;
use common::*;
use denc::types::*;
use peering::store::{PgStoreOps, StoreOp, StoreTxn};
use std::time::Instant;

const ENTRIES: u64 = 100_000;
const BATCH: u64 = 1000;

#[test]
#[ignore = "bench"]
fn snapmap_scan_cost() {
    let (_disk, mut ad, _sim) = new_adapter(512, 1, 11);
    let s = spg(1, 0);
    let mut t = StoreTxn::default();
    t.push(StoreOp::CreatePg);
    ad.submit(s, &t);
    for b in 0..ENTRIES / BATCH {
        let keys: Vec<Vec<u8>> = (0..BATCH)
            .map(|i| {
                let n = b * BATCH + i;
                let h = Hobject::new(format!("o{n}").as_bytes(), SnapId(n + 2), n as u32, 1, b"");
                peering::snaps::rev_key(&h)
            })
            .collect();
        let mut txn = store::obj::OTxn::new();
        for k in &keys {
            txn.omap_set(CollT::Pg(s), &storeadapt::snapmap::mapper_obj(s), k, b"v");
        }
        ad.with_store(|st| st.commit(&txn)).unwrap();
    }
    let t0 = Instant::now();
    let (_ops, msgs) = ad.snapmap_check(s, &Hobject::MIN(), &Hobject::MAX());
    let check_ms = t0.elapsed().as_secs_f64() * 1e3;
    assert!(msgs.is_empty(), "{msgs:?}");
    let t0 = Instant::now();
    let found = ad.snapmap_key_scan(s);
    eprintln!(
        "{ENTRIES} mapper entries: first-chunk check {check_ms:.1} ms; key scan (deep only) {:.1} ms ({} msgs)",
        t0.elapsed().as_secs_f64() * 1e3,
        found.len()
    );
}
