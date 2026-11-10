// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Cost of the PG log trim txn against a plain log append (doc/perf/pgtrim-20261031.md). Steady state of one PG: every
//! write appends one entry; every `BATCH`-th write also trims `BATCH` entries and keeps a dup window of `DUPS`.
//! Prints the mean wall time of `submit` per txn class. Run:
//! `cargo test --release -p storeadapt --test trim_cost -- --ignored --nocapture`
mod common;
use common::*;
use denc::types::*;
use peering::store::{PgStoreOps, StoreOp, StoreTxn};
use pgwire::LogOp;
use std::time::Instant;

const BATCH: u64 = 100;
const KEEP: u64 = 250;
const DUPS: u64 = 3000;
const WRITES: u64 = 3_000_000;

#[test]
#[ignore = "bench"]
fn trim_cost() {
    let (_disk, mut ad, _sim) = new_adapter(256, 1, 7);
    let s = spg(1, 0);
    let mut g = PgGen::new(s, 7);
    let mut t = StoreTxn::default();
    t.push(StoreOp::CreatePg);
    ad.submit(s, &t);
    let (mut plain, mut trim) = ((0f64, 0u64), (0f64, 0u64));
    for w in 1..=WRITES {
        let e = g.entry(LogOp::MODIFY);
        let mut t = StoreTxn::default();
        t.push(StoreOp::LogAppend(vec![e]));
        let is_trim = w % BATCH == 0 && w > KEEP + BATCH;
        if is_trim {
            let to = g.ver - KEEP;
            t.push(StoreOp::LogTrim {
                to: Eversion::new(g.epoch, to),
                dups_from: Some(Eversion::new(g.epoch, to.saturating_sub(DUPS).max(1))),
                tail_up: true,
            });
        }
        let t0 = Instant::now();
        ad.submit(s, &t);
        let us = t0.elapsed().as_secs_f64() * 1e6;
        if w > 5_000 {
            let c = if is_trim { &mut trim } else { &mut plain };
            c.0 += us;
            c.1 += 1;
        }
    }
    eprintln!(
        "plain append: {:.1} us (n={}); trim txn: {:.1} us (n={})",
        plain.0 / plain.1 as f64,
        plain.1,
        trim.0 / trim.1 as f64,
        trim.1
    );
}
