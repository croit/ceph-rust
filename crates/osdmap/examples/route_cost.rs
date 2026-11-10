// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Per-op client send-path placement cost (profiling round, doc/perf/profile-rdma-20261021.md): ns per call of the pieces
//! `NativeSessions::route` + `PgWatch::track/untrack` run for EVERY op, on the real fixture map. Run:
//! `cargo run --release -p osdmap --example route_cost` (lab/rdma-spike/route-cost.sh). Output: one `name ns_per_call` line each.

use denc::types::PgT;
use osdmap::*;
use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

fn bench(name: &str, iters: u64, mut f: impl FnMut(u64)) {
    for i in 0..iters / 10 {
        f(i);
    }
    let t = Instant::now();
    for i in 0..iters {
        f(i);
    }
    println!("{name} {:.1}", t.elapsed().as_nanos() as f64 / iters as f64);
}

fn main() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/osdmap/full/0091.bin");
    let m = OsdMap::decode_from(&std::fs::read(p).unwrap()).unwrap();
    let (&pool_id, pool) = m
        .pools
        .iter()
        .find(|(_, p)| p.is_replicated() && p.size >= 2 && p.pg_num >= 8)
        .expect("replicated pool in the fixture");
    let n = pool.pg_num;
    let names: Vec<Vec<u8>> = (0..1024)
        .map(|i| format!("cell-c4kL-{i}").into_bytes())
        .collect();
    let iters = 2_000_000;
    bench("object_to_raw_pg+raw_pg_to_pg", iters, |i| {
        let raw = m
            .object_to_raw_pg(pool_id, &names[(i & 1023) as usize], b"", b"", -1)
            .unwrap();
        black_box(pool.raw_pg_to_pg(raw));
    });
    bench(
        "pg_to_up_acting (full CRUSH, every op today)",
        iters / 4,
        |i| {
            black_box(m.pg_to_up_acting(PgT::new(pool_id as u64, (i as u32) % n)));
        },
    );
    let mut w = PgWatch::default();
    w.observe(None, &m);
    // steady state of QD32: 32 PGs followed, track + untrack per op
    for s in 0..32 {
        w.track(PgT::new(pool_id as u64, s % n), m.epoch);
    }
    bench("PgWatch track+untrack (32 followed)", iters, |i| {
        let pg = PgT::new(pool_id as u64, (i as u32) % n);
        w.track(pg, m.epoch);
        w.untrack(black_box(pg));
    });
    bench("PgWatch interval_since", iters, |i| {
        black_box(w.interval_since(PgT::new(pool_id as u64, (i as u32) % n)));
    });
    // Fix 1: per-epoch memo hit (PG -> primary), std SipHash map vs PgHashMap (what NativeSessions uses now).
    let mut sip: std::collections::HashMap<PgT, i32> = Default::default();
    let mut fast: PgHashMap<i32> = Default::default();
    for s in 0..n {
        let pg = PgT::new(pool_id as u64, s);
        let p = m.pg_to_up_acting(pg).acting_primary;
        sip.insert(pg, p);
        fast.insert(pg, p);
    }
    bench("memo hit, std HashMap (SipHash)", iters, |i| {
        black_box(sip.get(&PgT::new(pool_id as u64, (i as u32) % n)));
    });
    bench("memo hit, PgHashMap (foldhash)", iters, |i| {
        black_box(fast.get(&PgT::new(pool_id as u64, (i as u32) % n)));
    });
}
