// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Replica fan-out blob (4 MiB write): rebuild the v9 blob from the skeleton payload + msgr2 data-segment crc.
//! before = `encode_v9` (copy) then `crc32c` pass; after = `encode_v9_crc` (copy fused with crc, combine).
//! `cargo run --release -p replwire --example bench_blob`.
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SpgT};
use replwire::{Data, Transaction, TxnOp};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let payload: Vec<u8> = (0..4usize << 20).map(|i| (i * 7) as u8).collect();
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(SpgT {
        pgid: PgT { pool: 1, seed: 2 },
        shard: ShardId::NO_SHARD,
    }));
    let o = t.obj(&Ghobject::new(
        Hobject {
            oid: vec![1; 3],
            ..Hobject::MIN()
        },
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    ));
    t.push(
        c,
        TxnOp::Write {
            oid: o,
            off: 0,
            data: Data::new(&payload),
        },
    );
    let n = 400;
    for round in 0..2 {
        let s = Instant::now();
        for _ in 0..n {
            let b = t.encode_v9().unwrap();
            black_box(crc::crc32c(!0, &b));
        }
        let a = s.elapsed().as_secs_f64() / n as f64;
        let s = Instant::now();
        for _ in 0..n {
            black_box(t.encode_v9_crc().unwrap());
        }
        let b = s.elapsed().as_secs_f64() / n as f64;
        if round == 1 {
            let mib = 4.0;
            println!(
                "copy + crc pass: {:.0} us ({:.2} GB/s)   fused: {:.0} us ({:.2} GB/s)   speedup {:.2}x",
                a * 1e6,
                mib * 1.048576 / a / 1e3,
                b * 1e6,
                mib * 1.048576 / b / 1e3,
                a / b
            );
        }
    }
}
