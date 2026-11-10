// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Micro-benchmarks of cls list/trim paths on MemCtx (ignored; MemCtx reads are memcpy, so the
//! numbers show cls-side CPU only). Run:
//! `cargo test --release -p cls --test micro_bench -- --ignored --nocapture --test-threads 1`
mod common;
use cls::mem::MemStore;
use cls::queue;
use common::*;
use std::time::Instant;

fn env_(body: &[u8]) -> Vec<u8> {
    let mut o = vec![1, 1];
    o.extend((body.len() as u32).to_le_bytes());
    o.extend(body);
    o
}
fn bl(x: &[u8]) -> Vec<u8> {
    let mut o = (x.len() as u32).to_le_bytes().to_vec();
    o.extend(x);
    o
}
fn time(name: &str, iters: u32, mut f: impl FnMut()) {
    f();
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns = t.elapsed().as_nanos() / iters as u128;
    println!("BENCH {name}: {ns} ns/call");
}

#[test]
#[ignore]
fn bench_queue_list_1000x200() {
    let mut s = MemStore::new();
    s.objects.insert("q".into(), Default::default());
    let init = queue::InitOp {
        queue_size: 1 << 20,
        max_urgent_data_size: 0,
        bl_urgent_data: vec![],
    };
    ok(&mut s, "q", "queue", "queue_init", &e(&init));
    let enq = queue::EnqueueOp {
        bl_data_vec: (0..1000).map(|i| vec![i as u8; 200]).collect(),
    };
    ok(&mut s, "q", "queue", "queue_enqueue", &e(&enq));
    let op = e(&queue::ListOp {
        max: 1000,
        start_marker: vec![],
        end_marker: vec![],
    });
    time("queue_list_entries max=1000 x 200 B", 2000, || {
        ok(&mut s, "q", "queue", "queue_list_entries", &op);
    });
}

#[test]
#[ignore]
fn bench_fifo_part_list_and_trim() {
    let mut s = MemStore::new();
    let params = cat(&[
        &(8u64 << 20).to_le_bytes(),
        &(512u64 << 10).to_le_bytes(),
        &(8u64 << 20).to_le_bytes(),
    ]);
    ok(
        &mut s,
        "p",
        "fifo",
        "init_part",
        &env_(&cat(&[&bl(b""), &env_(&params)])),
    );
    for _ in 0..10 {
        let bufs: Vec<Vec<u8>> = (0..100).map(|i| vec![i as u8; 200]).collect();
        let mut b = bl(b"");
        b.extend(100u32.to_le_bytes());
        for x in &bufs {
            b.extend(bl(x));
        }
        b.extend(20_000u64.to_le_bytes());
        assert_eq!(call(&mut s, "p", "fifo", "push_part", &env_(&b)).ret, 100);
    }
    let list = env_(&cat(&[&[0], &0u64.to_le_bytes(), &1000i32.to_le_bytes()]));
    time("fifo part_list max=1000 x 200 B", 2000, || {
        ok(&mut s, "p", "fifo", "part_list", &list);
    });
    let reply: cls::fifo::ListPartReply = d(&ok(&mut s, "p", "fifo", "part_list", &list));
    let last = reply.entries.last().unwrap().ofs;
    let trim = env_(&cat(&[&[0], &last.to_le_bytes(), &[1]]));
    time(
        "fifo trim_part exclusive (repeated at the last entry)",
        20000,
        || {
            ok(&mut s, "p", "fifo", "trim_part", &trim);
        },
    );
}
