// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Single-core microbenchmarks of the msgr2 frame data path (review nt-wireperf, 2026-11-08): payload GB/s of one
//! thread per cell, crc and secure mode. Diagnostic only (no NIC, no store); compare arms on the same runner in release:
//! `cargo test --release -p msgr2 --test wire_perf -- --ignored --nocapture --test-threads=1`.
//! Output: one `wire_perf cell=<name> bytes=<payload> GB/s=<x>` line per cell.
use bytes::Bytes;
use msgr2::*;
use std::hint::black_box;
use std::time::{Duration, Instant};

const BIG: usize = 4 << 20;
const SMALL: usize = 4 << 10;
/// Measured time per cell (after a warm-up of a quarter of it).
const BUDGET: Duration = Duration::from_millis(600);

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn secret() -> ConnSecret {
    ConnSecret::new(&[7; 64]).unwrap()
}

fn encoder(rev: Revision, secure: bool) -> Encoder {
    let mut e = Encoder::new(rev);
    if secure {
        e.set_secure(&secret(), Role::Client).unwrap();
    }
    e
}

fn mode(rev: Revision, secure: bool) -> String {
    format!(
        "{}-{}",
        if secure { "secure" } else { "crc" },
        if rev == Revision::V21 { "v2.1" } else { "v2.0" }
    )
}

/// Run `f` (one operation on `bytes` payload bytes) for the budget and print its payload rate.
fn cell(name: &str, bytes: usize, mut f: impl FnMut()) {
    let warm = Instant::now();
    while warm.elapsed() < BUDGET / 4 {
        f();
    }
    let (t, mut n) = (Instant::now(), 0u64);
    while t.elapsed() < BUDGET {
        for _ in 0..16 {
            f();
        }
        n += 16;
    }
    println!(
        "wire_perf cell={name} bytes={bytes} GB/s={:.3}",
        bytes as f64 * n as f64 / t.elapsed().as_secs_f64() / 1e9
    );
}

/// NT-wireperf-01: a large front segment, partly fed, the rest received through a direct loan (copy + crc fused).
#[test]
#[ignore = "release microbenchmark"]
fn perf_rx_direct_front() {
    let segs = [payload(41, 1), payload(BIG, 2), Vec::new(), Vec::new()];
    let mut w = Vec::new();
    Encoder::new(Revision::V21)
        .encode_message(&segs[0], &segs[1], &segs[2], &segs[3], &mut w)
        .unwrap();
    let start = PREAMBLE_LEN + 41 + 4;
    let (cut, end) = (start + (128 << 10), start + BIG);
    cell("rx-direct-front-crc-v2.1", BIG, || {
        let mut d = Decoder::new(Revision::V21);
        d.feed(black_box(&w[..cut]));
        let (mut buf, mut crcs) = d.direct_take().unwrap();
        crcs.update_copy(&w[cut..end], &mut buf.spare_capacity_mut()[..end - cut]);
        // SAFETY: update_copy initialized the complete remaining segment.
        unsafe { buf.set_len(BIG) };
        d.direct_put(buf, crcs);
        d.feed(&w[end..]);
        black_box(d.poll_owned().unwrap().unwrap());
    });
}

/// NT-wireperf-02/03: a front rope (shared run inside the front) on the copying fallback (no reference sharing).
#[test]
#[ignore = "release microbenchmark"]
fn perf_tx_rope_fallback() {
    let rope = [(1, Bytes::from(payload(BIG, 3)))];
    let header = MsgHeader2::default().to_bytes();
    for (rev, secure) in [
        (Revision::V20, false),
        (Revision::V20, true),
        (Revision::V21, true),
    ] {
        let mut enc = encoder(rev, secure);
        let (mut out, mut chunks) = (Vec::with_capacity(BIG + 4096), Vec::new());
        cell(&format!("tx-rope-{}", mode(rev, secure)), BIG, || {
            out.clear();
            enc.encode_message_rope(
                &header,
                &[1, 2],
                black_box(&rope),
                &Default::default(),
                &[],
                &Bytes::new(),
                &Default::default(),
                &mut out,
                &mut chunks,
            )
            .unwrap();
            black_box(&out);
        });
    }
}

/// NT-wireperf-03: a data segment in two parts (replicated/EC multipart) on the copying path.
#[test]
#[ignore = "release microbenchmark"]
fn perf_tx_parts() {
    let data = Bytes::from(payload(BIG / 2, 4));
    let more = [(Bytes::from(payload(BIG / 2, 5)), Default::default())];
    let (front, header) = (payload(200, 6), MsgHeader2::default().to_bytes());
    for (rev, secure) in [
        (Revision::V20, false),
        (Revision::V20, true),
        (Revision::V21, true),
    ] {
        let mut enc = encoder(rev, secure);
        let (mut out, mut chunks) = (Vec::with_capacity(BIG + 4096), Vec::new());
        cell(&format!("tx-parts-{}", mode(rev, secure)), BIG, || {
            out.clear();
            enc.encode_message_parts(
                &header,
                &front,
                &[],
                black_box(&data),
                &Default::default(),
                black_box(&more),
                &mut out,
                &mut chunks,
            )
            .unwrap();
            black_box(&out);
        });
    }
}

/// NT-wireperf-03: contiguous messages through the copying emitter, large and small (small-frame overhead).
#[test]
#[ignore = "release microbenchmark"]
fn perf_tx_plain() {
    let (front, header) = (payload(200, 7), MsgHeader2::default().to_bytes());
    for size in [BIG, SMALL] {
        let data = payload(size, 8);
        for (rev, secure) in [
            (Revision::V21, false),
            (Revision::V20, true),
            (Revision::V21, true),
        ] {
            let mut enc = encoder(rev, secure);
            let mut out = Vec::with_capacity(size + 4096);
            cell(&format!("tx-plain-{}", mode(rev, secure)), size, || {
                out.clear();
                enc.encode_message(&header, &front, &[], black_box(&data), &mut out)
                    .unwrap();
                black_box(&out);
            });
        }
    }
}
