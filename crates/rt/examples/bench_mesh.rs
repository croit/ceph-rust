// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Cross-core handoff cost: producer allocates + fills a buffer and sends it over the SPSC mesh, the consumer reads one
//! byte per page and drops it. `cargo run --release -p rt [--features mimalloc] --example bench_mesh -- [KiB] [fill|nofill]`.
use rt::mesh::mesh;
use std::time::Instant;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let kib: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(64);
    let fill = args.get(2).is_none_or(|s| s != "nofill");
    let n = 200_000usize * 64 / kib.max(1) / 4;
    let mut eps = mesh::<Vec<u8>>(2, 256);
    let mut b = eps.pop().unwrap();
    let mut a = eps.pop().unwrap();
    let src = vec![7u8; kib << 10];
    let t0 = Instant::now();
    let h = std::thread::spawn(move || {
        let mut got = 0;
        let mut sum = 0u64;
        while got < n {
            b.drain(64, |_, v: Vec<u8>| {
                for p in v.chunks(4096) {
                    sum += u64::from(p[0]);
                }
                got += 1;
            });
        }
        sum
    });
    for _ in 0..n {
        let mut v = Vec::with_capacity(kib << 10);
        if fill {
            v.extend_from_slice(&src);
        } else {
            v.resize(kib << 10, 1);
        }
        let mut m = v;
        while let Err(x) = a.send(1, m) {
            m = x;
            std::hint::spin_loop();
        }
    }
    let s = h.join().unwrap();
    let dt = t0.elapsed().as_secs_f64();
    println!(
        "{kib} KiB msgs: {:.2} Mmsg/s, {:.1} GB/s, {:.0} ns/msg (sum {s})",
        n as f64 / dt / 1e6,
        (n * (kib << 10)) as f64 / dt / 1e9,
        dt / n as f64 * 1e9
    );
}
