// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH

//! Micro benchmark of the encrypted-image data path cipher: AES-XTS
//! encrypt/decrypt of 4 KiB and 64 KiB extents with 128- and 256-bit keys.
//! Run: `cargo run --release -p rustyrbd --example xts-bench`.

use rustyrbd::luks::AesXts;
use std::hint::black_box;
use std::time::{Duration, Instant};

fn main() {
    println!(
        "{:<10} {:>6} {:<7} {:>10} {:>10}",
        "cipher", "size", "dir", "ns/op", "MB/s"
    );
    for (name, key_len) in [("AES-128", 32usize), ("AES-256", 64)] {
        let key: Vec<u8> = (0..key_len as u8).collect();
        let xts = AesXts::new(&key, 4096).unwrap();
        for size in [4096usize, 65536] {
            for (dir, decrypt) in [("enc", false), ("dec", true)] {
                let mut buf = vec![0x5au8; size];
                for _ in 0..2000 {
                    xts.apply(black_box(&mut buf), 0, decrypt).unwrap();
                }
                let mut ops = 0u64;
                let start = Instant::now();
                while start.elapsed() < Duration::from_secs(1) {
                    for _ in 0..1000 {
                        xts.apply(black_box(&mut buf), black_box(ops), decrypt)
                            .unwrap();
                        ops += 1;
                    }
                }
                let ns = start.elapsed().as_nanos() as f64 / ops as f64;
                println!(
                    "{:<10} {:>6} {:<7} {:>10.0} {:>10.0}",
                    name,
                    size,
                    dir,
                    ns,
                    size as f64 / ns * 1000.0
                );
            }
        }
    }
}
