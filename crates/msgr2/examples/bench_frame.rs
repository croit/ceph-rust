// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! msgr2 frame layer single-core throughput. `cargo run --release -p msgr2 --example bench_frame`.
use msgr2::{ConnSecret, Decoder, Encoder, Revision, Role};
use std::time::Instant;

fn gbs(bytes: usize, iters: usize, f: &mut impl FnMut()) -> f64 {
    for _ in 0..3 {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    (bytes * iters) as f64 / t.elapsed().as_secs_f64() / 1e9
}

fn main() {
    let secret = ConnSecret::new(&(0..64u8).collect::<Vec<_>>()).unwrap();
    println!(
        "| mode | msg | encode GB/s | decode (feed copy+crc/dec) GB/s | decode no-copy GB/s | crc32c only GB/s | memcpy GB/s |"
    );
    println!("|---|---|---|---|---|---|---|");
    for secure in [false, true] {
        for &sz in &[64 << 10, 256 << 10, 1 << 20, 4 << 20] {
            let data: Vec<u8> = (0..sz).map(|i| (i * 7) as u8).collect();
            let hdr = [1u8; 53];
            let front = [2u8; 100];
            let iters = ((2usize << 30) / sz).max(8);
            let mut enc = Encoder::new(Revision::V21);
            let mut dec = Decoder::new(Revision::V21);
            let mut dec2 = Decoder::new(Revision::V21);
            if secure {
                enc.set_secure(&secret, Role::Client).unwrap();
                dec.set_secure(&secret, Role::Server).unwrap();
                dec2.set_secure(&secret, Role::Server).unwrap();
            }
            let mut out = Vec::with_capacity(sz + 1024);
            let e = gbs(sz, iters, &mut || {
                out.clear();
                enc.encode_message(&hdr, &front, &[], &data, &mut out)
                    .unwrap();
            });
            // decode: need a fresh frame per iteration (secure nonce advances); pre-encode a ring of frames
            let ring = 8usize;
            let mut enc2 = Encoder::new(Revision::V21);
            if secure {
                enc2.set_secure(&secret, Role::Client).unwrap();
            }
            let n = iters + 3;
            let _ = n;
            // encode on the fly outside the timing: time only decode
            let mut frames: Vec<Vec<u8>> = Vec::new();
            for _ in 0..ring {
                let mut o = Vec::new();
                enc2.encode_message(&hdr, &front, &[], &data, &mut o)
                    .unwrap();
                frames.push(o);
            }
            // plain decode with copy (crc mode: frames reusable; secure: nonces advance, so re-encode in blocks)
            let d = if !secure {
                gbs(sz, iters, &mut || {
                    let f = &frames[0];
                    dec.feed(f);
                    let fr = dec.poll().unwrap().unwrap();
                    std::hint::black_box(fr.segment(3).len());
                    assert!(dec.poll().unwrap().is_none());
                })
            } else {
                let mut tot = std::time::Duration::ZERO;
                let mut done = 0;
                let mut e3 = Encoder::new(Revision::V21);
                e3.set_secure(&secret, Role::Client).unwrap();
                let mut d3 = Decoder::new(Revision::V21);
                d3.set_secure(&secret, Role::Server).unwrap();
                let mut o = Vec::new();
                while done < iters {
                    o.clear();
                    e3.encode_message(&hdr, &front, &[], &data, &mut o).unwrap();
                    let t = Instant::now();
                    d3.feed(&o);
                    let fr = d3.poll().unwrap().unwrap();
                    std::hint::black_box(fr.segment(3).len());
                    tot += t.elapsed();
                    done += 1;
                }
                (sz * iters) as f64 / tot.as_secs_f64() / 1e9
            };
            let dnc = if !secure {
                gbs(sz, iters, &mut || {
                    let f = &frames[0];
                    let b = dec2.recv_buf(f.len());
                    b[..f.len()].copy_from_slice(f);
                    dec2.commit(f.len());
                    let _ = dec2.poll().unwrap().unwrap();
                }) // includes the copy: placeholder, see crc-only column
            } else {
                0.0
            };
            let c = gbs(sz, iters, &mut || {
                std::hint::black_box(crc::crc32c(!0, std::hint::black_box(&data)));
            });
            let mut dst = vec![0u8; sz];
            let m = gbs(sz, iters, &mut || {
                dst.copy_from_slice(std::hint::black_box(&data));
                std::hint::black_box(&dst);
            });
            println!(
                "| {} | {} KiB | {e:.1} | {d:.1} | {dnc:.1} | {c:.1} | {m:.1} |",
                if secure { "secure" } else { "crc" },
                sz >> 10
            );
        }
    }
}
