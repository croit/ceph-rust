// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `ecxor`: offline parity check of one object of an m = 1 EC pool (lab byte sweeps, OQ 41).
//!
//!   croit-flashstore-tool ecxor <chunk_bytes> <shard0> .. <shard k-1> <parity>
//! Files = raw per-shard object bytes (`objectstore ... get-bytes`). With m = 1 the reed_sol_van / isa parity row is all
//! ones: parity = XOR of the data shards. Shards may be short (mode O sparse shard sizes): missing bytes are zero.
//! Prints the sizes, then `ok` or `MISMATCH chunk <i> off <o> (<n> bytes)` per bad chunk and `<n> mismatching bytes`;
//! exit 1 on a mismatch, 2 on usage / read errors.

pub fn run(a: &[String]) -> i32 {
    if a.len() < 3 {
        eprintln!(
            "usage: croit-flashstore-tool ecxor <chunk_bytes> <shard0> .. <shard k-1> <parity>"
        );
        return 2;
    }
    let Ok(chunk) = a[0].parse::<usize>() else {
        eprintln!("ecxor: bad chunk size {}", a[0]);
        return 2;
    };
    let chunk = chunk.max(1);
    let mut files = Vec::new();
    for (i, p) in a[1..].iter().enumerate() {
        match std::fs::read(p) {
            Ok(b) => {
                println!("shard {i}: {} bytes ({p})", b.len());
                files.push(b);
            }
            Err(e) => {
                eprintln!("ecxor: {p}: {e}");
                return 2;
            }
        }
    }
    let parity = files.pop().unwrap_or_default();
    let len = files
        .iter()
        .map(Vec::len)
        .chain([parity.len()])
        .max()
        .unwrap_or(0);
    let at = |b: &Vec<u8>, i: usize| b.get(i).copied().unwrap_or(0);
    let (mut bad, mut bad_chunks) = (0usize, 0usize);
    let mut c = 0;
    while c < len {
        let end = (c + chunk).min(len);
        let n = (c..end)
            .filter(|&i| files.iter().fold(0u8, |x, f| x ^ at(f, i)) != at(&parity, i))
            .count();
        if n > 0 {
            bad += n;
            bad_chunks += 1;
            if bad_chunks <= 20 {
                println!("MISMATCH chunk {} off {c} ({n} bytes)", c / chunk);
            }
        }
        c = end;
    }
    if bad == 0 {
        println!("ok");
        0
    } else {
        println!("{bad} mismatching bytes in {bad_chunks} chunks");
        1
    }
}
