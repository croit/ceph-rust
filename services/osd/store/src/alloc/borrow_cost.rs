// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Churn cost of borrowed chunks vs a plain region (adr 0021 am. 56). Measurement (ignored test).

use super::*;
use crate::rng::Rng;

/// ns per churn step (free one live extent, reserve one of the same size) with `sizes` mixed, base full + borrowed chunks
/// vs a plain region at the same data volume (adr 0021 am. 56). Measurement, run with --release --ignored --nocapture.
fn churn(a: &mut Alloc, data_blocks: u64, sizes: &[u32], steps: u64) -> (f64, u64) {
    let mut rng = Rng::new(3);
    let mut live: Vec<(u64, u32)> = Vec::new();
    let mut got = 0u64;
    while got < data_blocks {
        let n = sizes[(rng.next_u64() % sizes.len() as u64) as usize];
        match a.reserve(n) {
            Some(b) => {
                live.push((b, n));
                got += n as u64;
            }
            None => break,
        }
    }
    let t = std::time::Instant::now();
    let mut fails = 0;
    for _ in 0..steps {
        let i = (rng.next_u64() % live.len() as u64) as usize;
        let (b, n) = live[i];
        a.unreserve(b, n);
        match a.reserve(n) {
            Some(nb) => live[i] = (nb, n),
            None => {
                fails += 1;
                live.swap_remove(i);
            }
        }
    }
    (t.elapsed().as_nanos() as f64 / steps as f64, fails)
}

#[test]
#[ignore = "measurement"]
fn borrowing_churn_cost() {
    const C: u64 = 16384;
    for sizes in [
        &[16u32][..],
        &[1u32][..],
        &[1, 16][..],
        &[1, 2, 4, 8, 16][..],
    ] {
        // plain: 16 chunks of region, data = 8 chunks + 4 % (50 % fill)
        let mut p = Alloc::new(0, 16 * C);
        let (pn, pf) = churn(&mut p, 8 * C, sizes, 400_000);
        // lent: base 4 chunks, 5 borrowed chunks (one chunk of headroom), same data volume
        let base: Vec<u64> = (0..4).map(|i| i * C).collect();
        let lent: Vec<u64> = (4..9).map(|i| i * C).collect();
        let mut l = Alloc::with_lent(&base, &lent, C);
        let (ln, lf) = churn(&mut l, 8 * C, sizes, 400_000);
        eprintln!(
            "sizes {sizes:?}: plain 50 % fill {pn:.0} ns/step ({pf} fails), base 4 + lent 5 chunks, 89 % fill {ln:.0} ns/step ({lf} fails)"
        );
    }
}
