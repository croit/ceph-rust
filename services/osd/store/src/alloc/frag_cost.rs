// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Cost of the fragmentation gauges on an e9455-size shard (doc/perf/w4m-20261101.md). Measurement (ignored test).

use super::*;
use crate::rng::Rng;

/// Cost of the fragmentation gauges (store perf counters, built on every core once a second for the control core) on one
/// shard the size of an e9455 gate shard (2026-11-01 perf dump: 229 M blocks = 895 k windows, 97 % used, 4.9 M free
/// blocks in whole windows, 0.95 M in windows without a 16-block run): ms of a whole walk ([`Alloc::frag_full`], the
/// former per-call cost) with every window summary stale, all fresh, and after one second of 4K overwrite churn (25 k
/// windows changed), and the longest [`Alloc::frag`] call of one complete bounded walk under the same churn per call.
/// doc/perf/w4m-20261101.md. Measurement, run with --release --ignored --nocapture.
#[test]
#[ignore = "measurement"]
fn frag_e9455_shard() {
    const N: u64 = 229_000_000;
    let mut a = Alloc::new(0, N);
    let mut rng = Rng::new(7);
    let mut full = Vec::new();
    for w in 0..N / WIN {
        let b = w * WIN;
        match rng.below(1000) {
            0..=20 => {}
            21..=80 => {
                // two 8-block holes: 16 free blocks, longest run 8
                a.apply_alloc_replay(b, 100);
                a.apply_alloc_replay(b + 108, 100);
                a.apply_alloc_replay(b + 216, 40);
            }
            _ => {
                a.apply_alloc_replay(b, WIN as u32);
                full.push(b);
            }
        }
    }
    let churn = |a: &mut Alloc, rng: &mut Rng, k: usize| {
        for _ in 0..k {
            let b = full[rng.below(full.len() as u64) as usize] + rng.below(WIN);
            if !a.is_free_rel(b) {
                a.apply_free(b, 1);
                a.release_held(b, 1);
            }
        }
    };
    let ms = |a: &Alloc| {
        let t = std::time::Instant::now();
        let f = a.frag_full();
        (t.elapsed().as_secs_f64() * 1e3, f)
    };
    let (stale, f0) = ms(&a);
    let (fresh, _) = ms(&a);
    churn(&mut a, &mut rng, 25_000);
    let (churned, _) = ms(&a);
    // bounded walk: one call per "second" with that second's churn before it, until a walk started after the first
    // call completes
    a.frag();
    let calls = a.n_windows().div_ceil(FRAG_STEP) + 1;
    let mut t_ms = Vec::new();
    for _ in 0..calls {
        churn(&mut a, &mut rng, 25_000);
        let t = std::time::Instant::now();
        a.frag();
        t_ms.push(t.elapsed().as_secs_f64() * 1e3);
    }
    t_ms.sort_by(f64::total_cmp);
    let (med, worst) = (t_ms[t_ms.len() / 2], t_ms[t_ms.len() - 1]);
    eprintln!(
        "{} windows: frag_full stale {stale:.2} ms, fresh {fresh:.2} ms, after 25k changed windows {churned:.2} ms; frag \
         (bounded, {FRAG_STEP} windows) median {med:.3} ms, longest {worst:.3} ms over {calls} calls with 25k changed windows each; gauges {f0:?} -> {:?}",
        a.n_windows(),
        a.frag()
    );
}
