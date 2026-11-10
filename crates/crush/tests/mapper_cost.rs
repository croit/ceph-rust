// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `do_rule` runs per PG: its cost must not scale with the map size. Bucket scratch sizing is a map
//! property, not a per-call scan.
use crush::*;
use std::time::{Duration, Instant};

fn leaf_map() -> CrushMap {
    let mut m = CrushMap::new();
    m.add_bucket(Bucket::straw2(-2, 1, &[(0, 0x10000), (1, 0x10000)]));
    m.add_bucket(Bucket::straw2(-3, 1, &[(2, 0x10000), (3, 0x10000)]));
    m.add_bucket(Bucket::straw2(-1, 2, &[(-2, 0x20000), (-3, 0x20000)]));
    m.add_rule(
        0,
        Rule::new(
            RULE_REPLICATED,
            vec![
                Step::new(OP_TAKE, -1, 0),
                Step::new(OP_CHOOSELEAF_FIRSTN, 0, 1),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    m
}

fn time_calls(m: &CrushMap, calls: u32) -> Duration {
    let w = vec![0x10000u32; m.max_devices as usize];
    let mut ws = Workspace::new(m, 3);
    let mut out = [0i32; 3];
    let t = Instant::now();
    for x in 0..calls {
        std::hint::black_box(m.do_rule(0, x, &mut out, &w, None, &mut ws));
    }
    t.elapsed()
}

#[test]
fn do_rule_cost_is_independent_of_map_size() {
    let small = leaf_map();
    let mut large = leaf_map();
    large.buckets.resize(50_000, None);
    large.finalize();
    assert_eq!(large.max_bucket_size(), small.max_bucket_size());
    let calls = 2000;
    let (mut ts, mut tl) = (Duration::MAX, Duration::MAX);
    for _ in 0..3 {
        ts = ts.min(time_calls(&small, calls));
        tl = tl.min(time_calls(&large, calls));
    }
    // The former per-call scan over every bucket slot made the 50k-slot map ~37x slower (debug build);
    // the interleaved minimum keeps the check robust against load spikes.
    assert!(
        tl < ts * 8 + Duration::from_millis(20),
        "small map {ts:?}, 50k-slot map {tl:?}"
    );
}
