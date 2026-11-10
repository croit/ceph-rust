// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Hostile maps and wire values must never panic, never spin (bounded wall clock) and keep the
//! documented "invalid rule => empty result" contract (spec crush.md sec 9, 10).

use crush::*;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Run `do_rule` on a worker thread and fail if it does not return within `limit_ms`.
fn run_bounded(
    m: CrushMap,
    result_max: usize,
    weights: Vec<u32>,
    limit_ms: u64,
) -> (usize, Vec<i32>) {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut ws = Workspace::new(&m, result_max);
        let mut out = vec![0i32; result_max];
        let n = m.do_rule(0, 0, &mut out, &weights, None, &mut ws);
        let _ = tx.send((n, out));
    });
    rx.recv_timeout(Duration::from_millis(limit_ms))
        .unwrap_or_else(|_| panic!("do_rule did not return within {limit_ms} ms"))
}

fn run(m: &CrushMap, x: u32, result_max: usize, weights: &[u32]) -> (usize, Vec<i32>) {
    let mut ws = Workspace::new(m, result_max);
    let mut out = vec![0i32; result_max];
    let n = m.do_rule(0, x, &mut out, weights, None, &mut ws);
    (n, out)
}

/// Two buckets of the same type that only list each other: no bucket of the requested type.
fn cyclic_map(op: u32) -> CrushMap {
    let mut m = CrushMap::new();
    m.add_bucket(Bucket::straw2(-2, 10, &[(-3, 1)]));
    m.add_bucket(Bucket::straw2(-3, 10, &[(-2, 1)]));
    m.add_rule(
        0,
        Rule::new(
            RULE_REPLICATED,
            vec![
                Step::new(OP_TAKE, -2, 0),
                Step::new(op, 0, 7),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    m
}

#[test]
fn cyclic_descent_firstn_terminates() {
    let (n, _) = run_bounded(cyclic_map(OP_CHOOSE_FIRSTN), 3, Vec::new(), 5000);
    assert_eq!(n, 0, "no bucket of the requested type exists");
}

#[test]
fn cyclic_descent_indep_terminates_with_none() {
    let (n, out) = run_bounded(cyclic_map(OP_CHOOSE_INDEP), 3, Vec::new(), 5000);
    assert_eq!(n, 3);
    assert!(out.iter().all(|&v| v == ITEM_NONE), "{out:?}");
}

/// `vary_r` beyond the 32-bit shift width: defined as a full shift-out (sub_r = 0), no panic.
#[test]
fn vary_r_beyond_shift_width_maps_like_vary_r_zero() {
    let base = host_map();
    let mut w = vec![0x10000u32; base.max_devices as usize];
    w[1] = 0x8000;
    let expect: Vec<(usize, Vec<i32>)> = {
        let mut m = base.clone();
        m.tunables.chooseleaf_vary_r = 0;
        (0..64).map(|x| run(&m, x, 3, &w)).collect()
    };
    for vary_r in [33u8, 40, 255] {
        let mut m = base.clone();
        m.tunables.chooseleaf_vary_r = vary_r;
        for (x, e) in expect.iter().enumerate() {
            assert_eq!(&run(&m, x as u32, 3, &w), e, "wire vary_r {vary_r} x {x}");
        }
    }
    let mut m = base.clone();
    m.rules[0] = Some(Rule::new(
        RULE_REPLICATED,
        vec![
            Step::new(OP_SET_CHOOSELEAF_VARY_R, 40, 0),
            Step::new(OP_TAKE, -1, 0),
            Step::new(OP_CHOOSELEAF_FIRSTN, 0, 1),
            Step::new(OP_EMIT, 0, 0),
        ],
    ));
    for (x, e) in expect.iter().enumerate() {
        assert_eq!(&run(&m, x as u32, 3, &w), e, "step vary_r 40 x {x}");
    }
}

#[test]
fn msr_negative_choose_count_is_an_invalid_rule() {
    let mut m = msr_map();
    m.rules[0] = Some(Rule::new(
        RULE_MSR_FIRSTN,
        vec![
            Step::new(OP_TAKE, -1, 0),
            Step::new(OP_CHOOSE_MSR, 1, 0),
            Step::new(OP_EMIT, 0, 0),
            Step::new(OP_TAKE, -1, 0),
            Step::new(OP_CHOOSE_MSR, -1, 0),
            Step::new(OP_EMIT, 0, 0),
        ],
    ));
    let (n, _) = run(&m, 0, 2, &[0x10000; 4]);
    assert_eq!(n, 0, "a negative CHOOSE_MSR count is invalid");
}

/// Classic emits the taken OSD for `take <osd>; emit` and then re-scans the same block forever, so
/// the reference daemon aborts on its own emit bounds check: no reference placement exists to match.
/// An OSD take is an invalid MSR rule here (empty result, never a spin), for both rule types.
#[test]
fn msr_take_osd_block_is_an_invalid_rule_not_a_spin() {
    for kind in [RULE_MSR_FIRSTN, RULE_MSR_INDEP] {
        let mut m = msr_map();
        m.rules[0] = Some(Rule::new(
            kind,
            vec![Step::new(OP_TAKE, 1, 0), Step::new(OP_EMIT, 0, 0)],
        ));
        let (n, _) = run_bounded(m, 2, vec![0x10000; 4], 2000);
        assert_eq!(n, 0, "take <osd>; emit is invalid (kind {kind})");
    }
}

#[test]
fn msr_fanout_saturates_instead_of_overflowing() {
    let mut m = msr_map();
    let huge = i32::MAX;
    m.rules[0] = Some(Rule::new(
        RULE_MSR_FIRSTN,
        vec![
            Step::new(OP_TAKE, -1, 0),
            Step::new(OP_CHOOSE_MSR, huge, 0),
            Step::new(OP_CHOOSE_MSR, huge, 0),
            Step::new(OP_CHOOSE_MSR, huge, 0),
            Step::new(OP_EMIT, 0, 0),
            Step::new(OP_TAKE, -1, 0),
            Step::new(OP_CHOOSE_MSR, huge, 0),
            Step::new(OP_CHOOSE_MSR, huge, 0),
            Step::new(OP_CHOOSE_MSR, huge, 0),
            Step::new(OP_EMIT, 0, 0),
        ],
    ));
    let (n, _) = run(&m, 0, 2, &[0x10000; 4]);
    assert_eq!(n, 0, "every stride span exceeds the result");
}

/// A wire `choose_local_fallback_tries` near `u32::MAX` wraps like every other u32 (spec conventions):
/// no overflow panic, a bounded run, a deterministic result. Larger-but-unwrapped retry bounds are the
/// unvalidated-tunable case (spec dependency), not an arithmetic case.
#[test]
fn local_fallback_extreme_tunable_does_not_overflow() {
    let m = host_map();
    let w = vec![0u32; m.max_devices as usize]; // all devices out: every try rejects
    for fallback in [u32::MAX, u32::MAX - 1, 5] {
        let mut m = m.clone();
        m.tunables.choose_local_fallback_tries = fallback;
        let a = run(&m, 0, 3, &w);
        let b = run(&m, 0, 3, &w);
        assert_eq!(a, b, "fallback {fallback} is not deterministic");
        assert!(a.0 <= 3);
    }
}

/// `do_rule` promises "never panics": an empty result slice is a valid call.
#[test]
fn empty_result_slice_maps_to_zero() {
    let m = host_map();
    let mut ws = Workspace::new(&m, 0);
    let w = vec![0x10000u32; m.max_devices as usize];
    assert_eq!(m.do_rule(0, 0, &mut [], &w, None, &mut ws), 0);
}

#[test]
fn crush_ln_out_of_contract_input_is_clamped() {
    for x in [0x1_0000u32, 0x1_ffff, 0x2_0000, u32::MAX] {
        assert_eq!(
            crush::hash::crush_ln(x),
            crush::hash::crush_ln(0xffff),
            "{x:#x}"
        );
    }
}

/// A three-hundred-level acyclic chain is a legal hierarchy: the leaf descent must reach the device.
#[test]
fn deep_leaf_descent_reaches_the_device() {
    let m = deep_chain_map(300, 1);
    let (n, out) = run(&m, 0, 1, &[0x10000; 1]);
    assert_eq!(n, 1);
    assert_eq!(out[0], 0);
}

/// The MSR descent bound comes from the map, not from a constant: a 300-level chain still maps.
#[test]
fn msr_deep_descent_reaches_the_device() {
    let mut m = deep_chain_map(300, 10);
    m.rules[0] = Some(Rule::new(
        RULE_MSR_FIRSTN,
        vec![
            Step::new(OP_TAKE, -1, 0),
            Step::new(OP_CHOOSE_MSR, 1, 0),
            Step::new(OP_EMIT, 0, 0),
        ],
    ));
    let (n, out) = run(&m, 0, 3, &[0x10000; 1]);
    assert_eq!(n, 1, "{out:?}");
    assert_eq!(out[0], 0);
}

#[test]
fn msr_cyclic_descent_terminates() {
    let mut m = CrushMap::new();
    m.add_bucket(Bucket::straw2(-2, 10, &[(-3, 1)]));
    m.add_bucket(Bucket::straw2(-3, 10, &[(-2, 1)]));
    m.add_rule(
        0,
        Rule::new(
            RULE_MSR_FIRSTN,
            vec![
                Step::new(OP_TAKE, -2, 0),
                Step::new(OP_CHOOSE_MSR, 1, 0),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    let (n, _) = run_bounded(m, 2, Vec::new(), 5000);
    assert_eq!(n, 0);
}

/// Spec sec 9: a rule needs one or more TAKE/CHOOSE_MSR+/EMIT blocks; without a block the result is empty.
#[test]
fn msr_rule_without_block_is_empty() {
    for kind in [RULE_MSR_FIRSTN, RULE_MSR_INDEP] {
        for steps in [
            vec![],
            vec![Step::new(OP_SET_MSR_DESCENTS, 1, 0)],
            vec![Step::new(OP_SET_MSR_COLLISION_TRIES, 1, 0)],
        ] {
            let mut m = msr_map();
            m.rules[0] = Some(Rule::new(kind, steps.clone()));
            assert_eq!(run(&m, 0, 3, &[0x10000; 4]).0, 0, "type {kind} {steps:?}");
        }
    }
}

/// Jewel map with two hosts (type 1) of two devices each under a root (type 2).
fn host_map() -> CrushMap {
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

/// Root (type 2) -> host bucket of two devices (type 1).
fn msr_map() -> CrushMap {
    let mut m = CrushMap::new();
    m.add_bucket(Bucket::straw2(-2, 1, &[(0, 0x10000), (1, 0x10000)]));
    m.add_bucket(Bucket::straw2(-1, 2, &[(-2, 0x20000)]));
    m.add_rule(
        0,
        Rule::new(
            RULE_MSR_FIRSTN,
            vec![
                Step::new(OP_TAKE, -1, 0),
                Step::new(OP_CHOOSE_MSR, 1, 0),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    m
}

/// `depth` buckets (type 10) chained from -1 down to a bucket of type `leaf_type` holding device 0.
fn deep_chain_map(depth: i32, leaf_type: u16) -> CrushMap {
    let mut m = CrushMap::new();
    for k in 1..depth {
        m.add_bucket(Bucket::straw2(-k, 10, &[(-k - 1, 1)]));
    }
    let last = -depth;
    m.add_bucket(Bucket::straw2(last, leaf_type, &[(0, 0x10000)]));
    m.name_map.insert(0, "osd.0".into());
    m.add_rule(
        0,
        Rule::new(
            RULE_REPLICATED,
            vec![
                Step::new(OP_TAKE, -1, 0),
                Step::new(OP_CHOOSELEAF_FIRSTN, 0, i32::from(leaf_type)),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    m
}

/// A rule's configured fanout can exceed the caller's result limit (spec sec 9):
/// only the intersecting strides are mapped; excess strides do not invalidate it.
#[test]
fn msr_fanout_larger_than_result_limit_maps_prefix() {
    for kind in [RULE_MSR_FIRSTN, RULE_MSR_INDEP] {
        let mut m = CrushMap::new();
        m.add_bucket(Bucket::straw2(-1, 1, &[(0, 0x10000)]));
        m.add_rule(
            0,
            Rule::new(
                kind,
                vec![
                    Step::new(OP_TAKE, -1, 0),
                    Step::new(OP_CHOOSE_MSR, 4, 0),
                    Step::new(OP_EMIT, 0, 0),
                ],
            ),
        );
        let m = CrushMap::decode(&m.encode()).unwrap();
        assert_eq!(run(&m, 0, 1, &[0x10000]), (1, vec![0]));
    }
}

/// An earlier block can consume one output slot before a later block's fanout
/// saturates; clipping that block to the remaining slot must not overflow.
#[test]
fn msr_saturated_fanout_after_prior_block_does_not_panic() {
    let mut m = msr_map();
    m.rules[0] = Some(Rule::new(
        RULE_MSR_FIRSTN,
        vec![
            Step::new(OP_TAKE, -1, 0),
            Step::new(OP_CHOOSE_MSR, 1, 0),
            Step::new(OP_EMIT, 0, 0),
            Step::new(OP_TAKE, -1, 0),
            Step::new(OP_CHOOSE_MSR, 1, 1),
            Step::new(OP_CHOOSE_MSR, i32::MAX, 0),
            Step::new(OP_CHOOSE_MSR, i32::MAX, 0),
            Step::new(OP_CHOOSE_MSR, i32::MAX, 0),
            Step::new(OP_EMIT, 0, 0),
        ],
    ));
    let m = CrushMap::decode(&m.encode()).unwrap();
    let (n, out) = run(&m, 0, 2, &[0x10000; 2]);
    assert_eq!(n, 1);
    assert!((0..2).contains(&out[0]));
}

/// Single-path MSR hierarchy of `depth` buckets, one CHOOSE_MSR step per level, decoded from the wire.
fn deep_msr_map(kind: u8, depth: i32) -> CrushMap {
    let mut map = CrushMap::new();
    for i in 1..depth {
        map.buckets
            .push(Some(Bucket::straw2(-i, 1, &[(-i - 1, 0x10000)])));
    }
    map.buckets
        .push(Some(Bucket::straw2(-depth, 1, &[(0, 0x10000)])));
    map.finalize();
    let mut steps = vec![Step::new(OP_TAKE, -1, 0)];
    steps.extend((1..depth).map(|_| Step::new(OP_CHOOSE_MSR, 1, 1)));
    steps.push(Step::new(OP_CHOOSE_MSR, 1, 0));
    steps.push(Step::new(OP_EMIT, 0, 0));
    map.add_rule(0, Rule::new(kind, steps));
    CrushMap::decode(&map.encode()).unwrap()
}

/// Reserving a workspace for a smaller map keeps the MSR frames a deeper map needs,
/// like every other workspace buffer.
#[test]
fn workspace_reserve_never_shrinks_msr_frames() {
    let deep = deep_msr_map(RULE_MSR_FIRSTN, 8);
    let mut ws = Workspace::new(&deep, 1);
    ws.reserve(&CrushMap::new(), 1);
    let mut out = [ITEM_NONE; 1];
    assert_eq!(deep.do_rule(0, 0, &mut out, &[0x10000], None, &mut ws), 1);
    assert_eq!(out, [0]);
}

/// Mapping depth comes from the wire rule, not the thread's native stack.
/// A subprocess contains the old mapper's stack-overflow abort for fail-before proof.
#[test]
fn msr_rule_depth_uses_workspace_instead_of_native_stack() {
    const CHILD: &str = "CRUSH_MSR_STACK_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "msr_rule_depth_uses_workspace_instead_of_native_stack",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success(), "deep MSR subprocess failed: {status}");
        return;
    }
    for kind in [RULE_MSR_FIRSTN, RULE_MSR_INDEP] {
        let map = deep_msr_map(kind, 512);
        let result = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || run(&map, 0, 1, &[0x10000]))
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(result, (1, vec![0]));
    }
}
