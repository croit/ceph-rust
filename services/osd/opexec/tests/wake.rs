// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Store wake tokens at the gate (adr 0043 am. 9): a store wake probes only the gated ops whose last probe named a cause
//! the wake resolved; an unnamed cause, `all`, an overflowing batch and the tick wake everyone; no wake-up is ever lost.
mod common;
use common::*;
use denc::types::EntityAddr;
use opexec::{ClientReq, Engine, Out};
use opwire::OsdOp;
use peering::wake::{CAUSE_MAX, WAKE_MAX, WakeSet};
use std::collections::{BTreeMap, BTreeSet};

fn req(tid: u64, oid: &str) -> ClientReq {
    ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(mkop(
            oid.as_bytes(),
            vec![OsdOp::write(0, vec![tid as u8; 8])],
        )),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    }
}

fn replied(outs: &[Out]) -> Vec<u64> {
    outs.iter()
        .filter_map(|o| match o {
            Out::Reply { conn: 1, tid, .. } => Some(*tid),
            _ => None,
        })
        .collect()
}

fn pages(pg: &TPg, oid: &str, p: &[u64]) {
    pg.obj_pages
        .borrow_mut()
        .insert(oid.as_bytes().to_vec(), p.to_vec());
}

/// The pages `done` arrived: no object waits for them any more.
fn arrive(pg: &TPg, done: &[u64]) {
    for v in pg.obj_pages.borrow_mut().values_mut() {
        v.retain(|p| !done.contains(p));
    }
}

fn ws(toks: &[u64]) -> WakeSet {
    let mut w = WakeSet::default();
    for &t in toks {
        w.push(t);
    }
    w
}

#[test]
fn only_the_ops_whose_page_arrived_are_probed() {
    let mut pg = TPg::new();
    let mut eng: Engine = engine(&pg);
    for i in 0..200u64 {
        pages(&pg, &format!("o{i}"), &[1000 + i]);
        eng.on_op(&mut pg, req(i + 1, &format!("o{i}")));
    }
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    assert_eq!(eng.parked_len(), 200);
    pg.warm_calls.borrow_mut().clear();
    let (p0, s0) = (eng.c.wake_probes, eng.c.wake_skips);

    // no wake, no probe
    eng.retry_woken(&mut pg, &WakeSet::default());
    assert!(pg.warm_calls.borrow().is_empty());

    // two pages arrive: exactly those two ops are probed, the 198 others are not
    arrive(&pg, &[1017, 1150]);
    eng.retry_woken(&mut pg, &ws(&[1017, 1150]));
    let mut r = replied(&settle(&mut pg, &mut eng));
    r.sort();
    assert_eq!(r, vec![18, 151]);
    let calls: Vec<String> = pg
        .warm_calls
        .borrow()
        .iter()
        .map(|n| String::from_utf8(n.clone()).unwrap())
        .collect();
    assert_eq!(calls, vec!["o17", "o150"]);
    assert_eq!(eng.c.wake_probes - p0, 2);
    assert_eq!(eng.c.wake_skips - s0, 198);

    // a token nobody waits for probes nobody
    pg.warm_calls.borrow_mut().clear();
    eng.retry_woken(&mut pg, &ws(&[7]));
    assert!(pg.warm_calls.borrow().is_empty());

    // an op arriving for another object costs one probe (its own), not one per gated op
    pages(&pg, "late", &[5000]);
    eng.on_op(&mut pg, req(1000, "late"));
    assert_eq!(pg.warm_calls.borrow().len(), 1);

    // `all` (unnamed change, tick, EC wake) wakes everyone
    pg.obj_pages.borrow_mut().clear();
    eng.retry_woken(&mut pg, &WakeSet::ALL);
    let r = replied(&settle(&mut pg, &mut eng));
    assert_eq!(r.len(), 199);
    assert!(!eng.has_parked());
    assert!(eng.c.wake_all >= 1);
}

#[test]
fn a_batch_past_the_token_bound_wakes_everyone() {
    let mut w = WakeSet::default();
    for t in 0..WAKE_MAX as u64 {
        w.push(t + 1);
    }
    assert!(!w.all);
    w.push(9999);
    assert!(w.all, "overflow degrades to all");
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pages(&pg, "a", &[1]);
    pages(&pg, "b", &[2]);
    eng.on_op(&mut pg, req(1, "a"));
    eng.on_op(&mut pg, req(2, "b"));
    settle(&mut pg, &mut eng);
    pg.obj_pages.borrow_mut().clear();
    eng.retry_woken(&mut pg, &w);
    assert_eq!(replied(&settle(&mut pg, &mut eng)).len(), 2);
}

#[test]
fn an_op_missing_two_pages_wakes_per_page_and_not_twice() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pages(&pg, "a", &[1, 2]);
    eng.on_op(&mut pg, req(1, "a"));
    settle(&mut pg, &mut eng);
    pg.warm_calls.borrow_mut().clear();
    arrive(&pg, &[1]);
    eng.retry_woken(&mut pg, &ws(&[1]));
    assert_eq!(
        pg.warm_calls.borrow().len(),
        1,
        "page 1 resolved one cause of two"
    );
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    // the token of page 1 again: the op now names page 2 only
    eng.retry_woken(&mut pg, &ws(&[1]));
    assert_eq!(pg.warm_calls.borrow().len(), 1);
    arrive(&pg, &[2]);
    eng.retry_woken(&mut pg, &ws(&[2]));
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![1]);
}

fn read(tid: u64, oid: &str) -> ClientReq {
    let mut r = req(tid, oid);
    r.op.ops = vec![OsdOp::read(0, 8)];
    r
}

fn scan(tid: u64) -> ClientReq {
    let mut r = req(tid, "shared");
    r.op.ops = vec![OsdOp::omap_get_vals(b"", 1024, b"")];
    r
}

fn seed_scan_object(pg: &mut TPg, eng: &mut Engine) {
    let mut r = req(100, "shared");
    r.op.ops.push(OsdOp::omap_set_vals(&BTreeMap::from([(
        b"key".to_vec(),
        b"value".to_vec(),
    )])));
    eng.on_op(pg, r);
    assert_eq!(replied(&settle(pg, eng)), [100]);
}

#[test]
fn local_credit_wait_never_blocks_the_owner_after_try_or_time_limits() {
    for elapsed in [false, true] {
        let mut pg = TPg::new();
        let mut eng = engine(&pg);
        seed_scan_object(&mut pg, &mut eng);
        pg.credit_owner.set(Some((1, 1)));
        pg.credit_slices.set(u32::MAX);
        eng.on_op(&mut pg, scan(1));
        eng.on_op(&mut pg, scan(2));
        assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
        if elapsed {
            pg.now += 31_000_000_000;
        }
        for _ in 0..130 {
            eng.retry_woken(&mut pg, &WakeSet::ALL);
            assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
            assert_eq!(
                pg.credit_blocking.get(),
                0,
                "credit waiter entered blocking mode"
            );
        }
        pg.credit_slices.set(0);
        let mut replies = Vec::new();
        for _ in 0..8 {
            eng.retry_woken(&mut pg, &WakeSet::ALL);
            replies.extend(replied(&settle(&mut pg, &mut eng)));
            if replies.len() == 2 {
                break;
            }
        }
        replies.sort();
        assert_eq!(replies, [1, 2]);
        assert_eq!(pg.credit_owner.get(), None);
        assert!(!eng.has_parked());
    }
}

#[test]
fn blocking_io_fallback_still_yields_when_it_first_meets_a_local_credit() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    seed_scan_object(&mut pg, &mut eng);
    pg.cold_scan.set(u32::MAX);
    eng.on_op(&mut pg, scan(2));
    for _ in 1..64 {
        eng.retry_woken(&mut pg, &WakeSet::ALL);
    }
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    pg.credit_owner.set(Some((1, 1)));
    eng.retry_woken(&mut pg, &WakeSet::ALL);
    assert_eq!(
        pg.credit_blocking.get(),
        1,
        "genuine misses selected fallback"
    );
    assert!(
        replied(&settle(&mut pg, &mut eng)).is_empty(),
        "local refusal is not an EIO reply"
    );
    eng.retry_woken(&mut pg, &WakeSet::ALL);
    assert_eq!(
        pg.credit_blocking.get(),
        1,
        "known local dependency stays yieldable"
    );
    pg.credit_owner.set(None);
    pg.cold_scan.set(0);
    eng.retry_woken(&mut pg, &WakeSet::ALL);
    assert_eq!(replied(&settle(&mut pg, &mut eng)), [2]);
}

/// A read whose every refused run claims progress (a data wait) and never finishes: the stuck detector counts from its
/// first refusal (a re-park never restarts it); 30 s later its next run is blocking and answers. Before: progress
/// refusals were not counted, the op was re-run on every wake forever.
#[test]
fn an_op_refused_with_progress_runs_blocking_30s_after_its_first_refusal() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.refuse_runs.set(u32::MAX);
    pg.refuse_progress.set(true);
    eng.on_op(&mut pg, read(1, "a"));
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    for s in 1..30 {
        pg.now += 1_000_000_000;
        eng.retry_woken(&mut pg, &WakeSet::ALL);
        assert!(
            replied(&settle(&mut pg, &mut eng)).is_empty(),
            "answered after {s} s"
        );
    }
    // refused 30 s after the first refusal: the next run is blocking
    pg.now += 1_000_000_000;
    eng.retry_woken(&mut pg, &WakeSet::ALL);
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    eng.retry_woken(&mut pg, &WakeSet::ALL);
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![1]);
    assert!(!eng.has_parked());
}

/// `skip_wake` (the host's check before an engine run) answers "no-op" exactly when `retry_woken` would do nothing.
#[test]
fn skip_wake_without_an_env() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pages(&pg, "a", &[1]);
    pages(&pg, "b", &[2]);
    eng.on_op(&mut pg, req(1, "a"));
    eng.on_op(&mut pg, req(2, "b"));
    settle(&mut pg, &mut eng);
    let s0 = eng.c.wake_skips;
    assert!(
        eng.skip_wake(&ws(&[7]), true, || true),
        "nobody waits for 7"
    );
    assert_eq!(eng.c.wake_skips - s0, 2);
    assert!(!eng.skip_wake(&ws(&[2]), true, || true), "b waits for 2");
    assert!(!eng.skip_wake(&WakeSet::ALL, true, || true));
    assert!(
        !eng.skip_wake(&ws(&[7]), false, || true),
        "not live: the engine runs"
    );
    assert!(
        !eng.skip_wake(&ws(&[7]), true, || false),
        "admission paused"
    );
    assert!(
        eng.skip_wake(&WakeSet::default(), true, || panic!("not asked")),
        "nothing woke"
    );
    // an op with an unnamed cause is probed on every wake
    pg.untracked_objs.borrow_mut().insert(b"c".to_vec());
    pages(&pg, "c", &[3]);
    eng.on_op(&mut pg, req(3, "c"));
    settle(&mut pg, &mut eng);
    assert!(!eng.skip_wake(&ws(&[7]), true, || true));
    arrive(&pg, &[1, 2, 3]);
    eng.retry_woken(&mut pg, &WakeSet::ALL);
    assert_eq!(replied(&settle(&mut pg, &mut eng)).len(), 3);
}

/// `quiet_without_wake` (the host leaves such an engine out of a pass where nothing woke) is exactly "a live engine's
/// `skip_wake` with an empty wake is a no-op": an engine that is not quiet is visited on every pass, a quiet one only by
/// a wake that names its ops.
#[test]
fn quiet_without_wake_matches_skip_wake_of_an_empty_wake() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert!(!eng.quiet_without_wake(), "nothing was parked yet");
    pages(&pg, "a", &[1]);
    eng.on_op(&mut pg, req(1, "a"));
    settle(&mut pg, &mut eng);
    assert!(eng.has_parked());
    assert!(eng.quiet_without_wake(), "only a store load gates it");
    assert!(eng.skip_wake(&WakeSet::default(), true, || panic!("not asked")));
    // the page arrives with a wake naming it: the op runs, nothing more waits for any wake
    arrive(&pg, &[1]);
    eng.retry_woken(&mut pg, &ws(&[1]));
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![1]);
    assert!(!eng.has_parked());
}

/// A replicated read whose cause a wake hits runs without a second probe (one resolution of the object per read); what
/// the run still misses re-gates it, and the next wake finishes it.
#[test]
fn a_read_whose_cause_arrived_runs_without_a_second_probe() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    eng.on_op(&mut pg, req(1, "a"));
    eng.on_op(&mut pg, req(2, "b"));
    settle(&mut pg, &mut eng);
    pages(&pg, "a", &[1]);
    pages(&pg, "b", &[2, 3]);
    eng.on_op(&mut pg, read(3, "a"));
    eng.on_op(&mut pg, read(4, "b"));
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    pg.warm_calls.borrow_mut().clear();
    let p0 = eng.c.wake_probes;

    arrive(&pg, &[1]);
    eng.retry_woken(&mut pg, &ws(&[1]));
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![3]);
    assert!(pg.warm_calls.borrow().is_empty(), "no second probe");
    assert_eq!((eng.c.wake_direct, eng.c.wake_probes - p0), (1, 0));

    // a part of b's causes: the run is refused (page 3 still missing) and re-gated, not answered
    arrive(&pg, &[2]);
    pg.refuse_runs.set(1);
    eng.retry_woken(&mut pg, &ws(&[2]));
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    assert_eq!(eng.c.wake_direct, 2);
    arrive(&pg, &[3]);
    eng.retry_woken(&mut pg, &ws(&[3]));
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![4]);
    assert!(!eng.has_parked());

    // writes still probe: the log head readiness is checked only there
    pages(&pg, "c", &[4]);
    eng.on_op(&mut pg, req(5, "c"));
    settle(&mut pg, &mut eng);
    pg.warm_calls.borrow_mut().clear();
    arrive(&pg, &[4]);
    eng.retry_woken(&mut pg, &ws(&[4]));
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![5]);
    assert_eq!(pg.warm_calls.borrow().len(), 1);
    assert_eq!(eng.c.wake_direct, 2);
}

#[test]
fn an_op_with_an_unnamed_cause_is_probed_on_every_wake() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pages(&pg, "a", &[5]);
    pg.untracked_objs.borrow_mut().insert(b"a".to_vec());
    pages(&pg, "b", &[6]);
    eng.on_op(&mut pg, req(1, "a"));
    eng.on_op(&mut pg, req(2, "b"));
    settle(&mut pg, &mut eng);
    pg.warm_calls.borrow_mut().clear();
    eng.retry_woken(&mut pg, &ws(&[99]));
    let calls = pg.warm_calls.borrow().clone();
    assert_eq!(
        calls,
        vec![b"a".to_vec()],
        "named op b skipped, unnamed op a probed"
    );
    arrive(&pg, &[5]);
    eng.retry_woken(&mut pg, &ws(&[5]));
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![1]);
}

/// The object state load of a run is non-blocking too (adr 0021 am. 11): a cold onode / attribute page met while a
/// directly woken read loads `_` + `snapset` re-gates the op (no answer, no blocking store read) and it runs on the
/// next wake.
#[test]
fn a_cold_state_load_regates_the_op() {
    let mut pg = TPg::new();
    // no object-state cache: a cache hit never loads the state (debug builds only re-load it to verify the hit)
    pg.obj_cap = 0;
    let mut eng = engine(&pg);
    eng.on_op(&mut pg, req(1, "a"));
    settle(&mut pg, &mut eng);
    pages(&pg, "a", &[1]);
    eng.on_op(&mut pg, read(2, "a"));
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    let s0 = eng.c.parked_scan;

    arrive(&pg, &[1]);
    pg.cold_attr.set(1);
    eng.retry_woken(&mut pg, &ws(&[1]));
    assert!(
        replied(&settle(&mut pg, &mut eng)).is_empty(),
        "cold state load answered"
    );
    assert_eq!(pg.cold_attr.get(), 0, "the state load ran non-blocking");
    assert_eq!(eng.c.parked_scan - s0, 1);
    assert!(eng.has_parked());

    eng.retry_woken(&mut pg, &WakeSet::ALL);
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![2]);
    assert!(!eng.has_parked());
    assert_eq!(eng.c.parked_scan - s0, 1);
}

/// A refused state load of a WRITE re-gates it without letting a later write of the same object overtake it: replies
/// come in submission order and the object holds both writes.
#[test]
fn a_cold_state_load_of_a_write_keeps_the_object_order() {
    let mut pg = TPg::new();
    // no object-state cache: a cache hit never loads the state (debug builds only re-load it to verify the hit)
    pg.obj_cap = 0;
    let mut eng = engine(&pg);
    eng.on_op(&mut pg, req(1, "a"));
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![1]);

    pg.cold_attr.set(1);
    eng.on_op(&mut pg, req(2, "a"));
    eng.on_op(&mut pg, req(3, "a"));
    assert!(
        replied(&settle(&mut pg, &mut eng)).is_empty(),
        "a write overtook the refused one"
    );
    assert_eq!(pg.cold_attr.get(), 0, "the state load ran non-blocking");
    assert!(eng.has_parked());

    eng.retry_woken(&mut pg, &WakeSet::ALL);
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![2, 3]);
    assert!(!eng.has_parked());
}

#[test]
fn a_cause_over_the_bound_is_unnamed() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let many: Vec<u64> = (1..=CAUSE_MAX as u64 + 1).collect();
    pages(&pg, "a", &many);
    eng.on_op(&mut pg, req(1, "a"));
    settle(&mut pg, &mut eng);
    pg.warm_calls.borrow_mut().clear();
    eng.retry_woken(&mut pg, &ws(&[999]));
    assert_eq!(
        pg.warm_calls.borrow().len(),
        1,
        "unknown cause: every wake probes"
    );
}

/// Seeds of a random test (`WAKE_SEEDS=N` for a longer hunt).
fn seeds(default: u64) -> u64 {
    std::env::var("WAKE_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn rnd(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

/// Random page arrivals, shared pages, unnamed causes, `all` wakes, bogus tokens, overflowing batches and op arrivals in
/// between: whenever an object has no pending page, none of its ops may stay gated (a lost wake-up), and no op runs
/// while its object still has a pending page.
#[test]
fn no_wakeup_is_lost_under_random_events() {
    for seed in 1..=seeds(600) {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut pg = TPg::new();
        let mut eng = engine(&pg);
        let nobj = 1 + rnd(&mut s) % 10;
        let names: Vec<String> = (0..nobj).map(|i| format!("obj{i}")).collect();
        for n in &names {
            if rnd(&mut s).is_multiple_of(4) {
                pg.untracked_objs.borrow_mut().insert(n.as_bytes().to_vec());
            }
        }
        let (mut next_page, mut tid) = (1u64, 0u64);
        let mut sent: BTreeMap<u64, usize> = BTreeMap::new();
        let mut done: BTreeSet<u64> = BTreeSet::new();
        for step in 0..80 {
            let ev = rnd(&mut s) % 6;
            if ev <= 2 {
                let k = (rnd(&mut s) % nobj) as usize;
                let name = &names[k];
                let pending = pg
                    .obj_pages
                    .borrow()
                    .get(name.as_bytes())
                    .is_some_and(|p| !p.is_empty());
                if !pending && !rnd(&mut s).is_multiple_of(3) {
                    let mut p = Vec::new();
                    for _ in 0..1 + rnd(&mut s) % 3 {
                        let shared = pg
                            .obj_pages
                            .borrow()
                            .values()
                            .flatten()
                            .copied()
                            .nth((rnd(&mut s) % 7) as usize);
                        match shared {
                            Some(x) if rnd(&mut s).is_multiple_of(3) => p.push(x),
                            _ => {
                                p.push(next_page);
                                next_page += 1;
                            }
                        }
                    }
                    pages(&pg, name, &p);
                }
                tid += 1;
                sent.insert(tid, k);
                eng.on_op(&mut pg, req(tid, name));
            } else if ev <= 4 {
                let pend: Vec<u64> = pg.obj_pages.borrow().values().flatten().copied().collect();
                let mut w = WakeSet::default();
                if !pend.is_empty() {
                    let p = pend[(rnd(&mut s) % pend.len() as u64) as usize];
                    arrive(&pg, &[p]);
                    w.push(p);
                }
                match rnd(&mut s) % 10 {
                    0 => w.all = true,
                    1 => w.push(1 << 40),
                    2 => (0..40).for_each(|i| w.push((1 << 41) + i)),
                    _ => {}
                }
                eng.retry_woken(&mut pg, &w);
            } else {
                eng.retry_woken(&mut pg, &WakeSet::default());
            }
            for t in replied(&settle(&mut pg, &mut eng)) {
                let k = sent[&t];
                assert!(
                    pg.obj_pages
                        .borrow()
                        .get(names[k].as_bytes())
                        .is_none_or(|p| p.is_empty()),
                    "seed {seed} step {step}: op {t} ran while {} still waits for pages",
                    names[k]
                );
                done.insert(t);
            }
            for (&t, &k) in &sent {
                let pend = pg
                    .obj_pages
                    .borrow()
                    .get(names[k].as_bytes())
                    .is_some_and(|p| !p.is_empty());
                assert!(
                    done.contains(&t) || pend,
                    "seed {seed} step {step}: op {t} on {} stays gated with no page pending (lost wake-up)",
                    names[k]
                );
            }
        }
    }
}

#[test]
fn ops_behind_the_probe_bound_are_not_left_waiting_for_a_consumed_wake() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    // 80 unnamed cold ops first (each probe costs one of the 64 probes of a pass), then 60 ops waiting for page 1
    for i in 0..80u64 {
        let n = format!("u{i}");
        pages(&pg, &n, &[100 + i]);
        pg.untracked_objs.borrow_mut().insert(n.as_bytes().to_vec());
        eng.on_op(&mut pg, req(i + 1, &n));
    }
    for i in 0..60u64 {
        let n = format!("n{i}");
        pages(&pg, &n, &[1]);
        eng.on_op(&mut pg, req(1000 + i, &n));
    }
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    arrive(&pg, &[1]);
    eng.retry_woken(&mut pg, &ws(&[1]));
    // the pass stopped at its probe bound before the named ops; their token is consumed, a later pass must still run them
    // (the unnamed ops get their pages, else they would hold the probe bound again as before this change)
    arrive(&pg, &(100..180).collect::<Vec<_>>());
    eng.retry_woken(&mut pg, &ws(&[100]));
    // A budget-limited sweep resumes its suffix before wrapping to the prefix whose pages just arrived; no additional
    // store completion is required, only the host's next-iteration runs (`runs_again`).
    let mut passes = 0;
    while eng.runs_again() {
        assert!(passes < 4, "sweep must finish within a few passes");
        eng.retry_woken(&mut pg, &WakeSet::NONE);
        passes += 1;
    }
    let r = replied(&settle(&mut pg, &mut eng));
    assert_eq!(
        r.len(),
        140,
        "every op ran, the named ones left behind by the probe bound included"
    );
}

/// An overflowing cause set is deliberately unnamed in production. A cold prefix
/// must not monopolize every retry's probe budget after another client's page arrives.
#[test]
fn cold_prefix_does_not_starve_an_unrelated_client() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    for i in 0..80u64 {
        let name = format!("flood{i}");
        pages(&pg, &name, &(100..109).collect::<Vec<_>>());
        eng.on_op(&mut pg, req(i + 1, &name));
    }
    pages(&pg, "victim", &[1]);
    let mut victim = req(1000, "victim");
    victim.conn = 2;
    eng.on_op(&mut pg, victim);
    assert!(settle(&mut pg, &mut eng).is_empty());
    arrive(&pg, &[1]);
    eng.retry_woken(&mut pg, &ws(&[1]));
    // Continue without any further store wake: the flood IO never completes. The host runs the PG again in the next
    // loop iteration while the sweep is unfinished (`runs_again`, `ListShare::pending`).
    let mut passes = 0;
    while eng.runs_again() {
        assert!(
            passes < 4,
            "sweep of 81 gated ops must finish within a few passes"
        );
        eng.retry_woken(&mut pg, &WakeSet::NONE);
        passes += 1;
    }
    let out = settle(&mut pg, &mut eng);
    assert!(out.iter().any(|o| matches!(
        o,
        Out::Reply {
            conn: 2,
            tid: 1000,
            ..
        }
    )));
    assert_eq!(eng.parked_len(), 80);
    assert!(replied(&out).is_empty(), "cold requests must remain parked");
    assert!(eng.quiet_without_wake(), "completed sweep must sleep");
    let probes = eng.c.wake_probes;
    for _ in 0..3 {
        eng.retry_woken(&mut pg, &WakeSet::NONE);
    }
    assert_eq!(eng.c.wake_probes, probes, "cold gate must not busy-loop");
}

/// Removing the preceding clients must preserve an unfinished gate sweep.
#[test]
fn blocklisting_a_cold_prefix_preserves_the_ready_tail_continuation() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let flood_ip = [10, 0, 0, 5];
    for i in 0..80u64 {
        let name = format!("flood{i}");
        pages(&pg, &name, &(100..109).collect::<Vec<_>>());
        let mut flood = req(i + 1, &name);
        flood.addr = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 9, flood_ip, 0);
        eng.on_op(&mut pg, flood);
    }
    pages(&pg, "victim", &[1]);
    eng.on_op(&mut pg, req(1000, "victim"));
    assert!(settle(&mut pg, &mut eng).is_empty());
    for _ in 0..3 {
        eng.retry_woken(&mut pg, &WakeSet::NONE);
    }
    arrive(&pg, &[1]);
    eng.retry_woken(&mut pg, &ws(&[1]));
    assert!(settle(&mut pg, &mut eng).is_empty());
    pg.blocklist.borrow_mut().push(flood_ip);
    eng.check_blocklist(&mut pg);
    let _ = settle(&mut pg, &mut eng); // fencing errors, not the victim reply
    eng.retry_woken(&mut pg, &WakeSet::NONE);
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![1000]);
    assert!(!eng.has_parked());
}

/// A consumed prefix wake survives every remaining slice of a long suffix.
#[test]
fn prefix_wake_survives_multiple_suffix_continuations() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pages(&pg, "victim", &[1]);
    eng.on_op(&mut pg, req(1000, "victim"));
    for i in 0..200u64 {
        let name = format!("flood{i}");
        pages(&pg, &name, &(100..109).collect::<Vec<_>>());
        eng.on_op(&mut pg, req(i + 1, &name));
    }
    for _ in 0..8 {
        eng.retry_woken(&mut pg, &WakeSet::NONE);
    }
    assert!(settle(&mut pg, &mut eng).is_empty());
    assert!(eng.quiet_without_wake());
    eng.retry_woken(&mut pg, &ws(&[999]));
    arrive(&pg, &[1]);
    eng.retry_woken(&mut pg, &ws(&[1]));
    let mut passes = 0;
    while eng.runs_again() {
        assert!(passes < 8, "sweep must finish within a few passes");
        eng.retry_woken(&mut pg, &WakeSet::NONE);
        passes += 1;
    }
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![1000]);
    assert!(eng.quiet_without_wake());
}

/// Cost of one wake event with `G` gated ops waiting for different pages (mock store: a probe is nearly free, so this is
/// the engine's own cost; real probes are tree walks). `cargo test --release -p opexec --test wake perf -- --ignored --nocapture`.
#[test]
#[ignore]
fn perf_wake_per_event() {
    let g: u64 = std::env::var("G")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512);
    let mut lat: Vec<u64> = Vec::new();
    let mut probes = 0u64;
    let mut ops = 0u64;
    let t_all = std::time::Instant::now();
    for rep in 0..40u64 {
        let mut pg = TPg::new();
        let mut eng = engine(&pg);
        for i in 0..g {
            pages(&pg, &format!("o{i}"), &[1000 + i]);
            eng.on_op(&mut pg, req(i + 1, &format!("o{i}")));
        }
        settle(&mut pg, &mut eng);
        let p0 = eng.c.wake_probes;
        let mut s = rep.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut order: Vec<u64> = (0..g).collect();
        for i in (1..order.len()).rev() {
            order.swap(i, (rnd(&mut s) % (i as u64 + 1)) as usize);
        }
        for i in order {
            arrive(&pg, &[1000 + i]);
            let w = ws(&[1000 + i]);
            let t = std::time::Instant::now();
            eng.retry_woken(&mut pg, &w);
            lat.push(t.elapsed().as_nanos() as u64);
            settle(&mut pg, &mut eng);
            ops += 1;
        }
        probes += eng.c.wake_probes - p0;
        assert!(!eng.has_parked());
    }
    lat.sort_unstable();
    let q = |p: f64| lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)];
    eprintln!(
        "G={g} wakes={ops} probes/wake={:.1} ns/wake mean={} p50={} p99={} p99.99={} max={} total={:?}",
        probes as f64 / ops as f64,
        lat.iter().sum::<u64>() / ops,
        q(0.5),
        q(0.99),
        q(0.9999),
        lat[lat.len() - 1],
        t_all.elapsed()
    );
}

fn req_at(tid: u64, oid: &str, off: u64) -> ClientReq {
    ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(mkop(
            oid.as_bytes(),
            vec![OsdOp::write(off, vec![tid as u8; 8])],
        )),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    }
}

/// Ops of one object that wait for different pages: an op whose own page arrived while an earlier op of its object still
/// waited (so it was not probed) runs as soon as that earlier op left, not when some other token of its cause arrives.
#[test]
fn an_op_unblocked_by_its_objects_earlier_op_runs_though_its_own_page_arrived_before() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let slot = |pg: &TPg, n: &str, s: u64, p: &[u64]| {
        pg.slot_pages
            .borrow_mut()
            .insert((n.as_bytes().to_vec(), s), p.to_vec());
    };
    slot(&pg, "a", 0, &[1]);
    slot(&pg, "a", 1, &[2]);
    eng.on_op(&mut pg, req_at(1, "a", 0));
    eng.on_op(&mut pg, req_at(2, "a", 4096));
    settle(&mut pg, &mut eng);
    // page 2 arrives first: op 2 is blocked behind op 1 (same object) and is not probed
    pg.slot_pages
        .borrow_mut()
        .get_mut(&(b"a".to_vec(), 1))
        .unwrap()
        .clear();
    eng.retry_woken(&mut pg, &ws(&[2]));
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    // page 1 arrives: op 1 runs, op 2 follows in the same pass
    pg.slot_pages
        .borrow_mut()
        .get_mut(&(b"a".to_vec(), 0))
        .unwrap()
        .clear();
    eng.retry_woken(&mut pg, &ws(&[1]));
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![1, 2]);
}

/// Like `no_wakeup_is_lost_under_random_events`, with ops of one object waiting for different pages (per-object order
/// blocks the later ones): an op may only stay gated while its own page is pending or an earlier op of its object is.
#[test]
fn no_wakeup_is_lost_with_per_object_order_under_random_events() {
    for seed in 1..=seeds(800) {
        let mut s = seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1;
        let mut pg = TPg::new();
        let mut eng = engine(&pg);
        let nobj = 1 + rnd(&mut s) % 4;
        let names: Vec<String> = (0..nobj).map(|i| format!("obj{i}")).collect();
        for n in &names {
            if rnd(&mut s).is_multiple_of(4) {
                pg.untracked_objs.borrow_mut().insert(n.as_bytes().to_vec());
            }
        }
        let (mut next_page, mut tid) = (1u64, 0u64);
        // tid -> (object, slot)
        let mut sent: BTreeMap<u64, (usize, u64)> = BTreeMap::new();
        let mut done: BTreeSet<u64> = BTreeSet::new();
        let pend = |pg: &TPg, k: usize, j: u64| {
            pg.slot_pages
                .borrow()
                .get(&(names[k].as_bytes().to_vec(), j))
                .is_some_and(|p| !p.is_empty())
        };
        for step in 0..80 {
            let ev = rnd(&mut s) % 6;
            if ev <= 2 {
                let k = (rnd(&mut s) % nobj) as usize;
                let j = rnd(&mut s) % 3;
                if !pend(&pg, k, j) && !rnd(&mut s).is_multiple_of(3) {
                    let mut p = Vec::new();
                    for _ in 0..1 + rnd(&mut s) % 2 {
                        p.push(next_page);
                        next_page += 1;
                    }
                    pg.slot_pages
                        .borrow_mut()
                        .insert((names[k].as_bytes().to_vec(), j), p);
                }
                tid += 1;
                sent.insert(tid, (k, j));
                eng.on_op(&mut pg, req_at(tid, &names[k], j * 4096));
            } else if ev <= 4 {
                let all: Vec<u64> = pg.slot_pages.borrow().values().flatten().copied().collect();
                let mut w = WakeSet::default();
                if !all.is_empty() {
                    let p = all[(rnd(&mut s) % all.len() as u64) as usize];
                    for v in pg.slot_pages.borrow_mut().values_mut() {
                        v.retain(|x| *x != p);
                    }
                    w.push(p);
                }
                if rnd(&mut s).is_multiple_of(10) {
                    w.push(1 << 40);
                }
                eng.retry_woken(&mut pg, &w);
            } else {
                eng.retry_woken(&mut pg, &WakeSet::default());
            }
            for t in replied(&settle(&mut pg, &mut eng)) {
                let (k, j) = sent[&t];
                assert!(
                    !pend(&pg, k, j),
                    "seed {seed} step {step}: op {t} ran while its page is pending"
                );
                done.insert(t);
            }
            for (&t, &(k, j)) in &sent {
                let earlier = sent
                    .iter()
                    .any(|(&u, &(k2, _))| u < t && k2 == k && !done.contains(&u));
                assert!(
                    done.contains(&t) || pend(&pg, k, j) || earlier,
                    "seed {seed} step {step}: op {t} (obj {k} slot {j}) stays gated with nothing pending (lost wake-up)"
                );
            }
        }
    }
}

fn ec_read(tid: u64, oid: &str) -> ClientReq {
    let mut r = req(tid, oid);
    r.op = Box::new(mkop(oid.as_bytes(), vec![OsdOp::read(0, 4096)]));
    r
}

fn ec_tok_of(oid: &str) -> u64 {
    peering::wake::ec_tok(&opexec::head_of(&mkop(oid.as_bytes(), vec![])))
}

fn ec_probed(pg: &TPg) -> Vec<String> {
    pg.ec_wait_calls
        .borrow_mut()
        .drain(..)
        .map(|n| String::from_utf8(n).unwrap())
        .collect()
}

/// EC reads parked on their object's primary read / write (`ec_wait`) name the object's EC token: a store wake or the EC
/// wake of another object probes none of them, the EC wake of their object probes exactly them. A wake whose token is
/// lost on the way (overflowed batch = `all`) and an interval / peering change (`retry`) still run every one of them:
/// no wake-up is lost.
#[test]
fn ec_reads_wake_on_their_object_only_and_never_miss_a_wake() {
    let mut pg = TPg::new();
    pg.ec = true;
    let mut eng: Engine = engine(&pg);
    for i in 0..100u64 {
        pg.ec_busy_objs
            .borrow_mut()
            .insert(format!("o{i}").into_bytes());
        eng.on_op(&mut pg, ec_read(i + 1, &format!("o{i}")));
    }
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    assert_eq!(eng.parked_len(), 100);
    ec_probed(&pg);
    let p0 = eng.c.wake_probes;

    // a store wake and the EC wake of an object nobody waits for: no probe
    eng.retry_woken(&mut pg, &ws(&[7, ec_tok_of("other")]));
    assert!(ec_probed(&pg).is_empty());
    assert_eq!(eng.c.wake_probes, p0);

    // the read of o17 finished: only its op is probed and answered
    pg.ec_busy_objs.borrow_mut().remove(b"o17".as_slice());
    eng.retry_woken(&mut pg, &ws(&[ec_tok_of("o17")]));
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![18]);
    assert_eq!(ec_probed(&pg), vec!["o17"]);
    assert_eq!(eng.c.wake_probes - p0, 1);

    // o5's token is lost in an overflowing batch: the batch degrades to `all`, o5 runs
    pg.ec_busy_objs.borrow_mut().remove(b"o5".as_slice());
    let mut w = WakeSet::default();
    for t in 0..=WAKE_MAX as u64 {
        w.push(1000 + t);
    }
    assert!(w.all);
    eng.retry_woken(&mut pg, &w);
    assert!(replied(&settle(&mut pg, &mut eng)).contains(&6));

    // an interval / peering change re-runs every parked op (`retry`): all finished reads answer
    pg.ec_busy_objs.borrow_mut().clear();
    eng.retry(&mut pg);
    let mut done = BTreeSet::new();
    for _ in 0..4 {
        done.extend(replied(&settle(&mut pg, &mut eng)));
        eng.retry_woken(&mut pg, &WakeSet::ALL);
    }
    done.extend(replied(&settle(&mut pg, &mut eng)));
    assert_eq!(eng.parked_len(), 0);
    assert_eq!(done.len(), 98);
}

fn ec_read_at(tid: u64, oid: &str, off: u64) -> ClientReq {
    let mut r = req(tid, oid);
    r.op = Box::new(mkop(oid.as_bytes(), vec![OsdOp::read(off, 4096)]));
    r
}

/// The replies in `outs` in order: (tid, data of the first op).
fn replies_in_order(outs: &mut Vec<Out>) -> Vec<(u64, Vec<u8>)> {
    let tids = replied(outs);
    tids.into_iter()
        .map(|t| {
            let r = reply_of(outs, 1, t).unwrap();
            assert_eq!(r.result, 0, "tid {t}");
            (t, r.ops[0].outdata.to_vec())
        })
        .collect()
}

/// A sequential reader keeps a queue of small reads of one object in flight from one session; each waits for the EC
/// shard read that covers it (the read token `Env::ec_wait` names). They pass each other at the gate (spec client-ops
/// 5.5 / 5.7 step 9): a read whose data arrived replies at once, whatever reads of the object are still ahead of it, and
/// the wake of its shard read probes only that read (one probe per completion, not one per queued read of the object).
/// A write queued among them keeps the per-object order: it runs after the reads before it, and the reads after it
/// reply after it and see its data.
#[test]
fn ec_reads_of_one_session_pass_each_other_and_a_write_keeps_its_place() {
    const N: u64 = 16;
    const BLK: u64 = 4096;
    let mut pg = TPg::new();
    pg.ec = true;
    let mut eng: Engine = engine(&pg);
    let old: Vec<u8> = (0..N).flat_map(|i| vec![i as u8; BLK as usize]).collect();
    let mut w = req(1, "s");
    w.op = Box::new(mkop(b"s", vec![OsdOp::write(0, old)]));
    eng.on_op(&mut pg, w);
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![1]);
    let tok = peering::wake::ec_rd_tok;
    for i in 0..N {
        pg.ec_rd_busy
            .borrow_mut()
            .insert((b"s".to_vec(), i * BLK), tok(i));
        eng.on_op(&mut pg, ec_read_at(10 + i, "s", i * BLK));
    }
    let mut w = req(50, "s");
    w.op = Box::new(mkop(
        b"s",
        vec![OsdOp::write(0, vec![0xee; (N * BLK) as usize])],
    ));
    eng.on_op(&mut pg, w);
    // the reads after the write find the reads ahead of it still in flight: they wait for those (covering) reads
    for i in 0..N {
        eng.on_op(&mut pg, ec_read_at(60 + i, "s", i * BLK));
    }
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    assert_eq!(eng.parked_len(), 2 * N as usize + 1);

    // the shard reads finish last first: each wake answers exactly its own read, the reads ahead still wait
    for i in (1..N).rev() {
        pg.ec_rd_busy.borrow_mut().remove(&(b"s".to_vec(), i * BLK));
        let p0 = eng.c.wake_probes;
        eng.retry_woken(&mut pg, &ws(&[tok(i)]));
        let mut outs = settle(&mut pg, &mut eng);
        assert_eq!(
            replies_in_order(&mut outs),
            vec![(10 + i, vec![i as u8; BLK as usize])],
            "read {i} waited for the reads of its session ahead of it"
        );
        assert_eq!(
            eng.c.wake_probes - p0,
            1,
            "one probe per shard read completion"
        );
    }
    // the first read finishes: it answers, then the write runs, then the reads behind it (with its data)
    pg.ec_rd_busy.borrow_mut().remove(&(b"s".to_vec(), 0));
    eng.retry_woken(&mut pg, &ws(&[tok(0)]));
    let mut outs = settle(&mut pg, &mut eng);
    // the write's completion wakes what waits for the object (`ec_forget`)
    eng.retry_woken(
        &mut pg,
        &ws(&[peering::wake::ec_tok(&opexec::head_of(&mkop(b"s", vec![])))]),
    );
    outs.extend(settle(&mut pg, &mut eng));
    let got = replies_in_order(&mut outs);
    assert_eq!(
        got.len(),
        N as usize + 2,
        "{:?}",
        got.iter().map(|g| g.0).collect::<Vec<_>>()
    );
    assert_eq!(
        got[0],
        (10, vec![0; BLK as usize]),
        "the first read saw the later write"
    );
    assert_eq!(got[1].0, 50, "a read after the write overtook it");
    let mut after: Vec<u64> = got[2..].iter().map(|g| g.0).collect();
    after.sort_unstable();
    assert_eq!(after, (60..60 + N).collect::<Vec<_>>());
    for (t, d) in &got[2..] {
        assert_eq!(
            d,
            &vec![0xee; BLK as usize],
            "read {t} after the write missed it"
        );
    }
    assert_eq!(eng.parked_len(), 0);
}

/// The gate scan is linear: one wake of a long gate notes each scanned op once and asks one ordering query per probe,
/// it does not compare every probed op with all the ops ahead of it.
#[test]
fn gate_scan_work_is_linear_in_the_gate() {
    const N: u64 = 4000;
    let mut pg = TPg::new();
    let mut eng: Engine = engine(&pg);
    for i in 0..N {
        pages(&pg, &format!("o{i}"), &[1000 + i]);
        eng.on_op(&mut pg, req(i + 1, &format!("o{i}")));
    }
    settle(&mut pg, &mut eng);
    assert_eq!(eng.parked_len(), N as usize);
    let steps0 = eng.c.gate_scan_steps;
    // the last 30 pages arrive: each of those ops is probed behind all the others
    let done: Vec<u64> = (N - 30..N).map(|i| 1000 + i).collect();
    arrive(&pg, &done);
    eng.retry_woken(&mut pg, &ws(&done));
    assert_eq!(replied(&settle(&mut pg, &mut eng)).len(), 30);
    let steps = eng.c.gate_scan_steps - steps0;
    assert!(steps <= 2 * N + 200, "{steps} steps for a gate of {N}");
}

/// A write the store's size check refuses while its pages load (`WriteErr::Blocked`, adr 0021 S8) logs nothing and runs
/// again after the store wake: one reply, one log entry.
#[test]
fn a_blocked_write_runs_again_after_the_wake() {
    let mut pg = TPg::new();
    let mut eng: Engine = engine(&pg);
    pg.check_blocks = 1;
    let n = pg.entries.len();
    eng.on_op(&mut pg, req(1, "o"));
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    assert_eq!(pg.check_blocks, 0);
    assert_eq!(pg.entries.len(), n, "nothing logged");
    eng.retry_woken(&mut pg, &WakeSet::ALL);
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![1]);
    assert_eq!(pg.entries.len(), n + 1);
    assert_eq!(eng.c.writes, 1, "the refused run is not counted");
}

/// A write refused on the PG log head (this PG's parked txn fences pgmeta, cold pgmeta page, admission) means every
/// later write of the PG is refused the same way until a store wake: one log probe per gate scan, not one per gated
/// write, and the writes the scan skips do not use up its probe bound (a read behind them still runs). No write is lost
/// once the log head is ready.
#[test]
fn a_cold_log_head_costs_one_probe_per_scan() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.cold_log.set(u32::MAX);
    let log_probes = |pg: &TPg| u32::MAX - pg.cold_log.get();
    for i in 0..200u64 {
        eng.on_op(&mut pg, req(i + 1, &format!("o{i}")));
    }
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    assert_eq!(eng.parked_len(), 200);
    // every arrival: its own probe and one of the gated writes (was: up to the probe bound of gated writes)
    assert!(log_probes(&pg) <= 2 * 200, "{} log probes", log_probes(&pg));

    eng.on_op(&mut pg, read(1000, "r"));
    assert_eq!(replied(&settle(&mut pg, &mut eng)), vec![1000]);

    let (n0, p0, s0) = (log_probes(&pg), eng.c.wake_probes, eng.c.wake_skips);
    eng.retry_woken(&mut pg, &WakeSet::ALL);
    assert!(replied(&settle(&mut pg, &mut eng)).is_empty());
    assert_eq!(log_probes(&pg) - n0, 1);
    assert_eq!((eng.c.wake_probes - p0, eng.c.wake_skips - s0), (1, 199));

    pg.cold_log.set(0);
    eng.retry_woken(&mut pg, &WakeSet::ALL);
    assert_eq!(replied(&settle(&mut pg, &mut eng)).len(), 200);
    assert!(!eng.has_parked());
}
