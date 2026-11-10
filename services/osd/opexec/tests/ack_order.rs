// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Per-object reply order of one client's ops (ceph_test_rados `finished tid N when last_acked_tid was M`): a
//! write-ordered read never overtakes the writes sent before it, through interval resets, aborts and parks.
mod common;
use common::*;
use denc::types::{EntityAddr, Hobject};
use opexec::{ClientReq, Engine, Out};
use opwire::{OsdOp, flag as mflag};

fn req(tid: u64, oid: &str, ops: Vec<OsdOp>, flags: u32) -> ClientReq {
    let mut op = mkop(oid.as_bytes(), ops);
    op.flags |= flags;
    ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(op),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    }
}

/// ceph_test_rados WriteOp: three stride writes, the header setxattr, an ordered 1-byte read.
fn write_op(eng: &mut Engine, pg: &mut TPg, oid: &str) {
    for t in 1..=3u64 {
        eng.on_op(
            pg,
            req(t, oid, vec![OsdOp::write(t * 10, vec![t as u8; 10])], 0),
        );
    }
    eng.on_op(pg, req(4, oid, vec![OsdOp::setxattr(b"_header", b"h")], 0));
    eng.on_op(pg, req(5, oid, vec![OsdOp::read(0, 1)], mflag::RWORDERED));
}

fn reply_tids(outs: &[Out]) -> Vec<u64> {
    outs.iter()
        .filter_map(|o| match o {
            Out::Reply { conn: 1, tid, .. } => Some(*tid),
            _ => None,
        })
        .collect()
}

fn head(oid: &str) -> Hobject {
    let r = req(0, oid, vec![], 0);
    opexec::engine::head_of(&r.op)
}

#[test]
fn reset_requeues_in_flight_writes_before_the_waiting_read() {
    let mut pg = TPg::new();
    pg.deferred = true;
    let mut eng = engine(&pg);
    write_op(&mut eng, &mut pg, "o");
    assert_eq!(pg.done.len(), 4, "writes pipelined, the read waits");
    // the first write commits, then the interval ends with 2..4 in flight
    let d = std::mem::take(&mut pg.done);
    eng.on_write_done(&mut pg, d[0].0, d[0].1, 0);
    let mut seen = reply_tids(&eng.take_out());
    pg.active = false;
    eng.reset();
    for (t, v) in &d[1..] {
        eng.on_write_done(&mut pg, *t, *v, -11);
    }
    seen.extend(reply_tids(&eng.take_out()));
    pg.active = true;
    pg.deferred = false;
    eng.retry(&mut pg);
    seen.extend(reply_tids(&settle(&mut pg, &mut eng)));
    assert_eq!(seen, vec![1, 2, 3, 4, 5]);
}

#[test]
fn ordered_read_stays_behind_a_write_parked_on_a_degraded_object() {
    // a write waits in the object's queue (behind a read), is parked as degraded when it runs: the ordered read queued
    // after it must not be answered first
    let mut pg = TPg::new();
    pg.deferred = true;
    let mut eng = engine(&pg);
    eng.on_op(&mut pg, req(1, "o", vec![OsdOp::write(0, vec![1; 10])], 0));
    eng.on_op(&mut pg, req(2, "o", vec![OsdOp::read(0, 1)], 0)); // waits for 1
    eng.on_op(&mut pg, req(3, "o", vec![OsdOp::write(10, vec![3; 10])], 0)); // behind the read
    eng.on_op(
        &mut pg,
        req(4, "o", vec![OsdOp::read(0, 1)], mflag::RWORDERED),
    );
    pg.degraded.insert(head("o"));
    pg.deferred = false;
    let mut seen = reply_tids(&settle(&mut pg, &mut eng));
    assert_eq!(seen, vec![1, 2], "3 parked (degraded), 4 behind it");
    pg.degraded.clear();
    eng.retry(&mut pg);
    seen.extend(reply_tids(&settle(&mut pg, &mut eng)));
    assert_eq!(seen, vec![1, 2, 3, 4]);
}

/// Tiny deterministic rng (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The ops of one ceph_test_rados WriteOp on `oid`, client tids `base+1..=base+4`.
fn write_op_reqs(oid: &str, base: u64) -> Vec<ClientReq> {
    vec![
        req(base + 1, oid, vec![OsdOp::write(39_000, vec![1; 9000])], 0),
        req(base + 2, oid, vec![OsdOp::write(129_051, vec![2; 3000])], 0),
        req(
            base + 3,
            oid,
            vec![OsdOp::setxattr(b"_header", b"h"), OsdOp::truncate(159_138)],
            0,
        ),
        req(base + 4, oid, vec![OsdOp::read(0, 1)], mflag::RWORDERED),
    ]
}

/// Random interleavings of an EC primary's events (interval resets with committed / rolled back writes, activation,
/// cold store pages, degraded / missing objects, completions in version order) under WriteOps on two objects: the
/// replies of each object's ops come in submission order (ceph_test_rados `finished tid N when last_acked_tid was M`).
#[test]
fn replies_per_object_stay_in_order_under_random_events() {
    for seed in 1..=3000u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let mut pg = TPg::new();
        pg.ec = true;
        pg.deferred = true;
        pg.deferred_log = true;
        let mut eng = engine(&pg);
        let objs = ["a", "b"];
        let mut todo: Vec<Vec<ClientReq>> = vec![write_op_reqs("a", 0), write_op_reqs("b", 100)];
        for t in &mut todo {
            t.reverse();
        }
        let mut pending: Vec<(u64, denc::types::Eversion)> = Vec::new();
        let mut acked: [u64; 2] = [0, 100];
        let mut trace: Vec<String> = Vec::new();
        let check = |outs: Vec<Out>, acked: &mut [u64; 2], trace: &mut Vec<String>| {
            for t in reply_tids(&outs) {
                let o = (t / 100) as usize;
                trace.push(format!("reply {t}"));
                assert!(
                    t >= acked[o],
                    "seed {seed}: reply {t} after {}: {trace:?}",
                    acked[o]
                );
                acked[o] = t;
            }
        };
        for _step in 0..60 {
            let a = rng.below(10);
            match a {
                0 | 1 => {
                    let o = rng.below(2) as usize;
                    if let Some(r) = todo[o].pop() {
                        trace.push(format!("send {}", r.tid));
                        eng.on_op(&mut pg, r);
                    }
                }
                2 | 3 => {
                    // the PG completes writes in version order
                    if pg.active && !pending.is_empty() {
                        let (t, v) = pending.remove(0);
                        trace.push(format!("done {t}"));
                        eng.on_write_done(&mut pg, t, v, 0);
                    }
                }
                4 => {
                    // interval change: the oldest `keep` writes committed (logged), the rest roll back
                    let keep = rng.below(pending.len() as u64 + 1) as usize;
                    let gone: Vec<_> = pending.split_off(keep);
                    if let Some((_, v)) = gone.first() {
                        pg.entries.retain(|e| e.version < *v);
                        pg.head = pg
                            .entries
                            .last()
                            .map_or(denc::types::Eversion::new(10, 0), |e| e.version);
                    }
                    trace.push(format!("interval keep {keep} drop {}", gone.len()));
                    pending.clear();
                    pg.active = false;
                    pg.epoch += 1;
                    eng.reset();
                }
                5 => {
                    trace.push("activate".into());
                    pg.active = true;
                    eng.retry(&mut pg);
                }
                6 => {
                    let n = rng.below(3) as u32;
                    trace.push(format!("cold {n}"));
                    pg.cold_data.set(n);
                    pg.ec_cold.set(rng.below(3) as u32);
                    pg.refuse_runs.set(rng.below(3) as u32);
                }
                7 => {
                    let h = head(objs[rng.below(2) as usize]);
                    if !pg.degraded.remove(&h) {
                        trace.push(format!("degraded {}", String::from_utf8_lossy(&h.oid)));
                        pg.degraded.insert(h);
                    } else {
                        trace.push("recovered".into());
                        eng.retry(&mut pg);
                    }
                }
                8 => {
                    let h = head(objs[rng.below(2) as usize]);
                    if !pg.missing.remove(&h) {
                        trace.push(format!("missing {}", String::from_utf8_lossy(&h.oid)));
                        pg.missing.insert(h);
                    } else {
                        trace.push("pulled".into());
                        eng.retry(&mut pg);
                    }
                }
                _ => {
                    trace.push("woken".into());
                    eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
                }
            }
            pending.extend(std::mem::take(&mut pg.done));
            check(eng.take_out(), &mut acked, &mut trace);
        }
        // settle: everything is answered eventually
        pg.active = true;
        pg.degraded.clear();
        pg.missing.clear();
        pg.cold_data.set(0);
        pg.ec_cold.set(0);
        pg.refuse_runs.set(0);
        for t in todo.iter_mut() {
            while let Some(r) = t.pop() {
                eng.on_op(&mut pg, r);
            }
        }
        for _ in 0..50 {
            eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
            pending.extend(std::mem::take(&mut pg.done));
            for (t, v) in std::mem::take(&mut pending) {
                eng.on_write_done(&mut pg, t, v, 0);
            }
            pending.extend(std::mem::take(&mut pg.done));
            check(eng.take_out(), &mut acked, &mut trace);
        }
        assert_eq!(acked, [4, 104], "seed {seed}: all answered: {trace:?}");
    }
}

#[test]
fn parked_writes_regated_stay_ahead_of_the_ordered_read_left_in_the_gate() {
    // lab trace (ceph_test_rados, EC primary after an interval reset): w2 parked (degraded), sx parked behind it, the
    // ordered read r skipped in the gate (cold: EC writes in flight); on recovery w2's run was refused (cold page) and
    // re-gated, sx went in after r: r answered before sx
    let mut pg = TPg::new();
    pg.ec = true;
    pg.deferred = true;
    let mut eng = engine(&pg);
    pg.active = false;
    eng.on_op(&mut pg, req(2, "o", vec![OsdOp::append(vec![2; 100])], 0));
    eng.on_op(
        &mut pg,
        req(3, "o", vec![OsdOp::setxattr(b"_header", b"h")], 0),
    );
    eng.on_op(
        &mut pg,
        req(4, "o", vec![OsdOp::read(0, 1)], mflag::RWORDERED),
    );
    pg.degraded.insert(head("o"));
    pg.active = true;
    pg.ec_cold.set(1); // the read is cold in this scan
    eng.retry(&mut pg);
    assert!(reply_tids(&eng.take_out()).is_empty());
    pg.degraded.clear();
    pg.ec_cold.set(1); // still cold
    pg.refuse_runs.set(1); // the parked write's run hits a cold page: re-gated
    eng.retry(&mut pg);
    let mut seen = reply_tids(&eng.take_out());
    pg.deferred = false;
    for _ in 0..4 {
        eng.retry_woken(&mut pg, &peering::wake::WakeSet::ALL);
        let mut d = std::mem::take(&mut pg.done);
        d.sort();
        for (t, v) in d {
            eng.on_write_done(&mut pg, t, v, 0);
        }
        seen.extend(reply_tids(&settle(&mut pg, &mut eng)));
    }
    assert_eq!(seen, vec![2, 3, 4]);
}

#[test]
fn last_write_done_releases_the_object_into_the_cache() {
    // four pipelined writes and a waiting ordered read: each completion lets the next run, the last one leaves the
    // object idle (its state goes to the cache), so the next op of the object is a cache hit
    let mut pg = TPg::new();
    pg.deferred = true;
    let mut eng = engine(&pg);
    write_op(&mut eng, &mut pg, "o");
    let mut seen = Vec::new();
    let mut rounds = 0;
    while !pg.done.is_empty() {
        for (t, v) in std::mem::take(&mut pg.done) {
            eng.on_write_done(&mut pg, t, v, 0);
            seen.extend(reply_tids(&eng.take_out()));
        }
        rounds += 1;
        assert!(rounds < 10, "completions keep coming");
    }
    assert_eq!(seen, vec![1, 2, 3, 4, 5]);
    // a write that finishes at a cacheable PG (deferred PGs never cache) leaves the object idle in the cache
    pg.deferred = false;
    eng.on_op(&mut pg, req(6, "o", vec![OsdOp::write(0, vec![6; 4])], 0));
    assert_eq!(reply_tids(&settle(&mut pg, &mut eng)), vec![6]);
    let hits = eng.c.obj_hits;
    eng.on_op(&mut pg, req(7, "o", vec![OsdOp::read(0, 1)], 0));
    assert_eq!(reply_tids(&eng.take_out()), vec![7]);
    assert_eq!(
        eng.c.obj_hits,
        hits + 1,
        "the idle object came from the cache"
    );
}

/// A write message that changes nothing (here: startsync) is logged (log-only entry with its result) and answered
/// after commit, in order with the object's in-flight writes: never acked ahead of them, and a resend is a dup.
#[test]
fn noop_write_is_logged_and_answered_in_order() {
    let mut pg = TPg::new();
    pg.deferred = true;
    pg.deferred_log = true;
    let mut eng = engine(&pg);
    eng.on_op(&mut pg, req(1, "o", vec![OsdOp::write(0, vec![1; 10])], 0));
    eng.on_op(
        &mut pg,
        req(2, "o", vec![OsdOp::new(opwire::consts::op::STARTSYNC)], 0),
    );
    assert!(
        reply_tids(&eng.take_out()).is_empty(),
        "the no-op is not answered ahead of the in-flight write"
    );
    pg.deferred = false;
    let mut seen = reply_tids(&settle(&mut pg, &mut eng));
    assert_eq!(seen, vec![1, 2]);
    let e = pg.entries.last().expect("log-only entry");
    assert_eq!((e.op, e.return_code), (pgwire::LogOp::ERROR, 0));
    let n = pg.entries.len();
    eng.on_op(
        &mut pg,
        req(2, "o", vec![OsdOp::new(opwire::consts::op::STARTSYNC)], 0),
    );
    seen = reply_tids(&settle(&mut pg, &mut eng));
    assert_eq!(seen, vec![2]);
    assert_eq!(pg.entries.len(), n, "resend answered as a dup");
}

/// Aborted writes still in flight (no reset before the aborts) re-run in arrival order, ahead of the ordered read
/// that waited for them.
#[test]
fn aborts_without_reset_requeue_in_order() {
    let mut pg = TPg::new();
    pg.deferred = true;
    let mut eng = engine(&pg);
    write_op(&mut eng, &mut pg, "o");
    let d = std::mem::take(&mut pg.done);
    assert_eq!(d.len(), 4);
    for (t, v) in &d {
        eng.on_write_done(&mut pg, *t, *v, -11);
    }
    assert!(reply_tids(&eng.take_out()).is_empty());
    pg.deferred = false;
    eng.retry(&mut pg);
    let seen = reply_tids(&settle(&mut pg, &mut eng));
    assert_eq!(seen, vec![1, 2, 3, 4, 5]);
}
