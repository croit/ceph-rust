// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! A pure read passes a write of its object that waits at a write-only gate (client-ops 5.4 #16, 5.5 (6), 5.12): the
//! write has not started (nothing logged, sent or applied), the read returns the state before it. A write that started,
//! a write parked on an object missing here, RWORDERED reads and every write keep their place. Replicated and EC.
mod common;
use common::*;
use denc::types::{EntityAddr, Hobject};
use opexec::{ClientReq, Engine, Out};
use opwire::{OsdOp, flag as mflag};

fn req(tid: u64, ops: Vec<OsdOp>, flags: u32) -> ClientReq {
    let mut op = mkop(b"o", ops);
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

/// Overwrite of the whole 8-byte object with `fill`.
fn write(tid: u64, fill: u8) -> ClientReq {
    req(tid, vec![OsdOp::write(0, vec![fill; 8])], 0)
}

fn read(tid: u64) -> ClientReq {
    req(tid, vec![OsdOp::read(0, 8)], 0)
}

fn ordered_read(tid: u64) -> ClientReq {
    req(tid, vec![OsdOp::read(0, 8)], mflag::RWORDERED)
}

fn head() -> Hobject {
    opexec::engine::head_of(&mkop(b"o", vec![]))
}

/// Replies in emission order: `(tid, result, data of the first op)`.
fn answers(mut outs: Vec<Out>) -> Vec<(u64, i32, Vec<u8>)> {
    let tids: Vec<u64> = outs
        .iter()
        .filter_map(|o| match o {
            Out::Reply { conn: 1, tid, .. } => Some(*tid),
            _ => None,
        })
        .collect();
    tids.into_iter()
        .map(|t| {
            let r = reply_of(&mut outs, 1, t).unwrap();
            let d = r
                .ops
                .first()
                .map(|o| o.outdata.to_vec())
                .unwrap_or_default();
            (t, r.result, d)
        })
        .collect()
}

fn tids(a: &[(u64, i32, Vec<u8>)]) -> Vec<u64> {
    a.iter().map(|x| x.0).collect()
}

/// A PG (EC or replicated) whose object "o" holds `[1; 8]`.
fn seeded(ec: bool) -> (TPg, Engine) {
    let mut pg = TPg::new();
    pg.ec = ec;
    let mut eng = engine(&pg);
    eng.on_op(&mut pg, write(1, 1));
    let a = answers(settle(&mut pg, &mut eng));
    assert_eq!(a, vec![(1, 0, vec![])], "seed write");
    (pg, eng)
}

fn submit(pg: &mut TPg, eng: &mut Engine, r: ClientReq) {
    eng.on_op(pg, r);
}

#[test]
fn pure_read_passes_a_write_parked_on_an_object_degraded_on_a_peer() {
    for ec in [false, true] {
        let (mut pg, mut eng) = seeded(ec);
        pg.degraded.insert(head());
        submit(&mut pg, &mut eng, write(2, 2));
        submit(&mut pg, &mut eng, read(3));
        submit(&mut pg, &mut eng, write(4, 4));
        submit(&mut pg, &mut eng, ordered_read(5));
        submit(&mut pg, &mut eng, read(6));
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(
            a,
            vec![(3, 0, vec![1; 8]), (6, 0, vec![1; 8])],
            "ec={ec}: pure reads answered at once with the state before the parked writes"
        );
        assert_eq!(
            pg.entries.len(),
            1,
            "ec={ec}: nothing of the parked writes logged"
        );
        pg.degraded.clear();
        eng.retry(&mut pg);
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(
            tids(&a),
            vec![2, 4, 5],
            "ec={ec}: writes, then the RWORDERED read, in order"
        );
        assert_eq!(
            a[2].2,
            vec![4; 8],
            "ec={ec}: RWORDERED read sees both writes"
        );
        submit(&mut pg, &mut eng, read(7));
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(a, vec![(7, 0, vec![4; 8])], "ec={ec}");
        assert!(!eng.has_parked());
    }
}

#[test]
fn pure_read_passes_a_write_blocked_by_scrub() {
    for ec in [false, true] {
        let (mut pg, mut eng) = seeded(ec);
        // the write runs in memory, its submit is refused (scrub write block, `WriteErr::Degraded`): parked
        pg.scrub.insert(head());
        submit(&mut pg, &mut eng, write(2, 2));
        submit(&mut pg, &mut eng, read(3));
        submit(&mut pg, &mut eng, ordered_read(4));
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(a, vec![(3, 0, vec![1; 8])], "ec={ec}");
        pg.scrub.clear();
        eng.retry(&mut pg);
        submit(&mut pg, &mut eng, read(5));
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(tids(&a), vec![2, 4, 5], "ec={ec}");
        assert_eq!(a[1].2, vec![2; 8], "ec={ec}");
        assert_eq!(a[2].2, vec![2; 8], "ec={ec}");
    }
}

#[test]
fn read_after_a_started_write_waits_for_it_and_never_sees_a_parked_one() {
    for ec in [false, true] {
        let (mut pg, mut eng) = seeded(ec);
        // write 2 is submitted (logged, applied here, repops out): it has started
        submit(&mut pg, &mut eng, write(2, 2));
        assert_eq!(pg.entries.len(), 2);
        assert!(eng.take_out().is_empty(), "ec={ec}: write 2 in flight");
        // the object degrades afterwards: write 4 queues behind read 3 and parks when it runs; reads wait for 2 only
        pg.degraded.insert(head());
        submit(&mut pg, &mut eng, read(3));
        submit(&mut pg, &mut eng, write(4, 4));
        submit(&mut pg, &mut eng, read(5));
        assert!(
            eng.take_out().is_empty(),
            "ec={ec}: reads wait for the write in flight"
        );
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(
            a,
            vec![(2, 0, vec![]), (3, 0, vec![2; 8]), (5, 0, vec![2; 8])],
            "ec={ec}: reads after write 2 see it once it is durable, never the parked write 4"
        );
        pg.degraded.clear();
        eng.retry(&mut pg);
        submit(&mut pg, &mut eng, read(6));
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(a, vec![(4, 0, vec![]), (6, 0, vec![4; 8])], "ec={ec}");
    }
}

#[test]
fn pure_reads_queued_behind_a_write_in_flight_pass_writes_parked_on_its_completion() {
    for ec in [false, true] {
        let (mut pg, mut eng) = seeded(ec);
        submit(&mut pg, &mut eng, write(2, 2));
        // queued on the object behind the write in flight, in arrival order
        submit(&mut pg, &mut eng, read(3));
        submit(&mut pg, &mut eng, write(4, 4));
        submit(&mut pg, &mut eng, read(5));
        submit(&mut pg, &mut eng, write(6, 6));
        submit(&mut pg, &mut eng, read(7));
        assert!(eng.take_out().is_empty(), "ec={ec}");
        // the object degrades before write 2 completes: write 4 parks when it runs, write 6 queues behind it
        pg.degraded.insert(head());
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(
            a,
            vec![
                (2, 0, vec![]),
                (3, 0, vec![2; 8]),
                (5, 0, vec![2; 8]),
                (7, 0, vec![2; 8])
            ],
            "ec={ec}"
        );
        pg.degraded.clear();
        eng.retry(&mut pg);
        submit(&mut pg, &mut eng, read(8));
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(
            a,
            vec![(4, 0, vec![]), (6, 0, vec![]), (8, 0, vec![6; 8])],
            "ec={ec}"
        );
    }
}

#[test]
fn reads_wait_with_a_write_parked_on_an_object_missing_here() {
    for ec in [false, true] {
        let (mut pg, mut eng) = seeded(ec);
        // missing on the primary: reads wait for the recovery too (client-ops 5.4 #15), no pass
        pg.missing.insert(head());
        submit(&mut pg, &mut eng, write(2, 2));
        submit(&mut pg, &mut eng, read(3));
        assert!(settle(&mut pg, &mut eng).is_empty(), "ec={ec}");
        // recovered, the parked ops not yet run again: a new read does not pass the write either
        pg.missing.clear();
        submit(&mut pg, &mut eng, read(4));
        assert!(settle(&mut pg, &mut eng).is_empty(), "ec={ec}");
        eng.retry(&mut pg);
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(
            a,
            vec![(2, 0, vec![]), (3, 0, vec![2; 8]), (4, 0, vec![2; 8])],
            "ec={ec}"
        );
    }
}

#[test]
fn gated_read_passes_the_write_that_parks_ahead_of_it() {
    for ec in [false, true] {
        let (mut pg, mut eng) = seeded(ec);
        pg.active = false;
        submit(&mut pg, &mut eng, write(2, 2));
        submit(&mut pg, &mut eng, read(3));
        submit(&mut pg, &mut eng, ordered_read(4));
        pg.active = true;
        pg.degraded.insert(head());
        eng.retry(&mut pg);
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(a, vec![(3, 0, vec![1; 8])], "ec={ec}");
        pg.degraded.clear();
        eng.retry(&mut pg);
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(tids(&a), vec![2, 4], "ec={ec}");
        assert_eq!(a[1].2, vec![2; 8], "ec={ec}");
    }
}

/// Full pool (client-ops 5.4 #11, 5.7 step 5): a growing write is dropped, not parked (the client resends it once the
/// flag clears), so a read is never held by it; the resend applies in order with later writes.
#[test]
fn full_pool_drops_the_write_and_reads_answer_old_data() {
    for ec in [false, true] {
        let (mut pg, mut eng) = seeded(ec);
        let grow = |tid| req(tid, vec![OsdOp::write(0, vec![2; 16])], 0);
        // step 5: pool full, growing write dropped without a reply
        pg.full = (true, false);
        submit(&mut pg, &mut eng, grow(2));
        submit(&mut pg, &mut eng, read(3));
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(a, vec![(3, 0, vec![1; 8])], "ec={ec}");
        assert_eq!(
            eng.take_dropped().len(),
            1,
            "ec={ec}: write dropped, map shared"
        );
        // #11: sent before the map that marked the pool full
        pg.full = (false, false);
        pg.marked_full = 11;
        submit(&mut pg, &mut eng, grow(2));
        submit(&mut pg, &mut eng, read(4));
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(a, vec![(4, 0, vec![1; 8])], "ec={ec}");
        assert_eq!(eng.take_dropped().len(), 1, "ec={ec}");
        // the client resends with the newer map, then writes on
        let resend = |r: ClientReq| {
            let mut r = r;
            r.op.osdmap_epoch = 12;
            r
        };
        submit(&mut pg, &mut eng, resend(grow(2)));
        submit(&mut pg, &mut eng, resend(write(5, 5)));
        submit(&mut pg, &mut eng, resend(read(6)));
        let a = answers(settle(&mut pg, &mut eng));
        assert_eq!(
            a,
            vec![(2, 0, vec![]), (5, 0, vec![]), (6, 0, vec![5; 8])],
            "ec={ec}"
        );
        assert!(eng.take_dropped().is_empty(), "ec={ec}");
    }
}
