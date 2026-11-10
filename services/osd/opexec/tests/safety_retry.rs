// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Reexecution preserves the requested range; compact writes charge their expanded storage.
mod common;
use common::*;
use denc::types::EntityAddr;
use opexec::{ClientReq, Engine};
use opwire::{OsdOp, errno};

fn feed(pg: &mut TPg, eng: &mut Engine, tid: u64, ops: Vec<OsdOp>) {
    eng.on_op(
        pg,
        ClientReq {
            placement_read: None,
            conn: 1,
            tid,
            op: Box::new(mkop(b"o", ops)),
            who: client(7),
            addr: EntityAddr::default(),
            peer_addr: EntityAddr::default(),
            caps: None,
            features: u64::MAX,
        },
    );
}

fn zero_after_failed_shrink(prefix: usize) {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let original = vec![0x5a; 8192];
    let mut outs = run(
        &mut pg,
        &mut eng,
        1,
        1,
        client(7),
        mkop(b"o", vec![OsdOp::write(0, original.clone())]),
    );
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    let head = pg.store.objects(pg.spg).keys().next().unwrap().clone();

    // EC reserves a version and projects the shrink while its boundary-stripe RMW is pending.
    pg.ec = true;
    pg.deferred = true;
    feed(&mut pg, &mut eng, 2, vec![OsdOp::truncate(4096)]);
    let pending = std::mem::take(&mut pg.done);
    assert_eq!(pending.len(), 1);
    let (shrink, version) = pending[0];
    assert_eq!(eng.in_flight(), 1);

    // The scrub write gate returns Degraded before the next op enters the EC dependency chain.
    pg.degraded.insert(head.clone());
    let mut ops = vec![OsdOp::stat(); prefix];
    ops.push(OsdOp::zero(0, 4096));
    feed(&mut pg, &mut eng, 3, ops);
    assert_eq!(eng.c.parked_obj, 1);
    assert!(eng.take_out().is_empty());
    assert_eq!(pg.store.objects(pg.spg)[&head].data, original);

    // The earlier RMW fails before logging, discarding the projected size. Scrub then unblocks writes.
    eng.on_write_done(&mut pg, shrink, version, -errno::EIO);
    let mut outs = eng.take_out();
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, -errno::EIO);
    pg.deferred = false;
    pg.degraded.clear();
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 3).unwrap().result, 0);
    let mut expected = original;
    expected[..4096].fill(0);
    assert_eq!(pg.store.objects(pg.spg)[&head].data, expected);
}

#[test]
fn zero_retry_after_failed_ec_shrink_preserves_tail_inline() {
    zero_after_failed_shrink(0);
}

#[test]
fn zero_retry_after_failed_ec_shrink_preserves_tail_spilled() {
    zero_after_failed_shrink(4);
}

#[test]
fn writesame_rejects_expanded_cost_before_logging_for_both_pool_types() {
    for ec in [false, true] {
        let mut pg = TPg::new();
        pg.ec = ec;
        pg.room_bytes = Some(3 << 20);
        let mut eng = engine(&pg);
        let before = pg.head;
        let mut outs = run(
            &mut pg,
            &mut eng,
            1,
            1,
            client(7),
            mkop(b"o", vec![OsdOp::writesame(0, 4 << 20, vec![0x5a; 512])]),
        );
        assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, -errno::ENOSPC);
        assert_eq!(pg.head, before, "space refusal must not enter the PG log");
        assert!(pg.store.objects(pg.spg).is_empty());
        let mut outs = run(
            &mut pg,
            &mut eng,
            1,
            2,
            client(7),
            mkop(b"o", vec![OsdOp::writesame(0, 4096, b"ABCD".to_vec())]),
        );
        assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
        assert_eq!(
            pg.store.objects(pg.spg).values().next().unwrap().data,
            b"ABCD".repeat(1024)
        );
    }
}
