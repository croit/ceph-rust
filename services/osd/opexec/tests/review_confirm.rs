// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Regression tests for the OSD review fixes.
mod common;
use common::*;
use opwire::OsdOp;

fn apply(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64, op: OsdOp) {
    let mut out = run(pg, eng, 1, tid, client(7), mkop(b"o", vec![op]));
    out.extend(settle(pg, eng));
    assert_eq!(reply_of(&mut out, 1, tid).unwrap().result, 0);
}

#[test]
fn review_old_write_resurrects_truncated_tail() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    apply(
        &mut pg,
        &mut eng,
        1,
        OsdOp::write(0, b"0123456789".to_vec()),
    );
    let mut newer = OsdOp::write(0, b"ab".to_vec());
    let mut ext = newer.extent();
    ext.truncate_seq = 2;
    ext.truncate_size = 4;
    newer.set_extent(ext);
    apply(&mut pg, &mut eng, 2, newer);
    assert_eq!(
        pg.store.objects(pg.spg).values().next().unwrap().data,
        b"ab23"
    );
    let mut old = OsdOp::write(2, b"XXXXXX".to_vec());
    let mut ext = old.extent();
    ext.truncate_seq = 1;
    ext.truncate_size = 10;
    old.set_extent(ext);
    apply(&mut pg, &mut eng, 3, old);
    // Stale writes are clipped to the current object size.
    assert_eq!(
        pg.store.objects(pg.spg).values().next().unwrap().data,
        b"abXX"
    );
}

#[test]
fn review_append_applies_incoming_truncate_hint() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    apply(
        &mut pg,
        &mut eng,
        1,
        OsdOp::write(0, b"0123456789".to_vec()),
    );
    let mut append = OsdOp::write(0, b"AB".to_vec());
    append.op = opwire::op::APPEND;
    let mut ext = append.extent();
    ext.truncate_seq = 2;
    ext.truncate_size = 4;
    append.set_extent(ext);
    apply(&mut pg, &mut eng, 2, append);
    // Classic appends at size 10 and uses oi.truncate_seq, ignoring these hints.
    assert_eq!(
        pg.store.objects(pg.spg).values().next().unwrap().data,
        b"0123456789AB"
    );
}

#[test]
fn review_omap_compare_ignores_clear_in_same_message() {
    use std::collections::BTreeMap;
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let mut set = OsdOp::read(0, 0);
    set.op = opwire::op::OMAP_SET_VALS;
    set.indata = denc::to_vec(&BTreeMap::from([(b"k".to_vec(), b"old".to_vec())]))
        .unwrap()
        .into();
    apply(&mut pg, &mut eng, 1, set);
    let mut clear = OsdOp::read(0, 0);
    clear.op = opwire::op::OMAP_CLEAR;
    let mut cmp = OsdOp::read(0, 0);
    cmp.op = opwire::op::OMAP_CMP;
    let assertions: opwire::OmapCmpIn = BTreeMap::from([(b"k".to_vec(), (Vec::new(), 1))]);
    cmp.indata = denc::to_vec(&assertions).unwrap().into();
    let mut out = run(
        &mut pg,
        &mut eng,
        1,
        2,
        client(7),
        mkop(b"o", vec![clear, cmp]),
    );
    out.extend(settle(&mut pg, &mut eng));
    assert_eq!(reply_of(&mut out, 1, 2).unwrap().result, 0);
    assert!(
        pg.store
            .objects(pg.spg)
            .values()
            .next()
            .unwrap()
            .omap
            .is_empty()
    );
}

#[test]
fn review_append_skips_partial_block_prefetch() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    apply(&mut pg, &mut eng, 1, OsdOp::write(0, vec![7u8; 3000]));
    pg.probes.borrow_mut().clear();
    pg.cold_data.set(1);
    let mut append = OsdOp::write(0, b"A".to_vec());
    append.op = opwire::op::APPEND;
    apply(&mut pg, &mut eng, 2, append);
    assert!(pg.probes.borrow().contains(&(3000, 1)));
    assert_eq!(pg.cold_data.get(), 0);
}

#[test]
fn stale_and_empty_writes_beyond_eof_do_not_extend() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let mut initial = OsdOp::write(0, b"abcd".to_vec());
    let mut e = initial.extent();
    e.truncate_seq = 2;
    e.truncate_size = 4;
    initial.set_extent(e);
    apply(&mut pg, &mut eng, 1, initial);
    for (i, data) in [b"xx".as_slice(), b""].into_iter().enumerate() {
        let mut old = OsdOp::write(6, data.to_vec());
        let mut e = old.extent();
        e.truncate_seq = 1;
        e.truncate_size = 10;
        old.set_extent(e);
        apply(&mut pg, &mut eng, 2 + i as u64, old);
        assert_eq!(
            pg.store.objects(pg.spg).values().next().unwrap().data,
            b"abcd"
        );
    }
}
