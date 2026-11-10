// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Replica side of an omap range removal (adr 0021 am. 25): a repop with a removal that the replica holds for cold
//! store pages keeps its order with the sets around it (also a set inside the removed range), is acked only after it
//! applied, and a scrub request queued behind it sees the state after the removal; a primary that dies while a replica
//! holds its removal ends with identical copies. The classic model sees the same messages as without the hold.
mod common;
use common::*;
use peering::Body;
use std::collections::BTreeMap;

const KEYS: usize = 200;

fn key(i: usize) -> Vec<u8> {
    format!("k{i:05}").into_bytes()
}

fn kv(a: usize, b: usize, v: u8) -> Vec<(Vec<u8>, Vec<u8>)> {
    (a..b).map(|i| (key(i), vec![v; 8])).collect()
}

fn omap_of(s: &Sim, osd: i32) -> BTreeMap<Vec<u8>, Vec<u8>> {
    s.nodes[&osd].store.objects(spg(1, 0))[&hobj(1, "idx")]
        .omap
        .clone()
}

fn setup(seed: u64) -> (Sim, Vec<i32>) {
    let mut s = cluster(seed, &[0, 1, 2], 1, 3, 2, 1);
    s.classic_all();
    let acting = s.acting_of(spg(1, 0).pgid);
    let t = s
        .write_ops(
            1,
            0,
            "idx",
            &[EcOp::Touch, EcOp::OmapSet(kv(0, KEYS, 1))],
            Some(0),
        )
        .unwrap();
    s.wait_writes(&[t], spg(1, 0));
    (s, acting)
}

fn tids_after(s: &mut Sim, ops: Vec<Vec<EcOp>>) -> Vec<u64> {
    let mut v = vec![];
    for o in ops {
        v.push(s.write_ops(1, 0, "idx", &o, Some(0)).unwrap());
    }
    v
}

fn all_equal(s: &Sim, acting: &[i32]) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let want = omap_of(s, acting[0]);
    for o in acting {
        assert_eq!(omap_of(s, *o), want, "osd.{o} omap identical");
    }
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
    want
}

/// The removal, a set INSIDE the removed range behind it, and a second removal behind that: applied in order on the
/// waiting replica (a reordered replica keeps/loses the wrong keys), acked only once applied.
#[test]
fn held_repop_keeps_order_and_acks_after_apply() {
    let (mut s, acting) = setup(91);
    let slow = acting[2];
    s.nodes[&slow].store.warm_waits.set(6);
    let tids = tids_after(
        &mut s,
        vec![
            vec![EcOp::OmapRmRange(key(10), key(150))],
            vec![EcOp::OmapSet(kv(20, 25, 9))],
            vec![EcOp::OmapRmRange(key(22), key(23))],
            vec![EcOp::OmapSet(kv(300, 301, 7))],
        ],
    );
    s.run_for(MS);
    assert!(
        omap_of(&s, slow).len() == KEYS,
        "replica applied nothing while its pages are cold"
    );
    s.wait_writes(&tids, spg(1, 0));
    s.run_for(500 * MS);
    let m = all_equal(&s, &acting);
    let mut want: BTreeMap<Vec<u8>, Vec<u8>> = kv(0, 10, 1).into_iter().collect();
    want.extend(kv(150, KEYS, 1));
    want.extend(kv(20, 25, 9));
    want.remove(&key(22));
    want.extend(kv(300, 301, 7));
    assert_eq!(m, want);
    assert_eq!(
        s.nodes[&slow].store.warm_waits.get(),
        0,
        "probes ran to warm"
    );
}

/// The primary dies while the replica holds its repop: the held messages go with the interval, the PG recovers to the
/// same content everywhere (the removal was never acked, so either outcome is legal, but all copies agree).
#[test]
fn new_interval_drops_held_repops() {
    let (mut s, acting) = setup(94);
    let (prim, slow) = (acting[0], acting[2]);
    s.nodes[&slow].store.warm_waits.set(1_000_000);
    let _ = tids_after(
        &mut s,
        vec![
            vec![EcOp::OmapRmRange(key(0), key(100))],
            vec![EcOp::OmapSet(kv(5, 6, 3))],
        ],
    );
    s.run_for(20 * MS);
    s.kill(prim);
    s.run_for(300 * MS);
    s.nodes[&slow].store.warm_waits.set(0);
    s.restart(prim);
    s.run_until(120_000 * MS, "pool clean", |s| s.pool_clean(1));
    let want = omap_of(&s, acting[1]);
    for o in &acting {
        assert_eq!(omap_of(&s, *o), want, "osd.{o} omap identical");
    }
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
}

/// A scrub chunk request queued on the wire behind the held repop (a classic primary asks for maps once its own copy
/// applied, not once the replicas acked) answers with the state AFTER the removal: a map of the pre-removal state is a
/// false inconsistency. Same for every replica.
#[test]
fn scrub_request_behind_held_repop_sees_the_removal() {
    use denc::types::Hobject;
    use replwire::{MOSDRepScrub, ReplMsg};
    let (mut s, acting) = setup(95);
    let (prim, slow, fast) = (acting[0], acting[2], acting[1]);
    s.nodes[&slow].store.warm_waits.set(20);
    s.capture = true;
    let pg = spg(1, 0);
    let tids = tids_after(&mut s, vec![vec![EcOp::OmapRmRange(key(10), key(150))]]);
    let e = s.epoch();
    for r in [slow, fast] {
        let min = s.pg(r, pg).unwrap().last_peering_reset();
        let req = MOSDRepScrub {
            pgid: pg,
            map_epoch: e,
            chunky: true,
            start: Hobject::MIN(),
            end: Hobject::MAX(),
            deep: true,
            seed: 0xFFFF_FFFF,
            min_epoch: min,
            ..Default::default()
        };
        s.inject(prim, r, Body::Repl(req.into()));
    }
    s.run_until(100 * MS, "the request waits behind the repop", |s| {
        s.pg(slow, pg).unwrap().repops_held() >= 2
    });
    s.wait_writes(&tids, pg);
    s.run_for(500 * MS);
    let maps: BTreeMap<i32, _> = s
        .captured
        .iter()
        .filter_map(|(f, _, b)| match b {
            Body::Repl(ReplMsg::RepScrubMap(m)) => {
                Some((*f, m.map.objects[&hobj(1, "idx")].clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(maps.len(), 2);
    assert_eq!(maps[&slow].object_omap_keys, (KEYS - 140) as u64);
    assert_eq!(maps[&slow].omap_digest, maps[&fast].omap_digest);
    all_equal(&s, &acting);
}
