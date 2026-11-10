// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Replica-side scrub (spec scrub.md 4) against a simulated cluster: a primary-side stub injects
//! reservation and chunk requests, the replica's replies are checked.
mod common;
use common::*;
use denc::types::{Hobject, PgShard, ShardId, SpgT};
use peering::{Action, Body};
use replwire::{MOSDRepScrub, MOSDRepScrubMap, MOSDScrubReserve, ReplMsg};

fn rep_scrub(
    pg: SpgT,
    epoch: u32,
    min_epoch: u32,
    start: Hobject,
    end: Hobject,
    deep: bool,
) -> Body {
    Body::Repl(
        MOSDRepScrub {
            pgid: pg,
            map_epoch: epoch,
            chunky: true,
            start,
            end,
            deep,
            seed: 0xFFFF_FFFF,
            min_epoch,
            ..Default::default()
        }
        .into(),
    )
}

fn reserve(pg: SpgT, epoch: u32, ty: i32, from: i32, nonce: u32, wait: bool) -> Body {
    Body::Repl(
        MOSDScrubReserve {
            pgid: pg,
            map_epoch: epoch,
            ty,
            from: PgShard {
                osd: from,
                shard: ShardId::NO_SHARD,
            },
            nonce,
            wait_for_resources: wait,
        }
        .into(),
    )
}

fn maps(s: &Sim, from: i32) -> Vec<MOSDRepScrubMap> {
    s.captured
        .iter()
        .filter_map(|(f, _, b)| match b {
            Body::Repl(ReplMsg::RepScrubMap(m)) if *f == from => Some(m.clone()),
            _ => None,
        })
        .collect()
}

fn reserves(s: &Sim, from: i32) -> Vec<MOSDScrubReserve> {
    s.captured
        .iter()
        .filter_map(|(f, _, b)| match b {
            Body::Repl(ReplMsg::ScrubReserve(m)) if *f == from => Some(m.clone()),
            _ => None,
        })
        .collect()
}

fn setup(seed: u64) -> (Sim, SpgT, i32, i32) {
    let mut s = cluster(seed, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let t: Vec<u64> = ["a", "b", "c"]
        .iter()
        .map(|n| {
            s.write_obj(1, 0, n, format!("data-{n}").as_bytes())
                .unwrap()
        })
        .collect();
    s.wait_writes(&t, pg);
    s.run_for(100 * MS);
    let prim = s.primary_of(pg.pgid);
    let rep = s.acting_of(pg.pgid)[1];
    s.capture = true;
    (s, pg, prim, rep)
}

fn lpr(s: &Sim, osd: i32, pg: SpgT) -> u32 {
    s.pg(osd, pg).unwrap().last_peering_reset()
}

#[test]
fn shallow_and_deep_chunk() {
    let (mut s, pg, prim, rep) = setup(70);
    let e = s.epoch();
    let min = lpr(&s, rep, pg);
    // extra state on the replica: user attr, an internal attr that must stay invisible, omap + header
    let ha = hobj(1, "a");
    {
        let p = s
            .nodes
            .get_mut(&rep)
            .unwrap()
            .store
            .pgs
            .get_mut(&pg)
            .unwrap();
        let o = p.objects.get_mut(&ha).unwrap();
        o.xattrs.insert(b"_user".to_vec(), b"uv".to_vec());
        o.xattrs.insert(b"internal".to_vec(), b"x".to_vec());
        o.omap.insert(b"k".to_vec(), b"v".to_vec());
        o.omap_header = b"hdr".to_vec();
    }
    s.inject(
        prim,
        rep,
        rep_scrub(pg, e, min, Hobject::MIN(), Hobject::MAX(), false),
    );
    s.run_for(100 * MS);
    let m = maps(&s, rep);
    assert_eq!(m.len(), 1);
    let m = &m[0];
    assert_eq!(m.map_epoch, min, "echo of min_epoch");
    assert_eq!(m.from.osd, rep);
    assert_eq!(m.pgid, pg);
    assert!(!m.preempted);
    assert_eq!(m.map.objects.len(), 3);
    let oa = &m.map.objects[&ha];
    assert_eq!(oa.size, 6);
    assert!(!oa.digest_present && !oa.omap_digest_present);
    assert_eq!(
        oa.attrs.keys().cloned().collect::<Vec<_>>(),
        vec![b"_".to_vec(), b"_user".to_vec()]
    );
    // the order is the hobject order and sizes follow the data
    let names: Vec<_> = m.map.objects.keys().cloned().collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
    assert!(m.map.valid_through > Default::default());

    // deep
    s.captured.clear();
    s.inject(
        prim,
        rep,
        rep_scrub(pg, e, min, Hobject::MIN(), Hobject::MAX(), true),
    );
    s.run_for(100 * MS);
    let m = &maps(&s, rep)[0];
    let oa = &m.map.objects[&ha];
    assert!(oa.digest_present && oa.omap_digest_present);
    assert_eq!(oa.digest, crc::crc32c(0xFFFF_FFFF, b"data-a"));
    let mut want = crc::crc32c(0xFFFF_FFFF, b"hdr");
    for p in [&[1u8, 0, 0, 0, b'k'][..], &[1, 0, 0, 0, b'v'][..]] {
        want = crc::crc32c(want, p);
    }
    assert_eq!(oa.omap_digest, want);
    assert_eq!((oa.object_omap_keys, oa.object_omap_bytes), (1, 1));
    let ob = &m.map.objects[&hobj(1, "b")];
    assert_eq!(ob.omap_digest, 0xFFFF_FFFF);
    assert!(ob.omap_digest_present);
    assert_eq!((ob.object_omap_keys, ob.object_omap_bytes), (0, 0));
    assert_eq!(ob.digest, crc::crc32c(0xFFFF_FFFF, b"data-b"));
    assert_eq!(s.pg(rep, pg).unwrap().scrub_chunks_served(), 2);
    assert!(!s.pg(rep, pg).unwrap().scrub_chunk_active());
}

#[test]
fn range_bounds() {
    let (mut s, pg, prim, rep) = setup(71);
    let e = s.epoch();
    let min = lpr(&s, rep, pg);
    let mut hs: Vec<Hobject> = ["a", "b", "c"].iter().map(|n| hobj(1, n)).collect();
    hs.sort();
    // [h1, h2) = exactly h1 ; end exclusive
    s.inject(
        prim,
        rep,
        rep_scrub(pg, e, min, hs[1].clone(), hs[2].clone(), false),
    );
    s.inject(
        prim,
        rep,
        rep_scrub(pg, e, min, hs[2].clone(), Hobject::MAX(), false),
    );
    s.run_for(100 * MS);
    let m = maps(&s, rep);
    assert_eq!(m.len(), 2);
    assert_eq!(m[0].map.objects.keys().collect::<Vec<_>>(), vec![&hs[1]]);
    assert_eq!(m[1].map.objects.keys().collect::<Vec<_>>(), vec![&hs[2]]);
}

#[test]
fn request_behind_repop_sees_the_write() {
    let (mut s, pg, prim, rep) = setup(72);
    let e = s.epoch();
    let min = lpr(&s, rep, pg);
    let t = s.write_obj(1, 0, "late", b"zz").unwrap();
    // same connection order: the RepOp reaches the replica before this request
    s.inject(
        prim,
        rep,
        rep_scrub(pg, e, min, Hobject::MIN(), Hobject::MAX(), true),
    );
    s.wait_writes(&[t], pg);
    s.run_for(100 * MS);
    let m = maps(&s, rep);
    assert_eq!(m.len(), 1);
    let o = &m[0].map.objects[&hobj(1, "late")];
    assert_eq!(o.size, 2);
    assert_eq!(o.digest, crc::crc32c(0xFFFF_FFFF, b"zz"));
}

#[test]
fn stale_requests_are_dropped() {
    let (mut s, pg, prim, rep) = setup(73);
    let e = s.epoch();
    let min = lpr(&s, rep, pg);
    // min_epoch older than our last peering reset, and a non-primary sender: no reply
    s.inject(
        prim,
        rep,
        rep_scrub(pg, e, 0, Hobject::MIN(), Hobject::MAX(), false),
    );
    let other = (0..3).find(|o| *o != prim && *o != rep).unwrap();
    s.inject(
        other,
        rep,
        rep_scrub(pg, e, min, Hobject::MIN(), Hobject::MAX(), false),
    );
    s.run_for(100 * MS);
    assert!(maps(&s, rep).is_empty());
    assert_eq!(s.pg(rep, pg).unwrap().scrub_chunks_served(), 0);
    // a primary receiving a scrub chunk request ignores it
    s.inject(
        rep,
        prim,
        rep_scrub(pg, e, min, Hobject::MIN(), Hobject::MAX(), false),
    );
    s.run_for(100 * MS);
    assert!(maps(&s, prim).is_empty());
}

fn two_pgs(seed: u64) -> (Sim, SpgT, SpgT, i32, i32, i32) {
    let s = cluster_cfg(seed, &[0, 1, 2], 1, 3, 2, 2, |c| c.max_scrubs = 1);
    let (p1, p2) = (spg(1, 0), spg(1, 1));
    let (a, b) = (s.primary_of(p1.pgid), s.primary_of(p2.pgid));
    let rep = (0..3).find(|o| *o != a && *o != b).unwrap();
    (s, p1, p2, a, b, rep)
}

#[test]
fn reservations_limit_release() {
    let (mut s, p1, p2, prim, prim2, rep) = two_pgs(74);
    let e = s.epoch();
    s.capture = true;
    // pg1 wait=true: grant, echoing epoch + nonce
    s.inject(
        prim,
        rep,
        reserve(p1, e, MOSDScrubReserve::REQUEST, prim, 7, true),
    );
    s.run_for(50 * MS);
    let r = reserves(&s, rep);
    assert_eq!(r.len(), 1);
    assert_eq!(
        (r[0].ty, r[0].nonce, r[0].map_epoch, r[0].from.osd),
        (MOSDScrubReserve::GRANT, 7, e, rep)
    );
    assert_eq!(r[0].pgid, p1);
    // pg2 wait=true: queued, no answer
    s.inject(
        prim2,
        rep,
        reserve(p2, e, MOSDScrubReserve::REQUEST, prim2, 9, true),
    );
    s.run_for(50 * MS);
    assert_eq!(reserves(&s, rep).len(), 1);
    assert!(s.pg(rep, p2).unwrap().scrub_reserved());
    // release pg1: pg2 gets its grant
    s.inject(
        prim,
        rep,
        reserve(p1, e, MOSDScrubReserve::RELEASE, prim, 0, false),
    );
    s.run_for(50 * MS);
    let r = reserves(&s, rep);
    assert_eq!(r.len(), 2);
    assert_eq!(
        (r[1].ty, r[1].nonce, r[1].pgid),
        (MOSDScrubReserve::GRANT, 9, p2)
    );
    assert!(!s.pg(rep, p1).unwrap().scrub_reserved());
    // immediate mode with the slot taken: REJECT
    s.inject(
        prim,
        rep,
        reserve(p1, e, MOSDScrubReserve::REQUEST, prim, 11, false),
    );
    s.run_for(50 * MS);
    let r = reserves(&s, rep);
    assert_eq!(r.len(), 3);
    assert_eq!((r[2].ty, r[2].nonce), (MOSDScrubReserve::REJECT, 11));
    assert!(!s.pg(rep, p1).unwrap().scrub_reserved());
    // a chunk request while the reservation is still pending cancels it and is served
    s.inject(
        prim,
        rep,
        reserve(p1, e, MOSDScrubReserve::REQUEST, prim, 12, true),
    );
    s.run_for(50 * MS);
    assert!(s.pg(rep, p1).unwrap().scrub_reserved());
    let min = lpr(&s, rep, p1);
    s.inject(
        prim,
        rep,
        rep_scrub(p1, e, min, Hobject::MIN(), Hobject::MAX(), false),
    );
    s.run_for(50 * MS);
    assert!(!s.pg(rep, p1).unwrap().scrub_reserved());
    assert_eq!(maps(&s, rep).len(), 1);
    // release of pg2 hands the slot to nobody; a fresh immediate request is granted again
    s.inject(
        prim2,
        rep,
        reserve(p2, e, MOSDScrubReserve::RELEASE, prim2, 0, false),
    );
    s.inject(
        prim,
        rep,
        reserve(p1, e, MOSDScrubReserve::REQUEST, prim, 13, false),
    );
    s.run_for(50 * MS);
    let r = reserves(&s, rep);
    assert_eq!(r.last().unwrap().ty, MOSDScrubReserve::GRANT);
    assert_eq!(r.last().unwrap().nonce, 13);
}

/// A raised `osd_max_scrubs` answers the queued requests in the budget owner. The timer-only pass applies that answer,
/// so it must collect the PGs that got it: else the replica's GRANT waits for the next full 1 s sweep.
#[test]
fn raised_scrub_limit_grants_in_the_same_tick_due() {
    let (mut s, p1, p2, prim, prim2, rep) = two_pgs(77);
    let e = s.epoch();
    s.capture = true;
    s.inject(
        prim,
        rep,
        reserve(p1, e, MOSDScrubReserve::REQUEST, prim, 1, true),
    );
    s.run_for(50 * MS);
    assert_eq!(reserves(&s, rep).len(), 1, "p1 holds the only slot");
    s.inject(
        prim2,
        rep,
        reserve(p2, e, MOSDScrubReserve::REQUEST, prim2, 2, true),
    );
    s.run_for(50 * MS);
    assert_eq!(reserves(&s, rep).len(), 1, "p2 waits for the slot");
    let now = s.now;
    let n = s.nodes.get_mut(&rep).unwrap();
    n.set.set_max_scrubs(2);
    let acts = n.set.tick_due(n.clock(now), &n.store);
    let granted = acts.iter().find_map(|a| match a {
        Action::Send(sd) => match &sd.body {
            Body::Repl(ReplMsg::ScrubReserve(m))
                if m.ty == MOSDScrubReserve::GRANT && m.nonce == 2 =>
            {
                Some(m.pgid)
            }
            _ => None,
        },
        _ => None,
    });
    assert_eq!(
        granted,
        Some(p2),
        "the GRANT of the queued request must not wait for the full tick: {acts:?}"
    );
}

#[test]
fn new_interval_frees_reservation() {
    let (mut s, p1, _p2, prim, _prim2, rep) = two_pgs(75);
    let e = s.epoch();
    s.capture = true;
    s.inject(
        prim,
        rep,
        reserve(p1, e, MOSDScrubReserve::REQUEST, prim, 1, true),
    );
    s.run_for(50 * MS);
    assert!(s.pg(rep, p1).unwrap().scrub_reserved());
    // the primary dies: new interval on the replica
    s.mark_down(prim);
    s.run_for(2_000 * MS);
    assert!(!s.pg(rep, p1).unwrap().scrub_reserved());
}

#[test]
fn many_objects_need_several_slices() {
    let mut s = cluster(76, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let names: Vec<String> = (0..150).map(|i| format!("o{i}")).collect();
    let t: Vec<u64> = names
        .iter()
        .map(|n| s.write_obj(1, 0, n, n.as_bytes()).unwrap())
        .collect();
    s.wait_writes(&t, pg);
    s.run_for(200 * MS);
    let (prim, rep) = (s.primary_of(pg.pgid), s.acting_of(pg.pgid)[1]);
    let (e, min) = (s.epoch(), lpr(&s, rep, pg));
    s.capture = true;
    s.inject(
        prim,
        rep,
        rep_scrub(pg, e, min, Hobject::MIN(), Hobject::MAX(), true),
    );
    s.run_for(1_000 * MS);
    let m = maps(&s, rep);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].map.objects.len(), 150);
    for n in &names {
        assert_eq!(
            m[0].map.objects[&hobj(1, n)].digest,
            crc::crc32c(0xFFFF_FFFF, n.as_bytes())
        );
    }
}

/// Deep scrub flags a large omap object with the CONFIGURED thresholds (strictly greater), on the replica's map.
#[test]
fn large_omap_thresholds_follow_config() {
    for (kthr, bthr, large) in [
        (200_000, 1 << 30, false),
        (2, 1 << 30, false),
        (1, 1 << 30, true),
        (200_000, 11, true),
    ] {
        let mut s = cluster_cfg(71, &[0, 1, 2], 1, 3, 2, 1, |c| {
            c.scrub.large_omap_keys = kthr;
            c.scrub.large_omap_bytes = bthr;
        });
        let pg = spg(1, 0);
        let t = s.write_obj(1, 0, "a", b"d").unwrap();
        s.wait_writes(&[t], pg);
        s.run_for(100 * MS);
        let (prim, rep) = (s.primary_of(pg.pgid), s.acting_of(pg.pgid)[1]);
        s.capture = true;
        let ha = hobj(1, "a");
        {
            let p = s
                .nodes
                .get_mut(&rep)
                .unwrap()
                .store
                .pgs
                .get_mut(&pg)
                .unwrap();
            let o = p.objects.get_mut(&ha).unwrap();
            o.omap.insert(b"k1".to_vec(), b"123456".to_vec());
            o.omap.insert(b"k2".to_vec(), b"123456".to_vec());
        }
        let (e, min) = (s.epoch(), lpr(&s, rep, pg));
        s.inject(
            prim,
            rep,
            rep_scrub(pg, e, min, Hobject::MIN(), Hobject::MAX(), true),
        );
        s.run_for(100 * MS);
        let m = &maps(&s, rep)[0];
        let o = &m.map.objects[&ha];
        assert_eq!((o.object_omap_keys, o.object_omap_bytes), (2, 12));
        assert_eq!(o.large_omap_object_found, large, "k>{kthr} b>{bthr}");
        if large {
            assert_eq!(
                (
                    o.large_omap_object_key_count,
                    o.large_omap_object_value_size
                ),
                (2, 12)
            );
        }
    }
}
