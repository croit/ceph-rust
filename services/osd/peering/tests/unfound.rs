// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Unfound objects: per-object tracking, `list_unfound`, `mark_unfound_lost revert|delete` (LOST_REVERT / LOST_DELETE log
//! entries, spec doc/spec/unfound-lost.md) on the deterministic simulator, with croit-flashstore-osd and classic stand-in peers.
mod common;
use common::*;
use peering::LostMode;
use peering::*;
use pgwire::LogOp;
use std::collections::BTreeMap;

const POOL: u64 = 1;

/// `mark_unfound_lost` and its answer: at once, or (submitted) once every member committed the entries.
fn mark(s: &mut Sim, osd: i32, mode: LostMode) -> Result<String, (i32, String)> {
    match mark_submit(s, osd, mode) {
        LostReply::Now(r) => r,
        LostReply::Later(tid) => mark_answer(s, osd, tid),
    }
}

fn mark_submit(s: &mut Sim, osd: i32, mode: LostMode) -> LostReply {
    let spg = spg(POOL, 0);
    let mut out = None;
    s.call(osd, |set, now, store| {
        let (r, acts) = set.mark_unfound_lost(now, spg, mode, store);
        out = r;
        acts
    });
    out.expect("pg exists")
}

/// Run until the deferred answer of marking `tid` on `osd` arrives (bounded: 5 s simulated).
fn mark_answer(s: &mut Sim, osd: i32, tid: u64) -> Result<String, (i32, String)> {
    for _ in 0..500 {
        if let Some(i) = s
            .lost_done
            .iter()
            .position(|(o, d)| *o == osd && d.tid == tid)
        {
            return s.lost_done.remove(i).1.result;
        }
        s.run_for(10 * MS);
    }
    panic!("mark_unfound_lost tid {tid} on osd.{osd} never answered");
}

fn lose(s: &mut Sim, osd: i32) {
    s.new_epoch(|m| {
        let e = m.epoch;
        m.osds.get_mut(&osd).unwrap().lost_at = e;
    });
}

/// object_info version of `name` on `osd` (None = no such object).
fn oi_version(s: &Sim, osd: i32, name: &str) -> Option<denc::types::Eversion> {
    s.nodes[&osd]
        .store
        .recovery_info(spg(POOL, 0), &hobj(POOL, name))
        .map(|ri| ri.version)
}

/// Version of the LOST_* entry of `name` in `osd`'s log.
fn lost_version(s: &Sim, osd: i32, name: &str) -> denc::types::Eversion {
    s.pg(osd, spg(POOL, 0))
        .unwrap()
        .log()
        .entries()
        .iter()
        .rev()
        .find(|e| {
            e.soid.oid == name.as_bytes() && matches!(e.op, LogOp::LOST_REVERT | LogOp::LOST_DELETE)
        })
        .expect("lost entry")
        .version
}

fn expect(pairs: &[(&str, &str)]) -> BTreeMap<String, Vec<u8>> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
        .collect()
}

/// Objects `a` (v1 on both OSDs of a size-`n` PG, v2 only on the old primary), `b` (created on the old primary only) and
/// `c` (everywhere). The old primary dies after the survivor `other` learned its log: `other` leads with `a` and `b`
/// unfound. With `n` = 3 the third OSD (`third`) was down during both writes.
struct Unf {
    s: Sim,
    old: i32,
    other: i32,
    third: Option<i32>,
}

fn unfound_setup(seed: u64, n: usize) -> Unf {
    let osds: Vec<i32> = (0..n as i32).collect();
    let mut s = cluster(seed, &osds, POOL, n as u32, 1, 1);
    let pg = spg(POOL, 0);
    let t1 = s.write_obj(POOL, 0, "a", b"a-v1").unwrap();
    let t2 = s.write_obj(POOL, 0, "c", b"c-v1").unwrap();
    s.wait_writes(&[t1, t2], pg);
    let old = s.primary_of(pg.pgid);
    let mut others: Vec<i32> = s
        .acting_of(pg.pgid)
        .into_iter()
        .filter(|o| *o != old)
        .collect();
    let other = others.remove(0);
    let third = others.first().copied();
    s.kill(other);
    if let Some(t) = third {
        s.kill(t);
    }
    s.run_for(300 * MS);
    let t1 = s.write_obj(POOL, 0, "a", b"a-v2").unwrap();
    let t2 = s.write_obj(POOL, 0, "b", b"b-v1").unwrap();
    s.wait_writes(&[t1, t2], pg);
    s.new_epoch(|m| m.rb.norecover = true);
    s.restart(other);
    s.run_for(5_000 * MS);
    s.kill(old);
    s.new_epoch(|m| m.rb.norecover = false);
    s.run_for(10_000 * MS);
    Unf {
        s,
        old,
        other,
        third,
    }
}

fn ops_of(s: &Sim, osd: i32) -> Vec<(String, LogOp)> {
    let mut v: Vec<(String, LogOp)> = s
        .pg(osd, spg(POOL, 0))
        .unwrap()
        .log()
        .entries()
        .iter()
        .filter(|e| matches!(e.op, LogOp::LOST_REVERT | LogOp::LOST_DELETE))
        .map(|e| (String::from_utf8_lossy(&e.soid.oid).into_owned(), e.op))
        .collect::<Vec<_>>();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

#[test]
fn unfound_is_tracked_per_object() {
    let u = unfound_setup(1, 2);
    let p = u.s.pg(u.other, spg(POOL, 0)).unwrap();
    assert!(
        p.state_string().contains("recovery_unfound"),
        "{}",
        p.state_string()
    );
    let names: Vec<String> = p
        .unfound()
        .iter()
        .map(|o| String::from_utf8_lossy(&o.oid.oid).into_owned())
        .collect();
    let mut names = names;
    names.sort();
    assert_eq!(names, ["a", "b"], "c is not missing");
    // no location (classic: locations empty); the dead old primary is the only place the data can be
    assert!(
        p.unfound()
            .iter()
            .all(|o| p.missing_locations(&o.oid).is_empty())
    );
    let m = p.might_have_unfound();
    assert_eq!(m.len(), 1);
    assert_eq!((m[0].0.osd, m[0].1), (u.old, "osd is down"));
}

#[test]
fn mark_is_refused_until_every_source_is_probed_or_lost() {
    let mut u = unfound_setup(2, 2);
    let r = mark(&mut u.s, u.other, LostMode::Revert);
    assert_eq!(r.as_ref().map_err(|e| e.0), Err(-22), "{r:?}");
    assert!(r.unwrap_err().1.contains("haven't probed all sources"));
    assert!(ops_of(&u.s, u.other).is_empty());
    lose(&mut u.s, u.old);
    u.s.run_for(2_000 * MS);
    mark(&mut u.s, u.other, LostMode::Delete).unwrap();
    // a second marking finds nothing unfound: idempotent success
    u.s.run_for(5_000 * MS);
    assert_eq!(
        mark(&mut u.s, u.other, LostMode::Delete).unwrap(),
        "pg has no unfound objects"
    );
}

#[test]
fn revert_goes_back_or_deletes_and_converges_with_the_old_primary() {
    let mut u = unfound_setup(3, 2);
    lose(&mut u.s, u.old);
    u.s.run_for(2_000 * MS);
    let msg = mark(&mut u.s, u.other, LostMode::Revert).unwrap();
    assert_eq!(msg, "pg has 2 objects unfound and apparently lost marking");
    u.s.run_for(5_000 * MS);
    // a had v1 here: reverted; b never existed here: deleted
    assert_eq!(
        ops_of(&u.s, u.other),
        [
            ("a".to_string(), LogOp::LOST_REVERT),
            ("b".to_string(), LogOp::LOST_DELETE)
        ]
    );
    let p = u.s.pg(u.other, spg(POOL, 0)).unwrap();
    assert!(
        p.missing().is_empty(),
        "{:?}",
        p.missing().iter().collect::<Vec<_>>()
    );
    assert!(p.unfound().is_empty());
    assert!(
        !p.state_string().contains("recovery_unfound"),
        "{}",
        p.state_string()
    );
    assert_eq!(
        u.s.contents(u.other, POOL, 0),
        expect(&[("a", "a-v1"), ("c", "c-v1")])
            .into_iter()
            .map(|(k, v)| (k.into_bytes(), v))
            .collect()
    );
    // the old primary comes back with a-v2 and b: its copies are overwritten / removed
    u.s.restart(u.old);
    u.s.run_for(20_000 * MS);
    assert!(u.s.pool_clean(POOL), "{}", u.s.dump());
    u.s.assert_replicas_equal(POOL, 0, &expect(&[("a", "a-v1"), ("c", "c-v1")]));
    u.s.assert_persisted_consistent();
    // the reverted object carries the LOST_REVERT version everywhere (a later write builds on it)
    let v = lost_version(&u.s, u.other, "a");
    for o in u.s.acting_of(spg(POOL, 0).pgid) {
        assert_eq!(oi_version(&u.s, o, "a"), Some(v), "osd.{o}");
        assert_eq!(oi_version(&u.s, o, "b"), None, "osd.{o}");
    }
    // the revert is a normal object version: a write on top works
    let t = u.s.write_obj(POOL, 0, "a", b"a-v3").unwrap();
    u.s.wait_writes(&[t], spg(POOL, 0));
    u.s.run_for(500 * MS);
    u.s.assert_replicas_equal(POOL, 0, &expect(&[("a", "a-v3"), ("c", "c-v1")]));
}

#[test]
fn delete_removes_every_unfound_object() {
    let mut u = unfound_setup(4, 2);
    lose(&mut u.s, u.old);
    u.s.run_for(2_000 * MS);
    mark(&mut u.s, u.other, LostMode::Delete).unwrap();
    u.s.run_for(5_000 * MS);
    assert_eq!(
        ops_of(&u.s, u.other),
        [
            ("a".to_string(), LogOp::LOST_DELETE),
            ("b".to_string(), LogOp::LOST_DELETE)
        ]
    );
    u.s.restart(u.old);
    u.s.run_for(20_000 * MS);
    assert!(u.s.pool_clean(POOL), "{}", u.s.dump());
    u.s.assert_replicas_equal(POOL, 0, &expect(&[("c", "c-v1")]));
}

/// Replicated deltas of spec ec-unfound-lost.md 4: `list_unfound` fields (|N|, state machine name, paging) and the
/// marking answered only once committed, its entries with the constructor-default (fully clean) clean_regions.
#[test]
fn marking_answers_after_commit_with_default_clean_regions() {
    let mut u = unfound_setup(4, 2);
    lose(&mut u.s, u.old);
    u.s.run_for(2_000 * MS);
    let p = u.s.pg(u.other, spg(POOL, 0)).unwrap();
    let l = p.list_unfound(None, 256);
    assert_eq!((l.num_missing, l.num_unfound, l.more), (2, 2, false));
    assert_eq!(l.state, "NotRecovering", "{}", p.state_string());
    assert!(l.objects.iter().all(|o| o.locations.is_empty()));
    assert!(l.might_have_unfound.is_some());
    let page = p.list_unfound(None, 1);
    assert_eq!((page.objects.len(), page.more), (1, true));
    let rest = p.list_unfound(Some(&page.objects[0].oid), 1);
    assert_eq!((rest.objects.len(), rest.more), (1, false));
    assert_ne!(rest.objects[0].oid, page.objects[0].oid);
    let LostReply::Later(tid) = mark_submit(&mut u.s, u.other, LostMode::Delete) else {
        panic!("marking submitted");
    };
    assert!(u.s.lost_done.is_empty(), "no answer before the commit");
    assert_eq!(
        mark_answer(&mut u.s, u.other, tid),
        Ok("pg has 2 objects unfound and apparently lost marking".into())
    );
    let p = u.s.pg(u.other, spg(POOL, 0)).unwrap();
    for e in p
        .log()
        .entries()
        .iter()
        .filter(|e| e.op == LogOp::LOST_DELETE)
    {
        assert_eq!(e.clean_regions, pgwire::ObjectCleanRegions::default());
        assert!(!e.mod_desc.can_local_rollback, "replicated: unrollbackable");
    }
}

#[test]
fn classic_peers_accept_the_lost_entries() {
    let mut u = unfound_setup(5, 3);
    let third = u.third.unwrap();
    lose(&mut u.s, u.old);
    lose(&mut u.s, third);
    u.s.classic_set(&[u.old, third]);
    u.s.run_for(2_000 * MS);
    // the third OSD is in the acting set again (down members are lost): bring it up as a classic stand-in
    u.s.restart(third);
    u.s.run_for(3_000 * MS);
    mark(&mut u.s, u.other, LostMode::Revert).unwrap();
    u.s.run_for(5_000 * MS);
    u.s.restart(u.old);
    u.s.run_for(20_000 * MS);
    assert!(u.s.pool_clean(POOL), "{}", u.s.dump());
    u.s.assert_replicas_equal(POOL, 0, &expect(&[("a", "a-v1"), ("c", "c-v1")]));
    assert!(
        u.s.classic_violations().is_empty(),
        "{:?}",
        u.s.classic_violations()
    );
}

/// The new primary (osd 2) never had `a`; only a peer (osd 1) holds the older version: the revert pulls it from there.
#[test]
fn revert_pulls_the_old_version_from_a_peer() {
    let mut s = cluster(6, &[0, 1, 2], POOL, 3, 1, 1);
    let pg = spg(POOL, 0);
    s.kill(2);
    s.run_for(300 * MS);
    let t = s.write_obj(POOL, 0, "a", b"a-v1").unwrap();
    s.wait_writes(&[t], pg);
    s.kill(1);
    s.run_for(300 * MS);
    let t = s.write_obj(POOL, 0, "a", b"a-v2").unwrap();
    s.wait_writes(&[t], pg);
    s.new_epoch(|m| m.rb.norecover = true);
    s.set_up_override(pg.pgid, vec![2, 1, 0]);
    s.restart(1);
    s.restart(2);
    s.run_for(8_000 * MS);
    s.kill(0);
    s.new_epoch(|m| m.rb.norecover = false);
    s.run_for(10_000 * MS);
    let prim = s.primary_of(pg.pgid);
    assert_eq!(prim, 2, "{}", s.dump());
    let p = s.pg(2, pg).unwrap();
    assert_eq!(p.unfound().len(), 1, "{}", p.state_string());
    lose(&mut s, 0);
    s.run_for(2_000 * MS);
    mark(&mut s, 2, LostMode::Revert).unwrap();
    s.run_for(10_000 * MS);
    assert_eq!(ops_of(&s, 2), [("a".to_string(), LogOp::LOST_REVERT)]);
    let p = s.pg(2, pg).unwrap();
    assert!(
        p.missing().is_empty() && p.unfound().is_empty(),
        "{}",
        p.state_string()
    );
    s.restart(0);
    s.run_for(20_000 * MS);
    s.assert_replicas_equal(POOL, 0, &expect(&[("a", "a-v1")]));
    let v = lost_version(&s, 2, "a");
    for o in s.acting_of(pg.pgid) {
        assert_eq!(
            oi_version(&s, o, "a"),
            Some(v),
            "osd.{o}: pulled old version stamped"
        );
    }
}

/// A classic primary marks objects lost: our replica applies the entries like any log-only update and keeps serving.
#[test]
fn replica_takes_lost_entries_from_a_classic_primary() {
    let mut s = cluster(7, &[0, 1], POOL, 2, 1, 1);
    let pg = spg(POOL, 0);
    let t = s.write_obj(POOL, 0, "a", b"1").unwrap();
    s.wait_writes(&[t], pg);
    s.run_for(100 * MS);
    let prim = s.primary_of(pg.pgid);
    let rep = s
        .acting_of(pg.pgid)
        .into_iter()
        .find(|o| *o != prim)
        .unwrap();
    let e = s.epoch();
    let head = s.pg(rep, pg).unwrap().info().last_update;
    let mut ent = pgwire::LogEntry::new(
        LogOp::LOST_REVERT,
        hobj(POOL, "a"),
        denc::types::Eversion::new(e, head.version + 1),
        head,
    );
    ent.reverting_to = head;
    ent.clean_regions = pgwire::ObjectCleanRegions::fully_dirty();
    let m = replwire::MOSDPGUpdateLogMissing {
        map_epoch: e,
        pgid: pg,
        from: denc::types::ShardId::NO_SHARD,
        rep_tid: 9,
        entries: denc::to_vec(&vec![ent]).unwrap(),
        min_epoch: e,
        pg_trim_to: Default::default(),
        pg_committed_to: head,
    };
    s.inject(
        prim,
        rep,
        Body::Repl(replwire::ReplMsg::UpdateLogMissing(m)),
    );
    s.run_for(200 * MS);
    let p = s.pg(rep, pg).unwrap();
    let it = p
        .missing()
        .iter()
        .next()
        .expect("object now missing")
        .1
        .clone();
    assert_eq!(it.need.version, head.version + 1);
    assert_eq!(it.have, head, "what we hold stays the base of the recovery");
    assert_eq!(p.log().entries().back().unwrap().op, LogOp::LOST_REVERT);
}

/// The entries are durable before recovery acts on them: a primary crash after the marking (recovery held back by
/// norecover) comes back with the LOST_* entries and the missing items, and recovery then finishes the revert/delete.
#[test]
fn marking_survives_a_primary_crash_before_recovery() {
    let mut u = unfound_setup(8, 2);
    lose(&mut u.s, u.old);
    u.s.run_for(2_000 * MS);
    u.s.new_epoch(|m| m.rb.norecover = true);
    u.s.run_for(1_000 * MS);
    mark(&mut u.s, u.other, LostMode::Revert).unwrap();
    u.s.run_for(500 * MS);
    let p = u.s.pg(u.other, spg(POOL, 0)).unwrap();
    assert_eq!(p.missing().len(), 2, "recovery held back");
    assert!(p.unfound().is_empty(), "nothing unfound after the marking");
    u.s.kill(u.other);
    u.s.run_for(500 * MS);
    u.s.restart(u.other);
    u.s.run_for(3_000 * MS);
    assert_eq!(
        ops_of(&u.s, u.other),
        [
            ("a".to_string(), LogOp::LOST_REVERT),
            ("b".to_string(), LogOp::LOST_DELETE)
        ],
        "entries persisted"
    );
    u.s.new_epoch(|m| m.rb.norecover = false);
    u.s.run_for(5_000 * MS);
    let p = u.s.pg(u.other, spg(POOL, 0)).unwrap();
    assert!(p.missing().is_empty(), "{}", p.state_string());
    assert_eq!(
        u.s.contents(u.other, POOL, 0),
        expect(&[("a", "a-v1"), ("c", "c-v1")])
            .into_iter()
            .map(|(k, v)| (k.into_bytes(), v))
            .collect()
    );
    u.s.assert_persisted_consistent();
}

/// The only holder of the old version goes down right after the marking (interval change before its reply): the command
/// answers -EAGAIN (classic never answers, doc/parity.md), the revert waits (unfound again, nothing lost or invented) and
/// completes once that OSD is back.
#[test]
fn revert_source_lost_mid_operation_waits_for_it() {
    let mut s = cluster(9, &[0, 1, 2], POOL, 3, 1, 1);
    let pg = spg(POOL, 0);
    s.kill(2);
    s.run_for(300 * MS);
    let t = s.write_obj(POOL, 0, "a", b"a-v1").unwrap();
    s.wait_writes(&[t], pg);
    s.kill(1);
    s.run_for(300 * MS);
    let t = s.write_obj(POOL, 0, "a", b"a-v2").unwrap();
    s.wait_writes(&[t], pg);
    s.new_epoch(|m| m.rb.norecover = true);
    s.set_up_override(pg.pgid, vec![2, 1, 0]);
    s.restart(1);
    s.restart(2);
    s.run_for(8_000 * MS);
    s.kill(0);
    s.new_epoch(|m| m.rb.norecover = false);
    s.run_for(10_000 * MS);
    assert_eq!(s.primary_of(pg.pgid), 2, "{}", s.dump());
    lose(&mut s, 0);
    s.run_for(2_000 * MS);
    let LostReply::Later(tid) = mark_submit(&mut s, 2, LostMode::Revert) else {
        panic!("marking submitted");
    };
    s.kill(1);
    let (e, why) = mark_answer(&mut s, 2, tid).expect_err("interval changed before the commit");
    assert_eq!(e, -11, "{why}");
    assert!(
        why.starts_with("interval changed before marking 1 unfound objects lost"),
        "{why}"
    );
    s.run_for(5_000 * MS);
    let p = s.pg(2, pg).unwrap();
    assert_eq!(p.missing().len(), 1, "{}", p.state_string());
    assert_eq!(p.unfound().len(), 1, "the old version is on osd.1 only");
    assert!(s.contents(2, POOL, 0).is_empty(), "nothing invented");
    s.restart(1);
    s.run_for(10_000 * MS);
    let p = s.pg(2, pg).unwrap();
    assert!(
        p.missing().is_empty() && p.unfound().is_empty(),
        "{}",
        p.state_string()
    );
    s.restart(0);
    s.run_for(20_000 * MS);
    s.assert_replicas_equal(POOL, 0, &expect(&[("a", "a-v1")]));
    let v = lost_version(&s, 2, "a");
    for o in s.acting_of(pg.pgid) {
        assert_eq!(oi_version(&s, o, "a"), Some(v), "osd.{o}");
    }
}
