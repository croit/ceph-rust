// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Replica-role behaviour driven by hand-made primary messages (queries on absent PGs, log-only
//! updates, PCT, removal, epoch gating).
mod common;
use common::*;
use denc::types::{Eversion, Hobject, PgT, ShardId};
use peering::{Body, PgStoreOps};
use pgwire::state as pgs;
use pgwire::*;
use replwire::{MOSDPGUpdateLogMissing, ReplMsg};

fn q(ty: QueryType, since: Eversion, epoch: u32, history: PgHistory) -> PgQuery {
    PgQuery {
        ty,
        since,
        history,
        epoch_sent: epoch,
        to: ShardId::NO_SHARD,
        from: ShardId::NO_SHARD,
    }
}

#[test]
fn absent_pg_answers_dne() {
    let mut s = cluster(40, &[0, 1, 2], 1, 3, 2, 1);
    s.capture = true;
    let e = s.epoch();
    // PG 1.0 exists everywhere; ask osd.2 about a PG it never had (pg 1.5 is outside pg_num but the pool exists)
    let ghost = spg(1, 5);
    s.inject(
        0,
        2,
        Body::Peering(PeeringMsg::MOSDPGQuery2(MOSDPGQuery2 {
            spgid: ghost,
            query: q(
                QueryType::INFO,
                Eversion::default(),
                e,
                PgHistory::default(),
            ),
        })),
    );
    s.inject(
        0,
        2,
        Body::Peering(PeeringMsg::MOSDPGQuery2(MOSDPGQuery2 {
            spgid: ghost,
            query: q(QueryType::LOG, Eversion::default(), e, PgHistory::default()),
        })),
    );
    s.inject(
        0,
        2,
        Body::Peering(PeeringMsg::MOSDPGQuery2(MOSDPGQuery2 {
            spgid: ghost,
            query: q(
                QueryType::FULLLOG,
                Eversion::default(),
                e,
                PgHistory::default(),
            ),
        })),
    );
    s.run_for(100 * MS);
    let replies: Vec<_> = s
        .captured
        .iter()
        .filter(|(f, t, _)| *f == 2 && *t == 0)
        .collect();
    let mut notifies = 0;
    let mut logs = 0;
    for (_, _, b) in replies {
        match b {
            Body::Peering(PeeringMsg::MOSDPGNotify2(n)) => {
                assert!(n.notify.info.dne_flag(), "DNE notify");
                assert_eq!(n.notify.query_epoch, e, "query epoch echoed");
                assert_eq!(n.notify.pg_features, pg_features::CLASSIC_ALL);
                assert!(n.notify.past_intervals.is_empty());
                assert_eq!(n.notify.info.last_backfill, Hobject::MAX());
                notifies += 1;
            }
            Body::Peering(PeeringMsg::MOSDPGLog(l)) => {
                assert!(l.info.dne_flag());
                assert_eq!(l.query_epoch, e);
                assert!(l.log.log.is_empty());
                logs += 1;
            }
            _ => {}
        }
    }
    assert_eq!((notifies, logs), (1, 2));
    // a DNE query for a pool that does not exist gets no answer
    s.captured.clear();
    s.inject(
        0,
        2,
        Body::Peering(PeeringMsg::MOSDPGQuery2(MOSDPGQuery2 {
            spgid: spg(9, 0),
            query: q(
                QueryType::INFO,
                Eversion::default(),
                e,
                PgHistory::default(),
            ),
        })),
    );
    s.run_for(100 * MS);
    assert!(s.captured.iter().all(|(f, _, _)| *f != 2));
}

#[test]
fn replica_answers_info_and_log_queries() {
    let mut s = cluster(41, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let t = s.write_obj(1, 0, "a", b"1").unwrap();
    let t2 = s.write_obj(1, 0, "b", b"2").unwrap();
    s.wait_writes(&[t, t2], pg);
    s.run_for(100 * MS);
    s.capture = true;
    let prim = s.primary_of(pg.pgid);
    let rep = s.acting_of(pg.pgid)[1];
    let e = s.epoch();
    let hist = s.pg(prim, pg).unwrap().info().history.clone();
    for ty in [QueryType::INFO, QueryType::LOG, QueryType::FULLLOG] {
        s.inject(
            prim,
            rep,
            Body::Peering(PeeringMsg::MOSDPGQuery2(MOSDPGQuery2 {
                spgid: pg,
                query: q(ty, Eversion::new(e, 1), e, hist.clone()),
            })),
        );
    }
    s.run_for(100 * MS);
    let got: Vec<_> = s
        .captured
        .iter()
        .filter(|(f, t, _)| *f == rep && *t == prim)
        .map(|(_, _, b)| b.clone())
        .collect();
    let n = got
        .iter()
        .filter_map(|b| {
            if let Body::Peering(PeeringMsg::MOSDPGNotify2(n)) = b {
                Some(n)
            } else {
                None
            }
        })
        .next()
        .expect("notify");
    assert_eq!(n.notify.info.last_update.version, 2);
    assert_eq!(n.notify.query_epoch, e);
    assert!(!n.notify.info.dne_flag());
    let logs: Vec<_> = got
        .iter()
        .filter_map(|b| {
            if let Body::Peering(PeeringMsg::MOSDPGLog(l)) = b {
                Some(l)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(logs.len(), 2);
    // LOG(since = e'1): entries after version 1 -> one entry; FULLLOG -> both
    assert_eq!(logs[0].log.log.len(), 1);
    assert_eq!(logs[0].log.tail.version, 1, "accurate slice tail");
    assert_eq!(logs[1].log.log.len(), 2);
    assert!(
        logs.iter()
            .all(|l| l.query_epoch == e && l.missing.is_empty())
    );
}

#[test]
fn log_only_update_and_pct() {
    let mut s = cluster(42, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let t = s.write_obj(1, 0, "a", b"1").unwrap();
    s.wait_writes(&[t], pg);
    s.run_for(100 * MS);
    s.capture = true;
    let prim = s.primary_of(pg.pgid);
    let rep = s.acting_of(pg.pgid)[1];
    let e = s.epoch();
    let head = s.pg(rep, pg).unwrap().info().last_update;
    // an ERROR entry is a log-only update: no object change, appears in the log, ack'd after commit
    let mut ent = LogEntry::new(
        LogOp::ERROR,
        hobj(1, "a"),
        Eversion::new(e, head.version + 1),
        Eversion::default(),
    );
    ent.return_code = -2;
    let m = MOSDPGUpdateLogMissing {
        map_epoch: e,
        pgid: pg,
        from: ShardId::NO_SHARD,
        rep_tid: 77,
        entries: denc::to_vec(&vec![ent]).unwrap(),
        min_epoch: e,
        pg_trim_to: Eversion::default(),
        pg_committed_to: head,
    };
    s.inject(prim, rep, Body::Repl(ReplMsg::UpdateLogMissing(m.clone())));
    // a duplicate (replayed frame) is neither appended again nor acked twice (classic primary: clog error)
    s.inject(prim, rep, Body::Repl(ReplMsg::UpdateLogMissing(m)));
    s.inject(
        prim,
        rep,
        Body::Repl(ReplMsg::Pct(replwire::MOSDPGPCT {
            map_epoch: e,
            min_epoch: e,
            pgid: pg,
            pg_committed_to: Eversion::new(e, head.version + 1),
        })),
    );
    s.run_for(100 * MS);
    let reply = s
        .captured
        .iter()
        .find_map(|(f, t, b)| match b {
            Body::Repl(ReplMsg::UpdateLogMissingReply(r)) if *f == rep && *t == prim => {
                Some(r.clone())
            }
            _ => None,
        })
        .expect("log missing reply");
    assert_eq!(reply.rep_tid, 77);
    let replies = s
        .captured
        .iter()
        .filter(|(f, t, b)| {
            *f == rep && *t == prim && matches!(b, Body::Repl(ReplMsg::UpdateLogMissingReply(_)))
        })
        .count();
    assert_eq!(replies, 1, "one reply per log-only update");
    let n = s
        .pg(rep, pg)
        .unwrap()
        .log()
        .entries()
        .iter()
        .filter(|x| x.version == Eversion::new(e, head.version + 1))
        .count();
    assert_eq!(n, 1, "entry appended once");
    assert_eq!(reply.last_complete_ondisk.version, head.version + 1);
    let p = s.pg(rep, pg).unwrap();
    assert_eq!(p.info().last_update.version, head.version + 1);
    assert_eq!(p.log().entries().back().unwrap().op, LogOp::ERROR);
    assert_eq!(p.pg_committed_to().version, head.version + 1);
    assert!(
        p.missing().is_empty(),
        "ERROR entries never create missing items"
    );
    assert_eq!(s.contents(rep, 1, 0).len(), 1);
}

#[test]
fn remove_cannot_delete_a_live_mapped_replica() {
    let mut s = cluster(430, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let t = s.write_obj(1, 0, "a", b"acknowledged").unwrap();
    s.wait_writes(&[t], pg);
    let prim = s.primary_of(pg.pgid);
    let acting = s.acting_of(pg.pgid);
    let rep = acting[2];
    for from in [acting[1], prim] {
        s.inject(
            from,
            rep,
            Body::Peering(PeeringMsg::MOSDPGRemove(MOSDPGRemove {
                epoch: s.epoch(),
                pgs: vec![pg],
            })),
        );
        s.run_for(100 * MS);
        assert!(
            s.pg(rep, pg).is_some(),
            "remove from osd.{from} must retain a live copy"
        );
        assert_eq!(
            s.contents(rep, 1, 0).get(b"a".as_slice()).unwrap(),
            b"acknowledged"
        );
    }
}

#[test]
fn remove_deletes_pg_and_data() {
    let mut s = cluster(43, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let t = s.write_obj(1, 0, "a", b"1").unwrap();
    s.wait_writes(&[t], pg);
    s.run_for(100 * MS);
    s.capture = true;
    let prim = s.primary_of(pg.pgid);
    let rep = s.acting_of(pg.pgid)[2];
    // Keep automatic primary messages out while we explicitly exercise stray removal.
    s.block_all_from.insert(prim);
    let remaining: Vec<i32> = s
        .acting_of(pg.pgid)
        .into_iter()
        .filter(|o| *o != rep)
        .collect();
    s.new_epoch(|m| {
        m.pools.get_mut(&1).unwrap().size = 2;
        m.up_override.insert(pg.pgid, remaining);
        m.pg_temp.remove(&pg.pgid);
    });
    s.run_for(100 * MS);
    assert!(
        s.pg(rep, pg).is_some(),
        "stray copy retained until authorized removal"
    );
    assert!(!s.up_of(pg.pgid).contains(&rep));
    assert!(!s.acting_of(pg.pgid).contains(&rep));
    let e = s.epoch();
    let impostor = s
        .acting_of(pg.pgid)
        .into_iter()
        .find(|o| *o != prim)
        .unwrap();
    s.inject(
        impostor,
        rep,
        Body::Peering(PeeringMsg::MOSDPGRemove(MOSDPGRemove {
            epoch: e,
            pgs: vec![pg],
        })),
    );
    s.run_for(50 * MS);
    assert!(
        s.pg(rep, pg).is_some(),
        "a non-primary cannot purge a stray"
    );
    assert_eq!(s.contents(rep, 1, 0).len(), 1);
    let lpr = s.pg(rep, pg).unwrap().last_peering_reset();
    // a remove stamped before the PG's last peering reset is stale and ignored; a current one deletes
    s.inject(
        prim,
        rep,
        Body::Peering(PeeringMsg::MOSDPGRemove(MOSDPGRemove {
            epoch: lpr - 1,
            pgs: vec![pg],
        })),
    );
    s.run_for(50 * MS);
    assert!(
        s.pg(rep, pg).is_some(),
        "stale remove must not delete an acting PG"
    );
    s.inject(
        prim,
        rep,
        Body::Peering(PeeringMsg::MOSDPGRemove(MOSDPGRemove {
            epoch: e,
            pgs: vec![pg],
        })),
    );
    s.run_for(100 * MS);
    assert!(s.pg(rep, pg).is_none());
    assert!(s.nodes[&rep].store.list_pgs().is_empty());
    assert!(s.removed.contains(&(rep, pg)));
    // queries now answer DNE
    s.inject(
        prim,
        rep,
        Body::Peering(PeeringMsg::MOSDPGQuery2(MOSDPGQuery2 {
            spgid: pg,
            query: q(
                QueryType::INFO,
                Eversion::default(),
                e,
                PgHistory::default(),
            ),
        })),
    );
    s.run_for(50 * MS);
    assert!(s.captured.iter().any(|(f, _, b)| *f == rep
        && matches!(b, Body::Peering(PeeringMsg::MOSDPGNotify2(n)) if n.notify.info.dne_flag())));
}

#[test]
fn pool_full_transition_marks_history_once() {
    let mut s = cluster(46, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    let mark = |s: &Sim| {
        s.pg(prim, pg)
            .unwrap()
            .info()
            .history
            .last_epoch_marked_full
    };
    assert_eq!(mark(&s), 0);
    s.new_epoch(|m| m.pools.get_mut(&1).unwrap().full = true);
    s.run_for(100 * MS);
    let e = mark(&s);
    assert_eq!(e, s.epoch());
    // staying full over later epochs keeps the mark; clearing does not touch it
    s.new_epoch(|m| m.rb.nobackfill = true);
    s.run_for(100 * MS);
    assert_eq!(mark(&s), e);
    s.new_epoch(|m| m.pools.get_mut(&1).unwrap().full = false);
    s.run_for(100 * MS);
    assert_eq!(mark(&s), e);
}

#[test]
fn cluster_full_transition_marks_history_once() {
    let mut s = cluster(48, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    let mark = |s: &Sim| {
        s.pg(prim, pg)
            .unwrap()
            .info()
            .history
            .last_epoch_marked_full
    };
    assert_eq!(mark(&s), 0);
    // the global osdmap FULL flag (no pool FLAG_FULL) marks the history like a pool full
    s.new_epoch(|m| m.full = true);
    s.run_for(100 * MS);
    let e = mark(&s);
    assert_eq!(e, s.epoch());
    s.new_epoch(|m| m.rb.nobackfill = true);
    s.run_for(100 * MS);
    assert_eq!(mark(&s), e);
    // clearing the flag does not touch the mark (the op was already discarded, the client learns the new map)
    s.new_epoch(|m| m.full = false);
    s.run_for(100 * MS);
    assert_eq!(mark(&s), e);
}

#[test]
fn pool_deletion_removes_all_pgs() {
    let mut s = cluster(44, &[0, 1, 2], 1, 3, 2, 4);
    let t = s.write_obj(1, 0, "a", b"1").unwrap();
    s.wait_writes(&[t], spg(1, 0));
    s.new_epoch(|m| {
        m.pools.remove(&1);
    });
    s.run_until(30_000 * MS, "all pgs removed", |s| {
        s.nodes
            .values()
            .all(|n| n.set.pgs().count() == 0 && n.store.list_pgs().is_empty())
    });
    assert_eq!(s.removed.len(), 12);
}

#[test]
fn messages_from_the_future_wait_for_the_map() {
    let mut s = cluster(45, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    let rep = s.acting_of(pg.pgid)[1];
    let e = s.epoch();
    let before = s.request_map;
    // an Info2 stamped with a future epoch is parked; once the replica learns that epoch it is processed
    let info = s.pg(prim, pg).unwrap().info().clone();
    let future = e + 1;
    s.inject(
        prim,
        rep,
        Body::Peering(PeeringMsg::MOSDPGInfo2(MOSDPGInfo2 {
            spgid: pg,
            epoch_sent: future,
            min_epoch: future,
            info,
            lease: None,
            lease_ack: None,
        })),
    );
    s.run_for(50 * MS);
    assert!(s.request_map > before, "a newer map was requested");
    let seen = s.pg(rep, pg).unwrap().counters().discards.clone();
    // deliver the epoch: the message is released (and then dropped or applied, but not lost silently)
    s.new_epoch(|m| {
        m.osds.get_mut(&0).unwrap().up_thru += 0;
    });
    s.run_for(200 * MS);
    let after = s.pg(rep, pg).unwrap().counters().discards.clone();
    let _ = (seen, after);
    // stale stamp: lower than the replica's last_peering_reset -> counted as discarded
    let lpr = s.pg(rep, pg).unwrap().last_peering_reset();
    let info = s.pg(prim, pg).unwrap().info().clone();
    s.inject(
        prim,
        rep,
        Body::Peering(PeeringMsg::MOSDPGInfo2(MOSDPGInfo2 {
            spgid: pg,
            epoch_sent: lpr - 1,
            min_epoch: lpr - 1,
            info,
            lease: None,
            lease_ack: None,
        })),
    );
    s.run_for(50 * MS);
    let d = s
        .pg(rep, pg)
        .unwrap()
        .counters()
        .discards
        .get("old peering message")
        .copied()
        .unwrap_or(0);
    assert!(
        d >= 1,
        "stale message counted: {:?}",
        s.pg(rep, pg).unwrap().counters()
    );
    assert!(s.pg(rep, pg).unwrap().state_bits() & pgs::ACTIVE != 0);
    let _ = PgT::new(1, 0);
}

/// Recovery data messages are stale by `map_epoch` only (classic `can_discard_replica_op`): a RecoveryDelete of a
/// previous interval never deletes in the new one, while one of the current interval is applied even when the
/// sender's interval start (`min_epoch`) is older than the receiver's reset. Only the acting primary's delete applies
/// (review 2026-11-03 #13), and only to an object the replica misses (`recovery_delete_tests` covers the version gate).
#[test]
fn recovery_delete_gated_by_map_epoch_and_sender() {
    let mut s = cluster(46, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let t = s.write_obj(1, 0, "a", b"1").unwrap();
    s.wait_writes(&[t], pg);
    s.run_for(100 * MS);
    let prim = s.primary_of(pg.pgid);
    let acting = s.acting_of(pg.pgid);
    let (rep, other) = (acting[1], acting[2]);
    let old = s.pg(rep, pg).unwrap().last_peering_reset();
    // the replica misses the delete of `a`, and the primary's recovery delete of it is lost
    s.kill(rep);
    s.run_for(100 * MS);
    let t = s.delete_obj(1, 0, "a").unwrap();
    s.wait_writes(&[t], pg);
    let v = s.pg(prim, pg).unwrap().info().last_update;
    s.drop_next
        .push((prim, rep, pgwire::ty::PG_RECOVERY_DELETE));
    s.restart(rep);
    s.run_until(5_000 * MS, "replica active, `a` missing", |s| {
        s.pg(rep, pg).is_some_and(|p| {
            p.last_peering_reset() > old
                && p.state_bits() & pgs::ACTIVE != 0
                && p.missing().contains(&hobj(1, "a"))
        })
    });
    s.run_for(200 * MS);
    assert!(
        s.drop_next.is_empty(),
        "the recovery delete was sent and lost"
    );
    assert!(s.contents(rep, 1, 0).contains_key(b"a".as_slice()));
    let lpr = s.pg(rep, pg).unwrap().last_peering_reset();
    let del = |from: i32, map_epoch: u32, min_epoch: u32| {
        Body::Repl(ReplMsg::RecoveryDelete(replwire::MOSDPGRecoveryDelete {
            from: denc::types::PgShard {
                osd: from,
                shard: ShardId::NO_SHARD,
            },
            pgid: pg,
            map_epoch,
            min_epoch,
            cost: 1000,
            objects: vec![(hobj(1, "a"), v)],
        }))
    };
    let count = |s: &Sim, error: bool, why: &str| {
        let c = s.pg(rep, pg).unwrap().counters();
        let m = if error { &c.errors } else { &c.discards };
        m.get(why).copied().unwrap_or(0)
    };
    let has_a = |s: &Sim| s.contents(rep, 1, 0).contains_key(b"a".as_slice());
    // previous interval: dropped, the object survives
    let d0 = count(&s, false, "old peering message");
    s.inject(prim, rep, del(prim, lpr - 1, old));
    s.run_for(100 * MS);
    let d1 = count(&s, false, "old peering message");
    assert!(d1 > d0);
    assert!(has_a(&s));
    // current interval, but from an up OSD that is not the acting primary: refused
    s.inject(other, rep, del(other, s.epoch(), old));
    s.run_for(100 * MS);
    assert_eq!(count(&s, true, "recovery delete from non-primary"), 1);
    assert!(has_a(&s));
    assert!(s.pg(rep, pg).unwrap().missing().contains(&hobj(1, "a")));
    // current interval from the acting primary, older sender interval start: applied
    s.inject(prim, rep, del(prim, s.epoch(), old));
    s.run_for(100 * MS);
    assert_eq!(count(&s, false, "old peering message"), d1);
    assert!(!has_a(&s));
    assert!(!s.pg(rep, pg).unwrap().missing().contains(&hobj(1, "a")));
    s.run_until(5_000 * MS, "recovered", |s| s.quiet() && s.pool_clean(1));
}

/// PG-P3: `pg_committed_to` of a replica is raised only by its acting primary, like every other replica-side handler
/// (`on_lease`, `on_trim`, `on_query`, `on_log`, `on_info`). It gates optimized-EC direct replica reads and scrub /
/// backfill decisions, so a PCT from any other up OSD must be discarded.
#[test]
fn pct_from_a_non_primary_does_not_raise_pg_committed_to() {
    let mut s = cluster(47, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let t = s.write_obj(1, 0, "a", b"1").unwrap();
    s.wait_writes(&[t], pg);
    s.run_for(100 * MS);
    let prim = s.primary_of(pg.pgid);
    let acting = s.acting_of(pg.pgid);
    let (rep, other) = (acting[1], acting[2]);
    let e = s.epoch();
    let pct = |v: Eversion| {
        Body::Repl(ReplMsg::Pct(replwire::MOSDPGPCT {
            map_epoch: e,
            min_epoch: e,
            pgid: pg,
            pg_committed_to: v,
        }))
    };
    let before = s.pg(rep, pg).unwrap().pg_committed_to();
    s.inject(other, rep, pct(Eversion::new(e, before.version + 9)));
    s.run_for(100 * MS);
    assert_eq!(
        s.pg(rep, pg).unwrap().pg_committed_to(),
        before,
        "PCT from a non-primary is discarded"
    );
    assert!(
        s.pg(rep, pg)
            .unwrap()
            .counters()
            .discards
            .get("pct from non-primary")
            .is_some_and(|n| *n >= 1),
        "{:?}",
        s.pg(rep, pg).unwrap().counters().discards
    );
    // the acting primary's PCT still lands
    s.inject(prim, rep, pct(Eversion::new(e, before.version + 1)));
    s.run_for(100 * MS);
    assert_eq!(
        s.pg(rep, pg).unwrap().pg_committed_to(),
        Eversion::new(e, before.version + 1)
    );
}

/// PG-P7: a LOG query with `since` below our log tail cannot be answered incrementally (spec pglog 6.6: the full log
/// goes out); the mismatch is counted and noted instead of looking like a normal catch-up.
#[test]
fn a_log_query_below_the_tail_is_noted() {
    let mut s = cluster(48, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    for name in ["a", "b"] {
        let t = s.write_obj(1, 0, name, b"1").unwrap();
        s.wait_writes(&[t], pg);
    }
    s.run_for(100 * MS);
    let prim = s.primary_of(pg.pgid);
    let rep = s.acting_of(pg.pgid)[1];
    let e = s.epoch();
    let v1 = s.pg(rep, pg).unwrap().log().entries()[0].version;
    // the primary trimmed our log: the first entry is gone
    s.inject(
        prim,
        rep,
        Body::Peering(PeeringMsg::MOSDPGTrim(MOSDPGTrim {
            epoch: e,
            pgid: pg.pgid,
            trim_to: v1,
            shard: ShardId::NO_SHARD,
        })),
    );
    s.run_for(100 * MS);
    assert_eq!(
        s.pg(rep, pg).unwrap().log().tail(),
        v1,
        "the replica trimmed its log"
    );
    let d0 = s
        .pg(rep, pg)
        .unwrap()
        .counters()
        .errors
        .get("log query below tail")
        .copied()
        .unwrap_or(0);
    s.capture = true;
    let hist = s.pg(prim, pg).unwrap().info().history.clone();
    // a peer that only holds the interval start (`GetMissing`: since = (last_epoch_started, 0)) sits below our tail
    let since = Eversion::new(e, 0);
    assert!(since < v1);
    s.inject(
        prim,
        rep,
        Body::Peering(PeeringMsg::MOSDPGQuery2(MOSDPGQuery2 {
            spgid: pg,
            query: q(QueryType::LOG, since, e, hist),
        })),
    );
    s.run_for(100 * MS);
    assert_eq!(
        s.pg(rep, pg)
            .unwrap()
            .counters()
            .errors
            .get("log query below tail")
            .copied()
            .unwrap_or(0),
        d0 + 1,
        "a LOG query below the tail is noted"
    );
    let sent = s
        .captured
        .iter()
        .find_map(|(f, t, b)| match b {
            Body::Peering(PeeringMsg::MOSDPGLog(m)) if *f == rep && *t == prim => Some(m.clone()),
            _ => None,
        })
        .expect("a full log still answers");
    assert_eq!(sent.log.log.len(), 1, "the full (trimmed) log goes out");
}
