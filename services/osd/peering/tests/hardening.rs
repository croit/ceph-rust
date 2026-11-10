// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Regression tests for the peering / recovery / replication hardening review (stray purge, async recovery, backfill
//! write blocking, re-admission of async targets).
mod common;
use common::*;
use peering::Body;
use pgwire::PeeringMsg;
use pgwire::state as pgs;
use replwire::ReplMsg;
use std::collections::BTreeMap;

fn payload(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|j| ((i * 131 + j * 7) % 251) as u8).collect()
}

/// Write `n` objects into pg 1.`seed`, wait for acks, return the model.
fn fill(s: &mut Sim, seed: u32, n: usize, tag: &str) -> BTreeMap<String, Vec<u8>> {
    let mut model = BTreeMap::new();
    let mut tids = vec![];
    for i in 0..n {
        let name = format!("{tag}{i}");
        let d = payload(i, 100 + i * 13);
        let t = s.write_obj(1, seed, &name, &d).expect("write accepted");
        tids.push(t);
        model.insert(name, d);
        s.run_for(MS / 2);
    }
    s.wait_writes(&tids, spg(1, seed));
    model
}

fn small_logs(c: &mut peering::Config) {
    c.min_pg_log_entries = 10;
    c.pg_log_trim_min = 1;
    c.pg_log_trim_max = 50;
    c.log_dups_tracked = 20;
}

/// An undersized PG keeps an up stray until it is clean again (classic purges strays only when clean): the stray may
/// hold the only extra copy of objects not written since it left.
#[test]
fn undersized_pg_keeps_up_stray() {
    let mut s = cluster_cfg(71, &[0, 1, 2], 1, 3, 2, 1, small_logs);
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 10, "a");
    let x = s.acting_of(pg.pgid)[2];
    s.kill(x);
    s.mark_out(x);
    s.run_for(500 * MS);
    // past the log: x needs backfill, so it is no acting candidate when it comes back
    model.extend(fill(&mut s, 0, 80, "b"));
    s.restart(x);
    s.run_for(5_000 * MS);
    let p = s.primary_of(pg.pgid);
    let st = s.pg(p, pg).unwrap().state_bits();
    assert!(
        st & pgs::ACTIVE != 0 && st & pgs::UNDERSIZED != 0 && st & pgs::CLEAN == 0,
        "active+undersized: {}",
        s.pg(p, pg).unwrap().state_string()
    );
    assert!(!s.acting_of(pg.pgid).contains(&x));
    assert!(
        s.pg(x, pg).is_some(),
        "up stray purged while the PG is undersized"
    );
    // back in: the PG becomes clean on [.., x] and nothing is lost
    s.mark_in(x);
    s.run_until(120_000 * MS, "clean", |s| s.pool_clean(1));
    s.run_for(500 * MS);
    s.assert_replicas_equal(1, 0, &model);
}

/// A replica whose stored stats carry a stale `num_objects_missing` (copied from a primary that activated with
/// missing objects) is no async-recovery target for good: the primary refreshes the peer's count from its missing
/// set before it re-chooses the acting set at the end of recovery (classic update_calc_stats), so the PG gets clean.
#[test]
fn stale_peer_missing_count_does_not_keep_async_target_out() {
    let mut s = cluster_cfg(72, &[0, 1, 2], 1, 3, 2, 1, |c| {
        small_logs(c);
        c.min_pg_log_entries = 400;
        c.async_recovery_min_cost = 5;
    });
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 5, "a");
    // the primary falls behind by 30 objects and comes back as primary: it activates with 30 missing, the replicas
    // copy that count into their stats
    let a = s.primary_of(pg.pgid);
    s.kill(a);
    s.run_for(300 * MS);
    model.extend(fill(&mut s, 0, 30, "b"));
    s.restart(a);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    assert_eq!(s.primary_of(pg.pgid), a);
    // a replica restarts without missing anything: its notify still reports the old count
    let c = s.acting_of(pg.pgid)[2];
    s.kill(c);
    s.run_for(300 * MS);
    s.restart(c);
    s.run_until(60_000 * MS, "clean with the replica back", |s| {
        s.pool_clean(1) && s.acting_of(pg.pgid).contains(&c)
    });
    s.run_for(500 * MS);
    s.assert_replicas_equal(1, 0, &model);
}

/// Writes to objects missing only on an async-recovery target proceed (classic: the target gets the log entries with an
/// empty transaction and keeps the object missing); recovery then brings it the newest version.
#[test]
fn writes_to_objects_missing_on_async_target_proceed() {
    let mut s = cluster_cfg(73, &[0, 1, 2], 1, 3, 2, 1, |c| {
        small_logs(c);
        c.min_pg_log_entries = 400;
        c.async_recovery_min_cost = 5;
        c.recovery_max_active = 1;
    });
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 5, "a");
    let victim = s.acting_of(pg.pgid)[2];
    s.kill(victim);
    s.run_for(300 * MS);
    model.extend(fill(&mut s, 0, 30, "b"));
    s.restart(victim);
    // the victim is an async target: out of acting by pg_temp, the PG active without it
    s.run_until(30_000 * MS, "async target out of acting", |s| {
        let p = s.primary_of(pg.pgid);
        s.map().pg_temp.contains_key(&pg.pgid)
            && !s.acting_of(pg.pgid).contains(&victim)
            && s.pg(p, pg)
                .is_some_and(|p| p.state_bits() & pgs::ACTIVE != 0)
    });
    let mut tids = vec![];
    for i in 0..30 {
        let name = format!("b{i}");
        let d = payload(1000 + i, 77);
        let t = s
            .write_obj(1, 0, &name, &d)
            .unwrap_or_else(|e| panic!("write to {name} refused while async-recovering: {e:?}"));
        tids.push(t);
        model.insert(name, d);
    }
    s.wait_writes(&tids, pg);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    s.run_for(500 * MS);
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
}

/// A backfill scan in flight holds back no client write (classic blocks only objects whose push is in flight): with the
/// target's digest held, writes anywhere in the not yet backfilled keyspace are accepted, and the backfill result
/// still matches.
#[test]
fn backfill_scan_does_not_block_writes() {
    let mut s = Sim::new(74);
    for o in 0..3 {
        s.add_osd_cfg(o, small_logs);
    }
    s.run_for(50 * MS);
    s.create_pool(1, 3, 2, 1);
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let mut model = fill(&mut s, 0, 60, "n");
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    // osd.3 joins and is backfilled; its first scan digest never arrives (a slow or silent target): the scan stays in
    // flight until its deadline
    s.drop_next.push((3, prim, 94));
    s.add_osd_cfg(3, small_logs);
    s.run_until(60_000 * MS, "backfilling", |s| {
        s.pg(s.primary_of(pg.pgid), pg)
            .is_some_and(|p| p.state_string().contains("backfilling"))
    });
    assert_eq!(s.primary_of(pg.pgid), prim);
    s.run_for(50 * MS);
    assert!(s.dropped_lost > 0, "digest not dropped yet");
    let mut tids = vec![];
    for i in 0..60 {
        let name = format!("n{i}");
        let d = payload(500 + i, 90);
        let t = s
            .write_obj(1, 0, &name, &d)
            .unwrap_or_else(|e| panic!("write to {name} refused during a backfill scan: {e:?}"));
        tids.push(t);
        model.insert(name, d);
    }
    s.wait_writes(&tids, pg);
    s.run_until(120_000 * MS, "clean on new set", |s| s.pool_clean(1));
    s.run_for(500 * MS);
    assert!(s.acting_of(pg.pgid).contains(&3));
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
}

/// A write parked on a degraded object moves that object to the front of recovery (classic `maybe_kick_recovery`): the
/// newest missing object is recovered first, not after every older one.
#[test]
fn parked_write_kicks_recovery_of_its_object() {
    let mut s = cluster_cfg(75, &[0, 1, 2], 1, 3, 2, 1, |c| {
        small_logs(c);
        c.min_pg_log_entries = 400;
        c.recovery_max_active = 1;
    });
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 5, "a");
    let victim = s.acting_of(pg.pgid)[2];
    s.kill(victim);
    s.run_for(300 * MS);
    model.extend(fill(&mut s, 0, 30, "b"));
    s.restart(victim);
    let last = hobj(1, "b29");
    s.run_until(30_000 * MS, "victim recovering", |s| {
        s.pg(victim, pg)
            .is_some_and(|p| p.missing().len() > 25 && p.missing().contains(&last))
            && s.pg(s.primary_of(pg.pgid), pg)
                .is_some_and(|p| p.state_bits() & pgs::ACTIVE != 0)
    });
    assert!(
        s.write_obj(1, 0, "b29", b"x").is_err(),
        "write to a degraded object parks"
    );
    s.run_until(30_000 * MS, "b29 recovered", |s| {
        s.pg(victim, pg)
            .is_some_and(|p| !p.missing().contains(&last))
    });
    let left = s.pg(victim, pg).unwrap().missing().len();
    assert!(left > 20, "b29 recovered only after {} others", 30 - left);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    s.assert_replicas_equal(1, 0, &model);
}

/// A primary that adopted the authoritative log in GetLog also takes the auth's `last_epoch_started` /
/// `last_interval_started` (classic proc_master_log), so it stays eligible as auth if the interval changes before it
/// activates.
#[test]
fn got_log_raises_last_epoch_started() {
    let mut s = cluster(76, &[0, 1], 1, 2, 1, 1);
    let pg = spg(1, 0);
    let model = fill(&mut s, 0, 4, "a");
    let a = s.primary_of(pg.pgid);
    let b = s.acting_of(pg.pgid)[1];
    s.kill(a);
    s.run_until(30_000 * MS, "b active alone", |s| {
        s.primary_of(pg.pgid) == b
            && s.pg(b, pg)
                .is_some_and(|p| p.state_bits() & pgs::ACTIVE != 0)
    });
    s.run_for(10_000 * MS);
    let mut model2 = model.clone();
    model2.extend(fill(&mut s, 0, 6, "b"));
    let (b_lu, b_les) = {
        let i = s.pg(b, pg).unwrap().info();
        (i.last_update, i.last_epoch_started)
    };
    s.restart(a);
    let mut saw = false;
    let end = s.now + 30_000 * MS;
    while s.now < end && !s.pool_clean(1) {
        s.run_for(MS / 4);
        if let Some(p) = s.pg(a, pg)
            && p.info().last_update >= b_lu
        {
            saw = true;
            assert!(
                p.info().last_epoch_started >= b_les,
                "log adopted, les {} < auth les {b_les} ({})",
                p.info().last_epoch_started,
                p.state_string()
            );
        }
    }
    assert!(saw && s.pool_clean(1));
    s.assert_replicas_equal(1, 0, &model2);
}

/// With the primary chosen outside `up` (auth primary by pg_temp), every up member is classified: a new up member
/// beyond `size` entries of `want` becomes a backfill target in that interval (classic: no early stop in the up loop).
#[test]
fn auth_primary_outside_up_classifies_every_up_member() {
    let mut s = cluster_cfg(77, &[0, 1, 2, 3], 1, 3, 1, 1, |c| {
        small_logs(c);
        c.force_auth_primary_missing_objects = 0;
    });
    let pg = spg(1, 0);
    s.set_up_override(pg.pgid, vec![0, 1, 2]);
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let mut model = fill(&mut s, 0, 5, "a");
    s.kill(1);
    s.kill(2);
    s.run_for(10_000 * MS);
    model.extend(fill(&mut s, 0, 5, "b"));
    s.restart(1);
    s.restart(2);
    s.set_up_override(pg.pgid, vec![1, 2, 3]);
    let mut seen = false;
    let end = s.now + 60_000 * MS;
    while s.now < end && !s.pool_clean(1) {
        s.run_for(MS);
        if s.primary_of(pg.pgid) == 0 && s.pg(3, pg).is_some() {
            seen = true;
        }
    }
    assert!(seen, "osd.3 got nothing while the auth primary osd.0 led");
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    s.assert_replicas_equal(1, 0, &model);
}

/// P9: a stray whose activation info says it is behind (it cannot be: the primary sends a bare info only to a peer it
/// believes current) fail-stops (classic asserts) instead of staying stray while the primary waits in activating for
/// good. The restarted OSD reports its real state and the PG goes clean.
#[test]
fn stray_behind_on_activation_info_fail_stops() {
    let mut s = cluster(76, &[0, 1, 2], 1, 3, 2, 1);
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let model = fill(&mut s, 0, 10, "p");
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    let acting = s.acting_of(pg.pgid);
    let r = *acting.iter().find(|o| **o != prim).unwrap();
    let t = *acting.iter().find(|o| **o != prim && **o != r).unwrap();
    // new interval without t: the activation of r is lost, r stays stray
    s.drop_next.push((prim, r, pgwire::msgs::ty::PG_INFO2));
    let lost = s.dropped_lost;
    s.kill(t);
    s.run_until(30_000 * MS, "activation lost", |s| s.dropped_lost > lost);
    assert_eq!(s.primary_of(pg.pgid), prim);
    let mut info = s.pg(prim, pg).unwrap().info().clone();
    info.pgid = pg;
    info.last_update.version += 1;
    let e = s.epoch();
    // the classic model flags exactly this message (classic `Stray::react(MInfoRec)` asserts): that is the case here
    s.classic = None;
    s.inject(
        prim,
        r,
        Body::Peering(PeeringMsg::MOSDPGInfo2(pgwire::MOSDPGInfo2 {
            spgid: pg,
            epoch_sent: e,
            min_epoch: e,
            info,
            lease: None,
            lease_ack: None,
        })),
    );
    s.run_for(1_000 * MS);
    assert_eq!(
        s.fatals,
        vec![(r, pg, "info activation: replica behind (needs log)")]
    );
    s.restart(r);
    s.restart(t);
    s.run_until(120_000 * MS, "clean after restart", |s| s.pool_clean(1));
    s.assert_replicas_equal(1, 0, &model);
}

/// R2: an undecodable repop from the primary fail-stops the replica (classic: the decode throws, the OSD goes down),
/// never a silent drop that holds the primary's write until some unrelated interval change. The write completes on the
/// new interval and the restarted replica catches up.
#[test]
fn replica_fail_stops_on_undecodable_repop() {
    // one entry whose struct header claims 4 bytes of garbage
    repop_logbl_fail_stop(
        vec![1, 0, 0, 0, 14, 5, 4, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        "repop: bad log entries",
    );
}

/// E3: a repop without `logbl` (classic asserts it is non-empty) is never applied as data without a log entry: the
/// replica fail-stops like on an undecodable repop.
#[test]
fn replica_fail_stops_on_repop_without_logbl() {
    repop_logbl_fail_stop(Vec::new(), "repop: empty logbl");
}

fn repop_logbl_fail_stop(logbl: Vec<u8>, why: &'static str) {
    let mut s = cluster(77, &[0, 1, 2], 1, 3, 2, 1);
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let mut model = fill(&mut s, 0, 10, "q");
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    s.capture = true;
    let t = s.write_obj(1, 0, "q0", b"again").unwrap();
    s.wait_writes(&[t], pg);
    model.insert("q0".into(), b"again".to_vec());
    let (r, mut bad) = s
        .captured
        .iter()
        .find_map(|(f, to, b)| match b {
            Body::Repl(ReplMsg::RepOp(m)) if *f == prim => Some((*to, m.clone())),
            _ => None,
        })
        .expect("a repop");
    s.capture = false;
    bad.logbl = logbl.into();
    s.inject(prim, r, Body::Repl(ReplMsg::RepOp(bad)));
    s.run_for(1_000 * MS);
    assert_eq!(s.fatals, vec![(r, pg, why)]);
    let t = s.write_obj(1, 0, "q1", b"after").unwrap();
    s.wait_writes(&[t], pg);
    model.insert("q1".into(), b"after".to_vec());
    s.restart(r);
    s.run_until(120_000 * MS, "clean after restart", |s| s.pool_clean(1));
    s.assert_replicas_equal(1, 0, &model);
}

/// F2: the croit-flashstore-osd primary never recovers onto a member the mon flagged FULL (classic `check_full` over
/// acting_recovery_backfill -> `recovery_toofull`, retry after osd_recovery_retry_interval): a classic replica aborts on
/// a push at its failsafe ratio. Recovery resumes once the flag clears.
#[test]
fn recovery_holds_while_a_member_is_full() {
    let mut s = cluster(78, &[0, 1, 2], 1, 3, 2, 1);
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let mut model = fill(&mut s, 0, 10, "f");
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    let r = *s.acting_of(pg.pgid).iter().find(|o| **o != prim).unwrap();
    s.kill(r);
    // new interval without r: the prior read lease runs out first
    s.run_for(10_000 * MS);
    model.extend(fill(&mut s, 0, 10, "g"));
    s.new_epoch(|m| m.osds.get_mut(&r).unwrap().full = true);
    s.restart(r);
    s.run_until(60_000 * MS, "recovery_toofull", |s| {
        s.pg(s.primary_of(pg.pgid), pg)
            .is_some_and(|p| p.state_string().contains("recovery_toofull"))
    });
    assert_eq!(s.primary_of(pg.pgid), prim);
    let push = replwire::ty::PUSH;
    let pushes = |s: &Sim| s.stats.msgs_by_type.get(&push).copied().unwrap_or(0);
    let before = pushes(&s);
    s.run_for(70_000 * MS);
    assert_eq!(pushes(&s), before, "no push while a member is full");
    let st = s.pg(prim, pg).unwrap().state_string();
    assert!(
        st.contains("recovery_toofull") && !st.contains("clean"),
        "{st}"
    );
    s.new_epoch(|m| m.osds.get_mut(&r).unwrap().full = false);
    s.run_until(120_000 * MS, "clean after the full flag cleared", |s| {
        s.pool_clean(1)
    });
    s.assert_replicas_equal(1, 0, &model);
}

fn bf_state(s: &Sim, pg: denc::types::SpgT, what: &str) -> bool {
    s.pg(s.primary_of(pg.pgid), pg)
        .is_some_and(|p| p.state_string().contains(what))
}

/// F1: an croit-flashstore-osd replica above backfillfull rejects a backfill reservation (REJECT_TOOFULL, classic
/// `try_reserve_recovery_space`): the primary shows backfill_toofull and pushes nothing to it. Below the ratio it
/// takes the backfill.
#[test]
fn backfillfull_replica_rejects_the_backfill_reservation() {
    let mut s = Sim::new(74);
    for o in 0..3 {
        s.add_osd_cfg(o, small_logs);
    }
    s.run_for(50 * MS);
    s.create_pool(1, 3, 2, 1);
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let model = fill(&mut s, 0, 60, "b");
    let pg = spg(1, 0);
    s.add_osd_cfg(3, small_logs);
    let full = peering::LocalFull {
        total: 1_000_000,
        used: 950_000,
        backfill_limit: 900_000,
        failsafe: false,
    };
    s.nodes.get_mut(&3).unwrap().set.set_local_full(full);
    s.run_until(60_000 * MS, "backfill_toofull", |s| {
        bf_state(s, pg, "backfill_toofull")
    });
    assert!(s.acting_of(pg.pgid).contains(&3) || s.up_of(pg.pgid).contains(&3));
    let push = replwire::ty::PUSH;
    let pushes = |s: &Sim| s.stats.msgs_by_type.get(&push).copied().unwrap_or(0);
    let before = pushes(&s);
    s.run_for(20_000 * MS);
    assert_eq!(
        pushes(&s),
        before,
        "no backfill push into a backfillfull replica"
    );
    s.nodes
        .get_mut(&3)
        .unwrap()
        .set
        .set_local_full(Default::default());
    s.run_until(120_000 * MS, "clean after space returned", |s| {
        s.pool_clean(1)
    });
    s.assert_replicas_equal(1, 0, &model);
}

/// C1 (classic `try_reserve_recovery_space`): a replica physically below backfillfull rejects a backfill whose data
/// would push it above (primary bytes minus what it holds); once there is room it grants, and the bytes the held
/// reservation still expects shrink as the data lands and are gone when the backfill ends. Run with a classic
/// stand-in on either side (classic primary -> croit-flashstore-osd replica, croit-flashstore-osd primary -> classic replica): every message
/// must be one classic accepts.
#[test]
fn replica_judges_projected_backfill_bytes() {
    for classic_side in ["primary", "replica"] {
        projected_backfill_run(classic_side);
    }
}

fn projected_backfill_run(classic_side: &str) {
    let mut s = Sim::new(75);
    for o in 0..3 {
        s.add_osd_cfg(o, small_logs);
    }
    s.run_for(50 * MS);
    s.create_pool(1, 3, 2, 1);
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let model = fill(&mut s, 0, 60, "p");
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    let primary_bytes: u64 = model.values().map(|v| v.len() as u64).sum();
    s.classic_set(&[if classic_side == "primary" { prim } else { 3 }]);
    // 10 KiB below the limit: physically fine, but not with the backfill's bytes
    let tight = peering::LocalFull {
        total: 1_000_000,
        used: 890_000,
        backfill_limit: 900_000,
        failsafe: false,
    };
    assert!(!tight.backfillfull_with(0) && tight.backfillfull_with(primary_bytes));
    s.add_osd_cfg(3, small_logs);
    s.nodes.get_mut(&3).unwrap().set.set_local_full(tight);
    s.run_until(60_000 * MS, "backfill_toofull", |s| {
        bf_state(s, pg, "backfill_toofull")
    });
    let push = replwire::ty::PUSH;
    let pushes = |s: &Sim| s.stats.msgs_by_type.get(&push).copied().unwrap_or(0);
    let before = pushes(&s);
    s.run_for(20_000 * MS);
    assert_eq!(
        pushes(&s),
        before,
        "no backfill push into a target the data would fill"
    );
    let held = |s: &Sim| s.nodes[&3].set.backfill_held(&s.nodes[&3].store);
    assert_eq!(held(&s), 0, "a rejected reservation holds nothing");
    // room for it: granted, the reservation counts the expected bytes until the data is there
    s.nodes
        .get_mut(&3)
        .unwrap()
        .set
        .set_local_full(peering::LocalFull {
            used: 500_000,
            ..tight
        });
    s.run_until(120_000 * MS, "reservation held", |s| held(s) > 0);
    let first = held(&s);
    assert!(first <= primary_bytes, "{first} > {primary_bytes}");
    let mut min_seen = first;
    let end = s.now + 120_000 * MS;
    while s.now < end && !s.pool_clean(1) {
        s.run_for(MS);
        min_seen = min_seen.min(held(&s));
    }
    assert!(s.pool_clean(1), "clean after space returned: {}", s.dump());
    assert!(
        min_seen < first || first == 0,
        "held bytes shrink as data lands"
    );
    assert_eq!(held(&s), 0, "released at the end of the backfill");
    s.assert_replicas_equal(1, 0, &model);
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
}

/// C1: the bytes one PG's held backfill reservation still expects count against the next PG's reservation on the
/// same OSD (classic sums them over all PGs): room for one backfill, not two, admits one at a time; both end clean.
#[test]
fn held_backfill_bytes_count_against_the_next_reservation() {
    // two backfill slots on every OSD: both reservations may be asked for at once, only space decides
    let cfg = |c: &mut peering::Config| {
        small_logs(c);
        c.max_backfills = 2;
    };
    let mut s = Sim::new(76);
    for o in 0..3 {
        s.add_osd_cfg(o, cfg);
    }
    s.run_for(50 * MS);
    s.create_pool(1, 3, 2, 2);
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let m0 = fill(&mut s, 0, 60, "x");
    let m1 = fill(&mut s, 1, 60, "y");
    let bytes = |m: &BTreeMap<String, Vec<u8>>| m.values().map(|v| v.len() as u64).sum::<u64>();
    let (b0, b1) = (bytes(&m0), bytes(&m1));
    // room for the larger one alone, not for both
    let room = b0.max(b1) + b0.min(b1) / 2;
    s.add_osd_cfg(3, cfg);
    s.classic_set(&[0, 1, 2]);
    s.nodes
        .get_mut(&3)
        .unwrap()
        .set
        .set_local_full(peering::LocalFull {
            total: 1_000_000,
            used: 900_000 - room,
            backfill_limit: 900_000,
            failsafe: false,
        });
    for seed in 0..2 {
        let pg = denc::types::PgT::new(1, seed);
        let mut up = s.up_of(pg);
        if !up.contains(&3) {
            up[2] = 3;
            s.set_up_override(pg, up);
        }
    }
    let (p0, p1) = (spg(1, 0), spg(1, 1));
    let mut both_held = false;
    let mut one_toofull = false;
    let end = s.now + 240_000 * MS;
    while s.now < end && !s.pool_clean(1) {
        s.run_for(MS);
        let n = &s.nodes[&3];
        let held: Vec<u64> = [p0, p1]
            .iter()
            .map(|p| n.set.pg(*p).map_or(0, |g| g.backfill_held(&n.store)))
            .collect();
        both_held |= held.iter().all(|h| *h > 0);
        one_toofull |= bf_state(&s, p0, "backfill_toofull") || bf_state(&s, p1, "backfill_toofull");
    }
    assert!(s.pool_clean(1), "{}", s.dump());
    assert!(
        !both_held,
        "both reservations held at once: the second ignored the first's bytes"
    );
    assert!(
        one_toofull,
        "the second backfill waited as backfill_toofull"
    );
    s.assert_replicas_equal(1, 0, &m0);
    s.assert_replicas_equal(1, 1, &m1);
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
}

/// F1: a replica that crosses backfillfull while it holds the backfill slot withdraws it at the next scan
/// (REVOKE_TOOFULL, classic `do_scan`), the primary stops and retries later.
#[test]
fn replica_crossing_backfillfull_revokes_at_the_next_scan() {
    let mut s = Sim::new(74);
    for o in 0..3 {
        s.add_osd_cfg(o, small_logs);
    }
    s.run_for(50 * MS);
    s.create_pool(1, 3, 2, 1);
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let model = fill(&mut s, 0, 600, "r");
    let pg = spg(1, 0);
    s.add_osd_cfg(3, small_logs);
    s.run_until(60_000 * MS, "backfilling", |s| {
        bf_state(s, pg, "backfilling")
    });
    let full = peering::LocalFull {
        total: 1_000_000,
        used: 950_000,
        backfill_limit: 900_000,
        failsafe: false,
    };
    s.nodes.get_mut(&3).unwrap().set.set_local_full(full);
    s.run_until(60_000 * MS, "backfill_toofull", |s| {
        bf_state(s, pg, "backfill_toofull")
    });
    s.nodes
        .get_mut(&3)
        .unwrap()
        .set
        .set_local_full(Default::default());
    s.run_until(180_000 * MS, "clean after space returned", |s| {
        s.pool_clean(1)
    });
    s.assert_replicas_equal(1, 0, &model);
}
