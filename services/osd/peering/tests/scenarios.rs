// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Peering scenarios on the deterministic simulator.
mod common;
use common::*;
use pgwire::state as pgs;
use std::collections::BTreeMap;

fn payload(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|j| ((i * 131 + j * 7) % 251) as u8).collect()
}

/// Write `n` objects into pg 1.0, wait for acks, return the model.
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

#[test]
fn writes_replicate_size3() {
    let mut s = cluster(11, &[0, 1, 2], 1, 3, 2, 1);
    let model = fill(&mut s, 0, 20, "o");
    s.run_for(200 * MS);
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
    s.assert_no_roundtrip_mismatch();
    for o in 0..3 {
        let p = s.pg(o, spg(1, 0)).unwrap();
        assert_eq!(p.info().last_update.version, 20);
        assert_eq!(p.info().last_complete, p.info().last_update);
    }
}

#[test]
fn writes_replicate_size1_and_2() {
    for (osds, size) in [(vec![0], 1), (vec![0, 1], 2)] {
        let mut s = cluster(12, &osds, 1, size, 1, 1);
        let model = fill(&mut s, 0, 10, "x");
        s.run_for(100 * MS);
        s.assert_replicas_equal(1, 0, &model);
        s.assert_persisted_consistent();
    }
}

#[test]
fn leases_keep_primary_readable() {
    let mut s = cluster(13, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    // run well past several lease intervals; the primary must always be readable once started
    let mut gaps = 0;
    let end = s.now + 120_000 * MS;
    s.run_for(1000 * MS);
    while s.now < end {
        s.run_for(500 * MS);
        let now = s.now;
        if !s.pg(prim, pg).unwrap().is_readable(now) {
            gaps += 1;
        }
    }
    assert_eq!(gaps, 0, "{}", s.dump());
    // replicas keep acking
    assert!(s.stats.msgs_by_type.get(&134).copied().unwrap_or(0) >= 10);
}

#[test]
fn lease_lost_without_acks() {
    let mut s = cluster(14, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    s.run_for(2000 * MS);
    assert!(s.pg(prim, pg).unwrap().is_readable(s.now));
    // replicas stop answering (their messages to the primary are dropped)
    for o in s.acting_of(pg.pgid) {
        if o != prim {
            s.block_all_from.insert(o);
        }
    }
    s.run_for(20_000 * MS);
    let now = s.now;
    assert!(
        !s.pg(prim, pg).unwrap().is_readable(now),
        "lease must expire"
    );
    assert!(
        !s.nodes
            .get_mut(&prim)
            .unwrap()
            .set
            .pg_mut(pg)
            .unwrap()
            .check_readable(now)
    );
    assert!(s.pg(prim, pg).unwrap().state_bits() & pgs::LAGGY != 0);
    // heal: acks resume, readable again
    s.heal();
    s.run_for(10_000 * MS);
    assert!(s.pg(prim, pg).unwrap().is_readable(s.now));
}

#[test]
fn replica_restart_catches_up_by_log() {
    let mut s = cluster(15, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 10, "a");
    let victim = s.acting_of(pg.pgid)[2];
    s.kill(victim);
    s.run_for(500 * MS);
    // PG stays active (min_size 2) but undersized+degraded
    let prim = s.primary_of(pg.pgid);
    s.run_until(10_000 * MS, "undersized active", |s| {
        s.pg(prim, pg).is_some_and(|p| {
            p.state_bits() & (pgs::ACTIVE | pgs::UNDERSIZED) == (pgs::ACTIVE | pgs::UNDERSIZED)
        })
    });
    model.extend(fill(&mut s, 0, 15, "b"));
    s.restart(victim);
    s.run_until(60_000 * MS, "clean again", |s| s.pool_clean(1));
    s.run_for(300 * MS);
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
    s.assert_no_roundtrip_mismatch();
    let v = s.pg(victim, pg).unwrap();
    assert_eq!(
        v.info().last_update,
        s.pg(prim, pg).unwrap().info().last_update
    );
    assert!(v.missing().is_empty());
}

#[test]
fn primary_change_and_return() {
    let mut s = cluster(16, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 8, "a");
    let old = s.primary_of(pg.pgid);
    s.kill(old);
    s.run_until(20_000 * MS, "new primary active", |s| {
        let p = s.primary_of(pg.pgid);
        p != old
            && s.pg(p, pg)
                .is_some_and(|x| x.state_bits() & pgs::ACTIVE != 0 && x.is_primary())
    });
    model.extend(fill(&mut s, 0, 8, "b"));
    s.restart(old);
    s.run_until(60_000 * MS, "clean after old primary returns", |s| {
        s.pool_clean(1)
    });
    s.run_for(300 * MS);
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
    s.assert_no_roundtrip_mismatch();
}

/// The primary applied writes locally that no replica ever saw, then died: when it returns its
/// log is divergent and must be rewound (primary path: merge_log from the auth log).
#[test]
fn divergent_primary_rewinds() {
    let mut s = cluster(17, &[0, 1, 2], 1, 3, 2, 1);
    s.verbose = true;
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 6, "a");
    let old = s.primary_of(pg.pgid);
    // cut the primary off from its replicas, then write: only the primary commits
    for o in s.acting_of(pg.pgid) {
        if o != old {
            s.partition(old, o);
        }
    }
    let t1 = s.write_obj(1, 0, "div_new", b"never acked").unwrap(); // new object
    let t2 = s.write_obj(1, 0, "a0", b"divergent overwrite").unwrap(); // modifies an existing object
    let t3 = s.delete_obj(1, 0, "a1").unwrap(); // deletes an existing object
    s.run_for(50 * MS);
    assert!(!s.is_acked(pg, t1) && !s.is_acked(pg, t2) && !s.is_acked(pg, t3));
    assert_eq!(s.pg(old, pg).unwrap().info().last_update.version, 9);
    s.kill(old);
    s.heal();
    s.run_until(20_000 * MS, "new primary active", |s| {
        let p = s.primary_of(pg.pgid);
        p != old
            && s.pg(p, pg)
                .is_some_and(|x| x.state_bits() & pgs::ACTIVE != 0 && x.is_primary())
    });
    model.extend(fill(&mut s, 0, 5, "b"));
    s.restart(old);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    s.run_for(500 * MS);
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
    s.assert_no_roundtrip_mismatch();
    let o = s.pg(old, pg).unwrap();
    assert!(o.missing().is_empty());
    assert_eq!(
        o.info().last_update,
        s.pg(s.primary_of(pg.pgid), pg).unwrap().info().last_update
    );
}

/// Same, but the returning OSD is a *replica* (forced mapping): the primary activates it with
/// MOSDPGLog / Info and the replica rewinds its divergent entries (Stray::MLogRec path).
#[test]
fn divergent_replica_rewinds() {
    let mut s = cluster(18, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 6, "a");
    let old = s.primary_of(pg.pgid);
    for o in s.acting_of(pg.pgid) {
        if o != old {
            s.partition(old, o);
        }
    }
    s.write_obj(1, 0, "div_new", b"never acked").unwrap();
    s.write_obj(1, 0, "a0", b"divergent overwrite").unwrap();
    s.delete_obj(1, 0, "a1").unwrap();
    s.run_for(50 * MS);
    s.kill(old);
    s.heal();
    s.run_until(20_000 * MS, "new primary active", |s| {
        let p = s.primary_of(pg.pgid);
        p != old
            && s.pg(p, pg)
                .is_some_and(|x| x.state_bits() & pgs::ACTIVE != 0 && x.is_primary())
    });
    model.extend(fill(&mut s, 0, 5, "b"));
    // old comes back but must not lead: force the mapping so it is the last replica
    let others: Vec<i32> = s.acting_of(pg.pgid);
    let mut up = others.clone();
    up.push(old);
    s.set_up_override(pg.pgid, up.clone());
    s.restart(old);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    s.run_for(500 * MS);
    assert_eq!(s.up_of(pg.pgid), up);
    assert_eq!(*s.acting_of(pg.pgid).last().unwrap(), old);
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
    s.assert_no_roundtrip_mismatch();
}

#[test]
fn undersized_then_joins() {
    // size 3 / min_size 2 with only two OSDs: active+undersized+degraded; third OSD joins -> clean
    let mut s = Sim::new(19);
    s.add_osd(0);
    s.add_osd(1);
    s.run_for(50 * MS);
    s.create_pool(1, 3, 2, 2);
    s.run_until(30_000 * MS, "active", |s| {
        s.pool_state_strings(1)
            .iter()
            .all(|x| x == "active+undersized+degraded")
    });
    let st = s.pool_state_strings(1);
    for x in &st {
        assert_eq!(x, "active+undersized+degraded", "{}", s.dump());
    }
    let model = fill(&mut s, 0, 10, "u");
    s.add_osd(2);
    s.run_until(60_000 * MS, "clean with 3", |s| s.pool_clean(1));
    s.run_for(500 * MS);
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
    s.assert_no_roundtrip_mismatch();
}

#[test]
fn below_min_size_is_peered_not_active() {
    let mut s = cluster(20, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let acting = s.acting_of(pg.pgid);
    s.kill(acting[1]);
    s.kill(acting[2]);
    s.run_for(5000 * MS);
    let prim = s.primary_of(pg.pgid);
    let p = s.pg(prim, pg).unwrap();
    assert!(p.state_bits() & pgs::ACTIVE == 0, "{}", p.state_string());
    assert!(p.state_bits() & pgs::PEERED != 0, "{}", p.state_string());
    assert_eq!(
        s.write_obj(1, 0, "x", b"y"),
        Err(peering::WriteErr::NotActive)
    );
    // back up: active+clean
    s.restart(acting[1]);
    s.restart(acting[2]);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
}

/// H-1: `osd_allow_recovery_below_min_size=false` keeps a PG below min_size incomplete (down) instead of peering
/// and recovering with too few copies.
#[test]
fn recovery_below_min_size_disabled_keeps_the_pg_incomplete() {
    let mut s = cluster_cfg(22, &[0, 1, 2], 1, 3, 2, 1, |c| {
        c.allow_recovery_below_min_size = false;
    });
    let pg = spg(1, 0);
    let acting = s.acting_of(pg.pgid);
    s.kill(acting[1]);
    s.kill(acting[2]);
    s.run_for(5_000 * MS);
    let prim = s.primary_of(pg.pgid);
    let p = s.pg(prim, pg).unwrap();
    assert_eq!(
        p.state_bits() & (pgs::ACTIVE | pgs::PEERED),
        0,
        "below min_size stays incomplete: {}",
        p.state_string()
    );
    assert_eq!(
        s.write_obj(1, 0, "x", b"y"),
        Err(peering::WriteErr::NotActive)
    );
}

#[test]
fn stale_interval_messages_are_dropped() {
    let mut s = cluster(21, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    // a flapping map: mark a replica down and up quickly to force interval changes with writes in flight
    let victim = s.acting_of(pg.pgid)[1];
    let mut model = fill(&mut s, 0, 5, "a");
    let t = s.write_obj(1, 0, "inflight", b"data").ok();
    s.mark_down(victim);
    s.run_for(30 * MS);
    s.mark_up(victim);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    if let Some(t) = t
        && s.is_acked(pg, t)
    {
        model.insert("inflight".into(), b"data".to_vec());
    }
    s.run_for(500 * MS);
    let _ = prim;
    // the in-flight write is either present everywhere or nowhere; replicas agree
    let objs: Vec<_> = s
        .acting_of(pg.pgid)
        .iter()
        .map(|o| s.contents(*o, 1, 0))
        .collect();
    assert!(objs.windows(2).all(|w| w[0] == w[1]), "{}", s.dump());
    s.assert_persisted_consistent();
}

fn small_logs(c: &mut peering::Config) {
    c.min_pg_log_entries = 10;
    c.pg_log_trim_min = 1;
    c.pg_log_trim_max = 50;
    c.log_dups_tracked = 20;
}

#[test]
fn log_trimming_bounds_log_and_keeps_dups() {
    let mut s = cluster_cfg(30, &[0, 1, 2], 1, 3, 2, 1, small_logs);
    let pg = spg(1, 0);
    let model = fill(&mut s, 0, 60, "t");
    s.run_for(500 * MS);
    for o in 0..3 {
        let p = s.pg(o, pg).unwrap();
        assert!(p.log().len() <= 12, "osd.{o} log len {}", p.log().len());
        assert!(p.log().tail().version > 40);
        assert!(p.log().log.dups.len() <= 20 && !p.log().log.dups.is_empty());
    }
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
}

/// PG log sizing from the options (spec pglog.md 6.3): the per-PG target is `target_per_osd / num_pgs` clamped to
/// [min, max] with min winning; a runtime change applies at the next trim; min > max (any order a runtime `config set`
/// may leave) never panics.
#[test]
fn log_target_follows_osd_pg_count_and_runtime_options() {
    let mut s = cluster_cfg(32, &[0, 1, 2], 1, 3, 2, 1, small_logs);
    let pg = spg(1, 0);
    let set_log = |s: &mut Sim, l: peering::PgLogCfg, num_pgs: u64| {
        for n in s.nodes.values_mut() {
            n.set.set_pg_log(l);
            n.set.set_num_pgs(num_pgs);
            n.set.push_cfg_to_pgs();
        }
    };
    let lens =
        |s: &Sim| -> Vec<usize> { (0..3).map(|o| s.pg(o, pg).unwrap().log().len()).collect() };
    let base = peering::PgLogCfg {
        min_entries: 10,
        max_entries: 30,
        trim_min: 1,
        trim_max: 50,
        target_per_osd: 40,
        dups_tracked: 20,
    };
    // 2 PGs on the OSD: target 40 / 2 = 20 entries
    set_log(&mut s, base, 2);
    let mut model = fill(&mut s, 0, 60, "a");
    s.run_for(500 * MS);
    for (o, l) in lens(&s).into_iter().enumerate() {
        assert!((18..=22).contains(&l), "osd.{o} log len {l} (target 20)");
    }
    // 1 PG: 40, capped by max 30
    set_log(&mut s, base, 1);
    model.extend(fill(&mut s, 0, 60, "b"));
    s.run_for(500 * MS);
    for (o, l) in lens(&s).into_iter().enumerate() {
        assert!((28..=32).contains(&l), "osd.{o} log len {l} (target 30)");
    }
    // min above max: min wins (classic max(min(t, max), min)), no panic
    set_log(
        &mut s,
        peering::PgLogCfg {
            min_entries: 40,
            max_entries: 5,
            ..base
        },
        1,
    );
    model.extend(fill(&mut s, 0, 60, "c"));
    s.run_for(500 * MS);
    for (o, l) in lens(&s).into_iter().enumerate() {
        assert!((38..=42).contains(&l), "osd.{o} log len {l} (target 40)");
    }
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
}

/// `osd_pg_stat_report_interval_max_epochs`: an unchanged primary PG re-publishes once the map moved more than the
/// bound past its last report, even when the time bound is far away (spec pg-io-stats.md 5).
#[test]
fn unchanged_pg_stats_republish_after_epoch_bound() {
    let mut s = cluster(93, &[0, 1, 2, 3], 1, 3, 2, 1);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    let other = (0..4).find(|o| !s.acting_of(pg.pgid).contains(o)).unwrap();
    for n in s.nodes.values_mut() {
        n.set.set_stats_report(3_600 * 1_000_000_000, 2, 8 << 20);
        n.set.push_cfg_to_pgs();
    }
    s.run_for(1_000 * MS);
    let seq = |s: &Sim| s.pgstats[&pg].1.reported_seq;
    let seq0 = seq(&s);
    // epochs that do not touch the PG (an OSD outside its acting set goes out and in): 1 then 2 epochs: within bound
    s.mark_out(other);
    s.run_for(200 * MS);
    s.mark_in(other);
    s.run_for(200 * MS);
    assert_eq!(
        seq(&s),
        seq0,
        "within the epoch bound and the hour: no re-publish"
    );
    s.mark_out(other);
    s.run_for(200 * MS);
    assert!(
        seq(&s) > seq0,
        "3 epochs past the last report: re-published"
    );
    assert_eq!(s.pgstats[&pg].0, prim);
}

/// A same-primary interval that stalls in peering must replace the mgr's old active+clean report, and keep it fresh.
#[test]
fn inactive_primary_replaces_clean_stats_and_keeps_reporting() {
    let mut s = cluster(193, &[0, 1, 2, 3], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let primary = s.primary_of(pg.pgid);
    let mut acting = s.acting_of(pg.pgid);
    let replacement = (0..4).find(|o| !acting.contains(o)).unwrap();
    assert_ne!(acting[2], primary);
    acting[2] = replacement;
    for peer in 0..4 {
        if peer != primary {
            s.partition(primary, peer);
        }
    }
    let epoch = s.new_epoch(|m| {
        m.up_override.insert(pg.pgid, acting);
        m.pg_temp.remove(&pg.pgid);
    });
    s.run_for(500 * MS);
    let live = s.nodes[&primary].set.pg(pg).unwrap();
    assert!(live.is_primary());
    assert_ne!(live.state_bits() & pgs::PEERING, 0);
    assert!(
        live.next_deadline()
            .is_some_and(|t| t <= s.now + 5_000 * MS),
        "inactive primary must retain its stats refresh deadline"
    );
    let reported = &s.pgstats[&pg];
    assert_eq!(reported.0, primary);
    assert_eq!(reported.1.reported_epoch, epoch);
    assert_ne!(reported.1.state & pgs::PEERING, 0);
    assert_eq!(reported.1.state & (pgs::ACTIVE | pgs::CLEAN), 0);
    let seq = reported.1.reported_seq;
    let last_fresh = reported.1.last_fresh;
    s.run_for(6_000 * MS);
    let reported = &s.pgstats[&pg].1;
    assert!(reported.reported_seq > seq);
    assert!(reported.last_fresh > last_fresh);
    assert_ne!(reported.state & pgs::PEERING, 0);
}

/// A replica is down while the primary trims its log past the replica's last_update: the replica
/// must be backfilled (scan, push, remove stale objects), then the PG goes clean.
#[test]
fn backfill_after_log_trimmed() {
    let mut s = cluster_cfg(31, &[0, 1, 2], 1, 3, 2, 1, small_logs);
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 8, "a");
    let acting = s.acting_of(pg.pgid);
    let victim = acting[2];
    s.kill(victim);
    s.run_for(300 * MS);
    // writes that trim far past the victim's last_update, including deletes of objects it holds
    model.extend(fill(&mut s, 0, 40, "b"));
    let t = s.delete_obj(1, 0, "a0").unwrap();
    model.remove("a0");
    s.wait_writes(&[t], pg);
    s.restart(victim);
    s.run_until(120_000 * MS, "clean after backfill", |s| s.pool_clean(1));
    s.run_for(500 * MS);
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
    s.assert_no_roundtrip_mismatch();
    assert!(
        s.stats.msgs_by_type.get(&94).copied().unwrap_or(0) > 0,
        "scan used: {:?}",
        s.stats.msgs_by_type
    );
    assert!(
        s.stats.msgs_by_type.get(&99).copied().unwrap_or(0) > 0,
        "backfill reservation used"
    );
    let v = s.pg(victim, pg).unwrap();
    assert!(v.info().last_backfill == hobject_max());
    // the end of backfill (Recovered) asks for acting = up itself: no periodic re-check of the acting set
    assert_eq!(s.stats.pg_temp_from_tick, 0, "pg_temp decided by the tick");
}

fn hobject_max() -> denc::types::Hobject {
    denc::types::Hobject::MAX()
}

/// A brand new OSD joins a PG whose log was trimmed: full backfill onto an empty OSD.
#[test]
fn backfill_new_osd() {
    let mut s = Sim::new(32);
    for o in 0..3 {
        s.add_osd_cfg(o, small_logs);
    }
    s.run_for(50 * MS);
    s.create_pool(1, 3, 2, 1);
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let model = fill(&mut s, 0, 50, "n");
    // replace the replica set: add osd.3, mark an old replica out
    s.add_osd_cfg(3, small_logs);
    s.run_for(2000 * MS);
    let pg = spg(1, 0);
    let acting = s.acting_of(pg.pgid);
    let out = acting[1];
    s.mark_out(out);
    s.run_until(120_000 * MS, "clean on new set", |s| s.pool_clean(1));
    s.run_for(500 * MS);
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
    assert!(
        s.acting_of(pg.pgid).contains(&3),
        "osd.3 joined by backfill"
    );
    assert!(s.pg(3, pg).unwrap().info().last_backfill == hobject_max());
    // the stray copy on the out OSD gets purged once the PG is clean
    s.run_until(30_000 * MS, "stray purged", |s| s.pg(out, pg).is_none());
}

#[test]
fn async_recovery_uses_pg_temp() {
    // a replica that is far behind is recovered while not in `acting` (pg_temp), then rejoins
    let mut s = cluster_cfg(33, &[0, 1, 2], 1, 3, 2, 1, |c| {
        small_logs(c);
        c.min_pg_log_entries = 400;
        c.async_recovery_min_cost = 5;
    });
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 5, "a");
    let victim = s.acting_of(pg.pgid)[2];
    s.kill(victim);
    s.run_for(300 * MS);
    model.extend(fill(&mut s, 0, 30, "b"));
    s.restart(victim);
    let mut saw_temp = false;
    let end = s.now + 60_000 * MS;
    while s.now < end && !s.pool_clean(1) {
        s.run_for(5 * MS);
        saw_temp |= s.map().pg_temp.contains_key(&pg.pgid);
    }
    assert!(s.pool_clean(1), "{}", s.dump());
    assert!(
        saw_temp,
        "pg_temp was requested for the async recovery target"
    );
    s.run_for(500 * MS);
    s.assert_replicas_equal(1, 0, &model);
    assert!(s.map().pg_temp.is_empty());
    assert_eq!(s.acting_of(pg.pgid), s.up_of(pg.pgid));
    // the end of recovery (Recovered) takes the async target back itself: no periodic re-check of the acting set
    assert_eq!(s.stats.pg_temp_from_tick, 0, "pg_temp decided by the tick");
}

/// Async recovery of the CRUSH primary itself (peering.md 6.2 step 5: every up member of `want` is a candidate, the
/// primary included): it returns more than `osd_async_recovery_min_cost` writes behind, takes itself out of acting
/// (pg_temp without it), the next member leads and keeps that pg_temp, the end of recovery clears it. A classic primary
/// makes the same choice: an acting primary that never takes the CRUSH primary out clears its pg_temp every epoch
/// (osdmap churn, PG never active; EC sibling: ec_primary.rs `ec_async_recovery_of_the_returning_up_primary`).
#[test]
fn async_recovery_of_the_returning_up_primary() {
    let mut s = cluster_cfg(34, &[0, 1, 2], 1, 3, 2, 1, |c| {
        small_logs(c);
        c.min_pg_log_entries = 400;
        c.async_recovery_min_cost = 5;
        c.recovery_max_active = 1;
    });
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 5, "a");
    let up = s.up_of(pg.pgid);
    let victim = up[0];
    assert_eq!(s.primary_of(pg.pgid), victim);
    s.kill(victim);
    s.run_for(300 * MS);
    model.extend(fill(&mut s, 0, 30, "b"));
    let e0 = s.epoch();
    s.restart(victim);
    let mut temps: Vec<Vec<i32>> = vec![Vec::new()];
    let end = s.now + 60_000 * MS;
    while s.now < end && !s.pool_clean(1) {
        s.run_for(5 * MS);
        let t = s.map().pg_temp.get(&pg.pgid).cloned().unwrap_or_default();
        if temps.last() != Some(&t) {
            temps.push(t);
        }
    }
    assert!(s.pool_clean(1), "{}", s.dump());
    s.run_for(500 * MS);
    assert_eq!(
        temps,
        vec![Vec::new(), up[1..].to_vec(), Vec::new()],
        "pg_temp set once by the returning primary, kept by the acting one, cleared once at Recovered"
    );
    s.assert_replicas_equal(1, 0, &model);
    assert_eq!(s.acting_of(pg.pgid), up);
    assert_eq!(s.stats.pg_temp_from_tick, 0, "pg_temp decided by the tick");
    assert!(
        s.epoch() - e0 <= 10,
        "osdmap churn: {} epochs since the restart",
        s.epoch() - e0
    );
}

#[test]
fn pg_goes_down_when_the_only_writer_is_gone() {
    // size 2 / min_size 1: A and B active; B dies, A writes alone and dies; B returns alone:
    // B must NOT activate (A may hold writes B lacks) until A is back.
    let mut s = cluster(50, &[0, 1], 1, 2, 1, 1);
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 4, "a");
    let acting = s.acting_of(pg.pgid);
    let (a, b) = (acting[0], acting[1]);
    s.kill(b);
    s.run_for(300 * MS);
    model.extend(fill(&mut s, 0, 4, "solo"));
    s.kill(a);
    s.run_for(300 * MS);
    s.restart(b);
    s.run_for(5000 * MS);
    let p = s.pg(b, pg).unwrap();
    assert!(
        p.state_bits() & pgs::DOWN != 0,
        "state {}",
        p.state_string()
    );
    assert!(p.state_bits() & pgs::ACTIVE == 0);
    assert!(
        p.info().last_update.version < 8,
        "b never saw the solo writes"
    );
    assert_eq!(
        s.write_obj(1, 0, "x", b"y"),
        Err(peering::WriteErr::NotActive)
    );
    s.restart(a);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    s.run_for(500 * MS);
    s.assert_replicas_equal(1, 0, &model);
    s.assert_persisted_consistent();
}

#[test]
fn old_primary_lease_delays_new_primary() {
    // after a failover the new primary must wait until the old primary's read lease has expired
    let mut s = cluster(51, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    s.run_for(1000 * MS);
    let old = s.primary_of(pg.pgid);
    s.kill(old);
    s.run_until(20_000 * MS, "new primary active", |s| {
        let p = s.primary_of(pg.pgid);
        p != old
            && s.pg(p, pg)
                .is_some_and(|x| x.state_bits() & pgs::ACTIVE != 0 && x.is_primary())
    });
    let p = s.primary_of(pg.pgid);
    let now = s.now;
    let pgp = s.pg(p, pg).unwrap();
    assert!(
        pgp.state_bits() & pgs::WAIT != 0,
        "WAIT while the old lease may still be valid: {}",
        pgp.state_string()
    );
    assert!(!pgp.is_readable(now));
    // writes are possible (WAIT only blocks reads/ops served under the lease in the op layer)
    s.run_for(20_000 * MS);
    let now = s.now;
    let pgp = s.pg(p, pg).unwrap();
    assert!(pgp.state_bits() & pgs::WAIT == 0, "{}", pgp.state_string());
    assert!(pgp.is_readable(now));
}

#[test]
fn remote_reservations_are_serialized() {
    // many PGs backfill onto one restarted OSD with max_backfills = 1: never more than one at a time
    let mut s = cluster_cfg(52, &[0, 1, 2], 1, 3, 2, 6, small_logs);
    let mut model = std::collections::BTreeMap::new();
    for seed in 0..6u32 {
        let m = fill(&mut s, seed, 4, &format!("p{seed}_"));
        model.insert(seed, m);
    }
    s.kill(2);
    s.run_for(300 * MS);
    for seed in 0..6u32 {
        let m = fill(&mut s, seed, 40, &format!("q{seed}_"));
        model.get_mut(&seed).unwrap().extend(m);
    }
    s.restart(2);
    let mut max_active = 0;
    let end = s.now + 120_000 * MS;
    while s.now < end && !s.pool_clean(1) {
        s.run_for(MS);
        for n in s.nodes.values() {
            let c = n
                .set
                .pgs()
                .filter(|(_, p)| matches!(p.rep_reservation(), peering::RepRes::Recovering { .. }))
                .count();
            max_active = max_active.max(c);
        }
    }
    assert!(s.pool_clean(1), "{}", s.dump());
    assert_eq!(
        max_active, 1,
        "reservation limiter let {max_active} through"
    );
    s.run_for(500 * MS);
    for (seed, m) in model {
        s.assert_replicas_equal(1, seed, &m);
    }
    s.assert_persisted_consistent();
}

#[test]
fn primary_reports_pg_stats() {
    let mut s = cluster(53, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let _model = fill(&mut s, 0, 7, "s");
    s.run_for(6000 * MS);
    let (osd, st) = s.pgstats.get(&pg).cloned().expect("stats published");
    assert_eq!(osd, s.primary_of(pg.pgid));
    assert_eq!(pgwire::state::state_string(st.state), "active+clean");
    assert_eq!(st.stats.sum.num_objects, 7);
    assert_eq!(st.stats.sum.num_objects_degraded, 0);
    assert_eq!(st.stats.sum.num_objects_misplaced, 0);
    assert_eq!(st.version.version, 7);
    assert_eq!(st.up, st.acting);
    assert_eq!(st.log_size, 7);
    assert!(st.reported_seq > 0 && st.reported_epoch > 0);
    assert_eq!(
        st.last_epoch_clean,
        s.pg(osd, pg).unwrap().info().history.last_epoch_clean
    );
    // degraded when a member is gone
    let victim = s.acting_of(pg.pgid)[2];
    s.kill(victim);
    s.run_for(6000 * MS);
    let (_, st) = s.pgstats.get(&pg).cloned().unwrap();
    let name = pgwire::state::state_string(st.state);
    assert!(
        name.contains("undersized") && name.contains("degraded"),
        "{name}"
    );
    assert!(st.stats.sum.num_objects_degraded > 0);
    let moving = st.up.iter().filter(|o| !st.acting.contains(o)).count() as i64;
    assert_eq!(
        st.stats.sum.num_objects_misplaced,
        st.stats.sum.num_objects * moving
    );
}

#[test]
fn pg_num_change_splits_instead_of_refusing() {
    // (split and merge in depth: split_merge.rs)
    let mut s = cluster(54, &[0, 1, 2], 1, 3, 2, 2);
    let pg0 = spg(1, 0);
    let prim = s.primary_of(pg0.pgid);
    let model = fill(&mut s, 0, 3, "r");
    // the mon raises pg_num 2 -> 4: PG 1.0 is a split parent
    s.set_pg_num(1, 4);
    s.run_until(30_000 * MS, "split settled", |s| s.pool_settled(1));
    let p = s.pg(prim, pg0).unwrap();
    assert!(p.refusal().is_none());
    assert!(p.state_bits() & pgs::ACTIVE != 0, "{}", p.state_string());
    // every replica holds every object, spread over the PGs by hash
    for o in s.acting_of(pg0.pgid) {
        let total: usize = (0..4).map(|seed| s.contents(o, 1, seed).len()).sum();
        assert_eq!(total, model.len());
    }
}

#[test]
fn lost_pg_temp_clear_is_resent_with_the_new_mon_session() {
    // the primary asks the mon to clear pg_temp after the async recovery; the request is lost with the mon session (seen live:
    // PGs stuck active+remapped until the primary restarted). Nothing repeats it by time (adr 0023 am. 1): the session that
    // lost it resets, and the new one re-sends every pending request.
    let mut s = cluster_cfg(34, &[0, 1, 2], 1, 3, 2, 1, |c| {
        small_logs(c);
        c.min_pg_log_entries = 400;
        c.async_recovery_min_cost = 5;
    });
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 0, 5, "a");
    let victim = s.acting_of(pg.pgid)[2];
    s.kill(victim);
    s.run_for(300 * MS);
    model.extend(fill(&mut s, 0, 30, "b"));
    s.drop_empty_temp = 1;
    s.restart(victim);
    let end = s.now + 90_000 * MS;
    while s.now < end && s.stats.pg_temp_dropped == 0 {
        s.run_for(50 * MS);
    }
    assert_eq!(
        s.stats.pg_temp_dropped, 1,
        "the clear request was dropped once"
    );
    // the old session is still up in the sim: the request stays pending, nothing sends it again by time
    let sent = s.stats.pg_temp_sent;
    s.run_for(15_000 * MS);
    assert_eq!(s.stats.pg_temp_sent, sent, "no time-based re-send");
    assert!(!s.map().pg_temp.is_empty(), "{}", s.dump());
    assert_ne!(s.acting_of(pg.pgid), s.up_of(pg.pgid));
    let from = s.stats.pg_temp_dropped_from[0];
    s.mon_session(from);
    let end = s.now + 90_000 * MS;
    while s.now < end && !s.pool_clean(1) {
        s.run_for(50 * MS);
    }
    assert_eq!(
        s.stats.pg_temp_sent,
        sent + 1,
        "re-sent once, by the session"
    );
    assert!(s.pool_clean(1), "{}", s.dump());
    s.run_for(500 * MS);
    s.assert_replicas_equal(1, 0, &model);
    assert!(s.map().pg_temp.is_empty());
    assert_eq!(s.acting_of(pg.pgid), s.up_of(pg.pgid));
}

/// Primary PGs of node `n` in a backfill or waiting for remote backfill slots (they hold a local backfill slot).
fn local_bf_holders(n: &Node) -> usize {
    use peering::{ASt, PSt, St};
    n.set
        .pgs()
        .filter(|(_, p)| {
            matches!(
                p.machine_state(),
                St::Primary(PSt::Active(
                    ASt::WaitRemoteBackfillReserved | ASt::Backfilling
                ))
            )
        })
        .count()
}

/// Local (primary side) reservations: with `osd_max_backfills` 1 an OSD never backfills more than one PG it leads at a
/// time, every PG still gets through (with classic stand-ins in either role), and no slot leaks after an interval change
/// (primary killed while it holds one) or when everything is clean.
fn local_reservations_run(seed: u64, classic: &[i32]) {
    let mut s = cluster_cfg(seed, &[0, 1, 2], 1, 3, 2, 8, small_logs);
    s.classic_set(classic);
    let mut model = std::collections::BTreeMap::new();
    for pg in 0..8u32 {
        let m = fill(&mut s, pg, 3, &format!("p{pg}_"));
        model.insert(pg, m);
    }
    s.kill(2);
    s.run_for(300 * MS);
    for pg in 0..8u32 {
        let m = fill(&mut s, pg, 40, &format!("q{pg}_"));
        model.get_mut(&pg).unwrap().extend(m);
    }
    s.restart(2);
    let mut max_holders = 0;
    let mut killed = false;
    let end = s.now + 200_000 * MS;
    while s.now < end && !s.pool_clean(1) {
        s.run_for(MS);
        for n in s.nodes.values() {
            max_holders = max_holders.max(local_bf_holders(n));
        }
        // a primary that holds a local slot dies mid-way: its slot must not leak when it comes back
        if !killed && s.nodes.values().any(|n| local_bf_holders(n) > 0) {
            let p = *s
                .nodes
                .iter()
                .find(|(_, n)| local_bf_holders(n) > 0)
                .unwrap()
                .0;
            if p != 2 {
                killed = true;
                s.kill(p);
                s.run_for(50 * MS);
                s.restart(p);
            }
        }
    }
    assert!(s.pool_clean(1), "{}", s.dump());
    assert_eq!(max_holders, 1, "local reserver let {max_holders} through");
    assert!(killed, "no primary was killed while holding a slot");
    s.run_for(2_000 * MS);
    for n in s.nodes.values() {
        assert_eq!(n.set.local_slots(), (0, 0), "local slot leaked");
    }
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
    for (pg, m) in model {
        s.assert_replicas_equal(1, pg, &m);
    }
    s.assert_persisted_consistent();
}

#[test]
fn local_reservations_bound_backfills_flashstore_only() {
    local_reservations_run(61, &[]);
}

#[test]
fn local_reservations_with_classic_peers() {
    local_reservations_run(62, &[0]);
    local_reservations_run(63, &[1, 2]);
}

/// Client io noted on the primary (counter-only, no re-sync) reaches the next periodic PG stats publish with a newer
/// `reported_seq`, so the mgr takes it (spec pg-io-stats.md 3).
#[test]
fn client_io_reaches_the_periodic_pg_stats() {
    let mut s = cluster(91, &[0, 1, 2], 1, 3, 2, 1);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    let seq0 = s.pgstats[&pg].1.reported_seq;
    let io = pgwire::IoCount {
        rd: 3,
        rd_kb: 5,
        wr: 2,
        wr_kb: 9,
    };
    s.nodes.get_mut(&prim).unwrap().set.note_io(pg, &io);
    s.nodes.get_mut(&prim).unwrap().set.note_io(pg, &io);
    let iv = s.nodes[&prim].cfg.stats_interval;
    s.run_for(iv + 100 * MS);
    let (from, st) = &s.pgstats[&pg];
    assert_eq!(*from, prim);
    assert!(st.reported_seq > seq0, "a newer publish");
    let sum = &st.stats.sum;
    assert_eq!(
        (
            sum.num_read,
            sum.num_read_kb,
            sum.num_write,
            sum.num_write_kb
        ),
        (6, 10, 4, 18)
    );
}

/// `dump_pg_recovery_stats` feed: a replica that restarts and recovers by log makes the primary walk
/// Peering -> Active/Activating -> WaitLocal/WaitRemoteRecoveryReserved -> Recovering -> Recovered -> Clean, every
/// visit timed; leaving the interval exits the nested states bottom up.
#[test]
fn recovery_walks_are_timed_per_state() {
    let mut s = cluster(15, &[0, 1, 2], 1, 3, 2, 1);
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    let _ = fill(&mut s, 0, 10, "a");
    let rows = |s: &Sim, o: i32| -> BTreeMap<&'static str, peering::recstats::StateRow> {
        s.nodes[&o]
            .set
            .rec_stats()
            .rows()
            .map(|(n, r)| (n, *r))
            .collect()
    };
    let before = rows(&s, prim);
    assert_eq!(before["Started/Primary/Active/Clean"].enter, 1);
    assert_eq!(
        before["Started/Primary/Active/Clean"].exit, 0,
        "still in it"
    );
    assert!(before["Started/Primary/Peering/GetInfo"].exit >= 1);
    let victim = s.acting_of(pg.pgid)[2];
    s.kill(victim);
    s.run_for(500 * MS);
    let _ = fill(&mut s, 0, 15, "b");
    s.restart(victim);
    s.run_until(60_000 * MS, "clean again", |s| s.pool_clean(1));
    s.run_for(300 * MS);
    let after = rows(&s, prim);
    let get = |n: &str| after.get(n).copied().unwrap_or_default();
    for st in [
        "Started/Primary/Active/WaitLocalRecoveryReserved",
        "Started/Primary/Active/WaitRemoteRecoveryReserved",
        "Started/Primary/Active/Recovering",
    ] {
        let r = get(st);
        assert!(r.enter >= 1 && r.exit >= 1, "{st}: {r:?}");
        assert!(
            r.min_ns <= r.max_ns && r.total_ns >= r.max_ns,
            "{st}: {r:?}"
        );
    }
    let clean = get("Started/Primary/Active/Clean");
    assert!(
        clean.enter >= 2 && clean.exit >= 1,
        "left Clean when the replica died: {clean:?}"
    );
    assert_eq!(clean.enter, clean.exit + 1, "in Clean again now: {clean:?}");
    // the nested parents were not left by the leaf moves inside Active
    let active = get("Started/Primary/Active");
    assert!(active.enter - active.exit <= 1);
    // a state only the replicas know never shows on the primary
    assert!(!after.contains_key("Started/ReplicaActive") && !after.contains_key("Started/Stray"));
    let replica = rows(&s, victim);
    assert!(replica["Started/ReplicaActive"].enter >= 1, "{replica:?}");
    // reset clears; transitions after it count from zero
    s.nodes.get_mut(&prim).unwrap().set.reset_rec_stats();
    assert!(rows(&s, prim).is_empty());
}
