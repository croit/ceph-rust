// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! A damaged local object is "missing locally" (adr 0065, oq 10): the primary pulls it from a healthy peer, a replica
//! marks it missing and the primary pushes it after the next peering, all copies damaged = unfound (no data is
//! invented), classic stand-in peers see nothing they would abort on.
mod common;
use common::*;
use denc::types::Eversion;

const POOL: u64 = 1;

fn small_logs(c: &mut peering::Config) {
    c.min_pg_log_entries = 10;
    c.pg_log_trim_min = 1;
    c.pg_log_trim_max = 50;
    c.log_dups_tracked = 20;
}

/// object_info of `name` on `osd` becomes undecodable.
fn damage(s: &mut Sim, osd: i32, name: &str) {
    s.nodes
        .get_mut(&osd)
        .unwrap()
        .store
        .pgs
        .get_mut(&spg(POOL, 0))
        .unwrap()
        .objects
        .get_mut(&hobj(POOL, name))
        .unwrap()
        .xattrs
        .insert(b"_".to_vec(), vec![0xff; 3]);
}

fn raw_oi(s: &Sim, osd: i32, name: &str) -> Vec<u8> {
    s.nodes[&osd].store.objects(spg(POOL, 0))[&hobj(POOL, name)]
        .xattrs
        .get(b"_".as_slice())
        .cloned()
        .unwrap_or_default()
}

fn healthy(s: &Sim, osd: i32, name: &str, data: &[u8]) -> bool {
    let o = &s.nodes[&osd].store.objects(spg(POOL, 0));
    o.get(&hobj(POOL, name)).is_some_and(|o| {
        o.data == data
            && o.xattrs
                .get(b"_".as_slice())
                .is_some_and(|b| denc::from_slice::<replwire::ObjectInfo>(b).is_ok())
    })
}

/// What the op engine does on an EIO of `name` at the primary: `Some(parked)`.
fn hit(s: &mut Sim, osd: i32, name: &str, known: Option<Eversion>) -> bool {
    let (spg_, h) = (spg(POOL, 0), hobj(POOL, name));
    let mut r = false;
    s.call(osd, |set, now, store| {
        let (b, acts) = set
            .with_pg(now, spg_, store, |pg| pg.local_damage(&h, known))
            .expect("pg");
        r = b;
        acts
    });
    r
}

fn setup(seed: u64, trim: bool) -> (Sim, i32, Vec<i32>) {
    let mut s = if trim {
        cluster_cfg(seed, &[0, 1, 2], POOL, 3, 2, 1, small_logs)
    } else {
        cluster(seed, &[0, 1, 2], POOL, 3, 2, 1)
    };
    let pg = spg(POOL, 0);
    let mut t = vec![
        s.write_obj(POOL, 0, "x", b"payload-x").unwrap(),
        s.write_obj(POOL, 0, "y", b"payload-y").unwrap(),
    ];
    if trim {
        // push "x" out of the log window: its version can only come from a peer
        for i in 0..60 {
            t.push(s.write_obj(POOL, 0, &format!("f{i}"), b"f").unwrap());
            s.run_for(MS);
        }
    }
    s.wait_writes(&t, pg);
    s.run_for(2_000 * MS);
    let prim = s.primary_of(pg.pgid);
    let reps = s
        .acting_of(pg.pgid)
        .into_iter()
        .filter(|o| *o != prim)
        .collect();
    (s, prim, reps)
}

#[test]
fn primary_damage_is_pulled_from_a_peer() {
    let (mut s, prim, _) = setup(201, false);
    let pg = spg(POOL, 0);
    damage(&mut s, prim, "x");
    assert!(!healthy(&s, prim, "x", b"payload-x"));
    assert!(hit(&mut s, prim, "x", None), "op must wait for the repair");
    let n = s.nodes.get_mut(&prim).unwrap().set.take_notices();
    assert!(
        n.iter().any(|m| m.starts_with("ERROR ")
            && m.contains("missing primary copy of x, will try copies on osd.")),
        "classic-like cluster log line: {n:?}"
    );
    assert!(s.pg(prim, pg).unwrap().missing().contains(&hobj(POOL, "x")));
    assert!(s.pg(prim, pg).unwrap().read_blocked(&hobj(POOL, "x")));
    // idempotent: a second op on the same object just waits
    assert!(hit(&mut s, prim, "x", None));
    s.run_until(60_000 * MS, "repaired", |s| {
        healthy(s, prim, "x", b"payload-x") && s.pool_clean(POOL)
    });
    let p = s.pg(prim, pg).unwrap();
    assert!(p.missing().is_empty());
    assert!(!p.read_blocked(&hobj(POOL, "x")));
    assert_eq!(p.shards_repaired(), 1);
    assert!(healthy(&s, prim, "y", b"payload-y"));
    s.assert_persisted_consistent();
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
}

/// The damaged object is older than the log window and its own object_info is gone: no version is known, the pull
/// carries 0'0 and the peer answers with its own version (classic does the same).
#[test]
fn damage_of_an_object_older_than_the_log_uses_the_peers_version() {
    let (mut s, prim, _) = setup(202, true);
    let pg = spg(POOL, 0);
    assert!(
        s.pg(prim, pg)
            .unwrap()
            .log()
            .entry_for(&hobj(POOL, "x"))
            .is_none(),
        "x is out of the log"
    );
    damage(&mut s, prim, "x");
    assert!(hit(&mut s, prim, "x", None));
    s.run_until(60_000 * MS, "repaired", |s| {
        healthy(s, prim, "x", b"payload-x") && s.pool_clean(POOL)
    });
    let v: Vec<Vec<u8>> = [0, 1, 2].iter().map(|o| raw_oi(&s, *o, "x")).collect();
    assert!(v.iter().all(|b| *b == v[0]), "same object_info everywhere");
    assert_eq!(s.pg(prim, pg).unwrap().shards_repaired(), 1);
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
}

/// The replica we pull from is damaged too: it answers "not here", marks the object missing itself, the primary
/// takes the third copy; after the next peering the primary pushes the object to the damaged replica.
#[test]
fn damaged_replica_is_pushed_by_the_primary() {
    let (mut s, prim, reps) = setup(203, false);
    let pg = spg(POOL, 0);
    let b = reps[0]; // first pull source
    damage(&mut s, prim, "x");
    damage(&mut s, b, "x");
    assert!(hit(&mut s, prim, "x", None));
    s.run_until(60_000 * MS, "primary repaired", |s| {
        healthy(s, prim, "x", b"payload-x")
    });
    s.run_for(2_000 * MS);
    assert!(
        s.pg(b, pg).unwrap().missing().contains(&hobj(POOL, "x")),
        "the damaged replica remembers it as missing"
    );
    // the primary learns of the replica's missing set at the next peering and pushes
    s.kill(b);
    s.run_for(1_000 * MS);
    s.restart(b);
    s.run_until(120_000 * MS, "replica repaired", |s| {
        healthy(s, b, "x", b"payload-x") && s.pool_clean(POOL)
    });
    assert!(s.pg(b, pg).unwrap().missing().is_empty());
    s.assert_persisted_consistent();
}

/// Every copy is damaged: the object is unfound, nothing is invented and the op keeps waiting (no EIO, no crash).
#[test]
fn all_copies_damaged_is_unfound() {
    let (mut s, prim, reps) = setup(204, false);
    let pg = spg(POOL, 0);
    for o in [prim, reps[0], reps[1]] {
        damage(&mut s, o, "x");
    }
    assert!(hit(&mut s, prim, "x", None));
    s.run_for(30_000 * MS);
    let p = s.pg(prim, pg).unwrap();
    assert!(p.missing().contains(&hobj(POOL, "x")), "still missing");
    assert!(p.state_string().contains("unfound"), "{}", p.state_string());
    assert!(p.read_blocked(&hobj(POOL, "x")));
    assert_eq!(raw_oi(&s, prim, "x"), vec![0xff; 3], "no data invented");
    assert_eq!(p.shards_repaired(), 0);
    // y is untouched and serves
    assert!(healthy(&s, prim, "y", b"payload-y"));
}

/// Replicas are classic stand-ins: the pull (version 0'0 included) and the push never violate the peer model.
#[test]
fn classic_replicas_serve_the_repair() {
    let (mut s, prim, reps) = setup(205, true);
    s.classic_set(&reps);
    s.run_for(1_000 * MS);
    damage(&mut s, prim, "x");
    assert!(hit(&mut s, prim, "x", None));
    s.run_until(60_000 * MS, "repaired", |s| {
        healthy(s, prim, "x", b"payload-x") && s.pool_clean(POOL)
    });
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
}

/// Damage found while a backfill runs: the backfill stops, our object is pulled first, the backfill resumes.
#[test]
fn damage_during_backfill_is_repaired_first() {
    let mut s = cluster_cfg(206, &[0, 1, 2], POOL, 3, 2, 1, small_logs);
    let pg = spg(POOL, 0);
    let mut t = vec![s.write_obj(POOL, 0, "x", b"payload-x").unwrap()];
    for i in 0..8 {
        t.push(s.write_obj(POOL, 0, &format!("a{i}"), b"a").unwrap());
    }
    s.wait_writes(&t, pg);
    s.run_for(1_000 * MS);
    let prim = s.primary_of(pg.pgid);
    let victim = *s.acting_of(pg.pgid).last().unwrap();
    s.kill(victim);
    s.run_for(300 * MS);
    let mut t = vec![];
    for i in 0..40 {
        t.push(s.write_obj(POOL, 0, &format!("b{i}"), b"b").unwrap());
        s.run_for(MS / 2);
    }
    s.wait_writes(&t, pg);
    damage(&mut s, prim, "x");
    s.restart(victim);
    s.run_until(240_000 * MS, "everything repaired and clean", |s| {
        healthy(s, prim, "x", b"payload-x")
            && healthy(s, victim, "x", b"payload-x")
            && s.pool_clean(POOL)
    });
    let p = s.pg(prim, pg).unwrap();
    assert!(p.missing().is_empty());
    assert_eq!(p.shards_repaired(), 1, "found by the backfill scan");
    s.assert_persisted_consistent();
}

/// The scrub's SnapMapper check no longer degrades silently when it cannot read: error counter + operator note.
#[test]
fn snapmap_check_read_failure_is_counted() {
    let (mut s, prim, _) = setup(207, false);
    let pg = spg(POOL, 0);
    s.nodes.get_mut(&prim).unwrap().store.snapmap_error = true;
    s.call(prim, |set, now, st| {
        set.request_scrub(now, pg, true, false, st)
    });
    s.run_until(60_000 * MS, "scrub finished", |s| {
        let p = s.pg(prim, pg).unwrap();
        p.scrub_counts().0 >= 1 && !p.scrub_running() && p.is_clean()
    });
    let p = s.pg(prim, pg).unwrap();
    assert!(
        p.counters()
            .errors
            .keys()
            .any(|k| k.contains("snapmap check")),
        "{:?}",
        p.counters().errors
    );
    let n = s.nodes.get_mut(&prim).unwrap().set.take_notices();
    assert!(
        n.iter()
            .any(|m| m.starts_with("ERROR ") && m.contains("snapmap check incomplete")),
        "cluster log line: {n:?}"
    );
}

/// The primary crashes right after it marked its damaged copy missing: the mark is durable, so the restarted primary
/// still repairs it (never serves or keeps the damaged copy as if it were good). Both a version from the log and an
/// unknown version (object older than the log: need 0'1 through peering) are covered.
#[test]
fn crash_after_the_mark_still_repairs() {
    for (seed, trim) in [(208, false), (209, true)] {
        let (mut s, prim, _) = setup(seed, trim);
        let pg = spg(POOL, 0);
        damage(&mut s, prim, "x");
        assert!(hit(&mut s, prim, "x", None));
        s.run_for(MS); // the mark is durable (store commit), the pull is not done yet
        assert!(!healthy(&s, prim, "x", b"payload-x"));
        s.kill(prim);
        assert!(!healthy(&s, prim, "x", b"payload-x"));
        s.run_for(2_000 * MS);
        s.restart(prim);
        s.run_until(120_000 * MS, "repaired after the restart", |s| {
            healthy(s, prim, "x", b"payload-x") && s.pool_clean(POOL)
        });
        assert!(s.pg(prim, pg).unwrap().missing().is_empty(), "seed {seed}");
        let v: Vec<Vec<u8>> = [0, 1, 2].iter().map(|o| raw_oi(&s, *o, "x")).collect();
        assert!(
            v.iter().all(|b| *b == v[0]),
            "seed {seed}: same object_info everywhere"
        );
        s.assert_persisted_consistent();
    }
}

/// A damaged replica copy of an object older than the log (need 0'1 in the replica's missing set) is pushed by the
/// primary after the next peering.
#[test]
fn damaged_replica_older_than_the_log_is_pushed() {
    let (mut s, prim, reps) = setup(210, true);
    let pg = spg(POOL, 0);
    let b = reps[0];
    damage(&mut s, prim, "x");
    damage(&mut s, b, "x");
    assert!(hit(&mut s, prim, "x", None));
    s.run_until(60_000 * MS, "primary repaired", |s| {
        healthy(s, prim, "x", b"payload-x")
    });
    s.run_for(2_000 * MS);
    assert!(s.pg(b, pg).unwrap().missing().contains(&hobj(POOL, "x")));
    s.kill(b);
    s.run_for(1_000 * MS);
    s.restart(b);
    s.run_until(120_000 * MS, "replica repaired", |s| {
        healthy(s, b, "x", b"payload-x") && s.pool_clean(POOL)
    });
    s.assert_persisted_consistent();
}

/// Damage found while the backfill is held by `nobackfill`: the repair (recovery) is not a backfill and must not wait
/// for the flag; the backfill resumes once the flag is cleared.
#[test]
fn damage_while_backfill_is_held_is_repaired() {
    let mut s = cluster_cfg(211, &[0, 1, 2], POOL, 3, 2, 1, small_logs);
    let pg = spg(POOL, 0);
    let mut t = vec![s.write_obj(POOL, 0, "x", b"payload-x").unwrap()];
    for i in 0..8 {
        t.push(s.write_obj(POOL, 0, &format!("a{i}"), b"a").unwrap());
    }
    s.wait_writes(&t, pg);
    s.run_for(1_000 * MS);
    let prim = s.primary_of(pg.pgid);
    let victim = *s.acting_of(pg.pgid).last().unwrap();
    s.kill(victim);
    s.run_for(300 * MS);
    let mut t = vec![];
    for i in 0..40 {
        t.push(s.write_obj(POOL, 0, &format!("b{i}"), b"b").unwrap());
        s.run_for(MS / 2);
    }
    s.wait_writes(&t, pg);
    s.new_epoch(|m| m.rb.nobackfill = true);
    s.restart(victim);
    s.run_until(60_000 * MS, "backfill held", |s| {
        s.pg(prim, pg)
            .is_some_and(|p| p.state_string().contains("backfill_wait"))
    });
    damage(&mut s, prim, "x");
    assert!(hit(&mut s, prim, "x", None));
    s.run_until(60_000 * MS, "repaired while nobackfill is set", |s| {
        healthy(s, prim, "x", b"payload-x")
    });
    assert!(!s.pg(prim, pg).unwrap().read_blocked(&hobj(POOL, "x")));
    s.new_epoch(|m| m.rb.nobackfill = false);
    s.run_until(240_000 * MS, "clean after the flag", |s| {
        healthy(s, victim, "x", b"payload-x") && s.pool_clean(POOL)
    });
    s.assert_persisted_consistent();
}

fn data_of(s: &Sim, osd: i32, name: &str) -> Option<Vec<u8>> {
    s.nodes[&osd]
        .store
        .objects(spg(POOL, 0))
        .get(&hobj(POOL, name))
        .map(|o| o.data.clone())
}

/// Version unknown (damaged object older than the log, every acting copy damaged): a stray that comes back with an
/// OLDER copy (it was out while the object was rewritten) must not serve the 0'0 pull, that would roll the object back.
/// The object stays unfound, nothing old is taken for current.
#[test]
fn unknown_version_is_never_pulled_from_a_stale_stray() {
    let mut s = cluster_cfg(212, &[0, 1, 2, 3], POOL, 3, 2, 1, small_logs);
    let pg = spg(POOL, 0);
    let t = s.write_obj(POOL, 0, "x", b"payload-OLD").unwrap();
    s.wait_writes(&[t], pg);
    s.run_for(1_000 * MS);
    let prim = s.primary_of(pg.pgid);
    let stale = *s.acting_of(pg.pgid).iter().find(|o| **o != prim).unwrap();
    s.kill(stale);
    s.mark_out(stale);
    s.run_until(120_000 * MS, "clean without the stale osd", |s| {
        s.pool_clean(POOL)
    });
    let mut t = vec![s.write_obj(POOL, 0, "x", b"payload-NEW").unwrap()];
    for i in 0..60 {
        t.push(s.write_obj(POOL, 0, &format!("f{i}"), b"f").unwrap());
        s.run_for(MS);
    }
    s.wait_writes(&t, pg);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(POOL));
    let prim = s.primary_of(pg.pgid);
    assert!(
        s.pg(prim, pg)
            .unwrap()
            .log()
            .entry_for(&hobj(POOL, "x"))
            .is_none(),
        "x is out of the log"
    );
    for o in s.acting_of(pg.pgid) {
        damage(&mut s, o, "x");
    }
    assert!(hit(&mut s, prim, "x", None));
    s.run_for(5_000 * MS);
    // the stale copy comes back as a stray
    assert_eq!(
        data_of(&s, stale, "x").as_deref(),
        Some(b"payload-OLD".as_slice())
    );
    s.restart(stale);
    s.run_for(20_000 * MS);
    let d = data_of(&s, prim, "x");
    assert_ne!(
        d.as_deref(),
        Some(b"payload-OLD".as_slice()),
        "rolled back to the stray's older copy"
    );
    let p = s.pg(prim, pg).unwrap();
    assert!(
        p.missing().contains(&hobj(POOL, "x")),
        "still missing (unfound)"
    );
}
