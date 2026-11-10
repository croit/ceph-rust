// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Recovery / backfill gating by osdmap flags and refused / revoked reservations (spec peering.md 4.4, 9.4).
mod common;
use common::*;
use peering::Body;
use replwire::{MBackfillReserve, MRecoveryReserve, ReplMsg};

fn small_logs(c: &mut peering::Config) {
    c.min_pg_log_entries = 10;
    c.pg_log_trim_min = 1;
    c.pg_log_trim_max = 50;
    c.log_dups_tracked = 20;
}

fn payload(i: usize) -> Vec<u8> {
    (0..100 + i)
        .map(|j| ((i * 131 + j * 7) % 251) as u8)
        .collect()
}

fn fill(s: &mut Sim, n: usize, tag: &str) {
    let mut tids = vec![];
    for i in 0..n {
        tids.push(
            s.write_obj(1, 0, &format!("{tag}{i}"), &payload(i))
                .unwrap(),
        );
        s.run_for(MS / 2);
    }
    s.wait_writes(&tids, spg(1, 0));
}

fn msgs(s: &Sim, ty: u16) -> u64 {
    s.stats.msgs_by_type.get(&ty).copied().unwrap_or(0)
}

fn prim_state(s: &Sim) -> String {
    let p = s.primary_of(spg(1, 0).pgid);
    s.pg(p, spg(1, 0)).unwrap().state_string()
}

/// victim misses many trimmed writes -> needs backfill when it returns
fn backfill_setup(seed: u64) -> (Sim, i32) {
    let mut s = cluster_cfg(seed, &[0, 1, 2], 1, 3, 2, 1, small_logs);
    fill(&mut s, 8, "a");
    let victim = s.acting_of(spg(1, 0).pgid)[2];
    s.kill(victim);
    s.run_for(300 * MS);
    fill(&mut s, 40, "b");
    (s, victim)
}

#[test]
fn nobackfill_holds_backfill_until_cleared() {
    let (mut s, victim) = backfill_setup(71);
    s.new_epoch(|m| m.rb.nobackfill = true);
    s.restart(victim);
    s.run_for(10_000 * MS);
    assert!(
        prim_state(&s).contains("backfill_wait"),
        "{}",
        prim_state(&s)
    );
    assert!(!prim_state(&s).contains("clean"));
    assert_eq!(
        msgs(&s, 99),
        0,
        "no backfill reservation traffic while held"
    );
    s.new_epoch(|m| m.rb.nobackfill = false);
    s.run_until(60_000 * MS, "clean after flag cleared", |s| s.pool_clean(1));
    assert!(msgs(&s, 99) > 0);
}

#[test]
fn norecover_holds_recovery_and_backfill() {
    // log-based recovery
    let mut s = cluster(72, &[0, 1, 2], 1, 3, 2, 1);
    fill(&mut s, 5, "a");
    let victim = s.acting_of(spg(1, 0).pgid)[2];
    s.kill(victim);
    s.run_for(300 * MS);
    fill(&mut s, 5, "b");
    s.new_epoch(|m| m.rb.norecover = true);
    s.restart(victim);
    s.run_for(10_000 * MS);
    assert!(
        prim_state(&s).contains("recovery_wait"),
        "{}",
        prim_state(&s)
    );
    assert_eq!(msgs(&s, 150), 0);
    s.new_epoch(|m| m.rb.norecover = false);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    // backfill is held by norecover too
    let (mut s, victim) = backfill_setup(73);
    s.new_epoch(|m| m.rb.norecover = true);
    s.restart(victim);
    s.run_for(10_000 * MS);
    assert!(
        prim_state(&s).contains("backfill_wait"),
        "{}",
        prim_state(&s)
    );
    assert_eq!(msgs(&s, 99), 0);
    s.new_epoch(|m| m.rb.norecover = false);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
}

#[test]
fn norebalance_holds_only_non_degraded_backfill() {
    let mut s = Sim::new(74);
    for o in 0..3 {
        s.add_osd_cfg(o, small_logs);
    }
    s.run_for(50 * MS);
    s.create_pool(1, 3, 2, 1);
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    fill(&mut s, 50, "n");
    s.new_epoch(|m| m.rb.norebalance = true);
    s.add_osd_cfg(3, small_logs);
    s.run_for(2000 * MS);
    let out = s.acting_of(spg(1, 0).pgid)[1];
    s.mark_out(out); // pure data movement: every acting member keeps all copies
    s.run_for(10_000 * MS);
    assert_eq!(
        msgs(&s, 99),
        0,
        "misplaced-only backfill held: {}",
        prim_state(&s)
    );
    s.new_epoch(|m| m.rb.norebalance = false);
    s.run_until(120_000 * MS, "clean on new set", |s| s.pool_clean(1));
    assert!(msgs(&s, 99) > 0);
}

fn bf_reserve(s: &Sim, ty: u32) -> Body {
    let e = s.epoch();
    Body::Repl(ReplMsg::BackfillReserve(MBackfillReserve {
        pgid: spg(1, 0),
        query_epoch: e,
        ty,
        priority: 0,
        primary_num_bytes: 0,
        shard_num_bytes: 0,
    }))
}

/// Wait until the primary has asked for the slot, hold the replica's answer back (grant never arrives).
fn stall_reservation(s: &mut Sim, victim: i32) -> i32 {
    let prim = s.primary_of(spg(1, 0).pgid);
    s.run_until(60_000 * MS, "backfill reservation requested", |s| {
        s.pg(prim, spg(1, 0))
            .is_some_and(|p| p.state_string().contains("backfill_wait"))
    });
    s.blocked.insert((victim, prim));
    prim
}

#[test]
fn backfill_reject_toofull_shows_state_and_retries() {
    let (mut s, victim) = backfill_setup(75);
    s.restart(victim);
    let prim = stall_reservation(&mut s, victim);
    let m = bf_reserve(&s, MBackfillReserve::REJECT_TOOFULL);
    s.inject(victim, prim, m);
    s.run_for(1000 * MS);
    let st = prim_state(&s);
    assert!(st.contains("backfill_toofull"), "{st}");
    assert!(!st.contains("backfilling") && !st.contains("clean"), "{st}");
    assert_eq!(
        s.pg(prim, spg(1, 0))
            .unwrap()
            .refused_full()
            .map(|(o, _)| o),
        Some(victim),
        "the refusing target OSD is recorded and exposed"
    );
    // the stale grant the replica may still send must not restart anything; retry only after the interval
    s.heal();
    s.run_for(15_000 * MS);
    assert!(
        prim_state(&s).contains("backfill_toofull"),
        "{}",
        prim_state(&s)
    );
    s.run_until(120_000 * MS, "retry completes backfill", |s| {
        s.pool_clean(1)
    });
    assert_eq!(
        s.pg(prim, spg(1, 0)).unwrap().refused_full(),
        None,
        "cleared once the reservation succeeds"
    );
}

#[test]
fn backfill_revoke_requeues_at_once() {
    let (mut s, victim) = backfill_setup(76);
    s.restart(victim);
    let prim = s.primary_of(spg(1, 0).pgid);
    s.run_until(60_000 * MS, "backfilling", |s| {
        s.pg(prim, spg(1, 0))
            .is_some_and(|p| p.state_string().contains("backfilling"))
    });
    let before = msgs(&s, 99);
    let m = bf_reserve(&s, MBackfillReserve::REVOKE);
    s.inject(victim, prim, m);
    s.run_for(200 * MS);
    assert!(msgs(&s, 99) > before, "release + new request sent");
    s.run_until(120_000 * MS, "clean", |s| s.pool_clean(1));
}

#[test]
fn recovery_revoke_requeues() {
    let mut s = cluster(77, &[0, 1, 2], 1, 3, 2, 1);
    fill(&mut s, 5, "a");
    let victim = s.acting_of(spg(1, 0).pgid)[2];
    s.kill(victim);
    s.run_for(300 * MS);
    fill(&mut s, 30, "b");
    s.restart(victim);
    let prim = s.primary_of(spg(1, 0).pgid);
    s.run_until(60_000 * MS, "recovery reserved", |s| {
        s.pg(prim, spg(1, 0))
            .is_some_and(|p| p.state_string().contains("recover"))
    });
    let before = msgs(&s, 150);
    let e = s.epoch();
    s.inject(
        victim,
        prim,
        Body::Repl(ReplMsg::RecoveryReserve(MRecoveryReserve {
            pgid: spg(1, 0),
            query_epoch: e,
            ty: MRecoveryReserve::REVOKE,
            priority: 0,
        })),
    );
    s.run_for(300 * MS);
    assert!(msgs(&s, 150) > before);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
}

#[test]
fn nobackfill_set_mid_backfill_releases_reservations_and_resumes() {
    let (mut s, victim) = backfill_setup(77);
    s.restart(victim);
    s.run_until(60_000 * MS, "backfilling", |s| {
        prim_state(s).contains("backfilling")
    });
    s.capture = true;
    s.new_epoch(|m| m.rb.nobackfill = true);
    s.run_for(2_000 * MS);
    let n = s
        .captured
        .iter()
        .filter(|(_, _, b)| {
            matches!(b, Body::Repl(ReplMsg::BackfillReserve(m)) if m.ty == MBackfillReserve::RELEASE)
        })
        .count();
    assert!(n > 0, "remote reservation released when the flag is set");
    assert!(
        prim_state(&s).contains("backfill_wait"),
        "{}",
        prim_state(&s)
    );
    s.new_epoch(|m| m.rb.nobackfill = false);
    s.run_until(60_000 * MS, "clean after flag cleared", |s| s.pool_clean(1));
}

#[test]
fn pauserec_holds_backfill() {
    let (mut s, victim) = backfill_setup(78);
    s.new_epoch(|m| m.rb.pauserec = true);
    s.restart(victim);
    s.run_for(10_000 * MS);
    assert!(
        prim_state(&s).contains("backfill_wait"),
        "{}",
        prim_state(&s)
    );
    assert_eq!(msgs(&s, 99), 0);
    s.new_epoch(|m| m.rb.pauserec = false);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
}

/// Revoked while pushes are in flight: the replies arrive while the PG waits for the new slot and are dropped.
/// The abandoned in-flight records must go with the reservation, else Recovering waits for them forever.
#[test]
fn recovery_revoke_with_pushes_in_flight_does_not_stall() {
    for seed in 90..96 {
        let mut s = cluster(seed, &[0, 1, 2], 1, 3, 2, 1);
        fill(&mut s, 5, "a");
        let victim = s.acting_of(spg(1, 0).pgid)[2];
        s.kill(victim);
        s.run_for(300 * MS);
        fill(&mut s, 60, "b");
        s.restart(victim);
        let prim = s.primary_of(spg(1, 0).pgid);
        s.run_until(60_000 * MS, "recovering", |s| {
            s.pg(prim, spg(1, 0))
                .is_some_and(|p| p.state_string().contains("recovering"))
        });
        let e = s.epoch();
        s.inject(
            victim,
            prim,
            Body::Repl(ReplMsg::RecoveryReserve(MRecoveryReserve {
                pgid: spg(1, 0),
                query_epoch: e,
                ty: MRecoveryReserve::REVOKE,
                priority: 0,
            })),
        );
        s.run_until(60_000 * MS, "clean after revoke", |s| s.pool_clean(1));
    }
}

/// A classic replica aborts on a RELEASE (or a second REQUEST) while its slot is requested but not yet granted
/// (RecoveryDone / RequestRecoveryPrio are unhandled in RepWaitRecoveryReserved). Flags set and cleared at every
/// point of a recovery must never put a RELEASE or REQUEST between a REQUEST and its GRANT.
#[test]
fn no_release_or_request_while_recovery_request_ungranted() {
    for seed in 120..128u64 {
        for delay in [0u64, 1, 2, 3, 5, 8, 13, 21] {
            let mut s = cluster(seed, &[0, 1, 2], 1, 3, 2, 1);
            fill(&mut s, 5, "a");
            let victim = s.acting_of(spg(1, 0).pgid)[2];
            s.kill(victim);
            s.run_for(300 * MS);
            fill(&mut s, 60, "b");
            s.capture = true;
            s.restart(victim);
            s.run_for(delay * MS);
            s.new_epoch(|m| m.rb.norecover = true);
            s.run_for(delay * MS + 50 * MS);
            s.new_epoch(|m| m.rb.norecover = false);
            s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
            let mut pending = std::collections::BTreeSet::new();
            for (from, to, b) in &s.captured {
                let Body::Repl(ReplMsg::RecoveryReserve(m)) = b else {
                    continue;
                };
                match m.ty {
                    MRecoveryReserve::REQUEST => {
                        assert!(
                            pending.insert((*from, *to)),
                            "seed {seed} delay {delay}: 2nd REQUEST {from}->{to} before GRANT"
                        );
                    }
                    MRecoveryReserve::GRANT => {
                        pending.remove(&(*to, *from));
                    }
                    MRecoveryReserve::RELEASE => assert!(
                        !pending.contains(&(*from, *to)),
                        "seed {seed} delay {delay}: RELEASE {from}->{to} before GRANT"
                    ),
                    _ => {}
                }
            }
        }
    }
}

/// A stale RECOVERY grant (late duplicate of an earlier round) from a peer that now holds our BACKFILL slot must not
/// be answered with a recovery RELEASE: the replica frees whatever slot it holds (classic RRC: RecoveryDone ->
/// RepNotRecovering), the backfill would run on without a reservation. croit-flashstore-osd peers only (a classic primary aborts on the
/// stale GRANT itself).
#[test]
fn stale_recovery_grant_does_not_release_a_held_backfill_slot() {
    let (mut s, victim) = backfill_setup(78);
    s.classic_off(); // an unsolicited GRANT aborts a classic primary: this models croit-flashstore-osd peers (dup replay)
    s.restart(victim);
    let prim = s.primary_of(spg(1, 0).pgid);
    s.run_until(60_000 * MS, "backfilling", |s| {
        s.pg(prim, spg(1, 0))
            .is_some_and(|p| p.state_string().contains("backfilling"))
    });
    // hold the backfill traffic back so the slot stays held while the stale grant arrives
    s.blocked.insert((prim, victim));
    s.blocked.insert((victim, prim));
    let before = msgs(&s, 150);
    let e = s.epoch();
    let grant = Body::Repl(ReplMsg::RecoveryReserve(MRecoveryReserve {
        pgid: spg(1, 0),
        query_epoch: e,
        ty: MRecoveryReserve::GRANT,
        priority: 0,
    }));
    s.inject(victim, prim, grant); // bypasses the block
    s.run_for(50 * MS);
    assert_eq!(
        msgs(&s, 150),
        before,
        "recovery RELEASE sent to the backfill slot holder"
    );
    let c = s.pg(prim, spg(1, 0)).unwrap().counters();
    assert_eq!(
        c.discards
            .get("stale recovery grant, peer busy with backfill")
            .copied(),
        Some(1),
        "{:?}",
        c.discards
    );
    s.heal();
    s.run_until(120_000 * MS, "clean", |s| s.pool_clean(1));
}

/// A full classic backfill target (before tracker 76751) answers a GET_DIGEST with nothing and queues BackfillTooFull
/// behind our next message: a RELEASE (or a new REQUEST) sent before its answer takes it to RepNotRecovering, where
/// that event aborts it (lab: 09-revoke round 5b, osd.1 PG 7.d). So a stop while the scan is unanswered owes the
/// RELEASE until the DIGEST (or REVOKE_TOOFULL / REJECT_TOOFULL / the scan deadline) arrives; the re-request waits.
#[test]
fn release_waits_for_the_answer_to_an_open_scan() {
    let (mut s, victim) = backfill_setup(79);
    s.restart(victim);
    let prim = s.primary_of(spg(1, 0).pgid);
    s.run_until(60_000 * MS, "backfilling", |s| {
        s.pg(prim, spg(1, 0))
            .is_some_and(|p| p.state_string().contains("backfilling"))
    });
    // the digest answer is held back: the scan stays open
    s.blocked.insert((victim, prim));
    s.run_for(5 * MS);
    let before = msgs(&s, 99);
    // the target preempts our slot (REVOKE): stop, release, queue again
    let m = bf_reserve(&s, MBackfillReserve::REVOKE);
    s.inject(victim, prim, m);
    s.run_for(200 * MS);
    assert_eq!(
        msgs(&s, 99),
        before,
        "RELEASE / REQUEST sent while the scan is open"
    );
    s.heal();
    s.run_for(200 * MS);
    assert!(
        msgs(&s, 99) >= before + 2,
        "owed RELEASE and the new REQUEST after the digest"
    );
    s.run_until(120_000 * MS, "clean", |s| s.pool_clean(1));
}

/// PG-L2: the pool option `recovery_priority` (pool_opts key 3, via `PoolParams`) reaches the backfill REQUEST.
/// The undersized acting set (2 of 3) asks in the 140 band: 140 + deficit 1 + option 5 + 10 = 156.
#[test]
fn pool_recovery_priority_shifts_the_backfill_request() {
    let (mut s, victim) = backfill_setup(81);
    s.new_epoch(|m| {
        m.pools.get_mut(&1).unwrap().recovery_priority = 5;
    });
    s.capture = true;
    let prim = s.primary_of(spg(1, 0).pgid);
    s.restart(victim);
    s.run_until(120_000 * MS, "clean", |s| s.pool_clean(1));
    let prios: Vec<u32> = s
        .captured
        .iter()
        .filter_map(|(from, to, b)| match b {
            Body::Repl(ReplMsg::BackfillReserve(m))
                if m.ty == MBackfillReserve::REQUEST && *from == prim && *to == victim =>
            {
                Some(m.priority)
            }
            _ => None,
        })
        .collect();
    assert!(
        !prios.is_empty() && prios.iter().all(|p| *p == 156),
        "{prios:?}"
    );
}
