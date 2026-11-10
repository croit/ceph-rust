// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Force recovery / force backfill (MOSDForceRecovery, spec force-recovery.md): flag guards, cancel, the priority in the
//! reservation REQUESTs, automatic clears, state string.
mod common;
use common::*;
use peering::Body;
use replwire::{MBackfillReserve, MOSDForceRecovery as F, MRecoveryReserve, ReplMsg};

fn small_logs(c: &mut peering::Config) {
    c.min_pg_log_entries = 10;
    c.pg_log_trim_min = 1;
    c.pg_log_trim_max = 50;
    c.log_dups_tracked = 20;
}

fn fill(s: &mut Sim, n: usize, tag: &str) {
    let mut tids = vec![];
    for i in 0..n {
        let data: Vec<u8> = (0..100 + i)
            .map(|j| ((i * 131 + j * 7) % 251) as u8)
            .collect();
        tids.push(s.write_obj(1, 0, &format!("{tag}{i}"), &data).unwrap());
        s.run_for(MS / 2);
    }
    s.wait_writes(&tids, spg(1, 0));
}

fn state(s: &Sim, osd: i32) -> String {
    s.pg(osd, spg(1, 0)).unwrap().state_string()
}

fn force(s: &mut Sim, osd: i32, options: u8, pgs: Vec<denc::types::SpgT>) {
    let m = F {
        fsid: [1; 16],
        forced_pgs: pgs,
        options,
    };
    s.call(osd, |set, now, st| set.force_command(now, m, st));
}

/// Degraded PG whose log recovery is held by `norecover`: `recovery_wait`, no reservation traffic.
fn held_recovery(seed: u64) -> (Sim, i32, i32) {
    let mut s = cluster(seed, &[0, 1, 2], 1, 3, 2, 1);
    fill(&mut s, 5, "a");
    let victim = s.acting_of(spg(1, 0).pgid)[2];
    s.kill(victim);
    s.run_for(300 * MS);
    fill(&mut s, 5, "b");
    s.new_epoch(|m| m.rb.norecover = true);
    s.restart(victim);
    s.run_for(10_000 * MS);
    let prim = s.primary_of(spg(1, 0).pgid);
    assert!(
        state(&s, prim).contains("recovery_wait"),
        "{}",
        state(&s, prim)
    );
    (s, prim, victim)
}

#[test]
fn force_recovery_sets_cancels_and_requests_at_255() {
    let (mut s, prim, victim) = held_recovery(201);
    let pg = spg(1, 0);
    let replica = s.acting_of(pg.pgid)[1];
    // a replica ignores the command
    force(&mut s, replica, F::OFR_RECOVERY, vec![pg]);
    assert!(
        !state(&s, replica).contains("forced"),
        "{}",
        state(&s, replica)
    );
    // set: state string order is recovery_wait, forced_recovery, ..., degraded
    force(&mut s, prim, F::OFR_RECOVERY, vec![pg]);
    let st = state(&s, prim);
    assert!(st.contains("recovery_wait+forced_recovery"), "{st}");
    assert!(!st.contains("forced_backfill"), "{st}");
    // cancel, cancel again (no-op), set again
    force(&mut s, prim, F::OFR_RECOVERY | F::OFR_CANCEL, vec![pg]);
    assert!(!state(&s, prim).contains("forced"), "{}", state(&s, prim));
    force(&mut s, prim, F::OFR_RECOVERY | F::OFR_CANCEL, vec![pg]);
    assert!(!state(&s, prim).contains("forced"));
    force(&mut s, prim, F::OFR_RECOVERY, vec![pg]);
    force(&mut s, prim, F::OFR_RECOVERY, vec![pg]); // idempotent
    assert!(state(&s, prim).contains("forced_recovery"));
    // no option bit: nothing; an unknown PG is dropped
    force(&mut s, prim, 0, vec![pg]);
    force(&mut s, prim, F::OFR_RECOVERY, vec![spg(1, 63)]);
    assert!(state(&s, prim).contains("forced_recovery"));
    // the REQUEST to the replica carries 255
    s.capture = true;
    s.new_epoch(|m| m.rb.norecover = false);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    let prios: Vec<u32> = s
        .captured
        .iter()
        .filter_map(|(from, to, b)| match b {
            Body::Repl(ReplMsg::RecoveryReserve(m))
                if m.ty == MRecoveryReserve::REQUEST && *from == prim && *to == victim =>
            {
                Some(m.priority)
            }
            _ => None,
        })
        .collect();
    assert!(
        !prios.is_empty() && prios.iter().all(|p| *p == 255),
        "{prios:?}"
    );
    assert!(
        !state(&s, prim).contains("forced"),
        "cleared with recovery: {}",
        state(&s, prim)
    );
}

#[test]
fn force_backfill_requests_at_254_and_clears_after_backfill() {
    let mut s = cluster_cfg(202, &[0, 1, 2], 1, 3, 2, 1, small_logs);
    fill(&mut s, 8, "a");
    let victim = s.acting_of(spg(1, 0).pgid)[2];
    s.kill(victim);
    s.run_for(300 * MS);
    fill(&mut s, 40, "b");
    s.new_epoch(|m| m.rb.nobackfill = true);
    s.restart(victim);
    s.run_for(10_000 * MS);
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    assert!(
        state(&s, prim).contains("backfill_wait"),
        "{}",
        state(&s, prim)
    );
    // a force-recovery on the backfill wait of a degraded PG is accepted too (its own flag, independent)
    force(&mut s, prim, F::OFR_BACKFILL, vec![pg]);
    let st = state(&s, prim);
    assert!(st.contains("backfill_wait+forced_backfill"), "{st}");
    assert!(!st.contains("forced_recovery"), "{st}");
    s.capture = true;
    s.new_epoch(|m| m.rb.nobackfill = false);
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
        !prios.is_empty() && prios.iter().all(|p| *p == 254),
        "{prios:?}"
    );
    assert!(!state(&s, prim).contains("forced"), "{}", state(&s, prim));
}

/// A PG that needs nothing (clean) ignores both commands: the flag is only set while degraded / waiting / working.
#[test]
fn clean_pg_ignores_force() {
    let mut s = cluster(203, &[0, 1, 2], 1, 3, 2, 1);
    fill(&mut s, 3, "a");
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let pg = spg(1, 0);
    let prim = s.primary_of(pg.pgid);
    force(&mut s, prim, F::OFR_RECOVERY, vec![pg]);
    force(&mut s, prim, F::OFR_BACKFILL, vec![pg]);
    assert!(!state(&s, prim).contains("forced"), "{}", state(&s, prim));
}

/// Both bits set: backfill wins (the mgr never sends that). The flag stays across a map change and is cleared by the PG
/// going clean.
#[test]
fn backfill_bit_wins_and_flags_clear_when_clean() {
    let (mut s, prim, _victim) = held_recovery(204);
    let pg = spg(1, 0);
    force(&mut s, prim, F::OFR_RECOVERY | F::OFR_BACKFILL, vec![pg]);
    let st = state(&s, prim);
    assert!(
        st.contains("forced_backfill") && !st.contains("forced_recovery"),
        "{st}"
    );
    force(&mut s, prim, F::OFR_BACKFILL | F::OFR_CANCEL, vec![pg]);
    force(&mut s, prim, F::OFR_RECOVERY, vec![pg]);
    s.new_epoch(|m| m.rb.nobackfill = true); // a map change that does not move the PG
    s.run_for(2000 * MS);
    assert!(
        state(&s, prim).contains("forced_recovery"),
        "{}",
        state(&s, prim)
    );
    s.new_epoch(|m| m.rb.norecover = false);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    assert!(!state(&s, prim).contains("forced"), "{}", state(&s, prim));
}
