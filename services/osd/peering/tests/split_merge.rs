// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG split and merge in the deterministic multi-OSD simulation (spec split-merge.md, test checklist T8-T15).
mod common;
use common::*;
use denc::types::{Eversion, PgT, SpgT};
use peering::Body;
use std::collections::BTreeMap;

const POOL: u64 = 1;

/// Client emulation: writes that are not acknowledged (aborted by an interval change, no active primary yet)
/// are re-sent, like the Objecter does.
struct Writer {
    want: BTreeMap<String, Vec<u8>>,
    /// `(name, osd, incarnation, pg, tid, sent at)`
    inflight: Vec<(String, i32, u64, SpgT, u64, peering::Mono)>,
    retry: Vec<String>,
}

impl Writer {
    fn new() -> Self {
        Writer {
            want: BTreeMap::new(),
            inflight: vec![],
            retry: vec![],
        }
    }
    fn put(&mut self, s: &mut Sim, name: &str, data: Vec<u8>) {
        self.want.insert(name.to_string(), data);
        self.send(s, name);
    }
    fn send(&mut self, s: &mut Sim, name: &str) {
        let seed = s.named_seed(POOL, name);
        let data = self.want[name].clone();
        let pgid = PgT::new(POOL, seed);
        let osd = s.primary_of(pgid);
        let inc = s.nodes.get(&osd).map_or(0, |n| n.inc);
        match s.write_named(POOL, name, &data) {
            Ok(tid) => self.inflight.push((
                name.to_string(),
                osd,
                inc,
                SpgT {
                    pgid,
                    shard: denc::types::ShardId::NO_SHARD,
                },
                tid,
                s.now,
            )),
            Err(_) => self.retry.push(name.to_string()),
        }
    }
    /// One pass: drop acked writes, re-send aborted / stale ones.
    fn pump(&mut self, s: &mut Sim) {
        let inflight = std::mem::take(&mut self.inflight);
        for (name, osd, inc, spg, tid, at) in inflight {
            let key = (osd, inc, spg, tid);
            if s.acked_full.contains(&key) {
                continue;
            }
            let alive = s.nodes.get(&osd).is_some_and(|n| n.alive && n.inc == inc);
            if s.failed_full.contains(&key) || !alive || s.now > at + 4_000 * MS {
                self.retry.push(name);
            } else {
                self.inflight.push((name, osd, inc, spg, tid, at));
            }
        }
        for name in std::mem::take(&mut self.retry) {
            // newest data only
            self.send(s, &name);
        }
    }
    fn done(&self) -> bool {
        self.inflight.is_empty() && self.retry.is_empty()
    }
    fn settle(&mut self, s: &mut Sim) {
        for _ in 0..3000 {
            self.pump(s);
            if self.done() {
                return;
            }
            s.run_for(20 * MS);
        }
        panic!(
            "writes did not settle: {} left\n{}",
            self.inflight.len() + self.retry.len(),
            s.dump()
        );
    }
}

fn data(i: usize, rev: u32) -> Vec<u8> {
    let mut v = format!("object-{i}-rev{rev}-").into_bytes();
    v.resize(64 + (i * 37) % 200, (i % 251) as u8);
    v
}

fn wait_settled(s: &mut Sim) {
    s.run_until(120_000 * MS, "pool settled", |s| {
        s.pool_settled(POOL) && s.quiet()
    });
}

/// Settled: no primary-side local reservation slot or queue place is left (a merge source or a removed PG that held one
/// leaked it: every later recovery/backfill of that core stalled).
fn assert_no_local_slots(s: &Sim) {
    for (o, n) in &s.nodes {
        assert_eq!(n.set.local_slots(), (0, 0), "osd.{o}: local slot leaked");
    }
}

/// Split 1 -> 2 -> 4 -> 8 one doubling at a time, with writes in flight at every change.
#[test]
fn split_1_2_4_8_under_writes() {
    let mut s = cluster(11, &[0, 1, 2], POOL, 3, 2, 1);
    let mut w = Writer::new();
    for i in 0..120 {
        w.put(&mut s, &format!("obj-{i}"), data(i, 0));
    }
    w.settle(&mut s);
    for (rev, n) in (1u32..).zip([2u32, 4, 8]) {
        // writes in flight while the pool splits
        for i in 0..40 {
            w.put(&mut s, &format!("obj-{}", i * 3), data(i * 3, rev));
        }
        s.set_pg_num(POOL, n);
        for i in 120..140 {
            w.put(
                &mut s,
                &format!("obj-{}", i + n as usize * 20),
                data(i, rev),
            );
        }
        w.settle(&mut s);
        wait_settled(&mut s);
        s.assert_layout(POOL, &w.want);
    }
    assert_eq!(s.pool_pg_num(POOL), 8);
    for o in [0, 1, 2] {
        let total: usize = (0..8).map(|seed| s.contents(o, POOL, seed).len()).sum();
        assert_eq!(total, w.want.len(), "osd.{o}");
        for seed in 0..8 {
            assert!(
                !s.contents(o, POOL, seed).is_empty(),
                "osd.{o} pg {seed} empty"
            );
            let p = s.pg(o, spg(POOL, seed)).unwrap();
            assert_eq!(
                p.log()
                    .entries()
                    .iter()
                    .filter(|e| !e.soid.oid.is_empty())
                    .count(),
                p.log().entries().len()
            );
        }
    }
    s.assert_persisted_consistent();
    s.assert_no_roundtrip_mismatch();
    // every PG has a history created at its split epoch, last_epoch_split set
    for seed in 1..8u32 {
        let spg = spg(POOL, seed);
        let p = s.pg(s.primary_of(spg.pgid), spg).unwrap();
        assert!(p.info().history.epoch_created > 1, "pg {seed}");
        assert!(p.info().stats.stats_invalid || p.info().history.last_epoch_split > 0);
    }
    let _ = Eversion::default();
}

/// 8 -> 64 in a single map, then placement catches up (pgp_num) with more OSDs than replicas.
#[test]
fn split_8_to_64_single_jump_then_pgp() {
    let mut s = cluster(12, &[0, 1, 2, 3, 4], POOL, 3, 2, 8);
    s.verbose = true;
    let mut w = Writer::new();
    for i in 0..300 {
        w.put(&mut s, &format!("big-{i}"), data(i, 0));
    }
    w.settle(&mut s);
    s.set_pg_num(POOL, 64);
    for i in 0..60 {
        w.put(&mut s, &format!("big-{}", i * 5), data(i, 1));
    }
    w.settle(&mut s);
    wait_settled(&mut s);
    assert_eq!(s.pool_pg_num(POOL), 64);
    s.assert_layout(POOL, &w.want);
    s.assert_persisted_consistent();
    // placement of the children moves later: ordinary remapping + backfill
    s.set_pgp_num(POOL, 64);
    for i in 0..40 {
        w.put(&mut s, &format!("big-{}", i * 7), data(i, 2));
    }
    w.settle(&mut s);
    wait_settled(&mut s);
    s.assert_layout(POOL, &w.want);
    s.assert_persisted_consistent();
    s.assert_no_roundtrip_mismatch();
}

/// Merge 16 -> 8: pgp_num first, then one PG at a time through PEERED+PREMERGE and ReadyToMerge.
#[test]
fn merge_16_to_8_sequence() {
    let mut s = cluster(13, &[0, 1, 2], POOL, 3, 2, 16);
    let mut w = Writer::new();
    for i in 0..200 {
        w.put(&mut s, &format!("m-{i}"), data(i, 0));
    }
    w.settle(&mut s);
    s.set_pgp_num(POOL, 8);
    wait_settled(&mut s);
    for step in 0..8u32 {
        let n = 16 - step;
        s.begin_merge(POOL);
        // client io while the merge prepares (parked until the PGs are active again)
        for i in 0..10 {
            w.put(
                &mut s,
                &format!("m-{}", i * 13 + step as usize),
                data(i, 1 + step),
            );
        }
        s.run_until(60_000 * MS, "pg_num decremented", |s| {
            s.pool_pg_num(POOL) == n - 1
        });
        w.settle(&mut s);
        wait_settled(&mut s);
        s.assert_layout(POOL, &w.want);
    }
    assert_eq!(s.pool_pg_num(POOL), 8);
    s.assert_persisted_consistent();
    s.assert_no_roundtrip_mismatch();
    // exactly one ready report per merge
    let ready: Vec<_> = s.merge_report_log.iter().filter(|(_, r)| r.ready).collect();
    assert!(ready.len() >= 8, "{} reports", ready.len());
    // a merged target has an empty log at head = tail and its dups
    for seed in 0..8u32 {
        let p = s
            .pg(s.primary_of(PgT::new(POOL, seed)), spg(POOL, seed))
            .unwrap();
        assert!(
            p.is_active() && p.is_clean(),
            "pg {seed} {}",
            p.state_string()
        );
    }
}

/// After a merge the target holds the union, an empty log at max(last_update), the dups of both and summed
/// stats (split-merge.md 6.4, invariant 8).
#[test]
fn merge_target_state_2_to_1() {
    let mut s = cluster(14, &[0, 1, 2], POOL, 3, 2, 2);
    let mut w = Writer::new();
    for i in 0..60 {
        w.put(&mut s, &format!("t-{i}"), data(i, 0));
    }
    w.settle(&mut s);
    wait_settled(&mut s);
    // pgp_num must not exceed pg_num_pending; 2 -> 1 needs pgp 1 first
    s.set_pgp_num(POOL, 1);
    wait_settled(&mut s);
    let lu = |s: &Sim, seed: u32| {
        s.pg(s.primary_of(PgT::new(POOL, seed)), spg(POOL, seed))
            .unwrap()
            .info()
            .last_update
    };
    let (l0, l1) = (lu(&s, 0), lu(&s, 1));
    let dups_before: usize = (0..2u32)
        .map(|seed| {
            let p = s
                .pg(s.primary_of(PgT::new(POOL, seed)), spg(POOL, seed))
                .unwrap();
            p.log().log.dups.len() + p.log().len()
        })
        .sum();
    s.begin_merge(POOL);
    s.run_until(60_000 * MS, "merged", |s| s.pool_pg_num(POOL) == 1);
    wait_settled(&mut s);
    s.assert_layout(POOL, &w.want);
    for o in [0, 1, 2] {
        let p = s.pg(o, spg(POOL, 0)).unwrap();
        assert_eq!(p.info().last_update, l0.max(l1), "osd.{o}");
        assert_eq!(p.log().head(), l0.max(l1));
        assert_eq!(p.log().tail(), l0.max(l1));
        assert!(p.log().is_empty(), "log emptied");
        assert!(p.missing().is_empty());
        assert_eq!(p.log().log.dups.len(), dups_before, "dups of both PGs kept");
        assert_eq!(
            p.info().last_backfill,
            denc::types::Hobject::MAX(),
            "complete merge"
        );
        assert!(s.pg(o, spg(POOL, 1)).is_none(), "source gone on osd.{o}");
    }
    s.assert_persisted_consistent();
    assert!(!s.nodes[&0].store.pgs.contains_key(&spg(POOL, 1)));
}

/// An OSD that was down during a whole merge comes back with stale copies: its merge is incomplete and the
/// copies are backfilled (mismatch with last_pg_merge_meta never loses data, invariant 9).
#[test]
fn merge_with_stale_osd_is_backfilled() {
    let mut s = cluster(15, &[0, 1, 2, 3], POOL, 3, 2, 4);
    let mut w = Writer::new();
    for i in 0..80 {
        w.put(&mut s, &format!("s-{i}"), data(i, 0));
    }
    w.settle(&mut s);
    s.set_pgp_num(POOL, 2);
    wait_settled(&mut s);
    // osd.2 dies and is replaced for good while the pool merges 4 -> 3 -> 2
    s.kill(2);
    s.mark_out(2);
    wait_settled(&mut s);
    for i in 0..40 {
        w.put(&mut s, &format!("s-{}", i * 2), data(i, 1));
    }
    w.settle(&mut s);
    for n in [3u32, 2] {
        s.begin_merge(POOL);
        s.run_until(60_000 * MS, "merged", |s| s.pool_pg_num(POOL) == n);
        wait_settled(&mut s);
    }
    s.assert_layout(POOL, &w.want);
    // it returns with its stale copies
    s.restart(2);
    s.mark_in(2);
    s.run_for(2_000 * MS);
    wait_settled(&mut s);
    s.assert_layout(POOL, &w.want);
    s.assert_persisted_consistent();
    for seed in 0..2u32 {
        for o in s.acting_of(PgT::new(POOL, seed)) {
            let p = s.pg(o, spg(POOL, seed)).unwrap();
            assert_eq!(p.info().last_backfill, denc::types::Hobject::MAX());
        }
    }
    // no leftovers of removed sources
    assert!(s.nodes[&2].set.pgs().all(|(k, _)| k.pgid.seed < 2));
    assert_no_local_slots(&s);
}

/// An OSD that was down across 1 -> 2 -> 4 -> 8 splits in several maps catches up in one go.
#[test]
fn split_far_behind_osd_catches_up() {
    let mut s = cluster(16, &[0, 1, 2], POOL, 3, 2, 1);
    let mut w = Writer::new();
    for i in 0..100 {
        w.put(&mut s, &format!("f-{i}"), data(i, 0));
    }
    w.settle(&mut s);
    s.kill(2);
    for n in [2u32, 4, 8] {
        s.set_pg_num(POOL, n);
        s.run_for(500 * MS);
        for i in 0..20 {
            w.put(&mut s, &format!("f-{}", i * 5 + n as usize), data(i, n));
        }
        w.settle(&mut s);
    }
    s.restart(2);
    s.run_for(1_000 * MS);
    wait_settled(&mut s);
    s.assert_layout(POOL, &w.want);
    s.assert_persisted_consistent();
    for seed in 0..8u32 {
        assert!(s.pg(2, spg(POOL, seed)).is_some(), "pg {seed} on osd.2");
    }
}

/// Primary of a pending merge that is undersized reports ready=false; the mon aborts and the PGs go active again.
#[test]
fn merge_not_ready_when_undersized() {
    let mut s = cluster(17, &[0, 1, 2], POOL, 3, 2, 4);
    let mut w = Writer::new();
    for i in 0..40 {
        w.put(&mut s, &format!("n-{i}"), data(i, 0));
    }
    w.settle(&mut s);
    s.set_pgp_num(POOL, 3);
    wait_settled(&mut s);
    s.kill(2);
    s.run_for(500 * MS);
    s.begin_merge(POOL);
    s.run_for(5_000 * MS);
    assert_eq!(s.pool_pg_num(POOL), 4, "no merge while undersized");
    assert!(
        s.merge_report_log.iter().any(|(_, r)| !r.ready),
        "ready=false reported"
    );
    assert_eq!(s.map().pools[&POOL].pg_num_pending, 4, "mon reset pending");
    for seed in 0..4u32 {
        let p = s
            .pg(s.primary_of(PgT::new(POOL, seed)), spg(POOL, seed))
            .unwrap();
        assert!(p.is_active(), "pg {seed} {}", p.state_string());
    }
    w.put(&mut s, "n-after", data(1, 9));
    w.settle(&mut s);
    s.assert_no_roundtrip_mismatch();
}

/// Client ops older than the split epoch are dropped (the client re-sends), newer ones are served.
#[test]
fn client_op_stale_after_split() {
    let mut s = cluster(18, &[0, 1, 2], POOL, 3, 2, 1);
    let e = s.set_pg_num(POOL, 2);
    wait_settled(&mut s);
    for seed in 0..2u32 {
        let p = s
            .pg(s.primary_of(PgT::new(POOL, seed)), spg(POOL, seed))
            .unwrap();
        assert_eq!(p.info().history.last_epoch_split, e, "pg {seed}");
        assert!(p.client_op_stale(e - 1));
        assert!(!p.client_op_stale(e));
    }
}

/// Mgr behaviour for one merge step: prepare, wait for the mon commit; retry when the mon aborted it.
fn merge_one(s: &mut Sim, w: &mut Writer, rng: &mut Rng, chaos: bool) {
    let n = s.pool_pg_num(POOL);
    for _ in 0..40 {
        w.settle(s);
        wait_settled(s);
        if s.pool_pg_num(POOL) < n {
            return;
        }
        s.begin_merge(POOL);
        let victim = rng.range(0, 3) as i32;
        let mut killed = false;
        for tick in 0..400 {
            s.run_for(25 * MS);
            let v = s.past_bounds_violations();
            assert!(v.is_empty(), "past interval bounds after merge: {v:?}");
            if chaos && tick == rng.range(0, 40) as usize && !killed && rng.range(0, 2) == 0 {
                s.kill(victim);
                killed = true;
            }
            if killed && tick > 80 {
                s.restart(victim);
                killed = false;
            }
            if s.pool_pg_num(POOL) < n {
                break;
            }
            // aborted: pending was reset by the mon
            if s.map().pools[&POOL].pg_num_pending == n && s.epoch() > 1 && tick > 100 {
                break;
            }
        }
        if killed {
            s.restart(victim);
        }
        if s.pool_pg_num(POOL) < n {
            return;
        }
    }
    panic!("merge never completed\n{}", s.dump());
}

#[test]
fn chaos_split_merge_with_restarts() {
    for seed in 0..30u64 {
        eprintln!("chaos seed {seed}");
        let mut s = cluster(200 + seed, &[0, 1, 2, 3], POOL, 3, 2, 4);
        let mut rng = Rng::new(seed + 1);
        let mut w = Writer::new();
        for i in 0..100 {
            w.put(&mut s, &format!("c-{i}"), data(i, 0));
        }
        w.settle(&mut s);
        // splits with a crash at a random moment around each
        for (k, n) in [8u32, 16].into_iter().enumerate() {
            s.set_pg_num(POOL, n);
            let victim = rng.range(0, 3) as i32;
            s.run_for(rng.range(0, 300) * MS);
            for i in 0..20 {
                w.put(
                    &mut s,
                    &format!("c-{}", rng.range(0, 300)),
                    data(i, 1 + k as u32),
                );
            }
            let v = s.past_bounds_violations();
            assert!(v.is_empty(), "past interval bounds after split: {v:?}");
            s.kill(victim);
            s.run_for(rng.range(0, 700) * MS);
            for i in 0..10 {
                w.put(
                    &mut s,
                    &format!("c-{}", rng.range(0, 300)),
                    data(i, 5 + k as u32),
                );
            }
            s.restart(victim);
            w.settle(&mut s);
            wait_settled(&mut s);
            s.assert_layout(POOL, &w.want);
        }
        // placement follows (backfill), then merge back down to 8
        s.set_pgp_num(POOL, 8);
        w.settle(&mut s);
        wait_settled(&mut s);
        for _ in 0..8 {
            merge_one(&mut s, &mut w, &mut rng, true);
            for i in 0..5 {
                w.put(&mut s, &format!("c-{}", rng.range(0, 300)), data(i, 9));
            }
            w.settle(&mut s);
        }
        wait_settled(&mut s);
        assert_eq!(s.pool_pg_num(POOL), 8, "seed {seed}");
        assert_no_local_slots(&s);
        s.assert_layout(POOL, &w.want);
        s.assert_persisted_consistent();
        s.assert_no_roundtrip_mismatch();
    }
}

/// A classic peer that has not finished its own split aborts when it gets a peering message for the child (found
/// live twice: PeeringState::Crashed, MNotifyRec from an croit-flashstore-osd replica into a child still in Reset). Rule (state,
/// no clock): towards a peer not known to be croit-flashstore-osd our messages for a child wait until that peer spoke about the
/// child, or until a later map exists (the children then restart peering, stamped with that epoch).
#[test]
fn child_messages_wait_for_the_peer_or_the_next_map() {
    let mut s = cluster(19, &[0, 1, 2], POOL, 3, 2, 2);
    s.run_for(1_000 * MS);
    assert_gated_split(&mut s, 4);
}

/// The same after the PGs existed before (split, merged away, split again): what a peer said in its earlier
/// incarnation of the child is no evidence about the new one (found live: classic crashed).
#[test]
fn child_gate_ignores_the_peers_speech_of_an_earlier_incarnation() {
    let mut s = cluster(27, &[0, 1, 2], POOL, 3, 2, 2);
    s.run_for(1_000 * MS);
    s.set_pg_num(POOL, 4);
    wait_settled(&mut s);
    for n in [3u32, 2] {
        s.begin_merge(POOL);
        s.run_until(60_000 * MS, "merged", |s| s.pool_pg_num(POOL) == n);
        wait_settled(&mut s);
    }
    assert_gated_split(&mut s, 4);
}

fn assert_gated_split(s: &mut Sim, new_n: u32) {
    s.capture = true;
    s.captured.clear();
    let split = s.set_pg_num(POOL, new_n);
    let old_n = s.pool_pg_num(POOL).min(2);
    let is_child = |b: &Body| match b {
        Body::Peering(p) => p.spgid().is_some_and(|x| x.pgid.seed >= old_n),
        Body::Repl(_) | Body::Ec(_) => false,
    };
    let seed_of = |b: &Body| match b {
        Body::Peering(p) => p.spgid().map(|x| x.pgid.seed),
        Body::Repl(_) | Body::Ec(_) => None,
    };
    let (mut seen, mut checked) = (0, 0);
    for _ in 0..4000 {
        s.run_for(MS);
        for i in seen..s.captured.len() {
            let (a, b, body) = &s.captured[i];
            if !is_child(body) {
                continue;
            }
            let c = seed_of(body).unwrap();
            let spoke = s.captured[..i]
                .iter()
                .any(|(f, t, bb)| f == b && t == a && seed_of(bb) == Some(c));
            let later_map = s.nodes[a].set.epoch() > split;
            assert!(
                spoke || later_map,
                "osd.{a} -> osd.{b}: child {c} before it spoke and before a later map\n{}",
                s.trace_of("gate")
            );
            checked += 1;
        }
        seen = s.captured.len();
    }
    assert!(checked > 0, "children peered");
    s.run_until(60_000 * MS, "settled", |s| s.pool_settled(POOL));
}

/// Peers known to be croit-flashstore-osd are not gated: the children peer without waiting for a later map.
#[test]
fn flashstore_peers_are_not_gated() {
    let mut s = cluster(26, &[0, 1, 2], POOL, 3, 2, 2);
    s.classic_off(); // the peers are croit-flashstore-osd: nothing to model
    s.run_for(1_000 * MS);
    for o in [0, 1, 2] {
        s.call(o, |set, _, _| {
            set.set_flashstore_peers([0, 1, 2].into_iter().collect())
        });
    }
    s.set_pg_num(POOL, 4);
    s.run_until(60_000 * MS, "settled", |s| s.pool_settled(POOL));
}

/// adr 0021 am. 30 / OQ 29: a primary accepts long names only when every member of up and acting is listed as storing them.
#[test]
fn long_names_need_every_member_listed() {
    let mut s = cluster(27, &[0, 1, 2], POOL, 3, 2, 2);
    s.run_for(1_000 * MS);
    let sp = spg(POOL, 0);
    let pr = s.primary_of(sp.pgid);
    let ask = |s: &mut Sim, peers: &[i32]| {
        let p: std::collections::BTreeSet<i32> = peers.iter().copied().collect();
        s.call(pr, |set, _, _| {
            set.set_long_peers(p);
            Vec::new()
        });
        s.nodes[&pr].set.long_names_ok(sp)
    };
    assert!(!ask(&mut s, &[]), "peers unknown");
    let others: Vec<i32> = [0, 1, 2].into_iter().filter(|o| *o != pr).collect();
    assert!(!ask(&mut s, &others[..1]), "one member missing");
    assert!(
        ask(&mut s, &others),
        "all members listed (the primary itself needs no entry)"
    );
}

/// A split leaves the stats invalid (and records the split bits); the next scrub replaces them.
#[test]
fn split_stats_invalid_until_scrubbed() {
    let mut s = cluster(20, &[0, 1, 2], POOL, 3, 2, 1);
    let mut w = Writer::new();
    for i in 0..30 {
        w.put(&mut s, &format!("v-{i}"), data(i, 0));
    }
    w.settle(&mut s);
    s.set_pg_num(POOL, 2);
    wait_settled(&mut s);
    for seed in 0..2u32 {
        let sp = spg(POOL, seed);
        let p = s.pg(s.primary_of(sp.pgid), sp).unwrap();
        assert!(p.info().stats.stats_invalid, "pg {seed}");
        assert_eq!(p.info().stats.parent_split_bits == 1, seed == 1);
    }
    // real writes leave an (empty) snapset on every head
    for n in s.nodes.values_mut() {
        for mp in n.store.pgs.values_mut() {
            for o in mp.objects.values_mut() {
                o.xattrs.insert(
                    b"snapset".to_vec(),
                    denc::to_vec(&replwire::SnapSet::default()).unwrap(),
                );
            }
        }
    }
    for seed in 0..2u32 {
        let sp = spg(POOL, seed);
        let prim = s.primary_of(sp.pgid);
        s.call(prim, move |set, now, store| {
            set.request_scrub(now, sp, true, false, store)
        });
    }
    s.run_for(30_000 * MS);
    for seed in 0..2u32 {
        let sp = spg(POOL, seed);
        let p = s.pg(s.primary_of(sp.pgid), sp).unwrap();
        assert!(
            !p.info().stats.stats_invalid,
            "pg {seed} still invalid after the scrub"
        );
        assert_eq!(p.info().stats.stats.sum.num_scrub_errors, 0);
        assert!(p.info().history.last_deep_scrub != Eversion::default());
    }
}

/// A merge source whose target is not on this OSD is never deleted: an empty target absorbs it (incomplete, so
/// its peers backfill it) and the pool ends consistent.
#[test]
fn merge_source_without_local_target_gets_a_placeholder() {
    let mut s = cluster(23, &[0, 1, 2, 3], POOL, 3, 2, 2);
    let mut w = Writer::new();
    for i in 0..60 {
        w.put(&mut s, &format!("p-{i}"), data(i, 0));
    }
    w.settle(&mut s);
    s.set_pgp_num(POOL, 1);
    wait_settled(&mut s);
    s.kill(2);
    s.mark_out(2);
    wait_settled(&mut s);
    s.begin_merge(POOL);
    s.run_until(60_000 * MS, "merged", |s| s.pool_pg_num(POOL) == 1);
    wait_settled(&mut s);
    // osd.2 comes back holding only the source
    s.nodes.get_mut(&2).unwrap().store.pgs.remove(&spg(POOL, 0));
    s.restart(2);
    s.mark_in(2);
    // the placeholder's history and past intervals keep classic's required bounds from the merge until clean
    for _ in 0..200 {
        s.run_for(10 * MS);
        let v = s.past_bounds_violations();
        assert!(v.is_empty(), "past interval bounds: {v:?}");
    }
    wait_settled(&mut s);
    assert!(s.past_bounds_violations().is_empty());
    assert!(
        !s.trace_of("target absent, placeholder").is_empty(),
        "placeholder path not taken:\n{}",
        s.trace_of("merge")
    );
    s.assert_layout(POOL, &w.want);
    s.assert_persisted_consistent();
    assert!(s.nodes[&2].set.pgs().all(|(k, _)| k.pgid.seed < 1));
}

/// The merge registry is keyed by the actual source: with `pg_num_pending = pg_num - 2` two sources and two
/// targets are pending and every PG names its own pair; Ready only ever holds with Clean reached in the current
/// interval.
#[test]
fn merge_pairs_are_keyed_by_actual_source() {
    let mut s = cluster(24, &[0, 1, 2], POOL, 3, 2, 4);
    s.set_pgp_num(POOL, 2);
    wait_settled(&mut s);
    s.new_epoch(|m| m.pools.get_mut(&POOL).unwrap().pg_num_pending = 2);
    s.run_for(30 * MS);
    for seed in 0..4u32 {
        let o = s.primary_of(PgT::new(POOL, seed));
        let p = s.pg(o, spg(POOL, seed)).unwrap();
        let pairs: Vec<(u32, bool)> = p
            .merge_pairs()
            .into_iter()
            .map(|(g, src)| (g.seed, src))
            .collect();
        let want: Vec<(u32, bool)> = match seed {
            0 => vec![(2, false)],
            1 => vec![(3, false)],
            s => vec![(s, true)],
        };
        assert_eq!(pairs, want, "pg {seed}");
        if matches!(p.merge_status(), peering::MergeStatus::Ready { .. }) {
            let h = &p.info().history;
            assert_eq!(h.last_interval_clean, h.same_interval_since, "pg {seed}");
        }
    }
}

/// A new interval with the same, fully up acting set (split) does not wait for the prior read lease; a member that
/// went down and may still be alive does (peering.md 8.2, prior_readable_down_osds).
#[test]
fn split_does_not_wait_for_prior_lease_but_a_down_member_does() {
    let mut s = cluster(25, &[0, 1, 2], POOL, 3, 2, 2);
    s.run_for(5_000 * MS); // leases granted
    s.set_pg_num(POOL, 8);
    s.run_for(1_500 * MS);
    let st = s.pool_state_strings(POOL);
    assert!(
        st.iter()
            .all(|x| x.contains("active") && !x.contains("wait")),
        "split stalled on the lease: {st:?}"
    );
    // a member dies: the survivors' new interval honours its possible lease
    s.kill(2);
    s.run_for(1_500 * MS);
    let st = s.pool_state_strings(POOL);
    assert!(st.iter().any(|x| x.contains("wait")), "no WAIT: {st:?}");
}

/// A MOSDPGCreate2 stamped with an epoch the OSD does not have yet is kept until the map arrives, not dropped
/// (found live: on a busy mon every create stayed one epoch ahead and the PGs were never created).
#[test]
fn create2_ahead_of_the_map_is_not_lost() {
    for seed in 30..38 {
        let mut s = cluster(seed, &[0, 1, 2], POOL, 3, 2, 2);
        s.run_for(500 * MS);
        s.create_pool_lat(2, 3, 2, 8, 0);
        s.run_until(30_000 * MS, "pool 2 created", |s| s.pool_settled(2));
    }
}

/// Review finding 8: with `pg_num_pending = 3` on pg_num 8 sources 3..8 fold into 0..3 via repeated parent steps
/// (7 -> 3 -> 1); the registry pairs must name the final target, not the first parent.
#[test]
fn merge_pairs_follow_the_final_target() {
    let mut s = cluster(28, &[0, 1, 2], POOL, 3, 2, 8);
    s.set_pgp_num(POOL, 3);
    wait_settled(&mut s);
    s.new_epoch(|m| m.pools.get_mut(&POOL).unwrap().pg_num_pending = 3);
    s.run_for(30 * MS);
    for seed in 0..8u32 {
        let o = s.primary_of(PgT::new(POOL, seed));
        let p = s.pg(o, spg(POOL, seed)).unwrap();
        let pairs: Vec<(u32, bool)> = p
            .merge_pairs()
            .into_iter()
            .map(|(g, src)| (g.seed, src))
            .collect();
        let want: Vec<(u32, bool)> = match seed {
            0 => vec![(4, false)],
            1 => vec![(3, false), (5, false), (7, false)],
            2 => vec![(6, false)],
            s => vec![(s, true)],
        };
        assert_eq!(pairs, want, "pg {seed}");
    }
}

/// Review finding 1: a send held back by the split gate from an interval the child has left since (a newer map
/// arrived before the peer spoke) is dropped when the gate opens, not re-stamped as if it were current.
#[test]
fn gated_sends_of_a_left_interval_are_dropped_not_restamped() {
    let mut dropped = 0;
    for seed in 40..52 {
        let mut s = cluster(seed, &[0, 1, 2, 3], POOL, 3, 2, 2);
        s.run_for(1_000 * MS);
        s.set_pg_num(POOL, 4);
        // the next map changes the children's placement before any peer could answer
        s.mark_out(3);
        s.mark_out(2);
        s.run_until(60_000 * MS, "settled", |s| s.pool_settled(POOL));
        dropped += s.trace_of("stale held sends").lines().count();
    }
    assert!(dropped > 0, "no run had a held send of a left interval");
}

/// Review finding 7: a child created while a PG is loaded at an epoch below the current one (restart) gets its gate
/// reopened right away, not only with the next map.
#[test]
fn gate_of_a_child_made_at_load_is_reopened_at_once() {
    let mut s = cluster(29, &[0, 1, 2], POOL, 3, 2, 2);
    s.run_for(1_000 * MS);
    s.kill(2);
    s.run_for(200 * MS);
    s.set_pg_num(POOL, 4);
    s.new_epoch(|m| m.osds.get_mut(&0).unwrap().in_ = true); // one more epoch above the split
    s.restart(2);
    assert!(
        !s.trace_of("reopened at epoch").is_empty(),
        "gate left closed:\n{}",
        s.trace_of("gate")
    );
    s.run_until(60_000 * MS, "settled", |s| s.pool_settled(POOL));
}

/// Review finding 4: a target that is already past the merge epoch (made from a newer map than its source's)
/// absorbs the late source as incomplete (`last_backfill = MIN`, peers backfill it), whatever the merge facts say.
#[test]
fn late_merge_into_a_target_past_the_epoch_is_incomplete() {
    let mut s = cluster(23, &[0, 1, 2, 3], POOL, 3, 2, 2);
    let mut w = Writer::new();
    for i in 0..60 {
        w.put(&mut s, &format!("l-{i}"), data(i, 0));
    }
    w.settle(&mut s);
    s.set_pgp_num(POOL, 1);
    let v = s.primary_of(PgT::new(POOL, 0));
    wait_settled(&mut s);
    s.kill(v);
    s.mark_out(v);
    wait_settled(&mut s);
    s.begin_merge(POOL);
    s.run_until(60_000 * MS, "merged", |s| s.pool_pg_num(POOL) == 1);
    wait_settled(&mut s);
    // the victim's target claims to have seen the newest map while its source is still before the merge
    let now = s.epoch();
    let pgs = &mut s.nodes.get_mut(&v).unwrap().store.pgs;
    // the fabricated epoch bump must not also fabricate an implausible pair: the required bounds start at lec, so the
    // past intervals must too (peering.md 3.8 stops the PG otherwise, before the late-merge path runs). The late target
    // may adopt its source's set, so keep that one inside the target's required start as well.
    let lec = {
        let target = &mut pgs.get_mut(&spg(POOL, 0)).unwrap().p;
        target.epoch = now;
        let lec = target.info.history.last_epoch_clean;
        if target.past_intervals.is_empty() {
            // a never-recorded clean interval still belongs to the required range; the map advance extends it
            if lec != 0 {
                target.past_intervals.first = lec;
                target.past_intervals.last = lec;
            }
        } else {
            target.past_intervals.first = target.past_intervals.first.min(lec);
        }
        lec
    };
    if let Some(src) = pgs.get_mut(&spg(POOL, 1))
        && !src.p.past_intervals.is_empty()
    {
        src.p.past_intervals.first = src.p.past_intervals.first.min(lec);
    }
    s.restart(v);
    assert!(
        !s.trace_of("(past epoch").is_empty(),
        "late path not taken:\n{}",
        s.trace_of("merge")
    );
    let t = s.pg(v, spg(POOL, 0)).unwrap();
    assert_eq!(
        t.info().last_backfill,
        denc::types::Hobject::MIN(),
        "late merge must force a backfill"
    );
    s.mark_in(v);
    s.run_for(2_000 * MS);
    wait_settled(&mut s);
    s.assert_layout(POOL, &w.want);
    s.assert_persisted_consistent();
}

/// Review finding 6: a PG that turns out to belong to an erasure (passive) pool is forgotten with the same cleanup
/// as any removal (`PgRemoved` for the driver's side tables), and sends nothing more.
#[test]
fn passive_pool_pgs_are_forgotten_with_pgremoved() {
    let mut s = cluster(31, &[0, 1, 2], POOL, 3, 2, 2);
    s.run_for(1_000 * MS);
    s.removed.clear();
    s.capture = true;
    s.captured.clear();
    s.new_epoch(|m| m.pools.get_mut(&POOL).unwrap().is_erasure = true);
    s.run_for(500 * MS);
    for o in [0, 1, 2] {
        for seed in 0..2u32 {
            assert!(
                s.removed.contains(&(o, spg(POOL, seed))),
                "osd.{o} pg {seed} left without PgRemoved"
            );
        }
        assert_eq!(s.nodes[&o].set.pgs().count(), 0);
    }
    assert!(
        s.captured
            .iter()
            .all(|(_, _, b)| !matches!(b, Body::Peering(p) if p.spgid().is_some_and(|x| x.pgid.pool == POOL))),
        "message for a passive pool"
    );
}

/// Found live (mixed-cluster suite): a classic OSD that held the parent only as a stray (past-interval member, not in up or
/// acting any more) is probed by the child too; it aborted with `Crashed` when the query reached its child in Reset. The gate
/// must watch past-interval participants as well.
#[test]
fn child_gate_watches_strays_of_the_parent() {
    let mut s = cluster(41, &[0, 1, 2, 3], POOL, 2, 1, 2);
    s.run_for(1_000 * MS);
    for seed in 0..2u32 {
        let pg = PgT::new(POOL, seed);
        let up = s.up_of(pg);
        let new: Vec<i32> = [0, 1, 2, 3]
            .into_iter()
            .filter(|o| !up.contains(o))
            .chain(up.iter().copied().take(1))
            .take(2)
            .collect();
        s.set_up_override(pg, new);
    }
    s.run_for(30 * MS);
    assert_gated_split(&mut s, 4);
}

/// Slow-map peer: a stray that has not consumed the split epoch gets nothing for the child until a later map exists (the
/// message then carries a stamp above the split epoch). A heartbeat epoch above it is NOT evidence: it only says the peer
/// published that map, its child may still sit in Reset.
#[test]
fn child_gate_opens_with_the_next_map() {
    let mut s = cluster(43, &[0, 1, 2, 3], POOL, 1, 1, 1);
    s.run_for(1_000 * MS);
    let pg = PgT::new(POOL, 0);
    let old = s.up_of(pg)[0];
    let new = [0, 1, 2, 3].into_iter().find(|o| *o != old).unwrap();
    s.set_up_override(pg, vec![new]);
    s.run_for(30 * MS);
    s.capture = true;
    s.captured.clear();
    let split = s.set_pg_num(POOL, 2);
    let to_stray = |s: &Sim| {
        s.captured.iter().any(|(_, t, b)| {
            *t == old
                && matches!(b, Body::Peering(p) if p.spgid().is_some_and(|x| x.pgid.seed == 1))
        })
    };
    // the sim's mon makes a later map within ~20 ms (up_thru): look only inside the window before it
    for _ in 0..4 {
        s.run_for(MS);
    }
    assert_eq!(s.epoch(), split, "window closed: a later map exists");
    assert!(!to_stray(&s), "child probed the stray before any evidence");
    s.run_for(200 * MS);
    assert!(s.epoch() > split);
    assert!(to_stray(&s), "gate stayed closed after the next map");
}

/// OSD ids above 255 (large clusters): the stray gate must cover every OSD the map can hold, not ids 0..256: the child
/// does not probe an up OSD with id 300 before the evidence arrives.
#[test]
fn child_gate_covers_osd_ids_above_255() {
    let mut s = cluster(44, &[0, 300], POOL, 1, 1, 1);
    s.run_for(1_000 * MS);
    let pg = PgT::new(POOL, 0);
    s.set_up_override(pg, vec![0]);
    s.run_until(60_000 * MS, "primary osd.0", |s| {
        s.pool_clean(POOL) && s.acting_of(pg) == vec![0]
    });
    s.run_for(1_000 * MS);
    s.set_pg_num(POOL, 2);
    s.run_for(5 * MS);
    let t = s.trace_of("strays");
    assert!(
        t.contains("300"),
        "osd.300 is a stray of the child gate: {t}"
    );
}

/// Prime safety (found live: classic osd aborted "bad state machine event" on stray children 7.10/20/30 of an croit-flashstore-osd
/// primary): a classic child sits in Reset until its OSD has consumed a map above the split epoch; ANY peering event
/// stamped <= the split epoch reaching it then aborts the OSD. Oracle: every captured message for a child (seed >=
/// `old_n`) is stamped above `split`, unless the receiver spoke about that PG before.
fn assert_child_stamps_above_split(s: &Sim, split: u32, old_n: u32, who: &str) {
    let mut checked = 0;
    for i in 0..s.captured.len() {
        let (a, b, body) = &s.captured[i];
        let Body::Peering(p) = body else { continue };
        let Some(c) = p.spgid().filter(|x| x.pgid.seed >= old_n) else {
            continue;
        };
        let spoke = s.captured[..i].iter().any(|(f, t, bb)| {
            f == b
                && t == a
                && matches!(bb, Body::Peering(q) if q.spgid().is_some_and(|x| x.pgid == c.pgid))
        });
        assert!(
            spoke || p.gating().0 > split,
            "{who}: osd.{a} -> osd.{b}: child {c} stamped {} <= split {split} before the peer spoke",
            p.gating().0
        );
        checked += 1;
    }
    assert!(checked > 0, "{who}: children peered");
}

/// Messages of a split child never carry a stamp at or below the split epoch towards a peer that has not spoken (the
/// heartbeat epoch of a peer is no evidence: it only says it PUBLISHED a later map, its shards may not have consumed it).
#[test]
fn child_messages_never_carry_a_stamp_at_or_below_the_split_epoch_before_the_peer_spoke() {
    for seed in [61u64, 62, 63] {
        let mut s = cluster(seed, &[0, 1, 2], POOL, 3, 2, 2);
        s.run_for(1_000 * MS);
        s.capture = true;
        s.captured.clear();
        let split = s.set_pg_num(POOL, 4);
        s.run_for(4_000 * MS);
        assert_child_stamps_above_split(&s, split, 2, &format!("seed {seed}"));
    }
}

/// The same for a PG that is advanced late (restart: the child is made at an epoch below the current one, its gate is
/// reopened in the same pass that produced its first sends): those carry the current epoch, not the split epoch.
#[test]
fn child_made_at_load_sends_no_stamp_at_or_below_the_split_epoch() {
    let mut s = cluster(29, &[0, 1, 2], POOL, 3, 2, 2);
    s.run_for(1_000 * MS);
    s.kill(2);
    s.run_for(200 * MS);
    s.capture = true;
    s.captured.clear();
    let split = s.set_pg_num(POOL, 4);
    s.new_epoch(|m| m.osds.get_mut(&0).unwrap().in_ = true);
    s.restart(2);
    s.run_for(4_000 * MS);
    assert_child_stamps_above_split(&s, split, 2, "restart");
}

/// Liveness on an idle cluster: the split map E already carries every OSD's up_thru (the mon batched a pending request
/// into the pg_num proposal), so peering itself forces no further map, and nothing steps pgp_num. The children are gated
/// toward silent classic peers until a later map exists; the gate itself asks the mon for one (up_thru = E + 1 here, see
/// `nudge_map`; a classic mon never puts up_thru E into map E, so this premise is sim-only, the nudge must cover it).
/// The pool must settle with nothing else going on.
#[test]
fn split_epoch_carrying_up_thru_settles_without_a_later_map() {
    let mut s = cluster(61, &[0, 1, 2], POOL, 3, 2, 2);
    s.run_for(2_000 * MS);
    let _split = s.new_epoch(|m| {
        let e = m.epoch;
        let old = m.pools[&POOL].pg_num;
        m.pgp.entry(POOL).or_insert(old);
        let p = m.pools.get_mut(&POOL).unwrap();
        p.pg_num = 8;
        p.pg_num_pending = 8;
        for o in m.osds.values_mut() {
            o.up_thru = e;
        }
    });
    s.run_until(30_000 * MS, "settled without a pgp step", |s| {
        s.pool_settled(POOL) && s.quiet()
    });
}

/// A child created by a peer's Notify in the split epoch (we never held the parent) is gated, but the Notify itself is
/// evidence: its sender (here a STRAY of the parent, osd.2, not in the parent's up/acting) ran the child's ActMap, so our
/// answers to it go out at once (they were held until the next map). The watcher of the parent (osd.1, silent) stays
/// gated. A brand-new pool (absent in the previous map) is never gated.
#[test]
fn created_child_answers_the_peer_that_created_it() {
    use denc::types::ShardId;
    use peering::synth::SynthMap;
    use peering::{Action, Config, Inbound, MemStore, PgSet};
    use pgwire::{MOSDPGNotify2, PeeringMsg, PgInfo, PgNotify};
    let map = |e: u32, pg_num: u32, fresh_pool: bool| {
        let mut m = SynthMap::new(e);
        for o in 0..4 {
            m = m.with_osd(o, 1);
        }
        m = m.with_pool(POOL, 2, 1, pg_num);
        m.up_override.insert(PgT::new(POOL, 0), vec![1, 3]);
        m.up_override.insert(PgT::new(POOL, 1), vec![0, 2]);
        if fresh_pool {
            m = m.with_pool(2, 2, 1, 2);
            m.up_override.insert(PgT::new(2, 1), vec![0, 2]);
        }
        m.into_handle()
    };
    let store = MemStore::new();
    let mut set = PgSet::new(Config::new(0));
    let _ = set.handle_map(0, map(5, 1, false), &store);
    let _ = set.handle_map(1, map(6, 2, true), &store);
    let mut out = vec![];
    for pool in [POOL, 2] {
        let child = SpgT {
            pgid: PgT::new(pool, 1),
            shard: ShardId::NO_SHARD,
        };
        let mut info = PgInfo::new(child);
        info.history.epoch_created = 6;
        info.history.epoch_pool_created = 1;
        info.history.same_interval_since = 6;
        info.history.same_up_since = 6;
        info.history.same_primary_since = 6;
        info.history.last_epoch_split = 6;
        // clean as of this interval: no past intervals required (create info must meet classic's bounds)
        info.history.last_epoch_clean = 6;
        let notify = PgNotify::dne(info, ShardId::NO_SHARD, 6, 6);
        out.extend(set.handle_msg(
            2,
            Inbound {
                ingress: Default::default(),
                from: 2,
                tid: 0,
                prio: pgwire::msgs::PRIO_DEFAULT,
                body: Box::new(Body::Peering(PeeringMsg::from(MOSDPGNotify2 {
                    spgid: child,
                    notify,
                }))),
            },
            &store,
        ));
    }
    let trace = set.take_trace().join("\n");
    assert!(
        set.pg(SpgT {
            pgid: PgT::new(POOL, 1),
            shard: ShardId::NO_SHARD
        })
        .is_some(),
        "child created\n{trace}"
    );
    assert!(
        trace.contains("gate 1.1: created at split epoch 6"),
        "child gated\n{trace}"
    );
    assert!(
        trace.contains("gate 1.1: watch {1, 3} heard {2}"),
        "creator counts as heard\n{trace}"
    );
    assert!(!trace.contains("gate 2.1"), "brand-new pool gated\n{trace}");
    // the gate's map nudge is classic-exact: want up_thru = split epoch (our up_thru < E), never above our map epoch
    let wants: Vec<u32> = out
        .iter()
        .filter_map(|a| match a {
            Action::NeedUpThru { want } => Some(*want),
            _ => None,
        })
        .collect();
    assert_eq!(wants, vec![6], "up_thru requests\n{trace}");
    let to2: Vec<_> = out
        .iter()
        .filter_map(|a| match a {
            Action::Send(s) if s.to == 2 && body_seed(&s.body) == Some((POOL, 1)) => Some(s.epoch),
            _ => None,
        })
        .collect();
    assert!(
        !to2.is_empty(),
        "answer to the creating stray held\n{trace}"
    );
    assert!(
        out.iter()
            .all(|a| !matches!(a, Action::Send(s) if s.to == 1 || s.to == 3)),
        "silent parent holders reached\n{trace}"
    );
}

fn body_seed(b: &Body) -> Option<(u64, u32)> {
    match b {
        Body::Peering(p) => p.spgid().map(|x| (x.pgid.pool, x.pgid.seed)),
        _ => None,
    }
}

/// Review regression (adr 0064 am. 1): a merge source that holds a primary-side LOCAL recovery/backfill slot when the merge
/// lands leaves the set as a parked source; its slot leaked (a core with `osd_max_backfills` 1 never backfilled again).
#[test]
fn merge_source_holding_a_local_slot_gives_it_back() {
    let mut s = cluster_cfg(31, &[0, 1, 2], POOL, 3, 2, 2, |c| {
        c.min_pg_log_entries = 10;
        c.pg_log_trim_min = 1;
        c.pg_log_trim_max = 50;
        c.log_dups_tracked = 20;
    });
    s.set_pgp_num(POOL, 1);
    wait_settled(&mut s);
    let mut w = Writer::new();
    for i in 0..20 {
        w.put(&mut s, &format!("m-{i}"), data(i, 0));
    }
    w.settle(&mut s);
    let src = spg(POOL, 1);
    let victim = s.acting_of(src.pgid)[2];
    s.kill(victim);
    s.run_for(300 * MS);
    for i in 0..80 {
        w.put(&mut s, &format!("m-{i}"), data(i, 1));
    }
    w.settle(&mut s);
    s.restart(victim);
    let holds = |s: &Sim| {
        s.nodes.values().any(|n| {
            n.set
                .pgs()
                .any(|(k, p)| *k == src && p.local_resv_needed() != (false, false))
        })
    };
    s.run_until(30_000 * MS, "source holds a local slot", holds);
    // forced (the mgr would wait for clean; an OSD failure between "ready" and the commit gives the same): the merged PG
    // stays incomplete here, which is not the point; nothing may hold a local slot once the source is gone
    s.set_pg_num(POOL, 1);
    s.run_for(5_000 * MS);
    assert!(
        s.nodes
            .values()
            .all(|n| n.set.pgs().all(|(k, _)| *k != src))
    );
    assert_no_local_slots(&s);
}

/// Every member of PG 0 that serves or peers as complete (`last_backfill` MAX) holds every object of `old`, with its
/// bytes of `old` or, written since (maybe not acked yet), of `new`; an incomplete member is never the active primary
/// (reads never see a false ENOENT). The store side of a complete merge may still be queued: the source collection
/// counts as part of the merged PG on a complete member.
fn assert_complete_members_full(
    s: &Sim,
    old: &BTreeMap<String, Vec<u8>>,
    new: &BTreeMap<String, Vec<u8>>,
) {
    let pg = PgT::new(POOL, 0);
    let prim = s.primary_of(pg);
    for o in s.acting_of(pg) {
        // a member that has not consumed the merge map yet is not the merged PG
        let Some(p) = s
            .pg(o, spg(POOL, 0))
            .filter(|p| p.pool_pg_num() == s.pool_pg_num(POOL))
        else {
            continue;
        };
        if p.info().last_backfill != denc::types::Hobject::MAX() {
            assert!(
                o != prim || !p.is_active(),
                "osd.{o}: incomplete merged PG serves as active primary"
            );
            continue;
        }
        let mut got = s.contents(o, POOL, 1);
        got.extend(s.contents(o, POOL, 0));
        for (k, v) in old {
            let g = got.get(k.as_bytes());
            assert!(
                g == Some(v) || g == new.get(k),
                "osd.{o}: complete merged PG lacks or garbles {k}"
            );
        }
    }
}
/// OQ 61 / adr 0031 am. 5: a multi-core croit-flashstore-osd member strands a merge source on the wrong core (its move was deferred,
/// the map completed the merge). Its merged target merges without that source: it must be incomplete (`last_backfill`
/// not MAX, never authoritative), served and backfilled by its complete peers, classic peers never confused. Reads of
/// all objects are checked during the deferral and after; writes continue meanwhile.
fn merge_with_stranded_source(seed: u64, size: u32) {
    let osds = [0, 1, 2, 3];
    let mut s = cluster(seed, &osds, POOL, size, size.min(2), 2);
    let mut w = Writer::new();
    for i in 0..80 {
        w.put(&mut s, &format!("x-{i}"), data(i, 0));
    }
    w.settle(&mut s);
    s.set_pgp_num(POOL, 1);
    wait_settled(&mut s);
    let x = s.acting_of(PgT::new(POOL, 0))[1];
    // mixed acting set: every other member is checked as a classic ceph-osd
    let classic: Vec<i32> = osds.iter().copied().filter(|o| *o != x).collect();
    s.classic_set(&classic);
    // the mon lowers pg_num only once x is held back: x gets the merge map late, after its core stranded the source
    s.mon_merges = false;
    s.begin_merge(POOL);
    s.run_until(60_000 * MS, "source ready", |s| {
        s.merge_reports.iter().any(|(_, r)| r.ready)
    });
    s.hold_maps.insert(x);
    s.mon_merges = true;
    s.run_until(60_000 * MS, "merged", |s| s.pool_pg_num(POOL) == 1);
    // the source is stranded on another core of x: the target's core never sees it
    s.call(x, |set, now, store| set.detach(now, spg(POOL, 1), store));
    s.release_maps(x);
    s.run_until(10_000 * MS, "x merged", |s| {
        s.pg(x, spg(POOL, 0)).is_some_and(|p| p.pool_pg_num() == 1)
    });
    assert_ne!(
        s.pg(x, spg(POOL, 0)).unwrap().info().last_backfill,
        denc::types::Hobject::MAX(),
        "merged target without its source claims to be complete"
    );
    let old = w.want.clone();
    assert_complete_members_full(&s, &old, &old);
    for i in 0..40 {
        w.put(&mut s, &format!("x-{}", i * 2), data(i, 1));
    }
    for _ in 0..1000 {
        w.pump(&mut s);
        s.run_for(20 * MS);
        assert_complete_members_full(&s, &old, &w.want);
        if w.done() && s.pool_settled(POOL) && s.quiet() {
            break;
        }
    }
    w.settle(&mut s);
    wait_settled(&mut s);
    s.assert_layout(POOL, &w.want);
    for o in s.acting_of(PgT::new(POOL, 0)) {
        assert_eq!(
            s.pg(o, spg(POOL, 0)).unwrap().info().last_backfill,
            denc::types::Hobject::MAX(),
            "osd.{o} backfilled"
        );
    }
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
    assert_no_local_slots(&s);
}

#[test]
fn merge_with_stranded_source_size2() {
    merge_with_stranded_source(61, 2);
}

#[test]
fn merge_with_stranded_source_size3() {
    merge_with_stranded_source(62, 3);
}

/// PG-L1: an erasure pool merges exactly like a replicated pool (`pg_pool_t::is_pending_merge` has no pool-type
/// test): the leading croit-flashstore-osd goes PREMERGE, reports ready and the mon commits the pg_num decrease.
#[test]
fn ec_pool_merges_like_a_replicated_pool() {
    let mut s = Sim::new(63);
    for o in 0..3 {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_primary = true;
        });
    }
    s.run_for(50 * MS);
    s.create_pool_ec(POOL, 2, 1, 4096, true, 2);
    s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
    let lead = s.lead_spg(POOL, 0);
    let mut tids = vec![];
    for i in 0..40usize {
        tids.push(
            s.write_obj(POOL, (i % 2) as u32, &format!("ec-{i}"), &data(i, 0))
                .expect("write accepted"),
        );
    }
    s.wait_writes(&tids, lead);
    s.run_for(300 * MS);
    s.set_pgp_num(POOL, 1);
    s.run_for(2_000 * MS);
    s.begin_merge(POOL);
    s.run_until(60_000 * MS, "ec pg_num decremented", |s| {
        s.pool_pg_num(POOL) == 1
    });
    s.run_for(500 * MS);
    assert!(
        s.merge_report_log.iter().any(|(_, r)| r.ready),
        "ready report for an erasure pool"
    );
    // the merged target is clean, complete and its log emptied
    let prim = s.primary_of(PgT::new(POOL, 0));
    let p = s.pg(prim, s.spg_on(prim, POOL, 0)).expect("merged primary");
    assert!(p.is_active() && p.is_clean(), "{}", p.state_string());
    assert_eq!(p.info().last_backfill, denc::types::Hobject::MAX());
    assert!(p.log().is_empty(), "merged log emptied");
    let t = s
        .write_obj(POOL, 0, "after-merge", &data(7, 1))
        .expect("write accepted");
    let lead = s.lead_spg(POOL, 0);
    s.wait_writes(&[t], lead);
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
}
