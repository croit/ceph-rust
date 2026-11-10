// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Randomized fault injection: kills, restarts, partitions, flapping, concurrent writes; at the end
//! the cluster must converge to active+clean with every acknowledged write present and identical
//! replicas, and every OSD's persisted state must equal its in-memory state.
#![expect(clippy::type_complexity)]
mod common;
use common::*;
use denc::types::Eversion;
use std::collections::{BTreeMap, BTreeSet};

struct Model {
    /// latest acked content per (pg seed, name); None = deleted
    acked: BTreeMap<(u32, String), Option<Vec<u8>>>,
    /// submitted, not acked: (seed, tid) -> (name, content)
    pending: BTreeMap<(u32, Eversion), (String, Option<Vec<u8>>)>,
    /// maybe-contents after failures/crashes
    maybe: BTreeMap<(u32, String), Vec<Option<Vec<u8>>>>,
    acked_seen: usize,
    failed_seen: usize,
}

impl Model {
    fn sync(&mut self, s: &Sim) {
        for (sp, _tid, ver) in &s.acked[self.acked_seen..] {
            let key = (sp.pgid.seed, *ver);
            if let Some((name, content)) = self.pending.remove(&key) {
                // earlier pending writes of the same pg are subsumed (acks are in version order)
                let older: Vec<_> = self
                    .pending
                    .range((sp.pgid.seed, Eversion::default())..key)
                    .map(|(k, _)| *k)
                    .collect();
                for k in older {
                    let (n, c) = self.pending.remove(&k).unwrap();
                    self.maybe.entry((k.0, n)).or_default().push(c);
                }
                self.maybe.remove(&(sp.pgid.seed, name.clone()));
                self.acked.insert((sp.pgid.seed, name), content);
            }
        }
        self.acked_seen = s.acked.len();
        for (sp, _tid, ver) in &s.failed[self.failed_seen..] {
            if let Some((name, content)) = self.pending.remove(&(sp.pgid.seed, *ver)) {
                self.maybe
                    .entry((sp.pgid.seed, name))
                    .or_default()
                    .push(content);
            }
        }
        self.failed_seen = s.failed.len();
    }
}

fn chaos(seed: u64, n_osds: i32, size: u32, min_size: u32, steps: usize) {
    let small = std::env::var("CHAOS_SMALL").is_ok();
    chaos_cfg(seed, n_osds, size, min_size, steps, small);
}

fn chaos_cfg(seed: u64, n_osds: i32, size: u32, min_size: u32, steps: usize, small: bool) {
    let dup = std::env::var("CHAOS_DUP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    chaos_dup(seed, n_osds, size, min_size, steps, small, dup);
}

/// `dup` = percent of peer messages delivered twice (the second copy later, after newer messages).
fn chaos_dup(
    seed: u64,
    n_osds: i32,
    size: u32,
    min_size: u32,
    steps: usize,
    small: bool,
    dup: u64,
) {
    // `CHAOS_SEED_ADD=1000` shifts every seed (wider local soaks)
    let seed = seed
        + std::env::var("CHAOS_SEED_ADD")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
    let osds: Vec<i32> = (0..n_osds).collect();
    let mut s = cluster_cfg(seed, &osds, 1, size, min_size, 3, |c| {
        if small {
            c.min_pg_log_entries = 8;
            c.pg_log_trim_min = 1;
            c.pg_log_trim_max = 30;
            c.log_dups_tracked = 12;
        }
    });
    s.dup_percent = dup;
    if dup > 0 {
        // msgr2 never delivers a message twice to a classic OSD: duplicates probe croit-flashstore-osd, not the classic model
        s.classic_off();
    }
    s.dup_kind = std::env::var("CHAOS_DUP_KIND")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if std::env::var("CHAOS_TRACE").is_ok() {
        s.dump_lines = 300;
    }
    let mut rng = Rng::new(seed ^ 0xABCDEF);
    let mut m = Model {
        acked: BTreeMap::new(),
        pending: BTreeMap::new(),
        maybe: BTreeMap::new(),
        acked_seen: 0,
        failed_seen: 0,
    };
    let mut dead: BTreeSet<i32> = BTreeSet::new();
    let mut out: BTreeSet<i32> = BTreeSet::new();
    let mut counter = 0u64;
    for _ in 0..steps {
        match rng.range(0, 10) {
            0..=5 => {
                // a few writes
                for _ in 0..rng.range(1, 4) {
                    let pgseed = rng.range(0, 2) as u32;
                    let name = format!("obj{}", rng.range(0, 9));
                    counter += 1;
                    if rng.range(0, 5) == 0 {
                        if s.delete_obj(1, pgseed, &name).is_ok() {
                            m.pending.insert((pgseed, s.last_version), (name, None));
                        }
                    } else {
                        let len = rng.range(1, 600) as usize;
                        let d: Vec<u8> = (0..len)
                            .map(|j| ((counter as usize + j) % 251) as u8)
                            .collect();
                        if s.write_obj(1, pgseed, &name, &d).is_ok() {
                            m.pending.insert((pgseed, s.last_version), (name, Some(d)));
                        }
                    }
                }
                s.run_for(rng.range(0, 40) * MS);
            }
            6 => {
                // kill (never below size-1 live OSDs so min_size writes stay possible most of the time)
                let live: Vec<i32> = osds.iter().copied().filter(|o| !dead.contains(o)).collect();
                if live.len() as u32 > min_size {
                    let v = live[rng.range(0, live.len() as u64 - 1) as usize];
                    s.kill(v);
                    dead.insert(v);
                }
                s.run_for(rng.range(0, 200) * MS);
            }
            7 => {
                if let Some(&v) = dead.iter().next() {
                    s.restart(v);
                    dead.remove(&v);
                }
                s.run_for(rng.range(0, 300) * MS);
            }
            9 if small => {
                let o = osds[rng.range(0, osds.len() as u64 - 1) as usize];
                if out.contains(&o) {
                    s.mark_in(o);
                    out.remove(&o);
                } else if out.is_empty() {
                    s.mark_out(o);
                    out.insert(o);
                }
                s.run_for(rng.range(0, 100) * MS);
            }
            8 => {
                // short partition between two live OSDs
                let live: Vec<i32> = osds.iter().copied().filter(|o| !dead.contains(o)).collect();
                if live.len() >= 2 {
                    let a = live[rng.range(0, live.len() as u64 - 1) as usize];
                    let b = live[rng.range(0, live.len() as u64 - 1) as usize];
                    if a != b {
                        s.partition(a, b);
                        s.run_for(rng.range(1, 100) * MS);
                        s.heal();
                    }
                }
            }
            _ => {
                s.run_for(rng.range(1, 100) * MS);
            }
        }
        m.sync(&s);
    }
    // converge: heal, restart everyone
    s.heal();
    for d in dead.clone() {
        s.restart(d);
    }
    for o in out.clone() {
        s.mark_in(o);
    }
    s.run_until(120_000 * MS, "converged", |s| s.pool_clean(1));
    s.run_for(2000 * MS);
    m.sync(&s);
    assert!(s.pool_clean(1), "{}", s.dump());
    s.assert_no_roundtrip_mismatch();
    s.assert_persisted_consistent();
    // identical replicas; every acked write present (or superseded by a possible later write)
    for pgseed in 0..3u32 {
        let pg = pgwire_pg(1, pgseed);
        let acting = s.acting_of(pg);
        let base = s.contents(acting[0], 1, pgseed);
        for o in &acting[1..] {
            let got = s.contents(*o, 1, pgseed);
            if got != base {
                let diff: Vec<String> = base
                    .keys()
                    .chain(got.keys())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .filter(|k| base.get(*k) != got.get(*k))
                    .map(|k| {
                        format!(
                            "{} osd{}={:?} osd{o}={:?}",
                            String::from_utf8_lossy(k),
                            acting[0],
                            base.get(k).map(|v| (v.len(), v.first().copied())),
                            got.get(k).map(|v| (v.len(), v.first().copied()))
                        )
                    })
                    .collect();
                panic!(
                    "seed {seed}: replicas differ in pg 1.{pgseed}: {diff:?}\n{}",
                    s.dump()
                );
            }
        }
        for ((ps, name), want) in &m.acked {
            if *ps != pgseed {
                continue;
            }
            let got = base.get(name.as_bytes()).cloned();
            let mut ok = got == *want;
            if !ok && let Some(alts) = m.maybe.get(&(*ps, name.clone())) {
                ok = alts.contains(&got);
            }
            if !ok {
                // a later unacked write may have survived
                for ((pps, _), (n, c)) in &m.pending {
                    if pps == ps && n == name && *c == got {
                        ok = true;
                    }
                }
            }
            assert!(
                ok,
                "seed {seed}: pg 1.{pgseed} object {name}: acked write lost (got {:?} bytes; acked {:?}; maybe {:?}; pending {:?})\n{}",
                got.map(|g| g.len()),
                want.as_ref().map(|w| w.len()),
                m.maybe.get(&(*ps, name.clone())).map(|v| v
                    .iter()
                    .map(|x| x.as_ref().map(|y| y.len()))
                    .collect::<Vec<_>>()),
                m.pending
                    .iter()
                    .filter(|(k, v)| k.0 == *ps && v.0 == *name)
                    .map(|(k, v)| (k.1.to_string(), v.1.as_ref().map(|y| y.len())))
                    .collect::<Vec<_>>(),
                s.dump()
            );
        }
        // no pg member has leftover temp objects or missing entries
        for o in &acting {
            let p = s.pg(*o, spg(1, pgseed)).unwrap();
            assert!(
                p.missing().is_empty(),
                "seed {seed}: osd.{o} still missing objects"
            );
            assert_eq!(
                s.nodes[o].store.temp_objects(spg(1, pgseed)),
                0,
                "seed {seed}: temp objects left on osd.{o}"
            );
        }
    }
}

fn pgwire_pg(pool: u64, seed: u32) -> denc::types::PgT {
    denc::types::PgT::new(pool, seed)
}

#[test]
fn chaos_size3_four_osds() {
    for seed in 1..=40 {
        chaos(seed, 4, 3, 2, 60);
    }
}

#[test]
fn chaos_size3_three_osds() {
    for seed in 100..=130 {
        chaos(seed, 3, 3, 2, 60);
    }
}

#[test]
fn chaos_size2() {
    for seed in 200..=220 {
        chaos(seed, 3, 2, 1, 50);
    }
}

#[test]
fn chaos_small_logs_backfill() {
    for seed in 400..=430 {
        chaos_cfg(seed, 4, 3, 2, 100, true);
    }
    for seed in 500..=520 {
        chaos_cfg(seed, 3, 2, 1, 100, true);
    }
}

#[test]
fn chaos_size1() {
    for seed in 300..=310 {
        chaos(seed, 1, 1, 1, 30);
    }
}

/// Reproduce one run: CHAOS_SEED=.. CHAOS_OSDS=.. CHAOS_SIZE=.. CHAOS_MIN=.. CHAOS_STEPS=..
#[test]
#[ignore]
fn chaos_one() {
    let g = |k: &str, d: u64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    chaos(
        g("CHAOS_SEED", 1),
        g("CHAOS_OSDS", 3) as i32,
        g("CHAOS_SIZE", 3) as u32,
        g("CHAOS_MIN", 2) as u32,
        g("CHAOS_STEPS", 60) as usize,
    );
}

/// Wide sweep: CHAOS_FROM/CHAOS_TO seeds with the given shape (ignored by default).
#[test]
#[ignore]
fn chaos_sweep() {
    let g = |k: &str, d: u64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    for seed in g("CHAOS_FROM", 1)..=g("CHAOS_TO", 100) {
        chaos(
            seed,
            g("CHAOS_OSDS", 3) as i32,
            g("CHAOS_SIZE", 3) as u32,
            g("CHAOS_MIN", 2) as u32,
            g("CHAOS_STEPS", 60) as usize,
        );
    }
}

#[test]
#[ignore]
fn chaos_probe() {
    // helper to inspect a failing run: re-run and print the missing objects and who has them
    let g = |k: &str, d: u64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let r = std::panic::catch_unwind(|| {
        chaos(
            g("CHAOS_SEED", 1),
            g("CHAOS_OSDS", 3) as i32,
            g("CHAOS_SIZE", 3) as u32,
            g("CHAOS_MIN", 2) as u32,
            g("CHAOS_STEPS", 60) as usize,
        );
    });
    let _ = r;
}

/// Duplicated peer messages (what replaying sent-unacked frames after a session reset would do; the duplicate arrives
/// after its original, `CHAOS_DUP_TY` filters by message type for bisecting): handlers ignore duplicates.
#[test]
fn chaos_duplicated_messages() {
    for seed in 600..=625 {
        chaos_dup(seed, 4, 3, 2, 60, false, 25);
    }
    for seed in 700..=715 {
        chaos_dup(seed, 3, 2, 1, 60, false, 40);
    }
}

#[test]
fn chaos_duplicated_messages_small_logs_backfill() {
    for seed in 800..=815 {
        chaos_dup(seed, 4, 3, 2, 100, true, 25);
    }
}
