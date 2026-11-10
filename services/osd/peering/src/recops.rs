// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! OSD-wide recovery-op budget `osd_recovery_max_active` (adr 0031 am. 10, spec replication.md 7.5): the number of
//! recovery / backfill object ops (pull, push, delete) in flight on the whole OSD. Three levels, no lock and no message
//! per op:
//!
//! * [`OpsOwner`] (control core): the limit and the quota each core holds. Quota moves only on demand.
//! * [`OpsLease`] (every core): the core's quota, split over its PGs as leases. A PG starts an op only below its
//!   lease (`Pg::rec.cap`), so the core never exceeds its quota and the OSD never exceeds the limit.
//! * Fairness: while anybody waits (a PG on this core, or a core at the owner) every lease is pinned to the ops in
//!   flight, so a finished op frees its unit for the first waiter instead of refilling its own PG (round robin per
//!   op, like classic's FIFO of PGs awaiting the throttle); with no waiter a PG refills itself freely.

use denc::types::SpgT;
use std::collections::{BTreeMap, VecDeque};

/// Core -> owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpsMsg {
    /// This many more units are wanted (queued FIFO per core).
    Want(u32),
    /// This many idle units go back.
    Return(u32),
}

/// Core -> owner, in order per sender (one lane).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpsReq {
    pub from: u32,
    pub msg: OpsMsg,
}

/// Owner -> core: units granted (0 = news only) and whether somebody waits for units (leases are pinned, idle quota
/// goes back).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpsReply {
    pub grant: u32,
    pub contended: bool,
}

/// The limit and the quota of every core, kept by one core.
#[derive(Debug, Default)]
pub(crate) struct OpsOwner {
    limit: usize,
    quota: BTreeMap<u32, usize>,
    want: VecDeque<(u32, usize)>,
    /// What each core was last told ([`OpsReply::contended`]).
    told: BTreeMap<u32, bool>,
}

impl OpsOwner {
    pub fn new(limit: usize) -> Self {
        OpsOwner {
            limit: limit.max(1),
            ..OpsOwner::default()
        }
    }
    /// `osd_recovery_max_active` changed: a lower limit is reached as the cores give units back.
    pub fn set_limit(&mut self, limit: usize, out: &mut Vec<(u32, OpsReply)>) {
        self.limit = limit.max(1);
        self.dispatch(out);
    }
    pub fn apply(&mut self, req: OpsReq, out: &mut Vec<(u32, OpsReply)>) {
        match req.msg {
            OpsMsg::Want(n) => {
                if let Some(w) = self.want.iter_mut().find(|w| w.0 == req.from) {
                    w.1 += n as usize;
                } else {
                    self.want.push_back((req.from, n as usize));
                }
            }
            OpsMsg::Return(n) => {
                if let Some(q) = self.quota.get_mut(&req.from) {
                    *q = q.saturating_sub(n as usize);
                    if *q == 0 {
                        self.quota.remove(&req.from);
                    }
                }
            }
        }
        self.dispatch(out);
    }
    fn total(&self) -> usize {
        self.quota.values().sum()
    }
    /// Units held by the cores (the sum never exceeds `limit` outside a limit decrease) and the limit.
    pub fn granted(&self) -> (usize, usize) {
        (self.total(), self.limit)
    }
    fn dispatch(&mut self, out: &mut Vec<(u32, OpsReply)>) {
        let mut free = self.limit.saturating_sub(self.total());
        let mut grants: Vec<(u32, usize)> = Vec::new();
        while free > 0 {
            let Some(w) = self.want.front_mut() else {
                break;
            };
            let g = w.1.min(free);
            free -= g;
            w.1 -= g;
            let c = w.0;
            if w.1 == 0 {
                self.want.pop_front();
            }
            *self.quota.entry(c).or_default() += g;
            grants.push((c, g));
        }
        // "contended" for a core = somebody ELSE waits (or the limit was lowered): its own wish is no reason to pin it
        let over = self.total() > self.limit;
        let cores: Vec<u32> = self.quota.keys().copied().collect();
        for c in cores {
            let contended = over || self.want.iter().any(|w| w.0 != c);
            let grant = grants
                .iter()
                .filter(|g| g.0 == c)
                .map(|g| g.1)
                .sum::<usize>();
            let told = self.told.insert(c, contended).unwrap_or(false);
            if grant > 0 || told != contended {
                out.push((
                    c,
                    OpsReply {
                        grant: grant as u32,
                        contended,
                    },
                ));
            }
        }
    }
}

/// Set the units of `spg` to `n` (`0` removes the entry) and answer the units it held before.
fn set(map: &mut BTreeMap<SpgT, usize>, spg: SpgT, n: usize) -> usize {
    if n == 0 {
        map.remove(&spg).unwrap_or(0)
    } else {
        map.insert(spg, n).unwrap_or(0)
    }
}

/// One core's quota and its split over the PGs of the core.
#[derive(Debug, Default)]
pub(crate) struct OpsLease {
    quota: usize,
    /// Units each PG holds: its lease, or the ops it still has in flight above a lowered lease.
    held: BTreeMap<SpgT, usize>,
    sum_held: usize,
    /// Ops each PG has in flight (as of its last sync), their sum and the highest sum seen (diagnostics: the lab
    /// check reads the peak, a once-a-second sample misses short recoveries).
    running: BTreeMap<SpgT, usize>,
    sum_running: usize,
    peak_running: usize,
    /// PGs that stopped at their lease with work left, in the order they asked.
    waiters: VecDeque<SpgT>,
    /// Units asked of the owner and not granted yet.
    asked: usize,
    /// The owner says somebody else waits for units.
    contended: bool,
    /// Units that came from the owner since the last pump: they are for this core's waiters. Units the PGs gave back go
    /// to the owner while somebody else waits (round robin per op across cores).
    fresh: usize,
}

impl OpsLease {
    fn free(&self) -> usize {
        self.quota.saturating_sub(self.sum_held)
    }
    /// Somebody else waits (another PG here, or at the owner): `spg`'s lease stays at the ops it has in flight.
    fn pinned_for(&self, spg: SpgT) -> bool {
        self.contended || self.waiters.iter().any(|s| *s != spg)
    }
    /// Units held by this core's PGs.
    pub fn held_total(&self) -> usize {
        self.sum_held
    }
    pub fn quota(&self) -> usize {
        self.quota
    }
    /// Highest number of ops in flight over this core's PGs at once, since start.
    pub fn peak_running(&self) -> usize {
        self.peak_running
    }
    fn set_running(&mut self, spg: SpgT, n: usize) {
        let old = set(&mut self.running, spg, n);
        self.sum_running = self.sum_running + n - old;
        self.peak_running = self.peak_running.max(self.sum_running);
    }
    /// A PG's state after an event: `inflight` ops, lease `cap`, `wants` = it stopped at the lease with work left.
    /// Returns the lease the PG keeps (a PG that wants nothing, or any PG while somebody waits, keeps only what it has in
    /// flight).
    pub fn sync(&mut self, spg: SpgT, inflight: usize, cap: usize, wants: bool) -> usize {
        let cap = if !wants || self.pinned_for(spg) {
            cap.min(inflight)
        } else {
            cap
        };
        self.set_held(spg, cap.max(inflight));
        self.set_running(spg, inflight);
        let at = self.waiters.iter().position(|s| *s == spg);
        match (wants, at) {
            (true, None) => self.waiters.push_back(spg),
            (false, Some(i)) => {
                self.waiters.remove(i);
            }
            _ => {}
        }
        cap
    }
    /// The PG is gone (removed, moved, reset): its units go back to the core.
    pub fn forget(&mut self, spg: SpgT) {
        self.set_held(spg, 0);
        self.set_running(spg, 0);
        self.waiters.retain(|s| *s != spg);
    }
    fn set_held(&mut self, spg: SpgT, n: usize) {
        let old = set(&mut self.held, spg, n);
        self.sum_held = self.sum_held + n - old;
    }
    /// Units from the owner.
    pub fn grant(&mut self, r: OpsReply) {
        self.quota += r.grant as usize;
        self.asked = self.asked.saturating_sub(r.grant as usize);
        self.fresh += r.grant as usize;
        self.contended = r.contended;
    }
    /// Something to do: PGs wait, or idle units must go back.
    pub fn needs_pump(&self) -> bool {
        (!self.waiters.is_empty() && (self.free() > 0 || self.waiters.len() > self.asked))
            || (self.contended && self.free() > 0)
    }
    /// Hand units to the waiting PGs in order (an even share each, a lone PG all of it; a PG that cannot use them gives them
    /// back at its next sync) and say what the owner must hear: more units wanted, idle units returned. While nobody else waits
    /// every free unit is offered; otherwise only the ones the owner just granted, the rest goes back. `grants` = the PGs
    /// and their new lease, to run again.
    pub fn pump(&mut self, grants: &mut Vec<(SpgT, usize)>, msgs: &mut Vec<OpsMsg>) {
        let mut offer = if self.contended {
            self.fresh.min(self.free())
        } else {
            self.free()
        };
        self.fresh = 0;
        while offer > 0 && !self.waiters.is_empty() {
            let share = offer.div_ceil(self.waiters.len());
            let Some(spg) = self.waiters.pop_front() else {
                break;
            };
            let lease = self.held.get(&spg).copied().unwrap_or(0) + share;
            self.set_held(spg, lease);
            grants.push((spg, lease));
            offer -= share;
        }
        if self.waiters.len() > self.asked {
            msgs.push(OpsMsg::Want((self.waiters.len() - self.asked) as u32));
            self.asked = self.waiters.len();
        }
        if self.contended && self.free() > 0 {
            let idle = self.free();
            self.quota -= idle;
            msgs.push(OpsMsg::Return(idle as u32));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spg(c: u32, n: u32) -> SpgT {
        SpgT {
            pgid: denc::types::PgT::new(1, c * 1000 + n),
            shard: denc::types::ShardId::NO_SHARD,
        }
    }

    /// A simulated PG: `work` ops left to start, `inflight` running, a lease.
    struct SimPg {
        spg: SpgT,
        work: usize,
        inflight: usize,
        cap: usize,
        wants: bool,
    }
    impl SimPg {
        /// The PG's recovery pass: start ops below the lease.
        fn step(&mut self) {
            self.wants = false;
            while self.work > 0 {
                if self.inflight >= self.cap {
                    self.wants = true;
                    break;
                }
                self.work -= 1;
                self.inflight += 1;
            }
        }
    }

    struct SimCore {
        id: u32,
        lease: OpsLease,
        pgs: Vec<SimPg>,
    }
    impl SimCore {
        fn sync(&mut self, i: usize) {
            let p = &mut self.pgs[i];
            p.cap = self.lease.sync(p.spg, p.inflight, p.cap, p.wants);
        }
        /// Pump: lease the free units to waiters and rerun them; returns the messages for the owner.
        fn pump(&mut self) -> Vec<OpsReq> {
            let mut all = Vec::new();
            loop {
                let (mut grants, mut msgs) = (Vec::new(), Vec::new());
                self.lease.pump(&mut grants, &mut msgs);
                all.extend(msgs.into_iter().map(|msg| OpsReq { from: self.id, msg }));
                if grants.is_empty() {
                    return all;
                }
                for (s, lease) in grants {
                    let i = self.pgs.iter().position(|p| p.spg == s).unwrap();
                    self.pgs[i].cap = lease;
                    self.pgs[i].step();
                    self.sync(i);
                }
            }
        }
        fn inflight(&self) -> usize {
            self.pgs.iter().map(|p| p.inflight).sum()
        }
    }

    /// Deterministic xorshift.
    fn rnd(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    /// 8 cores, uneven PGs (one core has all the work first), random op completions and message delays: the ops in flight
    /// never exceed the limit, every PG finishes (liveness), and every unit is back at the owner at the end (no leak).
    fn run(limit: usize, seed: u64, change_limit: bool) {
        let mut rng = seed | 1;
        let mut owner = OpsOwner::new(limit);
        let mut cores: Vec<SimCore> = (0..8)
            .map(|c| SimCore {
                id: c,
                lease: OpsLease::default(),
                pgs: (0..(1 + c % 3))
                    .map(|n| SimPg {
                        spg: spg(c, n),
                        work: if c < 2 { 200 } else { 30 },
                        inflight: 0,
                        cap: 0,
                        wants: false,
                    })
                    .collect(),
            })
            .collect();
        // in-order lanes: core -> owner, owner -> core
        let mut up: Vec<VecDeque<OpsReq>> = vec![VecDeque::new(); 8];
        let mut down: Vec<VecDeque<OpsReply>> = vec![VecDeque::new(); 8];
        let mut max_limit = limit;
        for step in 0..200_000u32 {
            let c = (rnd(&mut rng) % 8) as usize;
            match rnd(&mut rng) % 6 {
                // a PG's event: its pass runs, then sync and pump
                0 | 1 => {
                    let n = cores[c].pgs.len();
                    let i = (rnd(&mut rng) as usize) % n;
                    cores[c].pgs[i].step();
                    cores[c].sync(i);
                    let m = cores[c].pump();
                    up[c].extend(m);
                }
                // an op completes
                2 | 3 => {
                    let n = cores[c].pgs.len();
                    let i = (rnd(&mut rng) as usize) % n;
                    if cores[c].pgs[i].inflight > 0 {
                        cores[c].pgs[i].inflight -= 1;
                        cores[c].pgs[i].step();
                        cores[c].sync(i);
                        let m = cores[c].pump();
                        up[c].extend(m);
                    }
                }
                // delivery to the owner
                4 => {
                    if let Some(r) = up[c].pop_front() {
                        let mut out = Vec::new();
                        owner.apply(r, &mut out);
                        for (core, rep) in out {
                            down[core as usize].push_back(rep);
                        }
                    }
                }
                // delivery to a core
                _ => {
                    if let Some(r) = down[c].pop_front() {
                        cores[c].lease.grant(r);
                        let m = cores[c].pump();
                        up[c].extend(m);
                    }
                }
            }
            if change_limit && step % 5000 == 2500 {
                let cur = 1 + (rnd(&mut rng) % 12) as usize;
                max_limit = max_limit.max(cur);
                let mut out = Vec::new();
                owner.set_limit(cur, &mut out);
                for (core, rep) in out {
                    down[core as usize].push_back(rep);
                }
            }
            let total: usize = cores.iter().map(|c| c.inflight()).sum();
            // a lowered limit is reached as ops finish: only the unchanged limit is a hard bound at every step
            if !change_limit {
                assert!(
                    total <= limit,
                    "seed {seed}: {total} ops in flight > limit {limit}"
                );
            }
            for c in &cores {
                assert!(c.lease.held_total() <= c.lease.quota() || c.inflight() > c.lease.quota());
            }
            assert!(owner.granted().0 <= max_limit);
        }
        // drain: deliver everything, complete everything
        for _ in 0..1_000_000u32 {
            let mut busy = false;
            for c in 0..8 {
                for i in 0..cores[c].pgs.len() {
                    if cores[c].pgs[i].inflight > 0 {
                        cores[c].pgs[i].inflight -= 1;
                        busy = true;
                    }
                    cores[c].pgs[i].step();
                    cores[c].sync(i);
                    let m = cores[c].pump();
                    up[c].extend(m);
                }
                while let Some(r) = up[c].pop_front() {
                    busy = true;
                    let mut out = Vec::new();
                    owner.apply(r, &mut out);
                    for (core, rep) in out {
                        down[core as usize].push_back(rep);
                    }
                }
                while let Some(r) = down[c].pop_front() {
                    busy = true;
                    cores[c].lease.grant(r);
                    let m = cores[c].pump();
                    up[c].extend(m);
                }
            }
            if !busy && cores.iter().all(|c| c.pgs.iter().all(|p| p.work == 0)) {
                break;
            }
        }
        assert!(
            cores
                .iter()
                .all(|c| c.pgs.iter().all(|p| p.work == 0 && p.inflight == 0)),
            "seed {seed}: a PG never finished"
        );
        // all PGs idle: every lease and quota unit is back (the owner may still hold a hoard on cores while uncontended)
        for c in &cores {
            assert_eq!(c.lease.held_total(), 0, "seed {seed}: leaked lease units");
        }
        let hoard: usize = cores.iter().map(|c| c.lease.quota()).sum();
        assert_eq!(
            owner.granted().0,
            hoard,
            "seed {seed}: owner and cores disagree on the quota"
        );
    }

    #[test]
    fn osd_wide_limit_never_exceeded_on_8_cores() {
        for (limit, seed) in [(1, 1), (3, 2), (10, 3), (10, 4), (24, 5)] {
            run(limit, seed, false);
        }
    }

    #[test]
    fn runtime_limit_changes_apply_and_nothing_leaks() {
        for seed in 1..6 {
            run(5, seed * 7919, true);
        }
    }

    /// One core, one PG, nobody else: it ramps up to the limit (one unit per round trip while it stops at its lease), then
    /// keeps its lease and refills itself in its own pass: no message, no kick, never pinned by its own wish.
    #[test]
    fn lone_pg_ramps_up_then_runs_without_messages() {
        let mut o = OpsOwner::new(4);
        let mut l = OpsLease::default();
        let s = spg(0, 0);
        let mut cap = 0;
        for _ in 0..10 {
            cap = l.sync(s, cap, cap, true);
            let (mut g, mut m) = (Vec::new(), Vec::new());
            l.pump(&mut g, &mut m);
            for msg in m {
                let mut out = Vec::new();
                o.apply(OpsReq { from: 0, msg }, &mut out);
                for (_, r) in out {
                    l.grant(r);
                }
            }
            let (mut g2, mut m2) = (Vec::new(), Vec::new());
            l.pump(&mut g2, &mut m2);
            if let Some((_, lease)) = g2.last() {
                cap = *lease;
            }
        }
        assert_eq!(cap, 4, "the whole limit");
        for _ in 0..100 {
            // an op completed and the pass refilled it: inflight == lease, still wanting
            assert_eq!(l.sync(s, 4, 4, true), 4, "not pinned by its own wish");
            let (mut g, mut m) = (Vec::new(), Vec::new());
            l.pump(&mut g, &mut m);
            assert!(g.is_empty() && m.is_empty());
        }
        // the work is issued: the lease shrinks to what runs and goes back as the ops finish
        assert_eq!(l.sync(s, 2, 4, false), 2);
        assert_eq!(l.sync(s, 0, 2, false), 0);
        assert_eq!(l.held_total(), 0);
    }

    /// Two cores, limit 1: the second waits at the owner, the first (told that somebody waits) gives the unit back as its
    /// op completes instead of refilling.
    #[test]
    fn a_waiting_core_gets_the_unit_when_the_op_completes() {
        let mut o = OpsOwner::new(1);
        let mut out = Vec::new();
        o.apply(
            OpsReq {
                from: 0,
                msg: OpsMsg::Want(1),
            },
            &mut out,
        );
        assert_eq!(out.len(), 1);
        let mut c0 = OpsLease::default();
        c0.grant(out[0].1);
        c0.pump(&mut Vec::new(), &mut Vec::new());
        out.clear();
        o.apply(
            OpsReq {
                from: 1,
                msg: OpsMsg::Want(1),
            },
            &mut out,
        );
        assert_eq!(
            out,
            vec![(
                0,
                OpsReply {
                    grant: 0,
                    contended: true
                }
            )],
            "core 1 waits, core 0 is told; core 1's own wish does not pin core 1"
        );
        c0.grant(out[0].1);
        let s = spg(0, 0);
        // core 0's PG runs one op with the lease, then completes it and wants more
        c0.set_held(s, 1);
        assert_eq!(c0.sync(s, 1, 1, true), 1);
        assert_eq!(
            c0.sync(s, 0, 1, true),
            0,
            "pinned: the lease follows the ops in flight"
        );
        let (mut g, mut m) = (Vec::new(), Vec::new());
        c0.pump(&mut g, &mut m);
        assert!(g.is_empty(), "the freed unit does not refill the own PG");
        assert_eq!(
            m,
            vec![OpsMsg::Want(1), OpsMsg::Return(1)],
            "it goes back to the owner"
        );
        out.clear();
        o.apply(
            OpsReq {
                from: 0,
                msg: OpsMsg::Return(1),
            },
            &mut out,
        );
        assert_eq!(
            out,
            vec![(
                1,
                OpsReply {
                    grant: 1,
                    contended: false
                }
            )],
            "core 1 is granted"
        );
    }
}
