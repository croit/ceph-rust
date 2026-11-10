// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! OSD-wide resource budgets (adr 0083 am. 4, adr 0031 am. 9): `osd_max_scrubs` (local scrubs and replica
//! reservations), `osd_max_backfills` (primary-side local and replica-side remote reservations, backfill and
//! recovery pools) and `osd_max_trimming_pgs`. Classic bounds the whole OSD; a budget divided over the PG cores would
//! run N times the configured load. ONE core (the control core, or the only core) keeps all counters ([`Slots`]),
//! the other cores reach it by message ([`SlotReq`] / [`SlotReply`]). A start or end of such work is rare, so the
//! round trip costs nothing on any hot path and no lock or shared counter exists.

use crate::pg::Pg;
use crate::types::*;
use denc::types::SpgT;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// What a reserver did to an item: handed it a slot, or took its slot away for a higher priority one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResvEv {
    Grant(SpgT, bool),
    Preempt(SpgT, bool),
}

/// One waiting request: highest priority first, FIFO within a priority (`Reverse(seq)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Queued {
    prio: u32,
    seq: std::cmp::Reverse<u64>,
    spg: SpgT,
}

/// One side's backfill / recovery reserver (classic `local_reserver` / `remote_reserver`): `osd_max_backfills` slots shared by
/// backfill AND log-based recovery, queued by priority (highest first, FIFO within), a queued request of a higher priority
/// than the lowest granted one takes that slot away (preemption, spec replication.md 7.3), items below
/// `osd_min_recovery_priority` wait / lose their slot.
///
/// The queue is a heap on `(priority, arrival)` with `queued` as its index: granting is one pop, queueing and releasing
/// are O(log n). An entry a re-request superseded (new priority or arrival) or a release dropped stays in the heap as a
/// stale one and is skipped when it surfaces (`compact` rebuilds the heap when stale ones dominate).
#[derive(Debug, Default)]
pub(crate) struct Reserver {
    max: usize,
    min_prio: u32,
    /// Slot holders: `(priority, is_backfill)`.
    granted: BTreeMap<SpgT, (u32, bool)>,
    /// Waiting: highest priority first, FIFO within a priority.
    queue: std::collections::BinaryHeap<Queued>,
    /// The current heap entry of every waiting PG: `(priority, arrival, is_backfill)`.
    queued: BTreeMap<SpgT, (u32, u64, bool)>,
    seq: u64,
    /// Heap entries examined (tests: the grant path never walks the whole queue).
    #[cfg(test)]
    pub(crate) scans: usize,
}

impl Reserver {
    fn new(max: usize) -> Self {
        Reserver {
            max,
            ..Reserver::default()
        }
    }
    /// Queue `spg` (a held or queued item is left alone) and run the queues.
    fn request(&mut self, spg: SpgT, prio: u32, backfill: bool) -> Vec<ResvEv> {
        if self.granted.contains_key(&spg) || self.queued.contains_key(&spg) {
            return Vec::new();
        }
        self.seq += 1;
        let seq = self.seq;
        self.queue.push(Queued {
            prio,
            seq: std::cmp::Reverse(seq),
            spg,
        });
        self.queued.insert(spg, (prio, seq, backfill));
        self.do_queues()
    }
    /// Primary-side request of an item that may already be known: a queued one moves to the back of its new priority, a
    /// held one takes the priority (a lowered one may be preempted by what waits) and is granted again.
    fn local_request(&mut self, spg: SpgT, prio: u32, backfill: bool) -> Vec<ResvEv> {
        if let Some(g) = self.granted.get_mut(&spg) {
            // the holder's kind follows its request: a later preemption names the pool the PG asks under now
            *g = (prio, backfill);
            let mut ev = self.do_queues();
            if !ev
                .iter()
                .any(|e| matches!(e, ResvEv::Preempt(s, _) if *s == spg))
            {
                ev.push(ResvEv::Grant(spg, backfill));
            }
            return ev;
        }
        if let Some(q) = self.queued.get_mut(&spg) {
            q.2 = backfill;
            if q.0 != prio {
                self.seq += 1;
                let seq = self.seq;
                q.0 = prio;
                q.1 = seq;
                self.queue.push(Queued {
                    prio,
                    seq: std::cmp::Reverse(seq),
                    spg,
                });
            }
            return self.do_queues();
        }
        self.request(spg, prio, backfill)
    }
    /// Drop whatever `spg` holds or waits for; the grants (and preemptions) this causes.
    fn release(&mut self, spg: SpgT) -> Vec<ResvEv> {
        self.queued.remove(&spg);
        self.granted.remove(&spg);
        self.do_queues()
    }
    /// `osd_max_backfills` changed.
    fn set_max(&mut self, max: usize) -> Vec<ResvEv> {
        self.max = max;
        self.do_queues()
    }
    /// `osd_min_recovery_priority` changed.
    fn set_min_prio(&mut self, min: u32) -> Vec<ResvEv> {
        self.min_prio = min;
        self.do_queues()
    }
    /// The lowest-priority holder (ties: the smallest pg).
    fn victim(&self) -> Option<(u32, SpgT, bool)> {
        self.granted
            .iter()
            .map(|(s, (p, b))| (*p, *s, *b))
            .min_by_key(|(p, s, _)| (*p, *s))
    }
    fn preempt(&mut self, ev: &mut Vec<ResvEv>) {
        if let Some((_, s, b)) = self.victim() {
            self.granted.remove(&s);
            ev.push(ResvEv::Preempt(s, b));
        }
    }
    /// The next waitable request (stale entries skipped), taken out of the heap.
    fn next_queued(&mut self) -> Option<Queued> {
        while let Some(q) = self.queue.pop() {
            #[cfg(test)]
            {
                self.scans += 1;
            }
            if self
                .queued
                .get(&q.spg)
                .is_some_and(|(prio, seq, _)| (*prio, *seq) == (q.prio, q.seq.0))
            {
                return Some(q);
            }
        }
        None
    }
    /// Classic `do_queues`: preempt holders above the limit or below the minimum priority, then grant by priority,
    /// preempting the lowest holder for a strictly higher priority request when the slots are taken.
    fn do_queues(&mut self) -> Vec<ResvEv> {
        let mut ev = Vec::new();
        while self
            .victim()
            .is_some_and(|(p, _, _)| self.granted.len() > self.max || p < self.min_prio)
        {
            self.preempt(&mut ev);
        }
        while let Some(q) = self.next_queued() {
            if q.prio < self.min_prio {
                self.queue.push(q); // waits for `osd_min_recovery_priority` to drop
                break;
            }
            if self.granted.len() >= self.max && self.victim().is_some_and(|(p, _, _)| q.prio > p) {
                self.preempt(&mut ev);
            }
            if self.granted.len() >= self.max {
                self.queue.push(q);
                break;
            }
            let (_, _, b) = self.queued.remove(&q.spg).expect("indexed");
            self.granted.insert(q.spg, (q.prio, b));
            ev.push(ResvEv::Grant(q.spg, b));
        }
        self.compact();
        ev
    }
    /// Stale entries only leave the heap when they surface at its top; behind a long-held head, cancel / re-request
    /// cycles would grow it without bound. Once they outnumber the live ones, rebuild the heap from the index (keys are
    /// unique `(priority, arrival)` pairs, so the grant order is unchanged). Bounds memory, no behaviour.
    fn compact(&mut self) {
        if self.queue.len() > 2 * self.queued.len() + 16 {
            self.queue = self
                .queued
                .iter()
                .map(|(spg, (prio, seq, _))| Queued {
                    prio: *prio,
                    seq: std::cmp::Reverse(*seq),
                    spg: *spg,
                })
                .collect();
        }
    }
    #[cfg(test)]
    fn holds(&self, spg: SpgT, backfill: bool) -> bool {
        self.granted.get(&spg).is_some_and(|g| g.1 == backfill)
    }
    fn dump(&self) -> ResvDump {
        ResvDump {
            granted: self.granted.iter().map(|(s, g)| (*s, g.1)).collect(),
            queued: self
                .queued
                .iter()
                .map(|(s, (p, _, b))| (*p, *s, *b))
                .collect(),
        }
    }
}

/// State of one reservation queue: granted `(pg, is_backfill)` and queued `(prio, pg, is_backfill)`.
#[derive(Debug, Default, Clone)]
pub struct ResvDump {
    pub granted: Vec<(SpgT, bool)>,
    pub queued: Vec<(u32, SpgT, bool)>,
}

/// Backfill / recovery reservations of a core (`dump_recovery_reservations`): the primary-side local queue and the
/// replica-side limiter with its limit.
#[derive(Debug, Default, Clone)]
pub struct Reservations {
    pub local: ResvDump,
    pub remote: ResvDump,
    pub remote_max: usize,
}

/// OSD-wide FIFO slots (`osd_max_scrubs`, `osd_max_trimming_pgs`); kept by [`Slots`].
#[derive(Debug, Default)]
pub(crate) struct ScrubReserver {
    pub max: usize,
    granted: BTreeSet<SpgT>,
    queue: VecDeque<SpgT>,
}
pub(crate) enum ScrubReq {
    Granted,
    Queued,
    Rejected,
}
impl ScrubReserver {
    /// `(granted, queued)` PGs (admin socket dump).
    pub fn dump(&self) -> (Vec<SpgT>, Vec<SpgT>) {
        (
            self.granted.iter().copied().collect(),
            self.queue.iter().copied().collect(),
        )
    }
    pub fn request(&mut self, spg: SpgT, immediate: bool) -> ScrubReq {
        if self.granted.contains(&spg) {
            return ScrubReq::Granted;
        }
        self.queue.retain(|s| *s != spg);
        if self.granted.len() < self.max {
            self.granted.insert(spg);
            ScrubReq::Granted
        } else if immediate {
            ScrubReq::Rejected
        } else {
            self.queue.push_back(spg);
            ScrubReq::Queued
        }
    }
    /// Free the slot / dequeue; returns the next PG granted.
    pub fn release(&mut self, spg: SpgT) -> Option<SpgT> {
        self.queue.retain(|s| *s != spg);
        if self.granted.remove(&spg)
            && self.granted.len() < self.max
            && let Some(n) = self.queue.pop_front()
        {
            self.granted.insert(n);
            return Some(n);
        }
        None
    }
    pub(crate) fn new(max: usize) -> Self {
        ScrubReserver {
            max,
            ..Default::default()
        }
    }
    /// Take a slot regardless of the limit (classic operator scrub with `flashstore_scrub_operator_limits` off).
    pub(crate) fn force(&mut self, spg: SpgT) {
        self.queue.retain(|s| *s != spg);
        self.granted.insert(spg);
    }
    /// New limit (runtime). A raised limit is taken up by [`ScrubReserver::fill`].
    pub(crate) fn set_max(&mut self, max: usize) {
        self.max = max;
    }
    /// Grant queued PGs while slots are free (a raised limit), in FIFO order.
    pub(crate) fn fill(&mut self) -> Vec<SpgT> {
        let mut out = Vec::new();
        while self.granted.len() < self.max
            && let Some(n) = self.queue.pop_front()
        {
            self.granted.insert(n);
            out.push(n);
        }
        out
    }
    pub(crate) fn len(&self) -> usize {
        self.granted.len()
    }
}

impl Pg {
    /// Ask the OSD-wide budget owner (served by the PG set, see `ResvAction`).
    pub(crate) fn slot_ask(&mut self, pool: SlotPool, op: SlotOp) {
        self.out.push(Action::Resv(ResvAction {
            pool,
            spg: self.spg,
            op,
        }));
    }
    pub(crate) fn slot_release(&mut self, pool: SlotPool) {
        self.slot_ask(pool, SlotOp::Release);
    }
    /// Give the replica-side backfill and recovery slots (or queue places) back.
    pub(crate) fn slot_release_remote(&mut self) {
        for backfill in [true, false] {
            self.slot_release(SlotPool::Resv {
                local: false,
                backfill,
            });
        }
    }
}

/// The OSD-wide budgets, kept by ONE core. Scrub and trim slots queue FIFO, backfill / recovery reservations by
/// priority with preemption (see [`Reserver`]).
#[derive(Debug)]
pub(crate) struct Slots {
    scrub_local: ScrubReserver,
    scrub_replica: ScrubReserver,
    trim: ScrubReserver,
    /// Primary-side reservations (classic `local_reserver`).
    local: Reserver,
    /// Replica-side reservations (classic `remote_reserver`).
    remote: Reserver,
    /// Core and request counter that currently hold or wait for each slot: the reply of a queued request goes there,
    /// and the release of a core the PG has left since (placement move) does not take the new holder's slot.
    holder: BTreeMap<(SlotPool, SpgT), (u32, u32)>,
}

impl Slots {
    pub fn new(scrubs: usize, backfills: usize, trimming: usize) -> Self {
        Slots {
            scrub_local: ScrubReserver::new(scrubs),
            scrub_replica: ScrubReserver::new(scrubs),
            trim: ScrubReserver::new(trimming),
            local: Reserver::new(backfills),
            remote: Reserver::new(backfills),
            holder: BTreeMap::new(),
        }
    }
    fn scrub_pool(&mut self, p: SlotPool) -> &mut ScrubReserver {
        match p {
            SlotPool::ScrubLocal => &mut self.scrub_local,
            SlotPool::ScrubReplica => &mut self.scrub_replica,
            SlotPool::Trim => &mut self.trim,
            SlotPool::Resv { .. } => unreachable!("reservations use the Reserver"),
        }
    }
    /// Replies for the queued requests a changed limit lets through.
    fn grant_all(&mut self, pool: SlotPool, grants: Vec<SpgT>, out: &mut Vec<(u32, SlotReply)>) {
        for g in grants {
            self.grant(pool, g, out);
        }
    }
    fn grant(&self, pool: SlotPool, spg: SpgT, out: &mut Vec<(u32, SlotReply)>) {
        if let Some(&(core, seq)) = self.holder.get(&(pool, spg)) {
            out.push((
                core,
                SlotReply {
                    pool,
                    spg,
                    seq,
                    answer: SlotAnswer::Granted,
                },
            ));
        }
    }
    /// Answers for what a reserver did: grants to the holders, and for a preempted holder (its slot is gone, so is its
    /// entry here) the news that it was preempted.
    fn emit(&mut self, local: bool, events: Vec<ResvEv>, out: &mut Vec<(u32, SlotReply)>) {
        for e in events {
            match e {
                ResvEv::Grant(s, b) => self.grant(SlotPool::Resv { local, backfill: b }, s, out),
                ResvEv::Preempt(s, b) => {
                    let pool = SlotPool::Resv { local, backfill: b };
                    if let Some((core, seq)) = self.holder.remove(&(pool, s)) {
                        out.push((
                            core,
                            SlotReply {
                                pool,
                                spg: s,
                                seq,
                                answer: SlotAnswer::Preempted,
                            },
                        ));
                    }
                }
            }
        }
    }
    fn side(&mut self, local: bool) -> &mut Reserver {
        if local {
            &mut self.local
        } else {
            &mut self.remote
        }
    }
    pub fn set_max_scrubs(&mut self, max: usize, out: &mut Vec<(u32, SlotReply)>) {
        self.scrub_local.set_max(max);
        self.scrub_replica.set_max(max);
        for p in [SlotPool::ScrubLocal, SlotPool::ScrubReplica] {
            let g = self.scrub_pool(p).fill();
            self.grant_all(p, g, out);
        }
    }
    pub fn set_max_trimming(&mut self, max: usize, out: &mut Vec<(u32, SlotReply)>) {
        self.trim.set_max(max);
        let g = self.trim.fill();
        self.grant_all(SlotPool::Trim, g, out);
    }
    pub fn set_max_backfills(&mut self, max: usize, out: &mut Vec<(u32, SlotReply)>) {
        for local in [true, false] {
            let ev = self.side(local).set_max(max);
            self.emit(local, ev, out);
        }
    }
    /// `osd_min_recovery_priority`.
    pub fn set_min_recovery_priority(&mut self, min: u32, out: &mut Vec<(u32, SlotReply)>) {
        for local in [true, false] {
            let ev = self.side(local).set_min_prio(min);
            self.emit(local, ev, out);
        }
    }
    pub fn local_scrubs(&self) -> usize {
        self.scrub_local.len()
    }
    /// PGs holding a trim slot (`osd_max_trimming_pgs`), diagnostics/tests.
    pub fn trimming_pgs(&self) -> usize {
        self.trim.len()
    }
    /// `(local granted, replica granted, replica queued)` scrub slots.
    pub fn dump(&self) -> (Vec<SpgT>, Vec<SpgT>, Vec<SpgT>) {
        let (g, q) = self.scrub_replica.dump();
        (self.scrub_local.dump().0, g, q)
    }
    /// Backfill / recovery reservations: `(local, remote)` as [`Reserver::dump`], and the backfill limit.
    pub fn dump_resv(&self) -> Reservations {
        Reservations {
            local: self.local.dump(),
            remote: self.remote.dump(),
            remote_max: self.remote.max,
        }
    }
    /// A local or remote backfill / recovery reservation is held (spec scrub.md 12.1.3, "recovery active").
    pub fn recovery_active(&self) -> bool {
        !self.local.granted.is_empty() || !self.remote.granted.is_empty()
    }
    /// Primary-side reservations `(granted, queued)` over both pools (diagnostics, tests: all zero when idle).
    pub fn local_resv_counts(&self) -> (usize, usize) {
        (self.local.granted.len(), self.local.queued.len())
    }
    /// Apply one request; the replies (to this and other cores, in grant order) are appended to `out`.
    pub fn apply(&mut self, req: SlotReq, out: &mut Vec<(u32, SlotReply)>) {
        let SlotReq {
            from,
            pool,
            spg,
            seq,
            op,
        } = req;
        let key = (pool, spg);
        let reply = |core: u32, spg, seq, granted: bool| {
            (
                core,
                SlotReply {
                    pool,
                    spg,
                    seq,
                    answer: if granted {
                        SlotAnswer::Granted
                    } else {
                        SlotAnswer::Rejected
                    },
                },
            )
        };
        if let SlotPool::Resv { local, backfill } = pool {
            match op {
                SlotOp::Release => {
                    if self.holder.get(&key).is_none_or(|h| h.0 != from) {
                        return;
                    }
                    self.holder.remove(&key);
                    let ev = self.side(local).release(spg);
                    self.emit(local, ev, out);
                }
                // a held slot is granted again, a queued one takes the new priority
                SlotOp::Request { prio, .. } => {
                    // one slot per PG and side: a request of the other kind replaces the earlier one's entry (its
                    // preemption or release would otherwise name a pool the reserver no longer holds)
                    self.holder.remove(&(
                        SlotPool::Resv {
                            local,
                            backfill: !backfill,
                        },
                        spg,
                    ));
                    self.holder.insert(key, (from, seq));
                    let ev = self.side(local).local_request(spg, prio, backfill);
                    self.emit(local, ev, out);
                }
                SlotOp::Force => unreachable!("only scrubs are forced"),
            }
            return;
        }
        match op {
            SlotOp::Release => {
                if self.holder.get(&key).is_none_or(|h| h.0 != from) {
                    return;
                }
                self.holder.remove(&key);
                if let Some(n) = self.scrub_pool(pool).release(spg) {
                    self.grant(pool, n, out);
                }
            }
            SlotOp::Force => {
                self.holder.insert(key, (from, seq));
                self.scrub_pool(pool).force(spg);
                out.push(reply(from, spg, seq, true));
            }
            SlotOp::Request { immediate, .. } => {
                self.holder.insert(key, (from, seq));
                match self.scrub_pool(pool).request(spg, immediate) {
                    ScrubReq::Granted => out.push(reply(from, spg, seq, true)),
                    ScrubReq::Rejected => {
                        self.holder.remove(&key);
                        out.push(reply(from, spg, seq, false));
                    }
                    ScrubReq::Queued => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod reserver_tests {
    use super::*;

    fn spg(n: u32) -> SpgT {
        SpgT {
            pgid: denc::types::PgT::new(1, n),
            shard: denc::types::ShardId::NO_SHARD,
        }
    }
    fn g(n: u32, b: bool) -> ResvEv {
        ResvEv::Grant(spg(n), b)
    }
    fn p(n: u32, b: bool) -> ResvEv {
        ResvEv::Preempt(spg(n), b)
    }

    #[test]
    fn zero_recovery_budget_holds_both_kinds_and_resumes_by_priority() {
        let mut r = Reserver::new(0);
        assert!(r.request(spg(1), 100, true).is_empty());
        assert!(r.request(spg(2), 140, false).is_empty());
        assert!(r.granted.is_empty());
        assert_eq!(r.set_max(1), vec![g(2, false)]);
        assert_eq!(r.set_max(0), vec![p(2, false)]);
        assert!(r.granted.is_empty());
        assert!(r.request(spg(2), 140, false).is_empty());
        assert_eq!(r.set_max(2), vec![g(2, false), g(1, true)]);
    }

    #[test]
    fn zero_fifo_budget_holds_new_work_without_revoking_active_work() {
        // Shared by primary scrubs, replica reservations and snap trimming.
        let mut r = ScrubReserver::new(0);
        assert!(matches!(r.request(spg(1), false), ScrubReq::Queued));
        assert!(matches!(r.request(spg(2), true), ScrubReq::Rejected));
        assert!(r.fill().is_empty());
        r.set_max(1);
        assert_eq!(r.fill(), vec![spg(1)]);
        r.set_max(0);
        assert!(matches!(r.request(spg(3), false), ScrubReq::Queued));
        assert_eq!(r.release(spg(1)), None);
        assert!(r.fill().is_empty());
        r.set_max(1);
        assert_eq!(r.fill(), vec![spg(3)]);
    }

    /// Backfill and recovery share the `osd_max_backfills` slots (no extra recovery pool): a second request waits, whatever
    /// its kind.
    #[test]
    fn backfill_and_recovery_share_the_slots() {
        let mut r = Reserver::new(1);
        assert_eq!(r.request(spg(1), 100, true), vec![g(1, true)]);
        assert!(r.request(spg(2), 100, true).is_empty());
        assert!(
            r.request(spg(3), 100, false).is_empty(),
            "same priority: waits"
        );
        assert_eq!(r.granted.len(), 1);
        assert_eq!(
            r.release(spg(1)),
            vec![g(2, true)],
            "FIFO within a priority"
        );
    }

    /// The RGW stall root cause (a long backfill held the only slot while degraded recovery waited): a higher priority
    /// request preempts the lowest holder instead of waiting for it; a request of equal or lower priority never does.
    #[test]
    fn higher_priority_preempts_the_lowest_holder() {
        let mut r = Reserver::new(2);
        r.request(spg(1), 140, true);
        r.request(spg(2), 140, true);
        assert!(
            r.request(spg(3), 140, true).is_empty(),
            "not strictly higher: waits"
        );
        assert_eq!(r.request(spg(4), 180, false), vec![p(1, true), g(4, false)]);
        assert!(r.granted.contains_key(&spg(4)) && !r.granted.contains_key(&spg(1)));
        // the victim asks again: queued behind the equal ones, never above the limit
        assert!(r.request(spg(1), 140, true).is_empty());
        assert_eq!(r.granted.len(), 2);
        // releasing the recovery grants the first waiting of the highest priority
        assert_eq!(r.release(spg(4)), vec![g(3, true)]);
    }

    /// A lowered limit preempts the lowest holders; a raised one grants the queue by priority.
    #[test]
    fn limit_changes() {
        let mut r = Reserver::new(3);
        for (i, pr) in [(1, 100), (2, 120), (3, 140)] {
            r.request(spg(i), pr, true);
        }
        assert_eq!(r.set_max(1), vec![p(1, true), p(2, true)]);
        for (i, pr) in [(4, 100), (5, 110)] {
            assert!(r.request(spg(i), pr, true).is_empty());
        }
        assert_eq!(r.set_max(3), vec![g(5, true), g(4, true)]);
        assert_eq!(r.granted.len(), 3);
    }

    /// `osd_min_recovery_priority`: lower priorities wait and lose their slot when it rises.
    #[test]
    fn min_priority() {
        let mut r = Reserver::new(2);
        r.request(spg(1), 100, true);
        assert_eq!(r.request(spg(2), 50, true), vec![g(2, true)]);
        assert_eq!(r.set_min_prio(120), vec![p(2, true), p(1, true)]);
        assert!(r.request(spg(3), 119, true).is_empty());
        assert_eq!(r.request(spg(4), 120, false), vec![g(4, false)]);
        assert_eq!(r.set_min_prio(0), vec![g(3, true)]);
    }

    /// A primary-side request of a PG that holds the slot is granted again (re-entering the wait keeps it), only a really
    /// held slot counts; a queued one moves to the back of its new priority.
    #[test]
    fn local_request_semantics() {
        let mut r = Reserver::new(1);
        assert_eq!(r.local_request(spg(1), 100, true), vec![g(1, true)]);
        assert!(r.local_request(spg(2), 100, true).is_empty());
        assert!(r.local_request(spg(3), 100, true).is_empty());
        assert!(
            r.local_request(spg(2), 100, true).is_empty(),
            "same priority: place kept"
        );
        assert_eq!(r.local_request(spg(1), 100, true), vec![g(1, true)]);
        assert_eq!(
            r.local_request(spg(3), 220, true),
            vec![p(1, true), g(3, true)],
            "220 preempts the 100 holder"
        );
        assert!(r.holds(spg(3), true) && !r.holds(spg(1), true));
    }

    /// Force-recovery (spec force-recovery.md 5): a forced waiter (255 / 254) goes ahead of every computed priority
    /// (<= 253) and preempts a lower holder; a cancel that lowers the holder lets a waiting higher one preempt it.
    #[test]
    fn forced_priority_orders_and_preempts() {
        let mut r = Reserver::new(1);
        assert_eq!(r.local_request(spg(1), 253, false), vec![g(1, false)]);
        assert!(r.local_request(spg(2), 253, false).is_empty());
        assert!(r.local_request(spg(3), 180, false).is_empty());
        assert_eq!(
            r.local_request(spg(3), 255, false),
            vec![p(1, false), g(3, false)],
            "forced recovery preempts a lower holder and passes the older waiter"
        );
        // forced backfill (254) waits behind a forced recovery holder, ahead of the rest
        assert!(r.local_request(spg(4), 254, true).is_empty());
        assert_eq!(
            r.release(spg(3)),
            vec![g(4, true)],
            "254 before the waiting 253"
        );
        // cancel on the holder: the waiting 253 preempts the lowered holder
        assert_eq!(
            r.local_request(spg(4), 100, true),
            vec![p(4, true), g(2, false)]
        );
    }

    #[test]
    fn repeated_request_is_queued_once() {
        let mut r = Reserver::new(1);
        r.request(spg(0), 100, true);
        assert!(r.request(spg(1), 100, true).is_empty());
        assert!(r.request(spg(1), 100, true).is_empty());
        assert_eq!(r.queued.len(), 1);
        assert_eq!(r.release(spg(0)), vec![g(1, true)]);
        assert!(
            r.release(spg(1)).is_empty(),
            "no stale duplicate left behind"
        );
        assert!(r.granted.is_empty() && r.queued.is_empty());
    }

    /// Cancel / re-request cycles of waiting PGs behind a long-held head leave stale heap entries that never surface:
    /// the heap stays bounded and the grant order (priority desc, FIFO within) is unchanged.
    #[test]
    fn stale_heap_entries_are_compacted_and_order_is_kept() {
        let mut r = Reserver::new(1);
        assert_eq!(r.request(spg(0), 250, true), vec![g(0, true)]);
        assert!(r.request(spg(1), 100, true).is_empty());
        assert!(r.request(spg(2), 100, true).is_empty());
        assert!(r.request(spg(3), 150, true).is_empty());
        for _ in 0..10_000 {
            r.release(spg(1));
            assert!(r.request(spg(1), 100, true).is_empty());
            assert!(
                r.queue.len() <= 2 * r.queued.len() + 16 + 1,
                "{}",
                r.queue.len()
            );
        }
        // 3 (150) first, then 2 (100, older), then 1 (100, re-requested last)
        assert_eq!(r.release(spg(0)), vec![g(3, true)]);
        assert_eq!(r.release(spg(3)), vec![g(2, true)]);
        assert_eq!(r.release(spg(2)), vec![g(1, true)]);
    }

    /// Granting inspects a few heap entries per event, never the whole queue: a mass recovery queues every PG of the
    /// OSD, and a rescan per grant made that quadratic (R11).
    #[test]
    fn granting_never_walks_the_whole_queue() {
        let mut r = Reserver::new(1);
        assert_eq!(r.request(spg(0), 100, true), vec![g(0, true)]);
        for i in 1..2000 {
            assert!(r.request(spg(i), 100, true).is_empty());
        }
        for i in 0..1999 {
            assert_eq!(r.release(spg(i)), vec![g(i + 1, true)], "{i}");
        }
        assert!(
            r.scans <= 4 * 2000,
            "{} heap entries examined for 2000 queued PGs",
            r.scans
        );
        assert_eq!(r.granted.len(), 1);
    }
}

#[cfg(test)]
mod owner_tests {
    use super::*;

    fn spg(n: u32) -> SpgT {
        SpgT {
            pgid: denc::types::PgT::new(1, n),
            shard: denc::types::ShardId::NO_SHARD,
        }
    }

    fn req(from: u32, pool: SlotPool, n: u32, op: SlotOp) -> SlotReq {
        SlotReq {
            from,
            pool,
            spg: spg(n),
            seq: from + 1,
            op,
        }
    }

    /// Budget 1, 8 cores each asking for a local scrub: one slot in total, the rest queue FIFO and are answered to
    /// their own core as the slot passes on; replica reservations are a separate budget.
    #[test]
    fn one_budget_for_all_cores() {
        let mut s = Slots::new(1, 1, 1);
        let mut out = Vec::new();
        for c in 0..8 {
            s.apply(
                req(
                    c,
                    SlotPool::ScrubLocal,
                    c,
                    SlotOp::Request {
                        immediate: false,
                        prio: 0,
                    },
                ),
                &mut out,
            );
            assert!(s.local_scrubs() <= 1);
        }
        assert_eq!(out.len(), 1, "only core 0 was answered: {out:?}");
        assert_eq!(out[0].0, 0);
        s.apply(
            req(
                0,
                SlotPool::ScrubReplica,
                100,
                SlotOp::Request {
                    immediate: true,
                    prio: 0,
                },
            ),
            &mut out,
        );
        assert!(
            out.last().unwrap().1.answer == SlotAnswer::Granted,
            "replica budget is separate"
        );
        for c in 0..7 {
            out.clear();
            s.apply(req(c, SlotPool::ScrubLocal, c, SlotOp::Release), &mut out);
            assert_eq!(s.local_scrubs(), 1, "the slot passed on, never above 1");
            assert_eq!(
                (out[0].0, out[0].1.spg, out[0].1.seq),
                (c + 1, spg(c + 1), c + 2)
            );
        }
        out.clear();
        s.apply(req(7, SlotPool::ScrubLocal, 7, SlotOp::Release), &mut out);
        assert_eq!(s.local_scrubs(), 0, "all released: nothing leaked");
        assert!(s.holder.keys().all(|k| k.0 == SlotPool::ScrubReplica));
    }

    /// Immediate request with the budget taken: rejected at once, nothing queued or held.
    #[test]
    fn immediate_request_is_rejected_when_full() {
        let mut s = Slots::new(1, 1, 1);
        let mut out = Vec::new();
        s.apply(
            req(
                0,
                SlotPool::ScrubLocal,
                1,
                SlotOp::Request {
                    immediate: true,
                    prio: 0,
                },
            ),
            &mut out,
        );
        s.apply(
            req(
                1,
                SlotPool::ScrubLocal,
                2,
                SlotOp::Request {
                    immediate: true,
                    prio: 0,
                },
            ),
            &mut out,
        );
        assert!(out[0].1.answer == SlotAnswer::Granted && out[1].1.answer == SlotAnswer::Rejected);
        s.apply(req(1, SlotPool::ScrubLocal, 2, SlotOp::Release), &mut out);
        assert_eq!(s.local_scrubs(), 1);
    }

    /// The PG moved to another core: the old core's late release must not take the new holder's slot.
    #[test]
    fn release_of_a_former_core_is_ignored() {
        let mut s = Slots::new(1, 1, 1);
        let mut out = Vec::new();
        s.apply(
            req(
                0,
                SlotPool::ScrubLocal,
                1,
                SlotOp::Request {
                    immediate: false,
                    prio: 0,
                },
            ),
            &mut out,
        );
        s.apply(
            req(
                2,
                SlotPool::ScrubLocal,
                1,
                SlotOp::Request {
                    immediate: false,
                    prio: 0,
                },
            ),
            &mut out,
        );
        s.apply(req(0, SlotPool::ScrubLocal, 1, SlotOp::Release), &mut out);
        assert_eq!(s.local_scrubs(), 1);
        s.apply(req(2, SlotPool::ScrubLocal, 1, SlotOp::Release), &mut out);
        assert_eq!(s.local_scrubs(), 0);
    }

    fn granted_count(s: &Slots, local: bool) -> usize {
        if local {
            s.local.dump().granted.len()
        } else {
            s.remote.dump().granted.len()
        }
    }

    fn resv(from: u32, pool: SlotPool, n: u32, prio: u32, op: SlotOp) -> SlotReq {
        let op = match op {
            SlotOp::Request { immediate, .. } => SlotOp::Request { immediate, prio },
            o => o,
        };
        req(from, pool, n, op)
    }

    const ASK: SlotOp = SlotOp::Request {
        immediate: false,
        prio: 0,
    };

    /// `osd_max_backfills` 1 on 8 cores: one backfill reservation per OSD on each side, queued ones are answered to
    /// their own core in priority order as the slot passes on; recovery shares the slot and preempts it by priority; all released:
    /// nothing leaks.
    #[test]
    fn backfill_budget_is_osd_wide_and_priority_ordered() {
        for (pool, local) in [
            (
                SlotPool::Resv {
                    local: true,
                    backfill: true,
                },
                true,
            ),
            (
                SlotPool::Resv {
                    local: false,
                    backfill: true,
                },
                false,
            ),
        ] {
            let mut s = Slots::new(3, 1, 2);
            let mut out = Vec::new();
            for c in 0..8 {
                let prio = if c == 0 { 200 } else { 100 + c };
                s.apply(resv(c, pool, c, prio, ASK), &mut out);
                assert!(granted_count(&s, local) <= 1);
            }
            assert_eq!(out.len(), 1, "only core 0 was answered");
            // a recovery request (255) preempts the backfill holder (core 0, 200): the slot passes at once, the holder
            // is told, no extra slot appears
            out.clear();
            let rec = SlotPool::Resv {
                local,
                backfill: false,
            };
            s.apply(resv(1, rec, 50, 255, ASK), &mut out);
            assert_eq!(
                granted_count(&s, local),
                1,
                "recovery shares the backfill slot"
            );
            assert_eq!(out.len(), 2, "{out:?}");
            assert_eq!((out[0].0, out[0].1.answer), (0, SlotAnswer::Preempted));
            assert_eq!((out[1].0, out[1].1.answer), (1, SlotAnswer::Granted));
            // the highest priority waiting (core 7) gets the slot after the recovery
            out.clear();
            s.apply(resv(1, rec, 50, 0, SlotOp::Release), &mut out);
            assert_eq!((out[0].0, out[0].1.spg), (7, spg(7)));
            assert_eq!(granted_count(&s, local), 1);
            // the preempted PG's late release changes nothing
            out.clear();
            s.apply(resv(0, pool, 0, 0, SlotOp::Release), &mut out);
            assert!(out.is_empty());
            for c in (1..8).rev() {
                out.clear();
                s.apply(resv(c, pool, c, 0, SlotOp::Release), &mut out);
                assert!(granted_count(&s, local) <= 1);
            }
            assert_eq!(s.local_resv_counts(), (0, 0), "nothing leaked");
            assert!(s.holder.is_empty());
        }
    }

    /// A raised limit lets the queued requests through, to their own cores.
    #[test]
    fn raised_backfill_limit_answers_the_queue() {
        let mut s = Slots::new(1, 1, 1);
        let mut out = Vec::new();
        for c in 0..4 {
            s.apply(
                resv(
                    c,
                    SlotPool::Resv {
                        local: false,
                        backfill: true,
                    },
                    c,
                    100,
                    ASK,
                ),
                &mut out,
            );
        }
        out.clear();
        s.set_max_backfills(3, &mut out);
        let cores: Vec<u32> = out.iter().map(|o| o.0).collect();
        assert_eq!(cores, vec![1, 2]);
        assert_eq!(granted_count(&s, false), 3);
    }

    /// A queued request of a PG that asks again takes the new priority and keeps one place; a release by a core the PG
    /// left does not free the slot of the new holder.
    #[test]
    fn requeue_updates_priority_and_former_core_release_is_ignored() {
        let mut s = Slots::new(1, 1, 1);
        let mut out = Vec::new();
        s.apply(
            resv(
                0,
                SlotPool::Resv {
                    local: true,
                    backfill: true,
                },
                1,
                254,
                ASK,
            ),
            &mut out,
        );
        s.apply(
            resv(
                1,
                SlotPool::Resv {
                    local: true,
                    backfill: true,
                },
                2,
                100,
                ASK,
            ),
            &mut out,
        );
        s.apply(
            resv(
                2,
                SlotPool::Resv {
                    local: true,
                    backfill: true,
                },
                3,
                100,
                ASK,
            ),
            &mut out,
        );
        s.apply(
            resv(
                1,
                SlotPool::Resv {
                    local: true,
                    backfill: true,
                },
                2,
                220,
                ASK,
            ),
            &mut out,
        );
        out.clear();
        s.apply(
            resv(
                0,
                SlotPool::Resv {
                    local: true,
                    backfill: true,
                },
                1,
                0,
                SlotOp::Release,
            ),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1.spg, spg(2), "raised priority goes first");
        out.clear();
        s.apply(
            resv(
                7,
                SlotPool::Resv {
                    local: true,
                    backfill: true,
                },
                2,
                0,
                SlotOp::Release,
            ),
            &mut out,
        );
        assert!(out.is_empty() && granted_count(&s, true) == 1);
    }

    /// `osd_max_trimming_pgs` 2 over 8 cores: two trimming PGs per OSD, FIFO.
    #[test]
    fn trim_budget_is_osd_wide() {
        let mut s = Slots::new(1, 1, 2);
        let mut out = Vec::new();
        for c in 0..8 {
            s.apply(req(c, SlotPool::Trim, c, ASK), &mut out);
        }
        assert_eq!(out.iter().map(|o| o.0).collect::<Vec<_>>(), vec![0, 1]);
        out.clear();
        s.apply(req(0, SlotPool::Trim, 0, SlotOp::Release), &mut out);
        assert_eq!((out[0].0, out[0].1.spg), (2, spg(2)));
        out.clear();
        s.set_max_trimming(4, &mut out);
        assert_eq!(out.iter().map(|o| o.0).collect::<Vec<_>>(), vec![3, 4]);
    }

    /// A PG that asks again under the other kind keeps one slot of that kind: a later preemption reaches the PG under the
    /// new pool and takes the slot (no budget overrun).
    #[test]
    fn kind_switch_of_a_holder_is_preempted_under_the_new_pool() {
        let pool = |backfill| SlotPool::Resv {
            local: true,
            backfill,
        };
        let mut s = Slots::new(3, 1, 2);
        let mut out = Vec::new();
        s.apply(resv(0, pool(true), 1, 100, ASK), &mut out);
        out.clear();
        s.apply(resv(0, pool(false), 1, 100, ASK), &mut out);
        out.clear();
        s.apply(resv(1, pool(true), 2, 200, ASK), &mut out);
        let pre: Vec<_> = out
            .iter()
            .filter(|(_, r)| r.answer == SlotAnswer::Preempted)
            .collect();
        assert_eq!(pre.len(), 1, "{out:?}");
        assert_eq!(
            (pre[0].0, pre[0].1.pool, pre[0].1.spg),
            (0, pool(false), spg(1))
        );
        assert_eq!(granted_count(&s, true), 1, "the slot passed on");
        assert!(s.local.holds(spg(2), true));
    }
}

#[cfg(test)]
mod active_tests {
    use super::*;
    use denc::types::{PgT, ShardId};

    fn spg() -> SpgT {
        SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        }
    }

    /// `osd_scrub_during_recovery` needs "recovery active" = a local or remote backfill / recovery reservation is
    /// held, not a waiting one and not a scrub slot (spec scrub.md 12.1.3).
    #[test]
    fn only_granted_recovery_reservations_count_as_active() {
        let mut slots = Slots::new(3, 1, 2);
        for local in [true, false] {
            for backfill in [false, true] {
                let pool = SlotPool::Resv { local, backfill };
                let req = SlotReq {
                    from: 0,
                    pool,
                    spg: spg(),
                    seq: 1,
                    op: SlotOp::Request {
                        immediate: false,
                        prio: 0,
                    },
                };
                let mut out = Vec::new();
                slots.apply(req, &mut out);
                assert!(slots.recovery_active(), "granted {pool:?}");
                let mut out = Vec::new();
                slots.apply(
                    SlotReq {
                        op: SlotOp::Release,
                        ..req
                    },
                    &mut out,
                );
                assert!(!slots.recovery_active(), "released {pool:?}");
            }
        }
        let mut out = Vec::new();
        slots.apply(
            SlotReq {
                from: 0,
                pool: SlotPool::ScrubLocal,
                spg: spg(),
                seq: 2,
                op: SlotOp::Request {
                    immediate: false,
                    prio: 0,
                },
            },
            &mut out,
        );
        assert!(!slots.recovery_active(), "a scrub slot is no recovery");
    }
}
