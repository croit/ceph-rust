// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Backfill, primary side (spec replication.md 7.1-7.4). Simple and conservative: one scan batch per
//! target at a time (digest of the target vs. our listing), push what is missing/different,
//! remove what only the target has, advance the target's `last_backfill` batch by batch, FINISH.
//! Client writes to objects of the batch whose push is queued or running are held back (`WriteErr::Degraded`); a
//! scan in flight holds back nothing. Objects behind the cursor (or in sync inside the batch) get full transactions,
//! objects beyond it only log entries; writes still in flight at digest time join the batch and are pushed once
//! committed.

use crate::pg::*;
use crate::recovery::PushBatch;
use crate::store::{PgStoreOps, StoreReadError};
use crate::types::*;
use denc::types::{Eversion, Hobject, PgShard, SpgT};
use pgwire::state as pgs;
use replwire::{
    MBackfillReserve, MOSDPGBackfill, MOSDPGBackfillRemove, MOSDPGScan, ObjectRecoveryProgress,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BfPhase {
    Idle,
    ScanSent,
    Pushing,
    Finishing,
    Done,
}

/// Per-target progress.
#[derive(Debug, Clone)]
pub(crate) struct Bf {
    pub phase: BfPhase,
    /// Next scan begin (inclusive); everything below it is in sync.
    pub cursor: Hobject,
    /// End (exclusive) of the batch in flight.
    pub batch_end: Hobject,
    pub batch_max: Option<Hobject>,
    pub todo: VecDeque<(Hobject, bool)>,
    pub pushing: BTreeSet<Hobject>,
}

impl Bf {
    /// `soid` is an object of the batch in flight whose push is queued or running (`todo` is sorted).
    fn needs_push(&self, soid: &Hobject) -> bool {
        self.pushing.contains(soid) || self.todo.binary_search_by(|(o, _)| o.cmp(soid)).is_ok()
    }
}

/// First key of `h`'s snap chain (clones and head share name, key, namespace and hash).
fn chain_start(h: &Hobject) -> Hobject {
    let mut s = h.clone();
    if !s.max {
        s.snap = denc::types::SnapId(0);
    }
    s
}

/// Exclusive end of `h`'s snap chain: the (unused) snapdir key sorts above the head and every clone.
fn chain_end(h: &Hobject) -> Hobject {
    let mut e = h.clone();
    if !e.max {
        e.snap = denc::types::SnapId(u64::MAX);
    }
    e
}

/// A safe batch edge for `end` (exclusive) of a batch that begins at `begin`; `listed` = the keys of the local listing,
/// `next` = where that listing stopped. A new clone sorts above every existing clone of its head, so an edge is safe at a
/// chain start, at a listed clone (the cursor sits on a listed object, like classic's frontier), or above the head. The
/// only unsafe edge lies above the newest listed clone and at or below the head: the clone a write makes then lands
/// behind the cursor while its head is beyond. With `begin` inside the chain the edge moves down to the largest listed
/// clone after `begin`; none = the listing holds no clone between `begin` and `end`, so the edge moves up to the chain
/// end (never past the listing). `None` = neither exists (a scan limit below the chain's keys): the caller stops.
fn safe_edge(
    end: Hobject,
    begin: &Hobject,
    next: &Hobject,
    listed: impl Iterator<Item = Hobject>,
) -> Option<Hobject> {
    if end.max || end.snap.0 == 0 || end.snap.0 > denc::types::SnapId::NOSNAP.0 {
        return Some(end);
    }
    let start = chain_start(&end);
    if start > *begin {
        return Some(start);
    }
    let clone = listed
        .filter(|k| k > begin && *k < end && k.snap.0 < denc::types::SnapId::NOSNAP.0)
        .max();
    clone.or_else(|| Some(chain_end(&end)).filter(|ce| ce <= next))
}

#[derive(Debug, Default)]
pub(crate) struct BackfillState {
    pub targets: BTreeMap<PgShard, Bf>,
    pub reserve_wait: BTreeSet<PgShard>,
    pub reserve_cur: Option<PgShard>,
    /// Remote slots by OSD: one per OSD even when it holds two targets (classic `unique_osd_shard_set`, adr 0049 am. 3).
    pub reserved: BTreeMap<i32, PgShard>,
    /// Targets with an unanswered GET_DIGEST -> answer deadline. A full classic replica answers nothing, queues
    /// BackfillTooFull behind our next message and (before tracker 76751) aborts if that message took it out of
    /// RepRecovering/RepWaitBackfillReserved: RELEASE / REQUEST to it wait for the DIGEST, its REVOKE_TOOFULL /
    /// REJECT_TOOFULL, or the deadline (classic-peer-model 5).
    /// Keyed by target pg_shard (one OSD may hold two targets).
    pub scan_wait: BTreeMap<PgShard, Mono>,
    /// RELEASEs owed to OSDs with a target in `scan_wait`.
    pub release_owed: BTreeMap<i32, PgShard>,
    /// Recovery/backfill ops started by this PG (scan or push): drives the OSD-wide `osd_recovery_sleep` pace.
    pub ops_started: u64,
}

/// Backfill bands and their maxima after the pool-option shift (spec replication.md 11.1).
const BACKFILL_PRIO: u32 = 100;
const BACKFILL_BAND_MAX: u32 = 139;
const BACKFILL_PRIO_DEGRADED: u32 = 140;
const DEGRADED_BAND_MAX: u32 = 179;
const BACKFILL_PRIO_INACTIVE: u32 = 220;
const INACTIVE_BAND_MAX: u32 = 253;
/// Reservation priority of a forced backfill (spec force-recovery.md 5): above every computed value (<= 253).
const BACKFILL_PRIO_FORCED: u32 = 254;

impl Pg {
    pub(crate) fn needs_backfill(&self) -> bool {
        self.prim.backfill_targets.iter().any(|p| {
            self.prim
                .peer_info
                .get(p)
                .is_none_or(|i| i.last_backfill != Hobject::MAX())
        })
    }

    pub(crate) fn start_backfill_reservation(&mut self) {
        if self.backfill_blocked() {
            self.hold_backfill();
            return;
        }
        self.set_st(St::Primary(PSt::Active(ASt::WaitLocalBackfillReserved)));
        self.state |= pgs::BACKFILL_WAIT;
        self.slot_ask(
            SlotPool::Resv {
                local: true,
                backfill: true,
            },
            SlotOp::Request {
                immediate: false,
                prio: self.backfill_priority(),
            },
        );
    }

    /// Reservation priority of backfill now (spec force-recovery.md 5, replication.md 11.1), re-evaluated at every use.
    pub(crate) fn backfill_priority(&self) -> u32 {
        if self.state & pgs::FORCED_BACKFILL != 0 {
            return BACKFILL_PRIO_FORCED;
        }
        let acting = self.acting_count();
        if acting < self.pool.min_size {
            let v = BACKFILL_PRIO_INACTIVE + (self.pool.min_size - acting);
            self.pool_priority(v, INACTIVE_BAND_MAX)
        } else if acting < self.pool.size {
            let v = BACKFILL_PRIO_DEGRADED + (self.pool.size - acting);
            self.pool_priority(v, DEGRADED_BAND_MAX)
        } else if self.state & pgs::DEGRADED != 0
            || self.info.stats.stats.sum.num_objects_degraded != 0
        {
            self.pool_priority(BACKFILL_PRIO_DEGRADED, DEGRADED_BAND_MAX)
        } else {
            self.pool_priority(BACKFILL_PRIO, BACKFILL_BAND_MAX)
        }
    }

    pub(crate) fn start_backfill_remote(&mut self) {
        self.set_st(St::Primary(PSt::Active(ASt::WaitRemoteBackfillReserved)));
        // one reservation per OSD (classic `unique_osd_shard_set`): two targets on one OSD share its slot
        let mut osds = BTreeSet::new();
        self.bf.reserve_wait = self
            .prim
            .backfill_targets
            .iter()
            .filter(|p| osds.insert(p.osd))
            .copied()
            .collect();
        self.bf_request_next();
    }

    fn bf_request_next(&mut self) {
        if self.bf.reserve_cur.is_some() {
            return;
        }
        let Some(p) = self.bf.reserve_wait.iter().next().copied() else {
            self.begin_backfilling();
            return;
        };
        if self.bf.release_owed.contains_key(&p.osd) {
            return; // asked once the owed RELEASE went out (`bf_scan_answered`)
        }
        self.bf.reserve_wait.remove(&p);
        self.bf.reserve_cur = Some(p);
        let (epoch, prio) = (self.map.epoch(), self.backfill_priority());
        // the target's projected-size fullness check: our bytes and what we remember the target holds (peering.md 4.4)
        let primary_num_bytes = self.info.stats.stats.sum.num_bytes.max(0);
        let shard_num_bytes = self
            .prim
            .peer_info
            .get(&p)
            .map_or(0, |i| i.stats.stats.sum.num_bytes.max(0));
        self.send_repl(
            p.osd,
            MBackfillReserve {
                pgid: SpgT {
                    pgid: self.spg.pgid,
                    shard: p.shard,
                },
                query_epoch: epoch,
                ty: MBackfillReserve::REQUEST,
                priority: prio,
                primary_num_bytes,
                shard_num_bytes,
            },
            0,
        );
    }

    pub(crate) fn backfill_granted(&mut self, from: i32) {
        if let Some(p) = self.bf.reserve_cur.filter(|p| p.osd == from) {
            self.bf.reserve_cur = None;
            self.bf.reserved.insert(from, p);
            if self.st == St::Primary(PSt::Active(ASt::WaitRemoteBackfillReserved)) {
                self.bf_request_next();
            }
        } else if !self.bf.reserved.contains_key(&from) && !self.rec_engaged(from) {
            // stale grant (a duplicated request re-reserved the slot after our release): give it back, unless the
            // peer holds / is asked for our RECOVERY slot: backfill RELEASE cancels any Rep state (classic
            // RemoteReservationCanceled in RWR/RRC)
            self.bf_release_or_owe(self.backfill_peer(from));
        } else if !self.bf.reserved.contains_key(&from) {
            self.discard("stale backfill grant, peer busy with recovery");
        }
    }

    fn begin_backfilling(&mut self) {
        if self.rec.slot_lost {
            return self.defer_backfill();
        }
        self.set_st(St::Primary(PSt::Active(ASt::Backfilling)));
        self.state &= !pgs::BACKFILL_WAIT;
        self.state |= pgs::BACKFILLING;
        self.rec.refused_by_full = None;
        let targets: Vec<PgShard> = self.prim.backfill_targets.iter().copied().collect();
        for p in targets {
            let lb = self
                .prim
                .peer_info
                .get(&p)
                .map_or(Hobject::MIN(), |i| i.last_backfill.clone());
            let (phase, cursor) = if lb == Hobject::MAX() {
                (BfPhase::Done, Hobject::MAX())
            } else {
                (BfPhase::Idle, lb)
            };
            self.bf.targets.insert(
                p,
                Bf {
                    phase,
                    cursor: cursor.clone(),
                    batch_end: cursor,
                    batch_max: None,
                    todo: VecDeque::new(),
                    pushing: BTreeSet::new(),
                },
            );
        }
    }

    pub(crate) fn release_backfill_reservations(&mut self) {
        self.slot_release(SlotPool::Resv {
            local: true,
            backfill: true,
        });
        let mut peers: Vec<PgShard> = std::mem::take(&mut self.bf.reserved)
            .into_values()
            .collect();
        peers.extend(self.bf.reserve_cur.take());
        for p in peers {
            self.bf_release_or_owe(p);
        }
        self.bf.reserve_wait.clear();
    }

    /// Send the RELEASE for `p` now, or owe it to `p.osd`'s unanswered GET_DIGEST (`bf_scan_answered` sends it).
    fn bf_release_or_owe(&mut self, p: PgShard) {
        if self.bf_scan_pending(p.osd) {
            self.bf.release_owed.insert(p.osd, p);
            return;
        }
        let epoch = self.map.epoch();
        self.send_bf_release(p, epoch);
    }

    /// Reservation replies lack a sender shard. Preserve the requested target for releases.
    pub(crate) fn backfill_peer(&self, osd: i32) -> PgShard {
        self.bf
            .reserved
            .get(&osd)
            .copied()
            .or_else(|| self.bf.reserve_cur.filter(|p| p.osd == osd))
            .or_else(|| self.bf.release_owed.get(&osd).copied())
            .or_else(|| {
                self.bf
                    .targets
                    .keys()
                    .chain(self.prim.backfill_targets.iter())
                    .find(|p| p.osd == osd)
                    .copied()
            })
            .unwrap_or_else(|| self.pshard(osd))
    }

    pub(crate) fn send_bf_release(&mut self, p: PgShard, epoch: u32) {
        self.send_repl(
            p.osd,
            MBackfillReserve::reply(
                SpgT {
                    pgid: self.spg.pgid,
                    shard: p.shard,
                },
                epoch,
                MBackfillReserve::RELEASE,
            ),
            0,
        );
    }

    /// A GET_DIGEST of ours to `osd` is unanswered.
    pub(crate) fn bf_scan_pending(&self, osd: i32) -> bool {
        self.bf.scan_wait.keys().any(|p| p.osd == osd)
    }

    /// `(osd, shard)` (DIGEST: that target) or every target on `osd` (`None`: REVOKE_TOOFULL / REJECT_TOOFULL carry no
    /// sender shard) answered our GET_DIGEST, or its deadline passed: its full event, if any, ran. Once no scan to that
    /// OSD is outstanding, send the owed RELEASE, then a REQUEST that waited for it.
    pub(crate) fn bf_scan_answered(&mut self, osd: i32, shard: Option<denc::types::ShardId>) {
        let n = self.bf.scan_wait.len();
        self.bf
            .scan_wait
            .retain(|p, _| p.osd != osd || shard.is_some_and(|s| s != p.shard));
        if self.bf.scan_wait.len() == n || self.bf_scan_pending(osd) {
            return;
        }
        if let Some(p) = self.bf.release_owed.remove(&osd) {
            let epoch = self.map.epoch();
            self.send_bf_release(p, epoch);
            if self.st == St::Primary(PSt::Active(ASt::WaitRemoteBackfillReserved)) {
                self.bf_request_next();
            }
        }
    }

    /// Housekeeping: scans unanswered past their deadline count as answered. The one owner of that deadline: a target
    /// still waiting for the digest stops its backfill here (retried after `osd_backfill_retry_interval`), and the owed
    /// RELEASE of a scan that no longer has a target goes out.
    pub(crate) fn bf_scan_deadlines(&mut self) {
        let now = self.now;
        let due: Vec<PgShard> = self
            .bf
            .scan_wait
            .iter()
            .filter(|(_, by)| now >= **by)
            .map(|(p, _)| *p)
            .collect();
        for p in due {
            eprintln!(
                "WARNING TIMEOUT backfill scan digest exceeded {}s (pg {:?}, osd.{} shard {:?})",
                self.cfg.backfill_retry / crate::types::SEC,
                self.spg,
                p.osd,
                p.shard
            );
            // the stall owes the RELEASE of the unanswered scan (`bf_scan_answered` sends it)
            if self
                .bf
                .targets
                .get(&p)
                .is_some_and(|b| b.phase == BfPhase::ScanSent)
            {
                self.backfill_stall(p, "backfill: scan reply timed out");
            }
            self.bf_scan_answered(p.osd, Some(p.shard));
        }
    }

    /// May a client write to `soid` proceed while backfill runs? (spec 7.4: the primary must not race a write with the
    /// push of the same object.) Only the objects of the batch that still need their push (queued or in flight) hold a
    /// write back; a scan in flight holds back nothing (writes beyond the cursor reach the target log-only and the
    /// digest comparison, with the writes still in flight, picks them up).
    pub(crate) fn backfill_blocks(&self, soid: &Hobject) -> bool {
        if self.st != St::Primary(PSt::Active(ASt::Backfilling)) {
            return false;
        }
        self.bf
            .targets
            .values()
            .any(|b| b.phase == BfPhase::Pushing && b.needs_push(soid))
    }

    /// Does the target get the full transaction for `soid`? Behind the cursor, or inside the batch being pushed and in
    /// sync on the target (not among the objects still to push).
    pub(crate) fn backfill_target_has_range(&self, p: &PgShard, soid: &Hobject) -> bool {
        match self.bf.targets.get(p) {
            Some(b) => {
                b.phase == BfPhase::Done
                    || *soid < b.cursor
                    || (b.phase == BfPhase::Pushing && *soid < b.batch_end && !b.needs_push(soid))
            }
            None => self
                .prim
                .peer_info
                .get(p)
                .is_none_or(|i| i.last_backfill == Hobject::MAX() || *soid <= i.last_backfill),
        }
    }

    pub(crate) fn backfill_step(&mut self, store: &impl PgStoreOps) {
        if self.st != St::Primary(PSt::Active(ASt::Backfilling)) {
            return;
        }
        let targets: Vec<PgShard> = self.bf.targets.keys().copied().collect();
        let epoch = self.map.epoch();
        for p in targets {
            // the phase only: the target's todo/pushing sets (up to 2x 512 objects) stay in place
            let Some(phase) = self.bf.targets.get(&p).map(|b| b.phase) else {
                continue;
            };
            match phase {
                BfPhase::Idle => {
                    let cursor = self.bf.targets[&p].cursor.clone();
                    if cursor == Hobject::MAX() {
                        self.send_finish(p);
                        continue;
                    }
                    self.send_repl(
                        p.osd,
                        MOSDPGScan {
                            op: MOSDPGScan::OP_GET_DIGEST,
                            map_epoch: epoch,
                            query_epoch: self.last_peering_reset,
                            pgid: SpgT {
                                pgid: self.spg.pgid,
                                shard: p.shard,
                            },
                            begin: cursor,
                            end: Hobject::MAX(),
                            from: self.me,
                            digest: None,
                        },
                        0,
                    );
                    let by = self.now + self.cfg.backfill_retry;
                    self.bf.scan_wait.insert(p, by);
                    self.bf.ops_started += 1;
                    let b = self.bf.targets.get_mut(&p).unwrap();
                    b.phase = BfPhase::ScanSent;
                }
                BfPhase::ScanSent => {
                    // the digest reply or the deadline in `bf_scan_deadlines` decides; nothing to do here
                    continue;
                }
                BfPhase::Pushing => {
                    self.backfill_pump_pushes(p, store);
                    // a local read error stops the whole backfill (reservations released, retry timer armed)
                    let Some(b) = self.bf.targets.get(&p) else {
                        return;
                    };
                    if b.todo.is_empty() && b.pushing.is_empty() {
                        // batch complete: advance the target's last_backfill
                        let (maxo, end) = (b.batch_max.clone(), b.batch_end.clone());
                        if let Some(m) = maxo {
                            self.send_backfill_progress(p, m.clone(), MOSDPGBackfill::OP_PROGRESS);
                            if let Some(pi) = self.prim.peer_info.get_mut(&p) {
                                pi.last_backfill = m;
                            }
                        }
                        let b = self.bf.targets.get_mut(&p).unwrap();
                        b.cursor = end;
                        b.batch_max = None;
                        b.phase = BfPhase::Idle;
                        self.backfill_step(store);
                        return;
                    }
                }
                _ => {}
            }
        }
    }

    fn send_backfill_progress(&mut self, p: PgShard, lb: Hobject, op: u32) {
        // The stats are advisory for the target's info: an unencodable value (a length past u32) must not panic the OSD
        // nor stop the backfill, the target gets empty stats and the error is logged.
        let (stats, compat) = match (
            denc::to_vec(&self.info.stats),
            denc::to_vec(&self.info.stats.stats),
        ) {
            (Ok(stats), Ok(compat)) => (stats, compat),
            _ => {
                self.error("backfill: pg stats not encodable, sending empty stats");
                let empty = pgwire::PgStat::default();
                (
                    denc::to_vec(&empty).unwrap_or_default(),
                    denc::to_vec(&empty.stats).unwrap_or_default(),
                )
            }
        };
        self.send_repl(
            p.osd,
            MOSDPGBackfill {
                op,
                map_epoch: self.map.epoch(),
                query_epoch: self.last_peering_reset,
                pgid: SpgT {
                    pgid: self.spg.pgid,
                    shard: p.shard,
                },
                last_backfill: lb,
                compat_stats: compat,
                stats,
            },
            0,
        );
    }

    fn send_finish(&mut self, p: PgShard) {
        self.send_backfill_progress(p, Hobject::MAX(), MOSDPGBackfill::OP_FINISH);
        self.bf.targets.get_mut(&p).unwrap().phase = BfPhase::Finishing;
    }

    fn backfill_pump_pushes(&mut self, p: PgShard, store: &impl PgStoreOps) {
        let mut batch = PushBatch::default();
        while self.backfill_pump_one(p, store, &mut batch) {}
        // A stop (`backfill_stall` / `stop_backfill`) cleared the targets, the push tracking and the reservations: what
        // the batch still holds must not reach the target.
        if self.st == St::Primary(PSt::Active(ASt::Backfilling)) && self.bf.targets.contains_key(&p)
        {
            self.flush_push_batch(p, &mut batch);
        }
    }

    /// Build the push of the head of `p`'s todo list; `true` = call again. Nothing is sent before the caller flushes
    /// the batch (one message per `osd_max_push_objects` / `osd_max_push_cost`, spec replication.md 6.3).
    fn backfill_pump_one(
        &mut self,
        p: PgShard,
        store: &impl PgStoreOps,
        batch: &mut PushBatch,
    ) -> bool {
        // `p` may be gone: a callee of the previous object stopped the backfill (`stop_backfill` clears the targets)
        let Some((oid, _)) = self.bf.targets.get(&p).and_then(|b| b.todo.front()) else {
            return false;
        };
        if self.rec_inflight() >= self.rec.cap {
            self.rec.wants = true;
            return false;
        }
        // Writes of the object still in flight reached this target log-only (beyond its cursor) and may not be in
        // the copy the push is built from yet: pushing now leaves the target at an older version under a current
        // log (OQ 41, adr 0049 am. 7). Push once they committed; new writes are refused meanwhile
        // (`backfill_blocks`), every write completion runs `backfill_step` again.
        if self.write_in_flight(oid) {
            return false;
        }
        let Some((oid, exists)) = self.bf.targets.get_mut(&p).and_then(|b| b.todo.pop_front())
        else {
            return false;
        };
        if self.pool.is_erasure {
            // EC: the target needs ITS shard of the object, rebuilt from k shards (ecrec)
            let ver = match store.object_version(self.spg, &oid) {
                Ok(v) => v,
                Err(StoreReadError::NoObject) => {
                    self.backfill_remove_vanished(p, oid, exists);
                    return true;
                }
                Err(_) => {
                    self.backfill_stall(p, "backfill: local object unreadable or corrupt");
                    return false;
                }
            };
            self.bf
                .targets
                .get_mut(&p)
                .unwrap()
                .pushing
                .insert(oid.clone());
            self.ec_backfill_push(p, oid, ver, exists, store);
            return true;
        }
        let mut ri = match store.recovery_info_checked(self.spg, &oid) {
            Ok(ri) => ri,
            Err(StoreReadError::NoObject) => {
                self.backfill_remove_vanished(p, oid, exists);
                return true;
            }
            Err(_) => {
                // our own copy is damaged: repair it from a peer first (recovery goes before backfill)
                if !self.local_damage(&oid, None) {
                    self.backfill_stall(p, "backfill: local object unreadable or corrupt");
                }
                return false;
            }
        };
        ri.object_exist = exists;
        let prog = ObjectRecoveryProgress::default();
        match store.build_push(
            self.spg,
            &ri,
            &prog,
            self.cfg.recovery_max_chunk,
            self.cfg.recovery_max_omap_entries,
        ) {
            Ok(op) => {
                self.rec.pushes.insert(
                    (oid.clone(), p.osd),
                    crate::recovery::PushInfo {
                        info: ri,
                        progress: op.after_progress.clone(),
                        stat: crate::recovery::RecStat::of(&op),
                    },
                );
                self.bf.targets.get_mut(&p).unwrap().pushing.insert(oid);
                self.bf.ops_started += 1;
                batch.add(op);
                if batch.at_limit(&self.cfg) {
                    self.flush_push_batch(p, batch);
                }
                true
            }
            Err(StoreReadError::NoObject) => {
                // removed between the info read and the push build: same as vanished
                self.backfill_remove_vanished(p, oid, exists);
                true
            }
            Err(_) => {
                self.backfill_stall(
                    p,
                    "backfill: build_push failed (local object unreadable or corrupt)",
                );
                false
            }
        }
    }

    /// A listed object is gone locally (deleted by a write that reached the target log-only): the target's copy goes
    /// too, else it would stay behind `last_backfill` (the version is not used by the receiver, classic
    /// `do_backfill_remove` / ours).
    fn backfill_remove_vanished(&mut self, p: PgShard, oid: Hobject, exists: bool) {
        if !exists {
            return;
        }
        self.send_repl(
            p.osd,
            MOSDPGBackfillRemove {
                pgid: SpgT {
                    pgid: self.spg.pgid,
                    shard: p.shard,
                },
                map_epoch: self.map.epoch(),
                ls: vec![(oid, Eversion::default())],
            },
            0,
        );
    }

    /// A write of `soid` is queued or not yet committed everywhere (EC: on this primary; replicated: its newest log
    /// entry is above `pg_committed_to`).
    pub(crate) fn write_in_flight(&self, soid: &Hobject) -> bool {
        if self.pool.is_erasure {
            self.ec_write_in_flight(soid)
        } else {
            self.log
                .newest_for(soid)
                .is_some_and(|v| v > self.pg_committed_to)
        }
    }

    /// Objects in `[lo, hi)` with a write in flight ([`Self::write_in_flight`]).
    fn writes_in_flight_in(&self, lo: &Hobject, hi: &Hobject) -> Vec<Hobject> {
        if self.pool.is_erasure {
            return self.ec_writes_in_flight_in(lo, hi);
        }
        let mut out: Vec<Hobject> = self
            .log
            .entries()
            .iter()
            .rev()
            .take_while(|e| e.version > self.pg_committed_to)
            .filter(|e| e.soid >= *lo && e.soid < *hi)
            .map(|e| e.soid.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// A digest we accept from a target in `ScanSent`: it lists from our cursor and ends past it (an `end == cursor`
    /// digest would re-scan the same range forever, `end < cursor` would move `last_backfill` backwards).
    fn digest_fits(b: &Bf, m: &MOSDPGScan) -> bool {
        b.phase == BfPhase::ScanSent && m.begin == b.cursor && m.end > b.cursor
    }

    /// The digest of `m.from` is one the backfill takes: otherwise its scan deadline (`bf_scan_deadlines`) stays armed
    /// and decides. A reply no target waits for any more (stopped, other phase) only settles the owed RELEASE.
    pub(crate) fn digest_rejected(&self, m: &MOSDPGScan) -> bool {
        self.bf
            .targets
            .get(&m.from)
            .is_some_and(|b| b.phase == BfPhase::ScanSent && !Self::digest_fits(b, m))
    }

    /// DIGEST reply from a backfill target.
    pub(crate) fn backfill_on_digest(&mut self, from: i32, m: MOSDPGScan, store: &impl PgStoreOps) {
        let p = m.from;
        if p.osd != from {
            self.discard("digest sender does not match connection");
            return;
        }
        let Some(b) = self.bf.targets.get(&p) else {
            self.discard("digest from non-target");
            return;
        };
        // A digest that does not advance past our cursor would re-scan the same range forever (end == cursor) or move
        // `last_backfill` backwards (end < cursor); an honest replica lists from `begin` and ends past it.
        if !Self::digest_fits(b, &m) {
            self.discard("unexpected digest");
            return;
        }
        let mut theirs: BTreeMap<Hobject, Eversion> =
            m.digest.unwrap_or_default().into_iter().collect();
        let mut end = m.end;
        // Removals are derived from "the target has it, we do not": that is only sound over a COMPLETE and
        // TRUSTED local listing. A read error aborts the comparison (no removal, no push); an object whose
        // object_info is damaged is neither absent nor deletable on the target (adr 0042).
        // The batch is bounded by OUR listing too (classic osd_backfill_scan_max): the target's digest of an empty or
        // short PG ends at MAX, which made ONE batch of the whole PG (and a write block over all of it).
        let listing = match store.list_objects(self.spg, &b.cursor, 0, self.cfg.backfill_scan_max) {
            Ok(l) => l,
            Err(_) => {
                self.backfill_stall(p, "backfill: local object listing failed");
                return;
            }
        };
        end = end.min(listing.next.clone());
        // A batch edge never splits an object's snap chain (clones + head). Writes are routed by position against the
        // cursor, and a write that clones the head carries the new clone and the head: with the edge between them the
        // target would get the head's overwrite (and a clone cut from its stale head) while the batch behind the edge
        // is never compared again (classic keeps `last_backfill_started` on listed objects, and a new clone sorts above
        // every listed clone of its head, so it never lands behind the frontier).
        let Some(e) = safe_edge(
            end,
            &m.begin,
            &listing.next,
            listing
                .objs
                .iter()
                .map(|o| o.0.clone())
                .chain(listing.corrupt.iter().cloned()),
        ) else {
            self.backfill_stall(p, "backfill: snap chain longer than the scan limit");
            return;
        };
        end = e;
        let mut corrupt: BTreeSet<Hobject> = listing.corrupt.into_iter().collect();
        let mut local: BTreeMap<Hobject, Eversion> = listing.objs.into_iter().collect();
        let mut todo: VecDeque<(Hobject, bool)> = VecDeque::new();
        for (o, v) in &local {
            if *o >= end {
                break;
            }
            match theirs.get(o) {
                Some(tv) if tv == v => {}
                Some(_) => todo.push_back((o.clone(), true)),
                None => todo.push_back((o.clone(), false)),
            }
        }
        // A heavy object (omap of more than one push chunk: minutes of push) gets a batch of its own: client writes are held back
        // for the whole batch range, so it must not drag the objects around it along. Those before it go first
        // (the batch ends at the heavy object, also when none of them needs a push: in-sync neighbours are held back by
        // the range too), then it alone (batch begins at it and ends right behind it).
        let chunk_keys = self.cfg.recovery_max_omap_entries as u64;
        let heavy = todo.iter().position(|(o, _)| {
            // An unanswerable probe (store error) must not read as "not heavy": the object then gets a batch of its
            // own and its push reports the error loudly (`backfill_stall`).
            match store.omap_keys_over(self.spg, o, chunk_keys) {
                Some(over) => over,
                None => {
                    self.error("backfill: omap size probe failed, treating the object as heavy");
                    true
                }
            }
        });
        if let Some(i) = heavy {
            // the heavy object's whole chain is the batch (never an edge inside a chain): the chain before it first
            let h = todo[i].0.clone();
            let start = chain_start(&h);
            let cut = if start > m.begin {
                start
            } else {
                chain_end(&h)
            };
            if cut < end {
                end = cut;
            }
        }
        todo.retain(|(o, _)| *o < end);
        local.retain(|o, _| *o < end);
        corrupt.retain(|o| *o < end);
        theirs.retain(|o, _| *o < end);
        // A write accepted before or during the scan can still be queued (EC: behind an RMW read) or uncommitted. It
        // reaches the target log-only (beyond its cursor) and the listing may predate it: a create is not listed, a
        // delete still is, an overwrite shows the old version (equal on both sides: skipped). Every such object of the
        // batch is pushed once its writes committed (the push waits, `backfill_pump_pushes`), or removed if gone by
        // then (OQ 46, adr 0049 am. 8; classic replays the log into the scan, `update_range`).
        // Complete without a log replay because the listing above and this set are one PG step: no commit runs between
        // them, and a committed write is visible to the listing (a queued txn is readable at once; `pg_committed_to` /
        // `ep.by_obj` move only after the local commit). A listing spanning PG events must take this set first.
        let inflight = self.writes_in_flight_in(&m.begin, &end);
        if !inflight.is_empty() {
            for o in &inflight {
                if !todo.iter().any(|(t, _)| t == o) {
                    todo.push_back((o.clone(), theirs.contains_key(o)));
                }
            }
            todo.make_contiguous().sort();
        }
        let mut removes = Vec::new();
        for (o, v) in &theirs {
            if !local.contains_key(o) && !corrupt.contains(o) && !inflight.contains(o) {
                removes.push((o.clone(), *v));
            }
        }
        if !corrupt.is_empty() {
            self.error("backfill: local object damaged (peer copies kept, not pushed)");
            // the damaged copies are repaired from a peer; recovery runs first, the backfill starts again behind it
            let mut repairing = false;
            for o in &corrupt {
                repairing |= self.local_damage(o, None);
            }
            if repairing {
                return;
            }
            // a damaged local object the target does not hold cannot be backfilled from here at all
            if corrupt.iter().any(|o| !theirs.contains_key(o)) {
                self.backfill_stall(p, "backfill: damaged local object missing on target");
                return;
            }
        }
        let batch_max = local
            .keys()
            .chain(theirs.keys())
            .chain(corrupt.iter())
            .max()
            .cloned();
        if !removes.is_empty() {
            self.send_repl(
                from,
                MOSDPGBackfillRemove {
                    pgid: SpgT {
                        pgid: self.spg.pgid,
                        shard: p.shard,
                    },
                    map_epoch: self.map.epoch(),
                    ls: removes,
                },
                0,
            );
        }
        let b = self.bf.targets.get_mut(&p).unwrap();
        b.todo = todo;
        b.batch_end = end;
        b.batch_max = batch_max;
        b.phase = BfPhase::Pushing;
    }

    /// A local read error or an unrecoverable local copy stops this backfill: release the local and remote
    /// reservations (other PGs must not starve behind a stuck one), show `backfill_unfound`, say so in the cluster
    /// log, and try again after `osd_backfill_retry_interval` (the error may be transient or repaired meanwhile).
    pub(crate) fn backfill_stall(&mut self, p: PgShard, why: &'static str) {
        self.error(why);
        self.notes.push(format!(
            "pg {}: backfill to osd.{} stopped: {why}; retry in {} s",
            self.spg,
            p.osd,
            self.cfg.backfill_retry / crate::types::SEC
        ));
        self.stop_backfill();
        self.state &= !(pgs::BACKFILL_WAIT | pgs::BACKFILLING);
        self.state |= pgs::BACKFILL_UNFOUND;
        self.set_st(St::Primary(PSt::Active(ASt::NotBackfilling)));
        self.rec.retry_at = self.now + self.cfg.backfill_retry;
    }

    pub(crate) fn backfill_on_finish_ack(&mut self, from: i32) {
        // FINISH_ACK has no sender shard: the in-flight target identifies it, not acting.
        let Some(p) = self
            .bf
            .targets
            .iter()
            .find_map(|(p, b)| (p.osd == from && b.phase == BfPhase::Finishing).then_some(*p))
        else {
            return;
        };
        let Some(b) = self.bf.targets.get_mut(&p) else {
            return;
        };
        b.phase = BfPhase::Done;
        if let Some(pi) = self.prim.peer_info.get_mut(&p) {
            pi.last_backfill = Hobject::MAX();
            pi.last_complete = pi.last_update;
        }
        self.prim.backfill_targets.remove(&p);
        if let Some(pm) = self.prim.peer_missing.get_mut(&p) {
            pm.clear();
        }
        if self.bf.targets.values().all(|b| b.phase == BfPhase::Done) {
            self.bf.targets.clear();
            self.release_backfill_reservations();
            self.state &= !pgs::BACKFILLING;
            self.all_recovered();
        }
    }

    pub(crate) fn backfill_push_done(&mut self, p: PgShard, soid: &Hobject) {
        if let Some(b) = self.bf.targets.get_mut(&p) {
            b.pushing.remove(soid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use denc::types::{PgT, ShardId};
    use std::sync::Arc;

    #[test]
    fn backfill_request_carries_pg_bytes() {
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        };
        let target = PgShard {
            osd: 1,
            shard: ShardId::NO_SHARD,
        };
        let map = SynthMap::new(4)
            .with_pool(1, 2, 1, 1)
            .with_osd(0, 1)
            .with_osd(1, 1)
            .into_handle();
        let mut pg = Pg::blank(Arc::new(Config::new(0)), spg, map, pgwire::PgInfo::new(spg));
        pg.acting = vec![0, 1];
        pg.up = pg.acting.clone();
        pg.st = St::Primary(PSt::Active(ASt::Activating));
        pg.info.stats.stats.sum.num_bytes = 7_000_000;
        pg.prim.backfill_targets.insert(target);
        let mut pi = pgwire::PgInfo::new(spg);
        pi.stats.stats.sum.num_bytes = 1_000_000;
        pg.prim.peer_info.insert(target, pi);
        pg.start_backfill_remote();
        let sent: Vec<_> = pg
            .take_actions()
            .into_iter()
            .filter_map(|a| match a {
                Action::Send(s) => match s.body {
                    Body::Repl(replwire::ReplMsg::BackfillReserve(m))
                        if m.ty == MBackfillReserve::REQUEST =>
                    {
                        Some(m)
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].primary_num_bytes, 7_000_000);
        assert_eq!(sent[0].shard_num_bytes, 1_000_000);
    }

    #[test]
    fn backfill_continuation_failure_releases_batch_and_retries() {
        use crate::recovery::PushInfo;
        use crate::store::{MemObj, MemStore};
        use denc::types::SnapId;
        use replwire::{MOSDPGPushReply, ObjectInfo, PushReplyOp, ReplMsg};

        for error in [
            StoreReadError::Io,
            StoreReadError::Corrupt,
            StoreReadError::NoObject,
            StoreReadError::VersionMismatch,
        ] {
            let spg = SpgT {
                pgid: PgT::new(1, 0),
                shard: ShardId::NO_SHARD,
            };
            let target = PgShard {
                osd: 1,
                shard: ShardId::NO_SHARD,
            };
            let map = SynthMap::new(4)
                .with_pool(1, 2, 1, 1)
                .with_osd(0, 1)
                .with_osd(1, 1)
                .into_handle();
            let mut cfg = Config::new(0);
            cfg.recovery_max_chunk = 4096;
            let mut pg = Pg::blank(Arc::new(cfg), spg, map, pgwire::PgInfo::new(spg));
            pg.acting = vec![0, 1];
            pg.up = pg.acting.clone();
            pg.st = St::Primary(PSt::Active(ASt::Backfilling));
            pg.state = pgs::ACTIVE | pgs::BACKFILLING;
            pg.prim.backfill_targets.insert(target);
            pg.prim.peer_info.insert(
                target,
                pgwire::PgInfo {
                    last_backfill: Hobject::MIN(),
                    ..pgwire::PgInfo::new(spg)
                },
            );
            pg.bf.reserved.insert(target.osd, target);
            let mut store = MemStore::new();
            store.submit(
                spg,
                &crate::StoreTxn {
                    ops: vec![crate::StoreOp::CreatePg],
                },
            );
            let oid = Hobject::new(b"large", SnapId::NOSNAP, 0, 1, b"");
            let version = Eversion::new(4, 1);
            let mut oi = ObjectInfo::new(oid.clone());
            oi.version = version;
            oi.size = 8192;
            store.pgs.get_mut(&spg).unwrap().objects.insert(
                oid.clone(),
                MemObj {
                    data: vec![0x5a; 8192],
                    xattrs: BTreeMap::from([(b"_".to_vec(), denc::to_vec(&oi).unwrap())]),
                    ..Default::default()
                },
            );
            let ri = store.recovery_info_checked(spg, &oid).unwrap();
            let chunk = store
                .build_push(spg, &ri, &ObjectRecoveryProgress::default(), 4096, 32)
                .unwrap();
            assert!(!chunk.after_progress.is_complete());
            pg.rec.pushes.insert(
                (oid.clone(), target.osd),
                PushInfo {
                    info: ri,
                    progress: chunk.after_progress,
                    stat: Default::default(),
                },
            );
            pg.bf.targets.insert(
                target,
                Bf {
                    phase: BfPhase::Pushing,
                    cursor: Hobject::MIN(),
                    batch_end: Hobject::MAX(),
                    batch_max: Some(oid.clone()),
                    todo: VecDeque::new(),
                    pushing: BTreeSet::from([oid.clone()]),
                },
            );
            assert!(pg.backfill_blocks(&oid));
            *store.push_error.borrow_mut() = Some(error.clone());
            pg.on_push_reply(
                target.osd,
                pgwire::msgs::PRIO_DEFAULT,
                MOSDPGPushReply {
                    pgid: spg,
                    map_epoch: 4,
                    from: target,
                    min_epoch: 4,
                    replies: vec![PushReplyOp { soid: oid.clone() }],
                    ..Default::default()
                },
                &store,
            );
            assert_eq!(
                pg.st,
                St::Primary(PSt::Active(ASt::NotBackfilling)),
                "{error:?}"
            );
            assert!(pg.bf.targets.is_empty());
            assert!(pg.rec.pushes.is_empty());
            assert!(!pg.backfill_blocks(&oid));
            assert!(pg.state & pgs::BACKFILL_UNFOUND != 0);
            assert!(pg.rec.retry_at > pg.now);
            assert!(pg.out.iter().any(|a| matches!(
                a,
                Action::Resv(ResvAction {
                    pool: SlotPool::Resv {
                        local: true,
                        backfill: true
                    },
                    op: SlotOp::Release,
                    ..
                })
            )));
            assert!(pg.out.iter().any(|a| matches!(a, Action::Send(s) if matches!(&s.body, Body::Repl(ReplMsg::BackfillReserve(m)) if m.ty == MBackfillReserve::RELEASE))));
            assert_eq!(pg.prim.peer_info[&target].last_backfill, Hobject::MIN());

            // A new reservation starts from the unchanged cursor and can finish the whole multi-chunk push.
            pg.start_backfill_remote();
            pg.backfill_granted(target.osd);
            pg.bf.targets.get_mut(&target).unwrap().phase = BfPhase::Pushing;
            pg.bf.targets.get_mut(&target).unwrap().batch_end = Hobject::MAX();
            pg.bf
                .targets
                .get_mut(&target)
                .unwrap()
                .todo
                .push_back((oid.clone(), false));
            pg.rec.cap = 3; // the lease a core's budget would hand out
            pg.backfill_step(&store);
            assert!(pg.rec.pushes.contains_key(&(oid.clone(), target.osd)));
            assert!(store.push_error.take().is_none());
            for _ in 0..2 {
                pg.on_push_reply(
                    target.osd,
                    pgwire::msgs::PRIO_DEFAULT,
                    MOSDPGPushReply {
                        pgid: spg,
                        map_epoch: 4,
                        from: target,
                        min_epoch: 4,
                        replies: vec![PushReplyOp { soid: oid.clone() }],
                        ..Default::default()
                    },
                    &store,
                );
                pg.backfill_step(&store);
            }
            assert!(pg.rec.pushes.is_empty());
            assert_eq!(pg.bf.targets[&target].phase, BfPhase::Finishing);
            pg.backfill_on_finish_ack(target.osd);
            assert!(!pg.prim.backfill_targets.contains(&target));
        }
    }

    /// Micro bench (`cargo test -p peering --release backfill_step_cost -- --ignored --nocapture`): ns per
    /// `backfill_step` event of a target with a full batch (512 queued, 512 pushing) at the op cap.
    #[test]
    #[ignore = "micro bench"]
    fn backfill_step_cost_with_a_full_batch() {
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        };
        let target = PgShard {
            osd: 1,
            shard: ShardId::NO_SHARD,
        };
        let map = SynthMap::new(4)
            .with_pool(1, 2, 1, 1)
            .with_osd(0, 1)
            .with_osd(1, 1)
            .into_handle();
        let mut pg = Pg::blank(Arc::new(Config::new(0)), spg, map, pgwire::PgInfo::new(spg));
        pg.acting = vec![0, 1];
        pg.up = pg.acting.clone();
        pg.st = St::Primary(PSt::Active(ASt::Backfilling));
        let obj = |n: usize| {
            Hobject::new(
                format!("o{n:06}").as_bytes(),
                denc::types::SnapId::NOSNAP,
                0,
                1,
                b"",
            )
        };
        pg.bf.targets.insert(
            target,
            Bf {
                phase: BfPhase::Pushing,
                cursor: Hobject::MIN(),
                batch_end: Hobject::MAX(),
                batch_max: None,
                todo: (0..512).map(|n| (obj(n), true)).collect(),
                pushing: (512..1024).map(obj).collect(),
            },
        );
        pg.rec.cap = 512;
        let store = crate::store::MemStore::new();
        let t = std::time::Instant::now();
        for _ in 0..1000 {
            pg.backfill_step(&store);
        }
        eprintln!("at cap: {} ns/event", t.elapsed().as_nanos() / 1000);
        assert_eq!(pg.bf.targets[&target].todo.len(), 512);
    }

    fn overlapping_target() -> (Pg, PgShard) {
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId(0),
        };
        let map = SynthMap::new(4)
            .with_pool(1, 3, 2, 1)
            .with_osd(0, 1)
            .with_osd(1, 1)
            .with_osd(2, 1)
            .with_osd(3, 1)
            .into_handle();
        let mut pg = Pg::blank(
            Arc::new(Config::new(0)),
            spg,
            map,
            pgwire::PgInfo::default(),
        );
        pg.pool.is_erasure = true;
        pg.acting = vec![0, 1, 2];
        pg.up = vec![0, 2, 3];
        let target = PgShard {
            osd: 2,
            shard: ShardId(1),
        };
        pg.prim.backfill_targets.insert(target);
        pg.prim.peer_info.insert(
            target,
            pgwire::PgInfo {
                last_backfill: Hobject::MIN(),
                ..Default::default()
            },
        );
        (pg, target)
    }

    #[test]
    fn reservation_and_release_keep_the_backfill_shard_after_target_removal() {
        let (mut pg, target) = overlapping_target();
        pg.start_backfill_remote();
        let sent = pg
            .out
            .iter()
            .find_map(|a| match a {
                Action::Send(s) => match &s.body {
                    Body::Repl(replwire::ReplMsg::BackfillReserve(m)) => Some(m.pgid.shard),
                    _ => None,
                },
                _ => None,
            })
            .unwrap();
        assert_eq!(sent, target.shard);
        pg.backfill_granted(target.osd);
        pg.prim.backfill_targets.clear();
        pg.out.clear();
        pg.release_backfill_reservations();
        assert!(pg.out.iter().any(|a| matches!(a, Action::Send(s)
            if matches!(&s.body, Body::Repl(replwire::ReplMsg::BackfillReserve(m))
                if m.ty == MBackfillReserve::RELEASE && m.pgid.shard == target.shard))));
    }

    #[test]
    fn digest_and_finish_ack_use_the_inflight_target_instead_of_acting() {
        let (mut pg, target) = overlapping_target();
        pg.start_backfill_remote();
        pg.backfill_granted(target.osd);
        pg.bf.targets.get_mut(&target).unwrap().phase = BfPhase::ScanSent;
        let digest = MOSDPGScan {
            op: MOSDPGScan::OP_DIGEST,
            map_epoch: 4,
            query_epoch: 4,
            pgid: pg.spg,
            begin: Hobject::MIN(),
            end: Hobject::MAX(),
            from: target,
            digest: Some(Vec::new()),
        };
        pg.backfill_on_digest(target.osd, digest, &crate::MemStore::new());
        assert!(!pg.counters.discards.contains_key("digest from non-target"));
        assert_ne!(pg.bf.targets[&target].phase, BfPhase::ScanSent);
        pg.bf.targets.get_mut(&target).unwrap().phase = BfPhase::Finishing;
        pg.backfill_on_finish_ack(target.osd);
        assert!(!pg.prim.backfill_targets.contains(&target));
    }

    /// Replicated size-2 primary in `st`, one backfill target `osd.1` whose reservation is granted.
    fn backfilling(st: ASt) -> (Pg, PgShard, crate::store::MemStore) {
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        };
        let target = PgShard {
            osd: 1,
            shard: ShardId::NO_SHARD,
        };
        let map = SynthMap::new(4)
            .with_pool(1, 2, 1, 1)
            .with_osd(0, 1)
            .with_osd(1, 1)
            .with_osd(2, 1)
            .into_handle();
        let mut pg = Pg::blank(Arc::new(Config::new(0)), spg, map, pgwire::PgInfo::new(spg));
        pg.acting = vec![0, 1];
        pg.up = pg.acting.clone();
        pg.acting_primary = 0;
        pg.up_primary = 0;
        pg.prim.acting_recovery_backfill = [pg.me, target].into_iter().collect();
        pg.prim.backfill_targets.insert(target);
        pg.prim.peer_info.insert(
            target,
            pgwire::PgInfo {
                last_backfill: Hobject::MIN(),
                last_update: Eversion::new(1, 1),
                ..pgwire::PgInfo::new(spg)
            },
        );
        pg.bf.reserved.insert(target.osd, target);
        pg.st = St::Primary(PSt::Active(st));
        pg.state = pgs::ACTIVE | pgs::BACKFILLING;
        let mut store = crate::store::MemStore::new();
        store.submit(
            spg,
            &crate::StoreTxn {
                ops: vec![crate::StoreOp::CreatePg],
            },
        );
        (pg, target, store)
    }

    /// Put a healthy local object with a decodable object_info into the store.
    fn put_object(store: &mut crate::store::MemStore, spg: SpgT, oid: &Hobject, v: Eversion) {
        use crate::store::MemObj;
        let mut oi = replwire::ObjectInfo::new(oid.clone());
        oi.version = v;
        oi.size = 64;
        store.pgs.get_mut(&spg).unwrap().objects.insert(
            oid.clone(),
            MemObj {
                data: vec![0x5a; 64],
                xattrs: BTreeMap::from([(b"_".to_vec(), denc::to_vec(&oi).unwrap())]),
                ..Default::default()
            },
        );
    }

    fn scan_replies(
        pg: &mut Pg,
        store: &crate::store::MemStore,
        target: PgShard,
        begin: Hobject,
        end: Hobject,
    ) -> Vec<Action> {
        let m = MOSDPGScan {
            op: MOSDPGScan::OP_DIGEST,
            map_epoch: pg.map.epoch(),
            query_epoch: pg.last_peering_reset,
            pgid: pg.spg,
            begin,
            end,
            from: target,
            digest: Some(Vec::new()),
        };
        pg.backfill_on_digest(target.osd, m, store);
        pg.take_actions()
    }

    /// A digest that does not advance past our cursor (end == cursor) would re-scan the same range forever, one with
    /// end < cursor moves `last_backfill` backwards: both are discarded, the target keeps waiting for its deadline.
    #[test]
    fn digest_that_does_not_advance_the_cursor_is_discarded() {
        let (mut pg, target, mut store) = backfilling(ASt::Backfilling);
        let cursor = Hobject::new(b"m", denc::types::SnapId::NOSNAP, 0, 1, b"");
        pg.bf.targets.insert(
            target,
            Bf {
                phase: BfPhase::ScanSent,
                cursor: cursor.clone(),
                batch_end: cursor.clone(),
                batch_max: None,
                todo: VecDeque::new(),
                pushing: BTreeSet::new(),
            },
        );
        let below = Hobject::new(b"a", denc::types::SnapId::NOSNAP, 0, 1, b"");
        for end in [cursor.clone(), below.clone()] {
            scan_replies(&mut pg, &store, target, cursor.clone(), end.clone());
            assert!(
                pg.counters.discards.contains_key("unexpected digest"),
                "digest end {end:?} was accepted"
            );
            assert_eq!(pg.bf.targets[&target].phase, BfPhase::ScanSent);
            assert_eq!(pg.bf.targets[&target].cursor, cursor, "cursor moved");
        }
        // an honest digest past the cursor still starts the batch, and its batch end may not go below it either
        put_object(&mut store, pg.spg, &cursor, Eversion::new(1, 1));
        let after = Hobject::new(b"z", denc::types::SnapId::NOSNAP, 0, 1, b"");
        scan_replies(&mut pg, &store, target, cursor.clone(), after);
        assert_eq!(pg.bf.targets[&target].phase, BfPhase::Pushing);
        assert!(pg.bf.targets[&target].batch_end > cursor);
    }

    /// A rejected digest leaves the scan deadline armed (the one owner of the stall): the target does not wait forever.
    #[test]
    fn a_rejected_digest_keeps_the_scan_deadline() {
        let (mut pg, target, store) = backfilling(ASt::Backfilling);
        let cursor = Hobject::new(b"m", denc::types::SnapId::NOSNAP, 0, 1, b"");
        pg.bf.targets.insert(
            target,
            Bf {
                phase: BfPhase::ScanSent,
                cursor: cursor.clone(),
                batch_end: cursor.clone(),
                batch_max: None,
                todo: VecDeque::new(),
                pushing: BTreeSet::new(),
            },
        );
        pg.now = 10;
        pg.bf.scan_wait.insert(target, 50);
        let m = MOSDPGScan {
            op: MOSDPGScan::OP_DIGEST,
            map_epoch: pg.map.epoch(),
            query_epoch: pg.last_peering_reset,
            pgid: pg.spg,
            begin: cursor.clone(),
            end: cursor.clone(), // does not advance
            from: target,
            digest: Some(Vec::new()),
        };
        pg.on_scan(target.osd, m, &store);
        assert!(pg.counters.discards.contains_key("unexpected digest"));
        assert!(pg.bf.scan_wait.contains_key(&target), "deadline kept");
        assert_eq!(pg.bf.targets[&target].phase, BfPhase::ScanSent);
        pg.now = 100;
        pg.rb_step();
        assert_eq!(pg.st, St::Primary(PSt::Active(ASt::NotBackfilling)));
        assert!(pg.bf.targets.is_empty() && pg.bf.scan_wait.is_empty());
        assert!(pg.rec.retry_at > pg.now, "retry armed");
        assert!(
            pg.counters
                .errors
                .contains_key("backfill: scan reply timed out")
        );
    }

    /// Object A is batched, building B fails and stops the backfill: A's push is dropped with the stop.
    #[test]
    fn a_stopped_backfill_sends_no_batched_push() {
        use crate::store::MemObj;
        let (mut pg, target, mut store) = backfilling(ASt::Backfilling);
        let a = Hobject::new(b"a", denc::types::SnapId::NOSNAP, 0, 1, b"");
        let bad = Hobject::new(b"b", denc::types::SnapId::NOSNAP, 0, 1, b"");
        put_object(&mut store, pg.spg, &a, Eversion::new(1, 1));
        store.pgs.get_mut(&pg.spg).unwrap().objects.insert(
            bad.clone(),
            MemObj {
                data: vec![1; 8],
                xattrs: BTreeMap::from([(b"_".to_vec(), vec![0xff; 3])]),
                ..Default::default()
            },
        );
        pg.bf.targets.insert(
            target,
            Bf {
                phase: BfPhase::Pushing,
                cursor: Hobject::MIN(),
                batch_end: Hobject::MAX(),
                batch_max: Some(bad.clone()),
                todo: VecDeque::from([(a.clone(), false), (bad.clone(), false)]),
                pushing: BTreeSet::new(),
            },
        );
        pg.rec.cap = 8;
        pg.take_actions();
        pg.backfill_step(&store);
        // the damaged B is repaired from a peer first: recovery takes over and the backfill stops
        assert_ne!(
            pg.st,
            St::Primary(PSt::Active(ASt::Backfilling)),
            "B stopped it"
        );
        assert!(pg.bf.targets.is_empty() && pg.rec.pushes.is_empty());
        assert!(
            !pg.take_actions().iter().any(|x| matches!(x, Action::Send(s)
                if matches!(&s.body, Body::Repl(replwire::ReplMsg::Push(_))))),
            "no push after the stop"
        );
    }

    /// One deadline, one reaction: a target still waiting for its digest stops the backfill (and keeps the retry
    /// timer), the RELEASE of the unanswered scan goes out exactly once (R7).
    #[test]
    fn an_expired_scan_deadline_stalls_once_and_releases_once() {
        let (mut pg, target, store) = backfilling(ASt::Backfilling);
        pg.now = 100;
        let cursor = Hobject::new(b"m", denc::types::SnapId::NOSNAP, 0, 1, b"");
        pg.bf.targets.insert(
            target,
            Bf {
                phase: BfPhase::ScanSent,
                cursor: cursor.clone(),
                batch_end: cursor.clone(),
                batch_max: None,
                todo: VecDeque::new(),
                pushing: BTreeSet::new(),
            },
        );
        pg.bf.scan_wait.insert(target, 50);
        pg.bf.release_owed.insert(target.osd, target);
        pg.take_actions();
        // the order `after_event` runs them in: `rb_step` first, then the backfill step
        pg.rb_step();
        pg.backfill_step(&store);
        let releases: Vec<_> = pg
            .take_actions()
            .into_iter()
            .filter(|a| {
                matches!(a, Action::Send(s) if matches!(&s.body, Body::Repl(replwire::ReplMsg::BackfillReserve(m))
                    if m.ty == MBackfillReserve::RELEASE && m.pgid.shard == target.shard))
            })
            .collect();
        assert_eq!(releases.len(), 1, "one RELEASE for the unanswered scan");
        assert_eq!(
            pg.st,
            St::Primary(PSt::Active(ASt::NotBackfilling)),
            "the deadline stopped the backfill"
        );
        assert!(pg.bf.targets.is_empty());
        assert!(pg.state & pgs::BACKFILL_UNFOUND != 0);
        assert!(pg.rec.retry_at > pg.now, "retried after the retry timer");
        assert_eq!(
            pg.counters.errors["backfill: scan reply timed out"], 1,
            "one error for one deadline"
        );
        assert_eq!(
            pg.notes.iter().filter(|n| n.contains("stopped")).count(),
            1,
            "one stop note for one deadline: {:?}",
            pg.notes
        );
        assert!(
            pg.notes.iter().all(|n| !n.contains("counted as answered")),
            "no note claims the scan was answered: {:?}",
            pg.notes
        );
    }

    /// A failed EC shard rebuild stops the backfill through `stop_backfill` (which clears the target map) while the
    /// push loop still runs: the loop must end, not panic on the cleared map (R1).
    #[test]
    fn ec_backfill_rebuild_failure_stops_without_panicking() {
        use crate::store::{MemObj, MemStore};
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId(0),
        };
        let target = PgShard {
            osd: 2,
            shard: ShardId(2),
        };
        let mut map = SynthMap::new(5)
            .with_osd(0, 1)
            .with_osd(1, 1)
            .with_osd(2, 1);
        map.pools.insert(
            1,
            pgwire::PoolParams {
                size: 3,
                min_size: 2,
                pg_num: 1,
                pg_num_pending: 1,
                is_erasure: true,
                ec_k: 2,
                ec: Some(Arc::new(pgwire::EcPoolInfo {
                    k: 2,
                    m: 1,
                    stripe_width: 8192,
                    chunk_size: 4096,
                    overwrites: true,
                    supported: true,
                    plugin: "isa".into(),
                    technique: "reed_sol_van".into(),
                    chunk_mapping: vec![0, 1, 2],
                    sub_chunks: 1,
                    primary_ok: true,
                    ..Default::default()
                })),
                ..Default::default()
            },
        );
        let mut pg = Pg::blank(
            Arc::new(Config::new(0)),
            spg,
            map.into_handle(),
            pgwire::PgInfo::new(spg),
        );
        pg.acting = vec![0, 1, 2];
        pg.up = pg.acting.clone();
        pg.acting_primary = 0;
        pg.up_primary = 0;
        pg.refresh_ecb();
        assert!(pg.ecb().is_some(), "code available");
        pg.prim.acting_recovery_backfill = [pg.me, target].into_iter().collect();
        pg.prim.backfill_targets.insert(target);
        pg.prim.peer_info.insert(
            target,
            pgwire::PgInfo {
                last_backfill: Hobject::MIN(),
                ..pgwire::PgInfo::new(spg)
            },
        );
        pg.bf.reserved.insert(target.osd, target);
        pg.st = St::Primary(PSt::Active(ASt::Backfilling));
        pg.state = pgs::ACTIVE | pgs::BACKFILLING;
        pg.rec.cap = 8;
        let oid = Hobject::new(b"shard", denc::types::SnapId::NOSNAP, 0, 1, b"");
        let v = Eversion::new(4, 1);
        let mut store = MemStore::new();
        store.submit(
            spg,
            &crate::StoreTxn {
                ops: vec![crate::StoreOp::CreatePg],
            },
        );
        // our shard is current, but no other shard can serve the read (the target does not count, its range does not
        // cover the object): the rebuild fails and stops the backfill
        let mut oi = replwire::ObjectInfo::new(oid.clone());
        oi.version = v;
        oi.size = 8192;
        store.pgs.get_mut(&spg).unwrap().objects.insert(
            oid.clone(),
            MemObj {
                data: vec![0x11; 8192],
                xattrs: BTreeMap::from([(b"_".to_vec(), denc::to_vec(&oi).unwrap())]),
                ..Default::default()
            },
        );
        pg.bf.targets.insert(
            target,
            Bf {
                phase: BfPhase::Pushing,
                cursor: Hobject::MIN(),
                batch_end: Hobject::MAX(),
                batch_max: Some(oid.clone()),
                todo: VecDeque::from([(oid.clone(), false)]),
                pushing: BTreeSet::new(),
            },
        );
        pg.backfill_step(&store); // must not panic: the failed rebuild cleared `bf.targets`
        assert_eq!(pg.st, St::Primary(PSt::Active(ASt::NotBackfilling)));
        assert!(pg.bf.targets.is_empty());
        assert!(pg.state & pgs::BACKFILL_UNFOUND != 0);
        assert!(pg.rec.retry_at > pg.now);
        assert!(pg.ep.recov.ops.is_empty());
        assert!(!pg.rec.pushes.contains_key(&(oid, target.osd)));
    }

    /// An unanswerable omap-size probe must not read as "not heavy": the object gets a batch of its own (and its push
    /// reports the error loudly) instead of dragging the objects behind it along (R5).
    #[test]
    fn an_unanswerable_omap_probe_treats_the_object_as_heavy() {
        let (mut pg, target, mut store) = backfilling(ASt::Backfilling);
        let cursor = Hobject::MIN();
        let a = Hobject::new(b"a", denc::types::SnapId::NOSNAP, 0, 1, b"");
        let b = Hobject::new(b"b", denc::types::SnapId::NOSNAP, 0, 1, b"");
        put_object(&mut store, pg.spg, &a, Eversion::new(1, 1));
        put_object(&mut store, pg.spg, &b, Eversion::new(1, 1));
        pg.bf.targets.insert(
            target,
            Bf {
                phase: BfPhase::ScanSent,
                cursor: cursor.clone(),
                batch_end: cursor.clone(),
                batch_max: None,
                todo: VecDeque::new(),
                pushing: BTreeSet::new(),
            },
        );
        store.omap_probe_error = true;
        scan_replies(&mut pg, &store, target, cursor, Hobject::MAX());
        assert!(
            pg.counters
                .errors
                .contains_key("backfill: omap size probe failed, treating the object as heavy")
        );
        let bf = &pg.bf.targets[&target];
        assert_eq!(
            bf.batch_end,
            chain_start(&a),
            "the batch ends right before the heavy object's chain"
        );
        assert!(
            bf.todo.is_empty(),
            "nothing is dragged along: {:?}",
            bf.todo
        );
    }

    fn snap_obj(name: &[u8], snap: u64) -> Hobject {
        Hobject::new(name, denc::types::SnapId(snap), 0, 1, b"")
    }

    fn scanning(pg: &mut Pg, target: PgShard, cursor: Hobject) {
        pg.bf.targets.insert(
            target,
            Bf {
                phase: BfPhase::ScanSent,
                cursor: cursor.clone(),
                batch_end: cursor,
                batch_max: None,
                todo: VecDeque::new(),
                pushing: BTreeSet::new(),
            },
        );
    }

    /// A batch edge between the newest clone of an object and its head: a write that clones the head (log entries for
    /// the new clone and the head) sees the clone behind the cursor and the head beyond it, so the target got the
    /// head's overwrite and a clone cut from its stale head, and the clone was never compared again. The edge stays at
    /// a chain start: the whole chain is beyond the cursor until its batch.
    #[test]
    fn a_batch_edge_never_splits_a_snap_chain() {
        let (mut pg, target, mut store) = backfilling(ASt::Backfilling);
        let x4 = snap_obj(b"x", 4);
        let y4 = snap_obj(b"y", 4);
        let y_head = snap_obj(b"y", denc::types::SnapId::NOSNAP.0);
        for o in [&x4, &y4, &y_head] {
            put_object(&mut store, pg.spg, o, Eversion::new(1, 1));
        }
        Arc::make_mut(&mut pg.cfg).backfill_scan_max = 2; // the listing stops between y@4 and y@head
        scanning(&mut pg, target, Hobject::MIN());
        scan_replies(&mut pg, &store, target, Hobject::MIN(), Hobject::MAX());
        let bf = &pg.bf.targets[&target];
        assert_eq!(
            bf.batch_end,
            chain_start(&y_head),
            "edge at the chain start"
        );
        assert_eq!(
            bf.todo.iter().map(|t| t.0.clone()).collect::<Vec<_>>(),
            vec![x4.clone()]
        );
        // batch done: the cursor is the chain start, so the new clone `y@6` and the head are both beyond it
        pg.bf.targets.get_mut(&target).unwrap().phase = BfPhase::Idle;
        pg.bf.targets.get_mut(&target).unwrap().cursor = chain_start(&y_head);
        assert!(!pg.backfill_target_has_range(&target, &snap_obj(b"y", 6)));
        assert!(!pg.backfill_target_has_range(&target, &y_head));
        assert!(pg.backfill_target_has_range(&target, &x4));
    }

    /// The heavy object's whole chain is its batch, not an edge between its clone and the head.
    #[test]
    fn a_heavy_clone_batches_its_whole_chain() {
        let (mut pg, target, mut store) = backfilling(ASt::Backfilling);
        let z3 = snap_obj(b"z", 3);
        let z_head = snap_obj(b"z", denc::types::SnapId::NOSNAP.0);
        let w = snap_obj(b"w", denc::types::SnapId::NOSNAP.0);
        for o in [&z3, &z_head, &w] {
            put_object(&mut store, pg.spg, o, Eversion::new(1, 1));
        }
        store
            .pgs
            .get_mut(&pg.spg)
            .unwrap()
            .objects
            .get_mut(&z3)
            .unwrap()
            .omap
            .extend((0..9000u32).map(|i| (i.to_be_bytes().to_vec(), vec![1])));
        let chain_z = chain_start(&z_head);
        let begin = chain_z.clone(); // the chain before z is done
        scanning(&mut pg, target, begin.clone());
        scan_replies(&mut pg, &store, target, begin, Hobject::MAX());
        let bf = &pg.bf.targets[&target];
        assert_eq!(
            bf.batch_end,
            chain_end(&z_head),
            "clone and head in one batch"
        );
        assert_eq!(bf.todo.len(), 2);
    }

    /// One chain with more keys than a scan holds and `begin` at its start: the listing stops at the head, so the edge
    /// would sit above the newest listed clone and at the head. A clone made after the batch (above every listed clone,
    /// below the head) would be behind the cursor while the head is beyond it. The edge moves down to the newest listed
    /// clone: the new clone and the head are both beyond the cursor.
    #[test]
    fn a_long_chain_edge_stays_on_a_listed_clone() {
        let (mut pg, target, mut store) = backfilling(ASt::Backfilling);
        let head = snap_obj(b"o", denc::types::SnapId::NOSNAP.0);
        for o in [
            snap_obj(b"o", 1),
            snap_obj(b"o", 2),
            snap_obj(b"o", 3),
            head.clone(),
        ] {
            put_object(&mut store, pg.spg, &o, Eversion::new(1, 1));
        }
        Arc::make_mut(&mut pg.cfg).backfill_scan_max = 3; // lists the three clones, stops at the head
        let begin = chain_start(&head);
        scanning(&mut pg, target, begin.clone());
        scan_replies(&mut pg, &store, target, begin, Hobject::MAX());
        let edge = snap_obj(b"o", 3);
        assert_eq!(
            pg.bf.targets[&target].batch_end, edge,
            "edge on the newest listed clone"
        );
        let b = pg.bf.targets.get_mut(&target).unwrap();
        b.phase = BfPhase::Idle;
        b.cursor = edge;
        assert!(pg.backfill_target_has_range(&target, &snap_obj(b"o", 2)));
        assert!(
            !pg.backfill_target_has_range(&target, &snap_obj(b"o", 4)),
            "new clone beyond"
        );
        assert!(!pg.backfill_target_has_range(&target, &head), "head beyond");
    }
}
