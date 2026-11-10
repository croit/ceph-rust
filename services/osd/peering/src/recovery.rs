// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Log-based recovery data plane: push apply (temp object then rename), pull serving, the
//! primary's pull/push engine, recovery deletes, reservations (replica grant side, primary
//! request side) and the replica side of backfill messages (spec replication.md 6, 7; peering.md
//! 4.4, 5.2). Primary-side backfill: `backfill.rs`.

use crate::pg::*;
use crate::plog::recompute_last_complete;
use crate::store::StoreReadError;
use crate::store::{PgStoreOps, StoreOp};
use crate::types::*;
use denc::types::{CollT, Eversion, Ghobject, Hobject, PgShard, SpgT};
use pgwire::state as pgs;
use pgwire::{MOSDPGTrim, PeeringMsg};
use replwire::interval::intersect_range;
use replwire::{
    IntervalSet, MBackfillReserve, MOSDPGBackfill, MOSDPGBackfillRemove, MOSDPGPull, MOSDPGPush,
    MOSDPGPushReply, MOSDPGRecoveryDelete, MOSDPGRecoveryDeleteReply, MOSDPGScan, MRecoveryReserve,
    ObjectRecoveryInfo, ObjectRecoveryProgress, PullOp, PushOp, PushReplyOp, Transaction, TxnOp,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub(crate) struct PullInfo {
    pub from: i32,
    pub info: ObjectRecoveryInfo,
    pub progress: ObjectRecoveryProgress,
    /// What the pull moved so far.
    pub stat: RecStat,
}

/// Data bytes and omap keys one object's recovery moved to one target (spec pg-io-stats.md 2): added to the PG's
/// `num_bytes_recovered` / `num_keys_recovered` once the object is recovered everywhere.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RecStat {
    pub bytes: u64,
    pub keys: u64,
}

impl RecStat {
    pub(crate) fn of(op: &PushOp) -> Self {
        Self {
            bytes: op.data.len() as u64,
            keys: op.omap_entries.len() as u64,
        }
    }
    pub(crate) fn plus(self, op: &PushOp) -> Self {
        let o = Self::of(op);
        Self {
            bytes: self.bytes + o.bytes,
            keys: self.keys + o.keys,
        }
    }
}

/// Running hinfo check of one EC shard push in flight (`Pg::ec_push_verify`).
#[derive(Debug, Clone)]
pub(crate) struct PushVerify {
    pub(crate) expect: u32,
    pub(crate) total: u64,
    pub(crate) crc: u32,
    pub(crate) next: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PushInfo {
    pub info: ObjectRecoveryInfo,
    pub progress: ObjectRecoveryProgress,
    /// What the pushes to this target moved so far.
    pub stat: RecStat,
}

/// PushOps of one `MOSDPGPush` message: at most `osd_max_push_objects` objects and below `osd_max_push_cost`
/// accumulated cost (spec replication.md 6.3). One message carries what was built up to that cut.
#[derive(Default)]
pub(crate) struct PushBatch {
    ops: Vec<PushOp>,
    cost: u64,
}

impl PushBatch {
    pub(crate) fn add(&mut self, op: PushOp) {
        self.cost += op.cost(REC_MSG_COST);
        self.ops.push(op);
    }
    /// The batch reached its object count or its cost: send it now.
    pub(crate) fn at_limit(&self, cfg: &Config) -> bool {
        self.ops.len() >= cfg.max_push_objects.max(1) || self.cost >= cfg.max_push_cost
    }
    fn take(&mut self) -> Vec<PushOp> {
        self.cost = 0;
        std::mem::take(&mut self.ops)
    }
}

/// Recovery bookkeeping (cleared at interval start).
#[derive(Debug, Default)]
pub(crate) struct RecoveryState {
    /// Peers we asked for a reservation and still await.
    pub reserve_wait: BTreeSet<i32>,
    pub reserve_cur: Option<i32>,
    /// `reserve_cur` was asked for but we no longer want it (flag, revoke): the replica cannot take a RELEASE before it
    /// granted (classic aborts on RecoveryDone in RepWaitRecoveryReserved, nor a second REQUEST), so we wait for the
    /// GRANT and release it right away.
    pub cur_cancelled: bool,
    pub reserved: BTreeSet<i32>,
    pub pulls: BTreeMap<Hobject, PullInfo>,
    /// By `(object, target OSD)`: "pushed to every target" is a range over the object.
    pub pushes: BTreeMap<(Hobject, i32), PushInfo>,
    /// By `(object, pg_shard)` (EC: one OSD may hold two positions, adr 0049 am. 3).
    pub deletes: BTreeSet<(Hobject, PgShard)>,
    pub failed_sources: BTreeSet<(i32, Hobject)>,
    /// Damaged local objects repaired from a peer in this interval (adr 0065): a second fault of the same object is
    /// answered EIO instead of repaired again (no repair loop on a fault that a fresh copy does not cure).
    pub dmg_repaired: BTreeSet<Hobject>,
    /// Replica: objects were recovered here, tell the primary once complete.
    pub had_missing: bool,
    pub reported: bool,
    /// Primary: when a refused (too full) backfill is tried again; 0 = not armed.
    pub retry_at: Mono,
    /// Primary: the last target OSD (id, map epoch) whose recovery / backfill reservation was refused because it is
    /// full (`backfill_toofull` / `recovery_toofull`). Operator-facing (`pg query`, the note); cleared when a
    /// reservation succeeds. Bounded: one entry.
    pub refused_by_full: Option<(i32, u32)>,
    /// Primary: the OSD-wide recovery pace holds this PG back until then (`osd_recovery_sleep*`); 0 = not armed.
    pub sleep_at: Mono,
    /// Primary: missing objects a client write waits for (parked as degraded): recovered first (classic
    /// `maybe_kick_recovery`). Cleared with the interval; stale names cost nothing.
    pub kick: BTreeSet<Hobject>,
    /// OSD-wide recovery-op budget (`osd_recovery_max_active`, adr 0031 am. 10): the ops this PG may have in flight at
    /// once. Handed out by the core's [`crate::recops::OpsLease`] (the PG starts an op only below it); 0 = none yet.
    pub cap: usize,
    /// The last recovery / backfill pass stopped at `cap` with work left: the PG waits for more.
    pub wants: bool,
    /// A slot was taken while the remote requests were pending (the local reserver preempted us, or a replica REVOKEd
    /// its recovery slot): go back to the queue as soon as they are answered (classic runs on without the slot; a stale
    /// GRANT would also reach a primary that moved on, which a classic primary there treats as an invalid event).
    pub slot_lost: bool,
    /// Primary: recovery stopped because everything left is unfound (classic UnfoundRecovery, spec ec-unfound-lost.md
    /// 1.7): NotRecovering without a retry timer until something becomes recoverable again (a marking, a new source).
    pub unfound_hold: bool,
    /// Cached answer of [`Pg::only_unfound_left`] with the [`Pg::unfound_key`] it was computed from: the predicate walks
    /// every missing object, the PG asks it after every event (a client op, a peer message, a tick) while a PG waits.
    pub unfound_verdict: Option<(u64, bool)>,
    /// Times the predicate walked the recovery set (tests: a held PG must not re-walk it per event).
    #[cfg(test)]
    pub unfound_walks: u64,
}

impl RecoveryState {
    /// Recovery order: objects a write waits for first, then by needed version.
    pub(crate) fn order(&self, need: Eversion, oid: &Hobject) -> (bool, Eversion) {
        (!self.kick.contains(oid), need)
    }
}

/// Resting recovery band and its maximum after the pool-option shift (spec replication.md 11.1).
const RECOVERY_PRIO: u32 = 180;
const RECOVERY_BAND_MAX: u32 = 219;
/// Recovery band of a PG whose known copies cannot satisfy `min_size` (deficit added to 220).
const RECOVERY_PRIO_INACTIVE: u32 = 220;
const INACTIVE_BAND_MAX: u32 = 253;
/// Reservation priority of a forced PG (spec force-recovery.md 5): above every computed value (<= 253).
const RECOVERY_PRIO_FORCED: u32 = 255;
/// Per-object cost added to the messenger throttle cost of a recovery message (classic charges every object op).
const REC_MSG_COST: u64 = 1000;

pub(crate) fn head_of(clone: &Hobject) -> Hobject {
    Hobject {
        snap: denc::types::SnapId::NOSNAP,
        ..clone.clone()
    }
}

fn temp_of(h: &Hobject) -> Hobject {
    Hobject {
        pool: Hobject::temp_pool(h.pool),
        ..h.clone()
    }
}

impl Pg {
    /// A clone travels with its head's SnapSet (every receiver derives the clone's snap mapper entry from it). While our
    /// own head is missing, its SnapSet is stale or absent (it would map the wrong snaps or none: a clone that snap
    /// trimming never finds), so the clone is recovered after the head. Classic skips it the same way ("still missing on
    /// primary").
    pub(crate) fn clone_waits_for_head(&self, oid: &Hobject) -> bool {
        crate::snaps::is_clone(oid) && self.missing.contains(&head_of(oid))
    }

    /// Header classes recognized by classic mclock; WPQ uses pool/OSD policy instead.
    pub(crate) fn recovery_message_priority(&self) -> u16 {
        if !self.cfg.recovery_mclock {
            return self
                .pool
                .recovery_op_priority
                .unwrap_or(self.cfg.recovery_op_priority);
        }
        if self.state & (pgs::FORCED_RECOVERY | pgs::FORCED_BACKFILL) != 0 {
            20
        } else if self.state & pgs::UNDERSIZED != 0 {
            15
        } else if self.state & pgs::DEGRADED != 0 {
            10
        } else {
            5
        }
    }

    /// Pause before the next recovery/backfill invocation (`osd_recovery_sleep*`; the DEGRADED bit selects the
    /// degraded variant, spec peering.md 13.1).
    pub(crate) fn recovery_sleep(&self) -> Mono {
        if self.state & pgs::DEGRADED != 0 {
            self.cfg.recovery_sleep_degraded
        } else {
            self.cfg.recovery_sleep
        }
    }

    /// The OSD-wide pace holds this recovery/backfill invocation back: a previous invocation started work inside the
    /// current sleep interval (classic `do_recovery` needs-sleep flag).
    pub(crate) fn recovery_sleep_hold(&self) -> bool {
        matches!(
            self.st,
            St::Primary(PSt::Active(ASt::Recovering | ASt::Backfilling))
        ) && self.recovery_sleep() > 0
            && self.now
                < self
                    .cfg
                    .rec_sched
                    .load(std::sync::atomic::Ordering::Relaxed)
    }

    // ---- reservations: replica side -----------------------------------------------------------------

    pub(crate) fn on_recovery_reserve(&mut self, from: i32, m: MRecoveryReserve) {
        if let St::Primary(PSt::Active(_)) = self.st {
            match m.ty {
                MRecoveryReserve::GRANT => self.primary_granted(from),
                MRecoveryReserve::REVOKE => self.recovery_revoked(from),
                _ => self.discard("recovery reserve at primary"),
            }
            return;
        }
        if self.st != St::ReplicaActive {
            self.discard("recovery reserve in non-active state");
            return;
        }
        if from != self.acting_primary {
            self.discard("recovery reserve from non-primary");
            return;
        }
        match m.ty {
            MRecoveryReserve::REQUEST => {
                if self.rep_res == RepRes::NotRecovering {
                    self.rep_res = RepRes::WaitRecovery;
                    self.slot_ask(
                        SlotPool::Resv {
                            local: false,
                            backfill: false,
                        },
                        SlotOp::Request {
                            immediate: false,
                            prio: m.priority,
                        },
                    );
                }
            }
            MRecoveryReserve::RELEASE => self.rep_release(),
            _ => self.discard("recovery reserve type"),
        }
    }

    /// Replica above backfillfull while it holds a backfill slot (classic `BackfillTooFull` in RepRecovering): send
    /// REVOKE_TOOFULL and give the slot back. `true` if it did.
    pub(crate) fn revoke_backfill_toofull(&mut self) -> bool {
        if self.rep_res != (RepRes::Recovering { backfill: true }) {
            return false;
        }
        let m = MBackfillReserve::reply(
            self.primary_spg(),
            self.map.epoch(),
            MBackfillReserve::REVOKE_TOOFULL,
        );
        self.send_repl(self.acting_primary, m, 0);
        self.rep_release();
        true
    }

    /// Shard bytes this PG expects to hold once a backfill from a primary with `primary_bytes` completes (classic
    /// `try_reserve_recovery_space`): EC = the primary's logical bytes / k plus one chunk per object we know of (a stripe
    /// overestimate per object). 0 = nothing to reserve.
    fn bf_projected(&self, primary_bytes: i64) -> u64 {
        let pb = primary_bytes.max(0) as u64;
        if pb == 0 {
            return 0;
        }
        match self.ec_ctx() {
            Some(e) if e.k > 0 => {
                let objs = self.info.stats.stats.sum.num_objects.max(0) as u64;
                pb / u64::from(e.k) + e.chunk.saturating_mul(objs)
            }
            _ => pb,
        }
    }

    /// Bytes the backfill reservation this replica holds (pending or granted) still expects: projected shard bytes
    /// minus what the shard holds now (it shrinks as pushes land and stale objects go). 0 without a reservation.
    pub fn backfill_held(&self, store: &impl PgStoreOps) -> u64 {
        if self.bf_space == 0
            || self.st != St::ReplicaActive
            || !matches!(
                self.rep_res,
                RepRes::WaitBackfill | RepRes::Recovering { backfill: true }
            )
        {
            return 0;
        }
        self.bf_space.saturating_sub(store.object_stats(self.spg).1)
    }

    pub(crate) fn on_backfill_reserve(
        &mut self,
        from: i32,
        m: MBackfillReserve,
        store: &impl PgStoreOps,
    ) {
        if matches!(self.st, St::Primary(_))
            && matches!(
                m.ty,
                MBackfillReserve::REJECT_TOOFULL | MBackfillReserve::REVOKE_TOOFULL
            )
        {
            self.bf_scan_answered(from, None); // its full event ran (the answer IS the reaction)
        }
        if let St::Primary(PSt::Active(_)) = self.st {
            match m.ty {
                MBackfillReserve::GRANT => self.backfill_granted(from),
                MBackfillReserve::REJECT_TOOFULL | MBackfillReserve::REVOKE_TOOFULL => {
                    self.backfill_toofull(from);
                }
                MBackfillReserve::REVOKE => self.backfill_revoked(from),
                _ => self.discard("backfill reserve type at primary"),
            }
            return;
        }
        if self.st != St::ReplicaActive {
            self.discard("backfill reserve in non-active state");
            return;
        }
        if from != self.acting_primary {
            self.discard("backfill reserve from non-primary");
            return;
        }
        // classic `try_reserve_recovery_space`: judge the fill as if the backfill data were already here
        let projected = if m.ty == MBackfillReserve::REQUEST {
            self.bf_projected(m.primary_num_bytes)
        } else {
            0
        };
        let pending = projected.saturating_sub(store.object_stats(self.spg).1);
        match m.ty {
            MBackfillReserve::REQUEST if self.local_full.backfillfull_with(pending) => {
                // no room for the backfill data, stay RepNotRecovering
                self.error(
                    "backfill reservation rejected: backfillfull with the pending backfill bytes",
                );
                let m = MBackfillReserve::reply(
                    self.primary_spg(),
                    m.query_epoch,
                    MBackfillReserve::REJECT_TOOFULL,
                );
                self.send_repl(from, m, 0);
                self.rep_release();
            }
            MBackfillReserve::REQUEST => {
                if self.rep_res == RepRes::NotRecovering {
                    self.rep_res = RepRes::WaitBackfill;
                    // held (and counted in this OSD's fill) until release, preemption or the end of the interval
                    self.bf_space = projected;
                    self.slot_ask(
                        SlotPool::Resv {
                            local: false,
                            backfill: true,
                        },
                        SlotOp::Request {
                            immediate: false,
                            prio: m.priority,
                        },
                    );
                }
            }
            MBackfillReserve::RELEASE => self.rep_release(),
            _ => self.discard("backfill reserve type"),
        }
    }

    fn rep_release(&mut self) {
        self.bf_space = 0;
        if self.rep_res != RepRes::NotRecovering {
            self.slot_release_remote();
            self.rep_res = RepRes::NotRecovering;
        }
    }

    /// Tell the primary that the remote reserver granted (`grant`) or preempted the slot of kind `backfill`.
    fn remote_resv_reply(&mut self, backfill: bool, grant: bool) {
        let (pgid, epoch, to) = (self.primary_spg(), self.map.epoch(), self.acting_primary);
        if backfill {
            let ty = if grant {
                MBackfillReserve::GRANT
            } else {
                MBackfillReserve::REVOKE
            };
            self.send_repl(to, MBackfillReserve::reply(pgid, epoch, ty), 0);
        } else {
            let ty = if grant {
                MRecoveryReserve::GRANT
            } else {
                MRecoveryReserve::REVOKE
            };
            self.send_repl(to, MRecoveryReserve::reply(pgid, epoch, ty), 0);
        }
    }

    /// The OSD-wide remote reserver granted our slot.
    pub fn remote_reserved(&mut self, now: Mono, backfill: bool) {
        self.now = now;
        let matches_state = matches!(
            (self.rep_res, backfill),
            (RepRes::WaitRecovery, false) | (RepRes::WaitBackfill, true)
        );
        if self.st != St::ReplicaActive || !matches_state {
            // stale grant: give the slot back
            self.slot_release_remote();
            return;
        }
        self.rep_res = RepRes::Recovering { backfill };
        self.remote_resv_reply(backfill, true);
    }

    /// The OSD-wide remote reserver took our granted slot for a higher priority request (its slot is free already): tell
    /// the primary (REVOKE) and stay as we are; the primary answers with RELEASE (classic `RepRecovering` on
    /// `Remote{Recovery,Backfill}Preempted`).
    pub fn remote_preempted(&mut self, now: Mono, backfill: bool) {
        self.now = now;
        if self.st != St::ReplicaActive || self.rep_res != (RepRes::Recovering { backfill }) {
            return;
        }
        // classic gives the reserved space back at once (the slot is gone; RELEASE follows)
        self.bf_space = 0;
        self.remote_resv_reply(backfill, false);
    }

    // ---- reservations: primary side -----------------------------------------------------------------------

    /// Ask the OSD-wide LOCAL reserver for a recovery slot (like classic's local reserver: bounds the PGs of this OSD
    /// that recover at once); the remote requests follow on the grant ([`Pg::local_reserved`]).
    pub(crate) fn start_recovery_reservation(&mut self) {
        if self.recovery_blocked() {
            self.hold_recovery();
            return;
        }
        self.set_st(St::Primary(PSt::Active(ASt::WaitLocalRecoveryReserved)));
        self.state |= pgs::RECOVERY_WAIT;
        self.slot_ask(
            SlotPool::Resv {
                local: true,
                backfill: false,
            },
            SlotOp::Request {
                immediate: false,
                prio: self.recovery_priority(),
            },
        );
    }

    /// Reservation priority of recovery now (spec force-recovery.md 5, replication.md 11.1): re-evaluated at every use,
    /// so a flag or pool-option change reaches the requests issued after it.
    pub(crate) fn recovery_priority(&self) -> u32 {
        if self.state & pgs::FORCED_RECOVERY != 0 {
            return RECOVERY_PRIO_FORCED;
        }
        let avail = self.avail_no_missing();
        if self.state & pgs::DEGRADED != 0 && avail < self.pool.min_size {
            let v = RECOVERY_PRIO_INACTIVE + (self.pool.min_size - avail);
            self.pool_priority(v, INACTIVE_BAND_MAX)
        } else {
            self.pool_priority(RECOVERY_PRIO, RECOVERY_BAND_MAX)
        }
    }

    /// Acting shards (primary included) whose missing set is empty: the copies known to satisfy reads
    /// (classic `avail_no_missing`, spec replication.md 11.1).
    fn avail_no_missing(&self) -> u32 {
        let mut n = u32::from(self.missing.is_empty());
        for p in &self.prim.acting_recovery_backfill {
            if p.osd != self.me.osd
                && self.acting.contains(&p.osd)
                && self.prim.peer_missing.get(p).is_none_or(|m| m.is_empty())
            {
                n += 1;
            }
        }
        n
    }

    /// Apply the pool option `recovery_priority` to a band value: the option is clamped to its documented range,
    /// the +10 shifts the band so an unset option sends 10 above the bare base, then the band maximum caps the
    /// result (spec replication.md 11.1).
    pub(crate) fn pool_priority(&self, base: u32, band_max: u32) -> u32 {
        let v = i64::from(base) + i64::from(self.pool.recovery_priority) + 10;
        v.clamp(0, i64::from(band_max)) as u32
    }

    /// The local reserver granted our slot of that kind (the PG waits for it: `PgSet` delivers nothing else): go on with
    /// the remote requests.
    pub fn local_reserved(&mut self, now: Mono, backfill: bool) {
        self.now = now;
        if self.local_wait().is_none_or(|w| w.0 != backfill) {
            return;
        }
        if backfill {
            self.start_backfill_remote();
        } else if self.recovery_set_full() {
            self.recovery_toofull();
        } else {
            self.start_recovery_remote();
        }
    }

    /// Classic `OSDMap::check_full(acting_recovery_backfill)`: a member the mon flagged FULL. Recovery would push into
    /// it, and a classic replica aborts on a push at its failsafe ratio (it never refuses log recovery itself).
    fn recovery_set_full(&self) -> bool {
        self.prim
            .acting_recovery_backfill
            .iter()
            .any(|p| self.map.is_full(p.osd))
    }

    /// A member of the recovery set is full: give the slots back, show `recovery_toofull`, try again after
    /// `osd_recovery_retry_interval` (classic `RecoveryTooFull`).
    fn recovery_toofull(&mut self) {
        self.release_recovery_reservations();
        self.cancel_inflight();
        self.set_st(St::Primary(PSt::Active(ASt::NotRecovering)));
        self.state &= !(pgs::RECOVERY_WAIT | pgs::RECOVERING);
        self.state |= pgs::RECOVERY_TOOFULL;
        self.rec.retry_at = self.now + self.cfg.recovery_retry;
        let who = self
            .prim
            .acting_recovery_backfill
            .iter()
            .find(|p| self.map.is_full(p.osd))
            .map(|p| p.osd);
        if let Some(osd) = who {
            self.rec.refused_by_full = Some((osd, self.map.epoch()));
            self.notes.push(format!(
                "pg {}: recovery held: osd.{} is full, retry in {}s",
                self.spg,
                osd,
                self.cfg.recovery_retry / crate::types::SEC
            ));
        } else {
            self.notes.push(format!(
                "pg {}: recovery held: a member of the recovery set is full, retry in {}s",
                self.spg,
                self.cfg.recovery_retry / crate::types::SEC
            ));
        }
    }

    /// Waiting for a local slot: `(backfill, priority)`.
    pub fn local_wait(&self) -> Option<(bool, u32)> {
        match self.st {
            St::Primary(PSt::Active(ASt::WaitLocalRecoveryReserved)) => {
                Some((false, self.recovery_priority()))
            }
            St::Primary(PSt::Active(ASt::WaitLocalBackfillReserved)) => {
                Some((true, self.backfill_priority()))
            }
            _ => None,
        }
    }

    /// `ceph pg force-recovery|force-backfill|cancel-*` (MOSDForceRecovery, spec force-recovery.md 3): only a primary
    /// acts. Setting needs the PG degraded, waiting or running that kind of work; cancelling works whenever the flag is
    /// set. The in-memory flag shows in the state string and re-prioritises the local reservation.
    pub fn force_recovery(
        &mut self,
        now: Mono,
        backfill: bool,
        cancel: bool,
        store: &impl PgStoreOps,
    ) {
        self.now = now;
        if !self.is_primary() {
            self.discard("force recovery at non-primary");
            return;
        }
        let (flag, work) = if backfill {
            (
                pgs::FORCED_BACKFILL,
                pgs::DEGRADED | pgs::BACKFILL_WAIT | pgs::BACKFILLING,
            )
        } else {
            (
                pgs::FORCED_RECOVERY,
                pgs::DEGRADED | pgs::RECOVERY_WAIT | pgs::RECOVERING,
            )
        };
        let forced = self.state & flag != 0;
        if cancel != forced || (!cancel && self.state & work == 0) {
            return; // set twice, cancel of an unset flag, or nothing to force
        }
        self.state ^= flag;
        // classic re-prioritises with the priority of the flag's own kind whichever phase the PG is in
        let prio = if backfill {
            self.backfill_priority()
        } else {
            self.recovery_priority()
        };
        match self.local_resv_needed() {
            (false, false) => {}
            (rec, _) => self.slot_ask(
                SlotPool::Resv {
                    local: true,
                    backfill: !rec,
                },
                SlotOp::Request {
                    immediate: false,
                    prio,
                },
            ),
        }
        self.after_event(store);
    }

    /// Which local slots this PG's state justifies: `(recovery, backfill)`. `PgSet` gives back anything else (safety
    /// net for interval changes, removal and every path that resets the PG without saying so).
    pub fn local_resv_needed(&self) -> (bool, bool) {
        use ASt::*;
        match self.st {
            St::Primary(PSt::Active(
                WaitLocalRecoveryReserved | WaitRemoteRecoveryReserved | Recovering,
            )) => (true, false),
            St::Primary(PSt::Active(
                WaitLocalBackfillReserved | WaitRemoteBackfillReserved | Backfilling,
            )) => (false, true),
            _ => (false, false),
        }
    }

    fn start_recovery_remote(&mut self) {
        self.set_st(St::Primary(PSt::Active(ASt::WaitRemoteRecoveryReserved)));
        let peers: Vec<PgShard> = self
            .prim
            .acting_recovery_backfill
            .iter()
            .copied()
            .filter(|p| *p != self.me && !self.prim.backfill_targets.contains(p))
            .filter(|p| self.prim.peer_missing.get(p).is_some_and(|m| !m.is_empty()))
            .collect();
        if peers.is_empty() {
            self.begin_recovering();
            return;
        }
        // Slots are requested one at a time in ascending OSD order: ordered acquisition rules out
        // AB-BA deadlocks between PGs that need the same set of remote slots.
        self.rec.reserve_wait = peers.iter().map(|p| p.osd).collect();
        self.rec_request_next();
    }

    fn rec_request_next(&mut self) {
        if self.rec.reserve_cur.is_some() {
            return;
        }
        let Some(o) = self.rec.reserve_wait.iter().next().copied() else {
            self.begin_recovering();
            return;
        };
        self.rec.reserve_wait.remove(&o);
        self.rec.reserve_cur = Some(o);
        let epoch = self.map.epoch();
        let prio = self.recovery_priority();
        self.send_repl(
            o,
            MRecoveryReserve {
                pgid: self.spg_of(o),
                query_epoch: epoch,
                ty: MRecoveryReserve::REQUEST,
                priority: prio,
            },
            0,
        );
    }

    pub(crate) fn spg_of(&self, osd: i32) -> SpgT {
        SpgT {
            pgid: self.spg.pgid,
            shard: self.pshard(osd).shard,
        }
    }

    /// `osd` holds or is asked for our recovery slot.
    pub(crate) fn rec_engaged(&self, osd: i32) -> bool {
        self.rec.reserved.contains(&osd) || self.rec.reserve_cur == Some(osd)
    }

    /// `osd` holds or is asked for our backfill slot.
    pub(crate) fn bf_engaged(&self, osd: i32) -> bool {
        self.bf.reserved.contains_key(&osd) || self.bf.reserve_cur.is_some_and(|p| p.osd == osd)
    }

    fn primary_granted(&mut self, from: i32) {
        if self.rec.reserve_cur == Some(from) {
            self.rec.reserve_cur = None;
            if std::mem::take(&mut self.rec.cur_cancelled) {
                let epoch = self.map.epoch();
                self.send_repl(
                    from,
                    MRecoveryReserve::reply(self.spg_of(from), epoch, MRecoveryReserve::RELEASE),
                    0,
                );
                if self.st == St::Primary(PSt::Active(ASt::WaitRemoteRecoveryReserved)) {
                    self.rec_request_next();
                }
                return;
            }
            self.rec.reserved.insert(from);
            if self.st == St::Primary(PSt::Active(ASt::WaitRemoteRecoveryReserved)) {
                self.rec_request_next();
            }
        } else if !self.rec.reserved.contains(&from) && !self.bf_engaged(from) {
            // stale grant (a duplicated request re-reserved the slot after our release): give it back, unless the
            // peer holds / is asked for our BACKFILL slot: RELEASE frees whatever slot the replica holds (classic RRC
            // RecoveryDone -> RepNotRecovering; ours `rep_release`)
            let epoch = self.map.epoch();
            self.send_repl(
                from,
                MRecoveryReserve::reply(self.spg_of(from), epoch, MRecoveryReserve::RELEASE),
                0,
            );
        } else if !self.rec.reserved.contains(&from) {
            self.discard("stale recovery grant, peer busy with backfill");
        }
    }

    fn begin_recovering(&mut self) {
        if self.rec.slot_lost {
            return self.defer_recovery();
        }
        self.set_st(St::Primary(PSt::Active(ASt::Recovering)));
        self.state &= !pgs::RECOVERY_WAIT;
        self.state |= pgs::RECOVERING;
        self.rec.refused_by_full = None;
    }

    pub(crate) fn release_recovery_reservations(&mut self) {
        self.slot_release(SlotPool::Resv {
            local: true,
            backfill: false,
        });
        let peers: Vec<i32> = std::mem::take(&mut self.rec.reserved).into_iter().collect();
        self.rec.cur_cancelled = self.rec.reserve_cur.is_some();
        let epoch = self.map.epoch();
        for o in peers {
            self.send_repl(
                o,
                MRecoveryReserve::reply(self.spg_of(o), epoch, MRecoveryReserve::RELEASE),
                0,
            );
        }
        self.rec.reserve_wait.clear();
    }

    // ---- flags and refused / revoked reservations (primary; spec peering.md 4.4, 5.3, 9.4) ---------------------

    fn degraded_now(&self) -> bool {
        self.state & (pgs::DEGRADED | pgs::UNDERSIZED) != 0
    }

    /// NORECOVER / PAUSEREC hold log-based recovery; NOREBALANCE holds it unless the PG is degraded.
    pub(crate) fn recovery_blocked(&self) -> bool {
        let f = self.map.rb_flags();
        f.norecover || f.pauserec || (f.norebalance && !self.degraded_now())
    }

    /// NORECOVER and PAUSEREC also hold backfill; NOBACKFILL; NOREBALANCE unless the PG is degraded.
    pub(crate) fn backfill_blocked(&self) -> bool {
        let f = self.map.rb_flags();
        f.norecover || f.pauserec || f.nobackfill || (f.norebalance && !self.degraded_now())
    }

    /// Flag-held start of recovery: no reservation traffic, the PG shows `recovery_wait`.
    pub(crate) fn hold_recovery(&mut self) {
        self.set_st(St::Primary(PSt::Active(ASt::NotRecovering)));
        self.state &= !pgs::RECOVERING;
        self.state |= pgs::RECOVERY_WAIT;
    }

    /// Flag-held start of backfill: no reservation traffic, the PG shows `backfill_wait`.
    pub(crate) fn hold_backfill(&mut self) {
        self.set_st(St::Primary(PSt::Active(ASt::NotBackfilling)));
        self.state &= !pgs::BACKFILLING;
        self.state |= pgs::BACKFILL_WAIT;
    }

    /// A replica refused (REJECT_TOOFULL) or withdrew (REVOKE_TOOFULL) its backfill slot: release everything, show
    /// `backfill_toofull`, try again after `osd_backfill_retry_interval`.
    pub(crate) fn backfill_toofull(&mut self, from: i32) {
        if !self.bf_reservation_live(from) {
            self.discard("backfill toofull outside a reservation");
            return;
        }
        self.stop_backfill();
        self.state &= !(pgs::BACKFILL_WAIT | pgs::BACKFILLING);
        self.state |= pgs::BACKFILL_TOOFULL;
        self.set_st(St::Primary(PSt::Active(ASt::NotBackfilling)));
        self.rec.retry_at = self.now + self.cfg.backfill_retry;
        self.rec.refused_by_full = Some((from, self.map.epoch()));
        self.notes.push(format!(
            "pg {}: backfill held: osd.{} is backfillfull, retry in {}s",
            self.spg,
            from,
            self.cfg.backfill_retry / crate::types::SEC
        ));
    }

    /// A replica preempted our backfill slot: stop, release, queue again.
    pub(crate) fn backfill_revoked(&mut self, from: i32) {
        if !self.bf_reservation_live(from) {
            self.discard("backfill revoke outside a reservation");
            return;
        }
        self.defer_backfill();
    }

    /// Stop, release, queue again (a preempted backfill: classic `DeferBackfill` / `RemoteReservationRevoked`).
    pub(crate) fn defer_backfill(&mut self) {
        self.rec.slot_lost = false;
        self.stop_backfill();
        self.state &= !(pgs::BACKFILL_WAIT | pgs::BACKFILLING);
        self.start_backfill_reservation();
    }

    /// The OSD-wide local reserver took our granted slot for a higher priority request (its slot is free already): give
    /// the remote slots back and queue again with the same priority rules as after a replica's REVOKE (classic
    /// `DeferRecovery` / `DeferBackfill` with delay 0). While the remote requests are pending the PG finishes that
    /// exchange first (classic ignores the preemption there and runs on without the slot, outside the budget): it defers
    /// when the last grant arrived.
    pub fn local_preempted(&mut self, now: Mono, backfill: bool) {
        self.now = now;
        use ASt::*;
        match (self.st, backfill) {
            (St::Primary(PSt::Active(Backfilling)), true) => self.defer_backfill(),
            (St::Primary(PSt::Active(Recovering)), false) => self.defer_recovery(),
            (St::Primary(PSt::Active(WaitRemoteBackfillReserved)), true)
            | (St::Primary(PSt::Active(WaitRemoteRecoveryReserved)), false) => {
                self.rec.slot_lost = true;
            }
            _ => {}
        }
    }

    /// Stop, release, queue again (a preempted recovery).
    pub(crate) fn defer_recovery(&mut self) {
        self.rec.slot_lost = false;
        self.release_recovery_reservations();
        self.cancel_inflight();
        self.state &= !(pgs::RECOVERY_WAIT | pgs::RECOVERING);
        self.start_recovery_reservation();
    }

    /// A replica preempted our recovery slot: stop, release, queue again (once pending requests are answered).
    pub(crate) fn recovery_revoked(&mut self, from: i32) {
        let live = matches!(
            self.st,
            St::Primary(PSt::Active(
                ASt::WaitRemoteRecoveryReserved | ASt::Recovering
            ))
        ) && (self.rec.reserved.contains(&from)
            || (self.rec.reserve_cur == Some(from) && !self.rec.cur_cancelled));
        if !live {
            self.discard("recovery revoke outside a reservation");
            return;
        }
        // While requests are pending, finish that exchange first (as for a local preemption): deferring now would let
        // the GRANT of the request in flight reach a primary in WaitLocalRecoveryReserved (classic ignores the REVOKE
        // there and never sees such a GRANT).
        if self.st == St::Primary(PSt::Active(ASt::WaitRemoteRecoveryReserved)) {
            self.rec.slot_lost = true;
            return;
        }
        self.defer_recovery();
    }

    fn bf_reservation_live(&self, from: i32) -> bool {
        matches!(
            self.st,
            St::Primary(PSt::Active(
                ASt::WaitRemoteBackfillReserved | ASt::Backfilling
            ))
        ) && self.prim.backfill_targets.iter().any(|p| p.osd == from)
    }

    /// Forget in-flight pulls, pushes and deletes when recovery or backfill stops. Their replies are dropped while the
    /// PG is not Recovering/Backfilling, so keeping the records would block the restarted work forever; the next
    /// pass re-issues whatever is still missing.
    fn cancel_inflight(&mut self) {
        self.rec.pulls.clear();
        self.rec.pushes.clear();
        self.rec.deletes.clear();
        self.ep.recov.cancel();
    }

    pub(crate) fn stop_backfill(&mut self) {
        self.leave_backfilling();
        self.release_backfill_reservations();
        self.bf.targets.clear();
        self.cancel_inflight();
    }

    /// Every exit from `Backfilling` (finish, preemption, too full, error) clears both forced flags (spec
    /// force-recovery.md 6.4).
    pub(crate) fn leave_backfilling(&mut self) {
        if self.st == St::Primary(PSt::Active(ASt::Backfilling)) {
            self.state &= !(pgs::FORCED_RECOVERY | pgs::FORCED_BACKFILL);
        }
    }

    /// Resume work that flags or a retry timer held back. Runs at the start of every housekeeping pass.
    pub(crate) fn rb_step(&mut self) {
        self.bf_scan_deadlines();
        self.damage_settle();
        // a flag set while work is in progress: like classic, defer and RELEASE the reservations (other PGs may
        // need the slots), wait in the held state, re-request when the flag clears
        match self.st {
            St::Primary(PSt::Active(
                ASt::WaitLocalRecoveryReserved | ASt::WaitRemoteRecoveryReserved | ASt::Recovering,
            )) if self.recovery_blocked() => {
                self.release_recovery_reservations();
                self.cancel_inflight();
                self.hold_recovery();
            }
            St::Primary(PSt::Active(
                ASt::WaitLocalBackfillReserved | ASt::WaitRemoteBackfillReserved | ASt::Backfilling,
            )) if self.backfill_blocked() => {
                self.stop_backfill();
                self.hold_backfill();
            }
            _ => {}
        }
        if self.rec.unfound_hold {
            if self.st != St::Primary(PSt::Active(ASt::NotRecovering)) {
                // recovery restarted by another path: the hold is over
                self.rec.unfound_hold = false;
                self.state &= !pgs::RECOVERY_UNFOUND;
            } else {
                // classic DoRecovery after UnfoundRecovery: a marking committed or a source turned up
                if self.unfound_resume_due() {
                    self.rec.unfound_hold = false;
                    self.state &= !pgs::RECOVERY_UNFOUND;
                    self.on_activate_complete();
                }
                return;
            }
        }
        match self.st {
            St::Primary(PSt::Active(ASt::NotRecovering))
                if !self.recovery_blocked()
                    && (self.rec.retry_at == 0 || self.now >= self.rec.retry_at) =>
            {
                self.rec.retry_at = 0;
                self.state &= !(pgs::RECOVERY_WAIT | pgs::RECOVERY_TOOFULL);
                self.on_activate_complete();
            }
            St::Primary(PSt::Active(ASt::NotBackfilling))
                if !self.backfill_blocked()
                    && (self.rec.retry_at == 0 || self.now >= self.rec.retry_at) =>
            {
                self.rec.retry_at = 0;
                self.state &= !(pgs::BACKFILL_WAIT | pgs::BACKFILL_TOOFULL | pgs::BACKFILL_UNFOUND);
                self.on_activate_complete();
            }
            _ => {}
        }
    }
    // ---- primary engine ---------------------------------------------------------------------------------------

    /// Recovery / backfill ops this PG has in flight (pull, push, delete: one per object), the units of the OSD-wide
    /// `osd_recovery_max_active` budget. Counted from the state, so an op cleared by an interval change or a cancel
    /// frees its unit with no bookkeeping of its own.
    pub(crate) fn rec_inflight(&self) -> usize {
        match self.st {
            St::Primary(PSt::Active(ASt::Backfilling)) => {
                self.bf.targets.values().map(|b| b.pushing.len()).sum()
            }
            St::Primary(PSt::Active(ASt::Recovering)) if self.pool.is_erasure => {
                self.ep.recov.ops.len() + self.rec.deletes.len()
            }
            St::Primary(PSt::Active(ASt::Recovering)) => {
                self.rec.pulls.len() + self.rec.pushes.len() + self.rec.deletes.len()
            }
            _ => 0,
        }
    }

    /// The budget changed (a lease was granted): run the recovery / backfill pass again.
    pub(crate) fn rec_kick(&mut self, now: Mono, store: &impl PgStoreOps) {
        self.now = now;
        self.after_event(store);
    }

    /// Drive pulls and pushes while Recovering.
    pub(crate) fn recovery_step(&mut self, store: &impl PgStoreOps) {
        if self.pool.is_erasure {
            return self.ec_recovery_step(store);
        }
        if self.st != St::Primary(PSt::Active(ASt::Recovering)) || self.recovery_blocked() {
            return;
        }
        let peers: Vec<PgShard> = self
            .prim
            .acting_recovery_backfill
            .iter()
            .copied()
            .filter(|p| *p != self.me && !self.prim.backfill_targets.contains(p))
            .collect();
        let peers_done = peers
            .iter()
            .all(|p| self.prim.peer_missing.get(p).is_none_or(|m| m.is_empty()));
        if self.missing.is_empty()
            && peers_done
            && self.rec.pulls.is_empty()
            && self.rec.pushes.is_empty()
            && self.rec.deletes.is_empty()
        {
            self.all_recovered();
            return;
        }
        let max = self.rec.cap;
        let mut inflight = self.rec.pulls.len() + self.rec.pushes.len() + self.rec.deletes.len();
        // 1. our own missing objects: pull
        let mut dirty = false;
        let mine: Vec<(Eversion, Hobject, bool)> = if inflight >= max {
            // at the cap nothing starts: skip collecting and ordering the missing set
            self.rec.wants |= !self.missing.is_empty();
            Vec::new()
        } else {
            let mut mine: Vec<_> = self
                .missing
                .iter()
                .map(|(o, i)| (i.need, o.clone(), i.is_delete()))
                .collect();
            // stable sort of an oid-ordered list: ties stay in oid order
            mine.sort_by_cached_key(|(need, oid, _)| self.rec.order(*need, oid));
            mine
        };
        for (need, oid, is_delete) in mine {
            if inflight >= max {
                self.rec.wants = true;
                break;
            }
            if self.rec.pulls.contains_key(&oid) {
                continue;
            }
            if is_delete {
                self.txn.push(StoreOp::RemoveObject(oid.clone()));
                self.missing.got(&oid, need);
                dirty = true;
                continue;
            }
            // LOST_REVERT (mark_unfound_lost): the data wanted is an older version, held by us or by a peer
            let revert = self.revert_of(&oid, need);
            if let Some(old) = revert
                && self.missing.get(&oid).is_some_and(|i| i.have == old)
                && self.revert_in_place(store, &oid, need, old)
            {
                dirty = true;
                continue;
            }
            let src = self.pull_source(&peers, &oid, need);
            let Some(src) = src else {
                continue; // unfound (lost.rs): waits for a source or mark_unfound_lost
            };
            let ri = ObjectRecoveryInfo {
                soid: oid.clone(),
                version: match revert {
                    Some(old)
                        if self
                            .prim
                            .peer_missing
                            .get(&src)
                            .is_some_and(|m| m.contains(&oid)) =>
                    {
                        old
                    }
                    // damaged object older than the log: the source answers with its own version
                    _ if need == crate::damage::NEED_ANY => Eversion::default(),
                    _ => need,
                },
                size: u64::MAX,
                copy_subset: BTreeMap::from([(0, u64::MAX)]),
                object_exist: false,
                ..Default::default()
            };
            let prog = ObjectRecoveryProgress::default();
            self.rec.pulls.insert(
                oid.clone(),
                PullInfo {
                    from: src.osd,
                    info: ri.clone(),
                    progress: prog.clone(),
                    stat: RecStat::default(),
                },
            );
            let prio = self.recovery_message_priority();
            self.send_pull(src, ri, prog, prio);
            inflight += 1;
        }
        if dirty {
            recompute_last_complete(&self.log, &mut self.info, &self.missing);
            self.info_dirty = true;
        }
        // 2. pushes to peers
        for p in &peers {
            let Some(pm) = self.prim.peer_missing.get(p) else {
                continue;
            };
            if inflight >= max {
                if !pm.is_empty() {
                    self.rec.wants = true;
                }
                continue;
            }
            let mut items: Vec<(Eversion, Hobject, Eversion, bool)> = pm
                .iter()
                .map(|(o, i)| (i.need, o.clone(), i.have, i.is_delete()))
                .collect();
            items.sort_by_cached_key(|(need, oid, ..)| self.rec.order(*need, oid));
            let mut pushes = PushBatch::default();
            let mut deletes: Vec<(Hobject, Eversion)> = Vec::new();
            for (need, oid, have, is_delete) in items {
                if inflight >= max {
                    self.rec.wants = true;
                    break;
                }
                if self.rec.pushes.contains_key(&(oid.clone(), p.osd))
                    || self.rec.deletes.contains(&(oid.clone(), *p))
                {
                    continue;
                }
                if is_delete {
                    self.rec.deletes.insert((oid.clone(), *p));
                    deletes.push((oid, need));
                    inflight += 1;
                    if deletes.len() >= self.cfg.max_push_objects.max(1) {
                        self.flush_recovery_deletes(*p, &mut deletes);
                    }
                    continue;
                }
                if self.missing.contains(&oid) {
                    continue; // we have to pull it first
                }
                if self.clone_waits_for_head(&oid) {
                    continue;
                }
                if self.write_in_flight(&oid) || self.applying.contains_key(&oid) {
                    // its commit runs recovery again, on the version it wrote / just recovered here (a store read before
                    // that commit may not see it yet: spec replication.md 6.6)
                    continue;
                }
                // Never skip silently (recovery would never finish): a local copy that is absent, older than the
                // version the peer needs, damaged or unreadable although our missing set says we have it is lost here
                // (classic `primary_error`): it becomes missing and is pulled from a peer that has it. Count it.
                let lost = match store.recovery_info_checked(self.spg, &oid) {
                    // NEED_ANY: a replica's damaged copy older than its log (adr 0065), our current version is the one
                    Ok(ri) if ri.version >= need || need == crate::damage::NEED_ANY => Ok(ri),
                    Ok(_) | Err(StoreReadError::NoObject) => Err(
                        "recovery: local copy absent or older than needed, re-pulling from a peer",
                    ),
                    Err(_) => Err("recovery: local copy unreadable, re-pulling from a peer"),
                };
                // newer than `need`: push the object as it is (classic pushes the current version); `got` accepts it
                let mut ri = match lost {
                    Ok(ri) => ri,
                    Err(why) => {
                        self.error(why);
                        self.local_damage(&oid, Some(need));
                        continue;
                    }
                };
                ri.object_exist = have != Eversion::default();
                let prog = ObjectRecoveryProgress::default();
                match store.build_push(
                    self.spg,
                    &ri,
                    &prog,
                    self.cfg.recovery_max_chunk,
                    self.cfg.recovery_max_omap_entries,
                ) {
                    Ok(op) => {
                        let after = op.after_progress.clone();
                        self.rec.pushes.insert(
                            (oid.clone(), p.osd),
                            PushInfo {
                                info: ri,
                                progress: after,
                                stat: RecStat::of(&op),
                            },
                        );
                        pushes.add(op);
                        inflight += 1;
                        if pushes.at_limit(&self.cfg) {
                            self.flush_push_batch(*p, &mut pushes);
                        }
                    }
                    Err(e) => {
                        self.error("build_push failed");
                        // Readable object_info does not establish that its payload/omap is readable. Like an
                        // info-read failure above, recover our copy before trying to send it to the missing peer.
                        if matches!(e, StoreReadError::Corrupt | StoreReadError::Io) {
                            self.local_damage(&oid, Some(ri.version));
                        }
                    }
                }
            }
            self.flush_push_batch(*p, &mut pushes);
            self.flush_recovery_deletes(*p, &mut deletes);
        }
        self.maybe_unfound_recovery();
    }

    /// Where can we get `oid` at `need` or newer: acting members that do not miss it first, then
    /// strays whose info says they have it (spec 6.4 missing_loc; strays are valid sources).
    fn pull_source(
        &self,
        acting_peers: &[PgShard],
        oid: &Hobject,
        need: Eversion,
    ) -> Option<PgShard> {
        self.holders(acting_peers, oid, need).first().copied()
    }

    /// LOST_REVERT, the old version is on our own disk: stamp it with the revert entry's version (object_info only, the
    /// data is already right). `false` = the local copy is not at that version (pull it from a peer).
    fn revert_in_place(
        &mut self,
        store: &impl PgStoreOps,
        oid: &Hobject,
        need: Eversion,
        old: Eversion,
    ) -> bool {
        let Some(local) = store.recovery_info(self.spg, oid) else {
            return false;
        };
        if local.version != old {
            return false;
        }
        self.txn.push(StoreOp::ApplyTxn {
            middle: bytes::Bytes::new(),
            data: self.revert_stamp_txn(oid, local.oi, need),
        });
        self.missing.got(oid, need);
        self.mark_applying(oid);
        true
    }

    /// Transaction that rewrites the object_info of `oid` so it carries version `v` (prior = the version it had).
    fn revert_stamp_txn(
        &self,
        oid: &Hobject,
        mut oi: replwire::ObjectInfo,
        v: Eversion,
    ) -> bytes::Bytes {
        oi.prior_version = oi.version;
        oi.version = v;
        let b = denc::to_vec(&oi).expect("encode object_info");
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(self.spg));
        let ox = t.obj(&Ghobject::head(oid.clone(), self.spg.shard));
        t.push(
            cx,
            TxnOp::SetAttr {
                oid: ox,
                name: b"_",
                value: &b,
            },
        );
        t.encode_v9().expect("encode revert txn").into()
    }

    /// `prio`: the recovery message priority for a new pull, the pull response's priority for its continuation
    /// (classic echoes it, spec replication.md 6.1).
    fn send_pull(
        &mut self,
        src: PgShard,
        ri: ObjectRecoveryInfo,
        prog: ObjectRecoveryProgress,
        prio: u16,
    ) {
        let m = MOSDPGPull {
            pgid: SpgT {
                pgid: self.spg.pgid,
                shard: src.shard,
            },
            map_epoch: self.map.epoch(),
            pulls: vec![PullOp {
                soid: ri.soid.clone(),
                recovery_info: ri,
                recovery_progress: prog,
            }],
            cost: REC_MSG_COST,
            from: self.me,
            min_epoch: self.last_peering_reset,
        };
        self.send_prio(src.osd, Body::Repl(m.into()), 0, prio);
    }

    /// Send the pushes of `batch` to `to` as one `MOSDPGPush` (nothing when empty).
    pub(crate) fn flush_push_batch(&mut self, to: PgShard, batch: &mut PushBatch) {
        let pushes = batch.take();
        if !pushes.is_empty() {
            let m = self.push_msg(to, pushes);
            self.send_repl(to.osd, m, 0);
        }
    }

    fn push_msg(&self, to: PgShard, pushes: Vec<PushOp>) -> MOSDPGPush {
        let cost = pushes.iter().map(|op| op.cost(REC_MSG_COST)).sum();
        MOSDPGPush {
            pgid: SpgT {
                pgid: self.spg.pgid,
                shard: to.shard,
            },
            map_epoch: self.map.epoch(),
            pushes,
            cost,
            from: self.me,
            min_epoch: self.last_peering_reset,
            is_repair: false,
        }
    }

    /// The next chunk of a push, with the acknowledging reply's priority (classic echoes it, spec replication.md 6.1).
    fn send_push(&mut self, to: PgShard, op: PushOp, prio: u16) {
        let m = self.push_msg(to, vec![op]);
        self.send_prio(to.osd, Body::Repl(m.into()), 0, prio);
    }

    /// One `MOSDPGRecoveryDelete` for `objects` (spec replication.md 6.5: at most `osd_max_push_objects` per message).
    pub(crate) fn flush_recovery_deletes(
        &mut self,
        to: PgShard,
        objects: &mut Vec<(Hobject, Eversion)>,
    ) {
        let objects = std::mem::take(objects);
        if objects.is_empty() {
            return;
        }
        let m = MOSDPGRecoveryDelete {
            from: self.me,
            pgid: SpgT {
                pgid: self.spg.pgid,
                shard: to.shard,
            },
            map_epoch: self.map.epoch(),
            min_epoch: self.last_peering_reset,
            cost: REC_MSG_COST * objects.len() as u64,
            objects,
        };
        self.send_repl(to.osd, m, 0);
    }

    /// Primary: a replica acked a push chunk.
    pub(crate) fn on_push_reply(
        &mut self,
        from: i32,
        prio: u16,
        m: MOSDPGPushReply,
        store: &impl PgStoreOps,
    ) {
        if self.pool.is_erasure {
            return self.ec_on_push_reply(from, m, store);
        }
        if !matches!(
            self.st,
            St::Primary(PSt::Active(ASt::Recovering | ASt::Backfilling))
        ) {
            self.discard("push reply outside Recovering/Backfilling");
            return;
        }
        let p = self.pshard(from);
        for r in m.replies {
            let key = (r.soid.clone(), from);
            let Some(pi) = self.rec.pushes.get(&key).cloned() else {
                self.discard("push reply for unknown push");
                continue;
            };
            if pi.progress.is_complete() {
                self.rec.pushes.remove(&key);
                // the object counts once, with the transfer of its last finishing target (classic on_global_recover)
                if !self
                    .rec
                    .pushes
                    .range((r.soid.clone(), i32::MIN)..)
                    .next()
                    .is_some_and(|((o, _), _)| *o == r.soid)
                {
                    self.object_recovered(pi.stat);
                }
                self.backfill_push_done(p, &r.soid);
                let v = pi.info.version;
                if let Some(pm) = self.prim.peer_missing.get_mut(&p) {
                    pm.got(&r.soid, v);
                    let empty = pm.is_empty();
                    if let Some(i) = self.prim.peer_info.get_mut(&p)
                        && empty
                    {
                        i.last_complete = i.last_update;
                    }
                }
            } else {
                match store.build_push(
                    self.spg,
                    &pi.info,
                    &pi.progress,
                    self.cfg.recovery_max_chunk,
                    self.cfg.recovery_max_omap_entries,
                ) {
                    Ok(op) => {
                        self.rec.pushes.insert(
                            key,
                            PushInfo {
                                info: pi.info,
                                progress: op.after_progress.clone(),
                                stat: pi.stat.plus(&op),
                            },
                        );
                        self.send_push(p, op, prio);
                    }
                    Err(e) => {
                        self.rec.pushes.remove(&key);
                        if self.bf.targets.contains_key(&p) {
                            // A failed chunk is still in the batch's pushing set. Cancel the whole batch without
                            // advancing its cursor, like an initial push failure; releasing only this marker would
                            // falsely complete the batch, while retaining it would block writes forever.
                            self.backfill_stall(
                                p,
                                "backfill: build_push continuation failed (local object unreadable or corrupt)",
                            );
                            return;
                        }
                        self.error("build_push (continue) failed");
                        // Only an unreadable copy is damage: a newer version (a write to an async-recovery target's
                        // object between chunks) or a queued removal is not, the next recovery pass pushes again.
                        if matches!(e, StoreReadError::Corrupt | StoreReadError::Io) {
                            self.local_damage(&r.soid, Some(pi.info.version));
                        }
                    }
                }
            }
        }
    }

    /// One object recovered on every target (classic `object_recovered` from `on_global_recover`, spec
    /// pg-io-stats.md 2): the recovery counters of the PG's stats; repaired too while the PG repairs.
    pub(crate) fn object_recovered(&mut self, s: RecStat) {
        let repair = self.state & pgs::REPAIR != 0;
        let sum = &mut self.info.stats.stats.sum;
        sum.num_objects_recovered += 1;
        sum.num_bytes_recovered += s.bytes as i64;
        sum.num_keys_recovered += s.keys as i64;
        if repair {
            sum.num_objects_repaired += 1;
        }
    }

    pub(crate) fn on_recovery_delete_reply(
        &mut self,
        from: i32,
        shard: denc::types::ShardId,
        objects: Vec<(Hobject, Eversion)>,
    ) {
        // the reply names the replier's shard: one OSD may hold two EC positions (adr 0049 am. 3)
        let p = if self.pool.is_erasure {
            PgShard { osd: from, shard }
        } else {
            ps(from)
        };
        for (o, v) in objects {
            let ours = self.rec.deletes.remove(&(o.clone(), p));
            if let Some(pm) = self.prim.peer_missing.get_mut(&p) {
                pm.got(&o, v);
            }
            // a recovered delete counts as one object, no bytes (spec pg-io-stats.md 2)
            let first = (
                o.clone(),
                PgShard {
                    osd: i32::MIN,
                    shard: denc::types::ShardId(i8::MIN),
                },
            );
            if ours
                && !self
                    .rec
                    .deletes
                    .range(first..)
                    .next()
                    .is_some_and(|(x, _)| *x == o)
            {
                self.object_recovered(RecStat::default());
            }
        }
    }

    /// EC L0 push verification (ec.md 4.6, 7.7): the first chunk carries `hinfo_key`; when it holds the cumulative
    /// hashes, the pushed shard bytes (contiguous from offset 0) must reproduce `hashes[our shard]` and
    /// `total_chunk_size` at the last chunk. No hashes (L1 after overwrites, mode O, no hinfo): nothing to verify.
    fn ec_push_verify(&mut self, op: &PushOp) -> Result<(), String> {
        let first = op.before_progress.first;
        let complete = op.after_progress.data_complete && op.after_progress.omap_complete;
        if first {
            self.push_verify.remove(&op.soid);
            if let Some(b) = op.attrset.get(ec::HINFO_KEY.as_bytes())
                && let Ok(h) = ec::HashInfo::decode(b)
                && let Some(&expect) = h.hashes.get(self.spg.shard.0 as usize)
            {
                self.push_verify.insert(
                    op.soid.clone(),
                    PushVerify {
                        expect,
                        total: h.total_chunk_size,
                        crc: u32::MAX,
                        next: 0,
                    },
                );
            }
        }
        let Some(v) = self.push_verify.get_mut(&op.soid) else {
            return Ok(());
        };
        let mut pos = 0usize;
        let mut contiguous = true;
        for (s, l) in &op.data_included {
            let end = (pos + *l as usize).min(op.data.len());
            if *s != v.next {
                contiguous = false;
                break;
            }
            v.crc = crc::crc32c(v.crc, &op.data[pos..end]);
            v.next += (end - pos) as u64;
            pos = end;
        }
        if !contiguous {
            // sparse or reordered push: the cumulative hash cannot be checked incrementally
            self.push_verify.remove(&op.soid);
            return Ok(());
        }
        if !complete {
            return Ok(());
        }
        let v = self.push_verify.remove(&op.soid).expect("present");
        if v.next != v.total {
            return Err(format!(
                "pushed {} shard bytes, hinfo total_chunk_size {}",
                v.next, v.total
            ));
        }
        if v.crc != v.expect {
            return Err(format!(
                "shard crc32c {:#010x} != hinfo hash {:#010x}",
                v.crc, v.expect
            ));
        }
        Ok(())
    }

    // ---- push apply (replica / pulling primary) ------------------------------------------------------------

    /// EC shard push chunk (ec.md 7.3): `data_included` is in SHARD offsets and the shard file is already a stripe
    /// multiple, so unlike the replicated push there is no truncate, zero fill, clone subset or omap. The first chunk
    /// of a multi-chunk object goes to a temp object that replaces the live one on the last chunk.
    pub(crate) fn push_txn_ec(&mut self, op: &PushOp) -> Result<Vec<u8>, String> {
        self.ec_push_verify(op)?;
        let first = op.before_progress.first;
        let complete = op.after_progress.data_complete && op.after_progress.omap_complete;
        let oneshot = first && complete;
        let final_o = op.soid.clone();
        let temp_o = temp_of(&final_o);
        let target = if oneshot {
            final_o.clone()
        } else {
            temp_o.clone()
        };
        let shard = self.spg.shard;
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(self.spg));
        let tgt = t.obj(&Ghobject::head(target.clone(), shard));
        if first {
            t.push(cx, TxnOp::Remove { oid: tgt });
            t.push(cx, TxnOp::Touch { oid: tgt });
            if !oneshot {
                self.temps.insert(temp_o.clone());
            }
        }
        let mut pos = 0usize;
        for (s, l) in &op.data_included {
            let end = pos + *l as usize;
            t.push(
                cx,
                TxnOp::Write {
                    oid: tgt,
                    off: *s,
                    data: replwire::Data::new(&op.data[pos..end.min(op.data.len())]),
                },
            );
            pos = end;
        }
        if first && !op.attrset.is_empty() {
            t.push(
                cx,
                TxnOp::SetAttrs {
                    oid: tgt,
                    attrs: op
                        .attrset
                        .iter()
                        .map(|(k, v)| (k.as_slice(), v.as_slice()))
                        .collect(),
                },
            );
        }
        if self.ec_ctx().is_some_and(|c| c.opt && !c.np) {
            // mode O, primary-capable shard: omap header + entries travel with the push (spec 10, 12.5)
            if first {
                t.push(cx, TxnOp::OmapClear { oid: tgt });
                t.push(
                    cx,
                    TxnOp::OmapSetHeader {
                        oid: tgt,
                        header: &op.omap_header,
                    },
                );
            }
            if !op.omap_entries.is_empty() {
                t.push(
                    cx,
                    TxnOp::OmapSetKeys {
                        oid: tgt,
                        pairs: op
                            .omap_entries
                            .iter()
                            .map(|(k, v)| (k.as_slice(), v.as_slice()))
                            .collect(),
                    },
                );
            }
        }
        if complete && let Some(c) = self.ec_ctx().filter(|c| c.opt) {
            // mode O (spec 10): a sparse push leaves the file short; it ends at the O shard size of the object
            t.push(
                cx,
                TxnOp::Truncate {
                    oid: tgt,
                    size: c.shard_size(op.recovery_info.size),
                },
            );
        }
        if self.cfg.ec_trace {
            let s = format!(
                "push {} v {} first {first} complete {complete} size {} data {:?}",
                crate::ecprim::tname(&final_o),
                op.version,
                op.recovery_info.size,
                op.data_included
            );
            self.ec_trace(|| s);
        }
        if complete && !oneshot {
            let fin = t.obj(&Ghobject::head(final_o.clone(), shard));
            t.push(cx, TxnOp::Remove { oid: fin });
            t.push(
                cx,
                TxnOp::CollMoveRename {
                    oid: tgt,
                    dest_cid: cx,
                    dest_oid: fin,
                },
            );
            self.temps.remove(&temp_o);
        }
        Ok(t.encode_v9().expect("encode push txn"))
    }

    /// Translate one push chunk into transaction ops (spec replication.md 6.4).
    ///
    /// `None` = the chunk cannot be applied: a partial push (kept ranges come from the local copy) found the local
    /// copy unreadable or damaged. Applying it would leave the unpushed ranges zeroed (silent data loss), so nothing
    /// is applied or acknowledged; our missing item turns fully dirty so the next peering asks for a FULL push.
    fn push_txn(&mut self, op: &PushOp, store: &impl PgStoreOps) -> Option<Vec<u8>> {
        if self.ec_ctx().is_some() {
            return match self.push_txn_ec(op) {
                Ok(b) => Some(b),
                Err(why) => {
                    // a wrong shard (e.g. decoded by a faulty classic OSD, tracker 74943) is never stored: no ack,
                    // the object stays missing and the next peering asks for a fresh push from the then-current sources
                    self.error("ec push: shard data fails its hinfo hash, refused");
                    self.notes.push(format!(
                        "pg {}: WARNING EC push of {} refused: {why}",
                        self.spg,
                        String::from_utf8_lossy(&op.soid.oid)
                    ));
                    None
                }
            };
        }
        let ri = &op.recovery_info;
        let before = &op.before_progress;
        let after = &op.after_progress;
        let first = before.first;
        let complete = after.data_complete && after.omap_complete;
        let local = if first && !complete && ri.object_exist {
            match store.recovery_info_checked(self.spg, &op.soid) {
                Ok(l) => Some(l),
                Err(StoreReadError::NoObject | StoreReadError::VersionMismatch) => None,
                Err(_) => {
                    self.error("push: local copy unreadable for a partial push, refused");
                    self.notes.push(format!(
                        "pg {}: partial push of {} refused: local copy unreadable or corrupt (full push needed)",
                        self.spg,
                        String::from_utf8_lossy(&op.soid.oid)
                    ));
                    let need = self.missing.get(&op.soid).map_or(op.version, |i| i.need);
                    self.missing.revise_need(op.soid.clone(), need, false);
                    self.info_dirty = true;
                    return None;
                }
            }
        } else {
            None
        };
        let clear_omap = !before.omap_complete;
        let final_o = op.soid.clone();
        let temp_o = temp_of(&final_o);
        let use_temp = !(first && complete);
        let target = if use_temp {
            temp_o.clone()
        } else {
            final_o.clone()
        };
        let shard = self.spg.shard;
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(self.spg));
        let tgt = t.obj(&Ghobject::head(target.clone(), shard));
        if first {
            if !complete {
                t.push(cx, TxnOp::Remove { oid: tgt });
                t.push(cx, TxnOp::Touch { oid: tgt });
                self.temps.insert(temp_o.clone());
            } else {
                if !ri.object_exist {
                    t.push(cx, TxnOp::Remove { oid: tgt });
                    t.push(cx, TxnOp::Touch { oid: tgt });
                }
                t.push(cx, TxnOp::RmAttrs { oid: tgt });
                if clear_omap {
                    t.push(cx, TxnOp::OmapClear { oid: tgt });
                }
            }
            t.push(
                cx,
                TxnOp::Truncate {
                    oid: tgt,
                    size: ri.size,
                },
            );
            if !op.omap_header.is_empty() {
                t.push(
                    cx,
                    TxnOp::OmapSetHeader {
                        oid: tgt,
                        header: &op.omap_header,
                    },
                );
            }
            if !complete
                && ri.object_exist
                && let Some(local) = &local
            {
                let lim = ri.size.min(local.size);
                let keep = subtract_set(&BTreeMap::from([(0u64, lim)]), &ri.copy_subset);
                let src = t.obj(&Ghobject::head(final_o.clone(), shard));
                for (s, l) in keep {
                    t.push(
                        cx,
                        TxnOp::CloneRange2 {
                            oid: src,
                            dest_oid: tgt,
                            src_off: s,
                            len: l,
                            dest_off: s,
                        },
                    );
                }
            }
        }
        // sparse zero ranges, then data
        let z = BTreeMap::from([(
            before.data_recovered_to,
            after
                .data_recovered_to
                .saturating_sub(before.data_recovered_to),
        )]);
        let zr = subtract_set(&intersect_set(&z, &ri.copy_subset), &op.data_included);
        for (s, l) in zr {
            t.push(
                cx,
                TxnOp::Zero {
                    oid: tgt,
                    off: s,
                    len: l,
                },
            );
        }
        let mut pos = 0usize;
        for (s, l) in &op.data_included {
            let end = pos + *l as usize;
            t.push(
                cx,
                TxnOp::Write {
                    oid: tgt,
                    off: *s,
                    data: replwire::Data::new(&op.data[pos..end.min(op.data.len())]),
                },
            );
            pos = end;
        }
        if !op.omap_entries.is_empty() {
            t.push(
                cx,
                TxnOp::OmapSetKeys {
                    oid: tgt,
                    pairs: op
                        .omap_entries
                        .iter()
                        .map(|(k, v)| (k.as_slice(), v.as_slice()))
                        .collect(),
                },
            );
        }
        if !op.attrset.is_empty() {
            t.push(
                cx,
                TxnOp::SetAttrs {
                    oid: tgt,
                    attrs: op
                        .attrset
                        .iter()
                        .map(|(k, v)| (k.as_slice(), v.as_slice()))
                        .collect(),
                },
            );
        }
        if complete {
            if use_temp {
                let fin = t.obj(&Ghobject::head(final_o.clone(), shard));
                t.push(cx, TxnOp::Remove { oid: fin });
                t.push(
                    cx,
                    TxnOp::CollMoveRename {
                        oid: tgt,
                        dest_cid: cx,
                        dest_oid: fin,
                    },
                );
                self.temps.remove(&temp_o);
            }
            for (src, ranges) in &ri.clone_subset {
                let so = t.obj(&Ghobject::head(src.clone(), shard));
                let fin = t.obj(&Ghobject::head(final_o.clone(), shard));
                for (s, l) in ranges {
                    t.push(
                        cx,
                        TxnOp::CloneRange2 {
                            oid: so,
                            dest_oid: fin,
                            src_off: *s,
                            len: *l,
                            dest_off: *s,
                        },
                    );
                }
            }
        }
        Some(t.encode_v9().expect("encode push txn"))
    }

    /// Replica (push target) or primary (pull response).
    /// `prio`: the push's header priority; the reply and a pull continuation echo it (spec replication.md 6.1).
    pub(crate) fn on_push(
        &mut self,
        from: i32,
        tid: u64,
        prio: u16,
        m: MOSDPGPush,
        store: &impl PgStoreOps,
    ) {
        let is_pull_resp = matches!(self.st, St::Primary(PSt::Active(_)));
        if !is_pull_resp && self.st != St::ReplicaActive {
            self.discard("push in wrong state");
            return;
        }
        if !is_pull_resp && from != self.acting_primary {
            self.discard("push from non-primary");
            return;
        }
        if self.local_full.failsafe {
            // Classic aborts here. There is no negative PushReply: consuming a log-recovery push without applying
            // or acknowledging it strands the sender's in-flight op, even after local space returns. Fail-stop so
            // the monitor's down/up interval makes recovery start again; never apply into NoSpace or falsely ack.
            self.fatal("push refused: local fill above failsafe");
            return;
        }
        let mut replies = Vec::new();
        let mut any_recovered = false;
        let mut refused = false;
        let mut cont_pulls: Vec<(PgShard, ObjectRecoveryInfo, ObjectRecoveryProgress)> = Vec::new();
        for op in &m.pushes {
            if op.version == Eversion::default() {
                // blank = the source does not have it
                if is_pull_resp {
                    if !self.rec.pulls.get(&op.soid).is_some_and(|p| p.from == from) {
                        self.discard("blank push for unknown pull source");
                        continue;
                    }
                    self.rec.pulls.remove(&op.soid);
                    self.rec.failed_sources.insert((from, op.soid.clone()));
                }
                continue;
            }
            if !op.data_consistent() {
                self.fatal("push: data/data_included mismatch");
                return;
            }
            let mut pulled = RecStat::default();
            if is_pull_resp {
                match self.rec.pulls.get_mut(&op.soid) {
                    // a reply continues exactly the pull in flight: same version, and its `before_progress` is the progress we
                    // asked with (a stale first chunk of the same version carries the same bytes at the same place)
                    Some(p) if p.from == from && p.progress == op.before_progress => {
                        p.stat = p.stat.plus(op);
                        pulled = p.stat;
                    }
                    Some(p) if p.from == from => {
                        // a late chunk of a pull that `cancel_inflight` dropped (deferred / preempted recovery) must not
                        // join a new pull of the same object: two streams would interleave in one temp object and its
                        // rename would install the mix as recovered
                        self.discard("pull reply out of sequence (stale chunk)");
                        continue;
                    }
                    _ => {
                        self.discard("push for unknown pull");
                        continue;
                    }
                }
            }
            let Some(bytes) = self.push_txn(op, store) else {
                refused = true;
                continue;
            };
            self.txn.push(StoreOp::ApplyTxn {
                middle: bytes::Bytes::new(),
                data: bytes.into(),
            });
            let complete = op.after_progress.data_complete && op.after_progress.omap_complete;
            if complete && crate::snaps::is_clone(&op.soid) {
                // the clone now exists at the pushed version: mapper from the head SnapSet the sender attached
                self.txn.push(StoreOp::SnapMap(crate::snaps::push_ops(
                    &op.soid,
                    &op.recovery_info.ss,
                )));
            }
            if complete {
                let mut got_v = op.recovery_info.version.max(op.version);
                if is_pull_resp
                    && let Some(need) = self.missing.get(&op.soid).map(|i| i.need)
                    && self.revert_of(&op.soid, need) == Some(op.recovery_info.version)
                {
                    // the old version a LOST_REVERT wanted arrived: it becomes the object at the revert entry's version
                    let b = self.revert_stamp_txn(&op.soid, op.recovery_info.oi.clone(), need);
                    self.txn.push(StoreOp::ApplyTxn {
                        middle: bytes::Bytes::new(),
                        data: b,
                    });
                    got_v = need;
                }
                self.missing.got(&op.soid, got_v);
                self.mark_applying(&op.soid);
                self.damage_repaired(&op.soid);
                if self.ec_ctx().is_some() {
                    // `recover_got`: a recovered object has no rollback info; entries up to its version roll forward
                    let to = got_v.min(self.log.head());
                    if to > self.log.log.can_rollback_to {
                        self.ec_roll_forward_to(to);
                    }
                }
                self.rec.had_missing = true;
                any_recovered = true;
                if is_pull_resp {
                    self.rec.pulls.remove(&op.soid);
                    // recovered here; peers still missing it count it with their pushes (spec pg-io-stats.md 2)
                    if !self
                        .prim
                        .peer_missing
                        .values()
                        .any(|m| m.get(&op.soid).is_some())
                    {
                        self.object_recovered(pulled);
                    }
                }
            } else if is_pull_resp {
                let mut ri = op.recovery_info.clone();
                ri.object_exist = false;
                if let Some(p) = self.rec.pulls.get_mut(&op.soid) {
                    p.info = ri.clone();
                    p.progress = op.after_progress.clone();
                }
                cont_pulls.push((self.pshard(from), ri, op.after_progress.clone()));
            }
            replies.push(PushReplyOp {
                soid: op.soid.clone(),
            });
        }
        recompute_last_complete(&self.log, &mut self.info, &self.missing);
        self.info_dirty = true;
        for (src, ri, prog) in cont_pulls {
            self.send_pull(src, ri, prog, prio);
        }
        if is_pull_resp {
            // a pulling primary needs no reply
            self.flush(Pending::Plain);
            return;
        }
        if refused && replies.is_empty() {
            // nothing was applied: no acknowledgement (the primary keeps the push in flight until the next peering)
            self.flush(Pending::Plain);
            return;
        }
        let reply = MOSDPGPushReply {
            pgid: SpgT {
                pgid: self.spg.pgid,
                shard: m.from.shard,
            },
            map_epoch: self.map.epoch(),
            replies,
            cost: m.cost,
            from: self.me,
            min_epoch: m.min_epoch,
        };
        let interval = self.last_peering_reset;
        self.flush(Pending::PushReply {
            interval,
            to: from,
            tid,
            prio,
            reply,
            recovered: any_recovered.then_some(self.info.last_complete),
        });
    }

    /// After a push commit: once nothing is missing tell the primary our durable last_complete
    /// (MOSDPGTrim, peering.md 4.2).
    pub(crate) fn maybe_report_recovered(&mut self, last_complete: Eversion) {
        if self.st == St::ReplicaActive
            && self.missing.is_empty()
            && self.rec.had_missing
            && !self.rec.reported
        {
            self.rec.reported = true;
            let to = self.acting_primary;
            if to >= 0 {
                self.send_peering(
                    to,
                    PeeringMsg::MOSDPGTrim(MOSDPGTrim {
                        epoch: self.map.epoch(),
                        pgid: self.spg.pgid,
                        trim_to: last_complete,
                        shard: self.primary_shard(),
                    }),
                );
            }
        }
    }

    // ---- pull serving -------------------------------------------------------------------------------------------

    /// `prio`: the pull's header priority; the answering push echoes it (spec replication.md 6.1).
    pub(crate) fn on_pull(
        &mut self,
        from: i32,
        tid: u64,
        prio: u16,
        m: MOSDPGPull,
        store: &impl PgStoreOps,
    ) {
        if matches!(self.st, St::Reset | St::ToDelete) {
            self.discard("pull in wrong state");
            return;
        }
        if self.pool.is_erasure {
            // EC recovery never pulls (the primary reads k shards itself)
            self.discard("pull in an erasure pool");
            return;
        }
        let mut pushes = Vec::new();
        for pull in &m.pulls {
            let mut ri = pull.recovery_info.clone();
            let blank = || PushOp {
                soid: pull.soid.clone(),
                ..Default::default()
            };
            let local = match store.recovery_info_checked(self.spg, &pull.soid) {
                Ok(l) => l,
                Err(e) => {
                    // our copy is damaged: say "not here" to the puller and remember it as missing (adr 0065)
                    if !matches!(
                        e,
                        StoreReadError::NoObject | StoreReadError::VersionMismatch
                    ) {
                        self.replica_damage(&pull.soid);
                    }
                    pushes.push(blank());
                    continue;
                }
            };
            // the puller does not know the version (damaged object older than its log): serve ours
            if ri.version == Eversion::default() && self.missing.get(&pull.soid).is_none() {
                ri.version = local.version;
            }
            // missing here: only the old version a LOST_REVERT primary asks for (the version we hold) can be served
            if self.missing.get(&pull.soid).is_some_and(|i| {
                i.have == Eversion::default()
                    || i.have != pull.recovery_info.version
                    || local.version != i.have
            }) {
                pushes.push(blank());
                continue;
            }
            if pull.recovery_progress.first && ri.size == u64::MAX {
                ri.size = local.size;
                ri.copy_subset = intersect_range(&ri.copy_subset, 0, local.size);
                ri.oi = local.oi.clone();
                ri.ss = local.ss.clone();
            }
            match store.build_push(
                self.spg,
                &ri,
                &pull.recovery_progress,
                self.cfg.recovery_max_chunk,
                self.cfg.recovery_max_omap_entries,
            ) {
                Ok(op) => pushes.push(op),
                Err(e) => {
                    // a data / omap read of our copy failed: damaged like an unreadable object_info
                    if matches!(e, StoreReadError::Corrupt | StoreReadError::Io) {
                        self.replica_damage(&pull.soid);
                    }
                    pushes.push(blank())
                }
            }
        }
        let cost = pushes.iter().map(|p| p.cost(REC_MSG_COST)).sum();
        let reply = MOSDPGPush {
            pgid: SpgT {
                pgid: self.spg.pgid,
                shard: m.from.shard,
            },
            map_epoch: self.map.epoch(),
            pushes,
            cost,
            from: self.me,
            min_epoch: m.min_epoch,
            is_repair: false,
        };
        self.send_prio(from, Body::Repl(reply.into()), tid, prio);
    }

    // ---- recovery delete (replica) ----------------------------------------------------------------------------------

    /// MOSDPGRecoveryDelete (replication.md 6.5). The dispatch already dropped one older than this interval
    /// (`stale_floor` = its `map_epoch`); here only the acting primary may delete, and only an object this replica
    /// misses that the delete recovers (`got` accepts): any other object keeps its local copy and is not echoed.
    pub(crate) fn on_recovery_delete(
        &mut self,
        from: i32,
        tid: u64,
        prio: u16,
        mut objects: Vec<(Hobject, Eversion)>,
        min_epoch: u32,
    ) {
        if self.st != St::ReplicaActive {
            self.discard("recovery delete in wrong state");
            return;
        }
        if from != self.acting_primary {
            self.error("recovery delete from non-primary");
            return;
        }
        let n = objects.len();
        objects.retain(|(o, v)| self.missing.got(o, *v));
        if objects.len() != n {
            self.error("recovery delete of an object not missing at that version");
        }
        if objects.is_empty() {
            return;
        }
        self.txn.extend(
            objects
                .iter()
                .map(|(o, _)| StoreOp::RemoveObject(o.clone())),
        );
        recompute_last_complete(&self.log, &mut self.info, &self.missing);
        self.info_dirty = true;
        let reply = MOSDPGRecoveryDeleteReply {
            pgid: self.primary_spg(),
            map_epoch: self.map.epoch(),
            min_epoch,
            objects,
            from: self.me,
        };
        let interval = self.last_peering_reset;
        self.flush(Pending::DeleteReply {
            interval,
            to: from,
            tid,
            prio,
            reply,
        });
    }

    // ---- backfill: replica side (spec 7.2) -------------------------------------------------------------------------------

    pub(crate) fn on_scan(&mut self, from: i32, m: MOSDPGScan, store: &impl PgStoreOps) {
        if let St::Primary(sub) = self.st {
            if m.op == MOSDPGScan::OP_DIGEST {
                // by pg_shard: one OSD may hold two targets (adr 0049 am. 3)
                if m.from.osd != from
                    || !(self.bf.scan_wait.contains_key(&m.from)
                        || self.bf.targets.contains_key(&m.from))
                {
                    self.discard("digest from another shard");
                    return;
                }
                if matches!(sub, PSt::Active(_)) && self.digest_rejected(&m) {
                    // the deadline of the scan keeps running: the target is stalled and retried there
                    self.discard("unexpected digest");
                    return;
                }
                self.bf_scan_answered(from, Some(m.from.shard));
                if matches!(sub, PSt::Active(_)) {
                    self.backfill_on_digest(from, m, store);
                }
            }
            return;
        }
        if self.st != St::ReplicaActive || m.op != MOSDPGScan::OP_GET_DIGEST {
            self.discard("scan in wrong state");
            return;
        }
        if from != self.acting_primary {
            self.discard("scan from non-primary");
            return;
        }
        if self.local_full.backfillfull_with(0) && self.revoke_backfill_toofull() {
            // classic `do_scan`: BackfillTooFull instead of a digest; the primary stops and retries later
            self.error("backfill revoked: local fill above backfillfull");
            return;
        }
        // Damaged objects are left out of the digest (the primary then re-pushes them, which repairs the copy); a
        // read error means no digest at all: the primary must never compare against a partial list.
        let Ok(l) = store.list_objects(
            self.spg,
            &m.begin,
            self.cfg.backfill_scan_min,
            self.cfg.backfill_scan_max,
        ) else {
            self.error("backfill scan: local list failed, no digest sent");
            return;
        };
        let (list, end) = (l.objs, l.next);
        let reply = MOSDPGScan {
            op: MOSDPGScan::OP_DIGEST,
            map_epoch: self.map.epoch(),
            query_epoch: m.query_epoch,
            pgid: self.primary_spg(),
            begin: m.begin,
            end,
            from: self.me,
            digest: Some(list),
        };
        self.send_repl(from, reply, 0);
    }

    pub(crate) fn on_backfill(&mut self, from: i32, m: MOSDPGBackfill) {
        if let St::Primary(PSt::Active(_)) = self.st {
            if m.op == MOSDPGBackfill::OP_FINISH_ACK {
                self.backfill_on_finish_ack(from);
            }
            return;
        }
        if self.st != St::ReplicaActive {
            self.discard("backfill msg in wrong state");
            return;
        }
        if from != self.acting_primary {
            self.discard("backfill msg from non-primary");
            return;
        }
        match m.op {
            MOSDPGBackfill::OP_PROGRESS | MOSDPGBackfill::OP_FINISH => {
                self.info.last_backfill = m.last_backfill.clone();
                match denc::from_slice::<pgwire::PgStat>(&m.stats) {
                    Ok(st) => {
                        let keep = self.info.stats.stats.sum.num_bytes;
                        self.info.stats = st;
                        if m.op == MOSDPGBackfill::OP_PROGRESS {
                            self.info.stats.stats.sum.num_bytes = keep;
                        }
                    }
                    // the primary retries the progress; zeroed or stale stats would be worse than none
                    Err(_) => self.error("backfill progress: peer stats undecodable"),
                }
                self.info_dirty = true;
                let pending = if m.op == MOSDPGBackfill::OP_FINISH {
                    let ack = MOSDPGBackfill {
                        op: MOSDPGBackfill::OP_FINISH_ACK,
                        map_epoch: self.map.epoch(),
                        query_epoch: m.query_epoch,
                        pgid: self.primary_spg(),
                        last_backfill: m.last_backfill,
                        // default values: no vectors or lengths, the encodes cannot fail
                        compat_stats: denc::to_vec(&pgwire::ObjectStatCollection::default())
                            .expect("encode object stat collection"),
                        stats: denc::to_vec(&pgwire::PgStat::default()).expect("encode pg stats"),
                    };
                    Pending::BackfillFinishAck {
                        interval: self.last_peering_reset,
                        to: from,
                        reply: ack,
                    }
                } else {
                    Pending::Plain
                };
                self.flush(pending);
            }
            _ => self.discard("backfill op"),
        }
    }

    pub(crate) fn on_backfill_remove(&mut self, from: i32, m: MOSDPGBackfillRemove) {
        if self.st != St::ReplicaActive {
            self.discard("backfill remove in wrong state");
            return;
        }
        if from != self.acting_primary {
            self.discard("backfill remove from non-primary");
            return;
        }
        for (o, _) in m.ls {
            self.txn.push(StoreOp::RemoveObject(o));
        }
        self.flush(Pending::Plain);
    }
}

fn intersect_set(a: &IntervalSet, b: &IntervalSet) -> IntervalSet {
    let mut out = IntervalSet::new();
    for (s, l) in a {
        for (x, y) in intersect_range(b, *s, s.saturating_add(*l)) {
            out.insert(x, y);
        }
    }
    out
}

/// `a \ b`.
fn subtract_set(a: &IntervalSet, b: &IntervalSet) -> IntervalSet {
    let mut out = IntervalSet::new();
    for (s, l) in a {
        let (mut cur, end) = (*s, s.saturating_add(*l));
        for (bs, bl) in b.range(..end) {
            let be = bs.saturating_add(*bl);
            if be <= cur {
                continue;
            }
            if *bs > cur {
                out.insert(cur, bs - cur);
            }
            cur = cur.max(be);
            if cur >= end {
                break;
            }
        }
        if cur < end {
            out.insert(cur, end - cur);
        }
    }
    out
}

#[cfg(test)]
mod priority_tests {
    use super::*;
    use crate::pg::{ASt, PSt, St};
    use crate::plog::MissingSet;
    use crate::synth::SynthMap;
    use denc::types::{PgT, ShardId, SnapId};
    use pgwire::PgInfo;
    use replwire::ReplMsg;
    use std::sync::Arc;

    fn pg(size: u32, min_size: u32, acting: &[i32]) -> Pg {
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        };
        let mut map = SynthMap::new(3).with_pool(1, size, min_size, 1);
        for o in 0..4 {
            map = map.with_osd(o, 1);
        }
        let mut pg = Pg::blank(
            Arc::new(Config::new(0)),
            spg,
            map.into_handle(),
            PgInfo::new(spg),
        );
        pg.acting = acting.to_vec();
        pg.up = acting.to_vec();
        pg.acting_primary = acting[0];
        pg.up_primary = acting[0];
        pg.st = St::Primary(PSt::Active(ASt::Recovering));
        pg.state = pgs::ACTIVE | pgs::RECOVERING;
        pg
    }

    fn missing() -> MissingSet {
        let mut m = MissingSet::default();
        m.add(
            Hobject::new(b"o", SnapId::NOSNAP, 1, 1, b""),
            Eversion::new(1, 1),
            Eversion::default(),
            false,
        );
        m
    }

    #[test]
    fn recovery_requests_use_scheduler_classes_instead_of_default_priority() {
        let mut p = pg(3, 2, &[0, 1, 2]);
        for (flags, expected) in [
            (0, 5),
            (pgs::DEGRADED, 10),
            (pgs::DEGRADED | pgs::UNDERSIZED, 15),
            (pgs::FORCED_RECOVERY, 20),
            (pgs::FORCED_BACKFILL, 20),
        ] {
            p.state = pgs::ACTIVE | flags;
            p.send_repl(1, ReplMsg::Pull(MOSDPGPull::default()), 0);
            let Action::Send(s) = p.out.pop().unwrap() else {
                panic!("expected recovery request");
            };
            assert_eq!(s.prio, expected, "flags={flags}");
        }
    }

    #[test]
    fn recovery_message_priority_honors_wpq_pool_and_osd_options() {
        let mut p = pg(3, 2, &[0, 1, 2]);
        Arc::make_mut(&mut p.cfg).recovery_mclock = false;
        Arc::make_mut(&mut p.cfg).recovery_op_priority = 7;
        assert_eq!(p.recovery_message_priority(), 7);
        p.pool.recovery_op_priority = Some(11);
        assert_eq!(p.recovery_message_priority(), 11);
        p.state |= pgs::FORCED_RECOVERY;
        assert_eq!(
            p.recovery_message_priority(),
            11,
            "WPQ keeps configured priority"
        );
        Arc::make_mut(&mut p.cfg).recovery_mclock = true;
        assert_eq!(
            p.recovery_message_priority(),
            20,
            "mclock ignores the pool option"
        );
        for body in [
            ReplMsg::Push(MOSDPGPush::default()),
            ReplMsg::Pull(MOSDPGPull::default()),
            ReplMsg::RecoveryDelete(MOSDPGRecoveryDelete::default()),
            ReplMsg::Scan(MOSDPGScan {
                op: MOSDPGScan::OP_GET_DIGEST,
                ..Default::default()
            }),
            ReplMsg::Backfill(MOSDPGBackfill::default()),
            ReplMsg::BackfillRemove(MOSDPGBackfillRemove::default()),
        ] {
            p.send_repl(1, body, 0);
            let Action::Send(s) = p.out.pop().unwrap() else {
                panic!("expected request")
            };
            assert_eq!(s.prio, 20, "type={}", s.body.msg_type());
        }
        // a replica's digest answers with the default priority, like classic
        p.send_repl(
            1,
            MOSDPGScan {
                op: MOSDPGScan::OP_DIGEST,
                ..Default::default()
            },
            0,
        );
        let Action::Send(s) = p.out.pop().unwrap() else {
            panic!("expected digest")
        };
        assert_eq!(s.prio, pgwire::msgs::PRIO_DEFAULT);
    }

    /// PG-L2: recovery bands, the deficit term and the `avail_no_missing` boost (spec replication.md 11.1).
    #[test]
    fn recovery_priority_follows_the_bands_and_deficit() {
        let mut p = pg(3, 2, &[0, 1, 2]);
        assert_eq!(p.recovery_priority(), 190, "resting band +10");
        p.state |= pgs::DEGRADED;
        p.prim.acting_recovery_backfill = [p.me, ps(1), ps(2)].into_iter().collect();
        assert_eq!(p.recovery_priority(), 190, "full copies satisfy min_size");
        p.prim.peer_missing.insert(ps(1), missing());
        p.prim.peer_missing.insert(ps(2), missing());
        assert_eq!(
            p.recovery_priority(),
            231,
            "one copy left: 220 + (min_size - 1) + 10"
        );
        p.pool.recovery_priority = 5;
        assert_eq!(p.recovery_priority(), 236, "pool option shifts by 5");
        p.state |= pgs::FORCED_RECOVERY;
        assert_eq!(p.recovery_priority(), 255, "forced has no pool term");
    }

    /// PG-L2: backfill bands (inactive, undersized, degraded full, plain) with the option shift and band caps.
    #[test]
    fn backfill_priority_follows_the_bands_and_clamps() {
        let mut p = pg(3, 2, &[0, 1, 2]);
        assert_eq!(p.backfill_priority(), 110, "plain band +10");
        p.state |= pgs::DEGRADED;
        assert_eq!(p.backfill_priority(), 150, "degraded full acting set");
        p.acting = vec![0, 1];
        assert_eq!(p.backfill_priority(), 151, "undersized deficit");
        p.acting = vec![0];
        assert_eq!(p.backfill_priority(), 231, "below min_size deficit");
        p.pool.recovery_priority = 5;
        assert_eq!(p.backfill_priority(), 236);
        p.pool.recovery_priority = 10;
        let mut q = pg(20, 20, &[0, 1]);
        q.pool.recovery_priority = 10;
        assert_eq!(q.backfill_priority(), 253, "band maximum caps the shift");
        p.state |= pgs::FORCED_BACKFILL;
        assert_eq!(p.backfill_priority(), 254, "forced has no pool term");
    }
}

#[cfg(test)]
mod batching_tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use crate::store::{MemObj, MemStore};
    use denc::types::{PgT, ShardId, SnapId};
    use std::sync::Arc;

    /// Replicated size-2 primary of `osd.0` in Recovering, one replica `osd.1`, budget for everything.
    fn recovery_pg() -> (Pg, PgShard, MemStore) {
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        };
        let peer = PgShard {
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
        pg.acting_primary = 0;
        pg.up_primary = 0;
        pg.prim.acting_recovery_backfill = [pg.me, peer].into_iter().collect();
        pg.prim.peer_info.insert(
            peer,
            pgwire::PgInfo {
                last_backfill: Hobject::MAX(),
                last_update: Eversion::new(1, 1),
                ..pgwire::PgInfo::new(spg)
            },
        );
        pg.st = St::Primary(PSt::Active(ASt::Recovering));
        pg.state = pgs::ACTIVE | pgs::RECOVERING;
        pg.rec.cap = 64;
        let mut store = MemStore::new();
        store.submit(
            spg,
            &crate::StoreTxn {
                ops: vec![crate::StoreOp::CreatePg],
            },
        );
        (pg, peer, store)
    }

    fn obj(name: &str) -> Hobject {
        Hobject::new(name.as_bytes(), SnapId::NOSNAP, 0, 1, b"")
    }

    fn put_object(store: &mut MemStore, spg: SpgT, oid: &Hobject) {
        let mut oi = replwire::ObjectInfo::new(oid.clone());
        oi.version = Eversion::new(1, 1);
        oi.size = 32;
        store.pgs.get_mut(&spg).unwrap().objects.insert(
            oid.clone(),
            MemObj {
                data: vec![0x5a; 32],
                xattrs: BTreeMap::from([(b"_".to_vec(), denc::to_vec(&oi).unwrap())]),
                ..Default::default()
            },
        );
    }

    fn repl_sends(pg: &mut Pg) -> Vec<replwire::ReplMsg> {
        pg.take_actions()
            .into_iter()
            .filter_map(|a| match a {
                Action::Send(s) => match s.body {
                    Body::Repl(m) => Some(m),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    /// One `MOSDPGPush` carries `osd_max_push_objects` objects (spec replication.md 6.3): 25 small objects are 3
    /// messages of 10/10/5 ops, not 25 messages (R4).
    #[test]
    fn recovery_pushes_go_out_in_batches() {
        let (mut pg, peer, mut store) = recovery_pg();
        let pm = pg
            .prim
            .peer_missing
            .entry(peer)
            .or_insert_with(|| crate::plog::MissingSet::new(true));
        for i in 0..25 {
            let oid = obj(&format!("obj{i}"));
            put_object(&mut store, pg.spg, &oid);
            pm.add(oid, Eversion::new(1, 1), Eversion::default(), false);
        }
        pg.recovery_step(&store);
        let sizes: Vec<usize> = repl_sends(&mut pg)
            .into_iter()
            .filter_map(|m| match m {
                replwire::ReplMsg::Push(m) => Some(m.pushes.len()),
                _ => None,
            })
            .collect();
        assert_eq!(sizes, [10, 10, 5], "one message per osd_max_push_objects");
        assert_eq!(pg.rec.pushes.len(), 25);
    }

    /// Same for the recovered deletes (spec replication.md 6.5): 25 delete items are 3 messages.
    #[test]
    fn recovery_deletes_go_out_in_batches() {
        let (mut pg, peer, store) = recovery_pg();
        let pm = pg
            .prim
            .peer_missing
            .entry(peer)
            .or_insert_with(|| crate::plog::MissingSet::new(true));
        for i in 0..25 {
            pm.add(
                obj(&format!("del{i}")),
                Eversion::new(1, 1),
                Eversion::default(),
                true,
            );
        }
        pg.recovery_step(&store);
        let sizes: Vec<usize> = repl_sends(&mut pg)
            .into_iter()
            .filter_map(|m| match m {
                replwire::ReplMsg::RecoveryDelete(m) => Some(m.objects.len()),
                _ => None,
            })
            .collect();
        assert_eq!(sizes, [10, 10, 5]);
        assert_eq!(pg.rec.deletes.len(), 25);
    }

    /// A backfill progress whose stats do not decode is reported and leaves the replica's stats alone (R10).
    #[test]
    fn undecodable_backfill_stats_are_reported_and_not_applied() {
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        };
        let map = SynthMap::new(4)
            .with_pool(1, 2, 1, 1)
            .with_osd(0, 1)
            .with_osd(1, 1)
            .into_handle();
        let mut pg = Pg::blank(Arc::new(Config::new(0)), spg, map, pgwire::PgInfo::new(spg));
        pg.acting_primary = 0;
        pg.st = St::ReplicaActive;
        pg.info.stats.stats.sum.num_objects = 5;
        let last_backfill = obj("b");
        pg.on_backfill(
            0,
            MOSDPGBackfill {
                op: MOSDPGBackfill::OP_PROGRESS,
                map_epoch: pg.map.epoch(),
                query_epoch: pg.last_peering_reset,
                pgid: pg.primary_spg(),
                last_backfill: last_backfill.clone(),
                compat_stats: Vec::new(),
                stats: vec![0xff],
            },
        );
        assert_eq!(
            pg.counters.errors["backfill progress: peer stats undecodable"],
            1
        );
        assert_eq!(pg.info.stats.stats.sum.num_objects, 5, "stale stats kept");
        assert_eq!(
            pg.info.last_backfill, last_backfill,
            "the cursor still moves"
        );
    }
}
