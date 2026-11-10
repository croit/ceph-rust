// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! A damaged local object (read checksum error, undecodable object_info; adr 0042 / 0065) is "missing locally": it
//! goes into our own pg missing set at its authoritative version, is persisted, and the normal recovery machinery
//! pulls it from a healthy peer (replicated pools only). Classic does the same for a primary read that fails with EIO
//! (own words: the object is marked missing on the primary, the op waits for the pull, then runs again).
//!
//! * primary ([`Pg::local_damage`]): called by the op engine on EIO of a head or clone read, and by backfill when its
//!   own copy is corrupt. The op waits (`read_blocked`), never fails with EIO while a repair may still work.
//! * replica ([`Pg::replica_damage`]): a pull we could not serve. The item is persisted in our missing set, the
//!   primary learns it at the next peering (classic-compatible: nothing new on the wire) and pushes the object.
//!
//! Version: the object_info version when the caller has it, else the newest log entry of the object, else
//! [`NEED_ANY`]: the object is older than the log, any version at or above 0'1 satisfies the item and the pull
//! carries version 0'0 (classic serves "requester does not know the version" with its own object_info version).

use crate::pg::*;
use crate::plog::recompute_last_complete;
use denc::types::{Eversion, Hobject, SnapId};
use pgwire::state as pgs;

/// Placeholder `need` of a damaged object that is older than the log window and whose own object_info is unreadable.
pub const NEED_ANY: Eversion = Eversion {
    version: 1,
    epoch: 0,
};

impl Pg {
    /// Objects of this PG repaired from a peer since the PG instance started (`num_shards_repaired`).
    pub fn shards_repaired(&self) -> u64 {
        self.shards_repaired
    }

    /// Damaged local objects waiting for their repair (memory only; the missing set is the durable record).
    pub fn damaged(&self) -> impl Iterator<Item = &Hobject> {
        self.dmg.iter()
    }

    /// Must an op on `head` wait? The head or one of its clones is in our missing set (a snap read of a clone that is
    /// not here yet would answer ENOENT; the missing set is durable, so this holds across restarts too). Clones sort
    /// right before their head.
    pub fn read_blocked(&self, head: &Hobject) -> bool {
        if self.missing.is_empty() {
            return false;
        }
        let mut lo = head.clone();
        lo.snap = SnapId(0);
        self.missing
            .wire()
            .missing
            .range(lo..=head.clone())
            .next()
            .is_some()
    }

    fn damage_need(&self, oid: &Hobject, known: Option<Eversion>) -> Option<Eversion> {
        if let Some(v) = known.filter(|v| *v != Eversion::default()) {
            return Some(v);
        }
        match self.log.entry_for(oid) {
            Some(e) if e.is_delete() => None,
            Some(e) => Some(e.version),
            None => Some(NEED_ANY),
        }
    }

    /// Primary: `oid` (head or clone) failed a local read or its object_info does not decode. `true` = the object is
    /// (now) in our missing set and the caller must park its op until it is recovered; `false` = no repair possible
    /// here (not an active replicated primary, object deleted): fail the op as before.
    pub fn local_damage(&mut self, oid: &Hobject, known: Option<Eversion>) -> bool {
        if self.pool.is_erasure
            || self.refuse.is_some()
            || !matches!(self.st, St::Primary(PSt::Active(_)))
            || *oid > self.info.last_backfill
        {
            return false;
        }
        if self.missing.contains(oid) {
            return true; // recovery is on it (or unfound: the op waits, like classic)
        }
        if self.rec.dmg_repaired.contains(oid) {
            // a fresh copy did not cure it (device fault, a read error that is not damage): no repair loop
            self.error("local object damaged again after its repair: EIO");
            return false;
        }
        let Some(need) = self.damage_need(oid, known) else {
            return false;
        };
        self.missing
            .add(oid.clone(), need, Eversion::default(), false);
        self.dmg.insert(oid.clone());
        self.error("local object damaged: repairing from a peer");
        recompute_last_complete(&self.log, &mut self.info, &self.missing);
        self.info_dirty = true;
        self.flush(Pending::Plain);
        // cluster log like classic (`primary_error`): where it will be taken from, or unfound
        let peers = self.recovery_peers();
        let from: Vec<String> = self
            .holders(&peers, oid, need)
            .iter()
            .map(|p| format!("osd.{}", p.osd))
            .collect();
        let name = String::from_utf8_lossy(&oid.oid);
        self.notes.push(if from.is_empty() {
            format!("ERROR {} missing primary copy of {name}, unfound", self.spg)
        } else {
            format!(
                "ERROR {} missing primary copy of {name}, will try copies on {}",
                self.spg,
                from.join(",")
            )
        });
        self.damage_kick_recovery();
        true
    }

    /// Recovery of a client-visible unreadable / degraded head is (re)started: an object-level backoff of that object
    /// (client-ops 16.6) kicks recovery instead of leaving the client blocked without progress.
    pub fn kick_recovery(&mut self, oid: &Hobject) {
        if self.missing.contains(oid) || self.obj_degraded(oid) {
            self.damage_kick_recovery();
        }
    }

    /// Get recovery going for a missing item added outside peering.
    fn damage_kick_recovery(&mut self) {
        match self.st {
            St::Primary(PSt::Active(ASt::Clean | ASt::Recovered)) => {
                self.state &= !pgs::CLEAN;
                self.state |= pgs::REPAIR;
                self.update_degraded_bits();
                self.start_recovery_reservation();
            }
            // a backfill in flight or held (flag, toofull): stop it, recovery of our own missing objects goes first
            // (classic order), the backfill starts again behind it (`all_recovered`). Recovery has its own flags: a
            // held backfill (nobackfill) must not hold the repair.
            St::Primary(PSt::Active(
                ASt::WaitLocalBackfillReserved
                | ASt::WaitRemoteBackfillReserved
                | ASt::Backfilling
                | ASt::NotBackfilling,
            )) => {
                self.stop_backfill();
                self.state &= !(pgs::BACKFILL_WAIT
                    | pgs::BACKFILLING
                    | pgs::BACKFILL_UNFOUND
                    | pgs::BACKFILL_TOOFULL);
                self.state |= pgs::REPAIR;
                self.rec.retry_at = 0;
                self.update_degraded_bits();
                self.start_recovery_reservation();
            }
            // Recovering / waiting for reservations: recovery_step sees the new item
            _ => {}
        }
    }

    /// Replica: a read of `oid` failed while serving a pull. Remember it as missing (persisted); the primary gets to
    /// know at the next peering and pushes the object. Objects beyond `last_backfill` are the primary's backfill job.
    pub(crate) fn replica_damage(&mut self, oid: &Hobject) {
        if self.st != St::ReplicaActive
            || self.pool.is_erasure
            || *oid > self.info.last_backfill
            || self.missing.contains(oid)
        {
            return;
        }
        let Some(need) = self.damage_need(oid, None) else {
            return;
        };
        self.missing
            .add(oid.clone(), need, Eversion::default(), false);
        self.dmg.insert(oid.clone());
        self.error("local object damaged (replica): marked missing");
        self.notes.push(format!(
            "ERROR {} local copy of {} is damaged (read error): marked missing, the primary repairs it",
            self.spg,
            String::from_utf8_lossy(&oid.oid)
        ));
        recompute_last_complete(&self.log, &mut self.info, &self.missing);
        self.info_dirty = true;
        self.flush(Pending::Plain);
    }

    /// An object came back through recovery: a repaired shard when it was a damaged one.
    pub(crate) fn damage_repaired(&mut self, oid: &Hobject) {
        if self.dmg.remove(oid) {
            self.shards_repaired += 1;
            self.rec.dmg_repaired.insert(oid.clone());
        }
    }

    /// Housekeeping: forget damage marks whose missing item is gone (deleted, reverted, re-peered).
    pub(crate) fn damage_settle(&mut self) {
        if !self.dmg.is_empty() {
            let m = &self.missing;
            self.dmg.retain(|o| m.contains(o));
        }
    }
}
