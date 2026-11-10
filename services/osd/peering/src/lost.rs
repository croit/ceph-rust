// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Unfound objects and `mark_unfound_lost revert|delete` (specs doc/spec/unfound-lost.md, doc/spec/ec-unfound-lost.md):
//! which objects of the needs-recovery set no reachable shard set can supply, who might still hold them, and the
//! LOST_REVERT / LOST_DELETE log entries an operator can write to give them up. The entries are replicated to the
//! recovery set like any log-only update (`MOSDPGUpdateLogMissing`), so classic peers apply them with their own code;
//! the command is answered once every member committed them ([`LostReply::Later`], [`crate::Action::LostMarked`]).

use crate::pg::*;
use crate::plog::MissingSet;
use crate::primary::RepOp;
use crate::store::PgStoreOps;
use crate::types::*;
use denc::types::{Eversion, Hobject, PgShard, SpgT};
use pgwire::state as pgs;
use pgwire::{LogEntry, LogOp, MissingItem, ObjectCleanRegions, ObjectModDesc};
use replwire::MOSDPGUpdateLogMissing;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

const EINVAL: i32 = -22;
const EROFS: i32 = -30;
const EAGAIN: i32 = -11;

/// Operator message or `(errno, message)`.
pub type LostResult = Result<String, (i32, String)>;

/// Answer of [`Pg::mark_unfound_lost`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LostReply {
    /// Answered at once (refused, or nothing unfound).
    Now(LostResult),
    /// The marking was submitted as update `tid`: [`crate::Action::LostMarked`] with this tid carries the answer once
    /// every member committed it, or `-EAGAIN` when the interval ends first.
    Later(u64),
}

/// Deferred answer of a marking ([`crate::Action::LostMarked`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LostDone {
    pub spg: SpgT,
    pub tid: u64,
    pub result: LostResult,
}

/// A marking waiting for its log update: entries not appended yet (EC: ordered behind writes submitted before it), or
/// appended and waiting for the commits of every member.
#[derive(Debug)]
pub(crate) struct LostPending {
    pub tid: u64,
    /// Objects marked (U of the operator message).
    pub count: usize,
    /// EC: entries waiting for the earlier writes to generate (`None` = appended and sent).
    pub queued: Option<Vec<LogEntry>>,
}

/// What `mark_unfound_lost` writes for the unfound objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LostMode {
    /// Back to the newest older version any acting member holds, else delete (replicated pools only).
    Revert,
    Delete,
}

/// One unfound object as `list_unfound` shows it (fields of its needs-recovery item).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnfoundObj {
    pub oid: Hobject,
    pub need: Eversion,
    pub have: Eversion,
    pub clean_regions: ObjectCleanRegions,
    /// Shards holding it at `need` (replicated: none; EC: too few to decode).
    pub locations: Vec<PgShard>,
}

/// `list_unfound` (spec ec-unfound-lost.md 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnfoundList {
    /// Objects missing anywhere in the recovery set (`num_missing`, delete items included).
    pub num_missing: usize,
    pub num_unfound: usize,
    /// At most `max` unfound objects after the offset, ascending.
    pub objects: Vec<UnfoundObj>,
    /// More needs-recovery items follow the last one listed.
    pub more: bool,
    /// Peering state machine name ([`Pg::unfound_state_name`]).
    pub state: &'static str,
    /// `Some` in Active / NotRecovering / NotBackfilling: possible holders whose missing set we lack, with status;
    /// `None` elsewhere (`available_might_have_unfound: false`).
    pub might_have_unfound: Option<Vec<(PgShard, &'static str)>>,
}

impl Pg {
    /// Active primary (not refused): the only state in which objects can be unfound.
    fn unfound_possible(&self) -> bool {
        self.refuse.is_none()
            && matches!(self.st, St::Primary(PSt::Active(_)))
            && self.state & pgs::ACTIVE != 0
    }

    /// Acting peers recovery pulls from / pushes to (no backfill targets: they are filled by backfill).
    pub(crate) fn recovery_peers(&self) -> Vec<PgShard> {
        self.prim
            .acting_recovery_backfill
            .iter()
            .copied()
            .filter(|p| *p != self.me && !self.prim.backfill_targets.contains(p))
            .collect()
    }

    /// `Some(version to fetch)` when the newest log entry of `oid` is the LOST_REVERT that made us need `need`: recovery
    /// then wants the older version (stamped with the revert entry's version once it is here), not `need` itself.
    pub(crate) fn revert_of(&self, oid: &Hobject, need: Eversion) -> Option<Eversion> {
        let e = self.log.entry_for(oid)?;
        (e.op == LogOp::LOST_REVERT && e.version == need).then_some(e.reverting_to)
    }

    /// Up OSDs that can supply `oid` for our missing item (`need`), acting members first. For a revert only acting
    /// members that hold exactly the version to revert to (their missing item's `have`) count.
    pub(crate) fn holders(
        &self,
        acting_peers: &[PgShard],
        oid: &Hobject,
        need: Eversion,
    ) -> Vec<PgShard> {
        let usable = |p: &PgShard| {
            self.map.is_up(p.osd)
                && !self.rec.failed_sources.contains(&(p.osd, oid.clone()))
                && self
                    .prim
                    .peer_info
                    .get(p)
                    .is_some_and(|i| *oid <= i.last_backfill)
        };
        let rv = self.revert_of(oid, need);
        let ok = |p: &PgShard, known_complete: bool| {
            usable(p)
                && rv.is_none_or(|rv| {
                    // a revert: a peer still missing the object helps only if it holds the old version to revert to
                    self.prim
                        .peer_missing
                        .get(p)
                        .and_then(|m| m.get(oid))
                        .is_none_or(|i| i.have == rv)
                })
                && self
                    .prim
                    .peer_info
                    .get(p)
                    .is_some_and(|i| known_complete || i.last_update >= need)
                && (rv.is_some()
                    || self
                        .prim
                        .peer_missing
                        .get(p)
                        .is_none_or(|m| !m.contains(oid)))
        };
        let mut v: Vec<PgShard> = acting_peers
            .iter()
            .filter(|p| ok(p, true))
            .copied()
            .collect();
        if need == crate::damage::NEED_ANY {
            // version unknown (adr 0065): the pull takes whatever the source holds, so only peers known to be current
            // qualify; a stray may hold an older copy (down for a while, divergent) and would roll the object back
            return v;
        }
        v.extend(
            self.prim
                .peer_info
                .keys()
                .filter(|p| **p != self.me && !acting_peers.contains(p))
                .filter(|p| ok(p, false))
                .copied(),
        );
        v
    }

    /// Needs-recovery set N (spec ec-unfound-lost.md 1.1): every object missing on us or on a member of the recovery
    /// set, one item per object (ours wins, else the first member's), delete items included.
    pub(crate) fn needs_recovery_items(&self) -> BTreeMap<Hobject, MissingItem> {
        let mut n: BTreeMap<Hobject, MissingItem> = self
            .missing
            .iter()
            .map(|(o, i)| (o.clone(), i.clone()))
            .collect();
        for p in &self.prim.acting_recovery_backfill {
            if *p == self.me {
                continue;
            }
            if let Some(m) = self.prim.peer_missing.get(p) {
                for (o, i) in m.iter() {
                    n.entry(o.clone()).or_insert_with(|| i.clone());
                }
            }
        }
        n
    }

    /// Shards holding `oid` at `need` (classic missing_loc, spec ec-unfound-lost.md 1.2), sorted. Replicated: the
    /// recovery sources of our missing object (a revert we can do in place counts us), else us and the members that do
    /// not miss it. EC: the members holding a current copy plus the activated strays holding `need`.
    pub(crate) fn locations_of(&self, oid: &Hobject, need: Eversion) -> Vec<PgShard> {
        let mut v: Vec<PgShard> = if self.pool.is_erasure {
            let mut v: Vec<PgShard> = self
                .prim
                .acting_recovery_backfill
                .iter()
                .filter(|p| self.ec_member_has(p, oid))
                .copied()
                .collect();
            v.extend(
                self.prim
                    .stray_src
                    .iter()
                    .filter(|p| self.is_stray_shard(**p) && self.stray_has(**p, oid, need))
                    .copied(),
            );
            v
        } else if let Some(i) = self.missing.get(oid) {
            let mut v = self.holders(&self.recovery_peers(), oid, i.need);
            if self.revert_of(oid, i.need) == Some(i.have) && i.have != Eversion::default() {
                v.push(self.me);
            }
            v
        } else {
            let mut v = vec![self.me];
            v.extend(self.recovery_peers().into_iter().filter(|p| {
                self.prim
                    .peer_missing
                    .get(p)
                    .is_none_or(|m| !m.contains(oid))
            }));
            v
        };
        v.sort();
        v.dedup();
        v
    }

    /// Spec ec-unfound-lost.md 1.4: a non-delete item whose locations cannot supply it (replicated: none; EC: their
    /// shard indices do not decode).
    fn item_unfound(&self, item: &MissingItem, locs: &[PgShard]) -> bool {
        if item.is_delete() {
            return false;
        }
        if self.pool.is_erasure {
            let shards: Vec<u32> = locs
                .iter()
                .filter(|p| p.shard.0 >= 0)
                .map(|p| p.shard.0 as u32)
                .collect();
            !self.ecb().is_some_and(|b| b.recoverable(&shards))
        } else {
            locs.is_empty()
        }
    }

    /// Nothing can be unfound without walking N: replicated with nothing missing on us (an object only peers miss is
    /// here), EC when the members missing nothing already decode every object.
    fn none_unfound(&self) -> bool {
        if !self.unfound_possible() {
            return true;
        }
        if !self.pool.is_erasure {
            return self.missing.is_empty();
        }
        let shards: Vec<u32> = self
            .prim
            .acting_recovery_backfill
            .iter()
            .filter(|p| {
                p.shard.0 >= 0
                    && self.map.is_up(p.osd)
                    && !self.prim.backfill_targets.contains(p)
                    && if **p == self.me {
                        self.missing.is_empty()
                    } else {
                        self.prim.peer_missing.get(p).is_some_and(|m| m.is_empty())
                    }
            })
            .map(|p| p.shard.0 as u32)
            .collect();
        self.ecb().is_some_and(|b| b.recoverable(&shards))
    }

    /// Some object may be unfound (cheap pre-check for [`Self::obj_unfound`]).
    pub(crate) fn may_be_unfound(&self) -> bool {
        !self.none_unfound()
    }

    /// The non-delete needs-recovery item `oid` at `need` is unfound.
    pub(crate) fn obj_unfound(&self, oid: &Hobject, need: Eversion) -> bool {
        let item = MissingItem::new(need, Eversion::default(), false);
        self.item_unfound(&item, &self.locations_of(oid, need))
    }

    /// The head is missing here and no location can supply it (client-ops 16.6): its ops get an object-level backoff
    /// instead of waiting forever. A missing head that a peer holds is degraded, not unfound.
    pub fn obj_unfound_head(&self, oid: &Hobject) -> bool {
        if !self.unfound_possible() {
            return false;
        }
        let Some(item) = self.missing.get(oid).cloned() else {
            return false;
        };
        self.item_unfound(&item, &self.locations_of(oid, item.need))
    }

    /// Unfound objects (active primary), ascending, with their locations. A delete item is never unfound; a revert
    /// whose old version we hold ourselves is not either.
    pub fn unfound(&self) -> Vec<UnfoundObj> {
        if self.none_unfound() {
            return Vec::new();
        }
        self.needs_recovery_items()
            .into_iter()
            .filter_map(|(oid, i)| {
                let locs = self.locations_of(&oid, i.need);
                self.item_unfound(&i, &locs).then_some(UnfoundObj {
                    oid,
                    need: i.need,
                    have: i.have,
                    clean_regions: i.clean_regions,
                    locations: locs,
                })
            })
            .collect()
    }

    /// Everything recovery still has to do is unfound (and there is something): classic UnfoundRecovery may fire.
    pub(crate) fn only_unfound_left(&mut self) -> bool {
        #[cfg(test)]
        {
            self.rec.unfound_walks += 1;
        }
        if self.none_unfound() {
            return false;
        }
        let n = self.needs_recovery_items();
        !n.is_empty()
            && n.iter()
                .all(|(o, i)| self.item_unfound(i, &self.locations_of(o, i.need)))
    }

    /// Where recovery can get our missing object `oid` from (classic `missing_loc` locations; empty = unfound, or not
    /// missing, or not an active primary). Replicated: never us.
    pub fn missing_locations(&self, oid: &Hobject) -> Vec<PgShard> {
        match self.missing.get(oid) {
            Some(i) if self.unfound_possible() && !i.is_delete() => {
                let mut v = self.locations_of(oid, i.need);
                if !self.pool.is_erasure {
                    v.retain(|p| *p != self.me);
                }
                v
            }
            _ => Vec::new(),
        }
    }

    /// Classic rule (spec ec-unfound-lost.md 3 check 5): we hold `p`'s missing set, or its info says it holds nothing.
    /// Holding its info alone does not count.
    fn probed(&self, p: &PgShard) -> bool {
        self.prim.peer_missing.contains_key(p)
            || self
                .prim
                .peer_info
                .get(p)
                .is_some_and(|i| i.is_empty() || i.dne_flag())
    }

    /// The OSD was declared lost (`ceph osd lost`) after it last came up.
    fn is_lost(&self, osd: i32) -> bool {
        self.map.lost_at(osd) > self.map.up_from(osd)
    }

    /// `might_have_unfound` of `pg query` / `list_unfound`: every possible holder whose missing set we lack, with its
    /// status (query outstanding / down / not queried).
    pub fn might_have_unfound(&self) -> Vec<(PgShard, &'static str)> {
        self.prim
            .might_have_unfound
            .iter()
            .filter(|p| !self.prim.peer_missing.contains_key(p))
            .map(|p| {
                let s = if self.prim.peer_missing_requested.contains(p) {
                    "querying"
                } else if !self.map.is_up(p.osd) {
                    "osd is down"
                } else {
                    "not queried"
                };
                (*p, s)
            })
            .collect()
    }

    /// Peering state machine name `list_unfound` reports: the state that answers the query (Active substates other
    /// than NotRecovering / NotBackfilling answer as Active; the peering substates as Peering).
    pub fn unfound_state_name(&self) -> &'static str {
        match self.st {
            St::Primary(PSt::Active(ASt::NotRecovering)) => "NotRecovering",
            St::Primary(PSt::Active(ASt::NotBackfilling)) => "NotBackfilling",
            St::Primary(PSt::Active(_)) => "Active",
            St::Primary(
                PSt::GetInfo
                | PSt::GetLog
                | PSt::GetMissing
                | PSt::WaitUpThru
                | PSt::Down
                | PSt::Incomplete,
            ) => "Peering",
            St::Reset => "Reset",
            _ => "Started",
        }
    }

    /// `list_unfound [offset]`: at most `max` unfound objects strictly after `offset` (hobject order), the counts, the
    /// state and the possible holders.
    pub fn list_unfound(&self, offset: Option<&Hobject>, max: usize) -> UnfoundList {
        let n = self.needs_recovery_items();
        let none = self.none_unfound();
        let num_unfound = if none {
            0
        } else {
            n.iter()
                .filter(|(o, i)| self.item_unfound(i, &self.locations_of(o, i.need)))
                .count()
        };
        let mut objects = Vec::new();
        let mut more = false;
        if num_unfound > 0 {
            let lo = offset.map_or(Bound::Unbounded, |o| Bound::Excluded(o.clone()));
            let mut it = n.range((lo, Bound::Unbounded)).peekable();
            while let Some((o, i)) = it.next() {
                let locs = self.locations_of(o, i.need);
                if !self.item_unfound(i, &locs) {
                    continue;
                }
                objects.push(UnfoundObj {
                    oid: o.clone(),
                    need: i.need,
                    have: i.have,
                    clean_regions: i.clean_regions.clone(),
                    locations: locs,
                });
                if objects.len() >= max {
                    more = it.peek().is_some();
                    break;
                }
            }
        }
        let state = self.unfound_state_name();
        let might = matches!(state, "Active" | "NotRecovering" | "NotBackfilling")
            .then(|| self.might_have_unfound());
        UnfoundList {
            num_missing: n.len(),
            num_unfound,
            objects,
            more,
            state,
            might_have_unfound: might,
        }
    }

    /// Every possible holder was either probed or is declared lost: only then is giving the objects up safe.
    fn all_unfound_are_queried_or_lost(&self) -> bool {
        self.prim
            .might_have_unfound
            .iter()
            .all(|p| self.probed(p) || !self.map.exists(p.osd) || self.is_lost(p.osd))
    }

    /// Past acting sets that may have written (not ours) plus every peer we heard from: who might hold data we miss.
    /// Built at activation, before the past intervals are pruned.
    pub(crate) fn build_might_have_unfound(&mut self) {
        let me = self.me;
        let mut s: BTreeSet<PgShard> = self
            .past
            .intervals
            .iter()
            .flat_map(|iv| iv.acting.iter().copied())
            .filter(|p| *p != me)
            .collect();
        s.extend(self.prim.peer_info.keys().copied().filter(|p| *p != me));
        self.prim.might_have_unfound.extend(s);
    }

    /// Newest version of `oid` any acting member holds below the one that is lost: `have` of our missing item and of
    /// the acting peers' items for it (0'0 = nobody has an older version).
    fn newest_available(&self, oid: &Hobject) -> Eversion {
        let mut v = self
            .missing
            .get(oid)
            .map_or(Eversion::default(), |i| i.have);
        for p in &self.prim.acting_recovery_backfill {
            if *p == self.me {
                continue;
            }
            if let Some(i) = self.prim.peer_missing.get(p).and_then(|m| m.get(oid)) {
                v = v.max(i.have);
            }
        }
        v
    }

    /// `pg <pgid> mark_unfound_lost revert|delete` (checks in classic order, spec ec-unfound-lost.md 3): give up every
    /// unfound object. Revert goes back to the newest older version an acting member holds (else deletes), delete
    /// removes (EC: delete only). One LOST_REVERT / LOST_DELETE entry per object (ascending) goes to the log and the
    /// recovery set as a log-only update; recovery then converges every copy. Answered once every member committed it.
    pub fn mark_unfound_lost(
        &mut self,
        now: Mono,
        mode: LostMode,
        store: &impl PgStoreOps,
    ) -> LostReply {
        self.now = now;
        if self.pool.is_erasure && mode == LostMode::Revert {
            return LostReply::Now(Err((EINVAL, "mode must be 'delete' for ec pool".into())));
        }
        if !self.is_primary() {
            return LostReply::Now(Err((EROFS, "not primary".into())));
        }
        let unfound = self.unfound();
        if unfound.is_empty() {
            return LostReply::Now(Ok("pg has no unfound objects".into()));
        }
        if !self.all_unfound_are_queried_or_lost() {
            return LostReply::Now(Err((
                EINVAL,
                format!(
                    "pg has {} unfound objects but we haven't probed all sources, not marking lost",
                    unfound.len()
                ),
            )));
        }
        if self.prim.lost.is_some() {
            // the unfound set of a marking in flight is still listed until it commits: one marking at a time
            return LostReply::Now(Err((
                EAGAIN,
                "a mark_unfound_lost of this pg is still committing; retry".into(),
            )));
        }
        let epoch = self.map.epoch();
        let mtime = self.wall();
        // EC: a write planned but not generated yet already owns its versions
        let mut v = if self.pool.is_erasure {
            self.log.head().max(self.ep.reserved)
        } else {
            self.log.head()
        };
        let mut entries: Vec<LogEntry> = Vec::with_capacity(unfound.len());
        for u in &unfound {
            v = Eversion::new(epoch, v.version + 1);
            let prev = if mode == LostMode::Revert {
                self.newest_available(&u.oid)
            } else {
                Eversion::default()
            };
            let op = if prev > Eversion::default() {
                LogOp::LOST_REVERT
            } else {
                LogOp::LOST_DELETE
            };
            // classic constructor defaults: user_version 0, no reqid, clean_regions fully clean
            let mut e = LogEntry::new(op, u.oid.clone(), v, u.need);
            e.mtime = mtime;
            e.reverting_to = prev;
            e.clean_regions = ObjectCleanRegions::default();
            if self.pool.is_erasure {
                // rollbackable while divergent (spec 3.1: TRY_DELETE of the entry's version)
                let mut b = ec::moddesc::ModDescBuilder::new();
                b.try_delete(v.version);
                let (bl, version, completed) = b.finish();
                e.mod_desc = ObjectModDesc {
                    version,
                    can_local_rollback: true,
                    rollback_info_completed: completed,
                    bl,
                };
                self.ep.xc_drop_obj(&u.oid);
            }
            entries.push(e);
        }
        self.write_tid += 1;
        let tid = self.write_tid;
        self.info.stats.stats_invalid = true;
        // EC: writes submitted before the marking generate first (version order)
        let queued = self.pool.is_erasure && self.ep.front_tid().is_some();
        if self.pool.is_erasure {
            self.ep.reserved = v;
        }
        self.prim.lost = Some(LostPending {
            tid,
            count: unfound.len(),
            queued: None,
        });
        if queued {
            if let Some(l) = self.prim.lost.as_mut() {
                l.queued = Some(entries);
            }
        } else {
            self.lost_submit(tid, entries);
        }
        self.notes.push(format!(
            "pg {}: marking {} unfound objects lost ({mode:?})",
            self.spg,
            unfound.len()
        ));
        self.after_event(store);
        LostReply::Later(tid)
    }

    /// EC generation loop: the queued marking goes out once no write submitted before it is left to generate (the
    /// oldest pending write `front_tid` is newer, or none).
    pub(crate) fn lost_generate_due(&mut self, front_tid: Option<u64>) {
        let Some(l) = self.prim.lost.as_mut() else {
            return;
        };
        if l.queued.is_none() || front_tid.is_some_and(|t| t < l.tid) {
            return;
        }
        let tid = l.tid;
        if let Some(entries) = l.queued.take() {
            self.lost_submit(tid, entries);
        }
    }

    /// Append the marking to our log (log-only: our missing set takes every entry, no object change), update our view
    /// of each member, send the entries to the recovery set and track the update like a write (complete when every
    /// member replied and our log is durable).
    fn lost_submit(&mut self, tid: u64, entries: Vec<LogEntry>) {
        let Some(last) = entries.last().map(|e| e.version) else {
            return;
        };
        let epoch = self.map.epoch();
        let pct = self.pg_committed_to;
        self.append_log(entries.clone(), Eversion::default(), pct, false, false);
        let logbl = denc::to_vec(&entries).expect("encode entries");
        let mut waiting = BTreeSet::new();
        let peers: Vec<PgShard> = self
            .prim
            .acting_recovery_backfill
            .iter()
            .copied()
            .filter(|p| *p != self.me)
            .collect();
        for p in peers {
            if let Some(pi) = self.prim.peer_info.get_mut(&p) {
                let pm = self
                    .prim
                    .peer_missing
                    .entry(p)
                    .or_insert_with(|| MissingSet::new(true));
                for e in &entries {
                    if e.soid <= pi.last_backfill {
                        pm.add_next_event(e);
                    }
                }
                pi.last_update = last;
                pi.stats.stats_invalid = true;
                if pm.is_empty() {
                    pi.last_complete = last;
                }
            }
            let m = MOSDPGUpdateLogMissing {
                map_epoch: epoch,
                pgid: SpgT {
                    pgid: self.spg.pgid,
                    shard: p.shard,
                },
                from: self.me.shard,
                rep_tid: tid,
                entries: logbl.clone(),
                min_epoch: self.last_peering_reset,
                pg_trim_to: self.prim.pg_trim_to,
                pg_committed_to: pct,
            };
            self.send_repl(p.osd, m, tid);
            waiting.insert(p);
        }
        self.prim.repops.insert(
            tid,
            RepOp {
                version: last,
                waiting,
                local_done: false,
                ec_objects: Vec::new(),
                t0: wprof::lat_t0(),
                t_local: 0,
            },
        );
        let interval = self.last_peering_reset;
        self.flush(Pending::LocalWrite { interval, tid });
    }

    /// Update `tid` committed everywhere: if it is the marking, answer it.
    pub(crate) fn lost_committed(&mut self, tid: u64) {
        if self
            .prim
            .lost
            .as_ref()
            .is_none_or(|l| l.tid != tid || l.queued.is_some())
        {
            return;
        }
        let Some(l) = self.prim.lost.take() else {
            return;
        };
        let msg = format!(
            "pg has {} objects unfound and apparently lost marking",
            l.count
        );
        self.notes.push(format!("pg {}: {msg}", self.spg));
        self.emit(Action::LostMarked(Box::new(LostDone {
            spg: self.spg,
            tid,
            result: Ok(msg),
        })));
    }

    /// The interval ended (or peering restarted) before the marking committed everywhere: answer `-EAGAIN` (classic
    /// never answers, doc/parity.md). Appended entries stay in the log and reach the members through peering.
    pub(crate) fn lost_abort(&mut self) {
        let Some(l) = self.prim.lost.take() else {
            return;
        };
        let msg = format!(
            "interval changed before marking {} unfound objects lost committed on every shard ({}); check list_unfound and retry",
            l.count,
            if l.queued.is_some() {
                "nothing was written"
            } else {
                "the entries may still apply"
            }
        );
        self.notes.push(format!("pg {}: {msg}", self.spg));
        self.emit(Action::LostMarked(Box::new(LostDone {
            spg: self.spg,
            tid: l.tid,
            result: Err((EAGAIN, msg)),
        })));
    }

    /// Classic UnfoundRecovery (spec ec-unfound-lost.md 1.7): a recovery pass with nothing in flight while everything
    /// left is unfound probes the strays; with no probe outstanding the reservations go back and the PG waits in
    /// NotRecovering (`recovery_unfound`) until something becomes recoverable ([`Self::unfound_resume_due`]).
    pub(crate) fn maybe_unfound_recovery(&mut self) {
        if self.st != St::Primary(PSt::Active(ASt::Recovering))
            || self.rec_inflight() != 0
            || !self.only_unfound_left()
        {
            return;
        }
        self.probe_strays();
        if !self.prim.peer_missing_requested.is_empty() {
            return;
        }
        self.release_recovery_reservations();
        self.set_st(St::Primary(PSt::Active(ASt::NotRecovering)));
        self.state &= !(pgs::RECOVERING | pgs::RECOVERY_WAIT);
        self.state |= pgs::RECOVERY_UNFOUND;
        self.rec.unfound_hold = true;
        // a fresh verdict from this point on (`unfound_resume_due` decides whether it may end)
        self.rec.unfound_verdict = None;
        self.notes.push(format!(
            "pg {}: recovery stopped, objects unfound (list_unfound / mark_unfound_lost)",
            self.spg
        ));
    }

    /// NotRecovering after UnfoundRecovery: recover again (classic DoRecovery) once something became recoverable (a
    /// committed marking, a new source) and no marking is in flight.
    pub(crate) fn unfound_resume_due(&mut self) -> bool {
        if self.prim.lost.is_some() {
            return false;
        }
        let key = self.unfound_key();
        let all_unfound = match self.rec.unfound_verdict {
            Some((k, v)) if k == key => v,
            _ => {
                let v = self.only_unfound_left();
                self.rec.unfound_verdict = Some((key, v));
                v
            }
        };
        !all_unfound
    }

    /// Cache key of [`Self::only_unfound_left`]: everything that predicate reads, folded into one word — map and
    /// interval identity, log ends, our missing set and every peer's, the peer info it judges sources by, stray
    /// probes, failed sources and the EC geometry. Per event that is a walk over the peers; the predicate itself walks
    /// every missing object.
    fn unfound_key(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.refuse.is_some().hash(&mut h); // unfound_possible
        matches!(self.st, St::Primary(PSt::Active(_))).hash(&mut h);
        self.up.hash(&mut h); // is_stray_shard
        self.acting.hash(&mut h);
        self.state.hash(&mut h); // ACTIVE and the recovery bits
        self.map.epoch().hash(&mut h); // is_up / up_from / lost_at / exists
        self.last_peering_reset.hash(&mut h); // interval: the recovery set
        self.log.head().hash(&mut h); // revert_of: the newest entry of an object
        self.log.tail().hash(&mut h);
        self.missing.stamp().hash(&mut h);
        self.missing.len().hash(&mut h);
        for p in &self.prim.acting_recovery_backfill {
            p.hash(&mut h);
        }
        for p in &self.prim.backfill_targets {
            p.hash(&mut h);
        }
        // `backfill_target_has_range` (EC) reads the targets' progress
        for (p, b) in &self.bf.targets {
            (
                p,
                b.phase == crate::backfill::BfPhase::Done,
                &b.cursor,
                &b.batch_end,
            )
                .hash(&mut h);
            (b.todo.len(), b.pushing.len()).hash(&mut h);
        }
        for (p, m) in &self.prim.peer_missing {
            p.hash(&mut h);
            m.stamp().hash(&mut h);
            m.len().hash(&mut h);
        }
        for (p, i) in &self.prim.peer_info {
            p.hash(&mut h);
            i.last_update.hash(&mut h);
            i.last_backfill.hash(&mut h);
        }
        for p in &self.prim.stray_src {
            p.hash(&mut h);
        }
        self.rec.failed_sources.hash(&mut h);
        self.pool.is_erasure.hash(&mut h);
        if let Some(b) = self.ecb() {
            (b.k, b.m, b.s, b.c, b.overwrites, b.omap).hash(&mut h);
        }
        h.finish()
    }
}

#[cfg(test)]
mod unfound_hold_tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use crate::store::MemStore;
    use denc::types::{PgT, ShardId, SnapId};
    use std::sync::Arc;

    /// Primary of a size-2 pool whose `count` missing objects nobody holds: everything left is unfound, the PG waits
    /// in NotRecovering (`recovery_unfound`) with the unfound hold set.
    fn held_pg(count: usize) -> (Pg, PgShard, MemStore) {
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
        // the peer is up and reachable, but it misses those objects too: nobody can supply them
        pg.prim.peer_info.insert(
            peer,
            pgwire::PgInfo {
                last_backfill: Hobject::MAX(),
                last_update: Eversion::default(),
                ..pgwire::PgInfo::new(spg)
            },
        );
        let pm = pg
            .prim
            .peer_missing
            .entry(peer)
            .or_insert_with(|| MissingSet::new(true));
        for i in 0..count {
            let oid = Hobject::new(format!("o{i}").as_bytes(), SnapId::NOSNAP, 0, 1, b"");
            pg.missing
                .add(oid.clone(), Eversion::new(1, 1), Eversion::default(), false);
            pm.add(oid, Eversion::new(1, 1), Eversion::default(), false);
        }
        pg.st = St::Primary(PSt::Active(ASt::NotRecovering));
        pg.state = pgs::ACTIVE | pgs::RECOVERY_UNFOUND;
        pg.rec.unfound_hold = true;
        (pg, peer, MemStore::new())
    }

    /// A held PG asks "is everything still unfound?" after every event: that answer is recomputed only when its inputs
    /// changed, and a source that appears still resumes recovery (R2).
    #[test]
    fn the_unfound_verdict_is_recomputed_only_when_its_inputs_change() {
        let (mut pg, peer, store) = held_pg(3);
        // the first events settle the resting state (state bits, the submit of the PG info)
        pg.after_event(&store);
        pg.after_event(&store);
        assert!(pg.rec.unfound_hold, "still nothing recoverable");
        let walked = pg.rec.unfound_walks;
        for _ in 0..50 {
            pg.after_event(&store);
        }
        assert_eq!(pg.rec.unfound_walks, walked, "no walk without a change");

        // an unrelated event (a stats report) changes no input
        pg.info.stats.stats.sum.num_objects = 7;
        pg.info_dirty = true;
        pg.after_event(&store);
        assert_eq!(
            pg.rec.unfound_walks, walked,
            "no re-walk for an unrelated change"
        );

        // the peer recovered them (its missing set drained): a source is there, recovery resumes at once
        let pm = pg.prim.peer_missing.get_mut(&peer).unwrap();
        for i in 0..3 {
            let oid = Hobject::new(format!("o{i}").as_bytes(), SnapId::NOSNAP, 0, 1, b"");
            pm.got(&oid, Eversion::new(1, 1));
        }
        pg.after_event(&store);
        assert_eq!(pg.rec.unfound_walks, walked + 1, "the change re-walks once");
        assert!(!pg.rec.unfound_hold, "the hold is over");
        assert_eq!(pg.state & pgs::RECOVERY_UNFOUND, 0);
    }

    /// A peer missing set that changes is a change too: the verdict is re-derived (and stays "all unfound"), never
    /// served stale.
    #[test]
    fn a_peer_missing_change_re_checks_the_verdict() {
        let (mut pg, peer, store) = held_pg(2);
        pg.after_event(&store);
        pg.after_event(&store);
        let walked = pg.rec.unfound_walks;
        let oid = Hobject::new(b"o2", SnapId::NOSNAP, 0, 1, b"");
        pg.missing
            .add(oid.clone(), Eversion::new(1, 1), Eversion::default(), false);
        pg.prim.peer_missing.get_mut(&peer).unwrap().add(
            oid,
            Eversion::new(1, 1),
            Eversion::default(),
            false,
        );
        pg.after_event(&store);
        assert_eq!(pg.rec.unfound_walks, walked + 1);
        assert!(pg.rec.unfound_hold, "everything left is still unfound");
    }

    /// A peer's missing set replaced by another one with the same size and change count (a re-fetch during peering)
    /// is a different input: the verdict is re-derived and the now-present source ends the hold.
    #[test]
    fn a_replaced_peer_missing_set_re_checks_the_verdict() {
        let (mut pg, peer, store) = held_pg(2);
        pg.after_event(&store);
        pg.after_event(&store);
        assert!(pg.rec.unfound_hold);
        let mut other = MissingSet::new(true);
        for i in 0..2 {
            let oid = Hobject::new(format!("x{i}").as_bytes(), SnapId::NOSNAP, 0, 1, b"");
            other.add(oid, Eversion::new(1, 1), Eversion::default(), false);
        }
        assert_eq!(other.stamp().1, pg.prim.peer_missing[&peer].stamp().1);
        assert_eq!(other.len(), pg.prim.peer_missing[&peer].len());
        pg.prim.peer_missing.insert(peer, other);
        pg.after_event(&store);
        assert!(
            !pg.rec.unfound_hold,
            "the peer holds o0/o1 now: recovery resumes"
        );
    }

    /// Measurement, not a gate: the cost of the per-event unfound check on a PG with a large unfound set
    /// (`cargo test -p peering --lib the_unfound_hold_cost -- --ignored --nocapture`).
    #[test]
    #[ignore]
    fn the_unfound_hold_cost() {
        const OBJECTS: usize = 20_000;
        const EVENTS: usize = 200;
        let (mut pg, _peer, store) = held_pg(OBJECTS);
        let t = std::time::Instant::now();
        for _ in 0..EVENTS {
            pg.after_event(&store);
        }
        println!(
            "{OBJECTS} unfound objects, {EVENTS} events: {:?} ({} walks)",
            t.elapsed(),
            pg.rec.unfound_walks
        );
    }
}
