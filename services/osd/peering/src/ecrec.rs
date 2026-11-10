// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! EC recovery as primary (spec ec.md 13, doc/ec-phase-b.md B7): rebuild the shard of every target that misses an
//! object from k surviving shards and push it (or apply it locally when we miss it ourselves). One [`RecOp`] per
//! object: attrs (from our shard, or from a source when we miss it), then chunks of whole stripes: read -> decode ->
//! re-encode -> one push per target shard -> wait for the acks -> next chunk.

use crate::ecprim::{Asked, Purpose};
use crate::pg::{ASt, PSt, Pending, Pg, St};
use crate::plog::recompute_last_complete;
use crate::store::{PgStoreOps, StoreOp};
use crate::types::*;
use denc::types::{Eversion, Hobject, PgShard, ShardId, SpgT};
use ecwire::{ECSubRead, MOSDECSubOpRead, MOSDECSubOpReadReply};
use replwire::{MOSDPGPush, MOSDPGPushReply, ObjectRecoveryInfo, ObjectRecoveryProgress, PushOp};
use std::collections::{BTreeMap, BTreeSet};

/// Wait before a failed object is tried again.
const RETRY: Mono = 3 * SEC;

/// Mode O omap recovery of one object (spec ec-optimized.md 10.1): one batch of entries per push round, after the last
/// pushed key, until the omap is exhausted; data and omap completion are independent.
#[derive(Debug, Default)]
struct OmapRec {
    /// Every entry was pushed (`omap_complete`).
    done: bool,
    /// Last key pushed (`omap_recovered_to`); `None` before the first entry.
    after: Option<Vec<u8>>,
    /// We miss the object: the primary-capable source shard's omap, one page at a time.
    src: Option<OmapSrc>,
    /// Batch of the current round, built before its data read; the push commits it.
    batch: Option<OmapBatch>,
    /// Entries pushed so far (`num_keys_recovered`, `ObjectRecoveryInfo::num_omap_keys`).
    keys: u64,
}

/// Omap of a remote source shard (we miss the object): its header and the fetched, not yet pushed entries.
#[derive(Debug)]
struct OmapSrc {
    /// Instance the pages come from (a member or a stray, spec missing-loc.md 6).
    from: PgShard,
    header: Vec<u8>,
    /// Source entries after `OmapRec::after` up to `cursor`: every source key in that range is here.
    buf: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Last key fetched (`None`: no page yet): the next page starts strictly after it. Never the empty key while the
    /// source is not `done` (a page that is not the last ends at a non-empty key, `ecopt::omap_batch`), so the wire
    /// start key ([`crate::ecopt::omap_wire_after`]) can express it.
    cursor: Option<Vec<u8>>,
    /// The source has no entries after `cursor`.
    done: bool,
}

/// The omap part of one push round.
#[derive(Debug)]
struct OmapBatch {
    /// First round only: the header primary-capable targets get.
    header: Option<Vec<u8>>,
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
    /// `OmapRec::after` / `done` once this batch is pushed.
    after: Option<Vec<u8>>,
    done: bool,
}

/// Where a recovery op is.
#[derive(Debug, PartialEq, Eq)]
enum RecState {
    /// Waiting for the object attributes from a source shard (we miss the object ourselves).
    /// No timer: given up only when a map shows the source down (`ec_recov_src_check`).
    NeedAttrs(Asked),
    /// Mode O (omap pool): next page of a source shard's omap (we miss the object ourselves).
    NeedOmap(Asked),
    Reading,
    /// Pushes of the current chunk in flight to these targets (by pg_shard: one OSD may hold two, adr 0049 am. 3).
    Pushing(BTreeSet<PgShard>),
}

/// Recovery of one object to its target shards.
#[derive(Debug)]
pub(crate) struct RecOp {
    version: Eversion,
    size: u64,
    attrs: BTreeMap<Vec<u8>, Vec<u8>>,
    ri: ObjectRecoveryInfo,
    /// Target shards (possibly including ourselves) and whether they hold an older copy.
    targets: Vec<(PgShard, bool)>,
    next_stripe: u64,
    nstripes: u64,
    first: bool,
    state: RecState,
    /// Targets that asked while chunks were already out (backfill of an object also being recovered): a fresh op after this one.
    joiners: Vec<(PgShard, bool)>,
    /// Mode O omap pool, object with omap: its omap recovery (`None`: no omap to push).
    omap: Option<OmapRec>,
    /// A clay repair read failed for this object: whole-chunk reads from now on.
    no_repair: bool,
    /// Id of the chunk read this op waits for (`EcRd::id`, set when the read is registered): any other completion of the
    /// object is a leftover of a cancelled op.
    pub(crate) read: Option<u64>,
}

/// Recovery bookkeeping of the EC primary.
#[derive(Debug, Default)]
pub(crate) struct EcRecov {
    pub(crate) ops: BTreeMap<Hobject, RecOp>,
    /// Objects whose last attempt failed (sources gone, version not there yet): retried at the given time.
    failed: BTreeMap<Hobject, Mono>,
}

impl EcRecov {
    /// Forget the work in flight (reservations released, backfill stopped); failed objects keep their retry time.
    pub(crate) fn cancel(&mut self) {
        self.ops.clear();
    }
}

/// Whole stripes one EC recovery read covers: the byte budget rounded UP to the stripe width, at least one
/// (classic `ECCommon.h` recovery read sizing, spec peering.md 13.4).
fn rec_stripes(budget: u64, stripe: u64) -> u64 {
    budget.div_ceil(stripe.max(1)).max(1)
}

impl Pg {
    /// Drive recovery of an EC PG: our own missing objects, then the peers'.
    pub(crate) fn ec_recovery_step(&mut self, store: &impl PgStoreOps) {
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
            && self.ep.recov.ops.is_empty()
            && self.rec.deletes.is_empty()
        {
            self.all_recovered();
            return;
        }
        let max = self.rec.cap;
        let mut inflight = self.ep.recov.ops.len() + self.rec.deletes.len();
        let any_unfound = self.may_be_unfound();
        // 1. our own missing objects
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
        let mut dirty = false;
        for (need, oid, is_delete) in mine {
            if inflight >= max {
                self.rec.wants = true;
                break;
            }
            if self.ep.recov.ops.contains_key(&oid)
                || self
                    .ep
                    .recov
                    .failed
                    .get(&oid)
                    .is_some_and(|t| *t > self.now)
            {
                continue;
            }
            if is_delete {
                self.txn.push(StoreOp::RemoveObject(oid.clone()));
                self.missing.got(&oid, need);
                dirty = true;
                continue;
            }
            if any_unfound && self.obj_unfound(&oid, need) {
                continue; // waits for a source or mark_unfound_lost (lost.rs)
            }
            if self.clone_waits_for_head(&oid) {
                continue;
            }
            self.ec_recov_start(oid, need, vec![(self.me, false)], store);
            inflight += 1;
        }
        if dirty {
            recompute_last_complete(&self.log, &mut self.info, &self.missing);
            self.info_dirty = true;
        }
        // 2. the peers' objects, grouped per object so one read serves every target
        let mut want: BTreeMap<Hobject, (Eversion, Vec<(PgShard, bool)>)> = BTreeMap::new();
        let max_objects = self.cfg.max_push_objects.max(1);
        for p in &peers {
            let Some(pm) = self.prim.peer_missing.get(p) else {
                continue;
            };
            if inflight >= max {
                // at the cap nothing starts: skip collecting and ordering the peer's missing set
                // (no clones); the probe stops at the first entry neither in flight nor cooling down
                self.rec.wants |= pm.iter().any(|(o, _)| {
                    !self.ep.recov.ops.contains_key(o)
                        && self.ep.recov.failed.get(o).is_none_or(|t| *t <= self.now)
                });
                continue;
            }
            let items: Vec<(Eversion, Hobject, Eversion, bool)> = pm
                .iter()
                .map(|(o, i)| (i.need, o.clone(), i.have, i.is_delete()))
                .collect();
            let mut deletes: Vec<(Hobject, Eversion)> = Vec::new();
            for (need, oid, have, is_delete) in items {
                if self.rec.deletes.contains(&(oid.clone(), *p)) {
                    continue;
                }
                if is_delete {
                    if inflight >= max {
                        self.rec.wants = true;
                        continue;
                    }
                    self.rec.deletes.insert((oid.clone(), *p));
                    deletes.push((oid, need));
                    inflight += 1;
                    if deletes.len() >= max_objects {
                        self.flush_recovery_deletes(*p, &mut deletes);
                    }
                    continue;
                }
                if self.missing.contains(&oid)
                    || self.applying.contains_key(&oid)
                    || self.ep.recov.ops.contains_key(&oid)
                    || self
                        .ep
                        .recov
                        .failed
                        .get(&oid)
                        .is_some_and(|t| *t > self.now)
                {
                    // we recover it first (or its local apply has not committed: spec replication.md 6.6) / already on
                    // its way
                    continue;
                }
                let e = want.entry(oid).or_insert((need, Vec::new()));
                if e.0 == need {
                    e.1.push((*p, have != Eversion::default()));
                }
            }
            self.flush_recovery_deletes(*p, &mut deletes);
        }
        let mut want: Vec<_> = want
            .into_iter()
            .filter(|(oid, (need, _))| !any_unfound || !self.obj_unfound(oid, *need))
            .collect();
        // stable sort of an oid-ordered list: ties stay in oid order
        want.sort_by_cached_key(|(oid, (need, _))| self.rec.order(*need, oid));
        for (oid, (need, targets)) in want {
            if inflight >= max {
                self.rec.wants = true;
                break;
            }
            if self.clone_waits_for_head(&oid) {
                continue;
            }
            self.ec_recov_start(oid, need, targets, store);
            inflight += 1;
        }
        self.maybe_unfound_recovery();
    }

    /// Recovery needs a backfill target's object: same machinery, called by the backfill driver.
    pub(crate) fn ec_backfill_push(
        &mut self,
        target: PgShard,
        oid: Hobject,
        need: Eversion,
        exists: bool,
        store: &impl PgStoreOps,
    ) {
        if let Some(op) = self.ep.recov.ops.get_mut(&oid) {
            let known = op
                .targets
                .iter()
                .chain(op.joiners.iter())
                .any(|(p, _)| *p == target);
            if !known {
                if op.first {
                    op.targets.push((target, exists));
                } else {
                    op.joiners.push((target, exists));
                }
            }
            return;
        }
        self.ec_recov_start(oid, need, vec![(target, exists)], store);
    }

    fn ec_recov_fail(&mut self, soid: &Hobject, why: &str) {
        let op = self.ep.recov.ops.remove(soid);
        // a backfill target waits for this push: stop that backfill (retry timer) instead of hanging on it
        let stalled: Vec<PgShard> = op
            .iter()
            .flat_map(|o| o.targets.iter().chain(o.joiners.iter()))
            .map(|(p, _)| *p)
            .filter(|p| self.bf.targets.contains_key(p))
            .collect();
        if let Some(p) = stalled.first() {
            self.backfill_stall(*p, "backfill: EC rebuild of an object failed");
        }
        let first = self
            .ep
            .recov
            .failed
            .insert(soid.clone(), self.now + RETRY)
            .is_none();
        self.error("ec recovery failed");
        if first {
            self.notes.push(format!(
                "pg {}: EC recovery of {} failed: {why} (retrying)",
                self.spg,
                String::from_utf8_lossy(&soid.oid)
            ));
        }
    }

    /// Map change in the interval: attribute / omap reads whose source went down fail their object (retried from another
    /// source). A source that is up is waited for.
    pub(crate) fn ec_recov_src_check(&mut self, _store: &impl PgStoreOps) {
        let gone: Vec<Hobject> = self
            .ep
            .recov
            .ops
            .iter()
            .filter(|(_, o)| matches!(&o.state, RecState::NeedAttrs(src) | RecState::NeedOmap(src) if self.ec_src_gone(src)))
            .map(|(s, _)| s.clone())
            .collect();
        for s in gone {
            self.ec_recov_fail(&s, "attributes source went down");
        }
    }

    /// A new source appeared (a stray, spec missing-loc.md 4.3): failed objects are tried again at once.
    pub(crate) fn ec_recov_retry_now(&mut self, now: Mono) {
        for t in self.ep.recov.failed.values_mut() {
            *t = (*t).min(now);
        }
    }

    /// Earliest runnable retry (timer for `Pg::next_deadline`). Reservation and
    /// budget changes wake suspended work; a cooldown must not spin their wait.
    pub(crate) fn ec_recov_next_retry(&self) -> Option<Mono> {
        if self.ep.recov.failed.is_empty()
            || self.st != St::Primary(PSt::Active(ASt::Recovering))
            || self.recovery_blocked()
        {
            return None;
        }
        // At the lease, an op completion or the lease grant (`rec.wants`) runs the PG again.
        // An idle PG gave its lease back (`OpsLease::sync`: cap 0, no wish yet): only the
        // cooldown wakes its recovery pass, which then asks for units.
        let inflight = self.rec_inflight();
        if inflight >= self.rec.cap && (inflight > 0 || self.rec.wants) {
            return None;
        }
        let sleep_until = if self.recovery_sleep() > 0 {
            self.cfg
                .rec_sched
                .load(std::sync::atomic::Ordering::Relaxed)
        } else {
            0
        };
        let any_unfound = self.may_be_unfound();
        self.ep
            .recov
            .failed
            .iter()
            .filter_map(|(oid, at)| {
                // Reads, pushes and local apply completions own these wakes. Old
                // cooldowns for removed/unfound objects cannot start recovery work.
                if self.ep.recov.ops.contains_key(oid) || self.applying.contains_key(oid) {
                    return None;
                }
                let missing = self.missing.get(oid).or_else(|| {
                    self.prim
                        .acting_recovery_backfill
                        .iter()
                        .filter(|p| **p != self.me && !self.prim.backfill_targets.contains(p))
                        .find_map(|p| self.prim.peer_missing.get(p).and_then(|m| m.get(oid)))
                })?;
                (!any_unfound || !self.obj_unfound(oid, missing.need)).then_some(*at)
            })
            .min()
            .map(|at| at.max(sleep_until))
    }

    fn ec_recov_start(
        &mut self,
        soid: Hobject,
        version: Eversion,
        targets: Vec<(PgShard, bool)>,
        store: &impl PgStoreOps,
    ) {
        if self.ecb().is_none() {
            return;
        }
        // This attempt owns the wake from now on; a failure installs a fresh
        // cooldown. Keeping the expired timestamp would spin the due-PG timer.
        self.ep.recov.failed.remove(&soid);
        let mut op = RecOp {
            version,
            size: 0,
            attrs: BTreeMap::new(),
            ri: ObjectRecoveryInfo::default(),
            targets,
            next_stripe: 0,
            nstripes: 0,
            first: true,
            state: RecState::Reading,
            joiners: Vec::new(),
            omap: None,
            no_repair: false,
            read: None,
        };
        if !self.missing.contains(&soid) {
            // our shard is current: attrs and object_info are local
            let attrs = match store.ec_getattrs(self.spg, &soid) {
                Ok(a) => a,
                Err(_) => return self.ec_recov_fail(&soid, "local attributes unreadable"),
            };
            let oi = match attrs
                .get(b"_".as_slice())
                .and_then(|b| denc::from_slice::<replwire::ObjectInfo>(b).ok())
            {
                Some(o) => o,
                None => return self.ec_recov_fail(&soid, "local object_info unreadable"),
            };
            if oi.version != version {
                // the local copy is not the version the target needs (yet): leave it for the next step
                self.ep.recov.failed.insert(soid, self.now + RETRY);
                return;
            }
            let mut ri = match store.recovery_info_checked(self.spg, &soid) {
                Ok(ri) => ri,
                // a vanished / damaged local copy (e.g. a clone whose head snapset does not decode): never push a
                // default recovery info, it would install an empty snap mapping on the target
                Err(_) => return self.ec_recov_fail(&soid, "local recovery info unreadable"),
            };
            ri.soid = soid.clone();
            ri.version = oi.version;
            ri.size = oi.size;
            ri.copy_subset = BTreeMap::from([(0, oi.size)]);
            ri.oi = oi.clone();
            op.size = oi.size;
            op.attrs = attrs;
            op.ri = ri;
            op.nstripes = oi.size.div_ceil(self.ecb().map_or(1, |b| b.s));
            op.omap = (self.ec_omap_ok() && oi.flags & replwire::oi::flag::OMAP != 0)
                .then(OmapRec::default);
            self.ep.recov.ops.insert(soid.clone(), op);
            self.ec_recov_chunk(&soid, store);
        } else {
            // we miss it: ask one source shard for the attributes first
            let (avail, src) = self.ec_sources(&soid);
            // attrs (and the omap of an omap pool) come from a primary-capable shard: a nonprimary shard holds no omap and
            // its object_info lags behind writes that did not touch it (shard_versions). Without FLAG_OMAP (a tentacle
            // cluster) a lagging nonprimary source failed the version check forever (object stuck unfound).
            let omap = self.ec_omap_ok();
            let np = |s: u32| self.pool.ec.as_ref().is_some_and(|e| e.is_nonprimary(s));
            let Some(&sh) = avail.iter().find(|s| **s != self.my_shard() && !np(**s)) else {
                return self.ec_recov_fail(&soid, "no source shard");
            };
            let Some(osd) = src
                .get(&sh)
                .copied()
                .or_else(|| self.ec_osd_holding(&soid, sh))
            else {
                return self.ec_recov_fail(&soid, "no source shard");
            };
            self.write_tid += 1;
            let tid = self.write_tid;
            let mut sr = ECSubRead {
                from: self.me,
                tid,
                ..Default::default()
            };
            sr.attrs_to_read.insert(soid.clone());
            if omap {
                // the shard answers "complete" at once for an object whose object_info has no omap
                sr.omap_headers_to_read.insert(soid.clone());
                sr.omap_read_from
                    .insert(soid.clone(), (Vec::new(), self.cfg.recovery_max_chunk));
            }
            let m = MOSDECSubOpRead {
                pgid: SpgT {
                    pgid: self.spg.pgid,
                    shard: ShardId(sh as i8),
                },
                map_epoch: self.map.epoch(),
                op: sr,
                min_epoch: self.last_peering_reset,
                trace: [0; 3],
                cost: 1000,
            };
            // recovery sub-reads carry the recovery message priority: a classic mclock shard schedules a read at or
            // below the forced class as background work, anything above as immediate (spec replication.md 6.1)
            let prio = self.recovery_message_priority();
            self.send_prio(osd, Body::Ec(ecwire::EcMsg::from(m)), tid, prio);
            let src = Asked {
                tid,
                osd,
                epoch: self.map.epoch(),
            };
            op.state = RecState::NeedAttrs(src);
            self.ep.recov.ops.insert(soid, op);
        }
    }

    /// Attributes of the source arrived (we miss the object): size, object_info, then the first chunk.
    pub(crate) fn ec_recov_attrs(
        &mut self,
        from: i32,
        tid: u64,
        m: MOSDECSubOpReadReply,
        store: &impl PgStoreOps,
    ) -> bool {
        let Some(soid) = self
            .ep
            .recov
            .ops
            .iter()
            .find(|(_, o)| {
                matches!(o.state, RecState::NeedAttrs(a) | RecState::NeedOmap(a) if a.tid == tid && a.osd == from)
            })
            .map(|(s, _)| s.clone())
        else {
            return false;
        };
        if self
            .ep
            .recov
            .ops
            .get(&soid)
            .is_some_and(|o| matches!(o.state, RecState::NeedOmap(_)))
        {
            self.ec_recov_omap_page(&soid, &m, store);
            return true;
        }
        let Some(a) = m.op.attrs_read.get(&soid) else {
            self.ec_recov_fail(&soid, "source has no attributes");
            return true;
        };
        let attrs: BTreeMap<Vec<u8>, Vec<u8>> =
            a.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let Some(oi) = attrs
            .get(b"_".as_slice())
            .and_then(|b| denc::from_slice::<replwire::ObjectInfo>(b).ok())
        else {
            self.ec_recov_fail(&soid, "source object_info unreadable");
            return true;
        };
        // the source must hold the version we need (as on the local path): an older copy would be rebuilt and marked recovered
        let need = self.ep.recov.ops.get(&soid).map(|o| o.version);
        if let Some(need) = need
            && need != oi.version
        {
            let why = format!(
                "source shard {} has version {:?}, need {need:?}",
                m.op.from.shard.0, oi.version
            );
            self.ec_recov_fail(&soid, &why);
            return true;
        }
        let s = self.ecb().map_or(1, |b| b.s);
        // the omap comes from the same primary-capable instance, page by page with the push rounds
        let omap =
            (self.ec_omap_ok() && oi.flags & replwire::oi::flag::OMAP != 0).then(|| OmapRec {
                src: Some(OmapSrc {
                    from: m.op.from,
                    header: Vec::new(),
                    buf: BTreeMap::new(),
                    cursor: None,
                    done: false,
                }),
                ..Default::default()
            });
        // a clone travels with its head's SnapSet: every receiver derives the clone's snap mapper entry from it, and the
        // source shard's clone attributes hold none. Our head is recovered first (see `ec_recovery_step`).
        let ss = if crate::snaps::is_clone(&soid) {
            match store.recovery_info_checked(self.spg, &crate::recovery::head_of(&soid)) {
                Ok(h) => h.ss,
                Err(_) => {
                    self.ec_recov_fail(&soid, "head SnapSet of the clone unreadable");
                    return true;
                }
            }
        } else {
            replwire::SnapSet::default()
        };
        if let Some(op) = self.ep.recov.ops.get_mut(&soid) {
            let mut ri = ObjectRecoveryInfo {
                soid: soid.clone(),
                version: oi.version,
                size: oi.size,
                copy_subset: BTreeMap::from([(0, oi.size)]),
                object_exist: false,
                ss,
                ..Default::default()
            };
            ri.oi = oi.clone();
            op.version = oi.version;
            op.size = oi.size;
            op.attrs = attrs;
            op.ri = ri;
            op.nstripes = oi.size.div_ceil(s);
            op.omap = omap;
            op.state = RecState::Reading;
        }
        self.ec_recov_omap_page(&soid, &m, store);
        true
    }

    /// Mode O, we miss the object: a page of the source shard's omap arrived (the first reply also carries the
    /// attributes and the header); the round that waited for it goes on.
    fn ec_recov_omap_page(
        &mut self,
        soid: &Hobject,
        m: &MOSDECSubOpReadReply,
        store: &impl PgStoreOps,
    ) {
        let Some(op) = self.ep.recov.ops.get_mut(soid) else {
            return;
        };
        op.state = RecState::Reading;
        let Some(src) = op.omap.as_mut().and_then(|o| o.src.as_mut()) else {
            return self.ec_recov_chunk(soid, store);
        };
        if m.op.errors.contains_key(soid) {
            return self.ec_recov_fail(soid, "source omap unreadable");
        }
        if let Some(h) = m.op.omap_headers_read.get(soid) {
            src.header = h.clone();
        }
        let page = m.op.omap_entries_read.get(soid);
        src.done = m.op.omaps_complete.get(soid).copied().unwrap_or(false);
        match page.and_then(|e| e.last_key_value()) {
            // a page that is not the last must move the cursor to a key the next request can start after
            Some((k, _))
                if !src.done && (k.is_empty() || src.cursor.as_ref().is_some_and(|c| k <= c)) =>
            {
                return self.ec_recov_fail(soid, "source omap pages without progress");
            }
            Some((k, _)) => src.cursor = Some(k.clone()),
            None if !src.done => {
                return self.ec_recov_fail(soid, "source omap pages without progress");
            }
            None => {}
        }
        if let Some(e) = page {
            src.buf
                .extend(e.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        self.ec_recov_chunk(soid, store);
    }

    /// Ask the omap source for its page after `cursor` (`None`: from the first key); the round waits in `NeedOmap`.
    fn ec_recov_omap_fetch(&mut self, soid: &Hobject, from: PgShard, cursor: Option<Vec<u8>>) {
        if !self.map.is_up(from.osd) {
            return self.ec_recov_fail(soid, "omap source gone");
        }
        self.write_tid += 1;
        let tid = self.write_tid;
        let mut sr = ECSubRead {
            from: self.me,
            tid,
            ..Default::default()
        };
        sr.omap_read_from.insert(
            soid.clone(),
            (cursor.unwrap_or_default(), self.cfg.recovery_max_chunk),
        );
        let msg = MOSDECSubOpRead {
            pgid: SpgT {
                pgid: self.spg.pgid,
                shard: from.shard,
            },
            map_epoch: self.map.epoch(),
            op: sr,
            min_epoch: self.last_peering_reset,
            trace: [0; 3],
            cost: 1000,
        };
        let prio = self.recovery_message_priority();
        self.send_prio(from.osd, Body::Ec(ecwire::EcMsg::from(msg)), tid, prio);
        if let Some(op) = self.ep.recov.ops.get_mut(soid) {
            op.state = RecState::NeedOmap(Asked {
                tid,
                osd: from.osd,
                epoch: self.map.epoch(),
            });
        }
    }

    /// Mode O: build the omap batch of the next push round (spec ec-optimized.md 10.1) unless it is built or the omap
    /// is done. Entries after the last pushed key of the source (our shard's store, or the fetched pages of a source
    /// shard) under the net effect of the object's pending EC_OMAP records (`ecomap::Overlay`; applying a record twice
    /// is harmless, so the whole log history since the object was last created is used), at most
    /// `recovery_max_omap_entries` and about `budget` bytes, at least one entry. `Ok(false)`: a source page was
    /// requested first (or the source is gone and the object failed).
    fn ec_recov_omap_prepare(
        &mut self,
        soid: &Hobject,
        budget: u64,
        store: &impl PgStoreOps,
    ) -> Result<bool, &'static str> {
        let wanted = self
            .ep
            .recov
            .ops
            .get(soid)
            .and_then(|o| o.omap.as_ref())
            .is_some_and(|o| !o.done && o.batch.is_none());
        if !wanted {
            return Ok(true);
        }
        let recs =
            crate::ecomap::pending(self.log.entries(), soid).ok_or("omap records unreadable")?;
        let ov = crate::ecomap::Overlay::of(&recs);
        let (spg, max) = (self.spg, self.cfg.recovery_max_omap_entries.max(1));
        let max_bytes = usize::try_from(budget).unwrap_or(usize::MAX);
        let Some(op) = self.ep.recov.ops.get_mut(soid) else {
            return Ok(true);
        };
        let first = op.first;
        let Some(om) = op.omap.as_mut() else {
            return Ok(true);
        };
        let fetch = loop {
            if let Some(src) = &om.src
                && src.buf.is_empty()
                && !src.done
            {
                break Some((src.from, src.cursor.clone()));
            }
            let (mut rows, mut more) = match &om.src {
                Some(src) => ov.range(
                    |after, n| {
                        let lo =
                            after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
                        let mut it = src.buf.range::<[u8], _>((lo, std::ops::Bound::Unbounded));
                        let v: Vec<_> = it
                            .by_ref()
                            .take(n)
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect();
                        Ok((v, it.next().is_some()))
                    },
                    om.after.as_deref(),
                    b"",
                    max,
                    max_bytes,
                ),
                None => ov.range(
                    |after, n| match store.ec_omap_read(spg, soid, after, budget, n) {
                        Ok((v, done)) => Ok((v, !done)),
                        Err(-2) => Ok((Vec::new(), false)),
                        Err(e) => Err(e),
                    },
                    om.after.as_deref(),
                    b"",
                    max,
                    max_bytes,
                ),
            }
            .map_err(|_| "omap unreadable")?;
            if let Some(src) = om.src.as_mut().filter(|s| !s.done) {
                // only the fetched range is known: entries past its last key wait for the next page
                let keep =
                    rows.partition_point(|(k, _)| src.cursor.as_ref().is_some_and(|c| k <= c));
                if keep == 0 {
                    // nothing of the fetched range survives the pending records
                    om.after.clone_from(&src.cursor);
                    src.buf.clear();
                    continue;
                }
                rows.truncate(keep);
                more = true;
            }
            let header = if !first {
                None
            } else if let Some(src) = &om.src {
                Some(ov.header(src.header.clone()))
            } else if ov.cleared() {
                Some(ov.header(Vec::new()))
            } else {
                match store.ec_omap_header(spg, soid) {
                    Ok(h) => Some(ov.header(h)),
                    Err(-2) => Some(ov.header(Vec::new())),
                    Err(_) => return Err("local omap header unreadable"),
                }
            };
            let after = rows
                .last()
                .map(|(k, _)| k.clone())
                .or_else(|| om.after.clone());
            om.batch = Some(OmapBatch {
                header,
                entries: rows.into_iter().collect(),
                after,
                done: !more,
            });
            break None;
        };
        if let Some((from, cursor)) = fetch {
            self.ec_recov_omap_fetch(soid, from, cursor);
            return Ok(false);
        }
        Ok(true)
    }

    /// Start the next push round: its omap batch (mode O), then the read of its chunk of whole stripes; a round past the
    /// data (a 0-byte object, or omap left after the last stripe) pushes no data.
    fn ec_recov_chunk(&mut self, soid: &Hobject, store: &impl PgStoreOps) {
        let Some(be) = self.ecb().cloned() else {
            return;
        };
        let Some(op) = self.ep.recov.ops.get(soid) else {
            return;
        };
        let per = rec_stripes(self.cfg.recovery_max_chunk, be.s);
        let s0 = op.next_stripe;
        let s1 = (s0 + per).min(op.nstripes);
        // one recovery chunk per round, data first, the rest for omap (at least one entry)
        let data = ((s1 - s0) * be.s).min(op.size.saturating_sub(s0 * be.s));
        match self.ec_recov_omap_prepare(
            soid,
            self.cfg.recovery_max_chunk.saturating_sub(data),
            store,
        ) {
            Ok(true) => {}
            Ok(false) => return,
            Err(why) => return self.ec_recov_fail(soid, why),
        }
        let Some(op) = self.ep.recov.ops.get_mut(soid) else {
            return;
        };
        if s0 >= op.nstripes {
            return self.ec_recov_push(soid.clone(), Vec::new(), store);
        }
        op.state = RecState::Reading;
        // clay, one lost shard: sub-chunk repair reads (fewer bytes than decoding whole chunks)
        if be.sub_chunks() > 1 && !op.no_repair && op.targets.len() == 1 {
            let lost = op.targets[0].0.shard.0 as u32;
            if self.ec_repair_begin(soid, (s0, s1), lost, store) {
                return;
            }
        }
        let raw: Vec<usize> = (0..be.k).collect();
        if self
            .ec_read_begin(
                Purpose::Recov,
                soid.clone(),
                (s0 * be.s, s1 * be.s),
                raw,
                store,
            )
            .is_err()
        {
            let why = format!(
                "not enough shards to decode (usable {:?}, missing on {:?}, backfill {:?}, up {:?})",
                self.ec_sources(soid).0,
                self.prim
                    .peer_missing
                    .iter()
                    .filter(|(_, m)| m.contains(soid))
                    .map(|(p, _)| p.osd)
                    .collect::<Vec<_>>(),
                self.prim
                    .backfill_targets
                    .iter()
                    .map(|p| p.osd)
                    .collect::<Vec<_>>(),
                self.acting
            );
            self.ec_recov_fail(soid, &why);
        }
    }

    /// Is read `id` the one the recovery op of `soid` waits for? A read is tied to its op by id: one that `cancel_inflight`
    /// left running (deferred / preempted recovery) can finish after a new op of the same object started, even over the
    /// same stripes (the object may have changed meanwhile), and must not be taken for that op's chunk. Consumes the id.
    fn ec_recov_reads(&mut self, soid: &Hobject, id: u64) -> bool {
        let ok = match self.ep.recov.ops.get_mut(soid) {
            Some(o) if o.state == RecState::Reading && o.read == Some(id) => {
                o.read = None;
                true
            }
            _ => false,
        };
        if !ok {
            self.discard("ec recovery read of a cancelled op");
        }
        ok
    }

    /// The chunk read `id` finished (`Purpose::Recov`).
    pub(crate) fn ec_recov_read_done(
        &mut self,
        soid: Hobject,
        id: u64,
        r: Result<Vec<u8>, i32>,
        store: &impl PgStoreOps,
    ) {
        if !self.ec_recov_reads(&soid, id) {
            return;
        }
        match r {
            Ok(logical) => self.ec_recov_push(soid, logical, store),
            Err(_) => self.ec_recov_fail(&soid, "decode read failed"),
        }
    }

    /// Re-encode `logical` (whole stripes of the current chunk) and deliver one chunk to every target.
    fn ec_recov_push(&mut self, soid: Hobject, logical: Vec<u8>, store: &impl PgStoreOps) {
        let Some(be) = self.ecb().cloned() else {
            return;
        };
        let bufs = if logical.is_empty() {
            vec![Vec::new(); be.n()]
        } else {
            be.encode_stripes(&logical)
        };
        let nstr = (logical.len() as u64) / be.s;
        self.ec_recov_push_bufs(soid, bufs, nstr, store);
    }

    /// A clay repair read finished: the lost shard's chunks of the current span (`Err`: whole-chunk reads next).
    pub(crate) fn ec_recov_repair_done(
        &mut self,
        soid: Hobject,
        lost: u32,
        id: u64,
        r: Result<Vec<u8>, i32>,
        store: &impl PgStoreOps,
    ) {
        if !self.ec_recov_reads(&soid, id) {
            return;
        }
        let Some(be) = self.ecb().cloned() else {
            return;
        };
        match r {
            Ok(chunks) => {
                let mut bufs = vec![Vec::new(); be.n()];
                let nstr = chunks.len() as u64 / be.c;
                bufs[lost as usize] = chunks;
                self.ec_recov_push_bufs(soid, bufs, nstr, store);
            }
            Err(_) => {
                if let Some(op) = self.ep.recov.ops.get_mut(&soid) {
                    op.no_repair = true;
                }
                self.ec_recov_chunk(&soid, store);
            }
        }
    }

    /// Deliver `nstr` stripes of per-shard chunk bytes to every target.
    fn ec_recov_push_bufs(
        &mut self,
        soid: Hobject,
        bufs: Vec<Vec<u8>>,
        nstr: u64,
        store: &impl PgStoreOps,
    ) {
        let Some(be) = self.ecb().cloned() else {
            return;
        };
        // one buffer per shard, shared by every target holding that shard id (moving a `Vec` into `Bytes` does not copy;
        // a per-target truncation below is a slice of it)
        let bufs: Vec<bytes::Bytes> = bufs.into_iter().map(bytes::Bytes::from).collect();
        let Some(op) = self.ep.recov.ops.get_mut(&soid) else {
            return;
        };
        let (s0, s1) = (op.next_stripe, op.next_stripe + nstr);
        let (omap_before, omap_was_done) = op.omap.as_ref().map_or((Vec::new(), true), |o| {
            (o.after.clone().unwrap_or_default(), o.done)
        });
        // commit the round's omap batch: the cursor moves past it, the source keeps only what follows
        let batch = op.omap.as_mut().and_then(|o| {
            let b = o.batch.take()?;
            o.after.clone_from(&b.after);
            o.done = b.done;
            o.keys += b.entries.len() as u64;
            if let (Some(src), Some(a)) = (o.src.as_mut(), &b.after) {
                src.buf.retain(|k, _| k > a);
            }
            Some(b)
        });
        let (omap_after, omap_done, omap_keys) =
            op.omap.as_ref().map_or((Vec::new(), true, 0), |o| {
                (o.after.clone().unwrap_or_default(), o.done, o.keys)
            });
        let before = ObjectRecoveryProgress {
            first: op.first,
            data_complete: !op.first && s0 >= op.nstripes,
            data_recovered_to: (s0 * be.s).min(op.size),
            omap_recovered_to: omap_before,
            omap_complete: omap_was_done,
        };
        let after = ObjectRecoveryProgress {
            first: false,
            data_complete: s1 >= op.nstripes,
            data_recovered_to: (s1 * be.s).min(op.size),
            omap_recovered_to: omap_after,
            omap_complete: omap_done,
        };
        let op_size = op.size;
        let attrs_all = op.attrs.clone();
        let first = op.first;
        let attrs = if first {
            op.attrs.clone()
        } else {
            BTreeMap::new()
        };
        let targets = op.targets.clone();
        let (version, mut ri) = (op.version, op.ri.clone());
        ri.num_omap_keys = omap_keys;
        op.first = false;
        op.next_stripe = s1;
        let opt = self
            .pool
            .ec
            .as_ref()
            .filter(|e| e.supported && e.optimized)
            .cloned();
        let oi: Option<replwire::ObjectInfo> = opt.as_ref().and_then(|_| {
            attrs_all
                .get(b"_".as_slice())
                .and_then(|b| denc::from_slice::<replwire::ObjectInfo>(b).ok())
        });
        let mut waiting: BTreeSet<PgShard> = BTreeSet::new();
        for (t, exists) in &targets {
            let sh = t.shard.0 as usize;
            let mut data = bufs[sh].clone();
            let mut attrs = attrs.clone();
            let mut version = version;
            if let Some(e) = &opt {
                // mode O (prim D.2): per-shard size, NP targets get only `_` at their shard version, no hinfo
                let raw = e
                    .chunk_mapping
                    .iter()
                    .position(|x| *x as usize == sh)
                    .unwrap_or(sh) as u32;
                let lim = ec::geom::opt_shard_size(
                    op_size,
                    u64::from(e.stripe_width),
                    u64::from(e.chunk_size),
                    e.k,
                    raw,
                );
                let keep = lim.saturating_sub(s0 * be.c).min(data.len() as u64) as usize;
                data.truncate(keep);
                attrs.remove(ec::HINFO_KEY.as_bytes());
                if let Some(oi) = &oi {
                    version = ecback::version_for_shard(oi, sh as u32);
                    if e.is_nonprimary(sh as u32) && first {
                        // current shard: the OI bytes unchanged; stale shard: OI at its version, no shard_versions
                        let mut o = oi.clone();
                        if version == oi.version {
                            attrs = attrs_all
                                .get(b"_".as_slice())
                                .map(|b| BTreeMap::from([(b"_".to_vec(), b.clone())]))
                                .unwrap_or_default();
                        } else {
                            o.version = version;
                            o.shard_versions.clear();
                            attrs = BTreeMap::from([(
                                b"_".to_vec(),
                                denc::to_vec(&o).unwrap_or_default(),
                            )]);
                        }
                    }
                }
            }
            // primary-capable targets only (a nonprimary shard holds no omap)
            let pc_omap = batch
                .as_ref()
                .filter(|_| !opt.as_ref().is_some_and(|e| e.is_nonprimary(sh as u32)));
            let mut ri = ri.clone();
            ri.object_exist = *exists;
            let included = if data.is_empty() {
                BTreeMap::new()
            } else {
                BTreeMap::from([(s0 * be.c, data.len() as u64)])
            };
            let push = PushOp {
                soid: soid.clone(),
                version,
                data,
                data_included: included,
                omap_header: pc_omap.and_then(|o| o.header.clone()).unwrap_or_default(),
                omap_entries: pc_omap.map(|o| o.entries.clone()).unwrap_or_default(),
                attrset: attrs.clone(),
                recovery_info: ri,
                after_progress: after.clone(),
                before_progress: before.clone(),
            };
            if *t == self.me {
                self.ec_recov_apply_local(&push);
            } else {
                let cost = push.cost(1000);
                let m = MOSDPGPush {
                    pgid: SpgT {
                        pgid: self.spg.pgid,
                        shard: t.shard,
                    },
                    map_epoch: self.map.epoch(),
                    pushes: vec![push],
                    cost,
                    from: self.me,
                    min_epoch: self.last_peering_reset,
                    is_repair: false,
                };
                self.send_repl(t.osd, m, 0);
                waiting.insert(*t);
            }
        }
        if waiting.is_empty() {
            self.ec_recov_chunk_acked(&soid, store);
        } else if let Some(op) = self.ep.recov.ops.get_mut(&soid) {
            op.state = RecState::Pushing(waiting);
        }
    }

    /// Our own shard gets its chunk (we missed the object): the same apply as a push target.
    fn ec_recov_apply_local(&mut self, op: &PushOp) {
        // the local shard (object_info, size) changes outside the write pipeline: no decoded read of the old state survives
        self.ec_invalidate(&op.soid);
        let bytes = match self.push_txn_ec(op) {
            Ok(b) => b,
            Err(why) => {
                self.error("ec recovery: rebuilt local shard fails its hinfo hash");
                self.ec_recov_fail(&op.soid, &format!("rebuilt shard rejected: {why}"));
                return;
            }
        };
        self.txn.push(StoreOp::ApplyTxn {
            middle: bytes::Bytes::new(),
            data: bytes.into(),
        });
        if op.after_progress.data_complete && op.after_progress.omap_complete {
            let got_v = op.recovery_info.version.max(op.version);
            self.missing.got(&op.soid, got_v);
            self.mark_applying(&op.soid);
            let to = got_v.min(self.log.head());
            if to > self.log.log.can_rollback_to {
                self.ec_roll_forward_to(to);
            }
            if crate::snaps::is_clone(&op.soid) {
                self.txn.push(StoreOp::SnapMap(crate::snaps::push_ops(
                    &op.soid,
                    &op.recovery_info.ss,
                )));
            }
        }
        recompute_last_complete(&self.log, &mut self.info, &self.missing);
        self.info_dirty = true;
        self.flush(Pending::Plain);
    }

    /// Every push of the chunk was acked (or there were none): next chunk, or finished.
    fn ec_recov_chunk_acked(&mut self, soid: &Hobject, store: &impl PgStoreOps) {
        let Some(op) = self.ep.recov.ops.get(soid) else {
            return;
        };
        if op.next_stripe < op.nstripes || op.omap.as_ref().is_some_and(|o| !o.done) {
            return self.ec_recov_chunk(soid, store);
        }
        let Some(op) = self.ep.recov.ops.remove(soid) else {
            return;
        };
        self.ep.recov.failed.remove(soid);
        // once per object: its logical size and the omap entries recovery read (spec pg-io-stats.md 2)
        self.object_recovered(crate::recovery::RecStat {
            bytes: op.size,
            keys: op.omap.as_ref().map_or(0, |o| o.keys),
        });
        for (p, _) in &op.targets {
            if *p == self.me {
                continue;
            }
            self.backfill_push_done(*p, soid);
            if let Some(pm) = self.prim.peer_missing.get_mut(p) {
                pm.got(soid, op.version);
                let empty = pm.is_empty();
                if let Some(i) = self.prim.peer_info.get_mut(p)
                    && empty
                {
                    i.last_complete = i.last_update;
                }
            }
        }
        // targets that joined while the chunks were already out get their own pass
        if !op.joiners.is_empty() {
            self.ec_recov_start(soid.clone(), op.version, op.joiners, store);
        }
    }

    /// A target acked a push chunk.
    pub(crate) fn ec_on_push_reply(
        &mut self,
        from: i32,
        m: MOSDPGPushReply,
        store: &impl PgStoreOps,
    ) {
        let from = PgShard {
            osd: from,
            shard: m.from.shard,
        };
        for r in m.replies {
            let Some(op) = self.ep.recov.ops.get_mut(&r.soid) else {
                self.discard("push reply for unknown push");
                continue;
            };
            let done = match &mut op.state {
                RecState::Pushing(w) => {
                    w.remove(&from);
                    w.is_empty()
                }
                _ => {
                    self.discard("push reply for a recovery not pushing");
                    false
                }
            };
            if done {
                self.ec_recov_chunk_acked(&r.soid, store);
            }
        }
    }
}

#[cfg(test)]
mod recov_tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use crate::store::{MemObj, StoreTxn};
    use crate::{Config, MemStore};
    use denc::types::{PgT, SnapId};
    use pgwire::{PgInfo, PoolParams};
    use replwire::ReplMsg;
    use std::rc::Rc;
    use std::sync::Arc;

    /// Acting primary (osd.0, shard 0) of a 2+1 isa pool, Recovering; `optimized` = mode O pool with omap.
    fn pg_with(optimized: bool) -> Pg {
        let mut map = SynthMap::new(5)
            .with_osd(0, 1)
            .with_osd(1, 1)
            .with_osd(2, 1);
        let ec = pgwire::EcPoolInfo {
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
            optimized,
            omap: optimized,
            nonprimary: if optimized { vec![1] } else { Vec::new() },
            ..Default::default()
        };
        map.pools.insert(
            1,
            PoolParams {
                size: 3,
                min_size: 2,
                pg_num: 1,
                pg_num_pending: 1,
                is_erasure: true,
                ec_k: 2,
                ec: Some(Arc::new(ec)),
                ..Default::default()
            },
        );
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId(0),
        };
        let mut pg = Pg::blank(
            Arc::new(Config::new(0)),
            spg,
            Rc::new(map),
            PgInfo::new(spg),
        );
        pg.acting = vec![0, 1, 2];
        pg.up = vec![0, 1, 2];
        pg.acting_primary = 0;
        pg.up_primary = 0;
        pg.refresh_ecb();
        assert!(pg.ecb().is_some(), "code available");
        pg.st = St::Primary(PSt::Active(ASt::Recovering));
        pg
    }

    fn pg() -> Pg {
        pg_with(false)
    }

    /// A failed attempt's cooldown must become a single wake, not an expired timer
    /// that runs the PG on every core iteration while the new push waits for its ack.
    #[test]
    fn recovery_retry_deadline_is_consumed_when_work_restarts() {
        let mut pg = pg();
        let mut cfg = (*pg.cfg).clone();
        cfg.stats_interval = 0;
        pg.cfg = Arc::new(cfg);
        pg.rec.cap = 2;
        pg.now = SEC;
        all_members(&mut pg);
        let soid = Hobject::new(b"retry", SnapId::NOSNAP, 7, 1, b"");
        let v = Eversion::new(4, 1);
        let peer = PgShard {
            osd: 1,
            shard: ShardId(1),
        };
        pg.prim.peer_missing.entry(peer).or_default().add(
            soid.clone(),
            v,
            Eversion::default(),
            false,
        );
        let mut store = store_of(&pg);
        // Unreadable local attributes fail the first attempt, with a future retry.
        pg.ec_recov_start(soid.clone(), v, vec![(peer, false)], &store);
        let retry = pg.now + RETRY;
        assert_eq!(pg.next_deadline(), Some(retry));
        // With nothing in flight and no wish, the core's lease takes the units back
        // (`OpsLease::sync`): the cooldown alone must still wake the recovery pass.
        pg.rec.cap = 0;
        assert_eq!(
            pg.next_deadline(),
            Some(retry),
            "idle PG keeps its retry wake"
        );
        pg.tick(retry, &store);
        assert!(pg.rec.wants, "the pass at cap 0 asks for units");
        assert!(
            pg.next_deadline().is_none_or(|d| d > retry),
            "the lease grant owns the wake"
        );
        let oi = replwire::ObjectInfo {
            version: v,
            ..Default::default()
        };
        store
            .pgs
            .get_mut(&pg.spg)
            .unwrap()
            .objects
            .insert(soid.clone(), memobj(&oi, &[]));
        // The grant starts the push, but its acknowledgement has not arrived.
        pg.rec.cap = 2;
        pg.rec.wants = false;
        pg.rec_kick(retry, &store);
        assert!(matches!(pg.ep.recov.ops[&soid].state, RecState::Pushing(_)));
        let due_visits = (0..1024)
            .filter(|_| pg.next_deadline().is_some_and(|d| d <= retry))
            .count();
        assert_eq!(
            due_visits, 0,
            "no repeated due-PG visits while waiting for a reply"
        );
        assert!(!pg.ep.recov.failed.contains_key(&soid));
    }

    /// Cooldowns retained across cancellation cannot schedule work while slots or
    /// a reservation are unavailable. The sleep cadence owns the wake while paced.
    #[test]
    fn recovery_retry_deadline_waits_for_its_scheduler() {
        let mut pg = pg();
        let mut cfg = (*pg.cfg).clone();
        cfg.stats_interval = 0;
        cfg.recovery_sleep = SEC;
        cfg.recovery_sleep_degraded = SEC;
        pg.cfg = Arc::new(cfg);
        pg.now = SEC;
        pg.rec.cap = 1;
        let soid = Hobject::new(b"retry", SnapId::NOSNAP, 7, 1, b"");
        all_members(&mut pg);
        pg.prim
            .peer_missing
            .entry(PgShard {
                osd: 1,
                shard: ShardId(1),
            })
            .or_default()
            .add(
                soid.clone(),
                Eversion::new(4, 1),
                Eversion::default(),
                false,
            );
        pg.prim
            .peer_missing
            .entry(PgShard {
                osd: 2,
                shard: ShardId(2),
            })
            .or_default();
        pg.ep.recov.failed.insert(soid.clone(), 2 * SEC);
        for state in [
            ASt::WaitLocalRecoveryReserved,
            ASt::WaitRemoteRecoveryReserved,
            ASt::NotRecovering,
            ASt::Backfilling,
            ASt::Recovered,
        ] {
            pg.st = St::Primary(PSt::Active(state));
            assert!(
                pg.next_deadline().is_none_or(|at| at > 2 * SEC),
                "state {state:?}"
            );
        }
        pg.st = St::Primary(PSt::Active(ASt::Recovering));
        pg.rec.cap = 0;
        pg.rec.wants = true;
        assert!(
            pg.next_deadline().is_none_or(|at| at > 2 * SEC),
            "the lease grant owns the wake"
        );
        pg.rec.wants = false;
        assert!(
            pg.next_deadline().is_some_and(|at| at <= 2 * SEC),
            "an idle PG without a lease wakes on its cooldown"
        );
        pg.rec.cap = 1;
        pg.cfg
            .rec_sched
            .store(3 * SEC, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            pg.next_deadline(),
            Some(3 * SEC),
            "sleep wins over cooldown"
        );
        pg.prim.peer_missing.clear();
        assert!(
            pg.next_deadline().is_none_or(|at| at > 3 * SEC),
            "removed work has no retry wake"
        );
    }

    /// Micro bench (`cargo test -p peering --release ec_recovery_step_cost -- --ignored --nocapture`): ns per
    /// `ec_recovery_step` event at the cap with 100k objects missing on a peer.
    #[test]
    #[ignore = "micro bench"]
    fn ec_recovery_step_cost_with_a_large_peer_missing_set() {
        let mut pg = pg();
        all_members(&mut pg);
        let pm = pg
            .prim
            .peer_missing
            .entry(PgShard {
                osd: 1,
                shard: ShardId(1),
            })
            .or_default();
        for n in 0..100_000u64 {
            let oid = Hobject::new(format!("o{n:06}").as_bytes(), SnapId::NOSNAP, 7, 1, b"");
            pm.add(oid, Eversion::new(4, 1), Eversion::default(), false);
        }
        let store = store_of(&pg);
        pg.rec.cap = 0;
        let t = std::time::Instant::now();
        for _ in 0..20 {
            pg.rec.wants = false;
            pg.ec_recovery_step(&store);
            assert!(pg.rec.wants);
        }
        eprintln!("at cap: {} ns/event", t.elapsed().as_nanos() / 20);
    }

    /// One object of the PG's collection with its `_` (object_info) attribute.
    fn memobj(oi: &replwire::ObjectInfo, xattrs: &[(&[u8], Vec<u8>)]) -> MemObj {
        let mut a = BTreeMap::from([(b"_".to_vec(), denc::to_vec(oi).unwrap())]);
        for (k, v) in xattrs {
            a.insert(k.to_vec(), v.clone());
        }
        MemObj {
            data: vec![0u8; oi.size as usize],
            xattrs: a,
            omap: BTreeMap::new(),
            omap_header: Vec::new(),
        }
    }

    /// A store holding the PG (and whatever the test puts into it).
    fn store_of(pg: &Pg) -> MemStore {
        let mut store = MemStore::new();
        store.submit(
            pg.spg,
            &StoreTxn {
                ops: vec![StoreOp::CreatePg],
            },
        );
        store
    }

    fn op(state: RecState) -> RecOp {
        RecOp {
            version: Eversion::new(4, 1),
            size: 0,
            attrs: BTreeMap::new(),
            ri: ObjectRecoveryInfo::default(),
            targets: vec![(
                PgShard {
                    osd: 0,
                    shard: ShardId(0),
                },
                false,
            )],
            next_stripe: 0,
            nstripes: 0,
            first: true,
            state,
            joiners: Vec::new(),
            omap: None,
            no_repair: false,
            read: None,
        }
    }

    /// A recovery deferred while its chunk read was in flight (`cancel_inflight` drops the op, not the read) and started
    /// again for the same object: the late read must not be taken as the new op's chunk. Here the new op still waits
    /// for the attributes of a source (size 0, no object_info): taking the stripes would install them as the complete
    /// object without attributes and mark it recovered.
    #[test]
    fn a_late_read_of_a_cancelled_recovery_is_not_the_new_ops_chunk() {
        let mut pg = pg();
        let store = MemStore::new();
        let soid = Hobject::new(b"obj", SnapId::NOSNAP, 7, 1, b"");
        let v = Eversion::new(4, 1);
        pg.missing.add(soid.clone(), v, Eversion::default(), false);
        let asked = Asked {
            tid: 9,
            osd: 1,
            epoch: 5,
        };
        pg.ep
            .recov
            .ops
            .insert(soid.clone(), op(RecState::NeedAttrs(asked)));
        // the old op's read #2
        pg.ec_recov_read_done(soid.clone(), 2, Ok(vec![7u8; 2 * 8192]), &store);
        assert!(pg.missing.contains(&soid), "not recovered by a stale read");
        assert!(
            !pg.txn.iter().any(|o| matches!(o, StoreOp::ApplyTxn { .. })),
            "nothing applied"
        );
        assert_eq!(pg.ep.recov.ops[&soid].state, RecState::NeedAttrs(asked));
        // the new op reads the same span (object changed meanwhile) with its own read #3: the old read and a late error
        // of it are no replies to it
        {
            let o = pg.ep.recov.ops.get_mut(&soid).unwrap();
            o.state = RecState::Reading;
            o.read = Some(3);
        }
        pg.ec_recov_read_done(soid.clone(), 2, Ok(vec![7u8; 2 * 8192]), &store);
        pg.ec_recov_read_done(soid.clone(), 2, Err(5), &store);
        pg.ec_recov_repair_done(soid.clone(), 0, 2, Ok(vec![7u8; 4096]), &store);
        assert_eq!(pg.ep.recov.ops[&soid].state, RecState::Reading);
        assert_eq!(pg.ep.recov.ops[&soid].read, Some(3));
        assert!(pg.missing.contains(&soid));
        // its own read is taken, once
        pg.ec_recov_read_done(soid.clone(), 3, Err(5), &store);
        assert!(pg.ep.recov.ops.get(&soid).is_none_or(|o| o.read != Some(3)));
    }

    /// A local copy whose recovery info does not decode (here a clone whose head snapset is garbage) fails the object:
    /// a default `ObjectRecoveryInfo` would push an empty snap set and recovery would install a wrong snap mapping.
    #[test]
    fn a_corrupt_local_recovery_info_fails_the_object() {
        let mut pg = pg();
        let mut store = store_of(&pg);
        let v = Eversion::new(4, 1);
        let head = Hobject::new(b"obj", SnapId::NOSNAP, 7, 1, b"");
        let clone = Hobject::new(b"obj", SnapId(3), 7, 1, b"");
        let oi = replwire::ObjectInfo {
            version: v,
            size: 0,
            ..Default::default()
        };
        let p = store.pgs.get_mut(&pg.spg).unwrap();
        p.objects
            .insert(head.clone(), memobj(&oi, &[(b"snapset", vec![0xff; 16])]));
        p.objects.insert(clone.clone(), memobj(&oi, &[]));
        // the peer shard 1 needs this object: our shard is current, so the push is built from the local copy
        let peer = PgShard {
            osd: 1,
            shard: ShardId(1),
        };
        pg.ec_recov_start(clone.clone(), v, vec![(peer, false)], &store);
        assert!(
            pg.ep.recov.ops.is_empty(),
            "a damaged local copy is not pushed"
        );
        assert!(
            !pg.out.iter().any(|a| matches!(a, Action::Send(s)
                if matches!(&s.body, Body::Repl(ReplMsg::Push(_))))),
            "no push for a damaged local copy"
        );
        assert!(
            pg.ep.recov.failed.contains_key(&clone),
            "retried, not silently recovered"
        );
        assert_eq!(
            pg.counters.errors.get("ec recovery failed").copied(),
            Some(1)
        );
    }

    /// A clone we miss is rebuilt from the shards; its snap mapper entry (here and on every target) comes from the
    /// SnapSet pushed with it, which only the head holds. A default SnapSet maps no snap: snap trimming would never find
    /// the clone (space leak, the snapshot data stays forever). The head's SnapSet travels with the push; while our head
    /// is missing too the clone waits for it.
    #[test]
    fn a_rebuilt_clone_carries_its_heads_snapset() {
        let mut pg = pg();
        all_members(&mut pg);
        let mut store = store_of(&pg);
        let v = Eversion::new(4, 2);
        let head = Hobject::new(b"snapped", SnapId::NOSNAP, 7, 1, b"");
        let clone = Hobject::new(b"snapped", SnapId(3), 7, 1, b"");
        let ss = replwire::SnapSet {
            seq: 5,
            clones: vec![SnapId(3)],
            clone_snaps: BTreeMap::from([(SnapId(3), vec![SnapId(3), SnapId(2)])]),
            ..Default::default()
        };
        let hoi = replwire::ObjectInfo {
            version: Eversion::new(4, 3),
            size: 0,
            ..Default::default()
        };
        store.pgs.get_mut(&pg.spg).unwrap().objects.insert(
            head.clone(),
            memobj(&hoi, &[(b"snapset", denc::to_vec(&ss).unwrap())]),
        );
        pg.missing.add(clone.clone(), v, Eversion::default(), false);
        let coi = replwire::ObjectInfo {
            version: v,
            size: 0,
            ..Default::default()
        };
        let me = pg.me;
        let pc = PgShard {
            osd: 2,
            shard: ShardId(2),
        };
        pg.ec_recov_start(clone.clone(), v, vec![(me, false), (pc, false)], &store);
        let (pushes, _) = drive(&mut pg, &store, &clone, Some((&coi, b"", &BTreeMap::new())));
        assert!(!pg.missing.contains(&clone), "{:?}", pg.notes);
        let snaps = pushes
            .iter()
            .map(|(_, p)| p.recovery_info.ss.clone_snaps.clone())
            .next()
            .expect("a push");
        assert_eq!(snaps, ss.clone_snaps, "the push maps the clone's snaps");
    }

    /// Our head is missing too: its SnapSet is stale or absent, the clone waits until the head is recovered.
    #[test]
    fn a_clone_waits_for_the_missing_head_of_the_primary() {
        let mut pg = pg();
        all_members(&mut pg);
        let store = store_of(&pg);
        let v = Eversion::new(4, 2);
        let head = Hobject::new(b"snapped", SnapId::NOSNAP, 7, 1, b"");
        let clone = Hobject::new(b"snapped", SnapId(3), 7, 1, b"");
        pg.missing.add(clone.clone(), v, Eversion::default(), false);
        pg.missing.add(
            head.clone(),
            Eversion::new(4, 3),
            Eversion::default(),
            false,
        );
        pg.rec.cap = 8;
        pg.ec_recovery_step(&store);
        assert!(
            !pg.ep.recov.ops.contains_key(&clone),
            "the clone is rebuilt before its head"
        );
        assert!(pg.ep.recov.ops.contains_key(&head), "the head goes first");
    }

    /// Drive the recovery of `soid` to its end: chunk reads are answered with zeros, attribute / omap sub-reads from
    /// `src` (`oi`, header, entries; paged as a source shard serves them), every push with its ack. Returns the pushes
    /// (target, op) in order and the start keys of the omap sub-reads.
    #[expect(clippy::type_complexity)]
    fn drive(
        pg: &mut Pg,
        store: &MemStore,
        soid: &Hobject,
        src: Option<(&replwire::ObjectInfo, &[u8], &BTreeMap<Vec<u8>, Vec<u8>>)>,
    ) -> (Vec<(PgShard, PushOp)>, Vec<Vec<u8>>) {
        let (mut pushes, mut starts) = (Vec::new(), Vec::new());
        for _ in 0..10_000 {
            let Some(op) = pg.ep.recov.ops.get(soid) else {
                return (pushes, starts);
            };
            if op.state == RecState::Reading
                && let Some(id) = op.read
            {
                let s = pg.ecb().unwrap().s;
                let n = rec_stripes(pg.cfg.recovery_max_chunk, s).min(op.nstripes - op.next_stripe);
                pg.ec_recov_read_done(soid.clone(), id, Ok(vec![0; (n * s) as usize]), store);
                continue;
            }
            let mut acted = false;
            for a in std::mem::take(&mut pg.out) {
                let Action::Send(s) = a else {
                    continue;
                };
                if matches!(
                    s.body,
                    Body::Repl(ReplMsg::Push(_)) | Body::Ec(ecwire::EcMsg::Read(_))
                ) {
                    // NT-flags-04: recovery pushes and sub-reads carry the recovery class, never 127 ("immediate")
                    assert_eq!(s.prio, pg.recovery_message_priority(), "{:?}", s.body);
                }
                match s.body {
                    Body::Repl(ReplMsg::Push(m)) => {
                        let from = PgShard {
                            osd: s.to,
                            shard: m.pgid.shard,
                        };
                        pushes.extend(m.pushes.into_iter().map(|p| (from, p)));
                        let reply = MOSDPGPushReply {
                            pgid: m.pgid,
                            map_epoch: m.map_epoch,
                            replies: vec![replwire::PushReplyOp { soid: soid.clone() }],
                            cost: 0,
                            from,
                            min_epoch: m.min_epoch,
                        };
                        pg.ec_on_push_reply(s.to, reply, store);
                        acted = true;
                    }
                    Body::Ec(ecwire::EcMsg::Read(m))
                        if m.op.attrs_to_read.contains(soid)
                            || m.op.omap_read_from.contains_key(soid) =>
                    {
                        let (oi, hdr, kv) = src.expect("a source");
                        let mut r = ecwire::ECSubReadReply {
                            from: PgShard {
                                osd: s.to,
                                shard: m.pgid.shard,
                            },
                            tid: m.op.tid,
                            ..Default::default()
                        };
                        if m.op.attrs_to_read.contains(soid) {
                            let a = BTreeMap::from([(b"_".to_vec(), denc::to_vec(oi).unwrap())]);
                            r.attrs_read.insert(soid.clone(), a);
                        }
                        if m.op.omap_headers_to_read.contains(soid) {
                            r.omap_headers_read.insert(soid.clone(), hdr.to_vec());
                        }
                        if let Some((start, max_bytes)) = m.op.omap_read_from.get(soid) {
                            starts.push(start.clone());
                            let lo = crate::ecopt::omap_wire_after(start)
                                .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
                            let rest = kv
                                .range::<[u8], _>((lo, std::ops::Bound::Unbounded))
                                .map(|(k, v)| (k.clone(), v.clone()));
                            let (page, done) = crate::ecopt::omap_batch(
                                rest,
                                *max_bytes,
                                pg.cfg.recovery_max_omap_entries,
                            );
                            r.omap_entries_read
                                .insert(soid.clone(), page.into_iter().collect());
                            r.omaps_complete.insert(soid.clone(), done);
                        }
                        let reply = MOSDECSubOpReadReply {
                            pgid: pg.spg,
                            map_epoch: m.map_epoch,
                            op: r,
                            min_epoch: m.min_epoch,
                            trace: [0; 3],
                        };
                        assert!(pg.ec_recov_attrs(s.to, m.op.tid, reply, store));
                        acted = true;
                    }
                    _ => {}
                }
            }
            assert!(acted, "recovery of {soid:?} stalled");
        }
        panic!("recovery of {soid:?} did not finish");
    }

    /// Every shard of the PG is a recovery source (the tests keep no peer missing sets).
    fn all_members(pg: &mut Pg) {
        pg.prim.acting_recovery_backfill = (0..3)
            .map(|i| PgShard {
                osd: i,
                shard: ShardId(i as i8),
            })
            .collect();
    }

    /// `n` omap entries of 1 MiB each: together larger than one push (`osd_recovery_max_chunk` 8 MiB).
    fn big_omap(n: u32) -> BTreeMap<Vec<u8>, Vec<u8>> {
        (0..n)
            .map(|i| (format!("k{i:02}").into_bytes(), vec![0x5a; 1 << 20]))
            .collect()
    }

    /// Mode O, our shard is current: an omap larger than one push (here 40 MiB) streams in batches of about one recovery
    /// chunk, after the data; header in the first push, entries to primary-capable targets only, the same progress for
    /// every target, the object complete only with both data and omap (spec ec-optimized.md 10.1).
    #[test]
    fn recovery_streams_an_omap_larger_than_one_push() {
        let mut pg = pg_with(true);
        assert!(pg.ec_omap_ok(), "mode O pool with omap");
        all_members(&mut pg);
        let mut store = store_of(&pg);
        let soid = Hobject::new(b"large-omap", SnapId::NOSNAP, 7, 1, b"");
        let v = Eversion::new(4, 1);
        let oi = replwire::ObjectInfo {
            version: v,
            size: 3 * 8192,
            flags: replwire::oi::flag::OMAP,
            ..Default::default()
        };
        let omap = big_omap(40);
        let mut obj = memobj(&oi, &[]);
        obj.omap = omap.clone();
        obj.omap_header = b"hdr".to_vec();
        store
            .pgs
            .get_mut(&pg.spg)
            .unwrap()
            .objects
            .insert(soid.clone(), obj);
        let pc = PgShard {
            osd: 2,
            shard: ShardId(2),
        };
        let np = PgShard {
            osd: 1,
            shard: ShardId(1),
        };
        pg.ec_recov_start(soid.clone(), v, vec![(pc, false), (np, false)], &store);
        let (pushes, _) = drive(&mut pg, &store, &soid, None);
        assert!(
            !pg.ep.recov.failed.contains_key(&soid),
            "recovery failed: {:?}",
            pg.notes
        );
        let to = |t: PgShard| -> Vec<&PushOp> {
            pushes
                .iter()
                .filter(|(p, _)| *p == t)
                .map(|(_, o)| o)
                .collect()
        };
        let (pcs, nps) = (to(pc), to(np));
        assert!(pcs.len() >= 5, "{} pushes", pcs.len());
        assert_eq!(pcs.len(), nps.len());
        let mut got = BTreeMap::new();
        for (i, (a, b)) in pcs.iter().zip(&nps).enumerate() {
            assert_eq!(a.before_progress, b.before_progress, "push {i}");
            assert_eq!(a.after_progress, b.after_progress, "push {i}");
            assert!(
                b.omap_entries.is_empty() && b.omap_header.is_empty(),
                "NP push {i}"
            );
            let bytes: usize = a.omap_entries.iter().map(|(k, v)| k.len() + v.len()).sum();
            assert!(
                bytes <= (8 << 20) + (1 << 20) + 3,
                "push {i}: {bytes} omap bytes"
            );
            assert_eq!(a.before_progress.first, i == 0);
            assert_eq!(
                a.omap_header.is_empty(),
                i > 0,
                "header in the first push only"
            );
            let p = &a.after_progress;
            assert_eq!(
                p.data_complete && p.omap_complete,
                i + 1 == pcs.len(),
                "push {i}"
            );
            if i > 0 {
                assert_eq!(
                    a.before_progress.omap_recovered_to,
                    pcs[i - 1].after_progress.omap_recovered_to
                );
            }
            got.extend(a.omap_entries.clone());
        }
        let p0 = &pcs[0].after_progress;
        assert!(
            p0.data_complete && !p0.omap_complete,
            "data and omap complete independently"
        );
        assert_eq!(pcs[0].omap_header, b"hdr");
        assert_eq!(got, omap);
        assert_eq!(pg.info.stats.stats.sum.num_keys_recovered, 40);
    }

    /// Mode O, we miss the object: the source shard's omap arrives page by page with the push rounds (each page after the
    /// last key of the one before) and the pending EC_OMAP records of the object lay over it; a page that the records
    /// remove completely moves on to the next one, an inserted key past the fetched pages waits for them.
    #[test]
    fn recovery_from_a_source_shard_pages_its_omap_under_the_pending_records() {
        let mut pg = pg_with(true);
        all_members(&mut pg);
        let store = store_of(&pg);
        let soid = Hobject::new(b"large-omap", SnapId::NOSNAP, 7, 1, b"");
        let v = Eversion::new(4, 2);
        pg.missing.add(soid.clone(), v, Eversion::default(), false);
        let rec = |r: ec::moddesc::EcOmap| {
            let mut b = ec::moddesc::ModDescBuilder::new();
            b.ec_omap(&r);
            b.finish().0
        };
        let up = |n: u64, bl: Vec<u8>| pgwire::LogEntry {
            op: pgwire::LogOp::MODIFY,
            soid: soid.clone(),
            version: Eversion::new(4, n),
            mod_desc: pgwire::ObjectModDesc {
                bl,
                can_local_rollback: true,
                ..Default::default()
            },
            ..Default::default()
        };
        use ec::moddesc::{EcOmap, OmapUp};
        pg.log.append_keep(up(
            1,
            rec(EcOmap {
                clear: false,
                header: Some(b"new".to_vec()),
                ups: vec![
                    OmapUp::RemoveRange(b"k00".to_vec(), b"k10".to_vec()),
                    OmapUp::Remove(vec![b"k20".to_vec()]),
                ],
            }),
        ));
        pg.log.append_keep(up(
            2,
            rec(EcOmap {
                clear: false,
                header: None,
                ups: vec![OmapUp::Insert(vec![
                    (b"k15x".to_vec(), b"a".to_vec()),
                    (b"zz".to_vec(), b"b".to_vec()),
                ])],
            }),
        ));
        let oi = replwire::ObjectInfo {
            version: v,
            size: 0,
            flags: replwire::oi::flag::OMAP,
            ..Default::default()
        };
        let src = big_omap(40);
        let pc = PgShard {
            osd: 2,
            shard: ShardId(2),
        };
        // we and the source shard's position both miss it (the source serves its pages all the same)
        let me = pg.me;
        pg.ec_recov_start(soid.clone(), v, vec![(me, false), (pc, false)], &store);
        let (pushes, starts) = drive(&mut pg, &store, &soid, Some((&oi, b"old", &src)));
        assert!(!pg.missing.contains(&soid), "our shard recovered");
        assert!(pg.temps.is_empty(), "the temp object became the object");
        assert!(
            !pg.ep.recov.failed.contains_key(&soid),
            "recovery failed: {:?}",
            pg.notes
        );
        let mut want = src.clone();
        want.retain(|k, _| {
            !(k.as_slice() >= b"k00".as_slice() && k.as_slice() < b"k10".as_slice())
        });
        want.remove(b"k20".as_slice());
        want.insert(b"k15x".to_vec(), b"a".to_vec());
        want.insert(b"zz".to_vec(), b"b".to_vec());
        let mut got = BTreeMap::new();
        let mut last: Option<Vec<u8>> = None;
        for (_, p) in &pushes {
            for k in p.omap_entries.keys() {
                assert!(
                    last.as_ref().is_none_or(|l| l < k),
                    "ascending, each key once"
                );
                last = Some(k.clone());
            }
            got.extend(p.omap_entries.clone());
        }
        assert_eq!(got, want);
        assert_eq!(pushes[0].1.omap_header, b"new");
        let fin = &pushes.last().unwrap().1.after_progress;
        assert!(fin.data_complete && fin.omap_complete);
        // pages within 8 MiB (7 entries), each after the last key of the page before; the first page (all removed by
        // the records) is followed by the next one before any entry is pushed
        assert_eq!(
            starts,
            [b"".as_slice(), b"k06", b"k13", b"k20", b"k27", b"k34"]
                .map(<[u8]>::to_vec)
                .to_vec()
        );
        assert_eq!(
            pg.info.stats.stats.sum.num_keys_recovered,
            want.len() as i64
        );
    }

    /// Runs a recovery test on its own thread: a recovery that loops inside one call (the `drive` bound never sees it)
    /// fails loudly after `limit` instead of hanging the test run.
    fn bounded(
        name: &'static str,
        limit: std::time::Duration,
        f: impl FnOnce() + std::marker::Send + 'static,
    ) {
        let (tx, rx) = std::sync::mpsc::channel();
        let h = std::thread::spawn(move || {
            f();
            let _ = tx.send(());
        });
        match rx.recv_timeout(limit) {
            Ok(()) => h.join().unwrap(),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                std::panic::resume_unwind(h.join().unwrap_err())
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                eprintln!(
                    "WARNING TIMEOUT {name} exceeded {:.3}s (recovery loops without progress)",
                    limit.as_secs_f64()
                );
                panic!(
                    "{name}: recovery did not return within {}s",
                    limit.as_secs()
                );
            }
        }
    }

    /// Mode O pg whose recovery pushes at most `n` omap entries per round (`osd_recovery_max_omap_entries_per_chunk`).
    fn pg_omap_entries(n: usize) -> Pg {
        let mut pg = pg_with(true);
        let mut cfg = (*pg.cfg).clone();
        cfg.recovery_max_omap_entries = n;
        pg.cfg = Arc::new(cfg);
        all_members(&mut pg);
        pg
    }

    /// Store with our shard's copy of `soid` (`size` bytes, `omap`).
    fn store_with(
        pg: &Pg,
        soid: &Hobject,
        oi: &replwire::ObjectInfo,
        omap: &[(&[u8], &[u8])],
    ) -> MemStore {
        let mut store = store_of(pg);
        let mut obj = memobj(oi, &[]);
        obj.omap = omap.iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
        store
            .pgs
            .get_mut(&pg.spg)
            .unwrap()
            .objects
            .insert(soid.clone(), obj);
        store
    }

    /// Omap entries the pushes to `t` carry, checked ascending and each key once.
    fn pushed_omap(pushes: &[(PgShard, PushOp)], t: PgShard) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut got = BTreeMap::new();
        let mut last: Option<Vec<u8>> = None;
        for (_, p) in pushes.iter().filter(|(p, _)| *p == t) {
            for (k, v) in &p.omap_entries {
                assert!(
                    last.as_ref().is_none_or(|l| l < k),
                    "ascending, each key once"
                );
                last = Some(k.clone());
                got.insert(k.clone(), v.clone());
            }
        }
        got
    }

    const PC: PgShard = PgShard {
        osd: 2,
        shard: ShardId(2),
    };

    /// Mode O, our shard is current, the first round's data fills the whole recovery chunk (omap budget 0, one entry
    /// at least) and a pending EC_OMAP record removes the empty key: the local omap read after the empty key must start
    /// strictly after it, not from the first key again (an empty cursor read as "from the start" looped forever on the
    /// PG core before any push).
    #[test]
    fn recovery_after_a_removed_empty_omap_key_makes_progress() {
        bounded(
            "recovery_after_a_removed_empty_omap_key_makes_progress",
            std::time::Duration::from_secs(120),
            || {
                let mut pg = pg_with(true);
                all_members(&mut pg);
                let soid = Hobject::new(b"empty-key", SnapId::NOSNAP, 7, 1, b"");
                let v = Eversion::new(4, 1);
                let oi = replwire::ObjectInfo {
                    version: v,
                    size: pg.cfg.recovery_max_chunk,
                    flags: replwire::oi::flag::OMAP,
                    ..Default::default()
                };
                let store = store_with(&pg, &soid, &oi, &[(b"", b"v"), (b"a", b"v")]);
                let mut b = ec::moddesc::ModDescBuilder::new();
                b.ec_omap(&ec::moddesc::EcOmap {
                    clear: false,
                    header: None,
                    ups: vec![ec::moddesc::OmapUp::Remove(vec![Vec::new()])],
                });
                pg.log.append_keep(pgwire::LogEntry {
                    op: pgwire::LogOp::MODIFY,
                    soid: soid.clone(),
                    version: v,
                    mod_desc: pgwire::ObjectModDesc {
                        bl: b.finish().0,
                        can_local_rollback: true,
                        ..Default::default()
                    },
                    ..Default::default()
                });
                pg.ec_recov_start(soid.clone(), v, vec![(PC, false)], &store);
                let (pushes, _) = drive(&mut pg, &store, &soid, None);
                assert!(!pg.ep.recov.failed.contains_key(&soid), "{:?}", pg.notes);
                assert_eq!(
                    pushed_omap(&pushes, PC),
                    BTreeMap::from([(b"a".to_vec(), b"v".to_vec())])
                );
                let fin = &pushes.last().unwrap().1.after_progress;
                assert!(fin.data_complete && fin.omap_complete);
            },
        );
    }

    /// Mode O, one omap entry per round: the empty key is pushed once (from the first key) and the next round starts
    /// strictly after it, from our shard's store and from a source shard's pages alike (a source page that is not the
    /// last never ends at the empty key, the wire start key cannot say "after it").
    #[test]
    fn recovery_pushes_an_empty_omap_key_once() {
        bounded(
            "recovery_pushes_an_empty_omap_key_once",
            std::time::Duration::from_secs(120),
            || {
                let omap: [(&[u8], &[u8]); 3] = [(b"", b"e"), (b"a", b"1"), (b"b", b"2")];
                let want: BTreeMap<Vec<u8>, Vec<u8>> =
                    omap.iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
                let soid = Hobject::new(b"empty-key", SnapId::NOSNAP, 7, 1, b"");
                let v = Eversion::new(4, 1);
                let oi = replwire::ObjectInfo {
                    version: v,
                    size: 0,
                    flags: replwire::oi::flag::OMAP,
                    ..Default::default()
                };
                // our shard is the source
                let mut pg = pg_omap_entries(1);
                let store = store_with(&pg, &soid, &oi, &omap);
                pg.ec_recov_start(soid.clone(), v, vec![(PC, false)], &store);
                let (pushes, _) = drive(&mut pg, &store, &soid, None);
                assert!(!pg.ep.recov.failed.contains_key(&soid), "{:?}", pg.notes);
                assert_eq!(pushed_omap(&pushes, PC), want);
                // a source shard's pages
                let mut pg = pg_omap_entries(1);
                let store = store_of(&pg);
                pg.missing.add(soid.clone(), v, Eversion::default(), false);
                let me = pg.me;
                pg.ec_recov_start(soid.clone(), v, vec![(me, false), (PC, false)], &store);
                let (pushes, starts) = drive(&mut pg, &store, &soid, Some((&oi, b"", &want)));
                assert!(!pg.ep.recov.failed.contains_key(&soid), "{:?}", pg.notes);
                assert!(!pg.missing.contains(&soid), "our shard recovered");
                assert_eq!(pushed_omap(&pushes, PC), want);
                assert_eq!(starts, [b"".to_vec(), b"a".to_vec()]);
            },
        );
    }

    /// Two targets holding the same shard id (an acting member and a backfill target of its position) share the chunk
    /// buffer of that shard: a recovery chunk is not copied once per target.
    #[test]
    fn recovery_chunk_buffers_are_shared_between_targets_of_one_shard() {
        let mut pg = pg();
        let store = store_of(&pg);
        let soid = Hobject::new(b"obj", SnapId::NOSNAP, 7, 1, b"");
        let mut o = op(RecState::Reading);
        o.size = 8192;
        o.nstripes = 1;
        o.targets = vec![
            (
                PgShard {
                    osd: 1,
                    shard: ShardId(1),
                },
                false,
            ),
            (
                PgShard {
                    osd: 2,
                    shard: ShardId(1),
                },
                true,
            ),
        ];
        pg.ep.recov.ops.insert(soid.clone(), o);
        let bufs = vec![vec![1u8; 4096], vec![2u8; 4096], vec![3u8; 4096]];
        pg.ec_recov_push_bufs(soid.clone(), bufs, 1, &store);
        let pushes: Vec<&replwire::MOSDPGPush> = pg
            .out
            .iter()
            .filter_map(|a| match a {
                Action::Send(s) => match &s.body {
                    Body::Repl(ReplMsg::Push(m)) => Some(m),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(pushes.len(), 2);
        let (a, b) = (&pushes[0].pushes[0], &pushes[1].pushes[0]);
        assert_eq!(a.data.as_ref(), &[2u8; 4096], "shard 1 bytes");
        assert_eq!(
            a.data.as_ptr(),
            b.data.as_ptr(),
            "one buffer for both targets of shard 1"
        );
    }
}

#[cfg(test)]
mod rec_stripe_tests {
    use super::rec_stripes;

    /// H-1: the EC recovery read budget is logical bytes rounded UP to whole stripes, at least one stripe.
    #[test]
    fn ec_recovery_read_budget_rounds_up_to_whole_stripes() {
        let mib = 1 << 20;
        assert_eq!(rec_stripes(10 * mib, 3 * mib), 4);
        assert_eq!(rec_stripes(6 * mib, 3 * mib), 2);
        assert_eq!(rec_stripes(1, 3 * mib), 1);
    }
}
