// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG split and merge as local transformations of PG state (spec split-merge.md 5, 6): the parent carves its
//! children out at the epoch that raised pg_num; the merge target absorbs its sources at the epoch that lowered it.
//! The osdmap is the only trigger, there are no messages between OSDs for it.

use crate::pg::{ASt, PSt, Pending, Pg, St};
use crate::plog::{IndexedLog, MissingSet, recompute_last_complete};
use crate::store::{PersistedPg, PgStoreOps, SplitChild, StoreOp};
use denc::types::{Eversion, Hobject, PgT, SpgT};
use pgwire::pgmath;
use pgwire::state as pgs;
use pgwire::{LogDup, MergeMeta, PgLog, PgMissing};
use std::collections::BTreeMap;

/// Make a merge placeholder's borrowed history and past intervals (both from the source) agree with the les/lec the
/// pool recorded for the merge (split-merge.md 6.4): the required past-interval bounds `[lec, sis)` must lie inside
/// the past intervals, or a classic OSD that creates the PG from our notify / log aborts when it later leads it.
/// - past intervals that start after lec (the source re-peered after the target): start them at lec;
/// - an interval that started after les (the source's sis): move sis back to lec and keep `same_up_since` and
///   `same_primary_since` at or below it.
fn placeholder_bounds(h: &mut pgwire::PgHistory, past: &mut pgwire::PastIntervals) {
    let lec = h.last_epoch_clean;
    if !past.is_empty() && lec < past.first {
        past.first = lec;
    }
    if h.last_epoch_started < h.same_interval_since {
        h.same_interval_since = lec;
        h.same_up_since = h.same_up_since.min(lec);
        h.same_primary_since = h.same_primary_since.min(lec);
    }
}

/// EC roll-forward of a merge source whose log is about to be emptied, as the normal EC trim does it
/// ([`Pg::ec_roll_forward_to`]): target and every source give up the stash of their entries. A source's own
/// transaction was already flushed when it was quiesced and `MergeIn` removes its pgmeta, so only its stash removals
/// are kept, in the target's transaction (applied after `MergeIn` moved the source's objects into the target
/// collection).
fn merge_source_roll_forward(sp: &mut Pg, to: Eversion, txn: &mut Vec<StoreOp>) {
    if sp.ec_ctx().is_none() {
        return;
    }
    sp.ec_roll_forward_to(to);
    for op in std::mem::take(&mut sp.txn) {
        // the rollback cursors go away with the source's pgmeta
        if let StoreOp::Shard(rm) = op {
            txn.push(StoreOp::Shard(rm));
        }
    }
}

/// What the primary of a pending merge (source or target) knows about it (split-merge.md 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeStatus {
    /// Not a primary, or not (yet) peered for the merge.
    No,
    /// Merge cannot proceed (undersized at activation): report `ready = false`.
    NotReady,
    /// Peered + premerge, not clean yet.
    Waiting,
    /// Peered + premerge + clean: ready to merge at this version.
    Ready {
        last_update: Eversion,
        last_epoch_started: u32,
        last_epoch_clean: u32,
    },
}

impl Pg {
    /// A merge is being prepared for this pool and this PG is its source or target. Every pool type merges
    /// (`pg_pool_t::is_pending_merge` has no type test; split-merge.md 13.1).
    pub fn is_pending_merge(&self) -> bool {
        pgmath::is_pending_merge(
            self.spg.pgid.seed,
            self.pool.pg_num,
            self.pool.pg_num_pending,
        )
    }

    /// The pending merges (keyed by their SOURCE pgid) this PG takes part in, and whether it is that source. The
    /// mon only prepares one merge at a time (`pg_num_pending = pg_num - 1`), but the registry must not rely on
    /// that: a target is listed once per source it absorbs, a source once.
    pub fn merge_pairs(&self) -> Vec<(PgT, bool)> {
        if !self.is_pending_merge() {
            return vec![];
        }
        let seed = self.spg.pgid.seed;
        let pool = self.spg.pgid.pool;
        let (pending, n) = (self.pool.pg_num_pending, self.pool.pg_num);
        if seed >= pending && seed < n {
            return vec![(PgT::new(pool, seed), true)];
        }
        (pending..n)
            .filter(|s| pgmath::merge_target(*s, pending) == seed)
            .map(|s| (PgT::new(pool, s), false))
            .collect()
    }

    /// Primary-side merge readiness (PEERED+PREMERGE; clean = ready). Ready only when Clean was reached IN THE
    /// CURRENT interval (`last_interval_clean == same_interval_since`): a CLEAN bit carried over from an earlier
    /// interval (same acting, new interval at pg_num_pending) says nothing about this one.
    pub fn merge_status(&self) -> MergeStatus {
        if !self.is_primary() || self.state & pgs::PREMERGE == 0 {
            return MergeStatus::No;
        }
        if self.merge_not_ready {
            return MergeStatus::NotReady;
        }
        let h = &self.info.history;
        if matches!(self.st, St::Primary(PSt::Active(ASt::Clean)))
            && self.state & pgs::CLEAN != 0
            && self.state & pgs::PEERED != 0
            && h.last_interval_clean == h.same_interval_since
            && h.last_epoch_clean >= h.same_interval_since
        {
            MergeStatus::Ready {
                last_update: self.info.last_update,
                last_epoch_started: h.last_epoch_started,
                last_epoch_clean: h.last_epoch_clean,
            }
        } else {
            MergeStatus::Waiting
        }
    }

    /// pg_num of the pool in this PG's current map.
    pub fn pool_pg_num(&self) -> u32 {
        self.pool.pg_num
    }

    // ---- split ---------------------------------------------------------------------------------------

    /// Split this PG after its AdvMap for the epoch that raised pg_num `old_n -> new_n`: returns the children
    /// (ascending seed). Everything lands in ONE store transaction of this PG (`SplitOut` + the rewritten log /
    /// missing / info / epoch); the children are persisted by the `SplitOut` op.
    pub(crate) fn split_self(&mut self, old_n: u32, new_n: u32) -> Vec<Pg> {
        self.hold_flush = false;
        let seed = self.spg.pgid.seed;
        let kids = pgmath::split_children(seed, old_n, new_n);
        if kids.is_empty() {
            self.flush(Pending::Plain);
            return vec![];
        }
        let epoch = self.map.epoch();
        let pool = self.spg.pgid.pool;
        self.info.history.last_epoch_split = epoch;
        let owner = |hash: u32| -> usize {
            kids.binary_search(&pgmath::object_pg(hash, new_n))
                .unwrap_or(kids.len())
        };
        let parts = self.info.stats.stats.sum.split(kids.len() + 1);
        let reset_bf = self.info.last_backfill != Hobject::MAX();

        // log entries by object hash; head/tail/rollback bounds and the dups are copied
        let old = std::mem::take(&mut self.log.log);
        let mut logs: Vec<PgLog> = (0..=kids.len())
            .map(|_| PgLog {
                head: old.head,
                tail: old.tail,
                can_rollback_to: old.can_rollback_to,
                rollback_info_trimmed_to: old.rollback_info_trimmed_to,
                log: Default::default(),
                dups: old.dups.clone(),
            })
            .collect();
        for e in old.log {
            let o = owner(e.soid.hash);
            logs[o].log.push_back(e);
        }
        // missing items by object hash (a non-MAX last_backfill clears them everywhere: backfill restarts)
        let old_m = self.missing.to_wire();
        let mut ms: Vec<PgMissing> = (0..=kids.len())
            .map(|_| PgMissing {
                missing: BTreeMap::new(),
                may_include_deletes: old_m.may_include_deletes,
            })
            .collect();
        if !reset_bf {
            for (h, it) in old_m.missing {
                let o = owner(h.hash);
                ms[o].missing.insert(h, it);
            }
        }

        let mut children: Vec<Pg> = Vec::with_capacity(kids.len());
        let mut split_ops: Vec<SplitChild> = Vec::with_capacity(kids.len());
        let mut logs_it = logs.into_iter();
        let mut ms_it = ms.into_iter();
        for (i, &c) in kids.iter().enumerate() {
            let cspg = SpgT {
                pgid: PgT::new(pool, c),
                // children keep the parent's shard (an EC child sits on the same acting position until pgp_num moves)
                shard: self.spg.shard,
            };
            let bits = pgmath::split_bits(c, new_n);
            let mut ci = self.info.clone();
            ci.pgid = cspg;
            ci.stats.stats.sum = parts[i];
            ci.stats.parent_split_bits = bits;
            ci.stats.stats_invalid = true;
            ci.history.epoch_created = epoch;
            ci.history.epoch_pool_created = self.info.history.epoch_pool_created.max(1);
            if reset_bf {
                ci.last_backfill = Hobject::MIN();
            }
            let mut child = Pg::blank(self.cfg.clone(), cspg, self.map.clone(), ci);
            child.lastmap = self.lastmap.clone();
            child.log = IndexedLog::new(logs_it.next().unwrap());
            child.missing = MissingSet::from_wire(ms_it.next().unwrap());
            // mode O: pwlc may point at entries that went to the other half (split_pwlc)
            let prev = crate::ecopt::rit_prev(&child.log.log);
            crate::ecopt::split_pwlc(&mut child.info, prev);
            child.past = self.past.clone();
            if child.acting_primary != self.acting_primary {
                child.info.history.same_primary_since = epoch;
            }
            child.persisted_epoch = epoch;
            child.created_in_store = true;
            child.last_peering_reset = epoch;
            child.sync_stats_mapping();
            child.info_dirty = false;
            recompute_last_complete(&child.log, &mut child.info, &child.missing);
            child.info.log_tail = child.log.tail();
            child.send_notify = child.acting_primary >= 0 && !child.is_primary();
            // a child copies the parent's (history, past intervals) pair, which can be implausible for the new
            // interval: it runs the same check before it may act or send (peering.md 3.8)
            child.check_past_interval_bounds();
            split_ops.push(SplitChild {
                spg: cspg,
                bits,
                state: Box::new(PersistedPg {
                    info: child.info.clone(),
                    log: child.log.log.clone(),
                    missing: child.missing.to_wire(),
                    past_intervals: child.past.clone(),
                    epoch,
                }),
            });
            children.push(child);
        }

        // the parent keeps the rest
        self.log = IndexedLog::new(logs_it.next().unwrap());
        self.missing = MissingSet::from_wire(ms_it.next().unwrap());
        self.missing.rewrite_all();
        let prev = crate::ecopt::rit_prev(&self.log.log);
        crate::ecopt::split_pwlc(&mut self.info, prev);
        self.info.stats.stats.sum = parts[kids.len()];
        self.info.stats.stats_invalid = true;
        if reset_bf {
            self.info.last_backfill = Hobject::MIN();
        }
        recompute_last_complete(&self.log, &mut self.info, &self.missing);
        self.info.log_tail = self.log.tail();
        self.info_dirty = true;
        self.past_dirty = true;
        self.txn.insert(
            0,
            StoreOp::SplitOut {
                parent_bits: pgmath::split_bits(seed, new_n),
                children: split_ops,
            },
        );
        self.txn
            .push(StoreOp::LogReplace(Box::new(self.log.log.clone())));
        self.flush(Pending::Plain);
        children
    }

    // ---- merge ---------------------------------------------------------------------------------------

    /// The PG is a merge source at the epoch it is about to process: stop everything (the caller then removes it
    /// from its table and hands it to the target, or deletes it). Pending store writes are already queued
    /// (visible to the target's `MergeIn`); in-flight client work is dropped, clients re-send to the target.
    /// Messages held for the store are dropped (the merge is a new interval: their primary aborted them; a PG leaving the
    /// core is not served here any more) and every residency lease of the PG is released.
    pub(crate) fn quiesce_for_merge(&mut self, store: &impl PgStoreOps) {
        self.flush(Pending::Plain);
        self.abort_interval_work();
        self.on_leave_primary_or_replica();
        self.drop_held();
        self.release_leases(store);
    }

    /// Empty target for a merge source whose target PG is not here (split-merge.md 4 priming, 6.4 step 6): history
    /// and past intervals of the source (placement is identical), nothing else; it is never complete
    /// (`last_backfill = MIN`) so its peers backfill it after the merge.
    /// Then absorbs `sources` like any target ([`Self::merge_from`]) and keeps classic's past-interval bounds.
    pub(crate) fn merge_placeholder(
        cfg: std::sync::Arc<crate::types::Config>,
        spg: SpgT,
        sources: Vec<(u32, Option<Pg>)>,
        meta: &MergeMeta,
        new_n: u32,
        now: crate::types::Mono,
    ) -> Pg {
        let first_source = sources
            .iter()
            .find_map(|(_, p)| p.as_ref())
            .expect("a placeholder is made for a local source");
        // the source's own map (parked before AdvMap(e)), not a history lookup that may miss
        let map = first_source.map_handle();
        let mut pg = Pg::create(
            cfg,
            spg,
            map,
            first_source.info.history.clone(),
            first_source.past.clone(),
            now,
        );
        pg.info.last_backfill = Hobject::MIN();
        // les/lec come from the merge facts the pool recorded (the PGs that were found ready), NOT from the source:
        // the source may have activated later than the target ever did, and a history les that no complete copy
        // reaches makes every later peering of the merged PG Incomplete (the placeholder's history spreads by Notify)
        let (les, lec) = if meta.source_seed != 0 {
            (meta.last_epoch_started, meta.last_epoch_clean)
        } else {
            (0, 0)
        };
        pg.info.history.last_epoch_started = les;
        pg.info.history.last_epoch_clean = lec;
        pg.info.last_epoch_started = les;
        pg.merge_from(sources, meta, new_n, false);
        // after merge_from: it may adopt a later source's past intervals
        placeholder_bounds(&mut pg.info.history, &mut pg.past);
        pg
    }

    /// Target side, executed BEFORE its AdvMap for the epoch that lowered pg_num `old_n -> new_n`
    /// (split-merge.md 6.4): absorb the sources (`None` = not present locally -> incomplete, backfilled later). `late`: this
    /// PG is already past the merge epoch (it was made from a newer map): its own history and intervals were built
    /// without the sources, so nothing can be trusted to match: always incomplete (`last_backfill = MIN`).
    /// Classic never merges late (the target waits for its sources, 6.4).
    pub(crate) fn merge_from(
        &mut self,
        sources: Vec<(u32, Option<Pg>)>,
        meta: &MergeMeta,
        new_n: u32,
        late: bool,
    ) {
        let seed = self.spg.pgid.seed;
        let pool = self.spg.pgid.pool;
        let bits = pgmath::split_bits(seed, new_n);
        let clean = |i: &pgwire::PgInfo, m: &MissingSet| {
            i.last_complete == i.last_update && i.last_backfill == Hobject::MAX() && m.is_empty()
        };
        let mut incomplete = !clean(&self.info, &self.missing);
        if meta.source_seed != 0
            && (pgmath::parent(meta.source_seed) != seed
                || self.info.last_update != meta.target_version)
        {
            incomplete = true;
        }
        if late || meta.source_seed == 0 {
            incomplete = true; // no merge facts to compare with: be safe
        }
        let cfg = self.cfg.clone();
        // the log is emptied below: its entries leave it, so an EC shard gives up their rollback stash first, exactly
        // as the normal EC trim does (`ec_trim_log_to` -> `ec_advance`): the log is rolled forward to the head being
        // kept. Replicated: nothing to apply. Then trim the whole log: every entry becomes a dup.
        let head = self.log.head();
        if self.ec_ctx().is_some() {
            self.ec_roll_forward_to(head);
        }
        self.log.trim(head, &cfg);
        let mut dups: Vec<LogDup> = std::mem::take(&mut self.log.log.dups).into();
        let mut last_update = self.info.last_update;
        let mut spgs: Vec<SpgT> = Vec::new();
        let mut adopt_past = None;
        for (s, src) in sources {
            spgs.push(SpgT {
                pgid: PgT::new(pool, s),
                shard: self.spg.shard,
            });
            let Some(mut sp) = src else {
                incomplete = true;
                continue;
            };
            if !clean(&sp.info, &sp.missing)
                || meta.source_seed != s
                || sp.info.last_update != meta.source_version
            {
                incomplete = true;
            }
            let h = sp.log.head();
            merge_source_roll_forward(&mut sp, h, &mut self.txn);
            sp.log.trim(h, &cfg);
            dups.extend(sp.log.log.dups.drain(..));
            self.info.stats.stats.sum.add(&sp.info.stats.stats.sum);
            self.info.stats.stats_invalid |= sp.info.stats.stats_invalid;
            last_update = last_update.max(sp.info.last_update);
            self.info.last_user_version =
                self.info.last_user_version.max(sp.info.last_user_version);
            if adopt_past.is_none() && self.past.is_empty() && !sp.past.is_empty() {
                adopt_past = Some(sp.past.clone());
            }
        }
        if let Some(p) = adopt_past {
            self.past = p;
            self.past_dirty = true;
        }
        dups.sort_by_key(|d| d.version);
        self.info.last_update = last_update;
        self.info.last_complete = last_update;
        self.info.log_tail = last_update;
        // mode O: merged pwlc collapses to the merged head
        let ep = self.map.epoch();
        crate::ecopt::merge_reset_pwlc(&mut self.info, ep);
        if incomplete {
            self.info.last_backfill = Hobject::MIN();
        }
        let mut log = PgLog::empty_at(last_update);
        log.dups = dups.into();
        self.log = IndexedLog::new(log);
        let del = self.missing.may_include_deletes();
        self.missing = MissingSet::new(del);
        self.missing.rewrite_all();
        self.info_dirty = true;
        self.txn.insert(
            0,
            StoreOp::MergeIn {
                sources: spgs,
                bits,
            },
        );
        self.txn
            .push(StoreOp::LogReplace(Box::new(self.log.log.clone())));
    }
}

#[cfg(test)]
mod tests {
    use super::placeholder_bounds;
    use crate::map::MapHandle;
    use crate::map::synth::SynthMap;
    use crate::pg::Pg;
    use crate::plog::IndexedLog;
    use crate::store::{ShardOp, StoreOp};
    use crate::types::Config;
    use denc::types::{Eversion, Hobject, PgT, ShardId, SnapId, SpgT};
    use ec::moddesc::ModDescBuilder;
    use pgwire::{EcPoolInfo, LogEntry, LogOp, ObjectModDesc, PastIntervals, PgHistory, PgLog};
    use std::sync::Arc;

    /// Classic `check_past_interval_bounds` (oldest map 1): non-empty required bounds `[lec, sis)` must lie inside the
    /// past intervals `[first, last + 1)`.
    fn bounds_hold(h: &PgHistory, p: &PastIntervals) -> bool {
        let (rs, re) = (h.last_epoch_clean.max(1), h.same_interval_since);
        if rs >= re {
            return true;
        }
        let (ps, pe) = p.bounds();
        !p.is_empty() && ps <= rs && pe >= re
    }

    fn src(sis: u32, pi: (u32, u32)) -> (PgHistory, PastIntervals) {
        let h = PgHistory {
            epoch_created: 5,
            same_interval_since: sis,
            same_up_since: sis,
            same_primary_since: sis,
            ..Default::default()
        };
        let p = PastIntervals {
            first: pi.0,
            last: pi.1,
            ..Default::default()
        };
        (h, p)
    }

    /// The source re-peered after the merge facts (its past intervals start after the recorded lec): the start moves
    /// back to lec.
    #[test]
    fn placeholder_past_start_moves_back_to_lec() {
        let (mut h, mut p) = src(30, (20, 29));
        h.last_epoch_started = 30;
        h.last_epoch_clean = 12;
        assert!(!bounds_hold(&h, &p));
        placeholder_bounds(&mut h, &mut p);
        assert_eq!(p.bounds(), (12, 30));
        assert_eq!(h.same_interval_since, 30);
        assert!(bounds_hold(&h, &p));
    }

    /// The source's interval began after the recorded les: sis (and up/primary since) move back to lec.
    #[test]
    fn placeholder_sis_after_les_moves_back() {
        let (mut h, mut p) = src(40, (20, 39));
        h.last_epoch_started = 15;
        h.last_epoch_clean = 15;
        h.same_up_since = 38;
        h.same_primary_since = 10;
        placeholder_bounds(&mut h, &mut p);
        assert_eq!(h.same_interval_since, 15);
        assert_eq!(h.same_up_since, 15);
        assert_eq!(h.same_primary_since, 10);
        assert_eq!(p.bounds().0, 15);
        assert!(bounds_hold(&h, &p));
        // empty past intervals stay empty: required bounds [15, 15) are empty
        let (mut h, mut p) = src(40, (0, 0));
        h.last_epoch_started = 15;
        h.last_epoch_clean = 15;
        placeholder_bounds(&mut h, &mut p);
        assert!(p.is_empty() && bounds_hold(&h, &p));
    }

    /// The real placeholder path: a source whose past intervals start after the recorded merge lec and whose interval
    /// began after the recorded les yields a placeholder within classic's bounds.
    #[test]
    fn merge_placeholder_keeps_classic_bounds() {
        use crate::map::synth::SynthMap;
        use crate::pg::Pg;
        use crate::types::Config;
        use denc::types::{PgT, SpgT};
        use std::sync::Arc;
        let map: crate::map::MapHandle = std::rc::Rc::new(
            SynthMap::new(40)
                .with_pool(1, 2, 1, 2)
                .with_osd(0, 1)
                .with_osd(1, 1),
        );
        let cfg = Arc::new(Config::new(0));
        let (h, p) = src(35, (20, 34));
        let spg1 = SpgT {
            pgid: PgT::new(1, 1),
            shard: denc::types::ShardId::NO_SHARD,
        };
        let source = Pg::create(cfg.clone(), spg1, map, h, p, 0);
        let meta = pgwire::MergeMeta {
            source_seed: 1,
            ready_epoch: 38,
            last_epoch_started: 14,
            last_epoch_clean: 12,
            ..Default::default()
        };
        let target = SpgT {
            pgid: PgT::new(1, 0),
            shard: denc::types::ShardId::NO_SHARD,
        };
        let ph = Pg::merge_placeholder(cfg, target, vec![(1, Some(source))], &meta, 1, 0);
        let (h, p) = (&ph.info().history, ph.past_intervals());
        assert!(bounds_hold(h, p), "history {h:?} past {:?}", p.bounds());
        assert_eq!((h.same_interval_since, p.bounds().0), (12, 12));
    }

    /// Consistent history and intervals are left alone.
    #[test]
    fn placeholder_consistent_is_unchanged() {
        let (mut h, mut p) = src(30, (10, 29));
        h.last_epoch_started = 30;
        h.last_epoch_clean = 10;
        let (h0, p0) = (h.clone(), p.clone());
        placeholder_bounds(&mut h, &mut p);
        assert_eq!((h, p), (h0, p0));
    }

    /// Map with pool 1 on two OSDs, EC k=2 m=2 when `ec` (else replicated), pg_num 2.
    fn merge_map(ec: bool) -> MapHandle {
        let mut m = SynthMap::new(40)
            .with_pool(1, 2, 1, 2)
            .with_osd(0, 1)
            .with_osd(1, 1);
        if ec {
            let p = m.pools.get_mut(&1).expect("pool 1");
            p.is_erasure = true;
            p.ec = Some(Arc::new(EcPoolInfo {
                k: 2,
                m: 2,
                stripe_width: 8192,
                chunk_size: 4096,
                supported: true,
                ..Default::default()
            }));
        }
        m.into_handle()
    }

    /// An EC log entry on object `name` whose rollback stash is `stash` (a DELETE in its mod_desc).
    fn stash_entry(name: &[u8], version: u64, stash: u64) -> LogEntry {
        let mut b = ModDescBuilder::new();
        b.delete(stash);
        let (bl, v, _) = b.finish();
        let mut e = LogEntry::new(
            LogOp::MODIFY,
            Hobject::new(name, SnapId::NOSNAP, 0x0b, 1, b""),
            Eversion::new(5, version),
            Eversion::default(),
        );
        e.mod_desc = ObjectModDesc {
            version: v,
            can_local_rollback: true,
            rollback_info_completed: false,
            bl,
        };
        e
    }

    /// A PG whose log still holds unapplied rollback state: entries above `can_rollback_to`, each with a stash.
    fn pg_with_stash(
        cfg: Arc<Config>,
        map: MapHandle,
        spg: SpgT,
        entries: [(&[u8], u64); 2],
    ) -> Pg {
        let mut pg = Pg::create(
            cfg,
            spg,
            map,
            PgHistory::default(),
            PastIntervals::default(),
            0,
        );
        pg.log = IndexedLog::new(PgLog::empty_at(Eversion::new(5, 0)));
        for (i, (name, stash)) in entries.into_iter().enumerate() {
            pg.log.append_keep(stash_entry(name, i as u64 + 1, stash));
        }
        pg.info.last_update = Eversion::new(5, 2);
        pg.info.last_complete = Eversion::new(5, 2);
        pg.info.last_backfill = Hobject::MAX();
        pg
    }

    /// `(object oid, generation)` of every stash removal the PG's queued transaction schedules.
    fn stash_removals(pg: &Pg) -> Vec<(Vec<u8>, u64)> {
        let mut v = Vec::new();
        for op in &pg.txn {
            if let StoreOp::Shard(ops) = op {
                for s in ops {
                    if let ShardOp::Remove { soid, generation } = s {
                        v.push((soid.oid.clone(), *generation));
                    }
                }
            }
        }
        v.sort();
        v
    }

    /// Merging a PG empties its log and the sources' logs, so the rollback stash of every entry that leaves them must
    /// be cleaned up first, as the normal EC trim does (`ec_trim_log_to` -> `ec_advance`): target and sources are rolled
    /// forward to the head being kept in the merge's own transaction. A replicated merge is unchanged.
    #[test]
    fn ec_merge_rolls_the_log_forward_before_trimming() {
        let cfg = Arc::new(Config::new(0));
        let target = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId(0),
        };
        let source = SpgT {
            pgid: PgT::new(1, 1),
            shard: ShardId(0),
        };
        let meta = pgwire::MergeMeta {
            source_seed: 1,
            ready_epoch: 40,
            last_epoch_started: 40,
            last_epoch_clean: 40,
            source_version: Eversion::new(5, 2),
            target_version: Eversion::new(5, 2),
        };
        let merged = |ec: bool| {
            let map = merge_map(ec);
            let mut pg = pg_with_stash(
                cfg.clone(),
                map.clone(),
                target,
                [(b"t1".as_slice(), 7), (b"t2".as_slice(), 8)],
            );
            let src = pg_with_stash(
                cfg.clone(),
                map,
                source,
                [(b"s1".as_slice(), 11), (b"s2".as_slice(), 12)],
            );
            pg.merge_from(vec![(1, Some(src))], &meta, 2, false);
            pg
        };
        let ec = merged(true);
        // rolled forward to the head being kept: the merged log starts there
        assert_eq!(ec.log.log.can_rollback_to, Eversion::new(5, 2));
        assert_eq!(ec.log.log.rollback_info_trimmed_to, Eversion::new(5, 2));
        assert!(ec.log.is_empty(), "the merged log is empty");
        assert_eq!(ec.log.log.dups.len(), 4, "every entry became a dup");
        // the target's and every source's stash is scheduled for removal in the merge's transaction, which empties the
        // log last (the roll-forward is what the normal EC trim does before those entries leave the log)
        assert_eq!(
            stash_removals(&ec),
            vec![
                (b"s1".to_vec(), 11),
                (b"s2".to_vec(), 12),
                (b"t1".to_vec(), 7),
                (b"t2".to_vec(), 8),
            ]
        );
        assert!(matches!(ec.txn.first(), Some(StoreOp::MergeIn { .. })));
        assert!(matches!(ec.txn.last(), Some(StoreOp::LogReplace(_))));

        // replicated: nothing to roll forward, the merge transaction keeps its two ops
        let rep = merged(false);
        assert_eq!(rep.log.log.can_rollback_to, Eversion::new(5, 2));
        assert_eq!(rep.log.log.rollback_info_trimmed_to, Eversion::new(5, 2));
        assert!(rep.log.is_empty(), "the merged log is empty");
        assert_eq!(rep.log.log.dups.len(), 4, "every entry became a dup");
        assert!(stash_removals(&rep).is_empty(), "no EC op for a replica");
        assert_eq!(rep.txn.len(), 2, "{:?}", rep.txn);
        assert!(matches!(rep.txn.first(), Some(StoreOp::MergeIn { .. })));
        assert!(matches!(rep.txn.last(), Some(StoreOp::LogReplace(_))));
    }
}
