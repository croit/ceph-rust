// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Snap trimming, PG side (spec snaptrim.md 2, 7): the queue arithmetic against the osdmap, the gate, the reservation
//! slot, the state bits and the purged-snaps bookkeeping. The trim steps themselves (clone / head rewrite as a logged
//! write) are built by the primary's op engine (`opexec::trim`); it drives this state machine through
//! [`Pg::trim_poll`], [`Pg::trim_snap_done`] and [`Pg::trim_stop`].

use crate::pg::{ASt, PSt, Pg, St};
use crate::snaps::{Ivs, iv_head, iv_insert, iv_intersect, iv_len, iv_subtract};
use crate::types::{Action, SEC, SlotOp, SlotPool};
use pgwire::state as pgs;

/// Intervals of `info.purged_snaps` reported in `pg_stat_t` (osd_max_snap_prune_intervals_per_epoch).
pub const PRUNE_INTERVALS: usize = 512;

/// Phase of this PG's trim run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Phase {
    #[default]
    Idle,
    /// Waiting for a trim slot (`osd_max_trimming_pgs`).
    WaitResv,
    /// Slot held: the engine may issue steps.
    Run,
}

/// Per-PG trimmer state (primary only, volatile).
#[derive(Debug, Default)]
pub(crate) struct Trim {
    /// `snap_trimq`: removed snaps still to trim, rebuilt from the map at every activation / map advance.
    pub q: Ivs,
    pub phase: Phase,
    /// A `SnapTrimKick` is on its way to the driver (since `kick_at`; re-sent after a second, a lost kick must not
    /// stall the PG).
    pub kick_out: bool,
    pub kick_at: u64,
    /// Clone / whiteout deletions since the run began (`pg_stat_t.objects_trimmed`).
    pub objects_trimmed: i64,
    pub run_start: u64,
    /// Seconds the last finished snap took.
    pub duration: f64,
    /// Publish stats at the next event even if the state bits did not change.
    pub stats_dirty: bool,
    /// `info.purged_snaps` changed since the peers last heard.
    pub share_pending: bool,
    /// A step failed in this epoch: no new run before the next map (no busy retry).
    pub err_epoch: Option<u32>,
    /// `snap_trimq_repeat`: purged snaps queued again by the purged-snaps scrub (spec snaptrim.md 7.3, 8.3). They stay
    /// in `q` across recomputes until their retrim finds no clone; finishing one does not touch `info.purged_snaps`.
    pub repeat: std::collections::BTreeSet<u64>,
}

/// Findings of a purged-snaps scrub (one PG, or summed over PGs / cores).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgedScrub {
    /// Mapper entries (clone, snap) of snaps the PG purged.
    pub strays: u64,
    /// Snaps queued for another trim (strays on active primaries; one per snap).
    pub retrimmed: u64,
    /// PGs whose mapper could not be read.
    pub read_errors: u64,
}

impl PurgedScrub {
    pub fn add(&mut self, o: &PurgedScrub) {
        self.strays += o.strays;
        self.retrimmed += o.retrimmed;
        self.read_errors += o.read_errors;
    }
}

/// What the engine may do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrimPoll {
    /// Nothing to do / not allowed now: the engine goes idle (the PG kicks it again when that changes).
    No,
    /// A slot was requested, the engine waits for the kick.
    Wait,
    /// Trim this snap (lowest queued).
    Go(u64),
}

impl Pg {
    /// `snap_trimq` (ids still to trim).
    pub fn snap_trimq(&self) -> &Ivs {
        &self.trim.q
    }

    /// Number of snap ids in the queue.
    pub fn snap_trimq_len(&self) -> u64 {
        iv_len(&self.trim.q)
    }

    /// Operator notes of this PG (clog-worthy lines), drained by the set.
    pub(crate) fn take_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notes)
    }

    fn is_active_primary(&self) -> bool {
        matches!(self.st, St::Primary(PSt::Active(_))) && self.refuse.is_none()
    }

    /// Spec 2.2 (simplified, idempotent): `trimq = queue - purged`, `purged &= queue`. Primary + active only.
    /// Returns true if `info.purged_snaps` changed (info dirty; the caller shares it).
    pub(crate) fn snap_recompute(&mut self) -> bool {
        if !self.is_active_primary() {
            return false;
        }
        let queue: Ivs = self.map.removed_snaps_queue(self.spg.pgid.pool);
        let purged = iv_intersect(&self.info.purged_snaps, &queue);
        let changed = purged != self.info.purged_snaps;
        if changed {
            self.info.purged_snaps = purged;
            self.info_dirty = true;
            self.trim.stats_dirty = true;
        }
        let mut q = iv_subtract(&queue, &self.info.purged_snaps);
        for s in &self.trim.repeat {
            iv_insert(&mut q, *s, 1);
        }
        if q != self.trim.q {
            self.trim.q = q;
            self.trim.stats_dirty = true;
        }
        changed
    }

    /// Gate (spec 7.1 `permit_trim` + NOSNAPTRIM).
    pub(crate) fn trim_permit(&self) -> bool {
        matches!(self.st, St::Primary(PSt::Active(ASt::Clean)))
            && self.state & pgs::CLEAN != 0
            && self.state & (pgs::PREMERGE | pgs::SCRUBBING) == 0
            && !self.scrub_pending()
            && !self.trim.q.is_empty()
            && !self.map.nosnaptrim()
            && self.trim.err_epoch != Some(self.map.epoch())
            && self.refuse.is_none()
    }

    /// Ask the driver to run the trimmer (once) when it may run.
    pub(crate) fn trim_kick(&mut self) {
        // cheap exits first: this runs after every event of every PG
        if self.trim.q.is_empty() || self.trim.phase != Phase::Idle {
            return;
        }
        if self.trim.kick_out && self.now < self.trim.kick_at + SEC {
            return;
        }
        if self.trim_permit() {
            self.trim.kick_out = true;
            self.trim.kick_at = self.now;
            self.out.push(Action::SnapTrimKick { spg: self.spg });
        }
    }

    /// Driver entry of the engine: where do we stand? Requests the slot on first call.
    pub fn trim_poll(&mut self) -> TrimPoll {
        self.trim.kick_out = false;
        if !self.trim_permit() {
            if self.trim.phase != Phase::Idle {
                self.trim_stop(false);
            }
            return TrimPoll::No;
        }
        match self.trim.phase {
            Phase::Idle => {
                self.trim.phase = Phase::WaitResv;
                self.state |= pgs::SNAPTRIM_WAIT;
                self.state &= !pgs::SNAPTRIM_ERROR;
                self.trim.stats_dirty = true;
                self.slot_ask(
                    SlotPool::Trim,
                    SlotOp::Request {
                        immediate: false,
                        prio: 0,
                    },
                );
                TrimPoll::Wait
            }
            Phase::WaitResv => TrimPoll::Wait,
            Phase::Run => match self.trim.q.keys().next() {
                Some(s) => TrimPoll::Go(*s),
                None => {
                    self.trim_stop(false);
                    TrimPoll::No
                }
            },
        }
    }

    /// The set granted the slot.
    pub(crate) fn trim_granted(&mut self) {
        if self.trim.phase != Phase::WaitResv {
            self.slot_release(SlotPool::Trim);
            return;
        }
        self.trim.phase = Phase::Run;
        self.state &= !(pgs::SNAPTRIM_WAIT | pgs::SNAPTRIM_ERROR);
        self.state |= pgs::SNAPTRIM;
        self.trim.run_start = self.now;
        self.trim.objects_trimmed = 0;
        self.trim.stats_dirty = true;
        self.trim.kick_out = true;
        self.out.push(Action::SnapTrimKick { spg: self.spg });
    }

    /// Leave the run (any reason): release the slot, clear the bits. `error` sets SNAPTRIM_ERROR.
    pub fn trim_stop(&mut self, error: bool) {
        if self.trim.phase != Phase::Idle {
            self.slot_release(SlotPool::Trim);
        }
        self.trim.phase = Phase::Idle;
        self.state &= !(pgs::SNAPTRIM | pgs::SNAPTRIM_WAIT);
        if error {
            self.state |= pgs::SNAPTRIM_ERROR;
            self.trim.err_epoch = Some(self.map.epoch());
        }
        self.trim.stats_dirty = true;
        if self.trim.share_pending && self.is_active_primary() {
            self.trim.share_pending = false;
            self.share_pg_info();
        }
    }

    /// Interval change / role change / PG delete: forget everything volatile.
    pub(crate) fn trim_reset(&mut self) {
        if self.trim.phase != Phase::Idle {
            self.slot_release(SlotPool::Trim);
        }
        self.trim = Trim::default();
        self.state &= !(pgs::SNAPTRIM | pgs::SNAPTRIM_WAIT | pgs::SNAPTRIM_ERROR);
    }

    /// The mapper has no more clones of `snap`: it is purged (info only, no log entry), shared with the replicas.
    pub fn trim_snap_done(&mut self, snap: u64) {
        crate::snaps::iv_erase(&mut self.trim.q, snap, 1);
        // a retrim of an already purged snap (purged-snaps scrub) changes nothing in the info
        if !self.trim.repeat.remove(&snap) {
            crate::snaps::iv_insert(&mut self.info.purged_snaps, snap, 1);
            self.info_dirty = true;
            self.trim.share_pending = true;
        }
        self.trim.duration = self.now.saturating_sub(self.trim.run_start) as f64 / 1e9;
        self.trim.stats_dirty = true;
        // spec 7.3: the reservation is released at the exit of Trimming; a finished snap leaves the run and the next
        // one goes back through WaitReservation. Releasing the slot after every snap lets the OSD-wide trim budget
        // round-robin between PGs instead of being held for a whole queue (CS-5566: a long queue starved scrub).
        self.trim_stop(false);
        if !self.trim.q.is_empty() {
            self.trim_kick();
        }
    }

    /// Queue `snap` for trimming again although the PG purged it (clones of it are still mapped). Active primary only
    /// (a replica never trims); the trimmer is kicked when it may run. Returns whether it was newly queued.
    pub(crate) fn queue_snap_retrim(&mut self, snap: u64) -> bool {
        if !self.is_active_primary() {
            return false;
        }
        let new = self.trim.repeat.insert(snap);
        iv_insert(&mut self.trim.q, snap, 1);
        self.trim.stats_dirty = true;
        self.trim_kick();
        new
    }

    /// One step of the purged-snaps scrub of this PG (spec osd-tell-gaps.md 2.2): read up to `max` mapper entries from
    /// `cursor` (`None` = the start) and test each mapped snap against `info.purged_snaps`; a hit is a stray, queued for
    /// a retrim on the active primary. The walk covers the mapped clones between the first and the last purged snap, so
    /// the cost follows the mapper, not the purged id ranges. Returns the findings and the cursor to go on from
    /// (`None` = this PG is done). Replicated and erasure-coded PGs maintain the same mapper.
    pub(crate) fn purged_scan_step(
        &mut self,
        store: &impl crate::store::PgStoreOps,
        cursor: Option<Vec<u8>>,
        max: usize,
    ) -> (PurgedScrub, Option<Vec<u8>>) {
        let mut f = PurgedScrub::default();
        let (Some((&first, _)), Some(end)) = (
            self.info.purged_snaps.iter().next(),
            self.info
                .purged_snaps
                .iter()
                .next_back()
                .map(|(s, l)| s.saturating_add(*l)),
        ) else {
            return (f, None);
        };
        let from = cursor.unwrap_or_else(|| crate::snaps::fwd_prefix(first));
        match store.snapmap_scan(self.spg, &from, max) {
            Ok((snaps, next)) => {
                for snap in snaps {
                    if snap >= end {
                        return (f, None);
                    }
                    if crate::snaps::iv_contains(&self.info.purged_snaps, snap) {
                        f.strays += 1;
                        f.retrimmed += u64::from(self.queue_snap_retrim(snap));
                    }
                }
                (f, next)
            }
            Err(e) => {
                // an unreadable index ends this PG's scan (never counted as clean): reported, rest treated as ok
                f.read_errors += 1;
                self.notes.push(format!(
                    "ERROR {} purged_snaps scrub: snap mapper unreadable ({e:?})",
                    self.spg
                ));
                (f, None)
            }
        }
    }

    /// `objects_trimmed += n`.
    pub fn trim_counted(&mut self, n: i64) {
        self.trim.objects_trimmed += n;
    }

    /// Scrub of the SnapMapper over a finished chunk `[start, end)` (spec snaptrim 8.2): local repair, silent to the
    /// wire, one operator note per finding. Runs on the primary and on every replica.
    pub(crate) fn snapmap_scrub(
        &mut self,
        store: &impl crate::store::PgStoreOps,
        start: &denc::types::Hobject,
        end: &denc::types::Hobject,
        deep: bool,
    ) {
        let (ops, mut msgs) = store.snapmap_check(self.spg, start, end);
        if deep && *start == denc::types::Hobject::MIN() {
            msgs.extend(store.snapmap_key_scan(self.spg));
        }
        for m in msgs {
            if m.starts_with(crate::store::SNAPMAP_READ_ERR) {
                // an incomplete check is an error of its own (cluster log), never a silent "nothing to repair"
                self.error("snapmap check: store read failed (chunk not fully checked)");
                self.notes.push(format!("ERROR {} {m}", self.spg));
            } else {
                self.notes.push(format!("pg {}: {m}", self.spg));
            }
        }
        if ops.is_empty() {
            return;
        }
        self.txn.push(crate::store::StoreOp::SnapMap(ops));
        self.flush(crate::pg::Pending::Plain);
    }

    /// Drop a stale mapper entry (clone object absent and not in the head's SnapSet): local repair, no log entry.
    pub fn snap_unmap(&mut self, clone: denc::types::Hobject) {
        self.txn.push(crate::store::StoreOp::SnapMap(vec![
            crate::snaps::MapOp::Remove { clone },
        ]));
        self.info_dirty = true;
    }

    /// `pg_stat_t` fields of the trimmer (spec 2.3).
    pub(crate) fn trim_fill_stat(&self, s: &mut pgwire::PgStat) {
        s.snaptrimq_len = u32::try_from(iv_len(&self.trim.q)).unwrap_or(u32::MAX);
        s.purged_snaps = iv_head(&self.info.purged_snaps, PRUNE_INTERVALS);
        s.objects_trimmed = self.trim.objects_trimmed;
        s.snaptrim_duration = self.trim.duration;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use crate::pg::Pending;
    use crate::snaps::{MapOp, iv_from_pairs};
    use crate::store::{MemStore, PgStoreOps, StoreOp};
    use crate::types::Config;
    use denc::types::{Hobject, PgT, ShardId, SnapId, SpgT};
    use std::sync::Arc;

    /// The purged-snaps walk reads the mapped clones, never the purged id range: ten clones against a purged interval
    /// of 10^9 ids end at once, in steps of at most `max` entries, and only clones inside a purged interval are strays.
    #[test]
    fn purged_walk_costs_the_mapper_not_the_interval() {
        check_purged_walk(false);
    }

    #[test]
    fn ec_purged_walk_finds_restored_clones() {
        check_purged_walk(true);
    }

    fn check_purged_walk(erasure: bool) {
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        };
        let map: crate::MapHandle = std::rc::Rc::new(SynthMap::new(5).with_pool(1, 3, 2, 1));
        let mut pg = Pg::blank(Arc::new(Config::new(0)), spg, map, pgwire::PgInfo::new(spg));
        pg.pool.is_erasure = erasure;
        let mut st = MemStore::new();
        pg.txn.push(StoreOp::CreatePg);
        pg.info_dirty = true;
        pg.flush(Pending::Plain);
        for a in std::mem::take(&mut pg.out) {
            if let Action::Persist { txn, .. } = a {
                st.submit(spg, &txn);
            }
        }
        // mapped snaps: 5..8 and 50 (gap), 100.. inside, 3e9 beyond the last purged snap
        let mapped = [5u64, 6, 7, 8, 50, 100, 101, 2_000_000_000, 3_000_000_000];
        for (i, snap) in mapped.iter().enumerate() {
            let clone = Hobject::new(format!("o{i}").as_bytes(), SnapId(*snap), 7, 1, b"");
            st.pgs.get_mut(&spg).unwrap().snapmap.apply(&MapOp::Set {
                clone,
                snaps: vec![*snap],
            });
        }
        pg.info.purged_snaps = iv_from_pairs(&[(1, 10), (100, 1_000_000_000)]);
        let t = std::time::Instant::now();
        let (mut total, mut cursor, mut steps) = (PurgedScrub::default(), None, 0);
        loop {
            let (f, next) = pg.purged_scan_step(&st, cursor, 3);
            total.add(&f);
            steps += 1;
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
        assert!(t.elapsed().as_millis() < 200, "{:?}", t.elapsed());
        // 5 6 7 8 and 100 101 are inside the purged intervals; 50 is in the gap; 2e9 and 3e9 are past the last one
        assert_eq!((total.strays, total.read_errors), (6, 0), "{total:?}");
        assert_eq!(steps, 3, "entries / max");
        // nothing purged: no read at all
        pg.info.purged_snaps = Default::default();
        assert_eq!(
            pg.purged_scan_step(&st, None, 3),
            (PurgedScrub::default(), None)
        );
        // Peer/disk interval maps are decoded without normalization. An overflowing
        // upper bound must retain its high members rather than panic or wrap.
        let snap = u64::MAX - 3;
        let clone = Hobject::new(b"high-snap", SnapId(snap), 7, 1, b"");
        st.pgs.get_mut(&spg).unwrap().snapmap.apply(&MapOp::Set {
            clone,
            snaps: vec![snap],
        });
        pg.info.purged_snaps = [(u64::MAX - 4, 8)].into();
        let (found, next) = pg.purged_scan_step(&st, None, 3);
        assert_eq!(found.strays, 1);
        assert!(next.is_none());
    }
}
