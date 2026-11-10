// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The PGs of one core with change tracking, so per-op queries stay O(1) instead of scanning every PG:
//! * [`PgMap::next_deadline`] / [`PgMap::due`] keep an ordered index of per-PG timer deadlines, refreshed only for PGs
//!   that were mutably accessed since the last query (a client read touches none);
//! * [`PgMap::take_touched`] tells the caller which PGs were mutably accessed since its last call (engine sync).
//!
//! Reads go through `Deref` to the inner `BTreeMap`; every mutable access (`get_mut`, `insert`, `remove`) marks its PG.

use crate::pg::Pg;
use crate::types::Mono;
use denc::types::SpgT;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ops::Deref;

/// PGs touched mutably since the last [`PgMap::take_touched`].
#[derive(Debug, PartialEq, Eq)]
pub enum Touched {
    /// Too many to list: treat every PG as touched.
    All,
    /// The PGs are in the caller's buffer.
    Listed,
}

#[derive(Default)]
struct Ix {
    /// PGs whose deadline must be recomputed (`None` of the list = all).
    dirty: Vec<SpgT>,
    dirty_all: bool,
    touched: Vec<SpgT>,
    touched_all: bool,
    /// Current deadline of every PG that has one, and the same ordered by time.
    deadlines: deadline::Index<SpgT>,
}

pub(crate) struct PgMap {
    m: BTreeMap<SpgT, Pg>,
    ix: RefCell<Ix>,
    /// PGs that did work since the last `note_busy`, each once (`PgCounters::ran`); reused, no hot-path allocation.
    ran: Vec<SpgT>,
}

impl Deref for PgMap {
    type Target = BTreeMap<SpgT, Pg>;
    fn deref(&self) -> &Self::Target {
        &self.m
    }
}

impl PgMap {
    pub fn new() -> PgMap {
        PgMap {
            m: BTreeMap::new(),
            ix: RefCell::new(Ix {
                dirty_all: true,
                touched_all: true,
                ..Ix::default()
            }),
            ran: Vec::new(),
        }
    }

    fn mark(&mut self, k: SpgT) {
        let ix = self.ix.get_mut();
        let cap = self.m.len() + 16;
        // one op touches the same PG several times in a row: one mark is enough
        if !ix.dirty_all && ix.dirty.last() != Some(&k) {
            ix.dirty.push(k);
            if ix.dirty.len() > cap {
                ix.dirty_all = true;
                ix.dirty.clear();
            }
        }
        if !ix.touched_all && ix.touched.last() != Some(&k) {
            ix.touched.push(k);
            if ix.touched.len() > cap {
                ix.touched_all = true;
                ix.touched.clear();
            }
        }
    }

    pub fn get_mut(&mut self, k: &SpgT) -> Option<&mut Pg> {
        self.mark(*k);
        self.m.get_mut(k)
    }

    /// Ops and bytes of one work unit of PG `k`, counter-only (neither deadlines nor engine state change); its busy time
    /// arrives with the next `note_busy`.
    pub(crate) fn note_work(&mut self, k: SpgT, ops: u64, bytes: u64) {
        if let Some(p) = self.m.get_mut(&k) {
            p.counters.work_ops = p.counters.work_ops.saturating_add(ops);
            p.counters.work_bytes = p.counters.work_bytes.saturating_add(bytes);
        }
        self.note_ran(k);
    }

    /// Client io of PG `k` into its stats (counter-only, like `note_work`).
    pub(crate) fn note_io(&mut self, k: SpgT, io: &pgwire::IoCount) {
        if let Some(p) = self.m.get_mut(&k) {
            p.info.stats.stats.sum.add_io(io);
        }
    }

    /// PG `k` did work (busy time arrives with the next `note_busy`).
    pub(crate) fn note_ran(&mut self, k: SpgT) {
        if let Some(p) = self.m.get_mut(&k)
            && !p.counters.ran
        {
            p.counters.ran = true;
            self.ran.push(k);
        }
    }

    /// Busy time of one runtime loop iteration (from the loop's one clock read), split evenly over the PGs that did
    /// work in it: per-PG busy time costs no clock read of its own (adr 0006 am. 4).
    pub(crate) fn note_busy(&mut self, ns: u64) {
        let n = self.ran.len() as u64;
        if n == 0 {
            return;
        }
        let (share, rest) = (ns / n, ns % n);
        for (i, k) in self.ran.drain(..).enumerate() {
            if let Some(p) = self.m.get_mut(&k) {
                p.counters.ran = false;
                let ns = share + if i == 0 { rest } else { 0 };
                p.counters.busy_ns = p.counters.busy_ns.saturating_add(ns);
            }
        }
    }

    pub fn insert(&mut self, k: SpgT, v: Pg) -> Option<Pg> {
        self.ix.get_mut().deadlines.register(k);
        self.mark(k);
        self.m.insert(k, v)
    }

    pub fn remove(&mut self, k: &SpgT) -> Option<Pg> {
        self.ix.get_mut().deadlines.unregister(*k);
        self.mark(*k);
        self.m.remove(k)
    }

    /// Give every PG the croit-flashstore-osd peer set (`Pg::nv_peers`).
    pub fn set_nv_peers(&mut self, nv: &std::sync::Arc<std::collections::BTreeSet<i32>>) {
        for p in self.m.values_mut() {
            p.nv_peers = nv.clone();
        }
    }

    /// Give every PG the new tunables (deadlines may depend on them: all are recomputed). Changed interval options
    /// reschedule every queued periodic target (spec scrub.md 12.1.4).
    pub fn set_cfg(&mut self, cfg: &std::sync::Arc<crate::types::Config>) {
        for p in self.m.values_mut() {
            if p.cfg.scrub.schedule_key() != cfg.scrub.schedule_key() {
                p.sp_redraw_targets();
            }
            p.cfg = cfg.clone();
        }
        self.ix.get_mut().dirty_all = true;
    }

    /// Earliest PG timer. Recomputes only the PGs touched since the previous call.
    pub fn next_deadline(&self) -> Option<Mono> {
        self.refresh();
        self.ix.borrow().deadlines.first().map(|(d, _)| d)
    }

    /// PGs whose timer is due at `now`, earliest first (O(due), not O(PGs)).
    pub fn due(&self, now: Mono) -> Vec<SpgT> {
        self.refresh();
        let mut ix = self.ix.borrow_mut();
        ix.deadlines.due(now)
    }

    /// Bring the deadline index up to date with the PGs touched since the previous refresh.
    fn refresh(&self) {
        let mut ix = self.ix.borrow_mut();
        let ix = &mut *ix;
        if ix.dirty_all {
            ix.dirty_all = false;
            ix.dirty.clear();
            for (k, p) in &self.m {
                ix.deadlines.set(*k, p.next_deadline());
            }
        } else {
            let mut dirty = std::mem::take(&mut ix.dirty);
            for k in dirty.drain(..) {
                let new = self.m.get(&k).and_then(|p| p.next_deadline());
                ix.deadlines.set(k, new);
            }
            ix.dirty = dirty; // keeps its capacity: no allocation per op
        }
    }

    /// PGs mutably accessed since the last call, sorted, into `out` (`Listed`). The buffers swap: the caller's (cleared)
    /// one takes the next marks, no allocation per call.
    pub fn take_touched(&mut self, out: &mut Vec<SpgT>) -> Touched {
        let ix = self.ix.get_mut();
        out.clear();
        if std::mem::replace(&mut ix.touched_all, false) {
            ix.touched.clear();
            return Touched::All;
        }
        std::mem::swap(&mut ix.touched, out);
        out.sort_unstable();
        out.dedup();
        Touched::Listed
    }
}
