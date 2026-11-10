// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Local workload diagnostics. These counters never enter the mgr counter catalogue or PG wire statistics.
use crate::{backend::Backend, osd::Osd};
use denc::types::SpgT;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Utilization {
    /// Internal counter lifetime; zero for a core, the PG's construction ID otherwise.
    pub generation: u64,
    pub busy_ns: u64,
    pub ops: u64,
    pub bytes: u64,
    /// Drains (PG-core inbox, messenger event pump) stopped by the work slice with work left (adr 0006 am. 4); cores only.
    pub slice_cuts: u64,
    /// Retained client/peer input per cause (`HoldWhy` order): episodes, total and longest held time; cores only.
    pub holds: [HoldStat; HoldWhy::ALL.len()],
    /// Kernel tier transport of this core, cumulative (cores only; adr 0474 am. 1): bytes received, receive pauses (ingress
    /// pool full) and their wall ns, working loop iterations >= 1 / 10 / 100 ms (every socket of the core unread that long).
    pub rx_bytes: u64,
    pub rx_pauses: u64,
    pub rx_pause_ns: u64,
    pub long_iters: [u64; 3],
    /// PG deletion steps that queued a txn (cores only; adr 0524 am. 1): back to back (no client demand for a gap), paced.
    pub rm_steps: [u64; 2],
}

/// Why a decoded message was retained instead of run (`Osd::hold_input`); the link reads no further input meanwhile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum HoldWhy {
    /// An earlier retained message of the same input lane goes first.
    #[default]
    Fifo,
    /// The cross-core output queue is full (`XOUT_MAX`).
    Xout,
    /// The PG's store shard admits no new write (`admission_ready_for`).
    Store,
    /// The lane's ingress byte window is exhausted (released when earlier ops finish).
    Ingress,
}

impl HoldWhy {
    pub(crate) const ALL: [HoldWhy; 4] = [
        HoldWhy::Fifo,
        HoldWhy::Xout,
        HoldWhy::Store,
        HoldWhy::Ingress,
    ];
    pub(crate) fn name(self) -> &'static str {
        match self {
            HoldWhy::Fifo => "fifo",
            HoldWhy::Xout => "xout",
            HoldWhy::Store => "store",
            HoldWhy::Ingress => "ingress",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HoldStat {
    pub n: u64,
    pub ns: u64,
    pub max_ns: u64,
}

impl<B: Backend> Osd<B> {
    /// Busy time of the previous runtime loop iteration, from the loop's one clock read; idle polling is excluded. The
    /// PGs that did work in that iteration share it; it also teaches the drain work slice (adr 0006 am. 4).
    pub fn note_core_busy(&mut self, ns: u64) {
        self.perf.util.busy_ns = self.perf.util.busy_ns.saturating_add(ns);
        self.perf.op.loop_busy_iters += 1;
        self.perf.op.loop_busy_ns += ns;
        self.pg.set.note_busy(ns);
        // listing continuations (adr 0522) and background work (store merges, compactions, checkpoints, PG deletion
        // steps; compaction helper steps) hand no units to the slice: their time is no cost of the units; the next drains
        // may take as long as the background work took (fair share)
        let bg = peering::PgStoreOps::bg_ns(&self.pg.store) + self.cl.helper_ns;
        self.slice.learn(
            ns.saturating_sub(self.pg.share.listed_ns())
                .saturating_sub(bg),
        );
        self.slice.share(bg);
    }

    /// Ops and bytes of one PG work unit; its busy time arrives with the next `note_core_busy`.
    pub(crate) fn note_pg_work(&mut self, spg: SpgT, ops: u64, bytes: u64) {
        self.perf.util.ops = self.perf.util.ops.saturating_add(ops);
        self.perf.util.bytes = self.perf.util.bytes.saturating_add(bytes);
        self.pg.set.note_work(spg, ops, bytes);
    }

    /// A drain of the PG-core inbox starts: the work units each source core may hand on in it (learned slice, adr 0006
    /// am. 4; at least what the own links handed on since the previous drain, am. 6).
    pub fn start_drain(&mut self) -> usize {
        self.slice.start_drain()
    }

    /// Work units the PG-core inbox handed on in this iteration (one call per drain).
    /// Listing pressure is collected independently across local and forwarded work
    /// and consumed at the next store poll, including on cores without an inbox.
    pub fn slice_add(&mut self, units: usize) {
        self.slice.add(units);
    }

    /// A retained input was resumed after `held` (one hold episode of cause `why`).
    pub(crate) fn note_hold(&mut self, why: HoldWhy, held: std::time::Duration) {
        let s = &mut self.perf.util.holds[why as usize];
        let ns = held.as_nanos() as u64;
        s.n += 1;
        s.ns = s.ns.saturating_add(ns);
        s.max_ns = s.max_ns.max(ns);
    }

    /// A drain stopped by the work slice with work left.
    pub fn note_slice_cut(&mut self) {
        self.perf.util.slice_cuts += 1;
    }

    /// Kernel tier driver hook, every loop iteration: the transport's cumulative counters of this core (absolute values).
    pub fn note_net_diag(
        &mut self,
        rx_bytes: u64,
        rx_pauses: u64,
        rx_pause_ns: u64,
        long_iters: [u64; 3],
    ) {
        let u = &mut self.perf.util;
        u.rx_bytes = rx_bytes;
        u.rx_pauses = rx_pauses;
        u.rx_pause_ns = rx_pause_ns;
        u.long_iters = long_iters;
    }

    pub(crate) fn pg_utilization(&self) -> Vec<(SpgT, Utilization)> {
        self.pg
            .set
            .pgs()
            .map(|(spg, p)| {
                let c = p.counters();
                (
                    *spg,
                    Utilization {
                        generation: c.work_generation,
                        busy_ns: c.busy_ns,
                        ops: c.work_ops,
                        bytes: c.work_bytes,
                        ..Default::default()
                    },
                )
            })
            .collect()
    }
}
