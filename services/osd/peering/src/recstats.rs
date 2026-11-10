// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Peering-state timing table behind `dump_pg_recovery_stats` / `reset_pg_recovery_stats` (spec osd-tell-gaps.md 1).
//!
//! Classic keeps one OSD-wide table keyed by the nested state names of its peering state machine. Ours has a flat
//! [`St`], so each state is mapped onto the classic path (`Started/Primary/Active/Clean`); a transition exits the
//! levels below the common ancestor and enters the levels of the target, like the classic machine. Classic states with
//! no equivalent here (`Initial`, `Start`, `Crashed`, `ToDelete/Deleting`, the replica reservation substates) never
//! get a row. Per-event counts (`events`, `event_time`) need an event notion our PGs do not have and stay zero.
//!
//! Cost: a transition pushes `(state, now)` into a small per-PG buffer ([`StTrack`], no allocation once grown); the
//! owning [`PgSet`](crate::PgSet) folds it into its fixed array while collecting the PG's actions. No locks, the table
//! lives on the owning core; the OSD merges the per-core tables when it dumps.
use crate::pg::{ASt, PSt, St};
use crate::types::Mono;

/// Classic state path names (all `/`-separated nested names this machine can show), indexed by the `S_*` ids.
pub const NAMES: [&str; 26] = [
    "Reset",
    "Started",
    "Started/Primary",
    "Started/Primary/Peering",
    "Started/Primary/Peering/GetInfo",
    "Started/Primary/Peering/GetLog",
    "Started/Primary/Peering/GetMissing",
    "Started/Primary/Peering/WaitUpThru",
    "Started/Primary/Peering/Down",
    "Started/Primary/Peering/Incomplete",
    "Started/Primary/WaitActingChange",
    "Started/Primary/Active",
    "Started/Primary/Active/Activating",
    "Started/Primary/Active/Clean",
    "Started/Primary/Active/Recovered",
    "Started/Primary/Active/Recovering",
    "Started/Primary/Active/NotRecovering",
    "Started/Primary/Active/Backfilling",
    "Started/Primary/Active/NotBackfilling",
    "Started/Primary/Active/WaitLocalRecoveryReserved",
    "Started/Primary/Active/WaitRemoteRecoveryReserved",
    "Started/Primary/Active/WaitLocalBackfillReserved",
    "Started/Primary/Active/WaitRemoteBackfillReserved",
    "Started/ReplicaActive",
    "Started/Stray",
    "Started/ToDelete",
];

const S_RESET: u8 = 0;
const S_STARTED: u8 = 1;
const S_PRIMARY: u8 = 2;
const S_PEERING: u8 = 3;
const S_WAIT_ACTING: u8 = 10;
const S_ACTIVE: u8 = 11;
const S_REPLICA: u8 = 23;
const S_STRAY: u8 = 24;
const S_TO_DELETE: u8 = 25;

/// Deepest nesting (`Started/Primary/Active/<leaf>`, `Started/Primary/Peering/<leaf>`).
const DEPTH: usize = 4;

/// Name ids from the root to the leaf of `st` (`[id; len]`).
fn chain(st: St) -> ([u8; DEPTH], usize) {
    let (a, b, c, d, n) = match st {
        St::Reset => (S_RESET, 0, 0, 0, 1),
        St::Stray => (S_STARTED, S_STRAY, 0, 0, 2),
        St::ReplicaActive => (S_STARTED, S_REPLICA, 0, 0, 2),
        St::ToDelete => (S_STARTED, S_TO_DELETE, 0, 0, 2),
        St::Primary(PSt::WaitActingChange) => (S_STARTED, S_PRIMARY, S_WAIT_ACTING, 0, 3),
        St::Primary(PSt::Active(a)) => (S_STARTED, S_PRIMARY, S_ACTIVE, active_id(a), 4),
        St::Primary(p) => (S_STARTED, S_PRIMARY, S_PEERING, peering_id(p), 4),
    };
    ([a, b, c, d], n)
}

fn peering_id(p: PSt) -> u8 {
    match p {
        PSt::GetInfo => 4,
        PSt::GetLog => 5,
        PSt::GetMissing => 6,
        PSt::WaitUpThru => 7,
        PSt::Down => 8,
        PSt::Incomplete => 9,
        // not Peering substates: `chain` never asks
        PSt::WaitActingChange | PSt::Active(_) => S_PEERING,
    }
}

fn active_id(a: ASt) -> u8 {
    match a {
        ASt::Activating => 12,
        ASt::Clean => 13,
        ASt::Recovered => 14,
        ASt::Recovering => 15,
        ASt::NotRecovering => 16,
        ASt::Backfilling => 17,
        ASt::NotBackfilling => 18,
        ASt::WaitLocalRecoveryReserved => 19,
        ASt::WaitRemoteRecoveryReserved => 20,
        ASt::WaitLocalBackfillReserved => 21,
        ASt::WaitRemoteBackfillReserved => 22,
    }
}

/// One row: counters of a state name, durations in ns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StateRow {
    pub enter: u64,
    pub exit: u64,
    /// Events handled while in the state (always 0: no per-PG event notion, see the module doc).
    pub events: u64,
    /// Time spent handling those events (always 0).
    pub event_ns: u64,
    /// Sum of the visit durations (exit - enter).
    pub total_ns: u64,
    /// Shortest / longest single visit (0 = none yet).
    pub min_ns: u64,
    pub max_ns: u64,
}

impl StateRow {
    fn seen(&self) -> bool {
        self.enter != 0 || self.exit != 0
    }

    /// Add `o` (another core's row of the same state).
    pub fn merge(&mut self, o: &StateRow) {
        self.enter += o.enter;
        self.exit += o.exit;
        self.events += o.events;
        self.event_ns += o.event_ns;
        self.total_ns += o.total_ns;
        if o.min_ns != 0 && (self.min_ns == 0 || o.min_ns < self.min_ns) {
            self.min_ns = o.min_ns;
        }
        self.max_ns = self.max_ns.max(o.max_ns);
    }
}

/// The timing table of one core.
#[derive(Debug, Default)]
pub struct RecStats {
    rows: [StateRow; NAMES.len()],
}

impl RecStats {
    /// `reset_pg_recovery_stats`.
    pub fn reset(&mut self) {
        *self = RecStats::default();
    }

    /// Rows that were entered or exited at least once, by name.
    pub fn rows(&self) -> impl Iterator<Item = (&'static str, &StateRow)> {
        NAMES
            .iter()
            .copied()
            .zip(self.rows.iter())
            .filter(|(_, r)| r.seen())
    }

    fn exit(&mut self, id: u8, dur: u64) {
        let r = &mut self.rows[usize::from(id)];
        r.exit += 1;
        r.total_ns += dur;
        r.max_ns = r.max_ns.max(dur);
        if r.min_ns == 0 || dur < r.min_ns {
            r.min_ns = dur;
        }
    }
}

/// Per-PG state: the open visits (name id, enter time) from the root, and the transitions not folded yet.
#[derive(Debug, Default)]
pub(crate) struct StTrack {
    open: [(u8, Mono); DEPTH],
    depth: usize,
    pend: Vec<(St, Mono)>,
}

impl StTrack {
    /// The PG enters `st` at `now`.
    pub(crate) fn push(&mut self, st: St, now: Mono) {
        self.pend.push((st, now));
    }

    /// Fold the pending transitions into `rs`.
    pub(crate) fn fold(&mut self, rs: &mut RecStats) {
        if self.pend.is_empty() {
            return;
        }
        let mut pend = std::mem::take(&mut self.pend);
        for (st, t) in pend.drain(..) {
            let (ids, n) = chain(st);
            let mut keep = 0;
            while keep < self.depth && keep < n && self.open[keep].0 == ids[keep] {
                keep += 1;
            }
            for l in (keep..self.depth).rev() {
                rs.exit(self.open[l].0, t.saturating_sub(self.open[l].1));
            }
            for (l, id) in ids.iter().copied().enumerate().take(n).skip(keep) {
                rs.rows[usize::from(id)].enter += 1;
                self.open[l] = (id, t);
            }
            self.depth = n;
        }
        self.pend = pend;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_states() -> Vec<St> {
        use ASt::*;
        let mut v = vec![St::Reset, St::Stray, St::ReplicaActive, St::ToDelete];
        for p in [
            PSt::GetInfo,
            PSt::GetLog,
            PSt::GetMissing,
            PSt::WaitUpThru,
            PSt::Down,
            PSt::Incomplete,
            PSt::WaitActingChange,
        ] {
            v.push(St::Primary(p));
        }
        for a in [
            Activating,
            WaitLocalRecoveryReserved,
            WaitRemoteRecoveryReserved,
            Recovering,
            NotRecovering,
            WaitLocalBackfillReserved,
            WaitRemoteBackfillReserved,
            Backfilling,
            NotBackfilling,
            Recovered,
            Clean,
        ] {
            v.push(St::Primary(PSt::Active(a)));
        }
        v
    }

    /// The id chain of every state spells its classic nested name, and every prefix is itself a name.
    #[test]
    fn chains_spell_the_classic_paths() {
        for st in all_states() {
            let (ids, n) = chain(st);
            let leaf = NAMES[usize::from(ids[n - 1])];
            for (l, id) in ids[..n].iter().enumerate() {
                let want: Vec<&str> = leaf.split('/').take(l + 1).collect();
                assert_eq!(NAMES[usize::from(*id)], want.join("/"), "{st:?} level {l}");
            }
            assert_eq!(leaf.split('/').count(), n, "{st:?}");
        }
    }

    #[test]
    fn transitions_exit_and_enter_below_the_common_ancestor() {
        let mut rs = RecStats::default();
        let mut t = StTrack::default();
        let act = |a| St::Primary(PSt::Active(a));
        t.push(St::Reset, 0);
        t.push(St::Primary(PSt::GetInfo), 10);
        t.push(act(ASt::Activating), 40);
        t.push(act(ASt::Recovering), 100);
        t.push(act(ASt::Clean), 160);
        t.fold(&mut rs);
        fn row(rs: &RecStats, n: &str) -> StateRow {
            *rs.rows().find(|(k, _)| *k == n).unwrap().1
        }
        let started = row(&rs, "Started");
        assert_eq!((started.enter, started.exit), (1, 0), "never left");
        let active = row(&rs, "Started/Primary/Active");
        assert_eq!((active.enter, active.exit), (1, 0));
        let peering = row(&rs, "Started/Primary/Peering");
        assert_eq!((peering.enter, peering.exit, peering.total_ns), (1, 1, 30));
        let rec = row(&rs, "Started/Primary/Active/Recovering");
        assert_eq!((rec.enter, rec.exit, rec.total_ns), (1, 1, 60));
        assert_eq!((rec.min_ns, rec.max_ns), (60, 60));
        let reset = row(&rs, "Reset");
        assert_eq!((reset.enter, reset.exit, reset.total_ns), (1, 1, 10));
        // a new interval leaves the whole branch, bottom up
        t.push(St::Reset, 500);
        t.fold(&mut rs);
        let clean = row(&rs, "Started/Primary/Active/Clean");
        assert_eq!((clean.exit, clean.total_ns), (1, 340));
        let started = row(&rs, "Started");
        assert_eq!((started.exit, started.total_ns), (1, 500 - 10));
        assert!(rs.rows().all(|(n, _)| n != "Started/Stray"));
        rs.reset();
        assert_eq!(rs.rows().count(), 0);
    }

    #[test]
    fn min_ignores_zero_and_merge_adds() {
        let mut a = StateRow {
            enter: 1,
            exit: 1,
            total_ns: 5,
            min_ns: 5,
            max_ns: 5,
            ..Default::default()
        };
        let b = StateRow {
            enter: 2,
            exit: 1,
            total_ns: 9,
            min_ns: 3,
            max_ns: 9,
            ..Default::default()
        };
        a.merge(&b);
        assert_eq!(
            (a.enter, a.exit, a.total_ns, a.min_ns, a.max_ns),
            (3, 2, 14, 3, 9)
        );
        a.merge(&StateRow::default());
        assert_eq!(a.min_ns, 3);
    }
}
