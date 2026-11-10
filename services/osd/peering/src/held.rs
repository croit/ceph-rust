// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Held queue of a replica / EC shard PG (adr 0636): the data-path messages that wait for the store, in arrival order,
//! with the state of the oldest one (the head) in one place.
//!
//! States ([`Held`]):
//! * `Idle`: nothing waits; an arriving message runs at once.
//! * `Busy { head, state, behind }`: `head` is the oldest message that has not run; every later message of the replica
//!   data path ([`HeldMsg::behind`]) queues in `behind`, in arrival order (classic applies a replica's data path in
//!   arrival order). A queued message has its store loads started when it queues ([`Step::kick`]: the blocks of an EC
//!   sub-read), so its device reads overlap the wait of the messages before it instead of starting only when it becomes
//!   the head (one device latency per queued sub-read, one after the other, adr 0636 am. 1); a kick that could not
//!   start them (cold tree path, closed admission) is repeated when a replay leaves it queued. `state` ([`HeadState`]):
//!   * `Due`: not evaluated yet (a replay yielded behind its store persist, or the head was released together with a
//!     persist of the same call): replayed at the PG's next commit or the next timer pass.
//!   * `Wait { on, loads }`: evaluated, waits for `on` ([`WaitOn`]); retried at store wakes and timer passes. `loads`:
//!     its load wait ([`LoadWait`]: slow-op clock + residency lease), opened at its first load verdict and kept until
//!     this head leaves the queue.
//!
//! Transitions (unit tests below):
//!
//! | from | event | to |
//! |---|---|---|
//! | Idle | arrive m: m runs | Idle |
//! | Idle | arrive m: m waits on w | Busy { m, Wait { w, load wait if w is one } } |
//! | Busy | arrive m, `behind` | m kicked and queued behind; over `REPOP_WAIT_*`: forced replay |
//! | Busy | arrive m, not `behind` | m runs (peering control of a new interval, read leases) |
//! | Idle | release m | Busy { m, Due } |
//! | Busy | release m | m queued behind (no bound: the release batch is bounded) |
//! | Busy | replay, head runs | its load wait ends; next message is the head: runs on, or `Due` after a persist; Idle when none |
//! | Busy | replay, head waits on w | Busy { head, Wait { w, load wait kept / opened for a load wait } } |
//! | Busy | replay ends, messages stay queued | those whose kick did not start their loads are kicked again |
//! | Busy { Due } | pause (store admission closed) | Busy { Wait { Admission } } |
//! | any | new interval, merge quiesce, PG leaves the core | Idle: everything dropped (the PG releases its leases) |
//!
//! Invariants: a `behind` message never runs before an older one that has not run; only the head is evaluated (a kick
//! only starts store loads: nothing runs, applies, answers, waits or takes a lease); a load wait belongs to its head
//! and ends exactly when that head leaves (never carried over to the next head); a forced replay forces exactly the
//! first message that reaches its load verdict (never an admission or space wait); one replay runs at most one message
//! that persists; nothing applies or answers because time passed (the clock only reports).

use crate::pg::HeldComplaint;
use crate::types::Mono;
use std::collections::VecDeque;

/// Messages / payload bytes held per PG; beyond that the head is forced: it applies at once (blocking count).
pub(crate) const REPOP_WAIT_MSGS: usize = 64;
pub(crate) const REPOP_WAIT_BYTES: usize = 64 << 20;

/// What an evaluated head waits for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WaitOn {
    /// The store's admission for this PG is closed (`PgStoreOps::admission_ready_for`): store progress reopens it.
    Admission,
    /// Its store shard is at its system floor (`PgStoreOps::apply_room`, adr 0021 S4): store progress makes room. Never
    /// forced.
    Space,
    /// Cold pages / blocks its apply or read touches (`warm*` probes): their loads complete.
    Loads,
}

impl WaitOn {
    /// A wait for store loads: it has a slow-op clock and a residency lease.
    fn is_load(&self) -> bool {
        matches!(self, WaitOn::Loads)
    }
}

/// The load wait of the head: since when it waits (slow op, `WARNING TIMEOUT`) and the residency lease its probes run
/// under (adr 0043 am. 18; 0 = the store needs none).
#[derive(Debug)]
pub(crate) struct LoadWait {
    complaint: HeldComplaint,
    lease: u64,
}

/// State of the head message ([`Held::Busy`]).
#[derive(Debug)]
pub(crate) enum HeadState {
    Due,
    Wait { on: WaitOn, loads: Option<LoadWait> },
}

/// The held queue (module docs).
#[derive(Debug, Default)]
pub(crate) enum Held<M> {
    #[default]
    Idle,
    Busy {
        head: M,
        state: HeadState,
        behind: VecDeque<Queued<M>>,
        /// Payload bytes of the head and of everything behind it, kept as messages come and go: the byte bound is
        /// checked on every arrival and never walks the queue.
        bytes: usize,
    },
}

/// A message queued behind the head; `kicked`: its store loads are started or resident ([`Step::kick`]).
#[derive(Debug)]
pub(crate) struct Queued<M> {
    m: M,
    kicked: bool,
}

/// One evaluation of a holdable message: what its previous wait left and whether a forced replay applies it.
#[derive(Debug, Default)]
pub(crate) struct Probe {
    /// Forced replay: the first message that reaches its load verdict applies without waiting for loads (it takes it).
    pub force: bool,
    /// The residency lease its probes run under (0: none yet).
    pub lease: u64,
}

/// A held message.
pub(crate) trait HeldMsg {
    /// Payload bytes it pins (`REPOP_WAIT_BYTES`).
    fn held_bytes(&self) -> usize;
    /// Does it queue behind a waiting head (`pg::held_behind`)?
    fn behind(&self) -> bool;
}

/// What the held queue needs from its PG.
pub(crate) trait Step<M> {
    /// Run `m` (`Pg::dispatch`). `Some` = it waits for `WaitOn`: nothing applied, logged or answered.
    fn eval(&mut self, m: M, probe: &mut Probe) -> Option<(M, WaitOn)>;
    /// Did a message run since this step began emit a store persist? (the driver queues it and rechecks capacity before
    /// the next held apply)
    fn persisted(&self) -> bool;
    fn lease_open(&mut self) -> u64;
    fn lease_release(&mut self, lease: u64);
    fn now(&self) -> Mono;
    /// Start the store loads of `m`, queued behind a waiting head (`Pg::ec_read_kick`): nothing runs, applies, answers
    /// or takes a lease. `false` = they could not be started yet (cold tree path, closed admission): kicked again when a
    /// replay leaves `m` queued. A message without loads to start answers `true`.
    fn kick(&mut self, m: &M) -> bool;
}

impl<M: HeldMsg> Held<M> {
    /// A message arrives (not from a replay).
    pub(crate) fn arrive(&mut self, m: M, step: &mut impl Step<M>) {
        if let Held::Busy { behind, bytes, .. } = self
            && m.behind()
        {
            // order: behind the head that waits; its loads overlap the wait
            let kicked = step.kick(&m);
            *bytes += m.held_bytes();
            behind.push_back(Queued { m, kicked });
            if self.full() {
                self.replay(true, step); // backpressure: the head applies now (blocking count)
            }
            return;
        }
        let mut probe = Probe::default();
        if let Some((m, on)) = step.eval(m, &mut probe) {
            match self {
                Held::Idle => {
                    let loads = waited(None, &on, step);
                    *self = Held::Busy {
                        bytes: m.held_bytes(),
                        head: m,
                        state: HeadState::Wait { on, loads },
                        behind: VecDeque::new(),
                    };
                }
                Held::Busy { behind, bytes, .. } => {
                    // only `behind` messages wait, and those queue while a head waits; kept in order all the same
                    debug_assert!(false, "a message that does not queue behind a head waited");
                    *bytes += m.held_bytes();
                    behind.push_back(Queued { m, kicked: false });
                }
            }
        }
    }

    /// `m` was released together with an earlier message of this PG that queued a store persist in the same call: it
    /// runs only after that persist is queued (at the next commit or timer pass; OQ 46 a), behind any waiting head.
    pub(crate) fn release(&mut self, m: M) {
        match self {
            Held::Idle => {
                *self = Held::Busy {
                    bytes: m.held_bytes(),
                    head: m,
                    state: HeadState::Due,
                    behind: VecDeque::new(),
                }
            }
            Held::Busy { behind, bytes, .. } => {
                *bytes += m.held_bytes();
                behind.push_back(Queued { m, kicked: false });
            }
        }
    }

    /// Run the held messages in order up to the first one that waits, or up to the one after a message that persisted
    /// (`Due`). `force`: the first message reaching its load verdict applies (`Probe::force`).
    pub(crate) fn replay(&mut self, force: bool, step: &mut impl Step<M>) {
        let Held::Busy {
            mut head,
            state,
            mut behind,
            mut bytes,
        } = std::mem::take(self)
        else {
            return;
        };
        let mut loads = match state {
            HeadState::Due => None,
            HeadState::Wait { loads, .. } => loads,
        };
        let mut force = force;
        loop {
            let mut probe = Probe {
                force,
                lease: loads.as_ref().map_or(0, |l| l.lease),
            };
            let head_bytes = head.held_bytes();
            let waits = step.eval(head, &mut probe);
            force = probe.force;
            if let Some((m, on)) = waits {
                let loads = waited(loads, &on, step);
                kick(&mut behind, step);
                *self = Held::Busy {
                    head: m,
                    state: HeadState::Wait { on, loads },
                    behind,
                    bytes,
                };
                return;
            }
            // the head left the queue (applied, answered or dropped): its load wait and its bytes end with it
            if let Some(l) = loads.take() {
                step.lease_release(l.lease);
            }
            bytes -= head_bytes;
            let Some(Queued { m: next, .. }) = behind.pop_front() else {
                return;
            };
            if step.persisted() {
                kick(&mut behind, step);
                *self = Held::Busy {
                    head: next,
                    state: HeadState::Due,
                    behind,
                    bytes,
                };
                return;
            }
            head = next;
        }
    }

    /// The store admission of the PG is closed: a `Due` head waits for store progress (a store wake), not for an
    /// already-due timer on every core iteration.
    pub(crate) fn pause(&mut self) {
        if let Held::Busy { state, .. } = self
            && matches!(state, HeadState::Due)
        {
            *state = HeadState::Wait {
                on: WaitOn::Admission,
                loads: None,
            };
        }
    }

    /// Drop everything (new interval: the primary aborted these; the PG stops serving). The head's lease is released by
    /// the PG with all its leases (`Pg::release_leases`). Returns the number of messages dropped.
    pub(crate) fn clear(&mut self) -> usize {
        let n = self.len();
        *self = Held::Idle;
        n
    }

    /// Every lease of the PG was released at the store (`Pg::release_leases`): the head's lease id is gone with them.
    pub(crate) fn forget_lease(&mut self) {
        if let Some(l) = self.loads_mut() {
            l.lease = 0;
        }
    }

    /// Report a load wait older than `REPOP_HELD_COMPLAINT_NS` loudly, once per period; `ctx(secs, msgs held)`.
    pub(crate) fn complain(&mut self, now: Mono, ctx: impl FnOnce(u64, usize) -> String) {
        let n = self.len();
        if let Some(l) = self.loads_mut() {
            l.complaint
                .warn(now, "replica write wait for store loads", |secs| {
                    ctx(secs, n)
                });
        }
    }

    /// The head's state for `tell dump_pgs` (`-` when idle): `due`, or `wait <WaitOn>` with the age of its load wait.
    pub(crate) fn describe(&self, now: Mono) -> String {
        match self {
            Held::Idle => "-".into(),
            Held::Busy {
                state: HeadState::Due,
                ..
            } => "due".into(),
            Held::Busy {
                state: HeadState::Wait { on, loads },
                ..
            } => match loads.as_ref().and_then(|l| l.complaint.since()) {
                Some(t) => format!("wait {on:?} for {} ms", now.saturating_sub(t) / 1_000_000),
                None => format!("wait {on:?}"),
            },
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Held::Idle => 0,
            Held::Busy { behind, .. } => 1 + behind.len(),
        }
    }

    pub(crate) fn is_idle(&self) -> bool {
        matches!(self, Held::Idle)
    }

    /// The head is `Due`: replay at the next commit / timer pass.
    pub(crate) fn due(&self) -> bool {
        matches!(
            self,
            Held::Busy {
                state: HeadState::Due,
                ..
            }
        )
    }

    /// Since when the head waits for store loads (None: no load wait).
    pub(crate) fn since(&self) -> Option<Mono> {
        match self {
            Held::Busy {
                state: HeadState::Wait { loads: Some(l), .. },
                ..
            } => l.complaint.since(),
            _ => None,
        }
    }

    fn loads_mut(&mut self) -> Option<&mut LoadWait> {
        match self {
            Held::Busy {
                state: HeadState::Wait { loads: Some(l), .. },
                ..
            } => Some(l),
            _ => None,
        }
    }

    fn full(&self) -> bool {
        let Held::Busy { bytes, .. } = self else {
            return false;
        };
        self.len() >= REPOP_WAIT_MSGS || *bytes >= REPOP_WAIT_BYTES
    }

    /// Payload bytes counted for the queue (tests: it must be the exact sum of the held messages).
    #[cfg(test)]
    fn counted_bytes(&self) -> usize {
        match self {
            Held::Idle => 0,
            Held::Busy { bytes, .. } => *bytes,
        }
    }
}

/// Kick the queued messages whose loads are not started yet (a replay leaves them queued).
fn kick<M>(behind: &mut VecDeque<Queued<M>>, step: &mut impl Step<M>) {
    for q in behind.iter_mut().filter(|q| !q.kicked) {
        q.kicked = step.kick(&q.m);
    }
}

/// The load wait after a wait verdict `on`: a load verdict starts it (clock + lease) or keeps it; an admission or space
/// wait keeps a running one as it is (its clock and pages stay with the head).
fn waited<M>(loads: Option<LoadWait>, on: &WaitOn, step: &mut impl Step<M>) -> Option<LoadWait> {
    if !on.is_load() {
        return loads;
    }
    let mut l = loads.unwrap_or_else(|| {
        let mut complaint = HeldComplaint::default();
        complaint.hold(step.now());
        LoadWait {
            complaint,
            lease: 0,
        }
    });
    if l.lease == 0 {
        l.lease = step.lease_open();
    }
    Some(l)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A test message: `id`, queues behind a head (`b`), payload bytes.
    #[derive(Debug, Clone, Copy, PartialEq)]
    struct T(u32, bool, usize);

    impl HeldMsg for T {
        fn held_bytes(&self) -> usize {
            self.2
        }
        fn behind(&self) -> bool {
            self.1
        }
    }

    fn t(id: u32) -> T {
        T(id, true, 0)
    }

    /// What one evaluation of a message does.
    #[derive(Debug, Clone)]
    enum Out {
        /// Runs (applied / answered / dropped); `persist`: it queued a store persist.
        Run(bool),
        /// Waits without reaching its load verdict.
        Wait(WaitOn),
        /// Reaches its load verdict: takes the force, else waits on `w`.
        Load(WaitOn),
    }

    #[derive(Default)]
    struct Mock {
        /// Per message: the outcomes of its next evaluations (the last one repeats).
        plan: BTreeMap<u32, Vec<Out>>,
        /// Evaluations in order: (id, force, lease as seen).
        seen: Vec<(u32, bool, u64)>,
        persisted: bool,
        leases: Vec<u64>,
        next_lease: u64,
        /// `lease_open` answers 0 (the store needs none) this many times first.
        no_lease: u32,
        released: Vec<u64>,
        now: Mono,
        /// Kicks in order.
        kicks: Vec<u32>,
        /// Per message: the answers of its next kicks (the last one repeats; none = `true`).
        kick_plan: BTreeMap<u32, Vec<bool>>,
    }

    impl Mock {
        fn plan(&mut self, id: u32, o: Vec<Out>) {
            self.plan.insert(id, o);
        }
        fn ids(&self) -> Vec<u32> {
            self.seen.iter().map(|s| s.0).collect()
        }
    }

    impl Step<T> for Mock {
        fn eval(&mut self, m: T, probe: &mut Probe) -> Option<(T, WaitOn)> {
            self.seen.push((m.0, probe.force, probe.lease));
            let p = self
                .plan
                .entry(m.0)
                .or_insert_with(|| vec![Out::Run(false)]);
            let o = if p.len() > 1 {
                p.remove(0)
            } else {
                p[0].clone()
            };
            match o {
                Out::Run(persist) => {
                    self.persisted |= persist;
                    None
                }
                Out::Wait(w) => Some((m, w)),
                Out::Load(w) => {
                    if std::mem::take(&mut probe.force) {
                        None
                    } else {
                        Some((m, w))
                    }
                }
            }
        }
        fn persisted(&self) -> bool {
            self.persisted
        }
        fn lease_open(&mut self) -> u64 {
            if self.no_lease > 0 {
                self.no_lease -= 1;
                return 0;
            }
            self.next_lease += 1;
            self.leases.push(self.next_lease);
            self.next_lease
        }
        fn lease_release(&mut self, lease: u64) {
            if lease != 0 {
                self.leases.retain(|l| *l != lease);
                self.released.push(lease);
            }
        }
        fn now(&self) -> Mono {
            self.now
        }
        fn kick(&mut self, m: &T) -> bool {
            self.kicks.push(m.0);
            match self.kick_plan.get_mut(&m.0) {
                Some(p) if p.len() > 1 => p.remove(0),
                Some(p) => p[0],
                None => true,
            }
        }
    }

    fn head_state(h: &Held<T>) -> Option<(u32, Option<WaitOn>, Option<u64>)> {
        match h {
            Held::Idle => None,
            Held::Busy { head, state, .. } => Some(match state {
                HeadState::Due => (head.0, None, None),
                HeadState::Wait { on, loads } => {
                    (head.0, Some(on.clone()), loads.as_ref().map(|l| l.lease))
                }
            }),
        }
    }

    /// A head waiting for loads at `now` 10 with lease 1 and `behind` queued after it.
    fn waiting(m: &mut Mock, behind: &[u32]) -> Held<T> {
        let mut h = Held::Idle;
        m.now = 10;
        m.plan(1, vec![Out::Load(WaitOn::Loads)]);
        h.arrive(t(1), m);
        for id in behind {
            h.arrive(t(*id), m);
        }
        h
    }

    #[test]
    fn idle_message_runs_at_once() {
        let (mut m, mut h) = (Mock::default(), Held::Idle);
        h.arrive(t(1), &mut m);
        assert!(h.is_idle());
        assert_eq!(m.ids(), [1]);
        assert!(m.leases.is_empty());
        assert!(m.kicks.is_empty(), "nothing to overlap with");
    }

    #[test]
    fn waiting_message_becomes_the_head_with_a_load_wait() {
        let mut m = Mock::default();
        let h = waiting(&mut m, &[]);
        assert_eq!(head_state(&h), Some((1, Some(WaitOn::Loads), Some(1))));
        assert_eq!(h.since(), Some(10));
        assert_eq!(h.len(), 1);
        assert!(!h.due());
    }

    #[test]
    fn admission_and_space_waits_have_no_load_wait() {
        for w in [WaitOn::Admission, WaitOn::Space] {
            let (mut m, mut h) = (Mock::default(), Held::Idle);
            m.plan(1, vec![Out::Wait(w.clone())]);
            h.arrive(t(1), &mut m);
            assert_eq!(head_state(&h), Some((1, Some(w), None)));
            assert_eq!(h.since(), None, "no slow-op clock");
            assert!(m.leases.is_empty(), "no lease");
        }
    }

    #[test]
    fn behind_messages_queue_in_order_and_others_run() {
        let mut m = Mock::default();
        let mut h = waiting(&mut m, &[2, 3]);
        h.arrive(T(4, false, 0), &mut m);
        assert_eq!(
            m.ids(),
            [1, 4],
            "queued messages are not evaluated, control messages run"
        );
        assert_eq!(
            m.kicks,
            [2, 3],
            "queued messages are kicked, control messages not"
        );
        assert_eq!(h.len(), 3);
        m.plan(1, vec![Out::Run(false)]);
        h.replay(false, &mut m);
        assert_eq!(m.ids(), [1, 4, 1, 2, 3], "arrival order");
        assert!(h.is_idle());
        assert_eq!(m.released, [1], "the head's lease ended with it");
        assert!(m.leases.is_empty());
    }

    #[test]
    fn a_kick_that_did_not_start_the_loads_is_repeated_while_the_message_stays_queued() {
        // the tree path of 2 is cold when it queues: its data loads start once a replay finds the path resident
        let mut m = Mock::default();
        m.kick_plan.insert(2, vec![false, false, true]);
        let mut h = waiting(&mut m, &[2, 3]);
        assert_eq!(m.kicks, [2, 3]);
        h.replay(false, &mut m);
        assert_eq!(m.kicks, [2, 3, 2], "only the one not kicked yet");
        h.replay(false, &mut m);
        h.replay(false, &mut m);
        assert_eq!(m.kicks, [2, 3, 2, 2], "kicked once its loads started");
        assert_eq!(m.ids(), [1, 1, 1, 1], "a kick never evaluates");
        assert_eq!(h.len(), 3);
        m.plan(1, vec![Out::Run(false)]);
        h.replay(false, &mut m);
        assert_eq!(m.ids(), [1, 1, 1, 1, 1, 2, 3], "arrival order");
        assert!(h.is_idle());
    }

    #[test]
    fn released_messages_are_kicked_when_a_replay_leaves_them_queued() {
        let mut m = Mock::default();
        let mut h = waiting(&mut m, &[]);
        h.release(t(2));
        h.release(t(3));
        assert!(
            m.kicks.is_empty(),
            "released in a call that persisted: kicked at the next replay"
        );
        h.replay(false, &mut m);
        assert_eq!(m.kicks, [2, 3]);
        // a head that persists leaves the next one due: the ones after it are kicked
        let mut h = waiting(&mut m, &[]);
        h.release(t(4));
        h.release(t(5));
        m.plan(1, vec![Out::Run(true)]);
        h.replay(false, &mut m);
        assert_eq!(head_state(&h), Some((4, None, None)));
        assert_eq!(m.kicks, [2, 3, 5]);
    }

    #[test]
    fn replay_stops_at_the_first_wait_and_the_new_head_gets_its_own_load_wait() {
        let mut m = Mock::default();
        let mut h = waiting(&mut m, &[2, 3]);
        m.plan(1, vec![Out::Run(false)]);
        m.plan(2, vec![Out::Load(WaitOn::Loads)]);
        m.now = 50;
        h.replay(false, &mut m);
        assert_eq!(m.ids(), [1, 1, 2]);
        assert_eq!(head_state(&h), Some((2, Some(WaitOn::Loads), Some(2))));
        assert_eq!(h.since(), Some(50), "the clock of the new head starts now");
        assert_eq!(m.released, [1]);
        assert_eq!(m.leases, [2]);
        assert_eq!(
            m.seen[2].2, 0,
            "the new head's first probe runs without a lease"
        );
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn a_head_dropped_without_applying_ends_its_load_wait() {
        // a duplicate / a message of a PG that left the active state: no lease or clock is left behind
        let mut m = Mock::default();
        let mut h = waiting(&mut m, &[]);
        m.plan(1, vec![Out::Run(false)]);
        h.replay(false, &mut m);
        assert!(h.is_idle());
        assert_eq!(h.since(), None);
        assert!(m.leases.is_empty());
    }

    #[test]
    fn replay_yields_after_a_persist_and_the_next_head_is_due() {
        let mut m = Mock::default();
        let mut h = waiting(&mut m, &[2, 3]);
        m.plan(1, vec![Out::Run(true)]);
        h.replay(false, &mut m);
        assert_eq!(m.ids(), [1, 1], "nothing runs after a persisting message");
        assert_eq!(head_state(&h), Some((2, None, None)));
        assert!(h.due());
        assert_eq!(h.since(), None);
        m.persisted = false;
        h.replay(false, &mut m);
        assert_eq!(m.ids(), [1, 1, 2, 3]);
        assert!(h.is_idle());
    }

    #[test]
    fn the_head_keeps_its_load_wait_through_admission_and_space_waits() {
        let mut m = Mock::default();
        let mut h = waiting(&mut m, &[2]);
        m.plan(
            1,
            vec![
                Out::Wait(WaitOn::Admission),
                Out::Wait(WaitOn::Space),
                Out::Load(WaitOn::Loads),
                Out::Run(false),
            ],
        );
        for (now, want) in [
            (20, WaitOn::Admission),
            (30, WaitOn::Space),
            (40, WaitOn::Loads),
        ] {
            m.now = now;
            h.replay(false, &mut m);
            assert_eq!(head_state(&h), Some((1, Some(want), Some(1))));
            assert_eq!(
                h.since(),
                Some(10),
                "one clock for the whole wait of the head"
            );
        }
        assert_eq!(m.seen.iter().map(|s| s.2).collect::<Vec<_>>(), [0, 1, 1, 1]);
        h.replay(false, &mut m);
        assert!(h.is_idle());
        assert_eq!(m.released, [1]);
        assert_eq!(m.next_lease, 1, "one lease for the head");
    }

    #[test]
    fn a_lease_the_store_did_not_give_is_asked_again_at_the_next_load_verdict() {
        let mut m = Mock {
            no_lease: 1,
            ..Default::default()
        };
        let mut h = waiting(&mut m, &[]);
        assert_eq!(head_state(&h), Some((1, Some(WaitOn::Loads), Some(0))));
        h.replay(false, &mut m);
        assert_eq!(head_state(&h), Some((1, Some(WaitOn::Loads), Some(1))));
        assert_eq!(h.since(), Some(10));
    }

    #[test]
    fn released_messages_wait_for_the_next_replay() {
        let (mut m, mut h) = (Mock::default(), Held::Idle);
        h.release(t(1));
        h.release(t(2));
        assert!(m.seen.is_empty());
        assert!(h.due());
        assert_eq!(h.len(), 2);
        h.replay(false, &mut m);
        assert_eq!(m.ids(), [1, 2]);
        assert!(h.is_idle());
    }

    #[test]
    fn a_release_behind_a_waiting_head_keeps_the_head_waiting() {
        let mut m = Mock::default();
        let mut h = waiting(&mut m, &[]);
        h.release(t(2));
        assert!(!h.due(), "no early re-evaluation of the waiting head");
        assert_eq!(head_state(&h), Some((1, Some(WaitOn::Loads), Some(1))));
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn pause_turns_a_due_head_into_an_admission_wait() {
        let (mut m, mut h) = (Mock::default(), Held::Idle);
        h.release(t(1));
        h.pause();
        assert_eq!(head_state(&h), Some((1, Some(WaitOn::Admission), None)));
        assert!(!h.due());
        let mut w = waiting(&mut m, &[]);
        w.pause();
        assert_eq!(
            head_state(&w),
            Some((1, Some(WaitOn::Loads), Some(1))),
            "a waiting head stays as it is"
        );
    }

    #[test]
    fn a_full_queue_forces_the_first_load_verdict_only() {
        let mut m = Mock::default();
        let mut h = waiting(&mut m, &[]);
        m.plan(2, vec![Out::Load(WaitOn::Loads)]);
        for id in 2..REPOP_WAIT_MSGS as u32 {
            h.arrive(t(id), &mut m);
        }
        assert_eq!(m.ids(), [1], "below the bound nothing runs");
        h.arrive(t(REPOP_WAIT_MSGS as u32), &mut m);
        assert_eq!(m.ids(), [1, 1, 2], "the head is forced, the next one waits");
        assert!(m.seen[1].1 && !m.seen[2].1);
        assert_eq!(head_state(&h), Some((2, Some(WaitOn::Loads), Some(2))));
        assert_eq!(m.released, [1]);
    }

    #[test]
    fn the_force_skips_admission_and_space_waits_and_ends_with_the_replay() {
        let mut m = Mock::default();
        let mut h = waiting(&mut m, &[]);
        m.plan(1, vec![Out::Wait(WaitOn::Space), Out::Load(WaitOn::Loads)]);
        h.replay(true, &mut m);
        assert_eq!(
            head_state(&h),
            Some((1, Some(WaitOn::Space), Some(1))),
            "space is never forced"
        );
        h.replay(false, &mut m);
        assert!(!m.seen[2].1, "a later replay is not forced");
        assert_eq!(head_state(&h), Some((1, Some(WaitOn::Loads), Some(1))));
    }

    #[test]
    fn the_byte_bound_forces_too() {
        let mut m = Mock::default();
        let mut h = waiting(&mut m, &[]);
        m.plan(1, vec![Out::Load(WaitOn::Loads)]);
        h.arrive(T(2, true, REPOP_WAIT_BYTES), &mut m);
        assert_eq!(m.ids(), [1, 1, 2]);
        assert!(h.is_idle());
    }

    /// The counted payload bytes are the exact sum of the held messages through arrivals, releases, replays and drops:
    /// the byte bound (`REPOP_WAIT_BYTES`) reads that one number per arrival instead of summing the whole queue (R3).
    #[test]
    fn the_counted_bytes_follow_every_arrival_release_and_replay() {
        let mut m = Mock::default();
        let mut h = Held::Idle;
        m.plan(1, vec![Out::Load(WaitOn::Loads)]);
        h.arrive(T(1, true, 100), &mut m);
        let mut want = 100;
        assert_eq!(h.counted_bytes(), want, "the head is counted");
        for (id, bytes) in [(2, 30), (3, 0), (4, 1000)] {
            h.arrive(T(id, true, bytes), &mut m);
            want += bytes;
            assert_eq!(h.counted_bytes(), want);
        }
        h.release(T(5, true, 7));
        want += 7;
        assert_eq!(h.counted_bytes(), want, "a released message is counted");
        // the head leaves the queue: its bytes leave with it, the next one is the head
        m.plan(2, vec![Out::Wait(WaitOn::Admission)]);
        m.plan(1, vec![Out::Run(false)]);
        h.replay(false, &mut m);
        want -= 100;
        assert_eq!(
            head_state(&h),
            Some((2, Some(WaitOn::Admission), None)),
            "2 is the head"
        );
        assert_eq!(h.counted_bytes(), want);
        // a pause and a complaint only report
        h.pause();
        h.complain(10, |_, _| String::new());
        assert_eq!(h.counted_bytes(), want);
        h.clear();
        assert_eq!(h.counted_bytes(), 0, "the queue is empty");
    }

    #[test]
    fn clear_drops_everything_and_leaves_the_leases_to_the_pg() {
        let mut m = Mock::default();
        let mut h = waiting(&mut m, &[2, 3]);
        assert_eq!(h.clear(), 3);
        assert!(h.is_idle());
        assert_eq!(h.since(), None);
        assert!(
            m.released.is_empty(),
            "the PG releases all its leases at once"
        );
        let mut h = waiting(&mut m, &[]);
        h.forget_lease();
        assert_eq!(head_state(&h), Some((1, Some(WaitOn::Loads), Some(0))));
    }

    #[test]
    fn the_complaint_reports_once_per_period_and_never_runs_anything() {
        let mut m = Mock::default();
        let mut h = waiting(&mut m, &[2]);
        let mut said = vec![];
        for now in [
            10,
            crate::pg::REPOP_HELD_COMPLAINT_NS + 10,
            crate::pg::REPOP_HELD_COMPLAINT_NS + 20,
        ] {
            h.complain(now, |secs, n| {
                said.push((secs, n));
                String::new()
            });
        }
        assert_eq!(
            said,
            [(crate::pg::REPOP_HELD_COMPLAINT_NS / crate::types::SEC, 2)]
        );
        assert_eq!(m.ids(), [1]);
        assert_eq!(h.len(), 2);
    }
}
