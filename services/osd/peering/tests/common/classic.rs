// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Executable model of a CLASSIC ceph-osd as seen by its peers (spec: doc/spec/classic-peer-model.md).
//!
//! Every message the Sim delivers to a node of the classic set is checked against the modeled state of that node's PG
//! copy; a message that would make a classic OSD abort (PeeringState `Crashed`, explicit asserts) fails the test with
//! the reason. Nodes of the classic set also behave like classic towards the others: a freshly split child stays
//! silent until its OSD consumed the NEXT map, shard map consumption lags the published epoch (heartbeats carry the
//! published one), etc. By default every node of every Sim is in the set (the whole cluster is checked); `classic_set`
//! narrows it (a mixed cluster: the rest stands for croit-flashstore-osd peers).
#![allow(clippy::allow_attributes, dead_code)]

use super::*;
use pgwire::PeeringMsg;
use replwire::ReplMsg;

pub use super::classic_table::*;

pub struct Classic {
    rng: Rng,
    /// Nodes treated as classic OSDs (None = every node).
    pub set: Option<BTreeSet<i32>>,
    /// Range of the shard map consumption lag behind the published map (ns).
    pub shard_lag: (Mono, Mono),
    /// Epoch the OSD's shard queues have consumed (lags `published`).
    pub shard: BTreeMap<i32, u32>,
    /// `(osd, child pgid) -> split epoch k`: created at k, no ActMap before the shard consumed a map > k.
    child: BTreeMap<(i32, PgT), u32>,
    /// Sends of children withheld until the child's first ActMap.
    held: Vec<(i32, Send)>,
    shard_last: BTreeMap<i32, Mono>,
    pub violations: Vec<String>,
    /// Panic at the first violation (default); tests that expect one turn it off and read `violations`.
    pub fatal: bool,
    /// Coverage: `"<state> <message>" -> count` of checked deliveries.
    pub cov: BTreeMap<String, u64>,
    pub checked: u64,
    /// Replica reservation substate per PG copy (own bookkeeping: classic ignores a RELEASE in RepWaitRecovery, our stand-in does not).
    rep: BTreeMap<(i32, SpgT), (CSt, u32)>,
    /// `(classic replica, pgid)`: a backfill GET_DIGEST reached it and the primary has not yet received its DIGEST or a
    /// backfill reserve answer. A full classic replica (before tracker 76751) answers nothing, queues BackfillTooFull
    /// behind whatever the primary sends next, and aborts if that moved it out of RepWaitBackfill/RepRecovering.
    /// Value: delivery time of the scan (the full event runs right behind it: a RELEASE a second later is safe).
    scan_open: BTreeMap<(i32, PgT), Mono>,
    pub unchecked: BTreeMap<String, u64>,
    /// PG copies already looked at for split-child detection.
    seen: BTreeSet<(i32, SpgT)>,
    /// Epoch the OSD held when a PG copy first appeared: classic's `last_peering_reset` is at least that (PG creation and
    /// OSD restart reset it).
    born: BTreeMap<(i32, SpgT), u32>,
    restarted: BTreeMap<i32, u32>,
    /// Last deliveries per PG (for violation reports).
    hist: BTreeMap<PgT, std::collections::VecDeque<String>>,
}

impl Classic {
    pub fn new() -> Self {
        Classic {
            rng: Rng::new(0xC1A55),
            set: None,
            shard_lag: (0, 0),
            shard: BTreeMap::new(),
            child: BTreeMap::new(),
            held: vec![],
            shard_last: BTreeMap::new(),
            violations: vec![],
            fatal: true,
            cov: BTreeMap::new(),
            checked: 0,
            rep: BTreeMap::new(),
            scan_open: BTreeMap::new(),
            unchecked: BTreeMap::new(),
            seen: BTreeSet::new(),
            born: BTreeMap::new(),
            restarted: BTreeMap::new(),
            hist: BTreeMap::new(),
        }
    }
    pub fn is_classic(&self, osd: i32) -> bool {
        self.set.as_ref().is_none_or(|s| s.contains(&osd))
    }
}

/// Short name of a message for reports and coverage.
pub fn kind(b: &Body) -> String {
    match b {
        Body::Peering(p) => {
            let n = format!("{p:?}");
            n.split(['(', ' ', '{']).next().unwrap_or("?").to_string()
        }
        Body::Repl(ReplMsg::BackfillReserve(m)) => format!(
            "BackfillReserve.{}",
            [
                "REQUEST",
                "GRANT",
                "REJECT_TOOFULL",
                "RELEASE",
                "REVOKE_TOOFULL",
                "REVOKE"
            ]
            .get(m.ty as usize)
            .unwrap_or(&"?")
        ),
        Body::Repl(ReplMsg::RecoveryReserve(m)) => format!(
            "RecoveryReserve.{}",
            ["REQUEST", "GRANT", "RELEASE", "REVOKE"]
                .get(m.ty as usize)
                .unwrap_or(&"?")
        ),
        Body::Repl(r) => {
            let n = format!("{r:?}");
            n.split(['(', ' ', '{']).next().unwrap_or("?").to_string()
        }
        Body::Ec(e) => {
            let n = format!("{e:?}");
            format!("Ec{}", n.split(['(', ' ', '{']).next().unwrap_or("?"))
        }
    }
}

/// Does the message enter the classic PG's peering state machine as an event (as opposed to the op path)?
/// Stage 1: the peering-class messages that every state before ActMap (Reset/Initial) turns into `Crashed`.
fn is_pg_event(b: &Body) -> bool {
    match b {
        Body::Peering(p) => !matches!(
            p,
            PeeringMsg::MOSDPGRemove(_) | PeeringMsg::MOSDPGCreate2(_)
        ),
        Body::Repl(ReplMsg::BackfillReserve(_) | ReplMsg::RecoveryReserve(_)) => true,
        _ => false,
    }
}

impl Sim {
    /// Check every node as a classic OSD (default) and make every node behave like one.
    pub fn classic_all(&mut self) {
        let c = self.classic.get_or_insert_with(Classic::new);
        c.set = None;
    }
    /// Only these nodes are classic; the others stand for croit-flashstore-osd peers (they are told so: no split gate towards them).
    pub fn classic_set(&mut self, ids: &[i32]) {
        let c = self.classic.get_or_insert_with(Classic::new);
        c.set = Some(ids.iter().copied().collect());
        self.classic_tell_peers();
    }
    pub fn classic_off(&mut self) {
        self.classic = None;
    }
    pub fn classic_violations(&self) -> Vec<String> {
        self.classic
            .as_ref()
            .map(|c| c.violations.clone())
            .unwrap_or_default()
    }
    /// Tell every node which OSDs run croit-flashstore-osd (the non-classic ones); classic stand-ins treat everybody as classic-like
    /// (no gating on their sends: real classic OSDs have no gate).
    pub(super) fn classic_tell_peers(&mut self) {
        let Some(c) = self.classic.as_ref() else {
            return;
        };
        let Some(set) = c.set.clone() else {
            return;
        };
        let all: Vec<i32> = self.nodes.keys().copied().collect();
        let nv: BTreeSet<i32> = all.iter().copied().filter(|o| !set.contains(o)).collect();
        for o in all.clone() {
            let peers = if set.contains(&o) {
                all.iter().copied().collect()
            } else {
                nv.clone()
            };
            if let Some(n) = self.nodes.get_mut(&o) {
                let _ = n.set.set_flashstore_peers(peers);
            }
        }
    }

    /// A map reached the node (its `PgSet` is already past it): split children appear, the shard queues and the
    /// peers learn of the epoch after their delays.
    pub(super) fn classic_on_map(&mut self, osd: i32, epoch: u32) {
        let Some(mut c) = self.classic.take() else {
            return;
        };
        if c.is_classic(osd) {
            // shard consumption after a lag, in order
            let lag = c.shard_lag;
            let d = if lag.1 > lag.0 {
                c.rng.range(lag.0, lag.1)
            } else {
                lag.0
            };
            let last = c.shard_last.get(&osd).copied().unwrap_or(0);
            let at = (self.now + d).max(last + 1);
            c.shard_last.insert(osd, at);
            let inc = self.nodes[&osd].inc;
            if d == 0 && lag.1 == 0 {
                c.shard.insert(osd, epoch);
            } else {
                self.schedule_abs(at, Ev::ShardMap { osd, inc, epoch });
            }
        }
        self.classic = Some(c);
        if self
            .classic
            .as_ref()
            .is_some_and(|c| c.shard.get(&osd) == Some(&epoch))
        {
            self.classic_on_shard(osd, epoch);
        }
    }

    /// After every call into a node: PG copies that appeared are looked at. A split child (created in the epoch that grew
    /// its pool's pg_num, whichever path made it: map advance, a create message advancing an old PG, ...) sits in Reset
    /// while the OSD's shard map is still its creation epoch.
    pub(super) fn classic_scan(&mut self, osd: i32) {
        let Some(mut c) = self.classic.take() else {
            return;
        };
        if let Some(n) = self.nodes.get(&osd).filter(|_| c.is_classic(osd)) {
            let cur = n.set.epoch();
            let shard = c.shard.get(&osd).copied().unwrap_or(cur);
            let present: BTreeSet<SpgT> = n.set.pgs().map(|(k, _)| *k).collect();
            c.seen.retain(|(o, k)| *o != osd || present.contains(k));
            let mut found = vec![];
            for (k, p) in n.set.pgs() {
                if !c.seen.insert((osd, *k)) {
                    continue;
                }
                c.born.insert((osd, *k), cur);
                let h = &p.info().history;
                let e = h.epoch_created;
                if e < 2 || h.last_epoch_split != e || shard > e {
                    continue;
                }
                let (old, new) = (self.map_at(e - 1), self.map_at(e));
                if let (Some(op), Some(np)) =
                    (old.pools.get(&k.pgid.pool), new.pools.get(&k.pgid.pool))
                    && k.pgid.seed >= op.pg_num
                    && k.pgid.seed < np.pg_num
                {
                    found.push((k.pgid, e));
                }
            }
            for (pgid, e) in found {
                c.child.insert((osd, pgid), e);
            }
        }
        self.classic = Some(c);
    }

    /// The OSD's shard queues consumed map `epoch`: its split children advance (ActMap) and may speak.
    pub(super) fn classic_on_shard(&mut self, osd: i32, epoch: u32) {
        let Some(mut c) = self.classic.take() else {
            return;
        };
        let e = c.shard.entry(osd).or_insert(0);
        *e = (*e).max(epoch);
        let cur = *e;
        c.child.retain(|(o, _), k| !(*o == osd && *k < cur));
        let (go, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut c.held)
            .into_iter()
            .partition(|(o, s)| *o == osd && !Self::child_hit(&c, *o, &s.body));
        c.held = keep;
        self.classic = Some(c);
        for (o, mut s) in go {
            // a child that left the interval of the held message says something else now (the stand-in regenerates it)
            let stale = body_spgs(&s.body).iter().any(|g| {
                self.nodes[&o]
                    .set
                    .pgs()
                    .any(|(k, p)| k.pgid == g.pgid && p.last_peering_reset() > s.epoch)
            });
            if stale {
                continue;
            }
            // the child says it now (stamped with the epoch it advanced to), as a classic one would
            s.epoch = s.epoch.max(cur);
            if let Body::Peering(p) = &mut s.body {
                p.restamp(s.epoch);
            }
            self.dispatch(o, vec![Action::Send(Box::new(s))]);
        }
    }

    fn child_hit(c: &Classic, osd: i32, b: &Body) -> bool {
        body_spgs(b)
            .iter()
            .any(|g| c.child.contains_key(&(osd, g.pgid)))
    }

    /// Outbound realism: a child of a split is silent until its OSD consumed a later map. Returns true = withheld.
    pub(super) fn classic_hold_send(&mut self, osd: i32, s: &Send) -> bool {
        let Some(c) = self.classic.as_mut() else {
            return false;
        };
        if !c.is_classic(osd) || !Self::child_hit(c, osd, &s.body) {
            return false;
        }
        c.held.push((osd, s.clone()));
        true
    }

    /// A node restarted: the classic OSD loads its PGs at the current map, no children pending, nothing withheld.
    pub(super) fn classic_on_restart(&mut self, osd: i32) {
        let e = self.epoch();
        if let Some(c) = self.classic.as_mut() {
            c.child.retain(|(o, _), _| *o != osd);
            c.held.retain(|(o, _)| *o != osd);
            c.rep.retain(|(o, _), _| *o != osd);
            c.seen.retain(|(o, _)| *o != osd);
            c.born.retain(|(o, _), _| *o != osd);
            c.restarted.insert(osd, e);
            c.shard.insert(osd, e);
        }
    }

    /// Check one delivery to `to`. Called before the node handles the message.
    pub(super) fn classic_check(&mut self, to: i32, from: i32, body: &Body) {
        let Some(mut c) = self.classic.take() else {
            return;
        };
        // the primary got the replica's answer to its scan: the replica processed the scan without a full event
        if let Body::Repl(ReplMsg::Scan(m)) = body
            && m.op == replwire::MOSDPGScan::OP_DIGEST
        {
            c.scan_open.remove(&(from, m.pgid.pgid));
        }
        // ... or the reaction to its full event (RepRecovering: REVOKE_TOOFULL, RepWaitBackfill: REJECT_TOOFULL)
        if let Body::Repl(ReplMsg::BackfillReserve(m)) = body
            && matches!(
                m.ty,
                replwire::MBackfillReserve::REVOKE_TOOFULL
                    | replwire::MBackfillReserve::REJECT_TOOFULL
            )
        {
            c.scan_open.remove(&(from, m.pgid.pgid));
        }
        if c.is_classic(to) {
            self.classic_check_inner(&mut c, to, from, body);
        }
        self.classic = Some(c);
    }

    /// Classic state of the PG copy on `osd` (the stand-in mirrors classic's machine; the split-child Reset window and
    /// the replica reservation substate are modeled here).
    fn classic_state(&self, c: &Classic, osd: i32, g: SpgT, shard: u32) -> CSt {
        if let Some(k) = c.child.get(&(osd, g.pgid))
            && shard <= *k
        {
            return CSt::Reset;
        }
        let Some(pg) = self.pg(osd, g) else {
            return CSt::NoPg;
        };
        use peering::{ASt, PSt, St};
        match pg.machine_state() {
            St::Reset => CSt::Reset,
            St::Stray => CSt::Stray,
            St::ToDelete => CSt::ToDelete,
            St::ReplicaActive => c
                .rep
                .get(&(osd, g))
                .filter(|(_, lpr)| *lpr == pg.last_peering_reset())
                .map_or(CSt::RepNot, |(s, _)| *s),
            St::Primary(p) => match p {
                PSt::GetInfo => CSt::GetInfo,
                PSt::GetLog => CSt::GetLog,
                PSt::GetMissing => CSt::GetMissing,
                PSt::WaitUpThru => CSt::WaitUpThru,
                PSt::Down => CSt::Down,
                PSt::Incomplete => CSt::Incomplete,
                PSt::WaitActingChange => CSt::WaitActingChange,
                PSt::Active(a) => match a {
                    ASt::WaitRemoteRecoveryReserved => CSt::WaitRemoteRec,
                    ASt::Recovering => CSt::Recovering,
                    ASt::WaitRemoteBackfillReserved => CSt::WaitRemoteBf,
                    ASt::WaitLocalBackfillReserved => CSt::WaitLocalBf,
                    ASt::WaitLocalRecoveryReserved => CSt::ActOther,
                    ASt::Backfilling => CSt::Backfilling,
                    ASt::NotBackfilling => CSt::NotBackfilling,
                    ASt::NotRecovering => CSt::FlagHeld,
                    _ => CSt::ActOther,
                },
            },
        }
    }

    /// An observed send of a classic stand-in (it is the classic OSD): collapses the reservation substate.
    pub(super) fn classic_observe_send(&mut self, osd: i32, s: &Send) {
        let Some(c) = self.classic.as_mut() else {
            return;
        };
        if !c.is_classic(osd) {
            return;
        }
        let (grant, reject) = match &s.body {
            Body::Repl(ReplMsg::RecoveryReserve(m)) => {
                (m.ty == replwire::MRecoveryReserve::GRANT, false)
            }
            Body::Repl(ReplMsg::BackfillReserve(m)) => (
                m.ty == replwire::MBackfillReserve::GRANT,
                m.ty == replwire::MBackfillReserve::REJECT_TOOFULL,
            ),
            _ => return,
        };
        let Some(g) = body_spgs(&s.body).first().copied() else {
            return;
        };
        // the reply names the primary's spg; our key is the same pgid
        let key = c
            .rep
            .keys()
            .find(|(o, k)| *o == osd && k.pgid == g.pgid)
            .copied();
        if let Some(k) = key {
            let lpr = c.rep[&k].1;
            if grant {
                // a GRANT only answers a pending request. The model applies a RELEASE when it is DELIVERED, but the node
                // may process it later (parked until the map): the GRANT it sent in between is real (messages cross),
                // the model already left the wait state: nothing to collapse.
                if matches!(c.rep[&k].0, CSt::RepWaitRec | CSt::RepWaitBf) {
                    c.rep.insert(k, (CSt::RepRec, lpr));
                }
            } else if reject {
                c.rep.insert(k, (CSt::RepNot, lpr));
            }
        }
    }

    fn classic_check_inner(&mut self, c: &mut Classic, to: i32, from: i32, body: &Body) {
        let (stamp, min, _) = gating_of(body);
        let node_epoch = self.nodes[&to].set.epoch();
        let shard = c.shard.get(&to).copied().unwrap_or(node_epoch);
        c.checked += 1;
        if bad_reserve_type(body) {
            let why = format!(
                "osd.{to}: {} from osd.{from} has a reserve type outside the enum: get_event ceph_abort at decode time",
                kind(body)
            );
            self.classic_violation(c, why, &body_spgs(body)[0]);
        }
        for g in body_spgs(body) {
            let h = c.hist.entry(g.pgid).or_default();
            h.push_back(format!(
                "{:>7}ms osd.{from} -> osd.{to} {} stamp {stamp}/{min} (shard {shard})",
                self.now / MS,
                kind(body)
            ));
            if h.len() > 60 {
                h.pop_front();
            }
        }
        if let Body::Repl(ReplMsg::Scan(m)) = body
            && m.op == replwire::MOSDPGScan::OP_GET_DIGEST
        {
            c.scan_open.insert((to, m.pgid.pgid), self.now);
        }
        for (g, ev) in classify(body) {
            // the stand-in's PG left ReplicaActive: the reservation bookkeeping starts over
            if self
                .pg(to, g)
                .is_none_or(|p| p.machine_state() != peering::St::ReplicaActive)
            {
                c.rep.remove(&(to, g));
                c.scan_open.remove(&(to, g.pgid));
            }
            // admission (spec 3): a message of a past interval is dropped, one beyond the map waits
            let lpr = self
                .interval_start(g.pgid, stamp.max(shard).min(self.epoch()))
                .max(c.born.get(&(to, g)).copied().unwrap_or(0))
                .max(c.restarted.get(&to).copied().unwrap_or(0))
                // the stand-in also restarts peering without a new interval (prior set affected by the map), like classic
                .max(self.pg(to, g).map_or(0, |p| p.last_peering_reset()));
            if self.pg(to, g).is_some() && (lpr > stamp || lpr > min) {
                *c.unchecked
                    .entry(format!("old interval {ev:?}"))
                    .or_default() += 1;
                continue;
            }
            let mut st = self.classic_state(c, to, g, shard);
            // classic leaves ToDelete with the next interval (Started::react(AdvMap) -> Reset -> Stray); the stand-in keeps deleting
            if st == CSt::ToDelete
                && self.interval_start(g.pgid, stamp.max(shard).min(self.epoch()))
                    > self.pg(to, g).map_or(0, |p| p.last_peering_reset())
            {
                // ... and Start puts the PG where the new interval says: primary -> Peering/GetInfo, else Stray
                let m = peering::PgMapView::pg_mapping(
                    &*self.map_at(stamp.max(shard).min(self.epoch()).max(1)),
                    g.pgid,
                );
                st = if m.acting_primary == to {
                    CSt::GetInfo
                } else {
                    CSt::Stray
                };
            }
            let mut check = true;
            if st == CSt::Reset {
                // a split child before its first ActMap aborts on stamps == E only (older ones are dropped, newer wait
                // for the map, which brings the ActMap first)
                match c.child.get(&(to, g.pgid)).copied() {
                    Some(k) if stamp == k && min >= k => {}
                    Some(_) => {
                        *c.unchecked
                            .entry(format!("child other stamp {ev:?}"))
                            .or_default() += 1;
                        continue;
                    }
                    None => {}
                }
            } else if stamp > node_epoch {
                *c.unchecked
                    .entry(format!("beyond receiver map {ev:?}"))
                    .or_default() += 1;
                check = false;
            }
            if st == CSt::NoPg {
                // create / drop rules (spec 3.4): only events with create info (Notify, Log) create a PG, and only on an
                // OSD in up or acting of the shard map. The PG is made at the creator's map, advanced to the shard map
                // (`advance_pg`) and then gets the event, so what counts is the role in the shard map: primary ->
                // GetInfo, else Stray (a Notify to a Stray aborts). Everything else for a missing PG is dropped (or
                // answered: Query -> DNE) and cannot abort.
                if !matches!(ev, CEv::Notify | CEv::Log) || !check {
                    *c.unchecked.entry(format!("no pg {ev:?}")).or_default() += 1;
                    continue;
                }
                let m = peering::PgMapView::pg_mapping(
                    &*self.map_at(shard.clamp(1, self.epoch())),
                    g.pgid,
                );
                if !m.up.contains(&to) && !m.acting.contains(&to) {
                    *c.unchecked
                        .entry(format!("create dropped, not up/acting {ev:?}"))
                        .or_default() += 1;
                    continue;
                }
                let lpr = self
                    .interval_start(g.pgid, stamp.max(shard).min(self.epoch()))
                    .max(c.restarted.get(&to).copied().unwrap_or(0));
                if lpr > stamp || lpr > min {
                    *c.unchecked
                        .entry(format!("old interval {ev:?}"))
                        .or_default() += 1;
                    continue;
                }
                st = if m.acting_primary == to {
                    CSt::GetInfo
                } else {
                    CSt::Stray
                };
            }
            let v = verdict(st, ev);
            if check {
                *c.cov.entry(format!("{st:?} {ev:?} {v:?}")).or_default() += 1;
            }
            if v == V::A && check {
                let split = match (st, c.child.get(&(to, g.pgid))) {
                    (CSt::Reset, Some(k)) => format!(
                        "; split child created at epoch {k}, its OSD's shard map is {shard}, no ActMap yet"
                    ),
                    _ => String::new(),
                };
                let mp = |e: u32| {
                    let m = peering::PgMapView::pg_mapping(
                        &*self.map_at(e.clamp(1, self.epoch())),
                        g.pgid,
                    );
                    format!(
                        "e{e}: up {:?} acting {:?} primary {}",
                        m.up, m.acting, m.acting_primary
                    )
                };
                let maps = format!(
                    "{} | {} | lpr {:?} | model lpr {} | shard {shard}",
                    mp(stamp),
                    mp(node_epoch),
                    self.pg(to, g).map(|p| p.last_peering_reset()),
                    self.interval_start(g.pgid, stamp.max(shard).min(self.epoch()))
                );
                let sim_st = self
                    .pg(to, g)
                    .map(|p| format!("{:?} {}", p.machine_state(), p.state_string()));
                let why = format!(
                    "osd.{to} pg {g} in classic state {st:?} [stand-in {sim_st:?}] {{{maps}}}: {ev:?} ({}) from osd.{from} stamped {stamp}/{min} => abort (spec classic-peer-model.md 2.1/2.2){split}",
                    kind(body),
                );
                self.classic_violation(c, why, &g);
            }
            // Stray::react(MInfoRec) asserts (spec missing-loc.md 4.4): after rewinding divergent entries the info's
            // last_update must equal the stray's own; a higher one only for a nonprimary shard covered by pwlc
            if st == CSt::Stray
                && check
                && let Body::Peering(PeeringMsg::MOSDPGInfo2(m)) = body
                && let Some(own) = self.pg(to, g).map(|p| p.info().last_update)
                && m.info.last_update > own
                && !m
                    .info
                    .partial_writes_last_complete
                    .get(&g.shard)
                    .is_some_and(|w| own >= w.0 && w.1 == m.info.last_update)
            {
                let why = format!(
                    "osd.{to} pg {g} Stray: MOSDPGInfo2 from osd.{from} with last_update {:?} above its own {own:?} => \
                     ceph_assert (Stray::react(MInfoRec))",
                    m.info.last_update
                );
                self.classic_violation(c, why, &g);
            }
            // replica reservation substate transitions
            if st == CSt::Stray && matches!(ev, CEv::Log | CEv::Info) {
                st = CSt::RepNot;
            }
            if matches!(
                st,
                CSt::RepNot | CSt::RepWaitRec | CSt::RepWaitBf | CSt::RepRec
            ) {
                let next = match (st, ev) {
                    (CSt::RepNot, CEv::RrReq) => CSt::RepWaitRec,
                    (CSt::RepNot, CEv::BrReq) => CSt::RepWaitBf,
                    (CSt::RepWaitRec, CEv::RrGrant) | (CSt::RepWaitBf, CEv::BrGrant) => CSt::RepRec,
                    (CSt::RepWaitRec | CSt::RepWaitBf, CEv::BrReject | CEv::BrRelease)
                    | (CSt::RepRec, CEv::RrRelease | CEv::BrReject | CEv::BrRelease) => CSt::RepNot,
                    (CSt::RepNot, CEv::RrRelease | CEv::BrReject | CEv::BrRelease) => CSt::RepNot,
                    // RepWait* ignores a recovery RELEASE: the request stays pending
                    (s, _) => s,
                };
                if check
                    && matches!(st, CSt::RepRec | CSt::RepWaitBf)
                    && !matches!(next, CSt::RepRec | CSt::RepWaitBf)
                    && c.scan_open
                        .get(&(to, g.pgid))
                        .is_some_and(|t| self.now < t + 1000 * MS)
                {
                    let why = format!(
                        "osd.{to} pg {g} in classic state {st:?}: {ev:?} ({}) from osd.{from} while its backfill GET_DIGEST \
                         is unanswered => a full replica's queued BackfillTooFull lands in {next:?}: abort before tracker \
                         76751 (spec classic-peer-model.md 5)",
                        kind(body)
                    );
                    self.classic_violation(c, why, &g);
                }
                let lpr = self.pg(to, g).map_or(0, |p| p.last_peering_reset());
                c.rep.insert((to, g), (next, lpr));
            }
        }
    }

    /// Epoch at which the current interval of `pgid` started as of map `at` (mapping or pool size changed, split, merge):
    /// classic's `last_peering_reset` of a PG that advanced to `at`.
    fn interval_start(&self, pgid: PgT, at: u32) -> u32 {
        let key = |e: u32| {
            let m = self.map_at(e);
            (
                peering::PgMapView::pg_mapping(&*m, pgid),
                m.pools.get(&pgid.pool).map(|p| {
                    (
                        p.size,
                        p.min_size,
                        pgwire::pgmath::is_pending_merge(pgid.seed, p.pg_num, p.pg_num_pending),
                    )
                }),
            )
        };
        let pg_num = |e: u32| self.map_at(e).pools.get(&pgid.pool).map(|p| p.pg_num);
        // the PG is a merge source (seed in [to, from)) or a target (parent of one) of `from -> to`
        let merge_rel = |from: u32, to: u32| {
            to < from
                && (pgid.seed >= to && pgid.seed < from
                    || pgid.seed < to
                        && (to..from).any(|c| {
                            pgwire::pgmath::stable_mod(c, to, pgwire::pgmath::pg_num_mask(to))
                                == pgid.seed
                        }))
        };
        let mut e = at.max(1);
        let cur = key(e);
        while e > 1 && key(e - 1) == cur {
            // a pg_num change that does not involve this PG (two other PGs merge) is no interval
            if let (Some(a), Some(b)) = (pg_num(e - 1), pg_num(e))
                && (pgwire::pgmath::is_split(pgid.seed, a, b) || merge_rel(a, b))
            {
                break;
            }
            e -= 1;
        }
        e
    }

    fn classic_violation(&mut self, c: &mut Classic, why: String, g: &SpgT) {
        let ctx = self.trace_of(&format!("{g}"));
        let tail: Vec<&str> = ctx.lines().rev().take(25).collect();
        let epochs: Vec<String> = self
            .log
            .iter()
            .filter(|l| l.contains("EPOCH"))
            .rev()
            .take(5)
            .map(|l| l.chars().take(260).collect())
            .collect();
        let hist_e = epochs.into_iter().rev().collect::<Vec<_>>().join("\n");
        let hist = c
            .hist
            .get(&g.pgid)
            .map(|h| h.iter().cloned().collect::<Vec<_>>().join("\n"))
            .unwrap_or_default();
        let msg = format!(
            "CLASSIC MODEL VIOLATION at {}ms: {why}\n-- recent trace of {g}:\n{}\n-- epochs:\n{hist_e}\n-- deliveries:\n{hist}",
            self.now / MS,
            tail.into_iter().rev().collect::<Vec<_>>().join("\n")
        );
        c.violations.push(msg.clone());
        if c.fatal {
            panic!("{msg}");
        }
    }

    /// One line for failure dumps: what the model currently withholds / waits for.
    pub fn classic_summary(&self) -> String {
        let Some(c) = self.classic.as_ref() else {
            return "classic model: off".into();
        };
        let held: Vec<String> = c
            .held
            .iter()
            .map(|(o, s)| format!("osd.{o}->osd.{} {} e{}", s.to, kind(&s.body), s.epoch))
            .collect();
        format!(
            "classic model: checked {} shard {:?} children {:?} held {:?}",
            c.checked, c.shard, c.child, held
        )
    }
}
