// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Split gates (adr 0029) and merge readiness reports (split-merge.md 6.1, 6.2).

use super::*;

/// Peers that held the parent of a freshly split child have not necessarily created the child yet: a classic
/// peer that gets a peering message for a child between its creation and its first ActMap aborts (adr 0029).
/// Our sends for the child to such a peer wait until it spoke itself (any message for the child: it has finished
/// the child's ActMap), or until a later map (epoch > split epoch) exists: messages stamped with that epoch wait in
/// the peer's map queue until its child advanced through it, ActMap included (peering.md 7.3 rule 1). Peers known
/// to be croit-flashstore-osd are never gated. Evidence, no clocks: speech, or a later map (NOT a heartbeat epoch: the peer only published it, its child may still sit in Reset).
#[derive(Debug)]
pub(super) struct SplitGate {
    epoch: u32,
    /// OSDs that held the parent before the split.
    watch: BTreeSet<i32>,
    heard: BTreeSet<i32>,
    /// Every other up OSD: a STRAY that still holds the parent (past-interval member, not in up/acting) is probed by the
    /// child too and aborts the same way, but may never speak (found live). Needs evidence like the members.
    strays: BTreeSet<i32>,
}

/// What the local primaries of one pending merge (source and target) reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MergeReg {
    src: MergeStatus,
    tgt: MergeStatus,
}

impl PgSet {
    // ---- merge readiness reports (MOSDPGReadyToMerge, split-merge.md 6.1, 6.2) --------------------------
    /// Re-read the merge status of `spg` after its events and report what changed.
    pub(super) fn note_merge(&mut self, spg: SpgT) {
        let (pairs, st) = match self.pgs.get(&spg) {
            // a stopped instance (peering.md 3.8) never reaches a merge: it reports no readiness
            Some(p) if !p.past_bounds_stopped() => (p.merge_pairs(), p.merge_status()),
            _ => (vec![], MergeStatus::No),
        };
        // every registry entry this PG is part of but no longer announces is cleared
        for (src, e) in self.merge_reg.iter_mut() {
            let is_src = *src == spg.pgid;
            // target of the source after any number of parent steps (pg_num_pending may be below pg_num - 1)
            let is_tgt = src.pool == spg.pgid.pool && {
                let mut t = src.seed;
                while t > spg.pgid.seed {
                    t = pgwire::pgmath::parent(t);
                }
                t == spg.pgid.seed && src.seed != spg.pgid.seed
            };
            if (is_src || is_tgt) && !pairs.iter().any(|(s, _)| s == src) {
                if is_src {
                    e.src = MergeStatus::No;
                } else {
                    e.tgt = MergeStatus::No;
                }
            }
        }
        for (src, is_src) in pairs {
            let e = self.merge_reg.entry(src).or_insert(MergeReg {
                src: MergeStatus::No,
                tgt: MergeStatus::No,
            });
            if is_src {
                e.src = st;
            } else {
                e.tgt = st;
            }
        }
        self.emit_merge_reports();
    }

    /// Is a send to `s.to` for a freshly split child still gated?
    pub(super) fn gated(&self, s: &Send) -> bool {
        !self.flashstore.contains(&s.to)
            && body_spgs(&s.body).iter().any(|g| {
                // shard-agnostic: an EC shard sends from its own shard id to the receiver's (different) shard id
                self.split_gate.range(pgid_range(g.pgid)).any(|(_, gt)| {
                    !gt.heard.contains(&s.to)
                        && (gt.watch.contains(&s.to) || gt.strays.contains(&s.to))
                })
            })
    }

    /// The OSDs known to run croit-flashstore-osd (never gated). Everything else is treated as classic.
    pub fn set_flashstore_peers(&mut self, peers: BTreeSet<i32>) -> Vec<Action> {
        self.nv_arc = std::sync::Arc::new(peers.clone());
        self.pgs.set_nv_peers(&self.nv_arc);
        self.flashstore = peers;
        self.release_held();
        self.finish()
    }

    /// Peers known to store long object names (classic, or croit-flashstore-osd whose store has the bit). Unknown = not listed.
    pub fn set_long_peers(&mut self, peers: BTreeSet<i32>) {
        self.long_peers = peers;
    }

    /// May this OSD, as primary of `spg`, accept an object name that needs the long-name index? Every other member of
    /// up and acting (backfill and async recovery targets are in up) must store it: a replica without the bit refuses
    /// the logged txn and its recovery push (adr 0021 am. 30, OQ 29).
    pub fn long_names_ok(&self, spg: SpgT) -> bool {
        let Some(pg) = self.pgs.get(&spg) else {
            return false;
        };
        let me = pg.me.osd;
        pg.up()
            .iter()
            .chain(pg.acting())
            .all(|o| *o == me || *o < 0 || *o == i32::MAX || self.long_peers.contains(o))
    }

    /// A later map than the split epoch exists: held messages are re-stamped with the current epoch and go out; a
    /// classic peer only handles them after its child advanced through that map, ActMap included.
    pub(super) fn reopen_gates(&mut self) {
        let cur = self.epoch();
        let old: Vec<(SpgT, SplitGate)> = {
            let ks: Vec<SpgT> = self
                .split_gate
                .iter()
                .filter(|(_, g)| g.epoch < cur)
                .map(|(k, _)| *k)
                .collect();
            ks.into_iter()
                .filter_map(|k| self.split_gate.remove(&k).map(|g| (k, g)))
                .collect()
        };
        for (k, g) in old {
            self.trace
                .push(format!("gate {k}: reopened at epoch {cur}"));
            // Both the held sends and the ones produced in this very pass (a late-advanced PG makes the child at an epoch
            // below the current one: its first sends are stamped with the split epoch and never saw the gate): towards a
            // peer that still needs the gate and has not spoken, a stamp at or below the split epoch is fatal for a classic
            // child in Reset. A message from an interval the child has left since is stale (peering regenerates fresh
            // ones), and re-stamping it would make it look current to the classic peer.
            for held in [true, false] {
                let list = if held { &mut self.held } else { &mut self.out };
                let before = list.len();
                let pgs = &self.pgs;
                let nv = &self.flashstore;
                let needs = |s: &Send| {
                    body_spgs(&s.body).iter().any(|x| x.pgid == k.pgid)
                        && !nv.contains(&s.to)
                        && !g.heard.contains(&s.to)
                        && (g.watch.contains(&s.to) || g.strays.contains(&s.to))
                        && (held || s.epoch <= g.epoch)
                };
                list.retain(|a| match a {
                    Action::Send(s) if needs(s) => pgs
                        .get(&k)
                        .is_some_and(|p| p.last_peering_reset() <= s.epoch),
                    _ => true,
                });
                if list.len() < before {
                    self.trace.push(format!(
                        "gate {k}: dropped {} stale held sends",
                        before - list.len()
                    ));
                }
                for a in list.iter_mut() {
                    if let Action::Send(s) = a
                        && needs(s)
                    {
                        s.epoch = cur;
                        if let Body::Peering(p) = &mut s.body {
                            p.restamp(cur);
                        }
                    }
                }
            }
        }
    }

    /// Record that `m.from` spoke about a gated child.
    pub(super) fn note_heard(&mut self, m: &Inbound) {
        let peering = matches!(*m.body, Body::Peering(_));
        if !peering && self.split_gate.is_empty() {
            return; // data path: nothing to record
        }
        let ep = wait_epoch(&m.body);
        let spgs = body_spgs(&m.body);
        if peering
            && let Some(cur) = self.cur.as_ref()
            && ep == cur.epoch()
            && cur.is_up(m.from)
        {
            for s in spgs.iter() {
                // Absent pools/PGs never create split gates in this map. Do not retain unsolicited
                // queries for them: such PGs may never be hosted here and hence never be forgotten.
                if cur
                    .pool(s.pgid.pool)
                    .is_some_and(|p| s.pgid.seed < p.pg_num)
                {
                    self.spoke.insert((m.from, *s), ep);
                }
            }
        }
        for (child, g) in self.split_gate.iter_mut() {
            // only a message of this incarnation of the child counts (an earlier one, from before a merge, does not)
            if ep >= g.epoch && spgs.iter().any(|s| s == child) {
                g.heard.insert(m.from);
            }
        }
    }

    /// Release the held sends whose gate opened (order kept) and retire gates nobody waits for any more.
    pub(super) fn release_held(&mut self) {
        if let Some(cur) = self.cur.clone() {
            let nv = &self.flashstore;
            self.split_gate.retain(|_, g| {
                g.watch
                    .iter()
                    .chain(&g.strays)
                    .any(|o| cur.is_up(*o) && !nv.contains(o) && !g.heard.contains(o))
            });
        }
        if self.held.is_empty() {
            return;
        }

        let (still, go): (Vec<Action>, Vec<Action>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|a| match a {
                Action::Send(s) => self.gated(s),
                _ => false,
            });
        self.held = still;
        // a held message of an interval its PG has left since is stale: peering sends fresh ones
        let pgs = &self.pgs;
        self.out.extend(go.into_iter().filter(|a| {
            match a {
                // by pgid: an EC send names the receiver's shard, not the sending PG's
                Action::Send(s) => body_spgs(&s.body).iter().all(|g| {
                    pgs.range(pgid_range(g.pgid))
                        .all(|(_, p)| p.last_peering_reset() <= s.epoch)
                }),
                _ => true,
            }
        }));
    }

    pub(super) fn emit_merge_reports(&mut self) {
        self.merge_reg
            .retain(|_, e| e.src != MergeStatus::No || e.tgt != MergeStatus::No);
        let reg = &self.merge_reg;
        self.merge_sent.retain(|p| reg.contains_key(p));
        let mut reports = Vec::new();
        for (src, e) in &self.merge_reg {
            if self.merge_sent.contains(src) {
                continue;
            }
            let not_ready = e.src == MergeStatus::NotReady || e.tgt == MergeStatus::NotReady;
            if not_ready {
                reports.push(MergeReport {
                    source: *src,
                    source_version: Eversion::default(),
                    target_version: Eversion::default(),
                    last_epoch_started: 0,
                    last_epoch_clean: 0,
                    ready: false,
                });
            } else if let (
                MergeStatus::Ready {
                    last_update: sv, ..
                },
                MergeStatus::Ready {
                    last_update: tv,
                    last_epoch_started,
                    last_epoch_clean,
                },
            ) = (e.src, e.tgt)
            {
                reports.push(MergeReport {
                    source: *src,
                    source_version: sv,
                    target_version: tv,
                    last_epoch_started,
                    last_epoch_clean,
                    ready: true,
                });
            }
        }
        for r in reports {
            self.merge_sent.insert(r.source);
            self.out.push(Action::ReadyToMerge(r));
        }
    }

    /// Drop a PG and every per-PG side entry (scrub slot, gate, held sends, parked source, merge registry); the
    /// driver is told with `PgRemoved`. Sends nothing and touches no store.
    pub(super) fn forget_pg(&mut self, spg: SpgT) {
        // data of this pool may stay on disk: never decline the pool afterwards (adr 0039 am. 1 point 7). A pool the
        // current map no longer has is deleted (ids are never reused): nothing to guard, the entry would only pile up.
        if self
            .cur
            .as_ref()
            .is_none_or(|m| m.pool(spg.pgid.pool).is_some())
        {
            self.held_pools.insert(spg.pgid.pool);
        }
        self.slots_forget(spg);
        self.split_gate.remove(&spg);
        self.spoke.retain(|k, _| k.1 != spg);
        self.held.retain(|a| match a {
            // by pgid: an EC send names the receiver's shard, not ours
            Action::Send(s) => !body_spgs(&s.body).iter().any(|g| g.pgid == spg.pgid),
            _ => true,
        });
        self.parked_src.retain(|k, _| k.1 != spg);
        self.trace.push(format!("removed {spg}"));
        self.pgs.remove(&spg);
        self.note_merge(spg);
        self.out.push(Action::PgRemoved { spg });
    }

    /// A PG created from a message (or by the mon) in the very epoch that split its parent is a split child for every
    /// classic peer that held the parent, although WE never held it (no local split made a gate): our messages about it
    /// would carry the split epoch and abort such a peer's child while it is still in Reset (found by the classic model:
    /// the new primary of a child with a different placement than its parent, created by a Notify of a peer's child).
    /// Liveness: like every split gate it opens at the latest with map E+1, which the child's primary forces: the
    /// child's interval starts at E and no OSD has up_thru >= E in map E, so its peering requests up_thru.
    /// Created later than E (peers lagging): no gate needed, our stamps are > E and wait in the peer's shard queue.
    pub(super) fn gate_created_child(&mut self, spg: SpgT) {
        let Some(cur) = self.cur.clone() else { return };
        let e = cur.epoch();
        if e < 2 || self.split_gate.contains_key(&spg) {
            return;
        }
        let Some(old) = self.map_at(e - 1).filter(|m| m.epoch() == e - 1) else {
            return;
        };
        let (Some(op), Some(np)) = (old.pool(spg.pgid.pool), cur.pool(spg.pgid.pool)) else {
            return;
        };
        let seed = spg.pgid.seed;
        if np.pg_num <= op.pg_num || seed < op.pg_num || seed >= np.pg_num {
            return;
        }
        let parent = PgT::new(spg.pgid.pool, pgwire::pgmath::ancestor(seed, op.pg_num));
        let mp = old.pg_mapping(parent);
        let me = self.cfg.whoami;
        let watch: BTreeSet<i32> = mp
            .up
            .iter()
            .chain(&mp.acting)
            .copied()
            .filter(|o| *o >= 0 && *o != me)
            .collect();
        self.trace
            .push(format!("gate {spg}: created at split epoch {e}"));
        self.insert_gate(spg, e, watch, &*cur);
    }

    /// Liveness: a gate opens with a map later than the split epoch `e`; ask the mon for one when none exists yet. The
    /// mon proposes a map iff our up_thru < `want` and then records up_thru = the MOSDAlive's version = our map epoch
    /// (osd-lifecycle 4.2; a version above its committed epoch is parked, never answered on an idle cluster). A classic
    /// mon never puts up_thru >= e into map e (version <= committed), so `want` = e (classic: interval start); only if
    /// up_thru already reached e (a map we hold carries it), `up_thru + 1`.
    fn nudge_map(&mut self, e: u32) {
        let Some(cur) = self.cur.clone() else { return };
        if cur.epoch() > e {
            return; // a later map exists: the gate reopens with it
        }
        let want = e.max(cur.up_thru(self.cfg.whoami).saturating_add(1));
        if want > self.up_thru_emitted {
            self.up_thru_want = self.up_thru_want.max(want);
            self.up_thru_emitted = want;
            self.out.push(Action::NeedUpThru { want });
        }
    }

    /// Gate child `ks` split at epoch `e` (map `map`): `watch` held the parent, every other up OSD is a possible stray.
    /// Speech already received about the child at >= `e` counts for watchers and strays alike (the message that
    /// created the child came from a peer whose child ran ActMap, possibly a stray of the parent: gating the answer
    /// to it only delayed peering until the next map).
    pub(super) fn insert_gate(
        &mut self,
        ks: SpgT,
        e: u32,
        watch: BTreeSet<i32>,
        map: &dyn crate::map::PgMapView,
    ) {
        let me = self.cfg.whoami;
        let strays: BTreeSet<i32> = (0..map.max_osd())
            .filter(|o| *o != me && map.is_up(*o) && !watch.contains(o))
            .collect();
        let heard: BTreeSet<i32> = watch
            .iter()
            .chain(&strays)
            .filter(|o| self.spoke.get(&(**o, ks)).is_some_and(|x| *x >= e))
            .copied()
            .collect();
        self.trace
            .push(format!("gate {ks}: watch {watch:?} heard {heard:?}"));
        self.trace.push(format!("gate {ks}: strays {strays:?}"));
        if !watch.is_empty() || !strays.is_empty() {
            self.split_gate.insert(
                ks,
                SplitGate {
                    epoch: e,
                    watch,
                    heard,
                    strays,
                },
            );
            self.nudge_map(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use pgwire::{MOSDPGQuery2, PgQuery};

    fn query(epoch: u32, pool: u64, seed: u32) -> Inbound {
        Inbound {
            ingress: Default::default(),
            from: 1,
            tid: 0,
            prio: pgwire::msgs::PRIO_DEFAULT,
            body: Box::new(Body::Peering(
                MOSDPGQuery2 {
                    spgid: SpgT {
                        pgid: PgT::new(pool, seed),
                        shard: ShardId::NO_SHARD,
                    },
                    query: PgQuery {
                        epoch_sent: epoch,
                        ..Default::default()
                    },
                }
                .into(),
            )),
        }
    }

    #[test]
    fn split_speech_cache_expires_with_the_map_and_ignores_absent_pgs() {
        let mut set = PgSet::new(Config::new(0));
        let map = |epoch| {
            SynthMap::new(epoch)
                .with_osd(0, 1)
                .with_osd(1, 1)
                .with_pool(1, 2, 1, 2)
                .into_handle()
        };
        set.add_map(map(10));
        let child = query(10, 1, 1);
        set.note_heard(&child);
        let spg = target_spg(&child.body).unwrap();
        let cur = set.cur.clone().unwrap();
        set.insert_gate(spg, 10, BTreeSet::from([1]), &*cur);
        assert!(set.split_gate[&spg].heard.contains(&1));
        assert_eq!(set.spoke.len(), 1, "current child speech must be retained");
        set.add_map(map(11));
        assert!(
            set.spoke.is_empty(),
            "old split evidence cannot open new gates"
        );
        for seed in 2..1000 {
            set.note_heard(&query(11, 1, seed));
            set.note_heard(&query(11, seed as u64, 0));
        }
        set.note_heard(&query(10, 1, 1));
        set.note_heard(&query(12, 1, 1));
        assert!(
            set.spoke.is_empty(),
            "irrelevant speech must not accumulate"
        );
    }
}
