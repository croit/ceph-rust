// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Map cache, epoch lookup, trimming and the old-map park/replay (open question 13d).

use super::*;

/// A create-from-message waiting for old maps, with what arrived for its PG meanwhile (replayed behind it, in order).
pub(super) struct ParkedOld {
    epoch: u32,
    m: Inbound,
    pub(super) after: Vec<Inbound>,
    /// Next epoch to ask for, and the last one the replay must reach (oldest kept map - 1 when parked).
    next: u32,
    last: u32,
    /// The PG and the children it split off so far, advanced through the chunks done (not in `pgs`).
    hold: BTreeMap<SpgT, Pg>,
    /// Actions the held PGs produced on the way (store writes, ...): driven only once the PG is in the set, a commit
    /// ack for a PG not in the set would be lost.
    deferred: Vec<Action>,
}

/// Bound of [`PgSet::parked_old`] (PGs) and of each PG's `after` queue.
pub(super) const PARK_MAX: usize = 1024;

impl PgSet {
    /// Remember a map without advancing PGs (startup: feed the retained maps oldest first).
    pub fn add_map(&mut self, m: MapHandle) {
        let e = m.epoch();
        if self.cur.as_ref().is_none_or(|c| c.epoch() < e) {
            // Only a gate created in this map can need remembered speech. Older gates reopen on this
            // advance; future-map messages are recorded again when routing releases their map wait.
            self.spoke.clear();
            self.cur = Some(m.clone());
        }
        self.maps.insert(e, m);
    }

    /// Map a stored PG (persisted at `epoch`) is loaded at: that epoch, else the first retained one after it (a gap in
    /// the stored history), else the newest before it. A pool missing from a map BEFORE the PG's epoch proves nothing
    /// (pool ids are never reused, so only a map at or after it proves the pool deleted): such a PG would be removed by
    /// mistake (data loss), so it is not loaded, kept on disk, and reported.
    pub(super) fn start_map(&mut self, spg: SpgT, epoch: u32) -> Option<MapHandle> {
        let m = self
            .maps
            .range(epoch..)
            .next()
            .or_else(|| self.maps.range(..epoch).next_back())
            .map(|(_, m)| m.clone())?;
        if m.epoch() < epoch && m.pool(spg.pgid.pool).is_none() {
            self.notices.push(format!(
                "ERROR {spg} stored at epoch {epoch}: no map at or after it, pool {} unknown in map {}: \
                 not loaded, kept on disk (map history incomplete)",
                spg.pgid.pool,
                m.epoch()
            ));
            return None;
        }
        Some(m)
    }

    pub(super) fn map_at(&self, epoch: u32) -> Option<MapHandle> {
        self.maps
            .range(..=epoch)
            .next_back()
            .or_else(|| self.maps.range(epoch..).next())
            .map(|(_, m)| m.clone())
    }

    /// A new osdmap epoch: advance every PG (AdvMap per epoch, then ActMap).
    pub fn handle_map(&mut self, now: Mono, m: MapHandle, store: &impl PgStoreOps) -> Vec<Action> {
        // every pool with a PG here before this map may lose it to the gate in this map: remember it (am. 1 point 7)
        // (a pool the current map no longer has is deleted: a PG still deleting there needs no guard, `forget_pg`)
        for k in self.pgs.keys() {
            if self
                .cur
                .as_ref()
                .is_none_or(|m| m.pool(k.pgid.pool).is_some())
            {
                self.held_pools.insert(k.pgid.pool);
            }
        }
        let before: Option<BTreeMap<u64, u32>> =
            self.cur.as_ref().map(|c| c.pg_nums().into_iter().collect());
        self.add_map(m);
        // Only pools known in the previous map are proven deleted. A stored pool
        // absent from an incomplete startup history must keep its held-data guard.
        let deleted: BTreeSet<u64> = before
            .iter()
            .flat_map(|pools| pools.keys().copied())
            .filter(|pool| {
                self.cur
                    .as_ref()
                    .is_some_and(|map| map.pool(*pool).is_none())
            })
            .collect();
        if let Some(before) = before {
            self.place_split_children(&before, store);
        }
        self.prune_withheld();
        self.advance_all(now, store);
        self.create_ec_primary_instances(now, store);
        self.act_all(now, store);
        // release messages that were waiting for this epoch
        let cur = self.epoch();
        let ready: Vec<u32> = self.waiting_map.range(..=cur).map(|(e, _)| *e).collect();
        for e in ready {
            if let Some(msgs) = self.waiting_map.remove(&e) {
                self.route_released(now, msgs, store);
            }
        }
        let creates: Vec<u32> = self.waiting_create.range(..=cur).map(|(e, _)| *e).collect();
        for e in creates {
            for c in self.waiting_create.remove(&e).unwrap_or_default() {
                self.create_now(now, c, store);
            }
        }
        let cmds = std::mem::take(&mut self.parked_scrub_cmds);
        for c in cmds {
            self.scrub_command_inner(now, c, store);
        }
        self.trim_maps();
        self.decline_trim();
        let actions = self.finish_at(now, store);
        self.pool_cache
            .borrow_mut()
            .retain(|pool, _| !deleted.contains(pool));
        self.passive_seen.retain(|pool| !deleted.contains(pool));
        self.held_pools.retain(|pool| !deleted.contains(pool));
        actions
    }

    /// Drop maps below the oldest a PG still uses, the `Config::map_cache` epochs below the newest (classic
    /// `osd_map_cache_size`: a PG created from a message stamped with an older epoch replays the maps since then, else
    /// its interval start stays behind its peers' and they discard its recovery traffic as old) and a held request.
    pub(super) fn trim_maps(&mut self) {
        let keep_from = self
            .min_pg_epoch()
            .unwrap_or(self.epoch())
            .min(self.epoch().saturating_sub(self.cfg.map_cache))
            .min(self.old_hold.unwrap_or(u32::MAX));
        let drop: Vec<u32> = self.maps.range(..keep_from).map(|(e, _)| *e).collect();
        // keep the newest map below the bound (create-info lookups use "at or before")
        for e in drop.iter().take(drop.len().saturating_sub(1)) {
            self.maps.remove(e);
        }
    }

    pub(super) fn oldest_map(&self) -> u32 {
        self.maps.keys().next().copied().unwrap_or(0)
    }

    /// A message for a PG whose create waits for old maps, or for a child its replay split off so far (held aside, not
    /// in the set): queued behind the create (classic: one ordered queue per PG; a newer Notify must not create the PG
    /// first and then meet the older one, nor create a second copy of a held child). Returns the message otherwise.
    pub(super) fn queue_behind_old(&mut self, spg: SpgT, m: Inbound) -> Option<Inbound> {
        let key = if self.parked_old.contains_key(&spg) {
            spg
        } else {
            match self
                .parked_old
                .iter()
                .find(|(_, p)| p.hold.contains_key(&spg))
            {
                Some((k, _)) => *k,
                None => return Some(m),
            }
        };
        let Some(p) = self.parked_old.get_mut(&key) else {
            return Some(m);
        };
        if p.after.len() < PARK_MAX {
            p.after.push(m);
        } else {
            self.drop_msg("old-map parking full");
        }
        None
    }

    /// Hold a create-from-message until the maps since its epoch are here; the driver is asked for them in chunks of
    /// `Config::old_map_chunk` epochs (memory stays bounded by one chunk however long the history is).
    pub(super) fn park_old(&mut self, spg: SpgT, epoch: u32, m: Inbound) {
        if self.parked_old.len() >= PARK_MAX {
            self.drop_msg("old-map parking full");
            return;
        }
        let oldest = self.oldest_map();
        self.trace.push(format!(
            "park {spg}: needs maps from {epoch}, oldest kept {oldest}"
        ));
        let last = oldest.saturating_sub(1);
        self.parked_old.insert(
            spg,
            ParkedOld {
                epoch,
                m,
                after: Vec::new(),
                next: epoch,
                last,
                hold: BTreeMap::new(),
                deferred: Vec::new(),
            },
        );
        self.old_hold = Some(self.old_hold.map_or(oldest, |h| h.min(oldest)));
        self.ask_old(epoch, last);
    }

    /// Request the chunk starting at `from` (once per outstanding `from`).
    fn ask_old(&mut self, from: u32, last: u32) {
        if self.old_out.insert(from) {
            let chunk = self.cfg.old_map_chunk.max(1);
            self.out.push(Action::NeedOldMaps {
                from,
                to: last.min(from.saturating_add(chunk - 1)),
            });
        }
    }

    /// Answer to [`Action::NeedOldMaps`] `{from, ..}`: persisted maps (any order; whatever the store still has at or
    /// above the newest epoch <= `from`, up to the requested `to`; empty = trimmed away). Each parked create waiting
    /// for `from` creates its PG on the start map (held aside, not in the set) and advances it through the chunk; the
    /// next chunk is requested, or after the last one the PG joins the set, advances through the kept maps and gets its
    /// message, followed by what arrived for it meanwhile. Creates whose maps are gone are dropped (peers retry at
    /// their next interval; classic would assert) and noticed.
    pub fn old_maps(
        &mut self,
        now: Mono,
        from: u32,
        maps: Vec<MapHandle>,
        store: &impl PgStoreOps,
    ) -> Vec<Action> {
        self.old_out.remove(&from);
        let chunk_end = maps.iter().map(|m| m.epoch()).max();
        for m in maps {
            self.maps.entry(m.epoch()).or_insert(m);
        }
        let due: Vec<SpgT> = self
            .parked_old
            .iter()
            .filter(|(_, p)| p.next == from)
            .map(|(s, _)| *s)
            .collect();
        for spg in due {
            let Some(mut p) = self.parked_old.remove(&spg) else {
                continue;
            };
            if self.pgs.contains_key(&spg) {
                // the PG came to exist meanwhile (mon create, merge placeholder): it wins, the replay is moot
                self.drop_msg("old-map replay: pg exists meanwhile");
                self.route_after(p.after, now, store);
                continue;
            }
            let usable = chunk_end.filter(|e| *e >= p.next);
            let started = !p.hold.is_empty() || self.start_replay(spg, &mut p, now);
            let Some(chunk_end) = usable.filter(|_| started) else {
                self.drop_msg("create-from-message: start map trimmed");
                self.notices.push(format!(
                    "pg {spg}: create message of epoch {} dropped, map no longer stored",
                    p.epoch
                ));
                self.route_after(p.after, now, store);
                continue;
            };
            let mark = self.out.len();
            self.replay_chunk(&mut p, chunk_end, now, store);
            let produced = self.out.split_off(mark);
            if produced.iter().any(|a| self.live_action(a, &p.hold)) {
                // rare: the chunk touched a PG of the set (a held merge source absorbed late by a live target). Its
                // writes may depend on the held ones (the source's collection) and must not wait behind the live PG's
                // later writes: emit everything now, in order (the held PGs lose these Plain commit acks; harmless)
                self.out.extend(std::mem::take(&mut p.deferred));
                self.out.extend(produced);
            } else {
                p.deferred.extend(produced);
            }
            if chunk_end >= p.last {
                self.finish_replay(spg, p, now, store);
            } else {
                p.next = chunk_end + 1;
                let last = p.last;
                self.parked_old.insert(spg, p);
                self.ask_old(chunk_end + 1, last);
            }
        }
        if self.parked_old.is_empty() {
            self.old_hold = None;
            self.old_out.clear();
        } else if let Some(h) = self.old_hold {
            // the chunks are consumed; what is kept is the replay's end (`h` and up)
            let gone: Vec<u32> = self.maps.range(..h).map(|(e, _)| *e).collect();
            for e in gone {
                self.maps.remove(&e);
            }
        }
        self.trim_maps();
        self.finish_at(now, store)
    }

    fn route_after(&mut self, after: Vec<Inbound>, now: Mono, store: &impl PgStoreOps) {
        self.route_released(now, after, store);
    }

    /// First chunk: create the PG on its start map into `p.hold` (its create info was bounds-checked by
    /// [`Self::note_create_bounds`] when it was parked). False = no usable start map or create info.
    fn start_replay(&mut self, spg: SpgT, p: &mut ParkedOld, now: Mono) -> bool {
        let (history, past) = match &*p.m.body {
            Body::Peering(PeeringMsg::MOSDPGNotify2(n)) => (
                n.notify.info.history.clone(),
                n.notify.past_intervals.clone(),
            ),
            Body::Peering(PeeringMsg::MOSDPGLog(l)) => {
                (l.info.history.clone(), l.past_intervals.clone())
            }
            _ => return false,
        };
        if self.maps.range(..=p.epoch).next_back().is_none() {
            return false;
        }
        let Some(map) = self.map_at(p.epoch) else {
            return false;
        };
        self.trace.push(format!(
            "create {spg} from replay at epoch {} hist {:?}",
            p.epoch, history.same_interval_since
        ));
        let pg = Pg::create(self.cfg.clone(), spg, map, history, past, now);
        p.hold.insert(spg, pg);
        true
    }

    /// Does `a` (produced during a replay chunk) belong to a PG of the set rather than to the replay's `hold`?
    fn live_action(&self, a: &Action, hold: &BTreeMap<SpgT, Pg>) -> bool {
        let pgids = action_pgids(a);
        !pgids.is_empty()
            && pgids.iter().all(|g| {
                hold.range(pgid_range(*g)).next().is_none()
                    && self.pgs.range(pgid_range(*g)).next().is_some()
            })
    }

    /// Put the held PGs into the set; returns their keys. A PG that exists in the set meanwhile (created from a
    /// message, by the mon, as a merge placeholder) wins: the held copy (empty, created from a message) and its
    /// deferred actions are dropped, never written over the live one.
    fn join_held(
        &mut self,
        hold: BTreeMap<SpgT, Pg>,
        deferred: &mut Vec<Action>,
    ) -> BTreeSet<SpgT> {
        let mut joined = BTreeSet::new();
        for (k, pg) in hold {
            if self.pgs.contains_key(&k) {
                self.drop_msg("old-map replay: pg exists meanwhile");
                self.trace
                    .push(format!("replay {k}: live pg wins, held copy dropped"));
                deferred.retain(|a| !action_pgids(a).contains(&k.pgid));
                continue;
            }
            self.pgs.insert(k, pg);
            joined.insert(k);
        }
        joined
    }

    /// Advance the held PGs (the parked one and the children it split off on the way) through the maps up to
    /// `chunk_end`, in lockstep like the normal advance, without touching the other PGs of the set or starting peering.
    fn replay_chunk(
        &mut self,
        p: &mut ParkedOld,
        chunk_end: u32,
        now: Mono,
        store: &impl PgStoreOps,
    ) {
        let known: BTreeSet<SpgT> = self.pgs.keys().copied().collect();
        let only = self.join_held(std::mem::take(&mut p.hold), &mut p.deferred);
        let hold = &mut p.hold;
        self.adv_limit = chunk_end;
        self.advance_set(Some((&only, &known)), now, store);
        self.adv_limit = u32::MAX;
        let mine: Vec<SpgT> = self
            .pgs
            .keys()
            .filter(|k| !known.contains(k))
            .copied()
            .collect();
        for k in mine {
            if let Some(pg) = self.pgs.remove(&k) {
                hold.insert(k, pg);
            }
        }
    }

    /// Last chunk done: the held PGs join the set, advance through the kept maps and start peering.
    fn finish_replay(&mut self, spg: SpgT, p: ParkedOld, now: Mono, store: &impl PgStoreOps) {
        let ParkedOld {
            m,
            after,
            hold,
            deferred,
            ..
        } = p;
        let Some(cur) = self.cur.clone() else { return };
        if self.pgs.contains_key(&spg) || !self.should_exist(&*cur, spg) {
            self.drop_msg("create info for pg we are not part of");
            self.route_after(after, now, store);
            return;
        }
        let mut deferred = deferred;
        let known: BTreeSet<SpgT> = self.pgs.keys().copied().collect();
        let only = self.join_held(hold, &mut deferred);
        self.out.extend(deferred);
        self.gate_created_child(spg);
        self.advance_and_act(&only, &known, now, store);
        self.deliver(spg, now, m, store);
        self.route_after(after, now, store);
    }
}

/// The PGs a per-PG action is about (empty for OSD-wide actions).
fn action_pgids(a: &Action) -> Vec<PgT> {
    match a {
        Action::Send(s) => body_spgs(&s.body).iter().map(|g| g.pgid).collect(),
        Action::Persist { spg, .. }
        | Action::WriteDone { spg, .. }
        | Action::ReadableChanged { spg, .. }
        | Action::PgStats { spg, .. }
        | Action::PgRemoved { spg }
        | Action::SubWritesAborted { spg, .. }
        | Action::SnapTrimKick { spg }
        | Action::Fatal { spg, .. } => vec![spg.pgid],
        Action::LostMarked(d) => vec![d.spg.pgid],
        Action::Placement { pgid, .. } => vec![*pgid],
        _ => Vec::new(),
    }
}
