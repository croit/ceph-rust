// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Message routing: map waiting, PG creation from create info, DNE replies, delivery.

use super::*;

/// Messages one PG may collect before it exists here (`waiting_pg`).
const WAIT_PG_MAX: usize = 1024;
/// Messages parked before this core's first map. A message for an epoch ahead of a map we have is parked without a
/// bound like classic's session `waiting_on_map` (memory bounded by ingress backpressure): a dropped sub-write or
/// repop has no resend while the interval stays, it would hang the client write.
const WAIT_MAP_MAX: usize = 4096;

impl PgSet {
    pub(super) fn drop_msg(&mut self, why: &'static str) {
        *self.dropped.entry(why).or_default() += 1;
    }

    /// Ask the mon for a map newer than ours, at most once per epoch: a peer (or a confused OSD) stamping many
    /// messages with an epoch we never reach must not turn into one request per message.
    pub(super) fn request_map(&mut self) {
        let have = self.epoch();
        if self.map_req >= have {
            return;
        }
        self.map_req = have;
        self.out.push(Action::RequestMap { have });
    }

    /// Create info (history + past intervals from a Notify2 / PGLog / PGCreate2) should satisfy classic's required
    /// past-interval bounds (peering.md 3.3, 3.8). Classic creates the PG without checking them (the check runs later in
    /// primary peering), so a mismatch is logged as a cluster-log error here and the create proceeds: refusing would
    /// leave a pool stuck in `creating` in a mixed cluster. Impossible wire data is already refused at decode (2.5).
    pub(super) fn note_create_bounds(
        &mut self,
        spg: SpgT,
        from: i32,
        history: &PgHistory,
        past: &PastIntervals,
    ) {
        let chk = past.check_required_bounds(history, self.cluster_trim());
        let Some(why) = chk.verdict.reason() else {
            return;
        };
        self.create_bounds_mismatch += 1;
        let n = self.create_bounds_mismatch;
        if n.is_power_of_two() {
            self.notices.push(format!(
                "ERROR {spg} create info from osd.{from}: {why} (history lec {} created {} sis {}, required [{},{}), past [{},{})) [{n}x]",
                history.last_epoch_clean,
                history.epoch_pool_created,
                history.same_interval_since,
                chk.required.0,
                chk.required.1,
                chk.past.0,
                chk.past.1
            ));
        }
    }

    pub(super) fn route(&mut self, now: Mono, m: Inbound, store: &impl PgStoreOps) {
        self.note_heard(&m);
        if !self.peer_links.is_empty() {
            self.peer_heard(m.from);
        }
        let e = wait_epoch(&m.body);
        let Some(cur) = self.cur.clone() else {
            // another core may have been handed the map before this one: the message waits for the first map
            if self.waiting_map.values().map(Vec::len).sum::<usize>() < WAIT_MAP_MAX {
                self.waiting_map.entry(e.max(1)).or_default().push(m);
            } else {
                self.drop_msg("no map yet");
            }
            return;
        };
        if e > cur.epoch() {
            self.request_map();
            self.waiting_map.entry(e).or_default().push(m);
            return;
        }
        if let Some(pool) = body_spgs(&m.body)
            .iter()
            .map(|s| s.pgid.pool)
            .find(|p| self.is_passive(*p))
        {
            self.note_passive(pool);
            if self.declines(pool) {
                // adr 0039 am. 1: answer as an empty backfill target that refuses backfill (silence stalls peering)
                if !matches!(&*m.body, Body::Peering(PeeringMsg::MOSDPGRemove(_))) {
                    self.decline(&*cur, m);
                }
                return;
            }
            self.drop_msg("message for passive (erasure) pool");
            return;
        }
        // PG removal addresses a list
        if let Body::Peering(PeeringMsg::MOSDPGRemove(r)) = &*m.body {
            let epoch = r.epoch;
            for spg in r.pgs.clone() {
                if self.pgs.contains_key(&spg) {
                    self.deliver(spg, now, m.clone(), store);
                } else if !self.parked_old.is_empty() {
                    // a PG of an old-map replay gets its own remove behind the replay (not lost)
                    let one = Inbound {
                        ingress: m.ingress.clone(),
                        from: m.from,
                        tid: m.tid,
                        prio: m.prio,
                        body: Box::new(Body::Peering(PeeringMsg::MOSDPGRemove(
                            pgwire::MOSDPGRemove {
                                epoch,
                                pgs: vec![spg],
                            },
                        ))),
                    };
                    let _ = self.queue_behind_old(spg, one);
                }
            }
            return;
        }
        if let Body::Peering(PeeringMsg::MOSDPGCreate2(_)) = &*m.body {
            self.drop_msg("create2 must use handle_create");
            return;
        }
        let Some(spg) = target_spg(&m.body) else {
            self.drop_msg("no target pg");
            return;
        };
        if !self.owns(spg) {
            self.drop_msg("pg owned by another core");
            return;
        }
        if self.pgs.get(&spg).is_some_and(|p| !p.is_deleting()) {
            self.deliver(spg, now, m, store);
            return;
        }
        // PG absent (or being deleted)
        let Some(m) = self.queue_behind_old(spg, m) else {
            return;
        };
        if self.pgs.contains_key(&spg) && self.should_exist(&*cur, spg) {
            // being deleted, and the current map puts us into the PG again: the delete finishes first (classic
            // interrupts it with the new interval), then `PgRemoved` routes what waited here in arrival order. A query
            // answered later, a notify or log that creates the PG then: the sender re-sends none of them by itself.
            self.wait_for_pg(spg, m);
            return;
        }
        match &*m.body {
            Body::Peering(PeeringMsg::MOSDPGQuery2(q)) => {
                self.dne_reply(&*cur, m.from, q.spgid, &q.query)
            }
            Body::Peering(PeeringMsg::MOSDPGNotify2(n)) => {
                let (h, pi, ep) = (
                    n.notify.info.history.clone(),
                    n.notify.past_intervals.clone(),
                    n.notify.epoch_sent,
                );
                self.create_from(spg, h, pi, ep, m, now, store);
            }
            Body::Peering(PeeringMsg::MOSDPGLog(l)) => {
                let (h, pi, ep) = (l.info.history.clone(), l.past_intervals.clone(), l.epoch);
                self.create_from(spg, h, pi, ep, m, now, store);
            }
            _ => {
                if self.should_exist(&*cur, spg) && !self.pgs.contains_key(&spg) {
                    self.wait_for_pg(spg, m);
                } else {
                    self.drop_msg("message for absent pg");
                }
            }
        }
    }

    /// Keep `m` until PG `spg` exists here (created) or its delete is done (`PgRemoved` routes it again). The bound
    /// is far above what peers send one PG before it exists (a few peering messages per interval); past it the
    /// message is a counted drop.
    fn wait_for_pg(&mut self, spg: SpgT, m: Inbound) {
        let q = self.waiting_pg.entry(spg).or_default();
        if q.len() < WAIT_PG_MAX {
            q.push(m);
        } else {
            self.drop_msg("waiting for pg: queue full");
        }
    }

    /// Route messages released together (map arrival, PG creation, old-map replay) in arrival order. The driver applies
    /// the store transactions of this call only after it returns: a sub-read / sub-write of a PG that already queued one
    /// here is held in the PG's replay queue instead of being served from the store now (a classic primary's RMW read
    /// right behind its sub-write read the old bytes: OQ 46 a, adr 0067 am. 9).
    pub(super) fn route_released(
        &mut self,
        now: Mono,
        msgs: Vec<Inbound>,
        store: &impl PgStoreOps,
    ) {
        // Earlier release batches and map advancement belong to this same driver call: their writes have not
        // reached the store either. Keep the fence across epoch buckets and nested PG-creation releases.
        let mut persisted: BTreeSet<SpgT> = self.out.iter().filter_map(persisted_spg).collect();
        for m in msgs {
            let n = self.out.len();
            self.route_ordered(now, m, store, &persisted);
            persisted.extend(self.out[n..].iter().filter_map(persisted_spg));
        }
    }

    /// Route within a driver call whose earlier store actions have not been applied yet.
    pub(super) fn route_ordered(
        &mut self,
        now: Mono,
        m: Inbound,
        store: &impl PgStoreOps,
        persisted: &BTreeSet<SpgT>,
    ) {
        if let Some(spg) = target_spg(&m.body)
            && persisted.contains(&spg)
            && crate::pg::held_behind(&m.body)
            && let Some(pg) = self.pgs.get_mut(&spg)
        {
            pg.hold_released(m);
            self.repop_wait.insert(spg);
        } else {
            self.route(now, m, store);
        }
    }

    pub(super) fn should_exist(&self, map: &dyn crate::map::PgMapView, spg: SpgT) -> bool {
        let m = map.pg_mapping(spg.pgid);
        let me = self.cfg.whoami;
        if spg.shard == ShardId::NO_SHARD {
            return m.up.contains(&me) || m.acting.contains(&me);
        }
        // erasure: the shard is our position in the mapping
        let i = spg.shard.0.max(0) as usize;
        m.up.get(i) == Some(&me) || m.acting.get(i) == Some(&me)
    }

    pub(super) fn deliver(&mut self, spg: SpgT, now: Mono, m: Inbound, store: &impl PgStoreOps) {
        self.advance_pg(spg, now, store);
        // a backfill reservation request / scan judges the fill with this core's held backfill reservations
        // (classic sums them over all PGs of the OSD); only these two pay for the walk
        let mut lf = self.local_full;
        if matches!(
            &*m.body,
            Body::Repl(ReplMsg::BackfillReserve(_) | ReplMsg::Scan(_))
        ) {
            lf.used = lf.used.saturating_add(self.backfill_held(store));
        }
        if let Some(pg) = self.pgs.get_mut(&spg) {
            pg.local_full = lf;
            pg.handle_msg(now, m, store);
        }
        self.collect(spg, now, store);
    }

    #[expect(clippy::too_many_arguments)]
    pub(super) fn create_from(
        &mut self,
        spg: SpgT,
        history: PgHistory,
        past: PastIntervals,
        epoch: u32,
        m: Inbound,
        now: Mono,
        store: &impl PgStoreOps,
    ) {
        let Some(cur) = self.cur.clone() else { return };
        if !self.should_exist(&*cur, spg) {
            self.drop_msg("create info for pg we are not part of");
            return;
        }
        if self.detached.contains(&spg) {
            // its copy is stored here unloaded (moved away, stranded, adr 0031 am. 5): an empty instance would be a
            // second copy
            self.drop_msg("create info for a pg stored unloaded here");
            return;
        }
        if self.withhold_create(spg, None, &*cur) {
            return;
        }
        self.note_create_bounds(spg, m.from, &history, &past);
        if epoch != 0 && epoch < self.oldest_map() {
            // the sender lags more than the kept epochs (`Config::map_cache`): replaying the maps since `epoch` is the
            // only way to see every interval (a stale start could let a primary miss an interval with acked writes).
            // Classic reads the map from its store (`get_map`); the driver does the same and answers with `old_maps`.
            self.park_old(spg, epoch, m);
            return;
        }
        let Some(map) = self.map_at(epoch) else {
            return;
        };
        self.trace.push(format!(
            "create {spg} from {} at epoch {epoch} hist {:?}",
            match &*m.body {
                Body::Peering(p) => format!("{}", p.msg_type()),
                _ => "?".into(),
            },
            history.same_interval_since
        ));
        let pg = Pg::create(self.cfg.clone(), spg, map, history, past, now);
        self.pgs.insert(spg, pg);
        self.gate_created_child(spg);
        self.deliver(spg, now, m, store);
    }

    pub(super) fn dne_reply(
        &mut self,
        map: &dyn crate::map::PgMapView,
        from: i32,
        spgid: SpgT,
        q: &pgwire::PgQuery,
    ) {
        if map.pool(spgid.pgid.pool).is_none() {
            return;
        }
        let epoch = map.epoch();
        let info = PgInfo::dne(spgid);
        let to_spg = SpgT {
            pgid: spgid.pgid,
            shard: q.from,
        };
        let body: PeeringMsg = match q.ty {
            QueryType::INFO => MOSDPGNotify2 {
                spgid: to_spg,
                notify: PgNotify::dne(info, q.from, q.epoch_sent, epoch),
            }
            .into(),
            _ => MOSDPGLog {
                epoch,
                info,
                log: PgLog::default(),
                missing: Default::default(),
                query_epoch: q.epoch_sent,
                past_intervals: PastIntervals::default(),
                to: q.from,
                from: spgid.shard,
                lease: None,
            }
            .into(),
        };
        let b = Body::Peering(body);
        let prio = b.priority();
        self.out.push(Action::Send(Box::new(Send {
            to: from,
            epoch,
            tid: 0,
            prio,
            body: b,
            producer: None,
        })));
    }

    /// Default per-OSD PG hard limit: the pinned defaults `mon_max_pg_per_osd` 500 x `osd_max_pg_per_osd_hard_ratio` 3.
    pub const PG_HARD_LIMIT_DEFAULT: f64 = 1500.0;

    /// Per-OSD PG hard limit `mon_max_pg_per_osd` x `osd_max_pg_per_osd_hard_ratio` (read at every create, like classic).
    pub fn set_pg_hard_limit(&mut self, limit: f64) {
        self.pg_hard_limit = limit;
    }

    /// PGs on the whole OSD now: the last OSD-wide count ([`Self::set_num_pgs`]) plus this core's change since (the
    /// other cores' changes count from the next hand-in, <= one tick later).
    pub fn pg_count_estimate(&self) -> u64 {
        (self.cfg.num_pgs_hint + self.pgs.len() as u64).saturating_sub(self.pgs_at_hint)
    }

    /// Hard PG limit (peering.md 7.3 rule 3a): at or above it, the create of `spg` is withheld and remembered
    /// (`mon_epoch`: a mon create of that MOSDPGCreate2 epoch; `None`: create info from a peer). `true` = withheld.
    pub(super) fn withhold_create(
        &mut self,
        spg: SpgT,
        mon_epoch: Option<u32>,
        map: &dyn crate::map::PgMapView,
    ) -> bool {
        if (self.pg_count_estimate() as f64) < self.pg_hard_limit {
            return false;
        }
        match mon_epoch {
            Some(e) => {
                let w = self.withheld_mon.entry(spg).or_insert(e);
                *w = (*w).min(e);
            }
            None => {
                let primary = map.pg_mapping(spg.pgid).acting_primary == self.cfg.whoami;
                self.withheld_peer.insert(spg, primary);
            }
        }
        self.drop_msg("hit max pg: create withheld");
        true
    }

    /// Withheld creates whose PG this OSD now leads: `PENDING_CREATING_PGS` of the mgr report (every withheld mon
    /// create counts, the mon sends those to the acting primary only).
    pub fn pending_creating_pgs(&self) -> u64 {
        (self.withheld_mon.len() + self.withheld_peer.values().filter(|p| **p).count()) as u64
    }

    /// Below the hard limit again: hand out the withheld creates there is room for (mon creates first) and forget them.
    /// The caller asks the mon to send its creates again from [`ResumeCreates::mon_from`] and forces a new interval of
    /// every [`ResumeCreates::peer`] PG (its primary then sends the create info again).
    pub fn take_resumable_creates(&mut self) -> ResumeCreates {
        let mut r = ResumeCreates::default();
        let n = self.pg_count_estimate() as f64;
        if n >= self.pg_hard_limit {
            return r;
        }
        let mut spare = (self.pg_hard_limit - n).ceil() as u64;
        if !self.withheld_mon.is_empty() {
            r.mon_from = self.withheld_mon.values().min().copied();
            spare = spare.saturating_sub(self.withheld_mon.len() as u64);
            self.withheld_mon.clear();
        }
        while spare > 0
            && let Some((spg, _)) = self.withheld_peer.pop_first()
        {
            r.peer.push(spg.pgid);
            spare -= 1;
        }
        r
    }

    /// A new map: a withheld peer create of a PG whose acting set no longer has us is forgotten.
    pub(super) fn prune_withheld(&mut self) {
        let Some(cur) = self.cur.clone() else { return };
        let me = self.cfg.whoami;
        self.withheld_peer.retain(|spg, _| {
            let acting = cur.pg_mapping(spg.pgid).acting;
            if spg.shard == ShardId::NO_SHARD {
                acting.contains(&me)
            } else {
                acting.get(spg.shard.0.max(0) as usize) == Some(&me)
            }
        });
    }

    /// MOSDPGCreate2 from the mon (already authenticated as mon traffic).
    pub fn handle_create(
        &mut self,
        now: Mono,
        m: MOSDPGCreate2,
        store: &impl PgStoreOps,
    ) -> Vec<Action> {
        let Some(cur) = self.cur.clone() else {
            return vec![];
        };
        if m.epoch > cur.epoch() {
            // the mon stamps a create with ITS newest epoch, which is usually ahead of ours: keep it until that map is
            // here (dropping it made every create of a busy mon lag one epoch behind forever)
            self.request_map();
            let e = m.epoch;
            self.waiting_create.entry(e).or_default().push(m);
            return self.finish_at(now, store);
        }
        self.create_now(now, m, store);
        self.finish_at(now, store)
    }

    pub(super) fn create_now(&mut self, now: Mono, m: MOSDPGCreate2, store: &impl PgStoreOps) {
        for (spg, (created, _stamp)) in &m.pgs {
            if !self.owns(*spg) {
                continue; // another core creates it from the same message
            }
            if self.is_passive(spg.pgid.pool) {
                self.note_passive(spg.pgid.pool);
                self.drop_msg("create2 for passive (erasure) pool");
                continue;
            }
            if self.pgs.contains_key(spg) {
                continue;
            }
            let Some((history, past)) = m.pg_extra.get(spg).cloned() else {
                self.drop_msg("create2 without pg_extra");
                continue;
            };
            if !past.is_empty() && m.epoch < past.bounds().1 {
                self.drop_msg("create2 past_intervals newer than msg epoch");
                continue;
            }
            self.note_create_bounds(*spg, -1, &history, &past);
            let Some(map) = self.map_at(m.epoch) else {
                continue;
            };
            let mapping = map.pg_mapping(spg.pgid);
            if mapping.acting_primary != self.cfg.whoami {
                self.drop_msg("create2 for pg we do not lead");
                continue;
            }
            if self.withhold_create(*spg, Some(m.epoch), &*map) {
                continue;
            }
            let mut h = history;
            if h.epoch_created == 0 {
                h.epoch_created = *created;
                h.epoch_pool_created = *created;
            }
            let pg = Pg::create(self.cfg.clone(), *spg, map, h, past, now);
            self.pgs.insert(*spg, pg);
            self.gate_created_child(*spg);
            self.advance_pg(*spg, now, store);
        }
    }
}

pub(super) fn persisted_spg(action: &Action) -> Option<SpgT> {
    match action {
        Action::Persist { spg, .. } => Some(*spg),
        _ => None,
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use crate::store::MemStore;
    use denc::types::{PgShard, PgT, ShardId, SpgT};

    /// One core with map `epoch` (pool 1, one PG) and its store.
    fn set_at(epoch: u32) -> (PgSet, MemStore) {
        let store = MemStore::new();
        let mut set = PgSet::new(Config::new(0));
        let m = SynthMap::new(epoch).with_osd(0, 1).with_pool(1, 1, 1, 1);
        let _ = set.handle_map(0, m.into_handle(), &store);
        (set, store)
    }

    /// A PG message stamped with `epoch`: a scrub reservation request is the cheapest body that carries one.
    fn future_msg(epoch: u32, tid: u64) -> Inbound {
        Inbound {
            ingress: Default::default(),
            from: 1,
            tid,
            prio: pgwire::msgs::PRIO_DEFAULT,
            body: Box::new(Body::Repl(ReplMsg::ScrubReserve(
                replwire::MOSDScrubReserve {
                    pgid: SpgT {
                        pgid: PgT::new(1, 0),
                        shard: ShardId::NO_SHARD,
                    },
                    map_epoch: epoch,
                    ty: replwire::MOSDScrubReserve::REQUEST,
                    from: PgShard {
                        osd: 1,
                        shard: ShardId::NO_SHARD,
                    },
                    nonce: 1,
                    wait_for_resources: true,
                },
            ))),
        }
    }

    fn map_requests(acts: &[Action]) -> usize {
        acts.iter()
            .filter(|a| matches!(a, Action::RequestMap { .. }))
            .count()
    }

    /// MOSDPGCreate2 at `epoch` for `seeds` of pool 1.
    fn create2(epoch: u32, seeds: &[u32]) -> MOSDPGCreate2 {
        let mut m = MOSDPGCreate2 {
            epoch,
            ..Default::default()
        };
        for seed in seeds {
            let s = SpgT {
                pgid: PgT::new(1, *seed),
                shard: ShardId::NO_SHARD,
            };
            m.pgs.insert(s, (epoch, denc::types::UTime::new(1, 0)));
            m.pg_extra.insert(
                s,
                (
                    PgHistory::new_pg(epoch, denc::types::UTime::new(1, 0)),
                    PastIntervals::default(),
                ),
            );
        }
        m
    }

    /// peering.md 7.3 rule 3a: a create at or above `mon_max_pg_per_osd` x `osd_max_pg_per_osd_hard_ratio` (all cores
    /// counted) is withheld, counted as pending, and handed back for re-solicitation once there is room again; a
    /// withheld peer create of a PG that no longer maps here is forgotten.
    #[test]
    fn creates_above_the_pg_hard_limit_are_withheld_and_resumed() {
        let store = MemStore::new();
        let mut set = PgSet::new(Config::new(0));
        let m = SynthMap::new(100).with_osd(0, 1).with_pool(1, 1, 1, 4);
        let _ = set.handle_map(0, m.into_handle(), &store);
        // the other cores host 2 PGs: room for one more under a limit of 3
        set.set_num_pgs(2);
        set.set_pg_hard_limit(3.0);
        let _ = set.handle_create(1, create2(100, &[0, 1, 2]), &store);
        assert_eq!(set.pgs().count(), 1);
        assert_eq!(set.pg_count_estimate(), 3);
        assert_eq!(set.pending_creating_pgs(), 2);
        assert_eq!(set.dropped.get("hit max pg: create withheld"), Some(&2));
        assert_eq!(
            set.take_resumable_creates(),
            ResumeCreates::default(),
            "no room yet"
        );
        // a peer create is withheld too and remembered with its role
        let map = set.cur.clone().unwrap();
        let s3 = SpgT {
            pgid: PgT::new(1, 3),
            shard: ShardId::NO_SHARD,
        };
        assert!(set.withhold_create(s3, None, &*map));
        assert_eq!(set.pending_creating_pgs(), 3);
        // room again (operator raised the limit): mon creates from the oldest withheld epoch, then the peer PGs
        set.set_pg_hard_limit(5.0);
        assert_eq!(
            set.take_resumable_creates(),
            ResumeCreates {
                mon_from: Some(100),
                peer: vec![],
            },
            "two mon creates use up the room"
        );
        set.set_pg_hard_limit(6.0);
        assert_eq!(
            set.take_resumable_creates(),
            ResumeCreates {
                mon_from: None,
                peer: vec![PgT::new(1, 3)],
            }
        );
        assert_eq!(set.pending_creating_pgs(), 0);
        // the mon sends its creates again: created now; a duplicate of an existing PG is no create
        let _ = set.handle_create(2, create2(100, &[0, 1, 2]), &store);
        assert_eq!(set.pgs().count(), 3);
        // a withheld peer create of a PG whose acting set moves away is forgotten with the next map
        set.set_pg_hard_limit(0.0);
        assert!(set.withhold_create(s3, None, &*map));
        let mut m = SynthMap::new(101)
            .with_osd(0, 1)
            .with_osd(1, 1)
            .with_pool(1, 1, 1, 4);
        m.pg_temp.insert(PgT::new(1, 3), vec![1]);
        let _ = set.handle_map(3, m.into_handle(), &store);
        assert_eq!(set.withheld_peer.len(), 0);
    }

    /// A peer stamping many messages with an epoch we never reach asks the mon for the map once, not once per message;
    /// every message stays parked (a drop could hang a client write: no repop resend while the interval stays).
    #[test]
    fn future_epoch_messages_ask_the_map_once_and_stay_parked() {
        let (mut set, store) = set_at(100);
        let n = WAIT_MAP_MAX + 100;
        let mut reqs = 0;
        for i in 0..n {
            let acts = set.handle_msg(1, future_msg(1_000_000 + (i % 3) as u32, i as u64), &store);
            reqs += map_requests(&acts);
        }
        assert_eq!(set.parked_msgs().0, n, "nothing dropped");
        assert_eq!(reqs, 1, "one outstanding map request");
    }

    /// MOSDPGCreate2 stamped ahead of our map asks for the map once and is kept.
    #[test]
    fn future_creates_ask_the_map_once() {
        let (mut set, store) = set_at(100);
        let mut reqs = 0;
        for i in 0..50 {
            let c = MOSDPGCreate2 {
                epoch: 1_000_000 + (i % 2) as u32,
                ..Default::default()
            };
            reqs += map_requests(&set.handle_create(1, c, &store));
        }
        assert_eq!(set.waiting_create.values().map(Vec::len).sum::<usize>(), 50);
        assert_eq!(reqs, 1, "one outstanding map request");
    }
}
