// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG load from the store, EC primary instance creation, multi-core adopt/detach.

use super::*;

impl PgSet {
    /// Load every PG from the store; each restarts at the map of its persisted epoch and is
    /// advanced through all later maps (an "OSD down -> up" inside the range starts a new interval).
    pub fn load_pgs(&mut self, now: Mono, store: &impl PgStoreOps) -> Vec<Action> {
        self.loaded = true;
        for spg in store.list_pgs() {
            // a stored PG (any state) = this OSD holds data of the pool: never decline it (adr 0039 am. 1 point 7)
            self.held_pools.insert(spg.pgid.pool);
            if self.detached.contains(&spg) {
                continue;
            }
            let Some(p) = store.load_pg(spg) else {
                continue;
            };
            // multi-core: this store's shard is where the PG lives, whatever its hash says
            if let (Some(sh), Some(o)) = (store.shard_of_pg(spg.pgid), self.cfg.owner)
                && o.default_shard(spg.pgid.pool, spg.pgid.seed) != sh
            {
                self.place.insert(spg.pgid, sh);
            }
            if !self.owns(spg) {
                continue;
            }
            if self.is_passive(spg.pgid.pool) {
                self.note_passive(spg.pgid.pool);
                continue;
            }
            let Some(m) = self.start_map(spg, p.epoch) else {
                continue;
            };
            let mut pg = Pg::load(self.cfg.clone(), spg, p, m, now);
            // leftovers of a crash (recovery or copy staging): removed with the first interval
            pg.temps.extend(store.list_temps(spg));
            self.pgs.insert(spg, pg);
        }
        self.advance_all(now, store);
        self.act_all(now, store);
        self.finish_at(now, store)
    }

    /// EC: this OSD became the acting primary of a PG at a shard position it holds no instance for (a remap moved it, e.g.
    /// OSDs were added to the rule's root) while an instance of an OLD position exists. Classic creates the new instance from the
    /// old one's notify (sent to itself); the old instance never leads (`Pg::is_primary`), so create it here from the old
    /// instance's history and past intervals.
    pub(super) fn create_ec_primary_instances(&mut self, now: Mono, store: &impl PgStoreOps) {
        let Some(cur) = self.cur.clone() else {
            return;
        };
        let me = self.cfg.whoami;
        let mut seen: BTreeSet<PgT> = BTreeSet::new();
        let mut make: Vec<(SpgT, PgHistory, PastIntervals, MapHandle)> = Vec::new();
        for (spg, pg) in self.pgs.iter() {
            if spg.shard == ShardId::NO_SHARD || pg.is_deleting() || !seen.insert(spg.pgid) {
                continue;
            }
            if self.is_passive(spg.pgid.pool) || !self.cfg.ec_primary {
                continue;
            }
            let m = cur.pg_mapping(spg.pgid);
            if m.acting_primary != me {
                continue;
            }
            let Some(i) = m.acting.iter().position(|o| *o == me) else {
                continue;
            };
            let new = SpgT {
                pgid: spg.pgid,
                shard: ShardId(i as i8),
            };
            if !self.pgs.contains_key(&new) && self.owns(new) {
                make.push((
                    new,
                    pg.info().history.clone(),
                    pg.past_intervals().clone(),
                    pg.map_handle(),
                ));
            }
        }
        let made = !make.is_empty();
        for (spg, h, past, map) in make {
            self.trace.push(format!(
                "create {spg} as the new primary position from an old instance"
            ));
            let pg = Pg::create(self.cfg.clone(), spg, map, h, past, now);
            self.pgs.insert(spg, pg);
        }
        if made {
            self.advance_all(now, store);
        }
    }

    /// Stop hosting `spg` here; its store copy stays (it moves to another core, adr 0031). Like a merge source: pending
    /// writes are queued, in-flight work is aborted (`SubWritesAborted`, unanswered writes), reservations go back.
    pub fn detach(&mut self, now: Mono, spg: SpgT, store: &impl PgStoreOps) -> Vec<Action> {
        if let Some(pg) = self.pgs.get_mut(&spg) {
            pg.quiesce_for_merge(store);
        }
        self.collect(spg, now, store);
        self.detached.insert(spg);
        self.forget_pg(spg);
        self.finish_at(now, store)
    }

    /// Messages for PG `pgid` (every instance) waiting here for a map or for the PG, oldest first per queue: the PG
    /// leaves this core, they go with it (adr 0031 am. 8). Messages addressing several PGs and creates waiting for an
    /// old-map replay stay.
    pub fn take_waiting(&mut self, pgid: PgT) -> Vec<Inbound> {
        let (lo, hi) = (
            SpgT {
                pgid,
                shard: ShardId(i8::MIN),
            },
            SpgT {
                pgid,
                shard: ShardId(i8::MAX),
            },
        );
        let keys: Vec<SpgT> = self.waiting_pg.range(lo..=hi).map(|(k, _)| *k).collect();
        let mut out = Vec::new();
        for k in keys {
            out.extend(self.waiting_pg.remove(&k).unwrap_or_default());
        }
        for q in self.waiting_map.values_mut() {
            out.extend(q.extract_if(.., |m| matches!(*body_spgs(&m.body), [s] if s.pgid == pgid)));
        }
        self.waiting_map.retain(|_, q| !q.is_empty());
        out
    }

    /// Never load stored instance `spg` here (a merge source stranded on the wrong core, adr 0031 am. 5): it stays in
    /// the store, never moved, until the merged PG is complete again or its pool is deleted.
    pub fn keep_unloaded(&mut self, spg: SpgT) {
        self.detached.insert(spg);
    }

    /// The stored unloaded copy was deleted. Allow a later incarnation of this PG to be created from peer state.
    /// Call only after removal succeeds; an extant stranded copy must still prevent an empty second instance.
    pub fn removed_unloaded(&mut self, spg: SpgT) {
        self.detached.remove(&spg);
    }

    /// A successful migration removed every source instance and switched routing to its destination. Retire all
    /// source fences only after that switch: earlier messages must still be unable to create a second empty copy.
    pub fn moved_unloaded(&mut self, pgid: PgT) {
        let lo = SpgT {
            pgid,
            shard: ShardId(i8::MIN),
        };
        let hi = SpgT {
            pgid,
            shard: ShardId(i8::MAX),
        };
        let gone: Vec<SpgT> = self.detached.range(lo..=hi).copied().collect();
        for spg in gone {
            self.detached.remove(&spg);
        }
    }

    /// The boot found no PG to load (empty store, no usable map): later pool switches load what appears in the store.
    pub fn note_loaded(&mut self) {
        self.loaded = true;
    }

    /// Start hosting a PG that was just put into this core's store (migration): load it like at boot and advance it
    /// to the current map.
    pub fn adopt(&mut self, now: Mono, spg: SpgT, store: &impl PgStoreOps) -> Vec<Action> {
        self.detached.remove(&spg);
        if self.pgs.contains_key(&spg) {
            return vec![];
        }
        if let Some(p) = store.load_pg(spg)
            && let Some(m) = self.start_map(spg, p.epoch)
        {
            let pg = Pg::load(self.cfg.clone(), spg, p, m, now);
            self.pgs.insert(spg, pg);
            self.advance_all(now, store);
            self.act_all(now, store);
        }
        self.finish_at(now, store)
    }
}
