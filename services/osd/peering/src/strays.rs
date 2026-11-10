// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Recovery sources outside the acting set (spec doc/spec/missing-loc.md, adr 0081): the primary probes the strays of
//! `might_have_unfound` for their log + missing set (classic `discover_all_missing`), keeps what they hold like a member's
//! (`peer_info` / `peer_missing`), activates a stray that holds something recovery needs (MOSDPGInfo2: a classic EC
//! stray serves sub-reads only when peered) and offers it as a source: replicated pulls ([`Pg::holders`]), EC sub-reads
//! of the stray's shard ([`Pg::ec_stray_src`]).

use crate::pg::Pg;
use crate::plog::MissingSet;
use denc::types::{Eversion, Hobject, PgShard, SpgT};
use pgwire::state as pgs;
use pgwire::{MOSDPGInfo2, MOSDPGLog, PgQuery, QueryType};
use std::collections::BTreeMap;

impl Pg {
    /// Is `p` an acting member (EC: at its own position; classic `actingset` holds pg_shards, so another instance on a
    /// member OSD is not one, adr 0049 am. 1)?
    pub(crate) fn in_acting(&self, p: PgShard) -> bool {
        if !self.pool.is_erasure {
            return self.acting.contains(&p.osd);
        }
        p.shard.0 >= 0 && self.acting.get(p.shard.0 as usize) == Some(&p.osd)
    }

    /// `p` holds no position of the current mapping at its shard (EC: the OSD may be a member at another position).
    pub(crate) fn is_stray_shard(&self, p: PgShard) -> bool {
        if !self.pool.is_erasure {
            return !self.up.contains(&p.osd) && !self.acting.contains(&p.osd);
        }
        let at = |v: &[i32]| p.shard.0 >= 0 && v.get(p.shard.0 as usize) == Some(&p.osd);
        !at(&self.acting) && !at(&self.up)
    }

    /// Spec 4.2 (`discover_all_missing`): FULLLOG queries to every `might_have_unfound` peer we know nothing about yet.
    pub(crate) fn probe_strays(&mut self) {
        let cands: Vec<PgShard> = self
            .prim
            .might_have_unfound
            .iter()
            .copied()
            .filter(|p| {
                *p != self.me
                    && self.map.is_up(p.osd)
                    && !self.prim.acting_recovery_backfill.contains(p)
                    && !self.prim.peer_purged.contains(p)
                    && !self.prim.peer_missing.contains_key(p)
                    && !self.prim.peer_missing_requested.contains(p)
                    && self
                        .prim
                        .peer_info
                        .get(p)
                        .is_none_or(|i| !i.is_empty() && !i.dne_flag())
                    && (!self.pool.is_erasure || p.shard.0 >= 0)
            })
            .collect();
        for p in cands {
            let q = PgQuery {
                ty: QueryType::FULLLOG,
                since: Eversion::default(),
                history: self.history_for_send(),
                epoch_sent: self.map.epoch(),
                to: p.shard,
                from: self.me.shard,
            };
            self.send_query(p, q);
            self.prim.peer_missing_requested.insert(p);
        }
    }

    /// Spec 4.1 triggers in Active: something is unfound, or the PG is degraded and `p` may hold what it misses.
    pub(crate) fn probe_strays_if_needed(&mut self, p: Option<PgShard>) {
        let unfound = self.state & pgs::RECOVERY_UNFOUND != 0;
        let degraded =
            p.is_some_and(|p| self.prim.might_have_unfound.contains(&p)) && self.needs_recovery();
        if unfound || degraded {
            self.probe_strays();
        }
    }

    /// Spec 4.3: the FULLLOG answer of a probed stray (Active). `false` = not a probe of ours.
    pub(crate) fn stray_on_log(&mut self, p: PgShard, m: &MOSDPGLog) -> bool {
        if !self.prim.peer_missing_requested.remove(&p)
            || self.prim.acting_recovery_backfill.contains(&p)
        {
            return false;
        }
        self.proc_peer_log(p, m);
        self.stray_search(p);
        true
    }

    /// Spec 3: does the stray `p` hold anything recovery needs? Then activate it (4.4) and let recovery look again.
    pub(crate) fn stray_search(&mut self, p: PgShard) {
        if self.prim.stray_src.contains(&p) || p == self.me || !self.is_stray_shard(p) {
            return;
        }
        let Some(pi) = self.prim.peer_info.get(&p) else {
            return;
        };
        if pi.last_update == Eversion::default() {
            return;
        }
        let needed = self.needs_recovery_map();
        if !needed.iter().any(|(o, need)| self.stray_has(p, o, *need)) {
            return;
        }
        let mut info = pi.clone();
        info.pgid = SpgT {
            pgid: self.spg.pgid,
            shard: self.me.shard,
        };
        info.history = self.history_for_send();
        if self.ec_opt() {
            info.partial_writes_last_complete = self.info.partial_writes_last_complete.clone();
            info.partial_writes_last_complete_epoch = self.info.partial_writes_last_complete_epoch;
        }
        let epoch = self.map.epoch();
        self.send_peering(
            p.osd,
            MOSDPGInfo2 {
                spgid: SpgT {
                    pgid: self.spg.pgid,
                    shard: p.shard,
                },
                epoch_sent: epoch,
                min_epoch: epoch,
                info,
                lease: None,
                lease_ack: None,
            },
        );
        self.prim.stray_src.insert(p);
        self.notes.push(format!(
            "pg {}: stray osd.{}({}) is a recovery source",
            self.spg, p.osd, p.shard.0
        ));
        if self.pool.is_erasure {
            // objects that failed for lack of shards are tried again at once
            let now = self.now;
            self.ec_recov_retry_now(now);
        }
    }

    /// Spec 3 (`add_source_info`): the probed peer `p` holds `oid` at `need`.
    pub(crate) fn stray_has(&self, p: PgShard, oid: &Hobject, need: Eversion) -> bool {
        self.map.is_up(p.osd)
            && self
                .prim
                .peer_info
                .get(&p)
                .is_some_and(|i| i.last_update >= need && *oid < i.last_backfill)
            && self
                .prim
                .peer_missing
                .get(&p)
                .is_some_and(|m| !m.contains(oid))
    }

    /// Needs-recovery set (spec 1): non-delete objects missing on us or on a recovering member, with their `need`.
    fn needs_recovery_map(&self) -> BTreeMap<Hobject, Eversion> {
        let mut v: BTreeMap<Hobject, Eversion> = BTreeMap::new();
        let mut add = |m: &MissingSet| {
            for (o, i) in m.iter() {
                if !i.is_delete() {
                    let e = v.entry(o.clone()).or_default();
                    *e = (*e).max(i.need);
                }
            }
        };
        add(&self.missing);
        for p in &self.prim.acting_recovery_backfill {
            if *p != self.me
                && !self.prim.backfill_targets.contains(p)
                && let Some(m) = self.prim.peer_missing.get(p)
            {
                add(m);
            }
        }
        v
    }

    /// `need` of `oid` if a member (or we) misses it.
    fn need_of(&self, oid: &Hobject) -> Option<Eversion> {
        let mut need: Option<Eversion> = None;
        let mut take = |m: Option<&MissingSet>| {
            if let Some(i) = m.and_then(|m| m.get(oid))
                && !i.is_delete()
            {
                need = Some(need.map_or(i.need, |n| n.max(i.need)));
            }
        };
        take(Some(&self.missing));
        for p in &self.prim.acting_recovery_backfill {
            if *p != self.me && !self.prim.backfill_targets.contains(p) {
                take(self.prim.peer_missing.get(p));
            }
        }
        need
    }

    /// EC (spec 6): shard -> OSD of activated strays that hold `soid` at the version recovery needs, for shards the members
    /// (`avail`) do not serve. Empty when no member misses the object.
    pub(crate) fn ec_stray_src(&self, soid: &Hobject, avail: &[u32]) -> BTreeMap<u32, i32> {
        let mut src = BTreeMap::new();
        if self.prim.stray_src.is_empty() {
            return src;
        }
        let Some(need) = self.need_of(soid) else {
            return src;
        };
        for p in &self.prim.stray_src {
            let sh = p.shard.0;
            if sh < 0 || avail.contains(&(sh as u32)) || src.contains_key(&(sh as u32)) {
                continue;
            }
            if self.is_stray_shard(*p) && self.stray_has(*p, soid, need) {
                src.insert(sh as u32, p.osd);
            }
        }
        src
    }
}
