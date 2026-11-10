// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Decline mode (adr 0039 am. 1): PGs of erasure pools the support gate rejects (optimized EC, ...) get
//! stateless answers that make this OSD an EMPTY, permanently too-full backfill target for a classic primary:
//! `last_backfill = MIN` is never auth, never picked for a position and never asked for data, so the primary peers
//! without our shard (pg_temp with a hole) instead of waiting for us forever. Nothing is stored, nothing is claimed;
//! only replies to messages a primary sent, stamped with the REQUEST's epochs (a stale answer is dropped by the
//! primary's interval check). Allow-list at the choke point: [`decline_violation`].

use super::*;
use crate::map::PgMapView;

/// Info we report for a declined shard: empty, backfill not started (`last_backfill = MIN`), default history
/// (classic `handle_pg_query_nopg` sends an empty info as well, but complete: that would make us an acting member).
fn declined_info(spg: SpgT) -> PgInfo {
    let mut i = PgInfo::dne(spg);
    i.last_backfill = denc::types::Hobject::MIN();
    i
}

impl PgSet {
    /// Erasure pool `pool` is rejected by the support gate and `ec_decline_unsupported` is on.
    /// Never for a pool this OSD holds (or held) PG data of (point 7): silence keeps classic waiting for us.
    pub fn declines(&self, pool: u64) -> bool {
        !self.held_pools.contains(&pool) && self.pool_entry(pool).is_some_and(|(_, _, d)| d)
    }

    /// This OSD holds (or held) PG data of `pool`: never declined, stays silent.
    pub fn holds_pool(&self, pool: u64) -> bool {
        self.held_pools.contains(&pool)
    }

    /// Pools of PGs stored on any core (multi-core boot union, adr 0031): never declined.
    pub fn note_held_pools(&mut self, pools: impl IntoIterator<Item = u64>) {
        self.held_pools.extend(pools);
    }

    fn decline_count(&mut self, what: &'static str) {
        *self.decline_stats.entry(what).or_default() += 1;
    }

    fn decline_send(&mut self, to: i32, epoch: u32, tid: u64, body: Body) {
        let prio = body.priority();
        self.out.push(Action::Send(Box::new(Send {
            to,
            epoch,
            tid,
            prio,
            body,
            producer: None,
        })));
    }

    /// Answer one message for a PG of a declined pool (routing already waited for the map epoch it names).
    pub(super) fn decline(&mut self, map: &dyn PgMapView, m: Inbound) {
        let Some(spg) = target_spg(&m.body) else {
            return self.decline_count("ignored: no target pg");
        };
        let size = map.pool(spg.pgid.pool).map_or(0, |p| p.size);
        if spg.shard.0 < 0 || spg.shard.0 as u32 >= size {
            return self.decline_count("ignored: shard out of range");
        }
        if !self.owns(spg) {
            return; // another core answers
        }
        let me = self.cfg.whoami;
        let from = m.from;
        match *m.body {
            Body::Peering(PeeringMsg::MOSDPGQuery2(q)) => {
                let info = declined_info(spg);
                let to_spg = SpgT {
                    pgid: spg.pgid,
                    shard: q.query.from,
                };
                let epoch = map.epoch();
                let body: PeeringMsg = if q.query.ty == QueryType::INFO {
                    MOSDPGNotify2 {
                        spgid: to_spg,
                        notify: PgNotify::dne(info, q.query.from, q.query.epoch_sent, epoch),
                    }
                    .into()
                } else {
                    MOSDPGLog {
                        epoch,
                        info,
                        log: PgLog::default(),
                        missing: Default::default(),
                        query_epoch: q.query.epoch_sent,
                        past_intervals: PastIntervals::default(),
                        to: q.query.from,
                        from: spg.shard,
                        lease: None,
                    }
                    .into()
                };
                self.decline_count("query answered (empty, incomplete)");
                self.decline_send(from, epoch, 0, Body::Peering(body));
            }
            // activation (Log; Info2 when the primary's partial-write info made us look non-empty) or a later info
            // share: the activate ack. Counted once by a primary in Active, discarded there otherwise; a primary in
            // a newer interval drops it (stamped with the primary's epoch).
            Body::Peering(PeeringMsg::MOSDPGLog(l)) => {
                self.decline_activate(spg, from, l.from, l.epoch, &l.info, true);
            }
            Body::Peering(PeeringMsg::MOSDPGInfo2(i)) => {
                // the primary sends its own info: its shard is `info.pgid.shard` (classic keys MInfoRec the same way)
                self.decline_activate(spg, from, i.info.pgid.shard, i.epoch_sent, &i.info, false);
            }
            Body::Ec(ecwire::EcMsg::Write(w)) => {
                // A backfill target (last_backfill MIN) gets every object with an EMPTY transaction (classic
                // `should_send_op` false, flag `backfill_or_async_recovery`; the dummy roll-forward op too). Only an
                // empty transaction is acknowledged: there is nothing to store. Anything else (undecodable, ops) means
                // the primary believes this OSD holds the shard: never acknowledge data we do not store.
                let empty = w.txn(self.cfg.page).is_ok_and(|t| t.ops.is_empty());
                if !empty {
                    self.decline_count("sub-write with data NOT acknowledged");
                    self.notices.push(format!(
                        "pg {spg}: declined EC shard got a sub-write with data from osd.{from} (tid {}); not acknowledged",
                        w.op.tid
                    ));
                    return;
                }
                let hw = self.declined.entry(spg).or_default();
                if let Some(e) = w.op.log_entries.last() {
                    *hw = (*hw).max(e.version);
                }
                let last_complete = *hw;
                let reply = ecwire::MOSDECSubOpWriteReply {
                    pgid: SpgT {
                        pgid: spg.pgid,
                        shard: w.op.from.shard,
                    },
                    map_epoch: w.map_epoch,
                    op: ecwire::ECSubWriteReply {
                        from: denc::types::PgShard {
                            osd: me,
                            shard: spg.shard,
                        },
                        tid: w.op.tid,
                        last_complete,
                        committed: true,
                        applied: true,
                    },
                    min_epoch: w.min_epoch,
                    trace: [0; 3],
                };
                self.decline_count("empty sub-write acknowledged");
                self.decline_send(from, w.map_epoch, m.tid, Body::Ec(reply.into()));
            }
            Body::Repl(ReplMsg::UpdateLogMissing(u)) => {
                let lcod = self.declined.get(&spg).copied().unwrap_or_default();
                let reply = replwire::MOSDPGUpdateLogMissingReply {
                    map_epoch: u.map_epoch,
                    pgid: SpgT {
                        pgid: spg.pgid,
                        shard: u.from,
                    },
                    from: spg.shard,
                    rep_tid: u.rep_tid,
                    min_epoch: u.min_epoch,
                    last_complete_ondisk: lcod,
                };
                self.decline_count("log update acknowledged");
                self.decline_send(from, u.map_epoch, m.tid, Body::Repl(reply.into()));
            }
            Body::Repl(ReplMsg::BackfillReserve(r))
                if r.ty == replwire::MBackfillReserve::REQUEST =>
            {
                let mp = map.pg_mapping(spg.pgid);
                let Some(pos) = mp.acting.iter().position(|o| *o == from) else {
                    return self.decline_count("ignored: reservation from a non-member");
                };
                let reply = replwire::MBackfillReserve::reply(
                    SpgT {
                        pgid: spg.pgid,
                        shard: ShardId(pos as i8),
                    },
                    r.query_epoch,
                    replwire::MBackfillReserve::REJECT_TOOFULL,
                );
                self.decline_count("backfill reservation rejected (toofull)");
                self.decline_send(from, r.query_epoch, 0, Body::Repl(reply.into()));
            }
            _ => self.decline_count("ignored: other message"),
        }
    }

    /// Activate ack (MOSDPGInfo2) to the primary `to` at its shard `to_shard`, stamped with the primary's epoch.
    fn decline_activate(
        &mut self,
        spg: SpgT,
        to: i32,
        to_shard: ShardId,
        epoch: u32,
        pinfo: &PgInfo,
        activation: bool,
    ) {
        if to_shard.0 < 0 {
            return self.decline_count("ignored: activation without primary shard");
        }
        let mut info = declined_info(spg);
        info.history = pinfo.history.clone();
        info.last_update = pinfo.last_update;
        info.last_complete = pinfo.last_update;
        info.log_tail = pinfo.log_tail;
        info.last_epoch_started = pinfo.last_epoch_started;
        info.last_interval_started = pinfo.last_interval_started;
        info.history.last_epoch_started = info
            .history
            .last_epoch_started
            .max(pinfo.last_epoch_started);
        info.history.last_interval_started = pinfo.history.same_interval_since;
        // the high-water mark of the last_complete we report restarts at the activation Log (a new primary may be
        // behind); a later info share only raises it
        let hw = self.declined.entry(spg).or_default();
        *hw = if activation {
            pinfo.last_update
        } else {
            (*hw).max(pinfo.last_update)
        };
        let body = pgwire::MOSDPGInfo2 {
            spgid: SpgT {
                pgid: spg.pgid,
                shard: to_shard,
            },
            epoch_sent: epoch,
            min_epoch: epoch,
            info,
            lease: None,
            lease_ack: None,
        };
        self.decline_count("activation acknowledged (backfill target)");
        self.decline_send(to, epoch, 0, Body::Peering(body.into()));
    }

    /// Forget high-water marks of PGs that are no longer declined here (map change, pool gone).
    pub(super) fn decline_trim(&mut self) {
        let keep: Vec<SpgT> = self
            .declined
            .keys()
            .copied()
            .filter(|s| self.declines(s.pgid.pool))
            .collect();
        self.declined.retain(|s, _| keep.contains(s));
    }
}

/// Outbound allow-list of decline mode (choke point, adr 0039 am. 1): exactly the six answers, every carried info
/// empty-incomplete (`last_backfill = MIN`: we never claim a shard), logs empty, reservations only REJECT_TOOFULL.
pub(super) fn decline_violation(b: &Body) -> Option<&'static str> {
    let min = denc::types::Hobject::MIN();
    let ok = match b {
        Body::Peering(PeeringMsg::MOSDPGNotify2(n)) => n.notify.info.last_backfill == min,
        Body::Peering(PeeringMsg::MOSDPGLog(l)) => {
            l.info.last_backfill == min
                && l.log.log.is_empty()
                && l.log.dups.is_empty()
                && l.from == l.info.pgid.shard
        }
        Body::Peering(PeeringMsg::MOSDPGInfo2(i)) => {
            i.info.last_backfill == min && i.lease.is_none() && i.lease_ack.is_none()
        }
        Body::Ec(ecwire::EcMsg::WriteReply(_)) => true,
        Body::Repl(ReplMsg::UpdateLogMissingReply(_)) => true,
        Body::Repl(ReplMsg::BackfillReserve(r)) => {
            r.ty == replwire::MBackfillReserve::REJECT_TOOFULL
        }
        _ => false,
    };
    (!ok).then_some("outbound message not allowed for a declined erasure pool")
}
