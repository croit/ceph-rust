// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Outbound validation (shard vs pool type, EC allow-lists) and PG addressing of message bodies.

use super::*;

pub fn target_spg(b: &Body) -> Option<SpgT> {
    Some(match b {
        Body::Peering(p) => return p.spgid(),
        Body::Repl(r) => match r {
            ReplMsg::RepOp(m) => m.pgid,
            ReplMsg::RepOpReply(m) => m.pgid,
            ReplMsg::UpdateLogMissing(m) => m.pgid,
            ReplMsg::UpdateLogMissingReply(m) => m.pgid,
            ReplMsg::Pct(m) => m.pgid,
            ReplMsg::Push(m) => m.pgid,
            ReplMsg::PushReply(m) => m.pgid,
            ReplMsg::Pull(m) => m.pgid,
            ReplMsg::RecoveryDelete(m) => m.pgid,
            ReplMsg::RecoveryDeleteReply(m) => m.pgid,
            ReplMsg::Scan(m) => m.pgid,
            ReplMsg::Backfill(m) => m.pgid,
            ReplMsg::BackfillRemove(m) => m.pgid,
            ReplMsg::BackfillReserve(m) => m.pgid,
            ReplMsg::RecoveryReserve(m) => m.pgid,
            ReplMsg::ScrubReserve(m) => m.pgid,
            ReplMsg::RepScrub(m) => m.pgid,
            ReplMsg::RepScrubMap(m) => m.pgid,
            ReplMsg::Scrub2(_) | ReplMsg::ForceRecovery(_) => return None,
        },
        Body::Ec(e) => e.spgid(),
    })
}

/// Actions a PG stopped by the past-interval bounds check must not emit (peering.md 3.8): every outbound message and
/// the PG-addressed mon reports. Persistence, local cleanup and the primary's INCOMPLETE stats pass.
pub(super) fn bounds_gated(a: &Action) -> bool {
    matches!(
        a,
        Action::Send(_)
            | Action::PgTemp { .. }
            | Action::PgCreated { .. }
            | Action::ReadyToMerge(_)
    )
}

/// Every shard of PG `pgid` as a key range (maps keyed by [`SpgT`] sort by pgid first).
pub(super) fn pgid_range(pgid: PgT) -> std::ops::RangeInclusive<SpgT> {
    SpgT {
        pgid,
        shard: ShardId(i8::MIN),
    }..=SpgT {
        pgid,
        shard: ShardId(i8::MAX),
    }
}

/// Every PG address a body names (empty if it is not PG-addressed): a multi-core OSD routes the body to the cores
/// owning these PGs.
pub fn body_spgs(b: &Body) -> Spgs<'_> {
    match b {
        Body::Peering(PeeringMsg::MOSDPGRemove(r)) => Spgs::Many(&r.pgs),
        Body::Repl(ReplMsg::Scrub2(s)) => Spgs::Many(&s.scrub_pgs),
        Body::Repl(ReplMsg::ForceRecovery(f)) => Spgs::Many(&f.forced_pgs),
        _ => Spgs::One(target_spg(b)),
    }
}

/// The PGs of a message ([`body_spgs`]): borrowed from the body or the one target inline (asked several times per
/// message on the data path: no allocation).
#[derive(Debug, Clone, Copy)]
pub enum Spgs<'a> {
    One(Option<SpgT>),
    Many(&'a [SpgT]),
}

impl std::ops::Deref for Spgs<'_> {
    type Target = [SpgT];
    fn deref(&self) -> &[SpgT] {
        match self {
            Spgs::One(o) => o.as_slice(),
            Spgs::Many(s) => s,
        }
    }
}

impl<'a> IntoIterator for Spgs<'a> {
    type Item = SpgT;
    type IntoIter = std::iter::Chain<
        std::option::IntoIter<SpgT>,
        std::iter::Copied<std::slice::Iter<'a, SpgT>>,
    >;
    fn into_iter(self) -> Self::IntoIter {
        let (one, many): (Option<SpgT>, &'a [SpgT]) = match self {
            Spgs::One(o) => (o, &[]),
            Spgs::Many(s) => (None, s),
        };
        one.into_iter().chain(many.iter().copied())
    }
}

/// What an EC PRIMARY adds (adr 0049): queries, activation, leases, pushes, pulls, scans, reservations, scrub requests and
/// the two EC sub-op requests, and the log-only update of `mark_unfound_lost` (spec ec-unfound-lost.md 3.3; classic EC
/// primaries send it for lost objects too). RepOp / PCT are replicated-only.
pub(super) fn ec_primary_may_send(b: &Body) -> bool {
    match b {
        Body::Peering(_) => true,
        Body::Repl(r) => !matches!(
            r,
            ReplMsg::RepOp(_)
                | ReplMsg::RepOpReply(_)
                | ReplMsg::UpdateLogMissingReply(_)
                | ReplMsg::Pct(_)
        ),
        Body::Ec(e) => matches!(e, ecwire::EcMsg::Write(_) | ecwire::EcMsg::Read(_)),
    }
}

/// Messages an EC shard may send (allow-list per message type and role, risk R1 of ec-gap.md): the replica-side
/// replies of peering, recovery, backfill and scrub plus the two EC sub-op replies. Everything a primary sends
/// (queries, leases, pushes, pulls, scans, sub-ops) is never allowed.
pub(super) fn ec_shard_may_send(b: &Body, primary: bool) -> bool {
    if primary && ec_primary_may_send(b) {
        return true;
    }
    match b {
        Body::Peering(p) => matches!(
            p,
            PeeringMsg::MOSDPGNotify2(_)
                | PeeringMsg::MOSDPGLog(_)
                | PeeringMsg::MOSDPGInfo2(_)
                | PeeringMsg::MOSDPGLeaseAck(_)
                | PeeringMsg::MOSDPGTrim(_)
        ),
        Body::Repl(r) => match r {
            ReplMsg::PushReply(_)
            // classic EC primaries send log-only updates too (write errors, lost objects) and wait for every shard
            | ReplMsg::UpdateLogMissingReply(_)
            | ReplMsg::ScrubReserve(_)
            | ReplMsg::RepScrubMap(_)
            | ReplMsg::BackfillReserve(_)
            | ReplMsg::RecoveryReserve(_)
            | ReplMsg::RecoveryDeleteReply(_) => true,
            ReplMsg::Scan(s) => s.op == replwire::MOSDPGScan::OP_DIGEST,
            ReplMsg::Backfill(b) => b.op == replwire::MOSDPGBackfill::OP_FINISH_ACK,
            _ => false,
        },
        Body::Ec(e) => matches!(
            e,
            ecwire::EcMsg::WriteReply(_) | ecwire::EcMsg::ReadReply(_)
        ),
    }
}

/// The shard a PG message names as its SENDER (`from`), where the message carries one.
pub(super) fn claimed_from(b: &Body) -> Option<ShardId> {
    match b {
        Body::Peering(p) => match p {
            PeeringMsg::MOSDPGQuery2(q) => Some(q.query.from),
            // Notify / Log of a STRAY legitimately name the shard it held in an old interval
            _ => None,
        },
        Body::Repl(r) => match r {
            ReplMsg::Push(m) => Some(m.from.shard),
            ReplMsg::PushReply(m) => Some(m.from.shard),
            ReplMsg::Pull(m) => Some(m.from.shard),
            ReplMsg::Scan(m) => Some(m.from.shard),
            _ => None,
        },
        Body::Ec(e) => match e {
            ecwire::EcMsg::Write(m) => Some(m.op.from.shard),
            ecwire::EcMsg::Read(m) => Some(m.op.from.shard),
            ecwire::EcMsg::WriteReply(m) => Some(m.op.from.shard),
            // NOT checked: a stale instance (shard of an old interval) answers a read the primary addressed to exactly that
            // (osd, shard); the primary waits for it until the next interval (live: 05-split stuck recovery after a remap)
            ecwire::EcMsg::ReadReply(_) => None,
        },
    }
}

/// Outbound shard-vs-pool-type validation (single choke point, see [`PgSet::finish`]): replicated pools only ever
/// use `NO_SHARD` and only when this OSD serves them (not tiered, adr 0168); erasure pools only when this OSD serves them as a shard (support gate + kill switch), only the
/// allow-listed replica-side message types, and only with a shard in range that the receiver holds in the current
/// mapping. Returns the violation, if any.
pub(super) fn spg_violation(
    map: &dyn crate::map::PgMapView,
    serves: &dyn Fn(u64) -> bool,
    declines: &dyn Fn(u64) -> bool,
    primary_ok: bool,
    me: i32,
    to: i32,
    b: &Body,
) -> Option<&'static str> {
    for spg in body_spgs(b) {
        let Some(pool) = map.pool(spg.pgid.pool) else {
            // unknown pool: replicated rule (shard must be NO_SHARD)
            if spg.shard != ShardId::NO_SHARD {
                return Some("outbound spg with shard in unknown pool");
            }
            continue;
        };
        if pool.is_erasure {
            // decline mode (adr 0039 am. 1): only its own six answers, then the same shard rules as a shard
            let declined = !serves(spg.pgid.pool) && declines(spg.pgid.pool);
            let primary_ok = primary_ok && !declined;
            if declined {
                if let Some(why) = super::decline::decline_violation(b) {
                    return Some(why);
                }
            } else if !serves(spg.pgid.pool) {
                return Some("outbound message for passive erasure pool");
            } else if !ec_shard_may_send(b, primary_ok) {
                return Some("outbound message type not allowed for an EC shard");
            }
            if spg.shard.0 < 0 || spg.shard.0 as u32 >= pool.size {
                return Some("outbound spg shard out of range for erasure pool");
            }
            let m = map.pg_mapping(spg.pgid);
            let i = spg.shard.0 as usize;
            // strays are queried / purged at the shard they held in an OLD interval (they hold it in no current mapping);
            // an OSD without such an instance answers DNE, so these two may name any shard in range
            // The acting primary also activates and reads from strays that hold what recovery needs (spec missing-loc.md
            // 4.4, 6): MOSDPGInfo2 and EC sub-reads to an old shard instance.
            let to_stray = matches!(
                b,
                Body::Peering(PeeringMsg::MOSDPGQuery2(_) | PeeringMsg::MOSDPGRemove(_))
            ) || (primary_ok
                && m.acting_primary == me
                && matches!(
                    b,
                    Body::Peering(PeeringMsg::MOSDPGInfo2(_)) | Body::Ec(ecwire::EcMsg::Read(_))
                ));
            if !to_stray && m.acting.get(i) != Some(&to) && m.up.get(i) != Some(&to) {
                return Some("outbound spg shard is not the receiver's shard");
            }
            if let Body::Peering(p) = b {
                // classic EC peers assert on the sender's own shard: `pg_notify_t(from == info.pgid.shard)`, and key
                // MInfoRec / MLogRec by `info.pgid.shard`. Our shard is our position in the mapping (a stray outside
                // up/acting keeps the shard of its on-disk PG: nothing to compare with).
                // With a pg_temp the acting and up positions of this OSD differ (the PG runs on the old members while the
                // up set already names the new positions): either is "ours".
                let at = |v: &[i32], s: ShardId| s.0 >= 0 && v.get(s.0 as usize) == Some(&me);
                let any = m.acting.contains(&me) || m.up.contains(&me);
                let own = |s: ShardId| !any || at(&m.acting, s) || at(&m.up, s);
                // With the primary role on (`primary_ok`) the acting primary needs the Notify / Log of STRAYS (an instance of
                // an old shard position next to the current one, e.g. after a remap): their shard is no position of this OSD
                // in the mapping, so `own` is not applied there (the classic assert, from == info.pgid.shard, still is). A
                // primary also sends Log / Info about the replica's shard, not its own.
                let bad = match p {
                    PeeringMsg::MOSDPGNotify2(n) => {
                        n.notify.to != spg.shard
                            || n.notify.from.0 < 0
                            || n.notify.from != n.notify.info.pgid.shard
                            || (!primary_ok && !n.notify.info.dne_flag() && !own(n.notify.from))
                    }
                    PeeringMsg::MOSDPGLog(l) => {
                        l.to != spg.shard
                            || l.from.0 < 0
                            || (l.from != l.info.pgid.shard && !primary_ok)
                            || (!primary_ok && !l.info.dne_flag() && !own(l.from))
                    }
                    PeeringMsg::MOSDPGInfo2(i) => {
                        i.info.pgid.shard.0 < 0 || (!primary_ok && !own(i.info.pgid.shard))
                    }
                    PeeringMsg::MOSDPGQuery2(q) => q.query.to != spg.shard || q.query.from.0 < 0,
                    _ => false,
                };
                if bad {
                    return Some("outbound notify/log/query shard mismatch in erasure pool");
                }
            }
            // the sender names ITS shard in the message: it must be the position this OSD holds in the mapping
            // (a stale PG instance after a remap would otherwise confuse classic peers)
            if let Some(s) = claimed_from(b) {
                let held = (s.0 >= 0).then_some(s.0 as usize);
                if held.is_none_or(|i| m.acting.get(i) != Some(&me) && m.up.get(i) != Some(&me)) {
                    return Some("outbound message claims a shard this OSD does not hold");
                }
            }
            continue;
        }
        if !serves(spg.pgid.pool) {
            return Some("outbound message for passive replicated pool");
        }
        if spg.shard != ShardId::NO_SHARD {
            return Some("outbound spg with shard in replicated pool");
        }
        if matches!(b, Body::Ec(_)) {
            return Some("outbound EC message for a replicated pool");
        }
        if let Body::Peering(p) = b {
            let bad = match p {
                PeeringMsg::MOSDPGNotify2(n) => {
                    n.notify.from != ShardId::NO_SHARD || n.notify.to != ShardId::NO_SHARD
                }
                PeeringMsg::MOSDPGLog(l) => {
                    l.from != ShardId::NO_SHARD || l.to != ShardId::NO_SHARD
                }
                _ => false,
            };
            if bad {
                return Some("outbound notify/log with shard in replicated pool");
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use pgwire::MOSDPGLease;

    fn map() -> crate::map::MapHandle {
        let mut m = SynthMap::new(3)
            .with_osd(0, 1)
            .with_osd(1, 1)
            .with_osd(2, 1)
            .with_pool(1, 3, 2, 8)
            .with_pool(7, 3, 2, 8);
        m.pools.get_mut(&7).unwrap().is_erasure = true;
        m.into_handle()
    }

    fn lease(pool: u64, shard: i8) -> Body {
        Body::Peering(
            MOSDPGLease {
                epoch: 3,
                spgid: SpgT {
                    pgid: PgT::new(pool, 1),
                    shard: ShardId(shard),
                },
                lease: Default::default(),
            }
            .into(),
        )
    }

    fn lease_ack(pool: u64, shard: i8) -> Body {
        Body::Peering(
            pgwire::MOSDPGLeaseAck {
                epoch: 3,
                spgid: SpgT {
                    pgid: PgT::new(pool, 1),
                    shard: ShardId(shard),
                },
                lease_ack: Default::default(),
            }
            .into(),
        )
    }

    #[test]
    fn outbound_shard_choke_point() {
        let m = map();
        let no = |_: u64| false;
        let rep = |p: u64| p == 1;
        // replicated + NO_SHARD: fine
        assert!(spg_violation(&*m, &rep, &|_: u64| false, false, 0, 0, &lease(1, -1)).is_none());
        // replicated pool this OSD does not serve (tiered, adr 0168): refused
        assert!(spg_violation(&*m, &no, &|_: u64| false, false, 0, 0, &lease(1, -1)).is_some());
        // the bogus message that crashed classic OSDs: NO_SHARD spg in an EC pool
        assert!(spg_violation(&*m, &no, &|_: u64| false, false, 0, 0, &lease(7, -1)).is_some());
        // EC pool we do not serve (gate / kill switch): refused whatever the shard
        assert!(spg_violation(&*m, &no, &|_: u64| false, false, 0, 0, &lease(7, 1)).is_some());
        // replicated pool with a shard
        assert!(spg_violation(&*m, &rep, &|_: u64| false, false, 0, 0, &lease(1, 1)).is_some());
        // EC message for a replicated pool
        assert!(
            spg_violation(
                &*m,
                &rep,
                &|_: u64| false,
                false,
                0,
                0,
                &ec_read_reply(1, -1)
            )
            .is_some()
        );
    }

    /// Read reply to `shard`, claimed to come from shard 1.
    fn ec_read_reply(pool: u64, shard: i8) -> Body {
        Body::Ec(
            ecwire::MOSDECSubOpReadReply {
                pgid: SpgT {
                    pgid: PgT::new(pool, 1),
                    shard: ShardId(shard),
                },
                map_epoch: 3,
                op: ecwire::ECSubReadReply {
                    from: denc::types::PgShard {
                        osd: 0,
                        shard: ShardId(1),
                    },
                    ..Default::default()
                },
                min_epoch: 3,
                trace: [0; 3],
            }
            .into(),
        )
    }

    #[test]
    fn outbound_ec_allow_list() {
        let m = map();
        let yes = |p: u64| p == 7;
        // the receiver must hold the shard in the current mapping
        let mp = m.pg_mapping(PgT::new(7, 1));
        let to = mp.up[0];
        let wrong = mp.up[1];
        let me = mp.up[1]; // the sender holds shard 1
        // replica-side reply with the right shard / receiver: allowed
        assert!(
            spg_violation(&*m, &yes, &|_: u64| false, false, me, to, &lease_ack(7, 0)).is_none()
        );
        assert!(
            spg_violation(
                &*m,
                &yes,
                &|_: u64| false,
                false,
                me,
                to,
                &ec_read_reply(7, 0)
            )
            .is_none()
        );
        // a read reply of a stale instance (shard held in an old interval, remapped since) IS sent: the primary asked
        // exactly that (osd, shard) and waits for the answer (classic does the same); dropping it stalls its recovery
        assert!(
            spg_violation(
                &*m,
                &yes,
                &|_: u64| false,
                false,
                to,
                to,
                &ec_read_reply(7, 0)
            )
            .is_none()
        );
        // wrong receiver for that shard, shard out of range, NO_SHARD
        assert!(
            spg_violation(
                &*m,
                &yes,
                &|_: u64| false,
                false,
                0,
                wrong,
                &ec_read_reply(7, 0)
            )
            .is_some()
        );
        assert!(
            spg_violation(
                &*m,
                &yes,
                &|_: u64| false,
                false,
                0,
                to,
                &ec_read_reply(7, 3)
            )
            .is_some()
        );
        assert!(
            spg_violation(
                &*m,
                &yes,
                &|_: u64| false,
                false,
                0,
                to,
                &ec_read_reply(7, -1)
            )
            .is_some()
        );
        // primary-side message types are never allowed from a shard
        assert!(spg_violation(&*m, &yes, &|_: u64| false, false, 0, to, &lease(7, 0)).is_some());
    }

    /// Classic EC peers assert `pg_notify_t.from == info.pgid.shard` and key every notify / info / log by the sender's
    /// shard: ours is our position in the mapping.
    #[test]
    fn outbound_ec_sender_shard() {
        let m = map();
        let yes = |p: u64| p == 7;
        let mp = m.pg_mapping(PgT::new(7, 1));
        let (me, primary) = (mp.up[1], mp.up[0]);
        let pgid = PgT::new(7, 1);
        let spg = |s: i8| SpgT {
            pgid,
            shard: ShardId(s),
        };
        let info = |s: i8| {
            let mut i = pgwire::PgInfo::new(spg(s));
            i.history.epoch_created = 5; // a real PG (no epoch_created = the DNE reply)
            i
        };
        let notify = |from: i8, info_shard: i8| {
            Body::Peering(
                pgwire::MOSDPGNotify2 {
                    spgid: spg(0),
                    notify: pgwire::PgNotify {
                        to: ShardId(0),
                        from: ShardId(from),
                        info: info(info_shard),
                        ..Default::default()
                    },
                }
                .into(),
            )
        };
        // we are shard 1
        assert!(
            spg_violation(
                &*m,
                &yes,
                &|_: u64| false,
                false,
                me,
                primary,
                &notify(1, 1)
            )
            .is_none()
        );
        // from != info.pgid.shard: the classic constructor assert
        assert!(
            spg_violation(
                &*m,
                &yes,
                &|_: u64| false,
                false,
                me,
                primary,
                &notify(1, 2)
            )
            .is_some()
        );
        // someone else's shard
        assert!(
            spg_violation(
                &*m,
                &yes,
                &|_: u64| false,
                false,
                me,
                primary,
                &notify(2, 2)
            )
            .is_some()
        );
        // the DNE reply to a query for a shard we do not hold names the QUERIED shard: classic expects exactly that answer
        // (an unanswered query keeps its primary in GetInfo forever)
        let dne = Body::Peering(
            pgwire::MOSDPGNotify2 {
                spgid: spg(0),
                notify: pgwire::PgNotify::dne(pgwire::PgInfo::dne(spg(2)), ShardId(0), 3, 3),
            }
            .into(),
        );
        assert!(spg_violation(&*m, &yes, &|_: u64| false, false, me, primary, &dne).is_none());
        let info2 = |s: i8| {
            Body::Peering(
                pgwire::MOSDPGInfo2 {
                    spgid: spg(0),
                    epoch_sent: 3,
                    min_epoch: 3,
                    info: info(s),
                    lease: None,
                    lease_ack: None,
                }
                .into(),
            )
        };
        assert!(spg_violation(&*m, &yes, &|_: u64| false, false, me, primary, &info2(1)).is_none());
        assert!(spg_violation(&*m, &yes, &|_: u64| false, false, me, primary, &info2(2)).is_some());
        assert!(
            spg_violation(&*m, &yes, &|_: u64| false, false, me, primary, &info2(-1)).is_some()
        );
    }

    /// Decline mode (adr 0039 am. 1): only the six answers, every info incomplete, then the usual shard rules.
    #[test]
    fn outbound_decline_allow_list() {
        let m = map();
        let no = |_: u64| false;
        let decl = |p: u64| p == 7;
        let mp = m.pg_mapping(PgT::new(7, 1));
        let (me, primary) = (mp.up[1], mp.up[0]);
        let pgid = PgT::new(7, 1);
        let spg = |s: i8| SpgT {
            pgid,
            shard: ShardId(s),
        };
        let v = |b: &Body| spg_violation(&*m, &no, &decl, true, me, primary, b);
        let mut incomplete = pgwire::PgInfo::dne(spg(1));
        incomplete.last_backfill = denc::types::Hobject::MIN();
        let notify = |info: pgwire::PgInfo| {
            Body::Peering(
                pgwire::MOSDPGNotify2 {
                    spgid: spg(0),
                    notify: pgwire::PgNotify::dne(info, ShardId(0), 3, 3),
                }
                .into(),
            )
        };
        assert!(v(&notify(incomplete.clone())).is_none());
        // a complete (classic nopg style) info would make us an acting member: never
        assert!(v(&notify(pgwire::PgInfo::dne(spg(1)))).is_some());
        let info2 = |info: pgwire::PgInfo, lease_ack: bool| {
            Body::Peering(
                pgwire::MOSDPGInfo2 {
                    spgid: spg(0),
                    epoch_sent: 3,
                    min_epoch: 3,
                    info,
                    lease: None,
                    lease_ack: lease_ack.then(Default::default),
                }
                .into(),
            )
        };
        assert!(v(&info2(incomplete.clone(), false)).is_none());
        assert!(v(&info2(incomplete.clone(), true)).is_some());
        let resv = |ty| {
            Body::Repl(ReplMsg::BackfillReserve(replwire::MBackfillReserve::reply(
                spg(0),
                3,
                ty,
            )))
        };
        assert!(v(&resv(replwire::MBackfillReserve::REJECT_TOOFULL)).is_none());
        assert!(v(&resv(replwire::MBackfillReserve::GRANT)).is_some());
        // shard rules still apply: an answer to the wrong receiver / naming a shard we do not hold
        let wr = |to_shard: i8, from_shard: i8| {
            Body::Ec(
                ecwire::MOSDECSubOpWriteReply {
                    pgid: spg(to_shard),
                    map_epoch: 3,
                    op: ecwire::ECSubWriteReply {
                        from: denc::types::PgShard {
                            osd: me,
                            shard: ShardId(from_shard),
                        },
                        tid: 1,
                        ..Default::default()
                    },
                    min_epoch: 3,
                    trace: [0; 3],
                }
                .into(),
            )
        };
        assert!(v(&wr(0, 1)).is_none());
        assert!(v(&wr(1, 1)).is_some());
        assert!(v(&wr(0, 2)).is_some());
        // everything a shard / primary sends otherwise: never (primary_ok is ignored for a declined pool)
        assert!(v(&lease(7, 0)).is_some());
        assert!(v(&lease_ack(7, 0)).is_some());
        assert!(v(&ec_read_reply(7, 0)).is_some());
        // not declined and not served: passive
        assert!(spg_violation(&*m, &no, &no, false, me, primary, &notify(incomplete)).is_some());
    }
}
