// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Primary role: GetInfo / GetLog / GetMissing / WaitUpThru / Active, choose_acting, activation,
//! client write fan-out (MOSDRepOp), leases, trimming and stats (spec peering.md 5.2, 6, 8.2, 9).
//! Primary-side backfill: `backfill.rs`.

use crate::pg::*;
use crate::plog::{
    MissingSet, merge_log, merge_log_ec, proc_replica_log, proc_replica_log_ec,
    recompute_last_complete,
};
use crate::store::StoreReadError;
use crate::store::{PgStoreOps, StoreOp};
use crate::types::*;
use denc::types::{Eversion, Hobject, OsdReqId, PgShard, SpgT, UTime};
use pgwire::state as pgs;
use pgwire::{
    LogEntry, LogOp, MOSDPGInfo2, MOSDPGLease, MOSDPGLeaseAck, MOSDPGLog, MOSDPGNotify2,
    MOSDPGQuery2, MOSDPGRemove, PeeringMsg, PgInfo, PgLease, PgLeaseAck, PgNotify, PgQuery, PgStat,
    PriorSet, QueryType,
};
use replwire::{MOSDRepOp, MOSDRepOpReply, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;

/// An in-flight replicated write.
#[derive(Debug, Clone)]
pub(crate) struct RepOp {
    pub version: Eversion,
    /// Members whose commit is outstanding, by pg_shard: an EC acting set may hold one remote OSD at two positions
    /// (adr 0049 am. 3); replicated keys are `(osd, NO_SHARD)`.
    pub waiting: BTreeSet<PgShard>,
    pub local_done: bool,
    /// EC write objects retained until every shard committed; empty for replicated/log-only writes.
    pub ec_objects: Vec<Hobject>,
    /// LAB: `wprof::lat_t0` at submit (0 in production builds), local-durable time.
    pub t0: u64,
    pub t_local: u64,
}

/// Refusal reasons of the EC primary role switches (not sticky: cleared when the switch is on at an interval start).
pub(crate) const REFUSE_OPT_ROLE: &str =
    "optimized EC PG led by this OSD: mode O primary role disabled (ec_opt_primary)";
pub(crate) const REFUSE_EC_ROLE: &str =
    "erasure-coded PG led by this OSD: primary role disabled (ec_enable_primary)";
/// Not a switch (spec 9.1): the map elected our nonprimary shard; `ec_np_primary_escape` asks for a pg_temp. A normal
/// transient after OSD restarts (classic does the same): a note, not an error.
pub(crate) const REFUSE_NP_SHARD: &str = "optimized EC PG: the map elected our nonprimary shard as primary (a nonprimary shard never leads)";

/// Primary-only transient state (cleared at every interval start).
#[derive(Debug, Default)]
pub(crate) struct Prim {
    /// Latest recovered-state durability fence; a newer recovery in the same interval supersedes it.
    pub recovery_complete: Option<u64>,
    pub peer_info: BTreeMap<PgShard, PgInfo>,
    pub peer_missing: BTreeMap<PgShard, MissingSet>,
    pub peer_info_requested: BTreeSet<PgShard>,
    pub peer_missing_requested: BTreeSet<PgShard>,
    pub prior: PriorSet,
    /// Members of earlier intervals that were down when the prior set was built and may still serve reads under their
    /// lease (`prior_readable_down_osds`, peering.md 5.3 / 8.2); an OSD leaves it once the map says it is dead.
    pub lease_down: BTreeSet<i32>,
    pub need_up_thru: bool,
    pub up_thru_sent: u32,
    pub might_have_unfound: BTreeSet<PgShard>,
    pub stray_set: BTreeSet<PgShard>,
    /// Strays activated as recovery sources this interval (spec missing-loc.md 4.4).
    pub stray_src: BTreeSet<PgShard>,
    pub peer_purged: BTreeSet<PgShard>,
    pub want_acting: Vec<i32>,
    /// The pg_temp asked for in this interval: sent once per wanted value, again only with a new mon session
    /// ([`crate::PgSet::resend_mon_requests`]); the mon applies it (new interval), ignores it because the primary changed
    /// (new interval) or it was lost with the session (adr 0023 am. 1).
    pub pending_temp: Option<Vec<i32>>,
    pub acting_recovery_backfill: BTreeSet<PgShard>,
    pub backfill_targets: BTreeSet<PgShard>,
    pub async_recovery_targets: BTreeSet<PgShard>,
    pub auth_shard: Option<PgShard>,
    /// Shard whose log GetLog fetches (mode O: may be a nonprimary shard, prim spec C.1); `None` = `auth_shard`.
    pub log_shard: Option<PgShard>,
    /// Mode O repeat GetLog (prim spec C.2): our log is behind the authoritative one and the get-log shard is
    /// nonprimary: fetch from `auth_shard` first, then choose again.
    pub repeat_getlog: bool,
    /// A repeat GetLog ran this interval (at most one: never ping-pong between two logs).
    pub repeated_getlog: bool,
    pub got_log: Option<MOSDPGLog>,
    pub peer_activated: BTreeSet<PgShard>,
    pub peer_lcod: BTreeMap<PgShard, Eversion>,
    pub min_lcod: Eversion,
    pub pg_trim_to: Eversion,
    pub repops: BTreeMap<u64, RepOp>,
    /// `mark_unfound_lost` waiting for its log update to commit everywhere (its repop tid, objects marked).
    pub lost: Option<crate::lost::LostPending>,
    pub pg_acting_features: u64,
    pub was_creating: bool,
    /// Last query sent to each peer this round (sent again as is when it may have been lost, see `redrive_peering`).
    pub queries: BTreeMap<PgShard, PgQuery>,
    /// Activation messages whose ack (MOSDPGInfo2) is outstanding.
    pub act_sent: BTreeMap<PgShard, PeeringMsg>,
    /// A vulnerability window or rebuild episode closed since the replicas last got our info (peering.md 9.6): the next
    /// map shares it.
    pub latch_unshared: bool,
    /// `go_clean` shares the info after this event's stats publish, so the replicas get the closed window.
    pub share_after_publish: bool,
    /// Active substate class the rebuild span last saw (`latch_rebuild_step`).
    pub rb_phase: crate::latch::RbPhase,
}

impl Prim {
    /// Shard GetLog fetches the log from.
    pub(crate) fn log_src(&self) -> Option<PgShard> {
        self.log_shard.or(self.auth_shard)
    }
}

/// Result of `choose_acting`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Chosen {
    Ok,
    NeedActingChange,
    Incomplete,
}

/// A client write handed to the PG (the op layer built the shipped transaction).
#[derive(Debug, Clone, Default)]
pub struct WriteReq {
    pub reqid: OsdReqId,
    /// Log entries to create: `(op, soid, user_version, mtime, snaps)`; versions are assigned.
    pub entries: Vec<WriteEntry>,
    /// The object-store transaction (replwire wire form).
    pub txn_middle: bytes::Bytes,
    /// Plain v9 blob, or - when `txn_refs` is non-empty - the LOCAL skeleton (`replwire::Transaction::encode_v9_split`):
    /// large write payloads stay out of line in `txn_refs` (shared with the client request, never copied) and the
    /// real blob is only built when a peer needs it (`WriteReq::wire`). Never send `txn_data` of a skeleton on a wire.
    pub txn_data: bytes::Bytes,
    pub txn_refs: Vec<bytes::Bytes>,
    /// Known crcs (owner-bound hints) of payloads in `txn_refs`, any order: `wire_rope` uses a matching one instead
    /// of a pass over the payload.
    pub txn_ref_crcs: Vec<replwire::BlobCrc>,
    /// Temp object this write creates) (copy staging, adr 0057 am. 1): remembered like a recovery temp (removed again at
    /// the next interval change) and announced to the replicas (`new_temp_oid`). A write without log entries is an
    /// unlogged temp write: no version, applied everywhere (also on backfill targets), acked like any repop.
    pub new_temp: Option<Hobject>,
    /// Temp object this write consumed (renamed into place) or drops: forgotten here and by the replicas
    /// (`discard_temp_oid`).
    pub discard_temp: Option<Hobject>,
}

impl WriteReq {
    /// `(middle, data)` as it goes into a MOSDRepOp: the stored blob, or the skeleton rebuilt into plain v9.
    pub fn wire(&self) -> Result<(bytes::Bytes, bytes::Bytes), WriteErr> {
        self.wire_crc().map(|(m, d, _)| (m, d))
    }

    /// [`Self::wire`] plus, for a rebuilt skeleton, the crc32c of the blob made during the payload copy (the msgr2
    /// frame then needs no pass over it; byte-exact by construction, see `Transaction::encode_v9_crc`).
    pub fn wire_crc(&self) -> Result<(bytes::Bytes, bytes::Bytes, replwire::BlobCrc), WriteErr> {
        if self.txn_refs.is_empty() {
            return Ok((
                self.txn_middle.clone(),
                self.txn_data.clone(),
                Default::default(),
            ));
        }
        let (t, crc) =
            Transaction::decode_split(&self.txn_data, &self.txn_refs, replwire::DEFAULT_PAGE)
                .and_then(|t| t.encode_v9_crc())
                .map_err(|_| WriteErr::TooBig(denc::errno::EINVAL))?;
        let blob: bytes::Bytes = t.into();
        let h = replwire::BlobCrc::new(&blob, crc);
        Ok((bytes::Bytes::new(), blob, h))
    }

    /// The MOSDRepOp DATA segment in rope form (`MOSDRepOp::txn_data_more`): for a skeleton, the v9 encoding without
    /// the large payloads (`Transaction::encode_v9_rope`) cut into pieces around the shared client payloads, which
    /// go to the peers by reference with their crc (one read pass here, no copy). A plain blob has no parts.
    pub fn wire_rope(&self) -> Result<WireRope, WriteErr> {
        if self.txn_refs.is_empty() {
            return Ok(WireRope {
                middle: self.txn_middle.clone(),
                data: self.txn_data.clone(),
                ..Default::default()
            });
        }
        let bad = |_| WriteErr::TooBig(denc::errno::EINVAL);
        let t = Transaction::decode_split(&self.txn_data, &self.txn_refs, replwire::DEFAULT_PAGE)
            .map_err(bad)?;
        let (head, cuts) = t.encode_v9_rope(&self.txn_refs).map_err(bad)?;
        let head = bytes::Bytes::from(head);
        let mut pieces: Vec<(bytes::Bytes, replwire::BlobCrc)> =
            Vec::with_capacity(2 * cuts.len() + 1);
        let mut pos = 0;
        for (at, r) in cuts {
            pieces.push((head.slice(pos..at), Default::default()));
            let h = match self.txn_ref_crcs.iter().find(|h| h.of(&r).is_some()) {
                Some(h) => h.clone(),
                None => replwire::BlobCrc::new(&r, crc::crc32c(!0, &r)),
            };
            pieces.push((r, h));
            pos = at;
        }
        pieces.push((head.slice(pos..), Default::default()));
        let (first, _) = pieces.remove(0);
        pieces.retain(|(b, _)| !b.is_empty());
        Ok(WireRope {
            data: first,
            more: pieces,
            ..Default::default()
        })
    }
}

/// The MOSDRepOp transaction fields of a write ([`WriteReq::wire_rope`]).
#[derive(Debug, Clone, Default)]
pub struct WireRope {
    pub middle: bytes::Bytes,
    pub data: bytes::Bytes,
    /// crc of `data`.
    pub data_crc: replwire::BlobCrc,
    /// Further pieces with their crcs.
    pub more: Vec<(bytes::Bytes, replwire::BlobCrc)>,
}

/// A replicated write planned against the current log head (entries numbered, peer encoding built).
#[derive(Debug)]
pub(crate) struct WritePlan {
    last: Eversion,
    pct: Eversion,
    entries: Vec<LogEntry>,
    encs: Vec<bytes::Bytes>,
    logbl: bytes::Bytes,
    wire: Option<WireRope>,
    w: WriteReq,
}

/// A peer received a write up to `last` (classic `pre_submit_op`): a peer that is complete stays complete, one with
/// missing objects keeps its `last_complete`.
pub(crate) fn peer_info_written(pi: &mut pgwire::PgInfo, last: Eversion) {
    if pi.last_complete == pi.last_update {
        pi.last_complete = last;
    }
    pi.last_update = last;
}

/// One log entry template of a write.
#[derive(Debug, Clone)]
pub struct WriteEntry {
    pub op: LogOp,
    pub soid: Hobject,
    pub user_version: u64,
    pub mtime: UTime,
    pub snaps: Vec<u8>,
    /// `return_code` of the entry (ERROR entries and RETURNVEC writes).
    pub return_code: i32,
    /// Per-op results of a RETURNVEC write (replayed for dups).
    pub op_returns: Vec<pgwire::LogOpReturnItem>,
    /// Version of the object this entry replaces (`0'0` = it did not exist) when the executor already loaded the
    /// object info for the same op; `None` = the PG asks the store (only for objects outside the log window).
    pub prior: Option<Eversion>,
}

impl Pg {
    // ---- start / GetInfo -----------------------------------------------------------------------

    /// Optimized pool, the map elected our NONPRIMARY shard (spec 9.1, adr 0067 am. O9): a nonprimary shard can never
    /// lead, so ask for pg_temp = the current acting set in shard order padded with NONE (the mon stores optimized
    /// pg_temps primary-capable-first, which moves the primary to a primary-capable shard), exactly what a classic
    /// nonprimary primary sends when want == acting. Only if some primary-capable position is filled.
    fn ec_np_primary_escape(&mut self) {
        let Some(e) = self.pool.ec.as_ref().filter(|e| e.supported && e.optimized) else {
            return;
        };
        let me = self.me.shard.0;
        if me < 0 || !e.is_nonprimary(me as u32) {
            return;
        }
        let size = self.pool.size as usize;
        let pc_present = |v: &[i32]| {
            v.iter()
                .enumerate()
                .any(|(s, o)| *o != pgwire::NONE_OSD && *o >= 0 && !e.is_nonprimary(s as u32))
        };
        let mut want = self.acting.clone();
        want.resize(size, pgwire::NONE_OSD);
        if !pc_present(&want) {
            // a pg_temp whose primary-capable members went down (the mon NONEs them) leaves us the only member: acting
            // can never hand the lead on, the up set can (adr 0067 am. 7)
            want = self.up.clone();
            want.resize(size, pgwire::NONE_OSD);
        }
        if !pc_present(&want) || want.len() != size {
            return;
        }
        self.notes.push(format!(
            "pg {}: map elected our nonprimary shard {me} as primary of an optimized EC PG: requesting pg_temp {want:?}",
            self.spg
        ));
        self.request_pg_temp(want);
    }

    pub(crate) fn primary_start(&mut self) {
        self.ec_lead_cfg = self.ec_lead_cfg_now();
        if self.ec_lead_cfg
            && matches!(self.refuse, Some(r) if r == REFUSE_OPT_ROLE || r == REFUSE_EC_ROLE || r == REFUSE_NP_SHARD)
        {
            // a role switch turned on again: it applies from this interval on; a new interval may elect another shard
            self.refuse = None;
        }
        if self.pool.is_erasure && self.refuse.is_none() && !self.ec_may_lead() {
            self.ec_refused_clear_temp();
            let np = self.ec_np_shard();
            // shard role only (adr 0039, 0049): lead an EC PG only with `ec_enable_primary`; else the operator sets
            // primary-affinity 0 on croit-flashstore-osd OSDs
            self.refuse = Some(match self.pool.ec.as_ref() {
                _ if np && self.ec_lead_cfg => REFUSE_NP_SHARD,
                Some(e) if e.optimized => REFUSE_OPT_ROLE,
                _ => REFUSE_EC_ROLE,
            });
            if self.refuse != Some(REFUSE_NP_SHARD) {
                self.notes.push(format!(
                    "pg {}: led by this OSD but the EC primary role is not implemented; set primary-affinity 0 on croit-flashstore-osd OSDs",
                    self.spg
                ));
            }
        }
        if self.refuse.is_some() {
            self.ec_np_primary_escape();
        }
        if let Some(why) = self.refuse {
            // unsupported pool feature: never peer, never activate (spec 7.7: refuse, do not corrupt)
            if why == REFUSE_NP_SHARD {
                self.notes.push(format!("pg {}: {why}", self.spg));
            } else {
                self.error(why);
            }
            self.set_st(St::Primary(PSt::Incomplete));
            self.state |= pgs::INCOMPLETE;
            return;
        }
        self.set_st(St::Primary(PSt::GetInfo));
        self.state |= pgs::PEERING;
        self.prim.was_creating = self.info.history.last_epoch_started == 0;
        if self.prim.was_creating {
            self.state |= pgs::CREATING;
            self.latch_created();
        }
        self.prim.pg_acting_features = self.cfg.pg_features;
        self.get_info_enter();
    }

    fn build_prior(&mut self) {
        let les = self.info.history.last_epoch_started;
        let (ec, min_present) = if self.pool.is_erasure {
            (true, self.pool.ec_k.max(1) as usize)
        } else {
            (false, 1)
        };
        self.prim.prior = PriorSet::build(
            &self.past,
            ec,
            min_present,
            les,
            &self.up,
            &self.acting,
            &*self.map,
        );
        self.prim.lease_down = self.prim.prior.down.clone();
        self.prim.need_up_thru =
            self.map.up_thru(self.me.osd) < self.info.history.same_interval_since;
    }

    /// Drop the prior-lease holders the map now shows dead (they marked themselves dead: MOSDMarkMeDead). When the
    /// last one goes, nothing of an earlier interval can still be read and the prior bound is void. Returns true then
    /// (the caller re-checks readability: WAIT ends early, peering.md 8.2 `check_prior_readable_down_osds`).
    pub(crate) fn check_lease_down(&mut self) -> bool {
        let n = self.prim.lease_down.len();
        let m = self.map.clone();
        self.prim.lease_down.retain(|o| !m.is_dead(*o));
        if self.prim.lease_down.len() == n || !self.prim.lease_down.is_empty() {
            return false;
        }
        self.lease.prior_ub = 0;
        true
    }

    fn get_info_enter(&mut self) {
        // GetInfo entry (peering.md 3.8): before the prior set is built, i.e. before any query of this round
        if self.check_past_interval_bounds() {
            return;
        }
        self.build_prior();
        self.query_probe_peers();
        self.check_lease_down();
        if self.prim.prior.pg_down {
            self.enter_down();
        } else if self.prim.peer_info_requested.is_empty() {
            self.got_info();
        }
    }

    fn query_probe_peers(&mut self) {
        let probe: Vec<PgShard> = self.prim.prior.probe.iter().copied().collect();
        for p in probe {
            if p == self.me {
                continue;
            }
            if self.prim.peer_info.contains_key(&p) || self.prim.peer_info_requested.contains(&p) {
                continue;
            }
            if !self.map.is_up(p.osd) {
                continue;
            }
            let q = PgQuery {
                ty: QueryType::INFO,
                since: Eversion::default(),
                history: self.history_for_send(),
                epoch_sent: self.map.epoch(),
                to: p.shard,
                from: self.me.shard,
            };
            self.send_query(p, q);
            self.prim.peer_info_requested.insert(p);
        }
    }

    // ---- lost peering messages (adr 0071) ----------------------------------------------------------

    pub(crate) fn send_query(&mut self, p: PgShard, q: PgQuery) {
        self.prim.queries.insert(p, q.clone());
        self.send_peering(
            p.osd,
            MOSDPGQuery2 {
                spgid: SpgT {
                    pgid: self.spg.pgid,
                    shard: p.shard,
                },
                query: q,
            },
        );
    }

    /// Send the query this peering round recorded for `p` again (a duplicate is harmless). False = none recorded.
    fn resend_query(&mut self, p: PgShard) -> bool {
        let Some(q) = self.prim.queries.get(&p).cloned() else {
            return false;
        };
        self.send_peering(
            p.osd,
            MOSDPGQuery2 {
                spgid: SpgT {
                    pgid: self.spg.pgid,
                    shard: p.shard,
                },
                query: q,
            },
        );
        true
    }

    fn send_activation(&mut self, p: PgShard, m: impl Into<PeeringMsg>) {
        let m: PeeringMsg = m.into();
        self.prim.act_sent.insert(p, m.clone());
        self.send_peering(p.osd, m);
    }

    /// Send again what this primary round still waits an answer for from `osd`: the queries of GetInfo / GetLog /
    /// GetMissing and the activations not acked yet. A duplicate is harmless (msgr replay produces the same); a peer the
    /// map marks down is skipped. Activations go again only to peers `act_to` accepts (croit-flashstore-osd: a classic replica would
    /// merge a repeated activation log). Returns the number of messages sent.
    pub(crate) fn redrive_peering(&mut self, osd: i32, act_to: &impl Fn(i32) -> bool) -> usize {
        let St::Primary(sub) = self.st else {
            return 0;
        };
        let me = self.me;
        let map = self.map.clone();
        let want = |p: &PgShard| *p != me && p.osd == osd && map.is_up(p.osd);
        let peers: Vec<PgShard> = match sub {
            PSt::GetInfo => self.prim.peer_info_requested.iter().copied().collect(),
            PSt::GetLog if self.prim.got_log.is_none() => self.prim.log_src().into_iter().collect(),
            PSt::GetMissing => self.prim.peer_missing_requested.iter().copied().collect(),
            PSt::Active(_) => {
                let mut n = 0;
                // stray probes (spec missing-loc.md 4.2)
                for p in self
                    .prim
                    .peer_missing_requested
                    .clone()
                    .into_iter()
                    .filter(|p| want(p))
                {
                    if self.resend_query(p) {
                        n += 1;
                    }
                }
                if self.state & pgs::ACTIVATING == 0 {
                    self.counters.redrives += n as u64;
                    return n;
                }
                let acts: Vec<(PgShard, PeeringMsg)> = self
                    .prim
                    .act_sent
                    .iter()
                    .filter(|(p, _)| {
                        want(p) && act_to(p.osd) && !self.prim.peer_activated.contains(p)
                    })
                    .map(|(p, m)| (*p, m.clone()))
                    .collect();
                for (p, m) in acts {
                    self.send_peering(p.osd, m);
                    n += 1;
                }
                self.counters.redrives += n as u64;
                return n;
            }
            _ => return 0,
        };
        let mut n = 0;
        for p in peers.into_iter().filter(|p| want(p)) {
            if self.resend_query(p) {
                n += 1;
            }
        }
        self.counters.redrives += n as u64;
        n
    }

    fn enter_down(&mut self) {
        self.set_st(St::Primary(PSt::Down));
        self.state &= !pgs::PEERING;
        self.state |= pgs::DOWN;
    }

    /// Spec 3.5 `proc_replica_notify`. Returns true if the info is new.
    fn proc_replica_notify(&mut self, from: i32, n: &PgNotify) -> bool {
        let p = PgShard {
            osd: from,
            shard: n.from,
        };
        if let Some(pi) = self.prim.peer_info.get(&p)
            && pi.last_update == n.info.last_update
        {
            return false;
        }
        if !self.map.is_up(from) || self.map.up_from(from) > n.epoch_sent {
            self.discard("notify from peer not up since epoch_sent");
            return false;
        }
        self.prim.peer_info.insert(p, n.info.clone());
        self.ec_prim_update_peer_pwlc(p, &n.info);
        self.update_history(&n.info.history);
        self.prim.might_have_unfound.insert(p);
        if self.is_stray_shard(p) {
            self.prim.stray_set.insert(p);
        }
        if self.in_acting(p) {
            self.prim.pg_acting_features &= n.pg_features;
        }
        true
    }

    pub(crate) fn on_notify(&mut self, from: i32, m: MOSDPGNotify2) {
        let St::Primary(sub) = self.st else {
            self.discard("notify in non-primary state");
            return;
        };
        let p = PgShard {
            osd: from,
            shard: m.notify.from,
        };
        match sub {
            PSt::WaitActingChange => {}
            PSt::GetInfo => {
                self.prim.peer_info_requested.remove(&p);
                let les_before = self.info.history.last_epoch_started;
                let new = self.proc_replica_notify(from, &m.notify);
                if new && self.info.history.last_epoch_started > les_before {
                    // history les rose: the prior set shrinks (older intervals are covered)
                    self.build_prior();
                    let probe = self.prim.prior.probe.clone();
                    self.prim.peer_info_requested.retain(|x| probe.contains(x));
                    self.query_probe_peers();
                }
                if self.prim.prior.pg_down {
                    self.enter_down();
                } else if self.prim.peer_info_requested.is_empty() {
                    self.got_info();
                }
            }
            PSt::Down => {
                if !self.prim.peer_info.contains_key(&p)
                    && self.map.is_up(from)
                    && self.map.up_from(from) <= m.notify.epoch_sent
                {
                    let before = self.info.history.last_epoch_started;
                    self.update_history(&m.notify.info.history);
                    if self.info.history.last_epoch_started > before {
                        self.state &= !pgs::DOWN;
                        self.state |= pgs::PEERING;
                        self.set_st(St::Primary(PSt::GetInfo));
                        self.prim.peer_info.insert(p, m.notify.info.clone());
                        self.get_info_enter();
                    }
                }
            }
            PSt::Incomplete => {
                if self.proc_replica_notify(from, &m.notify) {
                    self.state &= !pgs::INCOMPLETE;
                    self.state |= pgs::PEERING;
                    self.got_info();
                }
            }
            PSt::Active(_) => {
                if m.notify.info.is_empty() || m.notify.info.dne_flag() {
                    // a probed stray without the PG (DNE answer): nothing to wait for
                    self.prim.peer_missing_requested.remove(&p);
                }
                if self.prim.peer_info.contains_key(&p) || self.prim.peer_purged.contains(&p) {
                    return;
                }
                if self.proc_replica_notify(from, &m.notify) {
                    // an old acting member may have returned: maybe request pg_temp
                    let _ = self.choose_acting(false, true);
                    self.probe_strays_if_needed(Some(p));
                }
            }
            _ => {
                self.proc_replica_notify(from, &m.notify);
            }
        }
    }

    // ---- GetLog ----------------------------------------------------------------------------------

    fn got_info(&mut self) {
        self.set_st(St::Primary(PSt::GetLog));
        match self.choose_acting(false, false) {
            Chosen::NeedActingChange => {
                self.set_st(St::Primary(PSt::WaitActingChange));
                return;
            }
            Chosen::Incomplete => {
                self.enter_incomplete();
                return;
            }
            Chosen::Ok => {}
        }
        let Some(auth) = self.prim.log_src() else {
            self.enter_incomplete();
            return;
        };
        if auth == self.me {
            self.got_log();
            return;
        }
        let Some(ai) = self.prim.peer_info.get(&auth).cloned() else {
            self.enter_incomplete();
            return;
        };
        if self.info.last_update < ai.log_tail {
            self.enter_incomplete();
            return;
        }
        // request_log_from: lower than our last_update for peers our extended log must cover
        let mut since = self.info.last_update;
        for p in &self.prim.acting_recovery_backfill {
            if *p == self.me {
                continue;
            }
            if let Some(pi) = self.prim.peer_info.get(p)
                && pi.last_update < self.info.log_tail
                && pi.last_update >= ai.log_tail
                && pi.last_update < since
            {
                since = pi.last_update;
            }
        }
        let q = PgQuery {
            ty: QueryType::LOG,
            since,
            history: self.history_for_send(),
            epoch_sent: self.map.epoch(),
            to: auth.shard,
            from: self.me.shard,
        };
        self.send_query(auth, q);
    }

    fn enter_incomplete(&mut self) {
        self.set_st(St::Primary(PSt::Incomplete));
        self.state &= !pgs::PEERING;
        self.state |= pgs::INCOMPLETE;
    }

    pub(crate) fn primary_on_log(&mut self, from: i32, m: MOSDPGLog) {
        let St::Primary(sub) = self.st else {
            return;
        };
        let p = PgShard {
            osd: from,
            shard: m.from,
        };
        match sub {
            PSt::GetLog => {
                if self.prim.log_src() != Some(p) {
                    self.discard("log from non-auth shard");
                    return;
                }
                self.prim.got_log = Some(m);
                self.got_log();
            }
            PSt::GetMissing => {
                if self.prim.peer_missing_requested.remove(&p) {
                    self.proc_peer_log(p, &m);
                    if self.prim.peer_missing_requested.is_empty() {
                        self.after_missing();
                    }
                }
            }
            // Queries are only sent in GetLog/GetMissing: a log now is a duplicate (stale peer state, would overwrite
            // the peer info and missing set).
            PSt::Active(_) if self.stray_on_log(p, &m) => {}
            PSt::WaitUpThru | PSt::Active(_) => self.discard("duplicate peer log"),
            _ => self.discard("log in wrong primary state"),
        }
    }

    pub(crate) fn proc_peer_log(&mut self, p: PgShard, m: &MOSDPGLog) {
        let mut oinfo = m.info.clone();
        let mut omissing = MissingSet::from_wire(m.missing.clone());
        omissing.set_may_include_deletes(self.map.flags().recovery_deletes);
        // mode O (prim spec B.3): our pwlc entry for the peer's shard raises its info and log head first
        let mut olog = std::borrow::Cow::Borrowed(&m.log);
        if self.ec_opt()
            && let Some(&w) = self.info.partial_writes_last_complete.get(&p.shard)
            && w.1 <= self.log.head()
        {
            let mut head = olog.head;
            if crate::ecopt::apply_pwlc(w, &mut oinfo, Some(&mut head)) {
                olog.to_mut().head = head;
            }
        }
        match self.ec_peer_ctx(p) {
            Some(ctx) => proc_replica_log_ec(&self.log, &mut oinfo, &olog, &mut omissing, ctx),
            None => proc_replica_log(&self.log, &mut oinfo, &olog, &mut omissing),
        }
        self.update_history(&m.info.history);
        self.ec_prim_update_peer_pwlc(p, &m.info);
        self.prim.peer_info.insert(p, oinfo);
        self.prim.peer_missing.insert(p, omissing);
    }

    /// GotLog: adopt the authoritative log (`proc_master_log`) and move on.
    fn got_log(&mut self) {
        if let Some(m) = self.prim.got_log.take() {
            let Some(auth) = self.prim.log_src() else {
                return;
            };
            let mut oinfo = m.info.clone();
            let mut olog = std::borrow::Cow::Borrowed(&m.log);
            let mut stats_invalid = false;
            if self.ec_opt() {
                // a nonprimary log reaching further back than ours (its trim lags behind partial writes that skipped it):
                // only the part after our tail takes part, a sparse log never extends ours backwards (OQ 45)
                let tail = self.log.tail();
                if olog.tail < tail && olog.head >= tail {
                    let l = olog.to_mut();
                    l.log.retain(|e| e.version > tail);
                    l.tail = tail;
                    oinfo.log_tail = tail;
                }
                // prim spec B.3 / C.3: our pwlc for the log's shard first (never past our own head), then the
                // keep-partial-writes rule
                if let Some(&w) = self.info.partial_writes_last_complete.get(&auth.shard)
                    && w.1 <= self.log.head()
                {
                    let mut head = olog.head;
                    if crate::ecopt::apply_pwlc(w, &mut oinfo, Some(&mut head)) {
                        olog.to_mut().head = head;
                    }
                }
                if olog.head < self.log.head() {
                    let olast = olog.log.back().map(|e| e.version);
                    let kept = self.ec_keep_partial(auth, olog.head, olast);
                    let (oh, mine) = (olog.head, self.log.head());
                    self.ec_trace(|| {
                        format!(
                            "proc_master_log from {}/{} ohead {oh} our head {mine} kept {:?}",
                            auth.osd,
                            auth.shard.0,
                            kept.as_ref().map(|e| e.version)
                        )
                    });
                    if let Some(he) = &kept {
                        let h = he.version;
                        olog.to_mut().head = h;
                        stats_invalid = true;
                        // stats of a shard that is exactly at the new head (nonprimary only if it was written)
                        if let Some(pi) = self.prim.peer_info.iter().find_map(|(p, pi)| {
                            (pi.stats.version == h
                                && (!self.is_np_shard(*p)
                                    || crate::ecopt::writes_shard(he, p.shard.0.max(0) as u32)))
                            .then_some(pi)
                        }) {
                            oinfo.stats = pi.stats.clone();
                            stats_invalid = false;
                        }
                    }
                    if self.info.last_backfill == Hobject::MAX()
                        && self.is_np_shard(auth)
                        && kept
                            .as_ref()
                            .is_none_or(|e| !crate::ecopt::writes_shard(e, auth.shard.0 as u32))
                    {
                        stats_invalid = true;
                    }
                }
            }
            let peer_head = oinfo.last_update.max(m.log.head);
            let mut info = self.info.clone();
            let mut ops = Vec::new();
            let merged = match self.ec_ctx() {
                Some(ctx) => merge_log_ec(
                    &mut self.log,
                    &mut info,
                    &mut self.missing,
                    &mut ops,
                    &oinfo,
                    &olog,
                    ctx,
                ),
                None => merge_log(
                    &mut self.log,
                    &mut info,
                    &mut self.missing,
                    &mut ops,
                    &oinfo,
                    &olog,
                ),
            };
            match merged {
                Ok(_) => {
                    self.info = info;
                    self.info.stats.stats_invalid |= stats_invalid;
                    self.txn.extend(ops);
                    self.info_dirty = true;
                    if self.ec_opt() {
                        // consider_rollback_pwlc (prim B.3): partial-write coverage past our new head is void
                        crate::ecopt::rollback_pwlc(&mut self.info, self.log.head());
                    }
                }
                Err(_) => {
                    self.error("proc_master_log: no overlap");
                    self.enter_incomplete();
                    return;
                }
            }
            // the authoritative log is ours now: so are its les / lis (classic proc_master_log), else this shard is no
            // auth candidate if the interval changes before it activates
            self.info.last_epoch_started =
                self.info.last_epoch_started.max(oinfo.last_epoch_started);
            self.info.last_interval_started = self
                .info
                .last_interval_started
                .max(oinfo.last_interval_started);
            self.update_history(&m.info.history);
            let mut ai = oinfo;
            ai.last_update = peer_head;
            self.prim.peer_info.insert(auth, ai);
            if std::mem::take(&mut self.prim.repeat_getlog) {
                // prim spec C.2: our log caught up with the authoritative one; choose again (now the nonprimary
                // shard's log can be fetched); this shard's missing set may not match the final log
                self.prim.peer_missing.remove(&auth);
                self.prim.repeated_getlog = true;
                self.flush(Pending::Plain);
                self.got_info();
                return;
            }
            let mut pm = MissingSet::from_wire(m.missing.clone());
            pm.set_may_include_deletes(self.map.flags().recovery_deletes);
            self.prim.peer_missing.insert(auth, pm);
            self.flush(Pending::Plain);
        }
        self.get_missing_enter();
    }

    // ---- GetMissing ----------------------------------------------------------------------------------

    fn get_missing_enter(&mut self) {
        self.set_st(St::Primary(PSt::GetMissing));
        let peers: Vec<PgShard> = self
            .prim
            .acting_recovery_backfill
            .iter()
            .copied()
            .filter(|p| *p != self.me)
            .collect();
        let del = self.map.flags().recovery_deletes;
        for p in peers {
            let Some(pi) = self.prim.peer_info.get(&p).cloned() else {
                continue;
            };
            let pm = self
                .prim
                .peer_missing
                .entry(p)
                .or_insert_with(|| MissingSet::new(del));
            pm.set_may_include_deletes(del);
            if pi.is_empty() {
                continue;
            }
            if pi.last_update < self.log.tail()
                || pi.last_backfill == Hobject::MIN()
                || (pi.last_update == pi.last_complete && pi.last_update == self.info.last_update)
            {
                pm.clear();
                continue;
            }
            if self.prim.peer_missing_requested.contains(&p) {
                continue;
            }
            let since = Eversion::new(pi.last_epoch_started, 0);
            let ty = if pi.log_tail <= since {
                QueryType::LOG
            } else {
                QueryType::FULLLOG
            };
            let q = PgQuery {
                ty,
                since,
                history: self.history_for_send(),
                epoch_sent: self.map.epoch(),
                to: p.shard,
                from: self.me.shard,
            };
            self.send_query(p, q);
            self.prim.peer_missing_requested.insert(p);
        }
        if self.prim.peer_missing_requested.is_empty() {
            self.after_missing();
        }
    }

    fn after_missing(&mut self) {
        if self.prim.need_up_thru {
            self.set_st(St::Primary(PSt::WaitUpThru));
            self.update_up_thru_request();
        } else {
            self.post_activate();
        }
    }

    // ---- choose_acting (spec 6.1, 6.2) -------------------------------------------------------------

    pub(crate) fn all_infos(&self) -> BTreeMap<PgShard, &PgInfo> {
        let mut m: BTreeMap<PgShard, &PgInfo> =
            self.prim.peer_info.iter().map(|(k, v)| (*k, v)).collect();
        m.insert(self.me, &self.info);
        m
    }

    pub(crate) fn find_best_info(
        &self,
        infos: &BTreeMap<PgShard, &PgInfo>,
        restrict: bool,
        oldest: bool,
        exclude_np: bool,
    ) -> Option<PgShard> {
        // mode O (ec-optimized-prim.md C.1): nonprimary shards hold sparse logs: in the AUTH pass (`exclude_np`) they
        // never set max_les and are never authoritative (they still lower min_last_update_acceptable); the GET-LOG
        // pass considers every shard
        let np = |p: &PgShard| exclude_np && self.is_np_shard(*p);
        let max_les = infos
            .iter()
            .filter(|(p, _)| !np(p))
            .map(|(_, i)| i)
            .map(|i| {
                let a = i.history.last_epoch_started;
                if i.is_incomplete() {
                    a
                } else {
                    a.max(i.last_epoch_started)
                }
            })
            .max()?;
        let min_lu = infos
            .values()
            .filter(|i| i.last_epoch_started >= max_les)
            .map(|i| i.last_update)
            .min()?;
        let mut best: Option<(PgShard, &PgInfo)> = None;
        for (p, i) in infos {
            if restrict && self.is_stray_shard(*p) {
                continue;
            }
            if np(p) {
                continue;
            }
            if i.last_update < min_lu || i.last_epoch_started < max_les || i.is_incomplete() {
                continue;
            }
            let better = match best {
                None => true,
                Some((bp, bi)) => {
                    if i.last_update != bi.last_update {
                        // rollback pools (EC): the OLDEST member wins, everyone else rolls back to it
                        (i.last_update > bi.last_update) != oldest
                    } else if i.log_tail != bi.log_tail {
                        i.log_tail < bi.log_tail
                    } else {
                        let im = i.last_complete == i.last_update;
                        let bm = bi.last_complete == bi.last_update;
                        if im != bm {
                            im
                        } else {
                            *p == self.me && bp != self.me
                        }
                    }
                }
            };
            if better {
                best = Some((*p, i));
            }
        }
        best.map(|(p, _)| p)
    }

    /// `choose_acting`. `only_temp` = only request pg_temp (Active/Recovered callers).
    pub(crate) fn choose_acting(&mut self, restrict: bool, only_temp: bool) -> Chosen {
        if self.pool.is_erasure {
            return self.choose_acting_ec(restrict, only_temp);
        }
        let infos = self.all_infos();
        let Some(auth) = self.find_best_info(&infos, restrict, false, false) else {
            return self.no_auth_acting();
        };
        let ai = infos[&auth];
        // primary selection
        let mut primary = auth;
        if self.up_primary >= 0 {
            let cand = ps(self.up_primary);
            if let Some(ci) = infos.get(&cand)
                && !ci.is_incomplete()
                && ci.last_update >= ai.log_tail
            {
                let approx = ci.stats.stats.sum.num_objects_missing.max(0) as u64
                    + ai.last_update.version.abs_diff(ci.last_update.version);
                primary = if approx > self.cfg.force_auth_primary_missing_objects {
                    auth
                } else {
                    cand
                };
            }
        }
        let pinfo = infos[&primary];
        let oldest_auth = pinfo.log_tail.min(ai.log_tail);
        let size = self.pool.size as usize;
        // calc_replicated_acting (stretch pools: bucket diversity, stretch.md 4)
        let (mut want, acting_backfill, backfill) = if self.pool.is_stretch() {
            let fit = infos
                .iter()
                .map(|(p, i)| {
                    let f = crate::stretch::Fit {
                        usable: !i.is_incomplete() && i.last_update >= oldest_auth,
                        last_update: i.last_update,
                    };
                    (p.osd, f)
                })
                .collect();
            let r = crate::stretch::calc_replicated_acting_stretch(
                &self.pool,
                &*self.map,
                primary.osd,
                &self.up,
                &self.acting,
                &fit,
                restrict,
            );
            let set = |s: BTreeSet<i32>| -> BTreeSet<PgShard> { s.into_iter().map(ps).collect() };
            (r.want, set(r.acting_backfill), set(r.backfill))
        } else {
            let mut want = vec![primary.osd];
            let mut acting_backfill: BTreeSet<PgShard> = BTreeSet::from([primary]);
            let mut backfill: BTreeSet<PgShard> = BTreeSet::new();
            for &o in &self.up {
                if o == primary.osd || o < 0 {
                    continue;
                }
                let p = ps(o);
                let Some(i) = infos.get(&p) else { continue };
                if i.is_incomplete() || i.last_update < oldest_auth {
                    backfill.insert(p);
                    acting_backfill.insert(p);
                } else {
                    want.push(o);
                    acting_backfill.insert(p);
                }
            }
            // every up member is classified (classic: no early stop): with the primary outside up, `want` may hold
            // size + 1 entries here and is cut to size below, the member cut off stays in acting_recovery_backfill
            if want.len() < size {
                let mut cands: Vec<(Eversion, i32)> = Vec::new();
                for &o in &self.acting {
                    let p = ps(o);
                    if want.contains(&o) || self.up.contains(&o) || o < 0 {
                        continue;
                    }
                    if let Some(i) = infos.get(&p)
                        && !i.is_incomplete()
                        && i.last_update >= oldest_auth
                    {
                        cands.push((i.last_update, o));
                    }
                }
                cands.sort_by_key(|b| std::cmp::Reverse(b.0));
                for (_, o) in cands {
                    if want.len() >= size {
                        break;
                    }
                    want.push(o);
                    acting_backfill.insert(ps(o));
                }
                if !restrict && want.len() < size {
                    let mut strays: Vec<(Eversion, i32)> = Vec::new();
                    for (p, i) in &infos {
                        if want.contains(&p.osd)
                            || self.up.contains(&p.osd)
                            || self.acting.contains(&p.osd)
                        {
                            continue;
                        }
                        if !i.is_incomplete()
                            && i.last_update >= oldest_auth
                            && self.map.is_up(p.osd)
                        {
                            strays.push((i.last_update, p.osd));
                        }
                    }
                    strays.sort_by_key(|b| std::cmp::Reverse(b.0));
                    for (_, o) in strays {
                        if want.len() >= size {
                            break;
                        }
                        want.push(o);
                        acting_backfill.insert(ps(o));
                    }
                }
            }
            (want, acting_backfill, backfill)
        };
        // recoverable
        if want.is_empty()
            || (!self.cfg.allow_recovery_below_min_size && (want.len() as u32) < self.pool.min_size)
        {
            self.prim.want_acting.clear();
            return Chosen::Incomplete;
        }
        // async recovery
        let mut async_set: BTreeSet<PgShard> = BTreeSet::new();
        {
            // every up member of want, the chosen primary included (a classic primary takes itself out the same way;
            // a different choice and the two primaries undo each other's pg_temp every epoch); highest cost first, ties
            // by the larger OSD id
            let mut cands: Vec<(u64, i32)> = Vec::new();
            for &o in &want {
                if !self.up.contains(&o) {
                    continue;
                }
                let i = infos[&ps(o)];
                let cost = i.stats.stats.sum.num_objects_missing.max(0) as u64
                    + ai.last_update.version.abs_diff(i.last_update.version);
                if cost > self.cfg.async_recovery_min_cost {
                    cands.push((cost, o));
                }
            }
            cands.sort_unstable_by(|a, b| b.cmp(a));
            for (_, o) in cands {
                if want.len() as u32 <= self.pool.min_size {
                    break;
                }
                let rest: Vec<i32> = want.iter().copied().filter(|x| *x != o).collect();
                // stretch.md 5: never break the site constraint; the member recovers synchronously instead
                if !pgwire::can_peer(&*self.map, &self.pool, &rest) {
                    continue;
                }
                want = rest;
                async_set.insert(ps(o));
            }
            while want.len() > size {
                want.pop();
            }
        }
        if want != self.acting {
            return self.need_acting_change(want);
        }
        if only_temp {
            return Chosen::Ok;
        }
        self.prim.want_acting.clear();
        self.prim.auth_shard = Some(auth);
        self.prim.log_shard = None;
        self.prim.repeat_getlog = false;
        self.prim.acting_recovery_backfill = acting_backfill;
        self.prim.backfill_targets = backfill;
        self.prim.async_recovery_targets = async_set;
        Chosen::Ok
    }

    /// No authoritative info: fall back to the up set as acting when it differs, else the PG is incomplete.
    pub(crate) fn no_auth_acting(&mut self) -> Chosen {
        if self.up != self.acting {
            self.request_pg_temp(self.up.clone());
            self.prim.want_acting = self.up.clone();
            return Chosen::NeedActingChange;
        }
        Chosen::Incomplete
    }

    /// Ask for the acting set `want` (an empty pg_temp when it equals up).
    pub(crate) fn need_acting_change(&mut self, want: Vec<i32>) -> Chosen {
        self.prim.want_acting = want.clone();
        let temp = if want == self.up { vec![] } else { want };
        self.request_pg_temp(temp);
        Chosen::NeedActingChange
    }

    /// Ask the mon for pg_temp `want` (peering.md 6.2: only sent if it differs from the pending request).
    pub(crate) fn request_pg_temp(&mut self, want: Vec<i32>) {
        if self.prim.pending_temp.as_ref() == Some(&want) {
            return;
        }
        self.prim.pending_temp = Some(want.clone());
        self.emit(Action::PgTemp {
            pgid: self.spg.pgid,
            want,
        });
    }

    // ---- activation (spec 6.4) ------------------------------------------------------------------------

    pub(crate) fn post_activate(&mut self) {
        // activation-time check (peering.md 3.8): runs before the first activation message, so a stopped PG never tells
        // its peers to activate; a history merge received during peering can make the pair unusable
        if self.needs_recovery() && self.check_past_interval_bounds() {
            return;
        }
        let activation_epoch = self.map.epoch();
        self.set_st(St::Primary(PSt::Active(ASt::Activating)));
        self.state &= !(pgs::PEERING | pgs::DOWN | pgs::INCOMPLETE);
        self.state |= pgs::ACTIVATING;
        self.send_notify = false;
        let writable = self.acting_writable();
        self.info.partial_writes_last_complete_epoch = activation_epoch;
        if self.ec_opt() {
            // adr 0067 am. 5: a pwlc entry merged from a peer may cover past the authoritative head (our own log was
            // the auth log: no proc_master_log rollback); never send coverage of divergent entries to the shards
            crate::ecopt::rollback_pwlc(&mut self.info, self.log.head());
        }
        if writable {
            self.info.last_epoch_started = self.info.last_epoch_started.max(activation_epoch);
            self.info.last_interval_started = self.info.history.same_interval_since;
            self.pg_committed_to = self.info.last_update;
        }
        self.prim.min_lcod = Eversion::default();
        self.prim.need_up_thru = false;
        recompute_last_complete(&self.log, &mut self.info, &self.missing);
        self.info.stats.stats.sum.num_objects_missing = self.missing.len() as i64;
        // snap trimq / purged_snaps from the map (spec snaptrim 2.2); the peers get the result below
        self.snap_recompute();
        // lease; no prior holder left: the replicas get no prior bound in the activation history either
        if self.prim.lease_down.is_empty() {
            self.lease.prior_ub = 0;
        }
        self.lease.ub_sent = self.now + self.readable_interval();

        let peers: Vec<PgShard> = self
            .prim
            .acting_recovery_backfill
            .iter()
            .copied()
            .filter(|p| *p != self.me)
            .collect();
        let del = self.map.flags().recovery_deletes;
        for p in peers {
            let Some(mut pi) = self.prim.peer_info.get(&p).cloned() else {
                self.error("activate: no info for peer");
                continue;
            };
            self.prim
                .peer_missing
                .entry(p)
                .or_insert_with(|| MissingSet::new(del));
            let to_create = pi.dne_flag();
            let lease = Some(self.current_lease());
            let epoch = self.map.epoch();
            let backfill_path = self.log.tail() > pi.last_update
                || pi.last_backfill == Hobject::MIN()
                || (self.prim.backfill_targets.contains(&p) && pi.last_backfill == Hobject::MAX());
            if pi.last_update == self.info.last_update && !backfill_path {
                if !pi.is_empty() {
                    let m = MOSDPGInfo2 {
                        spgid: SpgT {
                            pgid: self.spg.pgid,
                            shard: p.shard,
                        },
                        epoch_sent: epoch,
                        min_epoch: epoch,
                        info: self.info_for_send(),
                        lease,
                        lease_ack: None,
                    };
                    self.send_activation(p, m);
                } else {
                    // peer has no PG: create it with an (empty) log
                    let m = MOSDPGLog {
                        epoch,
                        info: self.info_for_send(),
                        log: self.log.copy_after(self.info.last_update),
                        missing: Default::default(),
                        query_epoch: self.last_peering_reset,
                        past_intervals: self.past.clone(),
                        to: p.shard,
                        from: self.me.shard,
                        lease,
                    };
                    self.send_activation(p, m);
                }
                continue;
            }
            let sent_log;
            let mut sent_info;
            if backfill_path {
                // the peer must be backfilled: reset what we believe it has, ship a log slice
                let mut i = self.info_for_send();
                let num_bytes = pi.stats.stats.sum.num_bytes.max(0);
                i.stats = PgStat::default();
                i.stats.stats.sum.num_bytes = num_bytes;
                i.last_backfill = Hobject::MIN();
                sent_log = self.log.copy_up_to(
                    self.cfg.max_pg_log_entries as usize,
                    self.cfg.log_dups_tracked,
                );
                i.log_tail = sent_log.tail;
                sent_info = i;
                if let Some(m) = self.prim.peer_missing.get_mut(&p) {
                    m.clear()
                }
                pi = sent_info.clone();
                self.prim.backfill_targets.insert(p);
            } else {
                sent_info = self.info_for_send();
                sent_log = self.log.copy_after(pi.last_update);
                let last_backfill = pi.last_backfill.clone();
                // mode O: entries that skipped a nonprimary peer do not make its objects missing (spec 5.2)
                let pctx = self.ec_peer_ctx(p);
                let pm = self.prim.peer_missing.entry(p).or_default();
                for e in &sent_log.log {
                    if e.op != LogOp::ERROR && e.soid <= last_backfill {
                        if !pm.may_include_deletes() && e.is_delete() {
                            pm.rm(&e.soid);
                        } else {
                            crate::ecopt::add_next_event(pm, pctx.as_ref(), e);
                        }
                    }
                }
                pi.last_update = self.info.last_update;
                if pm.is_empty() {
                    pi.last_complete = self.info.last_update;
                }
            }
            sent_info.pgid = SpgT {
                pgid: self.spg.pgid,
                shard: p.shard,
            };
            let m = MOSDPGLog {
                epoch,
                info: sent_info,
                log: sent_log,
                missing: Default::default(),
                query_epoch: self.last_peering_reset,
                past_intervals: if to_create {
                    self.past.clone()
                } else {
                    Default::default()
                },
                to: p.shard,
                from: self.me.shard,
                lease,
            };
            self.send_activation(p, m);
            self.prim.peer_info.insert(p, pi);
        }
        if writable && self.ec_opt() {
            // mode O (spec 6.1, prim A.7 b / C.6): the primary rolls forward to head too (no stash / pwlc debt crosses
            // intervals), AFTER the peer messages are built (adr 0067 am. 6): the roll-forward may restart a shard's pwlc
            // at an entry that writes it ((v, v)), which no longer bridges that NP peer's real head to the pwlc-raised
            // `pi.last_update` the log slice starts after
            let h = self.log.head();
            self.ec_advance(h, true);
        }
        // after the peer loop: the members' missing sets are complete only now (classic activate: missing_loc setup)
        if self.needs_recovery() {
            self.build_might_have_unfound();
            // spec missing-loc.md 2.3 + 4: strays whose log we already hold (the auth log shard), then probe the rest
            let known: Vec<PgShard> = self.prim.peer_missing.keys().copied().collect();
            for p in known {
                if !self.prim.acting_recovery_backfill.contains(&p) {
                    self.stray_search(p);
                }
            }
            self.probe_strays();
        }
        if self.acting_count() < self.pool.size {
            self.state |= pgs::UNDERSIZED;
        }
        self.info.stats.state = self.state;
        self.info_dirty = true;
        let interval = self.last_peering_reset;
        self.flush(Pending::Activate {
            interval,
            activation_epoch,
        });
    }

    fn current_lease(&self) -> PgLease {
        PgLease {
            readable_until: to_ts(self.lease.readable_until),
            readable_until_ub: to_ts(self.lease.ub_sent),
            interval: to_ts(self.readable_interval()),
        }
    }

    /// Our own activation commit (primary).
    pub(crate) fn prim_self_activated(&mut self) {
        self.prim.peer_activated.insert(self.me);
        self.check_all_activated();
    }

    pub(crate) fn primary_on_info(&mut self, from: i32, m: MOSDPGInfo2) {
        let St::Primary(PSt::Active(_)) = self.st else {
            self.discard("info at primary outside Active");
            return;
        };
        let p = if self.pool.is_erasure {
            PgShard {
                osd: from,
                shard: m.info.pgid.shard,
            }
        } else {
            ps(from)
        };
        if !self.prim.acting_recovery_backfill.contains(&p) {
            self.discard("info from non-member");
            return;
        }
        if let Some(a) = m.lease_ack {
            self.proc_lease_ack(from, a);
        }
        if self.prim.peer_activated.insert(p) {
            self.prim.act_sent.remove(&p);
            if let Some(pi) = self.prim.peer_info.get_mut(&p) {
                pi.last_epoch_started = m.info.last_epoch_started;
                pi.last_interval_started = m.info.last_interval_started;
            }
            self.check_all_activated();
        }
    }

    fn check_all_activated(&mut self) {
        if self.prim.peer_activated.len() == self.prim.acting_recovery_backfill.len()
            && self.state & pgs::ACTIVATING != 0
        {
            self.all_replicas_activated();
        }
    }

    fn all_replicas_activated(&mut self) {
        self.prim.act_sent.clear();
        self.state &= !(pgs::ACTIVATING | pgs::CREATING | pgs::PREMERGE);
        self.merge_not_ready = false;
        if self.is_pending_merge() {
            // a merge is being prepared for this pool: peered, NOT active (client io waits); recovery and
            // backfill run, scrub does not (split-merge.md 6.1)
            self.state |= pgs::PEERED | pgs::PREMERGE;
            self.merge_not_ready = self.acting_count() != self.pool.size;
        } else if self.acting_writable() {
            self.state |= pgs::ACTIVE;
        } else {
            self.state |= pgs::PEERED;
        }
        // Prior leases only matter while a member of a previous interval is DOWN in the map (it may still be alive
        // and serving reads under its lease): `prior_readable_down_osds` (peering.md 5.3 AllReplicasActivated, 8.2).
        // Every prior member that is up has started the new interval and dropped its lease, so a split, a
        // pg_num_pending change or a restart of all members with the same acting waits for nothing.
        let down_prior = {
            let m = &self.map;
            self.prim.lease_down.iter().any(|o| !m.is_up(*o))
        };
        if self.lease.prior_ub > self.now && down_prior {
            self.state |= pgs::WAIT;
            self.lease.wait_until = self.lease.prior_ub;
            self.lease.wait_from = self.now.max(1);
            self.notes.push(format!(
                "pg {}: wait for prior read leases, up to {} ms (holders {:?})",
                self.spg,
                (self.lease.prior_ub - self.now) / 1_000_000,
                self.prim.lease_down
            ));
        } else {
            self.lease.prior_ub = 0;
        }
        if self.prim.was_creating {
            self.emit(Action::PgCreated {
                pgid: self.spg.pgid,
            });
            self.prim.was_creating = false;
        }
        self.info.history.last_epoch_started = self
            .info
            .history
            .last_epoch_started
            .max(self.info.last_epoch_started);
        self.info.history.last_interval_started = self
            .info
            .history
            .last_interval_started
            .max(self.info.last_interval_started);
        self.info_dirty = true;
        // leases
        self.renew_lease();
        self.share_pg_info();
        self.update_degraded_bits();
        self.flush(Pending::Plain);
        self.on_activate_complete();
    }

    pub(crate) fn share_pg_info(&mut self) {
        self.prim.latch_unshared = false;
        let epoch = self.map.epoch();
        let peers: Vec<PgShard> = self
            .prim
            .acting_recovery_backfill
            .iter()
            .copied()
            .filter(|p| *p != self.me)
            .collect();
        let info = self.info_for_send();
        for p in peers {
            // spec 9.7.1 (c): the stored copy learns what we push, before the send (merge, not assign)
            if let Some(pi) = self.prim.peer_info.get_mut(&p) {
                pi.last_epoch_started = info.last_epoch_started;
                pi.last_interval_started = info.last_interval_started;
                pi.history.merge(&info.history);
            }
            let m = MOSDPGInfo2 {
                spgid: SpgT {
                    pgid: self.spg.pgid,
                    shard: p.shard,
                },
                epoch_sent: epoch,
                min_epoch: epoch,
                info: info.clone(),
                lease: Some(self.current_lease()),
                lease_ack: None,
            };
            self.send_peering(p.osd, m);
        }
    }

    pub(crate) fn needs_recovery(&self) -> bool {
        !self.missing.is_empty()
            || self
                .prim
                .acting_recovery_backfill
                .iter()
                .filter(|p| **p != self.me && !self.prim.backfill_targets.contains(p))
                .any(|p| self.prim.peer_missing.get(p).is_some_and(|m| !m.is_empty()))
    }

    pub(crate) fn on_activate_complete(&mut self) {
        if self.needs_recovery() {
            self.start_recovery_reservation();
        } else if self.needs_backfill() {
            self.start_backfill_reservation();
        } else {
            // Fence unless no recovery/backfill txn was queued since the last committed fence: a round of an earlier
            // interval can have emptied the missing sets while its local txns are still uncommitted.
            self.recovered(self.recovery_writes != self.recovery_fenced);
        }
    }

    /// AllReplicasRecovered -> Recovered -> (GoClean) Clean, after a recovery round: fenced.
    pub(crate) fn all_recovered(&mut self) {
        self.recovered(true);
    }

    /// `fence`: persist an ordered fence on this PG before publishing clean (a recovery round ran).
    fn recovered(&mut self, fence: bool) {
        self.release_recovery_reservations();
        // recovery is over (spec force-recovery.md 6.1-6.3): its flag goes, the backfill flag only with no backfill left
        self.state &= !pgs::FORCED_RECOVERY;
        if self.needs_backfill() {
            self.state &= !(pgs::RECOVERING | pgs::RECOVERY_WAIT);
            self.start_backfill_reservation();
            return;
        }
        self.state &= !(pgs::RECOVERING
            | pgs::RECOVERY_WAIT
            | pgs::BACKFILL_WAIT
            | pgs::RECOVERY_UNFOUND
            | pgs::FORCED_BACKFILL);
        self.set_st(St::Primary(PSt::Active(ASt::Recovered)));
        if self.acting != self.up {
            // the async-recovery cost reads the peers' missing counts: refresh them first, as classic does
            self.refresh_missing_counts();
            let _ = self.choose_acting(true, true);
        }
        if self.prim.async_recovery_targets.is_empty() && self.prim.backfill_targets.is_empty() {
            if !fence {
                self.go_clean();
                return;
            }
            // Recovery updates the visible missing sets before its local transactions commit. Persist an
            // ordered fence on this PG before publishing clean or deleting any of its recovery sources.
            self.info_dirty = true;
            self.prim.recovery_complete = self.flush(Pending::RecoveryComplete {
                interval: self.last_peering_reset,
                writes: self.recovery_writes,
            });
        }
    }

    pub(crate) fn go_clean(&mut self) {
        self.set_st(St::Primary(PSt::Active(ASt::Clean)));
        // classic try_mark_clean clears both flags on every call, even when the PG stays undersized
        self.state &= !(pgs::FORCED_RECOVERY | pgs::FORCED_BACKFILL);
        if self.acting_count() == self.pool.size {
            self.state |= pgs::CLEAN;
            self.info.history.last_epoch_clean = self.map.epoch();
            self.info.history.last_interval_clean = self.info.history.same_interval_since;
            self.past.clear();
            self.past_dirty = true;
        }
        self.info_dirty = true;
        // classic try_mark_clean: publish the stats (may close the vulnerability window) before sharing the info
        self.prim.share_after_publish = true;
        // purge strays only once clean and not preparing a merge (classic purge_strays): an undersized PG keeps every
        // stray, it may hold the only extra copy of what the acting set has not re-replicated yet
        if self.state & pgs::CLEAN == 0 || self.state & pgs::PREMERGE != 0 {
            self.update_degraded_bits();
            self.flush(Pending::Plain);
            return;
        }
        let strays: Vec<PgShard> = self.prim.stray_set.iter().copied().collect();
        for s in strays {
            if self.map.is_up(s.osd) && !self.prim.peer_purged.contains(&s) {
                self.send_peering(
                    s.osd,
                    MOSDPGRemove {
                        epoch: self.map.epoch(),
                        pgs: vec![SpgT {
                            pgid: self.spg.pgid,
                            shard: s.shard,
                        }],
                    },
                );
                self.prim.peer_info.remove(&s);
                self.prim.peer_missing.remove(&s);
                self.prim.peer_purged.insert(s);
            }
        }
        self.update_degraded_bits();
        self.flush(Pending::Plain);
    }

    pub(crate) fn update_degraded_bits(&mut self) {
        let copies_missing: usize = self.missing.len()
            + self
                .prim
                .acting_recovery_backfill
                .iter()
                .filter(|p| **p != self.me && !self.prim.backfill_targets.contains(p))
                .map(|p| self.prim.peer_missing.get(p).map_or(0, |m| m.len()))
                .sum::<usize>();
        let undersized = self.acting_count() < self.pool.size;
        if undersized {
            self.state |= pgs::UNDERSIZED;
        } else {
            self.state &= !pgs::UNDERSIZED;
        }
        // a backfill target outside acting is data movement (misplaced), not a missing copy
        let bf_in_acting = self
            .prim
            .backfill_targets
            .iter()
            .any(|t| self.in_acting(*t));
        if copies_missing > 0 || undersized || bf_in_acting {
            self.state |= pgs::DEGRADED;
        } else {
            self.state &= !pgs::DEGRADED;
        }
        if self.acting != self.up {
            self.state |= pgs::REMAPPED;
        } else {
            self.state &= !pgs::REMAPPED;
        }
    }

    pub(crate) fn primary_actmap(&mut self, _store: &impl PgStoreOps) {
        if matches!(self.st, St::Primary(PSt::Active(_))) {
            self.probe_strays_if_needed(None);
        }
    }

    pub(crate) fn on_active_advmap(&mut self) {
        self.update_degraded_bits();
        // new removed / purged snaps in the map; tell the replicas when our purged set shrank (spec 2.2); a closed
        // vulnerability window / rebuild episode they have not seen yet goes out the same way (peering.md 9.6)
        if self.snap_recompute() || self.prim.latch_unshared {
            self.share_pg_info();
        }
    }

    /// Abort in-flight work of the interval that just ended.
    pub(crate) fn abort_interval_work(&mut self) {
        self.lost_abort();
        if self.pool.is_erasure {
            self.ec_abort_interval();
        }
        let reps = std::mem::take(&mut self.prim.repops);
        let pgid = self.spg.pgid;
        let keys: Vec<(i32, SpgT, u64)> = reps
            .iter()
            .flat_map(|(&tid, r)| {
                r.waiting.iter().map(move |p| {
                    (
                        p.osd,
                        SpgT {
                            pgid,
                            shard: p.shard,
                        },
                        tid,
                    )
                })
            })
            .collect();
        if !keys.is_empty() {
            self.out.push(Action::SubWritesAborted {
                spg: self.spg,
                keys,
            });
        }
        for (tid, r) in reps {
            self.out.push(Action::WriteDone {
                spg: self.spg,
                tid,
                version: r.version,
                result: -11,
            });
        }
    }

    // ---- leases (primary, spec 8.2) -----------------------------------------------------------------

    pub(crate) fn renew_lease(&mut self) {
        self.lease.ub_sent = self.now + self.readable_interval();
        self.recalc_readable_until();
        let peers = self.peer_shards_acting();
        if peers.is_empty() {
            self.lease.next_send = self.now + self.readable_interval() / 2;
            return;
        }
        let epoch = self.map.epoch();
        for p in peers {
            self.send_peering(
                p.osd,
                MOSDPGLease {
                    epoch,
                    spgid: SpgT {
                        pgid: self.spg.pgid,
                        shard: p.shard,
                    },
                    lease: self.current_lease(),
                },
            );
        }
        self.lease.sent_at = self.now;
        self.lease.next_send = self.now + self.readable_interval() / 2;
    }

    fn recalc_readable_until(&mut self) {
        let mut ru = self.lease.ub_sent;
        for p in self.peer_shards_acting() {
            ru = ru.min(self.lease.acks.get(&p.osd).copied().unwrap_or(0));
        }
        let was = self.is_readable(self.now);
        self.lease.readable_until = ru;
        self.lease.readable_until_ub = ru;
        let is = self.is_readable(self.now);
        if self.state & pgs::LAGGY != 0 && is {
            self.state &= !pgs::LAGGY;
            self.laggy_note(false);
        }
        if was != is {
            self.emit(Action::ReadableChanged {
                spg: self.spg,
                readable: is,
            });
        }
    }

    fn proc_lease_ack(&mut self, from: i32, a: PgLeaseAck) {
        let v = from_ts(a.readable_until_ub);
        let e = self.lease.acks.entry(from).or_insert(0);
        if v > *e {
            *e = v;
            self.lease.acked_at.insert(from, self.now);
            self.recalc_readable_until();
        }
    }

    pub(crate) fn on_lease_ack(&mut self, from: i32, m: MOSDPGLeaseAck) {
        if let St::Primary(PSt::Active(_)) = self.st {
            self.proc_lease_ack(from, m.lease_ack);
        } else {
            self.discard("lease ack outside Active");
        }
    }

    /// LAGGY edge diagnostics (operator log, rate limited per PG and interval: 1st, 2nd, 4th, ... episode): what the
    /// lease waits for. Call after setting (`on`) or clearing the bit; a repeated set is ignored.
    /// Leave WAIT (prior leases expired, or every prior holder is dead) and requeue the ops that waited.
    pub(crate) fn end_wait(&mut self) {
        let why = if self.now >= self.lease.wait_until {
            "leases expired"
        } else {
            "holders dead"
        };
        self.notes.push(format!(
            "pg {}: wait ended after {} ms ({why})",
            self.spg,
            self.now.saturating_sub(self.lease.wait_from) / 1_000_000
        ));
        self.lease.wait_from = 0;
        self.state &= !pgs::WAIT;
        self.lease.wait_until = 0;
        self.lease.prior_ub = 0;
        let r = self.is_readable(self.now);
        self.emit(Action::ReadableChanged {
            spg: self.spg,
            readable: r,
        });
    }

    fn laggy_note(&mut self, on: bool) {
        let now = self.now;
        let l = &mut self.lease;
        if on == (l.laggy_at != 0) {
            return;
        }
        if !on {
            let (n, d) = (l.laggy_n, (now.saturating_sub(l.laggy_at)) / 1_000_000);
            l.laggy_at = 0;
            if n.is_power_of_two() {
                self.notes.push(format!(
                    "pg {}: laggy cleared after {d} ms [{n}x]",
                    self.spg
                ));
            }
            return;
        }
        l.laggy_at = now.max(1);
        l.laggy_n += 1;
        let n = l.laggy_n;
        if n.is_power_of_two() {
            let st = self.lease_status(now);
            self.notes
                .push(format!("pg {}: laggy ({st}) [{n}x]", self.spg));
        }
    }

    /// Primary read lease state for logs and `dump_pgs`: ages relative to `now` (ms), per-peer acks.
    pub fn lease_status(&self, now: Mono) -> String {
        let ms = |t: Mono| (now as i64 - t as i64) / 1_000_000;
        let l = &self.lease;
        // the OSDs whose ack `recalc_readable_until` waits for (ours too when it holds another position, adr 0049 am. 4)
        let mut osds: Vec<i32> = self.peer_shards_acting().iter().map(|p| p.osd).collect();
        osds.sort_unstable();
        osds.dedup();
        let acks: Vec<String> = osds
            .iter()
            .map(|o| match (l.acks.get(o), l.acked_at.get(o)) {
                (Some(ub), Some(at)) => {
                    format!("osd.{o} {} ms ago (ub {:+} ms)", ms(*at), -ms(*ub))
                }
                _ => format!("osd.{o} never"),
            })
            .collect();
        let sent = if l.sent_at == 0 {
            "never".to_string()
        } else {
            format!("{} ms ago", ms(l.sent_at))
        };
        format!(
            "readable until {:+} ms, renewal sent {sent}, epoch {}, acks: {}",
            -ms(l.readable_until),
            self.map.epoch(),
            acks.join(", ")
        )
    }

    /// Mark LAGGY if a client op arrives while the lease expired (spec 8.2). Returns readable.
    pub fn check_readable(&mut self, now: Mono) -> bool {
        self.now = now;
        let r = self.is_readable(now);
        if !r && self.is_primary() && self.state & pgs::ACTIVE != 0 && self.state & pgs::WAIT == 0 {
            self.state |= pgs::LAGGY;
            self.laggy_note(true);
        }
        r
    }

    /// Timers: lease renewal, WAIT expiry, stats.
    pub fn tick(&mut self, now: Mono, store: &impl PgStoreOps) {
        self.tick_timers(now);
        self.after_event(store);
    }

    /// Lease/control timers continue while the driver submits a bounded persist batch.
    pub(crate) fn tick_timers(&mut self, now: Mono) {
        self.now = now;
        self.ec_lead_switch_off();
        self.ec_lead_switch_on();
        if let St::Primary(PSt::Active(_)) = self.st {
            if self.state & pgs::WAIT != 0
                && self.lease.wait_until != 0
                && now >= self.lease.wait_until
            {
                self.end_wait();
            }
            if self.state & (pgs::ACTIVE | pgs::PEERED) != 0
                && self.lease.next_send != 0
                && now >= self.lease.next_send
            {
                self.renew_lease();
            }
            // lease expiry notice
            if self.lease.readable_until != 0
                && now >= self.lease.readable_until
                && self.state & pgs::ACTIVE != 0
            {
                self.state |= pgs::LAGGY;
                self.laggy_note(true);
            }
        }
    }

    // ---- trim (primary, spec 6.3 aggressive) ------------------------------------------------------------

    pub(crate) fn calc_trim_to(&mut self) -> Eversion {
        let cfg = self.cfg.clone();
        // min wins over max (a runtime `config set` may order them either way; never `clamp`, which panics on min > max)
        let t = if cfg.num_pgs_hint > 0 && cfg.target_pg_log_entries_per_osd > 0 {
            (cfg.target_pg_log_entries_per_osd / cfg.num_pgs_hint)
                .min(cfg.max_pg_log_entries)
                .max(cfg.min_pg_log_entries)
        } else {
            cfg.min_pg_log_entries
        };
        let limit = self
            .log
            .head()
            .min(self.log.log.can_rollback_to)
            .min(self.pg_committed_to);
        if limit == Eversion::default() || limit == self.prim.pg_trim_to {
            return Eversion::default();
        }
        let approx = self
            .log
            .head()
            .version
            .saturating_sub(self.log.tail().version);
        if approx <= t {
            return Eversion::default();
        }
        let n = (approx - t).min(cfg.pg_log_trim_max);
        if n < cfg.pg_log_trim_min && cfg.pg_log_trim_max >= cfg.pg_log_trim_min {
            return Eversion::default();
        }
        let l = self.log.entries().len() as u64;
        if l <= t || n == 0 {
            return Eversion::default();
        }
        let nth = self.log.entries()[(n - 1).min(l - 1) as usize].version;
        let leave = self.log.entries()[(l - t - 1) as usize].version;
        let trim = nth.min(leave).min(limit);
        if trim <= self.log.tail() {
            return Eversion::default();
        }
        trim
    }

    // ---- client writes ------------------------------------------------------------------------------------

    /// Submit a replicated write. On success the returned tid appears in `Action::WriteDone`.
    pub fn submit_write(
        &mut self,
        now: Mono,
        w: WriteReq,
        store: &impl PgStoreOps,
    ) -> Result<u64, WriteErr> {
        let _s = wprof::span(wprof::S::PgLog);
        self.now = now;
        self.write_checks(&w)?;
        if self.pool.is_erasure {
            return self.ec_submit_write(w, store);
        }
        let mut p = self.write_plan(w, store)?;
        let tid = {
            self.write_tid += 1;
            self.write_tid
        };
        // local append (+ txn)
        let trim_to = self.calc_trim_to();
        let last = p.last;
        let async_empty = self.async_targets_missing(&p.entries);
        self.own_txn_next();
        self.write_append(&mut p, store);
        if trim_to != Eversion::default() {
            self.prim.pg_trim_to = trim_to;
            self.trim_log_to(trim_to);
        }
        let waiting = self.send_repops(&p, tid, &async_empty);
        self.prim.repops.insert(
            tid,
            RepOp {
                version: last,
                waiting,
                local_done: false,
                ec_objects: Vec::new(),
                t0: wprof::lat_t0(),
                t_local: 0,
            },
        );
        let interval = self.last_peering_reset;
        self.flush(Pending::LocalWrite { interval, tid });
        Ok(tid)
    }

    /// Refusals of a write before anything is planned (state, scrub, missing / recovering objects).
    fn write_checks(&mut self, w: &WriteReq) -> Result<(), WriteErr> {
        if !matches!(self.st, St::Primary(PSt::Active(_))) || self.state & pgs::ACTIVE == 0 {
            return Err(WriteErr::NotActive);
        }
        self.sp_preempt(w.entries.iter().map(|e| &e.soid));
        for we in &w.entries {
            if self.scrub_blocks_write(&we.soid) {
                return Err(WriteErr::Degraded(we.soid.clone()));
            }
            if self.obj_degraded(&we.soid) {
                // the parked write waits for this object: recover it first
                self.rec.kick.insert(we.soid.clone());
                return Err(WriteErr::Degraded(we.soid.clone()));
            }
        }
        Ok(())
    }

    /// A write of `soid` must wait: missing here or on a recovery / backfill peer, or inside the running backfill
    /// window. Checked for the head before a write-ordered op's dup lookup too (client-ops s5.4: a resent write is
    /// answered only once every copy holds the object again).
    pub fn obj_degraded(&self, soid: &Hobject) -> bool {
        self.missing.contains(soid)
            // an async-recovery target that misses the object does not hold the write back: it gets the log entries
            // with an empty transaction and keeps the object missing (`send_repops`, client-ops.md rule 16)
            || self.prim.peer_missing.iter().any(|(p, m)| {
                self.prim.acting_recovery_backfill.contains(p)
                    && !self.prim.async_recovery_targets.contains(p)
                    && m.contains(soid)
            })
            || self.backfill_blocks(soid)
    }

    /// `prior_version` of the log entry of write `we`: the version of the object it replaces (0'0 if it does not exist or
    /// was deleted; an earlier entry of the same batch wins, then the log window, then the stored object_info). A stored
    /// version that cannot be read is an error, never "new".
    pub(crate) fn write_entry_prior(
        &self,
        batch: &[LogEntry],
        we: &WriteEntry,
        store: &impl PgStoreOps,
    ) -> Result<Eversion, StoreReadError> {
        if let Some(e) = batch.iter().rev().find(|e| e.soid == we.soid) {
            return Ok(if e.is_delete() {
                Eversion::default()
            } else {
                e.version
            });
        }
        if let Some(v) = self.log.window_version(&we.soid) {
            return Ok(v.unwrap_or_default());
        }
        match we
            .prior
            .map_or_else(|| store.object_version(self.spg, &we.soid), Ok)
        {
            Err(StoreReadError::NoObject) => Ok(Eversion::default()),
            r => r,
        }
    }

    /// Log entries, their peer encoding and the repop DATA of a replicated write (nothing changed yet).
    fn write_plan(&mut self, w: WriteReq, store: &impl PgStoreOps) -> Result<WritePlan, WriteErr> {
        if w.txn_refs.is_empty() {
            store.check_write(self.spg, &w.txn_middle, &w.txn_data)
        } else {
            store.check_write_split(self.spg, &w.txn_data, &w.txn_refs)
        }?;
        // peers get the real v9 blob (rebuilt once from a skeleton); no peer, no copy
        let has_peers = self
            .prim
            .acting_recovery_backfill
            .iter()
            .any(|p| *p != self.me);
        let wire = if has_peers {
            Some(w.wire_rope()?)
        } else {
            None
        };
        let epoch = self.map.epoch();
        let mut v = self.log.head();
        let mut entries: Vec<LogEntry> = Vec::new();
        for we in &w.entries {
            v = Eversion::new(epoch, v.version + 1);
            let prior = match self.write_entry_prior(&entries, we, store) {
                Ok(p) => p,
                // unknown is not "new": logging prior 0'0 for an existing object would diverge the replicas
                Err(_) => {
                    self.error("write: local object_info unreadable, refused");
                    self.notes.push(format!(
                        "pg {}: write to {} refused (EIO): local object_info unreadable or corrupt",
                        self.spg,
                        String::from_utf8_lossy(&we.soid.oid)
                    ));
                    return Err(WriteErr::TooBig(denc::errno::EIO));
                }
            };
            let e = log_entry_from_write(w.reqid, we, v, prior);
            entries.push(e);
        }
        let last = entries.last().map(|e| e.version).unwrap_or(self.log.head());
        // encoded before the entries move into the log (no clone); peers only
        // the local store writes the slices of the same encoding
        let (logbl, encs) = if has_peers {
            crate::plog::encode_log_entries(&entries).expect("encode entries")
        } else {
            (bytes::Bytes::new(), Vec::new())
        };
        Ok(WritePlan {
            last,
            pct: self.pg_committed_to,
            entries,
            encs,
            logbl,
            wire,
            w,
        })
    }

    /// The local half of a planned write: log append and the store txn (flushed by the caller).
    fn write_append(&mut self, p: &mut WritePlan, store: &impl PgStoreOps) {
        self.append_log_enc(
            std::mem::take(&mut p.entries),
            std::mem::take(&mut p.encs),
            Eversion::default(),
            p.pct,
            true,
            store.lazy_info(),
        );
        let w = &p.w;
        self.txn.push(if w.txn_refs.is_empty() {
            StoreOp::ApplyTxn {
                middle: w.txn_middle.clone(),
                data: w.txn_data.clone(),
            }
        } else {
            StoreOp::ApplyTxnSplit {
                skel: w.txn_data.clone(),
                refs: w.txn_refs.clone(),
                hints: w.txn_ref_crcs.clone(),
            }
        });
    }

    /// Send the repops of a planned write (already in our log) and record the peers' new last_update.
    /// Async-recovery targets that miss an object of this write: they get the entries with an empty transaction (the
    /// replica adds them to its missing set, classic `should_send_op`); their missing set here follows the same
    /// entries, so recovery pushes the newest version (classic `pre_submit_op`).
    pub(crate) fn async_targets_missing(&mut self, entries: &[LogEntry]) -> BTreeSet<PgShard> {
        let mut out = BTreeSet::new();
        for t in &self.prim.async_recovery_targets {
            let Some(pm) = self.prim.peer_missing.get_mut(t) else {
                continue;
            };
            if !entries.iter().any(|e| pm.contains(&e.soid)) {
                continue;
            }
            for e in entries.iter().filter(|e| e.op != LogOp::ERROR) {
                pm.add_next_event(e);
            }
            out.insert(*t);
        }
        out
    }

    fn send_repops(
        &mut self,
        p: &WritePlan,
        tid: u64,
        async_empty: &BTreeSet<PgShard>,
    ) -> BTreeSet<PgShard> {
        let w = &p.w;
        let last = p.last;
        let unlogged = w.entries.is_empty();
        // an unlogged temp write (copy staging, adr 0057) assigns no version: `last` is the log head, which a logged
        // write in flight legitimately holds. Only a logged write must be newer than every repop in flight.
        debug_assert!(
            unlogged || self.prim.repops.values().all(|r| r.version < last),
            "pg {}: repop tid {tid} version {last:?} reuses an in-flight version (log head {:?})",
            self.spg,
            self.log.head()
        );
        let epoch = self.map.epoch();
        let stats = self.stat_cache.encode(&self.info.stats);
        let mut waiting = BTreeSet::new();
        let peers: Vec<PgShard> = self
            .prim
            .acting_recovery_backfill
            .iter()
            .copied()
            .filter(|p| *p != self.me)
            .collect();
        let first_soid = w
            .entries
            .first()
            .map(|e| e.soid.clone())
            .or_else(|| w.new_temp.clone())
            .or_else(|| w.discard_temp.clone())
            .unwrap_or_default();
        if let Some(t) = &w.new_temp {
            self.temps.insert(t.clone());
        }
        if let Some(t) = &w.discard_temp {
            self.temps.remove(t);
        }
        for ps_ in peers {
            // an unlogged temp write goes to every peer: whether the final object lies beyond a backfill target's
            // range is only known to the write that renames it (that one is emptied, see `discard_temp_oid`)
            let beyond = !unlogged
                && self.prim.backfill_targets.contains(&ps_)
                && w.entries
                    .iter()
                    .all(|e| !self.backfill_target_has_range(&ps_, &e.soid));
            let rope = if beyond || async_empty.contains(&ps_) {
                WireRope {
                    data: Transaction::new().encode_v9().expect("empty txn").into(),
                    ..Default::default()
                }
            } else {
                p.wire.clone().expect("peers exist, wire built")
            };
            let m = MOSDRepOp {
                map_epoch: epoch,
                min_epoch: self.last_peering_reset,
                trace: [0; 3],
                reqid: w.reqid,
                pgid: SpgT {
                    pgid: self.spg.pgid,
                    shard: ps_.shard,
                },
                poid: first_soid.clone(),
                acks_wanted: 5,
                version: last,
                logbl: p.logbl.clone(),
                pg_stats: stats.clone(),
                pg_trim_to: self.prim.pg_trim_to,
                new_temp_oid: w.new_temp.clone().unwrap_or_else(Hobject::MIN),
                discard_temp_oid: w.discard_temp.clone().unwrap_or_else(Hobject::MIN),
                from: self.me,
                updated_hit_set_history: None,
                pg_committed_to: p.pct,
                txn_middle: rope.middle,
                txn_data: rope.data,
                txn_data_crc: rope.data_crc,
                txn_data_more: rope.more,
            };
            self.send_repl(ps_.osd, m, tid);
            waiting.insert(ps_);
            self.peer_written(ps_, last);
        }
        waiting
    }

    /// A peer received our write up to `last`.
    fn peer_written(&mut self, p: PgShard, last: Eversion) {
        if let Some(pi) = self.prim.peer_info.get_mut(&p) {
            peer_info_written(pi, last);
        }
    }

    pub(crate) fn local_write_committed(&mut self, tid: u64) {
        if let Some(r) = self.prim.repops.get_mut(&tid) {
            r.local_done = true;
            wprof::lat(0, r.t0);
            r.t_local = wprof::lat_t0();
        }
        self.complete_repops();
    }

    pub(crate) fn on_repop_reply(&mut self, from: i32, tid: u64, m: MOSDRepOpReply) {
        if !matches!(self.st, St::Primary(PSt::Active(_))) {
            self.discard("repop reply outside Active");
            return;
        }
        if m.ack_type & MOSDRepOp::ACK_ONDISK == 0 {
            return;
        }
        let Some(r) = self.prim.repops.get_mut(&tid) else {
            self.discard("repop reply for unknown tid");
            return;
        };
        r.waiting.remove(&ps(from));
        wprof::lat(1, r.t0);
        self.prim.peer_lcod.insert(ps(from), m.last_complete_ondisk);
        self.calc_min_lcod();
        self.complete_repops();
    }

    /// Complete finished writes strictly in version order and advance `pg_committed_to`.
    pub(crate) fn complete_repops(&mut self) {
        while let Some((&tid, r)) = self.prim.repops.iter().next() {
            if !(r.local_done && r.waiting.is_empty()) {
                break;
            }
            let version = r.version;
            wprof::lat(2, r.t0);
            wprof::lat(3, r.t_local);
            let r = self.prim.repops.remove(&tid).expect("completed repop");
            self.pg_committed_to = self.pg_committed_to.max(version);
            self.out.push(Action::WriteDone {
                spg: self.spg,
                tid,
                version,
                result: 0,
            });
            if self.pool.is_erasure {
                #[cfg(test)]
                {
                    self.ep.completion_object_visits += r.ec_objects.len();
                }
                self.ec_forget(tid, &r.ec_objects);
            }
            self.lost_committed(tid);
        }
    }

    pub(crate) fn calc_min_lcod(&mut self) {
        let mut min = self.info.last_complete;
        for p in &self.prim.acting_recovery_backfill {
            if *p == self.me {
                continue;
            }
            match self.prim.peer_lcod.get(p) {
                Some(v) => min = min.min(*v),
                None => return,
            }
        }
        self.prim.min_lcod = min;
    }

    /// A peer made our log-only update (lost/unfound marking) durable.
    pub(crate) fn on_update_log_missing_reply(
        &mut self,
        from: i32,
        m: replwire::MOSDPGUpdateLogMissingReply,
    ) {
        if !matches!(self.st, St::Primary(PSt::Active(_))) {
            self.discard("update_log_missing_reply outside Active");
            return;
        }
        let Some(r) = self.prim.repops.get_mut(&m.rep_tid) else {
            self.discard("update_log_missing_reply for unknown tid");
            return;
        };
        // the reply names the replier's shard (EC: one OSD may hold two positions, adr 0049 am. 3)
        let key = if self.pool.is_erasure {
            PgShard {
                osd: from,
                shard: m.from,
            }
        } else {
            ps(from)
        };
        r.waiting.remove(&key);
        self.prim.peer_lcod.insert(key, m.last_complete_ondisk);
        self.calc_min_lcod();
        self.complete_repops();
    }

    // ---- stats ---------------------------------------------------------------------------------------------

    /// `num_objects_missing` of us and every peer from what we know now (classic update_calc_stats): our and the
    /// peers' missing sets; a backfill target (or a peer without a missing set) by its object count. The peers' own
    /// reports go stale (a replica copies the primary's stats at activation) and feed the async-recovery cost.
    fn refresh_missing_counts(&mut self) {
        self.info.stats.stats.sum.num_objects_missing = self.missing.len() as i64;
        let objects = self.info.stats.stats.sum.num_objects.max(0);
        for (p, pi) in self.prim.peer_info.iter_mut() {
            if *p == self.me {
                continue;
            }
            let by_count = || (objects - pi.stats.stats.sum.num_objects.max(0)).max(0);
            let missing = if self.prim.backfill_targets.contains(p) {
                by_count()
            } else {
                self.prim
                    .peer_missing
                    .get(p)
                    .map_or_else(by_count, |m| m.len() as i64)
            };
            pi.stats.stats.sum.num_objects_missing = missing;
        }
    }

    pub(crate) fn wall(&self) -> UTime {
        let ns = self.cfg.wall_base_ns + self.now;
        UTime::new((ns / SEC) as u32, (ns % SEC) as u32)
    }

    /// Build the primary's `pg_stat_t` (spec 9.3).
    pub fn build_pg_stat(&mut self, store: &impl PgStoreOps) -> PgStat {
        self.update_degraded_bits();
        self.refresh_missing_counts();
        let mut s = self.info.stats.clone();
        self.stats_seq += 1;
        s.version = self.info.last_update;
        s.reported_seq = self.stats_seq;
        s.reported_epoch = self.map.epoch();
        s.state = self.state;
        s.log_start = self.log.tail();
        s.ondisk_log_start = self.log.tail();
        s.created = self.info.history.epoch_created;
        s.last_epoch_clean = self.info.history.last_epoch_clean;
        s.last_scrub = self.info.history.last_scrub;
        s.last_scrub_stamp = self.info.history.last_scrub_stamp;
        s.last_deep_scrub = self.info.history.last_deep_scrub;
        s.last_deep_scrub_stamp = self.info.history.last_deep_scrub_stamp;
        s.last_deep_scrub_start_stamp = self.info.history.last_deep_scrub_start_stamp;
        s.last_clean_scrub_stamp = self.info.history.last_clean_scrub_stamp;
        self.sp_fill_stat(&mut s);
        self.trim_fill_stat(&mut s);
        s.log_size = self
            .log
            .head()
            .version
            .saturating_sub(self.log.tail().version) as i64;
        s.ondisk_log_size = s.log_size;
        s.log_dups_size = self.log.log.dups.len() as i64;
        s.up = self.up.clone();
        s.acting = self.acting.clone();
        s.up_primary = self.up_primary;
        s.acting_primary = self.acting_primary;
        s.mapping_epoch = self.info.history.same_interval_since;
        s.blocked_by = self.prim.prior.blocked_by.keys().copied().collect();
        let (n, b) = store.object_stats(self.spg);
        // EC: our shard holds 1/k of the (stripe padded) data: shard bytes * k only approximates the logical sum of
        // oi.size a classic primary keeps. Flag it (adr 0049 am. 5): classic shards copy these stats from every
        // sub-write and keep them as primary; v20.2.x deep scrub reports a num_bytes mismatch of valid stats as an
        // error (PG inconsistent), invalid stats are replaced by the scrub count without one.
        let ec = self.pool.ec.as_ref().filter(|e| e.supported);
        let b = match ec {
            Some(e) => b.saturating_mul(u64::from(e.k)),
            None => b,
        };
        if ec.is_some() {
            s.stats_invalid = true;
            self.info.stats.stats_invalid = true;
        }
        s.stats.sum.num_objects = n as i64;
        s.stats.sum.num_bytes = b as i64;
        let copies = self
            .pool
            .size
            .max(self.up.len() as u32)
            .max(self.acting_count()) as i64;
        s.stats.sum.num_object_copies = n as i64 * copies;
        let miss: usize = self.missing.len()
            + self
                .prim
                .acting_recovery_backfill
                .iter()
                .filter(|p| **p != self.me)
                .map(|p| self.prim.peer_missing.get(p).map_or(0, |m| m.len()))
                .sum::<usize>();
        let under = (self.pool.size as i64 - self.acting_count() as i64).max(0) * n as i64;
        s.stats.sum.num_objects_degraded = miss as i64 + under;
        // copies that still have to move to up members outside acting (backfill target, remap); recomputed every time,
        // else a value inherited with a peer's pg_info (classic primary, merge) sticks and the mgr throttles pg_num forever
        let moving = self.up.iter().filter(|o| !self.acting.contains(o)).count() as i64;
        s.stats.sum.num_objects_misplaced = n as i64 * moving;
        s.stats.sum.num_objects_missing_on_primary = self.missing.len() as i64;
        s.stats.sum.num_objects_unfound = self.unfound().len() as i64;
        self.info.stats.stats.sum = s.stats.sum;
        let t = self.wall();
        s.last_fresh = t;
        if self.state & pgs::CLEAN != 0 {
            s.last_clean = t;
        }
        if self.state & pgs::ACTIVE != 0 {
            s.last_active = t;
        }
        if self.state & (pgs::ACTIVE | pgs::PEERED) != 0 {
            s.last_peered = t;
        }
        s.last_unstale = t;
        if self.state & pgs::DEGRADED == 0 {
            s.last_undegraded = t;
        }
        if self.state & pgs::UNDERSIZED == 0 {
            s.last_fullsized = t;
        }
        if s.last_change == UTime::default() || s.state != self.last_stats_state {
            s.last_change = t;
        }
        let was = self.last_stats_state;
        if s.state & pgs::ACTIVE != 0
            && (was & pgs::ACTIVE == 0 || s.last_became_active == UTime::default())
        {
            s.last_became_active = t;
        }
        if s.state & (pgs::ACTIVE | pgs::PEERED) != 0
            && (was & (pgs::ACTIVE | pgs::PEERED) == 0 || s.last_became_peered == UTime::default())
        {
            s.last_became_peered = t;
        }
        self.latch_publish(&mut s, t);
        let i = &mut self.info.stats;
        (
            i.last_fresh,
            i.last_change,
            i.last_active,
            i.last_peered,
            i.last_clean,
        ) = (
            s.last_fresh,
            s.last_change,
            s.last_active,
            s.last_peered,
            s.last_clean,
        );
        (i.last_unstale, i.last_undegraded, i.last_fullsized) =
            (s.last_unstale, s.last_undegraded, s.last_fullsized);
        (
            i.last_became_active,
            i.last_became_peered,
            i.last_scrub_duration,
        ) = (
            s.last_became_active,
            s.last_became_peered,
            s.last_scrub_duration,
        );
        self.last_stats_state = s.state;
        s
    }

    /// Housekeeping run after every public entry point.
    pub(crate) fn after_event(&mut self, store: &impl PgStoreOps) {
        self.peer_trace();
        if matches!(self.st, St::Primary(PSt::Active(_))) && self.pool.is_erasure {
            self.ec_pump(store);
            self.ec_tick(store);
            self.ec_idle_rollforward(store.lazy_info());
        }
        if matches!(self.st, St::Primary(PSt::Active(_))) {
            self.rec.wants = false;
            self.rb_step();
            // OSD-wide pace of recovery/backfill invocations (osd_recovery_sleep*, replication.md 7.5,
            // peering.md 13.1): one invocation per sleep interval across the PGs of this core. A held PG wakes
            // through `next_deadline`.
            let sleep = self.recovery_sleep();
            if self.recovery_sleep_hold() {
                self.rec.sleep_at = self.cfg.rec_sched.load(Ordering::Relaxed);
            } else {
                self.rec.sleep_at = 0;
                let before = (self.rec_inflight() as u64, self.bf.ops_started);
                self.recovery_step(store);
                if !self.backfill_blocked() {
                    self.backfill_step(store);
                }
                if sleep > 0 && (self.rec_inflight() as u64, self.bf.ops_started) != before {
                    self.cfg
                        .rec_sched
                        .store(self.now + sleep, Ordering::Relaxed);
                }
            }
        }
        // after the recovery / backfill steps (they move the substate); the span change rides on this event's txn
        if self.is_primary() {
            self.latch_rebuild_step();
        }
        if !self.txn.is_empty() || self.missing.is_dirty() || self.info_dirty || self.past_dirty {
            self.flush(Pending::Plain);
        }
        // Inactive primaries must replace their old active+clean report too: peering, down and incomplete are
        // operator-visible states. A deleting instance must not resurrect its removed stats.
        if self.is_primary() && !self.is_deleting() {
            let changed = self.state != self.last_stats_state
                || self.trim.stats_dirty
                || self.prim.share_after_publish;
            self.trim.stats_dirty = false;
            let epoch = self.map.epoch();
            if changed
                || self.now >= self.last_stats_pub + self.cfg.stats_interval
                || epoch > self.last_stats_epoch.saturating_add(self.cfg.stats_epochs)
            {
                self.last_stats_pub = self.now;
                self.last_stats_epoch = epoch;
                let st = self.build_pg_stat(store);
                self.emit(Action::PgStats {
                    spg: self.spg,
                    stat: Box::new(st),
                });
                // a latch opened / closed by this publish is persisted now, even without a txn in flight (op
                // completion path); a publish that changed nothing writes nothing
                if self.info_dirty {
                    self.flush(Pending::Plain);
                }
            }
        }
        if std::mem::take(&mut self.prim.share_after_publish) && self.is_primary() {
            self.share_pg_info();
        }
        self.update_up_thru_request();
        self.scrub_step(store);
        if self.is_primary() {
            self.trim_kick();
        }
    }
}

/// The log entry of write `we` at version `v` with `prior_version` `prior`.
pub(crate) fn log_entry_from_write(
    reqid: OsdReqId,
    we: &WriteEntry,
    v: Eversion,
    prior: Eversion,
) -> LogEntry {
    let mut e = LogEntry::with_regions(
        we.op,
        we.soid.clone(),
        v,
        prior,
        pgwire::ObjectCleanRegions::fully_dirty(),
    );
    e.reqid = reqid;
    e.user_version = we.user_version;
    e.mtime = we.mtime;
    e.snaps = we.snaps.clone();
    e.return_code = we.return_code;
    e.op_returns = we.op_returns.clone();
    e
}
