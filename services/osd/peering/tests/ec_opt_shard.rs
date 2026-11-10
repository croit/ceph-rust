// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optimized EC (mode O, adr 0067) shard role against a MODEL of a classic optimized primary (spec ec-optimized.md 5,
//! 6, 8): kill switch, sparse logs of nonprimary shards, pg_committed_to / trim clamps, pwlc maintenance on
//! primary-capable shards, pwlc-based activation of a nonprimary shard, rollback that skips partial writes, backfill
//! sub-writes. Own vectors, no oracle.
use bytes::Bytes;
use denc::types::{Eversion, Ghobject, Hobject, PgShard, PgT, ShardId, SnapId, SpgT};
use ec::moddesc::ModDescBuilder;
use ecwire::*;
use peering::synth::SynthMap;
use peering::{Action, Body, Config, Inbound, MemStore, PgSet, PgStoreOps, St};
use pgwire::{
    LogEntry, LogOp, MOSDPGInfo2, MOSDPGLog, MOSDPGQuery2, ObjectModDesc, PastIntervals,
    PeeringMsg, PgHistory, PgInfo, PgLog, PgQuery, QueryType, ShardIdSet,
};
use replwire::txn::*;

// k=2 m=2, C=4K: shard 0 raw 0 (PC), shard 1 raw 1 (NONPRIMARY), shards 2, 3 parity (PC)
const PRIM: i32 = 1; // classic primary, shard 0
const ME: i32 = 3;
const POOL: u64 = 7;
const S: u64 = 8192;
const LIVE: u64 = u64::MAX;
const ALL: [u32; 4] = [0, 1, 2, 3];
const PARTIAL: [u32; 3] = [0, 2, 3]; // a write that skipped the nonprimary shard 1

fn ev(v: u64) -> Eversion {
    Eversion::new(5, v)
}
fn obj(name: &str) -> Hobject {
    Hobject::new(
        name.as_bytes(),
        SnapId::NOSNAP,
        0x1234_5678,
        POOL as i64,
        b"",
    )
}

fn opt_map(epoch: u32, me_shard: usize) -> peering::MapHandle {
    // acting: PRIM at shard 0, ME at `me_shard`, the others fill the rest; later epochs swap the two other OSDs (a
    // new interval, same position for us and the primary)
    let mut acting = vec![PRIM, 2, 4, 0];
    let mut it = if epoch >= 6 { vec![4, 2] } else { vec![2, 4] }.into_iter();
    for (i, slot) in acting.iter_mut().enumerate().skip(1) {
        *slot = if i == me_shard {
            ME
        } else {
            it.next().unwrap()
        };
    }
    opt_map_acting(epoch, acting)
}

fn opt_map_acting(epoch: u32, acting: Vec<i32>) -> peering::MapHandle {
    opt_map_temp(epoch, acting, None)
}

/// [`opt_map_acting`] with `up` and an optional pg_temp (shard order) on every PG.
fn opt_map_temp(epoch: u32, acting: Vec<i32>, temp: Option<Vec<i32>>) -> peering::MapHandle {
    let mut m = SynthMap::new(epoch);
    for o in [1, 2, 3, 4] {
        m = m.with_osd(o, 1);
    }
    m = m.with_pool(POOL, 4, 3, 16);
    let p = m.pools.get_mut(&POOL).unwrap();
    p.is_erasure = true;
    p.ec_k = 2;
    p.ec_optimizations = true;
    p.ec = Some(std::sync::Arc::new(pgwire::EcPoolInfo {
        k: 2,
        m: 2,
        stripe_width: S as u32,
        chunk_size: 4096,
        overwrites: true,
        supported: true,
        chunk_mapping: vec![0, 1, 2, 3],
        optimized: true,
        nonprimary: vec![1],
        plugin: "isa".into(),
        technique: "reed_sol_van".into(),
        profile: Default::default(),
        ..Default::default()
    }));
    for seed in 0..16 {
        m.up_override.insert(PgT::new(POOL, seed), acting.clone());
        if let Some(t) = &temp {
            m.pg_temp.insert(PgT::new(POOL, seed), t.clone());
        }
    }
    m.into_handle()
}

struct H {
    set: PgSet,
    store: MemStore,
    sent: Vec<peering::Send>,
    now: u64,
    tid: u64,
    shard: i8,
}

impl H {
    fn new(me_shard: usize, opt_on: bool) -> H {
        let mut cfg = Config::new(ME);
        cfg.ec_enable = ec::EcEnable::All;
        if opt_on {
            cfg.ec_enable_optimized = ec::EcEnable::All;
        }
        let mut h = H {
            set: PgSet::new(cfg),
            store: MemStore::new(),
            sent: vec![],
            now: 1_000_000,
            tid: 100,
            shard: me_shard as i8,
        };
        let a = h.set.handle_map(h.now, opt_map(5, me_shard), &h.store);
        h.run(a);
        h
    }
    fn spg(&self) -> SpgT {
        SpgT {
            pgid: PgT::new(POOL, 3),
            shard: ShardId(self.shard),
        }
    }
    fn run(&mut self, acts: Vec<Action>) {
        let mut q: std::collections::VecDeque<Action> = acts.into();
        while let Some(a) = q.pop_front() {
            match a {
                Action::Send(s) => self.sent.push(*s),
                Action::Persist { spg, token, txn } => {
                    self.store.submit(spg, &txn);
                    let more = self.set.on_commit(self.now, spg, token, &self.store);
                    q.extend(more);
                }
                _ => {}
            }
        }
    }
    fn msg(&mut self, body: Body) {
        self.tid += 1;
        self.now += 1000;
        let a = self.set.handle_msg(
            self.now,
            Inbound {
                ingress: Default::default(),
                from: PRIM,
                tid: self.tid,
                prio: pgwire::msgs::PRIO_DEFAULT,
                body: Box::new(body),
            },
            &self.store,
        );
        self.run(a);
    }
    fn take(&mut self) -> Vec<peering::Send> {
        let v = std::mem::take(&mut self.sent);
        for s in &v {
            assert_eq!(s.to, PRIM, "a shard only talks to its primary: {s:?}");
            for spg in peering::body_spgs(&s.body) {
                assert_eq!(spg.shard, ShardId(0), "{s:?}");
            }
        }
        v
    }
    fn pg(&self) -> &peering::Pg {
        self.set.pg(self.spg()).expect("pg")
    }
    fn history(&self) -> PgHistory {
        PgHistory {
            epoch_created: 5,
            same_interval_since: 5,
            same_up_since: 5,
            same_primary_since: 5,
            last_epoch_started: 5,
            last_interval_started: 5,
            epoch_pool_created: 5,
            ..Default::default()
        }
    }
    fn query_info(&mut self) {
        let q = MOSDPGQuery2 {
            spgid: self.spg(),
            query: PgQuery {
                ty: QueryType::INFO,
                since: Eversion::default(),
                history: self.history(),
                epoch_sent: 5,
                to: ShardId(self.shard),
                from: ShardId(0),
            },
        };
        self.msg(Body::Peering(PeeringMsg::from(q)));
    }
    fn prim_info(&self, last_update: Eversion) -> PgInfo {
        let mut info = PgInfo::new(SpgT {
            pgid: PgT::new(POOL, 3),
            shard: ShardId(0),
        });
        info.history = self.history();
        info.last_epoch_started = 5;
        info.last_update = last_update;
        info.last_complete = last_update;
        info
    }
    fn activate_log(&mut self, info: PgInfo, log: PgLog) {
        let m = MOSDPGLog {
            epoch: 5,
            info,
            log,
            missing: Default::default(),
            query_epoch: 5,
            past_intervals: PastIntervals::default(),
            to: ShardId(self.shard),
            from: ShardId(0),
            lease: None,
        };
        self.msg(Body::Peering(PeeringMsg::from(m)));
    }
    fn write(
        &mut self,
        entries: Vec<LogEntry>,
        txn: Vec<u8>,
        pct: Eversion,
        trim_to: Eversion,
        backfill: bool,
    ) -> u64 {
        let tid = self.tid + 1000;
        let at = entries.last().map(|e| e.version).unwrap_or_default();
        let m = MOSDECSubOpWrite {
            pgid: self.spg(),
            map_epoch: 5,
            op: ECSubWrite {
                txn_zc: Vec::new(),
                txn_data_more: Vec::new(),
                txn_payload_at: None,
                txn_hints: Default::default(),
                from: PgShard {
                    osd: PRIM,
                    shard: ShardId(0),
                },
                tid,
                reqid: Default::default(),
                soid: entries.first().map(|e| e.soid.clone()).unwrap_or_default(),
                stats: Default::default(),
                txn_middle: Bytes::new(),
                txn_data: Bytes::from(txn),
                at_version: at,
                trim_to,
                log_entries: entries,
                temp_added: Default::default(),
                temp_removed: Default::default(),
                updated_hit_set_history: None,
                pg_committed_to: pct,
                backfill_or_async_recovery: backfill,
            },
            min_epoch: 5,
            trace: [0; 3],
        };
        self.msg(Body::Ec(m.into()));
        tid
    }
    fn replies(&mut self) -> Vec<u64> {
        self.take()
            .into_iter()
            .filter_map(|s| match s.body {
                Body::Ec(EcMsg::WriteReply(r)) => Some(r.op.tid),
                _ => None,
            })
            .collect()
    }
    fn gh(&self, o: &Hobject, g: u64) -> Ghobject {
        Ghobject::new(o.clone(), g, ShardId(self.shard))
    }
    fn txn(&self, f: impl FnOnce(&mut Transaction<'static>, Cx, &Self)) -> Vec<u8> {
        let mut t = Transaction::new();
        let c = t.coll(&denc::types::CollT::Pg(self.spg()));
        f(&mut t, c, self);
        t.encode_v9().unwrap()
    }
    /// Shard write of `data` at shard offset `off` (+ `_`), optionally stashing the old range under `stash`.
    fn write_txn(
        &self,
        o: &Hobject,
        v: Eversion,
        off: u64,
        data: &'static [u8],
        stash: Option<u64>,
    ) -> Vec<u8> {
        let ob = leak(oi(o, v, 4096));
        let o = o.clone();
        self.txn(move |t, c, h| {
            let live = t.obj(&h.gh(&o, LIVE));
            if let Some(g) = stash {
                let st = t.obj(&h.gh(&o, g));
                t.push(c, TxnOp::Touch { oid: st });
                t.push(
                    c,
                    TxnOp::CloneRange2 {
                        oid: live,
                        dest_oid: st,
                        src_off: off,
                        len: data.len() as u64,
                        dest_off: off,
                    },
                );
            } else {
                t.push(c, TxnOp::Touch { oid: live });
            }
            t.push(
                c,
                TxnOp::Write {
                    oid: live,
                    off,
                    data: Data::new(data),
                },
            );
            t.push(
                c,
                TxnOp::SetAttrs {
                    oid: live,
                    attrs: vec![(b"_".as_slice(), ob)],
                },
            );
        })
    }
    fn empty_txn(&self) -> Vec<u8> {
        Transaction::new().encode_v9().unwrap()
    }
}

fn leak(b: Vec<u8>) -> &'static [u8] {
    Box::leak(b.into_boxed_slice())
}
fn oi(o: &Hobject, v: Eversion, size: u64) -> Vec<u8> {
    let mut i = replwire::ObjectInfo::new(o.clone());
    i.version = v;
    i.size = size;
    denc::to_vec(&i).unwrap()
}
fn md(f: impl FnOnce(&mut ModDescBuilder)) -> ObjectModDesc {
    let mut b = ModDescBuilder::new();
    f(&mut b);
    let (bl, ver, done) = b.finish();
    ObjectModDesc {
        version: ver,
        can_local_rollback: true,
        rollback_info_completed: done,
        bl,
    }
}
fn entry(o: &Hobject, v: Eversion, prior: Eversion, written: &[u32], m: ObjectModDesc) -> LogEntry {
    let mut e = LogEntry::new(LogOp::MODIFY, o.clone(), v, prior);
    e.mod_desc = m;
    if written.len() < 4 {
        let mut s = ShardIdSet::default();
        for w in written {
            s.0[0] |= 1 << w;
        }
        e.written_shards = s;
    }
    e
}
fn pwlc(info: &PgInfo, s: i8) -> Option<(u64, u64)> {
    info.partial_writes_last_complete
        .get(&ShardId(s))
        .map(|(a, b)| (a.version, b.version))
}

static A: [u8; 4096] = [b'A'; 4096];
static B: [u8; 4096] = [b'B'; 4096];

/// S0: an optimized pool with `ec_enable_optimized` off is treated like a gate reject: declined (empty shard answers,
/// adr 0039 am. 1) by default, fully passive with `ec_decline_unsupported` off; never a PG. On: served.
#[test]
fn optimized_off_is_declined_or_passive_and_on_serves() {
    let mut h = H::new(1, false);
    h.query_info();
    assert!(!h.take().is_empty(), "declined: the query is answered");
    assert!(h.set.pg(h.spg()).is_none());
    let n = h.set.take_notices();
    assert!(
        n.iter()
            .any(|x| x.contains("ec_enable_optimized") && x.contains("declined")),
        "{n:?}"
    );
    h.set.set_ec_decline(false);
    h.query_info();
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    assert!(h.sent.is_empty() && h.set.pg(h.spg()).is_none());
    let a = h
        .set
        .set_ec_enables(2_000_000, ec::EcEnable::All, ec::EcEnable::All, &h.store);
    h.run(a);
    h.query_info();
    assert_eq!(h.take().len(), 1, "notify");
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    assert_eq!(h.pg().machine_state(), St::ReplicaActive);
}

/// S1a, nonprimary shard: sparse log (only entries that wrote us arrive), `pg_committed_to` naming a version we never
/// saw is clamped to our head (crt never passes the log), `trim_to` clamped to crt; nonprimary keeps no pwlc.
#[test]
fn np_sparse_log_and_clamps() {
    let mut h = H::new(1, true);
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    h.take();
    let o = obj("a");
    // v1: full create (all shards)
    let e1 = entry(
        &o,
        ev(1),
        Eversion::default(),
        &ALL,
        md(|b| {
            b.create();
        }),
    );
    let t = h.write_txn(&o, ev(1), 0, &A, None);
    let tid = h.write(vec![e1], t, Eversion::default(), Eversion::default(), false);
    assert_eq!(h.replies(), vec![tid]);
    // v2, v3: partial writes to shard 0 only (not sent to us). v4: write to us with prior v1 (>= rule), pct = v3
    let e4 = entry(
        &o,
        ev(4),
        ev(1),
        &[0, 1, 2, 3],
        md(|b| {
            b.rollback_extents_v3(4, &[(0, 4096)], 4096, &[[0b1111, 0]]);
        }),
    );
    let t = h.write_txn(&o, ev(4), 0, &B, Some(4));
    let tid = h.write(vec![e4], t, ev(3), ev(3), false);
    assert_eq!(h.replies(), vec![tid]);
    let l = h.pg().log();
    // v1 was trimmed: trim_to v3 clamped to crt v1
    assert_eq!(
        l.entries()
            .iter()
            .map(|e| e.version.version)
            .collect::<Vec<_>>(),
        vec![4]
    );
    // crt clamped to the head BEFORE the new entry (v1), not v3: entry 4 stays rollbackable
    assert_eq!(l.log.can_rollback_to, ev(1));
    assert_eq!(h.store.stash(h.spg()).len(), 1);
    assert_eq!(l.tail(), ev(1));
    assert!(h.pg().info().partial_writes_last_complete.is_empty());
    // dummy roll-forward to v4 cleans the stash
    let tid = h.write(vec![], h.empty_txn(), ev(4), Eversion::default(), false);
    assert_eq!(h.replies(), vec![tid]);
    assert!(h.store.stash(h.spg()).is_empty());
    assert_eq!(h.pg().log().log.can_rollback_to, ev(4));
    let p = h.store.load_pg(h.spg()).unwrap();
    assert_eq!((p.log.head, p.log.can_rollback_to), (ev(4), ev(4)));
}

/// S1a, primary-capable parity shard: partial writes that skipped shard 1 roll forward here and maintain pwlc for
/// shard 1 (spec 8); a later write to shard 1 collapses it.
#[test]
fn pc_shard_maintains_pwlc() {
    let mut h = H::new(2, true);
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    h.take();
    let o = obj("b");
    let e1 = entry(
        &o,
        ev(1),
        Eversion::default(),
        &ALL,
        md(|b| {
            b.create();
        }),
    );
    let t = h.write_txn(&o, ev(1), 0, &A, None);
    h.write(vec![e1], t, Eversion::default(), Eversion::default(), false);
    for v in [2, 3] {
        let e = entry(
            &o,
            ev(v),
            ev(v - 1),
            &PARTIAL,
            md(|b| {
                b.append(4096);
            }),
        );
        let t = h.write_txn(&o, ev(v), 4096 * (v - 1), &B, None);
        h.write(vec![e], t, ev(v - 1), Eversion::default(), false);
    }
    // roll forward v1..v3 (dummy): pwlc[1] = (v1, v3)
    h.write(vec![], h.empty_txn(), ev(3), Eversion::default(), false);
    assert_eq!(pwlc(h.pg().info(), 1), Some((1, 3)));
    assert_eq!(h.pg().info().partial_writes_last_complete_epoch, 5);
    // v4 writes shard 1: collapses to (v4, v4) once rolled forward
    let e4 = entry(
        &o,
        ev(4),
        ev(3),
        &ALL,
        md(|b| {
            b.append(4096);
        }),
    );
    let t = h.write_txn(&o, ev(4), 0, &A, None);
    h.write(vec![e4], t, ev(4), Eversion::default(), false);
    // pct v4 clamped to head before the entry (v3): not yet
    assert_eq!(pwlc(h.pg().info(), 1), Some((1, 3)));
    h.write(vec![], h.empty_txn(), ev(4), Eversion::default(), false);
    assert_eq!(pwlc(h.pg().info(), 1), Some((4, 4)));
    // persisted with the info
    let p = h.store.load_pg(h.spg()).unwrap();
    assert_eq!(pwlc(&p.info, 1), Some((4, 4)));
    h.take();
}

/// O12: a write that fails on the classic primary (e.g. `[stat,delete]` of a missing object = ENOENT) is recorded as
/// an ERROR log entry sent to every shard by MOSDPGUpdateLogMissing; the client op completes only when every shard
/// replied. The reply must pass the EC shard outbound allow-list, and the log-only update moves the cursors like an
/// applied write (roll forward to pct) instead of the backfill-target path (crt to head, pwlc invalidated).
#[test]
fn log_only_error_entry_is_acked_and_keeps_pwlc() {
    let mut h = H::new(2, true);
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    h.take();
    let o = obj("b");
    let e1 = entry(
        &o,
        ev(1),
        Eversion::default(),
        &ALL,
        md(|b| {
            b.create();
        }),
    );
    let t = h.write_txn(&o, ev(1), 0, &A, None);
    h.write(vec![e1], t, Eversion::default(), Eversion::default(), false);
    for v in [2, 3] {
        let e = entry(
            &o,
            ev(v),
            ev(v - 1),
            &PARTIAL,
            md(|b| {
                b.append(4096);
            }),
        );
        let t = h.write_txn(&o, ev(v), 4096 * (v - 1), &B, None);
        h.write(vec![e], t, ev(v - 1), Eversion::default(), false);
    }
    h.take();
    let mut err = LogEntry::new(LogOp::ERROR, obj("gone"), ev(4), Eversion::default());
    err.return_code = -2;
    h.msg(Body::Repl(replwire::ReplMsg::UpdateLogMissing(
        replwire::MOSDPGUpdateLogMissing {
            map_epoch: 5,
            pgid: SpgT {
                pgid: PgT::new(POOL, 3),
                shard: ShardId(2),
            },
            from: ShardId(0),
            rep_tid: 4242,
            entries: denc::to_vec(&vec![err]).unwrap(),
            min_epoch: 5,
            pg_trim_to: Eversion::default(),
            pg_committed_to: ev(3),
        },
    )));
    let s = h.take();
    let r: Vec<_> = s
        .iter()
        .filter_map(|s| match &s.body {
            Body::Repl(replwire::ReplMsg::UpdateLogMissingReply(r)) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(r.len(), 1, "log-only update must be acked: {s:?}");
    assert_eq!((r[0].rep_tid, r[0].from), (4242, ShardId(2)));
    assert_eq!(h.pg().info().last_update, ev(4));
    assert_eq!(h.pg().log().log.can_rollback_to, ev(3));
    assert_eq!(pwlc(h.pg().info(), 1), Some((1, 3)));
}

/// S1b: a nonprimary shard behind the primary only by partial writes activates through MOSDPGInfo: the primary's
/// pwlc for us covers our head and ends at its last_update -> our last_update/head are raised, ack sent. Without
/// that pwlc the info is refused (needs a log).
#[test]
fn np_activation_via_pwlc() {
    for with_pwlc in [true, false] {
        let mut h = H::new(1, true);
        h.query_info();
        h.take();
        let o = obj("c");
        // our log: v1 (full write); the primary is at v3 (v2, v3 skipped shard 1)
        let mut log = PgLog {
            head: ev(1),
            ..Default::default()
        };
        log.log.push_back(entry(
            &o,
            ev(1),
            Eversion::default(),
            &ALL,
            md(|b| {
                b.create();
            }),
        ));
        let mut pi = h.prim_info(ev(1));
        h.activate_log(pi.clone(), log);
        h.take();
        assert_eq!(h.pg().info().last_update, ev(1));
        // new interval: primary sends info at v3
        let a = h.set.handle_map(h.now, opt_map(6, 1), &h.store);
        h.run(a);
        h.take();
        pi.history.same_interval_since = 6;
        pi.last_epoch_started = 6;
        pi.history.last_epoch_started = 6;
        pi.last_update = ev(3);
        pi.last_complete = ev(3);
        if with_pwlc {
            pi.partial_writes_last_complete
                .insert(ShardId(1), (ev(1), ev(3)));
            pi.partial_writes_last_complete_epoch = 6;
        }
        let m = MOSDPGInfo2 {
            spgid: h.spg(),
            epoch_sent: 6,
            min_epoch: 6,
            info: pi,
            lease: None,
            lease_ack: None,
        };
        h.msg(Body::Peering(PeeringMsg::from(m)));
        let sent = h.take();
        if with_pwlc {
            assert_eq!(h.pg().machine_state(), St::ReplicaActive);
            let i = h.pg().info();
            // last_complete stays: the create of v1 is missing here (activation log), only last_update moves
            assert_eq!(i.last_update, ev(3));
            assert_eq!(h.pg().log().head(), ev(3));
            assert_eq!(pwlc(i, 1), Some((1, 3)));
            assert!(
                sent.iter()
                    .any(|s| matches!(&s.body, Body::Peering(PeeringMsg::MOSDPGInfo2(_))))
            );
            let p = h.store.load_pg(h.spg()).unwrap();
            assert_eq!((p.info.last_update, p.log.head), (ev(3), ev(3)));
        } else {
            assert_ne!(h.pg().machine_state(), St::ReplicaActive);
            assert!(
                !sent
                    .iter()
                    .any(|s| matches!(&s.body, Body::Peering(PeeringMsg::MOSDPGInfo2(_)))),
                "{sent:?}"
            );
        }
    }
}

/// OQ 37 (adr 0067 am. 5): a nonprimary shard whose head was raised by pwlc (v3: partial writes that skipped it)
/// meets a new primary whose authoritative log ends one entry earlier (v2; v3 divergent). Its info carries either no
/// pwlc (empty map: nothing replaces our own stale (v1, v3)) or an entry past its own head (merged from a peer). The
/// rewind to v2 followed by `update_peer_info` must not raise us to v3 again, or the info activation is refused for
/// good (PG stuck activating, every resend and `pg repeer` alike).
#[test]
fn np_ahead_by_stale_pwlc_rewinds_and_activates() {
    np_ahead_by_stale_pwlc(false);
    np_ahead_by_stale_pwlc(true);
}

fn np_ahead_by_stale_pwlc(primary_past_head: bool) {
    let mut h = H::new(1, true);
    h.query_info();
    h.take();
    let o = obj("e");
    let mut log = PgLog {
        head: ev(1),
        ..Default::default()
    };
    log.log.push_back(entry(
        &o,
        ev(1),
        Eversion::default(),
        &ALL,
        md(|b| {
            b.create();
        }),
    ));
    let mut pi = h.prim_info(ev(1));
    h.activate_log(pi.clone(), log);
    h.take();
    // interval 6: primary at v3, v2 and v3 skipped shard 1 -> our head is raised to v3 by its pwlc
    let a = h.set.handle_map(h.now, opt_map(6, 1), &h.store);
    h.run(a);
    h.take();
    pi.history.same_interval_since = 6;
    pi.last_epoch_started = 6;
    pi.history.last_epoch_started = 6;
    pi.last_update = ev(3);
    pi.last_complete = ev(3);
    pi.partial_writes_last_complete
        .insert(ShardId(1), (ev(1), ev(3)));
    pi.partial_writes_last_complete_epoch = 6;
    let info = |pi: &PgInfo, e: u32| MOSDPGInfo2 {
        spgid: SpgT {
            pgid: PgT::new(POOL, 3),
            shard: ShardId(1),
        },
        epoch_sent: e,
        min_epoch: e,
        info: pi.clone(),
        lease: None,
        lease_ack: None,
    };
    h.msg(Body::Peering(PeeringMsg::from(info(&pi, 6))));
    h.take();
    assert_eq!(h.pg().machine_state(), St::ReplicaActive);
    assert_eq!(h.pg().info().last_update, ev(3));
    // interval 7 (the other two OSDs swap again): the new primary's log ends at v2 (v3 was not on enough shards),
    // its pwlc has nothing for us or covers past its own head
    let a = h
        .set
        .handle_map(h.now, opt_map_acting(7, vec![PRIM, ME, 2, 4]), &h.store);
    h.run(a);
    h.take();
    assert_eq!(h.pg().machine_state(), St::Stray);
    let mut p7 = h.prim_info(ev(2));
    p7.history.same_interval_since = 7;
    p7.history.same_up_since = 7;
    p7.last_epoch_started = 7;
    p7.history.last_epoch_started = 7;
    p7.partial_writes_last_complete_epoch = 7;
    if primary_past_head {
        p7.partial_writes_last_complete
            .insert(ShardId(1), (ev(1), ev(3)));
    }
    for _ in 0..2 {
        // the first activation and its resend (adr 0071) both succeed
        h.msg(Body::Peering(PeeringMsg::from(info(&p7, 7))));
        let sent = h.take();
        assert_eq!(h.pg().machine_state(), St::ReplicaActive, "{sent:?}");
        assert!(
            sent.iter()
                .any(|s| matches!(&s.body, Body::Peering(PeeringMsg::MOSDPGInfo2(_)))),
            "{sent:?}"
        );
    }
    let i = h.pg().info();
    assert_eq!((i.last_update, h.pg().log().head()), (ev(2), ev(2)));
    assert_eq!(
        pwlc(i, 1),
        Some((1, 2)),
        "coverage past the new head is void"
    );
    let p = h.store.load_pg(h.spg()).unwrap();
    assert_eq!((p.info.last_update, p.log.head), (ev(2), ev(2)));
    assert_eq!(pwlc(&p.info, 1), Some((1, 2)));
}

/// S1c: a nonprimary shard ahead of the authoritative log rolls back only what it was written: the entry that
/// skipped it is ignored, the written one is undone (data + `_` only, shard version restored).
#[test]
fn np_rollback_skips_partial_writes() {
    let mut h = H::new(1, true);
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    h.take();
    let o = obj("d");
    let e1 = entry(
        &o,
        ev(1),
        Eversion::default(),
        &ALL,
        md(|b| {
            b.create();
        }),
    );
    let t = h.write_txn(&o, ev(1), 0, &A, None);
    h.write(vec![e1], t, Eversion::default(), Eversion::default(), false);
    // one op, two entries: v2 skipped shard 1 (only logged here), v3 wrote shard 1 with a stash
    let e2 = entry(
        &o,
        ev(2),
        ev(1),
        &PARTIAL,
        md(|b| {
            b.append(4096);
        }),
    );
    let mut old = replwire::ObjectInfo::new(o.clone());
    old.version = ev(2);
    old.size = 4096;
    old.shard_versions.insert(ShardId(1), ev(1));
    let old_oi = denc::to_vec(&old).unwrap();
    let e3 = entry(
        &o,
        ev(3),
        ev(2),
        &ALL,
        md(|b| {
            b.set_attrs(&[
                (b"_".to_vec(), Some(old_oi.clone())),
                (b"snapset".to_vec(), None),
            ]);
            b.rollback_extents_v3(3, &[(0, 4096)], 8192, &[[0, 0]]);
        }),
    );
    let t = h.write_txn(&o, ev(3), 0, &B, Some(3));
    h.write(vec![e2, e3], t, ev(1), Eversion::default(), false);
    assert_eq!(h.store.objects(h.spg())[&o].data, B.to_vec());
    // new interval: auth log ends at v1 -> rewind both
    let a = h.set.handle_map(h.now, opt_map(6, 1), &h.store);
    h.run(a);
    h.take();
    let mut pi = h.prim_info(ev(1));
    pi.history.same_interval_since = 6;
    pi.last_epoch_started = 6;
    pi.history.last_epoch_started = 6;
    let m = MOSDPGInfo2 {
        spgid: h.spg(),
        epoch_sent: 6,
        min_epoch: 6,
        info: pi,
        lease: None,
        lease_ack: None,
    };
    h.msg(Body::Peering(PeeringMsg::from(m)));
    h.take();
    assert_eq!(h.pg().machine_state(), St::ReplicaActive);
    assert!(h.pg().missing().is_empty(), "rolled back, not missing");
    let objs = h.store.objects(h.spg());
    assert_eq!(objs[&o].data, A.to_vec());
    let got: replwire::ObjectInfo = denc::from_slice(&objs[&o].xattrs[b"_".as_slice()]).unwrap();
    assert_eq!(got.version, ev(1), "shard version, not the PC version v2");
    assert!(got.shard_versions.is_empty());
    assert!(h.store.stash(h.spg()).is_empty());
    assert_eq!(h.pg().log().head(), ev(1));
}

static A2: [u8; 8192] = [b'A'; 8192];
static B2: [u8; 8192] = [b'B'; 8192];

/// Review 2026-11-03 #5: a divergent entry whose ROLLBACK_EXTENTS v3 carries fewer shard sets than extents (count
/// truncated) is never rolled back partially (first extent restored, the second left divergent, the stash dropped
/// for good): the record is unparsable, so the shard removes its copy and marks the object missing at its prior
/// version (pglog case 5, recovered from the other shards).
#[test]
fn pc_short_shard_set_vector_goes_to_recovery() {
    let mut h = H::new(2, true);
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    h.take();
    let o = obj("e");
    let e1 = entry(
        &o,
        ev(1),
        Eversion::default(),
        &ALL,
        md(|b| {
            b.create();
        }),
    );
    let t = h.write_txn(&o, ev(1), 0, &A2, None);
    h.write(vec![e1], t, Eversion::default(), Eversion::default(), false);
    // v2 overwrites both pages with a stash of both; its shard-set count says 1 for 2 extents
    let mut m = md(|b| {
        b.rollback_extents_v3(
            2,
            &[(0, 4096), (4096, 4096)],
            8192,
            &[[0b1111, 0], [0b1111, 0]],
        );
    });
    let at = m.bl.len() - 8;
    assert_eq!(m.bl[at..at + 4], 2u32.to_le_bytes());
    m.bl[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
    let e2 = entry(&o, ev(2), ev(1), &ALL, m);
    let t = h.write_txn(&o, ev(2), 0, &B2, Some(2));
    h.write(vec![e2], t, ev(1), Eversion::default(), false);
    assert_eq!(h.store.objects(h.spg())[&o].data, B2.to_vec());
    assert_eq!(h.store.stash(h.spg()).len(), 1);
    // new interval: the authoritative log ends at v1 -> v2 is divergent here
    let a = h.set.handle_map(h.now, opt_map(6, 2), &h.store);
    h.run(a);
    h.take();
    let mut pi = h.prim_info(ev(1));
    pi.history.same_interval_since = 6;
    pi.last_epoch_started = 6;
    pi.history.last_epoch_started = 6;
    let m = MOSDPGInfo2 {
        spgid: h.spg(),
        epoch_sent: 6,
        min_epoch: 6,
        info: pi,
        lease: None,
        lease_ack: None,
    };
    h.msg(Body::Peering(PeeringMsg::from(m)));
    h.take();
    assert_eq!(h.pg().log().head(), ev(1));
    let it = h
        .pg()
        .missing()
        .get(&o)
        .expect("object missing, to be recovered");
    assert_eq!(it.need, ev(1), "{it:?}");
    assert!(
        !h.store.objects(h.spg()).contains_key(&o),
        "the local copy is removed, never half rolled back: {:?}",
        h.store
            .objects(h.spg())
            .get(&o)
            .map(|x| x.data[4095..4097].to_vec())
    );
}

/// S1a: backfill / async-recovery sub-write: logged, not applied, crt moves to the head without cleanup, pwlc
/// invalid until the next interval.
#[test]
fn backfill_subwrite_invalidates_pwlc() {
    let mut h = H::new(2, true);
    let mut pi = h.prim_info(Eversion::default());
    pi.partial_writes_last_complete
        .insert(ShardId(1), (ev(0), ev(0)));
    pi.partial_writes_last_complete_epoch = 5;
    h.activate_log(pi, PgLog::default());
    h.take();
    assert_eq!(pwlc(h.pg().info(), 1), Some((0, 0)));
    let o = obj("e");
    let e1 = entry(
        &o,
        ev(1),
        Eversion::default(),
        &ALL,
        md(|b| {
            b.create();
        }),
    );
    let tid = h.write(
        vec![e1],
        h.empty_txn(),
        Eversion::default(),
        Eversion::default(),
        true,
    );
    assert_eq!(h.replies(), vec![tid]);
    let i = h.pg().info();
    let (a, b) = i.partial_writes_last_complete[&ShardId(1)];
    assert_eq!((a.version, a.epoch, b.version), (u64::MAX, 0, u64::MAX));
    assert_eq!(i.partial_writes_last_complete_epoch, 0);
    assert_eq!(h.pg().log().log.can_rollback_to, ev(1));
    assert!(!h.store.objects(h.spg()).contains_key(&o));
}

/// S1d escape hatch (O9): the map elects our nonprimary shard (shard 0 down, no pg_temp). We never lead: the PG
/// stays frozen and asks for pg_temp = acting in shard order (mon stores it primary-capable first). A parity shard
/// elected primary (legacy-style refusal) asks for nothing; no peering message leaves either way. With the primary role
/// on (the default) the nonprimary-shard case is a note, never the "role disabled" error (boot noise after restarts).
#[test]
fn np_elected_primary_requests_pg_temp() {
    let none = pgwire::NONE_OSD;
    for (acting, me_shard, expect, role) in [
        (vec![none, ME, 2, 4], 1, true, false),
        (vec![none, ME, 2, 4], 1, true, true),
        // shard 1 and 2 down -> ME (shard 3, parity, PC) is primary: plain refusal, no pg_temp
        (vec![none, none, none, ME], 3, false, false),
    ] {
        let mut cfg = Config::new(ME);
        cfg.ec_enable = ec::EcEnable::All;
        cfg.ec_enable_optimized = ec::EcEnable::All;
        cfg.ec_primary = role;
        cfg.ec_opt_primary = role;
        let mut set = PgSet::new(cfg);
        let store = MemStore::new();
        let mut acts = set.handle_map(1_000_000, opt_map_acting(5, acting.clone()), &store);
        let spg = SpgT {
            pgid: PgT::new(POOL, 3),
            shard: ShardId(me_shard),
        };
        // the PG exists (created by the mon) and is mapped to us as primary
        let mut c = pgwire::MOSDPGCreate2 {
            epoch: 5,
            ..Default::default()
        };
        c.pgs.insert(spg, (5, Default::default()));
        let hist = PgHistory {
            epoch_created: 5,
            same_interval_since: 5,
            same_up_since: 5,
            same_primary_since: 5,
            epoch_pool_created: 5,
            ..Default::default()
        };
        c.pg_extra.insert(spg, (hist, PastIntervals::default()));
        acts.extend(set.handle_create(1_000_001, c, &store));
        let temps: Vec<_> = acts
            .iter()
            .filter_map(|a| match a {
                Action::PgTemp { pgid, want } if pgid.seed == 3 => Some(want.clone()),
                _ => None,
            })
            .collect();
        assert!(
            !acts.iter().any(|a| matches!(a, Action::Send(_))),
            "no peering traffic from a refused primary: {acts:?}"
        );
        if expect {
            assert_eq!(temps, vec![acting.clone()], "{acts:?}");
            let why = set.pg(spg).unwrap().refusal().expect("refused");
            let notes = set.take_notices();
            if role {
                assert!(why.contains("nonprimary shard"), "{why}");
                assert!(
                    !notes
                        .iter()
                        .any(|n| n.contains("error") || n.contains("primary-affinity")),
                    "{notes:#?}"
                );
            } else {
                assert!(why.contains("role disabled"), "{why}");
            }
        } else {
            assert!(temps.is_empty(), "{temps:?}");
        }
    }
}

/// S1d omap (spec 12.2, OQ O2): EC_OMAP travels only in mod_desc and is applied by a primary-capable shard at
/// roll-forward, to the live object, or, when a later logged entry deleted the object, to that entry's stash
/// generation; a nonprimary shard never applies it; rollback before roll-forward leaves no trace.
#[test]
fn ec_omap_applied_at_roll_forward() {
    use ec::moddesc::{EcOmap, OmapUp};
    for me_shard in [2usize, 1] {
        let mut h = H::new(me_shard, true);
        h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
        h.take();
        let o = obj("omap");
        let set = |k: &str| EcOmap {
            clear: false,
            header: Some(b"hdr".to_vec()),
            ups: vec![OmapUp::Insert(vec![(k.as_bytes().to_vec(), b"v".to_vec())])],
        };
        // v1 create + omap {a}
        let e1 = entry(
            &o,
            ev(1),
            Eversion::default(),
            &ALL,
            md(|b| {
                b.create().ec_omap(&set("a"));
            }),
        );
        let t = h.write_txn(&o, ev(1), 0, &A, None);
        h.write(vec![e1], t, Eversion::default(), Eversion::default(), false);
        let objs = h.store.objects(h.spg());
        assert!(objs[&o].omap.is_empty(), "not before roll-forward");
        // v2 omap {b}; v3 deletes the object (stash gen 3)
        let e2 = entry(
            &o,
            ev(2),
            ev(1),
            &ALL,
            md(|b| {
                b.ec_omap(&set("b"));
            }),
        );
        h.write(vec![e2], h.empty_txn(), ev(1), Eversion::default(), false);
        // roll-forward of v1 happened (pct v1): {a} on the live object of a PC shard only
        let objs = h.store.objects(h.spg());
        let pc = me_shard != 1;
        assert_eq!(objs[&o].omap.contains_key(b"a".as_slice()), pc);
        assert_eq!(objs[&o].omap_header == b"hdr", pc);
        let mut e3 = entry(
            &o,
            ev(3),
            ev(2),
            &ALL,
            md(|b| {
                b.delete(3);
            }),
        );
        e3.op = LogOp::DELETE;
        let oo = o.clone();
        let t = h.txn(move |t, c, h| {
            let live = t.obj(&h.gh(&oo, LIVE));
            let st = t.obj(&h.gh(&oo, 3));
            t.push(
                c,
                TxnOp::CollMoveRename {
                    oid: live,
                    dest_cid: c,
                    dest_oid: st,
                },
            );
        });
        h.write(vec![e3], t, ev(2), Eversion::default(), false);
        // v2 rolled forward AFTER v3 moved the object: {b} lands on stash generation 3
        let stash = h.store.stash(h.spg());
        if pc {
            let s = stash
                .iter()
                .find(|(k, _)| k.0 == o && k.1 == 3)
                .map(|(_, v)| v.clone())
                .expect("stash gen 3");
            assert!(s.omap.contains_key(b"b".as_slice()) && s.omap.contains_key(b"a".as_slice()));
        } else {
            assert!(stash.values().all(|s| s.omap.is_empty()));
        }
        h.take();
    }
}

/// A sub-read held behind a sub-write that waited for cold stash data must see that write once both replay: the
/// replay may not answer the read before the write's transaction reached the store (live: classic primary RMW read
/// stale nonprimary bytes -> parity without them, client reads corrupt).
#[test]
fn held_sub_read_sees_the_held_sub_write_before_it() {
    let mut h = H::new(1, true);
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    h.take();
    let o = obj("rw");
    let e1 = entry(
        &o,
        ev(1),
        Eversion::default(),
        &ALL,
        md(|b| {
            b.create();
        }),
    );
    let t = h.write_txn(&o, ev(1), 0, &A, None);
    h.write(vec![e1], t, Eversion::default(), Eversion::default(), false);
    h.take();
    // overwrite with a stash: its old data is cold, the sub-write waits; the read behind it waits too
    h.store.data_waits.set(1);
    let e2 = entry(
        &o,
        ev(2),
        ev(1),
        &ALL,
        md(|b| {
            b.rollback_extents_v3(2, &[(0, 4096)], 4096, &[[0, 0]]);
        }),
    );
    let t = h.write_txn(&o, ev(2), 0, &B, Some(2));
    h.write(vec![e2], t, ev(1), Eversion::default(), false);
    let mut op = ECSubRead {
        from: PgShard {
            osd: PRIM,
            shard: ShardId(0),
        },
        tid: 77,
        ..Default::default()
    };
    op.to_read.insert(o.clone(), vec![(0, 4096, 0)]);
    op.subchunks.insert(o.clone(), vec![(0, 1)]);
    let r = MOSDECSubOpRead {
        pgid: h.spg(),
        map_epoch: 5,
        op,
        min_epoch: 5,
        trace: [0; 3],
        cost: 4096,
    };
    h.msg(Body::Ec(r.into()));
    assert!(h.take().is_empty(), "write and read are held");
    // blocks arrive: replay (store wake), then timers until the read was answered
    let mut got = None;
    for _ in 0..10 {
        h.now += 1000;
        let a = h.set.retry_repops(h.now, &h.store);
        h.run(a);
        let a = h.set.tick(h.now, &h.store);
        h.run(a);
        for s in h.take() {
            if let Body::Ec(EcMsg::ReadReply(rr)) = s.body {
                got = rr.op.buffers_read.get(&o).map(|v| v[0].1.to_vec());
            }
        }
        if got.is_some() {
            break;
        }
    }
    assert_eq!(
        got.expect("read answered"),
        B.to_vec(),
        "read must see the write queued before it"
    );
}

/// A duplicate sub-write (a session replay delivers it again) whose stash source is cold is discarded at once: it never
/// waits for loads, so it leaves no residency lease (pinned store memory until the next interval) and no hold clock (the
/// next held write would count as a slow op from the duplicate's arrival on) behind an empty queue.
#[test]
fn duplicate_sub_write_with_cold_stash_leaves_no_hold_behind() {
    let mut h = H::new(1, true);
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    h.take();
    let o = obj("dup");
    let e1 = entry(
        &o,
        ev(1),
        Eversion::default(),
        &ALL,
        md(|b| {
            b.create();
        }),
    );
    let t = h.write_txn(&o, ev(1), 0, &A, None);
    h.write(vec![e1], t, Eversion::default(), Eversion::default(), false);
    let e2 = entry(
        &o,
        ev(2),
        ev(1),
        &ALL,
        md(|b| {
            b.rollback_extents_v3(2, &[(0, 4096)], 4096, &[[0, 0]]);
        }),
    );
    let t2 = h.write_txn(&o, ev(2), 0, &B, Some(2));
    let tid = h.write(
        vec![e2.clone()],
        t2.clone(),
        ev(1),
        Eversion::default(),
        false,
    );
    assert_eq!(h.replies().last(), Some(&tid), "the original is acked");
    h.store.data_waits.set(1);
    h.write(vec![e2], t2, ev(1), Eversion::default(), false);
    assert!(h.replies().is_empty(), "a duplicate is never acked twice");
    assert_eq!(h.pg().repops_held(), 0, "nothing held");
    assert_eq!(h.pg().repops_held_since(), None, "no hold clock");
    assert!(
        h.store.leases.borrow().is_empty(),
        "no residency lease without a held op"
    );
    assert_eq!(h.store.data_waits.get(), 1, "the duplicate probed nothing");
}

/// A held sub-write (cold stash source) and the sub-read behind it end with their interval (adr 0636): a new acting set
/// drops the queue unanswered and releases the residency lease; a later store wake applies nothing of it.
#[test]
fn a_new_interval_drops_held_sub_ops_and_their_lease() {
    let mut h = H::new(1, true);
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    h.take();
    let o = obj("iv");
    let e1 = entry(
        &o,
        ev(1),
        Eversion::default(),
        &ALL,
        md(|b| {
            b.create();
        }),
    );
    let t = h.write_txn(&o, ev(1), 0, &A, None);
    h.write(vec![e1], t, Eversion::default(), Eversion::default(), false);
    h.take();
    h.store.data_waits.set(u32::MAX);
    let e2 = entry(
        &o,
        ev(2),
        ev(1),
        &ALL,
        md(|b| {
            b.rollback_extents_v3(2, &[(0, 4096)], 4096, &[[0, 0]]);
        }),
    );
    let t = h.write_txn(&o, ev(2), 0, &B, Some(2));
    h.write(vec![e2], t, ev(1), Eversion::default(), false);
    let mut op = ECSubRead {
        from: PgShard {
            osd: PRIM,
            shard: ShardId(0),
        },
        tid: 78,
        ..Default::default()
    };
    op.to_read.insert(o.clone(), vec![(0, 4096, 0)]);
    op.subchunks.insert(o.clone(), vec![(0, 1)]);
    h.msg(Body::Ec(
        MOSDECSubOpRead {
            pgid: h.spg(),
            map_epoch: 5,
            op,
            min_epoch: 5,
            trace: [0; 3],
            cost: 4096,
        }
        .into(),
    ));
    assert!(h.take().is_empty(), "write and read are held");
    assert_eq!(h.pg().repops_held(), 2);
    assert_eq!(h.store.leases.borrow().len(), 1, "the head's lease");
    let a = h.set.handle_map(h.now, opt_map(6, 1), &h.store);
    h.run(a);
    assert_eq!(
        h.pg().repops_held(),
        0,
        "the new interval dropped the queue"
    );
    assert_eq!(h.pg().repops_held_since(), None, "no hold clock");
    assert!(h.store.leases.borrow().is_empty(), "lease released");
    h.store.data_waits.set(0);
    for _ in 0..3 {
        h.now += 1000;
        let a = h.set.retry_repops(h.now, &h.store);
        h.run(a);
        let a = h.set.tick(h.now, &h.store);
        h.run(a);
    }
    assert!(
        !h.take().iter().any(|s| matches!(
            s.body,
            Body::Ec(EcMsg::WriteReply(_)) | Body::Ec(EcMsg::ReadReply(_))
        )),
        "nothing of the old interval is answered"
    );
    assert_eq!(h.pg().info().last_update, ev(1), "nothing of it applied");
}

/// OQ 46 symptom a (lab-c PG 12.7, classic primary, our nonprimary shard): the primary's map is newer than ours; its
/// sub-write and the RMW sub-read right behind it (same range, the classic primary relies on in-order apply) both wait
/// for that map and are released by one `handle_map`. The read must see the write: the write's transaction reaches the
/// store only after the call (an `Action::Persist`), so the read may not be answered from the store inside it.
#[test]
fn map_waiting_sub_read_sees_the_sub_write_released_with_it() {
    let mut h = H::new(1, true);
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    h.take();
    let o = obj("mw");
    let e1 = entry(
        &o,
        ev(1),
        Eversion::default(),
        &ALL,
        md(|b| {
            b.create();
        }),
    );
    let t = h.write_txn(&o, ev(1), 0, &A, None);
    h.write(vec![e1], t, Eversion::default(), Eversion::default(), false);
    h.take();
    // epoch 6: same acting (no new interval), only the primary has it yet
    let e2 = entry(
        &o,
        Eversion::new(6, 2),
        ev(1),
        &ALL,
        md(|b| {
            b.rollback_extents_v3(2, &[(0, 4096)], 4096, &[[0, 0]]);
        }),
    );
    let t = h.write_txn(&o, Eversion::new(6, 2), 0, &B, Some(2));
    let w = MOSDECSubOpWrite {
        pgid: h.spg(),
        map_epoch: 6,
        op: ECSubWrite {
            txn_zc: Vec::new(),
            txn_data_more: Vec::new(),
            txn_payload_at: None,
            txn_hints: Default::default(),
            from: PgShard {
                osd: PRIM,
                shard: ShardId(0),
            },
            tid: 500,
            reqid: Default::default(),
            soid: o.clone(),
            stats: Default::default(),
            txn_middle: Bytes::new(),
            txn_data: Bytes::from(t),
            at_version: Eversion::new(6, 2),
            trim_to: Eversion::default(),
            log_entries: vec![e2],
            temp_added: Default::default(),
            temp_removed: Default::default(),
            updated_hit_set_history: None,
            pg_committed_to: ev(1),
            backfill_or_async_recovery: false,
        },
        min_epoch: 5,
        trace: [0; 3],
    };
    h.msg(Body::Ec(w.into()));
    let mut op = ECSubRead {
        from: PgShard {
            osd: PRIM,
            shard: ShardId(0),
        },
        tid: 501,
        ..Default::default()
    };
    op.to_read.insert(o.clone(), vec![(0, 4096, 0)]);
    op.subchunks.insert(o.clone(), vec![(0, 1)]);
    let r = MOSDECSubOpRead {
        pgid: h.spg(),
        map_epoch: 6,
        op,
        min_epoch: 5,
        trace: [0; 3],
        cost: 4096,
    };
    h.msg(Body::Ec(r.into()));
    assert!(h.take().is_empty(), "write and read wait for epoch 6");
    h.now += 1000;
    let a = h
        .set
        .handle_map(h.now, opt_map_acting(6, vec![PRIM, ME, 2, 4]), &h.store);
    h.run(a);
    let mut got = None;
    for _ in 0..10 {
        for s in h.take() {
            if let Body::Ec(EcMsg::ReadReply(rr)) = s.body {
                got = rr.op.buffers_read.get(&o).map(|v| v[0].1.to_vec());
            }
        }
        if got.is_some() {
            break;
        }
        h.now += 1000;
        let a = h.set.retry_repops(h.now, &h.store);
        h.run(a);
        let a = h.set.tick(h.now, &h.store);
        h.run(a);
    }
    assert_eq!(
        got.expect("read answered"),
        B.to_vec(),
        "read must see the sub-write released before it"
    );
}

/// adr 0067 am. 7 (lab ebb 13.6, stuck incomplete for good): a pg_temp left by an earlier escape after the mon NONEd its
/// down primary-capable members makes our nonprimary shard the only acting member, so the primary. Acting can no longer
/// hand the lead on; the escape asks for the up set (all up again) instead of nothing.
#[test]
fn np_elected_by_stale_pg_temp_requests_the_up_set() {
    let none = pgwire::NONE_OSD;
    let up = vec![1, ME, 2, 4];
    let mut cfg = Config::new(ME);
    cfg.ec_enable = ec::EcEnable::All;
    cfg.ec_enable_optimized = ec::EcEnable::All;
    let mut set = PgSet::new(cfg);
    let store = MemStore::new();
    let map = opt_map_temp(5, up.clone(), Some(vec![none, ME, none, none]));
    let mut acts = set.handle_map(1_000_000, map, &store);
    let spg = SpgT {
        pgid: PgT::new(POOL, 3),
        shard: ShardId(1),
    };
    let mut c = pgwire::MOSDPGCreate2 {
        epoch: 5,
        ..Default::default()
    };
    c.pgs.insert(spg, (5, Default::default()));
    let hist = PgHistory {
        epoch_created: 5,
        same_interval_since: 5,
        same_up_since: 5,
        same_primary_since: 5,
        epoch_pool_created: 5,
        ..Default::default()
    };
    c.pg_extra.insert(spg, (hist, PastIntervals::default()));
    acts.extend(set.handle_create(1_000_001, c, &store));
    let temps: Vec<_> = acts
        .iter()
        .filter_map(|a| match a {
            Action::PgTemp { pgid, want } if pgid.seed == 3 => Some(want.clone()),
            _ => None,
        })
        .collect();
    assert!(
        !acts.iter().any(|a| matches!(a, Action::Send(_))),
        "{acts:?}"
    );
    assert_eq!(temps, vec![up], "{acts:?}");
    assert!(set.pg(spg).unwrap().refusal().is_some());
}
