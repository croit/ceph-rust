// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Decline mode (adr 0039 am. 1): an erasure pool the support gate rejects (optimized EC, lrc, ...) is answered as an
//! EMPTY backfill target that refuses backfill, so a classic primary peers without our shard instead of waiting for
//! us forever. Checked against the messages a classic primary sends a backfill target: what we answer (only replies,
//! request epochs, never a complete info, never data acked), and that nothing is stored or created. Frozen tests.
use bytes::Bytes;
use denc::types::{Eversion, Hobject, PgShard, PgT, ShardId, SnapId, SpgT};
use ecwire::*;
use peering::synth::SynthMap;
use peering::{Action, Body, Config, Inbound, MemStore, PgSet, PgStoreOps};
use pgwire::{
    LogEntry, LogOp, MOSDPGInfo2, MOSDPGLog, MOSDPGQuery2, PastIntervals, PeeringMsg, PgHistory,
    PgInfo, PgLog, PgQuery, QueryType,
};
use replwire::txn::Transaction;
use replwire::{MBackfillReserve, MOSDPGUpdateLogMissing, ReplMsg};

const ME: i32 = 3; // this OSD: shard 3 (a parity position of k2 m2)
const PRIM: i32 = 1; // classic primary: shard 0
const POOL: u64 = 9;
const SHARD: i8 = 3;

fn pgid() -> PgT {
    PgT::new(POOL, 5)
}
fn spg(s: i8) -> SpgT {
    SpgT {
        pgid: pgid(),
        shard: ShardId(s),
    }
}
fn ev(e: u32, v: u64) -> Eversion {
    Eversion::new(e, v)
}

/// k2 m2 pool; `supported` = what the support gate said (false = e.g. allow_ec_optimizations).
fn map(epoch: u32, supported: bool) -> peering::MapHandle {
    let mut m = SynthMap::new(epoch);
    for o in [PRIM, 2, 4, ME] {
        m = m.with_osd(o, 1);
    }
    m = m.with_pool(POOL, 4, 3, 8);
    let p = m.pools.get_mut(&POOL).unwrap();
    p.is_erasure = true;
    p.ec_optimizations = !supported;
    p.ec = Some(std::sync::Arc::new(pgwire::EcPoolInfo {
        supported,
        reason: if supported {
            String::new()
        } else {
            "optimized EC pool (allow_ec_optimizations) not implemented (phase C)".into()
        },
        k: 2,
        m: 2,
        stripe_width: 8192,
        chunk_size: 4096,
        ..Default::default()
    }));
    for seed in 0..8 {
        m.up_override
            .insert(PgT::new(POOL, seed), vec![PRIM, 2, 4, ME]);
    }
    m.into_handle()
}

struct H {
    set: PgSet,
    store: MemStore,
    tid: u64,
    notices: Vec<String>,
}

impl H {
    fn new(decline: bool, supported: bool) -> H {
        let mut cfg = Config::new(ME);
        cfg.ec_decline = decline;
        let mut h = H {
            set: PgSet::new(cfg),
            store: MemStore::new(),
            tid: 0,
            notices: vec![],
        };
        let a = h.set.handle_map(1, map(20, supported), &h.store);
        assert!(sends(a).is_empty());
        h
    }

    fn msg(&mut self, body: impl Into<Body>) -> Vec<peering::Send> {
        self.tid += 1;
        let a = self.set.handle_msg(
            2,
            Inbound {
                ingress: Default::default(),
                from: PRIM,
                tid: self.tid,
                prio: pgwire::msgs::PRIO_DEFAULT,
                body: Box::new(body.into()),
            },
            &self.store,
        );
        let n = self.set.take_notices();
        assert!(
            n.iter().all(|x| !x.contains("dropped outbound")),
            "choke point dropped an answer: {n:?}"
        );
        self.notices.extend(n);
        let s = sends(a);
        for x in &s {
            assert_eq!(x.to, PRIM, "only the primary is answered: {x:?}");
            for p in peering::body_spgs(&x.body) {
                assert_eq!(p, spg(0), "answers name the primary's shard: {x:?}");
            }
        }
        s
    }

    fn query(&mut self, ty: QueryType) -> Vec<peering::Send> {
        let q = MOSDPGQuery2 {
            spgid: spg(SHARD),
            query: PgQuery {
                ty,
                since: Default::default(),
                history: PgHistory {
                    epoch_created: 10,
                    same_interval_since: 18,
                    ..Default::default()
                },
                epoch_sent: 19,
                to: ShardId(SHARD),
                from: ShardId(0),
            },
        };
        self.msg(Body::Peering(q.into()))
    }

    /// Activation of a backfill target, as classic `activate()` sends it: peer info with last_backfill MIN.
    fn activate(&mut self, last_update: Eversion) -> Vec<peering::Send> {
        let mut info = PgInfo::new(spg(SHARD));
        info.history.epoch_created = 10;
        info.history.same_interval_since = 20;
        info.last_update = last_update;
        info.last_complete = last_update;
        info.last_epoch_started = 20;
        info.last_backfill = Hobject::MIN();
        let m = MOSDPGLog {
            epoch: 20,
            info,
            log: PgLog::default(),
            missing: Default::default(),
            query_epoch: 20,
            past_intervals: PastIntervals::default(),
            to: ShardId(SHARD),
            from: ShardId(0),
            lease: None,
        };
        self.msg(Body::Peering(m.into()))
    }

    fn sub_write(
        &mut self,
        tid: u64,
        txn: Vec<u8>,
        entries: Vec<LogEntry>,
        backfill: bool,
    ) -> Vec<peering::Send> {
        let m = MOSDECSubOpWrite {
            pgid: spg(SHARD),
            map_epoch: 19, // older than our map: the reply must carry THIS epoch
            op: ECSubWrite {
                from: PgShard {
                    osd: PRIM,
                    shard: ShardId(0),
                },
                tid,
                soid: obj(),
                txn_middle: Bytes::new(),
                txn_data: Bytes::from(txn),
                at_version: entries.last().map(|e| e.version).unwrap_or_default(),
                log_entries: entries,
                backfill_or_async_recovery: backfill,
                ..Default::default()
            },
            min_epoch: 18,
            trace: [0; 3],
        };
        self.msg(Body::Ec(m.into()))
    }
}

fn sends(a: Vec<Action>) -> Vec<peering::Send> {
    a.into_iter()
        .filter_map(|a| match a {
            Action::Send(s) => Some(*s),
            _ => None,
        })
        .collect()
}

fn obj() -> Hobject {
    Hobject::new(b"o1", SnapId::NOSNAP, 0x1234, POOL as i64, b"")
}

fn empty_txn() -> Vec<u8> {
    Transaction::new().encode_v9().unwrap()
}

fn data_txn() -> Vec<u8> {
    let mut t = Transaction::new();
    let c = t.coll(&denc::types::CollT::Pg(spg(SHARD)));
    let o = t.obj(&denc::types::Ghobject::head(obj(), ShardId(SHARD)));
    t.push(c, replwire::txn::TxnOp::Touch { oid: o });
    t.encode_v9().unwrap()
}

fn entry(v: Eversion) -> LogEntry {
    LogEntry::new(LogOp::MODIFY, obj(), v, Eversion::default())
}

fn assert_nothing_stored(h: &H) {
    assert_eq!(h.set.pgs().count(), 0, "no PG object for a declined pool");
    assert!(
        h.store.list_pgs().is_empty(),
        "nothing stored for a declined pool"
    );
}

#[test]
fn query_is_answered_as_an_empty_incomplete_shard() {
    let mut h = H::new(true, false);
    let s = h.query(QueryType::INFO);
    assert_eq!(s.len(), 1);
    let Body::Peering(PeeringMsg::MOSDPGNotify2(n)) = &s[0].body else {
        panic!("{s:?}")
    };
    // never complete: classic would make a complete empty shard an acting member (real sub-writes)
    assert_eq!(n.notify.info.last_backfill, Hobject::MIN());
    assert!(n.notify.info.is_incomplete() && n.notify.info.is_empty());
    assert_eq!(n.notify.info.pgid, spg(SHARD));
    assert_eq!((n.notify.from, n.notify.to), (ShardId(SHARD), ShardId(0)));
    // classic nopg stamps: query_epoch = the query's (protects against a new interval), epoch_sent = our map
    assert_eq!((n.notify.query_epoch, n.notify.epoch_sent), (19, 20));
    for ty in [QueryType::LOG, QueryType::FULLLOG, QueryType::MISSING] {
        let s = h.query(ty);
        let Body::Peering(PeeringMsg::MOSDPGLog(l)) = &s[0].body else {
            panic!("{s:?}")
        };
        assert!(l.log.log.is_empty());
        assert_eq!(l.info.last_backfill, Hobject::MIN());
        assert_eq!(
            (l.from, l.to, l.query_epoch),
            (ShardId(SHARD), ShardId(0), 19)
        );
    }
    assert_nothing_stored(&h);
    let n = std::mem::take(&mut h.notices);
    assert!(n.iter().any(|x| x.contains("declined")), "{n:?}");
}

#[test]
fn activation_is_acked_with_the_primarys_epoch_and_an_incomplete_info() {
    let mut h = H::new(true, false);
    let s = h.activate(ev(20, 7));
    assert_eq!(s.len(), 1);
    let Body::Peering(PeeringMsg::MOSDPGInfo2(i)) = &s[0].body else {
        panic!("{s:?}")
    };
    assert_eq!(i.spgid, spg(0));
    assert_eq!(
        i.info.pgid,
        spg(SHARD),
        "MInfoRec.from = (osd, info.pgid.shard): our shard"
    );
    assert_eq!(i.info.last_backfill, Hobject::MIN());
    assert_eq!((i.epoch_sent, i.min_epoch), (20, 20));
    assert!(i.lease.is_none() && i.lease_ack.is_none());
    assert_eq!(i.info.history.last_epoch_started, 20);
    // a later info share (MOSDPGInfo2 with the primary's own info) is acked the same way (discarded by an active
    // primary that counted us already)
    let mut pinfo = PgInfo::new(spg(0));
    pinfo.history.epoch_created = 10;
    pinfo.last_update = ev(20, 9);
    let s = h.msg(Body::Peering(
        MOSDPGInfo2 {
            spgid: spg(SHARD),
            epoch_sent: 20,
            min_epoch: 20,
            info: pinfo,
            lease: None,
            lease_ack: None,
        }
        .into(),
    ));
    let Body::Peering(PeeringMsg::MOSDPGInfo2(i)) = &s[0].body else {
        panic!("{s:?}")
    };
    assert_eq!(
        (i.spgid, i.info.pgid, i.epoch_sent),
        (spg(0), spg(SHARD), 20)
    );
    assert_nothing_stored(&h);
}

#[test]
fn empty_sub_writes_are_acked_with_request_epochs_and_a_monotonic_last_complete() {
    let mut h = H::new(true, false);
    h.activate(ev(20, 7));
    let s = h.sub_write(501, empty_txn(), vec![entry(ev(20, 8))], true);
    assert_eq!(s.len(), 1);
    let Body::Ec(EcMsg::WriteReply(r)) = &s[0].body else {
        panic!("{s:?}")
    };
    assert_eq!(r.pgid, spg(0));
    assert_eq!(
        (r.map_epoch, r.min_epoch),
        (19, 18),
        "request epochs: a stale reply is dropped by the primary"
    );
    assert_eq!(r.op.tid, 501);
    assert_eq!(
        r.op.from,
        PgShard {
            osd: ME,
            shard: ShardId(SHARD)
        }
    );
    assert!(r.op.committed && r.op.applied);
    assert_eq!(r.op.last_complete, ev(20, 8));
    // dummy roll-forward op (no entries, empty txn): acked, last_complete does not go back
    let s = h.sub_write(502, empty_txn(), vec![], true);
    let Body::Ec(EcMsg::WriteReply(r)) = &s[0].body else {
        panic!("{s:?}")
    };
    assert_eq!((r.op.tid, r.op.last_complete), (502, ev(20, 8)));
    // empty transaction without the backfill flag (should_send true, nothing for our shard): nothing to store, acked
    let s = h.sub_write(503, empty_txn(), vec![entry(ev(20, 9))], false);
    assert_eq!(s.len(), 1);
    assert_nothing_stored(&h);
}

#[test]
fn a_sub_write_with_data_is_never_acknowledged() {
    let mut h = H::new(true, false);
    h.activate(ev(20, 7));
    for backfill in [true, false] {
        let s = h.sub_write(600, data_txn(), vec![entry(ev(20, 8))], backfill);
        assert!(s.is_empty(), "data sub-write acked: {s:?}");
    }
    // undecodable transaction: not empty, not acked
    let s = h.sub_write(601, vec![1, 2, 3], vec![entry(ev(20, 8))], true);
    assert!(s.is_empty());
    let n = std::mem::take(&mut h.notices);
    assert!(n.iter().any(|x| x.contains("not acknowledged")), "{n:?}");
    assert_eq!(
        h.set
            .decline_stats
            .get("sub-write with data NOT acknowledged"),
        Some(&3)
    );
    assert_nothing_stored(&h);
}

#[test]
fn log_update_is_acked_and_backfill_reservation_rejected() {
    let mut h = H::new(true, false);
    h.activate(ev(20, 7));
    let s = h.msg(Body::Repl(ReplMsg::UpdateLogMissing(
        MOSDPGUpdateLogMissing {
            map_epoch: 19,
            pgid: spg(SHARD),
            from: ShardId(0),
            rep_tid: 77,
            min_epoch: 18,
            ..Default::default()
        },
    )));
    let Body::Repl(ReplMsg::UpdateLogMissingReply(r)) = &s[0].body else {
        panic!("{s:?}")
    };
    assert_eq!((r.pgid, r.from, r.rep_tid), (spg(0), ShardId(SHARD), 77));
    assert_eq!(
        (r.map_epoch, r.min_epoch, r.last_complete_ondisk),
        (19, 18, ev(20, 7))
    );
    let resv = |ty| {
        Body::Repl(ReplMsg::BackfillReserve(MBackfillReserve {
            pgid: spg(SHARD),
            query_epoch: 19,
            ty,
            priority: 110,
            primary_num_bytes: 1 << 20,
            shard_num_bytes: 1 << 19,
        }))
    };
    let s = h.msg(resv(MBackfillReserve::REQUEST));
    let Body::Repl(ReplMsg::BackfillReserve(r)) = &s[0].body else {
        panic!("{s:?}")
    };
    assert_eq!(
        (r.pgid, r.ty, r.query_epoch),
        (spg(0), MBackfillReserve::REJECT_TOOFULL, 19)
    );
    // RELEASE (sent to targets reserved before us) and everything else: no answer
    assert!(h.msg(resv(MBackfillReserve::RELEASE)).is_empty());
    assert_nothing_stored(&h);
}

#[test]
fn other_messages_get_no_answer() {
    let mut h = H::new(true, false);
    let lease = Body::Peering(
        pgwire::MOSDPGLease {
            epoch: 20,
            spgid: spg(SHARD),
            lease: Default::default(),
        }
        .into(),
    );
    assert!(h.msg(lease).is_empty());
    let read = Body::Ec(
        MOSDECSubOpRead {
            pgid: spg(SHARD),
            map_epoch: 20,
            op: ECSubRead {
                from: PgShard {
                    osd: PRIM,
                    shard: ShardId(0),
                },
                tid: 9,
                ..Default::default()
            },
            min_epoch: 20,
            trace: [0; 3],
            cost: 0,
        }
        .into(),
    );
    assert!(
        h.msg(read).is_empty(),
        "never serve a read: we hold nothing"
    );
    let remove = Body::Peering(
        pgwire::MOSDPGRemove {
            epoch: 20,
            pgs: vec![spg(SHARD)],
        }
        .into(),
    );
    assert!(h.msg(remove).is_empty());
    // NO_SHARD / out of range on an erasure pool: dropped (classic aborts on those spgs)
    for bad in [-1i8, 4] {
        let q = MOSDPGQuery2 {
            spgid: spg(bad),
            query: PgQuery {
                ty: QueryType::INFO,
                since: Default::default(),
                history: PgHistory::default(),
                epoch_sent: 19,
                to: ShardId(bad),
                from: ShardId(0),
            },
        };
        assert!(h.msg(Body::Peering(q.into())).is_empty());
    }
    assert_nothing_stored(&h);
}

#[test]
fn switch_off_and_kill_switch_pools_stay_silent() {
    // ec_decline_unsupported=false: bit-for-bit passive (adr 0039 point 2)
    let mut h = H::new(false, false);
    assert!(h.query(QueryType::INFO).is_empty());
    assert!(h.activate(ev(20, 7)).is_empty());
    assert!(
        h.sub_write(1, empty_txn(), vec![entry(ev(20, 8))], true)
            .is_empty()
    );
    assert_nothing_stored(&h);
    // supported pool disabled by ec_enable_pools (default off): never declined (on-disk shards may exist)
    let mut h = H::new(true, true);
    assert!(h.query(QueryType::INFO).is_empty());
    assert!(h.activate(ev(20, 7)).is_empty());
    assert_nothing_stored(&h);
}

#[test]
fn runtime_switch_takes_effect() {
    let mut h = H::new(true, false);
    assert_eq!(h.query(QueryType::INFO).len(), 1);
    h.set.set_ec_decline(false);
    assert!(h.query(QueryType::INFO).is_empty());
    h.set.set_ec_decline(true);
    assert_eq!(h.query(QueryType::INFO).len(), 1);
}

/// Run the PG set's actions against the store (persist + commit), collecting sends.
fn run(set: &mut PgSet, store: &mut MemStore, acts: Vec<Action>) -> Vec<peering::Send> {
    let mut out = vec![];
    let mut q: std::collections::VecDeque<Action> = acts.into();
    while let Some(a) = q.pop_front() {
        match a {
            Action::Send(s) => out.push(*s),
            Action::Persist { spg, token, txn } => {
                store.submit(spg, &txn);
                q.extend(set.on_commit(3, spg, token, &*store));
            }
            _ => {}
        }
    }
    out
}

/// Review finding (data safety): an OSD that holds PG data of a pool (served as a legacy shard, then the pool was
/// flagged allow_ec_optimizations / rejected by a stricter gate) must NOT answer "empty": classic would stop waiting for
/// a prior-interval member and could activate from a stale shard (acked writes lost). It stays silent instead, at
/// runtime and after a restart (stored PGs), and when another core holds the data (boot union).
#[test]
fn a_pool_with_data_on_this_osd_is_never_declined() {
    let mut cfg = Config::new(ME);
    cfg.ec_enable = ec::EcEnable::All;
    let mut store = MemStore::new();
    let mut set = PgSet::new(cfg.clone());
    {
        let a = set_map(&mut set, &store, map(20, true));
        run(&mut set, &mut store, a);
    }
    // the classic primary activates our shard: a real PG with data state
    let mut info = PgInfo::new(spg(0));
    info.history.epoch_created = 10;
    info.history.same_interval_since = 20;
    info.last_epoch_started = 20;
    let log = MOSDPGLog {
        epoch: 20,
        info,
        log: PgLog::default(),
        missing: Default::default(),
        query_epoch: 20,
        past_intervals: PastIntervals::default(),
        to: ShardId(SHARD),
        from: ShardId(0),
        lease: None,
    };
    let a = set.handle_msg(
        2,
        Inbound {
            ingress: Default::default(),
            from: PRIM,
            tid: 1,
            prio: pgwire::msgs::PRIO_DEFAULT,
            body: Box::new(Body::Peering(log.into())),
        },
        &store,
    );
    run(&mut set, &mut store, a);
    assert_eq!(set.pgs().count(), 1, "served as a shard");
    assert!(!store.list_pgs().is_empty());
    // the pool turns unsupported (new interval): the PG is forgotten in memory, its data stays on disk
    {
        let a = set_map(&mut set, &store, map(21, false));
        run(&mut set, &mut store, a);
    }
    assert_eq!(set.pgs().count(), 0);
    let query = |e: u32| MOSDPGQuery2 {
        spgid: spg(SHARD),
        query: PgQuery {
            ty: QueryType::INFO,
            since: Default::default(),
            history: PgHistory::default(),
            epoch_sent: e,
            to: ShardId(SHARD),
            from: ShardId(0),
        },
    };
    let ask = |set: &mut PgSet, store: &MemStore| {
        let a = set.handle_msg(
            4,
            Inbound {
                ingress: Default::default(),
                from: PRIM,
                tid: 2,
                prio: pgwire::msgs::PRIO_DEFAULT,
                body: Box::new(Body::Peering(query(21).into())),
            },
            store,
        );
        sends(a)
    };
    assert!(
        ask(&mut set, &store).is_empty(),
        "runtime: pool with data here must stay silent"
    );
    assert!(!set.declines(POOL) && set.holds_pool(POOL));
    // restart: the stored PG marks the pool
    let mut set2 = PgSet::new(cfg.clone());
    {
        let a = set_map(&mut set2, &store, map(21, false));
        run(&mut set2, &mut store, a);
    }
    {
        let a = set2.load_pgs(5, &store);
        run(&mut set2, &mut store, a);
    }
    assert!(
        ask(&mut set2, &store).is_empty(),
        "boot: stored PG of the pool must keep it silent"
    );
    // another core held the data: the boot union keeps this core silent too
    let mut empty = MemStore::new();
    let mut set3 = PgSet::new(cfg);
    {
        let a = set_map(&mut set3, &empty, map(21, false));
        run(&mut set3, &mut empty, a);
    }
    set3.note_held_pools([POOL]);
    let a = set3.handle_msg(
        4,
        Inbound {
            ingress: Default::default(),
            from: PRIM,
            tid: 2,
            prio: pgwire::msgs::PRIO_DEFAULT,
            body: Box::new(Body::Peering(query(21).into())),
        },
        &empty,
    );
    assert!(
        sends(a).is_empty(),
        "boot union: pool held on another core must stay silent"
    );
    // control: without any data the same pool is declined
    let mut set4 = PgSet::new(Config::new(ME));
    {
        let a = set_map(&mut set4, &empty, map(21, false));
        run(&mut set4, &mut empty, a);
    }
    let a = set4.handle_msg(
        4,
        Inbound {
            ingress: Default::default(),
            from: PRIM,
            tid: 2,
            prio: pgwire::msgs::PRIO_DEFAULT,
            body: Box::new(Body::Peering(query(21).into())),
        },
        &empty,
    );
    assert_eq!(sends(a).len(), 1);
}

fn set_map(set: &mut PgSet, store: &MemStore, m: peering::MapHandle) -> Vec<Action> {
    set.handle_map(1, m, store)
}
