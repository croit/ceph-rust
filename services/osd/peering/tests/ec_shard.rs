// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Sans-IO scenarios of the EC shard role against a MODEL of a classic EC primary (adr 0039/0040): the model builds
//! the exact messages a classic primary sends (queries, activation, sub-writes with rollback info, sub-reads, pushes)
//! and the tests check what this OSD answers (shard-qualified, after commit only), what it stores, and how it rolls
//! back / forward. Frozen tests: no oracle dependency.
use bytes::Bytes;
use denc::types::{Eversion, Ghobject, Hobject, PgShard, PgT, ShardId, SnapId, SpgT};
use ec::moddesc::ModDescBuilder;
use ecwire::*;
use peering::synth::SynthMap;
use peering::{Action, Body, Config, Inbound, MemStore, PgSet, St, body_spgs};
use pgwire::{
    LogEntry, LogOp, MOSDPGInfo2, MOSDPGLog, MOSDPGQuery2, ObjectModDesc, PastIntervals,
    PeeringMsg, PgHistory, PgInfo, PgLog, PgQuery, QueryType,
};
use replwire::txn::*;

const ME: i32 = 3; // this OSD: shard 1
const PRIM: i32 = 1; // classic primary: shard 0
const OTHER: i32 = 2; // classic: shard 2
const SHARD: i8 = 1;
const POOL: u64 = 7;
const S: u64 = 8192; // stripe_width (k = 2)
const C: u64 = 4096; // chunk size
const LIVE: u64 = u64::MAX;

fn pgid() -> PgT {
    PgT::new(POOL, 3)
}
fn spg_me() -> SpgT {
    SpgT {
        pgid: pgid(),
        shard: ShardId(SHARD),
    }
}
fn spg_prim() -> SpgT {
    SpgT {
        pgid: pgid(),
        shard: ShardId(0),
    }
}
fn ev(e: u32, v: u64) -> Eversion {
    Eversion::new(e, v)
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
fn gh(o: &Hobject, generation: u64) -> Ghobject {
    Ghobject::new(o.clone(), generation, ShardId(SHARD))
}

fn ec_map(epoch: u32, overwrites: bool, acting: [i32; 3]) -> peering::MapHandle {
    ec_map_sc(epoch, overwrites, acting, 1)
}

/// `sub_chunks` > 1: a clay pool (sub-chunk reads, ec-clay.md 7.1).
fn ec_map_sc(
    epoch: u32,
    overwrites: bool,
    acting: [i32; 3],
    sub_chunks: u32,
) -> peering::MapHandle {
    let mut m = SynthMap::new(epoch);
    for o in [PRIM, OTHER, ME, 4] {
        m = m.with_osd(o, 1);
    }
    m = m.with_pool(POOL, 3, 2, 16);
    let p = m.pools.get_mut(&POOL).unwrap();
    p.is_erasure = true;
    p.ec_k = 2;
    p.ec = Some(std::sync::Arc::new(pgwire::EcPoolInfo {
        k: 2,
        m: 1,
        stripe_width: S as u32,
        chunk_size: C as u32,
        overwrites,
        supported: true,
        reason: String::new(),
        sub_chunks,
        ..Default::default()
    }));
    for seed in 0..16 {
        m.up_override.insert(PgT::new(POOL, seed), acting.to_vec());
    }
    m.into_handle()
}

/// One OSD (this one) plus the classic primary model.
struct H {
    set: PgSet,
    store: MemStore,
    sent: Vec<peering::Send>,
    now: u64,
    tid: u64,
    epoch: u32,
    notices: Vec<String>,
}

impl H {
    fn new(overwrites: bool) -> H {
        H::with_acting(overwrites, [PRIM, ME, OTHER])
    }

    fn with_acting(overwrites: bool, acting: [i32; 3]) -> H {
        H::with_sc(overwrites, acting, 1)
    }

    fn with_sc(overwrites: bool, acting: [i32; 3], sub_chunks: u32) -> H {
        let mut cfg = Config::new(ME);
        cfg.ec_enable = ec::EcEnable::All;
        let mut h = H {
            set: PgSet::new(cfg),
            store: MemStore::new(),
            sent: vec![],
            now: 1_000_000,
            tid: 100,
            epoch: 5,
            notices: vec![],
        };
        let acts = h.set.handle_map(
            h.now,
            ec_map_sc(5, overwrites, acting, sub_chunks),
            &h.store,
        );
        h.run(acts);
        h
    }

    /// Execute actions: persist into the store, commit, collect sends.
    fn run(&mut self, acts: Vec<Action>) {
        let mut q: std::collections::VecDeque<Action> = acts.into();
        while let Some(a) = q.pop_front() {
            match a {
                Action::Send(s) => self.sent.push(*s),
                Action::Persist { spg, token, txn } => {
                    use peering::PgStoreOps;
                    self.store.submit(spg, &txn);
                    let more = self.set.on_commit(self.now, spg, token, &self.store);
                    q.extend(more);
                }
                _ => {}
            }
        }
    }

    fn msg(&mut self, body: impl Into<Body>) {
        self.tid += 1;
        self.now += 1000;
        let a = self.set.handle_msg(
            self.now,
            Inbound {
                ingress: Default::default(),
                from: PRIM,
                tid: self.tid,
                prio: pgwire::msgs::PRIO_DEFAULT,
                body: Box::new(body.into()),
            },
            &self.store,
        );
        self.run(a);
    }

    fn take(&mut self) -> Vec<peering::Send> {
        // the choke point of the PG set already validated these; re-check what a classic OSD would see
        let v = std::mem::take(&mut self.sent);
        let n = self.set.take_notices();
        assert!(
            n.iter().all(|x| !x.contains("dropped outbound")),
            "choke point dropped a message: {n:?} {:?}",
            self.set.dropped
        );
        self.notices.extend(n);
        for s in &v {
            assert_eq!(s.to, PRIM, "a shard only talks to its primary: {s:?}");
            for spg in peering::body_spgs(&s.body) {
                assert_eq!(
                    spg.shard,
                    ShardId(0),
                    "spg must name the primary's shard: {s:?}"
                );
            }
        }
        v
    }

    fn pg(&self) -> &peering::Pg {
        self.set.pg(spg_me()).expect("pg")
    }

    fn new_epoch(&mut self, overwrites: bool, min_size: u32) {
        self.new_epoch_pg_num(overwrites, min_size, 16);
    }

    fn new_epoch_pg_num(&mut self, overwrites: bool, min_size: u32, pg_num: u32) {
        self.new_epoch_pgs(overwrites, min_size, pg_num, 16);
    }

    fn new_epoch_pgs(&mut self, overwrites: bool, min_size: u32, pg_num: u32, pgp_num: u32) {
        self.epoch += 1;
        let mut m = SynthMap::new(self.epoch);
        for o in [PRIM, OTHER, ME, 4] {
            m = m.with_osd(o, 1);
        }
        m = m.with_pool(POOL, 3, min_size, pg_num);
        m.pgp.insert(POOL, pgp_num);
        let p = m.pools.get_mut(&POOL).unwrap();
        p.is_erasure = true;
        p.ec_k = 2;
        p.ec = Some(std::sync::Arc::new(pgwire::EcPoolInfo {
            k: 2,
            m: 1,
            stripe_width: S as u32,
            chunk_size: C as u32,
            overwrites,
            supported: true,
            reason: String::new(),
            ..Default::default()
        }));
        for seed in 0..pg_num {
            m.up_override
                .insert(PgT::new(POOL, seed), vec![PRIM, ME, OTHER]);
        }
        let a = self.set.handle_map(self.now, m.into_handle(), &self.store);
        self.run(a);
    }

    // ---- the classic primary model ------------------------------------------------------------------------------

    fn history(&self) -> PgHistory {
        PgHistory {
            epoch_created: 5,
            same_interval_since: self.epoch,
            same_up_since: self.epoch,
            same_primary_since: self.epoch,
            last_epoch_started: self.epoch,
            last_interval_started: self.epoch,
            epoch_pool_created: 5,
            ..Default::default()
        }
    }

    fn query_info(&mut self) {
        let q = MOSDPGQuery2 {
            spgid: spg_me(),
            query: PgQuery {
                ty: QueryType::INFO,
                since: Eversion::default(),
                history: self.history(),
                epoch_sent: self.epoch,
                to: ShardId(SHARD),
                from: ShardId(0),
            },
        };
        self.msg(Body::Peering(PeeringMsg::from(q)));
    }

    /// Activation of a fresh (empty) shard: MOSDPGLog with an empty log.
    fn activate_empty(&mut self) {
        let mut info = PgInfo::new(spg_me());
        info.history = self.history();
        info.last_epoch_started = self.epoch;
        let m = MOSDPGLog {
            epoch: self.epoch,
            info,
            log: PgLog::default(),
            missing: Default::default(),
            query_epoch: self.epoch,
            past_intervals: PastIntervals::default(),
            to: ShardId(SHARD),
            from: ShardId(0),
            lease: None,
        };
        self.msg(Body::Peering(PeeringMsg::from(m)));
    }

    /// Activation of an already up to date (or rewound) shard: MOSDPGInfo2 with the auth `last_update`.
    fn activate_info(&mut self, last_update: Eversion) {
        let mut info = PgInfo::new(spg_me());
        info.history = self.history();
        info.last_epoch_started = self.epoch;
        info.last_update = last_update;
        info.last_complete = last_update;
        let m = MOSDPGInfo2 {
            spgid: spg_me(),
            epoch_sent: self.epoch,
            min_epoch: self.epoch,
            info,
            lease: None,
            lease_ack: None,
        };
        self.msg(Body::Peering(PeeringMsg::from(m)));
    }

    fn write_op(
        &mut self,
        at: Eversion,
        entry: LogEntry,
        txn: Vec<u8>,
        pct: Eversion,
        trim_to: Eversion,
        backfill: bool,
    ) -> u64 {
        let tid = self.tid + 1000;
        let m = MOSDECSubOpWrite {
            pgid: spg_me(),
            map_epoch: self.epoch,
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
                soid: entry.soid.clone(),
                stats: Default::default(),
                txn_middle: Bytes::new(),
                txn_data: Bytes::from(txn),
                at_version: at,
                trim_to,
                log_entries: vec![entry],
                temp_added: Default::default(),
                temp_removed: Default::default(),
                updated_hit_set_history: None,
                pg_committed_to: pct,
                backfill_or_async_recovery: backfill,
            },
            min_epoch: self.epoch,
            trace: [0; 3],
        };
        self.msg(Body::Ec(m.into()));
        tid
    }

    /// Dummy roll-forward op (no entries, no transaction), ec.md 11.1 step 5.
    fn dummy(&mut self, pct: Eversion, trim_to: Eversion) -> u64 {
        let tid = self.tid + 2000;
        let m = MOSDECSubOpWrite {
            pgid: spg_me(),
            map_epoch: self.epoch,
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
                soid: Hobject::default(),
                stats: Default::default(),
                txn_middle: Bytes::new(),
                txn_data: Bytes::from(Transaction::new().encode_v9().unwrap()),
                at_version: Eversion::default(),
                trim_to,
                log_entries: vec![],
                temp_added: Default::default(),
                temp_removed: Default::default(),
                updated_hit_set_history: None,
                pg_committed_to: pct,
                backfill_or_async_recovery: false,
            },
            min_epoch: self.epoch,
            trace: [0; 3],
        };
        self.msg(Body::Ec(m.into()));
        tid
    }
}

fn mod_desc(f: impl FnOnce(&mut ModDescBuilder)) -> ObjectModDesc {
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

fn entry(o: &Hobject, at: Eversion, prior: Eversion, md: ObjectModDesc) -> LogEntry {
    let mut e = LogEntry::new(LogOp::MODIFY, o.clone(), at, prior);
    e.mod_desc = md;
    e
}

fn oi(o: &Hobject, v: Eversion, size: u64) -> Vec<u8> {
    let mut i = replwire::ObjectInfo::new(o.clone());
    i.version = v;
    i.size = size;
    denc::to_vec(&i).unwrap()
}

/// hinfo bytes for `total` shard bytes with the given per-shard buffers hashed from zero state.
fn hinfo(total: u64, shard_bufs: &[&[u8]]) -> Vec<u8> {
    let mut h = ec::HashInfo::new(3);
    h.append(0, shard_bufs).unwrap();
    assert_eq!(h.total_chunk_size, total);
    h.encode()
}

fn txn(f: impl FnOnce(&mut Transaction<'static>, Cx)) -> Vec<u8> {
    let mut t = Transaction::new();
    let c = t.coll(&denc::types::CollT::Pg(spg_me()));
    f(&mut t, c);
    t.encode_v9().unwrap()
}

fn leak(b: Vec<u8>) -> &'static [u8] {
    Box::leak(b.into_boxed_slice())
}

/// Create the object: one stripe `A` on every shard.
fn create_txn(o: &Hobject, v: Eversion, data: &'static [u8]) -> Vec<u8> {
    let (o, d) = (o.clone(), data);
    let hb = leak(hinfo(C, &[d, d, d]));
    let ob = leak(oi(&o, v, S));
    txn(move |t, c| {
        let live = t.obj(&gh(&o, LIVE));
        t.push(c, TxnOp::Touch { oid: live });
        t.push(
            c,
            TxnOp::Write {
                oid: live,
                off: 0,
                data: Data::new(d),
            },
        );
        t.push(
            c,
            TxnOp::SetAttrs {
                oid: live,
                attrs: vec![(b"_".as_slice(), ob), (b"hinfo_key".as_slice(), hb)],
            },
        );
    })
}

/// Overwrite the first chunk (L1): stash the old bytes under generation `v.version`, hinfo cleared.
fn overwrite_txn(o: &Hobject, v: Eversion, data: &'static [u8]) -> Vec<u8> {
    let o = o.clone();
    let mut hi = ec::HashInfo::new(3);
    hi.total_chunk_size = C;
    hi.clear_hashes(C);
    let hb = leak(hi.encode());
    let ob = leak(oi(&o, v, S));
    txn(move |t, c| {
        let live = t.obj(&gh(&o, LIVE));
        let st = t.obj(&gh(&o, v.version));
        t.push(c, TxnOp::Touch { oid: st });
        t.push(
            c,
            TxnOp::CloneRange2 {
                oid: live,
                dest_oid: st,
                src_off: 0,
                len: C,
                dest_off: 0,
            },
        );
        t.push(
            c,
            TxnOp::Write {
                oid: live,
                off: 0,
                data: Data::new(data),
            },
        );
        t.push(
            c,
            TxnOp::SetAttrs {
                oid: live,
                attrs: vec![(b"_".as_slice(), ob), (b"hinfo_key".as_slice(), hb)],
            },
        );
    })
}

/// Append one stripe (shard bytes `data` at shard offset `off`).
fn append_txn(o: &Hobject, v: Eversion, off: u64, data: &'static [u8]) -> Vec<u8> {
    let o = o.clone();
    let mut hi = ec::HashInfo::new(3);
    hi.total_chunk_size = off + C;
    hi.clear_hashes(off + C);
    let hb = leak(hi.encode());
    let ob = leak(oi(&o, v, off / C * S + S));
    txn(move |t, c| {
        let live = t.obj(&gh(&o, LIVE));
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
                attrs: vec![(b"_".as_slice(), ob), (b"hinfo_key".as_slice(), hb)],
            },
        );
    })
}

type Extents = Vec<(Hobject, Vec<(u64, u64, u32)>)>;
static A: [u8; 4096] = [b'A'; 4096];
static B: [u8; 4096] = [b'B'; 4096];
static D: [u8; 4096] = [b'D'; 4096];

fn old_attrs(o: &Hobject, v: Eversion, hash_total: u64) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let mut hi = ec::HashInfo::new(3);
    hi.total_chunk_size = hash_total;
    hi.clear_hashes(hash_total);
    vec![
        (b"_".to_vec(), Some(oi(o, v, S))),
        (b"hinfo_key".to_vec(), Some(hi.encode())),
    ]
}

// ---- tests ---------------------------------------------------------------------------------------------------------

/// Peering as an EC replica: DNE answer to the query, creation + activation from the primary's log, ack.
#[test]
fn replica_peering_flow_is_shard_qualified() {
    let mut h = H::new(true);
    h.query_info();
    let sent = h.take();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let Body::Peering(PeeringMsg::MOSDPGNotify2(n)) = &sent[0].body else {
        panic!("expected a notify, got {:?}", sent[0].body)
    };
    assert_eq!(n.spgid, spg_prim());
    assert_eq!(n.notify.from, ShardId(SHARD));
    assert_eq!(n.notify.to, ShardId(0));
    // activation creates the PG (a classic primary sends the log to a peer it just probed)
    h.activate_empty();
    let sent = h.take();
    let acks: Vec<_> = sent
        .iter()
        .filter_map(|s| match &s.body {
            Body::Peering(PeeringMsg::MOSDPGInfo2(i)) => Some(i),
            _ => None,
        })
        .collect();
    assert_eq!(acks.len(), 1, "{sent:?}");
    assert_eq!(acks[0].spgid, spg_prim());
    assert_eq!(h.pg().machine_state(), St::ReplicaActive);
    assert_eq!(h.pg().info().pgid, spg_me());
}

/// Sub-write: durable before the reply, reply addressed to the primary's shard, cursors stay until roll-forward,
/// roll-forward by `pg_committed_to` deletes the stash (ec.md 7.1, 7.6).
#[test]
fn subwrite_reply_after_commit_and_stash_lifecycle() {
    let mut h = H::new(true);
    h.activate_empty();
    h.take();
    let o = obj("rbd_data.1.0000");
    let v1 = ev(5, 1);
    let v2 = ev(5, 2);
    let v3 = ev(5, 3);
    // 1: create
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    let tid = h.write_op(
        v1,
        e1,
        create_txn(&o, v1, &A),
        Eversion::default(),
        Eversion::default(),
        false,
    );
    let sent = h.take();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let Body::Ec(EcMsg::WriteReply(r)) = &sent[0].body else {
        panic!("{:?}", sent[0].body)
    };
    assert_eq!(r.pgid, spg_prim());
    assert_eq!(r.op.tid, tid);
    // OQ 30d: the classic primary feeds this into min_last_complete_ondisk (log trim): never 0'0
    assert_eq!(r.op.last_complete, v1);
    assert!(r.op.committed && r.op.applied);
    assert_eq!(
        r.op.from,
        PgShard {
            osd: ME,
            shard: ShardId(SHARD)
        }
    );
    assert_eq!(sent[0].prio, pgwire::msgs::PRIO_HIGH);
    assert_eq!(h.store.objects(spg_me())[&o].data, A.to_vec());
    // cursors have not moved: nothing is rolled forward yet
    let log = h.pg().log();
    assert_eq!(log.log.can_rollback_to, Eversion::default());
    assert_eq!(log.head(), v1);

    // 2: overwrite of chunk 0 with a stash
    let e2 = entry(
        &o,
        v2,
        v1,
        mod_desc(|b| {
            b.set_attrs(&old_attrs(&o, v1, C));
            b.rollback_extents(2, &[(0, C)]);
        }),
    );
    h.write_op(
        v2,
        e2,
        overwrite_txn(&o, v2, &B),
        v1,
        Eversion::default(),
        false,
    );
    h.take();
    assert_eq!(h.store.objects(spg_me())[&o].data, B.to_vec());
    assert_eq!(h.store.stash(spg_me()).len(), 1, "stash of generation 2");
    assert_eq!(h.pg().log().log.can_rollback_to, v1);

    // 3: append, pg_committed_to = v1 only
    let e3 = entry(
        &o,
        v3,
        v2,
        mod_desc(|b| {
            b.set_attrs(&old_attrs(&o, v2, C));
            b.append(S);
        }),
    );
    h.write_op(
        v3,
        e3,
        append_txn(&o, v3, C, &D),
        v1,
        Eversion::default(),
        false,
    );
    h.take();
    assert_eq!(h.store.objects(spg_me())[&o].data.len(), 2 * C as usize);
    assert_eq!(
        h.store.stash(spg_me()).len(),
        1,
        "entry 2 not yet committed everywhere"
    );

    // dummy roll-forward to v3: stash of entry 2 is gone, cursors advanced, a reply is sent
    let tid = h.dummy(v3, Eversion::default());
    let sent = h.take();
    assert!(matches!(&sent[0].body, Body::Ec(EcMsg::WriteReply(r)) if r.op.tid == tid));
    assert!(h.store.stash(spg_me()).is_empty());
    let log = h.pg().log();
    assert_eq!(
        (log.log.can_rollback_to, log.log.rollback_info_trimmed_to),
        (v3, v3)
    );
    // and the cursors are what a restart would load
    use peering::PgStoreOps;
    let p = h.store.load_pg(spg_me()).unwrap();
    assert_eq!(
        (p.log.can_rollback_to, p.log.rollback_info_trimmed_to),
        (v3, v3)
    );
    assert_eq!(p.log.head, v3);
}

/// Trim passes entries whose roll-forward never ran: their stash goes first.
#[test]
fn trim_cleans_stash() {
    let mut h = H::new(true);
    h.activate_empty();
    let o = obj("a");
    let (v1, v2) = (ev(5, 1), ev(5, 2));
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    h.write_op(
        v1,
        e1,
        create_txn(&o, v1, &A),
        Eversion::default(),
        Eversion::default(),
        false,
    );
    let e2 = entry(
        &o,
        v2,
        v1,
        mod_desc(|b| {
            b.set_attrs(&old_attrs(&o, v1, C));
            b.rollback_extents(2, &[(0, C)]);
        }),
    );
    h.write_op(
        v2,
        e2,
        overwrite_txn(&o, v2, &B),
        v1,
        Eversion::default(),
        false,
    );
    assert_eq!(h.store.stash(spg_me()).len(), 1);
    h.dummy(v2, v2); // trim_to = v2
    h.take();
    assert!(h.store.stash(spg_me()).is_empty());
    assert_eq!(h.pg().log().tail(), v2);
}

/// A shard ahead of the authoritative log rolls its divergent entries back (case 4).
#[test]
fn divergent_entries_roll_back() {
    let mut h = H::new(true);
    h.activate_empty();
    h.take();
    let o = obj("a");
    let (v1, v2, v3) = (ev(5, 1), ev(5, 2), ev(5, 3));
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    h.write_op(
        v1,
        e1,
        create_txn(&o, v1, &A),
        Eversion::default(),
        Eversion::default(),
        false,
    );
    let e2 = entry(
        &o,
        v2,
        v1,
        mod_desc(|b| {
            b.set_attrs(&old_attrs(&o, v1, C));
            b.rollback_extents(2, &[(0, C)]);
        }),
    );
    h.write_op(
        v2,
        e2,
        overwrite_txn(&o, v2, &B),
        v1,
        Eversion::default(),
        false,
    );
    let e3 = entry(
        &o,
        v3,
        v2,
        mod_desc(|b| {
            b.set_attrs(&old_attrs(&o, v2, C));
            b.append(S);
        }),
    );
    h.write_op(
        v3,
        e3,
        append_txn(&o, v3, C, &D),
        v1,
        Eversion::default(),
        false,
    );
    h.take();
    assert_eq!(h.store.objects(spg_me())[&o].data.len(), 2 * C as usize);

    // the primary failed over; the new interval's auth log ends at v1 (entries 2 and 3 never committed everywhere)
    h.new_epoch(true, 3);
    h.take(); // notify
    h.activate_info(v1);
    let sent = h.take();
    assert!(
        sent.iter()
            .any(|s| matches!(&s.body, Body::Peering(PeeringMsg::MOSDPGInfo2(_)))),
        "activation ack: {sent:?}"
    );
    let pg = h.pg();
    assert_eq!(pg.log().head(), v1);
    assert_eq!(pg.info().last_update, v1);
    assert!(pg.missing().is_empty(), "case 4: rolled back, not missing");
    let ob = &h.store.objects(spg_me())[&o];
    assert_eq!(ob.data, A.to_vec(), "overwrite and append undone");
    // attributes are back to what write 1 stored
    assert_eq!(ob.xattrs[b"_".as_slice()], oi(&o, v1, S));
    assert!(
        h.store.stash(spg_me()).is_empty(),
        "stash consumed by the rollback"
    );
    assert!(
        h.notices
            .iter()
            .any(|n| n.contains("EC divergent entries undone")),
        "operator note: {:?}",
        h.notices
    );
}

/// Entries that cannot be rolled back (primary marked them unrollbackable) fall to case 5: the object is removed
/// and goes missing at its prior version.
#[test]
fn unrollbackable_divergent_entry_becomes_missing() {
    let mut h = H::new(true);
    h.activate_empty();
    let o = obj("a");
    let (v1, v2) = (ev(5, 1), ev(5, 2));
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    h.write_op(
        v1,
        e1,
        create_txn(&o, v1, &A),
        Eversion::default(),
        Eversion::default(),
        false,
    );
    let mut e2 = entry(&o, v2, v1, ObjectModDesc::unrollbackable());
    e2.mod_desc = ObjectModDesc::unrollbackable();
    h.write_op(
        v2,
        e2,
        overwrite_txn(&o, v2, &B),
        v1,
        Eversion::default(),
        false,
    );
    h.take();
    h.new_epoch(true, 3);
    h.take();
    h.activate_info(v1);
    h.take();
    let pg = h.pg();
    assert!(
        pg.missing().contains(&o),
        "missing: {:?}",
        pg.missing().wire()
    );
    assert_eq!(pg.missing().get(&o).unwrap().need, v1);
    assert!(
        !h.store.objects(spg_me()).contains_key(&o),
        "local copy removed"
    );
}

/// Backfill / async recovery target: the entry is logged but nothing is applied.
#[test]
fn log_only_subwrite() {
    let mut h = H::new(true);
    h.activate_empty();
    h.take();
    let o = obj("a");
    let v1 = ev(5, 1);
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    h.write_op(
        v1,
        e1,
        Transaction::new().encode_v9().unwrap(),
        Eversion::default(),
        Eversion::default(),
        true,
    );
    let sent = h.take();
    assert!(matches!(&sent[0].body, Body::Ec(EcMsg::WriteReply(_))));
    assert!(!h.store.objects(spg_me()).contains_key(&o));
    assert_eq!(h.pg().log().head(), v1);
    assert!(
        h.pg().missing().contains(&o),
        "object stays missing until recovered"
    );
}

/// Sub-read: data, short reads, ENOENT, the L0 hinfo check (bad hash and size) and attribute reads.
#[test]
fn subread_and_l0_hinfo_check() {
    let mut h = H::new(false); // L0
    h.activate_empty();
    let o = obj("a");
    let v1 = ev(5, 1);
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    h.write_op(
        v1,
        e1,
        create_txn(&o, v1, &A),
        Eversion::default(),
        Eversion::default(),
        false,
    );
    h.take();
    let read = |h: &mut H, to_read: Extents, attrs: Vec<Hobject>| {
        let m = MOSDECSubOpRead {
            pgid: spg_me(),
            map_epoch: 5,
            op: ECSubRead {
                from: PgShard {
                    osd: PRIM,
                    shard: ShardId(0),
                },
                tid: 77,
                to_read: to_read.into_iter().collect(),
                attrs_to_read: attrs.into_iter().collect(),
                subchunks: Default::default(),
                omap_read_from: Default::default(),
                omap_headers_to_read: Default::default(),
            },
            min_epoch: 5,
            trace: [0; 3],
            cost: 0,
        };
        h.msg(Body::Ec(m.into()));
        let mut s = h.take();
        assert_eq!(s.len(), 1);
        let Body::Ec(EcMsg::ReadReply(r)) = s.remove(0).body else {
            panic!()
        };
        assert_eq!(r.pgid, spg_prim());
        assert_eq!(r.op.tid, 77);
        r.op
    };
    let missing = obj("nope");
    let r = read(
        &mut h,
        vec![
            (o.clone(), vec![(0, C, 0)]),
            (missing.clone(), vec![(0, C, 0)]),
        ],
        vec![o.clone()],
    );
    assert_eq!(r.buffers_read[&o][0].1.as_ref(), A.as_slice());
    assert_eq!(r.errors[&missing], -2);
    let attrs = &r.attrs_read[&o];
    assert!(attrs.contains_key(b"_".as_slice()) && attrs.contains_key(b"hinfo_key".as_slice()));
    // read past the end: empty buffer, success; partial read inside the chunk: data
    let r = read(
        &mut h,
        vec![(o.clone(), vec![(C, 100, 0), (10, 20, 0)])],
        vec![],
    );
    assert!(r.errors.is_empty());
    assert_eq!(r.buffers_read[&o][0].1.len(), 0);
    assert_eq!(r.buffers_read[&o][1].1.as_ref(), &A[10..30]);

    // corrupt the shard bytes underneath: the whole-shard read fails the recorded hash
    use peering::PgStoreOps;
    let mut st = h.store.clone();
    let bad = txn(|t, c| {
        let live = t.obj(&gh(&o, LIVE));
        t.push(
            c,
            TxnOp::Write {
                oid: live,
                off: 5,
                data: Data::new(b"Z"),
            },
        );
    });
    st.submit(
        spg_me(),
        &peering::StoreTxn {
            ops: vec![peering::StoreOp::ApplyTxn {
                middle: Bytes::new(),
                data: bad.into(),
            }],
        },
    );
    h.store = st;
    let r = read(&mut h, vec![(o.clone(), vec![(0, C, 0)])], vec![]);
    assert_eq!(r.errors[&o], -5, "bad hash is EIO");
    // a partial read is not checked against the whole-shard hash
    let r = read(&mut h, vec![(o.clone(), vec![(100, 10, 0)])], vec![]);
    assert!(r.errors.is_empty());
}

/// L1 overwrite metadata legitimately clears hashes; whole-shard reads must not run the L0 validator.
#[test]
fn subread_l1_accepts_cleared_hash_vector() {
    use peering::PgStoreOps;
    let mut h = H::new(true);
    h.activate_empty();
    h.take();
    let o = obj("cleared-hashes");
    h.store.submit(
        spg_me(),
        &peering::StoreTxn {
            ops: vec![peering::StoreOp::ApplyTxn {
                middle: Bytes::new(),
                data: create_txn(&o, ev(5, 1), &A).into(),
            }],
        },
    );
    let mut hi = ec::HashInfo::new(3);
    hi.clear_hashes(C);
    h.store
        .pgs
        .get_mut(&spg_me())
        .unwrap()
        .objects
        .get_mut(&o)
        .unwrap()
        .xattrs
        .insert(ec::HINFO_KEY.as_bytes().to_vec(), hi.encode());
    let r = clay_read(&mut h, &o, vec![(0, C, 0)], None);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.buffers_read[&o][0].1.as_ref(), A.as_slice());
}

/// Recovery push of a shard: one-shot, and multi-chunk through a temp object.
#[test]
fn push_apply_one_shot_and_chunked() {
    let mut h = H::new(true);
    h.activate_empty();
    let o = obj("a");
    let v1 = ev(5, 1);
    // the object is missing locally: a log-only write recorded it
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    h.write_op(
        v1,
        e1,
        Transaction::new().encode_v9().unwrap(),
        Eversion::default(),
        Eversion::default(),
        true,
    );
    h.take();
    assert!(h.pg().missing().contains(&o));
    let attrs: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = [
        (b"_".to_vec(), oi(&o, v1, S)),
        (b"hinfo_key".to_vec(), hinfo(C, &[&A, &A, &A])),
    ]
    .into_iter()
    .collect();
    let ri = replwire::ObjectRecoveryInfo {
        soid: o.clone(),
        version: v1,
        size: S, // LOGICAL size: the shard file is C bytes
        object_exist: false,
        copy_subset: [(0u64, S)].into_iter().collect(),
        ..Default::default()
    };
    // chunk 1 of 2 (shard offsets 0..2048), then chunk 2 (2048..4096) which completes
    let first = replwire::PushOp {
        soid: o.clone(),
        version: v1,
        data: A[..2048].to_vec().into(),
        data_included: [(0u64, 2048u64)].into_iter().collect(),
        attrset: attrs.clone(),
        recovery_info: ri.clone(),
        before_progress: replwire::ObjectRecoveryProgress::default(),
        after_progress: replwire::ObjectRecoveryProgress {
            first: false,
            data_complete: false,
            data_recovered_to: 4096,
            omap_complete: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let second = replwire::PushOp {
        soid: o.clone(),
        version: v1,
        data: A[2048..].to_vec().into(),
        data_included: [(2048u64, 2048u64)].into_iter().collect(),
        recovery_info: ri,
        before_progress: first.after_progress.clone(),
        after_progress: replwire::ObjectRecoveryProgress {
            first: false,
            data_complete: true,
            data_recovered_to: S,
            omap_complete: true,
            ..Default::default()
        },
        ..Default::default()
    };
    for (i, op) in [first, second].into_iter().enumerate() {
        let m = replwire::MOSDPGPush {
            pgid: spg_me(),
            map_epoch: 5,
            pushes: vec![op],
            cost: 0,
            from: PgShard {
                osd: PRIM,
                shard: ShardId(0),
            },
            min_epoch: 5,
            is_repair: false,
        };
        h.msg(Body::Repl(replwire::ReplMsg::Push(m)));
        let sent = h.take();
        let Body::Repl(replwire::ReplMsg::PushReply(r)) = &sent[0].body else {
            panic!("{:?}", sent[0].body)
        };
        assert_eq!(r.pgid, spg_prim());
        assert_eq!(r.replies[0].soid, o);
        if i == 0 {
            assert!(
                !h.store.objects(spg_me()).contains_key(&o),
                "temp until complete"
            );
        }
    }
    let ob = &h.store.objects(spg_me())[&o];
    assert_eq!(ob.data, A.to_vec());
    assert_eq!(ob.xattrs[b"_".as_slice()], oi(&o, v1, S));
    assert_eq!(h.store.temp_objects(spg_me()), 0);
    assert!(h.pg().missing().is_empty());
}

/// A pushed shard whose bytes do not reproduce the hinfo hash (a wrong reconstruction, tracker 74943) is refused:
/// no reply, no live object, still missing. One-shot and in the last chunk of a multi-chunk push.
#[test]
fn push_with_wrong_hinfo_hash_is_refused() {
    for chunked in [false, true] {
        let mut h = H::new(true);
        h.activate_empty();
        let o = obj("a");
        let v1 = ev(5, 1);
        let e1 = entry(
            &o,
            v1,
            Eversion::default(),
            mod_desc(|b| {
                b.create();
            }),
        );
        h.write_op(
            v1,
            e1,
            Transaction::new().encode_v9().unwrap(),
            Eversion::default(),
            Eversion::default(),
            true,
        );
        h.take();
        let attrs: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = [
            (b"_".to_vec(), oi(&o, v1, S)),
            (b"hinfo_key".to_vec(), hinfo(C, &[&A, &A, &A])),
        ]
        .into_iter()
        .collect();
        let ri = replwire::ObjectRecoveryInfo {
            soid: o.clone(),
            version: v1,
            size: S,
            object_exist: false,
            copy_subset: [(0u64, S)].into_iter().collect(),
            ..Default::default()
        };
        // the same length, different bytes: only the hash can tell
        let bad: Vec<u8> = B.to_vec();
        let ops: Vec<replwire::PushOp> = if chunked {
            let first = replwire::PushOp {
                soid: o.clone(),
                version: v1,
                data: A[..2048].to_vec().into(),
                data_included: [(0u64, 2048u64)].into_iter().collect(),
                attrset: attrs.clone(),
                recovery_info: ri.clone(),
                before_progress: replwire::ObjectRecoveryProgress::default(),
                after_progress: replwire::ObjectRecoveryProgress {
                    first: false,
                    data_complete: false,
                    data_recovered_to: 4096,
                    omap_complete: true,
                    ..Default::default()
                },
                ..Default::default()
            };
            let second = replwire::PushOp {
                soid: o.clone(),
                version: v1,
                data: bad[2048..].to_vec().into(),
                data_included: [(2048u64, 2048u64)].into_iter().collect(),
                recovery_info: ri,
                before_progress: first.after_progress.clone(),
                after_progress: replwire::ObjectRecoveryProgress {
                    first: false,
                    data_complete: true,
                    data_recovered_to: S,
                    omap_complete: true,
                    ..Default::default()
                },
                ..Default::default()
            };
            vec![first, second]
        } else {
            vec![replwire::PushOp {
                soid: o.clone(),
                version: v1,
                data: bad.into(),
                data_included: [(0u64, 4096u64)].into_iter().collect(),
                attrset: attrs,
                recovery_info: ri,
                before_progress: replwire::ObjectRecoveryProgress::default(),
                after_progress: replwire::ObjectRecoveryProgress {
                    first: false,
                    data_complete: true,
                    data_recovered_to: S,
                    omap_complete: true,
                    ..Default::default()
                },
                ..Default::default()
            }]
        };
        let n = ops.len();
        for (i, op) in ops.into_iter().enumerate() {
            let m = replwire::MOSDPGPush {
                pgid: spg_me(),
                map_epoch: 5,
                pushes: vec![op],
                cost: 0,
                from: PgShard {
                    osd: PRIM,
                    shard: ShardId(0),
                },
                min_epoch: 5,
                is_repair: false,
            };
            h.msg(Body::Repl(replwire::ReplMsg::Push(m)));
            let sent = h.take();
            let acked = sent
                .iter()
                .any(|s| matches!(&s.body, Body::Repl(replwire::ReplMsg::PushReply(_))));
            // chunked: the clean first chunk is acked, the corrupt last one is not
            assert_eq!(acked, chunked && i + 1 < n, "chunked {chunked} chunk {i}");
        }
        assert!(
            !h.store.objects(spg_me()).contains_key(&o),
            "no live object"
        );
        assert!(h.pg().missing().contains(&o), "still missing");
    }
}

/// Messages for another shard, from a non-primary, or in a PG that is not active are dropped silently.
#[test]
fn foreign_and_stale_subops_are_dropped() {
    let mut h = H::new(true);
    h.activate_empty();
    h.take();
    let o = obj("a");
    let v1 = ev(5, 1);
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    // an object of another shard in the transaction: nothing applied, nothing logged, no reply
    let bad = txn(|t, c| {
        let other = t.obj(&Ghobject::new(o.clone(), LIVE, ShardId(2)));
        t.push(c, TxnOp::Touch { oid: other });
    });
    h.write_op(
        v1,
        e1.clone(),
        bad,
        Eversion::default(),
        Eversion::default(),
        false,
    );
    let sent = h.take();
    assert!(sent.is_empty(), "{sent:?}");
    assert!(!h.store.objects(spg_me()).contains_key(&o));
}

/// The kill switch is off by default: a supported pool is as passive as an unsupported one (bit for bit).
#[test]
fn kill_switch_off_is_silent() {
    let mut h = H::new(true);
    // same setup but with the switch off
    let mut set = PgSet::new(Config::new(ME));
    let acts = set.handle_map(1, ec_map(5, true, [PRIM, ME, OTHER]), &h.store);
    assert!(acts.is_empty());
    h.set = set;
    h.query_info();
    h.activate_empty();
    assert!(h.sent.is_empty() && h.set.pg(spg_me()).is_none());
    let n = h.set.take_notices();
    assert!(n.iter().any(|x| x.contains("ec_enable_pools")), "{n:?}");
    h.sent.clear();
    // switching it on loads nothing (nothing on disk) but serves new PGs
    let acts = h.set.set_ec_enable(2_000_000, ec::EcEnable::All, &h.store);
    h.run(acts);
    h.activate_empty();
    assert!(h.set.pg(spg_me()).is_some());
}

/// An EC PG led by this OSD (a pg_temp can make us primary despite primary-affinity 0): frozen, silent, and peers'
/// notifies / logs / infos do not drive it through peering (live bug: it requested bogus pg_temps).
#[test]
fn refused_primary_stays_frozen_and_silent() {
    let mut h = H::with_acting(true, [ME, PRIM, OTHER]);
    let spg_lead = SpgT {
        pgid: pgid(),
        shard: ShardId(0),
    };
    // peers announce themselves to the PG (create it first through a notify from the classic shard)
    let mut info = PgInfo::new(SpgT {
        pgid: pgid(),
        shard: ShardId(1),
    });
    info.history = h.history();
    let n = pgwire::MOSDPGNotify2 {
        spgid: spg_lead,
        notify: pgwire::PgNotify {
            query_epoch: 5,
            epoch_sent: 5,
            info,
            to: ShardId(0),
            from: ShardId(1),
            past_intervals: PastIntervals::default(),
            pg_features: 0,
        },
    };
    for _ in 0..3 {
        h.msg(Body::Peering(PeeringMsg::from(n.clone())));
    }
    let acts_sent = std::mem::take(&mut h.sent);
    assert!(
        acts_sent.is_empty(),
        "a refused primary emitted {acts_sent:?}"
    );
    if let Some(pg) = h.set.pg(spg_lead) {
        assert_eq!(pg.machine_state(), St::Primary(peering::PSt::Incomplete));
        assert!(pg.refusal().is_some());
    }
}

/// Stash GC at activation: a leaked stash object goes, the one a pending entry owns stays.
#[test]
fn activation_collects_leaked_stash() {
    let mut h = H::new(true);
    h.activate_empty();
    let o = obj("a");
    let (v1, v2) = (ev(5, 1), ev(5, 2));
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    h.write_op(
        v1,
        e1,
        create_txn(&o, v1, &A),
        Eversion::default(),
        Eversion::default(),
        false,
    );
    let e2 = entry(
        &o,
        v2,
        v1,
        mod_desc(|b| {
            b.set_attrs(&old_attrs(&o, v1, C));
            b.rollback_extents(2, &[(0, C)]);
        }),
    );
    h.write_op(
        v2,
        e2,
        overwrite_txn(&o, v2, &B),
        v1,
        Eversion::default(),
        false,
    );
    // a leak: stash generation 77 that no entry mentions
    use peering::PgStoreOps;
    let leak = txn(|t, c| {
        let s = t.obj(&gh(&o, 77));
        t.push(c, TxnOp::Touch { oid: s });
    });
    h.store.submit(
        spg_me(),
        &peering::StoreTxn {
            ops: vec![peering::StoreOp::ApplyTxn {
                middle: Bytes::new(),
                data: leak.into(),
            }],
        },
    );
    assert_eq!(h.store.stash(spg_me()).len(), 2);
    h.new_epoch(true, 3);
    h.take();
    h.activate_info(v2);
    h.take();
    let st = h.store.stash(spg_me());
    assert_eq!(st.len(), 1, "{:?}", st.keys().collect::<Vec<_>>());
    assert!(st.keys().all(|(_, g)| *g == 2));
}

/// pg_num increase: the shard PG splits like a replica: objects (and their stash) move to the child by hash, the
/// child keeps our shard, log entries follow their objects.
#[test]
fn shard_pg_splits_with_its_stash() {
    let mut h = H::new(true);
    h.activate_empty();
    h.take();
    let hobj = |name: &str, hash: u32| {
        Hobject::new(name.as_bytes(), SnapId::NOSNAP, hash, POOL as i64, b"")
    };
    let (stay, go) = (hobj("stay", 0x03), hobj("go", 0x13)); // 0x13 & 31 = 19 = 3 + 16
    let mut v = 0;
    for o in [&stay, &go] {
        v += 1;
        let at = ev(5, v);
        let e = entry(
            o,
            at,
            Eversion::default(),
            mod_desc(|b| {
                b.create();
            }),
        );
        h.write_op(
            at,
            e,
            create_txn(o, at, &A),
            Eversion::default(),
            Eversion::default(),
            false,
        );
    }
    // an overwrite of `go` leaves a stash
    let v3 = ev(5, 3);
    let e = entry(
        &go,
        v3,
        ev(5, 2),
        mod_desc(|b| {
            b.set_attrs(&old_attrs(&go, ev(5, 2), C));
            b.rollback_extents(3, &[(0, C)]);
        }),
    );
    h.write_op(
        v3,
        e,
        overwrite_txn(&go, v3, &B),
        ev(5, 2),
        Eversion::default(),
        false,
    );
    h.take();
    assert_eq!(h.store.stash(spg_me()).len(), 1);

    h.new_epoch_pg_num(true, 2, 32);
    h.take();
    let child = SpgT {
        pgid: PgT::new(POOL, 19),
        shard: ShardId(SHARD),
    };
    assert!(h.set.pg(child).is_some(), "child PG exists on our shard");
    let parent_objs = h.store.objects(spg_me());
    let child_objs = h.store.objects(child);
    assert!(parent_objs.contains_key(&stay) && !parent_objs.contains_key(&go));
    assert!(child_objs.contains_key(&go) && !child_objs.contains_key(&stay));
    assert!(
        h.store.stash(spg_me()).is_empty(),
        "the stash left with its object"
    );
    assert_eq!(h.store.stash(child).len(), 1);
    assert!(
        h.set
            .pg(child)
            .unwrap()
            .log()
            .entries()
            .iter()
            .all(|e| e.soid == go)
    );
    assert!(h.pg().log().entries().iter().all(|e| e.soid == stay));
}

/// Found live: classic OSDs aborted (PeeringState::Crashed) on an MNotifyRec from an EC shard for a split child still
/// in Reset. The split gate keys children by OUR shard id while the notify names the receiver's shard (0), so the
/// gate never matched on EC pools. Towards the (classic) primary nothing about a child may go out in the split epoch;
/// with a later map the held messages leave, restamped.
#[test]
fn split_children_are_gated_towards_the_classic_primary_per_pgid() {
    let mut h = H::new(true);
    h.activate_empty();
    h.take();
    let split_epoch = h.epoch + 1;
    h.new_epoch_pg_num(true, 2, 32);
    let sent = h.take();
    let child_msgs = |v: &[peering::Send]| {
        v.iter()
            .filter(|s| s.to == PRIM && body_spgs(&s.body).iter().any(|g| g.pgid.seed >= 16))
            .map(|s| s.epoch)
            .collect::<Vec<_>>()
    };
    assert!(
        child_msgs(&sent).is_empty(),
        "child message in the split epoch: {sent:?}"
    );
    // a later map: the held child messages may go, stamped with the new epoch (never the split epoch)
    h.new_epoch_pg_num(true, 2, 32);
    let later = child_msgs(&h.take());
    assert!(!later.is_empty(), "held child messages never released");
    assert!(
        later.iter().all(|e| *e > split_epoch),
        "stale stamp {later:?} (split at {split_epoch})"
    );
}

/// Activation through MOSDPGLog (the shard is behind AND divergent): the divergent entry rolls back, the auth entry
/// is appended and its object goes missing; `can_rollback_to` jumps to the head, the stash debt stays.
#[test]
fn merge_log_rolls_back_divergent_and_appends_auth_entries() {
    let mut h = H::new(true);
    h.activate_empty();
    h.take();
    let o = obj("a");
    let (v1, v2) = (ev(5, 1), ev(5, 2));
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    h.write_op(
        v1,
        e1,
        create_txn(&o, v1, &A),
        Eversion::default(),
        Eversion::default(),
        false,
    );
    let e2 = entry(
        &o,
        v2,
        v1,
        mod_desc(|b| {
            b.set_attrs(&old_attrs(&o, v1, C));
            b.rollback_extents(2, &[(0, C)]);
        }),
    );
    h.write_op(
        v2,
        e2,
        overwrite_txn(&o, v2, &B),
        v1,
        Eversion::default(),
        false,
    );
    h.take();
    assert_eq!(h.store.stash(spg_me()).len(), 1);

    h.new_epoch(true, 3);
    h.take();
    // auth log: (5,1) then a new write (6,2) to another object; the primary's slice starts after our common point
    let ob = obj("b");
    let auth = entry(
        &ob,
        ev(6, 2),
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    let mut info = PgInfo::new(spg_me());
    info.history = h.history();
    info.last_epoch_started = h.epoch;
    info.last_update = v1;
    info.last_complete = v1;
    let m = MOSDPGLog {
        epoch: h.epoch,
        info,
        log: PgLog {
            head: ev(6, 2),
            tail: v1,
            log: [auth].into(),
            can_rollback_to: v1,
            rollback_info_trimmed_to: v1,
            dups: Default::default(),
        },
        missing: Default::default(),
        query_epoch: h.epoch,
        past_intervals: PastIntervals::default(),
        to: ShardId(SHARD),
        from: ShardId(0),
        lease: None,
    };
    h.msg(Body::Peering(PeeringMsg::from(m)));
    let sent = h.take();
    assert!(
        sent.iter()
            .any(|s| matches!(&s.body, Body::Peering(PeeringMsg::MOSDPGInfo2(_)))),
        "{sent:?}"
    );
    let pg = h.pg();
    assert_eq!(pg.log().head(), ev(6, 2));
    assert_eq!(pg.info().last_update, ev(6, 2));
    assert!(pg.missing().contains(&ob) && !pg.missing().contains(&o));
    assert_eq!(
        h.store.objects(spg_me())[&o].data,
        A.to_vec(),
        "overwrite rolled back"
    );
    assert!(h.store.stash(spg_me()).is_empty());
    let l = pg.log();
    assert_eq!(l.log.can_rollback_to, ev(6, 2));
    assert!(l.log.rollback_info_trimmed_to <= v1);
    // persisted the same
    use peering::PgStoreOps;
    let p = h.store.load_pg(spg_me()).unwrap();
    assert_eq!(p.log.head, ev(6, 2));
    assert_eq!(p.log.can_rollback_to, ev(6, 2));
}

/// Activation through an MOSDPGLog whose auth head is BELOW ours (merge_log step "rewind if we are ahead"): the
/// divergent entries roll back like on MOSDPGInfo (case 4), they do not fall to case 5 (object removed + missing).
#[test]
fn merge_log_behind_us_rolls_back_divergent() {
    let mut h = H::new(true);
    h.activate_empty();
    h.take();
    let o = obj("a");
    let (v1, v2) = (ev(5, 1), ev(5, 2));
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    h.write_op(
        v1,
        e1.clone(),
        create_txn(&o, v1, &A),
        Eversion::default(),
        Eversion::default(),
        false,
    );
    let e2 = entry(
        &o,
        v2,
        v1,
        mod_desc(|b| {
            b.set_attrs(&old_attrs(&o, v1, C));
            b.rollback_extents(2, &[(0, C)]);
        }),
    );
    h.write_op(
        v2,
        e2,
        overwrite_txn(&o, v2, &B),
        v1,
        Eversion::default(),
        false,
    );
    h.take();
    assert_eq!(h.store.stash(spg_me()).len(), 1);

    h.new_epoch(true, 3);
    h.take();
    let mut info = PgInfo::new(spg_me());
    info.history = h.history();
    info.last_epoch_started = h.epoch;
    info.last_update = v1;
    info.last_complete = v1;
    let m = MOSDPGLog {
        epoch: h.epoch,
        info,
        log: PgLog {
            head: v1,
            tail: Eversion::default(),
            log: [e1].into(),
            can_rollback_to: v1,
            rollback_info_trimmed_to: v1,
            dups: Default::default(),
        },
        missing: Default::default(),
        query_epoch: h.epoch,
        past_intervals: PastIntervals::default(),
        to: ShardId(SHARD),
        from: ShardId(0),
        lease: None,
    };
    h.msg(Body::Peering(PeeringMsg::from(m)));
    h.take();
    let pg = h.pg();
    assert_eq!(pg.log().head(), v1);
    assert!(pg.missing().is_empty(), "case 4: rolled back, not missing");
    assert_eq!(
        h.store.objects(spg_me())[&o].data,
        A.to_vec(),
        "overwrite rolled back"
    );
    assert!(h.store.stash(spg_me()).is_empty(), "stash consumed");
}

/// pg_num decrease of an EC pool: the source merges into the target of OUR shard. Sources were looked up (and the
/// placeholder / MergeIn named) with NO_SHARD: the target lost the source's objects and a NO_SHARD PG appeared in an
/// erasure pool.
#[test]
fn shard_pg_merge_keeps_our_shard() {
    let mut h = H::new(true);
    h.activate_empty();
    h.take();
    // second PG on our shard: seed 11 merges into seed 3 at pg_num 8
    let src = SpgT {
        pgid: PgT::new(POOL, 11),
        shard: ShardId(SHARD),
    };
    let mut info = PgInfo::new(src);
    info.history = h.history();
    info.last_epoch_started = h.epoch;
    h.msg(Body::Peering(PeeringMsg::from(MOSDPGLog {
        epoch: h.epoch,
        info,
        log: PgLog::default(),
        missing: Default::default(),
        query_epoch: h.epoch,
        past_intervals: PastIntervals::default(),
        to: ShardId(SHARD),
        from: ShardId(0),
        lease: None,
    })));
    h.take();
    assert!(h.set.pg(src).is_some(), "source PG active on our shard");
    let moved = Hobject::new(b"m", SnapId::NOSNAP, 0x0b, POOL as i64, b"");
    use peering::PgStoreOps;
    let t = {
        let mut t = Transaction::new();
        let c = t.coll(&denc::types::CollT::Pg(src));
        let x = t.obj(&gh(&moved, LIVE));
        t.push(c, TxnOp::Touch { oid: x });
        t.encode_v9().unwrap()
    };
    h.store.submit(
        src,
        &peering::StoreTxn {
            ops: vec![peering::StoreOp::ApplyTxn {
                middle: Bytes::new(),
                data: t.into(),
            }],
        },
    );
    assert!(h.store.objects(src).contains_key(&moved));

    h.new_epoch_pgs(true, 2, 8, 8);
    h.take();
    assert!(
        h.set.pgs().all(|(k, _)| k.shard == ShardId(SHARD)),
        "PG without our shard: {:?}",
        h.set.pgs().map(|(k, _)| *k).collect::<Vec<_>>()
    );
    assert!(
        h.store.pgs.keys().all(|k| k.shard == ShardId(SHARD)),
        "store PG without our shard: {:?}",
        h.store.pgs.keys().collect::<Vec<_>>()
    );
    assert!(h.set.pg(src).is_none() && !h.store.pgs.contains_key(&src));
    assert!(
        h.store.objects(spg_me()).contains_key(&moved),
        "source object merged into our shard's target"
    );
}

/// Held (split-gated) sends of an EC child name the classic primary's shard, not ours: forgetting the child (kill
/// switch off) must drop them too, else they leave later for a PG that no longer exists here.
#[test]
fn forgotten_ec_child_drops_its_held_sends() {
    let mut h = H::new(true);
    h.activate_empty();
    h.take();
    h.new_epoch_pg_num(true, 2, 32);
    h.take(); // child messages are held by the split gate
    let a = h.set.set_ec_enable(h.now, ec::EcEnable::Off, &h.store);
    h.run(a);
    assert!(h.set.pgs().next().is_none(), "EC PGs forgotten");
    h.new_epoch_pg_num(true, 2, 32);
    let sent = std::mem::take(&mut h.sent);
    assert!(sent.is_empty(), "sends of forgotten PGs: {sent:?}");
    assert!(
        h.set.dropped.is_empty(),
        "held sends of a forgotten PG reached the choke point: {:?}",
        h.set.dropped
    );
    let n = h.set.take_notices();
    assert!(
        n.iter().all(|x| !x.contains("dropped outbound")),
        "held sends of a forgotten PG reached the choke point: {n:?}"
    );
}

/// L0 sub-read of an EMPTY shard object without `hinfo_key`: success (the classic backend creates a fresh hinfo of
/// size 0); a non-empty object without hinfo stays EIO.
#[test]
fn subread_empty_object_without_hinfo() {
    let mut h = H::new(false); // L0
    h.activate_empty();
    h.take();
    let (empty, full) = (obj("empty"), obj("full"));
    use peering::PgStoreOps;
    let t = txn(|t, c| {
        let e = t.obj(&gh(&empty, LIVE));
        t.push(c, TxnOp::Touch { oid: e });
        let f = t.obj(&gh(&full, LIVE));
        t.push(
            c,
            TxnOp::Write {
                oid: f,
                off: 0,
                data: Data::new(&A),
            },
        );
    });
    h.store.submit(
        spg_me(),
        &peering::StoreTxn {
            ops: vec![peering::StoreOp::ApplyTxn {
                middle: Bytes::new(),
                data: t.into(),
            }],
        },
    );
    let m = MOSDECSubOpRead {
        pgid: spg_me(),
        map_epoch: h.epoch,
        op: ECSubRead {
            from: PgShard {
                osd: PRIM,
                shard: ShardId(0),
            },
            tid: 9,
            to_read: [
                (empty.clone(), vec![(0, C, 0)]),
                (full.clone(), vec![(0, C, 0)]),
            ]
            .into_iter()
            .collect(),
            attrs_to_read: Default::default(),
            subchunks: Default::default(),
            omap_read_from: Default::default(),
            omap_headers_to_read: Default::default(),
        },
        min_epoch: h.epoch,
        trace: [0; 3],
        cost: 0,
    };
    h.msg(Body::Ec(m.into()));
    let s = h.take();
    let Body::Ec(EcMsg::ReadReply(r)) = &s[0].body else {
        panic!("{s:?}")
    };
    assert!(!r.op.errors.contains_key(&empty), "{:?}", r.op.errors);
    assert_eq!(r.op.buffers_read[&empty][0].1.len(), 0);
    assert_eq!(r.op.errors[&full], -5);
}

/// One sub-read of `o` with sub-chunk list `subs` (None = no entry).
fn clay_read(
    h: &mut H,
    o: &Hobject,
    ext: Vec<(u64, u64, u32)>,
    subs: Option<Vec<(i32, i32)>>,
) -> ECSubReadReply {
    let m = MOSDECSubOpRead {
        pgid: spg_me(),
        map_epoch: h.epoch,
        op: ECSubRead {
            from: PgShard {
                osd: PRIM,
                shard: ShardId(0),
            },
            tid: 11,
            to_read: [(o.clone(), ext)].into_iter().collect(),
            attrs_to_read: Default::default(),
            subchunks: subs.map(|s| (o.clone(), s)).into_iter().collect(),
            omap_read_from: Default::default(),
            omap_headers_to_read: Default::default(),
        },
        min_epoch: h.epoch,
        trace: [0; 3],
        cost: 0,
    };
    h.msg(Body::Ec(m.into()));
    let mut s = h.take();
    assert_eq!(s.len(), 1);
    let Body::Ec(EcMsg::ReadReply(r)) = s.remove(0).body else {
        panic!()
    };
    r.op
}

/// Clay pool (S = 4, sc = C/4): fragmented sub-chunk reads gather (first, count) ranges per chunk stride
/// (ec-clay.md 7.1), multi-stripe; one range with count == S is a plain read.
#[test]
fn clay_subchunk_gather_reads() {
    let mut h = H::with_sc(true, [PRIM, ME, OTHER], 4); // L1
    h.activate_empty();
    h.take();
    let o = obj("clay");
    let data: Vec<u8> = (0..3 * C).map(|i| (i * 7 + i / 1000) as u8).collect();
    let d = leak(data.clone());
    use peering::PgStoreOps;
    let t = txn(|t, c| {
        let live = t.obj(&gh(&o, LIVE));
        t.push(
            c,
            TxnOp::Write {
                oid: live,
                off: 0,
                data: Data::new(d),
            },
        );
    });
    h.store.submit(
        spg_me(),
        &peering::StoreTxn {
            ops: vec![peering::StoreOp::ApplyTxn {
                middle: Bytes::new(),
                data: t.into(),
            }],
        },
    );
    let sc = (C / 4) as usize;
    let gather = |off: usize, len: usize, subs: &[(usize, usize)]| -> Vec<u8> {
        let mut v = Vec::new();
        let mut m_ = 0;
        while m_ < len {
            for (f, n) in subs {
                let a = off + m_ + f * sc;
                v.extend_from_slice(&data[a.min(data.len())..(a + n * sc).min(data.len())]);
            }
            m_ += C as usize;
        }
        v
    };
    // repair-style lists (k=4,m=2,d=5 shapes scaled to S=4) over 2 stripes from offset C
    for subs in [
        vec![(0, 2)],
        vec![(2, 2)],
        vec![(0, 1), (2, 1)],
        vec![(1, 1), (3, 1)],
        vec![(3, 1), (0, 1)],
    ] {
        let s32: Vec<(i32, i32)> = subs.iter().map(|(a, b)| (*a as i32, *b as i32)).collect();
        let r = clay_read(&mut h, &o, vec![(C, 2 * C, 0)], Some(s32));
        assert!(r.errors.is_empty(), "{subs:?}: {:?}", r.errors);
        let b = &r.buffers_read[&o][0];
        assert_eq!(b.0, C);
        assert_eq!(
            b.1.as_ref(),
            gather(C as usize, 2 * C as usize, &subs).as_slice(),
            "{subs:?}"
        );
    }
    // past the end: the third stride is short (object = 3 chunks, read 2 from 2C)
    let r = clay_read(&mut h, &o, vec![(2 * C, 2 * C, 0)], Some(vec![(1, 2)]));
    assert_eq!(
        r.buffers_read[&o][0].1.as_ref(),
        gather(2 * C as usize, 2 * C as usize, &[(1, 2)]).as_slice()
    );
    // whole chunk list / absent list: plain read
    for subs in [Some(vec![(0, 4)]), None] {
        let r = clay_read(&mut h, &o, vec![(0, 3 * C, 0)], subs);
        assert_eq!(r.buffers_read[&o][0].1.as_ref(), data.as_slice());
    }
    // out-of-range sub-chunk list: EINVAL for the object
    let r = clay_read(&mut h, &o, vec![(0, C, 0)], Some(vec![(3, 2)]));
    assert_eq!(r.errors[&o], -22);
    let r = clay_read(&mut h, &o, vec![(0, C, 0)], Some(vec![(-1, 1)]));
    assert_eq!(r.errors[&o], -22);
    // a single range whose count is S but which starts inside the chunk is malformed: EINVAL, not the whole extent
    let r = clay_read(&mut h, &o, vec![(0, C, 0)], Some(vec![(1, 4)]));
    assert_eq!(r.errors[&o], -22);
    // an extent no reply piece can carry: EINVAL for the object, nothing allocated or read
    let r = clay_read(&mut h, &o, vec![(0, 1 << 62, 0)], Some(vec![(0, 1)]));
    assert_eq!(r.errors[&o], -22);
    // missing object: ENOENT through the gather
    let r = clay_read(&mut h, &obj("none"), vec![(0, C, 0)], Some(vec![(0, 1)]));
    assert_eq!(r.errors[&obj("none")], -2);
}

/// L0 clay shard: fragmented reads are not hinfo-checked unless they return the whole shard at offset 0 (literal rule).
#[test]
fn clay_subchunk_reads_l0_hinfo() {
    let mut h = H::with_sc(false, [PRIM, ME, OTHER], 4);
    h.activate_empty();
    let o = obj("c0");
    let v1 = ev(5, 1);
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    h.write_op(
        v1,
        e1,
        create_txn(&o, v1, &A),
        Eversion::default(),
        Eversion::default(),
        false,
    );
    h.take();
    let sc = (C / 4) as usize;
    let r = clay_read(&mut h, &o, vec![(0, C, 0)], Some(vec![(1, 1), (3, 1)]));
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let want: Vec<u8> = [&A[sc..2 * sc], &A[3 * sc..]].concat();
    assert_eq!(r.buffers_read[&o][0].1.as_ref(), want.as_slice());
    // two ranges covering the whole shard: checked against hinfo, passes
    let r = clay_read(&mut h, &o, vec![(0, C, 0)], Some(vec![(0, 2), (2, 2)]));
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.buffers_read[&o][0].1.as_ref(), A.as_slice());
}

/// Non-clay pool (S = 1): only `[(0, 1)]` is a plain read, anything else EOPNOTSUPP.
#[test]
fn non_clay_subchunk_lists() {
    let mut h = H::new(true);
    h.activate_empty();
    let o = obj("p");
    let v1 = ev(5, 1);
    let e1 = entry(
        &o,
        v1,
        Eversion::default(),
        mod_desc(|b| {
            b.create();
        }),
    );
    h.write_op(
        v1,
        e1,
        create_txn(&o, v1, &A),
        Eversion::default(),
        Eversion::default(),
        false,
    );
    h.take();
    let r = clay_read(&mut h, &o, vec![(0, C, 0)], Some(vec![(0, 1)]));
    assert_eq!(r.buffers_read[&o][0].1.as_ref(), A.as_slice());
    let r = clay_read(&mut h, &o, vec![(0, C, 0)], Some(vec![(0, 2)]));
    assert_eq!(r.errors[&o], -95);
}

/// One map arrival releases several epoch buckets before the driver applies any returned store transaction.
/// A sub-read in a later bucket must stay behind the preceding sub-write of the same PG.
#[test]
fn map_release_keeps_subread_behind_write_across_epoch_buckets() {
    let mut h = H::new(false);
    h.activate_empty();
    h.take();
    let o = obj("future-write");
    let v = ev(6, 1);
    h.epoch = 6;
    h.write_op(
        v,
        entry(
            &o,
            v,
            Eversion::default(),
            mod_desc(|b| {
                b.create();
            }),
        ),
        create_txn(&o, v, &A),
        Eversion::default(),
        Eversion::default(),
        false,
    );
    h.epoch = 7;
    h.msg(Body::Ec(
        MOSDECSubOpRead {
            pgid: spg_me(),
            map_epoch: 7,
            op: ECSubRead {
                from: PgShard {
                    osd: PRIM,
                    shard: ShardId(0),
                },
                tid: 77,
                to_read: [(o.clone(), vec![(0, C, 0)])].into(),
                ..Default::default()
            },
            min_epoch: 5,
            trace: [0; 3],
            cost: 0,
        }
        .into(),
    ));
    assert_eq!(h.set.parked_msgs().0, 2);
    h.take();
    let acts = h
        .set
        .handle_map(h.now, ec_map(7, false, [PRIM, ME, OTHER]), &h.store);
    assert!(acts.iter().any(|a| matches!(a, Action::Persist { .. })));
    assert!(
        !acts.iter().any(
            |a| matches!(a, Action::Send(s) if matches!(&s.body, Body::Ec(EcMsg::ReadReply(_))))
        ),
        "sub-read answered before the driver applied the preceding write"
    );
    h.run(acts);
    let replies = h.take();
    let r = replies
        .iter()
        .find_map(|s| match &s.body {
            Body::Ec(EcMsg::ReadReply(r)) => Some(&r.op),
            _ => None,
        })
        .expect("read reply after persist");
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.buffers_read[&o][0].1.as_ref(), A.as_slice());
}
