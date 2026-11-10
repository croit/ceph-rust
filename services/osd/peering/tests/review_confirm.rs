// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! EC attribute byte-name regression; fixture adapted from ec_shard.rs.
use bytes::Bytes;
use denc::types::{Eversion, Ghobject, Hobject, PgShard, PgT, ShardId, SnapId, SpgT};
use ec::moddesc::ModDescBuilder;
use ecwire::*;
use peering::synth::SynthMap;
use peering::{Action, Body, Config, Inbound, MemStore, PgSet};
use pgwire::{
    LogEntry, LogOp, MOSDPGLog, ObjectModDesc, PastIntervals, PeeringMsg, PgHistory, PgInfo, PgLog,
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
        let acts = h
            .set
            .handle_map(h.now, ec_map(5, overwrites, acting), &h.store);
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

static A: [u8; 4096] = [b'A'; 4096];

#[test]
fn review_ec_attribute_subread_silently_drops_binary_name() {
    let mut h = H::new(true);
    h.activate_empty();
    let o = obj("a");
    let v1 = ev(5, 1);
    h.write_op(
        v1,
        entry(
            &o,
            v1,
            Eversion::default(),
            mod_desc(|b| {
                b.create();
            }),
        ),
        create_txn(&o, v1, &A),
        Eversion::default(),
        Eversion::default(),
        false,
    );
    h.take();
    let mut t = Transaction::new();
    let c = t.coll(&denc::types::CollT::Pg(spg_me()));
    let g = gh(&o, LIVE);
    let ox = t.obj(&g);
    t.push(
        c,
        TxnOp::SetAttr {
            oid: ox,
            name: b"_user\xff",
            value: b"must-survive",
        },
    );
    use peering::PgStoreOps;
    h.store.submit(
        spg_me(),
        &peering::StoreTxn {
            ops: vec![peering::StoreOp::ApplyTxn {
                middle: Bytes::new(),
                data: t.encode_v9().unwrap().into(),
            }],
        },
    );
    assert!(
        h.store.objects(spg_me())[&o]
            .xattrs
            .contains_key(b"_user\xff".as_slice())
    );
    h.msg(Body::Ec(
        MOSDECSubOpRead {
            pgid: spg_me(),
            map_epoch: 5,
            op: ECSubRead {
                from: PgShard {
                    osd: PRIM,
                    shard: ShardId(0),
                },
                tid: 99,
                attrs_to_read: [o.clone()].into_iter().collect(),
                ..Default::default()
            },
            min_epoch: 5,
            trace: [0; 3],
            cost: 0,
        }
        .into(),
    ));
    let mut sent = h.take();
    assert_eq!(sent.len(), 1);
    let Body::Ec(EcMsg::ReadReply(reply)) = sent.remove(0).body else {
        panic!()
    };
    assert!(reply.op.errors.is_empty());
    assert_eq!(
        reply.op.attrs_read[&o],
        h.store.objects(spg_me())[&o].xattrs
    );
    let (wire, data) = reply.op.to_struct_bytes().unwrap();
    let decoded = ecwire::ECSubReadReply::from_struct_bytes(&wire, &data).unwrap();
    assert_eq!(
        decoded.attrs_read[&o][b"_user\xff".as_slice()],
        b"must-survive"
    );
}
