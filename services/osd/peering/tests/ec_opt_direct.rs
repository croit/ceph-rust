#![expect(clippy::field_reassign_with_default)]
// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optimized EC direct reads (adr 0067 am. 3, spec ec-optimized.md 7.3) of a nonprimary / parity shard against a MODEL
//! of a classic optimized primary: what is served from our shard file and every refusal (EAGAIN = redrive through the
//! primary). Own vectors, no oracle.
use bytes::Bytes;
use denc::types::{Eversion, Ghobject, Hobject, PgShard, PgT, ShardId, SnapId, SpgT};
use ec::moddesc::ModDescBuilder;
use ecwire::*;
use peering::synth::SynthMap;
use peering::{Action, Body, Config, Inbound, MemStore, PgSet, PgStoreOps};
use pgwire::{
    LogEntry, LogOp, MOSDPGLog, ObjectModDesc, PastIntervals, PeeringMsg, PgHistory, PgInfo, PgLog,
    ShardIdSet,
};
use replwire::txn::*;

// k=2 m=2, C=4K: shard 0 raw 0 (PC), shard 1 raw 1 (NONPRIMARY), shards 2, 3 parity (PC)
const PRIM: i32 = 1; // classic primary, shard 0
const ME: i32 = 3;
const POOL: u64 = 7;
const S: u64 = 8192;
const LIVE: u64 = u64::MAX;
const ALL: [u32; 4] = [0, 1, 2, 3];

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
    clock: std::sync::Arc<peering::PeerClockSlot>,
}

impl H {
    fn new(me_shard: usize, opt_on: bool) -> H {
        let mut cfg = Config::new(ME);
        // the heartbeat core's slot for the primary: equal clocks, exact bounds
        let clock = std::sync::Arc::new(peering::PeerClockSlot::default());
        clock.store(Some(peering::PeerClockBounds {
            up_from: 1,
            lower: Some(0),
            upper: Some(0),
        }));
        cfg.peer_clocks.insert(PRIM, clock.clone());
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
            clock,
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
        let ob = leak(oi(o, v, SIZE));
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

static A: [u8; 4096] = [b'A'; 4096];
static B: [u8; 4096] = [b'B'; 4096];
const SIZE: u64 = 16384; // two stripes of 8192 (k=2, C=4096)
const SEC: u64 = 1_000_000_000;
const MS: u64 = 1_000_000;

use peering::ecdirect::DirectExtent;

fn rd(offset: u64, length: u64) -> DirectExtent {
    DirectExtent {
        offset,
        length,
        truncate_seq: 0,
        truncate_size: 0,
        sparse: false,
    }
}

impl H {
    /// Lease from the primary (interval 4 s), as the primary's `renew_lease` sends it now (same clock).
    fn lease(&mut self) {
        self.lease_sent(self.now);
    }
    /// Lease the primary sent at `sent` (ub = sent + interval), delivered now.
    fn lease_sent(&mut self, sent: u64) {
        let ub = sent + 4 * SEC;
        let m = pgwire::MOSDPGLease {
            epoch: 5,
            spgid: self.spg(),
            lease: pgwire::PgLease {
                readable_until: denc::types::Timespan {
                    sec: (ub / SEC) as i32,
                    nsec: (ub % SEC) as i32,
                },
                readable_until_ub: denc::types::Timespan {
                    sec: (ub / SEC) as i32,
                    nsec: (ub % SEC) as i32,
                },
                interval: denc::types::Timespan { sec: 4, nsec: 0 },
            },
        };
        self.msg(Body::Peering(PeeringMsg::from(m)));
    }
    fn direct(
        &self,
        o: &Hobject,
        reads: &[DirectExtent],
        v: bool,
    ) -> Result<peering::ecdirect::DirectRead, i32> {
        self.pg().ec_direct_read(self.now, o, reads, v, &self.store)
    }
    /// Shard 1 holds A at shard 0..4096 (stripe 0) and B at 4096..8192 (stripe 1), committed (pct = head).
    fn setup(&mut self) -> Hobject {
        let o = self.setup_without_lease();
        self.lease();
        self.take();
        o
    }
    fn setup_without_lease(&mut self) -> Hobject {
        self.activate_log(self.prim_info(Eversion::default()), PgLog::default());
        self.take();
        let o = obj("a");
        let e1 = entry(
            &o,
            ev(1),
            Eversion::default(),
            &ALL,
            md(|b| {
                b.create();
            }),
        );
        let t = self.write_txn(&o, ev(1), 0, &A, None);
        self.write(vec![e1], t, Eversion::default(), Eversion::default(), false);
        let e2 = entry(
            &o,
            ev(2),
            ev(1),
            &ALL,
            md(|b| {
                b.rollback_extents_v3(2, &[(4096, 4096)], 8192, &[[0b1111, 0]]);
            }),
        );
        let t = self.write_txn(&o, ev(2), 4096, &B, Some(2));
        self.write(vec![e2], t, ev(1), Eversion::default(), false);
        // idle pct: everything committed
        self.write(vec![], self.empty_txn(), ev(2), Eversion::default(), false);
        self.take();
        o
    }
}

#[test]
fn serves_own_chunks_under_lease_and_refuses_without() {
    let mut h = H::new(1, true);
    let o = h.setup();
    // stripe 0 chunk of shard 1 = logical 4096..8192: single-chunk read inside
    let r = h.direct(&o, &[rd(4096 + 8, 16)], false).expect("served");
    assert_eq!(r.data, vec![vec![b'A'; 16]]);
    // two stripes: our chunks of both, contiguous in the shard file
    let r = h.direct(&o, &[rd(100, 16384 - 100)], false).unwrap();
    assert_eq!(r.data[0].len(), 8192);
    assert!(r.data[0][..4096].iter().all(|b| *b == b'A'));
    assert!(r.data[0][4096..].iter().all(|b| *b == b'B'));
    // a read that lies on the other shard: nothing of it on us
    assert!(h.direct(&o, &[rd(0, 100)], false).unwrap().data[0].is_empty());
    // beyond the object: empty, not an error
    assert!(h.direct(&o, &[rd(SIZE, 100)], false).unwrap().data[0].is_empty());
    // A replica cannot read after the actual granted deadline.
    h.now += 4 * SEC;
    assert_eq!(h.direct(&o, &[rd(4096, 16)], false).unwrap_err(), 11);
    // a new lease revives it
    h.lease();
    h.take();
    assert!(h.direct(&o, &[rd(4096, 16)], false).is_ok());
    // a map change that makes a new interval kills the lease and the role
    let a = h.set.handle_map(h.now + 1, opt_map(6, 1), &h.store);
    h.run(a);
    assert_eq!(h.direct(&o, &[rd(4096, 16)], false).unwrap_err(), 11);
}

#[test]
fn never_without_lease() {
    let mut h = H::new(1, true);
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    h.take();
    let o = obj("a");
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
    h.write(vec![], h.empty_txn(), ev(1), Eversion::default(), false);
    h.take();
    assert_eq!(h.direct(&o, &[rd(4096, 16)], false).unwrap_err(), 11);
}

#[test]
fn uncommitted_missing_absent_and_short_are_refused() {
    let mut h = H::new(1, true);
    let o = h.setup();
    // v3 rewrites our chunk but pct stays v2: the write is not committed everywhere (it may roll back)
    let e3 = entry(
        &o,
        ev(3),
        ev(2),
        &ALL,
        md(|b| {
            b.rollback_extents_v3(3, &[(0, 4096)], 8192, &[[0b1111, 0]]);
        }),
    );
    let t = h.write_txn(&o, ev(3), 0, &B, Some(3));
    h.write(vec![e3], t, ev(2), Eversion::default(), false);
    h.take();
    h.lease();
    h.take();
    assert_eq!(h.direct(&o, &[rd(4096, 16)], false).unwrap_err(), 11);
    // committed: served, with the new bytes
    h.write(vec![], h.empty_txn(), ev(3), Eversion::default(), false);
    h.take();
    assert_eq!(
        h.direct(&o, &[rd(4096, 16)], false).unwrap().data,
        vec![vec![b'B'; 16]]
    );
    // an object we never had
    assert_eq!(
        h.direct(&obj("nope"), &[rd(4096, 16)], false).unwrap_err(),
        11
    );
    // zero length is the primary's business
    assert_eq!(h.direct(&o, &[rd(4096, 0)], false).unwrap_err(), 11);
}

#[test]
fn short_shard_file_is_a_hole_for_the_primary() {
    let mut h = H::new(1, true);
    h.activate_log(h.prim_info(Eversion::default()), PgLog::default());
    h.take();
    let o = obj("a");
    // OI says 16384 bytes, the shard file only has stripe 0 (stripe 1 is a zero hole for the primary)
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
    h.write(vec![], h.empty_txn(), ev(1), Eversion::default(), false);
    h.take();
    h.lease();
    h.take();
    assert!(h.direct(&o, &[rd(4096, 16)], false).is_ok());
    assert_eq!(h.direct(&o, &[rd(12288, 16)], false).unwrap_err(), 11);
    assert_eq!(h.direct(&o, &[rd(100, 16000)], false).unwrap_err(), 11);
    // a sparse read answers the hole as a hole (adr 0067 am. 4.5)
    let sp = |off, len| DirectExtent {
        sparse: true,
        ..rd(off, len)
    };
    let r = h.direct(&o, &[sp(100, 16000)], false).unwrap();
    assert_eq!(r.extents[0].as_deref(), Some(&[(4096, 4096)][..]));
    assert!(r.data[0] == A.to_vec());
    let r = h.direct(&o, &[sp(12288, 16)], false).unwrap();
    assert_eq!(
        (r.extents[0].as_deref(), r.data[0].len()),
        (Some(&[][..]), 0)
    );
}

#[test]
fn parity_shard_never_serves() {
    let mut h = H::new(2, true);
    let o = h.setup();
    assert_eq!(h.direct(&o, &[rd(0, 16)], false).unwrap_err(), 11);
}

#[test]
fn truncate_rule_and_versions() {
    let mut h = H::new(1, true);
    let o = h.setup();
    // truncate_seq newer than the object's, truncate_size inside our chunk: the read stops there
    let mut e = rd(4096, 4096);
    e.truncate_seq = 1;
    e.truncate_size = 4096 + 10;
    let r = h.direct(&o, &[e], true).unwrap();
    assert_eq!(r.data, vec![vec![b'A'; 10]]);
    // versions: our shard only, with our local OI version (the shard version of a nonprimary shard)
    assert_eq!(r.versions, vec![(ShardId(1), ev(2))]);
}

#[test]
fn object_missing_on_our_shard_is_refused() {
    let mut h = H::new(1, true);
    let o = obj("m");
    // the activation log carries a write of `m` that we have not got: missing (recovery pushes it later)
    let e1 = entry(
        &o,
        ev(1),
        Eversion::default(),
        &ALL,
        md(|b| {
            b.create();
        }),
    );
    let mut log = PgLog::default();
    log.head = ev(1);
    log.tail = Eversion::default();
    log.log.push_back(e1);
    h.activate_log(h.prim_info(ev(1)), log);
    h.take();
    h.lease();
    h.take();
    assert!(h.pg().missing().contains(&o), "setup: object is missing");
    assert_eq!(h.direct(&o, &[rd(4096, 16)], false).unwrap_err(), 11);
}

#[test]
fn delayed_lease_expires_at_the_primary_deadline() {
    let mut h = H::new(1, true);
    let o = h.setup();
    let t0 = h.now;
    h.now = t0 + 2500 * MS;
    h.lease_sent(t0 + 500 * MS);
    h.take();
    h.now = t0 + 4400 * MS;
    assert!(h.direct(&o, &[rd(4096, 16)], false).is_ok());
    h.now = t0 + 4600 * MS;
    assert_eq!(h.direct(&o, &[rd(4096, 16)], false).unwrap_err(), 11);
}

/// The original 3/4-from-receipt rule granted stale reads after failover when the baseline transit time was large.
#[test]
fn equally_delayed_leases_never_extend_reads_past_a_failover_bound() {
    let mut h = H::new(1, true);
    let o = h.setup_without_lease();
    let base = h.now;
    // Clock bounds from a real round trip may be loose. delta upper=0 is safe for these equal clocks;
    // observing repeated 2.5s lease transit is not a clock-offset measurement.
    h.clock.store(Some(peering::PeerClockBounds {
        up_from: 1,
        lower: Some(-2_500_000_000),
        upper: Some(0),
    }));
    // A's activation at base reaches B at base+2.5; its ack lets A renew at base+2.5.
    h.now = base + 2500 * MS;
    h.lease_sent(base);
    h.now = base + 5000 * MS;
    h.lease_sent(base + 2500 * MS);
    h.take();
    // A crashes after its renewal, B misses the new maps. C/D wait out A's final promise (base+6.5),
    // activate without B and acknowledge a newer object. B must refuse its still-locally-committed old bytes.
    h.now = base + 6700 * MS;
    assert_eq!(h.direct(&o, &[rd(4096, 16)], false).unwrap_err(), 11);
}

#[test]
fn direct_reads_require_a_grant_and_current_incarnation_clock_bounds() {
    let mut h = H::new(1, true);
    let o = h.setup();
    h.clock.store(None);
    assert_eq!(h.direct(&o, &[rd(4096, 16)], false).unwrap_err(), 11);
    h.clock.store(Some(peering::PeerClockBounds {
        up_from: 2,
        lower: Some(0),
        upper: Some(0),
    }));
    assert_eq!(h.direct(&o, &[rd(4096, 16)], false).unwrap_err(), 11);
    h.clock.store(Some(peering::PeerClockBounds {
        up_from: 1,
        lower: Some(0),
        upper: Some(0),
    }));
    assert!(h.direct(&o, &[rd(4096, 16)], false).is_ok());
    // An updated, wider bound must be applied to an already-received grant on the next read.
    h.clock.store(Some(peering::PeerClockBounds {
        up_from: 1,
        lower: Some(0),
        upper: Some(5_000_000_000),
    }));
    assert_eq!(h.direct(&o, &[rd(4096, 16)], false).unwrap_err(), 11);
}

#[test]
fn lease_upper_bound_without_a_readable_grant_never_authorizes_reads() {
    let mut h = H::new(1, true);
    let o = h.setup_without_lease();
    h.msg(Body::Peering(PeeringMsg::from(pgwire::MOSDPGLease {
        epoch: 5,
        spgid: h.spg(),
        lease: pgwire::PgLease {
            readable_until: Default::default(),
            readable_until_ub: denc::types::Timespan { sec: 100, nsec: 0 },
            interval: denc::types::Timespan { sec: 4, nsec: 0 },
        },
    })));
    assert_eq!(h.direct(&o, &[rd(4096, 16)], false).unwrap_err(), 11);
}

#[test]
fn zero_grant_revokes_an_existing_grant() {
    let mut h = H::new(1, true);
    let o = h.setup();
    assert!(h.direct(&o, &[rd(4096, 16)], false).is_ok());
    h.msg(Body::Peering(PeeringMsg::from(pgwire::MOSDPGLease {
        epoch: 5,
        spgid: h.spg(),
        lease: pgwire::PgLease {
            readable_until: Default::default(),
            readable_until_ub: denc::types::Timespan { sec: 100, nsec: 0 },
            interval: denc::types::Timespan { sec: 4, nsec: 0 },
        },
    })));
    assert_eq!(h.direct(&o, &[rd(4096, 16)], false).unwrap_err(), 11);
}

/// Deterministic generated asymmetric heartbeat transit, lease transit and primary clock offsets.
#[test]
fn random_delays_never_allow_reads_after_the_primary_promise() {
    let mut rng = 0x9e3779b97f4a7c15u64;
    for _ in 0..256 {
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let offset = next() % (20 * SEC);
        let outbound = next() % (6 * SEC);
        let inbound = next() % (6 * SEC);
        let delay = next() % (10 * SEC);
        let mut h = H::new(1, true);
        let o = h.setup_without_lease();
        let sent = h.now;
        h.clock.store(Some(peering::PeerClockBounds {
            up_from: 1,
            lower: Some(offset as i64 - inbound as i64),
            upper: Some((offset + outbound) as i64),
        }));
        h.now = sent + delay;
        h.lease_sent(sent + offset);
        let deadline = sent + 4 * SEC;
        for now in [h.now, deadline, deadline + next() % (10 * SEC)] {
            h.now = now;
            if h.direct(&o, &[rd(4096, 16)], false).is_ok() {
                assert!(now < deadline, "offset={offset} delay={delay}");
            }
        }
    }
}
