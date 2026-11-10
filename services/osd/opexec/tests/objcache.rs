// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Object-state cache model test (adr 0160 D5): random client ops (pipelined writes, reads, stats, deletes) interleaved
//! with store changes behind the engine (recovery / repair: object removals that change the PG's generation), failed
//! and aborted writes and interval resets, against a model of the object contents. Debug builds also verify every
//! cache hit against the store (`verify_hit`). The negative test proves a missed invalidation is caught.
mod common;
use common::*;
use denc::types::EntityAddr;
use opexec::{ClientReq, Engine, head_of};
use opwire::{OsdOp, errno};
use peering::{PgStoreOps, StoreOp, StoreTxn};
use std::collections::BTreeMap;

const OBJS: usize = 6;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn name(i: usize) -> Vec<u8> {
    format!("obj{i}").into_bytes()
}

fn req(tid: u64, oid: &[u8], ops: Vec<OsdOp>) -> ClientReq {
    ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(mkop(oid, ops)),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0x3f17_ffff_fffd_ffff,
    }
}

/// What a read / stat must answer, fixed when the op was submitted (per-object order).
enum Expect {
    Read(Option<Vec<u8>>),
    Stat(Option<u64>),
}

struct Model {
    pg: TPg,
    eng: Engine,
    objs: BTreeMap<Vec<u8>, Vec<u8>>,
    expect: BTreeMap<u64, Expect>,
    tid: u64,
}

impl Model {
    fn new() -> Self {
        let pg = TPg::new();
        let eng = engine(&pg);
        Model {
            pg,
            eng,
            objs: BTreeMap::new(),
            expect: BTreeMap::new(),
            tid: 0,
        }
    }

    fn op(&mut self, oid: &[u8], ops: Vec<OsdOp>) -> u64 {
        self.tid += 1;
        self.eng.on_op(&mut self.pg, req(self.tid, oid, ops));
        self.tid
    }

    /// Complete up to `n` submitted writes in order, with `rc`.
    fn complete(&mut self, n: usize, rc: i32) {
        let k = n.min(self.pg.done.len());
        for (tid, v) in self.pg.done.drain(..k).collect::<Vec<_>>() {
            self.eng.on_write_done(&mut self.pg, tid, v, rc);
        }
        // failed / aborted writes put ops back at the gate
        self.eng.retry(&mut self.pg);
    }

    fn check(&mut self) {
        for o in self.eng.take_out() {
            let opexec::Out::Reply { tid, reply, .. } = o else {
                continue;
            };
            let Some(e) = self.expect.remove(&tid) else {
                continue;
            };
            match e {
                Expect::Read(None) | Expect::Stat(None) => {
                    assert_eq!(reply.result, -errno::ENOENT, "tid {tid}")
                }
                Expect::Read(Some(d)) => {
                    assert_eq!(reply.result, 0, "tid {tid}");
                    assert_eq!(&reply.ops[0].outdata[..], &d[..], "tid {tid}");
                }
                Expect::Stat(Some(sz)) => {
                    assert_eq!(reply.result, 0, "tid {tid}");
                    let got = u64::from_le_bytes(reply.ops[0].outdata[..8].try_into().unwrap());
                    assert_eq!(got, sz, "tid {tid}");
                }
            }
        }
    }

    fn step(&mut self, r: &mut Rng) {
        let i = r.below(OBJS as u64) as usize;
        let oid = name(i);
        match r.below(20) {
            0..=5 => {
                let len = 1 + r.below(64) as usize;
                let data = vec![r.next() as u8; len];
                if r.below(2) == 0 {
                    self.op(&oid, vec![OsdOp::writefull(data.clone())]);
                    self.objs.insert(oid, data);
                } else {
                    let off = r.below(32) as usize;
                    self.op(&oid, vec![OsdOp::write(off as u64, data.clone())]);
                    let cur = self.objs.entry(oid).or_default();
                    if cur.len() < off + len {
                        cur.resize(off + len, 0);
                    }
                    cur[off..off + len].copy_from_slice(&data);
                }
            }
            6..=9 => {
                let want = self.objs.get(&oid).cloned();
                let t = self.op(&oid, vec![OsdOp::read(0, 4096)]);
                self.expect.insert(t, Expect::Read(want));
            }
            10..=11 => {
                let want = self.objs.get(&oid).map(|d| d.len() as u64);
                let t = self.op(&oid, vec![OsdOp::stat()]);
                self.expect.insert(t, Expect::Stat(want));
            }
            12 => {
                if self.objs.remove(&oid).is_some() {
                    self.op(&oid, vec![OsdOp::delete()]);
                }
            }
            13 => {
                // recovery / repair removed the object behind the engine (nothing in flight on it)
                self.settle();
                let head = head_of(&mkop(&oid, vec![]));
                self.pg.store.submit(
                    self.pg.spg,
                    &StoreTxn {
                        ops: vec![StoreOp::RemoveObject(head)],
                    },
                );
                self.pg.foreign();
                self.objs.remove(&oid);
            }
            14..=15 => self.complete(1 + r.below(3) as usize, 0),
            16 => self.complete(1, -errno::EIO), // failed write (the test store applied it: the content stays)
            17 => self.complete(1, -errno::EAGAIN), // aborted: re-runs as a dup
            18 => {
                self.settle();
                self.check(); // replies before the reset (it forgets unsent output)
                self.eng.reset();
                self.eng.retry(&mut self.pg);
            }
            _ => self.settle(),
        }
        self.check();
    }

    fn settle(&mut self) {
        while !self.pg.done.is_empty() {
            self.complete(usize::MAX, 0);
        }
    }
}

#[test]
fn model_with_foreign_changes_failures_and_resets() {
    let mut hits = 0;
    for seed in 1..=24u64 {
        let mut m = Model::new();
        let mut r = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        for _ in 0..1500 {
            m.step(&mut r);
        }
        m.settle();
        m.check();
        assert!(
            m.expect.is_empty(),
            "seed {seed}: unanswered {:?}",
            m.expect.keys()
        );
        hits += m.eng.c.obj_hits;
    }
    assert!(hits > 1000, "the cache served ({hits} hits)");
}

#[test]
fn off_without_capacity() {
    let mut m = Model::new();
    m.pg.obj_cap = 0;
    let mut r = Rng(42);
    for _ in 0..500 {
        m.step(&mut r);
    }
    assert_eq!(m.eng.c.obj_hits + m.eng.c.obj_misses, 0);
}

/// A store change behind the engine WITHOUT a new generation: the debug check of the next hit catches it.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "stale object-state cache entry")]
fn missed_invalidation_is_caught() {
    let mut m = Model::new();
    m.op(b"x", vec![OsdOp::writefull(b"abc".to_vec())]);
    m.settle();
    m.op(b"x", vec![OsdOp::stat()]);
    let head = head_of(&mkop(b"x", vec![]));
    m.pg.store.submit(
        m.pg.spg,
        &StoreTxn {
            ops: vec![StoreOp::RemoveObject(head)],
        },
    );
    m.op(b"x", vec![OsdOp::stat()]);
}

/// The PG changed objects while writes were in flight (generation moved): the post-write state of those writes is not
/// cached when the object becomes idle; the next op loads the store.
#[test]
fn state_of_writes_across_a_generation_change_is_not_cached() {
    let mut m = Model::new();
    m.op(b"x", vec![OsdOp::writefull(b"abc".to_vec())]);
    let head = head_of(&mkop(b"x", vec![]));
    m.pg.store.submit(
        m.pg.spg,
        &StoreTxn {
            ops: vec![StoreOp::RemoveObject(head)],
        },
    );
    m.pg.foreign();
    m.settle();
    let t = m.op(b"x", vec![OsdOp::stat()]);
    m.expect.insert(t, Expect::Stat(None));
    m.check();
    assert!(m.expect.is_empty());
    assert_eq!(m.eng.c.obj_hits, 0);
}
