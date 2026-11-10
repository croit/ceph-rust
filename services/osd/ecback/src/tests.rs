// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Deterministic model tests: generated shard transactions are applied to byte-vector shard stores and compared
//! with a plain logical model; every step is also rolled back from its `mod_desc` and compared with the previous
//! state; reads are checked for every k-subset of shards.

use super::*;
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use ec::{EcMode, PoolEcInput, Verdict, evaluate};
use pgwire::ObjectModDesc;
use replwire::txn::{Data, Transaction, TxnOp};
use std::collections::BTreeMap;

#[test]
fn reclaim_splits_only_zero_blocks_without_scanning_ordinary_writes() {
    let mut data = vec![7u8; 4 * 4096];
    data[4096..3 * 4096].fill(0);
    for reclaim in [false, true] {
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId(0),
        }));
        let oid = t.obj(&Ghobject::new(
            Hobject::new(b"reclaim", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId(0),
        ));
        crate::RECLAIM_SCAN_BYTES.with(|n| n.set(0));
        crate::shard_write(&mut t, cx, oid, 4096, &data, reclaim);
        crate::RECLAIM_SCAN_BYTES
            .with(|n| assert_eq!(n.get(), if reclaim { data.len() } else { 0 }));
        if reclaim {
            assert_eq!(t.ops.len(), 3);
            assert!(matches!(t.ops[0].op, TxnOp::Write { off: 4096, .. }));
            assert!(matches!(
                t.ops[1].op,
                TxnOp::Zero {
                    off: 8192,
                    len: 8192,
                    ..
                }
            ));
            assert!(matches!(t.ops[2].op, TxnOp::Write { off: 16384, .. }));
        } else {
            assert_eq!(t.ops.len(), 1);
            assert!(matches!(t.ops[0].op, TxnOp::Write { .. }));
        }
    }
}

const LIVE: u64 = u64::MAX;

fn facts(k: u32, m: u32, chunk: u32, overwrites: bool, plugin: &str, tech: &str) -> EcFacts {
    facts_with(k, m, chunk, overwrites, plugin, tech, &[])
}

fn facts_with(
    k: u32,
    m: u32,
    chunk: u32,
    overwrites: bool,
    plugin: &str,
    tech: &str,
    extra: &[(&str, &str)],
) -> EcFacts {
    let mut p: BTreeMap<String, String> = BTreeMap::new();
    for (a, b) in extra {
        p.insert(a.to_string(), b.to_string());
    }
    p.insert("plugin".into(), plugin.into());
    p.insert("technique".into(), tech.into());
    p.insert("k".into(), k.to_string());
    p.insert("m".into(), m.to_string());
    match evaluate(&PoolEcInput {
        size: k + m,
        min_size: k,
        stripe_width: k * chunk,
        flag_overwrites: overwrites,
        flag_optimizations: false,
        flag_omap: false,
        profile: Some(&p),
        ..Default::default()
    }) {
        Verdict::Supported(f) => f,
        Verdict::Unsupported(r) => panic!("{r}"),
    }
}

/// lrc k=4 m=2 l=3: pool size 8 (k = 4 data shards, 4 parity-role shards).
fn facts_lrc(chunk: u32, overwrites: bool) -> EcFacts {
    let p: BTreeMap<String, String> = [("plugin", "lrc"), ("k", "4"), ("m", "2"), ("l", "3")]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    match evaluate(&PoolEcInput {
        size: 8,
        min_size: 5,
        stripe_width: 4 * chunk,
        flag_overwrites: overwrites,
        profile: Some(&p),
        ..Default::default()
    }) {
        Verdict::Supported(f) => f,
        Verdict::Unsupported(r) => panic!("{r}"),
    }
}

/// Spec ec-lrc.md 6 (minimum_to_decode) for lrc 4/2/3, want = position mask, re-written here on position masks as an
/// independent oracle: does a plan exist for the available shards `avail`?
fn lrc_423_recoverable(avail: u32, want: u32) -> bool {
    let layers = [(0b0111_0111u32, 2u32), (0b0000_1111, 1), (0b1111_0000, 1)];
    let e_total = !avail & 0xFF;
    let mut e_want = want & e_total;
    if e_want == 0 {
        return true;
    }
    let mut e_nr = e_total;
    for (mask, ml) in layers.iter().rev() {
        let lw = want & mask;
        if lw == 0 || lw & e_want == 0 {
            continue;
        }
        let er = mask & e_nr;
        if er.count_ones() <= *ml {
            e_nr &= !er;
            e_want &= !er;
        }
    }
    if e_want == 0 {
        return true;
    }
    let mut e = e_total;
    for (mask, ml) in layers.iter().rev() {
        let le = e & mask;
        if le != 0 && le.count_ones() <= *ml {
            e &= !le;
        }
    }
    e == 0
}

fn hobj(name: &str) -> Hobject {
    Hobject::new(name.as_bytes(), SnapId::NOSNAP, 0x1234, 1, b"")
}

#[derive(Clone, Default, PartialEq, Eq, Debug)]
struct Obj {
    data: Vec<u8>,
    attrs: BTreeMap<Vec<u8>, Vec<u8>>,
}
type Store = BTreeMap<(Hobject, u64), Obj>;

#[derive(Debug, Clone)]
enum L {
    Create(&'static str),
    Write(&'static str, u64, Vec<u8>),
    Zero(&'static str, u64, u64),
    Trunc(&'static str, u64),
    Remove(&'static str),
    Attr(&'static str, &'static str, Vec<u8>),
    Clone(&'static str, &'static str),
}

fn ltxn(ops: &[L]) -> Vec<u8> {
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(denc::types::SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId(0),
    }));
    let g = |n: &str| Ghobject::new(hobj(n), LIVE, ShardId(0));
    for op in ops {
        match op {
            L::Create(n) => {
                let o = t.obj(&g(n));
                t.push(cx, TxnOp::Create { oid: o });
            }
            L::Write(n, off, d) => {
                let o = t.obj(&g(n));
                t.push(
                    cx,
                    TxnOp::Write {
                        oid: o,
                        off: *off,
                        data: Data::new(d),
                    },
                );
            }
            L::Zero(n, off, len) => {
                let o = t.obj(&g(n));
                t.push(
                    cx,
                    TxnOp::Zero {
                        oid: o,
                        off: *off,
                        len: *len,
                    },
                );
            }
            L::Trunc(n, s) => {
                let o = t.obj(&g(n));
                t.push(cx, TxnOp::Truncate { oid: o, size: *s });
            }
            L::Remove(n) => {
                let o = t.obj(&g(n));
                t.push(cx, TxnOp::Remove { oid: o });
            }
            L::Attr(n, k, v) => {
                let o = t.obj(&g(n));
                t.push(
                    cx,
                    TxnOp::SetAttrs {
                        oid: o,
                        attrs: vec![(k.as_bytes(), v.as_slice())],
                    },
                );
            }
            L::Clone(a, b) => {
                let (x, y) = (t.obj(&g(a)), t.obj(&g(b)));
                t.push(
                    cx,
                    TxnOp::Clone {
                        oid: x,
                        dest_oid: y,
                    },
                );
            }
        }
    }
    t.encode_v9().unwrap()
}

/// Shared generation (wire rope + local skeleton) is byte-identical to the copied blobs.
pub(crate) fn check_shared(shared: &[crate::SharedTxn], blobs: &[Vec<u8>]) {
    assert_eq!(shared.len(), blobs.len());
    for (sh, (s, b)) in shared.iter().zip(blobs).enumerate() {
        let (mut flat, mut pos) = (Vec::new(), 0);
        for (at, r) in &s.zc {
            flat.extend_from_slice(&s.inline[pos..*at]);
            flat.extend_from_slice(r);
            pos = *at;
        }
        flat.extend_from_slice(&s.inline[pos..]);
        assert_eq!(&flat, b, "shard {sh}: rope");
        let t = Transaction::decode_split(&s.skel, &s.refs, 4096).unwrap();
        assert_eq!(&t.encode_v9().unwrap(), b, "shard {sh}: skeleton");
        assert_eq!(s.zc.len(), s.refs.len(), "shard {sh}: same payloads shared");
    }
}

/// Every shared run of the legacy generator carries the encode's crcs, equal to a full pass: the msgr2 crc (seed `!0`)
/// and the store's 4K block crcs.
pub(crate) fn check_hints(shared: &[crate::SharedTxn]) {
    for (sh, s) in shared.iter().enumerate() {
        for r in s.zc.iter().map(|(_, r)| r).chain(&s.refs) {
            let want = crc::crc32c(!0, r);
            let h = s
                .hints
                .iter()
                .find(|h| h.of(r).is_some())
                .unwrap_or_else(|| panic!("shard {sh}: run of {} B without a crc hint", r.len()));
            assert_eq!(h.of(r), Some(want), "shard {sh}: run crc");
            let p = h.payload().unwrap();
            let blocks = p.blocks_at(0, r.len() / 4096).unwrap_or(&[]);
            assert_eq!(blocks.len(), r.len() / 4096, "shard {sh}: block count");
            for (b, &c) in r.as_chunks::<4096>().0.iter().zip(blocks) {
                assert_eq!(c, crc::crc32c(0, b), "shard {sh}: block crc");
            }
        }
    }
}

fn apply_shard(st: &mut Store, bytes: &[u8]) {
    let t = Transaction::decode(&[], bytes, 4096).unwrap();
    let key = |ox| {
        let g = t.get_obj(ox);
        (g.hobj.clone(), g.generation)
    };
    for op in &t.ops {
        match &op.op {
            TxnOp::Create { oid } | TxnOp::Touch { oid } => {
                st.entry(key(*oid)).or_default();
            }
            TxnOp::Write { oid, off, data } => {
                let o = st.entry(key(*oid)).or_default();
                let end = *off as usize + data.len();
                if o.data.len() < end {
                    o.data.resize(end, 0);
                }
                o.data[*off as usize..end].copy_from_slice(&data.to_vec());
            }
            TxnOp::Zero { oid, off, len } => {
                let o = st.entry(key(*oid)).or_default();
                let end = (*off + *len) as usize;
                if o.data.len() < end {
                    o.data.resize(end, 0);
                }
                o.data[*off as usize..end].fill(0);
            }
            TxnOp::Truncate { oid, size } => {
                st.get_mut(&key(*oid))
                    .unwrap()
                    .data
                    .resize(*size as usize, 0);
            }
            TxnOp::Remove { oid } => {
                st.remove(&key(*oid)).expect("remove of absent object");
            }
            TxnOp::SetAttrs { oid, attrs } => {
                let o = st.get_mut(&key(*oid)).expect("setattrs on absent object");
                for (k, v) in attrs {
                    o.attrs.insert(k.to_vec(), v.to_vec());
                }
            }
            TxnOp::RmAttr { oid, name } => {
                st.get_mut(&key(*oid)).unwrap().attrs.remove(*name);
            }
            TxnOp::Clone { oid, dest_oid } => {
                let o = st.get(&key(*oid)).expect("clone of absent").clone();
                st.insert(key(*dest_oid), o);
            }
            TxnOp::CloneRange2 {
                oid,
                dest_oid,
                src_off,
                len,
                dest_off,
            } => {
                let src = st.get(&key(*oid)).expect("clone_range of absent").clone();
                let d = st.entry(key(*dest_oid)).or_default();
                let (a, b) = (*src_off as usize, (*src_off + *len) as usize);
                assert!(b <= src.data.len(), "clone_range past source end");
                let end = *dest_off as usize + (b - a);
                if d.data.len() < end {
                    d.data.resize(end, 0);
                }
                d.data[*dest_off as usize..end].copy_from_slice(&src.data[a..b]);
            }
            TxnOp::CollMoveRename { oid, dest_oid, .. } => {
                let o = st.remove(&key(*oid)).expect("rename of absent");
                st.insert(key(*dest_oid), o);
            }
            o => panic!("unexpected shard op {o:?}"),
        }
    }
}

/// Undo `md` on one shard store (ec.md 7.6, own mini executor).
fn rollback(be: &Backend, st: &mut Store, soid: &Hobject, md: &ObjectModDesc) {
    use ec::moddesc::{ModOp, parse};
    for op in parse(&md.bl).unwrap().iter().rev() {
        match op {
            ModOp::Append { old_size } => {
                st.get_mut(&(soid.clone(), LIVE))
                    .unwrap()
                    .data
                    .resize(be.shard_size(*old_size).unwrap() as usize, 0);
            }
            ModOp::SetAttrs(a) => {
                let o = st.get_mut(&(soid.clone(), LIVE)).unwrap();
                for (k, v) in a {
                    match v {
                        Some(v) => o.attrs.insert(k.clone(), v.clone()),
                        None => o.attrs.remove(k),
                    };
                }
            }
            ModOp::Delete { version } => {
                st.remove(&(soid.clone(), LIVE));
                let o = st.remove(&(soid.clone(), *version)).expect("stash");
                st.insert((soid.clone(), LIVE), o);
            }
            ModOp::Create => {
                st.remove(&(soid.clone(), LIVE));
            }
            ModOp::RollbackExtents {
                generation,
                extents,
                ..
            } => {
                let stash = st.remove(&(soid.clone(), *generation)).expect("stash");
                let live = st.get_mut(&(soid.clone(), LIVE)).unwrap();
                for (o, l) in extents {
                    let (a, b) = (*o as usize, (*o + *l) as usize);
                    if live.data.len() < b {
                        live.data.resize(b, 0);
                    }
                    live.data[a..b].copy_from_slice(&stash.data[a..b]);
                }
            }
            o => panic!("unexpected {o:?}"),
        }
    }
}

struct Cl {
    be: Backend,
    shards: Vec<Store>,
    model: BTreeMap<String, Vec<u8>>,
    ver: u64,
    /// shards that serve reads (degraded tests drop some)
    avail: Vec<u32>,
}

impl Cl {
    fn new(f: &EcFacts) -> Cl {
        let be = Backend::new(f).unwrap();
        let n = be.n();
        Cl {
            be,
            shards: vec![Store::new(); n],
            model: BTreeMap::new(),
            ver: 0,
            avail: (0..n as u32).collect(),
        }
    }

    fn read_stripe(&self, soid: &Hobject, stripe: u64) -> Vec<u8> {
        let be = &self.be;
        let raw: Vec<usize> = (0..be.k).collect();
        let plan = be.plan_read(stripe, stripe + 1, &raw, &self.avail).unwrap();
        let mut got = BTreeMap::new();
        for sh in &plan.shards {
            let d = &self.shards[*sh as usize][&(soid.clone(), LIVE)].data;
            let (a, l) = plan.shard_range(be.c);
            let (a, e) = (a as usize, (a + l) as usize);
            got.insert(*sh, d[a.min(d.len())..e.min(d.len())].to_vec());
        }
        be.assemble(&plan, &got, stripe * be.s, be.s).unwrap()
    }

    /// Apply a logical transaction; returns the per-object mod_desc and the pre-state for rollback tests.
    fn apply(&mut self, ops: &[L]) -> Result<(Vec<Store>, BTreeMap<Hobject, ObjectModDesc>), i32> {
        self.ver += 1;
        let txn = ltxn(ops);
        let names: Vec<&str> = ops
            .iter()
            .flat_map(|o| match o {
                L::Create(a) | L::Remove(a) | L::Trunc(a, _) => vec![*a],
                L::Write(a, ..) | L::Zero(a, ..) | L::Attr(a, ..) => vec![*a],
                L::Clone(a, b) => vec![*a, *b],
            })
            .collect();
        let mut olds = BTreeMap::new();
        let mut versions = BTreeMap::new();
        for n in names {
            let h = hobj(n);
            let exists = self.model.contains_key(n);
            let src = self
                .avail
                .iter()
                .find_map(|s| self.shards[*s as usize].get(&(h.clone(), LIVE)));
            olds.insert(
                h.clone(),
                OldObj {
                    exists,
                    size: self.model.get(n).map_or(0, |m| m.len() as u64),
                    attrs: if exists {
                        src.map(|o| o.attrs.clone()).unwrap_or_default()
                    } else {
                        Default::default()
                    },
                },
            );
            versions.insert(h, self.ver);
        }
        let plan = self.be.plan_write(PgT::new(1, 0), &txn, &olds, &versions)?;
        let mut old = BTreeMap::new();
        for (h, st) in plan.reads() {
            old.insert((h.clone(), st), self.read_stripe(&h, st));
        }
        let mds = plan.mod_descs();
        let posts = plan.post();
        let shared = plan.clone().generate_shared(&old)?;
        let gen_ = plan.generate(&old)?;
        check_shared(&shared, &gen_.txns);
        check_hints(&shared);
        let prev = self.shards.clone();
        for (sh, t) in gen_.txns.iter().enumerate() {
            apply_shard(&mut self.shards[sh], t);
        }
        // model
        for op in ops {
            match op {
                L::Create(n) => {
                    self.model.entry(n.to_string()).or_default();
                }
                L::Write(n, off, d) => {
                    let m = self.model.entry(n.to_string()).or_default();
                    let end = *off as usize + d.len();
                    if m.len() < end {
                        m.resize(end, 0);
                    }
                    m[*off as usize..end].copy_from_slice(d);
                }
                L::Zero(n, off, len) => {
                    if let Some(m) = self.model.get_mut(*n) {
                        let end = (*off + *len).min(m.len() as u64) as usize;
                        if (*off as usize) < end {
                            m[*off as usize..end].fill(0);
                        }
                    }
                }
                L::Trunc(n, s) => {
                    self.model
                        .entry(n.to_string())
                        .or_default()
                        .resize(*s as usize, 0);
                }
                L::Remove(n) => {
                    self.model.remove(*n);
                }
                L::Attr(n, ..) => {
                    self.model.entry(n.to_string()).or_default();
                }
                L::Clone(a, b) => {
                    let v = self.model[*a].clone();
                    self.model.insert(b.to_string(), v);
                }
            }
        }
        // the planned post state is what the shards really hold
        for (h, p) in &posts {
            let real = self.shards[0].get(&(h.clone(), LIVE));
            assert_eq!(p.exists, real.is_some(), "post exists {h:?}");
            if let Some(r) = real {
                assert_eq!(p.attrs, r.attrs, "post attrs {h:?}");
                let name = String::from_utf8(h.oid.to_vec()).unwrap();
                assert_eq!(p.size, self.model[&name].len() as u64, "post size {h:?}");
            }
        }
        Ok((prev, mds))
    }

    /// Shard files equal the encoding of the model, hinfo consistent, every k-subset reads the model.
    fn check(&self) {
        let be = &self.be;
        for (name, m) in &self.model {
            let h = hobj(name);
            let mut padded = m.clone();
            padded.resize(m.len().div_ceil(be.s as usize) * be.s as usize, 0);
            let want = be.encode_stripes(&padded);
            #[expect(clippy::needless_range_loop)]
            for sh in 0..be.n() {
                let o = &self.shards[sh][&(h.clone(), LIVE)];
                assert_eq!(o.data, want[sh], "{name} shard {sh} bytes");
                let hi = ec::HashInfo::decode(&o.attrs[ec::HINFO_KEY.as_bytes()]).unwrap();
                assert_eq!(
                    hi.total_chunk_size as usize,
                    o.data.len(),
                    "{name} hinfo total"
                );
                if hi.has_hashes() {
                    let mut f = ec::HashInfo::new(be.n());
                    let bufs: Vec<&[u8]> = (0..be.n())
                        .map(|s| &self.shards[s][&(h.clone(), LIVE)].data[..])
                        .collect();
                    f.append(0, &bufs).unwrap();
                    assert_eq!(f.hashes[sh], hi.hashes[sh], "{name} hinfo hash {sh}");
                }
            }
            // reads: every subset of k shards (non-MDS shec: every subset of >= k shards; the planner must refuse
            // exactly the patterns the recoverability predicate refuses)
            if !m.is_empty() {
                let n = be.n();
                let shec = matches!(*be.codec, ec::Code::Shec(_));
                let lrc = matches!(*be.codec, Code::Lrc(_));
                for mask in 0u32..(1 << n) {
                    let cnt = mask.count_ones() as usize;
                    if !lrc && cnt != be.k && !(shec && cnt > be.k) {
                        continue;
                    }
                    let avail: Vec<u32> = (0..n as u32).filter(|s| mask >> s & 1 == 1).collect();
                    let (off, len) = (0u64, m.len() as u64);
                    let (s0, s1) = (off / be.s, (off + len).div_ceil(be.s));
                    let want = be.raw_chunks_of(off, len).unwrap();
                    let plan = be.plan_read(s0, s1, &want, &avail);
                    if let ec::Code::Shec(sc) = &*be.codec {
                        let raw: Vec<usize> = avail.iter().map(|s| *s as usize).collect();
                        if want.len() == be.k {
                            assert_eq!(plan.is_ok(), sc.recoverable(&raw), "{name} {avail:?}");
                        }
                        if plan.is_err() {
                            continue;
                        }
                    }
                    if lrc {
                        let ok = lrc_423_recoverable(
                            mask,
                            want.iter().fold(0, |a, r| a | 1 << be.mapping[*r]),
                        );
                        if !ok {
                            assert!(plan.is_err(), "{name} {avail:?} planned but unrecoverable");
                            continue;
                        }
                    }
                    let plan = plan.unwrap_or_else(|e| panic!("{name} {avail:?}: plan error {e}"));
                    let (a, l) = plan.shard_range(be.c);
                    let got: BTreeMap<u32, Vec<u8>> = plan
                        .shards
                        .iter()
                        .map(|sh| {
                            let d = &self.shards[*sh as usize][&(h.clone(), LIVE)].data;
                            (*sh, d[a as usize..(a + l) as usize].to_vec())
                        })
                        .collect();
                    assert_eq!(
                        &be.assemble(&plan, &got, off, len).unwrap(),
                        m,
                        "{name} {avail:?}"
                    );
                    // client read shape: shared reply buffers, crc fused into the interleave
                    let shared: BTreeMap<u32, bytes::Bytes> = got
                        .iter()
                        .map(|(s, v)| (*s, bytes::Bytes::copy_from_slice(v)))
                        .collect();
                    let (d, c) = be.assemble_crc(&plan, &shared, off, len, true).unwrap();
                    assert_eq!(&d, m, "{name} {avail:?} (crc variant)");
                    assert_eq!(c, Some(crc::crc32c(!0, m)), "{name} {avail:?} fused crc");
                }
            }
        }
        // no stray live objects
        for st in &self.shards {
            for (h, g) in st.keys() {
                if *g == LIVE {
                    assert!(
                        self.model
                            .contains_key(&String::from_utf8(h.oid.to_vec()).unwrap())
                    );
                }
            }
        }
    }

    /// Roll the last op back on every shard and compare with the pre-state.
    fn check_rollback(&self, prev: &[Store], g: &BTreeMap<Hobject, ObjectModDesc>) {
        #[expect(clippy::needless_range_loop)]
        for sh in 0..self.be.n() {
            let mut st = self.shards[sh].clone();
            for (soid, md) in g {
                rollback(&self.be, &mut st, soid, md);
            }
            assert_eq!(st, prev[sh], "rollback restores shard {sh}");
        }
    }

    fn step(&mut self, ops: &[L]) {
        let (prev, g) = self
            .apply(ops)
            .unwrap_or_else(|e| panic!("{ops:?}: errno {e}"));
        self.check();
        self.check_rollback(&prev, &g);
    }
}

fn pat(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
        .collect()
}

#[test]
fn l0_append_and_writefull() {
    let f = facts(2, 1, 64, false, "isa", "reed_sol_van");
    assert_eq!(f.mode, EcMode::L0);
    let mut c = Cl::new(&f);
    c.step(&[
        L::Create("a"),
        L::Write("a", 0, pat(256, 1)),
        L::Attr("a", "_", vec![1, 2]),
    ]);
    // append at the aligned end
    c.step(&[L::Write("a", 256, pat(100, 2))]);
    // end is no longer stripe aligned: append refused, nothing changed
    assert_eq!(
        c.apply(&[L::Write("a", 356, pat(10, 3))]).err(),
        Some(EOPNOTSUPP)
    );
    // overwrite / zero / shrink refused
    assert_eq!(
        c.apply(&[L::Write("a", 0, pat(10, 3))]).err(),
        Some(EOPNOTSUPP)
    );
    assert_eq!(c.apply(&[L::Zero("a", 0, 10)]).err(), Some(EOPNOTSUPP));
    assert_eq!(c.apply(&[L::Trunc("a", 100)]).err(), Some(EOPNOTSUPP));
    c.check();
    // WRITEFULL = truncate(0) + write replaces the object and keeps its attrs
    c.step(&[L::Trunc("a", 0), L::Write("a", 0, pat(300, 9))]);
    assert_eq!(
        c.shards[0][&(hobj("a"), LIVE)].attrs[b"_".as_slice()],
        vec![1, 2]
    );
    // delete + create in one transaction
    c.step(&[L::Remove("a"), L::Create("a"), L::Write("a", 0, pat(50, 4))]);
    c.step(&[L::Remove("a")]);
    assert!(c.model.is_empty());
}

#[test]
fn l1_overwrite_rmw_all_shapes() {
    for (k, m, chunk) in [(2, 1, 32), (2, 2, 64), (3, 2, 32), (4, 2, 32)] {
        for (plugin, tech) in [
            ("isa", "reed_sol_van"),
            ("isa", "cauchy"),
            ("jerasure", "reed_sol_van"),
        ] {
            let f = facts(k, m, chunk, true, plugin, tech);
            let mut c = Cl::new(&f);
            let s = (k * chunk) as u64;
            c.step(&[
                L::Create("o"),
                L::Write("o", 0, pat((s * 3 + 5) as usize, 1)),
            ]);
            // partial head + tail inside the old extent
            c.step(&[L::Write("o", s / 2, pat((s * 2) as usize, 2))]);
            // overwrite within one chunk
            c.step(&[L::Write("o", 3, pat(7, 3))]);
            // zero a middle range
            c.step(&[L::Zero("o", s - 4, 9)]);
            // zero past the end is clamped
            c.step(&[L::Zero("o", s * 3, 100)]);
            // append across a stripe boundary
            let sz = c.model["o"].len() as u64;
            c.step(&[L::Write("o", sz, pat((s + 3) as usize, 4))]);
            // sparse write with a gap
            let sz = c.model["o"].len() as u64;
            c.step(&[L::Write("o", sz + s * 2 + 1, pat(9, 5))]);
            // shrink to an unaligned size, then grow by truncate
            c.step(&[L::Trunc("o", s + 3)]);
            c.step(&[L::Trunc("o", s * 2 + 10)]);
            // shrink to an aligned size
            c.step(&[L::Trunc("o", s)]);
            // truncate and write in one transaction
            c.step(&[
                L::Trunc("o", s / 3),
                L::Write("o", s / 3, pat((s * 2) as usize, 6)),
            ]);
            // write then truncate below it
            c.step(&[L::Write("o", s, pat(40, 7)), L::Trunc("o", s + 5)]);
            // clone then modify the head
            c.step(&[
                L::Clone("o", "o.clone"),
                L::Write("o", 1, pat(5, 8)),
                L::Attr("o.clone", "_", vec![9]),
            ]);
            // delete the clone, recreate the head from scratch
            c.step(&[L::Remove("o.clone")]);
            c.step(&[L::Trunc("o", 0), L::Write("o", 0, pat(77, 9))]);
            c.step(&[L::Remove("o")]);
        }
    }
}

/// Delete with snapshots = clone, remove the head, recreate it as a whiteout; then the head is written again.
#[test]
fn clone_then_whiteout_delete_keeps_the_clone() {
    for ow in [false, true] {
        let f = facts(2, 1, 32, ow, "isa", "reed_sol_van");
        let mut c = Cl::new(&f);
        let s = c.be.s as usize;
        c.step(&[
            L::Create("o"),
            L::Write("o", 0, pat(s * 2 + 7, 1)),
            L::Attr("o", "_", vec![1]),
        ]);
        let before = c.model["o"].clone();
        c.step(&[
            L::Clone("o", "o.c"),
            L::Remove("o"),
            L::Create("o"),
            L::Attr("o", "_", vec![2]),
            L::Attr("o.c", "_", vec![3]),
        ]);
        assert_eq!(c.model["o.c"], before, "clone keeps the old bytes");
        assert!(c.model["o"].is_empty());
        // WRITEFULL of the whiteout head
        c.step(&[L::Trunc("o", 0), L::Write("o", 0, pat(s + 3, 9))]);
        assert_eq!(c.model["o.c"], before);
        c.check();
    }
}

#[test]
fn degraded_rmw_reads_decode() {
    let f = facts(3, 2, 32, true, "isa", "reed_sol_van");
    for dead in 0..5u32 {
        let mut c = Cl::new(&f);
        c.step(&[L::Create("o"), L::Write("o", 0, pat(500, 1))]);
        c.avail.retain(|s| *s != dead);
        c.step(&[L::Write("o", 10, pat(200, 2))]);
        c.step(&[L::Write("o", 450, pat(100, 3))]);
        c.avail.retain(|s| *s != (dead + 1) % 5);
        c.step(&[L::Trunc("o", 130)]);
    }
}

#[test]
fn random_ops_lrc() {
    random_ops(facts_lrc(32, true));
}

/// lrc degraded reads: any single dead shard (local repair reads fewer than k.. more than k shards), two dead, then
/// planner and assembly agree with the independent single-pass oracle.
#[test]
fn lrc_degraded_reads_and_planner() {
    let mut c = Cl::new(&facts_lrc(32, true));
    c.step(&[L::Create("o"), L::Write("o", 0, pat(300, 1))]);
    for dead in 0..8u32 {
        c.avail = (0..8u32).filter(|s| *s != dead).collect();
        let plan =
            c.be.plan_read(0, 3, &c.be.raw_chunks_of(0, 300).unwrap(), &c.avail)
                .unwrap();
        // a lost data shard is rebuilt from its local group: l = 3 reads + the other group's wanted data
        assert!(plan.shards.len() <= 5, "{dead}: {:?}", plan.shards);
        c.step(&[L::Write("o", 5, pat(100, 2))]);
    }
    c.avail = (0..8u32).collect();
    c.check();
}

#[test]
fn random_ops_stay_consistent() {
    random_ops(facts(3, 2, 32, true, "isa", "reed_sol_van"));
}

/// Same model run on the jerasure bit-matrix codes (packet XOR, decode by GF(2) elimination).
#[test]
fn random_ops_bit_matrix_codes() {
    for (tech, extra) in [
        ("cauchy_good", vec![("packetsize", "4")]),
        ("cauchy_orig", vec![("packetsize", "4")]),
        ("liber8tion", vec![("packetsize", "4")]),
        ("liberation", vec![("packetsize", "4"), ("w", "7")]),
        ("blaum_roth", vec![("packetsize", "4"), ("w", "6")]),
    ] {
        let chunk = if tech == "liberation" {
            224
        } else if tech == "blaum_roth" {
            96
        } else {
            32
        };
        random_ops(facts_with(3, 2, chunk, true, "jerasure", tech, &extra));
    }
}

/// Same model on the non-MDS shec code (multiple + single): reads for every shard subset, one dead shard per step.
#[test]
fn random_ops_shec() {
    for tech in ["multiple", "single"] {
        random_ops(facts_with(4, 3, 32, true, "shec", tech, &[("c", "2")]));
    }
}

/// EC parity step 1 (spec ec-parity.md 5.1, 7): chunks that are not multiples of 32 (liberation w=7 ps=4 unit 28,
/// isa unit 1) and shec k = 1 through writes, RMW, degraded reads and hinfo.
#[test]
fn random_ops_odd_chunks_and_shec_k1() {
    let lib = [("packetsize", "4"), ("w", "7")];
    random_ops(facts_with(2, 2, 140, true, "jerasure", "liberation", &lib));
    random_ops(facts(3, 2, 100, true, "isa", "reed_sol_van"));
    random_ops(facts_with(
        1,
        1,
        96,
        true,
        "shec",
        "multiple",
        &[("c", "1")],
    ));
}

fn random_ops(f: EcFacts) {
    let mut x = 0x9E37_79B9u32;
    let mut rnd = move |n: u32| {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x % n
    };
    let mut c = Cl::new(&f);
    let names = ["a", "b", "c"];
    for i in 0..300 {
        let n = names[rnd(3) as usize];
        let sz = c.model.get(n).map_or(0, |m| m.len() as u64);
        let ops = match rnd(8) {
            0 | 1 => vec![L::Write(
                n,
                rnd(300) as u64,
                pat(rnd(200) as usize + 1, i as u8),
            )],
            2 => vec![L::Write(n, sz, pat(rnd(150) as usize + 1, i as u8))],
            3 => vec![L::Trunc(n, rnd(400) as u64)],
            4 => vec![L::Zero(n, rnd(300) as u64, rnd(120) as u64 + 1)],
            5 if c.model.contains_key(n) => vec![L::Remove(n)],
            6 => vec![L::Attr(n, "x", vec![i as u8])],
            _ => vec![
                L::Create(n),
                L::Write(n, 0, pat(rnd(300) as usize, i as u8)),
            ],
        };
        // dead shard of the moment
        let n = c.be.n() as u32;
        let dead = rnd(n + 1);
        c.avail = (0..n).filter(|s| *s != dead).collect();
        c.step(&ops);
    }
}

/// Writes planned back to back (the first still in flight) use the projected state; generating and applying them in
/// order gives the same shards as applying them one at a time.
#[test]
fn pipelined_plans_use_projected_state() {
    for ow in [false, true] {
        let f = facts(2, 1, 32, ow, "isa", "reed_sol_van");
        let mut c = Cl::new(&f);
        c.step(&[L::Create("o"), L::Write("o", 0, pat(64, 1))]);
        let s = c.be.s as usize; // 64
        let h = hobj("o");
        let pg = PgT::new(1, 0);
        let ops1 = [
            L::Write("o", s as u64, pat(s, 2)),
            L::Attr("o", "x", vec![1]),
        ];
        let ops2 = [L::Write("o", 2 * s as u64, pat(s + 5, 3))];
        let olds1: BTreeMap<_, _> = [(
            h.clone(),
            OldObj {
                exists: true,
                size: s as u64,
                attrs: c.shards[0][&(h.clone(), LIVE)].attrs.clone(),
            },
        )]
        .into();
        let vs = |v| [(h.clone(), v)].into();
        let p1 = c.be.plan_write(pg, &ltxn(&ops1), &olds1, &vs(10)).unwrap();
        let olds2: BTreeMap<_, _> = p1.post().into_iter().map(|(k, v)| (k, v.into())).collect();
        let p2 = c.be.plan_write(pg, &ltxn(&ops2), &olds2, &vs(11)).unwrap();
        assert!(p1.reads().is_empty() && p2.reads().is_empty());
        for p in [p1, p2] {
            let g = p.generate(&BTreeMap::new()).unwrap();
            for (sh, t) in g.txns.iter().enumerate() {
                apply_shard(&mut c.shards[sh], t);
            }
        }
        let mut m = pat(64, 1);
        m.extend(pat(s, 2));
        m.extend(pat(s + 5, 3));
        c.model.insert("o".into(), m);
        c.check();
    }
}

/// Inconsistent pool facts are refused (None), never a panic later in encode/read.
#[test]
fn from_parts_rejects_bad_geometry() {
    let ok = |k: u32, m: u32, sw: u32, c: u32, map: Vec<u32>| {
        Backend::from_parts("isa", "reed_sol_van", (k, m), (sw, c), map, true).is_some()
    };
    assert!(ok(2, 1, 8192, 4096, vec![0, 1, 2]));
    assert!(ok(2, 1, 8192, 4096, vec![2, 0, 1]));
    // stripe_width != k * chunk
    assert!(!ok(2, 1, 4096, 4096, vec![0, 1, 2]));
    assert!(!ok(2, 1, 8192 + 32, 4096, vec![0, 1, 2]));
    // mapping not a permutation of 0..k+m
    assert!(!ok(2, 1, 8192, 4096, vec![0, 1, 1]));
    assert!(!ok(2, 1, 8192, 4096, vec![0, 1, 3]));
    assert!(!ok(2, 1, 8192, 4096, vec![0, 1]));
    assert!(!ok(2, 1, 8192, 4096, vec![0, 1, 2, 3]));
    // k / m / chunk bounds
    assert!(!ok(1, 1, 4096, 4096, vec![0, 1]));
    assert!(!ok(2, 0, 8192, 4096, vec![0, 1]));
    assert!(!ok(2, 1, 0, 0, vec![0, 1, 2]));
    let big: Vec<u32> = (0..300).collect();
    assert!(!ok(200, 100, 200 * 32, 32, big));
    // unknown technique
    assert!(
        Backend::from_parts(
            "jerasure",
            "cauchy_good",
            (2, 1),
            (8192, 4096),
            vec![0, 1, 2],
            true
        )
        .is_none()
    );
}

/// Snap rollback after a new snap (op layer shape): make_writeable clones the head first, then the head is replaced by
/// a copy of an older clone. The new clone must get the OLD head bytes (shard order = transaction order of the clones).
#[test]
fn rollback_after_new_snap_clones_the_old_head_first() {
    for ow in [false, true] {
        let f = facts(2, 1, 32, ow, "isa", "reed_sol_van");
        let mut c = Cl::new(&f);
        let s = c.be.s as usize;
        c.step(&[
            L::Create("o"),
            L::Write("o", 0, pat(s * 2, 1)),
            L::Attr("o", "_", vec![1]),
        ]);
        let v1 = c.model["o"].clone();
        c.step(&[L::Clone("o", "o.c1"), L::Attr("o.c1", "_", vec![2])]);
        c.step(&[L::Write("o", s as u64 * 2, pat(s, 2))]);
        let v2 = c.model["o"].clone();
        c.step(&[
            L::Clone("o", "o.c2"),
            L::Attr("o.c2", "_", vec![3]),
            L::Remove("o"),
            L::Clone("o.c1", "o"),
            L::Attr("o", "_", vec![4]),
        ]);
        assert_eq!(c.model["o.c2"], v2);
        assert_eq!(c.model["o"], v1);
        c.check();
    }
}

/// Op-layer shaped random history on one head with snapshots (L1, pool geometry of the live failures, k4m2 4 KiB):
/// writes at random offsets, truncates, attr-only updates, each optionally after a new snap (make_writeable clone
/// first), rollbacks to an older clone (clone the head away, remove it, clone the old clone back), clone removal
/// (snap trim), delete + recreate. Every step: shards == encoding of the model, rollback from mod_desc restores.
#[test]
fn snapshot_history_with_rollbacks_stays_consistent() {
    let f = facts(4, 2, 4096, true, "isa", "reed_sol_van");
    let mut x = 0x2545_F491u32;
    let mut rnd = move |n: u32| {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x % n
    };
    const CLONES: [&str; 8] = [
        "h.c0", "h.c1", "h.c2", "h.c3", "h.c4", "h.c5", "h.c6", "h.c7",
    ];
    let mut c = Cl::new(&f);
    c.step(&[L::Create("h"), L::Write("h", 0, pat(300_000, 1))]);
    for i in 0..120u32 {
        let head = c.model.contains_key("h");
        let live: Vec<&'static str> = CLONES
            .iter()
            .copied()
            .filter(|n| c.model.contains_key(*n))
            .collect();
        let mut ops: Vec<L> = Vec::new();
        // a new snap since the last write: clone the head first
        let free = CLONES.iter().copied().find(|n| !c.model.contains_key(*n));
        if head
            && rnd(3) == 0
            && let Some(cl) = free
        {
            ops.push(L::Clone("h", cl));
            ops.push(L::Attr(cl, "_", vec![i as u8]));
        }
        match rnd(7) {
            0 | 1 => {
                for _ in 0..1 + rnd(3) {
                    let off = rnd(900_000) as u64;
                    ops.push(L::Write("h", off, pat(1 + rnd(200_000) as usize, i as u8)));
                }
                ops.push(L::Trunc("h", rnd(1_000_000) as u64));
            }
            2 => {
                let sz = c.model.get("h").map_or(0, |m| m.len() as u64);
                ops.push(L::Write("h", sz, pat(1 + rnd(150_000) as usize, i as u8)));
            }
            3 if !live.is_empty() && head => {
                let from = live[rnd(live.len() as u32) as usize];
                ops.push(L::Remove("h"));
                ops.push(L::Clone(from, "h"));
            }
            4 | 6 if !live.is_empty() => {
                // snap trim of a clone: its own transaction
                if ops.is_empty() {
                    ops.push(L::Remove(live[rnd(live.len() as u32) as usize]));
                }
            }
            5 if head && rnd(4) == 0 => ops.push(L::Remove("h")),
            _ => {}
        }
        if !ops.iter().any(|o| matches!(o, L::Remove("h"))) || ops.len() > 1 {
            ops.push(L::Attr("h", "_", vec![i as u8, 1]));
        }
        if !c.model.contains_key("h") && !ops.iter().any(|o| matches!(o, L::Clone(_, "h"))) {
            ops.insert(0, L::Create("h"));
        }
        c.step(&ops);
    }
}

/// Same model on clay (spec ec-clay.md): (2,2,3) S=4 and the nu=1 profile (3,2,4) S=8, sub-chunk size 64 (primary
/// rule 0.6); per-stripe codewords through multi-stripe spans.
#[test]
fn random_ops_clay() {
    for (k, d, chunk) in [(2, "3", 256), (3, "4", 512)] {
        random_ops(facts_with(k, 2, chunk, true, "clay", "", &[("d", d)]));
        random_ops(facts_with(
            k,
            2,
            chunk,
            true,
            "clay",
            "",
            &[("d", d), ("scalar_mds", "isa")],
        ));
        random_ops(facts_with(
            k,
            2,
            chunk,
            true,
            "clay",
            "",
            &[("d", d), ("scalar_mds", "shec")],
        ));
    }
}

/// clay primary role only for MDS scalars (spec ec-clay.md 0.6); sub-chunk size % 64 == 32 is primary-capable.
#[test]
fn clay_primary_restriction() {
    let f = facts_with(2, 2, 256, true, "clay", "", &[("d", "3")]);
    assert!(f.primary_ok && Backend::new(&f).is_some());
    // sc = 32 (classic <= 21.1.x wrote wrong parity, fixed in 21.2.0): primary like classic 21.2.0
    let f = facts_with(2, 2, 128, true, "clay", "", &[("d", "3")]);
    assert!(f.primary_ok && Backend::new(&f).is_some());
    // scalar shec: MDS (= reed_sol_van) for m == 2, not for m >= 3 (shard only)
    let f = facts_with(4, 2, 4096, true, "clay", "", &[("scalar_mds", "shec")]);
    assert!(f.primary_ok && Backend::new(&f).is_some());
    let f = facts_with(4, 3, 6912, true, "clay", "", &[("scalar_mds", "shec")]);
    assert!(!f.primary_ok && Backend::new(&f).is_none());
}

/// clay (3,2,4) at the lab pool geometry (chunk 4096, sub-chunk 512): multi-chunk, multi-stripe objects read from
/// every k-subset (regression: live degraded read by an croit-flashstore-osd primary differed).
#[test]
fn clay_lab_geometry_big_objects() {
    let f = facts_with(3, 2, 4096, false, "clay", "", &[("d", "4")]);
    // the whole chunk on the wire is (0, S): a (0, 1) read makes a classic shard return only sub-chunk 0 of each stripe
    assert_eq!(Backend::new(&f).unwrap().sub_chunks(), 8);
    let mut c = Cl::new(&f);
    c.step(&[L::Create("o"), L::Write("o", 0, pat(8191, 1))]);
    c.step(&[L::Create("p"), L::Write("p", 0, pat(100_003, 2))]);
}

/// clay single-shard repair from sub-chunks (spec ec-clay.md 6): every lost shard, all others up or one more down
/// (aloof), multi-stripe; helpers send d * C / q bytes per stripe instead of k * C.
#[test]
fn clay_repair_plan_rebuilds_every_shard() {
    for (k, m, d, chunk) in [(2, 2, "3", 256), (3, 2, "4", 512), (4, 3, "5", 1024)] {
        let f = facts_with(k, m, chunk, false, "clay", "", &[("d", d)]);
        let be = Backend::new(&f).unwrap();
        let data = pat(be.s as usize * 3, 7);
        let shards = be.encode_stripes(&data);
        let n = be.n() as u32;
        for lost in 0..n {
            for down in std::iter::once(None).chain((0..n).filter(|x| *x != lost).map(Some)) {
                let avail: Vec<u32> = (0..n).filter(|s| *s != lost && Some(*s) != down).collect();
                let Some(plan) = be.plan_repair(0, 3, lost, &avail) else {
                    continue;
                };
                let spec = plan.repair.clone().unwrap();
                let got: BTreeMap<u32, Vec<u8>> = plan
                    .shards
                    .iter()
                    .map(|s| (*s, be.gather_sub(&shards[*s as usize], &spec.ranges)))
                    .collect();
                let q_bytes: usize = got.values().map(|v| v.len()).sum();
                assert!(
                    q_bytes < plan.shards.len() * 3 * be.c as usize,
                    "{k},{m} lost {lost}"
                );
                assert_eq!(
                    be.repair_shard(&plan, &got).unwrap(),
                    shards[lost as usize],
                    "({k},{m},{d}) lost {lost} down {down:?}"
                );
                // a short reply is refused, not decoded
                let mut bad = got.clone();
                bad.values_mut().next().unwrap().pop();
                assert_eq!(be.repair_shard(&plan, &bad), Err(EIO));
            }
        }
        // no repair path off clay
        let rs = Backend::new(&facts_with(2, 1, 64, false, "isa", "reed_sol_van", &[])).unwrap();
        assert!(rs.plan_repair(0, 1, 0, &[1, 2]).is_none());
    }
}

/// `encode_stripes_crc` = `encode_stripes` plus the per-4K block crcs of every shard buffer, for chunk sizes below, at and
/// above the 4K grid (blocks straddle chunks when C is not a multiple of 4096) and odd stripe counts.
#[test]
fn encode_stripes_crc_block_crcs_match_a_pass_over_every_shard() {
    for (k, m, chunk) in [
        (2u32, 1u32, 64u32),
        (2, 1, 4096),
        (3, 2, 4096),
        (2, 1, 6144),
        (4, 2, 8192),
    ] {
        let be = Backend::new(&facts_with(k, m, chunk, false, "isa", "reed_sol_van", &[])).unwrap();
        for ns in [0usize, 1, 3, 17, 64] {
            let data: Vec<u8> = (0..ns * (k * chunk) as usize)
                .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
                .collect();
            let (bufs, blocks) = be.encode_stripes_crc(&data);
            assert_eq!(bufs, be.encode_stripes(&data), "k{k} m{m} c{chunk} ns{ns}");
            for (sh, (b, bc)) in bufs.iter().zip(&blocks).enumerate() {
                let want: Vec<u32> = b
                    .as_chunks::<4096>()
                    .0
                    .iter()
                    .map(|x| crc::crc32c(0, x))
                    .collect();
                assert_eq!(bc.blocks(), &want[..], "shard {sh} k{k} c{chunk} ns{ns}");
                assert_eq!(bc.crc(0), crc::crc32c(0, b), "shard {sh}: hinfo crc");
                assert_eq!(bc.crc(!0), crc::crc32c(!0, b), "shard {sh}: msgr2 crc");
            }
        }
    }
}

/// EC parity step 3 (spec ec-parity.md 3.4): legacy isa k=2 m=1 mapping `_DD` (M' = [1, 2, 0]) stores the classic
/// literal index sequence: client chunk 0 on shard 1, shard 0 = the unassigned input slot (zeros here), shard 2 =
/// parity (overwrites client chunk 1). Re-encoding what a read returns (recovery) gives the same shards; an optimized
/// pool keeps plain placement.
#[test]
fn literal_placement_isa_mapping() {
    let f = facts_with(
        2,
        1,
        64,
        false,
        "isa",
        "reed_sol_van",
        &[("mapping", "_DD")],
    );
    assert_eq!(f.chunk_mapping, [1, 2, 0]);
    let b = Backend::new(&f).unwrap();
    assert!(b.codec.rewrites_data());
    let data = pat(2 * 128, 7);
    let sh = b.encode_stripes(&data);
    let (s, c) = (128usize, 64usize);
    for st in 0..2 {
        let d0 = &data[st * s..st * s + c];
        assert_eq!(&sh[1][st * c..(st + 1) * c], d0);
        assert!(sh[0][st * c..(st + 1) * c].iter().all(|x| *x == 0));
        // isa row 0 is XOR: parity = zeros ^ d0
        assert_eq!(&sh[2][st * c..(st + 1) * c], d0);
    }
    let (sh2, crcs) = b.encode_stripes_crc(&data);
    assert_eq!(sh2, sh);
    for (v, cr) in sh.iter().zip(&crcs) {
        assert_eq!(cr.crc(0), crc::crc32c(0, v));
    }
    // a read returns shard M'[r] as client chunk r; re-encoding it reproduces every shard
    let logical: Vec<u8> = (0..2)
        .flat_map(|st| [&sh[1][st * c..(st + 1) * c], &sh[2][st * c..(st + 1) * c]].concat())
        .collect();
    assert_eq!(b.encode_stripes(&logical), sh);
    let plain = Backend::from_profile(&f.profile, (128, 64), f.chunk_mapping.clone(), false)
        .unwrap()
        .literal_placement(false)
        .unwrap();
    assert!(!plain.codec.rewrites_data());
    assert_eq!(plain.encode_stripes(&data)[2][..c], data[c..2 * c]);
}

/// Degenerate ranges: `raw_chunks_of` says "none" for an empty range and `Err(EINVAL)` instead of wrapping past
/// `u64`, and `assemble` refuses the same range instead of returning a silently short buffer.
#[test]
fn empty_and_overflowing_ranges_are_refused() {
    let f = facts(2, 1, 32, true, "isa", "reed_sol_van");
    let be = Backend::new(&f).unwrap();
    assert_eq!(be.raw_chunks_of(0, 0), Ok(Vec::new()));
    assert_eq!(be.raw_chunks_of(u64::MAX - 1, 4), Err(EINVAL));
    assert_eq!(be.raw_chunks_of(5, u64::MAX), Err(EINVAL));
    assert_eq!(be.raw_chunks_of(0, 1), Ok(vec![0]));
    let avail: Vec<u32> = (0..be.n() as u32).collect();
    let raw: Vec<usize> = (0..be.k).collect();
    let plan = be.plan_read(0, 1, &raw, &avail).unwrap();
    let got: BTreeMap<u32, Vec<u8>> = plan
        .shards
        .iter()
        .map(|sh| (*sh, vec![7u8; be.c as usize]))
        .collect();
    assert_eq!(be.assemble(&plan, &got, u64::MAX - 1, 4), Err(EINVAL));
}

/// `plan_read` bounds-checks every wanted raw chunk: an index the pool does not have is `EINVAL`, not a panic.
#[test]
fn plan_read_refuses_an_unknown_raw_chunk() {
    let f = facts(2, 1, 32, true, "isa", "reed_sol_van");
    let be = Backend::new(&f).unwrap();
    let avail: Vec<u32> = (0..be.n() as u32).collect();
    assert!(be.plan_read(0, 1, &[0], &avail).is_ok());
    assert_eq!(be.plan_read(0, 1, &[be.n()], &avail).err(), Some(EINVAL));
    assert_eq!(
        be.plan_read(0, 1, &[usize::MAX], &avail).err(),
        Some(EINVAL)
    );
}

/// A logical size that does not fit a shard size is `EINVAL`, not a wrapped size that would drive truncate limits
/// (shec k=1: S == C, the only geometry where the multiply can overflow).
#[test]
fn shard_size_of_an_impossible_object_is_an_error() {
    let prof: BTreeMap<String, String> = [
        ("plugin", "shec"),
        ("technique", "single"),
        ("k", "1"),
        ("m", "1"),
        ("c", "1"),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_string(), b.to_string()))
    .collect();
    let be = Backend::from_profile(&prof, (1024, 1024), (0..2).collect(), true).unwrap();
    assert_eq!(be.shard_size(4096), Ok(4096));
    assert_eq!(be.shard_size(u64::MAX - 1), Err(EINVAL));
}

/// A permuted chunk mapping keeps its codec when the `Backend` is shared: the placement is rebuilt from a clone, not
/// from an exclusive `Arc` unwrap (which would silently drop a supported pool).
#[test]
fn literal_placement_of_a_shared_backend() {
    let be = Backend::from_parts(
        "isa",
        "reed_sol_van",
        (2, 1),
        (128, 64),
        vec![1, 0, 2],
        true,
    )
    .unwrap();
    let _shared = be.clone();
    assert!(be.literal_placement(true).is_some());
}

/// Truncate-up past 64 MiB is a classic-legal op (only `osd_max_object_size` bounds objects, in the op layer): the
/// generator plans the zero stripes of spec ec.md 11.1 step 1 and every shard holds them up to the formula size.
#[test]
fn truncate_up_writes_zero_stripes_past_64_mib() {
    let f = facts(2, 1, 4096, true, "isa", "reed_sol_van");
    let be = Backend::new(&f).unwrap();
    let s = be.s;
    let size = (64 << 20) + s;
    let h = hobj("grow");
    let txn = ltxn(&[L::Create("grow"), L::Trunc("grow", size)]);
    let olds = BTreeMap::from([(h.clone(), OldObj::default())]);
    let versions = BTreeMap::from([(h.clone(), 1)]);
    let plan = be
        .plan_write(PgT::new(1, 0), &txn, &olds, &versions)
        .unwrap();
    assert!(
        plan.reads().is_empty(),
        "an extending truncate reads nothing"
    );
    let gen_ = plan.generate(&BTreeMap::new()).unwrap();
    let mut shards: Vec<Store> = vec![Store::new(); be.n()];
    for (sh, t) in gen_.txns.iter().enumerate() {
        apply_shard(&mut shards[sh], t);
    }
    let shard_len = be.shard_size(size).unwrap();
    for (sh, st) in shards.iter().enumerate() {
        assert_eq!(
            st[&(h.clone(), LIVE)].data.len() as u64,
            shard_len,
            "shard {sh} size"
        );
    }
    // the last stripe reads back as zeros from the shards
    let last = size / s - 1;
    let raw: Vec<usize> = (0..be.k).collect();
    let avail: Vec<u32> = (0..be.n() as u32).collect();
    let plan = be.plan_read(last, last + 1, &raw, &avail).unwrap();
    let (a, l) = plan.shard_range(be.c);
    let got: BTreeMap<u32, Vec<u8>> = plan
        .shards
        .iter()
        .map(|sh| {
            let d = &shards[*sh as usize][&(h.clone(), LIVE)].data;
            (*sh, d[a as usize..(a + l) as usize].to_vec())
        })
        .collect();
    assert_eq!(
        be.assemble(&plan, &got, last * s, s).unwrap(),
        vec![0u8; s as usize]
    );
}

/// Reducing the new size must not bypass the size ceiling on the old object metadata.
fn check_truncate_old_size_limit(optimized: bool) {
    let be = Arc::new(Backend::new(&facts(2, 1, 4096, true, "isa", "reed_sol_van")).unwrap());
    let h = hobj("bad-size");
    let txn = ltxn(&[L::Trunc("bad-size", 100)]);
    let versions = BTreeMap::from([(h.clone(), 2)]);
    for size in [u64::MAX, MAX_OBJECT_SIZE + 1] {
        let olds = BTreeMap::from([(
            h.clone(),
            OldObj {
                exists: true,
                size,
                attrs: BTreeMap::from([(
                    ec::HINFO_KEY.as_bytes().to_vec(),
                    ec::HashInfo::new(be.n()).encode(),
                )]),
            },
        )]);
        let err = if optimized {
            be.plan_write_o(
                PgT::new(1, 0),
                &txn,
                &olds,
                &versions,
                OCtx {
                    members: &[0, 1, 2],
                    first_write: false,
                },
            )
            .err()
        } else {
            be.plan_write(PgT::new(1, 0), &txn, &olds, &versions).err()
        };
        assert_eq!(err, Some(EFBIG), "optimized={optimized} old size {size}");
    }
}

#[test]
fn legacy_truncate_rejects_impossible_old_size() {
    check_truncate_old_size_limit(false);
}

#[test]
fn optimized_truncate_rejects_impossible_old_size() {
    check_truncate_old_size_limit(true);
}
