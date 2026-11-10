// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optimized-EC generator model tests (ec-optimized.md 15 invariants 1-5): generated shard transactions applied
//! to byte-vector shard stores, compared with a plain logical model after every op; every op rolled back by an
//! independent mini shard executor (spec 6.2 + wgen 3.2) on a copy; every k-subset decodes the model; shard sizes
//! follow the formula; parity = encode(data); written_shards == shards with work; NP shards hold the version the
//! primary's `shard_versions` says.

use super::*;
use denc::types::{CollT, Eversion, Ghobject, Hobject, PgT, ShardId, SnapId};
use ec::moddesc::{ModOp, parse, shard_set_contains as raw_contains, shard_set_is_empty};
use pgwire::ObjectModDesc;
use pgwire::log::ShardIdSet;
use replwire::oi::ObjectInfo;
use replwire::txn::{Data, Transaction, TxnOp};
use std::collections::BTreeMap;
use std::sync::Arc;

const LIVE: u64 = u64::MAX;

fn be(k: u32, m: u32, c: u32, plugin: &str, tech: &str) -> Backend {
    Backend::from_parts(plugin, tech, (k, m), (k * c, c), (0..k + m).collect(), true).unwrap()
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
    Write(u64, Vec<u8>),
    Zero(u64, u64),
    Trunc(u64),
    Remove,
    Create,
    Attr(&'static str, Vec<u8>),
    RmAttr(&'static str),
    /// WRITEFULL as the op layer emits it for EC: truncate 0 + write.
    Full(Vec<u8>),
    /// Snapshot clone of the head into `name`, then nothing else on the clone.
    CloneTo(&'static str),
    Hint,
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
                let o = st.get_mut(&key(*oid)).expect("write to absent object");
                assert_eq!(off % 4096, 0, "unaligned shard write");
                assert_eq!(data.len() % 4096, 0, "unaligned shard write length");
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
                    .expect("truncate of absent")
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
                // past the source end reads zeros, the destination grows (BlueStore semantics, wgen U-W7)
                let src = st.get(&key(*oid)).expect("clone_range of absent").clone();
                let d = st.entry(key(*dest_oid)).or_default();
                let end = (*dest_off + *len) as usize;
                if d.data.len() < end {
                    d.data.resize(end, 0);
                }
                for i in 0..*len as usize {
                    d.data[*dest_off as usize + i] =
                        src.data.get(*src_off as usize + i).copied().unwrap_or(0);
                }
            }
            TxnOp::CollMoveRename { oid, dest_oid, .. } => {
                let o = st.remove(&key(*oid)).expect("rename of absent");
                st.insert(key(*dest_oid), o);
            }
            // advisory, no stored state
            TxnOp::SetAllocHint { .. } => {}
            o => panic!("unexpected shard op {o:?}"),
        }
    }
}

fn is_np(b: &Backend, shard: u32) -> bool {
    let r = b.mapping.iter().position(|s| *s == shard).unwrap();
    r >= 1 && r < b.k
}

fn written_has(w: &ShardIdSet, shard: u32) -> bool {
    w.is_empty() || crate::shard_set_contains(w, shard)
}

/// Independent mini shard executor: undo `md` of an entry with `written` on shard `me`.
fn rollback(
    b: &Backend,
    me: u32,
    st: &mut Store,
    soid: &Hobject,
    md: &ObjectModDesc,
    written: &ShardIdSet,
) {
    if !written_has(written, me) {
        return;
    }
    let raw = b.mapping.iter().position(|s| *s == me).unwrap();
    let g = Geo {
        k: b.k as u64,
        c: b.c,
    };
    let np = is_np(b, me);
    for op in parse(&md.bl).unwrap().iter().rev() {
        match op {
            ModOp::Append { old_size } => {
                if let Some(o) = st.get_mut(&(soid.clone(), LIVE)) {
                    o.data.resize(g.shard_size(*old_size, raw) as usize, 0);
                }
            }
            ModOp::SetAttrs(a) => {
                let o = st.get_mut(&(soid.clone(), LIVE)).unwrap();
                for (k, v) in a {
                    if np && k.as_slice() != b"_" {
                        continue;
                    }
                    match v {
                        Some(v) if np => {
                            let mut oi: ObjectInfo = denc::from_slice(v).unwrap();
                            if let Some(sv) = oi.shard_versions.get(&ShardId(me as i8)).copied()
                                && sv != oi.version
                            {
                                oi.version = sv;
                                oi.shard_versions.clear();
                            }
                            o.attrs.insert(k.clone(), denc::to_vec(&oi).unwrap());
                        }
                        Some(v) => {
                            o.attrs.insert(k.clone(), v.clone());
                        }
                        None => {
                            o.attrs.remove(k);
                        }
                    }
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
                object_size,
                shards,
            } => {
                let mine: Vec<(u64, u64)> = extents
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| {
                        shards.is_empty()
                            || shard_set_is_empty(&shards[*i])
                            || raw_contains(&shards[*i], me)
                    })
                    .map(|(_, e)| *e)
                    .collect();
                if mine.is_empty() {
                    continue;
                }
                let ss = g.shard_size(object_size.unwrap(), raw);
                let stash = st.remove(&(soid.clone(), *generation)).expect("stash");
                let live = st.get_mut(&(soid.clone(), LIVE)).unwrap();
                for (o, l) in mine {
                    if o >= ss {
                        continue;
                    }
                    let l = l.min(ss - o);
                    let (a, e) = (o as usize, (o + l) as usize);
                    if live.data.len() < e {
                        live.data.resize(e, 0);
                    }
                    for i in a..e {
                        live.data[i] = stash.data.get(i).copied().unwrap_or(0);
                    }
                }
            }
            o => panic!("unexpected {o:?}"),
        }
    }
}

/// Roll forward (stash cleanup) of an entry on shard `me`.
fn roll_forward(me: u32, st: &mut Store, soid: &Hobject, md: &ObjectModDesc) {
    let ops = parse(&md.bl).unwrap();
    for g in ec::moddesc::stash_generations_for(&ops, me) {
        st.remove(&(soid.clone(), g));
    }
}

#[derive(Clone, Debug, Default)]
struct MObj {
    data: Vec<u8>,
    user: BTreeMap<Vec<u8>, Vec<u8>>,
    version: Eversion,
}

struct Cl {
    b: Arc<Backend>,
    shards: Vec<Store>,
    model: BTreeMap<String, MObj>,
    ver: u64,
    first_write: bool,
    /// shard ids that are members (others are down: get nothing, never checked).
    members: Vec<u32>,
    stats: (u64, u64),
    /// PDW selection of every write (`Always`: PDW output is checked == conventional, then applied).
    pdw: PdwMode,
    /// Ops generated with PDW.
    pdw_ops: u64,
    /// Extent cache model (filled from `OGenerated::pages` when `pdw` is on): must equal the shard bytes always.
    xc: BTreeMap<(Hobject, usize, u64), Vec<u8>>,
}

fn oi_bytes(
    soid: &Hobject,
    v: Eversion,
    prior: Eversion,
    size: u64,
    sv: &BTreeMap<ShardId, Eversion>,
) -> Vec<u8> {
    let mut oi = ObjectInfo::new(soid.clone());
    oi.version = v;
    oi.prior_version = prior;
    oi.size = size;
    // the op layer copies what it decoded; the generator must rewrite it anyway
    oi.shard_versions = sv.clone();
    denc::to_vec(&oi).unwrap()
}

impl Cl {
    fn new(b: Backend) -> Cl {
        let n = b.n();
        Cl {
            b: Arc::new(b),
            shards: vec![Store::new(); n],
            model: BTreeMap::new(),
            ver: 0,
            first_write: true,
            members: (0..n as u32).collect(),
            stats: (0, 0),
            pdw: PdwMode::Never,
            pdw_ops: 0,
            xc: BTreeMap::new(),
        }
    }

    fn primary(&self) -> u32 {
        self.b.mapping[0]
    }

    fn old_of(&self, h: &Hobject, name: &str) -> OldObj {
        match self.model.get(name) {
            None => OldObj::default(),
            Some(m) => OldObj {
                exists: true,
                size: m.data.len() as u64,
                attrs: self.shards[self.primary() as usize][&(h.clone(), LIVE)]
                    .attrs
                    .clone(),
            },
        }
    }

    /// Run one logical op on object `name`; checks all invariants, returns the written set.
    fn op(&mut self, name: &str, op: &L) -> ShardIdSet {
        if std::env::var("OTRACE").is_ok() {
            eprintln!("op {name} {}", short(op));
        }
        let h = hobj(name);
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(denc::types::SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId(0),
        }));
        let gh = |n: &str| Ghobject::new(hobj(n), LIVE, ShardId(0));
        let exists = self.model.contains_key(name);
        let old = self.model.get(name).cloned().unwrap_or_default();
        let mut new = old.clone();
        let mut new_exists = exists;
        self.ver += 1;
        let mut versions = BTreeMap::new();
        let mut olds = BTreeMap::new();
        let mut clone_target: Option<(&'static str, MObj)> = None;
        let ox = t.obj(&gh(name));
        match op {
            L::Write(off, d) => {
                t.push(
                    cx,
                    TxnOp::Write {
                        oid: ox,
                        off: *off,
                        data: Data::new(d),
                    },
                );
                let end = (*off as usize) + d.len();
                if new.data.len() < end {
                    new.data.resize(end, 0);
                }
                new.data[*off as usize..end].copy_from_slice(d);
                new_exists = true;
            }
            L::Zero(off, len) => {
                t.push(
                    cx,
                    TxnOp::Zero {
                        oid: ox,
                        off: *off,
                        len: *len,
                    },
                );
                let end = ((off + len) as usize).min(new.data.len());
                for i in (*off as usize)..end {
                    new.data[i] = 0;
                }
            }
            L::Trunc(sz) => {
                t.push(cx, TxnOp::Truncate { oid: ox, size: *sz });
                new.data.resize(*sz as usize, 0);
                new_exists = true;
            }
            L::Remove => {
                t.push(cx, TxnOp::Remove { oid: ox });
                new_exists = false;
            }
            L::Create => {
                t.push(cx, TxnOp::Create { oid: ox });
                new_exists = true;
            }
            L::Attr(k, v) => {
                let key = format!("_{k}");
                t.push(
                    cx,
                    TxnOp::SetAttrs {
                        oid: ox,
                        attrs: vec![],
                    },
                );
                new.user.insert(key.into_bytes(), v.clone());
                new_exists = true;
            }
            L::RmAttr(k) => {
                new.user.remove(format!("_{k}").as_bytes());
            }
            L::Full(d) => {
                t.push(cx, TxnOp::Truncate { oid: ox, size: 0 });
                t.push(
                    cx,
                    TxnOp::Write {
                        oid: ox,
                        off: 0,
                        data: Data::new(d),
                    },
                );
                new.data = d.clone();
                new_exists = true;
            }
            L::CloneTo(c) => {
                let co = t.obj(&gh(c));
                // clone first in the transaction, like the op layer's make_writeable
                t.ops.clear();
                t.push(
                    cx,
                    TxnOp::Clone {
                        oid: ox,
                        dest_oid: co,
                    },
                );
                let ch = hobj(c);
                versions.insert(ch.clone(), self.ver);
                olds.insert(ch, OldObj::default());
                clone_target = Some((c, old.clone()));
                self.ver += 1;
            }
            L::Hint => {
                t.push(
                    cx,
                    TxnOp::SetAllocHint {
                        oid: ox,
                        expected_object_size: 1 << 20,
                        expected_write_size: 4096,
                        flags: 0,
                    },
                );
            }
        }
        let v = Eversion::new(1, self.ver);
        // attrs: `_` (+ user) on every modifying op of an existing result
        let mut ov: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let old_sv = if exists {
            let pa = &self.shards[self.primary() as usize][&(h.clone(), LIVE)].attrs;
            denc::from_slice::<ObjectInfo>(&pa[b"_".as_slice()])
                .unwrap()
                .shard_versions
        } else {
            BTreeMap::new()
        };
        if new_exists {
            let prior = if exists {
                old.version
            } else {
                Eversion::default()
            };
            ov.push((
                b"_".to_vec(),
                oi_bytes(&h, v, prior, new.data.len() as u64, &old_sv),
            ));
            for (k, val) in &new.user {
                if old.user.get(k) != Some(val) || !exists {
                    ov.push((k.clone(), val.clone()));
                }
            }
            let refs: Vec<(&[u8], &[u8])> = ov
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect();
            t.push(
                cx,
                TxnOp::SetAttrs {
                    oid: ox,
                    attrs: refs,
                },
            );
            if let L::RmAttr(k) = op {
                let kk = format!("_{k}");
                let leaked: &'static [u8] = Box::leak(kk.into_bytes().into_boxed_slice());
                t.push(
                    cx,
                    TxnOp::RmAttr {
                        oid: ox,
                        name: leaked,
                    },
                );
            }
        }
        let mut clone_attr: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        if let Some((c, src)) = &clone_target {
            let co = t.obj(&gh(c));
            let cv = Eversion::new(1, self.ver - 1);
            clone_attr.push((
                b"_".to_vec(),
                oi_bytes(
                    &hobj(c),
                    cv,
                    src.version,
                    src.data.len() as u64,
                    &BTreeMap::new(),
                ),
            ));
            let refs: Vec<(&[u8], &[u8])> = clone_attr
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect();
            t.push(
                cx,
                TxnOp::SetAttrs {
                    oid: co,
                    attrs: refs,
                },
            );
        }
        let txn = t.encode_v9().unwrap();
        olds.insert(h.clone(), self.old_of(&h, name));
        versions.insert(h.clone(), self.ver);
        let mk_plan = || {
            self.b
                .plan_write_o(
                    PgT::new(1, 0),
                    &txn,
                    &olds,
                    &versions,
                    OCtx {
                        members: &self.members,
                        first_write: self.first_write,
                    },
                )
                .unwrap_or_else(|e| panic!("plan {op:?}: {e}"))
        };
        let plan = mk_plan();
        let mut pdw_plan = (self.pdw != PdwMode::Never).then(mk_plan);
        let mut pdw_reads = 0;
        if let Some(p) = pdw_plan.as_mut()
            && p.select_pdw(self.pdw, |_, _| true, |_, _, _| false) == 0
        {
            pdw_plan = None;
        }
        if plan.consumed_first_write {
            self.first_write = false;
        }
        // old bytes: exactly what was asked, garbage elsewhere (catches reliance on unrequested data)
        let gather = |reads: Vec<(Hobject, usize, Ext)>, cnt: &mut u64| {
            let mut oldb = BTreeMap::new();
            for (oh, raw, ext) in reads {
                let sh = self.b.mapping[raw];
                let (lo, hi) = (ext.first().unwrap(), ext.last_end().unwrap());
                let mut buf = vec![0xEEu8; (hi - lo) as usize];
                let src = &self.shards[sh as usize][&(oh.clone(), LIVE)].data;
                for (a, e) in ext.iter() {
                    for x in a..e {
                        buf[(x - lo) as usize] = src.get(x as usize).copied().unwrap_or(0);
                    }
                }
                *cnt += ext.bytes();
                oldb.insert((oh, raw), (lo, buf));
            }
            oldb
        };
        let oldb = gather(plan.reads(), &mut self.stats.0);
        let mds = plan.mod_descs();
        let written = plan.written();
        let w_main = written[&h];
        let plan_wu = plan.written_union();
        let shared = plan.clone();
        let mut gen_ = plan.generate(&oldb).unwrap();
        let mut shared = Some((shared, oldb.clone()));
        if let Some(p) = pdw_plan {
            // PDW == conventional RMW byte for byte (records and plan shape are shared, only reads differ)
            assert_eq!(p.mod_descs(), mds);
            assert_eq!(p.written(), written);
            let pb = gather(p.reads(), &mut pdw_reads);
            shared = Some((p.clone(), pb.clone()));
            let pg = p.generate(&pb).unwrap();
            assert_eq!(pg.txns, gen_.txns, "PDW != conventional for {op:?}");
            gen_ = pg;
            self.pdw_ops += 1;
            self.crash_matrix(&gen_.txns, &mds, &written, op);
        }
        // shared generation (rope + local skeleton, columns by reference) == copied blobs, every history
        if let Some((p, ob)) = shared {
            let s = p
                .clone()
                .generate_shared(&ob, &BTreeMap::new(), None)
                .unwrap();
            assert_eq!(s.txns.len(), gen_.txns.len());
            for (sh, (a, b)) in s.txns.iter().zip(&gen_.txns).enumerate() {
                assert_eq!(a.is_some(), b.is_some(), "shard {sh}");
                if let (Some(a), Some(b)) = (a, b) {
                    crate::tests::check_shared(std::slice::from_ref(a), std::slice::from_ref(b));
                }
            }
            assert_eq!(s.pages.len(), gen_.pages.len());
            assert_eq!(s.mds, gen_.mds);
            // one-form-per-shard output (primary): local = skeleton only, peers = rope only, same content
            let loc = self.members[0];
            let l = p.generate_shared(&ob, &BTreeMap::new(), Some(loc)).unwrap();
            for (sh, (a, b)) in l.txns.iter().zip(&s.txns).enumerate() {
                let (Some(a), Some(b)) = (a, b) else { continue };
                if sh as u32 == loc {
                    assert!(a.inline.is_empty() && a.zc.is_empty());
                    assert_eq!((&a.skel, &a.refs), (&b.skel, &b.refs));
                } else {
                    assert!(a.skel.is_empty() && a.refs.is_empty());
                    assert_eq!((&a.inline, &a.zc), (&b.inline, &b.zc));
                }
            }
        }
        let prev = self.shards.clone();
        let n = self.b.n();
        let wu = plan_wu;
        for sh in 0..n as u32 {
            let t = &gen_.txns[sh as usize];
            if !self.members.contains(&sh) {
                assert!(t.is_none(), "txn for a non-member");
                continue;
            }
            // invariant 5: a member has work iff it is written
            let w = wu.is_none_or(|u| crate::shard_set_contains(&u, sh));
            assert_eq!(
                t.is_some(),
                w,
                "shard {sh} txn vs written {written:?} op {op:?}"
            );
            if let Some(t) = t {
                self.stats.1 += t.len() as u64;
                apply_shard(&mut self.shards[sh as usize], t);
            }
        }
        // model update
        if let Some((c, src)) = clone_target {
            let mut cm = src.clone();
            cm.version = Eversion::new(1, self.ver - 1);
            self.model.insert(c.to_string(), cm);
        }
        if new_exists {
            new.version = v;
            self.model.insert(name.to_string(), new);
        } else {
            self.model.remove(name);
        }
        let downs: Vec<u32> = (0..n as u32)
            .filter(|s| !self.members.contains(s))
            .collect();
        for d in downs {
            self.recover_shard(d);
        }
        self.check_xc(&gen_.pages);
        self.check();
        // rollback of this op restores the previous shards (members), then roll forward the real ones
        let mut rb = self.shards.clone();
        for &sh in &self.members {
            let st = &mut rb[sh as usize];
            for (oh, md) in mds.iter().rev() {
                rollback(&self.b, sh, st, oh, md, &written[oh]);
            }
            let (a, b) = (
                strip(&prev[sh as usize], is_np(&self.b, sh)),
                strip(st, is_np(&self.b, sh)),
            );
            assert_eq!(a, b, "rollback of {op:?} on shard {sh}");
            for (oh, md) in &mds {
                if written_has(&written[oh], sh) {
                    roll_forward(sh, &mut self.shards[sh as usize], oh, md);
                }
            }
            assert!(
                self.shards[sh as usize].keys().all(|(_, g)| *g == LIVE),
                "stash left after roll forward on {sh}"
            );
        }
        w_main
    }

    /// Invariants 1, 2 and the shard_versions rule for every object.
    fn check(&self) {
        let b = &self.b;
        let (k, n) = (b.k, b.n());
        let g = Geo {
            k: k as u64,
            c: b.c,
        };
        for (name, m) in &self.model {
            let h = hobj(name);
            let p = m.data.len() as u64;
            let mut cols: Vec<Vec<u8>> = Vec::new();
            for r in 0..n {
                let sh = b.mapping[r];
                let o = self.shards[sh as usize]
                    .get(&(h.clone(), LIVE))
                    .unwrap_or_else(|| panic!("{name} missing on shard {sh}"));
                assert_eq!(
                    o.data.len() as u64,
                    g.shard_size(p, r),
                    "{name} size on shard {sh} (raw {r}) p={p}"
                );
                cols.push(o.data.clone());
            }
            let len = cols[0].len();
            // data columns = model bytes
            for (r, col) in cols.iter().enumerate().take(k) {
                for (so, byte) in col.iter().enumerate() {
                    let lo = g.shard_to_ro(r, so as u64) as usize;
                    let want = m.data.get(lo).copied().unwrap_or(0);
                    assert_eq!(*byte, want, "{name} raw {r} shard off {so}");
                }
            }
            // parity over the parity length (data columns zero extended)
            let pad = |c: &Vec<u8>| {
                let mut v = c.clone();
                v.resize(len, 0);
                v
            };
            let d: Vec<Vec<u8>> = cols[..k].iter().map(pad).collect();
            let dr: Vec<&[u8]> = d.iter().map(|v| &v[..]).collect();
            let mut par = vec![vec![0u8; len]; n - k];
            {
                let mut pr: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
                b.codec.encode(&dr, &mut pr);
            }
            for j in 0..n - k {
                assert_eq!(pad(&cols[k + j]), par[j], "{name} parity {j}");
            }
            // shard versions: an NP shard's `_` version == what the primary says
            let poi: ObjectInfo = denc::from_slice(
                &self.shards[self.primary() as usize][&(h.clone(), LIVE)].attrs[b"_".as_slice()],
            )
            .unwrap();
            assert_eq!(poi.version, m.version, "{name} primary version");
            for r in 0..n {
                let sh = b.mapping[r];
                let a = &self.shards[sh as usize][&(h.clone(), LIVE)].attrs;
                let oi: ObjectInfo = denc::from_slice(&a[b"_".as_slice()]).unwrap();
                if r >= 1 && r < k {
                    assert_eq!(
                        oi.version,
                        crate::version_for_shard(&poi, sh),
                        "{name} NP shard {sh} version"
                    );
                    assert_eq!(a.len(), 1, "NP shard {sh} holds only `_`");
                } else {
                    assert_eq!(oi.version, m.version, "{name} PC shard {sh} version");
                    let user: BTreeMap<Vec<u8>, Vec<u8>> = a
                        .iter()
                        .filter(|(k, _)| k.as_slice() != b"_")
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    assert_eq!(user, m.user, "{name} PC shard {sh} user attrs");
                }
            }
        }
        // objects not in the model exist nowhere
        for st in &self.shards {
            for (oh, _) in st.keys().filter(|(_, g)| *g == LIVE) {
                assert!(
                    self.model.keys().any(|n| hobj(n) == *oh),
                    "stray object {oh:?}"
                );
            }
        }
    }

    /// Every k-subset decodes the model objects.
    fn check_subsets(&self, max: usize) {
        let b = &self.b;
        let (k, n) = (b.k, b.n());
        let g = Geo {
            k: k as u64,
            c: b.c,
        };
        let subsets = subsets(n, k);
        for sub in subsets.iter().take(max) {
            for (name, m) in &self.model {
                let h = hobj(name);
                let len = self.shards[b.mapping[0] as usize][&(h.clone(), LIVE)]
                    .data
                    .len();
                let have: Vec<(u32, Vec<u8>)> = sub
                    .iter()
                    .map(|r| {
                        let sh = b.mapping[*r];
                        let mut v = self.shards[sh as usize][&(h.clone(), LIVE)].data.clone();
                        v.resize(len, 0);
                        (sh, v)
                    })
                    .collect();
                let want: Vec<u32> = (0..k).map(|r| b.mapping[r]).collect();
                let cols = b.rebuild_shards(&have, &want).unwrap();
                let mut out = vec![0u8; m.data.len()];
                for (r, (_, col)) in cols.iter().enumerate() {
                    for (so, byte) in col.iter().enumerate() {
                        let lo = g.shard_to_ro(r, so as u64) as usize;
                        if lo < out.len() {
                            out[lo] = *byte;
                        }
                    }
                }
                assert_eq!(out, m.data, "{name} decode from {sub:?}");
            }
        }
    }
}

/// Shard store without stash objects; NP `_` compared by version only (rollback rewrites it, spec 6.2).
type Stripped = BTreeMap<Hobject, (Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>)>;

fn strip(st: &Store, np: bool) -> Stripped {
    st.iter()
        .filter(|((_, g), _)| *g == LIVE)
        .map(|((h, _), o)| {
            let mut a = o.attrs.clone();
            if np && let Some(v) = a.get_mut(b"_".as_slice()) {
                let oi: ObjectInfo = denc::from_slice(v).unwrap();
                *v = oi.version.version.to_le_bytes().to_vec();
            }
            (h.clone(), (o.data.clone(), a))
        })
        .collect()
}

fn subsets(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    fn go(i: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        if i == n || n - i < k - cur.len() {
            return;
        }
        cur.push(i);
        go(i + 1, n, k, cur, out);
        cur.pop();
        go(i + 1, n, k, cur, out);
    }
    go(0, n, k, &mut cur, &mut out);
    out
}

fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8 | 1
        })
        .collect()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn random_run(b: Backend, seed: u64, steps: usize, members: Option<Vec<u32>>) {
    random_run_pdw(b, seed, steps, members, PdwMode::Never);
}

/// Returns the number of PDW ops.
fn random_run_pdw(
    b: Backend,
    seed: u64,
    steps: usize,
    members: Option<Vec<u32>>,
    pdw: PdwMode,
) -> u64 {
    let s = b.s;
    let mut cl = Cl::new(b);
    cl.pdw = pdw;
    if let Some(m) = members {
        cl.members = m;
    }
    let mut rng = Rng(seed | 1);
    let names = ["a", "b"];
    let mut nclone = 0;
    let mut partial = 0;
    for step in 0..steps {
        let name = names[rng.below(2) as usize];
        let size = cl.model.get(name).map_or(0, |m| m.data.len() as u64);
        let exists = cl.model.contains_key(name);
        let span = 3 * s + 5000;
        let op = match rng.below(13) {
            0..=3 => {
                let off = if rng.below(3) == 0 {
                    rng.below(span) / 4096 * 4096
                } else {
                    rng.below(span)
                };
                let cap = if rng.below(4) == 0 { 2 * s } else { 9000 };
                let len = 1 + rng.below(cap);
                L::Write(off, bytes(seed ^ step as u64, len as usize))
            }
            4 if exists => L::Write(size, bytes(step as u64, 1 + rng.below(s) as usize)),
            5 if exists => L::Zero(rng.below(size + 1), 1 + rng.below(s)),
            6 if exists => L::Trunc(rng.below(size + 1)),
            7 if exists => L::Trunc(size + rng.below(2 * s)),
            8 if exists => L::Remove,
            9 => L::Full(bytes(step as u64 + 7, rng.below(2 * s) as usize + 1)),
            10 => L::Attr(["x", "y"][rng.below(2) as usize], bytes(step as u64, 5)),
            11 if exists && nclone < 6 => {
                nclone += 1;
                L::CloneTo(["c1", "c2", "c3", "c4", "c5", "c6"][nclone - 1])
            }
            12 if exists => {
                if rng.below(2) == 0 {
                    L::RmAttr("x")
                } else {
                    L::Hint
                }
            }
            _ => L::Create,
        };
        if matches!(
            op,
            L::Zero(..) | L::Remove | L::Attr(..) | L::RmAttr(_) | L::Hint
        ) && !exists
        {
            continue;
        }
        if let L::CloneTo(c) = &op
            && cl.model.contains_key(*c)
        {
            continue;
        }
        if !cl.op(name, &op).is_empty() {
            partial += 1;
        }
    }
    assert!(partial > 3, "only {partial} partial writes");
    cl.check_subsets(40);
    cl.pdw_ops
}

#[test]
fn random_histories_all_geometries() {
    for (k, m, c, pl, te) in [
        (2, 1, 4096, "isa", "reed_sol_van"),
        (2, 2, 4096, "isa", "reed_sol_van"),
        (3, 2, 8192, "isa", "cauchy"),
        (4, 2, 16384, "isa", "reed_sol_van"),
        (4, 2, 4096, "jerasure", "reed_sol_van"),
        (8, 3, 4096, "isa", "reed_sol_van"),
    ] {
        for seed in 1..=6u64 {
            random_run(be(k, m, c, pl, te), seed * 7919 + k as u64, 120, None);
        }
    }
}

#[test]
fn random_histories_degraded_members() {
    // one shard down: it gets nothing (recovered from the model before each check, as recovery would)
    for (k, m, c) in [(4u32, 2u32, 4096u32), (3, 2, 8192)] {
        let b = be(k, m, c, "isa", "reed_sol_van");
        for seed in 1..=3u64 {
            for down in [1u32, k - 1, k] {
                let members: Vec<u32> = (0..k + m).filter(|s| *s != down).collect();
                random_run(b.clone(), seed * 13 + u64::from(down), 80, Some(members));
            }
        }
    }
}

impl Cl {
    /// Crash/replay of one (PDW) write on every member (each shard decides alone): applied then rolled back = old data
    /// and parity; rolled back then the entry re-sent and applied again = the same bytes as one clean apply.
    fn crash_matrix(
        &self,
        txns: &[Option<Vec<u8>>],
        mds: &BTreeMap<Hobject, ObjectModDesc>,
        written: &BTreeMap<Hobject, ShardIdSet>,
        op: &L,
    ) {
        for &sh in &self.members {
            let Some(t) = &txns[sh as usize] else {
                continue;
            };
            let np = is_np(&self.b, sh);
            let mut once = self.shards[sh as usize].clone();
            apply_shard(&mut once, t);
            let mut st = once.clone();
            for (oh, md) in mds.iter().rev() {
                rollback(&self.b, sh, &mut st, oh, md, &written[oh]);
            }
            assert_eq!(
                strip(&self.shards[sh as usize], np),
                strip(&st, np),
                "crash rollback of {op:?} on shard {sh}"
            );
            apply_shard(&mut st, t);
            assert_eq!(st, once, "replay after rollback of {op:?} on shard {sh}");
        }
    }

    /// Rebuild shard `sh` completely from the model (data, sizes, attrs as a recovery push would).
    fn recover_shard(&mut self, sh: u32) {
        let b = self.b.clone();
        let raw = b.mapping.iter().position(|s| *s == sh).unwrap();
        let g = Geo {
            k: b.k as u64,
            c: b.c,
        };
        let mut st = Store::new();
        for (name, m) in &self.model {
            let h = hobj(name);
            let p = m.data.len() as u64;
            let len = g.shard_size(p, raw) as usize;
            let mut data = vec![0u8; len];
            if raw < b.k {
                for (so, byte) in data.iter_mut().enumerate() {
                    *byte = m
                        .data
                        .get(g.shard_to_ro(raw, so as u64) as usize)
                        .copied()
                        .unwrap_or(0);
                }
            } else {
                // parity: encode the zero-extended data columns
                let plen = g.shard_size(p, 0) as usize;
                let cols: Vec<Vec<u8>> = (0..b.k)
                    .map(|r| {
                        (0..plen)
                            .map(|so| {
                                m.data
                                    .get(g.shard_to_ro(r, so as u64) as usize)
                                    .copied()
                                    .unwrap_or(0)
                            })
                            .collect()
                    })
                    .collect();
                let d: Vec<&[u8]> = cols.iter().map(|v| &v[..]).collect();
                let mut par = vec![vec![0u8; plen]; b.m];
                {
                    let mut pr: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
                    b.codec.encode(&d, &mut pr);
                }
                data = par[raw - b.k].clone();
            }
            let pa = &self.shards[b.mapping[0] as usize][&(h.clone(), LIVE)].attrs;
            let attrs = if raw >= 1 && raw < b.k {
                // NP push: OI with version := shard version, shard_versions cleared (spec 6.3)
                let mut oi: ObjectInfo = denc::from_slice(&pa[b"_".as_slice()]).unwrap();
                oi.version = crate::version_for_shard(&oi, sh);
                oi.shard_versions.clear();
                BTreeMap::from([(b"_".to_vec(), denc::to_vec(&oi).unwrap())])
            } else {
                pa.clone()
            };
            st.insert((h, LIVE), Obj { data, attrs });
        }
        self.shards[sh as usize] = st;
    }
}

#[test]
fn spec_example_e2_partial_overwrite() {
    // k=4 m=2 C=16K: 64K object, overwrite 4096 bytes at 20480 -> written {0,1,4,5}, s2/s3 get nothing
    let mut cl = Cl::new(be(4, 2, 16384, "isa", "reed_sol_van"));
    cl.op("a", &L::Write(0, bytes(1, 65536)));
    cl.op("a", &L::Attr("x", vec![1])); // first write consumed above; this is a partial PC-only op
    let w = cl.op("a", &L::Write(20480, bytes(2, 4096)));
    assert_eq!(w.0, [0b110011, 0]);
    // the rollback record
    let h = hobj("a");
    let txn = {
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(denc::types::SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId(0),
        }));
        let ox = t.obj(&Ghobject::new(h.clone(), LIVE, ShardId(0)));
        let d = bytes(3, 4096);
        t.push(
            cx,
            TxnOp::Write {
                oid: ox,
                off: 20480,
                data: Data::new(&d),
            },
        );
        t.encode_v9().unwrap()
    };
    let olds = BTreeMap::from([(h.clone(), cl.old_of(&h, "a"))]);
    let plan =
        cl.b.plan_write_o(
            PgT::new(1, 0),
            &txn,
            &olds,
            &BTreeMap::from([(h.clone(), 11)]),
            OCtx {
                members: &cl.members,
                first_write: false,
            },
        )
        .unwrap();
    // conventional reads: s0, s2, s3 at [4096, 8192)
    let r: Vec<(usize, Vec<(u64, u64)>)> = plan
        .reads()
        .into_iter()
        .map(|(_, r, e)| (r, e.iter().collect()))
        .collect();
    assert_eq!(
        r,
        vec![
            (0, vec![(4096, 8192)]),
            (2, vec![(4096, 8192)]),
            (3, vec![(4096, 8192)])
        ]
    );
    let md = &plan.mod_descs()[&h];
    let ops = parse(&md.bl).unwrap();
    assert_eq!(md.version, 2);
    match &ops[0] {
        ModOp::RollbackExtents {
            generation,
            extents,
            object_size,
            shards,
        } => {
            assert_eq!((*generation, *object_size), (11, Some(65536)));
            assert_eq!(extents, &vec![(4096, 4096)]);
            assert!(
                raw_contains(&shards[0], 1)
                    && raw_contains(&shards[0], 4)
                    && raw_contains(&shards[0], 5)
            );
            assert!(!raw_contains(&shards[0], 0) && !raw_contains(&shards[0], 2));
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn spec_example_truncate_unaligned_records() {
    // k=4 m=2 C=16K: o=100000 -> truncate 20000: extents [(0,32768),(0,16384)], sets [{0..5},{4,5}], object_size 102400
    let mut cl = Cl::new(be(4, 2, 16384, "isa", "reed_sol_van"));
    cl.op("a", &L::Write(0, bytes(1, 100000)));
    let h = hobj("a");
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(denc::types::SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId(0),
    }));
    let ox = t.obj(&Ghobject::new(h.clone(), LIVE, ShardId(0)));
    t.push(
        cx,
        TxnOp::Truncate {
            oid: ox,
            size: 20000,
        },
    );
    let txn = t.encode_v9().unwrap();
    let olds = BTreeMap::from([(h.clone(), cl.old_of(&h, "a"))]);
    let plan =
        cl.b.plan_write_o(
            PgT::new(1, 0),
            &txn,
            &olds,
            &BTreeMap::from([(h.clone(), 9)]),
            OCtx {
                members: &cl.members,
                first_write: false,
            },
        )
        .unwrap();
    assert!(plan.written()[&h].is_empty());
    let ops = parse(&plan.mod_descs()[&h].bl).unwrap();
    match &ops[0] {
        ModOp::RollbackExtents {
            extents,
            object_size,
            shards,
            ..
        } => {
            assert_eq!(*object_size, Some(102400));
            assert_eq!(extents, &vec![(0, 32768), (0, 16384)]);
            for s in 0..6 {
                assert!(raw_contains(&shards[0], s));
            }
            assert!(
                raw_contains(&shards[1], 4)
                    && raw_contains(&shards[1], 5)
                    && !raw_contains(&shards[1], 0)
            );
        }
        o => panic!("{o:?}"),
    }
    // and the model run of the same op passes all invariants incl. rollback
    cl.op("a", &L::Trunc(20000));
}

#[test]
fn spec_example_append_k2() {
    // k=2 m=1 C=4K: o=5000, append 1000 -> APPEND(8192), ROLLBACK_EXTENTS(gen,[(0,4096)],8192,[{1,2}])
    let mut cl = Cl::new(be(2, 1, 4096, "isa", "reed_sol_van"));
    cl.op("a", &L::Write(0, bytes(1, 5000)));
    let h = hobj("a");
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(denc::types::SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId(0),
    }));
    let ox = t.obj(&Ghobject::new(h.clone(), LIVE, ShardId(0)));
    let d = bytes(2, 1000);
    t.push(
        cx,
        TxnOp::Write {
            oid: ox,
            off: 5000,
            data: Data::new(&d),
        },
    );
    let txn = t.encode_v9().unwrap();
    let olds = BTreeMap::from([(h.clone(), cl.old_of(&h, "a"))]);
    let plan =
        cl.b.plan_write_o(
            PgT::new(1, 0),
            &txn,
            &olds,
            &BTreeMap::from([(h.clone(), 3)]),
            OCtx {
                members: &cl.members,
                first_write: false,
            },
        )
        .unwrap();
    let ops = parse(&plan.mod_descs()[&h].bl).unwrap();
    assert_eq!(ops[0], ModOp::Append { old_size: 8192 });
    match &ops[1] {
        ModOp::RollbackExtents {
            extents,
            object_size,
            shards,
            ..
        } => {
            assert_eq!(
                (extents.clone(), *object_size),
                (vec![(0, 4096)], Some(8192))
            );
            assert!(
                raw_contains(&shards[0], 1)
                    && raw_contains(&shards[0], 2)
                    && !raw_contains(&shards[0], 0)
            );
        }
        o => panic!("{o:?}"),
    }
    cl.op("a", &L::Write(5000, bytes(2, 1000)));
}

#[test]
fn first_write_in_interval_forces_all_then_partial() {
    let mut cl = Cl::new(be(4, 2, 4096, "isa", "reed_sol_van"));
    cl.op("a", &L::Write(0, bytes(1, 16384)));
    cl.first_write = true;
    // in-place overwrite of shard 2 only, but first in the interval: all shards
    assert!(cl.op("a", &L::Write(8192, bytes(2, 4096))).is_empty());
    // next one: partial, NP shards 1 and 3 become stale
    assert_eq!(cl.op("a", &L::Write(8192, bytes(3, 4096))).0, [0b110101, 0]);
    let h = hobj("a");
    let poi: ObjectInfo =
        denc::from_slice(&cl.shards[0][&(h.clone(), LIVE)].attrs[b"_".as_slice()]).unwrap();
    assert_eq!(poi.shard_versions.len(), 2);
    // a later partial write to shard 1: its entry goes away, shard 3 keeps its older version
    let v3 = poi.shard_versions[&ShardId(3)];
    assert_eq!(cl.op("a", &L::Write(4096, bytes(4, 100))).0, [0b110011, 0]);
    let poi: ObjectInfo =
        denc::from_slice(&cl.shards[0][&(h.clone(), LIVE)].attrs[b"_".as_slice()]).unwrap();
    assert_eq!(poi.shard_versions.get(&ShardId(3)), Some(&v3));
    assert!(!poi.shard_versions.contains_key(&ShardId(1)));
    assert!(poi.shard_versions.contains_key(&ShardId(2)));
    cl.check_subsets(100);
}

#[test]
fn pure_attr_update_is_pc_only() {
    let mut cl = Cl::new(be(4, 2, 4096, "isa", "reed_sol_van"));
    cl.op("a", &L::Write(0, bytes(1, 20000)));
    assert_eq!(cl.op("a", &L::Attr("x", vec![7])).0, [0b110001, 0]);
    assert_eq!(cl.op("a", &L::RmAttr("x")).0, [0b110001, 0]);
    // alloc hint forces all
    assert!(cl.op("a", &L::Hint).is_empty());
}

#[test]
fn small_overwrite_reads_little() {
    // 4 KiB overwrite in a big object reads at most (k-1) pages and writes 1 data + m parity pages
    let mut cl = Cl::new(be(8, 3, 16384, "isa", "reed_sol_van"));
    cl.op("a", &L::Write(0, bytes(1, 8 * 16384 * 4)));
    cl.op("a", &L::Attr("x", vec![1]));
    cl.stats = (0, 0);
    cl.op("a", &L::Write(3 * 16384 + 4096, bytes(2, 4096)));
    assert_eq!(cl.stats.0, 7 * 4096);
}

fn short(op: &L) -> String {
    match op {
        L::Write(o, d) => format!("Write({o}, {})", d.len()),
        L::Full(d) => format!("Full({})", d.len()),
        L::Attr(k, _) => format!("Attr({k})"),
        o => format!("{o:?}"),
    }
}

const PDW_PROFILES: [(u32, u32, u32, &str, &str); 9] = [
    (2, 1, 4096, "isa", "reed_sol_van"),
    (2, 1, 8192, "jerasure", "reed_sol_van"),
    (2, 2, 4096, "isa", "reed_sol_van"),
    (3, 2, 8192, "isa", "cauchy"),
    (4, 2, 16384, "isa", "reed_sol_van"),
    (4, 2, 4096, "jerasure", "reed_sol_van"),
    (6, 3, 4096, "isa", "cauchy"),
    (8, 3, 4096, "isa", "reed_sol_van"),
    (8, 3, 16384, "jerasure", "reed_sol_van"),
];

#[test]
fn pdw_equals_conventional_all_profiles() {
    // every overwrite PDW may take is generated both ways: identical transactions; the PDW output is applied, so
    // parity = encode(data), every k-subset decodes, rollback / replay of every PDW step restore the old parity
    for (k, m, c, pl, te) in PDW_PROFILES {
        let mut n = 0;
        for seed in 1..=3u64 {
            n += random_run_pdw(
                be(k, m, c, pl, te),
                seed * 104729 + k as u64,
                120,
                None,
                PdwMode::Always,
            );
        }
        assert!(n > 10, "k{k}m{m} {pl}: only {n} PDW ops");
    }
}

#[test]
fn pdw_degraded_members() {
    // a data or parity shard down: PDW reads/writes skip it, results still match
    for (k, m, c) in [(4u32, 2u32, 4096u32), (3, 2, 8192)] {
        let b = be(k, m, c, "isa", "reed_sol_van");
        for down in [1u32, k - 1, k, k + m - 1] {
            let members: Vec<u32> = (0..k + m).filter(|s| *s != down).collect();
            let n = random_run_pdw(
                b.clone(),
                31 + u64::from(down),
                100,
                Some(members),
                PdwMode::Always,
            );
            assert!(n > 3, "down {down}: only {n} PDW ops");
        }
    }
}

#[test]
fn pdw_auto_choice_rule() {
    // k8m3: one 4K page overwrite reads 1 data + 3 parity (PDW) instead of 7 data pages
    let mut cl = Cl::new(be(8, 3, 16384, "isa", "reed_sol_van"));
    cl.pdw = PdwMode::Auto;
    cl.op("a", &L::Write(0, bytes(1, 8 * 16384 * 4)));
    cl.op("a", &L::Attr("x", vec![1]));
    cl.op("a", &L::Write(3 * 16384 + 4096, bytes(2, 4096)));
    assert_eq!(cl.pdw_ops, 1);
    // k2m1: conventional reads 1 shard, PDW 2 -> conventional
    let mut cl = Cl::new(be(2, 1, 4096, "isa", "reed_sol_van"));
    cl.pdw = PdwMode::Auto;
    cl.op("a", &L::Write(0, bytes(1, 65536)));
    cl.op("a", &L::Write(8192, bytes(2, 4096)));
    assert_eq!(cl.pdw_ops, 0);
}

#[test]
fn pdw_never_chosen_without_a_coding_matrix() {
    // review L2: jerasure reed_sol_van w=16/32 (`Code::Wide`) has no GF(2^8) matrix for the parity delta; `Auto` and
    // `Always` must fall back to the conventional RMW instead of failing the client write with EOPNOTSUPP
    for w in ["16", "32"] {
        let profile: BTreeMap<String, String> = [
            ("plugin", "jerasure"),
            ("technique", "reed_sol_van"),
            ("k", "8"),
            ("m", "3"),
            ("w", w),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        let b = Backend::from_profile(&profile, (8 * 16384, 16384), (0..11).collect(), true)
            .expect("w=16/32 profile");
        assert!(b.codec.matrix().is_none(), "w={w}: wide code");
        for mode in [PdwMode::Auto, PdwMode::Always] {
            let mut cl = Cl::new(b.clone());
            cl.pdw = mode;
            cl.op("a", &L::Write(0, bytes(1, 8 * 16384 * 4)));
            cl.op("a", &L::Write(3 * 16384 + 4096, bytes(2, 4096)));
            assert_eq!(cl.pdw_ops, 0, "w={w} {mode:?}");
        }
    }
}

impl Cl {
    /// Apply the extent cache update of one write, then every cached page must equal the shard bytes.
    fn check_xc(&mut self, pages: &[(Hobject, Option<Vec<crate::owgen::Page>>)]) {
        for (h, p) in pages {
            match p {
                None => self.xc.retain(|(o, _, _), _| o != h),
                Some(v) => {
                    for (r, off, d) in v {
                        self.xc.insert((h.clone(), *r, *off), d.clone());
                    }
                }
            }
        }
        for ((h, r, off), d) in &self.xc {
            let sh = self.b.mapping[*r] as usize;
            let Some(obj) = self.shards[sh].get(&(h.clone(), LIVE)) else {
                panic!("cached page of absent object {h:?}");
            };
            let got: Vec<u8> = (*off..*off + d.len() as u64)
                .map(|x| obj.data.get(x as usize).copied().unwrap_or(0))
                .collect();
            assert!(&got == d, "cached page raw {r} off {off} stale");
        }
    }
}

// ---- omap (S4) -------------------------------------------------------------------------------------------------

mod omap {
    use super::*;
    use ec::moddesc::{EcOmap, OmapUp};

    fn backend(omap: bool) -> Backend {
        let mut b = be(2, 2, 4096, "isa", "reed_sol_van");
        b.omap = omap;
        b
    }

    fn cx_obj(t: &mut Transaction, h: &Hobject) -> (replwire::Cx, replwire::Ox) {
        let cx = t.coll(&CollT::Pg(denc::types::SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId(0),
        }));
        let ox = t.obj(&Ghobject::new(h.clone(), LIVE, ShardId(0)));
        (cx, ox)
    }

    fn olds_with(h: &Hobject, size: u64, omap_flag: bool) -> BTreeMap<Hobject, OldObj> {
        let mut oi = ObjectInfo::new(h.clone());
        oi.size = size;
        if omap_flag {
            oi.flags |= replwire::oi::flag::OMAP;
        }
        let attrs = BTreeMap::from([(b"_".to_vec(), denc::to_vec(&oi).unwrap())]);
        BTreeMap::from([(
            h.clone(),
            OldObj {
                exists: true,
                size,
                attrs,
            },
        )])
    }

    fn plan(
        b: &Arc<Backend>,
        t: &Transaction,
        olds: &BTreeMap<Hobject, OldObj>,
        h: &Hobject,
    ) -> Result<OWritePlan, i32> {
        let members: Vec<u32> = (0..4).collect();
        b.plan_write_o(
            PgT::new(1, 0),
            &t.encode_v9().unwrap(),
            olds,
            &BTreeMap::from([(h.clone(), 7)]),
            OCtx {
                members: &members,
                first_write: false,
            },
        )
    }

    fn records(md: &ObjectModDesc) -> Vec<ModOp> {
        parse(&md.bl).unwrap()
    }

    fn omaps(ops: &[ModOp]) -> Vec<EcOmap> {
        ops.iter()
            .filter_map(|o| match o {
                ModOp::EcOmap(e) => Some(e.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn omap_needs_the_pool_flag() {
        let h = hobj("a");
        let mut t = Transaction::new();
        let (cx, ox) = cx_obj(&mut t, &h);
        t.push(
            cx,
            TxnOp::OmapSetKeys {
                oid: ox,
                pairs: vec![(&b"k"[..], &b"v"[..])].into(),
            },
        );
        let olds = olds_with(&h, 0, false);
        assert_eq!(
            plan(&Arc::new(backend(false)), &t, &olds, &h).err(),
            Some(EOPNOTSUPP)
        );
        assert!(plan(&Arc::new(backend(true)), &t, &olds, &h).is_ok());
    }

    #[test]
    fn omap_only_op_is_pc_only_with_records_in_order() {
        let h = hobj("a");
        let mut t = Transaction::new();
        let (cx, ox) = cx_obj(&mut t, &h);
        // set, clear, header, set again, rm, range: a clear starts a record, a header after it is its own record
        t.push(
            cx,
            TxnOp::OmapSetKeys {
                oid: ox,
                pairs: vec![(&b"x"[..], &b"1"[..])].into(),
            },
        );
        t.push(cx, TxnOp::OmapClear { oid: ox });
        t.push(
            cx,
            TxnOp::OmapSetHeader {
                oid: ox,
                header: b"H",
            },
        );
        t.push(
            cx,
            TxnOp::OmapSetKeys {
                oid: ox,
                pairs: vec![(&b"a"[..], &b"2"[..])].into(),
            },
        );
        t.push(
            cx,
            TxnOp::OmapRmKeys {
                oid: ox,
                keys: vec![b"b"],
            },
        );
        t.push(
            cx,
            TxnOp::OmapRmKeyRange {
                oid: ox,
                first: b"c",
                last: b"e",
            },
        );
        // the op layer always rewrites object_info
        let mut oi = ObjectInfo::new(h.clone());
        oi.size = 100;
        oi.flags |= replwire::oi::flag::OMAP;
        let oib = denc::to_vec(&oi).unwrap();
        t.push(
            cx,
            TxnOp::SetAttr {
                oid: ox,
                name: b"_",
                value: &oib,
            },
        );
        let b = Arc::new(backend(true));
        let olds = olds_with(&h, 100, true);
        let p = plan(&b, &t, &olds, &h).unwrap();
        // PC shards only: raw 0 and the two parity shards
        assert_eq!(p.written()[&h].0, [0b1101, 0]);
        let md = p.mod_descs()[&h].clone();
        let recs = omaps(&records(&md));
        assert_eq!(recs.len(), 2);
        assert!(recs[0].clear && recs[0].header.is_none() && recs[0].ups.is_empty());
        assert!(!recs[1].clear && recs[1].header.as_deref() == Some(b"H".as_slice()));
        assert_eq!(recs[1].ups.len(), 3);
        // no record carries clear + header (UI-3)
        assert!(recs.iter().all(|r| !(r.clear && r.header.is_some())));
        let g = p.generate(&BTreeMap::new()).unwrap();
        assert!(g.txns[1].is_none(), "the nonprimary shard gets nothing");
        for sh in [0, 2, 3] {
            assert!(g.txns[sh].is_some(), "shard {sh}");
        }
        // omap bytes never enter a shard transaction
        for t in g.txns.iter().flatten() {
            let tx = Transaction::decode(&[], t, 4096).unwrap();
            assert!(tx.ops.iter().all(|o| !matches!(
                o.op,
                TxnOp::OmapSetKeys { .. } | TxnOp::OmapClear { .. } | TxnOp::OmapSetHeader { .. }
            )));
        }
    }

    #[test]
    fn truncate_to_zero_keeps_an_omap_object() {
        let h = hobj("a");
        let b = Arc::new(backend(true));
        let mk = |t: &mut Transaction| {
            let (cx, ox) = cx_obj(t, &h);
            t.push(cx, TxnOp::Truncate { oid: ox, size: 0 });
        };
        // data object without omap: stash + create (a DELETE record)
        let mut t = Transaction::new();
        mk(&mut t);
        let p = plan(&b, &t, &olds_with(&h, 8192, false), &h).unwrap();
        let ops = records(&p.mod_descs()[&h]);
        assert!(ops.iter().any(|o| matches!(o, ModOp::Delete { .. })));
        // with omap data: the normal truncate-down path, the omap survives (no DELETE)
        let mut t = Transaction::new();
        mk(&mut t);
        let p = plan(&b, &t, &olds_with(&h, 8192, true), &h).unwrap();
        let ops = records(&p.mod_descs()[&h]);
        assert!(!ops.iter().any(|o| matches!(o, ModOp::Delete { .. })));
        // omap ops in the same transaction before the truncate: the same
        let mut t = Transaction::new();
        let (cx, ox) = cx_obj(&mut t, &h);
        t.push(
            cx,
            TxnOp::OmapSetKeys {
                oid: ox,
                pairs: vec![(&b"k"[..], &b"v"[..])].into(),
            },
        );
        t.push(cx, TxnOp::Truncate { oid: ox, size: 0 });
        let p = plan(&b, &t, &olds_with(&h, 8192, false), &h).unwrap();
        let ops = records(&p.mod_descs()[&h]);
        assert!(!ops.iter().any(|o| matches!(o, ModOp::Delete { .. })));
        assert_eq!(omaps(&ops).len(), 1);
    }

    #[test]
    fn remove_drops_omap_ops_before_it_and_keeps_those_after_the_recreate() {
        let h = hobj("a");
        let mut t = Transaction::new();
        let (cx, ox) = cx_obj(&mut t, &h);
        t.push(
            cx,
            TxnOp::OmapSetKeys {
                oid: ox,
                pairs: vec![(&b"old"[..], &b"1"[..])].into(),
            },
        );
        t.push(cx, TxnOp::Remove { oid: ox });
        t.push(cx, TxnOp::Touch { oid: ox });
        t.push(
            cx,
            TxnOp::OmapSetKeys {
                oid: ox,
                pairs: vec![(&b"new"[..], &b"2"[..])].into(),
            },
        );
        let p = plan(&Arc::new(backend(true)), &t, &olds_with(&h, 0, true), &h).unwrap();
        let ops = records(&p.mod_descs()[&h]);
        assert!(ops.iter().any(|o| matches!(o, ModOp::Delete { .. })));
        let recs = omaps(&ops);
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].ups,
            vec![OmapUp::Insert(vec![(b"new".to_vec(), b"2".to_vec())])]
        );
    }

    #[test]
    fn clone_entry_carries_the_replayed_records_of_its_source() {
        let (src, dst) = (hobj("a"), {
            let mut c = hobj("a");
            c.snap = SnapId(5);
            c
        });
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(denc::types::SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId(0),
        }));
        let a = t.obj(&Ghobject::new(src.clone(), LIVE, ShardId(0)));
        let c = t.obj(&Ghobject::new(dst.clone(), LIVE, ShardId(0)));
        t.push(
            cx,
            TxnOp::Clone {
                oid: a,
                dest_oid: c,
            },
        );
        let b = Arc::new(backend(true));
        let members: Vec<u32> = (0..4).collect();
        let p = b
            .plan_write_o(
                PgT::new(1, 0),
                &t.encode_v9().unwrap(),
                &olds_with(&src, 100, true),
                &BTreeMap::from([(dst.clone(), 9)]),
                OCtx {
                    members: &members,
                    first_write: false,
                },
            )
            .unwrap();
        assert_eq!(p.clone_srcs(), vec![src.clone()]);
        // without pending records the clone entry has none
        assert!(omaps(&records(&p.mod_descs()[&dst])).is_empty());
        let rec = EcOmap {
            ups: vec![OmapUp::Insert(vec![(b"k".to_vec(), b"v".to_vec())])],
            ..Default::default()
        };
        let g = p
            .generate_omap(
                &BTreeMap::new(),
                &BTreeMap::from([(src, vec![rec.clone(), rec.clone()])]),
            )
            .unwrap();
        let ops = records(&g.mds[&dst]);
        assert!(matches!(ops[0], ModOp::Create));
        assert_eq!(omaps(&ops), vec![rec.clone(), rec]);
    }
}

// ---- alloc hint (OQ 99) ---------------------------------------------------------------------------------------

/// The client alloc hint (flags kept, sizes scaled `ceil(x / stripe) * chunk`) is in every member shard's transaction,
/// before the data write; without a hint op there is none.
#[test]
fn alloc_hint_reaches_every_member_shard() {
    let b = Arc::new(be(2, 2, 4096, "isa", "reed_sol_van")); // stripe 8192
    let h = hobj("a");
    let run = |hint: Option<(u64, u64, u32)>| {
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(denc::types::SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId(0),
        }));
        let ox = t.obj(&Ghobject::new(h.clone(), LIVE, ShardId(0)));
        t.push(cx, TxnOp::Touch { oid: ox });
        if let Some((o, w, f)) = hint {
            t.push(
                cx,
                TxnOp::SetAllocHint {
                    oid: ox,
                    expected_object_size: o,
                    expected_write_size: w,
                    flags: f,
                },
            );
        }
        t.push(
            cx,
            TxnOp::Write {
                oid: ox,
                off: 0,
                data: Data::new(&[5u8; 8192]),
            },
        );
        let members: Vec<u32> = (0..4).collect();
        let g = b
            .plan_write_o(
                PgT::new(1, 0),
                &t.encode_v9().unwrap(),
                &BTreeMap::new(),
                &BTreeMap::from([(h.clone(), 7)]),
                crate::OCtx {
                    members: &members,
                    first_write: true,
                },
            )
            .unwrap()
            .generate(&BTreeMap::new())
            .unwrap();
        g.txns
            .iter()
            .map(|x| {
                let bytes = x.as_ref().expect("all shards written");
                let t = Transaction::decode(&[], bytes, 4096).unwrap();
                let (mut hints, mut at, mut wr) = (Vec::new(), usize::MAX, usize::MAX);
                for (i, op) in t.ops.iter().enumerate() {
                    match &op.op {
                        TxnOp::SetAllocHint {
                            expected_object_size,
                            expected_write_size,
                            flags,
                            ..
                        } => {
                            at = at.min(i);
                            hints.push((*expected_object_size, *expected_write_size, *flags));
                        }
                        TxnOp::Write { .. } => wr = wr.min(i),
                        _ => {}
                    }
                }
                (hints, at, wr)
            })
            .collect::<Vec<_>>()
    };
    let with = run(Some((1 << 20, 65536, 256)));
    assert_eq!(with.len(), 4);
    for (hints, at, wr) in with {
        assert_eq!(hints, vec![(1 << 19, 32768, 256)]);
        assert!(at < wr);
    }
    for (hints, ..) in run(None) {
        assert!(hints.is_empty());
    }
}

/// `ec_pdw` accepts exactly its documented values; a typo is reported by the setter, never silently `off`.
#[test]
fn pdw_mode_parse_rejects_unknown_values() {
    assert_eq!(PdwMode::parse("off"), Some(PdwMode::Never));
    assert_eq!(PdwMode::parse("auto"), Some(PdwMode::Auto));
    assert_eq!(PdwMode::parse("always"), Some(PdwMode::Always));
    for bad in ["", "auot", "on", "true", "1", "Auto", " off"] {
        assert_eq!(PdwMode::parse(bad), None, "{bad:?}");
    }
}

/// Truncate-up plans no data at all (ec-optimized-wgen.md 1.4: no read, no will_write), also past 64 MiB: only the
/// fix-up truncates of spec 2.5 touch the shards. The op layer's `osd_max_object_size` is the only size bound.
#[test]
fn truncate_up_needs_no_fill_or_read() {
    let mut cl = Cl::new(be(2, 1, 4096, "isa", "reed_sol_van"));
    cl.op("a", &L::Write(0, bytes(1, 5000)));
    let h = hobj("a");
    let size = (64 << 20) + 4096;
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(denc::types::SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId(0),
    }));
    let ox = t.obj(&Ghobject::new(h.clone(), LIVE, ShardId(0)));
    t.push(cx, TxnOp::Truncate { oid: ox, size });
    let txn = t.encode_v9().unwrap();
    let olds = BTreeMap::from([(h.clone(), cl.old_of(&h, "a"))]);
    let plan =
        cl.b.plan_write_o(
            PgT::new(1, 0),
            &txn,
            &olds,
            &BTreeMap::from([(h.clone(), 9)]),
            OCtx {
                members: &cl.members,
                first_write: false,
            },
        )
        .unwrap();
    assert!(plan.reads().is_empty(), "a truncate-up reads nothing");
    let gen_ = plan.generate(&BTreeMap::new()).unwrap();
    for (sh, t) in gen_.txns.iter().enumerate() {
        let Some(bytes) = t else {
            continue;
        };
        let t = Transaction::decode(&[], bytes, 4096).unwrap();
        let mut trunc = None;
        for op in &t.ops {
            match &op.op {
                TxnOp::Write { .. } => panic!("shard {sh}: a truncate-up writes no data"),
                TxnOp::Truncate { size, .. } => trunc = Some(*size),
                _ => {}
            }
        }
        let raw = cl.b.mapping.iter().position(|s| *s == sh as u32).unwrap();
        let want = ec::geom::opt_shard_size(size, cl.b.s, cl.b.c, cl.b.k as u32, raw as u32);
        assert_eq!(
            trunc,
            Some(want),
            "shard {sh}: fix-up truncate to the formula size"
        );
    }
}
