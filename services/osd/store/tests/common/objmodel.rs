// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Reference model + random generator for L2 object transactions (semantics of `store::obj::txn`).
#![allow(dead_code)]

use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, ObjError, Store, TOp};
use store::rng::Rng;

pub fn pgc(pool: u64, seed: u32) -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(pool, seed),
        shard: ShardId::NO_SHARD,
    })
}
pub fn tmpc(pool: u64, seed: u32) -> CollT {
    CollT::PgTemp(SpgT {
        pgid: PgT::new(pool, seed),
        shard: ShardId::NO_SHARD,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct MObj {
    pub data: Vec<u8>,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    pub omap: BTreeMap<Vec<u8>, Vec<u8>>,
    pub hdr: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Model {
    pub colls: BTreeMap<CollT, BTreeMap<Ghobject, MObj>>,
}

fn counted(o: &Ghobject) -> bool {
    !o.is_pgmeta() && !o.hobj.is_temp()
}

impl Model {
    fn objs(&mut self, c: &CollT) -> Result<&mut BTreeMap<Ghobject, MObj>, ObjError> {
        self.colls.get_mut(c).ok_or(ObjError::NoColl)
    }

    /// Atomic: on error the model is unchanged.
    pub fn apply_txn(&mut self, t: &OTxn) -> Result<(), ObjError> {
        let save = self.clone();
        for op in &t.ops {
            if let Err(e) = self.apply(op) {
                *self = save;
                return Err(e);
            }
        }
        Ok(())
    }

    pub fn apply(&mut self, op: &TOp) -> Result<(), ObjError> {
        match op {
            TOp::MkColl { cid, exist_ok, .. } => {
                if self.colls.contains_key(cid) {
                    if !exist_ok {
                        return Err(ObjError::Exists);
                    }
                } else {
                    self.colls.insert(*cid, BTreeMap::new());
                }
            }
            TOp::RmColl { cid } => {
                if !self.objs(cid)?.is_empty() {
                    return Err(ObjError::NotEmpty);
                }
                self.colls.remove(cid);
            }
            TOp::SetCollBits { cid, .. } | TOp::SetCollDvTrack { cid, .. } => {
                self.objs(cid)?;
            }
            // a store-local rewrite of unchanged bytes: the content stays; dedup records are not objects
            TOp::Reformat { .. } | TOp::DedupKv { .. } => {}
            TOp::Touch { cid, oid } => {
                self.objs(cid)?.entry(oid.clone()).or_default();
            }
            TOp::Write {
                cid,
                oid,
                off,
                data,
            } => {
                let o = self.objs(cid)?.entry(oid.clone()).or_default();
                if !data.is_empty() {
                    let end = *off as usize + data.len();
                    if o.data.len() < end {
                        o.data.resize(end, 0);
                    }
                    o.data[*off as usize..end].copy_from_slice(data);
                }
            }
            TOp::Zero { cid, oid, off, len } => {
                let o = self.objs(cid)?.entry(oid.clone()).or_default();
                if *len > 0 {
                    let end = (*off + *len) as usize;
                    if o.data.len() < end {
                        o.data.resize(end, 0);
                    }
                    o.data[*off as usize..end].fill(0);
                }
            }
            TOp::Truncate { cid, oid, size } => {
                if let Some(o) = self.objs(cid)?.get_mut(oid) {
                    o.data.resize(*size as usize, 0);
                }
            }
            TOp::Remove { cid, oid } => {
                self.objs(cid)?.remove(oid);
            }
            TOp::SetAttrs { cid, oid, attrs } => {
                let o = self.objs(cid)?.entry(oid.clone()).or_default();
                for (k, v) in attrs {
                    o.xattrs.insert(k.to_vec(), v.to_vec());
                }
            }
            TOp::RmAttr { cid, oid, name } => {
                if let Some(o) = self.objs(cid)?.get_mut(oid) {
                    o.xattrs.remove(name.as_ref());
                }
            }
            TOp::RmAttrs { cid, oid } => {
                if let Some(o) = self.objs(cid)?.get_mut(oid) {
                    o.xattrs.clear();
                }
            }
            TOp::Clone { cid, src, dst } => {
                let m = self.objs(cid)?;
                let s = m.get(src).cloned().ok_or(ObjError::NoEnt)?;
                if src != dst {
                    m.insert(dst.clone(), s);
                }
            }
            TOp::CloneRange {
                cid,
                src,
                dst,
                src_off,
                len,
                dst_off,
            } => {
                let m = self.objs(cid)?;
                let s = m.get(src).cloned().ok_or(ObjError::NoEnt)?;
                let d = m.entry(dst.clone()).or_default();
                if *len > 0 {
                    let (so, l) = (*src_off as usize, *len as usize);
                    let mut chunk = vec![0u8; l];
                    let avail = s.data.len().saturating_sub(so).min(l);
                    if avail > 0 {
                        chunk[..avail].copy_from_slice(&s.data[so..so + avail]);
                    }
                    let end = *dst_off as usize + l;
                    if d.data.len() < end {
                        d.data.resize(end, 0);
                    }
                    d.data[*dst_off as usize..end].copy_from_slice(&chunk);
                }
            }
            TOp::MoveRename {
                cid,
                oid,
                dcid,
                doid,
            } => {
                self.objs(dcid)?;
                if let Some(o) = self.objs(cid)?.remove(oid) {
                    self.objs(dcid)?.insert(doid.clone(), o);
                }
            }
            TOp::OmapSetKeys { cid, oid, pairs } => {
                let o = self.objs(cid)?.entry(oid.clone()).or_default();
                for (k, v) in pairs {
                    o.omap.insert(k.to_vec(), v.to_vec());
                }
            }
            TOp::OmapSetRun { cid, oid, run } => {
                let o = self.objs(cid)?.entry(oid.clone()).or_default();
                for (k, v) in run.view().iter() {
                    o.omap.insert(k.to_vec(), v.to_vec());
                }
            }
            TOp::OmapRmKeys { cid, oid, keys } => {
                if let Some(o) = self.objs(cid)?.get_mut(oid) {
                    for k in keys {
                        o.omap.remove(k.as_ref());
                    }
                }
            }
            TOp::OmapRmKeyRange {
                cid,
                oid,
                first,
                last,
            } => {
                if let Some(o) = self.objs(cid)?.get_mut(oid) {
                    o.omap.retain(|k, _| {
                        !(k.as_slice() >= first.as_ref() && k.as_slice() < last.as_ref())
                    });
                }
            }
            TOp::OmapClear { cid, oid } => {
                if let Some(o) = self.objs(cid)?.get_mut(oid) {
                    // ObjectStore omap_clear also drops the omap header (classic behavior).
                    o.omap.clear();
                    o.hdr.clear();
                }
            }
            TOp::OmapSetHeader { cid, oid, header } => {
                self.objs(cid)?.entry(oid.clone()).or_default().hdr = header.to_vec();
            }
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for (c, m) in &self.colls {
            c.hash(&mut h);
            for (o, v) in m {
                o.hash(&mut h);
                v.hash(&mut h);
            }
        }
        h.finish()
    }

    /// (objects, bytes) that count towards collection stats.
    pub fn stats(&self, c: &CollT) -> (u64, u64) {
        self.colls[c]
            .iter()
            .filter(|(o, _)| counted(o))
            .fold((0, 0), |(n, b), (_, v)| (n + 1, b + v.data.len() as u64))
    }
}

pub fn universe(pool: i64, n: usize) -> Vec<Ghobject> {
    let names: [&[u8]; 7] = [
        b"rbd_data.1",
        b"a",
        b"a\0b",
        b"",
        b"obj",
        b"\xff\xfe",
        b"zz",
    ];
    let nss: [&[u8]; 3] = [b"", b"ns", b"n\0s"];
    let mut v = Vec::new();
    let mut r = Rng::new(0x0b1ec7);
    while v.len() < n {
        let nm = names[r.below(names.len() as u64) as usize];
        let mut oid = nm.to_vec();
        oid.extend_from_slice(format!("{}", r.below(6)).as_bytes());
        let mut h = Hobject::new(
            &oid,
            if r.pct(70) {
                SnapId::NOSNAP
            } else {
                SnapId(r.below(5))
            },
            r.next_u64() as u32,
            pool,
            nss[r.below(3) as usize],
        );
        if r.pct(15) {
            h.set_key(b"loc");
        }
        let g = Ghobject::new(h, Ghobject::NO_GEN, ShardId::NO_SHARD);
        if !v.contains(&g) {
            v.push(g);
        }
    }
    // pgmeta and a temp object
    v.push(Ghobject::pgmeta(pool, 0, ShardId::NO_SHARD));
    let mut t = Hobject::new(b"temp_1", SnapId::NOSNAP, 7, Hobject::temp_pool(pool), b"");
    t.set_key(b"");
    v.push(Ghobject::new(t, Ghobject::NO_GEN, ShardId::NO_SHARD));
    v
}

fn bytes(r: &mut Rng, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    r.fill(&mut v);
    v
}

fn rand_len(r: &mut Rng) -> u64 {
    match r.below(100) {
        0..=29 => r.range(1, 100),
        30..=44 => 4096,
        45..=54 => 4096 * r.range(1, 6),
        55..=84 => r.range(1, 20_000),
        85..=96 => r.range(4096, 70_000),
        _ => r.range(200_000, 330_000),
    }
}

fn rand_off(r: &mut Rng) -> u64 {
    match r.below(100) {
        0..=24 => 0,
        25..=44 => 4096 * r.below(10),
        45..=94 => r.below(45_000),
        _ => r.below(400_000),
    }
}

pub struct Gen {
    pub long_key: usize,
    /// Omap keys of about this length (0 = off), sharing a long prefix so they differ only in the last bytes (adr 0021
    /// am. 10: set to the store key limit minus a margin to exercise tree pages holding 1-3 entries).
    pub big_key: usize,
    pub rng: Rng,
    pub pool: i64,
    pub objs: Vec<Ghobject>,
    /// Percent of txns that are many-op storms (0 = off): big op mixes, collection create/drop storms (remove_pg of many
    /// collections in ONE txn), wipes, omap-heavy multi-record txns.
    pub storm_pct: u8,
    /// Spare collections (same shard as the group under test) the storms create and drop.
    pub storm_colls: Vec<CollT>,
    /// Payload byte cap of one storm txn (stay below ring/2, ADR 0028).
    pub storm_budget: usize,
    wide: Vec<Ghobject>,
    /// Percent of data ops with sizes/offsets around the inline threshold (adr 0021 am. 14): many small objects that grow, shrink, get zeroed and cloned across 0..4 KiB.
    pub small_pct: u8,
    /// PG metadata objects in the universe, and the percent of ops that are PG-log-like omap ops on them (append, trim
    /// by range, dup drop, info rewrite; shapes found the am. 28 interior-page bug). Empty = off.
    pub pgmeta: Vec<Ghobject>,
    pub pgmeta_pct: u8,
    /// Percent of txns that enable compression (adr 0059 am. 1) and of writes shaped for it: chunk-aligned, compressible.
    pub comp_pct: u8,
    /// Percent of omap / xattr values sized 2 KiB .. 70 KiB (data-block values, adr 0021 am. 46, around `V_EXT_MAX`).
    pub big_val_pct: u8,
    /// Percent of values (>= 40 B) shaped like structured, compressible records of three kinds (adr 0021 am. 58: inline value
    /// compression with shard templates).
    pub comp_val_pct: u8,
    /// Kinds of those records (1..=3): fewer kinds = more values per class (a class trains its dictionary from its first values).
    pub comp_val_kinds: u8,
    /// Percent of omap set ops that are sorted client batches of 64..=160 keys (`TOp::OmapSetRun`, adr 0476 omap runs):
    /// keys over the `okey` space (exact `kNN` keys and `kNN.MMM` keys inside its removal ranges), mostly small values.
    /// As many of the omap removal ops are batches of as many keys on an existing object ([`Gen::rm_batch`], runs of
    /// removals).
    pub run_pct: u8,
    seq: u64,
}

impl Gen {
    pub fn new(seed: u64, pool: i64) -> Gen {
        Gen {
            long_key: 300,
            big_key: 0,
            rng: Rng::new(seed),
            pool,
            objs: universe(pool, 22),
            storm_pct: 0,
            storm_colls: Vec::new(),
            storm_budget: 400_000,
            wide: Vec::new(),
            small_pct: 0,
            pgmeta: Vec::new(),
            big_val_pct: 0,
            comp_val_pct: 0,
            comp_val_kinds: 3,
            pgmeta_pct: 0,
            comp_pct: 0,
            run_pct: 0,
            seq: 0,
        }
    }

    /// A sorted client batch of at least 64 keys for `TOp::OmapSetRun`.
    fn run_batch(&mut self) -> store::obj::KvRunData<'static> {
        let n = self.rng.range(64, 161);
        let mut m: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        while (m.len() as u64) < n {
            let a = self.rng.below(40);
            let k = if self.rng.pct(15) {
                format!("k{a:02}").into_bytes()
            } else {
                format!("k{a:02}.{:03}", self.rng.below(400)).into_bytes()
            };
            let v = if self.rng.pct(2) {
                self.val()
            } else if self.comp_val_pct > 0 && self.rng.pct(self.comp_val_pct) {
                let l = self.rng.range(80, 400) as usize;
                self.comp_rec(l)
            } else {
                let l = self.rng.below(60) as usize;
                bytes(&mut self.rng, l)
            };
            m.insert(k, v);
        }
        let mut enc = Vec::new();
        denc::SortedKv::encode_into(
            &mut enc,
            m.len(),
            m.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        );
        store::obj::KvRunData::from_encoding(enc.into()).expect("sorted batch")
    }

    /// A client removal batch of 64..=160 keys of an object holding `have`: most of them its keys, the rest from the
    /// sorted-batch key space ([`Gen::run_batch`], mostly absent); usually a sorted set, sometimes out of order with a
    /// repeat (the store sorts it).
    fn rm_batch(&mut self, have: &[&Vec<u8>]) -> Vec<TxnBytes<'static>> {
        let n = self.rng.range(64, 161) as usize;
        let mut m: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
        while m.len() < n {
            if !have.is_empty() && self.rng.pct(70) {
                m.insert(have[self.rng.below(have.len() as u64) as usize].clone());
            } else {
                let a = self.rng.below(40);
                m.insert(format!("k{a:02}.{:03}", self.rng.below(400)).into_bytes());
            }
        }
        let mut keys: Vec<Vec<u8>> = m.into_iter().collect();
        if self.rng.pct(10) {
            keys.reverse();
            keys.push(keys[n / 2].clone());
        }
        keys.into_iter().map(TxnBytes::Owned).collect()
    }

    /// Generator with storms enabled (wide object universe).
    pub fn with_storm(seed: u64, pool: i64, pct: u8, colls: Vec<CollT>) -> Gen {
        let mut g = Gen::new(seed, pool);
        g.storm_pct = pct;
        g.storm_colls = colls;
        g.wide = universe(pool, 300);
        g
    }

    fn len(&mut self) -> u64 {
        if self.small_pct > 0 && self.rng.pct(self.small_pct) {
            return match self.rng.below(10) {
                0..=5 => self.rng.range(1, 600),
                6..=7 => self.rng.range(600, 2100),
                8 => self.rng.range(2000, 4200),
                _ => 4096,
            };
        }
        rand_len(&mut self.rng)
    }

    fn off(&mut self) -> u64 {
        if self.small_pct > 0 && self.rng.pct(self.small_pct) {
            return if self.rng.pct(55) {
                0
            } else {
                self.rng.below(2300)
            };
        }
        rand_off(&mut self.rng)
    }

    fn obj(&mut self) -> Ghobject {
        self.objs[self.rng.below(self.objs.len() as u64) as usize].clone()
    }

    fn existing(&mut self, m: &Model, c: &CollT) -> Option<Ghobject> {
        let ks: Vec<&Ghobject> = m.colls[c].keys().collect();
        if ks.is_empty() {
            None
        } else {
            Some(ks[self.rng.below(ks.len() as u64) as usize].clone())
        }
    }

    fn val(&mut self) -> Vec<u8> {
        if self.big_val_pct > 0 && self.rng.pct(self.big_val_pct) {
            let n = match self.rng.below(10) {
                0 => self.rng.range(65_000, 70_000),
                1 => 2048,
                _ => self.rng.range(2040, 20_000),
            } as usize;
            return bytes(&mut self.rng, n);
        }
        let n = match self.rng.below(100) {
            0..=69 => self.rng.below(60),
            70..=84 => self.rng.range(100, 1500),
            85..=94 => self.rng.range(1900, 6000),
            _ => self.rng.range(9000, 20_000),
        } as usize;
        if n >= 40 && self.comp_val_pct > 0 && self.rng.pct(self.comp_val_pct) {
            return self.comp_rec(n);
        }
        bytes(&mut self.rng, n)
    }

    /// A structured, compressible record of `n` bytes, one of `comp_val_kinds` kinds.
    fn comp_rec(&mut self, n: usize) -> Vec<u8> {
        let kind = self.rng.below(self.comp_val_kinds as u64) as usize;
        let phrase: &[u8] = [
            &b"owner-0001 STANDARD application/octet "[..],
            b"directory entry inode mode 0644 ",
            b"snapshot-name-with-a-long-tail ",
        ][kind];
        let mut v = vec![[8u8, 9, b'i'][kind], [3u8, 1, 0][kind]];
        while v.len() < n {
            v.extend_from_slice(phrase);
            let r = self.rng.next_u64().to_le_bytes();
            v.extend_from_slice(&r[..4]);
        }
        v.truncate(n);
        v
    }

    fn okey(&mut self) -> Vec<u8> {
        if self.big_key > 0 && self.rng.pct(8) {
            let mut k = vec![b'q'; self.big_key - 2 - self.rng.below(2) as usize * 9];
            k.extend_from_slice(format!("{:02}", self.rng.below(20)).as_bytes());
            return k;
        }
        if self.rng.pct(3) {
            return vec![b'x'; self.long_key];
        }
        format!("k{:02}", self.rng.below(40)).into_bytes()
    }

    /// One txn on the collections of `group` (all of one shard). `colls` must exist in the model.
    pub fn txn(&mut self, m: &Model, colls: &[CollT]) -> OTxn<'static> {
        if self.storm_pct > 0 && self.rng.pct(self.storm_pct) {
            let t = self.storm(m, colls);
            if !t.is_empty() {
                return t;
            }
        }
        let nops = self.rng.range(1, 5);
        self.build(m, colls, nops as usize, usize::MAX)
    }

    fn build(&mut self, m: &Model, colls: &[CollT], nops: usize, budget: usize) -> OTxn<'static> {
        let mut scratch = m.clone();
        let mut t = OTxn::new();
        let mut spent = 0usize;
        let comp_on = self.comp_pct > 0 && self.rng.pct(self.comp_pct);
        if comp_on {
            t.comp = Some(store::compress::CompSpec {
                alg: [
                    store::compress::Alg::Lz4,
                    store::compress::Alg::Zstd,
                    store::compress::Alg::Snappy,
                    store::compress::Alg::Zlib,
                ][self.rng.below(4) as usize],
                ratio_permille: 875,
                min_bytes: 8192,
                chunk_blks: [8u8, 16, 32][self.rng.below(3) as usize],
            });
        }
        for _ in 0..nops {
            if spent >= budget {
                break;
            }
            let c = colls[self.rng.below(colls.len() as u64) as usize];
            if !self.pgmeta.is_empty() && self.rng.pct(self.pgmeta_pct) {
                let op = self.pgmeta_op(c);
                if scratch.apply(&op).is_ok() {
                    spent += op_bytes(&op);
                    t.ops.push(op);
                }
                continue;
            }
            let o = self.obj();
            let op = match self.rng.below(100) {
                0..=27 if comp_on && self.rng.pct(60) => {
                    // chunk-shaped compressible write (offset on a 4 KiB multiple, often on a 32 KiB boundary)
                    let off =
                        32768 * self.rng.below(6) + 4096 * self.rng.below(2) * self.rng.below(8);
                    let n =
                        32768 * self.rng.range(1, 5) + 4096 * self.rng.below(3) * self.rng.below(8);
                    let mut data = Vec::with_capacity(n as usize);
                    while data.len() < n as usize {
                        let run = self.rng.range(8, 400) as usize;
                        let b = self.rng.below(256) as u8;
                        data.resize((data.len() + run).min(n as usize), b);
                    }
                    TOp::Write {
                        cid: c,
                        oid: o,
                        off,
                        data: TxnBytes::Owned(data),
                    }
                }
                0..=27 => {
                    let n = self.len() as usize;
                    TOp::Write {
                        cid: c,
                        oid: o,
                        off: self.off(),
                        data: TxnBytes::Owned(bytes(&mut self.rng, n)),
                    }
                }
                28..=33 => TOp::Zero {
                    cid: c,
                    oid: o,
                    off: self.off(),
                    len: self.len(),
                },
                34..=39 => TOp::Truncate {
                    cid: c,
                    oid: o,
                    size: self.off(),
                },
                40..=44 => TOp::Remove { cid: c, oid: o },
                45..=46 => TOp::Touch { cid: c, oid: o },
                47..=53 => {
                    let n = self.rng.range(0, 3);
                    let attrs = (0..n)
                        .map(|_| {
                            let k = if self.rng.pct(3) {
                                vec![b'a'; self.long_key]
                            } else {
                                format!("attr{}", self.rng.below(6)).into_bytes()
                            };
                            (TxnBytes::Owned(k), TxnBytes::Owned(self.val()))
                        })
                        .collect();
                    TOp::SetAttrs {
                        cid: c,
                        oid: o,
                        attrs,
                    }
                }
                54..=55 => TOp::RmAttr {
                    cid: c,
                    oid: o,
                    name: TxnBytes::Owned(format!("attr{}", self.rng.below(6)).into_bytes()),
                },
                56 => TOp::RmAttrs { cid: c, oid: o },
                57..=60 => {
                    let Some(s) = self.existing(&scratch, &c) else {
                        continue;
                    };
                    TOp::Clone {
                        cid: c,
                        src: s,
                        dst: o,
                    }
                }
                61..=62 => {
                    let Some(s) = self.existing(&scratch, &c) else {
                        continue;
                    };
                    TOp::CloneRange {
                        cid: c,
                        src: s,
                        dst: o,
                        src_off: self.off(),
                        len: self.len().min(60_000),
                        dst_off: self.off(),
                    }
                }
                63..=66 => {
                    let dc = colls[self.rng.below(colls.len() as u64) as usize];
                    let d = self.obj();
                    TOp::MoveRename {
                        cid: c,
                        oid: o,
                        dcid: dc,
                        doid: d,
                    }
                }
                67..=77 if self.run_pct > 0 && self.rng.pct(self.run_pct) => TOp::OmapSetRun {
                    cid: c,
                    oid: o,
                    run: self.run_batch(),
                },
                67..=77 => {
                    let n = self.rng.range(0, 5);
                    let pairs = (0..n)
                        .map(|_| (TxnBytes::Owned(self.okey()), TxnBytes::Owned(self.val())))
                        .collect();
                    TOp::OmapSetKeys {
                        cid: c,
                        oid: o,
                        pairs,
                    }
                }
                78..=82 if self.run_pct > 0 && self.rng.pct(self.run_pct) => {
                    // an object of the collection (a removal of a missing one fails)
                    let o = self.existing(&scratch, &c).unwrap_or(o);
                    let have: Vec<&Vec<u8>> = scratch
                        .colls
                        .get(&c)
                        .and_then(|os| os.get(&o))
                        .map(|mo| mo.omap.keys().collect())
                        .unwrap_or_default();
                    let keys = self.rm_batch(&have);
                    TOp::OmapRmKeys {
                        cid: c,
                        oid: o,
                        keys,
                    }
                }
                78..=82 => {
                    let n = self.rng.range(0, 4);
                    let keys = (0..n).map(|_| TxnBytes::Owned(self.okey())).collect();
                    TOp::OmapRmKeys {
                        cid: c,
                        oid: o,
                        keys,
                    }
                }
                83..=85 => {
                    let a = self.rng.below(40);
                    let b = a + self.rng.below(15);
                    TOp::OmapRmKeyRange {
                        cid: c,
                        oid: o,
                        first: TxnBytes::Owned(format!("k{a:02}").into_bytes()),
                        last: TxnBytes::Owned(format!("k{b:02}").into_bytes()),
                    }
                }
                86..=87 => TOp::OmapClear { cid: c, oid: o },
                _ => {
                    let h = if self.rng.pct(30) { vec![] } else { self.val() };
                    TOp::OmapSetHeader {
                        cid: c,
                        oid: o,
                        header: TxnBytes::Owned(h),
                    }
                }
            };
            if scratch.apply(&op).is_ok() {
                spent += op_bytes(&op);
                t.ops.push(op);
            }
        }
        t
    }

    /// A PG-log-like omap op on one of the PG metadata objects: log entry appends (rising keys), trims of the oldest
    /// entries by range, dup appends and range drops, rewrites of fixed keys, key removals, now and then a big value
    /// (fragmented).
    fn pgmeta_op(&mut self, c: CollT) -> TOp<'static> {
        let o = self.pgmeta[self.rng.below(self.pgmeta.len() as u64) as usize].clone();
        self.seq += 1;
        let s = self.seq;
        let lk = |n: u64| format!("{n:010}").into_bytes();
        let dk = |n: u64| format!("dup_{n:010}").into_bytes();
        match self.rng.below(100) {
            0..=44 => {
                let n = self.rng.range(1, 3);
                let mut pairs = Vec::new();
                for i in 0..n {
                    let vl = self.rng.range(100, 300) as usize;
                    let v = bytes(&mut self.rng, vl);
                    pairs.push((TxnBytes::Owned(lk(s * 4 + i)), TxnBytes::Owned(v)));
                }
                if self.rng.pct(30) {
                    let vl = self.rng.range(8, 600) as usize;
                    let v = bytes(&mut self.rng, vl);
                    pairs.push((TxnBytes::Owned(b"_info".to_vec()), TxnBytes::Owned(v)));
                }
                TOp::OmapSetKeys {
                    cid: c,
                    oid: o,
                    pairs,
                }
            }
            45..=59 => TOp::OmapRmKeyRange {
                cid: c,
                oid: o,
                first: TxnBytes::Owned(b"0".to_vec()),
                last: TxnBytes::Owned(lk((s * 4).saturating_sub(self.rng.range(4, 60)))),
            },
            60..=74 => {
                let pairs = (0..self.rng.range(1, 6))
                    .map(|i| {
                        let vl = self.rng.range(20, 120) as usize;
                        let v = bytes(&mut self.rng, vl);
                        (TxnBytes::Owned(dk(s * 8 + i)), TxnBytes::Owned(v))
                    })
                    .collect();
                TOp::OmapSetKeys {
                    cid: c,
                    oid: o,
                    pairs,
                }
            }
            75..=84 => TOp::OmapRmKeyRange {
                cid: c,
                oid: o,
                first: TxnBytes::Owned(b"dup_".to_vec()),
                last: TxnBytes::Owned(dk((s * 8).saturating_sub(self.rng.range(8, 80)))),
            },
            85..=92 => {
                let keys = (0..self.rng.range(1, 4))
                    .map(|_| {
                        TxnBytes::Owned(match self.rng.below(3) {
                            0 => b"_info".to_vec(),
                            1 => lk((s * 4).saturating_sub(self.rng.below(20))),
                            _ => dk((s * 8).saturating_sub(self.rng.below(40))),
                        })
                    })
                    .collect();
                TOp::OmapRmKeys {
                    cid: c,
                    oid: o,
                    keys,
                }
            }
            _ => {
                // a value too big for the inline form: this txn's ops on the object take the tree path (fragments)
                let vl = self.rng.range(3000, 9000) as usize;
                let v = bytes(&mut self.rng, vl);
                TOp::OmapSetKeys {
                    cid: c,
                    oid: o,
                    pairs: vec![(TxnBytes::Owned(b"_biginfo".to_vec()), TxnBytes::Owned(v))],
                }
            }
        }
    }

    #[allow(unused_assignments)]
    fn storm(&mut self, m: &Model, colls: &[CollT]) -> OTxn<'static> {
        let mut scratch = m.clone();
        let mut t = OTxn::new();
        let mut spent = 0usize;
        let wide = if self.wide.is_empty() {
            self.objs.clone()
        } else {
            self.wide.clone()
        };
        macro_rules! add {
            ($op:expr) => {{
                let op = $op;
                if scratch.apply(&op).is_ok() {
                    spent += op_bytes(&op);
                    t.ops.push(op);
                }
            }};
        }
        match self.rng.below(100) {
            0..=29 => {
                let n = self.rng.range(40, 250) as usize;
                return self.build(m, colls, n, self.storm_budget);
            }
            30..=59 if !self.storm_colls.is_empty() => {
                // create / fill / drop many collections in one txn (remove_pg x N)
                let k = (self.rng.range(2, 12) as usize).min(self.storm_colls.len());
                let start = self.rng.below(self.storm_colls.len() as u64) as usize;
                for j in 0..k {
                    let c = self.storm_colls[(start + j) % self.storm_colls.len()];
                    if scratch.colls.contains_key(&c) {
                        if self.rng.pct(70) {
                            let objs: Vec<Ghobject> = scratch.colls[&c].keys().cloned().collect();
                            for o in objs {
                                add!(TOp::Remove { cid: c, oid: o });
                            }
                            add!(TOp::RmColl { cid: c });
                            continue;
                        }
                    } else {
                        add!(TOp::MkColl {
                            cid: c,
                            bits: 0,
                            exist_ok: false
                        });
                    }
                    for _ in 0..self.rng.range(3, 30) {
                        if spent >= self.storm_budget {
                            break;
                        }
                        let o = wide[self.rng.below(wide.len() as u64) as usize].clone();
                        let n = self.rng.range(1, 3000) as usize;
                        let d = bytes(&mut self.rng, n);
                        add!(TOp::Write {
                            cid: c,
                            oid: o.clone(),
                            off: 0,
                            data: TxnBytes::Owned(d)
                        });
                        let pairs = (0..self.rng.range(0, 4))
                            .map(|_| (TxnBytes::Owned(self.okey()), TxnBytes::Owned(self.val())))
                            .collect();
                        add!(TOp::OmapSetKeys {
                            cid: c,
                            oid: o,
                            pairs
                        });
                    }
                }
            }
            60..=79 => {
                // wipe objects of the group (all or a part of each collection) in one txn
                for c in colls {
                    let objs: Vec<Ghobject> = scratch.colls[c].keys().cloned().collect();
                    let frac = self.rng.range(30, 100);
                    for o in objs {
                        if self.rng.below(100) < frac {
                            add!(TOp::Remove { cid: *c, oid: o });
                        }
                    }
                }
            }
            _ => {
                // omap-heavy: many big values over a few objects (multi-record WAL chain) + many key ranges
                let c = colls[self.rng.below(colls.len() as u64) as usize];
                let objs: Vec<Ghobject> = (0..self.rng.range(2, 8))
                    .map(|_| wide[self.rng.below(wide.len() as u64) as usize].clone())
                    .collect();
                for o in &objs {
                    if spent >= self.storm_budget {
                        break;
                    }
                    let n = self.rng.range(10, 60);
                    let pairs = (0..n)
                        .map(|_| {
                            let l = self.rng.range(50, 3000) as usize;
                            (
                                TxnBytes::Owned(self.okey()),
                                TxnBytes::Owned(bytes(&mut self.rng, l)),
                            )
                        })
                        .collect();
                    add!(TOp::OmapSetKeys {
                        cid: c,
                        oid: o.clone(),
                        pairs
                    });
                }
                for _ in 0..self.rng.range(0, 20) {
                    let o = objs[self.rng.below(objs.len() as u64) as usize].clone();
                    let a = self.rng.below(40);
                    let b = a + self.rng.below(20);
                    add!(TOp::OmapRmKeyRange {
                        cid: c,
                        oid: o,
                        first: TxnBytes::Owned(format!("k{a:02}").into_bytes()),
                        last: TxnBytes::Owned(format!("k{b:02}").into_bytes()),
                    });
                }
            }
        }
        t
    }
}

/// Payload bytes an op puts into the WAL record (approximate).
fn op_bytes(op: &TOp) -> usize {
    match op {
        TOp::Write { data, .. } => data.len(),
        TOp::OmapSetKeys { pairs, .. } => pairs.iter().map(|(k, v)| k.len() + v.len()).sum(),
        TOp::OmapSetRun { run, .. } => run.bytes(),
        TOp::SetAttrs { attrs, .. } => attrs.iter().map(|(k, v)| k.len() + v.len()).sum(),
        TOp::OmapSetHeader { header, .. } => header.len(),
        _ => 0,
    }
}

/// Compare the store against the model (reads, attrs, omap, listing with cursor, stats). `Err` = first diff.
pub fn verify<D: store::dev::BlockDev, C: store::dev::Clock>(
    st: &mut Store<D, C>,
    m: &Model,
    gn: &Gen,
    rng: &mut Rng,
) -> Result<(), String> {
    let e = |c: &CollT, o: &Ghobject, what: &str, x: ObjError| {
        format!(
            "{c} {:?}: {what}: {x:?}",
            String::from_utf8_lossy(&o.hobj.oid)
        )
    };
    for (c, objs) in &m.colls {
        if !st.coll_exists(c).map_err(|x| format!("{c}: {x:?}"))? {
            return Err(format!("collection {c} missing"));
        }
        let (n, b) = m.stats(c);
        let s = st.coll_stats(c).unwrap().unwrap();
        if (s.nobj, s.nbytes) != (n, b) {
            return Err(format!("{c}: stats {:?} want ({n},{b})", s));
        }
        // listing with cursor, page size 5
        let mut got = Vec::new();
        let mut cur = Ghobject::MIN();
        loop {
            let (v, next) = st
                .list(c, &cur, None, 5)
                .map_err(|x| format!("list: {x:?}"))?;
            got.extend(v);
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }
        let want: Vec<Ghobject> = objs.keys().cloned().collect();
        if got != want {
            return Err(format!(
                "{c}: listing differs: got {} want {}",
                got.len(),
                want.len()
            ));
        }
        let all: std::collections::BTreeSet<&Ghobject> =
            gn.objs.iter().chain(objs.keys()).collect();
        for o in all {
            let st_o = st.stat(c, o).map_err(|x| e(c, o, "stat", x))?;
            match (objs.get(o), st_o) {
                (None, None) => {}
                (None, Some(_)) => {
                    return Err(format!(
                        "{c} {:?}: should not exist",
                        String::from_utf8_lossy(&o.hobj.oid)
                    ));
                }
                (Some(_), None) => {
                    return Err(format!(
                        "{c} {:?}: missing",
                        String::from_utf8_lossy(&o.hobj.oid)
                    ));
                }
                (Some(mo), Some(s)) => {
                    if s.size != mo.data.len() as u64 {
                        return Err(format!(
                            "{c} {:?}: size {} want {}",
                            String::from_utf8_lossy(&o.hobj.oid),
                            s.size,
                            mo.data.len()
                        ));
                    }
                    let d = st
                        .read(c, o, 0, s.size + 10)
                        .map_err(|x| e(c, o, "read", x))?;
                    if d != mo.data {
                        let at = d.iter().zip(&mo.data).position(|(a, b)| a != b);
                        return Err(format!(
                            "{c} {:?}: data differs (first diff {at:?}, len {} vs {})",
                            String::from_utf8_lossy(&o.hobj.oid),
                            d.len(),
                            mo.data.len()
                        ));
                    }
                    if !mo.data.is_empty() {
                        let off = rng.below(mo.data.len() as u64);
                        let len = rng.range(1, 9000);
                        let d = st
                            .read(c, o, off, len)
                            .map_err(|x| e(c, o, "read slice", x))?;
                        let end = (off + len).min(mo.data.len() as u64);
                        if d != mo.data[off as usize..end as usize] {
                            return Err(format!(
                                "{c} {:?}: slice {off}+{len} differs",
                                String::from_utf8_lossy(&o.hobj.oid)
                            ));
                        }
                    }
                    if st.getattrs(c, o).map_err(|x| e(c, o, "getattrs", x))? != mo.xattrs {
                        return Err(format!(
                            "{c} {:?}: xattrs differ",
                            String::from_utf8_lossy(&o.hobj.oid)
                        ));
                    }
                    if let Some((k, v)) = mo.xattrs.iter().next()
                        && st
                            .getattr(c, o, k)
                            .map_err(|x| e(c, o, "getattr", x))?
                            .as_ref()
                            != Some(v)
                    {
                        return Err("getattr differs".into());
                    }
                    if st.omap_all(c, o).map_err(|x| e(c, o, "omap", x))? != mo.omap {
                        return Err(format!(
                            "{c} {:?}: omap differs",
                            String::from_utf8_lossy(&o.hobj.oid)
                        ));
                    }
                    if st.omap_header(c, o).map_err(|x| e(c, o, "hdr", x))? != mo.hdr {
                        return Err(format!(
                            "{c} {:?}: omap header differs",
                            String::from_utf8_lossy(&o.hobj.oid)
                        ));
                    }
                    // paged omap iteration
                    let mut from = Vec::new();
                    let mut all = BTreeMap::new();
                    loop {
                        let (kv, more) = st
                            .omap_iter(c, o, &from, 3)
                            .map_err(|x| e(c, o, "omap_iter", x))?;
                        for (k, v) in &kv {
                            all.insert(k.clone(), v.clone());
                        }
                        if !more {
                            break;
                        }
                        from = kv.last().unwrap().0.clone();
                        from.push(0);
                    }
                    if all != mo.omap {
                        return Err(format!(
                            "{c} {:?}: paged omap differs",
                            String::from_utf8_lossy(&o.hobj.oid)
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
