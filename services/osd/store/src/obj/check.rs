// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Online consistency checker of the object layer (the L2 part of "fsck", design 6.2): every key belongs to a
//! live onode, names <-> onodes are a bijection, extents are sane (non-overlapping, inside the object, runs
//! <= 64, optionally every block checksum), fragments complete and not orphaned, flags cover existing keys,
//! per-collection counters equal a recount. The block bitmap itself is checked offline by `fsck` with
//! [`super::onode::fsck_refs`].

use super::keys::*;
use super::onode::*;
use super::shardio::ShardStore;
use super::{Result, Store};
use crate::BLK;
use crate::StoreError;
use crate::codec::blk_crc;
use crate::dev::{BlockDev, Clock};
use crate::tree::ScanCursor;
use denc::types::Ghobject;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckReport {
    pub colls: u64,
    pub onodes: u64,
    pub extents: u64,
    pub data_blocks: u64,
    pub omap_keys: u64,
    pub fragments: u64,
    /// Objects whose data lives in the tree (adr 0021 am. 14).
    pub inline_objects: u64,
    /// Refcount records (runs of shared data blocks, adr 0021 am. 32).
    pub shared_runs: u64,
    /// Omap / xattr / header values in data blocks (adr 0021 am. 46).
    pub ext_values: u64,
    /// Inconsistencies found (empty = clean).
    pub errors: Vec<String>,
}

#[derive(Default)]
struct Obj {
    on: Option<Onode>,
    named: u32,
    ext: Vec<(u64, Ext)>,
    attrs: u64,
    omap: u64,
    hdr: bool,
    /// Length of the inline data value (`d` key), if any.
    inl: Option<usize>,
    frag_main: Vec<(u8, Vec<u8>, u32)>,
    frags: HashMap<(u8, Vec<u8>), Vec<u32>>,
    /// Values in data blocks: (slot flag, pba, block crcs) (adr 0021 am. 46).
    vext: Vec<(u32, u64, Vec<u32>)>,
}

fn scan_all<D: BlockDev, C: Clock>(
    s: &mut ShardStore<D>,
    clk: &mut C,
    f: &mut dyn FnMut(&[u8], &[u8]),
) -> Result<()> {
    // past every tag below `f` and every tag from `g` up (the shard-internal `l` records); no key outgrows the tree's
    // key limit, so this bounds every tag
    let top = vec![0xffu8; s.sh.max_key() + 1];
    for (a, b) in [(&b""[..], &b"f"[..]), (&b"g"[..], &top[..])] {
        let mut cur = ScanCursor::new(a, b).listing(); // whole-store check: never displaces the working set
        while !s.tscan(clk, &mut cur, 4096, f)? {}
    }
    Ok(())
}

/// Live omap entries of every object of an LSM store (adr 0610), `(id, keys)`: candidate ids are
/// the objects of both memtables and the ids with an entry in a run, found by a walk over the runs
/// ([`crate::olsm::read::next_run_id`]). Object ids are sparse (`lsn << 12 | seq`): a fence's id span is no candidate
/// list (enumerating it listed thousands of empty ids per object and made the check of a few hundred txns take
/// minutes). An id whose entries are all tombstones yields nothing. Each candidate is listed through the engine. Merge
/// and flush keep the entry content, so a job between two walk steps or listings is harmless.
fn engine_omap<D: BlockDev, C: Clock>(
    s: &mut ShardStore<D>,
    clk: &mut C,
) -> Result<Vec<(u64, u64)>> {
    let mut ids: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    {
        let Some(o) = s.sh.state().olsm.as_ref() else {
            return Ok(Vec::new());
        };
        for m in std::iter::once(&o.active).chain(o.frozen.as_deref()) {
            ids.extend(m.sorted_ids());
        }
        #[cfg(feature = "rocksdb")]
        if let Some(mem) = &s.sh.state().rocks_mem {
            for m in std::iter::once(&mem.active).chain(mem.frozen.as_deref()) {
                ids.extend(m.sorted_ids());
            }
        }
    }
    let mut from = 0;
    loop {
        let next = loop {
            match s.sh.olsm_next_run_id(from) {
                Err(StoreError::Miss) => s.miss_wait(clk)?,
                r => break r?,
            }
        };
        let Some(id) = next else { break };
        ids.insert(id);
        let Some(n) = id.checked_add(1) else { break };
        from = n;
    }
    #[cfg(feature = "splinterdb")]
    if s.sh.splinter_selected() {
        let mut after = None;
        loop {
            let page = loop {
                match s.sh.splinter_ids(after) {
                    Err(StoreError::Miss) => s.miss_wait(clk)?,
                    r => break r?,
                }
            };
            let Some((batch, more)) = page else {
                break;
            };
            after = batch.last().copied();
            ids.extend(batch);
            if !more {
                break;
            }
        }
    }
    let mut out = Vec::new();
    #[cfg(feature = "rocksdb")]
    {
        let mut after = None;
        loop {
            let page = loop {
                match s.sh.rocks_ids(after) {
                    Err(StoreError::Miss) => s.miss_wait(clk)?,
                    r => break r?,
                }
            };
            let Some((external, more)) = page else {
                break;
            };
            after = external.last().copied();
            ids.extend(external);
            if !more {
                break;
            }
        }
    }
    for id in ids {
        let mut nk = 0u64;
        let mut from: Vec<u8> = Vec::new();
        let mut excl = false;
        loop {
            let (page, more) = loop {
                #[cfg(feature = "rocksdb")]
                let page = if s.sh.rocks_selected() {
                    s.sh.rocks_list(None, id, &from, excl, b"", OMAP_SCAN_PAGE)
                } else {
                    s.sh.olsm_list(None, id, &from, excl, b"", OMAP_SCAN_PAGE)
                };
                #[cfg(not(feature = "rocksdb"))]
                let page = s.sh.olsm_list(None, id, &from, excl, b"", OMAP_SCAN_PAGE);
                match page {
                    Err(StoreError::Miss) => s.miss_wait(clk)?,
                    r => break r?,
                }
            };
            nk += page.len() as u64;
            match (more, page.last()) {
                (true, Some((k, _))) => {
                    from = k.to_vec();
                    excl = true;
                }
                _ => break,
            }
        }
        if nk > 0 {
            out.push((id, nk));
        }
    }
    Ok(out)
}

/// Entries per engine listing of the object-layer check.
const OMAP_SCAN_PAGE: usize = 1024;

/// Does a key of `tag` have the length its id-keyed layout needs (`keys::idkey`: tag, id big endian, sub tag, then the
/// extent block / user name)? Tags with other layouts check their keys where they decode them.
fn id_key_len_ok(tag: u8, n: usize) -> bool {
    match tag {
        T_ONODE | T_HDR => n == 10,
        T_EXT => n == 14,
        T_ATTR | T_OMAP => n >= 10,
        _ => true,
    }
}

pub fn check_shard<D: BlockDev, C: Clock>(
    s: &mut ShardStore<D>,
    clk: &mut C,
    deep: bool,
) -> Result<CheckReport> {
    check_shard_plan(s, clk, deep, None)
}

/// A counter record rewritten from the recount: (finding text, key, recounted value).
pub(super) type Correction = (String, Vec<u8>, Vec<u8>);

pub(super) fn check_shard_plan<D: BlockDev, C: Clock>(
    s: &mut ShardStore<D>,
    clk: &mut C,
    deep: bool,
    mut corrections: Option<&mut Vec<Correction>>,
) -> Result<CheckReport> {
    let mut rep = CheckReport::default();
    let mut colls: BTreeMap<u64, (CollInfo, u64, i64, i64, i64, i64)> = BTreeMap::new();
    let mut coll_keys = BTreeMap::new();
    let mut names: Vec<(u64, Option<Ghobject>, u64, bool)> = Vec::new();
    let mut objs: BTreeMap<u64, Obj> = BTreeMap::new();
    let mut errs: Vec<String> = Vec::new();
    let mut recs: Vec<(u64, u32, u32)> = Vec::new();
    let mut shared: Vec<(u64, u32)> = Vec::new();
    scan_all(s, clk, &mut |k, v| {
        // a malformed key is reported, never indexed past its end
        let Some(&tag) = k.first() else {
            errs.push("empty key".into());
            return;
        };
        if !id_key_len_ok(tag, k.len()) {
            errs.push(format!(
                "bad key length {} for tag {tag:#x}: {k:?}",
                k.len()
            ));
            return;
        }
        let id_of = |k: &[u8]| onode_id_of(k).unwrap_or_default();
        match tag {
            T_COLL => match CollInfo::decode(v) {
                Some(i) => {
                    coll_keys.insert(i.id, k.to_vec());
                    colls.insert(i.id, (i, 0, 0, 0, 0, 0));
                }
                None => errs.push(format!("bad collection record {k:?}")),
            },
            T_NAME | T_LNAME => {
                if k.len() < 9 || v.len() != 8 {
                    errs.push("bad name record".into());
                } else {
                    let long = k[0] == T_LNAME;
                    names.push((
                        u64::from_be_bytes(k[1..9].try_into().unwrap()),
                        if long {
                            decode_long_key(&k[9..])
                        } else {
                            decode_sort_key(&k[9..])
                        },
                        u64::from_le_bytes(v.try_into().unwrap()),
                        long,
                    ));
                }
            }
            T_ONODE => match Onode::decode(v) {
                Some(o) => objs.entry(id_of(k)).or_default().on = Some(o),
                None => errs.push(format!("bad onode record {}", id_of(k))),
            },
            T_ATTR | T_OMAP => {
                let o = objs.entry(id_of(k)).or_default();
                if k[0] == T_ATTR {
                    o.attrs += 1;
                } else {
                    o.omap += 1;
                }
                if v.first() == Some(&V_EXT) {
                    match vext(v) {
                        Some((_, e)) => o.vext.push((
                            if k[0] == T_ATTR { F_AEXT } else { F_OEXT },
                            e.pba(),
                            (0..e.len()).map(|i| e.crc(i)).collect(),
                        )),
                        None => errs.push(format!("onode {}: bad value extent", id_of(k))),
                    }
                } else if v.first() == Some(&1) && v.len() == 9 {
                    let ty = if k[0] == T_ATTR { FT_ATTR } else { FT_OMAP };
                    o.frag_main.push((
                        ty,
                        k[10..].to_vec(),
                        u32::from_le_bytes(v[5..9].try_into().unwrap()),
                    ));
                } else if v.first() == Some(&V_CINL) {
                    if vcomp_len(v).is_none() {
                        errs.push(format!("onode {}: bad compressed value", id_of(k)));
                    }
                } else if v.first() != Some(&0) {
                    errs.push(format!("onode {}: bad value marker", id_of(k)));
                }
            }
            T_HDR => {
                let o = objs.entry(id_of(k)).or_default();
                o.hdr = true;
                if v.first() == Some(&V_EXT) {
                    match vext(v) {
                        Some((_, e)) => {
                            o.vext
                                .push((F_HEXT, e.pba(), (0..e.len()).map(|i| e.crc(i)).collect()))
                        }
                        None => errs.push(format!("onode {}: bad header value extent", id_of(k))),
                    }
                } else if v.first() == Some(&1) && v.len() == 9 {
                    o.frag_main
                        .push((3, vec![], u32::from_le_bytes(v[5..9].try_into().unwrap())));
                } else if v.first() == Some(&V_CINL) {
                    if vcomp_len(v).is_none() {
                        errs.push(format!("onode {}: bad compressed header", id_of(k)));
                    }
                } else if v.first() != Some(&0) {
                    errs.push(format!("onode {}: bad header value marker", id_of(k)));
                }
            }
            T_EXT => match Ext::decode(v) {
                Some(e) => objs
                    .entry(id_of(k))
                    .or_default()
                    .ext
                    .push((u32::from_be_bytes(k[10..14].try_into().unwrap()) as u64, e)),
                None => errs.push(format!("onode {}: bad extent record", id_of(k))),
            },
            T_INL => {
                if k.len() != 9 {
                    errs.push("bad inline data key".into());
                } else {
                    objs.entry(id_of(k)).or_default().inl = Some(v.len());
                }
            }
            T_FRAG => {
                let n = k.len();
                if n < 15 {
                    errs.push("bad fragment key".into());
                } else {
                    let idx = u32::from_be_bytes(k[n - 4..].try_into().unwrap());
                    objs.entry(id_of(k))
                        .or_default()
                        .frags
                        .entry((k[10], k[11..n - 4].to_vec()))
                        .or_default()
                        .push(idx);
                }
            }
            T_REF => match ref_decode(v) {
                Some((n, c)) if k.len() == 9 => {
                    recs.push((u64::from_be_bytes(k[1..9].try_into().unwrap()), n, c))
                }
                _ => errs.push(format!("bad refcount record {k:?}")),
            },
            T_DICT => {
                if k.len() != 2 || v.len() > DICT_MAX {
                    errs.push(format!("bad dictionary record {k:?} of {} bytes", v.len()));
                }
            }
            super::dedup::T_DEDUP => {
                if super::dedup::parse_key(k).is_none()
                    || super::dedup::RecordValue::decode(v).is_none()
                {
                    errs.push(format!("bad dedup record {k:?}"));
                }
            }
            // the mount removes what an earlier build left (`FEAT_OMAP_UNCOUNTED`)
            T_OPEND => errs.push(format!(
                "omap counter record {} of an earlier build",
                id_of(k)
            )),
            // omap LSM manifest records (adr 0610): checked with their run extents by the shard fsck
            crate::shard::T_LSM => {}
            t => errs.push(format!("unknown key tag {t:#x}")),
        }
    })?;
    rep.colls = colls.len() as u64;
    // Omap on an LSM store lives in the engine, not in the tree: add the live engine entries per object, so the same
    // flag / counter / dead-onode checks below report both formats identically.
    if s.omap_lsm {
        for (id, nk) in engine_omap(s, clk)? {
            objs.entry(id).or_default().omap += nk;
        }
    }
    let mk = s.sh.max_key();
    for (cn, g, id, long) in &names {
        if !colls.contains_key(cn) {
            errs.push(format!("name in unknown collection {cn}"));
        }
        match objs.get_mut(id) {
            Some(o) if o.on.is_some() => o.named += 1,
            _ => errs.push(format!("name points to missing onode {id}")),
        }
        match g {
            None => errs.push(format!("undecodable name key of onode {id}")),
            // an `L` key on a store without the bit: an older binary would mount it and not see the object
            Some(_) if *long && !s.long_names => {
                errs.push(format!(
                    "onode {id}: long-name key without the long_name feature"
                ));
            }
            // a short name under `L` is invisible to lookups (they try `N`), a long one under `N` cannot exist
            Some(g) if *long && name_key_len(g) <= mk => {
                errs.push(format!(
                    "onode {id}: name in the long index fits the normal one"
                ));
            }
            Some(g) if !*long && name_key_len(g) > mk => {
                errs.push(format!("onode {id}: name over the tree key limit"));
            }
            Some(_) => {}
        }
    }
    let mut owner: HashMap<u64, (u64, bool)> = HashMap::new();
    for (cn, g, id, _) in &names {
        owner.insert(
            *id,
            (
                *cn,
                g.as_ref().is_some_and(|g: &Ghobject| {
                    !g.is_pgmeta() && !g.hobj.is_temp() && g.generation == Ghobject::NO_GEN
                }),
            ),
        );
    }
    for (id, o) in &objs {
        let Some(on) = &o.on else {
            errs.push(format!("keys of dead onode {id}"));
            continue;
        };
        rep.onodes += 1;
        if o.named != 1 {
            errs.push(format!("onode {id} has {} names", o.named));
        }
        let nblk = blocks_for(on.size);
        let mut end = 0u64;
        let (mut cphys, mut corig) = (0u64, 0u64);
        for (l, e) in &o.ext {
            rep.extents += 1;
            rep.data_blocks += e.len() as u64;
            if e.shared {
                shared.push((e.pba, e.len()));
            }
            if *l < end {
                errs.push(format!("onode {id}: overlapping extents at block {l}"));
            }
            let span = e.span() as u64;
            // a run above `MAX_RUN` blocks never decodes (`Ext::decode`: "bad extent record" above)
            if *l + span > nblk {
                errs.push(format!(
                    "onode {id}: extent {l}+{span} outside object ({nblk} blocks)",
                ));
            }
            end = *l + span;
            if let Some(m) = e.comp {
                cphys += m.phys_charge(e.len());
                corig += span * BLK as u64;
                if on.flags & F_COMP == 0 {
                    errs.push(format!("onode {id}: compressed extent {l} without F_COMP"));
                }
            }
        }
        for (fl, pba, crcs) in &o.vext {
            rep.ext_values += 1;
            rep.data_blocks += crcs.len() as u64;
            if on.flags & fl == 0 {
                errs.push(format!(
                    "onode {id}: value in data blocks at {pba} without its onode flag"
                ));
            }
            if deep {
                // Media read (no cache), like the data extents below.
                let data = s.read_runs(clk, &[(*pba, crcs.len() as u32)])?;
                for (i, (b, &want)) in data[0].as_chunks::<BLK>().0.iter().zip(crcs).enumerate() {
                    let p = pba + i as u64;
                    if blk_crc(p, b) != want {
                        errs.push(format!(
                            "onode {id}: value checksum mismatch at physical block {p}"
                        ));
                    }
                }
            }
        }
        if on.flags & F_COMP != 0 && (on.comp, on.comp_orig) != (cphys, corig) {
            let m = format!(
                "onode {id}: compression counters ({}, {}) != recount ({cphys}, {corig})",
                on.comp, on.comp_orig
            );
            match corrections.as_deref_mut() {
                Some(fixes) => {
                    let mut fixed = on.clone();
                    fixed.comp = cphys;
                    fixed.comp_orig = corig;
                    fixes.push((m, onode_key(*id), fixed.encode()));
                }
                None => errs.push(m),
            }
        }
        match (on.flags & F_INLINE != 0, o.inl) {
            (true, Some(l)) => {
                rep.inline_objects += 1;
                if l == 0 || l > BLK || l as u64 > on.size {
                    errs.push(format!(
                        "onode {id}: inline data of {l} bytes in an object of {} bytes",
                        on.size
                    ));
                }
                if !o.ext.is_empty() {
                    errs.push(format!("onode {id}: inline data and extents"));
                }
            }
            (true, None) => errs.push(format!("onode {id}: F_INLINE without inline data")),
            (false, Some(_)) => errs.push(format!("onode {id}: inline data without F_INLINE")),
            (false, None) => {}
        }
        if o.omap > 0 && on.flags & F_OMAP == 0 {
            errs.push(format!("onode {id}: omap keys without F_OMAP"));
        }
        if o.hdr && on.flags & F_HDR == 0 {
            errs.push(format!("onode {id}: header without F_HDR"));
        }
        rep.omap_keys += o.omap;
        for (ty, key, n) in &o.frag_main {
            let want: Vec<u32> = (0..*n).collect();
            let mut have = o
                .frags
                .get(&(*ty, key.clone()))
                .cloned()
                .unwrap_or_default();
            have.sort_unstable();
            if have != want {
                errs.push(format!("onode {id}: fragments of {key:?} incomplete"));
            }
            let f = match *ty {
                FT_ATTR => F_AFRAG,
                FT_OMAP => F_OFRAG,
                _ => F_HFRAG,
            };
            if on.flags & f == 0 {
                errs.push(format!("onode {id}: fragmented value without frag flag"));
            }
        }
        for ((ty, key), v) in &o.frags {
            rep.fragments += v.len() as u64;
            if !o.frag_main.iter().any(|(t, k, _)| t == ty && k == key) {
                errs.push(format!("onode {id}: orphan fragments of {key:?}"));
            }
        }
        if let Some((cn, counted)) = owner.get(id)
            && *counted
            && let Some(c) = colls.get_mut(cn)
        {
            c.2 += 1;
            c.3 += on.size as i64;
            c.4 += cphys as i64;
            c.5 += corig as i64;
        }
        if deep {
            for (l, e) in &o.ext {
                let data = s.read_runs(clk, &[(e.pba, e.len())])?;
                let mut crc_bad = false;
                for i in 0..e.len() as usize {
                    if blk_crc(e.pba + i as u64, &data[0][i * BLK..(i + 1) * BLK]) != e.crcs[i] {
                        errs.push(format!(
                            "onode {id}: checksum mismatch at block {}",
                            l + i as u64
                        ));
                        crc_bad = true;
                    }
                }
                if let Some(m) = e.comp.filter(|_| !crc_bad) {
                    let b = &data[0];
                    let clen = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
                    let ok = clen > 0
                        && clen <= b.len() - 4
                        && crate::compress::Alg::from_u8(m.alg).is_some_and(|a| {
                            s.codec
                                .decompress_vec(
                                    a,
                                    &b[4..4 + clen],
                                    &mut s.decbuf,
                                    m.raw_blks as usize * BLK,
                                )
                                .is_some()
                        })
                        && crc::crc32c(0, &s.decbuf) == m.lcrc;
                    if !ok {
                        errs.push(format!(
                            "onode {id}: compressed chunk at block {l} does not decompress"
                        ));
                    }
                }
            }
        }
    }
    if !s.shared_ext && (!shared.is_empty() || !recs.is_empty()) {
        errs.push("shared extents or refcount records without the shared_ext feature".into());
    }
    if let Err(m) = crate::fsck::shared_check(&shared, &recs)
        && corrections.is_none()
    {
        errs.push(m);
    }
    rep.shared_runs = recs.len() as u64;
    for (id, (info, _, n, b, cp, co)) in &colls {
        if (info.nobj, info.nbytes, info.comp, info.comp_orig) != (*n, *b, *cp, *co) {
            let m = format!(
                "collection {id}: counters ({}, {}, {}, {}) != recount ({n}, {b}, {cp}, {co})",
                info.nobj, info.nbytes, info.comp, info.comp_orig
            );
            match corrections.as_deref_mut() {
                Some(fixes) => {
                    let mut fixed = info.clone();
                    (fixed.nobj, fixed.nbytes, fixed.comp, fixed.comp_orig) = (*n, *b, *cp, *co);
                    fixes.push((m, coll_keys[id].clone(), fixed.encode()));
                }
                None => errs.push(m),
            }
        }
    }
    if let Err(e) = s.sh.state_mut().verify_point_cache() {
        errs.push(e);
    }
    rep.errors = errs;
    Ok(rep)
}
impl<D: BlockDev, C: Clock> Store<D, C> {
    /// Check the object layer of every shard (`deep`: also verify every data block checksum).
    pub fn check(&mut self, deep: bool) -> Result<CheckReport> {
        let mut total = CheckReport::default();
        for s in &mut self.shards {
            let r = check_shard(s, &mut self.clk, deep)?;
            total.colls += r.colls;
            total.onodes += r.onodes;
            total.extents += r.extents;
            total.data_blocks += r.data_blocks;
            total.ext_values += r.ext_values;
            total.omap_keys += r.omap_keys;
            total.fragments += r.fragments;
            total.inline_objects += r.inline_objects;
            total.shared_runs += r.shared_runs;
            total.errors.extend(
                r.errors
                    .into_iter()
                    .map(|e| format!("shard {}: {e}", s.idx)),
            );
        }
        Ok(total)
    }
}
