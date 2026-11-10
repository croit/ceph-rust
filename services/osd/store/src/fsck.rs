// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Offline consistency check of the durable (checkpointed) state of a shard (design 6.2): walks the tree from
//! the newest valid root slot and verifies
//!  * every page: crc, magic, self address, level, heap accounting, parent's child crc;
//!  * keys strictly ascending inside pages and inside the fences given by the parent separators;
//!  * every page address inside the meta region, referenced exactly once;
//!  * the persisted meta bitmap == the set of reachable pages (no leaks, no double use);
//!  * the persisted data bitmap (`f` chunks): popcount == root counter, no bits outside the region, and - if the
//!    caller supplies `refs` (L2: which extents does this key/value reference?) - exactly the referenced
//!    extents (no leaks, no double allocation, nothing referenced but free).
//!
//! WAL records after `ckpt_lsn` are NOT applied (run it on an image right after mount, or on a crash image to
//! check that whatever root survived is consistent).

use crate::alloc::CHUNK_BYTES;
use crate::dev::{BlockDev, Clock};
use crate::layout::{
    MetaGeom, RootSlot, ShardDir, Superblock, read_meta_image_checked, read_root, read_super,
};
use crate::page::{self, LEAF};
use crate::sio::Sio;
use std::collections::HashSet;

/// Data block references the L2 hook reports (adr 0021 am. 32).
#[derive(Clone, Debug, Default)]
pub struct Refs {
    /// Exclusive extents `(blk, nblk)`: referenced exactly once, no refcount record covers them.
    pub ext: Vec<(u64, u32)>,
    /// Extents flagged as possibly shared `(blk, nblk)`.
    pub shared: Vec<(u64, u32)>,
    /// Refcount records `(blk, nblk, owners)`.
    pub recs: Vec<(u64, u32, u32)>,
}

/// L2 hook: add the data references of a key/value pair.
pub type RefFn<'a> = &'a dyn Fn(&[u8], &[u8], &mut Refs);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsckReport {
    pub shard: u32,
    pub root_seq: u64,
    pub ckpt_lsn: u64,
    pub height: u8,
    pub pages: u64,
    pub leaves: u64,
    pub interior: u64,
    /// Detached subtree pages still allocated (lazy free, adr 0021 am. 18)
    pub dead_pages: u64,
    /// Delta pages and leaves that carry deltas (adr 0021 am. 19).
    pub delta_pages: u64,
    pub delta_leaves: u64,
    /// Interior pages in the compact format (the rest is slotted, adr 0021 am. 13)
    pub interior_compact: u64,
    pub empty_leaves: u64,
    /// Leaves and keys by the tag byte of the first key of the leaf (lab statistics; L2 tags, adr 0021).
    pub tag_leaves: std::collections::BTreeMap<u8, (u64, u64)>,
    pub keys: u64,
    /// Bytes of keys + values (user keyspace).
    pub kv_bytes: u64,
    pub data_blocks_used: u64,
    pub meta_pages_used: u64,
}

struct Item {
    addr: u64,
    crc: u32,
    level: u8,
    lo: Vec<u8>,
    hi: Option<Vec<u8>>,
}

/// Check all shards of the device.
pub fn fsck<D: BlockDev, C: Clock>(
    dev: &mut D,
    clk: &mut C,
    refs: Option<RefFn>,
) -> Result<Vec<FsckReport>, String> {
    let (sb, dirs) = read_super(dev, clk).map_err(|e| format!("superblock: {e}"))?;
    dirs.iter()
        .map(|d| fsck_shard(dev, clk, &sb, d, refs))
        .collect()
}

/// Shared refcount runs `(physical block, block count, owner count)`.
pub type RefRecords = Vec<(u64, u32, u32)>;

/// Corrections derived from the complete durable ownership census.
#[derive(Clone, Debug, Default)]
pub struct RepairPlan {
    pub shard: u32,
    pub leaks: Vec<(u64, u32)>,
    pub missing: Vec<(u64, u32)>,
    /// False-free portions of persisted metadata cells; publish with cell_take + checkpoint, never data CRCs.
    pub missing_meta: Vec<(u64, u32)>,
    /// Exclusive owner keys to relocate, in key order. Metadata and shared references keep their blocks.
    pub relocate: Vec<Vec<u8>>,
    /// Old and rebuilt shared refcount records; applied only when different.
    pub refs: Option<(RefRecords, RefRecords)>,
    pub used_counter: Option<(u64, u64)>,
    pub meta_counter: Option<(u64, u64)>,
}

/// Validate every shard before returning corrections. Object/value aliases are relocated by owner key;
/// refcounts derive only from flagged owners. Structural damage is refused.
pub fn repair_plan<D: BlockDev, C: Clock>(
    dev: &mut D,
    clk: &mut C,
    refs: RefFn,
) -> Result<Vec<RepairPlan>, String> {
    let (sb, dirs) = read_super(dev, clk).map_err(|e| e.to_string())?;
    dirs.iter()
        .map(|dir| repair_plan_shard(dev, clk, &sb, dir, refs))
        .collect()
}

/// [`repair_plan`] of one shard (the repair mount fences its false frees before replay, `ShardCfg::repair_fence`).
pub fn repair_plan_shard<D: BlockDev, C: Clock>(
    dev: &mut D,
    clk: &mut C,
    sb: &Superblock,
    dir: &ShardDir,
    refs: RefFn,
) -> Result<RepairPlan, String> {
    let mut plan = RepairPlan {
        shard: dir.shard,
        ..Default::default()
    };
    walk_shard(dev, clk, sb, dir, Some(refs), Some(&mut plan))?;
    Ok(plan)
}

pub fn fsck_shard<D: BlockDev, C: Clock>(
    dev: &mut D,
    clk: &mut C,
    sb: &Superblock,
    dir: &ShardDir,
    refs: Option<RefFn>,
) -> Result<FsckReport, String> {
    walk_shard(dev, clk, sb, dir, refs, None)
}

fn walk_shard<D: BlockDev, C: Clock>(
    dev: &mut D,
    clk: &mut C,
    sb: &Superblock,
    dir: &ShardDir,
    refs: Option<RefFn>,
    mut repair: Option<&mut RepairPlan>,
) -> Result<FsckReport, String> {
    let e = |m: String| format!("shard {}: {m}", dir.shard);
    let root: RootSlot = read_root(dev, clk, dir).map_err(|x| e(format!("root slot: {x}")))?;
    let geom = MetaGeom::new(dir, sb.node_size).map_err(|x| e(format!("meta geometry: {x}")))?;
    let psz = sb.node_size as usize;
    let mut rep = FsckReport {
        shard: dir.shard,
        root_seq: root.seq,
        ckpt_lsn: root.ckpt_lsn,
        height: root.tree_height,
        ..Default::default()
    };

    // ---- meta bitmap (legacy fixed image or elastic image in meta pages)
    let img = read_meta_image_checked(dev, clk, sb, &geom, &root, repair.is_none())
        .map_err(|x| e(format!("meta bitmap: {x}")))?;
    let bm = img.meta;
    let dead = img.dead;
    let mut io = Sio::new(dev, clk);
    let page_idx = |addr: u64| {
        geom.page_idx(addr)
            .or_else(|| bm.cell_page_idx(addr, geom.bpp))
    };
    let mut reach: HashSet<u32> = HashSet::new();
    // the elastic image's own pages are meta pages in use
    for &a in &img.blob_pages {
        let Some(ix) = page_idx(a) else {
            return Err(e(format!("meta image page {a} outside the meta space")));
        };
        if !reach.insert(ix) || !bm.get(ix) {
            return Err(e(format!("meta image page {a} double used or not marked")));
        }
    }

    // ---- leaf deltas (adr 0021 am. 19): every delta page is a valid used meta page; the chains they hold are applied
    // to the base leaves below, so keys, extents and key order are judged on the logical (durable) state
    let mut chains = crate::delta::ChainSet::new();
    for sg in &img.segs {
        let reqs: Vec<(u64, u32)> = sg.pages.iter().map(|p| (p.0, geom.bpp as u32)).collect();
        let bufs = io
            .read(&reqs)
            .map_err(|x| e(format!("read delta pages: {x}")))?;
        for (&(addr, crc), b) in sg.pages.iter().zip(&bufs) {
            let Some(ix) = page_idx(addr) else {
                return Err(e(format!("delta page {addr} outside the meta region")));
            };
            if !reach.insert(ix) || !bm.get(ix) {
                return Err(e(format!("delta page {addr} double used or not marked")));
            }
            page::validate_delta(b, psz, addr).map_err(|m| e(format!("delta page {addr}: {m}")))?;
            if page::stored_crc(b) != crc {
                return Err(e(format!("delta page {addr}: crc differs from directory")));
            }
            for (a, c, w, ops) in
                crate::delta::parse_page(b).map_err(|m| e(format!("delta page {addr}: {m}")))?
            {
                chains
                    .load(a, c, sg.seq, w, ops)
                    .map_err(|m| e(format!("delta page {addr}: {m}")))?;
            }
            rep.delta_pages += 1;
        }
    }
    let (mut dtmp, mut dents) = (vec![0u8; psz], page::Ents::default());

    // ---- tree walk, level by level
    let mut alloc = dir.new_alloc();
    let mut extents = Refs::default();
    let mut owners = Vec::new();
    let mut lsm_runs: Vec<Vec<u8>> = Vec::new();
    if let Some((addr, crc, height)) = root.tree_ref().map_err(|m| e(m.into()))? {
        let mut front = vec![Item {
            addr,
            crc,
            level: height - 1,
            lo: Vec::new(),
            hi: None,
        }];
        let mut key = Vec::new();
        while !front.is_empty() {
            let reqs: Vec<(u64, u32)> = front.iter().map(|i| (i.addr, geom.bpp as u32)).collect();
            for it in &front {
                let Some(ix) = page_idx(it.addr) else {
                    return Err(e(format!(
                        "page address {} outside the meta region",
                        it.addr
                    )));
                };
                if !reach.insert(ix) {
                    return Err(e(format!("page {} referenced twice", it.addr)));
                }
                if !bm.get(ix) {
                    return Err(e(format!(
                        "reachable page {} not marked in meta bitmap",
                        it.addr
                    )));
                }
            }
            let bufs = io.read(&reqs).map_err(|x| e(format!("read pages: {x}")))?;
            let mut next = Vec::new();
            for (it, b) in front.iter().zip(&bufs) {
                page::validate(b, psz, it.addr).map_err(|m| e(format!("page {}: {m}", it.addr)))?;
                if page::stored_crc(b) != it.crc {
                    return Err(e(format!(
                        "page {}: crc differs from parent reference",
                        it.addr
                    )));
                }
                if page::level(b) != it.level {
                    return Err(e(format!(
                        "page {}: level {} expected {}",
                        it.addr,
                        page::level(b),
                        it.level
                    )));
                }
                rep.pages += 1;
                // a leaf with deltas is judged as it reads: base image + chain
                let applied;
                let b = if page::kind(b) == LEAF && chains.get(it.addr).is_some() {
                    let mut c = b.clone();
                    chains
                        .apply(it.addr, it.crc, &mut c, &mut dtmp, &mut dents)
                        .map_err(|m| e(format!("leaf {}: {m}", it.addr)))?;
                    if chains.chain_bytes(it.addr, it.crc) > 0 {
                        rep.delta_leaves += 1;
                    }
                    applied = c;
                    &applied
                } else {
                    b
                };
                let n = page::nslots(b);
                let leaf = page::kind(b) == LEAF;
                let mut prev: Option<Vec<u8>> = None;
                if leaf {
                    rep.leaves += 1;
                    if n > 0 {
                        let mut k0 = Vec::new();
                        page::key_into(b, 0, &mut k0);
                        rep.tag_leaves
                            .entry(k0.first().copied().unwrap_or(0))
                            .or_default()
                            .0 += 1;
                    }
                    if n == 0 {
                        rep.empty_leaves += 1;
                    }
                } else {
                    rep.interior += 1;
                    rep.interior_compact += page::is_compact(b) as u64;
                    if n == 0 {
                        return Err(e(format!("interior page {} has no children", it.addr)));
                    }
                }
                for i in 0..n {
                    key.clear();
                    if leaf || i > 0 {
                        page::key_into(b, i, &mut key);
                        if key.as_slice() < it.lo.as_slice()
                            || it.hi.as_deref().is_some_and(|h| key.as_slice() >= h)
                        {
                            return Err(e(format!("page {}: key outside parent fences", it.addr)));
                        }
                        if prev.as_deref().is_some_and(|p| p >= key.as_slice()) {
                            return Err(e(format!("page {}: keys not ascending", it.addr)));
                        }
                        prev = Some(key.clone());
                    }
                    if leaf {
                        let v = page::leaf_ent(b, i).1;
                        if key.first() == Some(&b'f') {
                            if key.len() != 9 || v.len() != CHUNK_BYTES {
                                return Err(e("malformed bitmap chunk key".into()));
                            }
                            let ci = u64::from_be_bytes(key[1..].try_into().unwrap());
                            alloc
                                .load_chunk(ci, v)
                                .map_err(|m| e(format!("chunk {ci}: {m}")))?;
                        } else {
                            rep.keys += 1;
                            let t = rep
                                .tag_leaves
                                .entry(key.first().copied().unwrap_or(0))
                                .or_default();
                            t.1 += 1;
                            rep.kv_bytes += (key.len() + v.len()) as u64;
                            if let Some(r) = refs {
                                let first = extents.ext.len();
                                r(&key, v, &mut extents);
                                for &(b, n) in &extents.ext[first..] {
                                    owners.push((b, n, key.clone()));
                                }
                                // omap LSM runs (adr 0610): their blocks are listed in the run metadata on the device;
                                // a run key of another length would hide its blocks (repair would see them leaked)
                                if key.starts_with(&crate::shard::LSM_RUN_PREFIX) {
                                    if key.len() != 10 {
                                        return Err(e(format!(
                                            "malformed omap LSM run key {key:02x?}"
                                        )));
                                    }
                                    lsm_runs.push(v.to_vec());
                                }
                            }
                        }
                    } else {
                        let (ca, cc) = page::int_child(b, i);
                        let lo = if i == 0 { it.lo.clone() } else { key.clone() };
                        let hi = if i + 1 < n {
                            let mut k = Vec::new();
                            page::key_into(b, i + 1, &mut k);
                            Some(k)
                        } else {
                            it.hi.clone()
                        };
                        next.push(Item {
                            addr: ca,
                            crc: cc,
                            level: it.level - 1,
                            lo,
                            hi,
                        });
                    }
                }
            }
            front = next;
        }
    }
    // ---- detached subtrees (lazy free, adr 0021 am. 18): still allocated, reachable only through the dead list; their
    // keys are deleted (not counted), their pages must be valid and are used meta pages exactly once
    let mut dfront: Vec<(u64, u32, u8)> = dead.iter().map(|d| (d.addr, d.crc, d.level)).collect();
    while !dfront.is_empty() {
        let reqs: Vec<(u64, u32)> = dfront.iter().map(|i| (i.0, geom.bpp as u32)).collect();
        for &(addr, _, _) in &dfront {
            let Some(ix) = page_idx(addr) else {
                return Err(e(format!(
                    "detached page address {addr} outside the meta region"
                )));
            };
            if !reach.insert(ix) {
                return Err(e(format!("detached page {addr} referenced twice")));
            }
            if !bm.get(ix) {
                return Err(e(format!("detached page {addr} not marked in meta bitmap")));
            }
        }
        let bufs = io
            .read(&reqs)
            .map_err(|x| e(format!("read detached pages: {x}")))?;
        let mut next = Vec::new();
        for (&(addr, crc, level), b) in dfront.iter().zip(&bufs) {
            page::validate(b, psz, addr).map_err(|m| e(format!("detached page {addr}: {m}")))?;
            if page::stored_crc(b) != crc || page::level(b) != level {
                return Err(e(format!(
                    "detached page {addr}: crc/level differs from its reference"
                )));
            }
            rep.dead_pages += 1;
            if level > 0 {
                for i in 0..page::nslots(b) {
                    let (ca, cc) = page::int_child(b, i);
                    next.push((ca, cc, level - 1));
                }
            }
        }
        dfront = next;
    }
    rep.meta_pages_used = reach.len() as u64;
    if reach.len() as u32 != bm.used() {
        return Err(e(format!(
            "meta bitmap marks {} pages, tree reaches {} (leak; {} tree pages, {} delta pages, {} detached pages, {} image pages)",
            bm.used(),
            reach.len(),
            rep.pages,
            rep.delta_pages,
            rep.dead_pages,
            img.blob_pages.len()
        )));
    }
    if bm.used() as u64 != root.meta_pages_used {
        if let Some(plan) = repair.as_deref_mut() {
            plan.meta_counter = Some((root.meta_pages_used, u64::from(bm.used())));
        } else {
            return Err(e("meta page counter in root slot".into()));
        }
    }

    // ---- data bitmap
    rep.data_blocks_used = alloc.n_alloc();
    if alloc.n_alloc() != root.used_blocks {
        if let Some(plan) = repair.as_deref_mut() {
            plan.used_counter = Some((root.used_blocks, alloc.n_alloc()));
        } else {
            return Err(e(format!(
                "bitmap chunks hold {} blocks, root slot says {}",
                alloc.n_alloc(),
                root.used_blocks
            )));
        }
    }
    // meta cells are allocated extents of the data region (not referenced by any object)
    let cells = bm.physical_extents(geom.bpp);
    for &(start, blocks) in &cells {
        if repair.is_none() && !alloc.is_allocated(start, blocks) {
            return Err(e(format!(
                "meta cell at block {start} is not allocated in the data bitmap"
            )));
        }
    }
    for v in lsm_runs {
        let m = crate::olsm::manifest::RunDesc::decode(&v)
            .and_then(|d| d.load(&mut crate::shard::SioRead(&mut io)))
            .map_err(|x| e(format!("omap LSM run: {x}")))?;
        extents.ext.extend(m.extents());
    }
    if refs.is_some() {
        let mut want = dir.new_alloc();
        for &(start, blocks) in &cells {
            if !want.in_region(start, blocks) || !want.is_unallocated(start, blocks) {
                return Err(e(format!(
                    "meta extent {start}+{blocks} is invalid or overlaps"
                )));
            }
            want.apply_alloc_replay(start, blocks);
        }
        // Stable owner selection independent of tree shape: shared / metadata first, then exclusive key order.
        if repair.is_some() {
            owners.sort_by(|a, b| a.2.cmp(&b.2));
            let rebuilt = shared_recount(&extents.shared).map_err(e)?;
            // Only a count mismatch is a finding: the daemon splits runs at every adjustment, so a consistent record
            // layout may differ from the canonical rebuild and stays as it is.
            if shared_check(&extents.shared, &extents.recs).is_err() {
                let mut old = extents.recs.clone();
                old.sort_unstable();
                repair.as_deref_mut().unwrap().refs = Some((old, rebuilt.clone()));
            }
            for (b, n) in shared_check(&extents.shared, &rebuilt).map_err(e)? {
                if !want.in_region(b, n) || !want.is_unallocated(b, n) {
                    return Err(e(format!(
                        "shared extent {b}+{n} overlaps metadata or is outside region"
                    )));
                }
                want.apply_alloc_replay(b, n);
            }
            // Engine-owned immutable runs keep their storage; repair never rewrites engine internals.
            for &(b, n) in &extents.ext[owners.len()..] {
                if !want.in_region(b, n) || !want.is_unallocated(b, n) {
                    return Err(e(format!(
                        "omap engine extent {b}+{n} overlaps another reference"
                    )));
                }
                want.apply_alloc_replay(b, n);
            }
            for (b, n, key) in &owners {
                if !want.in_region(*b, *n) {
                    return Err(e(format!("extent {b}+{n} outside the data region")));
                }
                if !want.is_unallocated(*b, *n) {
                    repair.as_deref_mut().unwrap().relocate.push(key.clone());
                }
                want.apply_alloc_replay(*b, *n);
            }
        }
        for &(b, n) in &extents.ext {
            if !want.in_region(b, n) {
                return Err(e(format!("extent {b}+{n} outside the data region")));
            }
            if repair.is_none() && !want.is_unallocated(b, n) {
                let conflicting: Vec<_> = owners
                    .iter()
                    .filter(|(start, len, _)| {
                        u128::from(*start) < u128::from(b) + u128::from(n)
                            && u128::from(b) < u128::from(*start) + u128::from(*len)
                    })
                    .map(|(start, len, key)| format!("key {key:02x?} extent {start}+{len}"))
                    .collect();
                return Err(e(format!(
                    "extent {b}+{n} double-referenced ({}; includes metadata if overlapping a meta cell)",
                    conflicting.join(", ")
                )));
            }
            want.apply_alloc_replay(b, n);
        }
        if (!extents.shared.is_empty() || !extents.recs.is_empty())
            && sb.features & crate::layout::FEAT_SHARED_EXT == 0
        {
            return Err(e("shared extents without the shared_ext feature".into()));
        }
        // shared blocks: owners == refcount record, each block once in the bitmap, never also exclusive; the records
        // are disk values, so the sweep needs every run inside the data region first (an unchecked one would be
        // compared against flagged extents of another range instead of being named)
        for &(b, n) in &extents.shared {
            if !want.in_region(b, n) {
                return Err(e(format!("shared extent {b}+{n} outside the data region")));
            }
        }
        for &(b, n, _) in &extents.recs {
            if !want.in_region(b, n) {
                return Err(e(format!(
                    "refcount record {b}+{n} outside the data region"
                )));
            }
        }
        let shared_runs = if repair.is_some() {
            Vec::new()
        } else {
            shared_check(&extents.shared, &extents.recs).map_err(e)?
        };
        for (b, n) in shared_runs {
            if !want.is_unallocated(b, n) {
                return Err(e(format!(
                    "shared extent {b}+{n} also referenced exclusively"
                )));
            }
            want.apply_alloc_replay(b, n);
        }
        for i in 0..alloc.n_words() {
            let (x, y) = (alloc.alloc_word(i), want.alloc_word(i));
            if x != y {
                if let Some(plan) = repair.as_deref_mut() {
                    let mut missing = y & !x;
                    while missing != 0 {
                        let blk =
                            alloc.phys_of(i as u64 * 64 + u64::from(missing.trailing_zeros()));
                        let at = cells.partition_point(|&(start, _)| start <= blk);
                        let in_cell = at > 0 && blk - cells[at - 1].0 < u64::from(cells[at - 1].1);
                        let target = if in_cell {
                            &mut plan.missing_meta
                        } else {
                            &mut plan.missing
                        };
                        push_leak(target, &alloc, blk);
                        missing &= missing - 1;
                    }
                    let mut bits = x & !y;
                    while bits != 0 {
                        let bit = bits.trailing_zeros();
                        push_leak(
                            &mut plan.leaks,
                            &alloc,
                            alloc.phys_of(i as u64 * 64 + u64::from(bit)),
                        );
                        bits &= bits - 1;
                    }
                } else {
                    let bit = (x ^ y).trailing_zeros() as u64;
                    let blk = alloc.phys_of(i as u64 * 64 + bit);
                    return Err(e(format!(
                        "block {blk}: bitmap says {}, extents say {}",
                        x >> bit & 1,
                        y >> bit & 1
                    )));
                }
            }
        }
    }
    Ok(rep)
}

/// Append leaked block `blk` (ascending) to `leaks`, extending the last run only while the run stays one allocator
/// segment: physically adjacent blocks of two segments (elastic chunks, an expansion behind the base region) map to
/// unrelated relative ranges, and a txn free must name a range of one segment (`State::check`).
fn push_leak(leaks: &mut Vec<(u64, u32)>, alloc: &crate::alloc::Alloc, blk: u64) {
    if let Some((start, len)) = leaks.last_mut()
        && *start + u64::from(*len) == blk
        && *len < u32::MAX
        && alloc.in_region(*start, *len + 1)
    {
        *len += 1;
    } else {
        leaks.push((blk, 1));
    }
}

/// Refcount consistency (adr 0021 am. 32): `shared` = extents flagged `EXT_SHARED`, `recs` = refcount records
/// `(blk, nblk, owners)`. Every block must have exactly as many flagged owners as its record says (no record = one
/// owner), records must not overlap and never cover a block without a flagged owner. Returns the distinct block runs
/// the flagged extents occupy (each at most one extent long), for the bitmap comparison.
pub fn shared_check(
    shared: &[(u64, u32)],
    recs: &[(u64, u32, u32)],
) -> Result<Vec<(u64, u32)>, String> {
    // events: (block, owner delta, record owner delta, record cover delta)
    let mut ev: Vec<(u64, i64, i64, i64)> = Vec::with_capacity(2 * (shared.len() + recs.len()));
    // the runs are disk values: a run whose end wraps is corrupt, never an event below its own start
    let end = |b: u64, n: u32| {
        b.checked_add(n as u64)
            .ok_or_else(|| format!("block {b}+{n} wraps the block address space"))
    };
    for &(b, n) in shared.iter() {
        ev.push((b, 1, 0, 0));
        ev.push((end(b, n)?, -1, 0, 0));
    }
    for &(b, n, c) in recs.iter() {
        ev.push((b, 0, c as i64, 1));
        ev.push((end(b, n)?, 0, -(c as i64), -1));
    }
    ev.sort_unstable_by_key(|x| x.0);
    let (mut k, mut r, mut rn) = (0i64, 0i64, 0i64);
    let mut out = Vec::new();
    let mut i = 0;
    while i < ev.len() {
        let at = ev[i].0;
        while i < ev.len() && ev[i].0 == at {
            k += ev[i].1;
            r += ev[i].2;
            rn += ev[i].3;
            i += 1;
        }
        let Some(&(next, ..)) = ev.get(i) else { break };
        let len = next - at;
        if rn > 1 {
            return Err(format!("refcount records overlap at block {at}"));
        }
        if rn == 1 && k != r {
            return Err(format!(
                "blocks {at}+{len}: {k} owners, refcount record says {r}"
            ));
        }
        if rn == 0 && k > 1 {
            return Err(format!(
                "blocks {at}+{len}: {k} owners without a refcount record"
            ));
        }
        if k > 0 {
            out.push((at, len as u32));
        }
    }
    Ok(out)
}

/// Rebuild refcount runs from the flagged references alone (offline repair): one run per stretch between extent
/// boundaries with two or more owners (one owner needs no record). Each run lies inside one flagged extent, so it is
/// never longer than an extent.
pub fn shared_recount(shared: &[(u64, u32)]) -> Result<RefRecords, String> {
    let mut events = std::collections::BTreeMap::<u64, i64>::new();
    for &(b, n) in shared {
        let end = b
            .checked_add(u64::from(n))
            .filter(|_| n > 0)
            .ok_or_else(|| format!("shared extent {b}+{n} is empty or wraps"))?;
        *events.entry(b).or_default() += 1;
        *events.entry(end).or_default() -= 1;
    }
    let (mut count, mut prev, mut out) = (0i64, 0u64, Vec::new());
    for (at, delta) in events {
        if count > 1 {
            let owners = u32::try_from(count).map_err(|_| "shared owner count overflow")?;
            out.push((prev, (at - prev) as u32, owners));
        }
        count += delta;
        prev = at;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Leaked runs never cross an allocator segment, even where two segments are physically adjacent: the free
    /// txn of such a run would be refused as outside the data region and repair could never finish.
    #[test]
    fn leak_runs_split_at_segment_boundaries() {
        let a = crate::alloc::Alloc::with_extents(1000, 100, &[(1100, 100)]);
        let mut leaks = Vec::new();
        for b in 1097..1103 {
            push_leak(&mut leaks, &a, b);
        }
        push_leak(&mut leaks, &a, 1150);
        assert_eq!(leaks, vec![(1097, 3), (1100, 3), (1150, 1)]);
        assert!(leaks.iter().all(|&(b, n)| a.in_region(b, n)));
    }

    /// The rebuild counts every flagged owner per block, splits at extent boundaries and drops single owners; its
    /// result always passes `shared_check`.
    #[test]
    fn shared_recount_counts_flagged_owners() {
        let shared = [(100, 10), (100, 10), (105, 5), (200, 4)];
        let r = shared_recount(&shared).unwrap();
        assert_eq!(r, vec![(100, 5, 2), (105, 5, 3)]);
        assert!(shared_check(&shared, &r).is_ok());
        assert!(shared_recount(&[(1, 0)]).is_err());
        assert!(shared_recount(&[(u64::MAX, 2)]).is_err());
    }
}
