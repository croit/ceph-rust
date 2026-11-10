// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Primary-side scrub map comparison (spec scrub.md 6.3): pick the authoritative copy of every object of a
//! chunk, classify per-shard and per-object inconsistencies, and plan the repair. Pure functions over the
//! decoded [`ScrubMap`]s; no PG state.

use denc::types::{Eversion, Hobject, SnapId};
use replwire::scrubmsgs::ScrubMap;
use replwire::{ObjectInfo, SnapSet, flag as oi_flag};
use std::collections::{BTreeMap, BTreeSet};

/// Per-shard error bits (local numbering; the rados `err_t` values are not in the spec).
pub mod err {
    pub const MISSING: u32 = 1 << 0;
    pub const STAT_ERROR: u32 = 1 << 1;
    pub const READ_ERROR: u32 = 1 << 2;
    pub const INFO_MISSING: u32 = 1 << 3;
    pub const INFO_CORRUPT: u32 = 1 << 4;
    pub const SNAPSET_MISSING: u32 = 1 << 5;
    pub const SNAPSET_CORRUPT: u32 = 1 << 6;
    /// Shard size != its own object_info size.
    pub const SIZE_INFO_MISMATCH: u32 = 1 << 7;
    /// Shard data / omap digest != the digest recorded in its own object_info.
    pub const DATA_DIGEST_INFO_MISMATCH: u32 = 1 << 8;
    pub const OMAP_DIGEST_INFO_MISMATCH: u32 = 1 << 9;
    // vs the authoritative copy
    pub const INFO_MISMATCH: u32 = 1 << 10;
    pub const SNAPSET_MISMATCH: u32 = 1 << 11;
    pub const SIZE_MISMATCH: u32 = 1 << 12;
    pub const DATA_DIGEST_MISMATCH: u32 = 1 << 13;
    pub const OMAP_DIGEST_MISMATCH: u32 = 1 << 14;
    pub const ATTR_NAME_MISMATCH: u32 = 1 << 15;
    pub const ATTR_VALUE_MISMATCH: u32 = 1 << 16;
    /// EC backend verification, distinct from comparisons between copies.
    pub const EC_HASH_MISMATCH: u32 = 1 << 17;
    pub const EC_SIZE_MISMATCH: u32 = 1 << 18;
    /// Errors only a deep scrub can find (they count as deep scrub errors).
    pub const DEEP_MASK: u32 = READ_ERROR
        | DATA_DIGEST_INFO_MISMATCH
        | OMAP_DIGEST_INFO_MISMATCH
        | DATA_DIGEST_MISMATCH
        | OMAP_DIGEST_MISMATCH
        | EC_HASH_MISMATCH
        | EC_SIZE_MISMATCH;
    /// Errors that disqualify a shard as the authoritative copy.
    pub const NOT_CANDIDATE: u32 = STAT_ERROR
        | READ_ERROR
        | INFO_MISSING
        | INFO_CORRUPT
        | SNAPSET_MISSING
        | SNAPSET_CORRUPT
        | SIZE_INFO_MISMATCH
        | DATA_DIGEST_INFO_MISMATCH
        | OMAP_DIGEST_INFO_MISMATCH
        | EC_HASH_MISMATCH
        | EC_SIZE_MISMATCH;
}

/// Per-object (shard independent) error bits.
pub mod oerr {
    pub const SIZE_TOO_LARGE: u32 = 1 << 0;
    /// The head's snapset lists a clone that exists on no shard.
    pub const CLONE_MISSING: u32 = 1 << 1;
    /// Clone not listed in the head's snapset.
    pub const CLONE_UNEXPECTED: u32 = 1 << 2;
    /// Clones without a head object.
    pub const HEADLESS_CLONE: u32 = 1 << 3;
    pub const CLONE_SIZE_MISMATCH: u32 = 1 << 4;
    /// No shard holds a usable copy: not repairable by scrub.
    pub const NO_AUTH: u32 = 1 << 5;
    /// Mode O deep scrub: the shard digests violate the CRC linearity of the code (prim spec E.6). Object level only, a
    /// deep error, never repaired from this finding.
    pub const DATA_DIGESTS: u32 = 1 << 6;
    /// Nonempty clone list with an unset snapshot sequence; trim cannot process it.
    pub const SNAPSET_SEQ: u32 = 1 << 7;
}

/// Result for one object that has any error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjReport {
    pub soid: Hobject,
    /// OSD holding the authoritative copy (`None`: no usable copy).
    pub auth: Option<i32>,
    pub auth_version: Eversion,
    pub obj_errors: u32,
    /// Shards (OSD ids) with errors. Never contains a shard without errors.
    pub shards: BTreeMap<i32, u32>,
    /// `user_version` of the authoritative object info.
    pub user_version: u64,
    /// Facts of every shard that returned the object (`list-inconsistent-obj`).
    pub info: BTreeMap<i32, ShardInfo>,
    /// Clones the head's snapset lists but no shard holds (head reports only).
    /// Raw `_` (object info) attr of the authoritative copy: `rados list-inconsistent-obj` asserts that the selected shard
    /// carries it.
    pub auth_oi: Vec<u8>,
    pub missing_clones: Vec<SnapId>,
}

/// Per-shard facts of one scrubbed object.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShardInfo {
    pub size: u64,
    pub data_digest: Option<u32>,
    pub omap_digest: Option<u32>,
}

impl ObjReport {
    /// Shards the repair can fix (an authoritative copy exists elsewhere).
    pub fn bad_shards(&self) -> Vec<i32> {
        if self.auth.is_none() {
            return vec![];
        }
        self.shards.keys().copied().collect()
    }
}

/// Totals of one compared chunk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChunkReport {
    pub objects: Vec<ObjReport>,
    pub num_objects: u64,
    pub omap_keys: u64,
    /// Logical user key + value bytes from complete, authoritative OMAP scans.
    pub omap_bytes: u64,
    /// At least one object lacks trustworthy local key lengths (peer wire maps carry value bytes only).
    pub omap_incomplete: bool,
    pub large_omap: u64,
    /// First large-omap object of the chunk `(hobject text, key count, value bytes)`: one cluster log line per chunk.
    pub large_omap_first: Option<(String, u64, u64)>,
    /// Errors by class, one per bad shard / per object error bit.
    pub shallow_errors: u64,
    pub deep_errors: u64,
    /// Of those: shard errors a repair can fix.
    pub fixable_shallow: u64,
    pub fixable_deep: u64,
}

struct Cand<'a> {
    obj: &'a replwire::scrubmsgs::ScrubObject,
    oi: Option<ObjectInfo>,
    errs: u32,
}

/// User key + value bytes of the authoritative OMAP. Key lengths are local-only metadata; a replica's value-only
/// wire count cannot establish them. A matching local OMAP remains usable when another copy wins authority due
/// to an unrelated data/snapset issue, but a stale, unreadable or different OMAP must not supply guessed key bytes.
fn logical_omap_bytes(auth: &Cand<'_>, local: Option<&Cand<'_>>) -> Option<u64> {
    let a = auth.obj;
    if !a.omap_digest_present || a.read_error || a.stat_error {
        return None;
    }
    if a.object_omap_keys == 0 && a.object_omap_bytes != 0 {
        return None;
    }
    let local = local?;
    let l = local.obj;
    if l.read_error
        || l.stat_error
        || !l.omap_digest_present
        || local.oi.as_ref()?.version != auth.oi.as_ref()?.version
        || l.omap_digest != a.omap_digest
        || l.object_omap_keys != a.object_omap_keys
        || l.object_omap_bytes != a.object_omap_bytes
    {
        return None;
    }
    a.object_omap_bytes.checked_add(l.object_omap_key_bytes?)
}

/// hobject_t text as classic logs it: `pool:bitrev-hash:nspace:key:oid:snap`.
pub(crate) fn hobj_str(h: &Hobject) -> String {
    format!(
        "{}:{:08x}:{}:{}:{}:{}",
        h.pool,
        h.hash.reverse_bits(),
        String::from_utf8_lossy(&h.nspace),
        String::from_utf8_lossy(&h.key),
        String::from_utf8_lossy(&h.oid),
        h.snap
    )
}

fn is_head(h: &Hobject) -> bool {
    h.snap == SnapId::NOSNAP
}
fn digests_recorded(oi: &ObjectInfo) -> u32 {
    (oi.flags & oi_flag::DATA_DIGEST != 0) as u32 + (oi.flags & oi_flag::OMAP_DIGEST != 0) as u32
}

/// Erasure-coded pool geometry for the comparison (shard files are `ceil(size/S) * C` bytes, their digests are shard
/// hashes, not object digests).
#[derive(Debug, Clone)]
pub struct EcGeom {
    pub stripe_width: u64,
    pub chunk: u64,
    /// Data shards: fewer good copies than this cannot repair anything.
    pub k: usize,
    /// Mode O (adr 0067): raw shard index of every OSD in the maps (per-shard sizes, nonprimary shards carry only a
    /// possibly older `_`, shard digests differ by design). `None` = legacy layout.
    pub opt: Option<BTreeMap<i32, u32>>,
    /// Mode O deep scrub: the plugin has the CRC encode/decode property (isa reed_sol_van, isa cauchy m=1), so the
    /// shard digests must satisfy the first-parity XOR identity (prim spec E.6).
    pub crc_check: bool,
}

impl EcGeom {
    fn raw(&self, osd: i32) -> Option<u32> {
        self.opt.as_ref().and_then(|m| m.get(&osd).copied())
    }
    /// Mode O nonprimary data shard (raw 1..k-1).
    fn np(&self, osd: i32) -> bool {
        self.raw(osd)
            .is_some_and(|r| r >= 1 && (r as usize) < self.k)
    }
}

fn eval<'a>(
    soid: &Hobject,
    o: &'a replwire::scrubmsgs::ScrubObject,
    deep: bool,
    ec: Option<&EcGeom>,
    osd: i32,
) -> Cand<'a> {
    let mut errs = 0;
    let mut oi = None;
    if o.stat_error {
        errs |= err::STAT_ERROR;
    }
    if o.read_error {
        errs |= err::READ_ERROR;
    }
    if o.ec_hash_mismatch {
        errs |= err::EC_HASH_MISMATCH;
    }
    if o.ec_size_mismatch {
        errs |= err::EC_SIZE_MISMATCH;
    }
    if !o.stat_error {
        match o.attrs.get(&b"_"[..]) {
            None => errs |= err::INFO_MISSING,
            Some(b) => match denc::from_slice::<ObjectInfo>(b) {
                Ok(x) => oi = Some(x),
                Err(_) => errs |= err::INFO_CORRUPT,
            },
        }
        if is_head(soid) && !ec.is_some_and(|g| g.np(osd)) {
            match o.attrs.get(&b"snapset"[..]) {
                None => errs |= err::SNAPSET_MISSING,
                Some(b) => {
                    if denc::from_slice::<SnapSet>(b).is_err() {
                        errs |= err::SNAPSET_CORRUPT;
                    }
                }
            }
        }
        if let Some(x) = &oi {
            let want = match ec {
                Some(g) if g.opt.is_some() => ec::geom::opt_shard_size(
                    x.size,
                    g.stripe_width,
                    g.chunk,
                    g.k as u32,
                    g.raw(osd).unwrap_or(0),
                ),
                Some(g) if g.stripe_width > 0 => x.size.div_ceil(g.stripe_width) * g.chunk,
                _ => x.size,
            };
            // mode O: a shard still in the legacy layout (written before allow_ec_optimizations flipped, spec 2.4)
            // keeps hinfo and may be padded to whole stripes
            let legacy = ec.is_some_and(|g| {
                g.opt.is_some()
                    && g.stripe_width > 0
                    && o.attrs.contains_key(&b"hinfo_key"[..])
                    && o.size == x.size.div_ceil(g.stripe_width) * g.chunk
            });
            if o.size != want && !legacy {
                errs |= err::SIZE_INFO_MISMATCH;
            }
            // the digest of an EC shard is a shard hash: never comparable with the object digest in object_info
            if deep && ec.is_none() {
                if x.flags & oi_flag::DATA_DIGEST != 0
                    && o.digest_present
                    && o.digest != x.data_digest
                {
                    errs |= err::DATA_DIGEST_INFO_MISMATCH;
                }
                if x.flags & oi_flag::OMAP_DIGEST != 0
                    && o.omap_digest_present
                    && o.omap_digest != x.omap_digest
                {
                    errs |= err::OMAP_DIGEST_INFO_MISMATCH;
                }
            }
        }
    }
    Cand { obj: o, oi, errs }
}

/// Prim spec E.6, mode O deep scrub: zero-extend every shard digest (crc32c seed -1 of the shard file) to the longest
/// shard and unseed it, which gives crc32c seed 0 of the zero-extended shard: GF(2)-linear in the bytes. The first
/// parity shard (raw k, coefficient row of ones) must then be the XOR of the k data shards. `false` when a needed
/// digest is absent (nothing to check; upstream decodes there through non-XOR rows, U-P5).
fn crc_linearity_broken(g: &EcGeom, cands: &[(i32, Cand)]) -> bool {
    let mut by_raw: BTreeMap<u32, (u64, u32)> = BTreeMap::new();
    for (osd, c) in cands {
        let Some(r) = g.raw(*osd) else { continue };
        if r as usize <= g.k && c.obj.digest_present && !c.obj.read_error && !c.obj.stat_error {
            by_raw.insert(r, (c.obj.size, c.obj.digest));
        }
    }
    if by_raw.len() != g.k + 1 {
        return false;
    }
    let len = by_raw.values().map(|v| v.0).max().unwrap_or(0);
    let zero = crc::crc32c_zeros(0xFFFF_FFFF, len as usize);
    let u = |(size, d): (u64, u32)| crc::crc32c_zeros(d, (len - size) as usize) ^ zero;
    let data = (0..g.k as u32).fold(0, |a, r| a ^ u(by_raw[&r]));
    data != u(by_raw[&(g.k as u32)])
}

fn user_attrs(o: &replwire::scrubmsgs::ScrubObject) -> BTreeMap<&[u8], &[u8]> {
    o.attrs
        .iter()
        .filter(|(k, _)| k.len() > 1 && k[0] == b'_')
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect()
}

fn same_group(a: &Hobject, b: &Hobject) -> bool {
    a.pool == b.pool && a.hash == b.hash && a.nspace == b.nspace && a.key == b.key && a.oid == b.oid
}

/// Compare the per-shard maps of one chunk. `maps` is keyed by OSD id; `primary` is tried first when picking
/// the authoritative copy. `deep` = the maps carry digests.
pub fn compare_chunk(
    maps: &BTreeMap<i32, ScrubMap>,
    primary: i32,
    deep: bool,
    max_object_size: u64,
) -> ChunkReport {
    compare_chunk_x(maps, primary, deep, max_object_size, None)
}

/// [`compare_chunk`] for an erasure-coded pool (`ec` = its geometry): shard sizes, shard digests and the EC flags of the
/// shard maps are judged with the EC rules (ec.md 13); an object with fewer than k good shards has no authority.
pub fn compare_chunk_ec(
    maps: &BTreeMap<i32, ScrubMap>,
    primary: i32,
    deep: bool,
    max_object_size: u64,
    ec: EcGeom,
) -> ChunkReport {
    compare_chunk_x(maps, primary, deep, max_object_size, Some(ec))
}

fn compare_chunk_x(
    maps: &BTreeMap<i32, ScrubMap>,
    primary: i32,
    deep: bool,
    max_object_size: u64,
    ec: Option<EcGeom>,
) -> ChunkReport {
    let mut rep = ChunkReport::default();
    let names: BTreeSet<&Hobject> = maps.values().flat_map(|m| m.objects.keys()).collect();
    let mut order: Vec<i32> = maps.keys().copied().collect();
    order.sort_by_key(|o| (*o != primary, *o));
    // per object: (auth osd, auth cand info) for the snapset pass
    struct AuthView {
        size: u64,
        snapset: Option<SnapSet>,
    }
    let mut auth_views: BTreeMap<&Hobject, AuthView> = BTreeMap::new();
    let mut by_obj: BTreeMap<&Hobject, ObjReport> = BTreeMap::new();

    for soid in &names {
        rep.num_objects += 1;
        let mut cands: Vec<(i32, Cand)> = Vec::new();
        let mut shard_errs: BTreeMap<i32, u32> = BTreeMap::new();
        for osd in &order {
            match maps[osd].objects.get(*soid) {
                None => {
                    shard_errs.insert(*osd, err::MISSING);
                }
                Some(o) => cands.push((*osd, eval(soid, o, deep, ec.as_ref(), *osd))),
            }
        }
        // auth: newest version, then most digests recorded, then the copy most shards agree on (so a single
        // corrupt primary does not overwrite two good replicas), primary first
        let sig = |c: &Cand| {
            (
                c.obj.size,
                c.obj.digest_present.then_some(c.obj.digest),
                c.obj.omap_digest_present.then_some(c.obj.omap_digest),
                c.obj.attrs.get(&b"_"[..]).cloned(),
                c.obj.attrs.get(&b"snapset"[..]).cloned(),
            )
        };
        let votes: Vec<usize> = cands
            .iter()
            .map(|(_, c)| {
                if c.errs & err::NOT_CANDIDATE != 0 {
                    return 0;
                }
                let s = sig(c);
                cands
                    .iter()
                    .filter(|(_, d)| d.errs & err::NOT_CANDIDATE == 0 && sig(d) == s)
                    .count()
            })
            .collect();
        let mut best: Option<usize> = None;
        for (i, (cosd, c)) in cands.iter().enumerate() {
            // mode O: a nonprimary shard is never authoritative (its `_` may be an older version)
            if c.errs & err::NOT_CANDIDATE != 0 || ec.as_ref().is_some_and(|g| g.np(*cosd)) {
                continue;
            }
            let Some(oi) = &c.oi else { continue };
            let better = match best {
                None => true,
                Some(b) => {
                    let boi = cands[b].1.oi.as_ref().expect("candidate has oi");
                    (oi.version, digests_recorded(oi), votes[i])
                        > (boi.version, digests_recorded(boi), votes[b])
                }
            };
            if better {
                best = Some(i);
            }
        }
        // EC: repairing a bad shard needs k good ones
        let best = match (best, ec.as_ref()) {
            (Some(_), Some(g))
                if cands
                    .iter()
                    .filter(|(_, c)| {
                        c.errs & err::NOT_CANDIDATE == 0 && c.errs & err::DEEP_MASK == 0
                    })
                    .count()
                    < g.k =>
            {
                None
            }
            (b, _) => b,
        };
        let mut obj_errors = 0u32;
        let (auth, auth_version) = match best {
            Some(b) => (
                Some(cands[b].0),
                cands[b]
                    .1
                    .oi
                    .as_ref()
                    .map(|o| o.version)
                    .unwrap_or_default(),
            ),
            None => {
                obj_errors |= oerr::NO_AUTH;
                rep.omap_incomplete |= deep;
                (None, Eversion::default())
            }
        };
        if let Some(b) = best {
            let a = &cands[b].1;
            let aoi = a.oi.as_ref().expect("oi");
            let logical = if ec.is_some() { aoi.size } else { a.obj.size };
            if logical > max_object_size {
                obj_errors |= oerr::SIZE_TOO_LARGE;
            }
            let a_oi_raw = a.obj.attrs.get(&b"_"[..]);
            let a_ss_raw = a.obj.attrs.get(&b"snapset"[..]);
            let a_user = user_attrs(a.obj);
            for (osd, c) in &cands {
                let mut e = c.errs;
                if *osd != cands[b].0 {
                    let np = ec.as_ref().is_some_and(|g| g.np(*osd));
                    let oi_ok = if np {
                        // mode O nonprimary shard: its `_` is the version the primary records for it (prim E.3)
                        let sh = ec.as_ref().and_then(|g| g.raw(*osd)).unwrap_or(0);
                        let want = aoi
                            .shard_versions
                            .get(&denc::types::ShardId(sh as i8))
                            .copied()
                            .unwrap_or(aoi.version);
                        c.oi.as_ref().is_some_and(|x| {
                            if want == aoi.version {
                                c.obj.attrs.get(&b"_"[..]) == a_oi_raw
                            } else {
                                x.version == want && x.size == aoi.size
                            }
                        })
                    } else {
                        c.obj.attrs.get(&b"_"[..]) == a_oi_raw
                    };
                    let opt = ec.as_ref().is_some_and(|g| g.opt.is_some());
                    if c.errs & (err::INFO_MISSING | err::INFO_CORRUPT | err::STAT_ERROR) == 0
                        && !oi_ok
                    {
                        e |= err::INFO_MISMATCH;
                    }
                    if is_head(soid)
                        && !np
                        && c.errs & (err::SNAPSET_MISSING | err::SNAPSET_CORRUPT | err::STAT_ERROR)
                            == 0
                        && c.obj.attrs.get(&b"snapset"[..]) != a_ss_raw
                    {
                        e |= err::SNAPSET_MISMATCH;
                    }
                    if !opt && !c.obj.stat_error && c.obj.size != a.obj.size {
                        e |= err::SIZE_MISMATCH;
                    }
                    if !np && !c.obj.stat_error {
                        let u = user_attrs(c.obj);
                        if u.keys().ne(a_user.keys()) {
                            e |= err::ATTR_NAME_MISMATCH;
                        } else if u != a_user {
                            e |= err::ATTR_VALUE_MISMATCH;
                        }
                    }
                    if deep && !opt {
                        if ec.is_none() {
                            if aoi.flags & oi_flag::DATA_DIGEST != 0
                                && c.obj.digest_present
                                && c.obj.digest != aoi.data_digest
                            {
                                e |= err::DATA_DIGEST_INFO_MISMATCH;
                            }
                            if aoi.flags & oi_flag::OMAP_DIGEST != 0
                                && c.obj.omap_digest_present
                                && c.obj.omap_digest != aoi.omap_digest
                            {
                                e |= err::OMAP_DIGEST_INFO_MISMATCH;
                            }
                        }
                        if c.obj.digest_present
                            && a.obj.digest_present
                            && c.obj.digest != a.obj.digest
                        {
                            e |= err::DATA_DIGEST_MISMATCH;
                        }
                        if c.obj.omap_digest_present
                            && a.obj.omap_digest_present
                            && c.obj.omap_digest != a.obj.omap_digest
                        {
                            e |= err::OMAP_DIGEST_MISMATCH;
                        }
                    }
                }
                if e != 0 {
                    shard_errs.insert(*osd, e);
                }
            }
            if deep {
                let local = cands
                    .iter()
                    .find(|(osd, _)| *osd == primary)
                    .map(|(_, c)| c);
                // EC wire maps deliberately use a sentinel OMAP digest. A remote EC authority therefore cannot
                // authenticate this primary's local key lengths, even when its counters and object version match.
                let logical_bytes = if ec.is_some() && cands[b].0 != primary {
                    None
                } else {
                    logical_omap_bytes(a, local)
                };
                let totals = logical_bytes.and_then(|bytes| {
                    Some((
                        rep.omap_keys.checked_add(a.obj.object_omap_keys)?,
                        rep.omap_bytes.checked_add(bytes)?,
                    ))
                });
                if let Some((keys, bytes)) = totals {
                    rep.omap_keys = keys;
                    rep.omap_bytes = bytes;
                } else {
                    rep.omap_incomplete = true;
                }
                if a.obj.large_omap_object_found {
                    rep.large_omap += 1;
                    if rep.large_omap_first.is_none() {
                        rep.large_omap_first = Some((
                            hobj_str(soid),
                            a.obj.large_omap_object_key_count,
                            a.obj.large_omap_object_value_size,
                        ));
                    }
                }
            }
            if deep
                && ec.as_ref().is_some_and(|g| g.crc_check && g.opt.is_some())
                && crc_linearity_broken(ec.as_ref().expect("ec"), &cands)
            {
                obj_errors |= oerr::DATA_DIGESTS;
            }
            auth_views.insert(
                soid,
                AuthView {
                    size: logical,
                    snapset: if is_head(soid) {
                        a_ss_raw.and_then(|b| denc::from_slice::<SnapSet>(b).ok())
                    } else {
                        None
                    },
                },
            );
        } else {
            for (osd, c) in &cands {
                if c.errs != 0 {
                    shard_errs.insert(*osd, c.errs);
                }
            }
        }
        let user_version = best
            .and_then(|b| cands[b].1.oi.as_ref())
            .map_or(0, |o| o.user_version);
        let info: BTreeMap<i32, ShardInfo> = cands
            .iter()
            .filter(|(_, c)| !c.obj.stat_error)
            .map(|(osd, c)| {
                (
                    *osd,
                    ShardInfo {
                        size: c.obj.size,
                        data_digest: c.obj.digest_present.then_some(c.obj.digest),
                        omap_digest: c.obj.omap_digest_present.then_some(c.obj.omap_digest),
                    },
                )
            })
            .collect();
        let auth_oi = best
            .and_then(|b| cands[b].1.obj.attrs.get(b"_".as_slice()))
            .cloned()
            .unwrap_or_default();
        by_obj.insert(
            soid,
            ObjReport {
                auth_oi,
                user_version,
                info,
                missing_clones: Vec::new(),
                soid: (*soid).clone(),
                auth,
                auth_version,
                obj_errors,
                shards: shard_errs.into_iter().filter(|(_, e)| *e != 0).collect(),
            },
        );
    }

    // snapshot metadata of head/clone groups (chunk ranges never split a group)
    let keys: Vec<&Hobject> = by_obj.keys().copied().collect();
    let mut i = 0;
    while i < keys.len() {
        let mut j = i + 1;
        while j < keys.len() && same_group(keys[i], keys[j]) {
            j += 1;
        }
        let group = &keys[i..j];
        i = j;
        let head = group.iter().find(|h| is_head(h));
        let clones: Vec<&&Hobject> = group
            .iter()
            .filter(|h| h.snap != SnapId::NOSNAP && h.snap != SnapId::SNAPDIR)
            .collect();
        if group.iter().any(|h| h.snap == SnapId::SNAPDIR) {
            continue;
        }
        match head {
            None => {
                for c in clones {
                    by_obj.get_mut(*c).expect("obj").obj_errors |= oerr::HEADLESS_CLONE;
                }
            }
            Some(h) => {
                let Some(ss) = auth_views.get(*h).and_then(|v| v.snapset.as_ref()) else {
                    continue;
                };
                if !ss.clones.is_empty() && ss.seq == 0 {
                    by_obj.get_mut(*h).expect("obj").obj_errors |= oerr::SNAPSET_SEQ;
                }
                let listed: BTreeSet<SnapId> = ss.clones.iter().copied().collect();
                for c in &ss.clones {
                    if !clones.iter().any(|x| x.snap == *c) {
                        let r = by_obj.get_mut(*h).expect("obj");
                        r.missing_clones.push(*c);
                        r.obj_errors |= oerr::CLONE_MISSING;
                    }
                }
                for c in &clones {
                    let r = by_obj.get_mut(**c).expect("obj");
                    if !listed.contains(&c.snap) {
                        r.obj_errors |= oerr::CLONE_UNEXPECTED;
                    } else {
                        let valid = ss.clone_size.get(&c.snap).is_some_and(|want| {
                            auth_views.get(**c).is_none_or(|v| *want == v.size)
                                && ss.clone_overlap.get(&c.snap).is_some_and(|overlap| {
                                    replwire::interval::checked_total(overlap)
                                        .is_some_and(|bytes| bytes <= *want)
                                })
                        });
                        if !valid {
                            r.obj_errors |= oerr::CLONE_SIZE_MISMATCH;
                        }
                    }
                }
            }
        }
    }

    for (_, r) in by_obj {
        if r.obj_errors == 0 && r.shards.is_empty() {
            continue;
        }
        for e in r.shards.values() {
            let fixable = r.auth.is_some();
            if e & err::DEEP_MASK != 0 {
                rep.deep_errors += 1;
                rep.fixable_deep += fixable as u64;
            } else {
                rep.shallow_errors += 1;
                rep.fixable_shallow += fixable as u64;
            }
        }
        rep.shallow_errors +=
            (r.obj_errors & !(oerr::NO_AUTH | oerr::DATA_DIGESTS)).count_ones() as u64;
        rep.deep_errors += u64::from(r.obj_errors & oerr::DATA_DIGESTS != 0);
        if r.shards.is_empty() && r.obj_errors & oerr::NO_AUTH != 0 {
            rep.shallow_errors += 1;
        }
        rep.objects.push(r);
    }
    rep
}

#[cfg(test)]
#[expect(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use replwire::scrubmsgs::ScrubObject;

    fn oi_bytes(h: &Hobject, ver: u64, size: u64) -> Vec<u8> {
        let mut o = ObjectInfo::new(h.clone());
        o.version = Eversion::new(1, ver);
        o.size = size;
        denc::to_vec(&o).unwrap()
    }
    fn so(h: &Hobject, ver: u64, data: &[u8]) -> ScrubObject {
        let mut s = ScrubObject {
            size: data.len() as u64,
            digest: crc::crc32c(0xFFFF_FFFF, data),
            digest_present: true,
            omap_digest: 0xFFFF_FFFF,
            omap_digest_present: true,
            ..Default::default()
        };
        s.attrs
            .insert(b"_".to_vec(), oi_bytes(h, ver, data.len() as u64));
        s.attrs.insert(
            b"snapset".to_vec(),
            denc::to_vec(&SnapSet::default()).unwrap(),
        );
        s
    }

    /// Mode O shards of a `n`-byte object as the scrub maps report them: OSD = raw shard, identity mapping.
    fn o_maps(
        tech: &str,
        k: u32,
        m: u32,
        n: usize,
        flip: Option<usize>,
    ) -> (BTreeMap<i32, ScrubMap>, EcGeom, bool) {
        let c = 4096u32;
        let be = ecback::Backend::from_parts(
            tech_plugin(tech),
            tech,
            (k, m),
            (k * c, c),
            (0..k + m).collect(),
            true,
        )
        .unwrap();
        let a = h("a");
        let data: Vec<u8> = (0..n).map(|i| (i * 31 % 251) as u8 | 1).collect();
        let plen =
            ec::geom::opt_shard_size(n as u64, u64::from(k * c), u64::from(c), k, 0) as usize;
        let mut padded = data.clone();
        padded.resize(plen.div_ceil(c as usize) * (k * c) as usize, 0);
        let enc = be.encode_stripes(&padded);
        let mut v = Vec::new();
        let mut flipped = false;
        #[expect(clippy::needless_range_loop)]
        for r in 0..(k + m) as usize {
            let size =
                ec::geom::opt_shard_size(n as u64, u64::from(k * c), u64::from(c), k, r as u32)
                    as usize;
            let mut col = enc[r][..size].to_vec();
            if flip == Some(r) && size > 0 {
                col[size / 2] ^= 0x10;
                flipped = true;
            }
            let mut o = so(&a, 3, &col);
            o.attrs.insert(b"_".to_vec(), oi_bytes(&a, 3, n as u64));
            v.push((r as i32, vec![(a.clone(), o)]));
        }
        let g = EcGeom {
            stripe_width: u64::from(k * c),
            chunk: u64::from(c),
            k: k as usize,
            opt: Some((0..(k + m) as i32).map(|o| (o, o as u32)).collect()),
            crc_check: true,
        };
        (maps(v), g, flipped)
    }
    fn tech_plugin(_t: &str) -> &'static str {
        "isa"
    }

    /// Prim spec E.6: clean O shards pass the CRC linearity check for every geometry and size; one flipped byte on a
    /// data shard or the first parity shard is an object-level deep error (never a repairable shard); a flip on parity
    /// >= 1 is not visible to it (upstream weakness UI-9).
    #[test]
    fn opt_crc_linearity() {
        for (tech, k, m) in [
            ("reed_sol_van", 2, 1),
            ("reed_sol_van", 2, 2),
            ("reed_sol_van", 3, 2),
            ("reed_sol_van", 4, 2),
            ("reed_sol_van", 6, 3),
            ("cauchy", 3, 1),
        ] {
            for n in [1usize, 5000, 3 * 4096 * k as usize + 100, 64 * 4096] {
                let (mp, g, _) = o_maps(tech, k, m, n, None);
                let r = compare_chunk_ec(&mp, 0, true, 1 << 27, g);
                assert!(
                    r.objects.is_empty(),
                    "{tech} k{k}m{m} n{n}: clean flagged {:?}",
                    r.objects
                );
                for flip in 0..(k + m) as usize {
                    let (mp, g, flipped) = o_maps(tech, k, m, n, Some(flip));
                    let r = compare_chunk_ec(&mp, 0, true, 1 << 27, g.clone());
                    if flipped && flip <= k as usize {
                        assert_eq!(r.objects.len(), 1, "{tech} k{k}m{m} n{n} flip {flip}");
                        let o = &r.objects[0];
                        assert_eq!(o.obj_errors, oerr::DATA_DIGESTS);
                        assert!(o.shards.is_empty() && o.bad_shards().is_empty());
                        assert_eq!((r.deep_errors, r.shallow_errors), (1, 0));
                    } else {
                        assert!(r.objects.is_empty(), "{tech} k{k}m{m} n{n} flip {flip}");
                    }
                    // shallow scrub and plugins without the CRC property never run it
                    assert!(
                        compare_chunk_ec(&mp, 0, false, 1 << 27, g.clone())
                            .objects
                            .is_empty()
                    );
                    let mut off = g.clone();
                    off.crc_check = false;
                    assert!(
                        compare_chunk_ec(&mp, 0, true, 1 << 27, off)
                            .objects
                            .is_empty()
                    );
                }
            }
        }
    }

    /// A missing digest (absent shard) skips the check instead of guessing.
    #[test]
    fn opt_crc_linearity_skips_without_all_digests() {
        let (mut mp, g, _) = o_maps("reed_sol_van", 3, 2, 20000, Some(0));
        mp.get_mut(&1)
            .unwrap()
            .objects
            .values_mut()
            .for_each(|o| o.digest_present = false);
        let r = compare_chunk_ec(&mp, 0, true, 1 << 27, g);
        assert!(
            r.objects
                .iter()
                .all(|o| o.obj_errors & oerr::DATA_DIGESTS == 0)
        );
    }

    fn h(n: &str) -> Hobject {
        Hobject::new(n.as_bytes(), SnapId::NOSNAP, 7, 1, b"")
    }
    fn maps(v: Vec<(i32, Vec<(Hobject, ScrubObject)>)>) -> BTreeMap<i32, ScrubMap> {
        v.into_iter()
            .map(|(o, l)| {
                (
                    o,
                    ScrubMap {
                        objects: l.into_iter().collect(),
                        ..Default::default()
                    },
                )
            })
            .collect()
    }

    #[test]
    fn clean_is_clean() {
        let a = h("a");
        let m = maps(vec![
            (0, vec![(a.clone(), so(&a, 3, b"xyz"))]),
            (1, vec![(a.clone(), so(&a, 3, b"xyz"))]),
        ]);
        let r = compare_chunk(&m, 0, true, 1 << 27);
        assert!(r.objects.is_empty());
        assert_eq!(r.num_objects, 1);
    }

    #[test]
    fn digest_mismatch_blames_the_odd_one_but_primary_wins_ties() {
        let a = h("a");
        let mut bad = so(&a, 3, b"xyz");
        bad.digest ^= 1;
        let m = maps(vec![
            (0, vec![(a.clone(), so(&a, 3, b"xyz"))]),
            (1, vec![(a.clone(), bad)]),
        ]);
        let r = compare_chunk(&m, 0, true, 1 << 27);
        assert_eq!(r.objects.len(), 1);
        assert_eq!(r.objects[0].auth, Some(0));
        assert_eq!(r.objects[0].bad_shards(), vec![1]);
        assert_eq!(r.objects[0].shards[&1], err::DATA_DIGEST_MISMATCH);
        assert_eq!((r.deep_errors, r.shallow_errors), (1, 0));
    }

    #[test]
    fn digest_info_errors_require_recorded_digest_evidence() {
        let h = h("digest-evidence");
        for recorded in [false, true] {
            let mut good = so(&h, 3, b"xyz");
            if recorded {
                let mut oi: ObjectInfo = denc::from_slice(&good.attrs[b"_".as_slice()]).unwrap();
                oi.flags |= oi_flag::DATA_DIGEST | oi_flag::OMAP_DIGEST;
                oi.data_digest = good.digest;
                oi.omap_digest = good.omap_digest;
                good.attrs.insert(b"_".to_vec(), denc::to_vec(&oi).unwrap());
            }
            let mut bad = good.clone();
            bad.digest ^= 1;
            bad.omap_digest ^= 1;
            let m = maps(vec![
                (0, vec![(h.clone(), good)]),
                (1, vec![(h.clone(), bad)]),
            ]);
            let r = compare_chunk(&m, 0, true, 1 << 27);
            assert_eq!(r.objects.len(), 1);
            let r = &r.objects[0];
            assert_eq!(r.bad_shards(), vec![1]);
            let arg = crate::scrubls::LsArg {
                interval: 0,
                get_snapsets: false,
                start_after: (vec![], vec![], 0),
                max_return: 0,
            };
            let vals = crate::scrubls::ls(std::slice::from_ref(r), 0, &|o| (o, -1), &arg).unwrap();
            let bytes = &vals[0];
            assert_eq!(
                u64::from_le_bytes(bytes[6..14].try_into().unwrap()),
                (1 << 4) | (1 << 5)
            );
            let union = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
            assert_eq!(union, if recorded { (1 << 9) | (1 << 10) } else { 0 });
        }
    }

    #[test]
    fn missing_and_size_and_stale() {
        let (a, b, c) = (h("a"), h("b"), h("c"));
        let mut short = so(&b, 3, b"xyz");
        short.size = 2;
        let m = maps(vec![
            (
                0,
                vec![
                    (a.clone(), so(&a, 3, b"xyz")),
                    (b.clone(), so(&b, 3, b"xyz")),
                    (c.clone(), so(&c, 2, b"old")),
                ],
            ),
            (
                1,
                vec![(b.clone(), short.clone()), (c.clone(), so(&c, 5, b"newer"))],
            ),
        ]);
        let r = compare_chunk(&m, 0, false, 1 << 27);
        let by = |n: &Hobject| r.objects.iter().find(|o| &o.soid == n).unwrap();
        assert_eq!(by(&a).shards[&1], err::MISSING);
        // b: replica's own size contradicts its object_info: it cannot be auth
        assert_eq!(by(&b).auth, Some(0));
        assert!(by(&b).shards[&1] & err::SIZE_INFO_MISMATCH != 0);
        // c: newest version wins even though the primary holds an older copy
        assert_eq!(by(&c).auth, Some(1));
        assert_eq!(by(&c).bad_shards(), vec![0]);
        assert!(by(&c).shards[&0] & err::INFO_MISMATCH != 0);
    }

    #[test]
    fn majority_beats_a_corrupt_primary() {
        let a = h("a");
        let mut bad = so(&a, 3, b"xyz");
        bad.digest ^= 1;
        let m = maps(vec![
            (0, vec![(a.clone(), bad)]),
            (1, vec![(a.clone(), so(&a, 3, b"xyz"))]),
            (2, vec![(a.clone(), so(&a, 3, b"xyz"))]),
        ]);
        let r = compare_chunk(&m, 0, true, 1 << 27);
        assert_eq!(r.objects[0].auth, Some(1));
        assert_eq!(r.objects[0].bad_shards(), vec![0]);
    }

    #[test]
    fn no_candidate_is_unfixable() {
        let a = h("a");
        let mut x = so(&a, 3, b"xyz");
        x.read_error = true;
        let m = maps(vec![
            (0, vec![(a.clone(), x.clone())]),
            (1, vec![(a.clone(), x)]),
        ]);
        let r = compare_chunk(&m, 0, true, 1 << 27);
        assert_eq!(r.objects[0].auth, None);
        assert!(r.objects[0].bad_shards().is_empty());
        assert!(r.objects[0].obj_errors & oerr::NO_AUTH != 0);
        assert!(r.deep_errors >= 1);
    }

    #[test]
    fn ec_scrub_rejects_verified_bad_shards_as_authority() {
        let a = h("ec-bad");
        let good = || {
            let mut o = so(&a, 3, &[0; 4096]);
            o.attrs.insert(b"_".to_vec(), oi_bytes(&a, 3, 8192));
            o
        };
        let geom = EcGeom {
            stripe_width: 8192,
            chunk: 4096,
            k: 2,
            opt: None,
            crc_check: false,
        };
        for hash_error in [false, true] {
            let mut bad = good();
            // Even newer object metadata cannot make a shard with failed physical verification usable.
            bad.attrs.insert(b"_".to_vec(), oi_bytes(&a, 4, 8192));
            bad.digest_present = false;
            bad.ec_hash_mismatch = hash_error;
            bad.ec_size_mismatch = !hash_error;
            let m = maps(vec![
                (0, vec![(a.clone(), bad.clone())]),
                (1, vec![(a.clone(), good())]),
                (2, vec![(a.clone(), good())]),
            ]);
            let r = compare_chunk_ec(&m, 0, true, 1 << 27, geom.clone());
            assert_eq!(r.objects[0].auth, Some(1));
            assert_eq!(r.objects[0].bad_shards(), vec![0]);
            // classic counts both EC verification failures as deep errors (err_t::DEEP_ERRORS)
            assert_eq!((r.deep_errors, r.shallow_errors), (1, 0));

            let arg = crate::scrubls::LsArg {
                interval: 0,
                get_snapsets: false,
                start_after: (vec![], vec![], 0),
                max_return: 0,
            };
            let vals = crate::scrubls::ls(&r.objects, 1, &|o| (o, o as i8), &arg).unwrap();
            let bytes = &vals[0];
            let union = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
            assert_eq!(union, if hash_error { 1 << 12 } else { 1 << 13 });

            let mut m = m;
            m.get_mut(&1).unwrap().objects.insert(a.clone(), bad);
            let r = compare_chunk_ec(&m, 0, true, 1 << 27, geom.clone());
            assert_eq!(r.objects[0].auth, None, "fewer than k intact shards");
            assert!(r.objects[0].bad_shards().is_empty());
            assert_eq!((r.fixable_shallow, r.fixable_deep), (0, 0));
        }
    }

    #[test]
    fn scrub_reports_zero_sequence_with_clones() {
        let head = h("zero-sequence");
        let mut clone = head.clone();
        clone.snap = SnapId(4);
        for seq in [0, 4] {
            let mut ss = SnapSet::default();
            ss.seq = seq;
            ss.clones = vec![clone.snap];
            ss.clone_size.insert(clone.snap, 1);
            ss.clone_overlap.insert(clone.snap, BTreeMap::new());
            ss.clone_snaps.insert(clone.snap, vec![clone.snap]);
            let mut ho = so(&head, 9, b"h");
            ho.attrs
                .insert(b"snapset".to_vec(), denc::to_vec(&ss).unwrap());
            let objects = vec![(head.clone(), ho), (clone.clone(), so(&clone, 5, b"c"))];
            let m = maps(vec![(0, objects.clone()), (1, objects)]);
            for deep in [false, true] {
                let r = compare_chunk(&m, 0, deep, 1 << 27);
                if seq != 0 {
                    assert!(r.objects.is_empty());
                    continue;
                }
                assert_eq!(
                    r.shallow_errors, 1,
                    "zero seq prevents snaptrim; scrub must report it"
                );
                assert_eq!(r.objects.len(), 1);
                assert_eq!(r.objects[0].soid, head);
                assert!(
                    r.objects[0].bad_shards().is_empty(),
                    "no proven repair source"
                );
                let arg = crate::scrubls::LsArg {
                    interval: 0,
                    get_snapsets: true,
                    start_after: (vec![], vec![], 0),
                    max_return: 0,
                };
                let page = crate::scrubls::ls(&r.objects, 0, &|o| (o, -1), &arg).unwrap();
                assert_eq!(page.len(), 1);
                assert_eq!(
                    u64::from_le_bytes(page[0][6..14].try_into().unwrap()),
                    1 << 3
                );
            }
        }
    }

    #[test]
    fn scrub_detects_shared_clone_metadata_damage() {
        let head = h("clone-metadata");
        let mut clone = head.clone();
        clone.snap = SnapId(4);
        for flaw in [
            "none",
            "size-missing",
            "overlap-missing",
            "overlap-too-large",
        ] {
            let mut ss = SnapSet::default();
            ss.seq = 4;
            ss.clones = vec![clone.snap];
            if flaw != "size-missing" {
                ss.clone_size.insert(clone.snap, 1);
            }
            if flaw != "overlap-missing" {
                let mut overlap = BTreeMap::new();
                if flaw == "overlap-too-large" {
                    overlap.insert(0, 2);
                }
                ss.clone_overlap.insert(clone.snap, overlap);
            }
            let mut ho = so(&head, 9, b"h");
            ho.attrs
                .insert(b"snapset".to_vec(), denc::to_vec(&ss).unwrap());
            let objects = vec![(head.clone(), ho), (clone.clone(), so(&clone, 5, b"c"))];
            let m = maps(vec![(0, objects.clone()), (1, objects)]);
            for deep in [false, true] {
                let r = compare_chunk(&m, 0, deep, 1 << 27);
                if flaw == "none" {
                    assert!(r.objects.is_empty());
                } else {
                    assert_eq!(r.objects.len(), 1, "{flaw}");
                    assert_eq!(r.objects[0].soid, clone);
                    assert_eq!(r.objects[0].obj_errors, oerr::CLONE_SIZE_MISMATCH);
                    assert!(r.objects[0].bad_shards().is_empty());
                    assert_eq!(r.shallow_errors, 1);
                }
            }
        }
    }

    #[test]
    fn snapset_clone_checks() {
        let head = h("a");
        let mut clone = head.clone();
        clone.snap = SnapId(4);
        let mut ss = SnapSet::default();
        ss.seq = 6;
        ss.clones = vec![SnapId(4), SnapId(6)];
        ss.clone_size.insert(SnapId(4), 1);
        ss.clone_overlap.insert(SnapId(4), BTreeMap::new());
        let mut ho = so(&head, 9, b"h");
        ho.attrs
            .insert(b"snapset".to_vec(), denc::to_vec(&ss).unwrap());
        let co = so(&clone, 5, b"c");
        let m = maps(vec![(0, vec![(clone.clone(), co), (head.clone(), ho)])]);
        let r = compare_chunk(&m, 0, false, 1 << 27);
        assert_eq!(r.objects.len(), 1);
        assert_eq!(r.objects[0].soid, head);
        assert!(r.objects[0].obj_errors & oerr::CLONE_MISSING != 0);
    }

    fn omap_obj(h: &Hobject, ver: u64) -> ScrubObject {
        let mut o = so(h, ver, b"xyz");
        let mut d = replwire::scrubmsgs::OmapDigest::default();
        d.entry(b"key", b"value");
        o.set_omap(&d);
        o
    }

    fn peer_copy(o: &ScrubObject) -> ScrubObject {
        denc::from_slice(&denc::to_vec(o).unwrap()).unwrap()
    }

    #[test]
    fn omap_logical_totals_count_user_keys_once() {
        let h = h("omap");
        let mut o = so(&h, 3, b"xyz");
        let mut d = replwire::scrubmsgs::OmapDigest::default();
        d.header(b"header-is-not-an-entry");
        d.entry(&[b'x'; 512], b"");
        d.entry(&[0, 0xff, b'a'], b"123456789");
        d.entry(b"", b"");
        o.set_omap(&d);
        let peer = peer_copy(&o);
        assert_eq!(peer.object_omap_key_bytes, None);
        let m = maps(vec![
            (0, vec![(h.clone(), o)]),
            (1, vec![(h.clone(), peer.clone())]),
            (2, vec![(h.clone(), peer)]),
        ]);
        let r = compare_chunk(&m, 0, true, 1 << 27);
        assert!(r.objects.is_empty());
        assert!(!r.omap_incomplete);
        assert_eq!((r.omap_keys, r.omap_bytes), (3, 524));
    }

    #[test]
    fn omap_remote_authority_accepts_matching_local_omap_after_data_corruption() {
        let h = h("omap");
        let good = omap_obj(&h, 3);
        let mut local = good.clone();
        local.digest ^= 1;
        let peer = peer_copy(&good);
        let m = maps(vec![
            (0, vec![(h.clone(), local)]),
            (1, vec![(h.clone(), peer.clone())]),
            (2, vec![(h.clone(), peer)]),
        ]);
        let r = compare_chunk(&m, 0, true, 1 << 27);
        assert_eq!(r.objects[0].auth, Some(1));
        assert!(!r.omap_incomplete);
        assert_eq!((r.omap_keys, r.omap_bytes), (1, 8));
    }

    #[test]
    fn omap_remote_authority_refuses_untrusted_local_key_lengths() {
        let h = h("omap");
        let good = omap_obj(&h, 3);
        for flaw in [
            "missing", "stale", "read", "stat", "digest", "count", "values", "unknown",
        ] {
            let mut local = good.clone();
            local.digest ^= 1; // the two intact replicas win authority
            match flaw {
                "stale" => {
                    local.attrs.insert(b"_".to_vec(), oi_bytes(&h, 2, 3));
                }
                "read" => local.read_error = true,
                "stat" => local.stat_error = true,
                "digest" => local.omap_digest ^= 1,
                "count" => local.object_omap_keys += 1,
                "values" => local.object_omap_bytes += 1,
                "unknown" => local.object_omap_key_bytes = None,
                _ => {}
            }
            let peer = peer_copy(&good);
            let mut m = maps(vec![
                (0, vec![(h.clone(), local)]),
                (1, vec![(h.clone(), peer.clone())]),
                (2, vec![(h.clone(), peer)]),
            ]);
            if flaw == "missing" {
                m.get_mut(&0).unwrap().objects.clear();
            }
            let r = compare_chunk(&m, 0, true, 1 << 27);
            assert_eq!(r.objects[0].auth, Some(1), "{flaw}");
            assert!(r.omap_incomplete, "{flaw}");
        }
    }

    #[test]
    fn omap_logical_totals_reject_counter_overflow() {
        let h = h("omap");
        let mut o = omap_obj(&h, 3);
        o.object_omap_bytes = u64::MAX;
        let m = maps(vec![(0, vec![(h, o)])]);
        let r = compare_chunk(&m, 0, true, 1 << 27);
        assert!(r.omap_incomplete);
    }

    #[test]
    fn ec_omap_logical_totals_do_not_scale_with_shard_count() {
        let (mut m, g, _) = o_maps("reed_sol_van", 2, 1, 6000, None);
        for map in m.values_mut() {
            for o in map.objects.values_mut() {
                let mut d = replwire::scrubmsgs::OmapDigest::default();
                d.entry(b"key", b"value");
                o.set_omap_stats(&d);
            }
        }
        for osd in [1, 2] {
            for o in m.get_mut(&osd).unwrap().objects.values_mut() {
                *o = peer_copy(o);
            }
        }
        let r = compare_chunk_ec(&m, 0, true, 1 << 27, g);
        assert!(r.objects.is_empty());
        assert!(!r.omap_incomplete);
        assert_eq!((r.omap_keys, r.omap_bytes), (1, 8));
    }

    #[test]
    fn ec_remote_authority_cannot_authenticate_local_omap_with_sentinel_digest() {
        let (mut m, g, _) = o_maps("reed_sol_van", 2, 1, 6000, None);
        for map in m.values_mut() {
            for o in map.objects.values_mut() {
                let mut d = replwire::scrubmsgs::OmapDigest::default();
                d.entry(b"key", b"value");
                o.set_omap_stats(&d);
            }
        }
        m.get_mut(&0)
            .unwrap()
            .objects
            .values_mut()
            .next()
            .unwrap()
            .size += 1;
        let r = compare_chunk_ec(&m, 0, true, 1 << 27, g);
        assert_eq!(r.objects[0].auth, Some(2));
        assert!(r.omap_incomplete);
    }
}
