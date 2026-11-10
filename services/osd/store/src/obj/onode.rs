// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Onode, collection and extent value formats (little endian).

use crate::BLK;

/// Onode flag bits. They only ever say "keys of this kind MAY exist" so that removal and clears can skip
/// range deletes on the common (RBD data) objects.
pub const F_OMAP: u32 = 1;
/// Some omap value is stored as fragments.
pub const F_OFRAG: u32 = 2;
/// Some xattr value is stored as fragments.
pub const F_AFRAG: u32 = 4;
/// Omap header key may exist.
pub const F_HDR: u32 = 8;
/// Header stored as fragments.
pub const F_HFRAG: u32 = 16;
/// The object's data (all of block 0, the rest is zeros) is the value of key `d` + id, not a device block. Unlike
/// the other flags this one is exact: set iff the key exists (checked by `Store::check`); such an object has no
/// extents and `len(d) <= size`.
pub const F_INLINE: u32 = 32;
/// Omap counters of earlier builds (adr 0021 am. 15): set iff the record carries them (format 2, or the 16-byte slot of
/// formats 3 and 4). Records of this build never have it: `Onode::decode` drops it with the counters
/// (`FEAT_OMAP_UNCOUNTED`), the next write of the onode stores format 1, or 3 / 4 with a zero slot.
pub const F_OCNT: u32 = 64;
/// Some extent of the object MAY be compressed (adr 0059 am. 1): mutations that cut a chunk look for one only then.
pub const F_COMP: u32 = 128;
/// Some omap / xattr / header value MAY live in data blocks (adr 0021 am. 46, `FEAT_EXT_VALUE`): removals of such entries
/// look at each record to free its blocks.
pub const F_OEXT: u32 = 256;
pub const F_AEXT: u32 = 512;
pub const F_HEXT: u32 = 1024;
/// The record carries `data_version` (format 4, adr 0593-dedup-deep-scrub-reformat). Exact like `F_INLINE`: set iff the record
/// is format 4. Set at the first data change of an object in a collection with data version tracking (`CollInfo::dv_on`);
/// never cleared while the object lives. Store with `FEAT_DEDUP`.
pub const F_DVER: u32 = 2048;
/// Value record forms (first byte of an omap / xattr / header record): inline bytes, fragment marker, data-block value
/// (adr 0021 am. 46: `[2][len u32][plain extent record]`).
pub const V_INLINE: u8 = 0;
pub const V_FRAG: u8 = 1;
pub const V_EXT: u8 = 2;
/// Inline zstd-compressed user omap value (adr 0021 am. 58, 59): `[5][class][len][zstd block]`.
pub const V_CINL: u8 = 5;
/// Largest value stored as data blocks (larger ones keep the fragment form).
pub const V_EXT_MAX: usize = 16 * BLK;
/// Stage-internal value form (adr 0021 am. 46): staged for data blocks, not flushed yet: `[3][len u32][pending index u32]`.
/// Never reaches the tree (`flush_ext_vals` replaces it).
pub const V_PEND: u8 = 3;

/// Length of the value a stored omap/xattr record holds (inline value, fragment marker, data-block reference).
pub fn raw_vlen(raw: &[u8]) -> u64 {
    match raw.first() {
        Some(&V_INLINE) => raw.len() as u64 - 1,
        Some(&V_CINL) => vcomp_len(raw).unwrap_or(0) as u64,
        Some(&V_FRAG) if raw.len() == 9 => u32::from_le_bytes(raw[1..5].try_into().unwrap()) as u64,
        Some(&V_EXT | &V_PEND) if raw.len() >= 5 => {
            u32::from_le_bytes(raw[1..5].try_into().unwrap()) as u64
        }
        _ => 0,
    }
}

/// The data-block form of a value record: (value length, its plain extent). `None` for the other forms or a malformed
/// record.
pub fn vext(raw: &[u8]) -> Option<(usize, ExtRaw<'_>)> {
    if raw.first() != Some(&V_EXT) || raw.len() < 5 {
        return None;
    }
    let len = u32::from_le_bytes(raw[1..5].try_into().unwrap()) as usize;
    let e = ExtRaw::new(&raw[5..])?;
    (e.comp().is_none()
        && !e.shared()
        && len <= e.len() as usize * BLK
        && len > (e.len() as usize - 1) * BLK)
        .then_some((len, e))
}

/// Encode the data-block form of a value of `len` bytes in blocks `[pba, pba + crcs.len())`.
pub fn vext_encode(len: usize, pba: u64, crcs: &[u32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(15 + 4 * crcs.len());
    v.push(V_EXT);
    v.extend_from_slice(&(len as u32).to_le_bytes());
    v.extend_from_slice(&ext_encode_c(pba, crcs, None));
    v
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Onode {
    pub size: u64,
    pub flags: u32,
    /// Physical bytes of the compressed extents and the logical bytes they stand for; carried with `F_COMP` only.
    pub comp: u64,
    pub comp_orig: u64,
    /// Data changes of this object (touch, write, zero, truncate, clone / clone_range destination) counted while its
    /// collection tracked them; carried with `F_DVER` only. With the onode id it names one data state of the object.
    pub dv: u64,
}

impl Onode {
    /// Format 1 (13 bytes), format 3 (45 bytes, `F_COMP`) with the compression counters, format 4 (53 bytes, `F_DVER`)
    /// with the compression counters (zero without `F_COMP`) and the data version: objects without compression and
    /// tracking keep the short record. Formats 3 and 4 keep the zero slot of the omap counters of earlier builds; format
    /// 2 (those counters alone) is read, never written.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert_eq!(self.flags & F_OCNT, 0, "no omap counters");
        let fmt = Self::format_of(self.flags);
        let mut v = crate::vpool::take([13, 29, 45, 53][fmt as usize - 1]);
        v.push(fmt);
        v.extend_from_slice(&self.size.to_le_bytes());
        v.extend_from_slice(&self.flags.to_le_bytes());
        if fmt >= 3 {
            v.extend_from_slice(&[0; 16]);
            v.extend_from_slice(&self.comp.to_le_bytes());
            v.extend_from_slice(&self.comp_orig.to_le_bytes());
        }
        if fmt == 4 {
            v.extend_from_slice(&self.dv.to_le_bytes());
        }
        v
    }
    /// Record format the flags call for: the record carries exactly the fields its flags announce.
    fn format_of(flags: u32) -> u8 {
        if flags & F_DVER != 0 {
            4
        } else if flags & F_COMP != 0 {
            3
        } else if flags & F_OCNT != 0 {
            2
        } else {
            1
        }
    }
    pub fn decode(b: &[u8]) -> Option<Onode> {
        let fmt = *b.first()?;
        if !(1..=4).contains(&fmt) || b.len() < [13, 29, 45, 53][fmt as usize - 1] {
            return None;
        }
        let flags = u32::from_le_bytes(b[9..13].try_into().unwrap());
        // the flags and the format must agree (a v1 record never claims counters)
        if fmt != Self::format_of(flags) {
            return None;
        }
        let g = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        // the omap counters of an earlier build are dropped (`FEAT_OMAP_UNCOUNTED`)
        Some(Onode {
            size: g(1),
            flags: flags & !F_OCNT,
            comp: if fmt >= 3 { g(29) } else { 0 },
            comp_orig: if fmt >= 3 { g(37) } else { 0 },
            dv: if fmt == 4 { g(45) } else { 0 },
        })
    }
}

/// `C` value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CollInfo {
    pub id: u64,
    pub bits: u32,
    /// Objects / bytes that count towards PG stats (pgmeta and temp objects do not).
    pub nobj: i64,
    pub nbytes: i64,
    /// Physical bytes of compressed extents / the logical bytes they stand for (statfs `data_compressed*`).
    pub comp: i64,
    pub comp_orig: i64,
    /// Data version tracking (adr 0593-dedup-deep-scrub-reformat): data changes of the collection's objects bump their
    /// `Onode::dv` while `dv_on`; `dv_gen` counts the times tracking was switched on, so a data version taken under one
    /// generation is never mistaken for one of another (writes while tracking was off left no trace).
    pub dv_on: bool,
    pub dv_gen: u64,
}

impl CollInfo {
    /// Format 1 (29 bytes); format 2 (45 bytes) adds the compression counters when either is non-zero; format 3 (54 bytes)
    /// adds both counter sets and the data version tracking state once tracking was ever switched on (`dv_gen` != 0).
    pub fn encode(&self) -> Vec<u8> {
        let f3 = self.dv_gen != 0;
        let f2 = !f3 && (self.comp != 0 || self.comp_orig != 0);
        let mut v = Vec::with_capacity(54);
        v.push(if f3 {
            3
        } else if f2 {
            2
        } else {
            1
        });
        v.extend_from_slice(&self.id.to_le_bytes());
        v.extend_from_slice(&self.bits.to_le_bytes());
        v.extend_from_slice(&self.nobj.to_le_bytes());
        v.extend_from_slice(&self.nbytes.to_le_bytes());
        if f2 || f3 {
            v.extend_from_slice(&self.comp.to_le_bytes());
            v.extend_from_slice(&self.comp_orig.to_le_bytes());
        }
        if f3 {
            v.push(self.dv_on as u8);
            v.extend_from_slice(&self.dv_gen.to_le_bytes());
        }
        v
    }
    pub fn decode(b: &[u8]) -> Option<CollInfo> {
        let fmt = *b.first()?;
        if !(1..=3).contains(&fmt)
            || b.len() < [29, 45, 54][fmt as usize - 1]
            || fmt == 3 && b[45] > 1
        {
            return None;
        }
        let g = |o: usize| i64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        Some(CollInfo {
            id: u64::from_le_bytes(b[1..9].try_into().unwrap()),
            bits: u32::from_le_bytes(b[9..13].try_into().unwrap()),
            nobj: g(13),
            nbytes: g(21),
            comp: if fmt >= 2 { g(29) } else { 0 },
            comp_orig: if fmt >= 2 { g(37) } else { 0 },
            dv_on: fmt == 3 && b[45] == 1,
            dv_gen: if fmt == 3 { g(46) as u64 } else { 0 },
        })
    }
}

/// Max blocks per extent run (design: len_blks u8 <= 64).
pub const MAX_RUN: u32 = 64;

/// Extent flag (byte 1 of the `e` value): the run holds one compressed chunk (adr 0059 am. 1).
pub const EXT_COMPRESSED: u8 = 1;
/// Extent flag (adr 0021 am. 32): the blocks MAY be shared with another extent (a clone); a free looks up the `r`
/// refcount records first. Unflagged blocks are never shared (no `r` record covers them). Store with `FEAT_SHARED_EXT`.
pub const EXT_SHARED: u8 = 2;
/// Extent flag (with `EXT_COMPRESSED`, adr 0059 am. 4): the record is a window of its chunk (`CompMeta::skip` / `win`
/// trailer bytes). Store format version 2.
pub const EXT_VIEW: u8 = 4;

/// `r` value: run length (blocks, 1..=`MAX_RUN`) and owner count (>= 2; absent record = 1 owner).
pub fn ref_encode(n: u32, owners: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&n.to_le_bytes());
    v.extend_from_slice(&owners.to_le_bytes());
    v
}

pub fn ref_decode(v: &[u8]) -> Option<(u32, u32)> {
    if v.len() != 8 {
        return None;
    }
    let n = u32::from_le_bytes(v[..4].try_into().unwrap());
    let c = u32::from_le_bytes(v[4..].try_into().unwrap());
    ((1..=MAX_RUN).contains(&n) && c >= 2).then_some((n, c))
}

/// Trailer of a compressed extent: algorithm, logical blocks the chunk covers, crc32c (seed 0) of the logical bytes, and
/// the window of the decoded chunk the record stands for (adr 0059 am. 4): decoded blocks `[skip, skip + win)` are the
/// record's logical blocks `[lblk, lblk + win)`. A whole chunk (`skip` 0, `win` = `raw_blks`) keeps the 6-byte trailer;
/// a window (`EXT_VIEW`) adds `skip u8, win u8`. Windows of one chunk share its physical
/// blocks through the refcount records (`EXT_SHARED`, adr 0021 am. 32).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompMeta {
    pub alg: u8,
    pub raw_blks: u8,
    pub lcrc: u32,
    pub skip: u8,
    pub win: u8,
}

impl CompMeta {
    /// A whole chunk of `raw_blks` logical blocks.
    pub fn whole(alg: u8, raw_blks: u8, lcrc: u32) -> CompMeta {
        CompMeta {
            alg,
            raw_blks,
            lcrc,
            skip: 0,
            win: raw_blks,
        }
    }
    /// The record covers only part of its chunk.
    pub fn is_view(&self) -> bool {
        self.skip != 0 || self.win != self.raw_blks
    }
    /// Window `[from, from + n)` relative to this record's first logical block.
    pub fn sub(&self, from: u8, n: u8) -> CompMeta {
        debug_assert!(n >= 1 && from as u32 + n as u32 <= self.win as u32);
        CompMeta {
            skip: self.skip + from,
            win: n,
            ..*self
        }
    }
    /// Physical bytes this record is charged in the compression counters (`Onode::comp`): the chunk's `len` blocks
    /// pro rata of the window (all of them for a whole chunk). Summed per record, so splits and frees stay exact.
    pub fn phys_charge(&self, len: u32) -> u64 {
        len as u64 * BLK as u64 * self.win as u64 / self.raw_blks as u64
    }
}

/// Encoded `e` value of a run at `pba` with per-block `crcs`.
pub fn ext_encode(pba: u64, crcs: &[u32]) -> Vec<u8> {
    ext_encode_c(pba, crcs, None)
}

/// `ext_encode` with the compressed trailer. The crcs and the length cover the PHYSICAL blocks.
pub fn ext_encode_c(pba: u64, crcs: &[u32], comp: Option<CompMeta>) -> Vec<u8> {
    let mut v = crate::vpool::take(18 + 4 * crcs.len());
    v.push(crcs.len() as u8);
    v.push(comp_flags(comp));
    v.extend_from_slice(&pba.to_le_bytes());
    for c in crcs {
        v.extend_from_slice(&c.to_le_bytes());
    }
    if let Some(m) = comp {
        push_trailer(&mut v, m);
    }
    v
}

/// Flag byte of a record with trailer `comp` (`EXT_SHARED` not included).
fn comp_flags(comp: Option<CompMeta>) -> u8 {
    match comp {
        None => 0,
        Some(m) if m.is_view() => EXT_COMPRESSED | EXT_VIEW,
        Some(_) => EXT_COMPRESSED,
    }
}

fn push_trailer(v: &mut Vec<u8>, m: CompMeta) {
    v.push(m.alg);
    v.push(m.raw_blks);
    v.extend_from_slice(&m.lcrc.to_le_bytes());
    if m.is_view() {
        v.push(m.skip);
        v.push(m.win);
    }
}

/// Trailer of a validated value `b` with `n` physical blocks.
fn comp_of(b: &[u8], n: usize) -> Option<CompMeta> {
    if b[1] & EXT_COMPRESSED == 0 {
        return None;
    }
    let t = &b[10 + 4 * n..];
    let (skip, win) = if b[1] & EXT_VIEW != 0 {
        (t[6], t[7])
    } else {
        (0, t[1])
    };
    Some(CompMeta {
        alg: t[0],
        raw_blks: t[1],
        lcrc: u32::from_le_bytes(t[2..6].try_into().unwrap()),
        skip,
        win,
    })
}

/// Shared by both decoders: flag 0 = plain run (1..=`MAX_RUN` blocks), flag 1 = compressed (trailer present, chunk span
/// within the run limit and larger than the physical length), flag 1 + `EXT_VIEW` = window of a compressed chunk
/// (non-empty, inside the chunk, not the whole chunk); any may carry `EXT_SHARED`. The length byte allows 255 blocks, but
/// no writer makes a run above `MAX_RUN` and every consumer holds at most that many (refcount adjust, crc arrays): a
/// longer run is a corrupt or foreign record, refused here instead of indexing out of bounds later.
fn ext_valid(b: &[u8]) -> bool {
    if b.len() < 10 {
        return false;
    }
    let n = b[0] as usize;
    let chunk_ok = |b: &[u8]| (b[11 + 4 * n] as usize) > n && b[11 + 4 * n] as u32 <= MAX_RUN;
    match b[1] & !EXT_SHARED {
        0 => n != 0 && n as u32 <= MAX_RUN && b.len() == 10 + 4 * n,
        EXT_COMPRESSED => n != 0 && b.len() == 16 + 4 * n && chunk_ok(b),
        f if f == EXT_COMPRESSED | EXT_VIEW => {
            n != 0 && b.len() == 18 + 4 * n && chunk_ok(b) && {
                let (raw, skip, win) = (b[11 + 4 * n], b[16 + 4 * n], b[17 + 4 * n]);
                win != 0 && skip as u32 + win as u32 <= raw as u32 && win != raw
            }
        }
        _ => false,
    }
}

/// Borrowed view of an encoded `e` value (no per-entry allocation).
#[derive(Clone, Copy, Debug)]
pub struct ExtRaw<'x>(&'x [u8]);

impl<'x> ExtRaw<'x> {
    /// `None` if the record is malformed (same checks as [`Ext::decode`]).
    pub fn new(b: &'x [u8]) -> Option<ExtRaw<'x>> {
        ext_valid(b).then_some(ExtRaw(b))
    }
    /// Physical blocks.
    pub fn len(&self) -> u32 {
        self.0[0] as u32
    }
    pub fn is_empty(&self) -> bool {
        false
    }
    pub fn comp(&self) -> Option<CompMeta> {
        comp_of(self.0, self.0[0] as usize)
    }
    /// `EXT_SHARED`: the blocks may have other owners (refcount records, adr 0021 am. 32).
    pub fn shared(&self) -> bool {
        self.0[1] & EXT_SHARED != 0
    }
    /// Logical blocks covered (`len` for a plain run).
    pub fn span(&self) -> u32 {
        self.comp().map_or(self.len(), |m| m.win as u32)
    }
    pub fn pba(&self) -> u64 {
        u64::from_le_bytes(self.0[2..10].try_into().unwrap())
    }
    pub fn crc(&self, i: u32) -> u32 {
        let o = 10 + 4 * i as usize;
        u32::from_le_bytes(self.0[o..o + 4].try_into().unwrap())
    }
    /// Encoded sub-run `[from, from + n)` (block offsets inside the run). Plain runs only.
    pub fn slice_encode(&self, from: u32, n: u32) -> Vec<u8> {
        debug_assert!(self.comp().is_none());
        let mut v = Vec::with_capacity(10 + 4 * n as usize);
        v.push(n as u8);
        v.push(self.0[1] & EXT_SHARED);
        v.extend_from_slice(&(self.pba() + from as u64).to_le_bytes());
        v.extend_from_slice(&self.0[10 + 4 * from as usize..10 + 4 * (from + n) as usize]);
        v
    }
    /// Encoded record of window `m` of this compressed record's chunk (same blocks and crcs), `EXT_SHARED` if `shared`.
    pub fn window_encode(&self, m: CompMeta, shared: bool) -> Vec<u8> {
        let n = self.len() as usize;
        let mut v = crate::vpool::take(18 + 4 * n);
        v.extend_from_slice(&self.0[..10 + 4 * n]);
        v[1] = comp_flags(Some(m)) | if shared { EXT_SHARED } else { 0 };
        push_trailer(&mut v, m);
        v
    }
}

/// `e` value: a run of `len` blocks at `pba` with one crc32c (salted with the block address) per block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ext {
    pub pba: u64,
    pub crcs: Vec<u32>,
    pub comp: Option<CompMeta>,
    /// `EXT_SHARED` (adr 0021 am. 32).
    pub shared: bool,
}

impl Ext {
    /// Physical blocks.
    pub fn len(&self) -> u32 {
        self.crcs.len() as u32
    }
    /// Logical blocks covered.
    pub fn span(&self) -> u32 {
        self.comp.map_or(self.len(), |m| m.win as u32)
    }
    pub fn is_empty(&self) -> bool {
        self.crcs.is_empty()
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut v = ext_encode_c(self.pba, &self.crcs, self.comp);
        if self.shared {
            v[1] |= EXT_SHARED;
        }
        v
    }
    pub fn decode(b: &[u8]) -> Option<Ext> {
        if !ext_valid(b) {
            return None;
        }
        let n = b[0] as usize;
        Some(Ext {
            pba: u64::from_le_bytes(b[2..10].try_into().unwrap()),
            comp: comp_of(b, n),
            shared: b[1] & EXT_SHARED != 0,
            crcs: b[10..10 + 4 * n]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c))
                .collect(),
        })
    }
    /// Sub-run `[from, from + n)` (block offsets inside the run). Plain runs only.
    pub fn slice(&self, from: u32, n: u32) -> Ext {
        debug_assert!(self.comp.is_none());
        Ext {
            pba: self.pba + from as u64,
            crcs: self.crcs[from as usize..(from + n) as usize].to_vec(),
            comp: None,
            shared: self.shared,
        }
    }
}

pub fn blocks_for(bytes: u64) -> u64 {
    bytes.div_ceil(BLK as u64)
}

/// fsck hook (`fsck::RefFn`): data extents referenced by an `e` key.
pub fn fsck_refs(k: &[u8], v: &[u8], out: &mut crate::fsck::Refs) {
    match k.first() {
        Some(&super::keys::T_EXT) => {
            if let Some(e) = Ext::decode(v) {
                if e.shared {
                    out.shared.push((e.pba, e.len()));
                } else {
                    out.ext.push((e.pba, e.len()));
                }
            }
        }
        Some(&super::keys::T_ATTR | &super::keys::T_OMAP | &super::keys::T_HDR) => {
            // values in data blocks (adr 0021 am. 46)
            if let Some((_, e)) = vext(v) {
                out.ext.push((e.pba(), e.len()));
            }
        }
        Some(&super::keys::T_REF) if k.len() == 9 => {
            // an undecodable record shows up as a count mismatch
            let (n, c) = ref_decode(v).unwrap_or((1, u32::MAX));
            out.recs
                .push((u64::from_be_bytes(k[1..9].try_into().unwrap()), n, c));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let o = Onode {
            size: 77,
            flags: 5,
            ..Default::default()
        };
        assert_eq!(o.encode().len(), 13);
        assert_eq!(Onode::decode(&o.encode()), Some(o));
        // format 2 of an earlier build (omap counters): read without the counters, written back short
        let mut b = vec![2u8];
        b.extend_from_slice(&(1u64 << 40).to_le_bytes());
        b.extend_from_slice(&(F_OMAP | F_OCNT | F_INLINE).to_le_bytes());
        b.extend_from_slice(&123_456_789_012u64.to_le_bytes());
        b.extend_from_slice(&77_000_000_000_000u64.to_le_bytes());
        let o = Onode {
            size: 1 << 40,
            flags: F_OMAP | F_INLINE,
            ..Default::default()
        };
        assert_eq!(Onode::decode(&b), Some(o.clone()));
        assert_eq!(o.encode().len(), 13);
        // flag and format must agree, truncated records are refused
        let mut x = b.clone();
        x[0] = 1;
        assert_eq!(Onode::decode(&x), None);
        let mut x = b.clone();
        x[9] &= !(F_OCNT as u8);
        assert_eq!(Onode::decode(&x), None);
        assert_eq!(Onode::decode(&b[..28]), None);
        assert_eq!(Onode::decode(&[]), None);
        let c = CollInfo {
            id: 9,
            bits: 3,
            nobj: -1,
            nbytes: 1 << 40,
            ..Default::default()
        };
        assert_eq!(CollInfo::decode(&c.encode()), Some(c));
        let e = Ext {
            pba: 12345,
            crcs: vec![1, 2, 3],
            comp: None,
            shared: false,
        };
        assert_eq!(Ext::decode(&e.encode()), Some(e.clone()));
        assert_eq!(e.slice(1, 2).pba, 12346);
    }
}

#[cfg(test)]
mod comp_tests {
    use super::*;

    #[test]
    fn compressed_formats() {
        let m = CompMeta::whole(2, 16, 0xdead_beef);
        let e = Ext {
            pba: 99,
            crcs: vec![7, 8, 9],
            comp: Some(m),
            shared: false,
        };
        let b = e.encode();
        assert_eq!(b.len(), 16 + 12);
        assert_eq!((e.len(), e.span()), (3, 16));
        assert_eq!(Ext::decode(&b), Some(e.clone()));
        let r = ExtRaw::new(&b).unwrap();
        assert_eq!(
            (r.len(), r.span(), r.pba(), r.crc(2), r.comp()),
            (3, 16, 99, 9, Some(m))
        );
        // refused: truncated, span not larger than the physical length, span above the run limit, unknown flag
        assert!(ExtRaw::new(&b[..b.len() - 1]).is_none());
        let mut x = b.clone();
        x[11 + 12] = 3;
        assert!(Ext::decode(&x).is_none());
        x[11 + 12] = 65;
        assert!(Ext::decode(&x).is_none());
        let mut x = b.clone();
        x[1] = 2;
        assert!(Ext::decode(&x).is_none());
        // a plain record is unchanged
        let p = Ext {
            pba: 5,
            crcs: vec![1, 2],
            comp: None,
            shared: false,
        };
        assert_eq!(p.encode().len(), 10 + 8);
        assert_eq!(ExtRaw::new(&p.encode()).unwrap().span(), 2);
        // a plain run above the run limit is malformed like a compressed one (review 2026-11-03 #6): every consumer
        // (refcount adjust, slices, crc arrays) holds at most `MAX_RUN` blocks, the validator must not let more through
        let run = |n: u32, shared: bool| Ext {
            pba: 5,
            crcs: vec![1; n as usize],
            comp: None,
            shared,
        };
        for shared in [false, true] {
            let ok = run(MAX_RUN, shared).encode();
            assert_eq!(Ext::decode(&ok).map(|e| e.len()), Some(MAX_RUN));
            assert!(ExtRaw::new(&ok).is_some());
            for n in [MAX_RUN + 1, 255] {
                let big = run(n, shared).encode();
                assert_eq!(big.len(), 10 + 4 * n as usize);
                assert!(Ext::decode(&big).is_none(), "{n}-block plain run accepted");
                assert!(ExtRaw::new(&big).is_none(), "{n}-block plain run accepted");
            }
        }
        // onode format 3 and collection format 2
        let o = Onode {
            size: 1 << 20,
            flags: F_COMP,
            comp: 4096,
            comp_orig: 65536,
            ..Default::default()
        };
        assert_eq!(o.encode().len(), 45);
        assert_eq!(Onode::decode(&o.encode()), Some(o.clone()));
        // an earlier build's format 3 with omap counters: read without them
        let mut b = o.encode();
        b[9..13].copy_from_slice(&(F_COMP | F_OCNT).to_le_bytes());
        b[13..21].copy_from_slice(&3u64.to_le_bytes());
        b[21..29].copy_from_slice(&9u64.to_le_bytes());
        assert_eq!(Onode::decode(&b), Some(o.clone()));
        let mut b = o.encode();
        b[0] = 1;
        assert_eq!(Onode::decode(&b), None);
        let c = CollInfo {
            id: 1,
            bits: 2,
            nobj: 3,
            nbytes: 4,
            comp: 5,
            comp_orig: 6,
            ..Default::default()
        };
        assert_eq!(c.encode().len(), 45);
        assert_eq!(CollInfo::decode(&c.encode()), Some(c));
    }

    #[test]
    fn data_version_formats() {
        // onode format 4: compression counters (zero without their flag) + the data version
        let o = Onode {
            size: 4096,
            flags: F_DVER,
            dv: 7,
            ..Default::default()
        };
        let b = o.encode();
        assert_eq!((b.len(), b[0]), (53, 4));
        assert_eq!(Onode::decode(&b), Some(o.clone()));
        let o2 = Onode {
            flags: F_DVER | F_COMP,
            comp: 3,
            comp_orig: 4,
            dv: u64::MAX,
            ..o.clone()
        };
        assert_eq!(Onode::decode(&o2.encode()), Some(o2.clone()));
        // an earlier build's format 4 with omap counters: read without them
        let mut x = o2.encode();
        x[9..13].copy_from_slice(&(F_DVER | F_COMP | F_OCNT).to_le_bytes());
        x[13..21].copy_from_slice(&1u64.to_le_bytes());
        x[21..29].copy_from_slice(&2u64.to_le_bytes());
        assert_eq!(Onode::decode(&x), Some(o2.clone()));
        // flag and format must agree, truncated records are refused
        let mut x = o.encode();
        x[0] = 3;
        assert_eq!(Onode::decode(&x), None);
        let mut x = o.encode();
        x[10] &= !((F_DVER >> 8) as u8);
        assert_eq!(Onode::decode(&x), None);
        assert_eq!(Onode::decode(&o.encode()[..52]), None);
        let mut x = Onode::default().encode();
        x[0] = 5;
        assert_eq!(Onode::decode(&x), None);
        // collection format 3 once tracking was switched on, also while it is off again
        for on in [true, false] {
            let c = CollInfo {
                id: 1,
                bits: 2,
                nobj: 3,
                nbytes: 4,
                dv_on: on,
                dv_gen: 9,
                ..Default::default()
            };
            let b = c.encode();
            assert_eq!((b.len(), b[0]), (54, 3));
            assert_eq!(CollInfo::decode(&b), Some(c));
        }
        let c = CollInfo {
            dv_gen: 1,
            ..Default::default()
        };
        let mut b = c.encode();
        b[45] = 2;
        assert_eq!(CollInfo::decode(&b), None);
        assert_eq!(CollInfo::decode(&c.encode()[..53]), None);
        // never switched on: the old short formats
        assert_eq!(CollInfo::default().encode().len(), 29);
    }
}

/// Inline compressed value record (adr 0021 am. 58, 59): `[V_CINL][class][plain length - 1: u16][zstd block]`, lengths 1..=64 KiB.
/// The block is a headerless zstd frame (no magic, dictionary id, content size or checksum) coded against the trained dictionary of
/// the value class `dict_class(value)`: values of one kind share structure and constant strings, and the dictionary carries the
/// entropy tables of the kind, which is what separates a 130 B LZ4 block from an 84 B one on an RGW index entry. The shard trains
/// one dictionary per class from its first `DICT_SAMPLES` values and stores it once under tree key `Z` + class, `DictTab`
/// (immutable afterwards).
/// Value classes (dictionary slots per shard).
pub const DICT_CLASSES: usize = 64;
/// Dictionary size and the number of values it is trained from (measured: 1 KiB from 64 samples is within 1 % of 4 KiB from 256).
pub const DICT_MAX: usize = 1024;
pub const DICT_SAMPLES: usize = 64;
/// zstd level of the value codec (level 1: 0.5 us per 300 B value).
const VAL_ZSTD_LEVEL: i32 = 1;

/// Shared dictionary slot: trained from the first values of all classes together, used by every class that has no dictionary of its
/// own yet (and by kinds whose first byte varies too much to ever fill a class).
pub const SHARED_CLASS: usize = DICT_CLASSES - 1;

/// Class of a value: its first byte (the type marker / struct version of the usual encodings). Later bytes are not used: fields like
/// inode numbers, versions or timestamps there would split one kind into many thin classes.
pub fn dict_class(val: &[u8]) -> usize {
    val[0] as usize % SHARED_CLASS
}

/// Tree key of the dictionary of class `c`.
pub fn dict_key(c: usize) -> [u8; 2] {
    [super::keys::T_DICT, c as u8]
}

pub fn vcomp_len(raw: &[u8]) -> Option<usize> {
    (raw.first() == Some(&V_CINL) && raw.len() > 4)
        .then(|| u16::from_le_bytes([raw[2], raw[3]]) as usize + 1)
}

/// Class a `V_CINL` record refers to; `None` = the record is too short to name one (never written: corrupt or foreign
/// tree data).
pub fn vcomp_dict(raw: &[u8]) -> Option<u8> {
    raw.get(1).copied()
}

/// A trained value dictionary. The zstd contexts that use it are built on first use per thread (`ZCTX`, keyed by `id`).
#[derive(Debug)]
pub struct ZDict {
    id: u64,
    bytes: Box<[u8]>,
}

impl ZDict {
    pub fn new(bytes: Vec<u8>) -> ZDict {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        ZDict {
            id: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            bytes: bytes.into_boxed_slice(),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Train a dictionary from sample values; `None` = the sample set is not usable (zstd refuses it).
    ///
    /// The trainer is zstd's default (`ZDICT_trainFromBuffer`: fastCover, d = 8, 4 k steps, level 3) except for the hash table:
    /// zstd sizes it for MB corpora (2^20 entries, 6 MiB of tables built, copied and freed per k step), which made one training of
    /// 64 values cost ~13 ms on the PG core in the write path (a pause of every replica at the same op, b-mix tail; page faults on
    /// the fresh tables dominate). Here the table has four slots per sample byte (each byte starts one d-mer, load <= 25 %), rounded
    /// up to a power of two, at most zstd's 2^20; the coded size stays within noise of the default trainer
    /// (`tests/comp.rs::zdict_train_sized_table_codes_like_default`).
    pub fn train(samples: &[Vec<u8>]) -> Option<ZDict> {
        use zstd::zstd_safe::zstd_sys;
        let sizes: Vec<usize> = samples.iter().map(Vec::len).collect();
        let flat = samples.concat();
        // SAFETY: an all-zero parameter block is zstd's "use the default" for every field (what `ZDICT_trainFromBuffer` starts from).
        let mut p: zstd_sys::ZDICT_fastCover_params_t = unsafe { std::mem::zeroed() };
        p.d = 8;
        p.steps = 4;
        p.f = (flat.len().next_power_of_two().trailing_zeros() + 2).min(20);
        p.zParams.compressionLevel = zstd::DEFAULT_COMPRESSION_LEVEL;
        let mut dict = vec![0u8; DICT_MAX];
        // SAFETY: `dict` holds `DICT_MAX` writable bytes; `flat` is the concatenation of `sizes.len()` samples of `sizes` bytes.
        let n = unsafe {
            zstd_sys::ZDICT_optimizeTrainFromBuffer_fastCover(
                dict.as_mut_ptr().cast(),
                dict.len(),
                flat.as_ptr().cast(),
                sizes.as_ptr(),
                sizes.len() as u32,
                &mut p,
            )
        };
        // SAFETY: plain query on a return code.
        if unsafe { zstd_sys::ZDICT_isError(n) } != 0 {
            return None;
        }
        dict.truncate(n);
        Some(ZDict::new(dict))
    }
}

type ValCtx = (
    u64,
    zstd::bulk::Compressor<'static>,
    zstd::bulk::Decompressor<'static>,
);

/// Contexts kept per thread: a core serves several shards with up to `DICT_CLASSES` dictionaries each, in practice a handful; the
/// cache must hold every dictionary in use (a miss builds a context, ~100 us: measured 6x slower reads with 64 classes in a 64-entry cache).
const ZCTX_CAP: usize = 256;

thread_local! {
    static ZCTX: std::cell::RefCell<Vec<ValCtx>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn with_ctx<R>(
    d: &ZDict,
    f: impl FnOnce(&mut zstd::bulk::Compressor<'static>, &mut zstd::bulk::Decompressor<'static>) -> R,
) -> Option<R> {
    ZCTX.with_borrow_mut(|v| {
        let i = match v.iter().position(|c| c.0 == d.id) {
            Some(i) => i,
            None => {
                let mut c =
                    zstd::bulk::Compressor::with_dictionary(VAL_ZSTD_LEVEL, &d.bytes).ok()?;
                let mut x = zstd::bulk::Decompressor::with_dictionary(&d.bytes).ok()?;
                c.include_magicbytes(false).ok()?;
                c.include_dictid(false).ok()?;
                c.include_contentsize(false).ok()?;
                c.include_checksum(false).ok()?;
                x.include_magicbytes(false).ok()?;
                if v.len() >= ZCTX_CAP {
                    v.swap_remove(0);
                }
                v.push((d.id, c, x));
                v.len() - 1
            }
        };
        let (_, c, x) = &mut v[i];
        Some(f(c, x))
    })
}

/// The plain value of a `V_CINL` record coded against `zd`; `None` = corrupt.
pub fn vcomp_unpack(raw: &[u8], zd: &ZDict) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    vcomp_unpack_into(raw, zd, &mut out).then_some(out)
}

/// [`vcomp_unpack`] appended to `out` (a listing encodes values in place); `false` = corrupt, `out` unchanged.
pub fn vcomp_unpack_into(raw: &[u8], zd: &ZDict, out: &mut Vec<u8>) -> bool {
    let Some(n) = vcomp_len(raw) else {
        return false;
    };
    let at = out.len();
    out.resize(at + n, 0);
    let got = with_ctx(zd, |_, x| {
        x.decompress_to_buffer(&raw[4..], &mut out[at..]).ok()
    })
    .flatten();
    if got != Some(n) {
        out.truncate(at);
        return false;
    }
    true
}

/// Adaptive sampling of value compression attempts per value class (adr 0021 am. 58): every failure doubles the number of values
/// of that class skipped next (up to 63), a success resets it, so incompressible values cost ~nothing and a compressible kind
/// mixed into random ones keeps being tried. One per stream of attempts (the stage's tree path, a shard's run merges): it
/// persists across txns and merge slices (a per-slice reset tried every class again in each of the small time-capped slices).
#[derive(Clone, Debug)]
pub struct VcAdapt {
    skip: [u8; DICT_CLASSES],
    fail: [u8; DICT_CLASSES],
}

impl Default for VcAdapt {
    fn default() -> Self {
        VcAdapt {
            skip: [0; DICT_CLASSES],
            fail: [0; DICT_CLASSES],
        }
    }
}

impl VcAdapt {
    /// Try a value of class `cls` now (else it is one of the skipped ones).
    #[inline]
    pub fn try_now(&mut self, cls: usize) -> bool {
        if self.skip[cls] > 0 {
            self.skip[cls] -= 1;
            false
        } else {
            true
        }
    }
    /// An attempt of class `cls` saved enough.
    #[inline]
    pub fn hit(&mut self, cls: usize) {
        self.fail[cls] = 0;
    }
    /// An attempt of class `cls` failed (or its dictionary could not be trained): skip twice as many as after the last one.
    #[inline]
    pub fn miss(&mut self, cls: usize) {
        self.fail[cls] = (self.fail[cls] + 1).min(6);
        self.skip[cls] = (1 << self.fail[cls]) - 1;
    }
    /// Values still to skip, all classes.
    pub fn skipping(&self) -> u32 {
        self.skip.iter().map(|&x| x as u32).sum()
    }
}

/// Compress `val` against `zd` into `scratch` (resized as needed) as a record of class `id`: the record is `scratch[..returned]`,
/// `usize::MAX` if coding failed.
pub fn vcomp_pack(val: &[u8], zd: &ZDict, id: u8, scratch: &mut Vec<u8>) -> usize {
    let max = zstd::zstd_safe::compress_bound(val.len()) + 4;
    if scratch.len() < max {
        scratch.resize(max, 0);
    }
    scratch[0] = V_CINL;
    scratch[1] = id;
    scratch[2..4].copy_from_slice(&((val.len() - 1) as u16).to_le_bytes());
    with_ctx(zd, |c, _| c.compress_to_buffer(val, &mut scratch[4..]).ok())
        .flatten()
        .map_or(usize::MAX, |n| n + 4)
}
