// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Txn staging: all KV effects of a txn accumulate in an overlay (`map` + `dels`), new object data in
//! per-object [`Dirty`] runs; `finish` allocates blocks, builds extent keys and the engine `Txn`. Reads inside
//! a txn see the overlay (read-your-writes), reads outside use an empty one.

use super::dirty::{Dirty, INF};
use super::keys::*;
use super::onode::*;
use super::shardio::{PfAdmit, PfState, RangeKey, RangeMemo, ScanMemo, ShardStore};
use super::txn::{KvRunData, OTxn, TOp};
use super::{KvList, ObjError, Result, SharedRead};
use crate::BLK;
use crate::codec::blk_seed;
use crate::compress::{Alg, Codec, CompSpec, bound, sample_incompressible};
use crate::dev::{BlockDev, Clock, IoBuf};
use crate::error::StoreError;
use crate::fx::FxMap;
use crate::olsm::Memtable;
use crate::olsm::read::{ListEnd, ListPos, ListQuery};
use crate::olsm::wire::{OOp, del_blob, put_blob};
use crate::pre::PreClaim;
use crate::runs::{RunBuilder, is_tomb, omap_id};
use crate::shard::{AllocClass, CopyRun, Txn};
use crate::state::{Extent, Op, Record};
use crate::tree::ScanCursor;
use bytes::Bytes;
use denc::types::{CollT, Ghobject};
use std::collections::{BTreeMap, VecDeque};
use std::mem::MaybeUninit;
use std::ops::Bound;
use std::sync::Arc;
#[cfg(feature = "splinterdb")]
#[path = "stage_splinter.rs"]
mod splinter;

#[cfg(feature = "rocksdb")]
#[path = "stage_rocks.rs"]
mod rocks;

/// Max object size in blocks ([`crate::MAX_OBJECT_BYTES`]).
const MAX_BLOCKS: u64 = crate::MAX_OBJECT_BYTES / BLK as u64;
/// Most extent runs a clone shares (adr 0021 am. 32): 2 extent records + 1 refcount record each go into the WAL record
/// (~600 B per 64-block run, ~100 B per 1-block run); bigger sources are copied as before. 1024 = every 4 MiB object (RBD /
/// CephFS default), however fragmented by 4 KiB overwrites (was 256: such heads were copied at the snapshot COW, am. 41).
const SHARE_MAX_EXTENTS: usize = 1024;
const ID_SEQ_BITS: u32 = 12;
/// A read whose device pieces average at least this many bytes is served by reference ([`Stage::read_eff_shared`]). Below
/// it the per-piece costs (a shared owner each, an iovec entry each, runs too small for a zero-copy send) exceed one copy
/// of the read (adr 0043 am. 13).
pub const SHARE_MIN_AVG: usize = 64 << 10;
/// CPU slice of an executor listing pass (adr 0021 S8): after this many admitted entries or bytes the pass ends and the
/// request continues at the next poll, so a long listing never holds the PG core longer than about one point op. A run the
/// engine exempts ([`crate::obj::Store::list_whole`]: the listing holds later ops of its object) lists whole.
const SCAN_SLICE_ENTRIES: usize = 256;
const SCAN_SLICE_BYTES: usize = 256 << 10;
/// Engine listing page of [`Stage::lsm_list`]: every call builds fresh cursors over all sources and seeks each run, so
/// a page covers a whole executor request (up to this many entries).
const LSM_LIST_PAGE: usize = 4096;
/// Key and value bytes of one engine listing page: a cold page keeps every extent it demanded protected until it
/// completes, so large values shrink the page instead of pinning up to [`LSM_LIST_PAGE`] values.
const LSM_LIST_PAGE_BYTES: usize = 1 << 20;
/// Entries one engine listing call merges, live or deleted ([`ListQuery::visits`]): the CPU slice of an LSM listing.
/// A page of live entries ends before it; a span of deleted keys ends the call here and the listing continues at the
/// key where it stopped (the executor slices it, [`Stage::lsm_walk`]), so it never holds the PG core for the whole span.
const LSM_LIST_VISITS: usize = 4096;
/// Largest read-ahead window of a listing (leaves; the tree clamps it to an eighth of its cache).
const SCAN_RA_MAX: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Slot {
    Attr,
    Omap,
    Hdr,
}

impl Slot {
    fn frag_ty(self) -> u8 {
        match self {
            Slot::Attr => FT_ATTR,
            Slot::Omap => FT_OMAP,
            Slot::Hdr => 3,
        }
    }
    fn frag_flag(self) -> u32 {
        match self {
            Slot::Attr => F_AFRAG,
            Slot::Omap => F_OFRAG,
            Slot::Hdr => F_HFRAG,
        }
    }
    /// Values of this slot may live in data blocks (adr 0021 am. 46).
    fn ext_flag(self) -> u32 {
        match self {
            Slot::Attr => F_AEXT,
            Slot::Omap => F_OEXT,
            Slot::Hdr => F_HEXT,
        }
    }
    fn main_key(self, id: u64, k: &[u8]) -> Vec<u8> {
        let mut out = crate::vpool::take(10 + k.len());
        self.main_key_into(id, k, &mut out);
        out
    }
    /// [`Self::main_key`] into a reused buffer (cleared first).
    fn main_key_into(self, id: u64, k: &[u8], out: &mut Vec<u8>) {
        let (tag, sub) = match self {
            Slot::Attr => (T_ATTR, S_ATTR),
            Slot::Omap => (T_OMAP, S_OMAP),
            Slot::Hdr => (T_HDR, S_HDR),
        };
        out.clear();
        out.push(tag);
        out.extend_from_slice(&id.to_be_bytes());
        out.push(sub);
        if self != Slot::Hdr {
            out.extend_from_slice(k);
        }
    }
}

struct CollEnt {
    info: Option<CollInfo>,
    dirty: bool,
}

/// Tree omap entries taken by the S7 format upgrade (adr 0611, [`Stage::upgrade_omap_take`]).
#[derive(Debug, Default)]
pub struct OmapTake {
    /// `(object id, key, value)` in keyspace order.
    pub entries: Vec<(u64, Bytes, Bytes)>,
    /// Run entry bytes of `entries`.
    pub bytes: usize,
    /// Per object the tree key span `[a, b)` the entries came from.
    spans: Vec<(u64, Vec<u8>, Vec<u8>)>,
    /// Fragment records of fragmented values.
    frags: Vec<Vec<u8>>,
    /// Data blocks of values stored there (adr 0021 am. 46).
    exts: Vec<(u64, u32)>,
}

struct Work<'a> {
    on: Onode,
    /// Compression counters of the onode as loaded (`comp`, `comp_orig`).
    orig_comp: (u64, u64),
    /// (collection, size, counted) as loaded; `None` = created in this txn.
    orig: Option<(u64, u64, bool)>,
    /// Collection the object currently lives in (its name key is found in `Stage::names` by id).
    coll: u64,
    counted: bool,
    gone: bool,
    dirty_on: bool,
    /// The PG's pgmeta object (PG log, info): hot, short-lived omap values, never compressed.
    pgmeta: bool,
    runs: Dirty<'a>,
    /// Created in this txn by a sharing clone: its extents are staged (overlay), so it is not "without extents".
    shared_in: bool,
}

impl Work<'_> {
    fn created(&self) -> bool {
        self.orig.is_none()
    }
    /// No committed or staged extents (created in this txn and not by a sharing clone).
    fn no_ext(&self) -> bool {
        self.orig.is_none() && !self.shared_in
    }
}

/// Objects touched by one txn (a handful in practice; linear search, no hashing, one allocation).
struct ObjTab<'a>(Vec<(u64, Work<'a>)>);

impl<'a> ObjTab<'a> {
    fn pos(&self, id: u64) -> Option<usize> {
        self.0.iter().position(|e| e.0 == id)
    }
    fn get(&self, id: &u64) -> Option<&Work<'a>> {
        self.pos(*id).map(|i| &self.0[i].1)
    }
    fn get_mut(&mut self, id: &u64) -> Option<&mut Work<'a>> {
        self.pos(*id).map(|i| &mut self.0[i].1)
    }
    fn contains_key(&self, id: &u64) -> bool {
        self.pos(*id).is_some()
    }
    fn insert(&mut self, id: u64, w: Work<'a>) {
        match self.pos(id) {
            Some(i) => self.0[i].1 = w,
            None => self.0.push((id, w)),
        }
    }
}

pub(crate) struct Built<B> {
    pub txn: Txn<B>,
    pub needs_compression: bool,
}

struct Encoding {
    id: u64,
    lblk: u64,
    bytes: Vec<u8>,
    phys: usize,
    raw_bytes: usize,
    meta: CompMeta,
}

/// Lifetime-free preparation state once borrowed payloads have acquired their existing owners.
pub(crate) type Saved<B> = Parts<'static, B>;
pub(crate) struct Parts<'a, B> {
    map: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    dels: Vec<(Vec<u8>, Vec<u8>)>,
    sruns: Vec<(u64, RunBuilder)>,
    /// Omap LSM ops of the txn (store with `FEAT_OMAP_LSM`, adr 0610), in op order: emitted as `Op::Omap`.
    oops: Vec<OOp>,
    /// Selected point-range ops and their native equivalents, for exact final WAL-size fallback.
    point_ranges: Vec<(usize, OOp)>,
    /// The same ops applied: the newest source of this txn's own omap reads (clone after writes of the txn).
    omem: Memtable,
    #[cfg(feature = "rocksdb")]
    rocks_omem: Option<crate::rocks_omap::mem::Memtable>,
    #[cfg(feature = "splinterdb")]
    splinter_omem: Option<crate::foreign_mem::Memtable>,
    sc: Scratch,
    objs: ObjTab<'a>,
    base_id: u64,
    seq: u64,
    frees: Vec<(u64, u32)>,
    pub data: Vec<(u64, B)>,
    data_crcs: Vec<Vec<u32>>,
    copies: Vec<CopyRun>,
    tails: Vec<u32>,
    /// Pre-written pieces claimed so far (adr 0477).
    pub pre: Vec<PreClaim>,
    planning: bool,
    planned: Vec<Extent>,
    freeing: bool,
    shrink: bool,
    grows: bool,
    comp: Option<CompSpec>,
    max_key: usize,
    soft_entry: usize,
    read_crc: Option<u32>,
    discovered: bool,
    material_obj: usize,
    material_pos: u64,
    material_span: Option<(u64, bool)>,
    material_raw_until: Option<u64>,
    /// `TOp::Reformat` with `max_frags`: (onode id, first block, end block, max_frags), checked after allocation.
    reformat_check: Option<(u64, u64, u64, u32)>,
    encoding: Option<Encoding>,
    compression_at_start: bool,
    payloads: Vec<crc::Payload>,
}

impl<B> Parts<'_, B> {
    pub fn progress(&self) -> (usize, u64, usize) {
        (
            self.material_obj,
            self.material_pos,
            self.data.len() + self.copies.len(),
        )
    }
    pub fn retain(self, owners: &[bytes::Bytes]) -> Saved<B> {
        let objs = ObjTab(
            self.objs
                .0
                .into_iter()
                .map(|(id, w)| {
                    let runs = Dirty {
                        runs: w
                            .runs
                            .runs
                            .into_iter()
                            .map(|(s, r)| {
                                (
                                    s,
                                    super::dirty::Run {
                                        n: r.n,
                                        data: r.data.map(|d| d.retained(owners)),
                                    },
                                )
                            })
                            .collect(),
                    };
                    (
                        id,
                        Work {
                            on: w.on,
                            orig_comp: w.orig_comp,
                            orig: w.orig,
                            coll: w.coll,
                            counted: w.counted,
                            gone: w.gone,
                            dirty_on: w.dirty_on,
                            pgmeta: w.pgmeta,
                            runs,
                            shared_in: w.shared_in,
                        },
                    )
                })
                .collect(),
        );
        Parts {
            map: self.map,
            dels: self.dels,
            sruns: self.sruns,
            oops: self.oops,
            point_ranges: self.point_ranges,
            omem: self.omem,
            #[cfg(feature = "rocksdb")]
            rocks_omem: self.rocks_omem,
            #[cfg(feature = "splinterdb")]
            splinter_omem: self.splinter_omem,
            sc: self.sc,
            objs,
            base_id: self.base_id,
            seq: self.seq,
            frees: self.frees,
            data: self.data,
            data_crcs: self.data_crcs,
            copies: self.copies,
            tails: self.tails,
            pre: self.pre,
            planning: self.planning,
            planned: self.planned,
            freeing: self.freeing,
            shrink: self.shrink,
            grows: self.grows,
            comp: self.comp,
            max_key: self.max_key,
            soft_entry: self.soft_entry,
            read_crc: self.read_crc,
            discovered: self.discovered,
            material_obj: self.material_obj,
            material_pos: self.material_pos,
            material_span: self.material_span,
            material_raw_until: self.material_raw_until,
            reformat_check: self.reformat_check,
            encoding: self.encoding,
            compression_at_start: self.compression_at_start,
            payloads: self.payloads,
        }
    }
}

/// Lifetime-free buffers kept by the [`ShardStore`] between txns: the staging code takes them at `Stage::new`
/// and hands them back (cleared, capacity kept) when it is dropped, so a steady-state txn allocates none of them.
#[derive(Default)]
pub(crate) struct Scratch {
    colls: FxMap<CollT, CollEnt>,
    coll_ids: FxMap<u64, CollT>,
    names: FxMap<Vec<u8>, Option<u64>>,
    vb: Vec<u8>,
    /// Main key of a value lookup (`get_val`): built here, not allocated per read.
    mk: Vec<u8>,
    /// Output of the value compressor (`try_comp`).
    cv: Vec<u8>,
    /// Raw extent values found by `extents_set`: `exts` indexes into `ext_raw`.
    ext_raw: Vec<u8>,
    exts: Vec<ExtIdx>,
    /// Onodes that got new data blocks in the last staged txn (read-after-write ordering), filled by `finish`.
    pub ids: Vec<u64>,
    /// Omap keys the txn removed blind (adr 0476 am. 5): not looked up, emitted as `Op::Del` (ascending). Reads of the
    /// txn see them removed unless a later op of the txn put them again (the map is newer).
    odel: KeyList,
    /// The blind keys of the removal batch being staged ([`Stage::rm_keys`]), merged into `odel` at its end.
    obatch: KeyList,
}

/// Ascending distinct keys back to back in one buffer: one sorted list per txn instead of a vector per key.
#[derive(Default)]
struct KeyList {
    buf: Vec<u8>,
    /// End offset of each key in `buf`.
    end: Vec<u32>,
}

impl KeyList {
    fn len(&self) -> usize {
        self.end.len()
    }

    fn is_empty(&self) -> bool {
        self.end.is_empty()
    }

    fn get(&self, i: usize) -> &[u8] {
        let a = if i == 0 { 0 } else { self.end[i - 1] as usize };
        &self.buf[a..self.end[i] as usize]
    }

    fn last(&self) -> Option<&[u8]> {
        self.len().checked_sub(1).map(|i| self.get(i))
    }

    /// Index of the first key `>= k`.
    fn lower_bound(&self, k: &[u8]) -> usize {
        let (mut lo, mut hi) = (0, self.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.get(mid) < k {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    fn contains(&self, k: &[u8]) -> bool {
        let i = self.lower_bound(k);
        i < self.len() && self.get(i) == k
    }

    /// Does a key lie in `[a, b)`?
    fn any_in(&self, a: &[u8], b: &[u8]) -> bool {
        let i = self.lower_bound(a);
        i < self.len() && self.get(i) < b
    }

    /// Append `k`, above every key of the list.
    fn push(&mut self, k: &[u8]) {
        debug_assert!(self.last().is_none_or(|l| l < k), "keys ascend");
        self.buf.extend_from_slice(k);
        self.end.push(self.buf.len() as u32);
    }

    /// Add the keys of `o` (ascending, none of them in the list): appended when they sort above the list, else merged
    /// into a new list (a batch below or between earlier ones of the txn).
    fn merge(&mut self, o: &KeyList) {
        if o.is_empty() {
            return;
        }
        if self.last().is_none_or(|l| l < o.get(0)) {
            let base = self.buf.len() as u32;
            self.buf.extend_from_slice(&o.buf);
            self.end.extend(o.end.iter().map(|e| base + e));
            return;
        }
        let mut m = KeyList {
            buf: Vec::with_capacity(self.buf.len() + o.buf.len()),
            end: Vec::with_capacity(self.len() + o.len()),
        };
        let (mut i, mut j) = (0, 0);
        while i < self.len() || j < o.len() {
            if j == o.len() || (i < self.len() && self.get(i) < o.get(j)) {
                m.push(self.get(i));
                i += 1;
            } else {
                m.push(o.get(j));
                j += 1;
            }
        }
        *self = m;
    }

    fn clear(&mut self) {
        self.buf.clear();
        self.end.clear();
    }
}

/// A device run serving part of a read: logical start, device block, length, stored block checksums.
pub(crate) struct Part {
    lblk: u64,
    pba: u64,
    n: u32,
    crcs: Vec<u32>,
    /// Compressed chunk: `lblk` is its first logical block, `n`/`pba`/`crcs` are physical.
    comp: Option<CompMeta>,
}

/// What the probe of a client read ([`Stage::warm_data`]) resolved for the read that follows it: the object, its size and the
/// one plain device piece of the range, found whole in the data cache. A single-use hand-over valid only while the shard
/// submitted no txn since (`lsn`): the read then skips the name lookup and the extent scan it would repeat.
pub(crate) struct HotProbe {
    lsn: u64,
    cid: CollT,
    oid: Ghobject,
    off: u64,
    len: u64,
    id: u64,
    size: u64,
    part: Part,
}

impl HotProbe {
    /// Is this the probe of exactly this read, and has the shard (`lsn` = its next WAL sequence number) not changed since?
    pub(crate) fn serves(&self, lsn: u64, cid: &CollT, oid: &Ghobject, off: u64, len: u64) -> bool {
        self.lsn == lsn
            && self.off == off
            && self.len == len
            && self.cid == *cid
            && self.oid == *oid
    }
}

/// Decode the compressed chunk in `phys` (the physical blocks as read: `u32` length, payload, zero padding): `None` when
/// the block crcs did not match (`crcs_ok` false), the framing or the codec fails, or the decoded bytes do not match the
/// chunk's logical crc.
fn decode_chunk(
    codec: &mut crate::compress::SoftCodec,
    stats: &mut super::shardio::ObjStats,
    m: CompMeta,
    phys: &[u8],
    crcs_ok: bool,
) -> Option<Vec<u8>> {
    if !crcs_ok || phys.len() < 4 {
        return None;
    }
    let clen = denc::le::rd_u32(phys, 0) as usize;
    if clen == 0 || clen > phys.len() - 4 {
        return None;
    }
    let alg = Alg::from_u8(m.alg)?;
    let raw_len = m.raw_blks as usize * BLK;
    stats.decomp += 1;
    let t0 = std::time::Instant::now();
    let mut dec = Vec::new();
    let r = codec
        .decompress_vec(alg, &phys[4..4 + clen], &mut dec, raw_len)
        .is_some();
    stats.decomp_ns += t0.elapsed().as_nanos() as u64;
    (r && crc::crc32c(0, &dec) == m.lcrc).then_some(dec)
}

/// Where [`Stage::read_comp_window`] puts the decoded bytes of a range.
enum CompDst<'o> {
    /// Copy into one buffer (blocks `[blk, blk+n)`, compressed and plain parts, holes zeroed).
    Flat(&'o mut [MaybeUninit<u8>]),
    /// Pieces in order, by reference to the decoded chunk (every part compressed, holes as zero pieces).
    Pieces(&'o mut Vec<(Bytes, Option<u32>)>),
}

/// crc32c (seed `!0`) of the `n` blocks from `blk` just read by `read_comp_window` into `out`, without a pass over the
/// whole range: a plain part contributes its verified block crcs, a whole decoded chunk its logical crc (`lcrc`, checked
/// when the chunk was decoded), a hole nothing but zeros; only a part of a chunk is hashed (hot in cache, right after
/// the copy). `got` = the block crcs of the plain parts in order.
fn comp_read_crc(parts: &[Part], blk: u64, n: u64, out: &[MaybeUninit<u8>], got: &[u32]) -> u32 {
    let (mut r, mut pos, mut gi) = (!0u32, blk, 0usize);
    let hole = |r: u32, k: u64| crc::crc32c_combine(r, 0, k * BLK as u64);
    for p in parts {
        match p.comp {
            None => {
                r = hole(r, p.lblk - pos);
                let seeds = (0..p.n as u64).map(|i| blk_seed(p.pba + i));
                r = crc::crc32c_blocks(r, got[gi..gi + p.n as usize].iter().copied().zip(seeds));
                gi += p.n as usize;
                pos = p.lblk + p.n as u64;
            }
            Some(m) => {
                let (lo, hi) = (blk.max(p.lblk), (blk + n).min(p.lblk + m.win as u64));
                r = hole(r, lo - pos);
                let len = (hi - lo) * BLK as u64;
                let c = if m.skip == 0 && m.win == m.raw_blks && hi - lo == m.win as u64 {
                    m.lcrc
                } else {
                    let d = &out[(lo - blk) as usize * BLK..(hi - blk) as usize * BLK];
                    // SAFETY: every byte of the range was written by the caller (decoded copy).
                    let d = unsafe { std::slice::from_raw_parts(d.as_ptr().cast::<u8>(), d.len()) };
                    crc::crc32c(0, d)
                };
                r = crc::crc32c_combine(r, c, len);
                pos = hi;
            }
        }
    }
    hole(r, blk + n - pos)
}

/// One extent run found by a lookup: logical start block + location of its encoded value in `ext_raw`.
#[derive(Clone, Copy, Debug)]
struct ExtIdx {
    lblk: u64,
    off: u32,
    len: u32,
}

pub(crate) struct Stage<'s, 'a, D: BlockDev, C: Clock> {
    pub cpu_yield: bool,
    pub s: &'s mut ShardStore<D>,
    pub clk: &'s mut C,
    map: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    dels: Vec<(Vec<u8>, Vec<u8>)>,
    /// Omap batches staged as runs (adr 0476), in txn order: (object, entries). Emitted as `RunPut`
    /// after the record's tree ops; a later op of the txn on one of their keys demotes it to a tree op first.
    sruns: Vec<(u64, RunBuilder)>,
    /// Omap LSM ops of the txn (store with `FEAT_OMAP_LSM`, adr 0610), in op order: emitted as `Op::Omap`.
    oops: Vec<OOp>,
    /// Selected point-range ops and their native equivalents, for exact final WAL-size fallback.
    point_ranges: Vec<(usize, OOp)>,
    /// Index in the transaction of the operation being applied: the identity of a point range removal's enumeration
    /// ([`RangeKey::seq`]), the same on every retry whatever earlier operations select.
    op_index: u32,
    /// The same ops applied: the newest source of this txn's own omap reads (clone after writes of the txn).
    omem: Memtable,
    #[cfg(feature = "rocksdb")]
    rocks_omem: Option<crate::rocks_omap::mem::Memtable>,
    #[cfg(feature = "splinterdb")]
    splinter_omem: Option<crate::foreign_mem::Memtable>,
    sc: Scratch,
    objs: ObjTab<'a>,
    base_id: u64,
    seq: u64,
    frees: Vec<(u64, u32)>,
    data: Vec<(u64, D::Buf)>,
    data_crcs: Vec<Vec<u32>>,
    /// `Txn::copies` so far: runs the DMA budget refused a staging copy for (adr 0175 am. 4).
    copies: Vec<CopyRun>,
    /// `Txn::tails` so far.
    tails: Vec<u32>,
    /// Pre-written pieces this txn claimed instead of allocating and writing (adr 0477): released if it is discarded.
    pre: Vec<PreClaim>,
    planning: bool,
    planned: Vec<Extent>,
    /// System class (`OTxn::sys` or meta-collection only): data and meta reserve floor = half the user reserve.
    freeing: bool,
    /// Op-triggered shrink (remove, truncate, zero, rmcoll): with `!grows` the txn may use ALL reserves (adr 0021 am. 21).
    shrink: bool,
    /// The txn can add state: an op outside the remove-only set (write, clone, attrs, omap set, touch, mkcoll, rename,
    /// ...) or a partial-block zero of a present block (a new block; the old one may stay shared with a clone).
    grows: bool,
    /// Compression of this txn's full aligned chunks (adr 0059 am. 1); `None` = raw writes. Never set on a store without
    /// `FEAT_COMPRESSION`.
    comp: Option<CompSpec>,
    max_key: usize,
    /// Entry size values of short keys stay under (inline limit, fragment chunk): `Tree::soft_entry`.
    soft_entry: usize,
    /// crc32c (seed `!0`, the msgr2 data-segment crc) of the bytes the last `eff_read` returned, when it came
    /// entirely from verified committed blocks (no overlay, no hole): lets the transport skip its own pass.
    pub read_crc: Option<u32>,
    discovered: bool,
    /// Values staged for data blocks (adr 0021 am. 46): `(main key, onode id, slot, bytes)`; the overlay holds `[V_PEND][index]`
    /// until `flush_ext_vals` (finish) allocates and stages the blocks of those still referenced.
    pending_ext: Vec<(Vec<u8>, u64, Slot, Vec<u8>)>,
    /// Classes whose dictionary this txn stages (`Z` puts in the overlay, bit per class); applied ones reach `State::dicts` with the record.
    pending_dicts: u64,
    material_obj: usize,
    material_pos: u64,
    material_span: Option<(u64, bool)>,
    material_raw_until: Option<u64>,
    /// `TOp::Reformat` with `max_frags`: (onode id, first block, end block, max_frags), checked after allocation.
    reformat_check: Option<(u64, u64, u64, u32)>,
    encoding: Option<Encoding>,
    compression_at_start: bool,
    /// Payload buffers of the txn (`OTxn::payloads`): device writes by reference + receive-pass block crcs (adr 0061
    /// am. 4).
    payloads: Vec<crc::Payload>,
}

/// Value of a `V_CINL` record when its dictionary is in the table (`None` = unknown dictionary or corrupt: slow path).
fn vc_fast(raw: &[u8], tab: &crate::state::DictTab) -> Option<Vec<u8>> {
    vcomp_unpack(raw, vc_dict(raw, tab)?)
}

/// Dictionary slot a `V_CINL` record names, when the table holds it.
fn vc_dict<'t>(raw: &[u8], tab: &'t crate::state::DictTab) -> Option<&'t Arc<ZDict>> {
    tab.slots.get(vcomp_dict(raw)? as usize)?.get()
}

/// [`vc_fast`] appended to `out` as `le32 length, value` (an encoded listing); `false` = slow path, `out` unchanged.
fn vc_fast_enc(raw: &[u8], tab: &crate::state::DictTab, out: &mut Vec<u8>) -> bool {
    let Some(zd) = vc_dict(raw, tab) else {
        return false;
    };
    let at = out.len();
    out.extend_from_slice(&[0; 4]);
    if !vcomp_unpack_into(raw, zd, out) {
        out.truncate(at);
        return false;
    }
    let n = (out.len() - at - 4) as u32;
    out[at..at + 4].copy_from_slice(&n.to_le_bytes());
    true
}

/// The entries of an encoded omap listing (`Stage::scan_omap_enc` without head) as pairs; keys only: empty values.
fn enc_decode(enc: &[u8], n: usize, values: bool) -> KvList {
    let mut p = 0usize;
    let mut take = || {
        let l = denc::le::rd_u32(enc, p) as usize;
        let v = enc[p + 4..p + 4 + l].to_vec();
        p += 4 + l;
        v
    };
    (0..n)
        .map(|_| {
            let k = take();
            (k, if values { take() } else { Vec::new() })
        })
        .collect()
}

/// `enc` with the values read at the end inserted, each as `le32 length, value` at its position (`ScanMemo::holes`).
fn splice_holes(enc: &[u8], holes: &[(usize, u32)], vals: &[Vec<u8>]) -> Vec<u8> {
    let extra: usize = vals.iter().map(|v| 4 + v.len()).sum();
    let mut out = Vec::with_capacity(enc.len() + extra + 1);
    let mut at = 0;
    for (&(pos, _), v) in holes.iter().zip(vals) {
        out.extend_from_slice(&enc[at..pos]);
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v);
        at = pos;
    }
    out.extend_from_slice(&enc[at..]);
    out
}

fn counted(o: &Ghobject) -> bool {
    // EC stash generations are bookkeeping of the shard, not objects of the pool
    !o.is_pgmeta() && !o.hobj.is_temp() && o.generation == Ghobject::NO_GEN
}

/// Owner count change `punch` applies to the blocks of one extent after its walk.
#[derive(Clone, Copy)]
enum RefOp {
    /// one owner less (`ref_adj`; the last one frees)
    Dec,
    /// one owner more (`ref_adj`)
    Inc,
    /// an exclusive (unflagged) extent got a second owner: new refcount record
    Two,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OmapScanMode {
    Values,
    Keys,
    Recovery,
}

type Kv = Vec<(Vec<u8>, Vec<u8>)>;

impl<D: BlockDev, C: Clock> Drop for Stage<'_, '_, D, C> {
    fn drop(&mut self) {
        if let Some(enc) = self.encoding.take() {
            self.s.cbuf = enc.bytes;
        }
        let mut sc = std::mem::take(&mut self.sc);
        sc.colls.clear();
        sc.coll_ids.clear();
        sc.names.drain().for_each(|(k, _)| crate::vpool::give(k));
        sc.vb.clear();
        sc.ext_raw.clear();
        sc.exts.clear();
        sc.odel.clear();
        sc.obatch.clear();
        self.s.scratch = sc;
    }
}

impl<'s, 'a, D: BlockDev, C: Clock> Stage<'s, 'a, D, C> {
    pub fn new(s: &'s mut ShardStore<D>, clk: &'s mut C) -> Self {
        let t = &s.sh.state().tree;
        let (max_key, soft_entry) = (t.max_key(), t.soft_entry());
        let base_id = s.sh.next_lsn() << ID_SEQ_BITS;
        let compression_at_start = s.compression;
        let mut sc = std::mem::take(&mut s.scratch);
        sc.ids.clear();
        #[cfg(feature = "rocksdb")]
        let rocks_omem =
            s.sh.rocks_selected()
                .then(crate::rocks_omap::mem::Memtable::new);
        #[cfg(feature = "splinterdb")]
        let splinter_omem =
            s.sh.splinter_selected()
                .then(crate::foreign_mem::Memtable::new);
        Stage {
            cpu_yield: false,
            s,
            clk,
            map: BTreeMap::new(),
            dels: Vec::new(),
            sruns: Vec::new(),
            oops: Vec::new(),
            point_ranges: Vec::new(),
            op_index: 0,
            omem: Memtable::new(),
            #[cfg(feature = "rocksdb")]
            rocks_omem,
            #[cfg(feature = "splinterdb")]
            splinter_omem,
            sc,
            objs: ObjTab(Vec::new()),
            base_id,
            seq: 0,
            frees: Vec::new(),
            data: Vec::new(),
            data_crcs: Vec::new(),
            copies: Vec::new(),
            tails: Vec::new(),
            pre: Vec::new(),
            planning: false,
            planned: Vec::new(),
            freeing: false,
            shrink: false,
            grows: false,
            comp: None,
            max_key,
            soft_entry,
            read_crc: None,
            discovered: false,
            pending_ext: Vec::new(),
            pending_dicts: 0,
            material_obj: 0,
            material_pos: 0,
            material_span: None,
            material_raw_until: None,
            reformat_check: None,
            encoding: None,
            compression_at_start,
            payloads: Vec::new(),
        }
    }

    pub fn resume(s: &'s mut ShardStore<D>, clk: &'s mut C, p: Parts<'a, D::Buf>) -> Self {
        Stage {
            cpu_yield: false,
            s,
            clk,
            map: p.map,
            dels: p.dels,
            sruns: p.sruns,
            oops: p.oops,
            point_ranges: p.point_ranges,
            op_index: 0,
            omem: p.omem,
            #[cfg(feature = "rocksdb")]
            rocks_omem: p.rocks_omem,
            #[cfg(feature = "splinterdb")]
            splinter_omem: p.splinter_omem,
            sc: p.sc,
            objs: p.objs,
            base_id: p.base_id,
            seq: p.seq,
            frees: p.frees,
            data: p.data,
            data_crcs: p.data_crcs,
            copies: p.copies,
            tails: p.tails,
            pre: p.pre,
            planning: p.planning,
            planned: p.planned,
            freeing: p.freeing,
            shrink: p.shrink,
            grows: p.grows,
            comp: p.comp,
            max_key: p.max_key,
            soft_entry: p.soft_entry,
            read_crc: p.read_crc,
            discovered: p.discovered,
            pending_ext: Vec::new(),
            pending_dicts: 0,
            material_obj: p.material_obj,
            material_pos: p.material_pos,
            material_span: p.material_span,
            material_raw_until: p.material_raw_until,
            reformat_check: p.reformat_check,
            encoding: p.encoding,
            compression_at_start: p.compression_at_start,
            payloads: p.payloads,
        }
    }

    pub fn into_parts(mut self) -> Parts<'a, D::Buf> {
        debug_assert!(
            self.pending_ext.is_empty(),
            "ext values staged but not flushed"
        );
        Parts {
            map: std::mem::take(&mut self.map),
            dels: std::mem::take(&mut self.dels),
            sruns: std::mem::take(&mut self.sruns),
            oops: std::mem::take(&mut self.oops),
            point_ranges: std::mem::take(&mut self.point_ranges),
            omem: std::mem::take(&mut self.omem),
            #[cfg(feature = "rocksdb")]
            rocks_omem: self.rocks_omem.take(),
            #[cfg(feature = "splinterdb")]
            splinter_omem: self.splinter_omem.take(),
            sc: std::mem::take(&mut self.sc),
            objs: ObjTab(std::mem::take(&mut self.objs.0)),
            base_id: self.base_id,
            seq: self.seq,
            frees: std::mem::take(&mut self.frees),
            data: std::mem::take(&mut self.data),
            data_crcs: std::mem::take(&mut self.data_crcs),
            copies: std::mem::take(&mut self.copies),
            tails: std::mem::take(&mut self.tails),
            pre: std::mem::take(&mut self.pre),
            planning: self.planning,
            planned: std::mem::take(&mut self.planned),
            freeing: self.freeing,
            shrink: self.shrink,
            grows: self.grows,
            comp: self.comp,
            max_key: self.max_key,
            soft_entry: self.soft_entry,
            read_crc: self.read_crc,
            discovered: self.discovered,
            material_obj: self.material_obj,
            material_pos: self.material_pos,
            material_span: self.material_span,
            material_raw_until: self.material_raw_until,
            reformat_check: self.reformat_check,
            encoding: self.encoding.take(),
            compression_at_start: self.compression_at_start,
            payloads: std::mem::take(&mut self.payloads),
        }
    }

    fn new_id(&mut self) -> Result<u64> {
        self.seq += 1;
        if self.seq >= 1 << ID_SEQ_BITS {
            return Err(ObjError::TooLarge);
        }
        Ok(self.base_id | self.seq)
    }

    // ------------------------------------------------------------------ KV overlay

    fn covered(&self, k: &[u8]) -> bool {
        self.dels
            .iter()
            .any(|(a, b)| a.as_slice() <= k && k < b.as_slice())
    }

    /// Overlay-aware point read; `f` sees the value (or `None`) without an allocation.
    fn kget_with<R>(&mut self, k: &[u8], f: impl FnOnce(Option<&[u8]>) -> R) -> Result<R> {
        // a staged run is newer than the overlay entries of its keys (a later op demotes the key first); its removal
        // entry: the key is absent
        if !self.sruns.is_empty()
            && let Some(id) = omap_id(k)
        {
            for (rid, b) in self.sruns.iter().rev() {
                if *rid == id
                    && let Some(i) = b.find(k)
                {
                    let v = b.entry(i).1;
                    return Ok(f((!is_tomb(v)).then_some(v)));
                }
            }
        }
        if let Some(v) = self.map.get(k) {
            return Ok(f(v.as_deref()));
        }
        if self.sc.odel.contains(k) || self.covered(k) {
            return Ok(f(None));
        }
        let mut vb = std::mem::take(&mut self.sc.vb);
        vb.clear();
        let r = self.s.tget(self.clk, k, &mut vb);
        let out = r.map(|found| f(found.then_some(vb.as_slice())));
        self.sc.vb = vb;
        out
    }

    fn kget(&mut self, k: &[u8]) -> Result<Option<Vec<u8>>> {
        self.kget_with(k, |v| v.map(<[u8]>::to_vec))
    }

    fn kput(&mut self, k: Vec<u8>, v: Vec<u8>) {
        self.map.insert(k, Some(v));
    }

    fn kdel(&mut self, k: Vec<u8>) {
        self.map.insert(k, None);
    }

    fn kforget(&mut self, a: &[u8], b: &[u8]) {
        let keys: Vec<Vec<u8>> = self
            .map
            .range::<[u8], _>((Bound::Included(a), Bound::Excluded(b)))
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            self.map.remove(&k);
        }
    }

    fn kdelrange(&mut self, a: Vec<u8>, b: Vec<u8>) {
        if a >= b {
            return;
        }
        self.kforget(&a, &b);
        self.dels.push((a, b));
    }

    /// A later op of this txn takes omap key `mk` (adr 0476): a staged run holding it gives it up and it
    /// becomes a tree put of the run's value (a tree removal for a removal entry).
    fn demote(&mut self, mk: &[u8]) -> Result<()> {
        if self.sruns.is_empty() {
            return Ok(());
        }
        let Some(id) = omap_id(mk) else {
            return Ok(());
        };
        let mut v = None;
        for (rid, b) in self.sruns.iter_mut().rev() {
            if *rid == id
                && let Some(i) = b.find_asc(mk)
            {
                if v.is_none() {
                    v = Some(b.entry(i).1.to_vec());
                }
                b.remove(i);
            }
        }
        match v {
            Some(v) if is_tomb(&v) => self.kdel(mk.to_vec()),
            Some(v) => self.kput(mk.to_vec(), v),
            None => {}
        }
        Ok(())
    }

    /// [`Stage::demote`] for every staged run key of `id` in `[a, b)`.
    fn demote_range(&mut self, id: u64, a: &[u8], b: &[u8]) -> Result<()> {
        if self.sruns.is_empty() {
            return Ok(());
        }
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for (rid, r) in &self.sruns {
            if *rid == id {
                for i in r.range(a, b) {
                    if !r.removed(i) {
                        keys.push(r.entry(i).0.to_vec());
                    }
                }
            }
        }
        keys.sort_unstable();
        keys.dedup();
        for k in keys {
            self.demote(&k)?;
        }
        Ok(())
    }

    /// The staged runs of `id` leave (its omap is cleared or the object removed by this txn).
    fn drop_sruns(&mut self, id: u64) {
        self.sruns.retain(|(rid, _)| *rid != id);
    }

    /// A client omap batch of `id` may be staged as one run (adr 0476): [`Stage::run_eligible`], every entry one inline
    /// tree entry, run room ([`Stage::run_admit`]).
    fn run_ok(&mut self, id: u64, run: &KvRunData<'_>) -> Result<bool> {
        if !self.run_eligible(id, run.len()) {
            return Ok(false);
        }
        let ext_min = self.s.val_ext_min;
        for (k, v) in run.view().iter() {
            let mkl = 10 + k.len();
            if 15 + k.len() > self.max_key
                || v.len() > self.inline_room(mkl)
                || (ext_min > 0 && v.len() >= ext_min)
            {
                return Ok(false);
            }
        }
        // WAL op bytes of the run: header, per entry its header and the tree key prefix + value tag
        let v = run.view();
        let bytes = crate::runs::RUN_OP_HDR + v.entries().len() + v.len() * (6 + 10 + 1);
        self.run_admit(id, bytes)
    }

    /// A batch of `n` entries of `id` may become a run (adr 0476): store feature, at least `run_min` entries, a pool
    /// object (not pgmeta, temp or an EC stash generation) with no value outside its record (fragments, data blocks: a
    /// blind write could not release them), and no run of `id` staged by this txn yet: one new run per object and record
    /// (its order lsn is the record's); a further batch of the txn takes the tree path (it demotes the staged run's keys
    /// it takes).
    fn run_eligible(&mut self, id: u64, n: usize) -> bool {
        if !self.s.omap_runs || n < self.s.run_min || self.sruns.iter().any(|(rid, _)| *rid == id) {
            return false;
        }
        let w = self.w(id);
        w.counted && w.on.flags & (F_OFRAG | F_OEXT) == 0
    }

    /// Run room for a run of `id` of `bytes` WAL op bytes. Without it a queued txn waits for the merges under way
    /// (`WouldBlock`, retried on store progress) instead of taking the tree path, whose dirty pages the merges need; an
    /// object at `run_max` runs waits for its compaction; blocking callers, a size pre-flight ([`Stage::plan`]: it sizes
    /// the tree path, the larger record, and never waits for merges) and a store whose merges cannot proceed take the
    /// tree path (`Ok(false)`).
    fn run_admit(&mut self, id: u64, bytes: usize) -> Result<bool> {
        // a run's entries are addressed by u32 offsets (`runs::RUN_BYTES_MAX`): a larger batch takes the tree path
        if !crate::runs::run_fits(bytes - crate::runs::RUN_OP_HDR) {
            return Ok(false);
        }
        // waiting for run room only pays while the core runs other work meanwhile: not in a blocking barrier, not for a
        // size pre-flight
        let wait = self.s.nonblock && !self.s.barrier && !self.planning;
        let room_obj = self.s.sh.run_room_obj(id);
        if room_obj && self.s.sh.run_room_for(bytes) {
            return Ok(true);
        }
        if wait && self.s.sh.run_admit_blocks(id, bytes) {
            // the object holds `run_max` runs (the compaction under way makes room) or the merges under way make pool room
            self.s.stats.run_waits += 1;
            self.s.wb_why = if room_obj {
                "run drains"
            } else {
                "run room obj"
            };
            self.s.wb_run = Some((id, bytes));
            return Err(ObjError::WouldBlock);
        }
        Ok(false)
    }

    /// A removal batch of `id` (`order`: the positions of `keys` ascending and distinct, `None`: `keys` is) may be staged as
    /// one run of removals (adr 0647-omap-blind-removals D1): [`Stage::run_eligible`], every key fits a tree entry (a
    /// longer key is in no run and no leaf), run room ([`Stage::run_admit`]).
    fn rm_run_ok<K: AsRef<[u8]>>(
        &mut self,
        id: u64,
        keys: &[K],
        order: Option<&[usize]>,
    ) -> Result<bool> {
        let n = order.map_or(keys.len(), <[usize]>::len);
        if !self.run_eligible(id, n) {
            return Ok(false);
        }
        let mut bytes = crate::runs::RUN_OP_HDR + n * (6 + 10);
        for j in 0..n {
            let k = keys[order.map_or(j, |o| o[j])].as_ref();
            if 15 + k.len() > self.max_key {
                return Ok(false);
            }
            bytes += k.len();
        }
        self.run_admit(id, bytes)
    }

    /// Stage a removal batch of `id` as one run of removal entries ([`Stage::rm_run_ok`]): blind, no tree access. It is
    /// newer than this txn's earlier ops on the keys (the record logs runs after its tree ops); a later op of the txn on
    /// one of the keys demotes it to a tree removal first ([`Stage::demote`]).
    fn stage_rm_run<K: AsRef<[u8]>>(&mut self, id: u64, keys: &[K], order: Option<&[usize]>) {
        let pfx = omap_key(id, b"");
        let n = order.map_or(keys.len(), <[usize]>::len);
        let kb: usize = keys.iter().map(|k| k.as_ref().len()).sum();
        let mut b = RunBuilder::with_capacity(n, kb + n * pfx.len());
        for j in 0..n {
            b.push(&pfx, keys[order.map_or(j, |o| o[j])].as_ref(), &[], &[]);
        }
        self.sruns.push((id, b));
        self.s.stats.run_puts += 1;
        self.s.stats.run_rms += 1;
    }

    /// Stage the batch as one run of `id`: blind (no tree access), one copy into the run buffer.
    fn stage_run(&mut self, id: u64, run: &KvRunData<'_>) {
        let pfx = omap_key(id, b"");
        let v = run.view();
        let mut b =
            RunBuilder::with_capacity(v.len(), v.entries().len() + v.len() * (pfx.len() + 1));
        for (k, val) in v.iter() {
            b.push(&pfx, k, &[V_INLINE], val);
        }
        self.sruns.push((id, b));
        self.s.stats.run_puts += 1;
    }

    /// Ascending merged scan of the tree and the overlay, at most `max` entries.
    /// Dedup records in `[a, b)` (keys and values, at most `max`; adr 0593-dedup-deep-scrub-reformat).
    pub fn dedup_scan(&mut self, a: &[u8], b: &[u8], max: usize) -> Result<Kv> {
        debug_assert!(a.first() == Some(&super::dedup::T_DEDUP));
        self.kscan_as(a, b, max, true)
    }

    fn kscan(&mut self, a: &[u8], b: &[u8], max: usize) -> Result<Kv> {
        self.kscan_as(a, b, max, false)
    }

    /// [`Self::kscan`]; `listing`: the tree leaves are read scan-resistant (`ScanCursor::listing`).
    fn kscan_as(&mut self, a: &[u8], b: &[u8], max: usize, listing: bool) -> Result<Kv> {
        let mut out = Vec::new();
        if a >= b || max == 0 {
            return Ok(out);
        }
        let mvec: Vec<(Vec<u8>, Option<Vec<u8>>)> = self
            .map
            .range::<[u8], _>((Bound::Included(a), Bound::Excluded(b)))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut mi = 0;
        let mut cur = ScanCursor::new(a, b);
        if listing {
            // a listing reads its leaves scan-resistant, in one rolling read-ahead window for the entries it wants
            cur.cold = true;
            cur.ra_win = (max / 32).clamp(1, SCAN_RA_MAX) as u32;
        }
        let mut buf: VecDeque<(Vec<u8>, Vec<u8>)> = VecDeque::new();
        let mut tdone = false;
        loop {
            if out.len() >= max {
                break;
            }
            while buf.is_empty() && !tdone {
                let want = (max - out.len()).clamp(16, 512);
                tdone = self.s.tscan(self.clk, &mut cur, want, &mut |k, v| {
                    buf.push_back((k.to_vec(), v.to_vec()))
                })?;
                let (dels, odel) = (&self.dels, &self.sc.odel);
                buf.retain(|(k, _)| {
                    !dels
                        .iter()
                        .any(|(x, y)| x.as_slice() <= k.as_slice() && k.as_slice() < y.as_slice())
                        && !odel.contains(k)
                });
            }
            let t = buf.front().map(|(k, _)| k.as_slice());
            let m = mvec.get(mi).map(|(k, _)| k.as_slice());
            match (t, m) {
                (None, None) => break,
                (Some(_), None) => out.push(buf.pop_front().unwrap()),
                (None, Some(_)) => {
                    if let Some(v) = &mvec[mi].1 {
                        out.push((mvec[mi].0.clone(), v.clone()));
                    }
                    mi += 1;
                }
                (Some(tk), Some(mk)) => {
                    if tk < mk {
                        out.push(buf.pop_front().unwrap());
                    } else {
                        if tk == mk {
                            buf.pop_front();
                        }
                        if let Some(v) = &mvec[mi].1 {
                            out.push((mvec[mi].0.clone(), v.clone()));
                        }
                        mi += 1;
                    }
                }
            }
        }
        Ok(out)
    }

    // ------------------------------------------------------------------ collections / names

    fn coll_ent(&mut self, cid: &CollT) -> Result<&mut CollEnt> {
        if !self.sc.colls.contains_key(cid) {
            let mut kb = [0u8; 15];
            let kn = coll_key_buf(cid, &mut kb);
            let info = self.kget_with(&kb[..kn], |v| v.map(CollInfo::decode))?;
            let info = match info {
                Some(Some(i)) => Some(i),
                Some(None) => return Err(ObjError::Eio("bad collection record".into())),
                None => None,
            };
            if let Some(i) = &info {
                self.sc.coll_ids.insert(i.id, *cid);
            }
            self.sc.colls.insert(*cid, CollEnt { info, dirty: false });
        }
        Ok(self.sc.colls.get_mut(cid).unwrap())
    }

    pub fn coll_info(&mut self, cid: &CollT) -> Result<Option<CollInfo>> {
        Ok(self.coll_ent(cid)?.info.clone())
    }

    fn coll_id(&mut self, cid: &CollT) -> Result<u64> {
        self.coll_ent(cid)?
            .info
            .as_ref()
            .map(|i| i.id)
            .ok_or(ObjError::NoColl)
    }

    fn load_work(&mut self, id: u64, coll: u64, oid: &Ghobject) -> Result<()> {
        if self.objs.contains_key(&id) {
            return Ok(());
        }
        let on = self
            .kget_with(&onode_key_arr(id), |v| v.map(Onode::decode))?
            .ok_or_else(|| ObjError::Eio(format!("onode {id} missing")))?
            .ok_or_else(|| ObjError::Eio(format!("onode {id} corrupt")))?;
        let c = counted(oid);
        self.objs.insert(
            id,
            Work {
                orig_comp: (on.comp, on.comp_orig),
                orig: Some((coll, on.size, c)),
                on,
                coll,
                counted: c,
                gone: false,
                dirty_on: false,
                pgmeta: oid.is_pgmeta(),
                runs: Dirty::default(),
                shared_in: false,
            },
        );
        Ok(())
    }

    /// Name-index key of `oid` in collection `cn` (adr 0021 am. 30): its `N` key, or the `L` key when that exceeds the
    /// tree key limit (a pure function of the name, so an object never changes index). `NameTooLong` when the store
    /// has no `FEAT_LONG_NAME` or even the `L` key does not fit.
    fn name_key_for(&self, cn: u64, oid: &Ghobject) -> Result<Vec<u8>> {
        let nk = name_key_of(cn, oid);
        if nk.len() <= self.max_key {
            return Ok(nk);
        }
        if !self.s.long_names {
            return Err(ObjError::NameTooLong);
        }
        let lk = long_key_of(cn, oid);
        if lk.len() > self.max_key {
            return Err(ObjError::NameTooLong);
        }
        Ok(lk)
    }

    /// An `L` key is about to be staged: the shard's `L` index is no longer known to be empty.
    fn note_long(&mut self, nk: &[u8]) {
        if nk[0] == T_LNAME {
            self.s.long_none = false;
        }
    }

    /// Does the `L` index of this shard (maybe) hold names? One whole-index probe, then cached until an `L` key is staged.
    /// The probe sees this stage's overlay; an "empty" answer that depends on overlay deletes is NOT cached: this txn
    /// may still fail or be a dry run (`check_txn`), and the tree would keep the `L` keys behind a stale "none".
    fn long_maybe(&mut self) -> Result<bool> {
        if !self.s.long_names {
            return Ok(false);
        }
        if self.s.long_none {
            return Ok(false);
        }
        let none = self.kscan(&[T_LNAME], &[T_LNAME + 1], 1)?.is_empty();
        let (a, b) = (&[T_LNAME][..], &[T_LNAME + 1][..]);
        let staged = self
            .map
            .range::<[u8], _>((Bound::Included(a), Bound::Excluded(b)))
            .next()
            .is_some()
            || self
                .dels
                .iter()
                .any(|(x, y)| x.as_slice() < b && a < y.as_slice());
        if none && !staged {
            self.s.long_none = true;
        }
        Ok(!none)
    }

    /// Current `N` key of object `id` (the `names` entry that points at it).
    fn name_of(&self, id: u64) -> Vec<u8> {
        self.sc
            .names
            .iter()
            .find(|(_, v)| **v == Some(id))
            .map(|(k, _)| k.clone())
            .expect("loaded object has a name entry")
    }

    /// Non-blocking readiness probe: touch the tree paths a read/write of `[off, off+len)` of `oid` will walk (name,
    /// then onode + object_info and snapset attrs + extent range). `WouldBlock` = a page was missing (its read is submitted). The
    /// follow-ups are probed together, so a cold object costs two read rounds, not four.
    pub fn warm(&mut self, cid: &CollT, oid: &Ghobject, off: u64, len: u64) -> Result<()> {
        let cn = self.coll_id(cid)?;
        let Ok(nk) = self.name_key_for(cn, oid) else {
            return Ok(()); // the real op reports it
        };
        let id = match self.sc.names.get(nk.as_slice()) {
            Some(r) => *r,
            None => self.kget_with(&nk, |v| {
                v.and_then(|b| b.try_into().ok()).map(u64::from_le_bytes)
            })?,
        };
        crate::vpool::give(nk);
        let Some(id) = id else { return Ok(()) };
        let mut blocked = false;
        let mut fold = |r: Result<()>| match r {
            Err(ObjError::WouldBlock) => {
                blocked = true;
                Ok(())
            }
            r => r,
        };
        fold(self.load_work(id, cn, oid))?;
        // both attributes an op's state load reads (`_` = object_info, `snapset`): an unprobed one misses in the run
        fold(self.get_val(id, Slot::Attr, b"_").map(drop))?;
        fold(self.get_val(id, Slot::Attr, b"snapset").map(drop))?;
        if self
            .objs
            .get(&id)
            .is_some_and(|w| w.on.flags & F_INLINE != 0)
        {
            fold(self.kget_with(&inl_key_arr(id), |_| ()))?;
        }
        if len > 0 {
            let a = off / BLK as u64;
            let b = (off + len).div_ceil(BLK as u64);
            fold(self.extents_set(id, a, b.min(MAX_BLOCKS)))?;
        }
        if blocked {
            Err(ObjError::WouldBlock)
        } else {
            Ok(())
        }
    }

    /// `warm` for a removal (adr 0021 am. 33): every page `remove_obj` and the txn's submit visit (name, onode, `_`,
    /// all extents, the routes of the object's key ranges), probed in one pass so the reads run in parallel instead of
    /// one blocking miss after the other. `WouldBlock` = reads queued.
    pub fn warm_rm(&mut self, cid: &CollT, oid: &Ghobject) -> Result<()> {
        let cn = self.coll_id(cid)?;
        let Ok(nk) = self.name_key_for(cn, oid) else {
            return Ok(());
        };
        let id = match self.sc.names.get(nk.as_slice()) {
            Some(r) => *r,
            None => self.kget_with(&nk, |v| {
                v.and_then(|b| b.try_into().ok()).map(u64::from_le_bytes)
            })?,
        };
        let Some(id) = id else { return Ok(()) };
        let mut blocked = false;
        let mut fold = |r: Result<()>| match r {
            Err(ObjError::WouldBlock) => {
                blocked = true;
                Ok(())
            }
            r => r,
        };
        fold(self.load_work(id, cn, oid))?;
        fold(self.get_val(id, Slot::Attr, b"_").map(drop))?;
        fold(self.extents_set(id, 0, INF))?;
        // shared extents (am. 32): the remove reads and rewrites their refcount records
        let mut refs: Vec<(u64, u32)> = Vec::new();
        for e in &self.sc.exts {
            if let Some(x) = ExtRaw::new(&self.sc.ext_raw[e.off as usize..(e.off + e.len) as usize])
                && x.shared()
            {
                refs.push((x.pba(), x.len()));
            }
        }
        for (pba, n) in refs {
            let a = ref_key(pba.saturating_sub(MAX_RUN as u64 - 1));
            if let Err(StoreError::Miss) = self.s.sh.prefetch(&a, &ref_key(pba + n as u64)) {
                blocked = true;
            }
        }
        // flags known once the onode is in (else the next pass probes the optional ranges)
        let flags = self.objs.get(&id).map_or(0, |w| w.on.flags);
        let mut ranges = vec![id_range(T_EXT, id), id_range(T_ATTR, id)];
        for (f, t) in [
            (F_OMAP, T_OMAP),
            (F_OFRAG | F_AFRAG | F_HFRAG, T_FRAG),
            (F_HDR, T_HDR),
            (F_INLINE, T_INL),
        ] {
            if flags & f != 0 {
                ranges.push(id_range(t, id));
            }
        }
        for (a, b) in &ranges {
            // errors: the real op reports them
            if let Err(StoreError::Miss) = self.s.sh.probe_range(a, b) {
                blocked = true;
            }
        }
        for k in [onode_key(id), nk] {
            if let Err(StoreError::Miss) = self.s.sh.probe_key(&k) {
                blocked = true;
            }
            crate::vpool::give(k);
        }
        if blocked {
            Err(ObjError::WouldBlock)
        } else {
            Ok(())
        }
    }

    /// Onode id of an existing object (`None` if absent).
    pub fn lookup(&mut self, cid: &CollT, oid: &Ghobject) -> Result<Option<u64>> {
        let cn = self.coll_id(cid)?;
        let nk = self.name_key_for(cn, oid)?;
        if let Some(r) = self.sc.names.get(nk.as_slice()) {
            let r = *r;
            crate::vpool::give(nk);
            return Ok(r);
        }
        let r = self
            .kget_with(&nk, |v| {
                v.map(|b| {
                    b.try_into()
                        .map(u64::from_le_bytes)
                        .map_err(|_| ObjError::Eio("bad name record".into()))
                })
            })?
            .transpose()?;
        if let Some(id) = r {
            self.load_work(id, cn, oid)?;
        }
        self.sc.names.insert(nk, r);
        Ok(r)
    }

    fn create(&mut self, cid: &CollT, oid: &Ghobject) -> Result<u64> {
        let cn = self.coll_id(cid)?;
        let nk = self.name_key_for(cn, oid)?;
        self.note_long(&nk);
        let id = self.new_id()?;
        self.kput(nk.clone(), id.to_le_bytes().to_vec());
        self.sc.names.insert(nk, Some(id));
        self.objs.insert(
            id,
            Work {
                on: Onode::default(),
                orig_comp: (0, 0),
                orig: None,
                coll: cn,
                counted: counted(oid),
                gone: false,
                dirty_on: true,
                pgmeta: oid.is_pgmeta(),
                runs: Dirty::default(),
                shared_in: false,
            },
        );
        Ok(id)
    }

    fn lookup_or_create(&mut self, cid: &CollT, oid: &Ghobject) -> Result<u64> {
        match self.lookup(cid, oid)? {
            Some(id) => Ok(id),
            None => self.create(cid, oid),
        }
    }

    fn w(&mut self, id: u64) -> &mut Work<'a> {
        self.objs.get_mut(&id).expect("onode loaded")
    }

    fn set_flag(&mut self, id: u64, f: u32) {
        let w = self.w(id);
        if w.on.flags & f != f {
            w.on.flags |= f;
            w.dirty_on = true;
        }
    }

    pub fn obj_size(&mut self, id: u64) -> u64 {
        self.w(id).on.size
    }

    /// The object's data version (adr 0593-dedup-deep-scrub-reformat): its counter and the tracking generation of its
    /// collection.
    pub fn data_version(&mut self, cid: &CollT, id: u64) -> Result<crate::obj::DataVersion> {
        let gen_ = self.coll_ent(cid)?.info.as_ref().map_or(0, |i| i.dv_gen);
        let tracking = self.coll_ent(cid)?.info.as_ref().is_some_and(|i| i.dv_on);
        Ok(crate::obj::DataVersion {
            id,
            dv_gen: gen_,
            dv: self.w(id).on.dv,
            tracking,
        })
    }

    fn set_size(&mut self, id: u64, size: u64) -> Result<()> {
        if blocks_for(size) > MAX_BLOCKS {
            return Err(ObjError::TooLarge);
        }
        let w = self.w(id);
        if w.on.size != size {
            w.on.size = size;
            w.dirty_on = true;
        }
        Ok(())
    }

    // ------------------------------------------------------------------ extents

    /// Extents overlapping blocks `[a, b)` into the scratch set (`sc.exts` + `sc.ext_raw`), ascending. No
    /// per-entry allocation: values are copied into one reusable buffer.
    fn extents_set(&mut self, id: u64, a: u64, b: u64) -> Result<()> {
        self.sc.ext_raw.clear();
        self.sc.exts.clear();
        let lo = a.saturating_sub(MAX_RUN as u64 - 1);
        if lo > u32::MAX as u64 || a >= b {
            return Ok(());
        }
        let start = ext_key_arr(id, lo as u32);
        let (end_v, end_a);
        let end: &[u8] = if b > u32::MAX as u64 {
            end_v = sub_range(T_EXT, S_EXT, id).1;
            &end_v
        } else {
            end_a = ext_key_arr(id, b as u32);
            &end_a
        };
        if a < u32::MAX as u64 && self.overlay_clear(&start, end) {
            return self.extents_fast(id, a, end);
        }
        let kv = self.kscan(&start, end, usize::MAX)?;
        for (k, v) in kv {
            let lblk = u32::from_be_bytes(k[10..14].try_into().unwrap()) as u64;
            let e = ExtRaw::new(&v).ok_or_else(|| ObjError::Eio("bad extent record".into()))?;
            if lblk + e.span() as u64 > a {
                ext_push(&mut self.sc, lblk, &v);
            }
        }
        Ok(())
    }

    /// Extents overlapping blocks `[a, b)`, ascending (owned form for the cold read/scrub/clone paths).
    /// Layout of blocks `[a, b)` of object `id` (adr 0593-dedup-deep-scrub-reformat, dedup-reformat.md 6) as the overlay
    /// sees it: logical extents, plain / compressed / shared physical bytes and the number of disjoint physical intervals
    /// they occupy (adjacent or overlapping runs merge).
    pub fn span_stats(&mut self, id: u64, a: u64, b: u64) -> Result<crate::obj::SpanStats> {
        let mut st = crate::obj::SpanStats::default();
        let mut phys: Vec<(u64, u64)> = Vec::new();
        for (l, e) in self.extents_in(id, a, b)? {
            let n = e.crcs.len() as u64;
            let span = e.span() as u64;
            let (lo, hi) = (l.max(a), (l + span).min(b));
            if lo >= hi {
                continue;
            }
            st.extents += 1;
            st.stored += (hi - lo) * BLK as u64;
            let (p0, pn) = if e.comp.is_some() {
                st.stored_compressed += span * BLK as u64;
                st.allocated_compressed += n * BLK as u64;
                (e.pba, n)
            } else {
                st.allocated += (hi - lo) * BLK as u64;
                (e.pba + (lo - l), hi - lo)
            };
            if e.shared {
                st.allocated_shared += pn * BLK as u64;
            }
            phys.push((p0, p0 + pn));
        }
        phys.sort_unstable();
        let mut end = None;
        for (s, e) in phys {
            match end {
                Some(x) if s <= x => end = Some(x.max(e)),
                _ => {
                    st.frags += 1;
                    end = Some(e);
                }
            }
        }
        Ok(st)
    }

    fn extents_in(&mut self, id: u64, a: u64, b: u64) -> Result<Vec<(u64, Ext)>> {
        self.extents_set(id, a, b)?;
        let mut out = Vec::with_capacity(self.sc.exts.len());
        for e in &self.sc.exts {
            let raw = &self.sc.ext_raw[e.off as usize..(e.off + e.len) as usize];
            out.push((
                e.lblk,
                Ext::decode(raw).ok_or_else(|| ObjError::Eio("bad extent record".into()))?,
            ));
        }
        Ok(out)
    }

    /// No pending put/delete of this txn touches `[a, b)`: the tree alone answers range reads.
    fn overlay_clear(&self, a: &[u8], b: &[u8]) -> bool {
        self.map
            .range::<[u8], _>((Bound::Included(a), Bound::Excluded(b)))
            .next()
            .is_none()
            && self
                .dels
                .iter()
                .all(|(x, y)| y.as_slice() <= a || x.as_slice() >= b)
            && !self.sc.odel.any_in(a, b)
    }

    /// Tree-only `extents_set`: one descent (predecessor + range in the same leaf) in the common case.
    fn extents_fast(&mut self, id: u64, a: u64, end: &[u8]) -> Result<()> {
        let pivot = ext_key_arr(id, a as u32);
        let mut bad;
        let hit = loop {
            self.sc.ext_raw.clear();
            self.sc.exts.clear();
            bad = false;
            let sc = &mut self.sc;
            let r = self.s.sh.scan_pred(&pivot, end, &mut |k, v| {
                if k.len() != 14 || k[..10] != pivot[..10] {
                    return;
                }
                let lblk = u32::from_be_bytes(k[10..14].try_into().unwrap()) as u64;
                match ExtRaw::new(v) {
                    Some(e) if lblk + e.span() as u64 > a => ext_push(sc, lblk, v),
                    Some(_) => {}
                    None => bad = true,
                }
            });
            match r {
                Err(StoreError::Miss) => self.s.miss_wait(self.clk)?,
                r => break r?,
            }
        };
        if hit {
            return if bad {
                Err(ObjError::Eio("bad extent record".into()))
            } else {
                Ok(())
            };
        }
        // predecessor may sit in the previous leaf: scan with the full look-back window
        let from = ext_key_arr(id, a.saturating_sub(MAX_RUN as u64 - 1) as u32);
        let mut cur = ScanCursor::new(&from, end);
        self.sc.ext_raw.clear();
        self.sc.exts.clear();
        bad = false;
        let sc = &mut self.sc;
        self.s.tscan(self.clk, &mut cur, usize::MAX, &mut |k, v| {
            if k.len() != 14 {
                return;
            }
            let lblk = u32::from_be_bytes(k[10..14].try_into().unwrap()) as u64;
            match ExtRaw::new(v) {
                Some(e) if lblk + e.span() as u64 > a => ext_push(sc, lblk, v),
                Some(_) => {}
                None => bad = true,
            }
        })?;
        if bad {
            return Err(ObjError::Eio("bad extent record".into()));
        }
        Ok(())
    }

    /// Release the committed blocks `[a, b)` of `id`: shrink/split extent runs, queue the block frees. A compressed record
    /// that is hit keeps its parts outside `[a, b)` as windows of the same chunk (adr 0059 am. 4): one part = same owner
    /// count, two parts = one owner more (refcount record), none = the record's ownership is released.
    fn punch(&mut self, id: u64, a: u64, b: u64) -> Result<()> {
        self.extents_set(id, a, b)?;
        // owner count changes of possibly shared blocks: applied through their refcounts after the walk (adr 0021 am. 32)
        let mut refs: Vec<(u64, u32, RefOp)> = Vec::new();
        for i in 0..self.sc.exts.len() {
            let ei = self.sc.exts[i];
            let raw = &self.sc.ext_raw[ei.off as usize..(ei.off + ei.len) as usize];
            let e = ExtRaw::new(raw).expect("validated by extents_set");
            let (s, len, span) = (ei.lblk, e.len() as u64, e.span() as u64);
            let (lo, hi) = (a.max(s), b.min(s + span));
            if lo >= hi {
                continue;
            }
            if let Some(m) = e.comp() {
                let (pba, n, shared_in) = (e.pba(), len as u32, e.shared());
                let mut acct = (-(m.phys_charge(n) as i64), -(span as i64 * BLK as i64));
                let mut parts = [None, None];
                if s < lo {
                    parts[0] = Some((s, m.sub(0, (lo - s) as u8)));
                }
                if hi < s + span {
                    parts[1] = Some((hi, m.sub((hi - s) as u8, (s + span - hi) as u8)));
                }
                let kept = parts.iter().flatten().count();
                if kept != 0 && !self.planning {
                    self.s.stats.comp_windows += 1;
                }
                let shared = shared_in || kept == 2;
                let enc = parts.map(|p| p.map(|(k, pm)| (k, pm, e.window_encode(pm, shared))));
                self.map.insert(ext_key(id, s as u32), None);
                for (k, pm, v) in enc.into_iter().flatten() {
                    self.map.insert(ext_key(id, k as u32), Some(v));
                    acct.0 += pm.phys_charge(n) as i64;
                    acct.1 += pm.win as i64 * BLK as i64;
                }
                self.comp_acct(id, acct.0, acct.1);
                match (kept, shared_in) {
                    (0, true) => refs.push((pba, n, RefOp::Dec)),
                    (0, false) => self.frees.push((pba, n)),
                    (2, true) => refs.push((pba, n, RefOp::Inc)),
                    (2, false) => refs.push((pba, n, RefOp::Two)),
                    _ => {}
                }
                continue;
            }
            if e.shared() {
                refs.push((e.pba() + (lo - s), (hi - lo) as u32, RefOp::Dec));
            } else {
                self.frees.push((e.pba() + (lo - s), (hi - lo) as u32));
            }
            if s < a {
                self.map.insert(
                    ext_key(id, s as u32),
                    Some(e.slice_encode(0, (a - s) as u32)),
                );
            } else {
                self.map.insert(ext_key(id, s as u32), None);
            }
            if s + len > b {
                let from = (b - s) as u32;
                self.map.insert(
                    ext_key(id, b as u32),
                    Some(e.slice_encode(from, len as u32 - from)),
                );
            }
        }
        for (pba, n, op) in refs {
            match op {
                RefOp::Dec => self.ref_adj(pba, n, false)?,
                RefOp::Inc => self.ref_adj(pba, n, true)?,
                // an unflagged extent is exclusive: no refcount record covers its blocks (am. 32 (a)); two owners now
                RefOp::Two => self.kput(ref_key(pba).to_vec(), ref_encode(n, 2)),
            }
        }
        Ok(())
    }

    /// Device runs holding the committed blocks `[blk, blk+n)` of `id` (`None` = all holes). Adjacent extents that
    /// are contiguous on the device merge up to the transfer limit. `crcs` also collects the stored block checksums.
    fn read_parts(&mut self, id: u64, blk: u64, n: u64, crcs: bool) -> Result<Option<Vec<Part>>> {
        let exts = self.extents_in(id, blk, blk + n)?;
        if exts.is_empty() {
            return Ok(None);
        }
        let mut parts: Vec<Part> = Vec::with_capacity(exts.len());
        for (s, e) in &exts {
            let (lo, hi) = (blk.max(*s), (blk + n).min(s + e.span() as u64));
            if lo >= hi {
                continue;
            }
            if e.comp.is_some() {
                // a compressed chunk is read whole (physical blocks), `span` says which logical blocks it stands for
                parts.push(Part {
                    lblk: *s,
                    pba: e.pba,
                    n: e.len(),
                    crcs: if crcs { e.crcs.clone() } else { Vec::new() },
                    comp: e.comp,
                });
                continue;
            }
            let (off, cnt) = ((lo - s) as u32, (hi - lo) as u32);
            let sl = e.slice(off, cnt);
            match parts.last_mut() {
                Some(p)
                    if p.comp.is_none()
                        && p.lblk + p.n as u64 == lo
                        && p.pba + p.n as u64 == sl.pba
                        && (p.n + cnt) as usize <= self.s.max_xfer_blk =>
                {
                    p.n += cnt;
                    if crcs {
                        p.crcs.extend_from_slice(&sl.crcs);
                    }
                }
                _ => parts.push(Part {
                    lblk: lo,
                    pba: sl.pba,
                    n: cnt,
                    crcs: if crcs { sl.crcs } else { Vec::new() },
                    comp: None,
                }),
            }
        }
        Ok(Some(parts))
    }

    /// Non-blocking readiness of the tree pages the omap keys `keys` of `oid` live on (the PG log head of the pgmeta object: a
    /// put there that finds its leaf evicted would spin the core on the load). Every key is probed so the loads overlap;
    /// `WouldBlock` = a page was missing (its read is submitted). An absent object is ready (the real op reports it).
    pub fn warm_omap(&mut self, cid: &CollT, oid: &Ghobject, keys: &[&[u8]]) -> Result<()> {
        let Some(id) = self.lookup(cid, oid)? else {
            return Ok(());
        };
        let mut blocked = false;
        if self.s.omap_lsm {
            // the run blocks of the keys: their reads go out together, the op parks once
            for k in keys {
                match self.lsm_get(id, k) {
                    Err(ObjError::WouldBlock) => blocked = true,
                    r => {
                        r?;
                    }
                }
            }
            return if blocked {
                Err(ObjError::WouldBlock)
            } else {
                Ok(())
            };
        }
        for k in keys {
            let mk = omap_key(id, k);
            let r = self.kget_with(&mk, |_| ());
            crate::vpool::give(mk);
            match r {
                Err(ObjError::WouldBlock) => blocked = true,
                r => r?,
            }
        }
        if blocked {
            Err(ObjError::WouldBlock)
        } else {
            Ok(())
        }
    }

    /// Non-blocking data prefetch for a client read of `[off, off+len)` (ADR 0043): submit the device reads of
    /// the committed blocks into the shard's prefetch table. `WouldBlock` = some are still in flight (retry after
    /// the wake). The tree path must be resident (`warm` first); anything unusual returns `Ok` (the real read
    /// then reads synchronously as before).
    pub fn warm_data(&mut self, cid: &CollT, oid: &Ghobject, off: u64, len: u64) -> Result<()> {
        let Some(id) = self.lookup(cid, oid)? else {
            return Ok(());
        };
        let size = self.obj_size(id);
        if off >= size || len == 0 {
            return Ok(());
        }
        let len = len.min(size - off);
        let bs = BLK as u64;
        let (a, b) = (off / bs, (off + len).div_ceil(bs));
        let Some(mut parts) = self.read_parts(id, a, b - a, true)? else {
            crate::dbg::PF_UNUSUAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        };
        // committed blocks of an object with an undurable write: the real read would spin in `wait_durable`; park,
        // the next durable advance wakes the gate
        if self.s.wlsn_pending(id) {
            crate::dbg::PF_WLSN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.s.wl_park();
            return Err(ObjError::WouldBlock);
        }
        // this read is already being served by a rolling read of the same runs: nothing to prefetch (probing every run of
        // a fragmented object again on each retry is quadratic in the runs)
        // (plain extents only: a compressed read is split into one rolling read per chunk, `rolling_covers` below)
        if parts.iter().all(|p| p.comp.is_none()) {
            let runs: Vec<(u64, u32, usize)> = parts
                .iter()
                .map(|p| (p.pba, p.n, (p.lblk - a) as usize))
                .collect();
            if self.s.rolling_resumes(&runs) {
                return Ok(());
            }
        }
        let mut blocked = false;
        let mut missing: Vec<(u64, u32)> = Vec::new();
        // every piece of the range sits in the data cache (no rolling read, no prefetch run, no compressed chunk)
        let mut all_cached = true;
        for p in &parts {
            if p.comp.is_some_and(|m| {
                self.s
                    .dcache
                    .get(p.pba, m.lcrc, m.raw_blks as usize * BLK)
                    .is_some()
            }) {
                all_cached = false;
                continue;
            }
            let mut o = 0u32;
            while o < p.n {
                let c = (p.n - o).min(self.s.max_xfer_blk as u32);
                if self.s.dc.touch(p.pba + o as u64, c) {
                    o += c;
                    continue;
                }
                all_cached = false;
                if self.s.rolling_covers(p.pba + o as u64, c) {
                    o += c;
                    continue;
                }
                match self.s.pf_state(p.pba + o as u64, c) {
                    // a waiting op's lease keeps the run until it reads it (no-op without a lease)
                    PfState::Ready => self.s.pf_hold(p.pba + o as u64, c),
                    PfState::InFlight => {
                        self.s.pf_hold(p.pba + o as u64, c);
                        blocked = true;
                    }
                    PfState::Absent => missing.push((p.pba + o as u64, c)),
                }
                o += c;
            }
        }
        // the op's missing runs are admitted together and in arrival order, or it waits for the wake; it never
        // falls back to a blocking read because younger ops hold the table (adr 0043 am. 2)
        if let Some(&(key, _)) = missing.first() {
            let blocks = missing.iter().map(|&(_, c)| c as u64).sum();
            match self.s.pf_admit(key, blocks, missing.len()) {
                PfAdmit::Yes => {
                    for &(pba, c) in &missing {
                        if self.s.pf_submit(pba, c, key) {
                            blocked = true;
                        } else if self.s.pf_has_inflight() {
                            // the device queue is full or the DMA budget has no buffer to spare: the rest is submitted
                            // after the next completion (a synchronous read here would stall the whole core for the
                            // duration of a 4M read)
                            blocked = true;
                            break;
                        }
                        // nothing in flight to wake us: this run is read synchronously by the real read (its buffer
                        // comes from the part of the DMA budget the read gate leaves)
                    }
                }
                PfAdmit::No => blocked = true,
                PfAdmit::Skip => {}
            }
        }
        if blocked {
            return Err(ObjError::WouldBlock);
        }
        // a read of one plain piece the data cache holds whole: leave what was resolved for the read that follows
        if all_cached
            && missing.is_empty()
            && parts.len() == 1
            && parts[0].comp.is_none()
            && self
                .objs
                .get(&id)
                .is_none_or(|w| w.runs.is_empty() && !w.no_ext() && w.on.flags & F_INLINE == 0)
        {
            let part = parts.pop().expect("one part");
            self.s.hot = Some(HotProbe {
                lsn: self.s.sh.next_lsn(),
                cid: *cid,
                oid: oid.clone(),
                off,
                len,
                id,
                size,
                part,
            });
        }
        Ok(())
    }

    /// `warm_data` for the source of a `clone_range` of `[off, off+len)` to the same offset (EC stash, adr 0021 am. 38):
    /// a range the clone will share needs no data, only its unaligned head / tail blocks (copied) are prefetched.
    pub fn warm_clone_src(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        off: u64,
        len: u64,
    ) -> Result<()> {
        let Some(id) = self.lookup(cid, oid)? else {
            return Ok(());
        };
        let bs = BLK as u64;
        let end = off.saturating_add(len);
        let (a, b) = (off.div_ceil(bs), end / bs);
        if a >= b || !self.range_shareable(id, a, b)? {
            return self.warm_data(cid, oid, off, len);
        }
        let mut r = Ok(());
        if a * bs > off {
            r = self.warm_data(cid, oid, off, a * bs - off);
        }
        if end > b * bs {
            match self.warm_data(cid, oid, b * bs, end - b * bs) {
                Err(ObjError::WouldBlock) => r = Err(ObjError::WouldBlock),
                Err(e) => return Err(e),
                Ok(()) => {}
            }
        }
        r
    }

    /// Committed content of blocks `[blk, blk+n)` of `id` into `out` (pre-zeroed). With `bad`, checksum
    /// mismatches are collected (logical block numbers) instead of failing.
    pub fn read_committed(
        &mut self,
        id: u64,
        blk: u64,
        n: u64,
        out: &mut [MaybeUninit<u8>],
        bad: Option<&mut Vec<u64>>,
    ) -> Result<()> {
        self.read_crc = None;
        if self.objs.get(&id).is_some_and(|w| w.no_ext()) {
            out.fill(MaybeUninit::new(0));
            return Ok(());
        }
        if self
            .objs
            .get(&id)
            .is_some_and(|w| w.on.flags & F_INLINE != 0)
        {
            // inline object: block 0 is the value of the `d` key (zero padded), everything else is a hole
            out.fill(MaybeUninit::new(0));
            if blk == 0 {
                self.kget_with(&inl_key_arr(id), |v| {
                    if let Some(v) = v {
                        for (o, b) in out.iter_mut().zip(v.iter().take(BLK)) {
                            *o = MaybeUninit::new(*b);
                        }
                    }
                })?;
            }
            return Ok(());
        }
        let parts = self.read_parts(id, blk, n, true)?;
        self.read_committed_parts(id, blk, n, parts, out, bad)
    }

    /// [`Stage::read_committed`] for the device pieces already resolved by [`Stage::read_parts`] (`None` = no extent: zeros) of
    /// a plain object (no inline value, extents present).
    fn read_committed_parts(
        &mut self,
        id: u64,
        blk: u64,
        n: u64,
        parts: Option<Vec<Part>>,
        out: &mut [MaybeUninit<u8>],
        mut bad: Option<&mut Vec<u64>>,
    ) -> Result<()> {
        let Some(parts) = parts else {
            out.fill(MaybeUninit::new(0));
            return Ok(());
        };
        self.s.wait_durable(self.clk, id)?;
        if parts.iter().any(|p| p.comp.is_some()) {
            return self.read_with_comp(&parts, blk, n, out, bad);
        }
        // device -> `out` in one pass (copy fused with the block crc), no intermediate buffers
        let runs: Vec<(u64, u32, usize)> = parts
            .iter()
            .map(|p| (p.pba, p.n, (p.lblk - blk) as usize))
            .collect();
        let got = self.s.read_runs_into(self.clk, &runs, out, bad.is_some())?;
        // holes read as zeros (the destination is not pre-zeroed: every byte is written exactly here or above)
        let mut pos = blk;
        for p in &parts {
            out[((pos - blk) as usize) * BLK..((p.lblk - blk) as usize) * BLK]
                .fill(MaybeUninit::new(0));
            pos = p.lblk + p.n as u64;
        }
        out[((pos - blk) as usize) * BLK..(n as usize) * BLK].fill(MaybeUninit::new(0));
        let mut gi = 0usize;
        let mut mismatch = false;
        for p in &parts {
            for i in 0..p.n as usize {
                let lb = p.lblk + i as u64;
                gi += 1;
                if got[gi - 1] != p.crcs[i] {
                    self.s.stats.crc_errors += 1;
                    mismatch = true;
                    match bad.as_deref_mut() {
                        Some(v) => v.push(lb),
                        None => {
                            return Err(ObjError::Eio(format!(
                                "checksum mismatch: onode {id} block {lb} at pba {}",
                                p.pba + i as u64
                            )));
                        }
                    }
                }
            }
        }
        // every block verified: the crc of the returned bytes follows from the block crcs alone (a hole block is
        // all zero: crc 0 under seed 0)
        if !mismatch {
            let hole = |k: u64| std::iter::repeat_n((0u32, 0u32), k as usize);
            let (mut r, mut pos, mut gi) = (!0u32, blk, 0usize);
            for p in &parts {
                r = crc::crc32c_blocks(r, hole(p.lblk - pos));
                let seeds = (0..p.n as u64).map(|i| blk_seed(p.pba + i));
                r = crc::crc32c_blocks(r, got[gi..gi + p.n as usize].iter().copied().zip(seeds));
                gi += p.n as usize;
                pos = p.lblk + p.n as u64;
            }
            r = crc::crc32c_blocks(r, hole(blk + n - pos));
            self.read_crc = Some(r);
        }
        Ok(())
    }

    /// `read_committed` for a range that touches compressed chunks: plain parts as usual, each chunk is read whole,
    /// verified against its block crcs, decompressed, checked against its logical crc and cut to the requested range.
    /// A failing chunk is a checksum mismatch (its first logical block is reported). Sets `read_crc` (no pass over the
    /// whole range, see [`comp_read_crc`]).
    fn read_with_comp(
        &mut self,
        parts: &[Part],
        blk: u64,
        n: u64,
        out: &mut [MaybeUninit<u8>],
        bad: Option<&mut Vec<u64>>,
    ) -> Result<()> {
        self.read_comp(parts, blk, n, CompDst::Flat(out), bad)
    }

    /// The reply of a read whose every part is a compressed chunk window (holes between them): the decoded chunks go out
    /// by reference, one piece per window, each with its crc32c (seed `!0`) known without a pass when the piece is a whole
    /// chunk. `[off, off+len)` is inside the `n` blocks from `b0`; head / tail cuts hash their (partial) piece.
    fn read_comp_pieces(
        &mut self,
        parts: &[Part],
        b0: u64,
        n: u64,
        off: u64,
        len: u64,
    ) -> Result<Vec<(Bytes, Option<u32>)>> {
        let mut pieces = Vec::with_capacity(parts.len() * 2 + 1);
        self.read_comp(parts, b0, n, CompDst::Pieces(&mut pieces), None)?;
        let (start, end) = (off - b0 * BLK as u64, off + len - b0 * BLK as u64);
        let mut pos = 0u64;
        pieces.retain_mut(|(b, c)| {
            let (lo, hi) = (pos, pos + b.len() as u64);
            pos = hi;
            if hi <= start || lo >= end {
                return false;
            }
            let (a, z) = (start.max(lo) - lo, end.min(hi) - lo);
            if (a, z) != (0, b.len() as u64) {
                *b = b.slice(a as usize..z as usize);
                *c = Some(crc::crc32c(!0, b));
            }
            true
        });
        Ok(pieces)
    }

    fn read_comp(
        &mut self,
        parts: &[Part],
        blk: u64,
        n: u64,
        mut dst: CompDst<'_>,
        mut bad: Option<&mut Vec<u64>>,
    ) -> Result<()> {
        let bad_len = bad.as_ref().map_or(0, |b| b.len());
        // A non-blocking caller (staged op) gets `WouldBlock` and is woken by the read completions; a blocking caller
        // reads each chunk through the synchronous device path, which ends on the completion or the device error:
        // no admission slot of another read is ever needed, so nothing waits on a timer.
        let result = self.read_comp_window(parts, blk, n, &mut dst, bad.as_deref_mut());
        if matches!(result, Err(ObjError::WouldBlock)) {
            if let Some(b) = bad {
                b.truncate(bad_len);
            }
            if let CompDst::Pieces(v) = &mut dst {
                v.clear();
            }
        }
        if !matches!(result, Err(ObjError::WouldBlock)) {
            let cache = result.is_ok();
            for p in parts.iter().filter(|p| p.comp.is_some()) {
                self.s.release_kept(&[(p.pba, p.n, 0)], cache);
            }
            let plain: Vec<_> = parts
                .iter()
                .filter(|p| p.comp.is_none())
                .map(|p| (p.pba, p.n, (p.lblk - blk) as usize))
                .collect();
            self.s.release_kept(&plain, cache);
        }
        result
    }

    fn read_comp_window(
        &mut self,
        parts: &[Part],
        blk: u64,
        n: u64,
        dst: &mut CompDst<'_>,
        mut bad: Option<&mut Vec<u64>>,
    ) -> Result<()> {
        let id_for_msg = parts.first().map_or(0, |p| p.lblk);
        // scrub / fsck (`bad` set) always verify the media
        let cached = bad.is_none() && !self.s.media;
        let mut got: Vec<u32> = Vec::new();
        if let CompDst::Flat(out) = dst {
            let mut pos = blk;
            for p in parts {
                let lo = blk.max(p.lblk);
                let span = p.comp.map_or(p.n as u64, |m| m.win as u64);
                let hi = (blk + n).min(p.lblk + span);
                out[(pos - blk) as usize * BLK..(lo - blk) as usize * BLK]
                    .fill(MaybeUninit::new(0));
                pos = pos.max(hi);
            }
            out[(pos - blk) as usize * BLK..].fill(MaybeUninit::new(0));
            let runs: Vec<(u64, u32, usize)> = parts
                .iter()
                .filter(|p| p.comp.is_none())
                .map(|p| (p.pba, p.n, (p.lblk - blk) as usize))
                .collect();
            if !runs.is_empty() {
                got = self.s.read_runs_kept(self.clk, &runs, out, !cached)?;
            }
        } else {
            debug_assert!(parts.iter().all(|p| p.comp.is_some()));
        }
        let mut gi = 0usize;
        let mut fail = |this: &mut Self, lb: u64, pba: u64| -> Result<()> {
            this.s.stats.crc_errors += 1;
            match bad.as_deref_mut() {
                Some(v) => {
                    v.push(lb);
                    Ok(())
                }
                None => Err(ObjError::Eio(format!(
                    "checksum mismatch: block {lb} at pba {pba} (object near block {id_for_msg})"
                ))),
            }
        };
        for p in parts.iter().filter(|p| p.comp.is_none()) {
            for i in 0..p.n as usize {
                gi += 1;
                if got[gi - 1] != p.crcs[i] {
                    fail(self, p.lblk + i as u64, p.pba + i as u64)?;
                }
            }
        }
        let mut waiting = 0;
        let mut pos = blk;
        for p in parts {
            let Some(m) = p.comp else { continue };
            let (lo, hi) = (blk.max(p.lblk), (blk + n).min(p.lblk + m.win as u64));
            // decoded bytes of the range: the record's first logical block is decoded block `skip`
            let (dlo, dhi) = (
                (m.skip as u64 + lo - p.lblk) as usize * BLK,
                (m.skip as u64 + hi - p.lblk) as usize * BLK,
            );
            let raw_len = m.raw_blks as usize * BLK;
            let retained = self
                .s
                .retained_decoded(p.pba, p.n, m.lcrc, raw_len, !cached);
            let chunk = if let Some(c) = retained {
                c
            } else if let Some(c) = cached
                .then(|| self.s.dcache.get(p.pba, m.lcrc, raw_len).cloned())
                .flatten()
            {
                c
            } else {
                // a ready prefetch entry is decoded in place; anything else is read into the physical scratch first
                let direct = if cached {
                    self.s.pf_with(p.pba, p.n, |phys, got, codec, stats| {
                        decode_chunk(codec, stats, m, phys, got == p.crcs)
                    })
                } else {
                    None
                };
                let dec = if let Some(d) = direct {
                    d
                } else {
                    let phys_len = p.n as usize * BLK;
                    let mut phys = std::mem::take(&mut self.s.pbuf);
                    phys.clear();
                    phys.reserve(phys_len);
                    let g = match self.s.read_runs_kept(
                        self.clk,
                        &[(p.pba, p.n, 0)],
                        &mut phys.spare_capacity_mut()[..phys_len],
                        !cached,
                    ) {
                        Ok(g) => g,
                        Err(ObjError::WouldBlock) => {
                            self.s.pbuf = phys;
                            waiting += 1;
                            // Four uncached chunks may await media at once. Ready chunks are decoded immediately;
                            // later retries reuse request-owned results instead of cycling the four-entry client cache.
                            if waiting == 4 {
                                return Err(ObjError::WouldBlock);
                            }
                            continue;
                        }
                        Err(e) => {
                            self.s.pbuf = phys;
                            return Err(e);
                        }
                    };
                    // SAFETY: the successful run read initialized every physical byte.
                    unsafe { phys.set_len(phys_len) };
                    let d =
                        decode_chunk(&mut self.s.codec, &mut self.s.stats, m, &phys, g == p.crcs);
                    self.s.pbuf = phys;
                    d
                };
                let ok = dec.is_some();
                let dec = dec.unwrap_or_default();
                if !ok {
                    if let CompDst::Flat(out) = dst {
                        // scrub's failed logical chunk stays initialized
                        out[(lo - blk) as usize * BLK..(hi - blk) as usize * BLK]
                            .fill(MaybeUninit::new(0));
                    }
                    fail(self, p.lblk, p.pba)?;
                    continue;
                }
                let c = Bytes::from(dec);
                self.s.keep_decoded(p.pba, p.n, m.lcrc, c.clone(), !cached);
                c
            };
            match dst {
                CompDst::Flat(out) => {
                    let d = &mut out[(lo - blk) as usize * BLK..(hi - blk) as usize * BLK];
                    let src = &chunk[dlo..dhi];
                    // SAFETY: equal lengths; `MaybeUninit<u8>` and `u8` share layout.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            src.as_ptr(),
                            d.as_mut_ptr().cast(),
                            src.len(),
                        )
                    };
                }
                CompDst::Pieces(v) => {
                    if lo > pos {
                        let z = (lo - pos) as usize * BLK;
                        v.push((Bytes::from(vec![0u8; z]), Some(crc::crc32c_zeros(!0, z))));
                    }
                    pos = hi;
                    let crc = if dlo == 0 && dhi == raw_len {
                        crc::crc32c_combine(!0, m.lcrc, raw_len as u64)
                    } else {
                        crc::crc32c(!0, &chunk[dlo..dhi])
                    };
                    v.push((chunk.slice(dlo..dhi), Some(crc)));
                }
            }
        }
        if waiting != 0 {
            return Err(ObjError::WouldBlock);
        }
        match dst {
            CompDst::Flat(out) if bad.is_none() => {
                self.read_crc = Some(comp_read_crc(parts, blk, n, out, &got));
            }
            CompDst::Flat(_) => {}
            CompDst::Pieces(v) => {
                if pos < blk + n {
                    let z = (blk + n - pos) as usize * BLK;
                    v.push((Bytes::from(vec![0u8; z]), Some(crc::crc32c_zeros(!0, z))));
                }
            }
        }
        Ok(())
    }

    /// Effective content (committed + this txn's overlay) of blocks `[blk, blk+n)`.
    pub fn eff_read(&mut self, id: u64, blk: u64, n: u64) -> Result<Vec<u8>> {
        let len = n as usize * BLK;
        if self.planning && self.comp.is_none() {
            // Raw staging decisions depend on ranges/lengths, not payload contents. The plan's
            // values are never applied; compression still reads real bytes to determine exact sizes.
            self.read_crc = None;
            return Ok(vec![0; len]);
        }
        let mut out: Vec<u8> = Vec::with_capacity(len);
        self.read_committed(id, blk, n, &mut out.spare_capacity_mut()[..len], None)?;
        // SAFETY: read_committed returned Ok, so it wrote all `len` bytes (device data or zeros).
        unsafe { out.set_len(len) };
        if let Some(w) = self.objs.get(&id) {
            if !w.runs.is_empty() {
                self.read_crc = None;
            }
            w.runs.overlay(blk, n, &mut out);
        }
        Ok(out)
    }

    fn eff_present(&mut self, id: u64, blk: u64) -> Result<bool> {
        if let Some(w) = self.objs.get(&id) {
            match w.runs.cover(blk) {
                Some(Some(_)) => return Ok(true),
                Some(None) => return Ok(false),
                None => {}
            }
            if w.no_ext() {
                return Ok(false);
            }
            if w.on.flags & F_INLINE != 0 {
                return Ok(blk == 0);
            }
        }
        Ok(!self.extents_in(id, blk, blk + 1)?.is_empty())
    }

    /// Block ranges inside `[a, b)` that hold data (committed and overlay, holes removed), ascending, merged.
    fn eff_ranges(&mut self, id: u64, a: u64, b: u64) -> Result<Vec<(u64, u64)>> {
        let mut r: Vec<(u64, u64)> = Vec::new();
        if self
            .objs
            .get(&id)
            .is_some_and(|w| !w.created() && w.on.flags & F_INLINE != 0)
        {
            r.push((0, 1));
        } else if !self.objs.get(&id).is_some_and(|w| w.no_ext()) {
            for (s, e) in self.extents_in(id, a, b)? {
                r.push((s, e.span() as u64));
            }
        }
        let mut out = effective_ranges(r, self.objs.get(&id).map(|w| &w.runs));
        out.retain_mut(|(s, n)| {
            let (lo, hi) = ((*s).max(a), (*s + *n).min(b));
            (*s, *n) = (lo, hi.saturating_sub(lo));
            lo < hi
        });
        Ok(out)
    }

    // ------------------------------------------------------------------ data ops

    /// Add `phys` / `orig` bytes to the onode's compression counters (negative = a compressed chunk went away).
    fn comp_acct(&mut self, id: u64, phys: i64, orig: i64) {
        let w = self.w(id);
        w.on.comp = (w.on.comp as i64 + phys).max(0) as u64;
        w.on.comp_orig = (w.on.comp_orig as i64 + orig).max(0) as u64;
        w.dirty_on = true;
    }

    /// Before a mutation of blocks `[a, b)` (`b = INF`: to the end) cuts a compressed chunk at its edges: `punch` keeps the
    /// rest of the chunk as windows, nothing to read, unless the chunk's blocks are then worth less than they occupy
    /// (`pull_chunk_rest`). Free for objects without `F_COMP`.
    fn pull_in(&mut self, id: u64, a: u64, b: u64) -> Result<()> {
        if self
            .objs
            .get(&id)
            .is_none_or(|w| w.no_ext() || w.on.flags & F_COMP == 0)
        {
            return Ok(());
        }
        self.pull_edge(id, a, a, b)?;
        if b != INF && b - 1 != a {
            self.pull_edge(id, b - 1, a, b)?;
        }
        Ok(())
    }

    fn pull_edge(&mut self, id: u64, blk: u64, a: u64, b: u64) -> Result<()> {
        self.extents_set(id, blk, blk + 1)?;
        let mut hit = None;
        for ei in &self.sc.exts {
            let raw = &self.sc.ext_raw[ei.off as usize..(ei.off + ei.len) as usize];
            let e = ExtRaw::new(raw).expect("validated by extents_set");
            let span = e.span() as u64;
            if let Some(m) = e.comp()
                && ei.lblk <= blk
                && blk < ei.lblk + span
            {
                hit = Some((ei.lblk, span, m, e.pba(), e.len(), e.shared()));
            }
        }
        let Some((s, span, m, pba, len, shared)) = hit else {
            return Ok(());
        };
        if (a <= s && s + span <= b) || self.w(id).runs.cover(s).is_some() {
            return Ok(()); // replaced whole, or an earlier op of this txn already pulled the chunk's windows in
        }
        self.pull_chunk_rest(id, s - m.skip as u64, m, (pba, len, shared), a, b)
    }

    /// Space rule of chunk windows (adr 0059 am. 4; BlueStore's compressed-blob garbage collection, own words): when
    /// the mutation of `[a, b)` leaves fewer logical blocks in the windows of the chunk `(pba, len physical blocks,
    /// shared flag)` (first logical block `cs`) than the chunk occupies, those blocks are brought into the overlay (one
    /// read and decompress) and the chunk is released at flush (each window's punch drops one owner): the live blocks then
    /// cost at most what they did, so a chunk and its overwrites never occupy more blocks than the chunk's logical span.
    /// Not when another object (a clone) shares the chunk too, nor when an earlier op of this txn has overlay inside a
    /// window (its holes / data stay as they are).
    fn pull_chunk_rest(
        &mut self,
        id: u64,
        cs: u64,
        m: CompMeta,
        (pba, len, shared): (u64, u32, bool),
        a: u64,
        b: u64,
    ) -> Result<()> {
        self.extents_set(id, cs, cs + m.raw_blks as u64)?;
        let mut wins: Vec<(u64, u64)> = Vec::new();
        for ei in &self.sc.exts {
            let raw = &self.sc.ext_raw[ei.off as usize..(ei.off + ei.len) as usize];
            let e = ExtRaw::new(raw).expect("validated by extents_set");
            if e.comp().is_some() && e.pba() == pba {
                wins.push((ei.lblk, e.span() as u64));
            }
        }
        let live: u64 = wins
            .iter()
            .map(|&(l, n)| n - (l + n).min(b).saturating_sub(l.max(a)))
            .sum();
        if live >= len as u64 {
            return Ok(());
        }
        let w = self.w(id);
        if wins.iter().any(|&(l, n)| {
            w.runs
                .runs
                .range(..l + n)
                .next_back()
                .is_some_and(|(s, r)| s + r.n > l)
        }) {
            return Ok(());
        }
        if shared && self.ref_owners(pba)? as usize > wins.len() {
            return Ok(());
        }
        for &(l, n) in &wins {
            let d = self.eff_read(id, l, n)?;
            self.w(id).runs.set(l, n, Some(d));
        }
        self.grows = true;
        if !self.planning {
            self.s.stats.comp_gc += live * BLK as u64;
        }
        Ok(())
    }

    /// Owner count of block `pba` (refcount record, absent = 1; adr 0021 am. 32).
    fn ref_owners(&mut self, pba: u64) -> Result<u32> {
        let from = ref_key(pba.saturating_sub(MAX_RUN as u64 - 1));
        let kv = self.kscan(&from, &ref_key(pba + 1), usize::MAX)?;
        for (k, v) in kv {
            let s = u64::from_be_bytes(k[1..9].try_into().unwrap());
            let (len, c) =
                ref_decode(&v).ok_or_else(|| ObjError::Eio("bad refcount record".into()))?;
            if s <= pba && pba < s + len as u64 {
                return Ok(c);
            }
        }
        Ok(1)
    }

    /// Write `data` at `off` as RMW boundary blocks plus an aligned middle: the unaligned head and tail go through private
    /// blocks (`eff_read` + patch), `middle(self, first block, blocks, from, len)` stages the aligned middle
    /// `data[from..from + len]` (the caller picks how it keeps the bytes). Sets the size; `pull_in` is the caller's.
    fn write_edges(
        &mut self,
        id: u64,
        off: u64,
        data: &[u8],
        middle: impl FnOnce(&mut Self, u64, u64, usize, usize),
    ) -> Result<()> {
        let bs = BLK as u64;
        let end = off + data.len() as u64;
        let mut used = 0;
        let head = (off % bs) as usize;
        if head != 0 {
            let mut block = self.eff_read(id, off / bs, 1)?;
            used = data.len().min(BLK - head);
            block[head..head + used].copy_from_slice(&data[..used]);
            self.w(id).runs.set(off / bs, 1, Some(block));
        }
        let mid = (data.len() - used) / BLK * BLK;
        if mid != 0 {
            middle(
                self,
                (off + used as u64) / bs,
                (mid / BLK) as u64,
                used,
                mid,
            );
            used += mid;
        }
        if used < data.len() {
            let blk = (off + used as u64) / bs;
            let mut block = self.eff_read(id, blk, 1)?;
            block[..data.len() - used].copy_from_slice(&data[used..]);
            self.w(id).runs.set(blk, 1, Some(block));
        }
        let size = self.obj_size(id).max(end);
        self.set_size(id, size)
    }

    /// Own only RMW boundary blocks; borrow the aligned middle until the DMA copy.
    fn write_data_b(&mut self, id: u64, off: u64, data: &'a [u8]) -> Result<()> {
        let bs = BLK as u64;
        if data.is_empty() {
            return Ok(());
        }
        let end = off
            .checked_add(data.len() as u64)
            .ok_or(ObjError::TooLarge)?;
        if blocks_for(end) > MAX_BLOCKS {
            return Err(ObjError::TooLarge);
        }
        self.pull_in(id, off / bs, end.div_ceil(bs))?;
        self.write_edges(id, off, data, |s, blk, n, from, len| {
            s.w(id).runs.set_cow(
                blk,
                n,
                Some(std::borrow::Cow::Borrowed(&data[from..from + len])),
            );
        })
    }

    fn write_data(&mut self, id: u64, off: u64, data: Vec<u8>) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let end = off
            .checked_add(data.len() as u64)
            .ok_or(ObjError::TooLarge)?;
        if blocks_for(end) > MAX_BLOCKS {
            return Err(ObjError::TooLarge);
        }
        let bs = BLK as u64;
        let (b0, b1) = (off / bs, (end - 1) / bs);
        let n = b1 - b0 + 1;
        self.pull_in(id, b0, b1 + 1)?;
        if off.is_multiple_of(bs) && end.is_multiple_of(bs) {
            self.w(id).runs.set(b0, n, Some(data));
            let size = self.obj_size(id).max(end);
            return self.set_size(id, size);
        }
        // The aligned middle retains the source allocation even when the destination is
        // unaligned; only its two RMW boundary blocks require private storage.
        let data = bytes::Bytes::from(data);
        self.write_edges(id, off, &data, |s, blk, n, from, len| {
            s.w(id).runs.set_data(
                blk,
                n,
                Some(super::dirty::Data::Shared(data.slice(from..from + len))),
            );
        })
    }

    fn zero_partial(&mut self, id: u64, blk: u64, lo: usize, hi: usize) -> Result<()> {
        if !self.eff_present(id, blk)? {
            return Ok(());
        }
        let mut b = self.eff_read(id, blk, 1)?;
        b[lo..hi].fill(0);
        if b.iter().all(|&byte| byte == 0) {
            // Reclaim an emptied boundary block too; a clone keeps its original
            // through the same reference accounting as an aligned hole.
            self.w(id).runs.hole(blk, 1);
        } else {
            // A rewritten block: no pure shrink (the old block may stay shared).
            self.grows = true;
            self.w(id).runs.set(blk, 1, Some(b));
        }
        Ok(())
    }

    fn zero_data(&mut self, id: u64, off: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let end = off.checked_add(len).ok_or(ObjError::TooLarge)?;
        if blocks_for(end) > MAX_BLOCKS {
            return Err(ObjError::TooLarge);
        }
        self.shrink = true;
        let bs = BLK as u64;
        let (hb, tb) = (off / bs, end / bs);
        self.pull_in(id, hb, end.div_ceil(bs))?;
        let (ho, te) = ((off % bs) as usize, (end % bs) as usize);
        if hb == tb {
            self.zero_partial(id, hb, ho, te)?;
        } else {
            if ho != 0 {
                self.zero_partial(id, hb, ho, BLK)?;
            }
            if te != 0 {
                self.zero_partial(id, tb, 0, te)?;
            }
        }
        let (fs, fe) = (off.div_ceil(bs), tb);
        if fs < fe {
            self.w(id).runs.hole(fs, fe - fs);
        }
        let size = self.obj_size(id).max(end);
        self.set_size(id, size)
    }

    fn truncate_data(&mut self, id: u64, size: u64) -> Result<()> {
        let old = self.obj_size(id);
        if size >= old {
            return self.set_size(id, size);
        }
        self.shrink = true;
        let bs = BLK as u64;
        self.pull_in(id, size / bs, INF)?;
        self.w(id).runs.hole(size.div_ceil(bs), INF);
        if !size.is_multiple_of(bs) {
            self.zero_partial(id, size / bs, (size % bs) as usize, BLK)?;
        }
        self.set_size(id, size)
    }

    // ------------------------------------------------------------------ values (xattr / omap / header)

    /// Entry size a value stored under a key of `klen` bytes may use: the soft limit (unchanged for every key that fitted
    /// before am. 10), or key + `KEY_VAL_ROOM` for long keys; never above the tree limit (`max_key` guarantees it).
    fn entry_budget(&self, klen: usize) -> usize {
        self.soft_entry.max(4 + klen + crate::tree::KEY_VAL_ROOM)
    }

    fn key_ok(&self, slot: Slot, k: &[u8]) -> Result<()> {
        // lengths of `main_key` (tag + id + sub [+ key]) and of the fragment key (+ type, key, u32 index)
        let main = if slot == Slot::Hdr { 10 } else { 10 + k.len() };
        if main > self.max_key || 15 + k.len() > self.max_key {
            return Err(ObjError::NameTooLong);
        }
        Ok(())
    }

    /// Release what the current record of `k` holds outside itself before it is replaced or removed: its fragments, or the
    /// data blocks of a `V_EXT` value (adr 0021 am. 46; a `V_PEND` value of this txn owns nothing yet). Callers check the
    /// slot's frag / ext flag first.
    fn drop_frags(&mut self, id: u64, slot: Slot, k: &[u8]) -> Result<()> {
        let mk = slot.main_key(id, k);
        let r = self.kget(&mk);
        crate::vpool::give(mk);
        let Some(v) = r? else {
            return Ok(());
        };
        if v.first() == Some(&V_FRAG) && v.len() == 9 {
            let n = denc::le::rd_u32(&v, 5);
            for i in 0..n {
                self.kdel(frag_key(id, slot.frag_ty(), k, i));
            }
        } else if let Some((_, e)) = vext(&v) {
            self.free_ext(e.pba(), e.len(), false)?;
        }
        Ok(())
    }

    /// Free the data blocks of every `V_EXT` record in `[a, b)` (removal of a whole range, adr 0021 am. 46). Records replaced
    /// or removed earlier in this txn were released then (the overlay hides them).
    fn free_ext_vals(&mut self, a: Vec<u8>, b: Vec<u8>) -> Result<()> {
        let mut runs = Vec::new();
        let mut from = a;
        loop {
            let kv = self.kscan(&from, &b, 2048)?;
            for (_, v) in &kv {
                if let Some((_, e)) = vext(v) {
                    runs.push((e.pba(), e.len()));
                }
            }
            match kv.last() {
                Some((k, _)) if kv.len() == 2048 => {
                    from = k.clone();
                    from.push(0);
                }
                _ => break,
            }
        }
        for (pba, n) in runs {
            self.free_ext(pba, n, false)?;
        }
        Ok(())
    }

    fn put_val(&mut self, id: u64, slot: Slot, k: &[u8], val: &[u8]) -> Result<()> {
        self.key_ok(slot, k)?;
        let mk = slot.main_key(id, k);
        if slot == Slot::Omap {
            self.demote(&mk)?;
        }
        let min = self.s.val_ext_min;
        if self.w(id).on.flags & (slot.frag_flag() | slot.ext_flag()) != 0 {
            self.drop_frags(id, slot, k)?;
        }
        // user omap values only: PG logs / pgmeta objects are hot, short-lived and gain nothing
        if slot == Slot::Omap
            && !self.w(id).pgmeta
            && let Some(rec) = self.try_comp(slot, val, mk.len())?
        {
            self.kput(mk, rec);
        } else if min > 0 && val.len() >= min && val.len() <= V_EXT_MAX {
            // data blocks (adr 0021 am. 46): allocated and staged at finish for the values still referenced then
            let mut v = Vec::with_capacity(9);
            v.push(V_PEND);
            v.extend_from_slice(&(val.len() as u32).to_le_bytes());
            v.extend_from_slice(&(self.pending_ext.len() as u32).to_le_bytes());
            self.pending_ext.push((mk.clone(), id, slot, val.to_vec()));
            self.kput(mk, v);
            self.set_flag(id, slot.ext_flag());
        } else {
            self.put_val_tree(id, slot, k, mk, val);
        }
        match slot {
            Slot::Omap => self.set_flag(id, F_OMAP),
            Slot::Hdr => self.set_flag(id, F_HDR),
            Slot::Attr => {}
        }
        Ok(())
    }

    /// Inline zstd form of an omap / header value (adr 0021 am. 58, 59): `[V_CINL][class][len][zstd block]` when the store has the
    /// feature, the value is big enough and the block saves at least 1/8 (and >= 16 B) and fits one tree entry. A class without a
    /// dictionary yet only collects samples (its values stay plain). The attempts are sampled per value class (`dict_class`,
    /// [`super::onode::VcAdapt`]).
    fn try_comp(&mut self, slot: Slot, val: &[u8], klen: usize) -> Result<Option<Vec<u8>>> {
        let min = self.s.val_comp_min;
        // values of the data-block size class (val_ext_min, default 2 KiB) stay out of the tree already: compressing them costs
        // ~1-2 us per value for no leaf space (measured: omap 4K cell -9 %), so only tree-resident sizes are tried
        let big = self.s.val_ext_min;
        if min == 0
            || val.len() < min
            || val.len() > V_EXT_MAX
            || (big > 0 && val.len() >= big)
            || slot != Slot::Omap
        {
            return Ok(None);
        }
        let cls = dict_class(val);
        if !self.s.vc.try_now(cls) {
            return Ok(None);
        }
        // the value's class dictionary, else the shared one; a class without its own dictionary keeps collecting samples
        let (id, zd) = match self.dict_for(cls)? {
            Some(z) => (cls, z),
            None => {
                let shared = self.dict_for(SHARED_CLASS)?;
                self.dict_sample(cls, val);
                match shared {
                    Some(z) => (SHARED_CLASS, z),
                    None => {
                        self.dict_sample(SHARED_CLASS, val);
                        return Ok(None);
                    }
                }
            }
        };
        let mut cv = std::mem::take(&mut self.sc.cv);
        let n = vcomp_pack(val, &zd, id as u8, &mut cv);
        let inline = self.entry_budget(klen + 1) - 4 - klen - 1;
        // a record must save 1/8 (and >= 16 B): a value too short to hold that much saving stays plain
        let save = (val.len() / 8).max(16);
        let ok = n != usize::MAX && n + save <= val.len() && n <= inline + 1;
        let rec = ok.then(|| cv[..n].to_vec());
        self.sc.cv = cv;
        if ok {
            self.s.vc.hit(cls);
            self.s.stats.val_comp += 1;
            self.s.stats.val_comp_saved += (val.len() + 1 - n) as u64;
        } else {
            self.s.vc.miss(cls);
        }
        Ok(rec)
    }

    /// The dictionary of class `cls` (adr 0021 am. 58, 59): the applied one, one found in the tree (cached when it is the applied
    /// one), or the one this shard trained that the tree does not hold yet (staged as the class's `Z` put in this txn, the table
    /// is only filled when that put is applied). `None` = the class has none yet.
    fn dict_for(&mut self, cls: usize) -> Result<Option<Arc<ZDict>>> {
        let tab = self.s.sh.state().dicts.clone();
        if let Some(d) = tab.slots[cls].get() {
            return Ok(Some(d.clone()));
        }
        if self.s.vc_absent >> cls & 1 == 0 {
            if let Some(t) = self.kget(&dict_key(cls))? {
                let d = tab.slots[cls].get_or_init(|| Arc::new(ZDict::new(t)));
                return Ok(Some(d.clone()));
            }
            // only this shard installs dictionaries (and only through a staged `Z` put the table then shows)
            self.s.vc_absent |= 1 << cls;
        }
        let Some(d) = self.s.vc_trained[cls].clone() else {
            return Ok(None);
        };
        if self.pending_dicts >> cls & 1 == 0 {
            self.kput(dict_key(cls).to_vec(), d.bytes().to_vec());
            self.pending_dicts |= 1 << cls;
            self.s.stats.dict_installs += 1;
        }
        Ok(Some(d))
    }

    /// Collect `val` as a training sample of its class; the `DICT_SAMPLES`-th sample trains the class dictionary (a few ms, once per
    /// class and shard), which `dict_for` stages from the next value on. A dry run (`plan`) neither collects nor trains: it sees the
    /// class without dictionary, i.e. plans the plain value, which is never smaller than the real record.
    fn dict_sample(&mut self, cls: usize, val: &[u8]) {
        if self.planning {
            return;
        }
        let want = self.s.val_dict_samples;
        let samples = &mut self.s.vc_samples[cls];
        samples.push(val.to_vec());
        if samples.len() < want {
            return;
        }
        match ZDict::train(samples) {
            Some(d) => self.s.vc_trained[cls] = Some(Arc::new(d)),
            None => self.s.vc.miss(cls),
        }
        self.s.vc_samples[cls] = Vec::new();
    }

    /// The dictionary a `V_CINL` record was coded with (tree lookup when the table lacks it).
    fn dict_of(&mut self, raw: &[u8]) -> Result<Arc<ZDict>> {
        let c = vcomp_dict(raw)
            .ok_or_else(|| ObjError::Eio("compressed value: record too short".into()))?
            as usize;
        if c >= DICT_CLASSES {
            return Err(ObjError::Eio(format!("compressed value: bad class {c}")));
        }
        let tab = self.s.sh.state().dicts.clone();
        if let Some(d) = tab.slots[c].get() {
            return Ok(d.clone());
        }
        let t = self
            .kget(&dict_key(c))?
            .ok_or_else(|| ObjError::Eio(format!("compressed value: dictionary {c} missing")))?;
        Ok(tab.slots[c].get_or_init(|| Arc::new(ZDict::new(t))).clone())
    }

    /// The tree forms of a value: inline record, or fragment entries + marker.
    /// Largest value stored inline (one tree entry) under a main key of `mklen` bytes.
    fn inline_room(&self, mklen: usize) -> usize {
        self.entry_budget(mklen + 1) - 4 - mklen - 1
    }

    fn put_val_tree(&mut self, id: u64, slot: Slot, k: &[u8], mk: Vec<u8>, val: &[u8]) {
        let inline = self.inline_room(mk.len());
        if val.len() <= inline {
            let mut v = crate::vpool::take(val.len() + 1);
            v.push(0);
            v.extend_from_slice(val);
            self.kput(mk, v);
        } else {
            let fk = frag_key(id, slot.frag_ty(), k, 0).len();
            let chunk = self.entry_budget(fk) - 4 - fk;
            let n = val.len().div_ceil(chunk) as u32;
            for (i, c) in val.chunks(chunk).enumerate() {
                self.kput(frag_key(id, slot.frag_ty(), k, i as u32), c.to_vec());
            }
            let mut m = vec![V_FRAG];
            m.extend_from_slice(&(val.len() as u32).to_le_bytes());
            m.extend_from_slice(&n.to_le_bytes());
            self.kput(mk, m);
            self.set_flag(id, slot.frag_flag());
        }
    }

    /// Remove key `k` of `slot` (its fragments or data blocks go with it).
    fn rm_val(&mut self, id: u64, slot: Slot, k: &[u8]) -> Result<()> {
        let mk = slot.main_key(id, k);
        if slot == Slot::Omap {
            self.demote(&mk)?;
        }
        if self.w(id).on.flags & (slot.frag_flag() | slot.ext_flag()) != 0 {
            self.drop_frags(id, slot, k)?;
        }
        self.kdel(mk);
        Ok(())
    }

    /// User keys of the omap entries in `[a, b)` (committed + this txn's overlay), scanned in bounded chunks.
    fn omap_keys_in(&mut self, a: Vec<u8>, b: Vec<u8>) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut from = a;
        loop {
            let kv = self.kscan(&from, &b, 2048)?;
            out.extend(kv.iter().map(|(k, _)| k[10..].to_vec()));
            match kv.last() {
                Some((k, _)) if kv.len() == 2048 => {
                    from = k.clone();
                    from.push(0);
                }
                _ => return Ok(out),
            }
        }
    }

    /// Omap removal batch of `id` (`TOp::OmapRmKeys`, a set of keys). An object without values outside their records
    /// gets the batch as one sorted list (adr 0476 am. 5): its keys ascending, each once. A batch that may be a run
    /// ([`Stage::rm_run_ok`]) is staged as one run of removals (adr 0647-omap-blind-removals D1: no tree access at commit,
    /// the merge removes the keys). Otherwise a key this txn has not touched is removed blind (`Op::Del`, no lookup), a
    /// touched one through the txn's view ([`Stage::rm_val`]); when the txn has not touched the object's omap, one check
    /// of the overlay covers every key. Objects with fragments or data-block values: key by key (each removal releases
    /// them).
    fn rm_keys<K: AsRef<[u8]>>(&mut self, id: u64, keys: &[K]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        if self.w(id).on.flags & (F_OFRAG | F_OEXT) != 0 {
            for k in keys {
                self.rm_val(id, Slot::Omap, k.as_ref())?;
            }
            return Ok(());
        }
        // a client batch is a sorted set on the wire: already ascending
        let key = |i: usize| keys[i].as_ref();
        let order: Option<Vec<usize>> = (!keys.windows(2).all(|w| w[0].as_ref() < w[1].as_ref()))
            .then(|| {
                let mut o: Vec<usize> = (0..keys.len()).collect();
                o.sort_unstable_by(|&i, &j| key(i).cmp(key(j)));
                o.dedup_by(|i, j| key(*i) == key(*j));
                o
            });
        if self.rm_run_ok(id, keys, order.as_deref())? {
            self.stage_rm_run(id, keys, order.as_deref());
            return Ok(());
        }
        let (a, b) = id_range(T_OMAP, id);
        let clean = !self.sruns.iter().any(|(rid, _)| *rid == id) && self.overlay_clear(&a, &b);
        let (mut bk, mut mk) = (
            std::mem::take(&mut self.sc.obatch),
            std::mem::take(&mut self.sc.mk),
        );
        bk.clear();
        let mut r = Ok(());
        for j in 0..order.as_ref().map_or(keys.len(), Vec::len) {
            let k = key(order.as_ref().map_or(j, |o| o[j]));
            Slot::Omap.main_key_into(id, k, &mut mk);
            if !clean {
                if let Err(e) = self.demote(&mk) {
                    r = Err(e);
                    break;
                }
                if self.touched(&mk) {
                    if let Err(e) = self.rm_val(id, Slot::Omap, k) {
                        r = Err(e);
                        break;
                    }
                    continue;
                }
            }
            bk.push(&mk);
        }
        if r.is_ok() && !bk.is_empty() {
            self.sc.odel.merge(&bk);
        }
        (self.sc.obatch, self.sc.mk) = (bk, mk);
        r
    }

    /// Has this txn put, removed or range-removed key `k`? Then its own view decides, not the committed state.
    fn touched(&self, k: &[u8]) -> bool {
        self.map.contains_key(k) || self.covered(k) || self.sc.odel.contains(k)
    }

    /// Decode a stored value (inline or fragment marker).
    fn decode_val(&mut self, id: u64, slot: Slot, k: &[u8], raw: &[u8]) -> Result<Vec<u8>> {
        match raw.first() {
            Some(&V_INLINE) => Ok(raw[1..].to_vec()),
            Some(&V_CINL) => {
                let zd = self.dict_of(raw)?;
                vcomp_unpack(raw, &zd)
                    .ok_or_else(|| ObjError::Eio(format!("onode {id}: bad compressed value")))
            }
            Some(&V_EXT) => {
                let (len, e) = vext(raw)
                    .ok_or_else(|| ObjError::Eio(format!("onode {id}: bad value extent")))?;
                let crcs: Vec<u32> = (0..e.len()).map(|i| e.crc(i)).collect();
                self.read_ext_val(id, len, e.pba(), &crcs)
            }
            Some(&V_PEND) if raw.len() == 9 => {
                let len = denc::le::rd_u32(raw, 1) as usize;
                let i = denc::le::rd_u32(raw, 5) as usize;
                match self.pending_ext.get(i) {
                    Some(p) if p.3.len() == len => Ok(p.3.clone()),
                    _ => Err(ObjError::Eio(format!(
                        "onode {id}: bad pending value record"
                    ))),
                }
            }
            Some(&V_FRAG) if raw.len() == 9 => {
                let total = denc::le::rd_u32(raw, 1) as usize;
                let n = denc::le::rd_u32(raw, 5);
                let mut out = Vec::with_capacity(total);
                for i in 0..n {
                    let f = self
                        .kget(&frag_key(id, slot.frag_ty(), k, i))?
                        .ok_or_else(|| {
                            ObjError::Eio(format!("onode {id}: fragment {i} missing"))
                        })?;
                    out.extend_from_slice(&f);
                }
                if out.len() != total {
                    return Err(ObjError::Eio(format!(
                        "onode {id}: fragment length mismatch"
                    )));
                }
                Ok(out)
            }
            _ => Err(ObjError::Eio(format!("onode {id}: bad value record"))),
        }
    }

    /// A value in data blocks (adr 0021 am. 46): waits until the object's data writes are durable (the value may be this
    /// object's unacked write), reads the run and checks every block crc.
    fn read_ext_val(&mut self, id: u64, len: usize, pba: u64, crcs: &[u32]) -> Result<Vec<u8>> {
        self.s.wait_durable(self.clk, id)?;
        let n = crcs.len();
        let mut out: Vec<u8> = Vec::with_capacity(n * BLK);
        let dst = &mut out.spare_capacity_mut()[..n * BLK];
        let got = self
            .s
            .read_runs_into(self.clk, &[(pba, n as u32, 0)], dst, false)?;
        // SAFETY: the run covers all n blocks and the read returned Ok.
        unsafe { out.set_len(n * BLK) };
        if got != crcs {
            return Err(ObjError::Eio(format!(
                "onode {id}: value blocks at {pba} fail their checksum"
            )));
        }
        out.truncate(len);
        Ok(out)
    }

    pub fn get_val(&mut self, id: u64, slot: Slot, k: &[u8]) -> Result<Option<Vec<u8>>> {
        if slot == Slot::Omap && self.s.omap_lsm {
            return self.lsm_get(id, k);
        }
        let mut mk = std::mem::take(&mut self.sc.mk);
        slot.main_key_into(id, k, &mut mk);
        let r = self.get_val_at(id, slot, k, &mk);
        self.sc.mk = mk;
        r
    }

    /// Values of `keys` of `id` (present keys only, in the given order). Omap on an LSM store reads the batch in one
    /// engine pass; every other case is one lookup per key.
    ///
    /// Non-blocking (the executor's reads): a key whose page is cold queues its load and the lookup goes on with the
    /// next key; the call refuses (`WouldBlock`) at the end, so one pass submits the loads of every cold key of the
    /// batch and the executor repeats the op once they are in (one device round trip per pass instead of one per cold
    /// key). A pass stops at the txn page budget of the shard (the pages one
    /// op may pull in at once), so the loads of one pass fit the cache.
    pub fn get_vals(
        &mut self,
        id: u64,
        slot: Slot,
        keys: &[&[u8]],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if slot == Slot::Omap && self.s.omap_lsm {
            let keys: Vec<Bytes> = keys.iter().map(|k| Bytes::copy_from_slice(k)).collect();
            loop {
                match self.engine_by_keys(id, &keys) {
                    Err(StoreError::Miss) => self.s.omap_miss_wait(self.clk)?,
                    r => {
                        return Ok(r?
                            .into_iter()
                            .map(|(k, v)| (k.to_vec(), v.to_vec()))
                            .collect());
                    }
                }
            }
        }
        let mut out = Vec::with_capacity(keys.len());
        let mut cold = 0usize;
        for k in keys {
            match self.get_val(id, slot, k) {
                Ok(Some(v)) if cold == 0 => out.push((k.to_vec(), v)),
                Ok(_) => {}
                Err(ObjError::WouldBlock) if self.s.nonblock => {
                    cold += 1;
                    if cold >= self.s.sh.txn_page_budget() {
                        break;
                    }
                }
                Err(e) => return Err(e),
            }
        }
        if cold > 0 {
            return Err(ObjError::WouldBlock);
        }
        Ok(out)
    }

    fn get_val_at(&mut self, id: u64, slot: Slot, k: &[u8], mk: &[u8]) -> Result<Option<Vec<u8>>> {
        // inline value: copied out of the page buffer once (a fragmented one takes the slow path below)
        let tab = self.s.sh.state().dicts.clone();
        let fast = self.kget_with(mk, |v| match v {
            None => Some(None),
            Some(r) if r.first() == Some(&V_INLINE) => Some(Some(r[1..].to_vec())),
            Some(r) if r.first() == Some(&V_CINL) => vc_fast(r, &tab).map(Some),
            Some(_) => None,
        })?;
        if let Some(r) = fast {
            return Ok(r);
        }
        match self.kget(mk)? {
            Some(raw) => Ok(Some(self.decode_val(id, slot, k, &raw)?)),
            None => Ok(None),
        }
    }

    /// Entries of `slot` (attr / omap) with user key `>= from`, at most `max`; `more` = further entries exist.
    pub fn scan_vals(
        &mut self,
        id: u64,
        slot: Slot,
        from: &[u8],
        max: usize,
    ) -> Result<(KvList, bool)> {
        if slot == Slot::Omap && self.s.omap_lsm {
            let (kv, more) = self.lsm_list(id, from, false, b"", max)?;
            return Ok((
                kv.into_iter()
                    .map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .collect(),
                more,
            ));
        }
        let (tag, sub) = match slot {
            Slot::Attr => (T_ATTR, S_ATTR),
            Slot::Omap => (T_OMAP, S_OMAP),
            Slot::Hdr => unreachable!(),
        };
        let (_, end) = sub_range(tag, sub, id);
        let start = slot.main_key(id, from);
        let mut kv = self.kscan(&start, &end, max.saturating_add(1))?;
        let more = kv.len() > max;
        kv.truncate(max);
        // values over the inline limit live in fragment entries (own key range, sorted like the omap keys): load the
        // ones of this page in parallel instead of one serial device read per cold leaf
        if self.w(id).on.flags & slot.frag_flag() != 0
            && let (Some(f), Some(l)) = (kv.first(), kv.last())
        {
            let a = frag_key(id, slot.frag_ty(), &f.0[10..], 0);
            let b = frag_key(id, slot.frag_ty(), &l.0[10..], u32::MAX);
            self.s.tprefetch(self.clk, &a, &b)?;
        }
        let mut out = Vec::with_capacity(kv.len());
        for (k, raw) in kv {
            let uk = k[10..].to_vec();
            let v = self.decode_val(id, slot, &uk, &raw)?;
            out.push((uk, v));
        }
        Ok((out, more))
    }

    // ------------------------------------------------------------------ format upgrade S7 (adr 0611)

    /// Tree omap entries left (adr 0476 runs included) and their bytes as engine run entries: the S7 space check and
    /// progress total. Value lengths from the records (no fragment or data-block read).
    pub fn upgrade_omap_survey(&mut self) -> Result<(u64, u64)> {
        let (mut from, end) = (vec![T_OMAP], vec![T_OMAP + 1]);
        let (mut n, mut bytes) = (0u64, 0u64);
        loop {
            let kv = self.kscan(&from, &end, 1024)?;
            let Some((last, _)) = kv.last() else {
                return Ok((n, bytes));
            };
            from = last.clone();
            from.push(0);
            for (k, raw) in &kv {
                n += 1;
                // id, key length and value tag varints: at most 10 + 5 + 5 bytes, 12 typical
                bytes += (k.len() - 10) as u64 + raw_vlen(raw) + 12;
            }
        }
    }

    /// Format upgrade S7 (adr 0611): the tree omap entries left (adr 0476 runs included), from the first one in
    /// `(object id, key)` order, decoded, until their run entry bytes reach `budget` (at least one entry). Nothing is
    /// staged: [`Stage::upgrade_omap_drop`] removes exactly these entries once their run is installed. The removal
    /// covers one contiguous key span per object, so it is exact: the scan saw every record inside the span.
    pub fn upgrade_omap_take(&mut self, budget: usize) -> Result<OmapTake> {
        let mut t = OmapTake::default();
        let (mut from, end) = (vec![T_OMAP], vec![T_OMAP + 1]);
        while t.bytes < budget.max(1) {
            let kv = self.kscan(&from, &end, 256)?;
            let Some((last, _)) = kv.last() else {
                break;
            };
            from = last.clone();
            from.push(0);
            for (k, raw) in kv {
                let id =
                    omap_id(&k).ok_or_else(|| ObjError::Eio(format!("bad omap tree key {k:?}")))?;
                let uk = k[10..].to_vec();
                if raw.first() == Some(&V_FRAG) && raw.len() == 9 {
                    let n = denc::le::rd_u32(&raw, 5);
                    t.frags
                        .extend((0..n).map(|i| frag_key(id, FT_OMAP, &uk, i)));
                } else if let Some((_, e)) = vext(&raw) {
                    t.exts.push((e.pba(), e.len()));
                }
                let v = self.decode_val(id, Slot::Omap, &uk, &raw)?;
                t.bytes += crate::olsm::run::entry_len(id, &uk, Some(&v));
                let mut b = k;
                b.push(0);
                match t.spans.last_mut() {
                    Some(sp) if sp.0 == id => sp.2 = b,
                    _ => t.spans.push((id, omap_key(id, &uk), b)),
                }
                t.entries.push((id, Bytes::from(uk), Bytes::from(v)));
                if t.bytes >= budget {
                    return Ok(t);
                }
            }
        }
        Ok(t)
    }

    /// Stage the removal of the entries of `t` from the tree: their key spans, fragments and data-block values.
    pub fn upgrade_omap_drop(&mut self, t: &OmapTake) -> Result<()> {
        for (_, a, b) in &t.spans {
            self.kdelrange(a.clone(), b.clone());
        }
        for k in &t.frags {
            self.kdel(k.clone());
        }
        for &(pba, n) in &t.exts {
            self.free_ext(pba, n, false)?;
        }
        Ok(())
    }

    /// S7 end of a shard: no tree omap entry is left (else `Eio`).
    pub fn upgrade_omap_finish(&mut self) -> Result<()> {
        if !self.kscan(&[T_OMAP], &[T_OMAP + 1], 1)?.is_empty() {
            return Err(ObjError::Eio(
                "omap upgrade: tree omap entries left after the conversion".into(),
            ));
        }
        Ok(())
    }

    /// Does the shard hold omap counter records (`c` keys) of an earlier build (`FEAT_OMAP_UNCOUNTED`)?
    pub(crate) fn counter_records(&mut self) -> Result<bool> {
        Ok(!self.kscan(&[T_OPEND], &[T_OPEND + 1], 1)?.is_empty())
    }

    /// Stage the removal of every omap counter record ([`Stage::counter_records`]).
    pub(crate) fn drop_counter_records(&mut self) {
        self.kdelrange(vec![T_OPEND], vec![T_OPEND + 1]);
    }

    // ------------------------------------------------------------------ whole-object ops

    /// Committed-view omap scan as entry pairs (cls, tests): [`Self::scan_omap_enc`] decoded. `values = false` emits
    /// empty value vectors and budgets serialized keys (4 + key length).
    #[allow(clippy::too_many_arguments)]
    pub fn scan_omap_range(
        &mut self,
        id: u64,
        from: &[u8],
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        values: bool,
    ) -> Result<(KvList, bool)> {
        let mode = if values {
            OmapScanMode::Values
        } else {
            OmapScanMode::Keys
        };
        let (enc, n, next) = self.scan_omap_selected(id, from, prefix, max, max_bytes, mode, 0)?;
        Ok((enc_decode(&enc, n, values), next.is_some()))
    }

    /// Committed-view omap listing encoded for a reply in one pass from the tree leaves (listing reply encoding, adr
    /// 0021 S8): `head` reserved zero bytes, then per entry `le32 key length, key` and, with `values`, `le32 value
    /// length, value` (the entry part of a denc `map<string, bufferlist>` / `set<string>`). No allocation per entry;
    /// inline values are copied once, from the leaf into the buffer. Selection, budget and `more` as
    /// [`Self::scan_omap_range`]. Returns `(buffer, entries, more)`; the buffer has room for one more byte (the caller's
    /// trailer).
    #[allow(clippy::too_many_arguments)]
    pub fn scan_omap_enc(
        &mut self,
        id: u64,
        from: &[u8],
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        values: bool,
        head: usize,
    ) -> Result<(Vec<u8>, usize, bool)> {
        let mode = if values {
            OmapScanMode::Values
        } else {
            OmapScanMode::Keys
        };
        let (enc, n, next) =
            self.scan_omap_selected(id, from, prefix, max, max_bytes, mode, head)?;
        Ok((enc, n, next.is_some()))
    }

    /// Complete immutable denc listing: count, encoded entries, then `more`.
    /// Request-scoped RocksDB scans share their completed retry result; native
    /// and blocking paths retain their existing encoding ownership.
    pub fn scan_omap_reply(
        &mut self,
        id: u64,
        from: &[u8],
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        values: bool,
    ) -> Result<Bytes> {
        #[cfg(feature = "rocksdb")]
        if self.s.sh.rocks_selected() && self.s.memo_session().is_some() {
            assert!(self.map.is_empty() && self.dels.is_empty() && self.sc.odel.is_empty());
            let mode = if values {
                OmapScanMode::Values
            } else {
                OmapScanMode::Keys
            };
            return self.rocks_scan_reply(id, from, prefix, (max, max_bytes), mode);
        }
        let (mut enc, n, more) = self.scan_omap_enc(id, from, prefix, max, max_bytes, values, 4)?;
        enc[..4].copy_from_slice(&(n as u32).to_le_bytes());
        enc.push(u8::from(more));
        Ok(enc.into())
    }

    pub fn scan_omap_recovery(
        &mut self,
        id: u64,
        from: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(KvList, Option<Vec<u8>>)> {
        // Recovery always admits its first entry, even with a zero count or byte budget.
        let (enc, n, next) = self.scan_omap_selected(
            id,
            from,
            b"",
            max.max(1),
            max_bytes,
            OmapScanMode::Recovery,
            0,
        )?;
        Ok((enc_decode(&enc, n, true), next))
    }

    /// The omap listing behind `scan_omap_enc` / `scan_omap_range` / `scan_omap_recovery`: the encoded entries (see
    /// [`Self::scan_omap_enc`]), their count and the first key not listed. A non-blocking run of an executor request
    /// (adr 0021 S8) keeps its progress in a scan memo of the shard: a refusal (cold leaf) or a CPU slice
    /// (`SCAN_SLICE_ENTRIES` / `SCAN_SLICE_BYTES` admitted in one pass, more to come) ends the pass with `WouldBlock`, the
    /// next run of the request continues at the key where it stopped. The result is the same as one uninterrupted run:
    /// the object cannot change in between without dropping the memo (`memo_drop`), and the request then starts over.
    #[allow(clippy::too_many_arguments)]
    fn scan_omap_selected(
        &mut self,
        id: u64,
        from: &[u8],
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        mode: OmapScanMode,
        head: usize,
    ) -> Result<(Vec<u8>, usize, Option<Vec<u8>>)> {
        // These APIs are only called on Store's fresh committed-view read Stage.
        assert!(self.map.is_empty() && self.dels.is_empty() && self.sc.odel.is_empty());
        if self.s.omap_lsm {
            return self.lsm_scan_selected(id, from, prefix, max, max_bytes, mode, head);
        }
        let session = self.s.memo_session();
        let mode_id = mode as u8;
        let same = |m: &ScanMemo| {
            m.mode == mode_id
                && m.head == head
                && m.max == max
                && m.max_bytes == max_bytes
                && m.from == from
                && m.prefix == prefix
        };
        let mut m = match session.and_then(|ss| self.s.memo_take(ss, id, same)) {
            Some(m) => m,
            None => {
                let start = Slot::Omap.main_key(id, from.max(prefix));
                let end = omap_prefix_end(id, prefix);
                // a guess that covers a typical page without regrowth (32 B per entry, at most 64 KiB up front)
                let mut enc = Vec::with_capacity(head + 1 + max.saturating_mul(32).min(64 << 10));
                enc.resize(head, 0);
                ScanMemo {
                    session: session.unwrap_or_default(),
                    id,
                    from: from.to_vec(),
                    prefix: prefix.to_vec(),
                    max,
                    max_bytes,
                    mode: mode_id,
                    head,
                    cur: ScanCursor::new(&start, &end).listing(),
                    lsm: None,
                    enc,
                    n: 0,
                    holes: Vec::new(),
                    hole_vals: Vec::new(),
                    bytes: 0,
                    walked: None,
                    touched: 0,
                }
            }
        };
        let (n0, next0) = (m.n, m.cur.next.clone());
        match self.omap_walk(&mut m, mode, self.s.list_sliced()) {
            Ok(()) => {}
            Err(ObjError::WouldBlock) if session.is_some() => {
                // refused or sliced: the next run continues here; entries admitted or leaves passed (a purged range
                // leaves leaves without entries) = progress (the engine does not count such a refusal against its try
                // bound)
                self.s.rm_progress |= m.n > n0 || m.cur.next != next0;
                self.s.memo_put(m);
                return Err(ObjError::WouldBlock);
            }
            Err(e) => return Err(e),
        }
        let next = m.walked.take().flatten();
        if m.hole_vals.len() < m.holes.len() {
            // values not inline in their leaf: load the fragments of the selected ones in parallel, then read them (a
            // refusal keeps the values read so far: none is read twice)
            let key = |h: (usize, u32)| h.0 - h.1 as usize..h.0;
            let (first, last) = (m.holes[m.hole_vals.len()], m.holes[m.holes.len() - 1]);
            let a = frag_key(id, FT_OMAP, &m.enc[key(first)], 0);
            let b = frag_key(id, FT_OMAP, &m.enc[key(last)], u32::MAX);
            if let Err(e) = self.s.tprefetch(self.clk, &a, &b) {
                if session.is_some() && matches!(e, ObjError::WouldBlock) {
                    m.walked = Some(next);
                    self.s.memo_put(m);
                }
                return Err(e);
            }
            while m.hole_vals.len() < m.holes.len() {
                let h = m.holes[m.hole_vals.len()];
                match self.get_val(id, Slot::Omap, &m.enc[key(h)]) {
                    Ok(Some(v)) => m.hole_vals.push(v),
                    Ok(None) => return Err(ObjError::Eio("omap entry disappeared".into())),
                    Err(e) => {
                        if session.is_some() && matches!(e, ObjError::WouldBlock) {
                            m.walked = Some(next);
                            self.s.memo_put(m);
                        }
                        return Err(e);
                    }
                }
            }
            m.enc = splice_holes(&m.enc, &m.holes, &m.hole_vals);
        }
        m.enc.reserve(1);
        Ok((std::mem::take(&mut m.enc), m.n, next))
    }

    /// The key walk of [`Self::scan_omap_selected`] from where `m` stands until the budget, the prefix or the object ends
    /// (`m.walked` set). `sliced`: the pass may end early with `WouldBlock` after its CPU slice (memo kept by the caller).
    fn omap_walk(&mut self, m: &mut ScanMemo, mode: OmapScanMode, sliced: bool) -> Result<()> {
        if m.walked.is_some() {
            return Ok(());
        }
        let (max, max_bytes) = (m.max, m.max_bytes);
        let tab = self.s.sh.state().dicts.clone();
        let (pass_n0, pass_b0) = (m.n, m.bytes);
        loop {
            let entry_room = max.saturating_sub(m.n).saturating_add(1);
            let byte_room = max_bytes.saturating_sub(m.bytes);
            let byte_entries = if mode == OmapScanMode::Keys {
                byte_room / 4
            } else {
                byte_room
            };
            let mut want = entry_room.min(byte_entries.max(1));
            if sliced {
                want = want.min(SCAN_SLICE_ENTRIES);
            }
            // leaves the rest of the request covers (about 32 entries per leaf), read ahead in one rolling window
            m.cur.ra_win = (entry_room / 32).clamp(1, SCAN_RA_MAX) as u32;
            let mut stopped = false;
            let mut next = None;
            let head = m.head;
            let (enc, n, holes, bytes, prefix) =
                (&mut m.enc, &mut m.n, &mut m.holes, &mut m.bytes, &m.prefix);
            let r = self.s.tscan(self.clk, &mut m.cur, want, &mut |key, raw| {
                if stopped {
                    return;
                }
                let k = &key[10..];
                // the cursor ends where the prefix ends (`omap_prefix_end`): every key it emits has the prefix (no
                // compare per key)
                debug_assert!(k.starts_with(prefix));
                let cost = if mode == OmapScanMode::Keys {
                    k.len().saturating_add(4)
                } else {
                    k.len()
                        .saturating_add(usize::try_from(raw_vlen(raw)).unwrap_or(usize::MAX))
                };
                let full = match mode {
                    OmapScanMode::Values => *n > 0 && *bytes >= max_bytes,
                    OmapScanMode::Keys => *bytes >= max_bytes,
                    // Recovery defers an entry equal to the remaining budget, after the first.
                    OmapScanMode::Recovery => *n > 0 && cost >= max_bytes.saturating_sub(*bytes),
                };
                if *n >= max || full {
                    next = Some(k.to_vec());
                    stopped = true;
                    return;
                }
                // out of room: grow once to what the rest of the request needs at the mean entry so far (doubling
                // copied the listing about once more; a 1024-entry page of 300 B entries crossed 64 -> 512 KiB)
                let need = 8 + k.len() + raw.len();
                if *n > 0 && enc.capacity() - enc.len() < need {
                    let left =
                        (max - *n).min(max_bytes.saturating_sub(*bytes) / (*bytes / *n).max(1) + 1);
                    enc.reserve(((enc.len() - head) / *n + 1).saturating_mul(left).max(need));
                }
                *bytes = bytes.saturating_add(cost);
                *n += 1;
                enc.extend_from_slice(&(k.len() as u32).to_le_bytes());
                enc.extend_from_slice(k);
                if mode == OmapScanMode::Keys {
                    return;
                }
                // inline values go straight from the leaf into the listing; the others are read at the end
                match raw.first() {
                    Some(&V_INLINE) => {
                        enc.extend_from_slice(&((raw.len() - 1) as u32).to_le_bytes());
                        enc.extend_from_slice(&raw[1..]);
                    }
                    Some(&V_CINL) if vc_fast_enc(raw, &tab, enc) => {}
                    _ => holes.push((enc.len(), k.len() as u32)),
                }
            });
            // the walk ended inside this step: a miss further on (the step's own read-ahead) does not matter
            if stopped {
                m.walked = Some(next);
                return Ok(());
            }
            if r? {
                m.walked = Some(None);
                return Ok(());
            }
            if sliced
                && (m.n - pass_n0 >= SCAN_SLICE_ENTRIES || m.bytes - pass_b0 >= SCAN_SLICE_BYTES)
            {
                self.s.scan_slice();
                return Err(ObjError::WouldBlock);
            }
        }
    }

    // ------------------------------------------------------------------ omap LSM (adr 0610)

    /// Stage an omap LSM op: logged with the record, visible to this txn's later omap reads.
    fn lsm_op(&mut self, op: OOp) {
        #[cfg(feature = "splinterdb")]
        if let Some(mem) = &mut self.splinter_omem {
            op.apply_splinter(mem, 0);
            self.oops.push(op);
            return;
        }
        #[cfg(feature = "rocksdb")]
        if let Some(mem) = &mut self.rocks_omem {
            op.apply_rocks(mem, 0);
            self.oops.push(op);
            return;
        }
        op.apply(&mut self.omem, 0);
        self.oops.push(op);
    }

    fn engine_get(&mut self, id: u64, key: &[u8]) -> crate::error::Result<Option<Bytes>> {
        #[cfg(feature = "splinterdb")]
        if let Some(mem) = &self.splinter_omem {
            return self.s.sh.splinter_get(Some(mem), id, key);
        }
        #[cfg(feature = "rocksdb")]
        if let Some(mem) = &self.rocks_omem {
            return self.s.sh.rocks_get(Some(mem), id, key);
        }
        self.s.sh.olsm_get(Some(&self.omem), id, key)
    }

    fn engine_by_keys(
        &mut self,
        id: u64,
        keys: &[Bytes],
    ) -> crate::error::Result<Vec<(Bytes, Bytes)>> {
        #[cfg(feature = "splinterdb")]
        if let Some(mem) = &self.splinter_omem {
            return self.s.sh.splinter_by_keys(Some(mem), id, keys);
        }
        #[cfg(feature = "rocksdb")]
        if let Some(mem) = &self.rocks_omem {
            return self.s.sh.rocks_by_keys(Some(mem), id, keys);
        }
        self.s.sh.olsm_by_keys(Some(&self.omem), id, keys)
    }

    /// One bounded step of the engine listing ([`crate::olsm::read::list_page`]).
    fn engine_list_page(
        &mut self,
        q: &ListQuery,
        pos: &mut ListPos,
        out: &mut Vec<(Bytes, Bytes)>,
    ) -> crate::error::Result<ListEnd> {
        self.s.sh.olsm_list_page(Some(&self.omem), q, pos, out)
    }

    /// Every omap key of `id` goes (omap_clear, removal): one range tombstone.
    fn lsm_clear(&mut self, id: u64) {
        self.lsm_op(OOp::Range {
            id,
            first: Bytes::new(),
            end: None,
        });
        let w = self.w(id);
        w.on.flags &= !F_OMAP;
        w.dirty_on = true;
    }

    /// Select a range removal from resident metadata, then identify the exact live keys only for
    /// the small-span path. No tombstone is staged until the enumeration has completed, so a
    /// refused cold read cannot leave a partially applied range in this transaction's overlay.
    ///
    /// A cold run chunk refuses a non-blocking staging run, and the retry re-applies the whole transaction. The keys
    /// found so far and the resume position are kept in the shard's [`RangeMemo`] first, so the retry continues the
    /// enumeration where the miss stopped it instead of rescanning the range (each chunk is visited once). The memo
    /// also keeps the point-path decision, so a retry under the same threshold skips the resident upper bound.
    fn lsm_rm_range(&mut self, id: u64, first: &[u8], last: &[u8]) -> Result<()> {
        let threshold = self.s.sh.omap_delete_range_threshold();
        let seq = self.op_index;
        let session = if threshold == 0 {
            None
        } else {
            self.s.memo_session()
        };
        let generation = self.s.sh.olsm_generation();
        let saved = session
            .and_then(|session| {
                let key = RangeKey {
                    session,
                    seq,
                    id,
                    first,
                    last,
                };
                self.s.range_memo_take(key, generation)
            })
            .filter(|m| m.threshold == threshold);
        let limit = match &saved {
            Some(_) => usize::try_from(threshold).ok(),
            None => self
                .s
                .sh
                .olsm_point_remove_range(Some(&self.omem), id, first, last),
        };
        if let Some(limit) = limit {
            let (mut keys, mut key_bytes, mut cur, mut excl) = match saved {
                Some(m) => (m.keys, m.key_bytes, m.cur, m.excl),
                None => (Vec::new(), 0u64, Bytes::copy_from_slice(first), false),
            };
            'enumerate: loop {
                let want = (limit - keys.len()).min(SCAN_SLICE_ENTRIES);
                let (page, more) = loop {
                    match self
                        .s
                        .sh
                        .olsm_range_keys(Some(&self.omem), id, &cur, excl, last, want)
                    {
                        Err(StoreError::Miss) => {
                            if let Some(session) = session {
                                // Non-blocking: the miss refuses this run; its retry continues from here.
                                self.s.range_memo_put(RangeMemo {
                                    session,
                                    seq,
                                    id,
                                    first: Bytes::copy_from_slice(first),
                                    last: Bytes::copy_from_slice(last),
                                    generation,
                                    threshold,
                                    keys: std::mem::take(&mut keys),
                                    key_bytes,
                                    cur: cur.clone(),
                                    excl,
                                });
                            }
                            self.s.miss_wait(self.clk)?;
                        }
                        r => break r?,
                    }
                };
                // Own only the keys: a key slice must not retain its old values' entire run chunk.
                for key in page {
                    key_bytes = key_bytes.saturating_add(4 + key.len() as u64);
                    if key_bytes > u32::MAX as u64 || key_bytes > self.s.sh.ring_bytes() / 2 {
                        break 'enumerate;
                    }
                    keys.push(Bytes::copy_from_slice(&key));
                }
                if keys.len() >= limit {
                    // The selector is conservative, but do not depend on it for correctness or
                    // allow an underestimated span to expand this record without the threshold.
                    break;
                }
                if !more {
                    if !keys.is_empty() {
                        self.point_ranges.push((
                            self.oops.len(),
                            OOp::Range {
                                id,
                                first: Bytes::copy_from_slice(first),
                                end: Some(Bytes::copy_from_slice(last)),
                            },
                        ));
                        self.lsm_op(OOp::Del {
                            id,
                            blob: del_blob(&keys),
                        });
                    }
                    return Ok(());
                }
                cur = keys
                    .last()
                    .expect("a nonterminal range page is nonempty")
                    .clone();
                excl = true;
            }
        }
        self.lsm_op(OOp::Range {
            id,
            first: Bytes::copy_from_slice(first),
            end: Some(Bytes::copy_from_slice(last)),
        });
        Ok(())
    }

    /// Omap value of `k` of `id`: this txn's ops, then the engine (run block misses wait / park like page misses).
    fn lsm_get(&mut self, id: u64, k: &[u8]) -> Result<Option<Vec<u8>>> {
        loop {
            match self.engine_get(id, k) {
                Err(StoreError::Miss) => self.s.omap_miss_wait(self.clk)?,
                r => return Ok(r?.map(|v| v.to_vec())),
            }
        }
    }

    /// Up to `max` omap entries of `id` from `from` (`excl`: after it) with `prefix`; `true` = more follow. Read in
    /// pages of [`LSM_LIST_PAGE`] entries and [`LSM_LIST_PAGE_BYTES`]: a run block miss continues the page where the
    /// merge stopped, a span of deleted keys costs one engine call per [`LSM_LIST_VISITS`] entries.
    fn lsm_list(
        &mut self,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        max: usize,
    ) -> Result<(Vec<(Bytes, Bytes)>, bool)> {
        #[cfg(feature = "rocksdb")]
        if self.s.sh.rocks_selected() && self.s.memo_session().is_some() {
            return self.rocks_list_memo(id, from, excl, prefix, max);
        }
        #[cfg(feature = "splinterdb")]
        if self.s.sh.splinter_selected()
            && self.s.memo_session().is_some()
            && !self.s.sh.splinter_independent_reads()
        {
            return self.splinter_list_memo(id, from, excl, prefix, max);
        }
        #[cfg(feature = "splinterdb")]
        if self.splinter_omem.is_some() {
            return self.splinter_list_pages(id, from, excl, prefix, max);
        }
        #[cfg(feature = "rocksdb")]
        if self.rocks_omem.is_some() {
            return self.rocks_list_pages(id, from, excl, prefix, max);
        }
        let mut out: Vec<(Bytes, Bytes)> = Vec::new();
        let mut pos = ListPos::new(from, excl);
        loop {
            let q = ListQuery {
                id,
                prefix,
                max: (max - out.len()).min(LSM_LIST_PAGE),
                max_bytes: LSM_LIST_PAGE_BYTES,
                visits: LSM_LIST_VISITS,
            };
            let mut page = Vec::new();
            let more = loop {
                match self.engine_list_page(&q, &mut pos, &mut page) {
                    Ok(ListEnd::Done { more }) => break more,
                    Ok(ListEnd::Resume) => {}
                    Err(StoreError::Miss) => self.s.miss_wait(self.clk)?,
                    Err(e) => return Err(e.into()),
                }
            };
            out.extend(page);
            if !more || out.len() == max {
                return Ok((out, more));
            }
            pos = ListPos {
                from: out
                    .last()
                    .expect("a page with more after it is not empty")
                    .0
                    .clone(),
                excl: true,
            };
        }
    }

    /// [`Self::lsm_list`] on the RocksDB engine: pages of [`LSM_LIST_PAGE`] entries, a miss re-runs the page it hit.
    #[cfg(feature = "rocksdb")]
    fn rocks_list_pages(
        &mut self,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        max: usize,
    ) -> Result<(Vec<(Bytes, Bytes)>, bool)> {
        let mut out: Vec<(Bytes, Bytes)> = Vec::new();
        let (mut cur, mut ex) = (Bytes::copy_from_slice(from), excl);
        loop {
            let want = (max - out.len()).min(LSM_LIST_PAGE);
            let (page, more) = loop {
                let mem = self.rocks_omem.as_ref().expect("RocksDB staging");
                match self.s.sh.rocks_list(Some(mem), id, &cur, ex, prefix, want) {
                    Err(StoreError::Miss) => self.s.miss_wait(self.clk)?,
                    r => break r?,
                }
            };
            out.extend(page);
            if !more || out.len() == max {
                return Ok((out, more));
            }
            cur = out
                .last()
                .expect("a page with more after it is not empty")
                .0
                .clone();
            ex = true;
        }
    }

    /// [`Self::lsm_list`] on the SplinterDB engine without a memo session: pages of
    /// [`LSM_LIST_PAGE`] entries, a miss waits for the worker and re-runs the page.
    #[cfg(feature = "splinterdb")]
    fn splinter_list_pages(
        &mut self,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        max: usize,
    ) -> Result<(Vec<(Bytes, Bytes)>, bool)> {
        let mut out: Vec<(Bytes, Bytes)> = Vec::new();
        let (mut cur, mut ex) = (Bytes::copy_from_slice(from), excl);
        loop {
            let want = (max - out.len()).min(LSM_LIST_PAGE);
            let (page, more) = loop {
                let mem = self.splinter_omem.as_ref().expect("SplinterDB staging");
                match self
                    .s
                    .sh
                    .splinter_list(Some(mem), id, &cur, ex, prefix, want)
                {
                    Err(StoreError::Miss) => self.s.omap_miss_wait(self.clk)?,
                    r => break r?,
                }
            };
            out.extend(page);
            if !more || out.len() == max {
                return Ok((out, more));
            }
            cur = out
                .last()
                .expect("a page with more after it is not empty")
                .0
                .clone();
            ex = true;
        }
    }

    /// [`Self::lsm_scan_selected`] on the SplinterDB engine without a memo session
    /// (blocking or independent reads): pages through [`Self::lsm_list`], which
    /// dispatches to the SplinterDB client, and encodes the selection.
    #[cfg(feature = "splinterdb")]
    fn splinter_scan_pages(
        &mut self,
        id: u64,
        from: &[u8],
        prefix: &[u8],
        limits: (usize, usize),
        mode: OmapScanMode,
        head: usize,
    ) -> Result<(Vec<u8>, usize, Option<Vec<u8>>)> {
        let (max, max_bytes) = limits;
        let mut enc = vec![0u8; head];
        let (mut n, mut bytes) = (0usize, 0usize);
        let (mut cur, mut excl) = (from.to_vec(), false);
        loop {
            // one entry more than the count allows: it is the `next` of a full page
            let (page, more) =
                self.lsm_list(id, &cur, excl, prefix, (max - n).saturating_add(1))?;
            for (k, v) in &page {
                let cost = if mode == OmapScanMode::Keys {
                    k.len().saturating_add(4)
                } else {
                    k.len().saturating_add(v.len())
                };
                let full = match mode {
                    OmapScanMode::Values => n > 0 && bytes >= max_bytes,
                    OmapScanMode::Keys => bytes >= max_bytes,
                    // Recovery defers an entry equal to the remaining budget, after the first.
                    OmapScanMode::Recovery => n > 0 && cost >= max_bytes.saturating_sub(bytes),
                };
                if n >= max || full {
                    enc.reserve(1);
                    return Ok((enc, n, Some(k.to_vec())));
                }
                bytes = bytes.saturating_add(cost);
                n += 1;
                enc.extend_from_slice(&(k.len() as u32).to_le_bytes());
                enc.extend_from_slice(k);
                if mode != OmapScanMode::Keys {
                    enc.extend_from_slice(&(v.len() as u32).to_le_bytes());
                    enc.extend_from_slice(v);
                }
            }
            match page.last() {
                Some((k, _)) if more => {
                    cur = k.to_vec();
                    excl = true;
                }
                _ => {
                    enc.reserve(1);
                    return Ok((enc, n, None));
                }
            }
        }
    }

    /// [`Self::scan_omap_selected`] of a store with the omap LSM engine: the same selection, budget and encoding over
    /// the engine's merged listing. A non-blocking run of an executor request keeps its progress in a scan memo of the
    /// shard like the tree listing does: a refusal (cold run block) or the end of a CPU slice ([`LSM_LIST_VISITS`]
    /// entries merged) ends the pass with `WouldBlock`, the next run continues at the key where the merge stopped.
    #[allow(clippy::too_many_arguments)]
    fn lsm_scan_selected(
        &mut self,
        id: u64,
        from: &[u8],
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        mode: OmapScanMode,
        head: usize,
    ) -> Result<(Vec<u8>, usize, Option<Vec<u8>>)> {
        #[cfg(feature = "rocksdb")]
        if self.s.sh.rocks_selected() && self.s.memo_session().is_some() {
            return self.rocks_scan_memo(id, from, prefix, (max, max_bytes), mode, head);
        }
        #[cfg(feature = "splinterdb")]
        if self.s.sh.splinter_selected()
            && self.s.memo_session().is_some()
            && !self.s.sh.splinter_independent_reads()
        {
            return self.splinter_scan_memo(id, from, prefix, (max, max_bytes), mode, head);
        }
        // Blocking or independent SplinterDB reads: the engine-dispatched page loop, not
        // the native LSM walk below (which reads only the native engine).
        #[cfg(feature = "splinterdb")]
        if self.s.sh.splinter_selected() {
            return self.splinter_scan_pages(id, from, prefix, (max, max_bytes), mode, head);
        }
        let session = self.s.memo_session();
        let mode_id = mode as u8;
        let same = |m: &ScanMemo| {
            m.mode == mode_id
                && m.head == head
                && m.max == max
                && m.max_bytes == max_bytes
                && m.from == from
                && m.prefix == prefix
        };
        let mut m = match session.and_then(|ss| self.s.memo_take(ss, id, same)) {
            Some(m) => m,
            None => {
                let mut enc = Vec::with_capacity(head + 1 + max.saturating_mul(32).min(64 << 10));
                enc.resize(head, 0);
                ScanMemo {
                    session: session.unwrap_or_default(),
                    id,
                    from: from.to_vec(),
                    prefix: prefix.to_vec(),
                    max,
                    max_bytes,
                    mode: mode_id,
                    head,
                    cur: ScanCursor::new(&[], &[]),
                    lsm: Some(ListPos::new(from, false)),
                    enc,
                    n: 0,
                    holes: Vec::new(),
                    hole_vals: Vec::new(),
                    bytes: 0,
                    walked: None,
                    touched: 0,
                }
            }
        };
        let (n0, pos0) = (m.n, m.lsm.clone());
        self.s.sh.olsm_take_demand_read();
        match self.lsm_walk(&mut m, mode) {
            Ok(()) => {}
            Err(ObjError::WouldBlock) if session.is_some() => {
                // refused or sliced: the next run continues here. The engine does not count a refusal against its try
                // bound that admitted entries, passed keys or started no read (it waits for the loads of an earlier
                // run: completion-driven, not a failed attempt; a run that retries before they landed repeats nothing)
                self.s.rm_progress |=
                    m.n > n0 || m.lsm != pos0 || !self.s.sh.olsm_take_demand_read();
                self.s.memo_put(m);
                return Err(ObjError::WouldBlock);
            }
            Err(e) => return Err(e),
        }
        let next = m.walked.take().flatten();
        m.enc.reserve(1);
        Ok((std::mem::take(&mut m.enc), m.n, next))
    }

    /// The listing walk of [`Self::lsm_scan_selected`] from where `m` stands until its budget, the prefix or the object
    /// ends (`m.walked` set). The engine's entries are admitted as it lists them and `m.lsm` follows its position, so
    /// whichever way a pass ends (`WouldBlock` of a cold run block or of the CPU slice) nothing listed is listed again
    /// and no deleted key is merged twice. `sliced` runs end after every engine call that stopped on its visit budget;
    /// others (blocking, or exempt by [`crate::obj::Store::list_whole`]) walk on.
    fn lsm_walk(&mut self, m: &mut ScanMemo, mode: OmapScanMode) -> Result<()> {
        let sliced = self.s.list_sliced();
        loop {
            // one entry more than the count allows: it is the `next` of a full page
            let entry_room = m.max.saturating_sub(m.n).saturating_add(1);
            let q = ListQuery {
                id: m.id,
                prefix: &m.prefix,
                max: entry_room.min(LSM_LIST_PAGE),
                max_bytes: LSM_LIST_PAGE_BYTES,
                visits: LSM_LIST_VISITS,
            };
            let mut page = Vec::new();
            let pos = m.lsm.as_mut().expect("an LSM listing memo");
            let r = self.engine_list_page(&q, pos, &mut page);
            // the entries listed before the call ended are decided, whichever way it ended
            if let Some(next) = Self::lsm_admit(m, mode, &page) {
                m.walked = Some(Some(next));
                return Ok(());
            }
            match r {
                Ok(ListEnd::Done { more: false }) => {
                    m.walked = Some(None);
                    return Ok(());
                }
                Ok(ListEnd::Done { more: true }) => {
                    let (k, _) = page.last().expect("a page with more after it is not empty");
                    m.lsm = Some(ListPos {
                        from: k.clone(),
                        excl: true,
                    });
                }
                Ok(ListEnd::Resume) if sliced => {
                    self.s.scan_slice();
                    return Err(ObjError::WouldBlock);
                }
                Ok(ListEnd::Resume) => {}
                Err(StoreError::Miss) => self.s.miss_wait(self.clk)?,
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Admit the entries of `page` into `m` by its budget (count, bytes, `mode`); `Some(key)`: the budget is spent, the
    /// first key not admitted.
    fn lsm_admit(m: &mut ScanMemo, mode: OmapScanMode, page: &[(Bytes, Bytes)]) -> Option<Vec<u8>> {
        for (k, v) in page {
            let cost = if mode == OmapScanMode::Keys {
                k.len().saturating_add(4)
            } else {
                k.len().saturating_add(v.len())
            };
            let full = match mode {
                OmapScanMode::Values => m.n > 0 && m.bytes >= m.max_bytes,
                OmapScanMode::Keys => m.bytes >= m.max_bytes,
                // Recovery defers an entry equal to the remaining budget, after the first.
                OmapScanMode::Recovery => m.n > 0 && cost >= m.max_bytes.saturating_sub(m.bytes),
            };
            if m.n >= m.max || full {
                return Some(k.to_vec());
            }
            m.bytes = m.bytes.saturating_add(cost);
            m.n += 1;
            m.enc.extend_from_slice(&(k.len() as u32).to_le_bytes());
            m.enc.extend_from_slice(k);
            if mode != OmapScanMode::Keys {
                m.enc.extend_from_slice(&(v.len() as u32).to_le_bytes());
                m.enc.extend_from_slice(v);
            }
        }
        None
    }

    fn remove_obj(&mut self, id: u64) -> Result<()> {
        self.shrink = true;
        self.drop_sruns(id);
        let (created, no_ext, flags) = {
            let w = self.w(id);
            (w.created(), w.no_ext(), w.on.flags)
        };
        let mut ranges = vec![id_range(T_EXT, id), id_range(T_ATTR, id)];
        if flags & F_OMAP != 0 {
            if self.s.omap_lsm {
                self.lsm_clear(id);
            } else {
                ranges.push(id_range(T_OMAP, id));
            }
        }
        if flags & (F_OFRAG | F_AFRAG | F_HFRAG) != 0 {
            ranges.push(id_range(T_FRAG, id));
        }
        if flags & F_HDR != 0 {
            ranges.push(id_range(T_HDR, id));
        }
        if flags & F_INLINE != 0 {
            ranges.push(id_range(T_INL, id));
        }
        // values in data blocks (adr 0021 am. 46); an object created by this txn has only staged ones (they own nothing yet)
        if !created {
            for (f, t) in [(F_AEXT, T_ATTR), (F_OEXT, T_OMAP), (F_HEXT, T_HDR)] {
                if flags & f != 0 {
                    let (a, b) = id_range(t, id);
                    self.free_ext_vals(a, b)?;
                }
            }
        }
        if !no_ext {
            for (_, e) in self.extents_in(id, 0, INF)? {
                self.free_ext(e.pba, e.len(), e.shared)?;
            }
        }
        if created {
            for (a, b) in ranges {
                self.kforget(&a, &b);
            }
        } else {
            // the object's committed omap runs go with its omap range (adr 0476)
            for (a, b) in ranges {
                self.kdelrange(a, b);
            }
            self.kdel(onode_key(id));
        }
        let nk = self.name_of(id);
        self.kdel(nk.clone());
        self.sc.names.insert(nk, None);
        let w = self.w(id);
        w.gone = true;
        w.runs = Dirty::default();
        Ok(())
    }

    fn clone_obj(&mut self, cid: &CollT, src: &Ghobject, dst: &Ghobject) -> Result<()> {
        let sid = self.lookup(cid, src)?.ok_or(ObjError::NoEnt)?;
        if src == dst {
            return Ok(());
        }
        if let Some(did) = self.lookup(cid, dst)? {
            self.remove_obj(did)?;
        }
        let nid = self.create(cid, dst)?;
        let size = self.obj_size(sid);
        let flags = self.w(sid).on.flags;
        let (attrs, _) = self.scan_vals(sid, Slot::Attr, b"", usize::MAX - 1)?;
        for (k, v) in attrs {
            self.put_val(nid, Slot::Attr, &k, &v)?;
        }
        if flags & F_HDR != 0
            && let Some(h) = self.get_val(sid, Slot::Hdr, b"")?
        {
            self.put_val(nid, Slot::Hdr, b"", &h)?;
        }
        if flags & F_OMAP != 0 && self.s.omap_lsm {
            let (om, _) = self.lsm_list(sid, b"", false, b"", usize::MAX - 1)?;
            let (n, blob) = put_blob(&om);
            self.lsm_op(OOp::Put { id: nid, n, blob });
            self.set_flag(nid, F_OMAP);
        } else if flags & F_OMAP != 0 {
            let (a, b) = id_range(T_OMAP, sid);
            self.demote_range(sid, &a, &b)?;
            let (om, _) = self.scan_vals(sid, Slot::Omap, b"", usize::MAX - 1)?;
            for (k, v) in om {
                self.put_val(nid, Slot::Omap, &k, &v)?;
            }
            self.set_flag(nid, F_OMAP);
        }
        if !self.share_extents(sid, nid)? {
            for (s, n) in self.eff_ranges(sid, 0, INF)? {
                let mut done = 0;
                while done < n {
                    let c = (n - done).min(256);
                    let d = self.eff_read(sid, s + done, c)?;
                    self.w(nid).runs.set(s + done, c, Some(d));
                    done += c;
                }
            }
        }
        self.set_size(nid, size)
    }

    /// Clone data by reference (adr 0021 am. 32): `nid` (created by this clone) gets the extent records of `sid`, both
    /// flagged `EXT_SHARED`, each block's owner count +1. `false` = not eligible, copy instead: sharing off, source with
    /// staged data of this txn (dirty runs), inline data, more than `SHARE_MAX_EXTENTS` runs (record size). Sharing off
    /// includes a store without `FEAT_SHARED_EXT` (set by mkfs only).
    fn share_extents(&mut self, sid: u64, nid: u64) -> Result<bool> {
        if self.s.share_off {
            return Ok(false);
        }
        let w = self.w(sid);
        if w.no_ext() || !w.runs.is_empty() || w.on.flags & F_INLINE != 0 {
            return Ok(false);
        }
        let (comp, comp_orig, cflag) = (w.on.comp, w.on.comp_orig, w.on.flags & F_COMP);
        self.extents_set(sid, 0, INF)?;
        if self.sc.exts.len() > SHARE_MAX_EXTENTS {
            return Ok(false);
        }
        let exts: Vec<(u64, bool, Vec<u8>)> = self
            .sc
            .exts
            .iter()
            .map(|e| {
                let mut v = self.sc.ext_raw[e.off as usize..(e.off + e.len) as usize].to_vec();
                let was = v[1] & EXT_SHARED != 0;
                v[1] |= EXT_SHARED;
                (e.lblk, was, v)
            })
            .collect();
        for (lblk, was_shared, v) in exts {
            let (pba, n) = {
                let e = ExtRaw::new(&v).expect("validated by extents_set");
                (e.pba(), e.len())
            };
            if was_shared {
                self.ref_adj(pba, n, true)?;
            } else {
                // an unflagged extent is exclusive: no refcount record covers its blocks (am. 32 (a)), so the scan of
                // `ref_adj` finds nothing; two owners now (a fragmented 4 MiB head: 1024 scans saved, am. 41)
                self.kput(ref_key(pba).to_vec(), ref_encode(n, 2));
            }
            self.kput(ext_key(sid, lblk as u32), v.clone());
            self.kput(ext_key(nid, lblk as u32), v);
        }
        let w = self.w(nid);
        w.shared_in = true;
        if cflag != 0 {
            w.on.flags |= F_COMP;
            w.on.comp = comp;
            w.on.comp_orig = comp_orig;
            w.dirty_on = true;
        }
        // reads of the clone must not race a data write of the source that is not durable yet
        self.sc.ids.push(nid);
        self.s.stats.shared_clones += 1;
        Ok(true)
    }

    /// `clone_range` (adr 0021 am. 38): bytes `[so, so+len)` of `sid` to `[dof, dof+len)` of `did`. The block-aligned
    /// middle shares the source's committed blocks (`share_range`) when eligible; the unaligned head / tail blocks and
    /// ineligible ranges are copied: only the source's data ranges are read and written, its holes become holes of the
    /// destination (a sparse EC truncate stash costs its data, not its logical length).
    fn clone_range(&mut self, sid: u64, did: u64, so: u64, len: u64, dof: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let bs = BLK as u64;
        let send = so.checked_add(len).ok_or(ObjError::TooLarge)?;
        let dend = dof.checked_add(len).ok_or(ObjError::TooLarge)?;
        if blocks_for(dend) > MAX_BLOCKS {
            return Err(ObjError::TooLarge);
        }
        let (a, b) = (so.div_ceil(bs), send / bs);
        if sid != did
            && so % bs == dof % bs
            && a < b
            && self.share_range(sid, did, a, b, dof.div_ceil(bs))?
        {
            let head = a * bs - so;
            if head > 0 {
                let d = self.read_eff_bytes(sid, so, head)?;
                self.write_data(did, dof, d)?;
            }
            let tail = send - b * bs;
            if tail > 0 {
                let d = self.read_eff_bytes(sid, b * bs, tail)?;
                self.write_data(did, dof + (b * bs - so), d)?;
            }
            let size = self.obj_size(did).max(dend);
            return self.set_size(did, size);
        }
        // every read precedes the first write: an overlapping range of the same object copies its old content
        let mut parts = Vec::new();
        for (s, n) in self.eff_ranges(sid, so / bs, send.div_ceil(bs))? {
            let (lo, hi) = ((s * bs).max(so), ((s + n) * bs).min(send));
            parts.push((lo - so, self.read_eff_bytes(sid, lo, hi - lo)?));
        }
        self.zero_data(did, dof, len)?;
        for (rel, d) in parts {
            self.write_data(did, dof + rel, d)?;
        }
        Ok(())
    }

    /// Can blocks `[a, b)` of `id` be shared by `share_range` (as far as the source decides; the destination's own
    /// `F_INLINE` / `F_COMP` is checked there)? Leaves the range's extents in the scratch set when it can.
    fn range_shareable(&mut self, id: u64, a: u64, b: u64) -> Result<bool> {
        if self.s.share_off || b > u32::MAX as u64 {
            return Ok(false);
        }
        let w = self.w(id);
        if w.no_ext()
            || w.on.flags & (F_INLINE | F_COMP) != 0
            || w.runs
                .runs
                .range(..b)
                .next_back()
                .is_some_and(|(s, r)| s + r.n > a)
        {
            return Ok(false);
        }
        self.extents_set(id, a, b)?;
        Ok(self.sc.exts.len() <= SHARE_MAX_EXTENTS
            && self.sc.exts.iter().all(|ei| {
                ExtRaw::new(&self.sc.ext_raw[ei.off as usize..(ei.off + ei.len) as usize])
                    .is_some_and(|e| e.comp().is_none())
            }))
    }

    /// Share the committed blocks `[a, b)` of `sid` as blocks `[da, da + b - a)` of `did` (adr 0021 am. 38): the old
    /// destination range is released (staged runs cut, committed blocks punched), the source records overlapping the
    /// range are split at its edges and the inner part flagged `EXT_SHARED`, the same inner records (same blocks, crcs
    /// salted by block address stay valid) are put for `did`, each block's owner count +1. Holes stay holes. `false` =
    /// not eligible (nothing changed): sharing off, source with staged data of this txn in the range, inline, compressed,
    /// more than `SHARE_MAX_EXTENTS` runs; destination inline or compressed.
    fn share_range(&mut self, sid: u64, did: u64, a: u64, b: u64, da: u64) -> Result<bool> {
        let n = b - a;
        if da + n > u32::MAX as u64 || self.w(did).on.flags & (F_INLINE | F_COMP) != 0 {
            return Ok(false);
        }
        if !self.range_shareable(sid, a, b)? {
            return Ok(false);
        }
        let exts: Vec<(u64, Vec<u8>)> = self
            .sc
            .exts
            .iter()
            .map(|e| {
                (
                    e.lblk,
                    self.sc.ext_raw[e.off as usize..(e.off + e.len) as usize].to_vec(),
                )
            })
            .collect();
        self.w(did).runs.cut(da, da + n);
        if !self.w(did).no_ext() {
            self.punch(did, da, da + n)?;
        }
        for (s, raw) in exts {
            let e = ExtRaw::new(&raw).expect("validated by extents_set");
            let end = s + e.len() as u64;
            let (lo, hi) = (a.max(s), b.min(end));
            if lo >= hi {
                continue;
            }
            let mut mid = e.slice_encode((lo - s) as u32, (hi - lo) as u32);
            mid[1] |= EXT_SHARED;
            if !e.shared() {
                // the source keeps its unflagged blocks outside the range exclusive (frees and defrag stay cheap)
                if s < lo {
                    self.kput(ext_key(sid, s as u32), e.slice_encode(0, (lo - s) as u32));
                }
                if hi < end {
                    self.kput(
                        ext_key(sid, hi as u32),
                        e.slice_encode((hi - s) as u32, (end - hi) as u32),
                    );
                }
                self.kput(ext_key(sid, lo as u32), mid.clone());
            }
            self.ref_adj(e.pba() + (lo - s), (hi - lo) as u32, true)?;
            self.kput(ext_key(did, (lo - a + da) as u32), mid);
        }
        self.w(did).shared_in = true;
        // reads of the destination must not race a data write of the source that is not durable yet
        self.sc.ids.push(did);
        self.s.stats.shared_ranges += 1;
        Ok(true)
    }

    /// Release blocks `[pba, pba + n)` of one extent: freed at once when exclusive, through the refcount when flagged.
    fn free_ext(&mut self, pba: u64, n: u32, shared: bool) -> Result<()> {
        if shared {
            self.ref_adj(pba, n, false)
        } else {
            self.frees.push((pba, n));
            Ok(())
        }
    }

    /// Owner count of blocks `[pba, pba + n)` (`n <= MAX_RUN`, one extent) +1 (`inc`) or -1. `r` records hold the counts
    /// of 2 or more (absent = 1) as runs of at most `MAX_RUN` blocks that never overlap, so the records that can touch the range
    /// start within `MAX_RUN - 1` blocks before it. Blocks that drop to 0 owners are freed (as an exclusive extent).
    fn ref_adj(&mut self, pba: u64, n: u32, inc: bool) -> Result<()> {
        let n = n as usize;
        debug_assert!(n >= 1 && n <= MAX_RUN as usize);
        let end = pba + n as u64;
        let from = ref_key(pba.saturating_sub(MAX_RUN as u64 - 1));
        let kv = self.kscan(&from, &ref_key(end), usize::MAX)?;
        let mut cnt = [1u32; MAX_RUN as usize];
        for (k, v) in kv {
            let s = u64::from_be_bytes(k[1..9].try_into().unwrap());
            let (len, c) =
                ref_decode(&v).ok_or_else(|| ObjError::Eio("bad refcount record".into()))?;
            let e = s + len as u64;
            if e <= pba {
                continue;
            }
            // split off the parts outside the range, take the counts inside
            self.kdel(k);
            if s < pba {
                self.kput(ref_key(s).to_vec(), ref_encode((pba - s) as u32, c));
            }
            if e > end {
                self.kput(ref_key(end).to_vec(), ref_encode((e - end) as u32, c));
            }
            for b in s.max(pba)..e.min(end) {
                cnt[(b - pba) as usize] = c;
            }
        }
        let mut i = 0;
        while i < n {
            let mut j = i + 1;
            while j < n && cnt[j] == cnt[i] {
                j += 1;
            }
            let (at, len) = (pba + i as u64, (j - i) as u32);
            match if inc { cnt[i] + 1 } else { cnt[i] - 1 } {
                0 => self.frees.push((at, len)),
                1 => {}
                c => self.kput(ref_key(at).to_vec(), ref_encode(len, c)),
            }
            i = j;
        }
        Ok(())
    }

    // ------------------------------------------------------------------ apply

    pub fn apply(&mut self, t: &'a OTxn) -> Result<()> {
        self.payloads.clone_from(&t.payloads.0);
        // strict whitelist (adr 0021 am. 21): only ops that can never add state keep a txn in the pure-shrink class. PG
        // bookkeeping (pgmeta omap: the delete's log entry, info, removal marker) is bounded by the PG log length and
        // does not count (adr 0021 S4, review F3): a client delete or a PG removal at the system floor still frees space.
        self.grows |= t.ops.iter().any(|o| {
            !matches!(
                o,
                TOp::Remove { .. }
                    | TOp::RmColl { .. }
                    | TOp::Truncate { .. }
                    | TOp::Zero { .. }
                    | TOp::RmAttr { .. }
                    | TOp::RmAttrs { .. }
                    | TOp::OmapRmKeys { .. }
                    | TOp::OmapRmKeyRange { .. }
                    | TOp::OmapClear { .. }
            ) && !matches!(
                o,
                TOp::OmapSetKeys { oid, .. } | TOp::OmapSetHeader { oid, .. } if oid.is_pgmeta()
            )
        });
        self.shrink |= t.frees;
        // system txn: touches only the meta collection (osdmaps, superblock): must succeed while user writes are
        // rejected (ADR 0021 amendment 4)
        if t.sys
            || (!t.ops.is_empty()
                && t.ops
                    .iter()
                    .all(|o| o.colls().iter().flatten().all(|c| matches!(c, CollT::Meta))))
        {
            self.freeing = true;
        }
        self.comp = t.comp.filter(|_| !self.s.comp_off);
        for (i, op) in t.ops.iter().enumerate() {
            self.op_index = u32::try_from(i).unwrap_or(u32::MAX);
            self.apply_op(op)?;
        }
        Ok(())
    }

    fn apply_op(&mut self, op: &'a TOp) -> Result<()> {
        self.apply_op_inner(op)?;
        self.dv_bump(op)
    }

    /// Data version of the object a data-changing op leaves changed (adr 0593-dedup-deep-scrub-reformat): +1 when its
    /// collection tracks data versions. Touch, write, zero, truncate (of an existing object) and the destination of
    /// clone / clone_range count; attrs, omap, rename and collection ops do not.
    fn dv_bump(&mut self, op: &TOp) -> Result<()> {
        let (cid, oid) = match op {
            TOp::Touch { cid, oid }
            | TOp::Write { cid, oid, .. }
            | TOp::Zero { cid, oid, .. }
            | TOp::Truncate { cid, oid, .. } => (cid, oid),
            TOp::Clone { cid, dst, .. } | TOp::CloneRange { cid, dst, .. } => (cid, dst),
            _ => return Ok(()),
        };
        if !self
            .sc
            .colls
            .get(cid)
            .and_then(|e| e.info.as_ref())
            .is_some_and(|i| i.dv_on)
        {
            return Ok(());
        }
        if let Some(id) = self.lookup(cid, oid)? {
            let w = self.w(id);
            w.on.dv += 1;
            w.on.flags |= F_DVER;
            w.dirty_on = true;
        }
        Ok(())
    }

    fn apply_op_inner(&mut self, op: &'a TOp) -> Result<()> {
        let has_memos = !self.s.memos.is_empty();
        #[cfg(feature = "splinterdb")]
        let has_memos = if self.splinter_omem.is_some() {
            !self.s.splinter_memos.is_empty()
        } else {
            has_memos
        };
        #[cfg(feature = "rocksdb")]
        let has_memos = if self.rocks_omem.is_some() {
            !self.s.rocks_memos.is_empty()
        } else {
            has_memos
        };
        if has_memos {
            // a listing of an object this op changes continues on nothing it read (adr 0021 S8): it starts over
            let objects = op.objects().into_iter().flatten();
            #[cfg(feature = "rocksdb")]
            let objects = {
                let mut objects = objects;
                if self.s.sh.rocks_selected()
                    && matches!(op, TOp::Clone { .. } | TOp::CloneRange { .. })
                {
                    // A clone reads its source; only the destination's memos
                    // are invalidated during RocksDB transaction planning.
                    objects.next();
                }
                objects
            };
            #[cfg(feature = "splinterdb")]
            let objects = {
                let mut objects = objects;
                if self.s.sh.splinter_selected()
                    && matches!(op, TOp::Clone { .. } | TOp::CloneRange { .. })
                {
                    objects.next();
                }
                objects
            };
            for (c, o) in objects {
                if let Ok(Some(id)) = self.lookup(c, o) {
                    #[cfg(feature = "rocksdb")]
                    if self.s.sh.rocks_selected() {
                        self.s.memo_drop_planning(id);
                        continue;
                    }
                    #[cfg(feature = "splinterdb")]
                    if self.s.sh.splinter_selected() {
                        let session = self.s.session_context();
                        self.s.splinter_memos.retain(|m| {
                            m.id != id || (m.engine_cursor.is_some() && Some(m.session) == session)
                        });
                        continue;
                    }
                    self.s.memo_drop(id);
                }
            }
        }
        match op {
            TOp::MkColl {
                cid,
                bits,
                exist_ok,
            } => {
                if self.coll_ent(cid)?.info.is_some() {
                    return if *exist_ok {
                        Ok(())
                    } else {
                        Err(ObjError::Exists)
                    };
                }
                let id = self.new_id()?;
                self.sc.coll_ids.insert(id, *cid);
                let e = self.coll_ent(cid)?;
                e.info = Some(CollInfo {
                    id,
                    bits: *bits,
                    nobj: 0,
                    nbytes: 0,
                    comp: 0,
                    comp_orig: 0,
                    dv_on: false,
                    dv_gen: 0,
                });
                e.dirty = true;
            }
            TOp::RmColl { cid } => {
                let id = self.coll_id(cid)?;
                if !self.kscan(&name_prefix(id), &name_end(id), 1)?.is_empty()
                    || self.long_maybe()?
                        && !self.kscan(&long_prefix(id), &long_end(id), 1)?.is_empty()
                {
                    return Err(ObjError::NotEmpty);
                }
                let e = self.coll_ent(cid)?;
                e.info = None;
                e.dirty = true;
                self.shrink = true;
            }
            TOp::SetCollBits { cid, bits } => {
                self.coll_id(cid)?;
                let e = self.coll_ent(cid)?;
                e.info.as_mut().unwrap().bits = *bits;
                e.dirty = true;
            }
            TOp::DedupKv {
                puts,
                dels,
                del_range,
                ..
            } => {
                if !self.s.dedup {
                    return Err(ObjError::Unsupported("dedup records need FEAT_DEDUP"));
                }
                let ok = |k: &[u8]| super::dedup::parse_key(k).is_some();
                let range_ok = del_range.as_ref().is_none_or(|(a, b)| {
                    a.first() == Some(&super::dedup::T_DEDUP)
                        && b.first() == Some(&super::dedup::T_DEDUP)
                        && a < b
                });
                if !puts.iter().all(|(k, _)| ok(k)) || !dels.iter().all(|k| ok(k)) || !range_ok {
                    return Err(ObjError::Invalid("not a dedup record key".into()));
                }
                // range delete, then puts, then deletes
                if let Some((a, b)) = del_range {
                    self.kdelrange(a.clone(), b.clone());
                }
                for (k, v) in puts {
                    self.kput(k.clone(), v.clone());
                }
                for k in dels {
                    self.kdel(k.clone());
                }
            }
            TOp::SetCollDvTrack { cid, on } => {
                if !self.s.dedup {
                    return Err(ObjError::Unsupported(
                        "data version tracking needs FEAT_DEDUP",
                    ));
                }
                self.coll_id(cid)?;
                let e = self.coll_ent(cid)?;
                let i = e.info.as_mut().unwrap();
                if i.dv_on != *on {
                    i.dv_gen += *on as u64;
                    i.dv_on = *on;
                    e.dirty = true;
                }
            }
            TOp::Touch { cid, oid } => {
                self.lookup_or_create(cid, oid)?;
            }
            TOp::Reformat {
                cid,
                oid,
                off,
                data,
                expect,
                max_frags,
            } => {
                let Some(id) = self.lookup(cid, oid)? else {
                    return Err(ObjError::Stale);
                };
                let now = self.data_version(cid, id)?;
                let end = off + data.len() as u64;
                if now != *expect
                    || !now.tracking
                    || end > self.obj_size(id)
                    || !off.is_multiple_of(BLK as u64)
                    || data.is_empty()
                {
                    return Err(ObjError::Stale);
                }
                self.write_data_b(id, *off, data)?;
                if *max_frags > 0 {
                    self.reformat_check =
                        Some((id, off / BLK as u64, end.div_ceil(BLK as u64), *max_frags));
                }
            }
            TOp::Write {
                cid,
                oid,
                off,
                data,
            } => {
                let id = self.lookup_or_create(cid, oid)?;
                self.write_data_b(id, *off, data)?;
            }
            TOp::Zero { cid, oid, off, len } => {
                let id = self.lookup_or_create(cid, oid)?;
                self.zero_data(id, *off, *len)?;
            }
            TOp::Truncate { cid, oid, size } => {
                if let Some(id) = self.lookup(cid, oid)? {
                    self.truncate_data(id, *size)?;
                }
            }
            TOp::Remove { cid, oid } => {
                if let Some(id) = self.lookup(cid, oid)? {
                    self.remove_obj(id)?;
                }
            }
            TOp::SetAttrs { cid, oid, attrs } => {
                let id = self.lookup_or_create(cid, oid)?;
                for (k, v) in attrs {
                    self.put_val(id, Slot::Attr, k, v)?;
                }
            }
            TOp::RmAttr { cid, oid, name } => {
                if let Some(id) = self.lookup(cid, oid)? {
                    self.rm_val(id, Slot::Attr, name)?;
                }
            }
            TOp::RmAttrs { cid, oid } => {
                if let Some(id) = self.lookup(cid, oid)? {
                    let (a, b) = id_range(T_ATTR, id);
                    if self.w(id).on.flags & F_AEXT != 0 {
                        self.free_ext_vals(a.clone(), b.clone())?;
                    }
                    self.kdelrange(a, b);
                    if self.w(id).on.flags & F_AFRAG != 0 {
                        let (a, b) = frag_range(id, FT_ATTR);
                        self.kdelrange(a, b);
                    }
                }
            }
            TOp::Clone { cid, src, dst } => self.clone_obj(cid, src, dst)?,
            TOp::CloneRange {
                cid,
                src,
                dst,
                src_off,
                len,
                dst_off,
            } => {
                let sid = self.lookup(cid, src)?.ok_or(ObjError::NoEnt)?;
                let did = self.lookup_or_create(cid, dst)?;
                self.clone_range(sid, did, *src_off, *len, *dst_off)?;
            }
            TOp::MoveRename {
                cid,
                oid,
                dcid,
                doid,
            } => {
                let Some(id) = self.lookup(cid, oid)? else {
                    return Ok(());
                };
                let dc = self.coll_id(dcid)?;
                if let Some(did) = self.lookup(dcid, doid)? {
                    if did == id {
                        return Ok(());
                    }
                    self.remove_obj(did)?;
                }
                let onk = self.name_of(id);
                self.kdel(onk.clone());
                self.sc.names.insert(onk, None);
                let nnk = self.name_key_for(dc, doid)?;
                self.note_long(&nnk);
                self.kput(nnk.clone(), id.to_le_bytes().to_vec());
                self.sc.names.insert(nnk, Some(id));
                let w = self.w(id);
                w.coll = dc;
                w.counted = counted(doid);
                w.pgmeta = doid.is_pgmeta();
            }
            TOp::OmapSetKeys { cid, oid, pairs } if self.s.omap_lsm => {
                let id = self.lookup_or_create(cid, oid)?;
                for (k, _) in pairs.iter() {
                    self.key_ok(Slot::Omap, k)?;
                }
                let (n, blob) = put_blob(pairs);
                self.lsm_op(OOp::Put { id, n, blob });
                self.set_flag(id, F_OMAP);
            }
            TOp::OmapSetRun { cid, oid, run } if self.s.omap_lsm => {
                let id = self.lookup_or_create(cid, oid)?;
                for (k, _) in run.view().iter() {
                    self.key_ok(Slot::Omap, k)?;
                }
                let (n, blob) = run.blob();
                self.lsm_op(OOp::Put { id, n, blob });
                self.set_flag(id, F_OMAP);
            }
            TOp::OmapRmKeys { cid, oid, keys } if self.s.omap_lsm => {
                if let Some(id) = self.lookup(cid, oid)?
                    && self.w(id).on.flags & F_OMAP != 0
                {
                    self.lsm_op(OOp::Del {
                        id,
                        blob: del_blob(keys),
                    });
                }
            }
            TOp::OmapRmKeyRange {
                cid,
                oid,
                first,
                last,
            } if self.s.omap_lsm => {
                if let Some(id) = self.lookup(cid, oid)?
                    && self.w(id).on.flags & F_OMAP != 0
                    && first < last
                {
                    self.lsm_rm_range(id, first, last)?;
                }
            }
            TOp::OmapClear { cid, oid } if self.s.omap_lsm => {
                if let Some(id) = self.lookup(cid, oid)? {
                    if self.w(id).on.flags & F_OMAP != 0 {
                        self.lsm_clear(id);
                    }
                    // ObjectStore omap_clear also drops the omap header
                    if self.w(id).on.flags & F_HDR != 0 {
                        self.rm_val(id, Slot::Hdr, b"")?;
                    }
                }
            }
            TOp::OmapSetKeys { cid, oid, pairs } => {
                let id = self.lookup_or_create(cid, oid)?;
                for (k, v) in pairs {
                    self.put_val(id, Slot::Omap, k, v)?;
                }
                self.set_flag(id, F_OMAP);
            }
            TOp::OmapSetRun { cid, oid, run } => {
                let id = self.lookup_or_create(cid, oid)?;
                if self.run_ok(id, run)? {
                    self.stage_run(id, run);
                } else {
                    for (k, v) in run.view().iter() {
                        self.put_val(id, Slot::Omap, k, v)?;
                    }
                }
                self.set_flag(id, F_OMAP);
            }
            TOp::OmapRmKeys { cid, oid, keys } => {
                if let Some(id) = self.lookup(cid, oid)?
                    && self.w(id).on.flags & F_OMAP != 0
                {
                    self.rm_keys(id, keys)?;
                }
            }
            TOp::OmapRmKeyRange {
                cid,
                oid,
                first,
                last,
            } => {
                if let Some(id) = self.lookup(cid, oid)?
                    && self.w(id).on.flags & F_OMAP != 0
                    && first < last
                {
                    let (a, b) = (omap_key(id, first), omap_key(id, last));
                    // staged runs of this txn in the range become tree puts the range removal then drops
                    self.demote_range(id, &a, &b)?;
                    if self.w(id).on.flags & (F_OFRAG | F_OEXT) != 0 {
                        // fragments and data-block values (adr 0021 am. 46) are released key by key
                        for uk in self.omap_keys_in(a, b)? {
                            self.rm_val(id, Slot::Omap, &uk)?;
                        }
                    } else {
                        self.kdelrange(a, b);
                    }
                }
            }
            TOp::OmapClear { cid, oid } => {
                if let Some(id) = self.lookup(cid, oid)? {
                    let flags = self.w(id).on.flags;
                    if flags & F_OMAP != 0 {
                        self.drop_sruns(id);
                        let (a, b) = id_range(T_OMAP, id);
                        if flags & F_OEXT != 0 {
                            self.free_ext_vals(a.clone(), b.clone())?;
                        }
                        // the committed runs go with the keys (adr 0476)
                        self.kdelrange(a, b);
                        if flags & F_OFRAG != 0 {
                            let (a, b) = frag_range(id, FT_OMAP);
                            self.kdelrange(a, b);
                        }
                        let w = self.w(id);
                        w.on.flags &= !(F_OMAP | F_OFRAG | F_OEXT);
                        w.dirty_on = true;
                    }
                    // ObjectStore omap_clear also drops the omap header
                    if self.w(id).on.flags & F_HDR != 0 {
                        self.rm_val(id, Slot::Hdr, b"")?;
                    }
                }
            }
            TOp::OmapSetHeader { cid, oid, header } => {
                let id = self.lookup_or_create(cid, oid)?;
                if header.is_empty() {
                    if self.w(id).on.flags & F_HDR != 0 {
                        self.rm_val(id, Slot::Hdr, b"")?;
                    }
                } else {
                    self.put_val(id, Slot::Hdr, b"", header)?;
                }
            }
        }
        Ok(())
    }

    /// Bytes `[off, off+len)` (zero beyond the data), effective content.
    pub fn read_eff_bytes(&mut self, id: u64, off: u64, len: u64) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let bs = BLK as u64;
        let (b0, b1) = (off / bs, (off + len - 1) / bs);
        let d = self.eff_read(id, b0, b1 - b0 + 1)?;
        Ok(self.cut_read(d, (off - b0 * bs) as usize, len))
    }

    /// `d` = the whole blocks of a read, cut to `len` bytes from byte `o`; the crc of the whole blocks no longer describes a
    /// cut one.
    fn cut_read(&mut self, mut d: Vec<u8>, o: usize, len: u64) -> Vec<u8> {
        // block-aligned start (the common big read): just cut the tail, no copy
        if o > 0 {
            d.copy_within(o..o + len as usize, 0);
        }
        d.truncate(len as usize);
        if o > 0 || !len.is_multiple_of(BLK as u64) {
            self.read_crc = None; // the crc covers whole blocks only
        }
        d
    }

    /// [`Stage::read_eff_bytes`] of a plain object (no overlay, no inline value, not planning) whose device pieces `parts`
    /// ([`Stage::read_parts`]) the caller has resolved already: no second extent lookup.
    fn read_plain_bytes(
        &mut self,
        id: u64,
        off: u64,
        len: u64,
        parts: Option<Vec<Part>>,
    ) -> Result<Vec<u8>> {
        let bs = BLK as u64;
        let (b0, b1) = (off / bs, (off + len - 1) / bs);
        let l = (b1 - b0 + 1) as usize * BLK;
        let mut d: Vec<u8> = Vec::with_capacity(l);
        self.read_crc = None;
        self.read_committed_parts(
            id,
            b0,
            b1 - b0 + 1,
            parts,
            &mut d.spare_capacity_mut()[..l],
            None,
        )?;
        // SAFETY: read_committed_parts returned Ok, so it wrote all `l` bytes (device data or zeros).
        unsafe { d.set_len(l) };
        Ok(self.cut_read(d, (off - b0 * bs) as usize, len))
    }

    /// [`Self::read_eff_bytes`] as shared pieces in order (the content is their concatenation), each with the crc32c (seed
    /// `!0`) of exactly its bytes when known without a pass. Plain committed data (no compressed chunk, no inline value, no
    /// overlay of this txn) in pieces of [`SHARE_MIN_AVG`] or more on average: every whole device / prefetch buffer is
    /// handed over by reference, its block crcs computed in place and verified against the stored ones exactly as on the
    /// copy path (mismatch = `Eio`); a prefetch run covering a piece only partly is copied. Committed data that is all
    /// compressed chunks (reads of at least [`SHARE_MIN_AVG`]): one piece per chunk window by reference to the decoded
    /// chunk, crc from the chunk's logical crc. Anything else reads as before (one copied piece).
    pub fn read_eff_shared(
        &mut self,
        id: u64,
        off: u64,
        len: u64,
    ) -> Result<Vec<(Bytes, Option<u32>)>> {
        self.read_eff_shared_inner(id, off, len, false)
            .map(|read| read.parts)
    }

    /// Shared read with a placement-only block-CRC sidecar. This keeps the
    /// ordinary SEND path free of CRC-vector allocations.
    pub fn read_eff_shared_verified(&mut self, id: u64, off: u64, len: u64) -> Result<SharedRead> {
        self.read_eff_shared_inner(id, off, len, true)
    }

    fn read_eff_shared_inner(
        &mut self,
        id: u64,
        off: u64,
        len: u64,
        verified: bool,
    ) -> Result<SharedRead> {
        if len == 0 {
            return Ok(SharedRead {
                parts: Vec::new(),
                block_crcs: verified.then(Vec::new),
            });
        }
        let bs = BLK as u64;
        let (b0, n) = (off / bs, (off + len).div_ceil(bs) - off / bs);
        // pieces of `SHARE_MIN_AVG` on average need that many bytes in total: a smaller read skips the extent lookup unless
        // the shard's data cache holds something (a small read of cached data is served by reference, see below)
        let plain = !self.planning
            && (n as usize * BLK >= SHARE_MIN_AVG || self.s.dc.len() > 0)
            && self
                .objs
                .get(&id)
                .is_none_or(|w| w.runs.is_empty() && !w.no_ext() && w.on.flags & F_INLINE == 0);
        // `Some(_)` = the extents are resolved (the copy path below reuses them)
        let resolved = if plain {
            // A completed extent lookup with no runs proves plain sparse data;
            // retain that proof as an empty list, distinct from no lookup.
            Some(Some(self.read_parts(id, b0, n, true)?.unwrap_or_default()))
        } else {
            None
        };
        self.shared_from(id, off, len, verified, resolved)
    }

    /// The read of the probe [`HotProbe`] left for exactly this read (`len` as the probe was given it).
    pub(crate) fn read_eff_shared_hot(
        &mut self,
        h: HotProbe,
        verified: bool,
    ) -> Result<SharedRead> {
        let len = h.len.min(h.size - h.off);
        self.shared_from(h.id, h.off, len, verified, Some(Some(vec![h.part])))
    }

    /// [`Stage::read_eff_shared`] from the extents of the range (`resolved`: `Some(_)` = already looked up, see
    /// [`Stage::read_parts`]; `None` = not looked up, the range reads as one copied piece).
    fn shared_from(
        &mut self,
        id: u64,
        off: u64,
        len: u64,
        verified: bool,
        resolved: Option<Option<Vec<Part>>>,
    ) -> Result<SharedRead> {
        let bs = BLK as u64;
        let (b0, n) = (off / bs, (off + len).div_ceil(bs) - off / bs);
        // every part a compressed chunk window: the decoded chunks go out by reference (no copy into a result buffer)
        if let Some(Some(ps)) = &resolved
            // An empty extent list is sparse plain data, not compressed chunks.
            && !ps.is_empty()
            && ps.iter().all(|p| p.comp.is_some())
        {
            self.s.wait_durable(self.clk, id)?;
            self.read_crc = None;
            return self
                .read_comp_pieces(ps, b0, n, off, len)
                .map(|parts| SharedRead {
                    parts,
                    block_crcs: None,
                });
        }
        // by reference: big enough pieces, or one piece the data cache holds whole (the encoder copies a segment below
        // `msgr2::ZC_MIN` into the frame anyway: the reference saves the store's copy and its buffer, adr 0043 am. 17)
        let share = match &resolved {
            Some(Some(ps)) => {
                ps.iter().all(|p| p.comp.is_none())
                    && (ps.iter().map(|p| p.n as usize).sum::<usize>() * BLK
                        >= SHARE_MIN_AVG * ps.len()
                        || (ps.len() == 1 && self.s.dc.covers(ps[0].pba, ps[0].n)))
            }
            _ => false,
        };
        if !share {
            self.read_crc = None;
            let d = match resolved {
                Some(parts) => self.read_plain_bytes(id, off, len, parts)?,
                None => self.read_eff_bytes(id, off, len)?,
            };
            return Ok(SharedRead {
                parts: vec![(Bytes::from(d), self.read_crc)],
                block_crcs: None,
            });
        }
        let parts = resolved.flatten().expect("a shared read has its pieces");
        // A resolved hole has no device data to race. Preserve the readiness
        // reported by warm_data and the previous ordinary zero-read path.
        if !parts.is_empty() {
            self.s.wait_durable(self.clk, id)?;
        }
        let runs: Vec<(u64, u32, usize)> = parts
            .iter()
            .map(|p| (p.pba, p.n, (p.lblk - b0) as usize))
            .collect();
        let mut segs = Vec::with_capacity(parts.len());
        let got = self
            .s
            .read_runs_shared(self.clk, &runs, &mut segs, verified)?;
        let mut gi = 0usize;
        for p in &parts {
            for (i, &want) in p.crcs.iter().enumerate() {
                if got[gi] != want {
                    self.s.stats.crc_errors += 1;
                    return Err(ObjError::Eio(format!(
                        "checksum mismatch: onode {id} block {} at pba {}",
                        p.lblk + i as u64,
                        p.pba + i as u64
                    )));
                }
                gi += 1;
            }
        }
        // every block verified: the crc of each piece follows from its block crcs (a hole block: crc 0 under seed 0); the
        // pieces are cut to `[off, off+len)` here, a cut piece takes the crcs of its whole blocks and hashes only the
        // partial blocks at its ends (never the whole piece again)
        let o = (off - b0 * bs) as usize;
        let end = o + len as usize;
        // `[a, b)` of the piece at block `d` of `k` blocks inside the range, `None` = outside
        let inside = |d: usize, k: usize| {
            let a = o.saturating_sub(d * BLK).min(k * BLK);
            let b = end.saturating_sub(d * BLK).min(k * BLK);
            (a < b).then_some((a, b))
        };
        let mut block_crcs =
            (verified && o == 0).then(|| Vec::with_capacity(len.div_ceil(bs) as usize));
        let hole = |d: usize, k: usize, out: &mut Vec<_>, crcs: &mut Option<Vec<u32>>| {
            if let Some((a, b)) = inside(d, k) {
                if let Some(crcs) = crcs {
                    crcs.extend(std::iter::repeat_n(0, (b - a).div_ceil(BLK)));
                }
                out.push((
                    Bytes::from(vec![0u8; b - a]),
                    Some(crc::crc32c_zeros(!0, b - a)),
                ));
            }
        };
        segs.sort_unstable_by_key(|s| s.dst);
        // The device grid and receipt grid differ only for a shifted start.
        // Keep the verified full blocks alive while deriving the new metadata;
        // holes contribute CRC 0 without reading or allocating a payload.
        let shifted_crcs = if verified && o != 0 {
            let mut segment = 0;
            let blocks = (0..n as usize).map(|index| {
                while segment < segs.len()
                    && index >= segs[segment].dst + segs[segment].data.len() / BLK
                {
                    segment += 1;
                }
                if let Some(s) = segs.get(segment)
                    && index >= s.dst
                {
                    let relative = index - s.dst;
                    let bytes = &s.data[relative * BLK..(relative + 1) * BLK];
                    let crc = crc::crc32c_blocks(
                        0,
                        [(got[s.ci + relative], blk_seed(s.pba + relative as u64))],
                    );
                    crc::VerifiedBlock::Data(bytes, crc)
                } else {
                    crc::VerifiedBlock::Zeros
                }
            });
            let reblocked = crc::crc32c_reblock(blocks, o, len as usize)
                .ok_or_else(|| ObjError::Eio("invalid verified READ block geometry".into()))?;
            self.s.stats.placement_crc_reblocked_bytes += len;
            self.s.stats.placement_crc_hashed_bytes += reblocked.hashed_bytes as u64;
            Some(reblocked.crcs)
        } else {
            None
        };
        let mut out = Vec::with_capacity(2 * segs.len() + 1);
        let mut pos = 0usize;
        for s in segs {
            if s.dst > pos {
                hole(pos, s.dst - pos, &mut out, &mut block_crcs);
            }
            let k = s.data.len() / BLK;
            let block = |i: usize| (got[s.ci + i], blk_seed(s.pba + i as u64));
            if let Some((a, b)) = inside(s.dst, k) {
                if let Some(crcs) = block_crcs.as_mut() {
                    debug_assert_eq!(a % BLK, 0);
                    crcs.extend((a / BLK..b / BLK).map(|i| {
                        crc::crc32c_blocks(0, [(got[s.ci + i], blk_seed(s.pba + i as u64))])
                    }));
                    if !b.is_multiple_of(BLK) {
                        crcs.push(crc::crc32c(0, &s.data[b / BLK * BLK..b]));
                    }
                }
                let c = if (a, b) == (0, k * BLK) {
                    crc::crc32c_blocks(!0, (0..k).map(block))
                } else {
                    crc::crc32c_range(&s.data, block, a, b)
                };
                out.push((s.data.slice(a..b), Some(c)));
            }
            pos = s.dst + k;
        }
        if pos < n as usize {
            hole(pos, n as usize - pos, &mut out, &mut block_crcs);
        }
        let block_crcs = shifted_crcs.or(block_crcs);
        debug_assert!(
            block_crcs
                .as_ref()
                .is_none_or(|c| c.len() == len.div_ceil(bs) as usize)
        );
        Ok(SharedRead {
            parts: out,
            block_crcs,
        })
    }

    // ------------------------------------------------------------------ finish

    /// Pure shrink (adr 0021 am. 21): frees something and can add nothing; may use every reserve down to zero.
    fn pure_shrink(&self) -> bool {
        self.shrink && !self.grows
    }

    /// Values staged for data blocks (adr 0021 am. 46) that the overlay still references: one block run each (padded to
    /// whole blocks, crcs like any data block), the record becomes `V_EXT`. Free space too fragmented for one run: the
    /// value keeps a tree form instead.
    fn flush_ext_vals(&mut self) -> Result<()> {
        let pend = std::mem::take(&mut self.pending_ext);
        for (i, (mk, id, slot, val)) in pend.iter().enumerate() {
            let live = matches!(
                self.map.get(mk.as_slice()),
                Some(Some(v)) if v.len() == 9
                    && v[0] == V_PEND
                    && denc::le::rd_u32(v, 5) as usize == i
            );
            if !live {
                continue;
            }
            let n = val.len().div_ceil(BLK) as u32;
            let (pba, got) = self.alloc_upto(n)?;
            if got < n {
                self.s.sh.unreserve(pba, got);
                let k = mk[10..].to_vec();
                self.put_val_tree(*id, *slot, &k, mk.clone(), val);
                continue;
            }
            let mut buf = vec![0u8; n as usize * BLK];
            buf[..val.len()].copy_from_slice(val);
            let crcs = self.data_run(pba, &buf);
            self.kput(mk.clone(), vext_encode(val.len(), pba, &crcs[..n as usize]));
            self.sc.ids.push(*id);
            self.s.stats.ext_values += 1;
        }
        Ok(())
    }

    /// A data run of at most `want` blocks (`Shard::alloc_data`: the longest free run when no run of `want` is free, adr
    /// 0475 am. 3); waits only while nothing is allocatable now (`Busy`).
    fn alloc_upto(&mut self, want: u32) -> Result<(u64, u32)> {
        let mut stall = crate::sio::Stall::new("data allocation wait");
        loop {
            let c = if self.pure_shrink() {
                AllocClass::Priv
            } else if self.freeing {
                AllocClass::Sys
            } else {
                AllocClass::User
            };
            match self.s.sh.alloc_data(want, c) {
                Ok(x) => return Ok(x),
                Err(StoreError::Busy) => {
                    #[cfg(feature = "lab")]
                    let t0 = std::time::Instant::now();
                    self.s.backpressure_round(self.clk, &mut stall)?;
                    #[cfg(feature = "lab")]
                    crate::dbg::qwait_done(0, t0);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Small-object data in the tree (adr 0021 am. 14). Decides at flush time, on the final state of the object, whether
    /// its dirty runs become the value of the inline key instead of device blocks. True = fully handled (inline put /
    /// delete, nothing to allocate); false = regular flush follows (runs possibly extended by the promotion of an
    /// inline block that outgrew the threshold or got blocks written beyond block 0).
    fn flush_inline(
        &mut self,
        id: u64,
        runs: &mut BTreeMap<u64, super::dirty::Run<'_>>,
    ) -> Result<bool> {
        let cap = self.s.inline_max;
        let (fresh, flags, size) = {
            let w = self.w(id);
            // no committed extents: a new object, or an empty one (extents lie inside [0, size))
            (
                w.no_ext() || w.orig.is_some_and(|o| o.1 == 0),
                w.on.flags,
                w.on.size,
            )
        };
        let inline = flags & F_INLINE != 0;
        if !inline && !(cap > 0 && fresh) {
            return Ok(false);
        }
        // effect of the runs on block 0 and on the blocks behind it (holes there change nothing: no extents)
        let mut blk0: Option<Option<&[u8]>> = None;
        let mut beyond = false;
        for (s, r) in runs.iter() {
            match (*s, &r.data) {
                (0, Some(d)) => {
                    blk0 = Some(Some(&d[..BLK]));
                    beyond |= r.n > 1;
                }
                (0, None) => blk0 = Some(None),
                (_, Some(_)) => beyond = true,
                _ => {}
            }
        }
        let key = inl_key_arr(id);
        if cap > 0 && size <= cap as u64 && !beyond {
            match blk0 {
                Some(Some(b)) if size > 0 => {
                    self.kput(key.to_vec(), b[..size as usize].to_vec());
                    self.set_flag(id, F_INLINE);
                    self.s.stats.inline_writes += 1;
                }
                Some(_) if inline => {
                    // block 0 became a hole (or the object empty): no data left
                    self.kdel(key.to_vec());
                    let w = self.w(id);
                    w.on.flags &= !F_INLINE;
                    w.dirty_on = true;
                }
                _ => {}
            }
            runs.clear();
            return Ok(true);
        }
        if inline {
            // the object leaves the inline form: its block 0 moves to a device block (unless this txn rewrote it)
            if blk0.is_none() {
                let mut buf = vec![0u8; BLK];
                self.kget_with(&key, |v| {
                    if let Some(v) = v {
                        buf[..v.len().min(BLK)].copy_from_slice(&v[..v.len().min(BLK)]);
                    }
                })?;
                runs.insert(
                    0,
                    super::dirty::Run {
                        n: 1,
                        data: Some(crate::obj::dirty::Data::Owned(buf)),
                    },
                );
            }
            self.kdel(key.to_vec());
            let w = self.w(id);
            w.on.flags &= !F_INLINE;
            w.dirty_on = true;
            self.s.stats.inline_promotions += 1;
        }
        Ok(false)
    }

    /// Materialize a device run, or just its size/record shape during preflight: a view of the payload when the device
    /// writes from it, else one copy into a device buffer, reusing exact-grid receive CRCs or fusing CRC computation
    /// into the copy when unknown (deferrable memory of the DMA budget: it is
    /// held until the txn's write). The budget refused that buffer (adr 0175 am. 4): the run is staged as a deferred copy
    /// ([`CopyRun`]: crcs over the source; the payload slice, a heap copy only for bytes outside the txn's payloads),
    /// copied into in-flight IO memory right before its device write. Never refused, never restaged.
    fn data_run(&mut self, pba: u64, src: &[u8]) -> [u32; MAX_RUN as usize] {
        let n = src.len() / BLK;
        let mut crcs = [0u32; MAX_RUN as usize];
        if self.planning {
            self.planned.push(Extent {
                blk: pba,
                nblk: n as u32,
                crcs: vec![0; n],
            });
        } else {
            for (i, c) in crcs[..n].iter_mut().enumerate() {
                *c = blk_seed(pba + i as u64);
            }
            let buf = match self.data_ref(src, &mut crcs[..n]) {
                Some(b) => b,
                None => match self.s.sh.try_alloc_data(n) {
                    Some(mut buf) => {
                        self.s.stats.staged_data_bytes += src.len() as u64;
                        if self.reuse_payload_crcs(src, &mut crcs[..n]) {
                            buf.copy_from_slice(src);
                        } else {
                            buf.copy_from_slice_crc32c(src, BLK, &mut crcs[..n]);
                        }
                        buf
                    }
                    None => {
                        self.payload_crcs(src, &mut crcs[..n]);
                        let src = match crc::Payload::find(&self.payloads, src) {
                            Some((p, off)) => p.owner.slice(off..off + src.len()),
                            None => Bytes::copy_from_slice(src),
                        };
                        self.s.stats.deferred_copy_bytes += src.len() as u64;
                        self.copies.push(CopyRun {
                            blk: pba,
                            src,
                            crcs: crcs[..n].to_vec(),
                            tail: false,
                        });
                        return crcs;
                    }
                },
            };
            self.data_crcs.push(crcs[..n].to_vec());
            self.data.push((pba, buf));
        }
        crcs
    }

    /// `src` (whole blocks) lies in a payload buffer of the txn the device can write from by reference (adr 0061 am.
    /// 4): a view of it, and `crcs` (holding the block seeds) turned into the block crcs, from the receive pass's block
    /// crcs when `src` sits on their grid (no pass), else by one read-only crc pass. `None` = copy as usual.
    fn data_ref(&mut self, src: &[u8], crcs: &mut [u32]) -> Option<D::Buf> {
        let (p, off) = crc::Payload::find(&self.payloads, src)?;
        let owner = p.owner.slice(off..off + src.len());
        let buf = self.s.sh.view_buf(&owner)?;
        self.payload_crcs(src, crcs);
        self.s.stats.zc_data_bytes += src.len() as u64;
        Some(buf)
    }

    /// `crcs` (holding the block seeds) of `src` (whole blocks): from the receive pass's block crcs when `src` lies in a
    /// payload on their grid (no pass), else one read-only crc pass.
    fn payload_crcs(&mut self, src: &[u8], crcs: &mut [u32]) {
        if !self.reuse_payload_crcs(src, crcs) {
            for (c, b) in crcs.iter_mut().zip(src.as_chunks::<BLK>().0) {
                *c = crc::crc32c(*c, b);
            }
        }
    }

    /// Reseed exact-grid receive checksums; leave seeds untouched when none match.
    fn reuse_payload_crcs(&mut self, src: &[u8], crcs: &mut [u32]) -> bool {
        let known = crc::Payload::find(&self.payloads, src)
            .and_then(|(p, off)| p.blocks_at(off, crcs.len()));
        match known {
            Some(k) => {
                debug_assert!(
                    src.as_chunks::<BLK>()
                        .0
                        .iter()
                        .zip(k)
                        .all(|(b, &k)| crc::crc32c(0, b) == k),
                    "receive-pass block crcs do not match the bytes"
                );
                for (c, &k) in crcs.iter_mut().zip(k) {
                    *c = crc::reseed_4k(*c, k);
                }
                self.s.stats.crc_reused_bytes += src.len() as u64;
                true
            }
            None => false,
        }
    }

    /// One physical run, so allocation backpressure cannot discard a copied prefix.
    fn write_raw_one(&mut self, id: u64, lblk: u64, src: &[u8]) -> Result<u64> {
        let want = (src.len() / BLK)
            .min(MAX_RUN as usize)
            .min(self.s.max_xfer_blk) as u32;
        if let Some(got) = self.claim_run(id, lblk, &src[..want as usize * BLK]) {
            return Ok(lblk + u64::from(got));
        }
        let (pba, got) = self.alloc_upto(want)?;
        let copies = self.copies.len();
        let crcs = self.data_run(pba, &src[..got as usize * BLK]);
        // the run ends in the object's partial last block: the next append reads it (adr 0043, tail blocks)
        let size = self.w(id).on.size;
        if !self.planning
            && !size.is_multiple_of(BLK as u64)
            && lblk + u64::from(got) == blocks_for(size)
        {
            match self.copies.get_mut(copies) {
                Some(c) => c.tail = true,
                None => self.tails.push(self.data.len() as u32 - 1),
            }
        }
        self.kput(
            ext_key(id, lblk as u32),
            ext_encode(pba, &crcs[..got as usize]),
        );
        Ok(lblk + got as u64)
    }

    /// The run `src` (logical block `lblk`) starts at the first byte of a piece this shard wrote ahead (adr 0477): its
    /// blocks become the extent (a prefix of at most `src`), nothing is allocated or written. The bytes are the very same
    /// memory (the piece holds it), the crcs come from the payload like for a write by reference. `None` = no such piece
    /// (or a size probe): allocate and write as usual.
    fn claim_run(&mut self, id: u64, lblk: u64, src: &[u8]) -> Option<u32> {
        if self.planning {
            return None;
        }
        let (pre, pba, got) = self
            .s
            .sh
            .pre_claim(src.as_ptr() as usize, (src.len() / BLK) as u32)?;
        let src = &src[..got as usize * BLK];
        let mut crcs = [0u32; MAX_RUN as usize];
        let crcs = &mut crcs[..got as usize];
        for (i, c) in crcs.iter_mut().enumerate() {
            *c = blk_seed(pba + i as u64);
        }
        self.payload_crcs(src, crcs);
        self.kput(ext_key(id, lblk as u32), ext_encode(pba, crcs));
        self.pre.push(PreClaim {
            id: pre,
            blk: pba,
            nblk: got,
            crcs: crcs.to_vec(),
        });
        Some(got)
    }

    /// Try to store the full chunk `src` (logical block `lblk`) compressed: `false` = store it raw (ratio not met, no
    /// contiguous room, codec failure). Layout: `u32 comp_len`, payload, zero padding to whole blocks.
    fn write_chunk(&mut self, id: u64, lblk: u64, src: &[u8], cs: CompSpec) -> Result<bool> {
        if let Some(enc) = &self.encoding {
            debug_assert_eq!((enc.id, enc.lblk, enc.raw_bytes), (id, lblk, src.len()));
            return self.submit_encoding();
        }
        // windows of a cut chunk share its blocks through refcount records: a (legacy) store without them stores raw
        if !self.s.shared_ext {
            return Ok(false);
        }
        let raw_blks = src.len() / BLK;
        // nothing can meet required_ratio and save a block
        if crate::compress::kept_blocks(raw_blks, 0, cs.ratio_permille).is_none() {
            return Ok(false);
        }
        let t0 = std::time::Instant::now();
        if sample_incompressible(&mut self.s.codec, cs, src) {
            self.s.stats.comp_sampled_out += 1;
            self.s.stats.comp_ns += t0.elapsed().as_nanos() as u64;
            return Ok(false);
        }
        let mut cbuf = std::mem::take(&mut self.s.cbuf);
        cbuf.resize(4 + bound(src.len()), 0);
        let clen = self.s.codec.compress(cs.alg, src, &mut cbuf[4..]);
        self.s.stats.comp_ns += t0.elapsed().as_nanos() as u64;
        let kept = clen.and_then(|l| crate::compress::kept_blocks(raw_blks, l, cs.ratio_permille));
        let Some(phys) = kept else {
            self.s.stats.comp_rejected += 1;
            self.s.cbuf = cbuf;
            return Ok(false);
        };
        if !self.compression_at_start {
            // FEAT_COMPRESSION not durable yet: raw now, the store sets the bit and stages this txn again
            self.s.comp_wanted = true;
            self.s.cbuf = cbuf;
            return Ok(false);
        }
        let clen = clen.unwrap();
        if !self.planning {
            cbuf[..4].copy_from_slice(&(clen as u32).to_le_bytes());
            cbuf[4 + clen..phys * BLK].fill(0);
        }
        let meta = CompMeta::whole(
            cs.alg as u8,
            raw_blks as u8,
            if self.planning {
                0
            } else {
                crc::crc32c(0, src)
            },
        );
        self.encoding = Some(Encoding {
            id,
            lblk,
            bytes: cbuf,
            phys,
            raw_bytes: src.len(),
            meta,
        });
        self.submit_encoding()
    }

    fn submit_encoding(&mut self) -> Result<bool> {
        let enc = self.encoding.take().unwrap();
        let (id, lblk, phys) = (enc.id, enc.lblk, enc.phys);
        let r = self.alloc_upto(phys as u32);
        let (pba, got) = match r {
            Ok(x) => x,
            Err(ObjError::NoSpace) => {
                self.s.cbuf = enc.bytes;
                return Ok(false); // the raw write reports the real ENOSPC
            }
            Err(e) => {
                self.encoding = Some(enc);
                return Err(e);
            }
        };
        if got as usize != phys {
            self.s.sh.unreserve(pba, got); // no contiguous room for the whole chunk
            self.s.cbuf = enc.bytes;
            self.s.stats.comp_rejected += 1;
            return Ok(false);
        }
        let crcs = self.data_run(pba, &enc.bytes[..phys * BLK]);
        let crcs = &crcs[..phys];
        self.kput(
            ext_key(id, lblk as u32),
            ext_encode_c(pba, crcs, Some(enc.meta)),
        );
        self.s.cbuf = enc.bytes;
        self.s.stats.comp_ok += 1;
        self.set_flag(id, F_COMP);
        self.comp_acct(id, (phys * BLK) as i64, enc.raw_bytes as i64);
        Ok(true)
    }

    /// Plan exact metadata/extent sizes without device buffers. Success keeps address reservations
    /// in `Record::data` until the caller finishes checking; failure returns every reservation.
    pub fn plan(mut self, t: &'a OTxn) -> Result<Record> {
        self.planning = true;
        let result = self.apply(t).and_then(|()| self.finish_inner(0));
        if result.is_err() {
            for e in &self.planned {
                self.s.sh.unreserve(e.blk, e.nblk);
            }
        }
        let Built { txn, .. } = result?;
        debug_assert!(txn.data.is_empty());
        Ok(Record {
            lsn: self.s.sh.next_lsn(),
            ops: txn.ops,
            data: std::mem::take(&mut self.planned),
            frees: txn.frees,
        })
    }

    /// Resolve data, build the engine txn. On error every reservation is returned.
    pub fn finish(mut self, token: u64) -> Result<Built<D::Buf>> {
        match self.finish_inner(token) {
            Ok(b) => Ok(b),
            Err(e) => {
                // every reservation is backed by a staged data buffer (see `flush_runs`) or a claimed pre-write
                self.discard_data();
                Err(e)
            }
        }
    }

    fn finish_inner(&mut self, token: u64) -> Result<Built<D::Buf>> {
        self.finish_inner_budget(token, None)
    }

    pub fn finish_prepare(
        &mut self,
        token: u64,
        budget: Option<&mut super::budget::Budget>,
    ) -> Result<Built<D::Buf>> {
        self.cpu_yield = false;
        self.finish_inner_budget(token, budget)
    }

    pub fn discovered(&self) -> bool {
        self.discovered
    }

    pub fn discard_data(&mut self) {
        for (b, buf) in &self.data {
            self.s.sh.unreserve(*b, (buf.len() / BLK) as u32);
        }
        self.data.clear();
        for c in std::mem::take(&mut self.copies) {
            self.s.sh.unreserve(c.blk, (c.src.len() / BLK) as u32);
        }
        for c in std::mem::take(&mut self.pre) {
            self.s.sh.pre_unclaim(c.id);
        }
    }

    fn finish_inner_budget(
        &mut self,
        token: u64,
        mut budget: Option<&mut super::budget::Budget>,
    ) -> Result<Built<D::Buf>> {
        if !self.discovered {
            self.flush_ext_vals()?;
            self.objs.0.sort_unstable_by_key(|e| e.0);
            // Discover every extent/refcount/inline dependency before DMA copies, CRC or compression.
            // These are staged metadata mutations only: no visible state changes before submit.
            for i in 0..self.objs.0.len() {
                let id = self.objs.0[i].0;
                if self.objs.0[i].1.gone || self.objs.0[i].1.runs.is_empty() {
                    continue;
                }
                let mut runs = std::mem::take(&mut self.objs.0[i].1.runs.runs);
                let inline = self.flush_inline(id, &mut runs);
                self.objs.0[i].1.runs.runs = runs;
                if inline? {
                    self.objs.0[i].1.runs.runs.clear();
                    continue;
                }
                if self.w(id).no_ext() {
                    continue;
                }
                // Match the materializer's adjacent-run spans without joining/copying payloads.
                let mut cursor = 0;
                loop {
                    let (start, end, next) = {
                        let mut it = self.objs.0[i].1.runs.runs.range(cursor..);
                        let Some((&s, run)) = it.next() else {
                            break;
                        };
                        let (mut end, mut last) = (s + run.n, s);
                        if self.comp.is_some() && run.data.is_some() {
                            for (&rs, rr) in it {
                                if rs != end || rr.data.is_none() {
                                    break;
                                }
                                end = rs + rr.n;
                                last = rs;
                            }
                        }
                        (s, end, last + 1)
                    };
                    self.punch(id, start, end)?;
                    cursor = next;
                }
            }
            self.discovered = true;
        }
        while self.material_obj < self.objs.0.len() {
            let i = self.material_obj;
            let (id, w) = &self.objs.0[i];
            let next = if w.gone {
                None
            } else {
                w.runs
                    .runs
                    .range(..=self.material_pos)
                    .next_back()
                    .filter(|(s, r)| **s + r.n > self.material_pos)
                    .or_else(|| w.runs.runs.range(self.material_pos..).next())
                    .map(|(&s, r)| (s, r.n, r.data.is_some()))
            };
            let Some((start, n, data)) = next else {
                if !w.gone && w.runs.runs.values().any(|r| r.data.is_some()) {
                    self.sc.ids.push(*id);
                }
                self.material_obj += 1;
                self.material_pos = 0;
                self.material_span = None;
                continue;
            };
            let id = *id;
            self.material_pos = self.material_pos.max(start);
            if !data {
                self.material_pos = start + n;
                self.material_span = None;
                continue;
            }
            if budget.as_mut().is_some_and(|b| !b.take()) {
                self.cpu_yield = true;
                self.s.wb_why = "cpu slice";
                return Err(ObjError::WouldBlock);
            }
            if self.material_span.is_none() {
                let mut end = start + n;
                if self.comp.is_some() {
                    for (&rs, rr) in self.objs.0[i].1.runs.runs.range(start + 1..) {
                        if rs != end || rr.data.is_none() {
                            break;
                        }
                        end = rs + rr.n;
                    }
                }
                let comp = self.comp.is_some_and(|cs| {
                    cs.chunk_blocks().is_some() && (end - start) * BLK as u64 >= cs.min_bytes as u64
                });
                self.material_span = Some((end, comp));
            }
            let (end, comp) = self.material_span.unwrap();
            let pos = self.material_pos;
            // A full aligned chunk, or the head / tail piece between chunk boundaries and the span edge: every piece of at
            // least `min_bytes` is compressed like a BlueStore blob of that size (a write of 8..60 KiB saves space too).
            let (stop, chunk) = if comp {
                let cs = self.comp.unwrap();
                let c = cs
                    .chunk_blocks()
                    .expect("a compressing span has a chunk size");
                let next = pos.next_multiple_of(c);
                let stop = if next == pos {
                    (pos + c).min(end)
                } else {
                    next.min(end)
                };
                (stop, (stop - pos) * BLK as u64 >= cs.min_bytes as u64)
            } else {
                ((pos + MAX_RUN as u64).min(end), false)
            };
            // Loan the unchanged run map out of self so the source can be borrowed without a Bytes clone.
            let runs = std::mem::take(&mut self.objs.0[i].1.runs.runs);
            let first = runs.range(..=pos).next_back().unwrap();
            let direct = first.0 + first.1.n >= stop;
            let mut scratch = std::mem::take(&mut self.sc.vb);
            let src = if direct {
                &first.1.data.as_ref().unwrap()
                    [(pos - first.0) as usize * BLK..(stop - first.0) as usize * BLK]
            } else {
                scratch.clear();
                for (&s, run) in runs.range(*first.0..stop) {
                    let lo = pos.max(s);
                    let hi = stop.min(s + run.n);
                    if lo < hi {
                        scratch.extend_from_slice(
                            &run.data.as_ref().unwrap()
                                [(lo - s) as usize * BLK..(hi - s) as usize * BLK],
                        );
                    }
                }
                scratch.as_slice()
            };
            let result = if chunk && self.material_raw_until.is_none() {
                match self.write_chunk(id, pos, src, self.comp.unwrap()) {
                    Ok(true) => Ok(stop),
                    Ok(false) => {
                        self.material_raw_until = Some(stop);
                        self.write_raw_one(id, pos, src)
                    }
                    Err(e) => Err(e),
                }
            } else {
                self.write_raw_one(id, pos, src)
            };
            self.sc.vb = scratch;
            self.objs.0[i].1.runs.runs = runs;
            self.material_pos = result?;
            if self
                .material_raw_until
                .is_some_and(|until| self.material_pos >= until)
            {
                self.material_raw_until = None;
            }
            if self.material_pos >= end {
                self.material_span = None;
            }
        }
        if let Some((id, a, b, max)) = self.reformat_check
            && self.span_stats(id, a, b)?.frags >= max as u64
        {
            return Err(ObjError::Stale); // the new allocation is not less fragmented: keep the old layout
        }
        // onodes + collection counters
        // per collection: objects, bytes, compressed physical bytes, compressed logical bytes
        type Delta = (u64, i64, i64, i64, i64);
        let mut delta: Vec<Delta> = Vec::new();
        fn dent(d: &mut Vec<Delta>, c: u64) -> &mut Delta {
            match d.iter().position(|e| e.0 == c) {
                Some(i) => &mut d[i],
                None => {
                    d.push((c, 0, 0, 0, 0));
                    d.last_mut().unwrap()
                }
            }
        }
        for i in 0..self.objs.0.len() {
            let (id, w) = (self.objs.0[i].0, &self.objs.0[i].1);
            let old = w
                .orig
                .filter(|o| o.2)
                .map(|o| (o.0, o.1, w.orig_comp.0, w.orig_comp.1));
            let new =
                (!w.gone && w.counted).then_some((w.coll, w.on.size, w.on.comp, w.on.comp_orig));
            if old != new {
                if let Some((c, sz, cp, co)) = old {
                    let d = dent(&mut delta, c);
                    d.1 -= 1;
                    d.2 -= sz as i64;
                    d.3 -= cp as i64;
                    d.4 -= co as i64;
                }
                if let Some((c, sz, cp, co)) = new {
                    let d = dent(&mut delta, c);
                    d.1 += 1;
                    d.2 += sz as i64;
                    d.3 += cp as i64;
                    d.4 += co as i64;
                }
            }
            if !w.gone && (w.dirty_on || w.created()) {
                let (k, v) = (onode_key(id), w.on.encode());
                self.kput(k, v);
            }
        }
        for (c, dn, db, dc, dco) in delta {
            if let Some(cid) = self.sc.coll_ids.get(&c).copied()
                && let Some(e) = self.sc.colls.get_mut(&cid)
                && let Some(i) = e.info.as_mut()
            {
                i.nobj += dn;
                i.nbytes += db;
                i.comp += dc;
                i.comp_orig += dco;
                e.dirty = true;
            }
        }
        let puts: Vec<(Vec<u8>, Option<Vec<u8>>)> = self
            .sc
            .colls
            .iter()
            .filter(|(_, e)| e.dirty)
            .map(|(c, e)| (coll_key(c), e.info.as_ref().map(|i| i.encode())))
            .collect();
        for (k, v) in puts {
            match v {
                Some(v) => self.kput(k, v),
                None => self.kdel(k),
            }
        }
        let mut txn: Txn<D::Buf> = Txn::new(token);
        txn.shrink = self.pure_shrink();
        txn.sys = self.freeing || txn.shrink;
        let odel = &self.sc.odel;
        txn.ops.reserve_exact(
            odel.len() + self.dels.len() + self.map.len() + self.oops.len() + self.sruns.len(),
        );
        // blind removals first (ascending): a later range removal or put of the txn applies over them
        txn.ops.extend((0..odel.len()).map(|i| {
            let k = odel.get(i);
            let mut v = crate::vpool::take(k.len());
            v.extend_from_slice(k);
            Op::Del(v)
        }));
        let mut oi = 0;
        for (a, b) in std::mem::take(&mut self.dels) {
            txn.ops.push(Op::DelRange(a, b));
        }
        for (k, v) in std::mem::take(&mut self.map) {
            txn.ops.push(match v {
                Some(v) => Op::Put(k, v),
                None => {
                    // a blind removal already removes it (both ascending: one merge pass)
                    while oi < odel.len() && odel.get(oi) < k.as_slice() {
                        oi += 1;
                    }
                    if oi < odel.len() && odel.get(oi) == k.as_slice() {
                        crate::vpool::give(k);
                        continue;
                    }
                    Op::Del(k)
                }
            });
        }
        self.sc.odel.clear();
        // omap LSM ops (adr 0610) in txn order; runs stay the last ops (adr 0476)
        let omap_base = txn.ops.len();
        txn.ops
            .extend(std::mem::take(&mut self.oops).into_iter().map(Op::Omap));
        for (id, b) in std::mem::take(&mut self.sruns) {
            if let Some(r) = b.finish(id) {
                txn.ops.push(Op::RunPut(r));
            }
        }
        txn.data = std::mem::take(&mut self.data);
        txn.data_crcs = std::mem::take(&mut self.data_crcs);
        txn.copies = std::mem::take(&mut self.copies);
        txn.tails = std::mem::take(&mut self.tails);
        txn.pre = std::mem::take(&mut self.pre);
        txn.frees = std::mem::take(&mut self.frees);
        if !self.point_ranges.is_empty() && !self.s.sh.point_ranges_fit(&mut txn, &self.planned) {
            // The original range fits independently of its record's later operations. Restore
            // every expanded range in its original position if expansion would exceed the WAL
            // ring's existing hard limit; normal submit checks all original constraints.
            for (index, range) in std::mem::take(&mut self.point_ranges) {
                txn.ops[omap_base + index] = Op::Omap(range);
            }
        }
        // pieces of this txn's payloads it did not claim are written ahead for nothing: no later txn takes them
        if !self.planning {
            for p in &self.payloads {
                let lo = p.owner.as_ptr() as usize;
                self.s.sh.pre_release_within(lo, lo + p.owner.len());
            }
        }
        Ok(Built {
            txn,
            needs_compression: self.s.comp_wanted && !self.compression_at_start,
        })
    }
}

/// Deep-scrub result of one object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScrubResult {
    pub size: u64,
    /// crc32c (Ceph raw chaining, caller seed) over the object bytes `[0, size)`.
    pub data_crc: u32,
    /// Logical blocks whose stored checksum did not match (the data crc then covers the bad bytes).
    pub bad_blocks: Vec<u64>,
    pub omap_keys: u64,
    /// User key + value bytes of the omap entries (adr 0614).
    pub omap_bytes: u64,
    /// crc32c over header and entries (each as `le32 len, bytes`) in key order; local definition.
    pub omap_crc: u32,
}

impl<D: BlockDev, C: Clock> Stage<'_, '_, D, C> {
    pub fn scrub_obj(&mut self, id: u64, seed: u32) -> Result<ScrubResult> {
        let size = self.obj_size(id);
        let nblk = blocks_for(size);
        let mut crc = seed;
        let mut bad = Vec::new();
        let mut b = 0u64;
        while b < nblk {
            let n = (nblk - b).min(256);
            let len = n as usize * BLK;
            let mut buf: Vec<u8> = Vec::with_capacity(len);
            self.read_committed(
                id,
                b,
                n,
                &mut buf.spare_capacity_mut()[..len],
                Some(&mut bad),
            )?;
            // SAFETY: read_committed returned Ok: every byte written (device data, zeros, failed chunks zeroed).
            unsafe { buf.set_len(len) };
            let lo = (b * BLK as u64) as usize;
            let hi = ((b + n) * BLK as u64).min(size) as usize;
            crc = crc::crc32c(crc, &buf[..hi - lo]);
            b += n;
        }
        let mut oc = 0u32;
        let (mut nk, mut nbytes) = (0u64, 0u64);
        let flags = self.w(id).on.flags;
        let enc =
            |c: u32, x: &[u8]| crc::crc32c(crc::crc32c(c, &(x.len() as u32).to_le_bytes()), x);
        if flags & F_HDR != 0
            && let Some(h) = self.get_val(id, Slot::Hdr, b"")?
        {
            oc = enc(oc, &h);
        }
        if flags & F_OMAP != 0 {
            let mut from = Vec::new();
            loop {
                let (kv, more) = self.scan_vals(id, Slot::Omap, &from, 1024)?;
                for (k, v) in &kv {
                    oc = enc(enc(oc, k), v);
                    nk += 1;
                    nbytes += (k.len() + v.len()) as u64;
                }
                if !more {
                    break;
                }
                from = kv.last().unwrap().0.clone();
                from.push(0);
            }
        }
        Ok(ScrubResult {
            size,
            data_crc: crc,
            bad_blocks: bad,
            omap_keys: nk,
            omap_bytes: nbytes,
            omap_crc: oc,
        })
    }
}

#[cfg(test)]
mod perf_tests {
    use super::*;
    use crate::dev::{SimClock, SimConfig, SimDev, SimDisk};
    use crate::layout::{MkfsParams, mkfs};
    use crate::obj::{Store, StoreCfg};
    use denc::types::{Hobject, PgT, ShardId, SnapId, SpgT};

    fn rig() -> (Store<SimDev, SimClock>, CollT, Ghobject) {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        mkfs(
            &mut disk.queue(),
            &mut SimClock::default(),
            &MkfsParams {
                shards: 1,
                wal_blocks: 1024,
                meta_pct: 8,
                align_blocks: 1,
                node_size: 8192,
                ..Default::default()
            },
        )
        .unwrap();
        let (mut st, _) =
            Store::mount(|| disk.queue(), SimClock::default(), StoreCfg::default()).unwrap();
        let c = CollT::Pg(SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        });
        let o = Ghobject::new(
            Hobject::new(b"overlay", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        );
        let mut t = OTxn::new();
        t.mkcoll(c);
        t.touch(c, &o);
        st.commit(&t).unwrap();
        (st, c, o)
    }

    #[test]
    #[ignore = "local debug staging measurement"]
    fn unaligned_overlay_bench() {
        let (mut store, c, o) = rig();
        let data = vec![0x73; 4 << 20];
        for off in [0, 1] {
            let mut txn = OTxn::new();
            txn.write(c, &o, off, &data);
            let start = std::time::Instant::now();
            let mut owned = 0;
            for _ in 0..100 {
                let mut stage = Stage::new(&mut store.shards[0], &mut store.clk);
                stage.apply(&txn).unwrap();
                owned = stage
                    .objs
                    .0
                    .iter()
                    .flat_map(|(_, w)| w.runs.runs.values())
                    .filter_map(|r| match &r.data {
                        Some(crate::obj::dirty::Data::Owned(v)) => Some(v.len()),
                        _ => None,
                    })
                    .sum::<usize>();
                std::hint::black_box(&stage);
            }
            println!(
                "4 MiB write offset {off}: {} owned overlay bytes, {:.0} ns/stage",
                owned,
                start.elapsed().as_nanos() as f64 / 100.0
            );
        }
    }

    #[test]
    fn unaligned_write_borrows_the_middle_and_preserves_boundary_overlays() {
        let (mut store, c, o) = rig();
        let data = vec![0x73; 4 << 20];
        let mut txn = OTxn::new();
        txn.write(c, &o, 1, &data);
        let mut stage = Stage::new(&mut store.shards[0], &mut store.clk);
        stage.apply(&txn).unwrap();
        let id = stage.lookup(&c, &o).unwrap().unwrap();
        let owned: usize = stage
            .w(id)
            .runs
            .runs
            .values()
            .filter_map(|r| match &r.data {
                Some(crate::obj::dirty::Data::Owned(v)) => Some(v.len()),
                _ => None,
            })
            .sum();
        assert_eq!(owned, 2 * BLK, "only the boundary blocks may be owned");
        let middle = stage
            .w(id)
            .runs
            .runs
            .get(&1)
            .unwrap()
            .data
            .as_ref()
            .unwrap();
        assert!(matches!(middle, crate::obj::dirty::Data::Borrowed(_)));
        assert_eq!(middle.as_ptr(), data[BLK - 1..].as_ptr());
        let bytes = stage.read_eff_bytes(id, 0, data.len() as u64 + 2).unwrap();
        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..1 + data.len()], &data);
        assert_eq!(bytes[data.len() + 1], 0);
        drop(stage);

        for (off, len) in [(7, 2), (0, 1), (1, 8192), (4096, 4097), (4095, 2)] {
            let base = vec![0x55; 3 * BLK];
            let patch = vec![0xa3; len];
            let mut first = OTxn::new();
            first.write(c, &o, 0, &base);
            let mut second = OTxn::new();
            second.write(c, &o, off, &patch);
            let mut stage = Stage::new(&mut store.shards[0], &mut store.clk);
            stage.apply(&first).unwrap();
            stage.apply(&second).unwrap();
            let id = stage.lookup(&c, &o).unwrap().unwrap();
            let mut expected = base.clone();
            expected[off as usize..off as usize + len].copy_from_slice(&patch);
            assert_eq!(
                stage.read_eff_bytes(id, 0, expected.len() as u64).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn aligned_owned_clone_input_is_moved_into_overlay() {
        let (mut store, c, o) = rig();
        let data = vec![0x91; 256 * BLK];
        let base = data.as_ptr();
        let mut stage = Stage::new(&mut store.shards[0], &mut store.clk);
        let id = stage.lookup(&c, &o).unwrap().unwrap();
        stage.write_data(id, BLK as u64, data).unwrap();
        let run = stage.w(id).runs.runs.get(&1).unwrap();
        assert_eq!(run.data.as_ref().unwrap().as_ptr(), base);
        assert_eq!(run.n, 256);
        let read = stage.read_eff_bytes(id, 0, 257 * BLK as u64).unwrap();
        assert_eq!(&read[..BLK], &[0u8; BLK]);
        assert!(read[BLK..].iter().all(|b| *b == 0x91));
    }

    #[test]
    fn unaligned_owned_clone_input_retains_middle_and_owns_only_boundaries() {
        let (mut store, c, o) = rig();
        let data = vec![0x91; 256 * BLK];
        let base = data.as_ptr();
        let mut stage = Stage::new(&mut store.shards[0], &mut store.clk);
        let id = stage.lookup(&c, &o).unwrap().unwrap();
        stage.write_data(id, 1, data).unwrap();
        let runs = &stage.w(id).runs.runs;
        let owned: usize = runs
            .values()
            .filter_map(|r| match &r.data {
                Some(super::super::dirty::Data::Owned(v)) => Some(v.len()),
                _ => None,
            })
            .sum();
        assert_eq!(owned, 2 * BLK);
        let middle = runs[&1].data.as_ref().unwrap();
        assert_eq!(middle.as_ptr(), base.wrapping_add(BLK - 1));
        assert_eq!(middle.len(), 255 * BLK);
        let read = stage.read_eff_bytes(id, 0, (256 * BLK + 2) as u64).unwrap();
        assert_eq!(read[0], 0);
        assert!(read[1..256 * BLK + 1].iter().all(|b| *b == 0x91));
        assert_eq!(read[256 * BLK + 1], 0);
    }
}

impl<D: BlockDev, C: Clock> Stage<'_, '_, D, C> {
    pub fn scan_colls(&mut self) -> Result<Vec<CollT>> {
        let kv = self.kscan(&[T_COLL], &[T_COLL + 1], usize::MAX)?;
        kv.iter()
            .map(|(k, _)| {
                decode_coll_key(k).ok_or_else(|| ObjError::Eio("bad collection key".into()))
            })
            .collect()
    }

    pub fn list(
        &mut self,
        cid: &CollT,
        begin: &Ghobject,
        end: Option<&Ghobject>,
        max: usize,
    ) -> Result<(Vec<Ghobject>, Option<Ghobject>)> {
        let cn = self.coll_id(cid)?;
        // an executor request's run lists at most one CPU slice (adr 0021 S8); its next run continues at `begin`
        let sliced = self.s.list_sliced();
        if sliced && self.s.pass_listed >= SCAN_SLICE_ENTRIES {
            self.s.scan_slice();
            return Err(ObjError::WouldBlock);
        }
        let a = name_key(cn, &sort_key(begin));
        let b = match end {
            Some(e) => name_key(cn, &sort_key(e)),
            None => name_end(cn).to_vec(),
        };
        let mut objs = self.scan_names(&a, &b, max.saturating_add(1), decode_sort_key)?;
        // long names (am. 30): the same range in the `L` index; the first `max + 1` of the union are among the first
        // `max + 1` of each part, so merging the two cut lists by the hobject order is exact
        if self.long_maybe()? {
            let la = long_key_of(cn, begin);
            let lb = match end {
                Some(e) => long_key_of(cn, e),
                None => long_end(cn).to_vec(),
            };
            let lobjs = self.scan_names(&la, &lb, max.saturating_add(1), decode_long_key)?;
            if !lobjs.is_empty() {
                objs.extend(lobjs);
                objs.sort_by_cached_key(sort_key);
            }
        }
        if sliced {
            self.s.pass_listed += objs.len();
        }
        let next = (objs.len() > max).then(|| objs.swap_remove(max));
        objs.truncate(max);
        Ok((objs, next))
    }

    /// Up to `max` objects of the name index range `[a, b)` (`N` or `L` keys, decoded by `dec`), ascending. A read stage
    /// (no staged ops) decodes straight from the leaves: no copy of the keys, no merge buffer.
    fn scan_names(
        &mut self,
        a: &[u8],
        b: &[u8],
        max: usize,
        dec: fn(&[u8]) -> Option<Ghobject>,
    ) -> Result<Vec<Ghobject>> {
        let bad = || ObjError::Eio("bad name key".into());
        if !self.map.is_empty() || !self.dels.is_empty() {
            let kv = self.kscan_as(a, b, max, true)?;
            return kv
                .iter()
                .map(|(k, _)| dec(&k[9..]).ok_or_else(bad))
                .collect();
        }
        let mut out = Vec::with_capacity(max.min(1024));
        if a >= b || max == 0 {
            return Ok(out);
        }
        let mut cur = ScanCursor::new(a, b).listing();
        cur.ra_win = (max / 32).clamp(1, SCAN_RA_MAX) as u32;
        let mut ok = true;
        while out.len() < max {
            let done =
                self.s.tscan(
                    self.clk,
                    &mut cur,
                    max - out.len(),
                    &mut |k, _| match dec(&k[9..]) {
                        Some(o) => out.push(o),
                        None => ok = false,
                    },
                )?;
            if !ok {
                return Err(bad());
            }
            if done {
                break;
            }
        }
        Ok(out)
    }
}

fn ext_push(sc: &mut Scratch, lblk: u64, v: &[u8]) {
    let off = sc.ext_raw.len() as u32;
    sc.ext_raw.extend_from_slice(v);
    sc.exts.push(ExtIdx {
        lblk,
        off,
        len: v.len() as u32,
    });
}

/// Resolve ordered committed ranges against the transaction's ordered write/hole overlay.
fn effective_ranges(ranges: Vec<(u64, u64)>, dirty: Option<&Dirty<'_>>) -> Vec<(u64, u64)> {
    // Each overlay run can split one original interval and add one data interval.
    // Both inputs are disjoint and ordered, so neither sorting nor rescanning is needed.
    let mut out: Vec<(u64, u64)> =
        Vec::with_capacity(ranges.len() + 2 * dirty.map_or(0, |d| d.runs.len()));
    let mut append = |start, end| {
        if start == end {
            return;
        }
        match out.last_mut() {
            Some((s, n)) if *s + *n == start => *n = end - *s,
            _ => out.push((start, end - start)),
        }
    };
    let mut base = ranges.into_iter().map(|(s, n)| (s, s + n));
    let mut head = base.next();
    for (&start, run) in dirty.into_iter().flat_map(|d| &d.runs) {
        let end = start + run.n;
        // Preserve the committed ranges preceding this overlay, including a cut prefix.
        while let Some((s, e)) = head {
            if s >= start {
                break;
            }
            append(s, e.min(start));
            if e <= start {
                head = base.next();
            } else {
                head = Some((start, e));
                break;
            }
        }
        // The overlay replaces committed data inside its interval, including holes.
        while let Some((s, e)) = head {
            if s >= end {
                break;
            }
            if e <= end {
                head = base.next();
            } else {
                head = Some((end, e));
                break;
            }
        }
        if run.data.is_some() {
            append(start, end);
        }
    }
    for (s, e) in head.into_iter().chain(base) {
        append(s, e);
    }
    out
}

/// Idle recompaction of cut compressed chunks (adr 0533).
mod rc;
pub(crate) use rc::RcOut;

/// Merge runs that touch each other and both hold data.
#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn main_key_into_matches_the_key_builders() {
        let mut b = vec![9u8; 40]; // reused dirty buffer
        for (id, k) in [
            (0u64, &b""[..]),
            (7, b"_"),
            (u64::MAX, b"snapset"),
            (1 << 40, b"0000000010.00000000000000001234"),
        ] {
            Slot::Attr.main_key_into(id, k, &mut b);
            assert_eq!(b, attr_key(id, k));
            Slot::Omap.main_key_into(id, k, &mut b);
            assert_eq!(b, omap_key(id, k));
            Slot::Hdr.main_key_into(id, k, &mut b);
            assert_eq!(b, hdr_key(id));
            assert_eq!(Slot::Attr.main_key(id, k), attr_key(id, k));
        }
    }
}

#[cfg(test)]
mod rm_batch_tests {
    use super::*;
    use crate::dev::{SimClock, SimConfig, SimDev, SimDisk};
    use crate::layout::{MkfsParams, mkfs};
    use crate::obj::{Store, StoreCfg};
    use denc::types::{Hobject, PgT, ShardId, SnapId, SpgT};

    type St = Store<SimDev, SimClock>;

    fn key(i: u64) -> Vec<u8> {
        format!("k{i:04}").into_bytes()
    }

    /// One shard, collection `c` with object `o` holding `key(0..n)` in the tree.
    fn rig(n: u64) -> (St, CollT, Ghobject) {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let p = MkfsParams {
            shards: 1,
            wal_blocks: 1024,
            meta_pct: 8,
            align_blocks: 1,
            node_size: 8192,
            ..Default::default()
        };
        mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
        let (mut st, _) =
            Store::mount(|| disk.queue(), SimClock::default(), StoreCfg::default()).unwrap();
        let c = CollT::Pg(SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        });
        let o = Ghobject::new(
            Hobject::new(b"batch", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        );
        let ks: Vec<Vec<u8>> = (0..n).map(key).collect();
        let mut t = OTxn::new();
        t.mkcoll(c);
        t.touch(c, &o);
        for k in &ks {
            t.omap_set(c, &o, k, b"value");
        }
        st.commit(&t).unwrap();
        (st, c, o)
    }

    fn rm(c: CollT, o: &Ghobject, keys: &[u64]) -> TOp<'static> {
        TOp::OmapRmKeys {
            cid: c,
            oid: o.clone(),
            keys: keys.iter().map(|&i| key(i).into()).collect(),
        }
    }

    /// The record's ops on the omap keys of `o` (the onode and other records left out).
    fn omap_ops(st: &mut St, c: &CollT, o: &Ghobject, t: &OTxn) -> Vec<Op> {
        let mut s = Stage::new(&mut st.shards[0], &mut st.clk);
        let id = s.lookup(c, o).unwrap().unwrap();
        let rec = s.plan(t).unwrap();
        rec.ops
            .into_iter()
            .filter(|op| match op {
                Op::Put(k, _) | Op::Del(k) => omap_id(k) == Some(id),
                _ => false,
            })
            .collect()
    }

    fn mk(st: &mut St, c: &CollT, o: &Ghobject, i: u64) -> Vec<u8> {
        let id = Stage::new(&mut st.shards[0], &mut st.clk)
            .lookup(c, o)
            .unwrap()
            .unwrap();
        omap_key(id, &key(i))
    }

    /// A batch in any order, with repeats and absent keys, stages as the same ascending list of blind removals.
    #[test]
    fn a_removal_batch_stages_as_one_sorted_list() {
        let (mut st, c, o) = rig(50);
        let want: Vec<Op> = [5u64, 10, 30, 77]
            .iter()
            .map(|&i| Op::Del(mk(&mut st, &c, &o, i)))
            .collect();
        for keys in [
            &[5u64, 10, 30, 77][..],
            &[77, 30, 10, 5],
            &[30, 5, 30, 77, 5, 10, 10],
        ] {
            let mut t = OTxn::new();
            t.push(rm(c, &o, keys));
            assert_eq!(omap_ops(&mut st, &c, &o, &t), want, "keys {keys:?}");
        }
        // two batches of the txn, the second below and between the first: still one ascending list
        let mut t = OTxn::new();
        t.push(rm(c, &o, &[30, 77]));
        t.push(rm(c, &o, &[5, 10]));
        assert_eq!(omap_ops(&mut st, &c, &o, &t), want);
        let mut t = OTxn::new();
        t.push(rm(c, &o, &[5, 77]));
        t.push(rm(c, &o, &[30, 10, 5]));
        assert_eq!(omap_ops(&mut st, &c, &o, &t), want);
    }

    /// Keys the txn touched before (put, removed, range-removed) are removed in the txn's own view, after its blind
    /// removals; reads of the txn see every removal; the committed omap holds exactly the rest.
    #[test]
    fn touched_keys_of_a_batch_follow_the_txn() {
        let (mut st, c, o) = rig(50);
        let mut t = OTxn::new();
        t.push(rm(c, &o, &[1, 3]));
        t.omap_set(c, &o, b"k0001", b"again");
        t.push(rm(c, &o, &[1, 2]));
        t.push(TOp::OmapRmKeyRange {
            cid: c,
            oid: o.clone(),
            first: key(20).into(),
            last: key(25).into(),
        });
        t.push(rm(c, &o, &[22, 30]));
        // blind removals first (ascending), then the txn's own view: key 22 (in the staged range) is removed after the
        // range op; key 1 (put again after its blind removal, then removed) needs no second removal
        let want: Vec<Op> = [1u64, 2, 3, 30, 22]
            .iter()
            .map(|&i| Op::Del(mk(&mut st, &c, &o, i)))
            .collect();
        assert_eq!(omap_ops(&mut st, &c, &o, &t), want);
        {
            let mut s = Stage::new(&mut st.shards[0], &mut st.clk);
            let id = s.lookup(&c, &o).unwrap().unwrap();
            s.apply(&t).unwrap();
            for i in [1u64, 2, 3, 20, 22, 24, 30] {
                assert_eq!(s.get_val(id, Slot::Omap, &key(i)).unwrap(), None, "key {i}");
            }
            for i in [0u64, 4, 19, 25, 49] {
                assert_eq!(
                    s.get_val(id, Slot::Omap, &key(i)).unwrap().as_deref(),
                    Some(&b"value"[..]),
                    "key {i}"
                );
            }
            let (kv, more) = s.scan_vals(id, Slot::Omap, b"", 100).unwrap();
            assert!(!more);
            let got: Vec<Vec<u8>> = kv.into_iter().map(|(k, _)| k).collect();
            let left: Vec<Vec<u8>> = (0..50u64)
                .filter(|i| ![1, 2, 3, 30].contains(i) && !(20..25).contains(i))
                .map(key)
                .collect();
            assert_eq!(got, left);
        }
        st.commit(&t).unwrap();
        let n = 50 - 4 - 5;
        let sc = st.scrub(&c, &o, 0).unwrap();
        assert_eq!((sc.omap_keys, sc.omap_bytes), (n, n * (5 + 5)));
    }

    /// The sorted key list against a set model: random ascending batches appended or merged below / between earlier ones.
    #[test]
    fn key_list_matches_a_set() {
        let mut rng = crate::rng::Rng::new(7);
        for _ in 0..200 {
            let mut l = KeyList::default();
            let mut m = std::collections::BTreeSet::new();
            for _ in 0..rng.range(1, 8) {
                let mut b: Vec<Vec<u8>> = (0..rng.range(0, 30))
                    .map(|_| {
                        (0..rng.range(0, 4))
                            .map(|_| b'a' + rng.below(4) as u8)
                            .collect()
                    })
                    .filter(|k| !m.contains(k))
                    .collect();
                b.sort();
                b.dedup();
                let mut o = KeyList::default();
                for k in &b {
                    o.push(k);
                }
                l.merge(&o);
                m.extend(b);
                assert_eq!(l.len(), m.len());
                for (i, k) in m.iter().enumerate() {
                    assert_eq!(l.get(i), k.as_slice());
                }
                for _ in 0..20 {
                    let p: Vec<u8> = (0..rng.range(0, 4))
                        .map(|_| b'a' + rng.below(5) as u8)
                        .collect();
                    let q: Vec<u8> = (0..rng.range(0, 4))
                        .map(|_| b'a' + rng.below(5) as u8)
                        .collect();
                    assert_eq!(l.contains(&p), m.contains(&p));
                    assert_eq!(
                        l.any_in(&p, &q),
                        p < q && m.range(p.clone()..q.clone()).next().is_some()
                    );
                }
            }
        }
    }
}

/// Value records the object layer never writes (corrupt or foreign tree data) end in `Eio` on every read path: media
/// corruption must not panic the OSD core.
#[cfg(test)]
mod bad_value_record_tests {
    use super::*;
    use crate::dev::{SimClock, SimConfig, SimDev, SimDisk};
    use crate::layout::{MkfsParams, mkfs};
    use crate::obj::{Store, StoreCfg};
    use denc::types::{Hobject, PgT, ShardId, SnapId, SpgT};

    fn rig_with(cfg: StoreCfg) -> (Store<SimDev, SimClock>, CollT, Ghobject, u64) {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        mkfs(
            &mut disk.queue(),
            &mut SimClock::default(),
            &MkfsParams {
                shards: 1,
                wal_blocks: 1024,
                meta_pct: 8,
                align_blocks: 1,
                node_size: 8192,
                ..Default::default()
            },
        )
        .unwrap();
        let (mut st, _) = Store::mount(|| disk.queue(), SimClock::default(), cfg).unwrap();
        let c = CollT::Pg(SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        });
        let o = Ghobject::new(
            Hobject::new(b"onode", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        );
        let mut t = OTxn::new();
        t.mkcoll(c);
        t.touch(c, &o);
        st.commit(&t).unwrap();
        let id = Stage::new(&mut st.shards[0], &mut st.clk)
            .lookup(&c, &o)
            .unwrap()
            .unwrap();
        (st, c, o, id)
    }

    fn rig() -> (Store<SimDev, SimClock>, CollT, Ghobject, u64) {
        rig_with(StoreCfg::default())
    }

    /// Run the store until nothing is queued, in flight or checkpointing.
    fn pump<D: BlockDev, C: Clock>(st: &mut Store<D, C>) {
        for _ in 0..10_000 {
            st.poll(&mut Vec::new()).unwrap();
            if st.quiet() {
                return;
            }
            st.idle();
        }
        panic!("store did not go quiet");
    }

    /// Commit one raw tree record: a value the object layer would never write.
    fn raw_put<D: BlockDev, C: Clock>(st: &mut Store<D, C>, mk: Vec<u8>, raw: Vec<u8>) {
        let mut txn: Txn<D::Buf> = Txn::new(0);
        txn.ops.push(Op::Put(mk, raw));
        loop {
            match st.shards[0].sh.submit(txn) {
                Ok(_) => break,
                Err((StoreError::Busy | StoreError::WalFull | StoreError::Miss, t)) => {
                    txn = t;
                    pump(st);
                }
                Err((e, _)) => panic!("raw put: {e:?}"),
            }
        }
        pump(st);
    }

    /// A `V_CINL` record too short to name its class: point get and omap listing report `Eio`, never an index panic.
    #[test]
    fn a_one_byte_compressed_value_is_eio_on_get_and_listing() {
        let (mut st, _, _, id) = rig();
        let k = b"k".to_vec();
        raw_put(&mut st, Slot::Omap.main_key(id, &k), vec![V_CINL]);
        let r = Stage::new(&mut st.shards[0], &mut st.clk).get_val(id, Slot::Omap, &k);
        assert!(matches!(r, Err(ObjError::Eio(_))), "{r:?}");
        let r = Stage::new(&mut st.shards[0], &mut st.clk).scan_omap_enc(
            id,
            b"",
            b"",
            16,
            1 << 20,
            true,
            0,
        );
        assert!(matches!(r, Err(ObjError::Eio(_))), "{r:?}");
    }

    /// A `V_PEND` record (stage-internal, never stored) naming no staged value, or one of another length: `Eio`.
    #[test]
    fn a_pending_value_record_without_its_value_is_eio() {
        let (mut st, _, _, id) = rig();
        let k = b"k".to_vec();
        let mut raw = vec![V_PEND];
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.extend_from_slice(&9u32.to_le_bytes());
        raw_put(&mut st, Slot::Omap.main_key(id, &k), raw.clone());
        let r = Stage::new(&mut st.shards[0], &mut st.clk).get_val(id, Slot::Omap, &k);
        assert!(matches!(r, Err(ObjError::Eio(_))), "{r:?}");
        // in range, but the record's length is not the staged value's
        let mut s = Stage::new(&mut st.shards[0], &mut st.clk);
        let mk = Slot::Omap.main_key(id, &k);
        s.pending_ext
            .push((mk.clone(), id, Slot::Omap, vec![1, 2, 3]));
        raw[1..5].copy_from_slice(&2u32.to_le_bytes());
        raw[5..9].copy_from_slice(&0u32.to_le_bytes());
        s.kput(mk, raw);
        let r = s.get_val(id, Slot::Omap, &k);
        assert!(matches!(r, Err(ObjError::Eio(_))), "{r:?}");
    }

    /// With a dictionary of the value's class in place, a value too short to save a whole record stays plain: the saving
    /// threshold never underflows on values below 16 B.
    #[test]
    fn a_short_value_of_a_compressed_class_stays_plain() {
        let mut cfg = StoreCfg::default();
        cfg.shard.val_comp_min = 8;
        let (mut st, c, o, id) = rig_with(cfg);
        // `DICT_SAMPLES` values of one class train its dictionary (the first value byte is the class), the next one
        // takes the compressed form: the class then has a dictionary the short value would be tried against
        let mut long = Vec::new();
        let mut keys = Vec::new();
        for i in 0..=DICT_SAMPLES {
            let mut v = vec![b'x'];
            v.extend_from_slice(format!("entry {i:04}").as_bytes());
            v.resize(300, b'.');
            long.push(v);
            keys.push(format!("long{i:03}").into_bytes());
        }
        // a value of the same class that cannot save 16 B (8 bytes) stays plain
        let short = vec![b'x'; 8];
        let mut t = OTxn::new();
        for (k, v) in keys.iter().zip(&long) {
            t.omap_set(c, &o, k, v);
        }
        t.omap_set(c, &o, b"short", &short);
        st.commit(&t).unwrap();
        let raw = |st: &mut Store<SimDev, SimClock>, k: &[u8]| {
            Stage::new(&mut st.shards[0], &mut st.clk)
                .kget(&Slot::Omap.main_key(id, k))
                .unwrap()
                .unwrap()
        };
        assert_eq!(
            raw(&mut st, keys.last().unwrap()).first(),
            Some(&V_CINL),
            "the class dictionary exists"
        );
        assert_eq!(raw(&mut st, b"short").first(), Some(&V_INLINE));
        let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        let got = st.omap_get(&c, &o, &refs).unwrap();
        for (k, v) in keys.iter().zip(&long) {
            assert_eq!(&got[k.as_slice()], v);
        }
        assert_eq!(
            st.omap_get(&c, &o, &[b"short"]).unwrap()[b"short".as_slice()],
            short
        );
    }
}

/// The txn build reserves room for every op it emits.
#[cfg(test)]
mod txn_build_tests {
    use super::*;
    use crate::dev::{SimClock, SimConfig, SimDisk};
    use crate::layout::{MkfsParams, mkfs};
    use crate::obj::{Store, StoreCfg};

    /// A txn emitting omap LSM ops after the reservation reallocated its op vector once: the reservation missed them.
    #[test]
    fn a_txn_reserves_room_for_every_op() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        mkfs(
            &mut disk.queue(),
            &mut SimClock::default(),
            &MkfsParams {
                shards: 1,
                wal_blocks: 1024,
                align_blocks: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let (mut st, _) =
            Store::mount(|| disk.queue(), SimClock::default(), StoreCfg::default()).unwrap();
        let mut s = Stage::new(&mut st.shards[0], &mut st.clk);
        s.kput(b"a".to_vec(), vec![V_INLINE, 1]);
        s.kput(b"b".to_vec(), vec![V_INLINE, 2]);
        s.dels.push((b"c".to_vec(), b"d".to_vec()));
        for _ in 0..2 {
            s.oops.push(OOp::Range {
                id: 1,
                first: Bytes::new(),
                end: None,
            });
        }
        let built = s.finish(1).unwrap();
        assert_eq!(built.txn.ops.len(), 5);
        assert_eq!(
            built.txn.ops.capacity(),
            built.txn.ops.len(),
            "the reservation missed ops pushed after it: the vector reallocated"
        );
    }
}

#[cfg(test)]
mod effective_range_tests {
    use super::*;

    #[test]
    fn effective_ranges_fragmented_overlay_has_linear_allocation_bytes() {
        for count in [128, 1024] {
            let base = vec![(0, count * 4)];
            let mut dirty = Dirty::default();
            for block in 0..count {
                dirty.hole(block * 4 + 1, 1);
            }
            let mut result = Vec::new();
            let allocated = crate::test_alloc::allocated_bytes(|| {
                result = effective_ranges(base, Some(&dirty));
            });
            eprintln!("effective_ranges holes={count} allocation_bytes={allocated}");
            assert_eq!(result.len() as u64, count + 1);
            assert!(
                allocated <= (count as usize + 1) * 64,
                "range planning requested {allocated} bytes for {count} one-block holes"
            );
            for block in 0..count * 4 {
                let present = result
                    .iter()
                    .any(|&(start, n)| start <= block && block < start + n);
                assert_eq!(present, block % 4 != 1, "block {block}");
            }
        }
    }

    #[test]
    fn effective_ranges_matches_dense_presence_model() {
        let mut rng = crate::rng::Rng::new(0x19284);
        for _ in 0..256 {
            let mut base = Vec::new();
            let mut want = [false; 128];
            for block in 0..128u64 {
                if rng.next_u64().is_multiple_of(3) {
                    base.push((block, 1));
                    want[block as usize] = true;
                }
            }
            let mut dirty = Dirty::default();
            for _ in 0..64 {
                let start = (rng.next_u64() % 128) as usize;
                let end = (start + 1 + (rng.next_u64() % 20) as usize).min(128);
                let data = rng.next_u64().is_multiple_of(2);
                dirty.set(
                    start as u64,
                    (end - start) as u64,
                    data.then(|| vec![0x63; (end - start) * BLK]),
                );
                want[start..end].fill(data);
            }
            let got = effective_ranges(base, Some(&dirty));
            assert!(got.windows(2).all(|w| w[0].0 + w[0].1 < w[1].0));
            for (block, &expected) in want.iter().enumerate() {
                assert_eq!(
                    got.iter()
                        .any(|&(s, n)| s <= block as u64 && (block as u64) < s + n),
                    expected,
                    "block {block}: {got:?}"
                );
            }
        }
    }
}
