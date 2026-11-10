// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Immutable sorted run: on-disk format, resident metadata, builder and chunk / page decoding (adr 0610 (2), (5)).
//!
//! Data: chunks (the write and allocation unit, target [`super::CHUNK_TARGET`]), each starting on a block boundary
//! and zero padded to whole [`BLK`] pages. A chunk payload is one stream of entries in ascending `(id, key)` order:
//! `varint id | varint klen | varint vtag | key | value` with `vtag = 0` for a point tombstone, else `vlen + 1`.
//! Entries may straddle page boundaries (no padding inside a chunk). Reads are page granular: every page has its own
//! crc32c (seed [`codec::blk_seed`] of the page's block, over the whole padded page) and the resident index holds,
//! per page in which an entry starts, the first such entry's key and byte offset and the packed key of the last entry
//! starting in the page ([`PageStart`]). A cold point get reads one page; only when the probed key's packed form equals
//! that of an entry straddling the page end does it read the following pages too, in the same read (a key past the
//! straddling entry is absent without a read).
//! Crcs live in the resident metadata, not in the chunk, so a stale chunk at the same address fails too.
//!
//! Meta extent (one write after all chunks): little endian
//! `magic u64 | run id u64 | lsn_lo u64 | lsn_hi u64 | chunks u32 | starts u32 | pages u32 | ranges u32 |
//! bloom words u32 | entries u64 | tombstones u64`, then per chunk `blk u64 | nblk u32 | len u32 | n u32 | tombs u32 |
//! bloom_off u32 | bloom_nw u32 | st_off u32 | st_n u32 | crc_off u32 | last id u64 | last klen u32 | last`, then per
//! page start `page u32 | off u16 | id u64 | klen u32 | key | last id u64 | last key prefix u64` (the packed last key),
//! then one crc u32 per page, then per range tombstone `id u64 | flen u32 | first | has_end u8 | elen u32 | end`, then
//! the bloom words (u64 each). The payload is zero padded; the last 16 bytes of the extent are the trailer
//! `payload len u32 | payload crc u32 (seed blk_seed(meta blk)) | magic u32 | crc32c of the previous 12 bytes`.
//! The manifest record of the run carries the payload crc as well (a stale meta extent fails against it).

use super::{Gk, Place, RangeT, Val, bloom, cmp_gk, key_prefix, ranges_find};
use crate::codec::{self, Dec, Enc};
use crate::{BLK, StoreError};
use bytes::Bytes;
use std::cmp::Ordering;
use std::sync::Arc;

const META_MAGIC: u64 = u64::from_le_bytes(*b"OLSMRUN3");
const TRAILER_MAGIC: u32 = u32::from_le_bytes(*b"OLTR");
const TRAILER: usize = 16;

/// Where a flush or merge writes its blocks: extents leased by the owner (the allocator stays owner-only).
pub trait BlockSink {
    /// Lease `nblk` contiguous blocks.
    fn alloc(&mut self, nblk: u32) -> Result<u64, StoreError>;
    /// Write `data` (whole blocks) at leased block `blk`; `crcs` = the per-block crcs of `data`
    /// ([`crate::codec::blk_crc`], computed by the builder anyway: the store records them for the extent without a second
    /// pass). Durable once [`BlockSink::sync`] returned.
    fn write(&mut self, blk: u64, data: Vec<u8>, crcs: &[u32]) -> Result<(), StoreError>;
    /// Wait until every write issued so far is durable.
    fn sync(&mut self) -> Result<(), StoreError>;
    /// Blocks of the largest contiguous extent the sink can still lease (adr 0610 am. 5): the builder seals a chunk
    /// before it would need more than this. Default: no limit below [`super::CHUNK_TARGET`].
    fn room(&self) -> u32 {
        super::CHUNK_MAX
    }
    /// A chunk of `nblk` blocks was sealed (counter hook; the lease admits chunks shorter than [`super::CHUNK_MAX`]).
    fn chunk(&mut self, _nblk: u32) {}
}

/// Read access to run blocks (any sub-range of a written extent). A cache front may answer [`StoreError::Miss`]
/// (read queued, retry after wake).
pub trait ChunkRead {
    fn read(&mut self, blk: u64, nblk: u32) -> Result<Bytes, StoreError>;
    /// Enable batched listing demand reads and next-fence hints. Default: legacy serial reads.
    fn scan_prefetch(&self) -> bool {
        false
    }
    /// Number of logical next fences to consider once per consumed chunk. Default: one.
    /// Foreground shard configuration accepts 1 through 16; cache and device budgets may decline any hint.
    fn scan_prefetch_chunks(&self) -> usize {
        1
    }
    /// Best-effort nonblocking hint for one future run chunk. Never changes demand read semantics.
    /// Blocking mount/fsck readers and lab backends ignore hints by default.
    fn prefetch(&mut self, _blk: u64, _nblk: u32) {}
    /// [`ChunkRead::read`] and whether every page of the result already passed its crc check in an earlier read
    /// (a cache front keeps the marks of [`ChunkRead::checked`]). Default: never.
    fn read_checked(&mut self, blk: u64, nblk: u32) -> Result<(Bytes, bool), StoreError> {
        self.read(blk, nblk).map(|b| (b, false))
    }
    /// The pages `[blk, blk + nblk)` just read passed their crc check. Default: not remembered.
    fn checked(&mut self, _blk: u64, _nblk: u32) {}
}

fn corrupt(what: &str) -> StoreError {
    StoreError::Corrupt(format!("olsm: {what}"))
}

#[inline]
fn put_var(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

#[inline]
fn var_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

#[inline]
fn get_var(b: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let x = *b.get(*pos)?;
        *pos += 1;
        v |= ((x & 0x7f) as u64) << shift;
        if x & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

/// Encoded size of one entry.
#[inline]
pub fn entry_len(id: u64, key: &[u8], val: Option<&[u8]>) -> usize {
    let vtag = val.map_or(0, |v| v.len() as u64 + 1);
    var_len(id) + var_len(key.len() as u64) + var_len(vtag) + key.len() + val.map_or(0, |v| v.len())
}

/// The first entry starting in a page of a chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageStart {
    /// Page index inside the chunk.
    pub page: u32,
    /// Byte offset of the entry inside the page.
    pub off: u16,
    pub id: u64,
    pub key: Bytes,
    /// [`pack`] of the last entry starting in the page (the one that may straddle the page end).
    pub last: u128,
}

impl PageStart {
    fn pos(&self) -> usize {
        self.page as usize * BLK + self.off as usize
    }
}

/// Resident index entry of one chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fence {
    pub first_id: u64,
    pub first: Bytes,
    pub last_id: u64,
    pub last: Bytes,
    pub blk: u64,
    pub nblk: u32,
    /// Payload bytes.
    pub len: u32,
    /// Entries and point tombstones in the chunk.
    pub n: u32,
    pub tombs: u32,
    /// The chunk's bloom filter: `bloom[off..off + nw]` of the run.
    pub bloom_off: u32,
    pub bloom_nw: u32,
    /// The chunk's page starts: `starts[st_off..st_off + st_n]` of the run.
    pub st_off: u32,
    pub st_n: u32,
    /// The chunk's page crcs: `page_crcs[crc_off..crc_off + nblk]` of the run.
    pub crc_off: u32,
}

impl Fence {
    /// `first <= (id, key)`: with `last >= (id, key)` known, the chunk spans it.
    fn starts_by(&self, id: u64, key: &[u8]) -> bool {
        cmp_gk(self.first_id, &self.first, id, key) != Ordering::Greater
    }
}

/// `(id, first 8 key bytes zero-padded)` as one integer: a smaller packed value means a smaller position; equal
/// values need the full key comparison.
#[inline]
fn pack(id: u64, key: &[u8]) -> u128 {
    (id as u128) << 64 | key_prefix(key) as u128
}

/// The crc of every 4 KiB page of `data` stored from block `blk`.
fn page_crcs(blk: u64, data: &[u8]) -> impl Iterator<Item = u32> + '_ {
    data.chunks(BLK)
        .enumerate()
        .map(move |(k, pg)| codec::blk_crc(blk + k as u64, pg))
}

/// Resident metadata of one run (fence index, page starts and crcs, range tombstones, bloom words; adr 0175 charged
/// by [`RunMeta::ram`]). The decoded meta extent lives in a shared, immutable [`RunBody`]: a GC prefix keeps an
/// untouched input as a residual with a new place only, so its copy costs a reference, not the metadata size
/// (doc/perf/latency-stall-20261107.md).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunMeta {
    pub id: u64,
    pub lsn_lo: u64,
    pub lsn_hi: u64,
    body: Arc<RunBody>,
    pub meta_blk: u64,
    pub meta_nblk: u32,
    pub meta_crc: u32,
    /// Manifest position (from the run's manifest record; not in the meta extent).
    pub place: Place,
}

/// The decoded meta extent of a run; immutable once the run is finished or loaded.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RunBody {
    pub fences: Vec<Fence>,
    /// Packed last key of every chunk, parallel to `fences` ([`pack`]): the chunk search reads this array only and
    /// compares full keys only on a prefix tie. Derived, not in the meta extent.
    lasts: Vec<u128>,
    /// Inclusive prefix sums of chunk entries (`n`: puts and point tombstones), derived with `lasts`. Never encoded.
    entry_prefix: Vec<u64>,
    pub starts: Vec<PageStart>,
    pub page_crcs: Vec<u32>,
    /// Sorted, disjoint.
    pub ranges: Vec<RangeT>,
    pub bloom: Vec<u64>,
    pub entries: u64,
    pub tombs: u64,
}

impl RunMeta {
    /// Both describe the same decoded metadata allocation (a residual kept by reference).
    #[cfg(test)]
    pub fn shares_body(&self, other: &RunMeta) -> bool {
        Arc::ptr_eq(&self.body, &other.body)
    }
}

impl std::ops::Deref for RunMeta {
    type Target = RunBody;
    fn deref(&self) -> &RunBody {
        &self.body
    }
}

impl RunBody {
    fn push_fence(&mut self, f: Fence) {
        self.lasts.push(pack(f.last_id, &f.last));
        self.entry_prefix.push(
            self.entry_prefix
                .last()
                .copied()
                .unwrap_or(0)
                .saturating_add(u64::from(f.n)),
        );
        self.fences.push(f);
    }
}

impl RunMeta {
    /// Payload bytes of all chunks (size class input of the merge policy).
    pub fn data_bytes(&self) -> u64 {
        self.fences.iter().map(|f| f.len as u64).sum()
    }
    /// Device blocks owned by the run (chunks + meta).
    pub fn blocks(&self) -> u64 {
        self.fences.iter().map(|f| f.nblk as u64).sum::<u64>() + self.meta_nblk as u64
    }
    /// Resident RAM.
    pub fn ram(&self) -> usize {
        size_of::<RunMeta>()
            + self.bloom.len() * 8
            + self.lasts.len() * 16
            + self.entry_prefix.capacity() * size_of::<u64>()
            + self.page_crcs.len() * 4
            + self
                .fences
                .iter()
                .map(|f| size_of::<Fence>() + f.last.len())
                .sum::<usize>()
            + self
                .starts
                .iter()
                .map(|s| size_of::<PageStart>() + s.key.len())
                .sum::<usize>()
            + self
                .ranges
                .iter()
                .map(|r| {
                    size_of::<RangeT>() + r.first.len() + r.end.as_ref().map_or(0, |e| e.len())
                })
                .sum::<usize>()
    }
    /// Index of the first chunk whose last key is `>= (id, key)` (the chunk a seek to `(id, key)` starts in).
    pub fn seek_chunk(&self, id: u64, key: &[u8]) -> usize {
        debug_assert_eq!(self.lasts.len(), self.fences.len());
        let q = pack(id, key);
        let (mut lo, mut hi) = (0, self.lasts.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            let below = match self.lasts[mid].cmp(&q) {
                Ordering::Equal => {
                    let f = &self.fences[mid];
                    cmp_gk(f.last_id, &f.last, id, key) == Ordering::Less
                }
                o => o == Ordering::Less,
            };
            if below {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
    /// Upper bound on the entries (puts and point tombstones) a listing of `[first, end)` of one object visits in this
    /// run, capped at `cap`. It bounds the live keys of the range and the enumeration work of a point removal alike: a
    /// span of point tombstones costs a scan although it holds no live key. Both boundaries include their whole
    /// chunk, so entries of other objects may overestimate. Fence metadata alone answers two binary searches and a
    /// prefix subtraction: no chunk access or allocation. A saturated prefix returns `cap` rather than undercounting.
    pub(super) fn range_entry_upper_bound(
        &self,
        id: u64,
        first: &[u8],
        end: &[u8],
        cap: u64,
    ) -> u64 {
        if first >= end || cap == 0 {
            return 0;
        }
        debug_assert_eq!(self.entry_prefix.len(), self.fences.len());
        let lo = self.seek_chunk(id, first);
        let hi = self
            .fences
            .partition_point(|f| cmp_gk(f.first_id, &f.first, id, end) == Ordering::Less);
        if lo >= hi {
            return 0;
        }
        let total = self.entry_prefix[hi - 1];
        if total == u64::MAX {
            return cap;
        }
        let before = lo.checked_sub(1).map_or(0, |i| self.entry_prefix[i]);
        (total - before).min(cap)
    }
    /// The chunk that may hold `(id, key)`.
    pub fn find_chunk(&self, id: u64, key: &[u8]) -> Option<usize> {
        let i = self.seek_chunk(id, key);
        // `seek_chunk` found the first chunk with `last >= (id, key)`
        (i < self.fences.len() && self.fences[i].starts_by(id, key)).then_some(i)
    }
    pub fn chunk_bloom(&self, i: usize) -> &[u64] {
        let f = &self.fences[i];
        &self.bloom[f.bloom_off as usize..(f.bloom_off + f.bloom_nw) as usize]
    }
    pub fn chunk_starts(&self, i: usize) -> &[PageStart] {
        let f = &self.fences[i];
        &self.starts[f.st_off as usize..(f.st_off + f.st_n) as usize]
    }
    pub fn chunk_crcs(&self, i: usize) -> &[u32] {
        let f = &self.fences[i];
        &self.page_crcs[f.crc_off as usize..f.crc_off as usize + f.nblk as usize]
    }
    /// Index (within chunk `i`'s starts) of the last page start `<= (id, key)`, 0 if none.
    pub fn start_for(&self, i: usize, id: u64, key: &[u8]) -> usize {
        let st = self.chunk_starts(i);
        st.partition_point(|s| cmp_gk(s.id, &s.key, id, key) != Ordering::Greater)
            .saturating_sub(1)
    }
    /// Range tombstone of this run covering `(id, key)`.
    pub fn range_cover(&self, id: u64, key: &[u8]) -> Option<&RangeT> {
        ranges_find(&self.ranges, id, key)
    }
    /// Key span `(first, last)` of the run's entries (`None` for a run of range tombstones only).
    pub fn span(&self) -> (Option<Gk>, Option<Gk>) {
        (
            self.fences.first().map(|f| Gk {
                id: f.first_id,
                key: f.first.clone(),
            }),
            self.fences.last().map(|f| Gk {
                id: f.last_id,
                key: f.last.clone(),
            }),
        )
    }
    /// Data and meta extents `(blk, nblk)`.
    pub fn extents(&self) -> impl Iterator<Item = (u64, u32)> + '_ {
        self.fences
            .iter()
            .map(|f| (f.blk, f.nblk))
            .chain(std::iter::once((self.meta_blk, self.meta_nblk)))
    }
}

#[derive(Clone, Copy, Debug)]
struct Ent {
    id: u64,
    koff: u32,
    klen: u32,
    voff: u32,
    /// `u32::MAX` = point tombstone.
    vlen: u32,
}

/// One parsed entry header at `p`: `(id, key range, value range or None)` and the end offset; `None` if the entry is
/// not completely inside `b`.
#[inline]
fn parse_ent(b: &[u8], p: usize) -> Option<(u64, usize, usize, Option<usize>, usize)> {
    let mut q = p;
    let id = get_var(b, &mut q)?;
    let klen = get_var(b, &mut q)? as usize;
    let vtag = get_var(b, &mut q)? as usize;
    let vl = vtag.saturating_sub(1);
    let end = q.checked_add(klen)?.checked_add(vl)?;
    (end <= b.len()).then_some((id, q, klen, (vtag != 0).then_some(vl), end))
}

/// Decoded entries of a contiguous part of a chunk; keys and values are slices of the read buffer.
#[derive(Debug, Clone)]
pub struct Chunk {
    buf: Bytes,
    ents: Vec<Ent>,
}

/// Verify the crcs of pages `first..first + n` of chunk `i` against `blocks`.
fn verify_pages(run: &RunMeta, i: usize, first: usize, blocks: &[u8]) -> Result<(), StoreError> {
    let f = &run.fences[i];
    let crcs = run.chunk_crcs(i);
    if !blocks.len().is_multiple_of(BLK) || first + blocks.len() / BLK > crcs.len() {
        return Err(corrupt("page read length"));
    }
    for (k, pg) in blocks.chunks(BLK).enumerate() {
        let b = f.blk + (first + k) as u64;
        if codec::blk_crc(b, pg) != crcs[first + k] {
            return Err(corrupt(&format!("page crc mismatch at blk {b}")));
        }
    }
    Ok(())
}

/// Pages `first..first + n` of chunk `i`, crcs verified unless the reader answers them as checked before.
fn read_pages(
    rd: &mut impl ChunkRead,
    run: &RunMeta,
    i: usize,
    first: usize,
    n: u32,
) -> Result<Bytes, StoreError> {
    let blk = run.fences[i].blk + first as u64;
    let (b, ok) = rd.read_checked(blk, n)?;
    if !ok {
        verify_pages(run, i, first, &b)?;
        rd.checked(blk, n);
    }
    Ok(b)
}

impl Chunk {
    /// Parse the entries of `buf[from..to]` up to and including the first one at or past `stop` (`(id, key)`): a
    /// bounded cursor ends on that entry and never looks further, so decoding the rest of the chunk is wasted work.
    /// `true` = every entry up to `to` was parsed.
    fn parse_until(
        buf: Bytes,
        from: usize,
        to: usize,
        stop: Option<(u64, &[u8])>,
    ) -> Result<(Chunk, bool), StoreError> {
        let mut ents = Vec::new();
        let mut p = from;
        let b = &buf[..to];
        while p < to {
            let (id, ko, kl, v, end) = parse_ent(b, p).ok_or_else(|| corrupt("chunk entry"))?;
            ents.push(Ent {
                id,
                koff: ko as u32,
                klen: kl as u32,
                voff: (ko + kl) as u32,
                vlen: v.map_or(u32::MAX, |v| v as u32),
            });
            p = end;
            if stop
                .is_some_and(|(sid, skey)| cmp_gk(id, &b[ko..ko + kl], sid, skey) != Ordering::Less)
            {
                break;
            }
        }
        let complete = p >= to;
        Ok((Chunk { buf, ents }, complete))
    }
    pub fn len(&self) -> usize {
        self.ents.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ents.is_empty()
    }
    #[inline]
    pub fn id(&self, i: usize) -> u64 {
        self.ents[i].id
    }
    #[inline]
    pub fn key(&self, i: usize) -> &[u8] {
        let e = &self.ents[i];
        &self.buf[e.koff as usize..(e.koff + e.klen) as usize]
    }
    pub fn key_bytes(&self, i: usize) -> Bytes {
        let e = &self.ents[i];
        self.buf.slice(e.koff as usize..(e.koff + e.klen) as usize)
    }
    #[inline]
    pub fn is_tomb(&self, i: usize) -> bool {
        self.ents[i].vlen == u32::MAX
    }
    pub fn val_slice(&self, i: usize) -> Option<&[u8]> {
        let e = &self.ents[i];
        (e.vlen != u32::MAX).then(|| &self.buf[e.voff as usize..(e.voff + e.vlen) as usize])
    }
    pub fn val(&self, i: usize) -> Val {
        let e = &self.ents[i];
        (e.vlen != u32::MAX).then(|| self.buf.slice(e.voff as usize..(e.voff + e.vlen) as usize))
    }
    /// First index with `(id, key) >= target` (`excl`: `>`).
    pub fn seek(&self, id: u64, key: &[u8], excl: bool) -> usize {
        self.ents.partition_point(|e| {
            let c = cmp_gk(
                e.id,
                &self.buf[e.koff as usize..(e.koff + e.klen) as usize],
                id,
                key,
            );
            c == Ordering::Less || (excl && c == Ordering::Equal)
        })
    }
}

/// Read and decode all of chunk `i` of `run` (merge input), verifying every page crc and the entry count.
pub fn load_chunk(rd: &mut impl ChunkRead, run: &RunMeta, i: usize) -> Result<Chunk, StoreError> {
    load_chunk_until(rd, run, i, None)
}

/// [`load_chunk`] for a bounded cursor: every page crc is verified, entries are decoded only up to the first one at
/// or past `stop` ([`Chunk::parse_until`]); the entry count is checked when the whole chunk was decoded.
pub fn load_chunk_until(
    rd: &mut impl ChunkRead,
    run: &RunMeta,
    i: usize,
    stop: Option<(u64, &[u8])>,
) -> Result<Chunk, StoreError> {
    let f = &run.fences[i];
    let b = read_pages(rd, run, i, 0, f.nblk)?;
    let (c, complete) = Chunk::parse_until(b, 0, f.len as usize, stop)?;
    if complete && c.len() != f.n as usize {
        return Err(corrupt("chunk entry count"));
    }
    Ok(c)
}

/// Read chunk `i` from its page start `s` to the chunk end (a listing seek: pages before the start are not read) and
/// decode it up to the first entry at or past `stop` ([`Chunk::parse_until`]; `None`: to the chunk end).
pub fn load_from(
    rd: &mut impl ChunkRead,
    run: &RunMeta,
    i: usize,
    s: usize,
    stop: Option<(u64, &[u8])>,
) -> Result<Chunk, StoreError> {
    let f = &run.fences[i];
    let st = &run.chunk_starts(i)[s];
    let pg = st.page as usize;
    let b = read_pages(rd, run, i, pg, f.nblk - pg as u32)?;
    Ok(Chunk::parse_until(b, st.off as usize, f.len as usize - pg * BLK, stop)?.0)
}

/// Point lookup of `(id, key)` in chunk `i`: one read of the page of the last page start `<= key`. The last entry
/// starting in that page may straddle its end; its packed key ([`PageStart::last`]) decides before the read whether the
/// key lies before it (the page alone), may be it (the pages up to the next page start) or lies after it (absent: the
/// next page start's key is greater). `Some(val)` = the run holds an entry (value or point tombstone).
pub fn get_in_chunk(
    rd: &mut impl ChunkRead,
    run: &RunMeta,
    i: usize,
    id: u64,
    key: &[u8],
) -> Result<Option<Val>, StoreError> {
    let f = &run.fences[i];
    let starts = run.chunk_starts(i);
    let s = run.start_for(i, id, key);
    let st = &starts[s];
    let pg = st.page as usize;
    // Byte span (relative to the page) of the entries from this page start up to the next one.
    let span = starts.get(s + 1).map_or(f.len as usize, |n| n.pos()) - pg * BLK;
    let mut end = span;
    if span > BLK {
        match pack(id, key).cmp(&st.last) {
            Ordering::Less => end = BLK,
            Ordering::Greater => return Ok(None),
            Ordering::Equal => {}
        }
    }
    let b = read_pages(rd, run, i, pg, end.div_ceil(BLK) as u32)?;
    let bb = &b[..end];
    let mut p = st.off as usize;
    while p < end {
        let Some((eid, ko, kl, v, next)) = parse_ent(bb, p) else {
            // a one-page read ends inside the straddling entry, which is greater than the key
            return if end < span {
                Ok(None)
            } else {
                Err(corrupt("page span entry"))
            };
        };
        match cmp_gk(eid, &bb[ko..ko + kl], id, key) {
            Ordering::Less => p = next,
            Ordering::Equal => return Ok(Some(v.map(|vl| b.slice(ko + kl..ko + kl + vl)))),
            Ordering::Greater => return Ok(None),
        }
    }
    Ok(None)
}

/// Streaming run writer shared by flush and merge: entries in ascending order, sealed chunk by chunk (one chunk of
/// staging), moved chunks by reference, range tombstones; [`RunBuilder::finish`] writes the meta extent.
#[derive(Debug)]
pub struct RunBuilder {
    cur: Vec<u8>,
    cur_n: u32,
    cur_tombs: u32,
    cur_last: (u64, usize, usize),
    cur_starts: Vec<PageStart>,
    cur_hashes: Vec<u64>,
    last: Option<(u64, Bytes)>,
    meta: RunBody,
    /// Payload bytes of the sealed and moved chunks.
    sealed: u64,
    /// Blocks written by this builder (moved chunks excluded).
    pub written_blocks: u64,
}

impl Default for RunBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RunBuilder {
    pub fn new() -> RunBuilder {
        RunBuilder {
            cur: Vec::with_capacity(super::CHUNK_TARGET + BLK),
            cur_n: 0,
            cur_tombs: 0,
            cur_last: (0, 0, 0),
            cur_starts: Vec::new(),
            cur_hashes: Vec::new(),
            last: None,
            meta: RunBody::default(),
            sealed: 0,
            written_blocks: 0,
        }
    }

    fn check_order(&self, id: u64, key: &[u8]) {
        debug_assert!(
            self.last
                .as_ref()
                .is_none_or(|(li, lk)| cmp_gk(*li, lk, id, key) == Ordering::Less),
            "run entries out of order"
        );
    }

    /// Append one entry (strictly ascending).
    pub fn push(
        &mut self,
        sink: &mut impl BlockSink,
        id: u64,
        key: &[u8],
        val: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        let need = entry_len(id, key, val);
        // Seal when the chunk would exceed the target or no longer fit the largest extent the sink can lease: a
        // fragmented region yields 4..16-block chunks instead of failing the 16-block request (adr 0610 am. 5).
        let blocks_after = (self.cur.len() + need).div_ceil(BLK) as u32;
        if self.cur_n > 0
            && (self.cur.len() + need > super::CHUNK_TARGET || blocks_after > sink.room())
        {
            self.seal(sink)?;
        }
        if cfg!(debug_assertions) {
            self.check_order(id, key);
            self.last = Some((id, Bytes::copy_from_slice(key)));
        }
        let pos = self.cur.len();
        let page = (pos / BLK) as u32;
        if self.cur_starts.last().is_none_or(|s| s.page != page) {
            self.cur_starts.push(PageStart {
                page,
                off: (pos % BLK) as u16,
                id,
                key: Bytes::copy_from_slice(key),
                last: 0,
            });
        }
        self.cur_starts.last_mut().expect("a page start").last = pack(id, key);
        let c = &mut self.cur;
        put_var(c, id);
        put_var(c, key.len() as u64);
        put_var(c, val.map_or(0, |v| v.len() as u64 + 1));
        let ko = c.len();
        c.extend_from_slice(key);
        if let Some(v) = val {
            c.extend_from_slice(v);
        } else {
            self.cur_tombs += 1;
        }
        self.cur_last = (id, ko, key.len());
        self.cur_n += 1;
        self.cur_hashes.push(bloom::hash(id, key));
        Ok(())
    }

    /// Seal the open chunk (if any).
    pub fn seal(&mut self, sink: &mut impl BlockSink) -> Result<(), StoreError> {
        if self.cur_n == 0 {
            return Ok(());
        }
        let (lid, lo, ll) = self.cur_last;
        let len = self.cur.len();
        let nblk = len.div_ceil(BLK) as u32;
        let blk = sink.alloc(nblk)?;
        let mut data =
            std::mem::replace(&mut self.cur, Vec::with_capacity(super::CHUNK_TARGET + BLK));
        let last = Bytes::copy_from_slice(&data[lo..lo + ll]);
        data.resize(nblk as usize * BLK, 0);
        let crc_off = self.meta.page_crcs.len() as u32;
        self.meta.page_crcs.extend(page_crcs(blk, &data));
        let nw = bloom::words_for(self.cur_n as usize);
        let off = self.meta.bloom.len();
        self.meta.bloom.resize(off + nw, 0);
        for h in self.cur_hashes.drain(..) {
            bloom::add(&mut self.meta.bloom[off..off + nw], h);
        }
        let first = &self.cur_starts[0];
        self.meta.push_fence(Fence {
            first_id: first.id,
            first: first.key.clone(),
            last_id: lid,
            last,
            blk,
            nblk,
            len: len as u32,
            n: self.cur_n,
            tombs: self.cur_tombs,
            bloom_off: off as u32,
            bloom_nw: nw as u32,
            st_off: self.meta.starts.len() as u32,
            st_n: self.cur_starts.len() as u32,
            crc_off,
        });
        self.meta.starts.append(&mut self.cur_starts);
        self.sealed += len as u64;
        self.meta.entries += self.cur_n as u64;
        self.meta.tombs += self.cur_tombs as u64;
        sink.write(blk, data, &self.meta.page_crcs[crc_off as usize..])?;
        sink.chunk(nblk);
        self.written_blocks += nblk as u64;
        self.cur_n = 0;
        self.cur_tombs = 0;
        Ok(())
    }

    /// Append chunk `i` of `src` by reference (no rewrite). Ascending order with the entries around it.
    pub fn push_moved(
        &mut self,
        sink: &mut impl BlockSink,
        src: &RunMeta,
        i: usize,
    ) -> Result<(), StoreError> {
        self.seal(sink)?;
        let mut f = src.fences[i].clone();
        if cfg!(debug_assertions) {
            self.check_order(f.first_id, &f.first);
            self.last = Some((f.last_id, f.last.clone()));
        }
        f.bloom_off = self.meta.bloom.len() as u32;
        self.meta.bloom.extend_from_slice(src.chunk_bloom(i));
        f.st_off = self.meta.starts.len() as u32;
        self.meta.starts.extend_from_slice(src.chunk_starts(i));
        f.crc_off = self.meta.page_crcs.len() as u32;
        self.meta.page_crcs.extend_from_slice(src.chunk_crcs(i));
        self.meta.entries += f.n as u64;
        self.meta.tombs += f.tombs as u64;
        self.sealed += f.len as u64;
        self.meta.push_fence(f);
        Ok(())
    }

    /// Add a range tombstone (any order; coalesced).
    pub fn add_range(&mut self, r: RangeT) {
        super::ranges_add(&mut self.meta.ranges, r);
    }

    /// Payload bytes pushed or moved so far.
    pub fn bytes(&self) -> u64 {
        self.sealed + self.cur.len() as u64
    }

    /// Chunks sealed or moved so far.
    pub fn chunks(&self) -> usize {
        self.meta.fences.len()
    }

    /// Nothing pushed, moved or added.
    pub fn is_empty(&self) -> bool {
        self.cur_n == 0 && self.meta.fences.is_empty() && self.meta.ranges.is_empty()
    }

    /// Seal, write the meta extent, wait for durability; returns the run's metadata and the blocks written.
    ///
    /// A failed allocation leaves the builder unchanged (the caller may retry the finish).
    pub fn finish(
        &mut self,
        sink: &mut impl BlockSink,
        run_id: u64,
        lsn_lo: u64,
        lsn_hi: u64,
    ) -> Result<(RunMeta, u64), StoreError> {
        self.seal(sink)?;
        let m = &self.meta;
        let mut e = Enc::new();
        e.u64(META_MAGIC)
            .u64(run_id)
            .u64(lsn_lo)
            .u64(lsn_hi)
            .u32(m.fences.len() as u32)
            .u32(m.starts.len() as u32)
            .u32(m.page_crcs.len() as u32)
            .u32(m.ranges.len() as u32)
            .u32(m.bloom.len() as u32)
            .u64(m.entries)
            .u64(m.tombs);
        for f in &m.fences {
            e.u64(f.blk)
                .u32(f.nblk)
                .u32(f.len)
                .u32(f.n)
                .u32(f.tombs)
                .u32(f.bloom_off)
                .u32(f.bloom_nw)
                .u32(f.st_off)
                .u32(f.st_n)
                .u32(f.crc_off)
                .u64(f.last_id)
                .u32(f.last.len() as u32)
                .bytes(&f.last);
        }
        for s in &m.starts {
            e.u32(s.page)
                .u16(s.off)
                .u64(s.id)
                .u32(s.key.len() as u32)
                .bytes(&s.key)
                .u64((s.last >> 64) as u64)
                .u64(s.last as u64);
        }
        for c in &m.page_crcs {
            e.u32(*c);
        }
        for r in &m.ranges {
            e.u64(r.id).u32(r.first.len() as u32).bytes(&r.first);
            match &r.end {
                Some(x) => e.u8(1).u32(x.len() as u32).bytes(x),
                None => e.u8(0).u32(0),
            };
        }
        for w in &m.bloom {
            e.u64(*w);
        }
        let plen = e.b.len();
        let nblk = (plen + TRAILER).div_ceil(BLK) as u32;
        let blk = sink.alloc(nblk)?;
        let pcrc = codec::blk_crc(blk, &e.b);
        e.pad_to(nblk as usize * BLK - TRAILER);
        let t0 = e.b.len();
        e.u32(plen as u32).u32(pcrc).u32(TRAILER_MAGIC);
        let tcrc = codec::crc(&e.b[t0..]);
        e.u32(tcrc);
        let crcs: Vec<u32> = page_crcs(blk, &e.b).collect();
        sink.write(blk, e.b, &crcs)?;
        sink.sync()?;
        let m = RunMeta {
            id: run_id,
            lsn_lo,
            lsn_hi,
            body: Arc::new(std::mem::take(&mut self.meta)),
            meta_blk: blk,
            meta_nblk: nblk,
            meta_crc: pcrc,
            place: Place::default(),
        };
        Ok((m, self.written_blocks + nblk as u64))
    }
}

/// Mount: read and verify the meta extent of a run described by the manifest (`meta_crc` must match).
pub fn load_meta(
    rd: &mut impl ChunkRead,
    blk: u64,
    nblk: u32,
    meta_crc: u32,
) -> Result<RunMeta, StoreError> {
    let b = rd.read(blk, nblk)?;
    if b.len() != nblk as usize * BLK || b.len() < TRAILER {
        return Err(corrupt("meta extent length"));
    }
    let t = &b[b.len() - TRAILER..];
    let mut d = Dec::new(t);
    let (plen, pcrc, magic, tcrc) = (
        d.u32().unwrap() as usize,
        d.u32().unwrap(),
        d.u32().unwrap(),
        d.u32().unwrap(),
    );
    if magic != TRAILER_MAGIC || codec::crc(&t[..12]) != tcrc || plen > b.len() - TRAILER {
        return Err(corrupt(&format!("meta trailer at blk {blk}")));
    }
    let p = &b[..plen];
    if codec::blk_crc(blk, p) != pcrc || pcrc != meta_crc {
        return Err(corrupt(&format!("meta crc at blk {blk}")));
    }
    let bad = || corrupt("meta decode");
    let mut d = Dec::new(p);
    if d.u64().ok_or_else(bad)? != META_MAGIC {
        return Err(bad());
    }
    let (id, lsn_lo, lsn_hi) = (
        d.u64().ok_or_else(bad)?,
        d.u64().ok_or_else(bad)?,
        d.u64().ok_or_else(bad)?,
    );
    let mut m = RunBody::default();
    let nf = d.u32().ok_or_else(bad)? as usize;
    let ns = d.u32().ok_or_else(bad)? as usize;
    let nc = d.u32().ok_or_else(bad)? as usize;
    let nr = d.u32().ok_or_else(bad)? as usize;
    let nw = d.u32().ok_or_else(bad)? as usize;
    m.entries = d.u64().ok_or_else(bad)?;
    m.tombs = d.u64().ok_or_else(bad)?;
    let key = |d: &mut Dec| -> Result<Bytes, StoreError> {
        let n = d.u32().ok_or_else(bad)? as usize;
        Ok(Bytes::copy_from_slice(d.bytes(n).ok_or_else(bad)?))
    };
    let u32s = |d: &mut Dec, n: usize| -> Result<Vec<u32>, StoreError> {
        (0..n).map(|_| d.u32().ok_or_else(bad)).collect()
    };
    for _ in 0..nf {
        let blk = d.u64().ok_or_else(bad)?;
        let v = u32s(&mut d, 9)?;
        let last_id = d.u64().ok_or_else(bad)?;
        let last = key(&mut d)?;
        let f = Fence {
            first_id: 0,
            first: Bytes::new(),
            last_id,
            last,
            blk,
            nblk: v[0],
            len: v[1],
            n: v[2],
            tombs: v[3],
            bloom_off: v[4],
            bloom_nw: v[5],
            st_off: v[6],
            st_n: v[7],
            crc_off: v[8],
        };
        let fits = |off: u32, n: u32, total: usize| off as usize + n as usize <= total;
        if !fits(f.bloom_off, f.bloom_nw, nw)
            || !fits(f.st_off, f.st_n, ns)
            || !fits(f.crc_off, f.nblk, nc)
            || f.st_n == 0
            || f.tombs > f.n
            || f.len as usize > f.nblk as usize * BLK
        {
            return Err(bad());
        }
        m.push_fence(f);
    }
    for _ in 0..ns {
        let page = d.u32().ok_or_else(bad)?;
        let off = d.u16().ok_or_else(bad)?;
        let id = d.u64().ok_or_else(bad)?;
        let k = key(&mut d)?;
        let (lid, lkey) = (d.u64().ok_or_else(bad)?, d.u64().ok_or_else(bad)?);
        m.starts.push(PageStart {
            page,
            off,
            id,
            key: k,
            last: (lid as u128) << 64 | lkey as u128,
        });
    }
    m.page_crcs = u32s(&mut d, nc)?;
    for f in &mut m.fences {
        let s = &m.starts[f.st_off as usize];
        f.first_id = s.id;
        f.first = s.key.clone();
    }
    for _ in 0..nr {
        let id = d.u64().ok_or_else(bad)?;
        let first = key(&mut d)?;
        let has = d.u8().ok_or_else(bad)?;
        let end = key(&mut d)?;
        m.ranges.push(RangeT {
            id,
            first,
            end: (has == 1).then_some(end),
        });
    }
    m.bloom.reserve_exact(nw);
    for _ in 0..nw {
        m.bloom.push(d.u64().ok_or_else(bad)?);
    }
    Ok(RunMeta {
        id,
        lsn_lo,
        lsn_hi,
        body: Arc::new(m),
        meta_blk: blk,
        meta_nblk: nblk,
        meta_crc,
        place: Place::default(),
    })
}

#[cfg(test)]
mod range_bound_tests {
    use super::*;
    use crate::olsm::labdev::MemBlocks;

    #[test]
    fn derived_entry_prefix_capacity_is_charged_to_resident_ram() {
        let mut d = MemBlocks::new();
        let mut w = RunBuilder::new();
        for i in 0..5u64 {
            w.push(&mut d, 1, &i.to_be_bytes(), Some(b"v")).unwrap();
            w.seal(&mut d).unwrap();
        }
        let (mut m, _) = w.finish(&mut d, 1, 1, 1).unwrap();
        let prefix_bytes = m.entry_prefix.capacity() * size_of::<u64>();
        let charged = m.ram();
        Arc::get_mut(&mut m.body).expect("unshared").entry_prefix = Vec::new();
        assert_eq!(charged - m.ram(), prefix_bytes);
    }
}
