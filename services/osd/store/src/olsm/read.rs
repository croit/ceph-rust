// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Reads over all sources of a shard, newest first (adr 0610 (5), am. 2): point get / by_keys and the seeked
//! per-object merge iterator for listings. A point get asks the memtables, the tier-0 runs and per deeper tier only
//! the runs of the one partition holding the key. A listing walks the keyspace in segments within which every tier
//! contributes one partition (or none); in a segment every source is seeked to the start key (memtable by its
//! ordered map, a run by its fence index then a binary search in the chunk), so one page costs `O(max x sources)`
//! plus one seek per source, never a rescan of the object. A range tombstone of a newer source skips every older
//! source past its end.

use super::manifest::{Part, part_at};
use super::mem::{MKey, ObjMem, Probe};
use super::run::{Chunk, get_in_chunk, load_chunk_until, load_from};
use super::{ChunkRead, Gk, Memtable, RangeWalk, RunMeta, bloom, cmp_gk};
use crate::StoreError;
use bytes::Bytes;
use std::collections::btree_map;
use std::ops::Bound;
use std::sync::Arc;

/// Sources of one shard, newest first: memtables (active, frozen), tier-0 runs, partitioned tiers.
#[derive(Debug)]
pub struct Sources<'a> {
    /// Newest first (`over`, active, frozen); absent ones are `None`.
    pub mems: [Option<&'a Memtable>; 3],
    pub top: &'a [Arc<RunMeta>],
    /// Tier 1, 2, ...: partitions sorted by key range.
    pub tiers: &'a [Vec<Part>],
}

impl<'a> Sources<'a> {
    /// Conservative upper bound on the entries a listing of `[first, end)` of object `id` visits, capped at `cap`.
    ///
    /// It bounds both the live keys of the range and the work of enumerating them: puts and point tombstones count
    /// alike, so a span of tombstones is not mistaken for a cheap scan. Run counts come from resident fence prefix
    /// sums and include whole boundary chunks; memtables (the transaction overlay, active and frozen) count their
    /// entries inside the range, stopping at the cap. Duplicate versions and range tombstones are deliberately not
    /// subtracted: they can inflate the bound, never make it too small. No data IO or allocation occurs; use this
    /// bound only to select a deletion strategy, not as an exact logical count.
    pub fn range_entry_upper_bound(&self, id: u64, first: &[u8], end: &[u8], cap: u64) -> u64 {
        if first >= end || cap == 0 {
            return 0;
        }
        let mut count = 0u64;
        for mem in self.mems() {
            if let Some(o) = mem.obj(id) {
                let left = usize::try_from(cap - count).unwrap_or(usize::MAX);
                let span = (
                    std::ops::Bound::Included(first),
                    std::ops::Bound::Excluded(end),
                );
                count += o.map.range::<[u8], _>(span).take(left).count() as u64;
                if count == cap {
                    return cap;
                }
            }
        }
        for run in self.top {
            count += run.range_entry_upper_bound(id, first, end, cap - count);
            if count == cap {
                return cap;
            }
        }
        for parts in self.tiers {
            let lo = match part_at(parts, id, first) {
                Ok(i) | Err(i) => i,
            };
            let hi = parts.partition_point(|p| p.lo.cmp_at(id, end) == std::cmp::Ordering::Less);
            if lo >= hi {
                continue;
            }
            for part in &parts[lo..hi] {
                for run in &part.runs {
                    count += run.range_entry_upper_bound(id, first, end, cap - count);
                    if count == cap {
                        return cap;
                    }
                }
            }
        }
        count
    }

    /// The memtables, newest first.
    fn mems(&self) -> impl Iterator<Item = &'a Memtable> + '_ {
        self.mems.iter().flatten().copied()
    }

    /// Runs that may hold `(id, key)`, newest first.
    fn runs_at<'s>(&'s self, id: u64, key: &'s [u8]) -> impl Iterator<Item = &'a RunMeta> + 's {
        self.top.iter().map(|r| &**r).chain(
            self.tiers
                .iter()
                .filter_map(move |parts| part_at(parts, id, key).ok().map(|i| &parts[i]))
                .flat_map(|p| p.runs.iter().map(|r| &**r)),
        )
    }

    /// Runs of the segment starting at `(id, from)` (newest first) and the segment's end inside object `id`
    /// (`None`: the segment reaches past the object's last key): the nearest partition bound after the start.
    fn segment(&self, id: u64, from: &[u8]) -> (Vec<&'a RunMeta>, Option<Bytes>) {
        let mut runs: Vec<&RunMeta> = self.top.iter().map(|r| &**r).collect();
        let mut end: Option<&Gk> = None;
        for parts in self.tiers {
            let bound = match part_at(parts, id, from) {
                Ok(i) => {
                    runs.extend(parts[i].runs.iter().map(|r| &**r));
                    parts[i].hi.as_ref()
                }
                Err(i) => parts.get(i).map(|p| &p.lo),
            };
            if let Some(b) = bound
                && end.is_none_or(|e| b < e)
            {
                end = Some(b);
            }
        }
        (runs, end.filter(|e| e.id == id).map(|e| e.key.clone()))
    }
}

/// What run `r` says about `(id, key)`.
pub fn probe_run(
    rd: &mut impl ChunkRead,
    r: &RunMeta,
    id: u64,
    key: &[u8],
    h: u64,
) -> Result<Probe, StoreError> {
    if let Some(i) = r.find_chunk(id, key)
        && bloom::maybe(r.chunk_bloom(i), h)
        && let Some(v) = get_in_chunk(rd, r, i, id, key)?
    {
        return Ok(Probe::Hit(v));
    }
    Ok(if r.range_cover(id, key).is_some() {
        Probe::Covered
    } else {
        Probe::Pass
    })
}

/// Value of `(id, key)`.
pub fn get(
    src: &Sources,
    rd: &mut impl ChunkRead,
    id: u64,
    key: &[u8],
) -> Result<Option<Bytes>, StoreError> {
    get_probed(src, rd, id, key).map(|(v, _)| v)
}

/// [`get`] and the number of runs consulted (filter + fence) until a source decided.
pub fn get_probed(
    src: &Sources,
    rd: &mut impl ChunkRead,
    id: u64,
    key: &[u8],
) -> Result<(Option<Bytes>, usize), StoreError> {
    for m in src.mems() {
        match m.probe(id, key) {
            Probe::Hit(v) => return Ok((v, 0)),
            Probe::Covered => return Ok((None, 0)),
            Probe::Pass => {}
        }
    }
    let h = bloom::hash(id, key);
    let mut n = 0;
    for r in src.runs_at(id, key) {
        n += 1;
        match probe_run(rd, r, id, key, h)? {
            Probe::Hit(v) => return Ok((v, n)),
            Probe::Covered => return Ok((None, n)),
            Probe::Pass => {}
        }
    }
    Ok((None, n))
}

/// Values of `keys` of object `id` (present keys only, in the given order). A key whose run block is not cached
/// ([`StoreError::Miss`]) does not stop the others: the blocks of all keys are requested in one pass, then `Miss`.
pub fn by_keys(
    src: &Sources,
    rd: &mut impl ChunkRead,
    id: u64,
    keys: &[Bytes],
) -> Result<Vec<(Bytes, Bytes)>, StoreError> {
    let mut out = Vec::with_capacity(keys.len());
    let mut miss = false;
    for k in keys {
        match get(src, rd, id, k) {
            Ok(Some(v)) => out.push((k.clone(), v)),
            Ok(None) => {}
            Err(StoreError::Miss) => miss = true,
            Err(e) => return Err(e),
        }
    }
    if miss {
        return Err(StoreError::Miss);
    }
    Ok(out)
}

/// Smallest object id `>= from` with an entry (a value or a point tombstone) in a run of `src` (the memtables are not
/// asked); `None`: no run entry at or after `from`. Per run one fence lookup; a chunk is read only when it spans
/// `from` (its first entry lies before it). Object ids are sparse (the object layer allocates `lsn << 12 | seq`), so
/// a fence's id span is no candidate list: a walk with this visits only ids that exist. With batched demand reads
/// every run's chunk is requested before [`StoreError::Miss`].
pub fn next_run_id(
    src: &Sources,
    rd: &mut impl ChunkRead,
    from: u64,
) -> Result<Option<u64>, StoreError> {
    let runs = src
        .top
        .iter()
        .chain(src.tiers.iter().flatten().flat_map(|p| &p.runs));
    let (mut best, mut miss) = (None::<u64>, false);
    for r in runs {
        let i = r.seek_chunk(from, b"");
        let Some(f) = r.fences.get(i) else { continue };
        let id = if f.first_id >= from {
            f.first_id
        } else if best == Some(from) {
            continue;
        } else {
            match load_from(rd, r, i, r.start_for(i, from, b""), None) {
                Ok(c) => {
                    let pos = c.seek(from, b"", false);
                    if pos == c.len() {
                        return Err(StoreError::Corrupt(
                            "olsm: chunk ends before its fence".into(),
                        ));
                    }
                    c.id(pos)
                }
                Err(StoreError::Miss) if rd.scan_prefetch() => {
                    miss = true;
                    continue;
                }
                Err(e) => return Err(e),
            }
        };
        best = Some(best.map_or(id, |b| b.min(id)));
    }
    if miss {
        return Err(StoreError::Miss);
    }
    Ok(best)
}

enum Cur<'a> {
    Mem {
        o: &'a ObjMem,
        it: btree_map::Range<'a, MKey, super::Val>,
        cur: Option<(&'a MKey, &'a super::Val)>,
    },
    Run {
        r: &'a RunMeta,
        ci: usize,
        chunk: Option<Chunk>,
        pos: usize,
        /// Chunk to (re)load lazily and the bound to seek to inside it.
        seek: Option<(Bytes, bool)>,
        hinted: bool,
    },
    Done,
}

impl<'a> Cur<'a> {
    fn mem(o: &'a ObjMem, from: Bound<&[u8]>) -> Cur<'a> {
        let mut it = o.map.range::<[u8], _>((from, Bound::Unbounded));
        Cur::Mem {
            o,
            cur: it.next(),
            it,
        }
    }
    fn run(r: &'a RunMeta, id: u64, from: &Bytes, excl: bool) -> Cur<'a> {
        Cur::Run {
            r,
            ci: r.seek_chunk(id, from),
            chunk: None,
            pos: 0,
            seek: Some((from.clone(), excl)),
            hinted: false,
        }
    }
    /// Reposition to keys `>= from` (`excl`: `>`), never backwards.
    fn seek(&mut self, id: u64, from: &Bytes, excl: bool) {
        match self {
            Cur::Mem { o, .. } => {
                let o = *o;
                let b = if excl {
                    Bound::Excluded(&from[..])
                } else {
                    Bound::Included(&from[..])
                };
                *self = Cur::mem(o, b);
            }
            // A target inside the decoded part of the current chunk moves the position there: no reload or
            // re-decode of the chunk (a covering range tombstone usually ends a few entries further on).
            Cur::Run {
                chunk: Some(c),
                pos,
                ..
            } if c.len() > *pos && {
                let last = c.len() - 1;
                match cmp_gk(c.id(last), c.key(last), id, from) {
                    std::cmp::Ordering::Greater => true,
                    std::cmp::Ordering::Equal => !excl,
                    std::cmp::Ordering::Less => false,
                }
            } =>
            {
                *pos = (*pos).max(c.seek(id, from, excl));
            }
            Cur::Run { r, .. } => {
                let r = *r;
                *self = Cur::run(r, id, from, excl);
            }
            Cur::Done => {}
        }
    }
    /// Make the head valid (load the chunk under the cursor).
    fn fill(
        &mut self,
        rd: &mut impl ChunkRead,
        id: u64,
        end: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        if let Cur::Run {
            r,
            ci,
            chunk,
            pos,
            seek,
            hinted,
        } = self
        {
            loop {
                if let Some(c) = chunk.as_ref().filter(|c| *pos < c.len()) {
                    if c.id(*pos) != id || end.is_some_and(|e| c.key(*pos) >= e) {
                        *self = Cur::Done;
                        return Ok(());
                    }
                    break;
                }
                if chunk.take().is_some() {
                    *ci += 1;
                    *hinted = false;
                }
                if *ci >= r.fences.len()
                    || r.fences[*ci].first_id > id
                    || end.is_some_and(|e| {
                        r.fences[*ci].first_id == id && &r.fences[*ci].first[..] >= e
                    })
                {
                    *self = Cur::Done;
                    return Ok(());
                }
                // A seek reads from the page start before the key, later chunks whole. Entries are decoded only up to
                // the first one at or past the cursor's bound: the end key, else the object's end (the next id).
                // Only a chunk whose last entry reaches the bound needs the per-entry stop comparison.
                let f = &r.fences[*ci];
                let stop = match end {
                    Some(e) => Some((id, e)),
                    None => id.checked_add(1).map(|n| (n, &[][..])),
                }
                .filter(|&(sid, skey)| {
                    cmp_gk(f.last_id, &f.last, sid, skey) != std::cmp::Ordering::Less
                });
                // The seek stays until its chunk is loaded: a refused load leaves the cursor describing where it stands
                // ([`Cur::bound`]).
                let c = match seek.clone() {
                    Some((k, excl)) => {
                        let c = load_from(rd, r, *ci, r.start_for(*ci, id, &k), stop)?;
                        *pos = c.seek(id, &k, excl);
                        *seek = None;
                        c
                    }
                    None => {
                        *pos = 0;
                        load_chunk_until(rd, r, *ci, stop)?
                    }
                };
                *chunk = Some(c);
            }
            let c = chunk.as_ref().expect("filled");
            if c.id(*pos) != id {
                *self = Cur::Done;
            }
        }
        Ok(())
    }
    /// Consider the configured next fences once per current chunk, inside the object's prefix and partition segment.
    fn prefetch(&mut self, rd: &mut impl ChunkRead, id: u64, prefix: &[u8], end: Option<&[u8]>) {
        if let Cur::Run {
            r,
            ci,
            chunk: Some(c),
            pos,
            hinted,
            ..
        } = self
        {
            if *hinted {
                return;
            }
            *hinted = true;
            if !c.key(*pos).starts_with(prefix) || end.is_some_and(|e| c.key(*pos) >= e) {
                return;
            }
            for f in r
                .fences
                .iter()
                .skip(*ci + 1)
                .take(rd.scan_prefetch_chunks())
            {
                if f.first_id > id
                    || f.last_id < id
                    || (f.first_id == id && !f.first.starts_with(prefix) && &f.first[..] >= prefix)
                    || end.is_some_and(|e| f.first_id == id && &f.first[..] >= e)
                {
                    break;
                }
                rd.prefetch(f.blk, f.nblk);
            }
        }
    }
    /// The smallest position `(key, excl)` at or after which this cursor can still deliver an entry of object `id`
    /// (`None`: it has none left): its head, else where the pending fill continues (the seek target, the next chunk's
    /// first key). Nothing a cursor holds lies before it; the merge consumed every smaller key already.
    fn bound(&self, id: u64) -> Option<(Bytes, bool)> {
        match self {
            Cur::Mem { cur, .. } => cur.map(|(k, _)| (k.key.clone(), false)),
            Cur::Run {
                r,
                ci,
                chunk,
                pos,
                seek,
                ..
            } => {
                if let Some(c) = chunk.as_ref().filter(|c| *pos < c.len()) {
                    return (c.id(*pos) == id).then(|| (c.key_bytes(*pos), false));
                }
                if let Some((k, excl)) = seek {
                    return Some((k.clone(), *excl));
                }
                let next = *ci + usize::from(chunk.is_some());
                r.fences
                    .get(next)
                    .filter(|f| f.first_id == id)
                    .map(|f| (f.first.clone(), false))
            }
            Cur::Done => None,
        }
    }
    fn head(&self) -> Option<&[u8]> {
        match self {
            Cur::Mem { cur, .. } => cur.map(|(k, _)| &k.key[..]),
            Cur::Run { chunk, pos, .. } => chunk.as_ref().map(|c| c.key(*pos)),
            Cur::Done => None,
        }
    }
    /// Take the head entry (key, value or tombstone).
    fn take(&mut self) -> (Bytes, super::Val) {
        match self {
            Cur::Mem { it, cur, .. } => {
                let (k, v) = cur.expect("head");
                *cur = it.next();
                (k.key.clone(), v.clone())
            }
            Cur::Run { chunk, pos, .. } => {
                let c = chunk.as_ref().expect("head");
                let e = (c.key_bytes(*pos), c.val(*pos));
                *pos += 1;
                e
            }
            Cur::Done => unreachable!("take on a finished cursor"),
        }
    }
    fn skip(&mut self) {
        match self {
            Cur::Mem { it, cur, .. } => *cur = it.next(),
            Cur::Run { pos, .. } => *pos += 1,
            Cur::Done => {}
        }
    }
}

/// A listing's position: the next key to look at (`excl`: strictly after `from`). Every key before it is decided
/// (its entry, if live, is in the listing's output); the listing continues from here exactly, so a call that ends
/// early ([`ListEnd::Resume`], a refused read) loses no work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListPos {
    pub from: Bytes,
    pub excl: bool,
}

impl ListPos {
    /// Start of a listing at key `from` (`excl`: after it).
    pub fn new(from: &[u8], excl: bool) -> ListPos {
        ListPos {
            from: Bytes::copy_from_slice(from),
            excl,
        }
    }
}

/// How a bounded listing call ended ([`list_page`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListEnd {
    /// The page is complete (`max` entries, the byte budget, the prefix or the object ended); `more`: keys follow it.
    Done { more: bool },
    /// The visit budget ran out first: the call's output so far and its position are valid, continue from there.
    Resume,
}

/// Listing page of object `id`: keys `> after` (all when `None`) starting with `prefix`, at most `max`; returns the
/// page and whether more keys follow.
#[cfg(test)]
pub fn list(
    src: &Sources,
    rd: &mut impl ChunkRead,
    id: u64,
    after: Option<&[u8]>,
    prefix: &[u8],
    max: usize,
) -> Result<(Vec<(Bytes, Bytes)>, bool), StoreError> {
    match after {
        Some(a) => list_from(src, rd, id, a, true, prefix, max),
        None => list_from(src, rd, id, b"", false, prefix, max),
    }
}

/// [`list`] from key `from` (`excl`: keys `> from`, else `>= from`). Runs to completion: the work is not bounded
/// (offline checks and tests); a listing on the PG core uses [`list_page`].
pub fn list_from(
    src: &Sources,
    rd: &mut impl ChunkRead,
    id: u64,
    from: &[u8],
    excl: bool,
    prefix: &[u8],
    max: usize,
) -> Result<(Vec<(Bytes, Bytes)>, bool), StoreError> {
    let q = ListQuery {
        id,
        prefix,
        max,
        max_bytes: usize::MAX,
        visits: usize::MAX,
    };
    let mut out = Vec::new();
    match list_page(src, rd, &q, &mut ListPos::new(from, excl), &mut out)? {
        ListEnd::Done { more } => Ok((out, more)),
        ListEnd::Resume => unreachable!("an unbounded visit budget does not run out"),
    }
}

/// One bounded step of a listing of object `q.id`: appends the live entries from `pos` on whose keys start with
/// `q.prefix` to `out` (the page: at most `q.max` entries; it also ends once its keys and values reach `q.max_bytes`, at
/// least one entry: a cold call keeps every extent it demanded protected until it completes, so the budget bounds
/// that working set) and stops after merging `q.visits` entries, live or not. A span of deleted keys therefore
/// costs the caller one step per `q.visits` entries, never one call that runs over all of them.
///
/// `pos` and `out` always describe the progress made, also when the call fails with [`StoreError::Miss`] (a run chunk
/// is not cached; its read is queued): the retry continues from `pos` and re-reads nothing it already merged. A
/// finished call leaves `pos` unspecified.
pub fn list_page(
    src: &Sources,
    rd: &mut impl ChunkRead,
    q: &ListQuery,
    pos: &mut ListPos,
    out: &mut Vec<(Bytes, Bytes)>,
) -> Result<ListEnd, StoreError> {
    let bytes = out.iter().map(|(k, v)| k.len() + v.len()).sum();
    let mut sink = ValueOut { v: out, bytes };
    list_bounded(src, rd, q, pos, None, &mut sink)
}

/// Exact live keys in the half-open range `[from, end)` (`excl`: strictly after `from`).
/// The same merged view as [`list_from`], without retaining values or visiting later segments.
pub fn list_range_keys(
    src: &Sources,
    rd: &mut impl ChunkRead,
    id: u64,
    from: &[u8],
    excl: bool,
    end: &[u8],
    max: usize,
) -> Result<(Vec<Bytes>, bool), StoreError> {
    if from >= end {
        return Ok((Vec::new(), false));
    }
    let mut out = Vec::new();
    let q = ListQuery {
        id,
        prefix: b"",
        max,
        max_bytes: usize::MAX,
        visits: usize::MAX,
    };
    match list_bounded(
        src,
        rd,
        &q,
        &mut ListPos::new(from, excl),
        Some(end),
        &mut out,
    )? {
        ListEnd::Done { more } => Ok((out, more)),
        ListEnd::Resume => unreachable!("an unbounded visit budget does not run out"),
    }
}

/// Monomorphized sinks keep the ordinary value listing unchanged while key-only consumers do not
/// retain a handle to every old value in the range.
trait ListOut {
    fn len(&self) -> usize;
    /// Key and value bytes collected (only sinks that keep values track them).
    fn bytes(&self) -> usize {
        0
    }
    fn entry(&mut self, key: Bytes, value: Bytes);
}
/// A value listing with the key + value byte count of the page ([`ListQuery::max_bytes`]).
struct ValueOut<'a> {
    v: &'a mut Vec<(Bytes, Bytes)>,
    bytes: usize,
}
impl ListOut for ValueOut<'_> {
    fn len(&self) -> usize {
        self.v.len()
    }
    fn bytes(&self) -> usize {
        self.bytes
    }
    fn entry(&mut self, key: Bytes, value: Bytes) {
        self.bytes = self.bytes.saturating_add(key.len() + value.len());
        self.v.push((key, value));
    }
}
impl ListOut for Vec<Bytes> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
    fn entry(&mut self, key: Bytes, _value: Bytes) {
        self.push(key);
    }
}

/// The segment loop of a listing from `pos` (see [`list_page`]); `last` = exclusive end key inside the object.
fn list_bounded(
    src: &Sources,
    rd: &mut impl ChunkRead,
    q: &ListQuery,
    pos: &mut ListPos,
    last: Option<&[u8]>,
    out: &mut impl ListOut,
) -> Result<ListEnd, StoreError> {
    let id = q.id;
    if pos.from[..] < *q.prefix {
        *pos = ListPos::new(q.prefix, false);
    }
    let mut prog = Progress {
        pos,
        visits: q.visits,
    };
    loop {
        if last.is_some_and(|e| &prog.pos.from[..] >= e) {
            return Ok(ListEnd::Done { more: false });
        }
        let (runs, mut end) = src.segment(id, &prog.pos.from);
        if let Some(last) = last
            && end.as_deref().is_none_or(|e| e > last)
        {
            end = Some(Bytes::copy_from_slice(last));
        }
        let from = prog.pos.from.clone();
        let seg = Seg {
            from: &from,
            excl: prog.pos.excl,
            end: end.as_deref(),
        };
        match list_seg(src, &runs, rd, q, seg, &mut prog, out)? {
            SegEnd::Done(more) => return Ok(ListEnd::Done { more }),
            SegEnd::Budget => return Ok(ListEnd::Resume),
            SegEnd::Next => {
                *prog.pos = ListPos {
                    from: end.expect("a segment ends inside the object"),
                    excl: false,
                };
            }
        }
    }
}

/// A bounded listing request ([`list_page`]): object, key prefix and the limits of the page and of one call.
#[derive(Debug)]
pub struct ListQuery<'q> {
    pub id: u64,
    pub prefix: &'q [u8],
    /// Entries of a page.
    pub max: usize,
    /// Key and value bytes of a page (at least one entry); `usize::MAX`: unbounded.
    pub max_bytes: usize,
    /// Entries (live, deleted or shadowed) one call merges before it ends with [`ListEnd::Resume`]; `usize::MAX`: unbounded.
    pub visits: usize,
}

/// One segment of a listing: keys from `from` (`excl`: after it) up to `end` (exclusive; `None`: the object's end).
struct Seg<'s> {
    from: &'s Bytes,
    excl: bool,
    end: Option<&'s [u8]>,
}

/// What a listing call has done so far: where it continues and the visits it has left.
struct Progress<'p> {
    pos: &'p mut ListPos,
    visits: usize,
}

/// How [`list_seg`] ended.
enum SegEnd {
    /// The listing is complete (`more`: keys follow the page).
    Done(bool),
    /// The segment ended with the page still open.
    Next,
    /// The visit budget ran out; `pos` is where the listing continues.
    Budget,
}

/// Merge the sources of one segment into `out`. `prog.pos` is kept at the first undecided key whenever the call ends
/// early (visit budget, refused read), so the caller continues exactly there.
fn list_seg(
    src: &Sources,
    runs: &[&RunMeta],
    rd: &mut impl ChunkRead,
    q: &ListQuery,
    seg: Seg,
    prog: &mut Progress,
    out: &mut impl ListOut,
) -> Result<SegEnd, StoreError> {
    let Seg { from, excl, end } = seg;
    let (id, prefix, max) = (q.id, q.prefix, q.max);
    let fb = if excl {
        Bound::Excluded(&from[..])
    } else {
        Bound::Included(&from[..])
    };
    let mut curs: Vec<Cur> = Vec::with_capacity(3 + runs.len());
    for m in src.mems() {
        curs.push(m.obj(id).map_or(Cur::Done, |o| Cur::mem(o, fb)));
    }
    for r in runs {
        curs.push(Cur::run(r, id, from, excl));
    }
    // Coverage must see every source's ranges, also of sources whose cursor ran out of entries.
    let ranges: Vec<&[super::RangeT]> = src
        .mems()
        .map(|m| m.obj(id).map_or(&[][..], |o| &o.ranges[..]))
        .chain(runs.iter().map(|r| &r.ranges[..]))
        .collect();
    // The merge emits ascending keys: each source holding range tombstones walks its list forward ([`RangeWalk`]).
    // Only those sources (newest first) are consulted; without any, coverage costs nothing per key.
    let mut walks: Vec<(usize, RangeWalk)> = ranges
        .iter()
        .enumerate()
        .filter(|(_, rs)| !rs.is_empty())
        .map(|(j, rs)| (j, RangeWalk::new(rs, id, from)))
        .collect();
    // Only cursors that moved since their last fill need one: an untouched cursor's head stays valid.
    let mut dirty = vec![true; curs.len()];
    // The previous winner and the runner-up (smallest head of the other cursors, lowest index on ties) while only the
    // winner has moved since: the winner wins again with one comparison while its new head stays below the runner-up's.
    let mut last: Option<(usize, Option<usize>)> = None;
    loop {
        let mut miss = false;
        for (c, d) in curs.iter_mut().zip(dirty.iter_mut()) {
            if !*d {
                continue;
            }
            match c.fill(rd, id, end) {
                Ok(()) => *d = false,
                Err(StoreError::Miss) => {
                    miss = true;
                    // with prefetch off only the first missing head is demanded per pass
                    if !rd.scan_prefetch() {
                        break;
                    }
                }
                Err(e) => return Err(e),
            }
        }
        // With prefetch every source's demanded head is requested before the operation parks. No merge decision may
        // use a partial set of heads. Hints follow demand admission so they cannot take slots from this round's heads.
        // The retry continues where the merge stands: the smallest key any source still has to deliver. `out` holds
        // everything before it, so `pos` is written on every refusal.
        if miss {
            let at = curs
                .iter()
                .filter_map(|c| c.bound(id))
                .min_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            if let Some((from, excl)) = at {
                *prog.pos = ListPos { from, excl };
            }
            return Err(StoreError::Miss);
        }
        let again = last.take().filter(|&(w, r)| {
            curs[w]
                .head()
                .is_some_and(|h| r.is_none_or(|r| curs[r].head().is_none_or(|rh| h < rh)))
        });
        let (w, runner) = match again {
            Some(x) => x,
            None => {
                // smallest head (lowest index on ties), then the smallest of the others
                let (mut win, mut run): (Option<usize>, Option<usize>) = (None, None);
                for i in 0..curs.len() {
                    let Some(k) = curs[i].head() else { continue };
                    match win {
                        None => win = Some(i),
                        Some(w) if k < curs[w].head().expect("winner head") => {
                            run = win;
                            win = Some(i);
                        }
                        Some(_) => {
                            if run.is_none_or(|r| k < curs[r].head().expect("runner head")) {
                                run = Some(i);
                            }
                        }
                    }
                }
                let Some(w) = win else {
                    return Ok(if end.is_none() {
                        SegEnd::Done(false)
                    } else {
                        SegEnd::Next
                    });
                };
                (w, run)
            }
        };
        let key = curs[w].head().expect("winner head");
        // past the segment: the next segment's sources may hold smaller keys than this one
        if end.is_some_and(|e| key >= e) {
            return Ok(SegEnd::Next);
        }
        if !key.starts_with(prefix) {
            return Ok(SegEnd::Done(false));
        }
        // Every key before the winner is decided: the call stops here, the next one starts at the winner.
        if prog.visits == 0 {
            *prog.pos = ListPos {
                from: Bytes::copy_from_slice(key),
                excl: false,
            };
            return Ok(SegEnd::Budget);
        }
        prog.visits -= 1;
        // A newer source's range tombstone covering the key hides it and every older entry up to the range end.
        if let Some((j, rend)) = walks
            .iter_mut()
            .take_while(|(j, _)| *j < w)
            .find_map(|(j, wk)| wk.find(ranges[*j], id, key).map(|x| (*j, x.end.clone())))
        {
            for (c, d) in curs[j + 1..].iter_mut().zip(dirty[j + 1..].iter_mut()) {
                match &rend {
                    Some(e) => {
                        if c.head().is_some_and(|h| h < &e[..]) {
                            c.seek(id, e, false);
                            *d = true;
                        }
                    }
                    None => *c = Cur::Done,
                }
            }
            continue;
        }
        if rd.scan_prefetch() {
            curs[w].prefetch(rd, id, prefix, end);
        }
        let (k, v) = curs[w].take();
        dirty[w] = true;
        // Older entries of the same key: only possible when the runner-up holds it (all other heads are not smaller).
        if runner.is_some_and(|r| curs[r].head() == Some(&k[..])) {
            for (c, d) in curs[w + 1..].iter_mut().zip(dirty[w + 1..].iter_mut()) {
                if c.head() == Some(&k[..]) {
                    if rd.scan_prefetch() {
                        c.prefetch(rd, id, prefix, end);
                    }
                    c.skip();
                    *d = true;
                }
            }
        } else {
            last = Some((w, runner));
        }
        if let Some(v) = v {
            if out.len() == max || (out.len() > 0 && out.bytes() >= q.max_bytes) {
                return Ok(SegEnd::Done(true));
            }
            out.entry(k, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::olsm::labdev::MemBlocks;
    use crate::olsm::tests::H;

    #[test]
    fn bounded_key_listing_never_reads_or_prefetches_chunks_past_the_end() {
        struct Bounded<'a> {
            dev: &'a mut MemBlocks,
            allowed: Vec<(u64, u32)>,
            reads: usize,
        }
        impl ChunkRead for Bounded<'_> {
            fn read(&mut self, blk: u64, nblk: u32) -> Result<Bytes, StoreError> {
                assert!(
                    self.allowed
                        .iter()
                        .any(|&(b, n)| blk >= b && blk + u64::from(nblk) <= b + u64::from(n))
                );
                self.reads += 1;
                self.dev.read(blk, nblk)
            }
            fn scan_prefetch(&self) -> bool {
                true
            }
            fn scan_prefetch_chunks(&self) -> usize {
                16
            }
            fn prefetch(&mut self, blk: u64, nblk: u32) {
                assert!(
                    self.allowed.contains(&(blk, nblk)),
                    "hint beyond the requested range"
                );
            }
        }
        let mut h = H::new(MemBlocks::new(), 1 << 30);
        for id in 1..=2 {
            for i in 0..2000 {
                h.put(id, format!("key/{i:06}").as_bytes(), &[7; 200]);
            }
        }
        h.flush();
        let end = b"key/000001".as_slice();
        let allowed = h
            .lsm
            .man
            .top()
            .iter()
            .flat_map(|r| r.fences.iter())
            .filter(|f| f.first_id <= 1 && (f.first_id < 1 || &f.first[..] < end) && f.last_id >= 1)
            .map(|f| (f.blk, f.nblk))
            .collect();
        let mut rd = Bounded {
            dev: &mut h.dev,
            allowed,
            reads: 0,
        };
        let (keys, more) =
            list_range_keys(&h.lsm.sources(), &mut rd, 1, b"key/000000", false, end, 256).unwrap();
        assert_eq!(keys, vec![Bytes::from_static(b"key/000000")]);
        assert!(!more);
        assert!(rd.reads > 0);
        rd.allowed.clear();
        assert_eq!(
            list_range_keys(&h.lsm.sources(), &mut rd, 1, end, false, end, 256).unwrap(),
            (vec![], false)
        );
    }

    struct HintReader<'a> {
        dev: &'a mut MemBlocks,
        chunks: usize,
        hints: Vec<(u64, u32)>,
    }
    impl ChunkRead for HintReader<'_> {
        fn read(&mut self, blk: u64, nblk: u32) -> Result<Bytes, StoreError> {
            self.dev.read(blk, nblk)
        }
        fn scan_prefetch(&self) -> bool {
            true
        }
        fn scan_prefetch_chunks(&self) -> usize {
            self.chunks
        }
        fn prefetch(&mut self, blk: u64, nblk: u32) {
            self.hints.push((blk, nblk));
        }
    }

    #[test]
    fn scan_window_hints_logical_fences_once_with_prefix_segment_object_and_run_bounds() {
        let mut h = H::new(MemBlocks::new(), 1 << 30);
        for id in 1..=2 {
            for prefix in ["a/", "z/"] {
                for i in 0..1800 {
                    h.put(id, format!("{prefix}{i:06}").as_bytes(), &[1; 200]);
                }
            }
        }
        h.flush();
        let r = &h.lsm.sources().top[0];
        let mut rd = HintReader {
            dev: &mut h.dev,
            chunks: 1,
            hints: vec![],
        };
        let from = Bytes::from_static(b"a/000000");
        for chunks in [1, 4] {
            rd.chunks = chunks;
            rd.hints.clear();
            let mut c = Cur::run(r, 1, &from, false);
            c.fill(&mut rd, 1, None).unwrap();
            c.prefetch(&mut rd, 1, b"a/", None);
            let want: Vec<_> = r
                .fences
                .iter()
                .skip(1)
                .take(chunks)
                .map(|f| (f.blk, f.nblk))
                .collect();
            assert_eq!(rd.hints, want, "logical hint order for window {chunks}");
            for _ in 0..16 {
                c.take();
                c.prefetch(&mut rd, 1, b"a/", None);
            }
            assert_eq!(rd.hints, want, "no per-entry reissue");
        }
        rd.chunks = 4;
        rd.hints.clear();
        let mut c = Cur::run(r, 1, &from, false);
        c.fill(&mut rd, 1, None).unwrap();
        c.prefetch(&mut rd, 1, b"a/", Some(&r.fences[3].first));
        assert_eq!(
            rd.hints,
            r.fences[1..3]
                .iter()
                .map(|f| (f.blk, f.nblk))
                .collect::<Vec<_>>(),
            "partition segment ends before fence 3"
        );
        for (id, prefix, ci) in [
            (
                1,
                b"a/".as_slice(),
                r.fences
                    .iter()
                    .rposition(|f| f.first_id == 1 && f.first.starts_with(b"a/"))
                    .unwrap(),
            ),
            (
                1,
                b"".as_slice(),
                r.fences.iter().rposition(|f| f.first_id == 1).unwrap(),
            ),
            (2, b"".as_slice(), r.fences.len() - 1),
        ] {
            rd.hints.clear();
            let mut c = Cur::run(r, id, &r.fences[ci].first, false);
            c.fill(&mut rd, id, None).unwrap();
            c.prefetch(&mut rd, id, prefix, None);
            assert!(
                rd.hints.is_empty(),
                "window stops at prefix/object/run bound, ci={ci}"
            );
        }
        // A newer range tombstone suppresses all covered cursor hints, including a four-fence window.
        let mut over = Memtable::default();
        over.del_range(1, 1, Bytes::new(), None);
        rd.hints.clear();
        let top = [r.clone()];
        let src = Sources {
            mems: [Some(&over), None, None],
            top: &top,
            tiers: &[],
        };
        assert_eq!(
            list(&src, &mut rd, 1, None, b"", 17).unwrap(),
            (vec![], false)
        );
        assert!(rd.hints.is_empty(), "tombstone skips happen before hinting");
    }

    /// A bounded cursor decodes its chunk only up to the first entry at or past the end key, and the bounded listing
    /// still returns exactly the live keys of `[from, end)` over overlapping runs with point and range tombstones.
    #[test]
    fn bounded_cursor_decodes_up_to_the_end_and_lists_the_same_keys() {
        let mut h = H::new(MemBlocks::new(), 1 << 30);
        let key = |i: u32| format!("key/{i:06}").into_bytes();
        for id in 1..=2 {
            for i in 0..3000 {
                h.put(id, &key(i), &[7; 200]);
            }
        }
        h.flush();
        for id in 1..=2 {
            for i in (0..3000).step_by(3) {
                h.del(id, &key(i));
            }
            for i in (1..3000).step_by(5) {
                h.put(id, &key(i), &[9; 100]);
            }
        }
        h.del_range(1, &key(1500), Some(&key(1600)));
        h.flush();
        h.put(1, &key(1550), &[1; 10]);
        h.del(1, &key(1001));
        let src = h.lsm.sources();
        let rd = &mut h.dev;
        let (all, more) = list_from(&src, &mut *rd, 1, b"", false, b"", usize::MAX).unwrap();
        assert!(!more);
        let all: Vec<Bytes> = all.into_iter().map(|(k, _)| k).collect();
        for (a, b) in [
            (0, 1),
            (0, 64),
            (17, 81),
            (990, 1060),
            (1490, 1610),
            (1549, 1551),
            (2900, 3000),
            (2999, 4000),
        ] {
            let (from, end) = (key(a), key(b));
            let want: Vec<Bytes> = all
                .iter()
                .filter(|k| k[..] >= from[..] && k[..] < end[..])
                .cloned()
                .collect();
            for max in [1, 7, usize::MAX] {
                let mut got = Vec::new();
                let (mut cur, mut excl) = (from.clone(), false);
                loop {
                    let (page, more) =
                        list_range_keys(&src, &mut *rd, 1, &cur, excl, &end, max).unwrap();
                    got.extend(page.iter().cloned());
                    if !more {
                        break;
                    }
                    cur = page.last().expect("nonterminal page").to_vec();
                    excl = true;
                }
                assert_eq!(got, want, "[{a}, {b}) max {max}");
            }
        }
        // The seek chunk of a short range is decoded only up to the end key, not to the chunk end.
        let r = &src.top[src.top.len() - 1];
        let from = Bytes::from(key(10));
        let end = key(12);
        let mut c = Cur::run(r, 1, &from, false);
        c.fill(&mut *rd, 1, Some(&end[..])).unwrap();
        let Cur::Run {
            chunk: Some(ch),
            ci,
            ..
        } = &c
        else {
            panic!("cursor holds a chunk")
        };
        assert!(
            ch.len() < r.fences[*ci].n as usize,
            "decoded {} of {}",
            ch.len(),
            r.fences[*ci].n
        );
        assert!(
            ch.key(ch.len() - 1) >= &end[..],
            "the stop entry is decoded"
        );
    }

    /// A forward walk answers exactly what the binary search answers for every non-decreasing key sequence, also
    /// across jumps over many ranges (the search fallback), object boundaries and an open-ended last range.
    #[test]
    fn range_walk_matches_ranges_find_for_ascending_keys() {
        use super::super::{RangeT, ranges_find};
        let key = |i: u32| Bytes::from(format!("k{i:06}"));
        let mut list = Vec::new();
        for id in 1..=3u64 {
            // ranges [10i, 10i + 4) for i < 300, then an open range on the last object
            for i in 0..300u32 {
                list.push(RangeT {
                    id,
                    first: key(10 * i),
                    end: Some(key(10 * i + 4)),
                });
            }
        }
        list.push(RangeT {
            id: 4,
            first: key(500),
            end: None,
        });
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = |m: u32| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((seed >> 33) as u32) % m
        };
        for round in 0..200 {
            let (mut id, mut i) = (1 + u64::from(next(2)), next(50));
            let mut walk = RangeWalk::new(&list, id, &key(i));
            for _ in 0..400 {
                let k = key(i);
                let want = ranges_find(&list, id, &k).map(|x| (x.id, x.first.clone()));
                let got = walk.find(&list, id, &k).map(|x| (x.id, x.first.clone()));
                assert_eq!(got, want, "round {round} id {id} key {i}");
                // mostly small steps, sometimes repeats, jumps over many ranges or to the next object
                match next(20) {
                    0 => {}
                    1 => i += 400 + next(1500),
                    2 if id < 4 => {
                        id += 1;
                        i = next(600);
                    }
                    _ => i += 1 + next(7),
                }
            }
        }
    }

    /// Short range tombstones in newer sources over older runs (the reseek inside a loaded chunk): listings in pages of
    /// every size match a model map, for both objects, with the newest source a memtable and with everything flushed.
    #[test]
    fn short_covering_ranges_list_like_a_model_map() {
        use std::collections::BTreeMap;
        let key = |i: u32| format!("key/{i:06}").into_bytes();
        let mut h = H::new(MemBlocks::new(), 1 << 30);
        let mut model: BTreeMap<(u64, Vec<u8>), Vec<u8>> = BTreeMap::new();
        for id in 1..=2u64 {
            for i in 0..4000 {
                h.put(id, &key(i), &[3; 150]);
                model.insert((id, key(i)), vec![3; 150]);
            }
        }
        h.flush();
        for id in 1..=2u64 {
            for i in (0..4000).step_by(7) {
                h.put(id, &key(i), &[4; 40]);
                model.insert((id, key(i)), vec![4; 40]);
            }
        }
        h.flush();
        let ranges = |h: &mut H<MemBlocks>,
                      model: &mut BTreeMap<(u64, Vec<u8>), Vec<u8>>,
                      from: u32,
                      step: u32| {
            for id in 1..=2u64 {
                for s in (from..4000).step_by(step as usize) {
                    let (a, b) = (key(s), key(s + 1 + s % 9));
                    h.del_range(id, &a, Some(&b[..]));
                    model.retain(|(i, k), _| !(*i == id && *k >= a && *k < b));
                }
            }
        };
        ranges(&mut h, &mut model, 5, 61);
        h.flush();
        ranges(&mut h, &mut model, 33, 97);
        for (round, flush) in [(0, false), (1, true)] {
            if flush {
                h.flush();
            }
            let src = h.lsm.sources();
            let rd = &mut h.dev;
            for id in 1..=2u64 {
                let want: Vec<(Vec<u8>, Vec<u8>)> = model
                    .range((id, Vec::new())..(id + 1, Vec::new()))
                    .map(|((_, k), v)| (k.clone(), v.clone()))
                    .collect();
                for max in [1, 13, 1024, usize::MAX] {
                    let mut got = Vec::new();
                    let (mut from, mut excl) = (Vec::new(), false);
                    loop {
                        let (page, more) =
                            list_from(&src, &mut *rd, id, &from, excl, b"", max).unwrap();
                        got.extend(page.iter().map(|(k, v)| (k.to_vec(), v.to_vec())));
                        if !more || page.is_empty() {
                            break;
                        }
                        from = page.last().expect("nonempty").0.to_vec();
                        excl = true;
                    }
                    assert_eq!(got.len(), want.len(), "round {round} id {id} max {max}");
                    assert!(got == want, "round {round} id {id} max {max}");
                }
            }
        }
    }

    /// A byte budget ends a value page once its keys and values reach it, always with at least one entry, and the
    /// pages together are exactly the unbounded listing.
    #[test]
    fn byte_budget_bounds_value_pages_and_keeps_progress() {
        let mut h = H::new(MemBlocks::new(), 1 << 30);
        for i in 0..60u32 {
            let size = if i % 10 == 0 { 300 << 10 } else { 20 << 10 };
            h.put(1, format!("k{i:04}").as_bytes(), &vec![i as u8; size]);
        }
        h.flush();
        h.put(1, b"k0005", &[9; 100]);
        let src = h.lsm.sources();
        let rd = &mut h.dev;
        let (all, more) = list_from(&src, &mut *rd, 1, b"", false, b"", usize::MAX).unwrap();
        assert!(!more);
        assert_eq!(all.len(), 60);
        let budget = 64 << 10;
        let mut got = Vec::new();
        let (mut from, mut excl) = (Vec::new(), false);
        loop {
            let q = ListQuery {
                id: 1,
                prefix: b"",
                max: 4096,
                max_bytes: budget,
                visits: usize::MAX,
            };
            let mut page = Vec::new();
            let more = match list_page(
                &src,
                &mut *rd,
                &q,
                &mut ListPos::new(&from, excl),
                &mut page,
            )
            .unwrap()
            {
                ListEnd::Done { more } => more,
                ListEnd::Resume => unreachable!("unbounded visits"),
            };
            assert!(!page.is_empty(), "a budgeted page makes progress");
            let bytes: usize = page.iter().map(|(k, v)| k.len() + v.len()).sum();
            let last = page.last().map(|(k, v)| k.len() + v.len()).unwrap();
            assert!(
                bytes - last < budget,
                "only the entry reaching the budget may exceed it"
            );
            got.extend(page.iter().cloned());
            if !more {
                break;
            }
            from = page.last().unwrap().0.to_vec();
            excl = true;
        }
        assert_eq!(got, all);
    }
}
