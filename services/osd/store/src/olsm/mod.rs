// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Omap LSM engine (adr 0610).
//!
//! One engine per store shard holds the omap of every object of the shard in one keyspace `(object id, omap key)`,
//! ordered by id (numeric) then key (bytes). All writes are blind: a put overwrites, a delete writes a point tombstone,
//! a range delete writes a range tombstone `[first, end)` within one object (`end = None`: to the object's last key,
//! i.e. `omap_clear` / object removal). Ops are applied in LSN order; the newest op wins.
//!
//! Structure:
//! - [`mem::Memtable`]: the shard's active write buffer. Keys and values are [`bytes::Bytes`] slices of the caller's
//!   buffers (no copy). Freeze = O(1) move into an `Arc`; the frozen memtable is immutable and may be read by another
//!   core.
//! - [`run`]: the immutable sorted run format: block-aligned chunks of whole entries (target [`CHUNK_TARGET`]) with
//!   crc32c, one meta extent (fence index with first/last key, crc, entry/tombstone counts and per-chunk bloom of
//!   every chunk; the run's range tombstones; trailer with crc). A chunk is self-contained (its bloom lives in the
//!   meta, not in a run-wide filter), so a merge can move it into its output by reference.
//! - [`job`]: flush (frozen memtable -> run) and merge (k-way, newest wins, chunk move / drop / rewrite) as pure
//!   functions over immutable inputs, a [`run::ChunkRead`] and a [`run::BlockSink`]; no store handle inside, so they
//!   can run on a helper core.
//! - [`manifest`]: the run set of a shard: tier 0 (flush runs, newest first) and deeper tiers partitioned by key
//!   range (am. 2), the merge policy and the manifest record encoding.
//! - [`remote`]: a flush or merge as a continuation over leased blocks and supplied chunks, stepped by the owner or
//!   a helper core.
//! - [`read`]: point get and the seeked merge iterator for listings.
//! - [`Olsm`]: owner-side state (active + frozen memtable + manifest) tying the parts together.
//!
//! Invariant used by every reader and the merge: inside one source (memtable or run) an entry is newer than every
//! range tombstone of the same source that covers it (a range tombstone drops the covered older entries when it is
//! applied, flushed or merged). So a source that holds an entry for a key decides the key; a source whose range
//! tombstone covers the key (and that holds no entry) decides "absent"; otherwise the next older source is asked.
//! Range tombstones of one source are kept as disjoint, coalesced intervals.

#[cfg(test)]
mod bench;
pub mod bloom;
pub mod cache;
pub mod job;
#[cfg(any(test, feature = "lab"))]
pub mod labdev;
pub mod manifest;
pub mod mem;
pub mod read;
pub mod remote;
pub mod run;
#[cfg(test)]
mod tests;
pub mod wire;

use bytes::Bytes;
use std::cmp::Ordering;
use std::sync::Arc;

pub use manifest::Manifest;
pub use mem::Memtable;
pub use run::{BlockSink, ChunkRead, RunMeta};

#[cfg(test)]
use crate::StoreError;

/// Target payload size of one run chunk (adr 0610). An entry larger than the target forms a chunk of its own.
pub const CHUNK_TARGET: usize = 64 * 1024;
/// Smallest lease piece / chunk: 16 KiB = 4 x 4 KiB block, the floor a fragmented region still fits (adr 0610 am. 5).
pub const CHUNK_MIN: u32 = (16 * 1024 / crate::BLK) as u32;
/// Largest lease piece / chunk: 64 KiB = 16 blocks = [`CHUNK_TARGET`].
pub const CHUNK_MAX: u32 = (CHUNK_TARGET / crate::BLK) as u32;
/// Merge fan of the size-tiered policy (adr 0610): `FAN` runs of one tier merge into one run of the next tier.
pub const FAN: usize = 8;
/// Bloom filter bits per key (adr 0610).
pub const BLOOM_BITS_PER_KEY: usize = 12;

/// Value of an entry: `Some` = put, `None` = point tombstone.
pub type Val = Option<Bytes>;

/// Compare keyspace positions `(id, key)`.
#[inline]
pub fn cmp_gk(a_id: u64, a_key: &[u8], b_id: u64, b_key: &[u8]) -> Ordering {
    a_id.cmp(&b_id).then_with(|| a_key.cmp(b_key))
}

/// A keyspace position `(object id, key)`; ordered by id, then key bytes. [`Gk::MIN`] is the start of the keyspace.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Gk {
    pub id: u64,
    pub key: Bytes,
}

impl Gk {
    pub const MIN: Gk = Gk {
        id: 0,
        key: Bytes::new(),
    };
    pub fn new(id: u64, key: &[u8]) -> Gk {
        Gk {
            id,
            key: Bytes::copy_from_slice(key),
        }
    }
    /// Order of this position against `(id, key)`.
    #[inline]
    pub fn cmp_at(&self, id: u64, key: &[u8]) -> Ordering {
        cmp_gk(self.id, &self.key, id, key)
    }
}

impl PartialOrd for Gk {
    fn partial_cmp(&self, o: &Gk) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Gk {
    fn cmp(&self, o: &Gk) -> Ordering {
        self.cmp_at(o.id, &o.key)
    }
}

/// `(id, key)` lies before the exclusive upper bound `hi` (`None` = end of the keyspace).
#[inline]
pub fn below(hi: Option<&Gk>, id: u64, key: &[u8]) -> bool {
    hi.is_none_or(|h| h.cmp_at(id, key) == Ordering::Greater)
}

/// Where a run sits in the manifest (adr 0610 am. 3): tier 0 = the unpartitioned flush tier (whole keyspace);
/// tier `t >= 1` = the partition `[lo, hi)` of tier `t` (`hi = None`: to the end of the keyspace). Held in the
/// manifest record, not in the run's meta extent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Place {
    pub tier: u32,
    pub lo: Gk,
    pub hi: Option<Gk>,
}

/// A range tombstone `[first, end)` inside one object; `end = None` = to the object's last key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeT {
    pub id: u64,
    pub first: Bytes,
    pub end: Option<Bytes>,
}

impl RangeT {
    /// Covers key `key` of object `id`.
    #[inline]
    pub fn covers(&self, id: u64, key: &[u8]) -> bool {
        id == self.id && key >= &self.first[..] && self.end.as_ref().is_none_or(|e| key < &e[..])
    }
    /// Covers every key in `[lo, hi]` (both inclusive, same object).
    pub fn covers_span(&self, id: u64, lo: &[u8], hi: &[u8]) -> bool {
        self.covers(id, lo) && self.covers(id, hi)
    }
    /// The part of this range inside the keyspace interval `[lo, hi)` (`hi = None`: unbounded), if any.
    pub fn clip(&self, lo: &Gk, hi: Option<&Gk>) -> Option<RangeT> {
        let first = match lo.id.cmp(&self.id) {
            Ordering::Greater => return None,
            Ordering::Equal if lo.key > self.first => lo.key.clone(),
            _ => self.first.clone(),
        };
        let end = match hi.map(|h| (h.id.cmp(&self.id), h)) {
            Some((Ordering::Less, _)) => return None,
            Some((Ordering::Equal, h)) => match &self.end {
                Some(e) if e[..] <= h.key[..] => Some(e.clone()),
                _ => Some(h.key.clone()),
            },
            _ => self.end.clone(),
        };
        if end.as_ref().is_some_and(|e| e[..] <= first[..]) {
            return None;
        }
        Some(RangeT {
            id: self.id,
            first,
            end,
        })
    }
    /// Intersects the inclusive span `[(lo_id, lo), (hi_id, hi)]`.
    pub fn touches(&self, lo_id: u64, lo: &[u8], hi_id: u64, hi: &[u8]) -> bool {
        // The range starts at or before the span's end and ends after the span's start.
        let starts_before_hi = cmp_gk(self.id, &self.first, hi_id, hi) != Ordering::Greater;
        let ends_after_lo = match self.id.cmp(&lo_id) {
            Ordering::Less => false,
            Ordering::Greater => true,
            Ordering::Equal => self.end.as_ref().is_none_or(|e| &e[..] > lo),
        };
        starts_before_hi && ends_after_lo
    }
}

/// Insert `r` into a sorted list of disjoint ranges, coalescing every range it overlaps or touches (valid because
/// a source's entries are newer than its own ranges, see the module invariant).
pub fn ranges_add(list: &mut Vec<RangeT>, r: RangeT) {
    // First range of the same object that ends at or after r.first (could overlap / touch).
    let lo = list.partition_point(|x| {
        x.id < r.id || (x.id == r.id && x.end.as_ref().is_some_and(|e| e[..] < r.first[..]))
    });
    let mut first = r.first;
    let mut end = r.end;
    let mut hi = lo;
    while hi < list.len() {
        let x = &list[hi];
        let starts_inside = x.id == r.id && end.as_ref().is_none_or(|e| x.first[..] <= e[..]);
        if !starts_inside {
            break;
        }
        if x.first[..] < first[..] {
            first = x.first.clone();
        }
        end = match (&end, &x.end) {
            (None, _) | (_, None) => None,
            (Some(a), Some(b)) => Some(if a[..] >= b[..] { a.clone() } else { b.clone() }),
        };
        hi += 1;
    }
    list.splice(
        lo..hi,
        std::iter::once(RangeT {
            id: r.id,
            first,
            end,
        }),
    );
}

/// The range of a sorted disjoint list covering `(id, key)`, if any.
pub fn ranges_find<'a>(list: &'a [RangeT], id: u64, key: &[u8]) -> Option<&'a RangeT> {
    let i = list.partition_point(|x| cmp_gk(x.id, &x.first, id, key) != Ordering::Greater);
    let x = list.get(i.checked_sub(1)?)?;
    x.covers(id, key).then_some(x)
}

/// [`ranges_find`] for non-decreasing keys: a forward-only position in one sorted disjoint range list, so a merge
/// that emits ascending keys checks coverage with about one comparison per key instead of a binary search over the
/// whole list. A position that would have to pass many ranges at once falls back to a binary search.
#[derive(Debug, Clone, Copy)]
pub struct RangeWalk {
    i: usize,
}

impl RangeWalk {
    /// Linear steps before a search: ranges passed between two consecutive keys are usually few.
    const STEPS: usize = 8;

    /// Positioned at the first range of `list` ending after `(id, key)`.
    pub fn new(list: &[RangeT], id: u64, key: &[u8]) -> RangeWalk {
        RangeWalk {
            i: ranges_from(list, id, key),
        }
    }

    /// The range of `list` covering `(id, key)`. Keys must not decrease between calls on the same list.
    pub fn find<'a>(&mut self, list: &'a [RangeT], id: u64, key: &[u8]) -> Option<&'a RangeT> {
        let ended = |x: &RangeT| match x.id.cmp(&id) {
            Ordering::Less => true,
            Ordering::Greater => false,
            Ordering::Equal => x.end.as_ref().is_some_and(|e| &e[..] <= key),
        };
        let mut steps = 0;
        while let Some(x) = list.get(self.i) {
            if !ended(x) {
                break;
            }
            self.i += 1;
            steps += 1;
            if steps == Self::STEPS {
                self.i += ranges_from(&list[self.i..], id, key);
                break;
            }
        }
        list.get(self.i).filter(|x| x.covers(id, key))
    }
}

/// Index of the first range of a sorted disjoint list ending after `(id, key)` (range ends ascend).
fn ranges_from(list: &[RangeT], id: u64, key: &[u8]) -> usize {
    list.partition_point(|x| match x.id.cmp(&id) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => x.end.as_ref().is_some_and(|e| &e[..] <= key),
    })
}

/// Some range of a sorted disjoint list intersects the inclusive span `[(lo_id, lo), (hi_id, hi)]`.
pub fn ranges_touch(list: &[RangeT], lo_id: u64, lo: &[u8], hi_id: u64, hi: &[u8]) -> bool {
    list.get(ranges_from(list, lo_id, lo))
        .is_some_and(|x| x.touches(lo_id, lo, hi_id, hi))
}

/// The first 8 bytes of `key`, zero-padded, as a big-endian integer: a smaller value means a smaller key; equal
/// values need the full comparison.
#[inline]
fn key_prefix(key: &[u8]) -> u64 {
    let mut p = [0u8; 8];
    let n = key.len().min(8);
    p[..n].copy_from_slice(&key[..n]);
    u64::from_be_bytes(p)
}

/// Owner-side engine state of one shard: active memtable, at most one frozen memtable being flushed, run manifest.
#[derive(Debug)]
pub struct Olsm {
    pub active: Memtable,
    pub frozen: Option<Arc<Memtable>>,
    pub man: Manifest,
}

impl Olsm {
    pub fn new(man: Manifest) -> Olsm {
        Olsm {
            active: Memtable::new(),
            frozen: None,
            man,
        }
    }

    /// Freeze the active memtable (O(1)); `None` while a frozen memtable is still flushing or nothing is buffered.
    pub fn freeze(&mut self) -> Option<Arc<Memtable>> {
        if self.frozen.is_some() || self.active.is_empty() {
            return None;
        }
        let f = Arc::new(std::mem::take(&mut self.active));
        self.frozen = Some(f.clone());
        Some(f)
    }

    /// A flush job of the frozen memtable finished and its run is durable: install it, drop the frozen memtable.
    pub fn flush_done(&mut self, run: RunMeta) {
        let f = self
            .frozen
            .take()
            .expect("flush_done without a frozen memtable");
        self.man.install_flush(Arc::new(run), f.lsn_hi());
    }

    /// Point get: newest source first.
    #[cfg(test)]
    pub fn get(
        &self,
        rd: &mut impl ChunkRead,
        id: u64,
        key: &[u8],
    ) -> Result<Option<Bytes>, StoreError> {
        read::get(&self.sources(), rd, id, key)
    }

    /// Listing page of object `id`: keys `> after` (all keys when `None`) starting with `prefix`, at most `max`;
    /// returns the page and whether more keys follow.
    #[cfg(test)]
    pub fn list(
        &self,
        rd: &mut impl ChunkRead,
        id: u64,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
    ) -> Result<(Vec<(Bytes, Bytes)>, bool), StoreError> {
        read::list(&self.sources(), rd, id, after, prefix, max)
    }

    /// Sources newest first.
    pub fn sources(&self) -> read::Sources<'_> {
        self.sources_over(None)
    }

    /// [`Olsm::sources`] with `over` as the newest memtable.
    pub fn sources_over<'a>(&'a self, over: Option<&'a Memtable>) -> read::Sources<'a> {
        read::Sources {
            mems: [over, Some(&self.active), self.frozen.as_deref()],
            top: self.man.top(),
            tiers: &self.man.tiers,
        }
    }
}
