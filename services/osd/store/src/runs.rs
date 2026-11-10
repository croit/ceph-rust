// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Omap batch runs (adr 0476): a client omap batch of a counted object is applied as ONE sorted run
//! (`Op::RunPut`) instead of per-key tree mutations. A run is the batch's tree entries (omap key, value record) in one
//! buffer with an entry index and a bloom filter; the object's runs are an overlay over the tree for its omap keys:
//! newest run first, then the tree. Runs leave by `Op::RunMerge` (into the tree, in key slices) or with the object's omap
//! (clear / remove). Durability: the WAL records of live runs stay in the ring (floor), replay rebuilds the runs.
//!
//! A tree op on a key a run holds (put, removal, range removal) kills the key in all runs of the object (they are older):
//! the newest run that holds a key decides, a dead entry means "not in the runs". A run whose entries are all killed
//! leaves at once.
//!
//! An entry with an empty value record is a removal (tombstone, [`is_tomb`]; adr 0647-omap-blind-removals D1, store
//! feature `FEAT_OMAP_TOMBS`): a client removal batch of a counted object is one run of removals, staged blind. While it
//! is the newest entry of its key the key is absent (older runs and the tree are shadowed, no tree lookup); a compaction
//! keeps it over the older entries of its key; the merge removes the key from the tree if it is there. Value records
//! are never empty (form byte), so the empty one is free as the removal mark.
//!
//! A run has two lsns: its order (`Run::lsn`, the lsn of the record that first logged it: newest wins, merge cutoffs)
//! and its record (`Run::rec`, the record holding its entries now: the WAL floor). A re-log (`RunBlob::ord` set) writes
//! the live entries of a run again under its order lsn, so the ring units of the original record can be released while
//! the run stays (ring liveness when merges cannot keep up).

use crate::fx::FxHasher;
use crate::obj::keys::{S_OMAP, T_OMAP, onode_id_of};
use bytes::Bytes;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hasher;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Entry header: key length u16, value length u32.
const EHDR: usize = 6;
/// WAL op header of a run: tag u8, order lsn u64, id u64, entries u32, bytes u32.
pub const RUN_OP_HDR: usize = 25;
/// Largest entry buffer of a run: entries are addressed by u32 offsets and the WAL op logs the byte count as u32
/// (review 2026-11-03 #9). Admission keeps every run within it: a larger client batch takes the tree path (stage
/// `run_ok`), a compaction whose inputs sum above it is not planned (its output is at most their bytes), a re-log is a
/// subset of its run. A seal above it is an engine bug: it stops loudly instead of wrapping offsets.
pub const RUN_BYTES_MAX: usize = u32::MAX as usize;

/// A run of `bytes` entry bytes is addressable ([`RUN_BYTES_MAX`]).
#[inline]
pub fn run_fits(bytes: usize) -> bool {
    bytes <= RUN_BYTES_MAX
}
/// A run entry's value record marks a removal (tombstone): the key is absent. Value records are never empty.
#[inline]
pub fn is_tomb(v: &[u8]) -> bool {
    v.is_empty()
}

/// Bloom filter bits per entry and bits per key (all in one 512-bit block).
const BLOOM_BITS: usize = 10;
const BLOOM_K: u32 = 7;

/// Object id of an omap tree key (`None`: not an omap key).
#[inline]
pub fn omap_id(k: &[u8]) -> Option<u64> {
    (k.len() >= OPFX && k[0] == T_OMAP && k[OPFX - 1] == S_OMAP)
        .then(|| onode_id_of(k))
        .flatten()
}

/// Smallest omap tree key of object `id`: `obj::keys::omap_key(id, b"")` as an array (no allocation).
fn key_lo(id: u64) -> [u8; OPFX] {
    let mut k = [0u8; OPFX];
    k[0] = T_OMAP;
    k[1..9].copy_from_slice(&id.to_be_bytes());
    k[9] = S_OMAP;
    k
}

/// Bytes every omap tree key of one object starts with: tag, object id, sub-tag ([`key_lo`]).
const OPFX: usize = 10;

/// Hash of a run key for the bloom of its run: the keys of a run share the object prefix, so only the rest is hashed.
#[inline]
fn hash(k: &[u8]) -> u64 {
    let mut h = FxHasher::default();
    h.write(k.get(OPFX..).unwrap_or(k));
    h.finish()
}

/// Order of two omap tree keys of the same object (they share the [`OPFX`] prefix): the 8 bytes after the prefix decide
/// most compares as one integer compare, the rest by a byte compare.
#[inline]
fn okey_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    debug_assert_eq!(a.get(..OPFX), b.get(..OPFX), "keys of one object");
    match (a.get(OPFX..OPFX + 8), b.get(OPFX..OPFX + 8)) {
        (Some(x), Some(y)) => {
            let (x, y) = (
                u64::from_be_bytes(x.try_into().unwrap()),
                u64::from_be_bytes(y.try_into().unwrap()),
            );
            x.cmp(&y).then_with(|| a[OPFX + 8..].cmp(&b[OPFX + 8..]))
        }
        _ => a.cmp(b),
    }
}

/// Bloom filter over the keys of one run.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct Bloom {
    bits: Vec<u64>,
}

impl Bloom {
    fn new(n: usize) -> Bloom {
        Bloom {
            bits: vec![0; (n * BLOOM_BITS).div_ceil(512).max(1) * 8],
        }
    }
    /// Blocked filter: the key's `BLOOM_K` bits lie in one 512-bit block (one cache line per lookup; no division). The
    /// block's first word, and the mix whose 9-bit groups are the key's bits in the block.
    #[inline]
    fn block(&self, h: u64) -> (usize, u64) {
        let blocks = (self.bits.len() / 8) as u128;
        let w = ((h as u128 * blocks) >> 64) as usize * 8;
        let mut x = (h ^ (h >> 29)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x ^= x >> 32;
        (w, x)
    }
    fn add(&mut self, k: &[u8]) {
        let (w, x) = self.block(hash(k));
        for i in 0..BLOOM_K {
            let b = (x >> (9 * i) & 511) as usize;
            self.bits[w + b / 64] |= 1 << (b % 64);
        }
    }
    /// May the run hold a key of hash `h` ([`hash`])? All `BLOOM_K` bits are tested, no exit at the first clear one:
    /// the answer varies key by key (a removal batch asks every run of its object for every key), a branch per bit
    /// mispredicts often, and the bits of one cache line cost less than one mispredict (adr 0476 am. 15).
    #[inline]
    pub fn may(&self, h: u64) -> bool {
        let (w, x) = self.block(h);
        let blk = &self.bits[w..w + 8];
        let mut all = 1;
        for i in 0..BLOOM_K {
            let b = (x >> (9 * i) & 511) as usize;
            all &= blk[b / 64] >> (b % 64);
        }
        all & 1 != 0
    }
    fn bytes(&self) -> usize {
        self.bits.len() * 8
    }
}

/// The logged form of a run: the omap entries of one object, strictly ascending keys, all in that object's omap key
/// space. Buffer: `[klen u16 LE][vlen u32 LE][key][value record]` per entry (vlen 0: a removal, [`is_tomb`]). Index and
/// bloom are derived (built once by the stage or the WAL decoder) and shared by clones.
#[derive(Clone, PartialEq, Eq)]
pub struct RunBlob {
    id: u64,
    /// Order lsn of a re-logged run; 0: a new run (its order is its record's lsn).
    ord: u64,
    buf: Bytes,
    offs: Arc<[u32]>,
    /// Search index ([`KeyIx`]): the 8 key bytes after the common prefix of all keys, one integer per entry.
    ix: Arc<KeyIx>,
    bloom: Arc<Bloom>,
    /// Tree leaf bytes its entries take once merged ([`RunBlob::tree_bytes`]; removals take none).
    tree: usize,
}

/// Dense search index of a run: the keys of a run share their first `lcp` bytes (the common prefix of its first and
/// last key); `px[i]` = the next 8 bytes of key `i` as a big-endian integer (zero padded). A search compares integers
/// in one dense array and reads a key from the run buffer only on equal integers: one cache line per probe instead of
/// two scattered reads (offset, then key bytes).
#[derive(PartialEq, Eq, Debug)]
struct KeyIx {
    lcp: usize,
    px: Vec<u64>,
}

/// `k[at..at + 8]` as a big-endian integer, zero padded: integer order = byte order of the keys at that position.
#[inline]
fn px_at(k: &[u8], at: usize) -> u64 {
    let t = k.get(at..).unwrap_or(&[]);
    if let Some(b) = t.get(..8) {
        return u64::from_be_bytes(b.try_into().unwrap());
    }
    let mut b = [0u8; 8];
    b[..t.len()].copy_from_slice(t);
    u64::from_be_bytes(b)
}

impl KeyIx {
    fn build(buf: &[u8], offs: &[u32]) -> KeyIx {
        let (first, last) = (ent(buf, offs[0]).0, ent(buf, offs[offs.len() - 1]).0);
        let lcp = first.iter().zip(last).take_while(|(a, b)| a == b).count();
        KeyIx {
            lcp,
            px: offs.iter().map(|&o| px_at(ent(buf, o).0, lcp)).collect(),
        }
    }
    fn bytes(&self) -> usize {
        self.px.len() * 8
    }
}

/// A key to search in one run: its integer at the run's [`KeyIx`] position, or its fixed lower bound when it does not
/// share the run's common prefix (0: below every key, `n`: above every key).
enum Probe {
    At(u64),
    Bound(usize),
}

impl std::fmt::Debug for RunBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RunBlob(id {}, ord {}, {} entries, {} B)",
            self.id,
            self.ord,
            self.len(),
            self.buf.len()
        )
    }
}

/// Killed (removed) entry indices of a run and their count: one bit per entry, words allocated at the first kill.
#[derive(Clone, Debug, Default)]
struct KillSet {
    words: Vec<u64>,
    n: usize,
}

impl KillSet {
    #[inline]
    fn get(&self, i: usize) -> bool {
        self.words
            .get(i / 64)
            .is_some_and(|w| w >> (i % 64) & 1 != 0)
    }
    /// Add entry `i` of a run of `len` entries; `true` when it was not in the set.
    #[inline]
    fn set(&mut self, i: usize, len: usize) -> bool {
        debug_assert!(i < len);
        if self.words.len() <= i / 64 {
            self.words.resize(len.div_ceil(64), 0);
        }
        let (w, m) = (&mut self.words[i / 64], 1u64 << (i % 64));
        let new = *w & m == 0;
        *w |= m;
        self.n += usize::from(new);
        new
    }
    /// Add entries `[i0, i1)` of a run of `len` entries word by word; `each` sees every index not in the set before.
    /// Returns how many those were.
    #[inline]
    fn set_range(
        &mut self,
        i0: usize,
        i1: usize,
        len: usize,
        mut each: impl FnMut(usize),
    ) -> usize {
        debug_assert!(i0 < i1 && i1 <= len);
        if self.words.len() < i1.div_ceil(64) {
            self.words.resize(len.div_ceil(64), 0);
        }
        let mut added = 0;
        let mut i = i0;
        while i < i1 {
            let (w, b) = (i / 64, i % 64);
            let take = (64 - b).min(i1 - i);
            let m = (u64::MAX >> (64 - take)) << b;
            let mut new = !self.words[w] & m;
            self.words[w] |= m;
            added += new.count_ones() as usize;
            while new != 0 {
                each(w * 64 + new.trailing_zeros() as usize);
                new &= new - 1;
            }
            i += take;
        }
        self.n += added;
        added
    }
    /// The set of the distinct indices `ix` of a run of `len` entries.
    fn from_indices(ix: &[usize], len: usize) -> KillSet {
        let mut s = KillSet::default();
        for &i in ix {
            s.set(i, len);
        }
        s
    }
    #[inline]
    fn len(&self) -> usize {
        self.n
    }
    #[inline]
    fn words(&self) -> &[u64] {
        &self.words
    }
    /// Heap bytes held.
    fn heap_bytes(&self) -> usize {
        self.words.capacity() * 8
    }
}

/// A run being staged (stage): entries pushed in strictly ascending key order, looked up by the rest of the txn, and
/// entries removed when a later op of the txn takes their key (demoted to a tree op).
#[derive(Default, Debug, Clone)]
pub struct RunBuilder {
    buf: Vec<u8>,
    offs: Vec<u32>,
    gone: KillSet,
    /// Lower bound of the last [`RunBuilder::find_asc`] key.
    at: usize,
    /// [`KeyIx`] built with the pushes ([`RunBuilder::index_at`]): window position and the integers so far.
    ix: Option<(usize, Vec<u64>)>,
    /// Tree leaf bytes of the entries pushed (removed ones included, removals take none).
    tree: usize,
}

impl RunBuilder {
    pub fn with_capacity(n: usize, bytes: usize) -> RunBuilder {
        RunBuilder {
            buf: Vec::with_capacity(bytes + n * EHDR),
            offs: Vec::with_capacity(n),
            gone: KillSet::default(),
            at: 0,
            ix: None,
            tree: 0,
        }
    }
    /// Build the run's [`KeyIx`] with the pushes, window at byte `at` (every key pushed must share its first `at` bytes
    /// with the others): a large run (compaction output) then seals without a pass over its keys.
    pub fn index_at(&mut self, at: usize) {
        self.ix = Some((at, Vec::with_capacity(self.offs.capacity())));
    }
    /// Append an entry: key = `pfx` + `key`, value = `vpfx` + `val` (the tree key / value record parts, no temporary); an
    /// empty value is a removal ([`is_tomb`]).
    #[inline]
    pub fn push(&mut self, pfx: &[u8], key: &[u8], vpfx: &[u8], val: &[u8]) {
        self.offs.push(self.buf.len() as u32);
        let (kl, vl) = (pfx.len() + key.len(), vpfx.len() + val.len());
        if vl > 0 {
            self.tree += 4 + kl + vl;
        }
        self.buf.extend_from_slice(&(kl as u16).to_le_bytes());
        self.buf.extend_from_slice(&(vl as u32).to_le_bytes());
        self.buf.extend_from_slice(pfx);
        self.buf.extend_from_slice(key);
        self.buf.extend_from_slice(vpfx);
        self.buf.extend_from_slice(val);
        if let Some((at, px)) = &mut self.ix {
            let k = &self.buf[self.buf.len() - vl - kl..self.buf.len() - vl];
            px.push(px_at(k, *at));
        }
    }
    /// Append an entry as encoded in a run buffer (header, key, value record): one copy.
    #[inline]
    fn push_enc(&mut self, e: &[u8]) {
        let (k, v) = ent(e, 0);
        if let Some((at, px)) = &mut self.ix {
            px.push(px_at(k, *at));
        }
        if !v.is_empty() {
            self.tree += 4 + k.len() + v.len();
        }
        self.offs.push(self.buf.len() as u32);
        self.buf.extend_from_slice(e);
    }
    /// Entries pushed (removed ones included).
    pub fn len(&self) -> usize {
        self.offs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.offs.len() == self.gone.len()
    }
    #[inline]
    pub fn entry(&self, i: usize) -> (&[u8], &[u8]) {
        ent(&self.buf, self.offs[i])
    }
    pub fn removed(&self, i: usize) -> bool {
        self.gone.get(i)
    }
    /// Index of the live entry with key `k`.
    pub fn find(&self, k: &[u8]) -> Option<usize> {
        let i = self
            .offs
            .binary_search_by(|&o| ent(&self.buf, o).0.cmp(k))
            .ok()?;
        (!self.removed(i)).then_some(i)
    }
    /// [`RunBuilder::find`] of a key of the run's object, searched forward from the previous call's position: the
    /// removals of a sorted key list cost O(log gap) each instead of O(log len); any key order stays correct.
    pub fn find_asc(&mut self, k: &[u8]) -> Option<usize> {
        let i = lower_bound_from(&self.buf, &self.offs, k, self.at);
        self.at = i;
        (i < self.offs.len() && ent(&self.buf, self.offs[i]).0 == k && !self.removed(i))
            .then_some(i)
    }
    /// Index range of the entries in `[a, b)` (removed ones included).
    pub fn range(&self, a: &[u8], b: &[u8]) -> std::ops::Range<usize> {
        let lo = self.offs.partition_point(|&o| ent(&self.buf, o).0 < a);
        let hi = self.offs.partition_point(|&o| ent(&self.buf, o).0 < b);
        lo..hi.max(lo)
    }
    pub fn remove(&mut self, i: usize) {
        self.gone.set(i, self.offs.len());
    }
    /// The run of object `id` (keys must be its omap keys, strictly ascending: checked in debug builds); `None` when
    /// every entry was removed.
    pub fn finish(self, id: u64) -> Option<RunBlob> {
        if self.is_empty() {
            return None;
        }
        let me = if self.gone.len() == 0 {
            self
        } else {
            let mut b = RunBuilder::with_capacity(self.len() - self.gone.len(), self.buf.len());
            for i in (0..self.len()).filter(|&i| !self.removed(i)) {
                let (k, v) = self.entry(i);
                b.push(k, &[], v, &[]);
            }
            b
        };
        let mut bloom = Bloom::new(me.offs.len());
        for &o in &me.offs {
            bloom.add(ent(&me.buf, o).0);
        }
        Some(me.seal(id, bloom))
    }
    /// The run with `bloom` already holding every key (built while the entries were pushed); no entry removed.
    fn seal(self, id: u64, bloom: Bloom) -> RunBlob {
        debug_assert_eq!(self.gone.len(), 0);
        assert!(
            run_fits(self.buf.len()),
            "run of {id}: {} entry bytes exceed the u32 offset space ({RUN_BYTES_MAX}): admission missed it",
            self.buf.len()
        );
        let ix = Arc::new(match self.ix {
            Some((lcp, px)) => {
                debug_assert!(
                    px.len() == self.offs.len()
                        && self.offs.iter().zip(&px).all(|(&o, &p)| {
                            let k = ent(&self.buf, o).0;
                            k.get(..lcp) == ent(&self.buf, self.offs[0]).0.get(..lcp)
                                && px_at(k, lcp) == p
                        }),
                    "incremental key index of run {id}"
                );
                KeyIx { lcp, px }
            }
            None => KeyIx::build(&self.buf, &self.offs),
        });
        let r = RunBlob {
            id,
            ord: 0,
            buf: Bytes::from(self.buf),
            offs: self.offs.into(),
            ix,
            bloom: Arc::new(bloom),
            tree: self.tree,
        };
        debug_assert!(
            r.valid(),
            "run of {id} not strictly ascending in its key space"
        );
        r
    }
}

/// Gallop over `[0, n)` with a predicate `less` that holds on a prefix: starts at `from` when `less(from - 1)` holds
/// (ascending searches: O(log gap) instead of O(log len)), else at 0, and doubles the step until a probe fails.
/// Returns `(lo, hi)`: `less` holds below `lo`, the first index where it fails lies in `[lo, hi]` (`hi` = the failed
/// probe or `n`), for a final binary search.
#[inline]
fn gallop(n: usize, from: usize, less: impl Fn(usize) -> bool) -> (usize, usize) {
    let mut lo = if from > 0 && from <= n && less(from - 1) {
        from
    } else {
        0
    };
    let (mut step, mut hi) = (1, n);
    while lo < n {
        let p = (lo + step - 1).min(n - 1);
        if less(p) {
            lo = p + 1;
            step *= 2;
        } else {
            hi = p;
            break;
        }
    }
    (lo, hi)
}

/// First index with key >= `k` among the entries `offs` of `buf` (keys of one object, ascending), searched forward from
/// `from` by a [`gallop`] when every key below `from` is smaller than `k`, else from the start.
fn lower_bound_from(buf: &[u8], offs: &[u32], k: &[u8], from: usize) -> usize {
    let less = |i: usize| okey_cmp(ent(buf, offs[i]).0, k).is_lt();
    let (lo, hi) = gallop(offs.len(), from, less);
    lo + offs[lo..hi].partition_point(|&o| okey_cmp(ent(buf, o).0, k).is_lt())
}

#[inline]
fn ent(buf: &[u8], o: u32) -> (&[u8], &[u8]) {
    let o = o as usize;
    let kl = u16::from_le_bytes([buf[o], buf[o + 1]]) as usize;
    let vl = u32::from_le_bytes([buf[o + 2], buf[o + 3], buf[o + 4], buf[o + 5]]) as usize;
    let k = o + EHDR;
    (&buf[k..k + kl], &buf[k + kl..k + kl + vl])
}

impl RunBlob {
    /// Validate a logged run (`n` entries in `buf`) and build its index and bloom. `None`: malformed, unsorted, or a key
    /// outside object `id`'s omap space.
    pub fn decode(id: u64, n: usize, buf: Bytes) -> Option<RunBlob> {
        if n == 0 || n > buf.len() / (EHDR + 10) {
            return None;
        }
        let mut offs = Vec::with_capacity(n);
        let (mut at, mut tree) = (0usize, 0usize);
        let mut prev: Option<&[u8]> = None;
        for _ in 0..n {
            if at + EHDR > buf.len() {
                return None;
            }
            let kl = u16::from_le_bytes([buf[at], buf[at + 1]]) as usize;
            let vl =
                u32::from_le_bytes([buf[at + 2], buf[at + 3], buf[at + 4], buf[at + 5]]) as usize;
            let end = (at + EHDR).checked_add(kl)?.checked_add(vl)?;
            if end > buf.len() {
                return None;
            }
            let k = &buf[at + EHDR..at + EHDR + kl];
            if omap_id(k) != Some(id) || prev.is_some_and(|p| p >= k) {
                return None;
            }
            prev = Some(k);
            offs.push(at as u32);
            if vl > 0 {
                tree += 4 + kl + vl;
            }
            at = end;
        }
        if at != buf.len() {
            return None;
        }
        let mut bloom = Bloom::new(n);
        for &o in &offs {
            bloom.add(ent(&buf, o).0);
        }
        Some(RunBlob {
            id,
            ord: 0,
            ix: Arc::new(KeyIx::build(&buf, &offs)),
            buf,
            offs: offs.into(),
            bloom: Arc::new(bloom),
            tree,
        })
    }

    fn valid(&self) -> bool {
        (0..self.len()).all(|i| {
            omap_id(self.key(i)) == Some(self.id) && (i == 0 || self.key(i - 1) < self.key(i))
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }
    /// Order lsn of a re-logged run (0: a new run).
    pub fn ord(&self) -> u64 {
        self.ord
    }
    /// The same entries as a re-log of the run with order lsn `ord` (> 0).
    pub fn with_ord(mut self, ord: u64) -> RunBlob {
        debug_assert!(ord > 0);
        self.ord = ord;
        self
    }
    /// Bytes of its WAL op encoding (`wal::encode_record`: header [`RUN_OP_HDR`], entries).
    pub fn wal_bytes(&self) -> usize {
        RUN_OP_HDR + self.buf.len()
    }
    pub fn len(&self) -> usize {
        self.offs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.offs.is_empty()
    }
    /// The logged bytes.
    pub fn raw(&self) -> &[u8] {
        &self.buf
    }
    #[inline]
    pub fn entry(&self, i: usize) -> (&[u8], &[u8]) {
        ent(&self.buf, self.offs[i])
    }
    #[inline]
    pub fn key(&self, i: usize) -> &[u8] {
        self.entry(i).0
    }
    /// Entry `i` as encoded (header, key, value record) and its key.
    #[inline]
    fn enc(&self, i: usize) -> (&[u8], &[u8]) {
        let o = self.offs[i] as usize;
        let (k, v) = ent(&self.buf, self.offs[i]);
        (&self.buf[o..o + EHDR + k.len() + v.len()], k)
    }
    pub fn first(&self) -> &[u8] {
        self.key(0)
    }
    pub fn last(&self) -> &[u8] {
        self.key(self.len() - 1)
    }
    /// Index of `k` (bloom, then binary search).
    #[inline]
    pub fn find(&self, k: &[u8]) -> Option<usize> {
        self.find_h(k, hash(k))
    }
    /// [`RunBlob::find`] with the key's hash computed once for all runs of an object.
    #[inline]
    fn find_h(&self, k: &[u8], h: u64) -> Option<usize> {
        if !self.bloom.may(h) {
            return None;
        }
        let i = self.lower_bound(k);
        (i < self.len() && self.key(i) == k).then_some(i)
    }
    /// `k` against the run's [`KeyIx`]: its integer when it shares the common prefix of the run's keys, else where it
    /// sorts (byte order, a key that is a proper prefix of another sorts first).
    #[inline]
    fn probe(&self, k: &[u8]) -> Probe {
        let l = self.ix.lcp;
        let c = &self.first()[..l];
        match k[..l.min(k.len())].cmp(&c[..l.min(k.len())]) {
            std::cmp::Ordering::Less => Probe::Bound(0),
            std::cmp::Ordering::Greater => Probe::Bound(self.len()),
            std::cmp::Ordering::Equal if k.len() < l => Probe::Bound(0),
            std::cmp::Ordering::Equal => Probe::At(px_at(k, l)),
        }
    }
    /// Is key `i` < `k` (`q` = the integer of `k`, [`RunBlob::probe`])? The key bytes are read only on equal integers.
    #[inline]
    fn below(&self, i: usize, q: u64, k: &[u8]) -> bool {
        let p = self.ix.px[i];
        p < q || (p == q && self.key(i) < k)
    }
    /// First entry whose index integer is >= `q`, only the index read: searched forward from `from` by a gallop when
    /// every integer below `from` is smaller (ascending searches: O(log gap) instead of O(log len)), else from the start.
    #[inline]
    fn ix_bound_from(&self, q: u64, from: usize) -> usize {
        let px = &self.ix.px;
        let (lo, hi) = gallop(px.len(), from, |i| px[i] < q);
        lo + px[lo..hi].partition_point(|&x| x < q)
    }
    /// Index of `k` (`q` = its integer, [`RunBlob::probe`]) given `i`, the first entry whose integer is `q`: one key
    /// compare, a search only when more entries share the integer.
    #[inline]
    fn find_at(&self, q: u64, k: &[u8], i: usize) -> Option<usize> {
        match self.key(i).cmp(k) {
            std::cmp::Ordering::Equal => Some(i),
            std::cmp::Ordering::Greater => None,
            std::cmp::Ordering::Less => {
                let i = self.bound_from(q, k, i + 1);
                (i < self.len() && self.key(i) == k).then_some(i)
            }
        }
    }
    /// [`RunBlob::lower_bound`] of `k` (`q` = its integer, [`RunBlob::probe`]) searched forward from `from` by a gallop
    /// when every key below `from` is smaller than `k` (ascending lookups: O(log gap) instead of O(log len)), else from
    /// the start.
    fn bound_from(&self, q: u64, k: &[u8], from: usize) -> usize {
        let (lo, hi) = gallop(self.len(), from, |i| self.below(i, q, k));
        self.bound_in(lo, hi, q, k)
    }
    /// First index in `[lo, hi)` whose key is >= `k` (`hi` if none; keys below `lo` are smaller, the key at `hi` is not).
    #[inline]
    fn bound_in(&self, mut lo: usize, mut hi: usize, q: u64, k: &[u8]) -> usize {
        while lo < hi {
            let m = lo + (hi - lo) / 2;
            if self.below(m, q, k) {
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        lo
    }
    /// First index with key >= `k`.
    pub fn lower_bound(&self, k: &[u8]) -> usize {
        match self.probe(k) {
            Probe::Bound(i) => i,
            Probe::At(q) => self.bound_in(0, self.len(), q, k),
        }
    }
    /// The same logged entries (one buffer).
    fn same(&self, o: &RunBlob) -> bool {
        self.buf.as_ptr() == o.buf.as_ptr() && self.buf.len() == o.buf.len()
    }
    /// Heap bytes held (buffer, index, bloom).
    pub fn mem(&self) -> usize {
        self.buf.len() + self.offs.len() * 4 + self.ix.bytes() + self.bloom.bytes()
    }
    /// Tree leaf bytes the entries take once merged (entry header of the page format: 4 B); a removal takes none.
    pub fn tree_bytes(&self) -> usize {
        self.tree
    }
}

/// One logged source of a run's entries: the run as first logged (its order lsn), the record holding its entries now
/// (the WAL floor), the WAL op bytes of a re-log of them (upper bound: the run as logged), and its live entries. A part
/// with no live entry holds no ring unit (it is not in the floor index).
#[derive(Clone, Debug)]
struct Part {
    ord: u64,
    rec: u64,
    wal: usize,
    live: usize,
}

/// A live run: its order lsn (its newest part's), its entries, the entries killed since (by later tree ops on their
/// keys), and its parts: one for a run as logged; a run built by a compaction keeps those of its inputs that still
/// hold live entries, each entry names its part.
#[derive(Clone, Debug)]
pub struct Run {
    pub lsn: u64,
    pub blob: RunBlob,
    dead: KillSet,
    parts: Vec<Part>,
    /// Part of each entry (empty: all in part 0).
    pidx: Vec<u16>,
}

impl Run {
    fn new(lsn: u64, rec: u64, blob: RunBlob) -> Run {
        let p = Part {
            ord: lsn,
            rec,
            wal: blob.wal_bytes(),
            live: blob.len(),
        };
        Run {
            lsn,
            blob,
            dead: KillSet::default(),
            parts: vec![p],
            pidx: Vec::new(),
        }
    }
    #[inline]
    pub fn is_dead(&self, i: usize) -> bool {
        self.dead.get(i)
    }
    #[inline]
    fn part_of(&self, i: usize) -> usize {
        self.pidx.get(i).map_or(0, |&p| p as usize)
    }
    /// Kill entry `i`: its part when it was live.
    fn kill(&mut self, i: usize) -> Option<usize> {
        if !self.dead.set(i, self.blob.len()) {
            return None;
        }
        let p = self.part_of(i);
        self.parts[p].live -= 1;
        Some(p)
    }
    /// Kill entries `[i0, i1)` (non-empty): the parts whose last live entry died, appended to `emptied`.
    fn kill_span(&mut self, i0: usize, i1: usize, emptied: &mut Vec<Part>) {
        let len = self.blob.len();
        if self.pidx.is_empty() {
            let n = self.dead.set_range(i0, i1, len, |_| ());
            let p = &mut self.parts[0];
            p.live -= n;
            if n > 0 && p.live == 0 {
                emptied.push(p.clone());
            }
        } else {
            let (parts, pidx) = (&mut self.parts, &self.pidx);
            self.dead.set_range(i0, i1, len, |i| {
                let p = &mut parts[pidx[i] as usize];
                p.live -= 1;
                if p.live == 0 {
                    emptied.push(p.clone());
                }
            });
        }
    }
    pub fn live(&self) -> usize {
        self.blob.len() - self.dead.len()
    }
    /// Parts held (1: a run as logged).
    pub fn n_parts(&self) -> usize {
        self.parts.len()
    }
    /// The live entries of part `p` as its re-log (`None`: none live).
    fn relog(&self, p: usize) -> Option<RunBlob> {
        let part = &self.parts[p];
        let n = self.blob.len().max(1);
        let mut b = RunBuilder::with_capacity(part.live, self.blob.buf.len() / n * part.live);
        for i in (0..self.blob.len()).filter(|&i| !self.is_dead(i) && self.part_of(i) == p) {
            let (k, v) = self.blob.entry(i);
            b.push(k, &[], v, &[]);
        }
        Some(b.finish(self.blob.id)?.with_ord(part.ord))
    }
}

/// Scratch of [`RunSet::kill_keys`], kept across records (no allocation per record).
#[derive(Debug, Default)]
struct KillBuf {
    /// [`hash`] of each key of the object's stretch.
    hs: Vec<u64>,
    /// Keys whose index integer one run holds: (key, first entry with that integer, the integer).
    cand: Vec<(u32, u32, u64)>,
    /// Entries to kill: (run, entry).
    hits: Vec<(u32, u32)>,
}

/// The runs of one object, ascending order lsn (a later run shadows an earlier one).
#[derive(Clone, Debug, Default)]
pub struct ObjRuns {
    pub runs: Vec<Run>,
    /// [`RunSet::inserted`] when the object last received a new run (idle merges).
    pub last_ins: u64,
    /// Every entry below this key is retired from the runs with order lsn <= the cutoff (merge slices from the object's
    /// first key on, [`RunSet::retire`]): (cutoff, key).
    pub retired: Option<(u64, Vec<u8>)>,
}

impl ObjRuns {
    /// [`ObjRuns::retired`] borrowed: scans start each covered run past its retired prefix (a skip of all-dead entries,
    /// not a walk over them).
    fn retired(&self) -> Option<(u64, &[u8])> {
        self.retired.as_ref().map(|(u, k)| (*u, k.as_slice()))
    }
}

/// Result of a run lookup.
#[derive(Debug, PartialEq, Eq)]
pub enum Hit<'a> {
    /// The newest run holding the key has it live: the value record.
    Live(&'a [u8]),
    /// The newest run holding the key removes it (a live removal entry): the key is absent, the tree is not asked.
    Gone,
    /// The runs hold the key, killed by a later tree op: the tree decides.
    Dead,
    /// No run holds the key.
    None,
}

/// All runs of a shard (part of `State`).
#[derive(Debug, Default)]
pub struct RunSet {
    objs: BTreeMap<u64, ObjRuns>,
    /// Parts with live entries by (record lsn, object, order lsn): the floor is the first. One record may hold runs of
    /// several objects.
    lsns: BTreeSet<(u64, u64, u64)>,
    /// WAL op bytes of those parts per record, and how many records hold each sum (the largest re-log of one record).
    recs: BTreeMap<u64, usize>,
    rec_sizes: BTreeMap<usize, u32>,
    mem: usize,
    tree_bytes: usize,
    entries: usize,
    nruns: usize,
    /// Runs inserted since creation (idle merges).
    inserted: u64,
    /// Entries of the new runs inserted since creation (merge pacing; re-logs do not count).
    admitted: u64,
    /// Objects by (`ObjRuns::last_ins`, id): the first is the one longest without a new run (idle merges).
    by_ins: BTreeSet<(u64, u64)>,
    /// Objects that received a run since their last compaction check (LIFO, each once: `queued` holds the members).
    cand: Vec<u64>,
    queued: crate::fx::FxSet<u64>,
    /// Re-logs of a compacted run's part (the part moved to the re-log's record).
    part_moves: u64,
    /// Changes (merge positions of an older version are stale).
    ver: u64,
    kb: KillBuf,
}

impl RunSet {
    pub fn is_empty(&self) -> bool {
        self.objs.is_empty()
    }
    /// Heap bytes held by the runs.
    pub fn mem(&self) -> usize {
        self.mem
    }
    /// Leaf bytes the runs' entries take once merged (upper bound of the tree growth).
    pub fn tree_bytes(&self) -> usize {
        self.tree_bytes
    }
    /// Entries held (live and killed).
    pub fn entries(&self) -> usize {
        self.entries
    }
    pub fn inserted(&self) -> u64 {
        self.inserted
    }

    /// Entries of the new runs inserted since creation (re-logs not counted).
    pub fn admitted(&self) -> u64 {
        self.admitted
    }
    pub fn n_runs(&self) -> usize {
        self.nruns
    }
    /// Entries of the runs killed by later tree ops (merged or superseded) but still held (lab timeline: a listing
    /// steps over them). Walks every run.
    pub fn dead_ents(&self) -> usize {
        self.objs
            .values()
            .flat_map(|o| &o.runs)
            .map(|r| r.dead.len())
            .sum()
    }
    /// Re-logs that moved a part of a compacted run to their record.
    pub fn part_moves(&self) -> u64 {
        self.part_moves
    }
    /// Record lsn of the oldest part with live entries (`None`: no runs): the WAL floor.
    pub fn floor(&self) -> Option<u64> {
        self.lsns.first().map(|x| x.0)
    }
    /// Object of the oldest live run (by record).
    pub fn oldest_obj(&self) -> Option<u64> {
        self.lsns.first().map(|x| x.1)
    }
    /// WAL op bytes of the live runs of the record holding the most (the largest re-log of one record).
    pub fn max_rec_bytes(&self) -> usize {
        self.rec_sizes.last_key_value().map_or(0, |(&b, _)| b)
    }
    /// Re-logs of the parts whose records lie in `[lo, hi]` (record lsns), oldest record first.
    pub fn relog_range(&self, lo: u64, hi: u64) -> Vec<RunBlob> {
        self.lsns
            .range((lo, 0, 0)..=(hi, u64::MAX, u64::MAX))
            .filter_map(|&(_, id, ord)| {
                let (ri, pi) = self.find_part(id, ord)?;
                self.objs[&id].runs[ri].relog(pi)
            })
            .collect()
    }
    /// Run index and part index of object `id`'s part with order lsn `ord` (the parts of the runs are disjoint,
    /// ascending ranges of order lsns).
    fn find_part(&self, id: u64, ord: u64) -> Option<(usize, usize)> {
        let runs = &self.objs.get(&id)?.runs;
        let ri = runs.partition_point(|r| r.lsn < ord);
        let pi = runs
            .get(ri)?
            .parts
            .binary_search_by_key(&ord, |p| p.ord)
            .ok()?;
        Some((ri, pi))
    }
    fn rec_size(&mut self, rec: u64, bytes: usize, add: bool) {
        let old = self.recs.get(&rec).copied().unwrap_or(0);
        let new = if add { old + bytes } else { old - bytes };
        if old > 0 {
            let c = self.rec_sizes.get_mut(&old).expect("record size counted");
            *c -= 1;
            if *c == 0 {
                self.rec_sizes.remove(&old);
            }
        }
        if new > 0 {
            self.recs.insert(rec, new);
            *self.rec_sizes.entry(new).or_default() += 1;
        } else {
            self.recs.remove(&rec);
        }
    }
    fn link(&mut self, id: u64, p: &Part) {
        self.lsns.insert((p.rec, id, p.ord));
        self.rec_size(p.rec, p.wal, true);
    }
    fn unlink_part(&mut self, id: u64, p: &Part) {
        self.lsns.remove(&(p.rec, id, p.ord));
        self.rec_size(p.rec, p.wal, false);
    }
    pub fn obj(&self, id: u64) -> Option<&ObjRuns> {
        self.objs.get(&id)
    }
    pub fn has_obj(&self, id: u64) -> bool {
        self.objs.contains_key(&id)
    }
    /// Objects with runs, ascending.
    pub fn ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.objs.keys().copied()
    }

    fn account(&mut self, r: &RunBlob, add: bool) {
        let (m, t, e) = (r.mem(), r.tree_bytes(), r.len());
        if add {
            self.mem += m;
            self.tree_bytes += t;
            self.entries += e;
            self.nruns += 1;
        } else {
            self.mem -= m;
            self.tree_bytes -= t;
            self.entries -= e;
            self.nruns -= 1;
        }
    }

    /// Apply a logged run of record `rec`: a new run (order `rec`, the newest of its object), or a re-log of the part
    /// with its order lsn: a part of a compacted run moves to the new record (its entries are there), a run as logged
    /// is replaced (replay: inserted at its order when the original record lies below the floor).
    pub fn insert(&mut self, rec: u64, blob: RunBlob) {
        self.ver += 1;
        let id = blob.id;
        let ord = if blob.ord == 0 { rec } else { blob.ord };
        self.inserted += 1;
        if blob.ord == 0 {
            self.admitted += blob.len() as u64;
        }
        if blob.ord != 0 {
            if let Some((ri, pi)) = self.find_part(id, ord)
                && self.objs[&id].runs[ri].parts.len() > 1
            {
                let old = self.objs[&id].runs[ri].parts[pi].clone();
                debug_assert_eq!(old.live, blob.len(), "re-log of a compacted run's part");
                self.unlink_part(id, &old);
                let p = &mut self.objs.get_mut(&id).unwrap().runs[ri].parts[pi];
                p.rec = rec;
                p.wal = blob.wal_bytes();
                let p = p.clone();
                self.link(id, &p);
                self.part_moves += 1;
                return;
            }
            self.remove(id, ord);
        }
        self.account(&blob, true);
        let run = Run::new(ord, rec, blob);
        self.link(id, &run.parts[0]);
        let fresh = !self.objs.contains_key(&id);
        let o = self.objs.entry(id).or_default();
        let old = o.last_ins;
        if ord == rec {
            o.last_ins = self.inserted;
        }
        let li = o.last_ins;
        let runs = &mut o.runs;
        let i = runs.partition_point(|r| r.lsn < ord);
        debug_assert!(
            runs.get(i).is_none_or(|r| r.parts[0].ord > ord),
            "run order lsn taken"
        );
        runs.insert(i, run);
        if fresh || li != old {
            self.by_ins.remove(&(old, id));
            self.by_ins.insert((li, id));
        }
        debug_assert_eq!(
            self.by_ins.len(),
            self.objs.len(),
            "idle index covers every object"
        );
        self.add_cand(id);
    }

    /// Remove the run of `id` holding order lsn `ord` alone (if live).
    fn remove(&mut self, id: u64, ord: u64) {
        let Some((ri, _)) = self.find_part(id, ord) else {
            return;
        };
        let o = self.objs.get_mut(&id).unwrap();
        debug_assert_eq!(o.runs[ri].parts.len(), 1, "replaced run is one part");
        let r = o.runs.remove(ri);
        if o.runs.is_empty() {
            self.forget(id);
        }
        self.unlink(&r);
    }

    fn unlink(&mut self, r: &Run) {
        for p in r.parts.iter().filter(|p| p.live > 0) {
            self.unlink_part(r.blob.id, p);
        }
        self.account(&r.blob, false);
    }

    /// Drop the runs of `id` whose entries are all killed (they would hold the floor for nothing).
    fn drop_dead(&mut self, id: u64) {
        self.ver += 1;
        let Some(o) = self.objs.get_mut(&id) else {
            return;
        };
        if o.runs.iter().all(|r| r.live() > 0) {
            return;
        }
        let (keep, gone): (Vec<Run>, Vec<Run>) = std::mem::take(&mut o.runs)
            .into_iter()
            .partition(|r| r.live() > 0);
        o.runs = keep;
        if o.runs.is_empty() {
            self.forget(id);
        }
        for r in gone {
            self.unlink(&r);
        }
    }

    /// Kill entry `i` of run `ri` of object `id`; a part left without live entries leaves the floor index. `true`: the
    /// run has no live entry left.
    /// [`RunSet::kill_at`] of every entry in `[i0, i1)` of run `ri` of `id`, one object lookup and dead bits set by
    /// words: true when an entry died and the run has none live left.
    fn kill_span(&mut self, id: u64, ri: usize, i0: usize, i1: usize) -> bool {
        if i0 >= i1 {
            return false;
        }
        self.ver += 1;
        let r = &mut self.objs.get_mut(&id).unwrap().runs[ri];
        let (before, mut gone) = (r.live(), Vec::new());
        r.kill_span(i0, i1, &mut gone);
        let empty = r.live() == 0 && before > 0;
        for p in &gone {
            self.unlink_part(id, p);
        }
        empty
    }

    fn kill_at(&mut self, id: u64, ri: usize, i: usize) -> bool {
        self.ver += 1;
        let r = &mut self.objs.get_mut(&id).unwrap().runs[ri];
        let Some(p) = r.kill(i) else {
            return false;
        };
        let empty = r.live() == 0;
        if r.parts[p].live == 0 {
            let p = r.parts[p].clone();
            self.unlink_part(id, &p);
        }
        empty
    }

    /// Point lookup of an omap tree key.
    #[inline]
    pub fn get(&self, k: &[u8]) -> Hit<'_> {
        let Some(o) = omap_id(k).and_then(|id| self.objs.get(&id)) else {
            return Hit::None;
        };
        let h = hash(k);
        for r in o.runs.iter().rev() {
            if let Some(i) = r.blob.find_h(k, h) {
                if r.is_dead(i) {
                    return Hit::Dead;
                }
                let v = r.blob.entry(i).1;
                return if is_tomb(v) { Hit::Gone } else { Hit::Live(v) };
            }
        }
        Hit::None
    }

    /// Kill `k` in every run of its object; returns its live value record (newest run) if it had one (a removal has
    /// none).
    pub fn kill(&mut self, k: &[u8]) -> Option<Vec<u8>> {
        self.kill_with(k, <[u8]>::to_vec)
    }

    /// Kill the keys of the leading ops of `ops` that have one (`key`; a record's stretch of tree puts and removals) in
    /// every run of their objects, values unread. Run-major (am. 15): the consecutive keys of one object go
    /// through each of its runs in two passes: bloom and index integers ([`KeyIx`]) give each key its first candidate
    /// entry, then the candidates' key bytes are compared (independent loads: no run-buffer miss sits between one key's
    /// search and the next). Ascending keys search each run forward from the previous key's position; any order is
    /// correct.
    pub fn kill_keys<T>(&mut self, ops: &[T], key: impl Fn(&T) -> Option<&[u8]>) {
        let ops = &ops[..ops.iter().take_while(|o| key(o).is_some()).count()];
        let id_of = |o: &T| key(o).and_then(omap_id);
        let mut s = 0;
        while s < ops.len() {
            let id = id_of(&ops[s]);
            let e = s + 1 + ops[s + 1..].iter().take_while(|o| id_of(o) == id).count();
            if let Some(id) = id {
                self.kill_keys_obj(id, &ops[s..e], &key);
            }
            s = e;
        }
    }

    /// [`RunSet::kill_keys`] of keys of object `id`.
    fn kill_keys_obj<T>(&mut self, id: u64, ops: &[T], key: &impl Fn(&T) -> Option<&[u8]>) {
        let Some(o) = self.objs.get(&id) else {
            return;
        };
        let k = |j: usize| key(&ops[j]).unwrap_or_default();
        let kb = &mut self.kb;
        kb.hs.clear();
        kb.hs.extend((0..ops.len()).map(|j| hash(k(j))));
        kb.hits.clear();
        for (ri, r) in o.runs.iter().enumerate() {
            let (b, n) = (&r.blob, r.blob.len());
            // bloom and index integers only: each key's first entry with its integer
            kb.cand.clear();
            let mut from = 0;
            for (j, &h) in kb.hs.iter().enumerate() {
                if !b.bloom.may(h) {
                    continue;
                }
                let Probe::At(q) = b.probe(k(j)) else {
                    continue;
                };
                let i = b.ix_bound_from(q, from);
                from = i;
                if i < n && b.ix.px[i] == q {
                    kb.cand.push((j as u32, i as u32, q));
                }
            }
            // the candidates' key bytes
            for &(j, i, q) in &kb.cand {
                if let Some(i) = b.find_at(q, k(j as usize), i as usize) {
                    kb.hits.push((ri as u32, i as u32));
                }
            }
        }
        let mut emptied = false;
        for x in 0..self.kb.hits.len() {
            let (ri, i) = self.kb.hits[x];
            emptied |= self.kill_at(id, ri as usize, i as usize);
        }
        if emptied {
            self.drop_dead(id);
        }
    }

    /// [`RunSet::kill`] handing the live value record (newest run; not a removal) to `live` instead of copying it.
    pub fn kill_with<R>(&mut self, k: &[u8], live: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let id = omap_id(k)?;
        let n = self.objs.get(&id)?.runs.len();
        let h = hash(k);
        let (mut live, mut out, mut emptied) = (Some(live), None, false);
        for ri in (0..n).rev() {
            let r = &self.objs[&id].runs[ri];
            let Some(i) = r.blob.find_h(k, h) else {
                continue;
            };
            // the newest run holding the key decides
            if let Some(f) = live.take()
                && !r.is_dead(i)
                && !is_tomb(r.blob.entry(i).1)
            {
                out = Some(f(r.blob.entry(i).1));
            }
            emptied |= self.kill_at(id, ri, i);
        }
        if emptied {
            self.drop_dead(id);
        }
        out
    }

    /// Kill every run entry in `[a, b)`.
    pub fn kill_range(&mut self, a: &[u8], b: &[u8]) {
        if self.objs.is_empty() {
            return;
        }
        let ids: Vec<u64> = self.ids_in(a, b).collect();
        for id in ids {
            for ri in 0..self.objs[&id].runs.len() {
                let r = &self.objs[&id].runs[ri];
                let (i0, i1) = (r.blob.lower_bound(a), r.blob.lower_bound(b));
                self.kill_span(id, ri, i0, i1);
            }
            self.drop_dead(id);
        }
    }

    /// Any run entry (live or not) in `[a, b)`?
    pub fn any_in(&self, a: &[u8], b: &[u8]) -> bool {
        self.ids_in(a, b).any(|id| {
            self.objs[&id].runs.iter().any(|r| {
                let i = r.blob.lower_bound(a);
                i < r.blob.len() && r.blob.key(i) < b
            })
        })
    }

    /// Objects whose omap key space intersects `[a, b)` (a superset at the low end: callers bound by key).
    fn ids_in<'s>(&'s self, a: &[u8], b: &'s [u8]) -> impl Iterator<Item = u64> + 's {
        let lo = match a.first() {
            Some(&t) if t > T_OMAP => None,
            Some(&T_OMAP) => {
                let mut x = [0u8; 8];
                let n = (a.len() - 1).min(8);
                x[..n].copy_from_slice(&a[1..1 + n]);
                Some(u64::from_be_bytes(x))
            }
            _ => Some(0),
        };
        lo.into_iter()
            .flat_map(move |lo| self.objs.range(lo..).map(|(&id, _)| id))
            .take_while(move |&id| key_lo(id).as_slice() < b)
    }

    /// Live entries in `[a, b)` in key order (newest run per key; killed keys left out, removals included: an empty value
    /// record, [`is_tomb`]).
    pub fn scan<'s>(
        &'s self,
        a: &'s [u8],
        b: &'s [u8],
    ) -> impl Iterator<Item = (&'s [u8], &'s [u8])> + 's {
        self.scan_except(a, b, &[])
    }

    /// [`RunSet::scan`] without the objects in `skip` (not visited at all: O(their runs), not O(their entries)).
    pub fn scan_except<'s>(
        &'s self,
        a: &'s [u8],
        b: &'s [u8],
        skip: &'s [u64],
    ) -> impl Iterator<Item = (&'s [u8], &'s [u8])> + 's {
        self.ids_in(a, b)
            .filter(move |id| !skip.contains(id))
            .flat_map(move |id| {
                let o = &self.objs[&id];
                Merge::new(o.runs.iter().collect(), a, b, o.retired())
            })
    }

    /// Live entries of object `id` in `[a, b)` among its runs with lsn <= `upto` (newest of those per key, removals
    /// included), as (run index of the object, entry index) in key order; valid while [`RunSet::ver`] is unchanged.
    pub fn merge_ix<'s>(
        &'s self,
        id: u64,
        upto: u64,
        a: &'s [u8],
        b: &'s [u8],
    ) -> impl Iterator<Item = (u32, u32)> + 's {
        // the runs at or below `upto` are a prefix of the object's runs: input j is run j
        let runs: Vec<&Run> = self
            .objs
            .get(&id)
            .map(|o| o.runs.iter().take_while(|r| r.lsn <= upto).collect())
            .unwrap_or_default();
        let mut m = Merge::new(runs, a, b, self.objs.get(&id).and_then(ObjRuns::retired));
        std::iter::from_fn(move || m.next_ix().map(|(j, i)| (j as u32, i as u32)))
    }
    /// Changes of the run set (any insert, kill, drop or swap).
    pub fn ver(&self) -> u64 {
        self.ver
    }

    /// Drop the runs of `id` with order lsn <= `upto` (merged into the tree).
    pub fn drop_upto(&mut self, id: u64, upto: u64) {
        self.ver += 1;
        let Some(o) = self.objs.get_mut(&id) else {
            return;
        };
        let n = o.runs.partition_point(|r| r.lsn <= upto);
        if o.retired.as_ref().is_some_and(|(u, _)| *u <= upto) {
            o.retired = None;
        }
        let gone: Vec<Run> = o.runs.drain(..n).collect();
        if o.runs.is_empty() {
            self.forget(id);
        }
        for r in gone {
            self.unlink(&r);
        }
    }

    /// A merge slice `[a, b)` of the runs of `id` with order lsn <= `upto` reached the tree (adr 0476, OQ 103): their
    /// entries in the slice leave the runs now (killed: parts without live entries leave the floor index), not at the
    /// merge's last slice, so live entries and the floor follow the merge; a run without live entries leaves. The run
    /// memory of the inputs returns at the last slice: rebuilding a half-dead run copies its live half in one step on the
    /// owner core (lab: commit max x2-4, doc/perf/omap-run-overlay-20261025.md). Runs newer than `upto` keep theirs (they
    /// shadow the merged values).
    pub fn retire(&mut self, id: u64, upto: u64, a: &[u8], b: &[u8]) {
        let Some(o) = self.objs.get(&id) else {
            return;
        };
        let n = o.runs.partition_point(|r| r.lsn <= upto);
        // the retired prefix grows by a slice from the object's first key or one continuing it under the same cutoff
        let lo = key_lo(id);
        if let Some(o) = self.objs.get_mut(&id)
            && (a <= lo.as_slice()
                || o.retired
                    .as_ref()
                    .is_some_and(|(u, k)| *u == upto && k.as_slice() >= a))
        {
            let k = match &o.retired {
                Some((u, k)) if *u == upto && k.as_slice() > b => k.clone(),
                _ => b.to_vec(),
            };
            o.retired = Some((upto, k));
        }
        let mut emptied = false;
        for ri in 0..n {
            let r = &self.objs[&id].runs[ri];
            let (i0, i1) = (r.blob.lower_bound(a), r.blob.lower_bound(b));
            emptied |= self.kill_span(id, ri, i0, i1);
        }
        if emptied {
            self.drop_dead(id);
        }
    }

    /// Drop every run of `id` (its omap was cleared or the object removed).
    pub fn drop_obj(&mut self, id: u64) {
        self.drop_upto(id, u64::MAX);
    }

    /// Newest order lsn among the runs of `id`.
    pub fn newest(&self, id: u64) -> Option<u64> {
        self.objs
            .get(&id)
            .and_then(|o| o.runs.last())
            .map(|r| r.lsn)
    }

    /// An object waits for a compaction check.
    pub fn has_cand(&self) -> bool {
        !self.cand.is_empty()
    }
    /// The object longest without a new run, if it received none since [`RunSet::inserted`] was `mark` (idle: its runs
    /// merge). Objects holding only replayed or re-logged runs count as idle from the start.
    pub fn idle_obj(&self, mark: u64) -> Option<u64> {
        self.by_ins
            .first()
            .filter(|&&(li, _)| li <= mark)
            .map(|&(_, id)| id)
    }

    /// `id` holds no run any more.
    fn forget(&mut self, id: u64) {
        if let Some(o) = self.objs.remove(&id) {
            self.by_ins.remove(&(o.last_ins, id));
        }
        debug_assert_eq!(
            self.by_ins.len(),
            self.objs.len(),
            "idle index covers every object"
        );
    }

    /// Next object to check for a compaction (it received runs since its last check).
    pub fn next_cand(&mut self) -> Option<u64> {
        let id = self.cand.pop()?;
        self.queued.remove(&id);
        Some(id)
    }
    /// Check object `id` again (a compaction of it ended); queued at most once.
    pub fn add_cand(&mut self, id: u64) {
        if self.queued.insert(id) {
            self.cand.push(id);
        }
    }

    /// A compaction of adjacent runs of object `id` above order lsn `barrier` (a tree merge in progress takes the runs at or
    /// below it) and outside the windows `busy` (order lsns of compactions under way): the oldest `fan` runs of the
    /// lowest size tier that has `fan` adjacent free runs (tier `t`: entries in `[fan^t, fan^(t+1))`; merged they reach a
    /// higher tier, so an object holds about `fan - 1` runs per tier); when the object holds `max` runs above the barrier
    /// (new batches wait) and no tier has `fan`, the `fan` (at least 2) adjacent free runs with the fewest entries. `None`:
    /// nothing to compact.
    pub fn compaction(
        &self,
        id: u64,
        fan: usize,
        max: usize,
        barrier: u64,
        busy: &[(u64, u64)],
    ) -> Option<Compaction> {
        let runs = &self.objs.get(&id)?.runs;
        let tier = |r: &Run| {
            let (mut t, mut x) = (0u32, fan);
            while r.blob.len() >= x {
                t += 1;
                x = x.saturating_mul(fan);
            }
            t
        };
        let free = |r: &Run| {
            r.lsn > barrier
                && !busy
                    .iter()
                    .any(|&(lo, hi)| r.lsn >= lo && r.parts[0].ord <= hi)
        };
        // maximal stretches of adjacent free runs of one tier: (tier, start, len)
        let mut best: Option<(u32, usize)> = None;
        let mut i = 0;
        while i < runs.len() {
            if !free(&runs[i]) {
                i += 1;
                continue;
            }
            let t = tier(&runs[i]);
            let mut j = i + 1;
            while j < runs.len() && free(&runs[j]) && tier(&runs[j]) == t {
                j += 1;
            }
            if j - i >= fan && best.is_none_or(|(bt, _)| t < bt) {
                best = Some((t, i));
            }
            i = j;
        }
        let w = match best {
            Some((_, s)) => &runs[s..s + fan],
            None if runs.iter().filter(|r| r.lsn > barrier).count() >= max => {
                // fewest entries among windows of `fan` (at least 2) adjacent free runs
                let k = fan.min(runs.len()).max(2);
                (0..=runs.len().saturating_sub(k))
                    .filter(|&s| runs[s..s + k].iter().all(free))
                    .min_by_key(|&s| runs[s..s + k].iter().map(|r| r.blob.len()).sum::<usize>())
                    .map(|s| &runs[s..s + k])?
            }
            None => return None,
        };
        // part indices are u16
        if w.iter().map(|r| r.parts.len()).sum::<usize>() > u16::MAX as usize + 1 {
            return None;
        }
        // inputs are a bit mask while stepping
        if w.len() > 64 {
            return None;
        }
        // the output holds at most the inputs' bytes: it must stay addressable
        let bytes = w.iter().map(|r| r.blob.buf.len()).sum::<usize>();
        if !run_fits(bytes) {
            return None;
        }
        let ins: Vec<Run> = w.to_vec();
        let n = ins.iter().map(|r| r.live()).sum::<usize>();
        // the output's keys lie between the smallest first and the largest last input key: their common prefix is one
        // of the output's, so its index is built with the pushes (no pass over a large output at the seal)
        let (lo, hi) = (
            ins.iter().map(|r| r.blob.first()).min().expect("inputs"),
            ins.iter().map(|r| r.blob.last()).max().expect("inputs"),
        );
        let mut out = RunBuilder::with_capacity(n, bytes);
        out.index_at(lo.iter().zip(hi).take_while(|(a, b)| a == b).count());
        let mut base = Vec::with_capacity(ins.len());
        let mut np = 0usize;
        for r in &ins {
            base.push(np);
            np += r.parts.len();
        }
        Some(Compaction {
            id,
            pos: vec![0; ins.len()],
            ins,
            out,
            bloom: Bloom::new(n),
            gp: Vec::with_capacity(n),
            base,
            live: vec![0; np],
            built: false,
            ready: None,
            helper_allowed: true,
        })
    }

    /// The inputs of `c` are still runs of its object (same order lsns and entry buffers, adjacent): its result can be
    /// swapped in. `false` stays false: an input left (merged, cleared, every entry killed) or was replaced (re-log of a
    /// run as logged).
    pub fn holds(&self, c: &Compaction) -> bool {
        self.inputs_at(c).is_some()
    }

    /// Index of the first input of `c` among its object's runs while [`RunSet::holds`].
    fn inputs_at(&self, c: &Compaction) -> Option<usize> {
        let runs = &self.objs.get(&c.id)?.runs;
        let n = c.ins.len();
        let first = runs.partition_point(|r| r.lsn < c.ins[0].lsn);
        (first + n <= runs.len()
            && c.ins
                .iter()
                .zip(&runs[first..first + n])
                .all(|(a, b)| a.lsn == b.lsn && a.blob.same(&b.blob)))
        .then_some(first)
    }

    /// Swap a finished compaction in when its inputs are still the object's runs ([`RunSet::holds`]; kills since its
    /// start apply to the result, parts take their current records). `false`: an input left or was replaced: the result
    /// is dropped.
    pub fn swap_in(&mut self, c: Compaction) -> bool {
        self.ver += 1;
        let id = c.id;
        let Some(first) = self.inputs_at(&c) else {
            return false;
        };
        let o = &self.objs[&id];
        let n = c.ins.len();
        let cur = &o.runs[first..first + n];
        let Compaction {
            ins,
            out,
            bloom,
            gp,
            base,
            mut live,
            ready,
            ..
        } = c;
        let (buf, offs) = ready
            .as_ref()
            .map_or((out.buf.as_slice(), out.offs.as_slice()), |b| {
                (b.buf.as_ref(), b.offs.as_ref())
            });
        // kills since the start (kills only add): each newly killed input entry that is the source of an output entry
        // kills it; the output entry of a key by binary search, its source input by its part. Inputs a tree merge
        // retires (all at or below its cutoff): every entry below the retired key is dead, so the output's prefix below
        // it dies at once and only the kills above it are looked up (a merge slice kills whole key ranges)
        let mut dead_now = Vec::new();
        let rk = o
            .retired
            .as_ref()
            .filter(|(u, _)| cur[n - 1].lsn <= *u)
            .map(|(_, k)| k.as_slice());
        if let Some(rk) = rk {
            let cut = offs.partition_point(|&o| ent(buf, o).0 < rk);
            for e in 0..cut {
                dead_now.push(e);
                live[gp[e] as usize] -= 1;
            }
        }
        for (j, (r, r0)) in cur.iter().zip(&ins).enumerate() {
            debug_assert_eq!(r.parts.len(), r0.parts.len());
            if r.dead.len() == r0.dead.len() {
                continue;
            }
            let parts = base[j]..base[j] + r.parts.len();
            let icut = rk.map_or(0, |k| r.blob.lower_bound(k));
            for (w, &word) in r.dead.words().iter().enumerate().skip(icut / 64) {
                let mut new = word & !r0.dead.words().get(w).copied().unwrap_or(0);
                if w == icut / 64 {
                    new &= !0u64 << (icut % 64);
                }
                while new != 0 {
                    let i = w * 64 + new.trailing_zeros() as usize;
                    new &= new - 1;
                    if let Ok(e) = offs.binary_search_by(|&o| ent(buf, o).0.cmp(r.blob.key(i)))
                        && parts.contains(&(gp[e] as usize))
                    {
                        dead_now.push(e);
                        live[gp[e] as usize] -= 1;
                    }
                }
            }
        }
        // parts with live output entries stay (same record: their floor index entry is unchanged); a part whose live
        // entries were all shadowed by newer runs leaves the floor index
        let np = live.len();
        let mut map = vec![0u16; np];
        let mut parts = Vec::new();
        let mut gone = Vec::new();
        for (j, r) in cur.iter().enumerate() {
            for (q, p) in r.parts.iter().enumerate() {
                let g = base[j] + q;
                if live[g] > 0 {
                    map[g] = parts.len() as u16;
                    parts.push(Part {
                        live: live[g],
                        ..p.clone()
                    });
                } else if p.live > 0 {
                    gone.push(p.clone());
                }
            }
        }
        let run = (!parts.is_empty()).then(|| {
            let blob = ready.unwrap_or_else(|| out.seal(id, bloom));
            // distinct: the retired prefix and the kills above it are disjoint, an output entry has one source input
            let dead = KillSet::from_indices(&dead_now, blob.len());
            debug_assert_eq!(dead.len(), dead_now.len());
            let pidx = if parts.len() == 1 {
                Vec::new()
            } else if parts.len() == np {
                gp
            } else {
                gp.iter().map(|&g| map[g as usize]).collect()
            };
            Run {
                lsn: parts.last().unwrap().ord,
                blob,
                dead,
                parts,
                pidx,
            }
        });
        for p in &gone {
            self.unlink_part(id, p);
        }
        let o = self.objs.get_mut(&id).unwrap();
        let nb = run.as_ref().map(|r| r.blob.clone());
        let old: Vec<Run> = o.runs.splice(first..first + n, run).collect();
        if o.runs.is_empty() {
            self.forget(id);
        }
        for r in &old {
            self.account(&r.blob, false);
        }
        if let Some(b) = &nb {
            self.account(b, true);
        }
        true
    }
}

/// A compaction of adjacent runs of one object into one (adr 0476 step 4): a k-way merge over clones of the input runs
/// (entry buffers shared, kills as of the start), built in slices off the client path; [`RunSet::swap_in`] installs it.
/// A pure function of its inputs: the result does not depend on where or when it is built.
#[derive(Debug)]
pub struct Compaction {
    id: u64,
    /// The inputs, oldest first, and the next entry of each.
    ins: Vec<Run>,
    pos: Vec<usize>,
    out: RunBuilder,
    /// Bloom of the output keys, built with them (sized for the live input entries).
    bloom: Bloom,
    /// Per output entry its input part (global: index into the inputs' parts in order); kills since the start and the
    /// parts left at swap time map through it.
    gp: Vec<u16>,
    /// Global index of each input's first part.
    base: Vec<usize>,
    /// Output entries per global part.
    live: Vec<usize>,
    /// Helper-side ownership conversion; Bloom and part counts are already built in `step`.
    built: bool,
    ready: Option<RunBlob>,
    helper_allowed: bool,
}

impl Compaction {
    pub fn id(&self) -> u64 {
        self.id
    }
    /// Input runs.
    pub fn inputs(&self) -> usize {
        self.ins.len()
    }
    /// Order lsns its inputs span (oldest part, newest run).
    pub fn window(&self) -> (u64, u64) {
        (self.ins[0].parts[0].ord, self.ins[self.ins.len() - 1].lsn)
    }
    /// Output entries so far.
    pub fn len(&self) -> usize {
        self.gp.len()
    }
    pub fn is_empty(&self) -> bool {
        self.gp.is_empty()
    }
    /// Input entries not yet merged.
    pub fn left(&self) -> usize {
        self.ins
            .iter()
            .zip(&self.pos)
            .map(|(r, &p)| r.blob.len() - p)
            .sum()
    }
    /// Heap bytes the result holds (counted with the run memory while it is built; its inputs are counted as the object's
    /// runs while [`RunSet::holds`] it): the output as allocated at the start (entry buffer at the inputs' bytes, offsets and
    /// search index at their live entries), bloom and part map.
    pub fn mem(&self) -> usize {
        self.out.buf.capacity()
            + self.out.offs.capacity() * (4 + 8)
            + self.bloom.bytes()
            + self.gp.capacity() * 2
            + self.ready.as_ref().map_or(0, |b| b.mem())
    }
    /// Conservative reservation while another core owns the job. Includes pinned input buffers even when still
    /// counted by the owner, cloned metadata, reserved output capacity, Bloom and owner reconciliation scratch.
    pub fn reservation(&self) -> usize {
        let n = self.out.offs.capacity();
        let parts = self.ins.iter().map(|r| r.parts.len()).sum::<usize>();
        self.out.buf.capacity()
            + std::mem::size_of::<crate::shard::RunCompactionJob>() + 256
            // index offsets and the search index of the sealed output (`KeyIx`)
            + n * (4 + 8)
            + self.gp.capacity() * std::mem::size_of::<u16>()
            + (self.base.capacity() + self.live.capacity()) * std::mem::size_of::<usize>()
            + (n * BLOOM_BITS).div_ceil(512).max(1) * 64
            // Deliberate slack for geometrically grown dead_now, pidx/dead bits, and ownership conversions.
            + n * 32
            // live/map and both geometrically grown Part vectors coexist with input clones at publication.
            + parts * (10 + 4 * std::mem::size_of::<Part>())
            + self.ins.len() * (8 + 2 * std::mem::size_of::<Run>())
            + self.pos.capacity() * std::mem::size_of::<usize>()
            + self.ins.capacity() * std::mem::size_of::<Run>()
            + self
                .ins
                .iter()
                .map(|r| {
                    r.blob.mem()
                        + r.dead.heap_bytes()
                        + r.pidx.capacity() * 2
                        + r.parts.capacity() * std::mem::size_of::<Part>()
                })
                .sum::<usize>()
    }
    pub fn built(&self) -> bool {
        self.built
    }
    pub fn helper_allowed(&self) -> bool {
        self.helper_allowed
    }
    pub fn keep_inline(&mut self) {
        self.helper_allowed = false;
    }
    /// Seal immutable output on the helper. Bloom and part metadata were built with each merge slice.
    /// The offset ownership conversion is proportional to the output, not a hard time-bounded slice.
    pub fn finish_output(&mut self) {
        if self.built {
            return;
        }
        debug_assert!(
            self.pos
                .iter()
                .zip(&self.ins)
                .all(|(p, r)| *p == r.blob.len())
        );
        let out = std::mem::take(&mut self.out);
        let bloom = std::mem::take(&mut self.bloom);
        self.ready = (!out.is_empty()).then(|| out.seal(self.id, bloom));
        self.built = true;
    }
    /// Merge up to `n` more input entries; `true` when done. Per key the newest input decides; a killed newest entry
    /// hides the key; a removal stays (older runs or the tree may hold the key) and cancels the older entries.
    pub fn step(&mut self, n: usize) -> bool {
        if self.built {
            return true;
        }
        let (ins, pos) = (&self.ins, &mut self.pos);
        for _ in 0..n {
            // one pass over the heads: the smallest key, the newest input holding it, and every input holding it
            let mut best: Option<(usize, &[u8])> = None;
            let mut same = 0u64;
            for (j, r) in ins.iter().enumerate() {
                if pos[j] < r.blob.len() {
                    let k = r.blob.key(pos[j]);
                    match best.map(|(_, bk)| okey_cmp(k, bk)) {
                        Some(std::cmp::Ordering::Greater) => {}
                        Some(std::cmp::Ordering::Equal) => {
                            best = Some((j, k));
                            same |= 1 << j;
                        }
                        _ => {
                            best = Some((j, k));
                            same = 1 << j;
                        }
                    }
                }
            }
            let Some((b, _)) = best else {
                return true;
            };
            let i = pos[b];
            while same != 0 {
                pos[same.trailing_zeros() as usize] += 1;
                same &= same - 1;
            }
            if !ins[b].is_dead(i) {
                let (e, k) = ins[b].blob.enc(i);
                self.out.push_enc(e);
                self.bloom.add(k);
                let g = self.base[b] + ins[b].part_of(i);
                self.gp.push(g as u16);
                self.live[g] += 1;
            }
        }
        (0..ins.len()).all(|j| pos[j] >= ins[j].blob.len())
    }
}

/// K-way merge of runs over `[a, b)`: per key the newest run (last in `runs`) decides; a killed newest entry hides the
/// key; a removal is yielded (callers drop the key). One pass over the live heads per entry (an object holds few runs: `run_max`, tiered by compaction): the smallest
/// key, the newest run holding it and every run holding it, keys cached per head (no entry decode per compare).
struct Merge<'s> {
    runs: Vec<&'s Run>,
    pos: Vec<usize>,
    end: Vec<usize>,
    /// Inputs with entries left, and the key of each one's head.
    act: Vec<usize>,
    head: Vec<&'s [u8]>,
    /// Scratch: the inputs holding the current key.
    same: Vec<usize>,
}

impl<'s> Merge<'s> {
    /// `retired`: [`ObjRuns::retired`]; the inputs it covers start past their retired (all dead) prefix.
    fn new(runs: Vec<&'s Run>, a: &[u8], b: &[u8], retired: Option<(u64, &[u8])>) -> Merge<'s> {
        let pos: Vec<usize> = runs
            .iter()
            .map(|r| match retired {
                Some((u, k)) if r.lsn <= u && k > a => r.blob.lower_bound(k),
                _ => r.blob.lower_bound(a),
            })
            .collect();
        let end: Vec<usize> = runs.iter().map(|r| r.blob.lower_bound(b)).collect();
        let act: Vec<usize> = (0..runs.len()).filter(|&j| pos[j] < end[j]).collect();
        let head = (0..runs.len())
            .map(|j| {
                if pos[j] < end[j] {
                    runs[j].blob.key(pos[j])
                } else {
                    &[][..]
                }
            })
            .collect();
        Merge {
            runs,
            pos,
            end,
            act,
            head,
            same: Vec::new(),
        }
    }

    /// The next live entry as (input, entry index).
    fn next_ix(&mut self) -> Option<(usize, usize)> {
        loop {
            let (&first, rest) = self.act.split_first()?;
            // the smallest head key; among equal keys the newest input (highest index)
            let (mut b, mut bk) = (first, self.head[first]);
            self.same.clear();
            self.same.push(first);
            for &j in rest {
                let k = self.head[j];
                match okey_cmp(k, bk) {
                    std::cmp::Ordering::Less => {
                        (b, bk) = (j, k);
                        self.same.clear();
                        self.same.push(j);
                    }
                    std::cmp::Ordering::Equal => {
                        if j > b {
                            b = j;
                        }
                        self.same.push(j);
                    }
                    std::cmp::Ordering::Greater => {}
                }
            }
            let i = self.pos[b];
            // every input holding the key moves past it (older ones are shadowed)
            let mut gone = false;
            for &j in &self.same {
                self.pos[j] += 1;
                if self.pos[j] < self.end[j] {
                    self.head[j] = self.runs[j].blob.key(self.pos[j]);
                } else {
                    gone = true;
                }
            }
            if gone {
                let (pos, end) = (&self.pos, &self.end);
                self.act.retain(|&j| pos[j] < end[j]);
            }
            if !self.runs[b].is_dead(i) {
                return Some((b, i));
            }
        }
    }
}

impl<'s> Iterator for Merge<'s> {
    type Item = (&'s [u8], &'s [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let (j, i) = self.next_ix()?;
        Some(self.runs[j].blob.entry(i))
    }
}

/// Run memory budget shared by the shards of a store and by the per-core stores of a device: a hot object's shard uses
/// the share of idle ones.
#[derive(Debug, Default)]
pub struct RunPool {
    bytes: AtomicUsize,
    soft: AtomicUsize,
    helpers: AtomicUsize,
    /// Publications that lowered a member's run bytes ([`RunPool::freed`]).
    freed: AtomicU64,
}

impl RunPool {
    /// Run bytes of all members.
    pub fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }
    /// Sum of the members' soft sizes.
    pub fn soft(&self) -> usize {
        self.soft.load(Ordering::Relaxed)
    }
    pub fn helper_bytes(&self) -> usize {
        self.helpers.load(Ordering::Relaxed)
    }
    /// How often a member lowered its run bytes: run room may have come back. A shard's run room depends on the bytes of
    /// every member (other cores' stores included), so a txn waiting for it is retried when this moves, not only on its
    /// own shard's progress.
    pub fn freed(&self) -> u64 {
        self.freed.load(Ordering::Relaxed)
    }
}

/// Shared remote-work credit follows the job, not its original owner Store's lifetime.
#[derive(Debug)]
pub struct HelperPermit {
    pool: Arc<RunPool>,
    bytes: usize,
}

impl Drop for HelperPermit {
    fn drop(&mut self) {
        self.pool.helpers.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// One shard's membership in a [`RunPool`]: its soft size and the run bytes it published; leaving (drop) takes both
/// back out.
#[derive(Debug)]
pub struct PoolShare {
    pool: Arc<RunPool>,
    soft: usize,
    published: usize,
}

impl PoolShare {
    pub fn join(pool: Arc<RunPool>, soft: usize) -> PoolShare {
        pool.soft.fetch_add(soft, Ordering::Relaxed);
        PoolShare {
            pool,
            soft,
            published: 0,
        }
    }
    pub fn pool(&self) -> &RunPool {
        &self.pool
    }
    /// Across all owners, remote jobs reserve at most one shared soft share (additional to live-run accounting).
    pub fn reserve_helper(&self, bytes: usize) -> Option<HelperPermit> {
        self.pool
            .helpers
            .try_update(Ordering::AcqRel, Ordering::Relaxed, |used| {
                used.checked_add(bytes).filter(|&n| n <= self.pool.soft())
            })
            .ok()?;
        Some(HelperPermit {
            pool: self.pool.clone(),
            bytes,
        })
    }
    /// Make the shard's current run bytes visible to the other members.
    pub fn publish(&mut self, bytes: usize) {
        if bytes > self.published {
            self.pool
                .bytes
                .fetch_add(bytes - self.published, Ordering::Relaxed);
        } else if bytes < self.published {
            self.pool
                .bytes
                .fetch_sub(self.published - bytes, Ordering::Relaxed);
            self.pool.freed.fetch_add(1, Ordering::Relaxed);
        }
        self.published = bytes;
    }
}

impl Drop for PoolShare {
    fn drop(&mut self) {
        self.publish(0);
        self.pool.soft.fetch_sub(self.soft, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_shares() {
        let p = Arc::new(RunPool::default());
        let mut a = PoolShare::join(p.clone(), 10);
        let mut b = PoolShare::join(p.clone(), 10);
        a.publish(7);
        b.publish(5);
        a.publish(3);
        assert_eq!((p.bytes(), p.soft()), (8, 20));
        drop(a);
        assert_eq!((p.bytes(), p.soft()), (5, 10));
        drop(b);
        assert_eq!((p.bytes(), p.soft()), (0, 0));
    }

    fn key(id: u64, u: &[u8]) -> Vec<u8> {
        crate::obj::keys::omap_key(id, u)
    }

    fn run(id: u64, kv: &[(&[u8], &[u8])]) -> RunBlob {
        let mut b = RunBuilder::default();
        let p = key_lo(id);
        for (k, v) in kv {
            b.push(&p, k, &[0], v);
        }
        b.finish(id).unwrap()
    }

    /// The `KeyIx` searches (`lower_bound`, the gallops `bound_from` and `ix_bound_from`, `find`, `find_at`) equal a
    /// plain byte-order search of the offsets for runs with long shared prefixes, keys that are prefixes of others, ties
    /// in the 8 index bytes, and probes outside the common prefix (other objects, shorter and longer keys); also after a
    /// WAL decode.
    #[test]
    fn key_index_search_equals_byte_search() {
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = |m: u64| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s % m
        };
        let alpha = [0u8, 1, b'a', b'b', 0xff];
        for case in 0..60 {
            let shared: Vec<u8> = (0..rnd(14)).map(|_| alpha[rnd(5) as usize]).collect();
            let mut us: Vec<Vec<u8>> = (0..1 + rnd(300))
                .map(|_| {
                    let mut u = shared.clone();
                    u.extend((0..rnd(12)).map(|_| alpha[rnd(5) as usize]));
                    u
                })
                .collect();
            us.sort();
            us.dedup();
            let kv: Vec<(&[u8], &[u8])> = us.iter().map(|u| (u.as_slice(), &b"v"[..])).collect();
            let r = run(7, &kv);
            let d = RunBlob::decode(7, r.len(), Bytes::copy_from_slice(r.raw())).unwrap();
            assert!(d == r, "case {case}: decode builds the same index");
            let plain = |k: &[u8]| r.offs.partition_point(|&o| ent(&r.buf, o).0 < k);
            let mut qs: Vec<Vec<u8>> = us.iter().map(|u| key(7, u)).collect();
            for _ in 0..200 {
                let mut u = shared[..rnd(shared.len() as u64 + 1) as usize].to_vec();
                u.extend((0..rnd(14)).map(|_| alpha[rnd(5) as usize]));
                qs.push(key(6 + rnd(3), &u));
            }
            qs.push(key(7, b""));
            qs.push(vec![T_OMAP]);
            qs.sort();
            let mut from = 0;
            for q in &qs {
                let want = plain(q);
                assert_eq!(r.lower_bound(q), want, "case {case} key {q:?}");
                let hit = (want < r.len() && r.key(want) == q.as_slice()).then_some(want);
                assert_eq!(r.find(q), hit, "case {case} find {q:?}");
                let f = match r.probe(q) {
                    Probe::Bound(i) => i,
                    Probe::At(x) => {
                        let px = &r.ix.px;
                        let i = r.ix_bound_from(x, from);
                        assert_eq!(
                            i,
                            px.partition_point(|&p| p < x),
                            "case {case} {q:?} {from}"
                        );
                        // `kill_keys`: the first entry with the key's integer, then the key bytes
                        let at = (i < r.len() && px[i] == x).then(|| r.find_at(x, q, i));
                        assert_eq!(at.flatten(), hit, "case {case} find_at {q:?}");
                        r.bound_from(x, q, from)
                    }
                };
                assert_eq!(f, want, "case {case} gallop key {q:?} from {from}");
                from = if rnd(4) == 0 {
                    rnd(r.len() as u64 + 2) as usize
                } else {
                    f
                };
            }
        }
    }

    #[test]
    fn blob_roundtrip_and_find() {
        let r = run(7, &[(b"a", b"1"), (b"b", b"22"), (b"c", b"")]);
        assert_eq!(r.len(), 3);
        assert_eq!(r.entry(1), (&key(7, b"b")[..], &b"\x0022"[..]));
        assert_eq!(r.find(&key(7, b"c")), Some(2));
        assert_eq!(r.find(&key(7, b"d")), None);
        assert_eq!(r.lower_bound(&key(7, b"bb")), 2);
        let d = RunBlob::decode(7, 3, r.buf.clone()).unwrap();
        assert_eq!(d, r);
        assert!(
            RunBlob::decode(8, 3, r.buf.clone()).is_none(),
            "other object"
        );
        assert!(RunBlob::decode(7, 2, r.buf.clone()).is_none(), "trailing");
        assert!(RunBlob::decode(7, 4, r.buf.clone()).is_none(), "short");
        let u = run(7, &[(b"a", b"1")]);
        let mut cat = r.buf.to_vec();
        cat.extend_from_slice(&u.buf);
        assert!(RunBlob::decode(7, 4, cat.into()).is_none(), "not ascending");
        assert_eq!(r.tree_bytes(), r.raw().len() - 3 * 2);
    }

    #[test]
    fn overlay_kill_scan_merge() {
        let mut s = RunSet::default();
        s.insert(10, run(1, &[(b"a", b"1"), (b"c", b"1")]));
        s.insert(11, run(2, &[(b"a", b"x")]));
        s.insert(12, run(1, &[(b"b", b"2"), (b"c", b"2")]));
        assert_eq!(s.floor(), Some(10));
        assert_eq!(s.get(&key(1, b"c")), Hit::Live(b"\x002"));
        assert_eq!(s.get(&key(1, b"a")), Hit::Live(b"\x001"));
        assert_eq!(s.get(&key(1, b"z")), Hit::None);
        let (a, b) = (key(1, b""), key(2, b""));
        let all: Vec<_> = s
            .scan(&a, &b)
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        assert_eq!(
            all,
            vec![
                (key(1, b"a"), b"\x001".to_vec()),
                (key(1, b"b"), b"\x002".to_vec()),
                (key(1, b"c"), b"\x002".to_vec())
            ]
        );
        // a tree op on c kills it in both runs; the newest live value is returned once
        assert_eq!(s.kill(&key(1, b"c")), Some(b"\x002".to_vec()));
        assert_eq!(s.kill(&key(1, b"c")), None);
        assert_eq!(s.get(&key(1, b"c")), Hit::Dead);
        assert_eq!(s.scan(&a, &b).count(), 2);
        // merge view of the older run only
        let o = &s.obj(1).unwrap().runs;
        let m: Vec<_> = s
            .merge_ix(1, 10, &a, &b)
            .map(|(j, i)| o[j as usize].blob.key(i as usize).to_vec())
            .collect();
        assert_eq!(m, vec![key(1, b"a")]);
        // whole-space scan sees both objects
        assert_eq!(s.scan(b"a", b"p").count(), 3);
        assert_eq!(s.scan(&key(1, b"b"), &key(1, b"c")).count(), 1);
        assert!(s.any_in(&key(2, b""), &key(3, b"")));
        assert!(!s.any_in(&key(3, b""), &key(4, b"")));
        assert_eq!(s.scan(&key(1, b""), &key(1, b"b\xff")).count(), 2);
        s.kill_range(&key(1, b""), &key(1, b"b\xff"));
        assert_eq!(s.scan(&a, &b).count(), 0);
        s.drop_upto(1, 10);
        assert_eq!(s.floor(), Some(11));
        s.drop_obj(1);
        s.drop_obj(2);
        assert!(s.is_empty());
        assert_eq!((s.mem(), s.entries(), s.tree_bytes()), (0, 0, 0));
    }

    /// A run of removals of object `id` (keys ascending).
    fn rm(id: u64, ks: &[&[u8]]) -> RunBlob {
        let mut b = RunBuilder::default();
        let p = key_lo(id);
        for k in ks {
            b.push(&p, k, &[], &[]);
        }
        b.finish(id).unwrap()
    }

    /// Removal entries (adr 0647 D1): a live removal hides its key from point reads (no tree lookup) and stays in the
    /// views (scan, merge positions) as an empty value record; a later run brings the key back, a tree op kills the
    /// removal like any entry; compaction keeps the newest entry per key, the removal over older puts; re-log and WAL
    /// decode keep removals; removals take no tree bytes.
    #[test]
    fn removals_shadow_compact_and_relog() {
        let mut s = RunSet::default();
        s.insert(10, run(1, &[(b"a", b"1"), (b"b", b"1"), (b"c", b"1")]));
        s.insert(11, rm(1, &[b"b", b"d"]));
        assert_eq!(
            s.tree_bytes(),
            3 * (4 + 11 + 2),
            "removals take no tree bytes"
        );
        assert_eq!(s.get(&key(1, b"a")), Hit::Live(b"\x001"));
        assert_eq!(s.get(&key(1, b"b")), Hit::Gone);
        assert_eq!(s.get(&key(1, b"d")), Hit::Gone);
        assert_eq!(s.get(&key(1, b"z")), Hit::None);
        let full = |v: &[u8]| v.to_vec();
        assert_eq!(
            view(&s, 1),
            vec![
                (key(1, b"a"), full(b"\x001")),
                (key(1, b"b"), vec![]),
                (key(1, b"c"), full(b"\x001")),
                (key(1, b"d"), vec![]),
            ]
        );
        let o = &s.obj(1).unwrap().runs;
        let (a, b) = (key(1, b""), key(2, b""));
        let m: Vec<_> = s
            .merge_ix(1, 11, &a, &b)
            .map(|(j, i)| (j, o[j as usize].blob.key(i as usize).to_vec()))
            .collect();
        assert_eq!(
            m,
            vec![
                (0, key(1, b"a")),
                (1, key(1, b"b")),
                (0, key(1, b"c")),
                (1, key(1, b"d"))
            ]
        );
        // re-log and WAL decode keep the removals
        let rl = s.relog_range(11, 11);
        assert_eq!(rl.len(), 1);
        assert!((0..rl[0].len()).all(|i| is_tomb(rl[0].entry(i).1)));
        let d = RunBlob::decode(1, 2, Bytes::copy_from_slice(rl[0].raw())).unwrap();
        assert_eq!((d.len(), d.tree_bytes()), (2, 0));
        assert_eq!(d.entry(1), (&key(1, b"d")[..], &b""[..]));
        // a removal has no value to hand out; the kill leaves the tree to decide
        assert_eq!(s.kill(&key(1, b"d")), None);
        assert_eq!(s.get(&key(1, b"d")), Hit::Dead);
        // a later run brings a removed key back; a compaction keeps the newest entry of every key
        s.insert(12, run(1, &[(b"b", b"3"), (b"e", b"3")]));
        s.insert(13, rm(1, &[b"a", b"e"]));
        let before = view(&s, 1);
        assert_eq!(
            before,
            vec![
                (key(1, b"a"), vec![]),
                (key(1, b"b"), full(b"\x003")),
                (key(1, b"c"), full(b"\x001")),
                (key(1, b"e"), vec![]),
            ]
        );
        let mut c = s.compaction(1, 4, 16, 0, &[]).unwrap();
        while !c.step(2) {}
        assert!(s.swap_in(c));
        assert_eq!(s.n_runs(), 1);
        assert_eq!(view(&s, 1), before);
        assert_eq!(
            s.entries(),
            4,
            "one entry per key: the removal cancelled the older puts"
        );
        assert_eq!(s.tree_bytes(), 2 * (4 + 11 + 2));
        assert_eq!(s.get(&key(1, b"a")), Hit::Gone);
        assert_eq!(s.get(&key(1, b"b")), Hit::Live(b"\x003"));
        s.drop_obj(1);
        assert_eq!((s.mem(), s.entries(), s.tree_bytes()), (0, 0, 0));
    }

    #[test]
    fn builder_remove() {
        let mut b = RunBuilder::default();
        let p = key(5, b"");
        for k in [&b"a"[..], b"b", b"c"] {
            b.push(&p, k, &[0], b"v");
        }
        assert_eq!(b.find(&key(5, b"b")), Some(1));
        assert_eq!(b.range(&key(5, b"b"), &key(5, b"z")), 1..3);
        b.remove(1);
        assert_eq!(b.find(&key(5, b"b")), None);
        let r = b.clone().finish(5).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r.key(1), &key(5, b"c")[..]);
        b.remove(0);
        b.remove(2);
        assert!(b.finish(5).is_none());
    }

    #[test]
    fn helper_sealed_output_preserves_late_kills_and_newer_runs() {
        fn send<T: Send>() {}
        send::<Compaction>();
        send::<crate::shard::RunCompactionJob>();
        let mut s = RunSet::default();
        s.insert(10, run(1, &[(b"a", b"1"), (b"b", b"old")]));
        s.insert(11, run(1, &[(b"b", b"new"), (b"c", b"3")]));
        let before = view(&s, 1);
        let mut c = s.compaction(1, 2, 4, 0, &[]).unwrap();
        let reserved = c.reservation();
        while !c.step(1) {
            assert!(c.mem() <= reserved);
        }
        c.finish_output();
        assert!(c.mem() <= reserved);
        assert_eq!(view(&s, 1), before, "helper cannot publish");
        s.kill(&key(1, b"b"));
        s.insert(12, run(1, &[(b"c", b"later"), (b"d", b"4")]));
        let expected = view(&s, 1);
        assert!(s.swap_in(c));
        assert_eq!(view(&s, 1), expected);
        assert_eq!(s.get(&key(1, b"a")), Hit::Live(b"\x001"));
        assert_eq!(s.get(&key(1, b"c")), Hit::Live(b"\x00later"));
    }

    #[test]
    fn helper_finished_result_rejected_after_object_replacement() {
        let mut s = RunSet::default();
        s.insert(10, run(1, &[(b"a", b"old")]));
        s.insert(11, run(1, &[(b"b", b"old")]));
        let mut c = s.compaction(1, 2, 4, 0, &[]).unwrap();
        while !c.step(1) {}
        c.finish_output();
        s.drop_obj(1);
        s.insert(11, run(1, &[(b"z", b"replacement")]));
        assert!(!s.swap_in(c));
        assert_eq!(
            view(&s, 1),
            vec![(key(1, b"z"), b"\x00replacement".to_vec())]
        );
        assert_eq!(s.floor(), Some(11));
    }

    fn view(s: &RunSet, id: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
        let (a, b) = (key(id, b""), key(id + 1, b""));
        s.scan(&a, &b)
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect()
    }

    /// `RunBuilder::find_asc` answers as `find` for ascending, repeated, absent and out-of-order keys and removed entries.
    #[test]
    fn builder_find_asc_equals_find() {
        let ks: Vec<Vec<u8>> = (0..200u32)
            .map(|i| format!("{:05}", i * 3).into_bytes())
            .collect();
        let kv: Vec<(&[u8], &[u8])> = ks.iter().map(|q| (q.as_slice(), &b"v"[..])).collect();
        let mut b = RunBuilder::default();
        let p = key(4, b"");
        for (k, v) in &kv {
            b.push(&p, k, &[0], v);
        }
        b.remove(10);
        let qs: Vec<u32> = (0..650).chain([5, 4, 300, 30, 30, 599, 0, 597]).collect();
        for q in qs {
            let k = key(4, format!("{q:05}").as_bytes());
            assert_eq!(b.find_asc(&k), b.find(&k), "key {q}");
        }
    }

    /// `kill_keys` (run-major, two passes per run) leaves the same runs, entries and floor as `kill` per key for
    /// ascending keys, keys absent from the runs, keys out of order, repeated keys, many keys sharing their index
    /// integer, keys of two objects (one object in two separate parts of the batch) and runs that leave in the batch
    /// (all entries killed); the ops from the first one without a key on stay.
    #[test]
    fn kill_keys_equals_kill() {
        let mut x = 0x9e37_79b9_u64;
        let mut rnd = move |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        for round in 0..40 {
            // odd rounds: keys sharing their first 8 bytes in 7 groups (index integer ties)
            let k = |i: u64| match round % 2 {
                0 => format!("{:08x}", i.wrapping_mul(0x9e37_79b9) % 4_000_000_000).into_bytes(),
                _ => format!("{}-shared-{i:05}", i % 7).into_bytes(),
            };
            let (mut a, mut b) = (RunSet::default(), RunSet::default());
            for r in 0..1 + rnd(6) {
                for id in [1, 2] {
                    let mut ks: Vec<Vec<u8>> = (0..1 + rnd(300)).map(|_| k(rnd(600))).collect();
                    ks.sort();
                    ks.dedup();
                    let kv: Vec<(&[u8], &[u8])> =
                        ks.iter().map(|q| (q.as_slice(), &b"v"[..])).collect();
                    a.insert(10 + 2 * r + id, run(id, &kv));
                    b.insert(10 + 2 * r + id, run(id, &kv));
                }
            }
            let mut ops: Vec<Option<Vec<u8>>> = Vec::new();
            for id in [1, 2, 1] {
                let mut ks: Vec<Vec<u8>> =
                    (0..1 + rnd(400)).map(|_| key(id, &k(rnd(600)))).collect();
                ks.sort();
                ks.dedup();
                ops.extend(ks.into_iter().map(Some));
            }
            // a few keys out of order or repeated
            for _ in 0..round % 4 {
                let q = match rnd(2) {
                    0 => key(1 + rnd(2), &k(rnd(600))),
                    _ => ops[rnd(ops.len() as u64) as usize].clone().unwrap(),
                };
                ops.insert(rnd(ops.len() as u64 + 1) as usize, Some(q));
            }
            if round % 3 == 0 {
                ops.insert(rnd(ops.len() as u64 + 1) as usize, None);
            }
            for q in ops.iter().map_while(|o| o.as_ref()) {
                a.kill(q);
            }
            b.kill_keys(&ops, |o| o.as_deref());
            for id in [1, 2] {
                assert_eq!(view(&a, id), view(&b, id), "round {round} object {id}");
            }
            assert_eq!(a.n_runs(), b.n_runs(), "round {round}");
            assert_eq!(a.lsns, b.lsns, "round {round}");
            assert_eq!(a.entries(), b.entries(), "round {round}");
        }
    }

    /// A compaction over runs a tree merge retires while it is built: the swap-in kills the retired prefix in bulk and
    /// looks up the other kills; view, floor and part counts equal those of the per-kill path (the same retires and
    /// kills, retired key forgotten).
    #[test]
    fn compaction_over_retired_runs() {
        let k = |i: u32| format!("k{i:04}").into_bytes();
        let build = |bulk: bool| {
            let mut s = RunSet::default();
            for g in 0..4u64 {
                let kv: Vec<(Vec<u8>, Vec<u8>)> = (0..50)
                    .map(|i| (k(i * 4 + g as u32), vec![g as u8]))
                    .collect();
                let kv: Vec<(&[u8], &[u8])> = kv
                    .iter()
                    .map(|(a, b)| (a.as_slice(), b.as_slice()))
                    .collect();
                s.insert(10 + g, run(1, &kv));
            }
            s.insert(20, run(1, &[(&k(3), b"n"), (&k(150), b"n")]));
            let mut c = s.compaction(1, 4, 16, 0, &[]).unwrap();
            assert_eq!(c.inputs(), 4);
            while !c.step(7) {}
            // a merge up to 13 retires [k0, k80) in two slices, a tree op kills k120 (all runs)
            s.retire(1, 13, &key(1, b""), &key(1, &k(40)));
            s.retire(1, 13, &key(1, &k(40)), &key(1, &k(80)));
            s.kill(&key(1, &k(120)));
            if !bulk {
                s.objs.get_mut(&1).unwrap().retired = None;
            }
            assert!(s.swap_in(c));
            let o = &s.obj(1).unwrap().runs;
            let parts: Vec<_> = o
                .iter()
                .flat_map(|r| r.parts.iter().map(|p| (p.ord, p.live)))
                .collect();
            (
                view(&s, 1),
                s.lsns.iter().copied().collect::<Vec<_>>(),
                parts,
                s.n_runs(),
            )
        };
        let (bulk, per_kill) = (build(true), build(false));
        assert_eq!(bulk, per_kill);
        let v = &bulk.0;
        assert!(
            v.iter()
                .all(|(kk, _)| kk.as_slice() >= key(1, &k(80)).as_slice() || kk == &key(1, &k(3)))
        );
        assert!(!v.iter().any(|(kk, _)| kk == &key(1, &k(120))));
        assert_eq!(bulk.3, 2);
    }

    /// Compaction keeps the merged view, kills that happen while it is built, and the floor of every part with live
    /// entries; re-logs of its parts move them to their new records.
    #[test]
    fn compaction_view_kills_floor_relog() {
        let mut s = RunSet::default();
        s.insert(10, run(1, &[(b"a", b"1"), (b"b", b"1"), (b"c", b"1")]));
        s.insert(11, run(2, &[(b"x", b"1")]));
        s.insert(12, run(1, &[(b"a", b"2"), (b"d", b"2")]));
        s.insert(13, run(1, &[(b"b", b"3"), (b"e", b"3")]));
        s.insert(14, run(1, &[(b"a", b"4"), (b"b", b"4")]));
        assert_eq!(s.n_runs(), 5);
        // c dead before the start: hidden in the result
        s.kill(&key(1, b"c"));
        let before = view(&s, 1);
        // tier rule: 4 one-tier runs at fan 4; 3 runs at fan 4 only above max
        assert!(s.compaction(1, 8, 16, 0, &[]).is_none());
        let mut c = s.compaction(1, 4, 16, 0, &[]).unwrap();
        assert_eq!(c.inputs(), 4);
        assert!(!c.step(2));
        // d killed while building: dead in the result
        s.kill(&key(1, b"d"));
        while !c.step(2) {}
        assert!(s.swap_in(c));
        assert_eq!(s.n_runs(), 2);
        let o = &s.obj(1).unwrap().runs;
        assert_eq!((o.len(), o[0].lsn), (1, 14));
        let after = view(&s, 1);
        let want: Vec<_> = before
            .into_iter()
            .filter(|(k, _)| k != &key(1, b"d"))
            .collect();
        assert_eq!(after, want);
        assert_eq!(s.get(&key(1, b"d")), Hit::Dead);
        // parts: 10 (c dead, a b shadowed) and 12 (a shadowed, d dead) left the floor; 13 (e), 14 (a b) hold
        assert_eq!(s.floor(), Some(11));
        let floors: Vec<_> = s.lsns.iter().copied().collect();
        assert_eq!(floors, vec![(11, 2, 11), (13, 1, 13), (14, 1, 14)]);
        // re-log of part 13 (record 20): the entries stay, the part moves
        let rl = s.relog_range(13, 13);
        assert_eq!(rl.len(), 1);
        assert_eq!((rl[0].ord(), rl[0].len()), (13, 1));
        s.insert(20, rl[0].clone());
        assert_eq!(s.n_runs(), 2);
        let floors: Vec<_> = s.lsns.iter().copied().collect();
        assert_eq!(floors, vec![(11, 2, 11), (14, 1, 14), (20, 1, 13)]);
        assert_eq!(view(&s, 1), want);
        // killing the last live entry of part 14 releases it; the run stays for part 13
        s.kill(&key(1, b"a"));
        s.kill(&key(1, b"b"));
        let floors: Vec<_> = s.lsns.iter().copied().collect();
        assert_eq!(floors, vec![(11, 2, 11), (20, 1, 13)]);
        s.kill(&key(1, b"e"));
        assert!(!s.has_obj(1));
        s.drop_obj(2);
        assert!(s.is_empty());
        assert_eq!(
            (s.mem(), s.entries(), s.tree_bytes(), s.n_runs()),
            (0, 0, 0, 0)
        );
        assert!(s.recs.is_empty() && s.rec_sizes.is_empty());
    }

    /// Random runs, kills and nested compactions (kills while built, multi-part inputs, shadowed parts): the merged
    /// view matches a model, the floor index holds exactly the parts with live entries, accounting returns to zero.
    #[test]
    fn compaction_random_kills_match_model() {
        use std::collections::BTreeMap;
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = |m: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % m
        };
        let mut s = RunSet::default();
        let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let mut c: Option<Compaction> = None;
        for lsn in 1..3000u64 {
            match rnd(8) {
                0..=2 => {
                    let mut ks: Vec<u16> = (0..1 + rnd(12)).map(|_| rnd(300) as u16).collect();
                    ks.sort_unstable();
                    ks.dedup();
                    // a quarter of the entries are removals (an empty value record)
                    let mut b = RunBuilder::default();
                    for k in &ks {
                        let mut val = Vec::new();
                        if rnd(4) != 0 {
                            val.push(0);
                            val.extend_from_slice(&lsn.to_le_bytes());
                        }
                        b.push(&key(1, &k.to_be_bytes()), &[], &val, &[]);
                        model.insert(key(1, &k.to_be_bytes()), val);
                    }
                    s.insert(lsn, b.finish(1).unwrap());
                }
                3..=4 => {
                    let k = key(1, &(rnd(300) as u16).to_be_bytes());
                    s.kill(&k);
                    model.remove(&k);
                }
                _ => match c.as_mut() {
                    None => c = s.compaction(1, 2 + rnd(3) as usize, 6, 0, &[]),
                    Some(cc) => {
                        if cc.step(1 + rnd(8) as usize) {
                            s.swap_in(c.take().unwrap());
                        }
                    }
                },
            }
            let want: Vec<_> = model.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            assert_eq!(view(&s, 1), want, "lsn {lsn}");
            let linked: Vec<_> = s
                .obj(1)
                .map(|o| {
                    o.runs
                        .iter()
                        .flat_map(|r| r.parts.iter().filter(|p| p.live > 0))
                        .map(|p| (p.rec, 1, p.ord))
                        .collect()
                })
                .unwrap_or_default();
            let mut linked: Vec<_> = linked;
            linked.sort_unstable();
            let floors: Vec<_> = s.lsns.iter().copied().collect();
            assert_eq!(floors, linked, "lsn {lsn}");
            if let Some(o) = s.obj(1) {
                for r in &o.runs {
                    let live: usize = r.parts.iter().map(|p| p.live).sum();
                    assert_eq!(live, r.live(), "lsn {lsn}");
                }
            }
        }
        s.drop_obj(1);
        assert_eq!(
            (s.mem(), s.entries(), s.tree_bytes(), s.n_runs()),
            (0, 0, 0, 0)
        );
    }

    /// A compaction whose input was replaced (re-log of a run as logged) or merged is dropped.
    #[test]
    fn compaction_lost_inputs() {
        let mut s = RunSet::default();
        for l in 1..=4u64 {
            s.insert(l, run(1, &[(&[b'a' + l as u8][..], b"v")]));
        }
        let c = s.compaction(1, 4, 16, 0, &[]).unwrap();
        let rl = s.relog_range(2, 2);
        s.insert(9, rl[0].clone());
        let mut c2 = c;
        while !c2.step(64) {}
        assert!(!s.swap_in(c2));
        assert_eq!(s.n_runs(), 4);
        // runs at or below a merge barrier are not taken
        assert!(s.compaction(1, 4, 16, 2, &[]).is_none());
        let mut c = s.compaction(1, 2, 16, 2, &[]).unwrap();
        assert_eq!(c.inputs(), 2);
        s.drop_upto(1, 3);
        while !c.step(64) {}
        assert!(!s.swap_in(c));
    }

    /// A compaction holds while its inputs stay (kills of some of their entries and newer runs leave them in place) and
    /// stops holding for good once an input leaves (every entry killed): its owner drops it before stepping it further.
    #[test]
    fn compaction_holds_until_an_input_leaves() {
        let mut s = RunSet::default();
        s.insert(1, run(1, &[(b"a", b"1"), (b"b", b"1")]));
        s.insert(2, run(1, &[(b"c", b"2"), (b"d", b"2")]));
        let mut c = s.compaction(1, 2, 16, 0, &[]).unwrap();
        assert!(s.holds(&c));
        assert!(!c.step(1));
        s.kill(&key(1, b"a"));
        s.insert(3, run(1, &[(b"e", b"3")]));
        assert!(s.holds(&c));
        s.kill(&key(1, b"b"));
        assert_eq!(s.n_runs(), 2, "an input with every entry killed leaves");
        assert!(!s.holds(&c));
        s.insert(4, run(1, &[(b"a", b"4"), (b"b", b"4")]));
        assert!(!s.holds(&c));
        while !c.step(64) {}
        assert!(!s.swap_in(c));
    }

    /// Anonymous mapping that a test touches only where it writes: a run buffer of gigabytes without resident memory.
    struct Sparse(*mut u8, usize);
    // SAFETY: the mapping is owned by this value alone and only read through `as_ref`.
    unsafe impl Send for Sparse {}
    impl AsRef<[u8]> for Sparse {
        fn as_ref(&self) -> &[u8] {
            // SAFETY: `self.0` maps `self.1` readable bytes until drop.
            unsafe { std::slice::from_raw_parts(self.0, self.1) }
        }
    }
    impl Drop for Sparse {
        fn drop(&mut self) {
            // SAFETY: unmaps exactly the mapping made in `sparse`.
            unsafe { libc::munmap(self.0.cast(), self.1) };
        }
    }

    /// A one-entry run of object `id` whose value fills `len` bytes: only the entry header and key are written, the value
    /// stays unmapped zero pages.
    fn sparse_run(id: u64, k: &[u8], len: usize) -> RunBlob {
        // SAFETY: fresh private anonymous mapping, checked below; MAP_NORESERVE: no swap reservation for the untouched rest.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED, "mmap {len}");
        let key = key(id, k);
        let vl = len - EHDR - key.len();
        // SAFETY: the mapping is `len` bytes, the header and key are far below that.
        let head = unsafe { std::slice::from_raw_parts_mut(p.cast::<u8>(), EHDR + key.len()) };
        head[..2].copy_from_slice(&(key.len() as u16).to_le_bytes());
        head[2..6].copy_from_slice(&(vl as u32).to_le_bytes());
        head[EHDR..].copy_from_slice(&key);
        RunBlob::decode(id, 1, Bytes::from_owner(Sparse(p.cast(), len))).expect("valid run")
    }

    /// Review 2026-11-03 #9: run entries are addressed by u32 offsets and the WAL op logs a u32 byte count. A run above
    /// `u32::MAX` bytes is refused: the bound itself, and the compaction planner refuses inputs whose bytes sum above it
    /// (the output holds at most their bytes) instead of building a run with wrapped offsets. Two inputs of 2 GiB + 4 KiB
    /// each, as sparse mappings: no 4 GiB of memory is touched.
    #[test]
    fn run_above_u32_offsets_is_refused() {
        assert!(run_fits(u32::MAX as usize) && !run_fits(u32::MAX as usize + 1));
        let len = (1usize << 31) + 4096;
        let mut s = RunSet::default();
        s.insert(1, sparse_run(1, b"a", len));
        s.insert(2, sparse_run(1, b"b", len));
        let bytes: usize = s
            .obj(1)
            .unwrap()
            .runs
            .iter()
            .map(|r| r.blob.buf.len())
            .sum();
        assert!(bytes > u32::MAX as usize);
        assert!(
            s.compaction(1, 2, 16, 0, &[]).is_none(),
            "compaction of {bytes} input bytes planned"
        );
        // inputs that fit still compact
        let mut s = RunSet::default();
        s.insert(1, sparse_run(1, b"a", 1 << 20));
        s.insert(2, sparse_run(1, b"b", 1 << 20));
        assert!(s.compaction(1, 2, 16, 0, &[]).is_some());
    }

    /// The memory of a compaction is its output as allocated at the start (reserved at the inputs' bytes), not the part
    /// built so far.
    #[test]
    fn compaction_memory_is_its_output_as_allocated() {
        let mut s = RunSet::default();
        let vals: Vec<Vec<u8>> = (0..64u8).map(|i| vec![i; 100]).collect();
        for l in 1..=2u64 {
            let kv: Vec<(Vec<u8>, &[u8])> = (0..64u8)
                .map(|i| (vec![l as u8, i], &vals[i as usize][..]))
                .collect();
            let kv: Vec<(&[u8], &[u8])> = kv.iter().map(|(k, v)| (&k[..], *v)).collect();
            s.insert(l, run(1, &kv));
        }
        let mut c = s.compaction(1, 2, 16, 0, &[]).unwrap();
        let start = c.mem();
        let inputs: usize = s
            .obj(1)
            .unwrap()
            .runs
            .iter()
            .map(|r| r.blob.buf.len())
            .sum();
        assert!(start >= inputs, "{start} < {inputs}");
        assert!(!c.step(1));
        assert_eq!(c.mem(), start);
        while !c.step(64) {}
        assert_eq!(c.mem(), start);
        assert!(start <= c.reservation());
    }

    /// The blocked filter keeps every inserted key and about 1 % false positives at 10 bits per key.
    #[test]
    fn bloom_false_positives() {
        let n = 50_000u64;
        let mut b = Bloom::new(n as usize);
        let k = |i: u64| {
            key(
                9,
                format!("{:016x}", i.wrapping_mul(0x9e37_79b9_7f4a_7c15)).as_bytes(),
            )
        };
        for i in 0..n {
            b.add(&k(i));
        }
        assert!((0..n).all(|i| b.may(hash(&k(i)))));
        let fp = (n..2 * n).filter(|&i| b.may(hash(&k(i)))).count();
        assert!(fp * 100 < n as usize * 2, "false positives {fp} of {n}");
    }

    fn splitmix(s: &mut u64) -> u64 {
        *s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *s;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// User key of the oprobe `s3name` shape: "data/XXXX/" + hex, 30..80 B (80 %), 80..200 B (18 %), 200..1100 B (2 %).
    fn s3name(idx: u64) -> Vec<u8> {
        let mut s = idx ^ 0x5333_4e41_4d45;
        let (a, b, c) = (splitmix(&mut s), splitmix(&mut s), splitmix(&mut s));
        let len = match a % 100 {
            0..=79 => 30 + (b % 51) as usize,
            80..=97 => 80 + (b % 121) as usize,
            _ => 200 + (b % 901) as usize,
        };
        let mut k = format!("data/{:04x}/", c >> 48).into_bytes();
        let mut t = c;
        while k.len() < len {
            k.extend_from_slice(format!("{:016x}", splitmix(&mut t)).as_bytes());
        }
        k.truncate(len);
        k
    }

    /// Cost of `kill_keys` per removed key (adr 0476 am. 15): one object, 64 clients alternating a set batch of 256
    /// keys (one run) and the removal of one of their earlier batches; the shard's compaction shape (fan 4, at most 24
    /// runs, the run-max admission, `KB_CB` entries per step); `KB_POLLUTE` x 64 random cache lines touched before
    /// each removal batch. `KB_SHAPE`: `ig` (oprobe S3 names, the previous batch removed), `ow` (omap-workload 48-byte
    /// keys, the batch `KB_DEPTH` back removed). `KB_RM=run`: each removal batch is staged as one run of removals (adr
    /// 0647-omap-blind-removals D1: built and inserted, no kill) instead of killed (the tree path's `kill_keys`).
    /// `KB_SOFT_MB` (default 0: none) models the tree merge: it takes every run of the object once the runs hold that
    /// much memory (16 = the default `run_soft_bytes`); `KB_RM=run` needs it (a removal leaves the runs only by a
    /// merge). Prints the removal's cost per key, the compaction steps' time per op and the merges (all after the
    /// warm-up). Run: `KB_SHAPE=ig cargo test -p store --release --lib kill_keys_cost -- --ignored --nocapture`.
    #[test]
    #[ignore = "microbench: run with --release"]
    fn kill_keys_cost() {
        let env = |k: &str, d: usize| -> usize {
            std::env::var(k)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(d)
        };
        let shape = std::env::var("KB_SHAPE").unwrap_or_else(|_| "ig".into());
        let (pol, cb, ops) = (
            env("KB_POLLUTE", 64),
            env("KB_CB", 512),
            env("KB_OPS", 60_000),
        );
        let depth = if shape == "ig" {
            1
        } else {
            env("KB_DEPTH", 15)
        };
        let rm_run = std::env::var("KB_RM").is_ok_and(|v| v == "run");
        let soft = env("KB_SOFT_MB", 0) << 20;
        assert!(
            soft > 0 || !rm_run,
            "KB_RM=run needs KB_SOFT_MB: a removal leaves the runs only by a merge"
        );
        let (clients, batch) = (64usize, 256u64);
        let (mut s, mut cps, mut lsn) = (RunSet::default(), Vec::<Compaction>::new(), 1u64);
        let (val, pfx) = (vec![0x5a; 300], key(1, b""));
        // the shard's `compact_step`: drop lost, start (fan 4, max 24), one budget of entries, smallest first
        let compact = |s: &mut RunSet, cps: &mut Vec<Compaction>, cb: usize| {
            cps.retain(|c| {
                let held = s.holds(c);
                if !held {
                    s.add_cand(c.id());
                }
                held
            });
            while let Some(id) = s.next_cand() {
                loop {
                    let busy: Vec<(u64, u64)> = cps.iter().map(|c| c.window()).collect();
                    match s.compaction(id, 4, 24, 0, &busy) {
                        Some(c) => cps.push(c),
                        None => break,
                    }
                }
            }
            cps.sort_by_key(|c| c.left());
            let (mut budget, mut done) = (cb, 0);
            for c in cps.iter_mut() {
                if budget == 0 {
                    break;
                }
                let l = c.left();
                done += c.step(budget) as usize;
                budget = budget.saturating_sub(l - c.left());
            }
            for c in cps.drain(..done).collect::<Vec<_>>() {
                let id = c.id();
                s.swap_in(c);
                s.add_cand(id);
            }
        };
        let mut q: Vec<std::collections::VecDeque<Vec<Vec<u8>>>> =
            vec![Default::default(); clients];
        let mut seq = vec![0u64; clients];
        // clients start out of phase (half of them with a removal)
        let mut rm: Vec<bool> = (0..clients as u64)
            .map(|mut c| splitmix(&mut c) & 1 == 1)
            .collect();
        let (mut pbuf, mut prng) = (vec![0u64; 4 << 20], 7u64);
        let (mut ns, mut nkeys, mut sum_r, mut nb) = (0u128, 0u64, 0u64, 0u64);
        // compaction time and merges after the warm-up (the first fifth of the ops)
        let (mut cns, mut merges) = (0u128, 0u64);
        let mut timed = |op: usize, s: &mut RunSet, cps: &mut Vec<Compaction>, cb: usize| {
            let t = std::time::Instant::now();
            compact(s, cps, cb);
            if op >= ops / 5 {
                cns += t.elapsed().as_nanos();
            }
        };
        for op in 0..ops {
            let c = op % clients;
            rm[c] = !rm[c];
            if rm[c] && q[c].len() >= depth {
                let mut ks: Vec<Vec<u8>> = q[c].pop_front().unwrap();
                ks.sort();
                let full: Vec<Vec<u8>> = ks.iter().map(|u| key(1, u)).collect();
                // a run of removals takes the set batch's run-max admission
                while rm_run && s.obj(1).is_some_and(|o| o.runs.len() >= 24) {
                    timed(op, &mut s, &mut cps, cb.max(256));
                }
                for _ in 0..pol * 64 {
                    let i = (splitmix(&mut prng) as usize % (pbuf.len() / 8)) * 8;
                    pbuf[i] = pbuf[i].wrapping_add(1);
                }
                let r = s.obj(1).map_or(0, |o| o.runs.len()) as u64;
                let t0 = std::time::Instant::now();
                if rm_run {
                    // as the stage builds it: the tree key prefix and the key per entry, no value
                    let mut b = RunBuilder::with_capacity(ks.len(), ks.len() * (pfx.len() + 48));
                    for k in &ks {
                        b.push(&pfx, k, &[], &[]);
                    }
                    lsn += 1;
                    s.insert(lsn, b.finish(1).unwrap());
                } else {
                    s.kill_keys(&full, |k| Some(k.as_slice()));
                }
                // the first fifth warms up
                if op >= ops / 5 {
                    ns += t0.elapsed().as_nanos();
                    (nkeys, sum_r, nb) = (nkeys + full.len() as u64, sum_r + r, nb + 1);
                }
            } else if !rm[c] {
                let ks: Vec<Vec<u8>> = (0..batch)
                    .map(|_| {
                        seq[c] += 1;
                        match shape.as_str() {
                            "ig" => s3name((c as u64) << 40 | seq[c]),
                            _ => {
                                let mut b = vec![b'k'; 48];
                                b[40..].copy_from_slice(
                                    &(250_000 + (c as u64) + 64 * seq[c]).to_be_bytes(),
                                );
                                b
                            }
                        }
                    })
                    .collect();
                // run-max admission: the batch waits for compactions while the object holds 24 runs
                while s.obj(1).is_some_and(|o| o.runs.len() >= 24) {
                    timed(op, &mut s, &mut cps, cb.max(256));
                }
                let mut sorted: Vec<&Vec<u8>> = ks.iter().collect();
                sorted.sort();
                let mut b = RunBuilder::with_capacity(sorted.len(), sorted.len() * 360);
                for k in sorted {
                    b.push(&pfx, k, &[0], &val);
                }
                lsn += 1;
                s.insert(lsn, b.finish(1).unwrap());
                q[c].push_back(ks);
            }
            timed(op, &mut s, &mut cps, cb);
            // the tree merge takes every run of the object (its compactions are lost and dropped at the next step)
            if soft > 0 && s.mem() >= soft {
                s.drop_upto(1, lsn);
                merges += (op >= ops / 5) as u64;
            }
        }
        eprintln!(
            "shape {shape} cb {cb} pollute {pol}: {nb} removal batches, mean runs {:.1}, {} {:.1} ns/key, compaction {:.0} ns/op, {merges} merges",
            sum_r as f64 / nb as f64,
            if rm_run { "removal run" } else { "kill_keys" },
            ns as f64 / nkeys as f64,
            cns as f64 / (ops - ops / 5) as f64
        );
    }

    /// The run key helpers produce the bytes of the tree's omap key layout (`obj::keys`): the WAL replay check
    /// (`omap_id`) and the run bounds (`key_lo`) must agree with the keys the object layer writes.
    #[test]
    fn omap_key_layout_matches_keys_rs() {
        use crate::obj::keys::{omap_key, sub_range};
        for id in [0u64, 1, 0x0102_0304_0506_0708, u64::MAX] {
            let mut want = vec![b'o'];
            want.extend_from_slice(&id.to_be_bytes());
            want.push(4);
            assert_eq!(key_lo(id).as_slice(), want.as_slice());
            assert_eq!(key_lo(id).as_slice(), omap_key(id, b"").as_slice());
            assert_eq!(
                key_lo(id).as_slice(),
                sub_range(T_OMAP, S_OMAP, id).0.as_slice()
            );
            for u in [&b""[..], b"k", b"\xff\x00key"] {
                let k = omap_key(id, u);
                assert_eq!(&k[..OPFX], want.as_slice());
                assert_eq!(&k[OPFX..], u);
                assert_eq!(omap_id(&k), Some(id));
            }
        }
        // not omap keys: other tag, other sub-tag, short
        assert_eq!(omap_id(&crate::obj::keys::attr_key(7, b"a")), None);
        assert_eq!(omap_id(&sub_range(T_OMAP, S_OMAP, 7).1), None);
        assert_eq!(omap_id(&key_lo(7)[..OPFX - 1]), None);
        assert_eq!(omap_id(b""), None);
    }

    /// The compaction candidates are a LIFO of distinct objects: `insert` / `add_cand` queue an object not queued,
    /// `next_cand` takes the newest. Model: a Vec searched on every push.
    #[test]
    fn cand_queue_matches_model() {
        let mut rng = crate::rng::Rng::new(9);
        let mut s = RunSet::default();
        let mut model: Vec<u64> = Vec::new();
        let push = |m: &mut Vec<u64>, id: u64| {
            if !m.contains(&id) {
                m.push(id);
            }
        };
        let mut lsn = 1;
        for _ in 0..20_000 {
            let id = rng.below(64);
            match rng.below(10) {
                0..=3 => {
                    s.insert(lsn, run(id, &[(b"k", b"v")]).with_ord(lsn));
                    lsn += 1;
                    push(&mut model, id);
                }
                4..=5 => {
                    s.add_cand(id);
                    push(&mut model, id);
                }
                6 => s.drop_obj(id),
                _ => assert_eq!(s.next_cand(), model.pop()),
            }
            assert_eq!(s.has_cand(), !model.is_empty());
        }
        while let Some(id) = model.pop() {
            assert_eq!(s.next_cand(), Some(id));
        }
        assert_eq!(s.next_cand(), None);
    }

    /// Cost of queueing compaction candidates while many objects receive runs (WAL replay of runs, memtable flushes).
    /// Measurement: `cargo test --release -p store --lib runs::tests::cand_insert_cost -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement"]
    fn cand_insert_cost() {
        for objs in [1_000u64, 10_000, 50_000] {
            let blobs: Vec<RunBlob> = (0..objs).map(|id| run(id, &[(b"k", b"v")])).collect();
            let mut best = f64::MAX;
            for _ in 0..3 {
                let mut s = RunSet::default();
                let t = std::time::Instant::now();
                for (i, b) in blobs.iter().enumerate() {
                    s.insert(i as u64 + 1, b.clone().with_ord(i as u64 + 1));
                }
                best = best.min(t.elapsed().as_nanos() as f64 / objs as f64);
                std::hint::black_box(&s);
            }
            eprintln!("cand_insert_cost: {objs} objects, {best:.0} ns per insert");
        }
    }

    /// `kill_span` (dead bits by words, one object lookup) leaves the run set exactly as `kill_at` of every entry of
    /// the span, single-part runs and compacted multi-part runs, with spans over live, dead and mixed entries.
    #[test]
    fn kill_span_equals_kill_at_per_entry() {
        let fp = |s: &RunSet| {
            format!(
                "{:?} {:?} {:?} {:?} {}",
                s.objs,
                s.lsns,
                s.recs,
                s.rec_sizes,
                s.dead_ents()
            )
        };
        let mut multi = 0;
        for seed in 0..30u64 {
            let build = || {
                let mut rng = crate::rng::Rng::new(seed);
                let mut s = RunSet::default();
                for lsn in 1..=8u64 {
                    let mut ks: Vec<Vec<u8>> = (0..1 + rng.below(200))
                        .map(|_| format!("{:04}", rng.below(400)).into_bytes())
                        .collect();
                    ks.sort();
                    ks.dedup();
                    let kv: Vec<(&[u8], &[u8])> =
                        ks.iter().map(|k| (k.as_slice(), &b"v"[..])).collect();
                    s.insert(lsn, run(1, &kv));
                    // compact now and then: multi-part runs
                    if lsn % 3 == 0
                        && let Some(mut c) = s.compaction(1, 2, 4, 0, &[])
                    {
                        while !c.step(1 << 20) {}
                        s.swap_in(c);
                    }
                }
                s
            };
            let (mut a, mut b) = (build(), build());
            multi += usize::from(a.objs[&1].runs.iter().any(|r| r.n_parts() > 1));
            let mut rng = crate::rng::Rng::new(seed ^ 0xabc);
            for _ in 0..40 {
                let Some(o) = a.objs.get(&1) else { break };
                let ri = rng.below(o.runs.len() as u64) as usize;
                let len = o.runs[ri].blob.len() as u64;
                let i0 = rng.below(len + 1) as usize;
                let i1 = (i0 + rng.below(len / 3 + 2) as usize).min(len as usize);
                let ea = a.kill_span(1, ri, i0, i1);
                let eb = (i0..i1).fold(false, |e, i| b.kill_at(1, ri, i) | e);
                assert_eq!(ea, eb, "seed {seed}: emptied");
                assert_eq!(fp(&a), fp(&b), "seed {seed}: state");
                if ea {
                    a.drop_dead(1);
                    b.drop_dead(1);
                }
            }
        }
        assert!(multi > 0, "no multi-part run built");
    }

    /// Cost of a range kill (omap rm-range, merge slice retire) per killed entry: one object, `runs` runs of `n` keys
    /// each, the whole key range killed by `kill_range`, then (fresh set) retired by `retire`.
    /// Measurement: `cargo test --release -p store --lib runs::tests::range_kill_cost -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement"]
    fn range_kill_cost() {
        for (runs, n) in [(1usize, 100_000usize), (4, 25_000)] {
            let keys: Vec<Vec<u8>> = (0..n).map(|i| format!("{i:08}").into_bytes()).collect();
            let kv: Vec<(&[u8], &[u8])> = keys.iter().map(|k| (k.as_slice(), &b"v"[..])).collect();
            let blob = run(1, &kv);
            let set = || {
                let mut s = RunSet::default();
                for r in 0..runs as u64 {
                    s.insert(r + 1, blob.clone().with_ord(r + 1));
                }
                s
            };
            let (a, b) = (key(1, b""), key(2, b""));
            let (mut best_k, mut best_r) = (f64::MAX, f64::MAX);
            for _ in 0..5 {
                let mut s = set();
                let t = std::time::Instant::now();
                s.kill_range(&a, &b);
                best_k = best_k.min(t.elapsed().as_nanos() as f64 / (runs * n) as f64);
                let mut s = set();
                let t = std::time::Instant::now();
                s.retire(1, u64::MAX, &a, &b);
                best_r = best_r.min(t.elapsed().as_nanos() as f64 / (runs * n) as f64);
                std::hint::black_box(&s);
            }
            eprintln!(
                "range_kill_cost: {runs} runs x {n} keys: kill_range {best_k:.1} ns/entry, retire {best_r:.1} ns/entry"
            );
        }
    }

    #[test]
    fn ids_in_bounds() {
        let mut s = RunSet::default();
        for id in [1u64, 2, 3] {
            s.insert(id, run(id, &[(b"k", b"v")]));
        }
        let ids = |a: &[u8], b: &[u8]| s.ids_in(a, b).collect::<Vec<_>>();
        assert_eq!(ids(&key(2, b""), &key(3, b"")), vec![2]);
        assert_eq!(ids(&key(2, b""), &key(3, b"a")), vec![2, 3]);
        assert_eq!(ids(b"", b"o"), Vec::<u64>::new());
        assert_eq!(ids(b"n", b"p"), vec![1, 2, 3]);
        assert_eq!(ids(b"p", b"q"), Vec::<u64>::new());
        assert_eq!(ids(b"", b"q"), vec![1, 2, 3]);
    }
}
