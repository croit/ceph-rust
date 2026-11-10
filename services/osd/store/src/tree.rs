// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! COW B+tree with a bounded page cache (design 2.6). Sans-IO: operations either complete on cached pages or
//! return `StoreError::Miss` after queueing the missing pages in `wants` (the shard issues the reads and
//! `install`s them; the caller retries). A miss never leaves a partial mutation: single operations descend
//! before they mutate, multi-op txns `probe` first (see `state::State::prepare`).
//!
//! * Pages are mutated in place in the cache (dirty pages are pinned). A checkpoint freezes them in slices while txns
//!   go on (`freeze_begin` / `freeze_step`, adr 0021 am. 40; pending interior pages are copied aside before they
//!   change): each leaf becomes a delta entry (am. 19) or a whole image at a fresh meta address. The previous version
//!   stays valid until the new root slot is durable.
//! * Child references hold (addr, crc) of the on-disk version. Pages that never reached the disk (splits, new
//!   root) have a virtual address (bit 63) until frozen.
//! * Structural removal of empty pages is deferred to `finish_txn` so that routing never changes in the middle
//!   of a txn (which could send a later op of the same txn to a non-resident neighbour).
//! * Under-full leaves merge with a resident dirty neighbour at the end of a txn (`merge_pass`, am. 29), the rest in
//!   the background compaction (am. 33); empty pages are removed. Removed subtrees are detached and freed lazily,
//!   depth first, by reading them back (`dead_kick`, am. 18).

use crate::alloc::MetaAlloc;
use crate::delta::{self, ChainSet};
use crate::error::{Result, StoreError};
use crate::layout::MetaGeom;
use crate::page::{self, INT, LEAF, REF_LEN};
use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};

pub const VIRT: u64 = page::VIRT;
const NONE: u64 = 0;
/// Image bytes per detached subtree (see `Tree::encode_ext`) and the section magic ("DEA1").
const DEAD_ENT: usize = 13;
const DEAD_MAGIC: u32 = 0x3141_4544;
const DELTA_MAGIC: u32 = 0x314c_4544; // "DEL1"
/// Range deletes are held back (`Busy`, shard admission) while this many detached subtrees await the drain.
pub const DEAD_SOFT: usize = 16384;
/// Dead-list entries the meta image keeps room for: the admission bound plus what one txn and the drain's expansion (a
/// few interior pages in flight, each listing its children) add on top.
const DEAD_ROOM: usize = DEAD_SOFT + 8192;
/// Chains folded back per checkpoint at most (adr 0021 am. 19).
const MAX_FOLD: usize = 64;
/// Underfull-leaf merge candidates kept per txn (adr 0021 am. 29).
const MERGE_CANDS: usize = 64;
/// Background compaction queue (adr 0021 am. 33): candidate keys and their arena bytes (bounded; full = dropped).
const CQ_CAP: usize = 4096;
const CQ_ARENA: usize = 256 << 10;

/// Pages (and page buffers) a tree with page budget `cap` holds before its shard shrinks it even with page reads in
/// flight: the cap plus 1/32, the small bounded overshoot of the memory target that reads in flight all the time
/// (rolling readahead, steady cold reads) may cause (`Shard::poll`). Free slots keep their page buffers up to it, so a
/// full cache allocates none per load.
pub fn buffer_mark(cap: usize) -> usize {
    cap + cap / 32
}

/// Outcome of a leaf merge attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Merge {
    Done,
    /// Not now: a sibling is cold or both pages are clean (the background compaction can take it).
    Later,
    No,
}

const F_DIRTY: u8 = 1;
const F_INFLIGHT: u8 = 2;
const F_REF: u8 = 4;
/// Structural change since the last freeze (split, prune, rebuilt interior page, ...): the page is rewritten whole.
const F_MOD: u8 = 8;
/// The touch log overflowed or is not kept: the page is rewritten whole.
const F_NOTRK: u8 = 16;
/// Leaf has an entry in the background compaction queue (adr 0021 am. 33).
const F_CQ: u8 = 32;
/// Pending in the running sliced freeze (adr 0021 am. 40): taken at its lsn, not yet processed.
const F_FRZ: u8 = 64;
/// A pending interior page dirtied again (for the next checkpoint) while the freeze runs.
const F_AGAIN: u8 = 128;

#[derive(Default, Debug)]
pub struct AddrHasher(u64);
impl Hasher for AddrHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, b: &[u8]) {
        for &x in b {
            self.0 = (self.0 ^ x as u64).wrapping_mul(0x100_0000_01b3);
        }
    }
    fn write_u64(&mut self, v: u64) {
        let h = v.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        self.0 = h ^ (h >> 29);
    }
}
type AddrMap = HashMap<u64, u32, BuildHasherDefault<AddrHasher>>;

#[derive(Clone, Debug)]
pub struct TreeCfg {
    /// Page size in bytes (4096..=32768, power of two).
    pub psz: usize,
    pub shard: u32,
    /// Cache budget in pages (soft: dirty and in-flight pages are never evicted).
    pub cache_pages: usize,
    /// Max pages one range operation may touch (probe).
    pub max_walk: usize,
    /// New and rebuilt interior pages use the compact format (adr 0021 am. 13); existing pages keep theirs.
    pub compact_int: bool,
    /// Queue leaves the txn-time merge could not take for the background compaction (adr 0021 am. 33). Tests switch it
    /// off to keep sparse leaves in place.
    pub bg_compact: bool,
}

/// A page the caller must read: `addr`, expected crc (from the parent) and level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Want {
    pub addr: u64,
    pub crc: u32,
    pub level: u8,
    /// A detached subtree page the lazy free reads (adr 0021 am. 18): `install` consumes it instead of caching it.
    pub dead: bool,
    /// A leaf read for a range scan (its miss or its readahead): cached without a reference (adr 0021 S5, scan-resistant
    /// cache), so a long listing does not push the point-op working set out; a point access references it as usual.
    pub scan: bool,
}

/// The segment a freeze writes: sealed pages, and the page being filled `(fill, addr)`.
#[derive(Debug, Default)]
struct SegOut {
    pages: Vec<(u64, u32)>,
    fill: Option<(delta::PageFill, u64)>,
}

/// A delta segment as persisted: the pages one checkpoint wrote (`seq` increases with every checkpoint that wrote deltas).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegDir {
    pub seq: u64,
    pub pages: Vec<(u64, u32)>,
}

/// A subtree a range delete detached from the tree without reading it (adr 0021 am. 18): its pages stay allocated
/// (and are listed in the checkpoint's meta image) until the lazy drain has read the root page, freed its children
/// or listed them in turn, and freed the page itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dead {
    pub addr: u64,
    pub crc: u32,
    pub level: u8,
}

#[derive(Debug)]
struct Page {
    buf: Box<[u8]>,
    addr: u64,
    flags: u8,
    /// crc of the image the page was read from / last written (the base its deltas apply to).
    dcrc: u32,
    /// Leaf delta tracking (adr 0021 am. 19): keys and spans touched since the last freeze (`delta::touch_*`).
    touched: Vec<u8>,
    /// Install sequence number: recently installed pages are protected from eviction so a txn that waits for
    /// several rounds of page loads keeps what it already loaded.
    seq: u64,
    /// Sliced freeze: the address this page had before the running freeze rewrote it (still mapped to it until the freeze
    /// ends: parents not yet processed route through it); 0 = none.
    alias: u64,
    /// Number of the last freeze that settled this leaf ([`Tree::settle`]; 0 = none).
    fz_no: u32,
    /// Debug: crc of the page (and touch log length) when the freeze took it, checked when it is processed.
    #[cfg(debug_assertions)]
    fz_crc: u32,
}

/// A sliced freeze in progress (adr 0021 am. 40).
#[derive(Debug)]
struct Fz {
    lsn: u64,
    /// Pages taken at `lsn`, bottom-up; `pos` = next to process (pages forced earlier are skipped).
    list: Vec<u32>,
    pos: usize,
    fr: Frozen,
    /// This freeze's delta segment: leaves settle into it as they are processed (their entries join the chains at
    /// once), so the end only cleans and seals (a whole emit at the end held the core 3-7 ms per checkpoint).
    seg: SegOut,
    /// Delta entries settled so far.
    n_entries: usize,
    /// Root reference and height at `lsn`.
    root: Option<(u64, u32, u8)>,
    /// Detached subtree list at `lsn` and its generation (the image of this checkpoint).
    dead: Vec<Dead>,
    dead_gen: u64,
    /// Chains dropped while the freeze runs: dropped again after its entries were added.
    dropped: Vec<u64>,
    /// Leaves settled into delta entries (slot, address): kept resident until the entries are in the chains.
    pinned: Vec<(u32, u64)>,
    /// Interior pages copied before a change (`fz_touch`), by slot.
    shadows: HashMap<u32, Shadow>,
    /// The end steps after the last pending page, in slices like the pages (adr 0021 am. 80).
    end: FzEnd,
}

/// End steps of a sliced freeze (adr 0021 am. 80), each in slices while txns keep committing, in this order:
/// `Fix(i)`: the live interior pages dirtied since the lsn (`Tree::dirty` from index `i`; pages added meanwhile are visited
/// too) take the new addresses of their processed children; every reference a txn copies afterwards (split halves, a new
/// root) comes from an updated page or is a fresh address, so an updated page stays updated. `Unalias(i)`: the processed
/// pages (`Fz::list` from `i`) drop their old addresses; only after `Fix` (an unfixed page routes through them). `Relog`:
/// segment cleaning, one chain at a time ([`Tree::relog_front`]). Then [`Tree::freeze_end`] seals the segment and writes
/// the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FzEnd {
    Fix(usize),
    Unalias(usize),
    /// Target segment pages.
    Relog(usize),
    Done,
}

/// A pending interior page's state at the freeze's lsn, taken before the live page changed (adr 0021 am. 40).
#[derive(Debug)]
struct Shadow {
    buf: Box<[u8]>,
    flags: u8,
    addr: u64,
    /// The live page is still in the tree (false: removed after the lsn, the slot may hold another page).
    live: bool,
}

/// RAM accounting of one tree ([`Tree::mem`]).
#[derive(Debug, Default, Clone, Copy)]
pub struct TreeMem {
    pub pages: u64,
    pub page_bytes: u64,
    /// Delta touch log buffers held, dirty leaves + pool (`touch_pool_bytes` of it: kept for reuse).
    pub touched_bytes: u64,
    pub touch_pool_bytes: u64,
    pub slab_slots: u64,
    pub slab_bytes: u64,
    /// Free slab slots (evicted/freed pages) and the buffers they keep.
    pub free_slots: u64,
    pub free_bytes: u64,
    pub chains: u64,
    pub chain_bytes: u64,
    pub dead: u64,
    pub retired: u64,
    /// Embedded dependency state and retained capture capacity, even while idle.
    pub dependency_bytes: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TreeStats {
    pub loads: u64,
    /// Of `loads`: leaves read for listings, cached unreferenced (`Want::scan`); of `evictions`: those evicted from the
    /// scan queue (before the CLOCK).
    pub scan_loads: u64,
    pub scan_evictions: u64,
    pub evictions: u64,
    /// CLOCK hand steps (eviction and aging, [`Tree::age`]): the hand's pace is the cache's eviction pressure.
    pub hand_steps: u64,
    pub splits: u64,
    pub grows: u64,
    pub pruned: u64,
    /// Key locates (point lookups, probes, puts, deletes; `locates = descents + hint_hits`): `descents` walked from the
    /// root, `hint_hits` found a remembered leaf. Positions a caller carries (sorted cursors) are not locates.
    pub locates: u64,
    pub descents: u64,
    pub hint_hits: u64,
    /// Detached subtree pages freed by the lazy drain / dropped as unreadable (leaked, reported by fsck).
    pub dead_detached: u64,
    pub dead_freed: u64,
    pub dead_lost: u64,
    /// Delta pages written by checkpoints (adr 0021 am. 19).
    pub delta_pages: u64,
    /// Leaf entries written as deltas; leaves written whole although tracked (entry or chain too big); leaves folded back
    /// by the cap (`consolidate`).
    pub delta_entries: u64,
    pub delta_declined: u64,
    /// Of `delta_declined`: the leaf's chain would exceed `chain_max`, the delta RAM cap or the delta page bound was
    /// reached (`delta_room`); the rest: the ops alone exceed `entry_max`.
    pub declined_chain: u64,
    pub declined_room: u64,
    pub delta_folded: u64,
    /// Segment cleaning (relog): chains copied forward, segments freed by it.
    pub relog_chains: u64,
    pub relog_segs: u64,
    /// Checkpoint freezes by page outcome: pages that needed no write (clean interiors, leaves with no net change),
    /// leaves and interior pages written whole (delta pages and the meta image not included).
    pub fz_clean: u64,
    pub fz_whole_leaves: u64,
    pub fz_whole_ints: u64,
    /// Underfull leaves merged into a dirty neighbour at the end of a txn (adr 0021 am. 29).
    pub merged: u64,
    /// Background compaction (adr 0021 am. 33): leaves merged, candidates dropped (queue full).
    pub compacted: u64,
    pub compact_dropped: u64,
}

/// Result of [`Tree::shape`].
#[derive(Debug, Default, Clone, Copy)]
pub struct TreeShape {
    pub height: u8,
    pub leaves: u64,
    pub interior: u64,
    /// Leaf entries.
    pub entries: u64,
    /// Bytes in use (header, prefix, slots, entries) of leaf / interior pages.
    pub leaf_used: u64,
    pub int_used: u64,
    /// Interior entries; bytes of key suffixes (after the page prefix) and of the part each shares with the
    /// previous entry's suffix (what per-entry front coding could still save); leaf values.
    pub int_entries: u64,
    pub int_sfx: u64,
    pub int_lcp: u64,
    pub leaf_sfx: u64,
    pub leaf_lcp: u64,
    pub leaf_val: u64,
}

/// Everything the checkpoint writer needs, snapshotted at freeze.
#[derive(Debug)]
pub struct Frozen {
    /// Page images in allocation order (`psz` each).
    pub arena: crate::fzarena::Arena,
    /// Pages the arena may hold (counted at `freeze_begin`: every pending page, the meta image, slack).
    pub room: usize,
    /// (new address, index into arena) in allocation order.
    pub pages: Vec<(u64, u32)>,
    /// Root reference of the frozen tree (None = empty tree).
    pub root: Option<(u64, u32)>,
    pub height: u8,
    /// Meta bitmap image for this checkpoint (old pages already cleared), `bm_blocks` long.
    pub bitmap: Vec<u8>,
    /// Pages superseded by this checkpoint: freed once its root slot is durable.
    pub free_after: Vec<u64>,
    pub meta_used: u32,
    /// Elastic store: `(page 0 address, its crc, pages)` of the meta image this checkpoint's root points at (its
    /// pages are part of `pages`/`arena` when the image changed). `bitmap` is empty then.
    pub blob: Option<(u64, u32, u32)>,
}

#[derive(Debug, Default)]
pub struct ScanCursor {
    /// Next key to emit (inclusive).
    pub next: Vec<u8>,
    /// Exclusive end.
    pub end: Vec<u8>,
    pub done: bool,
    /// Deep readahead window in leaves (0 = the default short readahead after a miss). A long scan whose consumer is
    /// cheap (the omap range pre-count, adr 0021 am. 26) keeps up to this many sibling leaf reads in flight; the tree
    /// clamps it to a fraction of its cache.
    pub ra_win: u32,
    /// Leaves already requested beyond the cursor leaf (only maintained when `ra_win` > 0; a hint, never exact).
    pub ra: u32,
    /// A listing (omap / object listing, range pre-count): the leaves it visits or reads gain no CLOCK reference, so
    /// it does not push the point-op working set out of the cache (adr 0021 S5). Point-style range reads (extent maps,
    /// refcount runs) keep their leaves referenced.
    pub cold: bool,
}

impl ScanCursor {
    pub fn new(start: &[u8], end: &[u8]) -> ScanCursor {
        ScanCursor {
            next: start.to_vec(),
            end: end.to_vec(),
            done: start >= end,
            ra_win: 0,
            ra: 0,
            cold: false,
        }
    }

    /// Same range, deep readahead window of `win` leaves.
    pub fn with_readahead(mut self, win: u32) -> ScanCursor {
        self.ra_win = win;
        self
    }

    /// Same range as a listing (see `cold`).
    pub fn listing(mut self) -> ScanCursor {
        self.cold = true;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanStatus {
    /// Range exhausted.
    Done,
    /// Budget used up; call again to continue.
    More,
}

/// Position of ascending puts or probes (omap run merges, adr 0476): the leaf of the last key, its upper fence and the
/// structure epoch. A key below the fence reuses that leaf (and the path the descent left in the tree) without a descent;
/// any structural change (split, eviction) ends the reuse. The caller passes strictly ascending keys and makes no other
/// tree call between them.
#[derive(Default, Debug)]
pub struct SortedCursor {
    leaf: u32,
    fence: Vec<u8>,
    has_fence: bool,
    epoch: u64,
    valid: bool,
    /// Interior path of `leaf` (root..parent, child index taken) when the cursor was set by [`Tree::probe_sorted`]: a
    /// key past the leaf's fence is routed from the deepest page of this path whose range holds it (the keys ascend:
    /// usually the parent, one route) instead of a descent from the root.
    path: Vec<(u32, u16)>,
}

impl SortedCursor {
    pub fn reset(&mut self) {
        self.valid = false;
    }
}

/// Source of a sorted write batch ([`Tree::write_sorted_batch`]): strictly ascending keys; an entry with an empty value
/// removes its key (omap run removals, adr 0647-omap-blind-removals: a batch never puts an empty value).
pub trait SortedSrc {
    /// Key of the next entry (`None`: no more).
    fn key(&self) -> Option<&[u8]>;
    /// Append the next entry (key, value as stored; empty: a removal) to `out` and move past it.
    fn take(&mut self, out: &mut page::Ents);
}

/// Distinct tree pages visited by the probes of one txn (see `Tree::probe_path`), and the located leaves of its keys: the
/// apply pass of the same txn mutates there without a second walk ([`Tree::put_at`], [`Tree::del_at`]) while the
/// structure epoch is the one [`Tree::seal_positions`] stamped after the probes.
/// Set of page slots, O(1) insert / test and O(1) clear: a txn's probes visit up to a few hundred distinct pages (a
/// 256-key omap batch spreads over as many leaves), where a linear `contains` per visited page made the probe pass
/// quadratic. Open addressing on `(round << 32) | slot`; [`SlotSet::clear`] bumps the round instead of wiping
/// the table.
#[derive(Debug, Default)]
struct SlotSet {
    tab: Vec<u64>,
    round: u32,
    len: usize,
}

impl SlotSet {
    fn clear(&mut self) {
        self.len = 0;
        self.round = self.round.wrapping_add(1);
        if self.round == 0 {
            // round wrapped: entries of round 0 would read as present
            self.tab.fill(0);
            self.round = 1;
        }
    }

    /// Insert `slot`: true when it was not in the set.
    fn insert(&mut self, slot: u32) -> bool {
        if self.round == 0 {
            self.round = 1;
        }
        if 2 * (self.len + 1) > self.tab.len() {
            self.grow();
        }
        let want = (u64::from(self.round) << 32) | u64::from(slot);
        let mask = self.tab.len() - 1;
        let mut i = Self::home(slot, mask);
        loop {
            let e = self.tab[i];
            if e == want {
                return false;
            }
            if (e >> 32) as u32 != self.round {
                self.tab[i] = want;
                self.len += 1;
                return true;
            }
            i = (i + 1) & mask;
        }
    }

    fn home(slot: u32, mask: usize) -> usize {
        (slot.wrapping_mul(0x9E37_79B9) >> 7) as usize & mask
    }

    /// Double the table (at least 64 entries) and re-insert the current round's slots.
    fn grow(&mut self) {
        let old = std::mem::take(&mut self.tab);
        self.tab = vec![0; (old.len() * 2).max(64)];
        self.len = 0;
        for e in old {
            if (e >> 32) as u32 == self.round {
                self.insert(e as u32);
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct PathSet {
    seen: SlotSet,
    last: Option<u32>,
    /// Visited pages that are not dirty yet (each needs a fresh meta page at the next checkpoint).
    pub clean: usize,
    pub leaves: usize,
    /// Distinct leaves that receive a put (only those can split; see `note_put`).
    put_leaves: SlotSet,
    /// Located leaves `(leaf, start, len)` of the probes in order; consecutive keys of one leaf share one entry. `start`
    /// / `len`: the interior path in `lpath`.
    legs: Vec<(u32, u32, u32)>,
    lpath: Vec<(u32, u16)>,
    /// Leg of the last `probe_path` ([`NO_LEG`]: the tree was empty).
    cur: u32,
    /// Structure epoch the legs are valid at (`Tree::seal_positions`; `u64::MAX`: not sealed).
    epoch: u64,
}

/// No located leaf (see [`PathSet::leg`]).
pub const NO_LEG: u32 = u32::MAX;

impl PathSet {
    pub fn reset(&mut self) {
        self.seen.clear();
        self.last = None;
        self.clean = 0;
        self.leaves = 0;
        self.put_leaves.clear();
        self.legs.clear();
        self.lpath.clear();
        self.cur = NO_LEG;
        self.epoch = u64::MAX;
    }

    /// Located leaf of the last `probe_path`, for [`Tree::put_at`] / [`Tree::del_at`] ([`NO_LEG`]: none).
    pub fn leg(&self) -> u32 {
        self.cur
    }

    /// The last `probe_path` was for a put: its leaf may split.
    pub fn note_put(&mut self) {
        if let Some(l) = self.last {
            self.put_leaves.insert(l);
        }
    }

    /// Distinct leaves noted by `note_put`.
    pub fn put_leaves(&self) -> usize {
        self.put_leaves.len
    }

    /// Distinct pages that must be resident at once.
    pub fn resident(&self) -> usize {
        self.seen.len
    }
}

/// How a put / delete finds the leaf of its key.
enum Find<'a> {
    /// Remembered leaf (`Tree::locate` hints) or a descent.
    Walk,
    /// Ascending keys (omap run merges).
    Sorted(&'a mut SortedCursor),
    /// The leg the txn's probe located (`Tree::put_at`).
    At(&'a PathSet, u32),
}

/// Interior page + entry index a fence key is read from.
type Fence = (u32, usize);

/// Remembered leaf location (see `Tree::locate`).
#[derive(Debug, Default)]
struct Hint {
    epoch: u64,
    has_lo: bool,
    has_hi: bool,
    /// Big-endian 8-byte prefixes of `lo` / `hi` (zero padded): monotone in key order, a cheap reject test.
    lo8: u64,
    hi8: u64,
    lo: Vec<u8>,
    hi: Vec<u8>,
    path: Vec<(u32, u16)>,
    leaf: u32,
}

/// Leaf split point for an append at the end of a key run that unrelated keys follow in the same leaf (pgmeta: a log
/// entry before `_info`, a dup record before the keys after `dup_`; a sequential object write before the next object):
/// the new entry `pos` opens the right page, the left page keeps the run full instead of half (the next appends land
/// right of it, a size-balanced split would leave every run page half empty). Only when `pos` is at or right of the
/// balanced point `m0` (the right page holds at most the balanced half + the new entry) and the new key extends its
/// left neighbour clearly further than its right one (lcp by 2+ bytes: random inserts keep the balanced split).
/// Records put in ascending key order (`Stage::finish`), so later puts of the txn never land in the full left page:
/// the dirty-page bound of `State::prepare` holds as for a balanced split (adr 0021 am. 35).
fn run_end_split(e: &page::Ents, pos: usize, m0: usize, psz: usize) -> Option<usize> {
    let n = e.len();
    if pos == 0 || pos + 1 >= n || pos < m0 {
        return None;
    }
    let (l, k, r) = (e.key(pos - 1), e.key(pos), e.key(pos + 1));
    if page::lcp(l, k) < page::lcp(k, r) + 2 {
        return None;
    }
    let fmt = page::FMT_SLOTTED;
    (page::fits(e, 0, pos, true, psz, fmt) && page::fits(e, pos, n, true, psz, fmt)).then_some(pos)
}

/// Longest tree entry (4 + key + value) a page accepts. Any set of entries <= this that fits `psz + 1 entry` can be
/// split into two pages that both fit (`page::Ents::split_point`): 2 * (max_entry + slot) <= page capacity.
pub fn max_entry_for(psz: usize) -> usize {
    psz / 2 - 256
}

/// Room an entry with the longest allowed key keeps for its value (inline value or one fragment chunk).
pub const KEY_VAL_ROOM: usize = 512;

/// Longest tree key: entry limit minus entry header, value tag and `KEY_VAL_ROOM` (8 KiB pages: 3323 B; was `psz / 16` = 512
/// before adr 0021 am. 10).
pub fn max_key_for(psz: usize) -> usize {
    max_entry_for(psz) - 5 - KEY_VAL_ROOM
}

/// Entry size up to which short-key values stay inline / fragments are cut (the pre-am.10 `max_entry`): keeps the
/// leaf density and fragment sizes of existing stores for every key that fitted before.
pub fn soft_entry_for(psz: usize) -> usize {
    psz / 4
}

const NHINT: usize = 32;
/// Max sibling leaves a cold scan reads ahead.
const SCAN_RA: usize = 32;

#[inline]
fn pfx8(k: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    let n = k.len().min(8);
    b[..n].copy_from_slice(&k[..n]);
    u64::from_be_bytes(b)
}

/// Which ends of a range delete `[a, b)` a page's key range holds: the lower end `a`, and the upper end = the keys right
/// below `b` (a page starting exactly at `b` holds nothing of the range). The root holds both.
///
/// Rule (adr 0021 S6): `del_range` reads and keeps only the pages holding an end; every other page of the range lies
/// completely inside it and is dropped whole by address (never read with the lazy free; without it interior pages are
/// read to free what lies below them). A child holding no end is never a boundary child, also not the first or last
/// child a descent clamps to when the end lies outside the parent's range (such a child lies inside the range).
///
/// Why a probed multi-op record never misses (OQ 133): the children a delete removes from a page lie strictly between
/// its end children, so their key range goes to `a`'s child, or to `b`'s child when `a` lies below the page; below that
/// child the range follows the route of the same end, which the delete read. A delete thus moves keys only inside its
/// range and only onto pages it read; a split moves keys only onto pages it created. By induction every page a later op
/// of the record reads (a put/remove: its key's route; a range delete: its ends' routes) was loaded by the record's
/// probe in the tree before the record, or read or created by an earlier op. The earlier rule also descended into the
/// clamped first/last children: a page inside the range before the record (not probed) can hold an end after an
/// overlapping earlier delete moved keys into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ends {
    a: bool,
    b: bool,
}

impl Ends {
    const BOTH: Ends = Ends { a: true, b: true };
}

/// Child of interior page `pg` holding the keys right below `b`: `b`'s route, or the child before it when that child
/// starts exactly at `b`.
fn route_below(pg: &[u8], b: &[u8], scratch: &mut Vec<u8>) -> usize {
    let i = page::int_route(pg, b);
    if i > 0 && page::int_key_eq(pg, i, b, scratch) {
        i - 1
    } else {
        i
    }
}

#[derive(Debug)]
pub struct Tree {
    cfg: TreeCfg,
    geom: MetaGeom,
    max_key: usize,
    max_entry: usize,
    slab: Vec<Page>,
    free: Vec<u32>,
    /// Free slots whose page buffer was given back ([`Tree::drop_clean`], [`Tree::set_cap`]): `free[..released]`; the next
    /// page in such a slot allocates one.
    released: usize,
    /// Page budget the CLOCK evicts to: `cache_pages` at mount, then what the device's page pool gives the shard
    /// ([`crate::pagepool`]). `cfg.cache_pages` stays the shard's own share (txn budget, walk and readahead bounds).
    cap: usize,
    map: AddrMap,
    root_addr: u64,
    root_crc: u32,
    height: u8,
    virt_next: u64,
    dirty: Vec<u32>,
    ndirty: usize,
    resident: usize,
    retired: Vec<u64>,
    /// The arena chunks of the finished checkpoints, for the next freeze ([`crate::fzarena::Arena`]): a fresh
    /// tens-of-MB arena per checkpoint cost its page faults, and its free (an EAL hugepage block, payload allocator)
    /// zeroed it on the core: 7-20 ms in one piece at checkpoint start and end.
    spare_chunks: Vec<Vec<u8>>,
    /// Pages per arena chunk: the shard's largest device write ([`Tree::set_ckpt_chunk`]).
    chunk_pages: usize,
    wants: Vec<Want>,
    /// Pages the failed lookups since the last `miss_log_clear` missed (wake tokens, adr 0043 am. 9).
    mlog: crate::toks::Toks<8>,
    /// Residency leases (adr 0043 am. 18): page address -> leases pinning it. `shrink` never evicts a pinned page; empty
    /// unless an op waits for its loads (a held replica write, an EC own-shard wait).
    pins: crate::fx::FxMap<u64, u32>,
    /// Misses of the leased probe in progress (`Some` while it runs): the store pins them for its lease.
    pin_log: Option<Vec<u64>>,
    pub(crate) dependencies: crate::dependencies::Dependencies,
    bad: Vec<(u64, StoreError)>,
    hand: usize,
    /// Inside [`Tree::scan`] of a listing cursor: leaf accesses set no CLOCK reference, leaf misses and readahead are read
    /// as scan pages (`Want::scan`).
    scanning: bool,
    /// Scan pages in load order `(slot, seq)`: `shrink` evicts these first (entries of pages gone since are skipped).
    scan_q: VecDeque<(u32, u64)>,
    seq: u64,
    pub meta: MetaAlloc,
    /// Elastic meta image: pages of the current image, its reference, and the cell-set generation it describes.
    blob_cur: Vec<u64>,
    blob_ref: Option<(u64, u32, u32)>,
    blob_gen: u64,
    path: Vec<(u32, u16)>,
    tmp: Vec<u8>,
    ents: page::Ents,
    /// Sorted write batches ([`Tree::write_sorted_batch`]): the new entries of one leaf, the merged leaf, the page cuts.
    bents: page::Ents,
    mrg: page::Ents,
    cuts: Vec<usize>,
    sep: Vec<u8>,
    keybuf: Vec<u8>,
    kb2: Vec<u8>,
    /// Scratch of a range delete's delta touch span (`[first deleted key, last + 1)`), reused per boundary leaf.
    span_lo: Vec<u8>,
    span_hi: Vec<u8>,
    /// Decoded key of one interior entry for [`page::int_key_eq`] (range-scan boundary compare, reused per descent).
    cmpbuf: Vec<u8>,
    /// Structure epoch: bumped by every change that can invalidate `hints`.
    epoch: u64,
    hints: Vec<Hint>,
    hint_next: usize,
    /// Hint of the last locate (tried first: a txn applies its sorted keys leaf by leaf).
    hint_last: usize,
    /// Compact reject table of `hints` (lo8, hi8; unbounded side 0 / MAX; never-matching default): the scan touches 16 B per hint.
    hint_rng: [(u64, u64); NHINT],
    pr_data: Vec<u8>,
    pr_idx: Vec<(u32, u32, u32)>,
    /// Underfull leaves seen by this txn's deletes (a key inside each): merge candidates for `finish_txn` (am. 29).
    mg_data: Vec<u8>,
    mg_idx: Vec<(u32, u32)>,
    /// Background compaction (adr 0021 am. 33): a key inside each underfull leaf the txn-time merge could not take (its
    /// neighbour cold, or both pages clean), FIFO. The arena is compacted when its dead front outgrows the live part.
    cq_data: Vec<u8>,
    cq_idx: VecDeque<(u32, u32)>,
    cq_key: Vec<u8>,
    remap: AddrMap2,
    /// Lazy subtree free (adr 0021 am. 18): range deletes detach on-disk subtrees without reading them.
    lazy: bool,
    /// Pages freed by address since the shard last looked (`take_gone`).
    gone: Vec<(u64, u32)>,
    /// Detached subtrees still allocated (persisted in the meta image), freed from the back (depth first).
    dead: Vec<Dead>,
    /// Addresses of `dead` entries whose page read is in flight.
    dead_fly: Vec<u64>,
    /// `dead` changed since the last freeze (the image needs a rewrite).
    dead_gen: u64,
    dead_frozen_gen: u64,
    /// Leaf deltas (adr 0021 am. 19).
    deltas: bool,
    delta_cap: usize,
    meta_growable: usize,
    touch_max: usize,
    entry_max: usize,
    chain_max: usize,
    /// Leaves one freeze may turn into deltas (`ShardCfg::ckpt_delta_leaves`, 0 = unbounded) and what is left of it in
    /// the running freeze.
    delta_leaf_max: usize,
    delta_left: usize,
    chains: ChainSet,
    /// Live delta segments, oldest first (persisted in the meta image), and their pages.
    segs: VecDeque<SegDir>,
    seg_pages: usize,
    /// Buffer of the delta page being filled (reused page after page).
    dpage_buf: Vec<u8>,
    /// Segment cleaning by relog (`FEAT_DELTA_RELOG`).
    relog: bool,
    delta_seq: u64,
    segs_gen: u64,
    segs_frozen_gen: u64,
    ops_buf: Vec<u8>,
    victims: Option<Vec<(u64, u32, Vec<u8>)>>,
    /// Entry bytes chosen by the freeze in progress.
    pending_delta: usize,
    /// Number of the freeze in progress or last begun (wrapping, never 0; 0 = none yet).
    fz_no: u32,
    /// Entry bytes of hot leaves (settled by the previous freeze too) the freeze in progress (until the next
    /// `freeze_begin`: the last one) chose / declined for the RAM cap ([`Tree::delta_room`]): what the next
    /// checkpoint folds old chains for ([`Tree::delta_victims`]).
    hot_chosen: usize,
    hot_short: usize,
    /// Sliced freeze in progress (adr 0021 am. 40).
    fz: Option<Box<Fz>>,
    /// Delta touch log buffers (`touch_max` bytes each) of pages that are clean again: a clean page holds none (it would
    /// keep up to `psz/4` outside the cache budget), a page that gets dirty takes one from here (no allocation on the
    /// write path). At most `cache_pages / 8` are kept.
    touch_pool: Vec<Vec<u8>>,
    /// Capacity of all touch log buffers held (pages + pool).
    touch_bytes: usize,
    pub stats: TreeStats,
    /// Leaves written whole by checkpoints, by the first byte of their first key (the caller's key tag: which key
    /// space the checkpoint write-back comes from, doc/perf/store-create-bytes-20261024.md).
    pub fz_whole_tag: Box<[u64; 256]>,
}

type AddrMap2 = HashMap<u64, (u64, u32), BuildHasherDefault<AddrHasher>>;

impl Tree {
    pub fn new(
        cfg: TreeCfg,
        geom: MetaGeom,
        meta: MetaAlloc,
        root: Option<(u64, u32, u8)>,
    ) -> Tree {
        assert!((4096..=32768).contains(&cfg.psz) && cfg.psz.is_power_of_two());
        let mut cfg = cfg;
        cfg.max_walk = cfg.max_walk.min(cfg.cache_pages / 4).max(4);
        let cap = cfg.cache_pages;
        debug_assert!(
            root.is_none_or(|(_, _, h)| h > 0),
            "a tree root reference carries height >= 1"
        );
        let (root_addr, root_crc, height) = root.unwrap_or((NONE, 0, 0));
        Tree {
            max_key: max_key_for(cfg.psz),
            max_entry: max_entry_for(cfg.psz),
            tmp: vec![0; cfg.psz],
            cfg,
            geom,
            slab: Vec::new(),
            free: Vec::new(),
            released: 0,
            cap,
            map: AddrMap::default(),
            root_addr,
            root_crc,
            height,
            virt_next: 1,
            dirty: Vec::new(),
            ndirty: 0,
            resident: 0,
            retired: Vec::new(),
            spare_chunks: Vec::new(),
            chunk_pages: 1,
            wants: Vec::new(),
            mlog: Default::default(),
            pins: Default::default(),
            pin_log: None,
            dependencies: Default::default(),
            bad: Vec::new(),
            hand: 0,
            scanning: false,
            scan_q: VecDeque::new(),
            seq: 0,
            meta,
            blob_cur: Vec::new(),
            blob_ref: None,
            blob_gen: 0,
            path: Vec::new(),
            ents: page::Ents::default(),
            bents: page::Ents::default(),
            mrg: page::Ents::default(),
            cuts: Vec::new(),
            sep: Vec::new(),
            keybuf: Vec::new(),
            kb2: Vec::new(),
            span_lo: Vec::new(),
            span_hi: Vec::new(),
            cmpbuf: Vec::new(),
            epoch: 1,
            hints: (0..NHINT).map(|_| Hint::default()).collect(),
            hint_next: 0,
            hint_last: 0,
            hint_rng: [(1, 0); NHINT],
            pr_data: Vec::new(),
            pr_idx: Vec::new(),
            mg_data: Vec::new(),
            mg_idx: Vec::new(),
            cq_data: Vec::new(),
            cq_idx: VecDeque::new(),
            cq_key: Vec::new(),
            remap: AddrMap2::default(),
            gone: Vec::new(),
            lazy: false,
            dead: Vec::new(),
            dead_fly: Vec::new(),
            dead_gen: 0,
            dead_frozen_gen: 0,
            deltas: false,
            delta_cap: 0,
            meta_growable: 0,
            touch_max: 0,
            entry_max: 0,
            chain_max: 0,
            delta_leaf_max: 0,
            delta_left: usize::MAX,
            chains: ChainSet::new(),
            segs: VecDeque::new(),
            seg_pages: 0,
            dpage_buf: Vec::new(),
            relog: false,
            delta_seq: 0,
            segs_gen: 0,
            segs_frozen_gen: 0,
            ops_buf: Vec::new(),
            victims: None,
            pending_delta: 0,
            fz_no: 0,
            hot_chosen: 0,
            hot_short: 0,
            fz: None,
            touch_pool: Vec::new(),
            touch_bytes: 0,
            stats: TreeStats::default(),
            fz_whole_tag: Box::new([0; 256]),
        }
    }

    fn int_fmt(&self) -> u8 {
        if self.cfg.compact_int {
            page::FMT_COMPACT
        } else {
            page::FMT_SLOTTED
        }
    }
    pub fn psz(&self) -> usize {
        self.cfg.psz
    }
    pub fn geom(&self) -> &MetaGeom {
        &self.geom
    }
    pub fn height(&self) -> u8 {
        self.height
    }
    pub fn dirty_pages(&self) -> usize {
        self.ndirty
    }
    pub fn resident_pages(&self) -> usize {
        self.resident
    }

    /// Bytes of the page budget (the cap) the tree holds no page buffer for: buffers are allocated on demand and kept by
    /// free slots, given back by a cache drop or a lower cap ([`Tree::set_cap`]). The data cache may use them meanwhile
    /// (adr 0633-data-cache-envelope).
    pub fn unallocated_bytes(&self) -> u64 {
        self.cap.saturating_sub(self.held()) as u64 * self.cfg.psz as u64
    }

    /// Slab slots (cached pages and free slots): what one revolution of the CLOCK hand covers.
    pub fn slots(&self) -> usize {
        self.slab.len()
    }

    /// Page buffers allocated: cached pages and free slots that kept theirs.
    fn held(&self) -> usize {
        self.slab.len() - self.released
    }

    /// Page budget the CLOCK evicts to (see `Tree::cap`).
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Set the page budget (the device's page pool, [`crate::pagepool`]): pages above it go at the next shrink, buffers of
    /// free slots above [`buffer_mark`] of it (and above the pages cached) go back to the allocator now. Call between
    /// operations only.
    pub fn set_cap(&mut self, cap: usize) {
        self.cap = cap;
        let keep = buffer_mark(cap).max(self.resident);
        while self.held() > keep && self.released < self.free.len() {
            let s = self.free[self.released] as usize;
            self.slab[s].buf = Box::default();
            self.released += 1;
        }
    }

    /// Cached pages are over the bounded overshoot of the budget ([`buffer_mark`]): the shard shrinks even with page reads
    /// in flight.
    pub fn over_mark(&self) -> bool {
        self.resident > buffer_mark(self.cap)
    }

    /// RAM held by this tree (operator memory accounting, `dump_mempools`): resident page images, delta tracking
    /// buffers, delta chains, bookkeeping lists.
    pub fn mem(&self) -> TreeMem {
        // O(1): operator command on a data core, no walk over the slab (millions of slots on a big cache)
        let psz = self.cfg.psz as u64;
        #[cfg(debug_assertions)]
        {
            // the counters match the slab: free slots and clean pages hold no touch log buffer
            let held: usize = self
                .slab
                .iter()
                .map(|p| p.touched.capacity())
                .sum::<usize>()
                + self.touch_pool.iter().map(Vec::capacity).sum::<usize>();
            debug_assert_eq!(held, self.touch_bytes);
            let free = self.slab.iter().filter(|p| p.addr == NONE).count();
            debug_assert_eq!(free, self.free.len());
            debug_assert!(
                self.slab
                    .iter()
                    .all(|p| p.flags & F_DIRTY != 0 || p.touched.capacity() == 0)
            );
        }
        TreeMem {
            pages: self.resident as u64,
            page_bytes: self.resident as u64 * psz,
            touched_bytes: self.touch_bytes as u64,
            touch_pool_bytes: (self.touch_pool.len() * self.touch_max) as u64,
            slab_slots: self.slab.len() as u64,
            slab_bytes: (self.slab.capacity() * std::mem::size_of::<Page>()) as u64,
            // freed / evicted slots keep their page buffer for the next page (no allocation on the hot path)
            free_slots: self.free.len() as u64,
            free_bytes: (self.free.len() - self.released) as u64 * psz,
            chains: self.chains.len() as u64,
            chain_bytes: self.chains.bytes() as u64,
            dead: self.dead.len() as u64,
            retired: self.retired.len() as u64,
            dependency_bytes: self.dependencies.bytes(),
        }
    }
    pub fn max_entry(&self) -> usize {
        self.max_entry
    }
    /// See [`soft_entry_for`].
    pub fn soft_entry(&self) -> usize {
        soft_entry_for(self.cfg.psz)
    }
    /// Pages one txn may need to pull in at once (a txn needing more can never be guaranteed to complete).
    pub fn txn_page_budget(&self) -> usize {
        self.cfg.cache_pages / 2
    }
    pub fn max_key(&self) -> usize {
        self.max_key
    }

    // ---------------------------------------------------------------- slab / cache

    fn new_slot(&mut self, kind: u8, level: u8, addr: u64) -> u32 {
        self.resident += 1;
        let s = if let Some(s) = self.free.pop() {
            let p = &mut self.slab[s as usize];
            if p.buf.is_empty() {
                p.buf = vec![0u8; self.cfg.psz].into_boxed_slice();
                self.released -= 1;
            }
            s
        } else {
            self.slab.push(Page {
                buf: vec![0u8; self.cfg.psz].into_boxed_slice(),
                addr: NONE,
                flags: 0,
                dcrc: 0,
                touched: Vec::new(),
                seq: 0,
                alias: 0,
                fz_no: 0,
                #[cfg(debug_assertions)]
                fz_crc: 0,
            });
            (self.slab.len() - 1) as u32
        };
        self.touch_release(s);
        let p = &mut self.slab[s as usize];
        let fmt = if self.cfg.compact_int {
            page::FMT_COMPACT
        } else {
            page::FMT_SLOTTED
        };
        page::init_fmt(&mut p.buf, kind, level, addr, self.cfg.shard, fmt);
        p.addr = addr;
        p.alias = 0;
        p.fz_no = 0;
        p.flags = F_REF;
        p.dcrc = 0;
        self.seq += 1;
        p.seq = self.seq;
        self.map.insert(addr, s);
        s
    }

    fn new_virtual(&mut self, kind: u8, level: u8) -> u32 {
        let a = VIRT | self.virt_next;
        self.virt_next += 1;
        let s = self.new_slot(kind, level, a);
        self.mark_dirty(s);
        s
    }

    /// Dirty by a structural change: rewritten whole at the next freeze.
    fn mark_dirty(&mut self, s: u32) {
        self.fz_touch(s);
        self.slab[s as usize].flags |= F_MOD;
        self.mark_dirty_val(s);
    }

    /// Dirty by a value-level change of a leaf (or by being on the path to one): a leaf may be written as a delta, a
    /// path page is rewritten only if one of its children is.
    fn mark_dirty_val(&mut self, s: u32) {
        if self.slab[s as usize].flags & F_FRZ != 0 {
            if page::level(&self.slab[s as usize].buf) == 0 {
                self.fz_process(s); // a leaf changes right after this
            } else {
                // a path page: unchanged now, but dirty again for the next checkpoint
                let p = &mut self.slab[s as usize];
                if p.flags & F_AGAIN == 0 {
                    p.flags |= F_AGAIN;
                    self.ndirty += 1;
                    self.dirty.push(s);
                }
                return;
            }
        }
        let p = &mut self.slab[s as usize];
        if p.flags & F_DIRTY == 0 {
            p.flags |= F_DIRTY;
            self.ndirty += 1;
            self.dirty.push(s);
        }
    }

    // ---------------------------------------------------------------- leaf deltas (adr 0021 am. 19)

    /// Is `s` a leaf whose changes are logged for a delta (real address, no structural change, log not overflowed)?
    #[inline]
    fn tracking(&self, s: u32) -> bool {
        let p = &self.slab[s as usize];
        self.deltas && p.flags & (F_NOTRK | F_MOD) == 0 && p.addr & VIRT == 0
    }

    #[inline]
    fn touch_key(&mut self, leaf: u32, key: &[u8]) {
        self.fz_touch(leaf);
        if self.tracking(leaf) && self.touch_room(leaf, key.len() + 3) {
            delta::touch_key(&mut self.slab[leaf as usize].touched, key);
        }
    }

    fn touch_span(&mut self, leaf: u32, a: &[u8], b: &[u8]) {
        self.fz_touch(leaf);
        if self.tracking(leaf) && self.touch_room(leaf, a.len() + b.len() + 5) {
            delta::touch_span(&mut self.slab[leaf as usize].touched, a, b);
        }
    }

    /// Room for `need` more bytes in the touch log of `leaf` (a buffer of `touch_max` bytes from the pool, so the
    /// append never reallocates). False = the log overflows: the leaf is written whole (`F_NOTRK`), its log released.
    fn touch_room(&mut self, leaf: u32, need: usize) -> bool {
        let max = self.touch_max;
        let p = &mut self.slab[leaf as usize];
        if p.touched.len() + need > max {
            p.flags |= F_NOTRK;
            self.touch_release(leaf);
            return false;
        }
        if p.touched.capacity() < max {
            let mut b = self.touch_pool.pop().unwrap_or_else(|| {
                let b = Vec::with_capacity(max);
                self.touch_bytes += b.capacity();
                b
            });
            let p = &mut self.slab[leaf as usize];
            b.extend_from_slice(&p.touched); // empty: only pool buffers ever hold entries
            self.touch_bytes -= p.touched.capacity();
            p.touched = b;
        }
        true
    }

    /// Take the touch log buffer from page `s` (clean again, freed, or overflowed): back to the pool, or freed when the
    /// pool is full. Never changes what the page or its delta chain hold; the log is empty after this.
    fn touch_release(&mut self, s: u32) {
        let mut b = std::mem::take(&mut self.slab[s as usize].touched);
        if b.capacity() == 0 {
            return;
        }
        if b.capacity() >= self.touch_max && self.touch_pool.len() < self.cfg.cache_pages / 8 {
            b.clear();
            self.touch_pool.push(b);
        } else {
            self.touch_bytes -= b.capacity();
        }
    }

    /// Bound the leaves one freeze turns into deltas (0 = unbounded); the others are written whole.
    pub fn set_delta_leaf_max(&mut self, n: usize) {
        self.delta_leaf_max = n;
    }

    /// Switch leaf deltas on (stores with `FEAT_LEAF_DELTA`; mount): limits derive from the page size, `cap` is the RAM
    /// the delta chains may hold (`0` = off). `segs` is the persisted segment directory; the caller then feeds the
    /// pages of those segments to [`Tree::load_delta_page`]. `relog`: the store may carry relogged chains
    /// (`FEAT_DELTA_RELOG`), and checkpoints clean the oldest segments by relogging.
    pub fn set_delta(&mut self, on: bool, relog: bool, cap: usize, segs: Vec<SegDir>) {
        self.deltas = on;
        self.relog = relog;
        self.delta_cap = cap;
        let psz = self.cfg.psz;
        // cap 0: chains of the store are still read and drained, but no new delta is written
        self.touch_max = if cap > 0 { psz / 4 } else { 0 };
        self.entry_max = psz / 4;
        self.chain_max = psz / 2;
        self.chains.clear();
        self.delta_seq = segs.iter().map(|s| s.seq).max().unwrap_or(0);
        self.seg_pages = segs.iter().map(|s| s.pages.len()).sum();
        self.segs = segs.into();
        self.segs_gen = 0;
        self.segs_frozen_gen = 0;
    }

    /// The live segment directory (what the next image lists).
    pub fn segdirs(&self) -> Vec<SegDir> {
        self.segs.iter().cloned().collect()
    }

    /// Mount: one page of a persisted segment (already read, `crc` from the directory): its entries join the chains.
    pub fn load_delta_page(&mut self, addr: u64, crc: u32, data: &[u8], seq: u64) -> Result<()> {
        page::validate_delta(data, self.cfg.psz, addr)
            .map_err(|m| StoreError::Corrupt(format!("delta page {addr}: {m}")))?;
        if page::stored_crc(data) != crc {
            return Err(StoreError::Corrupt(format!(
                "delta page {addr}: crc differs from the directory"
            )));
        }
        let bad = |m| StoreError::Corrupt(format!("delta page {addr}: {m}"));
        for (a, c, w, ops) in delta::parse_page(data).map_err(bad)? {
            if w & delta::RESTART != 0 && !self.relog {
                return Err(bad("relogged entry without FEAT_DELTA_RELOG"));
            }
            self.chains.load(a, c, seq, w, ops).map_err(bad)?;
        }
        Ok(())
    }

    pub fn delta_chain_bytes(&self) -> usize {
        self.chains.bytes()
    }

    pub fn delta_segments(&self) -> usize {
        self.segs.len()
    }

    pub fn delta_pages(&self) -> usize {
        self.seg_pages
    }

    /// Forget the delta chain of the image at `addr` (rewritten whole or freed). While a sliced freeze runs (adr 0021
    /// am. 40) the drop waits for its end: the checkpoint it writes may still need the chain's segments (the page is in
    /// its tree in the state of its lsn).
    fn drop_chain(&mut self, addr: u64) {
        if self.deltas {
            if let Some(fz) = self.fz.as_mut() {
                fz.dropped.push(addr);
            } else {
                self.chains.remove(addr);
            }
        }
    }

    /// Pages the delta segments may occupy: four times what the RAM cap holds (cold chains pin their segments), and a
    /// sixteenth of the meta space at most (its pages plus what elastic growth can still add, see
    /// [`Tree::set_meta_growable`]) so delta pages never starve ordinary tree pages. Segment cleaning (relog) copies the
    /// live chains of a segment forward, so its write amplification is about `bound / (bound - live)`, at most 4/3 while
    /// the RAM term binds. Counting only the pages a young elastic meta area holds made relog copy each live chain about
    /// three times on ice-a (doc/perf/store-create-bytes-20261024.md, adr 0021 am. 66).
    pub fn delta_max_pages(&self) -> usize {
        let meta = self.meta.len() as usize + self.meta_growable;
        (4 * self.delta_cap / self.cfg.psz).min((meta / 16).max(4))
    }

    /// Meta pages elastic growth can still add (shard, at each checkpoint start; 0 for a fixed meta area or while
    /// growth is blocked).
    pub fn set_meta_growable(&mut self, pages: usize) {
        self.meta_growable = pages;
    }

    /// May a leaf become a delta now? The RAM cap and the page bound hold; `pending` = entry bytes of this freeze so far
    /// (already in the chains: entries join them as their leaves settle). Over them the (resident) dirty leaf is simply
    /// written whole, which also drops its chain: no extra read, and for a working set far beyond the cap the store
    /// behaves as without deltas.
    fn delta_room(&self, pending: usize) -> bool {
        let psz = self.cfg.psz;
        self.chains.bytes() <= self.delta_cap
            && self.delta_pages() <= self.delta_max_pages()
            // the directory entries of this freeze's segment fit the meta image next to the reserved sections
            && self.meta.blob_len() + self.ext_reserve() + 12 * (pending / psz + 3)
                <= crate::alloc::blob_max_len(psz)
    }

    /// Chains to fold back into whole pages before the next freeze, oldest first, each one a leaf to load and write
    /// (`(addr, crc, route key)`):
    /// - the delta segments occupy more pages than allowed (chains of cold leaves pin old segments): [`MAX_FOLD`];
    /// - the last freeze declined entries of hot leaves (settled by the freeze before too) for the RAM cap: chains until
    ///   the cap has room for what that freeze chose and lacked for hot leaves once more.
    ///   Segment cleaning (relog) keeps the page bound, so without this chains whose leaves went cold held the cap for
    ///   good and every hot leaf was written whole (e9455 osd.0: ~0 delta entries vs 50-70k per shard and minute on its
    ///   peers, 2.5x checkpoint pages, doc/perf/straggler-1s-20261101.md). Oldest first = cold first: a hot chain is
    ///   young (it reaches `chain_max` and its leaf is written whole), a cold one only ages. A fold (a leaf load and a
    ///   whole write) pays off only for room a leaf keeps using: a hot leaf's chain saves a whole write per checkpoint,
    ///   while room for leaves dirty once in a while (a working set far beyond the cap) is folded again before their
    ///   next change (`small_updates` over 200k keys: +50 % reads for -6 % writes when every decline counted).
    ///   Returns the victims `[from, from + max)` of this checkpoint and how many it has (the sliced start folds them in
    ///   windows, adr 0021 am. 80).
    pub fn delta_victims(&mut self, from: usize, max: usize) -> (Vec<(u64, u32, Vec<u8>)>, usize) {
        if !self.deltas {
            return (Vec::new(), 0);
        }
        let (want, cap) = if self.delta_pages() > self.delta_max_pages() {
            (usize::MAX, MAX_FOLD)
        } else if self.hot_short > 0 {
            // demand = what the last freeze chose and lacked for hot leaves. The freeze about to start still sees today's
            // room (folded chains leave at its end), the next one gets what the fold frees: room for both, at most one
            // demand
            let demand = self.hot_chosen + self.hot_short;
            let room = self.delta_cap.saturating_sub(self.chains.bytes());
            ((2 * demand).saturating_sub(room).min(demand), usize::MAX)
        } else {
            return (Vec::new(), 0);
        };
        // chosen once per checkpoint (its start is sliced and retried while the leaves load): the windows of one start
        // index the same list whatever txns did between them (`State::delta_gc`)
        let v = self
            .victims
            .get_or_insert_with(|| self.chains.victims(want, cap));
        let end = from.saturating_add(max).min(v.len());
        (
            v.get(from..end).map_or_else(Vec::new, <[_]>::to_vec),
            v.len(),
        )
    }

    /// Mark the leaf holding `route` for a whole rewrite at the next freeze, if it is still the page `(addr, crc)` the
    /// chain belongs to (else the chain is stale and dropped). `Err(Miss)`: pages queued.
    pub fn consolidate(&mut self, addr: u64, crc: u32, route: &[u8]) -> Result<()> {
        if self.root_addr == NONE {
            self.chains.remove(addr);
            return Ok(());
        }
        let leaf = self.descend(route)?;
        let p = &self.slab[leaf as usize];
        if p.addr == addr && p.dcrc == crc {
            if p.flags & F_MOD == 0 {
                self.stats.delta_folded += 1;
            }
            self.mark_path(leaf); // the parents must be dirty to take the new address
            self.slab[leaf as usize].flags |= F_MOD; // written whole
        } else {
            self.chains.remove(addr);
        }
        Ok(())
    }

    fn mark_path(&mut self, leaf: u32) {
        for k in 0..self.path.len() {
            let s = self.path[k].0;
            self.mark_dirty_val(s);
        }
        self.mark_dirty_val(leaf);
    }

    /// Drop a page from the tree (its disk image, if any, is freed at the next checkpoint).
    fn retire(&mut self, s: u32) {
        self.fz_touch(s);
        self.unalias(s);
        self.epoch += 1;
        let p = &mut self.slab[s as usize];
        if p.flags & F_DIRTY != 0 {
            self.ndirty -= 1;
        }
        let addr = p.addr;
        p.flags = 0;
        p.addr = NONE;
        self.map.remove(&addr);
        self.free.push(s);
        self.resident -= 1;
        self.stats.pruned += 1;
        self.touch_release(s);
        // a shadowed page (sliced freeze) still to be frozen: its copy frees the address (adr 0021 am. 40). A dead
        // shadow belongs to an earlier page of this slot (pruned, slot reused): the page retired now is not shadowed
        if let Some(sh) = self
            .fz
            .as_mut()
            .and_then(|f| f.shadows.get_mut(&s))
            .filter(|sh| sh.live)
        {
            sh.live = false;
            return;
        }
        if addr & VIRT == 0 {
            self.retired.push(addr);
            self.drop_chain(addr);
        }
    }

    fn lookup(&mut self, addr: u64, crc: u32, level: u8) -> Result<u32> {
        let scan = self.scanning && level == 0;
        if let Some(&s) = self.map.get(&addr) {
            // a resident page is read without the crc check; its level must still be the one the reference states, or a
            // forged image could route a descent back into an ancestor
            if page::level(&self.slab[s as usize].buf) != level {
                return Err(StoreError::Corrupt(format!(
                    "page {addr}: level {} where the reference expects {level}",
                    page::level(&self.slab[s as usize].buf)
                )));
            }
            if !scan {
                self.slab[s as usize].flags |= F_REF;
            }
            return Ok(s);
        }
        if let Some((_, e)) = self.bad.iter().find(|(a, _)| *a == addr) {
            return Err(e.clone());
        }
        let w = Want {
            addr,
            crc,
            level,
            dead: false,
            scan,
        };
        if !self.wants.contains(&w) {
            self.wants.push(w);
        }
        self.mlog.push(addr);
        if let Some(l) = &mut self.pin_log {
            l.push(addr);
        }
        self.dependencies.miss(addr);
        Err(StoreError::Miss)
    }

    fn resident_child(&self, parent: u32, idx: usize) -> Option<u32> {
        let (a, _) = page::int_child(&self.slab[parent as usize].buf, idx);
        self.map.get(&a).copied()
    }

    fn child_slot(&mut self, parent: u32, idx: usize) -> Result<u32> {
        let b = &self.slab[parent as usize].buf;
        let (addr, crc) = page::int_child(b, idx);
        let lvl = page::level(b) - 1;
        self.lookup(addr, crc, lvl)
    }

    fn root_slot(&mut self) -> Result<u32> {
        self.lookup(self.root_addr, self.root_crc, self.height - 1)
    }

    /// Pages that must be read before the failed operation can succeed.
    pub fn take_wants(&mut self, out: &mut Vec<Want>) {
        out.append(&mut self.wants);
    }
    /// Pages looked up and missed since the last [`Tree::miss_log_clear`].
    pub fn miss_log(&self) -> &crate::toks::Toks<8> {
        &self.mlog
    }
    pub fn miss_log_clear(&mut self) {
        self.mlog.clear();
    }
    /// Start (`Some`, an empty buffer) or end (`None`, returns the buffer with the misses since) collecting the misses of
    /// a leased probe.
    pub fn pin_log(&mut self, buf: Option<Vec<u64>>) -> Option<Vec<u64>> {
        std::mem::replace(&mut self.pin_log, buf)
    }
    /// One more lease keeps the page at `addr` resident once it is loaded (until [`Tree::unpin`]).
    pub fn pin(&mut self, addr: u64) {
        *self.pins.entry(addr).or_insert(0) += 1;
    }
    pub fn unpin(&mut self, addr: u64) {
        if let Some(n) = self.pins.get_mut(&addr) {
            *n -= 1;
            if *n == 0 {
                self.pins.remove(&addr);
            }
        }
    }
    /// Pinned page addresses (tests, diagnostics).
    pub fn pinned(&self) -> usize {
        self.pins.len()
    }
    fn is_pinned(&self, addr: u64) -> bool {
        !self.pins.is_empty() && self.pins.contains_key(&addr)
    }
    pub fn has_wants(&self) -> bool {
        !self.wants.is_empty()
    }
    pub(crate) fn is_bad(&self, addr: u64) -> bool {
        self.bad.iter().any(|(a, _)| *a == addr)
    }
    pub fn is_resident(&self, addr: u64) -> bool {
        self.map.contains_key(&addr)
    }

    /// A page freed by address: an earlier failed read of it (damaged page in a removed range, transient error) no longer
    /// applies once the address is reused (a healthy new page there would fail with the stale error until remount).
    fn unbad(&mut self, addr: u64) {
        if !self.bad.is_empty() {
            self.bad.retain(|(a, _)| *a != addr);
        }
    }

    /// Addresses whose read failed (operations needing them fail). Tests.
    pub fn bad_addrs(&self) -> impl Iterator<Item = u64> + '_ {
        self.bad.iter().map(|(a, _)| *a)
    }

    /// Record a failed page read (io error / crc mismatch): operations needing it fail with `e`.
    pub fn mark_bad(&mut self, addr: u64, e: StoreError) {
        if !self.bad.iter().any(|(a, _)| *a == addr) {
            self.bad.push((addr, e));
        }
    }

    /// Insert a page image read from disk, verifying crc, address and level against the parent's expectation.
    pub fn install(&mut self, w: &Want, data: &[u8]) -> Result<()> {
        if w.dead {
            return self.dead_process(w, data);
        }
        if self.map.contains_key(&w.addr) {
            return Ok(());
        }
        page::validate(data, self.cfg.psz, w.addr)
            .map_err(|m| StoreError::Corrupt(format!("tree page {}: {m}", w.addr)))?;
        if page::stored_crc(data) != w.crc {
            return Err(StoreError::Corrupt(format!(
                "tree page {}: crc differs from parent reference (lost/stale write)",
                w.addr
            )));
        }
        if page::level(data) != w.level {
            return Err(StoreError::Corrupt(format!(
                "tree page {}: level {} expected {}",
                w.addr,
                page::level(data),
                w.level
            )));
        }
        let s = self.new_slot(page::kind(data), page::level(data), w.addr);
        self.slab[s as usize].buf.copy_from_slice(data);
        self.slab[s as usize].dcrc = w.crc;
        if w.scan {
            // first in line for eviction once out of the load protection window (`shrink`)
            self.slab[s as usize].flags &= !F_REF;
            self.stats.scan_loads += 1;
            if self.scan_q.len() >= self.cap {
                self.scan_q.pop_front(); // only stale entries can be that old (the cache holds fewer pages)
            }
            self.scan_q.push_back((s, self.slab[s as usize].seq));
        }
        if self.deltas && w.level == 0 {
            // the deltas of earlier checkpoints bring the base image to its last durable state
            let r = self.chains.apply(
                w.addr,
                w.crc,
                &mut self.slab[s as usize].buf,
                &mut self.tmp,
                &mut self.ents,
            );
            if let Err(m) = r {
                self.forget(s); // not retire(): the page is still referenced on disk
                return Err(StoreError::Corrupt(format!("leaf {}: {m}", w.addr)));
            }
        }
        self.stats.loads += 1;
        Ok(())
    }

    /// Drop the cached copy in slot `s` (clean) without freeing its disk image.
    fn forget(&mut self, s: u32) {
        self.fz_touch(s);
        self.unalias(s);
        self.epoch += 1;
        let p = &mut self.slab[s as usize];
        let addr = p.addr;
        p.flags = 0;
        p.addr = NONE;
        self.map.remove(&addr);
        self.free.push(s);
        self.resident -= 1;
        self.touch_release(s);
    }

    /// Evict clean pages (CLOCK) until within budget. Call between operations only.
    pub fn shrink(&mut self) {
        self.evict_to(self.cap, self.slab.len());
    }

    /// Advance the CLOCK hand by up to `steps` slots as [`Tree::shrink`] does, stopping after `max` evictions: the pages
    /// one CLOCK over this tree and a faster one would evict ([`crate::pagepool`]). Returns the pages evicted. Call
    /// between operations only.
    pub fn age(&mut self, steps: usize, max: usize) -> usize {
        self.evict_to(self.resident.saturating_sub(max), steps)
    }

    /// Evict clean pages until at most `keep` are cached: listing leaves first, oldest first, then up to `steps` steps of
    /// the CLOCK hand. Returns the pages evicted.
    fn evict_to(&mut self, keep: usize, steps: usize) -> usize {
        let (n, before) = (self.slab.len(), self.resident);
        if n == 0 {
            return 0;
        }
        let protect = self.txn_page_budget() as u64; // pages a txn loaded stay until it ran
        // listing leaves first, oldest first (adr 0021 S5): a listing far faster than the point ops' reuse interval would
        // otherwise turn the CLOCK hand over the hot set between two of its touches
        while self.resident > keep
            && let Some(&(slot, seq)) = self.scan_q.front()
        {
            let p = &self.slab[slot as usize];
            if p.seq == seq && p.addr != NONE && p.seq + protect > self.seq {
                break; // the younger ones are protected too
            }
            self.scan_q.pop_front();
            // gone, reloaded, referenced by a point access since, or busy: the CLOCK owns it
            if p.seq == seq
                && p.addr != NONE
                && p.flags & (F_DIRTY | F_INFLIGHT | F_REF) == 0
                && !self.is_pinned(p.addr)
            {
                self.evict(slot);
                self.stats.scan_evictions += 1;
            }
        }
        let mut budget = steps;
        while self.resident > keep && budget > 0 {
            budget -= 1;
            self.hand = (self.hand + 1) % n;
            let pinned = self.is_pinned(self.slab[self.hand].addr);
            let p = &mut self.slab[self.hand];
            if p.addr == NONE
                || p.flags & (F_DIRTY | F_INFLIGHT) != 0
                || p.seq + protect > self.seq
                || pinned
            {
                continue;
            }
            if p.flags & F_REF != 0 {
                p.flags &= !F_REF;
                continue;
            }
            self.evict(self.hand as u32);
        }
        self.stats.hand_steps += (steps - budget) as u64;
        before - self.resident
    }

    /// Operator cache drop: evict every clean cached page and give the buffers of all free slots back to the allocator.
    /// Kept: dirty and in-flight pages, pages a running sliced freeze still holds (`F_FRZ`, `F_AGAIN`) and pinned pages
    /// (their loss would lose changes or fail a lease). Call between operations only. Returns `(pages dropped, pages
    /// kept)`; O(slab), an operator command.
    pub fn drop_clean(&mut self) -> (u64, u64) {
        let (mut dropped, mut kept) = (0, 0);
        for s in 0..self.slab.len() {
            let p = &self.slab[s];
            if p.addr == NONE {
                continue;
            }
            if p.flags & (F_DIRTY | F_INFLIGHT | F_FRZ | F_AGAIN) != 0 || self.is_pinned(p.addr) {
                kept += 1;
                continue;
            }
            self.evict(s as u32);
            dropped += 1;
        }
        self.scan_q.clear();
        for &s in &self.free {
            let p = &mut self.slab[s as usize];
            if !p.buf.is_empty() {
                p.buf = Box::default();
                self.released += 1;
            }
        }
        (dropped, kept)
    }

    /// Drop the clean cached page in `slot` (cache eviction).
    fn evict(&mut self, slot: u32) {
        self.unalias(slot);
        let p = &mut self.slab[slot as usize];
        let addr = p.addr;
        p.addr = NONE;
        p.flags = 0;
        self.epoch += 1;
        self.map.remove(&addr);
        self.free.push(slot);
        self.resident -= 1;
        self.stats.evictions += 1;
        self.touch_release(slot);
    }

    // ---------------------------------------------------------------- descent

    /// Leaf covering `key` and whether it has an upper fence. Fills `self.path` (interior pages root..parent
    /// with the child index taken) and, when there is a fence, `self.keybuf` (smallest key above the leaf's
    /// range). Recently located leaves are remembered with their key range (`hints`): a key inside such a range
    /// reuses the stored path without searching the interior pages. Hints are valid while `epoch` is unchanged;
    /// every structural change (split, root change, page removal, eviction) bumps it.
    fn locate(&mut self, key: &[u8]) -> Result<(u32, bool)> {
        self.stats.locates += 1;
        let ep = self.epoch;
        let k8 = pfx8(key);
        for j in 0..=NHINT {
            let i = if j == 0 { self.hint_last } else { j - 1 };
            let (l8, h8) = self.hint_rng[i];
            if k8 < l8 || k8 > h8 {
                continue;
            }
            let h = &self.hints[i];
            if h.epoch == ep
                && (!h.has_lo || (k8 >= h.lo8 && key >= h.lo.as_slice()))
                && (!h.has_hi || (k8 <= h.hi8 && key < h.hi.as_slice()))
            {
                let (leaf, has) = (h.leaf, h.has_hi);
                self.hint_last = i;
                self.path.clear();
                self.path.extend_from_slice(&h.path);
                self.keybuf.clear();
                if has {
                    self.keybuf.extend_from_slice(&h.hi);
                }
                self.stats.hint_hits += 1;
                if !self.scanning {
                    self.slab[leaf as usize].flags |= F_REF;
                }
                for k in 0..self.path.len() {
                    let s = self.path[k].0;
                    self.slab[s as usize].flags |= F_REF;
                }
                #[cfg(debug_assertions)]
                {
                    let (p0, kb0) = (self.path.clone(), self.keybuf.clone());
                    let r = self
                        .locate_full(key, false)
                        .expect("hinted pages are resident");
                    assert_eq!(
                        (r, &self.path, &self.keybuf),
                        ((leaf, has), &p0, &kb0),
                        "stale tree hint"
                    );
                }
                return Ok((leaf, has));
            }
        }
        self.stats.descents += 1;
        self.locate_full(key, true)
    }

    fn locate_full(&mut self, key: &[u8], store: bool) -> Result<(u32, bool)> {
        self.path.clear();
        let mut s = self.root_slot()?;
        let (mut lo, mut hi): (Option<Fence>, Option<Fence>) = (None, None);
        loop {
            let b = &self.slab[s as usize].buf;
            if page::level(b) == 0 {
                break;
            }
            let idx = page::int_route(b, key);
            if idx > 0 {
                lo = Some((s, idx));
            }
            if idx + 1 < page::nslots(b) {
                hi = Some((s, idx + 1));
            }
            self.path.push((s, idx as u16));
            s = self.child_slot(s, idx)?;
        }
        self.keybuf.clear();
        if let Some((fs, fi)) = hi {
            let fb = &self.slab[fs as usize].buf;
            page::key_into(fb, fi, &mut self.keybuf);
        }
        if store {
            let n = self.hint_next;
            self.hint_next = (n + 1) % NHINT;
            self.hint_last = n;
            let h = &mut self.hints[n];
            h.epoch = self.epoch;
            h.leaf = s;
            h.path.clear();
            h.path.extend_from_slice(&self.path);
            h.has_lo = lo.is_some();
            h.lo.clear();
            if let Some((ls, li)) = lo {
                page::key_into(&self.slab[ls as usize].buf, li, &mut h.lo);
            }
            h.has_hi = hi.is_some();
            h.hi.clear();
            h.hi.extend_from_slice(&self.keybuf);
            h.lo8 = pfx8(&h.lo);
            h.hi8 = pfx8(&h.hi);
            self.hint_rng[n] = (
                if h.has_lo { h.lo8 } else { 0 },
                if h.has_hi { h.hi8 } else { u64::MAX },
            );
        }
        Ok((s, hi.is_some()))
    }

    fn find_leaf(&mut self, key: &[u8]) -> Result<Option<u32>> {
        if self.root_addr == NONE {
            return Ok(None);
        }
        Ok(Some(self.locate(key)?.0))
    }

    /// Like `find_leaf`, also returns the smallest key greater than every key of that leaf's range
    /// (`fence`, left in `self.keybuf`; false = rightmost leaf).
    fn find_leaf_fence(&mut self, key: &[u8]) -> Result<Option<(u32, bool)>> {
        if self.root_addr == NONE {
            return Ok(None);
        }
        Ok(Some(self.locate(key)?))
    }

    fn descend(&mut self, key: &[u8]) -> Result<u32> {
        Ok(self.locate(key)?.0)
    }

    fn ensure_root(&mut self) {
        if self.root_addr == NONE {
            let s = self.new_virtual(LEAF, 0);
            self.root_addr = self.slab[s as usize].addr;
            self.root_crc = 0;
            self.height = 1;
        }
    }

    // ---------------------------------------------------------------- reads

    pub fn get(&mut self, key: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        let Some(leaf) = self.find_leaf(key)? else {
            return Ok(false);
        };
        let b = &self.slab[leaf as usize].buf;
        match page::leaf_search(b, key) {
            Ok(i) => {
                out.extend_from_slice(page::leaf_ent(b, i).1);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    /// Greatest entry with key <= `key` if it lives in the same leaf as `key`'s position: `Some(found)` (the entry, if any,
    /// is appended to `ok`/`ov`); `None` = the answer may be in the previous leaf (caller falls back to a scan).
    pub fn get_le(
        &mut self,
        key: &[u8],
        ok: &mut Vec<u8>,
        ov: &mut Vec<u8>,
    ) -> Result<Option<bool>> {
        let Some(leaf) = self.find_leaf(key)? else {
            return Ok(Some(false));
        };
        let b = &self.slab[leaf as usize].buf;
        let i = match page::leaf_search(b, key) {
            Ok(i) => i + 1,
            Err(i) => i,
        };
        if i == 0 {
            return Ok(None);
        }
        page::key_into(b, i - 1, ok);
        ov.extend_from_slice(page::leaf_ent(b, i - 1).1);
        Ok(Some(true))
    }

    /// One-descent "predecessor + range": emits the greatest entry with key <= `pivot` (only if it lives in the
    /// pivot's leaf) followed by every entry in `(pivot, end)`, ascending. `Ok(false)` = the predecessor may sit
    /// in the previous leaf: nothing was emitted, the caller falls back to a look-back scan. After
    /// `Err(Miss)` entries may have been emitted already: the caller discards them and retries.
    pub fn scan_pred(
        &mut self,
        pivot: &[u8],
        end: &[u8],
        f: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<bool> {
        let Some((leaf, has_fence)) = self.find_leaf_fence(pivot)? else {
            return Ok(true);
        };
        let b = &self.slab[leaf as usize].buf;
        let n = page::nslots(b);
        let mut i = match page::leaf_search(b, pivot) {
            Ok(i) => i,
            Err(0) => return Ok(false),
            Err(i) => i - 1,
        };
        let mut key = std::mem::take(&mut self.kb2);
        while i < n {
            key.clear();
            page::key_into(b, i, &mut key);
            if key.as_slice() >= end {
                self.kb2 = key;
                return Ok(true);
            }
            f(&key, page::leaf_ent(b, i).1);
            i += 1;
        }
        self.kb2 = key;
        if !has_fence || self.keybuf.as_slice() >= end {
            return Ok(true);
        }
        let fence = std::mem::take(&mut self.keybuf);
        let mut cur = ScanCursor::new(&fence, end);
        self.keybuf = fence;
        // a point-style lookup restarted from the pivot after every miss: its leaves stay referenced (a scan-mode
        // read would be evicted before the restart reaches it under cache pressure)
        self.scan_leaves(&mut cur, usize::MAX, usize::MAX, f)?;
        Ok(true)
    }

    /// Like `probe_key`, also accumulating the distinct pages of the paths of a whole txn into `s` (for the
    /// meta-space estimate: pages shared by many keys count once, pages already dirty cost nothing new).
    pub fn probe_path(&mut self, key: &[u8], s: &mut PathSet) -> Result<()> {
        if self.root_addr == NONE {
            s.cur = NO_LEG;
            return Ok(());
        }
        let (leaf, _) = self.locate(key)?;
        self.note_probe(leaf, s);
        Ok(())
    }

    /// Count the located `leaf` and its interior path (`self.path`) into `s` (see [`Tree::probe_path`]).
    fn note_probe(&mut self, leaf: u32, s: &mut PathSet) {
        if s.legs.get(s.cur as usize).is_none_or(|l| l.0 != leaf) {
            s.cur = s.legs.len() as u32;
            s.legs
                .push((leaf, s.lpath.len() as u32, self.path.len() as u32));
            s.lpath.extend_from_slice(&self.path);
        }
        if s.last == Some(leaf) {
            return; // same leaf as the previous probe: its path is already counted
        }
        s.last = Some(leaf);
        for k in 0..=self.path.len() {
            let slot = if k < self.path.len() {
                self.path[k].0
            } else {
                leaf
            };
            if s.seen.insert(slot) {
                if self.dirties_anew(slot) {
                    s.clean += 1;
                }
                s.leaves += (k == self.path.len()) as usize;
            }
        }
    }

    /// The legs `s` holds are the leaves of their keys now: stamp the structure epoch (any later structural change voids
    /// them, [`Tree::put_at`] walks then).
    pub fn seal_positions(&self, s: &mut PathSet) {
        s.epoch = self.epoch;
    }

    /// A change of page `slot` adds a dirty page: it is clean, or a pending interior page of a running sliced freeze
    /// (the next checkpoint needs a copy of its own, adr 0021 am. 40).
    fn dirties_anew(&self, slot: u32) -> bool {
        let p = &self.slab[slot as usize];
        p.flags & F_DIRTY == 0 || (p.flags & (F_FRZ | F_AGAIN) == F_FRZ && page::level(&p.buf) > 0)
    }

    /// Pages queued for loading and not yet read.
    pub fn wants_len(&self) -> usize {
        self.wants.len()
    }

    /// Make sure the path for `key` is cached (queues misses).
    pub fn probe_key(&mut self, key: &[u8]) -> Result<()> {
        self.find_leaf(key).map(|_| ())
    }

    /// Emit entries of the range in key order until the budget is used up. Resumable after a miss. A listing cursor
    /// (`ScanCursor::cold`) is scan-resistant: the leaves it visits or reads (miss, readahead) gain no CLOCK reference.
    pub fn scan(
        &mut self,
        cur: &mut ScanCursor,
        max_entries: usize,
        max_bytes: usize,
        f: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<ScanStatus> {
        let was = std::mem::replace(&mut self.scanning, cur.cold);
        let r = self.scan_leaves(cur, max_entries, max_bytes, f);
        self.scanning = was;
        r
    }

    fn scan_leaves(
        &mut self,
        cur: &mut ScanCursor,
        max_entries: usize,
        max_bytes: usize,
        f: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<ScanStatus> {
        let (mut ne, mut nb) = (0usize, 0usize);
        let mut key = Vec::new();
        // the right sibling the walk goes on in without a descent (`step_leaf`): it starts at its first entry
        let mut stepped: Option<u32> = None;
        while !cur.done {
            let (leaf, has_fence, from) = if let Some(s) = stepped.take() {
                (s, true, 0)
            } else {
                let found = match self.find_leaf_fence(&cur.next) {
                    Err(StoreError::Miss) => {
                        // readahead: the next leaves of this scan are read in the same round (a cold scan would
                        // otherwise take one serial device read per leaf)
                        if cur.ra_win > 0 {
                            // a miss with `ra` > 0 is normally a window leaf still in flight; one evicted before the scan
                            // came (needs > cache/2 other loads meanwhile, see `shrink`) is read on demand like this one
                            if cur.ra == 0 {
                                self.ra_topup(cur);
                            }
                        } else {
                            self.readahead((max_entries.saturating_sub(ne) / 32).clamp(1, SCAN_RA));
                        }
                        return Err(StoreError::Miss);
                    }
                    r => r?,
                };
                let Some((leaf, has_fence)) = found else {
                    cur.done = true;
                    break;
                };
                let i = page::leaf_lower_bound(&self.slab[leaf as usize].buf, &cur.next);
                (leaf, has_fence, i)
            };
            if cur.ra_win > 0 && (cur.ra as usize) * 4 < cur.ra_win as usize * 3 {
                self.ra_topup(cur); // rolling window: refill before the leaves already asked for run out
            }
            let b = &self.slab[leaf as usize].buf;
            let n = page::nslots(b);
            // every key of the leaf is below its fence: a fence at or below the end needs no compare per key
            let check_end = !has_fence || self.keybuf.as_slice() > cur.end.as_slice();
            // leaf keys = page prefix + entry suffix: the prefix is copied once per leaf
            key.clear();
            key.extend_from_slice(page::prefix(b));
            let pl = key.len();
            let mut i = from;
            let mut stopped = false;
            while i < n {
                if ne >= max_entries || nb >= max_bytes {
                    stopped = true;
                    break;
                }
                let (sfx, v) = page::leaf_ent(b, i);
                key.truncate(pl);
                key.extend_from_slice(sfx);
                if check_end && key.as_slice() >= cur.end.as_slice() {
                    cur.done = true;
                    return Ok(ScanStatus::Done);
                }
                f(&key, v);
                ne += 1;
                nb += key.len() + v.len();
                i += 1;
            }
            if stopped {
                // resume right after the last emitted key (`key`; nothing emitted from this leaf: unchanged)
                if i > from {
                    cur.next.clear();
                    cur.next.extend_from_slice(&key);
                    cur.next.push(0);
                }
                return Ok(ScanStatus::More);
            }
            if !has_fence {
                cur.done = true;
                return Ok(ScanStatus::Done);
            }
            if self.keybuf.as_slice() >= cur.end.as_slice() {
                cur.done = true;
                return Ok(ScanStatus::Done);
            }
            cur.next.clear();
            cur.next.extend_from_slice(&self.keybuf);
            cur.ra = cur.ra.saturating_sub(1);
            if ne >= max_entries || nb >= max_bytes {
                return Ok(ScanStatus::More);
            }
            stepped = self.step_leaf();
        }
        Ok(ScanStatus::Done)
    }

    /// The right sibling of the leaf the path ends in, without a descent: the next child of the same level-1 parent when it
    /// is resident and not that parent's last child (its fence, the parent's next separator, is then known; the last
    /// child's fence lies above the parent). Moves the path and the fence (`keybuf`) to it. `None`: the caller descends.
    fn step_leaf(&mut self) -> Option<u32> {
        let &(ps, pi) = self.path.last()?;
        let pb = &self.slab[ps as usize].buf;
        let ni = pi as usize + 1;
        if ni + 1 >= page::nslots(pb) {
            return None;
        }
        let s = self.resident_child(ps, ni)?;
        self.keybuf.clear();
        page::key_into(pb, ni + 1, &mut self.keybuf);
        if let Some(p) = self.path.last_mut() {
            p.1 = ni as u16;
        }
        if !self.scanning {
            self.slab[s as usize].flags |= F_REF;
        }
        Some(s)
    }

    /// After a miss on a leaf (`self.path` = the path to it): also queue reads for the next `n` sibling leaves of the same
    /// level-1 parent that are not resident.
    fn readahead(&mut self, n: usize) {
        self.readahead_from(0, n, None);
    }

    /// Rolling readahead of a cursor with a deep window: after the leaf the path points at, ask for the sibling leaves
    /// (same level-1 parent) up to `ra_win` ahead, never past the cursor's end key and never more than an eighth of the
    /// cache (the read-ahead pages must still be resident when the scan arrives). Hint only: nothing depends on it.
    fn ra_topup(&mut self, cur: &mut ScanCursor) {
        let win = (cur.ra_win as usize).min(self.cfg.cache_pages / 8).max(1);
        let have = cur.ra as usize;
        if have >= win {
            return;
        }
        cur.ra = (have + self.readahead_from(have, win - have, Some(&cur.end))) as u32;
    }

    /// Asks for the siblings `skip + 1 ..= skip + n` after the path's leaf (only those starting below `end`, when
    /// given); returns how many siblings that covers (resident ones included; 0 = no level-1 parent). Past the last
    /// child of the level-1 parent a bounded scan's window goes on in the next level-1 parent (read first when not
    /// resident), so a long scan does not drain its pipeline at every parent boundary.
    fn readahead_from(&mut self, skip: usize, n: usize, end: Option<&[u8]>) -> usize {
        let Some(&(ps, pi)) = self.path.last() else {
            return 0;
        };
        let b = &self.slab[ps as usize].buf;
        if self.slab[ps as usize].addr == NONE || page::level(b) != 1 {
            return 0;
        }
        let rem = page::nslots(b).saturating_sub(pi as usize + 1);
        // no allocation per call: wants go straight into the tree's list, the key scratch is reused
        let mut ws = std::mem::take(&mut self.wants);
        let mut kb = std::mem::take(&mut self.kb2);
        let mut covered = 0;
        let mut at_end = false;
        if skip < rem {
            (covered, at_end) =
                self.ra_children(ps, pi as usize + 1 + skip, n, end, &mut ws, &mut kb);
        }
        if let Some(end) = end
            && !at_end
            && covered < n
            && let Some(&(gs, gi)) = self
                .path
                .len()
                .checked_sub(2)
                .and_then(|i| self.path.get(i))
        {
            let gb = &self.slab[gs as usize].buf;
            let gi = gi as usize + 1;
            let next_below_end = gi < page::nslots(gb) && {
                kb.clear();
                page::key_into(gb, gi, &mut kb);
                kb.as_slice() < end
            };
            if next_below_end && self.slab[gs as usize].addr != NONE {
                let (naddr, ncrc) = page::int_child(gb, gi);
                match self.map.get(&naddr).copied() {
                    Some(ns) if page::level(&self.slab[ns as usize].buf) == 1 => {
                        let (c, _) = self.ra_children(
                            ns,
                            skip.saturating_sub(rem),
                            n - covered,
                            Some(end),
                            &mut ws,
                            &mut kb,
                        );
                        covered += c;
                    }
                    Some(_) => {}
                    None => {
                        let w = Want {
                            addr: naddr,
                            crc: ncrc,
                            level: 1,
                            dead: false,
                            scan: false, // interior: cached like any other
                        };
                        if !ws.contains(&w) {
                            ws.push(w);
                        }
                    }
                }
            }
        }
        self.wants = ws;
        self.kb2 = kb;
        covered
    }

    /// Wants (into `ws`, the tree's want list, deduplicated) for the non-resident children `lo .. lo + n` of the level-1
    /// page in slab slot `ps`, those starting below `end` only; returns how many it covered and whether the range end
    /// cut it short. `kb`: key scratch.
    fn ra_children(
        &self,
        ps: u32,
        lo: usize,
        n: usize,
        end: Option<&[u8]>,
        ws: &mut Vec<Want>,
        kb: &mut Vec<u8>,
    ) -> (usize, bool) {
        let b = &self.slab[ps as usize].buf;
        let hi = (lo + n).min(page::nslots(b));
        let mut covered = 0;
        for j in lo..hi {
            if let Some(end) = end {
                kb.clear();
                page::key_into(b, j, kb);
                if kb.as_slice() >= end {
                    return (covered, true); // this child starts beyond the range
                }
            }
            covered += 1;
            let (addr, crc) = page::int_child(b, j);
            let w = Want {
                addr,
                crc,
                level: 0,
                dead: false,
                scan: self.scanning,
            };
            if !self.map.contains_key(&addr) && !ws.contains(&w) {
                ws.push(w);
            }
        }
        (covered, false)
    }

    /// Load the pages of `[a, b)` in parallel rounds (read path: an omap page's fragments); no-op when the range is
    /// too big to be worth it. `Miss` = reads queued.
    pub fn prefetch_some(&mut self, a: &[u8], b: &[u8]) -> Result<()> {
        match self.probe_range_ex(a, b, self.cfg.cache_pages / 4, false) {
            Err(StoreError::TxnTooLarge) => Ok(()),
            r => r.map(|_| ()),
        }
    }

    // ---------------------------------------------------------------- writes

    pub fn put(&mut self, key: &[u8], val: &[u8]) -> Result<()> {
        self.put_inner(key, val, Find::Walk)
    }

    /// [`Tree::put`] at leg `leg` of `s` (the probe of the same txn located `key` there, [`PathSet::leg`]): no walk while
    /// the structure is unchanged since [`Tree::seal_positions`], else (or for [`NO_LEG`]) a walk.
    pub fn put_at(&mut self, s: &PathSet, leg: u32, key: &[u8], val: &[u8]) -> Result<()> {
        self.put_inner(key, val, Find::At(s, leg))
    }

    /// Puts and removals (an empty value) of the strictly ascending entries of `src` (omap run merge, adr 0476 am. 4),
    /// leaf by leaf: the entries below the fence of one leaf are merged with its entries in one rebuild, cut into as many
    /// pages as they need ([`page::leaf_cuts`]: full pages for an append at the right end of the tree, else balanced),
    /// instead of one insert (and page copy or rebuild) per entry; a leaf that receives one entry takes the single put or
    /// removal. A leaf whose entries change not at all (removals of absent keys) stays clean; one that removals emptied
    /// is pruned, one they thinned is a merge candidate (as after [`Tree::del`]). `f(key, val)` sees every entry in key
    /// order (`None`: a removal). On an error the writes of the leaves before stay applied.
    pub fn write_sorted_batch(
        &mut self,
        cur: &mut SortedCursor,
        src: &mut impl SortedSrc,
        mut f: impl FnMut(&[u8], Option<&[u8]>),
    ) -> Result<()> {
        self.ensure_root();
        let (mut bents, mut mrg, mut cuts) = (
            std::mem::take(&mut self.bents),
            std::mem::take(&mut self.mrg),
            std::mem::take(&mut self.cuts),
        );
        let r = self.write_batch_inner(cur, src, &mut f, &mut bents, &mut mrg, &mut cuts);
        (self.bents, self.mrg, self.cuts) = (bents, mrg, cuts);
        r
    }

    fn write_batch_inner(
        &mut self,
        cur: &mut SortedCursor,
        src: &mut impl SortedSrc,
        f: &mut impl FnMut(&[u8], Option<&[u8]>),
        bents: &mut page::Ents,
        mrg: &mut page::Ents,
        cuts: &mut Vec<usize>,
    ) -> Result<()> {
        while let Some(k0) = src.key() {
            let leaf = self.locate_sorted(cur, k0)?;
            bents.clear();
            while let Some(k) = src.key()
                && (!cur.has_fence || k < cur.fence.as_slice())
            {
                src.take(bents);
            }
            for j in 0..bents.len() {
                let (k, v) = (bents.key(j), bents.val(j));
                if k.len() > self.max_key || 4 + k.len() + v.len() > self.max_entry {
                    return Err(StoreError::Invalid(
                        "key or value too large for a tree page",
                    ));
                }
            }
            if bents.len() == 1 {
                let (k, v) = (bents.key(0), bents.val(0));
                if v.is_empty() {
                    if let Ok(i) = page::leaf_search(&self.slab[leaf as usize].buf, k) {
                        self.del_slot(leaf, i, k);
                    }
                    f(k, None);
                } else {
                    self.put_inner(k, v, Find::Sorted(cur))?;
                    f(k, Some(v));
                }
                continue;
            }
            let n_old = page::nslots(&self.slab[leaf as usize].buf);
            // what the batch changes: puts, and removals that find their key
            let (mut puts, mut gone) = (false, false);
            page::leaf_merge(&self.slab[leaf as usize].buf, bents, mrg, |j, old| {
                let v = bents.val(j);
                if v.is_empty() {
                    gone |= old.is_some();
                    f(bents.key(j), None);
                } else {
                    puts = true;
                    f(bents.key(j), Some(v));
                }
            });
            if !puts && !gone {
                continue;
            }
            self.mark_path(leaf);
            self.fz_touch(leaf);
            let append = mrg.len() == n_old + bents.len()
                && (n_old == 0 || mrg.key(n_old - 1) < bents.key(0));
            let full_left = append && self.rightmost_upto(self.path.len());
            page::leaf_cuts(mrg, self.cfg.psz, full_left, cuts);
            if cuts.is_empty() {
                assert!(
                    page::build(
                        &mut self.slab[leaf as usize].buf,
                        mrg,
                        0,
                        mrg.len(),
                        page::FMT_SLOTTED
                    ),
                    "merged leaf fits"
                );
                for j in 0..bents.len() {
                    self.touch_key(leaf, bents.key(j));
                }
                if gone {
                    if mrg.is_empty() {
                        let mut hi = bents.key(0).to_vec();
                        hi.push(0);
                        self.push_prune(bents.key(0), &hi);
                    } else if self.underfull(leaf) {
                        self.push_merge(leaf);
                    }
                }
                continue;
            }
            // several pages: split them off the leaf right to left, each a 2-way split of the leaf (its separators go
            // in after the leaf's slot in descending order); an interior split moves the leaf's route: descend again
            self.slab[leaf as usize].flags |= F_MOD; // the leaf keeps its slot but not its content
            let mut hi = mrg.len();
            for &c in cuts.iter().rev() {
                let r = self.new_virtual(LEAF, 0);
                assert!(
                    page::build(
                        &mut self.slab[r as usize].buf,
                        mrg,
                        c,
                        hi,
                        page::FMT_SLOTTED
                    ),
                    "cut page fits"
                );
                page::short_sep(mrg.key(c - 1), mrg.key(c), &mut self.sep);
                self.epoch += 1;
                self.stats.splits += 1;
                let (h, s0) = (self.height, self.stats.splits);
                self.propagate(Some(r));
                if self.height != h || self.stats.splits != s0 {
                    let l2 = self.descend(mrg.key(0))?;
                    debug_assert_eq!(l2, leaf, "the leaf of its first key");
                }
                hi = c;
            }
            assert!(
                page::build(
                    &mut self.slab[leaf as usize].buf,
                    mrg,
                    0,
                    hi,
                    page::FMT_SLOTTED
                ),
                "left page fits"
            );
        }
        Ok(())
    }

    /// The leaf of `key` at leg `leg` of `s` (path into `self.path`) while the structure epoch is the sealed one, else a
    /// walk.
    fn locate_at(&mut self, s: &PathSet, leg: u32, key: &[u8]) -> Result<u32> {
        let Some(&(leaf, p0, n)) = s.legs.get(leg as usize) else {
            return self.descend(key);
        };
        if s.epoch != self.epoch {
            return self.descend(key);
        }
        self.path.clear();
        self.path
            .extend_from_slice(&s.lpath[p0 as usize..(p0 + n) as usize]);
        #[cfg(debug_assertions)]
        {
            let p1 = self.path.clone();
            let r = self
                .locate_full(key, false)
                .expect("probed pages are resident");
            assert_eq!((r.0, &self.path), (leaf, &p1), "stale probed position");
        }
        Ok(leaf)
    }

    /// The leaf of ascending `key`: the cursor's while `key` is below its fence and the structure is unchanged, else a
    /// descent that moves the cursor there.
    fn locate_sorted(&mut self, cur: &mut SortedCursor, key: &[u8]) -> Result<u32> {
        if cur.valid && cur.epoch == self.epoch && (!cur.has_fence || key < cur.fence.as_slice()) {
            #[cfg(debug_assertions)]
            {
                let p0 = self.path.clone();
                let r = self
                    .locate_full(key, false)
                    .expect("cursor pages are resident");
                assert_eq!((r.0, &self.path), (cur.leaf, &p0), "stale sorted cursor");
            }
            return Ok(cur.leaf);
        }
        let (leaf, has) = self.locate(key)?;
        cur.leaf = leaf;
        cur.path.clear();
        cur.path.extend_from_slice(&self.path);
        cur.has_fence = has;
        cur.fence.clear();
        cur.fence.extend_from_slice(&self.keybuf);
        cur.epoch = self.epoch;
        cur.valid = true;
        Ok(leaf)
    }

    /// [`Tree::probe_path`] of ascending keys: a key in the leaf of the previous one is counted there without a descent;
    /// another key is routed from the deepest page of the previous leaf's path that holds it (see [`SortedCursor`]). The
    /// keys ascend, so only the upper end of a page's range can be passed, and a route to a child other than the page's
    /// last proves it was not (the next separator is above the key); the root holds every key. Each page on the way is
    /// routed once ([`page::int_route_fence`]: child reference and fence from the same walk).
    pub fn probe_sorted(
        &mut self,
        cur: &mut SortedCursor,
        key: &[u8],
        s: &mut PathSet,
    ) -> Result<()> {
        if self.root_addr == NONE {
            return Ok(());
        }
        let live = cur.valid && cur.epoch == self.epoch;
        if live && s.last == Some(cur.leaf) && (!cur.has_fence || key < cur.fence.as_slice()) {
            return Ok(());
        }
        if live && !cur.path.is_empty() {
            // the fence goes to `keybuf` first: a miss below leaves the cursor as it was
            self.keybuf.clear();
            let mut d = cur.path.len();
            let (mut pg, mut r) = loop {
                let p = cur.path[d - 1].0;
                let r = page::int_route_fence(&self.slab[p as usize].buf, key, &mut self.keybuf);
                d -= 1;
                if r.fenced || d == 0 {
                    break (p, r);
                }
            };
            self.path.clear();
            self.path.extend_from_slice(&cur.path[..d]);
            let leaf = loop {
                self.path.push((pg, r.idx as u16));
                let lvl = page::level(&self.slab[pg as usize].buf) - 1;
                let c = self.lookup(r.addr, r.crc, lvl)?;
                if lvl == 0 {
                    break c;
                }
                pg = c;
                r = page::int_route_fence(&self.slab[pg as usize].buf, key, &mut self.keybuf);
            };
            for k in 0..self.path.len() {
                let slot = self.path[k].0;
                self.slab[slot as usize].flags |= F_REF;
            }
            // a route in the previous leaf's parent counts as a remembered leaf, a route from a page above it as a descent
            self.stats.locates += 1;
            if d + 1 < cur.path.len() {
                self.stats.descents += 1;
            } else {
                self.stats.hint_hits += 1;
            }
            #[cfg(debug_assertions)]
            {
                let (p0, kb0, has) = (
                    self.path.clone(),
                    self.keybuf.clone(),
                    !self.keybuf.is_empty(),
                );
                let r = self
                    .locate_full(key, false)
                    .expect("cursor pages are resident");
                assert_eq!(
                    (r, &self.path, &self.keybuf),
                    ((leaf, has), &p0, &kb0),
                    "stale sorted route"
                );
            }
            self.note_probe(leaf, s);
        } else {
            self.probe_path(key, s)?;
        }
        // `key` is located: its leaf's interior path is in `path`, its fence in `keybuf`
        cur.leaf = s.last.expect("probed leaf");
        cur.has_fence = !self.keybuf.is_empty();
        std::mem::swap(&mut cur.fence, &mut self.keybuf);
        cur.path.clear();
        cur.path.extend_from_slice(&self.path);
        cur.epoch = self.epoch;
        cur.valid = true;
        Ok(())
    }

    fn put_inner(&mut self, key: &[u8], val: &[u8], find: Find<'_>) -> Result<()> {
        if key.len() > self.max_key || 4 + key.len() + val.len() > self.max_entry {
            return Err(StoreError::Invalid(
                "key or value too large for a tree page",
            ));
        }
        self.ensure_root();
        let leaf = match find {
            Find::Walk => self.descend(key)?,
            Find::Sorted(c) => self.locate_sorted(c, key)?,
            Find::At(s, leg) => self.locate_at(s, leg, key)?,
        };
        self.mark_path(leaf);
        self.touch_key(leaf, key);
        let found = page::leaf_search(&self.slab[leaf as usize].buf, key);
        let pos = match found {
            Ok(i) => {
                let b = &mut self.slab[leaf as usize].buf;
                if page::leaf_val_len(b, i) == val.len() {
                    page::leaf_set_same_len(b, i, val);
                    return Ok(());
                }
                page::remove_range(b, &mut self.ents, i, i + 1);
                i
            }
            Err(i) => i,
        };
        let rightmost = self.rightmost_upto(self.path.len());
        let split = self.insert_leaf(leaf, pos, key, val, rightmost);
        self.propagate(split);
        Ok(())
    }

    pub fn del(&mut self, key: &[u8]) -> Result<bool> {
        self.del_inner(key, None)
    }

    /// [`Tree::del`] at leg `leg` of `s` (see [`Tree::put_at`]).
    pub fn del_at(&mut self, s: &PathSet, leg: u32, key: &[u8]) -> Result<bool> {
        self.del_inner(key, Some((s, leg)))
    }

    fn del_inner(&mut self, key: &[u8], at: Option<(&PathSet, u32)>) -> Result<bool> {
        if self.root_addr == NONE {
            return Ok(false);
        }
        let leaf = match at {
            Some((s, leg)) => self.locate_at(s, leg, key)?,
            None => self.descend(key)?,
        };
        let Ok(i) = page::leaf_search(&self.slab[leaf as usize].buf, key) else {
            return Ok(false);
        };
        self.del_slot(leaf, i, key);
        Ok(true)
    }

    /// Remove entry `i` (key `key`) of `leaf` (path in `self.path`): an emptied leaf is pruned, a thinned one is a merge
    /// candidate (both at the txn's end).
    fn del_slot(&mut self, leaf: u32, i: usize, key: &[u8]) {
        self.mark_path(leaf);
        self.touch_key(leaf, key);
        let b = &mut self.slab[leaf as usize].buf;
        page::remove_range(b, &mut self.ents, i, i + 1);
        if page::nslots(b) == 0 {
            let mut hi = key.to_vec();
            hi.push(0);
            self.push_prune(key, &hi);
        } else if self.underfull(leaf) {
            self.push_merge(leaf);
        }
    }

    fn rightmost_upto(&self, depth: usize) -> bool {
        self.path[..depth]
            .iter()
            .all(|&(s, i)| i as usize + 1 == page::nslots(&self.slab[s as usize].buf))
    }

    /// Insert into a leaf; returns the new right sibling if the page split (separator in `self.sep`).
    fn insert_leaf(
        &mut self,
        s: u32,
        pos: usize,
        key: &[u8],
        val: &[u8],
        rightmost: bool,
    ) -> Option<u32> {
        let psz = self.cfg.psz;
        let b = &mut self.slab[s as usize].buf;
        if page::leaf_insert(b, &mut self.tmp, pos, key, val) {
            return None;
        }
        self.ents.load(b);
        self.ents.insert(pos, key, val);
        let n = self.ents.len();
        if page::fits(&self.ents, 0, n, true, psz, page::FMT_SLOTTED) {
            assert!(page::build(b, &self.ents, 0, n, page::FMT_SLOTTED));
            return None;
        }
        let m = if rightmost && pos == n - 1 {
            n - 1
        } else {
            let m0 = self.ents.split_point(true, psz, page::FMT_SLOTTED);
            run_end_split(&self.ents, pos, m0, psz).unwrap_or(m0)
        };
        page::short_sep(self.ents.key(m - 1), self.ents.key(m), &mut self.sep);
        self.epoch += 1;
        self.slab[s as usize].flags |= F_MOD; // the left half keeps its slot but not its content
        let r = self.new_virtual(LEAF, 0);
        let (l, rb) = two_bufs(&mut self.slab, s, r);
        assert!(
            page::build(l, &self.ents, 0, m, page::FMT_SLOTTED),
            "left half must fit"
        );
        assert!(
            page::build(rb, &self.ents, m, n, page::FMT_SLOTTED),
            "right half must fit"
        );
        self.stats.splits += 1;
        Some(r)
    }

    /// Insert `(self.sep -> right child)` after child `idx` of interior page `s`.
    fn insert_int(
        &mut self,
        s: u32,
        pos: usize,
        key: &[u8],
        addr: u64,
        rightmost: bool,
    ) -> Option<u32> {
        self.fz_touch(s);
        self.epoch += 1;
        self.slab[s as usize].flags |= F_MOD;
        let psz = self.cfg.psz;
        let fmt = self.int_fmt();
        let b = &mut self.slab[s as usize].buf;
        if page::int_insert(b, &mut self.tmp, &mut self.ents, pos, key, addr, 0) {
            return None;
        }
        let level = page::level(b);
        self.ents.load(b);
        let mut v = [0u8; REF_LEN];
        v[..8].copy_from_slice(&addr.to_le_bytes());
        self.ents.insert(pos, key, &v);
        let n = self.ents.len();
        if page::fits(&self.ents, 0, n, false, psz, fmt) {
            assert!(page::build(b, &self.ents, 0, n, fmt));
            return None;
        }
        let m = if rightmost && pos == n - 1 && page::fits(&self.ents, 0, n - 1, false, psz, fmt) {
            n - 1
        } else if let Some(m) = self.ents.try_split_point(false, psz, fmt) {
            m
        } else {
            // a fresh compact encode re-places restarts every 16 entries; after insert/remove churn with long
            // shared suffixes that can need more than two pages. Keeping the page's restarts bounds each half by
            // its in-place bytes (+ the new entry, + the right half's first suffix), which always splits.
            let b = &self.slab[s as usize].buf;
            self.ents.load_keep(b);
            self.ents.insert(pos, key, &v);
            self.ents.split_point(false, psz, fmt)
        };
        self.sep.clear();
        self.sep.extend_from_slice(self.ents.key(m));
        let r = self.new_virtual(INT, level);
        let (l, rb) = two_bufs(&mut self.slab, s, r);
        assert!(page::build(l, &self.ents, 0, m, fmt), "left half must fit");
        assert!(
            page::build(rb, &self.ents, m, n, fmt),
            "right half must fit"
        );
        self.stats.splits += 1;
        Some(r)
    }

    fn propagate(&mut self, mut split: Option<u32>) {
        let mut depth = self.path.len();
        while let Some(rs) = split {
            let raddr = self.slab[rs as usize].addr;
            if depth == 0 {
                self.grow_root(raddr);
                return;
            }
            depth -= 1;
            let (ps, idx) = self.path[depth];
            let hint = self.rightmost_upto(depth)
                && idx as usize + 1 == page::nslots(&self.slab[ps as usize].buf);
            let key = std::mem::take(&mut self.sep);
            split = self.insert_int(ps, idx as usize + 1, &key, raddr, hint);
            if split.is_none() {
                self.sep = key;
            }
        }
    }

    fn grow_root(&mut self, raddr: u64) {
        self.epoch += 1;
        let (oa, oc) = (self.root_addr, self.root_crc);
        let s = self.new_virtual(INT, self.height);
        let fmt = self.int_fmt();
        let b = &mut self.slab[s as usize].buf;
        let mut v = [0u8; REF_LEN];
        v[..8].copy_from_slice(&oa.to_le_bytes());
        v[8..].copy_from_slice(&oc.to_le_bytes());
        self.ents.clear();
        self.ents.push(b"", &v);
        v[..8].copy_from_slice(&raddr.to_le_bytes());
        v[8..].copy_from_slice(&0u32.to_le_bytes());
        self.ents.push(&self.sep, &v);
        assert!(page::build(b, &self.ents, 0, 2, fmt));
        self.root_addr = self.slab[s as usize].addr;
        self.root_crc = 0;
        self.height += 1;
        self.stats.grows += 1;
    }

    // ---------------------------------------------------------------- range delete

    /// Make the pages `del_range(a, b)` reads resident (queues misses): the routes of its two ends (see [`Ends`]); without
    /// the lazy free also the interior pages inside the range (their subtrees are dropped page by page). `TxnTooLarge` if
    /// that is more than the walk limit. Returns an upper bound of the pages the delete rewrites (the two routes, not the
    /// pages it empties).
    pub fn probe_range(&mut self, a: &[u8], b: &[u8]) -> Result<usize> {
        self.probe_range_ex(a, b, self.cfg.max_walk, true)
    }

    /// After a successful `probe_range(a, b)`: add the pages `del_range(a, b)` leaves dirty to `s` (shared with the
    /// txn's other probes, so neighbouring range deletes of one txn count their common pages once). `dr_node` keeps
    /// only pages on the routes of the two ends (resident after the probe): every other page of the range is dropped
    /// whole, and a route page it empties is pruned at `finish_txn` (no fresh page).
    pub fn probe_range_paths(&mut self, a: &[u8], b: &[u8], s: &mut PathSet) {
        if a >= b || self.root_addr == NONE {
            return;
        }
        for upper in [false, true] {
            let mut addr = self.root_addr;
            while let Some(&slot) = self.map.get(&addr) {
                let p = &self.slab[slot as usize];
                let leaf = page::level(&p.buf) == 0;
                if s.seen.insert(slot) {
                    s.clean += self.dirties_anew(slot) as usize;
                    s.leaves += leaf as usize;
                }
                if leaf {
                    break;
                }
                let i = if upper {
                    route_below(&p.buf, b, &mut self.cmpbuf)
                } else {
                    page::int_route(&p.buf, a)
                };
                addr = page::int_child(&p.buf, i).0;
            }
        }
        s.last = None;
    }

    /// Make the whole range resident without the per-txn limit (mount: bitmap chunks), in as few load rounds
    /// as the tree has levels. Caller evicts afterwards (`shrink`).
    pub fn prefetch_range(&mut self, a: &[u8], b: &[u8]) -> Result<()> {
        self.probe_range_ex(a, b, usize::MAX, false).map(|_| ())
    }

    /// `skip`: pages a delete never reads are not loaded (`del_range` frees them by address, so a delete costs the two
    /// routes + without the lazy free the interior pages inside the range, however big the range); `false` loads every
    /// page of the range (prefetch).
    fn probe_range_ex(&mut self, a: &[u8], b: &[u8], limit: usize, skip: bool) -> Result<usize> {
        if a >= b || self.root_addr == NONE {
            return Ok(0);
        }
        // pages fully inside the range are emptied and retired (no new page needed); only the two routes are rewritten
        let dirtied = 2 * (self.height as usize + 1);
        let mut visited = 0;
        let mut miss = false;
        match self.root_slot() {
            Ok(r) => self.probe_node(
                r,
                a,
                b,
                (Some(Ends::BOTH), skip),
                &mut visited,
                &mut miss,
                limit,
            )?,
            Err(StoreError::Miss) => miss = true,
            Err(e) => return Err(e),
        }
        if miss {
            Err(StoreError::Miss)
        } else {
            Ok(dirtied.min(visited))
        }
    }

    /// The children of interior page `s` whose ranges hold the ends of `[a, b)` that `ends` places in `s`: `a`'s, and the
    /// one holding the keys right below `b`. Every child after `a`'s (from the first one when `a` lies below `s`) and before
    /// `b`'s (up to the last one when `b` lies above `s`) lies completely inside `[a, b)`.
    fn end_children(
        &mut self,
        s: u32,
        a: &[u8],
        b: &[u8],
        ends: Ends,
    ) -> (Option<usize>, Option<usize>) {
        let pg = &self.slab[s as usize].buf;
        let ia = ends.a.then(|| page::int_route(pg, a));
        let ib = ends.b.then(|| route_below(pg, b, &mut self.cmpbuf));
        (ia, ib)
    }

    /// `ends` of [`Tree::probe_node`]: the ends of the range the children `ia`, `ib` hold.
    fn child_ends(ia: Option<usize>, ib: Option<usize>) -> [Option<(usize, Ends)>; 2] {
        let one = ia.is_some() && ia == ib;
        [
            ia.map(|i| (i, Ends { a: true, b: one })),
            ib.filter(|_| !one).map(|i| (i, Ends { a: false, b: true })),
        ]
    }

    /// `mode` = (`ends`: the ends of the range page `s` holds, `None` = the whole page lies inside the range; `skip`: do
    /// not load covered pages a delete never reads). Loads exactly the pages `dr_node` reads: in the tree as the record's
    /// probe finds it and in the tree as each later op of the record finds it (see [`Ends`]).
    #[allow(clippy::too_many_arguments)]
    fn probe_node(
        &mut self,
        s: u32,
        a: &[u8],
        b: &[u8],
        mode: (Option<Ends>, bool),
        visited: &mut usize,
        miss: &mut bool,
        limit: usize,
    ) -> Result<()> {
        let (ends, skip) = mode;
        *visited += 1;
        if *visited > limit {
            return Err(StoreError::TxnTooLarge);
        }
        let lvl = page::level(&self.slab[s as usize].buf);
        if lvl == 0 {
            return Ok(());
        }
        let (ia, ib) = match ends {
            Some(e) => self.end_children(s, a, b, e),
            None => (None, None),
        };
        // the children between lie completely inside the range: a covered leaf is freed by address, never read; with the
        // lazy free no covered page is read at all (its subtree is detached and freed in the background, adr 0021 am. 18)
        let between = if skip && (lvl == 1 || self.lazy) {
            0..0
        } else {
            ia.map_or(0, |i| i + 1)..ib.unwrap_or_else(|| page::nslots(&self.slab[s as usize].buf))
        };
        let kids = Self::child_ends(ia, ib)
            .into_iter()
            .flatten()
            .map(|(i, e)| (i, Some(e)))
            .chain(between.map(|i| (i, None)));
        for (i, e) in kids {
            match self.child_slot(s, i) {
                Ok(c) => self.probe_node(c, a, b, (e, skip), visited, miss, limit)?,
                Err(StoreError::Miss) => *miss = true,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Free a page by address: the resident copy if any, else just its disk image (at the next checkpoint).
    fn retire_addr(&mut self, addr: u64, crc: u32) {
        if let Some(&s) = self.map.get(&addr) {
            self.retire(s);
        } else {
            self.epoch += 1;
            self.stats.pruned += 1;
            if addr & VIRT == 0 {
                self.retired.push(addr);
                self.drop_chain(addr);
                self.gone.push((addr, crc));
                self.unbad(addr);
            }
        }
    }

    /// Pages freed by address (`retire_addr`, a detach) since the last call, `(addr, crc)`: a read of one that was asked for
    /// earlier and is still queued or in flight must not install its image (a stale copy would outlive the free and
    /// later shadow or unmap the page that reuses the address) nor mark the address bad. The shard drops those reads.
    pub fn take_gone(&mut self, out: &mut Vec<(u64, u32)>) {
        out.append(&mut self.gone);
    }

    pub fn has_gone(&self) -> bool {
        !self.gone.is_empty()
    }

    /// Free a resident page and everything below it (leaves by address; interior pages were loaded by the probe).
    fn drop_subtree(&mut self, s: u32) -> Result<()> {
        let lvl = page::level(&self.slab[s as usize].buf);
        if lvl > 0 {
            for i in 0..page::nslots(&self.slab[s as usize].buf) {
                if lvl == 1 {
                    let (ca, cc) = page::int_child(&self.slab[s as usize].buf, i);
                    self.retire_addr(ca, cc);
                } else {
                    let c = self.child_slot(s, i)?;
                    self.drop_subtree(c)?;
                }
            }
        }
        self.retire(s);
        Ok(())
    }

    // ---------------------------------------------------------------- lazy subtree free (adr 0021 am. 18)

    /// Drop the subtree at `addr` (level `level`, expected `crc`) that a range delete covered completely: a resident
    /// page is dropped with everything below it that is resident; whatever lives only on disk is freed by address
    /// (leaves) or detached into the dead list (interior pages) and read later by the drain. Never reads a page. The
    /// reference's level bounds the descent: a page of another level is a corrupt image, not a way back up the tree.
    fn drop_addr(&mut self, addr: u64, crc: u32, level: u8) -> Result<()> {
        if let Some(&s) = self.map.get(&addr) {
            if page::level(&self.slab[s as usize].buf) != level {
                return Err(StoreError::Corrupt(format!(
                    "detached page {addr}: level {} where the reference expects {level}",
                    page::level(&self.slab[s as usize].buf)
                )));
            }
            if level > 0 {
                for i in 0..page::nslots(&self.slab[s as usize].buf) {
                    let (ca, cc) = page::int_child(&self.slab[s as usize].buf, i);
                    self.drop_addr(ca, cc, level - 1)?;
                }
            }
            self.retire(s);
        } else if level == 0 {
            self.retire_addr(addr, crc);
        } else {
            debug_assert!(addr & VIRT == 0, "virtual pages are always resident");
            self.epoch += 1;
            // a read asked for before the detach must not cache it (the drain frees it)
            self.gone.push((addr, crc));
            self.dead.push(Dead { addr, crc, level });
            self.dead_gen += 1;
            self.stats.dead_detached += 1;
        }
        Ok(())
    }

    /// Switch the lazy subtree free on/off (stores with `FEAT_LAZY_FREE`; mount) and load the persisted dead list.
    pub fn set_lazy(&mut self, on: bool, dead: Vec<Dead>) {
        self.lazy = on;
        self.dead = dead;
        self.dead_fly.clear();
        self.dead_gen = 0;
        self.dead_frozen_gen = 0;
    }

    /// Detached subtrees waiting for the drain.
    pub fn dead_len(&self) -> usize {
        self.dead.len()
    }

    /// The drain (or a detach) changed state the next checkpoint must persist or free.
    pub fn dead_dirty(&self) -> bool {
        self.dead_gen != self.dead_frozen_gen || !self.retired.is_empty()
    }

    /// Ask for the pages of up to `max - inflight` detached subtrees (newest first: depth first keeps the list short);
    /// the shard reads them like tree pages and hands them to [`Tree::install`].
    pub fn dead_kick(&mut self, max: usize) {
        let mut i = self.dead.len();
        while i > 0 && self.dead_fly.len() < max {
            i -= 1;
            let d = self.dead[i];
            if self.dead_fly.contains(&d.addr) {
                continue;
            }
            // a resident page is dropped, not detached, and stale reads are not cached
            debug_assert!(
                !self.map.contains_key(&d.addr),
                "detached page {} is resident",
                d.addr
            );
            self.dead_fly.push(d.addr);
            self.wants.push(Want {
                addr: d.addr,
                crc: d.crc,
                level: d.level,
                dead: true,
                scan: false,
            });
        }
    }

    /// A drain read finished: free the children of the detached page (leaves by address, interior pages go into the
    /// dead list), then the page itself. The checkpoint after this one persists the result; until then the old
    /// pages stay intact for a crash (they are freed only once a root without them is durable).
    fn dead_process(&mut self, w: &Want, data: &[u8]) -> Result<()> {
        self.dead_fly.retain(|&a| a != w.addr);
        let Some(i) = self.dead.iter().rposition(|d| d.addr == w.addr) else {
            return Ok(()); // already gone (duplicate read)
        };
        let d = self.dead[i];
        page::validate(data, self.cfg.psz, w.addr)
            .map_err(|m| StoreError::Corrupt(format!("detached page {}: {m}", w.addr)))?;
        if page::stored_crc(data) != d.crc
            || page::level(data) != d.level
            || page::kind(data) != page::INT
        {
            return Err(StoreError::Corrupt(format!(
                "detached page {}: crc/level differs from its reference",
                w.addr
            )));
        }
        self.dead.remove(i);
        for k in 0..page::nslots(data) {
            let (ca, cc) = page::int_child(data, k);
            self.drop_addr(ca, cc, d.level - 1)?;
        }
        self.retired.push(w.addr);
        self.unbad(w.addr);
        self.epoch += 1;
        self.dead_gen += 1;
        self.stats.dead_freed += 1;
        Ok(())
    }

    /// The drain read of `addr` could not be issued now (a read of the same page asked for before the detach occupies
    /// the address): ask again at the next kick.
    pub fn dead_unfly(&mut self, addr: u64) {
        self.dead_fly.retain(|&a| a != addr);
    }

    /// The read of a detached page failed or the page is damaged: its subtree cannot be freed (the pages stay
    /// allocated, fsck reports them as a leak); the entry is dropped so the drain does not retry forever.
    pub fn dead_failed(&mut self, addr: u64) {
        self.dead_fly.retain(|&a| a != addr);
        if let Some(i) = self.dead.iter().rposition(|d| d.addr == addr) {
            self.dead.remove(i);
            self.dead_gen += 1;
            self.stats.dead_lost += 1;
        }
    }

    /// Delete all keys in `[a, b)`; requires a successful `probe_range` (never misses then, also as a later op of a
    /// probed record: see [`Ends`]).
    pub fn del_range(&mut self, a: &[u8], b: &[u8]) -> Result<()> {
        if a >= b || self.root_addr == NONE {
            return Ok(());
        }
        let r = self.root_slot()?;
        self.dr_node(r, a, b, Ends::BOTH)?;
        self.push_prune(a, b);
        Ok(())
    }

    /// Range delete below page `s`, which holds the ends `ends` of `[a, b)`: the end children lose the keys in range,
    /// the children between them are dropped whole (the lazy free and leaves by address, never read).
    fn dr_node(&mut self, s: u32, a: &[u8], b: &[u8], ends: Ends) -> Result<bool> {
        self.slab[s as usize].flags |= F_REF;
        if page::level(&self.slab[s as usize].buf) == 0 {
            if self.slab[s as usize].flags & F_FRZ != 0 {
                let pg = &self.slab[s as usize].buf;
                if page::leaf_lower_bound(pg, a) < page::leaf_lower_bound(pg, b) {
                    self.fz_process(s);
                }
            }
            let pg = &mut self.slab[s as usize].buf;
            let lo = page::leaf_lower_bound(pg, a);
            let hi = page::leaf_lower_bound(pg, b);
            if lo < hi {
                let span = self.deltas.then(|| {
                    let mut k0 = std::mem::take(&mut self.span_lo);
                    let mut k1 = std::mem::take(&mut self.span_hi);
                    k0.clear();
                    k1.clear();
                    page::key_into(pg, lo, &mut k0);
                    page::key_into(pg, hi - 1, &mut k1);
                    k1.push(0);
                    (k0, k1)
                });
                page::remove_range(pg, &mut self.ents, lo, hi);
                self.mark_dirty_val(s);
                if let Some((k0, k1)) = span {
                    self.touch_span(s, &k0, &k1);
                    self.span_lo = k0;
                    self.span_hi = k1;
                }
                if self.underfull(s) {
                    self.push_merge(s);
                }
                return Ok(true);
            }
            return Ok(false);
        }
        let (ia, ib) = self.end_children(s, a, b, ends);
        let mut modified = false;
        for (i, e) in Self::child_ends(ia, ib).into_iter().flatten() {
            let c = self.child_slot(s, i)?;
            modified |= self.dr_node(c, a, b, e)?;
        }
        let lo = ia.map_or(0, |i| i + 1);
        let hi = ib.unwrap_or_else(|| page::nslots(&self.slab[s as usize].buf));
        if lo < hi {
            self.fz_touch(s);
            let lvl = page::level(&self.slab[s as usize].buf);
            for i in lo..hi {
                if self.lazy {
                    let (ca, cc) = page::int_child(&self.slab[s as usize].buf, i);
                    self.drop_addr(ca, cc, lvl - 1)?;
                } else if lvl == 1 {
                    let (ca, cc) = page::int_child(&self.slab[s as usize].buf, i);
                    self.retire_addr(ca, cc);
                } else {
                    let c = self.child_slot(s, i)?;
                    self.drop_subtree(c)?;
                }
            }
            self.int_remove_children(s, lo, hi);
            modified = true;
        }
        if modified {
            self.mark_dirty(s);
        }
        Ok(modified)
    }

    fn push_prune(&mut self, a: &[u8], b: &[u8]) {
        let o = self.pr_data.len() as u32;
        self.pr_data.extend_from_slice(a);
        self.pr_data.extend_from_slice(b);
        self.pr_idx.push((o, a.len() as u32, b.len() as u32));
    }

    /// A leaf holding less than a third of a page after a delete (not empty: those are pruned): merge candidate.
    fn underfull(&self, s: u32) -> bool {
        let b = &self.slab[s as usize].buf;
        page::nslots(b) > 0 && self.cfg.psz - page::free_total(b) < self.cfg.psz / 3
    }

    fn push_merge(&mut self, s: u32) {
        if self.mg_idx.len() >= MERGE_CANDS {
            return;
        }
        let o = self.mg_data.len();
        page::key_into(&self.slab[s as usize].buf, 0, &mut self.mg_data);
        self.mg_idx
            .push((o as u32, (self.mg_data.len() - o) as u32));
    }

    /// Leaf routing `key` if every page on the way is resident (path in `self.path`); never queues a read.
    fn find_resident(&mut self, key: &[u8]) -> Option<u32> {
        self.path.clear();
        let mut s = *self.map.get(&self.root_addr)?;
        loop {
            let b = &self.slab[s as usize].buf;
            if page::level(b) == 0 {
                return Some(s);
            }
            if page::nslots(b) == 0 {
                return None;
            }
            let idx = page::int_route(b, key);
            self.path.push((s, idx as u16));
            s = self.resident_child(s, idx)?;
        }
    }

    /// End of a txn: merge the underfull leaves its deletes left (adr 0021 am. 29). Only with a neighbour that is
    /// resident (no read) and only when one of the two pages is dirty already (the thinned leaf is): the merged page
    /// takes the place of the dirty one and the other is freed, so the dirty set never grows and the txn's page
    /// estimate (clean pages on its paths) still holds. A leaf that needs a cold or clean neighbour goes to the
    /// background compaction queue (adr 0021 am. 33).
    fn merge_pass(&mut self) {
        let idx = std::mem::take(&mut self.mg_idx);
        let data = std::mem::take(&mut self.mg_data);
        for &(o, l) in &idx {
            let key = &data[o as usize..(o + l) as usize];
            // one queue entry per leaf (`F_CQ`, cleared when the background step looks at it; a fresh slot has it clear)
            match self.find_resident(key) {
                Some(leaf) if self.merge_leaf(leaf, false) == Merge::Later => {
                    if self.slab[leaf as usize].flags & F_CQ == 0 && self.cq_push(key) {
                        self.slab[leaf as usize].flags |= F_CQ;
                    }
                }
                Some(_) => {}
                None => {
                    self.cq_push(key);
                }
            }
        }
        self.mg_idx = idx;
        self.mg_data = data;
        self.mg_idx.clear();
        self.mg_data.clear();
        self.fix_root();
    }

    /// Merge leaf `x` (path in `self.path`) with its left or right sibling under the same parent: the entries of the
    /// right page move into the left one, the right page is removed from the parent and freed (like a pruned page).
    /// `bg` (background compaction, adr 0021 am. 33): both pages may be clean; the path is dirtied first (between txns:
    /// no txn estimate to keep).
    fn merge_leaf(&mut self, x: u32, bg: bool) -> Merge {
        let Some(&(p, i)) = self.path.last() else {
            return Merge::No;
        };
        if !self.underfull(x) {
            return Merge::No;
        }
        let (i, n) = (i as usize, page::nslots(&self.slab[p as usize].buf));
        let psz = self.cfg.psz;
        let mut later = false;
        let pairs = [(i > 0).then(|| (i - 1, i)), (i + 1 < n).then(|| (i, i + 1))];
        for (li, ri) in pairs.into_iter().flatten() {
            let (Some(l), Some(r)) = (self.resident_child(p, li), self.resident_child(p, ri))
            else {
                later = true;
                continue;
            };
            let (lp, rp) = (&self.slab[l as usize], &self.slab[r as usize]);
            if page::level(&lp.buf) != 0 || page::level(&rp.buf) != 0 {
                continue;
            }
            let used = |b: &[u8]| psz - page::free_total(b) - page::HDR;
            if used(&lp.buf) + used(&rp.buf) > psz * 65 / 100 {
                continue;
            }
            if !bg && (lp.flags | rp.flags) & F_DIRTY == 0 {
                later = true;
                continue;
            }
            self.ents.load(&lp.buf);
            for k in 0..page::nslots(&rp.buf) {
                self.keybuf.clear();
                page::key_into(&rp.buf, k, &mut self.keybuf);
                self.ents.push(&self.keybuf, page::leaf_ent(&rp.buf, k).1);
            }
            let m = self.ents.len();
            if !page::fits(&self.ents, 0, m, true, psz, page::FMT_SLOTTED) {
                continue;
            }
            if bg {
                self.mark_path(x); // l and x share the parent: same ancestors
            }
            self.fz_touch(l);
            assert!(page::build(
                &mut self.slab[l as usize].buf,
                &self.ents,
                0,
                m,
                page::FMT_SLOTTED
            ));
            // the dirty page's ancestors are dirty (mark_path; a freeze clears all at once): the dirty set never grows
            debug_assert!(
                self.path
                    .iter()
                    .all(|&(s, _)| self.slab[s as usize].flags & F_DIRTY != 0),
                "merge under a clean ancestor"
            );
            self.mark_dirty(l);
            self.int_remove_child(p, ri);
            self.mark_dirty(p);
            self.retire(r);
            if bg {
                self.stats.compacted += 1;
            } else {
                self.stats.merged += 1;
            }
            return Merge::Done;
        }
        if later { Merge::Later } else { Merge::No }
    }

    /// Queue a candidate; false = not queued (switched off, or full: counted as dropped).
    fn cq_push(&mut self, key: &[u8]) -> bool {
        if !self.cfg.bg_compact {
            return false;
        }
        if self.cq_idx.len() >= CQ_CAP || self.cq_data.len() + key.len() > CQ_ARENA {
            self.stats.compact_dropped += 1;
            return false;
        }
        if self.cq_idx.capacity() == 0 {
            self.cq_idx.reserve_exact(CQ_CAP); // once: no allocation per candidate afterwards
            self.cq_data.reserve_exact(CQ_ARENA);
        }
        self.cq_idx
            .push_back((self.cq_data.len() as u32, key.len() as u32));
        self.cq_data.extend_from_slice(key);
        true
    }

    /// Drop candidate `i` (`i` < a few: the probe window). Its bytes stay in the arena until the front passes them.
    fn cq_remove(&mut self, i: usize) {
        self.cq_idx.remove(i);
        match self.cq_idx.front() {
            None => self.cq_data.clear(),
            Some(&(o, _)) if o as usize > CQ_ARENA / 2 => {
                // dead front bytes: move the live keys down (amortized; within the reserved capacity)
                let o = o as usize;
                self.cq_data.drain(..o);
                for e in self.cq_idx.iter_mut() {
                    e.0 -= o as u32;
                }
            }
            Some(_) => {}
        }
    }

    /// Background compaction candidates queued (adr 0021 am. 33).
    pub fn compact_pending(&self) -> usize {
        self.cq_idx.len()
    }

    /// One background compaction step (adr 0021 am. 33) on candidate `i` of the queue (the caller probes the first few
    /// in turn, so their reads overlap), between txns only: the candidate's leaf is merged with a sibling under the same
    /// parent, reading what is cold first (both siblings at once). `Ok(true)` = a merge, the candidate stays at `i` (the
    /// merged leaf may still be underfull); `Ok(false)` = the candidate is done and removed (not underfull any more, no
    /// fitting sibling, or gone); `Err(Miss)` = reads queued, the candidate stays (retry after a load). Other errors
    /// remove the candidate. No new durable state: the merged tree is persisted by the next checkpoint like any
    /// txn-time merge (am. 29).
    pub fn compact_step(&mut self, i: usize) -> Result<bool> {
        let Some(&(o, l)) = self.cq_idx.get(i) else {
            return Ok(false);
        };
        let mut key = std::mem::take(&mut self.cq_key);
        key.clear();
        key.extend_from_slice(&self.cq_data[o as usize..(o + l) as usize]);
        let r = self.compact_at(&key);
        self.cq_key = key;
        match r {
            Err(StoreError::Miss) => Err(StoreError::Miss),
            Ok(Merge::Done) => {
                self.fix_root();
                Ok(true)
            }
            r => {
                self.cq_remove(i);
                r.map(|_| false)
            }
        }
    }

    fn compact_at(&mut self, key: &[u8]) -> Result<Merge> {
        if self.root_addr == NONE {
            return Ok(Merge::No);
        }
        let (leaf, _) = self.locate(key)?;
        self.slab[leaf as usize].flags &= !F_CQ;
        if !self.underfull(leaf) {
            return Ok(Merge::No);
        }
        let Some(&(p, i)) = self.path.last() else {
            return Ok(Merge::No); // the root leaf
        };
        let (i, n) = (i as usize, page::nslots(&self.slab[p as usize].buf));
        let mut miss = false;
        for j in [i.checked_sub(1), (i + 1 < n).then_some(i + 1)]
            .into_iter()
            .flatten()
        {
            match self.child_slot(p, j) {
                Ok(_) => {}
                Err(StoreError::Miss) => miss = true,
                Err(e) => return Err(e),
            }
        }
        if miss {
            return Err(StoreError::Miss);
        }
        Ok(match self.merge_leaf(leaf, true) {
            Merge::Done => Merge::Done,
            _ => Merge::No,
        })
    }

    /// End of a txn: remove pages that became empty, collapse the root.
    pub fn finish_txn(&mut self) -> Result<()> {
        self.finish_prune()?;
        if !self.mg_idx.is_empty() {
            self.merge_pass();
        }
        Ok(())
    }

    fn finish_prune(&mut self) -> Result<()> {
        if self.pr_idx.is_empty() {
            return Ok(());
        }
        let Some(level) = self.height.checked_sub(1) else {
            return Err(StoreError::Corrupt("tree root without height".into()));
        };
        let idx = std::mem::take(&mut self.pr_idx);
        let data = std::mem::take(&mut self.pr_data);
        for &(o, al, bl) in &idx {
            if self.root_addr == NONE {
                break;
            }
            let (o, al, bl) = (o as usize, al as usize, bl as usize);
            let (a, b) = (&data[o..o + al], &data[o + al..o + al + bl]);
            if let Some(&r) = self.map.get(&self.root_addr) {
                self.prune(r, level, a, b)?;
            }
        }
        self.fix_root();
        self.pr_idx = idx;
        self.pr_data = data;
        self.pr_idx.clear();
        self.pr_data.clear();
        Ok(())
    }

    /// Children of interior page `s` overlapping `[a, b)` as routes see the ends (`a` below `s` routes to the first child,
    /// `b` above it to the last): `prune` looks at every resident one.
    fn child_range(&mut self, s: u32, a: &[u8], b: &[u8]) -> (usize, usize) {
        let pg = &self.slab[s as usize].buf;
        (page::int_route(pg, a), route_below(pg, b, &mut self.cmpbuf))
    }

    /// Remove empty descendants overlapping `[a, b)`; true if page `s` is empty afterwards. `level` is the page's
    /// level from its tree position: the descent never follows a page that claims another one.
    fn prune(&mut self, s: u32, level: u8, a: &[u8], b: &[u8]) -> Result<bool> {
        if page::level(&self.slab[s as usize].buf) != level {
            return Err(StoreError::Corrupt(format!(
                "page {}: level {} where the tree position expects {level}",
                self.slab[s as usize].addr,
                page::level(&self.slab[s as usize].buf)
            )));
        }
        if level == 0 {
            return Ok(page::nslots(&self.slab[s as usize].buf) == 0);
        }
        if page::nslots(&self.slab[s as usize].buf) == 0 {
            // emptied by an earlier range of the same txn; nothing to route through
            return Ok(true);
        }
        let (c0, c1) = self.child_range(s, a, b);
        let mut modified = false;
        for i in (c0..=c1).rev() {
            let Some(c) = self.resident_child(s, i) else {
                continue;
            };
            if self.prune(c, level - 1, a, b)? {
                self.int_remove_child(s, i);
                self.retire(c);
                modified = true;
            }
        }
        if modified {
            self.mark_dirty(s);
        }
        Ok(page::nslots(&self.slab[s as usize].buf) == 0)
    }

    fn int_remove_child(&mut self, s: u32, i: usize) {
        self.int_remove_children(s, i, i + 1);
    }

    /// Remove children `lo..hi` of interior page `s`. When the first child goes and one stays, the first child kept takes
    /// over the -inf slot (its range grows down to the page's lower fence: prune removes empty children only, a range
    /// delete only children inside its range when it keeps that child, [`Ends`]), then slots 1..=hi go in place
    /// (`c_splice`: prefix kept, never grows, am. 13). A rebuild without slot 0 took the longer prefix of the remaining
    /// keys and turned every entry sharing exactly the extra bytes into a restart: a full compact page overflowed (assert
    /// during txn apply = OSD crash on PG-log-shaped trims, adr 0021 am. 28)
    fn int_remove_children(&mut self, s: u32, lo: usize, hi: usize) {
        self.fz_touch(s);
        self.epoch += 1;
        let b = &mut self.slab[s as usize].buf;
        if lo == 0 && hi < page::nslots(b) {
            let (ak, ck) = page::int_child(b, hi);
            page::int_set_ref(b, 0, ak, ck);
            page::remove_range(b, &mut self.ents, 1, hi + 1);
        } else {
            page::remove_range(b, &mut self.ents, lo, hi);
        }
    }

    fn fix_root(&mut self) {
        loop {
            let Some(&r) = self.map.get(&self.root_addr) else {
                return;
            };
            let b = &self.slab[r as usize].buf;
            if page::level(b) == 0 {
                return;
            }
            match page::nslots(b) {
                0 => {
                    // empty interior root: becomes an empty leaf
                    self.fz_touch(r);
                    self.epoch += 1;
                    let a = self.slab[r as usize].addr;
                    let sh = self.cfg.shard;
                    page::init(&mut self.slab[r as usize].buf, LEAF, 0, a, sh);
                    self.mark_dirty(r);
                    self.height = 1;
                    return;
                }
                1 => {
                    let (ca, _) = page::int_child(b, 0);
                    if !self.map.contains_key(&ca) {
                        return;
                    }
                    // a pending root (and child) takes its new form first: the child reference is read after that
                    self.fz_touch(r);
                    let (ca, cc) = page::int_child(&self.slab[r as usize].buf, 0);
                    self.retire(r);
                    self.root_addr = ca;
                    self.root_crc = cc;
                    self.height -= 1;
                }
                _ => return,
            }
        }
    }

    // ---------------------------------------------------------------- checkpoint

    /// Number of meta pages a freeze would need right now (dirty tree pages + the elastic image).
    pub fn freeze_need(&self) -> usize {
        self.ndirty + self.blob_need()
    }

    /// Pages of the elastic meta image a freeze may write (0 for a legacy store).
    pub fn blob_need(&self) -> usize {
        if self.meta.is_elastic() {
            // the freeze itself may add a delta segment to the directory: one page of slack
            crate::alloc::blob_pages(self.blob_len(), self.cfg.psz) + usize::from(self.deltas)
        } else {
            0
        }
    }

    /// Payload bytes of the elastic image: the meta bitmap/cells plus (lazy free) the dead-subtree list.
    pub fn blob_len(&self) -> usize {
        self.meta.blob_len() + self.ext_len()
    }

    fn dead_section_len(&self) -> usize {
        8 + 4 + DEAD_ENT * self.dead.len()
    }

    fn delta_section_len(&self) -> usize {
        8 + 4 + 12 * self.segs.len() + 12 * self.seg_pages
    }

    /// Extension section bytes of an image listing `dead` detached subtrees: the dead section (lazy free) and the
    /// delta directory as it is.
    fn ext_bytes(&self, dead: usize) -> usize {
        let dead = if self.lazy {
            8 + 4 + DEAD_ENT * dead
        } else {
            0
        };
        dead + if self.deltas {
            self.delta_section_len()
        } else {
            0
        }
    }

    /// Image bytes behind the meta bitmap/cells that must stay available for the extension sections: the dead list at
    /// its admission bound (lazy free) plus the delta directory as it is. Meta-space growth (cells) and new delta
    /// segments stay within `blob_max_len` minus this, so a freeze never finds an image too large to write (that would
    /// fail the shard at every checkpoint, also after a remount).
    pub fn ext_reserve(&self) -> usize {
        self.ext_bytes(if self.lazy {
            self.dead.len().max(DEAD_ROOM)
        } else {
            0
        })
    }

    fn ext_len(&self) -> usize {
        self.ext_bytes(self.dead.len())
    }

    /// Extension sections behind the meta image, each `[magic u32][len u32][payload]`: the detached subtrees (lazy free,
    /// `[count u32] (addr u64, crc u32, level u8)*`) and the delta segment directory (`[nsegs u32] ([seq u64][npages
    /// u32] (addr u64, crc u32)*)*`).
    fn encode_ext(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(self.ext_len());
        if self.lazy {
            o.extend_from_slice(&DEAD_MAGIC.to_le_bytes());
            o.extend_from_slice(&((self.dead_section_len() - 8) as u32).to_le_bytes());
            o.extend_from_slice(&(self.dead.len() as u32).to_le_bytes());
            for d in &self.dead {
                o.extend_from_slice(&d.addr.to_le_bytes());
                o.extend_from_slice(&d.crc.to_le_bytes());
                o.push(d.level);
            }
        }
        if self.deltas {
            o.extend_from_slice(&DELTA_MAGIC.to_le_bytes());
            o.extend_from_slice(&((self.delta_section_len() - 8) as u32).to_le_bytes());
            o.extend_from_slice(&(self.segs.len() as u32).to_le_bytes());
            for s in &self.segs {
                o.extend_from_slice(&s.seq.to_le_bytes());
                o.extend_from_slice(&(s.pages.len() as u32).to_le_bytes());
                for &(a, c) in &s.pages {
                    o.extend_from_slice(&a.to_le_bytes());
                    o.extend_from_slice(&c.to_le_bytes());
                }
            }
        }
        o
    }

    /// Parse the extension sections of an image payload (`b` = the bytes behind the meta image): the detached
    /// subtrees and the delta segment directory (empty when a section is absent).
    pub fn decode_ext(b: &[u8]) -> std::result::Result<(Vec<Dead>, Vec<SegDir>), &'static str> {
        let (mut dead, mut segs) = (None, None);
        let mut o = 0;
        let rd32 = |p: &[u8], at: usize| -> std::result::Result<usize, &'static str> {
            Ok(u32::from_le_bytes(
                p.get(at..at + 4)
                    .ok_or("image section")?
                    .try_into()
                    .unwrap(),
            ) as usize)
        };
        let rd64 = |p: &[u8], at: usize| -> std::result::Result<u64, &'static str> {
            Ok(u64::from_le_bytes(
                p.get(at..at + 8)
                    .ok_or("image section")?
                    .try_into()
                    .unwrap(),
            ))
        };
        while o < b.len() {
            let (magic, len) = (rd32(b, o)? as u32, rd32(b, o + 4)?);
            let p = b.get(o + 8..o + 8 + len).ok_or("image section length")?;
            o += 8 + len;
            match magic {
                DEAD_MAGIC if dead.is_none() => {
                    let n = rd32(p, 0)?;
                    if p.len() != 4 + DEAD_ENT * n {
                        return Err("dead list length");
                    }
                    dead = Some(
                        (0..n)
                            .map(|i| {
                                let q = 4 + DEAD_ENT * i;
                                Dead {
                                    addr: denc::le::rd_u64(p, q),
                                    crc: u32::from_le_bytes(p[q + 8..q + 12].try_into().unwrap()),
                                    level: p[q + 12],
                                }
                            })
                            .collect(),
                    );
                }
                DELTA_MAGIC if segs.is_none() => {
                    let n = rd32(p, 0)?;
                    let mut q = 4;
                    let mut v = Vec::new();
                    for _ in 0..n {
                        let (seq, np) = (rd64(p, q)?, rd32(p, q + 8)?);
                        q += 12;
                        let mut pages = Vec::new();
                        for _ in 0..np {
                            pages.push((rd64(p, q)?, rd32(p, q + 8)? as u32));
                            q += 12;
                        }
                        v.push(SegDir { seq, pages });
                    }
                    if q != p.len() {
                        return Err("delta directory length");
                    }
                    segs = Some(v);
                }
                _ => return Err("unknown or repeated image section"),
            }
        }
        Ok((dead.unwrap_or_default(), segs.unwrap_or_default()))
    }

    /// Address of meta page `idx` (base area or elastic cell).
    pub fn page_addr(&self, idx: u32) -> u64 {
        if idx < self.meta.base_pages() {
            self.geom.page_addr(idx)
        } else {
            self.meta.cell_page_addr(idx, self.geom.bpp)
        }
    }

    /// Index of the meta page at `addr`, if it lies in the base area or a present cell.
    pub fn page_idx(&self, addr: u64) -> Option<u32> {
        self.geom
            .page_idx(addr)
            .or_else(|| self.meta.cell_page_idx(addr, self.geom.bpp))
    }

    /// Mount: the pages of the elastic meta image the root slot points at, and the crc of its first page.
    pub fn set_blob(&mut self, addrs: Vec<u64>, crc: u32) {
        self.blob_ref = Some((addrs[0], crc, addrs.len() as u32));
        self.blob_cur = addrs;
        self.blob_gen = self.meta.layout_gen();
    }

    /// Snapshot all dirty pages for a checkpoint at `lsn` in one call ([`Tree::freeze_begin`] + all steps +
    /// [`Tree::freeze_end`]). Live pages stay mutable; mutations after this call belong to the next checkpoint.
    pub fn freeze(&mut self, lsn: u64) -> Result<Frozen> {
        self.freeze_begin(lsn)?;
        while !self.freeze_step(usize::MAX).0 {}
        Ok(self.freeze_end())
    }

    /// Sliced freeze (adr 0021 am. 40), step 1: the checkpoint at `lsn` takes the dirty pages as they are now (`F_FRZ`,
    /// pending). [`Tree::freeze_step`] then processes them bottom-up in slices (delta entry or fresh address, seal, copy
    /// into the arena) while txns keep mutating the tree: before a pending page changes, a leaf is processed, an interior
    /// page copied aside (`fz_touch`), so each pending page is frozen exactly in its state at `lsn` (copy on write). Meta space growth waits for the end (the image describes the cells of `lsn`); the detached-subtree
    /// list of the image is the one of `lsn`.
    pub fn freeze_begin(&mut self, lsn: u64) -> Result<()> {
        assert!(self.fz.is_none(), "freeze already running");
        // between freezes the count is exactly the dirty pages (a leak grows `dirty_pages` for good: am. 42)
        #[cfg(debug_assertions)]
        assert_eq!(
            self.ndirty,
            self.slab.iter().filter(|p| p.flags & F_DIRTY != 0).count(),
            "dirty page count drifted"
        );
        if (self.meta.free() as usize) < self.freeze_need()
            || self.meta.is_elastic() && self.blob_len() > crate::alloc::blob_max_len(self.cfg.psz)
        {
            return Err(StoreError::NoSpace);
        }
        // pending pages bottom-up: each page's level is read once (a comparison sort read two pages per comparison, random
        // over the slab: 12-21 ms in one piece for ~10k dirty pages), then the slots go into their level's run (counting sort)
        let mut dt = crate::diag::t0();
        let mut dirty = std::mem::take(&mut self.dirty);
        let mut lv: Vec<(u8, u32)> = Vec::with_capacity(dirty.len());
        let mut per = [0usize; 256];
        for &s in &dirty {
            let p = &mut self.slab[s as usize];
            // dirty and not yet listed (the dirty list may hold a page twice)
            if p.flags & (F_DIRTY | F_FRZ) == F_DIRTY {
                p.flags |= F_FRZ;
                #[cfg(debug_assertions)]
                {
                    p.fz_crc = crate::codec::crc(&p.buf) ^ p.touched.len() as u32;
                }
                let l = page::level(&p.buf);
                per[l as usize] += 1;
                lv.push((l, s));
            }
        }
        let mut at = [0usize; 256];
        for l in 1..256 {
            at[l] = at[l - 1] + per[l - 1];
        }
        dirty.clear();
        dirty.resize(lv.len(), 0);
        for &(l, s) in &lv {
            dirty[at[l as usize]] = s;
            at[l as usize] += 1;
        }
        let list = dirty;
        crate::diag::lap(30, &mut dt);
        let psz = self.cfg.psz;
        // arena room for every pending page (written whole, or a delta entry: delta pages <= entries) plus the meta image
        // freeze_end appends (twice its current size: dead list / delta directory grow meanwhile): growing a 50-300 MB
        // arena at freeze_end copied all of it (adr 0021 am. 62)
        let blob = crate::alloc::blob_pages(self.blob_len(), psz);
        let room = list.len() + 2 * blob + 2;
        let arena = crate::fzarena::Arena::new(
            psz,
            self.chunk_pages,
            std::mem::take(&mut self.spare_chunks),
        );
        crate::diag::lap(31, &mut dt);
        let fr = Frozen {
            arena,
            room,
            pages: Vec::with_capacity(list.len()),
            root: None,
            height: 0,
            bitmap: Vec::new(),
            // pages retired before `lsn`: no longer referenced by this checkpoint's tree
            free_after: std::mem::take(&mut self.retired),
            meta_used: 0,
            blob: None,
        };
        self.remap.clear();
        self.victims = None;
        self.pending_delta = 0;
        self.hot_chosen = 0;
        self.hot_short = 0;
        self.fz_no = self.fz_no.wrapping_add(1).max(1);
        self.delta_left = if self.delta_leaf_max == 0 {
            usize::MAX
        } else {
            self.delta_leaf_max
        };
        let root = (self.root_addr != NONE).then_some((self.root_addr, self.root_crc, self.height));
        self.fz = Some(Box::new(Fz {
            lsn,
            list,
            pos: 0,
            fr,
            seg: SegOut::default(),
            n_entries: 0,
            root,
            dead: self.dead.clone(),
            dead_gen: self.dead_gen,
            dropped: Vec::new(),
            pinned: Vec::new(),
            shadows: HashMap::new(),
            end: FzEnd::Fix(0),
        }));
        Ok(())
    }

    /// A sliced freeze is running (between [`Tree::freeze_begin`] and [`Tree::freeze_end`]).
    pub fn fz_active(&self) -> bool {
        self.fz.is_some()
    }

    /// Process up to `budget` units: pending pages (bottom-up), then the end steps ([`FzEnd`]; a visited dirty page, an
    /// unaliased page or a relogged chain is one unit each). Returns (all done = [`Tree::freeze_end`] may run, units).
    pub fn freeze_step(&mut self, budget: usize) -> (bool, usize) {
        let mut n = 0;
        loop {
            let fz = self.fz.as_mut().expect("freeze running");
            if fz.pos >= fz.list.len() {
                break;
            }
            if n >= budget {
                return (false, n);
            }
            let s = fz.list[fz.pos];
            fz.pos += 1;
            if let Some(sh) = fz.shadows.remove(&s) {
                self.fz_process_shadow(s, sh);
                n += 1;
            } else if self.slab[s as usize].flags & F_FRZ != 0 {
                self.fz_process(s);
                n += 1;
            }
        }
        let done = self.fz_end_steps(budget, &mut n);
        (done, n)
    }

    /// Units left in the current step of the running freeze: pending pages (upper bound: some may have been forced
    /// already), then dirty pages to visit, pages to unalias, chains that may be relogged (upper bound).
    pub fn fz_left(&self) -> usize {
        self.fz.as_ref().map_or(0, |f| {
            if f.pos < f.list.len() {
                return f.list.len() - f.pos;
            }
            match f.end {
                FzEnd::Fix(i) => self.dirty.len().saturating_sub(i),
                FzEnd::Unalias(i) => f.list.len().saturating_sub(i),
                FzEnd::Relog(_) => self.chains.len(),
                FzEnd::Done => 0,
            }
        })
    }

    /// The running freeze wrote its pages and is in its end steps (fix-up, unalias, relog).
    pub fn fz_ending(&self) -> bool {
        self.fz
            .as_ref()
            .is_some_and(|f| f.pos >= f.list.len() && f.end != FzEnd::Done)
    }

    /// The end steps of the running freeze (every pending page processed) within `budget` units (`n` counts on).
    fn fz_end_steps(&mut self, budget: usize, n: &mut usize) -> bool {
        let mut dt = crate::diag::t0();
        loop {
            let end = self.fz.as_ref().expect("freeze running").end;
            match end {
                FzEnd::Fix(mut i) => {
                    // live interior pages changed while the freeze ran (shadowed ones, their split halves, new roots) still
                    // reference children by the addresses those had before it: take the new ones (every such page is dirty)
                    while i < self.dirty.len() {
                        if *n >= budget {
                            self.fz.as_mut().expect("freeze running").end = FzEnd::Fix(i);
                            crate::diag::lap(32, &mut dt);
                            return false;
                        }
                        let s = self.dirty[i];
                        i += 1;
                        *n += 1;
                        let p = &mut self.slab[s as usize];
                        if p.addr == NONE || page::level(&p.buf) == 0 {
                            continue;
                        }
                        for k in 0..page::nslots(&p.buf) {
                            let (ca, _) = page::int_child(&p.buf, k);
                            if let Some(&(na, nc)) = self.remap.get(&ca) {
                                page::int_set_ref(&mut p.buf, k, na, nc);
                            }
                        }
                    }
                    // a root taken from an unfixed page (`fix_root`) is an old address too
                    if let Some(&(na, nc)) = self.remap.get(&self.root_addr) {
                        (self.root_addr, self.root_crc) = (na, nc);
                    }
                    self.fz.as_mut().expect("freeze running").end = FzEnd::Unalias(0);
                }
                FzEnd::Unalias(mut i) => {
                    let fz = self.fz.as_mut().expect("freeze running");
                    while i < fz.list.len() {
                        if *n >= budget {
                            fz.end = FzEnd::Unalias(i);
                            crate::diag::lap(32, &mut dt);
                            return false;
                        }
                        // processed pages keep only their new address
                        let s = fz.list[i];
                        i += 1;
                        *n += 1;
                        let p = &mut self.slab[s as usize];
                        if p.alias != 0 {
                            let a = std::mem::replace(&mut p.alias, 0);
                            if self.map.get(&a) == Some(&s) {
                                self.map.remove(&a);
                            }
                        }
                    }
                    // relog down to the page bound minus what this freeze wrote (room for the next freeze)
                    let own = fz.seg.pages.len() + usize::from(fz.seg.fill.is_some());
                    let end = if self.deltas && self.relog {
                        FzEnd::Relog(self.delta_max_pages().saturating_sub(own))
                    } else {
                        FzEnd::Done
                    };
                    self.fz.as_mut().expect("freeze running").end = end;
                    self.epoch += 1;
                    crate::diag::lap(32, &mut dt);
                }
                FzEnd::Relog(target) => {
                    let mut fz = self.fz.take().expect("freeze running");
                    let more = self.relog_front(&mut fz.fr, fz.lsn, &mut fz.seg, target, budget, n);
                    if !more {
                        fz.end = FzEnd::Done;
                    }
                    self.fz = Some(fz);
                    crate::diag::lap(15, &mut dt);
                    if more {
                        return false;
                    }
                }
                FzEnd::Done => return true,
            }
        }
    }

    /// Drop the alias address of slot `s` (sliced freeze) before the slot is freed or reused.
    fn unalias(&mut self, s: u32) {
        let a = std::mem::replace(&mut self.slab[s as usize].alias, 0);
        if a != 0 && self.map.get(&a) == Some(&s) {
            self.map.remove(&a);
        }
    }

    /// Write barrier of the sliced freeze: page `s` is about to change (content, address, removal). If it is pending,
    /// a leaf is processed now (one page), an interior page is copied (its image of the freeze's lsn is processed from
    /// the copy in its turn, after its children: no cascade through pending descendants).
    #[inline]
    fn fz_touch(&mut self, s: u32) {
        if self.slab[s as usize].flags & F_FRZ != 0 {
            let mut dt = crate::diag::t0();
            if page::level(&self.slab[s as usize].buf) == 0 {
                self.fz_process(s);
            } else {
                self.fz_shadow(s);
            }
            crate::diag::lap(17, &mut dt);
        }
    }

    /// Copy pending interior page `s` (its state at the freeze's lsn) aside; the live page is free to change and is dirty
    /// for the next checkpoint (its child references are brought up to date at the freeze's end).
    fn fz_shadow(&mut self, s: u32) {
        let p = &mut self.slab[s as usize];
        #[cfg(debug_assertions)]
        assert_eq!(
            p.fz_crc,
            crate::codec::crc(&p.buf) ^ p.touched.len() as u32,
            "page changed after the freeze took it (missing write barrier)"
        );
        let sh = Shadow {
            buf: p.buf.clone(),
            flags: p.flags,
            addr: p.addr,
            live: true,
        };
        p.flags &= !F_FRZ;
        let again = p.flags & F_AGAIN != 0;
        p.flags &= !F_AGAIN;
        if !again {
            // the next checkpoint's copy (the taken one stays counted until it is processed)
            self.ndirty += 1;
            self.dirty.push(s);
        }
        self.fz
            .as_mut()
            .expect("freeze running")
            .shadows
            .insert(s, sh);
    }

    /// Freeze the copy of a shadowed interior page: clean (no child moved, no change of its own) or a fresh address +
    /// sealed image. The live page (if still in the tree) takes the new address as its durable base.
    fn fz_process_shadow(&mut self, s: u32, mut sh: Shadow) {
        let mut fz = self.fz.take().expect("freeze running");
        let lsn = fz.lsn;
        let old = sh.addr;
        self.ndirty -= 1;
        let moved = (0..page::nslots(&sh.buf))
            .any(|i| self.remap.contains_key(&page::int_child(&sh.buf, i).0));
        if old & VIRT == 0 && sh.flags & F_MOD == 0 && !moved {
            // unchanged at the lsn: the checkpoint keeps referencing the old image
            self.stats.fz_clean += 1;
            if !sh.live {
                self.retired.push(old); // removed from the tree after the lsn: freed with the next checkpoint
            }
            self.fz = Some(fz);
            return;
        }
        let idx = self.meta.alloc().expect("checked free pages");
        let new = self.page_addr(idx);
        for i in 0..page::nslots(&sh.buf) {
            let (ca, _) = page::int_child(&sh.buf, i);
            if let Some(&(na, nc)) = self.remap.get(&ca) {
                page::int_set_ref(&mut sh.buf, i, na, nc);
            }
        }
        let c = page::seal(&mut sh.buf, new, lsn);
        self.stats.fz_whole_ints += 1;
        let i = fz.fr.arena.push(&sh.buf);
        fz.fr.pages.push((new, i));
        self.remap.insert(old, (new, c));
        if old & VIRT == 0 {
            fz.fr.free_after.push(old);
        }
        if sh.live {
            let p = &mut self.slab[s as usize];
            p.addr = new;
            p.dcrc = c;
            p.alias = old;
            self.map.insert(new, s);
            if old == self.root_addr {
                self.root_addr = new;
                self.root_crc = c;
            }
        } else {
            self.retired.push(new); // only this checkpoint references it
        }
        self.fz = Some(fz);
    }

    /// Freeze one pending page (its pending children are processed): a delta entry, a clean path page, or a fresh
    /// address + sealed image copied into the arena (the old address stays mapped to it until the freeze ends: parents
    /// not yet processed still route through it).
    fn fz_process(&mut self, s: u32) {
        let mut fz = self.fz.take().expect("freeze running");
        let p = &mut self.slab[s as usize];
        debug_assert!(p.flags & F_FRZ != 0);
        #[cfg(debug_assertions)]
        assert_eq!(
            p.fz_crc,
            crate::codec::crc(&p.buf) ^ p.touched.len() as u32,
            "page changed after the freeze took it (missing write barrier)"
        );
        p.flags &= !F_FRZ;
        let again = p.flags & F_AGAIN != 0;
        p.flags &= !F_AGAIN;
        let lsn = fz.lsn;
        // pages that need no new image of their own (adr 0021 am. 19): a leaf with a small net change becomes a
        // delta entry, a path page none of whose children moved and that did not change itself stays as it is
        let mut dt = crate::diag::t0();
        let ents = fz.n_entries;
        if self.settle(s, &mut fz) {
            if fz.n_entries == ents {
                self.stats.fz_clean += 1;
            }
            if page::level(&self.slab[s as usize].buf) == 0 {
                // resident until the freeze ends, when the segment page holding its entry is written
                self.slab[s as usize].flags |= F_INFLIGHT;
                fz.pinned.push((s, self.slab[s as usize].addr));
            }
            if again {
                // settle uncounted the taken copy; the next checkpoint's copy stays counted (F_AGAIN)
                self.slab[s as usize].flags |= F_DIRTY;
            }
            crate::diag::lap(13, &mut dt);
            self.fz = Some(fz);
            return;
        }
        let idx = self.meta.alloc().expect("checked free pages");
        let new = self.page_addr(idx);
        self.touch_release(s); // written whole: the new image is the base of the next log
        let p = &mut self.slab[s as usize];
        let old = p.addr;
        if page::level(&p.buf) > 0 {
            for i in 0..page::nslots(&p.buf) {
                let (ca, _) = page::int_child(&p.buf, i);
                if let Some(&(na, nc)) = self.remap.get(&ca) {
                    page::int_set_ref(&mut p.buf, i, na, nc);
                }
            }
        }
        if page::level(&p.buf) == 0 {
            self.stats.fz_whole_leaves += 1;
            let tag = match page::prefix(&p.buf).first() {
                Some(&t) => t,
                None if page::nslots(&p.buf) > 0 => {
                    page::leaf_ent(&p.buf, 0).0.first().copied().unwrap_or(0)
                }
                None => 0,
            };
            self.fz_whole_tag[tag as usize] += 1;
        } else {
            self.stats.fz_whole_ints += 1;
        }
        let c = page::seal(&mut p.buf, new, lsn);
        p.dcrc = c;
        let i = fz.fr.arena.push(&p.buf);
        fz.fr.pages.push((new, i));
        p.addr = new;
        p.alias = old;
        p.flags = (p.flags & !(F_DIRTY | F_MOD | F_NOTRK)) | F_INFLIGHT;
        // the taken copy is written: uncounted; a re-dirtied page (F_AGAIN) stays dirty with the count its re-dirtying
        // added (am. 42: keeping this count as well leaked one dirty page per such page and checkpoint)
        self.ndirty -= 1;
        if again {
            p.flags |= F_DIRTY;
        }
        self.map.insert(new, s);
        self.remap.insert(old, (new, c));
        if old & VIRT == 0 {
            fz.fr.free_after.push(old);
            self.drop_chain(old);
        }
        if old == self.root_addr {
            self.root_addr = new;
            self.root_crc = c;
        }
        crate::diag::lap(14, &mut dt);
        self.fz = Some(fz);
    }

    /// Sliced freeze, last step (every pending page processed): delta pages, root reference and meta image of the
    /// checkpoint at the freeze's lsn.
    pub fn freeze_end(&mut self) -> Frozen {
        let mut dt = crate::diag::t0();
        let fz = *self.fz.take().expect("freeze running");
        debug_assert!(fz.pos >= fz.list.len() && fz.end == FzEnd::Done);
        let Fz {
            lsn,
            mut list,
            mut fr,
            seg,
            root,
            dead,
            dead_gen,
            dropped,
            pinned,
            ..
        } = fz;
        list.clear();
        if self.dirty.is_empty() {
            self.dirty = list; // keep the capacity
        }
        self.emit_deltas(&mut fr, lsn, seg);
        // chains dropped while the freeze ran (page rewritten or removed after it was settled) must not keep the entry
        // just added
        for a in dropped {
            self.drop_chain(a);
        }
        for (s, a) in pinned {
            let p = &mut self.slab[s as usize];
            if p.addr == a {
                p.flags &= !F_INFLIGHT;
            }
        }
        crate::diag::lap(15, &mut dt);
        if let Some((a, c, h)) = root {
            fr.root = Some(self.remap.get(&a).copied().unwrap_or((a, c)));
            fr.height = h;
        }
        if self.meta.is_elastic() {
            // the image lists the detached subtrees of `lsn` (the drain and new detaches since belong to the next one)
            let live = std::mem::replace(&mut self.dead, dead);
            let live_gen = std::mem::replace(&mut self.dead_gen, dead_gen);
            self.freeze_blob(&mut fr, lsn);
            self.dead = live;
            self.dead_gen = live_gen;
            crate::diag::lap(16, &mut dt);
            return fr;
        }
        let idxs = self.free_idxs(&fr.free_after);
        fr.meta_used = self.meta.used() - idxs.len() as u32;
        fr.bitmap = self
            .meta
            .encode(self.geom.bm_blocks as usize * crate::BLK, Some(&idxs));
        fr
    }

    /// Freeze step for a dirty page that may need no image of its own (adr 0021 am. 19). A leaf with a small net change
    /// against its durable state (base image + chain) becomes a delta entry pushed on `entries` (`(base addr, base
    /// crc, route key, ops)`); a path page that did not change itself and none of whose children is rewritten is simply
    /// clean again. True = handled (the page is clean), false = it is written whole.
    fn settle(&mut self, s: u32, fz: &mut Fz) -> bool {
        let p = &self.slab[s as usize];
        if p.addr & VIRT != 0 || p.flags & F_MOD != 0 {
            return false;
        }
        if page::level(&p.buf) == 0 {
            // settled by the previous freeze too: a leaf whose chain saves a whole write in each checkpoint
            let hot = p.fz_no != 0 && p.fz_no.wrapping_add(1) == self.fz_no;
            self.slab[s as usize].fz_no = self.fz_no;
            let p = &self.slab[s as usize];
            if !self.deltas || p.flags & F_NOTRK != 0 || self.delta_left == 0 {
                return false;
            }
            let (addr, crc) = (p.addr, p.dcrc);
            let mut ops = std::mem::take(&mut self.ops_buf);
            self.delta_left -= 1;
            let r = delta::build_ops(&p.buf, &p.touched, self.entry_max, &mut ops);
            let ok = match r {
                delta::Built::Empty => true, // touched and put back: no net change
                delta::Built::Route(route) => {
                    let chain_ok =
                        self.chains.chain_bytes(addr, crc) + 4 + ops.len() <= self.chain_max;
                    let fits = chain_ok && self.delta_room(self.pending_delta);
                    if fits {
                        self.pending_delta += 4 + ops.len();
                        if hot {
                            self.hot_chosen += 4 + ops.len();
                        }
                        self.seg_push(&mut fz.fr, fz.lsn, &mut fz.seg, addr, crc, false, &ops);
                        self.chains.add(addr, crc, self.delta_seq + 1, &route, &ops);
                        fz.n_entries += 1;
                        self.stats.delta_entries += 1;
                    } else {
                        self.stats.delta_declined += 1;
                        if chain_ok {
                            self.stats.declined_room += 1;
                            if hot && self.chains.bytes() > self.delta_cap {
                                self.hot_short += 4 + ops.len(); // the RAM cap, not the page or image bound
                            }
                        } else {
                            self.stats.declined_chain += 1;
                        }
                    }
                    fits
                }
                delta::Built::TooBig => {
                    self.stats.delta_declined += 1;
                    false
                }
            };
            self.ops_buf = ops;
            if !ok {
                return false;
            }
        } else {
            for i in 0..page::nslots(&p.buf) {
                if self.remap.contains_key(&page::int_child(&p.buf, i).0) {
                    return false;
                }
            }
        }
        let p = &mut self.slab[s as usize];
        p.flags &= !(F_DIRTY | F_MOD | F_NOTRK);
        self.ndirty -= 1;
        self.touch_release(s);
        true
    }

    /// End of a freeze's delta segment `w` (its entries were written and added to the chains as their leaves settled, the
    /// oldest segments cleaned by relog in the end steps, [`Tree::relog_front`]): seal the last page, and release the oldest
    /// segments no chain refers to any more (their pages are freed with this checkpoint).
    fn emit_deltas(&mut self, fr: &mut Frozen, lsn: u64, mut w: SegOut) {
        if !self.deltas {
            return;
        }
        let seq = self.delta_seq + 1;
        if let Some((f, a)) = w.fill.take() {
            self.seg_seal(fr, lsn, &mut w.pages, f, a);
        }
        if !w.pages.is_empty() {
            self.delta_seq = seq;
            self.stats.delta_pages += w.pages.len() as u64;
            self.seg_pages += w.pages.len();
            self.segs.push_back(SegDir {
                seq,
                pages: w.pages,
            });
            self.segs_gen += 1;
        }
        while let Some(f) = self.segs.front() {
            if self.chains.holds(f.seq) {
                break;
            }
            self.pop_front_seg(fr);
        }
    }

    fn pop_front_seg(&mut self, fr: &mut Frozen) {
        let f = self.segs.pop_front().expect("front segment");
        self.seg_pages -= f.pages.len();
        fr.free_after.extend(f.pages.iter().map(|p| p.0));
        self.segs_gen += 1;
    }

    /// Append one entry to the freeze's segment (a fresh delta page when the current one is full).
    #[allow(clippy::too_many_arguments)]
    fn seg_push(
        &mut self,
        fr: &mut Frozen,
        lsn: u64,
        w: &mut SegOut,
        addr: u64,
        crc: u32,
        restart: bool,
        ops: &[u8],
    ) {
        if w.fill.as_ref().is_none_or(|(f, _)| !f.fits(ops.len())) {
            if let Some((f, a)) = w.fill.take() {
                self.seg_seal(fr, lsn, &mut w.pages, f, a);
            }
            let idx = self.meta.alloc().expect("checked free pages");
            let a = self.page_addr(idx);
            // the buffer of the last sealed page (its tail is zeroed by `finish`)
            let mut b = std::mem::take(&mut self.dpage_buf);
            b.resize(self.cfg.psz, 0);
            page::init(&mut b, page::DELTA, 0, a, self.cfg.shard);
            w.fill = Some((delta::PageFill::new(b), a));
        }
        w.fill.as_mut().unwrap().0.push(addr, crc, restart, ops);
    }

    fn seg_seal(
        &mut self,
        fr: &mut Frozen,
        lsn: u64,
        pages: &mut Vec<(u64, u32)>,
        f: delta::PageFill,
        addr: u64,
    ) {
        let mut b = f.finish();
        let c = page::seal(&mut b, addr, lsn);
        let i = fr.arena.push(&b);
        fr.pages.push((addr, i));
        pages.push((addr, c));
        self.dpage_buf = b;
    }

    /// Segment cleaning (relog, adr 0021 am. 65): segments are freed oldest first and only once no chain holds them, so a
    /// few cold chains pin old, mostly dead segments until the page bound declines every new delta (leaves written whole,
    /// 8 KiB per small change). While the segments exceed the page bound minus what this freeze wrote (room for the next
    /// freeze: the rate the bound is consumed is the rate it is cleaned), the chains holding the front segment are copied
    /// whole into this freeze's segment (first entry flagged [`delta::RESTART`]) and the front segment is freed with this
    /// checkpoint. Stops where the meta pages, the image size, or the arena reserved at `freeze_begin` would not take
    /// the copies (the arena is never regrown: am. 62); the page bound then declines as before.
    /// An end step of the sliced freeze (adr 0021 am. 80): copies chains while `*n < budget` (one unit each; `n` counts on)
    /// down to `target` segment pages (the page bound minus what this freeze wrote before its relog). True = more to clean
    /// (call again in the next slice), false = done for this freeze.
    fn relog_front(
        &mut self,
        fr: &mut Frozen,
        lsn: u64,
        w: &mut SegOut,
        target: usize,
        budget: usize,
        n: &mut usize,
    ) -> bool {
        let psz = self.cfg.psz;
        let seq = self.delta_seq + 1;
        while self.seg_pages + w.pages.len() + usize::from(w.fill.is_some()) > target {
            let Some(front) = self.segs.front() else {
                return false;
            };
            let fseq = front.seq;
            // holders in batches (a chain relogged leaves the set); no chain left: the front is free
            loop {
                if *n >= budget {
                    return true;
                }
                let batch = self.chains.holders(fseq, (budget - *n).min(64));
                if batch.is_empty() {
                    break;
                }
                for a in batch {
                    *n += 1;
                    let (crc, ops) = self.chains.lend(a);
                    let used = w.fill.as_ref().map(|(f, _)| f.used());
                    let need = delta::new_pages(psz, used, delta::blobs(&ops).map(<[u8]>::len));
                    // directory entries of this segment (+ the page being filled); the image size bound as in
                    // `delta_room`, the pages the image takes as `freeze_blob` writes it
                    let dir = 12 * (w.pages.len() + need + 3);
                    let img = crate::alloc::blob_pages(self.blob_len() + dir, psz);
                    if self.meta.blob_len() + self.ext_reserve() + dir
                        > crate::alloc::blob_max_len(psz)
                        || (self.meta.free() as usize) < need + img + 1
                        || fr.room - fr.arena.pages() < need + img + 1
                    {
                        // no room: this chain stays where it is (the chains relogged so far are complete copies)
                        self.chains.give_back(a, ops);
                        return false;
                    }
                    for (i, b) in delta::blobs(&ops).enumerate() {
                        self.seg_push(fr, lsn, w, a, crc, i == 0, b);
                    }
                    self.chains.relogged(a, ops, seq);
                    self.stats.relog_chains += 1;
                }
            }
            self.stats.relog_segs += 1;
            self.pop_front_seg(fr);
        }
        false
    }

    /// Elastic store: the meta image is rewritten into fresh meta pages whenever anything changed (tree pages,
    /// freed pages, the cell set); the previous image's pages are freed with the checkpoint like superseded tree
    /// pages. Unchanged: the root keeps pointing at the current image.
    fn freeze_blob(&mut self, fr: &mut Frozen, lsn: u64) {
        let psz = self.cfg.psz;
        let changed = !fr.pages.is_empty()
            || !fr.free_after.is_empty()
            || self.blob_ref.is_none()
            || self.meta.layout_gen() != self.blob_gen
            || self.dead_gen != self.dead_frozen_gen
            || self.segs_gen != self.segs_frozen_gen;
        if changed {
            let len = self.blob_len();
            let k = crate::alloc::blob_pages(len, psz);
            let addrs: Vec<u64> = (0..k)
                .map(|_| {
                    let idx = self.meta.alloc().expect("checked free pages");
                    self.page_addr(idx)
                })
                .collect();
            fr.free_after.append(&mut self.blob_cur);
            let idxs = self.free_idxs(&fr.free_after);
            let mut payload = self.meta.blob_encode(&idxs);
            if self.lazy || self.deltas {
                payload.extend_from_slice(&self.encode_ext());
            }
            self.dead_frozen_gen = self.dead_gen;
            self.segs_frozen_gen = self.segs_gen;
            let (img, c0) = crate::alloc::blob_pack(&payload, psz, &addrs, self.cfg.shard, lsn);
            let first = fr.arena.push(&img);
            for (i, &a) in addrs.iter().enumerate() {
                fr.pages.push((a, first + i as u32));
            }
            fr.meta_used = self.meta.used() - idxs.len() as u32;
            self.blob_ref = Some((addrs[0], c0, k as u32));
            self.blob_cur = addrs;
            self.blob_gen = self.meta.layout_gen();
        } else {
            fr.meta_used = self.meta.used();
        }
        fr.blob = self.blob_ref;
    }

    /// A frozen page's write completed.
    pub fn page_written(&mut self, addr: u64) {
        if let Some(&s) = self.map.get(&addr) {
            self.slab[s as usize].flags &= !F_INFLIGHT;
        }
    }

    /// A finished checkpoint's arena: its chunks serve the next freeze, up to the chunks of `keep_pages` pages (the
    /// budgeted checkpoint size, the soft dirty mark) plus one; an outsized checkpoint (overload, post-replay) frees the
    /// rest, so the arena never keeps the high-water of the largest checkpoint ever (review M2).
    pub fn arena_return(&mut self, a: crate::fzarena::Arena, keep_pages: usize) {
        self.spare_chunks.extend(a.into_chunks());
        self.spare_chunks
            .truncate(keep_pages.div_ceil(self.chunk_pages.max(1)) + 1);
    }

    /// Bytes of the arena chunks kept for the next checkpoint.
    pub fn spare_arena_bytes(&self) -> usize {
        self.spare_chunks.iter().map(Vec::capacity).sum()
    }

    /// Pages per checkpoint arena chunk: the shard's largest device write (a write job is a slice of one chunk).
    /// Chunks of the earlier size are dropped.
    pub fn set_ckpt_chunk(&mut self, pages: usize) {
        self.chunk_pages = pages.max(1);
        self.spare_chunks.clear();
    }

    /// Meta page indices of the addresses a checkpoint freed (the bitmap/cell-set image it writes).
    fn free_idxs(&self, free_after: &[u64]) -> Vec<u32> {
        free_after
            .iter()
            .map(|&a| self.page_idx(a).expect("freed page address"))
            .collect()
    }

    /// The checkpoint's root slot is durable: superseded pages become reusable.
    pub fn ckpt_complete(&mut self, free_after: &[u64]) {
        for &a in free_after {
            let i = self.page_idx(a).expect("freed page address");
            self.meta.clear(i);
        }
    }

    // ---------------------------------------------------------------- introspection (tests, fsck helpers)

    /// Page counts and bytes in use of the resident pages (the whole tree when everything is cached): density
    /// measurements (interior pages per entry = RAM to keep the interior resident).
    pub fn shape(&self) -> TreeShape {
        let mut s = TreeShape {
            height: self.height,
            ..Default::default()
        };
        for p in self.slab.iter().filter(|p| p.addr != NONE) {
            let b = &p.buf;
            let used = (self.cfg.psz - page::free_total(b)) as u64;
            let leaf = page::kind(b) == LEAF;
            let mut prev: Vec<u8> = Vec::new();
            let mut full = Vec::new();
            let pl = page::prefix(b).len();
            let (mut sfx, mut lcp, mut val) = (0u64, 0u64, 0u64);
            for i in 0..page::nslots(b) {
                let (k, v) = if leaf {
                    let (k, v) = page::leaf_ent(b, i);
                    (k, v.len())
                } else {
                    full.clear();
                    page::key_into(b, i, &mut full);
                    (&full[pl..], 0)
                };
                sfx += k.len() as u64;
                lcp += k.iter().zip(&prev).take_while(|(a, b)| a == b).count() as u64;
                val += v as u64;
                prev.clear();
                prev.extend_from_slice(k);
            }
            if leaf {
                s.leaves += 1;
                s.leaf_used += used;
                s.entries += page::nslots(b) as u64;
                s.leaf_sfx += sfx;
                s.leaf_lcp += lcp;
                s.leaf_val += val;
            } else {
                s.interior += 1;
                s.int_used += used;
                s.int_entries += page::nslots(b) as u64;
                s.int_sfx += sfx;
                s.int_lcp += lcp;
            }
        }
        s
    }

    /// Every resident leaf image (measurement tests: what a page-level codec would see).
    pub fn leaf_images(&self, f: &mut dyn FnMut(&[u8])) {
        for p in self.slab.iter().filter(|p| p.addr != NONE) {
            if page::kind(&p.buf) == LEAF {
                f(&p.buf);
            }
        }
    }

    /// Every resident page with a disk address sits on an allocated meta page and is the one the address maps to (a
    /// stale copy of a freed page would shadow or unmap the page that reuses the address). Test helper.
    pub fn check_resident_alloc(&self) -> std::result::Result<(), String> {
        for (s, p) in self.slab.iter().enumerate() {
            if p.addr == NONE || p.addr & VIRT != 0 {
                continue;
            }
            if self.map.get(&p.addr) != Some(&(s as u32)) {
                return Err(format!("resident page {} is not the mapped one", p.addr));
            }
            match self.page_idx(p.addr) {
                Some(i) if self.meta.get(i) => {}
                _ => return Err(format!("resident page {} is not allocated", p.addr)),
            }
        }
        Ok(())
    }
}

fn two_bufs(slab: &mut [Page], a: u32, b: u32) -> (&mut [u8], &mut [u8]) {
    assert_ne!(a, b);
    if a < b {
        let (x, y) = slab.split_at_mut(b as usize);
        (&mut x[a as usize].buf, &mut y[0].buf)
    } else {
        let (x, y) = slab.split_at_mut(a as usize);
        (&mut y[0].buf, &mut x[b as usize].buf)
    }
}

#[cfg(test)]
mod slot_set_tests {
    use super::SlotSet;

    #[test]
    fn insert_dedups_across_growth_and_clear() {
        let mut s = SlotSet::default();
        for round in 0..3u32 {
            for i in 0..1000u32 {
                assert!(s.insert(i * 7 + round), "fresh slot");
            }
            for i in 0..1000u32 {
                assert!(!s.insert(i * 7 + round), "slot inserted twice");
            }
            assert_eq!(s.len, 1000);
            s.clear();
            assert_eq!(s.len, 0);
        }
    }

    #[test]
    fn generation_wrap_wipes_old_entries() {
        let mut s = SlotSet::default();
        assert!(s.insert(5));
        s.round = u32::MAX;
        s.len = 0;
        assert!(s.insert(9));
        s.clear(); // wraps to 0: wiped, generation 1 again
        assert!(s.insert(5), "an entry of an old generation reads as absent");
        assert!(s.insert(9));
        assert!(!s.insert(5));
    }
}

#[cfg(test)]
mod hot_path_alloc_tests {
    use super::*;
    use crate::layout::{MetaGeom, ShardDir};

    fn dir() -> ShardDir {
        ShardDir {
            shard: 0,
            region_start: 0,
            region_blocks: 1 << 22,
            root_a: 0,
            root_b: 1,
            wal_start: 2,
            wal_blocks: 64,
            meta_start: 66,
            meta_blocks: 1 << 16,
            data_start: (1 << 15) + 66,
            data_blocks: 1000,
            ext: vec![],
            chunk_blocks: 0,
            #[cfg(feature = "elastic")]
            lent: Vec::new(),
        }
    }

    /// One-leaf tree with real page addresses and leaf deltas on.
    fn leaf_tree() -> Tree {
        let psz = 4096;
        let geom = MetaGeom::new(&dir(), psz as u32).unwrap();
        let mut t = Tree::new(
            TreeCfg {
                psz,
                shard: 0,
                cache_pages: 64,
                max_walk: 64,
                compact_int: true,
                bg_compact: false,
            },
            geom,
            MetaAlloc::new(64),
            None,
        );
        t.set_delta(true, false, 1 << 20, Vec::new());
        for i in 0..12u8 {
            t.put(format!("k{i:02}").as_bytes(), &[i; 100]).unwrap();
        }
        let fr = t.freeze(1).unwrap();
        t.ckpt_complete(&fr.free_after);
        t
    }

    /// Review store/tree.rs T5: the touch span of a range delete came from two fresh `Vec`s per boundary leaf; the
    /// tree's scratch buffers now carry it, so a delete of a resident leaf does not allocate.
    #[test]
    fn del_range_reuses_its_span_buffers() {
        let mut t = leaf_tree();
        // warm the scratch a txn keeps across its ranges (touch log, prune and merge arenas)
        for k in [b"k02", b"k04"] {
            let hi = [k[0], k[1], k[2] + 1];
            t.del_range(k, &hi).unwrap();
            t.finish_txn().unwrap();
        }
        let n = crate::test_alloc::allocations(|| {
            t.del_range(b"k06", b"k07").unwrap();
        });
        assert_eq!(n, 0, "a range delete allocated on the hot path");
    }
}

#[cfg(test)]
mod corrupt_tree_tests {
    use super::*;
    use crate::layout::{MetaGeom, ShardDir};

    /// All-resident tree of height 3 (keys `k{i:08}`, `i < 60000`, values `[7; 100]`): the root (level 2) has at least
    /// three children.
    pub(super) fn tall_tree() -> Tree {
        let psz = 4096;
        let dir = ShardDir {
            shard: 0,
            region_start: 0,
            region_blocks: 1 << 22,
            root_a: 0,
            root_b: 1,
            wal_start: 2,
            wal_blocks: 64,
            meta_start: 66,
            meta_blocks: 1 << 16,
            data_start: (1 << 15) + 66,
            data_blocks: 1000,
            ext: vec![],
            chunk_blocks: 0,
            #[cfg(feature = "elastic")]
            lent: Vec::new(),
        };
        let geom = MetaGeom::new(&dir, psz as u32).unwrap();
        let mut t = Tree::new(
            TreeCfg {
                psz,
                shard: 0,
                cache_pages: 8192,
                max_walk: 2048,
                compact_int: true,
                bg_compact: false,
            },
            geom,
            MetaAlloc::new((1 << 16) - 1),
            None,
        );
        for i in 0..60_000u64 {
            t.put(format!("k{i:08}").as_bytes(), &[7u8; 100]).unwrap();
        }
        assert_eq!(t.height(), 3, "test tree must have an interior root");
        let r = *t.map.get(&t.root_addr).expect("resident root");
        assert!(
            page::nslots(&t.slab[r as usize].buf) >= 3,
            "test tree needs a child strictly between the boundary ones"
        );
        t
    }

    /// A reference that points a child of the root back at the root: every descent driven by the reference's level,
    /// from `del_range` (detach or subtree drop) to `prune`, must refuse it instead of recursing forever.
    fn point_child_at_root(t: &mut Tree, child: usize) {
        let r = *t.map.get(&t.root_addr).expect("resident root");
        let (addr, _) = (t.root_addr, t.root_crc);
        page::int_set_ref(&mut t.slab[r as usize].buf, child, addr, 0);
    }

    #[test]
    fn del_range_refuses_a_page_referencing_an_ancestor() {
        for lazy in [true, false] {
            let mut t = tall_tree();
            t.set_lazy(lazy, Vec::new());
            point_child_at_root(&mut t, 1);
            match t.del_range(b"", &[0xff; 8]) {
                Err(StoreError::Corrupt(m)) => assert!(m.contains("level"), "{m}"),
                Err(e) => panic!("lazy {lazy}: unexpected error {e:?}"),
                Ok(()) => panic!("lazy {lazy}: a cyclic image was accepted"),
            }
        }
    }

    #[test]
    fn prune_refuses_a_page_referencing_an_ancestor() {
        let mut t = tall_tree();
        point_child_at_root(&mut t, 1);
        // the prune spans a range delete pushes (finish_prune walks them from the root)
        t.push_prune(b"", &[0xff; 8]);
        match t.finish_txn() {
            Err(StoreError::Corrupt(m)) => assert!(m.contains("level"), "{m}"),
            Err(e) => panic!("unexpected error {e:?}"),
            Ok(()) => panic!("a cyclic image was accepted"),
        }
    }
}

/// A probed record never misses while it applies, whatever its earlier ops did to the tree (adr 0021 S6, OQ 133): records
/// through `State::prepare` / `State::apply` on a cold tree (every page on "disk", nothing resident).
#[cfg(test)]
mod record_probe_tests {
    use super::*;
    use crate::alloc::Alloc;
    use crate::state::{Op, Record, State};
    use std::collections::BTreeMap;

    const N: u64 = 60_000;
    type Disk = HashMap<u64, Vec<u8>>;
    type Model = BTreeMap<Vec<u8>, Vec<u8>>;

    fn key(i: u64) -> Vec<u8> {
        format!("k{i:08}").into_bytes()
    }

    /// Index of the first key `>= k` (`N` if none).
    fn first_at(k: &[u8]) -> u64 {
        let (mut lo, mut hi) = (0, N);
        while lo < hi {
            let m = (lo + hi) / 2;
            if key(m).as_slice() < k {
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        lo
    }

    /// `corrupt_tree_tests::tall_tree` written to `disk` and evicted, with its model.
    fn cold_state(lazy: bool) -> (State, Disk, Model) {
        let mut t = super::corrupt_tree_tests::tall_tree();
        t.set_lazy(lazy, Vec::new());
        let mut disk = Disk::new();
        checkpoint(&mut t, &mut disk, 1);
        let model = (0..N).map(|i| (key(i), vec![7u8; 100])).collect();
        (State::new(t, Alloc::new(0, 1024)), disk, model)
    }

    /// Write every dirty page to `disk`, then drop every page from the cache.
    fn checkpoint(t: &mut Tree, disk: &mut Disk, lsn: u64) {
        let fr = t.freeze(lsn).unwrap();
        for &(addr, idx) in &fr.pages {
            disk.insert(addr, fr.arena.slice(idx as usize, 1).to_vec());
            t.page_written(addr);
        }
        t.ckpt_complete(&fr.free_after);
        t.drop_clean();
        assert_eq!(t.resident_pages(), 0, "cold tree");
    }

    fn load(t: &mut Tree, disk: &Disk) {
        let mut wants = Vec::new();
        t.take_wants(&mut wants);
        assert!(!wants.is_empty(), "miss without a wanted page");
        for w in &wants {
            t.install(w, &disk[&w.addr]).unwrap();
        }
    }

    /// `prepare` (loading what it asks for) + `apply`: the apply must not fail.
    fn commit(st: &mut State, disk: &Disk, model: &mut Model, lsn: u64, ops: Vec<Op>) {
        let rec = Record {
            lsn,
            ops,
            ..Default::default()
        };
        loop {
            match st.prepare(&rec) {
                Ok(_) => break,
                Err(StoreError::Miss) => load(&mut st.tree, disk),
                Err(e) => panic!("prepare: {e:?}"),
            }
        }
        if let Err((e, torn)) = st.apply(&rec) {
            panic!(
                "probed record failed to apply (torn {torn}): {e:?}: {:?}",
                rec.ops
            );
        }
        for op in &rec.ops {
            match op {
                Op::Put(k, v) => {
                    model.insert(k.clone(), v.clone());
                }
                Op::Del(k) => {
                    model.remove(k);
                }
                Op::DelRange(a, b) => {
                    let gone: Vec<Vec<u8>> = model
                        .range::<[u8], _>((
                            std::ops::Bound::Included(a.as_slice()),
                            std::ops::Bound::Excluded(b.as_slice()),
                        ))
                        .map(|(k, _)| k.clone())
                        .collect();
                    for k in gone {
                        model.remove(&k);
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    fn verify(st: &mut State, disk: &Disk, model: &Model) {
        verify_keys(st, disk, model, 0..N);
    }

    /// The keys with indices `idx` read back as the model holds them.
    fn verify_keys(st: &mut State, disk: &Disk, model: &Model, idx: impl IntoIterator<Item = u64>) {
        for i in idx {
            let k = key(i);
            let mut out = Vec::new();
            let got = loop {
                out.clear();
                match st.tree.get(&k, &mut out) {
                    Ok(f) => break f.then_some(&out),
                    Err(StoreError::Miss) => load(&mut st.tree, disk),
                    Err(e) => panic!("get: {e:?}"),
                }
            };
            assert_eq!(got, model.get(&k), "key {i}");
        }
    }

    /// Lower fences of the root's children (child 0: the empty key) as key indices.
    fn root_fences(t: &mut Tree, disk: &Disk) -> Vec<u64> {
        let r = loop {
            match t.root_slot() {
                Ok(r) => break r,
                Err(StoreError::Miss) => load(t, disk),
                Err(e) => panic!("root: {e:?}"),
            }
        };
        let pg = &t.slab[r as usize].buf;
        assert_eq!(page::level(pg), 2, "test tree has height 3");
        let mut out = vec![0];
        for i in 1..page::nslots(pg) {
            let mut sep = Vec::new();
            page::key_into(pg, i, &mut sep);
            out.push(first_at(&sep));
        }
        out
    }

    /// The record of the review (CX-04): `[DelRange(a1, b1), (Put(x),) DelRange(a2, b2)]`, a2 < a1 < b2 < b1. The first
    /// delete drops root child 3 whole; the second one's end b2 (in child 3 before the record) then lies in child 2,
    /// whose first leaf is inside both ranges and was loaded by no probe: the earlier rule descended into it as the
    /// clamped route of a2 (a2 lies below child 2) and missed after the first delete had changed the tree.
    #[test]
    fn overlapping_range_deletes_of_one_record_never_miss() {
        for lazy in [true, false] {
            for put in [false, true] {
                let (mut st, disk, mut model) = cold_state(lazy);
                let f = root_fences(&mut st.tree, &disk);
                assert!(f.len() >= 5, "root needs children 0..=4: {f:?}");
                let mid = |c: usize| (f[c] + f[c + 1]) / 2;
                assert!(mid(2) - f[2] > 100, "a1 must lie past child 2's first leaf");
                let mut ops = vec![Op::DelRange(key(mid(2)), key(mid(4)))];
                if put {
                    ops.push(Op::Put(key(mid(2) + 1), b"z".to_vec()));
                }
                ops.push(Op::DelRange(key(mid(1)), key(mid(3))));
                commit(&mut st, &disk, &mut model, 2, ops);
                verify(&mut st, &disk, &model);
            }
        }
    }

    /// Range deletes with ends outside the keyspace (below the first key, above the last one) or straddling the first and
    /// last key, also overlapping ones in one record that empty the tree down to one key, then all of it.
    #[test]
    fn range_deletes_past_the_keyspace_ends_never_miss() {
        // `g` sorts below `k00000000` (and above the reserved `f` range), `l` above `k00059999`
        let (lo, hi) = (b"g".to_vec(), b"l".to_vec());
        let m = N / 2;
        for lazy in [true, false] {
            let (mut st, mut disk, mut model) = cold_state(lazy);
            let records = [
                vec![Op::DelRange(lo.clone(), b"h".to_vec())],
                vec![Op::DelRange(hi.clone(), b"m".to_vec())],
                vec![
                    Op::DelRange(lo.clone(), key(5)),
                    Op::DelRange(key(N - 5), hi.clone()),
                ],
                vec![
                    Op::DelRange(key(m), hi.clone()),
                    Op::Put(key(m + 1), b"z".to_vec()),
                    Op::DelRange(lo.clone(), key(m + 2_000)),
                    Op::Put(key(7), b"y".to_vec()),
                ],
                vec![
                    Op::DelRange(lo.clone(), hi.clone()),
                    Op::Put(key(3), b"x".to_vec()),
                ],
            ];
            for (lsn, ops) in (2..).zip(records) {
                commit(&mut st, &disk, &mut model, lsn, ops);
                checkpoint(&mut st.tree, &mut disk, lsn);
                verify(&mut st, &disk, &model);
            }
            assert_eq!(model.keys().collect::<Vec<_>>(), [&key(3)]);
        }
    }

    /// Separators of every interior page (the whole tree loaded once, then evicted again).
    fn separators(t: &mut Tree, disk: &Disk) -> Vec<Vec<u8>> {
        loop {
            match t.prefetch_range(b"", &[0xff]) {
                Ok(()) => break,
                Err(StoreError::Miss) => load(t, disk),
                Err(e) => panic!("prefetch: {e:?}"),
            }
        }
        let mut out = Vec::new();
        for p in &t.slab {
            if p.addr != NONE && page::level(&p.buf) > 0 {
                for i in 1..page::nslots(&p.buf) {
                    let mut sep = Vec::new();
                    page::key_into(&p.buf, i, &mut sep);
                    out.push(sep);
                }
            }
        }
        t.drop_clean();
        out.sort();
        out
    }

    /// Random multi-op records (puts that split, removals, range deletes overlapping each other, ends on separators) on a
    /// tree made cold before every record. Fails without the end rule ([`Ends`]).
    #[test]
    fn random_records_on_a_cold_tree_never_miss() {
        for lazy in [true, false] {
            let n = random_records(lazy, false);
            // 18 / 19 with these seeds (lazy / not)
            assert!(n >= 10, "only {n} records split pages");
        }
    }

    /// As [`random_records_on_a_cold_tree_never_miss`], plus bursts of growing values that split leaves and interior pages
    /// before the record's later ops (a put stretch then a range delete: raw KV records only).
    #[test]
    fn random_records_with_put_bursts_never_miss() {
        for lazy in [true, false] {
            let n = random_records(lazy, true);
            // 109 / 120 with these seeds (lazy / not)
            assert!(n >= 80, "only {n} records split pages");
        }
    }

    /// 200 random records of 2-6 ops (`bursts`: also put bursts); after every record its ends' keys and a random sample
    /// read back as the model holds them, every 25 records and at the end all keys. Returns the records whose puts split
    /// a page.
    fn random_records(lazy: bool, bursts: bool) -> u32 {
        let (mut st, mut disk, mut model) = cold_state(lazy);
        let mut rng = crate::rng::Rng::new(0xC04 + lazy as u64);
        // own stream for the read-back sample: the records stay those of the generator alone
        let mut sample = crate::rng::Rng::new(0x5A4 + lazy as u64);
        let mut seps = separators(&mut st.tree, &disk);
        let mut lsn = 1;
        let mut split_records = 0;
        for round in 0..200 {
            let mut ops = Vec::new();
            for _ in 0..rng.range(2, 6) {
                // a key, a separator, or a key right after one
                let sep = &seps[rng.below(seps.len() as u64) as usize];
                let end = match rng.below(3) {
                    0 => key(rng.below(N)),
                    1 => sep.clone(),
                    _ => key((first_at(sep) + rng.below(100)).min(N - 1)),
                };
                match rng.below(if bursts { 5 } else { 4 }) {
                    0 | 1 => {
                        let w = [40u64, 3_000, 20_000][rng.below(3) as usize];
                        let mut b = key((first_at(&end) + 1 + rng.below(w)).min(N));
                        if rng.below(2) == 0 {
                            // up to the next separator: an end exactly on a child boundary
                            let i = seps.partition_point(|s| s < &b);
                            b = seps.get(i).cloned().unwrap_or(b);
                        }
                        if end < b {
                            ops.push(Op::DelRange(end, b));
                        }
                    }
                    2 => {
                        let v = vec![b'v'; rng.range(1, 400) as usize];
                        ops.push(Op::Put(key(first_at(&end).min(N - 1)), v));
                    }
                    3 => ops.push(Op::Del(key(rng.below(N)))),
                    _ => {
                        let from = first_at(&end).min(N - 1);
                        for i in from..(from + rng.range(20, 120)).min(N) {
                            ops.push(Op::Put(key(i), vec![b'w'; rng.range(300, 400) as usize]));
                        }
                    }
                }
            }
            // the keys at the ops' ends and next to them
            let mut probe: Vec<u64> = (0..32).map(|_| sample.below(N)).collect();
            for op in &ops {
                let (Op::Put(k, _) | Op::Del(k) | Op::DelRange(k, _)) = op else {
                    unreachable!()
                };
                let i = first_at(k);
                probe.extend([i.saturating_sub(1), i.min(N - 1)]);
                if let Op::DelRange(_, b) = op {
                    let j = first_at(b);
                    probe.extend([j.saturating_sub(1), j.min(N - 1)]);
                }
            }
            lsn += 1;
            let splits = st.tree.stats.splits;
            commit(&mut st, &disk, &mut model, lsn, ops);
            split_records += (st.tree.stats.splits > splits) as u32;
            if model.len() < 25_000 {
                // refill a block so later deletes find whole subtrees again
                let from = rng.below(N - 15_000);
                for ch in (from..from + 15_000).collect::<Vec<_>>().chunks(300) {
                    lsn += 1;
                    let ops = ch
                        .iter()
                        .map(|&i| Op::Put(key(i), vec![7u8; 100]))
                        .collect();
                    commit(&mut st, &disk, &mut model, lsn, ops);
                }
            }
            checkpoint(&mut st.tree, &mut disk, lsn);
            verify_keys(&mut st, &disk, &model, probe);
            if round % 25 == 24 {
                verify(&mut st, &disk, &model);
                seps = separators(&mut st.tree, &disk);
            }
        }
        verify(&mut st, &disk, &model);
        split_records
    }
}
