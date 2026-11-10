// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! store: storage engine (doc/design/storage-engine.md, ADR 0021). Sans-IO, single-threaded per shard, no locks.
//!
//! M2.0: `dev` (BlockDev re-export, SimDev with fault injection, clocks).
//! M2.1: `layout` (superblock, shard directory, root slots, mkfs/mount), `wal` (unit format, replay),
//! `shard` (group commit, parallel data+WAL commit, in-order ack).
//! M2.2: `page` (slotted B+tree page), `tree` (COW B+tree, page cache, freeze for checkpoints), `state`
//! (record application: tree + allocator), checkpoint state machine in `shard`, `fsck`.
//! M2.3: `alloc` (data bitmap allocator with reserved/held overlays, meta page allocator), ENOSPC handling,
//! reader epochs and statfs in `shard`.

pub mod admit;
pub mod alloc;
#[cfg(test)]
mod alloc_dense;
pub mod codec;
pub mod compress;
pub mod delta;
mod dependencies;
pub mod dev;
pub mod devidle;
pub mod diag;
pub mod error;
pub mod fastclock;
#[cfg(test)]
mod format_golden;
pub mod fsck;
pub mod fx;
pub mod fzarena;
pub mod layout;
#[cfg(feature = "elastic")]
pub mod lend;
pub mod obj;
pub mod olsm;
// Shared immutable-overlay mechanics, separate from direct-owned native LSM.
// Each selected foreign backend owns its own buffer instance in State.
#[cfg(all(feature = "splinterdb", not(feature = "rocksdb")))]
#[path = "rocks_omap/mem.rs"]
pub(crate) mod foreign_mem;
#[cfg(all(feature = "splinterdb", feature = "rocksdb"))]
pub(crate) use rocks_omap::mem as foreign_mem;
pub mod page;
pub mod pagepool;
pub mod pre;
pub mod report;
pub mod rng;
#[cfg(feature = "rocksdb")]
pub mod rocks_omap;
pub mod runs;
pub mod shard;
pub mod sio;
pub(crate) mod space;
#[cfg(feature = "splinterdb")]
pub mod splinter_omap;
pub mod state;
#[cfg(test)]
mod test_alloc;
pub mod toks;
pub mod tree;
pub(crate) mod trim;
pub mod upgrade;
pub mod vpool;
pub mod wal;

pub use error::StoreError;

/// Engine block size (fixed, design 2.3). Device LBAs of 512 B are used 8 at a time.
pub const BLK: usize = 4096;

/// Largest object size the format can address (extent keys carry a u32 block number): 16 TiB. The OSD's configurable
/// `osd_max_object_size` policy lies far below; this bound only rejects corrupt or impossible ranges.
pub const MAX_OBJECT_BYTES: u64 = (1 << 32) * BLK as u64;

/// Lab counters of the synchronous read fallbacks (process wide, relaxed; read by the exit report).
pub mod dbg {
    use std::sync::atomic::AtomicU64;
    /// Sync reads: calls with device jobs left after the prefetch table, their blocks, wall ns spent waiting.
    pub static SYNC_CALLS: AtomicU64 = AtomicU64::new(0);
    pub static SYNC_BLOCKS: AtomicU64 = AtomicU64::new(0);
    pub static SYNC_NS: AtomicU64 = AtomicU64::new(0);
    /// Blocking tree-page miss waits (`ShardStore::miss_wait`): calls and wall ns spent spinning (feature `lab`).
    pub static MISS_CALLS: AtomicU64 = AtomicU64::new(0);
    pub static MISS_NS: AtomicU64 = AtomicU64::new(0);
    /// `Store::parked_on` probes that found a non-empty parked queue, and the parked txns they scanned (feature `lab`).
    pub static PARK_SCANS: AtomicU64 = AtomicU64::new(0);
    pub static PARK_ITEMS: AtomicU64 = AtomicU64::new(0);
    /// Why `Store::queue` parked a txn (feature `lab`): 0 prepare WouldBlock, 1 submit WouldBlock, 2 queue not empty, 3 large.
    pub static PARK_WHY: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
    /// `resume_queue` outcomes (feature `lab`): 0 head gated (no progress since its last try), 1 prepare WouldBlock, 2 submit
    /// WouldBlock, 3 submitted, 4 polls that resumed, 5 budget / round cap ended the shard's turn with work left, 6 lookahead page loads submitted.
    pub static RQ: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];
    #[inline(always)]
    pub fn rq(_r: usize) {
        #[cfg(feature = "lab")]
        RQ[_r].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    #[inline(always)]
    pub fn park_why(_r: usize) {
        #[cfg(feature = "lab")]
        PARK_WHY[_r].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    /// Tree ops of a txn whose page was not resident at `prepare`, by key tag (feature `lab`).
    pub static PREP_MISS: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];
    /// Blocking miss waits by origin: key tag of a point read, 0 = submit (tree puts / dels of a txn) (feature `lab`).
    pub static MISS_TAG: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];
    /// A blocking miss of a point read with key tag `t` (0 = txn submit). Counted with feature `lab` only.
    #[inline(always)]
    pub fn miss_tag(_t: u8) {
        #[cfg(feature = "lab")]
        MISS_TAG[_t as usize].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    /// A blocking miss wait that started at `t0` is over (feature `lab`).
    #[cfg(feature = "lab")]
    pub fn miss_wait_done(t0: std::time::Instant) {
        use std::sync::atomic::Ordering::Relaxed;
        MISS_CALLS.fetch_add(1, Relaxed);
        MISS_NS.fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
    }
    /// A txn op whose page was not resident at `prepare` (feature `lab`).
    #[cfg(feature = "lab")]
    pub fn prep_miss(key: &[u8]) {
        PREP_MISS[key.first().copied().unwrap_or(0) as usize]
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    /// `warm_data` outcomes that leave the read synchronous: skip (too big), submit refused (queue full), write pending.
    pub static PF_SKIP: AtomicU64 = AtomicU64::new(0);
    pub static PF_BUSY: AtomicU64 = AtomicU64::new(0);
    pub static PF_WLSN: AtomicU64 = AtomicU64::new(0);
    pub static PF_UNUSUAL: AtomicU64 = AtomicU64::new(0);
    pub static PF_YES: AtomicU64 = AtomicU64::new(0);
    pub static PF_SUBMIT: AtomicU64 = AtomicU64::new(0);
    pub static PF_EXPIRED: AtomicU64 = AtomicU64::new(0);
    pub static PF_SERVED: AtomicU64 = AtomicU64::new(0);
    /// Blocking waits inside `Store::queue` (feature `lab`): [0] allocation `Busy` (held blocks / reclaim wait for a
    /// checkpoint), [1] `submit` `Busy`/`WalFull`; calls and wall ns.
    pub static QWAIT_CALLS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    pub static QWAIT_NS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    /// `Shard::validate` refusals by reason (feature `lab`): 1 dead list, 2 dirty hard, 3 meta space, 4 data backlog,
    /// 5 device queue, 6 ready units, 7 WAL ring, 8 multi ready, 9 multi ring.
    pub static BUSY: [AtomicU64; 11] = [const { AtomicU64::new(0) }; 11];
    #[inline(always)]
    pub fn busy(_r: usize) {
        #[cfg(feature = "lab")]
        BUSY[_r].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    /// A blocking wait of kind `k` that started at `t0` is over (feature `lab`).
    #[cfg(feature = "lab")]
    pub fn qwait_done(k: usize, t0: std::time::Instant) {
        use std::sync::atomic::Ordering::Relaxed;
        QWAIT_CALLS[k].fetch_add(1, Relaxed);
        QWAIT_NS[k].fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
    }
}
