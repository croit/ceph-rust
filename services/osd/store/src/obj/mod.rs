// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! L2 object layer (stage M2.4): collections, onodes, extents with per-4k crc, xattrs, omap, listing, clone,
//! deep-scrub read path, on top of the per-shard KV (`Shard`). See doc/design/storage-engine.md, "Impl notes
//! (M2.4)".
//!
//! Blocking driver: operations spin `Shard::poll` through a [`crate::dev::Clock`] while they wait for tree
//! pages or device reads (single-thread API for now; the engine underneath is the sans-IO state machine).

mod budget;
pub mod check;
mod datacache;
pub mod dedup;
mod defrag;
mod dirty;
pub mod keys;
pub mod onode;
mod recompact;
mod repair;
pub use repair::{RepairReport, refuse_engine};
mod shardio;
mod stage;
mod store;
pub mod txn;
mod upgrade_omap;

pub use check::CheckReport;
pub use defrag::DefragStats;
pub use recompact::{Census, RcStats};
pub use shardio::{CacheDropped, ShardStore};
pub use store::{
    CACHE_UNIT_BYTES, CollStats, CompCounters, DATA_FLOOR_BYTES, MIN_CACHE_PAGES, ObjStat,
    POINT_PER_UNIT, PRE_PIECE, PreTicket, QueueBuildContext, QueueBuilder, Queued, ScrubResult,
    ShardMountState, Store, StoreCfg, StoreStatfs, run_soft_for_pages, shard_of_spg,
};
pub use txn::{KvRunData, OTxn, TOp};
pub(crate) use upgrade_omap::{avail_blocks as upgrade_avail_blocks, blocks_of as upgrade_blocks};

use crate::error::StoreError;

/// Layout of a range of one object (adr 0593-dedup-deep-scrub-reformat, dedup-reformat.md 6), from its extent records.
/// `allocated`: physical bytes of the plain extents inside the range; compressed extents count whole (`stored_compressed`
/// logical, `allocated_compressed` physical); `allocated_shared`: physical bytes of extents that may be shared with a clone;
/// `frags`: disjoint physical intervals after merging. `cached` of the fork has no counterpart (the data version check
/// of the rewrite covers concurrent writes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpanStats {
    pub stored: u64,
    pub allocated: u64,
    pub stored_compressed: u64,
    pub allocated_compressed: u64,
    pub allocated_shared: u64,
    pub extents: u64,
    pub frags: u64,
}

/// Data state of one object (adr 0593-dedup-deep-scrub-reformat): while `tracking`, every data change bumps `dv`; the
/// triple (`id`, `dv_gen`, `dv`) names one data state on this store (a recreated object gets a new onode id, a
/// re-enabled tracking a new generation). Local to this store's copy: replicas differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataVersion {
    pub id: u64,
    pub dv_gen: u64,
    pub dv: u64,
    pub tracking: bool,
}

/// Object-layer error (errno-like).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjError {
    /// ENOENT: object missing.
    NoEnt,
    /// Collection missing.
    NoColl,
    /// EEXIST (collection).
    Exists,
    /// Collection not empty.
    NotEmpty,
    /// EIO: checksum mismatch or device/tree corruption; text says where.
    Eio(String),
    /// ENOSPC (also after the forced checkpoint).
    NoSpace,
    /// Txn does not fit one WAL unit / tree page budget; split it (PG layer, R11).
    TooLarge,
    /// Attr name / omap key / object name longer than the tree entry limit allows.
    NameTooLong,
    /// Collections of one txn live on different shards.
    CrossShard,
    /// The collection lives on a shard this (per-core) store did not mount: another core owns it.
    NotMounted(u32),
    Unsupported(&'static str),
    Invalid(String),
    /// Internal: a non-blocking probe (`Store::warm`) needs a tree page that is not resident (its read is already
    /// submitted). Never returned by any other API.
    WouldBlock,
    /// A reformat rewrite (`TOp::Reformat`, adr 0593-dedup-deep-scrub-reformat) no longer applies: the object changed
    /// since its data was read, or the new layout would not be better. Nothing was staged; never returned by any other op.
    Stale,
    /// Engine error that does not map to the above.
    Store(StoreError),
}

impl std::fmt::Display for ObjError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ObjError {}

impl From<StoreError> for ObjError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NoSpace => ObjError::NoSpace,
            StoreError::TxnTooLarge => ObjError::TooLarge,
            StoreError::Io(_) | StoreError::Corrupt(_) => ObjError::Eio(format!("{e:?}")),
            e => ObjError::Store(e),
        }
    }
}

/// Ordered key/value pairs.
pub type KvList = Vec<(Vec<u8>, Vec<u8>)>;

pub type Result<T> = std::result::Result<T, ObjError>;

/// Shared READ bytes and optional source-verified seed-0 CRCs on the returned
/// data's 4 KiB grid. `block_crcs` is present only when the store could derive
/// every full block from checksums it verified during this read; a partial
/// final block is checksummed from its bytes. `None` requires a later payload
/// pass or ordinary SEND. The parts retain the original backing by reference.
#[derive(Debug)]
pub struct SharedRead {
    pub parts: Vec<(bytes::Bytes, Option<u32>)>,
    pub block_crcs: Option<Vec<u32>>,
}
