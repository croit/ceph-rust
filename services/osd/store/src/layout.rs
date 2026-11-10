// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! On-disk layout (design section 3): superblock A/B, shard directory, per-shard region
//! `[root A][root B][WAL ring][meta][data]`, root slots. All structures crc32c-protected, little endian.

use crate::BLK;
use crate::alloc::MetaAlloc;
use crate::codec::{Dec, Enc, crc};
use crate::dev::{BlockDev, Clock};
use crate::error::{Result, StoreError};
use crate::sio::Sio;

pub const SB_MAGIC: &[u8; 8] = b"FLSTORE1";
pub const ROOT_MAGIC: u32 = 0x544f_4f52; // "ROOT"
/// Root slot with the omap run floor (adr 0476): `wal_tail_lsn` + `run_floor` follow `meta_pages_used`.
/// Written only when they differ from the plain form (`ckpt_lsn + 1` both), so a store without live runs keeps the old slot.
pub const ROOT_MAGIC2: u32 = 0x3254_4f52; // "RT2"
/// 2: `e` records may be windows of compressed chunks (`EXT_VIEW`, adr 0059 am. 4).
pub const FORMAT_VERSION: u32 = 2;
/// Incompatible feature bits (`Superblock::features`) this build understands. A store carrying any other bit, or another
/// `FORMAT_VERSION`, is refused at mount with `Corrupt("unsupported ...")` instead of being misread: a later build
/// that extends the format sets a bit here (or bumps the version) and older builds from this one on stop cleanly.
/// Elastic meta space (adr 0021 am. 12): tree pages also live in cells carved from the data region on demand and the
/// meta image is stored in meta pages (`alloc::blob_pack`); `Superblock::cell_pages` gives the cell size. Must be
/// durable before the first root slot that points at an elastic image.
pub const FEAT_ELASTIC_META: u64 = 1;
/// Compact interior pages (adr 0021 am. 13): new and rebuilt interior tree pages use page format 1 (front-coded
/// separators, 5-byte child addresses); pages of format 0 stay valid. Needs device addresses below 2^39 blocks.
pub const FEAT_COMPACT_INT: u64 = 2;
/// Small-object data stored inline in the tree (adr 0021 am. 14): onode flag `F_INLINE`, key tag `d`. An older build would
/// read such an object as holes, so the bit must be durable before the first inline write.
pub const FEAT_INLINE_DATA: u64 = 4;
/// Onode format 2 with exact omap key/byte counters (adr 0021 am. 15); older builds fail on such an onode. Since
/// `FEAT_OMAP_UNCOUNTED` no build writes the counters; still set by mkfs with the omap run format.
pub const FEAT_OMAP_COUNTERS: u64 = 8;
/// Lazy subtree free (adr 0021 am. 18): the elastic meta image carries a list of detached subtrees whose pages are still
/// allocated; an older build would never free them (leak) and refuse the image, so the bit must be durable first.
pub const FEAT_LAZY_FREE: u64 = 16;
/// Leaf deltas (adr 0021 am. 19): checkpoints may write lightly dirty leaves as deltas in `page::DELTA` pages, listed in
/// the meta image; an older build would read the stale base pages (silent loss of updates), so the bit must be durable
/// before the first delta. Needs `FEAT_ELASTIC_META`.
pub const FEAT_LEAF_DELTA: u64 = 32;
/// Device expand (adr 0021 am. 20): the superblock lists extents added behind the original shard regions (`Superblock::expand`);
/// every shard owns one more data extent per generation. An older build would not know them (allocations there read as
/// outside the region, capacity lost), so the bit must be durable before the first extent is used.
pub const FEAT_EXPAND: u64 = 64;
/// Lazy PG info (adr 0021 am. 27): no meaning for the store engine itself. With it the PG layer (storeadapt) may leave
/// the pgmeta `_info` / `_loghead` keys behind the log entries of client writes and rebuilds them from the log at load;
/// an older build would load the stale head and info (reused log versions), so it must refuse such a store.
pub const FEAT_LAZY_PGINFO: u64 = 128;
/// Long object names (adr 0021 am. 30): names whose `N` key exceeds the tree key limit live in the `L` name index. An older
/// build would not list those objects (its fsck calls the tag unknown), so the bit must be durable before the first `L`
/// key. Adding the bit rewrites no data: only names refused before use `L`.
pub const FEAT_LONG_NAME: u64 = 256;
/// Inline compression (adr 0059 am. 1): `e` extents may carry the COMPRESSED flag (logical span != physical length). An older
/// build would read the compressed payload as data, so the bit must be durable before the first such extent. Set only by the
/// first compressed write (`Store::queue`: durable before that txn is submitted); mkfs and mount never add it, so a store
/// without compressed data stays mountable by an older build. Sticky: `read_super` / `heal_super` never drop it.
pub const FEAT_COMPRESSION: u64 = 512;
/// Shared extents (adr 0021 am. 32): snapshot clones reference the source's data blocks; `e` extents may carry `EXT_SHARED`
/// and `r` refcount records exist. An older build would free a block still owned by another object, so the bit must be
/// durable before the first shared extent. Gated like the other format bits (adr 0021 am. 22): mkfs sets it;
/// a store without it never shares (clones copy), so it stays
/// mountable by an older build. Stores that got it at first use (am. 32 as first shipped) keep it: sticky.
pub const FEAT_SHARED_EXT: u64 = 1024;
/// Omap / xattr / header values of at least `ShardCfg::val_ext_min` bytes live in data blocks (adr 0021 am. 46): record form
/// `[2][len][extent]`, onode flags `F_OEXT`/`F_AEXT`/`F_HEXT`. An older build would read such a record as corrupt and leak
/// its blocks. Set by mkfs only (format change of am. 46: fresh mkfs); a store without it never
/// writes the form.
pub const FEAT_EXT_VALUE: u64 = 2048;
/// User omap values (counted objects; not PG logs) of at least `ShardCfg::val_comp_min` bytes may be stored zstd-compressed inline (adr 0021 am. 58, 59):
/// record form `[5][class][len][zstd block]` against the shard's trained class dictionaries (tree keys `Z` + class). An older build would read it as corrupt.
/// mkfs only; a store without it never writes the form. Bit 8192 was the LZ4 form of am. 58 as first shipped (retired: such a store is refused, re-mkfs).
pub const FEAT_VAL_COMP: u64 = 16384;
/// Chunk-table data regions (adr 0021 am. 47, elastic shards step 1): each shard owns `base_pct` % of its data space as whole
/// `chunk_blocks` chunks (superblock fields); the rest is unowned (future shared pool). Mkfs only, needs the cargo feature
/// `elastic`; a build without it refuses such a store (re-mkfs).
pub const FEAT_CHUNKED: u64 = 4096;
/// Omap batch runs (adr 0476): WAL record ops `RunPut` / `RunMerge` (tags 4, 5), root slot form 2 (WAL
/// floor). An older build cannot replay such a WAL. Set by mkfs with `FEAT_OMAP_COUNTERS`
/// (the only omap format; required).
pub const FEAT_OMAP_RUNS: u64 = 32768;
/// Leaf-delta segment cleaning (adr 0021 am. 65): a delta entry may carry the restart flag (`delta::RESTART`, bit 31
/// of its length) of a relogged chain; an older build reads such an entry as malformed. Set by mkfs with
/// `FEAT_LEAF_DELTA`.
pub const FEAT_DELTA_RELOG: u64 = 65536;
/// Blind omap writes (adr 0476 am. 5): WAL record ops tags 6 and 7, an omap key removal / put whose counter delta the
/// apply took into the object's `c` record. An older build cannot replay such a WAL. Set by mkfs with `FEAT_OMAP_RUNS`;
/// since `FEAT_OMAP_UNCOUNTED` no build writes the tags (replay reads them as a plain removal / put).
pub const FEAT_OMAP_BLIND: u64 = 131072;
/// Dedup pipeline state (adr 0593-dedup-deep-scrub-reformat): onode format 4 (`F_DVER`, data version), collection format 3
/// (tracking state) and dedup records (tag `D`). An older build would refuse those records as corrupt, so the bit must be
/// durable before the first of them: set when data version tracking is first switched on (`Store::queue`), never by mkfs
/// or mount, so a store without dedup use stays mountable by an older build. Sticky like `FEAT_COMPRESSION`.
pub const FEAT_DEDUP: u64 = 262144;
/// Omap LSM engine (adr 0610): user omap keys live in the shard's olsm runs instead of the tree: WAL record ops tags
/// 8-10 (`Op::Omap`), run manifest records (tree tag `l`). An older build can neither replay such a WAL nor see the
/// omap. Mkfs only (`MkfsParams::omap_lsm`, default off during phase 2).
pub const FEAT_OMAP_LSM: u64 = 524288;
/// An offline format upgrade step is in progress (adr 0611): `Superblock::upgrading` names it. Incompatible: no build
/// mounts the store for service until `croit-flashstore-tool upgrade` finished the step (`crate::upgrade`); older builds refuse
/// the unknown bit.
pub const FEAT_UPGRADING: u64 = 1 << 20;
/// Kernel passthrough (cmd) namespace: the mkfs DSM probe verdict is stored (`Superblock::dsm_verdict`, adr 0169 am. 8). Set by
/// mkfs only when a verdict was probed. Incompatible: an older build refuses the store instead of running its own DSM probe
/// on open. Without the bit the verdict is unknown: the namespace runs without runtime deallocate.
pub const FEAT_DSM_VERDICT: u64 = 1 << 21;
/// PG log dup records live in the retained log keys (adr/0634-pg-log-dups-from-retained-entries): a PG trim keeps the trimmed entries' log keys
/// below the tail as the dup records of the window (the loader derives them) instead of writing one dup key per entry.
/// An older build would load those keys as live log entries and lose dup detection (a resent op could apply twice), so
/// it must refuse the store. Set by every mount for service (sticky, `Store::mount_shards`): durable before the store
/// takes any txn, so no PG core waits for a superblock write at its first trim (adr 0634).
pub const FEAT_LOG_DUPS: u64 = 1 << 22;
/// Omap keeps no per-object counters (adr 0647-omap-blind-removals): onode counters (`F_OCNT`) and `c` records are
/// neither written nor read; a mount removes the `c` records an earlier build left (`Store::drop_counter_records`) and
/// `Onode::decode` drops the onode counters. An older build would read stale counters (its check reports them, its
/// blind ops add to them), so it must refuse the store. Set by mkfs and by every mount (sticky): durable before the
/// first uncounted txn.
pub const FEAT_OMAP_UNCOUNTED: u64 = 1 << 23;
/// Omap runs may hold removal entries (adr 0647-omap-blind-removals D1, `runs::is_tomb`: an empty value record): a client
/// removal batch is logged as one run of removals. An older build would read a removal as a value (an empty value
/// record: undecodable, merged into the tree as a value), so it must refuse the store. Set by mkfs and by every mount
/// (sticky): durable before the first txn.
pub const FEAT_OMAP_TOMBS: u64 = 1 << 24;
/// Actual RocksDB OMAP base, with native logical OMAP WAL operations. Distinct
/// incompatible identity: an older/native-only build must not interpret it as LSM.
pub const FEAT_OMAP_ROCKSDB: u64 = 1 << 25;
/// Independent file-backed SplinterDB OMAP. Old/feature-disabled binaries refuse.
pub const FEAT_OMAP_SPLINTERDB: u64 = 1 << 26;
/// Pinned library has 64 registered thread slots; reserve one for provisioning.
/// This bounds only the optional foreign engine, not native shard/core routing.
pub const MAX_SPLINTERDB_SHARDS: u32 = 63;
/// Bits set after mkfs (at first use or at mount, by any core): `read_super` / `heal_super` keep them when either copy has
/// them.
pub const FEATURES_STICKY: u64 = FEAT_COMPRESSION
    | FEAT_SHARED_EXT
    | FEAT_DEDUP
    | FEAT_LOG_DUPS
    | FEAT_OMAP_UNCOUNTED
    | FEAT_OMAP_TOMBS;
/// Most expansions one store takes (the list sits in the superblock block).
pub const MAX_EXPANSIONS: usize = 64;
/// Extents are whole multiples of this many blocks per shard (16 MiB).
pub const EXPAND_UNIT: u64 = 4096;
pub const FEATURES_KNOWN: u64 = FEAT_ELASTIC_META
    | FEAT_COMPACT_INT
    | FEAT_INLINE_DATA
    | FEAT_OMAP_COUNTERS
    | FEAT_LAZY_FREE
    | FEAT_LEAF_DELTA
    | FEAT_EXPAND
    | FEAT_LAZY_PGINFO
    | FEAT_LONG_NAME
    | FEAT_COMPRESSION
    | FEAT_SHARED_EXT
    | FEAT_EXT_VALUE
    | FEAT_VAL_COMP
    | FEAT_OMAP_RUNS
    | FEAT_DELTA_RELOG
    | FEAT_OMAP_BLIND
    | FEAT_DEDUP
    | FEAT_OMAP_LSM
    | FEAT_UPGRADING
    | FEAT_DSM_VERDICT
    | FEAT_LOG_DUPS
    | FEAT_OMAP_UNCOUNTED
    | FEAT_OMAP_TOMBS
    | if cfg!(feature = "rocksdb") {
        FEAT_OMAP_ROCKSDB
    } else {
        0
    }
    | if cfg!(feature = "splinterdb") {
        FEAT_OMAP_SPLINTERDB
    } else {
        0
    }
    | if cfg!(feature = "elastic") {
        FEAT_CHUNKED
    } else {
        0
    };
const DIR_ENTRY: usize = 128;
/// Entries per lending-table block (adr 0021 am. 49; format in `lend`).
pub const LEND_EPB: u64 = 509;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Superblock {
    pub version: u32,
    pub features: u64,
    pub osd_fsid: [u8; 16],
    pub osd_id: i32,
    pub cluster_fsid: [u8; 16],
    pub lba_size: u32,
    pub size_bytes: u64,
    pub nsid: u32,
    /// AWUPF/AWUN seen at mkfs (informational; correctness never depends on them).
    pub awupf_lbas: u32,
    pub awun_lbas: u32,
    /// Device attested power-loss-protected (VWC absent) or lab override given.
    pub plp: bool,
    pub shards: u32,
    pub node_size: u32,
    pub wal_blocks: u64,
    pub meta_pct: u32,
    pub dir_blk: u64,
    pub dir_blocks: u32,
    pub dir_crc: u32,
    pub mkfs_time: u64,
    /// Pages per elastic meta cell (stored only with `FEAT_ELASTIC_META`, else 0).
    pub cell_pages: u32,
    /// Device expansions in order (only with `FEAT_EXPAND`).
    pub expand: Vec<Expansion>,
    /// Chunked store (only with `FEAT_CHUNKED`, else 0): percent of the data space owned as base chunks, chunk size in blocks.
    pub base_pct: u32,
    pub chunk_blocks: u64,
    /// Id of the offline upgrade step in progress (`crate::upgrade::Step::id`; stored only with `FEAT_UPGRADING`, else 0).
    pub upgrading: u32,
    /// Passthrough DSM accepted (`Some(true)`) or rejected (`Some(false)`) by the mkfs probe (stored only with
    /// `FEAT_DSM_VERDICT`, else `None` = unknown).
    pub dsm_verdict: Option<bool>,
}

/// One device expand: shard `s` owns blocks `start + s * per_shard .. + per_shard` as an extra data extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expansion {
    pub start: u64,
    pub per_shard: u64,
}

impl Superblock {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.bytes(SB_MAGIC).u32(self.version).u64(self.features);
        e.bytes(&self.osd_fsid)
            .u32(self.osd_id as u32)
            .bytes(&self.cluster_fsid);
        e.u32(self.lba_size)
            .u64(self.size_bytes)
            .u32(self.nsid)
            .u32(self.awupf_lbas)
            .u32(self.awun_lbas);
        e.u8(self.plp as u8)
            .u32(self.shards)
            .u32(self.node_size)
            .u64(self.wal_blocks)
            .u32(self.meta_pct);
        e.u64(self.dir_blk)
            .u32(self.dir_blocks)
            .u32(self.dir_crc)
            .u64(self.mkfs_time);
        if self.features & FEAT_ELASTIC_META != 0 {
            e.u32(self.cell_pages);
        }
        if self.features & FEAT_EXPAND != 0 {
            e.u32(self.expand.len() as u32);
            for x in &self.expand {
                e.u64(x.start).u64(x.per_shard);
            }
        }
        if self.features & FEAT_CHUNKED != 0 {
            e.u32(self.base_pct).u64(self.chunk_blocks);
        }
        if self.features & FEAT_UPGRADING != 0 {
            e.u32(self.upgrading);
        }
        if self.features & FEAT_DSM_VERDICT != 0 {
            // 2 = no verdict under the bit: decode refuses it (mkfs sets the bit only with a verdict)
            e.u8(self.dsm_verdict.map_or(2, u8::from));
        }
        let c = crc(&e.b);
        e.u32(c);
        e.pad_to(BLK);
        e.b
    }

    /// `(version, features)` of a copy a newer build wrote (format version above this build's or an unknown feature
    /// bit) in a layout this build may not decode: fields behind an unknown bit move the crc. The copy is intact when
    /// the crc that ends its encoding (followed by zero padding) verifies; a copy whose version or feature field only
    /// rotted has no such crc and stays a damaged copy.
    fn newer(b: &[u8]) -> Option<(u32, u64)> {
        let mut d = Dec::new(b);
        if d.bytes(8)? != SB_MAGIC {
            return None;
        }
        let (version, features) = (d.u32()?, d.u64()?);
        if version <= FORMAT_VERSION && features & !FEATURES_KNOWN == 0 {
            return None;
        }
        // the crc ends where the zero padding starts, or up to 4 bytes later (zero high bytes of the crc itself)
        let z = b.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
        (z.saturating_sub(4).max(d.pos)..=z)
            .filter(|&p| p + 4 <= b.len())
            .any(|p| u32::from_le_bytes(b[p..p + 4].try_into().unwrap()) == crc(&b[..p]))
            .then_some((version, features))
    }

    fn decode(b: &[u8]) -> Option<Superblock> {
        let mut d = Dec::new(b);
        if d.bytes(8)? != SB_MAGIC {
            return None;
        }
        let mut sb = Superblock {
            version: d.u32()?,
            features: d.u64()?,
            osd_fsid: d.arr16()?,
            osd_id: d.u32()? as i32,
            cluster_fsid: d.arr16()?,
            lba_size: d.u32()?,
            size_bytes: d.u64()?,
            nsid: d.u32()?,
            awupf_lbas: d.u32()?,
            awun_lbas: d.u32()?,
            plp: d.u8()? != 0,
            shards: d.u32()?,
            node_size: d.u32()?,
            wal_blocks: d.u64()?,
            meta_pct: d.u32()?,
            dir_blk: d.u64()?,
            dir_blocks: d.u32()?,
            dir_crc: d.u32()?,
            mkfs_time: d.u64()?,
            cell_pages: 0,
            expand: Vec::new(),
            base_pct: 0,
            chunk_blocks: 0,
            upgrading: 0,
            dsm_verdict: None,
        };
        if sb.features & FEAT_ELASTIC_META != 0 {
            sb.cell_pages = d.u32()?;
        }
        if sb.features & FEAT_EXPAND != 0 {
            let n = d.u32()? as usize;
            if n > MAX_EXPANSIONS {
                return None;
            }
            for _ in 0..n {
                sb.expand.push(Expansion {
                    start: d.u64()?,
                    per_shard: d.u64()?,
                });
            }
        }
        if sb.features & FEAT_CHUNKED != 0 {
            sb.base_pct = d.u32()?;
            sb.chunk_blocks = d.u64()?;
            if !(10..=90).contains(&sb.base_pct) || !sb.chunk_blocks.is_power_of_two() {
                return None;
            }
        }
        if sb.features & FEAT_UPGRADING != 0 {
            sb.upgrading = d.u32()?;
            if sb.upgrading == 0 {
                return None;
            }
        }
        if sb.features & FEAT_DSM_VERDICT != 0 {
            sb.dsm_verdict = match d.u8()? {
                0 => Some(false),
                1 => Some(true),
                _ => return None,
            };
        }
        let end = d.pos;
        if d.u32()? != crc(&b[..end]) {
            return None;
        }
        Some(sb)
    }
}

/// One shard's regions (engine block addresses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardDir {
    pub shard: u32,
    pub region_start: u64,
    pub region_blocks: u64,
    pub root_a: u64,
    pub root_b: u64,
    pub wal_start: u64,
    pub wal_blocks: u64,
    pub meta_start: u64,
    pub meta_blocks: u64,
    pub data_start: u64,
    pub data_blocks: u64,
    /// Extra data extents `(first block, blocks)` of device expansions (derived from the superblock, not stored here).
    pub ext: Vec<(u64, u64)>,
    /// Chunk size in blocks of a chunked store (derived from the superblock, not stored here; 0 = plain region).
    pub chunk_blocks: u64,
    /// Borrowed chunks of a chunked store by slot (engine block or `alloc::HOLE`; derived from the lending table, adr 0021 am. 49).
    #[cfg(feature = "elastic")]
    pub lent: Vec<u64>,
}

impl ShardDir {
    /// Data blocks including the expansion extents.
    pub fn data_total(&self) -> u64 {
        self.data_blocks + self.ext.iter().map(|e| e.1).sum::<u64>()
    }

    /// Is `blk..blk+n` inside one data extent of this shard?
    pub fn in_data(&self, blk: u64, n: u64) -> bool {
        let inside =
            |s: u64, len: u64| blk.checked_sub(s).is_some_and(|r| r <= len && n <= len - r);
        #[cfg(feature = "elastic")]
        if self
            .lent
            .iter()
            .any(|&p| p != crate::alloc::HOLE && inside(p, self.chunk_blocks))
        {
            return true;
        }
        inside(self.data_start, self.data_blocks) || self.ext.iter().any(|e| inside(e.0, e.1))
    }

    /// The data block allocator of this shard (empty: nothing allocated).
    pub fn new_alloc(&self) -> crate::alloc::Alloc {
        #[cfg(feature = "elastic")]
        if let Some(nc) = self.data_blocks.checked_div(self.chunk_blocks) {
            let phys: Vec<u64> = (0..nc)
                .map(|i| self.data_start + i * self.chunk_blocks)
                .collect();
            return crate::alloc::Alloc::with_lent(&phys, &self.lent, self.chunk_blocks);
        }
        crate::alloc::Alloc::with_extents(self.data_start, self.data_blocks, &self.ext)
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        let start = e.b.len();
        e.u32(self.shard)
            .u64(self.region_start)
            .u64(self.region_blocks)
            .u64(self.root_a)
            .u64(self.root_b);
        e.u64(self.wal_start)
            .u64(self.wal_blocks)
            .u64(self.meta_start)
            .u64(self.meta_blocks);
        e.u64(self.data_start).u64(self.data_blocks);
        let n = e.b.len() - start;
        e.bytes(&vec![0; DIR_ENTRY - n]);
    }
    fn decode(d: &mut Dec) -> Option<ShardDir> {
        let s = d.pos;
        let r = ShardDir {
            shard: d.u32()?,
            region_start: d.u64()?,
            region_blocks: d.u64()?,
            root_a: d.u64()?,
            root_b: d.u64()?,
            wal_start: d.u64()?,
            wal_blocks: d.u64()?,
            meta_start: d.u64()?,
            meta_blocks: d.u64()?,
            data_start: d.u64()?,
            data_blocks: d.u64()?,
            ext: Vec::new(),
            chunk_blocks: 0,
            #[cfg(feature = "elastic")]
            lent: Vec::new(),
        };
        d.bytes(DIR_ENTRY - (d.pos - s))?;
        Some(r)
    }
}

/// Per-shard root slot (one 4 KiB block, two per shard, slot = seq & 1). Tree root, meta bitmap
/// location and counters describe the checkpoint at `ckpt_lsn`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RootSlot {
    pub shard: u32,
    pub seq: u64,
    pub epoch: u32,
    /// All WAL records with lsn <= ckpt_lsn are reflected in the checkpointed state (replay starts after).
    pub ckpt_lsn: u64,
    /// Ring block index of the first unit to replay and the crc of the unit preceding it (chain seed).
    pub wal_tail_pos: u64,
    pub wal_tail_prev_crc: u32,
    pub tree_root: u64,
    pub tree_crc: u32,
    pub tree_height: u8,
    pub meta_bitmap_addr: u64,
    pub meta_bitmap_len: u32,
    pub meta_bitmap_crc: u32,
    pub next_onode_id: u64,
    pub used_blocks: u64,
    pub meta_pages_used: u64,
    /// First lsn of the unit at `wal_tail_pos` (replay chain start): `ckpt_lsn + 1` unless live omap runs hold older units
    /// (adr 0476). 0 = plain form.
    pub wal_tail_lsn: u64,
    /// Lsn of the oldest omap run live at `ckpt_lsn` (`ckpt_lsn + 1` = none): replay rebuilds the runs from the records in
    /// `[run_floor, ckpt_lsn]`. 0 = plain form.
    pub run_floor: u64,
}

impl RootSlot {
    /// Replay chain start (the plain form when not recorded).
    pub fn tail_lsn(&self) -> u64 {
        if self.wal_tail_lsn == 0 {
            self.ckpt_lsn.saturating_add(1)
        } else {
            self.wal_tail_lsn
        }
    }
    /// Omap run floor (the plain form when not recorded).
    pub fn floor(&self) -> u64 {
        if self.run_floor == 0 {
            self.ckpt_lsn.saturating_add(1)
        } else {
            self.run_floor
        }
    }

    /// Root reference `(addr, crc, height)` of the checkpointed tree (`None` = no tree yet). A root address without a
    /// height is refused: the tree's page level is `height - 1`, and no reader may compute it from height 0.
    pub fn tree_ref(&self) -> std::result::Result<Option<(u64, u32, u8)>, &'static str> {
        if self.tree_root == 0 {
            return Ok(None);
        }
        if self.tree_height == 0 {
            return Err("tree root with height 0");
        }
        Ok(Some((self.tree_root, self.tree_crc, self.tree_height)))
    }

    pub fn encode(&self) -> Vec<u8> {
        let next = self.ckpt_lsn.saturating_add(1);
        let plain = self.tail_lsn() == next && self.floor() == next;
        let mut e = Enc::new();
        e.u32(if plain { ROOT_MAGIC } else { ROOT_MAGIC2 })
            .u32(self.shard)
            .u64(self.seq)
            .u32(self.epoch)
            .u64(self.ckpt_lsn);
        e.u64(self.wal_tail_pos).u32(self.wal_tail_prev_crc);
        e.u64(self.tree_root)
            .u32(self.tree_crc)
            .u8(self.tree_height);
        e.u64(self.meta_bitmap_addr)
            .u32(self.meta_bitmap_len)
            .u32(self.meta_bitmap_crc);
        e.u64(self.next_onode_id)
            .u64(self.used_blocks)
            .u64(self.meta_pages_used);
        if !plain {
            e.u64(self.wal_tail_lsn).u64(self.run_floor);
        }
        let c = crc(&e.b);
        e.u32(c);
        e.pad_to(BLK);
        e.b
    }

    pub fn decode(b: &[u8]) -> Option<RootSlot> {
        let mut d = Dec::new(b);
        let m = d.u32()?;
        if m != ROOT_MAGIC && m != ROOT_MAGIC2 {
            return None;
        }
        let mut r = RootSlot {
            shard: d.u32()?,
            seq: d.u64()?,
            epoch: d.u32()?,
            ckpt_lsn: d.u64()?,
            wal_tail_pos: d.u64()?,
            wal_tail_prev_crc: d.u32()?,
            tree_root: d.u64()?,
            tree_crc: d.u32()?,
            tree_height: d.u8()?,
            meta_bitmap_addr: d.u64()?,
            meta_bitmap_len: d.u32()?,
            meta_bitmap_crc: d.u32()?,
            next_onode_id: d.u64()?,
            used_blocks: d.u64()?,
            meta_pages_used: d.u64()?,
            wal_tail_lsn: 0,
            run_floor: 0,
        };
        // no slot exists past the last representable lsn: a value whose `+ 1` wraps is a damaged copy (its replay
        // chain start would wrap with it)
        let next = r.ckpt_lsn.checked_add(1)?;
        if m == ROOT_MAGIC2 {
            r.wal_tail_lsn = d.u64()?;
            r.run_floor = d.u64()?;
            if r.run_floor > next || r.wal_tail_lsn > r.run_floor.min(next) {
                return None;
            }
        } else {
            (r.wal_tail_lsn, r.run_floor) = (next, next);
        }
        let end = d.pos;
        (d.u32()? == crc(&b[..end])).then_some(r)
    }
}

/// Meta region carve-up: `[bitmap A][bitmap B][tree pages...]` (engine block addresses). Pages are `node_size`
/// bytes; the bitmap of used pages is rewritten wholesale at every checkpoint, alternating A/B.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaGeom {
    /// Blocks per tree page.
    pub bpp: u64,
    pub npages: u32,
    pub bm_a: u64,
    pub bm_b: u64,
    pub bm_blocks: u32,
    pub pages_start: u64,
}

impl MetaGeom {
    pub fn new(dir: &ShardDir, node_size: u32) -> Result<MetaGeom> {
        let ns = node_size as u64;
        if ns < BLK as u64 || ns > 32768 || !ns.is_power_of_two() {
            return Err(StoreError::BadGeometry(format!("node size {node_size}")));
        }
        let bpp = ns / BLK as u64;
        let first = (dir.meta_blocks / bpp) as u32;
        let bm_blocks = (crate::alloc::MetaAlloc::bytes_needed(first) / BLK) as u32;
        let rest = dir.meta_blocks.saturating_sub(2 * bm_blocks as u64);
        let npages = (rest / bpp) as u32;
        if npages < 8 {
            return Err(StoreError::BadGeometry("meta region too small".into()));
        }
        Ok(MetaGeom {
            bpp,
            npages,
            bm_a: dir.meta_start,
            bm_b: dir.meta_start + bm_blocks as u64,
            bm_blocks,
            pages_start: dir.meta_start + 2 * bm_blocks as u64,
        })
    }
    /// Blocks of one elastic meta cell of `cell_pages` pages: one allocator extent, so at most `u32::MAX` blocks.
    pub fn cell_blocks(&self, cell_pages: u32) -> Result<u64> {
        let blocks = u64::from(cell_pages) * self.bpp;
        if blocks > u64::from(u32::MAX) {
            return Err(StoreError::BadGeometry(
                "metadata cell exceeds allocator extent limit".into(),
            ));
        }
        Ok(blocks)
    }
    pub fn page_addr(&self, idx: u32) -> u64 {
        self.pages_start + idx as u64 * self.bpp
    }
    /// Page index of a valid page address.
    pub fn page_idx(&self, addr: u64) -> Option<u32> {
        let r = addr.checked_sub(self.pages_start)?;
        (r % self.bpp == 0 && r / self.bpp < self.npages as u64).then_some((r / self.bpp) as u32)
    }
}

/// Chain seed for the first WAL unit after mkfs: binds units to this filesystem instance so units left by a
/// previous mkfs on the same device never validate.
pub fn wal_chain_seed(osd_fsid: &[u8; 16], shard: u32) -> u32 {
    let mut e = Enc::new();
    e.bytes(osd_fsid).u32(shard).bytes(b"wal");
    crc(&e.b)
}

/// Identity stamped into every WAL unit header (see `UnitHeader::store_id`); never 0.
pub fn wal_store_id(sb: &Superblock, shard: u32) -> u32 {
    let mut e = Enc::new();
    e.bytes(&sb.osd_fsid)
        .u32(shard)
        .u64(sb.mkfs_time)
        .bytes(b"wal-id");
    crc(&e.b).max(1)
}

/// Upper bound of `MkfsParams::shards` (any count `1..=MAX_SHARDS`, not only powers of two: adr 0160).
pub const MAX_SHARDS: u32 = 256;
/// WAL ring sizing (adr 0160 am. 4): the device's total WAL budget is `min(WAL_TOTAL_MAX, device / WAL_TOTAL_DIV)`, split
/// evenly over the shards, each ring clamped to `WAL_RING_MIN..=WAL_RING_MAX` bytes. 4 GiB total: measured clean (IOPS,
/// tails, no ring-full) down to 0.5 GiB at 8 shards (doc/perf/wal-size-20261017.md); was 32 GiB.
pub const WAL_TOTAL_MAX: u64 = 4 << 30;
pub const WAL_TOTAL_DIV: u64 = 64;
pub const WAL_RING_MIN: u64 = 64 << 20;
pub const WAL_RING_MAX: u64 = 4 << 30;

/// WAL ring blocks per shard for a device of `bytes` with `shards` shards (see [`WAL_TOTAL_MAX`]).
pub fn wal_blocks_for(bytes: u64, shards: u32) -> u64 {
    let total = (bytes / WAL_TOTAL_DIV).min(WAL_TOTAL_MAX);
    (total / u64::from(shards.max(1))).clamp(WAL_RING_MIN, WAL_RING_MAX) / BLK as u64
}

/// Region alignment of production devices (64 MiB).
pub const PROD_ALIGN_BLOCKS: u64 = 16_384;
/// Default `store_base_pct` of production devices (adr 0021 am. 55): 25 % of each shard's data space is static, the rest is the shared pool.
pub const PROD_BASE_PCT: u32 = 25;

/// Base meta area cap per shard of a production device: 1/1024 of the shard's share (about 0.1 % of the device) but at
/// least 64 MiB; tree pages beyond it come from elastic cells (adr 0021 am. 12) instead of a fixed 1 % of the drive.
pub fn meta_base_cap(bytes: u64, shards: u32) -> u64 {
    (bytes / BLK as u64 / u64::from(shards.max(1)) / 1024).max(16_384)
}

impl MkfsParams {
    /// Parameters for a device of `bytes` with `shards` shards: production-size devices (>= 256 GiB) get 1 GiB
    /// region alignment, smaller (lab) devices 1 MiB and a larger initial meta area; WAL rings per [`wal_blocks_for`].
    pub fn for_device(bytes: u64, shards: u32) -> MkfsParams {
        let lab = bytes < 256 << 30;
        MkfsParams {
            shards,
            wal_blocks: wal_blocks_for(bytes, shards),
            // 64 MiB regions: 1 GiB wasted up to one GiB per shard (28 GiB = 1.5 % of a 1.92 TB drive at 32 shards, adr 0021 am. 54)
            align_blocks: if lab { 256 } else { PROD_ALIGN_BLOCKS },
            // elastic: only the initial base area; tree pages beyond it come from the data region (am. 12)
            meta_pct: if lab { 2 } else { 1 },
            // production: the base area is only the start of the elastic meta space (cells follow on demand)
            meta_max_blocks: if lab {
                u64::MAX
            } else {
                meta_base_cap(bytes, shards)
            },
            // elastic shard capacity default (adr 0021 am. 55): production devices get the chunked store with the shared pool
            chunked: cfg!(feature = "elastic") && !lab,
            base_pct: PROD_BASE_PCT,
            ..MkfsParams::default()
        }
    }
}

/// `store_shards` setting: `auto` (one shard per configured OSD core) or an explicit count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreShards {
    Auto,
    Count(u32),
}

impl StoreShards {
    /// `"auto"` or `1..=MAX_SHARDS`.
    pub fn parse(s: &str) -> std::result::Result<StoreShards, String> {
        match s.trim() {
            "auto" => Ok(StoreShards::Auto),
            v => match v.parse::<u32>() {
                Ok(n) if (1..=MAX_SHARDS).contains(&n) => Ok(StoreShards::Count(n)),
                _ => Err(format!("store_shards {v:?}: auto or 1..={MAX_SHARDS}")),
            },
        }
    }

    /// The shard count for an OSD that runs on `cores` cores.
    pub fn resolve(self, cores: usize) -> u32 {
        match self {
            StoreShards::Auto => (cores as u32).clamp(1, MAX_SHARDS),
            StoreShards::Count(n) => n,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MkfsParams {
    pub shards: u32,
    pub wal_blocks: u64,
    pub meta_pct: u32,
    /// Cap of the base meta area per shard in blocks (elastic meta only; `u64::MAX` = none, adr 0021 am. 54).
    pub meta_max_blocks: u64,
    /// Region alignment in blocks (design: 1 GiB = 262144; tests use small values).
    pub align_blocks: u64,
    pub osd_fsid: [u8; 16],
    pub cluster_fsid: [u8; 16],
    pub osd_id: i32,
    pub nsid: u32,
    pub node_size: u32,
    /// Lab only: accept a device with volatile write cache.
    pub allow_volatile_cache: bool,
    /// Passthrough DSM probe verdict of the device (`FEAT_DSM_VERDICT`); `None` = not probed (no bit).
    pub dsm_verdict: Option<bool>,
    pub mkfs_time: u64,
    /// Elastic meta space (default): `meta_pct` is only the initial base area, tree pages beyond it come from the
    /// data region in cells on demand. `false` = the legacy fixed meta region (tests, comparison).
    pub elastic_meta: bool,
    /// Pages per meta cell; 0 = `cell_pages_for`.
    pub cell_pages: u32,
    /// Chunk-table data regions (default off, cargo feature `elastic`, adr 0021 am. 47): each shard owns `base_pct` % of its data space
    /// as whole chunks of `chunk_blocks` (power of two; default 1 GiB), the rest stays unowned.
    pub chunked: bool,
    pub base_pct: u32,
    pub chunk_blocks: u64,
    /// Lab: format only the first `max_bytes` of the device (default: all). The superblock records the formatted size.
    pub max_bytes: u64,
    /// Compact interior tree pages (default; needs a device below 2 PiB). `false` = format 0 interior pages only.
    pub compact_int: bool,
    /// Allow small-object data inline in the tree (default; the threshold is a run-time setting, `ShardCfg::inline_max`).
    pub inline_data: bool,
    /// The omap batch run format (adr 0476: `FEAT_OMAP_COUNTERS`, `FEAT_OMAP_RUNS`, `FEAT_OMAP_BLIND`; default).
    /// `false` = an older format (tests of the required-feature gate).
    pub omap_runs: bool,
    /// Lazy subtree free (default; needs `elastic_meta`).
    pub lazy_free: bool,
    /// Leaf deltas (default; needs `elastic_meta`).
    pub leaf_delta: bool,
    /// Leaf-delta segment cleaning by relog (default; needs `leaf_delta`; `FEAT_DELTA_RELOG`). Without it the oldest
    /// segments are only freed by folding their chains back into whole leaves.
    pub delta_relog: bool,
    /// Lazy PG info (default; `FEAT_LAZY_PGINFO`).
    pub lazy_pginfo: bool,
    /// Long object names (default; `FEAT_LONG_NAME`).
    pub long_names: bool,
    /// Shared extents for snapshot clones (default; `FEAT_SHARED_EXT`).
    pub shared_ext: bool,
    /// Large omap / xattr values in data blocks (default; `FEAT_EXT_VALUE`, adr 0021 am. 46).
    pub ext_values: bool,
    /// zstd-compressed inline user omap values with trained per-class dictionaries (counted objects; not PG logs) (default; `FEAT_VAL_COMP`, adr 0021 am. 59).
    pub val_comp: bool,
    /// Omap LSM engine (`FEAT_OMAP_LSM`, adr 0610; default off).
    pub omap_lsm: bool,
    /// Actual RocksDB as the OMAP engine. Requires an external identity-bound DB
    /// initialized by provisioning; never converts an existing native engine.
    pub omap_rocksdb: bool,
    /// Fresh stores only; also selects the native logical OMAP WAL representation.
    pub omap_splinterdb: bool,
}

/// Default elastic cell size: about 1 MiB of tree pages (a multiple of 64 pages), at most 1/64 of a shard's pages.
pub fn cell_pages_for(node_size: u32, region_blocks: u64) -> u32 {
    let bpp = node_size as u64 / BLK as u64;
    let target = ((1u64 << 20) / node_size as u64).max(64);
    let cap = (region_blocks / bpp / 64).max(1);
    let cap = 1u64 << (63 - cap.leading_zeros());
    target.min(cap).max(64) as u32
}

impl Default for MkfsParams {
    fn default() -> Self {
        MkfsParams {
            shards: 32,
            wal_blocks: 262_144, // 1 GiB
            meta_pct: 1,         // elastic: initial base area only (adr 0021 am. 12)
            meta_max_blocks: u64::MAX,
            align_blocks: 262_144,
            osd_fsid: [0; 16],
            cluster_fsid: [0; 16],
            osd_id: 0,
            nsid: 1,
            node_size: 8192,
            allow_volatile_cache: false,
            dsm_verdict: None,
            mkfs_time: 0,
            elastic_meta: true,
            compact_int: true,
            inline_data: true,
            omap_runs: true,
            lazy_free: true,
            leaf_delta: true,
            delta_relog: true,
            lazy_pginfo: true,
            long_names: true,
            shared_ext: true,
            ext_values: true,
            val_comp: true,
            omap_lsm: false,
            omap_rocksdb: false,
            omap_splinterdb: false,
            cell_pages: 0,
            chunked: false,
            base_pct: 75,
            chunk_blocks: 262_144, // 1 GiB
            max_bytes: u64::MAX,
        }
    }
}

fn align_up(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

/// Blocks of the shard directory holding `shards` entries: mkfs writes it, the mount check requires exactly it.
fn dir_blocks_for(shards: u32) -> u32 {
    (shards as usize * DIR_ENTRY).div_ceil(BLK) as u32
}

/// Shortest WAL ring mkfs writes (mkfs rule, [`plan`]): a mount refuses a shorter one (the ring arithmetic divides by it).
const WAL_BLOCKS_MIN: u64 = 64;

/// The shard directory in its on-disk form: entries back to back, zero-padded to a length of `bytes`.
fn encode_dir(dirs: &[ShardDir], bytes: usize) -> Vec<u8> {
    let mut e = Enc::new();
    dirs.iter().for_each(|d| d.encode(&mut e));
    e.pad_to(bytes);
    e.b
}

/// Compute the layout (pure).
pub fn plan(total_blocks: u64, p: &MkfsParams) -> Result<(Superblock, Vec<ShardDir>)> {
    if p.omap_rocksdb && !cfg!(feature = "rocksdb") {
        return Err(StoreError::Invalid(
            "RocksDB format requires the rocksdb build feature",
        ));
    }
    if p.omap_splinterdb && p.shards > MAX_SPLINTERDB_SHARDS {
        return Err(StoreError::Invalid(
            "SplinterDB supports at most 63 native shards per process",
        ));
    }
    if p.omap_splinterdb && (!cfg!(feature = "splinterdb") || p.omap_lsm || p.omap_rocksdb) {
        return Err(StoreError::Invalid(
            "SplinterDB requires its build feature and an exclusive engine selection",
        ));
    }
    let bad = |m: &str| Err(StoreError::BadGeometry(m.into()));
    if p.shards == 0 || p.shards > MAX_SHARDS {
        return bad(&format!("shards must be 1..={MAX_SHARDS}"));
    }
    if p.align_blocks == 0 || p.wal_blocks < WAL_BLOCKS_MIN || p.meta_pct > 50 {
        return bad("bad align/wal/meta params");
    }
    let dir_blocks = dir_blocks_for(p.shards);
    let dir_blk = 2;
    if p.chunked {
        if !cfg!(feature = "elastic") {
            return bad("chunked store needs the cargo feature elastic");
        }
        if !(10..=90).contains(&p.base_pct)
            || !p.chunk_blocks.is_power_of_two()
            || p.chunk_blocks < crate::alloc::WIN
        {
            return bad("base_pct 10..=90 and chunk_blocks a power of two >= 256");
        }
    }
    // the lending table of a chunked store (adr 0021 am. 49) follows the directory: two copies per table block, sized for
    // an upper bound of the pool chunks (the exact count depends on the regions placed behind it)
    let lend_blocks = if p.chunked {
        2 * (total_blocks / p.chunk_blocks + 1).div_ceil(LEND_EPB)
    } else {
        0
    };
    let first = align_up(dir_blk + dir_blocks as u64 + lend_blocks, p.align_blocks);
    if total_blocks <= first {
        return bad("device too small");
    }
    if p.compact_int && total_blocks >= crate::page::ADDR_LIMIT {
        return bad("device too large for compact interior pages (2 PiB)");
    }
    let region = (total_blocks - first) / p.shards as u64 / p.align_blocks * p.align_blocks;
    let mut meta = region * p.meta_pct as u64 / 100;
    if p.elastic_meta {
        meta = meta.min(p.meta_max_blocks);
    }
    if region < 2 + p.wal_blocks + meta + 64 {
        return bad("device too small for shards x (wal + meta + data)");
    }
    // Whole base chunks per chunked shard; the shared pool keeps >= 2 chunks per shard (small devices: lower base). A
    // shard whose data space is too small for that base has no allocatable data at all: refuse it here, never write a
    // directory that the mount refuses (or an allocator over an empty base).
    let base = if p.chunked {
        let full = (region - 2 - p.wal_blocks - meta) / p.chunk_blocks;
        let base = (full * p.base_pct as u64 / 100).min(full.saturating_sub(2));
        if base == 0 {
            return bad(&format!(
                "chunked shard: {full} chunks of {} blocks per shard hold no base chunk at base_pct {} (raise base_pct, use a smaller chunk or fewer shards)",
                p.chunk_blocks, p.base_pct
            ));
        }
        base
    } else {
        0
    };
    let mut dirs = Vec::new();
    for s in 0..p.shards {
        let start = first + s as u64 * region;
        let wal_start = start + 2;
        let meta_start = wal_start + p.wal_blocks;
        let data_start = meta_start + meta;
        dirs.push(ShardDir {
            shard: s,
            region_start: start,
            region_blocks: region,
            root_a: start,
            root_b: start + 1,
            wal_start,
            wal_blocks: p.wal_blocks,
            meta_start,
            meta_blocks: meta,
            data_start,
            data_blocks: if p.chunked {
                base * p.chunk_blocks
            } else {
                start + region - data_start
            },
            ext: Vec::new(),
            chunk_blocks: if p.chunked { p.chunk_blocks } else { 0 },
            #[cfg(feature = "elastic")]
            lent: Vec::new(),
        });
    }
    // The mount's geometry checks, before mkfs can invalidate an existing store and before cell_pages_for divides by
    // the node size / blocks per page. Every shard has the same meta size.
    let geom = MetaGeom::new(&dirs[0], p.node_size)?;
    let dir = encode_dir(&dirs, dir_blocks as usize * BLK);
    let sb = Superblock {
        version: FORMAT_VERSION,
        features: if p.elastic_meta { FEAT_ELASTIC_META } else { 0 }
            | if p.compact_int { FEAT_COMPACT_INT } else { 0 }
            | if p.inline_data { FEAT_INLINE_DATA } else { 0 }
            | if p.omap_runs {
                // the omap batch run format (adr 0476)
                FEAT_OMAP_COUNTERS | FEAT_OMAP_RUNS | FEAT_OMAP_BLIND
            } else {
                0
            }
            | FEAT_OMAP_UNCOUNTED
            | FEAT_OMAP_TOMBS
            | if p.lazy_free && p.elastic_meta {
                FEAT_LAZY_FREE
            } else {
                0
            }
            | if p.leaf_delta && p.elastic_meta {
                FEAT_LEAF_DELTA
            } else {
                0
            }
            | if p.delta_relog && p.leaf_delta && p.elastic_meta {
                FEAT_DELTA_RELOG
            } else {
                0
            }
            | if p.lazy_pginfo { FEAT_LAZY_PGINFO } else { 0 }
            | if p.long_names { FEAT_LONG_NAME } else { 0 }
            | if p.shared_ext { FEAT_SHARED_EXT } else { 0 }
            | if p.ext_values { FEAT_EXT_VALUE } else { 0 }
            | if p.val_comp { FEAT_VAL_COMP } else { 0 }
            | if p.omap_lsm || p.omap_rocksdb || p.omap_splinterdb {
                FEAT_OMAP_LSM
            } else {
                0
            }
            | if p.omap_rocksdb { FEAT_OMAP_ROCKSDB } else { 0 }
            | if p.omap_splinterdb {
                FEAT_OMAP_SPLINTERDB
            } else {
                0
            }
            | if p.chunked { FEAT_CHUNKED } else { 0 }
            | if p.dsm_verdict.is_some() {
                FEAT_DSM_VERDICT
            } else {
                0
            },
        osd_fsid: p.osd_fsid,
        osd_id: p.osd_id,
        cluster_fsid: p.cluster_fsid,
        lba_size: 0,
        size_bytes: 0,
        nsid: p.nsid,
        awupf_lbas: 0,
        awun_lbas: 0,
        plp: false,
        shards: p.shards,
        node_size: p.node_size,
        wal_blocks: p.wal_blocks,
        meta_pct: p.meta_pct,
        dir_blk,
        dir_blocks,
        dir_crc: crc(&dir),
        mkfs_time: p.mkfs_time,
        cell_pages: match (p.elastic_meta, p.cell_pages) {
            (false, _) => 0,
            (true, 0) => cell_pages_for(p.node_size, region),
            (true, n) => n,
        },
        expand: Vec::new(),
        base_pct: if p.chunked { p.base_pct } else { 0 },
        chunk_blocks: if p.chunked { p.chunk_blocks } else { 0 },
        upgrading: 0,
        dsm_verdict: p.dsm_verdict,
    };
    if p.elastic_meta && (sb.cell_pages < 64 || !sb.cell_pages.is_multiple_of(64)) {
        return bad("cell pages must be a multiple of 64");
    }
    geom.cell_blocks(sb.cell_pages)?;
    Ok((sb, dirs))
}

/// Format the device: refuses volatile-cache devices (adr 0008) unless overridden. Writes shard dirs, root
/// slots, an invalidated WAL head per shard, then both superblock copies last.
pub fn mkfs<D: BlockDev, C: Clock>(
    dev: &mut D,
    clk: &mut C,
    p: &MkfsParams,
) -> Result<(Superblock, Vec<ShardDir>)> {
    let g = dev.geometry();
    if g.vwc && !p.allow_volatile_cache {
        return Err(StoreError::VolatileCache);
    }
    if g.lba_size == 0 || !(BLK as u32).is_multiple_of(g.lba_size) || g.lba_size > BLK as u32 {
        return Err(StoreError::BadGeometry(format!("lba size {}", g.lba_size)));
    }
    let cap = g.capacity_bytes().min(p.max_bytes);
    let total_blocks = cap / BLK as u64;
    let (mut sb, dirs) = plan(total_blocks, p)?;
    sb.lba_size = g.lba_size;
    sb.size_bytes = cap;
    sb.awupf_lbas = g.awupf_lbas;
    sb.awun_lbas = g.awun_lbas;
    sb.plp = !g.vwc;

    let mut io = Sio::new(dev, clk);
    // the old store (if any) is gone first: a crash from here on leaves no superblock = not formatted, never a mix
    io.zero(0, 2)?;
    // everything replay reads must be ours: the WAL rings are zeroed whole (stale units of an earlier store with
    // the same fsid/mkfs_time and a catching-up epoch would validate), roots and the directory are rewritten below,
    // meta images / bitmaps / data are only reachable through the new roots (adr 0021 am. 36)
    for d in &dirs {
        io.zero(d.wal_start, d.wal_blocks)?;
    }
    io.write_one(sb.dir_blk, &encode_dir(&dirs, sb.dir_blocks as usize * BLK))?;
    #[cfg(feature = "elastic")]
    if p.chunked {
        crate::lend::format(&mut io, &crate::lend::Geom::of(&sb, &dirs)?)?;
    }
    let zero = vec![0u8; BLK];
    for d in &dirs {
        let slot = RootSlot {
            shard: d.shard,
            seq: 1,
            epoch: 0,
            wal_tail_prev_crc: wal_chain_seed(&p.osd_fsid, d.shard),
            ..Default::default()
        };
        // slot = seq & 1 (even: A, odd: B); seq 1 lives in B
        io.write(&[(d.root_b, &slot.encode()), (d.root_a, &zero)])?;
    }
    let b = sb.encode();
    io.write_one(0, &b)?;
    io.write_one(1, &b)?;
    Ok((sb, dirs))
}

/// Names of the feature bits in `f` (unknown bits as `0x..`), for status output.
pub fn feature_names(f: u64) -> Vec<String> {
    const N: [(u64, &str); 26] = [
        (FEAT_ELASTIC_META, "elastic_meta"),
        (FEAT_COMPACT_INT, "compact_int"),
        (FEAT_INLINE_DATA, "inline_data"),
        (FEAT_OMAP_COUNTERS, "omap_counters"),
        (FEAT_LAZY_FREE, "lazy_free"),
        (FEAT_LEAF_DELTA, "leaf_delta"),
        (FEAT_EXPAND, "expand"),
        (FEAT_LAZY_PGINFO, "lazy_pginfo"),
        (FEAT_LONG_NAME, "long_name"),
        (FEAT_COMPRESSION, "compression"),
        (FEAT_SHARED_EXT, "shared_ext"),
        (FEAT_EXT_VALUE, "ext_value"),
        (FEAT_VAL_COMP, "val_comp"),
        (FEAT_OMAP_RUNS, "omap_runs"),
        (FEAT_DELTA_RELOG, "delta_relog"),
        (FEAT_OMAP_BLIND, "omap_blind"),
        (FEAT_DEDUP, "dedup"),
        (FEAT_OMAP_LSM, "omap_lsm"),
        (FEAT_OMAP_ROCKSDB, "omap_rocksdb"),
        (FEAT_UPGRADING, "upgrading"),
        (FEAT_DSM_VERDICT, "dsm_verdict"),
        (FEAT_LOG_DUPS, "log_dups"),
        (FEAT_OMAP_UNCOUNTED, "omap_uncounted"),
        (FEAT_OMAP_TOMBS, "omap_tombs"),
        (FEAT_OMAP_SPLINTERDB, "omap_splinterdb"),
        (FEAT_CHUNKED, "chunked"),
    ];
    let mut v: Vec<String> = N
        .iter()
        .filter(|(b, _)| f & b != 0)
        .map(|(_, n)| (*n).to_owned())
        .collect();
    let rest = f & !N.iter().fold(0, |a, (b, _)| a | b);
    if rest != 0 {
        v.push(format!("{rest:#x}"));
    }
    v
}

/// Incompatible bits every store of this build must carry (what `mkfs` sets by default; `FEAT_COMPACT_INT` depends on the
/// device size, `FEAT_EXPAND` / `FEAT_COMPRESSION` are set at runtime). A missing bit an upgrade step adds is refused by
/// the mount gate with the `croit-flashstore-tool upgrade` command (`crate::upgrade`, adr 0611); any other missing bit by
/// [`check_required`] (`StoreCfg::shard.require_current`).
pub const FEATURES_REQUIRED: u64 = FEAT_ELASTIC_META
    | FEAT_INLINE_DATA
    | FEAT_OMAP_COUNTERS
    | FEAT_LAZY_FREE
    | FEAT_LEAF_DELTA
    | FEAT_LAZY_PGINFO
    | FEAT_LONG_NAME
    | FEAT_SHARED_EXT
    | FEAT_EXT_VALUE
    | FEAT_OMAP_RUNS
    | FEAT_DELTA_RELOG
    | FEAT_OMAP_BLIND;

/// Refuse a store lacking a required bit no upgrade step adds (older format): re-mkfs the OSD.
pub fn check_required(sb: &Superblock) -> Result<()> {
    let miss = FEATURES_REQUIRED & !sb.features;
    if miss == 0 {
        return Ok(());
    }
    Err(StoreError::Corrupt(format!(
        "unsupported store format: missing features {:?} (older store; there is no in-place upgrade: re-mkfs this OSD)",
        feature_names(miss)
    )))
}

/// Validate the superblock fields that are raw disk input before they size an allocation or an address: a crc-valid
/// copy whose field rotted (or that a foreign/hostile writer made) is `Corrupt`, never an allocation of its value, an
/// overflow or an access outside the device. The bounds are exactly what [`plan`] writes.
fn check_super(sb: &Superblock, cap_bytes: u64) -> Result<()> {
    let bad = |m: String| Err(StoreError::Corrupt(format!("superblock: {m}")));
    if !(1..=MAX_SHARDS).contains(&sb.shards) {
        return bad(format!(
            "{} shards (mkfs writes 1..={MAX_SHARDS})",
            sb.shards
        ));
    }
    if sb.wal_blocks < WAL_BLOCKS_MIN {
        return bad(format!(
            "WAL of {} blocks (mkfs writes at least {WAL_BLOCKS_MIN})",
            sb.wal_blocks
        ));
    }
    if sb.lba_size == 0 || !(BLK as u32).is_multiple_of(sb.lba_size) {
        return bad(format!("lba size {}", sb.lba_size));
    }
    // the store never exceeds the device it was made on (a grown device is fine, a shrunk one is not)
    if sb.size_bytes == 0 || sb.size_bytes > cap_bytes {
        return bad(format!(
            "store size {} B (the device has {cap_bytes} B)",
            sb.size_bytes
        ));
    }
    if sb.dir_blocks != dir_blocks_for(sb.shards) || sb.dir_blk < 2 {
        return bad(format!(
            "shard directory at {} + {} blocks for {} shards",
            sb.dir_blk, sb.dir_blocks, sb.shards
        ));
    }
    let size = sb.size_bytes / BLK as u64;
    if sb
        .dir_blk
        .checked_add(sb.dir_blocks as u64)
        .is_none_or(|e| e > size)
    {
        return bad(format!(
            "shard directory at {} + {} blocks outside the store ({size} blocks)",
            sb.dir_blk, sb.dir_blocks
        ));
    }
    if sb.features & FEAT_ELASTIC_META != 0
        && (sb.cell_pages < 64 || !sb.cell_pages.is_multiple_of(64))
    {
        return bad(format!(
            "meta cell of {} pages (mkfs writes a multiple of 64)",
            sb.cell_pages
        ));
    }
    Ok(())
}

/// Validate every decoded shard directory entry before its fields reach the allocator, the WAL ring arithmetic or the
/// lending geometry (they size vectors and divide by them): the entries are exactly the [`plan`] carve-up
/// `[root A][root B][WAL][meta][data]` of ascending, disjoint regions inside the store.
fn check_dirs(sb: &Superblock, dirs: &[ShardDir]) -> Result<()> {
    let bad = |d: &ShardDir, m: &str| {
        Err(StoreError::Corrupt(format!(
            "shard {} directory: {m}",
            d.shard
        )))
    };
    let size = sb.size_bytes / BLK as u64;
    let chunked = sb.features & FEAT_CHUNKED != 0;
    let mut end = sb.dir_blk + sb.dir_blocks as u64;
    for (i, d) in dirs.iter().enumerate() {
        if d.shard as usize != i {
            return bad(d, "entries out of shard order");
        }
        if d.wal_blocks != sb.wal_blocks {
            return bad(
                d,
                &format!(
                    "WAL of {} blocks, superblock {}",
                    d.wal_blocks, sb.wal_blocks
                ),
            );
        }
        let Some(region_end) = d.region_start.checked_add(d.region_blocks) else {
            return bad(d, "region wraps the address space");
        };
        if d.region_blocks == 0 || d.region_start < end || region_end > size {
            return bad(d, "region outside the store (or over the shard directory)");
        }
        let regions = d
            .region_start
            .checked_add(1)
            .and_then(|root_b| root_b.checked_add(1).map(|wal| (root_b, wal)))
            .and_then(|(root_b, wal_start)| {
                wal_start.checked_add(d.wal_blocks).and_then(|meta| {
                    meta.checked_add(d.meta_blocks)
                        .map(|data| (root_b, wal_start, meta, data))
                })
            });
        let Some((root_b, wal_start, meta_start, data_start)) = regions else {
            return bad(d, "regions wrap the address space");
        };
        if (d.root_a, d.root_b, d.wal_start, d.meta_start, d.data_start)
            != (d.region_start, root_b, wal_start, meta_start, data_start)
        {
            return bad(
                d,
                "regions not where mkfs carves them (root A, root B, WAL, meta, data)",
            );
        }
        if data_start >= region_end {
            return bad(d, "no data region behind WAL and meta");
        }
        let rest = region_end - data_start;
        if chunked {
            // whole base chunks of the region; the pool behind them keeps >= 2 chunks (mkfs lowers the base for that)
            let full = rest / sb.chunk_blocks;
            let base = d.data_blocks / sb.chunk_blocks;
            if d.data_blocks == 0
                || !d.data_blocks.is_multiple_of(sb.chunk_blocks)
                || base.saturating_add(2) > full
            {
                return bad(
                    d,
                    "data region is not whole chunks of the region (pool floor 2)",
                );
            }
        } else if d.data_blocks == 0 || d.data_blocks > rest {
            return bad(d, "data region outside the region");
        }
        end = region_end;
    }
    Ok(())
}

/// Read and validate superblock (either copy) and shard directory.
pub fn read_super<D: BlockDev, C: Clock>(
    dev: &mut D,
    clk: &mut C,
) -> Result<(Superblock, Vec<ShardDir>)> {
    let geometry = dev.geometry();
    let cap = geometry.capacity_bytes();
    let mut io = Sio::new(dev, clk);
    let blks = io.read(&[(0, 1), (1, 1)])?;
    let copies: Vec<Superblock> = blks.iter().filter_map(|b| Superblock::decode(b)).collect();
    // any intact copy written by a build with another format (version, unknown feature bit) refuses the mount: never
    // fall back to an older copy of a store a newer build already touched; such a copy may not even decode here
    if let Some((version, features)) = blks.iter().find_map(|b| Superblock::newer(b)) {
        return Err(StoreError::Newer(format!(
            "store format version {version} features {:?} is newer than this build (version {FORMAT_VERSION}): downgrade not possible after {:?} was enabled",
            feature_names(features),
            feature_names(features & !FEATURES_KNOWN)
        )));
    }
    if let Some(s) = copies.iter().find(|s| s.version != FORMAT_VERSION) {
        return Err(StoreError::Corrupt(format!(
            "unsupported store format: version {} features {:#x} (this build: version {FORMAT_VERSION} features {FEATURES_KNOWN:#x}); there is no in-place upgrade for this version yet (adr 0611 S1): re-mkfs this OSD",
            s.version, s.features
        )));
    }
    if copies.iter().any(|s| {
        s.features & (FEAT_OMAP_ROCKSDB | FEAT_OMAP_SPLINTERDB)
            == FEAT_OMAP_ROCKSDB | FEAT_OMAP_SPLINTERDB
            || s.features & FEAT_OMAP_ROCKSDB != 0
                && s.features & (FEAT_OMAP_UNCOUNTED | FEAT_OMAP_TOMBS)
                    != FEAT_OMAP_UNCOUNTED | FEAT_OMAP_TOMBS
    }) {
        return Err(StoreError::Invalid(
            "conflicting or ambiguous legacy bit-25 foreign OMAP identity; no automatic conversion",
        ));
    }
    // The pre-main experimental RocksDB branch used bit 23 before main assigned
    // it to uncounted OMAP. Never reinterpret that ambiguous LSM store as native
    // or heal away its identity. Main sets UNCOUNTED and TOMBS together.
    if copies.iter().any(|s| {
        s.features & (FEAT_OMAP_LSM | FEAT_OMAP_UNCOUNTED) == FEAT_OMAP_LSM | FEAT_OMAP_UNCOUNTED
            && s.features & (FEAT_OMAP_TOMBS | FEAT_OMAP_ROCKSDB) == 0
    }) {
        return Err(StoreError::Invalid(
            "ambiguous legacy RocksDB bit-23 store: no automatic format conversion",
        ));
    }
    // FEAT_COMPRESSION is sticky: a crash (or another core) between the two copy writes of the first compressed
    // write must not let a fallback copy hide it
    let sticky = copies.iter().fold(0, |a, s| a | s.features) & FEATURES_STICKY;
    let mut sb = copies.into_iter().next().ok_or(StoreError::NotFormatted)?;
    sb.features |= sticky;
    check_super(&sb, cap)?;
    // Reject before callers can heal copies, set feature bits or publish a mount epoch.
    if sb.lba_size != geometry.lba_size {
        return Err(StoreError::BadGeometry(format!(
            "lba size {} differs from the store's {} (changed since mkfs)",
            geometry.lba_size, sb.lba_size
        )));
    }
    let dir = io.read_one(sb.dir_blk, sb.dir_blocks)?;
    if crc(&dir) != sb.dir_crc {
        return Err(StoreError::Corrupt("shard directory crc".into()));
    }
    let mut d = Dec::new(&dir);
    let dirs = (0..sb.shards)
        .map(|_| ShardDir::decode(&mut d))
        .collect::<Option<Vec<_>>>()
        .ok_or(StoreError::Corrupt("shard directory".into()))?;
    check_dirs(&sb, &dirs)?;
    let mut dirs = with_expansions(&sb, dirs)?;
    if sb.features & FEAT_CHUNKED != 0 {
        // the allocator scans whole windows of a chunk (mkfs refuses smaller chunks)
        if sb.chunk_blocks < crate::alloc::WIN {
            return Err(StoreError::Corrupt(format!(
                "chunk of {} blocks below the allocator window ({})",
                sb.chunk_blocks,
                crate::alloc::WIN
            )));
        }
        for d in dirs.iter_mut() {
            d.chunk_blocks = sb.chunk_blocks;
            if !d.ext.is_empty() {
                return Err(StoreError::Corrupt(
                    "chunked shard directory: data region is not whole chunks".into(),
                ));
            }
        }
        // borrowed chunks per shard from the lending table (adr 0021 am. 49): allocator, replay and fsck see them
        #[cfg(feature = "elastic")]
        {
            let l = crate::lend::Lending::load(&mut io, &sb, &dirs)?;
            for d in dirs.iter_mut() {
                d.lent = l.slots(d.shard);
            }
        }
    }
    Ok((sb, dirs))
}

/// Add the extents of the superblock's expansions to the shard directory entries (and check them).
fn with_expansions(sb: &Superblock, mut dirs: Vec<ShardDir>) -> Result<Vec<ShardDir>> {
    let bad = |m: String| Err(StoreError::Corrupt(format!("expansion list: {m}")));
    if sb.features & FEAT_EXPAND == 0 {
        return if sb.expand.is_empty() {
            Ok(dirs)
        } else {
            bad("present without the feature bit".into())
        };
    }
    let mut end = dirs.last().map_or(0, |d| d.region_start + d.region_blocks);
    for x in &sb.expand {
        if x.per_shard == 0 || x.start < end {
            return bad(format!(
                "extent at {} (+{} per shard) overlaps the store",
                x.start, x.per_shard
            ));
        }
        // the extents of all shards end within the store size the expand recorded
        let Some(e) = x
            .per_shard
            .checked_mul(dirs.len() as u64)
            .and_then(|n| n.checked_add(x.start))
            .filter(|&e| e <= sb.size_bytes / BLK as u64)
        else {
            return bad(format!(
                "extent at {} (+{} per shard) beyond the store ({} bytes)",
                x.start, x.per_shard, sb.size_bytes
            ));
        };
        for d in dirs.iter_mut() {
            d.ext
                .push((x.start + d.shard as u64 * x.per_shard, x.per_shard));
        }
        end = e;
    }
    Ok(dirs)
}

/// First block behind everything the store manages (shard regions and expansion extents).
fn managed_end(sb: &Superblock, dirs: &[ShardDir]) -> u64 {
    match sb.expand.last() {
        Some(x) => x.start + x.per_shard * sb.shards as u64,
        None => dirs.last().map_or(0, |d| d.region_start + d.region_blocks),
    }
}

/// Make both superblock copies equal to `sb` (the copy `read_super` picked): a crash between the two writes of an
/// expand (or a torn copy) leaves one copy older; a later fallback to it would lose the extents shards allocate in.
/// Copy 0 first, each write durable on completion (adr 0008). Sticky feature bits found in either copy are kept
/// (another core may have set one since `sb` was read). The read-modify-write is serialized across the cores of the
/// process (cold path): two cores enabling different sticky bits at once would otherwise each write the copies without
/// the other's bit. One process owns a device (exclusive claim), so this covers every writer.
pub fn heal_super<D: BlockDev, C: Clock>(dev: &mut D, clk: &mut C, sb: &Superblock) -> Result<()> {
    static SUPER_RMW: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // a panic under the lock left no partial state behind it: both copies are re-read
    let _rmw = SUPER_RMW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut io = Sio::new(dev, clk);
    let cur = io.read(&[(0, 1), (1, 1)])?;
    let mut sb = sb.clone();
    for c in &cur {
        if let Some(s) = Superblock::decode(c) {
            sb.features |= s.features & FEATURES_STICKY;
        }
    }
    let b = sb.encode();
    for (blk, c) in cur.iter().enumerate() {
        if c[..] != b[..] {
            io.write_one(blk as u64, &b)?;
        }
    }
    Ok(())
}

/// Device versus store sizes (`croit-flashstore-tool sizes`), bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sizes {
    /// What the device reports now.
    pub device_bytes: u64,
    /// What the superblock recorded at mkfs / the last expand.
    pub store_bytes: u64,
    /// Bytes the shards manage (regions + extents); `device_bytes - managed_bytes` is unused tail.
    pub managed_bytes: u64,
    pub shards: u32,
    pub expansions: usize,
    /// Data capacity (all shards, extents included), bytes.
    pub data_bytes: u64,
    /// Bytes per shard an expand would add now (0 = device did not grow by one unit per shard).
    pub expandable_per_shard: u64,
}

fn expand_per_shard(total_blocks: u64, end: u64, shards: u32) -> u64 {
    total_blocks.saturating_sub(end) / shards as u64 / EXPAND_UNIT * EXPAND_UNIT
}

pub fn sizes<D: BlockDev, C: Clock>(dev: &mut D, clk: &mut C) -> Result<Sizes> {
    let (sb, dirs) = read_super(dev, clk)?;
    let g = dev.geometry();
    let total = g.capacity_bytes() / BLK as u64;
    let end = managed_end(&sb, &dirs);
    Ok(Sizes {
        device_bytes: g.capacity_bytes(),
        store_bytes: sb.size_bytes,
        managed_bytes: end * BLK as u64,
        shards: sb.shards,
        expansions: sb.expand.len(),
        data_bytes: dirs.iter().map(ShardDir::data_total).sum::<u64>() * BLK as u64,
        expandable_per_shard: expand_per_shard(total, end, sb.shards) * BLK as u64,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpandReport {
    pub old_bytes: u64,
    pub new_bytes: u64,
    /// Bytes added to every shard.
    pub per_shard_bytes: u64,
    pub generations: usize,
}

/// Grow the store into a device (or namespace) that grew since mkfs / the last expand (`croit-flashstore-tool expand`,
/// adr 0021 am. 20). OFFLINE: nothing may have the store mounted. Every shard gets one more data extent
/// carved from the space behind the managed area, equal sizes, whole `EXPAND_UNIT`s. The only durable step is the
/// superblock (copy 0 then copy 1, each durable on completion): before it the new blocks are unreferenced, after it
/// every mount sees the extents (all free: the allocator bitmap has no bits for them). A crash between the two copies
/// is healed here and by every mount (`heal_super`). Returns `None` when the device did not grow by a unit per shard.
pub fn expand<D: BlockDev, C: Clock>(dev: &mut D, clk: &mut C) -> Result<Option<ExpandReport>> {
    let (sb, dirs) = read_super(dev, clk)?;
    if sb.features & FEAT_CHUNKED != 0 {
        return Err(StoreError::BadGeometry(
            "expand of a chunked store is not supported (re-mkfs)".into(),
        ));
    }
    heal_super(dev, clk, &sb)?;
    // `read_super` refused a changed LBA size before the heal
    let g = dev.geometry();
    let total = g.capacity_bytes() / BLK as u64;
    let end = managed_end(&sb, &dirs);
    if total < end {
        return Err(StoreError::BadGeometry(format!(
            "device ({total} blocks) is smaller than the store ({end} blocks): never shrink"
        )));
    }
    let per_shard = expand_per_shard(total, end, sb.shards);
    if per_shard == 0 {
        return Ok(None);
    }
    if sb.expand.len() >= MAX_EXPANSIONS {
        return Err(StoreError::BadGeometry(format!(
            "{MAX_EXPANSIONS} expansions done already"
        )));
    }
    if sb.features & FEAT_COMPACT_INT != 0 && total >= crate::page::ADDR_LIMIT {
        return Err(StoreError::BadGeometry(
            "device too large for compact interior pages (2 PiB)".into(),
        ));
    }
    let mut s = sb.clone();
    s.features |= FEAT_EXPAND;
    s.expand.push(Expansion {
        start: end,
        per_shard,
    });
    s.size_bytes = g.capacity_bytes();
    let b = s.encode();
    let mut io = Sio::new(dev, clk);
    io.write_one(0, &b)?;
    io.write_one(1, &b)?;
    Ok(Some(ExpandReport {
        old_bytes: sb.size_bytes,
        new_bytes: s.size_bytes,
        per_shard_bytes: per_shard * BLK as u64,
        generations: s.expand.len(),
    }))
}

/// The meta page allocation state a root slot points at.
#[derive(Debug)]
pub struct MetaImage {
    pub meta: MetaAlloc,
    /// Elastic image: addresses of its pages and the crc of the first one (empty for a fresh/legacy image).
    pub blob_pages: Vec<u64>,
    pub blob_crc: u32,
    /// Legacy fixed bitmap: `(addr, blocks, crc)` of the copy the root slot references.
    pub legacy: Option<(u64, u32, u32)>,
    /// Lazy free: detached subtrees still allocated (adr 0021 am. 18).
    pub dead: Vec<crate::tree::Dead>,
    /// Leaf deltas: the live delta segments (adr 0021 am. 19).
    pub segs: Vec<crate::tree::SegDir>,
}

/// Load the meta page bitmap of a root slot: nothing (no checkpoint with a tree yet), the legacy fixed A/B bitmap
/// or the elastic image stored in meta pages.
pub fn read_meta_image<D: BlockDev, C: Clock>(
    dev: &mut D,
    clk: &mut C,
    sb: &Superblock,
    geom: &MetaGeom,
    root: &RootSlot,
) -> Result<MetaImage> {
    read_meta_image_checked(dev, clk, sb, geom, root, true)
}

/// Offline repair may recount a root counter; bitmap CRC, geometry and reachability
/// validation remain mandatory. Normal mounts/checks require the counter to match.
pub(crate) fn read_meta_image_checked<D: BlockDev, C: Clock>(
    dev: &mut D,
    clk: &mut C,
    sb: &Superblock,
    geom: &MetaGeom,
    root: &RootSlot,
    check_counter: bool,
) -> Result<MetaImage> {
    let elastic = sb.features & FEAT_ELASTIC_META != 0;
    let bad = |m: &str| Err(StoreError::Corrupt(m.into()));
    let mk = |m: MetaAlloc| MetaImage {
        meta: m,
        blob_pages: Vec::new(),
        blob_crc: 0,
        legacy: None,
        dead: Vec::new(),
        segs: Vec::new(),
    };
    if root.meta_bitmap_len == 0 {
        if root.tree_root != 0 || root.meta_pages_used != 0 {
            return bad("tree without meta bitmap");
        }
        return Ok(mk(if elastic {
            MetaAlloc::new_elastic(geom.npages, sb.cell_pages)
        } else {
            MetaAlloc::new(geom.npages)
        }));
    }
    let a = root.meta_bitmap_addr;
    let mut io = Sio::new(dev, clk);
    if a == geom.bm_a || a == geom.bm_b {
        if root.meta_bitmap_len != geom.bm_blocks {
            return bad("meta bitmap location");
        }
        let b = io.read_one(a, root.meta_bitmap_len)?;
        if u32::from_le_bytes(b[0..4].try_into().unwrap()) != root.meta_bitmap_crc {
            return bad("meta bitmap crc vs root slot");
        }
        let m = MetaAlloc::decode(&b, geom.npages)
            .map_err(|e| StoreError::Corrupt(format!("meta bitmap: {e}")))?;
        if check_counter && m.used() as u64 != root.meta_pages_used {
            return bad("meta page count vs root slot");
        }
        let mut r = mk(m);
        r.legacy = Some((a, root.meta_bitmap_len, root.meta_bitmap_crc));
        return Ok(r);
    }
    if !elastic {
        return bad("elastic meta image on a store without the feature");
    }
    let (psz, bpp) = (sb.node_size as usize, geom.bpp as u32);
    let p0 = io.read_one(a, bpp)?;
    if crate::page::stored_crc(&p0) != root.meta_bitmap_crc {
        return bad("meta image crc vs root slot");
    }
    let corrupt = |m: &str| StoreError::Corrupt(format!("meta image: {m}"));
    let (k, len, refs) = crate::alloc::blob_head(&p0, psz, a).map_err(corrupt)?;
    if k as u32 != root.meta_bitmap_len {
        return bad("meta image page count vs root slot");
    }
    let reqs: Vec<(u64, u32)> = refs.iter().map(|&(ra, _)| (ra, bpp)).collect();
    let rest = io.read(&reqs)?;
    let payload = crate::alloc::blob_unpack(&p0, &rest, &refs, len, psz).map_err(corrupt)?;
    let (m, used) = MetaAlloc::blob_decode_ext(&payload, geom.npages).map_err(corrupt)?;
    m.validate_extents(geom.bpp).map_err(corrupt)?;
    // behind the meta image: the extension sections of the features that need them (an image written before a feature
    // came on has none: empty), nothing otherwise
    let (dead, segs) = if sb.features & (FEAT_LAZY_FREE | FEAT_LEAF_DELTA) != 0 {
        if used == payload.len() {
            (Vec::new(), Vec::new())
        } else {
            crate::tree::Tree::decode_ext(&payload[used..]).map_err(corrupt)?
        }
    } else if used != payload.len() {
        return bad("meta image has extension sections on a store without their features");
    } else {
        (Vec::new(), Vec::new())
    };
    if (!dead.is_empty() && sb.features & FEAT_LAZY_FREE == 0)
        || (!segs.is_empty() && sb.features & FEAT_LEAF_DELTA == 0)
    {
        return bad("meta image section of a feature the store does not have");
    }
    if m.ppc() != sb.cell_pages {
        return bad("meta image cell size differs from the superblock");
    }
    if check_counter && m.used() as u64 != root.meta_pages_used {
        return bad("meta page count vs root slot");
    }
    // every detached subtree root is a used meta page (listed once)
    let mut seen: Vec<u32> = Vec::with_capacity(dead.len());
    for d in &dead {
        match geom
            .page_idx(d.addr)
            .or_else(|| m.cell_page_idx(d.addr, geom.bpp))
        {
            Some(i) if m.get(i) && d.level > 0 => seen.push(i),
            _ => return bad("dead-subtree root outside the used meta pages"),
        }
    }
    seen.sort_unstable();
    if seen.windows(2).any(|w| w[0] == w[1]) {
        return bad("dead-subtree root listed twice");
    }
    // every delta page is a used meta page, listed once, of a strictly increasing segment sequence
    let mut dseen: Vec<u32> = Vec::new();
    for w in segs.windows(2) {
        if w[0].seq >= w[1].seq {
            return bad("delta segments out of order");
        }
    }
    for sg in &segs {
        for &(addr, _) in &sg.pages {
            match geom
                .page_idx(addr)
                .or_else(|| m.cell_page_idx(addr, geom.bpp))
            {
                Some(i) if m.get(i) => dseen.push(i),
                _ => return bad("delta page outside the used meta pages"),
            }
        }
    }
    dseen.sort_unstable();
    if dseen.windows(2).any(|w| w[0] == w[1]) {
        return bad("delta page listed twice");
    }
    let mut pages = vec![a];
    pages.extend(refs.iter().map(|r| r.0));
    // the image's own pages are meta pages it marks used, each once (the next checkpoint frees them by index)
    let mut idxs: Vec<u32> = Vec::with_capacity(pages.len());
    for &p in &pages {
        match geom.page_idx(p).or_else(|| m.cell_page_idx(p, geom.bpp)) {
            Some(i) if m.get(i) && !idxs.contains(&i) => idxs.push(i),
            _ => return bad("meta image page outside the used meta pages"),
        }
    }
    let mut r = mk(m);
    r.blob_pages = pages;
    r.blob_crc = root.meta_bitmap_crc;
    r.dead = dead;
    r.segs = segs;
    Ok(r)
}

/// Read both root slots; the valid one with the highest seq wins.
pub fn read_root<D: BlockDev, C: Clock>(
    dev: &mut D,
    clk: &mut C,
    dir: &ShardDir,
) -> Result<RootSlot> {
    let mut io = Sio::new(dev, clk);
    let blks = io.read(&[(dir.root_a, 1), (dir.root_b, 1)])?;
    blks.iter()
        .filter_map(|b| RootSlot::decode(b))
        .filter(|r| r.shard == dir.shard)
        .max_by_key(|r| r.seq)
        .ok_or(StoreError::NotFormatted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::{SimClock, SimConfig, SimDisk};

    fn small() -> MkfsParams {
        MkfsParams {
            shards: 4,
            wal_blocks: 256,
            align_blocks: 16,
            meta_pct: 3,
            ..Default::default()
        }
    }

    #[test]
    fn overflowing_data_ranges_are_rejected() {
        let (_, dirs) = plan((64 << 20) / BLK as u64, &small()).unwrap();
        let d = &dirs[0];
        assert!(!d.in_data(u64::MAX, 2));
        assert!(!d.in_data(d.data_start, u64::MAX));
        assert!(d.in_data(d.data_start, d.data_blocks));
        assert!(!d.in_data(d.data_start + d.data_blocks - 1, 2));
    }

    #[test]
    fn incompatible_device_geometry_is_refused_without_writes() {
        for elastic_meta in [false, true] {
            let disk = SimDisk::new(SimConfig::new(64 << 20));
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            let (mut sb, _) = mkfs(
                &mut dev,
                &mut clk,
                &MkfsParams {
                    elastic_meta,
                    ..small()
                },
            )
            .unwrap();
            // Byte-preserving migration from a 512-byte namespace to a 4K namespace:
            // all store offsets still resolve, but Shard::mount forbids the new geometry.
            sb.lba_size = 512;
            // A torn/missing copy makes a premature superblock heal observable.
            let mut io = Sio::new(&mut dev, &mut clk);
            io.write_one(0, &sb.encode()).unwrap();
            io.write_one(1, &[0; BLK]).unwrap();
            let before = disk.image();
            let writes = disk.stats().writes;
            assert!(crate::fsck::fsck(&mut dev, &mut clk, None).is_err());
            let d = disk.clone();
            assert!(
                crate::obj::Store::mount(
                    move || d.queue(),
                    SimClock::default(),
                    crate::obj::StoreCfg::default(),
                )
                .is_err()
            );
            assert!(expand(&mut dev, &mut clk).is_err());
            assert_eq!(
                disk.stats().writes,
                writes,
                "rejected device must not be healed"
            );
            for b in [0, 1] {
                assert_eq!(disk.image().read_lba(b), before.read_lba(b));
            }
        }
    }

    #[test]
    fn invalid_meta_image_address_is_rejected() {
        let mut cfg = SimConfig::new(64 << 20);
        cfg.lba_size = 512;
        cfg.lba_count = (64 << 20) / 512;
        let disk = SimDisk::new(cfg);
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (mut sb, dirs) = mkfs(&mut dev, &mut clk, &small()).unwrap();
        sb.features |= FEAT_ELASTIC_META;
        let geom = MetaGeom::new(&dirs[0], sb.node_size).unwrap();
        let mut root = read_root(&mut dev, &mut clk, &dirs[0]).unwrap();
        root.meta_bitmap_addr = u64::MAX;
        root.meta_bitmap_len = 1;
        // The same raw fields are obtained from a CRC-valid root before reading its image.
        let root = RootSlot::decode(&root.encode()).unwrap();
        assert!(matches!(
            read_meta_image(&mut dev, &mut clk, &sb, &geom, &root),
            Err(StoreError::Invalid("sio: LBA range beyond the device"))
        ));
    }

    #[test]
    fn mkfs_mount_roundtrip() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (sb, dirs) = mkfs(&mut dev, &mut clk, &small()).unwrap();
        let (sb2, dirs2) = read_super(&mut dev, &mut clk).unwrap();
        assert_eq!((sb.clone(), dirs.clone()), (sb2, dirs2));
        // regions disjoint, ordered, inside the device
        let total = 64 << 8;
        let mut end = 0;
        for d in &dirs {
            assert!(d.region_start >= end && d.region_start % 16 == 0);
            assert_eq!(
                d.data_start + d.data_blocks,
                d.region_start + d.region_blocks
            );
            end = d.region_start + d.region_blocks;
            let r = read_root(&mut dev, &mut clk, d).unwrap();
            assert_eq!((r.seq, r.epoch, r.shard), (1, 0, d.shard));
        }
        assert!(end <= total);
    }

    #[test]
    fn rocksdb_identity_is_distinct_from_native_omap_features() {
        assert_eq!(FEAT_OMAP_ROCKSDB, 1 << 25);
        assert_eq!(
            FEAT_OMAP_ROCKSDB & (FEAT_OMAP_UNCOUNTED | FEAT_OMAP_TOMBS),
            0
        );
        let (sb, _) = plan(
            (64 << 20) / BLK as u64,
            &MkfsParams {
                omap_lsm: true,
                ..small()
            },
        )
        .unwrap();
        assert_eq!(sb.features & FEAT_OMAP_ROCKSDB, 0);
        assert_ne!(sb.features & FEAT_OMAP_UNCOUNTED, 0);
        assert_ne!(sb.features & FEAT_OMAP_TOMBS, 0);
    }

    #[test]
    fn rocksdb_format_requires_build_support_in_either_superblock_copy() {
        let params = MkfsParams {
            omap_rocksdb: true,
            ..small()
        };
        if cfg!(feature = "rocksdb") {
            let (sb, _) = plan((64 << 20) / BLK as u64, &params).unwrap();
            assert_ne!(sb.features & (1 << 25), 0);
            assert_ne!(sb.features & FEAT_OMAP_LSM, 0);
            assert_eq!(feature_names(1 << 25), vec!["omap_rocksdb"]);
        } else {
            assert!(matches!(
                plan((64 << 20) / BLK as u64, &params),
                Err(StoreError::Invalid(_))
            ));
            for copy in [0, 1] {
                let disk = SimDisk::new(SimConfig::new(64 << 20));
                let mut dev = disk.queue();
                let mut clk = SimClock::default();
                let (mut sb, _) = mkfs(&mut dev, &mut clk, &small()).unwrap();
                sb.features |= (1 << 25) | FEAT_OMAP_LSM;
                Sio::new(&mut dev, &mut clk)
                    .write_one(copy, &sb.encode())
                    .unwrap();
                assert!(matches!(
                    read_super(&mut dev, &mut clk),
                    Err(StoreError::Newer(_))
                ));
            }
        }
    }

    #[test]
    fn ambiguous_legacy_rocksdb_copy_refuses_before_mount_writes() {
        for copy in [0, 1] {
            let disk = SimDisk::new(SimConfig::new(64 << 20));
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            let (mut sb, _) = mkfs(
                &mut dev,
                &mut clk,
                &MkfsParams {
                    omap_lsm: true,
                    ..small()
                },
            )
            .unwrap();
            // Independent old branch identity, even when the other copy looks
            // like a valid current native store. Do not merge away the ambiguity.
            sb.features |= 1 << 23;
            sb.features &= !((1 << 24) | (1 << 25));
            Sio::new(&mut dev, &mut clk)
                .write_one(copy, &sb.encode())
                .unwrap();
            let before = disk.image();
            let result = crate::obj::Store::mount(
                || disk.queue(),
                SimClock::default(),
                crate::obj::StoreCfg::default(),
            );
            assert!(
                matches!(result, Err(crate::obj::ObjError::Store(StoreError::Invalid(m)))
                if m.contains("ambiguous legacy RocksDB"))
            );
            let after = disk.image();
            for blk in [0, 1] {
                assert_eq!(before.read_lba(blk), after.read_lba(blk));
            }
        }
    }

    #[test]
    fn foreign_engine_identities_are_distinct_and_legacy_splinter_never_heals_as_rocks() {
        assert_eq!(FEAT_OMAP_SPLINTERDB, 1 << 26);
        assert_eq!(
            FEAT_OMAP_SPLINTERDB & (FEAT_OMAP_ROCKSDB | FEAT_OMAP_UNCOUNTED | FEAT_OMAP_TOMBS),
            0
        );
        let both = MkfsParams {
            omap_rocksdb: true,
            omap_splinterdb: true,
            ..small()
        };
        assert!(plan((64 << 20) / BLK as u64, &both).is_err());
        for copy in [0, 1] {
            for dual in [false, true] {
                let disk = SimDisk::new(SimConfig::new(64 << 20));
                let mut dev = disk.queue();
                let mut clk = SimClock::default();
                let (mut sb, _) = mkfs(&mut dev, &mut clk, &small()).unwrap();
                sb.features |= FEAT_OMAP_LSM | FEAT_OMAP_ROCKSDB;
                if dual {
                    sb.features |= FEAT_OMAP_SPLINTERDB;
                } else {
                    sb.features &= !(FEAT_OMAP_UNCOUNTED | FEAT_OMAP_TOMBS);
                }
                Sio::new(&mut dev, &mut clk)
                    .write_one(copy, &sb.encode())
                    .unwrap();
                let before = disk.image();
                assert!(read_super(&mut dev, &mut clk).is_err());
                let after = disk.image();
                for block in [0, 1] {
                    assert_eq!(before.read_lba(block), after.read_lba(block));
                }
            }
        }
    }

    /// The upgrade mark (adr 0611) round-trips with its step id; a mark without an id is a damaged copy.
    #[test]
    fn upgrading_mark_roundtrip() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (mut sb, _) = mkfs(&mut dev, &mut clk, &small()).unwrap();
        assert_eq!(sb.upgrading, 0);
        sb.features |= FEAT_UPGRADING;
        sb.upgrading = 7;
        heal_super(&mut dev, &mut clk, &sb).unwrap();
        let (sb2, _) = read_super(&mut dev, &mut clk).unwrap();
        assert_eq!(sb2, sb);
        assert!(feature_names(sb2.features).iter().any(|f| f == "upgrading"));
        sb.upgrading = 0;
        assert_eq!(Superblock::decode(&sb.encode()), None);
        sb.features &= !FEAT_UPGRADING;
        assert_eq!(Superblock::decode(&sb.encode()).unwrap().upgrading, 0);
    }

    #[cfg(feature = "elastic")]
    #[test]
    fn chunked_mkfs_mount_roundtrip() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let p = MkfsParams {
            chunked: true,
            chunk_blocks: 256,
            base_pct: 75,
            ..small()
        };
        let (sb, dirs) = mkfs(&mut dev, &mut clk, &p).unwrap();
        let (sb2, dirs2) = read_super(&mut dev, &mut clk).unwrap();
        assert_eq!((sb.clone(), dirs.clone()), (sb2.clone(), dirs2));
        assert_eq!((sb2.base_pct, sb2.chunk_blocks), (75, 256));
        for d in &dirs {
            assert_eq!(d.chunk_blocks, 256);
            assert!(d.data_blocks > 0 && d.data_blocks % 256 == 0);
            let full = (d.region_start + d.region_blocks - d.data_start) / 256;
            assert_eq!(d.data_blocks / 256, (full * 75 / 100).min(full - 2));
            assert!(
                full - d.data_blocks / 256 >= 2,
                "pool floor: 2 chunks per shard"
            );
            let a = d.new_alloc();
            assert_eq!(a.len(), d.data_blocks);
            assert_eq!(a.start(), d.data_start);
        }
        // small device: the base is lowered so that the pool keeps 2 chunks per shard
        let p = MkfsParams {
            chunked: true,
            chunk_blocks: 1024,
            base_pct: 90,
            ..small()
        };
        let (_, dirs) = plan(64 << 8, &p).unwrap();
        assert!(dirs.iter().all(|d| d.data_blocks / 1024 + 2
            <= (d.region_start + d.region_blocks - d.data_start) / 1024));
        // out of range / not a power of two
        for (b, c) in [(9, 256), (91, 256), (75, 300)] {
            let p = MkfsParams {
                chunked: true,
                chunk_blocks: c,
                base_pct: b,
                ..small()
            };
            assert!(plan(64 << 8, &p).is_err());
        }
        // expand of a chunked store is refused
        assert!(expand(&mut dev, &mut clk).is_err());
    }

    #[cfg(not(feature = "elastic"))]
    #[test]
    fn chunked_mkfs_needs_the_feature() {
        let p = MkfsParams {
            chunked: true,
            ..small()
        };
        assert!(plan(64 << 8, &p).is_err());
    }

    #[test]
    fn superblock_copy_fallback_and_corruption() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        mkfs(&mut dev, &mut clk, &small()).unwrap();
        disk.corrupt(0, 20, 0x40);
        read_super(&mut dev, &mut clk).unwrap();
        disk.corrupt(1, 100, 0x01);
        assert_eq!(
            read_super(&mut dev, &mut clk).unwrap_err(),
            StoreError::NotFormatted
        );
    }

    #[test]
    fn splinter_selection_is_explicit_and_never_changes_native_defaults() {
        let mut p = small();
        let (native, _) = plan(64 << 8, &p).unwrap();
        assert_eq!(native.features & FEAT_OMAP_SPLINTERDB, 0);
        p.omap_lsm = true;
        let (lsm, _) = plan(64 << 8, &p).unwrap();
        assert_ne!(lsm.features & FEAT_OMAP_LSM, 0);
        assert_eq!(lsm.features & FEAT_OMAP_SPLINTERDB, 0);
        p.omap_splinterdb = true;
        assert!(plan(64 << 8, &p).is_err());
        p.omap_lsm = false;
        assert_eq!(plan(64 << 8, &p).is_ok(), cfg!(feature = "splinterdb"));
        p.shards = 64;
        assert_eq!(
            plan(64 << 18, &p).unwrap_err(),
            StoreError::Invalid("SplinterDB supports at most 63 native shards per process")
        );
        p.omap_splinterdb = false;
        assert!(
            plan(64 << 18, &p).is_ok(),
            "native engine shard admission must not inherit the foreign thread bound"
        );
    }

    #[cfg(not(feature = "splinterdb"))]
    #[test]
    fn splinter_disabled_refuses_even_one_marked_superblock_without_writes() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (mut sb, _) = mkfs(&mut dev, &mut clk, &small()).unwrap();
        sb.features |= FEAT_OMAP_SPLINTERDB | FEAT_OMAP_LSM;
        Sio::new(&mut dev, &mut clk)
            .write_one(1, &sb.encode())
            .unwrap();
        let writes = disk.stats().write_lbas;
        assert!(matches!(
            read_super(&mut dev, &mut clk),
            Err(StoreError::Newer(_))
        ));
        assert_eq!(writes, disk.stats().write_lbas);
    }

    #[test]
    fn newer_format_copies_refuse_the_mount() {
        // a store a later build marked (format version, unknown incompat feature bit) is refused, also when only one
        // copy carries the mark (never a fallback to the older copy)
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (sb, _) = mkfs(&mut dev, &mut clk, &small()).unwrap();
        let mark = |copy: u64, f: &dyn Fn(&mut Superblock)| {
            let mut s = sb.clone();
            f(&mut s);
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            Sio::new(&mut dev, &mut clk)
                .write_one(copy, &s.encode())
                .unwrap();
        };
        for (copy, f) in [
            (
                0u64,
                &(|s: &mut Superblock| s.features |= 1 << 40) as &dyn Fn(&mut Superblock),
            ),
            (0, &|s: &mut Superblock| s.version = 0), // an older format
            (1, &|s: &mut Superblock| s.version = 0),
            (1, &|s: &mut Superblock| s.features |= 1 << 63),
            (1, &|s: &mut Superblock| s.version = FORMAT_VERSION + 1),
        ] {
            mark(0, &|_| {});
            mark(1, &|_| {});
            read_super(&mut dev, &mut clk).unwrap();
            mark(copy, f);
            match read_super(&mut dev, &mut clk) {
                Err(StoreError::Corrupt(m)) => {
                    assert!(m.contains("unsupported store format"), "{m}");
                    assert!(m.contains("re-mkfs"), "{m}")
                }
                Err(StoreError::Newer(m)) => assert!(m.contains("downgrade not possible"), "{m}"),
                r => panic!("copy {copy}: {r:?}"),
            }
        }
    }

    /// W2: a newer build may add superblock fields behind a new feature bit; this build cannot decode such a copy (the
    /// crc follows fields it does not know) but must still read it as a newer store, never as "not formatted". A copy
    /// whose feature field only rotted (no crc verifies) is damaged: the other copy serves.
    #[test]
    fn newer_layout_with_unknown_fields_reads_as_newer() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (sb, _) = mkfs(&mut dev, &mut clk, &small()).unwrap();
        let enc = sb.encode();
        let end = (20..BLK - 4)
            .find(|&p| u32::from_le_bytes(enc[p..p + 4].try_into().unwrap()) == crc(&enc[..p]))
            .unwrap();
        // the newer layout: an unknown feature bit with a field of its own (all-zero high crc bytes covered too)
        let newer = |extra: u64| {
            let mut b = enc[..end].to_vec();
            b[12..20].copy_from_slice(&(sb.features | 1 << 40).to_le_bytes());
            b.extend_from_slice(&extra.to_le_bytes());
            let c = crc(&b);
            b.extend_from_slice(&c.to_le_bytes());
            b.resize(BLK, 0);
            b
        };
        let put = |copy: u64, b: &[u8]| {
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            Sio::new(&mut dev, &mut clk).write_one(copy, b).unwrap();
        };
        for extra in 0..64u64 {
            for copies in [&[0u64, 1][..], &[0], &[1]] {
                put(0, &enc);
                put(1, &enc);
                for &c in copies {
                    put(c, &newer(extra));
                }
                match read_super(&mut dev, &mut clk) {
                    Err(StoreError::Newer(m)) => {
                        assert!(m.contains("downgrade not possible"), "{m}")
                    }
                    r => panic!("copies {copies:?} extra {extra}: {r:?}"),
                }
            }
        }
        // bit rot in the feature field of copy 0: no crc verifies, copy 1 serves
        put(0, &enc);
        put(1, &enc);
        let mut rot = enc.clone();
        rot[17] ^= 0x01; // features bit 40
        put(0, &rot);
        assert_eq!(read_super(&mut dev, &mut clk).unwrap().0, sb);
    }

    /// C1: CRC-valid but out-of-range superblock values are `Corrupt` at read_super, never a panic or a wrapped
    /// address later in the mount.
    #[cfg(feature = "elastic")]
    #[test]
    fn crc_valid_out_of_range_superblock_is_corrupt() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let p = MkfsParams {
            chunked: true,
            chunk_blocks: 256,
            base_pct: 50,
            ..small()
        };
        let (sb, _) = mkfs(&mut dev, &mut clk, &p).unwrap();
        let put = |s: &Superblock| {
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            let mut io = Sio::new(&mut dev, &mut clk);
            io.write_one(0, &s.encode()).unwrap();
            io.write_one(1, &s.encode()).unwrap();
        };
        let mut s = sb.clone();
        s.chunk_blocks = 128;
        put(&s);
        match read_super(&mut dev, &mut clk) {
            Err(StoreError::Corrupt(m)) => assert!(m.contains("allocator window"), "{m}"),
            r => panic!("{r:?}"),
        }
        // an expansion whose extents wrap around the address space (or leave the store)
        let mut s = sb.clone();
        s.chunk_blocks = 0;
        s.base_pct = 0;
        s.features &= !FEAT_CHUNKED;
        s.features |= FEAT_EXPAND;
        let end = s.size_bytes / BLK as u64;
        for x in [
            Expansion {
                start: end,
                per_shard: u64::MAX / 2,
            },
            Expansion {
                start: end,
                per_shard: 1,
            },
        ] {
            s.expand = vec![x];
            put(&s);
            match read_super(&mut dev, &mut clk) {
                Err(StoreError::Corrupt(m)) => assert!(m.contains("beyond the store"), "{m}"),
                r => panic!("{x:?}: {r:?}"),
            }
        }
        put(&sb);
        assert_eq!(read_super(&mut dev, &mut clk).unwrap().0, sb);
    }

    /// C1c: a crc-valid superblock or directory whose geometry is out of range is `Corrupt` before any field sizes an
    /// allocation or an address (`shards`, directory, WAL, lba, store size, region carve-up are all raw disk input).
    #[test]
    fn crc_valid_damaged_geometry_is_corrupt() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (sb, dirs) = mkfs(&mut dev, &mut clk, &small()).unwrap();
        let dir_bytes = encode_dir(&dirs, sb.dir_blocks as usize * BLK);
        // `dir` is the block to put the directory bytes at (never the superblock field under test)
        let write = |s: &Superblock, dir: Option<(u64, &[u8])>| {
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            let mut io = Sio::new(&mut dev, &mut clk);
            io.write_one(0, &s.encode()).unwrap();
            io.write_one(1, &s.encode()).unwrap();
            if let Some((blk, dir)) = dir {
                io.write_one(blk, dir).unwrap();
            }
        };
        let mut check = |what: &str| match read_super(&mut dev, &mut clk) {
            Err(StoreError::Corrupt(_)) => {}
            r => panic!("{what}: {r:?}"),
        };
        for (what, f) in [
            (
                "no shards",
                &(|s: &mut Superblock| s.shards = 0) as &dyn Fn(&mut Superblock),
            ),
            ("shards above the limit", &|s: &mut Superblock| {
                s.shards = MAX_SHARDS + 1
            }),
            ("directory of 2^32 blocks", &|s: &mut Superblock| {
                s.dir_blocks = u32::MAX
            }),
            (
                "directory at the top of the address space",
                &|s: &mut Superblock| s.dir_blk = u64::MAX,
            ),
            ("no WAL blocks", &|s: &mut Superblock| s.wal_blocks = 0),
            (
                "lba size not a divisor of a block",
                &|s: &mut Superblock| s.lba_size = 3,
            ),
            ("store larger than the device", &|s: &mut Superblock| {
                s.size_bytes = u64::MAX
            }),
            ("meta cell of no pages", &|s: &mut Superblock| {
                s.cell_pages = 0
            }),
        ] {
            let mut s = sb.clone();
            f(&mut s);
            write(&s, Some((sb.dir_blk, &dir_bytes)));
            check(what);
        }
        for (what, f) in [
            (
                "data start at the top of the address space",
                &(|d: &mut ShardDir| d.data_start = u64::MAX) as &dyn Fn(&mut ShardDir),
            ),
            ("region wraps the address space", &|d: &mut ShardDir| {
                d.region_blocks = u64::MAX
            }),
            ("unbounded data region", &|d: &mut ShardDir| {
                d.data_blocks = u64::MAX
            }),
            ("root A not at the region start", &|d: &mut ShardDir| {
                d.root_a = 0
            }),
            ("WAL of another size", &|d: &mut ShardDir| d.wal_blocks = 0),
        ] {
            let mut ds = dirs.clone();
            f(&mut ds[0]);
            let bytes = encode_dir(&ds, dir_bytes.len());
            let mut s = sb.clone();
            s.dir_crc = crc(&bytes);
            write(&s, Some((sb.dir_blk, &bytes)));
            check(what);
        }
        // control: the store as mkfs wrote it mounts
        write(&sb, Some((sb.dir_blk, &dir_bytes)));
        assert_eq!(read_super(&mut dev, &mut clk).unwrap().0, sb);
    }

    /// S5: a chunked shard whose data space holds no whole base chunk is refused by `plan`: mkfs never writes a
    /// directory its own `read_super` refuses (or an allocator over an empty base).
    #[cfg(feature = "elastic")]
    #[test]
    fn chunked_plan_refuses_a_shard_without_a_base_chunk() {
        // 64 MiB, 4 shards of 4080 blocks: 3700 data blocks = 3 chunks of 1024, 25 % of them rounds to no base chunk
        let p = MkfsParams {
            chunked: true,
            chunk_blocks: 1024,
            base_pct: 25,
            ..small()
        };
        match plan(64 << 8, &p) {
            Err(StoreError::BadGeometry(m)) => assert!(m.contains("base_pct"), "{m}"),
            r => panic!("{r:?}"),
        }
        // a chunk below the data space leaves no whole chunk at all, also at the largest base
        let p = MkfsParams {
            chunk_blocks: 2048,
            base_pct: 90,
            ..p
        };
        assert!(plan(64 << 8, &p).is_err());
        // 3 chunks at 50 % keep one base chunk and the pool floor of two: mkfs writes what the mount accepts
        let p = MkfsParams {
            chunk_blocks: 1024,
            base_pct: 50,
            ..p
        };
        let (_, dirs) = plan(64 << 8, &p).unwrap();
        assert!(dirs.iter().all(|d| d.data_blocks == 1024));
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (sb, dirs2) = mkfs(&mut dev, &mut clk, &p).unwrap();
        assert_eq!(dirs, dirs2, "mkfs writes the planned directory");
        assert_eq!((sb.chunk_blocks, sb.base_pct), (1024, 50));
        assert_eq!(read_super(&mut dev, &mut clk).unwrap(), (sb, dirs2));
    }

    #[test]
    fn root_slot_crc_and_ab() {
        let r = RootSlot {
            shard: 3,
            seq: 9,
            epoch: 2,
            ckpt_lsn: 77,
            wal_tail_pos: 5,
            ..Default::default()
        };
        let mut b = r.encode();
        // the plain form decodes with the tail and run floor at ckpt_lsn + 1 and encodes the same bytes
        let plain = RootSlot {
            wal_tail_lsn: 78,
            run_floor: 78,
            ..r.clone()
        };
        assert_eq!(RootSlot::decode(&b), Some(plain.clone()));
        assert_eq!(plain.encode(), b);
        b[10] ^= 1;
        assert_eq!(RootSlot::decode(&b), None);
        assert_eq!(RootSlot::decode(&vec![0; BLK]), None);
        // run floor below the checkpoint: second form, round trip
        let f = RootSlot {
            wal_tail_lsn: 40,
            run_floor: 41,
            ..r.clone()
        };
        let b = f.encode();
        assert_eq!(u32::from_le_bytes(b[..4].try_into().unwrap()), ROOT_MAGIC2);
        assert_eq!(RootSlot::decode(&b), Some(f.clone()));
        // a tail after the floor, or a floor past the checkpoint, is not a valid slot
        let bad = RootSlot {
            wal_tail_lsn: 42,
            ..f.clone()
        };
        assert_eq!(RootSlot::decode(&bad.encode()), None);
        let bad = RootSlot { run_floor: 79, ..f };
        assert_eq!(RootSlot::decode(&bad.encode()), None);
        // the last representable lsn has no successor: its replay chain start cannot be recorded, so such a slot is a
        // damaged copy (the arithmetic must not wrap)
        let top = RootSlot {
            ckpt_lsn: u64::MAX,
            wal_tail_lsn: 1,
            run_floor: 1,
            ..r.clone()
        };
        assert_eq!(RootSlot::decode(&top.encode()), None);
        let top = RootSlot {
            ckpt_lsn: u64::MAX,
            ..r
        };
        assert_eq!(RootSlot::decode(&top.encode()), None);
    }

    /// The DSM probe verdict (adr 0169 am. 8) round-trips through mkfs and read; a store formatted without a probe has no
    /// verdict and no bit (what a store from before the probe reads as); a bit without a verdict byte is a damaged copy.
    #[test]
    fn dsm_verdict_roundtrip() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (sb, _) = mkfs(&mut dev, &mut clk, &small()).unwrap();
        assert_eq!((sb.dsm_verdict, sb.features & FEAT_DSM_VERDICT), (None, 0));
        for v in [false, true] {
            let mut p = small();
            p.dsm_verdict = Some(v);
            let (sb, _) = mkfs(&mut dev, &mut clk, &p).unwrap();
            assert_eq!(sb.features & FEAT_DSM_VERDICT, FEAT_DSM_VERDICT);
            let (sb2, _) = read_super(&mut dev, &mut clk).unwrap();
            assert_eq!((sb2.dsm_verdict, sb2.clone()), (Some(v), sb));
            assert!(
                feature_names(sb2.features)
                    .iter()
                    .any(|f| f == "dsm_verdict")
            );
        }
        let (mut sb, _) = read_super(&mut dev, &mut clk).unwrap();
        sb.dsm_verdict = None;
        assert_eq!(Superblock::decode(&sb.encode()), None);
        sb.features &= !FEAT_DSM_VERDICT;
        let (sb2, _) = {
            heal_super(&mut dev, &mut clk, &sb).unwrap();
            read_super(&mut dev, &mut clk).unwrap()
        };
        assert_eq!(
            (sb2.dsm_verdict, sb2.features & FEAT_DSM_VERDICT),
            (None, 0)
        );
    }

    #[test]
    fn mkfs_rejects_volatile_cache_and_tiny() {
        let mut cfg = SimConfig::new(64 << 20);
        cfg.vwc = true;
        let disk = SimDisk::new(cfg);
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        assert_eq!(
            mkfs(&mut dev, &mut clk, &small()).unwrap_err(),
            StoreError::VolatileCache
        );
        let mut p = small();
        p.allow_volatile_cache = true;
        let (sb, _) = mkfs(&mut dev, &mut clk, &p).unwrap();
        assert!(!sb.plp);
        let disk = SimDisk::new(SimConfig::new(1 << 20));
        assert!(matches!(
            mkfs(&mut disk.queue(), &mut clk, &small()),
            Err(StoreError::BadGeometry(_))
        ));
    }

    #[test]
    fn works_on_512_byte_lbas() {
        let mut cfg = SimConfig::new(64 << 20);
        cfg.lba_size = 512;
        cfg.lba_count = (64 << 20) / 512;
        cfg.max_xfer_lbas = 256;
        let disk = SimDisk::new(cfg);
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        mkfs(&mut dev, &mut clk, &small()).unwrap();
        let (sb, dirs) = read_super(&mut dev, &mut clk).unwrap();
        assert_eq!(sb.lba_size, 512);
        read_root(&mut dev, &mut clk, &dirs[0]).unwrap();
    }
}
