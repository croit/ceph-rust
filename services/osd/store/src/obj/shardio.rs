// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! One shard + the blocking glue the object layer needs: event pump, waits, tree get/scan with miss
//! handling, device reads, "written but not yet durable" tracking.

use super::keys::{T_COLL, T_LNAME, T_NAME, T_ONODE};
use super::{ObjError, Result};
use crate::BLK;
use crate::codec::blk_seed;
use crate::dev::{BlockDev, Clock, IoBuf, IoError};
use crate::error::StoreError;
use crate::fx::{FxMap, FxSet};
use crate::shard::{Event, PF_TOKEN, Shard};
use crate::sio::Stall;
use crate::tree::{ScanCursor, ScanStatus};
use bytes::Bytes;
use std::collections::{BTreeMap, VecDeque};
use std::mem::MaybeUninit;

/// A piece of a shared read result ([`ShardStore::read_runs_shared`]): blocks `[dst, dst + data.len() / BLK)` of the read
/// (the runs' destination numbering), device block `pba` first; their crcs sit at `ci..` of the returned crc vector.
#[derive(Clone, Debug)]
pub struct Seg {
    pub dst: usize,
    pub pba: u64,
    pub ci: usize,
    pub data: Bytes,
}

/// Destination of a device read ([`ShardStore::read_runs_into`] / [`ShardStore::read_runs_shared`]).
pub(crate) enum Out<'a> {
    /// One buffer, run data at `dst_blk * BLK` (copied, fused with the block crcs).
    Flat(&'a mut [MaybeUninit<u8>]),
    /// Segments: immutable whole device buffers or exact slices of retained prefetch buffers.
    Shared(&'a mut Vec<Seg>),
}

impl Out<'_> {
    fn sink(&mut self, dst: usize, n: usize, ci: usize) -> Sink<'_> {
        match self {
            Out::Flat(o) => Sink::Copy(&mut o[dst * BLK..(dst + n) * BLK]),
            Out::Shared(segs) => Sink::Share { segs, dst, ci },
        }
    }
}

/// Where the blocks of one device command / prefetch run go.
pub(crate) enum Sink<'a> {
    /// Copied into this slice, fused with the block crcs.
    Copy(&'a mut [MaybeUninit<u8>]),
    /// Appended as a [`Seg`] at block `dst` (crc index `ci`).
    Share {
        segs: &'a mut Vec<Seg>,
        dst: usize,
        ci: usize,
    },
}

impl Sink<'_> {
    /// Deliver bytes that are exactly this command's / run's blocks: shared by reference (block crcs computed in place,
    /// no copy) or copied into the flat destination.
    fn whole(self, data: Bytes, pba: u64, known: Option<&[u32]>, crcs: &mut [u32]) {
        match self {
            Sink::Copy(d) => fill(&data, pba, d, known, crcs),
            Sink::Share { segs, dst, ci } => {
                match known {
                    Some(k) => crcs.copy_from_slice(k),
                    None => crc_in_place(&data, pba, crcs),
                }
                segs.push(Seg { dst, pba, ci, data });
            }
        }
    }

    /// [`Sink::whole`] for a completed device buffer: it becomes the shared bytes only when shared.
    fn buf<B: IoBuf + Send + 'static>(self, b: B, pba: u64, crcs: &mut [u32]) {
        match self {
            Sink::Copy(d) => crc_copy(b.as_slice(), pba, d, crcs),
            s => s.whole(b.into_shared(), pba, None, crcs),
        }
    }
}

/// `src` into `dst` and its block crcs into `crcs`: `known` (computed when the device read completed) are taken over, else
/// the crcs come from the copy pass.
fn fill(
    src: &[u8],
    pba: u64,
    dst: &mut [MaybeUninit<u8>],
    known: Option<&[u32]>,
    crcs: &mut [u32],
) {
    match known {
        None => crc_copy(src, pba, dst, crcs),
        Some(k) => {
            // SAFETY: `MaybeUninit<u8>` has the layout of `u8`; the shared view is only read.
            let s = unsafe { &*(std::ptr::from_ref(src) as *const [MaybeUninit<u8>]) };
            dst.copy_from_slice(s);
            crcs.copy_from_slice(k);
        }
    }
}

/// Block crcs (seeded with the engine block address, `codec::blk_crc`) of `src` from device block `pba` on, copied to `dst`
/// in the same pass.
fn crc_copy(src: &[u8], pba: u64, dst: &mut [MaybeUninit<u8>], crcs: &mut [u32]) {
    let d = dst.as_chunks_mut::<BLK>().0.iter_mut();
    for (i, (s, d)) in src.as_chunks::<BLK>().0.iter().zip(d).enumerate() {
        crcs[i] = crc::crc32c_copy_uninit(blk_seed(pba + i as u64), s, d);
    }
}

/// Block crcs of `data` (from device block `pba` on) without moving it.
fn crc_in_place(data: &[u8], pba: u64, crcs: &mut [u32]) {
    for (i, b) in data.as_chunks::<BLK>().0.iter().enumerate() {
        crcs[i] = crc::crc32c(blk_seed(pba + i as u64), b);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ObjStats {
    pub txns: u64,
    pub read_ios: u64,
    pub read_blocks: u64,
    pub crc_errors: u64,
    pub durable_waits: u64,
    /// Objects whose data was written inline into the tree (adr 0021 am. 14) / inline objects that outgrew the threshold.
    pub inline_writes: u64,
    /// Omap / xattr / header values written as data blocks (adr 0021 am. 46).
    pub ext_values: u64,
    /// User omap values (counted objects; not PG logs) stored compressed (adr 0021 am. 58) and the bytes that saved.
    pub val_comp: u64,
    pub val_comp_saved: u64,
    /// Value-compression dictionaries this shard installed (adr 0021 am. 58).
    pub dict_installs: u64,
    pub inline_promotions: u64,
    /// Compression (adr 0059 am. 1): chunks stored compressed / rejected (ratio or no room) / decompressed on read.
    pub comp_ok: u64,
    pub comp_rejected: u64,
    /// Chunks skipped by the incompressibility sample (no full compress run).
    pub comp_sampled_out: u64,
    /// Windows of compressed chunks rewritten by the chunk space rule (adr 0059 am. 4; BlueStore `gc_merged`).
    pub comp_gc: u64,
    /// Compressed records cut into windows (adr 0059 am. 4).
    pub comp_windows: u64,
    pub decomp: u64,
    /// Time spent compressing (samples included) / decompressing, ns.
    pub comp_ns: u64,
    pub decomp_ns: u64,
    /// Clones that shared the source's extents instead of copying (adr 0021 am. 32).
    pub shared_clones: u64,
    /// `clone_range` ops that shared the aligned middle instead of copying (adr 0021 am. 38).
    pub shared_ranges: u64,
    /// Bytes copied/CRCed into new device data buffers during staging (including preflight).
    pub staged_data_bytes: u64,
    /// Payload bytes written to the device by reference (zero copy, adr 0061 am. 4).
    pub zc_data_bytes: u64,
    /// Data bytes staged as deferred copies ([`crate::shard::CopyRun`]): the DMA budget refused the staging copy, the
    /// shard copies them right before their device write (adr 0175 am. 4).
    pub deferred_copy_bytes: u64,
    /// Data bytes whose block crcs came from the receive pass (no crc pass, adr 0061 am. 4).
    pub crc_reused_bytes: u64,
    /// Placement bytes covered by a shifted receipt CRC grid.
    pub placement_crc_reblocked_bytes: u64,
    /// Source bytes newly hashed to construct shifted receipt CRCs.
    pub placement_crc_hashed_bytes: u64,
    /// Omap batches staged as runs (adr 0476), and queued txns that waited for run room (a compaction or run merges).
    pub run_puts: u64,
    pub run_waits: u64,
    /// Of `run_puts`: removal batches staged as runs of removals (adr 0647-omap-blind-removals).
    pub run_rms: u64,
    /// Listing passes of executor requests (adr 0021 S8) that continued a scan memo after a refusal or a slice, and passes
    /// that ended in a slice (budget used, the request runs again at the next poll).
    pub scan_resumes: u64,
    pub scan_slices: u64,
}

/// What an operator cache drop released ([`ShardStore::drop_caches`]); also its running total (`dropped`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CacheDropped {
    /// Clean tree pages evicted / pages that had to stay (dirty, in flight, held by a checkpoint, pinned; of the last drop,
    /// not summed).
    pub tree_pages: u64,
    pub tree_kept: u64,
    pub tree_bytes: u64,
    /// Data cache runs and their bytes.
    pub data_runs: u64,
    pub data_bytes: u64,
    /// Decoded compressed chunks and their bytes.
    pub decomp_entries: u64,
    pub decomp_bytes: u64,
    /// Bytes of the clean omap run cache.
    pub omap_run_bytes: u64,
}

impl CacheDropped {
    pub(crate) fn add(&mut self, o: &CacheDropped) {
        self.tree_pages += o.tree_pages;
        self.tree_bytes += o.tree_bytes;
        self.data_runs += o.data_runs;
        self.data_bytes += o.data_bytes;
        self.decomp_entries += o.decomp_entries;
        self.decomp_bytes += o.decomp_bytes;
        self.omap_run_bytes += o.omap_run_bytes;
    }
}

pub struct ShardStore<D: BlockDev> {
    pub sh: Shard<D>,
    pub idx: u32,
    /// Capacity of the device when the shard was opened (compared with the size mkfs recorded, [`Store::size_mismatch`]).
    pub dev_bytes: u64,
    pub(crate) tok: u64,
    pub(crate) acked: Vec<u64>,
    pub(crate) reads: FxMap<u64, std::result::Result<D::Buf, IoError>>,
    /// Sync read tokens whose wait gave up (`read_runs_inner`): their completions are dropped on arrival.
    abandoned: std::collections::HashSet<u64, crate::fx::FxBuild>,
    rolling: Vec<RollingRead>,
    rolling_tokens: FxMap<u64, usize>,
    read_session: Option<(u64, u64)>,
    wake: bool,
    pub(crate) released: u64,
    /// onode id -> LSN of its newest (possibly not yet durable) data write.
    wlsn: FxMap<u64, u64>,
    wq: VecDeque<(u64, u64)>,
    /// A `warm_data` refused an op because its object has an undurable write: wake the gate when writes become durable.
    wl_wait: bool,
    pub max_xfer_blk: usize,
    /// Largest object (bytes) whose data is kept inline in the tree; 0 = off (store without `FEAT_INLINE_DATA`).
    pub inline_max: usize,
    /// Omap / xattr / header values of at least this many bytes go to data blocks (adr 0021 am. 46); 0 = never (store without
    /// `FEAT_EXT_VALUE` or the setting off).
    pub val_ext_min: usize,
    /// User omap values (counted objects; not PG logs) of at least this many bytes are tried for inline zstd compression (adr 0021 am. 58; store with
    /// `FEAT_VAL_COMP`); 0 = off.
    pub val_comp_min: usize,
    /// Samples a class collects before its dictionary is trained.
    pub val_dict_samples: usize,
    /// Adaptive sampling of the attempts per value class.
    pub vc: super::onode::VcAdapt,
    /// Classes whose dictionary is known absent from the tree (bit per class; only this shard installs them).
    pub vc_absent: u64,
    /// Training samples per value class (up to `DICT_SAMPLES`), and the dictionaries trained from them that the tree does not hold yet.
    pub vc_samples: Vec<Vec<Vec<u8>>>,
    pub vc_trained: Vec<Option<std::sync::Arc<super::onode::ZDict>>>,
    /// Omap keys live in the shard's LSM engine (store with `FEAT_OMAP_LSM`, adr 0610); the header stays in the tree.
    pub omap_lsm: bool,
    /// Client omap batches of pool objects may be logged as runs (store with `FEAT_OMAP_RUNS`, not with the LSM engine,
    /// `ShardCfg::run_soft_bytes` > 0; adr 0476), batches of at least `run_min` keys.
    pub omap_runs: bool,
    pub run_min: usize,
    /// Names too long for the `N` index go to `L` (store with `FEAT_LONG_NAME`, adr 0021 am. 30); without it they are refused.
    pub long_names: bool,
    /// Compressed extents may be written: `FEAT_COMPRESSION` is durable in the superblock. Until then a chunk that would
    /// compress is stored raw and sets `comp_wanted` (the store makes the bit durable and stages the txn again).
    pub compression: bool,
    pub(crate) comp_wanted: bool,
    /// Setting the bit failed (device error, drain timeout): stay raw until the next mount.
    pub(crate) comp_off: bool,
    /// `FEAT_DEDUP` is durable (adr 0593-dedup-deep-scrub-reformat): data version tracking and dedup records may be written.
    pub dedup: bool,
    /// The store has `FEAT_SHARED_EXT` (adr 0021 am. 32; mkfs). Without it clones copy eagerly.
    pub shared_ext: bool,
    /// `ShardCfg::shared_clone` off, or the store lacks `FEAT_SHARED_EXT`: clones copy eagerly.
    pub(crate) share_off: bool,
    /// `ShardCfg::pf_retain`: runs that served a read whole stay in the data cache (`dc`, adr 0043 "Data cache").
    pub(crate) pf_retain: bool,
    /// Decompressed chunks of recent reads (adr 0059 am. 1).
    pub(crate) dcache: crate::compress::DecompCache,
    pub(crate) codec: crate::compress::SoftCodec,
    pub(crate) cbuf: Vec<u8>,
    pub(crate) pbuf: Vec<u8>,
    pub(crate) decbuf: Vec<u8>,
    /// The `L` index of this shard is known to be empty (one probe; cleared when a txn stages an `L` key): list and rmcoll skip it.
    pub(crate) long_none: bool,
    pub stats: ObjStats,
    pub(crate) scratch: super::stage::Scratch,
    /// Data prefetch table (client reads, ADR 0021 am. 9), keyed by first device block.
    pf: BTreeMap<u64, Pf<D::Buf>>,
    /// Time of the last `pump_at`.
    now: u64,
    /// Blocks held by `pf` entries (leased ready runs excepted: `pf_leased`).
    pf_blocks: u64,
    /// Completed prefetch errors still awaiting a reader; avoids scanning healthy reads.
    pf_errors: usize,
    /// Ready runs a residency lease holds (adr 0043 am. 18): (entries, blocks). They wait for their op, not for capacity,
    /// so they never count against the admission caps (a held op never blocks the admission of another).
    pf_leased: (usize, u64),
    /// Generation of the next `pf` entry (a lease names the entry it holds, not a later one at the same block).
    pf_gen: u64,
    /// Residency leases of ops that wait for their loads (adr 0043 am. 18): what each one pins.
    leases: FxMap<u64, Lease>,
    /// Lease of the probe in progress (0 = none, [`super::Store::lease_use`]).
    pub(crate) lease: u64,
    /// Miss buffer of the leased probes, reused (`Shard::pin_log`).
    pub(crate) pin_scratch: Vec<u64>,
    /// Data cache (pinless, invalidated by frees): runs that served a read. Capacity [`ShardStore::dc_cap`]: the floor
    /// plus the unused tree page budget (adr 0633-data-cache-envelope), shared with `pf`; evicted first when an admission
    /// needs the room.
    pub(crate) dc: super::datacache::DataCache,
    /// Running total of the operator cache drops.
    pub(crate) dropped: CacheDropped,
    /// Operator cache drops run.
    pub(crate) drops: u64,
    /// The probe of the client read that runs next, when it found the whole range in `dc` (single use, see [`HotProbe`]).
    pub(crate) hot: Option<super::stage::HotProbe>,
    /// Prefetch admission queue: ops denied capacity, in first-denial order (`pf_admit`).
    pf_q: VecDeque<PfWait>,
    /// Commands still in flight per submission batch (`Pf::batch`): the batch wakes its ops once, when the last one completes.
    pf_batch: FxMap<u64, u32>,
    /// Reused event buffer of `pump_at`.
    evbuf: Vec<Event<D::Buf>>,
    /// Non-blocking mode ([`Store::warm`]): a tree miss returns `WouldBlock` instead of spinning (ADR 0021 am. 8).
    pub(crate) nonblock: bool,
    /// A blocking queue barrier (`Store::drain_queued`) holds the core: a parked txn takes the tree path instead of waiting
    /// for run room, since nothing else runs on the core while it waits.
    pub(crate) barrier: bool,
    /// Explicit media verification: bypass client prefetch and decompressed cache.
    pub(crate) media: bool,
    /// A page load finished since `Store::poll` last looked (parked ops may run).
    pub(crate) woke: bool,
    /// Specific wakes since `Store::poll` last looked: tree pages loaded, prefetch runs completed (adr 0043 am. 9).
    pub(crate) wtoks: crate::toks::Toks<16>,
    /// Prefetch runs the current probe waits on or submitted (see [`ShardStore::cause_begin`]).
    clog: std::cell::Cell<crate::toks::Toks<8>>,
    /// A refused run made progress since `Store::take_rm_progress` last looked (listing slice, data admission).
    pub(crate) rm_progress: bool,
    #[cfg(feature = "splinterdb")]
    pub(crate) local_wait: bool,
    /// Listings of executor requests in progress (adr 0021 S8), at most one per (request, object, scan).
    pub(crate) memos: Vec<ScanMemo>,
    #[cfg(feature = "rocksdb")]
    pub(crate) rocks_memos: Vec<RocksScanMemo>,
    /// Key enumerations of the FIFO head's point range removals stopped by cold reads ([`RangeMemo`]), at most one per
    /// (staging session, operation).
    range_memos: Vec<RangeMemo>,
    #[cfg(feature = "splinterdb")]
    pub(crate) splinter_memos: Vec<SplinterScanMemo>,
    /// Sequence of listing slices: wake token of the next slice (`toks::tok_slice`).
    slice_seq: u64,
    /// Objects listed by the current run of an executor request (object listings slice on it, adr 0021 S8).
    pub(crate) pass_listed: usize,
    /// The current run of an executor request lists without CPU slice ([`crate::obj::Store::list_whole`]); every run
    /// starts sliced.
    pub(crate) list_whole: bool,
    /// Park barriers of listing requests `(session, last park seq when it first listed, touched)` (`Store::list`).
    list_barriers: Vec<((u64, u64), u64, u64)>,
    /// An op was refused a rolling slot (all `ROLLING_READS` sessions busy): the next release wakes the gate. Releases wake
    /// nobody else: a wake probes every parked op, O(runs) each, so one per finished read was quadratic in the readers.
    rolling_wait: bool,
    /// Device reads of the FIFO head's own sessions completed: progress of a parked head (`Store::resume_queue` stall
    /// clock).
    pub(crate) head_reads: u64,
    /// Tree pages loaded (`Event::Page`).
    pub(crate) pages_loaded: u64,
    /// Origin of the last `WouldBlock` this shard returned (diagnostics: `tell dump_pgs` store_diag of a parked FIFO head).
    pub(crate) wb_why: &'static str,
    /// The omap run admission (object, WAL op bytes) of the last `WouldBlock` when it came from run room
    /// ([`Shard::run_admit_blocks`]); `None` for every other origin.
    pub(crate) wb_run: Option<(u64, usize)>,
    /// Free-space defragmentation (adr 0021 am. 33): switch and sweep state.
    pub defrag: bool,
    pub(crate) df: super::defrag::Defrag<D::Buf>,
    /// Idle recompaction and extent census (adr 0533).
    pub(crate) rc: super::recompact::Rc,
}

/// Owned worker output across fair owner slices, never a live database iterator.
#[cfg(feature = "rocksdb")]
pub(crate) struct EnginePage {
    entries: crate::rocks_omap::PageEntries,
    next: usize,
    pub end: crate::rocks_omap::PageEnd,
    charge: usize,
}
#[cfg(feature = "rocksdb")]
impl EnginePage {
    pub fn new(entries: crate::rocks_omap::PageEntries, end: crate::rocks_omap::PageEnd) -> Self {
        let charge = entries
            .bytes()
            .saturating_add(128)
            .saturating_add(match &end {
                crate::rocks_omap::PageEnd::Next(k) => k.len().saturating_add(32),
                _ => 0,
            });
        Self {
            entries,
            next: 0,
            end,
            charge,
        }
    }
    pub fn peek(&self) -> Option<(&[u8], &[u8])> {
        self.entries.get(self.next)
    }
    pub fn last(&self) -> bool {
        self.next + 1 == self.entries.len()
    }
    pub fn advance(&mut self) {
        self.next += 1;
    }
}

#[cfg(all(test, feature = "rocksdb"))]
#[test]
fn engine_page_retains_full_backing_charge_through_consumption() {
    let entries = crate::rocks_omap::PageEntries::test_from_pairs(&[
        (b"one", &[1; 1024]),
        (b"two", &[2; 2048]),
    ]);
    let backing = entries.bytes();
    let mut page = EnginePage::new(
        entries,
        crate::rocks_omap::PageEnd::Next(Bytes::from_static(b"three")),
    );
    let expected = backing + 128 + 5 + 32;
    for (index, key) in [b"one", b"two"].into_iter().enumerate() {
        assert_eq!(page.peek().unwrap().0, key);
        assert_eq!(page.last(), index == 1);
        page.advance();
        assert_eq!(page.charge, expected);
    }
    assert!(page.peek().is_none());
    assert_eq!(page.charge, expected);
}

/// Identity of a point range removal's key enumeration inside a staging session: the removal of `[first, last)` of
/// object `id` that is operation `seq` of the transaction. The operation index is the same on every retry whatever
/// strategy earlier operations select, so a saved enumeration is only ever continued by the operation that started it.
pub(crate) struct RangeKey<'a> {
    pub session: (u64, u64),
    pub seq: u32,
    pub id: u64,
    pub first: &'a [u8],
    pub last: &'a [u8],
}

/// Progress of a point range removal's key enumeration (adr 0660 am. 2): the shard FIFO head stages without blocking,
/// a cold run chunk refuses the whole transaction, and its retry re-applies every operation. The keys found so far and
/// the resume position survive here, so the retry continues the enumeration instead of rescanning the range. Valid
/// only while the engine's newest omap op is unchanged (`generation`): flushes and merges move data without changing it, so a
/// key-position continuation stays exact across them. The memo also carries the point-path decision: a retry under the
/// same `threshold` reuses it instead of recomputing the resident upper bound on every attempt.
pub(crate) struct RangeMemo {
    pub session: (u64, u64),
    pub seq: u32,
    pub id: u64,
    pub first: Bytes,
    pub last: Bytes,
    pub generation: u64,
    /// `flashstore_omap_delete_range_threshold` the point path was selected under (also its key limit).
    pub threshold: u64,
    pub keys: Vec<Bytes>,
    pub key_bytes: u64,
    pub cur: Bytes,
    pub excl: bool,
}

/// What one executor request's omap listing (adr 0021 S8) admitted so far and where it continues: a refused (cold leaf)
/// or sliced pass keeps it, the next run of the request continues it instead of starting over. The request is identified
/// by its read session (`(conn, tid)`, [`ShardStore::read_session`]) and the scan's parameters. Dropped when the request
/// ends (session closed without `keep`), by any mutation of the object ([`ShardStore::memo_drop`]), or after
/// `PF_TTL_NS` untouched (request dropped while parked).
pub(crate) struct ScanMemo {
    pub session: (u64, u64),
    pub id: u64,
    /// The scan: first key, prefix, entry and byte budget, mode (stage `OmapScanMode`).
    pub from: Vec<u8>,
    pub prefix: Vec<u8>,
    pub max: usize,
    pub max_bytes: usize,
    pub mode: u8,
    /// Reserved bytes in front of the listing (`Stage::scan_omap_enc`).
    pub head: usize,
    pub cur: ScanCursor,
    /// Omap LSM engine listing (`cur` unused): the key it continues at ([`crate::olsm::read::ListPos`]).
    pub lsm: Option<crate::olsm::read::ListPos>,
    /// Admitted entries, encoded (`head` reserved bytes, then `le32 len, key [, le32 len, value]` per entry).
    pub enc: Vec<u8>,
    /// Entries in `enc`.
    pub n: usize,
    /// Admitted entries whose value is read at the end (fragment / data-block / slow-path forms): position in `enc`
    /// where the value goes (right after its key), key length.
    pub holes: Vec<(usize, u32)>,
    /// Values of `holes` read so far, in order.
    pub hole_vals: Vec<Vec<u8>>,
    pub bytes: usize,
    /// The key walk ended (`Some(next)`): only the values of `holes` are left to read.
    pub walked: Option<Option<Vec<u8>>>,
    pub touched: u64,
}
#[cfg(feature = "rocksdb")]
pub(crate) struct RocksScanMemo {
    pub scan: ScanMemo,
    /// Complete immutable listing reply with exact-length backing. Writable
    /// listing callers keep using `scan.enc`.
    pub reply: Option<Bytes>,
    pub engine_page: Option<EnginePage>,
    pub engine_cursor: Option<(Bytes, bool)>,
    pub engine_revision: u64,
}

#[cfg(feature = "splinterdb")]
pub(crate) struct SplinterScanMemo {
    pub scan: ScanMemo,
    pub engine_cursor: Option<(Bytes, bool)>,
    pub engine_revision: u64,
}
#[cfg(feature = "splinterdb")]
impl std::ops::Deref for SplinterScanMemo {
    type Target = ScanMemo;
    fn deref(&self) -> &ScanMemo {
        &self.scan
    }
}
#[cfg(feature = "splinterdb")]
impl std::ops::DerefMut for SplinterScanMemo {
    fn deref_mut(&mut self) -> &mut ScanMemo {
        &mut self.scan
    }
}
#[cfg(feature = "splinterdb")]
impl SplinterScanMemo {
    pub(crate) fn engine_charge(&self) -> usize {
        if self.engine_cursor.is_none() {
            return 0;
        }
        self.enc
            .capacity()
            .saturating_mul(4)
            .saturating_add(self.n.saturating_mul(128))
            .saturating_add(self.from.len() + self.prefix.len() + 256)
    }
}
#[cfg(feature = "rocksdb")]
impl std::ops::Deref for RocksScanMemo {
    type Target = ScanMemo;
    fn deref(&self) -> &ScanMemo {
        &self.scan
    }
}
#[cfg(feature = "rocksdb")]
impl std::ops::DerefMut for RocksScanMemo {
    fn deref_mut(&mut self) -> &mut ScanMemo {
        &mut self.scan
    }
}
#[cfg(feature = "rocksdb")]
impl RocksScanMemo {
    pub(crate) fn engine_charge(&self) -> usize {
        if self.engine_cursor.is_none() {
            return 0;
        }
        // Retained encoding, return clone/decoded output, and allocation growth.
        self.enc
            .capacity()
            .saturating_add(self.reply.as_ref().map_or(0, Bytes::len))
            .saturating_mul(4)
            .saturating_add(self.n.saturating_mul(128))
            .saturating_add(self.engine_page.as_ref().map_or(0, |p| p.charge))
            .saturating_add(self.from.len() + self.prefix.len() + 256)
            .saturating_add(
                self.walked
                    .as_ref()
                    .and_then(|k| k.as_ref())
                    .map_or(0, |k| k.capacity().saturating_mul(4)),
            )
    }
}

impl<D: BlockDev> std::fmt::Debug for ShardStore<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ShardStore#{}", self.idx)
    }
}

impl<D: BlockDev> ShardStore<D> {
    pub fn new(sh: Shard<D>, idx: u32) -> ShardStore<D> {
        let mut sh = sh;
        sh.enable_point_cache(&[T_COLL, T_NAME, T_LNAME, T_ONODE]);
        let g = sh.dev().geometry();
        let dev_bytes = g.capacity_bytes();
        ShardStore {
            idx,
            dev_bytes,
            tok: 0,
            acked: Vec::new(),
            reads: FxMap::default(),
            abandoned: Default::default(),
            rolling: Vec::new(),
            rolling_tokens: Default::default(),
            read_session: None,
            wake: false,
            released: 0,
            wlsn: FxMap::default(),
            wl_wait: false,
            wq: VecDeque::new(),
            max_xfer_blk: crate::dev::max_xfer_blks(&g) as usize,
            inline_max: 0,
            val_ext_min: 0,
            val_comp_min: 0,
            val_dict_samples: super::onode::DICT_SAMPLES,
            vc: super::onode::VcAdapt::default(),
            vc_absent: 0,
            vc_samples: vec![Vec::new(); super::onode::DICT_CLASSES],
            vc_trained: vec![None; super::onode::DICT_CLASSES],
            omap_lsm: false,
            omap_runs: false,
            run_min: 64,
            long_names: false,
            compression: false,
            comp_wanted: false,
            comp_off: false,
            shared_ext: false,
            share_off: false,
            pf_retain: false,
            dcache: Default::default(),
            codec: Default::default(),
            cbuf: Vec::new(),
            pbuf: Vec::new(),
            decbuf: Vec::new(),
            long_none: false,
            stats: ObjStats::default(),
            scratch: Default::default(),
            evbuf: Vec::new(),
            pf: BTreeMap::new(),
            now: 0,
            pf_blocks: 0,
            pf_errors: 0,
            pf_leased: (0, 0),
            pf_gen: 0,
            leases: Default::default(),
            lease: 0,
            pin_scratch: Vec::new(),
            dc: Default::default(),
            dropped: CacheDropped::default(),
            drops: 0,
            hot: None,
            pf_q: VecDeque::new(),
            pf_batch: Default::default(),
            nonblock: false,
            barrier: false,
            media: false,
            woke: false,
            wtoks: Default::default(),
            clog: Default::default(),
            rm_progress: false,
            #[cfg(feature = "splinterdb")]
            local_wait: false,
            memos: Vec::new(),
            #[cfg(feature = "rocksdb")]
            rocks_memos: Vec::new(),
            range_memos: Vec::new(),
            #[cfg(feature = "splinterdb")]
            splinter_memos: Vec::new(),
            slice_seq: 0,
            pass_listed: 0,
            list_whole: false,
            list_barriers: Vec::new(),
            rolling_wait: false,
            head_reads: 0,
            pages_loaded: 0,
            wb_why: "",
            wb_run: None,
            defrag: false,
            df: Default::default(),
            rc: Default::default(),
            dedup: false,
            sh,
        }
    }

    /// One poll: reaps device completions and shard events (acks go to the ack list).
    /// Poll the shard; true when it reported an event.
    pub fn pump<C: Clock>(&mut self, clk: &mut C) -> Result<bool> {
        let now = clk.now();
        self.pump_at(now)
    }

    /// [`ShardStore::pump`] with the caller-supplied time (one clock read for all shards of a `Store::poll`).
    pub fn pump_at(&mut self, now: u64) -> Result<bool> {
        self.now = now;
        let mut ev = std::mem::take(&mut self.evbuf);
        self.sh.poll(now, &mut ev);
        let events = !ev.is_empty();
        if !ev.is_empty() && !self.pf_q.is_empty() {
            // any completion may have freed device queue slots a waiting prefetch needs
            self.woke = true;
        }
        for e in ev.drain(..) {
            match e {
                // defrag moves (adr 0021 am. 33) are the store's own txns: never reported
                Event::Acked(t) if t & super::defrag::DF_ACK != 0 => {}
                Event::Acked(t) => self.acked.push(t),
                Event::Read { token, result } if token & PF_TOKEN != 0 => {
                    self.pf_done(token & !PF_TOKEN, result);
                }
                Event::Read { token, result } => {
                    if self.rolling_tokens.remove(&token).is_some() {
                        self.rolling_done(token, result);
                    } else if !self.abandoned.remove(&token) {
                        self.reads.insert(token, result);
                    }
                }
                Event::Wake => {
                    self.sh.state_mut().tree.dependencies.invalidate();
                    self.wake = true;
                    self.woke = true;
                }
                Event::Page(a) => {
                    self.pages_loaded += 1;
                    let tree = &mut self.sh.state_mut().tree;
                    if tree.dependencies.active() {
                        let failed = tree.is_bad(a);
                        tree.dependencies.page(a, failed, now);
                    }
                    self.wake = true;
                    self.wtoks.push(crate::toks::tok_page(self.idx as usize, a));
                }
                Event::Released { .. } => self.released += 1,
                Event::Failed(f) => return Err(f.into()),
            }
        }
        self.evbuf = ev;
        self.rolling_progress();
        let d = self.sh.durable_lsn();
        let mut durable_moved = false;
        while self.wq.front().is_some_and(|&(l, _)| l <= d) {
            durable_moved = true;
            let (l, id) = self.wq.pop_front().unwrap();
            if self.wlsn.get(&id) == Some(&l) {
                self.wlsn.remove(&id);
            }
        }
        if durable_moved && self.wl_wait {
            self.wl_wait = false;
            self.woke = true;
        }
        // a prefetch admission waiter nobody probed any more (its op ran another way, or the first missing run it keyed on was
        // prefetched by another op) is dropped here; ops queued behind it were denied because of it and nothing in flight
        // would ever wake them: wake the gate. A leased waiter is never dropped as gone: its lease release removes it.
        if self.pf_expire_waiters(now) {
            self.woke = true;
        }
        if self.sh.is_failed() {
            return Err(StoreError::Failed.into());
        }
        if self.sh.dev().is_dead() {
            return Err(ObjError::Eio("device dead".into()));
        }
        Ok(events)
    }

    /// [`pump`](Self::pump) inside a bounded wait: a device completion, a submit or a shard event is progress for
    /// `stall`. A stretch without any is reported (`WARNING TIMEOUT`, see [`Stall`]); it fails the wait only with device
    /// IO in flight (nothing completed or submitted for the whole stretch while IO was outstanding: a device stall). With
    /// nothing in flight the shard waits for memory (DMA budget refusals, adr 0175 am. 4: the IO that frees it runs on
    /// other cores) or for another core: pressure throttles, it never fails the op, so the wait goes on and the next
    /// stretch starts.
    fn pump_bounded<C: Clock>(
        &mut self,
        clk: &mut C,
        stall: &mut Stall,
        ctx: std::fmt::Arguments,
    ) -> Result<()> {
        let ios = self.sh.stats.io_completions;
        let busy = self.in_flight();
        // without a completion, more IO in flight than before means a submit
        if self.pump(clk)? || self.sh.stats.io_completions != ios || self.in_flight() > busy {
            stall.progress();
        } else if stall.expired(ctx) {
            if self.in_flight() > 0 {
                return Err(ObjError::Invalid("wait timed out".into()));
            }
            stall.progress();
        }
        Ok(())
    }

    /// Device commands of this shard in flight.
    fn in_flight(&mut self) -> usize {
        let dev = self.sh.dev();
        dev.queue_depth().saturating_sub(dev.queue_space())
    }

    pub fn idle<C: Clock>(&mut self, clk: &mut C) {
        let h = self.sh.dev().next_deadline();
        clk.idle(h);
    }

    /// One round of a synchronous read's wait for a device queue slot or in-flight IO memory (adr 0175 am. 4), holding
    /// no memory of its own read: polls completions (IO in flight returns its buffers) and expires idle prefetch runs of
    /// this shard, while every other core's store sweep gives back parked memory. Memory held without IO in flight stays
    /// within the read gate, so a refused request has IO in flight ahead of it; on the SPDK tier every shard has a core
    /// of its own (`croit-flashstore-osd` refuses to start otherwise), so that IO completes while this core waits. A stretch of
    /// `stall` without progress is reported (`WARNING TIMEOUT`, once per stretch) and the wait goes on: pressure never
    /// fails the read.
    fn short_wait<C: Clock>(
        &mut self,
        clk: &mut C,
        stall: &mut Stall,
        ctx: std::fmt::Arguments,
    ) -> Result<()> {
        let ios = self.sh.stats.io_completions;
        // no progress for a stretch: reported, and the next stretch starts
        if self.pump(clk)? || self.sh.stats.io_completions != ios || stall.expired(ctx) {
            stall.progress();
        }
        self.pf_expire(clk.now());
        self.idle(clk);
        Ok(())
    }

    /// Pump until `f` holds; bounded by [`Stall`].
    pub fn wait<C: Clock>(
        &mut self,
        clk: &mut C,
        mut f: impl FnMut(&mut Self) -> bool,
    ) -> Result<()> {
        let mut stall = Stall::new("shard wait");
        loop {
            if f(self) {
                return Ok(());
            }
            self.pump_bounded(clk, &mut stall, format_args!("pump/idle loop"))?;
            if f(self) {
                return Ok(());
            }
            self.idle(clk);
        }
    }

    /// Force a checkpoint covering everything submitted so far and wait for it.
    pub fn checkpoint<C: Clock>(&mut self, clk: &mut C) -> Result<()> {
        if self.sh.read_only() {
            return Err(StoreError::Invalid("read-only mount: checkpoint refused").into());
        }
        #[cfg(feature = "splinterdb")]
        if self.sh.splinter_selected() {
            self.sh.request_omap_flush();
            self.wait(clk, |s| s.sh.splinter_drained())?;
            // Publication submission clears the overlay; make that native record durable
            // before declaring the explicit checkpoint/drain complete.
            let target = self.sh.next_lsn() - 1;
            self.wait(clk, |s| s.sh.durable_lsn() >= target)?;
        }
        let target = self.sh.next_lsn() - 1;
        // background merges (adr 0021 am. 33) need a checkpoint even with nothing logged: wait for one that starts now
        let bg = self.sh.bg_dirty();
        if self.sh.ckpt_lsn() >= target && !bg {
            return Ok(());
        }
        let n = self.sh.stats.checkpoints + u64::from(self.sh.ckpt_active());
        self.sh.request_checkpoint();
        self.wait(clk, |s| {
            s.sh.ckpt_lsn() >= target && (!bg || s.sh.stats.checkpoints > n)
        })
    }

    /// One round of a blocking caller's backpressure wait (allocation or submit retry after `Busy`/`WalFull`): the
    /// next shard event round. `stall` (one per wait, named after what the caller waits for) bounds the wait like
    /// [`Self::wait`]: past it the wait fails loudly instead of reporting backpressure as a full store.
    pub(crate) fn backpressure_round<C: Clock>(
        &mut self,
        clk: &mut C,
        stall: &mut Stall,
    ) -> Result<()> {
        if self.nonblock {
            self.wb_why = "backpressure";
            return Err(ObjError::WouldBlock);
        }
        // blocking caller at the allocation gate with the pool open: nobody pumps the pool request here, the store
        // level (`queue_blocking`) takes the chunk and retries
        #[cfg(feature = "elastic")]
        if self.sh.lend.want {
            return Err(ObjError::NoSpace);
        }
        self.pump_bounded(clk, stall, format_args!("store backpressure"))?;
        self.idle(clk);
        Ok(())
    }

    pub fn miss_wait<C: Clock>(&mut self, clk: &mut C) -> Result<()> {
        if self.nonblock {
            self.wb_why = TREE_MISS;
            return Err(ObjError::WouldBlock);
        }
        self.wake = false;
        #[cfg(feature = "lab")]
        let t0 = std::time::Instant::now();
        let r = self.wait(clk, |s| s.wake);
        #[cfg(feature = "lab")]
        crate::dbg::miss_wait_done(t0);
        r
    }

    /// Foreign read credit is released by another request on this same core.
    /// Never pump/block waiting for it, even if the executor selected IO fallback.
    /// Other engines and genuine independent IO misses retain miss_wait policy.
    pub(crate) fn omap_miss_wait<C: Clock>(&mut self, clk: &mut C) -> Result<()> {
        #[cfg(feature = "splinterdb")]
        if self.sh.splinter_credit_blocked() {
            self.local_wait = true;
            let mut cause = self.clog.get();
            cause.set_overflow(); // Local release is an unnamed wake, not a page token.
            self.clog.set(cause);
            self.wb_why = "foreign read credit";
            return Err(ObjError::WouldBlock);
        }
        #[cfg(feature = "splinterdb")]
        if self.sh.splinter_independent_reads() {
            // A cold FIFO visibility barrier cannot run an executor owner. Only
            // foreign worker reads are synchronous here; native allocation and
            // page admission keep their existing nonblocking preparation policy.
            self.wake = false;
            return self.wait(clk, |s| s.wake);
        }
        self.miss_wait(clk)
    }

    pub fn tget<C: Clock>(&mut self, clk: &mut C, key: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        loop {
            match self.sh.get(key, out) {
                Err(StoreError::Miss) => {
                    out.clear();
                    crate::dbg::miss_tag(key.first().copied().unwrap_or(2));
                    self.miss_wait(clk)?;
                }
                r => return r.map_err(Into::into),
            }
        }
    }

    /// Scan step with the engine's budget; retries misses. Returns whether the range is exhausted.
    pub fn tscan<C: Clock>(
        &mut self,
        clk: &mut C,
        cur: &mut ScanCursor,
        max_entries: usize,
        f: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<bool> {
        // the budget is per call, not per retry: entries emitted before a miss stay emitted (the cursor moved past
        // them), so a retry may only emit what is left. Before this a cold scan restarted its budget after every
        // missing leaf and walked the whole rest of the range (O(keys) page loads and memory for a 1024-entry page).
        let mut emitted = 0usize;
        loop {
            let left = max_entries.saturating_sub(emitted);
            if left == 0 {
                return Ok(false);
            }
            let r = self.sh.scan(cur, left, usize::MAX, &mut |k, v| {
                emitted += 1;
                f(k, v)
            });
            match r {
                Err(StoreError::Miss) => self.miss_wait(clk)?,
                Ok(ScanStatus::Done) => return Ok(true),
                Ok(ScanStatus::More) => return Ok(false),
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Load the tree pages of `[a, b)` (parallel reads); the later point lookups then hit the cache.
    pub fn tprefetch<C: Clock>(&mut self, clk: &mut C, a: &[u8], b: &[u8]) -> Result<()> {
        loop {
            match self.sh.prefetch(a, b) {
                Err(StoreError::Miss) => self.miss_wait(clk)?,
                r => return r.map_err(Into::into),
            }
        }
    }

    /// A listing pass of the current executor request ends after its CPU slice (adr 0021 S8): a non-blocking run that
    /// [`crate::obj::Store::list_whole`] did not exempt.
    pub(crate) fn list_sliced(&self) -> bool {
        self.memo_session().is_some() && !self.list_whole
    }

    /// The executor request a listing pass belongs to: only non-blocking runs of a request can continue a listing
    /// later (a blocking run finishes it in one go).
    pub(crate) fn memo_session(&self) -> Option<(u64, u64)> {
        if self.nonblock {
            self.read_session
        } else {
            None
        }
    }

    /// The memo of this request's scan of `id` that `same` accepts (the scan's parameters; taken out, `memo_put` returns
    /// it).
    pub(crate) fn memo_take(
        &mut self,
        session: (u64, u64),
        id: u64,
        same: impl Fn(&ScanMemo) -> bool,
    ) -> Option<ScanMemo> {
        let i = self
            .memos
            .iter()
            .position(|m| m.session == session && m.id == id && same(m))?;
        self.stats.scan_resumes += 1;
        Some(self.memos.swap_remove(i))
    }

    pub(crate) fn memo_put(&mut self, mut m: ScanMemo) {
        m.touched = self.now;
        self.memos.push(m);
    }

    #[cfg(feature = "rocksdb")]
    pub(crate) fn rocks_memo_take(
        &mut self,
        session: (u64, u64),
        id: u64,
        same: impl Fn(&RocksScanMemo) -> bool,
    ) -> Option<RocksScanMemo> {
        let i = self
            .rocks_memos
            .iter()
            .position(|m| m.session == session && m.id == id && same(m))?;
        self.stats.scan_resumes += 1;
        Some(self.rocks_memos.swap_remove(i))
    }

    #[cfg(feature = "rocksdb")]
    pub(crate) fn rocks_memo_put(&mut self, mut m: RocksScanMemo) {
        m.touched = self.now;
        self.rocks_memos.push(m);
    }

    #[cfg(feature = "splinterdb")]
    pub(crate) fn splinter_memo_take(
        &mut self,
        session: (u64, u64),
        id: u64,
        same: impl Fn(&SplinterScanMemo) -> bool,
    ) -> Option<SplinterScanMemo> {
        let i = self
            .splinter_memos
            .iter()
            .position(|m| m.session == session && m.id == id && same(m))?;
        self.stats.scan_resumes += 1;
        Some(self.splinter_memos.swap_remove(i))
    }
    #[cfg(feature = "splinterdb")]
    pub(crate) fn splinter_memo_put(&mut self, mut m: SplinterScanMemo) {
        m.touched = self.now;
        self.splinter_memos.push(m);
    }

    /// The park barrier of listing request `session`: `now` (the shard's last park sequence) at its first listing.
    pub(crate) fn list_barrier(&mut self, session: (u64, u64), now: u64) -> u64 {
        let t = self.now;
        match self.list_barriers.iter_mut().find(|b| b.0 == session) {
            Some(b) => {
                b.2 = t;
                b.1
            }
            None => {
                self.list_barriers.push((session, now, t));
                now
            }
        }
    }

    /// The saved enumeration of operation `key.seq` of this staging session, if it is that removal's and still
    /// describes the engine (`generation`: `Shard::olsm_generation`). Enumerations of other operations of the session
    /// stay for their own turn; those of other sessions are discarded (only the shard FIFO head stages, and a session's
    /// enumerations are released when its staging ends, [`ShardStore::range_memo_release`]).
    pub(crate) fn range_memo_take(
        &mut self,
        key: RangeKey<'_>,
        generation: u64,
    ) -> Option<RangeMemo> {
        self.range_memos.retain(|m| m.session == key.session);
        let i = self.range_memos.iter().position(|m| m.seq == key.seq)?;
        let m = self.range_memos.swap_remove(i);
        let same = m.id == key.id
            && m.first[..] == *key.first
            && m.last[..] == *key.last
            && m.generation == generation;
        if same {
            self.stats.scan_resumes += 1;
        }
        same.then_some(m)
    }

    /// Keep a point range removal's enumeration for the retry of its transaction after a cold read refused it.
    pub(crate) fn range_memo_put(&mut self, m: RangeMemo) {
        self.range_memos
            .retain(|o| o.session != m.session || o.seq != m.seq);
        self.range_memos.push(m);
    }

    /// The staging of `session` ended (prepared, failed or abandoned): its saved enumerations describe no future retry.
    pub(crate) fn range_memo_release(&mut self, session: (u64, u64)) {
        if !self.range_memos.is_empty() {
            self.range_memos.retain(|m| m.session != session);
        }
    }

    /// A mutation of object `id` is being staged: its listings in progress no longer describe it (they start over).
    #[inline]
    pub(crate) fn memo_drop(&mut self, id: u64) {
        #[cfg(feature = "splinterdb")]
        if self.sh.splinter_selected() {
            self.splinter_memos.retain(|m| m.id != id);
            return;
        }
        #[cfg(feature = "rocksdb")]
        if self.sh.rocks_selected() {
            self.rocks_memos.retain(|m| m.id != id);
            return;
        }
        if !self.memos.is_empty() {
            self.memos.retain(|m| m.id != id);
        }
    }

    #[cfg(feature = "rocksdb")]
    pub(crate) fn memo_drop_planning(&mut self, id: u64) {
        if !self.sh.rocks_selected() {
            self.memo_drop(id);
            return;
        }
        let session = self.read_session;
        self.rocks_memos
            .retain(|m| m.id != id || Some(m.session) == session);
    }

    /// End a listing pass early (CPU slice, adr 0021 S8): the request is refused and named for the wake that the next poll
    /// delivers, so it continues after the other ops of the core had their turn. The caller reports the progress it made
    /// (a slice that ended with nothing kept would otherwise look like progress forever).
    pub(crate) fn scan_slice(&mut self) {
        self.slice_seq += 1;
        let t = crate::toks::tok_slice(self.idx as usize, self.slice_seq);
        let mut c = self.clog.get();
        c.push(t);
        self.clog.set(c);
        self.wtoks.push(t);
        self.stats.scan_slices += 1;
    }

    /// Wait until the data of onode `id` is durable (reads must not race the data write of an unacked txn).
    pub fn wait_durable<C: Clock>(&mut self, clk: &mut C, id: u64) -> Result<()> {
        if let Some(&l) = self.wlsn.get(&id)
            && l > self.sh.durable_lsn()
        {
            self.stats.durable_waits += 1;
            if self.nonblock {
                self.wl_wait = true;
                self.wb_why = "data durable";
                return Err(ObjError::WouldBlock);
            }
            self.wait(clk, |s| s.sh.durable_lsn() >= l)?;
        }
        Ok(())
    }

    pub fn note_write(&mut self, id: u64, lsn: u64) {
        self.wlsn.insert(id, lsn);
        self.wq.push_back((lsn, id));
    }

    /// Read `(pba, nblk)` runs from the device (concurrently, split at the transfer limit). No crc check.
    pub fn read_runs<C: Clock>(
        &mut self,
        clk: &mut C,
        runs: &[(u64, u32)],
    ) -> Result<Vec<Vec<u8>>> {
        let mut dst = 0usize;
        let placed: Vec<(u64, u32, usize)> = runs
            .iter()
            .map(|&(pba, n)| {
                let r = (pba, n, dst);
                dst += n as usize;
                r
            })
            .collect();
        let mut flat: Vec<u8> = Vec::with_capacity(dst * BLK);
        // This helper is used by deep check: verify media, never a client prefetch/result cache.
        self.read_runs_into(
            clk,
            &placed,
            &mut flat.spare_capacity_mut()[..dst * BLK],
            true,
        )?;
        // SAFETY: the runs cover every block of `flat` (placed back to back) and the read returned Ok.
        unsafe { flat.set_len(dst * BLK) };
        Ok(placed
            .iter()
            .map(|&(_, n, d)| flat[d * BLK..(d + n as usize) * BLK].to_vec())
            .collect())
    }

    /// Read `(pba, nblk, dst_blk)` runs from the device straight into `out` (run data lands at block `dst_blk` of
    /// `out`; concurrent, split at the transfer limit). One pass per block: DMA buffer -> `out` fused with the block
    /// crc (`codec::blk_crc` of the engine block address). Returns the crcs of all blocks in run order. No crc check.
    /// `media` bypasses prefetch and retained request results (scrub/deep check must verify device bytes).
    pub fn read_runs_into<C: Clock>(
        &mut self,
        clk: &mut C,
        runs: &[(u64, u32, usize)],
        out: &mut [MaybeUninit<u8>],
        media: bool,
    ) -> Result<Vec<u32>> {
        self.read_runs_inner(clk, runs, Out::Flat(out), media, false)
    }

    /// [`ShardStore::read_runs_into`] without the payload copy (client reads): device buffers become immutable
    /// `Bytes`; partial prefetch coverage retains exact slices of the same backing. Block crcs are computed in place
    /// or reused from the exact physical range. `segs` gets the pieces in completion order (sort by `dst`), together
    /// covering every run block once.
    /// Returns the block crcs in run order. No crc check.
    ///
    /// `media`: bypass the data cache and prefetch table. Set for the RDMA placement read, whose pieces are handed to
    /// the transport for an RMA WRITE: only device buffers come from the registered buffer arena, a piece served from
    /// the cache region or a retained request result would be outside it and the transport would have to refuse the
    /// placement (spec rdma-placement-runtime.md). Ordinary reads pass false and keep cache and prefetch.
    pub fn read_runs_shared<C: Clock>(
        &mut self,
        clk: &mut C,
        runs: &[(u64, u32, usize)],
        segs: &mut Vec<Seg>,
        media: bool,
    ) -> Result<Vec<u32>> {
        self.read_runs_inner(clk, runs, Out::Shared(segs), media, false)
    }

    /// Retain completed physical results until the whole compressed read has finished.
    pub(crate) fn read_runs_kept<C: Clock>(
        &mut self,
        clk: &mut C,
        runs: &[(u64, u32, usize)],
        out: &mut [MaybeUninit<u8>],
        media: bool,
    ) -> Result<Vec<u32>> {
        self.read_runs_inner(clk, runs, Out::Flat(out), media, true)
    }

    fn read_runs_inner<C: Clock>(
        &mut self,
        clk: &mut C,
        runs: &[(u64, u32, usize)],
        mut out: Out<'_>,
        media: bool,
        keep: bool,
    ) -> Result<Vec<u32>> {
        let media = media || self.media;
        // Prefetch is the first device read of this operation, not a speculative
        // error that may be hidden by issuing the same command again. Check
        // overlaps too: a later read may request a larger range than its probe.
        if self.pf_errors > 0 {
            for &(pba, n, _) in runs {
                let end = pba + u64::from(n);
                let failed = self
                    .pf
                    .range_mut(..end)
                    .rev()
                    .take_while(|(k, e)| **k + u64::from(e.n) > pba)
                    .find_map(|(&k, e)| {
                        e.failed.map(|error| {
                            let held = e.holders > 0;
                            e.served |= held;
                            (k, error, held)
                        })
                    });
                if let Some((k, error, held)) = failed {
                    if !held {
                        self.pf_drop(k);
                    }
                    return Err(ObjError::Eio(format!(
                        "device prefetch read at block {k}: {error:?}"
                    )));
                }
            }
        }
        let shape = Shape::of(&out);
        if self.nonblock {
            if media {
                return self.rolling_read(runs, out, true, keep);
            }
            let retained = self
                .rolling
                .iter()
                .any(|r| r.session == self.read_session && r.runs == runs && r.shape == shape);
            let (mut prefetched, mut inflight) = (true, false);
            for &(pba, n, _) in runs {
                for off in (0..n as usize).step_by(self.max_xfer_blk) {
                    let (pba, c) = (pba + off as u64, (n as usize - off).min(self.max_xfer_blk));
                    if self.dc.covers(pba, c as u32) {
                        continue;
                    }
                    match self
                        .pf
                        .range(..=pba)
                        .next_back()
                        .filter(|(k, e)| *k + e.n as u64 >= pba + c as u64)
                    {
                        Some((_, e)) if e.buf.is_some() => {}
                        // a prefetch of this range is in flight (this op's own, woken by a part of its causes, or
                        // another op's): wait for it, a rolling read would read the same blocks a second time
                        Some((_, e)) if e.failed.is_none() => {
                            inflight = true;
                            self.cause_pf(e.batch);
                        }
                        _ => prefetched = false,
                    }
                }
            }
            if !retained && inflight {
                self.rm_progress = true; // completion-driven data wait, not a failed metadata scan attempt
                self.wb_why = "prefetch in flight";
                return Err(ObjError::WouldBlock);
            }
            if retained || !prefetched {
                return self.rolling_read(runs, out, false, keep);
            }
        }
        struct Job {
            run: usize,
            off: usize,
            pba: u64,
            n: u32,
            tok: u64,
        }
        let mut jobs = Vec::new();
        let mut base = Vec::with_capacity(runs.len());
        let mut nb = 0usize;
        for (i, &(pba, n, _)) in runs.iter().enumerate() {
            base.push(nb);
            nb += n as usize;
            let mut off = 0usize;
            while off < n as usize {
                let c = (n as usize - off).min(self.max_xfer_blk);
                self.tok += 1;
                jobs.push(Job {
                    run: i,
                    off,
                    pba: pba + off as u64,
                    n: c as u32,
                    tok: self.tok & (PF_TOKEN - 1),
                });
                off += c;
            }
        }
        let mut crcs = vec![0u32; nb];
        // runs in the data cache or read ahead by a client op's `warm_data`: no device wait
        if !media && (!self.pf.is_empty() || self.dc.len() > 0) {
            jobs.retain(|j| {
                let d0 = runs[j.run].2 + j.off;
                let c0 = base[j.run] + j.off;
                let n = j.n as usize;
                !self.serve_ready(j.pba, j.n, out.sink(d0, n, c0), &mut crcs[c0..c0 + n])
            });
        }
        if !jobs.is_empty() {
            use std::sync::atomic::Ordering::Relaxed;
            crate::dbg::SYNC_CALLS.fetch_add(1, Relaxed);
            crate::dbg::SYNC_BLOCKS.fetch_add(jobs.iter().map(|j| u64::from(j.n)).sum(), Relaxed);
        }
        // clock only for a synchronous read (diagnostics): a read served from the prefetch table (the common case) reads
        // none (adr 0043: one clock read per loop iteration)
        let sync_t0 = (!jobs.is_empty()).then(std::time::Instant::now);
        let mut next = 0;
        while next < jobs.len() {
            // every submitted job's completion is consumed, also after an error (it holds a device buffer): the first
            // error is returned once the batch is drained
            let mut err: Option<ObjError> = None;
            let mut sent = 0;
            'submit: for j in &jobs[next..jobs.len().min(next + 16)] {
                // a job's buffer is in-flight IO memory (adr 0175 am. 4). `Busy`: a full device queue or no buffer within
                // the DMA budget now. With jobs of the batch in flight, the batch ends here: they are waited for and
                // consumed (their buffers return), the rest follows in the next batch. With none, the core waits holding
                // nothing of this read but data already sunk (shared within the read gate, or copied)
                let mut stall = Stall::new("sync read submit");
                loop {
                    match self.sh.submit_io_read(j.pba, j.n, j.tok) {
                        Ok(()) => break,
                        Err(StoreError::Busy) if sent > 0 => break 'submit,
                        Err(StoreError::Busy) => {
                            if let Err(e) = self.short_wait(
                                clk,
                                &mut stall,
                                format_args!("device queue full or DMA budget short"),
                            ) {
                                err = Some(e);
                                break 'submit;
                            }
                        }
                        Err(e) => {
                            err = Some(e.into());
                            break 'submit;
                        }
                    }
                }
                sent += 1;
                self.stats.read_ios += 1;
                self.stats.read_blocks += j.n as u64;
            }
            let batch = &jobs[next..next + sent];
            next += sent;
            let mut toks = [0u64; 16];
            for (t, j) in toks.iter_mut().zip(batch) {
                *t = j.tok;
            }
            let toks = &toks[..batch.len()];
            if let Err(e) = self.wait(clk, |s| toks.iter().all(|t| s.reads.contains_key(t))) {
                err.get_or_insert(e);
            }
            for j in batch {
                match self.reads.remove(&j.tok) {
                    Some(Ok(b)) if err.is_none() => {
                        let (d0, c0, n) =
                            (runs[j.run].2 + j.off, base[j.run] + j.off, j.n as usize);
                        out.sink(d0, n, c0).buf(b, j.pba, &mut crcs[c0..c0 + n]);
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        err.get_or_insert_with(|| {
                            ObjError::Eio(format!("device read at block {}: {e:?}", j.pba))
                        });
                    }
                    // the wait gave up: the completion is dropped when it arrives
                    None => {
                        self.abandoned.insert(j.tok);
                    }
                }
            }
            if let Some(e) = err {
                return Err(e);
            }
        }
        if let Some(t0) = sync_t0 {
            crate::dbg::SYNC_NS.fetch_add(
                t0.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        Ok(crcs)
    }
}

// ------------------------------------------------------------------ data prefetch (ADR 0043)

/// Ready prefetched runs older than this are dropped (their reader pin delays block reuse).
const PF_TTL_NS: u64 = 200_000_000;
/// A waiter in the admission queue not re-probed for this long is dropped (its op is gone).
const PF_WAIT_NS: u64 = 50_000_000;
/// Cap on prefetch entries per shard; beyond it reads stay synchronous.
const PF_MAX: usize = 1024;
/// Cap on prefetched blocks per shard (reads in flight or waiting for their op); beyond it reads stay synchronous.
const PF_MAX_BLOCKS: u64 = 8192;

/// At most four request sessions with rolling reads per shard (plus the FIFO head's own, [`fifo_session`]), and 32 MiB
/// of rolling DMA in total. Result storage is proportional to the admitted read ranges (already required by the read
/// API), never to device depth.
const ROLLING_READS: usize = 4;
const ROLLING_BLOCKS: usize = 8192;

/// Read-session namespaces of the store's own readers (`(namespace, id)`); executor requests use `(conn, tid)` and
/// `u64::MAX - 1` is the executor's internal copy connection. FIFO head preparation, keyed by its token.
pub(crate) const STAGE_SESSION: u64 = u64::MAX;
/// FIFO head translation ([`crate::obj::QueueBuilder`]), keyed by its token.
pub(crate) const BUILD_SESSION: u64 = u64::MAX - 2;
/// Idle recompaction (adr 0533), keyed by the shard.
pub(crate) const RC_SESSION: u64 = u64::MAX - 3;
/// Scrub media reads (`Store::read_media_async`), keyed by the scrub session.
pub(crate) const MEDIA_SESSION: u64 = u64::MAX - 4;

/// `ShardStore::wb_why` of a tree page miss (the parked head's stall clock counts page loads while it waits for pages).
pub(crate) const TREE_MISS: &str = "tree miss";

/// The shard FIFO head's own reads (its preparation and translation) never wait for a session slot: executor requests
/// keep their completed reads while they wait at the visibility fence for that head, so a head refused a slot waited
/// for itself (the shard livelocked, lab case 36). One head per shard: at most its two sessions beyond
/// `ROLLING_READS` (a former head's leftovers expire after `PF_TTL_NS`).
fn fifo_session(s: Option<(u64, u64)>) -> bool {
    matches!(s, Some((STAGE_SESSION | BUILD_SESSION, _)))
}

/// Runs of one read as `(first block, blocks)` sorted by block (disjoint inside one read).
fn by_pba(runs: &[(u64, u32, usize)]) -> Vec<(u64, u32)> {
    let mut v: Vec<(u64, u32)> = runs.iter().map(|&(b, n, _)| (b, n)).collect();
    v.sort_unstable();
    v
}

struct ReadJob {
    tok: u64,
    pba: u64,
    n: usize,
    dst: usize,
    crc: usize,
}

/// Result form of a read; a parked read resumes only into the same form.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    /// One buffer of this many bytes.
    Flat(usize),
    /// Segments ([`Seg`]).
    Shared,
}

impl Shape {
    fn of(out: &Out<'_>) -> Shape {
        match out {
            Out::Flat(o) => Shape::Flat(o.len()),
            Out::Shared(_) => Shape::Shared,
        }
    }
}

struct RollingRead {
    session: Option<(u64, u64)>,
    media: bool,
    /// Read by the request's latest run: its decoded chunk goes to the client cache when the request ends.
    used: bool,
    runs: Vec<(u64, u32, usize)>,
    /// `(first block, blocks)` of `runs` ordered by block: [`ShardStore::rolling_covers`] is asked once per piece of every
    /// object read (900 for a fragmented 4 MiB object) and must not scan the runs of every read in flight.
    by_pba: Vec<(u64, u32)>,
    shape: Shape,
    /// `Shape::Flat`: the result buffer.
    data: Vec<MaybeUninit<u8>>,
    /// `Shape::Shared`: the pieces read so far (immutable: a retained read hands out clones on every retry).
    segs: Vec<Seg>,
    crcs: Vec<u32>,
    run: usize,
    off: usize,
    base: usize,
    jobs: Vec<ReadJob>,
    error: Option<String>,
    epoch: u64,
    touched: u64,
    /// Request-owned decoded chunk; never reused outside its pinned read/session.
    decoded: Option<(u32, bytes::Bytes)>,
    /// An op returned `WouldBlock` on this read and waits: woken once when the whole read completes (not per command).
    waiting: bool,
}

impl<D: BlockDev> ShardStore<D> {
    /// A resumable read already owns this immutable extent snapshot. The actual non-blocking
    /// read will consume/resume it; the gate must not prefetch its prefix again on every retry.
    pub(crate) fn rolling_resumes(&self, runs: &[(u64, u32, usize)]) -> bool {
        self.rolling.iter().any(|r| !r.media && r.runs == runs)
    }

    /// A rolling read of another op holds a run containing `[pba, pba+n)` (compressed chunks: one run per read).
    pub(crate) fn rolling_covers(&self, pba: u64, n: u32) -> bool {
        let end = pba + u64::from(n);
        self.rolling.iter().any(|r| {
            let i = r.by_pba.partition_point(|&(b, _)| b <= pba);
            !r.media && i > 0 && end <= r.by_pba[i - 1].0 + u64::from(r.by_pba[i - 1].1)
        })
    }

    fn rolling_read(
        &mut self,
        runs: &[(u64, u32, usize)],
        out: Out<'_>,
        media: bool,
        keep: bool,
    ) -> Result<Vec<u32>> {
        let shape = Shape::of(&out);
        let pos = self.rolling.iter().position(|r| {
            r.session == self.read_session && r.media == media && r.runs == runs && r.shape == shape
        });
        let i = match pos {
            Some(i) => i,
            None => {
                if !self.rolling_room() {
                    self.rm_progress = true; // data admission waits must never fall back to a blocking scan
                    self.rolling_wait = true;
                    self.wb_why = "rolling slot";
                    return Err(ObjError::WouldBlock);
                }
                let len = match shape {
                    Shape::Flat(n) => n,
                    Shape::Shared => 0,
                };
                let mut data = Vec::with_capacity(len);
                // SAFETY: MaybeUninit has no initialization requirement. Only completed run ranges
                // are copied to the caller; holes are never inspected.
                unsafe { data.set_len(len) };
                self.rolling.push(RollingRead {
                    session: self.read_session,
                    media,
                    used: true,
                    runs: runs.to_vec(),
                    by_pba: by_pba(runs),
                    shape,
                    data,
                    segs: Vec::new(),
                    crcs: vec![0; runs.iter().map(|r| r.1 as usize).sum()],
                    run: 0,
                    off: 0,
                    base: 0,
                    jobs: Vec::new(),
                    error: None,
                    epoch: self.sh.read_pin(),
                    touched: self.now,
                    decoded: None,
                    waiting: false,
                });
                self.head_reads += u64::from(fifo_session(self.read_session));
                self.rolling.len() - 1
            }
        };
        self.rolling[i].touched = self.now;
        self.rolling[i].used = true;
        self.rolling_progress();
        let r = &mut self.rolling[i];
        if !r.jobs.is_empty() || (r.error.is_none() && r.run < r.runs.len()) {
            r.waiting = true;
            let key = r.runs[0].0;
            self.cause_pf(key); // the op is woken by this read's completion token, not by every wake
            self.rm_progress = true; // completion-driven data wait, not a failed metadata scan attempt
            self.wb_why = "rolling read";
            return Err(ObjError::WouldBlock);
        }
        if let Some(e) = &r.error {
            let e = e.clone();
            if self.read_session.is_none() {
                let r = self.rolling.remove(i);
                self.sh.read_unpin(r.epoch);
                self.rolling_freed();
            }
            return Err(ObjError::Eio(e));
        }
        match out {
            // Holes are initialized by read_committed. Never copy an uninitialized hole over a
            // compressed caller's initialized destination.
            Out::Flat(out) => {
                for &(_, n, dst) in &r.runs {
                    out[dst * BLK..(dst + n as usize) * BLK]
                        .copy_from_slice(&r.data[dst * BLK..(dst + n as usize) * BLK]);
                }
            }
            Out::Shared(segs) => segs.extend(r.segs.iter().cloned()),
        }
        let crcs = r.crcs.clone();
        // Executor retries must be able to read earlier ranges again when a later range parks.
        // Direct callers have no session and consume the result immediately.
        if self.read_session.is_none() && !keep {
            let r = self.rolling.remove(i);
            self.sh.read_unpin(r.epoch);
            self.rolling_freed();
        }
        Ok(crcs)
    }

    /// The current session may hold another rolling read: a FIFO head session, a session that holds one already, or one
    /// of at most `ROLLING_READS` request sessions.
    fn rolling_room(&self) -> bool {
        let cur = self.read_session;
        if fifo_session(cur) || self.rolling.iter().any(|r| r.session == cur) {
            return true;
        }
        let mut seen = [None; ROLLING_READS];
        let mut n = 0;
        for r in self.rolling.iter().filter(|r| !fifo_session(r.session)) {
            if !seen[..n].contains(&Some(r.session)) {
                if n == ROLLING_READS {
                    return false;
                }
                seen[n] = Some(r.session);
                n += 1;
            }
        }
        n < ROLLING_READS
    }

    /// `Some`: a run of request `session` begins. `None`: the current run ends; `keep` = it was refused and the request
    /// runs again: every read of the request stays, also those this run did not reach (it stopped at an earlier refusal,
    /// e.g. at a listing that starts over: dropping them made every retry re-read one value and drop the next, a request
    /// that never finished). Reads a retry no longer asks for (relocated extents) expire after `PF_TTL_NS` idle; `!keep`
    /// (the request ended) releases all of them.
    pub(crate) fn read_session(&mut self, session: Option<(u64, u64)>, keep: bool) {
        #[cfg(feature = "rocksdb")]
        if self.sh.rocks_selected() {
            self.sh.rocks_session(session, keep);
            if session.is_none()
                && !keep
                && let Some(cur) = self.read_session
            {
                self.rocks_memos.retain(|m| m.session != cur);
            }
        }
        #[cfg(feature = "splinterdb")]
        self.sh.splinter_session(session, keep);
        #[cfg(feature = "splinterdb")]
        if session.is_none()
            && !keep
            && let Some(cur) = self.read_session
        {
            self.splinter_memos.retain(|m| m.session != cur);
        }
        self.list_whole = false;
        if session.is_none()
            && !keep
            && let Some(cur) = self.read_session
            && !self.memos.is_empty()
        {
            self.memos.retain(|m| m.session != cur); // the request is done: its listings with it
        }
        if session.is_none()
            && !keep
            && let Some(cur) = self.read_session
        {
            self.range_memo_release(cur);
        }
        if session.is_none()
            && !keep
            && let Some(cur) = self.read_session
        {
            self.list_barriers.retain(|b| b.0 != cur);
        }
        if let Some(session) = session {
            self.pass_listed = 0; // a new run of a request
            for r in &mut self.rolling {
                if r.session == Some(session) {
                    r.used = false;
                }
            }
        } else if !keep {
            let mut i = 0;
            while i < self.rolling.len() {
                if self.rolling[i].session == self.read_session {
                    let mut r = self.rolling.remove(i);
                    self.cache_decoded(&mut r);
                    self.sh.read_unpin(r.epoch);
                    self.rolling_freed();
                } else {
                    i += 1;
                }
            }
        }
        self.read_session = session;
        #[cfg(feature = "rocksdb")]
        if self.sh.rocks_selected() {
            self.sh.rocks_scan_charge(
                self.rocks_memos
                    .iter()
                    .map(RocksScanMemo::engine_charge)
                    .sum(),
            );
        }
        #[cfg(feature = "splinterdb")]
        self.sh.splinter_scan_charge(
            self.splinter_memos
                .iter()
                .map(SplinterScanMemo::engine_charge)
                .sum(),
        );
    }

    pub(crate) fn session_context(&self) -> Option<(u64, u64)> {
        self.read_session
    }
    pub(crate) fn restore_session(&mut self, session: Option<(u64, u64)>) {
        self.read_session = session;
        #[cfg(feature = "rocksdb")]
        self.sh.rocks_session(session, true);
        #[cfg(feature = "splinterdb")]
        self.sh.splinter_session(session, true);
    }

    fn cache_decoded(&mut self, r: &mut RollingRead) {
        if !r.media
            && r.used
            && let Some((crc, data)) = r.decoded.take()
        {
            let (pba, n, _) = r.runs[0];
            self.dcache.put(pba, n, crc, data);
        }
    }

    /// The decoded chunk a completed window of this request holds (by reference, no copy): completed chunks belong to
    /// this request, not the client cache (also valid for fresh media verification).
    pub(crate) fn retained_decoded(
        &mut self,
        pba: u64,
        n: u32,
        crc: u32,
        raw_len: usize,
        media: bool,
    ) -> Option<bytes::Bytes> {
        let r = self.rolling.iter_mut().find(|r| {
            r.session == self.read_session
                && r.media == media
                && r.runs == [(pba, n, 0)]
                && r.decoded
                    .as_ref()
                    .is_some_and(|(c, d)| *c == crc && d.len() == raw_len)
        })?;
        r.used = true;
        r.touched = self.now;
        r.decoded.as_ref().map(|(_, d)| d.clone())
    }

    /// Keep a decoded chunk for the rest of this request (a retry finds it again) and, at the end, the client cache.
    pub(crate) fn keep_decoded(
        &mut self,
        pba: u64,
        n: u32,
        crc: u32,
        data: bytes::Bytes,
        media: bool,
    ) {
        if let Some(r) = self
            .rolling
            .iter_mut()
            .find(|r| r.session == self.read_session && r.media == media && r.runs == [(pba, n, 0)])
        {
            r.decoded = Some((crc, data));
            return;
        }
        // A prefetched chunk needs decoded ownership, but no additional physical buffer or copy.
        if self.rolling_room() {
            self.rolling.push(RollingRead {
                session: self.read_session,
                media,
                used: true,
                runs: vec![(pba, n, 0)],
                by_pba: vec![(pba, n)],
                shape: Shape::Flat(0),
                data: Vec::new(),
                segs: Vec::new(),
                crcs: Vec::new(),
                run: 1,
                off: 0,
                base: 0,
                jobs: Vec::new(),
                error: None,
                epoch: self.sh.read_pin(),
                touched: self.now,
                decoded: Some((crc, data)),
                waiting: false,
            });
        } else if !media {
            self.dcache.put(pba, n, crc, data);
        }
    }

    /// Direct blocking/nonblocking callers have no executor session to release their completed window.
    pub(crate) fn release_kept(&mut self, runs: &[(u64, u32, usize)], cache: bool) {
        if self.read_session.is_some() {
            return;
        }
        let mut i = 0;
        while i < self.rolling.len() {
            if self.rolling[i].session.is_none() && self.rolling[i].runs == runs {
                let mut r = self.rolling.remove(i);
                if cache {
                    self.cache_decoded(&mut r);
                }
                self.sh.read_unpin(r.epoch);
                self.rolling_freed();
            } else {
                i += 1;
            }
        }
    }

    fn rolling_done(&mut self, tok: u64, result: std::result::Result<D::Buf, IoError>) {
        for r in &mut self.rolling {
            let Some(i) = r.jobs.iter().position(|j| j.tok == tok) else {
                continue;
            };
            let j = r.jobs.swap_remove(i);
            match result {
                Ok(b) => {
                    let crcs = &mut r.crcs[j.crc..j.crc + j.n];
                    match r.shape {
                        Shape::Shared => Sink::Share {
                            segs: &mut r.segs,
                            dst: j.dst,
                            ci: j.crc,
                        }
                        .buf(b, j.pba, crcs),
                        Shape::Flat(_) => Sink::Copy(&mut r.data[j.dst * BLK..(j.dst + j.n) * BLK])
                            .buf(b, j.pba, crcs),
                    }
                }
                Err(e) => r.error = Some(format!("device read at block {}: {e:?}", j.pba)),
            }
            r.touched = self.now;
            self.head_reads += u64::from(fifo_session(r.session));
            return;
        }
        // An expired/cancelled continuation: the ordinary read pin ended at completion.
    }

    /// A rolling read ended (result taken, released or expired): wake the gate only when an op waits for a slot.
    fn rolling_freed(&mut self) {
        self.released += 1;
        if std::mem::take(&mut self.rolling_wait) {
            self.woke = true;
        }
    }

    fn rolling_progress(&mut self) {
        let mut rolling = std::mem::take(&mut self.rolling);
        // Includes commands of expired continuations until their completion is reaped.
        let mut blocks: usize = self.rolling_tokens.values().sum();
        for r in &mut rolling {
            while r.error.is_none() && r.run < r.runs.len() {
                let (pba, n, dst) = r.runs[r.run];
                let n = n as usize;
                if r.off == n {
                    r.base += n;
                    r.run += 1;
                    r.off = 0;
                    continue;
                }
                let c = (n - r.off).min(self.max_xfer_blk).min(ROLLING_BLOCKS);
                let (pba, dst, ci) = (pba + r.off as u64, dst + r.off, r.base + r.off);
                let sink = match r.shape {
                    Shape::Shared => Sink::Share {
                        segs: &mut r.segs,
                        dst,
                        ci,
                    },
                    Shape::Flat(_) => Sink::Copy(&mut r.data[dst * BLK..(dst + c) * BLK]),
                };
                if !r.media && self.serve_ready(pba, c as u32, sink, &mut r.crcs[ci..ci + c]) {
                    r.off += c;
                    continue;
                }
                // Leave admitted prefetch alone until it completes; do not issue a duplicate.
                if !r.media && matches!(self.pf_state(pba, c as u32), PfState::InFlight) {
                    break;
                }
                let (space, depth) = self.sh.read_queue();
                let keep = (depth / 16).clamp(1, 8).min(depth.saturating_sub(1));
                if blocks + c > ROLLING_BLOCKS || space <= keep {
                    break;
                }
                self.tok += 1;
                let tok = self.tok & (PF_TOKEN - 1);
                match self.sh.submit_read(pba, c as u32, tok, false) {
                    Ok(()) => {}
                    Err(StoreError::Busy) => break,
                    Err(e) => {
                        r.error = Some(format!("device read at block {pba}: {e:?}"));
                        break;
                    }
                }
                self.rolling_tokens.insert(tok, c);
                r.jobs.push(ReadJob {
                    tok,
                    pba,
                    n: c,
                    dst,
                    crc: ci,
                });
                r.off += c;
                blocks += c;
                self.stats.read_ios += 1;
                self.stats.read_blocks += c as u64;
            }
        }
        // the op of a read that returned WouldBlock is woken once, when the read is whole (a retry probes every run)
        for r in &mut rolling {
            if r.waiting && r.jobs.is_empty() && (r.error.is_some() || r.run >= r.runs.len()) {
                r.waiting = false;
                self.wtoks
                    .push(crate::toks::tok_pf(self.idx as usize, r.runs[0].0));
                self.rm_progress = true; // completed IO is progress, not an executor scan retry
            }
        }
        self.rolling = rolling;
    }
}

/// A completed prefetch remains device-owned until a shared reader needs it.
/// Partial sharing keeps the full immutable owner in the entry for later reads.
enum PfBuf<B> {
    Device(B),
    Shared(Bytes),
}

impl<B: IoBuf> PfBuf<B> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Device(b) => b.as_slice(),
            Self::Shared(b) => b,
        }
    }

    fn into_shared(self) -> Bytes
    where
        B: Send + 'static,
    {
        match self {
            Self::Device(b) => b.into_shared(),
            Self::Shared(b) => b,
        }
    }
}

/// Device run `[key, key + n)` read ahead of its client op. The reader pin of the read stays held while the entry
/// holds data, so the blocks cannot be freed and reused under it: the content always matches what the (COW) tree
/// addresses name.
pub(crate) struct Pf<B> {
    n: u32,
    /// Submit time while in flight, completion time once ready/failed (TTL base).
    t: u64,
    /// Original device backing, retained immutably after its first shared consumer.
    buf: Option<PfBuf<B>>,
    /// Block crcs of `buf`, computed when the read completed (the core waits for the rest of the op's reads meanwhile; the
    /// serving pass takes them over instead of reading the cold data again).
    crcs: Vec<u32>,
    /// The device read failed: counts as ready; the real read consumes the error, never retries the IO.
    /// Retains its reader pin until consumed/expired, so the error cannot name a recycled block.
    failed: Option<IoError>,
    /// A free of its blocks was submitted while the run was out (its reader pin keeps the blocks unreused until it goes;
    /// the data cache holds no pin): never moved into the data cache.
    freed: bool,
    /// Submission batch (key of the first run of the admission): the op waits for the batch, not for each run.
    batch: u64,
    /// Entry generation (`ShardStore::pf_gen`).
    ver: u64,
    /// Leases holding the run: it neither expires nor leaves the table when read until the last one is released.
    holders: u32,
    /// Its blocks count in `pf_leased` (ready while held), not in `pf_blocks`.
    leased: bool,
    /// Read whole while held: on the last release it goes like a consumed run (into the data cache).
    served: bool,
}

/// What a residency lease pins: prefetch runs `(key, ver)` and tree page addresses.
#[derive(Default)]
struct Lease {
    runs: Vec<(u64, u64)>,
    pages: FxSet<u64>,
}

impl<D: BlockDev> ShardStore<D> {
    /// Remember that a parked op waits for write durability (the next durable advance wakes the gate).
    pub(crate) fn wl_park(&mut self) {
        self.wl_wait = true;
    }

    /// Is a write of onode `id` still short of durable (reads must then wait: `wait_durable`)?
    pub(crate) fn wlsn_pending(&self, id: u64) -> bool {
        self.wlsn
            .get(&id)
            .is_some_and(|&l| l > self.sh.durable_lsn())
    }

    /// Start collecting what a probe waits on (adr 0043 am. 9): tree pages it misses and prefetch runs in flight.
    pub(crate) fn cause_begin(&mut self) {
        #[cfg(feature = "splinterdb")]
        {
            self.local_wait = false;
        }
        self.sh.miss_log_clear();
        self.clog.set(Default::default());
    }

    /// Add the causes collected since [`ShardStore::cause_begin`] to `out` (shard-prefixed tokens).
    pub(crate) fn cause_collect(&self, out: &mut crate::toks::Toks<8>) {
        for &a in self.sh.miss_log().as_slice() {
            out.push(crate::toks::tok_page(self.idx as usize, a));
        }
        if self.sh.miss_log().overflowed() {
            out.set_overflow();
        }
        out.merge(&self.clog.get());
    }

    fn cause_pf(&self, key: u64) {
        let mut c = self.clog.get();
        c.push(crate::toks::tok_pf(self.idx as usize, key));
        self.clog.set(c);
    }

    /// State of the device run `[pba, pba+n)` in the prefetch table.
    pub(crate) fn pf_state(&self, pba: u64, n: u32) -> PfState {
        if self.dc.covers(pba, n) {
            return PfState::Ready;
        }
        if let Some((&k, e)) = self.pf.range(..=pba).next_back()
            && k + e.n as u64 >= pba + n as u64
        {
            return if e.buf.is_some() || e.failed.is_some() {
                PfState::Ready
            } else {
                self.cause_pf(e.batch);
                PfState::InFlight
            };
        }
        // an entry overlapping the range or an address the token cannot carry: the real read goes synchronous. The table
        // keeps its runs disjoint (`forget_freed` walks back from the last run before a free and stops at the first run
        // ending before it; the lookups above take the last run starting at or before an address): a run admitted over a
        // shorter one inside it would escape the free marking and carry freed blocks into the data cache. With disjoint
        // runs only the last run starting before the end can reach into the range.
        let end = pba + u64::from(n);
        if pba >= PF_TOKEN
            || self
                .pf
                .range(..end)
                .next_back()
                .is_some_and(|(&k, e)| k + u64::from(e.n) > pba)
        {
            PfState::Ready
        } else {
            PfState::Absent
        }
    }

    /// Admission of one op's missing runs (`blocks` blocks in `runs` runs, `key` = its first block) into the
    /// prefetch table, all or nothing (an op never holds capacity it cannot complete with: no partial-hold
    /// livelock) and in first-denial order (`pf_q`: a later op only passes when the free capacity also covers every
    /// op queued before it, so the oldest waiter is never starved by younger ones). `No` = wait for the wake
    /// (capacity frees on consume/expiry), `Skip` = never fits (the read stays synchronous).
    /// A leased op (`self.lease`) keeps its place until it is admitted or its lease is released (it is never dropped as
    /// gone: [`ShardStore::pf_freed`] wakes it when capacity frees).
    pub(crate) fn pf_admit(&mut self, key: u64, blocks: u64, runs: usize) -> PfAdmit {
        // device queue slots: one command per run; a share stays free for the WAL writes (acks of writes must not queue
        // behind a full queue of reads), and an op is admitted only when ALL its commands fit now (a half submitted op
        // holds ready data that expires before its rest is read: thrash)
        let (q_space, q_depth) = self.sh.read_queue();
        let q_keep = (q_depth / 16).max(8);
        let q_room = q_depth.saturating_sub(q_keep);
        if runs > q_room {
            crate::dbg::PF_SKIP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return PfAdmit::Skip;
        }
        let free_q = q_space.saturating_sub(q_keep);
        if blocks > PF_MAX_BLOCKS || runs > PF_MAX {
            crate::dbg::PF_SKIP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return PfAdmit::Skip;
        }
        let (now, lease) = (self.now, self.lease);
        self.pf_expire_waiters(now);
        let (mut ab, mut ar, mut pos) = (0u64, 0usize, None);
        for (i, w) in self.pf_q.iter().enumerate() {
            if (lease != 0 && w.lease == lease) || (lease == 0 && w.lease == 0 && w.key == key) {
                pos = Some(i);
                break;
            }
            ab += w.blocks;
            ar += w.runs;
        }
        // cached runs never cost an admission its room
        self.dc_fit(self.pf_blocks + self.pf_leased.1 + ab + blocks);
        let free_b = PF_MAX_BLOCKS.saturating_sub(self.pf_blocks);
        let free_r = PF_MAX.saturating_sub(self.pf.len() - self.pf_leased.0);
        if free_b >= ab + blocks && free_r >= ar + runs && free_q >= ar + runs {
            if let Some(i) = pos {
                self.pf_q.remove(i);
            }
            self.sh.set_read_admission_waiting(!self.pf_q.is_empty());
            crate::dbg::PF_YES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return PfAdmit::Yes;
        }
        match pos {
            Some(i) => {
                let w = &mut self.pf_q[i];
                (w.key, w.t, w.blocks, w.runs) = (key, now, blocks, runs);
            }
            None => self.pf_q.push_back(PfWait {
                key,
                blocks,
                runs,
                t: now,
                lease,
            }),
        }
        self.sh.set_read_admission_waiting(!self.pf_q.is_empty());
        PfAdmit::No
    }

    /// Submit the read of `[pba, pba+n)` into the prefetch table (admitted by `pf_admit`). False = the device queue
    /// is full or its DMA budget has no buffer to spare now (nothing submitted: the op waits for the prefetch reads in
    /// flight, else the real read goes synchronous).
    pub(crate) fn pf_submit(&mut self, pba: u64, n: u32, batch: u64) -> bool {
        match self.sh.submit_read(pba, n, PF_TOKEN | pba, self.pf_retain) {
            Ok(()) => {
                self.cause_pf(batch);
                *self.pf_batch.entry(batch).or_insert(0) += 1;
                crate::dbg::PF_SUBMIT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.stats.read_ios += 1;
                self.stats.read_blocks += n as u64;
                self.pf_blocks += n as u64;
                self.pf_gen += 1;
                self.pf.insert(
                    pba,
                    Pf {
                        n,
                        t: self.now,
                        buf: None,
                        crcs: Vec::new(),
                        failed: None,
                        freed: false,
                        batch,
                        ver: self.pf_gen,
                        holders: 0,
                        leased: false,
                        served: false,
                    },
                );
                self.pf_hold(pba, n);
                true
            }
            Err(_) => {
                crate::dbg::PF_BUSY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                false
            }
        }
    }

    /// No client read in progress: no prefetch run in the table and no rolling read of a session outside namespace
    /// `own` (idle recompaction, adr 0533).
    pub(crate) fn reads_idle(&self, own: u64) -> bool {
        self.pf.is_empty()
            && self
                .rolling
                .iter()
                .all(|r| r.session.is_some_and(|s| s.0 == own))
    }

    /// Prefetch admission waiters queued (tests, diagnostics).
    pub fn pf_waiters(&self) -> usize {
        self.pf_q.len()
    }

    /// A probe left its resolved read for the read that follows (see [`ShardStore::hot`]).
    pub fn hot_probe_pending(&self) -> bool {
        self.hot.is_some()
    }

    /// Data cache use: (entries, blocks); shares [`ShardStore::dc_cap`] with the prefetch table (tests, diagnostics).
    pub fn data_cache_usage(&self) -> (usize, u64) {
        (self.dc.len(), self.dc.blocks())
    }

    /// Blocks the data cache and the prefetch table may hold together (adr 0633-data-cache-envelope): the floor
    /// (`ShardCfg::data_floor_blocks`) plus the part of the shard's tree page budget the tree has not allocated ([`Shard::data_cache_lend`]; 0 on a device
    /// that reads only into a DMA pool). The tree grows on demand and keeps its pages: the data cache gives the memory
    /// back as it does (metadata first), down to the floor.
    pub fn dc_cap(&self) -> u64 {
        self.sh.data_floor_blocks() + self.sh.data_cache_lend() / BLK as u64
    }

    /// Take the capacity from the envelope and evict down to it, leaving `pf` blocks for the prefetch table (its current
    /// and admitted runs). O(1) per evicted run. The held bytes the run cache's share reads are the ones left after the
    /// eviction, so the two caches converge in one pass instead of a pass later.
    fn dc_fit(&mut self, pf: u64) {
        let floor = self.sh.data_floor_blocks();
        let cap = self.dc_cap();
        self.dc.set_cap(cap);
        self.dc.evict_to(cap.saturating_sub(pf));
        self.sh
            .set_data_cache_held((self.dc.blocks() + pf).saturating_sub(floor) * BLK as u64);
        self.sh.trim_ram();
    }

    /// Operator cache drop (`ceph tell osd.N cache drop`): every clean cached item of this shard goes: data cache runs,
    /// decoded-chunk entries, clean tree pages (dirty, in-flight, checkpoint-held and pinned pages stay: they carry
    /// changes or leases) and the clean omap run cache; the memory of all of it returns to the allocator. The prefetch
    /// table is request state (reads in progress) and is not touched. Call between operations only. The next read of
    /// anything dropped is a cache miss and reads the device.
    pub fn drop_caches(&mut self) -> CacheDropped {
        // the probe of a pending read resolved its range against the cache being dropped
        self.hot = None;
        let (data_runs, data_blocks) = self.dc.clear();
        let (decomp_entries, decomp_bytes) = self.dcache.clear();
        let psz = self.sh.tree_psz() as u64;
        let (tree_pages, tree_kept) = self.sh.drop_tree_clean();
        let omap_run_bytes = self.sh.olsm_drop_cache();
        self.sh.trim_ram();
        let d = CacheDropped {
            tree_pages,
            tree_kept,
            tree_bytes: tree_pages * psz,
            data_runs,
            data_bytes: data_blocks * BLK as u64,
            decomp_entries,
            decomp_bytes,
            omap_run_bytes,
        };
        self.dropped.add(&d);
        self.drops += 1;
        d
    }

    /// Prefetch table use: (entries, blocks) — bounded by `PF_MAX` / `PF_MAX_BLOCKS` (tests, diagnostics).
    pub fn pf_usage(&self) -> (usize, u64) {
        (self.pf.len(), self.pf_blocks)
    }

    /// Continuation result bytes and DMA blocks, including expired requests' outstanding IO.
    pub fn rolling_usage(&self) -> (usize, usize) {
        (
            self.rolling
                .iter()
                .map(|r| r.data.len() + r.segs.iter().map(|s| s.data.len()).sum::<usize>())
                .sum(),
            self.rolling_tokens.values().sum(),
        )
    }

    /// Any prefetch read still on the device (its completion will wake the waiting ops)?
    pub(crate) fn pf_has_inflight(&self) -> bool {
        self.pf
            .values()
            .any(|p| p.buf.is_none() && p.failed.is_none())
    }

    /// Capacity was freed: ops waiting in the admission queue must retry.
    fn pf_freed(&mut self) {
        if !self.pf_q.is_empty() {
            self.woke = true;
        }
    }

    /// Serve `[pba, pba+n)` from the data cache or a ready prefetch entry into `dst` with the block crcs. False = in
    /// neither.
    fn serve_ready(&mut self, pba: u64, n: u32, dst: Sink<'_>, crcs: &mut [u32]) -> bool {
        match self.dc.get(pba, n) {
            Some((data, known)) => {
                dst.whole(data, pba, Some(known), crcs);
                true
            }
            None => self.pf_serve(pba, n, dst, crcs),
        }
    }

    /// Serve `[pba, pba+n)` from a ready prefetch entry with its physical block crcs. Shared destinations retain
    /// the original backing, including partial coverage; copying destinations copy directly. False = not there.
    /// A run served whole leaves the table (its reader pin goes); with `pf_retain` its bytes and crcs move into
    /// the data cache (no copy) unless a free of its blocks was submitted meanwhile.
    pub(crate) fn pf_serve(&mut self, pba: u64, n: u32, dst: Sink<'_>, crcs: &mut [u32]) -> bool {
        let Some((&k, e)) = self.pf.range_mut(..=pba).next_back() else {
            return false;
        };
        let (off, en) = ((pba - k) as usize, e.n);
        if k + (en as u64) < pba + n as u64 {
            return false;
        }
        // a held run stays for its lease (`served`: it is cached when the last holder releases it)
        let held = e.holders > 0;
        e.served |= held && off == 0 && n == en;
        let whole = off == 0 && n == en && !held;
        let Some(b) = e.buf.take() else {
            return false;
        };
        let range = off * BLK..(off + n as usize) * BLK;
        let known = &e.crcs[off..off + n as usize];
        let shared = match dst {
            Sink::Copy(d) => {
                fill(&b.as_slice()[range], pba, d, Some(known), crcs);
                e.buf = Some(b);
                None
            }
            s @ Sink::Share { .. } => {
                let data = b.into_shared();
                s.whole(data.slice(range), pba, Some(known), crcs);
                if !whole {
                    // Keep all prefetched blocks and their physical reader pin;
                    // subsequent ordinary/compressed/shared readers use this owner.
                    e.buf = Some(PfBuf::Shared(data));
                    return true;
                }
                Some(data)
            }
        };
        self.pf_consumed(k, whole, Cached::Plain(shared));
        true
    }

    /// Run `f` on the bytes and block crcs of a ready prefetch entry that holds `[pba, pba+n)`, in place (nothing is
    /// copied out; the codec and the counters come along for the callee). The entry is consumed as [`Self::pf_serve`]
    /// consumes a whole run. `None` = not (yet) there: the caller reads through [`Self::read_runs_kept`].
    pub(crate) fn pf_with<R>(
        &mut self,
        pba: u64,
        n: u32,
        f: impl FnOnce(&[u8], &[u32], &mut crate::compress::SoftCodec, &mut ObjStats) -> R,
    ) -> Option<R> {
        let (&k, e) = self.pf.range_mut(..=pba).next_back()?;
        let (off, en) = ((pba - k) as usize, e.n);
        if k + (en as u64) < pba + n as u64 {
            return None;
        }
        let b = e.buf.as_ref()?;
        let r = f(
            &b.as_slice()[off * BLK..(off + n as usize) * BLK],
            &e.crcs[off..off + n as usize],
            &mut self.codec,
            &mut self.stats,
        );
        // a compressed chunk: its decoded form is what the decompressed-chunk cache keeps, the physical bytes are not
        // cached a second time; a held run stays for its lease (dropped on the last release)
        let whole = off == 0 && n == en && self.pf.get(&k).is_some_and(|e| e.holders == 0);
        self.pf_consumed(k, whole, Cached::No);
        Some(r)
    }

    /// A ready prefetch entry was read: a whole run is done with. It leaves the table (its reader pin goes); with
    /// `pf_retain` and `Cached::Plain` its bytes (`Some` = already shared by the reader, else the device buffer the entry
    /// still holds) and block crcs move into the data cache, unless a free of its blocks was submitted meanwhile.
    fn pf_consumed(&mut self, k: u64, whole: bool, cache: Cached) {
        if !whole {
            return;
        }
        crate::dbg::PF_SERVED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let put = match (cache, self.pf.get_mut(&k)) {
            (Cached::Plain(shared), Some(e)) if self.pf_retain && !e.freed => {
                let data = shared.or_else(|| e.buf.take().map(PfBuf::into_shared));
                data.map(|d| (e.n, d, std::mem::take(&mut e.crcs)))
            }
            _ => None,
        };
        self.pf_drop(k);
        if let Some((n, data, crcs)) = put {
            self.dc.put(k, n, data, crcs);
        }
    }

    /// Remove entry `k` (its pin goes) and wake the admission waiters.
    fn pf_drop(&mut self, k: u64) {
        if let Some(e) = self.pf.remove(&k) {
            self.pf_unacct(&e);
            self.sh.read_release(PF_TOKEN | k);
        }
        self.pf_freed();
    }

    /// The blocks of a removed entry leave their counter.
    fn pf_unacct(&mut self, e: &Pf<D::Buf>) {
        self.pf_errors -= usize::from(e.failed.is_some());
        if e.leased {
            self.pf_leased.0 -= 1;
            self.pf_leased.1 -= e.n as u64;
        } else {
            self.pf_blocks -= e.n as u64;
        }
    }

    /// A held entry that is ready moves to `pf_leased` (its admission capacity frees: waiters retry).
    fn pf_lease_acct(&mut self, k: u64) {
        let Some(e) = self.pf.get_mut(&k) else {
            return;
        };
        if e.holders > 0 && !e.leased && (e.buf.is_some() || e.failed.is_some()) {
            e.leased = true;
            self.pf_blocks -= e.n as u64;
            self.pf_leased.0 += 1;
            self.pf_leased.1 += e.n as u64;
            self.pf_freed();
        }
    }

    /// An entry the last lease let go counts as an unheld ready run again (its TTL runs from now).
    fn pf_unlease_acct(&mut self, k: u64) {
        let now = self.now;
        let Some(e) = self.pf.get_mut(&k) else {
            return;
        };
        if e.leased {
            e.leased = false;
            e.t = now;
            self.pf_leased.0 -= 1;
            self.pf_leased.1 -= e.n as u64;
            self.pf_blocks += e.n as u64;
        }
    }

    /// The probe's lease (`self.lease`, none = no-op) holds the prefetch run covering `[pba, pba+n)`, if there is one:
    /// it stays until the lease is released (no TTL expiry, no drop when another reader consumes it).
    pub(crate) fn pf_hold(&mut self, pba: u64, n: u32) {
        let lease = self.lease;
        if lease == 0 {
            return;
        }
        let Some((&k, e)) = self.pf.range_mut(..=pba).next_back() else {
            return;
        };
        if k + (e.n as u64) < pba + n as u64 {
            return;
        }
        let Some(l) = self.leases.get_mut(&lease) else {
            return;
        };
        if l.runs.contains(&(k, e.ver)) {
            return;
        }
        l.runs.push((k, e.ver));
        e.holders += 1;
        self.pf_lease_acct(k);
    }

    /// Open lease `id` (no pins yet).
    pub(crate) fn lease_open(&mut self, id: u64) {
        self.leases.insert(id, Lease::default());
    }

    /// Pin the tree pages a leased probe missed (`addrs`, from [`crate::shard::Shard::pin_log`]).
    pub(crate) fn lease_pin_pages(&mut self, id: u64, addrs: &[u64]) {
        let Some(l) = self.leases.get_mut(&id) else {
            return;
        };
        for &a in addrs {
            if l.pages.insert(a) {
                self.sh.pin_page(a);
            }
        }
    }

    /// Release lease `id`: its pages may be evicted again, its runs expire / leave the table as unheld runs do (one read
    /// whole meanwhile goes as consumed), its admission waiter leaves the queue.
    pub(crate) fn lease_release(&mut self, id: u64) {
        let Some(l) = self.leases.remove(&id) else {
            return;
        };
        for a in l.pages {
            self.sh.unpin_page(a);
        }
        for (k, ver) in l.runs {
            let Some(e) = self.pf.get_mut(&k) else {
                continue;
            };
            if e.ver != ver {
                continue;
            }
            e.holders -= 1;
            if e.holders > 0 {
                continue;
            }
            let served = std::mem::take(&mut e.served);
            self.pf_unlease_acct(k);
            if served {
                self.pf_consumed(k, true, Cached::Plain(None));
            }
        }
        let before = self.pf_q.len();
        self.pf_q.retain(|w| w.lease != id);
        self.sh.set_read_admission_waiting(!self.pf_q.is_empty());
        if self.pf_q.len() != before {
            self.pf_freed(); // the waiters behind it may fit now
        }
    }

    /// Copies of the partial last blocks `txn` writes (its `tails`): `(pba, bytes, block crc)`, taken before the submit
    /// consumes the buffers ([`ShardStore::cache_tails`] files them once it is accepted). Empty unless `pf_retain`.
    pub(crate) fn tail_blocks(&self, txn: &crate::shard::Txn<D::Buf>) -> Vec<(u64, Bytes, u32)> {
        if !self.pf_retain {
            return Vec::new();
        }
        let runs = txn.tails.iter().filter_map(|&i| {
            let (pba, buf) = txn.data.get(i as usize)?;
            Some((*pba, buf.as_slice(), txn.data_crcs.get(i as usize)?))
        });
        let copies = (txn.copies.iter())
            .filter(|c| c.tail)
            .map(|c| (c.blk, &c.src[..], &c.crcs));
        runs.chain(copies)
            .filter_map(|(pba, src, crcs)| {
                let n = src.len() / BLK;
                let last = src.get((n - 1) * BLK..n * BLK)?;
                Some((
                    pba + n as u64 - 1,
                    Bytes::copy_from_slice(last),
                    *crcs.get(n - 1)?,
                ))
            })
            .collect()
    }

    /// Put the tail blocks of an accepted txn ([`ShardStore::tail_blocks`]) into the data cache: the next append to the
    /// object finds its partial last block resident instead of reading it back from the device. Committed data is
    /// never written in place and every free passes [`ShardStore::forget_freed`], so the entry is as valid as one filled
    /// by a read; reads still wait for the txn to be durable (`wlsn_pending`).
    pub(crate) fn cache_tails(&mut self, tails: Vec<(u64, Bytes, u32)>) {
        for (pba, data, crc) in tails {
            self.dc.put(pba, 1, data, vec![crc]);
        }
    }

    /// Leased ready runs: (entries, blocks) (tests, diagnostics).
    pub fn pf_leased_usage(&self) -> (usize, u64) {
        self.pf_leased
    }

    /// The blocks of `frees` are freed by a txn being submitted: the caches drop them (no copy may outlive the free), runs
    /// still out in the prefetch table are never cached (their pin keeps the old bytes valid for the reads that resolved
    /// them before the free).
    pub(crate) fn forget_freed(&mut self, frees: &[(u64, u32)]) {
        self.dcache.forget(frees);
        self.dc.forget(frees);
        if self.pf.is_empty() {
            return;
        }
        for &(pba, n) in frees {
            let end = pba + u64::from(n);
            // disjoint runs sorted by start: walk back from the last one starting before `end` while they reach `pba`
            for (&k, e) in self.pf.range_mut(..end).rev() {
                if k + u64::from(e.n) <= pba {
                    break;
                }
                e.freed = true;
            }
        }
    }

    fn pf_done(&mut self, key: u64, result: std::result::Result<D::Buf, IoError>) {
        let batch = match (self.pf.get_mut(&key), result) {
            // the TTL runs from completion: a slow device (queueing > TTL) must not expire a run before its op got
            // the wake, or a multi-run op would re-read forever
            (Some(e), Ok(b)) => {
                e.crcs = vec![0; e.n as usize];
                crc_in_place(b.as_slice(), key, &mut e.crcs);
                e.buf = Some(PfBuf::Device(b));
                e.t = self.now;
                let batch = e.batch;
                self.pf_lease_acct(key);
                batch
            }
            (Some(e), Err(error)) => {
                e.failed = Some(error);
                self.pf_errors += 1;
                e.t = self.now;
                let batch = e.batch;
                self.pf_lease_acct(key);
                batch
            }
            (None, _) => {
                self.sh.read_release(PF_TOKEN | key);
                key
            }
        };
        // an op with N runs in flight waits for the last of them: one wake and one retry instead of N (each retry
        // probes every run of the object)
        match self.pf_batch.get_mut(&batch) {
            Some(n) if *n > 1 => *n -= 1,
            Some(_) => {
                self.pf_batch.remove(&batch);
                self.wtoks
                    .push(crate::toks::tok_pf(self.idx as usize, batch));
            }
            None => self
                .wtoks
                .push(crate::toks::tok_pf(self.idx as usize, batch)),
        }
    }

    /// Drop the client-op admission waiters nobody probed for `PF_WAIT_NS`; true if one went. A leased waiter stays: its
    /// lease release removes it.
    fn pf_expire_waiters(&mut self, now: u64) -> bool {
        let n = self.pf_q.len();
        self.pf_q
            .retain(|w| w.lease != 0 || now.saturating_sub(w.t) <= PF_WAIT_NS);
        self.sh.set_read_admission_waiting(!self.pf_q.is_empty());
        self.pf_q.len() != n
    }

    /// Drop ready/failed entries nobody claimed (op gone, partial overlap, ...).
    pub(crate) fn pf_expire(&mut self, now: u64) {
        // the tree grew since the last admission: the data cache gives its memory back without waiting for a read
        self.dc_fit(self.pf_blocks + self.pf_leased.1);
        if !self.memos.is_empty() {
            self.memos
                .retain(|m| now.saturating_sub(m.touched) <= PF_TTL_NS);
        }
        #[cfg(feature = "rocksdb")]
        if self.sh.rocks_selected() && !self.rocks_memos.is_empty() {
            let sh = &self.sh;
            self.rocks_memos.retain(|m| {
                sh.rocks_session_admitted(m.session) || now.saturating_sub(m.touched) <= PF_TTL_NS
            });
        }
        #[cfg(feature = "splinterdb")]
        if self.sh.splinter_selected() {
            let sh = &self.sh;
            self.splinter_memos.retain(|m| {
                sh.splinter_session_admitted(m.session)
                    || now.saturating_sub(m.touched) <= PF_TTL_NS
            });
        }
        self.list_barriers
            .retain(|b| now.saturating_sub(b.2) <= PF_TTL_NS);
        let mut i = 0;
        while i < self.rolling.len() {
            // In-flight reads have their own pins; drop only the snapshot/result pin here. A read with runs left to
            // submit is not idle: it waits for room (device queue, rolling window, DMA budget), resumes at a pump and
            // expires once read; its op waits for its completion.
            let r = &self.rolling[i];
            if r.jobs.is_empty()
                && (r.error.is_some() || r.run >= r.runs.len())
                && now.saturating_sub(r.touched) > PF_TTL_NS
            {
                let r = self.rolling.remove(i);
                self.sh.read_unpin(r.epoch);
                self.rolling_freed();
            } else {
                i += 1;
            }
        }
        if self.pf.is_empty() {
            return;
        }
        let old: Vec<u64> = self
            .pf
            .iter()
            .filter(|(_, e)| {
                e.holders == 0
                    && (e.buf.is_some() || e.failed.is_some())
                    && now.saturating_sub(e.t) > PF_TTL_NS
            })
            .map(|(&k, _)| k)
            .collect();
        for k in old {
            crate::dbg::PF_EXPIRED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Some(e) = self.pf.remove(&k) {
                self.pf_unacct(&e);
            }
            self.sh.read_release(PF_TOKEN | k);
        }
        self.pf_freed();
    }
}

/// What a consumed prefetch run leaves for the data cache ([`ShardStore::pf_consumed`]).
enum Cached {
    /// Plain data: cache it (`Some` = the bytes the reader already shares).
    Plain(Option<Bytes>),
    /// A compressed chunk (cached decoded by the decompressed-chunk cache): nothing.
    No,
}

/// Result of [`ShardStore::pf_state`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PfState {
    Absent,
    InFlight,
    Ready,
}

/// Result of [`ShardStore::pf_admit`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PfAdmit {
    Yes,
    No,
    Skip,
}

/// An op waiting for prefetch capacity.
pub(crate) struct PfWait {
    key: u64,
    blocks: u64,
    runs: usize,
    t: u64,
    /// Residency lease of the op (0 = a client op: dropped `PF_WAIT_NS` after its last probe).
    lease: u64,
}

impl<D: BlockDev> ShardStore<D> {
    /// One line of wake / prefetch / durability state for `tell dump_pgs` (a parked op that never wakes).
    pub(crate) fn diag(&self) -> String {
        let rolling: Vec<String> = self
            .rolling
            .iter()
            .take(8)
            .map(|r| {
                format!(
                    "{:?}/{}/{}/{}/{}of{}/{}",
                    r.session,
                    u8::from(r.media),
                    u8::from(r.used),
                    r.jobs.len(),
                    r.run,
                    r.runs.len(),
                    u8::from(r.waiting)
                )
            })
            .collect();
        format!(
            "woke={} wl_wait={} pf_q={} pf={} pf_blocks={} wq={} wlsn={} durable_lsn={} rolling={}[{}] rwait={} \
             run_waits={} released={} {}",
            self.woke,
            self.wl_wait,
            self.pf_q.len(),
            self.pf.len(),
            self.pf_blocks,
            self.wq.len(),
            self.wlsn.len(),
            self.sh.durable_lsn(),
            self.rolling.len(),
            rolling.join(" "),
            self.rolling_wait,
            self.stats.run_waits,
            self.released,
            self.sh.run_diag(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ShardStore;
    use crate::dev::{SimClock, SimConfig, SimDev, SimDisk};
    use crate::layout::{MkfsParams, mkfs, read_super};
    use crate::obj::{OTxn, Store, StoreCfg};
    use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};

    /// Codex review (adr 0175 am. 4): a blocking wait past its stall bound with nothing in flight waits for memory or
    /// another core (DMA budget refusals): reported, never failed, and its next stretch starts. With IO in flight and no
    /// completion for the whole stretch it is a device stall and fails.
    #[test]
    fn a_stalled_wait_fails_only_with_device_io_in_flight() {
        use nvme::BlockDev;
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let p = MkfsParams {
            shards: 1,
            wal_blocks: 1024,
            align_blocks: 1,
            ..Default::default()
        };
        mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
        let (mut st, _) =
            Store::mount(|| disk.queue(), SimClock::default(), StoreCfg::default()).unwrap();
        let mut clk = st.clk.clone();
        let sh = &mut st.shards[0];
        // nothing in flight, every in-flight IO buffer refused: no progress, the wait goes on
        disk.refuse_io_bufs(u64::MAX);
        let mut stall = crate::sio::Stall::aged("test wait");
        assert!(
            sh.pump_bounded(&mut clk, &mut stall, format_args!("memory"))
                .is_ok()
        );
        assert!(
            sh.pump_bounded(&mut clk, &mut stall, format_args!("memory"))
                .is_ok(),
            "the next stretch started"
        );
        disk.clear_faults();
        // a read in flight whose completion does not come within the stretch: a device stall
        let buf = sh.sh.dev().alloc_buf_uninit(4096);
        assert!(sh.sh.dev().submit_read(0, buf, u64::MAX >> 8).is_ok());
        let mut stall = crate::sio::Stall::aged("test wait");
        assert!(
            sh.pump_bounded(&mut clk, &mut stall, format_args!("device"))
                .is_err()
        );
    }

    /// Codex review: a stretch that waited for memory with nothing in flight ends with the round that finally submits
    /// (a checkpoint whose buffers the budget refused until now): the submit is progress, the new IO starts a fresh
    /// stretch, so the wait does not fail although no completion came yet.
    #[test]
    fn a_submit_after_a_refused_stretch_is_progress() {
        use nvme::BlockDev;
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let p = MkfsParams {
            shards: 1,
            wal_blocks: 1024,
            align_blocks: 1,
            ..Default::default()
        };
        mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
        let (mut st, _) =
            Store::mount(|| disk.queue(), SimClock::default(), StoreCfg::default()).unwrap();
        // something logged for the checkpoint to write
        let c = CollT::Pg(SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        });
        let o = Ghobject::new(
            Hobject::new(b"o", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        );
        let mut t = OTxn::new();
        t.mkcoll(c);
        t.write(c, &o, 0, &[7; 4096]);
        st.commit(&t).unwrap();
        let mut clk = st.clk.clone();
        let sh = &mut st.shards[0];
        disk.refuse_io_bufs(u64::MAX);
        sh.sh.request_checkpoint();
        // the checkpoint runs up to its first write, refused: nothing in flight
        for _ in 0..1000 {
            if disk.stats().refused_io_bufs > 0
                && sh.sh.dev().queue_space() == sh.sh.dev().queue_depth()
            {
                break;
            }
            let mut stall = crate::sio::Stall::new("test wait");
            assert!(
                sh.pump_bounded(&mut clk, &mut stall, format_args!("memory"))
                    .is_ok()
            );
            sh.idle(&mut clk);
        }
        let dev = sh.sh.dev();
        assert_eq!(
            dev.queue_space(),
            dev.queue_depth(),
            "refused: nothing in flight"
        );
        assert!(disk.stats().refused_io_bufs > 0);
        // memory back: this round submits the checkpoint at the end of an aged stretch, no completion yet
        disk.clear_faults();
        let mut stall = crate::sio::Stall::aged("test wait");
        assert!(
            sh.pump_bounded(&mut clk, &mut stall, format_args!("submit"))
                .is_ok()
        );
        let dev = sh.sh.dev();
        assert!(
            dev.queue_space() < dev.queue_depth(),
            "the checkpoint went out"
        );
    }

    /// L2 / M1 (store reviews): a synchronous read batch whose first job fails must not leave the completions (device
    /// buffers) of the other jobs of the batch behind.
    #[test]
    fn failed_sync_read_batch_leaves_no_completions() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let p = MkfsParams {
            shards: 1,
            wal_blocks: 1024,
            align_blocks: 1,
            meta_pct: 8,
            ..Default::default()
        };
        mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
        let (_, dirs) = read_super(&mut disk.queue(), &mut SimClock::default()).unwrap();
        let c = CollT::Pg(SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        });
        let obj = |n: &[u8]| {
            Ghobject::new(
                Hobject::new(n, SnapId::NOSNAP, 1, 1, b""),
                Ghobject::NO_GEN,
                ShardId::NO_SHARD,
            )
        };
        let (a, b) = (obj(b"small"), obj(b"big"));
        let big: Vec<u8> = (0..1 << 20).map(|i| (i % 251) as u8).collect();
        {
            let (mut st, _) =
                Store::mount(|| disk.queue(), SimClock::default(), StoreCfg::default()).unwrap();
            let mut t = OTxn::new();
            t.mkcoll(c);
            t.write(c, &a, 0, &[1; 4096]);
            t.write(c, &b, 0, &big);
            st.commit(&t).unwrap();
            st.checkpoint().unwrap();
        }
        let (mut st, _) =
            Store::mount(|| disk.queue(), SimClock::default(), StoreCfg::default()).unwrap();
        // tree pages resident; then every data block read fails (media error)
        assert_eq!(st.read(&c, &a, 0, 4096).unwrap(), vec![1; 4096]);
        let d = &dirs[0];
        disk.fail_reads(d.data_start, d.data_blocks);
        for _ in 0..3 {
            assert!(st.read(&c, &b, 0, big.len() as u64).is_err());
            assert!(
                st.shards[0].reads.is_empty(),
                "{} orphaned read completions",
                st.shards[0].reads.len()
            );
        }
        disk.clear_faults();
        assert_eq!(st.read(&c, &b, 0, big.len() as u64).unwrap(), big);
    }

    /// The prefetch table keeps its runs disjoint: a read whose range only overlaps a run in the table (a 64-block read
    /// of an extent after a 5-block read inside it) is no new run, so a free of a block of the larger range is never
    /// missed by `forget_freed` (it would carry the freed block into the data cache when the run is consumed).
    #[test]
    fn prefetch_runs_stay_disjoint_and_frees_mark_them() {
        use super::PfState;
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let p = MkfsParams {
            shards: 1,
            wal_blocks: 1024,
            align_blocks: 1,
            meta_pct: 8,
            ..Default::default()
        };
        mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
        let (_, dirs) = read_super(&mut disk.queue(), &mut SimClock::default()).unwrap();
        let (mut st, _) =
            Store::mount(|| disk.queue(), SimClock::default(), StoreCfg::default()).unwrap();
        let s = &mut st.shards[0];
        let b = dirs[0].data_start;
        assert_eq!(s.pf_state(b + 5, 5), PfState::Absent);
        assert!(s.pf_submit(b + 5, 5, b + 5));
        assert_eq!(s.pf_state(b + 5, 5), PfState::InFlight);
        // overlapping, not covered: never a second run over the first
        assert_eq!(s.pf_state(b, 64), PfState::Ready);
        assert_eq!(s.pf_state(b + 8, 8), PfState::Ready);
        assert_eq!(s.pf_state(b, 6), PfState::Ready);
        // disjoint neighbours are runs of their own
        assert_eq!(s.pf_state(b, 5), PfState::Absent);
        assert_eq!(s.pf_state(b + 10, 54), PfState::Absent);
        assert!(s.pf_submit(b + 10, 54, b + 10));
        s.forget_freed(&[(b + 50, 1)]);
        assert!(
            s.pf[&(b + 10)].freed,
            "the run holding the freed block is marked"
        );
        assert!(!s.pf[&(b + 5)].freed);
    }

    /// The run cache and the data cache each borrow the tree page budget the tree has not allocated, at least half
    /// each (adr 0633 am. 5): after the other cache filled, and again after the tree grew into the budget, both give an
    /// overshoot back at the next sweep / driver pass, without an insertion of their own.
    #[test]
    fn borrowed_cache_shares_converge_without_insertions() {
        let disk = SimDisk::new(SimConfig::new(256 << 20));
        let p = MkfsParams {
            shards: 1,
            wal_blocks: 1024,
            align_blocks: 1,
            omap_lsm: true,
            ..Default::default()
        };
        mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
        let mut cfg = StoreCfg::default();
        cfg.shard.cache_pages = 1024;
        cfg.shard.data_floor_blocks = 64;
        let (mut st, _) = Store::mount(|| disk.queue(), SimClock::default(), cfg).unwrap();
        let blk = crate::BLK as u64;
        let floor = st.shards[0].sh.data_floor_blocks() * blk;
        // the first pass sizes the run cache from the lendable tree budget
        let mut acked = Vec::new();
        st.clk.t += 10_000_000;
        st.poll(&mut acked).unwrap();
        let run = |s: &ShardStore<SimDev>| {
            let (b, own, cap) = s.sh.run_cache_for_test().expect("omap engine");
            (b as u64, own as u64, cap as u64)
        };
        let dc = |s: &ShardStore<SimDev>| (s.dc.blocks() * blk).saturating_sub(floor);
        // the run cache fills its cap: its own plus the whole lendable budget (the data cache holds nothing)
        let l = st.shards[0].sh.lendable();
        assert!(l > 16 * blk, "lendable {l}");
        let (bytes, own, cap) = run(&st.shards[0]);
        assert_eq!(cap, own + l);
        st.shards[0]
            .sh
            .fill_run_cache_for_test((cap - bytes) as usize / crate::BLK);
        assert_eq!(run(&st.shards[0]).0, cap);
        // the data cache fills its share (the run cache's lend falls to half)
        let n = st.shards[0].sh.data_floor_blocks() + st.shards[0].sh.data_cache_lend() / blk;
        for i in 0..n {
            st.shards[0]
                .dc
                .put(i, 1, bytes::Bytes::from(vec![0u8; crate::BLK]), vec![0]);
        }
        assert_eq!(dc(&st.shards[0]), st.shards[0].sh.data_cache_lend());
        assert!(
            run(&st.shards[0]).0 - own + dc(&st.shards[0]) > l,
            "the shares overshoot before the pass"
        );
        // one sweep re-fits the data cache, then the run cache from the bytes it leaves
        st.clk.t += 10_000_000;
        st.poll(&mut acked).unwrap();
        let (l, rb, db) = (
            st.shards[0].sh.lendable(),
            run(&st.shards[0]).0 - own,
            dc(&st.shards[0]),
        );
        assert!(rb + db <= l, "run {rb} + data {db} over the lendable {l}");
        assert!(db <= st.shards[0].sh.data_cache_lend());
        assert!(rb <= run(&st.shards[0]).2 - own);
        // the tree grows into the lendable part (a smaller page budget under the same held pages): the sweep's two
        // fits follow it, the data cache first, the run cache from the bytes it leaves (the page exchange would
        // restore the budget here, so the fits run without it)
        let psz = st.shards[0].sh.tree_psz() as u64;
        let cap = st.shards[0].sh.state().tree.cap();
        st.shards[0]
            .sh
            .state_mut()
            .tree
            .set_cap(cap - (l / 2 / psz) as usize);
        let l2 = st.shards[0].sh.lendable();
        assert!(l2 < l);
        st.shards[0].pf_expire(st.clk.t + 10_000_000);
        st.shards[0].sh.olsm_fit_cache();
        let (rb, db) = (run(&st.shards[0]).0 - own, dc(&st.shards[0]));
        assert!(rb + db <= l2, "run {rb} + data {db} over the lendable {l2}");
        assert!(db <= st.shards[0].sh.data_cache_lend());
        assert!(rb <= run(&st.shards[0]).2 - own);
    }
}
