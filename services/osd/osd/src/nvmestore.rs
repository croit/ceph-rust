// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The OSD on the real storage engine (crates `store` + `storeadapt`): [`NvmeMeta`] implements [`MetaStore`]
//! (identity, superblock, osdmaps, meta values) as objects of the engine's meta collection, and
//! [`open_nvme`] splits one mounted [`Store`] into that plus the PG-side `PgStoreOps` (async queue/poll,
//! adr 0008). Both halves share the store handle; the owner thread never borrows it re-entrantly.
//!
//! Objects in the meta collection (pool -1): `identity`, `superblock` (data), `osdmap.<e:010>` (full map),
//! `inc.<e:010>` (incremental), `m.<key>` (informational values). Map commits and replacements are single
//! atomic txns; meta writes block until durable (rare: one per map message), PG writes never block.
use crate::backend::Backend;
use crate::meta::{Identity, MapKind, MetaError, MetaStore, Result};
use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use denc::{Decode, Encode};
use messages::{OsdSuperblock, StoreStatfs};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use store::dev::{BlockDev, Clock};
use store::obj::{OTxn, ObjError, Store, TOp};
use storeadapt::StoreAdapter;

/// Superblock feature bits of the mounted store (0 until mounted). Process-wide: set once at start, read by `tell status`.
static STORE_FEATURES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// A store was mounted (else the backend is a lab one without the on-disk name limit).
static STORE_MOUNTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Clones share extents (config `flashstore_store_shared_clone`, default on; adr 0021 am. 32) on a store with
/// `FEAT_SHARED_EXT` (set by mkfs). Off = kill switch, clones copy.
static STORE_SHARED_CLONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
/// Runs that served a read stay in the store data cache for re-reads (config `flashstore_store_pf_retain`, default on; adr
/// 0043 "Data cache"); false = read-cache bypass for device-path measurements.
static STORE_PF_RETAIN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
/// Helper-core run compaction (config `flashstore_store_compact_helpers`, adr 0534 am. 1): on by default (one job per free
/// helper core); `false` keeps every run compaction on the owner core.
static STORE_COMPACT_HELPERS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);
/// WAL group commit (config `flashstore_store_wal_coalesce`, adr 0021 am. 37): units in flight per shard before the open unit
/// waits for a completion; `usize::MAX` = store default, 0 = off.
static STORE_WAL_COALESCE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
/// Leaves one checkpoint turns into deltas (config `flashstore_store_ckpt_delta_leaves`, adr 0021 am. 39); `usize::MAX` = store
/// default, 0 = unbounded.
static STORE_CKPT_DELTA_LEAVES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
/// Leaf deltas built ahead of a checkpoint per core poll (config `flashstore_store_ckpt_slice`, adr 0021 am. 40); `usize::MAX` =
/// store default, 0 = synchronous checkpoint start.
static STORE_CKPT_SLICE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
/// Parked-txn lookahead (config `flashstore_store_park_lookahead`, adr 0021 am. 44); `usize::MAX` = store default, 0 = off.
static STORE_PARK_LOOKAHEAD: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
/// Values in data blocks from this size (config `flashstore_store_val_ext_min`, adr 0021 am. 46); `usize::MAX` = store default, 0 = off.
static STORE_VAL_EXT_MIN: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
/// User omap values (counted objects; not PG logs) compressed inline from this size (config `flashstore_store_val_comp_min`, adr 0021 am. 58); `usize::MAX` = store default, 0 = off.
static STORE_VAL_COMP_MIN: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
/// Opt-in LSM range-delete candidate threshold, fixed before stores mount; zero keeps native range deletes.
static OMAP_DELETE_RANGE_THRESHOLD: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// Preserve malformed startup input for a loud store_cfg error without reserving a valid u64 value.
static OMAP_DELETE_RANGE_THRESHOLD_VALID: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);
#[cfg(feature = "splinterdb")]
static SPLINTERDB_CONFIG: std::sync::Mutex<
    std::result::Result<Option<store::splinter_omap::Config>, String>,
> = std::sync::Mutex::new(Ok(None));

/// Cold tool provisioning override. Daemons use `set_store_options` instead.
#[cfg(feature = "splinterdb")]
pub fn set_splinterdb_config(cfg: Option<store::splinter_omap::Config>) {
    set_splinterdb_config_result(Ok(cfg));
}

/// Keep tool parsing errors dormant until the persistent format selects SplinterDB.
#[cfg(feature = "splinterdb")]
pub fn set_splinterdb_config_result(
    cfg: std::result::Result<Option<store::splinter_omap::Config>, String>,
) {
    *SPLINTERDB_CONFIG.lock().expect("store startup options") = cfg;
}
/// Foreground LSM listing batched demand reads and bounded next-chunk read-ahead (default on).
static OMAP_SCAN_PREFETCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
/// Cold startup configuration only: copied into each shard before mounting, never
/// locked on an operation path. The native store feature selects the engine.
#[cfg(feature = "rocksdb")]
static ROCKSDB_ROOT: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);
#[cfg(feature = "rocksdb")]
static ROCKSDB_PROFILE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "rocksdb")]
static ROCKSDB_WORKER_CPU: std::sync::Mutex<store::rocks_omap::WorkerCpu> =
    std::sync::Mutex::new(store::rocks_omap::WorkerCpu::Next);
/// `None` = the default tuning.
#[cfg(feature = "rocksdb")]
static ROCKSDB_TUNING: std::sync::Mutex<Option<store::rocks_omap::Tuning>> =
    std::sync::Mutex::new(None);
/// Persistent per-shard adaptive listing window (default on; requires scan prefetch).
static OMAP_SCAN_PREFETCH_ADAPTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);
/// Adaptive ceiling; zero preserves an invalid startup value until store_cfg rejects it.
static OMAP_SCAN_PREFETCH_MAX: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(16);
/// Fixed logical next chunks per active cursor; zero preserves invalid startup input.
static OMAP_SCAN_PREFETCH_CHUNKS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(1);
/// Cell sweeps while meta growth is blocked by fragmentation (config `flashstore_store_defrag_cells`, default on; adr 0021
/// am. 51).
static STORE_DEFRAG_CELLS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
/// Hole-first allocation below this many whole free windows (config `flashstore_store_keep_windows`, adr 0021 am. 51);
/// `usize::MAX` = store default, 0 = off.
static STORE_KEEP_WINDOWS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
/// Data runs of at most this many blocks are placed hole-first (config `flashstore_store_small_dense`, adr 0475);
/// `usize::MAX` = store default (16 = 64 KiB), 0 = kill switch.
static STORE_SMALL_DENSE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

/// Elastic pool (config `flashstore_store_lend_auto`, default ON when built with `elastic`, `false` disables; adr 0021 am. 52/53): shards ask the pool owner for chunks.
/// Needs a chunked store (mkfs `store_base_pct`) and a build with the `elastic` feature.
#[cfg(feature = "elastic")]
static STORE_LEND_AUTO: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
/// Ask below this percentage of a chunk of free space (config `flashstore_store_lend_wm_pct`); `usize::MAX` = store default.
#[cfg(feature = "elastic")]
static STORE_LEND_WM_PCT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
/// Pause after an empty pool answer, ms (config `flashstore_store_lend_retry_ms`); `usize::MAX` = store default.
#[cfg(feature = "elastic")]
static STORE_LEND_RETRY_MS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

/// Elastic reclaim tuning (adr 0021 am. 57, am. 61: reclaim always runs with `lend_auto`): `flashstore_store_reclaim_hyst_pct` /
/// `flashstore_store_reclaim_mbps` (`usize::MAX` = store default).
#[cfg(feature = "elastic")]
static STORE_RECLAIM: [std::sync::atomic::AtomicUsize; 2] = [
    std::sync::atomic::AtomicUsize::new(usize::MAX),
    std::sync::atomic::AtomicUsize::new(usize::MAX),
];

/// Last value of `k` in the local config (a key set twice: the last one wins).
fn local_opt<'a>(local: &'a [(String, String)], k: &str) -> Option<&'a str> {
    local
        .iter()
        .rev()
        .find(|(n, _)| n == k)
        .map(|(_, v)| v.trim())
}

/// Numeric option: absent or unparsable = `usize::MAX` (the store's default; `0` is a real value = off).
fn local_num(local: &[(String, String)], k: &str) -> usize {
    local_opt(local, k)
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(usize::MAX)
}

/// An on/off option in the local config (absent = on). Anything but a known spelling refuses the start: a typo must
/// not flip the option (the opt-in and opt-out flavours used to read it as the opposite value).
fn bool_option(local: &[(String, String)], k: &str) -> std::result::Result<bool, String> {
    let Some(v) = local_opt(local, k) else {
        return Ok(true);
    };
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(format!("{k} must be true or false, got {v:?}")),
    }
}

/// Elastic reclaim keys (am. 57) from the local config (last setting wins): `[hyst_pct, mbps]`.
#[cfg(feature = "elastic")]
fn reclaim_options(local: &[(String, String)]) -> [usize; 2] {
    [
        local_num(local, "flashstore_store_reclaim_hyst_pct"),
        local_num(local, "flashstore_store_reclaim_mbps"),
    ]
}

#[cfg(feature = "elastic")]
fn set_reclaim_options(local: &[(String, String)]) {
    for (a, v) in STORE_RECLAIM.iter().zip(reclaim_options(local)) {
        a.store(v, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Apply `reclaim_options` values to a shard config.
#[cfg(all(
    feature = "elastic",
    any(test, feature = "lab", feature = "spdk", feature = "kernel-nvme")
))]
fn apply_reclaim(c: &mut store::shard::ShardCfg, r: [usize; 2]) {
    if let n @ 0..=100 = r[0] {
        c.reclaim_hyst_pct = n as u32;
    }
    match r[1] {
        usize::MAX | 0 => {}
        n => c.reclaim_mbps = n.min(u32::MAX as usize) as u32,
    }
}

/// Serializes the tests that set the process-wide store options (`set_store_options`): parallel test threads would
/// overwrite each other's settings between set and read.
#[cfg(all(test, any(feature = "lab", feature = "spdk", feature = "kernel-nvme")))]
static OPTIONS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Read the `flashstore_store_*` store options (compact helpers, shared clone, reclaim, ...) from the local config (last
/// setting wins). Call once before mounting; an unknown on/off spelling refuses the start.
pub fn set_store_options(local: &[(String, String)]) -> std::result::Result<(), String> {
    use std::sync::atomic::Ordering::Relaxed;
    let threshold = local_opt(local, "flashstore_omap_delete_range_threshold")
        .map(str::parse::<u64>)
        .unwrap_or(Ok(0));
    OMAP_DELETE_RANGE_THRESHOLD.store(threshold.as_ref().copied().unwrap_or(0), Relaxed);
    OMAP_DELETE_RANGE_THRESHOLD_VALID.store(threshold.is_ok(), Relaxed);
    OMAP_SCAN_PREFETCH.store(
        bool_option(local, "flashstore_omap_scan_prefetch")?,
        Relaxed,
    );
    #[cfg(feature = "splinterdb")]
    {
        let parsed = (|| -> std::result::Result<_, String> {
            let get = |key: &str| {
                local
                    .iter()
                    .rev()
                    .find(|(n, _)| n == key)
                    .map(|(_, v)| v.trim())
            };
            let root = get("flashstore_store_splinterdb_dir").filter(|r| !r.is_empty());
            let mut cfg = store::splinter_omap::Config::new(root.unwrap_or_default().into(), 0);
            cfg.io = get("flashstore_store_splinterdb_io")
                .unwrap_or("buffered")
                .parse()
                .map_err(str::to_owned)?;
            cfg.prefetch_bytes = get("flashstore_store_splinterdb_prefetch_bytes")
                .unwrap_or("1048576")
                .parse()
                .map_err(|_| "invalid SplinterDB prefetch byte budget")?;
            cfg.scan_readahead_pages = get("flashstore_store_splinterdb_scan_readahead_pages")
                .unwrap_or("4")
                .parse()
                .map_err(|_| "invalid SplinterDB scan read-ahead pages")?;
            cfg.cache_stats =
                match get("flashstore_store_splinterdb_cache_stats").unwrap_or("false") {
                    "true" | "1" | "yes" | "on" => true,
                    "false" | "0" | "no" | "off" => false,
                    _ => return Err("invalid SplinterDB cache statistics boolean".into()),
                };
            cfg.isolate_cleaner =
                match get("flashstore_store_splinterdb_cleaner_isolation").unwrap_or("false") {
                    "true" | "1" | "yes" | "on" => true,
                    "false" | "0" | "no" | "off" => false,
                    _ => return Err("invalid SplinterDB cleaner isolation boolean".into()),
                };
            cfg.normal_maintenance =
                match get("flashstore_store_splinterdb_normal_maintenance").unwrap_or("false") {
                    "true" | "1" | "yes" | "on" => true,
                    "false" | "0" | "no" | "off" => false,
                    _ => return Err("invalid SplinterDB normal maintenance boolean".into()),
                };
            cfg.memtable_maintenance =
                match get("flashstore_store_splinterdb_memtable_maintenance").unwrap_or("false") {
                    "true" | "1" | "yes" | "on" => true,
                    "false" | "0" | "no" | "off" => false,
                    _ => return Err("invalid SplinterDB memtable maintenance boolean".into()),
                };
            cfg.pipelined_barrier =
                match get("flashstore_store_splinterdb_pipelined_barrier").unwrap_or("false") {
                    "true" | "1" | "yes" | "on" => true,
                    "false" | "0" | "no" | "off" => false,
                    _ => return Err("invalid SplinterDB pipelined barrier boolean".into()),
                };
            cfg.defer_log_writeback =
                match get("flashstore_store_splinterdb_defer_log_writeback").unwrap_or("false") {
                    "true" | "1" | "yes" | "on" => true,
                    "false" | "0" | "no" | "off" => false,
                    _ => return Err("invalid SplinterDB defer log writeback boolean".into()),
                };
            cfg.apply_threads = get("flashstore_store_splinterdb_apply_threads")
                .unwrap_or("1")
                .parse()
                .ok()
                .filter(|n| (1..=4).contains(n))
                .ok_or("SplinterDB apply threads must be in 1..=4")?;
            cfg.checkpoint_log_bytes = get("flashstore_store_splinterdb_checkpoint_log_bytes")
                .unwrap_or("0")
                .parse()
                .ok()
                .filter(|n: &u64| *n == 0 || (64 << 20..=4 << 30).contains(n))
                .ok_or("SplinterDB checkpoint log bytes must be 0 or 64MiB..=4GiB")?;
            if cfg.normal_maintenance && (!cfg.isolate_cleaner || cfg.cache_stats) {
                return Err("SplinterDB normal maintenance requires cleaner isolation and cache statistics disabled".into());
            }
            if cfg.memtable_maintenance && !cfg.normal_maintenance {
                return Err("SplinterDB memtable maintenance requires normal maintenance".into());
            }
            Ok(root.map(|_| cfg))
        })();
        *SPLINTERDB_CONFIG.lock().expect("store startup options") = parsed;
    }
    OMAP_SCAN_PREFETCH_ADAPTIVE.store(
        bool_option(local, "flashstore_omap_scan_prefetch_adaptive")?,
        Relaxed,
    );
    // a chunk window outside 1..=16 stays 0 here and refuses the start in `store_cfg` (no silent fallback)
    let chunks = local_opt(local, "flashstore_omap_scan_prefetch_chunks").map_or(1, |v| {
        v.parse::<usize>()
            .ok()
            .filter(|n| (1..=store::shard::OMAP_SCAN_PREFETCH_MAX_CHUNKS).contains(n))
            .unwrap_or(0)
    });
    OMAP_SCAN_PREFETCH_CHUNKS.store(chunks, Relaxed);
    let max_chunks = local_opt(local, "flashstore_omap_scan_prefetch_max_chunks").map_or(16, |v| {
        v.parse::<usize>()
            .ok()
            .filter(|n| (1..=store::shard::OMAP_SCAN_PREFETCH_MAX_CHUNKS).contains(n))
            .unwrap_or(0)
    });
    OMAP_SCAN_PREFETCH_MAX.store(max_chunks, Relaxed);
    STORE_COMPACT_HELPERS.store(
        bool_option(local, "flashstore_store_compact_helpers")?,
        Relaxed,
    );
    #[cfg(feature = "elastic")]
    set_reclaim_options(local);
    STORE_SHARED_CLONE.store(
        bool_option(local, "flashstore_store_shared_clone")?,
        Relaxed,
    );
    STORE_PF_RETAIN.store(bool_option(local, "flashstore_store_pf_retain")?, Relaxed);
    STORE_DEFRAG_CELLS.store(
        bool_option(local, "flashstore_store_defrag_cells")?,
        Relaxed,
    );
    for (a, k) in [
        (&STORE_WAL_COALESCE, "flashstore_store_wal_coalesce"),
        (
            &STORE_CKPT_DELTA_LEAVES,
            "flashstore_store_ckpt_delta_leaves",
        ),
        (&STORE_CKPT_SLICE, "flashstore_store_ckpt_slice"),
        (&STORE_PARK_LOOKAHEAD, "flashstore_store_park_lookahead"),
        (&STORE_VAL_EXT_MIN, "flashstore_store_val_ext_min"),
        (&STORE_VAL_COMP_MIN, "flashstore_store_val_comp_min"),
        (&STORE_KEEP_WINDOWS, "flashstore_store_keep_windows"),
        (&STORE_SMALL_DENSE, "flashstore_store_small_dense"),
    ] {
        a.store(local_num(local, k), Relaxed);
    }
    #[cfg(feature = "elastic")]
    {
        STORE_LEND_AUTO.store(bool_option(local, "flashstore_store_lend_auto")?, Relaxed);
        STORE_LEND_WM_PCT.store(local_num(local, "flashstore_store_lend_wm_pct"), Relaxed);
        STORE_LEND_RETRY_MS.store(local_num(local, "flashstore_store_lend_retry_ms"), Relaxed);
    }
    #[cfg(feature = "rocksdb")]
    {
        let o = rocksdb_options(local)?;
        ROCKSDB_PROFILE.store(o.profile, Relaxed);
        *ROCKSDB_ROOT.lock().expect("RocksDB startup config") = o.root;
        *ROCKSDB_WORKER_CPU.lock().expect("RocksDB startup config") = o.worker_cpu;
        *ROCKSDB_TUNING.lock().expect("RocksDB startup config") = o.tuning;
    }
    Ok(())
}

/// Parsed `flashstore_rocksdb_*` startup options (defaults when no RocksDB root is configured).
#[cfg(feature = "rocksdb")]
struct RocksdbOptions {
    root: Option<std::path::PathBuf>,
    profile: bool,
    worker_cpu: store::rocks_omap::WorkerCpu,
    tuning: Option<store::rocks_omap::Tuning>,
}

/// `flashstore_rocksdb_*` startup options. Without `flashstore_rocksdb_dir` no RocksDB store can open, so the other
/// RocksDB keys are ignored and reset to defaults: a native (LSM/B-tree) OSD sharing a config with RocksDB OSDs must
/// not refuse to start on keys it never reads. With a root, every key is validated before any is published.
#[cfg(feature = "rocksdb")]
fn rocksdb_options(local: &[(String, String)]) -> std::result::Result<RocksdbOptions, String> {
    let Some(root) = local_opt(local, "flashstore_rocksdb_dir").filter(|v| !v.is_empty()) else {
        return Ok(RocksdbOptions {
            root: None,
            profile: false,
            worker_cpu: store::rocks_omap::WorkerCpu::Next,
            tuning: None,
        });
    };
    let profile = local_opt(local, "flashstore_rocksdb_profile").is_some()
        && bool_option(local, "flashstore_rocksdb_profile")?;
    let key = "flashstore_rocksdb_worker_cpu";
    let worker_cpu = match local_opt(local, key) {
        None | Some("") => store::rocks_omap::WorkerCpu::Next,
        Some(v) => v.parse().map_err(|e| format!("{key} {e}"))?,
    };
    Ok(RocksdbOptions {
        root: Some(root.into()),
        profile,
        worker_cpu,
        tuning: Some(rocksdb_tuning(local)?),
    })
}

/// `flashstore_rocksdb_*` engine limits (absent or empty = default); out-of-range refuses the start.
#[cfg(feature = "rocksdb")]
fn rocksdb_tuning(
    local: &[(String, String)],
) -> std::result::Result<store::rocks_omap::Tuning, String> {
    let mut t = store::rocks_omap::Tuning::default();
    for (k, slot) in [
        ("flashstore_rocksdb_low_threads", &mut t.low_threads),
        ("flashstore_rocksdb_high_threads", &mut t.high_threads),
        ("flashstore_rocksdb_background_jobs", &mut t.background_jobs),
        (
            "flashstore_rocksdb_write_buffer_number",
            &mut t.write_buffers,
        ),
        ("flashstore_rocksdb_l0_slowdown_trigger", &mut t.l0_slowdown),
        ("flashstore_rocksdb_l0_stop_trigger", &mut t.l0_stop),
    ] {
        if let Some(v) = local_opt(local, k).filter(|v| !v.is_empty()) {
            *slot = v
                .parse()
                .map_err(|_| format!("{k} must be a number, got {v:?}"))?;
        }
    }
    t.validate().map_err(|e| e.to_string())?;
    Ok(t)
}

/// Object-state cache share of the cache budget in bytes (adr 0160 D5); 0 = no budget set (the share of the default
/// target).
static OBJ_CACHE_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Object-state cache heads per store cache scale unit (adr 0160 D5): one per two point-cache entries (an object's
/// object_info + snapset), i.e. the decoded tier covers the objects the store's point cache covers.
const OBJ_HEADS_PER_UNIT: u64 = store::obj::POINT_PER_UNIT / 2;

/// Split a cache budget into (store, object-state cache) bytes: each store cache unit is joined by its heads.
pub fn split_cache_budget(budget: u64) -> (u64, u64) {
    let heads = OBJ_HEADS_PER_UNIT * opexec::OBJ_HEAD_BYTES;
    let obj = (u128::from(budget) * u128::from(heads)
        / u128::from(store::obj::CACHE_UNIT_BYTES + heads)) as u64;
    (budget - obj, obj)
}

/// Object-state cache capacity per PG in heads (adr 0160 D5): the cache share over `pgs`, the PGs this OSD hosts (all
/// cores, primary and replica; 0 before the first count = one), so the caches of all its PGs stay within the share.
pub fn obj_cache_per_pg(pgs: u64) -> usize {
    let bytes = match OBJ_CACHE_BYTES.load(std::sync::atomic::Ordering::Relaxed) {
        0 => split_cache_budget(crate::memory::active().caches).1,
        b => b,
    };
    opexec::obj_cache_cap(bytes / pgs.max(1))
}

/// Does this OSD's backend store long object names (adr 0021 am. 30)? Lab backends without a store do.
pub fn long_names_supported() -> bool {
    !STORE_MOUNTED.load(std::sync::atomic::Ordering::Relaxed)
        || store_features() & store::layout::FEAT_LONG_NAME != 0
}

/// Feature bits of the mounted store, or 0 before the mount.
pub fn store_features() -> u64 {
    STORE_FEATURES.load(std::sync::atomic::Ordering::Relaxed)
}

/// `tell status` view: bits present.
pub fn store_feature_report() -> serde_json::Value {
    let f = store_features();
    serde_json::json!({
        "present": store::layout::feature_names(f),
    })
}

/// Epochs per atomic map-commit txn (keeps the WAL record small on large catch-ups).
const MAP_CHUNK: usize = 16;

fn err(what: &str, e: ObjError) -> MetaError {
    MetaError(format!("{what}: {e}"))
}

/// Ghobject of a named object in the meta collection.
fn meta_obj(name: &str) -> Ghobject {
    Ghobject::new(
        Hobject::new(name.as_bytes(), SnapId(0), 0, Hobject::POOL_META, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn map_name(e: u32, k: MapKind) -> String {
    match k {
        MapKind::Full => format!("osdmap.{e:010}"),
        MapKind::Inc => format!("inc.{e:010}"),
    }
}

fn parse_map_name(n: &[u8]) -> Option<(u32, MapKind)> {
    let s = std::str::from_utf8(n).ok()?;
    if let Some(e) = s.strip_prefix("osdmap.") {
        Some((e.parse().ok()?, MapKind::Full))
    } else {
        Some((s.strip_prefix("inc.")?.parse().ok()?, MapKind::Inc))
    }
}

/// [`MetaStore`] on the engine's meta collection.
pub struct NvmeMeta<D: BlockDev, C: Clock> {
    st: Rc<RefCell<Store<D, C>>>,
    /// Stored maps `(epoch, full?)`.
    maps: BTreeSet<(u32, bool)>,
}

impl<D: BlockDev, C: Clock> std::fmt::Debug for NvmeMeta<D, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NvmeMeta({} maps)", self.maps.len())
    }
}

impl<D: BlockDev, C: Clock> NvmeMeta<D, C> {
    /// Attach to a mounted store (creates the meta collection if missing, indexes the stored maps).
    pub fn new(st: Rc<RefCell<Store<D, C>>>) -> Result<Self> {
        let mut m = NvmeMeta {
            st,
            maps: BTreeSet::new(),
        };
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: CollT::Meta,
            bits: 0,
            exist_ok: true,
        });
        m.commit(&t)?;
        m.index_maps()?;
        Ok(m)
    }

    /// Attach to a store mounted read-only ([`Store::mount_shards_read_only`]): like [`Self::new`] but commits nothing;
    /// the meta collection (device shard 0) must exist.
    pub fn open_read_only(st: Rc<RefCell<Store<D, C>>>) -> Result<Self> {
        let mut m = NvmeMeta {
            st,
            maps: BTreeSet::new(),
        };
        let exists =
            m.st.borrow_mut()
                .coll_exists(&CollT::Meta)
                .map_err(|e| err("meta collection", e))?;
        if !exists {
            return Err(MetaError("meta collection: missing".into()));
        }
        m.index_maps()?;
        Ok(m)
    }

    /// Index the stored maps of the meta collection.
    fn index_maps(&mut self) -> Result<()> {
        let m = self;
        let mut cur = Ghobject::MIN();
        loop {
            let (objs, next) =
                m.st.borrow_mut()
                    .list(&CollT::Meta, &cur, None, 512)
                    .map_err(|e| err("list meta", e))?;
            for o in objs {
                if let Some((e, k)) = parse_map_name(&o.hobj.oid) {
                    m.maps.insert((e, k == MapKind::Full));
                }
            }
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }
        Ok(())
    }

    fn commit(&self, t: &OTxn) -> Result<()> {
        self.st.borrow_mut().commit(t).map_err(|e| err("commit", e))
    }

    pub(crate) fn read_obj(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let (c, o) = (CollT::Meta, meta_obj(name));
        let mut st = self.st.borrow_mut();
        match st.stat(&c, &o).map_err(|e| err(name, e))? {
            None => Ok(None),
            Some(s) => Ok(Some(st.read(&c, &o, 0, s.size).map_err(|e| err(name, e))?)),
        }
    }

    /// Replace the content of `name` (txn part).
    fn put<'a>(t: &mut OTxn<'a>, name: &str, data: Vec<u8>) {
        let o = meta_obj(name);
        t.push(TOp::Truncate {
            cid: CollT::Meta,
            oid: o.clone(),
            size: 0,
        });
        t.push(TOp::Write {
            cid: CollT::Meta,
            oid: o,
            off: 0,
            data: data.into(),
        });
    }

    fn put_now(&self, name: &str, data: Vec<u8>) -> Result<()> {
        let mut t = OTxn::new();
        Self::put(&mut t, name, data);
        self.commit(&t)
    }
}

/// The OSD-level space report of one store statfs (classic's fields; see the comments).
fn statfs_of(s: &store::obj::StoreStatfs) -> StoreStatfs {
    // Fullness is judged at the fullest shard (design 2.1, adr 0021 S4): PGs map to shards by hash, so one shard can
    // hit its floor while the device sum still reads nearfull. Charge at least that fill; on a pooled store the
    // shard's fill already counts the pool it can still borrow (`fullest_shard_pct`).
    let worst = (s.total_bytes as f64 * f64::from(s.fullest_shard_pct) / 100.0) as u64;
    let used = s.used_bytes.max(worst).min(s.total_bytes);
    // What is really held is `allocated`/`data_stored` (object data) plus `internal_metadata` (tree pages in use), as
    // classic reports its own allocations. The fullness charge above it (a hot shard, a meta-bound shard) is withheld capacity: Ceph's own
    // `internally_reserved`, part of total - available (full ratios, RAW USE, %USE) but not of DATA / META.
    let real = s.real_used_bytes.min(used);
    let meta = s.meta_used_bytes;
    // `real` holds the tree pages only on elastic shards: subtract just those from the data figure
    let data = real.saturating_sub(s.real_meta_bytes) as i64;
    StoreStatfs {
        total: s.total_bytes,
        available: s.total_bytes - used,
        internally_reserved: crate::meta::internally_reserved(
            s.total_bytes,
            s.total_bytes - used,
            real,
        ),
        allocated: data,
        data_stored: data,
        internal_metadata: meta as i64,
        ..Default::default()
    }
}

impl<D: BlockDev, C: Clock> MetaStore for NvmeMeta<D, C> {
    fn load_identity(&self) -> Result<Option<Identity>> {
        match self.read_obj("identity")? {
            None => Ok(None),
            Some(b) => Ok(Some(Identity::from_text(&String::from_utf8_lossy(&b))?)),
        }
    }

    fn store_identity(&mut self, id: &Identity) -> Result<()> {
        self.put_now("identity", id.to_text().into_bytes())
    }

    fn load_superblock(&self) -> Result<Option<OsdSuperblock>> {
        match self.read_obj("superblock")? {
            None => Ok(None),
            Some(b) => Ok(Some(
                OsdSuperblock::decode(&mut denc::Decoder::new(&b))
                    .map_err(|e| MetaError(format!("superblock: {e}")))?,
            )),
        }
    }

    fn store_superblock(&mut self, sb: &OsdSuperblock) -> Result<()> {
        let b = sb
            .encode_to_vec()
            .map_err(|e| MetaError(format!("superblock encode: {e}")))?;
        self.put_now("superblock", b)
    }

    fn commit_maps(&mut self, blobs: &[(u32, MapKind, Vec<u8>)], sb: &OsdSuperblock) -> Result<()> {
        // maps first (chunked), superblock last in its own txn: it never refers to missing maps
        for ch in blobs.chunks(MAP_CHUNK) {
            let mut t = OTxn::new();
            for (e, k, b) in ch {
                Self::put(&mut t, &map_name(*e, *k), b.clone());
            }
            self.commit(&t)?;
            for (e, k, _) in ch {
                self.maps.insert((*e, *k == MapKind::Full));
            }
        }
        self.store_superblock(sb)
    }

    fn get_map(&self, epoch: u32, kind: MapKind) -> Result<Option<Vec<u8>>> {
        if !self.maps.contains(&(epoch, kind == MapKind::Full)) {
            return Ok(None);
        }
        self.read_obj(&map_name(epoch, kind))
    }

    fn map_epochs(&self, through: u32) -> Result<Vec<u32>> {
        let mut epochs = Vec::new();
        for &(epoch, _) in self.maps.range(..=(through, true)) {
            if epochs.last() != Some(&epoch) {
                epochs.push(epoch);
            }
        }
        Ok(epochs)
    }

    fn size_mismatch(&self) -> Option<(u64, u64)> {
        self.st.borrow().size_mismatch()
    }

    fn statfs(&self) -> StoreStatfs {
        statfs_of(&self.st.borrow().statfs())
    }

    fn get_meta(&self, key: &str) -> Option<String> {
        let b = self.read_obj(&format!("m.{key}")).ok()??;
        Some(String::from_utf8_lossy(&b).trim().to_owned())
    }

    fn set_meta(&mut self, key: &str, val: &str) -> Result<()> {
        self.put_now(&format!("m.{key}"), val.as_bytes().to_vec())
    }

    fn bench_put(&mut self, slot: u64, data: &[u8]) -> Result<()> {
        self.put_now(&format!("bench.{slot}"), data.to_vec())
    }

    fn bench_cleanup(&mut self, slots: u64) -> Result<()> {
        let mut t = OTxn::new();
        for k in 0..slots {
            let o = meta_obj(&format!("bench.{k}"));
            // only what exists: called at every start (leftovers of a crashed bench), usually nothing to do
            if self
                .st
                .borrow_mut()
                .stat(&CollT::Meta, &o)
                .ok()
                .flatten()
                .is_some()
            {
                t.push(TOp::Remove {
                    cid: CollT::Meta,
                    oid: o,
                });
            }
        }
        if t.is_empty() {
            return Ok(());
        }
        self.commit(&t)
    }

    fn trim_maps(&mut self, below: u32) -> Result<u32> {
        // keep the newest full map at or before `below` (base for rebuilding later epochs)
        let Some(&(base, _)) = self
            .maps
            .range(..=(below, true))
            .rev()
            .find(|(_, full)| *full)
        else {
            return Ok(self.maps.iter().next().map_or(0, |m| m.0));
        };
        let old: Vec<(u32, bool)> = self.maps.range(..(base, false)).copied().collect();
        for ch in old.chunks(MAP_CHUNK * 4) {
            let mut t = OTxn::new();
            for (e, full) in ch {
                let k = if *full { MapKind::Full } else { MapKind::Inc };
                t.push(TOp::Remove {
                    cid: CollT::Meta,
                    oid: meta_obj(&map_name(*e, k)),
                });
            }
            self.commit(&t)?;
            for x in ch {
                self.maps.remove(x);
            }
        }
        Ok(base)
    }
}

/// Both OSD-side views of one mounted store.
#[expect(missing_debug_implementations)]
pub struct NvmeStores<D: BlockDev, C: Clock> {
    pub meta: NvmeMeta<D, C>,
    pub pgs: StoreAdapter<D, C>,
}

/// [`Backend`] on the NVMe store (static dispatch).
#[derive(Debug)]
pub struct Nvme<D, C>(std::marker::PhantomData<(D, C)>);

impl<D: BlockDev, C: Clock> Backend for Nvme<D, C> {
    type Meta = NvmeMeta<D, C>;
    type Pg = StoreAdapter<D, C>;
    fn set_omap_delete_range_threshold(pg: &Self::Pg, threshold: u64) {
        pg.with_store(|s| s.set_omap_delete_range_threshold(threshold));
    }
    fn helpers_configured(pg: &Self::Pg) -> bool {
        pg.with_store(|s| s.helpers_configured())
    }
    fn compaction_helpers(pg: &Self::Pg, helpers: bool, credit: usize) {
        pg.with_store(|s| s.compaction_helpers(helpers, credit));
    }
    fn take_compaction(pg: &Self::Pg) -> Option<store::shard::HelperJob> {
        pg.with_store(Store::take_compaction)
    }
    fn return_compaction(pg: &Self::Pg, job: store::shard::HelperJob, publish: bool) -> bool {
        pg.with_store(|s| s.return_compaction(job, publish))
    }
    fn compaction_activity(pg: &Self::Pg, queued: usize, completed: bool) {
        pg.with_store(|s| s.compaction_activity(queued, completed));
    }
}

/// Wire a mounted store into the OSD: finishes interrupted PG removals, returns the meta and PG halves.
pub fn open_nvme<D: BlockDev, C: Clock>(store: Store<D, C>) -> Result<NvmeStores<D, C>> {
    let shared = Rc::new(RefCell::new(store));
    let meta = NvmeMeta::new(shared.clone())?;
    let ad = StoreAdapter::from_shared(shared);
    ad.resume_removals()
        .map_err(|e| err("resume pg removals", e))?;
    ad.recover_structural()
        .map_err(|e| err("finish pg split cleanup", e))?;
    Ok(NvmeStores { meta, pgs: ad })
}

/// Wire a per-core store (only this core's shards mounted, [`Store::mount_shards`]) into a worker core: the PG half
/// only (the meta collection lives on shard 0, core 0's). Finishes interrupted PG removals / splits of its shards.
pub fn open_nvme_pgs<D: BlockDev, C: Clock>(store: Store<D, C>) -> Result<StoreAdapter<D, C>> {
    let ad = StoreAdapter::from_shared(Rc::new(RefCell::new(store)));
    ad.resume_removals()
        .map_err(|e| err("resume pg removals", e))?;
    ad.recover_structural()
        .map_err(|e| err("finish pg split cleanup", e))?;
    Ok(ad)
}

// ---------------- devices

#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
pub use devs::*;

#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
mod devs {
    use super::*;

    use nvme::any::{AnyCtrl, AnyDev};
    use store::dev::MonoClock;
    use store::error::StoreError;
    use store::layout::{MkfsParams, mkfs, read_super};
    use store::obj::StoreCfg;

    /// Store cache budget in bytes of the whole process (0 = built-in per-shard defaults), adr 0062.
    static CACHE_BUDGET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// Size the store caches and the object-state caches (adr 0160 D5) and set the process envelope (adr 0175) from
    /// `osd_memory_target`, `osd_memory_base` and `osd_memory_cache_min`, each from the local config (`--set`, conf file)
    /// before the mon config db fetched at start (`mon`, [`crate::monboot::boot`], adr 0175 am. 2) before the Ceph
    /// default: file above mon, as in Ceph. Call once before mounting; a later change applies at the next start. Returns
    /// the startup log line (value and source of each option, the shares).
    pub fn set_memory_target(
        local: &[(String, String)],
        mon: &std::collections::BTreeMap<String, String>,
    ) -> String {
        let get = |k: &str, d: u64| {
            local
                .iter()
                .rev()
                .find(|(n, _)| n == k)
                .and_then(|(_, v)| crate::memory::parse_size(v))
                .map(|v| (v, "local"))
                .or_else(|| {
                    mon.get(k)
                        .and_then(|v| crate::memory::parse_size(v))
                        .map(|v| (v, "mon"))
                })
                .unwrap_or((d, "default"))
        };
        let target = get("osd_memory_target", crate::memory::TARGET_DEFAULT);
        let base = get("osd_memory_base", crate::memory::BASE_DEFAULT);
        let min = get("osd_memory_cache_min", crate::memory::CACHE_MIN_DEFAULT);
        let env = crate::memory::Envelope::derive(target.0, base.0, min.0);
        crate::memory::set(env);
        let budget = env.caches;
        CACHE_BUDGET.store(budget, std::sync::atomic::Ordering::Relaxed);
        OBJ_CACHE_BYTES.store(
            split_cache_budget(budget).1,
            std::sync::atomic::Ordering::Relaxed,
        );
        let mib = |b: u64| b >> 20;
        format!(
            "memory envelope: osd_memory_target {} MiB ({}), osd_memory_base {} MiB ({}), osd_memory_cache_min {} MiB ({}): \
             caches {} MiB, ingress {} MiB",
            mib(target.0),
            target.1,
            mib(base.0),
            base.1,
            mib(min.0),
            min.1,
            mib(env.caches),
            mib(env.ingress)
        )
    }

    /// Charge `bytes` of fixed pinned buffers (`what`) against the envelope's caches share after
    /// [`set_memory_target`] and before mounting ([`crate::memory::Envelope::charge_pinned`]). Returns the startup log
    /// line, or the refusal when the target cannot hold them.
    pub fn charge_pinned(bytes: u64, what: &str) -> std::result::Result<String, String> {
        let env = crate::memory::active().charge_pinned(bytes, what)?;
        crate::memory::set(env);
        CACHE_BUDGET.store(env.caches, std::sync::atomic::Ordering::Relaxed);
        OBJ_CACHE_BYTES.store(
            split_cache_budget(env.caches).1,
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(format!(
            "memory envelope: {what} pins {} MiB: pinned {} MiB, caches {} MiB",
            bytes >> 20,
            env.pinned >> 20,
            env.caches >> 20
        ))
    }

    /// Current cache budget in bytes (store + object-state caches, [`split_cache_budget`]; 0 = defaults).
    pub fn cache_budget() -> u64 {
        CACHE_BUDGET.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The omap run budget of this process's device (all per-core stores join it, adr 0476).
    static RUN_POOL: std::sync::LazyLock<std::sync::Arc<store::runs::RunPool>> =
        std::sync::LazyLock::new(Default::default);
    /// The queue state table of this process's device (all per-core stores publish in it, adr 0533).
    static DEV_IDLE: std::sync::LazyLock<std::sync::Arc<store::devidle::DevIdle>> =
        std::sync::LazyLock::new(Default::default);
    /// The tree page budget of this process's device (all per-core stores' shards exchange in it, adr 0062 am. 3).
    static PAGE_POOL: std::sync::LazyLock<std::sync::Arc<store::pagepool::PagePool>> =
        std::sync::LazyLock::new(Default::default);

    /// A numeric store option (`usize::MAX` = the store's default) applied to a config field.
    fn apply(a: &std::sync::atomic::AtomicUsize, f: impl FnOnce(usize)) {
        match a.load(std::sync::atomic::Ordering::Relaxed) {
            usize::MAX => {}
            n => f(n),
        }
    }

    /// [`apply`] for an option the store keeps as `u32`: above `u32::MAX` the start is refused (the cast would wrap the
    /// value into a smaller, different threshold instead of applying what was configured).
    fn apply_u32(
        a: &std::sync::atomic::AtomicUsize,
        k: &str,
        f: impl FnOnce(u32),
    ) -> std::result::Result<(), String> {
        match a.load(std::sync::atomic::Ordering::Relaxed) {
            usize::MAX => Ok(()),
            n => {
                let v = u32::try_from(n)
                    .map_err(|_| format!("{k} must be at most {}, got {n}", u32::MAX))?;
                f(v);
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn store_cfg(total_shards: u32) -> std::result::Result<StoreCfg, String> {
        store_cfg_for_features(total_shards, 0)
    }

    pub(super) fn store_cfg_for_features(
        total_shards: u32,
        _features: u64,
    ) -> std::result::Result<StoreCfg, String> {
        use std::sync::atomic::Ordering::Relaxed;
        let mut c = match CACHE_BUDGET.load(Relaxed) {
            0 => StoreCfg::default(),
            b => StoreCfg::for_memory(split_cache_budget(b).0, total_shards)
                .map_err(|e| e.to_string())?,
        };
        c.shard.require_current = true;
        if !OMAP_DELETE_RANGE_THRESHOLD_VALID.load(Relaxed) {
            return Err(
                "flashstore_omap_delete_range_threshold must be an unsigned 64-bit integer".into(),
            );
        }
        c.shard.omap_delete_range_threshold = OMAP_DELETE_RANGE_THRESHOLD.load(Relaxed);
        #[cfg(feature = "rocksdb")]
        {
            c.shard.rocksdb = ROCKSDB_ROOT
                .lock()
                .expect("RocksDB startup config")
                .as_ref()
                .map(|root| {
                    let mut r = store::rocks_omap::Config::new(root.clone());
                    r.profile = ROCKSDB_PROFILE.load(Relaxed);
                    r.worker_cpu = *ROCKSDB_WORKER_CPU.lock().expect("RocksDB startup config");
                    r.tuning = ROCKSDB_TUNING
                        .lock()
                        .expect("RocksDB startup config")
                        .unwrap_or_default();
                    #[cfg(target_os = "linux")]
                    {
                        // SAFETY: sched_getcpu has no pointer arguments or side effects.
                        let cpu = unsafe { libc::sched_getcpu() };
                        r.cpu = (cpu >= 0).then_some(cpu as usize);
                    }
                    r
                });
        }
        c.shard.omap_scan_prefetch = OMAP_SCAN_PREFETCH.load(Relaxed);
        c.shard.omap_scan_prefetch_adaptive = OMAP_SCAN_PREFETCH_ADAPTIVE.load(Relaxed);
        let chunks = OMAP_SCAN_PREFETCH_CHUNKS.load(Relaxed);
        #[cfg(feature = "splinterdb")]
        if _features & store::layout::FEAT_OMAP_SPLINTERDB != 0 {
            c.shard.splinterdb = SPLINTERDB_CONFIG
                .lock()
                .map_err(|e| e.to_string())?
                .clone()?;
        }
        if !(1..=store::shard::OMAP_SCAN_PREFETCH_MAX_CHUNKS).contains(&chunks) {
            return Err("flashstore_omap_scan_prefetch_chunks must be an integer in 1..=16".into());
        }
        c.shard.omap_scan_prefetch_chunks = chunks;
        let max_chunks = OMAP_SCAN_PREFETCH_MAX.load(Relaxed);
        if !(1..=store::shard::OMAP_SCAN_PREFETCH_MAX_CHUNKS).contains(&max_chunks) {
            return Err(
                "flashstore_omap_scan_prefetch_max_chunks must be an integer in 1..=16".into(),
            );
        }
        c.shard.omap_scan_prefetch_max_chunks = max_chunks;
        // per-core stores of the device share one run budget: a hot object's shard may use the share of idle ones
        c.shard.run_pool = Some(RUN_POOL.clone());
        // background work of every core's shards sees the whole device's queues (adr 0533)
        c.shard.dev_idle = Some(DEV_IDLE.clone());
        // and one tree page budget: a hot shard's tree may use the pages idle shards leave unused
        c.shard.page_pool = Some(PAGE_POOL.clone());
        c.shard.run_helpers = STORE_COMPACT_HELPERS.load(Relaxed);
        c.shard.shared_clone = STORE_SHARED_CLONE.load(Relaxed);
        c.shard.pf_retain = STORE_PF_RETAIN.load(Relaxed);
        c.shard.defrag_cells = STORE_DEFRAG_CELLS.load(Relaxed);
        apply(&STORE_WAL_COALESCE, |n| c.shard.wal_coalesce = n);
        apply(&STORE_CKPT_DELTA_LEAVES, |n| c.shard.ckpt_delta_leaves = n);
        apply(&STORE_CKPT_SLICE, |n| c.shard.ckpt_slice = n);
        apply(&STORE_PARK_LOOKAHEAD, |n| c.shard.park_lookahead = n);
        apply_u32(&STORE_VAL_EXT_MIN, "flashstore_store_val_ext_min", |n| {
            c.shard.val_ext_min = n
        })?;
        apply_u32(&STORE_VAL_COMP_MIN, "flashstore_store_val_comp_min", |n| {
            c.shard.val_comp_min = n
        })?;
        apply(&STORE_KEEP_WINDOWS, |n| {
            c.shard.keep_windows = n.min(u32::MAX as usize) as u32
        });
        apply(&STORE_SMALL_DENSE, |n| {
            c.shard.small_dense = n.min(store::alloc::WIN as usize) as u32
        });
        #[cfg(feature = "elastic")]
        {
            c.shard.lend_auto = STORE_LEND_AUTO.load(Relaxed);
            apply(&STORE_LEND_WM_PCT, |n| {
                c.shard.lend_wm_pct = n.min(100) as u32
            });
            apply(&STORE_LEND_RETRY_MS, |n| c.shard.lend_retry_ms = n as u64);
            apply_reclaim(
                &mut c.shard,
                STORE_RECLAIM.each_ref().map(|a| a.load(Relaxed)),
            );
        }
        Ok(c)
    }

    /// Remember the mounted store's feature bits (status).
    fn note_features<D: BlockDev, C: Clock>(st: &Store<D, C>) {
        let f = st.features();
        STORE_FEATURES.store(f, std::sync::atomic::Ordering::Relaxed);
        STORE_MOUNTED.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Startup line: how freed data blocks reach the device (adr 0642), with the limits of one command.
    fn note_trim<D: BlockDev>(d: &D) {
        let (l, ls) = (d.dealloc_limits(), u64::from(d.geometry().lba_size));
        if l.is_on() {
            eprintln!(
                "store: trim={} ranges={} range_max={}B max={}B gran={}B",
                l.via,
                l.max_ranges,
                u64::from(l.range_lbas) * ls,
                l.max_lbas.saturating_mul(ls),
                l.gran_lbas * ls
            );
        } else {
            eprintln!("store: trim={}", l.via);
        }
    }

    /// The store type the daemon runs on.
    pub type DevStore = Store<AnyDev, MonoClock>;

    /// mkfs parameters for a device of `bytes` with `shards` store shards (`store_shards`, adr 0160): WAL rings and
    /// alignment per [`MkfsParams::for_device`].
    pub fn mkfs_params_for(bytes: u64, shards: u32) -> MkfsParams {
        MkfsParams::for_device(bytes, shards)
    }

    /// Format the device (destroys its content).
    pub fn mkfs_dev(ctrl: &AnyCtrl, p: &MkfsParams) -> std::result::Result<(), String> {
        let mut dev = ctrl.open_queue()?;
        let mut clk = MonoClock::default();
        #[cfg(feature = "splinterdb")]
        if p.omap_splinterdb {
            let cfg = SPLINTERDB_CONFIG
                .lock()
                .map_err(|e| e.to_string())?
                .clone()?
                .ok_or("SplinterDB mkfs requires explicit root/capacity")?;
            cfg.validate_create(64 << 20).map_err(|e| e.to_string())?;
            let g = dev.geometry();
            if g.vwc && !p.allow_volatile_cache {
                return Err("native device has volatile cache".into());
            }
            let (sb, _) =
                store::layout::plan(g.capacity_bytes().min(p.max_bytes) / store::BLK as u64, p)
                    .map_err(|e| e.to_string())?;
            store::splinter_omap::create(&cfg, &sb, 64 << 20).map_err(|e| e.to_string())?;
        }
        mkfs(&mut dev, &mut clk, p)
            .map(|_| ())
            .map_err(|e| format!("mkfs: {e:?}"))
    }

    /// Does the device hold a store (any intact superblock copy)? A store of an unsupported (newer) format, with a
    /// damaged directory or an unreadable superblock counts as formatted: mkfs must never re-create it without `--wipe`
    /// (the mount then fails with the reason). A queue that cannot be opened is an error, never "not formatted".
    pub fn is_formatted(ctrl: &AnyCtrl) -> std::result::Result<bool, String> {
        formatted_on(ctrl.open_queue())
    }

    /// [`is_formatted`] on an opened (or failed) queue: fails closed.
    pub(super) fn formatted_on<D: BlockDev>(
        q: std::result::Result<D, String>,
    ) -> std::result::Result<bool, String> {
        let mut d = q.map_err(|e| format!("cannot probe the device for a store: {e}"))?;
        Ok(!matches!(
            read_super(&mut d, &mut MonoClock::default()),
            Err(store::StoreError::NotFormatted)
        ))
    }

    /// Extra queue handle the pool owner needs for the lending table (adr 0021 am. 49/52: completions must not mix with a
    /// shard's): 1 on a chunked store with the pool in use, else 0. Only the store mounting shard 0 asks for it.
    fn pool_queue(sb: &store::layout::Superblock) -> usize {
        // the same predicate `Store::mount_with` takes the lending table for (`FEAT_CHUNKED` + `lend_auto`)
        #[cfg(feature = "elastic")]
        if sb.features & store::layout::FEAT_CHUNKED != 0
            && STORE_LEND_AUTO.load(std::sync::atomic::Ordering::Relaxed)
        {
            return 1;
        }
        let _ = sb;
        0
    }

    /// Mount (replays the WAL of every shard).
    pub fn mount_dev(
        ctrl: &AnyCtrl,
    ) -> std::result::Result<(DevStore, Vec<store::wal::ReplayStats>), String> {
        mount_queues(ctrl, |q| q, false, None)
    }

    /// Writable offline repair mount (`croit-flashstore-tool repair`): root usage counter drift is tolerated
    /// (`ShardCfg::repair_counters`), every structural check stays; false frees are fenced before replay and false-free
    /// metadata cells are allocated by the mount's own checkpoint (`ShardCfg::repair_fence`).
    pub fn mount_dev_repair(
        ctrl: &AnyCtrl,
    ) -> std::result::Result<(DevStore, Vec<store::wal::ReplayStats>), String> {
        mount_queues(ctrl, |q| q, false, Some(true))
    }

    /// The repair dry pass: [`mount_dev_read_only`] with the false-free fence of [`mount_dev_repair`], so the overlay
    /// replays and checkpoints exactly as the writable repair mount will.
    pub fn mount_dev_repair_preview(
        ctrl: &AnyCtrl,
    ) -> std::result::Result<(RoStore, Vec<store::wal::ReplayStats>), String> {
        let over = store::dev::Overlay::default();
        mount_queues(
            ctrl,
            move |q| store::dev::CowDev::new(q, over.clone()),
            true,
            Some(true),
        )
    }

    /// A mount of the device's store that never writes to it (`croit-flashstore-tool fsck`): replay, the post-replay checkpoint,
    /// superblock healing and a `--accept-wal-loss` cut happen in a memory overlay ([`store::dev::CowDev`]).
    pub type RoStore = Store<store::dev::CowDev<AnyDev>, MonoClock>;

    /// See [`RoStore`]. Root usage counter drift is tolerated (`ShardCfg::repair_counters`): the checks report it.
    pub fn mount_dev_read_only(
        ctrl: &AnyCtrl,
    ) -> std::result::Result<(RoStore, Vec<store::wal::ReplayStats>), String> {
        refuse_splinter_read_only(ctrl)?;
        let over = store::dev::Overlay::default();
        mount_queues(
            ctrl,
            move |q| store::dev::CowDev::new(q, over.clone()),
            true,
            Some(false),
        )
    }

    /// Mount a subset of the device's shards read-only for the degraded offline export (`croit-flashstore-tool
    /// objectstore --skip-shard` / `--shards`): the device is wrapped in a [`store::dev::CowDev`] overlay so nothing
    /// reaches it, and only the shards `owned` accepts are opened and replayed ([`Store::mount_shards_read_only`]).
    /// A selected shard whose mount fails (damaged meta region) is recorded, not fatal; the returned report is indexed
    /// by device shard id.
    pub fn mount_dev_read_only_shards(
        ctrl: &AnyCtrl,
        owned: impl Fn(u32) -> bool,
    ) -> std::result::Result<
        (
            RoStore,
            Vec<store::wal::ReplayStats>,
            Vec<store::obj::ShardMountState>,
        ),
        String,
    > {
        let over = store::dev::Overlay::default();
        mount_queues_shards(
            ctrl,
            move |q| store::dev::CowDev::new(q, over.clone()),
            owned,
        )
    }

    /// [`mount_dev_read_only_shards`] on wrapped queue handles: one per owned shard (the superblock handle is reused for
    /// the first owned shard, as in [`Store::mount_shards_read_only`]).
    #[expect(clippy::type_complexity)]
    fn mount_queues_shards<D: BlockDev>(
        ctrl: &AnyCtrl,
        mut wrap: impl FnMut(AnyDev) -> D,
        owned: impl Fn(u32) -> bool,
    ) -> std::result::Result<
        (
            Store<D, MonoClock>,
            Vec<store::wal::ReplayStats>,
            Vec<store::obj::ShardMountState>,
        ),
        String,
    > {
        let mut d0 = wrap(ctrl.open_queue()?);
        let (sb, _) = read_super(&mut d0, &mut MonoClock::default())
            .map_err(|e| format!("superblock: {e:?}"))?;
        ctrl.apply_dsm_verdict(sb.dsm_verdict);
        note_trim(&d0);
        let n_owned = (0..sb.shards).filter(|s| owned(*s)).count();
        let mut qs = vec![d0];
        for _ in 1..n_owned {
            qs.push(wrap(ctrl.open_queue()?));
        }
        let cfg = store_cfg_for_features(sb.shards, sb.features)?;
        let (st, stats, report) = Store::mount_shards_read_only(
            move || qs.pop().expect("one queue per owned shard prepared"),
            MonoClock::default(),
            cfg,
            owned,
        )
        .map_err(|e| format!("mount: {e}"))?;
        note_features(&st);
        Ok((st, stats, report))
    }

    /// Header-only gate: CowDev cannot protect a separately stored foreign image.
    pub fn refuse_splinter_read_only(ctrl: &AnyCtrl) -> std::result::Result<(), String> {
        let mut d = ctrl.open_queue()?;
        let (sb, _) = read_super(&mut d, &mut MonoClock::default()).map_err(|e| e.to_string())?;
        if sb.features & store::layout::FEAT_OMAP_SPLINTERDB != 0 {
            return Err("SplinterDB read-only inspection/dry-run is unsupported: its public open mutates the database".into());
        }
        Ok(())
    }

    fn mount_queues<D: BlockDev>(
        ctrl: &AnyCtrl,
        mut wrap: impl FnMut(AnyDev) -> D,
        _read_only: bool,
        repair: Option<bool>,
    ) -> std::result::Result<(Store<D, MonoClock>, Vec<store::wal::ReplayStats>), String> {
        let mut d0 = wrap(ctrl.open_queue()?);
        let (sb, _) = read_super(&mut d0, &mut MonoClock::default())
            .map_err(|e| format!("superblock: {e:?}"))?;
        // runtime deallocate follows the verdict the mkfs probe stored (adr 0169 am. 8); opens never probe DSM
        ctrl.apply_dsm_verdict(sb.dsm_verdict);
        note_trim(&d0);
        let mut qs = vec![d0];
        for _ in 1..sb.shards as usize + pool_queue(&sb) {
            qs.push(wrap(ctrl.open_queue()?));
        }
        let mut cfg = store_cfg_for_features(sb.shards, sb.features)?;
        // `repair`: None = daemon/tool mount, Some(fence) = offline check/repair mount (counter drift tolerated)
        cfg.shard.repair_counters = repair.is_some();
        cfg.shard.repair_fence = repair == Some(true);
        #[cfg(feature = "rocksdb")]
        if let Some(r) = &mut cfg.shard.rocksdb {
            r.read_only = _read_only;
        }
        if sb.features & store::layout::FEAT_OMAP_SPLINTERDB != 0 && cache_budget() == 0 {
            // Offline-tool default: explicit 256MiB native+foreign share per shard.
            // Production callers set the process memory envelope before mount.
            cfg.shard.cache_pages = (256 << 20) / sb.node_size as usize;
        }
        let (st, stats) = Store::mount(
            move || qs.pop().expect("one queue per shard prepared"),
            MonoClock::default(),
            cfg,
        )
        .map_err(|e| format!("mount: {e}"))?;
        note_features(&st);
        Ok((st, stats))
    }

    /// Run the offline format upgrade steps of adr 0611 on the device (`croit-flashstore-tool upgrade`; the OSD is stopped).
    pub fn upgrade_dev(
        ctrl: &AnyCtrl,
        opts: store::upgrade::Opts,
        ev: &mut dyn FnMut(&store::upgrade::Event),
    ) -> std::result::Result<store::upgrade::Report, store::upgrade::UpgradeError> {
        use store::upgrade::UpgradeError;
        let mut d0 = ctrl.open_queue().map_err(UpgradeError::Open)?;
        let (sb, _) = read_super(&mut d0, &mut MonoClock::default())?;
        let cfg = store_cfg_for_features(sb.shards, sb.features)
            .map_err(|e| UpgradeError::Obj(ObjError::Invalid(format!("store config: {e}"))))?;
        store::upgrade::run(|| ctrl.open_queue(), MonoClock::default(), cfg, opts, ev)
    }

    /// Exit code of an OSD whose store format this build cannot serve as is (EX_CONFIG): an offline upgrade step is
    /// needed or was interrupted, or a newer build wrote the store (adr 0611).
    pub const EXIT_FORMAT: i32 = 78;

    /// Shard count of the formatted device `spec` (superblock), after the format gate: `Err((EXIT_FORMAT, ..))` with the
    /// exact `croit-flashstore-tool upgrade` command when an offline step is needed (adr 0611), `Err((1, ..))` otherwise.
    pub fn device_shards(ctrl: &AnyCtrl, spec: &str) -> std::result::Result<u32, (i32, String)> {
        let mut d0 = ctrl.open_queue().map_err(|e| (1, e))?;
        let (sb, _) = read_super(&mut d0, &mut MonoClock::default()).map_err(|e| match e {
            StoreError::Newer(m) => (EXIT_FORMAT, format!("superblock: {m}")),
            e => (1, format!("superblock: {e:?}")),
        })?;
        store::upgrade::mount_check(&sb).map_err(|e| match e {
            StoreError::UpgradeNeeded(m) => (
                EXIT_FORMAT,
                format!(
                    "store upgrade needed: {m}; with this OSD stopped run: croit-flashstore-tool upgrade --dev {spec}"
                ),
            ),
            StoreError::Newer(m) => (EXIT_FORMAT, m),
            e => (1, format!("superblock: {e}")),
        })?;
        Ok(sb.shards)
    }

    /// The queue handles core `core` of `n` needs to mount its shards (`shard % n == core`): one per shard. Opened on
    /// the calling thread, usable on any one thread afterwards (`AnyDev: Send`).
    pub fn core_queues(
        ctrl: &AnyCtrl,
        shards: u32,
        core: usize,
        n: usize,
    ) -> std::result::Result<Vec<AnyDev>, String> {
        let mut owned = (0..shards).filter(|s| *s as usize % n == core).count();
        if core == 0 {
            // the core of shard 0 owns the pool (one more queue for the lending table)
            let mut d0 = ctrl.open_queue()?;
            let (sb, _) = read_super(&mut d0, &mut MonoClock::default())
                .map_err(|e| format!("superblock: {e:?}"))?;
            owned += pool_queue(&sb);
            // as `mount_queues`: the stored DSM verdict before any shard reads the device's deallocate limits (the cores
            // mount after every core's queues exist, core 0's first)
            ctrl.apply_dsm_verdict(sb.dsm_verdict);
            note_trim(&d0);
        }
        (0..owned).map(|_| ctrl.open_queue()).collect()
    }

    /// Mount the shards of core `core` (WAL replay of those shards only) with the queues of [`core_queues`].
    /// `shards` = the device's shard count: the cache budget is split per shard over all of them, so a core that owns
    /// more shards (cores not dividing shards) gets the larger share its load needs.
    /// `cpus` is the launcher's selected physical service CPU list, not the
    /// already-pinned calling thread's affinity or a support-thread CPU pool.
    pub fn mount_dev_core(
        mut qs: Vec<AnyDev>,
        core: usize,
        cpus: &[usize],
        shards: u32,
    ) -> std::result::Result<(DevStore, Vec<store::wal::ReplayStats>), String> {
        let n = cpus.len();
        if core >= n {
            return Err("core outside selected service CPU budget".into());
        }
        // `mount_shards` opens one handle for the superblock (reused for the first shard) and one per further shard,
        // plus the pool table on the core holding shard 0: a count that does not match is an error, not a panic inside
        // the mount closure.
        let Some(d0) = qs.first_mut() else {
            return Err(format!("core {core} of {n} owns no shard of {shards}"));
        };
        let (sb, _) =
            read_super(d0, &mut MonoClock::default()).map_err(|e| format!("superblock: {e:?}"))?;
        let owned = (0..shards).filter(|s| *s as usize % n == core).count()
            + if core == 0 { pool_queue(&sb) } else { 0 };
        if qs.len() != owned {
            return Err(format!(
                "core {core} of {n} needs {owned} queue handles for {shards} shards, got {}",
                qs.len()
            ));
        }
        let cfg = store_cfg_for_features(shards, sb.features)?;
        #[cfg(any(feature = "rocksdb", feature = "splinterdb"))]
        let cfg = {
            let mut cfg = cfg;
            #[cfg(feature = "rocksdb")]
            if let Some(r) = &mut cfg.shard.rocksdb {
                r.set_cpu_budget(core, cpus).map_err(|e| e.to_string())?;
            }
            #[cfg(feature = "splinterdb")]
            {
                let (worker, cleaner) = splinter_worker_cpus(cpus, core)?;
                place_splinter_cpus(&mut cfg, n, Some(worker), cleaner);
                // Apply helpers float within the service CPU set (no extra CPU),
                // off this shard's worker and maintenance CPUs when possible.
                if let Some(foreign) = &mut cfg.shard.splinterdb
                    && n > 1
                {
                    foreign.apply_cpus =
                        splinter_apply_cpus(cpus, foreign.cpu, foreign.cleaner_cpu);
                }
            }
            cfg
        };
        let r = Store::mount_shards(
            move || qs.pop().expect("one queue per owned shard prepared"),
            MonoClock::default(),
            cfg,
            move |s| s as usize % n == core,
        )
        .map_err(|e| format!("mount core {core}: {e}"))?;
        note_features(&r.0);
        Ok(r)
    }

    #[cfg(feature = "splinterdb")]
    pub(super) fn splinter_worker_cpus(
        cpus: &[usize],
        core: usize,
    ) -> std::result::Result<(usize, Option<usize>), String> {
        let n = cpus.len();
        if core >= n {
            return Err("foreign worker CPU map does not match the assigned OSD cores".into());
        }
        Ok((cpus[(core + 1) % n], (n > 1).then(|| cpus[(core + 2) % n])))
    }

    /// CPUs for a shard's apply helpers: the service set without the shard's
    /// SplinterDB worker and maintenance/cleaner CPUs, which already carry the
    /// worker's own apply slice and the library's background threads. Falls back
    /// to the whole set when fewer than two CPUs would remain.
    #[cfg(feature = "splinterdb")]
    pub(super) fn splinter_apply_cpus(
        cpus: &[usize],
        worker: Option<usize>,
        cleaner: Option<usize>,
    ) -> Vec<usize> {
        let rest: Vec<usize> = cpus
            .iter()
            .copied()
            .filter(|c| Some(*c) != worker && Some(*c) != cleaner)
            .collect();
        if rest.len() > 1 { rest } else { cpus.to_vec() }
    }

    #[cfg(feature = "splinterdb")]
    pub(super) fn place_splinter_cpus(
        cfg: &mut StoreCfg,
        cores: usize,
        worker: Option<usize>,
        cleaner: Option<usize>,
    ) {
        if let Some(foreign) = &mut cfg.shard.splinterdb {
            foreign.cleaner_cpu = None;
            if let Some(cpu) = worker {
                foreign.cpu = Some(cpu);
                if foreign.isolate_cleaner && cores > 1 {
                    foreign.cleaner_cpu = cleaner.filter(|c| *c != cpu);
                }
            }
        }
    }

    /// Daemon start: open the `--dev` spec, mount (WAL replay), return both halves plus a one-line mount report.
    /// `spdk:` specs need the SPDK environment initialized by the caller first.
    pub fn open_dev_spec(
        spec: &str,
    ) -> std::result::Result<(NvmeStores<AnyDev, MonoClock>, String), String> {
        let spec = nvme::any::DevSpec::parse(spec)?;
        let ctrl = AnyCtrl::open_exclusive(&spec)?;
        open_dev_ctrl(&ctrl, spec.is_dev_only())
    }

    /// [`open_dev_spec`] on an already opened controller.
    pub fn open_dev_ctrl(
        ctrl: &AnyCtrl,
        dev_only: bool,
    ) -> std::result::Result<(NvmeStores<AnyDev, MonoClock>, String), String> {
        let t0 = std::time::Instant::now();
        let (st, stats) = mount_dev(ctrl)?;
        let txns: u64 = stats.iter().map(|s| s.txns).sum();
        let report = format!(
            "store mounted ({} shards, replayed {txns} txns in {} ms){}",
            st.nshards(),
            t0.elapsed().as_millis(),
            if dev_only {
                " [DEV/LAB file device]"
            } else {
                ""
            }
        );
        let parts = open_nvme(st).map_err(|e| e.to_string())?;
        Ok((parts, report))
    }
}

#[cfg(test)]
mod statfs_split_tests {
    use super::*;

    fn raw(real: u64, meta_in_real: u64) -> store::obj::StoreStatfs {
        store::obj::StoreStatfs {
            total_bytes: 1 << 30,
            used_bytes: real,
            real_used_bytes: real,
            real_meta_bytes: meta_in_real,
            meta_used_pages: 100,
            meta_used_bytes: 100 * 8192,
            ..Default::default()
        }
    }

    /// Elastic shards: tree pages lie in `real_used_bytes`, so DATA is real - meta. Fixed meta region: `real_used_bytes`
    /// is data only (the region is outside the data blocks), DATA must not shrink by META.
    #[test]
    fn data_is_real_minus_meta_only_where_meta_is_inside_real() {
        let meta = 100 * 8192;
        let el = statfs_of(&raw(10 << 20, meta));
        assert_eq!(el.allocated, (10 << 20) - meta as i64);
        assert_eq!(el.allocated, el.data_stored);
        assert_eq!(el.internal_metadata, meta as i64);
        let fixed = statfs_of(&raw(10 << 20, 0));
        assert_eq!(fixed.allocated, 10 << 20);
        assert_eq!(fixed.data_stored, 10 << 20);
        assert_eq!(fixed.internal_metadata, meta as i64);
        // META is the store's page bytes: a 4 KiB-page store (node_size 4096) must not report 8 KiB per page
        let mut small_pages = raw(10 << 20, 0);
        small_pages.meta_used_bytes = 100 * 4096;
        assert_eq!(statfs_of(&small_pages).internal_metadata, 100 * 4096);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::types::Uuid;
    use store::dev::{SimClock, SimConfig, SimDisk};
    use store::layout::{MkfsParams, mkfs};
    use store::obj::StoreCfg;

    fn mount(disk: &SimDisk) -> NvmeMeta<store::dev::SimDev, SimClock> {
        let d = disk.clone();
        let (st, _) =
            Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default()).unwrap();
        NvmeMeta::new(Rc::new(RefCell::new(st))).unwrap()
    }

    /// An unknown on/off spelling is an error, never the opposite of what was meant: the opt-in and opt-out flavours
    /// used to read a typo as the other value in silence.
    #[test]
    fn on_off_options_reject_unknown_spellings() {
        let kv = |v: &str| vec![("flashstore_store_shared_clone".to_string(), v.to_string())];
        let key = "flashstore_store_shared_clone";
        assert_eq!(bool_option(&[], key), Ok(true), "absent = on");
        for on in ["true", "1", "yes", "on", "TRUE", "On"] {
            assert_eq!(bool_option(&kv(on), key), Ok(true), "{on}");
        }
        for off in ["false", "0", "no", "off", "Off"] {
            assert_eq!(bool_option(&kv(off), key), Ok(false), "{off}");
        }
        let e = bool_option(&kv("flase"), key).unwrap_err();
        assert!(e.contains(key) && e.contains("flase"), "{e}");
    }

    /// D3: the store probe fails closed: a queue that cannot be opened is an error, never "not formatted" (mkfs/prepare
    /// would discard and re-create an existing store).
    #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
    #[test]
    fn store_probe_fails_closed() {
        use super::devs::formatted_on;
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        assert!(formatted_on::<store::dev::SimDev>(Err("no qpair".into())).is_err());
        assert_eq!(formatted_on(Ok(disk.queue())), Ok(false));
        let p = MkfsParams {
            shards: 1,
            wal_blocks: 256,
            align_blocks: 1,
            meta_pct: 8,
            ..Default::default()
        };
        mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
        assert_eq!(formatted_on(Ok(disk.queue())), Ok(true));
        // a newer build's store (unknown incompat bit): formatted, never re-created by an older build's mkfs
        {
            let mut d = disk.queue();
            let mut c = SimClock::default();
            let (mut sb, _) = store::layout::read_super(&mut d, &mut c).unwrap();
            sb.features |= 1 << 40;
            store::layout::heal_super(&mut d, &mut c, &sb).unwrap();
        }
        assert_eq!(formatted_on(Ok(disk.queue())), Ok(true));
        // unreadable superblock: formatted (the mount reports the reason), never re-created
        disk.fail_reads(0, 2);
        assert_eq!(formatted_on(Ok(disk.queue())), Ok(true));
    }

    /// `mount_dev_core` mounts exactly the queues [`core_queues`] prepared: one too few is an error naming the counts,
    /// never a panic inside the mount closure.
    #[cfg(feature = "lab")]
    #[test]
    fn mount_dev_core_refuses_a_queue_count_that_does_not_match_the_shards() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = std::env::temp_dir().join(format!(
            "croit-flashstore-qcount-{}.img",
            std::process::id()
        ));
        let spec = nvme::any::DevSpec::parse(&format!("file:{},size=64M", path.display())).unwrap();
        let ctrl = nvme::any::AnyCtrl::open_exclusive_create(&spec, true).unwrap();
        set_store_options(&[]).unwrap();
        let p = MkfsParams {
            shards: 4,
            wal_blocks: 512,
            align_blocks: 16,
            meta_pct: 4,
            allow_volatile_cache: true,
            ..Default::default()
        };
        mkfs_dev(&ctrl, &p).unwrap();
        let mut qs = core_queues(&ctrl, 4, 0, 2).unwrap();
        let needed = qs.len();
        qs.pop().unwrap();
        let cpus = [0, 1];
        let Err(e) = mount_dev_core(qs, 0, &cpus, 4) else {
            panic!("a queue handle too few must be refused");
        };
        assert!(e.contains(&format!("needs {needed}")), "{e}");
        // the prepared count mounts
        let (st, _) = mount_dev_core(core_queues(&ctrl, 4, 0, 2).unwrap(), 0, &cpus, 4).unwrap();
        drop(st);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "lab")]
    #[test]
    fn mount_dev_core_rejects_invalid_cpu_budgets_before_queue_access() {
        for (core, cpus) in [(0, &[][..]), (2, &[3, 7][..])] {
            assert!(matches!(mount_dev_core(Vec::new(), core, cpus, 4),
                Err(e) if e.contains("outside selected service CPU budget")));
        }
    }

    /// Backing configuration is startup-only; format selection stays persistent.
    #[cfg(all(
        feature = "splinterdb",
        any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
    ))]
    #[test]
    fn splinter_workers_rotate_within_sparse_selected_service_cpu_vectors() {
        let cpus = [8, 11, 17, 23];
        for (core, expected) in [(11, Some(17)), (17, Some(23)), (23, Some(8)), (8, Some(11))]
            .into_iter()
            .enumerate()
        {
            assert_eq!(devs::splinter_worker_cpus(&cpus, core).unwrap(), expected);
        }
        assert_eq!(devs::splinter_worker_cpus(&[17], 0).unwrap(), (17, None));
        assert_eq!(
            devs::splinter_worker_cpus(&[9, 31], 0).unwrap(),
            (31, Some(9))
        );
        assert_eq!(
            devs::splinter_worker_cpus(&[9, 31], 1).unwrap(),
            (9, Some(31))
        );
        assert!(devs::splinter_worker_cpus(&[], 0).is_err());
        assert!(devs::splinter_worker_cpus(&cpus, 4).is_err());
    }

    #[cfg(all(
        feature = "splinterdb",
        any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
    ))]
    #[test]
    fn splinter_apply_helpers_avoid_worker_and_maintenance_cpus() {
        let cpus = [4, 5, 6, 7];
        // Core 1: worker 6, cleaner/maintenance 7 -> helpers on 4 and 5.
        let (worker, cleaner) = devs::splinter_worker_cpus(&cpus, 1).unwrap();
        assert_eq!(
            devs::splinter_apply_cpus(&cpus, Some(worker), cleaner),
            [4, 5]
        );
        // Without cleaner isolation only the worker CPU is excluded.
        assert_eq!(devs::splinter_apply_cpus(&cpus, Some(6), None), [4, 5, 7]);
        // Fewer than two remaining CPUs: keep floating over the whole set.
        assert_eq!(
            devs::splinter_apply_cpus(&[4, 5, 6], Some(5), Some(6)),
            [4, 5, 6]
        );
        assert_eq!(
            devs::splinter_apply_cpus(&[9, 31], Some(31), Some(9)),
            [9, 31]
        );
    }

    #[cfg(all(
        feature = "splinterdb",
        any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
    ))]
    fn splinter_store_cfg(shards: u32) -> std::result::Result<store::obj::StoreCfg, String> {
        devs::store_cfg_for_features(
            shards,
            store::layout::FEAT_OMAP_LSM | store::layout::FEAT_OMAP_SPLINTERDB,
        )
    }

    #[cfg(all(
        feature = "splinterdb",
        any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
    ))]
    #[test]
    fn unused_splinter_options_never_poison_other_engine_mount_configuration() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = SPLINTERDB_CONFIG.lock().unwrap().clone();
        for root in [None, Some("/unused/foreign/root")] {
            for (key, value) in [
                ("flashstore_store_splinterdb_io", "invalid"),
                ("flashstore_store_splinterdb_prefetch_bytes", "not-a-number"),
                (
                    "flashstore_store_splinterdb_scan_readahead_pages",
                    "not-a-number",
                ),
                ("flashstore_store_splinterdb_cache_stats", "invalid"),
                ("flashstore_store_splinterdb_cleaner_isolation", "invalid"),
                ("flashstore_store_splinterdb_normal_maintenance", "true"),
            ] {
                let mut options = vec![(key.to_string(), value.to_string())];
                if let Some(root) = root {
                    options.push(("flashstore_store_splinterdb_dir".into(), root.into()));
                }
                set_store_options(&options).unwrap();
                for features in [
                    0,
                    store::layout::FEAT_OMAP_LSM,
                    store::layout::FEAT_OMAP_LSM | store::layout::FEAT_OMAP_ROCKSDB,
                ] {
                    let cfg = devs::store_cfg_for_features(4, features).unwrap();
                    assert!(cfg.shard.splinterdb.is_none(), "unused backend {key}");
                }
                assert!(
                    splinter_store_cfg(4).is_err(),
                    "selected backend must refuse {key}"
                );
            }
        }
        // Valid-but-unused configuration is not forwarded or admitted either.
        set_store_options(&[(
            "flashstore_store_splinterdb_dir".into(),
            "/unused/foreign/root".into(),
        )])
        .unwrap();
        assert!(store_cfg(4).unwrap().shard.splinterdb.is_none());
        assert!(splinter_store_cfg(4).unwrap().shard.splinterdb.is_some());
        // Offline-tool argument parsing uses the same deferred result gate.
        set_splinterdb_config_result(Err("tool SplinterDB option error".into()));
        assert!(store_cfg(4).unwrap().shard.splinterdb.is_none());
        assert_eq!(
            splinter_store_cfg(4).unwrap_err(),
            "tool SplinterDB option error"
        );
        *SPLINTERDB_CONFIG.lock().unwrap() = original;
    }

    #[cfg(all(
        feature = "splinterdb",
        any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
    ))]
    #[test]
    fn splinter_startup_root_is_forwarded_but_never_selects_an_engine() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = SPLINTERDB_CONFIG.lock().unwrap().clone();
        set_store_options(&[(
            "flashstore_store_splinterdb_dir".into(),
            "  /explicit/omap-root  ".into(),
        )])
        .unwrap();
        let cfg = splinter_store_cfg(1).unwrap();
        assert_eq!(
            cfg.shard.splinterdb.as_ref().unwrap().io,
            store::splinter_omap::IoMode::Buffered
        );
        assert_eq!(
            cfg.shard.splinterdb.as_ref().unwrap().root,
            std::path::PathBuf::from("/explicit/omap-root")
        );
        assert!(!mkfs_params_for(64 << 20, 1).omap_splinterdb);
        assert!(!cfg.shard.splinterdb.as_ref().unwrap().isolate_cleaner);
        assert_eq!(cfg.shard.splinterdb.as_ref().unwrap().cleaner_cpu, None);
        set_store_options(&[]).unwrap();
        assert!(store_cfg(1).unwrap().shard.splinterdb.is_none());
        *SPLINTERDB_CONFIG.lock().unwrap() = original;
    }

    #[cfg(all(
        feature = "splinterdb",
        any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
    ))]
    #[test]
    fn splinter_cleaner_cpu_resolution_is_local_opt_in_and_has_legacy_fallbacks() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = SPLINTERDB_CONFIG.lock().unwrap().clone();
        let mut options = vec![
            (
                "flashstore_store_splinterdb_dir".into(),
                "/explicit/omap-root".into(),
            ),
            (
                "flashstore_store_splinterdb_cleaner_isolation".into(),
                "true".into(),
            ),
        ];
        set_store_options(&options).unwrap();
        let base = splinter_store_cfg(4).unwrap();
        assert!(base.shard.splinterdb.as_ref().unwrap().isolate_cleaner);
        let mut a = base.clone();
        let mut b = base.clone();
        devs::place_splinter_cpus(&mut a, 4, Some(11), Some(17));
        devs::place_splinter_cpus(&mut b, 4, Some(17), Some(23));
        assert_eq!(a.shard.splinterdb.as_ref().unwrap().cleaner_cpu, Some(17));
        assert_eq!(b.shard.splinterdb.as_ref().unwrap().cleaner_cpu, Some(23));
        assert_eq!(base.shard.splinterdb.as_ref().unwrap().cpu, None);
        assert_eq!(
            splinter_store_cfg(4)
                .unwrap()
                .shard
                .splinterdb
                .unwrap()
                .cleaner_cpu,
            None
        );
        devs::place_splinter_cpus(&mut a, 1, Some(11), Some(17));
        assert_eq!(a.shard.splinterdb.as_ref().unwrap().cleaner_cpu, None);
        devs::place_splinter_cpus(&mut a, 4, None, Some(17));
        assert_eq!(a.shard.splinterdb.as_ref().unwrap().cpu, Some(11));
        assert_eq!(a.shard.splinterdb.as_ref().unwrap().cleaner_cpu, None);
        devs::place_splinter_cpus(&mut a, 4, Some(17), Some(17));
        assert_eq!(a.shard.splinterdb.as_ref().unwrap().cleaner_cpu, None);
        a.shard.splinterdb.as_mut().unwrap().isolate_cleaner = false;
        devs::place_splinter_cpus(&mut a, 4, Some(11), Some(17));
        assert_eq!(a.shard.splinterdb.as_ref().unwrap().cleaner_cpu, None);
        options.push((
            "flashstore_store_splinterdb_cleaner_isolation".into(),
            "invalid".into(),
        ));
        set_store_options(&options).unwrap();
        assert!(
            splinter_store_cfg(4)
                .unwrap_err()
                .contains("cleaner isolation boolean")
        );
        *SPLINTERDB_CONFIG.lock().unwrap() = original;
    }

    #[cfg(all(
        feature = "splinterdb",
        any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
    ))]
    #[test]
    fn splinter_normal_maintenance_is_strict_opt_in_without_expanding_placement() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = SPLINTERDB_CONFIG.lock().unwrap().clone();
        let mut options = vec![
            (
                "flashstore_store_splinterdb_dir".into(),
                "/explicit/omap-root".into(),
            ),
            (
                "flashstore_store_splinterdb_normal_maintenance".into(),
                "true".into(),
            ),
        ];
        set_store_options(&options).unwrap();
        assert!(
            splinter_store_cfg(4)
                .unwrap_err()
                .contains("requires cleaner isolation")
        );
        options.push((
            "flashstore_store_splinterdb_cleaner_isolation".into(),
            "true".into(),
        ));
        set_store_options(&options).unwrap();
        let mut cfg = splinter_store_cfg(4).unwrap();
        assert!(cfg.shard.splinterdb.as_ref().unwrap().normal_maintenance);
        devs::place_splinter_cpus(&mut cfg, 4, Some(11), Some(17));
        let foreign = cfg.shard.splinterdb.as_ref().unwrap();
        assert_eq!((foreign.cpu, foreign.cleaner_cpu), (Some(11), Some(17)));
        devs::place_splinter_cpus(&mut cfg, 1, Some(11), Some(17));
        assert_eq!(cfg.shard.splinterdb.as_ref().unwrap().cleaner_cpu, None);
        options.push((
            "flashstore_store_splinterdb_cache_stats".into(),
            "true".into(),
        ));
        set_store_options(&options).unwrap();
        assert!(
            splinter_store_cfg(4)
                .unwrap_err()
                .contains("cache statistics disabled")
        );
        options.push((
            "flashstore_store_splinterdb_normal_maintenance".into(),
            "invalid".into(),
        ));
        set_store_options(&options).unwrap();
        assert!(
            splinter_store_cfg(4)
                .unwrap_err()
                .contains("normal maintenance boolean")
        );
        options.push((
            "flashstore_store_splinterdb_normal_maintenance".into(),
            "false".into(),
        ));
        set_store_options(&options).unwrap();
        assert!(
            !splinter_store_cfg(4)
                .unwrap()
                .shard
                .splinterdb
                .unwrap()
                .normal_maintenance
        );
        *SPLINTERDB_CONFIG.lock().unwrap() = original;
    }

    #[cfg(all(
        feature = "splinterdb",
        any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
    ))]
    #[test]
    fn splinter_read_policy_is_explicit_and_invalid_io_never_falls_back() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = SPLINTERDB_CONFIG.lock().unwrap().clone();
        let mut options = vec![
            (
                "flashstore_store_splinterdb_dir".into(),
                "/explicit/omap-root".into(),
            ),
            ("flashstore_store_splinterdb_io".into(), "buffered".into()),
            (
                "flashstore_store_splinterdb_prefetch_bytes".into(),
                "262144".into(),
            ),
            (
                "flashstore_store_splinterdb_scan_readahead_pages".into(),
                "3".into(),
            ),
            (
                "flashstore_store_splinterdb_cache_stats".into(),
                "true".into(),
            ),
        ];
        set_store_options(&options).unwrap();
        let cfg = splinter_store_cfg(1).unwrap().shard.splinterdb.unwrap();
        assert_eq!(cfg.io, store::splinter_omap::IoMode::Buffered);
        assert_eq!(cfg.prefetch_bytes, 262144);
        assert_eq!(cfg.scan_readahead_pages, 3);
        assert!(cfg.cache_stats);
        options.push(("flashstore_store_splinterdb_io".into(), "invalid".into()));
        set_store_options(&options).unwrap();
        assert!(
            splinter_store_cfg(1)
                .unwrap_err()
                .contains("direct or buffered")
        );
        *SPLINTERDB_CONFIG.lock().unwrap() = original;
    }

    #[cfg(all(
        feature = "splinterdb",
        any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
    ))]
    #[test]
    fn splinter_apply_threads_and_memtable_maintenance_parse_strictly() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = SPLINTERDB_CONFIG.lock().unwrap().clone();
        let base: Vec<(String, String)> = vec![(
            "flashstore_store_splinterdb_dir".into(),
            "/explicit/omap-root".into(),
        )];
        set_store_options(&base).unwrap();
        let cfg = splinter_store_cfg(1).unwrap().shard.splinterdb.unwrap();
        assert_eq!((cfg.apply_threads, cfg.memtable_maintenance), (1, false));
        for (value, ok) in [
            ("3", true),
            ("4", true),
            ("0", false),
            ("5", false),
            ("x", false),
        ] {
            let mut options = base.clone();
            options.push((
                "flashstore_store_splinterdb_apply_threads".into(),
                value.into(),
            ));
            set_store_options(&options).unwrap();
            match splinter_store_cfg(1) {
                Ok(c) => {
                    assert!(ok, "accepted {value}");
                    assert_eq!(
                        c.shard.splinterdb.unwrap().apply_threads,
                        value.parse::<usize>().unwrap()
                    );
                }
                Err(e) => {
                    assert!(!ok, "refused {value}");
                    assert!(e.contains("apply threads"));
                }
            }
        }
        set_store_options(&base).unwrap();
        assert_eq!(
            splinter_store_cfg(1)
                .unwrap()
                .shard
                .splinterdb
                .unwrap()
                .checkpoint_log_bytes,
            0,
            "default keeps the library's checkpoint size"
        );
        for (value, ok) in [
            ("0", true),
            ("67108864", true),
            ("1073741824", true),
            ("4294967296", true),
            ("67108863", false),
            ("4294967297", false),
            ("1GiB", false),
        ] {
            let mut options = base.clone();
            options.push((
                "flashstore_store_splinterdb_checkpoint_log_bytes".into(),
                value.into(),
            ));
            set_store_options(&options).unwrap();
            match splinter_store_cfg(1) {
                Ok(c) => {
                    assert!(ok, "accepted {value}");
                    assert_eq!(
                        c.shard.splinterdb.unwrap().checkpoint_log_bytes,
                        value.parse::<u64>().unwrap()
                    );
                }
                Err(e) => {
                    assert!(!ok, "refused {value}");
                    assert!(e.contains("checkpoint log bytes"), "{e}");
                }
            }
        }
        let mut options = base.clone();
        options.push((
            "flashstore_store_splinterdb_memtable_maintenance".into(),
            "true".into(),
        ));
        set_store_options(&options).unwrap();
        assert!(
            splinter_store_cfg(1)
                .unwrap_err()
                .contains("requires normal maintenance")
        );
        options.push((
            "flashstore_store_splinterdb_cleaner_isolation".into(),
            "true".into(),
        ));
        options.push((
            "flashstore_store_splinterdb_normal_maintenance".into(),
            "true".into(),
        ));
        set_store_options(&options).unwrap();
        assert!(
            splinter_store_cfg(1)
                .unwrap()
                .shard
                .splinterdb
                .unwrap()
                .memtable_maintenance
        );
        options.push((
            "flashstore_store_splinterdb_memtable_maintenance".into(),
            "maybe".into(),
        ));
        set_store_options(&options).unwrap();
        assert!(
            splinter_store_cfg(1)
                .unwrap_err()
                .contains("memtable maintenance boolean")
        );
        *SPLINTERDB_CONFIG.lock().unwrap() = original;
    }

    /// W1: `fsck`'s mount never writes the device (a normal mount does: new root, epoch).
    #[cfg(all(feature = "lab", feature = "splinterdb"))]
    #[test]
    fn native_engines_mount_with_unusable_splinter_options() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = SPLINTERDB_CONFIG.lock().unwrap().clone();
        for lsm in [false, true] {
            let path = std::env::temp_dir().join(format!(
                "croit-flashstore-unused-sdb-{}-{lsm}.img",
                std::process::id()
            ));
            let spec =
                nvme::any::DevSpec::parse(&format!("file:{},size=64M", path.display())).unwrap();
            let ctrl = nvme::any::AnyCtrl::open_exclusive_create(&spec, true).unwrap();
            mkfs_dev(
                &ctrl,
                &MkfsParams {
                    shards: 1,
                    wal_blocks: 512,
                    align_blocks: 16,
                    meta_pct: 4,
                    allow_volatile_cache: true,
                    omap_lsm: lsm,
                    ..Default::default()
                },
            )
            .unwrap();
            set_store_options(&[
                (
                    "flashstore_store_splinterdb_dir".into(),
                    "relative-unused-root".into(),
                ),
                ("flashstore_store_splinterdb_io".into(), "invalid".into()),
            ])
            .unwrap();
            let (st, _) = mount_dev_read_only(&ctrl).unwrap();
            drop(st);
            let (st, _) = mount_dev(&ctrl).unwrap();
            drop(st);
            drop(ctrl);
            std::fs::remove_file(path).unwrap();
        }
        *SPLINTERDB_CONFIG.lock().unwrap() = original;
    }

    #[cfg(feature = "lab")]
    #[test]
    fn read_only_device_mount_writes_nothing() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = std::env::temp_dir().join(format!(
            "croit-flashstore-romount-{}.img",
            std::process::id()
        ));
        let spec = nvme::any::DevSpec::parse(&format!("file:{},size=64M", path.display())).unwrap();
        let ctrl = nvme::any::AnyCtrl::open_exclusive_create(&spec, true).unwrap();
        let p = MkfsParams {
            shards: 2,
            wal_blocks: 512,
            align_blocks: 16,
            meta_pct: 4,
            allow_volatile_cache: true,
            ..Default::default()
        };
        mkfs_dev(&ctrl, &p).unwrap();
        let before = std::fs::read(&path).unwrap();
        let (st, _) = mount_dev_read_only(&ctrl).unwrap();
        drop(st);
        assert!(
            std::fs::read(&path).unwrap() == before,
            "read-only mount wrote the device"
        );
        let (st, _) = mount_dev(&ctrl).unwrap();
        drop(st);
        assert!(
            std::fs::read(&path).unwrap() != before,
            "a normal mount writes (test not vacuous)"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn meta_roundtrip_restart_and_trim() {
        let disk = SimDisk::new(SimConfig::new(512 << 20));
        let p = MkfsParams {
            shards: 1,
            wal_blocks: 1024,
            align_blocks: 1,
            meta_pct: 8,
            ..Default::default()
        };
        mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
        let id = Identity {
            whoami: 4,
            cluster_fsid: Uuid([1; 16]),
            osd_fsid: Uuid([2; 16]),
            key: "AQ==".into(),
            crush_device_class: "nvme".into(),
            created_at: "t".into(),
            ceph_version_when_created: "v".into(),
        };
        let mut m = mount(&disk);
        assert!(m.load_identity().unwrap().is_none() && m.load_superblock().unwrap().is_none());
        m.store_identity(&id).unwrap();
        let mut sb = OsdSuperblock {
            cluster_fsid: id.cluster_fsid,
            whoami: 4,
            osd_fsid: id.osd_fsid,
            ..Default::default()
        };
        sb.current_epoch = 100;
        let mut blobs = Vec::new();
        for e in 1..=100u32 {
            blobs.push((e, MapKind::Inc, vec![e as u8; 700]));
            if e % 10 == 0 {
                blobs.push((e, MapKind::Full, vec![e as u8; 5000]));
            }
        }
        m.commit_maps(&blobs, &sb).unwrap();
        m.set_meta("k", "v").unwrap();
        // crash-style restart: nothing flushed explicitly, WAL replay brings it back
        drop(m);
        let mut m = mount(&disk);
        assert_eq!(m.load_identity().unwrap().unwrap(), id);
        assert_eq!(m.load_superblock().unwrap().unwrap(), sb);
        // Full/inc duplicates collapse; the actual index survives remount even without sb.mapc.
        assert_eq!(m.map_epochs(37).unwrap(), (1..=37).collect::<Vec<_>>());
        assert_eq!(m.map_epochs(1000).unwrap(), (1..=100).collect::<Vec<_>>());
        assert_eq!(
            m.get_map(37, MapKind::Inc).unwrap().unwrap(),
            vec![37u8; 700]
        );
        assert_eq!(
            m.get_map(40, MapKind::Full).unwrap().unwrap(),
            vec![40u8; 5000]
        );
        assert!(m.get_map(37, MapKind::Full).unwrap().is_none());
        assert_eq!(m.get_meta("k").as_deref(), Some("v"));
        // trim below 55: newest full at or before 55 is 50, everything older goes
        assert_eq!(m.trim_maps(55).unwrap(), 50);
        assert!(
            m.get_map(49, MapKind::Inc).unwrap().is_none()
                && m.get_map(40, MapKind::Full).unwrap().is_none()
        );
        assert!(
            m.get_map(50, MapKind::Full).unwrap().is_some()
                && m.get_map(51, MapKind::Inc).unwrap().is_some()
        );
        drop(m);
        let m = mount(&disk);
        assert_eq!(m.map_epochs(60).unwrap(), (50..=60).collect::<Vec<_>>());
        assert!(
            m.get_map(49, MapKind::Inc).unwrap().is_none()
                && m.get_map(60, MapKind::Full).unwrap().is_some()
        );
        let sf = m.statfs();
        assert!(sf.total > 0);
        // reported fill is never below the fullest shard's (one hot shard must trip the full flags, ADR 0021 am. 5)
        let st = m.st.borrow().statfs();
        assert!(
            sf.available as f64
                <= sf.total as f64 * (1.0 - f64::from(st.fullest_shard_pct) / 100.0) + 1.0
        );
        // breakdown: data + tree pages (total - available - internally_reserved) are what the shards really hold, the
        // fullness charge sits in internally_reserved only
        assert_eq!(
            sf.total - sf.available - sf.internally_reserved,
            st.real_used_bytes
        );
        assert_eq!(
            (sf.allocated + sf.internal_metadata) as u64,
            st.real_used_bytes
        );
        assert!(st.real_used_bytes <= st.used_bytes);
    }
}

#[cfg(all(test, any(feature = "lab", feature = "spdk", feature = "kernel-nvme")))]
mod mem_target_tests {
    use super::devs::*;

    #[test]
    fn memory_target_from_local_config() {
        let kv = |k: &str, v: &str| (k.to_owned(), v.to_owned());
        let none = std::collections::BTreeMap::new();
        set_memory_target(
            &[kv("osd_memory_target", "2G"), kv("osd_memory_base", "512M")],
            &none,
        );
        // caches = target - base - ingress (target/16, floor 256 MiB; doc/design/memory-envelope.md)
        assert_eq!(cache_budget(), (2 << 30) - (512 << 20) - (256 << 20));
        // below base + min: floor
        set_memory_target(&[kv("osd_memory_target", "100")], &none);
        assert_eq!(cache_budget(), 128 << 20);
        set_memory_target(&[], &none);
        assert_eq!(cache_budget(), (4u64 << 30) - (768 << 20) - (256 << 20));
        // adr 0175 am. 2: the mon config db (fetched at start) below the local config, above the default; Ceph sizes
        let mon: std::collections::BTreeMap<String, String> =
            [kv("osd_memory_target", "8GiB"), kv("osd_memory_base", "1G")]
                .into_iter()
                .collect();
        let line = set_memory_target(&[kv("osd_memory_base", "512M")], &mon);
        assert_eq!(cache_budget(), (8u64 << 30) - (512 << 20) - (512 << 20));
        assert_eq!(crate::memory::active().target, 8 << 30);
        assert!(
            line.contains("osd_memory_target 8192 MiB (mon)")
                && line.contains("osd_memory_base 512 MiB (local)")
                && line.contains("osd_memory_cache_min 128 MiB (default)"),
            "{line}"
        );
        // a local value wins; an unparsable one falls through to the next source
        set_memory_target(&[kv("osd_memory_target", "6G")], &mon);
        assert_eq!(crate::memory::active().target, 6 << 30);
        set_memory_target(&[kv("osd_memory_target", "lots")], &mon);
        assert_eq!(crate::memory::active().target, 8 << 30);
        // fixed pinned buffers come out of the caches; over the floor = refused, envelope unchanged
        let before = cache_budget();
        let line = charge_pinned(512 << 20, "source-pull").expect("fits");
        assert!(
            line.contains("pins 512 MiB") && line.contains("caches"),
            "{line}"
        );
        assert_eq!(cache_budget(), before - (512 << 20));
        assert_eq!(crate::memory::active().pinned, 512 << 20);
        assert!(charge_pinned(64 << 30, "source-pull").is_err());
        assert_eq!(cache_budget(), before - (512 << 20));
        set_memory_target(&[], &none);
        assert_eq!(crate::memory::active().pinned, 0);
        // adr 0160 D5: the object-state share joins each store cache unit and is split over the PGs the OSD hosts: the
        // caches of all PGs stay within it at every PG count
        let (st, obj) = crate::nvmestore::split_cache_budget(cache_budget());
        assert_eq!(st + obj, cache_budget());
        assert!(
            obj > cache_budget() / 32 && obj < cache_budget() / 8,
            "{obj}"
        );
        let mut prev = usize::MAX;
        for pgs in [1u64, 16, 128, 200, 500, 1500] {
            let cap = crate::nvmestore::obj_cache_per_pg(pgs);
            assert!(
                cap > 0 && cap <= prev && cap as u64 * opexec::OBJ_HEAD_BYTES * pgs <= obj,
                "{pgs} PGs: {cap}"
            );
            prev = cap;
        }
        // power-of-two tables: at 128 PGs at least half the share is usable
        let cap = crate::nvmestore::obj_cache_per_pg(128);
        assert!(cap as u64 * opexec::OBJ_HEAD_BYTES * 128 * 2 > obj, "{cap}");
        assert_eq!(
            crate::nvmestore::obj_cache_per_pg(0),
            crate::nvmestore::obj_cache_per_pg(1)
        );
    }
}

#[cfg(all(test, any(feature = "lab", feature = "spdk", feature = "kernel-nvme")))]
mod omap_scan_cfg_tests {
    use super::devs::store_cfg;
    use super::*;

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_tuning_defaults_are_forwarded_and_out_of_range_refused() {
        use store::rocks_omap::Tuning;
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let keys = [
            ("flashstore_rocksdb_low_threads", "2"),
            ("flashstore_rocksdb_high_threads", "1"),
            ("flashstore_rocksdb_background_jobs", "4"),
            ("flashstore_rocksdb_write_buffer_number", "2"),
            ("flashstore_rocksdb_l0_slowdown_trigger", "0"),
            ("flashstore_rocksdb_l0_stop_trigger", "0"),
        ];
        for (k, v) in keys {
            assert_eq!(crate::config::ConfigDb::default().get(k), Some(v), "{k}");
            assert!(crate::config::forwarded(k));
        }
        let dir = ("flashstore_rocksdb_dir".to_string(), "/root".to_string());
        set_store_options(std::slice::from_ref(&dir)).unwrap();
        assert_eq!(
            store_cfg(4).unwrap().shard.rocksdb.unwrap().tuning,
            Tuning::default()
        );
        // Explicit defaults are identical to absent options.
        let mut explicit: Vec<(String, String)> = keys
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        explicit.push(dir.clone());
        set_store_options(&explicit).unwrap();
        assert_eq!(
            store_cfg(4).unwrap().shard.rocksdb.unwrap().tuning,
            Tuning::default()
        );
        set_store_options(&[
            dir.clone(),
            ("flashstore_rocksdb_low_threads".into(), "3".into()),
            ("flashstore_rocksdb_l0_slowdown_trigger".into(), "8".into()),
            ("flashstore_rocksdb_l0_stop_trigger".into(), "16".into()),
        ])
        .unwrap();
        let t = store_cfg(4).unwrap().shard.rocksdb.unwrap().tuning;
        assert_eq!(
            (t.low_threads, t.l0_slowdown, t.l0_stop, t.high_threads),
            (3, 8, 16, 1)
        );
        for (k, v) in [
            ("flashstore_rocksdb_low_threads", "0"),
            ("flashstore_rocksdb_high_threads", "many"),
            ("flashstore_rocksdb_write_buffer_number", "1"),
        ] {
            assert!(
                set_store_options(&[dir.clone(), (k.into(), v.into())]).is_err(),
                "{k}={v}"
            );
        }
        set_store_options(&[]).unwrap();
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_worker_cpu_defaults_to_next_is_forwarded_and_rejects_unknown_modes() {
        use store::rocks_omap::WorkerCpu;
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key = "flashstore_rocksdb_worker_cpu";
        assert_eq!(crate::config::ConfigDb::default().get(key), Some("next"));
        assert!(crate::config::forwarded(key));
        let dir = ("flashstore_rocksdb_dir".to_string(), "/root".to_string());
        set_store_options(std::slice::from_ref(&dir)).unwrap();
        assert_eq!(
            store_cfg(4).unwrap().shard.rocksdb.unwrap().worker_cpu,
            WorkerCpu::Next
        );
        for (v, want) in [
            ("owner", WorkerCpu::Owner),
            ("FLOAT", WorkerCpu::Float),
            ("next", WorkerCpu::Next),
        ] {
            set_store_options(&[dir.clone(), (key.into(), v.into())]).unwrap();
            assert_eq!(
                store_cfg(4).unwrap().shard.rocksdb.unwrap().worker_cpu,
                want
            );
        }
        assert!(
            set_store_options(&[dir.clone(), (key.into(), "spread".into())])
                .unwrap_err()
                .contains(key)
        );
        set_store_options(&[]).unwrap();
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_profile_is_opt_in_forwarded_and_rejects_unknown_boolean_spellings() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key = "flashstore_rocksdb_profile";
        assert_eq!(crate::config::ConfigDb::default().get(key), Some("false"));
        assert!(crate::config::forwarded(key));
        set_store_options(&[("flashstore_rocksdb_dir".into(), "/root".into())]).unwrap();
        assert!(!store_cfg(4).unwrap().shard.rocksdb.unwrap().profile);
        set_store_options(&[
            ("flashstore_rocksdb_dir".into(), "/root".into()),
            (key.into(), "ON".into()),
        ])
        .unwrap();
        assert!(store_cfg(4).unwrap().shard.rocksdb.unwrap().profile);
        set_store_options(&[
            ("flashstore_rocksdb_dir".into(), "/root".into()),
            (key.into(), "OFF".into()),
        ])
        .unwrap();
        assert!(!store_cfg(4).unwrap().shard.rocksdb.unwrap().profile);
        assert!(
            set_store_options(&[
                ("flashstore_rocksdb_dir".into(), "/root".into()),
                (key.into(), "maybe".into())
            ])
            .unwrap_err()
            .contains(key)
        );
        set_store_options(&[]).unwrap();
    }

    /// A native (LSM/B-tree) OSD from a RocksDB-capable build may share a config template with RocksDB OSDs: without
    /// a RocksDB root it ignores every other RocksDB key (even invalid ones) and still validates native options.
    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_keys_without_root_do_not_refuse_native_start() {
        use std::sync::atomic::Ordering::Relaxed;
        use store::rocks_omap::WorkerCpu;
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let junk: Vec<(String, String)> = [
            ("flashstore_rocksdb_profile", "maybe"),
            ("flashstore_rocksdb_worker_cpu", "spread"),
            ("flashstore_rocksdb_low_threads", "0"),
            ("flashstore_rocksdb_high_threads", "many"),
            ("flashstore_rocksdb_background_jobs", "99"),
            ("flashstore_rocksdb_write_buffer_number", "1"),
            ("flashstore_rocksdb_l0_slowdown_trigger", "2000"),
            ("flashstore_rocksdb_l0_stop_trigger", "-1"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        // With a root, each junk value refuses the start.
        let dir = ("flashstore_rocksdb_dir".to_string(), "/root".to_string());
        for kv in &junk {
            assert!(
                set_store_options(&[dir.clone(), kv.clone()]).is_err(),
                "{kv:?}"
            );
        }
        // Non-default valid settings, then no root: state resets to defaults and junk is ignored.
        set_store_options(&[
            dir.clone(),
            ("flashstore_rocksdb_profile".into(), "on".into()),
            ("flashstore_rocksdb_worker_cpu".into(), "float".into()),
            ("flashstore_rocksdb_low_threads".into(), "3".into()),
        ])
        .unwrap();
        for unset in [None, Some(""), Some("  ")] {
            let mut cfg = junk.clone();
            if let Some(v) = unset {
                cfg.push(("flashstore_rocksdb_dir".into(), v.into()));
            }
            set_store_options(&cfg).unwrap_or_else(|e| panic!("dir {unset:?}: {e}"));
            assert!(store_cfg(4).unwrap().shard.rocksdb.is_none());
            assert!(!ROCKSDB_PROFILE.load(Relaxed));
            assert_eq!(*ROCKSDB_WORKER_CPU.lock().unwrap(), WorkerCpu::Next);
            assert!(ROCKSDB_TUNING.lock().unwrap().is_none());
        }
        // Native validation still applies next to ignored RocksDB keys.
        let mut cfg = junk;
        cfg.push(("flashstore_omap_scan_prefetch".into(), "flase".into()));
        let e = set_store_options(&cfg).unwrap_err();
        assert!(e.contains("flashstore_omap_scan_prefetch"), "{e}");
        set_store_options(&[]).unwrap();
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_startup_keeps_native_option_validation_and_last_root() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key = "flashstore_rocksdb_dir";
        assert_eq!(crate::config::ConfigDb::default().get(key), Some(""));
        assert!(crate::config::forwarded(key));
        set_store_options(&[
            ("flashstore_rocksdb_dir".into(), "/first-root".into()),
            ("flashstore_rocksdb_dir".into(), " /last-root ".into()),
            ("flashstore_omap_scan_prefetch".into(), "OFF".into()),
            ("flashstore_omap_delete_range_threshold".into(), "64".into()),
        ])
        .unwrap();
        let cfg = store_cfg(4).unwrap();
        assert_eq!(
            cfg.shard.rocksdb.unwrap().root,
            std::path::PathBuf::from("/last-root")
        );
        assert!(!cfg.shard.omap_scan_prefetch);
        assert_eq!(cfg.shard.omap_delete_range_threshold, 64);

        let e = set_store_options(&[
            ("flashstore_rocksdb_dir".into(), "/unused-root".into()),
            ("flashstore_omap_scan_prefetch".into(), "flase".into()),
        ])
        .unwrap_err();
        assert!(e.contains("flashstore_omap_scan_prefetch"), "{e}");
        set_store_options(&[("flashstore_rocksdb_dir".into(), "  ".into())]).unwrap();
        assert!(store_cfg(4).unwrap().shard.rocksdb.is_none());
        set_store_options(&[]).unwrap();
        assert!(store_cfg(4).unwrap().shard.rocksdb.is_none());
    }

    #[test]
    fn omap_delete_range_threshold_defaults_validates_and_reaches_store_config() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key = "flashstore_omap_delete_range_threshold";
        assert_eq!(crate::config::ConfigDb::default().get(key), Some("0"));
        assert!(crate::config::forwarded(key));
        set_store_options(&[]).unwrap();
        assert_eq!(store_cfg(4).unwrap().shard.omap_delete_range_threshold, 0);
        for n in [0, 1, 64, 1_048_576, u64::MAX] {
            set_store_options(&[(key.into(), n.to_string())]).unwrap();
            assert_eq!(store_cfg(4).unwrap().shard.omap_delete_range_threshold, n);
        }
        set_store_options(&[(key.into(), "17".into()), (key.into(), "64".into())]).unwrap();
        assert_eq!(store_cfg(4).unwrap().shard.omap_delete_range_threshold, 64);
        for bad in ["", "many", "4.0", "-1", "18446744073709551616"] {
            set_store_options(&[(key.into(), "64".into()), (key.into(), bad.into())]).unwrap();
            assert!(
                store_cfg(4).unwrap_err().contains(key),
                "invalid value {bad:?}"
            );
        }
        set_store_options(&[]).unwrap();
        assert_eq!(store_cfg(4).unwrap().shard.omap_delete_range_threshold, 0);
    }

    #[test]
    fn omap_scan_prefetch_defaults_to_adaptive_and_explicit_modes_reach_store_config() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_store_options(&[]).unwrap();
        let c = store_cfg(4).unwrap().shard;
        assert!(c.omap_scan_prefetch && c.omap_scan_prefetch_adaptive);
        assert_eq!(
            (c.omap_scan_prefetch_chunks, c.omap_scan_prefetch_max_chunks),
            (1, 16)
        );
        for key in [
            "flashstore_omap_scan_prefetch",
            "flashstore_omap_scan_prefetch_adaptive",
        ] {
            assert_eq!(
                crate::config::DEFAULTS
                    .iter()
                    .find(|(n, _)| *n == key)
                    .unwrap()
                    .1,
                "true"
            );
        }
        set_store_options(&[
            (
                "flashstore_omap_scan_prefetch_adaptive".into(),
                "false".into(),
            ),
            ("flashstore_omap_scan_prefetch_chunks".into(), "4".into()),
        ])
        .unwrap();
        let c = store_cfg(4).unwrap().shard;
        assert!(c.omap_scan_prefetch && !c.omap_scan_prefetch_adaptive);
        assert_eq!(c.omap_scan_prefetch_chunks, 4);
        for adaptive in ["true", "false"] {
            set_store_options(&[
                ("flashstore_omap_scan_prefetch".into(), "false".into()),
                (
                    "flashstore_omap_scan_prefetch_adaptive".into(),
                    adaptive.into(),
                ),
            ])
            .unwrap();
            assert!(!store_cfg(4).unwrap().shard.omap_scan_prefetch);
        }
        // Last boolean override wins; missing options restore production defaults.
        set_store_options(&[
            ("flashstore_omap_scan_prefetch".into(), "false".into()),
            ("flashstore_omap_scan_prefetch".into(), "true".into()),
        ])
        .unwrap();
        assert!(store_cfg(4).unwrap().shard.omap_scan_prefetch);
        set_store_options(&[]).unwrap();
        assert!(store_cfg(4).unwrap().shard.omap_scan_prefetch_adaptive);
    }

    #[test]
    fn omap_scan_prefetch_window_validates_numeric_startup_values() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for (key, default) in [
            ("flashstore_omap_scan_prefetch_chunks", 1),
            ("flashstore_omap_scan_prefetch_max_chunks", 16),
        ] {
            let value = |c: store::shard::ShardCfg| {
                if key.ends_with("max_chunks") {
                    c.omap_scan_prefetch_max_chunks
                } else {
                    c.omap_scan_prefetch_chunks
                }
            };
            for n in [1, 4, 16] {
                set_store_options(&[(key.into(), n.to_string())]).unwrap();
                assert_eq!(value(store_cfg(4).unwrap().shard), n);
            }
            // Last local override wins, including validation failures instead of silent fallback.
            set_store_options(&[(key.into(), "1".into()), (key.into(), "4".into())]).unwrap();
            assert_eq!(value(store_cfg(4).unwrap().shard), 4);
            for bad in ["", "four", "4.0", "-1", "0", "17", "184467440737095516160"] {
                set_store_options(&[(key.into(), bad.into())]).unwrap();
                assert!(
                    store_cfg(4).unwrap_err().contains(key),
                    "invalid value {bad:?}"
                );
            }
            set_store_options(&[]).unwrap();
            assert_eq!(value(store_cfg(4).unwrap().shard), default);
        }
    }

    /// A store option value above `u32::MAX` refuses the start: the cast into the store's `u32` field would wrap it into
    /// a smaller, different threshold (e.g. 2^32 + 4096 became 4096).
    #[test]
    fn value_thresholds_above_u32_are_refused_not_wrapped() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for (key, value) in [
            (
                "flashstore_store_val_ext_min",
                (|c: store::shard::ShardCfg| c.val_ext_min) as fn(_) -> _,
            ),
            ("flashstore_store_val_comp_min", |c| c.val_comp_min),
        ] {
            set_store_options(&[(key.into(), ((1u64 << 32) + 4096).to_string())]).unwrap();
            let e = store_cfg(4).unwrap_err();
            assert!(e.contains(key), "{e}");
            set_store_options(&[(key.into(), u32::MAX.to_string())]).unwrap();
            assert_eq!(value(store_cfg(4).unwrap().shard), u32::MAX);
        }
        set_store_options(&[]).unwrap();
    }

    /// An unknown on/off spelling refuses the start, naming key and value (a typo used to flip the option silently).
    #[test]
    fn invalid_on_off_spelling_refuses_the_start() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for key in [
            "flashstore_omap_scan_prefetch",
            "flashstore_omap_scan_prefetch_adaptive",
            "flashstore_store_compact_helpers",
            "flashstore_store_shared_clone",
            "flashstore_store_pf_retain",
            "flashstore_store_defrag_cells",
        ] {
            let e = set_store_options(&[(key.into(), "flase".into())]).unwrap_err();
            assert!(e.contains(key) && e.contains("flase"), "{e}");
        }
        set_store_options(&[]).unwrap();
    }
}

#[cfg(all(
    test,
    feature = "elastic",
    any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
))]
mod lend_cfg_tests {
    use super::*;
    #[cfg(feature = "lab")]
    use nvme::any::AnyCtrl;
    #[cfg(feature = "lab")]
    use store::layout::MkfsParams;

    /// The daemon mount paths hand the pool owner one queue more than the shards (the lending table queue): a chunked store
    /// mounted through `mount_dev` and `mount_dev_core` (core 0 owns shard 0 and the pool).
    #[cfg(feature = "lab")]
    #[test]
    fn chunked_store_mounts_with_the_pool_queue() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path =
            std::env::temp_dir().join(format!("croit-flashstore-poolq-{}.img", std::process::id()));
        let spec =
            nvme::any::DevSpec::parse(&format!("file:{},size=128M", path.display())).unwrap();
        let ctrl = AnyCtrl::open_exclusive_create(&spec, true).unwrap();
        set_store_options(&[]).unwrap();
        let p = MkfsParams {
            shards: 2,
            wal_blocks: 2048,
            align_blocks: 256,
            meta_pct: 2,
            chunked: true,
            chunk_blocks: 256,
            base_pct: 50,
            allow_volatile_cache: true,
            ..Default::default()
        };
        mkfs_dev(&ctrl, &p).unwrap();
        let (st, _) = mount_dev(&ctrl).unwrap();
        drop(st);
        let qs = core_queues(&ctrl, 2, 0, 2).unwrap();
        assert_eq!(qs.len(), 2, "one shard + the pool queue");
        let (st, _) = mount_dev_core(qs, 0, &[0, 1], 2).unwrap();
        drop(st);
        assert_eq!(
            core_queues(&ctrl, 2, 1, 2).unwrap().len(),
            1,
            "worker core: shard only"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn lend_keys_reach_the_store_config() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let kv = |k: &str, v: &str| (k.to_owned(), v.to_owned());
        set_store_options(&[]).unwrap();
        let c = store_cfg(4).unwrap().shard;
        assert!(c.lend_auto, "default on");
        let d = store::obj::StoreCfg::default().shard;
        assert_eq!(
            (c.lend_wm_pct, c.lend_retry_ms),
            (d.lend_wm_pct, d.lend_retry_ms)
        );
        set_store_options(&[
            kv("flashstore_store_lend_auto", "true"),
            kv("flashstore_store_lend_wm_pct", "40"),
            kv("flashstore_store_lend_retry_ms", "7"),
        ])
        .unwrap();
        let c = store_cfg(4).unwrap().shard;
        assert!(c.lend_auto);
        assert_eq!((c.lend_wm_pct, c.lend_retry_ms), (40, 7));
        set_store_options(&[kv("flashstore_store_lend_auto", "false")]).unwrap();
        assert!(!store_cfg(4).unwrap().shard.lend_auto);
        set_store_options(&[]).unwrap();
        assert!(store_cfg(4).unwrap().shard.lend_auto);
    }
}

#[cfg(all(test, feature = "elastic"))]
mod reclaim_cfg_tests {
    use super::*;

    /// Pure parse + apply (no globals: the lend test resets them concurrently).
    #[test]
    fn reclaim_keys_reach_the_store_config() {
        let kv = |k: &str, v: &str| (k.to_owned(), v.to_owned());
        let d = store::obj::StoreCfg::default().shard;
        let mut c = d.clone();
        apply_reclaim(&mut c, reclaim_options(&[]));
        assert_eq!(
            (c.reclaim_hyst_pct, c.reclaim_mbps),
            (d.reclaim_hyst_pct, d.reclaim_mbps)
        );
        apply_reclaim(
            &mut c,
            reclaim_options(&[
                kv("flashstore_store_reclaim_hyst_pct", "5"),
                kv("flashstore_store_reclaim_mbps", "200"),
            ]),
        );
        assert_eq!((c.reclaim_hyst_pct, c.reclaim_mbps), (5, 200));
    }
}

/// The store on a `kernel:` device (adr 0169; lab: a regular file through O_DIRECT + io_uring): mkfs, mount, object
/// writes/reads across sizes, remount (WAL replay), data intact.
#[cfg(all(test, feature = "lab", feature = "kernel-nvme", target_os = "linux"))]
mod kernel_dev_tests {
    use super::*;
    use denc::types::{PgT, SpgT};
    use nvme::any::{AnyCtrl, DevSpec};
    use store::layout::MkfsParams;

    fn img() -> Option<std::path::PathBuf> {
        let dirs = [
            std::env::var_os("CARGO_TARGET_DIR").map(Into::into),
            Some(std::env::temp_dir()),
        ];
        for d in dirs.into_iter().flatten() {
            let p: std::path::PathBuf = d;
            let p = p.join(format!("croit-flashstore-kdev-{}.img", std::process::id()));
            let f = std::fs::File::create(&p).ok()?;
            f.set_len(256 << 20).ok()?;
            if DevSpec::parse(&format!("kernel:{}", p.display()))
                .and_then(|s| AnyCtrl::open_exclusive(&s))
                .is_ok()
            {
                return Some(p);
            }
            let _ = std::fs::remove_file(&p);
        }
        None
    }

    #[test]
    fn store_on_a_kernel_device_survives_remount() {
        let _opts = OPTIONS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(path) = img() else {
            eprintln!("no O_DIRECT capable directory: skipped");
            return;
        };
        let spec = DevSpec::parse(&format!("kernel:{}", path.display())).unwrap();
        let ctrl = AnyCtrl::open_exclusive(&spec).unwrap();
        assert!(
            AnyCtrl::open_exclusive(&spec).is_err(),
            "a second opener is refused"
        );
        set_store_options(&[]).unwrap();
        let p = MkfsParams {
            shards: 2,
            wal_blocks: 2048,
            align_blocks: 256,
            meta_pct: 4,
            allow_volatile_cache: true,
            ..Default::default()
        };
        mkfs_dev(&ctrl, &p).unwrap();
        let cid = CollT::Pg(SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        });
        let oid = |n: u32| {
            Ghobject::new(
                Hobject::new(format!("o{n}").as_bytes(), SnapId::NOSNAP, n, 1, b""),
                Ghobject::NO_GEN,
                ShardId::NO_SHARD,
            )
        };
        let data = |n: u32, len: usize| -> Vec<u8> {
            (0..len).map(|i| (i as u32 * 31 + n) as u8).collect()
        };
        let sizes = [100usize, 4096, 8192 + 7, 65536, 1 << 20];
        {
            let (mut st, _) = mount_dev(&ctrl).unwrap();
            let mut t = OTxn::new();
            t.mkcoll(cid);
            st.commit(&t).unwrap();
            for (n, len) in sizes.iter().enumerate() {
                let (o, d) = (oid(n as u32), data(n as u32, *len));
                let mut t = OTxn::new();
                t.write(cid, &o, 0, &d);
                st.commit(&t).unwrap();
            }
            for (n, len) in sizes.iter().enumerate() {
                let r = st.read(&cid, &oid(n as u32), 0, *len as u64).unwrap();
                assert_eq!(r, data(n as u32, *len), "object {n} before remount");
            }
        }
        let (mut st, _) = mount_dev(&ctrl).unwrap();
        for (n, len) in sizes.iter().enumerate() {
            let r = st.read(&cid, &oid(n as u32), 0, *len as u64).unwrap();
            assert_eq!(r, data(n as u32, *len), "object {n} after remount");
        }
        drop(st);
        drop(ctrl);
        let _ = std::fs::remove_file(&path);
    }
}
