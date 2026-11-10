// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! RocksDB persistence for the shard OMAP facade (ADR 0681).
//!
//! The owner retains the native active/frozen memtables and WAL authority. Only a
//! native-durable frozen table may cross this boundary. The worker atomically
//! writes its final effects and watermark with RocksDB WAL and sync enabled.
//! All blocking DB calls, including reads, execute on that worker, not the PG core.

use self::mem::{Memtable, ObjMem};
use crate::error::{Result, StoreError};
use crate::layout::Superblock;
use crate::olsm::mem::Probe;

pub(crate) mod mem;
use bytes::Bytes;
use rocksdb_lib::{
    BlockBasedOptions, Cache, DB, DBCompressionType, Env, Options, ReadOptions, WriteBatch,
    WriteOptions,
};
use rtrb::{Consumer, Producer, RingBuffer};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{JoinHandle, Thread};
use std::time::{Duration, Instant};

const IDENTITY: &[u8] = b"\0identity";
const WATERMARK: &[u8] = b"\0watermark";
const QUEUE: usize = 16;
pub(crate) const PAGE: usize = 256;
/// Worker batching is independent of the owner's fair CPU slice.
pub(crate) const SCAN_BATCH: usize = 1024;

mod metrics;
mod page;
use page::PageBuilder;
pub(crate) use page::PageEntries;

/// Where a shard's blocking worker runs inside the selected service CPU budget
/// (`flashstore_rocksdb_worker_cpu`). Placement only: no data, ordering or
/// durability effect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WorkerCpu {
    /// The next selected service CPU after the owner's (historical default).
    #[default]
    Next,
    /// The owner's own CPU: worker and owner never run at the same time there.
    Owner,
    /// Any CPU of the service budget; the kernel scheduler balances it.
    Float,
}

impl std::str::FromStr for WorkerCpu {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "next" => Ok(Self::Next),
            "owner" => Ok(Self::Owner),
            "float" => Ok(Self::Float),
            _ => Err(format!("must be next, owner or float, got {s:?}")),
        }
    }
}

/// Explicit external database location. Every shard gets its own identity-bound
/// child directory. Read-only is mandatory for non-mutating offline tools.
#[derive(Clone, Debug)]
pub struct Config {
    pub root: PathBuf,
    pub read_only: bool,
    /// Opt-in timing/counter diagnostics; never changes write/sync policy.
    pub profile: bool,
    /// Blocking worker CPU; never a logical shard/core index.
    pub cpu: Option<usize>,
    /// Worker placement rule applied by [`set_cpu_budget`](Self::set_cpu_budget).
    pub worker_cpu: WorkerCpu,
    /// Engine resource limits; see [`Tuning`] for the defaults.
    pub tuning: Tuning,
    /// Explicit service budget for initialization of the process-wide DB pools.
    /// Empty retains the caller's affinity for offline/single-owner consumers.
    background_cpus: Vec<usize>,
    /// Explicit test-only filesystem bypass. This field does not exist in a
    /// production build; it never relaxes native device admission.
    #[cfg(any(test, feature = "lab"))]
    pub allow_non_nvme: bool,
}

impl Config {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            read_only: false,
            profile: false,
            cpu: None,
            worker_cpu: WorkerCpu::Next,
            tuning: Tuning::default(),
            background_cpus: Vec::new(),
            #[cfg(any(test, feature = "lab"))]
            allow_non_nvme: false,
        }
    }

    /// Place blocking work per [`worker_cpu`](Self::worker_cpu) (default: the
    /// next selected service CPU, not the owner's). `Float` leaves the worker on
    /// the whole budget. DB background pools may use this same bounded service
    /// budget. The caller supplies physical CPU IDs before owner threads narrow
    /// their own affinity.
    pub fn set_cpu_budget(&mut self, owner: usize, cpus: &[usize]) -> Result<()> {
        if owner >= cpus.len()
            || cpus
                .iter()
                .enumerate()
                .any(|(i, cpu)| cpus[..i].contains(cpu))
        {
            return Err(StoreError::Invalid("invalid RocksDB service CPU budget"));
        }
        #[cfg(target_os = "linux")]
        if cpus.iter().any(|cpu| *cpu >= libc::CPU_SETSIZE as usize) {
            return Err(StoreError::Invalid("RocksDB CPU exceeds CPU_SETSIZE"));
        }
        self.cpu = match self.worker_cpu {
            WorkerCpu::Next => Some(cpus[(owner + 1) % cpus.len()]),
            WorkerCpu::Owner => Some(cpus[owner]),
            WorkerCpu::Float => None,
        };
        self.background_cpus = cpus.to_vec();
        Ok(())
    }

    /// Split overlapping L0 compaction only with four explicitly selected
    /// service CPUs. Unknown/smaller budgets stay serial; never infer spare
    /// capacity from the host CPU count or the caller's inherited affinity.
    fn subcompactions(&self) -> u32 {
        if self.background_cpus.len() >= 4 {
            2
        } else {
            1
        }
    }

    pub fn path(&self, sb: &Superblock, shard: u32) -> Result<PathBuf> {
        if !self.root.is_absolute() {
            return Err(StoreError::Invalid(
                "RocksDB root must be an absolute filesystem directory",
            ));
        }
        let name: String = sb.osd_fsid.iter().map(|b| format!("{b:02x}")).collect();
        Ok(self.root.join(name).join(format!("shard-{shard}")))
    }

    /// Bind every existing descendant to the admitted root, including mountpoints
    /// (which canonicalization alone cannot detect). Root ownership/topology must
    /// remain stable while the service runs; changing mounts under an open DB is
    /// not a supported administrative operation.
    fn validate_location(&self, path: &Path) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let root = std::fs::symlink_metadata(&self.root).map_err(err)?;
        if !root.is_dir() || std::fs::canonicalize(&self.root).map_err(err)? != self.root {
            return Err(StoreError::Invalid(
                "RocksDB root must be a canonical directory",
            ));
        }
        let mut next = self.root.clone();
        for part in path.strip_prefix(&self.root).map_err(err)?.components() {
            if !matches!(part, std::path::Component::Normal(_)) {
                return Err(StoreError::Invalid("invalid RocksDB descendant path"));
            }
            next.push(part);
            match std::fs::symlink_metadata(&next) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() && m.dev() == root.dev() => {}
                Ok(_) => {
                    return Err(StoreError::Invalid(
                        "RocksDB descendant is a symlink or crosses the admitted filesystem",
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => return Err(err(e)),
            }
        }
        Ok(())
    }

    /// Cold admission only. Keep the DB, its WAL and its SSTs on this one
    /// filesystem. Only direct NVMe or strictly validated linear LVM is supported.
    pub fn admit(&self) -> Result<()> {
        #[cfg(any(test, feature = "lab"))]
        if self.allow_non_nvme {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::fs::MetadataExt;
            if !self.root.is_absolute()
                || std::fs::canonicalize(&self.root).map_err(err)? != self.root
            {
                return Err(StoreError::Invalid(
                    "RocksDB root must exist and contain no symlinks or parent traversal",
                ));
            }
            let name = std::ffi::CString::new(self.root.as_os_str().as_bytes()).map_err(err)?;
            // SAFETY: initialized output, valid NUL-terminated path.
            let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statfs(name.as_ptr(), &mut fs) } != 0 {
                return Err(err(std::io::Error::last_os_error()));
            }
            if !matches!(fs.f_type as u64, 0xef53 | 0x58465342) {
                return Err(StoreError::Invalid(
                    "RocksDB requires local ext4 or XFS on admitted NVMe",
                ));
            }
            let dev = std::fs::metadata(&self.root).map_err(err)?.dev();
            let sys = std::fs::canonicalize(format!(
                "/sys/dev/block/{}:{}",
                libc::major(dev),
                libc::minor(dev)
            ))
            .map_err(err)?;
            if sys.join("dm").is_dir() {
                let node = Path::new("/dev").join(sys.file_name().ok_or_else(|| err("LV name"))?);
                return nvme::kdev::validate_lvm_filesystem(&node, dev).map_err(err);
            }
            let ns = if sys.join("partition").exists() {
                sys.parent().ok_or_else(|| err("partition parent"))?
            } else {
                &sys
            };
            if !ns.join("nsid").is_file() || ns.join("dm").exists() {
                return Err(StoreError::Invalid(
                    "RocksDB filesystem must be on direct NVMe or validated linear LVM",
                ));
            }
            let node = Path::new("/dev").join(ns.file_name().ok_or_else(|| err("namespace name"))?);
            let probe = nvme::kprobe::KernelProbe(node);
            let controller = probe.identify_ctrl_raw().map_err(err)?;
            if controller.get(525).is_none_or(|vwc| vwc & 1 != 0) {
                return Err(StoreError::VolatileCache);
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        Err(StoreError::Invalid(
            "production RocksDB filesystem admission requires Linux",
        ))
    }
}

fn identity(sb: &Superblock, shard: u32) -> Vec<u8> {
    let mut b = b"croit-flashstore-rocks-omap-v1".to_vec();
    b.extend_from_slice(&sb.osd_fsid);
    b.extend_from_slice(&sb.mkfs_time.to_le_bytes());
    b.extend_from_slice(&sb.shards.to_le_bytes());
    b.extend_from_slice(&shard.to_le_bytes());
    b
}

fn err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Corrupt(format!("RocksDB OMAP: {e}"))
}

fn key(id: u64, k: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + k.len());
    key_into(&mut out, id, k);
    out
}

/// Encode into worker-local scratch; never retain a borrow in an answer.
fn key_into(out: &mut Vec<u8>, id: u64, k: &[u8]) {
    out.clear();
    out.reserve(9 + k.len());
    out.push(1);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(k);
}

fn object_end(id: u64) -> Vec<u8> {
    id.checked_add(1).map_or_else(|| vec![2], |n| key(n, b""))
}

/// Engine resource limits (`flashstore_rocksdb_*` tuning options). Defaults: two
/// compaction threads and four background jobs (ADR 0726 am. 1; historically 1
/// and 2); none of these change sync policy, ordering or durability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tuning {
    /// Shared low-priority (compaction) pool threads, process-wide.
    pub low_threads: u32,
    /// Shared high-priority (flush) pool threads, process-wide.
    pub high_threads: u32,
    /// `max_background_jobs` per database.
    pub background_jobs: u32,
    /// `max_write_buffer_number` (active plus immutable memtables).
    pub write_buffers: u32,
    /// L0 file count that starts write slowdown; 0 = library default.
    pub l0_slowdown: u32,
    /// L0 file count that stops writes; 0 = library default.
    pub l0_stop: u32,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            low_threads: 2,
            high_threads: 1,
            background_jobs: 4,
            write_buffers: 2,
            l0_slowdown: 0,
            l0_stop: 0,
        }
    }
}

impl Tuning {
    /// Bounded values only: a typo must refuse startup, not starve the owners'
    /// service CPUs or remove all write backpressure.
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        let in_range = |v: u32, lo: u32, hi: u32| (lo..=hi).contains(&v);
        if !in_range(self.low_threads, 1, 8) || !in_range(self.high_threads, 1, 4) {
            return Err("RocksDB pool threads out of range (low 1..=8, high 1..=4)");
        }
        if !in_range(self.background_jobs, 1, 16) || !in_range(self.write_buffers, 2, 8) {
            return Err("RocksDB background jobs (1..=16) or write buffers (2..=8) out of range");
        }
        if self.l0_slowdown > 1024 || self.l0_stop > 1024 {
            return Err("RocksDB L0 trigger above 1024");
        }
        if self.l0_slowdown != 0 && self.l0_stop != 0 && self.l0_stop < self.l0_slowdown {
            return Err("RocksDB L0 stop trigger below slowdown trigger");
        }
        Ok(())
    }
}

fn options(mem: usize, subcompactions: u32, t: &Tuning) -> Result<Options> {
    if mem < 4 << 20 {
        return Err(StoreError::Invalid("RocksDB memory share below 4 MiB"));
    }
    if !(1..=2).contains(&subcompactions) {
        return Err(StoreError::Invalid("invalid RocksDB subcompaction bound"));
    }
    t.validate().map_err(StoreError::Invalid)?;
    // Env::new wraps process-wide default pools, not private per-shard pools.
    // Bound those shared pools; their first creator determines inherited affinity.
    // Values are bounded by `Tuning::validate`, so the casts cannot truncate.
    let mut env = Env::new().map_err(err)?;
    env.set_background_threads(t.low_threads as i32);
    env.set_high_priority_background_threads(t.high_threads as i32);
    let mut table = BlockBasedOptions::default();
    table.set_block_cache(&Cache::new_lru_cache(mem / 2));
    table.set_bloom_filter(10.0, false);
    let mut o = Options::default();
    o.set_env(&env);
    o.set_max_background_jobs(t.background_jobs as i32);
    // Subcompactions are additional threads, not covered by max_background_jobs.
    // With the default single shared low pool thread this bounds the facade to
    // at most one additional automatic-compaction range worker across its shard
    // databases; a larger low pool (opt-in) raises that bound accordingly.
    o.set_max_subcompactions(subcompactions);
    o.set_write_buffer_size(mem / 4);
    o.set_max_write_buffer_number(t.write_buffers as i32);
    if t.l0_slowdown != 0 {
        o.set_level_zero_slowdown_writes_trigger(t.l0_slowdown as i32);
    }
    if t.l0_stop != 0 {
        o.set_level_zero_stop_writes_trigger(t.l0_stop as i32);
    }
    o.set_max_open_files(128);
    o.set_target_file_size_base((mem / 2) as u64);
    o.set_max_compaction_bytes((mem as u64).saturating_mul(4));
    o.set_block_based_table_factory(&table);
    o.set_compression_type(DBCompressionType::Lz4);
    o.set_paranoid_checks(true);
    Ok(o)
}

/// Fresh provisioning only; never invoked by mount. An existing database is an
/// error even if its identity matches. Neither native nor external data is erased.
pub fn create(cfg: &Config, sb: &Superblock, mem: usize) -> Result<()> {
    cfg.admit()?;
    if cfg.read_only {
        return Err(StoreError::Invalid("cannot create read-only RocksDB"));
    }
    for s in 0..sb.shards {
        let path = cfg.path(sb, s)?;
        cfg.validate_location(&path)?;
        if path.try_exists().map_err(err)? {
            return Err(StoreError::Invalid(
                "RocksDB shard directory already exists",
            ));
        }
    }
    for s in 0..sb.shards {
        let path = cfg.path(sb, s)?;
        let parent = path.parent().expect("shard parent");
        if !parent.try_exists().map_err(err)? {
            std::fs::create_dir(parent).map_err(err)?;
            sync_dir(&cfg.root)?;
        }
        cfg.validate_location(&path)?;
        std::fs::create_dir(&path).map_err(err)?;
        cfg.validate_location(&path)?;
        sync_dir(parent)?;
        let mut o = options(mem, 1, &cfg.tuning)?;
        o.create_if_missing(true);
        o.set_error_if_exists(true);
        let db = DB::open(&o, &path).map_err(err)?;
        let mut b = WriteBatch::default();
        b.put(IDENTITY, identity(sb, s));
        b.put(WATERMARK, 0u64.to_le_bytes());
        let mut w = WriteOptions::default();
        w.set_sync(true);
        db.write_opt(b, &w).map_err(err)?;
        // Also make the newly created directory entry durable before native mkfs
        // can be reported successful.
        sync_dir(&path)?;
        sync_dir(parent)?;
        sync_dir(&cfg.root)?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(err)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Query {
    Keys {
        id: u64,
        keys: Vec<Bytes>,
    },
    Page {
        id: u64,
        from: Bytes,
        excl: bool,
        prefix: Bytes,
        entries: usize,
        versions: [(u64, u64); 3],
        session: Option<(u64, u64)>,
    },
    Ids {
        after: Option<u64>,
    },
}

#[derive(Debug)]
pub(crate) enum Answer {
    Entries(Vec<(Bytes, Bytes)>, bool),
    Page(PageEntries, PageEnd),
    Ids(Vec<u64>, bool),
}

/// Worker-merged continuation, never a raw iterator position. Unknown retains
/// the old bool-only path when copying the key would exceed answer credits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PageEnd {
    End,
    Next(Bytes),
    Unknown,
}

impl PageEnd {
    pub fn has_more(&self) -> bool {
        !matches!(self, Self::End)
    }
}

impl Answer {
    fn bytes(&self) -> usize {
        match self {
            Self::Entries(v, _) => v.iter().map(|(k, v)| k.len() + v.len() + 64).sum(),
            Self::Page(v, end) => v.bytes().saturating_add(match end {
                PageEnd::Next(k) => k.len().saturating_add(32),
                _ => 0,
            }),
            Self::Ids(v, _) => v.len() * 8,
        }
    }
}

impl Query {
    fn touches(&self, ids: &[u64]) -> bool {
        match self {
            Self::Keys { id, .. } | Self::Page { id, .. } => ids.binary_search(id).is_ok(),
            Self::Ids { .. } => true,
        }
    }
    fn bytes(&self) -> usize {
        128 + match self {
            Self::Keys { keys, .. } => keys.iter().map(|k| k.len() + 32).sum(),
            Self::Page { from, prefix, .. } => from.len() + prefix.len(),
            Self::Ids { .. } => 0,
        }
    }
}

/// One physical filesystem sample shared by the service's shards. Never sum its
/// available bytes once per DB. Reservation is conservative compaction/flush room,
/// separate from the native raw-device allocator.
#[derive(Debug, Default)]
pub(crate) struct Space {
    free: AtomicU64,
    total: AtomicU64,
    reserve: AtomicU64,
    users: AtomicU64,
}

/// The worker owns the reservation, not its owner-side endpoint. In particular a
/// detached slow DB close cannot release capacity still used by that database.
#[derive(Debug)]
struct SpaceLease {
    space: Arc<Space>,
    bytes: u64,
}
impl SpaceLease {
    fn new(space: Arc<Space>, bytes: u64) -> Self {
        space.reserve.fetch_add(bytes, Ordering::AcqRel);
        space.users.fetch_add(1, Ordering::AcqRel);
        Self { space, bytes }
    }
}
impl Drop for SpaceLease {
    fn drop(&mut self) {
        self.space.reserve.fetch_sub(self.bytes, Ordering::AcqRel);
        self.space.users.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Space {
    fn join(root: &Path) -> Result<Arc<Self>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::sync::{LazyLock, Mutex, Weak};
            static SHARED: LazyLock<Mutex<HashMap<u64, Weak<Space>>>> =
                LazyLock::new(Default::default);
            let dev = std::fs::metadata(root).map_err(err)?.dev();
            let mut map = SHARED.lock().map_err(err)?;
            if let Some(s) = map.get(&dev).and_then(Weak::upgrade) {
                return Ok(s);
            }
            let s = Arc::new(Self::default());
            s.refresh(root)?;
            map.insert(dev, Arc::downgrade(&s));
            Ok(s)
        }
        #[cfg(not(unix))]
        {
            let _ = root;
            Err(StoreError::Invalid(
                "RocksDB filesystem accounting requires Unix",
            ))
        }
    }

    fn refresh(&self, root: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let p = std::ffi::CString::new(root.as_os_str().as_bytes()).map_err(err)?;
            // SAFETY: initialized output and a NUL-terminated owned path.
            let mut fs: libc::statvfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statvfs(p.as_ptr(), &mut fs) } != 0 {
                return Err(err(std::io::Error::last_os_error()));
            }
            self.free.store(
                (fs.f_bavail as u64).saturating_mul(fs.f_frsize as u64),
                Ordering::Release,
            );
            self.total.store(
                (fs.f_blocks as u64).saturating_mul(fs.f_frsize as u64),
                Ordering::Release,
            );
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = root;
            Err(StoreError::Invalid(
                "RocksDB filesystem accounting requires Unix",
            ))
        }
    }

    pub fn available(&self) -> u64 {
        self.free
            .load(Ordering::Acquire)
            .saturating_sub(self.reserve.load(Ordering::Acquire))
    }
    pub fn sample(&self) -> (u64, u64) {
        (self.available(), self.total.load(Ordering::Acquire).max(1))
    }
}

#[derive(Debug)]
enum Request {
    Flush(Arc<Memtable>, Option<Instant>),
    Read(Query, Option<(u64, u64)>, usize),
    Page(
        Query,
        [Option<Arc<ObjMem>>; 3],
        usize,
        Option<(u64, u64)>,
        Option<Instant>,
    ),
}

#[derive(Debug)]
enum Completion {
    Flushed(u64, Vec<u64>, Option<Instant>),
    Read(Query, Arc<Answer>, Option<(u64, u64)>),
    Refused(Query, Option<(u64, u64)>),
    Failed(StoreError),
}

/// Fixed queue-slot metadata, never an allocation per completion. Off-mode still
/// has the larger slot layout, but performs no new clock reads or atomic adds.
#[derive(Debug)]
struct Response {
    value: Completion,
    handoff: Option<metrics::Handoff>,
}

// Return the exact bounded queue value on pressure; boxing it would allocate on
// the very retry path being measured (and change the existing ownership policy).
#[allow(clippy::result_large_err)]
fn push_request_with(
    tx: &mut Producer<Request>,
    mut request: Request,
    profile: &metrics::Profile,
    clock: impl FnOnce() -> Instant,
) -> std::result::Result<(), rtrb::PushError<Request>> {
    let mut profiled = false;
    if let Request::Page(_, _, _, _, stamp) = &mut request {
        *stamp = metrics::enqueue_stamp_with(profile, clock);
        profiled = stamp.is_some();
    }
    let result = tx.push(request);
    if profiled && result.is_ok() {
        profile.add(metrics::profile::HANDOFF_ACCEPTED, 1);
    }
    result
}

impl Response {
    fn unprofiled(value: Completion) -> Self {
        Self {
            value,
            handoff: None,
        }
    }
}

#[allow(clippy::result_large_err)] // Same allocation-free full-ring ownership.
fn push_response_with(
    tx: &mut Producer<Response>,
    mut response: Response,
    profile: &metrics::Profile,
    clock: impl FnOnce() -> Instant,
) -> std::result::Result<(), rtrb::PushError<Response>> {
    let profiled = response.handoff.is_some();
    if let Some(trace) = &mut response.handoff {
        trace.publishing_with(profile, clock);
    }
    let result = tx.push(response);
    if profiled {
        profile.add(
            if result.is_ok() {
                metrics::profile::HANDOFF_PUBLISHED
            } else {
                metrics::profile::HANDOFF_FULL_RETRIES
            },
            1,
        );
    }
    result
}

struct Statistics(Options);

impl std::fmt::Debug for Statistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Statistics").finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Database {
    #[cfg(test)]
    page_visits: std::cell::Cell<usize>,
    #[cfg(test)]
    point_copied: std::cell::Cell<usize>,
    #[cfg(test)]
    point_visits: std::cell::Cell<usize>,
    db: DB,
    watermark: u64,
    read_only: bool,
    page_bytes: usize,
    path: PathBuf,
    statistics: Option<Statistics>,
    profile: Option<Arc<metrics::Metrics>>,
}

impl Database {
    #[cfg(test)]
    fn open(path: &Path, expected: &[u8], mem: usize, read_only: bool) -> Result<Self> {
        Self::open_profiled(path, expected, mem, read_only, None, 1)
    }

    /// Default tuning (tests and fixed-configuration callers).
    #[cfg(test)]
    fn open_profiled(
        path: &Path,
        expected: &[u8],
        mem: usize,
        read_only: bool,
        profile: Option<Arc<metrics::Metrics>>,
        subcompactions: u32,
    ) -> Result<Self> {
        Self::open_tuned(
            path,
            expected,
            mem,
            read_only,
            profile,
            subcompactions,
            &Tuning::default(),
        )
    }

    fn open_tuned(
        path: &Path,
        expected: &[u8],
        mem: usize,
        read_only: bool,
        profile: Option<Arc<metrics::Metrics>>,
        subcompactions: u32,
        tuning: &Tuning,
    ) -> Result<Self> {
        if !path.join("CURRENT").is_file() {
            return Err(StoreError::Invalid(
                "missing RocksDB database; refusing to create replacement",
            ));
        }
        let mut o = options(mem, subcompactions, tuning)?;
        if profile.is_some() {
            o.enable_statistics();
            o.set_statistics_level(rocksdb_lib::statistics::StatsLevel::ExceptHistogramOrTimers);
        }
        let db = if read_only {
            DB::open_for_read_only(&o, path, false)
        } else {
            DB::open(&o, path)
        }
        .map_err(err)?;
        if db.get(IDENTITY).map_err(err)?.as_deref() != Some(expected) {
            return Err(StoreError::Invalid("RocksDB store/shard identity mismatch"));
        }
        let seq = db
            .get(WATERMARK)
            .map_err(err)?
            .ok_or_else(|| err("missing watermark"))?;
        let watermark = u64::from_le_bytes(
            seq.as_slice()
                .try_into()
                .map_err(|_| err("bad watermark"))?,
        );
        Ok(Self {
            #[cfg(test)]
            page_visits: std::cell::Cell::new(0),
            #[cfg(test)]
            point_copied: std::cell::Cell::new(0),
            #[cfg(test)]
            point_visits: std::cell::Cell::new(0),
            db,
            watermark,
            read_only,
            page_bytes: (mem / 4).max(1),
            path: path.to_owned(),
            statistics: profile.as_ref().map(|_| Statistics(o)),
            profile,
        })
    }

    /// Allocated filesystem bytes of this DB's files (WAL, SSTs and metadata),
    /// not logical OMAP size and not the usage of the containing filesystem.
    fn allocated_bytes(&self) -> Result<u64> {
        use std::os::unix::fs::MetadataExt;
        let mut bytes = 0u64;
        for entry in std::fs::read_dir(&self.path).map_err(err)? {
            let entry = entry.map_err(err)?;
            match entry.metadata() {
                Ok(m) if m.is_file() => {
                    bytes = bytes.saturating_add(m.blocks().saturating_mul(512))
                }
                Ok(_) => {}
                // Compaction can retire a file between enumeration and stat.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(err(e)),
            }
        }
        Ok(bytes)
    }

    fn flush(&mut self, mem: &Memtable) -> Result<u64> {
        if self.read_only || mem.lsn_hi() <= self.watermark {
            return Err(StoreError::Invalid(
                "read-only or nonmonotonic RocksDB flush",
            ));
        }
        let started = self.profile.as_ref().map(|_| Instant::now());
        let cpu_start = self.profile.as_ref().and_then(|_| metrics::thread_cpu_ns());
        let mut points = 0u64;
        let mut ranges = 0u64;
        let mut b = WriteBatch::default();
        // WriteBatch owns each appended key. Reuse only our encoding scratch,
        // rather than allocating a prefixed Vec for every materialized point.
        let mut point_key = Vec::new();
        for id in mem.sorted_ids() {
            let obj = mem.obj(id).expect("enumerated object");
            points += obj.map.len() as u64;
            ranges += obj.ranges.len() as u64;
            // The memtable invariant says every surviving point is newer than
            // any range covering it. Apply ranges first, then surviving points.
            for r in &obj.ranges {
                let end = r
                    .end
                    .as_ref()
                    .map_or_else(|| object_end(id), |e| key(id, e));
                b.delete_range(key(id, &r.first), end);
            }
            for (k, v) in &obj.map {
                key_into(&mut point_key, id, &k.key);
                match v {
                    Some(v) => b.put(&point_key, v),
                    None => b.delete(&point_key),
                }
            }
        }
        b.put(WATERMARK, mem.lsn_hi().to_le_bytes());
        drop(point_key);
        let mut w = WriteOptions::default();
        w.set_sync(true);
        let batch_bytes = self
            .profile
            .as_ref()
            .map_or(0, |_| b.size_in_bytes() as u64);
        let cpu_built = self.profile.as_ref().and_then(|_| metrics::thread_cpu_ns());
        let built = self.profile.as_ref().map(|_| Instant::now());
        let result = self.db.write_opt(b, &w);
        let finished = self.profile.as_ref().map(|_| Instant::now());
        let cpu_finished = self.profile.as_ref().and_then(|_| metrics::thread_cpu_ns());
        if let (Some(m), Some(started), Some(built), Some(finished)) =
            (&self.profile, started, built, finished)
        {
            m.profile.add(
                metrics::profile::BUILD_NS,
                metrics::nanos(built.duration_since(started)),
            );
            m.profile.add(
                metrics::profile::WRITE_NS,
                metrics::nanos(finished.duration_since(built)),
            );
            m.profile.record_cpu(cpu_start, cpu_built, cpu_finished);
            m.profile.add(metrics::profile::POINTS, points);
            m.profile.add(metrics::profile::RANGES, ranges);
            m.profile.add(metrics::profile::BATCH_BYTES, batch_bytes);
            m.profile.record_batch(batch_bytes, result.is_err());
        }
        result.map_err(err)?;
        self.watermark = mem.lsn_hi();
        Ok(self.watermark)
    }

    #[cfg(test)]
    fn read(&self, q: &Query) -> Result<Answer> {
        self.read_limit(q, usize::MAX)
    }

    fn read_limit(&self, q: &Query, limit: usize) -> Result<Answer> {
        match q {
            Query::Keys { id, keys } => {
                #[cfg(test)]
                {
                    self.point_copied.set(0);
                    self.point_visits.set(0);
                }
                let mut out = Vec::new();
                let mut bytes = 0usize;
                for k in keys {
                    #[cfg(test)]
                    self.point_visits.set(self.point_visits.get() + 1);
                    // Pin one value at a time: do not allocate an entire over-
                    // budget MultiGet batch and only refuse it after completion.
                    if let Some(v) = self.db.get_pinned(key(*id, k)).map_err(err)? {
                        bytes = bytes
                            .saturating_add(k.len())
                            .saturating_add(v.len())
                            .saturating_add(64);
                        if bytes > limit {
                            return Err(StoreError::TxnTooLarge);
                        }
                        #[cfg(test)]
                        self.point_copied.set(self.point_copied.get() + v.len());
                        out.push((k.clone(), Bytes::copy_from_slice(&v)));
                    }
                }
                Ok(Answer::Entries(out, false))
            }
            Query::Page { .. } => self.page_limit(q, &[None, None, None], limit),
            Query::Ids { after } => {
                let mut r = ReadOptions::default();
                r.set_iterate_upper_bound(vec![2]);
                let mut it = self.db.raw_iterator_opt(r);
                match after {
                    Some(id) => it.seek(object_end(*id)),
                    None => it.seek([1]),
                }
                let mut out = Vec::new();
                while let Some(k) = it.key() {
                    if k.len() < 9 || k[0] != 1 {
                        return Err(err("malformed OMAP key"));
                    }
                    if out.len() == PAGE {
                        break;
                    }
                    let id = u64::from_be_bytes(k[1..9].try_into().expect("id"));
                    out.push(id);
                    it.seek(object_end(id));
                }
                it.status().map_err(err)?;
                Ok(Answer::Ids(out, it.valid()))
            }
        }
    }

    /// Merge one immutable logical page off-core. Range tombstones seek over the
    /// covered DB prefix instead of walking every persisted deleted key. Point
    /// candidates remain separate so newer puts inside a skipped range survive.
    #[cfg(test)]
    fn page(&self, q: &Query, view: &[Option<Arc<ObjMem>>; 3]) -> Result<Answer> {
        self.page_limit(q, view, usize::MAX)
    }

    fn page_limit(
        &self,
        q: &Query,
        view: &[Option<Arc<ObjMem>>; 3],
        limit: usize,
    ) -> Result<Answer> {
        use std::ops::Bound;
        let Query::Page {
            id,
            from,
            excl,
            prefix,
            entries,
            ..
        } = q
        else {
            return Err(StoreError::Invalid("non-page RocksDB overlay query"));
        };
        let mut timing = self
            .profile
            .as_ref()
            .and_then(|m| metrics::PageTimer::start(&m.profile));
        let mut options = ReadOptions::default();
        options.set_iterate_upper_bound(object_end(*id));
        let mut it = self.db.raw_iterator_opt(options);
        if let Some(t) = &mut timing {
            t.mark(1);
        }
        let result = (|| {
            let start: &[u8] = from.as_ref().max(prefix.as_ref());
            let exclusive = *excl && start == from.as_ref();
            let prefix_empty = prefix.is_empty();
            let bound = if exclusive {
                Bound::Excluded(start)
            } else {
                Bound::Included(start)
            };
            let mut points = view.each_ref().map(|o| {
                o.as_ref()
                    .map(|o| o.map.range::<[u8], _>((bound, Bound::Unbounded)).peekable())
            });
            #[cfg(test)]
            self.page_visits.set(0);
            it.seek(key(*id, start));
            if let Some(k) = it.key() {
                if k.len() < 9 || k[0] != 1 {
                    return Err(err("malformed OMAP key"));
                }
                if exclusive && &k[9..] == start {
                    it.next();
                }
            }
            let mut out = PageBuilder::default();
            let mut bytes = 0usize;
            if let Some(t) = &mut timing {
                t.mark(2);
            }
            loop {
                #[cfg(test)]
                self.page_visits.set(self.page_visits.get() + 1);
                // Skip ranges in O(number of covering ranges), not O(DB entries).
                // Reuse one safe borrowed pair until this iteration advances or
                // seeks. Separate key/key/value calls repeat validity checks
                // and DB-key access; returned output still acquires ownership.
                let entry = it.item();
                if let Some((k, _)) = entry {
                    if k.len() < 9 || k[0] != 1 {
                        return Err(err("malformed OMAP key"));
                    }
                    let base = &k[9..];
                    let covered = view
                        .iter()
                        .flatten()
                        .find_map(|o| crate::olsm::ranges_find(&o.ranges, *id, base));
                    if let Some(r) = covered {
                        let end = r
                            .end
                            .as_ref()
                            .map_or_else(|| object_end(*id), |e| key(*id, e));
                        it.seek(end);
                        continue;
                    }
                }
                // Each stream advances past the selected key below. After the
                // initial exclusive seek, no owned per-entry cursor is necessary.
                // Borrow candidates until the iterator advances; only returned DB
                // keys and the continuation need owned copies. All returned
                // payloads go into one credit-bounded, independently owned batch.
                let base = entry
                    .map(|(k, _)| &k[9..])
                    .filter(|k| prefix_empty || k.starts_with(prefix));
                let mut candidate = base;
                // Selection, not value precedence: equal overlay keys leave
                // the DB candidate selected. Only a strictly smaller overlay
                // replaces it, so neither value lookup nor advance needs to
                // compare the chosen key's bytes against the DB key again.
                let mut base_selected = base.is_some();
                for stream in points.iter_mut().flatten() {
                    while stream.peek().is_some_and(|(_, v)| v.is_none()) {
                        stream.next();
                        #[cfg(test)]
                        self.page_visits.set(self.page_visits.get() + 1);
                    }
                    if let Some(&(k, _)) = stream.peek()
                        && (prefix_empty || k.key.starts_with(prefix))
                        && candidate.is_none_or(|old| k.key.as_ref() < old)
                    {
                        candidate = Some(k.key.as_ref());
                        base_selected = false;
                    }
                }
                let Some(k) = candidate else {
                    it.status().map_err(err)?;
                    return Ok(Answer::Page(out.finish(), PageEnd::End));
                };
                let mut answer = Probe::Pass;
                for o in view.iter().flatten() {
                    if let Some(v) = o.map.get(k) {
                        answer = Probe::Hit(v.clone());
                        break;
                    }
                    if crate::olsm::ranges_find(&o.ranges, *id, k).is_some() {
                        answer = Probe::Covered;
                        break;
                    }
                }
                let value = match &answer {
                    Probe::Hit(v) => v.as_deref(),
                    Probe::Covered => None,
                    Probe::Pass => {
                        if base_selected {
                            entry.map(|(_, value)| value)
                        } else {
                            None
                        }
                    }
                };
                if let Some(v) = value {
                    let cost = k.len().saturating_add(v.len()).saturating_add(64);
                    if cost > limit && out.is_empty() {
                        return Err(StoreError::TxnTooLarge);
                    }
                    if out.len() == (*entries).clamp(1, SCAN_BATCH)
                        || (!out.is_empty()
                            && (bytes >= self.page_bytes || bytes.saturating_add(cost) > limit))
                        || !out.push(k, v, *entries, self.page_bytes, limit)?
                    {
                        it.status().map_err(err)?;
                        let next_bytes = k.len().saturating_add(32);
                        let end = if next_bytes <= limit.saturating_sub(out.bytes()) {
                            PageEnd::Next(Bytes::copy_from_slice(k))
                        } else {
                            PageEnd::Unknown
                        };
                        return Ok(Answer::Page(out.finish(), end));
                    }
                    bytes = bytes.saturating_add(cost);
                }
                for stream in points.iter_mut().flatten() {
                    if stream.peek().is_some_and(|(pk, _)| pk.key.as_ref() == k) {
                        stream.next();
                    }
                }
                if base_selected {
                    it.next();
                }
            }
        })();
        if let Some(t) = &mut timing {
            t.mark(3);
        }
        drop(it);
        if let Some(t) = timing {
            t.finish(result.is_ok());
        }
        result
    }
}

fn pin(cpu: Option<usize>) -> Result<()> {
    pin_cpus(cpu.as_slice())
}

fn pin_cpus(cpus: &[usize]) -> Result<()> {
    #[cfg(target_os = "linux")]
    if !cpus.is_empty() {
        if cpus.iter().any(|cpu| *cpu >= libc::CPU_SETSIZE as usize) {
            return Err(StoreError::Invalid("RocksDB CPU exceeds CPU_SETSIZE"));
        }
        // SAFETY: initialized CPU set, checked index; pid 0 selects this worker.
        let rc = unsafe {
            let mut mask: libc::cpu_set_t = std::mem::zeroed();
            for cpu in cpus {
                libc::CPU_SET(*cpu, &mut mask);
            }
            libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &mask)
        };
        if rc != 0 {
            return Err(err(std::io::Error::last_os_error()));
        }
    }
    #[cfg(not(target_os = "linux"))]
    if !cpus.is_empty() {
        return Err(StoreError::Invalid("RocksDB CPU pinning needs Linux"));
    }
    Ok(())
}

/// Owner wake installed after mount (the driver's core wake handle): the worker
/// calls it after every published completion, so an owner sleeping in its idle
/// wait sees the result without waiting out its sleep cap. The callee must be
/// cheap when the owner is awake (no syscall) and may be called from any thread.
#[derive(Clone)]
pub struct OwnerWake(pub Arc<dyn Fn() + Send + Sync>);

impl std::fmt::Debug for OwnerWake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnerWake")
    }
}

/// Set once by the owner, read by the worker after each publication.
type WakeSlot = Arc<std::sync::OnceLock<OwnerWake>>;

/// Publish-then-wake: the caller has already pushed the completion, so the
/// owner's post-announcement re-check ([`Client::has_completion`]) or this wake
/// observes it (no lost wake, see `rt::wake`).
#[inline]
fn notify_owner(wake: &WakeSlot) {
    if let Some(w) = wake.get() {
        (w.0)();
    }
}

#[derive(Debug)]
struct WorkerEnv {
    stop: Arc<AtomicBool>,
    root: PathBuf,
    space: Arc<Space>,
    allocated: Arc<AtomicU64>,
    metrics: Arc<metrics::Metrics>,
    wake: WakeSlot,
    #[cfg(test)]
    hold: Arc<AtomicBool>,
}

/// Cold diagnostic work, not the authoritative free-space admission refresh.
fn observe_diagnostics(
    db: &Database,
    allocated: &AtomicU64,
    metrics: &metrics::Metrics,
) -> Result<()> {
    let started = Instant::now();
    metrics.observe(db);
    let result = db
        .allocated_bytes()
        .map(|n| allocated.store(n, Ordering::Release));
    metrics.record(3, started);
    result
}

fn worker(mut db: Database, mut rx: Consumer<Request>, mut tx: Producer<Response>, env: WorkerEnv) {
    let WorkerEnv {
        stop,
        root,
        space,
        allocated,
        metrics,
        wake,
        #[cfg(test)]
        hold,
    } = env;
    let mut sampled = Instant::now();
    while !stop.load(Ordering::Acquire) {
        if sampled.elapsed() >= Duration::from_millis(250) {
            if let Err(e) = observe_diagnostics(&db, &allocated, &metrics) {
                let _ = tx.push(Response::unprofiled(Completion::Failed(e)));
                notify_owner(&wake);
                return;
            }
            if let Err(e) = space.refresh(&root) {
                let _ = tx.push(Response::unprofiled(Completion::Failed(e)));
                notify_owner(&wake);
                return;
            }
            sampled = Instant::now();
        }
        let req = match rx.pop() {
            Ok(r) => r,
            Err(_) => {
                std::thread::park_timeout(Duration::from_millis(10));
                continue;
            }
        };
        let mut handoff = match &req {
            Request::Page(_, _, _, _, queued) => {
                metrics::Handoff::dequeued(&metrics.profile, *queued)
            }
            _ => None,
        };
        let materialized = matches!(&req, Request::Flush(..));
        #[cfg(test)]
        {
            while hold.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
                std::thread::park_timeout(Duration::from_millis(1));
            }
            if stop.load(Ordering::Acquire) {
                return;
            }
        }
        let kind = match &req {
            Request::Flush(m, queued) => {
                if let Some(queued) = queued {
                    metrics.profile.elapsed(metrics::profile::QUEUE_NS, *queued);
                }
                metrics.materialized_bytes(m.bytes());
                0
            }
            Request::Read(..) => 1,
            Request::Page(..) => 2,
        };
        let started = Instant::now();
        let out = match req {
            Request::Flush(m, _) => db
                .flush(&m)
                .map(|lsn| Completion::Flushed(lsn, m.sorted_ids(), None)),
            Request::Read(q, session, limit) => match db.read_limit(&q, limit) {
                Err(StoreError::TxnTooLarge) => Ok(Completion::Refused(q, session)),
                r => r.map(|a| Completion::Read(q, Arc::new(a), session)),
            },
            Request::Page(q, view, limit, session, _) => match db.page_limit(&q, &view, limit) {
                Err(StoreError::TxnTooLarge) => Ok(Completion::Refused(q, session)),
                r => r.map(|a| Completion::Read(q, Arc::new(a), None)),
            },
        };
        metrics.record(kind, started);
        if materialized {
            // Admission space is authoritative and refreshed after every write.
            // Properties/file accounting are diagnostics: the periodic path
            // above samples them without one directory walk per durable batch.
            // Do not reset sampled here: a busy writer must not starve sampling.
            if let Err(e) = space.refresh(&root) {
                let _ = tx.push(Response::unprofiled(Completion::Failed(e)));
                notify_owner(&wake);
                return;
            }
        }
        let failed = out.is_err();
        let mut c = out.unwrap_or_else(Completion::Failed);
        if metrics.profile.enabled
            && let Completion::Flushed(_, _, at) = &mut c
        {
            *at = Some(Instant::now());
        }
        if let Some(trace) = &mut handoff {
            trace.ready(&metrics.profile);
        }
        let mut c = Response { value: c, handoff };
        loop {
            match push_response_with(&mut tx, c, &metrics.profile, Instant::now) {
                Ok(()) => break,
                Err(rtrb::PushError::Full(v)) => c = v,
            }
            // Full ring: the owner has unconsumed completions; make sure it runs.
            notify_owner(&wake);
            if stop.load(Ordering::Acquire) {
                return;
            }
            std::thread::park_timeout(Duration::from_millis(1));
        }
        notify_owner(&wake);
        if failed {
            return;
        }
    }
}

/// Owner-side bounded worker endpoint. No DB handle or blocking filesystem call
/// is reachable from its request/poll methods. Pending work keeps its shard active
/// until completions are consumed, including when no native device IO is pending.
#[derive(Debug)]
pub(crate) struct Client {
    tx: Producer<Request>,
    rx: Consumer<Response>,
    thread: Thread,
    join: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    cache: HashMap<Query, Arc<Answer>>,
    pending: HashSet<Query>,
    cache_bytes: usize,
    budget: usize,
    pub watermark: u64,
    pub flushed: Option<u64>,
    flushing: bool,
    pub failure: Option<StoreError>,
    pub read_only: bool,
    pub space: Arc<Space>,
    allocated: Arc<AtomicU64>,
    metrics: Arc<metrics::Metrics>,
    session: Option<(u64, u64)>,
    session_parents: HashMap<(u64, u64), (u64, u64)>,
    refused: Option<Query>,
    retained_owner: Option<(u64, u64)>,
    retained: HashMap<Query, Arc<Answer>>,
    retained_bytes: usize,
    retained_error: bool,
    read_budget: usize,
    scan_charge: usize,
    touched: Instant,
    /// A competing session is waiting for retained completion credits. Keep the
    /// owner polling until actual release/expiry, without synthetic read wakes.
    waiting_for_credits: bool,
    publication_started: Option<Instant>,
    blocked_started: Option<Instant>,
    freeze_profile: Option<(u64, Instant)>,
    /// Owner wake shared with the worker (empty until the driver installs it).
    wake: WakeSlot,
    #[cfg(test)]
    hold: Arc<AtomicBool>,
    #[cfg(test)]
    credit_clock: Option<Instant>,
    #[cfg(test)]
    credit_clock_reads: std::cell::Cell<u64>,
}

/// Exclusive credit ownership for one non-yielding, bounded scan slice. Only
/// charging is exposed: queries, polling, release and publication require the
/// Client back. Every entry/growth is still checked against the same budget.
///
/// An executing slice (including OS preemption) is active, not abandoned. Drop
/// starts a fresh idle lease; it never expires, releases or wakes the owner.
/// Safety does not depend on Drop: a forgotten guard leaves the previous charge
/// and timestamp in place, reclaimable through ordinary idle expiry.
#[derive(Debug)]
pub(crate) struct ScanAdmission<'a> {
    client: &'a mut Client,
}

impl ScanAdmission<'_> {
    pub(crate) fn charge(&mut self, bytes: usize) -> Result<()> {
        self.client.charge_scan(bytes)
    }
}

impl Drop for ScanAdmission<'_> {
    fn drop(&mut self) {
        self.client.touched = self.client.credit_now();
    }
}

impl Client {
    #[cfg(test)]
    pub(crate) fn test_space(&mut self, free: u64) {
        self.space = Arc::new(Space {
            free: AtomicU64::new(free),
            total: AtomicU64::new(1 << 30),
            reserve: AtomicU64::new(0),
            users: AtomicU64::new(1),
        });
    }
    pub fn open(
        cfg: &Config,
        sb: &Superblock,
        shard: u32,
        mem: usize,
        floor: u64,
        frontier: u64,
    ) -> Result<Self> {
        cfg.admit()?;
        let space = Space::join(&cfg.root)?;
        let path = cfg.path(sb, shard)?;
        cfg.validate_location(&path)?;
        if std::fs::canonicalize(&path).map_err(err)? != path {
            return Err(StoreError::Invalid(
                "RocksDB shard directory contains symlinks or traversal",
            ));
        }
        let id = identity(sb, shard);
        let cpu = cfg.cpu;
        let background_cpus = cfg.background_cpus.clone();
        let subcompactions = cfg.subcompactions();
        let tuning = cfg.tuning;
        let read_only = cfg.read_only;
        let (tx, req) = RingBuffer::new(QUEUE);
        let (out, rx) = RingBuffer::new(QUEUE);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker_space = space.clone();
        let lease = SpaceLease::new(
            space.clone(),
            if read_only {
                0
            } else {
                (mem as u64).saturating_mul(8)
            },
        );
        let allocated = Arc::new(AtomicU64::new(0));
        let worker_allocated = allocated.clone();
        let metrics = Arc::new(metrics::Metrics::new_profiled(cfg.profile));
        metrics.cache_capacity(mem / 2);
        let worker_metrics = metrics.clone();
        let wake = WakeSlot::default();
        let worker_wake = wake.clone();
        #[cfg(test)]
        let hold = Arc::new(AtomicBool::new(false));
        #[cfg(test)]
        let worker_hold = hold.clone();
        let root = cfg.root.clone();
        let (boot_tx, boot_rx) = std::sync::mpsc::sync_channel(1);
        let join = std::thread::Builder::new()
            .name(format!("omap-rocks-{shard}"))
            .spawn(move || {
                // Declared before DB construction, released only after its open
                // failure or worker/DB destruction, including timeout detachment.
                let _lease = lease;
                // Shared Rocks pools inherit their first initializer's affinity.
                // Open within the admitted service mask before narrowing this
                // worker to its selected CPU (none for `WorkerCpu::Float`).
                let opened = (if background_cpus.is_empty() {
                    pin(cpu)
                } else {
                    pin_cpus(&background_cpus)
                })
                .and_then(|()| {
                    Database::open_tuned(
                        &path,
                        &id,
                        mem,
                        read_only,
                        worker_metrics
                            .profile
                            .enabled
                            .then(|| worker_metrics.clone()),
                        subcompactions,
                        &tuning,
                    )
                })
                .and_then(|db| {
                    pin(cpu)?;
                    if db.watermark < floor || db.watermark > frontier {
                        Err(err(format!(
                            "watermark {} outside native [{floor}, {frontier}]",
                            db.watermark
                        )))
                    } else {
                        Ok(db)
                    }
                });
                match opened {
                    Ok(db) => {
                        if let Err(e) = observe_diagnostics(&db, &worker_allocated, &worker_metrics)
                        {
                            let _ = boot_tx.send(Err(e));
                            return;
                        }
                        if boot_tx.send(Ok(db.watermark)).is_ok() {
                            worker(
                                db,
                                req,
                                out,
                                WorkerEnv {
                                    stop: stopping,
                                    root,
                                    space: worker_space,
                                    allocated: worker_allocated,
                                    metrics: worker_metrics,
                                    wake: worker_wake,
                                    #[cfg(test)]
                                    hold: worker_hold,
                                },
                            );
                        }
                    }
                    Err(e) => {
                        let _ = boot_tx.send(Err(e));
                    }
                }
            })
            .map_err(err)?;
        let watermark = match boot_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(r) => r?,
            Err(e) => {
                stop.store(true, Ordering::Release);
                return Err(err(format!("WARNING TIMEOUT RocksDB open: {e}")));
            }
        };
        Ok(Self {
            tx,
            rx,
            thread: join.thread().clone(),
            join: Some(join),
            stop,
            cache: HashMap::new(),
            pending: HashSet::new(),
            cache_bytes: 0,
            budget: mem / 4,
            watermark,
            flushed: None,
            flushing: false,
            failure: None,
            read_only,
            space,
            allocated,
            metrics,
            session: None,
            session_parents: HashMap::new(),
            refused: None,
            retained_owner: None,
            retained: HashMap::new(),
            retained_bytes: 0,
            retained_error: false,
            read_budget: mem.saturating_mul(2),
            scan_charge: 0,
            touched: Instant::now(),
            waiting_for_credits: false,
            publication_started: None,
            blocked_started: None,
            freeze_profile: None,
            wake,
            #[cfg(test)]
            hold,
            #[cfg(test)]
            credit_clock: None,
            #[cfg(test)]
            credit_clock_reads: std::cell::Cell::new(0),
        })
    }

    /// Install the owner wake (first install wins: a core's wake handle never
    /// changes). Without one the owner relies on its idle cap, as before.
    pub fn set_owner_wake(&self, w: OwnerWake) {
        let _ = self.wake.set(w);
    }

    /// A worker completion is published and not yet consumed by
    /// [`poll`](Self::poll): the owner's idle re-check after it announced its
    /// sleep.
    pub fn has_completion(&self) -> bool {
        !self.rx.is_empty()
    }

    pub fn poll(&mut self) -> bool {
        let mut wake = self.expire_session();
        while let Ok(c) = self.rx.pop() {
            if let Some(trace) = c.handoff {
                let outcome = match &c.value {
                    Completion::Read(..) => Some(metrics::profile::HANDOFF_SUCCESS),
                    Completion::Refused(..) => Some(metrics::profile::HANDOFF_REFUSED),
                    Completion::Failed(..) => Some(metrics::profile::HANDOFF_FAILED),
                    Completion::Flushed(..) => None,
                };
                trace.consumed(&self.metrics.profile, outcome);
            }
            wake = true;
            self.metrics.event(13);
            match c.value {
                Completion::Flushed(lsn, ids, completed) => {
                    if let Some(completed) = completed {
                        self.metrics
                            .profile
                            .elapsed(metrics::profile::COMPLETION_NS, completed);
                        self.publication_started = Some(Instant::now());
                    }
                    self.watermark = lsn;
                    self.flushed = Some(lsn);
                    self.flushing = false;
                    self.cache.retain(|q, _| !q.touches(&ids));
                    self.cache_bytes = self.cache.iter().map(|(q, a)| q.bytes() + a.bytes()).sum();
                    self.retained.retain(|q, _| !q.touches(&ids));
                    self.retained_bytes = self
                        .retained
                        .iter()
                        .map(|(q, a)| q.bytes() + a.bytes())
                        .sum();
                    if self.refused.as_ref().is_some_and(|q| q.touches(&ids)) {
                        self.refused = None;
                    }
                }
                Completion::Read(q, a, session) => {
                    self.pending.remove(&q);
                    if session.is_some() && session == self.retained_owner {
                        let bytes = a.bytes().saturating_add(q.bytes());
                        if (!self.retained.is_empty()
                            && self.retained_bytes.saturating_add(bytes) > self.budget)
                            || self.scan_charge.saturating_add(
                                self.retained_bytes.saturating_add(bytes).saturating_mul(4),
                            ) > self.read_budget
                        {
                            self.retained_error = true;
                        } else {
                            self.retained_bytes = self.retained_bytes.saturating_add(bytes);
                            self.retained.insert(q, a);
                        }
                        continue;
                    }
                    let bytes = a.bytes().saturating_add(q.bytes());
                    if self.cache_bytes.saturating_add(bytes) > self.budget {
                        self.cache.clear();
                        self.cache_bytes = 0;
                    }
                    self.cache_bytes += bytes;
                    self.cache.insert(q, a);
                }
                Completion::Refused(q, session) => {
                    self.pending.remove(&q);
                    if session.is_some() && session == self.retained_owner {
                        self.retained_error = true;
                    } else {
                        self.refused = Some(q);
                    }
                }
                Completion::Failed(e) => {
                    self.failure = Some(e);
                }
            }
        }
        if self.join.as_ref().is_some_and(|j| j.is_finished()) && self.failure.is_none() {
            self.failure = Some(err("worker exited unexpectedly"));
            wake = true;
        }
        wake
    }

    #[cfg(test)]
    pub(crate) fn test_hold_worker(&self, hold: bool) {
        self.hold.store(hold, Ordering::Release);
        self.thread.unpark();
    }

    #[cfg(test)]
    pub(crate) fn test_stop_worker(&self) {
        self.stop.store(true, Ordering::Release);
        self.thread.unpark();
    }

    #[cfg(test)]
    pub(crate) fn test_expire_credits(&mut self) {
        self.touched = self.credit_now() - Duration::from_secs(31);
    }

    #[cfg(test)]
    pub(crate) fn test_credit_clock(&mut self, now: Instant) {
        self.credit_clock = Some(now);
    }

    #[cfg(test)]
    pub(crate) fn test_credit_clock_reads(&self) -> u64 {
        self.credit_clock_reads.get()
    }

    #[cfg(test)]
    pub(crate) fn test_read_budget(&mut self, bytes: usize) {
        self.read_budget = bytes;
    }

    #[cfg(test)]
    pub(crate) fn test_cached_page(&self) -> Option<Arc<Answer>> {
        self.cache
            .values()
            .find(|a| matches!(***a, Answer::Page(..)))
            .cloned()
    }

    fn credit_now(&self) -> Instant {
        #[cfg(test)]
        {
            self.credit_clock_reads
                .set(self.credit_clock_reads.get() + 1);
            if let Some(now) = self.credit_clock {
                return now;
            }
        }
        Instant::now()
    }

    pub fn busy(&self) -> bool {
        self.flushing || !self.pending.is_empty() || self.flushed.is_some()
    }

    /// Readiness polling is broader than materialization admission. A retained-
    /// credit waiter must not stop an otherwise idle worker flushing durable data.
    pub fn needs_poll(&self) -> bool {
        self.busy() || self.waiting_for_credits
    }

    pub fn allocated_bytes(&self) -> u64 {
        self.allocated.load(Ordering::Acquire)
    }

    pub fn metrics(&self) -> metrics::Sample {
        self.metrics.sample()
    }

    pub fn profile_metrics(&self) -> [u64; 72] {
        let mut out = self.metrics.profile.sample();
        if let Some(at) = self.publication_started {
            out[metrics::profile::PUBLICATION_NS] =
                out[metrics::profile::PUBLICATION_NS].saturating_add(metrics::nanos(at.elapsed()));
        }
        if let Some(at) = self.blocked_started {
            out[metrics::profile::BACKPRESSURE_NS] =
                out[metrics::profile::BACKPRESSURE_NS].saturating_add(metrics::nanos(at.elapsed()));
        }
        out
    }

    pub fn note_blocked(&mut self) {
        if self.metrics.profile.enabled && self.blocked_started.is_none() {
            self.blocked_started = Some(Instant::now());
            self.metrics
                .profile
                .add(metrics::profile::BACKPRESSURE_INTERVALS, 1);
        }
    }

    pub fn note_frozen(&mut self, lsn: u64, bytes: u64, durable_lsn: u64) {
        if self.metrics.profile.enabled {
            if self.freeze_profile.replace((lsn, Instant::now())).is_some() {
                self.metrics
                    .profile
                    .add(metrics::profile::FREEZE_TRACK_ERRORS, 1);
            }
            self.metrics.profile.record_freeze(bytes, lsn > durable_lsn);
        }
    }

    fn note_enqueued(&mut self, lsn: u64, at: Instant) {
        if let Some((frozen_lsn, started)) = self.freeze_profile.take() {
            if lsn == frozen_lsn {
                self.metrics
                    .profile
                    .add(metrics::profile::FREEZE_ENQUEUES, 1);
                self.metrics.profile.add(
                    metrics::profile::FREEZE_WAIT_NS,
                    metrics::nanos(at.duration_since(started)),
                );
            } else {
                self.metrics
                    .profile
                    .add(metrics::profile::FREEZE_TRACK_ERRORS, 1);
            }
        }
    }

    pub fn note_unblocked(&mut self) {
        if let Some(at) = self.blocked_started.take() {
            self.metrics
                .profile
                .elapsed(metrics::profile::BACKPRESSURE_NS, at);
        }
    }

    pub fn note_published(&mut self) {
        if let Some(at) = self.publication_started.take() {
            self.metrics
                .profile
                .elapsed(metrics::profile::PUBLICATION_NS, at);
        }
    }
    pub fn pending_reads(&self) -> u64 {
        self.pending.len() as u64
    }
    pub fn materializing(&self) -> bool {
        self.flushing
    }
    pub fn session(&self) -> Option<(u64, u64)> {
        self.session
    }

    /// One admitted read session owns aggregate completion credits. Scans retain
    /// output in request memos; points publish directly into protected answers.
    /// Competing sessions park without consuming the admitted request's credits.
    /// Request cancellation/finish releases ownership; abandoned sessions expire
    /// after 30s without another execution attempt (not the ordinary cache TTL).
    pub fn read_session(&mut self, session: Option<(u64, u64)>, keep: bool) {
        if let (Some(child), Some(parent), Some(owner)) =
            (session, self.session, self.retained_owner)
            && child != parent
            && self.credit_session(parent) == owner
        {
            self.session_parents.insert(child, owner);
        }
        if session.is_none() && !keep && self.retained_owner == self.session {
            self.retained_owner = None;
            self.retained.clear();
            self.retained_bytes = 0;
            self.retained_error = false;
            self.scan_charge = 0;
            self.session_parents.clear();
            self.waiting_for_credits = false;
        } else if session.is_none()
            && !keep
            && let Some(child) = self.session
        {
            self.session_parents.remove(&child);
        }
        self.session = session;
        if session.is_some_and(|s| self.session_admitted(s)) {
            self.touched = self.credit_now();
        }
    }

    pub fn retained_session(&self) -> Option<(u64, u64)> {
        self.retained_owner
    }

    fn credit_session(&self, session: (u64, u64)) -> (u64, u64) {
        self.session_parents
            .get(&session)
            .copied()
            .unwrap_or(session)
    }
    pub fn session_admitted(&self, session: (u64, u64)) -> bool {
        self.retained_owner == Some(self.credit_session(session))
    }
    pub fn set_scan_charge(&mut self, bytes: usize) {
        self.scan_charge = bytes;
    }

    fn expire_session(&mut self) -> bool {
        self.expire_session_after(self.credit_now().duration_since(self.touched))
    }

    fn expire_session_after(&mut self, idle: Duration) -> bool {
        if idle < Duration::from_secs(30) {
            return false;
        }
        let released = self.retained_owner.take().is_some();
        self.retained.clear();
        self.retained_bytes = 0;
        self.retained_error = false;
        self.scan_charge = 0;
        self.session_parents.clear();
        self.waiting_for_credits = false;
        released
    }

    pub fn admit_scan(&mut self, session: (u64, u64), bytes: usize) -> Result<()> {
        self.claim_scan(session)?;
        self.charge_scan(bytes)
    }

    pub(crate) fn scan_admission(&mut self, session: (u64, u64)) -> Result<ScanAdmission<'_>> {
        self.claim_scan(session)?;
        Ok(ScanAdmission { client: self })
    }

    fn claim_scan(&mut self, session: (u64, u64)) -> Result<()> {
        self.expire_session();
        let owner = self.credit_session(session);
        if self.retained_owner.is_some_and(|s| s != owner) {
            self.waiting_for_credits = true;
            return Err(StoreError::Miss);
        }
        self.retained_owner = Some(owner);
        self.touched = self.credit_now();
        Ok(())
    }

    fn charge_scan(&mut self, bytes: usize) -> Result<()> {
        if bytes.saturating_add(self.retained_bytes.saturating_mul(4)) > self.read_budget {
            return Err(StoreError::TxnTooLarge);
        }
        self.scan_charge = bytes;
        Ok(())
    }

    pub fn flush(&mut self, m: Arc<Memtable>) -> Result<()> {
        if self.flushing || self.flushed.is_some() {
            return Err(StoreError::Busy);
        }
        if self.read_only {
            return Err(StoreError::Invalid("RocksDB flush on read-only mount"));
        }
        if let Some(e) = &self.failure {
            return Err(e.clone());
        }
        let queued = self.metrics.profile.enabled.then(Instant::now);
        let lsn = m.lsn_hi();
        self.tx
            .push(Request::Flush(m, queued))
            .map_err(|_| StoreError::Busy)?;
        if let Some(at) = queued {
            self.note_enqueued(lsn, at);
        }
        self.flushing = true;
        self.thread.unpark();
        Ok(())
    }

    pub fn query(&mut self, q: Query) -> Result<Arc<Answer>> {
        self.query_view(q, [None, None, None])
    }

    /// Request memos own unconsumed scan batches; the opportunistic cache must
    /// not pin their consumed values or be required to preserve scan progress.
    pub fn take_page(
        &mut self,
        q: Query,
        view: [Option<Arc<ObjMem>>; 3],
    ) -> Result<(PageEntries, PageEnd)> {
        if !matches!(q, Query::Page { .. }) {
            return Err(StoreError::Invalid("non-page RocksDB batch query"));
        }
        let answer = self.query_view(q.clone(), view)?;
        if let Some(cached) = self.cache.remove(&q) {
            self.cache_bytes = self
                .cache_bytes
                .saturating_sub(q.bytes().saturating_add(cached.bytes()));
        }
        match Arc::try_unwrap(answer) {
            Ok(Answer::Page(page, end)) => Ok((page, end)),
            Err(shared) => match &*shared {
                Answer::Page(page, end) => Ok((page.clone(), end.clone())),
                _ => Err(StoreError::Invalid("wrong RocksDB page response")),
            },
            _ => Err(StoreError::Invalid("wrong RocksDB page response")),
        }
    }

    pub fn query_view(&mut self, q: Query, view: [Option<Arc<ObjMem>>; 3]) -> Result<Arc<Answer>> {
        self.metrics.event(10);
        if let Some(e) = &self.failure {
            return Err(e.clone());
        }
        if self.refused.as_ref() == Some(&q) {
            return Err(StoreError::TxnTooLarge);
        }
        let retain = self.session.is_some() && matches!(q, Query::Keys { .. });
        if self.session.is_some() {
            self.expire_session();
            let owner = self.session.map(|s| self.credit_session(s));
            if self.retained_owner.is_some() && self.retained_owner != owner {
                self.waiting_for_credits = true;
                return Err(StoreError::Miss);
            }
            self.retained_owner = owner;
            self.touched = self.credit_now();
            if self.retained_error {
                return Err(StoreError::TxnTooLarge);
            }
        }
        if retain {
            if self.retained_error {
                return Err(StoreError::TxnTooLarge);
            }
            if let Some(a) = self.retained.get(&q) {
                return Ok(a.clone());
            }
        }
        if let Some(a) = self.cache.get(&q).cloned() {
            if retain {
                let bytes = q.bytes().saturating_add(a.bytes());
                // One oversized answer is supported, as for a single large DB
                // value/page. A compound response above its configured read share
                // fails explicitly rather than evicting progress and livelocking.
                if (!self.retained.is_empty()
                    && self.retained_bytes.saturating_add(bytes) > self.budget)
                    || self
                        .scan_charge
                        .saturating_add(self.retained_bytes.saturating_add(bytes).saturating_mul(4))
                        > self.read_budget
                {
                    return Err(StoreError::TxnTooLarge);
                }
                self.retained_bytes = self.retained_bytes.saturating_add(bytes);
                self.retained.insert(q, a.clone());
            }
            return Ok(a);
        }
        // One read in flight bounds result memory even for a single oversized
        // value. Multi-get and paged scans batch keys within that request.
        if self.pending.is_empty() {
            let available = self
                .read_budget
                .saturating_sub(self.scan_charge)
                .saturating_sub(self.retained_bytes.saturating_mul(4));
            let mut limit = available / 4;
            if retain && !self.retained.is_empty() {
                limit = limit.min(self.budget.saturating_sub(self.retained_bytes));
            }
            limit = limit.saturating_sub(q.bytes());
            let req = if matches!(q, Query::Page { .. }) {
                Request::Page(q.clone(), view, limit, self.retained_owner, None)
            } else {
                Request::Read(
                    q.clone(),
                    if retain { self.retained_owner } else { None },
                    limit,
                )
            };
            if push_request_with(&mut self.tx, req, &self.metrics.profile, Instant::now).is_ok() {
                self.metrics.event(11);
                self.pending.insert(q);
                self.thread.unpark();
            }
        }
        if !self.pending.is_empty() {
            self.metrics.event(12);
        }
        Err(StoreError::Miss)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.unpark();
        if let Some(j) = self.join.take() {
            let until = Instant::now() + Duration::from_secs(30);
            while !j.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(1));
            }
            if j.is_finished() {
                let _ = j.join();
            } else {
                eprintln!(
                    "WARNING TIMEOUT RocksDB worker shutdown exceeded 30s; retaining owned state until thread exits"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
