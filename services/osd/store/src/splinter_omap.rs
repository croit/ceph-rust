// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
//! Independent SplinterDB base for logical OMAP. Native WAL owns ACK/replay.
//! Foreign calls run only on the shard's bounded worker, never on a PG reactor.
use crate::error::{Result, StoreError};
use crate::foreign_mem::{Memtable, ObjMem};
use crate::layout::Superblock;
use crate::olsm::mem::{MKey, Probe};
use bytes::Bytes;
use rtrb::{Consumer, Producer, RingBuffer};
pub use splinterdb_lib::IoMode;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread::{JoinHandle, Thread};
use std::time::{Duration, Instant};
mod scan_cache;
pub(crate) mod timing;
use scan_cache::ScanCache;

const IDENTITY: &[u8] = b"\0identity";
const WATERMARK: &[u8] = b"\0watermark";
pub(crate) const PAGE: usize = 256;
pub(crate) const MAX_SCAN_ROWS: usize = PAGE * 16;
const QUEUE: usize = 16;
/// Upper bound of threads applying one flush (worker plus helpers).
const MAX_APPLY_THREADS: usize = 4;
/// Points per dynamically claimed apply chunk: ~40 chunks for a typical ~80k-point
/// materialization balance three threads; a smaller flush uses fewer helpers.
const APPLY_CHUNK: usize = 2048;
type View = [Option<Arc<ObjMem>>; 3];
fn err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Corrupt(format!("SplinterDB OMAP: {e}"))
}
fn key(id: u64, user: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(9 + user.len());
    v.push(1);
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(user);
    v
}
fn object_end(id: u64) -> Vec<u8> {
    if id == u64::MAX {
        vec![2]
    } else {
        key(id + 1, b"")
    }
}
fn prefix_end(id: u64, prefix: &[u8]) -> Vec<u8> {
    let mut end = key(id, prefix);
    for i in (9..end.len()).rev() {
        if end[i] != 255 {
            end[i] += 1;
            end.truncate(i + 1);
            return end;
        }
    }
    object_end(id)
}
fn identity(sb: &Superblock, shard: u32) -> Vec<u8> {
    let mut v = b"nvmeosd-splinter-omap-v1".to_vec();
    v.extend_from_slice(&sb.osd_fsid);
    v.extend_from_slice(&sb.mkfs_time.to_le_bytes());
    v.extend_from_slice(&sb.shards.to_le_bytes());
    v.extend_from_slice(&shard.to_le_bytes());
    v
}

#[derive(Clone, Debug)]
pub struct Config {
    pub root: PathBuf,
    /// Required for fresh creation, per shard, not summed or shared capacity.
    pub capacity: u64,
    pub cpu: Option<usize>,
    /// Startup-only experiment; the daemon resolves the cleaner CPU from its budget.
    pub isolate_cleaner: bool,
    /// Resolved cleaner CPU, never an implicit extra CPU. None keeps lazy legacy startup.
    pub cleaner_cpu: Option<usize>,
    /// Default-off experiment: one normal-maintenance worker, no memtable pool.
    /// Requires cleaner isolation and a distinct resolved assigned CPU.
    pub normal_maintenance: bool,
    /// Default-off experiment: one SplinterDB memtable worker on top of normal maintenance.
    pub memtable_maintenance: bool,
    /// Threads applying one overlay flush (1 = the worker alone). Extra threads are
    /// registered helpers floating over `apply_cpus`; without a resolved placement the
    /// worker applies alone.
    pub apply_threads: usize,
    /// Resolved service CPU set for apply helpers; empty keeps the worker alone.
    pub apply_cpus: Vec<usize>,
    /// SplinterDB log growth per automatic checkpoint; 0 keeps the library default
    /// (one cache size). 64MiB..=4GiB and at most a quarter of the creation capacity.
    pub checkpoint_log_bytes: u64,
    /// Opt-in: a registered durability thread runs each flush's barriers and
    /// watermark while the worker applies the next flush (one awaits durability).
    pub pipelined_barrier: bool,
    /// Opt-in (patched library): filled log pages are written at the next
    /// durability wait instead of by the inserting thread.
    pub defer_log_writeback: bool,
    /// Creation only: provision images without the library log (marker `shard-N.nolog`);
    /// barriers then checkpoint and the native WAL is the only log. Opens follow the
    /// image's marker, never this setting.
    pub no_log: bool,
    /// Public upstream open mutates its image. This mode explicitly refuses.
    pub read_only: bool,
    pub io: IoMode,
    /// Soft upstream extent-prefetch budget; not a physical IO ceiling.
    pub prefetch_bytes: u64,
    /// Owned logical pages per scan window;1 disables extra Rust look-ahead.
    pub scan_readahead_pages: usize,
    pub cache_stats: bool,
    #[cfg(any(test, feature = "lab"))]
    pub allow_non_nvme: bool,
}
impl Config {
    pub fn new(root: PathBuf, capacity: u64) -> Self {
        Self {
            root,
            capacity,
            cpu: None,
            isolate_cleaner: false,
            cleaner_cpu: None,
            normal_maintenance: false,
            memtable_maintenance: false,
            apply_threads: 1,
            apply_cpus: Vec::new(),
            checkpoint_log_bytes: 0,
            pipelined_barrier: false,
            defer_log_writeback: false,
            no_log: false,
            read_only: false,
            io: IoMode::Buffered,
            prefetch_bytes: 1 << 20,
            scan_readahead_pages: 4,
            cache_stats: false,
            #[cfg(any(test, feature = "lab"))]
            allow_non_nvme: false,
        }
    }
    pub fn path(&self, sb: &Superblock, shard: u32) -> Result<PathBuf> {
        if !self.root.is_absolute() {
            return Err(StoreError::Invalid("SplinterDB root must be absolute"));
        }
        Ok(self
            .directory(&sb.osd_fsid)
            .join(format!("shard-{shard}.db")))
    }
    pub fn directory(&self, fsid: &[u8; 16]) -> PathBuf {
        let id: String = fsid.iter().map(|b| format!("{b:02x}")).collect();
        self.root.join(id)
    }
    pub fn validate_create(&self, cache: usize) -> Result<()> {
        self.admit()?;
        self.options(cache)?;
        if self.capacity < 128 << 20
            || !self.capacity.is_multiple_of(128 << 10)
            || self.capacity > i64::MAX as u64
            || cache < 64 << 20
            || !(cache as u64).is_multiple_of(256 << 10)
            || self.capacity / 1024 > cache as u64
        {
            return Err(StoreError::Invalid(
                "SplinterDB requires per-shard capacity >=128MiB (128KiB aligned), cache >=64MiB (256KiB aligned) and capacity <=1024*cache",
            ));
        }
        Ok(())
    }
    fn options(&self, cache: usize) -> Result<splinterdb_lib::Options> {
        if self.normal_maintenance && !self.isolate_cleaner {
            return Err(StoreError::Invalid(
                "SplinterDB normal maintenance requires explicit cleaner isolation",
            ));
        }
        let normal_maintenance = self.normal_maintenance
            && self
                .cpu
                .zip(self.cleaner_cpu)
                .is_some_and(|(worker, helper)| worker != helper);
        if normal_maintenance && self.cache_stats {
            return Err(StoreError::Invalid(
                "SplinterDB normal maintenance requires cache statistics disabled",
            ));
        }
        if self.memtable_maintenance && !self.normal_maintenance {
            return Err(StoreError::Invalid(
                "SplinterDB memtable maintenance requires normal maintenance",
            ));
        }
        if !(1..=MAX_APPLY_THREADS).contains(&self.apply_threads) {
            return Err(StoreError::Invalid(
                "SplinterDB apply threads must be in 1..=4",
            ));
        }
        // Capacity is known only at creation; reopen keeps the absolute bound.
        let ckpt = self.checkpoint_log_bytes;
        if ckpt != 0
            && (!(64 << 20..=4 << 30).contains(&ckpt)
                || (self.capacity != 0 && ckpt > self.capacity / 4))
        {
            return Err(StoreError::Invalid(
                "SplinterDB checkpoint log bytes must be 0 (default) or 64MiB..=4GiB and <=capacity/4",
            ));
        }
        if !(1..=16).contains(&self.scan_readahead_pages) {
            return Err(StoreError::Invalid(
                "SplinterDB scan read-ahead pages must be in 1..=16",
            ));
        }
        if self.prefetch_bytes < 128 << 10 || self.prefetch_bytes > cache as u64 / 4 {
            return Err(StoreError::Invalid(
                "SplinterDB prefetch bytes must be >=128KiB and <=one quarter of its cache; zero does not disable upstream prefetch",
            ));
        }
        Ok(splinterdb_lib::Options {
            io: self.io,
            prefetch_bytes: self.prefetch_bytes,
            cache_stats: self.cache_stats,
            normal_maintenance,
            memtable_maintenance: normal_maintenance && self.memtable_maintenance,
            checkpoint_log_bytes: self.checkpoint_log_bytes,
            defer_log_writeback: self.defer_log_writeback,
            no_log: false,
        })
    }
    /// Extra apply helpers that will actually run: none without a resolved placement.
    fn apply_helpers(&self) -> usize {
        if self.cpu.is_some() && self.apply_cpus.len() > 1 {
            self.apply_threads.saturating_sub(1)
        } else {
            0
        }
    }
    /// Cold preflight, before native discard/format. Files are independently sized
    /// per shard; do not provision their virtual capacities against nonexistent
    /// filesystem space or consume the worker/recovery reserve.
    pub fn validate_provision(&self, shards: u32, cache: usize) -> Result<()> {
        if shards > crate::layout::MAX_SPLINTERDB_SHARDS {
            return Err(StoreError::Invalid(
                "SplinterDB supports at most 63 native shards per process",
            ));
        }
        self.validate_create(cache)?;
        if shards == 0 {
            return Err(StoreError::Invalid(
                "SplinterDB requires at least one shard",
            ));
        }
        let need = self
            .capacity
            .checked_add((cache as u64).saturating_mul(8))
            .and_then(|n| n.checked_mul(u64::from(shards)))
            .ok_or(StoreError::NoSpace)?;
        let space = Space::join(&self.root)?;
        space.refresh(&self.root)?;
        if need > space.available() {
            return Err(StoreError::NoSpace);
        }
        Ok(())
    }
    pub fn admit(&self) -> Result<()> {
        if self.read_only {
            return Err(StoreError::Invalid(
                "SplinterDB public open is mutating; read-only access is unsupported",
            ));
        }
        if !self.root.is_absolute() || std::fs::canonicalize(&self.root).map_err(err)? != self.root
        {
            return Err(StoreError::Invalid(
                "SplinterDB root must exist and be canonical",
            ));
        }
        #[cfg(any(test, feature = "lab"))]
        if self.allow_non_nvme {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
            let name = std::ffi::CString::new(self.root.as_os_str().as_bytes()).map_err(err)?;
            let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
            // SAFETY: initialized bounded output and live C path.
            if unsafe { libc::statfs(name.as_ptr(), &mut fs) } != 0 {
                return Err(err(std::io::Error::last_os_error()));
            }
            if !matches!(fs.f_type as u64, 0xef53 | 0x58465342) {
                return Err(StoreError::Invalid(
                    "SplinterDB requires local ext4/XFS on admitted PLP NVMe",
                ));
            }
            let dev = std::fs::metadata(&self.root).map_err(err)?.dev();
            let sys = std::fs::canonicalize(format!(
                "/sys/dev/block/{}:{}",
                libc::major(dev),
                libc::minor(dev)
            ))
            .map_err(err)?;
            // No silent admission of arbitrary stacked storage. Mounted linear-LVM
            // validation needs a separate read-only admission contract.
            if sys.join("dm").exists() {
                return Err(StoreError::Invalid(
                    "SplinterDB filesystem admission currently requires direct kernel NVMe",
                ));
            }
            let ns = if sys.join("partition").exists() {
                sys.parent().ok_or_else(|| err("partition parent"))?
            } else {
                &sys
            };
            if !ns.join("nsid").is_file() {
                return Err(StoreError::Invalid(
                    "SplinterDB filesystem is not on direct NVMe",
                ));
            }
            let node = Path::new("/dev").join(ns.file_name().ok_or_else(|| err("NVMe namespace"))?);
            let ctrl = nvme::kprobe::KernelProbe(node)
                .identify_ctrl_raw()
                .map_err(err)?;
            if ctrl.get(525).is_none_or(|v| v & 1 != 0) {
                return Err(StoreError::VolatileCache);
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        Err(StoreError::Invalid("SplinterDB requires Linux"))
    }
    fn validate_file(&self, file: &Path) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let root = std::fs::metadata(&self.root).map_err(err)?;
        let dir = file.parent().ok_or_else(|| err("database parent"))?;
        let m = std::fs::symlink_metadata(dir).map_err(err)?;
        if !m.is_dir() || m.dev() != root.dev() || std::fs::canonicalize(dir).map_err(err)? != dir {
            return Err(StoreError::Invalid(
                "SplinterDB directory escapes the admitted filesystem",
            ));
        }
        if let Ok(m) = std::fs::symlink_metadata(file)
            && (!m.is_file()
                || m.file_type().is_symlink()
                || m.dev() != root.dev()
                || m.nlink() != 1)
        {
            return Err(StoreError::Invalid(
                "SplinterDB image must be a regular file on its admitted filesystem",
            ));
        }
        Ok(())
    }
}

/// Fresh provisioning only; never called by mount to heal missing files.
pub fn create(cfg: &Config, sb: &Superblock, cache: usize) -> Result<()> {
    cfg.validate_provision(sb.shards, cache)?;
    let first = cfg.path(sb, 0)?;
    let dir = first.parent().expect("bound image directory");
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .map_err(err)?;
    std::fs::File::open(&cfg.root)
        .and_then(|f| f.sync_all())
        .map_err(err)?;
    for shard in 0..sb.shards {
        let path = cfg.path(sb, shard)?;
        cfg.validate_file(&path)?;
        if cfg.no_log {
            // The mode marker is durable before the image exists: an image is never
            // reopened in a mode other than the one it was written in.
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path.with_extension("nolog"))
                .and_then(|f| f.sync_all())
                .map_err(err)?;
            std::fs::File::open(dir)
                .and_then(|f| f.sync_all())
                .map_err(err)?;
        }
        let mut options = cfg.options(cache)?;
        options.no_log = cfg.no_log;
        let mut db = splinterdb_lib::Database::open_with_options(
            &path,
            cache as u64,
            cfg.capacity,
            true,
            options,
        )
        .map_err(err)?;
        db.put(IDENTITY, &identity(sb, shard)).map_err(err)?;
        db.put(WATERMARK, &0u64.to_le_bytes()).map_err(err)?;
        db.durable_barrier().map_err(err)?;
        db.close().map_err(err)?;
        std::fs::File::open(&path)
            .and_then(|f| f.sync_all())
            .map_err(err)?;
        let bound = binding(&path, &identity(sb, shard))?;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path.with_extension("identity"))
            .map_err(err)?;
        f.write_all(&bound)
            .and_then(|_| f.sync_all())
            .map_err(err)?;
        let lock = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path.with_extension("lock"))
            .map_err(err)?;
        lock.sync_all().map_err(err)?;
    }
    std::fs::File::open(dir)
        .and_then(|f| f.sync_all())
        .map_err(err)
}

/// Whether the image at `path` was created without the library log (its marker).
fn no_log_image(path: &Path) -> Result<bool> {
    path.with_extension("nolog").try_exists().map_err(err)
}

fn binding(path: &Path, id: &[u8]) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).map_err(err)?;
    if !m.is_file() || m.file_type().is_symlink() || m.nlink() != 1 {
        return Err(err("invalid bound image"));
    }
    let mut b = id.to_vec();
    b.extend_from_slice(&m.ino().to_le_bytes());
    Ok(b)
}
/// Validate before any mutating foreign open. The private directory and inode
/// binding intentionally forbid implicit image replacement/copy migration.
pub fn validate_binding(cfg: &Config, sb: &Superblock, shard: u32) -> Result<()> {
    cfg.admit()?;
    let path = cfg.path(sb, shard)?;
    cfg.validate_file(&path)?;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.with_extension("identity"))
        .map_err(err)?;
    let mut stored = Vec::new();
    f.by_ref().take(257).read_to_end(&mut stored).map_err(err)?;
    if stored != binding(&path, &identity(sb, shard))? {
        return Err(err("pre-open identity/inode binding mismatch"));
    }
    Ok(())
}

/// Filesystem sample shared by all shards using one physical filesystem.
#[derive(Debug, Default)]
pub(crate) struct Space {
    free: AtomicU64,
    total: AtomicU64,
    reserved: AtomicU64,
}
impl Space {
    fn reserve(self: &Arc<Self>, bytes: u64) -> Result<Lease> {
        let mut old = self.reserved.load(Ordering::Acquire);
        loop {
            let next = old.checked_add(bytes).ok_or(StoreError::NoSpace)?;
            if next > self.free.load(Ordering::Acquire) {
                return Err(StoreError::NoSpace);
            }
            match self.reserved.compare_exchange_weak(
                old,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Lease {
                        space: self.clone(),
                        bytes,
                    });
                }
                Err(v) => old = v,
            }
        }
    }
    fn join(root: &Path) -> Result<Arc<Self>> {
        use std::os::unix::fs::MetadataExt;
        static POOL: OnceLock<Mutex<HashMap<u64, Weak<Space>>>> = OnceLock::new();
        let dev = std::fs::metadata(root).map_err(err)?.dev();
        let mut pool = POOL.get_or_init(Default::default).lock().map_err(err)?;
        if let Some(s) = pool.get(&dev).and_then(Weak::upgrade) {
            return Ok(s);
        }
        let s = Arc::new(Self::default());
        s.refresh(root)?;
        pool.insert(dev, Arc::downgrade(&s));
        Ok(s)
    }
    fn refresh(&self, root: &Path) -> Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(root.as_os_str().as_bytes()).map_err(err)?;
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: initialized output, live path; runs only on a worker/cold startup.
        if unsafe { libc::statvfs(path.as_ptr(), &mut s) } != 0 {
            return Err(err(std::io::Error::last_os_error()));
        }
        self.free
            .store(s.f_bavail.saturating_mul(s.f_frsize), Ordering::Release);
        self.total
            .store(s.f_blocks.saturating_mul(s.f_frsize), Ordering::Release);
        Ok(())
    }
    pub fn sample(&self) -> (u64, u64) {
        (self.available(), self.total.load(Ordering::Acquire))
    }
    pub fn available(&self) -> u64 {
        self.free
            .load(Ordering::Acquire)
            .saturating_sub(self.reserved.load(Ordering::Acquire))
    }
}
#[derive(Debug)]
pub(crate) struct Lease {
    space: Arc<Space>,
    bytes: u64,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.space.reserved.fetch_sub(self.bytes, Ordering::AcqRel);
    }
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
        versions: [(u64, u64); 3],
        session: Option<(u64, u64)>,
        keys_only: bool,
        demand: usize,
    },
    Ids {
        after: Option<u64>,
    },
}
impl Query {
    fn demand(&self) -> usize {
        match self {
            Self::Page { demand, .. } => (*demand).clamp(1, MAX_SCAN_ROWS),
            _ => PAGE,
        }
    }
    fn touches(&self, ids: &[u64]) -> bool {
        match self {
            Self::Keys { id, .. } | Self::Page { id, .. } => ids.binary_search(id).is_ok(),
            Self::Ids { .. } => true,
        }
    }
    fn bytes(&self) -> usize {
        192 + match self {
            Self::Keys { keys, .. } => keys.iter().map(|k| k.len() + 32).sum(),
            Self::Page { from, prefix, .. } => from.len() + prefix.len(),
            Self::Ids { .. } => 0,
        }
    }
}
#[derive(Debug)]
pub(crate) enum Answer {
    Entries(Vec<(Bytes, Bytes)>, bool),
    Ids(Vec<u64>, bool),
}
impl Answer {
    fn bytes(&self) -> usize {
        match self {
            Self::Entries(v, _) => v.iter().map(|(k, v)| k.len() + v.len() + 64).sum(),
            Self::Ids(v, _) => v.len() * 8,
        }
    }
}

struct Database {
    db: splinterdb_lib::Database,
    watermark: u64,
    // Declared after db: teardown closes the foreign handle before releasing debt.
    debt: Vec<Arc<Lease>>,
    seeks: std::cell::Cell<u64>,
    spec_errors: std::cell::Cell<u64>,
    /// Points per claimed parallel-apply chunk (`APPLY_CHUNK`; tests use smaller).
    apply_chunk: usize,
    /// The image runs without the library log (`shard-N.nolog`): barriers checkpoint.
    checkpointed: bool,
    #[cfg(test)]
    fail_row: std::cell::Cell<Option<usize>>,
    #[cfg(test)]
    fail_barrier: Option<u8>,
}
impl Database {
    fn open_with_options(
        path: &Path,
        id: &[u8],
        mem: usize,
        mut options: splinterdb_lib::Options,
    ) -> Result<Self> {
        // The log mode is a property of the image, fixed at creation: a logged image
        // opened without its log would lose its logged, not yet checkpointed updates.
        options.no_log = no_log_image(path)?;
        let db = splinterdb_lib::Database::open_with_options(path, mem as u64, 0, false, options)
            .map_err(err)?;
        if db.get(IDENTITY, 256).map_err(err)?.as_deref() != Some(id) {
            return Err(err("database/native identity mismatch"));
        }
        let mark = db
            .get(WATERMARK, 8)
            .map_err(err)?
            .ok_or_else(|| err("missing watermark"))?;
        let watermark = u64::from_le_bytes(
            mark.as_slice()
                .try_into()
                .map_err(|_| err("invalid watermark"))?,
        );
        Ok(Self {
            db,
            watermark,
            debt: Vec::new(),
            seeks: std::cell::Cell::new(0),
            spec_errors: std::cell::Cell::new(0),
            apply_chunk: APPLY_CHUNK,
            checkpointed: options.no_log,
            #[cfg(test)]
            fail_row: std::cell::Cell::new(None),
            #[cfg(test)]
            fail_barrier: None,
        })
    }
    fn cursor<'a>(
        &'a self,
        from: &[u8],
        excl: bool,
        end: Option<&[u8]>,
    ) -> Result<splinterdb_lib::Cursor<'a>> {
        self.seeks.set(self.seeks.get().saturating_add(1));
        self.db.cursor(from, excl, end).map_err(err)
    }
    fn range_delete(&mut self, id: u64, first: &[u8], end: Option<&[u8]>) -> Result<()> {
        let upper = end.map_or_else(|| object_end(id), |e| key(id, e));
        let mut from = key(id, first);
        let mut exclusive = false;
        loop {
            let page = {
                let mut it = self
                    .db
                    .cursor(&from, exclusive, Some(&upper))
                    .map_err(err)?;
                let mut keys = Vec::new();
                while keys.len() < PAGE {
                    let Some((k, _)) = it.current().map_err(err)? else {
                        break;
                    };
                    keys.push(k.to_vec());
                    it.advance().map_err(err)?;
                }
                keys // iterator is destroyed BEFORE any mutation on this thread
            };
            if page.is_empty() {
                return Ok(());
            }
            from = page.last().expect("nonempty page").clone();
            exclusive = true;
            for k in page {
                self.db.delete(&k).map_err(err)?;
            }
        }
    }
    #[cfg(test)]
    fn flush(&mut self, m: &Memtable) -> Result<u64> {
        self.flush_timed(m, &timing::Timings::default())
    }
    /// The original single-thread apply: per object, its ranges then its points.
    fn apply_serial(&mut self, m: &Memtable) -> Result<()> {
        // Foreign mutations borrow their key only for the synchronous call. Reuse
        // one bounded scratch buffer rather than allocating for every point.
        let mut raw = Vec::new();
        for id in m.sorted_ids() {
            let o = m.obj(id).expect("enumerated object");
            for r in &o.ranges {
                self.range_delete(id, &r.first, r.end.as_deref())?;
            }
            raw.clear();
            raw.push(1);
            raw.extend_from_slice(&id.to_be_bytes());
            for (k, v) in &o.map {
                raw.truncate(9);
                raw.extend_from_slice(&k.key);
                match v {
                    Some(v) => self.db.put(&raw, v),
                    None => self.db.delete(&raw),
                }
                .map_err(err)?;
            }
        }
        Ok(())
    }
    /// Every object's range deletions first, on this thread (a range touches only its
    /// object's keys, and each object's ranges still precede its points). Then the
    /// sorted points, each key exactly once per flush, as a shared queue of contiguous
    /// chunks claimed by this thread and the helpers. Always waits for every helper
    /// that took the round, so none mutates after return; the first error fails the
    /// whole flush.
    fn apply_parallel(&mut self, m: &Arc<Memtable>, pool: &ApplyPool) -> Result<()> {
        let ids = m.sorted_ids();
        for &id in &ids {
            let o = m.obj(id).expect("enumerated object");
            for r in &o.ranges {
                self.range_delete(id, &r.first, r.end.as_deref())?;
            }
        }
        let round = Arc::new(ApplyRound::new(m.clone(), &ids, self.apply_chunk));
        // One helper per two chunks beyond the first keeps tiny flushes local.
        let wanted = (round.chunks.len() / 2).min(pool.helpers());
        let dispatched = pool.dispatch(&round, wanted);
        let db = &mut self.db;
        let own = round.drain(|k, v| match v {
            Some(v) => db.put(k, v),
            None => db.delete(k),
        });
        let others = pool.collect(dispatched);
        own.map(drop).and(others)
    }
    #[cfg(test)]
    fn flush_timed(&mut self, m: &Memtable, timings: &timing::Timings) -> Result<u64> {
        self.flush_with(m, timings, None)
    }
    /// One overlay flush. `parallel` (shared memtable + helper pool) splits the
    /// points across threads; every point is applied before the data barrier.
    fn flush_with(
        &mut self,
        m: &Memtable,
        timings: &timing::Timings,
        parallel: Option<(&Arc<Memtable>, &ApplyPool)>,
    ) -> Result<u64> {
        let lsn = self.apply_with(m, timings, parallel)?;
        #[cfg(test)]
        let fail = self.fail_barrier;
        #[cfg(not(test))]
        let fail = None;
        let checkpointed = self.checkpointed;
        let db = &mut self.db;
        durable_steps(lsn, timings, fail, checkpointed, |step| match step {
            DurableStep::Barrier => db.durable_barrier(),
            DurableStep::Put(k, v) => db.put(k, v),
        })?;
        self.watermark = lsn;
        Ok(lsn)
    }
    /// Applies one overlay flush without its durability step; returns its LSN.
    fn apply_with(
        &mut self,
        m: &Memtable,
        timings: &timing::Timings,
        parallel: Option<(&Arc<Memtable>, &ApplyPool)>,
    ) -> Result<u64> {
        let lsn = m.lsn_hi();
        let apply = timings.start(timing::APPLY);
        match parallel.filter(|(_, pool)| pool.helpers() > 0) {
            Some((shared, pool)) => self.apply_parallel(shared, pool)?,
            None => self.apply_serial(m)?,
        }
        drop(apply);
        Ok(lsn)
    }
    fn read(&self, q: &Query, view: &View, limit: usize) -> Result<Answer> {
        self.read_batch(q, view, limit, q.demand(), || false)
    }
    fn read_batch(
        &self,
        q: &Query,
        view: &View,
        limit: usize,
        rows: usize,
        mut pressure: impl FnMut() -> bool,
    ) -> Result<Answer> {
        let demand = q.demand();
        let rows = rows.max(demand).min(MAX_SCAN_ROWS);
        match q {
            Query::Keys { id, keys } => {
                let mut out = Vec::with_capacity(keys.len());
                let mut lookup = self.db.lookup().map_err(err)?;
                let mut raw = key(*id, b"");
                for k in keys {
                    raw.truncate(9);
                    raw.extend_from_slice(k);
                    let value = lookup.get(&raw, usize::MAX).map_err(err)?;
                    if let Some(v) = value {
                        out.push((k.clone(), Bytes::from(v)));
                    }
                }
                Ok(Answer::Entries(out, false))
            }
            Query::Page {
                id,
                from,
                excl,
                prefix,
                keys_only,
                ..
            } => {
                use std::ops::Bound;
                let mut cursor = from.clone().max(prefix.clone());
                let mut exclusive = *excl && cursor == *from;
                let start = cursor.clone();
                let bound = if exclusive {
                    Bound::Excluded(&start[..])
                } else {
                    Bound::Included(&start[..])
                };
                let mut points = view.each_ref().map(|o| {
                    o.as_ref()
                        .map(|o| o.map.range::<[u8], _>((bound, Bound::Unbounded)).peekable())
                });
                let upper = prefix_end(*id, prefix);
                let lower = key(*id, &cursor);
                let mut it = if lower < upper {
                    Some(self.cursor(&lower, exclusive, Some(&upper))?)
                } else {
                    None
                };
                let mut out = Vec::new();
                let mut bytes = 0usize;
                let mut speculative_value_bytes = 0usize;
                let mut inspected = 0usize;
                // Wide demand may yield after positive progress; never yield an empty
                // uncertain page. Bound optional inspected work after demand completes.
                macro_rules! checkpoint {
                    () => {
                        if out.len() >= PAGE && out.len() < demand && pressure() {
                            return Ok(Answer::Entries(out, true));
                        }
                        if rows > demand && out.len() >= demand {
                            if pressure() || inspected >= rows.saturating_sub(demand) {
                                return Ok(Answer::Entries(out, true));
                            }
                            inspected += 1;
                        }
                    };
                }
                macro_rules! scan_step {
                    ($op:expr) => {
                        match $op {
                            Ok(v) => v,
                            Err(_) if rows > demand && out.len() >= demand => {
                                // Optional future work cannot invalidate a completed
                                // demand page. Never turn its error into a false EOF.
                                self.spec_errors
                                    .set(self.spec_errors.get().saturating_add(1));
                                out.truncate(demand);
                                return Ok(Answer::Entries(out, true));
                            }
                            Err(e) => return Err(e),
                        }
                    };
                }
                loop {
                    checkpoint!();
                    #[cfg(test)]
                    let injected = self.fail_row.get() == Some(out.len());
                    #[cfg(not(test))]
                    let injected = false;
                    let row = if injected {
                        Err(StoreError::Io(nvme::IoError::Aborted))
                    } else {
                        match it.as_mut() {
                            Some(it) => it.current().map_err(err),
                            None => Ok(None),
                        }
                    };
                    let base = scan_step!(row);
                    if let Some((raw, _)) = base {
                        if raw.len() < 9 || raw[0] != 1 {
                            return Err(err("malformed object key"));
                        }
                        if let Some(r) = view
                            .iter()
                            .flatten()
                            .find_map(|o| crate::olsm::ranges_find(&o.ranges, *id, &raw[9..]))
                        {
                            let end = r
                                .end
                                .as_ref()
                                .map_or_else(|| upper.clone(), |k| key(*id, k));
                            drop(it.take());
                            it = if end < upper {
                                Some(scan_step!(self.cursor(&end, false, Some(&upper))))
                            } else {
                                None
                            };
                            continue;
                        }
                    }
                    let base_key = base.and_then(|(raw, _)| {
                        let k = &raw[9..];
                        (k.starts_with(prefix)
                            && (k > &cursor[..] || (!exclusive && k == &cursor[..])))
                            .then(|| Bytes::copy_from_slice(k))
                    });
                    if base.is_some_and(|(raw, _)| exclusive && raw[9..] <= cursor[..]) {
                        scan_step!(it.as_mut().unwrap().advance().map_err(err));
                        continue;
                    }
                    let mut candidate = base_key.clone();
                    for p in points.iter_mut().flatten() {
                        while p.peek().is_some_and(|(_, v)| v.is_none()) {
                            checkpoint!();
                            p.next();
                        }
                        if let Some((k, _)) = p.peek()
                            && k.key.starts_with(prefix)
                            && candidate.as_ref().is_none_or(|old| k.key < *old)
                        {
                            candidate = Some(k.key.clone());
                        }
                    }
                    let Some(k) = candidate else {
                        return Ok(Answer::Entries(out, false));
                    };
                    let mut answer = Probe::Pass;
                    for o in view.iter().flatten() {
                        if let Some(v) = o.map.get(&k[..]) {
                            answer = Probe::Hit(v.clone());
                            break;
                        }
                        if crate::olsm::ranges_find(&o.ranges, *id, &k).is_some() {
                            answer = Probe::Covered;
                            break;
                        }
                    }
                    let value = match &answer {
                        Probe::Hit(v) => v.as_deref(),
                        Probe::Covered => None,
                        Probe::Pass => base
                            .filter(|_| base_key.as_ref() == Some(&k))
                            .map(|(_, v)| v),
                    };
                    if let Some(v) = value {
                        let materialized = k.len().saturating_add(v.len()).saturating_add(64);
                        if out.len() >= demand
                            && speculative_value_bytes.saturating_add(materialized) > limit
                        {
                            return Ok(Answer::Entries(out, true));
                        }
                        let cost = k
                            .len()
                            .saturating_add(if *keys_only { 0 } else { v.len() })
                            .saturating_add(64);
                        if out.len() == rows
                            || (!out.is_empty() && bytes.saturating_add(cost) > limit)
                        {
                            return Ok(Answer::Entries(out, true));
                        }
                        let v = if *keys_only {
                            Bytes::new()
                        } else {
                            match &answer {
                                Probe::Hit(Some(v)) => v.clone(),
                                _ => Bytes::copy_from_slice(v),
                            }
                        };
                        bytes = bytes.saturating_add(cost);
                        if out.len() >= demand {
                            speculative_value_bytes =
                                speculative_value_bytes.saturating_add(materialized);
                        }
                        out.push((k.clone(), v));
                    }
                    cursor = k.clone();
                    exclusive = true;
                    for p in points.iter_mut().flatten() {
                        if p.peek().is_some_and(|(pk, _)| pk.key == k) {
                            p.next();
                        }
                    }
                    if base_key.as_ref() == Some(&k) {
                        scan_step!(it.as_mut().unwrap().advance().map_err(err));
                    }
                }
            }
            Query::Ids { after } => {
                let mut from = after.map_or_else(|| vec![1], object_end);
                let mut ids = Vec::new();
                loop {
                    let id = {
                        let mut it = self.db.cursor(&from, false, Some(&[2])).map_err(err)?;
                        let Some((k, _)) = it.current().map_err(err)? else {
                            return Ok(Answer::Ids(ids, false));
                        };
                        if k.len() < 9 || k[0] != 1 {
                            return Err(err("malformed inventory key"));
                        }
                        u64::from_be_bytes(k[1..9].try_into().unwrap())
                    };
                    if ids.len() == PAGE {
                        return Ok(Answer::Ids(ids, true));
                    }
                    ids.push(id);
                    if id == u64::MAX {
                        return Ok(Answer::Ids(ids, false));
                    }
                    from = object_end(id);
                }
            }
        }
    }
}

#[derive(Debug)]
enum Request {
    Flush(Arc<Memtable>, Vec<Arc<Lease>>, Instant),
    Read(Query, View, ReadAllowance, Option<(u64, u64)>, Instant),
}
#[derive(Debug)]
struct ReadAllowance {
    bytes: usize,
    rows: usize,
    epoch: u64,
}
impl ReadAllowance {
    fn retired(&self, epoch: &AtomicU64) -> bool {
        epoch.load(Ordering::Acquire) != self.epoch
    }
    fn should_yield(&self, hints: &WorkerHints, queued: bool) -> bool {
        self.retired(&hints.epoch)
            || hints.stop.load(Ordering::Acquire)
            || hints.pressure.load(Ordering::Acquire)
            || queued
    }
}
/// Owner wake installed after mount (the driver's core wake handle, as for the
/// RocksDB worker): called by the worker after every published completion so an
/// owner sleeping in its idle wait sees it without waiting out its sleep cap.
/// Cheap when the owner is awake; callable from any thread.
#[derive(Clone)]
pub struct OwnerWake(pub Arc<dyn Fn() + Send + Sync>);
impl std::fmt::Debug for OwnerWake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnerWake")
    }
}
/// Set once by the owner, read by the worker after each publication.
type WakeSlot = Arc<std::sync::OnceLock<OwnerWake>>;
/// Publish-then-wake: the completion is already pushed, so the owner's
/// post-announcement re-check ([`Client::has_completion`]) or this wake sees it.
#[inline]
fn notify_owner(wake: &WakeSlot) {
    if let Some(w) = wake.get() {
        (w.0)();
    }
}
struct WorkerHints {
    stop: Arc<AtomicBool>,
    pressure: Arc<AtomicBool>,
    epoch: Arc<AtomicU64>,
    wake: WakeSlot,
}
#[derive(Debug)]
enum Completion {
    /// Applied and durable (watermark barrier done); pipelined flushes carry no ids.
    Flushed(u64, Vec<u64>),
    /// Pipelined only: applied and visible, durability pending on its thread.
    Applied(u64, Vec<u64>),
    Read(Query, Arc<Answer>, Option<(u64, u64)>),
    Failed(StoreError),
}
#[derive(Debug, Default)]
struct Metrics {
    timings: timing::Timings,
    db_used: AtomicU64,
    db_capacity: AtomicU64,
    pages: AtomicU64,
    points: AtomicU64,
    flushes: AtomicU64,
    seeks: AtomicU64,
    spec_errors: AtomicU64,
    engine: [AtomicU64; 9],
    sample_valid: AtomicBool,
    sample_errors: AtomicU64,
    sample_origin: OnceLock<Instant>,
    sample_ns: AtomicU64,
    normal_workers: AtomicU64,
    maintenance_busy: AtomicBool,
    maintenance_stack: AtomicU64,
}
fn pin(cpu: Option<usize>) -> Result<()> {
    if let Some(cpu) = cpu {
        if cpu >= libc::CPU_SETSIZE as usize {
            return Err(StoreError::Invalid("SplinterDB CPU exceeds CPU_SETSIZE"));
        }
        let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        // SAFETY: bounded CPU and initialized mask; selects only this worker.
        if unsafe {
            libc::CPU_SET(cpu, &mut mask);
            libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &mask)
        } != 0
        {
            return Err(err(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Cold startup sequencing. The caller already validated/pinned the worker CPU.
/// Static closures make failure/drop ordering independently testable; no dispatch
/// or extra state is added to request handling.
fn open_with_cleaner<T>(
    cpus: (Option<usize>, Option<usize>),
    mut pin_cpu: impl FnMut(Option<usize>) -> Result<()>,
    open: impl FnOnce() -> Result<T>,
    prime: impl FnOnce(&mut T) -> Result<()>,
) -> Result<T> {
    let (worker, cleaner) = cpus;
    let cleaner = cleaner.filter(|c| worker.is_some() && Some(*c) != worker);
    if cleaner.is_some() {
        pin_cpu(cleaner)?;
    }
    let mut db = open()?;
    if cleaner.is_some() {
        prime(&mut db)?;
        pin_cpu(worker)?;
    }
    Ok(db)
}
/// One step of a flush's durability sequence, run by one registered thread.
enum DurableStep<'a> {
    Barrier,
    Put(&'a [u8], &'a [u8]),
}
/// Data barrier, then the watermark, then its barrier. Unlike an atomic batch, every
/// earlier mutation may survive separately: native redo stays pinned and the
/// watermark is only written AFTER the data barrier. `fail` injects a barrier
/// failure in tests (1 = data, 2 = watermark barrier).
fn durable_steps(
    lsn: u64,
    timings: &timing::Timings,
    fail: Option<u8>,
    checkpointed: bool,
    mut op: impl FnMut(DurableStep<'_>) -> std::io::Result<()>,
) -> Result<()> {
    if checkpointed {
        // Without the library log a barrier checkpoints the tree: every update that
        // returned before it is in that one atomic checkpoint. The watermark put
        // follows all of the flush's updates, so one checkpoint covers both and a
        // crash recovers either the previous checkpoint or data plus watermark.
        if fail == Some(1) {
            return Err(StoreError::Io(nvme::IoError::Aborted));
        }
        let watermark = timings.start(timing::WATERMARK);
        let mark = lsn.to_le_bytes();
        op(DurableStep::Put(WATERMARK, &mark)).map_err(err)?;
        drop(watermark);
        let barrier = timings.start(timing::DATA_BARRIER);
        if fail == Some(2) {
            return Err(StoreError::Io(nvme::IoError::Aborted));
        }
        op(DurableStep::Barrier).map_err(err)?;
        drop(barrier);
        return Ok(());
    }
    let barrier = timings.start(timing::DATA_BARRIER);
    if fail == Some(1) {
        return Err(StoreError::Io(nvme::IoError::Aborted));
    }
    op(DurableStep::Barrier).map_err(err)?;
    drop(barrier);
    let watermark = timings.start(timing::WATERMARK);
    let mark = lsn.to_le_bytes();
    op(DurableStep::Put(WATERMARK, &mark)).map_err(err)?;
    drop(watermark);
    let barrier = timings.start(timing::WATERMARK_BARRIER);
    if fail == Some(2) {
        return Err(StoreError::Io(nvme::IoError::Aborted));
    }
    op(DurableStep::Barrier).map_err(err)?;
    drop(barrier);
    Ok(())
}
/// A contiguous run of one object's points: `len` points from `first` in map order.
#[derive(Debug)]
struct Chunk {
    id: u64,
    first: MKey,
    len: usize,
}
/// Splits a flush's points (objects in id order, keys in map order) into chunks of
/// at most `size` points; one walk over the keys, boundaries keep their key.
fn plan_chunks(m: &Memtable, ids: &[u64], size: usize) -> Vec<Chunk> {
    let size = size.max(1);
    let mut out = Vec::new();
    for &id in ids {
        let o = m.obj(id).expect("enumerated object");
        let n = o.map.len();
        for (i, k) in o.map.keys().step_by(size).enumerate() {
            out.push(Chunk {
                id,
                first: k.clone(),
                len: size.min(n - i * size),
            });
        }
    }
    out
}
/// Applies one chunk through `apply(raw_key, value_or_tombstone)`; `raw` is scratch.
fn apply_chunk(
    m: &Memtable,
    c: &Chunk,
    raw: &mut Vec<u8>,
    apply: &mut impl FnMut(&[u8], Option<&[u8]>) -> std::io::Result<()>,
) -> Result<()> {
    let o = m.obj(c.id).expect("planned object");
    raw.clear();
    raw.push(1);
    raw.extend_from_slice(&c.id.to_be_bytes());
    for (k, v) in o.map.range::<MKey, _>(&c.first..).take(c.len) {
        raw.truncate(9);
        raw.extend_from_slice(&k.key);
        apply(raw, v.as_deref()).map_err(err)?;
    }
    Ok(())
}
/// One materialization's points as a shared chunk queue: the worker and every
/// helper claim chunks until none is left, so a stalled thread delays only its
/// current chunk. The first error stops further claims; every claimed chunk
/// still finishes before its thread reports.
#[derive(Debug)]
struct ApplyRound {
    mem: Arc<Memtable>,
    chunks: Vec<Chunk>,
    next: AtomicUsize,
    failed: AtomicBool,
}
impl ApplyRound {
    fn new(mem: Arc<Memtable>, ids: &[u64], size: usize) -> Self {
        let chunks = plan_chunks(&mem, ids, size);
        Self {
            mem,
            chunks,
            next: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
        }
    }
    /// Claims and applies chunks; returns how many this caller applied.
    fn drain(
        &self,
        mut apply: impl FnMut(&[u8], Option<&[u8]>) -> std::io::Result<()>,
    ) -> Result<usize> {
        let mut raw = Vec::new();
        let mut done = 0;
        while !self.failed.load(Ordering::Acquire) {
            let i = self.next.fetch_add(1, Ordering::AcqRel);
            let Some(c) = self.chunks.get(i) else {
                break;
            };
            if let Err(e) = apply_chunk(&self.mem, c, &mut raw, &mut apply) {
                self.failed.store(true, Ordering::Release);
                return Err(e);
            }
            done += 1;
        }
        Ok(done)
    }
}

/// One materialization's chunk queue handed to a helper.
type ApplyJob = Arc<ApplyRound>;
#[derive(Debug)]
struct ApplyHelper {
    jobs: Option<std::sync::mpsc::SyncSender<ApplyJob>>,
    done: std::sync::mpsc::Receiver<Result<()>>,
    join: Option<JoinHandle<()>>,
}
/// Registered helper threads applying flush slices for one shard's worker. Started
/// after its database opened, dropped (joined, deregistered) before it closes.
#[derive(Debug, Default)]
struct ApplyPool {
    helpers: Vec<ApplyHelper>,
}
impl ApplyPool {
    fn start(
        db: &splinterdb_lib::Database,
        shard: u32,
        extra: usize,
        cpus: &[usize],
        stack: usize,
    ) -> Result<Self> {
        let mut pool = Self::default();
        for _ in 0..extra {
            let handle = db.shared_handle().map_err(err)?;
            let (jobs, job_rx) = std::sync::mpsc::sync_channel::<ApplyJob>(1);
            let (done_tx, done) = std::sync::mpsc::sync_channel::<Result<()>>(1);
            let (ready_tx, ready) = std::sync::mpsc::sync_channel::<Result<()>>(1);
            let cpus = cpus.to_vec();
            let join = std::thread::Builder::new()
                .name(format!("omap-sapply-{shard}"))
                .stack_size(stack)
                .spawn(move || {
                    let attached = pin_set(&cpus).and_then(|()| {
                        // SAFETY: the pool is dropped (this thread joined) before the
                        // worker closes the database; the worker runs no cursor or
                        // lookup while a dispatched slice is outstanding.
                        unsafe { splinterdb_lib::Mutator::attach(handle) }.map_err(err)
                    });
                    let mut m = match attached {
                        Ok(m) => {
                            let _ = ready_tx.send(Ok(()));
                            m
                        }
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                            return;
                        }
                    };
                    while let Ok(job) = job_rx.recv() {
                        let r = job
                            .drain(|k, v| match v {
                                Some(v) => m.put(k, v),
                                None => m.delete(k),
                            })
                            .map(drop);
                        drop(job);
                        if done_tx.send(r).is_err() {
                            break;
                        }
                    }
                })
                .map_err(err)?;
            pool.helpers.push(ApplyHelper {
                jobs: Some(jobs),
                done,
                join: Some(join),
            });
            match ready.recv_timeout(Duration::from_secs(30)) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => {
                    return Err(err(format!(
                        "WARNING TIMEOUT SplinterDB apply helper start: {e}"
                    )));
                }
            }
        }
        Ok(pool)
    }
    fn helpers(&self) -> usize {
        self.helpers.len()
    }
    /// Hands the round to up to `wanted` helpers; returns how many took it.
    fn dispatch(&self, round: &ApplyJob, wanted: usize) -> usize {
        let mut sent = 0;
        for h in self.helpers.iter().take(wanted) {
            if h.jobs
                .as_ref()
                .is_some_and(|tx| tx.send(round.clone()).is_ok())
            {
                sent += 1;
            } else {
                // A gone helper takes no chunk; the others and the worker drain
                // the whole round, and `collect` only waits for those that took it.
                break;
            }
        }
        sent
    }
    /// Waits for every helper that took the round, then reports the first error
    /// (or a lost helper).
    fn collect(&self, sent: usize) -> Result<()> {
        let mut first = Ok(());
        for h in self.helpers.iter().take(sent) {
            let r = h
                .done
                .recv()
                .unwrap_or_else(|_| Err(err("SplinterDB apply helper exited")));
            if first.is_ok() {
                first = r;
            }
        }
        first
    }
}
impl Drop for ApplyPool {
    fn drop(&mut self) {
        for h in &mut self.helpers {
            h.jobs.take();
        }
        for h in &mut self.helpers {
            if let Some(j) = h.join.take() {
                let _ = j.join();
            }
        }
    }
}

/// Registered thread running the durability sequence (data barrier, watermark,
/// watermark barrier) of applied flushes strictly in LSN order, so the worker can
/// apply the next flush meanwhile (pipelined barrier, opt-in). At most one flush
/// awaits durability; native publication still follows only its `Flushed`.
#[derive(Debug)]
struct Durability {
    jobs: Option<std::sync::mpsc::SyncSender<u64>>,
    done: std::sync::mpsc::Receiver<Result<u64>>,
    join: Option<JoinHandle<()>>,
    outstanding: bool,
}
impl Durability {
    fn start(
        db: &splinterdb_lib::Database,
        shard: u32,
        cpus: &[usize],
        stack: usize,
        metrics: Arc<Metrics>,
        worker: Thread,
        // (injected test failure, image without the library log)
        steps: (Option<u8>, bool),
    ) -> Result<Self> {
        let (fail, checkpointed) = steps;
        let handle = db.shared_handle().map_err(err)?;
        let (jobs, job_rx) = std::sync::mpsc::sync_channel::<u64>(1);
        let (done_tx, done) = std::sync::mpsc::sync_channel::<Result<u64>>(1);
        let (ready_tx, ready) = std::sync::mpsc::sync_channel::<Result<()>>(1);
        let cpus = cpus.to_vec();
        let join =
            std::thread::Builder::new()
                .name(format!("omap-sdur-{shard}"))
                .stack_size(stack)
                .spawn(move || {
                    let attached = pin_set(&cpus).and_then(|()| {
                        // SAFETY: dropped (this thread joined) before the worker closes the
                        // database; it mutates only the watermark key, which no cursor or
                        // lookup of the worker reads after open.
                        unsafe { splinterdb_lib::Mutator::attach(handle) }.map_err(err)
                    });
                    let mut m = match attached {
                        Ok(m) => {
                            let _ = ready_tx.send(Ok(()));
                            m
                        }
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                            return;
                        }
                    };
                    while let Ok(lsn) = job_rx.recv() {
                        let r = durable_steps(lsn, &metrics.timings, fail, checkpointed, |step| {
                            match step {
                                DurableStep::Barrier => m.durable_barrier(),
                                DurableStep::Put(k, v) => m.put(k, v),
                            }
                        })
                        .map(|()| lsn);
                        let failed = r.is_err();
                        if done_tx.send(r).is_err() {
                            break;
                        }
                        worker.unpark();
                        if failed {
                            break;
                        }
                    }
                })
                .map_err(err)?;
        let d = Self {
            jobs: Some(jobs),
            done,
            join: Some(join),
            outstanding: false,
        };
        match ready.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(())) => Ok(d),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(err(format!(
                "WARNING TIMEOUT SplinterDB durability thread start: {e}"
            ))),
        }
    }
    /// Hands over an applied flush; the previous one must have been collected.
    fn submit(&mut self, lsn: u64) -> Result<()> {
        debug_assert!(!self.outstanding, "one flush awaits durability at a time");
        self.jobs
            .as_ref()
            .is_some_and(|tx| tx.send(lsn).is_ok())
            .then_some(())
            .ok_or_else(|| err("SplinterDB durability thread exited"))?;
        self.outstanding = true;
        Ok(())
    }
    /// The outstanding flush's result if it finished (never blocks).
    fn try_finished(&mut self) -> Option<Result<u64>> {
        if !self.outstanding {
            return None;
        }
        let r = match self.done.try_recv() {
            Ok(r) => r,
            Err(std::sync::mpsc::TryRecvError::Empty) => return None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err(err("SplinterDB durability thread exited"))
            }
        };
        self.outstanding = false;
        Some(r)
    }
    /// Waits for the outstanding flush's result, if any.
    fn wait(&mut self) -> Option<Result<u64>> {
        if !std::mem::take(&mut self.outstanding) {
            return None;
        }
        Some(
            self.done
                .recv()
                .unwrap_or_else(|_| Err(err("SplinterDB durability thread exited"))),
        )
    }
}
impl Drop for Durability {
    fn drop(&mut self) {
        self.jobs.take();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}
/// Pins the calling thread to a CPU set; an empty set keeps its affinity.
fn pin_set(cpus: &[usize]) -> Result<()> {
    if cpus.is_empty() {
        return Ok(());
    }
    let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    for &cpu in cpus {
        if cpu >= libc::CPU_SETSIZE as usize {
            return Err(StoreError::Invalid("SplinterDB CPU exceeds CPU_SETSIZE"));
        }
        // SAFETY: bounded CPU on an initialized mask.
        unsafe { libc::CPU_SET(cpu, &mut mask) };
    }
    // SAFETY: initialized mask for this thread only.
    if unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &mask) } != 0 {
        return Err(err(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn maintenance_read_budget(mem: usize, stack: usize) -> Result<usize> {
    (mem / 4)
        .checked_sub(stack)
        .filter(|remaining| *remaining > 0)
        .ok_or(StoreError::Invalid(
            "SplinterDB maintenance stack exceeds read-memory allowance",
        ))
}
fn observe(db: &Database, root: &Path, space: &Space, metrics: &Metrics) -> Result<()> {
    let _sample = metrics.timings.start(timing::SAMPLE);
    let (used, capacity) = db.db.space().map_err(err)?;
    metrics.db_used.store(used, Ordering::Release);
    metrics.db_capacity.store(capacity, Ordering::Release);
    metrics.seeks.store(db.seeks.get(), Ordering::Relaxed);
    metrics
        .spec_errors
        .store(db.spec_errors.get(), Ordering::Relaxed);
    let maintenance = db.db.maintenance_stats().map_err(err)?;
    metrics
        .normal_workers
        .store(maintenance.normal_workers, Ordering::Relaxed);
    metrics
        .maintenance_busy
        .store(maintenance.busy, Ordering::Relaxed);
    match db.db.read_stats() {
        Ok(s) => {
            let v = [
                u64::from(s.valid),
                s.hits,
                s.misses,
                s.engine_read_bytes,
                s.engine_write_bytes,
                s.prefetch_pages,
                u64::from(s.direct),
                s.cache_bytes,
                s.prefetch_bytes,
            ];
            for (slot, value) in metrics.engine.iter().zip(v) {
                slot.store(value, Ordering::Relaxed);
            }
            let origin = metrics.sample_origin.get_or_init(Instant::now);
            metrics.sample_ns.store(
                origin.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
                Ordering::Relaxed,
            );
            metrics.sample_valid.store(true, Ordering::Release);
        }
        Err(_) => {
            metrics.sample_valid.store(false, Ordering::Release);
            metrics.sample_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
    space.refresh(root)
}
/// Publishes one completion (retrying while the ring is full), then wakes the
/// owner. False when the worker is stopping.
fn push_completion(tx: &mut Producer<Completion>, mut c: Completion, hints: &WorkerHints) -> bool {
    loop {
        match tx.push(c) {
            Ok(()) => break,
            Err(rtrb::PushError::Full(v)) => c = v,
        }
        if hints.stop.load(Ordering::Acquire) {
            return false;
        }
        std::thread::park_timeout(Duration::from_millis(1));
    }
    notify_owner(&hints.wake);
    true
}
fn worker(
    opened: (Database, ApplyPool, Option<Durability>),
    mut rx: Consumer<Request>,
    mut tx: Producer<Completion>,
    hints: WorkerHints,
    root: PathBuf,
    space: Arc<Space>,
    metrics: Arc<Metrics>,
) {
    // Bound after `db`, `pool` and `durability` are dropped (helpers joined and
    // deregistered) first.
    let (mut db, pool, mut durability) = opened;
    let stop = &hints.stop;
    let mut sampled = Instant::now();
    while !stop.load(Ordering::Acquire) {
        if sampled.elapsed() >= Duration::from_millis(250) {
            if let Err(e) = observe(&db, &root, &space, &metrics) {
                let _ = push_completion(&mut tx, Completion::Failed(e), &hints);
                return;
            }
            sampled = Instant::now();
        }
        // A pipelined flush became durable: report it in order.
        if let Some(r) = durability.as_mut().and_then(Durability::try_finished) {
            match r {
                Ok(lsn) => {
                    db.watermark = lsn;
                    if !push_completion(&mut tx, Completion::Flushed(lsn, Vec::new()), &hints) {
                        return;
                    }
                }
                Err(e) => {
                    let _ = push_completion(&mut tx, Completion::Failed(e), &hints);
                    return;
                }
            }
        }
        let req = match rx.pop() {
            Ok(r) => r,
            Err(_) => {
                std::thread::park_timeout(Duration::from_millis(10));
                continue;
            }
        };
        let refresh = matches!(req, Request::Flush(..));
        let out = match req {
            Request::Flush(m, leases, enqueued) => {
                metrics.timings.dequeued(false, enqueued);
                db.debt = leases;
                metrics.flushes.fetch_add(1, Ordering::Relaxed);
                match durability.as_mut() {
                    None => db
                        .flush_with(&m, &metrics.timings, Some((&m, &pool)))
                        .map(|lsn| Completion::Flushed(lsn, m.sorted_ids())),
                    // Pipelined: apply, report the previous flush's durability (in
                    // order), hand this one to the durability thread, report Applied.
                    Some(d) => db
                        .apply_with(&m, &metrics.timings, Some((&m, &pool)))
                        .and_then(|lsn| {
                            match d.wait() {
                                Some(Ok(prev)) => {
                                    db.watermark = prev;
                                    if !push_completion(
                                        &mut tx,
                                        Completion::Flushed(prev, Vec::new()),
                                        &hints,
                                    ) {
                                        return Err(err("SplinterDB worker stopping"));
                                    }
                                }
                                Some(Err(e)) => return Err(e),
                                None => {}
                            }
                            d.submit(lsn)?;
                            Ok(Completion::Applied(lsn, m.sorted_ids()))
                        }),
                }
            }
            Request::Read(q, view, allowance, session, enqueued) => {
                metrics.timings.dequeued(true, enqueued);
                let _read = metrics.timings.start(if matches!(q, Query::Page { .. }) {
                    timing::SCAN
                } else {
                    timing::POINT_READ
                });
                let limit = allowance.bytes;
                if matches!(q, Query::Page { .. }) {
                    metrics.pages.fetch_add(1, Ordering::Relaxed);
                } else {
                    metrics.points.fetch_add(1, Ordering::Relaxed);
                }
                let retain = if matches!(q, Query::Keys { .. }) {
                    session
                } else {
                    None
                };
                let answer = if let Query::Keys { id, keys } = &q {
                    // One logical result, cancellable between bounded foreign
                    // batches. Cache pressure never truncates a by-keys reply.
                    let mut entries = Vec::new();
                    let mut error = None;
                    for keys in keys.chunks(PAGE) {
                        if stop.load(Ordering::Acquire) {
                            return;
                        }
                        match db.read(
                            &Query::Keys {
                                id: *id,
                                keys: keys.to_vec(),
                            },
                            &view,
                            limit,
                        ) {
                            Ok(Answer::Entries(v, _)) => entries.extend(v),
                            Ok(_) => unreachable!("keys answer"),
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    error.map_or_else(|| Ok(Answer::Entries(entries, false)), Err)
                } else {
                    db.read_batch(&q, &view, limit, allowance.rows, || {
                        allowance.should_yield(&hints, rx.peek().is_ok())
                    })
                };
                answer.map(|a| Completion::Read(q, Arc::new(a), retain))
            }
        };
        let out = out.and_then(|c| {
            if refresh {
                observe(&db, &root, &space, &metrics)?;
                sampled = Instant::now();
            } else {
                metrics.seeks.store(db.seeks.get(), Ordering::Relaxed);
                metrics
                    .spec_errors
                    .store(db.spec_errors.get(), Ordering::Relaxed);
            }
            Ok(c)
        });
        let failed = out.is_err();
        if !push_completion(&mut tx, out.unwrap_or_else(Completion::Failed), &hints) || failed {
            return;
        }
        // Keep dynamic disk debt alive through the foreign call AND sample even
        // if the owner timed out/dropped while this worker remained in C.
        db.debt.clear();
    }
    drop(pool);
    if let Err(e) = db.db.close() {
        eprintln!("SplinterDB worker close failed (not a durable shutdown): {e}");
    }
}

#[derive(Debug)]
pub(crate) struct Client {
    tx: Producer<Request>,
    rx: Consumer<Completion>,
    wake: WakeSlot,
    thread: Thread,
    join: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    pressure: Arc<AtomicBool>,
    epoch: Arc<AtomicU64>,
    scan: ScanCache,
    cache: HashMap<Query, Arc<Answer>>,
    pending: HashSet<Query>,
    cache_bytes: usize,
    budget: usize,
    pub watermark: u64,
    pub flushed: Option<u64>,
    flushing: bool,
    /// Pipelined: a flush was applied and awaits its durability (`Flushed`).
    durable_pending: bool,
    /// Pipelined: an applied flush's LSN not yet taken by the shard.
    applied: Option<u64>,
    pub failure: Option<StoreError>,
    pub space: Arc<Space>,
    metrics: Arc<Metrics>,
    session: Option<(u64, u64)>,
    parents: HashMap<(u64, u64), (u64, u64)>,
    owner: Option<(u64, u64)>,
    retained: HashMap<Query, Arc<Answer>>,
    retained_bytes: usize,
    read_budget: usize,
    scan_charge: usize,
    touched: Instant,
    // A synchronous sessionless store call cannot schedule the suspended owner.
    // Exclude only that bounded call's duration from abandonment, not idle time.
    owner_pause: Option<((u64, u64), Instant)>,
    read_scope_depth: usize,
    independent_reads: bool,
    waiting: bool,
    #[cfg(test)]
    pub(crate) hold_completions: bool,
    #[cfg(test)]
    logical_used_override: std::cell::Cell<Option<u64>>,
    accepted: std::collections::VecDeque<(u64, Arc<Lease>)>,
}
impl Client {
    pub fn open(
        cfg: &Config,
        sb: &Superblock,
        shard: u32,
        mem: usize,
        floor: u64,
        frontier: u64,
    ) -> Result<Self> {
        if sb.shards > crate::layout::MAX_SPLINTERDB_SHARDS {
            return Err(StoreError::Invalid(
                "SplinterDB supports at most 63 native shards per process",
            ));
        }
        cfg.admit()?;
        let path = cfg.path(sb, shard)?;
        validate_binding(cfg, sb, shard)?;
        if !path.is_file() {
            return Err(StoreError::Invalid(
                "SplinterDB image missing; mount never creates it",
            ));
        }
        let cache = (mem / 2) & !((256 << 10) - 1);
        if cache < 64 << 20 {
            return Err(StoreError::Invalid(
                "SplinterDB shard memory share must allow >=64MiB cache plus overlay/read budgets",
            ));
        }
        let options = cfg.options(cache)?;
        if options.normal_maintenance && sb.shards > 31 {
            return Err(StoreError::Invalid(
                "SplinterDB normal maintenance supports at most 31 native shards per process",
            ));
        }
        let apply_helpers = cfg.apply_helpers();
        let helper_threads = usize::from(options.normal_maintenance)
            + usize::from(options.memtable_maintenance)
            + apply_helpers
            + usize::from(cfg.pipelined_barrier);
        let pipelined = cfg.pipelined_barrier;
        // One caller per shard plus its helpers share the 63 registered-thread slots.
        if (sb.shards as usize).saturating_mul(1 + helper_threads) > 63 {
            return Err(StoreError::Invalid(
                "SplinterDB shards times (worker plus helper threads) exceed 63 registered threads",
            ));
        }
        // Charge the actual default pthread stack+guard of every helper thread against
        // existing read retention credit, not foreign cache or an increased memory target.
        let helper_stack = if helper_threads > 0 {
            splinterdb_lib::maintenance_stack_bytes().map_err(err)?
        } else {
            0
        };
        let maintenance_stack = helper_stack.saturating_mul(helper_threads);
        let read_budget = maintenance_read_budget(mem, maintenance_stack)?;
        let apply_cpus = cfg.apply_cpus.clone();
        let space = Space::join(&cfg.root)?;
        let bytes = (mem as u64).saturating_mul(4);
        space.reserved.fetch_add(bytes, Ordering::AcqRel);
        let lease = Lease {
            space: space.clone(),
            bytes,
        };
        let (tx, req) = RingBuffer::new(QUEUE);
        let (out, rx) = RingBuffer::new(QUEUE);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let pressure = Arc::new(AtomicBool::new(false));
        let worker_pressure = pressure.clone();
        let epoch = Arc::new(AtomicU64::new(0));
        let worker_epoch = epoch.clone();
        let wake = WakeSlot::default();
        let worker_wake = wake.clone();
        let metrics = Arc::new(Metrics::default());
        metrics
            .maintenance_stack
            .store(maintenance_stack as u64, Ordering::Relaxed);
        let wm = metrics.clone();
        let root = cfg.root.clone();
        let cpu = cfg.cpu;
        let cleaner_cpu = cfg
            .isolate_cleaner
            .then_some(cfg.cleaner_cpu)
            .flatten()
            .filter(|c| cpu.is_some() && Some(*c) != cpu);
        let id = identity(sb, shard);
        let ws = space.clone();
        let (boot, ready) = std::sync::mpsc::sync_channel(1);
        let join = std::thread::Builder::new()
            .name(format!("omap-splinter-{shard}"))
            .spawn(move || {
                let _lease = lease;
                use std::os::unix::fs::OpenOptionsExt;
                let opened = (|| {
                    pin(cpu)?;
                    let lock = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(path.with_extension("lock"))
                        .map_err(err)?;
                    use std::os::fd::AsRawFd;
                    // SAFETY: advisory exclusive nonblocking lock on this identity-bound file.
                    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
                    {
                        return Err(err("SplinterDB image already open"));
                    }
                    let db = open_with_cleaner(
                        (cpu, cleaner_cpu),
                        pin,
                        || Database::open_with_options(&path, &id, cache, options),
                        |db| db.db.prime_io().map_err(err),
                    )?;
                    if db.watermark < floor || db.watermark > frontier {
                        return Err(err(format!(
                            "watermark {} outside native[{floor},{frontier}]",
                            db.watermark
                        )));
                    }
                    observe(&db, &root, &ws, &wm)?;
                    if let Some(cleaner_cpu) = cleaner_cpu {
                        eprintln!("SplinterDB shard {shard}: worker CPU {cpu:?}, cleaner CPU {cleaner_cpu}");
                    }
                    if options.normal_maintenance {
                        eprintln!("SplinterDB shard {shard}: one normal-maintenance worker on CPU {cleaner_cpu:?}, stack+guard {maintenance_stack} bytes");
                    }
                    if db.checkpointed {
                        eprintln!("SplinterDB shard {shard}: library log off; barriers checkpoint");
                    }
                    let maintenance = db.db.maintenance_stats().map_err(err)?;
                    eprintln!("SplinterDB shard {shard}: effective normal_workers={} memtable_workers={} queue_scale_percent={}", maintenance.normal_workers, maintenance.memtable_workers, maintenance.queue_scale_percent);
                    let pool = ApplyPool::start(&db.db, shard, apply_helpers, &apply_cpus, helper_stack)?;
                    eprintln!("SplinterDB shard {shard}: apply threads={} helper CPUs {:?}", apply_helpers + 1, if apply_helpers > 0 { apply_cpus.as_slice() } else { &[] });
                    let durability = if pipelined {
                        let d = Durability::start(&db.db, shard, &apply_cpus, helper_stack, wm.clone(), std::thread::current(), (None, db.checkpointed))?;
                        eprintln!("SplinterDB shard {shard}: pipelined barrier on its durability thread");
                        Some(d)
                    } else {
                        None
                    };
                    Ok((db, lock, pool, durability))
                })();
                match opened {
                    Ok((db, _lock, pool, durability)) => {
                        if boot.send(Ok(db.watermark)).is_ok() {
                            worker(
                                (db, pool, durability),
                                req,
                                out,
                                WorkerHints {
                                    stop: stopping,
                                    pressure: worker_pressure,
                                    epoch: worker_epoch,
                                    wake: worker_wake,
                                },
                                root,
                                ws,
                                wm,
                            );
                        }
                    }
                    Err(e) => {
                        let _ = boot.send(Err(e));
                    }
                }
            })
            .map_err(err)?;
        let watermark = match ready.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(watermark)) => watermark,
            Ok(Err(e)) => {
                // The worker has closed its DB before reporting the error; join
                // also waits for its lock/reservation teardown before returning.
                join.join()
                    .map_err(|_| err("SplinterDB startup cleanup panicked"))?;
                return Err(e);
            }
            Err(e) => {
                stop.store(true, Ordering::Release);
                join.thread().unpark();
                return Err(err(format!("WARNING TIMEOUT SplinterDB open: {e}")));
            }
        };
        Ok(Self {
            tx,
            rx,
            wake,
            thread: join.thread().clone(),
            join: Some(join),
            stop,
            pressure,
            epoch,
            scan: ScanCache::new(cfg.scan_readahead_pages),
            cache: HashMap::new(),
            pending: HashSet::new(),
            cache_bytes: 0,
            budget: mem / 16,
            watermark,
            flushed: None,
            flushing: false,
            durable_pending: false,
            applied: None,
            failure: None,
            space,
            metrics,
            session: None,
            parents: HashMap::new(),
            owner: None,
            retained: HashMap::new(),
            retained_bytes: 0,
            read_budget,
            scan_charge: 0,
            touched: Instant::now(),
            owner_pause: None,
            read_scope_depth: 0,
            independent_reads: false,
            waiting: false,
            #[cfg(test)]
            hold_completions: false,
            #[cfg(test)]
            logical_used_override: std::cell::Cell::new(None),
            accepted: Default::default(),
        })
    }
    fn credit(&self, s: (u64, u64)) -> (u64, u64) {
        self.parents.get(&s).copied().unwrap_or(s)
    }
    pub fn retained_session(&self) -> Option<(u64, u64)> {
        self.owner
    }
    pub fn session(&self) -> Option<(u64, u64)> {
        self.session
    }
    pub fn query_session(&self) -> Option<(u64, u64)> {
        if self.independent_reads {
            None
        } else {
            self.session()
        }
    }
    pub fn independent_reads(&self) -> bool {
        self.independent_reads
    }
    pub fn session_admitted(&self, s: (u64, u64)) -> bool {
        self.owner == Some(self.credit(s))
    }
    /// Unlike an IO miss, this wait can only progress when another request runs.
    pub fn credit_blocked(&self) -> bool {
        self.query_session().is_some()
            && self.owner.is_some()
            && self.owner != self.session.map(|s| self.credit(s))
    }
    pub fn begin_blocking_read(&mut self) -> bool {
        let wake = self.read_scope_depth == 0 && self.expire();
        if self.read_scope_depth == 0
            && self.query_session().is_none()
            && let Some(owner) = self.owner
        {
            self.owner_pause = Some((owner, Instant::now()));
        }
        self.read_scope_depth += 1;
        wake
    }
    pub fn end_blocking_read(&mut self) {
        self.read_scope_depth -= 1;
        if self.read_scope_depth == 0
            && let Some((owner, start)) = self.owner_pause.take()
            && self.owner == Some(owner)
        {
            self.touched += start.elapsed();
        }
    }
    pub fn begin_barrier_read(&mut self) -> bool {
        debug_assert!(!self.independent_reads && self.read_scope_depth == 0);
        self.independent_reads = true;
        self.begin_blocking_read()
    }
    pub fn end_barrier_read(&mut self) {
        self.end_blocking_read();
        self.independent_reads = false;
    }
    /// Ends the scan credit. A completed window survives request retirement so the
    /// next request of a paginated listing can continue in it (matched by object,
    /// prefix, projection and overlay revisions, invalidated by materialization);
    /// idle expiry drops it. The epoch still cancels optional in-flight work.
    fn release(&mut self, keep_window: bool) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.touched = Instant::now();
        if !keep_window {
            self.scan.clear();
        }
        self.owner = None;
        self.retained.clear();
        self.retained_bytes = 0;
        self.parents.clear();
        self.scan_charge = 0;
        self.owner_pause = None;
        self.waiting = false;
    }
    fn expire(&mut self) -> bool {
        if self.owner_pause.is_some() || self.touched.elapsed() < Duration::from_secs(30) {
            return false;
        }
        let had = self.owner.is_some();
        self.release(false);
        had
    }
    pub fn read_session(&mut self, session: Option<(u64, u64)>, keep: bool) {
        if let (Some(child), Some(parent), Some(owner)) = (session, self.session, self.owner)
            && child != parent
            && self.credit(parent) == owner
        {
            self.parents.insert(child, owner);
        }
        if session.is_none() && !keep {
            if self.owner == self.session {
                self.release(true);
            } else if let Some(child) = self.session {
                // An unadmitted tag or a one-shot barrier child did not use A's
                // window. Its retirement must not cancel A's pending request.
                if !self.independent_reads && self.session_admitted(child) {
                    self.epoch.fetch_add(1, Ordering::AcqRel);
                }
                self.parents.remove(&child);
            }
        }
        self.session = session;
        if !self.independent_reads && session.is_some_and(|s| self.session_admitted(s)) {
            self.touched = Instant::now();
        }
    }
    pub fn set_scan_charge(&mut self, n: usize) {
        self.scan_charge = n;
    }
    pub fn set_pressure(&mut self, on: bool) {
        self.pressure.store(on, Ordering::Release);
        self.scan.pressure(on);
    }
    pub fn admit_scan(&mut self, session: (u64, u64), bytes: usize) -> Result<()> {
        self.expire();
        let owner = self.credit(session);
        if self.owner.is_some_and(|o| o != owner) {
            self.waiting = true;
            return Err(StoreError::Miss);
        }
        self.owner = Some(owner);
        self.touched = Instant::now();
        // The memory envelope is soft. The admitted native request must finish
        // even if one value or its accumulated output exceeds its share. Other
        // sessions wait for this credit; output growth is charged, not invalidated.
        self.scan_charge = bytes;
        Ok(())
    }
    pub fn busy(&self) -> bool {
        !self.can_flush() || self.durable_pending
    }
    pub fn needs_poll(&self) -> bool {
        self.busy() || self.waiting
    }
    pub fn logical_available(&self) -> u64 {
        let cap = self.metrics.db_capacity.load(Ordering::Acquire);
        let used = self.metrics.db_used.load(Ordering::Acquire);
        #[cfg(test)]
        let used = self.logical_used_override.get().unwrap_or(used);
        cap.saturating_sub(used).saturating_sub(cap / 8)
    }
    pub fn available(&self) -> u64 {
        self.space.available().min(self.logical_available())
    }
    pub fn allocated_bytes(&self) -> u64 {
        self.metrics.db_used.load(Ordering::Acquire)
    }
    pub fn capacity(&self) -> u64 {
        self.metrics.db_capacity.load(Ordering::Acquire)
    }
    #[cfg(test)]
    pub(crate) fn test_logical_used(&self, used: u64) {
        // Owner-only injection must survive concurrent worker space sampling.
        self.logical_used_override.set(Some(used));
    }
    /// Reserve incoming growth before native acceptance. Deletes use the recovery
    /// headroom already withheld by `logical_available`/the worker filesystem lease.
    pub fn reserve(&self, ops: &[crate::state::Op], pending: usize) -> Result<Option<Arc<Lease>>> {
        let growth = ops.iter().fold(0u64, |sum, op| match op {
            crate::state::Op::Omap(crate::olsm::wire::OOp::Put { n, blob, .. }) => sum
                .saturating_add(blob.len() as u64)
                .saturating_add(u64::from(*n) * 64),
            _ => sum,
        });
        if growth == 0 {
            return Ok(None);
        }
        // Charge key/record framing and rewrite slack along with the entire
        // pre-existing overlay, not only the already installed base.
        let charge = growth.saturating_mul(4);
        if charge.saturating_add((pending as u64).saturating_mul(4)) > self.logical_available() {
            return Err(StoreError::NoSpace);
        }
        self.space.reserve(charge).map(|l| Some(Arc::new(l)))
    }
    pub fn accepted(&mut self, lsn: u64, lease: Arc<Lease>) {
        self.accepted.push_back((lsn, lease));
    }
    pub fn counters(&self) -> [u64; 5] {
        [
            self.metrics.pages.load(Ordering::Relaxed),
            self.metrics.points.load(Ordering::Relaxed),
            self.metrics.flushes.load(Ordering::Relaxed),
            self.allocated_bytes(),
            self.metrics.db_capacity.load(Ordering::Acquire),
        ]
    }
    pub fn read_gauges(&self) -> [u64; 29] {
        let mut out = [0; 29];
        out[..9].copy_from_slice(&self.scan.counters());
        out[9] = self.metrics.seeks.load(Ordering::Relaxed);
        for (i, slot) in self.metrics.engine[1..].iter().enumerate() {
            out[10 + i] = slot.load(Ordering::Relaxed);
        }
        let valid = self.metrics.sample_valid.load(Ordering::Acquire);
        out[18] = u64::from(valid) * self.metrics.engine[0].load(Ordering::Relaxed);
        out[19] = u64::from(valid);
        out[20] = self.metrics.sample_errors.load(Ordering::Relaxed);
        out[21] = self.metrics.sample_origin.get().map_or(0, |t| {
            (t.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64)
                .saturating_sub(self.metrics.sample_ns.load(Ordering::Relaxed))
        });
        out[22] = self.cache_bytes as u64;
        out[23] = self.retained_bytes as u64;
        out[24] = self.scan_charge as u64;
        out[25] = self.metrics.spec_errors.load(Ordering::Relaxed);
        out[26] = self.metrics.normal_workers.load(Ordering::Relaxed);
        out[27] = u64::from(self.metrics.maintenance_busy.load(Ordering::Relaxed));
        out[28] = self.metrics.maintenance_stack.load(Ordering::Relaxed);
        out
    }
    pub fn timing_counters(&self) -> [u64; timing::FIELDS] {
        self.metrics.timings.snapshot()
    }
    pub fn flush(&mut self, m: Arc<Memtable>) -> Result<()> {
        if self.flushing || self.flushed.is_some() {
            return Err(StoreError::Busy);
        }
        if let Some(e) = &self.failure {
            return Err(e.clone());
        }
        let held = self
            .accepted
            .iter()
            .take_while(|(lsn, _)| *lsn <= m.lsn_hi())
            .map(|(_, l)| l.clone())
            .collect();
        self.tx
            .push(Request::Flush(m, held, Instant::now()))
            .map_err(|_| StoreError::Busy)?;
        self.set_pressure(true);
        self.flushing = true;
        self.thread.unpark();
        Ok(())
    }
    /// Install the owner wake (first install wins: a core's wake handle never
    /// changes). Without one the owner relies on its idle cap, as before.
    pub fn set_owner_wake(&self, w: OwnerWake) {
        let _ = self.wake.set(w);
    }
    /// A worker completion is published and not yet consumed by [`poll`](Self::poll):
    /// the owner's idle re-check after it announced its sleep.
    pub fn has_completion(&self) -> bool {
        !self.rx.is_empty()
    }
    /// A flush's objects changed in the engine: drop windows and answers of them.
    fn invalidate_applied(&mut self, ids: &[u64]) {
        self.scan.invalidate(ids);
        self.cache.retain(|q, _| !q.touches(ids));
        self.cache_bytes = self.cache.iter().map(|(q, a)| q.bytes() + a.bytes()).sum();
        self.retained.retain(|q, _| !q.touches(ids));
        self.retained_bytes = self
            .retained
            .iter()
            .map(|(q, a)| q.bytes() + a.bytes())
            .sum();
    }
    /// The LSN of a pipelined flush that became visible since the last call: its
    /// frozen buffer may go; publication still waits for its `flushed`.
    pub fn take_applied(&mut self) -> Option<u64> {
        self.applied.take()
    }
    /// A new flush may be sent: none in flight, none awaiting publication and no read
    /// pending. A pipelined flush may still await durability.
    pub fn can_flush(&self) -> bool {
        !self.flushing && self.flushed.is_none() && self.pending.is_empty()
    }
    pub fn poll(&mut self) -> bool {
        let mut wake = self.expire();
        #[cfg(test)]
        if self.hold_completions {
            return wake;
        }
        while let Ok(c) = self.rx.pop() {
            wake = true;
            match c {
                Completion::Applied(lsn, ids) => {
                    // Visible in the engine: invalidate as at a flush and accept the
                    // next flush; durability and native publication follow (Flushed).
                    self.invalidate_applied(&ids);
                    self.flushing = false;
                    self.durable_pending = true;
                    self.applied = Some(lsn);
                }
                Completion::Flushed(lsn, ids) => {
                    while self.accepted.front().is_some_and(|(l, _)| *l <= lsn) {
                        self.accepted.pop_front();
                    }
                    self.watermark = lsn;
                    self.flushed = Some(lsn);
                    if std::mem::take(&mut self.durable_pending) {
                        // Pipelined: already invalidated at Applied; a later flush may
                        // be in flight, so `flushing` is left as it is.
                        continue;
                    }
                    self.flushing = false;
                    self.invalidate_applied(&ids);
                }
                Completion::Read(q, a, session) => {
                    self.pending.remove(&q);
                    if let Query::Page {
                        session: Some(request),
                        ..
                    } = &q
                    {
                        // Route by captured request identity, not the current
                        // caller or Keys-only retention tag in the completion.
                        if self.session_admitted(*request) {
                            self.scan.insert(q, a);
                        }
                        continue;
                    }
                    let bytes = q.bytes().saturating_add(a.bytes());
                    if session.is_some() && session == self.owner {
                        self.retained_bytes = self.retained_bytes.saturating_add(bytes);
                        self.retained.insert(q, a);
                        continue;
                    }
                    if self.cache_bytes.saturating_add(bytes) > self.budget {
                        self.cache.clear();
                        self.cache_bytes = 0;
                    }
                    self.cache_bytes = self.cache_bytes.saturating_add(bytes);
                    self.cache.insert(q, a);
                }
                Completion::Failed(e) => self.failure = Some(e),
            }
        }
        if self.join.as_ref().is_some_and(|j| j.is_finished()) && self.failure.is_none() {
            self.failure = Some(err("worker exited unexpectedly"));
            wake = true;
        }
        wake
    }
    pub fn query(&mut self, q: Query) -> Result<Arc<Answer>> {
        self.query_view(q, [None, None, None])
    }
    pub fn query_view(&mut self, q: Query, view: View) -> Result<Arc<Answer>> {
        self.query_view_take(q, view, usize::MAX)
    }
    /// As [`query_view`](Self::query_view); a hit in the owned scan window copies at
    /// most `take` rows (what the caller's pass can consume), marking `more`.
    pub fn query_view_take(
        &mut self,
        mut q: Query,
        view: View,
        take: usize,
    ) -> Result<Arc<Answer>> {
        if let Query::Page { demand, .. } = &mut q {
            *demand = (*demand).clamp(1, MAX_SCAN_ROWS);
        }
        if let Some(e) = &self.failure {
            return Err(e.clone());
        }
        self.expire();
        let session = self.query_session();
        let retain = session.is_some() && matches!(q, Query::Keys { .. });
        if session.is_some() {
            let owner = session.map(|s| self.credit(s));
            if self.owner.is_some() && self.owner != owner {
                self.waiting = true;
                return Err(StoreError::Miss);
            }
            self.owner = owner;
            self.touched = Instant::now();
        } else if self.owner.is_none() {
            self.touched = Instant::now();
        }
        if retain && let Some(a) = self.retained.get(&q) {
            return Ok(a.clone());
        }
        // Sessionless recovery/scrub reads use the existing single worker slot
        // and ordinary answer cache. They never acquire or alter a scan credit.
        let owned_page = matches!(
            q,
            Query::Page {
                session: Some(_),
                ..
            }
        );
        if owned_page {
            if let Some(a) = self.scan.get_take(&q, take) {
                return Ok(a);
            }
        } else if session.is_some() {
            self.scan.interrupt();
        }
        if let Some(a) = self.cache.get(&q).cloned() {
            if retain {
                let bytes = q.bytes().saturating_add(a.bytes());
                self.retained_bytes = self.retained_bytes.saturating_add(bytes);
                self.retained.insert(q, a.clone());
            } else if session.is_none() && (self.owner.is_some() || matches!(q, Query::Page { .. }))
            {
                // Deliver the independent answer instead of accumulating loan
                // results beside A. One oversized row/full by-keys result is
                // still allowed for progress; this remains a soft byte budget.
                self.cache.remove(&q);
                self.cache_bytes = self.cache_bytes.saturating_sub(q.bytes() + a.bytes());
            }
            return Ok(a);
        }
        if self.pending.is_empty() {
            let pages = if owned_page { self.scan.prepare(&q) } else { 1 };
            let mut limit = self
                .read_budget
                .saturating_sub(self.scan_charge)
                .saturating_sub(self.retained_bytes.saturating_mul(4))
                .saturating_sub(self.cache_bytes.saturating_mul(4))
                .saturating_sub(self.scan.bytes().saturating_mul(4))
                / 4;
            if retain && !self.retained.is_empty() {
                limit = limit.min(self.budget.saturating_sub(self.retained_bytes));
            }
            limit = limit.saturating_sub(q.bytes());
            if self
                .tx
                .push(Request::Read(
                    q.clone(),
                    view,
                    ReadAllowance {
                        bytes: limit,
                        rows: q.demand().saturating_mul(pages).min(MAX_SCAN_ROWS),
                        epoch: self.epoch.load(Ordering::Acquire),
                    },
                    if retain { self.owner } else { None },
                    Instant::now(),
                ))
                .is_ok()
            {
                self.pending.insert(q);
                self.thread.unpark();
            }
        }
        Err(StoreError::Miss)
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.unpark();
        if let Some(j) = self.join.take() {
            let end = Instant::now() + Duration::from_secs(30);
            while !j.is_finished() && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(1));
            }
            if j.is_finished() {
                let _ = j.join();
            } else {
                eprintln!(
                    "WARNING TIMEOUT SplinterDB shutdown; worker retains image lock and space lease"
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "splinter_omap_tests.rs"]
mod tests;
