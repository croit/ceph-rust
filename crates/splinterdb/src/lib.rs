// SPDX-License-Identifier: LGPL-3.0-only
//! Pinned SplinterDB binding. No native library/dependency build without `native`.
//! Handles are single-thread-owned; borrowed iterator views never outlive them.
#![cfg(feature = "native")]

use std::cell::RefCell;
use std::ffi::{CString, c_char, c_int, c_void};
use std::marker::PhantomData;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const REVISION: &str = "73f89d8879e2e5603933f756c8c4d2c60a12d9c6";

/// Startup-only IO policy, never a weaker persistence/ACK policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IoMode {
    Direct,
    #[default]
    Buffered,
}
impl std::str::FromStr for IoMode {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "direct" => Ok(Self::Direct),
            "buffered" => Ok(Self::Buffered),
            _ => Err("SplinterDB IO must be direct or buffered"),
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub io: IoMode,
    /// Soft upstream extent look-ahead budget, not a physical-IO hard limit.
    /// Zero retains the pinned library's local-SSD default.
    pub prefetch_bytes: u64,
    /// Opt-in cache counters; disabled counters must not be reported as measured zeros.
    pub cache_stats: bool,
    /// Experimental one-worker normal pool. Memtable workers remain disabled.
    /// The caller owns startup affinity; raw cache statistics must be disabled.
    /// Uses fixed queue scale101: ordinary normal help at two queued tasks;
    /// forced progress and zero-worker memtable help remain enabled. No hard
    /// queue/memory/latency bound. Disabled retains the original scale0 policy.
    pub normal_maintenance: bool,
    /// Experimental one-worker memtable pool, only together with `normal_maintenance`.
    /// Memtable incorporation leaves the inserting caller; with queue scale101 the caller
    /// still helps once two memtable tasks wait. Costs one more registered thread.
    pub memtable_maintenance: bool,
    /// Log growth that arms an automatic checkpoint (each writes back the cache and
    /// syncs). Zero keeps the pinned default (one cache size). Larger values mean
    /// fewer checkpoints but more log space and replay at open.
    pub checkpoint_log_bytes: u64,
    /// Patched library option: write filled log pages at the next durability wait
    /// (barrier, checkpoint seal) instead of as each fills. Same durability.
    pub defer_log_writeback: bool,
    /// Run without the library log: a durable barrier checkpoints the tree. Only for
    /// callers whose own redo log covers every update after the last barrier.
    pub no_log: bool,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadStats {
    pub valid: bool,
    pub hits: u64,
    pub misses: u64,
    pub engine_read_bytes: u64,
    pub engine_write_bytes: u64,
    pub prefetch_pages: u64,
    pub direct: bool,
    pub cache_bytes: u64,
    pub prefetch_bytes: u64,
}
unsafe extern "C" {
    fn nv_sdb_open(
        path: *const c_char,
        cache: u64,
        capacity: u64,
        create: c_int,
        buffered: c_int,
        prefetch_bytes: u64,
        stats: c_int,
        normal_maintenance: c_int,
        memtable_maintenance: c_int,
        checkpoint_log_bytes: u64,
        defer_log_writeback: c_int,
        no_log: c_int,
        out: *mut *mut c_void,
    ) -> c_int;
    fn nv_sdb_close(db: *mut *mut c_void, force: c_int) -> c_int;
    fn nv_sdb_put(db: *mut c_void, k: *const u8, kn: usize, v: *const u8, vn: usize) -> c_int;
    fn nv_sdb_delete(db: *mut c_void, k: *const u8, kn: usize) -> c_int;
    fn nv_sdb_barrier(db: *mut c_void) -> c_int;
    fn nv_sdb_prime_io(db: *mut c_void) -> c_int;
    fn nv_sdb_acquire_caller(registration: *mut u64) -> c_int;
    fn nv_sdb_release_caller(registration: u64) -> c_int;
    fn nv_sdb_caller_matches(registration: u64) -> c_int;
    fn nv_sdb_maintenance_stack_bytes(bytes: *mut u64) -> c_int;
    fn nv_sdb_maintenance(db: *mut c_void, out: *mut u64) -> c_int;
    fn nv_sdb_space(db: *mut c_void, used: *mut u64, capacity: *mut u64);
    fn nv_sdb_read_stats(db: *mut c_void, out: *mut u64) -> c_int;
    fn nv_sdb_lookup_new(db: *mut c_void, result: *mut *mut c_void) -> c_int;
    fn nv_sdb_lookup(
        db: *mut c_void,
        k: *const u8,
        kn: usize,
        result: *mut c_void,
        v: *mut *const u8,
        vn: *mut usize,
        found: *mut c_int,
    ) -> c_int;
    fn nv_sdb_lookup_free(result: *mut c_void);
    fn nv_sdb_iter_open(
        db: *mut c_void,
        from: *const u8,
        n: usize,
        exclusive: c_int,
        end: *const u8,
        en: usize,
        out: *mut *mut c_void,
    ) -> c_int;
    fn nv_sdb_iter_current(
        it: *mut c_void,
        k: *mut *const u8,
        kn: *mut usize,
        v: *mut *const u8,
        vn: *mut usize,
        found: *mut c_int,
    ) -> c_int;
    fn nv_sdb_iter_next(it: *mut c_void) -> c_int;
    fn nv_sdb_iter_close(it: *mut c_void);
}

fn status(rc: c_int) -> std::io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(rc))
    }
}

// The pinned platform shares 64 registered thread IDs across all DB instances.
// Count one caller per distinct thread, plus helpers per handle, leaving one
// spare slot. Caller credits follow explicit last-handle deregistration, not
// an assumption that database close also deregisters its caller.
const THREAD_SLOTS: usize = 63;
#[derive(Debug, Default)]
struct ThreadBudget(AtomicUsize);
impl ThreadBudget {
    fn reserve(&self, slots: usize) -> std::io::Result<ThreadLease<'_>> {
        self.0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(slots).filter(|next| *next <= THREAD_SLOTS)
            })
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EAGAIN))?;
        Ok(ThreadLease {
            budget: self,
            slots,
        })
    }
}
#[derive(Debug)]
struct ThreadLease<'a> {
    budget: &'a ThreadBudget,
    slots: usize,
}
impl Drop for ThreadLease<'_> {
    fn drop(&mut self) {
        self.budget.0.fetch_sub(self.slots, Ordering::AcqRel);
    }
}
static THREAD_BUDGET: ThreadBudget = ThreadBudget(AtomicUsize::new(0));

#[derive(Debug, Default)]
struct CallerState {
    handles: usize,
    lease: Option<ThreadLease<'static>>,
    registration: u64,
    poisoned: bool,
}
impl CallerState {
    fn check_registration(&mut self, matches: bool) -> std::io::Result<()> {
        if !matches && !self.poisoned {
            self.poisoned = true;
            if let Some(lease) = self.lease.take() {
                std::mem::forget(lease);
            }
            eprintln!(
                "SplinterDB caller registration lost; admission credit retained, caller disabled"
            );
        }
        if self.poisoned {
            Err(std::io::Error::from_raw_os_error(libc::EOWNERDEAD))
        } else {
            Ok(())
        }
    }
}
impl Drop for CallerState {
    fn drop(&mut self) {
        // A deliberately leaked DB can still own library resources. Do not
        // recycle its admission credit merely because its caller exits.
        if let Some(lease) = self.lease.take() {
            std::mem::forget(lease);
        }
    }
}
thread_local! {
    static CALLER: Rc<RefCell<CallerState>> = Rc::new(RefCell::new(CallerState::default()));
}
#[derive(Debug)]
struct CallerLease {
    state: Rc<RefCell<CallerState>>,
}
impl CallerLease {
    fn acquire() -> std::io::Result<Self> {
        CALLER.with(|caller| {
            let mut state = caller.borrow_mut();
            if state.poisoned {
                return Err(std::io::Error::from_raw_os_error(libc::EOWNERDEAD));
            }
            if state.handles == 0 {
                let lease = THREAD_BUDGET.reserve(1)?;
                let mut registration = 0;
                // SAFETY: exclusive new wrapper caller; C refuses registration
                // belonging to an API caller outside this wrapper.
                status(unsafe { nv_sdb_acquire_caller(&mut registration) })?;
                state.lease = Some(lease);
                state.registration = registration;
            } else {
                // SAFETY: native TLS read only. Do not trust an existing credit
                // after a failed nested native open changed this caller's ID.
                let matches = unsafe { nv_sdb_caller_matches(state.registration) } != 0;
                state.check_registration(matches)?;
            }
            state.handles += 1;
            drop(state);
            Ok(Self {
                state: Rc::clone(caller),
            })
        })
    }
    fn verify(&self) -> std::io::Result<()> {
        let mut state = self.state.borrow_mut();
        // SAFETY: native TLS read only; called after every native open attempt,
        // including errors while another database on this caller remains live.
        let matches = unsafe { nv_sdb_caller_matches(state.registration) } != 0;
        state.check_registration(matches)
    }
    fn poisoned(&self) -> bool {
        self.state.borrow().poisoned
    }
}
impl Drop for CallerLease {
    fn drop(&mut self) {
        let mut caller = self.state.borrow_mut();
        caller.handles -= 1;
        if caller.handles == 0 && !caller.poisoned {
            // SAFETY: every native handle on this caller has finished close,
            // including its helper joins. C validates the exact registration.
            let rc = unsafe { nv_sdb_release_caller(caller.registration) };
            if rc == 0 {
                caller.lease.take();
            } else {
                let _ = caller.check_registration(false);
            }
        }
    }
}

fn verify_open_attempt<T>(
    result: std::io::Result<T>,
    verify: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<T> {
    // Verification must not be skipped by an early return on the native error.
    verify()?;
    result
}

/// Cold admission cost of the default pthread stack and guard for one helper.
/// No thread is created. This is not a bound on task-queue/engine memory.
pub fn maintenance_stack_bytes() -> std::io::Result<usize> {
    let mut bytes = 0;
    // SAFETY: initialized writable output; queries pthread defaults only.
    status(unsafe { nv_sdb_maintenance_stack_bytes(&mut bytes) })?;
    usize::try_from(bytes).map_err(|_| std::io::Error::from_raw_os_error(libc::EOVERFLOW))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MaintenanceStats {
    pub normal_workers: u64,
    /// Coherent snapshot of both queues and running tasks, not all engine debt.
    pub busy: bool,
    pub memtable_workers: u64,
    /// Effective immutable library configuration, not a measured queue length.
    pub queue_scale_percent: u64,
}

#[derive(Debug)]
pub struct Database {
    handle: *mut c_void,
    // Released only after the native close has joined its maintenance worker.
    threads: Option<ThreadLease<'static>>,
    caller: Option<CallerLease>,
    _owner: PhantomData<Rc<()>>,
}
impl Database {
    /// Open only an existing image, or exclusively create a new one. Opening is
    /// mutating: upstream recovery/close are NOT read-only even with O_RDONLY.
    pub fn open(path: &Path, cache: u64, capacity: u64, create: bool) -> std::io::Result<Self> {
        Self::open_with_options(path, cache, capacity, create, Options::default())
    }
    pub fn open_with_options(
        path: &Path,
        cache: u64,
        capacity: u64,
        create: bool,
        options: Options,
    ) -> std::io::Result<Self> {
        if options.normal_maintenance && options.cache_stats {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "normal maintenance requires cache statistics disabled",
            ));
        }
        if options.memtable_maintenance && !options.normal_maintenance {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "memtable maintenance requires normal maintenance",
            ));
        }
        let path = CString::new(path.as_os_str().as_bytes())?;
        let caller = CallerLease::acquire()?;
        let helpers =
            usize::from(options.normal_maintenance) + usize::from(options.memtable_maintenance);
        let threads = if helpers > 0 {
            Some(THREAD_BUDGET.reserve(helpers)?)
        } else {
            None
        };
        let mut handle = std::ptr::null_mut();
        // SAFETY: stable path/output; C retains its own config and stable callbacks.
        let rc = unsafe {
            nv_sdb_open(
                path.as_ptr(),
                cache,
                capacity,
                i32::from(create),
                i32::from(options.io == IoMode::Buffered),
                options.prefetch_bytes,
                i32::from(options.cache_stats),
                i32::from(options.normal_maintenance),
                i32::from(options.memtable_maintenance),
                options.checkpoint_log_bytes,
                i32::from(options.defer_log_writeback),
                i32::from(options.no_log),
                &mut handle,
            )
        };
        let opened = Self {
            handle,
            threads,
            caller: Some(caller),
            _owner: PhantomData,
        };
        verify_open_attempt(status(rc), || {
            opened.caller.as_ref().expect("open caller").verify()
        })?;
        if opened.handle.is_null() {
            return Err(std::io::Error::other("SplinterDB returned no handle"));
        }
        Ok(opened)
    }
    fn handle(&self) -> std::io::Result<*mut c_void> {
        if self.caller.as_ref().is_some_and(CallerLease::poisoned) {
            Err(std::io::Error::from_raw_os_error(libc::EOWNERDEAD))
        } else if self.handle.is_null() {
            Err(std::io::Error::from_raw_os_error(libc::EBADF))
        } else {
            Ok(self.handle)
        }
    }
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> std::io::Result<()> {
        // SAFETY: both nonnull slice pointers remain live until the synchronous call returns.
        status(unsafe {
            nv_sdb_put(
                self.handle()?,
                key.as_ptr(),
                key.len(),
                value.as_ptr(),
                value.len(),
            )
        })
    }
    pub fn delete(&mut self, key: &[u8]) -> std::io::Result<()> {
        // SAFETY: key remains live; only this thread owns the database.
        status(unsafe { nv_sdb_delete(self.handle()?, key.as_ptr(), key.len()) })
    }
    pub fn durable_barrier(&mut self) -> std::io::Result<()> {
        // SAFETY: synchronous barrier on this live, exclusively owned database.
        status(unsafe { nv_sdb_barrier(self.handle()?) })
    }
    /// Cold startup: complete one aligned read of the existing superblock page.
    /// Initializes/reuses the pinned LAIO context under this thread's affinity;
    /// does not mutate logical data or replace a durability barrier. Pending
    /// request storage remains C-owned until terminal completion (not cancellable).
    pub fn prime_io(&mut self) -> std::io::Result<()> {
        // SAFETY: exclusively borrowed live DB; synchronous return after request teardown.
        status(unsafe { nv_sdb_prime_io(self.handle()?) })
    }
    pub fn maintenance_stats(&self) -> std::io::Result<MaintenanceStats> {
        let mut out = [0; 4];
        // SAFETY: live owner-bound DB; four writable scalars. The native query
        // locks task groups without running maintenance or reading raw counters.
        status(unsafe { nv_sdb_maintenance(self.handle()?, out.as_mut_ptr()) })?;
        Ok(MaintenanceStats {
            normal_workers: out[0],
            busy: out[1] != 0,
            memtable_workers: out[2],
            queue_scale_percent: out[3],
        })
    }
    /// Worker-sampled logical extent usage/capacity; not filesystem free space.
    pub fn space(&self) -> std::io::Result<(u64, u64)> {
        let (mut used, mut capacity) = (0, 0);
        // SAFETY: one live database owner, writable output integers; no concurrent API users.
        unsafe { nv_sdb_space(self.handle()?, &mut used, &mut capacity) };
        if used > capacity {
            return Err(std::io::Error::other(
                "invalid SplinterDB allocation accounting",
            ));
        }
        Ok((used, capacity))
    }
    /// Revision-pinned worker sample; engine misses/bytes are not OS cache misses
    /// or physical device reads. IO mode is verified from the live descriptor.
    pub fn read_stats(&self) -> std::io::Result<ReadStats> {
        let mut out = [0u64; 9];
        // SAFETY: live single-thread-owned handle and nine writable scalar slots.
        status(unsafe { nv_sdb_read_stats(self.handle()?, out.as_mut_ptr()) })?;
        Ok(ReadStats {
            valid: out[0] != 0,
            hits: out[1],
            misses: out[2],
            engine_read_bytes: out[3],
            engine_write_bytes: out[4],
            prefetch_pages: out[5],
            direct: out[6] != 0,
            cache_bytes: out[7],
            prefetch_bytes: out[8],
        })
    }
    pub fn get(&self, key: &[u8], max_bytes: usize) -> std::io::Result<Option<Vec<u8>>> {
        self.lookup()?.get(key, max_bytes)
    }
    /// Reusable, single-thread lookup scratch for a bounded batch. Returned values
    /// are owned; the last foreign result/ref is released when the scratch drops.
    pub fn lookup(&self) -> std::io::Result<Lookup<'_>> {
        let mut handle = std::ptr::null_mut();
        // SAFETY: live database and writable result; Lookup owns its C cleanup.
        status(unsafe { nv_sdb_lookup_new(self.handle()?, &mut handle) })?;
        Ok(Lookup { db: self, handle })
    }
    pub fn cursor<'a>(
        &'a self,
        from: &[u8],
        exclusive: bool,
        end: Option<&[u8]>,
    ) -> std::io::Result<Cursor<'a>> {
        let from = from.to_vec();
        let end = end.map(<[u8]>::to_vec);
        let mut handle = std::ptr::null_mut();
        // SAFETY: bounds' owned allocations are retained by Cursor; database outlives it.
        status(unsafe {
            nv_sdb_iter_open(
                self.handle()?,
                from.as_ptr(),
                from.len(),
                i32::from(exclusive),
                end.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
                end.as_ref().map_or(0, Vec::len),
                &mut handle,
            )
        })?;
        Ok(Cursor {
            handle,
            db: self,
            _from: from,
            _end: end,
        })
    }
    /// On failure upstream leaves the handle open, allowing an explicit retry.
    pub fn close(&mut self) -> std::io::Result<()> {
        if self.handle.is_null() {
            self.threads.take();
            self.caller.take();
            return Ok(());
        }
        self.handle()?;
        // SAFETY: mutable access excludes all cursors and lookups.
        let result = status(unsafe { nv_sdb_close(&mut self.handle, 0) });
        if self.handle.is_null() {
            self.threads.take();
            self.caller.take();
        }
        result
    }
}
impl Database {
    /// Raw handle for [`Mutator`]s on helper threads. Upstream permits concurrent
    /// inserts/deletes from distinct registered threads; this wrapper alone keeps
    /// every other call on the owner thread.
    pub fn shared_handle(&self) -> std::io::Result<SharedHandle> {
        Ok(SharedHandle(self.handle()?))
    }
}

/// Opaque native handle that may cross to a helper thread; it grants nothing until
/// [`Mutator::attach`] registers that thread.
#[derive(Clone, Copy, Debug)]
pub struct SharedHandle(*mut c_void);
// SAFETY: an inert pointer value; every use goes through `Mutator`'s contract.
unsafe impl Send for SharedHandle {}

/// Point mutations of one live database from a registered helper thread. Takes one
/// registered-thread credit (the same 63-slot budget as callers and maintenance
/// helpers) for this thread until dropped. Not `Send`: it stays on its thread.
#[derive(Debug)]
pub struct Mutator {
    handle: *mut c_void,
    caller: CallerLease,
}
impl Mutator {
    /// Registers the calling thread for `handle`.
    ///
    /// # Safety
    /// The database behind `handle` must stay open until this `Mutator` is dropped:
    /// its owner must not close or drop it earlier, and must not run cursors or
    /// lookups on keys a helper is mutating concurrently.
    pub unsafe fn attach(handle: SharedHandle) -> std::io::Result<Self> {
        if handle.0.is_null() {
            return Err(std::io::Error::from_raw_os_error(libc::EBADF));
        }
        Ok(Self {
            handle: handle.0,
            caller: CallerLease::acquire()?,
        })
    }
    fn live(&self) -> std::io::Result<*mut c_void> {
        self.caller.verify()?;
        Ok(self.handle)
    }
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> std::io::Result<()> {
        let handle = self.live()?;
        // SAFETY: registered thread, open database (attach contract), live slices.
        status(unsafe { nv_sdb_put(handle, key.as_ptr(), key.len(), value.as_ptr(), value.len()) })
    }
    pub fn delete(&mut self, key: &[u8]) -> std::io::Result<()> {
        let handle = self.live()?;
        // SAFETY: registered thread, open database (attach contract), live key.
        status(unsafe { nv_sdb_delete(handle, key.as_ptr(), key.len()) })
    }
    /// Blocking durability barrier from this registered thread: covers every
    /// update that returned before the call, from any registered thread.
    pub fn durable_barrier(&mut self) -> std::io::Result<()> {
        let handle = self.live()?;
        // SAFETY: registered thread, open database (attach contract).
        status(unsafe { nv_sdb_barrier(handle) })
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        if let Err(e) = self.close() {
            if self.caller.as_ref().is_some_and(CallerLease::poisoned) {
                // A different registration must not silently take over a live
                // DB or its borrowed state. Preserve unresolved native ownership
                // and helper/caller credits rather than auto-registering to close.
                std::mem::forget(self.threads.take());
                std::mem::forget(self.caller.take());
                eprintln!(
                    "SplinterDB poisoned owner: native handle and admission credits retained: {e}"
                );
                return;
            }
            eprintln!("SplinterDB close failed; forced teardown is NOT a durability success: {e}");
            // SAFETY: no borrowed users survive Database; force frees even on failure.
            let rc = unsafe { nv_sdb_close(&mut self.handle, 1) };
            if rc != 0 {
                eprintln!("SplinterDB forced close also reported error {rc}");
            }
        }
    }
}

#[derive(Debug)]
pub struct Lookup<'a> {
    db: &'a Database,
    handle: *mut c_void,
}
impl Lookup<'_> {
    pub fn get(&mut self, key: &[u8], max_bytes: usize) -> std::io::Result<Option<Vec<u8>>> {
        let mut value = std::ptr::null();
        let mut len = 0;
        let mut found = 0;
        // SAFETY: exclusively borrowed scratch tied to a live, single-thread DB.
        // The pinned synchronous lookup resets its preceding result on each call.
        status(unsafe {
            nv_sdb_lookup(
                self.db.handle()?,
                key.as_ptr(),
                key.len(),
                self.handle,
                &mut value,
                &mut len,
                &mut found,
            )
        })?;
        if found == 0 {
            return Ok(None);
        }
        if len > max_bytes {
            return Err(std::io::Error::from_raw_os_error(libc::E2BIG));
        }
        // SAFETY: result retains this span until the next mutable get or drop.
        let bytes = if len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(value, len) }
        };
        Ok(Some(bytes.to_vec()))
    }
}
impl Drop for Lookup<'_> {
    fn drop(&mut self) {
        if self.db.caller.as_ref().is_some_and(CallerLease::poisoned) {
            return; // Retain borrowed native state with the unresolved database.
        }
        // SAFETY: the database borrow outlives its scratch/result cleanup.
        unsafe { nv_sdb_lookup_free(self.handle) };
    }
}

#[derive(Debug)]
pub struct Cursor<'a> {
    handle: *mut c_void,
    db: &'a Database,
    _from: Vec<u8>,
    _end: Option<Vec<u8>>,
}
impl Cursor<'_> {
    pub fn current(&mut self) -> std::io::Result<Option<(&[u8], &[u8])>> {
        self.db.handle()?;
        let mut key = std::ptr::null();
        let mut value = std::ptr::null();
        let mut kn = 0;
        let mut vn = 0;
        let mut found = 0;
        // SAFETY: valid iterator/output storage; C checks status after blob materialization.
        status(unsafe {
            nv_sdb_iter_current(
                self.handle,
                &mut key,
                &mut kn,
                &mut value,
                &mut vn,
                &mut found,
            )
        })?;
        if found == 0 {
            return Ok(None);
        }
        // SAFETY: spans remain borrowed until the next mutable iterator operation.
        let k = if kn == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(key, kn) }
        };
        let v = if vn == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(value, vn) }
        };
        Ok(Some((k, v)))
    }
    pub fn advance(&mut self) -> std::io::Result<()> {
        self.db.handle()?;
        // SAFETY: exclusively borrowed live iterator, bounds retained by this handle.
        status(unsafe { nv_sdb_iter_next(self.handle) })
    }
}
impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        if self.db.caller.as_ref().is_some_and(CallerLease::poisoned) {
            // The retained C iterator may still hold its original bound slices.
            std::mem::forget(std::mem::take(&mut self._from));
            if let Some(end) = self._end.take() {
                std::mem::forget(end);
            }
            return; // Retain borrowed native state with the unresolved database.
        }
        unsafe { nv_sdb_iter_close(self.handle) };
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn registered_thread_budget_checks_aggregate_limit_and_releases_exact_credits() {
        let budget = ThreadBudget::default();
        let owners_and_helpers = budget.reserve(62).unwrap();
        assert_eq!(
            budget.reserve(2).unwrap_err().raw_os_error(),
            Some(libc::EAGAIN)
        );
        let caller = budget.reserve(1).unwrap();
        assert!(budget.reserve(1).is_err());
        drop(owners_and_helpers);
        let helper = budget.reserve(1).unwrap();
        assert_eq!(budget.0.load(Ordering::Acquire), 2);
        drop(helper);
        drop(caller);
        assert_eq!(budget.0.load(Ordering::Acquire), 0);
        assert!(budget.reserve(usize::MAX).is_err());
        assert_eq!(budget.0.load(Ordering::Acquire), 0);
    }

    #[test]
    fn concurrent_admission_cannot_consume_an_already_reserved_slot() {
        let budget = ThreadBudget::default();
        let held = budget.reserve(THREAD_SLOTS).unwrap();
        std::thread::scope(|scope| {
            let children: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        assert_eq!(
                            budget.reserve(1).unwrap_err().raw_os_error(),
                            Some(libc::EAGAIN),
                        )
                    })
                })
                .collect();
            for child in children {
                child.join().unwrap();
            }
        });
        assert_eq!(budget.0.load(Ordering::Acquire), THREAD_SLOTS);
        drop(held);
        assert!(budget.reserve(THREAD_SLOTS).is_ok());
    }

    #[test]
    fn caller_registration_is_shared_until_last_lease_and_can_be_reacquired() {
        for _ in 0..80 {
            let a = CallerLease::acquire().unwrap();
            let b = CallerLease::acquire().unwrap();
            assert_eq!(a.state.borrow().handles, 2);
            drop(a);
            assert_eq!(b.state.borrow().handles, 1);
            drop(b);
            CALLER.with(|state| {
                let state = state.borrow();
                assert_eq!(state.handles, 0);
                assert!(state.lease.is_none());
                assert!(!state.poisoned);
            });
        }
    }

    #[test]
    fn nested_open_failure_poisoning_does_not_wait_for_the_last_live_handle() {
        // Independent registry/failure model: A stays live while B's open loses
        // registration. No native thread-create fault or invalid native handle
        // is needed to exercise the wrapper's open-result and lease ordering.
        let budget: &'static ThreadBudget = Box::leak(Box::new(ThreadBudget::default()));
        let state = Rc::new(RefCell::new(CallerState {
            handles: 2,
            lease: Some(budget.reserve(1).unwrap()),
            registration: 7,
            poisoned: false,
        }));
        let a = CallerLease {
            state: Rc::clone(&state),
        };
        let b = CallerLease {
            state: Rc::clone(&state),
        };
        let result: std::io::Result<()> =
            verify_open_attempt(Err(std::io::Error::from_raw_os_error(libc::EIO)), || {
                state.borrow_mut().check_registration(false)
            });
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EOWNERDEAD));
        assert!(a.poisoned());
        drop(b);
        assert_eq!(state.borrow().handles, 1);
        // Even a subsequent matching identity cannot rehabilitate the caller
        // or authorize a new acquisition using the old admission credit.
        assert_eq!(
            state
                .borrow_mut()
                .check_registration(true)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EOWNERDEAD)
        );
        drop(a);
        assert_eq!(state.borrow().handles, 0);
        assert_eq!(budget.0.load(Ordering::Acquire), 1);
    }

    #[test]
    fn successful_native_open_is_also_checked_for_registration_loss() {
        let mut caller = CallerState::default();
        let result = verify_open_attempt(Ok(17), || caller.check_registration(false));
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EOWNERDEAD));
        assert!(caller.poisoned);
    }
}
