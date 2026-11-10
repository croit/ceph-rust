// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Crash dump writer (spec/ops-observability.md 4): on a panic, write `<crash_dir>/<crash_id>/{meta,log,done}` in the
//! layout the host's `ceph-crash` agent posts to the mgr crash module (`RECENT_CRASH`, `ceph crash ls/info`).
//!
//! The panic hook runs on the panicking core before the process aborts (`panic = "abort"`); it only formats strings and
//! writes two small files and aborts even in unwind builds. Linux daemon startup suppresses native cores with
//! `PR_SET_DUMPABLE=0` (`LimitCORE=0` alone does not exclude piped collectors: cores hold keys and data).
//!
//! Fatal signals (SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGXCPU, SIGXFSZ, SIGSYS: FFI in SPDK/liburing/verbs, unsafe code, `abort()` of the
//! liveness watchdog) get a minimal dump from a signal handler that only uses async-signal-safe calls (clock_gettime,
//! mkdir, open, openat, fstat, fchown, write, fsync, close, renameat): everything else (dir, crash uuid, static meta
//! fields, the crash dir's owner) is prepared at install. No backtrace and no log tail (neither is signal-safe);
//! `signal` and `fault_addr` name the failure. The handler runs once (SA_RESETHAND, on the thread's alternate stack when
//! it has one), then re-raises: the default action ends the process with the same signal. A panic writes its own dump
//! and suppresses the one of its SIGABRT.
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Mutex, Once};

/// Who crashed.
#[derive(Clone, Debug)]
pub struct CrashCfg {
    /// `/var/lib/ceph/crash`
    pub dir: PathBuf,
    /// `osd.N`
    pub entity: String,
    pub version: String,
    pub process: String,
    /// Data device serial (the `bluestore_bdev_serial`/`flashstore_bdev_serial` boot key): names which drive a crash came
    /// from. Empty before the store device identity is known (the early command-line install).
    pub device_serial: String,
    /// Data device model, same provenance as [`Self::device_serial`].
    pub device_model: String,
}

/// Log lines kept for the dump (`log` file).
const TAIL_LINES: usize = 400;

/// The current configuration (leaked `Box`, replaced by every [`install`]; null = none yet). A plain atomic pointer: the
/// panic hook reads it without a lock. Replaced ones stay allocated (a hook may still read them; a handful per process).
static CFG: AtomicPtr<CrashCfg> = AtomicPtr::new(std::ptr::null_mut());

/// The configuration a dump goes to; `None` before the first [`install`] and when `crash_dir` is empty (disabled).
fn current() -> Option<&'static CrashCfg> {
    // SAFETY: CFG only ever holds null or a leaked, never freed `Box<CrashCfg>`
    unsafe { CFG.load(Ordering::Acquire).as_ref() }.filter(|c| !c.dir.as_os_str().is_empty())
}
static TAIL: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Remember a log line for the crash dump (cold path: called per emitted log line).
pub fn note(line: &str) {
    if let Ok(mut t) = TAIL.lock() {
        if t.len() >= TAIL_LINES {
            t.pop_front();
        }
        t.push_back(line.to_owned());
    }
}

fn tail_text() -> String {
    // the hook must never block on a lock the panicking thread may hold
    match TAIL.try_lock() {
        Ok(t) => t.iter().fold(String::new(), |mut s, l| {
            s.push_str(l);
            s.push('\n');
            s
        }),
        Err(_) => String::new(),
    }
}

fn rd(p: &str) -> String {
    std::fs::read_to_string(p)
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

/// `2026-10-10T12:34:56.123456Z` (UTC, classic `utime_t::gmtime`).
pub fn iso_utc(d: std::time::Duration) -> String {
    let mut b = sig::Buf::new();
    sig::iso_utc_into(&mut b, d.as_secs(), u64::from(d.subsec_micros()));
    String::from_utf8_lossy(b.bytes()).into_owned()
}

fn gmtime(t: std::time::SystemTime) -> String {
    iso_utc(t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default())
}

fn os_release(key: &str) -> Option<String> {
    let t = std::fs::read_to_string("/etc/os-release").ok()?;
    t.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k == key).then(|| v.trim_matches('"').to_owned())
    })
}

/// Add the os-release keys of the classic crash meta document to `m`.
fn os_fields(m: &mut Value) {
    for (k, key) in [
        ("os_name", "NAME"),
        ("os_id", "ID"),
        ("os_version_id", "VERSION_ID"),
        ("os_version", "VERSION"),
    ] {
        if let Some(v) = os_release(key) {
            m[k] = Value::String(v);
        }
    }
}

/// Add the data device identity (serial, model) to `m`: ties a crash to the block device it came from. Empty values
/// (before the store identity is known) are omitted, never invented.
fn device_fields(m: &mut Value, serial: &str, model: &str) {
    if !serial.is_empty() {
        m["device_serial"] = Value::String(serial.to_owned());
    }
    if !model.is_empty() {
        m["device_model"] = Value::String(model.to_owned());
    }
}

/// Frames of a captured backtrace in the classic shape ` N: (function+0x0) [0x0]` (the mgr crash module derives the
/// stack signature from the text before the last space of each frame), source-location lines dropped, the panic
/// machinery on top (hook, `core::panicking`) cut off.
fn frames(bt: &str) -> Vec<String> {
    let funcs: Vec<&str> = bt
        .lines()
        .filter_map(|l| {
            let (n, rest) = l.trim_start().split_once(": ")?;
            n.chars().all(|c| c.is_ascii_digit()).then_some(rest)
        })
        .collect();
    let skip = funcs
        .iter()
        .take(16)
        .rposition(|f| f.contains("rust_begin_unwind") || f.contains("core::panicking::"))
        .map_or(0, |i| i + 1);
    funcs[skip..]
        .iter()
        .enumerate()
        .map(|(i, f)| format!(" {}: ({f}+0x0) [0x0]", i + 1))
        .collect()
}

/// What a dump records about the failure.
#[derive(Debug)]
pub struct Failure<'a> {
    pub msg: &'a str,
    pub file: &'a str,
    pub line: u32,
    pub thread: &'a str,
    pub backtrace: &'a str,
}

/// Write `<dir>/<crash_id>/{meta,log,done}`; `meta` appears atomically (rename) so `ceph-crash` never posts half a
/// file. The dump directory is `0700` and every file `0600` (a dump carries host details, the stack and the log tail,
/// and the log can hold admin-command values). The dir stays owned by the writer until the dump is complete, then it
/// is handed to the owner of the crash directory (the user the host's agent that posts it runs as, `ceph`), so a
/// root-run OSD (SPDK tier) leaves a dump it can read. The dir is opened once `O_NOFOLLOW` (fstat: it must be a
/// directory the process owns) and every file is created inside it with `openat(O_EXCL|O_NOFOLLOW)` and chowned
/// through its fd: a symlink planted under a dump name is never followed.
pub fn write_dump(cfg: &CrashCfg, f: &Failure<'_>, tail: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    if cfg.dir.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "crash dumps disabled (empty crash_dir)",
        ));
    }
    let now = std::time::SystemTime::now();
    let ts = gmtime(now);
    let id = format!(
        "{ts}_{}",
        cephx::challenge::random_uuid_v4().map_err(|e| std::io::Error::other(format!("{e:?}")))?
    );
    let dir = cfg.dir.join(&id);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    let owner = match owner(&cfg.dir) {
        Ok(o) => Some(o),
        Err(e) => {
            eprintln!(
                "croit-flashstore-osd: WARNING crash dump: crash dir {}: {e} (the dump keeps the writer's owner)",
                cfg.dir.display()
            );
            None
        }
    };
    let mut m = json!({
        "crash_id": id,
        "timestamp": ts,
        "process_name": cfg.process,
        "entity_name": cfg.entity,
        "ceph_version": cfg.version,
        "utsname_hostname": rd("/proc/sys/kernel/hostname"),
        "utsname_sysname": "Linux",
        "utsname_release": rd("/proc/sys/kernel/osrelease"),
        "utsname_version": rd("/proc/sys/kernel/version"),
        "utsname_machine": std::env::consts::ARCH,
        "assert_condition": "panic",
        "assert_func": "",
        "assert_file": f.file,
        "assert_line": f.line,
        "assert_thread_name": f.thread,
        "assert_msg": format!(
            "{} In function 'panic' thread {} time {ts}\n{}: {}: FAILED panic({})\n",
            f.file, f.thread, f.file, f.line, f.msg
        ),
        "backtrace": frames(f.backtrace),
    });
    os_fields(&mut m);
    device_fields(&mut m, &cfg.device_serial, &cfg.device_model);
    dump_into(&dir, &m, tail, owner)?;
    Ok(dir)
}

/// The dump into the fresh `dir` (created `0700` by the caller): `log`, then `meta` (atomic via `meta.tmp`), then
/// `done`; the dir is handed to `owner` only once `done` is written and synced, and the dir is fsynced after.
fn dump_into(
    dir: &std::path::Path,
    m: &Value,
    tail: &str,
    owner: Option<(u32, u32)>,
) -> std::io::Result<()> {
    let d = open_dump_dir(dir)?;
    create_file(&d, "log", tail.as_bytes(), owner).map_err(|e| named(dir, e))?;
    create_file(
        &d,
        "meta.tmp",
        serde_json::to_string_pretty(m)?.as_bytes(),
        owner,
    )
    .map_err(|e| named(dir, e))?;
    rename_in(&d, "meta.tmp", "meta").map_err(|e| named(dir, e))?;
    create_file(&d, "done", b"", owner).map_err(|e| named(dir, e))?;
    if let Some((uid, gid)) = owner {
        chown_fd_warn(&d, &dir.display().to_string(), uid, gid);
    }
    d.sync_all().map_err(|e| named(dir, e))?;
    Ok(())
}

/// A dump-file error with the dump dir in front of it.
fn named(dir: &std::path::Path, e: std::io::Error) -> std::io::Error {
    std::io::Error::new(e.kind(), format!("{}: {e}", dir.display()))
}

/// Open the dump dir for writing (final component never a symlink) and verify by fstat that it is a directory owned
/// by our euid: we created it moments ago, anything else is a planted entry we refuse to write into.
fn open_dump_dir(dir: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: NUL-terminated path; the fd is owned by the returned File.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        eprintln!(
            "croit-flashstore-osd: WARNING crash dump {}: the dump dir cannot be opened, the dump is aborted",
            dir.display()
        );
        return Err(std::io::Error::last_os_error());
    }
    if !fd_is_our_dir(fd) {
        // SAFETY: close the fd, no longer owned
        unsafe { libc::close(fd) };
        eprintln!(
            "croit-flashstore-osd: WARNING crash dump {}: not a directory owned by this process, the dump is aborted",
            dir.display()
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "dump dir not owned by this process",
        ));
    }
    // SAFETY: fd is open and owned by the File from here on.
    Ok(unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) })
}

/// fstat of `fd`: a directory owned by our euid.
fn fd_is_our_dir(fd: std::os::fd::RawFd) -> bool {
    // SAFETY: fd is open; a zeroed `stat` is a valid value (it is overwritten by fstat)
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return false;
    }
    (st.st_mode & libc::S_IFMT) == libc::S_IFDIR && st.st_uid == unsafe { libc::geteuid() }
}

/// Create `name` in the open dump dir (`O_EXCL|O_NOFOLLOW`, 0600: a stale or planted entry is refused, never
/// followed), fchown it to `owner` through the fd (a failure only warns), write `data` and fsync it.
fn create_file(
    dir: &std::fs::File,
    name: &str,
    data: &[u8],
    owner: Option<(u32, u32)>,
) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    let c = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: dirfd is open for the life of `dir`; the name is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is open and owned by the File from here on.
    let mut f = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    if let Some((uid, gid)) = owner {
        chown_fd_warn(&f, name, uid, gid);
    }
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// `renameat` inside the open dump dir (`meta.tmp` -> `meta`): the rename replaces a symlink at the name itself,
/// never writes through it.
fn rename_in(dir: &std::fs::File, from: &str, to: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let c = |n: &str| {
        std::ffi::CString::new(n)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
    };
    let (cf, ct) = (c(from)?, c(to)?);
    // SAFETY: both names are NUL-terminated and relative to the open dir.
    if unsafe { libc::renameat(dir.as_raw_fd(), cf.as_ptr(), dir.as_raw_fd(), ct.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// fchown of a written dump entry through its fd: a dump the collector cannot read is still worth writing, so a
/// failure is announced and never fails the dump.
fn chown_fd_warn(f: &std::fs::File, what: &str, uid: u32, gid: u32) {
    use std::os::fd::AsRawFd as _;
    // SAFETY: f is open
    if unsafe { libc::fchown(f.as_raw_fd(), uid, gid) } != 0 {
        eprintln!(
            "croit-flashstore-osd: WARNING crash dump {what}: chown {uid}:{gid}: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// `(uid, gid)` that own the crash directory (`ceph-crash` runs as that user by default and posts only dumps it can
/// read): opened `O_NOFOLLOW` and read off the fd, never through a path that follows a symlink in the final
/// component.
fn owner(dir: &std::path::Path) -> std::io::Result<(u32, u32)> {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: NUL-terminated path
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is open; a zeroed `stat` is a valid value (it is overwritten by fstat)
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstat(fd, &mut st) };
    unsafe { libc::close(fd) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((st.st_uid, st.st_gid))
}

/// Install or refine crash reporting: the panic hook (the previous hook still runs afterwards: message on stderr, then
/// the process aborts) and the fatal-signal handler, both once per process; every call replaces the configuration they
/// use. The daemon calls it first thing at start with what its command line says (classic installs its handlers during
/// global init, before the store is touched), again once the conf file is resolved, and finally with the effective
/// config and the OSD's identity. An empty `crash_dir` disables the dump files; a panic still ends the process. The
/// directory is not created here (the caller creates it as the user the daemon runs as: the dump's owner is the crash
/// directory's, resolved now).
pub fn install(cfg: CrashCfg) {
    let enabled = !cfg.dir.as_os_str().is_empty();
    if enabled {
        sig::prepare(&cfg);
    } else {
        sig::disable();
    }
    CFG.store(Box::into_raw(Box::new(cfg)), Ordering::Release);
    static HOOKS: Once = Once::new();
    HOOKS.call_once(|| {
        sig::install();
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            DUMPED.store(true, Ordering::SeqCst);
            if let Some(cfg) = current() {
                let msg = match info.payload().downcast_ref::<&str>() {
                    Some(s) => (*s).to_owned(),
                    None => info
                        .payload()
                        .downcast_ref::<String>()
                        .cloned()
                        .unwrap_or_else(|| "panic".into()),
                };
                let (file, line) = info.location().map_or(("", 0), |l| (l.file(), l.line()));
                let th = std::thread::current();
                let bt = std::backtrace::Backtrace::force_capture().to_string();
                let f = Failure {
                    msg: &msg,
                    file,
                    line,
                    thread: th.name().unwrap_or("?"),
                    backtrace: &bt,
                };
                match write_dump(cfg, &f, &tail_text()) {
                    Ok(d) => eprintln!(
                        "croit-flashstore-osd: crash dump written to {}",
                        d.display()
                    ),
                    Err(e) => eprintln!("croit-flashstore-osd: crash dump failed: {e}"),
                }
            }
            prev(info);
            // A core cannot be replaced while the others keep its PGs' peers waiting: fail-stop in every build (the
            // release profile aborts anyway; an unwind build would otherwise lose the core and keep running).
            std::process::abort();
        }));
    });
}

/// A dump was written (panic) or is being written (signal): the process ends, no second dump.
static DUMPED: AtomicBool = AtomicBool::new(false);

/// The fatal-signal dump: prepared at install, written from the handler with async-signal-safe calls only.
mod sig {
    use super::{DUMPED, Ordering};
    use std::sync::atomic::AtomicPtr;

    /// Everything the handler needs that is not known before the crash.
    struct Prep {
        /// `<crash dir>` bytes (no NUL).
        dir: Vec<u8>,
        /// `_<uuid>` suffix of the crash id.
        id_suffix: String,
        /// meta fields after `timestamp` (with leading comma), entity/version/uname/os.
        fields: String,
        /// Owner of the crash directory: the handler hands it the dump dir and files (fchown).
        owner: Option<(u32, u32)>,
    }

    /// The current preparation (leaked `Box`, replaced by [`prepare`], null = no dump): one atomic load in the handler.
    static PREP: AtomicPtr<Prep> = AtomicPtr::new(std::ptr::null_mut());

    pub(super) const SIGNALS: [(i32, &str); 8] = [
        (libc::SIGSEGV, "SIGSEGV"),
        (libc::SIGBUS, "SIGBUS"),
        (libc::SIGILL, "SIGILL"),
        (libc::SIGFPE, "SIGFPE"),
        (libc::SIGABRT, "SIGABRT"),
        (libc::SIGXCPU, "SIGXCPU"),
        (libc::SIGXFSZ, "SIGXFSZ"),
        (libc::SIGSYS, "SIGSYS"),
    ];

    /// Precompute everything the handler writes for `cfg` (replaces the previous preparation).
    pub(super) fn prepare(cfg: &super::CrashCfg) {
        let mut m = serde_json::json!({
            "process_name": cfg.process,
            "entity_name": cfg.entity,
            "ceph_version": cfg.version,
            "utsname_hostname": super::rd("/proc/sys/kernel/hostname"),
            "utsname_sysname": "Linux",
            "utsname_release": super::rd("/proc/sys/kernel/osrelease"),
            "utsname_version": super::rd("/proc/sys/kernel/version"),
            "utsname_machine": std::env::consts::ARCH,
            "backtrace": [],
        });
        super::os_fields(&mut m);
        super::device_fields(&mut m, &cfg.device_serial, &cfg.device_model);
        let body = m.to_string(); // `{...}`
        let prep = Prep {
            dir: cfg.dir.as_os_str().as_encoded_bytes().to_vec(),
            id_suffix: format!(
                "_{}",
                cephx::challenge::random_uuid_v4().expect("system randomness unavailable")
            ),
            fields: format!(",{}", &body[1..body.len() - 1]),
            owner: super::owner(&cfg.dir).ok(),
        };
        // a replaced preparation stays allocated: a handler on another thread may be reading it
        PREP.store(Box::into_raw(Box::new(prep)), Ordering::Release);
    }

    /// No dump from the handler (empty `crash_dir`); the signal still ends the process.
    pub(super) fn disable() {
        PREP.store(std::ptr::null_mut(), Ordering::Release);
    }

    /// The handlers for [`SIGNALS`] (once per process).
    pub(super) fn install() {
        for (s, _) in SIGNALS {
            // SAFETY: plain sigaction with a handler that only calls async-signal-safe functions
            unsafe {
                let mut sa: libc::sigaction = std::mem::zeroed();
                sa.sa_sigaction = handler as *const () as usize;
                sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_RESETHAND;
                libc::sigemptyset(&mut sa.sa_mask);
                libc::sigaction(s, &sa, std::ptr::null_mut());
            }
        }
    }

    /// Fixed-size, allocation-free byte buffer (the handler never allocates).
    pub(super) struct Buf {
        b: [u8; 4096],
        n: usize,
    }

    impl Buf {
        pub(super) const fn new() -> Self {
            Self { b: [0; 4096], n: 0 }
        }
        /// Append (truncated at capacity; the last byte always stays NUL for syscall paths).
        pub(super) fn push(&mut self, s: &[u8]) {
            let k = s.len().min(self.b.len() - 1 - self.n);
            self.b[self.n..self.n + k].copy_from_slice(&s[..k]);
            self.n += k;
            self.b[self.n] = 0;
        }
        fn clear(&mut self) {
            self.n = 0;
            self.b[0] = 0;
        }
        /// NUL-terminated contents (for a syscall path).
        fn c_ptr(&self) -> *const libc::c_char {
            self.b.as_ptr().cast()
        }
        /// Zero-padded decimal of `width` digits.
        pub(super) fn dec(&mut self, mut v: u64, width: usize) {
            let mut d = [b'0'; 20];
            let mut i = d.len();
            while v > 0 || i == d.len() {
                i -= 1;
                d[i] = b'0' + (v % 10) as u8;
                v /= 10;
            }
            let digits = d.len() - i;
            for _ in digits..width {
                self.push(b"0");
            }
            self.push(&d[i..]);
        }
        pub(super) fn hex(&mut self, v: u64) {
            self.push(b"0x");
            let mut started = false;
            for sh in (0..16).rev() {
                let x = ((v >> (sh * 4)) & 0xf) as usize;
                if x != 0 || started || sh == 0 {
                    started = true;
                    self.push(&[b"0123456789abcdef"[x]]);
                }
            }
        }
        pub(super) fn bytes(&self) -> &[u8] {
            &self.b[..self.n]
        }
    }

    /// `2026-10-10T12:34:56.123456Z` without allocating (`iso_utc` is built on it).
    pub(super) fn iso_utc_into(b: &mut Buf, secs: u64, micros: u64) {
        let (y, m, d, h, mi, s) = osddir::civil_from_secs(secs);
        b.dec(y, 4);
        b.push(b"-");
        b.dec(m, 2);
        b.push(b"-");
        b.dec(d, 2);
        b.push(b"T");
        b.dec(h, 2);
        b.push(b":");
        b.dec(mi, 2);
        b.push(b":");
        b.dec(s, 2);
        b.push(b".");
        b.dec(micros, 6);
        b.push(b"Z");
    }

    /// The meta document for `sig` at `ts` (pure: also used by the tests).
    pub(super) fn meta_into(
        b: &mut Buf,
        ts: &[u8],
        id_suffix: &str,
        fields: &str,
        sig: i32,
        addr: u64,
    ) {
        let name = SIGNALS
            .iter()
            .find(|(s, _)| *s == sig)
            .map_or("signal", |(_, n)| *n);
        b.push(b"{\"crash_id\":\"");
        b.push(ts);
        b.push(id_suffix.as_bytes());
        b.push(b"\",\"timestamp\":\"");
        b.push(ts);
        b.push(b"\"");
        b.push(fields.as_bytes());
        b.push(b",\"signal\":\"");
        b.push(name.as_bytes());
        b.push(b"\",\"signal_number\":");
        b.dec(sig as u64, 1);
        b.push(b",\"fault_addr\":\"");
        b.hex(addr);
        b.push(b"\"}");
    }

    /// Open the dump dir (final component never a symlink) and verify by fstat that it is a directory owned by our
    /// euid; `-1` when it is not (the dump is aborted: we would write into a planted entry).
    pub(super) fn open_dir(dir: &Buf) -> libc::c_int {
        // SAFETY: async-signal-safe syscalls; `dir` is NUL-terminated
        unsafe {
            let fd = libc::open(
                dir.c_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            );
            if fd < 0 {
                return -1;
            }
            // a zeroed `stat` is a valid value (overwritten by fstat)
            let mut st: libc::stat = std::mem::zeroed();
            let ok = libc::fstat(fd, &mut st) == 0
                && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR
                && st.st_uid == libc::geteuid();
            if !ok {
                libc::close(fd);
                let m = b"croit-flashstore-osd: WARNING crash dump: the dump dir is not a directory owned by this process, the dump is aborted\n";
                libc::write(2, m.as_ptr().cast(), m.len());
                return -1;
            }
            fd
        }
    }

    /// Create `name` in the open dump dir (`O_EXCL|O_NOFOLLOW`, 0600: a stale or planted entry is refused, never
    /// followed), fchown it to `owner` through the fd (a failure only writes the WARNING), write `data` and fsync it.
    pub(super) fn create_file(
        dirfd: libc::c_int,
        name: &Buf,
        data: &[u8],
        owner: Option<(u32, u32)>,
    ) -> bool {
        // SAFETY: async-signal-safe syscalls; `name` is NUL-terminated; dirfd is open
        unsafe {
            let fd = libc::openat(
                dirfd,
                name.c_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            );
            if fd < 0 {
                return false;
            }
            if let Some((uid, gid)) = owner
                && libc::fchown(fd, uid, gid) != 0
            {
                // loud (write(2) is async-signal-safe), the dump is still worth writing
                let m = b"croit-flashstore-osd: WARNING crash dump chown failed\n";
                libc::write(2, m.as_ptr().cast(), m.len());
            }
            let mut off = 0;
            while off < data.len() {
                let w = libc::write(fd, data[off..].as_ptr().cast(), data.len() - off);
                if w <= 0 {
                    break;
                }
                off += w as usize;
            }
            libc::fsync(fd);
            libc::close(fd);
            off == data.len()
        }
    }

    /// The handler's buffers: static, not on the signal stack (the alternate stack of a thread is only a few KiB).
    /// Used by the one thread that won `DUMPED`.
    struct Scratch(std::cell::UnsafeCell<[Buf; 5]>);
    // SAFETY: only the thread that set `DUMPED` touches it, once
    unsafe impl Sync for Scratch {}
    static SCRATCH: Scratch = Scratch(std::cell::UnsafeCell::new([const { Buf::new() }; 5]));

    fn dump(sig: i32, addr: u64) {
        // SAFETY: PREP only ever holds null or a leaked, never freed `Box<Prep>` (an atomic load is signal-safe)
        let Some(p) = (unsafe { PREP.load(Ordering::Acquire).as_ref() }) else {
            return;
        };
        // SAFETY: the caller won `DUMPED`: no other access to SCRATCH, now or later
        let [ts, dir, meta, a, b] = unsafe { &mut *SCRATCH.0.get() };
        for x in [&mut *ts, &mut *dir, &mut *meta, &mut *a, &mut *b] {
            x.clear();
        }
        // SAFETY: clock_gettime is async-signal-safe
        let now = unsafe {
            let mut t: libc::timespec = std::mem::zeroed();
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut t);
            t
        };
        iso_utc_into(ts, now.tv_sec as u64, now.tv_nsec as u64 / 1000);
        dir.push(&p.dir);
        dir.push(b"/");
        dir.push(ts.bytes());
        dir.push(p.id_suffix.as_bytes());
        // SAFETY: mkdir is async-signal-safe; NUL-terminated path
        unsafe {
            libc::mkdir(dir.c_ptr(), 0o700);
        }
        // the dir stays ours until the dump is complete: opened once (verified), every entry relative to that fd
        let d = open_dir(dir);
        if d < 0 {
            return;
        }
        meta_into(meta, ts.bytes(), &p.id_suffix, &p.fields, sig, addr);
        a.clear();
        a.push(b"meta.tmp");
        if !create_file(d, a, meta.bytes(), p.owner) {
            unsafe { libc::close(d) };
            return;
        }
        b.clear();
        b.push(b"meta");
        // SAFETY: renameat is async-signal-safe; both names are relative to the open dir
        if unsafe { libc::renameat(d, a.c_ptr(), d, b.c_ptr()) } != 0 {
            unsafe { libc::close(d) };
            return;
        }
        a.clear();
        a.push(b"done");
        if !create_file(d, a, b"", p.owner) {
            unsafe { libc::close(d) };
            return;
        }
        // hand the directory over last, then sync it: only now can the collector (the crash dir's owner) read it
        if let Some((uid, gid)) = p.owner
            && unsafe { libc::fchown(d, uid, gid) } != 0
        {
            // loud (write(2) is async-signal-safe), the dump is still worth writing
            let m = b"croit-flashstore-osd: WARNING crash dump chown failed\n";
            unsafe {
                libc::write(2, m.as_ptr().cast(), m.len());
            }
        }
        unsafe {
            libc::fsync(d);
            libc::close(d);
        }
        b.clear();
        b.push(b"croit-flashstore-osd: fatal signal, crash dump written to ");
        b.push(dir.bytes());
        b.push(b"\n");
        // SAFETY: write(2) to stderr is async-signal-safe
        unsafe {
            libc::write(2, b.bytes().as_ptr().cast(), b.bytes().len());
        }
    }

    extern "C" fn handler(sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
        if !DUMPED.swap(true, Ordering::SeqCst) {
            // SAFETY: the kernel passes a valid siginfo for SA_SIGINFO handlers
            let addr = if info.is_null() {
                0
            } else {
                unsafe { (*info).si_addr() as u64 }
            };
            dump(sig, addr);
        }
        // SA_RESETHAND restored the default action: re-raise so the process ends with this signal (a hardware fault
        // also re-faults on return)
        // SAFETY: raise is async-signal-safe
        unsafe {
            libc::raise(sig);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_crash_directory_refuses_filesystem_output() {
        let result = write_dump(
            &CrashCfg {
                dir: PathBuf::new(),
                entity: "osd.9".into(),
                version: "v".into(),
                process: "croit-flashstore-osd".into(),
                device_serial: String::new(),
                device_model: String::new(),
            },
            &Failure {
                msg: "disabled",
                file: "test",
                line: 1,
                thread: "test",
                backtrace: "",
            },
            "",
        );
        // Clean up the old implementation's relative output when demonstrating fail-before.
        if let Ok(dir) = &result {
            std::fs::remove_dir_all(dir).unwrap();
        }
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    /// An unwind-capable binary must still terminate the whole daemon, even if a caller catches panics.
    #[test]
    fn panic_is_process_fatal_with_or_without_dumps() {
        const CHILD: &str = "FLASHSTORE_PANIC_CHILD";
        if let Some(dir) = std::env::var_os(CHILD) {
            // Keep this regression from creating a native core on developer machines.
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: valid pointer to this process's limit.
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
            install(CrashCfg {
                dir: dir.into(),
                entity: "osd.9".into(),
                version: "v".into(),
                process: "croit-flashstore-osd".into(),
                device_serial: String::new(),
                device_model: String::new(),
            });
            note("last diagnostic");
            let _ = std::panic::catch_unwind(|| panic!("fatal owner core"));
            std::process::exit(42);
        }
        let root = std::env::temp_dir().join(format!("crash-panic-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        for enabled in [false, true] {
            let cwd = root.join(if enabled { "enabled" } else { "disabled" });
            std::fs::create_dir_all(&cwd).unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "crash::tests::panic_is_process_fatal_with_or_without_dumps",
                ])
                .env(
                    CHILD,
                    if enabled {
                        cwd.as_os_str()
                    } else {
                        std::ffi::OsStr::new("")
                    },
                )
                .current_dir(&cwd)
                .spawn()
                .unwrap();
            let start = std::time::Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if start.elapsed() > std::time::Duration::from_secs(10) {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("WARNING TIMEOUT panic child exceeded 10s (enabled={enabled})");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(libc::SIGABRT), "{status}");
            let dumps: Vec<_> = std::fs::read_dir(&cwd)
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert_eq!(dumps.len(), usize::from(enabled));
            if enabled {
                let dump = dumps[0].path();
                assert!(dump.join("done").exists());
                assert_eq!(
                    std::fs::read_to_string(dump.join("log")).unwrap(),
                    "last diagnostic\n"
                );
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    /// NT-crashreport-07: the early (command line) install already reports a crash; a later install replaces its
    /// directory and identity for both the panic and the signal path. Runs itself as a child per path.
    #[test]
    fn reinstall_refines_the_early_crash_config() {
        const CHILD: &str = "FLASHSTORE_REINSTALL_CHILD";
        if let Ok(mode) = std::env::var(CHILD) {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: valid pointer, affects only this test child.
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
            let root = PathBuf::from(std::env::var("FLASHSTORE_REINSTALL_ROOT").unwrap());
            let cfg = |dir: &str, entity: &str, serial: &str| CrashCfg {
                dir: if dir.is_empty() {
                    PathBuf::new()
                } else {
                    root.join(dir)
                },
                entity: entity.into(),
                version: "v".into(),
                process: "croit-flashstore-osd".into(),
                device_serial: serial.into(),
                device_model: if serial.is_empty() {
                    String::new()
                } else {
                    "MODELX".into()
                },
            };
            install(cfg("early", "osd", ""));
            if mode == "early" {
                panic!("before the store mount");
            }
            install(cfg("final", "osd.7", "SER12345"));
            if mode == "disabled" {
                install(cfg("", "osd.7", ""));
            }
            if mode == "panic" {
                panic!("after setup");
            }
            // SAFETY: deliberate fatal signal for the test child
            unsafe {
                libc::raise(libc::SIGSEGV);
            }
            unreachable!();
        }
        for (mode, want_sig, want) in [
            ("early", libc::SIGABRT, Some(("early", "osd"))),
            ("panic", libc::SIGABRT, Some(("final", "osd.7"))),
            ("signal", libc::SIGSEGV, Some(("final", "osd.7"))),
            ("disabled", libc::SIGSEGV, None),
        ] {
            let root =
                std::env::temp_dir().join(format!("crash-reinst-{}-{mode}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            for d in ["early", "final"] {
                std::fs::create_dir_all(root.join(d)).unwrap();
            }
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "crash::tests::reinstall_refines_the_early_crash_config",
                ])
                .env(CHILD, mode)
                .env("FLASHSTORE_REINSTALL_ROOT", &root)
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let start = std::time::Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if start.elapsed() > std::time::Duration::from_secs(10) {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("WARNING TIMEOUT reinstall child exceeded 10s ({mode})");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            use std::os::unix::process::ExitStatusExt;
            let sig = status.signal();
            // a hardware fault may surface as SIGBUS on macOS
            assert!(
                sig == Some(want_sig) || (want_sig == libc::SIGSEGV && sig == Some(libc::SIGBUS)),
                "{mode}: {status}"
            );
            let dumps = |d: &str| -> Vec<PathBuf> {
                std::fs::read_dir(root.join(d))
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .collect()
            };
            match want {
                Some((dir, entity)) => {
                    let other = if dir == "early" { "final" } else { "early" };
                    assert!(dumps(other).is_empty(), "{mode}: dump in {other}");
                    let found = dumps(dir);
                    assert_eq!(found.len(), 1, "{mode}: {found:?}");
                    assert!(found[0].join("done").is_file());
                    let v: Value = serde_json::from_str(
                        &std::fs::read_to_string(found[0].join("meta")).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(v["entity_name"], entity, "{mode}");
                    if dir == "final" {
                        assert_eq!(v["device_serial"], "SER12345", "{mode}");
                        assert_eq!(v["device_model"], "MODELX", "{mode}");
                    } else {
                        assert!(
                            v.get("device_serial").is_none(),
                            "{mode}: the early install names no device"
                        );
                    }
                }
                None => {
                    assert!(
                        dumps("early").is_empty() && dumps("final").is_empty(),
                        "{mode}"
                    );
                }
            }
            std::fs::remove_dir_all(&root).unwrap();
        }
    }

    #[test]
    fn dump_has_the_fields_the_crash_module_needs() {
        let dir = std::env::temp_dir().join(format!("crash-test-{}", std::process::id()));
        let cfg = CrashCfg {
            dir: dir.clone(),
            entity: "osd.3".into(),
            version: "ceph version 21.2.0 (x) croit-flashstore-osd".into(),
            process: "croit-flashstore-osd".into(),
            device_serial: "SER12345".into(),
            device_model: "MODELX".into(),
        };
        let bt = "   0: std::backtrace::Backtrace::force_capture\n             at /rustc/x/lib.rs:1\n   1: osd::foo\n";
        let p = write_dump(
            &cfg,
            &Failure {
                msg: "boom",
                file: "a.rs",
                line: 7,
                thread: "core-1",
                backtrace: bt,
            },
            "line1\nline2\n",
        )
        .unwrap();
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(p.join("meta")).unwrap()).unwrap();
        let id = v["crash_id"].as_str().unwrap();
        let ts = v["timestamp"].as_str().unwrap();
        assert!(
            id.starts_with(ts) && ts.ends_with('Z') && ts.contains('T'),
            "{id}"
        );
        assert_eq!(p.file_name().unwrap().to_str().unwrap(), id);
        assert_eq!(v["entity_name"], "osd.3");
        assert_eq!(v["device_serial"], "SER12345");
        assert_eq!(v["device_model"], "MODELX");
        assert!(
            v["assert_msg"]
                .as_str()
                .unwrap()
                .ends_with("FAILED panic(boom)\n")
        );
        assert_eq!(
            v["backtrace"],
            json!([
                " 1: (std::backtrace::Backtrace::force_capture+0x0) [0x0]",
                " 2: (osd::foo+0x0) [0x0]"
            ])
        );
        assert_eq!(
            std::fs::read_to_string(p.join("log")).unwrap(),
            "line1\nline2\n"
        );
        assert!(!p.join("meta.tmp").exists());
        assert!(p.join("done").is_file()); // ceph-crash posts only dirs with `done`
        // a dump is private: directory 0700, files 0600 (log tail can hold admin-command values)
        use std::os::unix::fs::PermissionsExt;
        let mode = |q: &std::path::Path| std::fs::metadata(q).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&p), 0o700, "dump directory is not 0700");
        for f in ["meta", "log", "done"] {
            assert_eq!(mode(&p.join(f)), 0o600, "{f} is not 0600");
        }
        // owned by the crash directory's owner (here the test user), so a root OSD's ceph-crash can read it
        let (uid, gid) = owner(&dir).unwrap();
        use std::os::unix::fs::MetadataExt;
        for q in [&p, &p.join("meta"), &p.join("log"), &p.join("done")] {
            let m = std::fs::metadata(q).unwrap();
            assert_eq!((m.uid(), m.gid()), (uid, gid), "{} owner", q.display());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pre-planted symlinks at the dump file names (`log`, `done`, `meta.tmp`) are refused (`O_EXCL`), never written
    /// through; a symlink at the final `meta` name is replaced by the rename; a dump dir that is a symlink is refused
    /// before anything is written. The signal path's raw `openat`/`open` obey the same contract.
    #[test]
    fn planted_symlinks_in_the_dump_dir_are_never_followed() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("crash-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let crash = root.join("crash");
        std::fs::create_dir_all(&crash).unwrap();
        let victim = root.join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        let m = json!({"crash_id": "x"});

        // panic path: symlinks at log / done / meta.tmp -> the first create fails, the victim is untouched
        let dump = crash.join("d");
        std::fs::create_dir(&dump).unwrap();
        for n in ["log", "done", "meta.tmp"] {
            symlink(&victim, dump.join(n)).unwrap();
        }
        assert!(
            dump_into(&dump, &m, "t", None).is_err(),
            "planted symlink followed"
        );
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        for n in ["log", "done", "meta.tmp"] {
            std::fs::remove_file(dump.join(n)).unwrap();
        }
        // a symlink at the final `meta` name is replaced by the rename, never written through
        symlink(&victim, dump.join("meta")).unwrap();
        dump_into(&dump, &m, "t", None).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(
            !std::fs::symlink_metadata(dump.join("meta"))
                .unwrap()
                .file_type()
                .is_symlink()
        );

        // a dump dir that is a symlink is refused at open, before anything is written
        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = crash.join("l");
        symlink(&real, &link).unwrap();
        assert!(dump_into(&link, &m, "t", None).is_err());
        assert!(!real.join("done").exists());

        // signal path: the same contract on the raw syscalls
        let sdump = crash.join("s");
        std::fs::create_dir(&sdump).unwrap();
        for n in ["log", "done", "meta.tmp"] {
            symlink(&victim, sdump.join(n)).unwrap();
        }
        let sfd = std::fs::File::open(&sdump).unwrap();
        use std::os::fd::AsRawFd as _;
        let mut name = sig::Buf::new();
        name.push(b"log");
        assert!(
            !sig::create_file(sfd.as_raw_fd(), &name, b"x", None),
            "planted symlink followed"
        );
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        let mut sdir = sig::Buf::new();
        sdir.push(link.as_os_str().as_encoded_bytes());
        assert_eq!(sig::open_dir(&sdir), -1, "symlinked dump dir opened");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn panic_machinery_frames_are_cut() {
        let bt = "   0: osd::crash::install::{closure#0}\n   1: std::panicking::panic_with_hook\n   2: core::panicking::panic_fmt\n   3: osd::tell::run_command\n   4: main\n";
        assert_eq!(
            frames(bt),
            [
                " 1: (osd::tell::run_command+0x0) [0x0]",
                " 2: (main+0x0) [0x0]"
            ]
        );
    }

    #[test]
    fn tail_is_bounded() {
        for i in 0..(TAIL_LINES + 50) {
            note(&format!("l{i}"));
        }
        let t = tail_text();
        assert_eq!(t.lines().count(), TAIL_LINES);
        assert!(t.ends_with(&format!("l{}\n", TAIL_LINES + 49)));
    }

    #[test]
    fn signal_meta_is_valid_json_with_the_crash_fields() {
        let mut ts = sig::Buf::new();
        sig::iso_utc_into(&mut ts, 1_790_000_000, 123_456);
        assert_eq!(
            std::str::from_utf8(ts.bytes()).unwrap(),
            "2026-09-21T14:13:20.123456Z"
        );
        let mut b = sig::Buf::new();
        sig::meta_into(
            &mut b,
            ts.bytes(),
            "_abc",
            ",\"entity_name\":\"osd.3\",\"backtrace\":[]",
            libc::SIGSEGV,
            0xdead_beef,
        );
        let v: Value = serde_json::from_slice(b.bytes()).unwrap();
        let ts = std::str::from_utf8(ts.bytes()).unwrap();
        assert_eq!(v["crash_id"], format!("{ts}_abc"));
        assert_eq!(v["timestamp"], ts);
        assert_eq!(v["entity_name"], "osd.3");
        assert_eq!(v["signal"], "SIGSEGV");
        assert_eq!(v["fault_addr"], "0xdeadbeef");
        for (signal, name) in [
            (libc::SIGXCPU, "SIGXCPU"),
            (libc::SIGXFSZ, "SIGXFSZ"),
            (libc::SIGSYS, "SIGSYS"),
        ] {
            let mut b = sig::Buf::new();
            sig::meta_into(
                &mut b,
                ts.as_bytes(),
                "_abc",
                ",\"backtrace\":[]",
                signal,
                0,
            );
            let meta: Value = serde_json::from_slice(b.bytes()).unwrap();
            assert_eq!(meta["signal"], name);
            assert_eq!(meta["signal_number"], signal);
        }
    }

    /// Every classic fatal signal leaves a complete report and still terminates the child with that signal.
    #[test]
    fn fatal_signal_writes_a_dump_and_still_kills() {
        if let Ok(dir) = std::env::var("CRASH_SIGNAL_CHILD") {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: valid pointer, affects only this test child.
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
            install(CrashCfg {
                dir: dir.into(),
                entity: "osd.9".into(),
                version: "v".into(),
                process: "croit-flashstore-osd".into(),
                device_serial: String::new(),
                device_model: String::new(),
            });
            // SAFETY: deliberate fatal signal for the test child
            unsafe {
                libc::raise(
                    std::env::var("CRASH_SIGNAL_NUMBER")
                        .unwrap()
                        .parse()
                        .unwrap(),
                );
            }
            unreachable!();
        }
        for (expected, name) in [
            (libc::SIGSEGV, "SIGSEGV"),
            #[cfg(target_os = "linux")]
            (libc::SIGBUS, "SIGBUS"),
            #[cfg(target_os = "linux")]
            (libc::SIGILL, "SIGILL"),
            #[cfg(target_os = "linux")]
            (libc::SIGFPE, "SIGFPE"),
            #[cfg(target_os = "linux")]
            (libc::SIGABRT, "SIGABRT"),
            #[cfg(target_os = "linux")]
            (libc::SIGXCPU, "SIGXCPU"),
            #[cfg(target_os = "linux")]
            (libc::SIGXFSZ, "SIGXFSZ"),
            #[cfg(target_os = "linux")]
            (libc::SIGSYS, "SIGSYS"),
        ] {
            let dir =
                std::env::temp_dir().join(format!("crash-sig-{}-{expected}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "crash::tests::fatal_signal_writes_a_dump_and_still_kills",
                ])
                .env("CRASH_SIGNAL_CHILD", &dir)
                .env("CRASH_SIGNAL_NUMBER", expected.to_string())
                .spawn()
                .unwrap();
            let start = std::time::Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if start.elapsed() > std::time::Duration::from_secs(10) {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("WARNING TIMEOUT fatal signal child exceeded 10s ({name})");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(expected), "{name}: {status}");
            let dumps: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
            assert_eq!(dumps.len(), 1, "{dumps:?}");
            let d = dumps[0].path();
            assert!(d.join("done").is_file());
            let v: Value =
                serde_json::from_str(&std::fs::read_to_string(d.join("meta")).unwrap()).unwrap();
            assert_eq!(v["entity_name"], "osd.9");
            assert_eq!(v["crash_id"].as_str(), d.file_name().unwrap().to_str());
            assert_eq!(v["signal"], name, "{v}");
            use std::os::unix::fs::PermissionsExt;
            let mode =
                |q: &std::path::Path| std::fs::metadata(q).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&d), 0o700, "signal dump directory is not 0700");
            for f in ["meta", "done"] {
                assert_eq!(mode(&d.join(f)), 0o600, "signal {f} is not 0600");
            }
            // the handler fchowns the dir and files to the crash dir's owner (here the test user)
            let (uid, gid) = owner(&dir).unwrap();
            use std::os::unix::fs::MetadataExt;
            for q in [&d, &d.join("meta"), &d.join("done")] {
                let m = std::fs::metadata(q).unwrap();
                assert_eq!((m.uid(), m.gid()), (uid, gid), "{} owner", q.display());
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
