// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Admin socket server (`/var/run/ceph/<cluster>-osd.<id>.asok`, spec/ops-observability.md 1).
//!
//! Wire protocol (classic, version "2"): the client sends one request terminated by NUL or newline, normally JSON
//! `{"prefix": "perf dump", ...}` (the legacy 4-byte big-endian codes 0/1/2 are accepted too); the server answers a
//! 4-byte big-endian length followed by the payload, then closes. Command failures are carried in-band: a negative
//! result is prefixed with `ERROR: (errno) text\n<message>\n`.
//!
//! One helper thread accepts and parses; it never touches OSD state. Commands go to the control core over a std channel
//! ([`AsokReq`]) and poke its wake handle; the control core takes them from its loop ([`crate::Osd::attach_asok`],
//! [`AsokRx`]) and answers through the per-request reply channel with the unserialized output: the worker serializes it
//! (counter documents are built from their snapshot there, [`crate::ctrsnap`]). A render thread builds the counter
//! documents of `ceph tell` replies ([`AsokRx::render`]) and pokes the control core when one is done. The hot cores never
//! see the socket, and every thread here runs on the helper CPUs ([`crate::helper_thread_start`]), not on a core's.
//!
//! The workers are owned ([`AsokServer`]): dropping it ends the request in progress of every worker (its client socket
//! is shut down, a reply it waits for is answered "shutting down") and joins them. A worker must not outlive the
//! daemon's `main`: replies of 128 KiB and more live in the DPDK hugepage heap (`eal_heap::HugeAlloc`), which SPDK's
//! exit-time `rte_eal_cleanup` unmaps (doc/perf/rdma-spike-20261019.md section 16).
use crate::tell::Out;
use ingress::Doorbell;
use serde_json::Value;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, SyncSender, TryRecvError, channel, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

/// `(result, message, output)` of a command.
pub(crate) type CmdResult = (i32, String, Out);

/// A parsed command on its way to the control core.
#[derive(Debug)]
pub struct AsokReq {
    /// The JSON command (`{"prefix": ..., ...}`).
    pub(crate) cmd: String,
    pub(crate) reply: Sender<CmdResult>,
}

/// A reply body to build off the cores: the output of a `ceph tell` counter command ([`AsokRx::render`]).
#[derive(Debug)]
pub(crate) struct RenderJob {
    out: Out,
    compact: bool,
    done: Sender<Vec<u8>>,
}

/// The control core's end of the admin socket: the request channel, the render thread's queue (`None` ends the thread)
/// and the doorbell both hand work back through (queued requests, finished bodies).
#[derive(Debug)]
pub struct AsokRx {
    rx: Receiver<AsokReq>,
    bell: Arc<Doorbell>,
    render: Sender<Option<RenderJob>>,
}

impl AsokRx {
    /// The next queued request.
    pub fn try_recv(&self) -> Option<AsokReq> {
        let r = self.rx.try_recv().ok()?;
        self.bell.take();
        Some(r)
    }

    /// A request or a finished body is queued or being queued: the control core's re-check after it announced its
    /// sleep (a worker or the render thread that queues later wakes it, [`Doorbell`]).
    pub fn waiting(&self) -> bool {
        self.bell.waiting()
    }

    /// Install the control core's wake handle: workers poke it after queueing a request, the render thread after a
    /// finished body.
    pub fn set_waker(&self, w: Arc<dyn ingress::Waker>) {
        self.bell.set_waker(w);
    }

    /// Hand `out` to the render thread; the body arrives on the returned channel ([`rendered`](Self::rendered)).
    /// `Err(out)`: the render thread is gone (shutdown).
    pub(crate) fn render(&self, out: Out, compact: bool) -> Result<Receiver<Vec<u8>>, Out> {
        let (done, body) = channel();
        match self.render.send(Some(RenderJob { out, compact, done })) {
            Ok(()) => Ok(body),
            Err(e) => Err(e.0.map_or_else(Out::default, |j| j.out)),
        }
    }

    /// The finished body of a [`render`](Self::render) job, if it is there.
    pub(crate) fn rendered(&self, body: &Receiver<Vec<u8>>) -> Result<Vec<u8>, TryRecvError> {
        let b = body.try_recv()?;
        self.bell.take();
        Ok(b)
    }
}

const MAX_REQ: usize = 64 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Classic `cpp_strerror` text for the errnos commands return: the libc text (thread-safe through std's error
/// string) in the `(<errno>) <text>` form.
fn strerror(r: i32) -> String {
    let text = std::io::Error::from_raw_os_error(-r).to_string();
    let suffix = format!(" (os error {})", -r);
    format!("({}) {}", -r, text.strip_suffix(&suffix).unwrap_or(&text))
}

/// Request text -> JSON command. Plain text is split into words (`perf dump` -> prefix).
fn parse_request(raw: &[u8]) -> String {
    if raw.len() == 4 && raw[..3] == [0, 0, 0] {
        let p = match raw[3] {
            0 => "0",
            1 => "perfcounters_dump",
            2 => "perfcounters_schema",
            _ => "foo",
        };
        return serde_json::json!({ "prefix": p }).to_string();
    }
    let s = String::from_utf8_lossy(raw).trim().to_owned();
    if s.starts_with('{') {
        s
    } else {
        serde_json::json!({ "prefix": s }).to_string()
    }
}

/// Response body for a finished command: error prefix, then the output serialized for the command's `format`
/// (pretty JSON by default, compact for `json` / `jsonl`, non-JSON output verbatim, [`Out::render`]).
pub(crate) fn render(cmd: &str, (r, rs, out): CmdResult) -> Vec<u8> {
    let compact = serde_json::from_str::<Value>(cmd)
        .ok()
        .is_some_and(|v| wants_compact(&v));
    let mut body = out.render(compact);
    if r < 0 {
        let mut e = format!("ERROR: {}\n{rs}\n", strerror(r)).into_bytes();
        e.append(&mut body);
        return e;
    }
    body
}

/// Whether the command's `format` asks for compact output (`json`, `jsonl`).
pub(crate) fn wants_compact(cmd: &Value) -> bool {
    cmd.get("format")
        .and_then(Value::as_str)
        .is_some_and(|f| f == "json" || f == "jsonl")
}

/// Pretty JSON with a trailing newline.
pub(crate) fn pretty(v: &Value) -> Vec<u8> {
    let mut body = serde_json::to_vec_pretty(v).unwrap_or_default();
    body.push(b'\n');
    body
}

/// Format command output bytes: compact and non-JSON output verbatim, JSON pretty otherwise.
pub(crate) fn format_bytes(compact: bool, out: Vec<u8>) -> Vec<u8> {
    if compact {
        return out;
    }
    match serde_json::from_slice::<Value>(&out) {
        Ok(v) => pretty(&v),
        Err(_) => out,
    }
}

/// Why [`read_request`] has no request.
#[derive(Debug, PartialEq, Eq)]
enum ReadError {
    /// The client closed the connection or sent nothing.
    Closed,
    /// No complete request within [`READ_TIMEOUT`]; the loud line was logged.
    Timeout,
    /// Longer than [`MAX_REQ`]: refused, never silently dropped (the client would only see a bare EOF).
    TooLong,
}

fn read_request(s: &mut impl Read) -> Result<Vec<u8>, ReadError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = match s.read(&mut chunk) {
            Ok(0) => return Err(ReadError::Closed),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                eprintln!(
                    "WARNING TIMEOUT asok request read exceeded {:.3}s (client sent no complete request)",
                    READ_TIMEOUT.as_secs_f64()
                );
                return Err(ReadError::Timeout);
            }
            Err(_) => return Err(ReadError::Closed),
        };
        for &byte in &chunk[..n] {
            // Legacy commands start with NUL and contain exactly four bytes.
            if buf.first() == Some(&0) || (buf.is_empty() && byte == 0) {
                buf.push(byte);
                if buf.len() == 4 {
                    return Ok(buf);
                }
            } else if byte == 0 || byte == b'\n' {
                return Ok(buf);
            } else {
                buf.push(byte);
            }
            if buf.len() >= MAX_REQ {
                return Err(ReadError::TooLong);
            }
        }
    }
}

/// Reply body -> its 4-byte length header. `None` = the body does not fit the classic u32 field (a truncated header
/// would desynchronize the client).
fn reply_len(len: usize) -> Option<u32> {
    u32::try_from(len).ok()
}

/// Write one reply: the big-endian length header, then the body. A body that does not fit the header is replaced by an
/// `EOVERFLOW` error.
fn answer(s: &mut impl Write, body: Vec<u8>) -> std::io::Result<()> {
    let body = match reply_len(body.len()) {
        Some(_) => body,
        None => render(
            "",
            (
                -denc::errno::EOVERFLOW,
                format!("reply of {} bytes exceeds the admin frame", body.len()),
                Out::default(),
            ),
        ),
    };
    let len = reply_len(body.len()).expect("a reply that fits the frame");
    s.write_all(&len.to_be_bytes())?;
    s.write_all(&body)
}

/// Publish one hand-off to the control core: [`Doorbell::queue`] before, [`Doorbell::ring`] after; a publish that
/// failed gives its count back ([`Doorbell::take`]).
fn publish<T, E>(bell: &Doorbell, send: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    bell.queue();
    let r = send();
    if r.is_ok() {
        bell.ring();
    } else {
        bell.take();
    }
    r
}

/// Serve one client. `register` gets the reply channel of a command before it goes to the control core (false: the
/// server is stopping, the command is not sent).
fn serve(
    mut s: UnixStream,
    tx: &SyncSender<AsokReq>,
    bell: &Doorbell,
    register: impl FnOnce(&Sender<CmdResult>) -> bool,
) {
    let _ = s.set_read_timeout(Some(READ_TIMEOUT));
    let _ = s.set_write_timeout(Some(READ_TIMEOUT));
    let raw = match read_request(&mut s) {
        Ok(raw) => raw,
        Err(ReadError::TooLong) => {
            eprintln!(
                "croit-flashstore-osd: admin socket request rejected: more than {MAX_REQ} bytes"
            );
            let _ = answer(
                &mut s,
                render(
                    "",
                    (
                        crate::tell::EINVAL,
                        format!("request exceeds {MAX_REQ} bytes"),
                        Out::default(),
                    ),
                ),
            );
            return;
        }
        Err(ReadError::Closed | ReadError::Timeout) => return,
    };
    let cmd = parse_request(&raw);
    let body = if serde_json::from_str::<Value>(&cmd)
        .ok()
        .and_then(|v| v.get("prefix").and_then(Value::as_str).map(|p| p == "0"))
        .unwrap_or(false)
    {
        b"2".to_vec()
    } else {
        let (rt, rr) = channel();
        let res = if !register(&rt) {
            (-38, "osd is shutting down".into(), Out::default())
        } else {
            match publish(bell, || {
                tx.try_send(AsokReq {
                    cmd: cmd.clone(),
                    reply: rt,
                })
            }) {
                // Commands have no wall-clock deadline in classic. The core owns command liveness (e.g. scatter's
                // progress checks); shutdown explicitly answers Busy.reply before joining these workers.
                Ok(()) => rr
                    .recv()
                    .unwrap_or_else(|_| (-38, "osd is shutting down".into(), Out::default())),
                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                    (-11, "admin command queue is full".into(), Out::default())
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    (-38, "osd is shutting down".into(), Out::default())
                }
            }
        };
        render(&cmd, res)
    };
    let _ = answer(&mut s, body);
}

/// Number of worker threads.
const WORKERS: usize = 4;

/// The request a worker is serving, for [`AsokServer`]'s drop to end it.
#[derive(Debug, Default)]
struct Busy {
    /// A handle of the client socket (its read side is shut down at stop: a blocked request read returns; the answer
    /// still goes out, a write is bounded by the socket's write timeout).
    client: Option<UnixStream>,
    /// The reply channel of the command sent to the control core (answered at stop: the core no longer polls).
    reply: Option<Sender<CmdResult>>,
}

#[derive(Debug, Default)]
struct Workers {
    stop: bool,
    busy: [Busy; WORKERS],
}

/// Handle of a running server. Drop stops and joins the workers (module doc) and removes the socket file. The accept
/// thread only accepts and queues (no large allocation); Drop wakes and joins it.
#[derive(Debug)]
pub struct AsokServer {
    path: PathBuf,
    bound: (u64, u64),
    workers: Arc<Mutex<Workers>>,
    /// The workers' queue: one `None` per worker ends it.
    queue: SyncSender<Option<UnixStream>>,
    threads: Vec<JoinHandle<()>>,
    accept: Option<JoinHandle<()>>,
    accept_wake: Option<UnixStream>,
    /// The render thread and its queue (a `None` ends it).
    render: Option<(Sender<Option<RenderJob>>, JoinHandle<()>)>,
}

impl Drop for AsokServer {
    fn drop(&mut self) {
        {
            let mut w = self.workers.lock().unwrap_or_else(PoisonError::into_inner);
            w.stop = true;
            for b in &mut w.busy {
                if let Some(c) = b.client.take() {
                    let _ = c.shutdown(std::net::Shutdown::Read);
                }
                if let Some(r) = b.reply.take() {
                    let _ = r.send((-38, "osd is shutting down".into(), Out::default()));
                }
            }
        }
        // Closing the private wake descriptor wakes poll even if the socket path was unlinked.
        drop(self.accept_wake.take());
        if let Some(thread) = self.accept.take()
            && thread.join().is_err()
        {
            eprintln!("croit-flashstore-osd: admin socket accept thread panicked");
        }
        // workers drain queued clients without serving them (stop), then take their `None`
        for _ in &self.threads {
            let _ = self.queue.send(None);
        }
        for t in self.threads.drain(..) {
            if t.join().is_err() {
                eprintln!("croit-flashstore-osd: admin socket worker panicked");
            }
        }
        // the control core may still hold a sender: the `None` ends the thread (queued jobs before it are built)
        if let Some((q, t)) = self.render.take() {
            let _ = q.send(None);
            if t.join().is_err() {
                eprintln!("croit-flashstore-osd: admin socket render thread panicked");
            }
        }
        if std::fs::symlink_metadata(&self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.bound) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Render thread: build the reply bodies of `ceph tell` counter commands until a `None` (or the end of the queue); each
/// finished body wakes the control core like a queued request.
fn render_jobs(jobs: &Receiver<Option<RenderJob>>, bell: &Doorbell) {
    while let Ok(Some(j)) = jobs.recv() {
        let body = j.out.render(j.compact);
        let _ = publish(bell, || j.done.send(body));
    }
}

/// Worker `id`: serve queued clients until a `None` (or the end of the queue).
fn work(
    id: usize,
    requests: &Mutex<Receiver<Option<UnixStream>>>,
    commands: &SyncSender<AsokReq>,
    bell: &Doorbell,
    workers: &Mutex<Workers>,
) {
    let lock = || workers.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        let next = requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv();
        let Ok(Some(client)) = next else {
            return;
        };
        {
            let mut w = lock();
            if w.stop {
                continue; // dropped unanswered: the daemon is going away
            }
            w.busy[id].client = client.try_clone().ok();
        }
        serve(client, commands, bell, |reply| {
            let mut w = lock();
            if w.stop {
                return false;
            }
            w.busy[id].reply = Some(reply.clone());
            true
        });
        lock().busy[id] = Busy::default();
    }
}

/// Name of the socket inside the private staging directory ([`Staging`]).
const STAGED: &std::ffi::CStr = c"s";

fn cpath(p: &Path) -> std::io::Result<std::ffi::CString> {
    std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{}: path contains NUL", p.display()),
        )
    })
}

/// `fstatat(dir, name)` without following a symlink.
fn stat_at(dir: &std::fs::File, name: &std::ffi::CStr) -> std::io::Result<libc::stat> {
    // SAFETY: dir is open, name NUL-terminated; a zeroed `stat` is valid and overwritten.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st)
}

/// Private directory (`mkdtemp`, 0700, owned by this process) next to the admin socket path. The socket is bound,
/// restricted and identified inside it, then published with one `renameat`: nobody else can create or replace an entry
/// in it, so the chmod never reaches a file planted in a writable parent (NT-security-03). Drop removes it.
struct Staging {
    path: PathBuf,
    dir: std::fs::File,
}

impl Staging {
    fn new(parent: &Path) -> std::io::Result<Self> {
        use std::os::unix::ffi::OsStringExt as _;
        let mut template = cpath(&parent.join(".asok.XXXXXX"))?.into_bytes_with_nul();
        // SAFETY: NUL-terminated writable template; mkdtemp replaces the X's in place.
        if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        template.pop();
        let path = PathBuf::from(std::ffi::OsString::from_vec(template));
        let c = cpath(&path)?;
        // SAFETY: NUL-terminated path; the fd is owned by the File below.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fd is open and owned by the File from here on.
        let dir = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        let m = dir.metadata()?;
        // SAFETY: geteuid has no preconditions.
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            // replaced between mkdtemp and open: not ours, leave it alone
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{}: staging directory was replaced", path.display()),
            ));
        }
        Ok(Self { path, dir })
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        // SAFETY: dir is open, the name NUL-terminated; inside the private dir only this process creates entries.
        unsafe { libc::unlinkat(self.dir.as_raw_fd(), STAGED.as_ptr(), 0) };
        // rmdir removes only an empty directory: at worst an empty one planted under the same name
        let _ = std::fs::remove_dir(&self.path);
    }
}

/// Restrict the staged admin socket `name` in `dir` to owner and group (`0660`). A socket any local user could reach
/// would let them run `bench`, `cache drop`, key handling and every other admin command, so a mode that cannot be set
/// or does not stick is a startup error, never a silent default.
fn restrict_socket(dir: &std::fs::File, name: &std::ffi::CStr) -> std::io::Result<()> {
    // SAFETY: dir is open, name NUL-terminated.
    if unsafe { libc::fchmodat(dir.as_raw_fd(), name.as_ptr(), 0o660, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mode = stat_at(dir, name)?.st_mode & 0o777;
    if mode != 0o660 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("admin socket mode is {mode:04o}, not 0660"),
        ));
    }
    Ok(())
}

/// Bind `path` and serve it from helper threads. Returns the control core's end ([`crate::Osd::attach_asok`]).
/// A stale socket (connection refused) is replaced; a live one, any non-socket entry (file, symlink, directory) and a
/// probe error (e.g. permission denied) are errors that leave the entry untouched.
pub fn start(path: &Path) -> std::io::Result<(AsokServer, AsokRx)> {
    start_with(path, restrict_socket)
}

/// [`start`] with the permission step injectable, so a failure after the bind is testable.
fn start_with(
    path: &Path,
    restrict: impl FnOnce(&std::fs::File, &std::ffi::CStr) -> std::io::Result<()>,
) -> std::io::Result<(AsokServer, AsokRx)> {
    match std::fs::symlink_metadata(path) {
        Ok(entry) if !entry.file_type().is_socket() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{}: refusing to replace a non-socket entry", path.display()),
            ));
        }
        Ok(_) => match UnixStream::connect(path) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!(
                        "{}: another daemon answers on this admin socket",
                        path.display()
                    ),
                ));
            }
            // stale: replaced atomically by the publishing rename below, never unlinked first
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
            Err(e) => {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("{}: {e}", path.display()),
                ));
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let parent = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(parent)?;
    let staging = Staging::new(parent)?;
    let l = UnixListener::bind(
        staging
            .path
            .join(std::ffi::OsStr::from_bytes(STAGED.to_bytes())),
    )?;
    // The bind went through the staging path: only an entry in our private dir proves it is the socket we bound.
    let st = stat_at(&staging.dir, STAGED)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{}: staged admin socket missing", staging.path.display()),
        ));
    }
    // identity of the file this call bound (an entry of the staging dir lives on its filesystem): a cleanup never
    // removes a socket another daemon put at the same path
    let bound = (staging.dir.metadata()?.dev(), st.st_ino);
    restrict(&staging.dir, STAGED)?;
    l.set_nonblocking(true)?;
    let (accept_wake, stop) = UnixStream::pair()?;
    // Publish: renameat replaces a stale socket (or whatever a writer of the parent put there meanwhile, which that
    // writer could remove itself) as one step and never follows a symlink at `path`.
    let target = cpath(path)?;
    // SAFETY: the staging dir is open, both names are NUL-terminated.
    if unsafe {
        libc::renameat(
            staging.dir.as_raw_fd(),
            STAGED.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
        )
    } != 0
    {
        let e = std::io::Error::last_os_error();
        return Err(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", path.display()),
        ));
    }
    drop(staging);
    let (tx, rx) = sync_channel(4);
    let bell = Arc::new(Doorbell::default());
    // Four workers and a bounded accept queue isolate a slow admin client without
    // creating an unbounded thread per request. Commands still run on the owner core.
    let (pending, requests) = sync_channel::<Option<UnixStream>>(16);
    let requests = Arc::new(Mutex::new(requests));
    let workers = Arc::new(Mutex::new(Workers::default()));
    let mut server = AsokServer {
        path: path.to_owned(),
        bound,
        workers: workers.clone(),
        queue: pending.clone(),
        threads: Vec::with_capacity(WORKERS),
        accept: None,
        accept_wake: Some(accept_wake),
        render: None,
    };
    for id in 0..WORKERS {
        let (requests, commands, workers) = (requests.clone(), tx.clone(), workers.clone());
        let bell = bell.clone();
        // on an error `server` drops: the workers started so far are stopped and joined
        server.threads.push(
            std::thread::Builder::new()
                .name(format!("asok-{id}"))
                .spawn(move || {
                    crate::helper_thread_start();
                    work(id, &requests, &commands, &bell, &workers)
                })?,
        );
    }
    let (render, jobs) = channel();
    let t = std::thread::Builder::new()
        .name("asok-render".into())
        .spawn({
            let bell = bell.clone();
            move || {
                crate::helper_thread_start();
                render_jobs(&jobs, &bell)
            }
        })?;
    server.render = Some((render.clone(), t));
    server.accept = Some(
        std::thread::Builder::new()
            .name("asok-accept".into())
            .spawn(move || {
                crate::helper_thread_start();
                let mut fds = [
                    libc::pollfd {
                        fd: l.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: stop.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];
                loop {
                    // Both descriptors remain owned by this closure throughout the wait.
                    if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        eprintln!("croit-flashstore-osd: admin socket accept poll: {error}");
                        return;
                    }
                    if fds[1].revents != 0 {
                        return;
                    }
                    match l.accept() {
                        Ok((client, _)) => {
                            if workers.lock().unwrap_or_else(PoisonError::into_inner).stop {
                                return;
                            }
                            // The workers block (with timeouts): a BSD-derived accept inherits the listener's
                            // O_NONBLOCK, which would end every read at once.
                            if client.set_nonblocking(false).is_err() {
                                continue;
                            }
                            // An overloaded admin endpoint sheds connections, never core IO.
                            let _ = pending.try_send(Some(client));
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                            ) => {}
                        Err(error) => {
                            eprintln!("croit-flashstore-osd: admin socket accept: {error}");
                            return;
                        }
                    }
                }
            })?,
    );
    Ok((server, AsokRx { rx, bell, render }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_command_keeps_its_reply_after_thirty_seconds() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(40)))
            .unwrap();
        let (tx, rx) = sync_channel(1);
        let worker = std::thread::spawn(move || serve(server, &tx, &Doorbell::default(), |_| true));
        client.write_all(b"bench\0").unwrap();
        let req = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // The old worker abandoned valid commands after 30 seconds, even though they were still running.
        std::thread::sleep(Duration::from_secs(31));
        let sent = req
            .reply
            .send((0, String::new(), Out::Raw(b"finished".to_vec())));
        let mut len = [0; 4];
        client.read_exact(&mut len).unwrap();
        let mut body = vec![0; u32::from_be_bytes(len) as usize];
        client.read_exact(&mut body).unwrap();
        worker.join().unwrap();
        assert!(sent.is_ok(), "worker abandoned the running command");
        assert_eq!(body, b"finished");
    }

    #[test]
    fn startup_preserves_non_socket_entries() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("asok-nonsocket-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("keyring");
        std::fs::write(&file, b"secret").unwrap();
        assert!(start(&file).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"secret");
        let alias = dir.join("alias");
        symlink(&file, &alias).unwrap();
        assert!(start(&alias).is_err());
        assert!(std::fs::symlink_metadata(&alias).unwrap().is_symlink());
        let dangling = dir.join("dangling");
        symlink(dir.join("absent"), &dangling).unwrap();
        assert!(start(&dangling).is_err());
        assert!(std::fs::symlink_metadata(&dangling).unwrap().is_symlink());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn command_output_formats() {
        let compact = br#"{"osd":{"op":1}}"#;
        let pretty = b"{\n  \"osd\": {\n    \"op\": 1\n  }\n}\n";
        let ok = |b: &[u8]| (0, String::new(), Out::Raw(b.to_vec()));
        let json = || {
            (
                0,
                String::new(),
                Out::Json(serde_json::json!({"osd": {"op": 1}})),
            )
        };
        for cmd in [r#"{}"#, r#"{"format":"json-pretty"}"#] {
            assert_eq!(render(cmd, ok(compact)), pretty);
            assert_eq!(render(cmd, json()), pretty);
            for raw in [b"".as_slice(), b"plain text\n", b"\0\xffbinary"] {
                assert_eq!(render(cmd, ok(raw)), raw);
            }
        }
        for cmd in [r#"{"format":"json"}"#, r#"{"format":"jsonl"}"#] {
            assert_eq!(render(cmd, ok(compact)), compact);
            assert_eq!(render(cmd, json()), compact);
        }
    }

    #[test]
    fn value_output_is_serialized_once_per_requested_format() {
        use crate::tell::Out;
        let v: Value = serde_json::json!({"b": 1, "a": {"z": [1, 2], "y": null}});
        // Same bytes as the former Value -> compact bytes -> parse -> pretty round trip, key order included.
        let compact = v.to_string().into_bytes();
        assert_eq!(Out::Json(v.clone()).render(true), compact);
        assert_eq!(
            Out::Json(v.clone()).render(false),
            format_bytes(false, compact.clone())
        );
        assert_eq!(
            Out::Json(v).render(false),
            pretty(&serde_json::from_slice(&compact).unwrap())
        );
        // Raw output keeps the old byte rules.
        assert_eq!(
            Out::Raw(b"plain text\n".to_vec()).render(false),
            b"plain text\n"
        );
        assert!(wants_compact(&serde_json::json!({"format": "jsonl"})));
        assert!(!wants_compact(
            &serde_json::json!({"format": "json-pretty"})
        ));
    }

    fn ask(path: &Path, req: &[u8]) -> String {
        let mut c = UnixStream::connect(path).unwrap();
        c.write_all(req).unwrap();
        c.write_all(b"\0").unwrap();
        let mut len = [0u8; 4];
        c.read_exact(&mut len).unwrap();
        let mut v = vec![0u8; u32::from_be_bytes(len) as usize];
        c.read_exact(&mut v).unwrap();
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn saturated_control_command_queue_returns_eagain_without_waiting() {
        let (tx, _rx) = sync_channel(0);
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || serve(server, &tx, &Doorbell::default(), |_| true));
        client.write_all(b"perf dump\0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut length = [0; 4];
        client.read_exact(&mut length).unwrap();
        let mut body = vec![0; u32::from_be_bytes(length) as usize];
        client.read_exact(&mut body).unwrap();
        assert!(String::from_utf8(body).unwrap().starts_with("ERROR: (11)"));
        worker.join().unwrap();
    }

    #[test]
    fn large_admin_request_uses_block_reads() {
        struct CountReads {
            input: std::io::Cursor<Vec<u8>>,
            calls: usize,
        }
        impl Read for CountReads {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                self.calls += 1;
                self.input.read(out)
            }
        }
        let text = format!("{{\"prefix\":\"{}\"}}", "x".repeat(16 * 1024));
        let mut wire = text.as_bytes().to_vec();
        wire.push(0);
        let old_calls = wire.len(); // Baseline requests one byte from Read each iteration.
        let expected_calls = wire.len().div_ceil(4096);
        let mut reader = CountReads {
            input: std::io::Cursor::new(wire),
            calls: 0,
        };
        assert_eq!(read_request(&mut reader).unwrap(), text.as_bytes());
        assert_eq!(reader.calls, expected_calls);
        println!(
            "admin request bytes={} baseline_reads={old_calls} buffered_reads={}",
            text.len(),
            reader.calls
        );
    }

    #[test]
    fn buffered_reader_preserves_legacy_and_text_boundaries() {
        for (wire, expected) in [
            (b"perf dump\0ignored".as_slice(), b"perf dump".as_slice()),
            (b"perf dump\nignored".as_slice(), b"perf dump".as_slice()),
            (&[0, 0, 0, 2, 99], &[0, 0, 0, 2]),
        ] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client.write_all(wire).unwrap();
            assert_eq!(read_request(&mut server).unwrap(), expected);
        }
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            client.write_all(&[0, 0]).unwrap();
            client.write_all(&[0, 1]).unwrap();
        });
        assert_eq!(read_request(&mut server).unwrap(), [0, 0, 0, 1]);
        writer.join().unwrap();
    }

    /// Drop of the server ends every request in progress at once and joins the workers before it returns (nothing of
    /// them runs past the daemon's `main`): a command waiting for the control core gets "shutting down", a client that
    /// never finishes its request is cut off; neither waits for its timeout (30 s / 5 s).
    #[test]
    fn drop_ends_requests_in_progress_and_joins_the_workers() {
        let p = std::env::temp_dir().join(format!("asok-drop-{}.asok", std::process::id()));
        let (srv, rx) = start(&p).unwrap();
        let mut waiting = UnixStream::connect(&p).unwrap();
        waiting
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        waiting.write_all(b"perf dump\0").unwrap();
        // the command reached the control core, which never answers (its loop ended)
        let req = rx.rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut stalled = UnixStream::connect(&p).unwrap();
        stalled.write_all(b"{unfinished").unwrap();
        // the stalled client is being served (its worker reads) before the drop
        let t = std::time::Instant::now();
        while !srv
            .workers
            .lock()
            .unwrap()
            .busy
            .iter()
            .filter(|b| b.client.is_some())
            .count()
            .eq(&2)
        {
            assert!(
                t.elapsed() < Duration::from_secs(5),
                "WARNING TIMEOUT asok workers busy exceeded 5s (test)"
            );
            std::thread::yield_now();
        }
        let t = std::time::Instant::now();
        drop(srv);
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        let mut len = [0u8; 4];
        waiting.read_exact(&mut len).unwrap();
        let mut body = vec![0; u32::from_be_bytes(len) as usize];
        waiting.read_exact(&mut body).unwrap();
        assert!(String::from_utf8(body).unwrap().starts_with("ERROR: (38)"));
        assert!(!p.exists());
        drop(req);
    }

    /// A queued command wakes the control core (doc/perf/sleep-register-20261101.md row 4): before, nothing did, and the
    /// command waited for the 1 ms deep-idle cap; with the cap gone it would wait for unrelated traffic.
    #[test]
    fn a_queued_command_wakes_the_control_core() {
        #[derive(Debug)]
        struct Woken(Mutex<Sender<()>>);
        impl ingress::Waker for Woken {
            fn wake(&self) {
                let _ = self.0.lock().unwrap().send(());
            }
        }
        let p = std::env::temp_dir().join(format!("asok-wake-{}.asok", std::process::id()));
        let (_srv, rx) = start(&p).unwrap();
        let (tx, woken) = channel();
        rx.set_waker(Arc::new(Woken(Mutex::new(tx))));
        assert!(!rx.waiting());
        let client = std::thread::spawn({
            let p = p.clone();
            move || ask(&p, br#"{"prefix":"perf dump"}"#.as_slice())
        });
        woken
            .recv_timeout(Duration::from_secs(5))
            .expect("WARNING TIMEOUT asok wake exceeded 5s (test): the queued command did not wake the core");
        assert!(rx.waiting(), "the re-check sees the queued command");
        let req = rx.try_recv().expect("queued");
        assert!(!rx.waiting());
        req.reply
            .send((0, String::new(), br#"{"osd":{"op":1}}"#.to_vec().into()))
            .unwrap();
        assert!(client.join().unwrap().contains("\"op\": 1"));
    }

    /// A body the render thread finished wakes the control core like a queued request: a `ceph tell` counter reply must
    /// not wait for unrelated traffic while the core sleeps.
    #[test]
    fn a_rendered_body_wakes_the_control_core() {
        #[derive(Debug)]
        struct Woken(Mutex<Sender<()>>);
        impl ingress::Waker for Woken {
            fn wake(&self) {
                let _ = self.0.lock().unwrap().send(());
            }
        }
        let p = std::env::temp_dir().join(format!("asok-render-wake-{}.asok", std::process::id()));
        let (_srv, rx) = start(&p).unwrap();
        let (tx, woken) = channel();
        rx.set_waker(Arc::new(Woken(Mutex::new(tx))));
        let body = rx
            .render(Out::Json(serde_json::json!({"osd": {"op": 1}})), true)
            .expect("render thread runs");
        woken
            .recv_timeout(Duration::from_secs(5))
            .expect("WARNING TIMEOUT asok render wake exceeded 5s (test): the finished body did not wake the core");
        assert!(rx.waiting(), "the re-check sees the finished body");
        assert_eq!(rx.rendered(&body).unwrap(), br#"{"osd":{"op":1}}"#);
        assert!(!rx.waiting());
    }

    #[test]
    fn slow_admin_client_does_not_block_another_client() {
        let p = std::env::temp_dir().join(format!("asok-parallel-{}.asok", std::process::id()));
        let (_srv, _rx) = start(&p).unwrap();
        let mut stalled = UnixStream::connect(&p).unwrap();
        stalled.write_all(b"{unfinished").unwrap();
        let mut ready = UnixStream::connect(&p).unwrap();
        ready
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        ready.write_all(b"0\0").unwrap();
        let mut reply = [0; 5];
        ready.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [0, 0, 0, 1, b'2']);
    }

    /// The socket is restricted to owner and group, and a mode that cannot be set is an error (it used to be swallowed:
    /// the daemon served admin commands on a socket any local user could reach).
    #[test]
    fn the_admin_socket_is_restricted_and_a_failed_restriction_is_an_error() {
        use std::os::unix::fs::PermissionsExt as _;
        let p = std::env::temp_dir().join(format!("asok-mode-{}.asok", std::process::id()));
        let (srv, _rx) = start(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "{}: {mode:04o}", p.display());
        drop(srv);
        // the result is propagated, never discarded
        let dir = std::fs::File::open(std::env::temp_dir()).unwrap();
        assert!(restrict_socket(&dir, c"asok-mode-absent").is_err());
    }

    /// A private directory per test: the staging directory must be gone after every start.
    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("asok-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir(&d).unwrap();
        d
    }

    fn entries(d: &Path) -> Vec<std::ffi::OsString> {
        let mut v: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        v.sort();
        v
    }

    /// A permission failure after the bind publishes nothing and leaves no staging directory behind.
    #[test]
    fn a_failed_restriction_removes_the_bound_socket() {
        let d = scratch("fail");
        let p = d.join("osd.asok");
        let r = start_with(&p, |_, _| Err(std::io::Error::other("chmod refused")));
        assert!(r.is_err());
        assert!(entries(&d).is_empty(), "left behind: {:?}", entries(&d));
        std::fs::remove_dir(d).unwrap();
    }

    /// A failed start never touches the published path: a socket another daemon bound there meanwhile stays.
    #[test]
    fn a_failed_restriction_keeps_a_socket_bound_by_another_daemon() {
        let d = scratch("swap");
        let p = d.join("osd.asok");
        let mut other = None;
        let r = start_with(&p, |_, _| {
            other = Some(UnixListener::bind(&p).unwrap());
            Err(std::io::Error::other("chmod refused"))
        });
        assert!(r.is_err());
        assert!(
            UnixStream::connect(&p).is_ok(),
            "the other daemon's socket was removed"
        );
        drop(other);
        std::fs::remove_file(&p).unwrap();
        assert!(entries(&d).is_empty(), "left behind: {:?}", entries(&d));
        std::fs::remove_dir(d).unwrap();
    }

    /// NT-security-03: a writer of the parent directory swaps the socket path for a symlink to a private file between
    /// bind and chmod. The chmod must not follow it (it used to widen the target to 0660); the published socket replaces
    /// the planted link.
    #[test]
    fn restriction_never_follows_a_symlink_planted_at_the_path() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = scratch("plant");
        let p = d.join("osd.asok");
        let victim = d.join("keyring");
        std::fs::write(&victim, b"secret").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (srv, _rx) = start_with(&p, |dir, name| {
            let _ = std::fs::remove_file(&p);
            std::os::unix::fs::symlink(&victim, &p).unwrap();
            restrict_socket(dir, name)
        })
        .unwrap();
        let mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "victim widened to {mode:04o}");
        assert!(
            std::fs::symlink_metadata(&p)
                .unwrap()
                .file_type()
                .is_socket()
        );
        assert!(UnixStream::connect(&p).is_ok());
        drop(srv);
        assert_eq!(entries(&d), vec![std::ffi::OsString::from("keyring")]);
        std::fs::remove_dir_all(d).unwrap();
    }

    /// A stale socket (nobody listens) is replaced in place; the replacement answers.
    #[test]
    fn a_stale_socket_is_replaced() {
        let d = scratch("stale");
        let p = d.join("osd.asok");
        drop(UnixListener::bind(&p).unwrap());
        let (srv, _rx) = start(&p).unwrap();
        assert!(UnixStream::connect(&p).is_ok());
        drop(srv);
        assert!(entries(&d).is_empty(), "left behind: {:?}", entries(&d));
        std::fs::remove_dir(d).unwrap();
    }

    /// A request longer than [`MAX_REQ`] is answered with an error, not dropped (the client used to see a bare EOF).
    #[test]
    fn an_oversize_request_is_refused_with_an_error() {
        let p = std::env::temp_dir().join(format!("asok-large-{}.asok", std::process::id()));
        let (_srv, _rx) = start(&p).unwrap();
        let c = UnixStream::connect(&p).unwrap();
        let writer = std::thread::spawn(move || {
            let mut c = c;
            // no terminator: the server must not wait for the rest of an impossible request
            let _ = c.write_all(&vec![b'x'; MAX_REQ + 1]);
            c
        });
        let mut c = writer.join().unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut len = [0u8; 4];
        c.read_exact(&mut len)
            .expect("the server answers instead of closing");
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        c.read_exact(&mut body).unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.starts_with("ERROR: (22)"), "{text}");
        assert!(text.contains("request exceeds"), "{text}");
    }

    /// A reply body is length-prefixed with a u32; one that does not fit is refused at the boundary instead of sending a
    /// truncated length that desynchronizes the client.
    #[test]
    fn a_reply_that_does_not_fit_the_length_header_is_refused() {
        assert_eq!(reply_len(0), Some(0));
        assert_eq!(reply_len(u32::MAX as usize), Some(u32::MAX));
        assert_eq!(reply_len(u32::MAX as usize + 1), None);
    }

    #[test]
    fn protocol_roundtrip() {
        let p = std::env::temp_dir().join(format!("asok-test-{}.asok", std::process::id()));
        let (srv, rx) = start(&p).unwrap();
        let core = std::thread::spawn(move || {
            for _ in 0..3 {
                let r = rx.rx.recv().unwrap();
                let v: Value = serde_json::from_str(&r.cmd).unwrap();
                let res = match v["prefix"].as_str().unwrap() {
                    "perf dump" => (
                        0,
                        String::new(),
                        Out::Json(serde_json::json!({"osd": {"op": 1}})),
                    ),
                    _ => (-22, "bad".to_owned(), Out::default()),
                };
                r.reply.send(res).unwrap();
            }
        });
        assert_eq!(ask(&p, b"0"), "2");
        let pretty = ask(&p, br#"{"prefix":"perf dump"}"#.as_slice());
        assert!(
            pretty.contains("\"op\": 1") && pretty.contains('\n'),
            "{pretty}"
        );
        let compact = br#"{"prefix":"perf dump","format":"json"}"#;
        assert_eq!(ask(&p, compact), r#"{"osd":{"op":1}}"#);
        assert_eq!(ask(&p, b"nope"), "ERROR: (22) Invalid argument\nbad\n");
        core.join().unwrap();
        // a second daemon on the same path is refused while this one lives
        assert!(start(&p).is_err());
        drop(srv);
        assert!(!p.exists());
    }

    /// jsonl and plain bodies reach the client byte for byte (one object per line, newline-terminated).
    #[test]
    fn jsonl_and_plain_bodies_are_not_reformatted() {
        let ok = |b: &[u8]| (0, String::new(), Out::Raw(b.to_vec()));
        let one = b"{\"a\":1}\n";
        assert_eq!(render(r#"{"prefix":"x","format":"jsonl"}"#, ok(one)), one);
        let two = b"{\"a\":1}\n{\"a\":2}\n";
        assert_eq!(render(r#"{"prefix":"x","format":"jsonl"}"#, ok(two)), two);
        let plain = b"line\n";
        assert_eq!(
            render(r#"{"prefix":"x","format":"plain"}"#, ok(plain)),
            plain
        );
        assert_eq!(render(r#"{"prefix":"x","format":"jsonl"}"#, ok(b"")), b"");
    }

    #[test]
    fn replacement_admin_socket_survives_old_server_drop() {
        let p = std::env::temp_dir().join(format!("asok-replace-{}.asok", std::process::id()));
        let (old, _old_rx) = start(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        let (replacement, _new_rx) = start(&p).unwrap();
        drop(old);
        assert!(
            UnixStream::connect(&p).is_ok(),
            "replacement must stay reachable"
        );
        drop(replacement);
        assert!(!p.exists(), "the owner removes its own socket");
    }

    #[test]
    fn drop_joins_accept_even_after_socket_path_is_unlinked() {
        let path = std::env::temp_dir().join(format!("asok-owned-{}.sock", std::process::id()));
        for unlink in [false, true] {
            let (server, _requests) = start(&path).unwrap();
            let workers = Arc::downgrade(&server.workers);
            if unlink {
                std::fs::remove_file(&path).unwrap();
            }
            drop(server);
            assert!(
                workers.upgrade().is_none(),
                "all worker and accept owners retired"
            );
            assert!(!path.exists());
        }
    }

    #[test]
    fn legacy_codes() {
        assert_eq!(
            parse_request(&[0, 0, 0, 1]),
            r#"{"prefix":"perfcounters_dump"}"#
        );
        assert_eq!(parse_request(b"perf dump"), r#"{"prefix":"perf dump"}"#);
    }
}
