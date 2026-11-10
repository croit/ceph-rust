// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Log sink state machine (spec ops-observability 6.9): the file sink writes
//! `<ISO-8601 local ts with µs and numeric offset> <thread id hex> <priority> osd <message>`; stderr keeps the existing
//! `[uptime] <message>` driver line. The sink keeps the last `log_max_recent` entries and answers `log dump` with the
//! classic framing. Pure sink logic (no process wiring), so it is unit-tested on every platform.
// The driver wiring (`obs`) is feature-gated; a bare test build compiles the sink without it.
#![cfg_attr(
    not(any(
        all(feature = "kernel-probe", target_os = "linux"),
        all(feature = "knet", target_os = "linux")
    )),
    allow(dead_code)
)]
use std::cell::OnceCell;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::thread::ThreadId;
use std::time::{Duration, Instant};

/// Longest text kept per line; anything longer is cut with a marker.
pub(crate) const LOG_TEXT_MAX: usize = 16 * 1024;

pub(crate) static LOG_DROPPED: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// The emitting thread's id and name, resolved once per thread (`thread_id` formatting is off the core loop).
    static THREAD: OnceCell<(ThreadId, Arc<str>)> = const { OnceCell::new() };
}

/// One recent log entry: emit time (formatted in the sink thread), emitting thread and text.
#[derive(Debug, Clone)]
pub(crate) struct Recent {
    /// Wall clock at emit time, since UNIX_EPOCH.
    at: Duration,
    /// Process uptime at emit time (the classic stderr prefix).
    uptime: f64,
    tid: ThreadId,
    name: Arc<str>,
    prio: u8,
    text: String,
}

pub(crate) struct Sink {
    stderr: bool,
    file: Option<(PathBuf, File)>,
    /// The in-memory recent ring, oldest first, capacity `log_max_recent`.
    recent: VecDeque<Recent>,
    max_recent: usize,
    max_new: usize,
    /// Effective `log_file` ("" = none), for the `log dump` footer.
    log_file: String,
    /// Sink start, the origin of the stderr uptime prefix of sink-generated lines.
    started: Instant,
}

impl Sink {
    pub(crate) fn new(
        stderr: bool,
        file: Option<(PathBuf, File)>,
        max_recent: usize,
        max_new: usize,
        log_file: String,
    ) -> Sink {
        Sink {
            stderr,
            file,
            recent: VecDeque::new(),
            max_recent,
            max_new,
            log_file,
            started: Instant::now(),
        }
    }

    /// Bound of the sink queue: `log_max_new` (spec 6.9).
    pub(crate) fn queue_cap(&self) -> usize {
        self.max_new.max(1)
    }
}

#[derive(Debug)]
pub(crate) enum LogCmd {
    Line(Recent),
    /// `log flush` from a core: flush now, no reply (the command answers without waiting).
    Flush,
    /// SIGHUP / `log reopen`: wakes the worker, which reopens the file sink when the reopen flag is set (`obs::reopen`).
    Reopen,
    /// Shutdown drain: flush and answer, so the waiter can bound it.
    FlushAndAck(std::sync::mpsc::Sender<()>),
    /// `log dump`: write the recent ring plus the caller's `logging levels` section to every sink.
    Dump {
        levels: String,
    },
}

/// The one line the file sink writes: `<ISO-8601 local ts with µs and numeric offset> <thread id hex> <priority>
/// <subsystem> <message>`.
pub(crate) fn format_entry(r: &Recent) -> String {
    format!(
        "{} {} {} osd {}",
        iso_local(r.at),
        tid_hex(r.tid),
        r.prio,
        r.text
    )
}

pub(crate) fn open_log(p: &PathBuf) -> std::io::Result<File> {
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    open_regular(p, true)
}

/// Open `p` for writing `O_NOFOLLOW` at its final component and refuse anything but a regular file. The SPDK
/// tiers keep root after the privilege drop, so a directory the daemon user can write must not redirect the open to
/// another file (a planted symlink would clobber it) or to a FIFO that blocks the opener for good.
pub(crate) fn open_regular(p: &PathBuf, append: bool) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut o = OpenOptions::new();
    o.create(true).write(true);
    if append {
        o.append(true);
    }
    let f = o
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(p)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(f)
}

pub(crate) fn reopen_sink(s: &mut Sink) {
    if let Some((p, f)) = &mut s.file {
        match open_log(p) {
            Ok(n) => *f = n,
            Err(e) => eprintln!(
                "croit-flashstore-osd: WARNING log reopen {}: {e}",
                p.display()
            ),
        }
    }
}

/// `<ts> <tid> <prio> osd <text>` to the file sink, `[uptime] <text>` to stderr, and the entry into the recent ring.
pub(crate) fn write_entry(s: &mut Sink, r: Recent) {
    if s.stderr {
        eprintln!("[{:9.3}] {}", r.uptime, r.text);
    }
    if let Some((_, f)) = &mut s.file {
        let _ = writeln!(f, "{}", format_entry(&r));
    }
    if s.max_recent > 0 {
        while s.recent.len() >= s.max_recent {
            s.recent.pop_front();
        }
        s.recent.push_back(r);
    }
}

/// Raw text to every enabled sink (a dump line).
fn write_text(s: &mut Sink, text: &str) {
    if s.stderr {
        eprintln!("{text}");
    }
    if let Some((_, f)) = &mut s.file {
        let _ = writeln!(f, "{text}");
    }
}

/// ISO-8601 local time with microseconds and the numeric UTC offset (`2026-11-05T11:20:00.123456+0100`); sink thread
/// only (localtime_r is not on the core loop).
fn iso_local(d: Duration) -> String {
    let secs = d.as_secs() as libc::time_t;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: localtime_r fills the caller's `tm`; it returns NULL for a time it cannot represent.
    if unsafe { libc::localtime_r(&secs, tm.as_mut_ptr()) }.is_null() {
        return osd::crash::iso_utc(d);
    }
    // SAFETY: localtime_r returned non-NULL, so the whole `tm` is initialized.
    let tm = unsafe { tm.assume_init() };
    let off = tm.tm_gmtoff;
    let (sign, off) = if off < 0 { ('-', -off) } else { ('+', off) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}{sign}{:02}{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        d.subsec_micros(),
        off / 3600,
        off % 3600 / 60
    )
}

/// `ThreadId` as the classic hex text.
fn tid_hex(t: ThreadId) -> String {
    let raw = format!("{t:?}");
    let n = raw
        .trim_start_matches("ThreadId(")
        .trim_end_matches(')')
        .parse::<u64>()
        .unwrap_or(0);
    format!("{n:x}")
}

/// The emitting thread's id and name; resolved once per thread (one small allocation, no per-line formatting).
fn thread_ident() -> (ThreadId, Arc<str>) {
    THREAD.with(|c| {
        c.get_or_init(|| {
            let t = std::thread::current();
            (t.id(), Arc::from(t.name().unwrap_or("(unnamed)")))
        })
        .clone()
    })
}

fn now_at() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

fn entry(uptime: f64, prio: u8, text: String) -> Recent {
    let (tid, name) = thread_ident();
    Recent {
        at: now_at(),
        uptime,
        tid,
        name,
        prio,
        text,
    }
}

/// `log dump` body: the ring, the caller's levels, the thread map and the buffering numbers (spec 6.9).
fn dump(s: &mut Sink, levels: &str) {
    write_text(s, "--- begin dump of recent events ---");
    let lines: Vec<String> = s.recent.iter().map(format_entry).collect();
    for l in lines {
        write_text(s, &l);
    }
    write_text(s, levels.trim_end_matches('\n'));
    write_text(s, "--- thread id/name ---");
    let mut seen: Vec<(ThreadId, Arc<str>)> = Vec::new();
    let threads: Vec<String> = s
        .recent
        .iter()
        .filter(|r| {
            let k = (r.tid, r.name.clone());
            if seen.contains(&k) {
                false
            } else {
                seen.push(k);
                true
            }
        })
        .map(|r| format!("{} {}", tid_hex(r.tid), r.name))
        .collect();
    for t in threads {
        write_text(s, &t);
    }
    write_text(s, &format!("max_recent {}", s.max_recent));
    write_text(s, &format!("max_new {}", s.max_new));
    write_text(s, &format!("log_file {}", s.log_file));
    write_text(s, "--- end dump of recent events ---");
}

/// One command of the sink worker (also driven directly by the tests).
pub(crate) fn handle(s: &mut Sink, cmd: LogCmd) {
    match cmd {
        LogCmd::Line(r) => {
            let dropped = LOG_DROPPED.swap(0, Ordering::Relaxed);
            if dropped != 0 {
                let text = format!("log queue: {dropped} lines dropped");
                let r = entry(s.started.elapsed().as_secs_f64(), 0, text);
                write_entry(s, r);
            }
            write_entry(s, r);
        }
        LogCmd::Flush => flush(s),
        LogCmd::Reopen => {}
        LogCmd::FlushAndAck(done) => {
            flush(s);
            let _ = done.send(());
        }
        LogCmd::Dump { levels } => {
            dump(s, &levels);
            flush(s);
        }
    }
}

fn flush(s: &mut Sink) {
    if let Some((_, f)) = &mut s.file {
        let _ = f.flush();
    }
}

pub(crate) fn retained_line(line: &str) -> String {
    if line.len() <= LOG_TEXT_MAX {
        return line.to_owned();
    }
    let mut end = LOG_TEXT_MAX - " [truncated]".len();
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} [truncated]", &line[..end])
}

pub(crate) fn enqueue_line(tx: &SyncSender<LogCmd>, r: Recent) -> bool {
    tx.try_send(LogCmd::Line(r)).is_ok()
}

/// One log entry from an OSD line, stamped and thread-tagged on the emitting core (no time or thread formatting).
pub(crate) fn line_entry(uptime: f64, prio: u8, text: &str) -> Recent {
    entry(uptime, prio, retained_line(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_log_text_has_a_byte_bound_and_valid_utf8() {
        let line = "ä".repeat(LOG_TEXT_MAX);
        let retained = retained_line(&line);
        assert!(retained.len() <= LOG_TEXT_MAX);
        assert!(retained.ends_with(" [truncated]"));
        assert_eq!(retained_line("ordinary line"), "ordinary line");
    }

    #[test]
    fn full_log_queue_preserves_accepted_prefix_and_bounds_text() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        assert!(enqueue_line(&tx, line_entry(1., 1, "first")));
        assert!(!enqueue_line(&tx, line_entry(2., 1, "second")));
        match rx.recv().unwrap() {
            LogCmd::Line(r) => assert_eq!((r.prio, r.text.as_str()), (1, "first")),
            _ => panic!("line expected"),
        }
        assert!(enqueue_line(
            &tx,
            line_entry(3., 1, &"x".repeat(LOG_TEXT_MAX * 2))
        ));
        match rx.recv().unwrap() {
            LogCmd::Line(r) => assert!(r.text.len() <= LOG_TEXT_MAX),
            _ => panic!("line expected"),
        }
    }

    /// The file sink is opened `O_NOFOLLOW` at its final component and only a regular file is accepted: a symlink or
    /// FIFO planted in an operator-writable log directory cannot redirect the root SPDK tier's writes or block it.
    #[test]
    fn log_file_never_follows_a_symlink() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("obs-log-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        std::fs::write(&target, "keep").unwrap();
        let link = dir.join("osd.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_log(&link).is_err(), "a symlink is refused");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        // a regular file opens (and appends)
        let plain = dir.join("plain.log");
        let mut f = open_log(&plain).unwrap();
        f.write_all(b"one\n").unwrap();
        drop(f);
        let mut f = open_log(&plain).unwrap();
        f.write_all(b"two\n").unwrap();
        drop(f);
        assert_eq!(std::fs::read_to_string(&plain).unwrap(), "one\ntwo\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sink keeps `log_max_recent` entries and `log dump` writes them with the classic framing to the enabled
    /// sinks (spec ops-observability 6.9): begin marker, entries, logging levels, thread map, max_recent, max_new,
    /// log_file, end marker. The file line is `<local ISO ts> <tid hex> <prio> osd <text>`.
    #[test]
    fn recent_ring_is_bounded_and_log_dump_writes_it() {
        let dir = std::env::temp_dir().join(format!("obs-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("osd.log");
        let f = open_log(&path).unwrap();
        let mut s = Sink::new(
            false,
            Some((path.clone(), f)),
            3,
            1000,
            path.display().to_string(),
        );
        for i in 0..5 {
            handle(
                &mut s,
                LogCmd::Line(line_entry(1., 1, &format!("line {i}"))),
            );
        }
        handle(
            &mut s,
            LogCmd::Dump {
                levels: "--- logging levels ---\n     1/5 osd".into(),
            },
        );
        drop(s.file.take());
        let text = std::fs::read_to_string(&path).unwrap();
        for i in 0..5 {
            assert!(
                text.lines()
                    .any(|l| l.ends_with(&format!(" 1 osd line {i}"))),
                "line {i}: {text}"
            );
        }
        // every log entry starts with `<ISO local ts> <tid hex> <prio> osd `
        for l in text.lines().take(5) {
            let f: Vec<&str> = l.split(' ').collect();
            assert_eq!((f.len(), f[2], f[3]), (6, "1", "osd"), "{l}");
            assert_eq!(f[0].len(), 31, "timestamp {l}");
            assert_eq!(f[0].as_bytes()[10], b'T', "{l}");
            let off = &f[0][26..];
            assert!(matches!(off.as_bytes()[0], b'+' | b'-'), "{l}");
            assert!(off[1..].bytes().all(|b| b.is_ascii_digit()), "{l}");
        }
        let dumped = &text[text
            .find("--- begin dump of recent events ---")
            .expect("begin marker")..];
        assert!(dumped.contains("line 2") && dumped.contains("line 4"));
        assert!(!dumped.contains("line 0"), "{dumped}");
        assert!(!dumped.contains("line 1 "), "{dumped}");
        assert!(dumped.contains("--- logging levels ---"));
        assert!(dumped.contains(" 1/5 osd"));
        assert!(dumped.contains("max_recent 3"));
        assert!(dumped.contains("max_new 1000"));
        assert!(dumped.contains(&format!("log_file {}", path.display())));
        assert!(dumped.contains("--- thread id/name ---"));
        assert!(dumped.ends_with("--- end dump of recent events ---\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
