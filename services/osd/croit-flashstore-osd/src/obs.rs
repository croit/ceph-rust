// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Process-level observability wiring (doc/spec/ops-observability.md): log sink (stderr / journald + optional file,
//! reopened on SIGHUP or `log reopen`), admin socket, crash dumps. Everything here is cold-path and off the hot cores.
use crate::logsink::{self, LogCmd, Sink};
use osd::{Backend, Osd};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::time::Duration;
use std::time::Instant;

/// Sink queue shared with the sink worker; set by [`start_sink`].
static LOG_TX: OnceLock<SyncSender<LogCmd>> = OnceLock::new();
/// A reopen is due: the request itself, so a full queue cannot lose it (the [`LogCmd::Reopen`] only wakes the worker,
/// and a full queue wakes it anyway).
static REOPEN: AtomicBool = AtomicBool::new(false);

/// `perf dump` logger `flashstore_dma_pool`: the SPDK DMA pool (when built in) and the kernel tier's shelf.
fn dma_pool_counters() -> Vec<(String, u64)> {
    #[cfg(feature = "spdk")]
    let v = nvme::dmapool::counters();
    #[cfg(not(feature = "spdk"))]
    let v = Vec::new();
    // the kernel tier's shelf exists only in builds with the kernel NVMe backend (not in the kernel-probe lab build)
    #[cfg(all(feature = "kernel-nvme", target_os = "linux"))]
    let v = v.into_iter().chain(nvme::kdev::pool_counters()).collect();
    v
}

fn start_sink(mut sink: Sink) {
    if LOG_TX.get().is_some() {
        return;
    }
    let (tx, rx) = sync_channel(sink.queue_cap());
    let result = std::thread::Builder::new()
        .name("osd-log".into())
        .spawn(move || {
            place_helper();
            while let Ok(cmd) = rx.recv() {
                if REOPEN.swap(false, Ordering::AcqRel) {
                    logsink::reopen_sink(&mut sink);
                }
                logsink::handle(&mut sink, cmd);
            }
        });
    if result.is_ok() {
        let _ = LOG_TX.set(tx);
    } else {
        eprintln!("croit-flashstore-osd: could not start log worker; falling back to stderr");
    }
}

/// Request reopening without waiting behind filesystem IO (the worker performs it before its next wait).
pub(crate) fn reopen() {
    REOPEN.store(true, Ordering::Release);
    if let Some(tx) = LOG_TX.get() {
        // a full queue already holds the wake-up: the worker sees the flag at its next command
        let _ = tx.try_send(logsink::LogCmd::Reopen);
    }
}

/// Queue a sink command without waiting; one that cannot be queued is reported (a lost admin command must be loud).
fn queue(tx: &SyncSender<LogCmd>, cmd: LogCmd, what: &str) -> bool {
    match tx.try_send(cmd) {
        Ok(()) => true,
        Err(std::sync::mpsc::TrySendError::Full(_)) => {
            eprintln!("croit-flashstore-osd: WARNING log {what} not queued (sink queue full)");
            false
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
            eprintln!("croit-flashstore-osd: WARNING log {what} not queued (sink gone)");
            false
        }
    }
}

/// `log flush`: queue a flush without waiting on the sink (the command answers empty, classic).
pub(crate) fn flush_now() {
    if let Some(tx) = LOG_TX.get() {
        queue(tx, LogCmd::Flush, "flush");
    }
}

/// `log dump`: queue the dump without waiting on the sink (the command answers empty, classic).
pub(crate) fn dump_now(levels: String) {
    if let Some(tx) = LOG_TX.get() {
        queue(tx, LogCmd::Dump { levels }, "dump");
    }
}

/// Start-up warning of a helper thread that could not start: names the helper and what the daemon runs without.
// The kernel-probe dev build starts neither the liveness checker nor the SIGHUP worker (it has no `sdnotify`/`sighup`);
// `test` keeps the warning contract covered in that build shape.
#[cfg(any(all(feature = "knet", target_os = "linux"), test))]
pub(crate) fn spawn_warning(name: &str, e: &std::io::Error, consequence: &str) -> String {
    format!("croit-flashstore-osd: WARNING {name} thread: {e} ({consequence})")
}

/// Spawn a named helper thread; a failed start is reported and the daemon keeps running without that helper.
#[cfg(all(feature = "knet", target_os = "linux"))]
pub(crate) fn spawn_helper(name: &str, consequence: &str, f: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new().name(name.into()).spawn(f) {
        eprintln!("{}", spawn_warning(name, &e, consequence));
    }
}

/// Preserve the crash tail immediately; enqueue a bounded sink copy without waiting.
pub(crate) fn emit(t0: Instant, line: osd::LogLine) {
    osd::crash::note(&line.text);
    let r = logsink::line_entry(t0.elapsed().as_secs_f64(), line.prio, &line.text);
    if let Some(tx) = LOG_TX.get() {
        if !logsink::enqueue_line(tx, r) {
            logsink::LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        // Preserve diagnostics before setup and on worker creation failure.
        // Only this exceptional cold fallback performs sink IO on the caller.
        eprintln!("[{:9.3}] {}", t0.elapsed().as_secs_f64(), line.text);
    }
}

/// What `setup` started; keep it alive until the OSD exits. Drop stops and joins the admin socket workers (they may hold
/// replies in the DPDK heap, which must not outlive `main`, `osd::asok`) and removes the socket. The other threads of the
/// process outside the cores never allocate 128 KiB or more (`eal_heap::HUGE_MIN`): osd-log (lines capped at
/// `LOG_TEXT_MAX`), sighup, sd-watchdog, asok-accept.
#[derive(Debug, Default)]
pub(crate) struct Obs {
    _asok: Option<osd::asok::AsokServer>,
}

impl Drop for Obs {
    fn drop(&mut self) {
        // Shutdown has a bounded best-effort drain: a failed sink cannot hang exit.
        if let Some(tx) = LOG_TX.get() {
            let (done, rx) = std::sync::mpsc::channel();
            if tx.try_send(LogCmd::FlushAndAck(done)).is_ok()
                && rx.recv_timeout(Duration::from_millis(500)).is_err()
            {
                eprintln!("WARNING TIMEOUT log flush exceeded 0.5s (shutdown, sink busy or gone)");
            }
        }
    }
}

/// After the control core's [`Osd`] exists (identity known): log sink, crash reporting with the effective config and
/// identity (refines the early one of `main`), admin socket. Failures are reported
/// and never stop the daemon.
pub(crate) fn setup<B: Backend>(osd: &mut Osd<B>) -> Obs {
    let id = osd.whoami();
    let (log_file, to_stderr, crash_dir, asok_path, max_recent, max_new) = {
        let c = osd.config();
        let cluster = c.get("cluster").unwrap_or("ceph").to_owned();
        let meta = osd::schema::Meta::new(&cluster, id, osd.hostname());
        let get = |k: &str| {
            osd::schema::get(c, &meta, k)
                .map(|s| s.trim().to_owned())
                .unwrap_or_default()
        };
        for k in ["log_to_syslog", "log_to_journald", "log_to_graylog"] {
            if c.bool(k, false) {
                eprintln!(
                    "croit-flashstore-osd: WARNING {k} is set but not implemented (logs go to the file / stderr sink)"
                );
            }
        }
        (
            if c.bool("log_to_file", false) {
                get("log_file")
            } else {
                String::new()
            },
            c.bool("log_to_stderr", true),
            get("crash_dir"),
            get("admin_socket"),
            c.u64("log_max_recent", 10_000) as usize,
            c.u64("log_max_new", 1_000) as usize,
        )
    };
    let mut file = None;
    if !log_file.is_empty() {
        let p = PathBuf::from(&log_file);
        match logsink::open_log(&p) {
            Ok(f) => file = Some((p, f)),
            Err(e) => {
                eprintln!(
                    "croit-flashstore-osd: WARNING log_file {log_file}: {e} (logging to stderr)"
                );
            }
        }
    }
    // never lose the diagnostics because the file could not be opened
    let to_stderr = to_stderr || (file.is_none() && !log_file.is_empty());
    let sink = Sink::new(to_stderr, file, max_recent, max_new, log_file.clone());
    osd::set_helper_thread_start(place_helper);
    #[cfg(feature = "knet")]
    if let Some(h) = rt::helper_cpus() {
        let cpus: Vec<String> = h.cpus.iter().map(usize::to_string).collect();
        eprintln!(
            "croit-flashstore-osd: helper threads (admin socket, log) on cpus {}{}",
            cpus.join(","),
            if h.shared {
                " (shared with the cores: the affinity mask has no CPU besides theirs)"
            } else {
                ""
            }
        );
    }
    start_sink(sink);
    osd::set_log_reopen(reopen);
    osd::set_log_flush(flush_now);
    osd::set_log_dump(dump_now);
    osd::set_read_shared_gauge(nvme::shared_pinned);
    #[cfg(feature = "spdk")]
    osd::set_payload_pool_counters(eal_heap::huge_pool_counters);
    osd::set_dma_pool_counters(dma_pool_counters);
    #[cfg(feature = "knet")]
    sighup_reopen();
    // the dump's owner is the crash directory's: create it as the user the daemon runs as before the handler resolves it
    let crash_dir = PathBuf::from(crash_dir);
    if !crash_dir.as_os_str().is_empty()
        && let Err(e) = std::fs::create_dir_all(&crash_dir)
    {
        eprintln!(
            "croit-flashstore-osd: WARNING crash dir {}: {e}",
            crash_dir.display()
        );
    }
    // name the data device in every crash report: support must be able to tie a crash to its block device
    let device = nvme::health::device();
    osd::crash::install(osd::crash::CrashCfg {
        dir: crash_dir,
        entity: format!("osd.{id}"),
        version: osd::version::ceph_version_pretty(),
        process: "croit-flashstore-osd".into(),
        device_serial: device
            .as_ref()
            .map_or_else(String::new, |d| d.ident.serial.clone()),
        device_model: device
            .as_ref()
            .map_or_else(String::new, |d| d.ident.model.clone()),
    });
    let mut o = Obs::default();
    if !asok_path.is_empty() {
        match osd::asok::start(std::path::Path::new(&asok_path)) {
            Ok((srv, rx)) => {
                osd.attach_asok(rx);
                o._asok = Some(srv);
                eprintln!("croit-flashstore-osd: admin socket {asok_path}");
            }
            Err(e) => eprintln!(
                "croit-flashstore-osd: admin socket {asok_path}: {e} (continuing without)"
            ),
        }
    }
    o
}

/// First thing of every helper thread: move off the cores' CPUs (it inherits the CPU of the core that starts it;
/// `rt::set_core_cpus`).
fn place_helper() {
    #[cfg(feature = "knet")]
    if let Err(e) = rt::place_helper_thread() {
        eprintln!("croit-flashstore-osd: helper thread cpu placement: {e} (continuing)");
    }
}

/// SIGHUP requests a worker reopen (it runs before the worker's next command; sink IO can delay it).
#[cfg(feature = "knet")]
fn sighup_reopen() {
    use signal_hook::consts::SIGHUP;
    let Ok(mut sigs) = signal_hook::iterator::Signals::new([SIGHUP]) else {
        return;
    };
    spawn_helper("sighup", "log reopen on SIGHUP not served", move || {
        place_helper();
        for _ in sigs.forever() {
            reopen();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    /// A full sink queue must not swallow admin commands silently (flush and dump alike, and a lost sink is named). Runs
    /// itself as a child: the warning goes to stderr.
    #[test]
    fn a_command_that_cannot_be_queued_is_reported() {
        const CHILD: &str = "FLASHSTORE_LOG_QUEUE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "obs::tests::a_command_that_cannot_be_queued_is_reported",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "child failed: {err}");
            assert!(
                err.contains("WARNING log flush not queued (sink queue full)"),
                "{err}"
            );
            assert!(
                err.contains("WARNING log dump not queued (sink gone)"),
                "{err}"
            );
            return;
        }
        let (tx, rx) = sync_channel(1);
        assert!(queue(&tx, LogCmd::Flush, "flush"), "empty queue");
        assert!(!queue(&tx, LogCmd::Flush, "flush"), "full queue");
        drop(rx);
        let (tx, rx) = sync_channel(1);
        drop(rx);
        assert!(
            !queue(
                &tx,
                LogCmd::Dump {
                    levels: String::new()
                },
                "dump"
            ),
            "sink gone"
        );
    }

    /// A helper thread that cannot start must be reported (naming what the daemon runs without). The spawn failure itself
    /// cannot be provoked portably in a test; the pinned contract is the WARNING rendering both call sites use.
    #[test]
    fn a_failed_helper_thread_is_reported_loudly() {
        let e = std::io::Error::from(std::io::ErrorKind::WouldBlock);
        let w = spawn_warning(
            "liveness",
            &e,
            "no WATCHDOG=1 pings, no stalled-core suicide",
        );
        assert!(
            w.starts_with("croit-flashstore-osd: WARNING liveness thread: "),
            "{w}"
        );
        assert!(w.contains("no WATCHDOG=1 pings"), "{w}");
        let w = spawn_warning("sighup", &e, "log reopen on SIGHUP not served");
        assert!(w.contains("WARNING sighup thread: "), "{w}");
    }

    #[test]
    #[ignore = "local slow-socket sink comparison; baseline synchronous algorithm versus bounded worker"]
    fn perf_slow_log_sink_owner_residence() {
        use std::io::Read;
        use std::os::fd::OwnedFd;
        const LINES: usize = 512;
        fn slow_sink() -> (Sink, std::thread::JoinHandle<usize>) {
            let (writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
            let file = File::from(OwnedFd::from(writer));
            let reader = std::thread::spawn(move || {
                let mut chunk = [0; 4096];
                let mut lines = 0;
                let mut bytes = 0;
                while lines < LINES {
                    let n = reader.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes += n;
                    lines += chunk[..n].iter().filter(|&&b| b == b'\n').count();
                    std::thread::sleep(Duration::from_micros(500));
                }
                bytes
            });
            (
                Sink::new(
                    false,
                    Some((PathBuf::new(), file)),
                    100,
                    LINES,
                    String::new(),
                ),
                reader,
            )
        }
        let text = "x".repeat(4096);
        let (sink, reader) = slow_sink();
        let old = std::sync::Mutex::new(sink);
        let started = Instant::now();
        for _ in 0..LINES {
            osd::crash::note(&text);
            logsink::write_entry(&mut old.lock().unwrap(), logsink::line_entry(1., 1, &text));
        }
        let baseline_owner_ns = started.elapsed().as_nanos();
        let baseline_bytes = reader.join().unwrap();
        let (sink, reader) = slow_sink();
        start_sink(sink);
        let started = Instant::now();
        for _ in 0..LINES {
            emit(
                started,
                osd::LogLine {
                    prio: 1,
                    text: text.clone(),
                },
            );
        }
        let queued_owner_ns = started.elapsed().as_nanos();
        let (done, completion) = std::sync::mpsc::channel();
        LOG_TX
            .get()
            .unwrap()
            .try_send(LogCmd::FlushAndAck(done))
            .unwrap();
        completion.recv_timeout(Duration::from_secs(5)).unwrap();
        let queued_bytes = reader.join().unwrap();
        assert_eq!(baseline_bytes, queued_bytes);
        assert_eq!(logsink::LOG_DROPPED.load(Ordering::Relaxed), 0);
        println!(
            "log lines={LINES} bytes={queued_bytes} baseline_owner_ns={baseline_owner_ns} queued_owner_ns={queued_owner_ns}"
        );
    }
}
