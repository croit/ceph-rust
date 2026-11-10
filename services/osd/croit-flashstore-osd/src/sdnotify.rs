// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Minimal systemd notify protocol (sd_notify(3)) and the core liveness checker thread (`osd::liveness`).
//! `READY=1` + `STATUS=booting` once core 0 runs (store mounted, loop turning): from then on the start is complete,
//! like the classic `Type=simple` unit, so waiting in preboot (`noup`, mon outage, map catch-up) never trips
//! `TimeoutStartSec`; `STATUS=active` when up in the map; `WATCHDOG=1` pings. Notification is a no-op when
//! `NOTIFY_SOCKET` is unset (foreground, container without notify); the checker always runs. No dependencies.
//! Sends never block (nonblocking socket): a service manager that stops draining its queue must not stall a core (log
//! callback) or the liveness checker. An undelivered `READY=1` is not latched; the checker resends it every second.
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Send one datagram to `$NOTIFY_SOCKET` (path or `@abstract`). true = the kernel accepted it or there is no
/// `NOTIFY_SOCKET`; otherwise it is dropped (best effort).
pub fn notify(msg: &str) -> bool {
    match std::env::var_os("NOTIFY_SOCKET").filter(|p| !p.is_empty()) {
        Some(p) => notify_at(&p, msg),
        None => true,
    }
}

fn notify_at(p: &std::ffi::OsStr, msg: &str) -> bool {
    let Ok(s) = UnixDatagram::unbound() else {
        return false;
    };
    if s.set_nonblocking(true).is_err() {
        return false;
    }
    let b = p.as_encoded_bytes();
    if let Some(name) = b.strip_prefix(b"@") {
        use std::os::linux::net::SocketAddrExt;
        std::os::unix::net::SocketAddr::from_abstract_name(name)
            .and_then(|a| s.send_to_addr(msg.as_bytes(), &a))
            .is_ok()
    } else {
        s.send_to(msg.as_bytes(), std::path::Path::new(p)).is_ok()
    }
}

/// `READY=1` delivered.
static READY: AtomicBool = AtomicBool::new(false);
/// The OSD is up in the map (status `active`, else `booting`).
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Current status; `READY=1` with it until one send is accepted.
fn publish() {
    let status = if ACTIVE.load(Ordering::Relaxed) {
        "active"
    } else {
        "booting"
    };
    if READY.load(Ordering::Relaxed) {
        notify(&format!("STATUS={status}"));
    } else if notify(&format!("READY=1\nSTATUS={status}")) {
        READY.store(true, Ordering::Relaxed);
    }
}

/// Called with every OSD log line: the boot state machine logs `osd::ACTIVE_MARKER` (at level 0, immune to debug_osd) when the OSD is up in the map.
pub fn on_log(line: &str) {
    if line.contains(osd::ACTIVE_MARKER) {
        ACTIVE.store(true, Ordering::Relaxed);
        publish();
    }
}

/// Watchdog interval from `WATCHDOG_USEC` (only if `WATCHDOG_PID` is unset or ours).
pub fn watchdog_interval() -> Option<Duration> {
    let us: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    if let Ok(p) = std::env::var("WATCHDOG_PID")
        && p.parse::<u32>().ok() != Some(std::process::id())
    {
        return None;
    }
    (us > 0).then(|| Duration::from_micros(us / 2))
}

/// Start the liveness checker thread (once per second, `osd::liveness::Checker`): `READY=1` when core 0 runs, a stalled
/// core makes the OSD unhealthy (heartbeat pings dropped) and past `osd_op_thread_suicide_timeout` aborts the process
/// (crash report, restart by the service manager). `WATCHDOG=1` every WatchdogSec/2 while the checker runs: systemd's
/// watchdog only catches a process whose checker itself is stuck (adr 0034).
pub fn start_liveness() {
    let sd = watchdog_interval();
    crate::obs::spawn_helper(
        "liveness",
        "no WATCHDOG=1 pings, no stalled-core suicide",
        move || {
            let live = &osd::liveness::LIVENESS;
            let mut chk = osd::liveness::Checker::default();
            let t0 = std::time::Instant::now();
            let mut last_ping: Option<Duration> = None;
            loop {
                let now = t0.elapsed();
                if live.started() && !READY.load(Ordering::Relaxed) {
                    publish();
                }
                let v = chk.check(live, now, |w| eprintln!("croit-flashstore-osd: {w}"));
                if matches!(v, osd::liveness::Verdict::Suicide { .. }) {
                    std::process::abort(); // the checker already printed the WARNING TIMEOUT line
                }
                if let Some(iv) = sd
                    && last_ping.is_none_or(|t| now.saturating_sub(t) >= iv)
                {
                    last_ping = Some(now);
                    notify("WATCHDOG=1");
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr;

    /// Fill the receive queue of `to` (`net.unix.max_dgram_qlen`) until a fresh sender is refused. One sender alone
    /// runs into its own send buffer first (queued datagrams stay charged to it), so each sender sends until its
    /// buffer is full; the returned senders keep their queued datagrams alive.
    fn fill(to: &SocketAddr) -> Vec<UnixDatagram> {
        let mut senders = Vec::new();
        loop {
            let f = UnixDatagram::unbound().unwrap();
            f.set_nonblocking(true).unwrap();
            let mut sent = 0;
            loop {
                match f.send_to_addr(b"fill", to) {
                    Ok(_) => sent += 1,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("fill notify queue: {e}"),
                }
            }
            senders.push(f);
            if sent == 0 {
                return senders;
            }
        }
    }

    /// A full queue of the service manager must not block the sender (a core's log callback, the liveness checker).
    #[test]
    fn a_full_notify_queue_cannot_block_the_caller() {
        let name = format!("flashstore-notify-full-{}", std::process::id());
        let a = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let receiver = UnixDatagram::bind_addr(&a).unwrap();
        let _fill = fill(&a);
        let (done, completed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            done.send(notify_at(
                std::ffi::OsStr::new(&format!("@{name}")),
                "WATCHDOG=1",
            ))
            .unwrap();
        });
        let result = completed.recv_timeout(Duration::from_secs(2));
        // a blocking sender is released by closing the receiver: the test never hangs
        drop(receiver);
        worker.join().unwrap();
        match result {
            Ok(delivered) => assert!(!delivered, "full queue reported as delivered"),
            Err(_) => panic!("WARNING TIMEOUT notify exceeded 2s (full notify queue)"),
        }
    }

    #[test]
    fn datagram_reaches_socket() {
        let p = std::env::temp_dir().join(format!("sdn-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let r = UnixDatagram::bind(&p).unwrap();
        r.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        // env and READY are process-global: this is the only test touching NOTIFY_SOCKET or publish()
        unsafe { std::env::set_var("NOTIFY_SOCKET", &p) };
        // queue full at boot: READY=1 is dropped, not latched
        let fill = fill(&SocketAddr::from_pathname(&p).unwrap());
        publish();
        assert!(!READY.load(Ordering::Relaxed));
        let mut b = [0u8; 64];
        r.set_nonblocking(true).unwrap();
        while r.recv(&mut b).is_ok() {}
        drop(fill);
        r.set_nonblocking(false).unwrap();
        publish(); // next checker tick: core 0 runs, the start is complete
        on_log("osd.1 is now active (up_from 5, map 6)"); // READY only once, then status updates
        notify("WATCHDOG=1");
        let n = r.recv(&mut b).unwrap();
        assert_eq!(&b[..n], b"READY=1\nSTATUS=booting");
        let n = r.recv(&mut b).unwrap();
        assert_eq!(&b[..n], b"STATUS=active");
        let n = r.recv(&mut b).unwrap();
        assert_eq!(&b[..n], b"WATCHDOG=1");
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        let _ = std::fs::remove_file(&p);
    }
}
