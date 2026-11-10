// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! DEV-ONLY kernel-TCP driver (ADR 0015 amendment, feature `kernel-probe`): std::net sockets and
//! a polling loop around the sans-IO [`Osd`] / [`MonClient`](monc::MonClient). Single threaded, blocking dial and
//! write with short timeouts; good enough for lab validation, never the production data path.
use crate::monboot::{dial, read_some, sockaddr, write_all};
use crate::{IoCmd, Listener, Osd};
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Local address the kernel would use to reach `target` (no packets are sent).
pub fn local_ip_towards(target: IpAddr, port: u16) -> Option<IpAddr> {
    let wildcard = if target.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    let s = UdpSocket::bind(SocketAddr::new(wildcard, 0)).ok()?;
    s.connect(SocketAddr::new(target, port)).ok()?;
    Some(s.local_addr().ok()?.ip())
}

/// Nonblocking write of as much of `data` as the kernel takes; Err = connection broken.
fn write_some(s: &mut TcpStream, data: &[u8]) -> Result<usize, ()> {
    let mut off = 0;
    while off < data.len() {
        match s.write(&data[off..]) {
            Ok(0) => return Err(()),
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(()),
        }
    }
    Ok(off)
}

/// Where the OSD listeners bind: the addresses of one kind (one per family).
#[derive(Clone, Debug)]
pub struct Binds {
    /// Public listeners.
    pub public: Vec<SocketAddr>,
    /// Cluster listeners.
    pub cluster: Vec<SocketAddr>,
    /// Heartbeat front.
    pub hb_front: Vec<SocketAddr>,
    /// Heartbeat back.
    pub hb_back: Vec<SocketAddr>,
}

/// The four bound OSD listeners, nonblocking (see [`bind_listeners`]).
#[derive(Debug)]
pub struct Listeners(Vec<(Listener, TcpListener)>);

/// Bind the four listeners of `binds`. `AddrInUse` of any of them fails the whole bind (the port search of
/// [`crate::portsel`] then tries the next ports).
pub fn bind_listeners(binds: &Binds) -> std::io::Result<Listeners> {
    [
        (Listener::Public, &binds.public),
        (Listener::Cluster, &binds.cluster),
        (Listener::HbFront, &binds.hb_front),
        (Listener::HbBack, &binds.hb_back),
    ]
    .into_iter()
    .flat_map(|(l, addrs)| addrs.iter().map(move |a| (l, *a)))
    .map(|(l, a)| {
        let s = TcpListener::bind(a)?;
        s.set_nonblocking(true)?;
        Ok((l, s))
    })
    .collect::<std::io::Result<_>>()
    .map(Listeners)
}

/// Run `osd` on the bound `listeners` until it wants to exit or `stop` is set (then shut down gracefully first).
/// Returns the exit code. `log` receives every log line.
pub fn run_osd<B: crate::Backend>(
    osd: &mut Osd<B>,
    listeners: Listeners,
    stop: &Arc<AtomicBool>,
    mut log: impl FnMut(&str),
) -> std::io::Result<i32> {
    let t0 = Instant::now();
    let lst = listeners.0;
    let mut socks: HashMap<u64, TcpStream> = HashMap::new();
    // Bytes the kernel did not take yet (offset = already written). Output is polled from the OSD only when a
    // connection has nothing pending, and the loop always keeps reading (no write-write deadlock).
    let mut pending: HashMap<u64, (Vec<u8>, usize)> = HashMap::new();
    let mut buf = vec![0u8; 1 << 17];
    osd.start(t0.elapsed());
    let mut stopping = false;
    // Latency: after activity keep spinning for a few ms (a request needs several hops + a store sync), sleep only when
    // idle (a fixed 1 ms sleep per iteration cost ~0.5 ms per hop: QD1 4 KiB write 5.5 ms vs 2.0 ms classic in the lab).
    let mut last_work = Instant::now();
    #[cfg(feature = "wprof-on")]
    let mut prof_t = Instant::now();
    #[cfg(feature = "wprof-on")]
    let mut busy = Duration::ZERO;
    loop {
        #[cfg(feature = "wprof-on")]
        let it0 = Instant::now();
        #[cfg(feature = "wprof-on")]
        if prof_t.elapsed() >= Duration::from_secs(2) {
            prof_t = Instant::now();
            log(&format!(
                "wprof busy {:.0} ms of 2000",
                busy.as_secs_f64() * 1e3
            ));
            busy = Duration::ZERO;
            let a = wprof::take();
            if a.iter().any(|s| s.1 > 0) {
                let v: Vec<String> = a
                    .iter()
                    .zip(wprof::NAMES)
                    .filter(|(s, _)| s.1 > 0)
                    .map(|(s, n)| format!("{n}={:.1}ms/{}/{}", s.0 / 1e6, s.1, s.2))
                    .collect();
                log(&format!("wprof 2s: {}", v.join(" ")));
            }
        }
        let now = t0.elapsed();
        if stop.load(Ordering::Relaxed) && !stopping {
            stopping = true;
            osd.shutdown(now);
        }
        for (l, s) in &lst {
            while let Ok((c, peer)) = s.accept() {
                c.set_nodelay(true).ok();
                c.set_nonblocking(true).ok();
                let id = osd.on_accept(*l, peer, t0.elapsed());
                socks.insert(id, c);
                last_work = Instant::now();
            }
        }
        while let Some(c) = osd.poll_io() {
            match c {
                IoCmd::Dial { conn, target, .. } => {
                    let Some(sa) = sockaddr(&target) else {
                        osd.on_dial_failed(conn, false, t0.elapsed());
                        continue;
                    };
                    match dial(sa) {
                        Ok(s) => {
                            socks.insert(conn, s);
                            osd.on_connected(conn, t0.elapsed());
                        }
                        Err(refused) => osd.on_dial_failed(conn, refused, t0.elapsed()),
                    }
                }
                IoCmd::Close { conn } => {
                    socks.remove(&conn);
                    pending.remove(&conn);
                }
                // plain TCP only
                c @ (IoCmd::RdmaPrepare { .. }
                | IoCmd::RdmaAccept { .. }
                | IoCmd::RdmaConnect { .. }
                | IoCmd::RdmaRelease { .. }
                | IoCmd::PlaceReadReply { .. }
                | IoCmd::PlaceReadCancel { .. }
                | IoCmd::SourcePullRead { .. }) => osd.rdma_decline(c, t0.elapsed()),
            }
        }
        let ids: Vec<u64> = socks.keys().copied().collect();
        for id in ids {
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            let alive = match socks.get_mut(&id) {
                Some(s) => read_some(s, &mut buf, |b| chunks.push(b.to_vec())),
                None => continue,
            };
            if !chunks.is_empty() {
                last_work = Instant::now();
            }
            for c in chunks {
                osd.on_bytes(id, &c, t0.elapsed());
            }
            if !alive {
                socks.remove(&id);
                pending.remove(&id);
                osd.on_closed(id, t0.elapsed());
            }
        }
        for id in osd.conn_ids() {
            let Some(s) = socks.get_mut(&id) else {
                // no socket: let the OSD drop what it queued
                let _ = osd.poll_output(id);
                continue;
            };
            let mut ok = true;
            if let Some((p, off)) = pending.get_mut(&id) {
                match write_some(s, &p[*off..]) {
                    Ok(n) => *off += n,
                    Err(()) => ok = false,
                }
                if *off >= p.len() {
                    pending.remove(&id);
                }
            }
            if ok && !pending.contains_key(&id) {
                let out = osd.poll_output(id);
                if !out.is_empty() {
                    last_work = Instant::now();
                    match write_some(s, &out) {
                        Ok(n) if n < out.len() => {
                            pending.insert(id, (out, n));
                        }
                        Ok(_) => {}
                        Err(()) => ok = false,
                    }
                }
            }
            if !ok {
                socks.remove(&id);
                pending.remove(&id);
                osd.on_closed(id, t0.elapsed());
            }
        }
        if osd.poll_store(t0.elapsed()) {
            last_work = Instant::now(); // e.g. a bench writes one block per iteration: no idle sleep in between
        }
        // retained inputs (adr 0084: admission refused when they arrived) are retried every iteration; this driver has no
        // transport pause, and without the call a held peering message was never delivered (croit-flashstore-osd stuck in peering)
        if osd.resume_inputs(t0.elapsed()) {
            last_work = Instant::now();
        }
        if osd.next_timer().is_some_and(|d| d <= t0.elapsed()) {
            osd.on_timer(t0.elapsed());
        }
        osd.end_pass(); // WAL group commit of the txns this pass submitted (adr 0021 am. 67)
        while let Some(l) = osd.poll_log() {
            log(&l);
        }
        if let Some(code) = osd.exit_code() {
            // flush closing frames
            for id in osd.conn_ids() {
                let mut out = pending
                    .remove(&id)
                    .map_or_else(Vec::new, |(p, off)| p[off..].to_vec());
                out.extend(osd.poll_output(id));
                if let Some(s) = socks.get_mut(&id).filter(|_| !out.is_empty()) {
                    let _ = write_all(s, &out);
                }
            }
            return Ok(code);
        }
        #[cfg(feature = "wprof-on")]
        if last_work >= it0 {
            busy += it0.elapsed();
        }
        if last_work.elapsed() < Duration::from_millis(5) {
            std::hint::spin_loop();
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Flag that becomes true on SIGINT / SIGTERM.
pub fn stop_flag_on_signals() -> Arc<AtomicBool> {
    let f = Arc::new(AtomicBool::new(false));
    for s in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        let _ = signal_hook::flag::register(s, f.clone());
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (live: two OSDs deadlocked writing 9 MB replication batches to each other): a write to a peer that does
    /// not read must return a short count immediately, never block.
    #[test]
    fn write_some_never_blocks() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (_peer, _) = l.accept().unwrap(); // never reads
        c.set_nonblocking(true).unwrap();
        let big = vec![7u8; 64 << 20];
        let t = Instant::now();
        let n = write_some(&mut c, &big).unwrap();
        assert!(n < big.len(), "kernel buffers cannot hold 64 MiB");
        assert!(t.elapsed() < Duration::from_secs(2));
    }
}
