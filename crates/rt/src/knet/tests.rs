// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Loopback tests of the kernel tier with a mock OSD (echo / sink): real sockets, real io_uring.
use super::*;
use denc::types::EntityAddr;
use osd::Listener;
use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

/// A received message: (connection, bytes, running crc).
type Got = (u64, Vec<u8>, u32);

#[derive(Default)]
struct Mock {
    next: u64,
    accept_limit: Option<usize>,
    echo: bool,
    live: BTreeSet<u64>,
    rx: HashMap<u64, Vec<u8>>,
    out: HashMap<u64, VecDeque<Bytes>>,
    notified: BTreeSet<u64>,
    io: VecDeque<IoCmd>,
    accepted: Vec<(u64, Listener, u16)>,
    closed: Vec<u64>,
    half_open: bool,
    eof: Vec<(u64, usize)>,
    connected: Vec<u64>,
    failed: Vec<(u64, bool)>,
    /// Stream of `[u64 len][payload]` messages parsed like the msgr2 segment assembler, with the direct-receive hooks.
    direct: bool,
    dst: HashMap<u64, DSt>,
    msgs: Vec<Got>,
    direct_puts: u64,
    direct_takes: u64,
    secure: bool,
    /// Any core-local decoder wants a loan (mirrored by `Local`; the decoders are !Send and stay on the core thread).
    secure_armed: bool,
    secure_takes: u64,
    secure_puts: u64,
    secure_feed_bytes: u64,
    secure_loan_bytes: u64,
    idle_timeout: Option<Duration>,
    last_rx: HashMap<u64, Duration>,
    idle_expired: BTreeSet<u64>,
    progress_calls: u64,
    written: Vec<(u64, usize)>,
    paused: bool,
    paused_connections: BTreeSet<u64>,
    flip_admission: Option<u64>,
    flip_calls: usize,
}

#[derive(Default)]
struct DSt {
    hdr: Vec<u8>,
    len: usize,
    got: usize,
    cur: Vec<u8>,
    crc: u32,
    in_payload: bool,
}

impl Mock {
    fn check_idle(&mut self, now: Duration) {
        let Some(timeout) = self.idle_timeout else {
            return;
        };
        for (&conn, &last) in &self.last_rx {
            if self.live.contains(&conn)
                && now.saturating_sub(last) >= timeout
                && self.idle_expired.insert(conn)
            {
                self.io.push_back(IoCmd::Close { conn });
            }
        }
    }

    fn feed(&mut self, conn: u64, mut data: &[u8]) {
        let s = self.dst.entry(conn).or_default();
        while !data.is_empty() {
            if !s.in_payload {
                let n = (8 - s.hdr.len()).min(data.len());
                s.hdr.extend_from_slice(&data[..n]);
                data = &data[n..];
                if s.hdr.len() < 8 {
                    break;
                }
                s.len = u64::from_le_bytes(s.hdr[..8].try_into().unwrap()) as usize;
                s.hdr.clear();
                s.cur = Vec::with_capacity(s.len);
                s.got = 0;
                s.crc = !0;
                s.in_payload = true;
            } else {
                let n = (s.len - s.got).min(data.len());
                s.cur.extend_from_slice(&data[..n]);
                s.crc = crc::crc32c(s.crc, &data[..n]);
                s.got += n;
                data = &data[n..];
            }
            if s.in_payload && s.got == s.len {
                s.in_payload = false;
                let v = std::mem::take(&mut s.cur);
                self.msgs.push((conn, v, s.crc));
            }
        }
    }
}

#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Mock>>);

impl Driver for Shared {
    fn keep_half_open(&self) -> bool {
        self.0.lock().unwrap().half_open
    }
    fn on_eof(&mut self, conn: u64, _now: Duration) {
        let mut m = self.0.lock().unwrap();
        let bytes = m.rx.get(&conn).map_or(0, Vec::len);
        m.eof.push((conn, bytes));
    }
    fn listener_accept_ready(&self, _: usize) -> bool {
        let state = self.0.lock().unwrap();
        state
            .accept_limit
            .is_none_or(|limit| state.live.len() < limit)
    }

    fn listener_accept_capacity(&self, _: usize) -> usize {
        let state = self.0.lock().unwrap();
        state
            .accept_limit
            .map_or(usize::MAX, |limit| limit.saturating_sub(state.live.len()))
    }
    fn admission_ready(&self) -> bool {
        !self.0.lock().unwrap().paused
    }
    fn input_ready(&self, conn: u64) -> bool {
        let mut m = self.0.lock().unwrap();
        if m.flip_admission == Some(conn) {
            m.flip_calls += 1;
            return m.flip_calls > 1;
        }
        !m.paused && !m.paused_connections.contains(&conn)
    }
    fn on_accept(&mut self, l: usize, peer: SocketAddr, now: Duration) -> Option<u64> {
        let mut m = self.0.lock().unwrap();
        m.next += 1;
        let id = m.next;
        m.live.insert(id);
        m.last_rx.insert(id, now);
        m.accepted.push((id, KINDS[l], peer.port()));
        Some(id)
    }
    fn on_connected(&mut self, conn: u64, _now: Duration) {
        self.0.lock().unwrap().connected.push(conn);
    }
    fn on_dial_failed(&mut self, conn: u64, refused: bool, _now: Duration) {
        let mut m = self.0.lock().unwrap();
        m.live.remove(&conn);
        m.failed.push((conn, refused));
    }
    fn on_closed(&mut self, conn: u64, _now: Duration) {
        let mut m = self.0.lock().unwrap();
        m.live.remove(&conn);
        m.closed.push(conn);
    }
    fn on_bytes(&mut self, conn: u64, data: &[u8], now: Duration) {
        let mut m = self.0.lock().unwrap();
        m.last_rx.insert(conn, now);
        if m.direct {
            m.feed(conn, data);
            return;
        }
        if m.echo {
            m.out
                .entry(conn)
                .or_default()
                .push_back(Bytes::copy_from_slice(data));
        } else {
            m.rx.entry(conn).or_default().extend_from_slice(data);
        }
    }
    fn output_written(&mut self, conn: u64, bytes: usize) {
        self.0.lock().unwrap().written.push((conn, bytes));
    }
    fn poll_io(&mut self) -> Option<IoCmd> {
        self.0.lock().unwrap().io.pop_front()
    }
    fn poll_output_chunks(&mut self, conn: u64) -> Vec<Bytes> {
        let mut m = self.0.lock().unwrap();
        m.notified.remove(&conn);
        m.out
            .get_mut(&conn)
            .map_or_else(Vec::new, |q| q.drain(..).collect())
    }
    fn poll_output_ready(&mut self) -> Option<u64> {
        let mut m = self.0.lock().unwrap();
        let id = m
            .out
            .iter()
            .find(|(id, q)| !q.is_empty() && !m.notified.contains(id))
            .map(|(id, _)| *id)?;
        m.notified.insert(id);
        Some(id)
    }
    fn rx_direct_want(&mut self, conn: u64) -> usize {
        let m = self.0.lock().unwrap();
        m.dst
            .get(&conn)
            .filter(|_| m.direct)
            .map_or(0, |s| if s.in_payload { s.len - s.got } else { 0 })
    }
    fn rx_direct_take(&mut self, conn: u64) -> Option<(msgr2::SegBuf, crc::BlockCrcs)> {
        let mut m = self.0.lock().unwrap();
        let s = m.dst.get_mut(&conn)?;
        let mut b = crc::BlockCrcs::with_len(s.len);
        b.update(&s.cur);
        let out = Some((msgr2::SegBuf::from(std::mem::take(&mut s.cur)), b));
        m.direct_takes += 1;
        out
    }
    fn rx_direct_put(&mut self, conn: u64, v: msgr2::SegBuf, crc: crc::BlockCrcs, _now: Duration) {
        let mut m = self.0.lock().unwrap();
        let Some(s) = m.dst.get_mut(&conn) else {
            return;
        };
        assert_eq!(v.len(), s.len, "buffer returned incomplete");
        s.in_payload = false;
        s.got = 0;
        m.direct_puts += 1;
        m.msgs.push((conn, v.to_vec(), crc.crc(!0)));
    }
    fn on_rx_progress(&mut self, conn: u64, now: Duration) {
        let mut m = self.0.lock().unwrap();
        if m.live.contains(&conn) {
            m.last_rx.insert(conn, now);
            m.progress_calls += 1;
        }
    }
}

/// Core-thread driver for the secure tests: owns the `!Send` msgr2 decoders and delegates everything else to the
/// shared mock. Created inside the core thread.
struct Local {
    sh: Shared,
    decoders: HashMap<u64, msgr2::Decoder>,
}

impl Local {
    fn new(sh: Shared) -> Self {
        Self {
            sh,
            decoders: HashMap::new(),
        }
    }

    fn sync_armed(&self) {
        let armed = self.decoders.values().any(|d| d.secure_want() > 0);
        self.sh.0.lock().unwrap().secure_armed = armed;
    }

    fn feed_secure(&mut self, conn: u64, bytes: &[u8]) {
        let decoder = self.decoders.get_mut(&conn).unwrap();
        decoder.feed(bytes);
        let mut m = self.sh.0.lock().unwrap();
        m.secure_feed_bytes += bytes.len() as u64;
        while let Some(frame) = decoder.poll_owned().unwrap() {
            m.msgs.push((conn, frame.segs[3].to_vec(), 0));
        }
        drop(m);
        self.sync_armed();
    }
}

impl Driver for Local {
    fn keep_half_open(&self) -> bool {
        self.sh.keep_half_open()
    }
    fn on_eof(&mut self, conn: u64, now: Duration) {
        self.sh.on_eof(conn, now);
    }
    fn admission_ready(&self) -> bool {
        self.sh.admission_ready()
    }
    fn input_ready(&self, conn: u64) -> bool {
        self.sh.input_ready(conn)
    }
    fn on_accept(&mut self, l: usize, peer: SocketAddr, now: Duration) -> Option<u64> {
        let id = self.sh.on_accept(l, peer, now)?;
        if self.sh.0.lock().unwrap().secure {
            let mut decoder = msgr2::Decoder::new(msgr2::Revision::V21);
            decoder
                .set_secure(
                    &msgr2::ConnSecret::new(&[7; 64]).unwrap(),
                    msgr2::Role::Server,
                )
                .unwrap();
            self.decoders.insert(id, decoder);
        }
        Some(id)
    }
    fn on_connected(&mut self, conn: u64, now: Duration) {
        self.sh.on_connected(conn, now);
    }
    fn on_dial_failed(&mut self, conn: u64, refused: bool, now: Duration) {
        self.sh.on_dial_failed(conn, refused, now);
    }
    fn on_closed(&mut self, conn: u64, now: Duration) {
        self.decoders.remove(&conn);
        self.sync_armed();
        self.sh.on_closed(conn, now);
    }
    fn on_bytes(&mut self, conn: u64, data: &[u8], now: Duration) {
        if self.decoders.contains_key(&conn) {
            self.sh.0.lock().unwrap().last_rx.insert(conn, now);
            self.feed_secure(conn, data);
        } else {
            self.sh.on_bytes(conn, data, now);
        }
    }
    fn poll_io(&mut self) -> Option<IoCmd> {
        self.sh.poll_io()
    }
    fn poll_output_chunks(&mut self, conn: u64) -> Vec<Bytes> {
        self.sh.poll_output_chunks(conn)
    }
    fn poll_output_ready(&mut self) -> Option<u64> {
        self.sh.poll_output_ready()
    }
    fn rx_direct_want(&mut self, conn: u64) -> usize {
        self.sh.rx_direct_want(conn)
    }
    fn rx_direct_take(&mut self, conn: u64) -> Option<(msgr2::SegBuf, crc::BlockCrcs)> {
        self.sh.rx_direct_take(conn)
    }
    fn rx_direct_put(&mut self, conn: u64, v: msgr2::SegBuf, crc: crc::BlockCrcs, now: Duration) {
        self.sh.rx_direct_put(conn, v, crc, now);
    }
    fn on_rx_progress(&mut self, conn: u64, now: Duration) {
        self.sh.on_rx_progress(conn, now);
    }
    fn rx_secure_want(&mut self, conn: u64) -> usize {
        self.decoders
            .get(&conn)
            .map_or(0, msgr2::Decoder::secure_want)
    }
    fn rx_secure_take(&mut self, conn: u64) -> Option<msgr2::SecureRxBuffer> {
        let loan = self.decoders.get_mut(&conn)?.secure_take()?;
        let mut m = self.sh.0.lock().unwrap();
        m.secure_loan_bytes += loan.remaining() as u64;
        m.secure_takes += 1;
        drop(m);
        self.sync_armed();
        Some(loan)
    }
    fn rx_secure_put(&mut self, conn: u64, buffer: msgr2::SecureRxBuffer, _now: Duration) {
        self.decoders
            .get_mut(&conn)
            .unwrap()
            .secure_put(buffer)
            .unwrap();
        self.sh.0.lock().unwrap().secure_puts += 1;
        self.feed_secure(conn, &[]);
    }
}

struct Srv {
    mock: Shared,
    ports: [u16; 4],
    stop: Arc<AtomicBool>,
    th: Option<JoinHandle<KStats>>,
}

impl Srv {
    fn stop(mut self) -> KStats {
        self.stop.store(true, Ordering::Relaxed);
        self.th.take().unwrap().join().unwrap()
    }
}

/// Four free ports from a block below the ephemeral range, unique within this test process: kernel-picked (port 0)
/// ports were also handed out as client source ports and to other tests running in parallel (bind races, a "dead" port
/// that answered).
fn free_ports() -> [u16; 4] {
    use std::sync::atomic::AtomicU32;
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let seed = std::process::id() * 52;
    loop {
        let base = 20_000 + (seed + NEXT.fetch_add(4, Ordering::Relaxed)) % 12_000;
        let ports = [0, 1, 2, 3].map(|i| (base + i) as u16);
        if ports
            .iter()
            .all(|&p| TcpListener::bind((Ipv4Addr::LOCALHOST, p)).is_ok())
        {
            return ports;
        }
    }
}

fn binds(ports: [u16; 4]) -> Binds {
    Binds(ports.map(|p| vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), p)]))
}

/// Free ports bound for `n` cores; retried with fresh ports when a parallel test took one between probe and bind.
fn bind_free(n: usize, steer: &Steer, backlog: i32) -> ([u16; 4], Vec<[Vec<OwnedFd>; 4]>) {
    for _ in 0..20 {
        let ports = free_ports();
        match bind_all(&binds(ports), n, steer, backlog) {
            Ok(f) => return (ports, f),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(e) => panic!("bind: {e}"),
        }
    }
    panic!("no free ports after 20 tries");
}

fn spawn_core(
    cfg: KCfg,
    fds: [Vec<OwnedFd>; 4],
    mock: Shared,
    stop: Arc<AtomicBool>,
) -> JoinHandle<KStats> {
    spawn_core_idle(cfg, fds, mock, stop, false)
}

/// `spin`: never block in the ring when idle (`Idle::Spin`).
fn spawn_core_idle(
    cfg: KCfg,
    fds: [Vec<OwnedFd>; 4],
    mock: Shared,
    stop: Arc<AtomicBool>,
    spin: bool,
) -> JoinHandle<KStats> {
    std::thread::spawn(move || {
        let mut n = KNet::new(cfg, fds).expect("ring");
        let mut d = Local::new(mock);
        let t0 = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            let now = t0.elapsed();
            let mut work = n.poll(&mut d, now);
            d.sh.0.lock().unwrap().check_idle(now);
            n.pump_io(&mut d, now);
            n.flush_out(&mut d);
            n.submit();
            work |= n.stats.enters == u64::MAX;
            if !work && !spin {
                n.wait(Duration::from_micros(200));
            }
        }
        n.stats
    })
}

fn start(cfg: KCfg, echo: bool) -> Srv {
    let (ports, mut fds) = bind_free(1, &Steer::Hash, 128);
    let mock = Shared::default();
    mock.0.lock().unwrap().echo = echo;
    let stop = Arc::new(AtomicBool::new(false));
    let th = spawn_core(cfg, fds.remove(0), mock.clone(), stop.clone());
    Srv {
        mock,
        ports,
        stop,
        th: Some(th),
    }
}

#[test]
fn admission_pause_retains_bounded_receive_leases_and_resumes_without_loss() {
    let (ports, mut fds) = bind_free(1, &Steer::Hash, 128);
    let mut n = KNet::new(
        KCfg {
            bufs: 8,
            buf_size: 4096,
            direct_min: 0,
            ..KCfg::default()
        },
        fds.remove(0),
    )
    .unwrap();
    let mut d = Shared::default();
    d.0.lock().unwrap().paused = true;
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0])).unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let data = vec![0x5A; 64 << 10];
    client.write_all(&data).unwrap();
    let start = Instant::now();
    while n.held_bytes == 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        n.poll(&mut d, start.elapsed());
        n.submit();
    }
    for _ in 0..100 {
        n.poll(&mut d, start.elapsed());
        n.submit();
        // bounded by the hold storage: spill store + provided ring
        assert!(
            n.slots
                .iter()
                .flatten()
                .map(|c| c.held.len())
                .sum::<usize>()
                <= 16
        );
    }
    assert!(
        d.0.lock().unwrap().rx.is_empty(),
        "no application bytes while throttled"
    );
    d.0.lock().unwrap().paused = false;
    loop {
        assert!(start.elapsed() < Duration::from_secs(10));
        n.poll(&mut d, start.elapsed());
        n.submit();
        let m = d.0.lock().unwrap();
        if m.rx.values().map(Vec::len).sum::<usize>() == data.len() {
            assert_eq!(m.rx.values().next().unwrap(), &data);
            break;
        }
    }
    assert!(n.held_bytes == 0);
    assert!(n.paused_rx.is_empty());
}

#[test]
fn paused_input_keeps_draining_the_socket_into_hold_storage() {
    let (ports, mut fds) = bind_free(1, &Steer::Hash, 128);
    let mut n = KNet::new(
        KCfg {
            bufs: 16,
            buf_size: 4096,
            direct_min: 0,
            ..KCfg::default()
        },
        fds.remove(0),
    )
    .unwrap();
    let mut d = Shared::default();
    d.0.lock().unwrap().paused = true;
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0])).unwrap();
    // below the hold capacity (16 spill + 8 provided buffers of 4 KiB): every byte leaves the kernel queue
    let data = pattern(64 << 10, 23);
    client.write_all(&data).unwrap();
    let start = Instant::now();
    while n.held_bytes < data.len() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "socket not drained while paused"
        );
        n.poll(&mut d, start.elapsed());
        n.submit();
    }
    assert_eq!(n.stats.rx_pauses, 0, "no pause while hold storage lasts");
    assert_eq!(n.stats.rx_hold_full, 0);
    assert!(
        d.0.lock().unwrap().rx.is_empty(),
        "no application bytes while throttled"
    );
    d.0.lock().unwrap().paused = false;
    loop {
        assert!(start.elapsed() < Duration::from_secs(10));
        n.poll(&mut d, start.elapsed());
        n.submit();
        if d.0.lock().unwrap().rx.values().map(Vec::len).sum::<usize>() == data.len() {
            break;
        }
    }
    assert_eq!(d.0.lock().unwrap().rx.values().next().unwrap(), &data);
    assert!(n.held_bytes == 0);
}

#[test]
fn independent_receive_admission_keeps_held_bytes_in_connection_order() {
    let (ports, mut fds) = bind_free(1, &Steer::Hash, 128);
    let cfg = KCfg {
        buf_size: 4096,
        bufs: 16,
        ..Default::default()
    };
    let mut net = KNet::new(cfg, fds.remove(0)).unwrap();
    let mut mock = Shared::default();
    let mut a = client(ports[0]);
    let mut b = client(ports[0]);
    let t = Instant::now();
    let deadline = t + Duration::from_secs(5);
    while mock.0.lock().unwrap().accepted.len() < 2 {
        assert!(Instant::now() < deadline, "accept timed out");
        net.poll(&mut mock, t.elapsed());
        net.pump_io(&mut mock, t.elapsed());
        net.submit();
        std::thread::yield_now();
    }
    let a_port = a.local_addr().unwrap().port();
    let (a_id, b_id) = {
        let m = mock.0.lock().unwrap();
        (
            m.accepted.iter().find(|x| x.2 == a_port).unwrap().0,
            m.accepted.iter().find(|x| x.2 != a_port).unwrap().0,
        )
    };
    mock.0.lock().unwrap().paused_connections.insert(a_id);
    let data = pattern(16 * 4096, 19);
    a.write_all(&data).unwrap();
    // Let the real multishot receive publish multiple provided-buffer completions before reaping them.
    while net.ring.completion().len() < 16 {
        assert!(Instant::now() < deadline, "receive completions timed out");
        net.kick();
        std::thread::yield_now();
    }
    net.poll(&mut mock, t.elapsed());
    assert!(
        net.slots
            .iter()
            .flatten()
            .map(|c| c.held.len())
            .sum::<usize>()
            >= 2
    );
    b.write_all(b"unrelated connection").unwrap();
    while mock
        .0
        .lock()
        .unwrap()
        .rx
        .get(&b_id)
        .is_none_or(|v| v.len() < 20)
    {
        assert!(Instant::now() < deadline, "unrelated input stalled");
        net.poll(&mut mock, t.elapsed());
        net.pump_io(&mut mock, t.elapsed());
        net.submit();
        std::thread::yield_now();
    }
    assert!(!mock.0.lock().unwrap().rx.contains_key(&a_id));
    // A becomes ready after its first head was skipped: later leases must wait for the next pass too.
    mock.0.lock().unwrap().flip_admission = Some(a_id);
    net.resume_rx(&mut mock, t.elapsed());
    assert!(!mock.0.lock().unwrap().rx.contains_key(&a_id));
    net.resume_rx(&mut mock, t.elapsed());
    while mock
        .0
        .lock()
        .unwrap()
        .rx
        .get(&a_id)
        .is_none_or(|v| v.len() < data.len())
    {
        assert!(Instant::now() < deadline, "resumed input timed out");
        net.poll(&mut mock, t.elapsed());
        net.pump_io(&mut mock, t.elapsed());
        net.submit();
        std::thread::yield_now();
    }
    assert_eq!(mock.0.lock().unwrap().rx[&a_id], data);
}

/// msgr2 redials a lossless session under the same connection id. Bytes the old socket received into hold storage
/// (input paused) belong to the old stream: after the old socket is gone they must never reach the new socket's
/// decoder (lab case 23: the old tail desynchronised the new stream, BadPreambleCrc / BadLateStatus, and the new
/// slot's hold count wrapped, leaving a paused receive never re-armed: a cluster link that stops reading).
#[test]
fn held_bytes_of_a_closed_socket_never_reach_a_redial_with_the_same_id() {
    use std::os::fd::IntoRawFd;
    let (ports, mut fds) = bind_free(1, &Steer::Hash, 128);
    let mut n = KNet::new(
        KCfg {
            bufs: 16,
            buf_size: 4096,
            direct_min: 0,
            ..KCfg::default()
        },
        fds.remove(0),
    )
    .unwrap();
    let mut d = Shared::default();
    d.0.lock().unwrap().paused = true;
    let mut old = TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0])).unwrap();
    let stale = pattern(16 << 10, 41);
    old.write_all(&stale).unwrap();
    let start = Instant::now();
    while n.held_bytes < stale.len() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "old bytes not held"
        );
        n.poll(&mut d, start.elapsed());
        n.submit();
    }
    let id = d.0.lock().unwrap().accepted[0].0;
    // the OSD closes the faulted link, then the session redials with the same connection id
    d.0.lock().unwrap().io.push_back(IoCmd::Close { conn: id });
    n.pump_io(&mut d, start.elapsed());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut new = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let slot = n.add_conn(server.into_raw_fd(), id, false);
    n.arm_recv(slot);
    let fresh = pattern(8 << 10, 77);
    new.write_all(&fresh).unwrap();
    d.0.lock().unwrap().paused = false;
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "new stream stalled"
        );
        n.poll(&mut d, start.elapsed());
        n.submit();
        if d.0
            .lock()
            .unwrap()
            .rx
            .get(&id)
            .is_some_and(|v| v.len() >= fresh.len())
        {
            break;
        }
    }
    assert_eq!(
        d.0.lock().unwrap().rx[&id],
        fresh,
        "only the new socket's bytes"
    );
    assert!(n.slots[slot as usize].as_ref().unwrap().held.is_empty());
    assert_eq!(n.held_bytes, 0);
}

/// Hold storage is owned per socket: one resume pass delivers every connection's held bytes while the OSD takes its
/// input, a connection with a large backlog never keeps another one's held bytes back.
#[test]
fn one_resume_pass_delivers_the_held_bytes_of_every_admitted_connection() {
    let (ports, mut fds) = bind_free(1, &Steer::Hash, 128);
    let mut n = KNet::new(
        KCfg {
            bufs: 16,
            buf_size: 4096,
            direct_min: 0,
            ..KCfg::default()
        },
        fds.remove(0),
    )
    .unwrap();
    let mut d = Shared::default();
    d.0.lock().unwrap().paused = true;
    let mut a = client(ports[0]);
    let mut b = client(ports[0]);
    let (big, small) = (pattern(48 << 10, 5), pattern(4 << 10, 6));
    a.write_all(&big).unwrap();
    b.write_all(&small).unwrap();
    let start = Instant::now();
    while n.held_bytes < big.len() + small.len() {
        assert!(start.elapsed() < Duration::from_secs(5), "bytes not held");
        n.poll(&mut d, start.elapsed());
        n.pump_io(&mut d, start.elapsed());
        n.submit();
    }
    assert_eq!(
        n.slots
            .iter()
            .flatten()
            .filter(|c| !c.held.is_empty())
            .count(),
        2
    );
    d.0.lock().unwrap().paused = false;
    n.resume_rx(&mut d, start.elapsed());
    assert_eq!(n.held_bytes, 0);
    let m = d.0.lock().unwrap();
    let mut got: Vec<&Vec<u8>> = m.rx.values().collect();
    got.sort_by_key(|v| v.len());
    assert_eq!(got, [&small, &big]);
}

#[test]
fn send_completion_rearms_output_whose_notification_was_consumed() {
    let (mut n, slot, _client) = idle_conn(77);
    let c = n.slots[slot as usize].as_mut().unwrap();
    c.sending = true;
    c.inflight += 1;
    c.st.runs.push(Bytes::from_static(b"first"));
    let mut d = Shared::default();
    d.0.lock()
        .unwrap()
        .out
        .entry(77)
        .or_default()
        .push_back(Bytes::from_static(b"second"));
    n.flush_out(&mut d); // notification is consumed, but the first send is still in flight
    assert_eq!(d.poll_output_ready(), None);
    n.on_send(&mut d, slot, 0, 5, 0, Duration::ZERO);
    let c = n.slots[slot as usize].as_ref().unwrap();
    assert!(
        c.sending,
        "completion must submit the pending second output"
    );
    assert_eq!(c.st.runs, [Bytes::from_static(b"second")]);
}

/// A SENDMSG that completes with 0 bytes for a non-empty batch faults the connection (it used to count as progress and
/// resubmit the same batch forever).
#[test]
fn zero_byte_send_completion_faults_the_connection() {
    let (mut n, slot, _client) = idle_conn(78);
    let c = n.slots[slot as usize].as_mut().unwrap();
    c.sending = true;
    c.inflight += 1;
    c.st.runs.push(Bytes::from_static(b"stuck"));
    let mut d = Shared::default();
    n.on_send(&mut d, slot, 0, 0, 0, Duration::ZERO);
    // faulted: the driver was told the connection died and the slot was torn down (no resubmit of the batch)
    assert!(
        n.slots[slot as usize]
            .as_ref()
            .is_none_or(|c| !c.sending && c.reported),
        "not resubmitted"
    );
}

fn idle_conn(id: u64) -> (KNet, u32, TcpStream) {
    use std::os::fd::IntoRawFd;
    let (_, mut fds) = bind_free(1, &Steer::Hash, 128);
    let mut n = KNet::new(KCfg::default(), fds.remove(0)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let slot = n.add_conn(server.into_raw_fd(), id, false);
    (n, slot, client)
}

/// NT-unsafe-06: dropping a `KNet` must retire its in-flight requests before their memory (provided buffers, send
/// state and payload) is freed: the ring-fd close tears down asynchronously, so a request still parked in the kernel
/// could later write into freed memory. A provided-buffer receive (the peer sends nothing) and a `MSG_WAITALL` send of
/// 64 MiB (the peer never reads) are parked; after the drop-time drain [`KNet::retire`] neither may still be found by a
/// cancel on the ring. Before: the drop only closed the sockets (each request keeps its file) and both were found.
#[test]
fn drop_retires_in_flight_requests_before_freeing_their_memory() {
    let (mut n, slot, _peer) = idle_conn(93);
    n.arm_recv(slot);
    let c = n.slots[slot as usize].as_mut().unwrap();
    c.sending = true;
    c.st.runs.push(Bytes::from(vec![0x5a_u8; 64 << 20]));
    n.resubmit_send(slot);
    n.ring.submit().unwrap();
    assert_eq!(n.slots[slot as usize].as_ref().unwrap().inflight, 2);
    n.retire();
    const MARK: u64 = u64::MAX;
    for u in [ud(K_RECV, slot, 0), ud(K_SEND, slot, 0)] {
        n.push(opcode::AsyncCancel::new(u).build().user_data(MARK));
        let t0 = Instant::now();
        let res = loop {
            n.ring.submit_and_wait(1).unwrap();
            let hit = n.ring.completion().find(|e| e.user_data() == MARK);
            if let Some(e) = hit {
                break e.result();
            }
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "WARNING TIMEOUT cancel probe exceeded 5s (request {u:#x})"
            );
        };
        assert_eq!(
            res,
            -libc::ENOENT,
            "request {u:#x} is still in flight after the drop-time drain (its memory would be freed under it)"
        );
    }
}

/// The accept retry is indexed by the flat listener list (kind x address family), not by the four kinds: with two
/// address families per kind (dual stack, 8 listeners) a shortage that hit a listener past the first four must be
/// retried too (before: only `0..4` were re-armed, so the heartbeat listeners never accepted again: a silent stall).
#[test]
fn every_listener_rearms_after_an_accept_resource_shortage() {
    let ports = free_ports();
    let binds = Binds(ports.map(|p| {
        vec![
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), p),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), p),
        ]
    }));
    let mut fds = match bind_all(&binds, 1, &Steer::Hash, 128) {
        Ok(f) => f,
        Err(e) => panic!("dual-stack bind {ports:?}: {e}"),
    };
    let mut n = KNet::new(KCfg::default(), fds.remove(0)).unwrap();
    assert_eq!(n.lst.len(), 8, "two families for each of the four kinds");
    assert!(
        n.ring.submission().is_empty(),
        "the accepts of KNet::new are submitted"
    );
    n.accepts.iter_mut().for_each(|a| a.retry = true);
    n.tick(Duration::from_secs(1));
    assert_eq!(
        n.ring.submission().len(),
        8,
        "one multishot accept queued per listener"
    );
}

/// A paused socket is queued for resume by (slot, connection id); the slot can be freed and taken by a new socket
/// under the same id (msgr2 redials a lossless session under it). Only a paused socket resumes: the new socket keeps
/// its single receive (before: a second receive was armed on it: two receivers splitting the stream, or one direct
/// buffer written by two requests).
#[test]
fn a_dead_paused_slot_does_not_arm_a_redial_under_the_same_id() {
    use std::os::fd::IntoRawFd;
    let (mut n, slot, _client) = idle_conn(90);
    let id = 90;
    let now = Duration::from_secs(1);
    // input not taken: the receive is paused and queued (as `on_recv` does when hold storage is used up)
    let c = n.slots[slot as usize].as_mut().unwrap();
    assert_eq!(c.inflight, 0, "no receive in flight");
    c.pause(&mut n.stats, now);
    n.paused_rx.push_back((slot, id));
    // the socket is torn down and its slot freed before the next resume pass
    let mut d = Shared::default();
    n.conn_dead(&mut d, slot, now);
    assert!(
        n.slots[slot as usize].is_none(),
        "torn down socket released its slot"
    );
    // the session redials under the same connection id and takes the freed slot
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _new = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    assert_eq!(n.add_conn(server.into_raw_fd(), id, false), slot);
    n.arm_recv(slot);
    assert_eq!(n.slots[slot as usize].as_ref().unwrap().inflight, 1);
    n.resume_rx(&mut d, now);
    assert_eq!(
        n.slots[slot as usize].as_ref().unwrap().inflight,
        1,
        "the stale resume entry must not arm a second receive"
    );
    assert!(n.paused_rx.is_empty(), "the stale entry is dropped");
}

/// A ring that cannot take an entry and cannot be submitted to (closed fd) must give up loudly instead of spinning a
/// core forever. The zcrx ring pushes through the same bound as the knet ring.
#[test]
#[should_panic(expected = "io_uring submission queue stalled")]
fn a_broken_ring_reports_a_stalled_submission_queue() {
    let ring = IoUring::new(1).unwrap();
    let fd = ring.as_raw_fd();
    // the ring stays alive (leaked) so its fd is never closed a second time (and possibly reused) by Drop
    let mut ring = std::mem::ManuallyDrop::new(ring);
    // SAFETY: our own ring fd, and `ring` is never submitted to again after the panic.
    unsafe { libc::close(fd) };
    let e = opcode::Nop::new().build().user_data(0);
    // SAFETY: a nop carries no buffer.
    unsafe { ring.submission().push(&e) }.unwrap();
    push_sqe_bounded(&mut ring, &mut 0, e, Duration::from_millis(10));
}

/// An operator `sockbuf` the kernel refuses is reported (before: both `setsockopt` results were dropped, the setting
/// silently unset).
#[test]
fn a_refused_socket_buffer_size_is_an_error() {
    let e = listen::set_sockbuf(-1, 1 << 20).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::EBADF), "{e}");
}

/// A zero-copy send keeps its runs alive until the notification; the vector comes from hold storage a notification
/// gave back, so a completion does not allocate (before: a fresh `Vec<Bytes>` clone per completion).
#[test]
fn a_zero_copy_send_reuses_its_hold_vector() {
    // CQE flags (IORING_CQE_F_MORE / IORING_CQE_F_NOTIF): the send completes, its notification follows
    const MORE: u32 = 2;
    const NOTIF: u32 = 8;
    let (mut n, slot, _client) = idle_conn(88);
    let mut d = Shared::default();
    let now = Duration::from_secs(1);
    // one zero-copy send of two runs completes, the notification follows: both runs stay held
    let c = n.slots[slot as usize].as_mut().unwrap();
    c.sending = true;
    c.inflight += 1;
    c.st.zc = true;
    c.st.runs = vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")];
    n.on_send(&mut d, slot, 1, 11, MORE, now);
    let held = &n.slots[slot as usize].as_ref().unwrap().zc_hold;
    assert_eq!(held.len(), 1, "the batch is held until the notification");
    assert_eq!(held[0].1.len(), 2, "both runs are held");
    let first = held[0].1.as_ptr();
    assert_eq!(n.slots[slot as usize].as_ref().unwrap().inflight, 1);
    // the notification: the vector goes back to the connection
    n.on_send(&mut d, slot, 1, 0, NOTIF, now);
    let c = n.slots[slot as usize].as_ref().unwrap();
    assert!(c.zc_hold.is_empty());
    assert_eq!(c.inflight, 0);
    assert_eq!(c.zc_spare.len(), 1, "the vector went back for reuse");
    // the next batch takes the same buffer: no allocation per completion
    let c = n.slots[slot as usize].as_mut().unwrap();
    c.sending = true;
    c.inflight += 1;
    c.st.runs = vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")];
    n.on_send(&mut d, slot, 2, 11, MORE, now);
    assert_eq!(
        n.slots[slot as usize].as_ref().unwrap().zc_hold[0]
            .1
            .as_ptr(),
        first,
        "the hold vector is reused"
    );
    // the modelled send's notification settles the in-flight count (no real request: the drop drain must not wait)
    n.on_send(&mut d, slot, 2, 0, NOTIF, now);
    assert_eq!(n.slots[slot as usize].as_ref().unwrap().inflight, 0);
}

/// Socket acceptance precedes zero-copy retirement: a graceful close must let the peer receive the queued bytes.
#[test]
fn zero_copy_close_keeps_queued_output_until_notification() {
    const NOTIF: u32 = 8;
    let (mut n, slot, mut client) = idle_conn(89);
    let now = Duration::from_secs(1);
    let c = n.slots[slot as usize].as_mut().unwrap();
    let payload = Bytes::from_static(b"accepted before FIN");
    // Model a completed SENDMSG_ZC whose notification is still pending; send the bytes on the real socket so the
    // test also detects an accidental abort on the graceful path.
    // SAFETY: live socket and initialized Bytes allocation, retained through the synchronous send.
    assert_eq!(
        unsafe {
            libc::send(
                c.fd,
                payload.as_ptr().cast(),
                payload.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        payload.len() as isize
    );
    c.inflight = 1;
    c.zc_hold.push((1, vec![payload.clone()]));
    n.close(&mut Shared::default(), 89, now);
    assert!(!n.slots[slot as usize].as_ref().unwrap().dying);
    assert_eq!(n.next_due(), Some(now + n.cfg.close_linger));
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut received = Vec::new();
    client.read_to_end(&mut received).unwrap_or_else(|e| {
        if matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            panic!("WARNING TIMEOUT graceful close output exceeded 3s (zero-copy close test): {e}");
        }
        panic!("graceful close output failed: {e}");
    });
    assert_eq!(received, payload);
    n.on_send(&mut Shared::default(), slot, 1, 0, NOTIF, now);
    assert!(n.slots[slot as usize].is_none());
    assert_eq!(n.free.iter().filter(|&&s| s == slot).count(), 1);
}

/// A peer withholding ACK/window progress cannot retain a terminal socket forever. Abort the TCP queue at the
/// existing linger deadline, but retain every zero-copy owner and the fd until the final notification arrives.
#[test]
fn zero_copy_close_deadline_aborts_without_releasing_unnotified_payload() {
    use std::sync::atomic::AtomicUsize;
    struct Payload(Arc<AtomicUsize>);
    impl AsRef<[u8]> for Payload {
        fn as_ref(&self) -> &[u8] {
            b"retained until notification"
        }
    }
    impl Drop for Payload {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    const NOTIF: u32 = 8;
    let (mut n, slot, _client) = idle_conn(90);
    let dropped = Arc::new(AtomicUsize::new(0));
    let now = Duration::from_secs(1);
    let c = n.slots[slot as usize].as_mut().unwrap();
    let fd = c.fd;
    c.inflight = 1;
    c.zc_hold
        .push((1, vec![Bytes::from_owner(Payload(dropped.clone()))]));
    n.close(&mut Shared::default(), 90, now);
    assert!(!n.slots[slot as usize].as_ref().unwrap().dying);
    n.tick(now + n.cfg.close_linger);
    assert!(n.slots[slot as usize].as_ref().unwrap().dying);
    assert_eq!(
        dropped.load(Ordering::Relaxed),
        0,
        "no early payload release"
    );
    // shutdown alone leaves getpeername valid. AF_UNSPEC disconnects TCP while preserving the descriptor for CQEs.
    // SAFETY: sockaddr_storage accepts all-zero initialization.
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: live socket and valid writable address/length storage.
    assert_eq!(
        unsafe { libc::getpeername(fd, (&raw mut address).cast(), &raw mut length) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOTCONN)
    );
    // SAFETY: F_GETFD reads flags from the owned descriptor without a variadic argument.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, libc::FD_CLOEXEC);
    n.on_send(&mut Shared::default(), slot, 1, 0, NOTIF, now);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    assert!(n.slots[slot as usize].is_none());
    assert_eq!(n.free.iter().filter(|&&s| s == slot).count(), 1);
}

/// NT-leaks-01 on the real kernel path: SENDMSG_ZC bytes queued behind the closed window of a peer that stops reading
/// (but still answers window probes) are never acknowledged, so their notifications never come. The close linger cut
/// must abort the TCP queue: the kernel then posts every notification and the slot, fd and payload owners are released.
/// Before: the cut only shut the socket down, the queued bytes kept waiting for the peer and the slot stayed forever.
#[test]
fn zero_copy_close_cut_frees_the_slot_of_a_peer_that_stopped_reading() {
    use std::os::fd::IntoRawFd;
    let (_, mut fds) = bind_free(1, &Steer::Hash, 128);
    let linger = Duration::from_millis(300);
    let mut n = KNet::new(
        KCfg {
            zc_min: 1,
            close_linger: linger,
            ..KCfg::default()
        },
        fds.remove(0),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap(); // never reads
    let (server, _) = listener.accept().unwrap();
    // adopted without the accept path's loopback probe (`local_peer` false): the sends really go zero copy
    let id = 92;
    let slot = n.add_conn(server.into_raw_fd(), id, false);
    let mut d = Local::new(Shared::default());
    d.sh.0
        .lock()
        .unwrap()
        .out
        .entry(id)
        .or_default()
        .push_back(Bytes::from(vec![0u8; 64 << 20]));
    let t0 = Instant::now();
    let step = |n: &mut KNet, d: &mut Local, now: Duration| {
        n.poll(d, now);
        n.pump_io(d, now);
        n.flush_out(d);
        n.submit();
    };
    // the peer's window closes with zero-copy bytes accepted but unacknowledged
    while n.slots[slot as usize]
        .as_ref()
        .is_some_and(|c| c.zc_hold.is_empty())
    {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "WARNING TIMEOUT zero-copy hold exceeded 5s (test)"
        );
        step(&mut n, &mut d, t0.elapsed());
    }
    assert!(n.stats.zc_sends > 0, "the sends went zero copy");
    d.sh.0
        .lock()
        .unwrap()
        .io
        .push_back(IoCmd::Close { conn: id });
    let limit = t0.elapsed() + linger + Duration::from_secs(3);
    while n.slots[slot as usize].is_some() {
        let now = t0.elapsed();
        assert!(
            now < limit,
            "WARNING TIMEOUT zero-copy close retirement exceeded {:.3}s (test, linger {linger:?}): slot, fd and payload \
             still held",
            limit.as_secs_f64()
        );
        step(&mut n, &mut d, now);
        n.wait(Duration::from_millis(10));
    }
    assert_eq!(n.free.iter().filter(|&&s| s == slot).count(), 1);
}

#[test]
fn finalized_boxed_listing_survives_zero_copy_notification_hold() {
    const MORE: u32 = 2;
    const NOTIF: u32 = 8;
    let (mut n, slot, _client) = idle_conn(89);
    let mut d = Shared::default();
    let now = Duration::from_secs(1);
    let mut builder = Vec::with_capacity(512 << 10);
    builder.extend_from_slice(&1u32.to_le_bytes());
    builder.extend_from_slice(&1u32.to_le_bytes());
    builder.push(b'k');
    builder.extend_from_slice(&(256u32 << 10).to_le_bytes());
    builder.resize(builder.len() + (256 << 10), 0x6b);
    builder.push(0);
    let expected = builder.clone();
    let reply = Bytes::from(builder.into_boxed_slice());
    let pointer = reply.as_ptr();
    let memo = reply.clone();
    let c = n.slots[slot as usize].as_mut().unwrap();
    c.sending = true;
    c.inflight += 1;
    c.st.zc = true;
    c.st.runs = vec![reply];
    drop(memo); // No Store/memo owner remains before the send completion.
    n.on_send(&mut d, slot, 1, expected.len() as i32, MORE, now);
    let held = &n.slots[slot as usize].as_ref().unwrap().zc_hold;
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].1[0].as_ptr(), pointer);
    assert_eq!(held[0].1[0].as_ref(), expected);
    n.on_send(&mut d, slot, 1, 0, NOTIF, now);
    assert!(n.slots[slot as usize].as_ref().unwrap().zc_hold.is_empty());
}

/// adr 0074 am. 4: output queued by a producer the loop does not count as "driven" (a deferred store txn settled
/// inside `poll_store`) must leave in the same iteration. The old loop flushed only when driven: the notification sat
/// in the queue while the core parked, until an unrelated event or the 10 ms output sweep timer.
#[test]
fn undriven_iteration_still_flushes_queued_output() {
    let (mut n, slot, _client) = idle_conn(77);
    let mut d = Shared::default();
    d.0.lock()
        .unwrap()
        .out
        .entry(77)
        .or_default()
        .push_back(Bytes::from_static(b"late reply"));
    d.0.lock().unwrap().io.push_back(IoCmd::Close { conn: 77 });
    assert!(n.output_pass(&mut d, Duration::ZERO, false));
    let c = n.slots[slot as usize].as_ref().unwrap();
    assert!(
        c.sending,
        "queued output must be on the wire before the core parks"
    );
    assert_eq!(c.st.runs, [Bytes::from_static(b"late reply")]);
    assert_eq!(
        d.0.lock().unwrap().io.len(),
        1,
        "socket commands wait for a driven pass"
    );
    assert!(
        !n.output_pass(&mut d, Duration::ZERO, false),
        "queue drained"
    );
}

/// adr 0074 am. 4: a notification consumed while a send is in flight stays owed by the transport across any number
/// of partial sends (more runs than one `sendmsg` takes); no sweep re-arms it.
#[test]
fn consumed_notification_stays_owed_across_partial_sends() {
    let (mut n, slot, _client) = idle_conn(77);
    let c = n.slots[slot as usize].as_mut().unwrap();
    c.sending = true;
    c.inflight += 1;
    c.st.runs.push(Bytes::from_static(b"first"));
    c.out
        .extend((0..2 * MAX_IOV + 3).map(|_| Bytes::from_static(b"x")));
    let mut d = Shared::default();
    d.0.lock()
        .unwrap()
        .out
        .entry(77)
        .or_default()
        .push_back(Bytes::from_static(b"late"));
    assert!(n.flush_out(&mut d)); // consumed while the first send is in flight
    assert_eq!(d.poll_output_ready(), None);
    let mut sent = Vec::new();
    while let Some(c) = n.slots[slot as usize].as_ref().filter(|c| c.sending) {
        assert!(sent.len() <= 2 * MAX_IOV + 5, "send loop does not end");
        let len: usize = c.st.runs.iter().map(Bytes::len).sum();
        sent.extend(c.st.runs.iter().cloned());
        n.on_send(&mut d, slot, 0, len as i32, 0, Duration::ZERO);
    }
    assert_eq!(sent.len(), 2 * MAX_IOV + 5);
    assert_eq!(sent.last(), Some(&Bytes::from_static(b"late")));
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(20);
    while !f() {
        assert!(Instant::now() < end, "timeout: {what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| {
            (i as u8)
                .wrapping_mul(31)
                .wrapping_add(seed)
                .wrapping_add((i >> 8) as u8)
        })
        .collect()
}

fn client(port: u16) -> TcpStream {
    let s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s
}

/// Write `data` from a thread (so a full echo path cannot deadlock the test) and read the same amount back.
fn echo_roundtrip(port: u16, data: Vec<u8>) {
    let c = client(port);
    let mut w = c.try_clone().unwrap();
    let d2 = data.clone();
    let t = std::thread::spawn(move || w.write_all(&d2).unwrap());
    let mut got = vec![0u8; data.len()];
    (&c).read_exact(&mut got).unwrap();
    t.join().unwrap();
    assert!(got == data, "echo mismatch ({} bytes)", data.len());
}

#[test]
fn echo_sizes_and_backpressure() {
    let s = start(KCfg::default(), true);
    for (i, n) in [1usize, 100, 4096, 65537, 3 << 20, 24 << 20]
        .into_iter()
        .enumerate()
    {
        echo_roundtrip(s.ports[0], pattern(n, i as u8));
    }
    let st = s.stop();
    assert!(st.accepted >= 6 && st.rx_bytes >= 27 << 20);
}

#[test]
fn sends_to_a_peer_on_this_host_never_go_zero_copy() {
    let cfg = KCfg {
        zc_min: 1,
        ..KCfg::default()
    };
    let s = start(cfg, true);
    for (i, n) in [1usize, 70_000, 5 << 20].into_iter().enumerate() {
        echo_roundtrip(s.ports[1], pattern(n, 7 + i as u8));
    }
    let st = s.stop();
    // zero copy is on for every batch size (zc_min 1), yet a loopback peer gets plain sends only: the kernel would copy
    // anyway, and looped zero-copy skbs skew the receiver's window estimate (rcvbuf overrun, see `submit_send`)
    assert_eq!(st.zc_sends, 0);
}

#[test]
fn listeners_map_to_osd_kinds() {
    let s = start(KCfg::default(), false);
    let _c: Vec<TcpStream> = (0..4).map(|i| client(s.ports[i])).collect();
    wait_until("4 accepts", || s.mock.0.lock().unwrap().accepted.len() == 4);
    let mut kinds: Vec<(Listener, u16)> = s
        .mock
        .0
        .lock()
        .unwrap()
        .accepted
        .iter()
        .map(|a| (a.1, a.2))
        .collect();
    kinds.sort_by_key(|k| k.1);
    let mut seen: Vec<Listener> = Vec::new();
    for (l, _) in &kinds {
        seen.push(*l);
    }
    for k in KINDS {
        assert!(seen.contains(&k), "{k:?} missing");
    }
    s.stop();
}

#[test]
fn many_concurrent_connections() {
    many_concurrent_connections_with(KCfg::default());
}

/// Classic provided buffers (adr 0053 am. 9: fallback where the ring registration fails) carry the same traffic.
#[test]
fn many_concurrent_connections_classic_buffers() {
    many_concurrent_connections_with(KCfg {
        force_classic: true,
        ..KCfg::default()
    });
}

fn many_concurrent_connections_with(cfg: KCfg) {
    let s = start(cfg, true);
    let port = s.ports[0];
    let th: Vec<_> = (0..64)
        .map(|i| {
            std::thread::spawn(move || echo_roundtrip(port, pattern(100_000 + i * 997, i as u8)))
        })
        .collect();
    for t in th {
        t.join().unwrap();
    }
    s.stop();
}

#[test]
fn starved_buffer_pool_loses_nothing() {
    starved_buffer_pool_loses_nothing_with(false);
}

#[test]
fn starved_classic_buffer_pool_loses_nothing() {
    starved_buffer_pool_loses_nothing_with(true);
}

fn starved_buffer_pool_loses_nothing_with(force_classic: bool) {
    let cfg = KCfg {
        bufs: 2,
        buf_size: 1024,
        force_classic,
        ..KCfg::default()
    };
    let s = start(cfg, false);
    let port = s.ports[0];
    let total = 200_000usize;
    let th: Vec<_> = (0..16u8)
        .map(|i| {
            std::thread::spawn(move || {
                let mut c = client(port);
                c.write_all(&pattern(total, i)).unwrap();
                c
            })
        })
        .collect();
    let keep: Vec<TcpStream> = th.into_iter().map(|t| t.join().unwrap()).collect();
    wait_until("all bytes", || {
        let m = s.mock.0.lock().unwrap();
        m.rx.len() == 16 && m.rx.values().all(|v| v.len() == total)
    });
    // per-connection stream integrity: every received stream is one of the sent patterns
    {
        let m = s.mock.0.lock().unwrap();
        let sent: Vec<Vec<u8>> = (0..16u8).map(|i| pattern(total, i)).collect();
        for v in m.rx.values() {
            assert!(sent.contains(v), "corrupted stream");
        }
    }
    drop(keep);
    let st = s.stop();
    assert!(st.nobufs > 0, "the pool should have run dry at least once");
    assert_eq!(st.provide_errs, 0);
}

/// A completion burst larger than the CQ overflows into the kernel's backlog; a spinning core with nothing to submit
/// must still flush it (regression: `kick` entered the kernel only for queued SQEs / task work, the backlog stayed
/// hidden and the connections stalled for good).
#[test]
fn cq_overflow_does_not_stall_a_spinning_core() {
    let cfg = KCfg {
        entries: 2, // CQ of 8 entries
        buf_size: 4096,
        ..KCfg::default()
    };
    let (ports, mut fds) = bind_free(1, &Steer::Hash, 128);
    let mock = Shared::default();
    let stop = Arc::new(AtomicBool::new(false));
    let th = spawn_core_idle(cfg, fds.remove(0), mock.clone(), stop.clone(), true);
    let total = 256 << 10;
    let keep: Vec<TcpStream> = (0..32u8)
        .map(|i| {
            std::thread::spawn(move || {
                let mut c = client(ports[0]);
                c.write_all(&pattern(total, i)).unwrap();
                c
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect();
    wait_until("all bytes", || {
        let m = mock.0.lock().unwrap();
        m.rx.len() == 32 && m.rx.values().all(|v| v.len() == total)
    });
    drop(keep);
    stop.store(true, Ordering::Relaxed);
    th.join().unwrap();
}

#[test]
fn peer_close_is_reported_once() {
    let s = start(KCfg::default(), false);
    let c = client(s.ports[0]);
    wait_until("accept", || s.mock.0.lock().unwrap().accepted.len() == 1);
    drop(c);
    wait_until("closed", || s.mock.0.lock().unwrap().closed.len() == 1);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(s.mock.0.lock().unwrap().closed.len(), 1);
    s.stop();
}

#[test]
fn osd_close_is_graceful_after_queued_output() {
    let s = start(KCfg::default(), false);
    let mut c = client(s.ports[0]);
    wait_until("accept", || s.mock.0.lock().unwrap().accepted.len() == 1);
    let big = pattern(2 << 20, 3);
    {
        let mut m = s.mock.0.lock().unwrap();
        let id = m.accepted[0].0;
        m.out
            .entry(id)
            .or_default()
            .push_back(Bytes::from(big.clone()));
        m.io.push_back(IoCmd::Close { conn: id });
    }
    let mut got = Vec::new();
    c.read_to_end(&mut got).unwrap(); // data first, then EOF
    assert!(got == big);
    assert!(
        s.mock.0.lock().unwrap().closed.is_empty(),
        "own close is not reported back"
    );
    s.stop();
}

/// A graceful close whose output cannot drain registers its linger cut as a deadline (`next_due`, doc/perf/
/// sleep-register-20261101.md row 10): the idle loop sleeps until it, instead of a 50 ms poll tick finding it. The cut
/// runs at the deadline and leaves nothing timed behind; before the close nothing is due.
#[test]
fn a_lingering_close_registers_its_cut_as_a_deadline() {
    let (ports, mut fds) = bind_free(1, &Steer::Hash, 128);
    let linger = Duration::from_millis(300);
    let mut n = KNet::new(
        KCfg {
            close_linger: linger,
            ..KCfg::default()
        },
        fds.remove(0),
    )
    .unwrap();
    let mut d = Local::new(Shared::default());
    let _client = TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0])).unwrap(); // never reads
    let t0 = Instant::now();
    let step = |n: &mut KNet, d: &mut Local, now: Duration| {
        n.poll(d, now);
        n.pump_io(d, now);
        n.flush_out(d);
        n.submit();
    };
    while d.sh.0.lock().unwrap().accepted.is_empty() {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "WARNING TIMEOUT accept exceeded 5s (test)"
        );
        step(&mut n, &mut d, t0.elapsed());
    }
    assert_eq!(n.next_due(), None, "nothing timed before the close");
    {
        let mut m = d.sh.0.lock().unwrap();
        let id = m.accepted[0].0;
        // far more than the socket buffers take: the close has to linger
        m.out
            .entry(id)
            .or_default()
            .push_back(Bytes::from(vec![0u8; 64 << 20]));
        m.io.push_back(IoCmd::Close { conn: id });
    }
    let closed = loop {
        let now = t0.elapsed();
        assert!(
            now < Duration::from_secs(5),
            "WARNING TIMEOUT close registration exceeded 5s (test)"
        );
        step(&mut n, &mut d, now);
        if n.next_due().is_some() {
            break now;
        }
    };
    assert_eq!(n.next_due(), Some(closed + linger));
    step(&mut n, &mut d, closed + linger - Duration::from_millis(1));
    assert_eq!(n.next_due(), Some(closed + linger), "not due yet");
    step(&mut n, &mut d, closed + linger);
    assert_eq!(n.next_due(), None, "cut at its deadline, nothing left");
}

#[test]
fn dial_connects_and_exchanges() {
    let s = start(KCfg::default(), false);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    s.mock.0.lock().unwrap().io.push_back(IoCmd::Dial {
        conn: 4242,
        target: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [127, 0, 0, 1], port),
        src: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    });
    s.mock.0.lock().unwrap().live.insert(4242);
    let (mut peer, _) = l.accept().unwrap();
    wait_until("connected", || s.mock.0.lock().unwrap().connected == [4242]);
    peer.write_all(b"hello from peer").unwrap();
    wait_until("rx", || {
        s.mock
            .0
            .lock()
            .unwrap()
            .rx
            .get(&4242)
            .is_some_and(|v| v.len() == 15)
    });
    s.mock
        .0
        .lock()
        .unwrap()
        .out
        .entry(4242)
        .or_default()
        .push_back(Bytes::from_static(b"hello from osd"));
    let mut b = [0u8; 14];
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    peer.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"hello from osd");
    drop(peer);
    wait_until("closed", || s.mock.0.lock().unwrap().closed == [4242]);
    s.stop();
}

/// The dial socket is bound to the OSD's own address before connect (not the route's pick): the peer sees `src`.
#[test]
fn dial_binds_the_given_source_address() {
    let s = start(KCfg::default(), false);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    s.mock.0.lock().unwrap().io.push_back(IoCmd::Dial {
        conn: 5,
        target: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [127, 0, 0, 1], port),
        src: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
    });
    s.mock.0.lock().unwrap().live.insert(5);
    let (_peer, from) = l.accept().unwrap();
    assert_eq!(from.ip().to_string(), "127.0.0.2");
    wait_until("connected", || s.mock.0.lock().unwrap().connected == [5]);
    s.stop();
}

/// A source address that is not local fails the dial (no silent fallback to the route's pick).
#[test]
fn dial_from_a_non_local_source_fails() {
    let s = start(KCfg::default(), false);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    s.mock.0.lock().unwrap().io.push_back(IoCmd::Dial {
        conn: 6,
        target: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [127, 0, 0, 1], port),
        src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
    });
    wait_until("failed", || s.mock.0.lock().unwrap().failed == [(6, false)]);
    s.stop();
}

/// A v6 target is dialled with an AF_INET6 socket (spec ip-addressing.md 4); no source: the socket stays unbound.
#[test]
fn dial_connects_to_an_ipv6_target() {
    let s = start(KCfg::default(), false);
    let l = TcpListener::bind("[::1]:0").unwrap();
    let port = l.local_addr().unwrap().port();
    s.mock.0.lock().unwrap().io.push_back(IoCmd::Dial {
        conn: 9,
        target: EntityAddr::v6(
            EntityAddr::TYPE_MSGR2,
            0,
            std::net::Ipv6Addr::LOCALHOST.octets(),
            port,
            0,
        ),
        src: None,
    });
    s.mock.0.lock().unwrap().live.insert(9);
    let (mut peer, from) = l.accept().unwrap();
    assert!(from.is_ipv6(), "{from}");
    wait_until("connected", || s.mock.0.lock().unwrap().connected == [9]);
    peer.write_all(b"v6 hello").unwrap();
    wait_until("rx over v6", || {
        s.mock
            .0
            .lock()
            .unwrap()
            .rx
            .get(&9)
            .is_some_and(|v| v.len() == 8)
    });
    s.stop();
}

/// The source bind uses our address of the target's family; a source of the other family is never bound (spec 8: the
/// dial still connects, unbound).
#[test]
fn dial_never_binds_a_source_of_the_other_family() {
    let s = start(KCfg::default(), false);
    let l = TcpListener::bind("[::1]:0").unwrap();
    let port = l.local_addr().unwrap().port();
    s.mock.0.lock().unwrap().io.push_back(IoCmd::Dial {
        conn: 10,
        target: EntityAddr::v6(
            EntityAddr::TYPE_MSGR2,
            0,
            std::net::Ipv6Addr::LOCALHOST.octets(),
            port,
            0,
        ),
        // an IPv4 source with an IPv6 target: the OSD never sends this, the transport must not try to bind it
        src: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    });
    s.mock.0.lock().unwrap().live.insert(10);
    let (_peer, from) = l.accept().unwrap();
    assert!(from.is_ipv6(), "unbound v6 dial, not a v4 source: {from}");
    wait_until("connected", || s.mock.0.lock().unwrap().connected == [10]);
    s.stop();
}

/// An accepted v6 connection carries its peer address (both families) to the OSD.
#[test]
fn accept_reports_the_peer_of_either_family() {
    let ports = free_ports();
    let binds = Binds(std::array::from_fn(|i| {
        vec![SocketAddr::new(
            if i == 0 {
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            },
            ports[i],
        )]
    }));
    let mut fds = match bind_all(&binds, 1, &Steer::Hash, 16) {
        Ok(f) => f,
        Err(e) => panic!("bind {ports:?}: {e}"),
    };
    let mock = Shared::default();
    let stop = Arc::new(AtomicBool::new(false));
    let th = spawn_core(KCfg::default(), fds.remove(0), mock.clone(), stop.clone());
    let _c = TcpStream::connect(("::1", ports[0])).unwrap();
    wait_until("accepted", || !mock.0.lock().unwrap().accepted.is_empty());
    assert_eq!(mock.0.lock().unwrap().accepted[0].1, Listener::Public);
    stop.store(true, Ordering::Relaxed);
    th.join().unwrap();
}

#[test]
fn dial_to_closed_port_reports_refused() {
    let s = start(KCfg::default(), false);
    let dead = free_ports()[0];
    s.mock.0.lock().unwrap().io.push_back(IoCmd::Dial {
        conn: 7,
        target: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [127, 0, 0, 1], dead),
        src: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    });
    wait_until("failed", || s.mock.0.lock().unwrap().failed == [(7, true)]);
    s.stop();
}

#[test]
fn second_daemon_on_the_same_port_is_refused() {
    let ports = free_ports();
    let _a = bind_all(&binds(ports), 2, &Steer::Hash, 16).unwrap();
    assert!(bind_all(&binds(ports), 1, &Steer::Hash, 16).is_err());
}

/// Steering: with the CPU filter a connection lands on the core pinned to the CPU that processes the SYN (loopback: the
/// sender's CPU).
#[test]
fn cpu_steering_picks_the_core_of_the_syn_cpu() {
    let cpus = crate::affinity_cpus();
    if cpus.len() < 2 {
        return;
    }
    let (c0, c1) = (cpus[0], cpus[1]);
    let (ports, mut fds) = bind_free(2, &Steer::Cpu(vec![c0, c1]), 128);
    let (m0, m1) = (Shared::default(), Shared::default());
    let stop = Arc::new(AtomicBool::new(false));
    let t1 = spawn_core(KCfg::default(), fds.remove(1), m1.clone(), stop.clone());
    let t0 = spawn_core(KCfg::default(), fds.remove(0), m0.clone(), stop.clone());
    for (cpu, _) in [(c0, 0), (c1, 1)] {
        let port = ports[0];
        std::thread::spawn(move || {
            crate::pin_current_thread(cpu).unwrap();
            let v: Vec<TcpStream> = (0..20).map(|_| client(port)).collect();
            std::thread::sleep(Duration::from_millis(300));
            drop(v);
        })
        .join()
        .unwrap();
    }
    wait_until("40 accepts", || {
        m0.0.lock().unwrap().accepted.len() + m1.0.lock().unwrap().accepted.len() == 40
    });
    assert_eq!(m0.0.lock().unwrap().accepted.len(), 20, "core 0");
    assert_eq!(m1.0.lock().unwrap().accepted.len(), 20, "core 1");
    stop.store(true, Ordering::Relaxed);
    t0.join().unwrap();
    t1.join().unwrap();
}

fn spawn_placed(
    fds: [Vec<OwnedFd>; 4],
    mock: Shared,
    stop: Arc<AtomicBool>,
    place: KPlace,
) -> JoinHandle<KStats> {
    std::thread::spawn(move || {
        let mut n = KNet::new(KCfg::default(), fds).expect("ring");
        n.set_place(place);
        let mut d = mock;
        let t0 = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            let now = t0.elapsed();
            let work = n.poll(&mut d, now);
            n.pump_io(&mut d, now);
            n.flush_out(&mut d);
            n.submit();
            if !work {
                n.wait(Duration::from_micros(200));
            }
        }
        n.stats
    })
}

/// Open question 11: every connection lands on core A's listener (the kernel's hash would do anything); A hands
/// public ones to the least loaded core, so 8 connections end up 4 + 4, and the moved ones work.
#[test]
fn public_connections_go_to_the_least_loaded_core() {
    let (pa, mut fa) = bind_free(1, &Steer::Hash, 128);
    let (_, mut fb) = bind_free(1, &Steer::Hash, 128);
    let (fa, fb) = (fa.remove(0), fb.remove(0));
    let (ma, mb) = (Shared::default(), Shared::default());
    ma.0.lock().unwrap().echo = true;
    mb.0.lock().unwrap().echo = true;
    let stop = Arc::new(AtomicBool::new(false));
    let mut g = KPlace::group(2);
    let (g1, g0) = (g.pop().unwrap(), g.pop().unwrap());
    let ta = spawn_placed(fa, ma.clone(), stop.clone(), g0);
    let tb = spawn_placed(fb, mb.clone(), stop.clone(), g1);
    // a burst: all SYNs before A got to pick for the first (in-transit sockets count as load)
    let clients: Vec<TcpStream> = (0..8).map(|_| client(pa[0])).collect();
    wait_until("8 accepts", || {
        ma.0.lock().unwrap().accepted.len() + mb.0.lock().unwrap().accepted.len() == 8
    });
    assert_eq!(ma.0.lock().unwrap().accepted.len(), 4, "core A");
    assert_eq!(mb.0.lock().unwrap().accepted.len(), 4, "core B (adopted)");
    // data flows on both kinds
    for (i, c) in clients.iter().enumerate() {
        let data = pattern(70_000 + i, i as u8);
        let mut w = c.try_clone().unwrap();
        let d2 = data.clone();
        let t = std::thread::spawn(move || w.write_all(&d2).unwrap());
        let mut got = vec![0u8; data.len()];
        (&*c).read_exact(&mut got).unwrap();
        t.join().unwrap();
        assert!(got == data, "echo mismatch on connection {i}");
    }
    // a closed connection frees its slot: the next one goes where it is least crowded
    drop(clients);
    wait_until("all closed", || {
        ma.0.lock().unwrap().live.is_empty() && mb.0.lock().unwrap().live.is_empty()
    });
    stop.store(true, Ordering::Relaxed);
    let (sa, sb) = (ta.join().unwrap(), tb.join().unwrap());
    assert_eq!((sa.placed_away, sa.adopted), (4, 0));
    assert_eq!((sb.placed_away, sb.adopted), (0, 4));
}

#[test]
fn advance_drops_whole_runs_and_trims_the_partial_one() {
    let mut r = vec![
        Bytes::from_static(b"abc"),
        Bytes::from_static(b"defg"),
        Bytes::from_static(b"h"),
    ];
    advance(&mut r, 5);
    assert_eq!(r, [Bytes::from_static(b"fg"), Bytes::from_static(b"h")]);
    advance(&mut r, 3);
    assert!(r.is_empty());
}

fn direct_msgs(sizes: &[usize], seed: u8) -> Vec<u8> {
    let mut w = Vec::new();
    for (i, &n) in sizes.iter().enumerate() {
        w.extend_from_slice(&(n as u64).to_le_bytes());
        w.extend_from_slice(&pattern(n, seed.wrapping_add(i as u8)));
    }
    w
}

fn start_direct(cfg: KCfg) -> Srv {
    let s = start(cfg, false);
    s.mock.0.lock().unwrap().direct = true;
    s
}

fn check_msgs(s: &Srv, conns: usize, sizes: &[usize], seeds: &[u8]) {
    let m = s.mock.0.lock().unwrap();
    assert_eq!(m.msgs.len(), conns * sizes.len());
    let mut per: HashMap<u64, Vec<&Got>> = HashMap::new();
    for x in &m.msgs {
        per.entry(x.0).or_default().push(x);
    }
    assert_eq!(per.len(), conns);
    for (_, v) in per {
        // messages of one connection arrive in order; every connection used its own seed
        let seed = (0..=255u8)
            .find(|sd| v[0].1 == pattern(sizes[0], *sd))
            .expect("known pattern");
        assert!(seeds.contains(&seed));
        for (i, x) in v.iter().enumerate() {
            assert!(
                x.1 == pattern(sizes[i], seed.wrapping_add(i as u8)),
                "msg {i} differs"
            );
            assert_eq!(x.2, crc::crc32c(!0, &x.1), "running crc of msg {i}");
        }
    }
}

fn secure_wire(sizes: &[usize]) -> Vec<u8> {
    let mut encoder = msgr2::Encoder::new(msgr2::Revision::V21);
    encoder
        .set_secure(
            &msgr2::ConnSecret::new(&[7; 64]).unwrap(),
            msgr2::Role::Client,
        )
        .unwrap();
    let mut wire = Vec::new();
    for (i, &size) in sizes.iter().enumerate() {
        encoder
            .encode_message(
                &[1; 41],
                &[2; 17],
                &[3; 7],
                &pattern(size, i as u8 + 11),
                &mut wire,
            )
            .unwrap();
    }
    wire
}

#[test]
#[ignore = "local Linux secure-ring versus loan copy/CQE comparison, not NIC throughput"]
fn perf_secure_receive_ring_vs_loan() {
    for size in [1 << 20, 4 << 20] {
        for direct_min in [0, 64 << 10] {
            let frames = 8usize;
            let s = start(
                KCfg {
                    direct_min,
                    ..KCfg::default()
                },
                false,
            );
            s.mock.0.lock().unwrap().secure = true;
            let wire = secure_wire(&vec![size; frames]);
            let frame_len = wire.len() / frames;
            assert_eq!(frame_len * frames, wire.len());
            let mut c = client(s.ports[0]);
            let started = Instant::now();
            for (i, frame) in wire.chunks_exact(frame_len).enumerate() {
                c.write_all(&frame[..128]).unwrap();
                wait_until("known secure frame", || {
                    let m = s.mock.0.lock().unwrap();
                    if direct_min == 0 {
                        m.secure_armed
                    } else {
                        m.secure_takes as usize == i + 1
                    }
                });
                c.write_all(&frame[128..]).unwrap();
                wait_until("authenticated frame", || {
                    s.mock.0.lock().unwrap().msgs.len() == i + 1
                });
            }
            let elapsed = started.elapsed();
            let (copied, received_in_loan) = {
                let m = s.mock.0.lock().unwrap();
                for (i, msg) in m.msgs.iter().enumerate() {
                    assert_eq!(msg.1, pattern(size, i as u8 + 11));
                }
                (m.secure_feed_bytes, m.secure_loan_bytes)
            };
            let stats = s.stop();
            assert_eq!(copied + received_in_loan, wire.len() as u64);
            println!(
                "secure size={size} direct_min={direct_min} frames={frames} wire_bytes={} decoder_feed_copy_bytes={copied} loan_bytes={received_in_loan} rx_cqes={} wall_us={} (wall includes polling-client coordination)",
                wire.len(),
                stats.rx_cqes,
                elapsed.as_micros()
            );
        }
    }
}

#[test]
fn slow_direct_receive_reports_progress_but_silent_peer_still_times_out() {
    let wire = secure_wire(&[1 << 20]);
    let cfg = KCfg {
        direct_min: 64 << 10,
        ..KCfg::default()
    };
    let s = start(cfg.clone(), false);
    {
        let mut m = s.mock.0.lock().unwrap();
        m.secure = true;
        m.idle_timeout = Some(Duration::from_millis(500));
    }
    let mut c = client(s.ports[0]);
    c.write_all(&wire[..128]).unwrap();
    wait_until("slow secure loan armed", || {
        s.mock.0.lock().unwrap().secure_takes == 1
    });
    let mut at = 128;
    // Stay below one 256 KiB receive request for longer than the idle cap.
    for i in 0..64 {
        c.write_all(&wire[at..at + 512]).unwrap();
        at += 512;
        wait_until("partial receive progress or premature timeout", || {
            let m = s.mock.0.lock().unwrap();
            m.progress_calls > i || !m.idle_expired.is_empty()
        });
        assert!(s.mock.0.lock().unwrap().idle_expired.is_empty());
        assert!(s.mock.0.lock().unwrap().msgs.is_empty());
        std::thread::sleep(Duration::from_millis(10));
    }
    c.write_all(&wire[at..]).unwrap();
    wait_until("slow secure frame authenticated", || {
        s.mock.0.lock().unwrap().msgs.len() == 1
    });
    assert_eq!(s.mock.0.lock().unwrap().msgs[0].1, pattern(1 << 20, 11));
    s.stop();

    let silent = start(cfg, false);
    {
        let mut m = silent.mock.0.lock().unwrap();
        m.secure = true;
        m.idle_timeout = Some(Duration::from_millis(500));
    }
    let mut c = client(silent.ports[0]);
    c.write_all(&wire[..128]).unwrap();
    wait_until("silent loan armed", || {
        silent.mock.0.lock().unwrap().secure_takes == 1
    });
    wait_until("silent partial peer expires", || {
        !silent.mock.0.lock().unwrap().idle_expired.is_empty()
    });
    // An owner-requested close intentionally emits no on_closed callback.
    // Verify the timed-out socket itself reaches EOF and no frame was delivered.
    c.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut byte = [0];
    assert_eq!(c.read(&mut byte).unwrap(), 0);
    assert!(silent.mock.0.lock().unwrap().msgs.is_empty());
    silent.stop();
}

#[test]
fn secure_receive_loan_completes_during_pause_and_preserves_next_frame() {
    let s = start(
        KCfg {
            direct_min: 64 << 10,
            ..KCfg::default()
        },
        false,
    );
    s.mock.0.lock().unwrap().secure = true;
    let wire = secure_wire(&[1 << 20, 17]);
    let mut c = client(s.ports[0]);
    c.write_all(&wire[..128]).unwrap();
    wait_until("secure decoder loan armed", || {
        s.mock.0.lock().unwrap().secure_takes == 1
    });
    s.mock.0.lock().unwrap().paused = true;
    let writer = std::thread::spawn(move || {
        c.write_all(&wire[128..]).unwrap();
        c
    });
    // the lent buffer is filled although the OSD takes no input; the next frame waits in hold storage
    wait_until("lent secure segment completed while paused", || {
        s.mock.0.lock().unwrap().secure_puts == 1
    });
    std::thread::sleep(Duration::from_millis(20));
    assert!(s.mock.0.lock().unwrap().msgs.len() < 2);
    s.mock.0.lock().unwrap().paused = false;
    wait_until("secure frames authenticated", || {
        s.mock.0.lock().unwrap().msgs.len() == 2
    });
    let keep = writer.join().unwrap();
    {
        let m = s.mock.0.lock().unwrap();
        assert_eq!(m.secure_puts, 1);
        assert_eq!(m.msgs[0].1, pattern(1 << 20, 11));
        assert_eq!(m.msgs[1].1, pattern(17, 12));
    }
    drop(keep);
    s.stop();
}

#[test]
fn secure_receive_partial_eof_releases_loan_after_completion() {
    let s = start(
        KCfg {
            direct_min: 64 << 10,
            ..KCfg::default()
        },
        false,
    );
    s.mock.0.lock().unwrap().secure = true;
    let wire = secure_wire(&[1 << 20]);
    let mut c = client(s.ports[0]);
    c.write_all(&wire[..128]).unwrap();
    wait_until("secure decoder loan armed", || {
        s.mock.0.lock().unwrap().secure_takes == 1
    });
    c.write_all(&wire[128..100_000]).unwrap();
    drop(c);
    wait_until("partial secure close", || {
        s.mock.0.lock().unwrap().closed.len() == 1
    });
    assert_eq!(s.mock.0.lock().unwrap().secure_puts, 0);
    assert!(s.mock.0.lock().unwrap().msgs.is_empty());
    let mut c = client(s.ports[0]);
    c.write_all(&wire).unwrap();
    wait_until("next secure connection healthy", || {
        s.mock.0.lock().unwrap().msgs.len() == 1
    });
    assert_eq!(s.mock.0.lock().unwrap().msgs[0].1, pattern(1 << 20, 11));
    s.stop();
}

#[test]
fn direct_receive_delivers_big_segments_in_place() {
    let cfg = KCfg {
        direct_min: 64 << 10,
        ..KCfg::default()
    };
    let s = start_direct(cfg);
    let sizes = [1 << 20, 5 << 20, 200_000, 64, 3 << 20, 0, 70_000];
    let w = direct_msgs(&sizes, 11);
    let mut c = client(s.ports[0]);
    c.write_all(&w[..8]).unwrap();
    wait_until("direct receive armed", || {
        s.mock.0.lock().unwrap().direct_takes == 1
    });
    let mut cw = c.try_clone().unwrap();
    let t = std::thread::spawn(move || {
        // odd-sized writes so message boundaries fall inside socket reads
        for ch in w[8..].chunks(300_017) {
            cw.write_all(ch).unwrap();
        }
    });
    wait_until("all messages", || {
        s.mock.0.lock().unwrap().msgs.len() == sizes.len()
    });
    t.join().unwrap();
    check_msgs(&s, 1, &sizes, &[11]);
    let puts = s.mock.0.lock().unwrap().direct_puts;
    assert!(
        puts >= 1,
        "big segments must have gone the direct way (puts={puts})"
    );
    s.stop();
}

#[test]
fn direct_receive_off_is_the_ring_path() {
    let cfg = KCfg {
        direct_min: 0,
        ..KCfg::default()
    };
    let s = start_direct(cfg);
    let sizes = [2 << 20, 100_000];
    let mut c = client(s.ports[0]);
    c.write_all(&direct_msgs(&sizes, 3)).unwrap();
    wait_until("msgs", || s.mock.0.lock().unwrap().msgs.len() == 2);
    check_msgs(&s, 1, &sizes, &[3]);
    assert_eq!(s.mock.0.lock().unwrap().direct_puts, 0);
    s.stop();
}

#[test]
fn direct_receive_many_connections() {
    let cfg = KCfg {
        direct_min: 64 << 10,
        ..KCfg::default()
    };
    let s = start_direct(cfg);
    let port = s.ports[0];
    let sizes = [800_000usize, 300_000, 1_500_000];
    // Publish the first frame header, then wait for the direct receives to be armed.
    // Sending every body immediately can let multishot recv finish all frames before cancellation.
    let mut clients = Vec::new();
    for _ in 0..32 {
        let mut c = client(port);
        c.write_all(&(sizes[0] as u64).to_le_bytes()).unwrap();
        clients.push(c);
    }
    wait_until("32 direct receives armed", || {
        s.mock.0.lock().unwrap().direct_takes == 32
    });
    let th: Vec<_> = clients
        .into_iter()
        .enumerate()
        .map(|(i, mut c)| {
            std::thread::spawn(move || {
                c.write_all(&direct_msgs(&sizes, (i as u8).wrapping_mul(7))[8..])
                    .unwrap();
                c
            })
        })
        .collect();
    let keep: Vec<TcpStream> = th.into_iter().map(|t| t.join().unwrap()).collect();
    wait_until("all", || {
        s.mock.0.lock().unwrap().msgs.len() == 32 * sizes.len()
    });
    let seeds: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7)).collect();
    check_msgs(&s, 32, &sizes, &seeds);
    assert!(
        s.mock.0.lock().unwrap().direct_puts > 0,
        "no segment went the direct way"
    );
    drop(keep);
    s.stop();
}

#[test]
fn peer_closing_in_the_middle_of_a_direct_receive_is_clean() {
    let cfg = KCfg {
        direct_min: 64 << 10,
        ..KCfg::default()
    };
    let s = start_direct(cfg);
    for cut in [100_000usize, 700_000, 2_000_000] {
        let mut c = client(s.ports[0]);
        let w = direct_msgs(&[3 << 20], 5);
        c.write_all(&w[..cut]).unwrap();
        drop(c); // FIN in the middle of the segment
    }
    wait_until("3 closes", || s.mock.0.lock().unwrap().closed.len() == 3);
    // the core is still healthy: a fresh connection delivers a full message
    let mut c = client(s.ports[0]);
    c.write_all(&direct_msgs(&[1 << 20], 9)).unwrap();
    wait_until("msg", || s.mock.0.lock().unwrap().msgs.len() == 1);
    check_msgs(&s, 1, &[1 << 20], &[9]);
    s.stop();
}

#[test]
fn chunked_sends_deliver_identical_bytes() {
    let cfg = KCfg {
        send_chunk: 100_000,
        ..KCfg::default()
    };
    let s = start(cfg, true);
    for (i, n) in [1usize, 99_999, 100_001, 5 << 20].into_iter().enumerate() {
        echo_roundtrip(s.ports[0], pattern(n, 3 + i as u8));
    }
    s.stop();
}

/// Peer steering: a connection from a source port `p` with `p % N == k` reaches the cluster listener of core `k`
/// (kernel reuseport group index), also when the SYN carries IP options (IHL > 5), and `pick_src_port` finds such
/// ports for a core count that does not divide the range start (regression: 6 cores picked `p % 6 == k + 2`).
#[test]
fn peer_source_port_selects_the_cluster_listener_of_the_core() {
    const N: usize = 6;
    let ports = free_ports();
    let opts = ListenOpts {
        port_steer: true,
        sockbuf: 0,
    };
    let fds = bind_all_with(&binds(ports), N, &Steer::Hash, 128, &opts).unwrap();
    for l in &fds {
        let fl = unsafe { libc::fcntl(l[1][0].as_raw_fd(), libc::F_GETFL) };
        unsafe { libc::fcntl(l[1][0].as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK) };
    }
    let sp = listen::SrcPorts::from_proc();
    let mut rnd = 0x1234_5678_9abc_def1u64;
    let mut keep = Vec::new();
    for round in 0..4 {
        for k in 0..N {
            let s =
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            assert!(s >= 0);
            if round >= 2 {
                // 4 option bytes (NOP NOP NOP EOL): IHL 6, the port sits at network header + 24
                let o = [1u8, 1, 1, 0];
                let r = unsafe {
                    libc::setsockopt(s, libc::IPPROTO_IP, libc::IP_OPTIONS, o.as_ptr().cast(), 4)
                };
                assert_eq!(r, 0, "IP_OPTIONS");
            }
            assert!(listen::pick_src_port(
                s,
                std::net::Ipv4Addr::LOCALHOST,
                &sp,
                N as u32,
                k as u32,
                &mut rnd
            ));
            let mut la: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut ll = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            unsafe { libc::getsockname(s, (&raw mut la).cast(), &raw mut ll) };
            assert_eq!(
                usize::from(u16::from_be(la.sin_port)) % N,
                k,
                "picked port residue"
            );
            let (sa, len) =
                listen::sockaddr(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ports[1]));
            let r = unsafe { libc::connect(s, (&raw const sa).cast(), len) };
            assert_eq!(r, 0, "connect round {round} core {k}");
            keep.push(s);
            std::thread::sleep(Duration::from_millis(20));
            let mut got = Vec::new();
            for (c, l) in fds.iter().enumerate() {
                let a = unsafe {
                    libc::accept(
                        l[1][0].as_raw_fd(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                if a >= 0 {
                    got.push(c);
                    unsafe { libc::close(a) };
                }
            }
            assert_eq!(got, vec![k], "round {round}: connection for core {k}");
        }
    }
    for s in keep {
        unsafe { libc::close(s) };
    }
}

#[test]
fn src_ports_follow_the_kernel_range_and_skip_reserved_ports() {
    let sp = listen::SrcPorts::parse("40000\t40011\n", "40000-40005,40010\n");
    let mut rnd = 7u64;
    let mut seen = BTreeSet::new();
    for _ in 0..200 {
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if listen::pick_src_port(s, std::net::Ipv4Addr::LOCALHOST, &sp, 3, 1, &mut rnd) {
            let mut la: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut ll = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            unsafe { libc::getsockname(s, (&raw mut la).cast(), &raw mut ll) };
            seen.insert(u16::from_be(la.sin_port));
        }
        unsafe { libc::close(s) };
    }
    // 40000..=40011 with p % 3 == 1: 40003 (reserved), 40006, 40009; never outside the range or reserved
    assert!(
        !seen.is_empty() && seen.iter().all(|p| [40006, 40009].contains(p)),
        "{seen:?}"
    );
    // garbage / empty: kernel defaults; nothing usable: no bind
    let d = listen::SrcPorts::parse("", "");
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(listen::pick_src_port(
        s,
        std::net::Ipv4Addr::LOCALHOST,
        &d,
        8,
        3,
        &mut rnd
    ));
    unsafe { libc::close(s) };
    let none = listen::SrcPorts::parse("40000 40001", "40000-40001");
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(!listen::pick_src_port(
        s,
        std::net::Ipv4Addr::LOCALHOST,
        &none,
        2,
        0,
        &mut rnd
    ));
    assert!(
        !listen::pick_src_port(s, std::net::Ipv4Addr::LOCALHOST, &d, 1, 0, &mut rnd),
        "one core: no binding"
    );
    unsafe { libc::close(s) };
}

/// Dial towards a kernel-tier peer: the source port selects core `rem` on the peer (port class), no relay hop.
#[test]
fn dial_ports_land_on_the_peer_core_by_port_class() {
    let lo = std::net::Ipv4Addr::LOCALHOST;
    let mut rnd = 11u64;
    let bound = |s: i32| {
        let mut la: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut ll = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        unsafe { libc::getsockname(s, (&raw mut la).cast(), &raw mut ll) };
        u16::from_be(la.sin_port)
    };
    let sp = listen::SrcPorts::parse("40000 44095", "");
    for n in [2u32, 4, 6, 8] {
        for rem in 0..n {
            let s =
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            assert!(listen::pick_src_port(s, lo, &sp, n, rem, &mut rnd));
            let p = bound(s);
            unsafe { libc::close(s) };
            assert_eq!(u32::from(p) % n, rem, "n {n}: port class");
        }
    }
}

/// Wake: a core with a wake handle really sleeps in its ring (the eventfd read is parked, not completed with EAGAIN in a
/// loop), a poke from another thread ends the sleep early, and `wait_if` skips the sleep when the re-check sees work. The
/// result tells how the sleep ended; a skipped sleep returns `None`, also right after a timed-out one (a stale timeout
/// booked a skipped sleep as a full one: wake-latency and timeout counters, inventory row 1 of
/// doc/perf/sleep-register-20261101.md). Without a wake handle the re-check runs too.
#[test]
fn wake_poke_ends_the_ring_sleep() {
    let fds = bind_all(&binds(free_ports()), 1, &Steer::Hash, 16).unwrap();
    let mut n = KNet::new(KCfg::default(), fds.into_iter().next().unwrap()).expect("ring");
    let t = Instant::now();
    assert_eq!(n.wait_if(Duration::from_secs(5), || false), None);
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "busy re-check without a wake handle must skip the sleep"
    );
    let w = crate::wake::Wake::new().unwrap();
    n.set_wake(w.clone());
    for _ in 0..3 {
        let t = Instant::now();
        let end = n.wait_if(Duration::from_millis(100), || true);
        assert!(
            t.elapsed() >= Duration::from_millis(80),
            "slept {:?}",
            t.elapsed()
        );
        assert_eq!(
            end,
            Some(Waited {
                timed_out: true,
                poke_ns: None
            })
        );
        n.poll(&mut Shared::default(), Duration::ZERO);
    }
    let t = Instant::now();
    assert_eq!(
        n.wait_if(Duration::from_secs(5), || false),
        None,
        "a skipped sleep after a timed-out one is no sleep"
    );
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "busy re-check must skip the sleep"
    );
    let w2 = w.clone();
    let h = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        w2.poke();
    });
    let t = Instant::now();
    let end = n.wait_if(Duration::from_secs(5), || true);
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "poke did not wake: {:?}",
        t.elapsed()
    );
    assert!(
        matches!(
            end,
            Some(Waited {
                timed_out: false,
                poke_ns: Some(_)
            })
        ),
        "{end:?}"
    );
    h.join().unwrap();
    n.poll(&mut Shared::default(), Duration::ZERO);
    let t = Instant::now();
    assert_eq!(n.wait_if(Duration::from_secs(5), || false), None);
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "busy re-check must skip the sleep"
    );
}

/// The RDMA control wake is the core's own (no mesh wake installed: `has_wake` stays false, like single-core mode and
/// `--knet-wake off`): a core that announced its sleep (`rdma_sleep_check`) is woken by a poke of a control thread at once, the
/// read is re-armed for the next sleep, and an awake core is not poked (no syscall) and sleeps its full cap.
#[cfg(feature = "rdma")]
#[test]
fn rdma_control_reply_wakes_a_sleeping_core() {
    let fds = bind_all(&binds(free_ports()), 1, &Steer::Hash, 16).unwrap();
    let mut n = KNet::new(KCfg::default(), fds.into_iter().next().unwrap()).expect("ring");
    let w = crate::wake::Wake::new().unwrap();
    n.set_rdma(KRdma::wake_only(w.clone()));
    assert!(!n.has_wake(), "no mesh wake: the control wake stands alone");
    let mut d = Shared::default();
    // awake: a poke is free and does not end the sleep of a core that did not announce it
    w.poke();
    let t = Instant::now();
    n.wait(Duration::from_millis(100));
    assert!(
        t.elapsed() >= Duration::from_millis(80),
        "{:?}",
        t.elapsed()
    );
    // sleeping, twice (the second proves the read was re-armed): the poke ends the sleep long before the cap
    for _ in 0..2 {
        assert!(
            !n.rdma_sleep_check(&mut d, Duration::ZERO),
            "no work to find"
        );
        let w2 = w.clone();
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            w2.poke();
        });
        let t = Instant::now();
        n.wait(Duration::from_secs(5));
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "control reply did not wake the core: {:?}",
            t.elapsed()
        );
        h.join().unwrap();
        n.poll(&mut d, Duration::ZERO); // consumes the wake, the core is awake again
    }
}

/// The close fence timeout is loud and names the limit and the connection.
#[cfg(feature = "rdma")]
#[test]
fn rdma_close_fence_timeout_message() {
    assert_eq!(
        krdma::fence_timeout(Duration::from_secs(5), 0x2a),
        "WARNING TIMEOUT rdma close fence exceeded 5s (conn 0x2a)"
    );
}

/// A connection whose peer is an address of this host is never a candidate for the RDMA upgrade (its QP pair would loop
/// through the NIC, doc/perf/rdma-size3-20261021.md); the same connection with a remote peer is.
#[cfg(feature = "rdma")]
#[test]
fn rdma_upgrade_skips_a_same_host_peer() {
    use std::os::fd::IntoRawFd;
    let fds = bind_all(&binds(free_ports()), 1, &Steer::Hash, 16).unwrap();
    let mut n = KNet::new(KCfg::default(), fds.into_iter().next().unwrap()).expect("ring");
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let _client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (server, _) = l.accept().unwrap();
    let fd = server.into_raw_fd();
    let slot = n.add_conn(fd, 9, false);
    assert!(local_peer(fd), "a loopback peer is a same-host peer");
    n.slots[slot as usize].as_mut().unwrap().local_peer = local_peer(fd);
    assert!(n.rdma_candidate(9).is_none());
    n.slots[slot as usize].as_mut().unwrap().local_peer = false;
    assert!(n.rdma_candidate(9).is_some_and(|(s, _)| s == slot));
}

/// Pin the calling thread to the CPU it runs on (threads it spawns inherit this). Loopback receive softirq runs on the
/// sender CPU, so with everything on one CPU every segment passes the spread co-location check.
fn pin_this_thread_to_its_cpu() {
    let cpu = listen::this_cpu().expect("sched_getcpu");
    // SAFETY: plain affinity call on this thread with a stack cpu set.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        assert_eq!(
            libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set),
            0
        );
    }
}

/// `n` cores sharing one mock OSD, joined in the receive-spread mesh (adr 0053 am. 3) with wake handles; cores sleep in
/// their ring when idle (`wait`), so job and done hand-offs must poke them. Everything runs on one CPU (see
/// `pin_this_thread_to_its_cpu`).
fn start_spread(
    n: usize,
    cfg: KCfg,
) -> (Shared, [u16; 4], Arc<AtomicBool>, Vec<JoinHandle<KStats>>) {
    let mock = Shared::default();
    mock.0.lock().unwrap().direct = true;
    let (ports, stop, th) = start_spread_with(vec![mock.clone(); n], cfg);
    (mock, ports, stop, th)
}

/// `start_spread` with one mock per core (`mocks[i]` drives core i). Echo tests need their own mock per core: a core
/// drops the output of a connection id it does not own (`flush_one`), so a shared echo mock loses bytes.
fn start_spread_with(
    mocks: Vec<Shared>,
    cfg: KCfg,
) -> ([u16; 4], Arc<AtomicBool>, Vec<JoinHandle<KStats>>) {
    let n = mocks.len();
    pin_this_thread_to_its_cpu();
    let (ports, fds) = bind_free(n, &Steer::Hash, 128);
    let stop = Arc::new(AtomicBool::new(false));
    let wakes: Arc<[Arc<crate::wake::Wake>]> =
        (0..n).map(|_| crate::wake::Wake::new().unwrap()).collect();
    let th = fds
        .into_iter()
        .zip(spread_mesh(n, Some(wakes.clone())))
        .zip(mocks)
        .enumerate()
        .map(|(i, ((f, sp), mock))| {
            let (cfg, stop, w) = (cfg.clone(), stop.clone(), wakes[i].clone());
            std::thread::spawn(move || {
                let mut net = KNet::new(cfg, f).expect("ring");
                net.set_wake(w);
                net.set_spread(sp);
                let mut d = mock;
                let t0 = Instant::now();
                while !stop.load(Ordering::Relaxed) {
                    let now = t0.elapsed();
                    let work = net.poll(&mut d, now);
                    net.pump_io(&mut d, now);
                    net.flush_out(&mut d);
                    net.submit();
                    if !work {
                        net.wait(Duration::from_millis(20));
                    }
                }
                net.stats
            })
        })
        .collect();
    (ports, stop, th)
}

/// `n` spread cores, each with its own echo mock.
fn start_spread_echo(
    n: usize,
) -> (
    Vec<Shared>,
    [u16; 4],
    Arc<AtomicBool>,
    Vec<JoinHandle<KStats>>,
) {
    let mocks: Vec<Shared> = (0..n).map(|_| Shared::default()).collect();
    for m in &mocks {
        m.0.lock().unwrap().echo = true;
    }
    let (ports, stop, th) = start_spread_with(mocks.clone(), KCfg::default());
    (mocks, ports, stop, th)
}

fn spread_cfg() -> KCfg {
    KCfg {
        direct_min: 64 << 10,
        spread_min: 64 << 10,
        ..KCfg::default()
    }
}

/// Big segments of many connections are received by helper cores: every message arrives complete, in order per
/// connection, with the right running crc; jobs went out and were served on other cores.
#[test]
fn spread_receive_delivers_segments_received_by_helper_cores() {
    for bigshot in [0, 8] {
        let cfg = KCfg {
            bigshot,
            ..spread_cfg()
        };
        let (mock, ports, stop, th) = start_spread(3, cfg);
        let sizes = [1 << 20, 5 << 20, 200_000, 64, 3 << 20, 0, 70_001];
        let mut clients = Vec::new();
        for _ in 0..8 {
            let mut c = client(ports[0]);
            c.write_all(&(sizes[0] as u64).to_le_bytes()).unwrap();
            clients.push(c);
        }
        wait_until("8 direct receives armed", || {
            mock.0.lock().unwrap().direct_takes == 8
        });
        let w: Vec<_> = clients
            .into_iter()
            .enumerate()
            .map(|(i, mut c)| {
                std::thread::spawn(move || {
                    // odd-sized writes so message boundaries fall inside socket reads
                    for ch in direct_msgs(&sizes, (i as u8).wrapping_mul(5))[8..].chunks(300_017) {
                        c.write_all(ch).unwrap();
                    }
                    c
                })
            })
            .collect();
        let keep: Vec<TcpStream> = w.into_iter().map(|t| t.join().unwrap()).collect();
        wait_until("all messages", || {
            mock.0.lock().unwrap().msgs.len() == 8 * sizes.len()
        });
        let srv = Srv {
            mock,
            ports,
            stop: stop.clone(),
            th: None,
        };
        let seeds: Vec<u8> = (0..8u8).map(|i| i.wrapping_mul(5)).collect();
        check_msgs(&srv, 8, &sizes, &seeds);
        drop(keep);
        stop.store(true, Ordering::Relaxed);
        let st: Vec<KStats> = th.into_iter().map(|t| t.join().unwrap()).collect();
        let jobs: u64 = st.iter().map(|s| s.spread_jobs).sum();
        let served: u64 = st.iter().map(|s| s.spread_served).sum();
        assert!(jobs > 0, "no segment rest was spread ({st:?})");
        assert_eq!(jobs, served, "every job ran on a helper");
        assert!(st.iter().map(|s| s.spread_bytes).sum::<u64>() > 0);
        if bigshot > 0 {
            assert!(st.iter().map(|s| s.bigshots).sum::<u64>() > 0, "{st:?}");
        }
    }
}

/// A peer that closes in the middle of a segment being received by a helper: the job comes back failed, the
/// connection is reported closed once, the fd is released, and the cores keep working.
#[test]
fn spread_receive_peer_close_mid_segment_is_clean() {
    let (mock, ports, stop, th) = start_spread(2, spread_cfg());
    for (k, cut) in [100_000usize, 700_000, 2_000_000].into_iter().enumerate() {
        let mut c = client(ports[0]);
        let w = direct_msgs(&[3 << 20], 5);
        c.write_all(&w[..8]).unwrap();
        wait_until("direct receive armed", || {
            mock.0.lock().unwrap().direct_takes == k as u64 + 1
        });
        c.write_all(&w[8..cut]).unwrap();
        std::thread::sleep(Duration::from_millis(30)); // the job is on the helper
        drop(c); // FIN in the middle of the segment
    }
    wait_until("3 closes", || mock.0.lock().unwrap().closed.len() == 3);
    let mut c = client(ports[0]);
    c.write_all(&direct_msgs(&[2 << 20], 9)).unwrap();
    wait_until("msg", || mock.0.lock().unwrap().msgs.len() == 1);
    let srv = Srv {
        mock: mock.clone(),
        ports,
        stop: stop.clone(),
        th: None,
    };
    check_msgs(&srv, 1, &[2 << 20], &[9]);
    assert_eq!(
        mock.0.lock().unwrap().closed.len(),
        3,
        "each close reported once"
    );
    drop(c);
    stop.store(true, Ordering::Relaxed);
    let st: Vec<KStats> = th.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(st.iter().map(|s| s.spread_jobs).sum::<u64>() >= 3, "{st:?}");
}

/// The OSD closes a connection while a helper is receiving its segment: the helper's receive ends (shutdown), the job
/// comes back, the slot is freed only then (no fd reuse under a live receive).
#[test]
fn spread_receive_osd_close_while_the_job_is_out() {
    let (mock, ports, stop, th) = start_spread(2, spread_cfg());
    let mut c = client(ports[0]);
    let w = direct_msgs(&[4 << 20], 7);
    c.write_all(&w[..300_000]).unwrap();
    wait_until("direct", || mock.0.lock().unwrap().direct_takes == 1);
    std::thread::sleep(Duration::from_millis(50));
    let id = mock.0.lock().unwrap().accepted[0].0;
    mock.0
        .lock()
        .unwrap()
        .io
        .push_back(IoCmd::Close { conn: id });
    // the client sees the close (EOF / reset) even though a helper holds a receive on the socket
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut b = [0u8; 16];
    let r = c.read(&mut b);
    assert!(matches!(r, Ok(0) | Err(_)), "{r:?}");
    let mut c2 = client(ports[0]);
    c2.write_all(&direct_msgs(&[1 << 20], 3)).unwrap();
    wait_until("msg", || mock.0.lock().unwrap().msgs.len() == 1);
    stop.store(true, Ordering::Relaxed);
    let st: Vec<KStats> = th.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(st.iter().map(|s| s.spread_jobs).sum::<u64>() >= 1, "{st:?}");
}

/// The connection's core stops while a helper still receives its segment (cores exit one by one): its drop leaves the
/// lent socket open, so the helper's next pieces read that socket, never a descriptor number reused meanwhile. Before,
/// the drop closed it: the helper's next receive failed (EBADF, or read a foreign socket) and the peer got a reset.
#[test]
fn spread_owner_drop_keeps_the_lent_socket_open() {
    use std::os::fd::IntoRawFd;
    pin_this_thread_to_its_cpu();
    let (_, fds) = bind_free(2, &Steer::Hash, 128);
    let mut fds = fds.into_iter();
    let mut sp = spread_mesh(2, None).into_iter();
    let mut owner = KNet::new(spread_cfg(), fds.next().unwrap()).unwrap();
    owner.set_spread(sp.next().unwrap());
    let mut helper = KNet::new(spread_cfg(), fds.next().unwrap()).unwrap();
    helper.set_spread(sp.next().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut c = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let slot = owner.add_conn(server.into_raw_fd(), 1, false);
    owner.arm_recv(slot);
    let mut d = Shared::default();
    d.0.lock().unwrap().direct = true;
    let w = direct_msgs(&[4 << 20], 7);
    c.write_all(&w[..300_000]).unwrap();
    let t0 = Instant::now();
    wait_until("the segment rest is out on the helper", || {
        owner.poll(&mut d, t0.elapsed());
        owner.submit();
        owner.stats.spread_jobs == 1
    });
    drop(owner);
    let rest = w[300_000..].to_vec();
    let writer = std::thread::spawn(move || c.write_all(&rest).map(|()| c));
    wait_until("the helper received the rest", || {
        helper.poll(&mut d, t0.elapsed());
        helper.submit();
        writer.is_finished() && helper.stats.spread_bytes > 0
    });
    assert!(
        writer.join().unwrap().is_ok(),
        "the peer saw the socket closed"
    );
}

/// Spread sends report written bytes to the driver, including a prefix sent before a fault.
#[test]
fn spread_send_reports_written_progress_on_success_and_error() {
    for failed in [None, Some(-libc::EPIPE)] {
        let (mut n, slot, _client) = idle_conn(99);
        n.set_spread(spread_mesh(1, None).remove(0));
        let c = n.slots[slot as usize].as_mut().unwrap();
        c.inflight = 1;
        c.sending = true;
        c.send_away = true;
        let job = spread::SendJob {
            from: 0,
            slot,
            id: c.id,
            fd: c.fd,
            st: SendState::boxed(),
            sent: 123,
            failed,
        };
        let sp = n.spread.as_mut().unwrap();
        let job = match sp.submit_send(job) {
            Ok(Some(job)) => job,
            _ => panic!("single-core mesh must select itself"),
        };
        let run = sp.park_send(job);
        sp.finish_send(run);
        let mut d = Shared::default();
        assert!(n.spread_reap(&mut d, Duration::ZERO));
        let state = d.0.lock().unwrap();
        assert_eq!(state.written, [(99, 123)]);
        assert_eq!(state.closed.len(), usize::from(failed.is_some()));
        drop(state);
        assert!(!n.spread_reap(&mut d, Duration::ZERO));
        assert_eq!(d.0.lock().unwrap().written, [(99, 123)]);
    }
}

/// Send spread (adr 0053 am. 12): echo replies of many connections leave as send jobs executed by the core with the
/// fewest send jobs; every byte arrives in order per connection, jobs ran on other cores too, all came back.
#[test]
fn send_spread_echoes_big_batches_in_order() {
    for n in [1, 3] {
        send_spread_echo(n, 2);
    }
    send_spread_echo(3, 8);
}

fn send_spread_echo(cores: usize, conns: usize) {
    let (_mocks, ports, stop, th) = start_spread_echo(cores);
    let t0 = Instant::now();
    let w: Vec<_> = (0..conns)
        .map(|i| {
            let port = ports[i % cores.min(2)];
            std::thread::spawn(move || {
                for (k, n) in [6usize << 20, 300_000, 1, 9 << 20].into_iter().enumerate() {
                    echo_roundtrip(port, pattern(n, (i * 7 + k) as u8));
                }
            })
        })
        .collect();
    let joined: Vec<bool> = w.into_iter().map(|t| t.join().is_ok()).collect();
    let ok = !joined.contains(&false);
    stop.store(true, Ordering::Relaxed);
    let st: Vec<KStats> = th.into_iter().map(|t| t.join().unwrap()).collect();
    eprintln!(
        "send spread echo cores={cores} conns={conns}: {:?}",
        t0.elapsed()
    );
    assert!(ok, "echo failed ({st:?})");
    let jobs: u64 = st.iter().map(|s| s.send_jobs).sum();
    let served: u64 = st.iter().map(|s| s.send_served).sum();
    assert!(jobs > 0, "no send batch was spread ({st:?})");
    assert!(
        cores == 1 || served > 0,
        "no send job ran on another core ({st:?})"
    );
    assert!(served <= jobs, "{st:?}");
    assert!(cores == 1 || st.iter().map(|s| s.send_served_bytes).sum::<u64>() > 0);
}

/// A peer that stops reading and then resets while its send job is out: the job comes back failed, the connection is
/// reported closed once, the slot is freed only then, and the cores keep serving.
#[test]
fn send_spread_peer_reset_while_the_job_is_out() {
    let (mocks, ports, stop, th) = start_spread_echo(2);
    let closed = || {
        mocks
            .iter()
            .map(|m| m.0.lock().unwrap().closed.len())
            .sum::<usize>()
    };
    let queued = || {
        mocks
            .iter()
            .any(|m| m.0.lock().unwrap().out.values().any(|q| !q.is_empty()))
    };
    for k in 0..3u64 {
        let mut c = client(ports[0]);
        // never read: the echo fills both socket buffers, the send job blocks on the full socket
        let data = pattern(16 << 20, 3);
        let mut w = c.try_clone().unwrap();
        let t = std::thread::spawn(move || {
            let _ = w.write_all(&data);
        });
        wait_until("send job out", queued);
        std::thread::sleep(Duration::from_millis(50));
        // RST instead of FIN: linger 0
        let l = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        // SAFETY: setsockopt on our own test socket with a stack struct.
        unsafe {
            use std::os::fd::AsRawFd;
            libc::setsockopt(
                c.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&raw const l).cast(),
                size_of::<libc::linger>() as u32,
            );
        }
        let _ = c.flush();
        drop(c);
        let _ = t.join();
        wait_until("close reported", || closed() as u64 == k + 1);
    }
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(closed(), 3, "each close reported once");
    echo_roundtrip(ports[0], pattern(5 << 20, 9));
    stop.store(true, Ordering::Relaxed);
    let st: Vec<KStats> = th.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(st.iter().map(|s| s.send_jobs).sum::<u64>() >= 3, "{st:?}");
}

/// The OSD closes a connection while its send job is out: the job's send ends (shutdown), the job comes back, the
/// slot is freed only then; queued output is dropped, nothing else breaks.
#[test]
fn send_spread_osd_close_while_the_job_is_out() {
    let (mocks, ports, stop, th) = start_spread_echo(2);
    let mut c = client(ports[0]);
    let data = pattern(16 << 20, 5);
    let mut w = c.try_clone().unwrap();
    let t = std::thread::spawn(move || {
        let _ = w.write_all(&data);
    });
    wait_until("output queued", || {
        mocks
            .iter()
            .any(|m| m.0.lock().unwrap().out.values().any(|q| !q.is_empty()))
    });
    std::thread::sleep(Duration::from_millis(50));
    let owner = mocks
        .iter()
        .find(|m| !m.0.lock().unwrap().accepted.is_empty())
        .expect("accepting core");
    let id = owner.0.lock().unwrap().accepted[0].0;
    owner
        .0
        .lock()
        .unwrap()
        .io
        .push_back(IoCmd::Close { conn: id });
    // drain until the close: everything that arrives is a prefix of the echo
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let want = pattern(16 << 20, 5);
    let mut got = 0usize;
    let mut b = vec![0u8; 1 << 20];
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if b[..n] != want[got..got + n] {
                    let at = (0..n).find(|&k| b[k] != want[got + k]).unwrap();
                    panic!(
                        "echo out of order at {got}+{at} (read {n}): got {:?} want {:?}",
                        &b[at..(at + 16).min(n)],
                        &want[got + at..got + at + 16]
                    );
                }
                got += n;
            }
        }
    }
    drop(c);
    let _ = t.join();
    echo_roundtrip(ports[0], pattern(3 << 20, 1));
    stop.store(true, Ordering::Relaxed);
    let st: Vec<KStats> = th.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(st.iter().map(|s| s.send_jobs).sum::<u64>() >= 1, "{st:?}");
}

/// One-shot ring receives after a big segment (`bigshot`): the next big segment is detected on its first buffer and
/// received direct; small messages in between still arrive; the connection falls back to multishot.
#[test]
fn bigshot_detects_the_next_big_segment_without_a_cancel() {
    let s = start_direct(KCfg {
        direct_min: 64 << 10,
        bigshot: 4,
        ..KCfg::default()
    });
    let sizes = [
        1 << 20,
        3 << 20,
        64,
        2 << 20,
        0,
        70_000,
        5,
        6,
        7,
        8,
        9,
        1 << 20,
    ];
    let w = direct_msgs(&sizes, 21);
    let mut c = client(s.ports[0]);
    c.write_all(&w[..8]).unwrap();
    wait_until("direct receive armed", || {
        s.mock.0.lock().unwrap().direct_takes == 1
    });
    for ch in w[8..].chunks(200_003) {
        c.write_all(ch).unwrap();
        std::thread::sleep(Duration::from_millis(2));
    }
    wait_until("all messages", || {
        s.mock.0.lock().unwrap().msgs.len() == sizes.len()
    });
    check_msgs(&s, 1, &sizes, &[21]);
    let st = s.stop();
    assert!(st.bigshots > 0, "{st:?}");
}

/// `SO_INCOMING_CPU` names the CPU that ran the receive softirq: a loopback segment is processed on the sending CPU, so
/// a thread pinned to one CPU that sends and then asks sees its own CPU (adr 0053 am. 4).
#[test]
fn incoming_cpu_is_the_cpu_that_processed_the_segment() {
    pin_this_thread_to_its_cpu();
    let cpu = listen::this_cpu().expect("sched_getcpu");
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (mut s, _) = l.accept().unwrap();
    c.write_all(b"x").unwrap();
    let mut b = [0u8; 1];
    s.read_exact(&mut b).unwrap();
    use std::os::fd::AsRawFd;
    assert_eq!(listen::incoming_cpu(s.as_raw_fd()), Some(cpu));
    assert!(listen::rx_on_this_cpu(s.as_raw_fd()));
}

/// `spread_coloc`: only segments of connections whose softirq runs on the receiving core's CPU go to helpers; data
/// stays complete and in order either way.
#[test]
fn spread_coloc_spreads_only_colocated_segments() {
    let cfg = KCfg {
        bigshot: 8,
        ..spread_cfg()
    };
    let (mock, ports, stop, th) = start_spread(3, cfg);
    let sizes = [1 << 20, 3 << 20, 200_000, 64, 70_001];
    let mut clients = Vec::new();
    for _ in 0..6 {
        let mut c = client(ports[0]);
        c.write_all(&(sizes[0] as u64).to_le_bytes()).unwrap();
        clients.push(c);
    }
    wait_until("6 direct receives armed", || {
        mock.0.lock().unwrap().direct_takes == 6
    });
    let w: Vec<_> = clients
        .into_iter()
        .enumerate()
        .map(|(i, mut c)| {
            std::thread::spawn(move || {
                for ch in direct_msgs(&sizes, (i as u8).wrapping_mul(7))[8..].chunks(250_013) {
                    c.write_all(ch).unwrap();
                }
                c
            })
        })
        .collect();
    let keep: Vec<TcpStream> = w.into_iter().map(|t| t.join().unwrap()).collect();
    wait_until("all messages", || {
        mock.0.lock().unwrap().msgs.len() == 6 * sizes.len()
    });
    let srv = Srv {
        mock,
        ports,
        stop: stop.clone(),
        th: None,
    };
    let seeds: Vec<u8> = (0..6u8).map(|i| i.wrapping_mul(7)).collect();
    check_msgs(&srv, 6, &sizes, &seeds);
    drop(keep);
    stop.store(true, Ordering::Relaxed);
    let st: Vec<KStats> = th.into_iter().map(|t| t.join().unwrap()).collect();
    let jobs: u64 = st.iter().map(|s| s.spread_jobs).sum();
    let coloc: u64 = st.iter().map(|s| s.rx_coloc).sum();
    let starts: u64 = st.iter().map(|s| s.direct_starts).sum();
    assert!(
        jobs <= coloc,
        "a job from a segment whose softirq ran elsewhere ({st:?})"
    );
    assert!(coloc <= starts, "{st:?}");
    assert_eq!(jobs, st.iter().map(|s| s.spread_served).sum::<u64>());
}

#[test]
fn one_poll_drains_a_queued_direct_segment_completely() {
    let (_, mut fds) = bind_free(1, &Steer::Hash, 128);
    let mut n = KNet::new(
        KCfg {
            direct_min: 64 << 10,
            ..KCfg::default()
        },
        fds.remove(0),
    )
    .unwrap();
    let mut d = Shared::default();
    d.0.lock().unwrap().direct = true;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    d.0.lock().unwrap().io.push_back(IoCmd::Dial {
        conn: 7,
        target: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [127, 0, 0, 1], port),
        src: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    });
    d.0.lock().unwrap().live.insert(7);
    let t = Instant::now();
    n.pump_io(&mut d, t.elapsed());
    n.submit();
    let (mut peer, _) = l.accept().unwrap();
    let size = DIRECT_CHUNK * 6;
    let w = direct_msgs(&[size], 31);
    peer.write_all(&w[..8]).unwrap();
    while d.0.lock().unwrap().direct_takes == 0 {
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "direct receive not armed"
        );
        n.poll(&mut d, t.elapsed());
        n.pump_io(&mut d, t.elapsed());
        n.submit();
    }
    // the whole segment waits in the socket, then ONE core iteration must take all of it; room for it beyond net.core.rmem_max
    // needs SO_RCVBUFFORCE (CAP_NET_ADMIN: the build host runs these tests as root)
    let fd = n.slots.iter().flatten().find(|c| c.id == 7).unwrap().fd;
    let rcvbuf: libc::c_int = 16 << 20;
    // SAFETY: plain int socket option on a socket the test owns.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            (&rcvbuf as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "SO_RCVBUFFORCE needs CAP_NET_ADMIN");
    peer.write_all(&w[8..]).unwrap();
    let mut inq: libc::c_int = 0;
    // any syscall of this thread may run the armed receive (task work): at most its one piece left the socket
    while (inq as usize) < size - DIRECT_CHUNK {
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "segment not queued (inq {inq})"
        );
        // SAFETY: SIOCINQ writes one int for a TCP socket the test owns.
        assert!(unsafe { libc::ioctl(fd, libc::FIONREAD, &mut inq) } >= 0);
    }
    n.poll(&mut d, t.elapsed());
    assert_eq!(
        d.0.lock().unwrap().msgs.len(),
        1,
        "segment left in the socket after one poll"
    );
    assert!(n.stats.rx_more_passes >= 5);
    assert_eq!(d.0.lock().unwrap().msgs[0].1, pattern(size, 31));
}

/// RDMA liveness channel (msgr2 spec 18) on a RoCEv2 device (Soft-RoCE is enough): two cores on one thread, one upgraded
/// connection between them over the device address. The passive side of every close learns it from the socket at once,
/// after what arrived over the QP is delivered. Run by lab/rdma-spike/rxe-teardown-test.sh.
#[cfg(feature = "rdma")]
mod krdma_liveness {
    use super::*;
    use crate::knet::krdma;

    const CONN: u64 = 1;
    const PLACEMENT_SENTINEL: u8 = 0x5a;
    /// The close must reach the passive side well within this (before: never, or the 10 s handshake timeout).
    const NOTICE: Duration = Duration::from_secs(1);

    #[derive(Default)]
    struct Peer {
        io: VecDeque<IoCmd>,
        out: VecDeque<Bytes>,
        notified: bool,
        rx: Vec<u8>,
        /// Our QP endpoint from `rdma_prepared` / `rdma_accepted`.
        endpoint: Option<Vec<u8>>,
        connected: bool,
        closed: Option<Instant>,
        placement_receipts: Vec<(u64, u32, Vec<u8>)>,
        placement_cancelled: Vec<(u64, u32)>,
        placement_faults: Vec<(u64, u32)>,
        placement_refusals: Vec<(u64, u32)>,
    }

    impl Driver for Peer {
        fn on_accept(&mut self, _: usize, _: SocketAddr, _: Duration) -> Option<u64> {
            panic!("no listener traffic in this test");
        }
        fn on_connected(&mut self, _: u64, _: Duration) {}
        fn on_dial_failed(&mut self, conn: u64, _: bool, _: Duration) {
            panic!("dial of {conn} failed");
        }
        fn on_closed(&mut self, conn: u64, _: Duration) {
            assert_eq!(conn, CONN);
            assert!(
                self.closed.replace(Instant::now()).is_none(),
                "closed twice"
            );
        }
        fn on_bytes(&mut self, _: u64, data: &[u8], _: Duration) {
            self.rx.extend_from_slice(data);
        }
        fn poll_io(&mut self) -> Option<IoCmd> {
            self.io.pop_front()
        }
        fn rdma_decline(&mut self, cmd: IoCmd, _: Duration) {
            panic!("declined: {cmd:?}");
        }
        fn rdma_prepared(&mut self, _: u64, endpoint: Option<Vec<u8>>, _: Duration) -> bool {
            self.endpoint = Some(endpoint.expect("prepared QP"));
            true
        }
        fn rdma_accepted(&mut self, _: u64, endpoint: Option<Vec<u8>>, _: Duration) -> bool {
            self.endpoint = Some(endpoint.expect("accepted QP"));
            // the ACCEPT frame: the last TCP output
            self.out.push_back(Bytes::from_static(b"accept"));
            true
        }
        fn rdma_connected(&mut self, _: u64, _: Duration) -> bool {
            self.connected = true;
            true
        }
        fn placement_preflight_refused(&mut self, conn: u64, tid: u64, retry: u32) {
            assert_eq!(conn, CONN);
            self.placement_refusals.push((tid, retry));
        }
        fn placement_success(&mut self, conn: u64, tid: u64, retry: u32, receipt: Vec<u8>) {
            assert_eq!(conn, CONN);
            self.out.push_back(Bytes::copy_from_slice(&receipt));
            self.placement_receipts.push((tid, retry, receipt));
        }
        fn placement_cancelled(&mut self, conn: u64, tid: u64, retry: u32) {
            assert_eq!(conn, CONN);
            self.out.push_back(Bytes::from_static(b"retired"));
            self.placement_cancelled.push((tid, retry));
        }
        fn placement_fault(&mut self, conn: u64, tid: u64, retry: u32) {
            assert_eq!(conn, CONN);
            self.placement_faults.push((tid, retry));
        }
        fn poll_output_chunks(&mut self, _: u64) -> Vec<Bytes> {
            self.notified = false;
            self.out.drain(..).collect()
        }
        fn poll_output_ready(&mut self) -> Option<u64> {
            (!self.out.is_empty() && !std::mem::replace(&mut self.notified, true)).then_some(CONN)
        }
    }

    struct Side {
        n: KNet,
        d: Peer,
    }

    struct Pair {
        a: Option<Side>,
        b: Option<Side>,
        t0: Instant,
        _hub: krdma::Hub,
    }

    impl Pair {
        fn step(&mut self) {
            let now = self.t0.elapsed();
            for s in [self.a.as_mut(), self.b.as_mut()].into_iter().flatten() {
                s.n.poll(&mut s.d, now);
                s.n.pump_io(&mut s.d, now);
                s.n.flush_out(&mut s.d);
                s.n.submit();
            }
        }
        fn run_until(&mut self, what: &str, limit: Duration, mut f: impl FnMut(&Pair) -> bool) {
            let end = Instant::now() + limit;
            while !f(self) {
                assert!(
                    Instant::now() < end,
                    "WARNING TIMEOUT {what} exceeded {}s (rdma liveness test)",
                    limit.as_secs_f64()
                );
                self.step();
            }
        }
        fn a(&mut self) -> &mut Side {
            self.a.as_mut().unwrap()
        }
        fn b(&mut self) -> &mut Side {
            self.b.as_mut().unwrap()
        }
        fn closed(s: &Option<Side>) -> bool {
            s.as_ref().unwrap().d.closed.is_some()
        }
        /// Transport faults counted by a side's planes.
        fn faulted(s: &mut Side) -> u64 {
            let st = s.n.rdma_status(Duration::from_secs(1 << 20)).unwrap();
            st.iter().map(|d| d.counters.faulted).sum()
        }
    }

    /// `a` = server (accepts the upgrade), `b` = client (offers it); connection `CONN` on both, upgraded.
    fn upgraded_pair() -> Pair {
        upgraded_pair_with(None)
    }

    /// [`upgraded_pair`] whose cores send chunks inside `zc` zero copy (`krdma::start`).
    fn upgraded_pair_with(zc: Option<&'static [u8]>) -> Pair {
        use std::os::fd::IntoRawFd;
        let addr: Ipv4Addr = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
            .expect("FLASHSTORE_TEST_RDMA_ADDR (local IPv4 of a RoCEv2 device)")
            .parse()
            .expect("FLASHSTORE_TEST_RDMA_ADDR is an IPv4 address");
        let ranges = zc.map(|bytes| [(bytes.as_ptr() as u64, bytes.len() as u64)]);
        // SAFETY: zc is immutable static backing, retained for the whole process.
        let (hub, mut planes) = unsafe {
            krdma::start(
                &[addr],
                2,
                64 << 20,
                0,
                ranges.as_ref().map(|r| r.as_slice()),
                false,
            )
        }
        .unwrap();
        let listener = TcpListener::bind((addr, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let side = |fd: i32, r: krdma::KRdma| {
            let (_, mut fds) = bind_free(1, &Steer::Hash, 16);
            let mut n = KNet::new(KCfg::default(), fds.remove(0)).unwrap();
            n.set_rdma(r);
            let slot = n.add_conn(fd, CONN, false);
            n.arm_recv(slot);
            Side {
                n,
                d: Peer::default(),
            }
        };
        let b = side(client.into_raw_fd(), planes.pop().unwrap().unwrap());
        let a = side(server.into_raw_fd(), planes.pop().unwrap().unwrap());
        let mut p = Pair {
            a: Some(a),
            b: Some(b),
            t0: Instant::now(),
            _hub: hub,
        };
        let limit = Duration::from_secs(10);
        p.b().d.io.push_back(IoCmd::RdmaPrepare { conn: CONN });
        p.run_until("prepare", limit, |p| {
            p.b.as_ref().unwrap().d.endpoint.is_some()
        });
        let endpoint = p.b().d.endpoint.take().unwrap();
        p.a().d.io.push_back(IoCmd::RdmaAccept {
            conn: CONN,
            endpoint,
        });
        p.run_until("accept", limit, |p| p.b.as_ref().unwrap().d.rx == b"accept");
        let endpoint = p.a().d.endpoint.take().unwrap();
        p.b().d.rx.clear();
        p.b().d.io.push_back(IoCmd::RdmaConnect {
            conn: CONN,
            endpoint,
        });
        p.run_until("connect", limit, |p| p.b.as_ref().unwrap().d.connected);
        p
    }

    /// 4 MiB in 64 KiB pieces: several credit windows in flight when the close comes.
    fn payload(seed: u8) -> Vec<Bytes> {
        (0..64)
            .map(|i| Bytes::from(pattern(64 << 10, seed.wrapping_add(i))))
            .collect()
    }

    fn joined(v: &[Bytes]) -> Vec<u8> {
        v.iter().flat_map(|b| b.iter().copied()).collect()
    }

    fn placement_window(
        pair: &mut Pair,
        attempt: rdma::verbs::WindowAttempt,
    ) -> rdma::verbs::AdvertisedWindow {
        placement_window_len(pair, attempt, 4096)
    }

    fn placement_window_len(
        pair: &mut Pair,
        attempt: rdma::verbs::WindowAttempt,
        length: usize,
    ) -> rdma::verbs::AdvertisedWindow {
        use rdma::verbs::{HostDestination, UnboundWindow, WindowState};

        let (core, qpn) = pair.b().n.test_placement_core(CONN).expect("client RC QP");
        let destination =
            HostDestination::register(core.device(), vec![PLACEMENT_SENTINEL; length + 1024])
                .expect("register destination");
        let range = destination
            .range()
            .subrange(1024, length as u64)
            .expect("subrange");
        let local = core
            .bind_window(
                qpn,
                UnboundWindow::allocate(destination).expect("type-2 window"),
                range,
            )
            .expect("bind window");
        pair.run_until("placement bind", Duration::from_secs(10), |_| {
            local.state() == WindowState::Bound
        });
        let (core, _) = pair.b().n.test_placement_core(CONN).unwrap();
        local.advertise(core, attempt).expect("advertise window")
    }

    /// The production KNet command, CQ pass and output path complete one placed READ on the
    /// same QP. The provider owns the destination window and source registration throughout.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_placement_handoff_reaches_driver_success() {
        use rdma::verbs::{ReadReceipt, WindowAttempt, WindowState};

        let source: &'static [u8] = Box::leak(vec![0x7bu8; 4096].into_boxed_slice());
        let mut pair = upgraded_pair_with(Some(source));
        let attempt = WindowAttempt {
            connection: 19,
            tid: 29,
            retry: 2,
        };
        let mut grant = placement_window(&mut pair, attempt);
        let descriptor = grant.descriptor();
        pair.a().d.io.push_back(IoCmd::PlaceReadReply {
            conn: CONN,
            tid: attempt.tid,
            retry: attempt.retry,
            grant: descriptor,
            pieces: vec![Bytes::from_static(source)],
            block_crcs: vec![crc::crc32c(0, source)],
            len: source.len() as u64,
        });
        pair.run_until("placement success", Duration::from_secs(10), |p| {
            !p.a.as_ref().unwrap().d.placement_receipts.is_empty()
                && !p.b.as_ref().unwrap().d.rx.is_empty()
        });
        let receipt_bytes = std::mem::take(&mut pair.a().d.placement_receipts[0].2);
        assert_eq!(pair.b.as_ref().unwrap().d.rx, receipt_bytes);
        let receipt = ReadReceipt::decode(&receipt_bytes, descriptor).expect("validated receipt");
        // SAFETY: this test owns both QPs and observed the ordered reply on the client QP.
        assert!(unsafe { grant.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
        let (core, _) = pair.b().n.test_placement_core(CONN).unwrap();
        grant.invalidate(core).expect("invalidate window");
        pair.run_until("placement invalidation", Duration::from_secs(10), |_| {
            grant.state() == WindowState::Retired
        });
        let buffer = grant
            .into_unbound()
            .expect("retired window")
            .into_destination()
            .expect("registered destination")
            .into_buffer()
            .expect("original buffer");
        assert_eq!(&buffer[1024..1024 + source.len()], source);
        receipt
            .verify(&buffer[1024..1024 + source.len()])
            .expect("CRC");
    }

    /// Already-queued SEND bytes precede the WRITE and its same-QP receipt.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_placement_drains_older_output_before_receipt() {
        use rdma::verbs::{ReadReceipt, WindowAttempt, WindowState};

        let source: &'static [u8] = Box::leak(vec![0x62u8; 4096].into_boxed_slice());
        let mut pair = upgraded_pair_with(Some(source));
        let attempt = WindowAttempt {
            connection: 19,
            tid: 34,
            retry: 1,
        };
        let mut grant = placement_window(&mut pair, attempt);
        let descriptor = grant.descriptor();
        let older = Bytes::from_static(b"older-send");
        pair.a().d.out.push_back(older.clone());
        pair.a().d.io.push_back(IoCmd::PlaceReadReply {
            conn: CONN,
            tid: attempt.tid,
            retry: attempt.retry,
            grant: descriptor,
            pieces: vec![Bytes::from_static(source)],
            block_crcs: vec![crc::crc32c(0, source)],
            len: source.len() as u64,
        });
        pair.run_until(
            "placement after older output",
            Duration::from_secs(10),
            |p| {
                let a = p.a.as_ref().unwrap();
                let b = p.b.as_ref().unwrap();
                a.d.placement_receipts.len() == 1
                    && b.d.rx.len() == older.len() + a.d.placement_receipts[0].2.len()
            },
        );
        let receipt_bytes = &pair.a.as_ref().unwrap().d.placement_receipts[0].2;
        let received = &pair.b.as_ref().unwrap().d.rx;
        assert_eq!(&received[..older.len()], older.as_ref());
        assert_eq!(&received[older.len()..], receipt_bytes);
        let receipt_bytes = receipt_bytes.clone();
        let receipt = ReadReceipt::decode(&receipt_bytes, descriptor).expect("matching receipt");
        assert!(unsafe { grant.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
        let (core, _) = pair.b().n.test_placement_core(CONN).unwrap();
        grant.invalidate(core).expect("invalidate window");
        pair.run_until(
            "placement older output invalidation",
            Duration::from_secs(10),
            |_| grant.state() == WindowState::Retired,
        );
        let buffer = grant
            .into_unbound()
            .expect("retired window")
            .into_destination()
            .expect("registered destination")
            .into_buffer()
            .expect("original buffer");
        receipt
            .verify(&buffer[1024..1024 + source.len()])
            .expect("CRC");
    }

    /// A SEND prefix exceeding all possible peer credits must wait, not reject placement.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_placement_older_prefix_backpressure_waits_for_credits() {
        placement_older_prefix_backpressure(false);
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_placement_older_prefix_backpressure_cancel_never_writes() {
        placement_older_prefix_backpressure(true);
    }

    fn placement_older_prefix_backpressure(cancel: bool) {
        use rdma::verbs::{ReadReceipt, WindowAttempt, WindowState};

        let source: &'static [u8] = Box::leak(vec![0x73u8; 4096].into_boxed_slice());
        let mut pair = upgraded_pair_with(Some(source));
        let attempt = WindowAttempt {
            connection: 19,
            tid: 36,
            retry: 1,
        };
        let mut grant = placement_window(&mut pair, attempt);
        let descriptor = grant.descriptor();
        let prefix_len = (rdma::DEFAULT_MAX_WINDOW as usize + 1) * rdma::DEFAULT_SLOT as usize;
        let older = Bytes::from(vec![0x46u8; prefix_len]);
        pair.a().d.out.push_back(older.clone());
        pair.a().d.io.push_back(IoCmd::PlaceReadReply {
            conn: CONN,
            tid: attempt.tid,
            retry: attempt.retry,
            grant: descriptor,
            pieces: vec![Bytes::from_static(source)],
            block_crcs: vec![crc::crc32c(0, source)],
            len: source.len() as u64,
        });
        // Deliberately do not poll the receiver: no receive slots/credits can return.
        let now = pair.t0.elapsed();
        {
            let a = pair.a();
            a.n.pump_io(&mut a.d, now);
            assert!(
                a.d.placement_refusals.is_empty(),
                "SEND backpressure is not unsupported placement"
            );
            assert_eq!(
                a.n.slots[a.n.by_id[&CONN] as usize]
                    .as_ref()
                    .unwrap()
                    .rdma
                    .placement
                    .len(),
                1
            );
            assert!(a.d.placement_receipts.is_empty());
        }
        if cancel {
            let a = pair.a();
            a.d.io.push_back(IoCmd::PlaceReadCancel {
                conn: CONN,
                tid: attempt.tid,
                retry: attempt.retry,
            });
            a.n.pump_io(&mut a.d, now);
        }
        pair.run_until(
            "placement after blocked prefix",
            Duration::from_secs(10),
            |p| {
                let a = p.a.as_ref().unwrap();
                let b = p.b.as_ref().unwrap();
                if cancel {
                    a.d.placement_cancelled == [(attempt.tid, attempt.retry)]
                        && b.d.rx.len() == older.len() + b"retired".len()
                } else {
                    a.d.placement_receipts.len() == 1
                        && b.d.rx.len() == older.len() + a.d.placement_receipts[0].2.len()
                }
            },
        );
        let receipt_bytes =
            (!cancel).then(|| pair.a.as_ref().unwrap().d.placement_receipts[0].2.clone());
        assert_eq!(&pair.b.as_ref().unwrap().d.rx[..older.len()], &older[..]);
        if cancel {
            assert_eq!(&pair.b.as_ref().unwrap().d.rx[older.len()..], b"retired");
            assert!(pair.a.as_ref().unwrap().d.placement_receipts.is_empty());
        }
        // SAFETY: both QPs are owned and the ordered same-QP receipt was received.
        assert!(unsafe { grant.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
        let (core, _) = pair.b().n.test_placement_core(CONN).unwrap();
        grant.invalidate(core).unwrap();
        pair.run_until(
            "blocked prefix invalidation",
            Duration::from_secs(10),
            |_| grant.state() == WindowState::Retired,
        );
        let buffer = grant
            .into_unbound()
            .unwrap()
            .into_destination()
            .unwrap()
            .into_buffer()
            .unwrap();
        if let Some(bytes) = receipt_bytes {
            ReadReceipt::decode(&bytes, descriptor)
                .unwrap()
                .verify(&buffer[1024..1024 + source.len()])
                .unwrap();
        } else {
            assert!(
                buffer.iter().all(|&byte| byte == PLACEMENT_SENTINEL),
                "cancel while prefix blocked must never post a WRITE"
            );
        }
        assert!(pair.a.as_ref().unwrap().d.placement_refusals.is_empty());
        assert!(pair.a.as_ref().unwrap().d.placement_faults.is_empty());
    }

    /// EOF has no WRITE, but still needs a same-QP terminal receipt and a
    /// retired destination before the caller may reuse its allocation.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_placement_empty_eof_retires_without_write() {
        use rdma::verbs::{ReadReceipt, WindowAttempt, WindowState};

        let mut pair = upgraded_pair();
        let attempt = WindowAttempt {
            connection: 19,
            tid: 36,
            retry: 1,
        };
        let mut grant = placement_window(&mut pair, attempt);
        let descriptor = grant.descriptor();
        pair.a().d.io.push_back(IoCmd::PlaceReadReply {
            conn: CONN,
            tid: attempt.tid,
            retry: attempt.retry,
            grant: descriptor,
            pieces: Vec::new(),
            block_crcs: Vec::new(),
            len: 0,
        });
        pair.run_until("placement EOF", Duration::from_secs(10), |p| {
            let a = p.a.as_ref().unwrap();
            let b = p.b.as_ref().unwrap();
            a.d.placement_receipts.len() == 1 && b.d.rx.len() == a.d.placement_receipts[0].2.len()
        });
        let receipt_bytes = &pair.a.as_ref().unwrap().d.placement_receipts[0].2;
        assert_eq!(&pair.b.as_ref().unwrap().d.rx, receipt_bytes);
        let receipt_bytes = receipt_bytes.clone();
        let receipt = ReadReceipt::decode(&receipt_bytes, descriptor).expect("EOF receipt");
        assert_eq!(receipt.written_len(), 0);
        assert!(unsafe { grant.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
        let (core, _) = pair.b().n.test_placement_core(CONN).unwrap();
        grant.invalidate(core).expect("invalidate window");
        pair.run_until("EOF invalidation", Duration::from_secs(10), |_| {
            grant.state() == WindowState::Retired
        });
        let buffer = grant
            .into_unbound()
            .expect("retired window")
            .into_destination()
            .expect("registered destination")
            .into_buffer()
            .expect("original buffer");
        assert!(buffer.iter().all(|&byte| byte == 0x5a));
        receipt.verify(&[]).expect("empty CRC");
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_placement_cancel_drains_writes_before_retired() {
        use rdma::verbs::{WindowAttempt, WindowState};

        let source: &'static [u8] = Box::leak(vec![0x7bu8; 4096].into_boxed_slice());
        let mut pair = upgraded_pair_with(Some(source));
        let attempt = WindowAttempt {
            connection: 19,
            tid: 30,
            retry: 3,
        };
        let mut grant = placement_window(&mut pair, attempt);
        let descriptor = grant.descriptor();
        pair.a().d.io.push_back(IoCmd::PlaceReadReply {
            conn: CONN,
            tid: attempt.tid,
            retry: attempt.retry,
            grant: descriptor,
            pieces: vec![Bytes::from_static(source)],
            block_crcs: vec![crc::crc32c(0, source)],
            len: source.len() as u64,
        });
        pair.a().d.io.push_back(IoCmd::PlaceReadCancel {
            conn: CONN,
            tid: attempt.tid,
            retry: attempt.retry,
        });
        pair.run_until("placement retired", Duration::from_secs(10), |p| {
            p.a.as_ref().unwrap().d.placement_cancelled == [(attempt.tid, attempt.retry)]
                && p.b.as_ref().unwrap().d.rx == b"retired"
        });
        assert!(pair.a.as_ref().unwrap().d.placement_receipts.is_empty());
        assert!(pair.a.as_ref().unwrap().d.placement_faults.is_empty());
        // SAFETY: this test owns both QPs and observed the callback after all WRITE CQEs.
        assert!(unsafe { grant.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
        let (core, _) = pair.b().n.test_placement_core(CONN).unwrap();
        grant.invalidate(core).expect("invalidate window");
        pair.run_until(
            "placement cancel invalidation",
            Duration::from_secs(10),
            |_| grant.state() == WindowState::Retired,
        );
        let _buffer = grant
            .into_unbound()
            .expect("retired window")
            .into_destination()
            .expect("registered destination")
            .into_buffer()
            .expect("original buffer");
    }

    /// Two attempts on the same RC connection keep separate destination windows,
    /// receipts and source owners through the KNet CQ pass.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_placement_parallel_owners_complete_independently() {
        use rdma::verbs::{ReadReceipt, WindowAttempt, WindowState};

        let first: &'static [u8] = Box::leak(vec![0x39u8; 4096].into_boxed_slice());
        let second: &'static [u8] = Box::leak(vec![0x7bu8; 4096].into_boxed_slice());
        let mut pool = Vec::with_capacity(first.len() + second.len());
        pool.extend_from_slice(first);
        pool.extend_from_slice(second);
        let pool: &'static [u8] = Box::leak(pool.into_boxed_slice());
        let mut pair = upgraded_pair_with(Some(pool));
        let attempts = [
            WindowAttempt {
                connection: 19,
                tid: 31,
                retry: 1,
            },
            WindowAttempt {
                connection: 19,
                tid: 32,
                retry: 1,
            },
        ];
        let grants = attempts.map(|attempt| placement_window(&mut pair, attempt));
        for (i, source) in [&pool[..4096], &pool[4096..]].into_iter().enumerate() {
            pair.a().d.io.push_back(IoCmd::PlaceReadReply {
                conn: CONN,
                tid: attempts[i].tid,
                retry: attempts[i].retry,
                grant: grants[i].descriptor(),
                pieces: vec![Bytes::from_static(source)],
                block_crcs: vec![crc::crc32c(0, source)],
                len: source.len() as u64,
            });
        }
        pair.run_until("parallel placement", Duration::from_secs(10), |p| {
            p.a.as_ref().unwrap().d.placement_receipts.len() == 2
        });
        assert!(pair.a.as_ref().unwrap().d.placement_cancelled.is_empty());
        assert!(pair.a.as_ref().unwrap().d.placement_faults.is_empty());
        for (i, (source, mut grant)) in [first, second].into_iter().zip(grants).enumerate() {
            let descriptor = grant.descriptor();
            let (tid, retry, receipt) = &pair.a.as_ref().unwrap().d.placement_receipts[i];
            assert_eq!((*tid, *retry), (attempts[i].tid, attempts[i].retry));
            let receipt_bytes = receipt.clone();
            let receipt =
                ReadReceipt::decode(&receipt_bytes, descriptor).expect("matching receipt");
            // SAFETY: the test owns both QPs and observed the corresponding
            // ordered success callback after all of this attempt's WRITE CQEs.
            assert!(unsafe { grant.confirm_peer_retired_unchecked(attempts[i], descriptor.rkey) });
            let (core, _) = pair.b().n.test_placement_core(CONN).unwrap();
            grant.invalidate(core).expect("invalidate window");
            pair.run_until("parallel invalidation", Duration::from_secs(10), |_| {
                grant.state() == WindowState::Retired
            });
            let buffer = grant
                .into_unbound()
                .expect("retired window")
                .into_destination()
                .expect("registered destination")
                .into_buffer()
                .expect("original buffer");
            assert_eq!(&buffer[1024..1024 + source.len()], source);
            receipt
                .verify(&buffer[1024..1024 + source.len()])
                .expect("CRC");
        }
    }

    /// A WRITE rejected by the peer's protection domain cannot turn into a
    /// success receipt or RETIRED proof. The live destination remains owned.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_placement_bad_remote_key_faults_without_retirement() {
        use rdma::verbs::WindowAttempt;

        let source: &'static [u8] = Box::leak(vec![0x4du8; 4096].into_boxed_slice());
        let mut pair = upgraded_pair_with(Some(source));
        let attempt = WindowAttempt {
            connection: 19,
            tid: 33,
            retry: 1,
        };
        let grant = placement_window(&mut pair, attempt);
        let mut descriptor = grant.descriptor();
        descriptor.rkey = 0;
        pair.a().d.io.push_back(IoCmd::PlaceReadReply {
            conn: CONN,
            tid: attempt.tid,
            retry: attempt.retry,
            grant: descriptor,
            pieces: vec![Bytes::from_static(source)],
            block_crcs: vec![crc::crc32c(0, source)],
            len: source.len() as u64,
        });
        pair.run_until("placement protection fault", Duration::from_secs(10), |p| {
            p.a.as_ref().unwrap().d.placement_faults == [(attempt.tid, attempt.retry)]
        });
        assert!(pair.a.as_ref().unwrap().d.placement_receipts.is_empty());
        assert!(pair.a.as_ref().unwrap().d.placement_cancelled.is_empty());
        assert!(pair.b.as_ref().unwrap().d.rx.is_empty());
        let before = rdma::verbs::quarantined_windows();
        drop(grant); // No same-QP proof: the destination stays quarantined.
        assert_eq!(rdma::verbs::quarantined_windows(), before + 1);
    }

    /// Peer loss while SQ backpressure holds unposted pieces cannot produce
    /// a successful receipt or ordered RETIRED record for the whole attempt.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_placement_peer_loss_with_pending_writes_faults() {
        use rdma::verbs::WindowAttempt;

        const PART: usize = 64 << 10;
        const PARTS: usize = 192;
        let source: &'static [u8] = Box::leak(vec![0x37u8; PART * PARTS].into_boxed_slice());
        let mut pair = upgraded_pair_with(Some(source));
        let attempt = WindowAttempt {
            connection: 19,
            tid: 35,
            retry: 1,
        };
        let grant = placement_window_len(&mut pair, attempt, source.len());
        let descriptor = grant.descriptor();
        pair.a().d.io.push_back(IoCmd::PlaceReadReply {
            conn: CONN,
            tid: attempt.tid,
            retry: attempt.retry,
            grant: descriptor,
            pieces: source
                .as_chunks::<PART>()
                .0
                .iter()
                .map(|part| Bytes::from_static(part))
                .collect(),
            block_crcs: source
                .as_chunks::<4096>()
                .0
                .iter()
                .map(|b| crc::crc32c(0, b))
                .collect(),
            len: source.len() as u64,
        });
        let now = pair.t0.elapsed();
        let a = pair.a();
        a.n.pump_io(&mut a.d, now); // accept the command without draining CQ completions
        drop(pair.b.take()); // lose the receiver endpoint without an ordered RETIRED proof
        pair.run_until("placement peer loss", Duration::from_secs(10), |p| {
            p.a.as_ref().unwrap().d.placement_faults == [(attempt.tid, attempt.retry)]
        });
        let a = pair.a.as_ref().unwrap();
        assert!(a.d.placement_receipts.is_empty());
        assert!(a.d.placement_cancelled.is_empty());
        let before = rdma::verbs::quarantined_windows();
        drop(grant);
        assert_eq!(rdma::verbs::quarantined_windows(), before + 1);
    }

    /// Output queued while a send is blocked on credits (its notification consumed by a `flush_one` that found the queue
    /// busy) leaves once the queue drains: the last reply of a burst never waits for a later message (ice-b client
    /// cells: the last 4 MiB read reply sat until the client's 120 s deadline).
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_output_queued_behind_a_blocked_send_leaves() {
        let mut p = upgraded_pair();
        let first = payload(5);
        p.a().d.out.extend(first.iter().cloned());
        p.step(); // 4 MiB against a window of at most 1 MiB: blocked on credits
        let last = Bytes::from(pattern(4096, 77));
        p.a().d.out.push_back(last.clone());
        let mut want = joined(&first);
        want.extend_from_slice(&last);
        p.run_until("last reply", Duration::from_secs(10), |p| {
            p.b.as_ref().unwrap().d.rx.len() >= want.len()
        });
        assert!(p.b().d.rx == want);
    }

    /// Zero-copy SEND through the knet output path (`rdma_flush` -> `Core::send_bytes`): chunks inside the
    /// registered range (large, unaligned, split across credit windows) go zero copy, small ones and one outside the range
    /// are copied; the stream arrives byte-exact and in order.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_zero_copy_output_arrives_byte_exact() {
        // the "payload heap": mapped for the life of the process
        let heap: &'static [u8] = Vec::leak(pattern(24 << 20, 11));
        let mut p = upgraded_pair_with(Some(heap));
        let chunks = [
            Bytes::from_static(&heap[..4 << 20]),
            Bytes::from_static(&heap[(4 << 20) + 3..(4 << 20) + 3 + 1000]), // below the threshold: copied
            Bytes::from(pattern(1 << 20, 99)), // outside the range: copied
            Bytes::from_static(&heap[(5 << 20) + 17..(21 << 20) + 5]), // 16 MiB, unaligned
            Bytes::from_static(&heap[(22 << 20)..(22 << 20) + (64 << 10)]), // exactly one slot
        ];
        let want = joined(&chunks);
        p.a().d.out.extend(chunks.iter().cloned());
        p.run_until("zero-copy transfer", Duration::from_secs(30), |p| {
            p.b.as_ref().unwrap().d.rx.len() >= want.len()
        });
        assert!(p.b().d.rx == want, "stream corrupted");
        let st = p.a().n.rdma_status(Duration::from_secs(1 << 20)).unwrap();
        let (zc, miss) = st.iter().fold((0, 0), |(z, m), d| {
            (z + d.counters.zc_bytes, m + d.counters.zc_misses)
        });
        eprintln!("zero copy: {zc} bytes, {miss} misses");
        // 20 MiB + 64 KiB eligible; a remainder below one slot after a credit stall is copied (at most one per chunk)
        assert!(zc >= (20 << 20) - (64 << 10), "zero-copy bytes {zc}");
        assert!(miss >= 1, "the chunk outside the range (once per offer)");
        // the status of `a` is rate-limited (one report per second): its faults come from the same snapshot
        assert_eq!(st.iter().map(|d| d.counters.faulted).sum::<u64>(), 0);
        assert_eq!(Pair::faulted(p.b()), 0);
    }

    /// The WAIT loser of the msgr2 race: the client closes right after the switch, nothing sent. The server learns it from
    /// the socket at once (before: at its handshake timeout, then its close fence hit the destroyed QP).
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_liveness_close_right_after_the_switch_is_seen_at_once() {
        let mut p = upgraded_pair();
        p.b().d.io.push_back(IoCmd::Close { conn: CONN });
        let t = Instant::now();
        p.run_until("close notice", NOTICE, |p| Pair::closed(&p.a));
        eprintln!("close noticed after {:?}", t.elapsed());
        assert_eq!(Pair::faulted(p.a()), 0);
        assert_eq!(Pair::faulted(p.b()), 0);
    }

    /// Graceful close with frames in flight: everything is delivered before the passive side sees the end.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_liveness_graceful_close_delivers_everything_then_ends() {
        let mut p = upgraded_pair();
        let data = payload(7);
        p.b().d.out.extend(data.iter().cloned());
        p.step(); // the output is taken (and partly posted) before the close
        p.b().d.io.push_back(IoCmd::Close { conn: CONN });
        let t = Instant::now();
        p.run_until("close notice", NOTICE, |p| Pair::closed(&p.a));
        eprintln!("close noticed after {:?}", t.elapsed());
        assert!(
            p.a().d.rx == joined(&data),
            "all frames delivered before the end"
        );
        assert_eq!(Pair::faulted(p.a()), 0);
        assert_eq!(Pair::faulted(p.b()), 0);
    }

    /// The peer dies (no fence, no close: its process ends) while this side has output in flight: the end is seen at once
    /// and this side's QP goes before its sends could run into the transport retry limit.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn krdma_liveness_dead_peer_is_seen_at_once() {
        let mut p = upgraded_pair();
        let data = payload(3);
        p.b().d.out.extend(data.iter().cloned());
        let want = joined(&data);
        p.run_until("transfer", Duration::from_secs(10), |p| {
            p.a.as_ref().unwrap().d.rx.len() == want.len()
        });
        assert!(p.a().d.rx == want);
        // the server sends towards the client while it dies
        p.a().d.out.extend(payload(9));
        p.step();
        drop(p.b.take());
        let t = Instant::now();
        p.run_until("death notice", NOTICE, |p| Pair::closed(&p.a));
        eprintln!("death noticed after {:?}", t.elapsed());
        // the transport retry limit is seconds away: run past it, no fault on this side
        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {
            p.step();
        }
        assert_eq!(Pair::faulted(p.a()), 0);
    }
}

mod zcrx;

/// The direct-receive pointer is handed to the kernel for `left` bytes: a loan with less spare capacity is refused in
/// release builds too (a silent kernel write past the allocation otherwise).
#[test]
#[should_panic(expected = "direct receive")]
fn direct_receive_refuses_a_loan_smaller_than_the_announced_bytes() {
    let mut dx = DirectRx::Crc {
        v: msgr2::SegBuf::from(Vec::with_capacity(4096)),
        crc: crc::BlockCrcs::default(),
        left: 8192,
    };
    let _ = dx.receive_pointer();
}

/// Two OSD listener setups on one IP (per-core `SO_REUSEPORT` groups, like two OSDs of a host) and a foreign socket in
/// the port range: both bind, on distinct ports, the foreign port is skipped (`osd::portsel`, spec osd-lifecycle).
#[test]
fn two_osd_listener_sets_on_one_ip_take_distinct_free_ports() {
    let lo = Ipv4Addr::LOCALHOST;
    let min = loop {
        let p = TcpListener::bind((lo, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if (20000..60000).contains(&p) && (p..p + 24).all(|q| TcpListener::bind((lo, q)).is_ok()) {
            break p;
        }
    };
    let foreign = TcpListener::bind((lo, min + 1)).unwrap();
    let sel = osd::portsel::PortSelect {
        explicit: None,
        min,
        max: min + 23,
        retry_count: 0,
        retry_delay: 0.0,
        addr_ports: [0, 0],
    };
    let bind = |p: [u16; 4]| {
        let binds = Binds(std::array::from_fn(|i| {
            vec![std::net::SocketAddr::from((lo, p[i]))]
        }));
        bind_all_with(&binds, 2, &Steer::Hash, 16, &ListenOpts::default())
    };
    let sets: [Vec<SocketAddr>; 4] = std::array::from_fn(|_| vec![SocketAddr::from((lo, 0))]);
    let sets: [&[SocketAddr]; 4] = std::array::from_fn(|i| sets[i].as_slice());
    let (p1, _f1) = osd::portsel::bind_with(&sel, sets, bind).unwrap();
    let (p2, _f2) = osd::portsel::bind_with(&sel, sets, bind).unwrap();
    let all: BTreeSet<u16> = p1.iter().chain(&p2).copied().collect();
    assert_eq!(all.len(), 8, "{p1:?} {p2:?}");
    assert!(!all.contains(&foreign.local_addr().unwrap().port()));
    // explicit override on taken ports: a clean error, no search
    let ex = osd::portsel::PortSelect {
        explicit: Some(p1[0]),
        ..sel
    };
    let e = osd::portsel::bind_with(&ex, sets, bind).unwrap_err();
    assert!(e.contains("explicit ports"), "{e}");
}

#[test]
fn bounded_accept_keeps_waiting_peer_in_backlog_until_its_socket_slot_returns() {
    let (ports, mut fds) = bind_free(1, &Steer::Hash, 8);
    let mut net = KNet::new(
        KCfg {
            bounded_accept: true,
            bufs: 8,
            buf_size: 4096,
            ..KCfg::default()
        },
        fds.remove(0),
    )
    .unwrap();
    let mut driver = Shared::default();
    driver.0.lock().unwrap().accept_limit = Some(1);
    let _first = TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0])).unwrap();
    let mut waiting = TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0])).unwrap();
    let start = Instant::now();
    while driver.0.lock().unwrap().accepted.is_empty() {
        net.poll(&mut driver, start.elapsed());
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "WARNING TIMEOUT first bounded accept exceeded 5s"
        );
    }
    assert!(net.accepts[0].paused);
    for _ in 0..32 {
        net.poll(&mut driver, start.elapsed());
    }
    assert_eq!(driver.0.lock().unwrap().accepted.len(), 1);
    waiting.write_all(b"queued").unwrap();
    let old = driver.0.lock().unwrap().accepted[0].0;
    net.abort_connection(old);
    driver.on_closed(old, start.elapsed());
    while driver.0.lock().unwrap().accepted.len() != 2 {
        net.poll(&mut driver, start.elapsed());
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "WARNING TIMEOUT resumed bounded accept exceeded 5s"
        );
    }
    assert!(net.accepts[0].paused);
    assert_eq!(driver.0.lock().unwrap().live.len(), 1);
}

#[test]
fn bounded_dual_family_accept_reserves_one_slot_per_armed_entry() {
    let ports = free_ports();
    let binds = Binds(ports.map(|p| {
        vec![
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), p),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), p),
        ]
    }));
    let mut fds = bind_all(&binds, 1, &Steer::Hash, 8).unwrap();
    let mut net = KNet::new(
        KCfg {
            bounded_accept: true,
            ..KCfg::default()
        },
        fds.remove(0),
    )
    .unwrap();
    let mut driver = Shared::default();
    driver.0.lock().unwrap().accept_limit = Some(1);
    let _v4 = TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0])).unwrap();
    let start = Instant::now();
    while driver.0.lock().unwrap().accepted.is_empty() {
        net.poll(&mut driver, start.elapsed());
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "WARNING TIMEOUT dual-family first accept exceeded 5s"
        );
    }
    // The IPv6 entry is first: an idle family must not reserve the only slot
    // and prevent the IPv4 connection above from being admitted.
    let _v6 = TcpStream::connect((std::net::Ipv6Addr::LOCALHOST, ports[0])).unwrap();
    for _ in 0..32 {
        net.poll(&mut driver, start.elapsed());
    }
    assert_eq!(
        driver.0.lock().unwrap().live.len(),
        1,
        "two address families must not reserve the same slot"
    );
    let old = driver.0.lock().unwrap().accepted[0].0;
    net.abort_connection(old);
    driver.on_closed(old, start.elapsed());
    while driver.0.lock().unwrap().accepted.len() < 2 {
        net.poll(&mut driver, start.elapsed());
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "WARNING TIMEOUT dual-family resumed accept exceeded 5s"
        );
    }
    assert_eq!(driver.0.lock().unwrap().live.len(), 1);
}
