// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Batching on a real verbs device (soft-RoCE, lab/rdma-spike/rxe-teardown-test.sh): small chunks packed into shared
//! SENDs arrive byte-exact and in order, a call's SENDs go out as one chained list (one doorbell), a header and the first
//! bytes of its payload by reference share a two-SGE SEND, receive slots are re-posted in lists, every core's CQ takes
//! its own completion vector, and completion channel events are acknowledged in batches without losing one.
#![cfg(all(feature = "verbs", target_os = "linux"))]

use bytes::Bytes;
use rdma::grant::SessionCap;
use rdma::verbs::{Core, CoreCfg, Device, Event, Qp, ZcMem};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

const SLOT: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(120);

fn cfg() -> CoreCfg {
    CoreCfg {
        srq_depth: 128,
        tx_slots: 32,
        max_window: 16,
        ..CoreCfg::default()
    }
}

fn byte(i: usize) -> u8 {
    (i % 251) as u8 ^ (i >> 12) as u8
}

fn device() -> Arc<Device> {
    let ip: IpAddr = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
        .expect("FLASHSTORE_TEST_RDMA_ADDR (local IP of a RoCEv2 device)")
        .parse()
        .expect("FLASHSTORE_TEST_RDMA_ADDR is an IP address");
    Device::open(rdma::gid_of(ip)).expect("device")
}

/// Connected, attached QP pair on two cores (sender, receiver): (sender core, receiver core, sender qpn, receiver qpn).
fn pair(dev: &Arc<Device>) -> (Core, Core, u32, u32) {
    let mut sc = Core::new(dev, cfg()).expect("sender core");
    let mut rc = Core::new(
        dev,
        CoreCfg {
            comp_vector: 1,
            ..cfg()
        },
    )
    .expect("receiver core");
    let (hs, hr) = (sc.handles(), rc.handles());
    let s = Qp::create(dev, hs, 1).expect("create QP");
    let r = Qp::create(dev, hr, 2).expect("create QP");
    let (es, er) = (s.endpoint(&hs), r.endpoint(&hr));
    s.connect(&hs, &er).expect("connect sender QP");
    r.connect(&hr, &es).expect("connect receiver QP");
    let (qs, qr) = (s.qpn(), r.qpn());
    let cap = SessionCap::new(0);
    sc.attach(s, &er, cap.acquire().unwrap())
        .expect("attach sender QP");
    rc.attach(r, &es, cap.acquire().unwrap())
        .expect("attach receiver QP");
    (sc, rc, qs, qr)
}

/// The clock the cores' grant ticks run on: one per process, so it never goes back between phases of a test.
fn clock_ns() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

/// One pass of both cores: grant ticks, completions. Returns whether the sender got `Writable` and the bytes the receiver
/// got.
fn step(sc: &mut Core, rc: &mut Core, qs: u32, qr: u32, rx: &mut Vec<u8>) -> bool {
    let now = clock_ns();
    sc.tick(now);
    rc.tick(now);
    let mut writable = false;
    sc.poll(|q, e| match e {
        Event::Writable if q == qs => writable = true,
        Event::Fault(m) => panic!("sender qp {q}: {m}"),
        _ => {}
    });
    let r0 = rc.stats;
    rc.poll(|q, e| match e {
        Event::Data(d) if q == qr => rx.extend_from_slice(d),
        Event::Fault(m) => panic!("receiver qp {q}: {m}"),
        _ => {}
    });
    // reposts leave in lists: one doorbell per pass, plus one before each credit-only SEND (no credit for an unposted
    // slot) and one per full batch of 64
    let r = rc.stats;
    let (k, d, c) = (
        r.rx_sends - r0.rx_sends,
        r.rx_doorbells - r0.rx_doorbells,
        r.credit_only - r0.credit_only,
    );
    assert!(
        d <= 1 + c + k / 64,
        "{d} receive doorbells in one pass of {k} SENDs with {c} credit-only SENDs"
    );
    writable
}

fn deadline(what: &str, t: Instant) {
    assert!(
        t.elapsed() < DEADLINE,
        "WARNING TIMEOUT rxe_batch {what} exceeded {:.3}s",
        DEADLINE.as_secs_f64()
    );
}

/// Offer `chunks` until all are taken and the receiver got `want` bytes; returns them.
fn transfer(
    sc: &mut Core,
    rc: &mut Core,
    (qs, qr): (u32, u32),
    chunks: &mut VecDeque<Bytes>,
    want: usize,
) -> Vec<u8> {
    let (t, mut rx) = (Instant::now(), Vec::with_capacity(want));
    let mut writable = true;
    while rx.len() < want {
        deadline("transfer", t);
        if std::mem::take(&mut writable) && !chunks.is_empty() {
            sc.send_chunks(qs, chunks);
        }
        writable |= step(sc, rc, qs, qr, &mut rx);
    }
    rx
}

/// Thousands of chunks smaller than a slot (a few bytes up to 400): the stream arrives byte-exact and in order, in far
/// fewer SENDs than chunks, and the receive slots are re-posted in lists.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn packed_small_chunks_arrive_byte_exact() {
    let dev = device();
    let (mut sc, mut rc, qs, qr) = pair(&dev);
    let (mut all, mut chunks) = (Vec::new(), VecDeque::new());
    for i in 0..6000usize {
        let len = 1 + (i * 37) % 400;
        let v: Vec<u8> = (0..len).map(|k| byte(all.len() + k)).collect();
        all.extend_from_slice(&v);
        chunks.push_back(Bytes::from(v));
    }
    let n = chunks.len() as u64;
    let rx = transfer(&mut sc, &mut rc, (qs, qr), &mut chunks, all.len());
    assert!(rx == all, "stream differs");
    let s = sc.stats;
    eprintln!(
        "rxe_batch packed: {} bytes in {n} chunks: {} SENDs, {} doorbells, {} credit stalls",
        s.tx_bytes, s.tx_sends, s.tx_doorbells, s.credit_stalls
    );
    assert_eq!(s.tx_chunks, n);
    assert_eq!(s.tx_bytes, all.len() as u64);
    assert!(
        s.tx_sends <= 45,
        "{} SENDs for {n} chunks: small chunks are not packed",
        s.tx_sends
    );
    assert!(s.tx_doorbells <= s.tx_sends, "more doorbells than SENDs");
    // receive side: reposts leave in lists, checked per poll pass in `step`
    drop(sc.detach(qs).expect("attached").qp);
    drop(rc.detach(qr).expect("attached").qp);
}

/// Message layout of the msgr2 frames the OSD sends: a header chunk, the payload by reference from registered memory, an
/// epilogue chunk. The header and the first payload bytes share one two-SGE SEND; the stream is exact.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn header_and_zero_copy_payload_share_a_send() {
    const MSGS: usize = 24;
    const PAY: usize = 3 * SLOT + 777;
    let dev = device();
    let (mut sc, mut rc, qs, qr) = pair(&dev);
    let heap: Vec<u8> = (0..MSGS * PAY).map(byte).collect();
    let heap = Bytes::from_owner(heap);
    let zc = ZcMem::register_owned(&dev, heap.clone()).expect("register");
    sc.set_zero_copy(zc, SLOT).expect("install registration");
    let (mut want, mut chunks) = (Vec::new(), VecDeque::new());
    for m in 0..MSGS {
        let hdr: Vec<u8> = (0..300).map(|k| (m * 7 + k) as u8).collect();
        let epi: Vec<u8> = (0..100).map(|k| (m * 11 + k) as u8 ^ 0x5a).collect();
        let pay = heap.slice(m * PAY..(m + 1) * PAY);
        want.extend_from_slice(&hdr);
        want.extend_from_slice(&pay);
        want.extend_from_slice(&epi);
        chunks.extend([Bytes::from(hdr), pay, Bytes::from(epi)]);
    }
    drop(heap);
    let rx = transfer(&mut sc, &mut rc, (qs, qr), &mut chunks, want.len());
    assert!(rx == want, "stream differs");
    let s = sc.stats;
    let msg_bytes = 300 + PAY + 100;
    let min_sends = (MSGS * msg_bytes).div_ceil(SLOT) as u64;
    eprintln!(
        "rxe_batch hdr+zc: {MSGS} messages of {msg_bytes} B: {} SENDs (>= {min_sends}), {} with two SGEs, {} zero-copy, \
         {} doorbells",
        s.tx_sends, s.tx_sge2, s.zc_sends, s.tx_doorbells
    );
    // a payload part left over by a credit stall below the threshold takes the copy path: most bytes still go by reference
    assert!(
        s.zc_bytes >= (MSGS * PAY * 3 / 4) as u64,
        "zero-copy bytes {}",
        s.zc_bytes
    );
    assert_eq!(s.zc_misses, 0);
    assert!(s.tx_sge2 > 0, "no SEND carried a header and payload bytes");
    // the stream is cut in slot-sized SENDs whatever the chunk boundaries: close to the minimum
    assert!(
        s.tx_sends <= min_sends + MSGS as u64,
        "{} SENDs, minimum {min_sends}",
        s.tx_sends
    );
    drop(sc.detach(qs).expect("attached").qp);
    drop(rc.detach(qr).expect("attached").qp);
}

/// A call that posts N SENDs rings the doorbell once: a burst of slot-sized chunks after the credit window opened.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn chained_post_of_n_sends_is_one_doorbell() {
    let dev = device();
    let (mut sc, mut rc, qs, qr) = pair(&dev);
    // open the credit window first: a stream that keeps the session busy for several grant ticks (the window grows with
    // the demand), then bursts right behind it
    let mut warm: VecDeque<Bytes> = (0..256).map(|_| Bytes::from(vec![3u8; SLOT])).collect();
    transfer(&mut sc, &mut rc, (qs, qr), &mut warm, 256 * SLOT);
    let (t, mut rx) = (Instant::now(), Vec::new());
    let mut best = (0, 0);
    let mut total = 0usize;
    while best.0 < 4 {
        deadline("chained post", t);
        let mut chunks: VecDeque<Bytes> =
            (0..8).map(|i| Bytes::from(vec![i as u8; SLOT])).collect();
        let (s0, d0) = (sc.stats.tx_sends, sc.stats.tx_doorbells);
        let taken = sc.send_chunks(qs, &mut chunks);
        total += taken;
        let (ds, dd) = (sc.stats.tx_sends - s0, sc.stats.tx_doorbells - d0);
        if ds >= 2 {
            assert_eq!(dd, 1, "{ds} SENDs of one call took {dd} doorbells");
            assert_eq!(taken, ds as usize * SLOT);
        }
        best.0 = best.0.max(ds);
        // let the credits come back before the next burst
        let before = rx.len();
        loop {
            deadline("chained post drain", t);
            step(&mut sc, &mut rc, qs, qr, &mut rx);
            if rx.len() >= total {
                break;
            }
        }
        assert_eq!(rx.len() - before, taken);
    }
    eprintln!("rxe_batch chain: up to {} SENDs in one doorbell", best.0);
    drop(sc.detach(qs).expect("attached").qp);
    drop(rc.detach(qr).expect("attached").qp);
}

/// Each core's CQ is created on its own completion vector, round robin over the device's vectors; cores on different
/// vectors exchange data.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn cores_use_their_own_completion_vectors() {
    let dev = device();
    let n = dev.comp_vectors();
    assert!(n >= 1);
    let cores: Vec<Core> = (0..n + 3)
        .map(|c| {
            Core::new(
                &dev,
                CoreCfg {
                    comp_vector: c,
                    srq_depth: 16,
                    tx_slots: 4,
                    ..cfg()
                },
            )
            .expect("core")
        })
        .collect();
    for (c, core) in cores.iter().enumerate() {
        assert_eq!(core.comp_vector(), c as u32 % n);
    }
    eprintln!(
        "rxe_batch vectors: device has {n}, {} cores placed",
        cores.len()
    );
    // pair() puts sender on vector 0 and receiver on vector 1 (the same one when the device has a single vector)
    let (mut sc, mut rc, qs, qr) = pair(&dev);
    assert_eq!(rc.comp_vector(), 1 % n);
    let mut chunks: VecDeque<Bytes> = [Bytes::from(vec![9u8; 5000])].into();
    let rx = transfer(&mut sc, &mut rc, (qs, qr), &mut chunks, 5000);
    assert!(rx.iter().all(|&b| b == 9));
    drop(sc.detach(qs).expect("attached").qp);
    drop(rc.detach(qr).expect("attached").qp);
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn poll(fds: *mut PollFd, nfds: u64, timeout: i32) -> i32;
}

/// Wait until the completion channel of `c` is readable.
fn wait_readable(c: &Core, t: Instant) {
    let mut p = PollFd {
        fd: c.fd(),
        events: 1, // POLLIN
        revents: 0,
    };
    // SAFETY: one valid pollfd
    let n = unsafe { poll(&mut p, 1, 5000) };
    assert!(
        n == 1,
        "WARNING TIMEOUT rxe_batch completion event exceeded 5s (after {:?})",
        t.elapsed()
    );
}

/// 100 armed wake-ups: each yields exactly one event, none is lost, the acknowledgements go out in batches (the CQ is
/// destroyed afterwards without blocking: every read event was acknowledged).
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn completion_events_are_acknowledged_in_batches() {
    const WAKES: usize = 100;
    let dev = device();
    let (mut sc, mut rc, qs, qr) = pair(&dev);
    let (t, mut rx) = (Instant::now(), Vec::new());
    for i in 0..WAKES {
        deadline("wake", t);
        // quiet both cores, then arm the receiver and send one small chunk
        while sc.poll(|_, _| ()) + rc.poll(|_, _| ()) > 0 {}
        rc.arm().expect("arm");
        let before = rx.len();
        let msg = Bytes::from(vec![i as u8; 32]);
        let mut chunks: VecDeque<Bytes> = [msg].into();
        while !chunks.is_empty() {
            deadline("wake send", t);
            sc.send_chunks(qs, &mut chunks);
            step(&mut sc, &mut rc, qs, qr, &mut rx);
        }
        // `step` above may already have consumed the data; the event is queued either way (armed before the SEND)
        wait_readable(&rc, t);
        assert_eq!(rc.ack(), 1, "wake {i}: one event per arming");
        while rx.len() < before + 32 {
            deadline("wake receive", t);
            step(&mut sc, &mut rc, qs, qr, &mut rx);
        }
    }
    assert_eq!(rc.stats.wakes, WAKES as u64);
    assert_eq!(
        rc.stats.wake_acks,
        (WAKES / 32) as u64,
        "events are acknowledged 32 at a time"
    );
    drop(sc.detach(qs).expect("attached").qp);
    drop(rc.detach(qr).expect("attached").qp);
    drop(rc); // the 4 events still unacknowledged are acknowledged before the CQ is destroyed
    drop(sc);
}
