// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Zero-copy SEND on a real verbs device (soft-RoCE in lab/rdma-spike/rxe-teardown-test.sh): `Core::send_bytes` posts
//! SGEs that point into a registered caller buffer (`ZcMem`) instead of copying into the send arena, and leases the buffer
//! to the send queue until the covering WR retires (`rdma::tx`, Lease). A separate SEND owner counts lease retirement;
//! the owned registration retains the underlying allocation until MR teardown.
#![cfg(all(feature = "verbs", target_os = "linux"))]

use bytes::Bytes;
use rdma::grant::SessionCap;
use rdma::verbs::{Core, CoreCfg, Device, Event, Qp, ZcMem};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

const SLOT: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(120);

fn cfg() -> CoreCfg {
    CoreCfg {
        srq_depth: 64,
        tx_slots: 8,
        max_window: 16,
        ..CoreCfg::default()
    }
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn provider_type2_mw_probe_uses_a_real_allocation() {
    let dev = device();
    assert!(dev.probe_type2_mw().expect("type-2 MW probe"));
}

/// A payload buffer: counts its release and poisons its bytes then.
struct Payload {
    data: Vec<u8>,
    released: Arc<AtomicUsize>,
}

impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for Payload {
    fn drop(&mut self) {
        self.data.fill(0xee);
        self.released.fetch_add(1, Relaxed);
    }
}

/// Tracks transport ownership separately from the registration's allocation ownership.
struct SendLease {
    data: Bytes,
    released: Arc<AtomicUsize>,
}

impl AsRef<[u8]> for SendLease {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SendLease {
    fn drop(&mut self) {
        self.released.fetch_add(1, Relaxed);
    }
}

fn byte(i: usize) -> u8 {
    (i % 251) as u8 ^ (i >> 16) as u8
}

/// A `len`-byte payload registered with `dev`; returns the bytes (sole reference), its registration and release counter.
fn registered(dev: &Arc<Device>, len: usize) -> (Bytes, Arc<ZcMem>, Arc<AtomicUsize>) {
    let data: Vec<u8> = (0..len).map(byte).collect();
    let released = Arc::new(AtomicUsize::new(0));
    let backing = Bytes::from(data);
    let zc = ZcMem::register_owned(dev, backing.clone()).expect("register");
    let b = Bytes::from_owner(SendLease {
        data: backing,
        released: released.clone(),
    });
    (b, zc, released)
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn owned_registration_retains_backing_and_checks_exact_bounds() {
    let dev = device();
    let released = Arc::new(AtomicUsize::new(0));
    let b = Bytes::from_owner(Payload {
        data: vec![0x5a; SLOT],
        released: released.clone(),
    });
    let addr = b.as_ptr() as u64;
    let reg = ZcMem::register_owned(&dev, b.clone()).expect("register owned");
    assert_eq!(reg.bytes(), SLOT as u64);
    assert_eq!(reg.regions(), 1);
    assert!(reg.lkey(addr, SLOT).is_some());
    assert!(reg.lkey(addr + SLOT as u64 - 1, 1).is_some());
    assert!(reg.lkey(addr - 1, SLOT).is_none());
    assert!(reg.lkey(addr + SLOT as u64, 1).is_none());
    assert!(reg.lkey(addr, SLOT + 1).is_none());
    assert!(reg.lkey(addr, 0).is_none());
    assert!(reg.lkey(addr, usize::MAX).is_none());
    drop(b);
    assert_eq!(
        released.load(Relaxed),
        0,
        "registration must retain the allocation"
    );
    let retained = reg.clone();
    drop(reg);
    assert_eq!(released.load(Relaxed), 0);
    drop(retained);
    assert_eq!(
        released.load(Relaxed),
        1,
        "last registration deregisters before releasing backing"
    );
    assert_eq!(
        ZcMem::register_owned(&dev, Bytes::new())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn registration_is_bound_to_one_pd_and_cannot_be_replaced() {
    let dev = device();
    let foreign_pd = device();
    let mut core = Core::new(&dev, cfg()).expect("core");
    let bytes = Bytes::from(vec![1; SLOT]);
    let foreign = ZcMem::register_owned(&foreign_pd, bytes.clone()).expect("foreign registration");
    assert_eq!(
        core.set_zero_copy(foreign, SLOT).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    let first = ZcMem::register_owned(&dev, bytes).expect("own registration");
    core.set_zero_copy(first, SLOT)
        .expect("install own registration");
    let released = Arc::new(AtomicUsize::new(0));
    let second = ZcMem::register_owned(
        &dev,
        Bytes::from_owner(Payload {
            data: vec![2; SLOT],
            released: released.clone(),
        }),
    )
    .expect("second registration");
    assert_eq!(
        core.set_zero_copy(second, SLOT).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        released.load(Relaxed),
        1,
        "refused registration releases its backing"
    );
}

fn device() -> Arc<Device> {
    let ip: IpAddr = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
        .expect("FLASHSTORE_TEST_RDMA_ADDR (local IP of a RoCEv2 device)")
        .parse()
        .expect("FLASHSTORE_TEST_RDMA_ADDR is an IP address");
    Device::open(rdma::gid_of(ip)).expect("device")
}

/// Sender and receiver core with one connected, attached QP pair: (sender core, receiver core, sender qpn, receiver qpn).
fn pair(dev: &Arc<Device>) -> (Core, Core, u32, u32) {
    let mut sc = Core::new(dev, cfg()).expect("sender core");
    let mut rc = Core::new(dev, cfg()).expect("receiver core");
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

/// 32 MiB from a registered buffer, offered from an unaligned start as the knet driver does (until refused, again on
/// `Writable`): arrives byte-exact, no send slot is used, the buffer is released exactly once and only after the last
/// byte arrived and the sender's completions retired it.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn zero_copy_send_arrives_byte_exact_and_releases_after_retirement() {
    const TOTAL: usize = 32 << 20;
    const SKIP: usize = 5; // unaligned start
    let dev = device();
    let (mut sc, mut rc, qs, qr) = pair(&dev);
    let (all, zc, released) = registered(&dev, TOTAL + SKIP);
    sc.set_zero_copy(zc, SLOT).expect("install registration");
    let mut b = all.slice(SKIP..);
    drop(all); // the leases and `b` are the only references now
    let (mut got, mut bad, mut writable) = (0usize, None, true);
    let t = Instant::now();
    let mut last_byte = None;
    loop {
        let now = t.elapsed();
        assert!(
            now < DEADLINE,
            "WARNING TIMEOUT rxe_zc exceeded {:.3}s (sent {} of {TOTAL}, got {got}, released {})",
            DEADLINE.as_secs_f64(),
            TOTAL - b.len(),
            released.load(Relaxed)
        );
        let offered = !b.is_empty();
        while std::mem::take(&mut writable) && !b.is_empty() {
            writable = sc.send_bytes(qs, &mut b) > 0;
        }
        if offered && b.is_empty() {
            // the last SENDs were just posted, no poll since: their lease must still be held
            assert_eq!(
                released.load(Relaxed),
                0,
                "released before the last SEND completed"
            );
        }
        assert_eq!(
            sc.free_tx_slots(),
            cfg().tx_slots as usize,
            "zero copy took a send slot"
        );
        sc.tick(now.as_nanos() as u64);
        rc.tick(now.as_nanos() as u64);
        sc.poll(|q, e| match e {
            Event::Writable if q == qs => writable = true,
            Event::Fault(m) => panic!("sender qp {q}: {m}"),
            _ => {}
        });
        rc.poll(|q, e| match e {
            Event::Data(d) if q == qr => {
                if bad.is_none()
                    && let Some(i) = d.iter().zip(got + SKIP..).position(|(&x, i)| x != byte(i))
                {
                    bad = Some(got + i);
                }
                got += d.len();
            }
            Event::Fault(m) => panic!("receiver qp {q}: {m}"),
            _ => {}
        });
        if got == TOTAL {
            let since = *last_byte.get_or_insert(now);
            if released.load(Relaxed) == 1 {
                eprintln!(
                    "rxe_zc: 32 MiB in {now:?}, buffer released {:?} after the last byte, zc sends {}, zc bytes {}, \
                     credit stalls {}",
                    now - since,
                    sc.stats.zc_sends,
                    sc.stats.zc_bytes,
                    sc.stats.credit_stalls
                );
                assert!(now - since < Duration::from_secs(1), "released late");
                break;
            }
        }
    }
    assert_eq!(bad, None, "stream corrupted (first bad byte)");
    assert_eq!(sc.stats.zc_bytes, TOTAL as u64);
    assert_eq!(sc.stats.zc_misses, 0);
    assert_eq!(released.load(Relaxed), 1);
    drop(sc.detach(qs).expect("attached").qp);
    drop(rc.detach(qr).expect("attached").qp);
}

/// Close / fault with zero-copy SENDs in flight: the leases leave the core with the detached QP and the buffer is
/// released only when that QP is destroyed, once. Small chunks and unregistered memory take the copy path.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn detach_keeps_leases_until_the_qp_is_destroyed() {
    let dev = device();
    let (mut sc, mut rc, qs, qr) = pair(&dev);
    let (all, zc, released) = registered(&dev, 4 << 20);
    sc.set_zero_copy(zc, SLOT).expect("install registration");
    // copy path: below the threshold, and outside the registration
    let mut small = all.slice(..1000);
    assert_eq!(sc.send_bytes(qs, &mut small), 1000);
    let mut foreign = Bytes::from(vec![1u8; 4 * SLOT]);
    let n = sc.send_bytes(qs, &mut foreign);
    assert!(n > 0 && sc.stats.zc_misses == 1 && sc.stats.zc_bytes == 0);
    // the copied SENDs arrive and their credits come back (the minimum window refused the rest of `foreign`)
    let t = Instant::now();
    let mut writable = false;
    while !writable {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "WARNING TIMEOUT rxe_zc credit return exceeded 10s"
        );
        let now = t.elapsed().as_nanos() as u64;
        sc.tick(now);
        rc.tick(now);
        rc.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "receiver qp {q}"));
        sc.poll(|q, e| match e {
            Event::Writable if q == qs => writable = true,
            Event::Fault(m) => panic!("sender qp {q}: {m}"),
            _ => {}
        });
    }
    let mut b = all.slice(SLOT..);
    drop((all, small, foreign));
    let n = sc.send_bytes(qs, &mut b);
    assert!(n >= SLOT, "credits for at least one zero-copy SEND");
    drop(b);
    assert_eq!(sc.stats.zc_bytes, n as u64);
    // no poll: the SENDs are still owned by the queue
    let det = sc.detach(qs).expect("attached");
    assert_eq!(
        released.load(Relaxed),
        0,
        "released with the QP still alive"
    );
    assert_eq!(
        sc.free_tx_slots() + det.held.slots.len(),
        cfg().tx_slots as usize
    );
    drop(det.qp); // QP destroyed (control-thread teardown in the daemon)
    assert_eq!(released.load(Relaxed), 1);
    sc.reclaim(&det.held);
    drop(rc.detach(qr).expect("attached").qp);
}
