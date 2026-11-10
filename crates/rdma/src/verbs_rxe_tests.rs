// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Teardown and fault paths of [`Core`] on a real verbs device (soft-RoCE in lab/rdma-spike/rxe-teardown-test.sh,
//! `#[ignore]`d; FLASHSTORE_TEST_RDMA_ADDR = local IP of a RoCEv2 device). Fault injection uses the core's test-only hooks.
use super::*;

#[test]
fn native_bad_wr_prefix_requires_an_aligned_in_list_pointer() {
    let storage = [0u64; 128];
    let first = storage.as_ptr().cast::<u8>();
    for (offset, expected) in [(0, 0), (32, 2), (1008, 63), (1, -1), (1024, -1)] {
        // SAFETY: the helper only validates numeric addresses; it does not
        // dereference either pointer, including deliberately malformed ones.
        assert_eq!(
            unsafe {
                ffi::rv_posted_prefix(first.cast(), 16, 64, first.wrapping_add(offset).cast())
            },
            expected
        );
    }
    // SAFETY: numeric validation only; neither pointer is dereferenced.
    assert_eq!(
        unsafe { ffi::rv_posted_prefix(first.cast(), 16, 64, std::ptr::null()) },
        -1
    );
    // SAFETY: numeric validation only, including this address below the list.
    assert_eq!(
        unsafe { ffi::rv_posted_prefix(first.cast(), 16, 64, first.wrapping_sub(1).cast()) },
        -1
    );
}

#[test]
fn send_only_receive_requires_the_immediate_credit_field() {
    assert!(valid_stream_receive(1));
    for flags in [0, 2, 3] {
        assert!(
            !valid_stream_receive(flags),
            "plain SEND or remote invalidation cannot enter the credited stream"
        );
    }
}

fn device() -> Arc<Device> {
    let ip: std::net::IpAddr = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
        .expect("FLASHSTORE_TEST_RDMA_ADDR (local IP of a RoCEv2 device)")
        .parse()
        .expect("FLASHSTORE_TEST_RDMA_ADDR is an IP address");
    Device::open(crate::gid_of(ip)).expect("device")
}

#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_window_arena_registration_checks_ranges() {
    // RXE may require writable host pages for pinning even when the MR grants
    // no local writes. Leak this initialized fixture to meet the permanent
    // mapping contract, including if provider deregistration fails.
    let arena = Box::leak(vec![0x42u8; 8192].into_boxed_slice());
    let dev = device();
    let start = arena.as_ptr() as u64;
    // SAFETY: this initialized allocation is mapped until process exit.
    let registration = unsafe { ZcMem::register_read_windows(&dev, &[(start, 8192)]) }.unwrap();
    assert_eq!(registration.bytes(), 8192);
    assert_eq!(registration.regions(), 1);
    assert!(registration.lkey(start + 4096, 4096).is_some());
    assert!(registration.lkey(start + 4096, 4097).is_none());
    // SAFETY: both ranges are in the same permanent allocation.
    assert!(
        unsafe { ZcMem::register_read_windows(&dev, &[(start, 4096), (start + 1, 4096)]) }.is_err()
    );
}

fn cfg() -> CoreCfg {
    CoreCfg {
        srq_depth: 64,
        tx_slots: 8,
        max_window: 16,
        ..CoreCfg::default()
    }
}

/// SQ capacity, not a grant-policy timer or fresh receive, resumes an owed
/// credit SEND. Synthetic ordinary CQ retirement makes the ordering exact.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_sq_retirement_resumes_deferred_credit_return() {
    let dev = device();
    let (mut sender, _receiver, qs, _) = linked(&dev);
    let c = sender.conns.get_mut(&qs).unwrap();
    let sid = c.sid;
    // Admission extras are already owed; no application output is pending.
    assert!(sender.pool.due(sid));
    let mut last = 0;
    while !c.tx.sq.full() {
        last = c.tx.sq.push_signaled(crate::ring::NO_SLOT);
    }
    let epoch = c.epoch;
    c.touched = true;
    sender.touched.push(qs);
    sender.flush_credits();
    assert!(sender.pool.due(sid));
    assert!(sender.touched.is_empty());
    assert!(!sender.conns[&qs].tx.blocked);

    // No real WR was posted for the synthetic occupied positions, so the CQ
    // is empty. The existing poll-result hook delivers this exact retirement.
    sender.wc[0] = ffi::Wc {
        wr_id: wr_id(epoch, last),
        qp_num: qs,
        ..Default::default()
    };
    sender.cq_error = Some(1);
    let before = sender.stats.credit_only;
    sender.poll(|_, event| assert!(!matches!(event, Event::Fault(_))));
    assert_eq!(sender.stats.credit_only - before, 1);
    assert!(!sender.pool.due(sid));
}

/// A repeated connect must not erase the prior RTR/SRQ ownership proof.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_setup_default_stays_send_only_and_reconnect_preserves_rtr() {
    let dev = device();
    let before = (leaked_cores(), teardown_failures());
    let (mut sc, mut rc) = (
        Core::new(&dev, cfg()).unwrap(),
        Core::new(&dev, cfg()).unwrap(),
    );
    let (hs, hr) = (sc.handles(), rc.handles());
    let (s, r) = (
        Qp::create(&dev, hs, 41).unwrap(),
        Qp::create(&dev, hr, 42).unwrap(),
    );
    let (es, er) = (s.endpoint(&hs), r.endpoint(&hr));
    #[cfg(feature = "memory-windows")]
    {
        assert!(s.local_read_limits().is_none());
        assert_eq!(
            s.connect_with_reads(&hs, &er, dev.read_limits().unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert!(!s.connected.get());
    }
    s.connect(&hs, &er).unwrap();
    r.connect(&hr, &es).unwrap();
    assert_eq!(
        s.connect(&hs, &er).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert!(s.connected.get());
    #[cfg(feature = "memory-windows")]
    for qp in [&s, &r] {
        assert_eq!(qp.read_depths(), ReadDepths::default());
        assert_eq!(qp.provider_read_depths().unwrap(), ReadDepths::default());
    }
    let cap = crate::grant::SessionCap::new(0);
    sc.attach(s, &er, cap.acquire().unwrap()).unwrap();
    rc.attach(r, &es, cap.acquire().unwrap()).unwrap();
    drop((sc, rc));
    assert_eq!((leaked_cores(), teardown_failures()), before);
}

/// Query the provider after asymmetric setup: a source-only peer consumes no
/// outgoing READ resources, and the reader cannot request more than its SQ.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_setup_programs_asymmetric_depths_bounded_by_sq() {
    let dev = device();
    let before = (leaked_cores(), teardown_failures());
    let caps = dev.read_limits().unwrap();
    assert!(caps.initiator >= 2 && caps.responder >= 2 && caps.max_sge > 0);
    let mut reader_cfg = cfg();
    reader_cfg.sq_depth = 2;
    let (mut reader, mut source) = (
        Core::new(&dev, reader_cfg).unwrap(),
        Core::new(&dev, cfg()).unwrap(),
    );
    let (hr, hs) = (reader.handles(), source.handles());
    let (r, s) = (
        Qp::create_for_reads(&dev, hr, 43).unwrap(),
        Qp::create_for_reads(&dev, hs, 44).unwrap(),
    );
    assert_eq!(r.local_read_limits(), Some(caps));
    let (er, es) = (r.endpoint(&hr), s.endpoint(&hs));
    let source_caps = ReadLimits {
        initiator: 0,
        ..caps
    };
    let reader_caps = ReadLimits {
        initiator: 2,
        responder: 0,
        ..caps
    };
    let rd = r.connect_with_reads(&hr, &es, source_caps).unwrap();
    let sd = s.connect_with_reads(&hs, &er, reader_caps).unwrap();
    assert_eq!((rd.outgoing(), rd.incoming()), (2, 0));
    assert_eq!((sd.outgoing(), sd.incoming()), (0, 2));
    for (qp, expected) in [(&r, rd), (&s, sd)] {
        assert_eq!(qp.read_depths(), expected);
        let actual = qp.provider_read_depths().unwrap();
        // Providers may round a nonzero requested depth up; zero stays disabled.
        for (actual, requested, bound) in [
            (actual.outgoing(), expected.outgoing(), caps.initiator),
            (actual.incoming(), expected.incoming(), caps.responder),
        ] {
            if requested == 0 {
                assert_eq!(actual, 0);
            } else {
                assert!(actual >= requested && u32::from(actual) <= bound);
            }
        }
    }
    assert_eq!(
        r.connect_with_reads(&hr, &es, source_caps)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert!(r.connected.get());
    assert_eq!(r.read_depths(), rd);
    let cap = crate::grant::SessionCap::new(0);
    let (qr, qs) = (r.qpn(), s.qpn());
    reader.attach(r, &es, cap.acquire().unwrap()).unwrap();
    source.attach(s, &er, cap.acquire().unwrap()).unwrap();
    assert_eq!(held_and_lent(&mut reader, &mut source, qr, qs, 4096), 4096);
    drop((reader, source));
    assert_eq!((leaked_cores(), teardown_failures()), before);
}

/// A core whose owner could not confirm the retire (control thread hung) is leaked: a QP the control thread still holds
/// on its CQ/SRQ is destroyed later without touching freed memory, and nothing counts as a refused destroy.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_leaked_core_outlives_a_qp_of_the_control_thread() {
    let dev = device();
    let core = Core::new(&dev, cfg()).expect("core");
    // stands for a pooled QP of a control thread that did not answer the retire
    let qp = Qp::create(&dev, core.handles(), 1).expect("qp");
    let (leaked, failures) = (leaked_cores(), teardown_failures());
    core.leak("test: retire not confirmed");
    assert_eq!(leaked_cores(), leaked + 1);
    qp.destroy()
        .expect("the CQ/SRQ the QP uses are still allocated");
    assert_eq!(teardown_failures(), failures);
}

/// A core with `n` attached connections (QPs in INIT: the fault paths need no traffic); returns the core, the sorted
/// QPNs and the endpoint the connections were attached towards.
fn core_with(dev: &Arc<Device>, n: u32) -> (Core, Vec<u32>, Endpoint) {
    let mut core = Core::new(dev, cfg()).expect("core");
    let cap = crate::grant::SessionCap::new(0);
    let peer = Qp::create(dev, core.handles(), 99).expect("peer qp");
    let peer_ep = peer.endpoint(&core.handles());
    drop(peer);
    let mut qpns = Vec::new();
    for psn in 0..n {
        let qp = Qp::create(dev, core.handles(), psn + 1).expect("qp");
        qpns.push(qp.qpn());
        core.attach(qp, &peer_ep, cap.acquire().unwrap())
            .expect("attach");
    }
    qpns.sort_unstable();
    (core, qpns, peer_ep)
}

struct ShutdownLease {
    bytes: Bytes,
    released: Arc<std::sync::atomic::AtomicUsize>,
}

impl AsRef<[u8]> for ShutdownLease {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ShutdownLease {
    fn drop(&mut self) {
        self.released
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Both direct shutdown and explicit core retention must hand SEND owners to the QP before dropping the SQ.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shutdown_retains_send_owners_when_qp_destroy_is_uncertain() {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let dev = device();
    for (fail, retain_core) in [(false, false), (true, false), (false, true), (true, true)] {
        let (mut core, qpns, _) = core_with(&dev, 1);
        let bytes = Bytes::from(vec![0x5a; 4096]);
        let reg = ZcMem::register_owned(&dev, bytes.clone()).expect("register source");
        let registration = Arc::downgrade(&reg);
        core.set_zero_copy(reg, 4096).expect("install registration");
        let released = Arc::new(AtomicUsize::new(0));
        let c = core.conns.get_mut(&qpns[0]).unwrap();
        c.tx.sq.push_zc(true);
        c.tx.sq.lease(Bytes::from_owner(ShutdownLease {
            bytes,
            released: released.clone(),
        }));
        c.qp.destroy_error = fail.then_some(5);
        let failures = teardown_failures();
        if retain_core {
            core.leak("test: retain core after control shutdown failure");
        } else {
            drop(core);
        }
        assert_eq!(
            released.load(Relaxed),
            usize::from(!fail),
            "transport lease: fail={fail}, retained={retain_core}"
        );
        assert_eq!(
            registration.upgrade().is_some(),
            fail || retain_core,
            "MR owner follows uncertain QP retirement"
        );
        assert_eq!(teardown_failures(), failures + u64::from(fail));
    }
}

/// Real provider refusal: a control QP still references the core's CQ/SRQ. Its arenas must outlive the core object.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shutdown_preserves_arenas_used_by_a_control_qp() {
    let dev = device();
    let core = Core::new(&dev, cfg()).expect("core");
    let qp = Qp::create(&dev, core.handles(), 1).expect("control qp");
    let references = Arc::strong_count(&dev);
    let failures = teardown_failures();
    drop(core);
    assert_eq!(
        Arc::strong_count(&dev),
        references,
        "both retained arenas keep their device owners"
    );
    assert_eq!(
        teardown_failures(),
        failures + 2,
        "provider refuses both SRQ and CQ destruction"
    );
    qp.destroy()
        .expect("control QP still has valid provider resources");
}

/// Inject only the returned deregistration error after actual provider cleanup, then check that ownership is retained.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shutdown_retains_arena_backing_on_uncertain_deregistration() {
    let dev = device();
    for fail in [false, true] {
        let references = Arc::strong_count(&dev);
        let mut arena = Arena::new(&dev, 1, 4096).expect("arena");
        arena.dereg_error = fail.then_some(5);
        let failures = teardown_failures();
        drop(arena);
        assert_eq!(Arc::strong_count(&dev), references + usize::from(fail));
        assert_eq!(teardown_failures(), failures + u64::from(fail));
    }
}

/// Faults reported by one poll, by QPN.
fn faults(core: &mut Core) -> Vec<u32> {
    let mut f = Vec::new();
    core.poll(|q, e| {
        if let Event::Fault(_) = e {
            f.push(q);
        }
    });
    f.sort_unstable();
    f
}

/// A broken core attaches no new connection; then the connections are detached (QPs destroyed before the core).
fn refuses_attach_and_detach(dev: &Arc<Device>, mut core: Core, qpns: Vec<u32>, peer: Endpoint) {
    let qp = Qp::create(dev, core.handles(), 50).expect("qp");
    let cap = crate::grant::SessionCap::new(0);
    assert!(core.attach(qp, &peer, cap.acquire().unwrap()).is_err());
    for q in qpns {
        drop(core.detach(q));
    }
}

/// Receive slots lost to the SRQ (a failed post) fault every connection of the core once, loudly and counted; the core
/// attaches no new connection (its credits would not be backed).
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_lost_receive_slots_fault_every_connection() {
    let dev = device();
    let (mut core, qpns, peer) = core_with(&dev, 3);
    assert!(faults(&mut core).is_empty());
    core.inject_rx_post_failure();
    assert_eq!(faults(&mut core), qpns);
    assert!(faults(&mut core).is_empty(), "reported once");
    assert_eq!(core.stats.rx_post_failures, 1);
    assert!(
        core.broken()
            .is_some_and(|w| w.contains("receive slots lost"))
    );
    refuses_attach_and_detach(&dev, core, qpns, peer);
}

/// A fatal CQ/SRQ/device async event of the device: every connection of the core faults once, the CQ is not polled
/// any more, no new attach.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_fatal_device_event_faults_every_connection() {
    let dev = device();
    let (mut core, qpns, peer) = core_with(&dev, 2);
    assert!(faults(&mut core).is_empty());
    dev.fatal.store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(faults(&mut core), qpns);
    assert!(faults(&mut core).is_empty(), "reported once");
    assert!(core.broken().is_some_and(|w| w.contains("fatal RDMA")));
    refuses_attach_and_detach(&dev, core, qpns, peer);
}

/// A CQ poll error loses completions: every connection of the core faults once, counted, no new attach.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_cq_poll_error_faults_every_connection() {
    let dev = device();
    let (mut core, qpns, peer) = core_with(&dev, 2);
    core.inject_cq_error(-5);
    assert_eq!(faults(&mut core), qpns);
    assert!(faults(&mut core).is_empty(), "reported once");
    assert_eq!(core.stats.cq_errors, 1);
    assert!(core.broken().is_some_and(|w| w.contains("ibv_poll_cq")));
    refuses_attach_and_detach(&dev, core, qpns, peer);
}

/// Two cores with one connected, attached QP pair; returns (sender core, receiver core, sender QPN, receiver QPN).
pub(super) fn linked(dev: &Arc<Device>) -> (Core, Core, u32, u32) {
    let mut sc = Core::new(dev, cfg()).expect("sender core");
    let mut rc = Core::new(dev, cfg()).expect("receiver core");
    let (qs, qr) = connect_pair(dev, &mut sc, &mut rc, 1);
    (sc, rc, qs, qr)
}

/// [`linked`] with negotiated READ depths on both QPs (spec rdma-read-offer.md):
/// the receiver may post READs, the sender answers them.
#[cfg(all(feature = "gpu", feature = "memory-windows"))]
fn linked_with_reads(dev: &Arc<Device>, want: u8) -> (Core, Core, u32, u32) {
    let mut sc = Core::new(dev, cfg()).expect("sender core");
    let mut rc = Core::new(dev, cfg()).expect("receiver core");
    let limits = dev.read_limits().expect("device READ limits");
    let depths = limits.negotiate(limits);
    assert!(
        depths.outgoing() >= want,
        "device offers {} READs",
        depths.outgoing()
    );
    let (hs, hr) = (sc.handles(), rc.handles());
    // The sender answers the receiver's READs: it is the READ responder.
    let s = Qp::create_read_responder(dev, hs, 1).expect("sender qp");
    let r = Qp::create(dev, hr, 2).expect("receiver qp");
    let (es, er) = (s.endpoint(&hs), r.endpoint(&hr));
    s.connect_with_read_depths(&hs, &er, depths)
        .expect("connect sender");
    r.connect_with_read_depths(&hr, &es, depths)
        .expect("connect receiver");
    // A READ is answered only when the responder's max_dest_rd_atomic is set
    // (rxe: RESPST_ERR_TOO_MANY_RDMA_ATM_REQ -> REM_INV_REQ). Assert what the
    // provider really programmed, not what we asked for.
    for (role, qp) in [("sender", &s), ("receiver", &r)] {
        let got = qp.provider_read_depths().expect("provider READ depths");
        assert!(
            got.outgoing() >= want && got.incoming() >= want,
            "{role} QP programmed outgoing={} incoming={}, want {want}",
            got.outgoing(),
            got.incoming()
        );
    }
    let (qs, qr) = (s.qpn(), r.qpn());
    let cap = crate::grant::SessionCap::new(0);
    sc.attach(s, &er, cap.acquire().unwrap())
        .expect("attach sender");
    rc.attach(r, &es, cap.acquire().unwrap())
        .expect("attach receiver");
    (sc, rc, qs, qr)
}

/// A connected QP pair between `sc` and `rc`, attached to both; returns (sender QPN, receiver QPN).
fn connect_pair(dev: &Arc<Device>, sc: &mut Core, rc: &mut Core, psn: u32) -> (u32, u32) {
    let (hs, hr) = (sc.handles(), rc.handles());
    let s = Qp::create(dev, hs, psn).expect("sender qp");
    let r = Qp::create(dev, hr, psn + 1).expect("receiver qp");
    let (es, er) = (s.endpoint(&hs), r.endpoint(&hr));
    s.connect(&hs, &er).expect("connect sender");
    r.connect(&hr, &es).expect("connect receiver");
    let (qs, qr) = (s.qpn(), r.qpn());
    let cap = crate::grant::SessionCap::new(0);
    sc.attach(s, &er, cap.acquire().unwrap())
        .expect("attach sender");
    rc.attach(r, &es, cap.acquire().unwrap())
        .expect("attach receiver");
    (qs, qr)
}

/// The receiver pauses, the sender sends `n` bytes, the receiver holds them and lends them; returns the bytes lent.
fn held_and_lent(sc: &mut Core, rc: &mut Core, qs: u32, qr: u32, n: usize) -> usize {
    rc.pause(qr);
    let data = vec![7u8; n];
    let mut sent = 0;
    let t = std::time::Instant::now();
    while rc.held(qr) == 0 || sent < n {
        assert!(
            t.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT rxe held data exceeded 10s (sent {sent} of {n}, held {})",
            rc.held(qr)
        );
        if sent < n {
            sent += sc.send(qs, &data[sent..]);
        }
        sc.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender qp {q} faulted"));
        rc.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "receiver qp {q} faulted"));
    }
    rc.lend(qr, usize::MAX, 64, |_, _| {})
}

/// The owner ends the lend once its borrower is done, then detaches: every held slot goes back to the SRQ, the core
/// stays usable.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_detach_after_unlend_returns_every_slot() {
    let dev = device();
    let (mut sc, mut rc, qs, qr) = linked(&dev);
    assert!(held_and_lent(&mut sc, &mut rc, qs, qr, 3 * 4096) > 0);
    rc.unlend(qr);
    drop(rc.detach(qr));
    assert_eq!(rc.stats.rx_withheld, 0);
    assert!(rc.broken().is_none());
    drop(sc.detach(qs));
}

/// Detach with a lend still open (owner bug): debug builds stop at the assertion; release builds never re-post the lent
/// slots (a borrower may still read them) and break the core loudly.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
#[cfg_attr(debug_assertions, should_panic(expected = "lent bytes"))]
fn rxe_detach_with_an_open_lend_never_reposts_the_lent_slots() {
    let dev = device();
    let (mut sc, mut rc, qs, qr) = linked(&dev);
    assert!(held_and_lent(&mut sc, &mut rc, qs, qr, 3 * 4096) > 0);
    drop(rc.detach(qr));
    assert!(rc.stats.rx_withheld > 0);
    assert!(rc.broken().is_some_and(|w| w.contains("open lend")));
    drop(sc.detach(qs));
}

/// RNR NAKs the device sent and received so far (soft-RoCE / mlx5 `hw_counters` whose name contains "rnr").
fn rnr_naks(dev: &Device) -> u64 {
    let dir = format!("/sys/class/infiniband/{}/ports/1/hw_counters", dev.name());
    let mut n = 0;
    let mut seen = 0;
    for e in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{dir}: {e}")) {
        let e = e.expect("counter entry");
        if e.file_name().to_string_lossy().contains("rnr") {
            seen += 1;
            n += std::fs::read_to_string(e.path())
                .expect("counter")
                .trim()
                .parse::<u64>()
                .expect("counter value");
        }
    }
    assert!(seen > 0, "{dir}: no RNR counters");
    n
}

fn granted(core: &mut Core, qpn: u32) -> u32 {
    let sid = core.conns[&qpn].sid;
    core.pool.credits(sid).granted()
}

fn avail(core: &mut Core, qpn: u32) -> u32 {
    let sid = core.conns[&qpn].sid;
    core.pool.credits(sid).avail()
}

/// One pass of both cores; `tick`: the grant policy runs (a 10 ms step of the synthetic clock). Returns the faults.
fn pump(sc: &mut Core, rc: &mut Core, now: &mut u64, tick: bool) -> Vec<(u32, String)> {
    let mut f = Vec::new();
    if tick {
        *now += TICK.as_nanos() as u64;
        sc.tick(*now);
        rc.tick(*now);
    }
    for c in [&mut *sc, &mut *rc] {
        c.poll(|q, e| {
            if let Event::Fault(w) = e {
                f.push((q, w));
            }
        });
    }
    f
}

/// Pump both cores (no tick) until nothing of `sc`'s data and of `rc`'s credit returns is on the wire any more: the
/// grant policy observes demand per tick, and a tick that fires while SENDs are still in flight (the device delivers
/// asynchronously) sees fewer arrivals than the peer sent, so the synthetic clock must only advance on a settled wire.
/// `rc` sends nothing but zero-length credit SENDs in these tests. 10 s bound (device-local delivery).
fn settle(sc: &mut Core, rc: &mut Core, now: &mut u64) -> Vec<(u32, String)> {
    let t = std::time::Instant::now();
    let mut f = Vec::new();
    loop {
        f.extend(pump(sc, rc, now, false));
        if sc.stats.tx_bytes == rc.stats.rx_bytes
            && sc.stats.rx_sends == rc.stats.credit_only + rc.stats.tx_sends
        {
            return f;
        }
        assert!(
            t.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT rxe wire settle exceeded 10s (data {} of {} bytes, credit SENDs {} of {})",
            rc.stats.rx_bytes,
            sc.stats.tx_bytes,
            sc.stats.rx_sends,
            rc.stats.credit_only
        );
    }
}

/// Teardown under load: the receiver detaches session B while B's peer still holds a large window and keeps sending
/// into the shared SRQ (B's QP is not destroyed yet). B's credits stay reserved: the pool does not lend them to session
/// A, so A's peer and B's peer together never find the SRQ empty (no RNR NAK on the device, no fault). After the
/// destroy and a CQ drain they are released.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_detached_session_credits_stay_reserved_until_its_qp_is_destroyed() {
    const DEPTH: u32 = 48;
    let dev = device();
    let mut sc = Core::new(
        &dev,
        CoreCfg {
            srq_depth: 64,
            slot: crate::MIN_SLOT,
            tx_slots: 256,
            max_window: 16,
            ..CoreCfg::default()
        },
    )
    .expect("sender core");
    let mut rc = Core::new(
        &dev,
        CoreCfg {
            srq_depth: DEPTH,
            slot: crate::MIN_SLOT,
            tx_slots: 8,
            max_window: 40,
            ..CoreCfg::default()
        },
    )
    .expect("receiver core");
    let (events, last_wqe) = std::sync::mpsc::channel();
    let _events = AsyncEvents::start(
        dev.clone(),
        move |q| {
            let _ = events.send(q);
        },
        || {},
    )
    .expect("async events");
    let (sa, ra) = connect_pair(&dev, &mut sc, &mut rc, 1);
    let (sb, rb) = connect_pair(&dev, &mut sc, &mut rc, 3);
    let data = vec![5u8; 1 << 20];
    let mut now = 0;
    let mut faults = Vec::new();
    // 1. B streams until the receiver lent it a large window
    let mut i = 0;
    while granted(&mut rc, rb) < 32 {
        i += 1;
        assert!(
            i < 5000,
            "B's window did not grow: {}",
            granted(&mut rc, rb)
        );
        sc.send(sb, &data);
        faults.extend(settle(&mut sc, &mut rc, &mut now));
        faults.extend(pump(&mut sc, &mut rc, &mut now, true));
    }
    // quiet, no tick (an idle tick would take B's window back): B's peer holds its whole window again
    for _ in 0..200 {
        faults.extend(pump(&mut sc, &mut rc, &mut now, false));
    }
    let b_window = avail(&mut sc, sb);
    // 2. the receiver detaches B; its QP lives on (destroy pending on the control thread)
    let det = rc.detach(rb).expect("attached");
    assert_eq!(det.held.credits, rc.pool.reserved());
    assert!(
        det.held.credits >= b_window,
        "B's peer holds {b_window}, reserved {}",
        det.held.credits
    );
    // 3. A streams: the pool lends it what is free, never B's reserved credits (no tick: every window of arrivals makes
    // A credit-blocked, demand growth up to what is free; without the reservation A grows into B's credits)
    for _ in 0..2000 {
        sc.send(sa, &data);
        faults.extend(pump(&mut sc, &mut rc, &mut now, false));
    }
    for _ in 0..200 {
        faults.extend(pump(&mut sc, &mut rc, &mut now, false));
    }
    let a_window = avail(&mut sc, sa);
    assert!(
        a_window + det.held.credits <= DEPTH,
        "A was lent B's reserved credits: A {a_window} + B {} > {DEPTH}",
        det.held.credits
    );
    // 4. both peers spend every credit while the receiver does not poll: every SEND must find a posted slot
    let naks = rnr_naks(&dev);
    for _ in 0..64 {
        sc.send(sa, &data);
        sc.send(sb, &data);
        sc.poll(|q, e| {
            if let Event::Fault(w) = e {
                faults.push((q, w));
            }
        });
    }
    // rnr_retry 6 at a 0.64 ms timer: an RNR would exhaust its retries well within this
    std::thread::sleep(std::time::Duration::from_millis(200));
    let naks = rnr_naks(&dev) - naks;
    for _ in 0..200 {
        faults.extend(pump(&mut sc, &mut rc, &mut now, false));
    }
    diag::diag!(
        "RESERVE B window {b_window} reserved {} A window {a_window} depth {DEPTH} rnr naks {naks} faults {faults:?}",
        det.held.credits
    );
    assert_eq!(
        naks, 0,
        "RNR NAKs while B's QP was detached but not destroyed"
    );
    assert!(faults.is_empty(), "faults: {faults:?}");
    // 5. teardown: ERR, last-WQE event, CQ drain, destroy; only then the credits come back
    let reserved = det.held.credits;
    let mut qp = det.qp;
    assert!(
        qp.to_err().expect("to ERR"),
        "connected: wait for the event"
    );
    wait_last_wqe(&last_wqe, qp.qpn());
    rc.quiesced(qp, det.held);
    assert_eq!(rc.pool.reserved(), reserved, "reserved until destroyed");
    faults.extend(pump(&mut sc, &mut rc, &mut now, false));
    let d = rc.drained().expect("drained by a pass that emptied the CQ");
    d.qp.destroy().expect("destroy");
    assert_eq!(rc.pool.reserved(), reserved);
    rc.reclaim(&d.held);
    assert_eq!(rc.pool.reserved(), 0);
    assert!(faults.is_empty(), "faults: {faults:?}");
    drop(rc.detach(ra));
    for q in [sa, sb] {
        drop(sc.detach(q));
    }
}

/// The device reports the port's active MTU in bytes (`FLASHSTORE_TEST_RDMA_MTU`: expected value, set by
/// lab/rdma-spike/rxe-teardown-test.sh per netdev MTU); the QP pair connects at it, a peer record without MTU only at 4096.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR, FLASHSTORE_TEST_RDMA_MTU"]
fn rxe_active_mtu_matches_the_netdev() {
    let want: u32 = std::env::var("FLASHSTORE_TEST_RDMA_MTU")
        .expect("FLASHSTORE_TEST_RDMA_MTU")
        .parse()
        .expect("FLASHSTORE_TEST_RDMA_MTU is a number");
    let dev = device();
    assert_eq!(dev.active_mtu(), want);
    let core = Core::new(&dev, cfg()).expect("core");
    let h = core.handles();
    let (s, r) = (
        Qp::create(&dev, h, 1).expect("qp"),
        Qp::create(&dev, h, 2).expect("qp"),
    );
    let (es, er) = (s.endpoint(&h), r.endpoint(&h));
    assert_eq!(es.mtu, want);
    // both ends at the smaller of the two: here the same device, so the port's MTU
    s.connect(&h, &er).expect("connect sender");
    r.connect(&h, &es).expect("connect receiver");
    // an older peer record (no MTU) is only usable on a 4096 port
    let legacy = Endpoint { mtu: 0, ..er };
    let t = Qp::create(&dev, h, 3).expect("qp");
    assert_eq!(t.connect(&h, &legacy).is_ok(), want >= 4096);
    for q in [s, r, t] {
        q.destroy().expect("destroy");
    }
}

/// `ip addr <op> <addr>/32 dev <netdev>` (root; the test netdev of lab/rdma-spike/rxe-teardown-test.sh).
fn ip_addr(op: &str, addr: std::net::IpAddr, netdev: &str) {
    let st = std::process::Command::new("ip")
        .args(["addr", op, &format!("{addr}/32"), "dev", netdev])
        .status()
        .expect("run ip");
    assert!(st.success(), "ip addr {op} {addr} dev {netdev}: {st}");
}

/// Wait until the GID lookup of `dev` is present (`want_ok`: returns its index) or gone (`AddrNotAvailable`); the
/// kernel updates the GID table from a work queue after an address change. 10 s bound.
fn wait_gid(dev: &Device, want_ok: bool) -> Option<u32> {
    let t = std::time::Instant::now();
    loop {
        match dev.gid_index() {
            Ok(i) if want_ok => return Some(i),
            Err(e) if !want_ok => {
                assert_eq!(e.kind(), io::ErrorKind::AddrNotAvailable, "{e}");
                return None;
            }
            _ => {}
        }
        assert!(
            t.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT rxe GID table update exceeded 10s (want present={want_ok})"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// GID table index of placeholder address `b` (a device opened by its GID); the kernel adds it from a work queue. 10 s
/// bound.
fn placeholder_gid_index(b: std::net::IpAddr) -> u32 {
    let t = std::time::Instant::now();
    loop {
        if let Ok(d) = Device::open(crate::gid_of(b)) {
            return d.gid_index().expect("placeholder GID index");
        }
        assert!(
            t.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT rxe placeholder GID {b} exceeded 10s"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Finding F2 (doc/perf/rdma-fault-20261022.md): the data address is removed and re-added (netplan apply, flush, bond
/// failover) and comes back at another GID table index; the slot it had is empty afterwards. A device opened before
/// sees the GID gone while the address is away (connects refused: `AddrNotAvailable`) and connects new QPs again
/// afterwards, at the new index; data flows. Needs root and FLASHSTORE_TEST_RDMA_DEV (the netdev of the address).
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR, FLASHSTORE_TEST_RDMA_DEV (root)"]
fn rxe_gid_change_is_followed() {
    let netdev = std::env::var("FLASHSTORE_TEST_RDMA_DEV").expect("FLASHSTORE_TEST_RDMA_DEV");
    let a: std::net::IpAddr = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
        .expect("FLASHSTORE_TEST_RDMA_ADDR")
        .parse()
        .expect("IP address");
    let std::net::IpAddr::V4(v4) = a else {
        panic!("FLASHSTORE_TEST_RDMA_ADDR must be IPv4")
    };
    let o = v4.octets();
    // whatever happens below: A is back and the placeholders gone afterwards (the following rxe tests open the device by
    // A)
    struct Restore(std::net::IpAddr, Vec<std::net::IpAddr>, String);
    impl Drop for Restore {
        fn drop(&mut self) {
            let ops = std::iter::once(("add", self.0)).chain(self.1.iter().map(|b| ("del", *b)));
            for (op, addr) in ops {
                let _ = std::process::Command::new("ip")
                    .args(["addr", op, &format!("{addr}/32"), "dev", &self.2])
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }
    }
    let mut restore = Restore(a, Vec::new(), netdev.clone());
    let dev = device();
    let mut sc = Core::new(&dev, cfg()).expect("sender core");
    let mut rc = Core::new(&dev, cfg()).expect("receiver core");
    let before = wait_gid(&dev, true).expect("GID present");
    ip_addr("del", a, &netdev);
    wait_gid(&dev, false);
    let (hs, hr) = (sc.handles(), rc.handles());
    let (s, r) = (
        Qp::create(&dev, hs, 1).expect("qp"),
        Qp::create(&dev, hr, 2).expect("qp"),
    );
    let err = s
        .connect(&hs, &r.endpoint(&hr))
        .expect_err("no connect while the GID is gone");
    assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable, "{err}");
    drop((s, r));
    // placeholder addresses (same netdev, private test range) take the lowest free GID slots until one holds A's old
    // index: on a device reused by an earlier run, lower slots may be free too, and A would get its old index back
    for k in 0..16u8 {
        let b = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 98 - k, o[2], o[3]));
        ip_addr("add", b, &netdev);
        restore.1.push(b);
        if placeholder_gid_index(b) >= before {
            break;
        }
    }
    ip_addr("add", a, &netdev);
    let after = wait_gid(&dev, true).expect("GID back");
    for b in std::mem::take(&mut restore.1) {
        ip_addr("del", b, &netdev); // the slots they took (A's old ones) are empty again
    }
    assert_ne!(
        before, after,
        "A came back at another index (a placeholder took its old one)"
    );
    let (qs, qr) = connect_pair(&dev, &mut sc, &mut rc, 3);
    let msg = b"after the address flap";
    assert_eq!(sc.send(qs, msg), msg.len());
    let mut got = Vec::new();
    let t = std::time::Instant::now();
    while got.len() < msg.len() {
        assert!(
            t.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT rxe data after the GID change exceeded 10s ({} of {} bytes)",
            got.len(),
            msg.len()
        );
        sc.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender qp {q} faulted"));
        rc.poll(|q, e| match e {
            Event::Data(d) if q == qr => got.extend_from_slice(d),
            Event::Fault(w) => panic!("receiver qp {q} faulted: {w}"),
            _ => {}
        });
    }
    assert_eq!(got, msg);
}

/// Wait for the last-WQE event of `qpn` (other QPs' events are skipped); 10 s bound (device-local event).
fn wait_last_wqe(rx: &std::sync::mpsc::Receiver<u32>, qpn: u32) {
    let t = std::time::Instant::now();
    loop {
        let left = std::time::Duration::from_secs(10).saturating_sub(t.elapsed());
        match rx.recv_timeout(left) {
            Ok(q) if q == qpn => return,
            Ok(_) => {}
            Err(_) => panic!("WARNING TIMEOUT rxe last-WQE event exceeded 10s (qp {qpn})"),
        }
    }
}

/// Teardown order on a real device: no last-WQE event before the move to ERR; the event comes after it; every receive
/// completion of the QP is in the CQ by then and a poll pass that empties the CQ drains them (slots posted again, counted
/// as orphans) before `Core::drained` hands the QP out for its destroy; nothing of it arrives afterwards.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_teardown_last_wqe_event_then_cq_drain_then_destroy() {
    let dev = device();
    let (events, last_wqe) = std::sync::mpsc::channel();
    let _events = AsyncEvents::start(
        dev.clone(),
        move |q| {
            let _ = events.send(q);
        },
        || {},
    )
    .expect("async events");
    let (mut sc, mut rc, qs, qr) = linked(&dev);
    // the sender spends its window; the receiver does not poll: the completions wait in its CQ
    let data = vec![3u8; 3 * 4096];
    let t = std::time::Instant::now();
    loop {
        assert!(
            t.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT rxe sends acknowledged exceeded 10s"
        );
        let n = sc.send(qs, &data);
        sc.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender qp {q} faulted"));
        if n == 0 && sc.free_tx_slots() == cfg().tx_slots as usize {
            break; // no credit left, every SEND acknowledged: landed in the receiver's SRQ
        }
    }
    let landed = sc.stats.tx_sends;
    assert!(landed > 0);
    assert!(last_wqe.try_recv().is_err(), "no last-WQE event before ERR");
    let mut det = rc.detach(qr).expect("attached");
    let reserved = det.held.credits;
    assert_eq!(rc.pool.reserved(), reserved);
    assert!(
        det.qp.to_err().expect("to ERR"),
        "connected: wait for its event"
    );
    wait_last_wqe(&last_wqe, det.qp.qpn());
    let orphans = rc.stats.rx_orphans;
    rc.quiesced(det.qp, det.held);
    assert!(
        rc.tearing_down() && rc.drained().is_none(),
        "not before a poll pass"
    );
    rc.poll(|q, e| panic!("event for qp {q} of a detached QP: {e:?}"));
    let d = rc.drained().expect("the pass emptied the CQ");
    assert_eq!(
        rc.stats.rx_orphans - orphans,
        landed,
        "every landed SEND drained before the destroy"
    );
    d.qp.destroy().expect("destroy");
    assert_eq!(rc.pool.reserved(), reserved, "reserved until the destroy");
    rc.reclaim(&d.held);
    assert_eq!(rc.pool.reserved(), 0);
    assert!(!rc.tearing_down());
    rc.poll(|q, e| panic!("event for qp {q} after the destroy: {e:?}"));
    assert_eq!(
        rc.stats.rx_orphans - orphans,
        landed,
        "nothing after the drain"
    );
    drop(sc.detach(qs));
}

/// QP number reuse: completions of a destroyed QP that are still in the CQ when a new connection carries the same QP
/// number belong to an older generation of the work-request id: ignored and counted, never applied to the new
/// connection (no fault, no retired WR of its fresh send queue).
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_completions_of_an_old_qp_never_reach_a_new_one_with_its_number() {
    let dev = device();
    let (mut sc, mut rc, qs, qr) = linked(&dev);
    // SENDs posted, the QP to ERR at once: their completions (done or flushed) wait in the CQ, not polled
    let sent = sc.send(qs, &vec![1u8; 3 * 4096]);
    assert!(sent > 0);
    sc.conns
        .get_mut(&qs)
        .expect("attached")
        .qp
        .to_err()
        .expect("to ERR");
    // completions are written asynchronously (soft-RoCE: a kernel task): give them time to be queued
    std::thread::sleep(std::time::Duration::from_millis(200));
    sc.reuse_qpn(qs);
    let mut faults = Vec::new();
    sc.poll(|q, e| {
        if let Event::Fault(w) = e {
            faults.push((q, w));
        }
    });
    diag::diag!("STALE sent {sent} stale completions {}", sc.stats.tx_stale);
    assert!(
        faults.is_empty(),
        "applied to the new connection: {faults:?}"
    );
    assert_eq!(sc.conns[&qs].tx.sq.outstanding(), 0);
    assert_eq!(sc.free_tx_slots(), cfg().tx_slots as usize);
    assert!(
        sc.stats.tx_stale > 0,
        "the old QP's completions were queued"
    );
    drop(sc.detach(qs));
    drop(rc.detach(qr));
}

#[cfg(feature = "memory-windows")]
fn window(dev: &Arc<Device>) -> (UnboundWindow, MemoryRange) {
    let destination =
        HostDestination::register(dev, vec![0x5a; 8192]).expect("register destination");
    let range = destination.range().subrange(1024, 4096).expect("subrange");
    (
        UnboundWindow::allocate(destination).expect("type-2 MW"),
        range,
    )
}

#[cfg(feature = "memory-windows")]
fn wait_window(core: &mut Core, window: &LocalWindow, want: WindowState) {
    let start = std::time::Instant::now();
    while window.state() != want {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT local window completion exceeded 10s (want {want:?}, got {:?})",
            window.state()
        );
        core.poll(|q, event| assert!(!matches!(event, Event::Fault(_)), "QP {q}: {event:?}"));
    }
}

/// Finish a successful test grant only after its final same-QP receipt arrives.
/// Callers own both endpoints and post no later WRITEs using this grant.
#[cfg(feature = "memory-windows")]
fn retire_written_grant(
    sender: &mut Core,
    receiver: &mut Core,
    sqpn: u32,
    rqpn: u32,
    mut grant: AdvertisedWindow,
    wire: &[u8],
) -> Vec<u8> {
    assert_eq!(sender.send(sqpn, wire), wire.len());
    let start = std::time::Instant::now();
    let mut received = Vec::new();
    while received.len() != wire.len() {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT test WRITE retirement receipt exceeded 10s"
        );
        sender.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
        receiver.poll(|q, e| match e {
            Event::Data(data) if q == rqpn => received.extend_from_slice(data),
            Event::Fault(why) => panic!("receiver {q}: {why}"),
            _ => {}
        });
    }
    assert_eq!(received, wire);
    let descriptor = grant.descriptor();
    let receipt = ReadReceipt::decode(&received, descriptor).expect("exact retirement receipt");
    // SAFETY: both test endpoints are owned, all WRITEs completed and the
    // ordered final receipt arrived. No later WRITE can use this grant.
    assert!(unsafe { grant.confirm_peer_retired_unchecked(descriptor.attempt, descriptor.rkey) });
    grant.invalidate(receiver).expect("local invalidation");
    let start = std::time::Instant::now();
    while grant.state() != WindowState::Retired {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT test WRITE retirement LOCAL_INV exceeded 10s"
        );
        receiver.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "receiver {q}: {e:?}"));
    }
    grant.verify_retired_read(&receipt).expect("placed CRC");
    grant
        .into_unbound()
        .expect("retired grant")
        .into_destination()
        .expect("MW released")
        .into_buffer()
        .expect("MR released")
}

/// Publication transfers the only owner; numeric receipt matching alone cannot recover it.
/// The test controls both QPs and receives the ordered end marker; the sender posts no later WRs.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_advertised_window_requires_peer_proof_and_local_cqe() {
    let dev = device();
    let (mut sender, mut receiver, sqpn, rqpn) = linked(&dev);
    let (window, range) = window(&dev);
    let local = receiver.bind_window(rqpn, window, range).expect("bind");
    wait_window(&mut receiver, &local, WindowState::Bound);
    let attempt = WindowAttempt {
        connection: 7,
        tid: 11,
        retry: 2,
    };
    let mut grant = local.advertise(&receiver, attempt).expect("advertise");
    let descriptor = grant.descriptor();
    assert_eq!(descriptor.attempt, attempt);
    assert_eq!(descriptor.range, range);
    assert!(grant.invalidate(&mut receiver).is_err());
    grant = grant.into_unbound().expect_err("peer has not retired");

    assert_eq!(sender.send(sqpn, b"retired"), 7);
    let mut received = false;
    let start = std::time::Instant::now();
    while !received {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT advertised window receipt exceeded 10s"
        );
        sender.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
        receiver.poll(|q, e| match e {
            Event::Data(data) if q == rqpn => {
                assert_eq!(data, b"retired");
                received = true;
            }
            Event::Fault(why) => panic!("receiver {q}: {why}"),
            _ => {}
        });
    }
    let same_key_other_qp = RemoteInvalidation {
        key: descriptor.rkey,
        identity: sender.conns[&sqpn].qp.window_identity.clone(),
    };
    assert!(!grant.matches_remote_invalidation(attempt, &same_key_other_qp));
    let same_qp = RemoteInvalidation {
        key: descriptor.rkey,
        identity: receiver.conns[&rqpn].qp.window_identity.clone(),
    };
    assert!(grant.matches_remote_invalidation(attempt, &same_qp));
    assert!(!grant.matches_remote_invalidation(
        WindowAttempt {
            retry: 3,
            ..attempt
        },
        &same_qp
    ));
    // SAFETY: the test owns both endpoints, observed the ordered final SEND, and will not post
    // any later RMA work for this attempt.
    unsafe {
        assert!(!grant.confirm_peer_retired_unchecked(attempt, descriptor.rkey.wrapping_add(1)));
        assert!(grant.confirm_peer_retired_unchecked(attempt, descriptor.rkey));
    }
    grant = grant.into_unbound().expect_err("local CQE still required");
    grant.invalidate(&mut receiver).expect("local invalidation");
    let start = std::time::Instant::now();
    while grant.state() != WindowState::Retired {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT advertised window invalidation exceeded 10s"
        );
        receiver.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "receiver {q}: {e:?}"));
    }
    let parent = grant.into_unbound().expect("recover after both proofs");
    assert!(
        parent
            .into_destination()
            .unwrap()
            .buffer()
            .iter()
            .all(|b| *b == 0x5a)
    );
    drop(sender.detach(sqpn));
    drop(receiver.detach(rqpn));
}

/// An invalidation completion must either report the exact key, or fault closed if the provider
/// omits WITH_INV. A plain zero-byte SEND is never accepted as a retirement receipt.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_send_with_invalidate_reports_key_or_faults_closed() {
    let dev = device();
    let (mut sender, mut receiver, sqpn, rqpn) = linked(&dev);
    let (window, range) = window(&dev);
    let mut local = receiver.bind_window(rqpn, window, range).expect("bind");
    wait_window(&mut receiver, &local, WindowState::Bound);
    receiver
        .enable_remote_invalidation(rqpn)
        .expect("negotiated receiver");
    assert_eq!(sender.send(sqpn, b"before"), 6);
    // SAFETY: test owns the live bound window on this exact connected QP and posts no later WRITE.
    unsafe { sender.send_invalidate(sqpn, local.test_rkey()) }.expect("send invalidation");
    let mut after = 0;
    let mut bytes = Vec::new();
    let mut keys = Vec::new();
    let mut fault = None;
    let start = std::time::Instant::now();
    while (bytes.len() != 11 || keys.is_empty()) && fault.is_none() {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT remote invalidation receive exceeded 10s (bytes {}, keys {})",
            bytes.len(),
            keys.len()
        );
        if after < 5 {
            after += sender.send(sqpn, &b"after"[after..]);
        }
        sender.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
        receiver.poll(|q, e| match e {
            Event::Data(data) if q == rqpn => bytes.extend_from_slice(data),
            Event::RemoteInvalidated(key) if q == rqpn => keys.push(key.key()),
            Event::Fault(why) if q == rqpn => fault = Some(why),
            _ => {}
        });
    }
    if let Some(why) = fault {
        assert!(
            why.contains("flags=0, len=0"),
            "unexpected receiver fault: {why}"
        );
        assert!(keys.is_empty(), "provider did not report WITH_INV");
        assert_eq!(local.state(), WindowState::Bound);
        // No receipt is accepted. The owner is quarantined rather than recycled.
        drop(sender.detach(sqpn));
        drop(local);
        drop(receiver.detach(rqpn));
        return;
    }
    assert_eq!(bytes, b"beforeafter");
    assert_eq!(after, 5);
    assert_eq!(keys, vec![local.test_rkey()]);
    // The peer QP is retired before local invalidation/reuse; an invalidation event alone
    // would not establish that no later peer posts can reach a recycled key.
    drop(sender.detach(sqpn));
    local.invalidate(&mut receiver).expect("local retirement");
    wait_window(&mut receiver, &local, WindowState::Retired);
    drop(local.into_unbound().expect("retired window"));
    drop(receiver.detach(rqpn));
}

/// Actual WRITE reads only the checked source subrange and changes only the bound destination subrange.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_owned_write_source_retained_through_cqe_and_same_qp_send() {
    let dev = device();
    let (mut sender, mut receiver, sqpn, rqpn) = linked(&dev);
    let (window, bound_range) = window(&dev);
    let mut local = receiver.bind_window(rqpn, window, bound_range).unwrap();
    wait_window(&mut receiver, &local, WindowState::Bound);
    let target = local.test_target().subrange(512, 1024).unwrap();
    let bytes = Bytes::from(vec![0xa7; 4096]);
    let original = bytes.as_ptr();
    let source = WriteSource::register(&dev, bytes).unwrap();
    let part = source.range().subrange(256, 1024).unwrap();
    assert_eq!(sender.send(sqpn, b"before"), 6);
    let (posted, allocations) =
        crate::test_alloc::count(|| sender.write(sqpn, source, part, target));
    assert_eq!(
        allocations, 0,
        "accepted WRITE posting allocates no Rust memory"
    );
    let handle = posted.unwrap();
    assert_eq!(handle.state(), WriteState::Pending);
    assert_eq!(sender.stats.tx_write_wrs, 1);
    assert_eq!(sender.stats.tx_write_bytes, 1024);
    assert_eq!(sender.stats.tx_write_doorbells, 1);
    assert_eq!(sender.stats.tx_write_sq_stalls, 0);
    let start = std::time::Instant::now();
    while handle.state() == WriteState::Pending {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT owned WRITE completion exceeded 10s"
        );
        sender.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
    }
    assert_eq!(handle.state(), WriteState::Complete);
    let source = handle.into_source().unwrap();
    assert_eq!(source.data().as_ptr(), original);
    assert!(source.data().iter().all(|b| *b == 0xa7));
    assert_eq!(sender.send(sqpn, b"after"), 5);
    let mut received = Vec::new();
    let start = std::time::Instant::now();
    while received.len() != 11 {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT owned WRITE SEND stream exceeded 10s"
        );
        sender.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
        receiver.poll(|q, e| match e {
            Event::Data(bytes) if q == rqpn => received.extend_from_slice(bytes),
            Event::Fault(why) => panic!("receiver {q}: {why}"),
            _ => {}
        });
    }
    assert_eq!(received, b"beforeafter");
    assert_eq!(sender.stats.tx_write_wrs, 1, "SEND is not a WRITE");
    assert_eq!(sender.stats.tx_write_bytes, 1024);
    assert_eq!(sender.stats.tx_write_doorbells, 1);
    local.invalidate(&mut receiver).unwrap();
    wait_window(&mut receiver, &local, WindowState::Retired);
    let destination = local.into_unbound().unwrap().into_destination().unwrap();
    let buffer = destination.into_buffer().unwrap();
    let start = (bound_range.address() - buffer.as_ptr() as u64) as usize;
    assert!(buffer[..start + 512].iter().all(|b| *b == 0x5a));
    assert!(buffer[start + 512..start + 1536].iter().all(|b| *b == 0xa7));
    assert!(buffer[start + 1536..].iter().all(|b| *b == 0x5a));
}

/// The owned WRITE source, published destination, cancellation retirement record, receipt CRC
/// and local retirement compose without msgr2 framing. The test controls both endpoints; RXE's missing
/// WITH_INV completion is qualified separately and cannot activate production placement.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_owned_write_into_advertised_window_verifies_exact_bytes() {
    let dev = device();
    let (mut sender, mut receiver, sqpn, rqpn) = linked(&dev);
    let (window, range) = window(&dev);
    let local = receiver.bind_window(rqpn, window, range).expect("bind");
    wait_window(&mut receiver, &local, WindowState::Bound);
    let attempt = WindowAttempt {
        connection: 17,
        tid: 23,
        retry: 1,
    };
    let mut grant = local.advertise(&receiver, attempt).expect("advertise");
    let descriptor = grant.descriptor();
    let payload = vec![0xa7; 4096];
    let crc = crc::crc32c(0, &payload);
    let payload = Bytes::from(payload);
    let first = WriteSource::register(&dev, payload.slice(0..1024)).expect("first source");
    let second = WriteSource::register(&dev, payload.slice(1024..)).expect("second source");
    let mut server = PlacedReadWrite::new(descriptor, sqpn);
    // SAFETY: this test holds the exact peer grant and keeps both RC QPs alive.
    unsafe { server.post(&mut sender, first) }.expect("post first WRITE");
    unsafe { server.post(&mut sender, second) }.expect("post second WRITE");
    server.cancel();
    let server = server
        .finish_cancel()
        .expect_err("pending WRITE cannot retire");
    let start = std::time::Instant::now();
    while server.state() == Some(WriteState::Pending) {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT advertised WRITE completion exceeded 10s"
        );
        sender.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
    }
    assert_eq!(server.state(), Some(WriteState::Complete));
    let (retired, writes) = server.finish_cancel().expect("completed WRITEs retired");
    assert_eq!(writes.len(), 2);
    drop(writes);
    let retired = retired.encode();
    assert_eq!(sender.send(sqpn, &retired), retired.len());
    let start = std::time::Instant::now();
    let mut received = Vec::new();
    while received.len() != retired.len() {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT advertised WRITE receipt exceeded 10s"
        );
        sender.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
        receiver.poll(|q, e| match e {
            Event::Data(data) if q == rqpn => received.extend_from_slice(data),
            Event::Fault(why) => panic!("receiver {q}: {why}"),
            _ => {}
        });
    }
    assert_eq!(
        RetirementRecord::decode(&received, descriptor)
            .expect("matched retirement")
            .kind,
        RetirementKind::Retired
    );
    let wire = ReadReceipt::encode(descriptor, 4096, &[crc]).expect("encode receipt");
    let receipt = ReadReceipt::decode(&wire, descriptor).expect("decode receipt");
    // SAFETY: this test owns both QPs, observed the ordered final SEND, and posts no later WRs.
    assert!(unsafe { grant.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
    grant.invalidate(&mut receiver).expect("local invalidation");
    let start = std::time::Instant::now();
    while grant.state() != WindowState::Retired {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT advertised WRITE invalidation exceeded 10s"
        );
        receiver.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "receiver {q}: {e:?}"));
    }
    let destination = grant
        .into_unbound()
        .expect("proof and local CQE")
        .into_destination()
        .expect("destination");
    let mut buffer = destination.into_buffer().expect("owned buffer");
    let start = (range.address() - buffer.as_ptr() as u64) as usize;
    receipt.verify(&buffer[start..start + 4096]).expect("CRC");
    assert!(buffer[..start].iter().all(|b| *b == 0x5a));
    assert!(buffer[start + 4096..].iter().all(|b| *b == 0x5a));
    buffer[start + 4095] ^= 1;
    assert!(receipt.verify(&buffer[start..start + 4096]).is_err());
    drop(sender.detach(sqpn));
    drop(receiver.detach(rqpn));
}

/// The successful receipt is sent only after the server WRITE CQE and terminal transition.
/// Source-pull PUT transport (adr 0665): the OSD side posts one RDMA READ from a
/// peer's READ-only type-2 MW into a pooled registered destination and gets
/// exactly the source bytes. This is the primitive the croit-flashstore-osd PUT uses.
#[cfg(all(feature = "gpu", feature = "memory-windows"))]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_source_pull_read_delivers_the_source_bytes() {
    let dev = device();
    // `client` holds the READ-only source, `server` is the OSD that reads it.
    let (mut client, mut server, sqpn, rqpn) = linked_with_reads(&dev, 8);
    let source_bytes: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let parent = HostDestination::register_prepared(&dev, source_bytes.clone()).expect("source");
    let range = parent.range();
    let window = UnboundWindow::allocate(parent).expect("source MW");
    let local = client
        .bind_read_source(sqpn, window, range)
        .expect("bind READ-only source");
    let started = std::time::Instant::now();
    while local.state() != WindowState::Bound {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT rxe source BIND exceeded 10s"
        );
        client.poll(|q, e| {
            if let Event::Fault(why) = e {
                panic!("client qp {q} faulted: {why}");
            }
        });
    }
    let published = local
        .advertise(
            &client,
            WindowAttempt {
                connection: 7,
                tid: 11,
                retry: 0,
            },
        )
        .expect("advertise READ-only source");
    let descriptor = published.descriptor();
    // The OSD's pooled registered destination.
    let destination = HostDestination::register(&dev, vec![0u8; 4096]).expect("destination");
    let target = ReadTarget::prepare(destination);
    // SAFETY: the descriptor was published on this live QP pair for this attempt
    // and the source stays immutable and registered until the READ completed.
    let source = unsafe { descriptor.remote_source() }.expect("source range");
    let handle = server.read(rqpn, target, source).expect("post READ");
    let started = std::time::Instant::now();
    while handle.state() == ReadState::Pending {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT rxe source-pull READ exceeded 10s"
        );
        client.poll(|q, e| {
            if let Event::Fault(why) = e {
                panic!("client qp {q} faulted: {why}");
            }
        });
        server.poll(|q, e| {
            if let Event::Fault(why) = e {
                panic!("server qp {q} faulted: {why}");
            }
        });
    }
    assert_eq!(handle.state(), ReadState::Complete);
    let destination = handle
        .into_target()
        .expect("completed target")
        .into_destination();
    assert_eq!(
        destination.buffer(),
        source_bytes.as_slice(),
        "the pulled bytes equal the client's source"
    );
}

#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_placed_read_success_reply_retires_window() {
    let dev = device();
    let (mut sender, mut receiver, sqpn, rqpn) = linked(&dev);
    let (window, range) = window(&dev);
    let local = receiver.bind_window(rqpn, window, range).expect("bind");
    wait_window(&mut receiver, &local, WindowState::Bound);
    let attempt = WindowAttempt {
        connection: 19,
        tid: 29,
        retry: 2,
    };
    let mut grant = local.advertise(&receiver, attempt).expect("advertise");
    let descriptor = grant.descriptor();
    let data = Bytes::from(vec![0xa9; 4096]);
    let registered = ZcMem::register_owned(&dev, data.clone()).expect("register pool");
    sender
        .set_zero_copy(registered, 4096)
        .expect("install pool registration");
    assert!(
        sender
            .prepare_write_sources(Vec::new(), 0, 4096)
            .unwrap()
            .is_empty()
    );
    let outside = Bytes::from(vec![0xa9; 4096]);
    let first_part = data.slice(0..1024);
    let second_part = data.slice(1024..);
    let refused = sender
        .prepare_write_sources(vec![first_part.clone(), outside.clone()], 5120, 5120)
        .expect_err("later part outside registered pool");
    assert_eq!(refused.parts[0].as_ptr(), first_part.as_ptr());
    assert_eq!(refused.parts[1].as_ptr(), outside.as_ptr());
    let refused = sender
        .prepare_write_sources(vec![first_part.clone(), second_part.clone()], 4096, 4095)
        .expect_err("pieces exceed grant");
    assert_eq!(refused.parts[0].as_ptr(), first_part.as_ptr());
    assert_eq!(refused.parts[1].as_ptr(), second_part.as_ptr());
    let refused = sender
        .prepare_write_sources(vec![first_part.clone(), second_part.clone()], 4095, 4096)
        .expect_err("pieces differ from declared reply length");
    assert_eq!(refused.parts[0].as_ptr(), first_part.as_ptr());
    assert_eq!(refused.parts[1].as_ptr(), second_part.as_ptr());
    let mut sources = sender
        .prepare_write_sources(vec![first_part, second_part], 4096, 4096)
        .expect("all pieces fit registered pool and grant")
        .into_iter();
    let first = sources.next().expect("first source");
    let second = sources.next().expect("second source");
    assert!(sources.next().is_none());
    let mut server = PlacedReadWrite::new(descriptor, sqpn);
    // SAFETY: both endpoints and the exact grant remain live through the completion and reply.
    unsafe { server.post(&mut sender, first) }.expect("post first WRITE");
    unsafe { server.post(&mut sender, second) }.expect("post second WRITE");
    let server = server
        .finish_success()
        .expect_err("pending WRITE cannot produce reply");
    let start = std::time::Instant::now();
    while server.state() == Some(WriteState::Pending) {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT placed READ WRITE completion exceeded 10s"
        );
        sender.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
    }
    let verified = [crc::crc32c(0, &data)];
    let server = server
        .finish_success_verified(&[])
        .expect_err("missing verified block CRC cannot produce reply");
    let (reply, writes) = server
        .finish_success_verified(&verified)
        .expect("successful WRITE CQEs and verified block CRC");
    assert_eq!(writes.len(), 2);
    drop(writes);
    assert_eq!(sender.send(sqpn, &reply), reply.len());
    let start = std::time::Instant::now();
    let mut received = Vec::new();
    while received.len() != reply.len() {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT placed READ success receipt exceeded 10s"
        );
        sender.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
        receiver.poll(|q, e| match e {
            Event::Data(bytes) if q == rqpn => received.extend_from_slice(bytes),
            Event::Fault(why) => panic!("receiver {q}: {why}"),
            _ => {}
        });
    }
    let receipt = ReadReceipt::decode(&received, descriptor).expect("exact success receipt");
    // SAFETY: this test owns both endpoints and observed the ordered same-QP receipt.
    assert!(unsafe { grant.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
    grant.invalidate(&mut receiver).expect("local invalidation");
    let start = std::time::Instant::now();
    while grant.state() != WindowState::Retired {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT placed READ local invalidation exceeded 10s"
        );
        receiver.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "receiver {q}: {e:?}"));
    }
    let destination = grant
        .into_unbound()
        .expect("retired owner")
        .into_destination()
        .expect("destination");
    let buffer = destination.into_buffer().expect("buffer");
    let start = (range.address() - buffer.as_ptr() as u64) as usize;
    receipt
        .verify(&buffer[start..start + 4096])
        .expect("placed CRC");
    drop(sender.detach(sqpn));
    drop(receiver.detach(rqpn));
}

/// Abandoning a pending handle must not deregister its last MR reference in CQ progress.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_owned_write_abandoned_handle_retains_source_after_cqe() {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let dev = device();
    let (mut sender, mut receiver, sqpn, rqpn) = linked(&dev);
    let (window, range) = window(&dev);
    let mut local = receiver.bind_window(rqpn, window, range).unwrap();
    wait_window(&mut receiver, &local, WindowState::Bound);
    let released = Arc::new(AtomicUsize::new(0));
    let data = Bytes::from_owner(ShutdownLease {
        bytes: Bytes::from(vec![0x83; 4096]),
        released: released.clone(),
    });
    let source = WriteSource::register(&dev, data).unwrap();
    let source_range = source.range();
    let before = quarantined_write_sources();
    let handle = sender
        .write(sqpn, source, source_range, local.test_target())
        .unwrap();
    assert_eq!(handle.state(), WriteState::Pending);
    drop(handle);
    assert_eq!(quarantined_write_sources(), before + 1);
    let start = std::time::Instant::now();
    while sender.conns[&sqpn].tx.sq.outstanding() != 0 {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT abandoned WRITE completion exceeded 10s"
        );
        sender.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
    }
    assert_eq!(quarantined_write_sources(), before + 1);
    assert_eq!(released.load(Relaxed), 0, "CQ progress retained the source");
    local.invalidate(&mut receiver).unwrap();
    wait_window(&mut receiver, &local, WindowState::Retired);
    drop(local.into_unbound().unwrap());
    drop(sender);
    drop(receiver);
    assert_eq!(released.load(Relaxed), 0, "the source stays quarantined");
}

/// Losing the WRITE CQE cannot return the source or free its registered backing.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_owned_write_source_is_quarantined_after_cq_loss() {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let dev = device();
    let (mut sender, mut receiver, sqpn, rqpn) = linked(&dev);
    let (window, range) = window(&dev);
    let mut local = receiver.bind_window(rqpn, window, range).unwrap();
    wait_window(&mut receiver, &local, WindowState::Bound);
    let released = Arc::new(AtomicUsize::new(0));
    let data = Bytes::from_owner(ShutdownLease {
        bytes: Bytes::from(vec![0x83; 4096]),
        released: released.clone(),
    });
    let source = WriteSource::register(&dev, data).unwrap();
    let source_range = source.range();
    let before = quarantined_write_sources();
    let handle = sender
        .write(sqpn, source, source_range, local.test_target())
        .unwrap();
    sender.inject_cq_error(-5);
    sender.poll(|_, _| {});
    assert_eq!(handle.state(), WriteState::Failed);
    assert!(handle.into_source().is_err());
    assert_eq!(quarantined_write_sources(), before + 1);
    assert_eq!(
        released.load(Relaxed),
        0,
        "the lost CQE cannot free DMA backing"
    );
    // With the sender CQE lost, retire its QP before releasing the remote grant.
    let failures = teardown_failures();
    drop(sender);
    assert_eq!(teardown_failures(), failures);
    local.invalidate(&mut receiver).unwrap();
    wait_window(&mut receiver, &local, WindowState::Retired);
    drop(local.into_unbound().unwrap());
    drop(receiver);
    assert_eq!(released.load(Relaxed), 0, "the source remains quarantined");
}

/// A permanent heap registration keeps mappings alive, not the allocator's
/// individual payload lease. Both must survive a failed, uncertain WRITE.
#[cfg(feature = "memory-windows")]
fn arena_write_lease(cq_loss: bool) {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let dev = device();
    let (mut sender, mut receiver, sqpn, rqpn) = linked(&dev);
    let (window, range) = window(&dev);
    let mut local = receiver.bind_window(rqpn, window, range).unwrap();
    wait_window(&mut receiver, &local, WindowState::Bound);
    // The MR deliberately has no Bytes owner, like the production payload
    // arena. Its mapping is permanent; ShutdownLease models one live extent.
    let arena: &'static [u8] = Box::leak(vec![0x83; 4096].into_boxed_slice());
    // SAFETY: this mapping remains initialized and immutable until process exit.
    let registration =
        unsafe { ZcMem::register(&dev, &[(arena.as_ptr() as u64, arena.len() as u64)]) }.unwrap();
    sender.set_zero_copy(registration, 4096).unwrap();
    let released = Arc::new(AtomicUsize::new(0));
    let data = Bytes::from_owner(ShutdownLease {
        bytes: Bytes::from_static(arena),
        released: released.clone(),
    });
    let source = sender
        .prepare_write_sources(vec![data], 4096, 4096)
        .unwrap()
        .pop()
        .unwrap();
    let source_range = source.range();
    let before = quarantined_write_sources();
    let handle = sender
        .write(sqpn, source, source_range, local.test_target())
        .unwrap();
    assert_eq!(released.load(Relaxed), 0);
    if cq_loss {
        sender.inject_cq_error(-5);
        sender.poll(|_, _| {});
        assert_eq!(handle.state(), WriteState::Failed);
    } else {
        let start = std::time::Instant::now();
        while handle.state() == WriteState::Pending {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "WARNING TIMEOUT arena WRITE completion exceeded 10s"
            );
            sender.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
        }
        assert_eq!(handle.state(), WriteState::Complete);
    }
    drop(handle);
    let released_after_drop = released.load(Relaxed);
    // Even the red regression retires the real QP before releasing its target.
    let failures = teardown_failures();
    drop(sender);
    assert_eq!(teardown_failures(), failures);
    local.invalidate(&mut receiver).unwrap();
    wait_window(&mut receiver, &local, WindowState::Retired);
    let destination = local.into_unbound().unwrap().into_destination().unwrap();
    let buffer = destination.into_buffer().unwrap();
    if !cq_loss {
        let offset = (range.address() - buffer.as_ptr() as u64) as usize;
        assert!(buffer[offset..offset + 4096].iter().all(|b| *b == 0x83));
    }
    drop(receiver);
    assert_eq!(quarantined_write_sources(), before + u64::from(cq_loss));
    if cq_loss {
        assert_eq!(
            released_after_drop, 0,
            "a failed WRITE must retain its arena extent lease"
        );
        assert_eq!(
            released.load(Relaxed),
            0,
            "the uncertain source stays quarantined"
        );
    } else {
        assert_eq!(
            released_after_drop, 1,
            "successful CQ retirement releases the lease"
        );
        assert_eq!(released.load(Relaxed), 1);
    }
}

#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_arena_write_lease_cq_loss_keeps_payload_owner() {
    arena_write_lease(true);
}

#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_arena_write_lease_success_releases_payload_owner() {
    arena_write_lease(false);
}

/// Rejected WRITE admission returns the exact source; neither wrong bounds nor another PD reaches verbs.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_owned_write_rejects_bounds_and_pd_without_losing_source() {
    let dev = device();
    let (mut sender, mut receiver, sqpn, rqpn) = linked(&dev);
    let (window, range) = window(&dev);
    let mut local = receiver.bind_window(rqpn, window, range).unwrap();
    wait_window(&mut receiver, &local, WindowState::Bound);
    let target = local.test_target().subrange(0, 1024).unwrap();
    let data = Bytes::from(vec![0x71; 2048]);
    let original = data.as_ptr();
    let source = WriteSource::register(&dev, data).unwrap();
    let outside = MemoryRange::new(source.range().address() + 1536, 1024).unwrap();
    let rejected = sender.write(sqpn, source, outside, target).unwrap_err();
    assert_eq!(rejected.error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(rejected.source.data().as_ptr(), original);
    let source = rejected.source;
    let valid = source.range().subrange(0, 1024).unwrap();
    let other = Device::open(crate::gid_of(
        std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
            .unwrap()
            .parse()
            .unwrap(),
    ))
    .unwrap();
    let other_source = WriteSource::register(&other, Bytes::from(vec![0x28; 1024])).unwrap();
    let other_range = other_source.range();
    let rejected = sender
        .write(sqpn, other_source, other_range, target)
        .unwrap_err();
    assert_eq!(rejected.error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(rejected.source.data(), &[0x28; 1024]);
    assert_eq!(sender.stats.tx_write_wrs, 0);
    assert_eq!(sender.stats.tx_write_bytes, 0);
    assert_eq!(sender.stats.tx_write_doorbells, 0);
    assert_eq!(sender.stats.tx_write_sq_stalls, 0);
    let handle = sender.write(sqpn, source, valid, target).unwrap();
    let start = std::time::Instant::now();
    while handle.state() == WriteState::Pending {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT owned WRITE after rejection exceeded 10s"
        );
        sender.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
    }
    assert_eq!(handle.state(), WriteState::Complete);
    assert_eq!(handle.into_source().unwrap().data().as_ptr(), original);
    local.invalidate(&mut receiver).unwrap();
    wait_window(&mut receiver, &local, WindowState::Retired);
    let destination = local.into_unbound().unwrap().into_destination().unwrap();
    let buffer = destination.into_buffer().unwrap();
    let start = (range.address() - buffer.as_ptr() as u64) as usize;
    assert!(buffer[start..start + 1024].iter().all(|b| *b == 0x71));
}

/// Real BIND/LOCAL_INV and byte-exact ordinary SENDs share the same RC SQ; a window stays private across key wrap.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_local_windows_share_send_order_and_recover_original_storage() {
    let dev = device();
    let (mut sc, mut rc, qs, qr) = linked(&dev);
    let destination = HostDestination::register(&dev, vec![0x5a; 8192]).expect("parent MR");
    let address = destination.buffer().as_ptr();
    let range = destination
        .range()
        .subrange(1024, 4096)
        .expect("checked subrange");
    let mut unbound = UnboundWindow::allocate(destination).expect("MW");
    let mut received = Vec::new();
    assert_eq!(sc.send(qs, b"before"), 6);
    for _ in 0..260 {
        let mut local = sc
            .bind_window(qs, unbound, range)
            .expect("bind exact subrange");
        assert_eq!(local.state(), WindowState::Binding);
        assert_eq!(local.range(), range);
        wait_window(&mut sc, &local, WindowState::Bound);
        local.invalidate(&mut sc).expect("post local invalidation");
        wait_window(&mut sc, &local, WindowState::Retired);
        unbound = local
            .into_unbound()
            .expect("recover only unadvertised invalidated window");
    }
    assert_eq!(sc.send(qs, b"after"), 5);
    let start = std::time::Instant::now();
    while received.len() != 11 {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT local window SEND stream exceeded 10s"
        );
        sc.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
        rc.poll(|q, e| match e {
            Event::Data(bytes) if q == qr => received.extend_from_slice(bytes),
            Event::Fault(why) => panic!("receiver {q}: {why}"),
            _ => {}
        });
    }
    assert_eq!(received, b"beforeafter");
    let destination = unbound.into_destination().expect("release MW");
    assert_eq!(destination.buffer().as_ptr(), address);
    assert!(destination.buffer().iter().all(|b| *b == 0x5a));
    let buffer = destination.into_buffer().expect("release MR");
    assert_eq!(buffer.as_ptr(), address);
}

/// Same-PD/exact-range admission preserves original ownership; SQ occupancy is real accepted provider WRs.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_local_windows_validate_pd_bounds_and_queue_room_without_send_credits() {
    let dev = device();
    let (mut sc, mut rc) = (
        Core::new(
            &dev,
            CoreCfg {
                sq_depth: 32,
                srq_depth: 8,
                max_window: 4,
                ..cfg()
            },
        )
        .unwrap(),
        Core::new(&dev, cfg()).unwrap(),
    );
    let (qs, qr) = connect_pair(&dev, &mut sc, &mut rc, 1);
    let (unbound, range) = window(&dev);
    let outside = MemoryRange::new(range.address(), 8192).unwrap();
    let rejected = sc.bind_window(qs, unbound, outside).unwrap_err();
    assert_eq!(rejected.error.kind(), std::io::ErrorKind::InvalidInput);
    let destination = rejected.window.into_destination().unwrap();
    assert_eq!(destination.range().address() + 1024, range.address());
    drop(destination);
    let other_pd = Device::open(crate::gid_of(
        std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
            .unwrap()
            .parse()
            .unwrap(),
    ))
    .unwrap();
    let (unbound, range) = window(&other_pd);
    let rejected = sc.bind_window(qs, unbound, range).unwrap_err();
    assert_eq!(rejected.error.kind(), std::io::ErrorKind::InvalidInput);
    drop(rejected.window);
    let before = avail(&mut sc, qs);
    let mut locals = Vec::new();
    for _ in 0..32 {
        let (unbound, range) = window(&dev);
        let (result, allocations) = crate::test_alloc::count(|| sc.bind_window(qs, unbound, range));
        assert_eq!(
            allocations, 0,
            "accepted bind posts allocate no Rust memory"
        );
        locals.push(result.unwrap());
    }
    assert_eq!(
        avail(&mut sc, qs),
        before,
        "local WRs consume no SEND credit"
    );
    let (unbound, range) = window(&dev);
    let (result, allocations) = crate::test_alloc::count(|| sc.bind_window(qs, unbound, range));
    assert_eq!(allocations, 0, "bind backpressure allocates no Rust memory");
    let rejected = result.unwrap_err();
    assert_eq!(rejected.error.kind(), std::io::ErrorKind::WouldBlock);
    let (remote, remote_range) = window(&dev);
    let mut remote = rc.bind_window(qr, remote, remote_range).unwrap();
    wait_window(&mut rc, &remote, WindowState::Bound);
    let source = WriteSource::register(&dev, Bytes::from(vec![0x99; 1024])).unwrap();
    let source_range = source.range();
    let target = remote.test_target().subrange(0, 1024).unwrap();
    let (result, allocations) =
        crate::test_alloc::count(|| sc.write(qs, source, source_range, target));
    assert_eq!(
        allocations, 0,
        "WRITE backpressure allocates no Rust memory"
    );
    let refused = result.unwrap_err();
    assert_eq!(refused.error.kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(refused.source.data(), &[0x99; 1024]);
    for local in &locals {
        wait_window(&mut sc, local, WindowState::Bound);
    }
    let mut extra = sc.bind_window(qs, rejected.window, range).unwrap();
    wait_window(&mut sc, &extra, WindowState::Bound);
    for local in &mut locals {
        let (result, allocations) = crate::test_alloc::count(|| local.invalidate(&mut sc));
        assert_eq!(
            allocations, 0,
            "accepted invalidate posts allocate no Rust memory"
        );
        result.unwrap();
    }
    let (result, allocations) = crate::test_alloc::count(|| extra.invalidate(&mut sc));
    assert_eq!(
        allocations, 0,
        "invalidate backpressure allocates no Rust memory"
    );
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(extra.state(), WindowState::Bound);
    for local in &locals {
        wait_window(&mut sc, local, WindowState::Retired);
    }
    extra.invalidate(&mut sc).unwrap();
    wait_window(&mut sc, &extra, WindowState::Retired);
    assert_eq!(avail(&mut sc, qs), before);
    assert_eq!(
        rc.stats.rx_sends, 0,
        "BIND/LOCAL_INV do not consume receive slots"
    );
    remote.invalidate(&mut rc).unwrap();
    wait_window(&mut rc, &remote, WindowState::Retired);
    drop(remote.into_unbound().unwrap());
    drop(locals);
    drop(extra);
}

/// Lost CQEs and SQ drain never grant ownership return; abandoning a bound handle retains its registration.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_local_windows_quarantine_after_lost_completion_and_qp_detach() {
    for lose_cqe in [true, false] {
        let dev = device();
        let (mut sc, rc, qs, _) = linked(&dev);
        let (unbound, range) = window(&dev);
        let local = sc.bind_window(qs, unbound, range).unwrap();
        if lose_cqe {
            sc.inject_cq_error(-5);
            sc.poll(|_, _| {});
            assert_eq!(
                local.state(),
                WindowState::Failed,
                "CQ failure reports terminal state before teardown"
            );
        } else {
            // detach drains marker ownership before QP destroy; no successful local invalidation was posted.
            let detached = sc.detach(qs).expect("detach");
            assert_eq!(local.state(), WindowState::Failed);
            drop(detached);
        }
        drop(sc);
        drop(rc);
        assert_eq!(local.state(), WindowState::Failed);
        let local = local.into_unbound().unwrap_err();
        let retained = Arc::strong_count(&dev);
        let before = quarantined_windows();
        drop(local);
        assert_eq!(quarantined_windows(), before + 1);
        assert_eq!(
            Arc::strong_count(&dev),
            retained,
            "unretired owner remains registered"
        );
    }
}

/// Even without a source MR, an uncertain QP destroy retains the device/PD whose provider QP may still exist.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_qp_uncertain_destroy_retains_device_without_send_sources() {
    let dev = device();
    let core = Core::new(&dev, cfg()).unwrap();
    let references = Arc::strong_count(&dev);
    let mut qp = Qp::create(&dev, core.handles(), 1).unwrap();
    // Actual destruction succeeds before injecting an uncertain result, as in the existing ownership gate.
    qp.destroy_error = Some(5);
    assert_eq!(qp.destroy().unwrap_err().raw_os_error(), Some(5));
    assert_eq!(Arc::strong_count(&dev), references + 1);
}

/// The SQ completions of a session are bounded by its SQ depth, not by our receive window: the peer's credit grant
/// (its own window, up to `MAX_PEER_WINDOW`) can fill the whole SQ with SENDs, and QP ERR flushes every WR,
/// unsignalled SENDs included.
#[test]
fn cq_capacity_covers_every_session_sq_and_rejects_overflow() {
    let cfg = CoreCfg {
        srq_depth: 8,
        max_window: 4,
        sq_depth: 32,
        ..CoreCfg::default()
    };
    let mut credits = crate::credit::Credits::new(cfg.max_window, crate::credit::MIN_WINDOW);
    credits
        .on_recv(crate::credit::Imm::Credits(cfg.sq_depth).encode())
        .unwrap();
    let mut sq = crate::ring::SendQueue::new(cfg.sq_depth);
    while !sq.full() && credits.can_send_data() {
        credits.take_data();
        sq.push(crate::ring::NO_SLOT, false);
    }
    assert_eq!(sq.outstanding(), cfg.sq_depth, "a peer grant fills the SQ");
    let per_session = cfg.sq_depth;
    assert_eq!(
        cq_depth(cfg).unwrap() as u32,
        8 + cfg.max_sessions() * per_session
    );
    let capped = CoreCfg {
        session_limit: Some(1),
        ..cfg
    };
    assert_eq!(capped.max_sessions(), 1);
    assert_eq!(cq_depth(capped).unwrap() as u32, 8 + per_session);
    let fitted = fit_cq_sessions(cfg, 8 + 2 * per_session).unwrap();
    assert_eq!(fitted.max_sessions(), 2);
    assert_eq!(cq_depth(fitted).unwrap() as u32, 8 + 2 * per_session);
    let already_capped = fit_cq_sessions(capped, 8 + 2 * per_session).unwrap();
    assert_eq!(already_capped.max_sessions(), 1);
    assert_eq!(
        fit_cq_sessions(cfg, 8 + per_session - 1)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
    let huge = CoreCfg {
        srq_depth: 1 << 24,
        max_window: 1 << 20,
        sq_depth: 1 << 30,
        ..CoreCfg::default()
    };
    assert_eq!(
        cq_depth(huge).unwrap_err().kind(),
        io::ErrorKind::InvalidInput,
        "an oversized CQ requirement must not silently truncate"
    );
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_core_fits_actual_provider_cq_capacity() {
    let dev = device();
    let cfg = CoreCfg {
        srq_depth: 1024,
        tx_slots: 8,
        slot: crate::MIN_SLOT,
        ..CoreCfg::default()
    };
    let requested = cq_depth(cfg).unwrap() as u32;
    let fitted = fit_cq_sessions(cfg, dev.max_cqe()).unwrap();
    assert!(cq_depth(fitted).unwrap() as u32 <= dev.max_cqe());
    assert_eq!(
        fitted.max_sessions() < cfg.max_sessions(),
        requested > dev.max_cqe()
    );
    let core = Core::new(&dev, cfg).unwrap();
    assert_eq!(core.max_connections(), fitted.max_sessions() as usize);
}

/// A lost QP (CQ poll error) faults every accepted WRITE of a `PlacedReadWrite`:
/// neither `finish_success_verified` nor `finish_cancel` can produce a terminal
/// record; the link must report `placement_fault` (the client retains its window).
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_placed_readwrite_qp_loss_faults_without_terminal_record() {
    let dev = device();
    let (mut sender, mut receiver, sqpn, rqpn) = linked(&dev);
    let (window, range) = window(&dev);
    let local = receiver.bind_window(rqpn, window, range).expect("bind");
    wait_window(&mut receiver, &local, WindowState::Bound);
    let attempt = WindowAttempt {
        connection: 31,
        tid: 41,
        retry: 1,
    };
    let grant = local.advertise(&receiver, attempt).expect("advertise");
    let descriptor = grant.descriptor();
    let data = Bytes::from(vec![0xb3; 4096]);
    let registered = ZcMem::register_owned(&dev, data.clone()).expect("register pool");
    sender
        .set_zero_copy(registered, 4096)
        .expect("install pool registration");
    let sources = sender
        .prepare_write_sources(vec![data], 4096, 4096)
        .expect("source fits registered pool and grant");
    let mut owner = PlacedReadWrite::new(descriptor, sqpn);
    // SAFETY: the test holds the exact peer grant on this live connected QP.
    for source in sources {
        unsafe { owner.post(&mut sender, source) }.expect("post WRITE");
    }
    // Lose the QP: the CQ poll error faults every accepted WRITE.
    sender.inject_cq_error(-5);
    let mut faults = 0;
    sender.poll(|q, event| {
        if matches!(event, Event::Fault(_)) {
            assert_eq!(q, sqpn);
            faults += 1;
        }
    });
    assert_eq!(faults, 1, "lost CQ must fault the owning link exactly once");
    assert!(sender.broken().is_some());
    assert_eq!(sender.stats.cq_errors, 1);
    sender.poll(|_, event| assert!(!matches!(event, Event::Fault(_)), "fault reported twice"));
    // The owner cannot produce a success receipt (no CQE proof).
    assert_eq!(owner.state(), Some(WriteState::Failed));
    // CANCEL cannot complete either: the failed CQE cannot prove peer retirement.
    owner.cancel();
    assert!(
        owner.finish_cancel().is_err(),
        "a failed CQE cannot prove peer retirement"
    );
    drop(sender.detach(sqpn));
    drop(receiver.detach(rqpn));
}

/// The targeted lab fault cannot fire on rejected admission. Its successful
/// transition proves an accepted WRITE on the affected QP, and that WRITE's
/// ownership remains failed/retained rather than producing a success receipt.
#[cfg(all(feature = "memory-windows", feature = "fault-inject"))]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_accepted_write_fault_preserves_source_and_counts_exact_qp_transition() {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let dev = device();
    let (mut sender, mut receiver, sqpn, rqpn) = linked(&dev);
    let (window, range) = window(&dev);
    let local = receiver.bind_window(rqpn, window, range).unwrap();
    wait_window(&mut receiver, &local, WindowState::Bound);
    let grant = local
        .advertise(
            &receiver,
            WindowAttempt {
                connection: 1,
                tid: 2,
                retry: 0,
            },
        )
        .unwrap();
    // SAFETY: the test retains the authenticated peer's exact grant on this QP.
    let target = unsafe {
        RemoteWriteTarget::from_raw_parts(range.address(), range.length(), grant.descriptor().rkey)
    }
    .unwrap();
    let released = Arc::new(AtomicUsize::new(0));
    let source = WriteSource::register(
        &dev,
        Bytes::from_owner(ShutdownLease {
            bytes: Bytes::from(vec![0xa3; 4096]),
            released: released.clone(),
        }),
    )
    .unwrap();
    let source_range = source.range();
    let before = crate::fault::write_qp_err_state();
    assert_eq!(before.0, 0);
    crate::fault::arm_write_qp_err(1);
    let bad_range = MemoryRange::new(source_range.address(), source_range.length() + 1).unwrap();
    let rejected = sender.write(sqpn, source, bad_range, target).unwrap_err();
    assert_eq!(rejected.error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(crate::fault::write_qp_err_state(), (1, before.1, before.2));
    let retained = quarantined_write_sources();
    let handle = sender
        .write(sqpn, rejected.source, source_range, target)
        .unwrap();
    assert_eq!(
        crate::fault::write_qp_err_state(),
        (0, before.1 + 1, before.2)
    );
    assert_eq!(handle.state(), WriteState::Failed);
    assert_eq!(quarantined_write_sources(), retained + 1);
    let handle = handle.into_source().unwrap_err();
    drop(handle);
    assert_eq!(
        quarantined_write_sources(),
        retained + 1,
        "failure and drop share one quarantine mark"
    );
    assert_eq!(
        released.load(Relaxed),
        0,
        "failed source backing remains retained"
    );
    let mut faulted = false;
    sender.poll(|qpn, event| {
        if qpn == sqpn && matches!(event, Event::Fault(_)) {
            faulted = true;
        }
    });
    assert!(faulted, "accepted-WR fault must reach the owning link");
    // No destination CPU access or reuse follows this uncertain peer failure.
    drop(sender.detach(sqpn));
    drop(receiver.detach(rqpn));
    drop(grant);
    assert_eq!(
        released.load(Relaxed),
        0,
        "QP teardown cannot release the uncertain source"
    );
}

/// SQ backpressure: a queue-full admission pauses the attempt; the rejected piece
/// and every remaining source are kept for the next SQ progress. The attempt
/// resumes and completes once the CQEs free SQ room.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_placed_readwrite_sq_backpressure_keeps_every_source() {
    let before = (quarantined_windows(), teardown_failures(), leaked_cores());
    let dev = device();
    // Small SQ: only 4 slots, so 5+ WRITEs will hit WouldBlock.
    let mut sc = Core::new(
        &dev,
        CoreCfg {
            tx_slots: 4,
            sq_depth: 4,
            ..CoreCfg::default()
        },
    )
    .expect("sender core");
    let mut rc = Core::new(&dev, cfg()).expect("receiver core");
    let (qs, qr) = connect_pair(&dev, &mut sc, &mut rc, 1);
    let (window, range) = window(&dev);
    let local = rc.bind_window(qr, window, range).expect("bind");
    wait_window(&mut rc, &local, WindowState::Bound);
    let attempt = WindowAttempt {
        connection: 51,
        tid: 61,
        retry: 1,
    };
    let grant = local.advertise(&rc, attempt).expect("advertise");
    let descriptor = grant.descriptor();
    // 8 pieces of 512 bytes each = 4096 total (fits the 4096-byte grant).
    let data = Bytes::from(vec![0xc3; 4096]);
    let registered = ZcMem::register_owned(&dev, data.clone()).expect("register pool");
    sc.set_zero_copy(registered, 4096).expect("install pool");
    let sources = sc
        .prepare_write_sources(
            (0..8).map(|i| data.slice(i * 512..(i + 1) * 512)).collect(),
            4096,
            4096,
        )
        .expect("all pieces fit");
    let mut owner = PlacedReadWrite::new(descriptor, qs);
    let mut pending = Vec::new();
    // SAFETY: the test holds the exact peer grant on this live connected QP.
    let mut sources = sources.into_iter();
    while let Some(source) = sources.next() {
        match unsafe { owner.post(&mut sc, source) } {
            Ok(()) => {}
            Err(e) if e.error.kind() == std::io::ErrorKind::WouldBlock => {
                pending.push(e.source);
                pending.extend(sources);
                break;
            }
            Err(e) => panic!("unexpected post error: {}", e.error),
        }
    }
    assert!(
        !pending.is_empty(),
        "SQ backpressure must reject at least one piece"
    );
    let accepted = (8 - pending.len()) as u64;
    assert_eq!(sc.stats.tx_write_wrs, accepted);
    assert_eq!(sc.stats.tx_write_bytes, accepted * 512);
    assert_eq!(sc.stats.tx_write_doorbells, accepted);
    assert_eq!(sc.stats.tx_write_sq_stalls, 1);
    // Drain the CQ: the accepted WRITEs complete, freeing SQ room.
    let start = std::time::Instant::now();
    while owner.state() == Some(WriteState::Pending) {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT placed READ WRITE completion exceeded 10s"
        );
        sc.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
    }
    // Post the pending pieces as the SQ frees room: the completion that retired the full SQ also sent the credit
    // return the full SQ had deferred (the admission extras), and that unsignaled SEND holds a position until the next
    // signaled WR retires it. Every refusal hands the source back.
    let mut restalls = 0;
    let start = std::time::Instant::now();
    for mut source in pending {
        loop {
            // SAFETY: same grant, same QP.
            match unsafe { owner.post(&mut sc, source) } {
                Ok(()) => break,
                Err(e) if e.error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        start.elapsed() < std::time::Duration::from_secs(10),
                        "WARNING TIMEOUT placed READ pending WRITE post exceeded 10s"
                    );
                    restalls += 1;
                    source = e.source;
                    sc.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
                }
                Err(e) => panic!("unexpected post error: {}", e.error),
            }
        }
    }
    // Drain the CQ again: every WRITE completes.
    let start = std::time::Instant::now();
    while owner.state() == Some(WriteState::Pending) {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT placed READ pending WRITE completion exceeded 10s"
        );
        sc.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
    }
    assert_eq!(owner.state(), Some(WriteState::Complete));
    assert_eq!(sc.stats.tx_write_wrs, 8);
    assert_eq!(sc.stats.tx_write_bytes, 4096);
    assert_eq!(sc.stats.tx_write_doorbells, 8);
    assert_eq!(sc.stats.tx_write_sq_stalls, 1 + restalls);
    let verified = [crc::crc32c(0, &data)];
    let (receipt, _) = owner
        .finish_success_verified(&verified)
        .expect("all WRITEs complete");
    let decoded = ReadReceipt::decode(&receipt, descriptor).unwrap();
    assert_eq!(
        decoded.written_len(),
        4096,
        "all eight pieces must survive SQ refusal"
    );
    let buffer = retire_written_grant(&mut sc, &mut rc, qs, qr, grant, &receipt);
    let offset = (range.address() - buffer.as_ptr() as u64) as usize;
    assert!(buffer[offset..offset + 4096].iter().all(|b| *b == 0xc3));
    assert!(buffer[..offset].iter().all(|b| *b == 0x5a));
    assert!(buffer[offset + 4096..].iter().all(|b| *b == 0x5a));
    drop(sc.detach(qs));
    drop(rc.detach(qr));
    drop(sc);
    drop(rc);
    assert_eq!(
        (quarantined_windows(), teardown_failures(), leaked_cores()),
        before
    );
}

/// Parallel READs: two `PlacedReadWrite` owners on the same QP each complete
/// independently; neither overwrites the other's terminal state.
#[cfg(feature = "memory-windows")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_placed_readwrite_parallel_attempts_complete_independently() {
    let before = (quarantined_windows(), teardown_failures(), leaked_cores());
    let dev = device();
    let (mut sc, mut rc, qs, qr) = linked(&dev);
    let (window, range) = window(&dev);
    let local = rc.bind_window(qr, window, range).expect("bind");
    wait_window(&mut rc, &local, WindowState::Bound);
    let attempt_a = WindowAttempt {
        connection: 71,
        tid: 81,
        retry: 1,
    };
    let attempt_b = WindowAttempt {
        connection: 71,
        tid: 82,
        retry: 1,
    };
    let grant_a = local.advertise(&rc, attempt_a).expect("advertise A");
    let descriptor_a = grant_a.descriptor();
    let data = Bytes::from(vec![0xd7; 4096]);
    let registered = ZcMem::register_owned(&dev, data.clone()).expect("register pool");
    sc.set_zero_copy(registered, 4096).expect("install pool");
    let sources_a = sc
        .prepare_write_sources(vec![data.slice(0..2048)], 2048, 2048)
        .expect("piece A fits");
    let sources_b = sc
        .prepare_write_sources(vec![data.slice(2048..4096)], 2048, 2048)
        .expect("piece B fits");
    let mut owner_a = PlacedReadWrite::new(descriptor_a, qs);
    let descriptor_b = WindowDescriptor {
        attempt: attempt_b,
        range: descriptor_a.range.subrange(2048, 2048).expect("subrange B"),
        rkey: descriptor_a.rkey,
    };
    let mut owner_b = PlacedReadWrite::new(descriptor_b, qs);
    // SAFETY: the test holds the exact peer grants on this live connected QP.
    for source in sources_a {
        unsafe { owner_a.post(&mut sc, source) }.expect("post A");
    }
    for source in sources_b {
        unsafe { owner_b.post(&mut sc, source) }.expect("post B");
    }
    // Drain the CQ: both owners complete.
    let start = std::time::Instant::now();
    while owner_a.state() == Some(WriteState::Pending)
        || owner_b.state() == Some(WriteState::Pending)
    {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "WARNING TIMEOUT parallel placed READ completion exceeded 10s"
        );
        sc.poll(|q, e| assert!(!matches!(e, Event::Fault(_)), "sender {q}: {e:?}"));
    }
    assert_eq!(owner_a.state(), Some(WriteState::Complete));
    assert_eq!(owner_b.state(), Some(WriteState::Complete));
    let crc_a = crc::crc32c(0, &data[0..2048]);
    let crc_b = crc::crc32c(0, &data[2048..4096]);
    let (receipt_a, _) = owner_a
        .finish_success_verified(&[crc_a])
        .expect("A complete");
    let (receipt_b, _) = owner_b
        .finish_success_verified(&[crc_b])
        .expect("B complete");
    assert!(!receipt_a.is_empty());
    assert!(!receipt_b.is_empty());
    assert_ne!(
        receipt_a, receipt_b,
        "distinct attempts produce distinct receipts"
    );
    let buffer = retire_written_grant(&mut sc, &mut rc, qs, qr, grant_a, &receipt_a);
    let offset = (range.address() - buffer.as_ptr() as u64) as usize;
    assert!(buffer[offset..offset + 4096].iter().all(|b| *b == 0xd7));
    assert!(buffer[..offset].iter().all(|b| *b == 0x5a));
    assert!(buffer[offset + 4096..].iter().all(|b| *b == 0x5a));
    drop(sc.detach(qs));
    drop(rc.detach(qr));
    drop(sc);
    drop(rc);
    assert_eq!(
        (quarantined_windows(), teardown_failures(), leaked_cores()),
        before
    );
}
