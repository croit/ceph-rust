// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Real RXE transfers with a lab-only source MR. Production source export,
//! attempt protocol and GPU registration are deliberately outside this fixture.
use super::*;
use crate::verbs::{CoreCfg, Device, Event, Qp, ReadLimits};
use std::{
    io::Write,
    sync::atomic::AtomicUsize,
    time::{Duration, Instant},
};

fn before_deadline(deadline: Instant, operation: &str) {
    if Instant::now() < deadline {
        return;
    }
    let message = format!("WARNING TIMEOUT {operation} exceeded 10s (owned RXE READ fixture)");
    diag::diag!("{message}");
    if let Ok(path) = std::env::var("WARNINGS_FILE") {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(file, "{message}").unwrap();
    }
    panic!("{message}");
}

struct Source {
    bytes: Vec<u8>,
    mr: *mut ffi::Opaque,
    _dev: Arc<Device>,
}
impl Drop for Source {
    fn drop(&mut self) {
        // SAFETY: Fixture drops both cores/QPs before this MR and its bytes.
        assert_eq!(unsafe { ffi::rv_dereg(self.mr) }, 0);
    }
}
struct Fixture {
    reader: Core,
    responder: Core,
    source: Source,
    qpn: u32,
    writables: usize,
}
impl Fixture {
    fn new() -> Self {
        let ip = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
            .unwrap()
            .parse()
            .unwrap();
        let dev = Device::open(crate::gid_of(ip)).unwrap();
        let cfg = CoreCfg {
            srq_depth: 64,
            tx_slots: 8,
            sq_depth: 8,
            max_window: 16,
            ..CoreCfg::default()
        };
        let (mut reader, mut responder) =
            (Core::new(&dev, cfg).unwrap(), Core::new(&dev, cfg).unwrap());
        let (hr, hs) = (reader.handles(), responder.handles());
        let (r, s) = (
            Qp::create_for_reads(&dev, hr, 51).unwrap(),
            Qp::create_for_reads(&dev, hs, 52).unwrap(),
        );
        let caps = dev.read_limits().unwrap();
        assert!(caps.initiator >= 2 && caps.responder >= 2 && caps.max_sge != 0);
        let (er, es) = (r.endpoint(&hr), s.endpoint(&hs));
        r.connect_with_reads(
            &hr,
            &es,
            ReadLimits {
                initiator: 0,
                responder: 2,
                ..caps
            },
        )
        .unwrap();
        s.connect_with_reads(
            &hs,
            &er,
            ReadLimits {
                initiator: 2,
                responder: 0,
                ..caps
            },
        )
        .unwrap();
        let qpn = r.qpn();
        let cap = crate::grant::SessionCap::new(0);
        reader.attach(r, &es, cap.acquire().unwrap()).unwrap();
        responder.attach(s, &er, cap.acquire().unwrap()).unwrap();
        let bytes: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        // SAFETY: stable immutable bytes retained until both peer QPs are gone.
        let mr =
            unsafe { ffi::rv_test_read_source(dev.p, bytes.as_ptr().cast(), bytes.len() as u64) };
        assert!(!mr.is_null());
        Self {
            reader,
            responder,
            qpn,
            writables: 0,
            source: Source {
                bytes,
                mr,
                _dev: dev,
            },
        }
    }
    fn source(&self, offset: usize) -> RemoteReadSource {
        // SAFETY: lab-only grant on this fixture's authenticated pair. The
        // immutable MR/bytes outlive both cores, including on test unwinding.
        unsafe {
            RemoteReadSource::from_raw_parts(
                self.source.bytes.as_ptr().add(offset) as u64,
                4096,
                ffi::rv_test_mr_rkey(self.source.mr),
            )
            .unwrap()
        }
    }
    fn target(&self) -> ReadTarget {
        ReadTarget::prepare(HostDestination::register(&self.source._dev, vec![0; 4096]).unwrap())
    }
    fn poll(&mut self) -> usize {
        let mut received = 0;
        self.reader.poll(|_, e| {
            assert!(!matches!(e, Event::Fault(_)), "{e:?}");
            if matches!(e, Event::Writable) {
                self.writables += 1;
            }
        });
        self.responder.poll(|_, e| match e {
            Event::Data(data) => {
                assert!(data.iter().all(|b| *b == 77));
                received += data.len();
            }
            Event::Fault(error) => panic!("{error}"),
            _ => {}
        });
        received
    }
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_post_exact_bytes_mixed_send_reuse_and_prepared_allocations() {
    let mut f = Fixture::new();
    let before = quarantined_read_targets();
    let (a, b, extra) = (f.target(), f.target(), f.target());
    let address = a.destination().range().address();
    let source = f.source(0);
    let (a, allocations) = crate::test_alloc::count(|| f.reader.read(f.qpn, a, source));
    assert_eq!(allocations, 0);
    let a = a.unwrap();
    let other_source = f.source(4096);
    let b = f.reader.read(f.qpn, b, other_source).unwrap();
    let rejected = f.reader.read(f.qpn, extra, source).unwrap_err();
    assert_eq!(rejected.error.kind(), io::ErrorKind::WouldBlock);
    drop(rejected.target);
    assert_eq!(f.reader.send(f.qpn, &[77; 64]), 64);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut received = 0;
    while a.state() == ReadState::Pending || b.state() == ReadState::Pending || received != 64 {
        before_deadline(deadline, "rxe READ/SEND");
        let (bytes, allocations) = crate::test_alloc::count(|| f.poll());
        assert_eq!(allocations, 0);
        received += bytes;
    }
    let mut target = a.into_target().unwrap();
    assert!(
        f.writables > 0,
        "READ admission must resume through Writable"
    );
    assert!(!f.reader.conns[&f.qpn].read_waiting);
    assert_eq!(target.destination().range().address(), address);
    assert_eq!(target.destination().buffer(), &f.source.bytes[..4096]);
    assert_eq!(
        b.into_target().unwrap().destination().buffer(),
        &f.source.bytes[4096..]
    );
    for _ in 0..8 {
        target.destination_mut().buffer_mut().fill(0);
        let (posted, allocations) =
            crate::test_alloc::count(|| f.reader.read(f.qpn, target, source));
        assert_eq!(allocations, 0);
        let posted = posted.unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while posted.state() == ReadState::Pending {
            before_deadline(deadline, "rxe READ reuse");
            f.poll();
        }
        target = posted.into_target().unwrap();
        assert_eq!(target.destination().range().address(), address);
        assert_eq!(target.destination().buffer(), &f.source.bytes[..4096]);
    }
    assert_eq!(quarantined_read_targets(), before);
}

#[derive(Debug)]
struct Retained {
    bytes: Vec<u8>,
    dropped: Arc<AtomicUsize>,
}
impl Drop for Retained {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
fn retained_target(f: &Fixture, dropped: &Arc<AtomicUsize>) -> ReadTarget {
    let mut owner = Retained {
        bytes: vec![0; 4096],
        dropped: dropped.clone(),
    };
    // SAFETY: owner retains exclusive initialized CPU storage; there are no
    // other aliases and provider access is controlled by the destination owner.
    let foreign = unsafe {
        crate::host_memory::ForeignHostAllocation::from_raw_parts(
            owner.bytes.as_mut_ptr() as u64,
            4096,
            owner,
        )
        .unwrap()
    };
    ReadTarget::prepare(
        HostDestination::register_foreign_prepared(&f.source._dev, foreign).unwrap(),
    )
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_post_rejection_returns_only_unaccepted_foreign_owner() {
    let mut f = Fixture::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let before = quarantined_read_targets();
    let (a, b) = (retained_target(&f, &dropped), retained_target(&f, &dropped));
    let source = f.source(0);
    let a = f.reader.read(f.qpn, a, source).unwrap();
    f.reader.read_post_error = Some(-11);
    let rejected = f.reader.read(f.qpn, b, source).unwrap_err();
    assert_eq!(rejected.error.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(
        rejected
            .error
            .get_ref()
            .and_then(|e| e.downcast_ref::<io::Error>())
            .and_then(io::Error::raw_os_error),
        Some(11)
    );
    assert_eq!(a.state(), ReadState::Failed);
    assert!(a.into_target().is_err()); // failed accepted owner is quarantined on drop
    drop(rejected.target);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    assert_eq!(quarantined_read_targets(), before + 1);
    // Fixture destroys both QPs before its test source MR. The accepted target
    // remains retained even if a late success raced the observer failure.
    drop(f);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_post_lost_cq_keeps_exact_foreign_allocation() {
    let mut f = Fixture::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let target = retained_target(&f, &dropped);
    let source = f.source(0);
    let handle = f.reader.read(f.qpn, target, source).unwrap();
    f.reader.inject_cq_error(-5);
    let mut faults = 0;
    f.reader.poll(|_, e| {
        if matches!(e, Event::Fault(_)) {
            faults += 1;
        }
    });
    assert_eq!(faults, 1);
    assert_eq!(handle.state(), ReadState::Failed);
    drop(handle);
    drop(f);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_post_abandoned_pending_target_stays_retained_after_success() {
    let mut f = Fixture::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let before = quarantined_read_targets();
    let target = retained_target(&f, &dropped);
    let source = f.source(0);
    let handle = f.reader.read(f.qpn, target, source).unwrap();
    assert_eq!(handle.state(), ReadState::Pending);
    drop(handle);
    assert_eq!(quarantined_read_targets(), before + 1);
    let deadline = Instant::now() + Duration::from_secs(10);
    while f.reader.conns[&f.qpn].tx.sq.pending_reads() != 0 {
        before_deadline(deadline, "rxe abandoned READ retirement");
        f.poll();
    }
    drop(f);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    assert_eq!(quarantined_read_targets(), before + 1);
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_post_old_epoch_cq_cannot_publish_reused_sequence() {
    let mut f = Fixture::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let old_target = retained_target(&f, &dropped);
    let new_target = f.target();
    let source = f.source(0);
    let old = f.reader.read(f.qpn, old_target, source).unwrap();
    // Test-only bookkeeping replacement keeps the real old CQE queued while
    // assigning the same numeric SQ sequence to the next logical generation.
    // This is not a physical QP destroy/recreate or peer-grant protocol test.
    f.reader.reuse_qpn(f.qpn);
    assert_eq!(old.state(), ReadState::Failed);
    let fresh = f.reader.read(f.qpn, new_target, source).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while fresh.state() == ReadState::Pending || f.reader.stats.tx_stale == 0 {
        before_deadline(deadline, "rxe READ old epoch");
        f.poll();
    }
    let target = fresh.into_target().unwrap();
    assert_eq!(target.destination().buffer(), &f.source.bytes[..4096]);
    assert_eq!(old.state(), ReadState::Failed);
    drop(old);
    drop(f);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_buffer_publication_and_reuse_preserve_bytes_address_without_allocations() {
    use crate::verbs::PreparedReadBuffer;
    let mut f = Fixture::new();
    let mut buffer = PreparedReadBuffer::prepare(&f.source._dev, 4096).unwrap();
    let range = buffer.range();
    assert_eq!(range.address() % 4096, 0);
    let source = f.source(0);
    for _ in 0..12 {
        let (pending, allocations) =
            crate::test_alloc::count(|| f.reader.read_buffer(f.qpn, buffer, source).unwrap());
        assert_eq!(allocations, 0);
        let pending = pending.try_finish().unwrap_err();
        let start = Instant::now() + Duration::from_secs(10);
        while pending.state() == ReadState::Pending {
            before_deadline(start, "reusable buffer READ");
            f.poll();
        }
        let (shared, allocations) = crate::test_alloc::count(|| pending.try_finish().unwrap());
        assert_eq!(allocations, 0);
        assert_eq!(shared.bytes().as_ptr() as u64, range.address());
        assert_eq!(&shared.bytes()[..], &f.source.bytes[..4096]);
        let lease = shared.bytes().clone();
        let slice = lease.slice(17..100);
        let shared = shared.try_reuse().unwrap_err();
        drop(lease);
        let shared = shared.try_reuse().unwrap_err();
        drop(slice);
        let (reused, allocations) = crate::test_alloc::count(|| shared.try_reuse().unwrap());
        assert_eq!(allocations, 0);
        buffer = reused;
        assert_eq!(buffer.range(), range);
    }
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_buffer_refusal_preserves_owner_and_lost_cq_retains_backing() {
    use crate::verbs::PreparedReadBuffer;
    let mut f = Fixture::new();
    let buffer = PreparedReadBuffer::prepare(&f.source._dev, 4096).unwrap();
    let range = buffer.range();
    let weak = buffer.test_owner();
    let source = f.source(0);
    let rejected = f
        .reader
        .read_buffer(f.qpn, buffer, source.subrange(0, 1).unwrap())
        .unwrap_err();
    assert_eq!(rejected.error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(rejected.buffer.range(), range);
    let pending = f
        .reader
        .read_buffer(f.qpn, rejected.buffer, source)
        .unwrap();
    f.reader.inject_cq_error(-5);
    f.reader.poll(|_, e| assert!(matches!(e, Event::Fault(_))));
    assert_eq!(pending.state(), ReadState::Failed);
    let pending = pending.try_finish().unwrap_err();
    drop(pending);
    drop(f);
    assert!(
        weak.upgrade().is_some(),
        "failed accepted DMA keeps the exact allocation owner"
    );
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_buffer_consumer_outlives_registration_without_reusing_its_storage() {
    use crate::verbs::PreparedReadBuffer;
    let mut f = Fixture::new();
    let buffer = PreparedReadBuffer::prepare(&f.source._dev, 4096).unwrap();
    let weak = buffer.test_owner();
    let source = f.source(0);
    let pending = f.reader.read_buffer(f.qpn, buffer, source).unwrap();
    let start = Instant::now() + Duration::from_secs(10);
    while pending.state() == ReadState::Pending {
        before_deadline(start, "published buffer owner");
        f.poll();
    }
    let shared = pending.try_finish().unwrap();
    let bytes = shared.bytes().clone();
    let address = bytes.as_ptr();
    drop(shared);
    assert!(
        weak.upgrade().is_none(),
        "registration owner retired on the control caller"
    );
    drop(f);
    assert_eq!(bytes.as_ptr(), address);
    assert!(bytes.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
}

/// `abandon_read` keeps a range only on the exact QP the READ was posted on: after its QP number names a newer
/// connection (number reused, new generation), that connection's destroy proves nothing about the old READ, so the
/// range is quarantined for good (counted) and never retained on (or released with) the newer QP.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_abandon_after_qpn_reuse_quarantines_instead_of_retaining() {
    let mut f = Fixture::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut owner = Retained {
        bytes: vec![0; 2 * 4096],
        dropped: dropped.clone(),
    };
    let address = (owner.bytes.as_mut_ptr() as u64).next_multiple_of(4096);
    // SAFETY: the aligned 4 KiB subrange lies inside the owner's initialized heap storage, which never moves and has
    // no other aliases; provider access is controlled by the registration.
    let allocation = unsafe {
        crate::host_memory::ForeignHostAllocation::from_raw_parts(address, 4096, owner).unwrap()
    };
    let mut registration =
        SharedHostRegistration::register(&f.source._dev, allocation, 1, None).unwrap();
    let target = ReadTarget::prepare(registration.try_lease(0, 4096).unwrap());
    let source = f.source(0);
    let handle = f.reader.read(f.qpn, target, source).unwrap();
    f.reader.reuse_qpn(f.qpn);
    let before = quarantined_read_targets();
    f.reader.abandon_read(handle, &mut registration);
    assert_eq!(quarantined_read_targets(), before + 1);
    assert!(
        f.reader
            .conns
            .get_mut(&f.qpn)
            .unwrap()
            .qp
            .retained()
            .reads
            .is_empty(),
        "the newer connection on the reused number must not own the old READ's range"
    );
    drop(f);
    drop(registration);
    assert_eq!(
        dropped.load(Ordering::Relaxed),
        0,
        "the quarantined backing stays"
    );
}
