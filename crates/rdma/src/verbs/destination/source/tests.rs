// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Actual READ-only type-2 BIND/READ/LOCAL_INV on owned RXE.
use super::*;
use crate::verbs::{
    CoreCfg, Device, Event, HostDestination, Qp, ReadLimits, ReadState, ReadTarget,
};
use std::{
    io,
    io::Write,
    sync::Arc,
    time::{Duration, Instant},
};

pub(super) fn deadline(operation: &str, start: Instant) {
    if start.elapsed() < Duration::from_secs(10) {
        return;
    }
    let message = format!("WARNING TIMEOUT {operation} exceeded 10s (owned RXE source window)");
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

pub(super) fn device() -> Arc<Device> {
    let ip = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
        .unwrap()
        .parse()
        .unwrap();
    Device::open(crate::gid_of(ip)).unwrap()
}

pub(super) fn pair(dev: &Arc<Device>) -> (Core, Core, u32, u32) {
    let cfg = CoreCfg {
        srq_depth: 64,
        tx_slots: 8,
        sq_depth: 8,
        max_window: 16,
        ..CoreCfg::default()
    };
    let (mut reader, mut source) = (Core::new(dev, cfg).unwrap(), Core::new(dev, cfg).unwrap());
    let (hr, hs) = (reader.handles(), source.handles());
    let (r, s) = (
        Qp::create_for_reads(dev, hr, 71).unwrap(),
        Qp::create_for_reads(dev, hs, 72).unwrap(),
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
    let (qr, qs) = (r.qpn(), s.qpn());
    let cap = crate::grant::SessionCap::new(0);
    reader.attach(r, &es, cap.acquire().unwrap()).unwrap();
    source.attach(s, &er, cap.acquire().unwrap()).unwrap();
    (reader, source, qr, qs)
}

pub(super) fn poll(core: &mut Core) {
    core.poll(|_, e| assert!(!matches!(e, Event::Fault(_)), "{e:?}"));
}

fn bound(source: &mut Core, window: &LocalReadSource) {
    let start = Instant::now();
    while window.state() == WindowState::Binding {
        deadline("source BIND", start);
        poll(source);
    }
    assert_eq!(window.state(), WindowState::Bound);
}

fn retire(source: &mut Core, window: &mut AdvertisedReadSource) {
    window.invalidate(source).unwrap();
    let start = Instant::now();
    while window.state() == WindowState::Invalidating {
        deadline("source LOCAL_INV", start);
        poll(source);
    }
    assert_eq!(window.state(), WindowState::Retired);
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_source_reuses_exact_parent_and_window_across_key_wrap() {
    let dev = device();
    let (mut reader, mut source, qr, qs) = pair(&dev);
    let data: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let address = data.as_ptr() as u64;
    let parent = HostDestination::register_prepared(&dev, data).unwrap();
    let range = parent.range();
    let mut unbound = UnboundWindow::allocate(parent).unwrap();
    let mut target = ReadTarget::prepare(HostDestination::register(&dev, vec![0; 4096]).unwrap());
    let mut first = None;
    let mut wrapped = false;
    for tid in 1..=260 {
        let (local, allocations) =
            crate::test_alloc::count(|| source.bind_read_source(qs, unbound, range));
        assert_eq!(allocations, 0);
        let local = local.unwrap();
        bound(&mut source, &local);
        let attempt = WindowAttempt {
            connection: 91,
            tid,
            retry: 0,
        };
        let (published, allocations) =
            crate::test_alloc::count(|| local.advertise(&source, attempt).unwrap());
        assert_eq!(allocations, 0);
        let mut published = published;
        let descriptor = published.descriptor();
        assert_eq!(descriptor.range.address(), address);
        let oldest = *first.get_or_insert(descriptor);
        if tid > 1 && descriptor.rkey == oldest.rkey {
            wrapped = true;
            // SAFETY: this test supplies a mismatching retired attempt; the
            // identity check must refuse it before granting any owner transition.
            assert!(!unsafe {
                published.confirm_peer_retired_unchecked(oldest.attempt, oldest.rkey)
            });
        }
        assert_eq!(
            published.invalidate(&mut source).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        // SAFETY: this fixture owns both connected endpoints and this exact
        // immutable source grant. No future READ is posted after the local CQ.
        let grant = unsafe { descriptor.remote_source().unwrap() };
        let (handle, allocations) = crate::test_alloc::count(|| reader.read(qr, target, grant));
        assert_eq!(allocations, 0);
        let handle = handle.unwrap();
        let start = Instant::now();
        while handle.state() == ReadState::Pending {
            deadline("source READ", start);
            poll(&mut reader);
        }
        target = handle.into_target().unwrap();
        assert!(
            target
                .destination()
                .buffer()
                .iter()
                .enumerate()
                .all(|(i, b)| *b == (i % 251) as u8)
        );
        // SAFETY: exact READ success observed, no other READ was accepted or
        // queued, and this fixture stops all admission for the advertised attempt.
        assert!(unsafe { published.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
        let (_, allocations) = crate::test_alloc::count(|| retire(&mut source, &mut published));
        assert_eq!(allocations, 0);
        let (recovered, allocations) =
            crate::test_alloc::count(|| published.into_unbound().unwrap());
        assert_eq!(allocations, 0);
        unbound = recovered;
    }
    assert!(
        wrapped,
        "actual provider key must wrap during the 260 bindings"
    );
    let bytes = unbound.into_destination().unwrap().into_buffer().unwrap();
    assert_eq!(bytes.as_ptr() as u64, address);
    assert!(bytes.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_source_requires_explicit_responder_setup_and_returns_unaccepted_parent() {
    let dev = device();
    let (mut ordinary, _peer, q, _) = crate::verbs::rxe_tests::linked(&dev);
    let parent = HostDestination::register_prepared(&dev, vec![8; 4096]).unwrap();
    let range = parent.range();
    let window = UnboundWindow::allocate(parent).unwrap();
    let rejected = ordinary.bind_read_source(q, window, range).unwrap_err();
    assert_eq!(rejected.error.kind(), io::ErrorKind::Unsupported);
    let bytes = rejected
        .window
        .into_destination()
        .unwrap()
        .into_buffer()
        .unwrap();
    assert_eq!(bytes.as_ptr() as u64, range.address());
    assert_eq!(bytes, vec![8; 4096]);
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_source_unpublished_retraction_still_requires_local_retirement() {
    let dev = device();
    let (_reader, mut source, _, qs) = pair(&dev);
    let parent = HostDestination::register_prepared(&dev, vec![9; 4096]).unwrap();
    let range = parent.range();
    let window = UnboundWindow::allocate(parent).unwrap();
    let local = source.bind_read_source(qs, window, range).unwrap();
    bound(&mut source, &local);
    let published = local
        .advertise(
            &source,
            WindowAttempt {
                connection: 91,
                tid: 1,
                retry: 0,
            },
        )
        .unwrap();
    // SAFETY: no descriptor was obtained, queued or exposed to any peer.
    let local = unsafe { published.retract_unpublished() };
    let mut local = local.into_unbound().unwrap_err();
    local.invalidate(&mut source).unwrap();
    let start = Instant::now();
    while local.state() == WindowState::Invalidating {
        deadline("unpublished source LOCAL_INV", start);
        poll(&mut source);
    }
    let parent = local.into_unbound().unwrap().into_destination().unwrap();
    assert_eq!(parent.range(), range);
    assert_eq!(parent.into_buffer().unwrap(), vec![9; 4096]);
}

#[derive(Debug)]
struct ForeignSource {
    bytes: Vec<u8>,
    released: Arc<std::sync::atomic::AtomicUsize>,
}
impl Drop for ForeignSource {
    fn drop(&mut self) {
        self.released
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_source_foreign_owner_released_once_after_peer_and_local_retirement() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dev = device();
    let (mut reader, mut source, qr, qs) = pair(&dev);
    let released = Arc::new(AtomicUsize::new(0));
    let mut owner = ForeignSource {
        bytes: vec![93; 4096],
        released: released.clone(),
    };
    let address = owner.bytes.as_mut_ptr() as u64;
    // SAFETY: exclusive initialized CPU allocation, retained without external
    // aliases; the window owner excludes CPU access throughout peer DMA.
    let foreign = unsafe {
        crate::host_memory::ForeignHostAllocation::from_raw_parts(address, 4096, owner).unwrap()
    };
    let parent = HostDestination::register_foreign_prepared(&dev, foreign).unwrap();
    let range = parent.range();
    let local = source
        .bind_read_source(qs, UnboundWindow::allocate(parent).unwrap(), range)
        .unwrap();
    bound(&mut source, &local);
    let attempt = WindowAttempt {
        connection: 92,
        tid: 1,
        retry: 0,
    };
    let mut published = local.advertise(&source, attempt).unwrap();
    let descriptor = published.descriptor();
    let target = ReadTarget::prepare(HostDestination::register(&dev, vec![0; 4096]).unwrap());
    // SAFETY: exact live grant on the fixture's pair; no READ is admitted after this transfer.
    let handle = reader
        .read(qr, target, unsafe { descriptor.remote_source().unwrap() })
        .unwrap();
    let start = Instant::now();
    while handle.state() == ReadState::Pending {
        deadline("foreign source READ", start);
        poll(&mut reader);
    }
    let target = handle.into_target().unwrap();
    assert!(target.destination().buffer().iter().all(|b| *b == 93));
    assert_eq!(released.load(Ordering::Relaxed), 0);
    // SAFETY: every accepted READ completed and all further admission stopped.
    assert!(unsafe { published.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
    retire(&mut source, &mut published);
    assert_eq!(released.load(Ordering::Relaxed), 0);
    let parent = published
        .into_unbound()
        .unwrap()
        .into_destination()
        .unwrap();
    let foreign = parent.into_foreign().unwrap();
    assert_eq!(foreign.range().address(), address);
    assert!(foreign.buffer().iter().all(|b| *b == 93));
    drop(foreign.into_owner());
    assert_eq!(released.load(Ordering::Relaxed), 1);
}

/// A session that ends without the peer's retirement proof abandons its windows to the QP: nothing is released
/// while the QP lives; its teardown (ERR, MW deallocation, destroy) releases MW, parent MR and the foreign owner,
/// nothing is quarantined.
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_abandoned_read_source_released_after_qp_destroy() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dev = device();
    let (mut reader, mut source, qr, qs) = pair(&dev);
    let released = Arc::new(AtomicUsize::new(0));
    let (quarantined, failures) = (
        crate::verbs::quarantined_windows(),
        crate::verbs::teardown_failures(),
    );
    let mut window = |fill: u8| {
        let mut owner = ForeignSource {
            bytes: vec![fill; 4096],
            released: released.clone(),
        };
        let address = owner.bytes.as_mut_ptr() as u64;
        // SAFETY: exclusive initialized CPU allocation, retained without external aliases.
        let foreign = unsafe {
            crate::host_memory::ForeignHostAllocation::from_raw_parts(address, 4096, owner).unwrap()
        };
        let parent = HostDestination::register_foreign_prepared(&dev, foreign).unwrap();
        let range = parent.range();
        let local = source
            .bind_read_source(qs, UnboundWindow::allocate(parent).unwrap(), range)
            .unwrap();
        bound(&mut source, &local);
        local
    };
    let unpublished = window(1);
    let published = window(2);
    let attempt = WindowAttempt {
        connection: 93,
        tid: 1,
        retry: 0,
    };
    let published = published.advertise(&source, attempt).unwrap();
    let descriptor = published.descriptor();
    let target = ReadTarget::prepare(HostDestination::register(&dev, vec![0; 4096]).unwrap());
    // SAFETY: exact live grant on the fixture's pair.
    let handle = reader
        .read(qr, target, unsafe { descriptor.remote_source().unwrap() })
        .unwrap();
    let start = Instant::now();
    while handle.state() == ReadState::Pending {
        deadline("abandoned source READ", start);
        poll(&mut reader);
    }
    assert!(
        handle
            .into_target()
            .unwrap()
            .destination()
            .buffer()
            .iter()
            .all(|b| *b == 2)
    );
    // The session ends: no answer, no LOCAL_INV.
    source.abandon_read_source(unpublished);
    source.abandon_published_read_source(published);
    let detached = source.detach(qs).expect("attached");
    assert_eq!(
        released.load(Ordering::Relaxed),
        0,
        "retained while the QP lives"
    );
    detached
        .qp
        .destroy()
        .expect("MWs deallocated, then the QP destroyed");
    assert_eq!(
        released.load(Ordering::Relaxed),
        2,
        "parents released after the destroy"
    );
    assert_eq!(crate::verbs::quarantined_windows(), quarantined);
    assert_eq!(crate::verbs::teardown_failures(), failures);
    drop(reader.detach(qr));
}

#[cfg(feature = "fault-inject")]
pub(super) mod negative {
    use super::*;
    use crate::verbs::ffi;

    // Field order also protects unexpected assertion/timeout unwinding: stop
    // both QPs before releasing the probe target or any source registration.
    pub(in crate::verbs::destination::source) struct Probe<P> {
        pub(in crate::verbs::destination::source) reader: Core,
        pub(in crate::verbs::destination::source) source: Core,
        pub(in crate::verbs::destination::source) backing: P,
        pub(in crate::verbs::destination::source) target: HostDestination,
    }
    impl<P> Probe<P> {
        pub(in crate::verbs::destination::source) fn access_denied(
            &mut self,
            qpn: u32,
            range: MemoryRange,
            rkey: u32,
            write: bool,
        ) {
            let (_, lkey) = self.target.read_registration();
            let local = self.target.range();
            let qp = &self.reader.conns[&qpn].qp;
            const ID: u64 = 0x51_0000;
            // SAFETY: deliberately unauthorized provider request in an owned
            // fixture, bypassing the safe live-grant API. Both addressed buffers
            // and their MRs remain live and inaccessible to CPU aliases until
            // both QPs are stopped, including if permission unexpectedly succeeds.
            let rc = unsafe {
                if write {
                    ffi::rv_post_write(qp.p, ID, local.address(), 4096, lkey, range.address(), rkey)
                } else {
                    ffi::rv_post_read(qp.p, ID, local.address(), 4096, lkey, range.address(), rkey)
                }
            };
            assert_eq!(rc, 0);
            let start = Instant::now();
            let mut completions = [ffi::Wc::default(); 32];
            loop {
                deadline("source permission denial CQ", start);
                // SAFETY: one owner polls its live CQ into valid scratch. This
                // terminal fault probe performs no further Core progress/reuse.
                let n = unsafe { ffi::rv_poll(self.reader.cq, completions.as_mut_ptr(), 32) };
                assert!(n >= 0);
                for wc in &completions[..n as usize] {
                    if wc.wr_id != ID {
                        continue;
                    }
                    // SAFETY: provider returns a static NUL-terminated status string.
                    let status =
                        unsafe { std::ffi::CStr::from_ptr(ffi::rv_wc_str(wc.status as i32)) };
                    assert_eq!(status.to_bytes(), b"remote access error");
                    return;
                }
            }
        }
        pub(in crate::verbs::destination::source) fn finish(self) {
            let Self {
                reader,
                source,
                backing,
                target,
            } = self;
            drop((reader, source));
            drop((backing, target));
        }
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_read_source_negative_parent_and_revoked_window_keys_are_denied() {
        for parent_key in [true, false] {
            let dev = device();
            let (reader, mut source, qr, qs) = pair(&dev);
            let parent = HostDestination::register_prepared(&dev, vec![41; 4096]).unwrap();
            let range = parent.range();
            // SAFETY: test-only observation of a live parent MR key; this key is
            // never exposed by the production source descriptor API.
            let mr_key = unsafe { ffi::rv_test_mr_rkey(parent.mr) };
            let local = source
                .bind_read_source(qs, UnboundWindow::allocate(parent).unwrap(), range)
                .unwrap();
            bound(&mut source, &local);
            let mut published = local
                .advertise(
                    &source,
                    WindowAttempt {
                        connection: 93,
                        tid: 1,
                        retry: 0,
                    },
                )
                .unwrap();
            let descriptor = published.descriptor();
            // SAFETY: no descriptor was ever sent and no peer READ was admitted.
            assert!(unsafe {
                published.confirm_peer_retired_unchecked(descriptor.attempt, descriptor.rkey)
            });
            retire(&mut source, &mut published);
            let backing = published.into_unbound().unwrap();
            let target = HostDestination::register(&dev, vec![0; 4096]).unwrap();
            let mut probe = Probe {
                reader,
                source,
                backing,
                target,
            };
            probe.access_denied(
                qr,
                range,
                if parent_key { mr_key } else { descriptor.rkey },
                false,
            );
            probe.finish();
        }
    }

    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn rxe_read_source_negative_write_is_denied_and_unretired_grant_is_retained() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dev = device();
        let (reader, mut source, qr, qs) = pair(&dev);
        let released = Arc::new(AtomicUsize::new(0));
        let mut owner = ForeignSource {
            bytes: vec![42; 4096],
            released: released.clone(),
        };
        // SAFETY: exclusive stable initialized CPU allocation; the source
        // window retains its only owner through this negative provider probe.
        let foreign = unsafe {
            crate::host_memory::ForeignHostAllocation::from_raw_parts(
                owner.bytes.as_mut_ptr() as u64,
                4096,
                owner,
            )
            .unwrap()
        };
        let parent = HostDestination::register_foreign_prepared(&dev, foreign).unwrap();
        let range = parent.range();
        let local = source
            .bind_read_source(qs, UnboundWindow::allocate(parent).unwrap(), range)
            .unwrap();
        bound(&mut source, &local);
        let backing = local
            .advertise(
                &source,
                WindowAttempt {
                    connection: 94,
                    tid: 1,
                    retry: 0,
                },
            )
            .unwrap();
        let descriptor = backing.descriptor();
        let target = HostDestination::register(&dev, vec![99; 4096]).unwrap();
        let before = crate::verbs::quarantined_windows();
        let mut probe = Probe {
            reader,
            source,
            backing,
            target,
        };
        probe.access_denied(qr, range, descriptor.rkey, true);
        // No peer-retirement/LOCAL_INV proof: ordinary teardown must retain the
        // unretired MW, QP reference and source allocation rather than grant reuse.
        probe.finish();
        assert_eq!(crate::verbs::quarantined_windows(), before + 1);
        assert_eq!(released.load(Ordering::Relaxed), 0);
    }
}

/// A PUT source on a GPU registration (host mock, the same MR access bits as the client's GET registration): each
/// attempt window is a READ-only MW over exactly the source's sub-range of the region's MR; the peer reads exactly
/// those bytes. The source's watch lives while the source or any of its windows lives: a window abandoned with its
/// session keeps it until the QP's destroy.
#[cfg(feature = "gpu")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_gpu_source_window_reads_exactly_its_subrange_and_holds_the_source() {
    use crate::gpu::{GpuAccess, GpuRegion, GpuSource};
    let dev = device();
    let (mut reader, mut source, qr, qs) = pair(&dev);
    let mut region_bytes: Vec<u8> = (0..3 * 4096).map(|i| (i / 4096 + 1) as u8).collect();
    let base = region_bytes.as_mut_ptr() as u64;
    // SAFETY: `region_bytes` outlives the region and is not touched while it lives.
    let region =
        unsafe { GpuRegion::register_host(&dev, base, 3 * 4096, GpuAccess::Write) }.unwrap();
    let range = crate::memory::MemoryRange::new(base + 4096, 4096).unwrap();
    let gpu = GpuSource::new(Arc::clone(&region), range).unwrap();
    let held = gpu.release_watch();
    let read_once = |source: &mut Core, reader: &mut Core, retry: u32| {
        let parent = gpu.window().unwrap();
        assert_eq!(parent.range(), range);
        let window = parent.borrowed_release_watch().unwrap();
        let local = source
            .bind_read_source(qs, UnboundWindow::allocate(parent).unwrap(), range)
            .unwrap();
        bound(source, &local);
        let attempt = WindowAttempt {
            connection: 94,
            tid: 1,
            retry,
        };
        let published = local.advertise(source, attempt).unwrap();
        let descriptor = published.descriptor();
        assert_eq!(descriptor.range, range);
        let target = ReadTarget::prepare(HostDestination::register(&dev, vec![0; 4096]).unwrap());
        // SAFETY: exact live grant on the fixture's pair; no READ is admitted after this transfer.
        let handle = reader
            .read(qr, target, unsafe { descriptor.remote_source().unwrap() })
            .unwrap();
        let start = Instant::now();
        while handle.state() == ReadState::Pending {
            deadline("GPU source READ", start);
            poll(reader);
        }
        let target = handle.into_target().unwrap();
        assert!(target.destination().buffer().iter().all(|b| *b == 2));
        (published, attempt, window)
    };
    // Attempt 0 is answered: peer retirement, LOCAL_INV, the window is gone.
    let (mut published, attempt, window) = read_once(&mut source, &mut reader, 0);
    let rkey = published.descriptor().rkey;
    // SAFETY: every accepted READ completed and all further admission stopped.
    assert!(unsafe { published.confirm_peer_retired_unchecked(attempt, rkey) });
    retire(&mut source, &mut published);
    drop(published);
    assert_eq!(window.strong_count(), 0);
    assert_eq!(held.strong_count(), 1);
    // Attempt 1's session ends without an answer: its QP keeps the window, and the window the source.
    let (published, _, window) = read_once(&mut source, &mut reader, 1);
    source.abandon_published_read_source(published);
    drop(gpu);
    let detached = source.detach(qs).expect("attached");
    assert_eq!(window.strong_count(), 1, "retained while the QP lives");
    assert_eq!(
        held.strong_count(),
        1,
        "the retained window holds the source"
    );
    detached
        .qp
        .destroy()
        .expect("MW deallocated, then the QP destroyed");
    assert_eq!(window.strong_count(), 0);
    assert_eq!(
        held.strong_count(),
        0,
        "the source is free after the destroy"
    );
    drop(reader.detach(qr));
    drop(region);
    drop(region_bytes);
}

/// The window-release notice of a GPU registration runs after every hold of the released window on the region is
/// gone: an owner that releases the registration from the notice (rados-ffi, synchronous) sees the MR deregistered,
/// never a still-live MR it would report as a failed deregistration.
#[cfg(feature = "gpu")]
#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_gpu_window_release_notice_follows_parent_release() {
    use crate::gpu::{GpuAccess, GpuRegion, GpuSource};
    use std::sync::atomic::{AtomicU8, Ordering};
    let dev = device();
    let mut region_bytes = vec![0u8; 4096];
    let base = region_bytes.as_mut_ptr() as u64;
    // SAFETY: `region_bytes` outlives the region and is not touched while it lives.
    let region = unsafe { GpuRegion::register_host(&dev, base, 4096, GpuAccess::Read) }.unwrap();
    let mr = region.release_watch();
    // 1 = notified with the MR deregistered, 2 = notified while the MR was still registered
    let seen = Arc::new(AtomicU8::new(0));
    let (watch, notice) = (mr.clone(), Arc::clone(&seen));
    region.notify_window_release(move || {
        let state = if watch.strong_count() == 0 { 1 } else { 2 };
        notice.store(state, Ordering::Release);
    });
    let range = crate::memory::MemoryRange::new(base, 4096).unwrap();
    let source = GpuSource::new(region, range).unwrap();
    // the source holds the last reference of the region: dropping it releases the MR and notifies
    drop(source);
    assert_eq!(
        seen.load(Ordering::Acquire),
        1,
        "notified before the MR was released"
    );
    assert_eq!(mr.strong_count(), 0);
    drop(region_bytes);
}
