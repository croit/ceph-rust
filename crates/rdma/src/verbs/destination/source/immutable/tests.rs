// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Actual READ-only MR/MW export of shared immutable host bytes.
use super::super::tests::{deadline, device, negative::Probe, pair, poll};
use super::*;
use crate::verbs::{PreparedReadBuffer, ReadState};
use std::time::Instant;

#[test]
#[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shared_read_source_keeps_aliases_and_reuses_exact_slice_without_allocations() {
    let dev = device();
    let (mut reader, mut source, qr, qs) = pair(&dev);
    let data = Bytes::from((0..16384).map(|i| (i % 251) as u8).collect::<Vec<_>>());
    let alias = data.clone();
    let piece = data.slice(17..8192 + 17);
    let address = piece.as_ptr() as u64;
    let mut prepared = PreparedReadSource::register(&dev, piece).unwrap();
    let range = prepared.range().subrange(17, 4096).unwrap();
    let mut target = PreparedReadBuffer::prepare(&dev, 4096).unwrap();
    let mut oldest = None;
    let mut wrapped = false;
    for tid in 1..=260 {
        let (result, allocations) = crate::test_alloc::count(|| {
            source.bind_shared_read_source(qs, prepared, range).unwrap()
        });
        assert_eq!(allocations, 0);
        let local = result;
        let start = Instant::now();
        while local.state() == WindowState::Binding {
            deadline("immutable source BIND", start);
            poll(&mut source);
        }
        let attempt = WindowAttempt {
            connection: 1,
            tid,
            retry: 0,
        };
        let (mut advertised, allocations) =
            crate::test_alloc::count(|| local.advertise(&source, attempt).unwrap());
        assert_eq!(allocations, 0);
        let descriptor = advertised.descriptor();
        assert_eq!(descriptor.range, range);
        let first = *oldest.get_or_insert(descriptor);
        if tid > 1 && first.rkey == descriptor.rkey {
            wrapped = true;
            // SAFETY: intentionally mismatching retired attempt is rejected.
            assert!(!unsafe {
                advertised.confirm_peer_retired_unchecked(first.attempt, first.rkey)
            });
        }
        assert_eq!(
            advertised.invalidate(&mut source).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        // SAFETY: exact source grant on the fixture's owned connected pair.
        let grant = unsafe { descriptor.remote_source().unwrap() };
        let pending = reader.read_buffer(qr, target, grant).unwrap();
        let start = Instant::now();
        while pending.state() == ReadState::Pending {
            deadline("immutable source READ", start);
            poll(&mut reader);
        }
        let shared = pending.try_finish().unwrap();
        assert_eq!(shared.bytes().as_ref(), &alias[34..34 + 4096]);
        assert_eq!(data.as_ref(), alias.as_ref());
        target = shared.try_reuse().unwrap();
        // SAFETY: exact accepted READ CQ consumed and all future admission stopped.
        assert!(unsafe { advertised.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
        let (result, allocations) = crate::test_alloc::count(|| advertised.invalidate(&mut source));
        assert_eq!(allocations, 0);
        result.unwrap();
        let start = Instant::now();
        while advertised.state() == WindowState::Invalidating {
            deadline("immutable source LOCAL_INV", start);
            poll(&mut source);
        }
        let (recovered, allocations) =
            crate::test_alloc::count(|| advertised.try_recover().unwrap());
        assert_eq!(allocations, 0);
        prepared = recovered;
        assert_eq!(prepared.bytes().as_ptr() as u64, address);
        assert_eq!(prepared.bytes().as_ref(), &alias[17..8192 + 17]);
    }
    assert!(wrapped);
    let returned = prepared.into_bytes().unwrap();
    assert_eq!(returned.as_ptr() as u64, address);
    drop((reader, source));
    assert_eq!(returned.as_ref(), &alias[17..8192 + 17]);
}

#[test]
#[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shared_read_source_arena_holds_parent_through_read_and_reuses_window() {
    let dev = device();
    let (mut reader, mut source, qr, qs) = pair(&dev);
    let raw: &'static [u8] = Box::leak(
        (0..16384)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    // SAFETY: the initialized heap allocation is mapped until process exit.
    let arena = unsafe {
        crate::verbs::ZcMem::register_read_windows(&dev, &[(raw.as_ptr() as u64, raw.len() as u64)])
    }
    .unwrap();
    let data = Bytes::from_static(raw);
    let alias = data.clone();
    let piece = data.slice(17..8192 + 17);
    let address = piece.as_ptr() as u64;
    let mut prepared = PreparedReadSource::from_arena(arena.clone(), piece).unwrap();
    drop(arena);
    let outside = Bytes::from_static(b"outside registered arena");
    let outside_ptr = outside.as_ptr();
    let rejected = prepared.replace_arena_bytes(outside).unwrap_err();
    assert_eq!(rejected.error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(rejected.data.as_ptr(), outside_ptr);
    assert_eq!(prepared.bytes().as_ptr() as u64, address);
    let mut target = PreparedReadBuffer::prepare(&dev, 4096).unwrap();
    let mut oldest = None;
    let mut wrapped = false;
    for tid in 1..=260 {
        let offset = if tid % 2 == 0 { 33 } else { 17 };
        let replacement = data.slice(offset..offset + 8192);
        let (previous, allocations) =
            crate::test_alloc::count(|| prepared.replace_arena_bytes(replacement).unwrap());
        assert_eq!(allocations, 0);
        drop(previous);
        let range = prepared.range().subrange(17, 4096).unwrap();
        let (result, allocations) = crate::test_alloc::count(|| {
            source.bind_shared_read_source(qs, prepared, range).unwrap()
        });
        assert_eq!(allocations, 0);
        let local = result;
        let start = Instant::now();
        while local.state() == WindowState::Binding {
            deadline("immutable source BIND", start);
            poll(&mut source);
        }
        let attempt = WindowAttempt {
            connection: 1,
            tid,
            retry: 0,
        };
        let (mut advertised, allocations) =
            crate::test_alloc::count(|| local.advertise(&source, attempt).unwrap());
        assert_eq!(allocations, 0);
        let descriptor = advertised.descriptor();
        assert_eq!(descriptor.range, range);
        let first = *oldest.get_or_insert(descriptor);
        if tid > 1 && first.rkey == descriptor.rkey {
            wrapped = true;
            // SAFETY: intentionally mismatching retired attempt is rejected.
            assert!(!unsafe {
                advertised.confirm_peer_retired_unchecked(first.attempt, first.rkey)
            });
        }
        assert_eq!(
            advertised.invalidate(&mut source).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        // SAFETY: exact source grant on the fixture's owned connected pair.
        let grant = unsafe { descriptor.remote_source().unwrap() };
        let pending = reader.read_buffer(qr, target, grant).unwrap();
        let start = Instant::now();
        while pending.state() == ReadState::Pending {
            deadline("immutable source READ", start);
            poll(&mut reader);
        }
        let shared = pending.try_finish().unwrap();
        assert_eq!(
            shared.bytes().as_ref(),
            &alias[offset + 17..offset + 17 + 4096]
        );
        assert_eq!(data.as_ref(), alias.as_ref());
        target = shared.try_reuse().unwrap();
        // SAFETY: exact accepted READ CQ consumed and all future admission stopped.
        assert!(unsafe { advertised.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
        let (result, allocations) = crate::test_alloc::count(|| advertised.invalidate(&mut source));
        assert_eq!(allocations, 0);
        result.unwrap();
        let start = Instant::now();
        while advertised.state() == WindowState::Invalidating {
            deadline("immutable source LOCAL_INV", start);
            poll(&mut source);
        }
        let (recovered, allocations) =
            crate::test_alloc::count(|| advertised.try_recover().unwrap());
        assert_eq!(allocations, 0);
        prepared = recovered;
        assert_eq!(prepared.bytes().as_ref(), &alias[offset..offset + 8192]);
    }
    assert!(wrapped);
    let returned = prepared.into_bytes().unwrap();
    assert_eq!(returned.as_ptr() as u64, address + 16);
    drop((reader, source));
    assert_eq!(returned.as_ref(), &alias[33..8192 + 33]);
}

#[test]
#[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shared_read_source_bounded_pool_reuses_windows_and_tickets() {
    let dev = device();
    let (mut reader, mut source, qr, qs) = pair(&dev);
    let raw: &'static [u8] = Box::leak(
        (0..16384)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    // SAFETY: the initialized heap allocation is mapped until process exit.
    let arena = unsafe {
        crate::verbs::ZcMem::register_read_windows(&dev, &[(raw.as_ptr() as u64, raw.len() as u64)])
    }
    .unwrap();
    let data = Bytes::from_static(raw);
    let alias = data.clone();
    let seed = data.slice(17..8192 + 17);
    let mut pool = ReadSourcePool::prepare(arena, &seed, 1).unwrap();
    let (first, first_ticket) = pool.checkout(seed.clone()).unwrap();
    let refused = pool.checkout(seed.clone()).unwrap_err();
    assert_eq!(refused.error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(refused.data.as_ptr(), seed.as_ptr());
    assert_eq!(pool.outstanding(), 1);
    let foreign = PreparedReadSource::from_arena(pool.registration.clone(), seed.clone()).unwrap();
    let refused = pool.put(foreign, first_ticket).unwrap_err();
    assert_eq!(pool.outstanding(), 1);
    assert_eq!(pool.available(), 0);
    drop(refused.source);
    pool.put(first, refused.ticket).unwrap();
    assert_eq!(pool.available(), 1);
    struct PayloadOwner {
        data: &'static [u8],
        drops: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl AsRef<[u8]> for PayloadOwner {
        fn as_ref(&self) -> &[u8] {
            self.data
        }
    }
    impl Drop for PayloadOwner {
        fn drop(&mut self) {
            self.drops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let payload = Bytes::from_owner(PayloadOwner {
        data: &raw[17..8192 + 17],
        drops: drops.clone(),
    });
    let (idle_source, ticket) = pool.checkout(payload).unwrap();
    assert_eq!(drops.load(std::sync::atomic::Ordering::Relaxed), 0);
    pool.put(idle_source, ticket).unwrap();
    assert_eq!(drops.load(std::sync::atomic::Ordering::Relaxed), 1);
    let mut target = PreparedReadBuffer::prepare(&dev, 4096).unwrap();
    let mut oldest = None;
    let mut wrapped = false;
    for tid in 1..=260 {
        let offset = if tid % 2 == 0 { 33 } else { 17 };
        let replacement = data.slice(offset..offset + 8192);
        let ((prepared, ticket), allocations) =
            crate::test_alloc::count(|| pool.checkout(replacement).unwrap());
        assert_eq!(allocations, 0);
        let range = prepared.range().subrange(17, 4096).unwrap();
        let (result, allocations) = crate::test_alloc::count(|| {
            source.bind_shared_read_source(qs, prepared, range).unwrap()
        });
        assert_eq!(allocations, 0);
        let local = result;
        let start = Instant::now();
        while local.state() == WindowState::Binding {
            deadline("immutable source BIND", start);
            poll(&mut source);
        }
        let attempt = WindowAttempt {
            connection: 1,
            tid,
            retry: 0,
        };
        let (mut advertised, allocations) =
            crate::test_alloc::count(|| local.advertise(&source, attempt).unwrap());
        assert_eq!(allocations, 0);
        let descriptor = advertised.descriptor();
        assert_eq!(descriptor.range, range);
        let first = *oldest.get_or_insert(descriptor);
        if tid > 1 && first.rkey == descriptor.rkey {
            wrapped = true;
            // SAFETY: intentionally mismatching retired attempt is rejected.
            assert!(!unsafe {
                advertised.confirm_peer_retired_unchecked(first.attempt, first.rkey)
            });
        }
        assert_eq!(
            advertised.invalidate(&mut source).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        // SAFETY: exact source grant on the fixture's owned connected pair.
        let grant = unsafe { descriptor.remote_source().unwrap() };
        let pending = reader.read_buffer(qr, target, grant).unwrap();
        let start = Instant::now();
        while pending.state() == ReadState::Pending {
            deadline("immutable source READ", start);
            poll(&mut reader);
        }
        let shared = pending.try_finish().unwrap();
        assert_eq!(
            shared.bytes().as_ref(),
            &alias[offset + 17..offset + 17 + 4096]
        );
        assert_eq!(data.as_ref(), alias.as_ref());
        target = shared.try_reuse().unwrap();
        // SAFETY: exact accepted READ CQ consumed and all future admission stopped.
        assert!(unsafe { advertised.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
        let (result, allocations) = crate::test_alloc::count(|| advertised.invalidate(&mut source));
        assert_eq!(allocations, 0);
        result.unwrap();
        let start = Instant::now();
        while advertised.state() == WindowState::Invalidating {
            deadline("immutable source LOCAL_INV", start);
            poll(&mut source);
        }
        let (recovered, allocations) =
            crate::test_alloc::count(|| advertised.try_recover().unwrap());
        assert_eq!(allocations, 0);
        assert_eq!(recovered.bytes().as_ref(), &alias[offset..offset + 8192]);
        let (_, allocations) = crate::test_alloc::count(|| pool.put(recovered, ticket).unwrap());
        assert_eq!(allocations, 0);
        assert_eq!(pool.available(), 1);
        assert_eq!(pool.outstanding(), 0);
    }
    assert!(wrapped);
    drop((reader, source, pool));
    assert_eq!(data.as_ref(), alias.as_ref());
}

#[test]
#[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shared_read_source_rejections_preserve_exact_source_and_disallow_write_binding() {
    let dev = device();
    let (_reader, mut source, _, qs) = pair(&dev);
    let data = Bytes::from(vec![73; 8192]);
    let address = data.as_ptr();
    let prepared = PreparedReadSource::register(&dev, data).unwrap();
    let range = prepared.range();
    let outside = MemoryRange::new(range.address() - 1, range.length()).unwrap();
    let rejected = source
        .bind_shared_read_source(qs, prepared, outside)
        .unwrap_err();
    assert_eq!(rejected.error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(rejected.source.bytes().as_ptr(), address);
    let rejected = source
        .bind_shared_read_source(u32::MAX, rejected.source, range)
        .unwrap_err();
    assert_eq!(rejected.error.kind(), io::ErrorKind::NotConnected);
    // Test-only access bypasses the public immutable type barrier. The common
    // parent must still refuse WRITE binding before any provider work is posted.
    let rejected = source
        .bind_window(qs, rejected.source.window, range)
        .unwrap_err();
    assert_eq!(rejected.error.kind(), io::ErrorKind::PermissionDenied);
    let prepared = PreparedReadSource {
        window: rejected.window,
    };
    let mut local = source.bind_shared_read_source(qs, prepared, range).unwrap();
    let start = Instant::now();
    while local.state() == WindowState::Binding {
        deadline("immutable unused source BIND", start);
        poll(&mut source);
    }
    local = local.try_recover().unwrap_err();
    local.invalidate(&mut source).unwrap();
    let start = Instant::now();
    while local.state() == WindowState::Invalidating {
        deadline("immutable unused source LOCAL_INV", start);
        poll(&mut source);
    }
    let returned = local.try_recover().unwrap().into_bytes().unwrap();
    assert_eq!(returned.as_ptr(), address);
    assert!(returned.iter().all(|b| *b == 73));
    let (mut ordinary, _peer, q, _) = crate::verbs::rxe_tests::linked(&dev);
    let prepared = PreparedReadSource::register(&dev, returned).unwrap();
    let rejected = ordinary
        .bind_shared_read_source(q, prepared, range)
        .unwrap_err();
    assert_eq!(rejected.error.kind(), io::ErrorKind::Unsupported);
    assert_eq!(rejected.source.into_bytes().unwrap().as_ptr(), address);
    let other = device(); // same provider, distinct device context and PD
    let data = Bytes::from(vec![47; 4096]);
    let pointer = data.as_ptr();
    let prepared = PreparedReadSource::register(&other, data).unwrap();
    let range = prepared.range();
    let rejected = source
        .bind_shared_read_source(qs, prepared, range)
        .unwrap_err();
    assert_eq!(rejected.error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(rejected.source.into_bytes().unwrap().as_ptr(), pointer);
}

#[test]
#[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shared_read_source_parent_and_revoked_keys_deny_remote_read() {
    for parent_key in [true, false] {
        let dev = device();
        let (reader, mut source, qr, qs) = pair(&dev);
        let prepared = PreparedReadSource::register(&dev, Bytes::from(vec![39; 4096])).unwrap();
        let range = prepared.range();
        // SAFETY: test-only parent key observation; production never exports it.
        let mr_key =
            unsafe { ffi::rv_test_mr_rkey(prepared.window.destination.as_ref().unwrap().mr) };
        let local = source.bind_shared_read_source(qs, prepared, range).unwrap();
        let start = Instant::now();
        while local.state() == WindowState::Binding {
            deadline("immutable negative BIND", start);
            poll(&mut source);
        }
        let mut published = local
            .advertise(
                &source,
                WindowAttempt {
                    connection: 1,
                    tid: 1,
                    retry: 0,
                },
            )
            .unwrap();
        let descriptor = published.descriptor();
        // SAFETY: descriptor never sent; no READ admitted.
        assert!(unsafe {
            published.confirm_peer_retired_unchecked(descriptor.attempt, descriptor.rkey)
        });
        published.invalidate(&mut source).unwrap();
        let start = Instant::now();
        while published.state() == WindowState::Invalidating {
            deadline("immutable negative LOCAL_INV", start);
            poll(&mut source);
        }
        let backing = published.try_recover().unwrap();
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
#[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shared_read_source_read_only_window_denies_remote_write() {
    let dev = device();
    let (reader, mut source, qr, qs) = pair(&dev);
    let prepared = PreparedReadSource::register(&dev, Bytes::from(vec![39; 4096])).unwrap();
    let range = prepared.range();
    let local = source.bind_shared_read_source(qs, prepared, range).unwrap();
    let start = Instant::now();
    while local.state() == WindowState::Binding {
        deadline("immutable write denial BIND", start);
        poll(&mut source);
    }
    let backing = local
        .advertise(
            &source,
            WindowAttempt {
                connection: 1,
                tid: 1,
                retry: 0,
            },
        )
        .unwrap();
    let key = backing.descriptor().rkey;
    let target = HostDestination::register(&dev, vec![0; 4096]).unwrap();
    let mut probe = Probe {
        reader,
        source,
        backing,
        target,
    };
    probe.access_denied(qr, range, key, true);
    probe.finish();
}

#[test]
#[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shared_read_source_failed_completion_retains_exact_owner() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Owner {
        data: Vec<u8>,
        released: Arc<AtomicUsize>,
    }
    impl AsRef<[u8]> for Owner {
        fn as_ref(&self) -> &[u8] {
            &self.data
        }
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            self.released.fetch_add(1, Ordering::Relaxed);
        }
    }
    let dev = device();
    let (_reader, mut source, _, qs) = pair(&dev);
    let released = Arc::new(AtomicUsize::new(0));
    let data = Bytes::from_owner(Owner {
        data: vec![91; 4096],
        released: released.clone(),
    });
    let alias = data.clone();
    let prepared = PreparedReadSource::register(&dev, data).unwrap();
    let range = prepared.range();
    let local = source.bind_shared_read_source(qs, prepared, range).unwrap();
    source.inject_cq_error(-5);
    source.poll(|_, _| {});
    assert_eq!(local.state(), WindowState::Failed);
    drop(local.try_recover().unwrap_err());
    drop((source, alias));
    assert_eq!(
        released.load(Ordering::Relaxed),
        0,
        "lost BIND completion retains the exact Bytes owner"
    );
}

#[test]
#[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shared_read_source_arena_lost_bind_retains_payload_and_parent() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Owner {
        data: &'static [u8],
        released: Arc<AtomicUsize>,
    }
    impl AsRef<[u8]> for Owner {
        fn as_ref(&self) -> &[u8] {
            self.data
        }
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            self.released.fetch_add(1, Ordering::Relaxed);
        }
    }
    let dev = device();
    let (_reader, mut source, _, qs) = pair(&dev);
    let released = Arc::new(AtomicUsize::new(0));
    let raw: &'static [u8] = Box::leak(vec![91u8; 4096].into_boxed_slice());
    // SAFETY: initialized heap mapping remains live for the process lifetime.
    let registration = unsafe {
        crate::verbs::ZcMem::register_read_windows(&dev, &[(raw.as_ptr() as u64, raw.len() as u64)])
    }
    .unwrap();
    let parent = Arc::downgrade(&registration);
    let data = Bytes::from_owner(Owner {
        data: raw,
        released: released.clone(),
    });
    let alias = data.clone();
    let prepared = PreparedReadSource::from_arena(registration, data).unwrap();
    let range = prepared.range();
    let local = source.bind_shared_read_source(qs, prepared, range).unwrap();
    source.inject_cq_error(-5);
    source.poll(|_, _| {});
    assert_eq!(local.state(), WindowState::Failed);
    drop(local.try_recover().unwrap_err());
    drop((source, alias));
    assert_eq!(
        released.load(Ordering::Relaxed),
        0,
        "lost BIND completion retains the exact Bytes owner"
    );
    assert!(
        parent.upgrade().is_some(),
        "lost BIND completion retains the parent MR"
    );
}
