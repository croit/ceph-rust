// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Real RXE READ -> shared payload -> kernel NVMe write-view ownership.
//! No storage I/O or durability/performance claim; the view is the actual KBuf.
use nvme::IoBuf;
use rdma::verbs::{
    Core, CoreCfg, Device, Event, PreparedReadBuffer, PreparedReadSource, PreparedWriteBuffer, Qp,
    ReadLimits, ReadState, RemoteWriteTarget, WindowAttempt, WindowState, WriteSource, WriteState,
};
use std::{
    io::Write,
    sync::Arc,
    time::{Duration, Instant},
};

fn before(start: Instant, operation: &str) {
    if start.elapsed() < Duration::from_secs(10) {
        return;
    }
    timed_out(operation);
}

fn timed_out(operation: &str) -> ! {
    let message = format!("WARNING TIMEOUT {operation} exceeded 10s (RXE kernel write-view)");
    eprintln!("{message}");
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
fn poll(core: &mut Core) {
    core.poll(|_, event| assert!(!matches!(event, Event::Fault(_)), "{event:?}"));
}

fn receive<T>(receiver: &std::sync::mpsc::Receiver<T>, operation: &str) -> T {
    match receiver.recv_timeout(Duration::from_secs(10)) {
        Ok(value) => value,
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("{operation}: consumer disconnected")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            timed_out(operation);
        }
    }
}
fn pair(device: &Arc<Device>) -> (Core, Core, u32, u32) {
    let config = CoreCfg {
        srq_depth: 64,
        tx_slots: 8,
        sq_depth: 8,
        max_window: 16,
        ..CoreCfg::default()
    };
    let (mut reader, mut source) = (
        Core::new(device, config).unwrap(),
        Core::new(device, config).unwrap(),
    );
    let (hr, hs) = (reader.handles(), source.handles());
    let (r, s) = (
        Qp::create_for_reads(device, hr, 81).unwrap(),
        Qp::create_for_reads(device, hs, 82).unwrap(),
    );
    let caps = device.read_limits().unwrap();
    assert!(caps.initiator > 0 && caps.responder > 0 && caps.max_sge > 0);
    let (er, es) = (r.endpoint(&hr), s.endpoint(&hs));
    r.connect_with_reads(
        &hr,
        &es,
        ReadLimits {
            initiator: 0,
            responder: 1,
            ..caps
        },
    )
    .unwrap();
    s.connect_with_reads(
        &hs,
        &er,
        ReadLimits {
            initiator: 1,
            responder: 0,
            ..caps
        },
    )
    .unwrap();
    let (qr, qs) = (r.qpn(), s.qpn());
    let cap = rdma::grant::SessionCap::new(0);
    reader.attach(r, &es, cap.acquire().unwrap()).unwrap();
    source.attach(s, &er, cap.acquire().unwrap()).unwrap();
    (reader, source, qr, qs)
}

fn kernel_consumer(
    payload: bytes::Bytes,
    address: u64,
) -> (std::thread::JoinHandle<()>, std::sync::mpsc::Sender<()>) {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let view = nvme::kdev::KBuf::view(&payload).expect("write view enabled");
        assert!(view.is_view());
        assert_eq!(view.as_slice().as_ptr() as u64, address);
        assert!(
            view.as_slice()
                .iter()
                .enumerate()
                .all(|(i, b)| *b == (i % 251) as u8)
        );
        drop(payload);
        ready_tx.send(()).unwrap();
        receive(&release_rx, "consumer view release");
        drop(view);
    });
    receive(&ready_rx, "consumer view ready");
    (worker, release_tx)
}

fn kernel_view_case(length: usize) {
    let ip = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
        .unwrap()
        .parse()
        .unwrap();
    let device = Device::open(rdma::gid_of(ip)).unwrap();
    let (mut reader, mut source, qr, qs) = pair(&device);
    let mut storage = nvme::kdev::KBuf::new(length);
    for (i, byte) in storage.as_mut_slice().iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let source_address = storage.as_slice().as_ptr();
    let data = storage.into_shared();
    assert_eq!(data.as_ptr(), source_address);
    let alias = data.clone();
    let parent = PreparedReadSource::register(&device, data).unwrap();
    assert_eq!(parent.bytes().as_ptr(), source_address);
    let range = parent.range();
    let local = source.bind_shared_read_source(qs, parent, range).unwrap();
    let start = Instant::now();
    while local.state() == WindowState::Binding {
        before(start, "kernel-view source BIND");
        poll(&mut source);
    }
    assert_eq!(local.state(), WindowState::Bound);
    let attempt = WindowAttempt {
        connection: 81,
        tid: 1,
        retry: 0,
    };
    let mut published = local.advertise(&source, attempt).unwrap();
    let descriptor = published.descriptor();
    // SAFETY: this test owns the live pair/source grant and stops admission
    // before confirming peer retirement after every accepted READ has completed.
    let grant = unsafe { descriptor.remote_source().unwrap() };
    let mut buffer = PreparedReadBuffer::prepare(&device, length).unwrap();
    let address = buffer.range().address();
    assert_eq!(address % 4096, 0);
    for _ in 0..8 {
        let pending = reader.read_buffer(qr, buffer, grant).unwrap();
        let start = Instant::now();
        while pending.state() == ReadState::Pending {
            before(start, "kernel-view READ");
            poll(&mut reader);
        }
        let shared = pending.try_finish().unwrap();
        let (worker, release_tx) = kernel_consumer(shared.bytes().clone(), address);
        let shared = shared.try_reuse().unwrap_err();
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        buffer = shared.try_reuse().unwrap();
        assert_eq!(buffer.range().address(), address);
    }
    // SAFETY: all eight exact READ CQEs observed; no more READ will be posted.
    assert!(unsafe { published.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
    published.invalidate(&mut source).unwrap();
    let start = Instant::now();
    while published.state() == WindowState::Invalidating {
        before(start, "kernel-view source LOCAL_INV");
        poll(&mut source);
    }
    let returned = published.try_recover().unwrap().into_bytes().unwrap();
    assert_eq!(returned.as_ptr(), source_address);
    assert_eq!(returned.as_ref(), alias.as_ref());
}

#[test]
#[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shared_read_buffer_is_a_zero_copy_kernel_write_view_and_blocks_dma_reuse() {
    for length in [4096, 1024 * 1024] {
        kernel_view_case(length);
    }
}

// WRITE uses ordinary QPs: this path must not require READ-capability setup.
fn write_pair(device: &Arc<Device>) -> (Core, Core, u32, u32) {
    let config = CoreCfg {
        srq_depth: 64,
        tx_slots: 8,
        sq_depth: 8,
        max_window: 16,
        ..CoreCfg::default()
    };
    let (mut sender, mut receiver) = (
        Core::new(device, config).unwrap(),
        Core::new(device, config).unwrap(),
    );
    let (hs, hr) = (sender.handles(), receiver.handles());
    let (s, r) = (
        Qp::create(device, hs, 83).unwrap(),
        Qp::create(device, hr, 84).unwrap(),
    );
    let (es, er) = (s.endpoint(&hs), r.endpoint(&hr));
    s.connect(&hs, &er).unwrap();
    r.connect(&hr, &es).unwrap();
    let (qs, qr) = (s.qpn(), r.qpn());
    let cap = rdma::grant::SessionCap::new(0);
    sender.attach(s, &er, cap.acquire().unwrap()).unwrap();
    receiver.attach(r, &es, cap.acquire().unwrap()).unwrap();
    (sender, receiver, qs, qr)
}

#[test]
#[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_shared_write_buffer_is_a_zero_copy_kernel_write_view_and_blocks_dma_reuse() {
    let ip = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
        .unwrap()
        .parse()
        .unwrap();
    let device = Device::open(rdma::gid_of(ip)).unwrap();
    for length in [4096, 1024 * 1024] {
        let (mut sender, mut receiver, qs, qr) = write_pair(&device);
        let data = bytes::Bytes::from((0..length).map(|i| (i % 251) as u8).collect::<Vec<_>>());
        let mut source = WriteSource::register(&device, data).unwrap();
        let mut buffer = PreparedWriteBuffer::prepare(&device, length).unwrap();
        let address = buffer.range().address();
        assert_eq!(address % 4096, 0);
        // Unaccepted admission returns the original prepared owner.
        let rejected = receiver.bind_write_buffer(u32::MAX, buffer).unwrap_err();
        assert_eq!(rejected.error.kind(), std::io::ErrorKind::NotConnected);
        buffer = rejected.buffer;
        assert_eq!(buffer.range().address(), address);
        // An unused local binding cannot recover until its LOCAL_INV completes.
        let mut local = receiver.bind_write_buffer(qr, buffer).unwrap();
        let start = Instant::now();
        while local.state() == WindowState::Binding {
            before(start, "unused write buffer BIND");
            poll(&mut receiver);
        }
        local = local.try_recover().unwrap_err();
        local.invalidate(&mut receiver).unwrap();
        let start = Instant::now();
        while local.state() == WindowState::Invalidating {
            before(start, "unused write buffer LOCAL_INV");
            poll(&mut receiver);
        }
        buffer = local.try_recover().unwrap();
        for tid in 1..=8 {
            let local = receiver.bind_write_buffer(qr, buffer).unwrap();
            let start = Instant::now();
            while local.state() == WindowState::Binding {
                before(start, "write buffer BIND");
                poll(&mut receiver);
            }
            let attempt = WindowAttempt {
                connection: 84,
                tid,
                retry: 0,
            };
            let mut published = local.advertise(&receiver, attempt).unwrap();
            let descriptor = published.descriptor();
            assert_eq!(descriptor.range.address(), address);
            // Neither publication nor a local BIND completion publishes bytes.
            published = published.try_finish().unwrap_err();
            assert_eq!(
                published.invalidate(&mut receiver).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            // SAFETY: this fixture retains the exact advertised live target on
            // its owned pair until WRITE CQ, peer retirement and LOCAL_INV.
            let target = unsafe {
                RemoteWriteTarget::from_raw_parts(address, length as u64, descriptor.rkey).unwrap()
            };
            let range = source.range();
            let pending = sender.write(qs, source, range, target).unwrap();
            let start = Instant::now();
            while pending.state() == WriteState::Pending {
                before(start, "kernel-view WRITE");
                poll(&mut sender);
            }
            source = pending.into_source().unwrap();
            // A successful sender CQ still does not authorize CPU publication.
            published = published.try_finish().unwrap_err();
            // SAFETY: exact WRITE CQ observed; no further request will be
            // admitted against this attempt, including after key reuse.
            assert!(unsafe { published.confirm_peer_retired_unchecked(attempt, descriptor.rkey) });
            published = published.try_finish().unwrap_err();
            published.invalidate(&mut receiver).unwrap();
            // Do not poll away the ownership boundary before this assertion.
            published = published.try_finish().unwrap_err();
            let start = Instant::now();
            while published.state() == WindowState::Invalidating {
                before(start, "kernel-view WRITE LOCAL_INV");
                poll(&mut receiver);
            }
            let shared = published.try_finish().unwrap();
            let (worker, release_tx) = kernel_consumer(shared.bytes().clone(), address);
            let shared = shared.try_reuse().unwrap_err();
            release_tx.send(()).unwrap();
            worker.join().unwrap();
            buffer = shared.try_reuse().unwrap();
            assert_eq!(buffer.range().address(), address);
        }
    }
}
