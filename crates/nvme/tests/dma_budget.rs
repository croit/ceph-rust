// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! DMA budget of the SPDK tier (adr 0175 am. 4) on a small EAL heap (no hugepages, no devices): deferrable memory is refused at
//! the read gate instead of exhausting the heap (backpressure), in-flight IO memory still gets its buffer from the last
//! quarter, a request refused at the gate trades its own core's parked blocks, and another core that allocates nothing
//! gives back parked blocks for it at its store sweep (`release_pooled`), shared reply data beyond half the budget
//! leaves as a heap copy, and an exhausted heap never panics and never waits: every store request is refused and
//! admitted at its retry once memory returned. One test: the budget and the heap are process-wide.
#![cfg(feature = "spdk")]

use nvme::IoBuf;
use nvme::dmapool::{self, BUDGET};
use nvme::spdk::DmaBuf;
use std::ffi::{CString, c_char, c_int};
use std::sync::mpsc;

const MIB: usize = 1 << 20;

fn eal_init() {
    unsafe extern "C" {
        fn rte_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
    }
    let args: Vec<CString> = [
        "nvme-dma-budget-test",
        "--no-pci",
        "--no-huge",
        "--in-memory",
        "--iova-mode=va",
        "--no-telemetry",
        "-m",
        "64",
    ]
    .iter()
    .map(|s| CString::new(*s).unwrap())
    .collect();
    let mut ptrs: Vec<_> = args.iter().map(|s| s.as_ptr().cast_mut()).collect();
    // SAFETY: owned C strings stay alive through EAL initialization; once per process (one test in this binary).
    assert!(unsafe { rte_eal_init(ptrs.len() as c_int, ptrs.as_mut_ptr()) } >= 0);
}

fn counter(name: &str) -> u64 {
    dmapool::counters()
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("counter {name}"))
        .1
}

fn filled(len: usize, v: u8) -> DmaBuf {
    let mut b = DmaBuf::new_uninit(len);
    b.copy_from_slice(&vec![v; len]);
    b
}

#[test]
fn a_small_dma_budget_backpressures_reads_and_never_panics() {
    eal_init();
    assert_eq!(BUDGET.held(), 0);
    dmapool::set_budget(32 * MIB as u64);

    // Codex review P1-2: core A parks the whole read gate (24 MiB) and then allocates nothing; core B, its own pool
    // empty, is refused 1 MiB. A's next store sweep gives back the room B wants, and B's retry is admitted (before: A's
    // sweep freed nothing while everything held was at the gate, and B was refused for good).
    let (to_a, a_cmd) = mpsc::channel::<()>();
    let (a_ack, from_a) = mpsc::channel::<()>();
    let core_a = std::thread::spawn(move || {
        drop(
            (0..24)
                .map(|_| DmaBuf::try_new_uninit(MIB).expect("within the gate"))
                .collect::<Vec<_>>(),
        );
        a_ack.send(()).unwrap();
        a_cmd.recv().unwrap();
        DmaBuf::release_pooled();
        a_ack.send(()).unwrap();
        a_cmd.recv().unwrap();
    });
    from_a.recv().unwrap();
    assert_eq!(BUDGET.held(), 24 * MIB as u64);
    let (to_b, b_cmd) = mpsc::channel::<()>();
    let (b_ack, from_b) = mpsc::channel::<bool>();
    let core_b = std::thread::spawn(move || {
        b_ack.send(DmaBuf::try_new_uninit(MIB).is_some()).unwrap();
        b_cmd.recv().unwrap();
        b_ack.send(DmaBuf::try_new_uninit(MIB).is_some()).unwrap();
    });
    assert!(
        !from_b.recv().unwrap(),
        "core B refused: the gate is parked on A"
    );
    assert_eq!(BUDGET.want(), MIB as u64);
    to_a.send(()).unwrap();
    from_a.recv().unwrap();
    assert_eq!(
        BUDGET.held(),
        23 * MIB as u64,
        "A's sweep gave back the room B wants"
    );
    assert_eq!(BUDGET.want(), 0);
    to_b.send(()).unwrap();
    assert!(from_b.recv().unwrap(), "B's retry admitted");
    core_b.join().unwrap();
    to_a.send(()).unwrap();
    core_a.join().unwrap();
    assert_eq!(
        BUDGET.held(),
        0,
        "both pools released as their threads ended"
    );
    assert_eq!(counter("data_short"), 1);
    assert_eq!(counter("pressure_drains"), 0);

    // another core parks 8 MiB, below the read gate (three quarters: 24 MiB)
    let (to_core, cmd) = mpsc::channel::<()>();
    let (ack, from_core) = mpsc::channel::<()>();
    let core = std::thread::spawn(move || {
        drop((0..8).map(|_| DmaBuf::new_uninit(MIB)).collect::<Vec<_>>());
        ack.send(()).unwrap();
        cmd.recv().unwrap();
        DmaBuf::release_pooled();
        ack.send(()).unwrap();
        cmd.recv().unwrap();
    });
    from_core.recv().unwrap();
    assert_eq!(BUDGET.held(), 8 * MIB as u64);

    // deferrable memory is admitted while everything held stays within the gate, then refused (backpressure, not a failed
    // allocation); the refusal drains no other core's pool
    let mut live = Vec::new();
    while let Some(b) = DmaBuf::try_new_uninit(MIB) {
        live.push(b);
        assert!(live.len() <= 16, "read gate not enforced");
    }
    assert_eq!(live.len(), 16);
    assert_eq!(BUDGET.held(), 24 * MIB as u64);
    assert_eq!(counter("data_short"), 2);
    assert_eq!(counter("pressure_drains"), 0);
    // in-flight IO memory takes its buffer from the last quarter
    live.push(DmaBuf::try_new_io_uninit(MIB).expect("the last quarter is in-flight IO's"));
    assert_eq!(BUDGET.held(), 25 * MIB as u64);
    // the other core's sweep gives back what is held above the gate plus the room the refused read wants; a core that
    // ends releases its pool
    to_core.send(()).unwrap();
    from_core.recv().unwrap();
    assert_eq!(BUDGET.held(), 23 * MIB as u64);
    assert_eq!(BUDGET.want(), 0);
    to_core.send(()).unwrap();
    core.join().unwrap();
    assert_eq!(BUDGET.held(), 17 * MIB as u64);

    // dropped buffers park on this core; a read refused at the gate trades just enough of them for its request
    drop(live);
    assert_eq!(BUDGET.held(), 17 * MIB as u64);
    let big = DmaBuf::try_new_uninit(8 * MIB).expect("parked blocks traded");
    assert_eq!(BUDGET.held(), 24 * MIB as u64, "one 1 MiB block went back");
    assert_eq!(counter("data_short"), 2);
    drop(big);
    // a lowered budget: the sweep gives back parked blocks down to the new gate (6 MiB), largest first
    dmapool::set_budget(8 * MIB as u64);
    DmaBuf::release_pooled();
    assert_eq!(BUDGET.held(), 6 * MIB as u64);
    assert_eq!(counter("pressure_drains"), 0);
    dmapool::set_budget(32 * MIB as u64);

    // shared reply data: zero-copy up to half the budget (16 MiB), a heap copy beyond; the block stays home
    let shared: Vec<bytes::Bytes> = (0..4u8)
        .map(|i| {
            let b = filled(4 * MIB, i);
            let p = b.as_slice().as_ptr();
            let s = b.into_shared();
            assert_eq!(s.as_ptr(), p, "zero-copy within the share");
            s
        })
        .collect();
    assert_eq!(BUDGET.shared(), 16 * MIB as u64);
    let b = filled(4 * MIB, 9);
    let p = b.as_slice().as_ptr();
    let copy = b.into_shared();
    assert_ne!(copy.as_ptr(), p, "beyond the share: a heap copy");
    assert!(copy.iter().all(|&v| v == 9));
    assert_eq!(counter("share_copies"), 1);
    assert_eq!(BUDGET.shared(), 16 * MIB as u64);
    drop(shared);
    assert_eq!(BUDGET.shared(), 0);

    // in-flight IO memory (a synchronous read) leaves zero-copy only while everything held stays within the gate: memory
    // held without IO in flight never exceeds it
    let mut gate = Vec::new();
    while let Some(b) = DmaBuf::try_new_uninit(MIB) {
        gate.push(b);
    }
    let mut io = DmaBuf::try_new_io_uninit(MIB).expect("the last quarter");
    io.copy_from_slice(&vec![3u8; MIB]);
    let p = io.as_slice().as_ptr();
    let copy = io.into_shared();
    assert_ne!(copy.as_ptr(), p, "held above the gate: a heap copy");
    assert_eq!(counter("share_copies"), 2);
    drop(gate);
    let mut io = DmaBuf::try_new_io_uninit(MIB).expect("room");
    io.copy_from_slice(&vec![4u8; MIB]);
    let p = io.as_slice().as_ptr();
    let s = io.into_shared();
    assert_eq!(s.as_ptr(), p, "held within the gate: zero-copy");
    drop((copy, s));
    assert_eq!(BUDGET.shared(), 0);

    // no budget, heap exhausted: deferrable and in-flight IO memory are refused (postponed), never a panic, never a wait
    dmapool::set_budget(0);
    let mut bufs = Vec::new();
    while let Some(b) = DmaBuf::try_new_uninit(4 * MIB) {
        bufs.push(b);
        assert!(bufs.len() <= 16, "a 64 MiB heap held more than 64 MiB");
    }
    assert!(bufs.len() >= 8, "only {} buffers of 4 MiB", bufs.len());
    let heap_short = counter("heap_short");
    assert!(heap_short >= 1);
    assert!(DmaBuf::try_new_io_uninit(4 * MIB).is_none());
    assert!(counter("heap_short") > heap_short);
    // another thread frees memory (its pool goes back to the heap as it ends): the retry is admitted
    let half = bufs.split_off(bufs.len() / 2);
    std::thread::spawn(move || drop(half)).join().unwrap();
    let b = DmaBuf::try_new_io_uninit(4 * MIB).expect("memory returned: admitted at the retry");
    assert_eq!(b.len(), 4 * MIB);
}
