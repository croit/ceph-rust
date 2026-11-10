// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Allocation gates of the queue scan paths on MemStore: the legacy `2pc_queue.remove_entries`
//! count must read entry pre-headers only (not materialize a ring) and the listing path must not
//! format a `String` per entry just to compare the end marker. One test on purpose: the counting
//! allocator is process-global, so a second parallel test would pollute both measurements.
mod common;
use cls::mem::MemStore;
use cls::queue::{self, EnqueueOp, InitOp, ListOp};
use cls::tpc_queue::{RemoveOp, Urgent};
use common::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Track;

// SAFETY: every call is forwarded to `System` unchanged; the atomics only account for the sizes.
unsafe impl GlobalAlloc for Track {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        PEAK.fetch_max(
            LIVE.fetch_add(l.size(), Ordering::Relaxed) + l.size(),
            Ordering::Relaxed,
        );
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Track = Track;

/// Run `f`, returning its result plus the allocation calls and the peak live bytes it caused.
fn measure<R>(f: impl FnOnce() -> R) -> (R, usize, usize) {
    let (a0, base) = (ALLOCS.load(Ordering::Relaxed), LIVE.load(Ordering::Relaxed));
    PEAK.store(base, Ordering::Relaxed);
    let r = f();
    (
        r,
        ALLOCS.load(Ordering::Relaxed) - a0,
        PEAK.load(Ordering::Relaxed).saturating_sub(base),
    )
}

const Q: &str = "q";
const LIST_ENTRIES: usize = 400;
const LIST_ENTRY: usize = 100;
const RING_ENTRIES: usize = 8192;
const RING_ENTRY: usize = 4096;
/// Slack over the head-only baseline for the count path: the 32 MiB ring must not be materialized
/// (its entry payloads alone would add ~32 MiB of live copies). The count reads through the 4 MiB
/// read-ahead window: one window plus its replacement and a wrap extension stay below 12 MiB.
const COUNT_SLACK: usize = 12 << 20;

/// `2pc_queue` head: valid urgent blob with the given committed entry count.
fn set_committed(s: &mut MemStore, entries: u32) -> Vec<u8> {
    s.msg(Q, |c| {
        let mut h = queue::read_head(c).unwrap();
        let mut u: Urgent = d(&h.bl_urgent_data);
        u.committed_entries = entries;
        h.bl_urgent_data = e(&u);
        queue::write_head(c, &h).unwrap();
        (0, h.tail.to_bytes())
    })
    .1
}

#[test]
fn queue_scans_do_not_materialize_payloads_or_format_per_entry() {
    // ---- listing: one allocation per returned entry (payload + marker), none for the compare ----
    let mut s = MemStore::new();
    let n = LIST_ENTRIES;
    ok(
        &mut s,
        Q,
        "queue",
        "queue_init",
        &e(&InitOp {
            queue_size: 1 << 20,
            max_urgent_data_size: 0,
            bl_urgent_data: vec![],
        }),
    );
    let items: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8; LIST_ENTRY]).collect();
    ok(
        &mut s,
        Q,
        "queue",
        "queue_enqueue",
        &e(&EnqueueOp { bl_data_vec: items }),
    );
    let tail = s
        .msg(Q, |c| (0, queue::read_head(c).unwrap().tail.to_bytes()))
        .1;
    let list = e(&ListOp {
        max: n as u64,
        start_marker: vec![],
        end_marker: tail.clone(),
    });
    let (r, allocs, _) = measure(|| s.call(Q, "queue", "queue_list_entries", &list));
    assert_eq!(r.ret, 0);
    // 2 per entry (payload copy + returned marker) + the encoded reply and window refills; a
    // formatted marker for the end_marker compare adds one allocation per entry on top
    assert!(
        allocs <= 2 * n + 64,
        "queue_list_entries allocated {allocs} times for {n} entries"
    );

    // ---- legacy remove_entries count: headers only, the ring is not materialized ----
    let mut s = MemStore::new();
    ok(
        &mut s,
        Q,
        "2pc_queue",
        "2pc_queue_init",
        &e(&InitOp {
            queue_size: (RING_ENTRIES * (RING_ENTRY + queue::ENTRY_OVERHEAD as usize)) as u64,
            max_urgent_data_size: 0,
            bl_urgent_data: vec![],
        }),
    );
    let items: Vec<Vec<u8>> = (0..RING_ENTRIES).map(|_| vec![7u8; RING_ENTRY]).collect();
    ok(
        &mut s,
        Q,
        "queue",
        "queue_enqueue",
        &e(&EnqueueOp { bl_data_vec: items }),
    );
    let tail = set_committed(&mut s, RING_ENTRIES as u32);
    // baseline: a call that reads the head and urgent data only (same message/ctx/clone cost)
    let (r, _, base_peak) = measure(|| s.call(Q, "2pc_queue", "2pc_queue_get_topic_stats", &[]));
    assert_eq!(r.ret, 0);
    let rm = e(&RemoveOp {
        end_marker: tail,
        entries_to_remove: 0,
    });
    let (r, _, peak) = measure(|| s.call(Q, "2pc_queue", "2pc_queue_remove_entries", &rm));
    assert_eq!(r.ret, 0);
    assert!(
        peak <= base_peak + COUNT_SLACK,
        "legacy remove_entries counted {} entries and peaked at {peak} bytes over {} \
         (materializing the ring would exceed it by the ring size)",
        RING_ENTRIES,
        base_peak
    );
    // the handler counted the whole range and emptied the queue
    let (ret, (urgent, head)) = s.msg(Q, |c| {
        let h = queue::read_head(c).unwrap();
        (0, (d::<Urgent>(&h.bl_urgent_data), h))
    });
    assert_eq!((ret, urgent.committed_entries), (0, 0));
    assert_eq!(head.front, head.tail);
}
