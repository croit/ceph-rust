// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Full mesh of SPSC rings between `n` cores: the only cross-core data path (adr 0006). Core `i` owns one producer
//! towards and one consumer from every other core `j`, so each ring has exactly one writer and one reader.
//! Message buffers move with the envelope; bounded ingress reservations follow actor retention.

use crate::spsc::{self, Consumer, Producer};

use ingress::order::Sequencer;
pub use ingress::order::{Route, Stamped};

/// One core's view of the mesh.
#[derive(Debug)]
pub struct Endpoint<T> {
    id: usize,
    tx: Vec<Option<Producer<Stamped<T>>>>,
    rx: Vec<Option<Consumer<Stamped<T>>>>,
    active_rx: Vec<usize>,
    cores: usize,
    lanes: usize,
    sequence: Sequencer,
    delivered: Vec<u64>,
    applied: Vec<u64>,
    /// Next source to poll (round robin, so a busy sender cannot starve the others).
    next: usize,
    /// Inbound rings popped since the last [`Endpoint::space_wakes`] (each once: `popped_mark`).
    popped: Vec<usize>,
    popped_mark: Vec<bool>,
}

/// Build the mesh: `n` endpoints, `cap` slots per ring (rounded up to a power of two).
pub fn mesh<T: Send>(n: usize, cap: usize) -> Vec<Endpoint<T>> {
    mesh_lanes(n, cap, 1)
}

/// Build independent data rings and two reserved rings (ordered controls and progress) per core pair.
/// `lanes == 1` retains the ordinary FIFO interface. Multi-lane callers stamp each message before attempting sends.
pub fn mesh_lanes<T: Send>(n: usize, cap: usize, lanes: usize) -> Vec<Endpoint<T>> {
    mesh_filtered(n, lanes, |_, _| Some(cap))
}

/// Physical shards route only to their owner. Controls, statistics, raw relay and progress connect every pair.
pub fn mesh_store<T: Send>(n: usize, cap: usize, shards: usize) -> Vec<Endpoint<T>> {
    mesh_filtered(n, shards + 4, |dst, lane| {
        if lane == 0 {
            Some(128)
        } else if lane == 1 {
            Some(2)
        } else if lane == shards + 2 {
            Some(32)
        } else if lane == shards + 3 {
            Some(cap)
        } else if (lane - 2) % n == dst {
            Some(32)
        } else {
            None
        }
    })
}

fn mesh_filtered<T: Send>(
    n: usize,
    lanes: usize,
    capacity: impl Fn(usize, usize) -> Option<usize>,
) -> Vec<Endpoint<T>> {
    assert!(lanes == 1 || lanes >= 3);
    let mut eps: Vec<Endpoint<T>> = (0..n)
        .map(|id| Endpoint {
            id,
            tx: (0..n * lanes).map(|_| None).collect(),
            rx: (0..n * lanes).map(|_| None).collect(),
            active_rx: Vec::new(),
            cores: n,
            lanes,
            sequence: Sequencer::new(n, lanes),
            delivered: vec![0; n * lanes],
            applied: vec![0; n],
            next: 0,
            popped: Vec::with_capacity(n * lanes),
            popped_mark: vec![false; n * lanes],
        })
        .collect();
    for i in 0..n {
        for j in 0..n {
            if i != j {
                for lane in 0..lanes {
                    let Some(cap) = capacity(j, lane) else {
                        continue;
                    };
                    let (p, c) = spsc::channel(cap);
                    eps[i].tx[j * lanes + lane] = Some(p);
                    eps[j].rx[i * lanes + lane] = Some(c);
                    eps[j].active_rx.push(i * lanes + lane);
                }
            }
        }
    }
    eps
}

impl<T> Endpoint<T> {
    /// This core's index.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Number of cores in the mesh.
    pub fn cores(&self) -> usize {
        self.cores
    }

    pub fn lanes(&self) -> usize {
        self.lanes
    }

    pub fn has_sender(&self, dst: usize, lane: usize) -> bool {
        self.tx[dst * self.lanes + lane].is_some()
    }

    /// Allocate only the cold ordered-control snapshot; data/progress stamping allocates nothing.
    pub fn stamp(&mut self, dst: usize, route: Route, value: T) -> Stamped<T> {
        assert!(dst < self.cores && dst != self.id);
        self.sequence.stamp(dst, route, value)
    }

    /// Send a stamped message; a full ring hands it back and registers this core for a space wake: the receiver's next
    /// [`space_wakes`](Self::space_wakes) after a pop of that ring names this core. A lane without a ring to `dst` (a
    /// shard lane `dst` does not own, [`mesh_store`]) is a routing bug: it panics instead of reporting a full ring, which
    /// the sender would retry forever.
    pub fn send_stamped(&mut self, dst: usize, value: Stamped<T>) -> Result<(), Stamped<T>> {
        let lane = value.lane;
        match self.tx[dst * self.lanes + lane].as_mut() {
            Some(p) => p.push_or_want(value),
            None => panic!(
                "mesh: core {} sent on lane {lane} to core {dst}, which has no ring for it (misrouted message)",
                self.id
            ),
        }
    }

    /// The ring to `dst` on `lane` has a free slot now (fresh look; the sleeper's re-check of a held backlog).
    pub fn tx_has_space(&self, dst: usize, lane: usize) -> bool {
        self.tx[dst * self.lanes + lane]
            .as_ref()
            .is_some_and(Producer::has_space)
    }

    /// After a drain: call `wake(source core)` for every ring this core popped whose sender registered for a space wake
    /// (a full ring, [`send_stamped`](Self::send_stamped)). One fence for all rings (Dekker with the sender's
    /// registration, `spsc::Producer::push_or_want`).
    pub fn space_wakes(&mut self, mut wake: impl FnMut(usize)) {
        if self.popped.is_empty() {
            return;
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        for s in self.popped.drain(..) {
            self.popped_mark[s] = false;
            if self.rx[s].as_ref().is_some_and(Consumer::take_want) {
                wake(s / self.lanes);
            }
        }
    }

    /// Send to core `dst` (!= own id); hands the value back when the ring is full (caller drains its own inbox and
    /// retries: never block, two full rings facing each other would deadlock).
    #[inline]
    pub fn send(&mut self, dst: usize, v: T) -> Result<(), T> {
        if dst == self.id {
            return Err(v);
        }
        assert_eq!(
            self.lanes, 1,
            "multi-lane callers must retain the stamp across retries"
        );
        let stamped = self.stamp(dst, Route::Data(0), v);
        self.send_stamped(dst, stamped).map_err(|v| {
            self.sequence.undo_single_send(dst);
            v.value
        })
    }

    /// Pop one message from any other core: `(source core, message)`.
    #[inline]
    pub fn poll(&mut self) -> Option<(usize, T)> {
        self.poll_ready(|_, _, _| true)
    }

    /// Visit only lane heads whose destination is ready and whose ordered-control dependencies have passed.
    pub fn poll_ready(
        &mut self,
        mut ready: impl FnMut(usize, usize, &T) -> bool,
    ) -> Option<(usize, T)> {
        let n = self.active_rx.len();
        let mut cursor = self.next;
        for _ in 0..n {
            let s = self.active_rx[cursor];
            cursor += 1;
            if cursor == n {
                cursor = 0;
            }
            let Some(c) = self.rx[s].as_mut() else {
                continue;
            };
            let Some(v) = c.peek() else { continue };
            // Empty rings require no source/lane division. The cursor wraps with
            // a branch rather than a division for every idle ring probe.
            let from = s / self.lanes;
            let lane = s % self.lanes;
            if self.lanes > 1 {
                if let Some(before) = &v.predecessors {
                    if v.generation != self.applied[from] + 1
                        || (0..self.lanes)
                            .any(|l| l != 1 && self.delivered[from * self.lanes + l] < before[l])
                    {
                        continue;
                    }
                } else if lane != 1 && v.generation != self.applied[from] {
                    continue;
                }
            }
            if !ready(from, lane, &v.value) {
                continue;
            }
            let v = c.pop().unwrap();
            if !self.popped_mark[s] {
                self.popped_mark[s] = true;
                self.popped.push(s);
            }
            self.delivered[s] = v.ordinal;
            if v.predecessors.is_some() {
                self.applied[from] = v.generation;
            }
            self.next = cursor;
            return Some((from, v.value));
        }
        None
    }

    /// No message from any core waits.
    pub fn inbox_empty(&self) -> bool {
        self.rx.iter().flatten().all(Consumer::is_empty)
    }

    /// Drain up to `max` messages into `f`; returns how many.
    pub fn drain(&mut self, max: usize, mut f: impl FnMut(usize, T)) -> usize {
        let mut k = 0;
        while k < max {
            let Some((s, v)) = self.poll() else { break };
            f(s, v);
            k += 1;
        }
        k
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stalled_data_lane_leaves_other_data_and_progress_capacity() {
        let mut eps = mesh_lanes::<u32>(2, 2, 4);
        let mut b = eps.pop().unwrap();
        let mut a = eps.pop().unwrap();
        for v in 0..2 {
            let m = a.stamp(1, Route::Data(0), v);
            a.send_stamped(1, m).unwrap();
        }
        let blocked = a.stamp(1, Route::Data(0), 2);
        assert!(a.send_stamped(1, blocked).is_err());
        for (route, v) in [(Route::Data(1), 10), (Route::Progress, 20)] {
            let m = a.stamp(1, route, v);
            a.send_stamped(1, m).unwrap();
        }
        let mut delivered = vec![];
        for _ in 0..4 {
            match b.poll_ready(|_, lane, _| lane != 2) {
                Some((_, v)) => delivered.push(v),
                None => break,
            }
        }
        delivered.sort();
        assert_eq!(delivered, [10, 20]);
        assert!(!b.inbox_empty());
    }

    /// A shard lane routed to a core that does not own the shard has no ring: loud, never a retried "full".
    #[test]
    #[should_panic(expected = "misrouted message")]
    fn a_shard_lane_to_a_non_owner_panics() {
        let mut a = mesh_store::<u32>(2, 8, 4).remove(0);
        // shard 0 belongs to core 0 (shard % cores): core 1 has no ring for it
        let m = a.stamp(1, Route::Data(0), 7);
        let _ = a.send_stamped(1, m);
    }

    #[test]
    fn ordered_barrier_waits_for_unsent_predecessors_and_fences_later_data() {
        let mut eps = mesh_lanes::<u32>(2, 2, 4);
        let mut b = eps.pop().unwrap();
        let mut a = eps.pop().unwrap();
        let before = a.stamp(1, Route::Data(0), 1);
        let barrier = a.stamp(1, Route::Ordered, 2);
        let after = a.stamp(1, Route::Data(1), 3);
        a.send_stamped(1, barrier).unwrap();
        a.send_stamped(1, after).unwrap();
        assert_eq!(b.poll(), None);
        let progress = a.stamp(1, Route::Progress, 4);
        a.send_stamped(1, progress).unwrap();
        assert_eq!(b.poll(), Some((0, 4)));
        a.send_stamped(1, before).unwrap();
        assert_eq!(b.poll(), Some((0, 1)));
        assert_eq!(b.poll(), Some((0, 2)));
        assert_eq!(b.poll(), Some((0, 3)));
    }

    #[test]
    fn all_pairs_deliver_in_order_across_threads() {
        let n = 4;
        let eps = mesh::<(usize, u32)>(n, 8);
        let hs: Vec<_> = eps
            .into_iter()
            .map(|mut ep| {
                std::thread::spawn(move || {
                    let me = ep.id();
                    let per = 5000u32;
                    let mut sent = vec![0u32; n];
                    let mut next = vec![0u32; n];
                    let mut got = 0;
                    while got < per * (n as u32 - 1)
                        || sent.iter().enumerate().any(|(j, &s)| j != me && s < per)
                    {
                        for (j, s) in sent.iter_mut().enumerate() {
                            if j != me && *s < per && ep.send(j, (me, *s)).is_ok() {
                                *s += 1;
                            }
                        }
                        ep.drain(16, |s, (from, seq)| {
                            assert_eq!(s, from);
                            assert_eq!(seq, next[s]);
                            next[s] += 1;
                            got += 1;
                        });
                    }
                    got
                })
            })
            .collect();
        for h in hs {
            assert_eq!(h.join().unwrap(), 5000 * 3);
        }
    }

    #[test]
    fn self_send_is_refused() {
        let mut eps = mesh::<u8>(2, 2);
        assert_eq!(eps[0].send(0, 1), Err(1));
        assert_eq!(eps[0].send(1, 2), Ok(()));
        assert_eq!(eps[1].poll(), Some((0, 2)));
    }
}

// Experimental source hints only. Not wired into production: every producer's
// notification shares one receiver cacheline and may hurt a busy many-to-one mesh.
#[cfg(test)]
mod hint_probe {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    struct Hinted {
        ep: Endpoint<u64>,
        published: Arc<AtomicU64>,
        local: u64,
        next: usize,
        sources: Vec<Vec<usize>>,
    }
    impl Hinted {
        fn new(ep: Endpoint<u64>, published: Arc<AtomicU64>) -> Self {
            let mut sources = vec![Vec::new(); ep.cores];
            for &index in &ep.active_rx {
                sources[index / ep.lanes].push(index);
            }
            Self {
                ep,
                published,
                local: 0,
                next: 0,
                sources,
            }
        }
        fn poll(&mut self) -> Option<(usize, u64)> {
            self.local |= self.published.swap(0, Ordering::Acquire);
            // Rotate sources; each hint survives until a fresh empty observation.
            let candidates = self.local.rotate_right(self.next as u32);
            if candidates == 0 {
                return None;
            }
            let mut remaining = candidates;
            while remaining != 0 {
                let bit = remaining.trailing_zeros() as usize;
                remaining &= remaining - 1;
                let source = (bit + self.next) % 64;
                for &index in &self.sources[source] {
                    let c = self.ep.rx[index].as_mut().unwrap();
                    if let Some(value) = c.peek() {
                        // This probe tests data-only traffic, not barrier policy.
                        assert!(value.predecessors.is_none() && value.generation == 0);
                        let value = c.pop().unwrap();
                        self.ep.delivered[index] = value.ordinal;
                        self.next = (source + 1) % 64;
                        return Some((source, value.value));
                    }
                }
                self.local &= !(1u64 << source);
            }
            None
        }
    }

    fn run(hinted: bool, producers: usize, messages: usize) -> u128 {
        let mut endpoints = mesh_store::<u64>(32, 256, 32);
        let receiver = endpoints.remove(0);
        let hints = Arc::new(AtomicU64::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(producers + 1));
        let mut joins = Vec::new();
        for mut sender in endpoints.drain(..producers) {
            let hints = hints.clone();
            let barrier = barrier.clone();
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                for value in 0..messages as u64 {
                    let mut message = sender.stamp(0, Route::Data(0), value);
                    while let Err(retained) = sender.send_stamped(0, message) {
                        message = retained;
                        std::hint::spin_loop();
                    }
                    if hinted {
                        hints.fetch_or(1 << sender.id(), Ordering::Release);
                    }
                }
            }));
        }
        let mut receiver = Hinted::new(receiver, hints);
        let mut expected = vec![0u64; 32];
        barrier.wait();
        let started = Instant::now();
        let mut count = 0;
        while count < producers * messages {
            let message = if hinted {
                receiver.poll()
            } else {
                receiver.ep.poll()
            };
            if let Some((from, value)) = message {
                assert_eq!(value, expected[from]);
                expected[from] += 1;
                count += 1;
            } else {
                std::hint::spin_loop();
            }
        }
        let elapsed = started.elapsed().as_nanos();
        for join in joins {
            join.join().unwrap();
        }
        elapsed
    }

    #[test]
    fn source_hints_deliver_every_data_message_in_order() {
        run(true, 4, 10_000);
    }

    #[test]
    #[ignore = "data-only source-readiness PoC; local CPU samples, not production qualification"]
    fn perf_sparse_source_hints() {
        let hints = Arc::new(AtomicU64::new(0));
        let mut receiver = Hinted::new(mesh_store::<u64>(32, 256, 32).remove(0), hints);
        let iterations = 200_000;
        let start = Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(receiver.ep.poll());
        }
        let baseline = start.elapsed().as_nanos();
        let start = Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(receiver.poll());
        }
        println!(
            "empty probes: baseline_ns={} hinted_ns={}",
            baseline / iterations,
            start.elapsed().as_nanos() / iterations
        );
        for producers in [1, 4, 8] {
            for sample in 0..3 {
                let messages = 50_000;
                let baseline = run(false, producers, messages);
                let hinted = run(true, producers, messages);
                println!(
                    "producers={producers} sample={sample} baseline_ns_msg={} hinted_ns_msg={}",
                    baseline / (producers * messages) as u128,
                    hinted / (producers * messages) as u128
                );
            }
        }
    }
}
