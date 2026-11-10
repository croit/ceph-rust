// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Glue between one [`Osd`] core and the SPSC [`mesh`](crate::mesh) of its OSD (adr 0031): inbound
//! [`XMsg`]s go to [`Osd::on_xmsg`], the OSD's outbound ones to the destination core's ring. A full ring never blocks:
//! the message waits in a per-destination backlog (order kept) and is retried on the next iteration, so two cores with
//! full rings towards each other cannot deadlock (each keeps draining its own inbox first). The full ring registers the
//! sender for a space wake: the receiver's drain that frees a slot pokes it ([`crate::mesh::Endpoint::space_wakes`]),
//! so a sender with a held backlog may sleep.
//!
//! The legacy single-ring backlog is bounded ([`MAX_BACKLOG`] messages over all destinations): beyond it the port stops taking messages
//! from the OSD, which then queues them itself and, past `osd::xcore::XOUT_MAX`, refuses new client ops (EAGAIN: the
//! objecter retries) instead of forwarding them. A stalled core therefore costs bounded memory on its peers; what is
//! still queued are replies to already admitted ops and peer messages, bounded by the work admitted before.
//! Production lane backlogs have separate fixed limits, so blocked data cannot consume control/progress capacity.
use crate::mesh::{Endpoint, Route, Stamped};
use osd::{Backend, Osd, XMsg};
use std::collections::VecDeque;
use std::time::Duration;

// Work share of one inbox drain, per source core (adr 0006 am. 4, am. 6): one work slice (`osd::xcore::Slice`, ~100 us,
// learned from the loop's busy time per work unit; work = `XMsg::slice_work`: payload bytes, one block at least), at least the
// work this core's own links handed on since the previous drain (`Osd::start_drain`). The own links' event pump runs per
// received chunk with a fresh slice; with one slice for the whole inbox a hot object's PG core ran ~5 own-link ops per
// iteration and 1 forwarded op, and forwarded clients waited ~15x longer. A source's share ends after its message that fills
// it (its first message always runs); round-robin over the source rings persists across drains (`Endpoint::poll_ready`).
// One 4 MiB write costs 3-4 ms on its PG core; 64 of them back to back (the old count-only bound) kept the core away from its
// network for 250-450 ms: the clients' TCP lost bursts.
// The share bounds a drain to one slice (or the own links' work) per source core. It is work only: a message counts at least
// one store block (`SLICE_MIN`), so the slice bounds runs of small messages too; a count bound on top of it only cut drains
// short of the slice. No clock read per message (adr 0006 am. 4).

/// Per-source accounting of one inbox drain: the work units each source core handed on.
#[derive(Debug)]
struct Shares {
    taken: Vec<usize>,
    budget: usize,
    full: bool,
}

impl Shares {
    fn new(cores: usize) -> Shares {
        Shares {
            taken: vec![0; cores],
            budget: 0,
            full: false,
        }
    }

    /// A drain starts: each source core may hand on `budget` work units.
    fn start(&mut self, budget: usize) {
        self.taken.fill(0);
        self.budget = budget;
        self.full = false;
    }

    /// Source core `from` has share left: its first message always runs, the message that fills its share is its last.
    fn open(&self, from: usize) -> bool {
        let taken = self.taken[from];
        taken == 0 || taken < self.budget
    }

    /// Source core `from` handed on a message of `units` work units (at least one block, `XMsg::slice_work`).
    fn take(&mut self, from: usize, units: usize) {
        self.taken[from] += units;
        self.full |= !self.open(from);
    }
}

/// Legacy single-ring backlog limit; also the maximum envelopes pulled during one send pass.
pub const MAX_BACKLOG: usize = 16 * 1024;

fn lane_limit(lanes: usize, lane: usize) -> usize {
    if lane == 0 {
        128
    } else if lane == 1 {
        2
    } else if lane == lanes - 1 {
        64
    } else {
        32
    }
}

/// Move the head of `queue` into the ring to `dst` until the ring is full (the refused message stays at the head).
/// Returns (anything sent, a sent message wakes its receiver, `XMsg::wakes`).
#[inline]
fn drain(
    ep: &mut Endpoint<XMsg>,
    dst: usize,
    queue: &mut VecDeque<Stamped<XMsg>>,
    queued: &mut usize,
    stalls: &mut u64,
) -> (bool, bool) {
    let (mut sent, mut wakes) = (false, false);
    while let Some(m) = queue.pop_front() {
        let w = m.value.wakes();
        match ep.send_stamped(dst, m) {
            Ok(()) => {
                *queued -= 1;
                sent = true;
                wakes |= w;
            }
            Err(m) => {
                *stalls += 1;
                queue.push_front(m);
                break;
            }
        }
    }
    (sent, wakes)
}

/// One core's mesh endpoint plus its send backlog.
#[derive(Debug)]
pub struct XPort {
    ep: Endpoint<XMsg>,
    shares: Shares,
    backlog: Vec<VecDeque<Stamped<XMsg>>>,
    active: VecDeque<usize>,
    queued: usize,
    /// Messages that had to wait for ring space (diagnostics).
    pub stalls: u64,
    /// Lab (NV_PHASE): per message kind (Op, Wire, other): count, total ns, longest ns.
    pub msg_stat: [(u64, u64, u64); 3],
    phase: bool,
    /// Wake handles of all cores (kernel tier idle sleep); poked after a message went to a sleeping core.
    #[cfg(target_os = "linux")]
    wake: Option<std::sync::Arc<[std::sync::Arc<crate::wake::Wake>]>>,
    #[cfg(target_os = "linux")]
    wake_pending: Vec<bool>,
    #[cfg(target_os = "linux")]
    wake_targets: Vec<usize>,
}

impl XPort {
    /// Wrap this core's endpoint.
    pub fn new(ep: Endpoint<XMsg>) -> XPort {
        let n = ep.cores();
        let lanes = ep.lanes();
        let backlog = (0..n * lanes)
            .map(|index| {
                let lane = index % lanes;
                let capacity = if !ep.has_sender(index / lanes, lane) {
                    0
                } else if lanes == 1 {
                    32
                } else {
                    lane_limit(lanes, lane)
                };
                VecDeque::with_capacity(capacity)
            })
            .collect();
        XPort {
            shares: Shares::new(n),
            ep,
            backlog,
            active: VecDeque::with_capacity(n * lanes),
            queued: 0,
            stalls: 0,
            msg_stat: [(0, 0, 0); 3],
            phase: std::env::var_os("NV_PHASE").is_some(),
            #[cfg(target_os = "linux")]
            wake: None,
            #[cfg(target_os = "linux")]
            wake_pending: vec![false; n],
            #[cfg(target_os = "linux")]
            wake_targets: Vec::with_capacity(n),
        }
    }

    /// Poke sleeping destination cores after sending to them (`wake[i]` = core i).
    #[cfg(target_os = "linux")]
    pub fn set_wake(&mut self, w: std::sync::Arc<[std::sync::Arc<crate::wake::Wake>]>) {
        self.wake = Some(w);
    }

    /// Nothing waits in the inbox (the sleeper's re-check after announcing its sleep, see `crate::wake`).
    pub fn inbox_empty(&self) -> bool {
        self.ep.inbox_empty()
    }

    /// This core's index.
    pub fn id(&self) -> usize {
        self.ep.id()
    }

    /// Deliver the inbox to `osd`, move its outbox to the rings. True if anything moved.
    pub fn pump<B: Backend>(&mut self, osd: &mut Osd<B>, now: Duration) -> bool {
        self.pump_with(osd, now, &mut |_| {})
    }

    /// [`XPort::pump`] with `flush_link`: what the driver does for the output this core queued on its own links (frames of
    /// a repop whose peer link lives here) before a send-first local txn is applied.
    pub fn pump_with<B: Backend>(
        &mut self,
        osd: &mut Osd<B>,
        now: Duration,
        flush_link: &mut impl FnMut(&mut Osd<B>),
    ) -> bool {
        let phase = self.phase;
        let mut stat = self.msg_stat;
        let mut received = 0;
        let mut units = 0usize;
        self.shares.start(osd.start_drain());
        loop {
            let shares = &self.shares;
            let Some((from, message)) = self
                .ep
                .poll_ready(|from, _, m| shares.open(from) && osd.xmsg_ready(from, m))
            else {
                break;
            };
            received += 1;
            let work = message.slice_work();
            units += work;
            self.shares.take(from, work);
            if phase {
                let kind = match &message {
                    XMsg::Op { .. } => 0,
                    XMsg::Wire { .. } => 1,
                    _ => 2,
                };
                let t = std::time::Instant::now();
                osd.on_xmsg_send_first(from, message, now);
                let ns = t.elapsed().as_nanos() as u64;
                stat[kind].0 += 1;
                stat[kind].1 += ns;
                stat[kind].2 = stat[kind].2.max(ns);
            } else {
                osd.on_xmsg_send_first(from, message, now);
            }
            if osd.late_pending() {
                // send-first (adr 0008 am. 2): the repops of a client write go to the rings before its local txn
                self.flush_out(osd);
                flush_link(osd);
                osd.apply_late();
            }
        }
        #[cfg(target_os = "linux")]
        self.wake_senders();
        if self.shares.full && !self.ep.inbox_empty() {
            osd.note_slice_cut();
        }
        osd.slice_add(units);
        let work = received != 0;
        self.msg_stat = stat;
        work | self.flush_out(osd)
    }

    /// Move the OSD's outbox to the rings. True if anything moved.
    pub fn flush_out<B: Backend>(&mut self, osd: &mut Osd<B>) -> bool {
        if self.ep.lanes() == 1 {
            self.send(|| osd.poll_xmsg())
        } else {
            self.send_osd(osd)
        }
    }

    /// Hand inbox messages to `f` until no source core with messages has share left (`budget` work units each, [`Shares`])
    /// or `f` refuses one (it was moved). Returns how many were moved. Same bounds as `pump`.
    #[cfg(test)]
    fn drain(&mut self, budget: usize, mut f: impl FnMut(usize, XMsg) -> bool) -> usize {
        self.shares.start(budget);
        let mut n = 0usize;
        loop {
            let shares = &self.shares;
            let Some((from, m)) = self.ep.poll_ready(|from, _, _| shares.open(from)) else {
                break;
            };
            n += 1;
            self.shares.take(from, m.slice_work());
            if !f(from, m) {
                break;
            }
        }
        #[cfg(target_os = "linux")]
        self.wake_senders();
        n
    }

    /// Poke the sender cores whose full ring this drain freed (they registered for space, `Endpoint::space_wakes`).
    #[cfg(target_os = "linux")]
    fn wake_senders(&mut self) {
        if let Some(w) = &self.wake {
            self.ep.space_wakes(|src| w[src].poke());
        }
    }

    /// Take messages from `next` (while the backlog has room) and move the backlog to the rings. True if anything moved.
    fn send(&mut self, mut next: impl FnMut() -> Option<(usize, XMsg)>) -> bool {
        let mut work = false;
        while self.queued < MAX_BACKLOG {
            let Some((dst, m)) = next() else { break };
            let m = self.ep.stamp(dst, Route::Data(0), m);
            self.backlog[dst].push_back(m);
            self.queued += 1;
        }
        for dst in 0..self.backlog.len() {
            let (sent, wakes) = drain(
                &mut self.ep,
                dst,
                &mut self.backlog[dst],
                &mut self.queued,
                &mut self.stalls,
            );
            work |= sent;
            #[cfg(target_os = "linux")]
            if wakes && let Some(w) = &self.wake {
                w[dst].poke(); // once per destination and batch, unless no message of it wakes (`XMsg::wakes`)
            }
            #[cfg(not(target_os = "linux"))]
            let _ = wakes;
        }
        work
    }

    /// Drain eligible source-lane heads even when another lane's backlog is full.
    fn send_osd<B: Backend>(&mut self, osd: &mut Osd<B>) -> bool {
        let lanes = self.ep.lanes();
        self.send_lanes(|backlog| {
            osd.poll_xmsg_ready(|dst, lane, _| {
                backlog[dst * lanes + lane].len() < lane_limit(lanes, lane)
            })
        })
    }

    fn send_lanes(
        &mut self,
        mut next: impl FnMut(&[VecDeque<Stamped<XMsg>>]) -> Option<(usize, Stamped<XMsg>)>,
    ) -> bool {
        let lanes = self.ep.lanes();
        let mut work = false;
        let mut pulled = 0;
        while pulled < MAX_BACKLOG {
            let Some((dst, m)) = next(&self.backlog) else {
                break;
            };
            let index = dst * lanes + m.lane();
            if self.backlog[index].is_empty() {
                self.active.push_back(index);
            }
            self.backlog[index].push_back(m);
            self.queued += 1;
            pulled += 1;
        }
        let visits = self.active.len();
        for _ in 0..visits {
            let index = self.active.pop_front().unwrap();
            let dst = index / lanes;
            let queue = &mut self.backlog[index];
            let (sent, wakes) = drain(&mut self.ep, dst, queue, &mut self.queued, &mut self.stalls);
            if !queue.is_empty() {
                self.active.push_back(index);
            }
            work |= sent;
            #[cfg(target_os = "linux")]
            if wakes && self.wake.is_some() && !self.wake_pending[dst] {
                self.wake_pending[dst] = true;
                self.wake_targets.push(dst);
            }
            #[cfg(not(target_os = "linux"))]
            let _ = wakes;
        }
        #[cfg(target_os = "linux")]
        if let Some(w) = &self.wake {
            // Publish every lane before the destination's single wake fence.
            for dst in self.wake_targets.drain(..) {
                self.wake_pending[dst] = false;
                w[dst].poke();
            }
        }
        work
    }

    /// Anything still waiting for ring space?
    pub fn backlog_len(&self) -> usize {
        self.queued
    }

    /// A held message could move now: the ring of a non-empty backlog has a free slot (the sleeper's re-check after
    /// announcing its sleep; a receiver that frees a slot later pokes it, [`crate::mesh::Endpoint::space_wakes`]).
    pub fn backlog_movable(&self) -> bool {
        let lanes = self.ep.lanes();
        self.queued != 0
            && self
                .backlog
                .iter()
                .enumerate()
                .any(|(i, q)| !q.is_empty() && self.ep.tx_has_space(i / lanes, i % lanes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::mesh;

    /// Drain budget before the loop reported any busy time (1 ns per work unit).
    const B: usize = osd::xcore::SLICE_NS as usize;

    /// Microbench of the backlog-to-ring path (`drain`), one thread: batches of 64 messages through `send` (one lane)
    /// and `send_lanes` (store mesh), the receiver drained between batches. Prints ns per message.
    /// `cargo test --release -p rt --lib perf_xport_drain -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn perf_xport_drain() {
        use ingress::order::{Outbox, Sequencer};
        const N: usize = 4_000_000;
        const BATCH: usize = 64;
        let mut eps = mesh::<XMsg>(2, 256);
        let mut rx = eps.pop().unwrap();
        let mut tx = XPort::new(eps.pop().unwrap());
        let r = rx.id();
        let t = std::time::Instant::now();
        for _ in 0..N / BATCH {
            let mut n = BATCH;
            tx.send(|| {
                (n > 0).then(|| {
                    n -= 1;
                    (r, XMsg::MonSession)
                })
            });
            while rx.poll().is_some() {}
        }
        let one = t.elapsed().as_nanos() as f64 / N as f64;
        let mut eps = crate::mesh::mesh_store::<XMsg>(2, 256, 4);
        let mut rx = eps.pop().unwrap();
        let mut tx = XPort::new(eps.pop().unwrap());
        let lanes = tx.ep.lanes();
        let mut sequence = Sequencer::new(2, lanes);
        let mut source = Outbox::new(2, lanes);
        let t = std::time::Instant::now();
        for _ in 0..N / BATCH {
            for k in 0..BATCH {
                let route = if k % 2 == 0 {
                    Route::Data(1)
                } else {
                    Route::Progress
                };
                source.push(1, sequence.stamp(1, route, XMsg::MonSession));
            }
            tx.send_lanes(|_| source.pop_ready(|_, _, _| true));
            while rx.poll().is_some() {}
        }
        let lanes_ns = t.elapsed().as_nanos() as f64 / N as f64;
        println!("perf_xport_drain: send {one:.2} ns/msg, send_lanes {lanes_ns:.2} ns/msg");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn multiple_destination_lanes_share_one_eventfd_wake() {
        use ingress::order::{Outbox, Sequencer};
        let mut endpoints = crate::mesh::mesh_store::<XMsg>(2, 8, 4);
        let mut sender = XPort::new(endpoints.pop().unwrap());
        let mut receiver = endpoints.pop().unwrap();
        let wakes: std::sync::Arc<[_]> =
            (0..2).map(|_| crate::wake::Wake::new().unwrap()).collect();
        wakes[receiver.id()].set_sleeping(true);
        sender.set_wake(wakes.clone());
        let lanes = sender.ep.lanes();
        let mut sequence = Sequencer::new(2, lanes);
        let mut source = Outbox::new(2, lanes);
        source.push(
            0,
            sequence.stamp(0, Route::Data(0), XMsg::ReqMap { have: 1 }),
        );
        source.push(
            0,
            sequence.stamp(0, Route::Progress, XMsg::ReqMap { have: 2 }),
        );
        assert!(sender.send_lanes(|_| source.pop_ready(|_, _, _| true)));
        let mut count = 0u64;
        // SAFETY: the successful send poked this sleeping core's valid eventfd;
        // a read into a u64 consumes the complete eight-byte eventfd counter.
        assert_eq!(
            unsafe { libc::read(wakes[0].raw_fd(), (&raw mut count).cast(), 8) },
            8
        );
        assert_eq!(count, 1);
        assert!(receiver.poll().is_some());
        assert!(receiver.poll().is_some());
    }

    /// Ring space wake (doc/perf/sleep-register-20261101.md rows 2, 3): a sender whose ring is full holds the rest in its
    /// backlog and may sleep; the receiver's drain that frees a slot pokes it. Before, nothing woke it: the backlog (and
    /// the client input held behind it at `XOUT_MAX`) waited for an idle cap or an unrelated event. An awake sender is
    /// not woken but sees the space in its re-check; a drain of a ring whose sender did not wait pokes nobody.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_drain_that_frees_ring_space_wakes_the_blocked_sender() {
        let mut eps = mesh::<XMsg>(2, 4);
        let mut rx = XPort::new(eps.pop().unwrap());
        let mut tx = XPort::new(eps.pop().unwrap());
        let (s, r) = (tx.id(), rx.id());
        let wakes: std::sync::Arc<[_]> =
            (0..2).map(|_| crate::wake::Wake::new().unwrap()).collect();
        tx.set_wake(wakes.clone());
        rx.set_wake(wakes.clone());
        let fill = |tx: &mut XPort, mut n: usize| {
            tx.send(|| {
                (n > 0).then(|| {
                    n -= 1;
                    (r, XMsg::MonSession)
                })
            })
        };
        assert!(fill(&mut tx, 6));
        assert_eq!(tx.backlog_len(), 2, "4 ring slots, 2 held");
        // the sender sleeps: announce, re-check (nothing can move)
        wakes[s].set_sleeping(true);
        assert!(!tx.backlog_movable());
        assert_eq!(rx.drain(B, |_, _| false), 1);
        assert_eq!(
            wakes[s].writes(),
            1,
            "the freed slot wakes the sleeping sender"
        );
        assert!(tx.backlog_movable());
        assert!(fill(&mut tx, 0));
        assert_eq!(tx.backlog_len(), 1);
        // awake sender: no syscall, its re-check before the next sleep sees the space
        wakes[s].set_sleeping(false);
        assert_eq!(rx.drain(B, |_, _| false), 1);
        wakes[s].set_sleeping(true);
        assert!(tx.backlog_movable(), "re-check after the announcement");
        assert!(fill(&mut tx, 0));
        assert_eq!(tx.backlog_len(), 0);
        // nothing held, nothing registered: drains poke nobody
        assert_eq!(rx.drain(B, |_, _| true), 4);
        assert_eq!(wakes[s].writes(), 1);
        wakes[s].set_sleeping(false);
    }

    /// A later pre-write piece of a frame (`wake: false`) leaves a sleeping PG core asleep; the frame's op on the same
    /// lane wakes it, and its drain takes the pieces before the op (single-lane and lane-aware send paths).
    #[cfg(target_os = "linux")]
    #[test]
    fn later_pieces_wait_for_the_op_of_their_frame_and_drain_before_it() {
        use ingress::order::{Outbox, Sequencer};
        // a frame in flight: its data segment is shared while it arrives (the watch of the pieces)
        let mut wire = Vec::new();
        msgr2::Encoder::new(msgr2::Revision::V21)
            .encode_message(
                &msgr2::MsgHeader2::default().to_bytes(),
                b"f",
                b"",
                &[7u8; 65536],
                &mut wire,
            )
            .unwrap();
        let mut dec = msgr2::Decoder::new(msgr2::Revision::V21);
        dec.set_prewrite(4096);
        dec.feed(&wire[..wire.len() / 2]);
        let watch = dec.early().expect("data segment shared").data.clone();
        let piece = |wake| XMsg::PrePiece {
            spg: denc::types::SpgT::default(),
            watch: watch.clone(),
            pieces: watch.view(0, 4096).expect("published"),
            wake,
            at: 0,
        };
        for lane_aware in [false, true] {
            let mut endpoints = if lane_aware {
                crate::mesh::mesh_store::<XMsg>(2, 8, 4)
            } else {
                crate::mesh::mesh::<XMsg>(2, 8)
            };
            let mut sender = XPort::new(endpoints.pop().unwrap());
            let mut receiver = endpoints.pop().unwrap();
            let wakes: std::sync::Arc<[_]> =
                (0..2).map(|_| crate::wake::Wake::new().unwrap()).collect();
            sender.set_wake(wakes.clone());
            let lanes = sender.ep.lanes();
            let mut sequence = Sequencer::new(2, lanes);
            let mut source = Outbox::new(2, lanes);
            let mut send = |sender: &mut XPort, m: XMsg| {
                if lane_aware {
                    source.push(0, sequence.stamp(0, Route::Data(0), m));
                    sender.send_lanes(|_| source.pop_ready(|_, _, _| true))
                } else {
                    let mut m = Some(m);
                    sender.send(|| m.take().map(|m| (0, m)))
                }
            };
            wakes[0].set_sleeping(true);
            assert!(send(&mut sender, piece(false)), "lane_aware {lane_aware}");
            assert!(send(&mut sender, piece(false)));
            assert_eq!(wakes[0].writes(), 0, "a later piece does not wake");
            assert!(send(&mut sender, XMsg::ReqMap { have: 9 }));
            assert_eq!(wakes[0].writes(), 1, "the op wakes");
            assert!(matches!(
                receiver.poll(),
                Some((_, XMsg::PrePiece { wake: false, .. }))
            ));
            assert!(matches!(
                receiver.poll(),
                Some((_, XMsg::PrePiece { wake: false, .. }))
            ));
            assert!(matches!(
                receiver.poll(),
                Some((_, XMsg::ReqMap { have: 9 }))
            ));
            wakes[0].set_sleeping(true);
            assert!(send(&mut sender, piece(true)));
            assert_eq!(wakes[0].writes(), 2, "the first piece of a frame wakes");
            assert!(receiver.poll().is_some());
        }
    }

    #[test]
    fn full_shard_ring_and_backlog_leave_other_shards_and_progress_ready() {
        use ingress::order::{Outbox, Sequencer};
        let mut endpoints = crate::mesh::mesh_store::<XMsg>(2, 8, 4);
        let mut sender = XPort::new(endpoints.pop().unwrap());
        let mut receiver = endpoints.pop().unwrap();
        let lanes = sender.ep.lanes();
        let mut sequence = Sequencer::new(2, lanes);
        let mut source = Outbox::new(2, lanes);
        // Physical shards 0 and 2 share destination core 0. A has a full ring, backlog and retained source head.
        for _ in 0..96 {
            source.push(
                0,
                sequence.stamp(0, Route::Data(0), XMsg::ReqMap { have: 1 }),
            );
            source.push(
                0,
                sequence.stamp(0, Route::Data(4), XMsg::ReqMap { have: 3 }),
            );
        }
        let drain = |sender: &mut XPort, source: &mut Outbox<XMsg>| {
            sender.send_lanes(|backlog| {
                source.pop_ready(|dst, lane, _| {
                    backlog[dst * lanes + lane].len() < lane_limit(lanes, lane)
                })
            })
        };
        for _ in 0..4 {
            drain(&mut sender, &mut source);
        }
        assert_eq!(sender.backlog_len(), 64);
        assert_eq!(source.len(), 64);
        source.push(
            0,
            sequence.stamp(0, Route::Data(2), XMsg::ReqMap { have: 2 }),
        );
        source.push(
            0,
            sequence.stamp(0, Route::Data(5), XMsg::CopyReply { id: 4, r: Err(2) }),
        );
        source.push(
            0,
            sequence.stamp(0, Route::Progress, XMsg::Stats(Box::default())),
        );
        drain(&mut sender, &mut source);
        let mut seen = 0;
        while let Some((from, message)) = receiver.poll_ready(|_, lane, _| lane != 2 && lane != 6) {
            assert_eq!(from, 1);
            assert!(matches!(
                message,
                XMsg::ReqMap { have: 2 } | XMsg::CopyReply { id: 4, .. } | XMsg::Stats(_)
            ));
            seen += 1;
            assert!(seen <= 3);
        }
        assert_eq!(seen, 3);
        assert_eq!(source.len(), 64);
        assert_eq!(sender.backlog_len(), 64);
        assert!(!receiver.inbox_empty());
    }

    #[test]
    fn source_barrier_keeps_unsent_predecessors_before_control_and_later_input() {
        use ingress::order::{Outbox, Sequencer};
        let mut endpoints = crate::mesh::mesh_store::<XMsg>(2, 8, 4);
        let mut sender = XPort::new(endpoints.pop().unwrap());
        let mut receiver = endpoints.pop().unwrap();
        let lanes = sender.ep.lanes();
        let mut sequence = Sequencer::new(2, lanes);
        let mut source = Outbox::new(2, lanes);
        for have in 0..96 {
            source.push(0, sequence.stamp(0, Route::Data(0), XMsg::ReqMap { have }));
        }
        source.push(0, sequence.stamp(0, Route::Ordered, XMsg::MonSession));
        source.push(
            0,
            sequence.stamp(0, Route::Data(2), XMsg::ReqMap { have: 100 }),
        );
        sender.send_lanes(|backlog| {
            source.pop_ready(|dst, lane, _| {
                backlog[dst * lanes + lane].len() < lane_limit(lanes, lane)
            })
        });
        assert!(receiver.poll_ready(|_, lane, _| lane != 2).is_none());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut got = 0;
        let mut control = false;
        while got < 97 {
            assert!(std::time::Instant::now() < deadline);
            sender.send_lanes(|backlog| {
                source.pop_ready(|dst, lane, _| {
                    backlog[dst * lanes + lane].len() < lane_limit(lanes, lane)
                })
            });
            while let Some((_, message)) = receiver.poll() {
                match message {
                    XMsg::ReqMap { have } if have < 96 => {
                        assert_eq!(have, got);
                        got += 1;
                    }
                    XMsg::MonSession => {
                        assert_eq!(got, 96);
                        control = true;
                    }
                    XMsg::ReqMap { have: 100 } => {
                        assert!(control);
                        got += 1;
                    }
                    _ => panic!("unexpected message"),
                }
            }
        }
        assert_eq!(source.len(), 0);
        assert_eq!(sender.backlog_len(), 0);
    }

    fn msgs(x: &mut XPort, from: &mut crate::mesh::Endpoint<XMsg>, n: usize) {
        for _ in 0..n {
            assert!(from.send(x.id(), XMsg::MonSession).is_ok());
        }
    }

    /// A relayed frame with `n` payload bytes (`n` work units).
    fn wire(n: usize) -> XMsg {
        let mut m = XMsg::Wire {
            link: 1,
            tid: 0,
            prio: 0,
            hdr: (0, 0, 0),
            segs: Default::default(),
            data_crc: Default::default(),
        };
        if let XMsg::Wire { segs, .. } = &mut m {
            segs.data = bytes::Bytes::from(vec![0u8; n]);
        }
        m
    }

    #[test]
    fn admission_stops_the_inbox_but_outbound_messages_still_progress() {
        let mut eps = mesh::<XMsg>(2, 128);
        let mut peer = eps.pop().unwrap();
        let mut x = XPort::new(eps.pop().unwrap());
        msgs(&mut x, &mut peer, 10);
        assert_eq!(x.drain(B, |_, _| false), 1);
        let mut msg = Some((peer.id(), XMsg::MonSession));
        assert!(x.send(|| msg.take()));
        assert!(peer.poll().is_some());
        assert_eq!(x.drain(B, |_, _| true), 9);
    }

    #[test]
    fn the_inbox_drain_stops_after_the_message_that_fills_the_work_slice() {
        use osd::xcore::SLICE_MIN;
        let mut eps = mesh::<XMsg>(2, 128);
        let mut peer = eps.pop().unwrap();
        let mut x = XPort::new(eps.pop().unwrap());
        // big payloads: the first message always runs, then the slice is full
        for _ in 0..3 {
            assert!(peer.send(x.id(), wire(4 << 20)).is_ok());
        }
        assert_eq!(x.drain(B, |_, _| true), 1);
        assert_eq!(x.drain(B, |_, _| true), 1);
        assert_eq!(x.drain(B, |_, _| true), 1);
        // payload-free messages count one block each: the message that fills the slice is the last
        let per = B.div_ceil(SLICE_MIN);
        msgs(&mut x, &mut peer, per + 5);
        assert_eq!(x.drain(B, |_, _| true), per);
        assert_eq!(x.drain(B, |_, _| true), 5);
    }

    /// adr 0006 am. 6: a hot PG core drained one forwarded op per iteration next to all of its own links' ops.
    #[test]
    fn every_source_core_gets_its_own_share_of_the_inbox_drain() {
        use osd::xcore::SLICE_MIN;
        let mut eps = mesh::<XMsg>(4, 128);
        let mut src = eps.split_off(1);
        let mut x = XPort::new(eps.pop().unwrap());
        let big = 4 << 20;
        // big messages fill a share each: every drain takes the first message of every source, in round-robin order
        for s in &mut src {
            for _ in 0..3 {
                assert!(s.send(x.id(), wire(big)).is_ok());
            }
        }
        for _ in 0..3 {
            let mut from = Vec::new();
            assert_eq!(
                x.drain(B, |f, _| {
                    from.push(f);
                    true
                }),
                3
            );
            from.sort_unstable();
            assert_eq!(from, [1, 2, 3]);
        }
        assert_eq!(x.drain(B, |_, _| true), 0);
        // a share as large as the own links' work since the previous drain (two messages): two per source
        for s in &mut src {
            for _ in 0..3 {
                assert!(s.send(x.id(), wire(big)).is_ok());
            }
        }
        assert_eq!(x.drain(2 * big, |_, _| true), 6);
        assert_eq!(x.drain(2 * big, |_, _| true), 3);
        // one source's backlog of small messages leaves the others' shares alone
        let per = B.div_ceil(SLICE_MIN);
        msgs(&mut x, &mut src[0], per + 5);
        msgs(&mut x, &mut src[1], 2);
        assert_eq!(x.drain(B, |_, _| true), per + 2);
        assert_eq!(x.drain(B, |_, _| true), 5);
        // work alone bounds a share: a run of small messages goes on to the end of its source's share (no count bound)
        msgs(&mut x, &mut src[0], 100);
        msgs(&mut x, &mut src[2], 1);
        assert_eq!(x.drain(100 * SLICE_MIN, |_, _| true), 101);
        assert_eq!(x.drain(B, |_, _| true), 0);
        // an empty share still takes each source's first message
        msgs(&mut x, &mut src[0], 2);
        msgs(&mut x, &mut src[1], 2);
        assert_eq!(x.drain(0, |_, _| true), 2);
        assert_eq!(x.drain(0, |_, _| true), 2);
    }

    #[test]
    fn a_stalled_peer_costs_bounded_memory_and_nothing_is_lost() {
        let mut eps = mesh::<XMsg>(2, 4);
        let mut b = eps.pop().unwrap();
        let mut x = XPort::new(eps.pop().unwrap());
        let mut left = 3 * MAX_BACKLOG;
        let mut produced = 0usize;
        // core 1 does not drain: the ring (4) fills, the backlog fills up to its limit, the port stops pulling
        for _ in 0..4 {
            x.send(|| {
                (left > 0).then(|| {
                    left -= 1;
                    produced += 1;
                    (1, XMsg::MonSession)
                })
            });
        }
        assert_eq!(x.backlog_len(), MAX_BACKLOG);
        assert_eq!(produced, MAX_BACKLOG + 4, "ring + backlog, then it stopped");
        // the peer wakes up: everything arrives (the rest of the outbox included), in the end nothing is left over
        let mut got = 0usize;
        while got < 3 * MAX_BACKLOG {
            x.send(|| {
                (left > 0).then(|| {
                    left -= 1;
                    (1, XMsg::MonSession)
                })
            });
            got += b.drain(usize::MAX, |_, _| ());
        }
        assert_eq!(x.backlog_len(), 0);
    }
}
