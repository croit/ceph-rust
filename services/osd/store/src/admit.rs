// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Device admission window (adr 0643-device-admission-fifo): the data writes of all store shards of one device enter
//! the device in arrival order, and at most one window of their bytes is in flight on the device.
//!
//! Why: NVMe controllers fetch from their submission queues round robin. A drive that fetches less than the shards
//! queue (PM9A3: ~12 ms of work) serves every shard's queue at 1/N of the device, so a write's latency follows its
//! own core's backlog (random over the PG hash). With the device holding only about what it fetches, round robin over
//! shallow queues is arrival order (doc/perf/w4m-p99-20261102.md).
//!
//! Order: a txn's data bytes take one range of the device's byte stream ([`DevAdmit::take`], one `fetch_add`): its
//! ticket. A write whose range ends at `end` may go to the device once `end <= done + window` ([`DevAdmit::limit`]),
//! where `done` counts the window bytes completed so far, all shards. The limit only grows with completions, so tickets
//! become admissible strictly in stream order, and no shard grants anything: a write is admissible by its position
//! alone. A core that does not run delays only its own admissible writes (their bytes stay counted until it submits
//! them); later tickets of other shards go as the others complete. Liveness: the oldest incomplete position `p` has
//! `done >= p`, so its write (at most one largest device write) is admissible whenever `window >= max transfer`.
//!
//! Uncontended path ([`Admit::free`]): a data txn of at most one largest device write, on a shard with no data in
//! flight or waiting, while nothing ticketed is incomplete (nothing is ahead of it), goes to the device outside the
//! window: no ticket, no probe, no shared line written (two loads of lines nobody writes while all writes take this
//! path, e.g. QD1). Order is not at stake: nothing is ahead. Bound: one such txn per shard (its next txn takes a
//! ticket, and any ticket outstanding sends every shard's txns through the window), so the device holds at most `lo`
//! beyond the window.
//!
//! Window ([`Admit::probe_landed`]): a window write submitted while its shard has no window bytes in flight is a probe
//! (its own submission queue holds none of the window). `ahead` = the stream bytes before the probe not complete at its
//! submission; `est` = the window bytes completed while the probe was in the device (itself included). A device that
//! holds the stream ahead of the probe (FIFO, or a window within its fetch depth) completes all of it first:
//! `est >= ahead`. A device that fetches less serves the probe after its fetch depth: `est < ahead`, and `est` is the
//! depth it serves ahead of a fresh command (so are bytes ahead that were not submitted yet: queue-capped or descheduled
//! shards). Rule per probe, with `step = window / 8`:
//! - `est >= ahead` (no limit seen): grow by `step` if the window held back a write of the shard since its last probe,
//!   else keep. A probe with nothing ahead (`ahead = 0`) is this case: the device drained the whole stream while the
//!   window held a write back, a growth signal of a window below the demand;
//! - `est < ahead`: `target = est + est / 8`; move toward it by at most `step` if the window held back a write, else
//!   only down (shrink to `target`, at most `step`).
//!
//! The window settles 1/8 above the depth the device serves ahead of a fresh command, or opens past the demand on a
//! device that holds everything.
//!
//! Bounds from geometry ([`Admit::new`]): at least one largest device write per shard of the device, at most what the
//! shards' queues can hold of data. Start: the upper bound, so a device behaves as without the window until a probe
//! measures a fetch limit (`est < ahead`). Nothing else is configured.
//!
//! Atomics: per window txn one `fetch_add` on the tail line, per poll with window completions one `fetch_add` on the
//! done line, a load of `done` / `window` only when a write is past the cached limit, is a probe or a probe lands;
//! the shard's own slot line (outstanding bytes, for give-back) is written by its core only. A txn on the uncontended
//! path loads `tail` and `done` and writes nothing shared. No locks, no allocation after `init`.
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Tag bit of the probe write (in the id part of a `K_DATA` / `K_PRE` tag: unit seqs and pre-write slots stay below it).
pub(crate) const ADM_PROBE: u64 = 1 << 55;
/// Tag bit of a data write outside the window ([`Admit::free`], `K_DATA` only).
pub(crate) const ADM_OFF: u64 = 1 << 54;
/// The window's tag bits in a `K_DATA` / `K_PRE` id.
pub(crate) const ADM_TAGS: u64 = ADM_PROBE | ADM_OFF;

use crate::devidle::Line;

/// Admission state of one device, shared by its shards (held by [`crate::devidle::DevIdle`]).
#[derive(Debug, Default)]
pub struct DevAdmit {
    /// Window bytes ticketed so far: the stream position of the next ticket.
    tail: Line,
    /// Window bytes completed (or given back) so far, all shards.
    done: Line,
    /// Window bytes (0 = not started: [`DevAdmit::start`]).
    win: Line,
    /// Per shard: bytes ticketed and not yet completed (give-back on failure / remount).
    slots: OnceLock<Box<[Line]>>,
}

impl DevAdmit {
    /// Size the per-shard slots (with [`crate::devidle::DevIdle::init`]).
    pub(crate) fn init(&self, n: usize) {
        self.slots
            .get_or_init(|| (0..n).map(|_| Line::default()).collect());
    }

    fn slot(&self, i: usize) -> Option<&AtomicU64> {
        self.slots.get().and_then(|s| s.get(i)).map(|l| &l.0)
    }

    /// The first shard sets the start window; later mounts keep the running one.
    pub(crate) fn start(&self, w: u64) {
        let _ = self.win.0.compare_exchange(0, w, Relaxed, Relaxed);
    }

    /// Current window bytes.
    pub fn window(&self) -> u64 {
        self.win.0.load(Relaxed)
    }

    #[cfg(test)]
    fn set_window(&self, w: u64) {
        self.win.0.store(w, Relaxed);
    }

    /// Move the window from `w` (read by the caller) to `new`. False: another shard's probe moved it since (its move
    /// stands; the shards' probes run concurrently).
    fn move_window(&self, w: u64, new: u64) -> bool {
        self.win
            .0
            .compare_exchange(w, new, Relaxed, Relaxed)
            .is_ok()
    }

    /// Window bytes completed so far.
    pub(crate) fn done(&self) -> u64 {
        self.done.0.load(Relaxed)
    }

    /// Stream positions up to this may go to the device now.
    pub(crate) fn limit(&self) -> u64 {
        self.done() + self.window()
    }

    /// Ticket `len` bytes for shard `i`: the start of its stream range.
    pub(crate) fn take(&self, i: usize, len: u64) -> u64 {
        if let Some(s) = self.slot(i) {
            s.fetch_add(len, Relaxed);
        }
        self.tail.0.fetch_add(len, Relaxed)
    }

    /// Ticket `len` bytes for shard `i` only if they are admissible at once (nothing ticketed waits for the window):
    /// the start of the range, `None` = the window is full.
    pub(crate) fn take_now(&self, i: usize, len: u64) -> Option<u64> {
        let fits = |t: u64| (t + len <= self.limit()).then_some(t + len);
        let t = self.tail.0.try_update(Relaxed, Relaxed, fits).ok()?;
        if let Some(s) = self.slot(i) {
            s.fetch_add(len, Relaxed);
        }
        Some(t)
    }

    /// Shard `i`'s window bytes completed (or will never be submitted). With slots only what the shard still counts (a
    /// reset gave the rest back already); a table without slots gives `len`.
    pub(crate) fn give(&self, i: usize, len: u64) {
        let n = match self.slot(i) {
            Some(s) => {
                let n = len.min(s.load(Relaxed));
                s.fetch_sub(n, Relaxed);
                n
            }
            None => len,
        };
        self.done.0.fetch_add(n, Relaxed);
    }

    /// Shard `i` reaps nothing more (failure, mount after an earlier instance): what it had ticketed counts as done.
    pub(crate) fn reset(&self, i: usize) {
        if let Some(s) = self.slot(i) {
            self.done.0.fetch_add(s.swap(0, Relaxed), Relaxed);
        }
    }

    /// Ticketed bytes not completed yet, all shards (in flight or waiting).
    pub fn outstanding(&self) -> u64 {
        self.tail.0.load(Relaxed).saturating_sub(self.done())
    }
}

/// Window counters of one shard (`perf dump` `adm_*`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AdmitStats {
    /// Data writes that did not go out at their commit because the window was full.
    pub waits: u64,
    /// Data writes outside the window (uncontended path: nothing ahead).
    pub free: u64,
    /// Probe writes evaluated; window steps up / down they made.
    pub probes: u64,
    pub grows: u64,
    pub shrinks: u64,
}

impl std::ops::AddAssign for AdmitStats {
    fn add_assign(&mut self, o: AdmitStats) {
        self.waits += o.waits;
        self.free += o.free;
        self.probes += o.probes;
        self.grows += o.grows;
        self.shrinks += o.shrinks;
    }
}

/// Why a backlog drain stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// Nothing left.
    Empty,
    /// The shard's own device queue has no room above its WAL floor.
    Queue,
    /// The front write is past the device window.
    Window,
    /// The front write is a deferred copy ([`crate::shard::CopyRun`]) the DMA budget has no buffer for now (adr 0175 am.
    /// N?): retried at every shard poll, as IO in flight completes.
    Dma,
}

/// One shard's side of the window: cached limit, own bytes in flight, the probe and the window rule.
#[derive(Debug)]
pub(crate) struct Admit {
    lo: u64,
    hi: u64,
    /// Largest device write: the most a txn on the uncontended path carries.
    xfer: u64,
    /// Cached [`DevAdmit::limit`] (reloaded when a write is past it).
    limit: u64,
    /// Own window bytes in flight; own bytes completed in this reap, not yet given to the device.
    pub(crate) inflight: u64,
    gave: u64,
    /// Own bytes outside the window, in flight or waiting for queue room.
    pub(crate) off: u64,
    /// The window held back a write of this shard since its last probe.
    blocked: bool,
    /// The probe in flight: (its stream start, `done` at its submission); landed in this reap.
    probe: Option<(u64, u64)>,
    landed: bool,
    pub(crate) stats: AdmitStats,
}

impl Admit {
    /// Bounds: `lo` = one largest device write (`max_xfer` bytes) per shard of the device (`shards`); `hi` = every
    /// shard's data slots (`data_slots`, its queue depth above the WAL floor) filled with largest writes.
    pub(crate) fn new(shards: usize, max_xfer: u64, data_slots: usize) -> Admit {
        let n = shards.max(1) as u64;
        let lo = n * max_xfer;
        Admit {
            lo,
            hi: (n * data_slots as u64 * max_xfer).max(lo),
            xfer: max_xfer,
            limit: 0,
            inflight: 0,
            gave: 0,
            off: 0,
            blocked: false,
            probe: None,
            landed: false,
            stats: AdmitStats::default(),
        }
    }

    /// The start window of the device: the upper bound (module doc).
    pub(crate) fn hi(&self) -> u64 {
        self.hi
    }

    /// A data txn of `bytes` takes the uncontended path (module doc): its writes carry [`ADM_OFF`] and take no ticket.
    /// Local state first: under load the shared lines are not read.
    #[inline]
    pub(crate) fn free(&mut self, dev: &DevAdmit, bytes: u64) -> bool {
        let f = bytes <= self.xfer && self.off == 0 && self.inflight == 0 && dev.outstanding() == 0;
        if f {
            self.off += bytes;
        }
        f
    }

    /// The write ending at stream position `end` may go to the device now.
    #[inline]
    pub(crate) fn admits(&mut self, dev: &DevAdmit, end: u64) -> bool {
        if end <= self.limit {
            return true;
        }
        self.limit = dev.limit();
        if end <= self.limit {
            return true;
        }
        self.blocked = true;
        false
    }

    /// A pre-write (adr 0477) of `len` bytes asks for a ticket that is admissible at once: its stream start.
    pub(crate) fn take_now(&mut self, dev: &DevAdmit, me: usize, len: u64) -> Option<u64> {
        let r = dev.take_now(me, len);
        self.blocked |= r.is_none();
        r
    }

    /// A window write of `len` bytes starting at stream position `start` goes to the device: the tag bit it carries
    /// ([`ADM_PROBE`] when it is the probe: the shard has no window bytes in flight and no probe out).
    #[inline]
    pub(crate) fn submitted(&mut self, dev: &DevAdmit, start: u64, len: u64) -> u64 {
        let probe = self.inflight == 0 && self.probe.is_none();
        self.inflight += len;
        if probe {
            self.probe = Some((start, dev.done()));
            ADM_PROBE
        } else {
            0
        }
    }

    /// A window write [`Admit::submitted`] with tag bit `probe` was refused by the device: its bytes go back.
    pub(crate) fn unsubmitted(&mut self, dev: &DevAdmit, me: usize, len: u64, probe: u64) {
        self.inflight = self.inflight.saturating_sub(len);
        if probe != 0 {
            self.probe = None;
        }
        dev.give(me, len);
    }

    /// A data write of `len` bytes completed (reap loop); `tag` = its [`ADM_TAGS`] bits.
    #[inline]
    pub(crate) fn completed(&mut self, len: u64, tag: u64) {
        if tag & ADM_OFF != 0 {
            self.off = self.off.saturating_sub(len);
            return;
        }
        self.inflight = self.inflight.saturating_sub(len);
        self.gave += len;
        self.landed |= tag & ADM_PROBE != 0;
    }

    /// End of a reap: the completed bytes go to the device count, then a landed probe moves the window.
    pub(crate) fn reaped(&mut self, dev: &DevAdmit, me: usize) {
        if self.gave > 0 {
            dev.give(me, std::mem::take(&mut self.gave));
        }
        if std::mem::take(&mut self.landed)
            && let Some((start, d0)) = self.probe.take()
        {
            self.probe_landed(dev, start, d0);
        }
    }

    /// The window rule (module doc).
    fn probe_landed(&mut self, dev: &DevAdmit, start: u64, d0: u64) {
        self.stats.probes += 1;
        let est = dev.done().saturating_sub(d0);
        let ahead = start.saturating_sub(d0);
        // no limit seen: nothing to approach (`MAX`); else 1/8 above the depth the device served ahead of the probe
        let target = if est >= ahead {
            u64::MAX
        } else {
            est + est / 8
        };
        let w = dev.window();
        let step = (w / 8).max(1);
        let new = if std::mem::take(&mut self.blocked) {
            target.clamp(w.saturating_sub(step), w.saturating_add(step))
        } else {
            target.clamp(w.saturating_sub(step), w)
        }
        .clamp(self.lo, self.hi);
        if new != w && dev.move_window(w, new) {
            if new > w {
                self.stats.grows += 1;
            } else {
                self.stats.shrinks += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const MIB: u64 = 1 << 20;

    #[test]
    fn tickets_become_admissible_in_stream_order_only() {
        let d = DevAdmit::default();
        d.init(3);
        d.start(8 * MIB);
        let mut a: Vec<Admit> = (0..3).map(|_| Admit::new(3, MIB, 16)).collect();
        // shard 0: 6 MiB, shard 1: 4 MiB, shard 2: 1 MiB
        let s0 = d.take(0, 6 * MIB);
        let s1 = d.take(1, 4 * MIB);
        let s2 = d.take(2, MIB);
        assert_eq!((s0, s1, s2), (0, 6 * MIB, 10 * MIB));
        assert!(a[0].admits(&d, s0 + 6 * MIB));
        assert!(
            !a[1].admits(&d, s1 + 4 * MIB),
            "10 MiB end is past the 8 MiB window"
        );
        assert!(
            a[1].admits(&d, s1 + 2 * MIB),
            "its first 2 MiB are inside: a txn goes out in waves"
        );
        assert!(!a[2].admits(&d, s2 + MIB), "a later ticket never passes");
        assert_eq!(d.outstanding(), 11 * MIB);
        // 2 MiB of shard 0 complete: the limit moves by exactly that much
        d.give(0, 2 * MIB);
        assert!(a[1].admits(&d, s1 + 4 * MIB));
        assert!(!a[2].admits(&d, s2 + MIB));
        d.give(0, MIB);
        assert!(a[2].admits(&d, s2 + MIB));
    }

    #[test]
    fn a_stalled_shard_holds_only_its_own_bytes_and_later_tickets_progress() {
        let d = DevAdmit::default();
        d.init(2);
        d.start(8 * MIB);
        let mut b = Admit::new(2, MIB, 16);
        // shard 0 takes the head of the stream and never runs again
        let h = d.take(0, 4 * MIB);
        assert_eq!(h, 0);
        // shard 1 keeps writing: 1 MiB writes, each completes before the next poll
        let mut inflight = VecDeque::new();
        let mut written = 0u64;
        for _ in 0..1000 {
            let s = d.take(1, MIB);
            // the device completes shard 1's oldest writes until the new one is admissible
            while !b.admits(&d, s + MIB) {
                let (_, l) = inflight.pop_front().expect(
                    "nothing in flight, the ticket still waits: the stalled head blocks it",
                );
                b.completed(l, 0);
                b.reaped(&d, 1);
            }
            b.submitted(&d, s, MIB);
            inflight.push_back((s + MIB, MIB));
            written += MIB;
            // at most the window minus the stalled head's bytes is in flight
            let fl: u64 = inflight.iter().map(|x| x.1).sum();
            assert!(fl <= 8 * MIB - 4 * MIB, "{fl} in flight");
        }
        assert_eq!(written, 1000 * MIB);
        // the stalled shard resumes: its head is admissible
        let mut a = Admit::new(2, MIB, 16);
        assert!(a.admits(&d, h + 4 * MIB));
        // or it fails: what it ticketed comes back, a late completion gives nothing twice
        d.reset(0);
        assert_eq!(d.outstanding(), inflight.iter().map(|x| x.1).sum::<u64>());
        d.give(0, 4 * MIB);
        assert_eq!(d.outstanding(), inflight.iter().map(|x| x.1).sum::<u64>());
    }

    #[test]
    fn take_now_only_when_nothing_waits() {
        let d = DevAdmit::default();
        d.init(2);
        d.start(4 * MIB);
        let mut a = Admit::new(2, MIB, 16);
        assert_eq!(a.take_now(&d, 0, 2 * MIB), Some(0));
        assert_eq!(a.take_now(&d, 0, 2 * MIB), Some(2 * MIB));
        assert_eq!(a.take_now(&d, 1, MIB), None, "window full");
        assert!(a.blocked);
        let s = d.take(1, MIB);
        d.give(0, 2 * MIB);
        // 1 MiB of shard 1 waits ahead: a pre-write of 2 MiB would end past the limit
        assert_eq!(a.take_now(&d, 0, 2 * MIB), None);
        assert_eq!(a.take_now(&d, 0, MIB), Some(s + MIB));
    }

    /// Uncontended path: a lone txn of one largest write on an idle device takes no ticket, is no probe and writes
    /// nothing shared; the shard's next txn while it is out, and any txn while a ticket is outstanding, go through the
    /// window (as probes: their shards have no window bytes in flight).
    #[test]
    fn a_txn_with_nothing_ahead_takes_no_ticket_and_no_probe() {
        let d = DevAdmit::default();
        d.init(2);
        d.start(8 * MIB);
        let mut a: Vec<Admit> = (0..2).map(|_| Admit::new(2, MIB, 16)).collect();
        assert!(!a[0].free(&d, 2 * MIB), "more than one largest write");
        assert!(a[0].free(&d, MIB));
        assert_eq!((d.outstanding(), a[0].off), (0, MIB));
        assert!(!a[0].free(&d, MIB), "one txn per shard outside the window");
        // shard 1 has nothing out and nothing is ticketed: it goes too (the bound: one per shard)
        assert!(a[1].free(&d, MIB));
        a[1].completed(MIB, ADM_OFF);
        a[1].reaped(&d, 1);
        assert_eq!(
            (a[1].off, d.outstanding(), d.done()),
            (0, 0, 0),
            "nothing shared written"
        );
        // shard 0's next txn takes a ticket; nothing ahead of it (its probe can only confirm `est >= ahead = 0`)
        let s0 = d.take(0, MIB);
        assert!(a[0].admits(&d, s0 + MIB));
        assert_eq!(a[0].submitted(&d, s0, MIB), ADM_PROBE);
        // a ticket is outstanding: shard 1's txn goes through the window behind it and is the probe
        assert!(!a[1].free(&d, MIB));
        let s1 = d.take(1, MIB);
        assert!(a[1].admits(&d, s1 + MIB));
        assert_eq!(a[1].submitted(&d, s1, MIB), ADM_PROBE);
        a[0].completed(MIB, ADM_OFF);
        a[0].completed(MIB, ADM_PROBE);
        a[0].reaped(&d, 0);
        a[1].completed(MIB, ADM_PROBE);
        a[1].reaped(&d, 1);
        assert_eq!(
            (a[0].stats.probes, a[1].stats.probes, d.outstanding()),
            (1, 1, 0)
        );
        assert_eq!(
            d.window(),
            8 * MIB,
            "all ahead completed first, not blocked: kept"
        );
        assert!(a[0].free(&d, MIB) && a[1].free(&d, MIB));
    }

    /// Discrete event model of one device under a closed loop of large writes: `k` internal command slots fetched round
    /// robin from the shards' submission queues (`k = usize::MAX`: the device fetches everything), served oldest first
    /// by `lanes` parallel units (1: one command at a time, in fetch order; more: each takes `lanes` x the per-command
    /// time +-50 %, so commands complete out of fetch order at the same throughput). Returns (mean, p99) txn latency
    /// in us and the final window.
    fn model(
        k: usize,
        lanes: usize,
        window: bool,
        start_hi: bool,
        clients: usize,
        txns: usize,
    ) -> (u64, u64, u64) {
        const SHARDS: usize = 4;
        const EXT: u64 = 128 << 10; // 4 MiB txn = 32 extents
        const PER: usize = 32;
        const TAU: u64 = 49; // us per extent: ~2.67 GB/s
        const QCAP: usize = 222;
        #[derive(Clone, Copy)]
        struct Cmd {
            sh: usize,
            txn: usize,
            tag: u64,
        }
        let d = DevAdmit::default();
        d.init(SHARDS);
        let mut adm: Vec<Admit> = (0..SHARDS).map(|_| Admit::new(SHARDS, EXT, QCAP)).collect();
        d.start(if start_hi { adm[0].hi() } else { adm[0].lo });
        if !window {
            d.set_window(u64::MAX / 4);
        }
        let mut back: Vec<VecDeque<(u64, usize)>> = vec![VecDeque::new(); SHARDS];
        let mut sq: Vec<VecDeque<Cmd>> = vec![VecDeque::new(); SHARDS];
        let mut inq: VecDeque<Cmd> = VecDeque::new();
        let mut rr = 0usize;
        let mut left = vec![0usize; clients + txns + 1];
        let mut t0 = vec![0u64; clients + txns + 1];
        let mut lat = Vec::new();
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        let mut next_txn = 0usize;
        let mut new_txn = |t: u64,
                           back: &mut Vec<VecDeque<(u64, usize)>>,
                           left: &mut Vec<usize>,
                           t0: &mut Vec<u64>| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let sh = (rng % SHARDS as u64) as usize;
            let id = next_txn;
            next_txn += 1;
            let mut e = d.take(sh, EXT * PER as u64);
            for _ in 0..PER {
                e += EXT;
                back[sh].push_back((e, id));
            }
            left[id] = PER;
            t0[id] = t;
        };
        let drain = |sh: usize,
                     adm: &mut Vec<Admit>,
                     back: &mut Vec<VecDeque<(u64, usize)>>,
                     sq: &mut Vec<VecDeque<Cmd>>| {
            while let Some(&(e, txn)) = back[sh].front() {
                if sq[sh].len() >= QCAP || !adm[sh].admits(&d, e) {
                    break;
                }
                back[sh].pop_front();
                let tag = adm[sh].submitted(&d, e - EXT, EXT);
                sq[sh].push_back(Cmd { sh, txn, tag });
            }
        };
        // commands in service: (finish time, command); the device's slots hold `inq` and these
        let mut busy: Vec<(u64, Cmd)> = Vec::new();
        let fetch =
            |inq: &mut VecDeque<Cmd>, sq: &mut Vec<VecDeque<Cmd>>, rr: &mut usize, held: usize| {
                while inq.len() + held < k {
                    let Some(i) = (0..SHARDS)
                        .map(|j| (*rr + j) % SHARDS)
                        .find(|&j| !sq[j].is_empty())
                    else {
                        break;
                    };
                    inq.push_back(sq[i].pop_front().unwrap());
                    *rr = (i + 1) % SHARDS;
                }
            };
        for _ in 0..clients {
            new_txn(0, &mut back, &mut left, &mut t0);
        }
        for sh in 0..SHARDS {
            drain(sh, &mut adm, &mut back, &mut sq);
        }
        fetch(&mut inq, &mut sq, &mut rr, 0);
        let mut t = 0u64;
        let mut srng = 0x2545_f491_4f6c_dd1du64;
        while lat.len() < txns {
            while busy.len() < lanes {
                let Some(c) = inq.pop_front() else { break };
                let s = if lanes == 1 {
                    TAU
                } else {
                    srng ^= srng << 13;
                    srng ^= srng >> 7;
                    srng ^= srng << 17;
                    TAU * lanes as u64 / 2 + srng % (TAU * lanes as u64)
                };
                busy.push((t + s, c));
            }
            let i = (0..busy.len())
                .min_by_key(|&i| busy[i].0)
                .expect("device idle with work ticketed");
            let (f, c) = busy.swap_remove(i);
            t = f;
            adm[c.sh].completed(EXT, if window { c.tag } else { 0 });
            adm[c.sh].reaped(&d, c.sh);
            left[c.txn] -= 1;
            if left[c.txn] == 0 {
                lat.push(t - t0[c.txn]);
                new_txn(t, &mut back, &mut left, &mut t0);
            }
            for sh in 0..SHARDS {
                drain(sh, &mut adm, &mut back, &mut sq);
            }
            fetch(&mut inq, &mut sq, &mut rr, busy.len());
        }
        // the warm-up (window ramp, first loop round) is not measured
        let mut l: Vec<u64> = lat[txns / 4..].to_vec();
        let mean = l.iter().sum::<u64>() / l.len() as u64;
        l.sort_unstable();
        (mean, l[l.len() * 99 / 100], d.window())
    }

    /// The measured mechanism (doc/perf/w4m-p99-20261102.md, model): a device that fetches 270 commands round robin,
    /// 32 x 4 MiB in flight. Without the window p99 is ~2.3x the mean; with it near the mean, at the same throughput
    /// (mean = Little), and the window settles near the fetch depth from below (ramp) and from above (shrink).
    #[test]
    fn model_round_robin_device_window_brings_p99_to_the_mean() {
        let (m0, p0, _) = model(270, 1, false, false, 32, 6000);
        let (m1, p1, w1) = model(270, 1, true, false, 32, 6000);
        let (m2, p2, w2) = model(270, 1, true, true, 32, 6000);
        eprintln!(
            "rr no window mean {m0} p99 {p0}; window from lo {m1} {p1} w {w1}; from hi {m2} {p2} w {w2}"
        );
        let k = 270 * (128 << 10) as u64;
        assert!(p0 > 2 * m0, "the model reproduces the split: {p0} vs {m0}");
        // a demand within the fetch depth (4 x 4 MiB): the window opens past it and changes nothing
        let (m3, p3, _) = model(270, 1, false, false, 4, 3000);
        let (m4, p4, w4) = model(270, 1, true, false, 4, 3000);
        eprintln!("rr 4 clients: no window {m3} {p3}; window {m4} {p4} w {w4}");
        assert!(m4 <= m3 + m3 / 50 && p4 <= p3 + p3 / 20);
        assert!(w4 >= 4 * 4 * MIB, "window {w4} below the demand");
        for (m, p, w) in [(m1, p1, w1), (m2, p2, w2)] {
            assert!(m <= m0 + m0 / 50, "throughput kept: mean {m} vs {m0}");
            assert!(p < m + m / 4, "p99 {p} near the mean {m}");
            assert!(
                w > k * 3 / 4 && w < k * 3 / 2,
                "window {w} near the fetch depth {k}"
            );
        }
    }

    /// A device that fetches everything (PM1743, FIFO): the window grows past the demand and changes nothing.
    #[test]
    fn model_fifo_device_window_opens_past_the_demand() {
        let (m0, p0, _) = model(usize::MAX, 1, false, false, 32, 4000);
        let (m1, p1, w1) = model(usize::MAX, 1, true, false, 32, 4000);
        eprintln!("fifo no window mean {m0} p99 {p0}; window {m1} {p1} w {w1}");
        assert!(m1 <= m0 + m0 / 50 && p1 <= p0 + p0 / 20);
        // opened to about what the shard queues hold (222 x 128 KiB each; the demand is more)
        let queues = 4 * 222 * (128u64 << 10);
        assert!(w1 >= queues * 3 / 4, "window {w1} vs the queues' {queues}");
    }

    /// A device that serves commands in parallel (8 units, completions out of fetch order): a probe may complete
    /// before bytes ahead of it. Within the fetch depth (4 x 4 MiB, the `w4mj2q2` cell) the window still opens past the
    /// demand and changes nothing; past it (32 x 4 MiB on a round-robin fetch of 270) it still brings p99 to the mean.
    #[test]
    fn model_parallel_device_completion_order_does_not_close_the_window() {
        for k in [270, usize::MAX] {
            let (m0, p0, _) = model(k, 8, false, false, 4, 3000);
            let (m1, p1, w1) = model(k, 8, true, true, 4, 3000);
            eprintln!("parallel k {k} 4 clients: no window {m0} {p0}; window {m1} {p1} w {w1}");
            assert!(w1 >= 4 * 4 * MIB, "window {w1} below the demand");
            assert!(m1 <= m0 + m0 / 50 && p1 <= p0 + p0 / 20);
            let (m2, p2, _) = model(k, 8, false, false, 32, 4000);
            let (m3, p3, w3) = model(k, 8, true, true, 32, 4000);
            eprintln!("parallel k {k} 32 clients: no window {m2} {p2}; window {m3} {p3} w {w3}");
            assert!(m3 <= m2 + m2 / 50, "throughput kept: mean {m3} vs {m2}");
            if k == usize::MAX {
                assert!(p3 <= p2 + p2 / 20);
            } else {
                assert!(
                    p2 > 2 * m2 && p3 < m3 + m3 / 4,
                    "p99 {p3} near the mean {m3} (without: {p2})"
                );
            }
        }
    }
}
