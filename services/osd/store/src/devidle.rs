// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Device idle signal (adr 0533): the shards of one device publish the busy/idle edges of their device
//! queue (the busy periods of adr 0474) in one table, so the background work of a shard (tree compaction, defrag,
//! evacuation, recompaction) sees whether ANY queue of the device is in use, not only its own.
//!
//! One slot per shard on its own cache line, written only by the shard's core at a queue edge (one relaxed store; a
//! saturated queue has no edges), read by the other shards' cores only when they have background work due. A slot is
//! an edge count: odd while commands are in flight, even when the queue drained. No time crosses cores (core clocks
//! need not agree): each reader ([`DevView`]) notes on its own clock when it last saw any other slot change.
//!
//! The table also holds the device's background checkpoint write budget (adr 0021 am. 76): the bytes of
//! background checkpoint writes in flight on the device, all shards together, stay within one largest device write (at
//! least one write goes out), so the WAL writes of every shard (the client ack path) queue behind at most that much bulk
//! data. The kernel tier gives a WAL write no priority over a checkpoint write (one blk-mq hardware queue per core, no
//! IO scheduler on NVMe; passthrough has none at all), and the controller serves its queues round-robin: what is in
//! flight ahead of a WAL write is what it waits for. Device write bandwidth x WAL write latency (e9455: ~24 us) is below
//! one largest device write, so that is the bound the bandwidth-delay product gives; small scattered page writes still
//! go out together up to it. Each shard also keeps its own share in its slot, so a mount or a failure returns what an
//! instance that reaps nothing more had in flight.
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// One shard's slot, written only by the shard's core.
#[repr(align(128))]
#[derive(Debug, Default)]
struct Slot {
    /// Queue edge count: odd while commands are in flight.
    edges: AtomicU64,
    /// Background checkpoint write bytes the shard has in flight.
    ck: AtomicU64,
    /// 1 = the shard holds the device's deallocate turn.
    trim: AtomicU64,
}

/// A counter on a cache line (pair) of its own: shared device-wide words written by every shard of the device.
#[repr(align(128))]
#[derive(Debug, Default)]
pub(crate) struct Line(pub(crate) AtomicU64);

/// Queue state of every shard of one device (`ShardCfg::dev_idle`).
#[derive(Debug, Default)]
pub struct DevIdle {
    slots: OnceLock<Box<[Slot]>>,
    /// Background checkpoint write bytes in flight on the device, all shards.
    ck: Line,
    /// 1 = a shard holds the deallocate turn (adr 0642).
    trim: Line,
    /// Device admission window of the shards' data writes (adr 0643-device-admission-fifo).
    pub admit: crate::admit::DevAdmit,
}

impl DevIdle {
    /// Size the table for the device's `n` shards (the first mount; a later mount of the same device agrees). False = the
    /// table was sized for another device: the caller uses a table of its own.
    pub fn init(&self, n: usize) -> bool {
        let ok = self
            .slots
            .get_or_init(|| (0..n).map(|_| Slot::default()).collect())
            .len()
            == n;
        if ok {
            self.admit.init(n);
        }
        ok
    }

    /// Slots of the table (0 = never sized: every look says quiet).
    pub(crate) fn len(&self) -> usize {
        self.slots.get().map_or(0, |s| s.len())
    }

    /// Edges shard `i` published so far.
    pub(crate) fn edges(&self, i: usize) -> u64 {
        self.slots
            .get()
            .and_then(|s| s.get(i))
            .map_or(0, |s| s.edges.load(Relaxed))
    }

    /// Shard `i`'s queue got its first command in flight (`busy`) or drained (`!busy`): the next edge (odd = busy).
    #[inline]
    pub(crate) fn edge(&self, i: usize, busy: bool) {
        if let Some(s) = self.slots.get().and_then(|s| s.get(i)) {
            let v = s.edges.load(Relaxed);
            if (v & 1 == 1) != busy {
                s.edges.store(v + 1, Relaxed);
            }
        }
    }
}

impl DevIdle {
    fn slot(&self, i: usize) -> Option<&Slot> {
        self.slots.get().and_then(|s| s.get(i))
    }

    /// Shard `i` may submit a background checkpoint write of `len` bytes: nothing is in flight on the device, or
    /// `len` more stay within `cap` (one largest device write). Counted for the device and in the shard's slot.
    #[inline]
    pub(crate) fn ck_take(&self, i: usize, len: u64, cap: u64) -> bool {
        let fits = |c: u64| (c == 0 || c + len <= cap).then_some(c + len);
        if self.ck.0.try_update(Relaxed, Relaxed, fits).is_err() {
            return false;
        }
        if let Some(s) = self.slot(i) {
            s.ck.fetch_add(len, Relaxed);
        }
        true
    }

    /// Shard `i`'s background checkpoint write of `len` bytes completed. A table without slots (a shard mounted on its
    /// own) has no reset, and gives `len`; with slots only what the shard still counts (a reset returned the rest).
    #[inline]
    pub(crate) fn ck_give(&self, i: usize, len: u64) {
        let n = match self.slot(i) {
            Some(s) => {
                // One RMW of the slot, clamped at 0: a concurrent `ck_reset` cannot take the same bytes off the device
                // twice, and the slot never wraps. The closure never rejects a value.
                let clamp = |c: u64| Some(c.saturating_sub(len));
                let held = s.ck.try_update(Relaxed, Relaxed, clamp).unwrap_or_default();
                held.min(len)
            }
            None => len,
        };
        self.ck.0.fetch_sub(n, Relaxed);
    }

    /// Shard `i` reaps nothing more (mount after an earlier instance, failure): its share goes back to the device.
    pub(crate) fn ck_reset(&self, i: usize) {
        if let Some(s) = self.slot(i) {
            self.ck.0.fetch_sub(s.ck.swap(0, Relaxed), Relaxed);
        }
    }

    /// A background checkpoint write is in flight on the device.
    #[inline]
    pub(crate) fn ck_busy(&self) -> bool {
        self.ck.0.load(Relaxed) != 0
    }

    /// Shard `i` takes the device's deallocate turn (adr 0642): one shard at a time sends deallocates and pauses
    /// after each, so the device sees one at a time. True if it holds the turn now; a table without slots: always.
    pub(crate) fn trim_take(&self, i: usize) -> bool {
        let Some(s) = self.slot(i) else {
            return true;
        };
        if s.trim.load(Relaxed) == 1 {
            return true;
        }
        if self
            .trim
            .0
            .compare_exchange(0, 1, Relaxed, Relaxed)
            .is_err()
        {
            return false;
        }
        s.trim.store(1, Relaxed);
        true
    }

    /// Shard `i` gives the deallocate turn back (if it holds it): its pause ended, or it reaps nothing more (mount after
    /// an earlier instance, failure).
    pub(crate) fn trim_give(&self, i: usize) {
        if let Some(s) = self.slot(i)
            && s.trim.swap(0, Relaxed) == 1
        {
            self.trim.0.store(0, Relaxed);
        }
    }

    #[cfg(test)]
    pub(crate) fn ck_bytes(&self) -> u64 {
        self.ck.0.load(Relaxed)
    }
}

/// One shard's view of the other queues of its device: the slot values it last saw and when (its own clock).
#[derive(Debug, Default)]
pub(crate) struct DevView {
    seen: Vec<u64>,
    changed: u64,
    /// Slot changes of other shards noticed so far (a gauge of what this view actually watches).
    pub(crate) changes: u64,
}

impl DevView {
    /// No queue of the device except `me`'s has a command in flight, and none changed during the last `gap` ns of this
    /// view's clock (`now`). A slot that changed since the last look counts as changed now: a reader that looks rarely
    /// waits a gap more, it never mistakes activity it did not watch for quiet.
    pub(crate) fn quiet(&mut self, d: &DevIdle, me: usize, now: u64, gap: u64) -> bool {
        let Some(slots) = d.slots.get() else {
            return true;
        };
        if self.seen.len() != slots.len() {
            // first look: what came before is unknown; a queue busy now still shows (odd count)
            self.seen = slots.iter().map(|s| s.edges.load(Relaxed)).collect();
        }
        let mut busy = false;
        for (i, s) in slots.iter().enumerate() {
            if i == me {
                continue;
            }
            let v = s.edges.load(Relaxed);
            if v != self.seen[i] {
                self.seen[i] = v;
                self.changed = now;
                self.changes += 1;
            }
            busy |= v & 1 == 1;
        }
        !busy && now.saturating_sub(self.changed) >= gap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_needs_every_other_queue_idle_for_the_gap_on_the_readers_clock() {
        let d = DevIdle::default();
        let mut v = DevView::default();
        assert!(v.quiet(&d, 0, 0, 10), "no table: nothing known, quiet");
        assert!(d.init(3));
        assert!(!d.init(4), "another device's shape is refused");
        assert!(v.quiet(&d, 0, 15, 10), "first look, nothing busy");
        d.edge(1, true);
        assert!(!v.quiet(&d, 0, 100, 10));
        let mut own = DevView::default();
        assert!(
            own.quiet(&d, 1, 100, 10),
            "a shard's own queue does not count"
        );
        d.edge(1, false);
        assert!(
            !v.quiet(&d, 0, 105, 10),
            "drained, seen at 105: a gap from there"
        );
        assert!(!v.quiet(&d, 0, 114, 10));
        assert!(v.quiet(&d, 0, 115, 10));
        // a whole busy period between two looks is still seen (the count moved)
        d.edge(2, true);
        d.edge(2, false);
        assert!(!v.quiet(&d, 0, 1000, 10));
        assert!(v.quiet(&d, 0, 1010, 10));
        d.edge(9, true); // out of range: ignored
        assert!(v.quiet(&d, 0, 2000, 10));
    }

    #[test]
    fn background_checkpoint_bytes_per_device_stay_within_one_largest_write() {
        let d = DevIdle::default();
        assert!(d.init(3));
        assert!(!d.ck_busy());
        assert!(d.ck_take(2, 4096, 16384));
        assert!(d.ck_take(0, 8192, 16384), "small writes go out together");
        assert!(!d.ck_take(1, 8192, 16384), "over one largest write");
        assert!(d.ck_take(1, 4096, 16384));
        d.ck_give(2, 4096);
        d.ck_give(0, 8192);
        d.ck_give(1, 4096);
        assert!(!d.ck_busy());
        assert!(
            d.ck_take(1, 65536, 16384),
            "nothing in flight: one write of any size"
        );
        assert!(!d.ck_take(0, 4096, 16384));
        // shard 1 stops without reaping: a reset returns its share, a late completion gives nothing twice
        d.ck_reset(1);
        assert!(!d.ck_busy());
        d.ck_give(1, 65536);
        assert!(d.ck_take(0, 4096, 16384) && d.ck_take(2, 4096, 16384));
        d.ck_reset(0);
        assert!(d.ck_busy(), "shard 2's write is still in flight");
        d.ck_give(2, 4096);
        assert!(!d.ck_busy());
    }

    #[test]
    fn ck_give_clamps_its_slot_and_takes_only_that_off_the_device() {
        let d = DevIdle::default();
        assert!(d.init(2));
        assert!(d.ck_take(0, 4096, 16384) && d.ck_take(1, 4096, 16384));
        d.ck_reset(0); // an earlier instance of shard 0 reaps nothing more: its share returns to the device
        assert_eq!(d.ck_bytes(), 4096, "shard 1's write is still in flight");
        d.ck_give(0, 65536); // late completion of that instance: the slot holds nothing for it
        assert_eq!(d.ck_bytes(), 4096, "only what the slot held comes off");
        assert_eq!(
            d.slot(0).unwrap().ck.load(Relaxed),
            0,
            "the slot clamps at 0"
        );
        // a give larger than the slot holds removes only the slot's bytes
        assert!(d.ck_take(0, 8192, 16384));
        d.ck_give(0, 65536);
        assert_eq!(d.ck_bytes(), 4096);
        d.ck_give(1, 4096);
        assert!(!d.ck_busy());
    }

    #[test]
    fn one_deallocate_turn_per_device() {
        let d = DevIdle::default();
        assert!(d.trim_take(0), "unsized table: always");
        assert!(d.init(3));
        assert!(d.trim_take(1));
        assert!(d.trim_take(1), "held: still");
        assert!(!d.trim_take(0) && !d.trim_take(2));
        d.trim_give(0);
        assert!(!d.trim_take(2), "only the holder gives it back");
        d.trim_give(1);
        d.trim_give(1);
        assert!(d.trim_take(2));
        assert!(!d.trim_take(1));
    }
}
