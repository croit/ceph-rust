// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Runtime deallocate of freed data blocks (adr 0642): which whole free windows may still be mapped in the drive's FTL,
//! the next deallocate command, the windows it holds while in flight, and the size of the next command.
//!
//! Granularity: whole free windows (`alloc::WIN` blocks) only, joined where they are adjacent in engine blocks, so a
//! command carries few large ranges. A window with a busy block is never deallocated: its freed blocks go out once the
//! window is free as a whole.
//!
//! A window turns dirty when blocks in it become allocatable after their free passed a durable checkpoint and every
//! older reader ([`Trim::freed`]), when a borrowed chunk enters the allocator, and at mount (every window). A dirty
//! window without a busy block is a candidate; a dirty window turns candidate when its last busy block becomes free
//! ([`Trim::freed`], [`Trim::unbusy`]). [`Trim::build`] walks the candidates from a round-robin cursor, drops those in
//! use again (they stay dirty) and takes whole windows up to the command budget; the windows it takes are clean. The
//! shard moves the command's windows from free to held while it is in flight (the device does not order a deallocate
//! against a later write of the same LBAs) and releases them at the completion.
//!
//! Size: the first command takes one window. A command the budget limited that completed within half the device idle
//! gap doubles the budget (up to the device limits); one slower than the gap shrinks it in proportion. A command so stays
//! about one gap long whatever the drive's cost per range or byte, and the next one waits as long as the last one took
//! (at least one gap): deallocates never keep the device busy more than half the time.

use crate::alloc::{Alloc, WIN};
use crate::dev::DeallocLimits;

/// Candidates found in use again that one walk drops at most: the range count of one NVMe Dataset Management command,
/// so a walk costs at most what describing one full command costs.
const WALK: u64 = nvme::DSM_MAX_RANGES as u64;

/// Deallocate state of one shard.
#[derive(Debug)]
pub struct Trim {
    lim: DeallocLimits,
    /// LBAs per engine block.
    lpb: u64,
    /// Device granularity in engine blocks (a range starts and ends on its multiples; at most one window).
    gran: u64,
    /// Largest range (multiple of `gran`), engine blocks; largest command, windows.
    range_blocks: u64,
    max_windows: u64,
    /// Windows the next command takes at most (pacing, see the module doc).
    budget: u64,
    /// Dirty windows (may hold blocks the device still maps) and candidates (dirty, whole free when marked), one bit per
    /// allocator window (relative window index).
    dirty: Vec<u64>,
    n_dirty: u64,
    cand: Vec<u64>,
    n_cand: u64,
    /// Window the next walk starts at.
    cursor: usize,
    /// Runs the command (built or in flight) holds `(engine block, blocks)`: whole windows; their window spans
    /// `[first, last]`; device ranges `(LBA, LBAs)` (the runs cut inward to the granularity, split at the range limit).
    runs: Vec<(u64, u32)>,
    spans: Vec<(usize, usize)>,
    ranges: Vec<(u64, u32)>,
    held: u64,
    /// The budget, not the candidates or the device limits, ended the built command.
    limited: bool,
    in_flight: bool,
    /// Store clock (ns): submit of the command in flight; end of the pause after the last completion.
    issued: u64,
    pause_until: u64,
    /// The one `WARNING` line about a failed deallocate was printed.
    pub warned: bool,
}

impl Trim {
    /// `lim` from [`nvme::BlockDev::dealloc_limits`]; off when the device has none, its granularity exceeds one
    /// window, or its limits cannot carry one whole window in one command.
    pub fn new(lim: DeallocLimits, lpb: u64) -> Trim {
        let lpb = lpb.max(1);
        let g = lim.gran_lbas.max(1);
        let gran = g / gcd(g, lpb);
        let range_blocks = u64::from(lim.range_lbas) / lpb / gran * gran;
        let max_blocks = lim.max_lbas / lpb;
        let fits = range_blocks
            .saturating_mul(u64::from(lim.max_ranges))
            .min(max_blocks)
            >= WIN;
        let lim = if !lim.is_on() {
            lim
        } else if gran > WIN {
            DeallocLimits::off("off(device granularity above one window)")
        } else if !fits {
            DeallocLimits::off("off(device limits below one window)")
        } else {
            lim
        };
        Trim {
            lim,
            lpb,
            gran,
            range_blocks,
            max_windows: (max_blocks / WIN).max(1),
            budget: 1,
            dirty: Vec::new(),
            n_dirty: 0,
            cand: Vec::new(),
            n_cand: 0,
            cursor: 0,
            runs: Vec::new(),
            spans: Vec::new(),
            ranges: Vec::new(),
            held: 0,
            limited: false,
            in_flight: false,
            issued: 0,
            pause_until: 0,
            warned: false,
        }
    }

    pub fn on(&self) -> bool {
        self.lim.is_on()
    }

    /// The device refused runtime deallocate (`Unsupported`): off for good, nothing dirty.
    pub fn turn_off(&mut self, why: &'static str) {
        self.lim = DeallocLimits::off(why);
        (self.dirty, self.cand) = (Vec::new(), Vec::new());
        (self.n_dirty, self.n_cand) = (0, 0);
    }

    /// Blocks the command in flight holds (whole windows).
    pub fn held(&self) -> u64 {
        self.held
    }

    /// Windows the command in flight holds (whole free windows again at its completion).
    pub fn held_windows(&self) -> u64 {
        self.held / WIN
    }

    /// Blocks of relative window `w` the command in flight holds (all of it or none).
    pub fn held_in(&self, w: usize) -> u64 {
        let i = self.spans.partition_point(|&(_, l)| l < w);
        if self.spans.get(i).is_some_and(|&(f, _)| f <= w) {
            WIN
        } else {
            0
        }
    }

    pub fn dirty_windows(&self) -> u64 {
        self.n_dirty
    }

    pub fn cand_windows(&self) -> u64 {
        self.n_cand
    }

    pub fn in_flight(&self) -> bool {
        self.in_flight
    }

    /// A command could be built (on, none in flight, a candidate).
    pub fn ready(&self) -> bool {
        self.on() && !self.in_flight && self.n_cand > 0
    }

    /// Store clock (ns) before which no command starts (the pause after the last completion).
    pub fn pause_until(&self) -> u64 {
        self.pause_until
    }

    fn set(bits: &mut Vec<u64>, n: &mut u64, w: usize) {
        if bits.len() * 64 <= w {
            bits.resize(w / 64 + 1, 0);
        }
        let (i, b) = (w / 64, 1u64 << (w % 64));
        if bits[i] & b == 0 {
            bits[i] |= b;
            *n += 1;
        }
    }

    fn clear(bits: &mut [u64], n: &mut u64, w: usize) {
        let b = 1u64 << (w % 64);
        if let Some(x) = bits.get_mut(w / 64)
            && *x & b != 0
        {
            *x &= !b;
            *n -= 1;
        }
    }

    fn is_set(bits: &[u64], w: usize) -> bool {
        bits.get(w / 64)
            .is_some_and(|x| x & (1u64 << (w % 64)) != 0)
    }

    /// Windows of the engine block run `[blk, blk + n)` (one allocator extent, so contiguous in the relative index).
    fn windows(a: &Alloc, blk: u64, n: u64) -> Option<std::ops::RangeInclusive<usize>> {
        let (w0, w1) = (a.window_of(blk)?, a.window_of(blk + n.max(1) - 1)?);
        Some(w0.min(w1)..=w0.max(w1))
    }

    /// Blocks `[blk, blk + n)` became allocatable (`a` after the change): their windows are dirty, candidates if whole
    /// free.
    pub fn freed(&mut self, a: &Alloc, blk: u64, n: u64) {
        if !self.on() {
            return;
        }
        for w in Self::windows(a, blk, n).into_iter().flatten() {
            Self::set(&mut self.dirty, &mut self.n_dirty, w);
            if a.window_busy(w) == 0 {
                Self::set(&mut self.cand, &mut self.n_cand, w);
            }
        }
    }

    /// Blocks `[blk, blk + n)` became free without being written (a reservation given back, `a` after the change): a
    /// dirty window they leave whole free is a candidate.
    pub fn unbusy(&mut self, a: &Alloc, blk: u64, n: u64) {
        if self.n_dirty == 0 {
            return;
        }
        for w in Self::windows(a, blk, n).into_iter().flatten() {
            if a.window_busy(w) == 0 && Self::is_set(&self.dirty, w) {
                Self::set(&mut self.cand, &mut self.n_cand, w);
            }
        }
    }

    /// Every window of the allocator (mount: the free map is durable, what the device deallocated is not).
    pub fn mark_all(&mut self, a: &Alloc) {
        if !self.on() {
            return;
        }
        for w in 0..a.n_windows() {
            Self::set(&mut self.dirty, &mut self.n_dirty, w);
            if a.window_busy(w) == 0 {
                Self::set(&mut self.cand, &mut self.n_cand, w);
            }
        }
    }

    /// First candidate at or after `from`, below `end`.
    fn next_cand(&self, from: usize, end: usize) -> Option<usize> {
        let mut i = from / 64;
        let mut word = self.cand.get(i)? & (!0u64 << (from % 64));
        loop {
            if word != 0 {
                let w = i * 64 + word.trailing_zeros() as usize;
                return (w < end).then_some(w);
            }
            i += 1;
            if i * 64 >= end {
                return None;
            }
            word = *self.cand.get(i)?;
        }
    }

    /// Ranges of a run of `k` windows (before the granularity cut).
    fn ranges_of(&self, k: u64) -> u64 {
        (k * WIN).div_ceil(self.range_blocks)
    }

    /// Build the next command from the candidates of `a`, holding at most `cap` blocks (whole windows). `true` = a
    /// command is ready: [`Self::runs`] are free in `a` (the caller holds them, then submits [`Self::ranges`]). `false` =
    /// nothing to send (the walk may still have dropped candidates in use again).
    pub fn build(&mut self, a: &Alloc, cap: u64) -> bool {
        self.reset();
        let budget = self.budget.min(cap / WIN).min(self.max_windows);
        if !self.ready() || budget == 0 {
            return false;
        }
        let nw = a.n_windows();
        if self.next_cand(self.cursor, nw).is_none() {
            self.cursor = 0;
        }
        // the walk: candidates ascending from the cursor; `open` = the run still growing (adjacent windows of one
        // extent, at most `u32::MAX` blocks); `closed` = ranges of the runs before it
        let max_ranges = u64::from(self.lim.max_ranges);
        let (mut pos, mut stale, mut taken, mut closed) = (self.cursor, 0, 0u64, 0u64);
        let mut open: Option<(usize, usize)> = None;
        let mut stop = None;
        while let Some(w) = self.next_cand(pos, nw) {
            if a.free_window_phys(w).is_none() {
                // in use again: stays dirty, a candidate again once whole free
                Self::clear(&mut self.cand, &mut self.n_cand, w);
                stale += 1;
                pos = w + 1;
                if stale >= WALK {
                    stop = Some(pos);
                    break;
                }
                continue;
            }
            let joins = open.is_some_and(|(f, l)| {
                l + 1 == w && a.window_joins(w) && (w - f + 1) as u64 * WIN <= u64::from(u32::MAX)
            });
            let k = open.map_or(0, |(f, l)| (l - f + 1) as u64);
            let ranges = if joins {
                closed + self.ranges_of(k + 1)
            } else {
                closed + self.ranges_of(k) + self.ranges_of(1)
            };
            if taken == budget || ranges > max_ranges {
                self.limited = taken == budget;
                stop = Some(w);
                break;
            }
            taken += 1;
            pos = w + 1;
            match &mut open {
                Some((_, l)) if joins => *l = w,
                _ => {
                    if let Some((f, l)) = open.replace((w, w)) {
                        closed += self.ranges_of((l - f + 1) as u64);
                        self.emit(a, f, l);
                    }
                }
            }
        }
        if let Some((f, l)) = open {
            self.emit(a, f, l);
        }
        self.cursor = stop.unwrap_or(nw);
        !self.runs.is_empty()
    }

    /// Take the free windows `[f, l]` (one run in engine blocks): held whole, sent cut inward to the granularity and
    /// split at the range limit. A run the cut leaves empty is not held (it cannot be deallocated on its own).
    fn emit(&mut self, a: &Alloc, f: usize, l: usize) {
        for w in f..=l {
            Self::clear(&mut self.cand, &mut self.n_cand, w);
            Self::clear(&mut self.dirty, &mut self.n_dirty, w);
        }
        let (p, n) = (a.window_phys(f), (l - f + 1) as u64 * WIN);
        let (mut b, e) = (
            p.next_multiple_of(self.gran),
            (p + n) / self.gran * self.gran,
        );
        if b >= e {
            return;
        }
        self.runs.push((p, n as u32));
        self.spans.push((f, l));
        self.held += n;
        while b < e {
            let m = (e - b).min(self.range_blocks);
            self.ranges.push((b * self.lpb, (m * self.lpb) as u32));
            b += m;
        }
    }

    fn reset(&mut self) {
        self.runs.clear();
        self.spans.clear();
        self.ranges.clear();
        self.held = 0;
        self.limited = false;
    }

    /// Runs of the command (built, or in flight).
    pub fn runs(&self) -> &[(u64, u32)] {
        &self.runs
    }

    /// Device ranges of the built command.
    pub fn ranges(&self) -> &[(u64, u32)] {
        &self.ranges
    }

    /// Engine blocks the device ranges cover.
    pub fn range_blocks(&self) -> u64 {
        self.ranges.iter().map(|r| u64::from(r.1)).sum::<u64>() / self.lpb
    }

    /// The built command was submitted at store clock `now`.
    pub fn submitted(&mut self, now: u64) {
        self.in_flight = true;
        self.issued = now;
    }

    /// The built command was not submitted: its windows are dirty candidates again; its runs (to release) are the
    /// caller's.
    pub fn unbuilt(&mut self) -> Vec<(u64, u32)> {
        for i in 0..self.spans.len() {
            let (f, l) = self.spans[i];
            for w in f..=l {
                Self::set(&mut self.dirty, &mut self.n_dirty, w);
                Self::set(&mut self.cand, &mut self.n_cand, w);
            }
        }
        self.limited = false;
        self.take()
    }

    /// The command in flight completed at store clock `now`: the next budget from its latency against `gap`, the pause
    /// before the next one; its runs (to release) are the caller's. Returns the latency too.
    pub fn completed(&mut self, now: u64, gap: u64) -> (u64, Vec<(u64, u32)>) {
        let lat = now.saturating_sub(self.issued);
        if lat > gap {
            self.budget =
                (u128::from(self.budget) * u128::from(gap) / u128::from(lat)).max(1) as u64;
        } else if self.limited && lat <= gap / 2 {
            self.budget = (self.budget * 2).min(self.max_windows);
        }
        self.pause_until = now + lat.max(gap);
        (lat, self.take())
    }

    fn take(&mut self) -> Vec<(u64, u32)> {
        self.in_flight = false;
        self.held = 0;
        self.spans.clear();
        self.ranges.clear();
        std::mem::take(&mut self.runs)
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAP: u64 = 10_000;

    fn lim(ranges: u32, range_lbas: u32, max_lbas: u64, gran_lbas: u64) -> DeallocLimits {
        DeallocLimits {
            max_ranges: ranges,
            range_lbas,
            max_lbas,
            gran_lbas,
            via: "test",
        }
    }

    fn big() -> DeallocLimits {
        lim(256, u32::MAX, u64::MAX, 1)
    }

    /// Run the built command like the shard: hold its runs, submit, complete after `lat`, release them.
    fn run(t: &mut Trim, a: &mut Alloc, lat: u64) -> Vec<(u64, u32)> {
        for &(b, n) in t.runs() {
            a.hold_free(b, n);
        }
        assert_eq!(a.n_held(), t.held());
        t.submitted(1);
        assert!(!t.ready());
        let (l, r) = t.completed(1 + lat, GAP);
        assert_eq!(l, lat);
        for &(b, n) in &r {
            a.release_held(b, n);
        }
        r
    }

    /// Build and run commands until no candidate is left; the runs deallocated, sorted.
    fn drain(t: &mut Trim, a: &mut Alloc) -> Vec<(u64, u32)> {
        let mut all = Vec::new();
        for _ in 0..10_000 {
            if !t.build(a, u64::MAX) {
                if t.cand_windows() == 0 {
                    all.sort_unstable();
                    return all;
                }
                continue;
            }
            all.extend(run(t, a, 0));
        }
        panic!("no progress");
    }

    #[test]
    fn off_and_granularity() {
        assert!(!Trim::new(DeallocLimits::NONE, 8).on());
        // one window does not fit in one command: off
        let t = Trim::new(lim(256, 4, 1 << 20, 1), 8);
        assert_eq!(t.lim.via, "off(device limits below one window)");
        let t = Trim::new(lim(256, u32::MAX, 8 * (WIN - 1), 1), 8);
        assert_eq!(t.lim.via, "off(device limits below one window)");
        // several ranges carry one window
        assert!(Trim::new(lim(4, 8 * 64, 1 << 20, 1), 8).on());
        // granularity above one window: off; else in blocks: lcm(gran, lpb) / lpb
        assert_eq!(
            Trim::new(lim(256, u32::MAX, u64::MAX, 8 * 2 * WIN), 8)
                .lim
                .via,
            "off(device granularity above one window)"
        );
        assert_eq!(Trim::new(lim(256, u32::MAX, u64::MAX, 16), 8).gran, 2);
        assert_eq!(Trim::new(lim(256, u32::MAX, u64::MAX, 12), 8).gran, 3);
        assert_eq!(Trim::new(big(), 8).gran, 1);
    }

    /// Only whole free windows go out, adjacent ones joined into one range; a window with a busy block stays dirty and
    /// goes out whole once its last busy block is free.
    #[test]
    fn whole_windows_only() {
        let mut a = Alloc::new(100, 10 * WIN);
        a.apply_alloc_replay(100 + WIN + 5, 3); // window 1 in use
        a.apply_alloc_replay(100 + 6 * WIN - 2, 4); // straddles windows 5/6
        let mut t = Trim::new(big(), 1);
        t.mark_all(&a);
        assert_eq!((t.dirty_windows(), t.cand_windows()), (10, 7));
        // budget one window: the first command takes window 0
        assert!(t.build(&a, u64::MAX));
        assert_eq!(t.ranges(), &[(100, WIN as u32)]);
        run(&mut t, &mut a, 0);
        assert_eq!(t.budget, 2);
        t.budget = 64;
        assert_eq!(
            drain(&mut t, &mut a),
            vec![
                (100 + 2 * WIN, (3 * WIN) as u32),
                (100 + 7 * WIN, (3 * WIN) as u32)
            ]
        );
        assert_eq!((t.dirty_windows(), t.cand_windows()), (3, 0));
        // the busy blocks of window 1 freed (a checkpoint passed): it goes out whole
        a.apply_free(100 + WIN + 5, 3);
        a.release_held(100 + WIN + 5, 3);
        t.freed(&a, 100 + WIN + 5, 3);
        assert_eq!(t.cand_windows(), 1);
        assert_eq!(drain(&mut t, &mut a), vec![(100 + WIN, WIN as u32)]);
        // a reservation given back in a clean window: no candidate
        let b = a.reserve(4).unwrap();
        a.unreserve(b, 4);
        t.unbusy(&a, b, 4);
        assert_eq!(t.cand_windows(), 0);
        // window 5's busy blocks freed: a candidate; window 6 still in use
        a.apply_free(100 + 6 * WIN - 2, 2);
        a.release_held(100 + 6 * WIN - 2, 2);
        t.freed(&a, 100 + 6 * WIN - 2, 2);
        assert_eq!((t.cand_windows(), t.dirty_windows()), (1, 2));
        // window 6 dirty and whole free again by a give-back: a candidate
        let b = 100 + 6 * WIN;
        a.apply_free(b, 2);
        a.release_held(b, 2);
        assert_eq!(a.window_busy(6), 0);
        t.unbusy(&a, b, 2);
        assert_eq!(t.cand_windows(), 2);
        assert_eq!(
            drain(&mut t, &mut a),
            vec![(100 + 5 * WIN, (2 * WIN) as u32)]
        );
        assert_eq!((t.dirty_windows(), t.cand_windows()), (0, 0));
    }

    #[test]
    fn candidates_in_use_again_are_dropped_and_granularity_cuts_inward() {
        let a0 = Alloc::new(0, 4 * WIN);
        let mut a = a0.clone();
        let mut t = Trim::new(big(), 1);
        t.mark_all(&a);
        // window 1 in use since it was marked
        a.apply_alloc_replay(WIN + 7, 1);
        t.budget = 8;
        assert!(t.build(&a, u64::MAX));
        assert_eq!(t.runs(), &[(0, WIN as u32), (2 * WIN, (2 * WIN) as u32)]);
        assert_eq!((t.dirty_windows(), t.cand_windows()), (1, 0));
        // granularity cut inward: the held runs stay whole windows
        let mut a = Alloc::new(3, 2 * WIN);
        let mut t = Trim::new(lim(256, u32::MAX, u64::MAX, 8), 1);
        t.mark_all(&a);
        t.budget = 8;
        assert!(t.build(&a, u64::MAX));
        assert_eq!(t.runs(), &[(3, (2 * WIN) as u32)]);
        assert_eq!(t.ranges(), &[(8, (2 * WIN - 8) as u32)]);
        assert_eq!(t.range_blocks(), 2 * WIN - 8);
        run(&mut t, &mut a, 0);
        assert_eq!(a.free_windows(), 2);
        // a window that straddles an extent start is no whole free window
        let a = Alloc::with_extents(0, WIN + 10, &[(5000, 2 * WIN)]);
        assert!(a.free_window_phys(0).is_some() && a.free_window_phys(1).is_none());
        let mut t = Trim::new(big(), 1);
        t.mark_all(&a);
        t.budget = 8;
        assert!(t.build(&a, u64::MAX));
        assert_eq!(t.runs(), &[(0, WIN as u32), (5000 + WIN - 10, WIN as u32)]);
    }

    #[test]
    fn budget_slow_start_and_shrink() {
        let mut a = Alloc::new(0, 64 * WIN);
        let mut t = Trim::new(big(), 1);
        t.mark_all(&a);
        // doubles while limited and fast
        let mut sizes = Vec::new();
        while t.build(&a, u64::MAX) {
            sizes.push(t.held_windows());
            run(&mut t, &mut a, GAP / 2);
        }
        assert_eq!(sizes, vec![1, 2, 4, 8, 16, 32, 1]);
        // the last command was not limited: the budget stays
        assert_eq!(t.budget, 64);
        // slower than the gap: shrinks in proportion, never below one window; the pause is the latency, at least a gap
        t.mark_all(&a);
        assert!(t.build(&a, u64::MAX));
        assert_eq!(t.held_windows(), 64);
        run(&mut t, &mut a, 4 * GAP);
        assert_eq!((t.budget, t.pause_until()), (16, 1 + 8 * GAP));
        t.mark_all(&a);
        assert!(t.build(&a, u64::MAX));
        run(&mut t, &mut a, 1000 * GAP);
        assert_eq!(t.budget, 1);
        assert!(t.build(&a, u64::MAX));
        run(&mut t, &mut a, 1);
        assert_eq!(t.pause_until(), 2 + GAP);
        // the cap: whole windows of it, none below one window
        t.mark_all(&a);
        t.budget = 64;
        assert!(t.build(&a, 3 * WIN - 1));
        assert_eq!(t.held_windows(), 2);
        assert!(t.limited);
        t.unbuilt();
        assert!(!t.build(&a, WIN - 1));
        assert!(t.ready());
    }

    #[test]
    fn device_limits_split() {
        let mut a = Alloc::new(0, 16 * WIN);
        // windows 3, 7, 11, 15 in use: runs of 3 windows
        for w in [3, 7, 11, 15] {
            a.apply_alloc_replay(w * WIN, 1);
        }
        // 2 ranges per command, 1 window per range
        let mut t = Trim::new(lim(2, WIN as u32, u64::MAX, 1), 1);
        t.mark_all(&a);
        t.budget = 64;
        let mut cmds = 0;
        while t.build(&a, u64::MAX) {
            assert!(t.ranges().len() <= 2 && t.ranges().iter().all(|r| u64::from(r.1) == WIN));
            assert!(!t.limited);
            run(&mut t, &mut a, 0);
            cmds += 1;
        }
        // a run of 3 windows needs 3 ranges: the walk splits it into 2 + 1
        assert_eq!((cmds, t.cand_windows(), t.dirty_windows()), (6, 0, 4));
        // 4 windows per command, 2 LBAs per block
        let mut a = Alloc::new(0, 16 * WIN);
        let mut t = Trim::new(lim(256, u32::MAX, 2 * 4 * WIN, 1), 2);
        t.mark_all(&a);
        t.budget = 64;
        assert!(t.build(&a, u64::MAX));
        assert_eq!(t.ranges(), &[(0, (2 * 4 * WIN) as u32)]);
        t.unbuilt();
        assert_eq!(drain(&mut t, &mut a).len(), 4);
    }

    #[test]
    fn extent_start_ends_a_run() {
        // the second extent right after the first in engine blocks: still two runs
        let mut a = Alloc::with_extents(0, 2 * WIN, &[(2 * WIN, 2 * WIN)]);
        let mut t = Trim::new(big(), 1);
        t.mark_all(&a);
        t.budget = 8;
        assert!(t.build(&a, u64::MAX));
        assert_eq!(
            t.runs(),
            &[(0, (2 * WIN) as u32), (2 * WIN, (2 * WIN) as u32)]
        );
        run(&mut t, &mut a, 0);
    }

    #[test]
    fn held_windows_and_not_submitted() {
        let mut a = Alloc::new(0, 8 * WIN);
        a.apply_alloc_replay(2 * WIN, 1);
        let mut t = Trim::new(big(), 1);
        t.mark_all(&a);
        t.budget = 8;
        assert!(t.build(&a, u64::MAX));
        for &(b, n) in t.runs() {
            a.hold_free(b, n);
        }
        t.submitted(1);
        assert_eq!((t.held_windows(), a.free_windows()), (7, 0));
        assert_eq!(
            (0..8).map(|w| t.held_in(w)).collect::<Vec<_>>(),
            [WIN, WIN, 0, WIN, WIN, WIN, WIN, WIN]
        );
        let (_, r) = t.completed(2, GAP);
        for (b, n) in r {
            a.release_held(b, n);
        }
        assert_eq!(
            (t.held_in(0), a.free_windows(), t.cand_windows()),
            (0, 7, 0)
        );
        // not submitted: dirty candidates again
        t.mark_all(&a);
        assert!(t.build(&a, u64::MAX));
        assert_eq!(t.unbuilt().len(), 2);
        assert_eq!((t.cand_windows(), t.dirty_windows(), t.held()), (7, 8, 0));
        // off: nothing is ever marked
        t.turn_off("off(test)");
        t.mark_all(&a);
        assert!(!t.ready());
    }
}
