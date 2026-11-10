// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Test-only dense reference allocator (`alloc::Alloc` before adr 0021 am. 24: four dense bitmaps), the oracle of the
//! equivalence property test.

use crate::alloc::{CHUNK_BLOCKS, CHUNK_BYTES, WIN};
use crate::state::Bitmap;

fn words_for(n: u64) -> usize {
    n.div_ceil(64) as usize
}

/// Set/clear bits `[i, i+n)`; returns the number of bits that changed.
fn set_range(v: &mut [u64], i: u64, n: u64, val: bool) -> u64 {
    let mut changed = 0;
    let (mut pos, end) = (i, i + n);
    while pos < end {
        let w = (pos / 64) as usize;
        let b = pos % 64;
        let take = (64 - b).min(end - pos);
        let mask = if take == 64 {
            !0
        } else {
            ((1u64 << take) - 1) << b
        };
        let old = v[w];
        let new = if val { old | mask } else { old & !mask };
        changed += (old ^ new).count_ones() as u64;
        v[w] = new;
        pos += take;
    }
    changed
}

/// Are all bits in `[i, i+n)` equal to `val`?
fn all_range(v: &[u64], i: u64, n: u64, val: bool) -> bool {
    let (mut pos, end) = (i, i + n);
    while pos < end {
        let w = (pos / 64) as usize;
        let b = pos % 64;
        let take = (64 - b).min(end - pos);
        let mask = if take == 64 {
            !0
        } else {
            ((1u64 << take) - 1) << b
        };
        let x = if val { v[w] } else { !v[w] };
        if x & mask != mask {
            return false;
        }
        pos += take;
    }
    true
}

/// One contiguous device extent of the data region: relative bit index `rel..rel+len` = engine blocks `phys..phys+len`.
#[derive(Clone, Copy, Debug)]
struct Seg {
    rel: u64,
    phys: u64,
    len: u64,
}

#[derive(Clone, Debug)]
pub struct DenseAlloc {
    /// The data region: the original extent first, then the extents added by a device expand (adr 0021 am. 20), in
    /// bit order. A run never crosses a segment boundary (the extents are not adjacent on the device).
    segs: Vec<Seg>,
    n: u64,
    alloc: Vec<u64>,
    reserved: Vec<u64>,
    held: Vec<u64>,
    busy: Vec<u64>,
    win_busy: Vec<u16>,
    cursor: u64,
    n_alloc: u64,
    n_reserved: u64,
    n_held: u64,
    n_busy: u64,
}

impl DenseAlloc {
    /// The region `start..start+n` plus further extents `(start, blocks)` (device expand).
    pub fn with_extents(start: u64, n0: u64, extra: &[(u64, u64)]) -> DenseAlloc {
        let mut segs = vec![Seg {
            rel: 0,
            phys: start,
            len: n0,
        }];
        let mut n = n0;
        for &(phys, len) in extra {
            segs.push(Seg { rel: n, phys, len });
            n += len;
        }
        let nw = words_for(n);
        let mut a = DenseAlloc {
            segs,
            n,
            alloc: vec![0; nw],
            reserved: vec![0; nw],
            held: vec![0; nw],
            busy: vec![0; nw],
            win_busy: vec![0; n.div_ceil(WIN) as usize],
            cursor: 0,
            n_alloc: 0,
            n_reserved: 0,
            n_held: 0,
            n_busy: 0,
        };
        // padding bits of the last word are permanently busy
        if !n.is_multiple_of(64) {
            let pad = !0u64 << (n % 64);
            a.busy[nw - 1] = pad;
            a.win_busy[(nw - 1) / 4] += pad.count_ones() as u16;
        }
        a
    }

    pub fn n_alloc(&self) -> u64 {
        self.n_alloc
    }
    pub fn n_reserved(&self) -> u64 {
        self.n_reserved
    }
    pub fn n_held(&self) -> u64 {
        self.n_held
    }
    /// Blocks allocatable right now.
    pub fn n_free(&self) -> u64 {
        self.n - self.n_busy
    }

    /// Relative block index; None if the range is outside the region (or spans two extents).
    fn rel(&self, blk: u64, n: u64) -> Option<u64> {
        if n == 0 {
            return None;
        }
        self.segs.iter().find_map(|s| {
            let r = blk.checked_sub(s.phys)?;
            (r + n <= s.len).then_some(s.rel + r)
        })
    }

    /// Relative index of a block known to be inside the region (callers validated with `in_region`).
    pub fn rel_of(&self, blk: u64) -> u64 {
        self.rel(blk, 1).expect("block inside the data region")
    }

    /// Engine block address of relative index `r`.
    pub fn phys_of(&self, r: u64) -> u64 {
        let s = self
            .segs
            .iter()
            .find(|s| r < s.rel + s.len)
            .expect("index inside the region");
        s.phys + (r - s.rel)
    }

    /// End (exclusive) of the extent holding relative index `r`.
    fn seg_end(&self, r: u64) -> u64 {
        self.segs
            .iter()
            .find(|s| r < s.rel + s.len)
            .map_or(self.n, |s| s.rel + s.len)
    }

    fn refresh(&mut self, i: u64, n: u64) {
        let (w0, w1) = ((i / 64) as usize, ((i + n - 1) / 64) as usize);
        for w in w0..=w1 {
            let pad = if w + 1 == self.busy.len() && !self.n.is_multiple_of(64) {
                !0u64 << (self.n % 64)
            } else {
                0
            };
            let new = self.alloc[w] | self.reserved[w] | self.held[w] | pad;
            let old = self.busy[w];
            if new != old {
                let d = new.count_ones() as i32 - old.count_ones() as i32;
                let wi = w / 4;
                self.win_busy[wi] = (self.win_busy[wi] as i32 + d) as u16;
                self.n_busy = (self.n_busy as i64 + d as i64) as u64;
                self.busy[w] = new;
            }
        }
    }

    fn set(&mut self, which: u8, i: u64, n: u64, val: bool) {
        self.set_raw(which, i, n, val);
        self.refresh(i, n);
    }

    /// `set` without refreshing the busy summary (the caller refreshes once after a pair of moves).
    fn set_raw(&mut self, which: u8, i: u64, n: u64, val: bool) {
        let (v, cnt) = match which {
            0 => (&mut self.alloc, &mut self.n_alloc),
            1 => (&mut self.reserved, &mut self.n_reserved),
            _ => (&mut self.held, &mut self.n_held),
        };
        let ch = set_range(v, i, n, val);
        *cnt = if val { *cnt + ch } else { *cnt - ch };
    }

    // ---------------------------------------------------------------- queries

    pub fn is_allocated(&self, blk: u64, n: u32) -> bool {
        self.rel(blk, n as u64)
            .is_some_and(|r| all_range(&self.alloc, r, n as u64, true))
    }
    pub fn is_unallocated(&self, blk: u64, n: u32) -> bool {
        self.rel(blk, n as u64)
            .is_some_and(|r| all_range(&self.alloc, r, n as u64, false))
    }
    pub fn is_reserved(&self, blk: u64, n: u32) -> bool {
        self.rel(blk, n as u64)
            .is_some_and(|r| all_range(&self.reserved, r, n as u64, true))
    }
    pub fn is_held(&self, blk: u64, n: u32) -> bool {
        self.rel(blk, n as u64)
            .is_some_and(|r| !all_range(&self.held, r, n as u64, false))
    }
    /// Durable-state bitmap as a plain `Bitmap` (tests, fsck).
    pub fn snapshot(&self) -> Bitmap {
        let mut b = Bitmap::new(self.n);
        for w in 0..self.alloc.len() {
            for bit in 0..64 {
                let i = w as u64 * 64 + bit;
                if i < self.n && self.alloc[w] >> bit & 1 != 0 {
                    b.set(i);
                }
            }
        }
        b
    }

    /// Every maximal run of allocatable blocks as `(engine block, blocks)`, ascending within each extent (free-space
    /// report; reserved and held blocks count as in use). Runs never span two extents.
    pub fn for_each_free(&self, mut f: impl FnMut(u64, u64)) {
        for s in &self.segs {
            let (mut pos, end) = (s.rel, s.rel + s.len);
            let mut cur: Option<u64> = None;
            while pos < end {
                let (w, bit) = ((pos / 64) as usize, pos % 64);
                let avail = (64 - bit).min(end - pos);
                let mask = if avail == 64 { !0 } else { (1u64 << avail) - 1 };
                let free = (!self.busy[w] >> bit) & mask;
                if free == mask {
                    cur.get_or_insert(pos);
                } else if free == 0 {
                    if let Some(c) = cur.take() {
                        f(self.phys_of(c), pos - c);
                    }
                } else {
                    for i in 0..avail {
                        if free >> i & 1 == 1 {
                            cur.get_or_insert(pos + i);
                        } else if let Some(c) = cur.take() {
                            f(self.phys_of(c), pos + i - c);
                        }
                    }
                }
                pos += avail;
            }
            if let Some(c) = cur {
                f(self.phys_of(c), end - c);
            }
        }
    }

    // ---------------------------------------------------------------- reservation

    /// Find `want` contiguous allocatable blocks (next-fit from the cursor, wrapping once). Relative index.
    fn find(&self, want: u64) -> Option<u64> {
        if want == 0 || want > self.n - self.n_busy {
            return None;
        }
        let from = self.cursor.min(self.n);
        self.scan(from, self.n, want)
            .or_else(|| self.scan(0, (from + want - 1).min(self.n), want))
    }

    fn scan(&self, from: u64, to: u64, want: u64) -> Option<u64> {
        if self.segs.len() == 1 {
            return self.scan_seg(from, to, want);
        }
        self.segs.iter().find_map(|s| {
            let (a, b) = (from.max(s.rel), to.min(s.rel + s.len));
            (a < b).then(|| self.scan_seg(a, b, want)).flatten()
        })
    }

    /// `scan` inside one extent.
    fn scan_seg(&self, from: u64, to: u64, want: u64) -> Option<u64> {
        let (mut run, mut run_start) = (0u64, 0u64);
        let mut pos = from;
        while pos < to {
            if pos.is_multiple_of(WIN) && self.win_busy[(pos / WIN) as usize] as u64 == WIN {
                run = 0;
                pos += WIN;
                continue;
            }
            let w = (pos / 64) as usize;
            let bit = pos % 64;
            let avail = (64 - bit).min(to - pos);
            let word = self.busy[w] >> bit;
            let z = (word.trailing_zeros() as u64).min(avail);
            if z > 0 {
                if run == 0 {
                    run_start = pos;
                }
                run += z;
                if run >= want {
                    return Some(run_start);
                }
            }
            if z >= avail {
                pos += avail;
                continue;
            }
            // a busy bit at pos+z: skip the whole busy run inside this word
            run = 0;
            let ones = (!(word >> z)).trailing_zeros() as u64;
            pos += z + ones.min(avail - z);
        }
        None
    }

    /// Reserve `n` contiguous blocks; returns the engine block address.
    pub fn reserve(&mut self, n: u32) -> Option<u64> {
        let r = self.find(n as u64)?;
        self.set(1, r, n as u64, true);
        self.cursor = (r + n as u64) % self.n;
        Some(self.phys_of(r))
    }

    /// Reserve a run of `min..=max` blocks (the longest free run at the first fit, up to `max`).
    pub fn reserve_upto(&mut self, min: u32, max: u32) -> Option<(u64, u32)> {
        let r = self.find(min as u64)?;
        let mut len = min as u64;
        let lim = self.seg_end(r);
        while len < max as u64 && r + len < lim && self.is_free_rel(r + len) {
            len += 1;
        }
        self.set(1, r, len, true);
        self.cursor = (r + len) % self.n;
        Some((self.phys_of(r), len as u32))
    }

    fn is_free_rel(&self, i: u64) -> bool {
        self.busy[(i / 64) as usize] >> (i % 64) & 1 == 0
    }

    pub fn unreserve(&mut self, blk: u64, n: u32) {
        let r = self.rel_of(blk);
        self.set(1, r, n as u64, false);
    }

    // ---------------------------------------------------------------- applied state

    /// Txn applied: reserved -> allocated.
    pub fn apply_alloc(&mut self, blk: u64, n: u32) {
        let r = self.rel_of(blk);
        self.set_raw(1, r, n as u64, false);
        self.set_raw(0, r, n as u64, true);
        self.refresh(r, n as u64);
    }

    /// Txn applied: allocated -> held (unusable until a checkpoint passes it).
    pub fn apply_free(&mut self, blk: u64, n: u32) {
        let r = self.rel_of(blk);
        self.set_raw(0, r, n as u64, false);
        self.set_raw(2, r, n as u64, true);
        self.refresh(r, n as u64);
    }

    /// Held -> free.
    pub fn release_held(&mut self, blk: u64, n: u32) {
        self.set(2, self.rel_of(blk), n as u64, false);
    }

    // ---------------------------------------------------------------- `f` chunk (de)serialization

    /// Persistent form of chunk `ci`; returns false if it is all zero (stored as an absent key).
    pub fn chunk_bytes(&self, ci: u64, out: &mut [u8; CHUNK_BYTES]) -> bool {
        let w0 = (ci * CHUNK_BLOCKS / 64) as usize;
        let mut any = 0u64;
        for k in 0..CHUNK_BYTES / 8 {
            let w = self.alloc.get(w0 + k).copied().unwrap_or(0);
            any |= w;
            out[k * 8..k * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        any != 0
    }

    /// Words of the durable bitmap (fsck).
    pub fn alloc_words(&self) -> &[u64] {
        &self.alloc
    }
}
