// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Wake tokens (adr 0043 am. 9): small fixed-size sets of u64 tokens naming what a blocked probe waits for (a tree page
//! miss, an in-flight prefetch run) and what a store wake resolved. No allocation; overflow is flagged and means
//! "unknown" (the consumer falls back to waking everything).

/// Bounded token set; `push` past `N` entries only sets the overflow flag.
#[derive(Clone, Copy, Debug)]
pub struct Toks<const N: usize> {
    n: u8,
    ovf: bool,
    t: [u64; N],
}

impl<const N: usize> Default for Toks<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Toks<N> {
    pub const fn new() -> Self {
        Toks {
            n: 0,
            ovf: false,
            t: [0; N],
        }
    }
    pub fn push(&mut self, t: u64) {
        let n = self.n as usize;
        if self.t[..n].contains(&t) {
            return;
        }
        if n < N {
            self.t[n] = t;
            self.n += 1;
        } else {
            self.ovf = true;
        }
    }
    /// Mark the set incomplete (the consumer must treat it as unknown).
    pub fn set_overflow(&mut self) {
        self.ovf = true;
    }
    pub fn as_slice(&self) -> &[u64] {
        &self.t[..self.n as usize]
    }
    /// More tokens were pushed than fit: the set is incomplete.
    pub fn overflowed(&self) -> bool {
        self.ovf
    }
    pub fn is_empty(&self) -> bool {
        self.n == 0 && !self.ovf
    }
    pub fn clear(&mut self) {
        self.n = 0;
        self.ovf = false;
    }
    pub fn merge<const M: usize>(&mut self, o: &Toks<M>) {
        for &t in o.as_slice() {
            self.push(t);
        }
        self.ovf |= o.ovf;
    }
}

const KIND_PAGE: u64 = 1 << 62;
const KIND_PF: u64 = 2 << 62;
const KIND_SLICE: u64 = 3 << 62;
const ID_MASK: u64 = (1 << 48) - 1;

/// Token of tree page `addr` of shard `si`.
pub fn tok_page(si: usize, addr: u64) -> u64 {
    KIND_PAGE | ((si as u64 & 0xff) << 48) | (addr & ID_MASK)
}

/// Token of the prefetch run starting at block `pba` of shard `si`.
pub fn tok_pf(si: usize, pba: u64) -> u64 {
    KIND_PF | ((si as u64 & 0xff) << 48) | (pba & ID_MASK)
}

/// Token of listing slice `seq` of shard `si` (adr 0021 S8): the sliced request waits for it, the next poll delivers it.
pub fn tok_slice(si: usize, seq: u64) -> u64 {
    KIND_SLICE | ((si as u64 & 0xff) << 48) | (seq & ID_MASK)
}
