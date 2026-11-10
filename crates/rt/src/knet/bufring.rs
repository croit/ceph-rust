// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Provided-buffer ring (io_uring `IORING_REGISTER_PBUF_RING`): the kernel picks a buffer per multishot-recv completion,
//! we hand it back after the msgr2 parser consumed the bytes (the same loop iteration, so the pool never runs dry
//! unless one CQ batch holds more completions than buffers: `ENOBUFS`, the recv is simply re-armed).
//!
//! Kernels whose ring registration fails (adr 0053 am. 9: Ubuntu noble 6.8.0-132.. rejects every valid
//! `IORING_REGISTER_PBUF_RING` call with `EINVAL`) get the same pool through classic provided buffers
//! ([`Provide::Classic`]): `give` is unchanged, `commit` turns the returned ids into `IORING_OP_PROVIDE_BUFFERS` entries.
use io_uring::{Submitter, opcode, squeue::Entry, types::BufRingEntry};
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::io;
use std::sync::atomic::{AtomicU16, Ordering};

/// Buffer group id of the ring.
pub const BGID: u16 = 1;
const PAGE: usize = 4096;

/// Fixed overflow storage used only when paused sockets would consume the shared receive pool.
pub struct Spill {
    mem: Box<[u8]>,
    free: Vec<u16>,
    bsz: usize,
}

impl std::fmt::Debug for Spill {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spill")
            .field("bytes", &self.mem.len())
            .field("free", &self.free.len())
            .finish()
    }
}

impl Spill {
    pub fn new(nbuf: u16, bsz: u32) -> io::Result<Self> {
        let bytes = (nbuf as usize)
            .checked_mul(bsz as usize)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let mut mem = Vec::new();
        mem.try_reserve_exact(bytes)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        mem.resize(bytes, 0);
        Ok(Self {
            mem: mem.into_boxed_slice(),
            free: (0..nbuf).collect(),
            bsz: bsz as usize,
        })
    }

    pub fn save(&mut self, data: &[u8]) -> Option<u16> {
        let id = self.free.pop()?;
        let start = id as usize * self.bsz;
        self.mem[start..start + data.len()].copy_from_slice(data);
        Some(id)
    }

    /// A free slot is left (the next `save` succeeds).
    pub fn has_room(&self) -> bool {
        !self.free.is_empty()
    }

    pub fn buf(&self, id: u16, len: usize) -> &[u8] {
        let start = id as usize * self.bsz;
        &self.mem[start..start + len]
    }

    pub fn give(&mut self, id: u16) {
        self.free.push(id);
    }
}

/// How the kernel receives the pool's buffers (decided once by the capability test, `capability::check`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provide {
    /// Registered provided-buffer ring (`IORING_REGISTER_PBUF_RING`): `commit` is one release store.
    Ring,
    /// Classic provided buffers (`IORING_OP_PROVIDE_BUFFERS`): `commit` queues one entry per run of consecutive ids.
    Classic,
}

impl Provide {
    /// Name in startup lines and reports.
    pub fn name(self) -> &'static str {
        match self {
            Provide::Ring => "ring",
            Provide::Classic => "classic",
        }
    }
}

/// `nbuf` buffers of `bsz` bytes plus the ring of their descriptors (registered with the kernel in [`Provide::Ring`]
/// mode; in [`Provide::Classic`] mode the same ring is our own staging list between `give` and `commit`).
pub struct BufRing {
    ring: *mut BufRingEntry,
    ring_layout: Layout,
    mem: *mut u8,
    mem_layout: Layout,
    nbuf: u16,
    bsz: u32,
    tail: u16,
    mode: Provide,
    /// Classic mode: ring position up to which the given ids were handed to the kernel.
    provided: u16,
}

impl std::fmt::Debug for BufRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufRing")
            .field("mode", &self.mode)
            .field("nbuf", &self.nbuf)
            .field("bsz", &self.bsz)
            .finish()
    }
}

impl BufRing {
    /// Allocate and (ring mode) register. `nbuf` must be a power of two (<= 32768). All buffers are given; classic mode
    /// hands them to the kernel with the first [`commit`](Self::commit).
    pub fn new(sub: &Submitter<'_>, nbuf: u16, bsz: u32, mode: Provide) -> io::Result<BufRing> {
        if !nbuf.is_power_of_two() || nbuf > 32768 || bsz == 0 || bsz > i32::MAX as u32 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let rl = Layout::from_size_align(nbuf as usize * size_of::<BufRingEntry>(), PAGE)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let ml = Layout::from_size_align(nbuf as usize * bsz as usize, PAGE)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: non-zero sizes; null checked below (Drop frees what exists).
        let (ring, mem) = unsafe { (alloc_zeroed(rl), alloc_zeroed(ml)) };
        let mut b = BufRing {
            ring: ring.cast(),
            ring_layout: rl,
            mem,
            mem_layout: ml,
            nbuf,
            bsz,
            tail: 0,
            mode,
            provided: 0,
        };
        if ring.is_null() || mem.is_null() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        if mode == Provide::Ring {
            // SAFETY: page-aligned zeroed ring of `nbuf` entries that lives until `unregister` (KNet::drop).
            unsafe { sub.register_buf_ring_with_flags(ring as u64, nbuf, BGID, 0)? };
        }
        for bid in 0..nbuf {
            b.give(bid);
        }
        if mode == Provide::Ring {
            b.publish_tail();
        }
        Ok(b)
    }

    /// The first `len` bytes of buffer `bid` (as reported by a completion).
    pub fn buf(&self, bid: u16, len: usize) -> &[u8] {
        debug_assert!(bid < self.nbuf && len <= self.bsz as usize);
        let len = len.min(self.bsz as usize);
        let bid = (bid % self.nbuf) as usize;
        // SAFETY: bid < nbuf (kernel-provided id of a buffer we registered), len clamped to the buffer size.
        unsafe { std::slice::from_raw_parts(self.mem.add(bid * self.bsz as usize), len) }
    }

    /// Return buffer `bid` to the pool (visible to the kernel after [`commit`](Self::commit)).
    pub fn give(&mut self, bid: u16) {
        let idx = (self.tail & (self.nbuf - 1)) as usize;
        // SAFETY: idx < nbuf; the entry is ours until the tail is published.
        unsafe {
            let e = &mut *self.ring.add(idx);
            e.set_addr(self.mem.add(bid as usize * self.bsz as usize) as u64);
            e.set_len(self.bsz);
            e.set_bid(bid);
        }
        self.tail = self.tail.wrapping_add(1);
    }

    /// Receive mode of this pool.
    pub fn mode(&self) -> Provide {
        self.mode
    }

    /// Publish the returned buffers. Ring mode: tail store, `push` unused. Classic mode: one `PROVIDE_BUFFERS` entry per
    /// run of consecutive ids, passed to `push` with the run's first id and length (the caller sets user data / flags and
    /// queues it). A failed entry hands
    /// its ids back with [`give_run`](Self::give_run).
    pub fn commit(&mut self, mut push: impl FnMut(Entry, u16, u16)) {
        if self.mode == Provide::Ring {
            self.publish_tail();
            return;
        }
        let mut run: Option<(u16, u16)> = None;
        while self.provided != self.tail {
            // SAFETY: index < nbuf; written by `give` and not yet handed to the kernel.
            let bid = unsafe { (*self.ring.add((self.provided & (self.nbuf - 1)) as usize)).bid() };
            self.provided = self.provided.wrapping_add(1);
            run = match run {
                Some((first, n)) if first + n == bid => Some((first, n + 1)),
                Some((first, n)) => {
                    push(self.provide_entry(first, n), first, n);
                    Some((bid, 1))
                }
                None => Some((bid, 1)),
            };
        }
        if let Some((first, n)) = run {
            push(self.provide_entry(first, n), first, n);
        }
    }

    /// Classic mode: give back the ids of a `PROVIDE_BUFFERS` entry the kernel rejected.
    pub fn give_run(&mut self, first: u16, n: u16) {
        for bid in first..first + n {
            self.give(bid);
        }
    }

    fn provide_entry(&self, first: u16, n: u16) -> Entry {
        // SAFETY (memory): `first + n <= nbuf`, the buffers live until the ring is closed (KNet field order).
        let addr = unsafe { self.mem.add(first as usize * self.bsz as usize) };
        opcode::ProvideBuffers::new(addr, self.bsz as i32, n, BGID, first).build()
    }

    fn publish_tail(&mut self) {
        // SAFETY: the tail lives in the first entry's `resv` field of the registered ring.
        unsafe {
            let t = BufRingEntry::tail(self.ring) as *const AtomicU16;
            (*t).store(self.tail, Ordering::Release);
        }
    }

    /// Unregister from the ring (before the memory is freed). Classic buffers go with the ring itself.
    pub fn unregister(&self, sub: &Submitter<'_>) {
        if self.mode == Provide::Ring {
            let _ = sub.unregister_buf_ring(BGID);
        }
    }

    /// Give up the buffer memory without freeing it: requests the kernel may still complete into it outlived a bounded
    /// drain ([`KNet`](super::KNet) drop). [`Drop`] then frees nothing.
    pub fn leak(&mut self) {
        self.ring = std::ptr::null_mut();
        self.mem = std::ptr::null_mut();
    }
}

impl Drop for BufRing {
    fn drop(&mut self) {
        // SAFETY: allocated with these layouts in `new`; null when allocation failed.
        unsafe {
            if !self.ring.is_null() {
                dealloc(self.ring.cast(), self.ring_layout);
            }
            if !self.mem.is_null() {
                dealloc(self.mem, self.mem_layout);
            }
        }
    }
}
