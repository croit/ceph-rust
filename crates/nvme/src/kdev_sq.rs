// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Submission side of the device ring with one SQE per in-flight command (adr 0169 am. 11).
//!
//! The kernel may read a command's SQE after `io_uring_enter` returned: Linux 6.12.y defers the copy of a
//! `URING_CMD` SQE and an io-wq worker that issues the command later reads the ring's SQE memory (upstream "io_uring/
//! uring_cmd: unconditionally copy SQEs at prep time" removed that). A ring that refills SQE slots in tail order would
//! then hand the worker another command: EINVAL at best, another command's IO at worst. Here every command owns its SQE
//! index from push until its CQE is reaped: the SQE is written into `sqes[index]`, only the index goes into the SQ
//! indirection array, and the index is reused only after [`SqOwn::release`]. Same stores per command as a plain push.
//!
//! The `io-uring` crate pushes in tail order and does not expose the ring layout, so the SQ ring and the SQE array are
//! mapped a second time from the ring fd (`IORING_OFF_SQ_RING`, `IORING_OFF_SQES`) with the offsets the kernel
//! returned in `io_uring_params` ([`io_uring::Parameters`] is `repr(transparent)` over it). The crate's own
//! `SubmissionQueue` is never used for this ring; its `Submitter` reads the shared tail and submits what is queued here.
use io_uring::squeue::Entry128;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

/// `IORING_OFF_SQES`: mmap offset of the SQE array.
const OFF_SQES: libc::off_t = 0x1000_0000;
/// `IORING_SQ_CQ_OVERFLOW`: completions wait in the kernel's overflow list.
const SQ_CQ_OVERFLOW: u32 = 1 << 1;

/// Kernel UAPI `struct io_uring_params` (120 bytes; `sq_off` at byte 40).
#[repr(C)]
struct Params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: SqOff,
    cq_off: [u32; 10],
}

/// Kernel UAPI `struct io_sqring_offsets`.
#[repr(C)]
struct SqOff {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

const _: () = assert!(std::mem::size_of::<Params>() == 120);
const _: () = assert!(std::mem::size_of::<io_uring::Parameters>() == 120);
const _: () = assert!(std::mem::size_of::<Entry128>() == 128);

/// One mapping of this module (unmapped on drop).
struct Map(*mut u8, usize);

impl Map {
    fn new(fd: RawFd, len: usize, off: libc::off_t) -> std::io::Result<Map> {
        // SAFETY: fresh shared mapping of the ring fd at a kernel-defined offset; checked below.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                off,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Map(p.cast(), len))
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        // SAFETY: our own mapping, not referenced after drop.
        unsafe { libc::munmap(self.0.cast(), self.1) };
    }
}

/// SQ of one ring with per-command SQE ownership (module doc). Single thread (the ring's issuer).
pub(super) struct SqOwn {
    tail: *const AtomicU32,
    flags: *const AtomicU32,
    mask: u32,
    array: *mut u32,
    sqes: *mut Entry128,
    /// Free SQE indices (an index is out while its command is in flight).
    free: Vec<u32>,
    /// Owner (user_data) of each SQE index while it is out.
    owner: Vec<Option<u64>>,
    local_tail: u32,
    _ring: Map,
    _sqes: Map,
}

impl SqOwn {
    /// Maps the SQ of `ring` (created without `IORING_SETUP_NO_SQARRAY`, nothing pushed yet).
    pub(super) fn new<C: io_uring::cqueue::EntryMarker>(
        ring: &io_uring::IoUring<Entry128, C>,
    ) -> std::io::Result<SqOwn> {
        // SAFETY: `Parameters` is `repr(transparent)` over the kernel's `io_uring_params` (size asserted above).
        let p = unsafe { &*(ring.params() as *const io_uring::Parameters).cast::<Params>() };
        let n = p.sq_entries as usize;
        let fd = std::os::fd::AsRawFd::as_raw_fd(ring);
        let rmap = Map::new(fd, p.sq_off.array as usize + n * 4, 0)?;
        let smap = Map::new(fd, n * std::mem::size_of::<Entry128>(), OFF_SQES)?;
        let at = |o: u32| rmap.0.wrapping_add(o as usize);
        let (tail, flags) = (
            at(p.sq_off.tail).cast::<AtomicU32>(),
            at(p.sq_off.flags).cast::<AtomicU32>(),
        );
        // SAFETY: offsets inside the SQ ring mapping as the kernel reported them.
        let mask = unsafe { *at(p.sq_off.ring_mask).cast::<u32>() };
        // SAFETY: as above; nothing was pushed yet, so the shared tail is the start.
        let local_tail = unsafe { (*tail).load(Ordering::Acquire) };
        Ok(SqOwn {
            tail,
            flags,
            mask,
            array: at(p.sq_off.array).cast(),
            sqes: smap.0.cast(),
            free: (0..n as u32).rev().collect(),
            owner: vec![None; n],
            local_tail,
            _ring: rmap,
            _sqes: smap,
        })
    }

    /// Queues `e` in an SQE index of its own until [`Self::release`]; the index is added to its `user_data` (bits
    /// 16..32, which the caller leaves zero; [`index_of`]). `None` = every index is out (reap first).
    pub(super) fn push(&mut self, mut e: Entry128) -> Option<u32> {
        let i = *self.free.last()?;
        debug_assert_eq!(
            index_of(e.get_user_data()),
            0,
            "user_data bits 16..32 are the SQE index"
        );
        let user = e.get_user_data() | u64::from(i) << 16;
        e.set_user_data(user);
        self.free.pop();
        // SAFETY: index `i` is not referenced by any command in flight (it was free); in bounds of the SQE array; the SQ
        // ring has room because every queued index is a distinct free index (at most `sq_entries` queued).
        unsafe {
            self.sqes.add(i as usize).write(e);
            self.array
                .add((self.local_tail & self.mask) as usize)
                .write_volatile(i);
            self.local_tail = self.local_tail.wrapping_add(1);
            (*self.tail).store(self.local_tail, Ordering::Release);
        }
        self.owner[i as usize] = Some(user);
        Some(i)
    }

    /// The command of this CQE `user_data` completed (its CQE was reaped): its SQE index may be reused.
    pub(super) fn release(&mut self, user_data: u64) {
        let i = index_of(user_data);
        match self.owner.get_mut(i as usize) {
            Some(o) if *o == Some(user_data) => {
                *o = None;
                self.free.push(i);
            }
            o => panic!(
                "kernel store: completion {user_data:#x} names SQE {i} owned by {:?}",
                o.map(|o| *o)
            ),
        }
    }

    pub(super) fn cq_overflow(&self) -> bool {
        // SAFETY: shared flags written by the kernel.
        unsafe { (*self.flags).load(Ordering::Acquire) & SQ_CQ_OVERFLOW != 0 }
    }

    /// TEST: SQE indices out (commands queued or in flight).
    #[cfg(test)]
    pub(super) fn out(&self) -> usize {
        self.owner.len() - self.free.len()
    }

    /// TEST: the SQE bytes at index `i`.
    #[cfg(test)]
    pub(super) fn sqe_bytes(&self, i: u32) -> [u8; 128] {
        // SAFETY: in-bounds read of plain SQE memory.
        unsafe { self.sqes.add(i as usize).cast::<[u8; 128]>().read() }
    }
}

/// SQE index carried in a command's `user_data` (bits 16..32).
pub(super) fn index_of(user_data: u64) -> u32 {
    (user_data >> 16) as u32 & 0xffff
}
