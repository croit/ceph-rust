// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Return path of pooled IO buffers that left their core as shared read data ([`crate::IoBuf::into_shared`]): every
//! buffer goes back to the thread that allocated it.
//!
//! The per-thread buffer pools are filled by the thread that drops a buffer. A read buffer handed to a reply is dropped by
//! the connection core after the send, not by the store core that allocated it; without a way home the store core's pool
//! drains (fresh DMA allocations per read) while the connection core's pool only fills, and once that is full every
//! further drop is a `spdk_dma_free` (`rte_free` memsets the block). A shared pool of fixed slots does not fix that: it
//! has to hold one whole large read (a 128 MiB object in 128 KiB commands = 1024 buffers; with several reads in flight
//! `byte cap / 4 KiB` = 65536 slots) and any lookup scans it.
//!
//! Instead each allocating thread owns an inbox: a lock-free stack of the buffers returned to it. A dropper pushes the
//! block (multi producer, a CAS on the head); the owner takes the whole chain with one `swap` at its next allocation and
//! hands it to its own pool (single consumer: no ABA). The list link and the pool key live in the first 16 bytes of the
//! parked block itself, so the structure needs no memory beyond one head per owner, nothing bounds it but the memory
//! the owner allocated in the first place, and the owner's pool applies its own byte cap when it takes the chain over.
//!
//! An owner that ends (thread exit) retires its inbox: the head becomes [`DEAD`], later pushes are refused (the dropper
//! pools or frees the block itself, as before) and the chain it holds is handed to the owner's free routine. Threads
//! beyond [`MAX_OWNERS`] have no inbox and their buffers are pooled by whoever drops them.
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Threads that can own an inbox (the OSD has one thread per core; beyond this, no return path).
pub(crate) const MAX_OWNERS: usize = 1024;
/// Head value of a retired inbox (blocks are 4 KiB aligned: never an address).
const DEAD: usize = 1;

static NEXT_OWNER: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// `0` = not assigned yet, `1 + id` = owner id, `usize::MAX` = none left.
    static OWNER: Cell<usize> = const { Cell::new(0) };
}

/// This thread's owner id (assigned on first use), `None` when [`MAX_OWNERS`] were handed out.
pub(crate) fn my_owner() -> Option<u16> {
    OWNER
        .try_with(|o| {
            if o.get() == 0 {
                let id = NEXT_OWNER.fetch_add(1, Ordering::Relaxed);
                o.set(if id < MAX_OWNERS { 1 + id } else { usize::MAX });
            }
            (o.get() != usize::MAX).then(|| (o.get() - 1) as u16)
        })
        .ok()
        .flatten()
}

/// Per-owner inboxes of returned blocks.
#[derive(Debug)]
pub(crate) struct Returns {
    heads: [AtomicUsize; MAX_OWNERS],
    /// Blocks taken back by their owner / pushes refused (owner retired or unknown: the dropper keeps the block).
    hits: AtomicU64,
    refused: AtomicU64,
}

/// The blocks of one inbox, newest first: `(address, key)`.
pub(crate) struct Chain<'a> {
    at: usize,
    hits: &'a AtomicU64,
}

impl Iterator for Chain<'_> {
    type Item = (usize, usize);
    fn next(&mut self) -> Option<(usize, usize)> {
        if self.at == 0 {
            return None;
        }
        let node = self.at as *const usize;
        // SAFETY: `at` is a block this chain owns exclusively since the `swap` that took it (a pusher wrote the link and
        // the key into its first 16 bytes before publishing it with a release CAS; the swap acquired it).
        let (next, key) = unsafe { (node.read(), node.add(1).read()) };
        let addr = self.at;
        self.at = next;
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some((addr, key))
    }
}

impl Returns {
    pub(crate) const fn new() -> Self {
        Returns {
            heads: [const { AtomicUsize::new(0) }; MAX_OWNERS],
            hits: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }

    /// Return the block at `addr` (4 KiB aligned, at least 16 bytes, no longer referenced by anyone) of pool `key` to
    /// `owner`. False = not accepted (retired or unknown owner, unusable address): the caller keeps the block.
    pub(crate) fn put(&self, owner: u16, addr: usize, key: usize) -> bool {
        let Some(head) = self.heads.get(owner as usize) else {
            return false;
        };
        if addr == 0 || !addr.is_multiple_of(4096) {
            return false;
        }
        let node = addr as *mut usize;
        // SAFETY: the caller hands over a block nobody else references; a block is at least one page.
        unsafe { node.add(1).write(key) };
        let mut h = head.load(Ordering::Relaxed);
        loop {
            if h == DEAD {
                self.refused.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            // SAFETY: as above, the block is still ours until the CAS publishes it.
            unsafe { node.write(h) };
            match head.compare_exchange_weak(h, addr, Ordering::Release, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(now) => h = now,
            }
        }
    }

    /// Everything returned to `owner` so far (the owner's thread only: one consumer).
    pub(crate) fn take_all(&self, owner: u16) -> Chain<'_> {
        let head = &self.heads[owner as usize];
        let at = match head.load(Ordering::Relaxed) {
            0 | DEAD => 0,
            _ => head.swap(0, Ordering::Acquire),
        };
        Chain {
            at,
            hits: &self.hits,
        }
    }

    /// The owner ends: refuse further returns and hand back what is parked.
    pub(crate) fn retire(&self, owner: u16) -> Chain<'_> {
        let at = match self.heads[owner as usize].swap(DEAD, Ordering::Acquire) {
            DEAD => 0,
            h => h,
        };
        Chain {
            at,
            hits: &self.hits,
        }
    }

    /// `(blocks taken back by their owner, pushes refused)`.
    pub(crate) fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.refused.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{Layout, alloc, dealloc};

    fn block() -> usize {
        // SAFETY: non-zero size, valid layout; freed by `release`.
        unsafe { alloc(Layout::from_size_align(4096, 4096).unwrap()) as usize }
    }

    fn release(a: usize) {
        // SAFETY: allocated by `block` with this layout.
        unsafe { dealloc(a as *mut u8, Layout::from_size_align(4096, 4096).unwrap()) }
    }

    #[test]
    fn a_whole_large_read_comes_back_to_its_owner_in_one_take() {
        // 4096 blocks (far above any fixed slot count) of two keys: all come back exactly once, newest first
        let r = Returns::new();
        let blocks: Vec<usize> = (0..4096).map(|_| block()).collect();
        for (i, &b) in blocks.iter().enumerate() {
            assert!(r.put(3, b, 1 + i % 2));
        }
        assert_eq!(
            r.take_all(4).count(),
            0,
            "another owner's inbox is separate"
        );
        let got: Vec<(usize, usize)> = r.take_all(3).collect();
        assert_eq!(got.len(), 4096);
        let mut addrs: Vec<usize> = got.iter().map(|g| g.0).collect();
        addrs.sort_unstable();
        let mut want = blocks.clone();
        want.sort_unstable();
        assert_eq!(addrs, want);
        assert!(
            got.iter()
                .all(|&(a, k)| k == 1 + blocks.iter().position(|&b| b == a).unwrap() % 2)
        );
        assert_eq!(r.take_all(3).count(), 0, "taken once");
        assert_eq!(r.stats(), (4096, 0));
        blocks.into_iter().for_each(release);
    }

    #[test]
    fn rejects_unusable_addresses_and_unknown_owners() {
        let r = Returns::new();
        assert!(!r.put(0, 0, 1));
        assert!(!r.put(0, 4097, 1));
        assert!(!r.put(MAX_OWNERS as u16, 4096, 1));
        assert_eq!(r.take_all(0).count(), 0);
    }

    #[test]
    fn a_retired_inbox_hands_back_its_blocks_and_refuses_more() {
        let r = Returns::new();
        let (a, b, c) = (block(), block(), block());
        assert!(r.put(7, a, 5));
        assert!(r.put(7, b, 6));
        let mut got: Vec<_> = r.retire(7).collect();
        got.sort_unstable();
        let mut want = vec![(a, 5), (b, 6)];
        want.sort_unstable();
        assert_eq!(got, want);
        assert!(!r.put(7, c, 1), "retired");
        assert_eq!(r.stats().1, 1);
        assert_eq!(r.take_all(7).count(), 0);
        assert_eq!(r.retire(7).count(), 0, "retiring twice is harmless");
        [a, b, c].into_iter().for_each(release);
    }

    #[test]
    fn concurrent_pushers_and_one_consumer_lose_and_duplicate_nothing() {
        static R: Returns = Returns::new();
        let per = 3000usize;
        let pushers: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(move || {
                    let mine: Vec<usize> = (0..per).map(|_| block()).collect();
                    for &b in &mine {
                        assert!(R.put(9, b, 2));
                    }
                    mine
                })
            })
            .collect();
        let mut got = Vec::new();
        let mut all = Vec::new();
        for p in pushers {
            all.extend(p.join().unwrap());
            got.extend(R.take_all(9).map(|g| g.0));
        }
        got.extend(R.take_all(9).map(|g| g.0));
        got.sort_unstable();
        all.sort_unstable();
        assert_eq!(got, all);
        all.into_iter().for_each(release);
    }

    #[test]
    fn owners_are_distinct_per_thread_and_stable() {
        let me = my_owner().unwrap();
        assert_eq!(my_owner(), Some(me));
        let other = std::thread::spawn(|| my_owner().unwrap()).join().unwrap();
        assert_ne!(me, other);
    }
}
