// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Recycling of large receive segment buffers.
//!
//! A multi-MiB segment buffer allocated per message is returned to the system when the application releases it, and
//! the allocator trims the heap top: the next message page-faults and zero-fills the same memory again. A [`Shelf`]
//! keeps released buffers per size class (powers of two) and hands them out again. It belongs to one dispatch domain
//! ([`crate::DispatchBudget`]): the domain's byte target is the credit for all messages in flight, so it also bounds
//! the memory parked here; a domain without a byte target keeps nothing. A client without a dispatch domain attaches
//! a shelf of its own ([`crate::Decoder::attach_shelf`], [`crate::Connection::attach_shelf`]), limited by its event byte budget.
//!
//! Ownership: a buffer reaches the application as [`bytes::Bytes`] (see [`Shelf::adopt`]); it returns to the shelf
//! only when the last reference (slice, clone, any thread) is dropped, never earlier.
use std::sync::{Arc, Mutex};

/// Segments shorter than this are not recycled (the allocator serves them from its bins without trimming).
pub(crate) const MIN_POOLED: usize = crate::decode::BLOCKS_MIN;

/// Room for the leading pad of a placed data segment (`Decoder::set_rx_place`): every size class is a power of two plus
/// this, so a placed power-of-two segment never takes the next class.
pub(crate) const PAD_ROOM: usize = crc::blocks::BLK;

#[derive(Debug, Default)]
struct Free {
    /// Capacity of all parked buffers.
    bytes: usize,
    /// Parked buffers; index = log2 of their capacity.
    classes: Vec<Vec<Vec<u8>>>,
}

/// Size-classed store of released segment buffers, bounded by `limit` bytes.
#[derive(Debug)]
pub struct Shelf {
    limit: usize,
    free: Mutex<Free>,
}

/// A parked-to-be buffer owned by a [`bytes::Bytes`]; returns to its shelf on drop.
struct Lease {
    buf: Vec<u8>,
    shelf: Arc<Shelf>,
}

impl AsRef<[u8]> for Lease {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.shelf.put(core::mem::take(&mut self.buf));
    }
}

impl Shelf {
    /// A shelf parking at most `limit` bytes of released buffers (0: recycles nothing).
    pub fn new(limit: u64) -> Self {
        Self {
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
            free: Mutex::default(),
        }
    }

    /// Size class of a buffer capacity: `2^k + PAD_ROOM` with `2^k >= MIN_POOLED` is class `k`.
    fn class(capacity: usize) -> Option<u32> {
        let body = capacity.checked_sub(PAD_ROOM)?;
        (body >= MIN_POOLED && body.is_power_of_two()).then(|| body.trailing_zeros())
    }

    /// An empty buffer with room for `len` bytes: a recycled one when the class is stocked, else a new allocation
    /// of the class size (exactly `len` when this shelf recycles nothing).
    pub(crate) fn take(&self, len: usize) -> Result<Vec<u8>, std::collections::TryReserveError> {
        let mut v = Vec::new();
        if self.limit == 0 || len < MIN_POOLED {
            v.try_reserve_exact(len)?;
            return Ok(v);
        }
        let cap = len
            .saturating_sub(PAD_ROOM)
            .max(MIN_POOLED)
            .checked_next_power_of_two()
            .and_then(|b| b.checked_add(PAD_ROOM))
            .unwrap_or(len);
        if let Some(class) = Self::class(cap) {
            let mut free = self.free.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(b) = free.classes.get_mut(class as usize).and_then(Vec::pop) {
                free.bytes -= b.capacity();
                return Ok(b);
            }
        }
        v.try_reserve_exact(cap)?;
        Ok(v)
    }

    pub(crate) fn put(&self, mut buf: Vec<u8>) {
        let cap = buf.capacity();
        let Some(class) = Self::class(cap) else {
            return;
        };
        buf.clear();
        let mut free = self.free.lock().unwrap_or_else(|e| e.into_inner());
        if free.bytes.saturating_add(cap) > self.limit {
            return;
        }
        if free.classes.len() <= class as usize {
            free.classes.resize_with(class as usize + 1, Vec::new);
        }
        free.bytes += cap;
        free.classes[class as usize].push(buf);
    }

    /// Hand a filled segment buffer to the application. A buffer of a recyclable class returns here when its last
    /// reference is dropped; any other (or any buffer of a shelf that recycles nothing) is an ordinary owned `Bytes`.
    pub(crate) fn adopt(self: &Arc<Self>, buf: Vec<u8>) -> bytes::Bytes {
        if self.limit != 0 && Self::class(buf.capacity()).is_some() {
            bytes::Bytes::from_owner(Lease {
                buf,
                shelf: self.clone(),
            })
        } else {
            bytes::Bytes::from(buf)
        }
    }

    #[cfg(test)]
    pub(crate) fn parked(&self) -> usize {
        self.free.lock().unwrap().bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recycles_by_class_and_bounds_memory() {
        let shelf = Arc::new(Shelf::new(2 * ((4 << 20) + PAD_ROOM) as u64));
        let a = shelf.take(4 << 20).unwrap();
        let ptr = a.as_ptr();
        assert_eq!(a.capacity(), (4 << 20) + PAD_ROOM);
        let mut a = a;
        a.resize(4 << 20, 7);
        let bytes = shelf.adopt(a);
        let tail = bytes.slice(1000..);
        drop(bytes);
        assert_eq!(shelf.parked(), 0, "a slice still references the buffer");
        drop(tail);
        assert_eq!(shelf.parked(), (4 << 20) + PAD_ROOM);
        let b = shelf.take(4 << 20).unwrap();
        assert_eq!(b.as_ptr(), ptr);
        assert!(b.is_empty());
        assert_eq!(shelf.parked(), 0);
        // limit: only two 4 MiB buffers stay parked
        let held: Vec<_> = (0..3)
            .map(|_| shelf.adopt(shelf.take(4 << 20).unwrap()))
            .collect();
        drop(held);
        assert_eq!(shelf.parked(), 2 * ((4 << 20) + PAD_ROOM));
    }

    #[test]
    fn disabled_shelf_and_small_segments_do_not_recycle() {
        let off = Arc::new(Shelf::new(0));
        let v = off.take(4 << 20).unwrap();
        assert_eq!(v.capacity(), 4 << 20);
        drop(off.adopt(v));
        assert_eq!(off.parked(), 0);
        let on = Arc::new(Shelf::new(1 << 30));
        let small = on.take(MIN_POOLED - 1).unwrap();
        drop(on.adopt(small));
        assert_eq!(on.parked(), 0);
        let odd = on.take(5 << 20).unwrap();
        assert_eq!(odd.capacity(), (8 << 20) + PAD_ROOM);
        // a placed power-of-two segment (pad room added by the caller) stays in its class
        let placed = on.take((4 << 20) + PAD_ROOM).unwrap();
        assert_eq!(placed.capacity(), (4 << 20) + PAD_ROOM);
    }
}
