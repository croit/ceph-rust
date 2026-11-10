// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Segment receive buffers, optionally readable while they are still being filled (adr 0477, receiver-side pre-write).
//!
//! A [`SegBuf`] is the memory one frame segment is assembled in: the decoder appends to it, or a transport that borrowed
//! it ([`crate::Decoder::direct_take_seg`]) receives into its spare capacity. Usually it is a plain `Vec<u8>`. A large
//! data segment of a decoder with pre-write on ([`crate::Decoder::set_prewrite`]) is *shared* instead: its allocation
//! belongs to an `Arc`, the writer publishes every new length ([`SegWatch::filled`]), and anyone holding a [`SegWatch`]
//! may take immutable `Bytes` views of the published prefix while the rest still arrives. The memory lives until the
//! last of writer, views and the frame's final `Bytes` is gone; it never moves (capacity is reserved up front).
//!
//! Contract (the reason this is sound): bytes below the published length are never written again (the writer only
//! appends into spare capacity), and the spare capacity is reachable only through the single writer. The bytes are
//! unverified until the frame's crc was checked; a view is only ever used for writes that nothing references before
//! that check (store pre-write, adr 0477 D1).
//!
//! [`SegWatch::gone`] tells the frame's fate to the holders of views: the writer was dropped before the frame completed
//! (crc failure, connection loss, decoder reset), or the frame's final `Bytes` (all clones and slices) were dropped.

use crate::rxpool::Shelf;
use bytes::Bytes;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};

const FILLING: u8 = 0;
const FINAL: u8 = 1;
const GONE: u8 = 2;

/// Shared segments that turned gone so far (process wide; one per large frame): a holder of many watches looks at
/// them again only when it moved ([`SegWatch::gone_epoch`]).
static GONE_EPOCH: AtomicU64 = AtomicU64::new(0);

fn mark_gone(mem: &SegMem) {
    mem.state.store(GONE, Ordering::Release);
    GONE_EPOCH.fetch_add(1, Ordering::Release);
}

/// The shared allocation of a segment being filled.
#[derive(Debug)]
struct SegMem {
    ptr: NonNull<u8>,
    cap: usize,
    /// Published length (pad included): `[0, filled)` is initialized and immutable.
    filled: AtomicUsize,
    state: AtomicU8,
    shelf: Option<Arc<Shelf>>,
}

// SAFETY: the allocation is owned by this value; readers only touch the published, immutable prefix; the unpublished
// rest is written through the one writer (`SegBuf`), which is `Send` but not shared.
unsafe impl Send for SegMem {}
// SAFETY: see above: concurrent readers see only `[0, filled)` (Acquire after the writer's Release).
unsafe impl Sync for SegMem {}

impl Drop for SegMem {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`cap` came from a `Vec<u8>` whose ownership moved here; length 0 = nothing to drop per element.
        let v = unsafe { Vec::from_raw_parts(self.ptr.as_ptr(), 0, self.cap) };
        match &self.shelf {
            Some(s) => s.put(v),
            None => drop(v),
        }
    }
}

/// Writer side of a shared segment.
#[derive(Debug)]
struct Writer {
    mem: Arc<SegMem>,
    len: usize,
    /// Turned into the frame's final `Bytes` (the fate goes with them).
    done: bool,
}

impl Drop for Writer {
    fn drop(&mut self) {
        if !self.done {
            mark_gone(&self.mem);
        }
    }
}

#[derive(Debug)]
enum Repr {
    Own(Vec<u8>),
    Shared(Writer),
    /// A complete segment in memory the receiver does not own ([`SegBuf::foreign`]).
    Foreign(Foreign),
}

/// A finished segment that a transport received straight into memory it does not own (a caller's read buffer).
struct Foreign {
    ptr: NonNull<u8>,
    len: usize,
    /// Vouches for the memory while any `Bytes` of the segment live (see [`SegBuf::foreign`]).
    _owner: Arc<dyn Send + Sync>,
}

impl core::fmt::Debug for Foreign {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Foreign")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

// SAFETY: the memory is only read (the segment is complete) and stays valid while `owner` lives (constructor contract).
unsafe impl Send for Foreign {}
// SAFETY: see above.
unsafe impl Sync for Foreign {}

impl AsRef<[u8]> for Foreign {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: `ptr..ptr + len` is initialized, unchanged and valid while `owner` lives (constructor contract).
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

/// Segment receive buffer: a `Vec<u8>`, or the writer of a shared segment (see the module docs). Never reallocates once
/// shared: appends beyond the capacity reserved up front panic.
#[derive(Debug)]
pub struct SegBuf(Repr);

impl Default for SegBuf {
    fn default() -> Self {
        SegBuf(Repr::Own(Vec::new()))
    }
}

impl From<Vec<u8>> for SegBuf {
    fn from(v: Vec<u8>) -> Self {
        SegBuf(Repr::Own(v))
    }
}

impl core::ops::Deref for SegBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.0 {
            Repr::Own(v) => v,
            // SAFETY: `[0, len)` is initialized; it is published, so it is never written again.
            Repr::Shared(w) => unsafe { core::slice::from_raw_parts(w.mem.ptr.as_ptr(), w.len) },
            Repr::Foreign(f) => f.as_ref(),
        }
    }
}

impl SegBuf {
    /// A complete segment of `len` bytes at `ptr` that a transport received into memory it does not own (a single
    /// read's caller buffer, adr 0467 A1b): its `Bytes` reference that memory instead of copying it.
    ///
    /// # Safety
    /// `ptr..ptr + len` holds the whole segment, is not written while the segment or any of its `Bytes` lives, and
    /// stays valid until the last of them is dropped; `owner` is the record that vouches for it.
    pub unsafe fn foreign(ptr: NonNull<u8>, len: usize, owner: Arc<dyn Send + Sync>) -> Self {
        SegBuf(Repr::Foreign(Foreign {
            ptr,
            len,
            _owner: owner,
        }))
    }

    /// The bytes of a foreign segment move into an owned buffer before any change (a complete foreign segment is never
    /// appended to by the decoder; this keeps every mutator total).
    fn own(&mut self) {
        if let Repr::Foreign(f) = &self.0 {
            let v = f.as_ref().to_vec();
            self.0 = Repr::Own(v);
        }
    }

    pub fn len(&self) -> usize {
        match &self.0 {
            Repr::Own(v) => v.len(),
            Repr::Shared(w) => w.len,
            Repr::Foreign(f) => f.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        match &self.0 {
            Repr::Own(v) => v.capacity(),
            Repr::Shared(w) => w.mem.cap,
            Repr::Foreign(f) => f.len,
        }
    }

    /// Start of the allocation (stable for a shared segment).
    pub fn as_ptr(&self) -> *const u8 {
        match &self.0 {
            Repr::Own(v) => v.as_ptr(),
            Repr::Shared(w) => w.mem.ptr.as_ptr(),
            Repr::Foreign(f) => f.ptr.as_ptr(),
        }
    }

    /// Start of the allocation for writes into the spare capacity (`as_mut_ptr().add(len())`); bytes below `len()` must
    /// not be written through it.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.own();
        match &mut self.0 {
            Repr::Own(v) => v.as_mut_ptr(),
            Repr::Shared(w) => w.mem.ptr.as_ptr(),
            Repr::Foreign(_) => unreachable!("owned above"),
        }
    }

    /// The memory is shared (pre-write armed).
    pub fn is_shared(&self) -> bool {
        matches!(self.0, Repr::Shared(_))
    }

    /// Set the length (publishes it for a shared segment).
    ///
    /// # Safety
    /// `new_len <= capacity()`, the bytes up to it are initialized, and `new_len >= len()` for a shared segment
    /// (published bytes stay).
    pub unsafe fn set_len(&mut self, new_len: usize) {
        self.own();
        match &mut self.0 {
            // SAFETY: forwarded caller contract.
            Repr::Own(v) => unsafe { v.set_len(new_len) },
            Repr::Shared(w) => {
                assert!(new_len <= w.mem.cap && new_len >= w.len);
                w.len = new_len;
                w.mem.filled.store(new_len, Ordering::Release);
            }
            Repr::Foreign(_) => unreachable!("owned above"),
        }
    }

    /// The uninitialized rest of the capacity.
    pub fn spare_capacity_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        self.own();
        match &mut self.0 {
            Repr::Own(v) => v.spare_capacity_mut(),
            Repr::Foreign(_) => unreachable!("owned above"),
            Repr::Shared(w) => {
                let n = w.mem.cap - w.len;
                // SAFETY: `[len, cap)` lies inside the allocation and only the writer (`&mut self`) reaches it; views
                // never cover it (they end at the published length = `len`).
                unsafe {
                    core::slice::from_raw_parts_mut(
                        w.mem.ptr.as_ptr().add(w.len).cast::<MaybeUninit<u8>>(),
                        n,
                    )
                }
            }
        }
    }

    pub fn extend_from_slice(&mut self, src: &[u8]) {
        self.own();
        match &mut self.0 {
            Repr::Own(v) => v.extend_from_slice(src),
            Repr::Foreign(_) => unreachable!("owned above"),
            Repr::Shared(_) => {
                let at = self.len();
                let spare = &mut self.spare_capacity_mut()[..src.len()];
                // SAFETY: same length; `src` cannot alias the writer's spare capacity.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src.as_ptr(),
                        spare.as_mut_ptr().cast::<u8>(),
                        src.len(),
                    )
                };
                // SAFETY: the `src.len()` bytes after `at` were just written.
                unsafe { self.set_len(at + src.len()) };
            }
        }
    }

    /// Append `src` and return `crc32c(seed, src)` in the same pass.
    pub fn extend_crc(&mut self, seed: u32, src: &[u8]) -> u32 {
        self.own();
        match &mut self.0 {
            Repr::Own(v) => crc::crc32c_extend(seed, src, v),
            Repr::Foreign(_) => unreachable!("owned above"),
            Repr::Shared(_) => {
                let at = self.len();
                let c =
                    crc::crc32c_copy_uninit(seed, src, &mut self.spare_capacity_mut()[..src.len()]);
                // SAFETY: `crc32c_copy_uninit` wrote all `src.len()` bytes after `at`.
                unsafe { self.set_len(at + src.len()) };
                c
            }
        }
    }

    /// Room for `n` more bytes without moving published bytes: a shared segment never grows.
    pub(crate) fn reserve_exact(&mut self, n: usize) -> Result<(), crate::Error> {
        self.own();
        match &mut self.0 {
            Repr::Own(v) => v
                .try_reserve_exact(n)
                .map_err(|_| crate::Error::AllocationFailed(n)),
            Repr::Foreign(_) => unreachable!("owned above"),
            Repr::Shared(w) => {
                if w.mem.cap - w.len >= n {
                    Ok(())
                } else {
                    Err(crate::Error::AllocationFailed(n))
                }
            }
        }
    }

    /// Zero-fill to `n` bytes (the leading pad of a block-mode data segment; before it is shared).
    pub(crate) fn resize_zero(&mut self, n: usize) {
        self.own();
        match &mut self.0 {
            Repr::Own(v) => v.resize(n, 0),
            Repr::Shared(_) => unreachable!("the pad is written before the segment is shared"),
            Repr::Foreign(_) => unreachable!("owned above"),
        }
    }

    /// The plain `Vec<u8>` (`None` for a shared segment).
    pub fn into_vec(self) -> Result<Vec<u8>, SegBuf> {
        match self.0 {
            Repr::Own(v) => Ok(v),
            r => Err(SegBuf(r)),
        }
    }

    /// Share this buffer (its bytes so far are published): the writer stays here, the watch goes to whoever may view the
    /// filled prefix. `shelf` takes the allocation back once the last holder is gone.
    pub(crate) fn share(&mut self, shelf: Option<Arc<Shelf>>) -> SegWatch {
        if let Repr::Shared(w) = &self.0 {
            return SegWatch(w.mem.clone());
        }
        self.own();
        let Repr::Own(v) = core::mem::replace(&mut self.0, Repr::Own(Vec::new())) else {
            unreachable!()
        };
        let mut v = core::mem::ManuallyDrop::new(v);
        let len = v.len();
        let mem = Arc::new(SegMem {
            // SAFETY: a Vec's pointer is never null (dangling for capacity 0, which nobody shares: callers reserve first).
            ptr: unsafe { NonNull::new_unchecked(v.as_mut_ptr()) },
            cap: v.capacity(),
            filled: AtomicUsize::new(len),
            state: AtomicU8::new(FILLING),
            shelf,
        });
        let watch = SegWatch(mem.clone());
        self.0 = Repr::Shared(Writer {
            mem,
            len,
            done: false,
        });
        watch
    }

    /// The finished segment as `Bytes` from byte `from` on: a plain buffer through `shelf` (recycled when the last
    /// reference drops) or as is; a shared one as the owner of its memory (the frame's fate: [`SegWatch::gone`] once all
    /// clones and slices are dropped).
    pub(crate) fn into_bytes(self, shelf: Option<&Arc<Shelf>>, from: usize) -> Bytes {
        let b = match self.0 {
            Repr::Own(v) => match shelf {
                Some(s) => s.adopt(v),
                None => Bytes::from(v),
            },
            Repr::Shared(mut w) => {
                w.done = true;
                w.mem.state.store(FINAL, Ordering::Release);
                Bytes::from_owner(Final {
                    mem: w.mem.clone(),
                    len: w.len,
                })
            }
            Repr::Foreign(f) => Bytes::from_owner(f),
        };
        if from > 0 { b.slice(from..) } else { b }
    }
}

/// Owner of a finished shared segment's `Bytes`.
struct Final {
    mem: Arc<SegMem>,
    len: usize,
}

impl AsRef<[u8]> for Final {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: the writer is gone; `[0, len)` is initialized and immutable.
        unsafe { core::slice::from_raw_parts(self.mem.ptr.as_ptr(), self.len) }
    }
}

impl Drop for Final {
    fn drop(&mut self) {
        mark_gone(&self.mem);
    }
}

/// Owner of a view of the published prefix.
struct View {
    mem: Arc<SegMem>,
    off: usize,
    len: usize,
}

impl AsRef<[u8]> for View {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: checked against the published length at creation; published bytes are immutable.
        unsafe { core::slice::from_raw_parts(self.mem.ptr.as_ptr().add(self.off), self.len) }
    }
}

/// Reader handle of a shared segment (see the module docs).
#[derive(Clone, Debug)]
pub struct SegWatch(Arc<SegMem>);

impl SegWatch {
    /// Published bytes of the buffer (the leading pad of a block-mode data segment included).
    pub fn filled(&self) -> usize {
        self.0.filled.load(Ordering::Acquire)
    }

    /// The frame failed before it completed, or its final `Bytes` are all dropped: nothing will use the segment.
    pub fn gone(&self) -> bool {
        self.0.state.load(Ordering::Acquire) == GONE
    }

    /// Count of shared segments of this process that turned gone so far. A watch read after a load of this value is
    /// gone if it turned gone before that count was taken; while the count stands, no watch turned gone.
    pub fn gone_epoch() -> u64 {
        GONE_EPOCH.load(Ordering::Acquire)
    }

    /// Same segment.
    pub fn same(&self, other: &SegWatch) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// The published bytes `[off, off + len)` of the buffer (pad included in the offsets), borrowed: no handle, no
    /// allocation (a peek at a few header bytes while the segment arrives).
    pub fn peek(&self, off: usize, len: usize) -> Option<&[u8]> {
        let end = off.checked_add(len)?;
        if end > self.filled() {
            return None;
        }
        // SAFETY: within the published prefix, whose bytes are immutable; the borrow keeps the buffer alive.
        Some(unsafe { core::slice::from_raw_parts(self.0.ptr.as_ptr().add(off), len) })
    }

    /// Immutable view of `[off, off + len)` of the buffer (pad included in the offsets), when published.
    pub fn view(&self, off: usize, len: usize) -> Option<Bytes> {
        let end = off.checked_add(len)?;
        if end > self.filled() || len == 0 {
            return None;
        }
        Some(Bytes::from_owner(View {
            mem: self.0.clone(),
            off,
            len,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_buffer_behaves_like_a_vec() {
        let mut s = SegBuf::from(Vec::with_capacity(16));
        s.extend_from_slice(b"abc");
        assert_eq!(s.extend_crc(!0, b"de"), crc::crc32c(!0, b"de"));
        assert_eq!(&s[..], b"abcde");
        assert!(!s.is_shared());
        assert_eq!(s.into_bytes(None, 1), Bytes::from_static(b"bcde"));
    }

    #[test]
    fn views_of_the_published_prefix_while_the_rest_arrives() {
        let mut s = SegBuf::from(Vec::with_capacity(8192));
        s.resize_zero(10);
        let w = s.share(None);
        assert!(s.is_shared());
        assert_eq!(w.filled(), 10);
        assert!(
            w.view(10, 1).is_none(),
            "nothing beyond the published length"
        );
        assert!(
            w.peek(8, 3).is_none(),
            "a peek stays in the published prefix"
        );
        assert_eq!(w.peek(8, 2), Some(&[0u8, 0][..]));
        s.extend_from_slice(&[1; 4086]);
        assert_eq!(w.peek(9, 2), Some(&[0u8, 1][..]));
        let v = w.view(10, 4086).unwrap();
        assert!(v.iter().all(|&b| b == 1));
        // the writer goes on filling while the view lives; the view never changes
        let at = s.len();
        s.spare_capacity_mut()[..4096].fill(MaybeUninit::new(2));
        // SAFETY: just initialized.
        unsafe { s.set_len(at + 4096) };
        assert_eq!(w.filled(), 8192);
        assert!(v.iter().all(|&b| b == 1));
        assert!(!w.gone());
        let b = s.into_bytes(None, 10);
        assert_eq!(b.len(), 8182);
        assert!(!w.gone(), "final bytes alive");
        let tail = b.slice(5000..);
        drop(b);
        assert!(!w.gone(), "a slice keeps the frame alive");
        drop(tail);
        assert!(w.gone());
        // the view outlives everything else
        assert!(v.iter().all(|&b| b == 1));
    }

    #[test]
    fn dropped_writer_marks_the_segment_gone_and_views_keep_the_memory() {
        let mut s = SegBuf::from(Vec::with_capacity(4096));
        let w = s.share(None);
        s.extend_from_slice(&[9; 4096]);
        let v = w.view(0, 4096).unwrap();
        let e0 = SegWatch::gone_epoch();
        drop(s);
        assert!(w.gone());
        assert!(
            SegWatch::gone_epoch() > e0,
            "the epoch moves with every segment that turns gone"
        );
        assert!(v.iter().all(|&b| b == 9));
    }

    #[test]
    fn shared_memory_returns_to_the_shelf_after_the_last_holder() {
        let shelf = Arc::new(Shelf::new(8 << 20));
        let mut s = SegBuf::from(shelf.take(4 << 20).unwrap());
        let w = s.share(Some(shelf.clone()));
        s.extend_from_slice(&[3; 4096]);
        let v = w.view(0, 4096).unwrap();
        let b = s.into_bytes(Some(&shelf), 0);
        drop(b);
        assert_eq!(shelf.parked(), 0, "the view still holds the memory");
        drop(v);
        drop(w);
        assert_eq!(shelf.parked(), (4 << 20) + crate::rxpool::PAD_ROOM);
    }

    #[test]
    #[should_panic]
    fn a_shared_segment_never_grows() {
        let mut s = SegBuf::from(Vec::with_capacity(16));
        let _w = s.share(None);
        s.extend_from_slice(&[0; 32]);
    }
}
