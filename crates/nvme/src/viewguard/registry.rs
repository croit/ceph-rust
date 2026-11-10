// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Registry and guarding allocator of [`super`] (debug and `viewguard` builds).
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Live views: `(start, id) -> len`.
static LIVE: Mutex<BTreeMap<(usize, u64), usize>> = Mutex::new(BTreeMap::new());
/// Entries in [`LIVE`] (lock-free fast path of [`check_free`]).
static COUNT: AtomicUsize = AtomicUsize::new(0);
/// Longest view registered so far (bounds the backward scan of [`overlap`]).
static MAX_LEN: AtomicUsize = AtomicUsize::new(0);
static NEXT: AtomicU64 = AtomicU64::new(1);

std::thread_local! {
    /// The registry itself allocates and frees (map nodes): those frees are not checked (no recursion into the lock).
    static BUSY: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Run `f` with the registry locked, unless this thread is inside the registry already.
fn with_live<R>(f: impl FnOnce(&mut BTreeMap<(usize, u64), usize>) -> R) -> Option<R> {
    let entered = BUSY.try_with(|b| !b.replace(true)).unwrap_or(false);
    if !entered {
        return None;
    }
    let r = f(&mut LIVE.lock().unwrap_or_else(|e| e.into_inner()));
    let _ = BUSY.try_with(|b| b.set(false));
    Some(r)
}

/// Register the memory `[ptr, ptr + len)` of a new write view; the id unregisters it ([`unregister`]).
pub fn register(ptr: usize, len: usize) -> u64 {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    MAX_LEN.fetch_max(len, Ordering::Relaxed);
    if with_live(|m| m.insert((ptr, id), len)).is_some() {
        COUNT.fetch_add(1, Ordering::Release);
    }
    id
}

/// The view `(ptr, id)` is gone (its `Bytes` reference is released right after).
pub fn unregister(ptr: usize, id: u64) {
    if with_live(|m| m.remove(&(ptr, id))).flatten().is_some() {
        COUNT.fetch_sub(1, Ordering::Release);
    }
}

/// A live view overlapping `[ptr, ptr + len)`: its `(start, len)`.
pub fn overlap(ptr: usize, len: usize) -> Option<(usize, usize)> {
    if COUNT.load(Ordering::Acquire) == 0 || len == 0 {
        return None;
    }
    let end = ptr.saturating_add(len);
    let reach = MAX_LEN.load(Ordering::Relaxed);
    with_live(|m| {
        m.range(..(end, 0))
            .rev()
            .take_while(|((s, _), _)| s.saturating_add(reach) > ptr)
            .find(|((s, _), l)| s + **l > ptr)
            .map(|((s, _), l)| (*s, *l))
    })
    .flatten()
}

/// A block `[ptr, ptr + len)` is being freed (or moved away by a reallocation): fail-stop with the freeing backtrace
/// when a live write view still points into it. Blocks below 4 KiB cannot back a view (a view is whole device
/// blocks) and are not looked at.
pub fn check_free(ptr: usize, len: usize) {
    if len < 4096 || COUNT.load(Ordering::Acquire) == 0 {
        return;
    }
    if let Some((s, l)) = overlap(ptr, len) {
        // the report allocates: mark this thread so its own frees are not checked again
        let _ = BUSY.try_with(|b| b.set(true));
        eprintln!(
            "ERROR write view guard: block {ptr:#x}+{len} freed while a write view {s:#x}+{l} into it is live \
             (payload freed or moved before the device completed); freeing stack:\n{}",
            std::backtrace::Backtrace::force_capture()
        );
        std::process::abort();
    }
}

/// Global allocator wrapper that runs [`check_free`] on every free and on every reallocation that moves or shrinks a
/// block (debug and `viewguard` builds; the daemon installs it around its allocator).
pub struct GuardAlloc<A>(pub A);

impl<A> std::fmt::Debug for GuardAlloc<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GuardAlloc")
    }
}

// SAFETY: forwards every call to the inner allocator unchanged; the checks only read the registry.
unsafe impl<A: std::alloc::GlobalAlloc> std::alloc::GlobalAlloc for GuardAlloc<A> {
    unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
        // SAFETY: forwarded caller contract.
        unsafe { self.0.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: std::alloc::Layout) -> *mut u8 {
        // SAFETY: forwarded caller contract.
        unsafe { self.0.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
        check_free(p as usize, l.size());
        // SAFETY: forwarded caller contract.
        unsafe { self.0.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: std::alloc::Layout, n: usize) -> *mut u8 {
        // a block that grows may move: the whole old block counts as freed; a shrink frees its tail
        if n >= l.size() {
            check_free(p as usize, l.size());
        } else {
            check_free(p as usize + n, l.size() - n);
        }
        // SAFETY: forwarded caller contract.
        unsafe { self.0.realloc(p, l, n) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_finds_views_inside_and_across_a_block() {
        let a = register(0x10_0000, 8192);
        let b = register(0x20_0000, 4096);
        assert_eq!(overlap(0x10_0000, 4096), Some((0x10_0000, 8192)));
        assert_eq!(
            overlap(0x0f_f000, 0x1001),
            Some((0x10_0000, 8192)),
            "block ends inside the view"
        );
        assert_eq!(
            overlap(0x10_1fff, 1),
            Some((0x10_0000, 8192)),
            "last byte of the view"
        );
        assert_eq!(overlap(0x10_2000, 0x1000), None, "right after the view");
        assert_eq!(overlap(0x0f_0000, 0x1_0000), None, "right before the view");
        assert_eq!(overlap(0x1f_0000, 0x2_0000), Some((0x20_0000, 4096)));
        unregister(0x10_0000, a);
        unregister(0x20_0000, b);
        assert_eq!(overlap(0x10_0000, 4096), None);
        assert_eq!(overlap(0x20_0000, 4096), None);
    }
}
