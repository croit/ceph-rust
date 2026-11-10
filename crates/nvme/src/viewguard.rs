// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Debug and `viewguard` builds only (never plain `lab`: every write view takes the registry lock and a crc32c, so
//! timing runs must not carry it): registry of the memory under live zero-copy write views (adr 0061 am. 4), checked by a
//! guarding global allocator on every free.
//!
//! A write view hands the device a pointer into a payload; the view's `Bytes` must keep that allocation alive until the
//! device completed. An owner that frees (or reallocates) the memory early makes the device write freed bytes: an
//! errno 14 when the allocator returned the pages to the kernel (allocations above its arena size are unmapped on
//! free), silently wrong data otherwise. [`check_free`] names the culprit at the moment of the free instead: a guarding
//! allocator calls it for every freed or moved block and fail-stops with the freeing backtrace
//! ([`GuardAlloc`]). Production builds: no registry, no checks.

#[cfg(any(debug_assertions, feature = "viewguard"))]
mod registry;
#[cfg(any(debug_assertions, feature = "viewguard"))]
pub use registry::*;

/// Per-view guard state: the payload crc at the view and the registry entry. Debug and `viewguard` builds only; a
/// zero-sized no-op otherwise.
#[cfg(any(debug_assertions, feature = "viewguard"))]
#[derive(Debug)]
pub struct ViewGuard {
    crc: u32,
    id: u64,
}

#[cfg(any(debug_assertions, feature = "viewguard"))]
impl ViewGuard {
    /// Guard the view of `data`.
    pub fn new(data: &[u8]) -> Self {
        Self {
            crc: crc::crc32c(0, data),
            id: register(data.as_ptr() as usize, data.len()),
        }
    }

    /// `(crc at the view, crc now)` when the bytes `ptr..ptr + len` of the view changed.
    ///
    /// # Safety
    /// `ptr..ptr + len` must be the live memory the guard was made for.
    pub unsafe fn changed(&self, ptr: *const u8, len: usize) -> Option<(u32, u32)> {
        // SAFETY: the caller keeps the range alive.
        let now = crc::crc32c(0, unsafe { std::slice::from_raw_parts(ptr, len) });
        (now != self.crc).then_some((self.crc, now))
    }

    /// The view at `ptr` is gone (call before its payload reference is released).
    pub fn release(&self, ptr: *const u8) {
        unregister(ptr as usize, self.id);
    }
}

/// Production build: no registry, no checks.
#[cfg(not(any(debug_assertions, feature = "viewguard")))]
#[derive(Debug)]
pub struct ViewGuard;

#[cfg(not(any(debug_assertions, feature = "viewguard")))]
impl ViewGuard {
    pub fn new(_data: &[u8]) -> Self {
        Self
    }

    /// # Safety
    /// As the guarded build; never reads anything here.
    pub unsafe fn changed(&self, _ptr: *const u8, _len: usize) -> Option<(u32, u32)> {
        None
    }

    pub fn release(&self, _ptr: *const u8) {}
}
