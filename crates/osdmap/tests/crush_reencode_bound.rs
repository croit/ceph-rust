// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! An incremental CRUSH blob is re-encoded canonically (short weight positions padded to bucket
//! size). A compact blob whose canonical form exceeds the u32 bufferlist length classic uses for
//! the CRUSH blob is refused before the padded form is materialized.
use osdmap::*;
use std::alloc::{GlobalAlloc, Layout, System};

/// Refuses any single allocation above 256 MiB, so materializing the padded form aborts the
/// test process instead of exhausting the runner's memory.
struct Capped;
const CAP: usize = 256 << 20;

unsafe impl GlobalAlloc for Capped {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() > CAP {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > CAP {
            return std::ptr::null_mut();
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Capped = Capped;

fn u32v(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}

/// One straw2 bucket of `items` items, one choose_args arg with `positions` empty positions.
fn short_positions_crush(items: i32, positions: u32) -> Vec<u8> {
    let mut map = crush::CrushMap::new();
    let ids: Vec<_> = (0..items).map(|id| (id, 0x10000)).collect();
    map.add_bucket(crush::Bucket::straw2(-1, 1, &ids));
    let mut raw = map.encode();
    // Replace the empty choose_args map and the two trailing MSR tunables.
    raw.truncate(raw.len() - 12);
    u32v(&mut raw, 1);
    raw.extend_from_slice(&(-1i64).to_le_bytes());
    u32v(&mut raw, 1);
    u32v(&mut raw, 0);
    u32v(&mut raw, positions);
    for _ in 0..positions {
        u32v(&mut raw, 0);
    }
    u32v(&mut raw, 0);
    u32v(&mut raw, 100);
    u32v(&mut raw, 100);
    raw
}

fn inc(crush: Vec<u8>) -> Incremental {
    Incremental {
        epoch: 2,
        crush,
        encode_features: u64::MAX,
        has_crc: false,
        ..Incremental::default()
    }
}

#[test]
fn unencodable_canonical_crush_is_refused_before_materializing() {
    let mut map = OsdMap::default();
    map.epoch = 1;
    let raw = short_positions_crush(32768, 32768);
    assert!(raw.len() < 512 * 1024);
    let refused = map.apply_incremental_checked(&inc(raw));
    assert!(
        matches!(
            refused,
            Err(Error::Invalid(
                "incremental crush map canonical encoding exceeds u32 length"
            ))
        ),
        "{:?}",
        refused.map(|m| m.epoch)
    );
}

#[test]
fn padded_canonical_crush_within_limit_is_installed() {
    let mut map = OsdMap::default();
    map.epoch = 1;
    let next = map
        .apply_incremental_checked(&inc(short_positions_crush(64, 8)))
        .unwrap();
    assert_eq!(next.epoch, 2);
    let stored = next.crush_blob();
    assert_eq!(
        crush::CrushMap::decode(stored)
            .unwrap()
            .encode_with_features(u64::MAX),
        stored
    );
    // 8 positions x 64 zero weights each, written explicitly.
    assert!(stored.len() > 8 * 64 * 4);
}
