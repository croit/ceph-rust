// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Allocation behaviour of the hot paths: repeated calls on one geometry must reuse their plans/scratch, and a
//! refused or parsed profile must not allocate per chunk or per extent (review EC-2/4/5/6/7/8/9).

use ec::bitmat::{BitCodec, BitTech};
use ec::clay::{ClayCodec, ClayProfile};
use ec::code::Code;
use ec::lrc::{LrcCodec, LrcSpec};
use ec::moddesc::{ModDescBuilder, parse};
use ec::wide::{WideCodec, WideKind};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::hint::black_box;

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}
struct CountingAllocator;
// SAFETY: allocation and deallocation are delegated unchanged to the system allocator.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
            let _ = BYTES.try_with(|n| n.set(n.get() + layout.size()));
        }
        // SAFETY: caller supplies the allocator's valid layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: allocation and layout came from this same system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Run `f` and report (result, allocations, allocated bytes).
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    ALLOCS.set(0);
    BYTES.set(0);
    TRACK.set(true);
    let v = f();
    TRACK.set(false);
    (v, ALLOCS.get(), BYTES.get())
}

fn pattern(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2654435761).wrapping_add(1);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 8) as u8
        })
        .collect()
}

fn pm(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
    kv.iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

/// EC-2: a k/m/l shorthand the mapping length check refuses must be rejected before the mapping and layer strings
/// are built (a mon-stored profile reaches `generate` on every OSD-map apply).
#[test]
fn lrc_generate_rejects_before_allocating() {
    let (r, _, bytes) = measure(|| LrcSpec::generate(2000, 0, 1));
    assert!(r.is_err());
    assert!(
        bytes < 4096,
        "generate allocated {bytes} bytes before refusing k+m=2000"
    );
}

/// EC-4: the decode plan of a `(have, want)` pair depends only on the geometry, so repeated decodes must not
/// rebuild the survivor inverse and the per-coefficient split tables.
#[test]
fn wide_decode_plans_are_reused() {
    let code = WideCodec::try_new(WideKind::Van, 8, 3, 32).unwrap();
    let len = 4096;
    let data: Vec<Vec<u8>> = (0..8).map(|i| pattern(len, i as u32 + 1)).collect();
    let mut parity = vec![vec![0u8; len]; 3];
    {
        let d: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let mut p: Vec<&mut [u8]> = parity.iter_mut().map(Vec::as_mut_slice).collect();
        code.encode(&d, &mut p);
    }
    let have: Vec<(usize, &[u8])> = (3..8)
        .map(|i| (i, data[i].as_slice()))
        .chain((8..11).map(|i| (i, parity[i - 8].as_slice())))
        .collect();
    let want = [0, 1, 2];
    let mut out = vec![vec![0u8; len]; 3];
    let mut o: Vec<&mut [u8]> = out.iter_mut().map(Vec::as_mut_slice).collect();
    code.decode_into(&have, &want, &mut o).unwrap();
    let (_, allocs, _) = measure(|| {
        for _ in 0..10 {
            code.decode_into(black_box(&have), &want, &mut o).unwrap();
        }
    });
    assert_eq!(out[0], data[0]);
    assert_eq!(
        allocs, 0,
        "a warmed decode must reuse its survivor inverse and tables"
    );
}

/// EC-5: the same for the bit-matrix codes: the elimination plan of a `(have, want)` pair is reused.
#[test]
fn bitmatrix_decode_plans_are_reused() {
    let code = BitCodec::try_new(BitTech::CauchyOrig, 4, 2, 8, 8).unwrap();
    let len = 4096;
    let data: Vec<Vec<u8>> = (0..4).map(|i| pattern(len, i as u32 + 1)).collect();
    let mut parity = vec![vec![0u8; len]; 2];
    {
        let d: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let mut p: Vec<&mut [u8]> = parity.iter_mut().map(Vec::as_mut_slice).collect();
        code.encode(&d, &mut p);
    }
    let have: Vec<(usize, &[u8])> = (1..4)
        .map(|i| (i, data[i].as_slice()))
        .chain([(4, parity[0].as_slice())])
        .collect();
    let want = [0, 5];
    let mut out = vec![vec![0u8; len]; 2];
    let mut o: Vec<&mut [u8]> = out.iter_mut().map(Vec::as_mut_slice).collect();
    code.decode_into(&have, &want, &mut o).unwrap();
    let (_, allocs, _) = measure(|| {
        for _ in 0..10 {
            code.decode_into(black_box(&have), &want, &mut o).unwrap();
        }
    });
    assert_eq!(out[0], data[0]);
    assert_eq!(out[1], parity[1]);
    assert_eq!(allocs, 0, "a warmed decode must reuse its elimination plan");
}

/// EC-5: read planning asks `decodable` for candidate subsets; a repeated question is answered from the plan cache.
#[test]
fn bitmatrix_decodable_reuses_its_plan() {
    let code = BitCodec::try_new(BitTech::BlaumRoth, 4, 2, 7, 8).unwrap();
    let have = [0, 1, 2, 3];
    assert!(code.decodable(&have));
    let (_, allocs, _) = measure(|| {
        for _ in 0..10 {
            assert!(code.decodable(black_box(&have)));
        }
    });
    assert_eq!(allocs, 0, "a repeated decodable() must reuse its plan");
}

fn clay_codec() -> ClayCodec {
    let p = ClayProfile::parse(&pm(&[
        ("plugin", "clay"),
        ("k", "4"),
        ("m", "2"),
        ("d", "5"),
    ]))
    .unwrap();
    let mut c = ClayCodec::new(&p).unwrap();
    c.set_chunk(16384);
    c
}

/// EC-6: `encode` runs once per stripe, so its work area must be reused across calls (a fresh `Work` per stripe
/// allocates 2*nodes*chunk + chunk/S bytes).
#[test]
fn clay_encode_scratch_is_reused() {
    let code = clay_codec();
    let len = 16384;
    let data: Vec<Vec<u8>> = (0..4).map(|i| pattern(len, i as u32 + 1)).collect();
    let mut parity = vec![vec![0u8; len]; 2];
    let d: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
    let mut p: Vec<&mut [u8]> = parity.iter_mut().map(Vec::as_mut_slice).collect();
    code.encode(&d, &mut p);
    let (_, allocs, _) = measure(|| {
        for _ in 0..10 {
            code.encode(black_box(&d), &mut p);
        }
    });
    assert_eq!(allocs, 0, "a warmed encode must reuse its work area");
    // the same for decode
    let have: Vec<(usize, &[u8])> = (0..3)
        .map(|i| (i, data[i].as_slice()))
        .chain([(4, parity[0].as_slice())])
        .collect();
    let want = [3, 5];
    let mut out = vec![vec![0u8; len]; 2];
    let mut o: Vec<&mut [u8]> = out.iter_mut().map(Vec::as_mut_slice).collect();
    code.decode_into(&have, &want, &mut o).unwrap();
    let (_, allocs, _) = measure(|| {
        for _ in 0..10 {
            code.decode_into(black_box(&have), &want, &mut o).unwrap();
        }
    });
    assert_eq!(out[0], data[3]);
    assert_eq!(out[1], parity[1]);
    assert_eq!(allocs, 0, "a warmed decode must reuse its work area");
}

/// EC-7: `encode_all` writes the layers into the caller's buffers; its scratch must not scale with the chunk size.
#[test]
fn lrc_encode_all_has_no_chunk_sized_scratch() {
    let code = LrcCodec::new(&LrcSpec::generate(4, 2, 3).unwrap(), "isa").unwrap();
    let run = |len: usize| {
        let data: Vec<Vec<u8>> = (0..code.k()).map(|i| pattern(len, i as u32 + 1)).collect();
        let mut out = vec![vec![0u8; len]; code.k() + code.m()];
        let d: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let mut o: Vec<&mut [u8]> = out.iter_mut().map(Vec::as_mut_slice).collect();
        code.encode_all(&d, &mut o);
        let (_, allocs, bytes) = measure(|| {
            let mut o: Vec<&mut [u8]> = out.iter_mut().map(Vec::as_mut_slice).collect();
            code.encode_all(black_box(&d), &mut o);
        });
        (allocs, bytes)
    };
    let (a16k, b16k) = run(16384);
    let (a1m, b1m) = run(1 << 20);
    assert_eq!(
        (a16k, b16k),
        (a1m, b1m),
        "encode_all scratch must not grow with the chunk size"
    );
}

/// EC-8: the placed (non-identity mapping) encode borrows its zero/parity work area instead of allocating a
/// chunk-sized buffer per call.
#[test]
fn placed_encode_has_no_chunk_sized_scratch() {
    let code = Code::from_profile(&pm(&[
        ("plugin", "isa"),
        ("k", "2"),
        ("m", "1"),
        ("mapping", "_DD"),
    ]))
    .unwrap()
    .placed(&[1, 2, 0])
    .unwrap();
    let run = |len: usize| {
        let data: Vec<Vec<u8>> = (0..code.k()).map(|i| pattern(len, i as u32 + 1)).collect();
        let mut parity = vec![vec![0u8; len]; code.m()];
        let d: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        {
            // warm up: the borrowed work area grows once per chunk size
            let mut p: Vec<&mut [u8]> = parity.iter_mut().map(Vec::as_mut_slice).collect();
            code.encode(&d, &mut p);
        }
        let (_, allocs, bytes) = measure(|| {
            let mut p: Vec<&mut [u8]> = parity.iter_mut().map(Vec::as_mut_slice).collect();
            code.encode(black_box(&d), &mut p);
        });
        (allocs, bytes)
    };
    let (a16k, b16k) = run(16384);
    let (a1m, b1m) = run(1 << 20);
    assert_eq!(
        (a16k, b16k),
        (a1m, b1m),
        "placed encode scratch must not grow with the chunk size"
    );
}

/// EC-9: a v3 ROLLBACK_EXTENTS keeps the per-extent shard sets inline; parsing must not allocate per extent.
#[test]
fn v3_extent_sets_parse_without_per_extent_allocation() {
    let extents: Vec<(u64, u64)> = (0..1000).map(|i| (i * 4096, 4096)).collect();
    let sets: Vec<[u64; 2]> = (0..1000).map(|i| [i as u64 + 1, i as u64]).collect();
    let mut b = ModDescBuilder::new();
    b.rollback_extents_v3(7, &extents, 1 << 20, &sets);
    let (bl, ..) = b.finish();
    let (ops, allocs, _) = measure(|| parse(&bl).unwrap());
    assert_eq!(ops.len(), 1);
    assert!(
        allocs <= 32,
        "parsing 1000 per-extent shard sets allocated {allocs} times (per-extent allocation is the regression)"
    );
}
