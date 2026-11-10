// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use ec::gf::{Codec, Kind};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::time::Instant;

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
struct CountingAllocator;
// SAFETY: allocation and deallocation are delegated unchanged to the system allocator.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
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

#[test]
fn repeated_decode_has_no_setup_allocations() {
    let code = Codec::new(Kind::IsaVan, 2, 2);
    let data = [[7; 32], [11; 32]];
    let mut p = [[0; 32]; 2];
    let (p0, p1) = p.split_at_mut(1);
    code.encode(&[&data[0], &data[1]], &mut [&mut p0[0], &mut p1[0]]);
    let have = [(1, data[1].as_slice()), (2, p[0].as_slice())];
    let mut out = [0; 32];
    code.decode_into(&have, &[0], &mut [&mut out]).unwrap();
    ALLOCATIONS.set(0);
    TRACK.set(true);
    for _ in 0..10 {
        code.decode_into(black_box(&have), &[0], &mut [&mut out])
            .unwrap();
    }
    TRACK.set(false);
    assert_eq!(out, data[0]);
    assert_eq!(
        ALLOCATIONS.get(),
        0,
        "a warmed decode must reuse its matrix and tables"
    );
}

#[test]
fn ordered_keys_preserve_reconstruction_and_duplicate_outputs() {
    for kind in [Kind::IsaVan, Kind::IsaCauchy, Kind::JerVan] {
        let code = Codec::new(kind, 3, 2);
        let data = [[7; 37], [11; 37], [19; 37]];
        let mut p0 = [0; 37];
        let mut p1 = [0; 37];
        code.encode(&[&data[0], &data[1], &data[2]], &mut [&mut p0, &mut p1]);
        for have in [
            [
                (2, data[2].as_slice()),
                (3, p0.as_slice()),
                (4, p1.as_slice()),
            ],
            [
                (4, p1.as_slice()),
                (2, data[2].as_slice()),
                (3, p0.as_slice()),
            ],
        ] {
            let mut a = [0; 37];
            let mut b = [0; 37];
            let mut c = [0; 37];
            for _ in 0..2 {
                code.decode_into(&have, &[1, 0, 1], &mut [&mut a, &mut b, &mut c])
                    .unwrap();
                assert_eq!(a, data[1]);
                assert_eq!(b, data[0]);
                assert_eq!(c, data[1]);
            }
        }
    }
}

#[test]
#[ignore = "local decode setup and region benchmark"]
fn perf_repeated_decode() {
    for len in [32, 4096] {
        let code = Codec::new(Kind::IsaVan, 8, 3);
        let data: Vec<Vec<u8>> = (0..8)
            .map(|i| (0..len).map(|j| (i * 17 + j) as u8).collect())
            .collect();
        let mut parity = vec![vec![0; len]; 3];
        code.encode(
            &data.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            &mut parity.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
        );
        let have: Vec<_> = (1..8)
            .map(|i| (i, data[i].as_slice()))
            .chain([(8, parity[0].as_slice())])
            .collect();
        let mut output = vec![0; len];
        code.decode_into(&have, &[0], &mut [&mut output]).unwrap();
        let n = 50_000;
        let start = Instant::now();
        for _ in 0..n {
            code.decode_into(
                black_box(&have),
                black_box(&[0]),
                &mut [black_box(&mut output)],
            )
            .unwrap();
        }
        let elapsed = start.elapsed().as_nanos();
        assert_eq!(output, data[0]);
        println!(
            "k=8 m=3 len={len} stable-pattern ns_per_decode={}",
            elapsed / n
        );
    }
}
