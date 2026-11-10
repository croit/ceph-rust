#![expect(clippy::type_complexity)]
// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Frozen known-answer vectors of the jerasure bit-matrix codes (standalone, no corpus). The expected FNV-1a hashes of
//! every parity chunk were generated once from an encoder that matched the upstream corpus byte for byte
//! (v0.92-988, all five techniques) and are frozen here.

use ec::Code;
use std::collections::BTreeMap;

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

fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf29ce484222325u64, |h, c| {
        (h ^ *c as u64).wrapping_mul(0x100000001b3)
    })
}

fn parity_hashes(kv: &[(&str, &str)]) -> Vec<u64> {
    let p: BTreeMap<String, String> = kv
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    let code = Code::from_profile(&p).unwrap();
    let (k, m) = (code.k(), code.m());
    let len = code.unit() * 2;
    let data: Vec<Vec<u8>> = (0..k).map(|i| pattern(len, i as u32 + 1)).collect();
    let mut par = vec![vec![0u8; len]; m];
    {
        let d: Vec<&[u8]> = data.iter().map(|v| &v[..]).collect();
        let mut o: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
        code.encode(&d, &mut o);
    }
    par.iter().map(|v| fnv(v)).collect()
}

#[test]
fn frozen_parity() {
    let cases: &[(&[(&str, &str)], &[u64])] = &[
        (
            &[
                ("plugin", "jerasure"),
                ("technique", "cauchy_orig"),
                ("k", "4"),
                ("m", "2"),
                ("packetsize", "32"),
            ],
            &[0x75956595bdcb3e, 0x98cd43aeea1c488a],
        ),
        (
            &[
                ("plugin", "jerasure"),
                ("technique", "cauchy_good"),
                ("k", "6"),
                ("m", "3"),
                ("packetsize", "32"),
            ],
            &[0xd32306a366131193, 0xa76af69814d20e44, 0xe264f11eeb4a7263],
        ),
        (
            &[
                ("plugin", "jerasure"),
                ("technique", "cauchy_good"),
                ("k", "4"),
                ("m", "2"),
                ("packetsize", "32"),
            ],
            &[0xd18a3ec7a69d8590, 0x2e448a5534e89746],
        ),
        (
            &[
                ("plugin", "jerasure"),
                ("technique", "liberation"),
                ("k", "5"),
                ("m", "2"),
                ("w", "7"),
                ("packetsize", "32"),
            ],
            &[0xdc62463cd0bf989, 0xf124638f4eb1135d],
        ),
        (
            &[
                ("plugin", "jerasure"),
                ("technique", "blaum_roth"),
                ("k", "5"),
                ("m", "2"),
                ("w", "6"),
                ("packetsize", "32"),
            ],
            &[0x6da375295c558b4, 0x5a763dd90120652e],
        ),
        (
            &[
                ("plugin", "jerasure"),
                ("technique", "liber8tion"),
                ("k", "8"),
                ("m", "2"),
                ("packetsize", "32"),
            ],
            &[0xb85f2bde02eda148, 0xffd6eaa82c32788d],
        ),
    ];
    for (kv, want) in cases {
        let got = parity_hashes(kv);
        assert_eq!(&got[..], *want, "{kv:?}");
    }
}
