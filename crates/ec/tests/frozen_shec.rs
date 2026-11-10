// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Frozen known-answer vectors of the shec plugin (standalone, no corpus). The FNV-1a hashes of every parity chunk
//! were generated once from an encoder that matched the upstream corpus byte for byte (v0.92-988, all 114 shec
//! entries, technique multiple); the technique single vectors share that code path (only the row split differs).

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
    let len = 96;
    let data: Vec<Vec<u8>> = (0..k).map(|i| pattern(len, i as u32 + 1)).collect();
    let mut par = vec![vec![0u8; len]; m];
    {
        let d: Vec<&[u8]> = data.iter().map(|v| &v[..]).collect();
        let mut o: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
        code.encode(&d, &mut o);
    }
    par.iter().map(|v| fnv(v)).collect()
}

const CASES: &[(&str, &str, &str, &str)] = &[
    ("multiple", "4", "3", "2"),
    ("single", "4", "3", "2"),
    ("multiple", "6", "4", "3"),
    ("single", "6", "4", "3"),
    ("multiple", "5", "2", "1"),
    ("single", "5", "2", "1"),
    ("multiple", "8", "4", "3"),
    ("multiple", "12", "7", "4"),
    ("single", "3", "2", "2"),
];

#[test]
fn frozen_parity() {
    let want: &[&[u64]] = &[
        &[0xc123a27de10dbb91, 0x359b4e4f2c1636d2, 0xf02c1fd99f5d0a56],
        &[0x9736a762fbaa52f6, 0x58d3c2342f5d3ca5, 0xdd108a3087af34e7],
        &[
            0xa0934cabd9c7f67b,
            0x808e3177a1cc1d13,
            0x5f3469dd645040c9,
            0x776a6067d778f953,
        ],
        &[
            0xc123a27de10dbb91,
            0x1c1b8e72876fe469,
            0xfbc91bbf66edd3d4,
            0x308751fda42e246e,
        ],
        &[0x9736a762fbaa52f6, 0x48d009b5daacab57],
        &[0x9736a762fbaa52f6, 0x48d009b5daacab57],
        &[
            0xc123a27de10dbb91,
            0x9775b8fea487a863,
            0x58b1fdc5ab6784a2,
            0x229cda2473fd4009,
        ],
        &[
            0xa0934cabd9c7f67b,
            0xa7d6d096df184cd3,
            0x2f6ea9f8ea7858cf,
            0xffb85ce6d1c26273,
            0x359a131df25e3909,
            0x653c0f2e2c47ba58,
            0xa16c82d1b67c3421,
        ],
        &[0xa0934cabd9c7f67b, 0xd3be7592ceb14ecd],
    ];
    for (i, (t, k, m, c)) in CASES.iter().enumerate() {
        let got = parity_hashes(&[
            ("plugin", "shec"),
            ("technique", t),
            ("k", k),
            ("m", m),
            ("c", c),
        ]);
        assert_eq!(got, want[i], "{t} {k} {m} {c}");
    }
}
