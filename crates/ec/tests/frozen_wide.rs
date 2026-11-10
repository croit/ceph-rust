#![expect(clippy::type_complexity)]
// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! jerasure reed_sol_van / r6_op at w=16 and w=32 (spec ec-jerasure-bitmatrix.md 7). Expected FNV-1a hashes of the
//! parity chunks (stripe_unit 4096, input `pattern`) were taken once from classic jerasure (ceph v21.1.1
//! ceph-erasure-code-tool, tests/oracle/wide-oracle.sh) and are frozen; the oracle comparison is optional.

use ec::Code;
use std::collections::BTreeMap;

const CHUNK: usize = 4096;

fn pattern(n: usize) -> Vec<u8> {
    let mut x = 0x9E3779B9u32;
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

/// (name, technique, k, m, w, parity hashes)
const CASES: &[(&str, &str, usize, usize, u32, &[u64])] = &[
    (
        "v16_4_2",
        "reed_sol_van",
        4,
        2,
        16,
        &[0x843a7dcf288ff6a7, 0x88d9acff0a11f69d],
    ),
    ("v16_2_1", "reed_sol_van", 2, 1, 16, &[0xe3bc5de493f779e5]),
    (
        "v16_8_3",
        "reed_sol_van",
        8,
        3,
        16,
        &[0x61d628599f6bb094, 0x48da53a54437481d, 0x6a38416fec03e896],
    ),
    (
        "v16_10_4",
        "reed_sol_van",
        10,
        4,
        16,
        &[
            0x85c9b519f4770db6,
            0x86b2375b6a71ccf1,
            0x9dbdf07c0b020c8e,
            0x82c4d589f4752e30,
        ],
    ),
    (
        "v32_4_2",
        "reed_sol_van",
        4,
        2,
        32,
        &[0x843a7dcf288ff6a7, 0xe95cb78e056bdfd2],
    ),
    (
        "v32_3_3",
        "reed_sol_van",
        3,
        3,
        32,
        &[0xc1bd5640ee7b86fd, 0x2326b9817e795be9, 0xe9ab51f43c7231f7],
    ),
    (
        "v32_8_4",
        "reed_sol_van",
        8,
        4,
        32,
        &[
            0x61d628599f6bb094,
            0xcdad7c901b3b27f8,
            0x7a88c68bfd886364,
            0x86af1bee7da09277,
        ],
    ),
    (
        "r16_5_2",
        "reed_sol_r6_op",
        5,
        2,
        16,
        &[0x47487010a9d953c3, 0xd963d21f0603c851],
    ),
    (
        "r16_2_2",
        "reed_sol_r6_op",
        2,
        2,
        16,
        &[0xe3bc5de493f779e5, 0x279a13be57f091dc],
    ),
    (
        "r32_6_2",
        "reed_sol_r6_op",
        6,
        2,
        32,
        &[0x44fb0667354ce6b9, 0xe2bc004a3ff56dfd],
    ),
    (
        "r32_3_2",
        "reed_sol_r6_op",
        3,
        2,
        32,
        &[0xc1bd5640ee7b86fd, 0xef4e66ea2a26f90e],
    ),
];

fn code(t: &str, k: usize, m: usize, w: u32) -> Code {
    let p: BTreeMap<String, String> = [
        ("plugin", "jerasure".to_string()),
        ("technique", t.to_string()),
        ("k", k.to_string()),
        ("m", m.to_string()),
        ("w", w.to_string()),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_string(), b))
    .collect();
    Code::from_profile(&p).unwrap()
}

fn encode(c: &Code, input: &[u8]) -> Vec<Vec<u8>> {
    let (k, m) = (c.k(), c.m());
    let data: Vec<&[u8]> = (0..k).map(|i| &input[i * CHUNK..(i + 1) * CHUNK]).collect();
    let mut par = vec![vec![0u8; CHUNK]; m];
    let mut o: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
    c.encode(&data, &mut o);
    par
}

#[test]
#[ignore]
fn emit() {
    let d = std::env::var("EC_WIDE_DIR").unwrap();
    std::fs::write(format!("{d}/in.bin"), pattern(16 * CHUNK)).unwrap();
}

/// Compare with the classic chunks; prints the table rows (use to refresh the frozen hashes).
#[test]
#[ignore = "needs EC_WIDE_ORACLE: run via crates/ec/tests/oracle/wide-oracle.sh"]
fn oracle() {
    let d = std::env::var("EC_WIDE_ORACLE").expect("EC_WIDE_ORACLE=<dir from wide-oracle.sh>");
    for (name, t, k, m, w, _) in CASES {
        let c = code(t, *k, *m, *w);
        let par = encode(&c, &pattern(16 * CHUNK)[..k * CHUNK]);
        let mut hs = vec![];
        for (r, p) in par.iter().enumerate() {
            let want = std::fs::read(format!("{d}/{name}.{}", k + r)).unwrap();
            assert_eq!(&want, p, "{name} parity {r}");
            hs.push(format!("{:#x}", fnv(p)));
        }
        for i in 0..*k {
            let want = std::fs::read(format!("{d}/{name}.{i}")).unwrap();
            assert_eq!(
                want,
                pattern(16 * CHUNK)[i * CHUNK..(i + 1) * CHUNK],
                "{name} data {i}"
            );
        }
        println!(
            "    (\"{name}\", \"{t}\", {k}, {m}, {w}, &[{}]),",
            hs.join(", ")
        );
    }
}

#[test]
fn frozen_parity() {
    for (name, t, k, m, w, h) in CASES {
        let c = code(t, *k, *m, *w);
        assert_eq!(c.unit(), (*w / 8) as usize);
        let par = encode(&c, &pattern(16 * CHUNK)[..k * CHUNK]);
        let got: Vec<u64> = par.iter().map(|p| fnv(p)).collect();
        assert_eq!(&got[..], *h, "{name}");
    }
}

#[test]
fn every_erasure_pattern_decodes() {
    for (name, t, k, m, w, _) in CASES {
        let c = code(t, *k, *m, *w);
        let n = k + m;
        let input = pattern(16 * CHUNK);
        let mut chunks: Vec<Vec<u8>> = (0..*k)
            .map(|i| input[i * CHUNK..(i + 1) * CHUNK].to_vec())
            .collect();
        chunks.extend(encode(&c, &input[..k * CHUNK]));
        // all lost-sets of size m (bitmask over n <= 14)
        for mask in 0u32..(1 << n) {
            if mask.count_ones() as usize != *m {
                continue;
            }
            let lost: Vec<usize> = (0..n).filter(|i| mask >> i & 1 == 1).collect();
            let avail: Vec<usize> = (0..n).filter(|i| mask >> i & 1 == 0).collect();
            let set = c.read_set(&lost, &avail).unwrap();
            let have: Vec<(usize, &[u8])> = set.iter().map(|&r| (r, &chunks[r][..])).collect();
            let mut out = vec![vec![0u8; CHUNK]; lost.len()];
            let mut o: Vec<&mut [u8]> = out.iter_mut().map(|v| &mut v[..]).collect();
            c.decode_into(&have, &lost, &mut o).unwrap();
            for (i, &l) in lost.iter().enumerate() {
                assert_eq!(out[i], chunks[l], "{name} lost {lost:?}");
            }
        }
    }
}
