// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Frozen known-answer vectors of the lrc plugin (standalone, no corpus). The FNV-1a hashes of every chunk (RAW order:
//! data chunks, then the other positions by ascending position) were generated once from an encoder that matched the
//! upstream corpus byte for byte (v0.92-988, all 18 lrc dirs, jerasure layers) and are frozen here. Default layers =
//! isa (Ceph main); the jerasure vector pins the pre-2024 corpus data.

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

fn hashes(kv: &[(&str, &str)]) -> Vec<u64> {
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
    data.iter().chain(&par).map(|v| fnv(v)).collect()
}

const L3: &str = "[[\"DDc_DDc_\",\"plugin=jerasure technique=reed_sol_van\"],[\"DDDc____\",\"\"],[\"____DDDc\",\"\"]]";
const L9: &str = "[[\"DDDc_DDc_\",\"\"],[\"DDDDc____\",\"\"],[\"_____DDDc\",\"\"]]";

#[test]
#[expect(clippy::type_complexity)]
fn frozen_lrc() {
    let cases: &[(&[(&str, &str)], &[u64])] = &[
        (
            &[("plugin", "lrc"), ("k", "4"), ("m", "2"), ("l", "3")],
            &[
                0x9b52d69f2e5e7965,
                0xc463b82d5fb75886,
                0x4417593c31693737,
                0x86d41d77df88c2b0,
                0x621121e6748f6741,
                0xc64dde50b83d5c86,
                0x1ea5fc12d2e7546b,
                0xbc22a04c3f5097ec,
            ],
        ),
        (
            &[("plugin", "lrc"), ("k", "8"), ("m", "4"), ("l", "3")],
            &[
                0x9b52d69f2e5e7965,
                0xc463b82d5fb75886,
                0x4417593c31693737,
                0x86d41d77df88c2b0,
                0x572ef2c88afb0cb8,
                0x642823fd11ddd89,
                0xd5ef07ae55471d1e,
                0x1ba14c23d029fdb8,
                0xcda5133f79067252,
                0x168bdf7c457c3f25,
                0xaabf32a2dd1a4617,
                0x13d3ce9e54437458,
                0x15bbd13267380a85,
                0xc625140a76ae10f8,
                0xd5a78f92fcbcabd1,
                0xbd4a6bbae760286f,
            ],
        ),
        (
            &[("plugin", "lrc"), ("mapping", "DDD__DD__"), ("layers", L9)],
            &[
                0x9b52d69f2e5e7965,
                0xc463b82d5fb75886,
                0x4417593c31693737,
                0x86d41d77df88c2b0,
                0x572ef2c88afb0cb8,
                0xb22ff83457e0324c,
                0xc7fdde87e7540e15,
                0xfb2d49d7da5206a,
                0x4d1c7d8a41cbe9ee,
            ],
        ),
        (
            &[("plugin", "lrc"), ("mapping", "DD__DD__"), ("layers", L3)],
            &[
                0x9b52d69f2e5e7965,
                0xc463b82d5fb75886,
                0x4417593c31693737,
                0x86d41d77df88c2b0,
                0x621121e6748f6741,
                0xc64dde50b83d5c86,
                0x157318f79dbb018d,
                0x349f0967c16fb8fa,
            ],
        ),
    ];
    for (kv, want) in cases {
        let got = hashes(kv);
        assert_eq!(&got[..], *want, "{kv:?}");
    }
}
