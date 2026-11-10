// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! clay plugin known answers (spec ec-clay.md 8). `frozen_chunks`: FNV-1a of every chunk of a 3-stripe pattern
//! object per profile, frozen from our encoder after it matched shards written by a live classic cluster byte for
//! byte (crates/ec/tests/oracle/clay-oracle.sh: v21.1.1 for the first 17 profiles, v21.2.0 for all 21 below incl. the
//! sub-chunk-32 / 160 shapes that 21.1.x got wrong). Stands alone.
//! `oracle` (TEMPORARY dev-time parity oracle): `EC_CLAY_ORACLE=<dir from clay-oracle.sh>` compares our encode with
//! the classic shards, decodes every <= m erasure pattern of the classic shards and repairs every chunk from their
//! sub-chunks.

use ec::Code;
use ec::clay::{ClayCodec, ClayProfile};
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

fn profile(k: &str, m: &str, d: &str, sc: &str, tech: &str) -> BTreeMap<String, String> {
    let mut p = BTreeMap::new();
    p.insert("plugin".to_string(), "clay".to_string());
    p.insert("k".into(), k.into());
    p.insert("m".into(), m.into());
    for (key, v) in [("d", d), ("scalar_mds", sc), ("technique", tech)] {
        if !v.is_empty() && v != "-" {
            p.insert(key.into(), v.into());
        }
    }
    p
}

/// Every chunk (k data then m parity) of `data` (a multiple of k*chunk) encoded per stripe.
fn encode_all(code: &Code, chunk: usize, data: &[u8]) -> Vec<Vec<u8>> {
    let (k, m) = (code.k(), code.m());
    let ns = data.len() / (k * chunk);
    let mut out = vec![Vec::new(); k + m];
    let mut par = vec![vec![0u8; chunk]; m];
    for s in 0..ns {
        let st = &data[s * k * chunk..(s + 1) * k * chunk];
        let d: Vec<&[u8]> = (0..k).map(|i| &st[i * chunk..(i + 1) * chunk]).collect();
        {
            let mut p: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
            code.encode(&d, &mut p);
        }
        for (i, c) in d.iter().enumerate() {
            out[i].extend_from_slice(c);
        }
        for (j, p) in par.iter().enumerate() {
            out[k + j].extend_from_slice(p);
        }
    }
    out
}

// (k, m, d, scalar_mds, technique, chunk size)
const CASES: &[(&str, &str, &str, &str, &str, usize)] = &[
    ("2", "2", "3", "", "", 4096),
    ("2", "2", "", "", "", 4096),
    ("2", "2", "3", "isa", "", 4096),
    ("3", "2", "4", "", "", 4096),
    ("4", "3", "5", "", "", 4096),
    ("4", "2", "5", "isa", "", 4096),
    ("5", "2", "6", "", "", 4096),
    ("3", "3", "4", "isa", "cauchy", 4096),
    ("3", "2", "4", "jerasure", "reed_sol_r6_op", 4096),
    ("4", "3", "6", "", "", 6912),
    ("5", "3", "7", "", "", 6912),
    ("6", "3", "8", "", "", 6912),
    ("8", "3", "10", "", "", 5184),
    ("8", "4", "11", "", "", 4096),
    ("5", "4", "6", "", "", 4096),
    // scalar shec with m == 2 (= reed_sol_van rows), verified against classic v21.1.1 (clay-oracle.sh)
    ("4", "2", "5", "shec", "", 4096),
    ("3", "2", "4", "shec", "multiple", 4096),
    // sub-chunks below the 64 B SIMD alignment (32 B) and a sub-chunk that is no multiple of 64 (160 B), verified
    // against classic v21.2.0, which fixed the in-place sub-chunk decode (21.1.x produced wrong output here: never
    // freeze 21.1.x for these shapes)
    ("12", "4", "15", "", "", 8192),
    ("10", "4", "13", "", "", 8192),
    ("12", "4", "15", "isa", "", 8192),
    ("6", "3", "8", "", "", 4320),
];

const FROZEN: &[&[u64]] = &[
    &[
        0x21ef2370fe73ee00,
        0x3dea1aee041a256f,
        0x3f95e3593030362c,
        0x8e49bf8fbbb2f892,
    ],
    &[
        0xe46a0470c3d6019f,
        0x4a313b4bdc16ee8b,
        0xc838259acebffe6a,
        0xb148722318a21753,
    ],
    &[
        0x6a25f13568b5656a,
        0x7e1a702327a931a3,
        0x70f7269bb7e5a0db,
        0xb25faa8ae3287bd5,
    ],
    &[
        0x8a34dd8e84e8e02c,
        0xb1919224cc31d450,
        0xd03d9ba743643bf1,
        0x2e310393de01af7f,
        0x233b1b28f9c2e402,
    ],
    &[
        0xfa5e6dcc2a6b14b4,
        0xe7ec5f0ee92ddcbb,
        0x9f2e2108dd2eb839,
        0x369293ea327eebd5,
        0x1893141b3390a4ad,
        0x5b3a6ac54d84ecc2,
        0xd9afe08391ffa7d7,
    ],
    &[
        0x8ecb8f8360507943,
        0x79e818b3d1b3000f,
        0x5e23a191cef55b16,
        0x1d3794cb2a391cd1,
        0xfc5e6e1181bc8c40,
        0x1013a49248ca2c0f,
    ],
    &[
        0xdecbffb2660dee70,
        0xfe68d5b0f0d69bb4,
        0xff3afad181dd577e,
        0xe8579256c99e3edb,
        0x92d4e5c8c39d94a,
        0xfeb3f20ba42b3fa9,
        0x177a87f912488da7,
    ],
    &[
        0xc459604e671e5aec,
        0xa02fd40b13d6f152,
        0xbea2b8a22d53f811,
        0x504bb2895daa4d1b,
        0x551be1cc47b9652c,
        0x1770d735a53b633d,
    ],
    &[
        0x99ec00be864c6466,
        0x5d8513d17b9dc6c7,
        0x2ce1a6d7ecf957c5,
        0x84fc8c7b8fda2987,
        0xfbef5a87ef8be294,
    ],
    &[
        0xd037a65d3dab1d03,
        0xa88b53044dddd8ea,
        0x58a80dcc6b403b,
        0x885d357f735df7e8,
        0xb4c11084fd24777f,
        0xb7837cc57eecb56a,
        0xf267c6aa076b21fa,
    ],
    &[
        0x3d355a4dc2bdc346,
        0x5db3f4e6fdd1baa8,
        0xaeedee5a03c51f01,
        0x12f66a7bf7714845,
        0x2b61e3e15e381906,
        0x3885c79331e48ef,
        0xeb05e52f1849d78f,
        0xa6afcfc5b286b05c,
    ],
    &[
        0xfe886194475279a0,
        0xaccefba0bc75a50a,
        0x81e1be2f79e9a540,
        0x90b15e7f05f36448,
        0x2536e9f5d5f66e38,
        0x8f9d360d751fec4a,
        0xb9013ca8b822e11c,
        0x2f9ddc086e635ec1,
        0x344469f5a2562849,
    ],
    &[
        0x8064e9000bb22e0d,
        0x2952fe420a895e85,
        0x43719745222dae70,
        0xeed8ffa600cc29da,
        0x25c4d08abbe1f9fe,
        0x6fd884ad95aff598,
        0xdd155b8823de5a4f,
        0xf45226897c51d112,
        0x685860452d2146a7,
        0xd336f222793cae4f,
        0xb6872144c2315572,
    ],
    &[
        0x908b45e1abdbde7e,
        0xed4dbfae8fbc5e5f,
        0xfa86ed14e29b5ba9,
        0x1ba53b29e9931132,
        0xf9282bf1a3bd43bb,
        0x2f7f0d83586565cd,
        0xc88138020d5003c7,
        0xb0c0a89e3789c379,
        0xfd1181dac8762185,
        0xb280558eb13da040,
        0x375f05516d3c0a27,
        0xc2bbd144fd7def82,
    ],
    &[
        0xd31c157f651d1fca,
        0x87b7186c232bb312,
        0xb64f5a9c7d2d7dd5,
        0x6d7ea67beb8e7a1f,
        0x9b324d1863138e4e,
        0xabd331f7589754d,
        0x5419fb943e8075b5,
        0xb3107ecdee3e3ff3,
        0xe3495d14a1c8eeb5,
    ],
    &[
        0xdec9a152db0ed5b9,
        0x538fd7c0fe9a4e1f,
        0x3ef67b5501b0ecf1,
        0xa6f2f56a1ea22873,
        0xf78fba93c4629774,
        0xaa69d406f9115022,
    ],
    &[
        0x72d7f04c8a77bfb7,
        0x53d8c91c57c5e25d,
        0x4cc966bd2bae629a,
        0x1a737c343730644f,
        0x2841954b2e1b5b0f,
    ],
    &[
        0xe9f3d81b9dc0592a,
        0xceae638beeada1f3,
        0x9dd914e0ae52aaac,
        0x7708b704d8ec58c7,
        0x1309f6ce07e1b8f,
        0x3f4d3012ede9fe09,
        0xba5ce3109c958d34,
        0x531bda727174fe0b,
        0x64be7b7ff9cd822a,
        0xbd9a0c7e4df9706,
        0xef958c8ccd3ee6fb,
        0x7f1803ffa0a007b6,
        0xbe1e9309ce5b6e95,
        0xe1ad694ecc6b828a,
        0xeeb19070b5a75855,
        0x9603cf6567c0867a,
    ],
    &[
        0xef8c70c64e3a4c32,
        0x98b6168b30ec1108,
        0x27bc6d0db92fb5a1,
        0x3251176d746c5c70,
        0x9becf1d990e6a2cb,
        0x9cc1904811290bd1,
        0xb3148460ce35b597,
        0x3eb0a14245b91c5b,
        0x448e822af4edae5c,
        0xe207ed49a0f45c42,
        0x13be2ebddafa6950,
        0x7584ba9d73265be0,
        0x5ff4254c0de6ca3f,
        0x5c76a88f6fba50f1,
    ],
    &[
        0x8f5aa629369ea308,
        0x2eab9f49678bcd9d,
        0xb9cc8f7d26407b79,
        0x81c083df258acb01,
        0xcea95b284b43901b,
        0x9d15f267a01de996,
        0x13ef7efc2d972d43,
        0x4ba24aaacfddbde9,
        0x3097ac882e5bc29f,
        0x81a7e15424427b2a,
        0x81692cf78e22a996,
        0x59591f5bca25522a,
        0x80d8823ab1bb1874,
        0xc351b91cb15c4716,
        0x91b27eea4d459031,
        0xf5dcd0e6549c8904,
    ],
    &[
        0xe26748ab466ef688,
        0x7c43e2e9c7170c7a,
        0xd90e37acf2e54bbd,
        0x79c702bce6dc9189,
        0x8f6028f1e4244057,
        0x95005fd34a73a93e,
        0xa9024d4e7b456e75,
        0xdf6eb2b98f37e6bb,
        0x9d1fbfb12e491ec,
    ],
];

#[test]
fn frozen_chunks() {
    let print = std::env::var("EC_CLAY_FREEZE").is_ok();
    for (i, &(k, m, d, sc, t, chunk)) in CASES.iter().enumerate() {
        let mut code = Code::from_profile(&profile(k, m, d, sc, t)).unwrap();
        code.set_chunk(chunk);
        let data = pattern(3 * code.k() * chunk, i as u32 + 1);
        let got: Vec<u64> = encode_all(&code, chunk, &data)
            .iter()
            .map(|c| fnv(c))
            .collect();
        if print {
            println!("    &{got:#x?},");
            continue;
        }
        assert_eq!(got, FROZEN[i], "clay {k} {m} {d} {sc} {t}");
    }
}

#[test]
#[ignore = "needs EC_CLAY_ORACLE: run via crates/ec/tests/oracle/clay-oracle.sh"]
fn oracle() {
    let root = std::env::var("EC_CLAY_ORACLE").expect("EC_CLAY_ORACLE=<dir from clay-oracle.sh>");
    let mut dirs: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.join("meta").exists())
        .collect();
    dirs.sort();
    assert!(!dirs.is_empty(), "no profiles in {root}");
    for dir in dirs {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let meta = std::fs::read_to_string(dir.join("meta")).unwrap();
        let f: Vec<&str> = meta.split_whitespace().collect();
        let (k, m) = (f[0], f[1]);
        let p = profile(k, m, f[2], f[3], f[4]);
        let (sw, size): (usize, usize) = (f[6].parse().unwrap(), f[7].parse().unwrap());
        let k: usize = k.parse().unwrap();
        let m: usize = m.parse().unwrap();
        let chunk = sw / k;
        let cp = ClayProfile::parse(&p).unwrap();
        assert_eq!(cp.chunk_size(sw), chunk, "{name}: get_chunk_size");
        let mut code = Code::from_profile(&p).unwrap();
        code.set_chunk(chunk);
        let mut data = std::fs::read(dir.join("obj")).unwrap();
        assert_eq!(data.len(), size);
        data.resize(size.div_ceil(sw) * sw, 0);
        let ours = encode_all(&code, chunk, &data);
        let classic: Vec<Vec<u8>> = (0..k + m)
            .map(|s| std::fs::read(dir.join(format!("shard{s}"))).unwrap())
            .collect();
        for s in 0..k + m {
            assert!(
                ours[s] == classic[s],
                "{name}: shard {s} differs from classic"
            );
        }
        // decode of classic shards: every <= m erasure pattern (sampled when large)
        let n = k + m;
        let mut cnt = 0;
        for mask in 0u32..1 << n {
            let lost = mask.count_ones() as usize;
            if lost == 0 || lost > m || (n > 9 && mask % 7 != 0) {
                continue;
            }
            let have: Vec<(usize, &[u8])> = (0..n)
                .filter(|r| mask >> r & 1 == 0)
                .map(|r| (r, &classic[r][..]))
                .collect();
            let want: Vec<usize> = (0..n).filter(|r| mask >> r & 1 == 1).collect();
            let mut out = vec![vec![0u8; classic[0].len()]; want.len()];
            {
                let mut o: Vec<&mut [u8]> = out.iter_mut().map(|v| &mut v[..]).collect();
                code.decode_into(&have, &want, &mut o).unwrap();
            }
            for (w, o) in want.iter().zip(&out) {
                assert!(*o == classic[*w], "{name}: decode {w} lost {want:?}");
            }
            cnt += 1;
        }
        // repair of every chunk from the classic helpers' repair sub-chunks
        let mut cc = ClayCodec::new(&cp).unwrap();
        cc.set_chunk(chunk);
        let sc = chunk / cp.s;
        for lost in 0..n {
            let avail: Vec<usize> = (0..n).filter(|r| *r != lost).collect();
            let h = cc.minimum_to_repair(lost, &avail).unwrap();
            let ranges = cc.repair_subchunks(lost);
            let bufs: Vec<Vec<u8>> = h
                .iter()
                .map(|r| {
                    let mut v = Vec::new();
                    for st in (0..classic[*r].len()).step_by(chunk) {
                        for (f, c) in &ranges {
                            v.extend_from_slice(&classic[*r][st + f * sc..st + (f + c) * sc]);
                        }
                    }
                    v
                })
                .collect();
            let hv: Vec<(usize, &[u8])> =
                h.iter().copied().zip(bufs.iter().map(|b| &b[..])).collect();
            let mut out = vec![0u8; classic[lost].len()];
            cc.repair(lost, &hv, &mut out).unwrap();
            assert!(out == classic[lost], "{name}: repair {lost}");
        }
        eprintln!(
            "{name}: {} shards identical, {cnt} decode patterns, {n} repairs ok",
            n
        );
    }
}
