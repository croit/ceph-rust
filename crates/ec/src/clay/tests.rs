// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::*;
use crate::gf::mul;

fn pm(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
    kv.iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

fn prof(k: usize, m: usize, d: usize, scalar: &str, tech: &str) -> ClayProfile {
    let (k, m, d) = (k.to_string(), m.to_string(), d.to_string());
    let mut v = vec![
        ("plugin", "clay"),
        ("k", &k[..]),
        ("m", &m[..]),
        ("d", &d[..]),
    ];
    if !scalar.is_empty() {
        v.push(("scalar_mds", scalar));
    }
    if !tech.is_empty() {
        v.push(("technique", tech));
    }
    ClayProfile::parse(&pm(&v)).unwrap()
}

fn codec(k: usize, m: usize, d: usize, scalar: &str, tech: &str) -> ClayCodec {
    ClayCodec::new(&prof(k, m, d, scalar, tech)).unwrap()
}

fn rnd(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// All k+m chunks of random data (one stripe of `cs` bytes).
fn chunks(c: &ClayCodec, cs: usize, seed: u64) -> Vec<Vec<u8>> {
    let (k, m) = (c.k(), c.m());
    let mut all: Vec<Vec<u8>> = (0..k).map(|i| rnd(cs, seed + i as u64)).collect();
    let mut par = vec![vec![0u8; cs]; m];
    {
        let d: Vec<&[u8]> = all.iter().map(|v| &v[..]).collect();
        let mut p: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
        c.encode(&d, &mut p);
    }
    all.extend(par);
    all
}

#[test]
fn parse_rules() {
    let p = ClayProfile::parse(&pm(&[("plugin", "clay")])).unwrap();
    assert_eq!((p.k, p.m, p.d, p.q, p.t, p.nu, p.s), (4, 2, 5, 2, 3, 0, 8));
    assert_eq!(
        (p.scalar.as_str(), p.technique.as_str()),
        ("jerasure", "reed_sol_van")
    );
    let p = ClayProfile::parse(&pm(&[
        ("k", ""),
        ("m", ""),
        ("d", ""),
        ("scalar_mds", "shec"),
    ]))
    .unwrap();
    assert_eq!((p.k, p.technique.as_str()), (4, "single"));
    for bad in [
        &[("k", "1")][..],
        &[("m", "1")],
        &[("d", "4")],
        &[("d", "6")],
        &[("k", "4 ")],
        &[("k", "-4")],
        &[("scalar_mds", "lrc")],
        &[("technique", "cauchy")],
        &[("scalar_mds", "isa"), ("technique", "liber8tion")],
        &[("m", "3"), ("technique", "reed_sol_r6_op"), ("d", "5")],
        &[("k", "2"), ("m", "4"), ("d", "4"), ("scalar_mds", "shec")],
        &[("k", "100"), ("m", "27"), ("d", "126")],
    ] {
        assert!(ClayProfile::parse(&pm(bad)).is_err(), "{bad:?}");
    }
    ClayProfile::parse(&pm(&[("k", "4"), ("m", "3"), ("scalar_mds", "shec")])).unwrap();
    // classic int grammar (spec ec-parity.md 1.1)
    let p = ClayProfile::parse(&pm(&[("k", "+04"), ("m", " 2"), ("d", "")])).unwrap();
    assert_eq!((p.k, p.m, p.d), (4, 2, 5));
}

/// Spec 2 table at su=4096 and the live get_chunk_size values.
#[test]
#[expect(clippy::type_complexity)]
fn chunk_size_table() {
    let rows: &[(
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
    )] = &[
        // k m d q t nu S C aloof
        (2, 2, 3, 2, 2, 0, 4, 4096, 0),
        (3, 2, 4, 2, 3, 1, 8, 4096, 0),
        (4, 2, 5, 2, 3, 0, 8, 4096, 0),
        (6, 2, 7, 2, 4, 0, 16, 4096, 0),
        (8, 2, 9, 2, 5, 0, 32, 4096, 0),
        (3, 3, 5, 3, 2, 0, 9, 4320, 0),
        (4, 3, 5, 2, 4, 1, 16, 4096, 1),
        (4, 3, 6, 3, 3, 2, 27, 4320, 0),
        (5, 3, 7, 3, 3, 1, 27, 4320, 0),
        (6, 3, 8, 3, 3, 0, 27, 4320, 0),
        (8, 3, 9, 2, 6, 1, 64, 4096, 1),
        (8, 3, 10, 3, 4, 1, 81, 5184, 0),
        (4, 4, 7, 4, 2, 0, 16, 4096, 0),
        (5, 4, 6, 2, 5, 1, 32, 4096, 2),
        (8, 4, 11, 4, 3, 0, 64, 4096, 0),
        (10, 4, 13, 4, 4, 2, 256, 8192, 0),
        (12, 4, 15, 4, 4, 0, 256, 8192, 0),
        (2, 4, 4, 3, 2, 0, 9, 4320, 1),
    ];
    for &(k, m, d, q, t, nu, s, c, aloof) in rows {
        let p = prof(k, m, d, "", "");
        assert_eq!((p.q, p.t, p.nu, p.s), (q, t, nu, s), "{k},{m},{d}");
        assert_eq!(p.chunk_size(k * 4096), c, "{k},{m},{d}");
        assert_eq!(m - q, aloof);
        // sc % 64 == 32 profiles (classic <= 21.1.x parity bug 0.2, fixed in 21.2.0) are primary-capable too
        assert!(p.primary_capable(c), "{k},{m},{d}");
        assert!(!p.primary_capable(c + 1), "{k},{m},{d}");
    }
    let live: &[(usize, usize, usize, &str, &str, usize, usize)] = &[
        (2, 2, 3, "", "", 8192, 4096),
        (4, 2, 5, "", "", 16384, 4096),
        (5, 3, 7, "", "", 20480, 4320),
        (10, 4, 13, "", "", 40960, 8192),
        (12, 4, 15, "", "", 49152, 8192),
        (8, 3, 10, "", "", 32768, 5184),
        (4, 2, 5, "isa", "", 16384, 4096),
        (4, 2, 5, "shec", "", 16384, 4096),
        (4, 2, 5, "jerasure", "cauchy_good", 16384, 524288),
        (4, 2, 5, "", "", 1, 256),
    ];
    for &(k, m, d, sc, t, w, c) in live {
        assert_eq!(
            prof(k, m, d, sc, t).chunk_size(w),
            c,
            "{k},{m},{d} {sc} {t}"
        );
    }
    assert!(ClayCodec::new(&prof(4, 2, 5, "shec", "")).is_some());
    assert!(ClayCodec::new(&prof(4, 3, 5, "shec", "")).is_none());
    assert!(ClayCodec::new(&prof(4, 2, 5, "jerasure", "cauchy_good")).is_none());
}

fn encode_lanes(c: &ClayCodec, data: &[Vec<u8>], sc: usize) -> Vec<Vec<u8>> {
    let s = c.sub_chunk_count();
    let d: Vec<Vec<u8>> = data
        .iter()
        .map(|v| v.iter().flat_map(|b| std::iter::repeat_n(*b, sc)).collect())
        .collect();
    let mut par = vec![vec![0u8; s * sc]; c.m()];
    {
        let dr: Vec<&[u8]> = d.iter().map(|v| &v[..]).collect();
        let mut p: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
        c.encode(&dr, &mut p);
    }
    par.iter()
        .map(|v| v.iter().step_by(sc).copied().collect())
        .collect()
}

/// Spec 3.6 worked examples (any sub-chunk size: all lanes equal).
#[test]
fn worked_examples() {
    let a = vec![1, 2, 3, 4];
    let b = vec![0x10, 0x20, 0x30, 0x40];
    for sc in [1, 7, 64] {
        let c = codec(2, 2, 3, "", "");
        let p = encode_lanes(&c, &[a.clone(), b.clone()], sc);
        assert_eq!(p[0], [0x12, 0x7B, 0xAC, 0xB9]);
        assert_eq!(p[1], [0xEE, 0x34, 0x0D, 0x46]);
        let c = codec(2, 2, 3, "isa", "");
        let p = encode_lanes(&c, &[a.clone(), b.clone()], sc);
        assert_eq!(p[0], [0x12, 0xF4, 0x26, 0x0A]);
        assert_eq!(p[1], [0xD3, 0x4A, 0x7C, 0xA8]);
        let c = codec(3, 2, 4, "", "");
        let d = vec![
            (1..=8).collect::<Vec<u8>>(),
            (1..=8).map(|i| i * 0x10).collect(),
            (0x80..=0x87).collect(),
        ];
        let p = encode_lanes(&c, &d, sc);
        assert_eq!(p[0], [0x16, 0xA7, 0xF7, 0xA5, 0xCB, 0x6C, 0x0F, 0xF2]);
        assert_eq!(p[1], [0x5C, 0x49, 0x79, 0x34, 0x1D, 0xB6, 0x0D, 0x83]);
    }
}

/// Independent check of spec 3.3/3.4 per byte: uncouple every plane, verify the mds parity equations.
fn check_constraints(c: &ClayCodec, all: &[Vec<u8>]) {
    let p = c.profile();
    let (q, t, s, nu, k) = (p.q, p.t, p.s, p.nu, p.k);
    let n = q * t;
    let kind = p.kind().unwrap();
    let pm = coding_matrix(kind, 2, 2);
    let g = coding_matrix(kind, k + nu, p.m);
    let sc = all[0].len() / s;
    let cval = |nd: usize, z: usize, b: usize| -> u8 {
        if nd < k {
            all[nd][z * sc + b]
        } else if nd < k + nu {
            0
        } else {
            all[nd - nu][z * sc + b]
        }
    };
    let dig = |z: usize, y: usize| (z / q.pow((t - 1 - y) as u32)) % q;
    for z in 0..s {
        for b in 0..sc {
            let u: Vec<u8> = (0..n)
                .map(|nd| {
                    let (x, y) = (nd % q, nd / q);
                    let zy = dig(z, y);
                    if zy == x {
                        return cval(nd, z, b);
                    }
                    let zp = z + x * q.pow((t - 1 - y) as u32) - zy * q.pow((t - 1 - y) as u32);
                    let (me, other) = (cval(nd, z, b), cval(y * q + zy, zp, b));
                    let (ch, cl) = if x > zy { (me, other) } else { (other, me) };
                    let uh = mul(pm[0], ch) ^ mul(pm[1], cl);
                    let ul = mul(pm[2], ch) ^ mul(pm[3], cl);
                    if x > zy { uh } else { ul }
                })
                .collect();
            for j in 0..p.m {
                let mut acc = 0u8;
                for i in 0..k + nu {
                    acc ^= mul(g[j * (k + nu) + i], u[i]);
                }
                assert_eq!(acc, u[k + nu + j], "plane {z} lane {b} parity {j}");
            }
        }
    }
}

const PROFILES: &[(usize, usize, usize, &str, &str)] = &[
    (2, 2, 3, "", ""),
    (2, 2, 3, "isa", ""),
    (3, 2, 4, "", ""),
    (4, 2, 5, "", ""),
    (4, 2, 5, "isa", ""),
    (4, 3, 5, "", ""),
    (5, 2, 6, "", ""),
    (3, 3, 4, "isa", "cauchy"),
    (3, 2, 4, "jerasure", "reed_sol_r6_op"),
    (6, 3, 8, "", ""),
    (8, 4, 11, "", ""),
    (8, 3, 10, "", ""),
    (8, 3, 9, "", ""),
    (5, 4, 6, "", ""),
    (4, 3, 6, "", ""),
    (5, 3, 7, "", ""),
    (4, 4, 7, "isa", ""),
    (10, 4, 13, "", ""),
    (4, 5, 8, "isa", ""),
];

fn subsets(n: usize, max: usize) -> Vec<Vec<usize>> {
    (0u32..1 << n)
        .filter(|b| b.count_ones() as usize <= max)
        .map(|b| (0..n).filter(|i| b >> i & 1 == 1).collect())
        .collect()
}

#[test]
fn constraints_and_all_erasures() {
    for &(k, m, d, sc_, t) in PROFILES {
        let c = codec(k, m, d, sc_, t);
        let s = c.sub_chunk_count();
        let sc = if s >= 64 { 1 } else { 3 };
        let all = chunks(&c, s * sc, (k * 100 + m * 10 + d) as u64);
        check_constraints(&c, &all);
        let pats = subsets(k + m, m);
        let step = pats.len().div_ceil(300);
        for (pi, lost) in pats.iter().enumerate() {
            if pi % step != 0 && lost.len() == m {
                continue;
            }
            let have: Vec<(usize, &[u8])> = (0..k + m)
                .filter(|r| !lost.contains(r))
                .map(|r| (r, &all[r][..]))
                .collect();
            let want: Vec<usize> = (0..k + m).collect();
            let mut outs = vec![vec![0u8; s * sc]; k + m];
            let mut o: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..]).collect();
            c.decode_into(&have, &want, &mut o).unwrap();
            assert_eq!(outs, all, "({k},{m},{d}) lost {lost:?}");
        }
        // too many erasures
        let have: Vec<(usize, &[u8])> = (m + 1..k + m).map(|r| (r, &all[r][..])).collect();
        let mut out = vec![0u8; s * sc];
        assert!(c.decode_into(&have, &[0], &mut [&mut out[..]]).is_err());
    }
}

#[test]
fn multi_stripe_per_chunk() {
    let mut c = codec(4, 2, 5, "", "");
    let cs = 8 * 64;
    let one: Vec<Vec<Vec<u8>>> = (0..3).map(|st| chunks(&c, cs, 7 + st)).collect();
    c.set_chunk(cs);
    let data: Vec<Vec<u8>> = (0..4)
        .map(|i| one.iter().flat_map(|s| s[i].clone()).collect())
        .collect();
    let mut par = vec![vec![0u8; 3 * cs]; 2];
    {
        let d: Vec<&[u8]> = data.iter().map(|v| &v[..]).collect();
        let mut p: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
        c.encode(&d, &mut p);
    }
    for (st, s) in one.iter().enumerate() {
        assert_eq!(&par[0][st * cs..(st + 1) * cs], &s[4][..]);
        assert_eq!(&par[1][st * cs..(st + 1) * cs], &s[5][..]);
    }
    let have = [
        (1, &data[1][..]),
        (2, &data[2][..]),
        (4, &par[0][..]),
        (5, &par[1][..]),
    ];
    let mut o = vec![vec![0u8; 3 * cs]; 2];
    let mut oo: Vec<&mut [u8]> = o.iter_mut().map(|v| &mut v[..]).collect();
    c.decode_into(&have, &[0, 3], &mut oo).unwrap();
    assert_eq!((&o[0], &o[1]), (&data[0], &data[3]));
}

#[test]
fn read_set_base_rule() {
    let c = codec(4, 2, 5, "", "");
    assert_eq!(c.read_set(&[1, 2], &[0, 1, 2, 3, 4, 5]), Some(vec![1, 2]));
    assert_eq!(c.read_set(&[3], &[5, 4, 2, 1, 0]), Some(vec![0, 1, 2, 4]));
    assert_eq!(c.read_set(&[3], &[5, 4, 2]), None);
}

#[test]
fn repair_subchunk_ranges() {
    let c = codec(4, 2, 5, "", "");
    let want: [&[(usize, usize)]; 6] = [
        &[(0, 4)],
        &[(4, 4)],
        &[(0, 2), (4, 2)],
        &[(2, 2), (6, 2)],
        &[(0, 1), (2, 1), (4, 1), (6, 1)],
        &[(1, 1), (3, 1), (5, 1), (7, 1)],
    ];
    for (i, w) in want.iter().enumerate() {
        assert_eq!(c.repair_subchunks(i), *w, "chunk {i}");
        assert_eq!(c.repair_sub_chunk_count(&[i]), 4);
    }
    let all: Vec<usize> = (1..6).collect();
    assert!(c.is_repair(&[0], &all));
    assert!(!c.is_repair(&[0], &[2, 3, 4, 5])); // column-mate 1 missing
    assert!(!c.is_repair(&[0, 1], &[2, 3, 4, 5]));
    assert!(!c.is_repair(&[1], &all));
    assert_eq!(c.minimum_to_repair(0, &all), Some(vec![1, 2, 3, 4, 5]));
}

/// Helper buffer of raw chunk `r` for repairing `lost` (spec 6.3 layout).
fn helper_bytes(c: &ClayCodec, chunk: &[u8], lost: usize) -> Vec<u8> {
    let sc = chunk.len() / c.sub_chunk_count();
    c.repair_subchunks(lost)
        .iter()
        .flat_map(|(f, n)| chunk[f * sc..(f + n) * sc].to_vec())
        .collect()
}

fn check_repair(c: &ClayCodec, all: &[Vec<u8>], lost: usize, helpers: &[usize]) {
    let bufs: Vec<Vec<u8>> = helpers
        .iter()
        .map(|r| helper_bytes(c, &all[*r], lost))
        .collect();
    assert!(bufs.iter().all(|b| b.len() * c.profile().q == all[0].len()));
    let h: Vec<(usize, &[u8])> = helpers
        .iter()
        .copied()
        .zip(bufs.iter().map(|b| &b[..]))
        .collect();
    let mut out = vec![0u8; all[0].len()];
    c.repair(lost, &h, &mut out).unwrap();
    let p = c.profile();
    assert!(
        out == all[lost],
        "({},{},{}) lost {lost} helpers {helpers:?}",
        p.k,
        p.m,
        p.d
    );
}

#[test]
fn repair_every_chunk_with_aloof() {
    for &(k, m, d, sc_, t) in PROFILES {
        let c = codec(k, m, d, sc_, t);
        let s = c.sub_chunk_count();
        let sc = if s >= 64 { 1 } else { 2 };
        let all = chunks(&c, s * sc, 99 + k as u64);
        let mut repaired = 0;
        for lost in 0..k + m {
            let avail: Vec<usize> = (0..k + m).filter(|r| *r != lost).collect();
            let h = c.minimum_to_repair(lost, &avail).expect("all up => repair");
            assert_eq!(h.len(), d);
            check_repair(&c, &all, lost, &h);
            // one more shard down: aloof set changes; repair when still is_repair
            for down in avail.iter().copied() {
                let av: Vec<usize> = avail.iter().copied().filter(|r| *r != down).collect();
                if let Some(h) = c.minimum_to_repair(lost, &av) {
                    check_repair(&c, &all, lost, &h);
                    repaired += 1;
                }
            }
        }
        assert_eq!(repaired > 0, d < k + m - 1, "({k},{m},{d})");
    }
}

/// U-CL4: (5,4,6) lost chunk 0 all up = column 4 fully aloof; ours must still repair.
#[test]
fn repair_fully_aloof_column() {
    let c = codec(5, 4, 6, "", "");
    let all = chunks(&c, 32 * 64, 3);
    let avail: Vec<usize> = (1..9).collect();
    let h = c.minimum_to_repair(0, &avail).unwrap();
    assert_eq!(h, vec![1, 2, 3, 4, 5, 6]);
    check_repair(&c, &all, 0, &h);
}

#[test]
fn repair_multi_stripe() {
    let mut c = codec(4, 3, 5, "", "");
    let cs = 16 * 64;
    let st: Vec<Vec<Vec<u8>>> = (0..2).map(|i| chunks(&c, cs, 50 + i)).collect();
    c.set_chunk(cs);
    let lost = 5;
    let avail: Vec<usize> = (0..7).filter(|r| *r != lost).collect();
    let h = c.minimum_to_repair(lost, &avail).unwrap();
    let bufs: Vec<Vec<u8>> = h
        .iter()
        .map(|r| {
            st.iter()
                .flat_map(|s| helper_bytes(&c, &s[*r], lost))
                .collect()
        })
        .collect();
    let hv: Vec<(usize, &[u8])> = h.iter().copied().zip(bufs.iter().map(|b| &b[..])).collect();
    let mut out = vec![0u8; 2 * cs];
    c.repair(lost, &hv, &mut out).unwrap();
    assert_eq!(&out[..cs], &st[0][lost][..]);
    assert_eq!(&out[cs..], &st[1][lost][..]);
}
