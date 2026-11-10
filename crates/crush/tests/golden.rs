// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Black-box golden tests vs crushtool output (testdata/crush, regenerate with gen.sh).

use crush::{CrushMap, Workspace};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/crush")
}

fn load(name: &str) -> (CrushMap, Vec<u8>) {
    let raw = fs::read(dir().join(format!("{name}.bin"))).unwrap();
    (
        CrushMap::decode(&raw).unwrap_or_else(|e| panic!("{name}: {e}")),
        raw,
    )
}

#[test]
fn reencode_byte_identical() {
    let mut n = 0;
    for e in fs::read_dir(dir()).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "bin") {
            let raw = fs::read(&p).unwrap();
            let m = CrushMap::decode(&raw).unwrap_or_else(|e| panic!("{p:?}: {e}"));
            assert!(m.encode() == raw, "re-encode differs: {p:?}");
            n += 1;
        }
    }
    assert!(n >= 10, "found only {n} maps");
}

#[test]
fn truncated_never_panics() {
    let (_, raw) = load("m_classes");
    for l in 0..raw.len() {
        let _ = CrushMap::decode(&raw[..l]);
    }
}

#[test]
fn mappings_match_crushtool() {
    let mut cache: BTreeMap<String, (CrushMap, Workspace)> = BTreeMap::new();
    let mut files = 0;
    let mut lines = 0;
    let mut names: Vec<_> = fs::read_dir(dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let n = p.file_name().unwrap().to_string_lossy();
            n.ends_with(".txt") && n.contains(".r") && n.contains(".n")
        })
        .collect();
    names.sort();
    for p in names {
        let fname = p.file_name().unwrap().to_string_lossy().to_string();
        let mapname = fname.split(".r").next().unwrap().to_string();
        let rest = &fname[mapname.len() + 2..];
        let rule: usize = rest.split('.').next().unwrap().parse().unwrap();
        let nrep: usize = rest.split('.').nth(1).unwrap()[1..].parse().unwrap();
        let (map, ws) = cache.entry(mapname.clone()).or_insert_with(|| {
            let (m, _) = load(&mapname);
            let ws = Workspace::new(&m, 16);
            (m, ws)
        });
        let text = fs::read_to_string(&p).unwrap();
        let mut it = text.lines();
        let hdr = it
            .next()
            .unwrap()
            .strip_prefix("# weights:")
            .unwrap()
            .trim()
            .to_string();
        let mut weights = vec![0x10000u32; map.max_devices as usize];
        for kv in hdr.split(',').filter(|s| !s.is_empty()) {
            let (d, w) = kv.split_once('=').unwrap();
            let w: f64 = w.parse().unwrap();
            weights[d.parse::<usize>().unwrap()] = (w * 65536.0) as u32;
        }
        let mut out = vec![0i32; nrep];
        for l in it {
            // CRUSH rule R x X [a,b,c]
            let (pre, vec) = l.split_once(" [").unwrap();
            let x: u32 = pre.rsplit(' ').next().unwrap().parse().unwrap();
            let exp: Vec<i32> = vec
                .trim_end_matches(']')
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.parse().unwrap())
                .collect();
            let n = map.do_rule(rule, x, &mut out, &weights, None, ws);
            assert_eq!(&out[..n], &exp[..], "{fname} x={x}");
            lines += 1;
        }
        files += 1;
    }
    assert!(files > 100, "only {files} files");
    eprintln!("{files} files, {lines} mappings OK");
}

fn stable_mod(v: u32, b: u32, mask: u32) -> u32 {
    if (v & mask) < b {
        v & mask
    } else {
        v & (mask >> 1)
    }
}

/// Whole-PG path vs osdmaptool raw mappings (pps, pool-id / default choose_args selection).
#[test]
fn pg_mappings_match_osdmaptool() {
    let mut total = 0;
    let mut with_args = 0;
    let mut bad = 0;
    for e in fs::read_dir(dir()).unwrap() {
        let p = e.unwrap().path();
        if !p.to_string_lossy().ends_with(".pgs.txt") {
            continue;
        }
        let text = fs::read_to_string(&p).unwrap();
        let mut map: Option<CrushMap> = None;
        let (mut pool, mut size, mut rule, mut pgp, mut hp) = (0u32, 0usize, 0usize, 0u32, true);
        let mut ws = None;
        for l in text.lines() {
            if let Some(h) = l.strip_prefix("# pool ") {
                let t: Vec<&str> = h.split(' ').collect();
                pool = t[0].parse().unwrap();
                size = t[2].parse().unwrap();
                rule = t[4].parse().unwrap();
                pgp = t[8].parse().unwrap();
                hp = t[10] == "1";
                let m = load(t[12]).0;
                ws = Some(Workspace::new(&m, 8));
                map = Some(m);
                continue;
            }
            let m = map.as_ref().unwrap();
            let mut f = l.split('\t');
            let pg = f.next().unwrap();
            let ps = u32::from_str_radix(pg.split('.').nth(1).unwrap(), 16).unwrap();
            let exp: Vec<i32> = f
                .next()
                .unwrap()
                .trim_matches(['[', ']'])
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.parse().unwrap())
                .collect();
            let mask = (1u32 << (32 - (pgp - 1).leading_zeros())) - 1;
            let sm = stable_mod(ps, pgp, mask);
            let x = if hp {
                crush::hash::hash32_2(sm, pool)
            } else {
                sm.wrapping_add(pool)
            };
            let args = m.choose_args_for(pool as i64);
            with_args += args.is_some() as usize;
            let weights = vec![0x10000u32; m.max_devices as usize];
            let mut out = vec![0i32; size];
            let n = m.do_rule(rule, x, &mut out, &weights, args, ws.as_mut().unwrap());
            if out[..n] != exp[..] {
                eprintln!("{p:?} pg {pg} got {:?} exp {exp:?}", &out[..n]);
                bad += 1;
            }
            total += 1;
        }
    }
    assert_eq!(bad, 0);
    assert!(total > 500 && with_args > 500, "{total} {with_args}");
}

#[test]
fn encode_with_features_gates_sections() {
    use crush::{FEATURE_CRUSH_TUNABLES5, FEATURE_SERVER_LUMINOUS};
    let (m, raw) = load("m_classes");
    let all = u64::MAX;
    // all features: identical to the verbatim encoding when the blob carries msr tail
    let full = m.encode_with_features(all);
    assert_eq!(CrushMap::decode(&full).unwrap().wire_stages, 9);
    assert_eq!(full.len(), m.encode_with_features(all).len());
    // without MSR: exactly the 8 trailing bytes less
    let no_msr = m.encode_with_features(all & !(1u64 << 38));
    assert_eq!(no_msr.len() + 8, full.len());
    assert_eq!(&no_msr[..], &full[..no_msr.len()]);
    assert_eq!(CrushMap::decode(&no_msr).unwrap().wire_stages, 8);
    // without luminous: no classes / choose_args either
    let pre = m.encode_with_features(FEATURE_CRUSH_TUNABLES5);
    assert!(pre.len() < no_msr.len());
    assert_eq!(CrushMap::decode(&pre).unwrap().wire_stages, 6);
    // without tunables5 (and luminous): 5 stages
    let t4 = m.encode_with_features(0);
    assert_eq!(CrushMap::decode(&t4).unwrap().wire_stages, 5);
    let _ = (raw, FEATURE_SERVER_LUMINOUS);
}

/// The counted canonical length equals the bytes the encoder writes, for every golden map and
/// every feature-dependent layout.
#[test]
fn encoded_len_matches_encoding() {
    use crush::{FEATURE_CRUSH_TUNABLES5, FEATURE_SERVER_LUMINOUS};
    let mut n = 0;
    for e in fs::read_dir(dir()).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "bin") {
            let m = CrushMap::decode(&fs::read(&p).unwrap()).unwrap();
            for f in [
                0,
                FEATURE_CRUSH_TUNABLES5,
                FEATURE_SERVER_LUMINOUS,
                !(1u64 << 38),
                u64::MAX,
            ] {
                let bytes = m.encode_with_features(f);
                assert_eq!(
                    m.encoded_len_with_features(f),
                    bytes.len() as u64,
                    "{p:?} {f:#x}"
                );
            }
            n += 1;
        }
    }
    assert!(n >= 10, "found only {n} maps");
}
