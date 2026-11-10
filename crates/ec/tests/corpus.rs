// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! TEMPORARY dev-time parity oracle (adr 0048): set `EC_CORPUS=<ceph-erasure-code-corpus>/v0.92-988` (any of its
//! version dirs) to compare our encoder byte-for-byte with the upstream corpus and to decode erasure patterns back from
//! the corpus chunks. The test is `#[ignore]`d (run `crates/ec/tests/oracle/corpus-oracle.sh <dir>`). Permanent tests are the frozen vectors in
//! `src/gf.rs`, `src/bitmat.rs` and `tests/frozen.rs`.

use ec::Code;
use ec::lrc::LrcCodec;
use std::collections::BTreeMap;

fn roundup(x: usize, a: usize) -> usize {
    x.div_ceil(a) * a
}

/// Chunk size classic computes for stripe width `w_` (spec ec.md 4.3.4); `None` = rule not modelled.
fn chunk_size(p: &BTreeMap<String, String>, code: &Code, w_: usize) -> Option<usize> {
    let k = code.k();
    let get = |key: &str| p.get(key).and_then(|v| v.parse::<usize>().ok());
    let plugin = p.get("plugin")?.as_str();
    let tech = p.get("technique").map_or("reed_sol_van", |s| s.as_str());
    let per_chunk = p
        .get("jerasure-per-chunk-alignment")
        .is_some_and(|v| v == "true");
    match (plugin, tech) {
        ("shec", _) => Some(roundup(w_, 32 * k) / k),
        ("isa", _) => Some(roundup(w_.div_ceil(k), 32)),
        // lrc: layer 0 sub-code (jerasure reed_sol_van in the corpus, k_0 = k for k/m/l)
        ("lrc", _) => Some(roundup(w_, 32 * k) / k),
        ("jerasure", "reed_sol_van") => {
            if per_chunk {
                Some(roundup(w_.div_ceil(k), 128))
            } else {
                Some(roundup(w_, 32 * k) / k)
            }
        }
        ("jerasure", "reed_sol_r6_op") => Some(roundup(w_, 32 * k) / k),
        ("jerasure", t) => {
            let w = get("w").unwrap_or(match t {
                "liber8tion" | "cauchy_orig" | "cauchy_good" => 8,
                _ => 7, // the corpus predates the blaum_roth default change (6)
            });
            let ps = get("packetsize").unwrap_or(2048);
            let cauchy = matches!(t, "cauchy_orig" | "cauchy_good");
            if per_chunk && cauchy {
                let x = roundup(w * ps, 16);
                Some(roundup(w_.div_ceil(k), x))
            } else {
                let a = if (w * ps * 4).is_multiple_of(16) {
                    k * w * ps * 4
                } else {
                    k * w * ps * 16
                };
                Some(roundup(w_, a) / k)
            }
        }
        _ => None,
    }
}

#[test]
#[ignore = "needs EC_CORPUS: run via crates/ec/tests/oracle/corpus-oracle.sh"]
fn corpus_oracle() {
    let root =
        std::env::var("EC_CORPUS").expect("EC_CORPUS=<ceph-erasure-code-corpus>/<version dir>");
    let only = std::env::var("EC_CORPUS_ONLY").ok();
    let (mut checked, mut skipped, mut decoded) = (0, 0, 0);
    let mut ents: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap())
        .collect();
    ents.sort_by_key(|e| e.file_name());
    for ent in ents {
        let name = ent.file_name().to_string_lossy().to_string();
        if !name.starts_with("plugin=") || only.as_ref().is_some_and(|o| !name.contains(o.as_str()))
        {
            continue;
        }
        let mut prof: BTreeMap<String, String> = name
            .split(' ')
            .filter_map(|t| t.split_once('='))
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        let Some(sw) = prof
            .remove("stripe-width")
            .and_then(|v| v.parse::<usize>().ok())
        else {
            continue;
        };
        if matches!(
            prof.get("technique").map(|s| s.as_str()),
            Some("liberation" | "blaum_roth")
        ) {
            prof.entry("w".into()).or_insert_with(|| "7".into());
        }
        // lrc corpus data = jerasure layers (spec ec-lrc.md 1.5)
        let code = if prof.get("plugin").is_some_and(|p| p == "lrc") {
            let spec = ec::EcProfile::parse(&prof).unwrap().lrc.unwrap();
            Code::Lrc(Box::new(LrcCodec::new(&spec, "jerasure").unwrap()))
        } else if let Ok(c) = Code::from_profile(&prof) {
            c
        } else {
            skipped += 1;
            continue;
        };
        // corpus files are named by POSITION (shard); raw chunk r is at position pos(r)
        let pos = |r: usize| match &code {
            Code::Lrc(l) => l.mapping()[r],
            _ => r,
        };
        let (k, m, n) = (code.k(), code.m(), code.n());
        let Some(chunk) = chunk_size(&prof, &code, sw) else {
            skipped += 1;
            continue;
        };
        assert_eq!(
            chunk % code.unit(),
            0,
            "{name} chunk {chunk} unit {}",
            code.unit()
        );
        let content = std::fs::read(ent.path().join("content")).unwrap();
        let mut padded = content.clone();
        padded.resize(chunk * k, 0);
        let data: Vec<&[u8]> = (0..k)
            .map(|i| &padded[i * chunk..(i + 1) * chunk])
            .collect();
        let mut par = vec![vec![0u8; chunk]; m];
        let mut pr: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
        code.encode(&data, &mut pr);
        let mut all: Vec<Vec<u8>> = Vec::new();
        for i in 0..n {
            let f = std::fs::read(ent.path().join(pos(i).to_string())).unwrap();
            let ours: &[u8] = if i < k { data[i] } else { &par[i - k] };
            assert_eq!(&f[..], ours, "{name} chunk {i}");
            all.push(f);
        }
        checked += 1;
        // decode: every single erasure and a few multi-erasure patterns, from the corpus bytes
        let mut pats: Vec<Vec<usize>> = (0..n).map(|i| vec![i]).collect();
        for s in 0..n.min(6) {
            pats.push((0..m.min(n)).map(|d| (s + d * 3 + d) % n).collect());
        }
        if matches!(code, Code::Lrc(_)) {
            for a in 0..n {
                for b in a + 1..n {
                    pats.push(vec![a, b]);
                }
            }
        }
        for mut lost in pats {
            lost.sort_unstable();
            lost.dedup();
            let avail: Vec<usize> = (0..n).filter(|i| !lost.contains(i)).collect();
            let Some(set) = code.read_set(&lost, &avail) else {
                continue;
            };
            if set.iter().any(|r| lost.contains(r)) {
                continue;
            }
            let have: Vec<(usize, &[u8])> = set.iter().map(|&r| (r, &all[r][..])).collect();
            let mut outs = vec![vec![0u8; chunk]; lost.len()];
            let mut o: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..]).collect();
            let r = code.decode_into(&have, &lost, &mut o);
            if r.is_err() && name.contains("blaum_roth") {
                // w=7 is tolerated by classic although w+1 is not prime: not MDS, some patterns are unrecoverable
                continue;
            }
            r.unwrap_or_else(|e| panic!("{name} lost {lost:?} read {set:?}: {e:?}"));
            for (i, l) in lost.iter().enumerate() {
                assert_eq!(outs[i], all[*l], "{name} lost {lost:?} chunk {l}");
            }
            decoded += 1;
        }
    }
    eprintln!("corpus cases checked: {checked}, skipped {skipped}, decodes {decoded}");
}
