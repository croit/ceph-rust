// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Dev tool: compare two directories of raw `.cap` transcripts recorded by `capture` (one against a classic
//! OSD, one against croit-flashstore-osd) with the same normalization as tests/differential.rs (wall-clock utimes, random
//! uuids, lock locker identity, bilog/gc time key suffixes). Usage:
//!   capdiff [--allow FILE] CLASSIC_DIR NVME_DIR
//! `--allow` lines: `<script> <msg-index|*> # reason` (known, explained divergences). Exit 1 on any other
//! mismatch; prints one line per mismatch and a summary.

#[path = "../tests/common/mod.rs"]
mod common;
use common::norm_op;
use std::collections::BTreeMap;
use std::path::Path;

struct Msg {
    text: String,
    result: i32,
    ops: Vec<(i32, Vec<u8>)>,
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap_or(0))
        .collect()
}

fn parse(text: &str) -> (u32, Vec<Msg>) {
    let t = text
        .lines()
        .find_map(|l| l.strip_prefix("# t=")?.trim().parse().ok())
        .unwrap_or(0);
    let mut v: Vec<Msg> = Vec::new();
    for l in text.lines() {
        if let Some(m) = l.strip_prefix("> ") {
            v.push(Msg {
                text: m.to_string(),
                result: 0,
                ops: Vec::new(),
            });
        } else if let Some(r) = l.strip_prefix("result=") {
            v.last_mut().unwrap().result = r.parse().unwrap_or(i32::MIN);
        } else if l.starts_with('[') {
            let rest = &l[l.find(']').unwrap() + 2..];
            let (rv, hex) = rest["rval=".len()..].split_once(" out=").unwrap();
            v.last_mut()
                .unwrap()
                .ops
                .push((rv.parse().unwrap_or(i32::MIN), unhex(hex)));
        }
    }
    (t, v)
}

fn normalize(text: &str, out: &[u8], c: u32) -> Vec<u8> {
    let mut w = text.split_whitespace();
    norm_op(
        (
            w.next().unwrap_or(""),
            w.next().unwrap_or(""),
            w.next().unwrap_or(""),
        ),
        out,
        c,
    )
}

fn main() {
    let mut a: Vec<String> = std::env::args().skip(1).collect();
    let mut allow: Vec<(String, String)> = Vec::new();
    if let Some(i) = a.iter().position(|x| x == "--allow") {
        let f = a.remove(i + 1);
        a.remove(i);
        for l in std::fs::read_to_string(f).unwrap_or_default().lines() {
            let l = l.split('#').next().unwrap_or("").trim();
            if let Some((s, m)) = l.split_once(char::is_whitespace)
                && !m.contains("inproc")
            {
                let m = m.split_whitespace().next().unwrap_or("*");
                allow.push((s.trim().to_string(), m.to_string()));
            }
        }
    }
    let [ca, nb] = a.as_slice() else {
        eprintln!("usage: capdiff [--allow FILE] CLASSIC_DIR NVME_DIR");
        std::process::exit(2);
    };
    let mut files: BTreeMap<String, ()> = BTreeMap::new();
    for e in std::fs::read_dir(ca).unwrap().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n.ends_with(".cap") {
            files.insert(n, ());
        }
    }
    let (mut bad, mut cmp, mut allowed) = (0, 0, 0);
    for n in files.keys() {
        let name = n.trim_end_matches(".cap");
        let Ok(tb) = std::fs::read_to_string(Path::new(nb).join(n)) else {
            println!("MISSING {name}: no capture on the croit-flashstore-osd side");
            bad += 1;
            continue;
        };
        let (ta, ma) = parse(&std::fs::read_to_string(Path::new(ca).join(n)).unwrap());
        let (tbt, mb) = parse(&tb);
        if ma.len() != mb.len() {
            println!("DIFF {name}: message count {} vs {}", ma.len(), mb.len());
            bad += 1;
            continue;
        }
        for (i, (x, y)) in ma.iter().zip(&mb).enumerate() {
            let ok_allow = allow.iter().any(|(s, m)| {
                (s == name || s.strip_suffix('*').is_some_and(|p| name.starts_with(p)))
                    && (m == "*" || m == &i.to_string())
            });
            let mut why = String::new();
            if x.result != y.result {
                why = format!(
                    "result classic {} croit-flashstore-osd {}",
                    x.result, y.result
                );
            } else {
                for (j, (p, q)) in x.ops.iter().zip(&y.ops).enumerate() {
                    cmp += 1;
                    let (np, nq) = (normalize(&x.text, &p.1, ta), normalize(&y.text, &q.1, tbt));
                    if p.0 != q.0 || np != nq {
                        why = format!(
                            "op {j} rval {}/{} out {}B/{}B{}",
                            p.0,
                            q.0,
                            np.len(),
                            nq.len(),
                            if p.0 == q.0 && np.len() == nq.len() {
                                let at = np.iter().zip(&nq).position(|(a, b)| a != b).unwrap_or(0);
                                {
                                    let w = |x: &[u8]| {
                                        x.iter()
                                            .skip(at.saturating_sub(8))
                                            .take(24)
                                            .map(|c| format!("{c:02x}"))
                                            .collect::<String>()
                                    };
                                    format!(
                                        " first diff at {at}: classic {} croit-flashstore-osd {}",
                                        w(&np),
                                        w(&nq)
                                    )
                                }
                            } else {
                                String::new()
                            }
                        );
                        break;
                    }
                }
            }
            if !why.is_empty() {
                if ok_allow {
                    allowed += 1;
                } else {
                    let t: String = x.text.chars().take(90).collect();
                    println!("DIFF {name} msg {i} [{t}]: {why}");
                    bad += 1;
                }
            }
        }
    }
    println!(
        "capdiff: {} scripts, {cmp} ops compared, {bad} mismatches, {allowed} allowed",
        files.len()
    );
    std::process::exit(i32::from(bad > 0));
}
