// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Dev tool: summarize op vectors in captured msgr2 streams.
//! `cargo run -p opwire --example summarize -- <dir-with-.bin> [prefix]`
//! Prints, per capture prefix (scenario), the distinct op signatures (client->OSD requests) with
//! counts and the first result seen in the matching reply.
#[path = "../tests/common/mod.rs"]
mod common;
use common::*;
use opwire::*;
use std::collections::BTreeMap;

fn sig(m: &MOSDOp) -> String {
    let mut s = Vec::new();
    for o in &m.ops {
        let mut n = op::name(o.op).unwrap_or("?").to_string();
        if o.op == op::CALL
            && let Ok(c) = o.cls_call()
        {
            n = format!(
                "call({}.{})",
                String::from_utf8_lossy(c.class),
                String::from_utf8_lossy(c.method)
            );
        }
        if o.op == op::WATCH {
            n = format!("watch/{}", o.watch().op);
        }
        s.push(n);
    }
    s.join(" + ")
}

fn list(dir: &str) {
    // SAFETY: single-threaded at startup.
    unsafe { std::env::set_var("OPWIRE_CAPDIR", dir) };
    for (name, bytes) in capture_files() {
        let n = frames(&bytes).map_or(0, |f| {
            f.iter()
                .filter(|x| matches!(x.0.ty, 42 | 43 | 44 | 61))
                .count()
        });
        println!("{name} {} {n}", bytes.len());
    }
}

/// Ordered, run-length-compressed op signatures per stream (c2s order).
fn trace(dir: &str, want: &str) {
    // SAFETY: single-threaded at startup.
    unsafe { std::env::set_var("OPWIRE_CAPDIR", dir) };
    for (name, bytes) in capture_files() {
        if !name.starts_with(want) || !name.ends_with("-c2s.bin") {
            continue;
        }
        let Some(fr) = frames(&bytes) else { continue };
        let mut out: Vec<(String, usize)> = Vec::new();
        for (h, f, m, d) in &fr {
            if h.ty != 42 {
                continue;
            }
            let ClientMsg::Op(o) = decode_client_parts(h.ty, h.version, f, m, d).unwrap() else {
                continue;
            };
            let s = format!(
                "{}:{}",
                String::from_utf8_lossy(&o.oid)
                    .split('.')
                    .next()
                    .unwrap_or(""),
                sig(&o)
            );
            match out.last_mut() {
                Some((l, n)) if *l == s => *n += 1,
                _ => out.push((s, 1)),
            }
        }
        if !out.is_empty() {
            println!("{name}");
            for (s, n) in out {
                println!("    {n}x {s}");
            }
        }
    }
}

fn main() {
    let dir = std::env::args().nth(1).expect("dir");
    if std::env::args().nth(2).as_deref() == Some("--list") {
        return list(&dir);
    }
    if std::env::args().nth(2).as_deref() == Some("--trace") {
        return trace(&dir, &std::env::args().nth(3).unwrap_or_default());
    }
    let want = std::env::args().nth(2).unwrap_or_default();
    // SAFETY: single-threaded at startup.
    unsafe { std::env::set_var("OPWIRE_CAPDIR", &dir) };
    let mut per: BTreeMap<String, BTreeMap<String, (usize, i32, u32)>> = BTreeMap::new();
    for (name, bytes) in capture_files() {
        if !name.starts_with(&want) || !name.ends_with("-c2s.bin") {
            continue;
        }
        let scen = name.split("-s").next().unwrap_or("").to_string();
        let sname = name.replace("-c2s.bin", "-s2c.bin");
        let rep = std::fs::read(std::path::Path::new(&dir).join(&sname)).unwrap_or_default();
        let (Some(req), Some(rpl)) = (frames(&bytes), frames(&rep)) else {
            continue;
        };
        let mut res: BTreeMap<u64, i32> = BTreeMap::new();
        for (h, f, m, d) in &rpl {
            if h.ty == 43
                && let Ok(ClientMsg::OpReply(r)) = decode_client_parts(h.ty, h.version, f, m, d)
            {
                res.insert(h.tid, r.result);
            }
        }
        for (h, f, m, d) in &req {
            if h.ty == 42 {
                let ClientMsg::Op(o) = decode_client_parts(h.ty, h.version, f, m, d).unwrap()
                else {
                    continue;
                };
                let e = per
                    .entry(scen.clone())
                    .or_default()
                    .entry(sig(&o))
                    .or_insert((0, res.get(&h.tid).copied().unwrap_or(i32::MIN), o.flags));
                e.0 += 1;
            }
        }
    }
    for (s, m) in per {
        println!("## {s}");
        for (k, (n, r, fl)) in m {
            println!("{n:6}  r={r:<5} fl={fl:#x}  {k}");
        }
    }
}
