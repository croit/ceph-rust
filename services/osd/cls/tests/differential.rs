// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Black-box differential test against a CLASSIC OSD.
//!
//! `testdata/cls/classic/*.ops` are oprobe scripts (messages separated by `---`, syntax of
//! crates/oprobe/src/script.rs, restricted to the subset below). `*.cap` are raw transcripts recorded
//! on a classic OSD (21.1.1) by `examples/capture.rs` (see `testdata/cls/classic/README`). This test
//! replays the same scripts on `MemStore` and requires identical message results, op rvals and op
//! outdata, after normalizing what legitimately differs: wall-clock utimes, random uuid names,
//! lock locker identity/address.
//!
//! Supported ops: call, create [excl], writefull, write, truncate, delete, setxattr, getxattr,
//! getxattrs, omap-set k=v.., omap-rm-keys, omap-clear, omap-set-header, omap-get-vals [after [max
//! [prefix]]], omap-get-keys [after [max]], omap-get-header, read, stat; directives `@...` ignored.

mod common;
use cls::ClsCtx;
use cls::errno::*;
use cls::mem::{MemCtx, MemStore};
use cls::registry;
use common::{kv_enc, norm_op};
use denc::Encoder;
use std::path::PathBuf;

// ------------------------------------------------------------------------------------- script

fn tokenize(text: &str) -> Vec<Vec<Vec<u8>>> {
    let mut stmts = Vec::new();
    let mut cur: Vec<Vec<u8>> = Vec::new();
    let mut tok: Vec<u8> = Vec::new();
    let mut have = false;
    let mut it = text.chars().peekable();
    macro_rules! end_tok {
        () => {
            if have {
                cur.push(std::mem::take(&mut tok));
                have = false;
            }
        };
    }
    macro_rules! end_stmt {
        () => {
            end_tok!();
            if !cur.is_empty() {
                stmts.push(std::mem::take(&mut cur));
            }
        };
    }
    while let Some(c) = it.next() {
        match c {
            ';' | '\n' => {
                end_stmt!();
            }
            c if c.is_whitespace() => {
                end_tok!();
            }
            '#' if !have => {
                for c in it.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
                end_stmt!();
            }
            '"' => {
                have = true;
                while let Some(c) = it.next() {
                    match c {
                        '"' => break,
                        '\\' => match it.next() {
                            Some('n') => tok.push(b'\n'),
                            Some('0') => tok.push(0),
                            Some(o) => tok.extend(o.to_string().bytes()),
                            None => break,
                        },
                        o => tok.extend(o.to_string().bytes()),
                    }
                }
            }
            '\'' => {
                have = true;
                for c in it.by_ref() {
                    if c == '\'' {
                        break;
                    }
                    tok.extend(c.to_string().bytes());
                }
            }
            o => {
                have = true;
                tok.extend(o.to_string().bytes());
            }
        }
    }
    if have {
        cur.push(tok);
    }
    if !cur.is_empty() {
        stmts.push(cur);
    }
    stmts
}

fn data(b: &[u8]) -> Vec<u8> {
    let t = String::from_utf8_lossy(b).into_owned();
    if let Some(h) = t.strip_prefix("hex:") {
        let h: String = h.chars().filter(|c| !c.is_whitespace()).collect();
        return (0..h.len() / 2)
            .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
            .collect();
    }
    if let Some(n) = t.strip_prefix("zeros:") {
        return vec![0; n.parse().unwrap()];
    }
    if let Some(n) = t.strip_prefix("seq:") {
        return (0..n.parse::<u64>().unwrap())
            .map(|i| (i % 251) as u8)
            .collect();
    }
    if let Some(r) = t.strip_prefix("rep:") {
        let (n, txt) = r.split_once(':').unwrap();
        return txt.as_bytes().repeat(n.parse().unwrap());
    }
    b.to_vec()
}

fn num(b: &[u8]) -> u64 {
    let t = String::from_utf8_lossy(b).replace('_', "");
    match t.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).unwrap(),
        None => t.parse().unwrap(),
    }
}

type Stmt = Vec<Vec<u8>>;

fn messages(text: &str) -> Vec<Vec<Stmt>> {
    text.split("\n---")
        .map(tokenize)
        .filter(|m: &Vec<Stmt>| !m.is_empty())
        .collect()
}

// ------------------------------------------------------------------------------------ results

#[derive(Debug, Default, PartialEq, Eq)]
struct Outcome {
    result: i32,
    /// (rval, outdata) of each op that was executed (not compared when `skip_ops`).
    ops: Vec<(i32, Vec<u8>)>,
    skip_ops: bool,
}

fn is_write(s: &Stmt) -> bool {
    match s[0].as_slice() {
        b"call" => {
            let (c, m) = (
                String::from_utf8_lossy(&s[1]),
                String::from_utf8_lossy(&s[2]),
            );
            registry::lookup(&c, &m).is_none_or(|m| m.wr())
        }
        b"create" | b"alloc-hint" | b"writefull" | b"write" | b"truncate" | b"delete"
        | b"setxattr" | b"omap-set" | b"omap-rm-keys" | b"omap-clear" | b"omap-set-header" => true,
        _ => false,
    }
}

fn run_op(c: &mut MemCtx, s: &Stmt) -> (i32, Vec<u8>) {
    let a = |i: usize| s.get(i).map(|x| data(x));
    let r = |r: Result<(), Errno>| (r.err().unwrap_or(0), Vec::new());
    match s[0].as_slice() {
        b"call" => {
            let class = String::from_utf8_lossy(&s[1]).into_owned();
            let method = String::from_utf8_lossy(&s[2]).into_owned();
            let rep = c.call(&class, &method, &a(3).unwrap_or_default());
            (rep.ret, rep.out)
        }
        b"create" => r(c.create(s.get(1).is_some_and(|x| x == b"excl"))),
        b"writefull" => r(c.write_full(&a(1).unwrap())),
        b"write" => r(c.write(num(&s[1]), &a(2).unwrap())),
        b"truncate" => r(c.truncate(num(&s[1]))),
        b"delete" => r(c.remove()),
        b"setxattr" => r(c.setxattr(&String::from_utf8_lossy(&s[1]), &a(2).unwrap())),
        b"getxattr" => match c.getxattr(&String::from_utf8_lossy(&s[1])) {
            Ok(v) => (0, v),
            Err(e) => (e, vec![]),
        },
        b"getxattrs" => match c.getxattrs_raw() {
            Ok(m) => (0, kv_enc(&m)),
            Err(e) => (e, vec![]),
        },
        b"omap-set" => {
            let kvs: Vec<(Vec<u8>, Vec<u8>)> = s[1..]
                .iter()
                .map(|t| {
                    let i = t.iter().position(|&b| b == b'=').unwrap();
                    (t[..i].to_vec(), data(&t[i + 1..]))
                })
                .collect();
            let e: Vec<(&[u8], &[u8])> = kvs
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect();
            r(c.omap_set(&e))
        }
        b"omap-rm-keys" => {
            let mut res = Ok(());
            for k in &s[1..] {
                res = res.and(c.omap_remove_key(k));
            }
            r(res)
        }
        b"omap-clear" => r(c.omap_clear()),
        b"omap-set-header" => r(c.omap_set_header(&a(1).unwrap())),
        b"omap-get-vals" => {
            let after = s.get(1).map_or(vec![], |x| x.clone());
            let max = s.get(2).map_or(1000, |x| num(x));
            let pre = s.get(3).map_or(vec![], |x| x.clone());
            match c.omap_get_vals(&after, &pre, max) {
                Ok((m, more)) => {
                    let mut o = kv_enc(&m);
                    o.push(more as u8);
                    (0, o)
                }
                Err(e) => (e, vec![]),
            }
        }
        b"omap-get-keys" => {
            let after = s.get(1).map_or(vec![], |x| x.clone());
            let max = s.get(2).map_or(1000, |x| num(x));
            match c.omap_get_keys(&after, max) {
                Ok((k, more)) => {
                    let mut e = Encoder::new();
                    e.count(k.len()).unwrap();
                    for x in &k {
                        e.bytes(x).unwrap();
                    }
                    let mut o = e.into_vec();
                    o.push(more as u8);
                    (0, o)
                }
                Err(e) => (e, vec![]),
            }
        }
        b"alloc-hint" => (0, Vec::new()),
        b"omap-get-header" => match c.omap_get_header() {
            Ok(v) => (0, v),
            Err(e) => (e, vec![]),
        },
        b"read" => match c.read(num(&s[1]), num(&s[2])) {
            Ok(v) => (0, v),
            Err(e) => (e, vec![]),
        },
        b"stat" => match c.stat() {
            Ok(st) => {
                let mut o = st.size.to_le_bytes().to_vec();
                o.extend(st.mtime.sec.to_le_bytes());
                o.extend(st.mtime.nsec.to_le_bytes());
                (0, o)
            }
            Err(e) => (e, vec![]),
        },
        other => panic!("unsupported op {}", String::from_utf8_lossy(other)),
    }
}

fn run_message(store: &mut MemStore, oid: &str, msg_all: &[Stmt]) -> Outcome {
    let snapc: Option<u64> = msg_all.iter().find_map(|s| {
        let t = String::from_utf8_lossy(&s[0]).into_owned();
        t.strip_prefix("@snapc=")
            .and_then(|r| r.split(':').next().and_then(|n| n.parse().ok()))
    });
    let msg: Vec<Stmt> = msg_all
        .iter()
        .filter(|s| !s[0].starts_with(b"@"))
        .cloned()
        .collect();
    let msg = msg.as_slice();
    let mut ctx = store.begin(oid);
    let mut out = Outcome::default();
    // rule #24: a read-only message on an absent object fails ENOENT before any op runs
    if !ctx.exists() && !msg.iter().any(is_write) {
        out.result = ENOENT;
        out.skip_ops = true;
        return out;
    }
    for s in msg {
        let (rv, od) = run_op(&mut ctx, s);
        out.ops.push((rv, od));
        if rv < 0 {
            out.result = rv;
            break;
        }
    }
    if out.result >= 0 {
        let returnvec = msg_all.iter().any(|s| {
            s[0].starts_with(b"@flags=") && String::from_utf8_lossy(&s[0]).contains("returnvec")
        });
        if (ctx.changed() || msg.iter().any(is_write)) && !returnvec {
            // client-ops s5.7: a successful mutating message drops ALL op outdata (no RETURNVEC)
            out.ops.iter_mut().for_each(|o| o.1.clear());
        }
        store.commit(oid, ctx);
        if let (Some(seq), true, Some(o)) =
            (snapc, msg.iter().any(is_write), store.objects.get_mut(oid))
        {
            o.snap_seq = o.snap_seq.max(seq);
        }
    }
    out
}

// ---------------------------------------------------------------------------- normalization

fn normalize(stmt: &Stmt, out: &[u8], c: u32) -> Vec<u8> {
    let w = |i: usize| {
        stmt.get(i)
            .map_or(String::new(), |x| String::from_utf8_lossy(x).into_owned())
    };
    norm_op((&w(0), &w(1), &w(2)), out, c)
}

// ----------------------------------------------------------------------------- capture parse

fn cap_time(text: &str) -> u32 {
    text.lines()
        .find_map(|l| l.strip_prefix("# t="))
        .and_then(|t| t.trim().parse().ok())
        .expect("cap header # t=")
}

fn parse_cap(text: &str) -> Vec<(String, Outcome)> {
    let mut v: Vec<(String, Outcome)> = Vec::new();
    for l in text.lines() {
        if let Some(m) = l.strip_prefix("> ") {
            v.push((m.to_string(), Outcome::default()));
        } else if let Some(r) = l.strip_prefix("result=") {
            v.last_mut().unwrap().1.result = r.parse().unwrap();
        } else if l.starts_with('[') {
            let rest = &l[l.find(']').unwrap() + 2..];
            let rv: i32 = rest["rval=".len()..rest.find(" out=").unwrap()]
                .parse()
                .unwrap();
            let hex = &rest[rest.find(" out=").unwrap() + 5..];
            let b = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            v.last_mut().unwrap().1.ops.push((rv, b));
        }
    }
    v
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/cls/classic")
}

/// Window of both buffers around the first differing byte.
fn first_diff(a: &[u8], b: &[u8]) -> String {
    let i = a
        .iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()));
    let lo = i.saturating_sub(24);
    let w = |x: &[u8]| -> String {
        x.iter()
            .skip(lo)
            .take(64)
            .map(|c| format!("{c:02x}"))
            .collect()
    };
    format!(
        "first diff at byte {i} (window from {lo}):\n      got  {}\n      want {}",
        w(a),
        w(b)
    )
}

/// `testdata/cls/classic/ALLOW`: explained divergences (`<script> <msg|*>`, trailing `*` = prefix match).
fn allowed(name: &str, msg: usize) -> bool {
    let text = std::fs::read_to_string(dir().join("ALLOW")).unwrap_or_default();
    text.lines().any(|l| {
        let mut w = l.split('#').next().unwrap_or("").split_whitespace();
        let (Some(s), Some(m)) = (w.next(), w.next()) else {
            return false;
        };
        (s == name || s.strip_suffix('*').is_some_and(|p| name.starts_with(p)))
            && (m == "*" || m == msg.to_string())
    })
}

/// Replay one case; returns the list of mismatches.
static COMPARED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Replay one case; returns the list of mismatches.
pub fn replay(name: &str) -> Vec<String> {
    let ops = std::fs::read_to_string(dir().join(format!("{name}.ops"))).unwrap();
    let cap = std::fs::read_to_string(dir().join(format!("{name}.cap")))
        .unwrap_or_else(|_| panic!("{name}.cap missing: record with examples/capture.rs"));
    let msgs = messages(&ops);
    let caps = parse_cap(&cap);
    let want_t = cap_time(&cap);
    assert_eq!(msgs.len(), caps.len(), "{name}: message count");
    let mut store = MemStore::new();
    store.env.now = denc::types::UTime::new(want_t, 0); // same clock as the recording: literals near "now" normalize alike
    let mut bad = Vec::new();
    for (i, (m, (text, want))) in msgs.iter().zip(&caps).enumerate() {
        let got = run_message(&mut store, "obj", m);
        if allowed(name, i) {
            continue;
        }
        let m: Vec<Stmt> = m
            .iter()
            .filter(|s| !s[0].starts_with(b"@"))
            .cloned()
            .collect();
        if got.result != want.result {
            bad.push(format!(
                "{name} msg {i} [{text}]: result got {} want {}",
                got.result, want.result
            ));
            continue;
        }
        if got.skip_ops {
            continue;
        }
        for (j, (g, st)) in got.ops.iter().zip(&m).enumerate() {
            let Some(w) = want.ops.get(j) else {
                bad.push(format!("{name} msg {i} op {j}: missing in capture"));
                continue;
            };
            // classic reports rval 0 for ops after the failing one only; compared ops all ran
            COMPARED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let (gn, wn) = (
                normalize(st, &g.1, store.env.now.sec),
                normalize(st, &w.1, want_t),
            );
            if g.0 != w.0 || gn != wn {
                bad.push(format!(
                    "{name} msg {i} [{text}] op {j} ({}): rval got {} want {}\n    got {} bytes, want {} bytes; {}",
                    String::from_utf8_lossy(&st[0]),
                    g.0,
                    w.0,
                    gn.len(),
                    wn.len(),
                    first_diff(&gn, &wn)
                ));
            }
        }
    }
    bad
}

#[test]
fn classic_transcripts() {
    let mut names: Vec<String> = std::fs::read_dir(dir())
        .unwrap()
        .filter_map(|e| {
            let p = e.ok()?.path();
            (p.extension()? == "ops").then(|| p.file_stem().unwrap().to_string_lossy().into_owned())
        })
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no differential cases");
    let mut bad = Vec::new();
    for n in &names {
        bad.extend(replay(n));
    }
    let n = COMPARED.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("differential: {} cases, {} ops compared", names.len(), n);
    assert!(n > 800, "suspiciously few compared ops: {n}");
    assert!(
        bad.is_empty(),
        "{} mismatches vs classic:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// Every registered method is exercised by at least one classic-recorded case.
#[test]
fn every_method_has_a_classic_case() {
    let mut seen = std::collections::BTreeSet::new();
    for e in std::fs::read_dir(dir()).unwrap().flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "ops") {
            let text = std::fs::read_to_string(&p).unwrap();
            for m in messages(&text) {
                for s in m {
                    if s[0] == b"call" {
                        seen.insert(format!(
                            "{}.{}",
                            String::from_utf8_lossy(&s[1]),
                            String::from_utf8_lossy(&s[2])
                        ));
                    }
                }
            }
        }
    }
    let mut missing = Vec::new();
    for class in cls::CLASSES {
        // classes without any classic transcript yet (rgw-family, needs a classic cluster capture
        // with RGW-shaped messages, rgw-gap T0) are covered by dencoder fixtures + scenario tests
        if !seen.iter().any(|s| s.starts_with(&format!("{class}."))) {
            continue;
        }
        for m in cls::methods(class) {
            if !seen.contains(&format!("{class}.{}", m.name)) {
                missing.push(format!("{class}.{}", m.name));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "methods without a differential case: {missing:?}"
    );
}
