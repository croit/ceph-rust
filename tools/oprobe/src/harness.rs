// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Differential harness: run canned script files against an OSD (objects chosen so that this OSD is
//! the acting primary) and produce normalized transcripts for diffing / golden comparison.

use crate::client::{Probe, Res, Target};
use crate::render::{Detail, render_reply};
use crate::script::{ScriptMsg, parse_file};
use std::path::Path;

/// A canned script file (`*.ops`): messages separated by `---`.
#[derive(Debug, Clone)]
pub struct ScriptFile {
    pub name: String,
    pub msgs: Vec<ScriptMsg>,
}

/// Load all `*.ops` files of `dir`, sorted by name.
pub fn load_dir(dir: &Path) -> Res<Vec<ScriptFile>> {
    let mut v = Vec::new();
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "ops") {
            v.push(load_file(&p)?);
        }
    }
    v.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(v)
}

/// Load one script file.
pub fn load_file(p: &Path) -> Res<ScriptFile> {
    let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let msgs = parse_file(&text).map_err(|e| format!("{}: {e}", p.display()))?;
    let name = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(ScriptFile { name, msgs })
}

/// Find an object name `prefix-N` whose acting primary is `osd` (current map).
pub fn pick_object(p: &Probe, pool: i64, nspace: &[u8], osd: i32, prefix: &str) -> Res<Vec<u8>> {
    for i in 0..4096 {
        let oid = format!("{prefix}-{i}").into_bytes();
        let t = Target {
            pool,
            oid: oid.clone(),
            nspace: nspace.to_vec(),
            key: Vec::new(),
            force_osd: None,
        };
        if p.locate(&t)?.primary == osd {
            return Ok(oid);
        }
    }
    Err(format!(
        "no object with primary osd.{osd} found in pool {pool}"
    ))
}

/// Run `f` against an object whose primary is `osd`; returns the normalized transcript.
pub fn run_file(
    p: &mut Probe,
    pool: i64,
    nspace: &[u8],
    osd: i32,
    f: &ScriptFile,
    nonce: &str,
) -> Res<String> {
    let oid = pick_object(p, pool, nspace, osd, &format!("oprobe-{}-{nonce}", f.name))?;
    let t = Target {
        pool,
        oid,
        nspace: nspace.to_vec(),
        key: Vec::new(),
        force_osd: None,
    };
    let mut out = format!("# {}\n", f.name);
    for m in &f.msgs {
        out.push_str(&format!("> {}\n", m.text));
        let o = p.exec(&t, m)?;
        if o.osd != osd {
            return Err(format!(
                "{}: op went to osd.{} instead of osd.{osd}",
                f.name, o.osd
            ));
        }
        match &o.reply {
            Some(r) => out.push_str(&render_reply(&o.req_ops, r, Detail::Normalized)),
            None => out.push_str(&format!("result=NO-REPLY ({})\n", o.note)),
        }
    }
    // tidy up (the outcome is not part of the transcript)
    let _ = p.exec(&t, &crate::script::parse_message("delete")?);
    Ok(out)
}

/// Line diff of two transcripts (None if equal).
pub fn diff(a_name: &str, a: &str, b_name: &str, b: &str) -> Option<String> {
    if a == b {
        return None;
    }
    let (al, bl): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    let mut s = String::new();
    for i in 0..al.len().max(bl.len()) {
        let (x, y) = (
            al.get(i).copied().unwrap_or("<missing>"),
            bl.get(i).copied().unwrap_or("<missing>"),
        );
        if x != y {
            s.push_str(&format!(
                "  line {}:\n    {a_name}: {x}\n    {b_name}: {y}\n",
                i + 1
            ));
        }
    }
    Some(s)
}
