// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The oprobe differential scripts run in-process against the engine; transcripts must equal the goldens captured
//! from a classic OSD (testdata/oprobe).
mod common;
use common::*;
use oprobe::harness::load_dir;
use oprobe::render::{Detail, render_reply};
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn transcript(f: &oprobe::harness::ScriptFile) -> String {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let oid = format!("oprobe-{}-x", f.name).into_bytes();
    let mut out = format!("# {}\n", f.name);
    for (i, m) in f.msgs.iter().enumerate() {
        out.push_str(&format!("> {}\n", m.text));
        let mut op = mkop(&oid, m.ops.clone());
        op.snapid = m.snapid;
        op.snap_seq = m.snap_seq;
        op.snaps = m.snaps.clone();
        op.flags |= m.flags;
        let mut outs = run(&mut pg, &mut eng, 1, 100 + i as u64, client(4100), op);
        match reply_of(&mut outs, 1, 100 + i as u64) {
            Some(r) => out.push_str(&render_reply(&m.ops, &r, Detail::Normalized)),
            None => out.push_str("result=NO-REPLY (none)\n"),
        }
    }
    out
}

#[test]
fn oprobe_goldens() {
    let dir = root().join("tools/oprobe/scripts");
    let gold = root().join("testdata/oprobe");
    let files = load_dir(&dir).expect("scripts");
    assert!(files.len() >= 30);
    let only = std::env::var("GOLDEN").ok();
    let mut bad = Vec::new();
    for f in &files {
        if let Some(o) = &only
            && !f.name.contains(o.as_str())
        {
            continue;
        }
        let want = std::fs::read_to_string(gold.join(format!("{}.out", f.name))).expect("golden");
        let got = transcript(f);
        if let Some(d) = oprobe::harness::diff("golden", &want, "ours", &got) {
            bad.push(format!("== {}\n{d}", f.name));
        }
    }
    assert!(
        bad.is_empty(),
        "{} scripts differ:\n{}",
        bad.len(),
        bad.join("\n")
    );
}
