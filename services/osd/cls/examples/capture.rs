// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Dev tool: run the `.ops` scripts of testdata/cls/classic against a CLASSIC OSD (lab cluster) with
//! oprobe and write RAW transcripts `<name>.cap` (full hex of every op's outdata; the oprobe text
//! renderer abbreviates). Usage (inside the lab network, see tests/differential.rs docs):
//!   capture --pool clsprobe --osd N [--scripts DIR] [--out DIR] [NAME...]
//! Each script runs on a fresh object whose acting primary is osd.N; the object is deleted afterwards.

use oprobe::client::{Opts, Probe, Target};
use oprobe::harness::{load_dir, pick_object};
use std::fmt::Write;

fn main() -> Result<(), String> {
    let mut a: Vec<String> = std::env::args().skip(1).collect();
    let mut take = |n: &str, d: &str| -> String {
        match a.iter().position(|x| x == n) {
            Some(i) if i + 1 < a.len() => {
                let v = a.remove(i + 1);
                a.remove(i);
                v
            }
            _ => d.to_string(),
        }
    };
    let pool = take("--pool", "clsprobe");
    let osd: i32 = take("--osd", "0").parse().map_err(|_| "bad --osd")?;
    let scripts = take("--scripts", "testdata/cls/classic");
    let out = take("--out", &scripts);
    let names = a;
    let mut p = Probe::connect(Opts::default())?;
    let pid = p
        .osdmap()
        .pool_id_by_name(&pool)
        .ok_or_else(|| format!("no pool {pool}"))?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut failed = 0;
    'scripts: for f in load_dir(std::path::Path::new(&scripts))? {
        if !names.is_empty() && !names.iter().any(|n| n.trim_end_matches(".ops") == f.name) {
            continue;
        }
        let oid = pick_object(&p, pid, b"", osd, &format!("cls-{}-{nonce:x}", f.name))?;
        let t = Target {
            pool: pid,
            oid,
            nspace: Vec::new(),
            key: Vec::new(),
            force_osd: None,
        };
        let tnow = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut s = format!("# {}\n# t={tnow}\n", f.name);
        for m in &f.msgs {
            let o = p.exec(&t, m)?;
            let _ = writeln!(s, "> {}", m.text);
            match &o.reply {
                Some(r) => {
                    let _ = writeln!(s, "result={}", r.result);
                    for (i, op) in r.ops.iter().enumerate() {
                        let h: String = op.outdata.iter().map(|b| format!("{b:02x}")).collect();
                        let _ = writeln!(s, "[{i}] rval={} out={h}", op.rval);
                    }
                }
                None => {
                    eprintln!("FAILED {}: no reply ({}); script skipped", f.name, o.note);
                    failed += 1;
                    continue 'scripts;
                }
            }
        }
        if let Ok(d) = oprobe::script::parse_message("delete") {
            let _ = p.exec(&t, &d);
        }
        let path = std::path::Path::new(&out).join(format!("{}.cap", f.name));
        std::fs::write(&path, s).map_err(|e| format!("{}: {e}", path.display()))?;
        println!("captured {}", path.display());
    }
    if failed > 0 {
        return Err(format!("{failed} scripts failed (no reply)"));
    }
    Ok(())
}
