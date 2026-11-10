// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Embeds `FLASHSTORE_GIT` = `<sha>[-dirty]` so a crash maps to source. Override with env FLASHSTORE_GIT (rsync copies
//! without .git); "unknown" if neither is available.
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let o = Command::new("git").args(args).output().ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn main() {
    println!("cargo:rerun-if-env-changed=FLASHSTORE_GIT");
    println!("cargo:rerun-if-changed=build.rs");
    let v = std::env::var("FLASHSTORE_GIT")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            match git(&["rev-parse", "--short=12", "HEAD"]) {
                Some(sha) => {
                    if let Some(top) = git(&["rev-parse", "--git-dir"]) {
                        println!("cargo:rerun-if-changed={top}/HEAD");
                        println!("cargo:rerun-if-changed={top}/index");
                    }
                    // dirty: tracked changes only (untracked lab files are noise)
                    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
                        .is_some_and(|s| !s.is_empty());
                    if dirty { format!("{sha}-dirty") } else { sha }
                }
                None => "unknown".into(),
            }
        });
    println!("cargo:rustc-env=FLASHSTORE_GIT={v}");
}
