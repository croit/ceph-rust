// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Compiles the git commit into the binary (`OPROBE_GIT`): `FLASHSTORE_GIT` (build host) wins, else
//! `git rev-parse --short=12 HEAD`, else `unknown`.
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=FLASHSTORE_GIT");
    if let Ok(head) = Command::new("git")
        .args(["rev-parse", "--git-path", "HEAD"])
        .output()
        && head.status.success()
    {
        println!(
            "cargo:rerun-if-changed={}",
            String::from_utf8_lossy(&head.stdout).trim()
        );
    }
    let git = std::env::var("FLASHSTORE_GIT")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let o = Command::new("git")
                .args(["rev-parse", "--short=12", "HEAD"])
                .output()
                .ok()?;
            o.status
                .success()
                .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=OPROBE_GIT={git}");
}
