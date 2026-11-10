// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
// Feature `verbs`: static rdma-core, all providers selected by upstream metadata; no application vendor allowlist.
use std::path::{Path, PathBuf};
use std::process::Command;

fn static_libs(dir: &Path) -> Vec<String> {
    let pc = dir.join("lib/pkgconfig/libibverbs.pc");
    assert!(
        pc.is_file(),
        "{} missing: build/install static rdma-core",
        pc.display()
    );
    println!("cargo:rerun-if-changed={}", pc.display());
    let mut paths = vec![dir.join("lib/pkgconfig")];
    if let Some(existing) = std::env::var_os("PKG_CONFIG_PATH") {
        paths.extend(std::env::split_paths(&existing));
    }
    let output = Command::new("pkg-config")
        .arg(format!(
            "--define-variable=libdir={}",
            dir.join("lib").display()
        ))
        .env(
            "PKG_CONFIG_PATH",
            std::env::join_paths(paths).expect("pkg-config search paths"),
        )
        .args(["--static", "--libs", "libibverbs"])
        .output()
        .expect("pkg-config not found (static rdma-core build dependency)");
    assert!(
        output.status.success(),
        "static libibverbs metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8(output.stdout).expect("UTF-8 libibverbs metadata");
    shlex::split(&output).expect("valid shell-quoted libibverbs metadata")
}

fn main() {
    println!("cargo:rerun-if-changed=csrc/shim.c");
    println!("cargo:rerun-if-env-changed=RDMA_CORE_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR");
    if std::env::var_os("CARGO_FEATURE_VERBS").is_none() {
        return;
    }
    let dir =
        PathBuf::from(std::env::var_os("RDMA_CORE_DIR").unwrap_or_else(|| "/opt/rdma-core".into()));
    assert!(
        dir.join("lib/libibverbs.a").exists(),
        "{}/lib/libibverbs.a missing: build rdma-core static (RDMA_CORE_DIR)",
        dir.display()
    );
    let libs = static_libs(&dir);
    let mut shim = cc::Build::new();
    if std::env::var_os("CARGO_FEATURE_MEMORY_WINDOWS").is_some() {
        shim.define("FLASHSTORE_MEMORY_WINDOWS", None);
    }
    if std::env::var_os("CARGO_FEATURE_FAULT_INJECT").is_some() {
        shim.define("FLASHSTORE_FAULT_INJECT", None);
    }
    shim.file("csrc/shim.c")
        .include(dir.join("include"))
        .define("RDMA_STATIC_PROVIDERS", "all")
        .warnings(true)
        .compile("rdmashim");
    // Upstream emits libibverbs, every configured provider and libibverbs again, resolving the all-provider table
    // and provider-to-core dependencies. Preserve that order; do not deduplicate the repeated core archive.
    for flag in libs {
        if let Some(path) = flag.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={path}");
        } else if let Some(name) = flag.strip_prefix("-l") {
            // No repeated modifier declarations: upstream repeats libibverbs for static link ordering. Default
            // bundling also keeps native provider objects with this Rust library instead of requiring host .so files.
            println!("cargo:rustc-link-lib=static={name}");
        } else if flag == "-pthread" {
            println!("cargo:rustc-link-lib=pthread");
        } else {
            panic!("unsupported static libibverbs metadata flag: {flag}");
        }
    }
}
