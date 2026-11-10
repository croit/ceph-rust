// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
// SPDK link setup, only with feature `spdk`. Uses the `pkg-config` binary (static spdk_nvme + spdk_env_dpdk;
// set PKG_CONFIG_PATH=/opt/spdk/lib/pkgconfig:/opt/dpdk/lib/pkgconfig). Constructor-registered DPDK drivers
// (PCI bus, mempool ring) get +whole-archive.
use std::process::Command;

fn pkg(args: &[&str]) -> String {
    let out = Command::new("pkg-config")
        .args(args)
        .args(["spdk_nvme", "spdk_env_dpdk"])
        .output()
        .expect("pkg-config not found");
    assert!(
        out.status.success(),
        "pkg-config spdk failed (PKG_CONFIG_PATH=/opt/spdk/lib/pkgconfig:/opt/dpdk/lib/pkgconfig): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn main() {
    println!("cargo:rerun-if-changed=csrc/shim.c");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    if std::env::var_os("CARGO_FEATURE_SPDK").is_none() {
        return;
    }
    let mut cc = cc::Build::new();
    cc.file("csrc/shim.c").warnings(true);
    for f in pkg(&["--cflags"]).split_whitespace() {
        if let Some(p) = f.strip_prefix("-I") {
            cc.include(p);
        } else if f.starts_with("-D") || f.starts_with("-m") {
            cc.flag(f);
        }
    }
    cc.compile("nvsshim");

    // Our shim is linked first (cc emits its link line before ours), then SPDK + DPDK archives. The SPDK .pc
    // list has them in dependency order; static archives need grouping because of mutual references.
    let libs = pkg(&["--static", "--libs"]);
    let mut spdk = Vec::new();
    let mut other = Vec::new();
    for t in libs.split_whitespace() {
        if let Some(p) = t.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={p}");
        } else if let Some(n) = t.strip_prefix("-l") {
            if n.starts_with("spdk_") {
                spdk.push(n.to_string());
            } else if !n.starts_with("rte_") {
                other.push(n.to_string()); // system libs; the rte_* archives are linked by crate dpdk-link (feature spdk)
            }
        }
    }
    for n in &spdk {
        let m = if matches!(n.as_str(), "spdk_env_dpdk" | "spdk_nvme") {
            "static:-bundle,+whole-archive"
        } else {
            "static:-bundle"
        };
        println!("cargo:rustc-link-lib={m}={n}");
    }
    for n in &other {
        println!("cargo:rustc-link-lib={n}");
    }
    // SPDK bundles ISA-L (crc32_iscsi, crc16_t10dif, ...) next to its libs; its .pc files do not list it, whole-archive spdk_nvme needs it.
    println!("cargo:rustc-link-lib=static:-bundle=isal");
    // Permissive deps static (uuid, ssl, crypto, zstd, z); libnuma comes from dpdk-link (after these archives, link kind
    // per FLASHSTORE_LGPL_LINK); glibc dynamic.
    for sys in ["uuid", "ssl", "crypto", "zstd", "z"] {
        println!("cargo:rustc-link-lib=static:-bundle={sys}");
    }
    for sys in ["m", "dl", "pthread", "rt"] {
        println!("cargo:rustc-link-lib={sys}");
    }
}
