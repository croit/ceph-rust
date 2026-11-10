// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
// Compiles the EAL shim (csrc/shim.c). The DPDK archives are linked once by crate dpdk-link (feature spdk); this script only
// needs the include flags (`pkg-config --cflags libdpdk`, PKG_CONFIG_PATH=/opt/dpdk/lib/pkgconfig).
use std::process::Command;

fn main() {
    if std::env::var_os("CARGO_FEATURE_SPDK").is_none() {
        return;
    }
    println!("cargo:rerun-if-changed=csrc/shim.c");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    let out = Command::new("pkg-config")
        .args(["--cflags", "libdpdk"])
        .output()
        .expect("pkg-config not found (set PKG_CONFIG_PATH=/opt/dpdk/lib/pkgconfig)");
    assert!(
        out.status.success(),
        "pkg-config libdpdk failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut cc = cc::Build::new();
    cc.file("csrc/shim.c").warnings(true);
    for f in String::from_utf8(out.stdout).unwrap().split_whitespace() {
        if let Some(p) = f.strip_prefix("-I") {
            cc.include(p);
        } else if f.starts_with("-D") || f.starts_with("-m") {
            cc.flag(f);
        }
    }
    cc.compile("nvshim");
}
