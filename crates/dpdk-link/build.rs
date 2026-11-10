// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
// The ONE place that links the native DPDK archives (needs the `pkg-config` binary, PKG_CONFIG_PATH=/opt/dpdk/lib/pkgconfig
// + /opt/spdk/lib/pkgconfig). Crates that need DPDK depend on this crate with feature `spdk` instead of linking it themselves:
// the rte_* archives SPDK's env_dpdk pulls in (SPDK pkg-config order). crates/nvme (SPDK driver) and crates/eal-heap (EAL
// hugepage heap) both use it.
use std::path::Path;
use std::process::Command;

/// Constructor-registered DPDK archives (drivers, buses, mempool ops): the linker drops them without
/// +whole-archive. This policy is ours, not the `.pc` file's.
const CONSTRUCTOR: [&str; 4] = ["rte_net_", "rte_bus_", "rte_mempool_", "rte_common_"];

fn pkg(pkgs: &[&str], args: &[&str]) -> String {
    let out = Command::new("pkg-config")
        .args(args)
        .args(pkgs)
        .output()
        .expect("pkg-config not found (set PKG_CONFIG_PATH=/opt/dpdk/lib/pkgconfig:/opt/spdk/lib/pkgconfig)");
    assert!(
        out.status.success(),
        "pkg-config {pkgs:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// `rerun-if-changed` for the resolved `.pc` files: a rebuilt DPDK/SPDK prefix at the same PKG_CONFIG_PATH
/// must not keep the old link line and DEP_DPDK_PMDS/DEP_DPDK_VERSION.
fn track_pc(pkgs: &[&str]) {
    for p in pkgs {
        let dir = pkg(&[p], &["--variable=pcfiledir"]);
        println!(
            "cargo:rerun-if-changed={}",
            Path::new(dir.trim()).join(format!("{p}.pc")).display()
        );
    }
}

/// Link kind of the LGPL-only C deps (libnuma): `FLASHSTORE_LGPL_LINK=dynamic` (default: the distro shared
/// libs, declared as package dependencies) or `static` (opt-in fully static build, `scripts/package.sh --all-static`,
/// which ships their sources for relinking). The single switch for both modes; doc/ops/packages.md.
fn lgpl_kind() -> &'static str {
    match std::env::var("FLASHSTORE_LGPL_LINK").as_deref() {
        Err(_) | Ok("dynamic") => "dylib",
        Ok("static") => "static:-bundle",
        Ok(v) => panic!("FLASHSTORE_LGPL_LINK={v}: expected dynamic or static"),
    }
}

/// Emit one `rustc-link-lib` with link kind `modifier` (`static:-bundle`, `static:-bundle,+whole-archive`, `dylib`, ...).
fn link_lib(modifier: &str, name: &str) {
    println!("cargo:rustc-link-lib={modifier}={name}");
}

/// Library name of a `-l` token: plain `-lX` or archive `-l:libX.a`. Any other `-l:` spelling fails loudly
/// instead of being skipped (the link would fail later with undefined symbols, far from the cause).
fn lib_name(t: &str) -> Option<&str> {
    if t.starts_with("-l:") {
        return Some(
            t.strip_prefix("-l:lib")
                .and_then(|n| n.strip_suffix(".a"))
                .unwrap_or_else(|| {
                    panic!("unparsable library token {t}: expected -l<name> or -l:lib<name>.a")
                }),
        );
    }
    t.strip_prefix("-l")
}

/// One static rte_* archive; constructor-registered prefixes keep all their objects.
fn link_dpdk_archive(name: &str) {
    let m = if CONSTRUCTOR.iter().any(|p| name.starts_with(p)) {
        "static:-bundle,+whole-archive"
    } else {
        "static:-bundle"
    };
    link_lib(m, name);
}

fn main() {
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR");
    println!("cargo:rerun-if-env-changed=FLASHSTORE_LGPL_LINK");
    if std::env::var_os("CARGO_FEATURE_SPDK").is_some() {
        link_for_spdk();
    }
}

/// SPDK-only: its pkg-config files list the rte_* archives env_dpdk needs, in dependency order.
fn link_for_spdk() {
    track_pc(&["libdpdk", "spdk_nvme", "spdk_env_dpdk"]);
    // DPDK archive dir (SPDK .pc files do not carry -L for it).
    println!(
        "cargo:rustc-link-search=native={}",
        pkg(&["libdpdk"], &["--variable=libdir"]).trim()
    );
    for t in pkg(&["spdk_nvme", "spdk_env_dpdk"], &["--static", "--libs"]).split_whitespace() {
        // the SDK archives and system libs come from crates/nvme/build.rs, libnuma is emitted below
        if let Some(n) = lib_name(t).filter(|n| n.starts_with("rte_")) {
            link_dpdk_archive(n);
        }
    }
    // rte_eal needs libnuma and must precede it on the link line: the archive order is ours to keep, so emit it here
    link_lib(lgpl_kind(), "numa");
}
