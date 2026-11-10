// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Regression tests for `build.rs`: compiled with rustc and run against a fake `pkg-config` that models one
//! prefix closure, then the emitted cargo directives are asserted. Unix only (the fake pkg-config is a shell
//! script); DPDK itself is Linux only, so the tests need no DPDK tree.
#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A scratch directory for one test, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "dpdk-link-{}-{}-{tag}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Compile `build.rs` and return the binary.
fn build_script(scratch: &Scratch) -> PathBuf {
    let bin = scratch.join("build-script");
    let st = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string()))
        .args(["--edition", "2024", "-o"])
        .arg(&bin)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs"))
        .status()
        .expect("spawn rustc");
    assert!(st.success(), "rustc failed to compile build.rs");
    bin
}

/// Fake `pkg-config` for one prefix: `.pc` files live in `pc_dir`, `libs` is the `--static --libs` answer.
fn fake_pkg_config(scratch: &Scratch, pc_dir: &Path, libs: &str) -> PathBuf {
    fs::create_dir_all(pc_dir).unwrap();
    for pc in ["libdpdk.pc", "spdk_nvme.pc", "spdk_env_dpdk.pc"] {
        fs::write(pc_dir.join(pc), "# fake\n").unwrap();
    }
    let exe = scratch.join("pkg-config");
    let script = format!(
        r#"#!/bin/sh
case "$*" in
  *--variable=pcfiledir*) printf '%s\n' '{}';;
  *--variable=libdir*) printf '%s\n' '/opt/dpdk/lib';;
  *--modversion*) printf '%s\n' '26.07.0';;
  *) printf '%s\n' '{}';;
esac
"#,
        pc_dir.display(),
        libs
    );
    fs::write(&exe, script).unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    exe
}

struct Run {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// Run the build script with the fake pkg-config first on PATH and exactly the given cargo features.
fn run(bin: &Path, pkg_config: &Path, features: &[&str], env: &[(&str, &OsStr)]) -> Run {
    let mut cmd = Command::new(bin);
    let path = std::env::var("PATH").unwrap_or_default();
    cmd.env(
        "PATH",
        format!("{}:{path}", pkg_config.parent().unwrap().display()),
    );
    cmd.env_remove("CARGO_FEATURE_SPDK");
    cmd.env_remove("FLASHSTORE_LGPL_LINK");
    for f in features {
        cmd.env(format!("CARGO_FEATURE_{}", f.to_uppercase()), "1");
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run build.rs");
    Run {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

impl Run {
    fn count(&self, line: &str) -> usize {
        self.stdout.lines().filter(|l| *l == line).count()
    }

    /// Assert a successful run that emitted `line` verbatim.
    fn want(&self, line: &str) {
        assert!(self.ok, "build.rs failed: {}", self.stderr);
        assert!(
            self.count(line) == 1,
            "expected exactly one {line:?}; stdout:\n{}",
            self.stdout
        );
    }
}

#[test]
fn spdk_whole_archives_constructor_libs_without_pc_flags() {
    let s = Scratch::new("no-whole");
    let bin = build_script(&s);
    // A .pc without whole-archive markers must not decide the policy: PCI bus and mempool ops register
    // through constructors and are dropped by the linker without it.
    let libs = "-L/opt/spdk/lib -lspdk_nvme -l:librte_eal.a -l:librte_bus_pci.a -l:librte_mempool_ring.a -lnuma";
    let pc = fake_pkg_config(&s, &s.join("pc"), libs);
    let r = run(&bin, &pc, &["spdk"], &[]);
    r.want("cargo:rustc-link-lib=static:-bundle,+whole-archive=rte_bus_pci");
    r.want("cargo:rustc-link-lib=static:-bundle,+whole-archive=rte_mempool_ring");
    r.want("cargo:rustc-link-lib=static:-bundle=rte_eal");
    r.want("cargo:rustc-link-lib=dylib=numa");
}

#[test]
fn static_lgpl_mode_links_libnuma_static() {
    let s = Scratch::new("static-numa");
    let bin = build_script(&s);
    let pc = fake_pkg_config(&s, &s.join("pc"), "-L/opt/spdk/lib -l:librte_eal.a -lnuma");
    let r = run(
        &bin,
        &pc,
        &["spdk"],
        &[("FLASHSTORE_LGPL_LINK", OsStr::new("static"))],
    );
    r.want("cargo:rustc-link-lib=static:-bundle=numa");
}

#[test]
fn spdk_tracks_its_resolved_pc_files() {
    let s = Scratch::new("spdk-rerun");
    let bin = build_script(&s);
    let pc_dir = s.join("pc");
    let pc = fake_pkg_config(
        &s,
        &pc_dir,
        "-L/opt/spdk/lib -lspdk_nvme -lspdk_env_dpdk -lrte_eal -lnuma",
    );
    let r = run(&bin, &pc, &["spdk"], &[]);
    for pc in ["libdpdk.pc", "spdk_nvme.pc", "spdk_env_dpdk.pc"] {
        r.want(&format!(
            "cargo:rerun-if-changed={}",
            pc_dir.join(pc).display()
        ));
    }
    r.want("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    r.want("cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR");
    r.want("cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR");
}

#[test]
fn spdk_links_archive_form_rte_libs() {
    let s = Scratch::new("spdk-archive");
    let bin = build_script(&s);
    let libs = "-L/opt/spdk/lib -lspdk_nvme -lspdk_env_dpdk -l:librte_eal.a -l:librte_bus_pci.a -l:librte_mempool_ring.a -lnuma -lpthread";
    let pc = fake_pkg_config(&s, &s.join("pc"), libs);
    let r = run(&bin, &pc, &["spdk"], &[]);
    r.want("cargo:rustc-link-search=native=/opt/dpdk/lib");
    r.want("cargo:rustc-link-lib=static:-bundle=rte_eal");
    r.want("cargo:rustc-link-lib=static:-bundle,+whole-archive=rte_bus_pci");
    r.want("cargo:rustc-link-lib=static:-bundle,+whole-archive=rte_mempool_ring");
    r.want("cargo:rustc-link-lib=dylib=numa");
    // the SPDK archives themselves are linked by crates/nvme/build.rs
    assert_eq!(r.count("cargo:rustc-link-lib=static:-bundle=spdk_nvme"), 0);
}

#[test]
fn unsupported_library_token_fails_loudly() {
    let s = Scratch::new("bad-token");
    let bin = build_script(&s);
    let pc = fake_pkg_config(&s, &s.join("pc"), "-L/opt/dpdk/lib -l:librte_eal.so");
    let r = run(&bin, &pc, &["spdk"], &[]);
    assert!(
        !r.ok,
        "an unparsable -l token must fail; stdout:\n{}",
        r.stdout
    );
    assert!(
        r.stderr.contains("-l:librte_eal.so"),
        "stderr does not name the token: {}",
        r.stderr
    );
}
