// SPDX-License-Identifier: LGPL-3.0-only
use std::path::{Path, PathBuf};

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("SplinterDB source directory")
        .map(|e| e.expect("source entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "c") {
            out.push(path);
        }
    }
}

/// Copies `from` into `to` recursively (fresh `to`).
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("patched source directory");
    for e in std::fs::read_dir(from).expect("SplinterDB source directory") {
        let p = e.expect("source entry").path();
        let dst = to.join(p.file_name().expect("entry name"));
        if p.is_dir() {
            copy_tree(&p, &dst);
        } else {
            std::fs::copy(&p, &dst).expect("copy SplinterDB source");
        }
    }
}

/// Our patch series over the pinned sources (`patches/series`, in order). With
/// any patch, the sources are copied to OUT_DIR and patched there; the submodule
/// itself is never modified.
fn patched_root(pinned: &Path) -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("patches");
    println!("cargo:rerun-if-changed={}", dir.display());
    let series: Vec<PathBuf> = std::fs::read_to_string(dir.join("series"))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| dir.join(l))
        .collect();
    if series.is_empty() {
        return pinned.to_path_buf();
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("splinterdb");
    let _ = std::fs::remove_dir_all(&out);
    copy_tree(&pinned.join("src"), &out.join("src"));
    copy_tree(&pinned.join("include"), &out.join("include"));
    for patch in series {
        println!("cargo:rerun-if-changed={}", patch.display());
        // Outside any repository (ceiling), so paths are relative to `out`.
        let status = std::process::Command::new("git")
            .current_dir(&out)
            .env(
                "GIT_CEILING_DIRECTORIES",
                out.parent().expect("OUT_DIR parent"),
            )
            .args(["apply", "-p1", "--whitespace=nowarn"])
            .arg(&patch)
            .status()
            .expect("git is required to apply the SplinterDB patch series");
        assert!(
            status.success(),
            "SplinterDB patch failed: {}",
            patch.display()
        );
    }
    out
}

fn main() {
    println!("cargo:rerun-if-env-changed=XXHASH_PREFIX");
    if std::env::var_os("CARGO_FEATURE_NATIVE").is_none() {
        return;
    }
    assert_eq!(
        std::env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("linux"),
        "the optional SplinterDB engine currently supports Linux only"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../third_party/splinterdb");
    assert!(
        root.join("include/splinterdb/splinterdb.h").is_file(),
        "SplinterDB source missing: run git submodule update --init -- third_party/splinterdb"
    );
    let revision = std::process::Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git is required to verify the SplinterDB source pin");
    assert!(
        revision.status.success()
            && String::from_utf8_lossy(&revision.stdout).trim()
                == "73f89d8879e2e5603933f756c8c4d2c60a12d9c6",
        "SplinterDB submodule revision differs from the audited binding: update the dependency and binding together"
    );
    let pinned = root;
    let root = patched_root(&pinned);
    let mut files = Vec::new();
    sources(&root.join("src"), &mut files);
    let mut build = cc::Build::new();
    build
        .files(&files)
        .file("csrc/binding.c")
        .include(root.join("include"))
        .include(root.join("src"))
        .include(root.join("src/platform_linux"))
        .define("_GNU_SOURCE", None)
        .define("XXH_STATIC_LINKING_ONLY", None)
        // Use xxHash's supported private-inline mode. LZ4 also carries an older
        // xxHash object; do not interpose or duplicate its global XXH symbols.
        .define("XXH_INLINE_ALL", None)
        .define("SPLINTERDB_PLATFORM_DIR", "platform_linux")
        .define(
            "GIT_VERSION",
            "\"73f89d8879e2e5603933f756c8c4d2c60a12d9c6\"",
        )
        .flag_if_supported("-std=gnu11")
        .flag_if_supported("-pthread")
        .pic(true)
        .warnings(false);
    if let Some(prefix) = std::env::var_os("XXHASH_PREFIX") {
        let prefix = PathBuf::from(prefix);
        build.include(prefix.join("include"));
    }
    let mut pinned_files = Vec::new();
    sources(&pinned.join("src"), &mut pinned_files);
    for path in pinned_files {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        pinned.join("include").display()
    );
    println!("cargo:rerun-if-changed={}", pinned.join("src").display());
    println!("cargo:rerun-if-changed=csrc/binding.c");
    build.compile("nvmeosd_splinterdb");
    println!("cargo:rustc-link-lib=aio");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=m");
}
