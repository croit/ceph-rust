// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
//! Standalone offline engine-selection and non-mutating refusal regressions.
#![cfg(feature = "lab")]
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "sdb-cli-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn tool(args: &[&str]) -> std::process::Output {
    let o = Command::new("timeout")
        .args(["-k", "2", "15", env!("CARGO_BIN_EXE_croit-flashstore-tool")])
        .args(args)
        .output()
        .unwrap();
    assert_ne!(
        o.status.code(),
        Some(124),
        "WARNING TIMEOUT SplinterDB CLI regression exceeded 15s"
    );
    o
}
#[test]
fn invalid_engine_options_never_create_native_device() {
    let t = Temp::new();
    let p = t.0.join("must-not-exist");
    let spec = format!("file:{}", p.display());
    for (args, expected) in [
        (vec!["--omap-engine", "invalid"], "unknown OMAP engine"),
        (
            vec!["--omap-engine", "splinterdb", "--omap-lsm"],
            "conflicts",
        ),
    ] {
        let mut a = vec!["mkfs", "--dev", &spec];
        a.extend(args);
        let o = tool(&a);
        assert!(!o.status.success());
        assert!(
            String::from_utf8_lossy(&o.stderr).contains(expected),
            "{o:?}"
        );
        assert!(!p.exists());
    }
    #[cfg(not(feature = "splinterdb"))]
    {
        let o = tool(&["mkfs", "--dev", &spec, "--omap-engine", "splinterdb"]);
        assert!(!o.status.success());
        assert!(String::from_utf8_lossy(&o.stderr).contains("build with --features splinterdb"));
        assert!(!p.exists());
    }
    #[cfg(feature = "splinterdb")]
    {
        let o = tool(&[
            "mkfs",
            "--dev",
            &spec,
            "--omap-engine",
            "splinterdb",
            "--splinterdb-dir",
            t.0.to_str().unwrap(),
            "--splinterdb-capacity",
            "134217728",
            "--splinterdb-lab-filesystem",
            "--store-shards",
            "64",
        ]);
        assert!(!o.status.success());
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("at most 63 native shards"),
            "{o:?}"
        );
        assert!(!p.exists());
    }
    #[cfg(feature = "splinterdb")]
    for (flag, value, expected) in [
        ("--splinterdb-io", "invalid", "direct or buffered"),
        ("--splinterdb-prefetch-bytes", "0", "prefetch bytes"),
        ("--splinterdb-scan-readahead-pages", "17", "1..=16"),
    ] {
        let o = tool(&[
            "mkfs",
            "--dev",
            &spec,
            "--omap-engine",
            "splinterdb",
            "--splinterdb-dir",
            t.0.to_str().unwrap(),
            "--splinterdb-capacity",
            "134217728",
            "--splinterdb-lab-filesystem",
            "--store-shards",
            "1",
            flag,
            value,
        ]);
        assert!(!o.status.success());
        assert!(
            String::from_utf8_lossy(&o.stderr).contains(expected),
            "{o:?}"
        );
        assert!(!p.exists());
    }
}

#[cfg(feature = "splinterdb")]
#[test]
fn readonly_cli_refuses_before_any_native_or_foreign_write() {
    use nvme::any::{AnyCtrl, DevSpec};
    use store::dev::MonoClock;
    use store::layout::{MkfsParams, mkfs};
    let t = Temp::new();
    let native = t.0.join("native");
    std::fs::File::create(&native)
        .unwrap()
        .set_len(32 << 20)
        .unwrap();
    let spec = format!("file:{}", native.display());
    let sb = {
        let ctrl = AnyCtrl::open(&DevSpec::parse(&spec).unwrap(), false).unwrap();
        mkfs(
            &mut ctrl.open_queue().unwrap(),
            &mut MonoClock::default(),
            &MkfsParams {
                shards: 1,
                wal_blocks: 256,
                align_blocks: 1,
                omap_splinterdb: true,
                allow_volatile_cache: true,
                ..Default::default()
            },
        )
        .unwrap()
        .0
    };
    // Deliberately not a valid DB: a safety refusal must occur before open/recovery.
    let cfg = store::splinter_omap::Config::new(t.0.clone(), 0);
    let foreign = cfg.path(&sb, 0).unwrap();
    std::fs::create_dir(foreign.parent().unwrap()).unwrap();
    std::fs::write(&foreign, b"foreign sentinel, never open").unwrap();
    let before = std::fs::read(&native).unwrap();
    let fb = std::fs::read(&foreign).unwrap();
    for args in [
        vec!["fsck"],
        vec!["free"],
        vec!["upgrade", "--dry-run"],
        vec!["objectstore", "--op", "list"],
    ] {
        let mut a = args;
        a.extend(["--dev", &spec]);
        let o = tool(&a);
        assert!(!o.status.success());
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("SplinterDB read-only"),
            "{o:?}"
        );
        assert_eq!(std::fs::read(&native).unwrap(), before);
        assert_eq!(std::fs::read(&foreign).unwrap(), fb);
    }
}

#[cfg(feature = "splinterdb")]
#[test]
fn existing_foreign_identity_refuses_before_native_discard_even_with_wipe() {
    let t = Temp::new();
    let native = t.0.join("native");
    std::fs::write(&native, b"native sentinel").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&native)
        .unwrap()
        .set_len(32 << 20)
        .unwrap();
    let before = std::fs::read(&native).unwrap();
    let root = t.0.join("foreign");
    std::fs::create_dir(&root).unwrap();
    let cfg = store::splinter_omap::Config::new(root.clone(), 128 << 20);
    let dir = cfg.directory(&[0x44; 16]);
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("keep"), b"foreign sentinel").unwrap();
    let spec = format!("file:{}", native.display());
    let root = root.to_str().unwrap();
    let o = tool(&[
        "mkfs",
        "--dev",
        &spec,
        "--wipe",
        "--store-shards",
        "1",
        "--omap-engine",
        "splinterdb",
        "--splinterdb-dir",
        root,
        "--splinterdb-capacity",
        "134217728",
        "--splinterdb-lab-filesystem",
        "--osd-uuid",
        "44444444-4444-4444-4444-444444444444",
    ]);
    assert!(!o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("before native discard/format"),
        "{o:?}"
    );
    assert_eq!(std::fs::read(&native).unwrap(), before);
    assert_eq!(
        std::fs::read(dir.join("keep")).unwrap(),
        b"foreign sentinel"
    );
}
