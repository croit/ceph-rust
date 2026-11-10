// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Storage-free dispatch regression for the lab-disabled kernel provisioning tool.
#![cfg(all(
    target_os = "linux",
    feature = "kernel-nvme",
    feature = "mon-std",
    not(feature = "lab"),
    not(feature = "spdk")
))]

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn run(args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_croit-flashstore-tool"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("WARNING TIMEOUT CLI argument rejection exceeded 10s ({args:?})");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn prepare_is_present_without_lab_or_spdk() {
    let out = run(&["prepare"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("prepare --dev"), "{stderr}");
    assert!(!stderr.contains("prepare|activate"), "{stderr}");
}

#[test]
fn invalid_device_specs_are_rejected_before_host_or_monitor_access() {
    for spec in ["kernel:relative", "file:/never-create-kernel-cli-fixture"] {
        let out = run(&["prepare", "--dev", spec]);
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains("bad --dev"), "{stderr}");
        assert!(!stderr.contains("prepare|activate"), "{stderr}");
        assert!(!stderr.contains("no mon_host"), "{stderr}");
    }
}

#[test]
fn backend_argument_errors_do_not_open_devices() {
    for args in [
        vec!["prepare", "--store-backend"],
        vec![
            "prepare",
            "--dev",
            "kernel:relative",
            "--store-backend",
            "bad",
        ],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{out:?}");
    }
}

const USAGE: &str = "usage: croit-flashstore-tool hwcheck | host-tune";

#[test]
fn lab_commands_remain_unavailable() {
    for cmd in ["bench", "crash"] {
        let out = run(&[cmd]);
        assert_eq!(out.status.code(), Some(2));
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains(USAGE), "{stderr}");
        assert!(
            !stderr.contains("bench"),
            "usage lists only compiled commands: {stderr}"
        );
    }
}

/// A record stream with zero rows is zero bytes: `--format jsonl` must not print a blank line (an empty line is not a
/// JSON record), while the array form still prints an empty array.
#[test]
fn empty_record_stream_writes_no_jsonl_line() {
    let root = std::env::temp_dir().join(format!(
        "croit-flashstore-tool-empty-{}",
        std::process::id()
    ));
    assert!(!root.exists(), "{} must not exist", root.display());
    let root = root.to_str().unwrap();
    let jsonl = run(&["list", "--osd-data-root", root, "--format", "jsonl"]);
    assert_eq!(jsonl.status.code(), Some(0), "{jsonl:?}");
    assert!(
        jsonl.stdout.is_empty(),
        "jsonl wrote {:?}",
        String::from_utf8_lossy(&jsonl.stdout)
    );
    let json = run(&["list", "--osd-data-root", root, "--format", "json"]);
    assert_eq!(json.status.code(), Some(0), "{json:?}");
    assert_eq!(String::from_utf8(json.stdout).unwrap(), "[]\n");
}

/// T1: the packaged (kernel-only) tool has the documented store maintenance and PG export commands: each answers with
/// its own argument error (no device given), not the general usage, and the general usage lists them.
#[test]
fn store_maintenance_is_present_without_lab_or_spdk() {
    for cmd in [
        "fsck",
        "repair",
        "sizes",
        "expand",
        "free",
        "upgrade",
        "objectstore",
        "raw",
        "dump",
        "support-bundle",
    ] {
        let out = run(&[cmd]);
        assert_eq!(out.status.code(), Some(2), "{cmd}: {out:?}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(!stderr.contains(USAGE), "{cmd} not compiled in: {stderr}");
    }
    let stderr = String::from_utf8(run(&["help"]).stderr).unwrap();
    for cmd in [
        "fsck",
        "repair",
        "upgrade",
        "objectstore",
        "raw",
        "prepare",
        "activate",
        "dump",
        "support-bundle",
    ] {
        assert!(stderr.contains(cmd), "usage misses {cmd}: {stderr}");
    }
}
