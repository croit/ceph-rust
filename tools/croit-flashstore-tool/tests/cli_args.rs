// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! CLI robustness (src/main.rs option helpers, src/raw.rs, src/bench*.rs, src/lifecycle.rs, src/ops.rs): a malformed or
//! zero-valued option, a foreign crash ledger and an unreadable superblock end in a message and an exit code, never in a
//! panic or a loop that never returns. The tool binary is run as a black box against a real `file:` device.
#![cfg(feature = "lab")]

use nvme::any::{AnyCtrl, DevSpec};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use store::dev::MonoClock;
use store::layout::{MkfsParams, mkfs};

const MIB: u64 = 1 << 20;
/// A run that has not finished by then is a hang (the option validation it tests never waits for a device).
const RUN_LIMIT: Duration = Duration::from_secs(60);

struct Dev {
    root: PathBuf,
    img: PathBuf,
}

impl Dev {
    fn new(name: &str, mib: u64) -> Dev {
        let root = std::env::temp_dir().join(format!(
            "croit-flashstore-tool-cli-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let img = root.join("dev.img");
        std::fs::File::create(&img)
            .unwrap()
            .set_len(mib * MIB)
            .unwrap();
        Dev { root, img }
    }

    fn spec(&self) -> String {
        format!("file:{}", self.img.display())
    }

    fn ctrl(&self) -> AnyCtrl {
        AnyCtrl::open(&DevSpec::parse(&self.spec()).unwrap(), false).unwrap()
    }

    /// A store like the OSD makes it (a handful of shards; the tool's own mkfs needs a mon).
    fn mkfs(&self) {
        let ctrl = self.ctrl();
        let mut d = ctrl.open_queue().unwrap();
        let p = MkfsParams {
            shards: 2,
            wal_blocks: 1024,
            align_blocks: 1,
            meta_pct: 4,
            allow_volatile_cache: true,
            ..Default::default()
        };
        mkfs(&mut d, &mut MonoClock::default(), &p).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_croit-flashstore-tool"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + RUN_LIMIT;
        loop {
            if child.try_wait().unwrap().is_some() {
                return child.wait_with_output().unwrap();
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!(
                    "WARNING TIMEOUT {args:?} exceeded {:.3}s",
                    RUN_LIMIT.as_secs_f64()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The command must fail (not panic, not hang) and say why on stderr.
    fn rejects(&self, args: &[&str], want: &str) {
        let o = self.run(args);
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.status.code(), Some(1), "{args:?}\nstderr: {err}");
        assert!(err.contains(want), "{args:?}: wanted {want:?} in {err}");
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// `--pgs 0` / `--clients 0` / `--qd 0` divided by zero, unwrapped an empty vector or queued nothing at all.
#[test]
fn zero_valued_counts_are_rejected() {
    let d = Dev::new("zero", 256);
    let spec = d.spec();
    d.rejects(&["bench", "--dev", &spec, "--pgs", "0"], "--pgs 0");
    d.rejects(&["bench-read", "--pgs", "0"], "--pgs 0");
    d.rejects(&["bench-read", "--clients", "0"], "--clients 0");
    d.rejects(&["bench-read", "--qd", "0"], "--qd 0");
    d.rejects(&["bench-full", "--qd", "0"], "--qd 0");
    d.rejects(&["bench-purge", "--qd", "0"], "--qd 0");
}

/// `jrnl4k:0` and `--secs 0` issued no append and then indexed `(pos - 1)` of an empty journal (underflow panic).
#[test]
fn zero_queue_depth_and_secs_in_the_journal_modes_are_rejected() {
    let d = Dev::new("jrnl", 256);
    let spec = d.spec();
    d.rejects(
        &["bench", "--dev", &spec, "--fs", "jrnl4k:0"],
        "--fs jrnl4k:0: qd 0",
    );
    d.rejects(
        &["bench", "--dev", &spec, "--fs", "jrnl4k:1", "--secs", "0"],
        "--secs 0 runs no append",
    );
    d.rejects(
        &["bench", "--dev", &spec, "--modes", "rw4k:0"],
        "bad mode rw4k:0",
    );
    // above the in-flight window the token ring cannot keep one slot per live token
    d.rejects(
        &["bench", "--dev", &spec, "--fs", "jrnl4k:8000"],
        "above the 4096-slot in-flight window",
    );
}

/// A value that does not parse used to be replaced by the default: a typo changed the measurement silently.
#[test]
fn malformed_numbers_are_rejected() {
    let d = Dev::new("num", 256);
    let spec = d.spec();
    d.rejects(
        &["bench", "--dev", &spec, "--secs", "abc"],
        "--secs: not a number",
    );
    d.rejects(
        &["bench", "--dev", &spec, "--pgs", "abc"],
        "--pgs: not a number",
    );
    d.rejects(
        &["bench", "--dev", &spec, "--cpu", "abc"],
        "--cpu: not a number",
    );
    d.rejects(
        &["raw", "--dev", &spec, "--secs", "abc"],
        "--secs: not a number",
    );
    d.rejects(
        &["raw", "--dev", &spec, "--region-mib", "abc"],
        "--region-mib: not a number",
    );
    d.rejects(
        &["raw", "--dev", &spec, "--offset-mib", "abc"],
        "--offset-mib: not a number",
    );
    d.rejects(
        &[
            "raw",
            "--dev",
            &spec,
            "--bs",
            "1m",
            "--region-mib",
            "1",
            "--qdepth",
            "abc",
        ],
        "--qdepth: not a number",
    );
    d.rejects(
        &["mkfs", "--dev", &spec, "--store-size", "abc"],
        "--store-size: not a number",
    );
}

/// A hand-edited or half-written ledger named txn ids the run cannot have (index out of bounds on the ack bitmap).
#[test]
fn crash_verify_rejects_a_foreign_ledger() {
    let d = Dev::new("ledger", 96);
    d.mkfs();
    let spec = d.spec();
    let ledger = d.root.join("ledger");
    std::fs::write(&ledger, [0xffu8; 8]).unwrap();
    let l = ledger.display().to_string();
    d.rejects(
        &["crash", "verify", "--dev", &spec, "--ledger", &l],
        "--ledger: record 0 (offset 0) names txn",
    );
    // a killed writer can have left a partial record
    std::fs::write(&ledger, [0u8; 12]).unwrap();
    d.rejects(
        &["crash", "verify", "--dev", &spec, "--ledger", &l],
        "4 trailing byte(s)",
    );
}

/// `--region-mib`/`--offset-mib` were shifted without a range check: a value above 2^44 MiB wrapped to a smaller offset
/// (and with `--write` wrote there).
#[test]
fn raw_region_and_offset_cannot_wrap() {
    let d = Dev::new("raw", 64);
    let spec = d.spec();
    d.rejects(
        &["raw", "--dev", &spec, "--offset-mib", "17592186044416"],
        "--offset-mib 17592186044416: above",
    );
    d.rejects(
        &[
            "raw",
            "--dev",
            &spec,
            "--region-mib",
            "17592186044416",
            "--secs",
            "0",
        ],
        "--region-mib 17592186044416: above",
    );
    d.rejects(
        &[
            "raw",
            "--dev",
            &spec,
            "--offset-mib",
            "1024",
            "--region-mib",
            "1",
            "--secs",
            "0",
        ],
        "is not inside the",
    );
}

fn json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("not json ({e}): {s}"))
}

/// `inspect` still prints the geometry/SMART part, but a device without a readable store identity is an error (exit 1),
/// not a document a script reads as a healthy OSD.
#[test]
fn inspect_reports_an_unreadable_superblock() {
    let d = Dev::new("inspect", 8);
    let spec = d.spec();
    let o = d.run(&["inspect", "--dev", &spec, "--format", "json"]);
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    let v = json(&String::from_utf8_lossy(&o.stdout));
    assert!(v["superblock"]["error"].is_string(), "{v}");
    assert_eq!(v["geometry"]["lba_size"], 4096, "{v}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("superblock: no croit-flashstore-osd store"),
        "{err}"
    );
}

/// `free` only reads allocator state: it must not replay/heal/checkpoint the device (the mount used to be read-write,
/// which rewrote the superblock of a store an older build had written).
#[test]
fn free_does_not_write() {
    let d = Dev::new("freero", 64);
    d.mkfs();
    // a store from a build before FEAT_LOG_DUPS: the read-write mount sets the sticky bit and heals the superblock
    {
        let ctrl = d.ctrl();
        let mut q = ctrl.open_queue().unwrap();
        let mut clk = MonoClock::default();
        let (mut sb, _) = store::layout::read_super(&mut q, &mut clk).unwrap();
        sb.features &= !store::layout::FEAT_LOG_DUPS;
        store::layout::heal_super(&mut q, &mut clk, &sb).unwrap();
    }
    let spec = d.spec();
    let before = std::fs::read(&d.img).unwrap();
    let o = d.run(&["free", "--dev", &spec, "--format", "json"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(json(&String::from_utf8_lossy(&o.stdout))["free_bytes"].is_number());
    assert!(
        before == std::fs::read(&d.img).unwrap(),
        "free wrote to the device"
    );
    // the read-only mount still sees the replay: fsck compares the same state and stays clean
    let o = d.run(&["fsck", "--dev", &spec]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
}

/// An explicit malformed identity must not register a new OSD or even create its device.
#[test]
fn provisioning_rejects_invalid_ids_before_device_creation() {
    let d = Dev::new("provision-id", 8);
    let missing = d.root.join("must-not-create.img");
    let spec = format!("file:{},size=8M", missing.display());
    for cmd in ["prepare", "mkfs"] {
        for id in ["invalid", "-1", "2147483648", "--wipe"] {
            let o = d.run(&[cmd, "--dev", &spec, "--id", id, "--no-host-checks"]);
            assert_eq!(o.status.code(), Some(2), "{cmd} {id}: {o:?}");
            assert!(!missing.exists(), "{cmd} {id} created a device");
        }
        let o = d.run(&[cmd, "--dev", &spec, "--no-host-checks", "--id"]);
        assert_eq!(o.status.code(), Some(2), "{cmd}: {o:?}");
        assert!(!missing.exists());
    }
}

/// Losing an explicit conf must not choose default storage options before a destructive operation.
#[test]
fn provisioning_refuses_unreadable_explicit_conf_before_device_creation() {
    let d = Dev::new("provision-conf", 8);
    let missing = d.root.join("must-not-create.img");
    let spec = format!("file:{},size=8M", missing.display());
    for cmd in ["prepare", "mkfs"] {
        // Missing explicit file and existing directory both used to silently become default options.
        for conf in [d.root.join("missing.conf"), d.root.clone()] {
            let conf = conf.display().to_string();
            let o = d.run(&[
                cmd,
                "--dev",
                &spec,
                "--conf",
                &conf,
                "--no-host-checks",
                "--mon-host",
                "127.0.0.1:1",
            ]);
            assert_eq!(
                o.status.code(),
                Some(if cmd == "prepare" { 3 } else { 1 }),
                "{cmd}: {o:?}"
            );
            assert!(String::from_utf8_lossy(&o.stderr).contains(&conf), "{o:?}");
            assert!(
                !missing.exists(),
                "{cmd} created a device after losing conf"
            );
        }
    }
}

/// A value-taking option that ends the command line without its value is a usage error, never "option not given".
#[test]
fn trailing_rocksdb_dir_without_value_is_a_usage_error() {
    let d = Dev::new("rocksdb-dir", 8);
    let o = d.run(&["fsck", "--dev", &d.spec(), "--rocksdb-dir"]);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(String::from_utf8_lossy(&o.stderr).contains("--rocksdb-dir needs a value"));
}

/// A target the OSD dir check refuses is refused before the device is formatted and before the mon is asked
/// (the mon address is unreachable: reaching it would be a different error and a formatted image).
#[test]
fn prepare_refuses_a_foreign_osd_dir_before_touching_device_or_mon() {
    let d = Dev::new("prepare-foreign-dir", 8);
    let spec = d.spec();
    let before = std::fs::read(&d.img).unwrap();
    let root = d.root.join("osd");
    let run = |extra: &[&str]| {
        let mut a = vec![
            "prepare",
            "--dev",
            &spec,
            "--no-host-checks",
            "--mon-host",
            "127.0.0.1:1",
            "--osd-data-root",
            root.to_str().unwrap(),
        ];
        a.extend(extra);
        d.run(&a)
    };
    // --id given: the dir of another OSD identity
    let dir = root.join("ceph-7");
    osddir::OsdDir {
        whoami: 7,
        osd_uuid: "foreign-osd".into(),
        cluster_fsid: "foreign-cluster".into(),
        dev: "file:/elsewhere".into(),
        crush_device_class: "nvme".into(),
        keyring: osddir::keyring_text(7, "k"),
    }
    .write(&dir)
    .unwrap();
    let o = run(&["--id", "7"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(
        err.contains("not this OSD") && err.contains("re-run"),
        "{err}"
    );
    assert!(
        before == std::fs::read(&d.img).unwrap(),
        "device was written"
    );
    // no --id: an unusable data root is refused before the device is touched as well
    std::fs::remove_dir_all(&root).unwrap();
    std::fs::write(&root, "not a directory").unwrap();
    let o = run(&[]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(err.contains("osd data root"), "{err}");
    assert!(
        before == std::fs::read(&d.img).unwrap(),
        "device was written"
    );
}

/// `--dev=SPEC` is `--dev SPEC` for every subcommand (one `--opt=value` split in `main`): `inspect --dev=X --id N` used to
/// inspect osd.N instead of the device X, `prepare`/`mkfs` reported "--dev required" for a given `--dev=`.
#[test]
fn equals_form_device_selects_the_device_like_the_space_form() {
    let d = Dev::new("equals-dev", 8);
    let spec = d.spec();
    let eq = format!("--dev={spec}");
    // inspect: the device is inspected although `--id` names another source
    let o = d.run(&["inspect", &eq, "--id", "99", "--format", "json"]);
    let v = json(&String::from_utf8_lossy(&o.stdout));
    assert_eq!(v["geometry"]["lba_size"], 4096, "{o:?}");
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    // prepare / mkfs: the device spec is read (and refused as a bad spec), not reported missing
    for cmd in ["prepare", "mkfs"] {
        let o = d.run(&[cmd, "--dev=bogus:x", "--no-host-checks"]);
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(!err.contains("--dev SPEC"), "{cmd}: {err}");
        assert!(err.contains("bogus"), "{cmd}: {err}");
    }
}
