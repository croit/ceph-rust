// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Offline store maintenance (src/ops.rs) against a real `file:` device: fsck/repair, sizes, expand after the
//! file grew, free space. The tool binary is run as a black box.
#![cfg(feature = "lab")]

use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT, Uuid};
use nvme::any::{AnyCtrl, DevSpec};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use store::dev::MonoClock;
use store::layout::{MkfsParams, mkfs};
use store::obj::OTxn;

const MIB: u64 = 1 << 20;

/// `flock` belongs to the open file description, and a child forked while the description is open keeps a copy until
/// its `exec` closes it (`O_CLOEXEC`): a sibling test's `Command::spawn` that overlaps an in-process exclusive open
/// can keep the device locked for a moment after the owner dropped it. In-process exclusive holders and
/// spawns therefore exclude each other (the spawn returns after `exec`, so no child outlives the guard with the fd).
static FORK_VS_LOCK: Mutex<()> = Mutex::new(());

fn fork_guard() -> MutexGuard<'static, ()> {
    FORK_VS_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Lab {
    root: PathBuf,
    dev: PathBuf,
}

impl Lab {
    fn new(name: &str, mib: u64) -> Lab {
        let root = std::env::temp_dir().join(format!(
            "croit-flashstore-tool-ops-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let dev = root.join("dev.img");
        std::fs::File::create(&dev)
            .unwrap()
            .set_len(mib * MIB)
            .unwrap();
        Lab { root, dev }
    }
    fn spec(&self) -> String {
        format!("file:{}", self.dev.display())
    }
    fn grow(&self, mib: u64) {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&self.dev)
            .unwrap()
            .set_len(mib * MIB)
            .unwrap();
    }
    fn mkfs(&self) {
        let ctrl = AnyCtrl::open(&DevSpec::parse(&self.spec()).unwrap(), false).unwrap();
        let mut d = ctrl.open_queue().unwrap();
        let p = MkfsParams {
            shards: 2,
            wal_blocks: 1024,
            align_blocks: 1,
            meta_pct: 4,
            osd_fsid: [7; 16],
            cluster_fsid: [9; 16],
            osd_id: 5,
            mkfs_time: 1_760_000_000,
            allow_volatile_cache: true,
            elastic_meta: true,
            compact_int: true,
            inline_data: true,
            omap_runs: true,
            lazy_free: true,
            leaf_delta: true,
            lazy_pginfo: true,
            long_names: true,
            shared_ext: true,
            ext_values: true,
            ..Default::default()
        };
        mkfs(&mut d, &mut MonoClock::default(), &p).unwrap();
    }
    fn dir(&self) -> PathBuf {
        let d = self.root.join("ceph-5");
        osddir::OsdDir {
            whoami: 5,
            osd_uuid: Uuid([7; 16]).to_string(),
            cluster_fsid: Uuid([9; 16]).to_string(),
            dev: self.spec(),
            crush_device_class: "nvme".into(),
            keyring: osddir::keyring_text(5, "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="),
        }
        .write(&d)
        .unwrap();
        d
    }
    /// objects `[from, to)` of `kib` KiB into 8 PGs
    fn write(&self, from: u32, to: u32, kib: usize) {
        let _g = fork_guard(); // declared first: dropped after the ctrl (see FORK_VS_LOCK)
        let ctrl = AnyCtrl::open_exclusive(&DevSpec::parse(&self.spec()).unwrap()).unwrap();
        let (mut st, _) = osd::nvmestore::mount_dev(&ctrl).unwrap();
        for i in from..to {
            let c = CollT::Pg(SpgT {
                pgid: PgT::new(1, i % 8),
                shard: ShardId::NO_SHARD,
            });
            let o = Ghobject::new(
                Hobject::new(format!("o{i}").as_bytes(), SnapId::NOSNAP, i, 1, b""),
                Ghobject::NO_GEN,
                ShardId::NO_SHARD,
            );
            let mut t = OTxn::new();
            if i < 8 {
                t.mkcoll(c);
            }
            let data = vec![i as u8; kib << 10];
            t.write(c, &o, 0, &data);
            st.commit(&t).unwrap();
        }
        st.checkpoint().unwrap();
    }
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let child = {
            let _g = fork_guard();
            Command::new(env!("CARGO_BIN_EXE_croit-flashstore-tool"))
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        };
        let o = child.wait_with_output().unwrap();
        (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    }
    fn ok(&self, args: &[&str]) -> String {
        let (c, o, e) = self.run(args);
        assert_eq!(c, 0, "{args:?}\nstdout: {o}\nstderr: {e}");
        o
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn json(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("not json ({e}): {s}"))
}

/// The device is found through the OSD data dir; the BlueStore-tool spellings are gone (usage, exit 2, nothing opened).
#[test]
fn data_path_and_no_bluestore_spellings() {
    let l = Lab::new("names", 64);
    l.mkfs();
    let d = l.dir();
    let d = d.to_str().unwrap();
    assert!(l.ok(&["fsck", "--data-path", d]).contains("fsck success"));
    assert_eq!(
        json(&l.ok(&["sizes", "--data-path", d, "--format", "json"]))["dev"],
        l.spec()
    );
    for w in [
        "show-label",
        "show-label-at",
        "set-label-key",
        "rm-label-key",
        "quick-fix",
        "bluefs-bdev-sizes",
        "bluefs-bdev-expand",
        "free-dump",
        "free-score",
        "free-fragmentation",
    ] {
        assert_eq!(l.run(&[w, "--data-path", d]).0, 2, "{w}");
    }
}

#[test]
fn fsck_and_repair() {
    let l = Lab::new("fsck", 96);
    l.mkfs();
    l.write(0, 60, 64);
    let spec = l.spec();
    let o = l.ok(&["fsck", "--dev", &spec]);
    assert!(o.contains("fsck success"), "{o}");
    let o = l.ok(&["fsck", "--deep", "--dev", &spec]);
    assert!(o.contains("fsck success"), "{o}");
    assert!(l.ok(&["repair", "--dev", &spec]).contains("repair success"));
    assert!(
        l.ok(&["repair", "--deep", "--dev", &spec])
            .contains("repair success")
    );
    // damage a data block: deep fsck finds it
    let lba = first_data_block(&l);
    corrupt(&l.dev, lba * 4096 + 100);
    let (c, o, _) = l.run(&["fsck", "--deep", "--dev", &spec]);
    assert_eq!(c, 1, "{o}");
    assert!(o.contains("fsck found"), "{o}");
    let before = std::fs::read(&l.dev).unwrap();
    let (code, out, _) = l.run(&["repair", "--deep", "--dev", &spec, "--format", "json"]);
    assert_eq!(code, 3, "{out}");
    let v = json(&out);
    assert_eq!(v["refused"], true);
    assert!(v["actions"].as_array().unwrap().is_empty());
    assert_eq!(
        std::fs::read(&l.dev).unwrap(),
        before,
        "refused repair wrote the device"
    );
}

/// Offset (in blocks) of a data block of some object: scan the file for the pattern of object 3 (`3` repeated).
fn first_data_block(l: &Lab) -> u64 {
    use std::io::Read;
    let mut f = std::fs::File::open(&l.dev).unwrap();
    let mut buf = vec![0u8; 4096];
    let mut blk = 0u64;
    while f.read_exact(&mut buf).is_ok() {
        if buf.iter().all(|&b| b == 3) {
            return blk;
        }
        blk += 1;
    }
    panic!("pattern of object 3 not found");
}

fn corrupt(path: &Path, off: u64) {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(&[0xee]).unwrap();
}

#[test]
fn sizes_expand_and_free() {
    let l = Lab::new("expand", 64);
    l.mkfs();
    l.write(0, 100, 64);
    let spec = l.spec();
    let s = json(&l.ok(&["sizes", "--dev", &spec, "--format", "json"]));
    assert_eq!(s["device_size"], 64 * MIB);
    assert_eq!(s["expandable"], 0);
    assert_eq!(s["expansions"], 0);
    // nothing to expand yet
    let v = json(&l.ok(&["expand", "--dev", &spec, "--format", "json"]));
    assert_eq!(v["expanded"], false);
    // free space before
    let before = free_bytes(&l);
    let f = json(&l.ok(&["free", "--dev", &spec, "--extents", "--format", "json"]));
    let list = f["extent_list"].as_array().unwrap();
    assert_eq!(f["extents"].as_u64(), Some(list.len() as u64));
    assert_eq!(
        list.iter().map(|e| e[1].as_u64().unwrap()).sum::<u64>(),
        before
    );
    assert!(list.iter().all(|e| e[0].as_u64().unwrap() % 4096 == 0));
    assert!(f["largest_extent"].as_u64().unwrap() <= before);
    for k in ["fragmentation_score", "fragmentation_rating"] {
        let x = f[k].as_f64().unwrap();
        assert!((0.0..=1.0).contains(&x), "{k}: {x}");
    }
    assert!(l.ok(&["free", "--dev", &spec]).contains("free "));
    // grow the device
    l.grow(192);
    let s = json(&l.ok(&["sizes", "--dev", &spec, "--format", "json"]));
    assert_eq!(s["device_size"], 192 * MIB);
    assert!(s["expandable"].as_u64().unwrap() >= 120 * MIB, "{s}");
    let v = json(&l.ok(&["expand", "--dev", &spec, "--format", "json"]));
    assert_eq!(v["expanded"], true);
    assert_eq!(v["new_size"], 192 * MIB);
    assert_eq!(v["expansions"], 1);
    let s = json(&l.ok(&["sizes", "--dev", &spec, "--format", "json"]));
    assert_eq!(
        (s["expandable"].as_u64(), s["expansions"].as_u64()),
        (Some(0), Some(1))
    );
    assert_eq!(
        json(&l.ok(&["expand", "--dev", &spec, "--format", "json"]))["expanded"],
        false
    );
    let after = free_bytes(&l);
    assert!(after >= before + 120 * MIB, "free {before} -> {after}");
    // the store keeps working and fills the new space
    assert!(
        l.ok(&["fsck", "--deep", "--dev", &spec])
            .contains("fsck success")
    );
    l.write(100, 1400, 64);
    assert!(
        l.ok(&["fsck", "--deep", "--dev", &spec])
            .contains("fsck success")
    );
    assert!(l.ok(&["repair", "--dev", &spec]).contains("repair success"));
}

fn free_bytes(l: &Lab) -> u64 {
    json(&l.ok(&["free", "--dev", &l.spec(), "--format", "json"]))["free_bytes"]
        .as_u64()
        .unwrap()
}

#[test]
fn refuses_a_device_in_use() {
    let l = Lab::new("busy", 64);
    l.mkfs();
    let dir = l.dir();
    let (spec, dirs, out, bundle_out) = (
        l.spec(),
        dir.display().to_string(),
        l.root.join("dump").display().to_string(),
        l.root.join("bundle").display().to_string(),
    );
    let _held = AnyCtrl::open_exclusive(&DevSpec::parse(&spec).unwrap()).unwrap();
    let conf = l.root.join("ceph.conf");
    std::fs::write(&conf, "[global]\n").unwrap();
    let confs = conf.display().to_string();
    let before = std::fs::read(&l.dev).unwrap();
    // every subcommand that opens a store device, read-only or not (a running OSD owns it): exit 3, "in use"
    let cmds: &[&[&str]] = &[
        &["fsck", "--dev", &spec],
        &["fsck", "--deep", "--dev", &spec],
        &["repair", "--dev", &spec],
        &["repair", "--deep", "--data-path", &dirs],
        &["sizes", "--dev", &spec],
        &["expand", "--dev", &spec],
        &["free", "--dev", &spec],
        &["free", "--extents", "--dev", &spec],
        &["objectstore", "--dev", &spec, "--op", "list"],
        &["dump", "--dev", &spec, "--out", &out],
        &["support-bundle", "--dev", &spec, "--out", &bundle_out],
        &["inspect", "--dev", &spec],
        &[
            "activate",
            "--id",
            "5",
            "--data-dir",
            &dirs,
            "--no-host-checks",
            "--conf",
            &confs,
        ],
        &["mkfs", "--dev", &spec],
        &["mkfs", "--dev", &spec, "--wipe"],
        &[
            "prepare",
            "--dev",
            &spec,
            "--wipe",
            "--no-host-checks",
            "--mon-host",
            "127.0.0.1:1",
        ],
        &["bench", "--dev", &spec],
    ];
    for c in cmds {
        let (code, _, e) = l.run(c);
        assert_eq!(code, 3, "{c:?}: {e}");
        assert!(e.contains("in use"), "{c:?}: {e}");
    }
    assert!(
        before == std::fs::read(&l.dev).unwrap(),
        "a refused tool wrote to the device"
    );
    drop(_held);
    l.ok(&["fsck", "--dev", &spec]); // the lock was the only obstacle
}

/// mkfs over a used file device (same fsid and mkfs_time, Write Zeroes unsupported = plain zero writes): the old WAL
/// is gone, the mount succeeds and the store is empty (adr 0021 am. 36).
#[test]
fn remkfs_over_a_used_store_mounts_empty() {
    let l = Lab::new("remkfs", 96);
    {
        l.mkfs();
        l.write(0, 40, 16);
        l.mkfs();
        let g = fork_guard();
        let ctrl = AnyCtrl::open_exclusive(&DevSpec::parse(&l.spec()).unwrap()).unwrap();
        for _ in 0..3 {
            let (st, stats) = osd::nvmestore::mount_dev(&ctrl).unwrap();
            assert!(stats.iter().all(|s| s.txns == 0), "{stats:?}");
            drop(st);
        }
        drop(ctrl);
        drop(g);
        assert!(l.ok(&["fsck", "--dev", &l.spec()]).contains("fsck success"));
    }
}

/// `--format` is the one shared parser: json / json-pretty parse for every document command, jsonl only for record
/// streams, text-only commands refuse json, and the old `--json` is gone (exit 2).
#[test]
fn format_flag_everywhere() {
    let l = Lab::new("fmt", 64);
    l.mkfs();
    l.write(0, 8, 16);
    let spec = l.spec();
    let root = l.root.to_str().unwrap().to_owned();
    l.dir();
    for f in ["json", "json-pretty"] {
        for cmd in ["sizes", "expand", "free", "fsck", "repair", "inspect"] {
            let v = json(&l.ok(&[cmd, "--dev", &spec, "--format", f]));
            assert!(v.is_object(), "{cmd} {f}");
        }
        let v = json(&l.ok(&["list", "--osd-data-root", &root, "--format", f]));
        assert_eq!(v.as_array().unwrap().len(), 1);
        let v = json(&l.ok(&["fsck", "--dev", &spec, &format!("--format={f}")]));
        assert_eq!(v["ok"], true);
    }
    assert!(json(&l.ok(&["inspect", "--dev", &spec]))["superblock"].is_object());
    let jl = l.ok(&["list", "--osd-data-root", &root, "--format", "jsonl"]);
    assert_eq!(jl.lines().count(), 1);
    assert!(json(jl.trim())["osd_id"] == 5);
    assert!(
        l.ok(&["fsck", "--dev", &spec, "--format", "plain"])
            .contains("fsck success")
    );
    for bad in [
        vec!["sizes", "--dev", &spec, "--format", "jsonl"],
        vec!["sizes", "--dev", &spec, "--format", "xml"],
        vec!["sizes", "--dev", &spec, "--format"],
        vec!["sizes", "--dev", &spec, "--json"],
        vec!["b3sum", "--format", "json", "-"],
        vec!["asok", "--id", "1", "--format", "jsonl", "status"],
    ] {
        assert_eq!(l.run(&bad).0, 2, "{bad:?}");
    }
}

/// A stable device path may name a different namespace after reboot. Offline
/// mutation must check the label against the selected directory before mounting.
#[test]
fn offline_commands_refuse_a_replaced_device_before_writing() {
    let l = Lab::new("wrong-device", 128);
    l.mkfs();
    l.write(0, 1, 4);
    let dir = l.dir();
    let mut od = osddir::OsdDir::read(&dir).unwrap();
    let baseline = std::fs::read(&l.dev).unwrap();
    for (uuid, cluster, id) in [
        (Uuid([8; 16]), Uuid([9; 16]), 5),
        (Uuid([7; 16]), Uuid([8; 16]), 5),
        (Uuid([7; 16]), Uuid([9; 16]), 6),
    ] {
        od.osd_uuid = uuid.to_string();
        od.cluster_fsid = cluster.to_string();
        od.whoami = id;
        od.keyring = osddir::keyring_text(id, "");
        od.write(&dir).unwrap();
        for cmd in [
            vec!["repair", "--data-path", dir.to_str().unwrap()],
            vec![
                "objectstore",
                "--data-path",
                dir.to_str().unwrap(),
                "--op",
                "remove",
                "--pgid",
                "1.0",
                "--force",
            ],
        ] {
            let (code, _, err) = l.run(&cmd);
            assert_eq!(code, 3, "{cmd:?}: {err}");
            assert!(err.contains("identity"), "{err}");
            assert_eq!(
                std::fs::read(&l.dev).unwrap(),
                baseline,
                "refusal wrote the device"
            );
        }
    }
}

/// `dump` is a production, READ-ONLY forensic copy: running it must not change a single byte of the device.
#[test]
fn dump_is_read_only() {
    let l = Lab::new("dumpro", 96);
    l.mkfs();
    l.write(0, 40, 16);
    let spec = l.spec();
    let out = l.root.join("dump").display().to_string();
    let before = std::fs::read(&l.dev).unwrap();
    let (c, o, e) = l.run(&["dump", "--dev", &spec, "--out", &out]);
    assert_eq!(c, 0, "stdout: {o}\nstderr: {e}");
    assert!(
        before == std::fs::read(&l.dev).unwrap(),
        "dump wrote to the device"
    );
    assert!(std::path::Path::new(&out).join("super.txt").exists());
    assert!(std::path::Path::new(&out).join("shard0.img").exists());
}

/// `support-bundle` collects the read-only outputs into `--out` (nothing written to the device) and, with
/// `--format json`, reports every collected file plus each step's exit status.
#[test]
fn support_bundle_collects_and_is_read_only() {
    use std::os::unix::fs::PermissionsExt;
    let l = Lab::new("bundle", 96);
    l.mkfs();
    l.write(0, 20, 16);
    let spec = l.spec();
    let out = l.root.join("bundle").display().to_string();
    // Reusing a public directory from an older tool version must restrict access before collecting metadata.
    std::fs::create_dir_all(&out).unwrap();
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o755)).unwrap();
    let before = std::fs::read(&l.dev).unwrap();
    let (c, o, e) = l.run(&[
        "support-bundle",
        "--dev",
        &spec,
        "--out",
        &out,
        "--format",
        "json",
    ]);
    assert_eq!(c, 0, "stdout: {o}\nstderr: {e}");
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o700,
        "metadata and logs must not be exposed to other users"
    );
    assert!(
        before == std::fs::read(&l.dev).unwrap(),
        "support-bundle wrote to the device"
    );
    let v = json(&o);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["dev"], spec.as_str(), "{v}");
    let steps = v["steps"].as_array().unwrap();
    let names: Vec<&str> = steps.iter().map(|s| s["step"].as_str().unwrap()).collect();
    for want in ["dump", "fsck", "inspect", "free", "list", "version"] {
        assert!(names.contains(&want), "missing step {want}: {v}");
    }
    assert!(steps.iter().all(|s| s["status"] == 0), "{v}");
    let files = v["files"].as_array().unwrap();
    let paths: Vec<&str> = files.iter().map(|f| f["path"].as_str().unwrap()).collect();
    for want in [
        "dump/super.txt",
        "dump/shard0.img",
        "fsck.txt",
        "inspect.txt",
        "free.txt",
        "list.txt",
        "version.txt",
    ] {
        assert!(paths.contains(&want), "missing file {want}: {v}");
    }
}

/// The tool runs as root into an operator-chosen directory: a symlink planted at a fixed output name must never be
/// written through (dump files, bundle step files) and a symlink cycle in the bundle directory must not hang the summary.
#[test]
fn dump_and_support_bundle_never_write_through_symlinks() {
    use std::os::unix::fs::symlink;
    let l = Lab::new("bundle-link", 96);
    l.mkfs();
    let spec = l.spec();
    let victim = l.root.join("victim.conf");
    std::fs::write(&victim, b"precious").unwrap();

    let out = l.root.join("dump-link");
    std::fs::create_dir_all(&out).unwrap();
    symlink(&victim, out.join("super.txt")).unwrap();
    let (c, _, e) = l.run(&["dump", "--dev", &spec, "--out", &out.display().to_string()]);
    assert_eq!(c, 1, "{e}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"precious");

    let out = l.root.join("bundle-link");
    std::fs::create_dir_all(&out).unwrap();
    symlink(&victim, out.join("fsck.txt")).unwrap();
    let (c, _, e) = l.run(&[
        "support-bundle",
        "--dev",
        &spec,
        "--out",
        &out.display().to_string(),
    ]);
    assert_eq!(c, 1, "{e}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"precious");

    // a rerun into a clean bundle dir that holds a loop link completes and lists no linked content
    let out = l.root.join("bundle-loop");
    std::fs::create_dir_all(&out).unwrap();
    symlink(&out, out.join("loop")).unwrap();
    let (c, o, e) = l.run(&[
        "support-bundle",
        "--dev",
        &spec,
        "--out",
        &out.display().to_string(),
        "--format",
        "json",
    ]);
    assert_eq!(c, 0, "{e}");
    let v = json(&o);
    assert!(
        v["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| !f["path"].as_str().unwrap().starts_with("loop")),
        "{v}"
    );
}

/// `dump` and `support-bundle` reject missing selectors and malformed device specs with a usage error (exit 2).
#[test]
fn dump_and_support_bundle_usage() {
    let l = Lab::new("usage", 64);
    l.mkfs();
    let spec = l.spec();
    let out = l.root.join("bundle").display().to_string();
    for args in [
        vec!["dump"],
        vec!["dump", "--dev", &spec],
        vec!["dump", "--out", &out],
        vec!["dump", "--dev", "kernel:relative", "--out", &out],
        vec!["support-bundle"],
        vec!["support-bundle", "--dev", &spec],
        vec!["support-bundle", "--out", &out],
        vec!["support-bundle", "--dev", "kernel:relative", "--out", &out],
    ] {
        let (c, _, e) = l.run(&args);
        assert_eq!(c, 2, "{args:?}: {e}");
    }
}

/// `wal-inspect` is read-only (the backing file is byte-for-byte unchanged), reports every shard as `ok` on a clean
/// store, drops nothing under `--preview-loss`, and speaks plain / json / json-pretty / jsonl.
#[test]
fn wal_inspect_clean_store_is_read_only_and_machine_readable() {
    let l = Lab::new("walinspect", 96);
    l.mkfs();
    l.write(0, 40, 16);
    let spec = l.spec();
    let before = std::fs::read(&l.dev).unwrap();
    let (c, o, e) = l.run(&["wal-inspect", "--dev", &spec]);
    assert_eq!(c, 0, "stdout: {o}\nstderr: {e}");
    assert!(o.contains("shard 0") && o.contains("shard 1"), "{o}");
    for fmt in ["json", "json-pretty"] {
        let v = json(&l.ok(&["wal-inspect", "--dev", &spec, "--format", fmt]));
        assert_eq!(v["dev"], spec.as_str());
        assert!(
            v["shards"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["ok"] == true),
            "{v}"
        );
    }
    // the preview flag on a clean store drops nothing
    let v = json(&l.ok(&[
        "wal-inspect",
        "--dev",
        &spec,
        "--preview-loss",
        "--format",
        "json",
    ]));
    for s in v["shards"].as_array().unwrap() {
        assert_eq!(s["dropped"].as_array().unwrap().len(), 0, "{v}");
    }
    // jsonl streams unit / record records and a final result
    let jl = l.ok(&["wal-inspect", "--dev", &spec, "--format", "jsonl"]);
    let rows: Vec<serde_json::Value> = jl.lines().map(json).collect();
    assert!(rows.iter().any(|r| r["type"] == "result"), "{jl}");
    assert_eq!(
        std::fs::read(&l.dev).unwrap(),
        before,
        "wal-inspect (and --preview-loss) wrote to the device"
    );
}

/// `wal-inspect` usage errors (missing selector, unknown shard, bad format) and refusal while the device is in use.
#[test]
fn wal_inspect_usage_and_device_in_use() {
    let l = Lab::new("walinspect-usage", 64);
    l.mkfs();
    let spec = l.spec();
    assert_eq!(l.run(&["wal-inspect"]).0, 2);
    assert_eq!(l.run(&["wal-inspect", "--dev", &spec, "--shard", "9"]).0, 2);
    assert_eq!(
        l.run(&["wal-inspect", "--dev", &spec, "--format", "xml"]).0,
        2
    );
    let _held = AnyCtrl::open_exclusive(&DevSpec::parse(&spec).unwrap()).unwrap();
    let (c, _, e) = l.run(&["wal-inspect", "--dev", &spec]);
    assert_eq!(c, 3, "{e}");
    assert!(e.contains("in use"), "{e}");
}

#[test]
fn repair_json_lists_counter_correction_and_both_checks() {
    let l = Lab::new("repair-counters", 64);
    l.mkfs();
    l.write(0, 4, 16);
    {
        let _g = fork_guard();
        let ctrl = AnyCtrl::open_exclusive(&DevSpec::parse(&l.spec()).unwrap()).unwrap();
        let (mut st, _) = osd::nvmestore::mount_dev(&ctrl).unwrap();
        let c = st.list_colls().unwrap()[0];
        let si = st.shard_of(&c);
        let key = store::obj::keys::coll_key(&c);
        let mut value = Vec::new();
        st.shards[si].tget(&mut st.clk, &key, &mut value).unwrap();
        let mut info = store::obj::onode::CollInfo::decode(&value).unwrap();
        info.nobj += 10;
        let s = &mut st.shards[si];
        let mut t = store::shard::Txn::new(0);
        t.sys = true;
        t.put(&key, &info.encode());
        let lsn = loop {
            match s.sh.submit(t) {
                Ok(lsn) => break lsn,
                Err((
                    store::StoreError::Miss | store::StoreError::Busy | store::StoreError::WalFull,
                    back,
                )) => {
                    t = back;
                    s.miss_wait(&mut st.clk).unwrap();
                }
                Err((e, _)) => panic!("fixture: {e}"),
            }
        };
        s.wait(&mut st.clk, |s| s.sh.durable_lsn() >= lsn).unwrap();
        st.checkpoint().unwrap();
    }
    let spec = l.spec();
    let v = json(&l.ok(&["repair", "--dev", &spec, "--deep", "--format", "json"]));
    assert_eq!(v["ok"], true);
    assert_eq!(v["refused"], false);
    assert!(!v["before"].as_array().unwrap().is_empty());
    assert!(v["after"].as_array().unwrap().is_empty());
    assert!(
        v["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().contains("rewrote from recount"))
    );
    assert!(
        l.ok(&["fsck", "--dev", &spec, "--deep"])
            .contains("success")
    );
}

/// The mechanism behind `FORK_VS_LOCK`: a child forked while the device is open keeps the `flock` after the owner
/// dropped its handle, until the child's `exec`. `pre_exec` stretches that window so it is deterministic. The window
/// is closed on Linux the moment `exec` returned (checked while the child still lives, blocked on its stdin). macOS
/// releases the `flock` of a forked child's inherited description asynchronously after `exec` (measured: busy for
/// ~5 ms after spawn returned, child alive or exited), so the release is not observable there without sleeping.
#[test]
fn forked_child_holds_a_dropped_lock_until_exec() {
    use std::os::unix::process::CommandExt;
    let _g = fork_guard(); // the stretched fork must not copy a sibling test's open device
    let l = Lab::new("fork-window", 4);
    let spec = l.spec();
    let mut fds = [0 as libc::c_int; 4]; // [ready r, ready w, go r, go w]
    // SAFETY: pipe(2) on two valid two-element slices.
    unsafe {
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        assert_eq!(libc::pipe(fds.as_mut_ptr().add(2)), 0);
    }
    let [ready_r, ready_w, go_r, go_w] = fds;
    let ctrl = AnyCtrl::open_exclusive(&DevSpec::parse(&spec).unwrap()).unwrap();
    let mut cmd = Command::new("cat");
    cmd.stdin(Stdio::piped());
    // SAFETY: the hook only calls async-signal-safe read/write on pipe fds.
    unsafe {
        cmd.pre_exec(move || {
            let b = 1u8;
            libc::write(ready_w, (&raw const b).cast(), 1);
            let mut x = 0u8;
            libc::read(go_r, (&raw mut x).cast(), 1);
            Ok(())
        });
    }
    let spawner = std::thread::spawn(move || cmd.spawn().unwrap());
    let mut b = 0u8;
    // SAFETY: read on our own pipe.
    assert_eq!(unsafe { libc::read(ready_r, (&raw mut b).cast(), 1) }, 1);
    drop(ctrl); // the child was forked with the open device and has not exec'd yet
    let e = AnyCtrl::open_exclusive(&DevSpec::parse(&spec).unwrap())
        .expect_err("child still holds the lock");
    assert!(e.to_string().contains("in use"), "{e}");
    // SAFETY: release the child.
    unsafe { libc::write(go_w, (&raw const b).cast(), 1) };
    // spawn returns once the child has exec'd; it stays alive reading stdin
    let mut child = spawner.join().unwrap();
    // exec closed the inherited description (O_CLOEXEC): the lock is free again although the child still lives
    #[cfg(target_os = "linux")]
    drop(AnyCtrl::open_exclusive(&DevSpec::parse(&spec).unwrap()).unwrap());
    drop(child.stdin.take()); // EOF: cat exits
    assert!(child.wait().unwrap().success());
    // SAFETY: closing our own pipe ends.
    for f in [ready_r, ready_w, go_r, go_w] {
        unsafe { libc::close(f) };
    }
}
