// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `activate --from-device` (OS disk lost, doc/how-to/prepare-and-activate.md): the OSD dir is recreated
//! from the device superblock alone (device read-only), a same-identity dir is left untouched, a
//! different identity is refused and no file is overwritten. `list --scan-devices` reports the
//! superblock of the kernel NVMe namespaces. The tool binary is run as a black box on a `file:` device.
#![cfg(feature = "lab")]

use denc::types::Uuid;
use nvme::any::{AnyCtrl, DevSpec};
use std::path::PathBuf;
use std::process::Command;
use store::dev::MonoClock;
use store::layout::{MkfsParams, mkfs};

const MIB: u64 = 1 << 20;
const OSD_UUID: [u8; 16] = [7; 16];
const CLUSTER_FSID: [u8; 16] = [9; 16];

struct Lab {
    root: PathBuf,
    dev: PathBuf,
    conf: PathBuf,
}

impl Lab {
    fn new(name: &str) -> Lab {
        let root = std::env::temp_dir().join(format!(
            "croit-flashstore-tool-fd-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let dev = root.join("dev.img");
        std::fs::File::create(&dev)
            .unwrap()
            .set_len(64 * MIB)
            .unwrap();
        let conf = root.join("ceph.conf");
        std::fs::write(&conf, "[global]\nmon host = v2:127.0.0.1:6789\n").unwrap();
        Lab { root, dev, conf }
    }

    fn spec(&self) -> String {
        format!("file:{}", self.dev.display())
    }

    /// A store like the OSD makes it (the tool's own mkfs needs a mon; identity fixed for the tests).
    fn mkfs(&self) {
        let ctrl = AnyCtrl::open(&DevSpec::parse(&self.spec()).unwrap(), false).unwrap();
        let mut d = ctrl.open_queue().unwrap();
        let p = MkfsParams {
            shards: 2,
            wal_blocks: 1024,
            align_blocks: 1,
            meta_pct: 4,
            osd_fsid: OSD_UUID,
            cluster_fsid: CLUSTER_FSID,
            osd_id: 5,
            allow_volatile_cache: true,
            ..Default::default()
        };
        mkfs(&mut d, &mut MonoClock::default(), &p).unwrap();
    }

    fn dir(&self) -> PathBuf {
        self.root.join("ceph-5")
    }

    fn fd_args(&self, extra: &[&str]) -> Vec<String> {
        let mut v = vec![
            "activate".to_string(),
            "--from-device".to_string(),
            "--dev".to_string(),
            self.spec(),
            "--data-dir".to_string(),
            self.dir().to_str().unwrap().to_string(),
            "--conf".to_string(),
            self.conf.to_str().unwrap().to_string(),
            "--no-host-checks".to_string(),
        ];
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    }

    fn run(&self, args: &[String]) -> (i32, String, String) {
        let o = Command::new(env!("CARGO_BIN_EXE_croit-flashstore-tool"))
            .args(args)
            .output()
            .unwrap();
        (
            o.status.code().unwrap(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The dir is created from the device identity (the files `prepare` writes) and the command continues
/// with the normal activate path (run config, exit 0).
#[test]
fn from_device_creates_the_osd_dir_and_acts_like_activate() {
    let l = Lab::new("create");
    l.mkfs();
    let (rc, out, err) = l.run(&l.fd_args(&["--format", "json"]));
    assert_eq!(rc, 0, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["status"], "activated");
    assert_eq!(v["osd_id"], 5);
    assert_eq!(v["osd_uuid"], Uuid(OSD_UUID).to_string());
    assert_eq!(v["cluster_fsid"], Uuid(CLUSTER_FSID).to_string());
    assert_eq!(v["data_dir"], l.dir().to_str().unwrap());
    assert!(!v["run_args"].as_array().unwrap().is_empty());
    // the files `prepare` writes
    assert_eq!(
        std::fs::read_to_string(l.dir().join("whoami")).unwrap(),
        "5\n"
    );
    assert_eq!(
        std::fs::read_to_string(l.dir().join("fsid")).unwrap(),
        format!("{}\n", Uuid(OSD_UUID))
    );
    assert_eq!(
        std::fs::read_to_string(l.dir().join("ceph_fsid")).unwrap(),
        format!("{}\n", Uuid(CLUSTER_FSID))
    );
    assert!(l.dir().join("croit-flashstore-osd").exists());
    assert!(l.dir().join("ready").exists());
    assert!(
        !l.dir().join("keyring").exists(),
        "no --keyring = an auth-none cluster, no keyring file"
    );
}

/// `--dev=SPEC` selects the device like `--dev SPEC` (one `--opt=value` split in `main`).
#[test]
fn from_device_takes_the_equals_form_device() {
    let l = Lab::new("equals");
    l.mkfs();
    let mut a = l.fd_args(&["--format", "json"]);
    let i = a.iter().position(|x| x == "--dev").unwrap();
    a[i] = format!("--dev={}", l.spec());
    a.remove(i + 1);
    let (rc, out, err) = l.run(&a);
    assert_eq!(rc, 0, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["osd_id"], 5);
    assert!(l.dir().join("ready").exists());
}

/// The device carries no class: `--crush-device-class` names it for the recreated marker (default nvme, as `prepare`).
#[test]
fn from_device_records_the_given_crush_device_class() {
    let l = Lab::new("class");
    l.mkfs();
    let (rc, _, err) = l.run(&l.fd_args(&["--crush-device-class", "fast"]));
    assert_eq!(rc, 0, "{err}");
    let d = osddir::OsdDir::read(&l.dir()).unwrap();
    assert_eq!(d.crush_device_class, "fast");

    let l = Lab::new("class-default");
    l.mkfs();
    let (rc, _, err) = l.run(&l.fd_args(&[]));
    assert_eq!(rc, 0, "{err}");
    assert_eq!(
        osddir::OsdDir::read(&l.dir()).unwrap().crush_device_class,
        "nvme"
    );
}

/// An omitted class preserves a same-identity directory's class; an explicit conflict is refused.
#[test]
fn from_device_preserves_an_existing_custom_class() {
    let l = Lab::new("class-preserve");
    l.mkfs();
    let (rc, _, err) = l.run(&l.fd_args(&["--crush-device-class", "fast"]));
    assert_eq!(rc, 0, "{err}");
    let marker = l.dir().join("croit-flashstore-osd");
    let before = std::fs::read(&marker).unwrap();
    let (rc, _, err) = l.run(&l.fd_args(&[]));
    assert_eq!(
        rc, 0,
        "omitted class must preserve the existing marker: {err}"
    );
    assert_eq!(std::fs::read(&marker).unwrap(), before);
    let (rc, _, err) = l.run(&l.fd_args(&["--crush-device-class", "slow"]));
    assert_eq!(rc, 3, "{err}");
    assert!(err.contains("refused"), "{err}");
    assert_eq!(std::fs::read(&marker).unwrap(), before);
}

/// A rerun on the same identity changes nothing (idempotent).
#[test]
fn from_device_is_idempotent_on_a_same_identity_dir() {
    let l = Lab::new("idempotent");
    l.mkfs();
    let (rc, _, err) = l.run(&l.fd_args(&[]));
    assert_eq!(rc, 0, "{err}");
    let before: Vec<(String, String)> = std::fs::read_dir(l.dir())
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read_to_string(e.path()).unwrap_or_default(),
            )
        })
        .collect();
    let (rc, _, err) = l.run(&l.fd_args(&[]));
    assert_eq!(rc, 0, "{err}");
    let after: Vec<(String, String)> = std::fs::read_dir(l.dir())
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read_to_string(e.path()).unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(before, after, "a same-identity dir is rewritten");
}

/// A dir with a different identity is refused (exit 3) and no file is overwritten.
#[test]
fn from_device_refuses_a_different_identity() {
    let l = Lab::new("mismatch");
    l.mkfs();
    let d = l.dir();
    osddir::OsdDir {
        whoami: 6,
        osd_uuid: Uuid(OSD_UUID).to_string(),
        cluster_fsid: Uuid(CLUSTER_FSID).to_string(),
        dev: l.spec(),
        crush_device_class: "nvme".into(),
        keyring: String::new(),
    }
    .write(&d)
    .unwrap();
    let before = std::fs::read_to_string(d.join("whoami")).unwrap();
    let (rc, _, err) = l.run(&l.fd_args(&[]));
    assert_eq!(rc, 3, "{err}");
    assert!(err.contains("refused"), "{err}");
    assert!(err.contains("osd id 5 (dir says 6)"), "{err}");
    assert_eq!(
        std::fs::read_to_string(d.join("whoami")).unwrap(),
        before,
        "the foreign file is overwritten"
    );
}

/// The key of the device comes from `--keyring FILE` (a classic keyring with the `osd.N` entry).
#[test]
fn from_device_takes_the_key_from_the_keyring_file() {
    use cephx::{CryptoKey, KeyType, UTime};
    let l = Lab::new("keyring");
    l.mkfs();
    let key = CryptoKey::generate(KeyType::Aes256Krb5, UTime::new(1_760_000_000, 0))
        .unwrap()
        .to_base64()
        .unwrap();
    let krf = l.root.join("osd.5.keyring");
    std::fs::write(&krf, format!("[osd.5]\n\tkey = {key}\n")).unwrap();
    let (rc, _, err) = l.run(&l.fd_args(&["--keyring", krf.to_str().unwrap()]));
    assert_eq!(rc, 0, "{err}");
    assert_eq!(
        std::fs::read_to_string(l.dir().join("keyring")).unwrap(),
        format!("[osd.5]\n\tkey = {key}\n")
    );
}

/// A `--keyring` file without the device's entity is refused (the dir is not created).
#[test]
fn from_device_refuses_a_keyring_without_the_entity() {
    use cephx::{CryptoKey, KeyType, UTime};
    let l = Lab::new("keyring-noentity");
    l.mkfs();
    let key = CryptoKey::generate(KeyType::Aes256Krb5, UTime::new(1_760_000_000, 0))
        .unwrap()
        .to_base64()
        .unwrap();
    let krf = l.root.join("osd.7.keyring");
    std::fs::write(&krf, format!("[osd.7]\n\tkey = {key}\n")).unwrap();
    let (rc, _, err) = l.run(&l.fd_args(&["--keyring", krf.to_str().unwrap()]));
    assert_eq!(rc, 3, "{err}");
    assert!(err.contains("no entry for osd.5"), "{err}");
    assert!(!l.dir().join("whoami").exists());
}

/// Usage errors (exit 2): `--from-device` needs exactly one of `--dev` / `--all` and no `--id`
/// (the id comes from the device); `--scan-devices` takes no `--osd-data-root`.
#[test]
fn from_device_usage() {
    let l = Lab::new("usage");
    let (rc, _, err) = l.run(&["activate".into(), "--from-device".into()]);
    assert_eq!(rc, 2, "{err}");
    let (rc, _, err) = l.run(&[
        "activate".into(),
        "--from-device".into(),
        "--dev".into(),
        l.spec(),
        "--all".into(),
    ]);
    assert_eq!(rc, 2, "{err}");
    // the id comes from the device superblock, never from --id
    let (rc, _, err) = l.run(&[
        "activate".into(),
        "--from-device".into(),
        "--dev".into(),
        l.spec(),
        "--id".into(),
        "7".into(),
    ]);
    assert_eq!(rc, 2, "{err}");
    // --scan-devices scans devices, not dirs
    let (rc, _, err) = l.run(&[
        "list".into(),
        "--scan-devices".into(),
        "--osd-data-root".into(),
        "/x".into(),
    ]);
    assert_eq!(rc, 2, "{err}");
}

/// `list --scan-devices`: read-only superblock scan of the kernel NVMe namespaces; every record carries
/// a status (flashstore | no flashstore | error); exit 0/1/3 per the rows. Only kernel-tier builds scan.
#[cfg(feature = "kernel-nvme")]
#[test]
fn list_scan_devices_reports_every_namespace() {
    let l = Lab::new("scan");
    let (rc, out, err) = l.run(&[
        "list".into(),
        "--scan-devices".into(),
        "--format".into(),
        "jsonl".into(),
    ]);
    assert!(matches!(rc, 0 | 1 | 3), "{err}");
    for line in out.lines() {
        let r: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(
            matches!(
                r["status"].as_str(),
                Some("flashstore" | "no flashstore" | "error")
            ),
            "{r:?}"
        );
        assert!(r.get("device").is_some(), "{r:?}");
    }
}
