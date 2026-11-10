// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Production lifecycle commands (adr 0034, doc/ops/deploy.md):
//! `prepare` (mkfs + `osd new` + OSD dir), `activate` (validate, emit run config), `list`, `inspect`.
//! `activate --from-device (--dev SPEC | --all) [--keyring FILE] [--crush-device-class C]` recreates the OSD dir from the device
//! superblock after an OS disk loss (device read-only; a same-identity dir is left untouched, a different
//! identity is refused; the keyring comes from a classic keyring file with the `osd.N` entry, omitted =
//! an auth-none cluster). `list --scan-devices` reports the superblock (osd id/uuid, cluster fsid, format
//! version) of every kernel NVMe namespace, read-only.
//! Exit codes: 0 ok, 1 runtime, 2 usage, 3 precondition/refused, 4 already prepared (no-op).
//! `activate`: 0 = run config emitted, 1 = runtime (incl. a device still not ready after the in-process wait of
//! 30 x 5 s at boot, like ceph-volume), 3 = refused (identity mismatch / foreign store, device held), 2 = usage.
//! `list --scan-devices`: 0 = every device scanned, 1 = a device unreadable, 3 = a device held (rows on stdout).
//! `activate --from-device`: 0 = activated, 3 = refused (identity mismatch, no store on `--dev`, device held), 1 = runtime.
//! Human log on stderr, `--format plain|json|json-pretty` (list: also `jsonl`) on stdout (outfmt). Only ever touches the device it is given.
use crate::{arg, flag, usage_err};
use cephx::keyring::Keyring;
use nvme::any::{AnyCtrl, DevSpec};
use osddir::{Conf, OsdDir};
use outfmt::Format;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn refuse(m: &str) -> i32 {
    eprintln!("croit-flashstore-tool: refused: {m}");
    3
}

fn out(f: Format, v: &Value, human: impl FnOnce() -> String) {
    if f.is_json() {
        println!("{}", f.doc(v));
    } else {
        println!("{}", human());
    }
}

fn conf_of(a: &[String], cluster: &str) -> Result<Conf, String> {
    Conf::load(&osddir::conf_file(a, cluster)?)
}

/// Host checks for a `spdk:` device: present on the PCI bus and bound to a userspace driver (never a device the
/// kernel owns: that could be a mounted disk). A `kernel:` spec (already resolved by `flashstore_store_backend`, adr 0169)
/// has no PCI claim to check: resolving it proved the controller is on the kernel driver and the node exists.
fn host_check_dev(spec: &str) -> Result<(), String> {
    let pci = match osddir::spec_pci(spec)? {
        Some(p) => p,
        None => return Ok(()), // file: lab device
    };
    if !osddir::pci_exists(pci) {
        return Err(format!("PCI device {pci} not found"));
    }
    match osddir::pci_driver(pci) {
        Some(d) if osddir::is_userspace_driver(&d) => Ok(()),
        Some(d) => Err(format!(
            "{pci} is bound to kernel driver {d:?}; bind it to vfio-pci first (croit-flashstore-prep@<id>.service)"
        )),
        None => Err(format!(
            "{pci} is not bound to vfio-pci/uio (croit-flashstore-prep@<id>.service)"
        )),
    }
}

/// Kernel devices may use ordinary pages; SPDK still requires its hugepage pool.
fn check_hugepages(spec: &str, need: u64, free: u64) -> Result<(), String> {
    if matches!(DevSpec::parse(spec)?, DevSpec::Spdk { .. }) && free < need {
        return Err(format!(
            "hugepages: {free} MB free (unreserved), {need} MB needed (`croit-flashstore-osd check` shows the fix)"
        ));
    }
    Ok(())
}

fn open_ro(spec: &str) -> Result<AnyCtrl, String> {
    let s = DevSpec::parse(spec)?;
    crate::devopen::open(&s, false, crate::devopen::MOUNT_HUGEPAGES_MB)
}

fn read_sb(ctrl: &AnyCtrl) -> Result<store::layout::Superblock, String> {
    let mut d = ctrl.open_queue()?;
    store::layout::read_super(&mut d, &mut store::dev::MonoClock::default())
        .map(|x| x.0)
        .map_err(|e| format!("no croit-flashstore-osd store on the device: {e:?}"))
}

fn sb_json(sb: &store::layout::Superblock) -> Value {
    json!({
        "osd_uuid": denc::types::Uuid(sb.osd_fsid).to_string(),
        "osd_id": sb.osd_id,
        "cluster_fsid": denc::types::Uuid(sb.cluster_fsid).to_string(),
        "lba_size": sb.lba_size, "size_bytes": sb.size_bytes, "shards": sb.shards,
        "plp": sb.plp, "version": sb.version, "mkfs_time": sb.mkfs_time,
        // passthrough DSM probe verdict of the mkfs that wrote the store (null = none stored; adr 0169 am. 8)
        "dsm_verdict": sb.dsm_verdict,
    })
}

// ---------------------------------------------------------------- prepare

/// Explicit other-engine preparation must not inherit SplinterDB backing flags.
/// With no selector, carry dormant settings: the device may already be SDB, and
/// its persistent identity (not a config default) must decide admission.
#[cfg(feature = "mon-std")]
fn splinter_prepare_args(
    a: &[String],
    opts: &std::collections::BTreeMap<String, String>,
) -> Vec<String> {
    let engine = arg(a, "--omap-engine").or_else(|| opts.get("flashstore_omap_engine").cloned());
    if engine.is_some_and(|e| e != "splinterdb")
        || flag(a, "--omap-lsm")
        || opts
            .get("flashstore_omap_lsm")
            .is_some_and(|v| matches!(v.as_str(), "true" | "1" | "yes"))
    {
        return Vec::new();
    }
    let mut m = Vec::new();
    for (flag, key) in [
        ("--splinterdb-dir", Some("flashstore_store_splinterdb_dir")),
        ("--splinterdb-capacity", None),
        ("--splinterdb-io", Some("flashstore_store_splinterdb_io")),
        (
            "--splinterdb-prefetch-bytes",
            Some("flashstore_store_splinterdb_prefetch_bytes"),
        ),
        (
            "--splinterdb-scan-readahead-pages",
            Some("flashstore_store_splinterdb_scan_readahead_pages"),
        ),
    ] {
        if let Some(value) = arg(a, flag).or_else(|| key.and_then(|k| opts.get(k).cloned())) {
            m.extend([flag.into(), value]);
        }
    }
    if flag(a, "--splinterdb-cache-stats")
        || opts
            .get("flashstore_store_splinterdb_cache_stats")
            .is_some_and(|s| matches!(s.as_str(), "true" | "1" | "yes" | "on"))
    {
        m.push("--splinterdb-cache-stats".into());
    }
    if flag(a, "--splinterdb-no-log") {
        m.push("--splinterdb-no-log".into());
    }
    #[cfg(feature = "lab")]
    if flag(a, "--splinterdb-lab-filesystem") {
        m.push("--splinterdb-lab-filesystem".into());
    }
    m
}

#[cfg(feature = "mon-std")]
pub fn prepare(a: &[String], f: Format) -> i32 {
    let want_id = match crate::mkfs::requested_id(a) {
        Ok(id) => id,
        Err(e) => return usage_err(&e),
    };
    let Some(dev) = arg(a, "--dev") else {
        return usage_err(
            "prepare --dev spdk:PCI[,ns=N] [--id N] [--osd-uuid U] [--crush-device-class nvme] [--cluster ceph]\n  [--store-shards auto|N] [--cores N] [--wal-mib N] [--conf F] [--keyring F] [--mon-host H] [--osd-data-root DIR] [--format-lba4k] [--wipe] [--no-discard] [--omap-lsm] [--format plain|json|json-pretty]",
        );
    };
    if let Err(e) = DevSpec::parse(&dev) {
        return usage_err(&e);
    }
    let cl = match osddir::cluster_from_args(a) {
        Ok(c) => c,
        Err(e) => return usage_err(&e),
    };
    let conf = match crate::devopen::optional_conf(a, &cl) {
        Ok(c) => c,
        Err(e) => return refuse(&e),
    };
    let opts_for = |id: i64| conf.for_osd(id);
    // `dev` (the identity recorded in the OSD dir) stays the spec as given; `open_dev` is what is checked and opened
    let open_dev = match crate::devopen::conf_backend_spec(&dev, &opts_for(want_id.unwrap_or(-1))) {
        Ok(d) => d,
        Err(e) => return refuse(&e),
    };
    if !flag(a, "--no-host-checks")
        && let Err(e) = host_check_dev(&open_dev)
    {
        return refuse(&e);
    }
    let root_flag = arg(a, "--osd-data-root").map(PathBuf::from);
    // one process owns a whole NVMe controller (adr 0103): a second OSD on another namespace could never start
    let root = match root_flag.clone() {
        Some(r) => r,
        None => match osddir::data_root(&opts_for(-1), &cl, -1) {
            Ok(r) => r,
            Err(e) => return refuse(&e),
        },
    };
    // debug/testing builds (feature spdk-mp, adr 0463): `shared` OSDs may share a controller with other `shared` ones
    let shared = |s: &str| DevSpec::parse(s).is_ok_and(|s| s.is_shared());
    let neighbours = match osddir::controller_neighbours(&root, &cl, &dev) {
        Ok(n) => n,
        Err(e) => return refuse(&e),
    };
    if let Some((id, d)) = neighbours
        .iter()
        .find(|(_, d)| !(shared(&dev) && shared(d)))
    {
        return refuse(&format!(
            "{dev}: the NVMe controller already holds osd.{id} ({d}); croit-flashstore-osd runs one OSD per controller (adr 0103): \
             use a single namespace per controller"
        ));
    }
    let conf_mon = conf.mon_host(want_id);
    let Some(mon_host) = arg(a, "--mon-host").or(conf_mon) else {
        return usage_err("no mon_host: --mon-host or mon_host in the conf file");
    };
    let keyring =
        arg(a, "--keyring").unwrap_or_else(|| format!("/var/lib/ceph/bootstrap-osd/{cl}.keyring"));
    let class = arg(a, "--crush-device-class").unwrap_or_else(|| "nvme".into());
    let mut m: Vec<String> = [
        "--dev",
        &open_dev,
        "--keyring",
        &keyring,
        "--mon-host",
        &mon_host,
        "--crush-device-class",
        &class,
    ]
    .map(String::from)
    .to_vec();
    m.extend(["--cluster".into(), cl.clone()]);
    for k in [
        "--id",
        "--osd-uuid",
        "--entity",
        "--store-size",
        "--conf",
        "--omap-engine",
        "--splinterdb-dir",
        "--splinterdb-capacity",
        "--splinterdb-io",
        "--splinterdb-prefetch-bytes",
        "--splinterdb-scan-readahead-pages",
    ] {
        if let Some(v) = arg(a, k) {
            m.extend([k.into(), v]);
        }
    }
    // store_shards (adr 0160): flag > conf `flashstore_store_shards` > auto; auto = the OSD's configured cores
    let opts = opts_for(want_id.unwrap_or(-1));
    m.extend(splinter_prepare_args(a, &opts));
    let (conf_shards, conf_cores) = osddir::mkfs_shard_opts(&opts);
    let shards = arg(a, "--store-shards")
        .or_else(|| arg(a, "--shards"))
        .or(conf_shards);
    if let Some(s) = shards {
        m.extend(["--store-shards".into(), s]);
    }
    if let Some(b) = arg(a, "--base-pct").or_else(|| opts.get("flashstore_store_base_pct").cloned())
    {
        m.extend(["--base-pct".into(), b]);
    }
    if let Some(c) = arg(a, "--cores").or(conf_cores.map(|c| c.to_string())) {
        m.extend(["--cores".into(), c]);
    }
    if let Some(w) = arg(a, "--wal-mib") {
        m.extend(["--wal-mib".into(), w]);
    }
    for k in ["--format-lba4k", "--wipe", "--allow-vwc", "--no-discard"] {
        if flag(a, k) {
            m.push(k.into());
        }
    }
    if flag(a, "--omap-lsm")
        || opts
            .get("flashstore_omap_lsm")
            .is_some_and(|v| matches!(v.as_str(), "true" | "1" | "yes"))
    {
        m.push("--omap-lsm".into());
    }
    if let Some(engine) =
        arg(a, "--omap-engine").or_else(|| opts.get("flashstore_omap_engine").cloned())
    {
        m.extend(["--omap-engine".into(), engine]);
    }
    if let Some(root) = arg(a, "--rocksdb-dir")
        .or_else(|| opts.get("flashstore_rocksdb_dir").cloned())
        .filter(|v| !v.is_empty())
    {
        m.extend(["--rocksdb-dir".into(), root]);
    }
    // Ceph's `bluestore_discard_on_mkfs` (default true) = the same opt-out as `--no-discard`
    if !flag(a, "--no-discard") && !crate::mkfs::conf_discard_on_mkfs(&opts) {
        m.push("--no-discard".into());
    }
    // Everything decidable about the OSD dir is decided before the device or the mon is touched (and again with the
    // mon-allocated id, which rolls the registration back on refusal).
    let admit = |plan: &crate::mkfs::Plan| -> Result<(), String> {
        probe_writable(&root)?;
        let Some(id) = plan.id else { return Ok(()) };
        let keyring = osddir::keyring_text(id, plan.key);
        OsdDir::admit(
            &prepared_dir(root_flag.as_deref(), &opts_for(id), &cl, id),
            id,
            plan.osd_uuid,
            plan.cluster_fsid,
            Some(&keyring),
        )
    };
    let p = match crate::mkfs::provision(&m, &admit) {
        Ok(p) => p,
        Err(e) => {
            return match e.strip_prefix("refused: ") {
                Some(r) => refuse(r),
                None => {
                    eprintln!("croit-flashstore-tool: prepare: {e}");
                    crate::devopen::exit_code(&e)
                }
            };
        }
    };
    let dir = prepared_dir(root_flag.as_deref(), &opts_for(p.id), &cl, p.id);
    let od = OsdDir {
        whoami: p.id,
        osd_uuid: p.osd_uuid.clone(),
        cluster_fsid: p.cluster_fsid.clone(),
        dev: dev.clone(),
        crush_device_class: p.class.clone(),
        keyring: osddir::keyring_text(p.id, &p.key),
    };
    let unchanged =
        p.already && OsdDir::read(&dir).is_ok_and(|e| e == od) && OsdDir::is_ready(&dir);
    if let Err(e) = publish_prepared_dir(&od, &dir, unchanged) {
        return refuse(&e);
    }
    let ids = p.ident.as_ref().map(|i| i.device_id()).unwrap_or_default();
    let v = json!({"osd_id": p.id, "osd_uuid": p.osd_uuid, "cluster_fsid": p.cluster_fsid, "dev": dev,
        "device_ids": ids, "size_bytes": p.size, "crush_device_class": p.class, "data_dir": dir, "already_prepared": unchanged});
    out(f, &v, || {
        format!(
            "osd.{} {} in {}",
            p.id,
            if unchanged {
                "already prepared"
            } else {
                "prepared"
            },
            dir.display()
        )
    });
    if unchanged { 4 } else { 0 }
}

/// The OSD data root must exist (created like `prepare` would) and accept a new file.
#[cfg(feature = "mon-std")]
fn probe_writable(root: &Path) -> Result<(), String> {
    let io = |e: std::io::Error| {
        format!(
            "osd data root {}: {e} (fix the path or permissions, or pass --osd-data-root)",
            root.display()
        )
    };
    std::fs::create_dir_all(root).map_err(io)?;
    let probe = root.join(format!(".prepare-probe-{}", std::process::id()));
    std::fs::File::create(&probe).map_err(io)?;
    std::fs::remove_file(&probe).map_err(io)
}

/// Publish the prepared OSD dir. The same OSD (id, OSD uuid, cluster fsid) is rewritten (its device spec, class or key
/// may have changed); any other existing content is only completed, never overwritten: a directory of another OSD
/// identity (e.g. a reused cluster name) is refused and stays intact.
#[cfg(feature = "mon-std")]
fn publish_prepared_dir(od: &OsdDir, dir: &Path, unchanged: bool) -> Result<(), String> {
    if unchanged {
        return Ok(());
    }
    match OsdDir::read(dir) {
        Ok(e)
            if e.whoami == od.whoami
                && e.osd_uuid == od.osd_uuid
                && e.cluster_fsid == od.cluster_fsid =>
        {
            od.write(dir)
        }
        _ => od.complete(dir).map(drop),
    }
}

// --------------------------------------------------------------- activate

pub fn activate(a: &[String], f: Format) -> i32 {
    if flag(a, "--from-device") {
        return activate_from_device(a, f);
    }
    match activate_one(a) {
        Ok((v, h)) => {
            out(f, &v, || h);
            0
        }
        Err((c, m)) => {
            eprintln!(
                "croit-flashstore-tool: {}",
                match c {
                    3 => format!("refused: {m}"),
                    2 => m,
                    _ => format!("activate: {m}"),
                }
            );
            c
        }
    }
}

/// How long `activate` waits for a device that is not ready yet at boot (slow udev, controller not bound yet):
/// classic ceph-volume's activation retries (30 x 5 s). In-process, so the unit's crash-loop policy (3 starts per
/// 30 min, classic ceph-osd@) stays untouched.
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
const DEVICE_READY_TRIES: u32 = 30;
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
const DEVICE_READY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Open the device read-only, waiting up to [`DEVICE_READY_TRIES`] x [`DEVICE_READY_INTERVAL`] while the failure is
/// "not ready" (exit 1 class); a refusal (exit 3 class) returns at once. Expiry prints the loud timeout line and
/// returns exit 1 (systemd `Restart=on-failure` may try once more within the unit's start limit).
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
fn open_ready(dev: &str) -> Result<AnyCtrl, (i32, String)> {
    let mut last = String::new();
    for i in 0..DEVICE_READY_TRIES {
        match open_ro(dev) {
            Ok(c) => return Ok(c),
            Err(e) => {
                let (code, msg) = device_open_err(dev, &e);
                if code != 1 {
                    return Err((code, msg));
                }
                if i == 0 {
                    eprintln!(
                        "activate: {msg}; waiting up to {}s",
                        DEVICE_READY_TRIES * DEVICE_READY_INTERVAL.as_secs() as u32
                    );
                }
                last = msg;
            }
        }
        std::thread::sleep(DEVICE_READY_INTERVAL);
    }
    let limit = DEVICE_READY_TRIES * DEVICE_READY_INTERVAL.as_secs() as u32;
    eprintln!("WARNING TIMEOUT activate device {dev} ready exceeded {limit}s ({last})");
    Err((1, last))
}

/// Classify an `activate` device-open failure (pure, unit-tested): "in use" (held by a running OSD/tool, mounted
/// or partitioned) is a permanent refusal (exit 3); anything else (the node is not there yet, the controller is
/// not bound to its driver yet, a transient EIO) is a runtime "not ready" (exit 1), which
/// [`open_ready`] waits for until the device appears (a slow boot: CS-5413/5484/5494).
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
fn device_open_err(dev: &str, e: &str) -> (i32, String) {
    if crate::devopen::exit_code(e) == 3 {
        (3, format!("device {dev}: {e}"))
    } else {
        (1, format!("device {dev} not ready: {e}"))
    }
}

/// The normal activate path without its output: validate the dir, the host and the store identity, build the
/// run config. `Err` = `(exit code, message)`. Exit codes: 2 = usage, 3 = refused (the OSD dir or the store
/// identity does not match, the device is held), 1 = runtime (incl. a device that is not ready/openable yet:
/// after the in-process wait of [`open_ready`]).
fn activate_one(a: &[String]) -> Result<(Value, String), (i32, String)> {
    let Some(id) = arg(a, "--id").and_then(|s| s.parse::<i64>().ok()) else {
        return Err((
            2,
            "activate --id N [--cluster ceph] [--conf F] [--data-dir D] [--format plain|json|json-pretty] [--no-store-check] [--no-host-checks]".into(),
        ));
    };
    let cl = osddir::cluster_from_args(a).map_err(|e| (2, e))?;
    let conf = conf_of(a, &cl).map_err(|e| (3, e))?;
    let opts = conf.for_osd(id);
    let dir = arg(a, "--data-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| osddir::data_dir(&opts, &cl, id));
    let od = OsdDir::read(&dir).map_err(|e| (3, e))?;
    if od.whoami != id {
        return Err((3, format!("{} belongs to osd.{}", dir.display(), od.whoami)));
    }
    if !OsdDir::is_ready(&dir) {
        return Err((
            3,
            format!(
                "{} has no `ready` file: prepare did not finish",
                dir.display()
            ),
        ));
    }
    let host = !flag(a, "--no-host-checks");
    // the tier the daemon will use (conf `flashstore_store_backend`, adr 0169): checks and the identity read follow it
    let dev = if host || !flag(a, "--no-store-check") {
        match crate::devopen::conf_backend_spec(&od.dev, &opts) {
            Ok(d) => d,
            Err(e) => return Err((3, e)),
        }
    } else {
        od.dev.clone()
    };
    if host {
        if let Err(e) = host_check_dev(&dev) {
            return Err((3, e));
        }
        let need = match osddir::hugepages_need_mb(&opts) {
            Ok(n) => n,
            Err(e) => return Err((3, e)),
        };
        let free = osddir::hugepages_free_mb();
        if let Err(e) = check_hugepages(&dev, need, free) {
            return Err((3, e));
        }
        if !osddir::memlock_unlimited() {
            return Err((
                3,
                "RLIMIT_MEMLOCK is not unlimited (LimitMEMLOCK=infinity / --ulimit memlock=-1)"
                    .into(),
            ));
        }
    }
    #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
    if !flag(a, "--no-store-check") {
        let ctrl = open_ready(&dev)?;
        let sb = read_sb(&ctrl).map_err(|e| (3, e))?;
        crate::objectstore::check_identity(&sb, &od).map_err(|e| (3, e))?;
        #[cfg(feature = "splinterdb")]
        if sb.features & store::layout::FEAT_OMAP_SPLINTERDB != 0 {
            let Some(root) = opts.get("flashstore_store_splinterdb_dir") else {
                return Err((
                    3,
                    "SplinterDB activation requires flashstore_store_splinterdb_dir".into(),
                ));
            };
            let cfg = store::splinter_omap::Config::new(root.into(), 0);
            for s in 0..sb.shards {
                store::splinter_omap::validate_binding(&cfg, &sb, s)
                    .map_err(|e| (3, e.to_string()))?;
            }
        }
    }
    let args = osddir::run_args(&opts, Some(&od), &dir).map_err(|e| (3, e))?;
    let v = json!({"osd_id": id, "osd_uuid": od.osd_uuid, "cluster_fsid": od.cluster_fsid, "dev": od.dev,
        "data_dir": dir, "run_args": args});
    Ok((
        v,
        format!(
            "croit-flashstore-osd run --id {id} --cluster {cl}   # = {}",
            args.join(" ")
        ),
    ))
}

// --------------------------------------------------- activate --from-device

/// `--from-device` outcome of one device: `Skip` = no usable store (only with `--all`), `Refused` = exit 3,
/// `Runtime` = exit 1.
enum FdErr {
    Skip,
    Refused(String),
    Runtime(String),
}

/// The target OSD dir of `activate --from-device` as far as the decision needs it (and nothing else).
#[derive(Debug)]
enum DirState {
    /// No `croit-flashstore-osd` marker: an empty or foreign dir; ours can be created.
    Empty,
    /// A marker is present but the dir is unreadable or inconsistent: never write into it.
    Broken(String),
    /// A readable dir.
    Read(OsdDir),
}

fn dir_state(dir: &Path) -> DirState {
    if !dir.join("croit-flashstore-osd").exists() {
        return DirState::Empty;
    }
    match OsdDir::read(dir) {
        Ok(d) => DirState::Read(d),
        Err(e) => DirState::Broken(format!("{}: {e}", dir.display())),
    }
}

/// The decision of `activate --from-device` (pure: unit-tested without a device).
#[derive(Debug, PartialEq, Eq)]
enum FromDevicePlan {
    /// No usable dir: create it (the files `prepare` writes).
    Create,
    /// The dir carries the same identity and device: no file is rewritten.
    Idempotent,
    /// The dir is broken or carries a different identity: refuse.
    Refuse(String),
}

fn from_device_plan(
    osd_id: i64,
    osd_uuid: &str,
    cluster_fsid: &str,
    spec: &str,
    dir: &DirState,
) -> FromDevicePlan {
    match dir {
        DirState::Empty => FromDevicePlan::Create,
        DirState::Broken(e) => FromDevicePlan::Refuse(e.clone()),
        DirState::Read(d) => {
            let mut m = Vec::new();
            if d.whoami != osd_id {
                m.push(format!("osd id {osd_id} (dir says {})", d.whoami));
            }
            if d.osd_uuid != osd_uuid {
                m.push(format!("osd uuid {osd_uuid} (dir says {})", d.osd_uuid));
            }
            if d.cluster_fsid != cluster_fsid {
                m.push(format!(
                    "cluster fsid {cluster_fsid} (dir says {})",
                    d.cluster_fsid
                ));
            }
            if m.is_empty() && !osddir::same_dev(&d.dev, spec) {
                m.push(format!("device {spec} (dir says {})", d.dev));
            }
            if m.is_empty() {
                FromDevicePlan::Idempotent
            } else {
                FromDevicePlan::Refuse(format!(
                    "the OSD dir identity does not match the device: {}",
                    m.join(", ")
                ))
            }
        }
    }
}

/// `activate --from-device` on one device: read the superblock (the device is never written), reconcile the
/// OSD dir (create it, or prove it is the same identity), then continue with the normal activate path.
/// `skip_no_store`: `--all` skips devices without a usable store, `--dev` refuses them.
fn from_device_one(
    a: &[String],
    spec: &str,
    cl: &str,
    conf: &Conf,
    kr: Option<&Keyring>,
    skip_no_store: bool,
) -> Result<(Value, String), FdErr> {
    // the handle is dropped before the normal activate path reopens the device (one exclusive open at a time)
    let sb = {
        let ctrl = match open_ro(spec) {
            Ok(c) => c,
            Err(e) => {
                return Err(if e.contains("in use") {
                    FdErr::Refused(e)
                } else {
                    FdErr::Runtime(e)
                });
            }
        };
        let mut d = ctrl.open_queue().map_err(FdErr::Runtime)?;
        match store::layout::read_super(&mut d, &mut store::dev::MonoClock::default()) {
            Ok((sb, _)) => sb,
            Err(e) => {
                return if skip_no_store {
                    Err(FdErr::Skip)
                } else {
                    Err(FdErr::Refused(format!(
                        "no croit-flashstore-osd store on the device {spec}: {e:?}"
                    )))
                };
            }
        }
    };
    let id = i64::from(sb.osd_id);
    let osd_uuid = denc::types::Uuid(sb.osd_fsid).to_string();
    let cluster_fsid = denc::types::Uuid(sb.cluster_fsid).to_string();
    let opts = conf.for_osd(id);
    let dir = arg(a, "--data-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| osddir::data_dir(&opts, cl, id));
    let state = dir_state(&dir);
    match from_device_plan(id, &osd_uuid, &cluster_fsid, spec, &state) {
        FromDevicePlan::Refuse(m) => return Err(FdErr::Refused(m)),
        FromDevicePlan::Create | FromDevicePlan::Idempotent => {}
    }
    let key = match kr {
        None => String::new(), // an auth-none cluster has no key
        Some(k) => match k.get(&format!("osd.{id}")).and_then(|e| e.key.clone()) {
            Some(k) => k
                .to_base64()
                .map_err(|e| FdErr::Runtime(format!("keyring: osd.{id}: key encoding: {e:?}")))?,
            None => {
                return Err(FdErr::Refused(format!(
                    "keyring: no entry for osd.{id} (a cephx cluster needs the key of the device)"
                )));
            }
        },
    };
    // The device carries no class: retain a same-identity marker's class when none was requested.
    // An explicit conflicting class still reaches `complete` and is refused without overwriting it.
    let class = arg(a, "--crush-device-class").unwrap_or_else(|| match &state {
        DirState::Read(d) => d.crush_device_class.clone(),
        _ => "nvme".into(),
    });
    if class.is_empty() || class.starts_with("--") {
        return Err(FdErr::Refused(format!(
            "--crush-device-class: not a device class: {class:?}"
        )));
    }
    let od = OsdDir {
        whoami: id,
        osd_uuid,
        cluster_fsid,
        dev: spec.to_owned(),
        crush_device_class: class,
        keyring: osddir::keyring_text(id, &key),
    };
    od.complete(&dir)
        .map_err(|e| FdErr::Refused(format!("{}: {e}", dir.display())))?;
    // the normal activate path validates host + store identity and builds the run config
    let mut na: Vec<String> = vec!["activate".into(), "--id".into(), id.to_string()];
    for k in ["--cluster", "--conf", "--data-dir"] {
        if let Some(v) = arg(a, k) {
            na.extend([k.into(), v]);
        }
    }
    for k in ["--no-host-checks", "--no-store-check"] {
        if flag(a, k) {
            na.push(k.into());
        }
    }
    let (v, h) = activate_one(&na).map_err(|(c, m)| {
        if c == 3 {
            FdErr::Refused(m)
        } else {
            FdErr::Runtime(m)
        }
    })?;
    Ok((
        json!({
            "dev": spec,
            "status": "activated",
            "osd_id": v["osd_id"],
            "osd_uuid": v["osd_uuid"],
            "cluster_fsid": v["cluster_fsid"],
            "data_dir": v["data_dir"],
            "run_args": v["run_args"],
        }),
        h,
    ))
}

/// `activate --from-device (--dev SPEC | --all) [--keyring FILE] [--crush-device-class C]`: the OS disk lost the OSD dirs
/// (doc/how-to/prepare-and-activate.md). The dir identity comes from the device superblock (read-only),
/// the keyring from `--keyring FILE` (a classic keyring with the `osd.N` entry; omitted = an auth-none
/// cluster). The device class is not on the device: `--crush-device-class` (default nvme, as `prepare`) names it for a
/// recreated dir; an existing same-identity dir keeps its own. Exit: 0 activated, 2 usage, 3 refused (identity mismatch, no store on `--dev`, device held),
/// 1 runtime.
fn activate_from_device(a: &[String], f: Format) -> i32 {
    let all = flag(a, "--all");
    let dev = arg(a, "--dev");
    if all && dev.is_some() {
        return usage_err("activate --from-device: --dev SPEC and --all are mutually exclusive");
    }
    if !all && dev.is_none() {
        return usage_err("activate --from-device: --dev SPEC or --all");
    }
    if arg(a, "--id").is_some() {
        return usage_err(
            "activate --from-device: the OSD id comes from the device superblock, --id is not used",
        );
    }
    if all && !cfg!(feature = "kernel-nvme") {
        return usage_err(
            "activate --from-device --all: needs a build with the kernel tier (feature kernel-nvme)",
        );
    }
    let cl = match osddir::cluster_from_args(a) {
        Ok(c) => c,
        Err(e) => return usage_err(&e),
    };
    let conf = match conf_of(a, &cl) {
        Ok(c) => c,
        Err(e) => return refuse(&e),
    };
    // one keyring file may carry every entity of the host
    let kr = match arg(a, "--keyring") {
        None => None,
        Some(p) => match std::fs::read_to_string(&p) {
            Ok(t) => match Keyring::parse(&t) {
                Ok(k) => Some(k),
                Err(e) => return usage_err(&format!("keyring {p}: {e:?}")),
            },
            Err(e) => return usage_err(&format!("keyring {p}: {e}")),
        },
    };
    let specs: Vec<String> = if all {
        nvme_namespaces()
            .into_iter()
            .map(|p| format!("kernel:{}", p.display()))
            .collect()
    } else {
        vec![dev.unwrap()]
    };
    let mut rows: Vec<(Value, Option<String>)> = Vec::new();
    let mut rc = 0;
    for spec in &specs {
        match from_device_one(a, spec, &cl, &conf, kr.as_ref(), all) {
            Ok((row, h)) => rows.push((row, Some(h))),
            Err(FdErr::Skip) => {}
            Err(FdErr::Refused(m)) => {
                eprintln!("croit-flashstore-tool: refused: {m}");
                rows.push((json!({"dev": spec, "status": "refused", "error": m}), None));
                rc = rc.max(3);
            }
            Err(FdErr::Runtime(m)) => {
                eprintln!("croit-flashstore-tool: activate --from-device: {m}");
                rows.push((json!({"dev": spec, "status": "error", "error": m}), None));
                rc = rc.max(1);
            }
        }
    }
    if !all {
        let (row, h) = rows.pop().expect("one --dev means exactly one row");
        return match h {
            Some(h) => {
                out(f, &row, || h);
                0
            }
            None => rc, // the message is on stderr
        };
    }
    if f.is_json() {
        let out = f.records(&rows.iter().map(|(r, _)| r.clone()).collect::<Vec<_>>());
        if !out.is_empty() {
            println!("{out}");
        }
    } else {
        for (_, h) in &rows {
            if let Some(h) = h {
                println!("{h}");
            }
        }
    }
    rc
}

/// Whole NVMe namespaces on the host (`/sys/class/block/nvme<C>n<N>` -> `/dev/nvme<C>n<N>`), ordered by
/// (controller, namespace); empty where sysfs is absent (non-Linux) or no namespace is on the kernel driver.
fn nvme_namespaces() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/class/block") {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if let Some(k) = is_ns_head(&n) {
                v.push((k, PathBuf::from(format!("/dev/{n}"))));
            }
        }
    }
    v.sort_by_key(|(k, _)| *k);
    v.into_iter().map(|(_, p)| p).collect()
}

/// Is the sysfs block name a whole NVMe namespace head (`nvme<C>n<N>`), not a partition (`nvme<C>n<N>p<M>`)
/// and not a controller entry (`nvme<C>` lives under /sys/class/nvme, not /sys/class/block)?
fn is_ns_head(name: &str) -> Option<(u32, u32)> {
    let rest = name.strip_prefix("nvme")?;
    let (c, n) = rest.split_once('n')?;
    Some((c.parse().ok()?, n.parse().ok()?))
}

/// One `list --scan-devices` row for `spec`: the superblock read without a mount (the device is never
/// written); `in_use` = the device is held (exit 3).
#[cfg(feature = "kernel-nvme")]
fn scan_device(spec: &str) -> (Value, bool) {
    let ctrl = match open_ro(spec) {
        Ok(c) => c,
        Err(e) => {
            return (
                json!({"device": spec, "status": "error", "error": e}),
                e.contains("in use"),
            );
        }
    };
    let mut d = match ctrl.open_queue() {
        Ok(d) => d,
        Err(e) => {
            return (
                json!({"device": spec, "status": "error", "error": e}),
                false,
            );
        }
    };
    match store::layout::read_super(&mut d, &mut store::dev::MonoClock::default()) {
        Ok((sb, _)) => (
            json!({
                "device": spec,
                "status": "flashstore",
                "osd_id": sb.osd_id,
                "osd_uuid": denc::types::Uuid(sb.osd_fsid).to_string(),
                "cluster_fsid": denc::types::Uuid(sb.cluster_fsid).to_string(),
                "format_version": sb.version,
            }),
            false,
        ),
        Err(store::error::StoreError::NotFormatted) => {
            (json!({"device": spec, "status": "no flashstore"}), false)
        }
        Err(e) => (
            json!({"device": spec, "status": "error", "error": format!("{e:?}")}),
            false,
        ),
    }
}

/// One plain row of `list --scan-devices`: bare tokens (no JSON quoting), like the `list` rows.
#[cfg(feature = "kernel-nvme")]
fn scan_row_plain(r: &Value) -> String {
    let dev = r["device"].as_str().unwrap_or("-");
    match r["status"].as_str() {
        Some("flashstore") => format!(
            "{dev:<20} flashstore  osd.{}  {}  {}  v{}",
            r["osd_id"],
            r["osd_uuid"].as_str().unwrap_or("-"),
            r["cluster_fsid"].as_str().unwrap_or("-"),
            r["format_version"]
        ),
        Some("no flashstore") => format!("{dev:<20} no flashstore"),
        _ => format!(
            "{dev:<20} error: {}",
            r["error"].as_str().unwrap_or("unreadable")
        ),
    }
}

/// `list --scan-devices`: every kernel NVMe namespace and its FlashStore superblock, read-only.
/// Exit: 0 = every device scanned, 1 = a device unreadable, 3 = a device held (rows: `status` flashstore |
/// no flashstore | error; the `error` field names the reason).
#[cfg(feature = "kernel-nvme")]
fn scan_devices(f: Format) -> i32 {
    let mut rows = Vec::new();
    let mut in_use = false;
    let mut errors = false;
    for p in nvme_namespaces() {
        let spec = format!("kernel:{}", p.display());
        let (row, busy) = scan_device(&spec);
        in_use |= busy;
        errors |= row["status"] == json!("error") && !busy;
        rows.push(row);
    }
    if f.is_json() {
        let out = f.records(&rows);
        if !out.is_empty() {
            println!("{out}");
        }
    } else {
        for r in &rows {
            println!("{}", scan_row_plain(r));
        }
    }
    if in_use {
        3
    } else if errors {
        1
    } else {
        0
    }
}

#[cfg(all(test, feature = "kernel-nvme"))]
mod kernel_host_tests {
    use super::check_hugepages;

    #[test]
    fn kernel_activation_does_not_require_reserved_hugepages() {
        assert!(check_hugepages("kernel:/dev/nvme0n1", 2048, 0).is_ok());
        assert!(check_hugepages("kernel:/dev/ng0n1", 2048, 0).is_ok());
        assert!(check_hugepages("kernel:relative", 2048, 0).is_err());
    }

    #[test]
    fn spdk_activation_still_requires_the_configured_hugepage_pool() {
        assert!(check_hugepages("spdk:0000:01:00.0", 2048, 0).is_err());
        assert!(check_hugepages("spdk:0000:01:00.0", 2048, 2048).is_ok());
    }
}

#[cfg(feature = "mon-std")]
/// Where `prepare` writes the OSD dir: where activate and the daemon look for it (`osddir::data_dir`: env >
/// conf `osd_data` > default); an explicit `--osd-data-root` places it at `<root>/<cluster>-<id>`.
fn prepared_dir(
    root_flag: Option<&std::path::Path>,
    opts: &std::collections::BTreeMap<String, String>,
    cl: &str,
    id: i64,
) -> PathBuf {
    match root_flag {
        Some(r) => r.join(format!("{cl}-{id}")),
        None => osddir::data_dir(opts, cl, id),
    }
}

// ------------------------------------------------------------------- list

pub fn list(a: &[String], f: Format) -> i32 {
    if flag(a, "--scan-devices") {
        if arg(a, "--osd-data-root").is_some() {
            return usage_err(
                "list --scan-devices: --osd-data-root is not used (the devices are scanned)",
            );
        }
        #[cfg(feature = "kernel-nvme")]
        return scan_devices(f);
        #[cfg(not(feature = "kernel-nvme"))]
        return usage_err(
            "list --scan-devices: needs a build with the kernel tier (feature kernel-nvme)",
        );
    }
    let root = match arg(a, "--osd-data-root") {
        Some(r) => PathBuf::from(r),
        None => {
            let cl = match osddir::cluster_from_args(a) {
                Ok(c) => c,
                Err(e) => return usage_err(&e),
            };
            let opts = match crate::devopen::optional_conf(a, &cl) {
                Ok(c) => c.for_osd(-1),
                Err(e) => return refuse(&e),
            };
            match osddir::data_root(&opts, &cl, -1) {
                Ok(r) => r,
                Err(e) => return refuse(&e),
            }
        }
    };
    let mut rows = Vec::new();
    let found = match osddir::scan(&root) {
        Ok(v) => v,
        Err(e) => return refuse(&e),
    };
    for (cl, id, p) in found {
        let row = match OsdDir::read(&p) {
            Ok(d) => {
                let drv = d.pci().and_then(osddir::pci_driver);
                json!({"cluster": cl, "osd_id": id, "osd_uuid": d.osd_uuid, "cluster_fsid": d.cluster_fsid,
                    "dev": d.dev, "driver": drv, "crush_device_class": d.crush_device_class,
                    "state": if OsdDir::is_ready(&p) { "ready" } else { "incomplete" }, "data_dir": p})
            }
            Err(e) => {
                json!({"cluster": cl, "osd_id": id, "state": "broken", "error": e, "data_dir": p})
            }
        };
        rows.push(row);
    }
    if f.is_json() {
        // a zero-row stream is zero bytes: an empty line is not a JSON record
        let out = f.records(&rows);
        if !out.is_empty() {
            println!("{out}");
        }
    } else {
        for r in &rows {
            println!(
                "{}-{}  {}  {}  driver={}  {}",
                r["cluster"].as_str().unwrap_or(""),
                r["osd_id"],
                r["state"].as_str().unwrap_or(""),
                r["dev"].as_str().unwrap_or("-"),
                r["driver"].as_str().unwrap_or("-"),
                r["osd_uuid"].as_str().unwrap_or("-")
            );
        }
    }
    0
}

// ---------------------------------------------------------------- inspect

/// Read-only identity dump: store superblock (no mount, no replay, no writes), controller identity, SMART summary,
/// plus the OSD dir if `--id` is given.
pub fn inspect(a: &[String], f: Format) -> i32 {
    let mut dir_v = Value::Null;
    let spec = match (
        arg(a, "--dev"),
        arg(a, "--id").and_then(|s| s.parse::<i64>().ok()),
    ) {
        (Some(d), _) => d,
        (None, Some(id)) => {
            let cl = match osddir::cluster_from_args(a) {
                Ok(c) => c,
                Err(e) => return usage_err(&e),
            };
            let opts = match crate::devopen::optional_conf(a, &cl) {
                Ok(c) => c.for_osd(id),
                Err(e) => return refuse(&e),
            };
            let dir = osddir::data_dir(&opts, &cl, id);
            match OsdDir::read(&dir) {
                Ok(d) => {
                    dir_v = json!({"path": dir, "whoami": d.whoami, "osd_uuid": d.osd_uuid, "cluster_fsid": d.cluster_fsid,
                        "dev": d.dev, "ready": OsdDir::is_ready(&dir)});
                    match crate::devopen::conf_backend_spec(&d.dev, &opts) {
                        Ok(s) => s,
                        Err(e) => return refuse(&e),
                    }
                }
                Err(e) => return refuse(&e),
            }
        }
        _ => {
            return usage_err(
                "inspect (--dev spdk:PCI[,ns=N] | --id N [--cluster C]) [--format plain|json|json-pretty]",
            );
        }
    };
    let ctrl = match open_ro(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("croit-flashstore-tool: inspect: {spec}: {e}");
            return crate::devopen::exit_code(&e);
        }
    };
    let sb = read_sb(&ctrl);
    let sb_err = sb.as_ref().err().cloned();
    let sb = sb
        .map(|s| sb_json(&s))
        .unwrap_or_else(|e| json!({"error": e}));
    let g = ctrl.geometry();
    let probe = ctrl.health_probe();
    let ident = probe.as_ref().map(|p| p.ident());
    let smart = probe.as_ref().and_then(|p| p.smart().ok()).map(|s| {
        json!({"critical_warning": s.critical_warning, "temperature_c": i32::from(s.temperature_k) - 273,
            "percentage_used": s.percentage_used, "available_spare": s.available_spare, "media_errors": s.media_errors,
            "power_on_hours": s.power_on_hours, "unsafe_shutdowns": s.unsafe_shutdowns})
    });
    // FNA bits 0/1 + several namespaces = a Format NVM would wipe them all (adr 0103)
    let ns = ctrl.ns_scope().map(|s| {
        json!({"fna": s.fna, "active": s.active, "allocated": s.allocated,
            "format_nvm_scope": if nvme::fna::check_format_scope(&s, 1).is_ok() { "namespace" } else { "all namespaces (refused)" }})
    });
    let v = json!({"dev": spec, "superblock": sb, "dir": dir_v, "namespaces": ns,
        "geometry": {"lba_size": g.lba_size, "capacity_bytes": g.capacity_bytes(), "vwc": g.vwc},
        "controller": ident.as_ref().map(|i| json!({"model": i.model, "serial": i.serial, "firmware": i.firmware, "device_id": i.device_id()})),
        "smart": smart});
    // plain = the indented document (no separate human layout)
    println!(
        "{}",
        if f == Format::Plain {
            Format::JsonPretty.doc(&v)
        } else {
            f.doc(&v)
        }
    );
    // the rest of the document (geometry, SMART) is still worth printing, but a device whose store identity cannot be
    // read is not "ok": exit 1 is the documented error code, a script must not read this as a healthy OSD
    if let Some(e) = sb_err {
        eprintln!("croit-flashstore-tool: inspect: {spec}: superblock: {e}");
        return 1;
    }
    0
}

#[cfg(all(test, feature = "mon-std"))]
mod dir_tests {
    use super::{prepared_dir, splinter_prepare_args};
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    #[test]
    fn prepare_preserves_a_foreign_directory() {
        let dir = std::env::temp_dir().join(format!("prepare-foreign-{}", std::process::id()));
        let original = osddir::OsdDir {
            whoami: 4,
            osd_uuid: "original-osd".into(),
            cluster_fsid: "original-cluster".into(),
            dev: "file:/original".into(),
            crush_device_class: "nvme".into(),
            keyring: osddir::keyring_text(4, "original-key"),
        };
        original.write(&dir).unwrap();
        let replacement = osddir::OsdDir {
            osd_uuid: "replacement-osd".into(),
            cluster_fsid: "replacement-cluster".into(),
            dev: "file:/replacement".into(),
            keyring: osddir::keyring_text(4, "replacement-key"),
            ..original.clone()
        };
        assert!(super::publish_prepared_dir(&replacement, &dir, false).is_err());
        assert_eq!(osddir::OsdDir::read(&dir).unwrap(), original);
        assert!(osddir::OsdDir::is_ready(&dir));
        // the same OSD re-prepared (device moved to another PCI address, new class) is updated in place
        let moved = osddir::OsdDir {
            dev: "file:/moved".into(),
            crush_device_class: "fast".into(),
            ..original.clone()
        };
        super::publish_prepared_dir(&moved, &dir, false).unwrap();
        assert_eq!(osddir::OsdDir::read(&dir).unwrap(), moved);
        assert!(osddir::OsdDir::is_ready(&dir));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn other_engine_prepare_never_inherits_splinter_flags() {
        let opts = BTreeMap::from([
            (
                "flashstore_store_splinterdb_dir".into(),
                "relative-unused-root".into(),
            ),
            ("flashstore_store_splinterdb_io".into(), "invalid".into()),
            (
                "flashstore_store_splinterdb_cache_stats".into(),
                "true".into(),
            ),
        ]);
        for engine in ["btree", "lsm", "rocksdb"] {
            let a = vec!["--omap-engine".into(), engine.into()];
            assert!(splinter_prepare_args(&a, &opts).is_empty());
            let mut configured = opts.clone();
            configured.insert("flashstore_omap_engine".into(), engine.into());
            assert!(splinter_prepare_args(&[], &configured).is_empty());
        }
        assert!(splinter_prepare_args(&["--omap-lsm".into()], &opts).is_empty());
        let mut legacy = opts.clone();
        legacy.insert("flashstore_omap_lsm".into(), "true".into());
        assert!(splinter_prepare_args(&[], &legacy).is_empty());
        // No selector is not permission to assume the existing device is B-tree.
        // Dormant options remain parseable without the SDB feature and are used
        // only if the persistent format actually selects the supported backend.
        let inherited = splinter_prepare_args(&[], &opts);
        assert_eq!(crate::mkfs::engine_options(&inherited).unwrap(), None);
        assert!(inherited.iter().any(|v| v == "relative-unused-root"));
        let selected = vec![
            "--omap-engine".into(),
            "splinterdb".into(),
            "--splinterdb-dir".into(),
            "/explicit/root".into(),
            "--splinterdb-capacity".into(),
            "134217728".into(),
        ];
        let backing = splinter_prepare_args(&selected, &opts);
        assert_eq!(
            crate::arg(&backing, "--splinterdb-dir"),
            Some("/explicit/root".into())
        );
        assert_eq!(
            crate::arg(&backing, "--splinterdb-capacity"),
            Some("134217728".into())
        );
    }

    /// T5: with conf `osd_data` set, prepare writes the dir activate and the daemon read.
    #[test]
    fn prepare_writes_the_osd_data_dir_activate_reads() {
        let opts = BTreeMap::from([("osd_data".to_string(), "/srv/ceph/$cluster-$id".to_string())]);
        assert_eq!(
            prepared_dir(None, &opts, "ceph", 4),
            osddir::data_dir(&opts, "ceph", 4)
        );
        assert_eq!(
            prepared_dir(None, &opts, "ceph", 4),
            PathBuf::from("/srv/ceph/ceph-4")
        );
        assert_eq!(
            osddir::data_root(&opts, "ceph", 4),
            Ok(PathBuf::from("/srv/ceph"))
        );
        assert_eq!(
            prepared_dir(Some(Path::new("/x")), &opts, "ceph", 4),
            PathBuf::from("/x/ceph-4")
        );
        assert_eq!(
            osddir::data_root(&BTreeMap::new(), "ceph", 4),
            Ok(PathBuf::from(osddir::DEFAULT_ROOT))
        );
    }
}

#[cfg(test)]
mod from_device_tests {
    #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
    use super::device_open_err;
    #[cfg(feature = "kernel-nvme")]
    use super::scan_row_plain;
    use super::{DirState, FromDevicePlan, from_device_plan, host_check_dev, is_ns_head};
    use osddir::OsdDir;

    const DEV: &str = "kernel:/dev/nvme0n1";

    #[cfg(feature = "kernel-nvme")]
    #[test]
    fn scan_plain_rows_carry_bare_tokens() {
        let r = serde_json::json!({"device": "kernel:/dev/nvme0n1", "status": "flashstore",
            "osd_id": 3, "osd_uuid": "u-1", "cluster_fsid": "f-1", "format_version": 7});
        assert_eq!(
            scan_row_plain(&r),
            "kernel:/dev/nvme0n1  flashstore  osd.3  u-1  f-1  v7"
        );
        let r = serde_json::json!({"device": "kernel:/dev/nvme1n1", "status": "no flashstore"});
        assert_eq!(scan_row_plain(&r), "kernel:/dev/nvme1n1  no flashstore");
        assert!(!scan_row_plain(&r).contains('"'));
    }

    fn od(id: i64, uuid: &str, fsid: &str, dev: &str) -> OsdDir {
        OsdDir {
            whoami: id,
            osd_uuid: uuid.into(),
            cluster_fsid: fsid.into(),
            dev: dev.into(),
            crush_device_class: "nvme".into(),
            keyring: String::new(),
        }
    }

    #[test]
    fn a_missing_dir_is_created() {
        assert_eq!(
            from_device_plan(5, "u", "c", DEV, &DirState::Empty),
            FromDevicePlan::Create
        );
    }

    #[test]
    fn a_broken_dir_is_refused() {
        assert_eq!(
            from_device_plan(
                5,
                "u",
                "c",
                DEV,
                &DirState::Broken("marker: bad json".into())
            ),
            FromDevicePlan::Refuse("marker: bad json".into())
        );
    }

    #[test]
    fn a_same_identity_dir_is_idempotent() {
        let d = DirState::Read(od(5, "u", "c", DEV));
        assert_eq!(
            from_device_plan(5, "u", "c", DEV, &d),
            FromDevicePlan::Idempotent
        );
    }

    #[test]
    fn an_osd_id_mismatch_is_refused() {
        let d = DirState::Read(od(6, "u", "c", DEV));
        let p = from_device_plan(5, "u", "c", DEV, &d);
        assert!(
            matches!(p, FromDevicePlan::Refuse(ref m) if m.contains("osd id 5 (dir says 6)")),
            "{p:?}"
        );
    }

    #[test]
    fn uuid_and_fsid_mismatches_are_refused() {
        let d = DirState::Read(od(5, "u-other", "c", DEV));
        assert!(
            matches!(from_device_plan(5, "u", "c", DEV, &d), FromDevicePlan::Refuse(ref m) if m.contains("osd uuid")),
            "{d:?}"
        );
        let d = DirState::Read(od(5, "u", "c-other", DEV));
        assert!(
            matches!(from_device_plan(5, "u", "c", DEV, &d), FromDevicePlan::Refuse(ref m) if m.contains("cluster fsid")),
            "{d:?}"
        );
    }

    #[test]
    fn a_different_device_in_the_dir_is_refused() {
        let d = DirState::Read(od(5, "u", "c", "kernel:/dev/nvme1n1"));
        assert!(
            matches!(from_device_plan(5, "u", "c", DEV, &d), FromDevicePlan::Refuse(ref m) if m.contains("device")),
            "{d:?}"
        );
    }

    #[test]
    fn namespace_head_names() {
        assert_eq!(is_ns_head("nvme0n1"), Some((0, 1)));
        assert_eq!(is_ns_head("nvme12n3"), Some((12, 3)));
        assert_eq!(is_ns_head("nvme0n10"), Some((0, 10)));
        assert_eq!(
            is_ns_head("nvme0n1p1"),
            None,
            "a partition is not a namespace head"
        );
        assert_eq!(
            is_ns_head("nvme0"),
            None,
            "a controller entry is not a namespace head"
        );
        assert_eq!(is_ns_head("sda"), None);
        assert_eq!(
            is_ns_head("nvme0c1n1"),
            None,
            "a multipath hidden path is not a /dev head"
        );
    }

    #[test]
    fn vmd_domain_is_refused_by_the_host_check_before_prepare_writes() {
        let e = host_check_dev("spdk:10000:03:00.0").unwrap_err();
        assert!(e.contains("VMD") && e.contains("kernel:"), "{e}");
    }

    #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
    #[test]
    fn activate_open_error_classifies_transient_not_ready_vs_permanent_in_use() {
        // held by a running OSD/tool (or mounted/partitioned): permanent refusal, no retry
        let (c, m) = device_open_err(
            DEV,
            "/dev/nvme0n1: in use (mounted, partition/holder active, or opened by another OSD or tool)",
        );
        assert_eq!(c, 3, "{m}");
        assert!(m.starts_with("device kernel:/dev/nvme0n1:"), "{m}");

        // a device that is not there/openable yet (slow udev, controller not bound yet, transient EIO): retryable
        for e in [
            "/dev/nvme0n1: No such file or directory (os error 2)",
            "/dev/nvme0n1: No such device (os error 19)",
            "/dev/nvme0n1: Input/output error (os error 5)",
        ] {
            let (c, m) = device_open_err(DEV, e);
            assert_eq!(c, 1, "{e}: {m}");
            assert!(
                m.starts_with("device kernel:/dev/nvme0n1 not ready:")
                    && m.contains(" not ready: ")
                    && m.contains(e),
                "{e}: {m}"
            );
        }
    }
}
