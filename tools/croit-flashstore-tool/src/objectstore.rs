// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `croit-flashstore-tool objectstore ...`: offline `ceph-objectstore-tool` parity (doc/ops/objectstore-tool.md).
//! Device: `--dev SPEC`, or `--id N [--cluster C]` / `--data-path DIR` (resolved through the OSD data dir).
//! Refuses while the OSD runs (its admin socket answers; `file:` devices are `flock`ed, `spdk:` devices are claimed with
//! SPDK's PCI lock before DPDK maps them, nvme::pcilock); a held device exits 3.
use crate::arg;
use nvme::any::{AnyCtrl, DevSpec};
use osd::nvmestore::{NvmeMeta, mount_dev};
use osddir::OsdDir;
use std::cell::RefCell;
use std::io::{IsTerminal, Write};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use storeadapt::StoreAdapter;

/// Ops that write; they first finish PG removals interrupted by a crash (like classic `finish_remove_pgs`).
/// The authoritative list lives in `ostool::mutating` (shared with the degraded-refusal check).
fn mutating(o: &ostool::Opts) -> bool {
    ostool::mutating(o)
}

/// `(device spec to open, admin socket of the OSD)`: an OSD-dir device follows conf `flashstore_store_backend`; the socket is known for `--id` / `--data-path` (conf `admin_socket`,
/// default `/var/run/ceph/<cluster>-osd.<id>.asok`, like the daemon).
pub(crate) fn resolve_dev(a: &[String]) -> Result<(String, Option<(OsdDir, String)>), String> {
    // same option syntax as `ostool::Opts::parse`: `--dev=X` must select X, not fall back to `--data-path`
    let a = outfmt::normalize_args(a);
    let a = a.as_slice();
    if let Some(d) = arg(a, "--dev") {
        crate::mkfs::configure_splinter(a)?;
        return Ok((d, None));
    }
    let cluster = osddir::cluster_from_args(a)?;
    let conf = crate::devopen::optional_conf(a, &cluster)?;
    let opts = |id: i64| conf.for_osd(id);
    let dir = if let Some(p) = arg(a, "--data-path") {
        std::path::PathBuf::from(p)
    } else if let Some(id) = arg(a, "--id").and_then(|s| s.parse::<i64>().ok()) {
        osddir::data_dir(&opts(id), &cluster, id)
    } else {
        return Err("need --dev SPEC, --id N or --data-path DIR".into());
    };
    let d = OsdDir::read(&dir)?;
    if let Some(want) = arg(a, "--id") {
        let want = want
            .parse::<i64>()
            .map_err(|_| "--id: invalid OSD id".to_owned())?;
        if want != d.whoami {
            return Err(format!(
                "refused: {} belongs to osd.{}, requested osd.{want}",
                dir.display(),
                d.whoami
            ));
        }
    }
    let id = d.whoami;
    let mut backing = a.to_vec();
    if arg(a, "--splinterdb-dir").is_none()
        && let Some(root) = opts(id).get("flashstore_store_splinterdb_dir")
    {
        backing.extend(["--splinterdb-dir".into(), root.clone()]);
    }
    for (flag, key) in [
        ("--splinterdb-io", "flashstore_store_splinterdb_io"),
        (
            "--splinterdb-prefetch-bytes",
            "flashstore_store_splinterdb_prefetch_bytes",
        ),
        (
            "--splinterdb-scan-readahead-pages",
            "flashstore_store_splinterdb_scan_readahead_pages",
        ),
    ] {
        if arg(a, flag).is_none()
            && let Some(value) = opts(id).get(key)
        {
            backing.extend([flag.into(), value.clone()]);
        }
    }
    if !a.iter().any(|s| s == "--splinterdb-cache-stats")
        && opts(id)
            .get("flashstore_store_splinterdb_cache_stats")
            .is_some_and(|s| matches!(s.as_str(), "true" | "1" | "yes" | "on"))
    {
        backing.push("--splinterdb-cache-stats".into());
    }
    crate::mkfs::configure_splinter(&backing)?;
    let asok = opts(id)
        .get("admin_socket")
        .map(|s| osddir::expand(s.trim(), &cluster, id))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("/var/run/ceph/{cluster}-osd.{id}.asok"));
    let dev = crate::devopen::conf_backend_spec(&d.dev, &opts(id))?;
    Ok((dev, Some((d, asok))))
}

/// The device superblock names the selected OSD directory's OSD: UUID, id and cluster fsid must agree. Provisioning
/// labels keep id -1 / a zero cluster fsid until the OSD first mounts, so those two fields only count once set.
/// Shared by `activate` and every directory-selected offline tool (`validate_device`).
pub(crate) fn check_identity(sb: &store::layout::Superblock, d: &OsdDir) -> Result<(), String> {
    let uuid = denc::types::Uuid(sb.osd_fsid).to_string();
    let cluster = denc::types::Uuid(sb.cluster_fsid).to_string();
    if uuid != d.osd_uuid
        || (sb.osd_id != -1 && i64::from(sb.osd_id) != d.whoami)
        || (sb.cluster_fsid != [0; 16] && cluster != d.cluster_fsid)
    {
        return Err(format!(
            "device identity (osd.{}, UUID {uuid}, cluster {cluster}) disagrees with selected OSD directory (osd.{}, UUID {}, cluster {}): the directory's device path names another OSD's device; check `croit-flashstore-tool inspect --dev SPEC` and fix the `dev` in the directory's croit-flashstore-osd marker (or pass the intended --dev)",
            sb.osd_id, d.whoami, d.osd_uuid, d.cluster_fsid
        ));
    }
    Ok(())
}

/// Bind a directory-selected device before replay, checkpoint, repair or upgrade can write.
/// A directly supplied device has no directory identity to compare. Provisioning labels
/// retain id -1 / zero cluster UUID; the OSD UUID is present from the initial format.
pub(crate) fn validate_device(ctrl: &AnyCtrl, expected: Option<&OsdDir>) -> Result<(), String> {
    let Some(d) = expected else {
        return Ok(());
    };
    let mut queue = ctrl.open_queue()?;
    let (sb, _) = store::layout::read_super(&mut queue, &mut store::dev::MonoClock::default())
        .map_err(|e| format!("refused: cannot read device identity: {e}"))?;
    check_identity(&sb, d).map_err(|e| format!("refused: {e}"))
}

/// Is a daemon answering on that admin socket?
pub(crate) fn osd_running(asok: &str) -> bool {
    UnixStream::connect(asok).is_ok()
}

fn compatibility_args(a: &[String]) -> Result<Vec<String>, String> {
    // Backing options are interpreted from the original arguments by resolve_dev,
    // never by the upstream-compatible objectstore operation parser.
    let mut filtered = Vec::new();
    let mut i = 0;
    while i < a.len() {
        if matches!(
            a[i].as_str(),
            "--rocksdb-dir"
                | "--splinterdb-dir"
                | "--splinterdb-capacity"
                | "--splinterdb-io"
                | "--splinterdb-prefetch-bytes"
                | "--splinterdb-scan-readahead-pages"
        ) {
            if i + 1 == a.len() || a[i + 1].starts_with("--") {
                return Err(format!("{} requires a value", a[i]));
            }
            i += 2;
        } else if matches!(
            a[i].as_str(),
            "--splinterdb-cache-stats" | "--splinterdb-lab-filesystem" | "--splinterdb-no-log"
        ) {
            i += 1;
        } else {
            filtered.push(a[i].clone());
            i += 1;
        }
    }
    Ok(filtered)
}

pub fn run(a: &[String]) -> i32 {
    let filtered = match compatibility_args(a) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("croit-flashstore-tool objectstore: {error}");
            return 2;
        }
    };
    let mut o = match ostool::Opts::parse(&filtered) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("croit-flashstore-tool objectstore: {e}\n{}", ostool::USAGE);
            return 2;
        }
    };
    if o.op.is_none() && o.objcmd.is_none() {
        eprintln!("{}", ostool::USAGE);
        return 2;
    }
    o.tty = o.tty || std::io::stdout().is_terminal();
    o.stdin_tty = std::io::stdin().is_terminal();
    if o.op.as_deref() == Some("dump-export") {
        let input: Box<dyn std::io::Read> = match o.file.as_deref() {
            None | Some("-") => Box::new(std::io::stdin()),
            Some(f) => match std::fs::File::open(f) {
                Ok(f) => Box::new(std::io::BufReader::new(f)),
                Err(e) => {
                    eprintln!("file: {f}: {e}");
                    return 1;
                }
            },
        };
        return ostool::dump_export_cmd(
            &o,
            input,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        );
    }
    let (spec, who) = match resolve_dev(a) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("croit-flashstore-tool objectstore: {e}");
            return if e.starts_with("refused:") { 3 } else { 2 };
        }
    };
    if let Some((d, asok)) = &who
        && osd_running(asok)
    {
        let id = d.whoami;
        eprintln!(
            "croit-flashstore-tool objectstore: osd.{id} is running (admin socket {asok} answers): stop it first (systemctl stop croit-flashstore-osd@{id})"
        );
        return 3;
    }
    // classic: ops that only read the export file need no store
    let dspec = match DevSpec::parse(&spec) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("croit-flashstore-tool objectstore: {e}");
            return 2;
        }
    };
    let ctrl = match crate::devopen::open(&dspec, false, crate::devopen::MOUNT_HUGEPAGES_MB) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("croit-flashstore-tool objectstore: {spec}: {e}");
            // held by a running OSD or another tool (file: flock, spdk: PCI claim)
            return crate::devopen::exit_code(&e);
        }
    };
    if let Err(e) = validate_device(&ctrl, who.as_ref().map(|(d, _)| d)) {
        eprintln!("croit-flashstore-tool objectstore: {e}");
        return 3;
    }
    if o.degraded() {
        return run_degraded(&ctrl, o);
    }
    if !mutating(&o) || o.dry_run {
        return match osd::nvmestore::mount_dev_read_only(&ctrl) {
            Ok((st, _)) => run_store(st, o),
            Err(e) => {
                eprintln!("Mount failed with '{e}'");
                eprintln!(
                    "croit-flashstore-tool objectstore: a damaged shard can be skipped: mount the healthy shards read-only with --skip-shard N (docs/how-to/recover-pg.md)"
                );
                1
            }
        };
    }
    let (st, _) = match mount_dev(&ctrl) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Mount failed with '{e}'");
            eprintln!(
                "croit-flashstore-tool objectstore: a damaged shard can be skipped: mount the healthy shards read-only with --skip-shard N (docs/how-to/recover-pg.md)"
            );
            return 1;
        }
    };
    run_store(st, o)
}

/// Degraded read-only mount (`--skip-shard N` / `--shards LIST`): mount only the selected shards, never write, and
/// report each shard's outcome. A mutating op is refused before anything is opened (exit [`ostool::EXIT_DEGRADED`]).
fn run_degraded(ctrl: &AnyCtrl, o: ostool::Opts) -> i32 {
    use store::obj::ShardMountState;
    if mutating(&o) {
        let what =
            o.op.clone()
                .or_else(|| o.objcmd.clone())
                .unwrap_or_default();
        eprintln!(
            "croit-flashstore-tool objectstore: --op {what} writes to the store and is refused on a degraded \
             read-only mount (--skip-shard/--shards); only read-only ops are allowed"
        );
        return ostool::EXIT_DEGRADED;
    }
    // Validate the selection against the device's shard count (read-only superblock probe).
    let nshards = {
        let mut q = match ctrl.open_queue() {
            Ok(q) => q,
            Err(e) => {
                eprintln!("Mount failed with '{e}'");
                return 1;
            }
        };
        let (sb, _) = match store::layout::read_super(&mut q, &mut store::dev::MonoClock::default())
        {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Mount failed with '{e}'");
                return 1;
            }
        };
        sb.shards
    };
    for &s in o.skip_shards.iter().chain(&o.shards) {
        if s >= nshards {
            eprintln!(
                "croit-flashstore-tool objectstore: shard id {s} is out of range (device has {nshards} shards)"
            );
            return 2;
        }
    }
    if o.excludes_shard(0) {
        eprintln!(
            "croit-flashstore-tool objectstore: shard 0 holds the OSD meta collection (superblock, OSD maps) every op \
             needs and cannot be skipped"
        );
        return 2;
    }
    let owned = |shard: u32| !o.excludes_shard(shard);
    let (st, _stats, report) = match osd::nvmestore::mount_dev_read_only_shards(ctrl, owned) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Mount failed with '{e}'");
            return 1;
        }
    };
    if let Err(e) = emit_mount_report(&o, &report) {
        eprintln!("croit-flashstore-tool objectstore: mount report: {e}");
    }
    // A selected shard whose mount failed (damaged, not skipped) must also be skipped: no export may be silently partial.
    let failed: Vec<u32> = report
        .iter()
        .enumerate()
        .filter_map(|(i, s)| matches!(s, ShardMountState::Failed(_)).then_some(i as u32))
        .collect();
    if !failed.is_empty() {
        eprintln!(
            "croit-flashstore-tool objectstore: shard(s) {} failed to mount; add --skip-shard for each failed shard",
            failed
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        return 1;
    }
    run_store(st, o)
}

/// Emit the per-shard mount report to stderr: one line per shard in plain mode, a `{"shards":[{"id","state","error"}]}`
/// document otherwise (`state` = `mounted` | `skipped` | `failed`).
fn emit_mount_report(
    o: &ostool::Opts,
    report: &[store::obj::ShardMountState],
) -> std::io::Result<()> {
    use store::obj::ShardMountState;
    let fmt = outfmt::Format::parse(&o.format).unwrap_or(outfmt::Format::Plain);
    let mut err = std::io::stderr().lock();
    if fmt != outfmt::Format::Plain {
        let shards: Vec<serde_json::Value> = report
            .iter()
            .enumerate()
            .map(|(id, s)| match s {
                ShardMountState::Mounted => serde_json::json!({"id": id, "state": "mounted"}),
                ShardMountState::Skipped => serde_json::json!({"id": id, "state": "skipped"}),
                ShardMountState::Failed(e) => {
                    serde_json::json!({"id": id, "state": "failed", "error": e})
                }
            })
            .collect();
        writeln!(err, "{}", fmt.doc(&serde_json::json!({ "shards": shards })))?;
        return Ok(());
    }
    for (id, s) in report.iter().enumerate() {
        match s {
            ShardMountState::Mounted => writeln!(err, "shard {id}: mounted")?,
            ShardMountState::Skipped => writeln!(err, "shard {id}: skipped")?,
            ShardMountState::Failed(e) => writeln!(err, "shard {id}: failed: {e}")?,
        }
    }
    Ok(())
}

fn run_store<D: store::dev::BlockDev + 'static>(
    st: store::obj::Store<D, store::dev::MonoClock>,
    o: ostool::Opts,
) -> i32 {
    let shared = Rc::new(RefCell::new(st));
    // a degraded session commits nothing, not even the (no-op) meta collection create
    let meta = if o.degraded() {
        NvmeMeta::open_read_only(shared.clone())
    } else {
        NvmeMeta::new(shared.clone())
    };
    let mut meta = match meta {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Mount failed with '{e}'");
            return 1;
        }
    };
    let ad = StoreAdapter::from_shared(shared);
    if mutating(&o)
        && !o.dry_run
        && let Err(e) = ad.resume_removals()
    {
        eprintln!("finish_remove_pgs: {e}");
        return 1;
    }
    let (mut out, mut err) = (std::io::stdout().lock(), std::io::stderr().lock());
    let mut c = ostool::Ctx {
        ad: &ad,
        meta: &mut meta,
        o: &o,
        out: &mut out,
        err: &mut err,
        input: Some(Box::new(std::io::stdin())),
    };
    ostool::run(&mut c)
}

#[cfg(test)]
mod tests {
    use super::resolve_dev;

    #[test]
    fn equals_device_selection_matches_the_compatibility_parser() {
        let root = std::env::temp_dir().join(format!("objectstore-equals-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let dir = root.join("ceph-5");
        osddir::OsdDir {
            whoami: 5,
            osd_uuid: denc::types::Uuid([5; 16]).to_string(),
            cluster_fsid: denc::types::Uuid([1; 16]).to_string(),
            dev: "file:/directory-selected.img".into(),
            crush_device_class: "nvme".into(),
            keyring: osddir::keyring_text(5, ""),
        }
        .write(&dir)
        .unwrap();
        let conf = root.join("ceph.conf");
        std::fs::write(&conf, format!("[osd]\nosd_data = {}\n", dir.display())).unwrap();
        let explicit = vec![
            "--data-path".into(),
            dir.display().to_string(),
            "--dev=file:/explicit.img".into(),
            "--op=remove".into(),
            "--pgid=1.0".into(),
            "--force".into(),
        ];
        ostool::Opts::parse(&explicit).unwrap();
        let (spec, who) = resolve_dev(&explicit).unwrap();
        assert_eq!(spec, "file:/explicit.img");
        assert!(who.is_none());
        for args in [
            vec![format!("--data-path={}", dir.display())],
            vec!["--id=5".into(), format!("--conf={}", conf.display())],
        ] {
            ostool::Opts::parse(&args).unwrap();
            let (spec, who) = resolve_dev(&args).unwrap();
            assert_eq!(spec, "file:/directory-selected.img");
            assert_eq!(who.unwrap().0.whoami, 5);
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_id_must_match_the_selected_osd_directory() {
        let root = std::env::temp_dir().join(format!("objectstore-id-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let dir = root.join("ceph-5");
        osddir::OsdDir {
            whoami: 5,
            osd_uuid: denc::types::Uuid([5; 16]).to_string(),
            cluster_fsid: denc::types::Uuid([1; 16]).to_string(),
            dev: "file:/wrong-osd.img".into(),
            crush_device_class: "nvme".into(),
            keyring: osddir::keyring_text(5, ""),
        }
        .write(&dir)
        .unwrap();
        let conf = root.join("ceph.conf");
        std::fs::write(&conf, format!("[osd]\nosd_data = {}\n", dir.display())).unwrap();
        let a = vec![
            "--id".into(),
            "6".into(),
            "--cluster".into(),
            "ceph".into(),
            "--conf".into(),
            conf.display().to_string(),
        ];
        let err = resolve_dev(&a).unwrap_err();
        assert!(err.contains("belongs to osd.5"), "{err}");
        assert_eq!(crate::ops::repair(&a, outfmt::Format::Json), 3);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod backing_option_tests {
    use super::compatibility_args;

    fn args(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn foreign_backing_options_never_reach_the_operation_parser() {
        let original = args(&[
            "--dev",
            "file:fixture",
            "--op",
            "list",
            "--rocksdb-dir",
            "/foreign/rocks",
            "--splinterdb-dir",
            "/foreign/splinter",
            "--splinterdb-capacity",
            "134217728",
            "--splinterdb-io",
            "buffered",
            "--splinterdb-prefetch-bytes",
            "262144",
            "--splinterdb-scan-readahead-pages",
            "3",
            "--splinterdb-cache-stats",
            "--splinterdb-lab-filesystem",
            "--splinterdb-no-log",
        ]);
        let retained = original.clone();
        assert_eq!(
            compatibility_args(&original).unwrap(),
            args(&["--dev", "file:fixture", "--op", "list"])
        );
        assert_eq!(
            original, retained,
            "resolve_dev still sees all backing settings"
        );
    }

    #[test]
    fn missing_foreign_option_values_are_not_silently_removed() {
        for flag in [
            "--rocksdb-dir",
            "--splinterdb-dir",
            "--splinterdb-capacity",
            "--splinterdb-io",
            "--splinterdb-prefetch-bytes",
            "--splinterdb-scan-readahead-pages",
        ] {
            assert!(
                compatibility_args(&args(&[flag]))
                    .unwrap_err()
                    .contains("requires a value")
            );
            assert!(compatibility_args(&args(&[flag, "--op", "list"])).is_err());
        }
    }
}
