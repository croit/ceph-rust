// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `croit-flashstore-osd run --id N [--cluster ceph] [--conf F] [--data-dir D] [-f] [--show-config] [flags...]`: conf-file driven
//! start (adr 0034, doc/ops/deploy.md). `/etc/ceph/<cluster>.conf` (`[global]` < `[osd]` < `[osd.N]`,
//! `flashstore_*` keys) + the OSD dir give the daemon flags; extra flags on the command line override them.
//! Exit 3 = configuration/precondition error (the unit sets RestartPreventExitStatus=3).
use crate::args::arg;
use osd::config::KeyClass;
use osddir::{Conf, OsdDir};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn norm_key(k: &str) -> String {
    k.replace([' ', '-'], "_")
}

/// Feed the command line's `--set k=v` into the option map the conf file fills (precedence: flag > `--set` > conf), so
/// `--set flashstore_hostname=X` acts exactly like the conf key. A key nobody reads is an error, not a silent no-op
/// (adr 0021 am. 60): a key we read is applied; a valid Ceph option we do not use is accepted and returned (the caller
/// reports it); anything else is an error. Returns the ignored keys.
fn merge_set(opts: &mut BTreeMap<String, String>, a: &[String]) -> Result<Vec<String>, String> {
    let mut ignored: Vec<String> = Vec::new();
    let mut it = a.iter();
    while let Some(x) = it.next() {
        if x != "--set" {
            continue;
        }
        let kv = it.next().ok_or("--set needs k=v")?;
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| format!("--set {kv:?}: expected k=v"))?;
        let k = norm_key(k.trim());
        match osd::config::classify(&k) {
            KeyClass::Read => {
                opts.retain(|ck, _| norm_key(ck) != k);
                opts.insert(k, v.to_owned());
            }
            KeyClass::Ignored => {
                if !ignored.contains(&k) {
                    ignored.push(k);
                }
            }
            KeyClass::Unknown => {
                return Err(format!(
                    "--set: unknown option {k:?} (not a Ceph option, not flashstore_*)"
                ));
            }
        }
    }
    Ok(ignored)
}

/// `flashstore_net` / `--net X` (single transport since adr 0682) are obsolete: one loud warning, never a start failure; the
/// key and the flag are not forwarded. Returns `a` without `--net X`.
fn drop_obsolete_net(opts: &mut BTreeMap<String, String>, a: &[String]) -> Vec<String> {
    let in_conf = opts.keys().any(|k| norm_key(k) == "flashstore_net");
    opts.retain(|k, _| norm_key(k) != "flashstore_net");
    let mut out = Vec::with_capacity(a.len());
    let mut it = a.iter().peekable();
    let mut on_cli = false;
    while let Some(x) = it.next() {
        if x == "--set" {
            let kv = it.next();
            if kv.is_some_and(|kv| {
                norm_key(kv.split('=').next().unwrap_or("").trim()) == "flashstore_net"
            }) {
                on_cli = true;
            } else {
                out.push(x.clone());
                out.extend(kv.cloned());
            }
        } else if x == "--net" {
            on_cli = true;
            if it.peek().is_some_and(|n| !n.starts_with('-')) {
                it.next();
            }
        } else {
            out.push(x.clone());
        }
    }
    if in_conf || on_cli {
        eprintln!(
            "croit-flashstore-osd: WARNING config: flashstore_net is obsolete (adr 0682), remove it"
        );
    }
    out
}

/// What `croit-flashstore-osd run` starts: the daemon's flags (without argv[0]) and the prepared OSD dir, if any (identity of the mon
/// config bootstrap).
#[derive(Debug)]
pub(crate) struct Resolved {
    pub(crate) args: Vec<String>,
    pub(crate) dir: Option<OsdDir>,
}

/// Daemon flag list for `run`; command line flags override the conf. Reads the conf and the OSD dir, no network.
pub(crate) fn resolve(a: &[String]) -> Result<Resolved, String> {
    let id: i64 = arg(a, "--id")
        .or_else(|| std::env::var("FLASHSTORE_ID").ok())
        .and_then(|s| s.parse().ok())
        .ok_or("run: --id N required")?;
    let cluster = osddir::cluster_from_args(a)?;
    let conf_p = osddir::conf_file(a, &cluster)?;
    let mut opts = Conf::load(&conf_p)?.for_osd(id);
    let stripped = drop_obsolete_net(&mut opts, a);
    let a = stripped.as_slice();
    // the conf file alone: its settings reach the daemon at conf-file level (`--conf-set`), next to the command line's
    let file_opts = opts.clone();
    let ignored = merge_set(&mut opts, a)?;
    let dir = arg(a, "--data-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| osddir::data_dir(&opts, &cluster, id));
    // An OSD dir that is there but does not validate (marker/whoami/fsid/device/spec/keyring) is a start error: treating it
    // as absent would silently drop its device, identity and keyring. Only a missing dir means "no OSD dir".
    let od = match std::fs::metadata(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{}: {e}", dir.display())),
        Ok(_) => Some(OsdDir::read(&dir)?),
    };
    if let Some(d) = &od
        && d.whoami != id
    {
        return Err(format!("{} belongs to osd.{}", dir.display(), d.whoami));
    }
    if let (Some(d), Some(dev)) = (&od, arg(a, "--dev"))
        && !osddir::same_dev(&dev, &d.dev)
    {
        return Err(format!(
            "--dev {dev:?} disagrees with {}/croit-flashstore-osd ({:?})",
            dir.display(),
            d.dev
        ));
    }
    // resolved flags + `--data` is not used (device store), `--hostname`/`--set` stay overridable
    let mut out: Vec<String> = Vec::new();
    // command line overrides first (the daemon takes the first occurrence of a flag)
    let mut skip = false;
    for (i, x) in a.iter().enumerate() {
        if skip {
            skip = false;
            continue;
        }
        match x.as_str() {
            "--id" | "--cluster" | "--conf" | "--data-dir" => skip = true,
            "-f" | "--foreground" | "--show-config" => {}
            _ => out.push(a[i].clone()),
        }
    }
    out.extend(osddir::run_args(&opts, od.as_ref(), &dir)?);
    out.extend(["--place-id".to_owned(), id.to_string()]); // L3 placement rank (adr 0063)
    // ceph options the daemon interprets itself (logging, admin socket, crash dir, op tracker): `--set k=v`
    out.extend(["--set".to_owned(), format!("cluster={cluster}")]);
    // valid Ceph options we do not use: one line each (the daemon's `status` lists them from its own local config)
    for k in &ignored {
        eprintln!("croit-flashstore-osd: --set {k} ignored: not used by croit-flashstore-osd");
    }
    // every setting reaches the daemon's local config with its source level (adr 0034 am. 6), so `config get/show`
    // answer startup-only options and `config diff` / the mgr's `config show` name the source like classic: conf file
    // and prepared OSD dir = `--conf-set`, daemon flags of the command line (`--cores 6` = `flashstore_cores`) = `--set`
    // (the command line's own `--set` pairs are already in `out`). Classic reads the whole file; a name that is neither a
    // Ceph option nor flashstore_* has no reader: one line, not forwarded.
    let mut file = file_opts.clone();
    if let Some(d) = &od {
        file.entry("flashstore_dev".to_owned())
            .or_insert_with(|| d.dev.clone());
    }
    let flags: BTreeMap<String, String> = cli_flag_options(a).into_iter().collect();
    for (flag, set) in [("--conf-set", file), ("--set", flags)] {
        for (k, v) in set {
            let k = norm_key(&k);
            if k == "osd_data" {
                continue; // resolved below
            }
            if osd::config::classify(&k) == KeyClass::Unknown {
                eprintln!("croit-flashstore-osd: conf option {k} ignored: not a Ceph option");
            } else {
                out.extend([flag.to_owned(), format!("{k}={v}")]);
            }
        }
    }
    // the resolved data dir (`--data-dir` > `FLASHSTORE_DATA_DIR` > `--set`/conf `osd_data`), metavariables expanded: the
    // daemon's `$osd_data/keyring` and `rotate-stored-key` use it. Its level is its source's; a command-line `--set
    // osd_data` always gets the resolved value as a command-line setting, so the raw one never wins. The built-in
    // default is not a setting: the daemon expands the same default itself.
    let cli_data = a.windows(2).any(|w| {
        w[0] == "--set" && norm_key(w[1].split('=').next().unwrap_or("").trim()) == "osd_data"
    });
    let data_flag = if arg(a, "--data-dir").is_some() || cli_data {
        Some("--set")
    } else if std::env::var("FLASHSTORE_DATA_DIR").is_ok_and(|d| !d.is_empty()) {
        Some("--env-set")
    } else if file_opts.get("osd_data").is_some_and(|d| !d.is_empty()) {
        Some("--conf-set")
    } else {
        None
    };
    if let Some(flag) = data_flag {
        out.extend([flag.to_owned(), format!("osd_data={}", dir.display())]);
    }
    Ok(Resolved { args: out, dir: od })
}

/// Daemon flags given on the command line as their option: `--cores 6` is `flashstore_cores = 6`, a bare flag is `true`.
fn cli_flag_options(a: &[String]) -> Vec<(String, String)> {
    const NOT_OPTIONS: &[&str] = &[
        "--id",
        "--cluster",
        "--conf",
        "--data-dir",
        "--set",
        "--foreground",
        "--show-config",
        "--mon-host",
        "--setuser",
        "--setgroup",
        "--setuser-match-path",
    ];
    let mut v = Vec::new();
    let mut i = 0;
    while i < a.len() {
        let x = a[i].as_str();
        i += 1;
        let Some(name) = x.strip_prefix("--") else {
            continue;
        };
        if NOT_OPTIONS.contains(&x) {
            i += usize::from(x != "--foreground" && x != "--show-config");
            continue;
        }
        let val = match a.get(i) {
            Some(n) if !n.starts_with("--") && n != "-f" => {
                i += 1;
                n.clone()
            }
            _ => "true".to_owned(),
        };
        v.push((format!("flashstore_{}", norm_key(name)), val));
    }
    v
}

/// `--show-config` line: the resolved daemon flags with the cephx secret option masked. The vector itself keeps the real
/// key (the daemon's key source resolves it); only this rendering hides it, because the line is routinely redirected,
/// pasted into tickets and attached to reports.
fn show_config(args: &[String]) -> String {
    let mut out: Vec<String> = Vec::with_capacity(args.len());
    let mut set = false;
    for x in args {
        if std::mem::take(&mut set) {
            out.push(masked_kv(x));
        } else {
            set = crate::args::SET_FLAGS.contains(&x.as_str());
            out.push(x.clone());
        }
    }
    out.join(" ")
}

/// `key=<secret>` -> `key=***`; every other `k=v` (and anything without `=`) unchanged.
fn masked_kv(kv: &str) -> String {
    match kv.split_once('=') {
        Some((k, v)) if !v.is_empty() && norm_key(k.trim()) == "key" => format!("{k}=***"),
        _ => kv.to_owned(),
    }
}

/// Mon session of the config bootstrap from the daemon's flags (`--mon-host`, `--hostname`, settings `ms_mon_cluster_mode=`,
/// the key options `key|keyfile|keyring|osd_data=` of every setting flag) and the OSD dir (entity, cluster fsid). The key is resolved
/// exactly as the daemon resolves it ([`osd::keysrc::resolve`]); nothing found = method NONE.
fn boot_cfg(args: &[String], dir: &OsdDir) -> Result<monc::Config, String> {
    let mon_host = osddir::mon_host_from_args(args)?;
    let (local, _) = crate::args::local_config(args);
    let host = arg(args, "--hostname").unwrap_or_else(osd::sysinfo::short_hostname);
    let key = osd::keysrc::resolve(&local, dir.whoami, &host)?.map(|f| f.key);
    let mut cfg = osd::monboot::osd_config(
        dir.whoami,
        key,
        &dir.cluster_fsid,
        &mon_host,
        host,
        osd::auth::mon_session_modes(&local).map(|m| m.modes),
    )?;
    // the daemon offers `auth_cluster_required` to the mon; so does its config bootstrap session
    cfg.methods = osd::auth::AuthLists::from_local(&local).0.cluster;
    osd::monboot::apply_mon_client(&mut cfg, |k| osd::config::local_get(&local, k));
    Ok(cfg)
}

#[cfg(all(feature = "knet", target_os = "linux"))]
pub fn main(a: &[String]) -> i32 {
    let Resolved { args, dir } = match resolve(a) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("croit-flashstore-osd: {e}");
            return 3;
        }
    };
    if a.iter().any(|x| x == "--show-config") {
        println!("{}", show_config(&args));
        return 0;
    }
    // the conf file may name another crash_dir (or disable it): before the mon config bootstrap
    osd::crash::install(crate::args::early_crash_cfg(&args));
    // classic bootstrap (doc/spec/osd-lifecycle.md 2.7, adr 0175 am. 2): the mon config db's options for this OSD before
    // the store is sized; without them the daemon starts on the local config and the defaults
    if let Some(d) = &dir {
        match boot_cfg(&args, d)
            .and_then(|c| osd::monboot::fetch_config(c, osd::monboot::BOOT_TIMEOUT))
        {
            Ok(c) => {
                eprintln!(
                    "croit-flashstore-osd: mon config bootstrap: {} options",
                    c.len()
                );
                osd::monboot::set_boot(c);
            }
            Err(e) => eprintln!("croit-flashstore-osd: mon config bootstrap skipped: {e}"),
        }
    }
    let mut full = vec!["croit-flashstore-osd".to_owned()];
    full.extend(args);
    crate::daemon(full)
}

/// Every flag the daemon reads (`croit-flashstore-osd run` maps `flashstore_<key>` conf entries to `--<key>`). Keep in sync when a flag
/// is added: an unlisted flag is reported at startup (a mistyped or unparsed conf key silently ignored invalidated a
/// rented A/B on 2026-10-15, adr 0021 am. 42).
const KNOWN_FLAGS: &[&str] = &[
    "--accept-wal-loss",
    "--cluster-addr",
    "--cluster",
    "--conf",
    "--cores",
    "--data-dir",
    "--data",
    "--dev",
    "--foreground",
    "--hostname",
    "--huge-dir",
    "--hugepages",
    "--id",
    "--idle",
    "--ip",
    "--knet-balance",
    "--knet-buf-kb",
    "--knet-bufs",
    "--knet-peer-cores",
    "--knet-peer-steer",
    "--knet-send-chunk-kb",
    "--knet-sockbuf-kb",
    "--knet-store-irq-park",
    "--knet-store-park",
    "--knet-wake",
    "--knet-zc-min",
    "--knet-zcrx",
    "--l3-placement",
    "--lcore",
    "--mem",
    "--mon-host",
    "--net-caps",
    "--place-id",
    "--port-base",
    "--public-addr",
    "--rdma",
    "--rdma-placement",
    "--rdma-source-pull",
    "--rdma-max-sessions",
    "--rdma-memory",
    "--set",
    "--setgroup",
    "--setuser-match-path",
    "--setuser",
    "--show-config",
    "--steer",
    "--store-backend",
    "--version",
];

/// Flags in `a` the daemon does not read (values of the setting flags are skipped).
pub(crate) fn unknown_flags(a: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip = false;
    for x in a {
        if std::mem::take(&mut skip) {
            continue;
        }
        if crate::args::SET_FLAGS.contains(&x.as_str()) {
            skip = true;
        } else if x.starts_with("--") && !KNOWN_FLAGS.contains(&x.as_str()) {
            out.push(x.clone());
        }
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_overrides_conf_and_run_flags_are_stripped() {
        let t = std::env::temp_dir().join(format!("run-test-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let conf = t.join("ceph.conf");
        std::fs::write(
            &conf,
            "[global]\nmon_host = v2:1.2.3.4:3300\n[osd.9]\nflashstore_dev = spdk:0000:03:00.0\nflashstore_ip = 10.0.0.9/24\n",
        )
        .unwrap();
        let a: Vec<String> = [
            "--id",
            "9",
            "--conf",
            conf.to_str().unwrap(),
            "--data-dir",
            "/nonexistent",
            "-f",
            "--ip",
            "10.9.9.9/24",
        ]
        .map(String::from)
        .to_vec();
        let v = resolve(&a).unwrap().args;
        let s = v.join(" ");
        assert!(
            s.starts_with("--ip 10.9.9.9/24 --dev spdk:0000:03:00.0"),
            "{s}"
        );
        assert!(s.contains("--ip 10.0.0.9/24")); // later duplicate; the daemon takes the first
        assert!(
            !v.iter()
                .any(|x| ["-f", "--id", "--conf"].contains(&x.as_str()))
        );
        assert!(resolve(&["--id".into(), "9".into(), "--conf".into(), "/nope".into()]).is_err());
        let _ = std::fs::remove_dir_all(&t);
    }

    /// `--show-config` hides the cephx secret of the conf (`key = ...`); the forwarded vector keeps it for the daemon's
    /// key resolver.
    #[test]
    fn show_config_masks_the_cephx_key() {
        let t = std::env::temp_dir().join(format!("run-mask-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let conf = t.join("ceph.conf");
        std::fs::write(
            &conf,
            "[osd.3]\nkey = AQDsecretSECRETsecretSECRET==\nflashstore_dev = spdk:0000:03:00.0\n",
        )
        .unwrap();
        let r = resolve(&run_a(&conf, &[])).unwrap();
        let shown = show_config(&r.args);
        assert!(shown.contains("--conf-set key=***"), "{shown}");
        assert!(!shown.contains("SECRET"), "{shown}");
        // other options of the same vector are untouched, and the real key still reaches the daemon
        assert!(
            shown.contains("--conf-set flashstore_dev=spdk:0000:03:00.0"),
            "{shown}"
        );
        assert!(
            r.args
                .join(" ")
                .contains("--conf-set key=AQDsecretSECRETsecretSECRET==")
        );
        // The accepted --set spelling trims whitespace around the key as well.
        let r = resolve(&run_a(&conf, &["--set", " key =AQDotherSECRET=="])).unwrap();
        assert!(!show_config(&r.args).contains("SECRET"));
        assert!(r.args.iter().any(|x| x == " key =AQDotherSECRET=="));
        let _ = std::fs::remove_dir_all(&t);
    }

    #[test]
    fn cli_device_must_match_the_prepared_osd() {
        let t = std::env::temp_dir().join(format!("run-clidev-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let conf = t.join("ceph.conf");
        std::fs::write(&conf, "[osd.3]\n").unwrap();
        let dir = t.join("osd");
        OsdDir {
            whoami: 3,
            osd_uuid: "5e3b3e2a-4f3c-4d3f-9a59-2b1c0d6e7f80".into(),
            cluster_fsid: "1d5c9f2e-8a1b-4c3d-9e7f-0a1b2c3d4e5f".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: osddir::keyring_text(3, "KEY"),
        }
        .write(&dir)
        .unwrap();
        let args = |dev: &str| -> Vec<String> {
            let (c, d) = (conf.to_str().unwrap(), dir.to_str().unwrap());
            ["--id", "3", "--conf", c, "--data-dir", d, "--dev", dev]
                .map(String::from)
                .to_vec()
        };
        for dev in ["spdk:0000:04:00.0", "spdk:0000:03:00.0,ns=2"] {
            let e = resolve(&args(dev)).unwrap_err();
            assert!(e.contains("--dev") && e.contains("disagrees"), "{e}");
        }
        if let Err(e) = resolve(&args("spdk:0000:03:00.0,ns=1")) {
            panic!("same device (explicit ns=1) refused: {e}");
        }
        let _ = std::fs::remove_dir_all(&t);
    }

    /// A present but damaged OSD dir fails the start; only a missing dir means "no OSD dir".
    #[test]
    fn a_present_but_damaged_osd_dir_is_an_error() {
        let t = std::env::temp_dir().join(format!("run-baddir-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let conf = t.join("ceph.conf");
        std::fs::write(&conf, "[osd.3]\nflashstore_dev = spdk:0000:03:00.0\n").unwrap();
        let dir = t.join("osd");
        OsdDir {
            whoami: 3,
            osd_uuid: "5e3b3e2a-4f3c-4d3f-9a59-2b1c0d6e7f80".into(),
            cluster_fsid: "1d5c9f2e-8a1b-4c3d-9e7f-0a1b2c3d4e5f".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: osddir::keyring_text(3, "KEY"),
        }
        .write(&dir)
        .unwrap();
        // the marker still says osd 3, the whoami file says 4
        std::fs::write(dir.join("whoami"), "4\n").unwrap();
        let a: Vec<String> = [
            "--id",
            "3",
            "--conf",
            conf.to_str().unwrap(),
            "--data-dir",
            dir.to_str().unwrap(),
        ]
        .map(String::from)
        .to_vec();
        let e = resolve(&a).unwrap_err();
        assert!(e.contains("whoami disagrees"), "{e}");
        let _ = std::fs::remove_dir_all(&t);
    }

    /// Startup-only options (conf, `--set`, flag, dir default) reach the daemon's config store with their source level
    /// (conf = `--conf-set`, command line = `--set`), so `config get/show` report the effective value and `config diff`
    /// both layers (adr 0034 am. 6).
    #[test]
    fn startup_options_are_forwarded_to_the_config_store() {
        let t = std::env::temp_dir().join(format!("run-eff-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let conf = t.join("ceph.conf");
        std::fs::write(
            &conf,
            "[osd.9]\nflashstore_dev = spdk:0000:03:00.0\nflashstore_cores = 6\nflashstore_ip = 10.0.0.9/24\nflashstore_port_base = 7000\n",
        )
        .unwrap();
        let a: Vec<String> = [
            "--id",
            "9",
            "--conf",
            conf.to_str().unwrap(),
            "--data-dir",
            "/nonexistent",
            "--ip",
            "10.9.9.9/24",
            "--set",
            "flashstore_port_base=7100",
            "--idle",
            "sleep",
        ]
        .map(String::from)
        .to_vec();
        let args = resolve(&a).unwrap().args;
        let s = args.join(" ");
        for want in [
            "--conf-set flashstore_cores=6",
            "--conf-set flashstore_dev=spdk:0000:03:00.0",
            "--conf-set flashstore_ip=10.0.0.9/24",
            "--set flashstore_ip=10.9.9.9/24",
            "--set flashstore_idle=sleep",
            "--conf-set flashstore_port_base=7000",
            "--set flashstore_port_base=7100",
        ] {
            assert!(s.contains(want), "{want} missing: {s}");
        }
        // the daemon's local config: the command line wins, every entry keeps its level
        let (local, src) = crate::args::local_config(&args);
        assert_eq!(
            osd::config::local_get(&local, "flashstore_ip"),
            Some("10.9.9.9/24")
        );
        assert_eq!(
            osd::config::local_get(&local, "flashstore_port_base"),
            Some("7100")
        );
        let level = |kv: &str| {
            src.level(
                local
                    .iter()
                    .position(|(k, v)| format!("{k}={v}") == kv)
                    .unwrap(),
            )
        };
        assert_eq!(level("flashstore_cores=6"), osd::config::Level::File);
        assert_eq!(
            level("flashstore_port_base=7100"),
            osd::config::Level::Cmdline
        );
        let _ = std::fs::remove_dir_all(&t);
    }

    /// An obsolete `flashstore_net` (conf, `--set`) or `--net X` is dropped, never forwarded, never a start failure.
    #[test]
    fn obsolete_net_is_dropped() {
        let mut opts: BTreeMap<String, String> =
            [("flashstore net".to_owned(), "kernel".to_owned())].into();
        let a: Vec<String> = [
            "--net",
            "kernel",
            "--cores",
            "2",
            "--set",
            "flashstore_net=kernel",
            "--set",
            "a=b",
        ]
        .map(String::from)
        .to_vec();
        let out = drop_obsolete_net(&mut opts, &a);
        assert!(opts.is_empty());
        assert_eq!(out, ["--cores", "2", "--set", "a=b"]);
    }

    /// Regression (knet-perf lab note): a command-line `--steer` / `--knet-peer-steer` must beat the conf's
    /// `flashstore_steer` / `flashstore_knet_peer_steer` (classic: command line overrides the conf; the daemon takes the
    /// first occurrence of a flag and `run` puts the command line first).
    #[test]
    fn cli_steer_beats_conf_steer() {
        let t = std::env::temp_dir().join(format!("run-steer-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let conf = t.join("ceph.conf");
        std::fs::write(
            &conf,
            "[osd]\nflashstore_steer = cpu\nflashstore_knet_peer_steer = off\n[osd.3]\nflashstore_dev = spdk:0000:03:00.0\n",
        )
        .unwrap();
        let a: Vec<String> = [
            "--id",
            "3",
            "--conf",
            conf.to_str().unwrap(),
            "--data-dir",
            "/nonexistent",
            "-f",
            "--set",
            "debug_osd=5/5",
            "--steer",
            "hash",
            "--knet-peer-steer",
            "on",
        ]
        .map(String::from)
        .to_vec();
        let first = |v: &[String], k: &str| v.windows(2).find(|w| w[0] == k).map(|w| w[1].clone());
        let v = resolve(&a).unwrap().args;
        assert_eq!(first(&v, "--steer").as_deref(), Some("hash"));
        assert_eq!(first(&v, "--knet-peer-steer").as_deref(), Some("on"));
        assert_eq!(first(&v, "--set").as_deref(), Some("debug_osd=5/5"));
        // without command line flags the conf applies
        let v = resolve(&a[..9]).unwrap().args;
        assert_eq!(first(&v, "--steer").as_deref(), Some("cpu"));
        assert_eq!(first(&v, "--knet-peer-steer").as_deref(), Some("off"));
        let _ = std::fs::remove_dir_all(&t);
    }

    /// Regression (adr 0021 am. 42): conf `flashstore_store_*` tunables reach the store as settings (they became the
    /// unparsed flag `--store-ckpt-slice` before); a command-line `--set` of the same key wins.
    #[test]
    fn conf_store_tunables_go_to_set_and_cli_wins() {
        let t = std::env::temp_dir().join(format!("run-store-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let conf = t.join("ceph.conf");
        std::fs::write(
            &conf,
            "[osd]\nflashstore_store_ckpt_slice = 0\nflashstore_store_wal_coalesce = 2\n[osd.3]\nflashstore_dev = spdk:0000:03:00.0\n",
        )
        .unwrap();
        let a: Vec<String> = [
            "--id",
            "3",
            "--conf",
            conf.to_str().unwrap(),
            "--data-dir",
            "/nonexistent",
            "--set",
            "flashstore_store_wal_coalesce=1",
        ]
        .map(String::from)
        .to_vec();
        let v = resolve(&a).unwrap().args;
        let s = v.join(" ");
        assert!(
            s.contains("--conf-set flashstore_store_ckpt_slice=0"),
            "{s}"
        );
        assert!(!s.contains("--store-"), "{s}");
        let (local, _) = crate::args::local_config(&v);
        assert_eq!(
            osd::config::local_get(&local, "flashstore_store_wal_coalesce"),
            Some("1")
        );
        assert!(unknown_flags(&v).is_empty(), "{s}");
        let _ = std::fs::remove_dir_all(&t);
    }

    fn run_a(conf: &std::path::Path, extra: &[&str]) -> Vec<String> {
        let mut a: Vec<String> = [
            "--id",
            "3",
            "--conf",
            conf.to_str().unwrap(),
            "--data-dir",
            "/nonexistent",
        ]
        .map(String::from)
        .to_vec();
        a.extend(extra.iter().map(|s| s.to_string()));
        a
    }

    /// adr 0021 am. 60: precedence flag > `--set` > conf; `--set flashstore_hostname=X` acts like the conf key.
    #[test]
    fn set_feeds_the_conf_option_map_and_flag_wins() {
        let t = std::env::temp_dir().join(format!("run-setprec-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let conf = t.join("ceph.conf");
        std::fs::write(
            &conf,
            "[osd]\nflashstore_hostname = conf0\n[osd.3]\nflashstore_dev = spdk:0000:03:00.0\n",
        )
        .unwrap();
        let first = |v: &[String], k: &str| v.windows(2).find(|w| w[0] == k).map(|w| w[1].clone());
        let v = resolve(&run_a(&conf, &[])).unwrap().args;
        assert_eq!(first(&v, "--hostname").as_deref(), Some("conf0"));
        let v = resolve(&run_a(&conf, &["--set", "flashstore_hostname=set1"]))
            .unwrap()
            .args;
        assert_eq!(first(&v, "--hostname").as_deref(), Some("set1"));
        // the conf value stays a lower layer (adr 0034 am. 6); the command line wins in the daemon's local config
        let (local, _) = crate::args::local_config(&v);
        assert_eq!(
            osd::config::local_get(&local, "flashstore_hostname"),
            Some("set1")
        );
        let v = resolve(&run_a(&conf, &["--set", "flashstore-hostname=set2"]))
            .unwrap()
            .args;
        assert_eq!(first(&v, "--hostname").as_deref(), Some("set2"));
        let v = resolve(&run_a(
            &conf,
            &["--set", "flashstore_hostname=set1", "--hostname", "flag"],
        ))
        .unwrap()
        .args;
        assert_eq!(first(&v, "--hostname").as_deref(), Some("flag"));
        let v = resolve(&run_a(&conf, &["--set", "flashstore_cores=4"]))
            .unwrap()
            .args;
        assert_eq!(first(&v, "--cores").as_deref(), Some("4"));
        let _ = std::fs::remove_dir_all(&t);
    }

    /// adr 0175 am. 2: the conf file's memory options reach the daemon (local config, above the mon config db), a command
    /// line `--set` wins; a prepared OSD dir comes back for the mon config bootstrap.
    #[test]
    fn conf_memory_options_are_forwarded_and_the_dir_returned() {
        let t = std::env::temp_dir().join(format!("run-mem-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let conf = t.join("ceph.conf");
        std::fs::write(
            &conf,
            "[global]\nmon_host = v2:127.0.0.1:3300\n[osd]\nosd_memory_target = 8G\nosd memory base = 1G\n[osd.3]\nflashstore_dev = spdk:0000:03:00.0\n",
        )
        .unwrap();
        let r = resolve(&run_a(&conf, &[])).unwrap();
        let s = r.args.join(" ");
        assert!(
            s.contains("--conf-set osd_memory_target=8G")
                && s.contains("--conf-set osd_memory_base=1G"),
            "{s}"
        );
        assert!(r.dir.is_none());
        let v = resolve(&run_a(&conf, &["--set", "osd_memory_target=6G"]))
            .unwrap()
            .args;
        let (local, _) = crate::args::local_config(&v);
        assert_eq!(
            osd::config::local_get(&local, "osd_memory_target"),
            Some("6442450944")
        );
        let dir = t.join("osd");
        OsdDir {
            whoami: 3,
            osd_uuid: "5e3b3e2a-4f3c-4d3f-9a59-2b1c0d6e7f80".into(),
            cluster_fsid: "1d5c9f2e-8a1b-4c3d-9e7f-0a1b2c3d4e5f".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: osddir::keyring_text(3, "KEY"),
        }
        .write(&dir)
        .unwrap();
        let a = [
            "--id",
            "3",
            "--conf",
            conf.to_str().unwrap(),
            "--data-dir",
            dir.to_str().unwrap(),
        ]
        .map(String::from)
        .to_vec();
        let r = resolve(&a).unwrap();
        assert_eq!(r.dir.as_ref().map(|d| d.whoami), Some(3));
        // the daemon learns the resolved data dir (its `$osd_data/keyring`), last so it wins over a raw conf value
        let s = r.args.join(" ");
        assert!(
            s.ends_with(&format!("--set osd_data={}", dir.display())),
            "{s}"
        );
        // the bootstrap session takes the dir's entity; a keyring without a valid key is refused before any network
        let e = boot_cfg(&r.args, r.dir.as_ref().unwrap()).unwrap_err();
        assert!(e.contains("keyring"), "{e}");
        let k = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, cephx::UTime::new(1, 0))
            .unwrap();
        std::fs::write(
            dir.join("keyring"),
            osddir::keyring_text(3, &k.to_base64().unwrap()),
        )
        .unwrap();
        let c = boot_cfg(&r.args, r.dir.as_ref().unwrap()).unwrap();
        assert_eq!(c.key, Some(k));
        let _ = std::fs::remove_dir_all(&t);
    }

    /// Every conf option reaches the daemon (classic reads the whole file), with classic's section precedence
    /// `[global]` < `[osd]` < `[osd.N]`; a command-line `--set` wins; a name Ceph does not know is not forwarded.
    #[test]
    fn every_conf_option_is_forwarded_with_section_precedence() {
        let t = std::env::temp_dir().join(format!("run-allconf-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let conf = t.join("ceph.conf");
        std::fs::write(
            &conf,
            "[global]\nmon_host = v2:127.0.0.1:3300\nosd heartbeat grace = 30\nosd_scrub_sleep = 0.1\n\
             rgw_thread_pool_size = 64\nno_such_thing = 1\n\
             [osd]\nosd_heartbeat_grace = 25\nosd_max_backfills = 3\n\
             [osd.4]\nosd_max_backfills = 9\n\
             [osd.3]\nflashstore_dev = spdk:0000:03:00.0\nosd_max_backfills = 2\n",
        )
        .unwrap();
        let sets = |extra: &[&str]| -> Vec<String> {
            let a = resolve(&run_a(&conf, extra)).unwrap().args;
            a.windows(2)
                .filter(|w| w[0] == "--conf-set")
                .map(|w| w[1].clone())
                .collect()
        };
        let s = sets(&[]);
        for want in [
            "osd_heartbeat_grace=25",
            "osd_max_backfills=2",
            "osd_scrub_sleep=0.1",
            "rgw_thread_pool_size=64",
            "mon_host=v2:127.0.0.1:3300",
        ] {
            assert!(s.iter().any(|x| x == want), "{want} missing: {s:?}");
        }
        assert!(!s.iter().any(|x| x.starts_with("no_such_thing")), "{s:?}");
        assert_eq!(
            s.iter()
                .filter(|x| x.starts_with("osd_heartbeat_grace="))
                .count(),
            1
        );
        // a command-line `--set` is a layer above the conf: both reach the daemon, the command line wins
        let v = resolve(&run_a(&conf, &["--set", "osd_heartbeat_grace=40"]))
            .unwrap()
            .args;
        let (local, _) = crate::args::local_config(&v);
        assert_eq!(
            osd::config::local_get(&local, "osd_heartbeat_grace"),
            Some("40")
        );
        assert!(
            v.windows(2)
                .any(|w| w == ["--conf-set", "osd_heartbeat_grace=25"])
        );
        let _ = std::fs::remove_dir_all(&t);
    }

    /// The resolved data dir carries the level of its source; the built-in default is no setting (the daemon expands
    /// the same default itself).
    #[test]
    fn data_dir_is_forwarded_with_its_source_level() {
        let t = std::env::temp_dir().join(format!("run-datalvl-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let conf = t.join("ceph.conf");
        let base = |extra: &str| {
            std::fs::write(
                &conf,
                format!("[osd.999999]\nflashstore_dev = spdk:0000:03:00.0\n{extra}"),
            )
            .unwrap();
        };
        let resolved = |a: &[&str]| -> Vec<String> {
            // an id no runner hosts: the default dir does not exist
            let mut v: Vec<String> = ["--id", "999999", "--conf", conf.to_str().unwrap()]
                .map(String::from)
                .to_vec();
            v.extend(a.iter().map(|s| s.to_string()));
            resolve(&v).unwrap().args
        };
        let data = |v: &[String]| -> Vec<(String, String)> {
            v.windows(2)
                .filter(|w| w[1].starts_with("osd_data="))
                .map(|w| (w[0].clone(), w[1].clone()))
                .collect()
        };
        base("");
        assert!(data(&resolved(&[])).is_empty());
        base("osd_data = /nonexistent/$cluster-$id\n");
        assert_eq!(
            data(&resolved(&[])),
            [(
                "--conf-set".to_owned(),
                "osd_data=/nonexistent/ceph-999999".to_owned()
            )]
        );
        let v = resolved(&["--data-dir", "/nonexistent/x"]);
        assert_eq!(
            data(&v),
            [("--set".to_owned(), "osd_data=/nonexistent/x".to_owned())]
        );
        let _ = std::fs::remove_dir_all(&t);
    }

    #[test]
    fn set_of_an_unknown_key_is_rejected() {
        let t = std::env::temp_dir().join(format!("run-setunk-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let conf = t.join("ceph.conf");
        std::fs::write(&conf, "[osd.3]\nflashstore_dev = spdk:0000:03:00.0\n").unwrap();
        let e = resolve(&run_a(&conf, &["--set", "no_such_option=1"])).unwrap_err();
        assert!(e.contains("no_such_option"), "{e}");
        // a valid Ceph option croit-flashstore-osd does not use is accepted, passed on and listed for `status`
        let v = resolve(&run_a(
            &conf,
            &[
                "--set",
                "rgw_thread_pool_size=3",
                "--set",
                "mds-cache-memory-limit=2",
            ],
        ))
        .unwrap()
        .args;
        let s = v.join(" ");
        assert!(s.contains("--set rgw_thread_pool_size=3"), "{s}");
        assert!(!s.contains("ignored_options"), "{s}");
        let e = resolve(&run_a(&conf, &["--set", "novalue"])).unwrap_err();
        assert!(e.contains("k=v"), "{e}");
        for ok in [
            "osd_memory_target=1G",
            "debug_osd=1/5",
            "osd_heartbeat_grace=30",
            "flashstore_store_ckpt_slice=0",
        ] {
            assert!(resolve(&run_a(&conf, &["--set", ok])).is_ok(), "{ok}");
        }
        let _ = std::fs::remove_dir_all(&t);
    }
}

#[cfg(test)]
mod flag_tests {
    use super::*;

    #[test]
    fn unparsed_flags_are_reported_and_pass_through_values_are_not() {
        let a: Vec<String> = [
            "--dev",
            "spdk:x",
            "--store-ckpt-slice",
            "0",
            "--set",
            "a=b",
            "--conf-set",
            "c=d",
            "--env-set",
            "osd_data=/x",
            "--steer",
            "cpu",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(unknown_flags(&a), ["--store-ckpt-slice"]);
    }

    /// `--knet-zcrx` is read by the kernel tier (`zcrx_plan`): no `WARN unknown flag` for it.
    #[test]
    fn knet_zcrx_is_a_known_flag() {
        let a: Vec<String> = ["--knet-zcrx", "auto"].map(String::from).to_vec();
        assert!(unknown_flags(&a).is_empty(), "{:?}", unknown_flags(&a));
    }
}
