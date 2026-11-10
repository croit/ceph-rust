// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Tiny flag helpers shared by the run modes (`kprod.rs` kernel tier).

pub(crate) fn args_of(a: &[String], k: &str) -> Vec<String> {
    a.windows(2)
        .filter(|w| w[0] == k)
        .map(|w| w[1].clone())
        .collect()
}

pub(crate) fn arg(a: &[String], k: &str) -> Option<String> {
    a.windows(2).find(|w| w[0] == k).map(|w| w[1].clone())
}

/// The flags that carry `k=v` settings, in level order: conf file and environment (both written by
/// `croit-flashstore-osd run`), command line (adr 0034 am. 6).
pub(crate) const SET_FLAGS: [&str; 3] = ["--conf-set", "--env-set", "--set"];

/// The daemon's local config from its setting flags, with the source level of each entry.
pub(crate) fn local_config(a: &[String]) -> (Vec<(String, String)>, osd::config::LocalSources) {
    let [file, env, cmdline] = SET_FLAGS.map(|f| args_of(a, f));
    osd::config::local_layers(
        file.iter().map(String::as_str),
        env.iter().map(String::as_str),
        cmdline.iter().map(String::as_str),
    )
}

/// Value of the effective `k=v` setting whose key is `k` (the last one in level order, [`SET_FLAGS`]), trimmed; Ceph
/// option names accept `_`, `-` and space spellings (the same normalisation as the conf file and the daemon's local
/// config).
pub(crate) fn set_opt(a: &[String], k: &str) -> Option<String> {
    let all: Vec<String> = SET_FLAGS.iter().flat_map(|f| args_of(a, f)).collect();
    all.iter()
        .rev()
        .filter_map(|s| s.split_once('='))
        .find(|(n, _)| n.trim().replace([' ', '-'], "_") == k)
        .map(|(_, v)| v.trim().to_owned())
}

/// `--store-backend spdk|kernel|kernel-cmd`, else the conf key `flashstore_store_backend` (arrives as `--conf-set`); `None` = as the
/// `--dev` spec says.
#[cfg(feature = "kernel-nvme")]
pub(crate) fn store_backend(a: &[String]) -> Option<String> {
    arg(a, "--store-backend").or_else(|| set_opt(a, "flashstore_store_backend"))
}

/// `--rdma true|false` (conf `flashstore_rdma`, default false): offer the RDMA upgrade on the public and cluster connections.
#[cfg(all(feature = "knet", target_os = "linux"))]
pub(crate) fn rdma_enabled(a: &[String]) -> Result<bool, String> {
    match arg(a, "--rdma").as_deref() {
        None | Some("false" | "no" | "off" | "0") => Ok(false),
        Some("true" | "yes" | "on" | "1") => Ok(true),
        Some(o) => Err(format!("bad --rdma {o:?} (true|false)")),
    }
}

/// `--rdma-placement true|false`: lab-only plain READ placement qualification.
/// A production build rejects an explicit request instead of silently ignoring it.
#[cfg(all(feature = "knet", target_os = "linux"))]
pub(crate) fn placement_lab_enabled(a: &[String], rdma: bool) -> Result<bool, String> {
    match arg(a, "--rdma-placement").as_deref() {
        None | Some("false" | "no" | "off" | "0") => Ok(false),
        Some("true" | "yes" | "on" | "1") if !cfg!(feature = "lab") => {
            Err("--rdma-placement requires the lab build feature".into())
        }
        Some("true" | "yes" | "on" | "1") if !rdma => {
            Err("--rdma-placement requires --rdma true".into())
        }
        Some("true" | "yes" | "on" | "1") => Ok(true),
        Some(other) => Err(format!("bad --rdma-placement {other:?} (true|false)")),
    }
}

/// `--rdma-source-pull` (conf `flashstore_rdma_source_pull`, default false): advertise the object
/// source-pull extension (adr 0665) on public client sessions. Requires RDMA and a
/// build with the memory-windows feature; the OSD additionally keeps it off when a device cannot
/// answer or post RDMA READs.
pub(crate) fn source_pull_lab_enabled(a: &[String], rdma: bool) -> Result<bool, String> {
    match arg(a, "--rdma-source-pull").as_deref() {
        None | Some("false" | "no" | "off" | "0") => Ok(false),
        Some("true" | "yes" | "on" | "1") if !cfg!(feature = "lab") => {
            Err("--rdma-source-pull requires the lab build feature".into())
        }
        Some("true" | "yes" | "on" | "1") if !rdma => {
            Err("--rdma-source-pull requires --rdma true".into())
        }
        Some("true" | "yes" | "on" | "1") => Ok(true),
        Some(other) => Err(format!("bad --rdma-source-pull {other:?} (true|false)")),
    }
}

/// `--rdma-memory SIZE` (conf `flashstore_rdma_memory`, default 256 MiB): registered (pinned) RDMA buffers of the whole OSD
/// process over all cores and devices. Separate from, and on top of, `osd_memory_target`.
#[cfg(all(feature = "rdma", feature = "knet", target_os = "linux"))]
pub(crate) fn rdma_memory(a: &[String]) -> Result<u64, String> {
    match arg(a, "--rdma-memory") {
        None => Ok(256 << 20),
        Some(s) => osddir::parse_size(&s)
            .filter(|&b| b > 0)
            .ok_or_else(|| format!("bad --rdma-memory {s:?} (bytes, K/M/G suffix)")),
    }
}

/// `--rdma-max-sessions N` (conf `flashstore_rdma_max_sessions`, default 0 = unlimited): most RDMA sessions of the whole OSD
/// process; a connection beyond it stays on TCP (never an error).
#[cfg(all(feature = "rdma", feature = "knet", target_os = "linux"))]
pub(crate) fn rdma_max_sessions(a: &[String]) -> Result<u32, String> {
    match arg(a, "--rdma-max-sessions") {
        None => Ok(0),
        Some(s) => s
            .parse()
            .map_err(|_| format!("bad --rdma-max-sessions {s:?} (a number, 0 = unlimited)")),
    }
}

/// Why `flashstore_rdma = true` cannot run here, if it cannot: it needs a build with feature `rdma`.
#[cfg(all(feature = "knet", target_os = "linux"))]
pub(crate) fn rdma_refusal(rdma: bool, built: bool) -> Option<String> {
    if !rdma {
        None
    } else if !built {
        Some("flashstore_rdma=true: this binary was built without feature rdma (cargo build --features rdma)".into())
    } else {
        None
    }
}

/// Number of OSD cores (`--cores N`, adr 0031): 1..=CPUs in the affinity mask (`mask_len`); default every CPU, at most the
/// store's shard count, and `legacy` (the `--data` mode) is single core. Cores beyond the shard count stay unused
/// (adr 0160), with the warning printed here.
pub(crate) fn cores(
    a: &[String],
    mask_len: usize,
    shards: Option<u32>,
    legacy: bool,
) -> Result<usize, String> {
    let cores = match arg(a, "--cores").map(|v| v.parse::<usize>()) {
        None if legacy => 1,
        None => mask_len.min(shards.unwrap_or(1) as usize).max(1),
        Some(Ok(n)) if (1..=mask_len).contains(&n) => n,
        Some(Ok(n)) => {
            return Err(format!(
                "--cores {n}: only {mask_len} CPUs in the affinity mask (one core per CPU)"
            ));
        }
        Some(Err(_)) => return Err("bad --cores (a number)".into()),
    };
    Ok(match shards {
        Some(s) => {
            let run = cores.min(s as usize);
            if let Some(w) = osd::CoreSpec::shard_balance(s, run, cores) {
                eprintln!("croit-flashstore-osd: {w}");
            }
            run
        }
        None => cores,
    })
}

/// Every explicit CPU must be inside the process' affinity mask.
fn in_mask(cpus: &[usize], mask: &[usize]) -> Result<(), String> {
    match cpus.iter().find(|c| !mask.contains(c)) {
        Some(bad) => Err(format!("cpu {bad} is not in the affinity mask {mask:?}")),
        None => Ok(()),
    }
}

/// CPUs of the OSD's cores (adr 0063, am. 1). Explicit `--lcore` (`flashstore_lcores`) is authoritative and `--l3-placement
/// false` keeps the plain `mask[..cores]` (resp. `FIRST..`) choice; otherwise the CPUs that take the queue IRQs of the
/// data NICs `ifaces` are left out when at least `cores` IRQ-free CPUs remain (otherwise the OSD shares them silently: the
/// spread IRQ layout of adr 0063 am. 2; `hwcheck` warns about concentrated IRQs), and the cores are
/// packed into one L3 domain of the rest, NIC-local NUMA node first (never fewer cores than the plain choice, never
/// outside the mask). Returns the CPUs, every one inside `mask`, and a log description.
pub(crate) fn choose_cpus(
    a: &[String],
    mask: &[usize],
    cores: usize,
    nvme_pci: Option<&str>,
    ifaces: &[String],
) -> Result<(Vec<usize>, String), String> {
    if let Some(l) = arg(a, "--lcore") {
        let first: usize = l
            .parse()
            .map_err(|_| format!("bad --lcore {l:?} (first CPU number)"))?;
        let end = first
            .checked_add(cores)
            .ok_or_else(|| format!("--lcore {first}: {cores} cores exceed the CPU number range"))?;
        let cpus: Vec<usize> = (first..end).collect();
        in_mask(&cpus, mask)?;
        return Ok((cpus, "explicit --lcore".into()));
    }
    if matches!(
        arg(a, "--l3-placement").as_deref(),
        Some("false" | "no" | "off" | "0")
    ) {
        return Ok((mask[..cores].to_vec(), "l3 placement disabled".into()));
    }
    let nic = hwcheck::nic_info(ifaces);
    let irq: Vec<usize> = nic.irq_cpus.iter().map(|&c| c as usize).collect();
    let (mask, irq_note) = match rt::topo::avoid_irq(mask, &irq, cores) {
        (m, rt::topo::Irq::Clear) => (m, String::new()),
        (m, rt::topo::Irq::Avoided(hit)) => (m, format!(", avoiding NIC IRQ cpus {hit:?}")),
        (m, rt::topo::Irq::Shared(hit)) => (m, format!(", sharing NIC IRQ cpus {hit:?}")),
    };
    let mask = mask.as_slice();
    let sys = std::path::Path::new("/sys");
    let hint = nic.numa.map(|n| n as usize).or_else(|| {
        nvme_pci
            .map(str::to_owned)
            .and_then(|b| rt::topo::pci_numa_node(sys, &b))
    });
    // rank: the OSD id (`croit-flashstore-osd run` passes it); direct invocations get 0 and rely on the lock files
    let rank = arg(a, "--place-id")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (cpus, p) = rt::topo::auto_place(&rt::topo::Request {
        mask,
        n: cores,
        rank,
        hint_node: hint,
    });
    let d = p.map_or_else(
        || "plain (whole mask or no topology)".to_owned(),
        |p| format!("l3 placement: {}", p.describe()),
    );
    Ok((cpus, format!("{d}{irq_note}")))
}

/// Once at start (adr 0166 am. 1): one WARN line per suboptimal network check (IRQ placement, offloads, rings) of the data
/// NICs `ifaces`, each with the exact fix. The OSD never changes NIC or IRQ settings itself.
pub(crate) fn warn_host_net(ifaces: &[String]) {
    for w in hwcheck::startup_warnings(ifaces) {
        eprintln!("croit-flashstore-osd: WARNING host: {w}");
    }
}

/// Crash reporting before the store and the mon session exist (spec ops-observability.md 4): `crash_dir` from the setting
/// flags (else the schema default), meta-expanded like `pid_file`, entity from `--place-id` / `--id` (`osd` when the
/// command line names none). [`crate::obs::setup`] replaces it with the effective config and the OSD's own id.
#[cfg(all(feature = "knet", target_os = "linux"))]
pub(crate) fn early_crash_cfg(a: &[String]) -> osd::crash::CrashCfg {
    let id: Option<i32> = arg(a, "--place-id")
        .or_else(|| arg(a, "--id"))
        .and_then(|s| s.parse().ok());
    let cluster = set_opt(a, "cluster").unwrap_or_else(|| "ceph".into());
    let host = arg(a, "--hostname").unwrap_or_else(osd::sysinfo::short_hostname);
    let opt = |k: &str| {
        set_opt(a, k)
            .or_else(|| osd::schema::effective_default(k).map(str::to_owned))
            .unwrap_or_default()
    };
    let dir = osd::schema::Meta::new(&cluster, id.unwrap_or(0), &host).expand(
        &opt("crash_dir"),
        &opt("run_dir"),
        &opt("tmp_dir"),
    );
    osd::crash::CrashCfg {
        dir: dir.into(),
        entity: id.map_or_else(|| "osd".to_owned(), |i| format!("osd.{i}")),
        version: osd::version::ceph_version_pretty(),
        process: "croit-flashstore-osd".into(),
        // the store device is not known yet (pre-mount): no device identity, as today's entity/version are
        device_serial: String::new(),
        device_model: String::new(),
    }
}

/// The daemon's pid file (option `pid_file`, last `--set pid_file=...`; empty = none, the default): metavariables
/// (`$cluster`, `$name`, `$id`, `$type`, `$host`, like `log_file`) are expanded with the identity `croit-flashstore-osd run`
/// passes (`--place-id`; a direct invocation is osd.0). Written at start with the pid and a newline, opened without
/// following a symlink at its final component, removed when the daemon returns if it still holds our pid (as classic
/// daemons).
#[cfg(all(feature = "knet", target_os = "linux"))]
pub(crate) struct PidFile(Option<std::path::PathBuf>);

#[cfg(all(feature = "knet", target_os = "linux"))]
impl PidFile {
    pub(crate) fn create(a: &[String]) -> Result<Self, String> {
        use std::io::Write as _;
        let raw = set_opt(a, "pid_file").unwrap_or_default();
        if raw.is_empty() {
            return Ok(Self(None));
        }
        let id = arg(a, "--place-id")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let cluster = set_opt(a, "cluster").unwrap_or_else(|| "ceph".into());
        let host = arg(a, "--hostname").unwrap_or_else(osd::sysinfo::short_hostname);
        let dir = |k: &str| {
            set_opt(a, k)
                .or_else(|| osd::schema::effective_default(k).map(str::to_owned))
                .unwrap_or_default()
        };
        let path = osd::schema::Meta::new(&cluster, id, &host).expand(
            &raw,
            &dir("run_dir"),
            &dir("tmp_dir"),
        );
        let p = std::path::PathBuf::from(&path);
        let mut f =
            crate::logsink::open_regular(&p, false).map_err(|e| format!("pid_file {path}: {e}"))?;
        f.set_len(0)
            .and_then(|()| f.write_all(format!("{}\n", std::process::id()).as_bytes()))
            .map_err(|e| format!("pid_file {path}: {e}"))?;
        Ok(Self(Some(p)))
    }
}

#[cfg(all(feature = "knet", target_os = "linux"))]
impl Drop for PidFile {
    fn drop(&mut self) {
        if let Some(p) = &self.0
            && std::fs::read_to_string(p).is_ok_and(|s| s.trim() == std::process::id().to_string())
        {
            let _ = std::fs::remove_file(p);
        }
    }
}

pub(crate) fn die(code: i32, m: impl std::fmt::Display) -> i32 {
    eprintln!("croit-flashstore-osd: {m}");
    code
}

#[cfg(all(test, feature = "knet", target_os = "linux"))]
mod rdma_tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn pid_file_written_and_removed() {
        let d = std::env::temp_dir().join(format!("croit-flashstore-pid-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("osd.3.pid");
        let ps = p.to_str().unwrap();
        assert!(
            PidFile::create(&v(&["--set", "pid_file="]))
                .unwrap()
                .0
                .is_none()
        );
        let g = PidFile::create(&v(&[
            "--set",
            "pid_file=/x",
            "--set",
            &format!("pid-file={ps}"),
        ]))
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            format!("{}\n", std::process::id())
        );
        drop(g);
        assert!(!p.exists());
        // a file another process took over stays
        let g = PidFile::create(&v(&["--set", &format!("pid_file={ps}")])).unwrap();
        std::fs::write(&p, "1\n").unwrap();
        drop(g);
        assert!(p.exists());
        assert!(PidFile::create(&v(&["--set", "pid_file=/nonexistent/dir/x.pid"])).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `pid_file` expands the Ceph metavariables like `log_file` does: the identity `croit-flashstore-osd run` passes (`--place-id`)
    /// and the cluster reach the path every OSD on the host would otherwise share literally.
    #[test]
    fn pid_file_expands_metavariables() {
        let d =
            std::env::temp_dir().join(format!("croit-flashstore-pidvar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let raw = format!("{}/$cluster-$name.pid", d.display());
        let g = PidFile::create(&v(&[
            "--place-id",
            "5",
            "--set",
            "cluster=c1",
            "--set",
            &format!("pid_file={raw}"),
        ]))
        .unwrap();
        let p = d.join("c1-osd.5.pid");
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            format!("{}\n", std::process::id()),
            "the expanded path"
        );
        assert!(!d.join("$cluster-$name.pid").exists(), "no literal name");
        drop(g);
        assert!(!p.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The pid file is opened `O_NOFOLLOW`: a symlink planted in an operator-writable directory must neither be
    /// followed (the root SPDK tier would clobber its target) nor leave the target alone but writable.
    #[test]
    fn pid_file_never_follows_a_symlink() {
        let d =
            std::env::temp_dir().join(format!("croit-flashstore-pidlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let target = d.join("target");
        std::fs::write(&target, "keep").unwrap();
        let link = d.join("osd.pid");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let e = match PidFile::create(&v(&["--set", &format!("pid_file={}", link.display())])) {
            Ok(_) => panic!("a symlink is refused"),
            Err(e) => e,
        };
        assert!(e.contains("pid_file"), "{e}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rdma_flag_values() {
        assert_eq!(rdma_enabled(&v(&[])), Ok(false));
        assert_eq!(rdma_enabled(&v(&["--rdma", "true"])), Ok(true));
        assert_eq!(rdma_enabled(&v(&["--rdma", "false"])), Ok(false));
        assert!(rdma_enabled(&v(&["--rdma", "maybe"])).is_err());
    }

    #[test]
    fn placement_lab_flag_requires_the_lab_build_and_kernel_rdma() {
        assert_eq!(placement_lab_enabled(&v(&[]), false), Ok(false));
        assert_eq!(
            placement_lab_enabled(&v(&["--rdma-placement", "false"]), false),
            Ok(false)
        );
        assert!(placement_lab_enabled(&v(&["--rdma-placement", "true"]), false).is_err());
        assert!(placement_lab_enabled(&v(&["--rdma-placement", "maybe"]), true).is_err());
        assert_eq!(
            placement_lab_enabled(&v(&["--rdma-placement", "true"]), true),
            if cfg!(feature = "lab") {
                Ok(true)
            } else {
                Err("--rdma-placement requires the lab build feature".into())
            }
        );
    }

    #[cfg(feature = "rdma")]
    #[test]
    fn rdma_memory_values() {
        assert_eq!(rdma_memory(&v(&[])), Ok(256 << 20));
        assert_eq!(rdma_memory(&v(&["--rdma-memory", "1G"])), Ok(1 << 30));
        assert!(rdma_memory(&v(&["--rdma-memory", "0"])).is_err());
        assert!(rdma_memory(&v(&["--rdma-memory", "lots"])).is_err());
    }

    #[cfg(feature = "rdma")]
    #[test]
    fn rdma_max_sessions_values() {
        assert_eq!(rdma_max_sessions(&v(&[])), Ok(0));
        assert_eq!(
            rdma_max_sessions(&v(&["--rdma-max-sessions", "250"])),
            Ok(250)
        );
        assert!(rdma_max_sessions(&v(&["--rdma-max-sessions", "-1"])).is_err());
        assert!(rdma_max_sessions(&v(&["--rdma-max-sessions", "many"])).is_err());
    }

    #[test]
    fn rdma_refused_without_the_feature() {
        assert_eq!(rdma_refusal(false, false), None);
        assert_eq!(rdma_refusal(true, true), None);
        assert!(rdma_refusal(true, false).unwrap().contains("feature rdma"));
    }

    #[test]
    fn mon_host_comes_from_the_named_conf_in_any_spelling() {
        let p =
            std::env::temp_dir().join(format!("croit-flashstore-args-conf-{}", std::process::id()));
        std::fs::write(
            &p,
            "[global]\nfsid = x\n[osd]\nmon-host = [v2:10.0.0.1:3300]  # comment\n",
        )
        .unwrap();
        let conf = p.to_str().unwrap();
        assert_eq!(
            osddir::mon_host_from_args(&v(&["--conf", conf])).unwrap(),
            "[v2:10.0.0.1:3300]"
        );
        assert_eq!(
            osddir::mon_host_from_args(&v(&["--mon-host", "v2:10.0.0.2:3300", "--conf", conf]))
                .unwrap(),
            "v2:10.0.0.2:3300"
        );
        assert!(
            osddir::mon_host_from_args(&v(&["--conf", "/nonexistent/x.conf"]))
                .unwrap_err()
                .contains("no mon_host")
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn bad_lcore_is_an_error() {
        assert!(
            choose_cpus(&v(&["--lcore", "x"]), &[0, 1, 2, 3], 2, None, &[])
                .unwrap_err()
                .contains("bad --lcore")
        );
        assert_eq!(
            choose_cpus(&v(&["--lcore", "2"]), &[0, 1, 2, 3], 2, None, &[])
                .unwrap()
                .0,
            [2, 3]
        );
        // an explicit CPU outside the affinity mask is refused here, not by the launchers
        assert!(
            choose_cpus(&v(&["--lcore", "6"]), &[0, 1, 2, 3], 2, None, &[])
                .unwrap_err()
                .contains("not in the affinity mask")
        );
        // the range end must not wrap (debug: panic; release: empty/reversed range that the launchers then index)
        for first in [usize::MAX, usize::MAX - 1] {
            let e = choose_cpus(
                &v(&["--lcore", &first.to_string()]),
                &[0, 1, 2, 3],
                2,
                None,
                &[],
            )
            .unwrap_err();
            assert!(e.contains("CPU number range"), "{e}");
        }
    }

    /// The `--set` key normalisation of Ceph option names (`_` / `-` / space): one lookup for the daemon flags.
    #[test]
    fn set_option_keys_accept_every_spelling() {
        for k in [
            "flashstore_port_name",
            "flashstore-port-name",
            "flashstore port name",
        ] {
            let a = v(&["--set", "x=1", "--set", &format!("{k}=bond0")]);
            assert_eq!(
                set_opt(&a, "flashstore_port_name").as_deref(),
                Some("bond0")
            );
        }
        // the last setting wins, flanked by unrelated keys, and the value is trimmed
        let a = v(&[
            "--set",
            "flashstore_port_name=a",
            "--set",
            "cluster=c1",
            "--set",
            "flashstore-port-name= b ",
        ]);
        assert_eq!(set_opt(&a, "flashstore_port_name").as_deref(), Some("b"));
        assert_eq!(set_opt(&a, "flashstore_cores"), None);
    }

    #[cfg(feature = "kernel-nvme")]
    #[test]
    fn store_backend_accepts_both_key_spellings() {
        assert_eq!(
            store_backend(&v(&["--set", "flashstore-store-backend=kernel"])).as_deref(),
            Some("kernel")
        );
        assert_eq!(
            store_backend(&v(&["--set", " flashstore_store_backend = kernel-cmd "])).as_deref(),
            Some("kernel-cmd")
        );
        // a command line flag wins over the conf key
        assert_eq!(
            store_backend(&v(&[
                "--set",
                "flashstore_store_backend=spdk",
                "--store-backend",
                "kernel",
            ]))
            .as_deref(),
            Some("kernel")
        );
    }

    /// adr 0031/0160: `--cores` range, the shard cap and the single-core `--data` legacy mode.
    #[test]
    fn cores_flag_range_default_and_shard_cap() {
        assert_eq!(cores(&v(&[]), 8, Some(16), false), Ok(8), "every CPU");
        assert_eq!(cores(&v(&[]), 8, Some(3), false), Ok(3), "shard cap");
        assert_eq!(cores(&v(&[]), 8, None, false), Ok(1), "no shards known");
        assert_eq!(cores(&v(&[]), 8, Some(16), true), Ok(1), "--data");
        assert_eq!(cores(&v(&["--cores", "4"]), 8, Some(16), false), Ok(4));
        assert_eq!(cores(&v(&["--cores", "4"]), 8, Some(2), false), Ok(2));
        for bad in ["0", "9", "x"] {
            assert!(cores(&v(&["--cores", bad]), 8, None, false).is_err());
        }
    }
}
