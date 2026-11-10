// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `host-tune` CLI against a fixture root: dry run, apply, idempotency, revert, exit codes.
#![cfg(unix)]
use hwcheck::action::Runner;
use hwcheck::tune::cli_with;
use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::rc::Rc;

struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
impl Root {
    fn new(tag: &str) -> Root {
        let p = std::env::temp_dir().join(format!("hosttune-it-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Root(p)
    }
    fn w(&self, rel: &str, s: &str) {
        let p = self.0.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, s).unwrap();
    }
    fn r(&self, rel: &str) -> String {
        fs::read_to_string(self.0.join(rel))
            .unwrap()
            .trim()
            .to_string()
    }
}

/// Command runner that applies `sysctl -w` and `cpupower frequency-set -g` to the fixture tree.
struct Sim {
    root: PathBuf,
    log: Rc<RefCell<Vec<String>>>,
}
impl Runner for Sim {
    fn run(&mut self, a: &[String]) -> Result<String, String> {
        self.log.borrow_mut().push(a.join(" "));
        let s: Vec<&str> = a.iter().map(String::as_str).collect();
        match s.as_slice() {
            ["sysctl", "-w", kv] => {
                let (k, v) = kv.split_once('=').unwrap();
                fs::write(self.root.join("proc/sys").join(k.replace('.', "/")), v)
                    .map_err(|e| e.to_string())?;
                Ok(String::new())
            }
            ["cpupower", "frequency-set", "-g", g] => {
                fs::write(
                    self.root
                        .join("sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
                    g,
                )
                .map_err(|e| e.to_string())?;
                Ok(String::new())
            }
            _ => Err(format!("unexpected {}", a.join(" "))),
        }
    }
}

fn fixture(tag: &str) -> Root {
    let r = Root::new(tag);
    r.w("proc/cpuinfo", "processor\t: 0\nflags\t\t: fpu sse4_2\n");
    r.w("proc/meminfo", "MemTotal: 263000000 kB\n");
    r.w("proc/sys/net/core/rmem_max", "212992");
    r.w("proc/sys/net/core/wmem_max", "212992");
    r.w("proc/sys/net/core/somaxconn", "128");
    r.w("proc/sys/kernel/numa_balancing", "1");
    r.w(
        "sys/kernel/mm/transparent_hugepage/enabled",
        "[always] madvise never",
    );
    r.w("sys/devices/system/cpu/online", "0-15");
    r.w(
        "sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
        "powersave",
    );
    // NIC node of 2 cpus = 2 queues: the spread layout is complete after one apply
    r.w("sys/devices/system/node/node0/cpulist", "0-1");
    r.w("etc/ceph/ceph.conf", "[osd.0]\nflashstore_lcores = 2-5\n");
    let b = "sys/class/net/eth0";
    r.w(&format!("{b}/flags"), "0x1003");
    r.w(&format!("{b}/device/numa_node"), "0");
    fs::create_dir_all(r.0.join("sys/bus/pci/devices/0000:41:00.0")).unwrap();
    fs::remove_dir_all(r.0.join(format!("{b}/device"))).unwrap();
    symlink(
        "../../../bus/pci/devices/0000:41:00.0",
        r.0.join(format!("{b}/device")),
    )
    .unwrap();
    r.w("sys/bus/pci/devices/0000:41:00.0/numa_node", "0");
    r.w(
        "proc/interrupts",
        "           CPU0       CPU1\n 40:          1          0  PCI-MSIX-0000:41:00.0   0-edge      eth0-TxRx-0\n 41:          0          1  PCI-MSIX-0000:41:00.0   1-edge      eth0-TxRx-1\n",
    );
    // no effective_affinity_list: kernels without it report the requested mask (a live kernel updates it itself)
    r.w("proc/irq/40/smp_affinity_list", "3");
    r.w("proc/irq/41/smp_affinity_list", "4");
    r
}

fn args(r: &Root, extra: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = [
        "--root",
        r.0.to_str().unwrap(),
        "--conf",
        "etc/ceph/ceph.conf",
        "--format",
        "json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

#[test]
fn dry_run_apply_idempotent_revert() {
    let r = fixture("flow");
    let log = Rc::new(RefCell::new(Vec::new()));
    let sim = || Sim {
        root: r.0.clone(),
        log: log.clone(),
    };
    let sf = r.0.join("state.json");
    let sfs = sf.to_str().unwrap();

    // dry run: exit 0, nothing changed
    assert_eq!(cli_with(&args(&r, &[]), sim()), 0);
    assert_eq!(r.r("proc/sys/net/core/wmem_max"), "212992");
    assert!(
        log.borrow().is_empty(),
        "dry run runs no command: {:?}",
        log.borrow()
    );

    // apply
    assert_eq!(
        cli_with(
            &args(
                &r,
                &[
                    "--apply",
                    "--state",
                    sfs,
                    "--check",
                    "os.sysctl",
                    "--check",
                    "mem.thp",
                    "--check",
                    "cpu.governor",
                    "--check",
                    "net.eth0.irq"
                ]
            ),
            sim()
        ),
        0
    );
    assert_eq!(r.r("proc/sys/net/core/wmem_max"), "16777216");
    assert_eq!(r.r("proc/sys/net/core/somaxconn"), "4096");
    assert_eq!(r.r("proc/sys/kernel/numa_balancing"), "0");
    assert_eq!(r.r("sys/kernel/mm/transparent_hugepage/enabled"), "madvise");
    assert_eq!(
        r.r("sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "performance"
    );
    // spread layout: queue k on NIC-local cpu k, OSD cores included
    assert_eq!(r.r("proc/irq/40/smp_affinity_list"), "0");
    assert_eq!(r.r("proc/irq/41/smp_affinity_list"), "1");
    assert!(sf.exists());

    // idempotent: second apply runs nothing
    let n = log.borrow().len();
    assert_eq!(
        cli_with(
            &args(
                &r,
                &[
                    "--apply",
                    "--state",
                    r.0.join("s2.json").to_str().unwrap(),
                    "--check",
                    "os.sysctl",
                    "--check",
                    "mem.thp",
                    "--check",
                    "cpu.governor",
                    "--check",
                    "net.eth0.irq"
                ]
            ),
            sim()
        ),
        0
    );
    assert_eq!(log.borrow().len(), n, "already good: no command");

    // revert restores the prior values; a bare --revert reads the --state file
    assert_eq!(cli_with(&args(&r, &["--revert", "--state", sfs]), sim()), 0);
    assert_eq!(r.r("proc/sys/net/core/wmem_max"), "212992");
    assert_eq!(r.r("proc/sys/net/core/somaxconn"), "128");
    assert_eq!(r.r("proc/sys/kernel/numa_balancing"), "1");
    assert_eq!(r.r("sys/kernel/mm/transparent_hugepage/enabled"), "always");
    assert_eq!(
        r.r("sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "powersave"
    );
    assert_eq!(r.r("proc/irq/40/smp_affinity_list"), "3");
    assert_eq!(r.r("proc/irq/41/smp_affinity_list"), "4");
}

#[test]
fn usage_errors_exit_2() {
    let r = fixture("usage");
    let log = Rc::new(RefCell::new(Vec::new()));
    let sim = || Sim {
        root: r.0.clone(),
        log: log.clone(),
    };
    assert_eq!(cli_with(&args(&r, &["--bogus"]), sim()), 2);
    assert_eq!(cli_with(&args(&r, &["--revert", "x", "--apply"]), sim()), 2);
    assert_eq!(
        cli_with(&args(&r, &["--zcrx-queues", "2"]), sim()),
        2,
        "zcrx needs the full set"
    );
    // a count of 0 or a sum beyond u32 would render `ethtool -L <if> combined 0` / a wrapped value: usage error
    for bad in [
        &[
            "--iface",
            "eth0",
            "--zcrx-queues",
            "2",
            "--host-queues",
            "0",
            "--osd-port",
            "6800",
        ][..],
        &[
            "--iface",
            "eth0",
            "--zcrx-queues",
            "0",
            "--host-queues",
            "6",
            "--osd-port",
            "6800",
        ],
        &[
            "--iface",
            "eth0",
            "--zcrx-queues",
            "3000000000",
            "--host-queues",
            "3000000000",
            "--osd-port",
            "6800",
        ],
    ] {
        assert_eq!(cli_with(&args(&r, bad), sim()), 2, "{bad:?}");
    }
    assert_eq!(cli_with(&["--format".into(), "yaml".into()], sim()), 2);
    assert_eq!(
        cli_with(&args(&r, &["--revert", "/nonexistent/state.json"]), sim()),
        1,
        "missing state file is a failure"
    );
}

#[test]
fn failing_command_exits_1() {
    let r = fixture("fail");
    // a runner that refuses everything: every sysctl step fails
    struct Deny;
    impl Runner for Deny {
        fn run(&mut self, a: &[String]) -> Result<String, String> {
            Err(format!("{}: denied", a.join(" ")))
        }
    }
    let sf = r.0.join("state.json");
    assert_eq!(
        cli_with(
            &args(
                &r,
                &[
                    "--apply",
                    "--state",
                    sf.to_str().unwrap(),
                    "--check",
                    "os.sysctl"
                ]
            ),
            Deny
        ),
        1
    );
    assert_eq!(r.r("proc/sys/net/core/wmem_max"), "212992");
}
