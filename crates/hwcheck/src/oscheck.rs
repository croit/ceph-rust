// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Kernel / OS: version, io_uring (adr 0053/0098), sysctls, virtualization, container, seccomp, capabilities.
use crate::action::{Action, Cmp, Step};
use crate::fs::Fs;
use crate::{Check, Facts, Section, Status};

fn status_field(fs: &Fs, key: &str) -> Option<String> {
    fs.read("proc/self/status")?.lines().find_map(|l| {
        l.strip_prefix(key)?
            .strip_prefix(':')
            .map(|v| v.trim().to_string())
    })
}

pub fn section(fs: &Fs, facts: &mut Facts) -> Section {
    let mut v = Vec::new();
    let rel = fs.read("proc/sys/kernel/osrelease");
    let distro = fs
        .read("etc/os-release")
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        })
        .unwrap_or_default();
    v.push(match rel {
        Some(r) => Check::new("os.kernel", "kernel")
            .val(format!("{r} {distro}").trim().to_string())
            .why("no release gate (adr 0098: backports/config decide); capabilities are probed (io_uring multishot recv, SEND_ZC, NAPI busy poll); version shown for reference only")
            .ok(),
        None => Check::new("os.kernel", "kernel").val("not available (not Linux or no procfs)").why("kernel features decide the usable tiers").na(),
    });

    // io_uring
    let dis = fs.read("proc/sys/kernel/io_uring_disabled");
    let group = fs.read("proc/sys/kernel/io_uring_group");
    let sysctl = format!(
        "io_uring_disabled={} io_uring_group={}",
        dis.as_deref().unwrap_or("n/a"),
        group.as_deref().unwrap_or("n/a")
    );
    let mut ck = Check::new("os.io_uring", "io_uring").why("kernel TCP tier (adr 0053) and kernel store (adr 0169): multishot accept/recv with provided buffers, bounded waits, optional SEND_ZC and registered buffers (adr 0098 capability probe); the OSD runs as user ceph without CAP_SYS_ADMIN (adr 0056), so kernel.io_uring_disabled must let that user create rings").w(8);
    let policy = uring_access::Access::read(&fs.p(""));
    let policy_act = iouring_policy_action(&policy);
    #[cfg(all(feature = "knet", target_os = "linux"))]
    {
        if fs.live() {
            match rt::knet::probe_iouring() {
                Ok(r) => {
                    facts.knet_probe =
                        Some(r.required.as_ref().map(|_| ()).map_err(|e| e.to_string()));
                    let detail = format!(
                        "ring {} ; multishot accept/recv+bufs {} ; rx buffers {} ; SEND_ZC {} ; fixed buffers {}",
                        r.ring_mode,
                        if r.required.is_ok() { "ok" } else { "MISSING" },
                        r.rx_buffers.as_ref().map_or("n/a", |(m, _)| m),
                        if r.send_zc { "yes" } else { "no" },
                        if r.fixed_buffers { "yes" } else { "no" }
                    );
                    ck = ck.val(format!("{detail}; {sysctl}"));
                    let ring_err = r.rx_buffers.as_ref().and_then(|(_, e)| e.clone());
                    ck = if let Some(a) = policy_act.clone() {
                        ck.val(format!("{detail}; {sysctl}; this process may use io_uring (CAP_SYS_ADMIN or group), the OSD user {} may not", uring_access::OSD_USER)).fail().act(a)
                    } else {
                        match r.required {
                            Ok(()) if ring_err.is_some() => ck.warn().fix(format!("provided-buffer ring registration fails ({}): receive buffers use classic PROVIDE_BUFFERS (one SQE per returned run, tier fully functional); known cause: Ubuntu noble 6.8.0-132 and later reject every valid IORING_REGISTER_PBUF_RING; use a kernel without that regression", ring_err.unwrap_or_default())),
                            Ok(()) => if r.send_zc { ck.ok() } else { ck.warn().fix("kernel without io_uring SENDMSG_ZC (probed): large-send zero copy off, tier works without it; use a kernel that has it (mainline since 6.1, distro backports count)") },
                            Err(e) => ck.fail().fix(format!("{e}; use a kernel with the required io_uring features (adr 0098)")),
                        }
                    };
                }
                Err(e) => {
                    facts.knet_probe = Some(Err(e.to_string()));
                    ck = ck
                        .val(format!("cannot create a ring: {e}; {sysctl}"))
                        .fail();
                    ck = match policy_act.clone() {
                        Some(a) => ck.act(a),
                        None if policy.self_allowed() => ck.fix(policy.explain()),
                        // this process (not the OSD user) lacks group membership under io_uring_disabled=1
                        None => ck.fix(format!(
                            "run the check as root or as user {}: {}",
                            uring_access::OSD_USER,
                            policy.explain()
                        )),
                    };
                }
            }
        } else {
            ck = match policy_act {
                Some(a) => ck
                    .val(format!("not probed (not a live host); {sysctl}"))
                    .fail()
                    .act(a),
                None => ck
                    .val(format!("not probed (not a live host); {sysctl}"))
                    .na(),
            };
        }
    }
    #[cfg(not(all(feature = "knet", target_os = "linux")))]
    {
        let _ = facts;
        ck = ck.val(format!(
            "probe compiled out (build --features knet on Linux); {sysctl}"
        ));
        ck = match policy_act {
            Some(a) => ck.fail().act(a),
            None => ck.na(),
        };
    }
    v.push(ck);
    v.push(zcrx_check(fs));

    // sysctls
    let mut sc = |id: &str, key: &str, min: u64, why: &str, want: u64, w: u8| {
        let path = format!("proc/sys/{}", key.replace('.', "/"));
        let c = Check::new(format!("os.sysctl.{id}"), key.to_string())
            .why(why.to_string())
            .w(w);
        v.push(match fs.num(&path) {
            Some(n) if n >= min => c.val(n.to_string()).ok(),
            Some(n) => c
                .val(format!("{n} (want >= {min})"))
                .warn()
                .act(Action::new(vec![Step::Sysctl {
                    key: key.into(),
                    want: want.to_string(),
                    cmp: Cmp::AtLeast,
                }])),
            None => c.val("not available").na(),
        });
    };
    sc(
        "rmem_max",
        "net.core.rmem_max",
        4 << 20,
        "kernel tier socket receive buffers (SO_RCVBUF is capped by it): small values limit single-stream throughput",
        16777216,
        4,
    );
    sc(
        "wmem_max",
        "net.core.wmem_max",
        4 << 20,
        "kernel tier socket send buffers (SO_SNDBUF cap): small values limit single-stream throughput",
        16777216,
        4,
    );
    sc(
        "somaxconn",
        "net.core.somaxconn",
        1024,
        "listen backlog: hundreds of clients connect at once after a restart",
        4096,
        2,
    );
    if let Some(nb) = fs.num("proc/sys/kernel/numa_balancing") {
        v.push(
            Check::new("os.sysctl.numa_balancing", "kernel.numa_balancing")
                .val(nb.to_string())
                .why("automatic NUMA page migration adds faults and jitter to pinned polling cores")
                .warn_if(nb != 0)
                .act(Action::new(vec![Step::Sysctl {
                    key: "kernel.numa_balancing".into(),
                    want: "0".into(),
                    cmp: Cmp::Eq,
                }]))
                .w(3),
        );
    }

    v.push(init_on_alloc(fs));

    // virtualization
    let hv = fs.read("proc/cpuinfo").is_some_and(|s| {
        s.lines()
            .any(|l| l.starts_with("flags") && l.split_whitespace().any(|f| f == "hypervisor"))
    });
    let vendor = fs.read("sys/class/dmi/id/sys_vendor").unwrap_or_default();
    let product = fs.read("sys/class/dmi/id/product_name").unwrap_or_default();
    let c = Check::new("os.virt", "virtualization")
        .why("production = bare metal (IOMMU/VFIO, invariant TSC, SR-IOV, real MSI-X); a VM runs the lab fallbacks (uio, kvm-clock) at lower and noisier performance");
    v.push(if hv {
        c.val(format!("VM ({} {})", vendor, product).trim().to_string())
            .warn()
            .fix("deploy on bare metal for production; VMs are for functional tests")
            .w(5)
    } else if vendor.is_empty() && product.is_empty() {
        c.val("no hypervisor flag; DMI not readable").na()
    } else {
        c.val(format!("bare metal ({vendor} {product})")).ok()
    });

    // container
    let cg = fs.read("proc/1/cgroup").unwrap_or_default();
    let ctr = fs.exists(".dockerenv")
        || fs.exists("run/.containerenv")
        || cg.contains("docker")
        || cg.contains("kubepods")
        || cg.contains("libpod");
    v.push(
        Check::new("os.container", "container")
            .val(if ctr { "running in a container" } else { "no" })
            .why("a container needs the host's vfio devices, hugetlbfs, memlock and sysfs mounted (deploy.md run contract); the host-level checks above only see what the container exposes")
            .ok(),
    );
    let sec = status_field(fs, "Seccomp");
    v.push(match sec.as_deref() {
        Some("2") => Check::new("os.seccomp", "seccomp").val("filter active").why("default container profiles can block io_uring_setup, which the kernel tier needs").warn().fix("allow io_uring in the seccomp profile or run with --security-opt seccomp=unconfined (lab)").w(3),
        Some(s) => Check::new("os.seccomp", "seccomp").val(if s == "0" { "none" } else { "strict" }).why("a syscall filter can block io_uring_setup").ok(),
        None => Check::new("os.seccomp", "seccomp").val("not available").why("a syscall filter can block io_uring_setup").na(),
    });
    // privileges
    let uid = status_field(fs, "Uid").and_then(|u| u.split_whitespace().next().map(str::to_string));
    let caps = status_field(fs, "CapEff").and_then(|c| u64::from_str_radix(&c, 16).ok());
    if let Some(caps) = caps {
        let ipc = caps & (1 << 14) != 0;
        let nice = caps & (1 << 23) != 0;
        let c = Check::new("os.caps", "privileges")
            .val(format!("uid {} IPC_LOCK={} SYS_NICE={}", uid.as_deref().unwrap_or("?"), ipc, nice))
            .why("the daemon needs IPC_LOCK (pin DMA memory) and SYS_NICE (RT/affinity); the unit grants both as ambient caps (adr 0056)");
        v.push(if ipc && nice { c.ok() } else { c.st(Status::Warn).fix("run the check as the service user with the unit's caps, or as root; in a container: --cap-add IPC_LOCK --cap-add SYS_NICE").w(2) });
    }
    Section {
        name: "Kernel / OS",
        checks: v,
    }
}

/// Host fix that lets the OSD user create io_uring instances (`kernel.io_uring_disabled`, adr 0053 am. 11); `None` when
/// the policy already allows it or the user is unknown. `=2` (RHEL 9 default): io_uring for the OSD group only
/// (`io_uring_group` + `=1`) where the kernel has the group sysctl, else `=0`; `=1`: the OSD group as `io_uring_group`.
fn iouring_policy_action(a: &uring_access::Access) -> Option<Action> {
    use uring_access::Sysctl;

    if a.osd_user_allowed() != Some(false) {
        return None;
    }
    let sysctl = |key: &str, want: String| Step::Sysctl {
        key: key.into(),
        want,
        cmp: Cmp::Eq,
    };
    let user = uring_access::OSD_USER;
    Some(match (a.disabled, a.group, a.osd_gid) {
        (Sysctl::Value(1), _, Some(g)) => {
            let alternative = a.group.named_gid().map_or_else(String::new, |named| {
                format!("; alternative: add {user} to group {named}")
            });
            Action::new(vec![sysctl("kernel.io_uring_group", g.to_string())])
                .note(format!("io_uring for group {g} (user {user}) and CAP_SYS_ADMIN{alternative}"))
        }
        (_, Sysctl::Value(_), Some(g)) => Action::new(vec![
            sysctl("kernel.io_uring_group", g.to_string()),
            sysctl("kernel.io_uring_disabled", "1".into()),
        ])
        .note(format!("io_uring for group {g} (user {user}) and CAP_SYS_ADMIN only; alternative for every process: sysctl -w kernel.io_uring_disabled=0")),
        _ => Action::new(vec![sysctl("kernel.io_uring_disabled", "0".into())])
            .note("io_uring for every process (this kernel has no kernel.io_uring_group)"),
    })
}

/// Kernel bool as `kstrtobool` reads it (`1/y/Y/t/T/on`, `0/n/N/f/F/off`).
fn parse_kbool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "y" | "yes" | "t" | "true" | "on" => Some(true),
        "0" | "n" | "no" | "f" | "false" | "off" => Some(false),
        _ => None,
    }
}

/// Build-time default of `init_on_alloc` from an installed kernel config (`CONFIG_INIT_ON_ALLOC_DEFAULT_ON`).
fn init_on_alloc_default(fs: &Fs) -> Option<bool> {
    let rel = fs.read("proc/sys/kernel/osrelease")?;
    [
        format!("boot/config-{rel}"),
        format!("lib/modules/{rel}/config"),
    ]
    .iter()
    .find_map(|p| fs.read(p))
    .map(|cfg| {
        cfg.lines()
            .any(|l| l == "CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y")
    })
}

/// `init_on_alloc`: the kernel zeroes every page it allocates (about 15-20 % of the CPU of large reads, profile
/// 2026-10-20). The parameter is boot-only (no sysfs file), so the effective value = cmdline, else the config default.
fn init_on_alloc(fs: &Fs) -> Check {
    let c = Check::new("os.init_on_alloc", "kernel init_on_alloc").why(
        "page zeroing on every allocation costs about 15-20 % of the CPU of large reads on the kernel tier (stage profile 2026-10-20)",
    );
    let (on, src) = match fs.cmdline_arg("init_on_alloc") {
        Some(v) => match parse_kbool(&v) {
            Some(b) => (b, "cmdline"),
            None => return c.val(format!("init_on_alloc={v} (unparsable)")).na(),
        },
        None => match init_on_alloc_default(fs) {
            Some(b) => (b, "kernel config default"),
            None if fs.has_proc() => {
                return c
                    .val("not on the cmdline; kernel config not readable (default unknown)")
                    .na();
            }
            None => return c.val("not available").na(),
        },
    };
    let c = c.val(format!("{} ({src})", if on { "1" } else { "0" }));
    if !on {
        return c.ok();
    }
    c.warn().w(6).fix(
        "kernel cmdline `init_on_alloc=0` (needs a reboot; Debian/Ubuntu: add to GRUB_CMDLINE_LINUX in /etc/default/grub, run update-grub; RHEL: grubby --update-kernel=ALL --args=init_on_alloc=0); trade-off: drops the hardening that clears freed-then-reused kernel memory (info-leak mitigation)",
    )
}

/// io_uring zero-copy receive of the kernel (adr 0464): optional speed-up, never a failure. The OSD's startup line gives
/// the full verdict for its public port (NIC, steering, registration); this row covers the kernel half.
fn zcrx_check(fs: &Fs) -> Check {
    let ck = Check::new("os.zcrx", "io_uring zero-copy receive")
        .why("kernel tier receive without the kernel copy (adr 0464); without it the copy receive runs unchanged")
        .w(2);
    #[cfg(all(feature = "knet", target_os = "linux"))]
    {
        if !fs.live() {
            return ck.val("not probed (not a live host)").na();
        }
        match rt::knet::zcrx::probe_kernel() {
            Ok(()) => ck.val("RECV_ZC and zcrx ring flags available (NIC: see net.<if>.zcrx_ready, OSD startup line)").ok(),
            // optional speed-up, not a defect: the advice goes into `why` (a `fix` is only for WARN/FAIL)
            Err(r) => ck
                .val(format!("missing: {}", r.as_str()))
                .why(format!("kernel tier receive without the kernel copy (adr 0464); without it the copy receive runs unchanged; {}", r.fix("<if>", 0)))
                .na(),
        }
    }
    #[cfg(not(all(feature = "knet", target_os = "linux")))]
    {
        let _ = fs;
        ck.val("probe compiled out (build --features knet on Linux)")
            .na()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("hwcheck-ioa-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(p.join("proc/sys/kernel")).unwrap();
        fs::create_dir_all(p.join("boot")).unwrap();
        fs::write(p.join("proc/sys/kernel/osrelease"), "6.1.0-test\n").unwrap();
        p
    }

    fn run(p: &std::path::Path, cmdline: &str, cfg: Option<&str>) -> Check {
        fs::write(p.join("proc/cmdline"), cmdline).unwrap();
        if let Some(c) = cfg {
            fs::write(p.join("boot/config-6.1.0-test"), c).unwrap();
        }
        init_on_alloc(&Fs::new(p))
    }

    #[test]
    fn cmdline_wins_over_config() {
        let p = root("a");
        let c = run(
            &p,
            "ro init_on_alloc=0",
            Some("CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y\n"),
        );
        assert_eq!(c.status, Status::Ok);
        let c = run(
            &p,
            "ro init_on_alloc=1",
            Some("# CONFIG_INIT_ON_ALLOC_DEFAULT_ON is not set\n"),
        );
        assert_eq!(c.status, Status::Warn);
        assert!(c.fix.unwrap().contains("init_on_alloc=0"));
        let _ = fs::remove_dir_all(&p);
    }

    #[test]
    fn config_default_applies_without_cmdline() {
        let p = root("b");
        assert_eq!(
            run(&p, "ro quiet", Some("CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y\n")).status,
            Status::Warn
        );
        assert_eq!(
            run(
                &p,
                "ro quiet",
                Some("# CONFIG_INIT_ON_ALLOC_DEFAULT_ON is not set\n")
            )
            .status,
            Status::Ok
        );
        let _ = fs::remove_dir_all(&p);
    }

    fn policy(files: &[(&str, &str)]) -> Option<Action> {
        let p = std::env::temp_dir().join(format!(
            "hwcheck-iou-{}-{}",
            files.len(),
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&p);
        for (f, c) in files {
            fs::create_dir_all(p.join(f).parent().unwrap()).unwrap();
            fs::write(p.join(f), c).unwrap();
        }
        let a = iouring_policy_action(&uring_access::Access::read(&p));
        let _ = fs::remove_dir_all(&p);
        a
    }

    const PASSWD: (&str, &str) = (
        "etc/passwd",
        "ceph:x:167:167::/var/lib/ceph:/sbin/nologin\n",
    );

    fn cmds(a: &Action) -> Vec<String> {
        a.steps.iter().flat_map(Step::commands).collect()
    }

    #[test]
    fn io_uring_policy_fix_for_the_osd_user() {
        // RHEL 9 default: group + 1 (least privilege), alternative 0 in the note
        let a = policy(&[
            ("proc/sys/kernel/io_uring_disabled", "2"),
            ("proc/sys/kernel/io_uring_group", "-1"),
            PASSWD,
        ])
        .unwrap();
        assert_eq!(
            cmds(&a),
            [
                "sysctl -w kernel.io_uring_group=167",
                "sysctl -w kernel.io_uring_disabled=1"
            ]
        );
        // no group sysctl: 0
        let a = policy(&[("proc/sys/kernel/io_uring_disabled", "2"), PASSWD]).unwrap();
        assert_eq!(cmds(&a), ["sysctl -w kernel.io_uring_disabled=0"]);
        // 1 with another group: the OSD group
        let a = policy(&[
            ("proc/sys/kernel/io_uring_disabled", "1"),
            ("proc/sys/kernel/io_uring_group", "6"),
            PASSWD,
        ])
        .unwrap();
        assert_eq!(cmds(&a), ["sysctl -w kernel.io_uring_group=167"]);
        // allowed: nothing to do
        assert!(
            policy(&[
                ("proc/sys/kernel/io_uring_disabled", "1"),
                ("proc/sys/kernel/io_uring_group", "167"),
                PASSWD
            ])
            .is_none()
        );
        assert!(policy(&[("proc/sys/kernel/io_uring_disabled", "0"), PASSWD]).is_none());
        // 1 without a ceph user: unknown, no guess
        assert!(
            policy(&[
                ("proc/sys/kernel/io_uring_disabled", "1"),
                ("proc/sys/kernel/io_uring_group", "6")
            ])
            .is_none()
        );
    }

    #[test]
    fn unknown_without_config_is_na() {
        let p = root("c");
        assert_eq!(run(&p, "ro quiet", None).status, Status::Na);
        let _ = fs::remove_dir_all(&p);
    }
}
