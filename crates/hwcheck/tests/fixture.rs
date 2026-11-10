// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Fixture sysfs/procfs trees (fake root) and the JSON schema stability test.
#![cfg(unix)]
use hwcheck::{Format, Options, Report, Status, render, run};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
impl Root {
    fn new(tag: &str) -> Root {
        let p = std::env::temp_dir().join(format!("hwcheck-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Root(p)
    }
    fn w(&self, rel: &str, s: &str) {
        let p = self.0.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, s).unwrap();
    }
    fn d(&self, rel: &str) {
        fs::create_dir_all(self.0.join(rel)).unwrap();
    }
    fn link(&self, rel: &str, target: &str) {
        let p = self.0.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        symlink(target, p).unwrap();
    }
    fn opts(&self) -> Options {
        Options {
            root: self.0.clone(),
            build_id: "test".into(),
            ..Default::default()
        }
    }
}

fn status(r: &Report, id: &str) -> (Status, String) {
    let c = r
        .sections
        .iter()
        .flat_map(|s| &s.checks)
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no check {id}"));
    (c.status, c.value.clone())
}

fn host(r: &Root) {
    r.w("proc/cpuinfo", "processor\t: 0\nvendor_id\t: AuthenticAMD\ncpu family\t: 25\nmodel\t\t: 17\nmodel name\t: AMD EPYC 9xx4\nstepping\t: 1\nflags\t\t: fpu sse4_2 pclmulqdq vpclmulqdq avx2 avx512f constant_tsc nonstop_tsc sha_ni\n\nprocessor\t: 1\n");
    r.w(
        "proc/cmdline",
        "BOOT_IMAGE=/vmlinuz ro intel_iommu=on iommu=pt isolcpus=2-9\n",
    );
    r.w(
        "proc/meminfo",
        "MemTotal:       263000000 kB\nMemAvailable:   250000000 kB\n",
    );
    r.w(
        "proc/mounts",
        "hugetlbfs /dev/hugepages hugetlbfs rw 0 0\n/dev/nvme0n1p1 / ext4 rw 0 0\n",
    );
    r.w(
        "proc/self/limits",
        "Max locked memory         unlimited            unlimited            bytes\n",
    );
    r.w(
        "proc/self/status",
        "Uid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\nSeccomp:\t0\nCpus_allowed_list:\t0-15\n",
    );
    r.w("proc/sys/kernel/osrelease", "6.12.0-test\n");
    r.w("proc/sys/net/core/rmem_max", "16777216");
    r.w("proc/sys/net/core/wmem_max", "212992");
    r.w("proc/sys/net/core/somaxconn", "4096");
    r.w("sys/devices/system/cpu/online", "0-15");
    for c in 0..16 {
        r.w(
            &format!("sys/devices/system/cpu/cpu{c}/topology/physical_package_id"),
            "0",
        );
        r.w(
            &format!("sys/devices/system/cpu/cpu{c}/topology/core_id"),
            &(c % 8).to_string(),
        );
    }
    r.w(
        "sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
        "powersave",
    );
    r.w("sys/devices/system/cpu/smt/active", "1");
    r.w("sys/devices/system/cpu/isolated", "2-9");
    r.w("sys/devices/system/node/node0/cpulist", "0-15");
    r.w(
        "sys/devices/system/clocksource/clocksource0/current_clocksource",
        "tsc",
    );
    r.w(
        "sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages",
        "4096",
    );
    r.w(
        "sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages",
        "4096",
    );
    r.w(
        "sys/kernel/mm/transparent_hugepage/enabled",
        "always [madvise] never",
    );
    r.w("sys/class/dmi/id/sys_vendor", "ACME");
    r.w("sys/class/dmi/id/product_name", "Server1");
    for g in 0..4 {
        r.d(&format!("sys/kernel/iommu_groups/{g}"));
    }
    r.d("sys/module/vfio_pci");
    r.w("dev/vfio/vfio", "");
}

fn nvme(r: &Root, bdf: &str, driver: &str, wc: &str, lbs: &str, speed: &str) {
    let b = format!("sys/bus/pci/devices/{bdf}");
    r.w(&format!("{b}/class"), "0x010802");
    r.w(&format!("{b}/vendor"), "0x144d");
    r.w(&format!("{b}/device"), "0xa80a");
    r.w(&format!("{b}/numa_node"), "0");
    r.w(&format!("{b}/current_link_speed"), speed);
    r.w(&format!("{b}/max_link_speed"), "16.0 GT/s PCIe");
    r.w(&format!("{b}/current_link_width"), "4");
    r.w(&format!("{b}/max_link_width"), "4");
    r.link(
        &format!("{b}/driver"),
        &format!("../../../../bus/pci/drivers/{driver}"),
    );
    if driver == "nvme" {
        r.w(&format!("{b}/nvme/nvme0/model"), "TESTDRIVE 3.84TB\n");
        r.w(&format!("{b}/nvme/nvme0/firmware_rev"), "FW1\n");
        r.w(&format!("{b}/nvme/nvme0/serial"), "SN0001\n");
        r.w(&format!("{b}/nvme/nvme0/state"), "live\n");
        r.d(&format!("{b}/nvme/nvme0/nvme0n1"));
        r.w("sys/block/nvme0n1/queue/write_cache", wc);
        r.w("sys/block/nvme0n1/queue/logical_block_size", lbs);
    }
}

fn nic(r: &Root, n: &str, drv: &str, rx: usize) {
    let b = format!("sys/class/net/{n}");
    r.w(&format!("{b}/speed"), "100000");
    r.w(&format!("{b}/mtu"), "9000");
    r.w(&format!("{b}/operstate"), "up");
    r.w(&format!("{b}/flags"), "0x1003");
    r.d("sys/bus/pci/devices/0000:41:00.0");
    r.link(
        &format!("{b}/device"),
        "../../../bus/pci/devices/0000:41:00.0",
    );
    r.link(
        &format!("{b}/device/driver"),
        &format!("../../../../bus/pci/drivers/{drv}"),
    );
    for q in 0..rx {
        r.d(&format!("{b}/queues/rx-{q}"));
        r.d(&format!("{b}/queues/tx-{q}"));
    }
}

#[test]
fn no_plp_is_fail_and_exit_1() {
    let r = Root::new("noplp");
    host(&r);
    nvme(
        &r,
        "0000:03:00.0",
        "nvme",
        "write back",
        "512",
        "16.0 GT/s PCIe",
    );
    let rep = run(&r.opts());
    assert_eq!(status(&rep, "nvme.0000:03:00.0.plp").0, Status::Fail);
    assert_eq!(rep.exit_code(), 1);
    let (s, v) = status(&rep, "nvme.0000:03:00.0.inuse");
    assert_eq!(s, Status::Ok);
    assert!(v.contains("mounted /"), "{v}");
    assert_eq!(status(&rep, "nvme.0000:03:00.0.lba").0, Status::Warn);
}

#[test]
fn plp_ok_warn_only_exits_0() {
    let r = Root::new("plp");
    host(&r);
    nvme(
        &r,
        "0000:03:00.0",
        "nvme",
        "write through",
        "4096",
        "8.0 GT/s PCIe",
    );
    nic(&r, "eth0", "bnxt_en", 1);
    let rep = run(&r.opts());
    assert_eq!(status(&rep, "nvme.0000:03:00.0.plp").0, Status::Ok);
    assert_eq!(
        status(&rep, "nvme.0000:03:00.0.link").0,
        Status::Warn,
        "downtrained link"
    );
    assert_eq!(status(&rep, "net.eth0.rss").0, Status::Warn);
    assert_eq!(status(&rep, "cpu.governor").0, Status::Warn);
    assert_eq!(status(&rep, "cpu.pclmul").0, Status::Ok);
    assert_eq!(status(&rep, "cpu.tsc").0, Status::Ok);
    assert_eq!(status(&rep, "mem.hugepages").0, Status::Ok);
    assert_eq!(status(&rep, "iommu.groups").0, Status::Ok);
    assert_eq!(status(&rep, "iommu.passthrough").0, Status::Ok);
    // the fixture has `sys/module/vfio_pci` (sysfs spells modules with '_')
    let (st, val) = status(&rep, "iommu.vfio");
    assert_eq!(st, Status::Ok, "{val}");
    assert!(val.starts_with("module loaded"), "{val}");
    assert_eq!(status(&rep, "os.sysctl.wmem_max").0, Status::Warn);
    assert_eq!(status(&rep, "mem.thp").0, Status::Ok);
    assert!(rep.count(Status::Warn) > 0);
    assert_eq!(rep.exit_code(), 0);
    assert!(!rep.top_fixes.is_empty() && rep.top_fixes.len() <= 3);
}

#[test]
fn userspace_bound_nvme_is_not_probed() {
    let r = Root::new("vfio");
    host(&r);
    nvme(&r, "0000:03:00.0", "vfio-pci", "", "", "16.0 GT/s PCIe");
    let rep = run(&r.opts());
    for s in ["plp", "lba", "inuse", "identity"] {
        let (st, v) = status(&rep, &format!("nvme.0000:03:00.0.{s}"));
        assert_eq!(st, Status::Na, "{s}");
        assert!(v.contains("not probed") || s == "identity", "{s}: {v}");
    }
    assert_eq!(status(&rep, "nvme.0000:03:00.0.link").0, Status::Ok);
    assert_eq!(rep.exit_code(), 0);
}

#[test]
fn conf_cross_checks() {
    let r = Root::new("conf");
    host(&r);
    nvme(
        &r,
        "0000:03:00.0",
        "nvme",
        "write through",
        "4096",
        "16.0 GT/s PCIe",
    );
    r.w("etc/ceph/ceph.conf", "[osd.0]\nflashstore_lcores = 0-11\nflashstore_hugepages_mb = 4096\n[osd.1]\nflashstore_lcores = 11-14\nflashstore_hugepages_mb = 9000\nflashstore_dev = spdk:0000:03:00.0\n");
    let rep = run(&r.opts());
    assert_eq!(status(&rep, "conf.osd.0.cores").0, Status::Warn, ">8 cores");
    assert_eq!(
        status(&rep, "conf.osd.1.cores").0,
        Status::Fail,
        "cpu 11 overlaps"
    );
    assert_eq!(
        status(&rep, "mem.hugepages").0,
        Status::Warn,
        "need 13096 MiB, have 8192"
    );
    assert_eq!(rep.exit_code(), 1);
}

#[test]
fn conf_pci_alias_matches_the_sysfs_device() {
    // `spdk:03:00.0` is the same device as sysfs `0000:03:00.0`: the per-drive checks must find its OSD.
    let r = Root::new("pcialias");
    host(&r);
    r.w("sys/devices/system/node/node1/cpulist", "16-31");
    nvme(
        &r,
        "0000:03:00.0",
        "nvme",
        "write through",
        "4096",
        "16.0 GT/s PCIe",
    );
    r.w(
        "etc/ceph/ceph.conf",
        "[osd.0]\nflashstore_lcores = 16-17\nflashstore_dev = spdk:03:00.0\n",
    );
    let rep = run(&r.opts());
    assert_eq!(
        status(&rep, "nvme.0000:03:00.0.numa").0,
        Status::Warn,
        "lcores off the drive's node"
    );
    assert_eq!(status(&rep, "conf.osd.0.dev").0, Status::Ok);
}

#[test]
fn schema_is_stable() {
    let r = Root::new("schema");
    host(&r);
    nvme(
        &r,
        "0000:03:00.0",
        "nvme",
        "write through",
        "4096",
        "16.0 GT/s PCIe",
    );
    nic(&r, "eth0", "mlx5_core", 8);
    let rep = run(&r.opts());
    let j = rep.to_json();
    let keys = |v: &serde_json::Value| -> Vec<String> {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(
        keys(&j),
        [
            "root",
            "schema",
            "sections",
            "summary",
            "tiers",
            "top_fixes",
            "version"
        ]
    );
    assert_eq!(j["schema"], 1);
    assert_eq!(
        keys(&j["summary"]),
        ["exit_code", "fail", "na", "ok", "warn"]
    );
    let secs: Vec<&str> = j["sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        secs,
        [
            "Build",
            "CPU",
            "Memory",
            "IOMMU / VFIO",
            "NVMe",
            "Network",
            "RDMA",
            "Kernel / OS",
            "Config"
        ]
    );
    for s in j["sections"].as_array().unwrap() {
        assert_eq!(keys(s), ["checks", "name"]);
        for c in s["checks"].as_array().unwrap() {
            assert_eq!(keys(c), ["fix", "id", "status", "title", "value", "why"]);
            assert!(["OK", "WARN", "FAIL", "N/A"].contains(&c["status"].as_str().unwrap()));
            assert!(c["fix"].is_null() || c["fix"].is_string());
        }
    }
    for t in j["tiers"].as_array().unwrap() {
        assert_eq!(keys(t), ["detail", "name", "usable"]);
    }
    let tn: Vec<&str> = j["tiers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(tn, ["kernel TCP", "SPDK", "kernel NVMe"]);
    // output formats parse back
    for f in [Format::Json, Format::JsonPretty] {
        let one: serde_json::Value = serde_json::from_str(&render(&rep, f, false)).unwrap();
        assert_eq!(one, j);
    }
    let plain = render(&rep, Format::Plain, false);
    assert!(!plain.contains('\x1b') && plain.contains("== Summary =="));
}

#[test]
fn cli_format_flag_is_the_shared_one() {
    let a = |v: &[&str]| -> Vec<String> { v.iter().map(|s| s.to_string()).collect() };
    for bad in [
        &["--json"][..],
        &["--format", "jsonl"],
        &["--format", "xml"],
        &["--format"],
        // value-less flags: an inline value is a usage error, not silently swallowed
        &["--no-color=bogus"],
        &["--help=x"],
    ] {
        assert_eq!(hwcheck::cli(&a(bad), "t"), 2, "{bad:?}");
    }
}

/// doc/ops/hwcheck.md: `fix` is null unless the check is WARN or FAIL.
#[test]
fn fix_text_only_on_warn_and_fail() {
    let r = Root::new("fix-null");
    host(&r);
    nvme(
        &r,
        "0000:03:00.0",
        "nvme",
        "write through",
        "4096",
        "16.0 GT/s PCIe",
    );
    nic(&r, "eth0", "mlx5_core", 8);
    let j = run(&r.opts()).to_json();
    for s in j["sections"].as_array().unwrap() {
        for c in s["checks"].as_array().unwrap() {
            let st = c["status"].as_str().unwrap();
            assert!(
                c["fix"].is_null() || st == "WARN" || st == "FAIL",
                "{} carries a fix on {st}: {}",
                c["id"],
                c["fix"]
            );
        }
    }
}

#[test]
fn empty_root_degrades() {
    let r = Root::new("empty");
    let rep = run(&r.opts());
    assert_eq!(rep.exit_code(), 0);
    assert_eq!(rep.count(Status::Fail), 0);
    assert!(Path::new(&rep.root).exists());
}

#[test]
fn nic_irqs_warn_only_when_concentrated() {
    let r = Root::new("irq");
    host(&r);
    nic(&r, "eth0", "bnxt_en", 2);
    r.w("etc/ceph/ceph.conf", "[osd.0]\nflashstore_lcores = 2-5\n");
    r.w(
        "proc/interrupts",
        "           CPU0       CPU1\n 40:          1          0  PCI-MSIX-0000:41:00.0   0-edge      eth0-TxRx-0\n 41:          0          1  PCI-MSIX-0000:41:00.0   1-edge      eth0-TxRx-1\n",
    );
    r.w("proc/irq/40/smp_affinity_list", "0-15");
    r.w("proc/irq/40/effective_affinity_list", "0");
    r.w("proc/irq/41/effective_affinity_list", "1");
    // 2 queues on 2 of 16 NIC-local cpus: concentrated, with the ethtool -L hint
    let (s, v) = status(&run(&r.opts()), "net.eth0.irq");
    assert_eq!(s, Status::Warn, "{v}");
    assert!(v.contains("concentrated"), "{v}");
    // one queue per NIC-local cpu, the IRQs on OSD cores: no warning
    r.w("sys/devices/system/cpu/online", "2-3");
    r.w("proc/irq/40/effective_affinity_list", "2");
    r.w("proc/irq/41/effective_affinity_list", "3");
    let (s, v) = status(&run(&r.opts()), "net.eth0.irq");
    assert_eq!(s, Status::Ok, "IRQs on OSD cores are fine: {v}");
}

fn rdma_dev(r: &Root, d: &str, n: &str, mtu: &str, gids: &[(&str, &str)]) {
    let b = format!("sys/class/infiniband/{d}");
    r.w(&format!("{b}/fw_ver"), "12.28.2006");
    r.w(&format!("{b}/ports/1/state"), "4: ACTIVE");
    r.w(&format!("{b}/ports/1/link_layer"), "Ethernet");
    r.d(&format!("{b}/device/net/{n}"));
    r.w(&format!("{b}/device/current_link_speed"), "8.0 GT/s PCIe");
    r.w(&format!("{b}/device/max_link_speed"), "8.0 GT/s PCIe");
    r.w(&format!("{b}/device/current_link_width"), "8");
    r.w(&format!("{b}/device/max_link_width"), "16");
    for (i, (g, ty)) in gids.iter().enumerate() {
        r.w(&format!("{b}/ports/1/gids/{i}"), g);
        r.w(&format!("{b}/ports/1/gid_attrs/types/{i}"), ty);
        r.w(&format!("{b}/ports/1/gid_attrs/ndevs/{i}"), n);
    }
    r.w(&format!("sys/class/net/{n}/mtu"), mtu);
}

#[test]
fn rdma_section() {
    let r = Root::new("rdma");
    host(&r);
    assert_eq!(status(&run(&r.opts()), "rdma.present").0, Status::Na);
    let ll = "fe80:0000:0000:0000:e61d:2dff:fe66:d806";
    let v4 = "0000:0000:0000:0000:0000:ffff:ac1c:002f";
    rdma_dev(
        &r,
        "mlx5_0",
        "eth1",
        "1500",
        &[(ll, "RoCE v2"), (v4, "IB/RoCE v1"), (v4, "RoCE v2")],
    );
    let rep = run(&r.opts());
    assert_eq!(status(&rep, "rdma.mlx5_0.1.port").0, Status::Ok);
    let (s, v) = status(&rep, "rdma.mlx5_0.1.gid");
    assert_eq!((s, v.as_str()), (Status::Ok, "172.28.0.47 on eth1"));
    let (s, v) = status(&rep, "rdma.mlx5_0.1.eth1.mtu");
    assert_eq!(
        (s, v.as_str()),
        (Status::Warn, "netdev mtu 1500 (RoCE path MTU 1024)"),
        "1500 works: warn, jumbo recommended"
    );
    r.w("sys/class/net/eth1/mtu", "1100");
    let (s, v) = status(&run(&r.opts()), "rdma.mlx5_0.1.eth1.mtu");
    assert_eq!(
        (s, v.as_str()),
        (Status::Warn, "netdev mtu 1100"),
        "below path MTU 1024: RDMA off"
    );
    r.w("sys/class/net/eth1/mtu", "1500");
    assert_eq!(status(&rep, "rdma.mlx5_0.1.eth1.dcqcn").0, Status::Na);
    assert_eq!(
        status(&rep, "rdma.mlx5_0.1.pcie").0,
        Status::Warn,
        "x8 of x16"
    );
    assert_eq!(rep.exit_code(), 0, "RDMA is optional: never FAIL");
    r.w("sys/class/net/eth1/mtu", "4192");
    r.w("sys/class/net/eth1/ecn/roce_np/enable/3", "1");
    r.w("sys/class/net/eth1/ecn/roce_rp/enable/3", "1");
    let rep = run(&r.opts());
    assert_eq!(status(&rep, "rdma.mlx5_0.1.eth1.mtu").0, Status::Ok);
    assert_eq!(status(&rep, "rdma.mlx5_0.1.eth1.dcqcn").0, Status::Ok);
    // DCQCN on another priority than RoCE's: without readable DCB (fixture) any enabled priority counts
    r.w("sys/class/net/eth1/ecn/roce_rp/enable/3", "0");
    r.w("sys/class/net/eth1/ecn/roce_rp/enable/0", "1");
    assert_eq!(
        status(&run(&r.opts()), "rdma.mlx5_0.1.eth1.dcqcn").0,
        Status::Ok
    );
    r.w("sys/class/net/eth1/ecn/roce_rp/enable/0", "0");
    assert_eq!(
        status(&run(&r.opts()), "rdma.mlx5_0.1.eth1.dcqcn").0,
        Status::Warn
    );
    // recorded RoCE loss: no counters = N/A, none = OK, drops without ECN marks = WARN with the lossless-class fix
    assert_eq!(status(&rep, "rdma.mlx5_0.1.loss").0, Status::Na);
    let hc = "sys/class/infiniband/mlx5_0/ports/1/hw_counters";
    for (f, x) in [
        ("out_of_sequence", "0"),
        ("packet_seq_err", "0"),
        ("np_ecn_marked_roce_packets", "0"),
        ("np_cnp_sent", "0"),
        ("rp_cnp_handled", "0"),
    ] {
        r.w(&format!("{hc}/{f}"), x);
    }
    assert_eq!(status(&run(&r.opts()), "rdma.mlx5_0.1.loss").0, Status::Ok);
    r.w(&format!("{hc}/out_of_sequence"), "81147");
    r.w(&format!("{hc}/np_cnp_sent"), "74646");
    let rep = run(&r.opts());
    let (s, v) = status(&rep, "rdma.mlx5_0.1.loss");
    assert_eq!(s, Status::Warn, "{v}");
    assert!(
        v.contains("out-of-sequence 81147") && v.contains("no ECN mark"),
        "{v}"
    );
    assert_eq!(rep.exit_code(), 0, "RDMA is optional: never FAIL");
    // only link-local GIDs: no IP for the RDMA connection
    let r2 = Root::new("rdma-noip");
    rdma_dev(&r2, "mlx5_1", "eth2", "9000", &[(ll, "RoCE v2")]);
    assert_eq!(
        status(&run(&r2.opts()), "rdma.mlx5_1.1.gid").0,
        Status::Warn
    );
}
