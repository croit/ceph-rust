// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The running OSD's view of its data NICs (adr 0063 am. 1, adr 0166 am. 1): which CPUs take the NIC's queue IRQs (the
//! core placement avoids them), the NIC's NUMA node, and the one-line startup warnings for the network checks.
use crate::fs::Fs;
use crate::net::{irq_check, live_checks, nic_irqs};
use crate::{Check, Status};

/// Physical NICs behind `ifname`: itself when it has a PCI device, else the lower devices of a bond / VLAN / bridge.
fn physical(fs: &Fs, ifname: &str, depth: u32) -> Vec<String> {
    let b = format!("sys/class/net/{ifname}");
    if fs.exists(&format!("{b}/device")) {
        return vec![ifname.to_string()];
    }
    if depth == 0 {
        return Vec::new();
    }
    fs.list(&b)
        .iter()
        .filter_map(|e| e.strip_prefix("lower_"))
        .flat_map(|l| physical(fs, l, depth - 1))
        .collect()
}

/// Data NICs of the OSD.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NicInfo {
    pub nics: Vec<String>,
    /// CPUs that receive a queue IRQ of any of the NICs (effective affinity), sorted.
    pub irq_cpus: Vec<u32>,
    /// NUMA node of the first NIC that reports one.
    pub numa: Option<u32>,
}

pub(crate) fn nic_info_at(fs: &Fs, ifaces: &[String]) -> NicInfo {
    let mut nics: Vec<String> = ifaces.iter().flat_map(|i| physical(fs, i, 3)).collect();
    nics.sort();
    nics.dedup();
    let irqs = fs.read("proc/interrupts").unwrap_or_default();
    let mut info = NicInfo::default();
    for n in &nics {
        let pci = fs
            .link_name(&format!("sys/class/net/{n}/device"))
            .unwrap_or_default();
        info.irq_cpus.extend(nic_irqs(fs, &irqs, n, &pci).1);
        let node = fs.read(&format!("sys/class/net/{n}/device/numa_node"));
        info.numa = info
            .numa
            .or_else(|| node?.parse::<i64>().ok()?.try_into().ok());
    }
    info.irq_cpus.sort_unstable();
    info.irq_cpus.dedup();
    info.nics = nics;
    info
}

/// IRQ CPUs and NUMA node of the NICs behind the interfaces `ifaces` of this host.
pub fn nic_info(ifaces: &[String]) -> NicInfo {
    nic_info_at(&Fs::new(std::path::Path::new("/")), ifaces)
}

pub(crate) fn warnings_at(fs: &Fs, ifaces: &[String]) -> Vec<Check> {
    let info = nic_info_at(fs, ifaces);
    let irqs = fs.read("proc/interrupts").unwrap_or_default();
    let mut v = Vec::new();
    for n in &info.nics {
        let pci = fs
            .link_name(&format!("sys/class/net/{n}/device"))
            .unwrap_or_default();
        let drv = fs
            .link_name(&format!("sys/class/net/{n}/device/driver"))
            .unwrap_or_default();
        v.push(irq_check(fs, &irqs, n, &pci));
        if fs.live() {
            v.extend(live_checks(n, &drv));
        }
    }
    v.retain(|c| c.status == Status::Warn);
    v
}

/// One line per RDMA fabric WARN (lossy RoCE class, recorded RoCE drops without ECN marks) of the RDMA devices behind
/// `ifaces`, with the fix; an OSD with RDMA on logs them once at start. `tos` = the RoCE TOS of its QPs.
pub fn rdma_startup_warnings(ifaces: &[String], tos: u8) -> Vec<String> {
    let fs = Fs::new(std::path::Path::new("/"));
    let nics = nic_info_at(&fs, ifaces).nics;
    lines(crate::rdma::fabric_checks(&fs, &nics, tos))
}

fn lines(mut v: Vec<Check>) -> Vec<String> {
    v.retain(|c| c.status == Status::Warn);
    v.iter()
        .map(|c| {
            format!(
                "{}: {}; fix: {}",
                c.title,
                c.value,
                c.fix.as_deref().unwrap_or("-")
            )
        })
        .collect()
}

/// One line per suboptimal network check (IRQ placement, offloads, rings) of the NICs behind `ifaces`, with the exact
/// fix; the OSD logs them once at start. The OSD never changes NIC settings.
pub fn startup_warnings(ifaces: &[String]) -> Vec<String> {
    lines(warnings_at(&Fs::new(std::path::Path::new("/")), ifaces))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    struct Root(PathBuf);
    impl Root {
        fn new(tag: &str) -> Root {
            let p =
                std::env::temp_dir().join(format!("hwcheck-start-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Root(p)
        }
        fn w(&self, rel: &str, s: &str) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, s).unwrap();
        }
        fn link(&self, rel: &str, target: &str) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(target, p).unwrap();
        }
        fn fs(&self) -> Fs {
            Fs::new(Path::new(&self.0))
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// eth0 (pci 0000:41:00.0, node 1, 2 queue IRQs), bond0 over eth0, vlan on bond0.
    fn host(r: &Root) {
        r.w("sys/class/net/eth0/device/numa_node", "1\n");
        r.link(
            "sys/class/net/eth0/device/driver",
            "../../../../bus/pci/drivers/bnxt_en",
        );
        r.link("sys/class/net/bond0/lower_eth0", "../eth0");
        r.link("sys/class/net/bond0.5/lower_bond0", "../bond0");
        r.w(
            "proc/interrupts",
            " 40:  1  0  PCI-MSIX-0000:41:00.0  0-edge  eth0-TxRx-0\n 41:  0  1  PCI-MSIX-0000:41:00.0  1-edge  eth0-TxRx-1\n 50:  5  5  IO-APIC  eth1-other\n",
        );
        r.w("proc/irq/40/effective_affinity_list", "0\n");
        r.w("proc/irq/41/effective_affinity_list", "8\n");
    }

    #[test]
    fn irq_cpus_and_node_through_bond_and_vlan() {
        let r = Root::new("info");
        host(&r);
        for i in ["eth0", "bond0", "bond0.5"] {
            let n = nic_info_at(&r.fs(), &[i.to_string()]);
            assert_eq!(n.nics, vec!["eth0".to_string()], "{i}");
            assert_eq!(n.irq_cpus, vec![0, 8], "{i}");
            assert_eq!(n.numa, Some(1), "{i}");
        }
        // unknown interface / lo: nothing to avoid
        assert_eq!(
            nic_info_at(&r.fs(), &["nope".to_string()]),
            NicInfo::default()
        );
        // kernel without effective affinity: the requested mask
        std::fs::remove_file(r.0.join("proc/irq/41/effective_affinity_list")).unwrap();
        r.w("proc/irq/41/smp_affinity_list", "4-5\n");
        assert_eq!(
            nic_info_at(&r.fs(), &["eth0".to_string()]).irq_cpus,
            vec![0, 4, 5]
        );
        // numa_node -1 = unknown
        r.w("sys/class/net/eth0/device/numa_node", "-1\n");
        assert_eq!(nic_info_at(&r.fs(), &["eth0".to_string()]).numa, None);
    }

    #[test]
    fn warning_only_when_irqs_are_concentrated() {
        let r = Root::new("warn");
        host(&r);
        let ifs = ["bond0".to_string()];
        // 2 queues, node 1 has 16 cpus: concentrated, fix = spread + more queues
        r.w("sys/devices/system/node/node1/cpulist", "0-15\n");
        let w = warnings_at(&r.fs(), &ifs);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].id, "net.eth0.irq");
        assert!(w[0].value.contains("concentrated"), "{}", w[0].value);
        // one queue per NIC-local cpu: no warning, whichever cpus are OSD cores
        r.w("sys/devices/system/node/node1/cpulist", "0-1\n");
        r.w("proc/irq/41/effective_affinity_list", "1\n");
        let w = warnings_at(&r.fs(), &ifs);
        assert!(w.is_empty(), "{w:?}");
    }
}
