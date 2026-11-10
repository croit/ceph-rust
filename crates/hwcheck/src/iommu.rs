// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! IOMMU / VFIO / UIO: which userspace-driver modes this host allows (adr 0004, 0056, 0165).
use crate::action::{Action, Step};
use crate::fs::Fs;
use crate::{Check, Facts, Section};

/// Kernel module present as loaded (`/sys/module/<m>`, always spelled with `_`) or as a file under /lib/modules/<rel>.
fn module_state(fs: &Fs, name: &str) -> &'static str {
    let fname = name.replace('-', "_");
    if fs.exists(&format!("sys/module/{fname}")) {
        return "loaded";
    }
    let rel = fs.read("proc/sys/kernel/osrelease").unwrap_or_default();
    // search the usual drivers/ trees (shallow, bounded)
    fn walk(fs: &Fs, dir: &str, fname: &str, depth: u8) -> bool {
        for e in fs.list(dir) {
            let p = format!("{dir}/{e}");
            let stem = e
                .trim_end_matches(".zst")
                .trim_end_matches(".xz")
                .trim_end_matches(".gz")
                .trim_end_matches(".ko")
                .replace('-', "_");
            if stem == fname && e.contains(".ko") {
                return true;
            }
            if depth > 0 && fs.p(&p).is_dir() && walk(fs, &p, fname, depth - 1) {
                return true;
            }
        }
        false
    }
    if !rel.is_empty() && walk(fs, &format!("lib/modules/{rel}/kernel/drivers"), &fname, 3) {
        "available (not loaded)"
    } else {
        "absent"
    }
}

pub fn section(fs: &Fs, facts: &mut Facts) -> Section {
    let mut v = Vec::new();
    if !fs.has_sys() {
        v.push(
            Check::new("iommu.groups", "IOMMU / VFIO")
                .val("not available (no sysfs)")
                .why("vfio-pci/uio and the IOMMU decide the userspace NVMe/NIC modes")
                .na(),
        );
        return Section {
            name: "IOMMU / VFIO",
            checks: v,
        };
    }
    let groups = fs.list("sys/kernel/iommu_groups").len();
    facts.iommu_groups = groups;
    let cmd = fs.cmdline();
    let iommu_arg: Vec<&String> = cmd
        .iter()
        .filter(|w| {
            w.starts_with("intel_iommu") || w.starts_with("amd_iommu") || w.starts_with("iommu")
        })
        .collect();
    let c = Check::new("iommu.groups", "IOMMU groups")
        .val(format!(
            "{groups} group(s); cmdline: {}",
            if iommu_arg.is_empty() { "no iommu option".to_string() } else { iommu_arg.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ") }
        ))
        .why("vfio-pci needs an IOMMU: DMA isolation, MSI-X interrupts for SPDK interrupt mode (adr 0165), non-root operation (adr 0056); without it only uio_pci_generic (lab, root)")
        .w(8);
    v.push(if groups > 0 {
        c.ok()
    } else {
        c.warn().fix("BIOS: enable VT-d (Intel) / AMD-Vi (SVM + IOMMU); kernel cmdline `intel_iommu=on iommu=pt` (AMD: `amd_iommu=on iommu=pt`); in a VM: add a virtual IOMMU")
    });
    let pt = iommu_arg.iter().any(|w| w.as_str() == "iommu=pt");
    v.push(if groups > 0 {
        Check::new("iommu.passthrough", "IOMMU passthrough mode")
            .val(if pt { "iommu=pt" } else { "translated (default)" })
            .why("kernel-driver devices (mlx5, kernel NVMe, kernel TCP tier) pay IOMMU translation per DMA unless iommu=pt; vfio-pci devices are isolated either way")
            .warn_if(!pt)
            .fix("kernel cmdline `iommu=pt`")
            .w(4)
    } else {
        Check::new("iommu.passthrough", "IOMMU passthrough mode").val("no IOMMU").why("only relevant with an active IOMMU").na()
    });
    let vf = module_state(fs, "vfio-pci");
    let dev = fs.exists("dev/vfio/vfio");
    facts.vfio = (vf != "absent") && groups > 0;
    let c = Check::new("iommu.vfio", "vfio-pci")
        .val(format!("module {vf}; /dev/vfio/vfio {}", if dev { "present" } else { "absent" }))
        .why("production driver for NVMe (adr 0004/0034): works under Secure Boot, DMA isolation, MSI-X, non-root")
        .w(6);
    v.push(if vf == "absent" {
        c.warn().fix("install/enable a kernel with CONFIG_VFIO_PCI (distribution kernels ship it); then `modprobe vfio-pci`")
    } else if vf.starts_with("available") {
        c.warn().act(Action::new(vec![Step::Module { name: "vfio-pci".into() }]).note("croit-flashstore-prep does this too"))
    } else {
        c.ok()
    });
    let noiommu = fs.read("sys/module/vfio/parameters/enable_unsafe_noiommu_mode");
    v.push(
        Check::new("iommu.noiommu", "vfio no-IOMMU mode")
            .val(match noiommu.as_deref() {
                Some("Y") | Some("1") => "enabled (unsafe)",
                Some(_) => "supported, off",
                None => "not available",
            })
            .why("lets vfio-pci run without an IOMMU (VMs without vIOMMU): no DMA isolation, no MSI-X eventfds; lab only")
            .ok(),
    );
    let uio_state = module_state(fs, "uio_pci_generic");
    facts.uio = uio_state != "absent";
    v.push(
        Check::new("iommu.uio", "uio_pci_generic")
            .val(uio_state)
            .why("lab fallback when no IOMMU (IOVA=PA, root, one INTx line: no SPDK interrupt mode); not for production")
            .ok(),
    );
    let irq = facts.vfio;
    v.push(
        Check::new("iommu.irq_mode", "NVMe interrupt mode (adr 0165)")
            .val(if irq { "possible (VFIO MSI-X)" } else { "not possible" })
            .why("sleeping through device waits needs one MSI-X vector + eventfd per qpair, i.e. VFIO; evaluated/deferred in adr 0165 (poll mode is the shipped default)")
            .st(if irq { crate::Status::Ok } else { crate::Status::Na }),
    );
    Section {
        name: "IOMMU / VFIO",
        checks: v,
    }
}
