// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Tier verdicts and "top 3 fixes" from the collected checks.
use crate::{Facts, Section, Status, Tier};

fn find<'a>(s: &'a [Section], id: &str) -> Option<&'a crate::Check> {
    s.iter().flat_map(|x| &x.checks).find(|c| c.id == id)
}

fn compiled(s: &[Section], id: &str) -> bool {
    find(s, id).is_some_and(|c| c.status == Status::Ok)
}

pub fn tiers(s: &[Section], f: &Facts) -> Vec<Tier> {
    let mut t = Vec::new();
    let hp = f.hugepages_free_mb > 0;
    let userspace_bind = f.vfio || f.uio;

    // kernel TCP
    let (usable, detail) = match (&f.knet_probe, compiled(s, "build.knet")) {
        (_, false) => (false, "build lacks knet".to_string()),
        (Some(Ok(())), _) => (true, "io_uring multishot capability test passed".into()),
        (Some(Err(e)), _) => (false, format!("io_uring: {e}")),
        (None, _) => (false, "io_uring not probed (not a live host)".into()),
    };
    t.push(Tier {
        name: "kernel TCP",
        usable,
        detail,
    });

    // SPDK
    let mut why = Vec::new();
    if !compiled(s, "build.spdk") {
        why.push("build lacks spdk".to_string());
    }
    if f.nvme_total == 0 {
        why.push("no NVMe controller".into());
    }
    if !hp {
        why.push("no free hugepages".into());
    }
    if !userspace_bind {
        why.push("no vfio/uio_pci_generic".into());
    }
    let mode = if f.vfio && f.iommu_groups > 0 {
        "vfio-pci (production)"
    } else {
        "uio_pci_generic, IOVA=PA (lab fallback only)"
    };
    t.push(Tier {
        name: "SPDK",
        usable: why.is_empty(),
        detail: if why.is_empty() {
            mode.to_string()
        } else {
            why.join("; ")
        },
    });

    // kernel NVMe
    t.push(Tier {
        name: "kernel NVMe",
        usable: f.nvme_kernel > 0 && cfg!(feature = "lab"),
        detail: if f.nvme_kernel == 0 {
            "no controller on the kernel nvme driver".into()
        } else if cfg!(feature = "lab") {
            format!(
                "{} controller(s); dev/lab tier (file:/dev/nvmeXnY, adr 0024)",
                f.nvme_kernel
            )
        } else {
            "dev/lab tier, compiled out of this build (adr 0024)".into()
        },
    });
    t
}

/// Up to three WARN/FAIL checks with a fix, FAIL first, then by performance weight.
pub fn top_fixes(s: &[Section]) -> Vec<(String, String)> {
    let mut v: Vec<&crate::Check> = s
        .iter()
        .flat_map(|x| &x.checks)
        .filter(|c| c.status >= Status::Warn && c.fix.is_some())
        .collect();
    v.sort_by_key(|c| std::cmp::Reverse((c.status == Status::Fail, c.weight)));
    let mut out: Vec<(String, String)> = Vec::new();
    for c in v {
        let fx = c.fix.clone().unwrap_or_default();
        if out.iter().all(|(_, f)| *f != fx) {
            out.push((c.id.clone(), fx));
        }
        if out.len() == 3 {
            break;
        }
    }
    out
}
