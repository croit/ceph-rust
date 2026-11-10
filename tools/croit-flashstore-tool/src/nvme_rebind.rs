// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `croit-flashstore-tool nvme-rebind --pci BDF --driver vfio-pci|uio_pci_generic [--dry-run]`: exclusive admission and
//! rebind of one NVMe function for the SPDK tier (caller: `croit-flashstore-prep@`). Every refusal names the exact
//! reason (mounted, holders, swap, exclusive or locked owner, not an NVMe controller); the claims are held through the
//! unbind (`nvme::pcibind`). `--dry-run`: admission only, nothing written.
//! Exit: 0 bound (or already), 3 refused (in use / not eligible; nothing changed), 1 rebind failed, 2 usage.
use crate::{arg, flag};
use outfmt::Format;
use serde_json::json;

pub fn run(a: &[String], f: Format) -> i32 {
    let (Some(pci), Some(driver)) = (arg(a, "--pci"), arg(a, "--driver")) else {
        return crate::usage_err(
            "usage: croit-flashstore-tool nvme-rebind --pci BDF --driver vfio-pci|uio_pci_generic [--dry-run]",
        );
    };
    match nvme::pcibind::rebind(&Default::default(), &pci, &driver, flag(a, "--dry-run")) {
        Ok(r) => {
            let v = json!({"pci": r.pci, "driver": r.driver, "from": r.from, "action": r.action, "claimed": r.claimed});
            if f.is_json() {
                println!("{}", f.doc(&v));
            } else {
                println!(
                    "nvme {}: {} -> {}: {} (held exclusively: {})",
                    r.pci,
                    r.from.as_deref().unwrap_or("unbound"),
                    r.driver,
                    r.action,
                    if r.claimed.is_empty() {
                        "-".into()
                    } else {
                        r.claimed.join(" ")
                    }
                );
            }
            0
        }
        Err(nvme::pcibind::Error::Refused(m)) => {
            eprintln!("croit-flashstore-tool: nvme-rebind: refused: {m}");
            3
        }
        Err(nvme::pcibind::Error::Failed(m)) => {
            eprintln!("croit-flashstore-tool: nvme-rebind: {m}");
            1
        }
    }
}
