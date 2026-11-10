// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Compiled-in tiers/features of this binary (a tier compiled out is N/A with the reason).
use crate::{Check, Section};

fn feat(id: &str, title: &str, on: bool, why: &str, how: &str) -> Check {
    let c = Check::new(format!("build.{id}"), title).why(why);
    if on {
        c.val("compiled in").ok()
    } else {
        c.val(format!("compiled out ({how})")).na()
    }
}

pub fn section(build_id: &str) -> Section {
    let mut v = vec![
        Check::new("build.version", "binary")
            .val(if build_id.is_empty() {
                "unknown"
            } else {
                build_id
            })
            .why("which build this report describes (the checks of tiers not compiled in are N/A)")
            .ok(),
        feat(
            "knet",
            "kernel TCP tier (io_uring)",
            cfg!(all(feature = "knet", target_os = "linux")),
            "any NIC (adr 0053)",
            "build --features knet on Linux",
        ),
        feat(
            "spdk",
            "SPDK NVMe driver",
            cfg!(feature = "spdk"),
            "userspace NVMe (adr 0004): production store path",
            "build --features spdk",
        ),
        feat(
            "mimalloc",
            "mimalloc allocator",
            cfg!(feature = "mimalloc"),
            "small-object allocation cost on the non-hot path",
            "build --features mimalloc",
        ),
        feat(
            "elastic",
            "elastic shard capacity",
            cfg!(feature = "elastic"),
            "chunked store + shared pool (adr 0021 am. 55)",
            "build with default features",
        ),
        Check::new("build.codecs", "compression codecs")
            .val("lz4, zstd (always linked)")
            .why("payload codecs of the store/objclass paths; no feature switch")
            .ok(),
    ];
    let lab = Check::new("build.lab", "lab/dev backends").why("file:/DevMemStore backends are DEV/LAB ONLY (adr 0024) and must not be in a production build");
    v.push(if cfg!(feature = "lab") {
        lab.val("compiled in")
            .warn()
            .fix("deploy the prod build (lab/build-remote.sh prod), not the lab one")
    } else {
        lab.val("compiled out").ok()
    });
    Section {
        name: "Build",
        checks: v,
    }
}
