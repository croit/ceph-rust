// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! croit-flashstore-osd OSD daemon entry point.
//!
//! Network (adr 0053): kernel TCP through io_uring (feature `knet`, Linux), any NIC, optionally upgraded to RDMA; see
//! `kprod.rs`.
//!
//! `croit-flashstore-osd kernel-probe ...` (feature `kernel-probe`, Linux): dev-only std::net driver (ADR 0015 amendment).

#[cfg(all(
    feature = "mimalloc",
    not(feature = "spdk"),
    not(feature = "heapprof"),
    not(feature = "viewguard")
))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

// LAB ONLY (adr 0024): every free is checked against the memory of live zero-copy write views (fail-stop with the
// freeing stack, `nvme::viewguard`).
#[cfg(all(
    feature = "mimalloc",
    not(feature = "spdk"),
    not(feature = "heapprof"),
    feature = "viewguard"
))]
#[global_allocator]
static ALLOC: nvme::viewguard::GuardAlloc<mimalloc::MiMalloc> =
    nvme::viewguard::GuardAlloc(mimalloc::MiMalloc);

// LAB ONLY (adr 0024): heap profile around mimalloc (or the system allocator without `mimalloc`), doc/perf/osd-rss-growth-20261029.md.
#[cfg(feature = "heapprof")]
#[global_allocator]
static ALLOC: heapprof::Prof = heapprof::Prof;

#[cfg(all(feature = "heapprof", not(target_os = "linux")))]
compile_error!(
    "feature heapprof: Linux kernel-tier builds only (lab/build-host-build.sh profiles heapprof / heapsys)"
);

// SPDK builds: small allocations in mimalloc, payload-sized ones (>= 128 KiB) in DPDK hugepage memory once the EAL is up
// (`kprod.rs`), so heap payloads can be DMA-mapped and RDMA-registered without a copy (adr 0061 am. 4, adr 0076).
#[cfg(all(feature = "mimalloc", feature = "spdk", not(feature = "heapprof")))]
#[global_allocator]
static ALLOC: eal_heap::HugeAlloc<mimalloc::MiMalloc> = eal_heap::HugeAlloc(mimalloc::MiMalloc);

#[cfg(all(feature = "spdk", not(feature = "mimalloc"), not(feature = "heapprof")))]
#[global_allocator]
static ALLOC: eal_heap::HugeAlloc<std::alloc::System> = eal_heap::HugeAlloc(std::alloc::System);

#[cfg(all(target_os = "linux", any(feature = "kernel-probe", feature = "knet")))]
mod addr;
#[cfg(all(feature = "knet", target_os = "linux"))]
mod args;
#[cfg(all(feature = "kernel-probe", target_os = "linux"))]
mod dev;
#[cfg(all(
    feature = "knet",
    target_os = "linux",
    any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
))]
mod devmeta;
#[cfg(any(
    test,
    all(
        target_os = "linux",
        feature = "spdk",
        feature = "kernel-nvme",
        feature = "knet"
    )
))]
mod ealargs;
#[cfg(feature = "heapprof")]
mod heapprof;
#[cfg(all(feature = "knet", target_os = "linux"))]
mod kprod;
#[cfg(any(
    all(feature = "kernel-probe", target_os = "linux"),
    all(feature = "knet", target_os = "linux"),
    test
))]
mod logsink;
#[cfg(all(
    feature = "knet",
    target_os = "linux",
    any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
))]
mod mcommon;
#[cfg(any(
    all(feature = "kernel-probe", target_os = "linux"),
    all(feature = "knet", target_os = "linux")
))]
mod obs;
#[cfg(all(feature = "knet", target_os = "linux"))]
mod privdrop;
#[cfg(all(feature = "knet", target_os = "linux"))]
mod run;
#[cfg(all(feature = "knet", target_os = "linux"))]
mod sdnotify;
#[cfg(all(
    feature = "knet",
    target_os = "linux",
    any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
))]
mod smartctl;
#[cfg(feature = "spdk-mp")]
mod spdkprimary;

/// Start the daemon with the flag vector `full` (argv[0] first).
#[cfg(all(feature = "knet", target_os = "linux"))]
pub(crate) fn daemon(full: Vec<String>) -> i32 {
    for f in run::unknown_flags(&full[1..]) {
        eprintln!(
            "croit-flashstore-osd: WARN unknown flag {f} ignored (a conf key flashstore_<key> becomes --<key>; store tunables flashstore_store_* go via --set)"
        );
    }
    let rdma = match args::rdma_enabled(&full) {
        Ok(v) => v,
        Err(e) => return args::die(2, e),
    };
    if let Some(why) = args::rdma_refusal(rdma, cfg!(feature = "rdma")) {
        return args::die(2, why);
    }
    let placement = match args::placement_lab_enabled(&full, rdma) {
        Ok(value) => value,
        Err(error) => return args::die(2, error),
    };
    let source_pull = match args::source_pull_lab_enabled(&full, rdma) {
        Ok(value) => value,
        Err(error) => return args::die(2, error),
    };
    #[cfg(not(all(feature = "knet", target_os = "linux")))]
    let _ = (placement, source_pull);
    // classic `--setuser`/`--setgroup` (spec osd-lifecycle.md 3.1a): before the store, sockets and files are opened
    if let Err(e) = privdrop::apply(&full) {
        return args::die(1, e);
    }
    // classic writes its pid file right after the privilege drop and fails the start when it cannot
    let _pid_file = match args::PidFile::create(&full) {
        Ok(p) => p,
        Err(e) => return args::die(1, e),
    };
    kprod::main_with(full, placement, source_pull)
}

fn main() {
    // `--opt=value` == `--opt value` everywhere: one split before any option lookup
    let argv = outfmt::normalize_args(&std::env::args().collect::<Vec<_>>());
    #[cfg(all(feature = "knet", target_os = "linux"))]
    {
        // no native core may hold keys or client data (adr 0035 am. 4): before anything is read
        if let Err(e) = privdrop::disable_core_dumps() {
            eprintln!("croit-flashstore-osd: {e}");
            std::process::exit(1);
        }
        // crash reports from the first instruction on, refined once config and identity are known
        osd::crash::install(args::early_crash_cfg(&argv));
    }
    #[cfg(feature = "heapprof")]
    heapprof::start();
    // operator override, ADR 0021 am. 9: mount a store whose acked WAL txns were lost to media corruption (DATA LOSS)
    if argv.iter().any(|a| a == "--accept-wal-loss") {
        store::wal::set_accept_wal_loss(true);
        eprintln!(
            "croit-flashstore-osd: --accept-wal-loss: a corrupt WAL will be cut at the damage, acked txns are LOST"
        );
    }
    let a1 = argv.get(1).cloned();
    // read-only host/hardware check (adr 0166): no cluster, no device binding, no state change
    if matches!(a1.as_deref(), Some("--check" | "check")) {
        let a: Vec<String> = argv[2..].to_vec();
        let id = format!(
            "{} git {}",
            osd::version::identity_line(),
            env!("FLASHSTORE_GIT")
        );
        std::process::exit(hwcheck::cli(&a, &id));
    }
    if matches!(a1.as_deref(), Some("version" | "--version" | "--net-caps")) {
        println!(
            "{} git {}",
            osd::version::identity_line(),
            env!("FLASHSTORE_GIT")
        );
        println!("net tiers: {}", net_tiers());
        return;
    }
    eprintln!(
        "{} git {} (net tiers: {})",
        osd::version::identity_line(),
        env!("FLASHSTORE_GIT"),
        net_tiers()
    );
    #[cfg(all(feature = "knet", target_os = "linux"))]
    if a1.as_deref() == Some("run") {
        let a: Vec<String> = argv[2..].to_vec();
        std::process::exit(run::main(&a));
    }
    #[cfg(feature = "spdk-mp")]
    if a1.as_deref() == Some("spdk-primary") {
        let a: Vec<String> = argv[2..].to_vec();
        std::process::exit(spdkprimary::main(&a));
    }
    #[cfg(all(feature = "kernel-probe", target_os = "linux"))]
    if a1.as_deref() == Some("kernel-probe") {
        std::process::exit(dev::main());
    }
    #[cfg(all(feature = "kernel-probe", not(target_os = "linux")))]
    if a1.as_deref() == Some("kernel-probe") {
        eprintln!(
            "croit-flashstore-osd: kernel-probe is a Linux dev driver (feature kernel-probe)"
        );
        std::process::exit(2);
    }
    #[cfg(all(feature = "knet", target_os = "linux"))]
    std::process::exit(daemon(argv));
    #[cfg(not(all(feature = "knet", target_os = "linux")))]
    {
        eprintln!(
            "no production driver compiled in (--features knet); dev driver: --features kernel-probe, `croit-flashstore-osd kernel-probe ...`"
        );
        std::process::exit(2);
    }
}

/// Compiled network paths, for `--version` / `--net-caps` and the startup line.
fn net_tiers() -> String {
    let mut v: Vec<String> = Vec::new();
    #[cfg(all(feature = "knet", target_os = "linux"))]
    v.push(
        if cfg!(feature = "rdma") {
            "kernel (+rdma upgrade)"
        } else {
            "kernel"
        }
        .into(),
    );
    if v.is_empty() {
        v.push("none".into());
    }
    v.join("; ")
}
