// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! croit-flashstore-osd provisioning tool.
//!
//! Output: every subcommand takes `--format plain|json|json-pretty` (jsonl for `list`, `raw`, `upgrade`; objectstore = classic json|json-pretty;
//! mkfs, bench*, crash, dump, ecxor, b3sum are text only); shared parser: crates/outfmt, doc/ops/croit-flashstore-tool.md.
//!   croit-flashstore-tool hwcheck [--format plain|json|json-pretty] [--root DIR] [--conf FILE]   (read-only host check, adr 0166)
//!   croit-flashstore-tool host-tune [--check ID]... [--iface IF] [--apply] [--revert STATE] [--emit-persist]   (applies hwcheck's host fixes on request, adr 0465)
//!   croit-flashstore-tool mkfs --dev kernel:/dev/NODE | spdk:PCI[,ns=N] | file:PATH[,size=8G]   (file: = DEV/LAB ONLY)
//!                     [--store-shards auto|N (alias --shards; auto = --cores, default 8)] [--cores N] [--format-lba4k] [--wipe] [--no-discard] [--allow-vwc] [--conf F]
//!   croit-flashstore-tool mkfs --data DIR   (legacy dev directory store, DevMemStore PGs) [--mon-host ADDR] [--keyring bootstrap-osd.keyring]
//!                     [--entity client.bootstrap-osd] [--osd-uuid UUID] [--id N]
//!                     [--crush-device-class nvme] [--size BYTES]

#[cfg(all(feature = "mimalloc", not(feature = "alloc-count")))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "alloc-count")]
mod alloc_count;
mod asok;
mod budget;
#[cfg(feature = "alloc-count")]
#[global_allocator]
static ALLOC: alloc_count::Counting = alloc_count::Counting::new();

#[cfg(feature = "lab")]
mod bench;
#[cfg(feature = "lab")]
mod bench_fs;
#[cfg(feature = "lab")]
mod bench_full;
#[cfg(feature = "lab")]
mod bench_omapfill;
#[cfg(feature = "lab")]
mod bench_omapmix;
#[cfg(feature = "lab")]
mod bench_omaprm;
#[cfg(feature = "lab")]
mod bench_purge;
#[cfg(feature = "lab")]
mod bench_read;
#[cfg(feature = "lab")]
mod bench_scan;
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
mod devopen;
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
mod dump;
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
mod fsout;
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
mod lifecycle;
#[cfg(all(
    feature = "mon-std",
    any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
))]
mod mkfs;
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
mod objectstore;
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
mod ops;
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
mod raw;
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
mod support_bundle;
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
mod walinspect;

mod b3sum;
mod ecxor;
#[cfg(all(feature = "kernel-nvme", target_os = "linux"))]
mod nvme_rebind;

/// Value of `--key VALUE` (the first `key`), `None` when the flag is absent or last.
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
pub(crate) fn arg(a: &[String], k: &str) -> Option<String> {
    a.iter()
        .position(|x| x == k)
        .and_then(|i| a.get(i + 1).cloned())
}

/// Is the flag `k` present? (Same text search for every subcommand.)
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
pub(crate) fn flag(a: &[String], k: &str) -> bool {
    a.iter().any(|x| x == k)
}

/// Numeric option `k`, `None` when absent. A value that does not parse is an error: a typo must never silently become a
/// different measurement, region or store size.
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
pub(crate) fn num_opt(a: &[String], k: &str) -> Result<Option<u64>, String> {
    match arg(a, k) {
        None => Ok(None),
        Some(s) => s
            .parse()
            .map(Some)
            .map_err(|_| format!("{k}: not a number: {s:?}")),
    }
}

/// Numeric option `k`, `d` when absent (see [`num_opt`]).
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
pub(crate) fn num(a: &[String], k: &str, d: u64) -> Result<u64, String> {
    Ok(num_opt(a, k)?.unwrap_or(d))
}

/// A MiB-sized option value in bytes (checked: a value that does not fit is an error, not a wrapped offset or budget).
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
pub(crate) fn mib(k: &str, v: u64) -> Result<u64, String> {
    v.checked_mul(1 << 20)
        .ok_or_else(|| format!("{k} {v}: above {} MiB", u64::MAX >> 20))
}

/// [`num`] for a floating point option (`--secs`).
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
pub(crate) fn fnum(a: &[String], k: &str, d: f64) -> Result<f64, String> {
    match arg(a, k) {
        None => Ok(d),
        Some(s) => s
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite())
            .ok_or_else(|| format!("{k}: not a number: {s:?}")),
    }
}

/// Usage error of a store subcommand: message on stderr, exit 2.
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
pub(crate) fn usage_err(m: &str) -> i32 {
    eprintln!("croit-flashstore-tool: {m}");
    2
}

/// How a subcommand takes `--format` (outfmt): one document, a record stream (also `jsonl`), or text only.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Doc,
    Records,
    TextOnly,
}

/// `None`: the subcommand parses `--format` itself (`hwcheck` is shared with `croit-flashstore-osd --check`; `objectstore` keeps the
/// classic ceph-objectstore-tool `--format json|json-pretty` contract).
fn kind(cmd: &str) -> Option<Kind> {
    match cmd {
        "prepare" | "activate" | "inspect" | "asok" | "fsck" | "repair" | "sizes" | "expand"
        | "free" | "bench-scan" | "support-bundle" | "nvme-rebind" | "hugepage-budget" => {
            Some(Kind::Doc)
        }
        "list" | "raw" | "upgrade" | "wal-inspect" => Some(Kind::Records),
        "b3sum" | "ecxor" | "mkfs" | "bench" | "crash" | "bench-purge" | "bench-full"
        | "bench-read" | "dump" => Some(Kind::TextOnly),
        _ => None,
    }
}

/// The shared `--format` parse for the subcommand `a[1]`; returns the format and `a[2..]` without it.
fn take_format(a: &[String]) -> Result<(outfmt::Format, Vec<String>), String> {
    let Some(k) = a.get(1).and_then(|c| kind(c)) else {
        return Ok((
            outfmt::Format::Plain,
            a.get(2..).unwrap_or_default().to_vec(),
        ));
    };
    let (f, rest) = outfmt::extract(&a[2..], k == Kind::Records)?;
    if k == Kind::TextOnly && f != outfmt::Format::Plain {
        return Err(format!("{}: text output only (--format plain)", a[1]));
    }
    Ok((f, rest))
}

/// Usage of the subcommands this build has (doc/ops/croit-flashstore-tool.md has every option).
fn usage() -> String {
    let mut u = vec![
        "usage: croit-flashstore-tool hwcheck | host-tune | asok | b3sum | ecxor   [--format plain|json|json-pretty]",
        "       croit-flashstore-tool hugepage-budget --id N [--cluster C] [--conf F]   (MB the daemon reserves; read by croit-flashstore-prep)",
    ];
    #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
    u.extend([
        "       croit-flashstore-tool activate [--id N | --from-device (--dev SPEC | --all) [--keyring FILE] [--crush-device-class C]]   (from-device: OSD dir from the device superblock, read-only)",
        "       croit-flashstore-tool list [--osd-data-root DIR | --scan-devices]   (scan-devices: superblock of every /dev/nvme*n1, read-only)",
        "       croit-flashstore-tool inspect   [--format plain|json|json-pretty]",
        "       croit-flashstore-tool fsck [--deep] | repair [--deep] | sizes | expand | free [--extents] | upgrade [--omap-lsm] [--dry-run]",
        "                    (each: --dev SPEC | --id N | --data-path DIR; offline)",
        "       croit-flashstore-tool objectstore (--id N | --dev SPEC) --op ...   (offline PG export/import, doc/ops/objectstore-tool.md)",
        "       croit-flashstore-tool raw --dev SPEC [--bs ..] [--qd ..] [--write] [--rand]   (device line rate below the store)",
        "       croit-flashstore-tool dump --dev SPEC --out DIR   (read-only forensic copy of the store metadata)",
        "       croit-flashstore-tool support-bundle (--id N | --dev SPEC) --out DIR [--format F]   (read-only support bundle)",
        "       croit-flashstore-tool wal-inspect (--id N | --dev SPEC) [--shard N] [--preview-loss] [--format plain|json|json-pretty|jsonl]   (read-only WAL decode)",
    ]);
    #[cfg(all(
        feature = "mon-std",
        any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
    ))]
    u.extend([
        "       croit-flashstore-tool prepare --dev SPEC ...   (mkfs + mon registration)",
        "       croit-flashstore-tool mkfs (--dev SPEC | --data DIR) [--mon-host ADDR] [--keyring FILE] [--entity E] [--osd-uuid U] [--id N]",
    ]);
    #[cfg(all(feature = "kernel-nvme", target_os = "linux"))]
    u.push("       croit-flashstore-tool nvme-rebind --pci BDF --driver vfio-pci|uio_pci_generic [--dry-run]   (prep: exclusive admission + rebind to the SPDK driver)");
    #[cfg(feature = "lab")]
    u.push("       croit-flashstore-tool bench | bench-* | crash   (lab build only)");
    u.push("(doc/ops/croit-flashstore-tool.md)");
    u.push("OMAP engines: fresh prepare/mkfs --omap-engine btree|lsm|rocksdb; RocksDB requires --rocksdb-dir ABSOLUTE_ROOT and the rocksdb build feature. Offline tools require the same --rocksdb-dir.");
    u.join("\n")
}

/// `croit-flashstore-tool <crate version> git <source sha>`, the identity every log line and report carries.
fn version() -> String {
    format!(
        "croit-flashstore-tool {} git {}",
        env!("CARGO_PKG_VERSION"),
        env!("FLASHSTORE_GIT")
    )
}

fn main() {
    // `--opt=value` == `--opt value` for every subcommand: one split before any option lookup
    let a = outfmt::normalize_args(&std::env::args().collect::<Vec<_>>());
    if a.get(1).map(String::as_str) == Some("--version") {
        println!("{}", version());
        return;
    }
    #[cfg(feature = "kernel-nvme")]
    let a = match store_backend_args(a) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("croit-flashstore-tool: {e}");
            std::process::exit(2);
        }
    };
    let (f, r) = match take_format(&a) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("croit-flashstore-tool: {e}");
            std::process::exit(2);
        }
    };
    if let Some(i) = a.iter().position(|x| x == "--rocksdb-dir") {
        // a flag without its value is a usage error, never "option not given"
        let Some(v) = a.get(i + 1).cloned() else {
            eprintln!("croit-flashstore-tool: --rocksdb-dir needs a value (ABSOLUTE_ROOT)");
            std::process::exit(2);
        };
        #[cfg(feature = "rocksdb")]
        if let Err(e) = osd::nvmestore::set_store_options(&[("flashstore_rocksdb_dir".into(), v)]) {
            eprintln!("croit-flashstore-tool: {e}");
            std::process::exit(2);
        }
        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = v;
            eprintln!(
                "croit-flashstore-tool: --rocksdb-dir requires a build with --features rocksdb"
            );
            std::process::exit(2);
        }
    }
    match a.get(1).map(String::as_str) {
        Some("hwcheck") => {
            let id = version();
            std::process::exit(hwcheck::cli(&r, &id))
        }
        Some("host-tune") => std::process::exit(hwcheck::tune::cli(&r)),
        Some("b3sum") => std::process::exit(b3sum::run(&r)),
        Some("ecxor") => std::process::exit(ecxor::run(&r)),
        Some("asok") => std::process::exit(asok::run(&r, f)),
        Some("hugepage-budget") => std::process::exit(budget::run(&r, f)),
        #[cfg(all(feature = "kernel-nvme", target_os = "linux"))]
        Some("nvme-rebind") => std::process::exit(nvme_rebind::run(&r, f)),
        #[cfg(all(
            feature = "mon-std",
            any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
        ))]
        Some("prepare") => std::process::exit(lifecycle::prepare(&r, f)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("activate") => std::process::exit(lifecycle::activate(&r, f)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("list") => std::process::exit(lifecycle::list(&r, f)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("inspect") => std::process::exit(lifecycle::inspect(&r, f)),
        #[cfg(all(
            feature = "mon-std",
            any(feature = "lab", feature = "spdk", feature = "kernel-nvme")
        ))]
        Some("mkfs") => std::process::exit(mkfs::run(&r)),
        #[cfg(feature = "lab")]
        Some("bench") => std::process::exit(bench::bench(&r)),
        #[cfg(feature = "lab")]
        Some("crash") => std::process::exit(bench::crash(&r)),
        #[cfg(feature = "lab")]
        Some("bench-purge") => std::process::exit(bench_purge::run(&r)),
        #[cfg(feature = "lab")]
        Some("bench-full") => std::process::exit(bench_full::run(&r)),
        #[cfg(feature = "lab")]
        Some("bench-read") => std::process::exit(bench_read::run(&r)),
        #[cfg(feature = "lab")]
        Some("bench-scan") => std::process::exit(bench_scan::run(&r, f)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("dump") => std::process::exit(dump::run(&r)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("support-bundle") => std::process::exit(support_bundle::run(&r, f)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("objectstore") => std::process::exit(objectstore::run(&r)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("fsck") => std::process::exit(ops::fsck(&r, f)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("repair") => std::process::exit(ops::repair(&r, f)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("sizes") => std::process::exit(ops::sizes(&r, f)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("expand") => std::process::exit(ops::expand(&r, f)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("raw") => std::process::exit(raw::run(&r, f)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("free") => std::process::exit(ops::free(&r, f)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("upgrade") => std::process::exit(ops::upgrade(&r, f)),
        #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
        Some("wal-inspect") => std::process::exit(walinspect::run(&r, f)),
        _ => {
            eprintln!("{}", usage());
            std::process::exit(2);
        }
    }
}

/// `--store-backend spdk|kernel|kernel-cmd` (any subcommand, adr 0169; `main` has split `--opt=value` already): the `--dev spdk:BDF[,ns=N]` value is replaced by
/// the kernel node of that namespace (the controller bound to the kernel nvme driver); the flag itself is consumed.
#[cfg(feature = "kernel-nvme")]
fn store_backend_args(mut a: Vec<String>) -> Result<Vec<String>, String> {
    let Some(i) = a.iter().position(|x| x == "--store-backend") else {
        return Ok(a);
    };
    let b = a
        .get(i + 1)
        .cloned()
        .ok_or("--store-backend needs a value")?;
    a.drain(i..i + 2);
    // the first device option is the one the subcommand selects
    if let Some(d) = a
        .iter()
        .position(|x| x == "--dev")
        .and_then(|j| a.get_mut(j + 1))
    {
        *d = nvme::any::resolve_backend(d, &b)?;
    }
    Ok(a)
}

#[cfg(all(test, feature = "kernel-nvme"))]
mod tests {
    use super::store_backend_args;

    /// `main` hands over `--dev=SPEC` split like `--dev SPEC`: the backend rewrite reaches it.
    #[test]
    fn store_backend_rewrites_equals_form_device() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let dev = v(&["--dev=spdk:0000:00:00.0"]);
        let mut a = v(&["t", "objectstore", "--store-backend=spdk"]);
        a.extend(dev.clone());
        let a = outfmt::normalize_args(&a);
        let mut want = v(&["t", "objectstore"]);
        want.extend(outfmt::normalize_args(&dev));
        assert_eq!(store_backend_args(a).unwrap(), want);
        let mut bad = v(&["t", "objectstore", "--store-backend=bogus"]);
        bad.extend(dev);
        assert!(
            store_backend_args(outfmt::normalize_args(&bad))
                .unwrap_err()
                .contains("bad store backend")
        );
    }
}
