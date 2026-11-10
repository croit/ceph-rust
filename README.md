# croit ceph-rust

**Ceph, rewritten in Rust for NVMe, fast networks and GPUs.**

croit ceph-rust is croit's ground-up Rust implementation of Ceph services and
client libraries. Every component speaks the Ceph wire protocol and drops into
an existing Ceph cluster: no forklift migration, no new tooling — your
monitors, managers, `ceph` CLI and applications keep working. Replace one
drive, one server or one client at a time.

More: [product page](https://www.croit.io/solutions/flashstore-osd) ·
[blog post: rebuilding Ceph in Rust](https://www.croit.io/blog/rebuilding-ceph-in-rust-flashstore-osd)

- **Built for flash.** FlashStore, our object store, is designed for NVMe from
  the first line: thread-per-core, lock-free hot paths, zero-copy data paths,
  acknowledged only when the data is durable on power-loss-protected NVMe.
- **Drop-in compatible.** The FlashStore OSD and librustyrados are
  wire-compatible with Ceph v21.2.0 (Umbrella) and v20.2.4 (Tentacle);
  librustyrbd exposes the v21.2.0 librbd C API and is tested against v21.2.0
  and v20.2.4 clusters. The OSD runs side by side with classic OSDs in the same
  pools and placement groups.
- **Fast networks and GPUs.** Kernel TCP over io_uring out of the box,
  optional RDMA (RoCEv2) between clients and OSDs, and GPUDirect RDMA into GPU
  memory through a NIXL plugin.
- **Self-tuning.** The OSD sizes its cores, queues and memory itself and tells
  you exactly which host setting to change, with the command to do it.
- **Clean room.** Written from scratch, without reusing Ceph's C++ code: it
  implements the Ceph wire protocol and behaviour from our own specifications.
- **Export-checked ABI.** Against Ceph v21.2.0 and v20.2.4: librustyrados
  exports all 407 C++ function symbols of the original librados, and the OSD
  implements all 26 methods of the original `cls-lock`.
- **Measured, not assumed.** Every change has to pass an extensive test suite
  and benchmarks against BlueStore on the same hardware.

## Status and roadmap

FlashStore OSD, librustyrados, librustyrbd and RDMA are in **public preview**
(since 9 November 2026): available for testing and evaluation, not yet
recommended for production data. General availability is planned for Q1 2027.
croit FlashStore OSD ships in the croit **frontier** release.

| Component | In this snapshot | Preview | GA |
|---|---|---|---|
| FlashStore OSD (drop-in for ceph-osd + BlueStore) | yes | Nov 2026 | Q1 2027 |
| librustyrados (librados replacement) | yes | Nov 2026 | Q1 2027 |
| librustyrbd (librbd replacement) | yes | Nov 2026 | Q1 2027 |
| RDMA (RoCEv2) transport | yes | Nov 2026 | Q1 2027 |
| Deduplication (replicated and erasure-coded pools) | no | Dec 2026 | Q1 2027 |
| KVBM/NIXL plugin (GPUDirect RDMA KV-cache offload) | no | Q1 2027 | Q2 2027 |
| CephFS2 + librustycephfs2 (transaction-based CephFS) | no | Q1 2027 | Q2 2027 |
| Rust RGW (S3 object gateway) | no | Q1 2027 | Q2 2027 |
| ceph-mon / ceph-mgr | use classic Ceph | – | – |

All dates are indicative and subject to change based on croit customer demand.

<!-- assets:begin -->
## Measured

Faster than or equal to stock librados/librbd in all 18 measured client
benchmark cells: 4 MiB RBD writes 2.1x (17.9 vs 8.5 GB/s), 4 MiB reads up to
1.95x, 4K random read (QD32, one object) 1.56x. The FlashStore OMAP engine
measures +23 % (single OSD) and +22 % (30-OSD cluster) geometric mean over
BlueStore on the same 5-host EPYC cluster. Full data, method and every cell:

- [benchmark report](assets/marketing/benchmark-report.pdf "target:_blank")
- [fact sheet](assets/marketing/fact-sheet.pdf "target:_blank")
- [press Q&A](assets/marketing/press-qa.pdf "target:_blank")
- [charts](assets/marketing/charts/rep3-throughput-ratio.png "target:_blank") and [architecture diagrams](assets/marketing/architecture/croit-flashstore-osd-architecture.png "target:_blank")
<!-- assets:end -->

## Requirements

- NVMe with power-loss protection (PLP) and 4 KiB sector format; whole
  namespaces, no partitions or filesystems.
- Linux 5.14 or newer (e.g. RHEL/Alma 9) with io_uring enabled.
- A Ceph v21.2.0 (Umbrella) or v20.2.4 (Tentacle) cluster.

## Get started

From the packages (.deb/.rpm on the [releases page](https://github.com/croit/ceph-rust/releases)):

```sh
croit-flashstore-tool prepare --dev kernel:/dev/ng0n1 --id 12     # once: create the OSD, mkfs, register with the mons
croit-flashstore-osd --check                                      # host check: prints the exact fix for every finding
systemctl enable --now croit-flashstore-osd@12
```

Operator manual: [docs/](docs/README.md).

## Build from source

```sh
cargo build --release -p croit-flashstore-osd
cargo build --release -p rustyrados
cargo build --release -p rustyrbd
cargo test -p croit-flashstore-osd
```

Production feature set (Linux): `knet,spdk,rdma,mimalloc`.

## What is in this snapshot

- **FlashStore OSD** — `services/osd/`: the `croit-flashstore-osd` daemon and
  its internal crates (store, osd, pgwire, replwire, msgr2 peering, ...).
- **librustyrados** — `crates/rustyrados`: rados client library (C API, C++
  ABI on x86_64, native Rust API).
- **librustyrbd** — `crates/rustyrbd`: rbd client library (C API).
- **croit-flashstore-tool** — `tools/croit-flashstore-tool`: the operator CLI
  (prepare, host checks, host-tune, lifecycle) plus its dependency
  `tools/ostool`, the offline store tool (parity subset of
  `ceph-objectstore-tool`).
- `deploy/` — the deployment assets the packages install: systemd units and
  drop-in examples, the preparation script, tmpfiles config and the smartctl
  sudoers entry.
- The workspace crates those three depend on (the `members` list of the root
  `Cargo.toml` is exactly the snapshot set, incl. `tools/oprobe`, the dev-only
  RADOS test driver the opexec golden and cls differential test suites run on;
  it is never linked into the daemon).
- `docs/` — the operator manual (served as a website on GitHub Pages).
- `doc/adr/` — the architecture decision records (ADRs).
- `testdata/` — wire-protocol test vectors (golden fixtures).
- License files (`COPYING`, `COPYING-*`, `AUTHORS`); every source file carries
  its SPDX license header.

Not included: the rest of the design documents (specs, perf, ops), test labs
and benchmark tooling, lab/dev CLI tools (benchrun, rdma-bench, ...), and the
components marked "no" in the roadmap table.

This repository is a **read-only source snapshot** of the croit ceph-rust
project: no issue tracker, no contribution workflow. Updates arrive as new
snapshot commits, one per snapshot.

## Snapshot provenance

- upstream repo: croit ceph-rust (private development repo)
- upstream commit: `c5792750020e66be3037bb1a5f2948ad678eadc0`
- Ceph tested against: `v21.2.0` (commit `b060042deb05d33e6cc358970cfb8221240bcf3e`)
- snapshot date: 2026-11-10

## License

Copyright croit GmbH and contributors (`AUTHORS`). Daemons: LGPL-3.0-only;
client libraries: MPL-2.0; documentation: CC-BY-SA-4.0. See `COPYING`.
