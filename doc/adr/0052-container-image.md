# 0052 OCI image + podman unit; one production binary for every NIC

Status: accepted, amended (am. 7)
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): AF_XDP/DPDK tier packaging is history; the rest stays valid.
Date: 2026-10-11
Consolidated 2026-10-19; full pre-consolidation text: git show 60868596d:doc/adr/0052-container-image.md
Amends: 0034 (deployment variant)

## Context

croit deploys croit-flashstore-osd as systemd services AND containers (no cephadm). Per-NIC build variants would multiply test/deploy matrices. Ops reference: doc/ops/deploy.md.

## Decision

Image:
- debian:trixie-slim + 2 stripped binaries (`croit-flashstore-osd`, `croit-flashstore-tool`) + `croit-flashstore-entry` + `croit-flashstore-health`. Built from PREBUILT build host binaries (`lab/build-remote.sh prod`), no compile-in-image: one build path, identical sha native and OCI.
- Dynamic: glibc (libc, libm, libgcc_s, ld-linux) and the LGPL-only libnuma + libelf (am. 9, adr 0589; image packages `libnuma1` + `libelf1t64` via the ldd -> dpkg mapping of `lab/deploy/container/build.sh`; `FLASHSTORE_LGPL_LINK=static` = opt-in fully static). Static: uuid, ssl, crypto, z, zstd (source builds into the glibc sysroot, am. 8), rdma-core without libnl (`build-rdma-core.sh`, `ENABLE_RESOLVE_NEIGH=0`), libxdp+libbpf (`crates/net/build.rs`, `crates/nvme/build.rs`). No libarchive/libfdt (meson probes disabled in `build-dpdk.sh`, asserted), no jansson/libpcap (patch 0003).
- `lab/deploy/container/build.sh <sha> prod|ctrlab`; tag = git sha12 (`-lab` suffix for ctrlab); push ONLY to the build host registry (`registry-up.sh`, `registry:2`, plain HTTP, insecure-registry on consumers). `ctrlab` = prod + `lab` feature (file: dev, af_packet) for labs without NVMe/VF; never deployed.

One binary:
- Prod binary = `dpdk,spdk,mimalloc,knet,rdma` (am. 7: the RDMA upgrade is built in and off at run time unless `flashstore_rdma = true`; static rdma-core of the image build, already linked for the DPDK mlx5 PMD); tier and NIC chosen at run time (`--net kernel|dpdk|afxdp`, EAL args), never at build time. `croit-flashstore-osd --version` / `--net-caps` print tiers + PMD list (`net` build.rs records linked `rte_net_*`).
- Build host `/opt/dpdk` = DPDK 26.07 via `lab/devcontainer/build-dpdk.sh`: bnxt (+`dpdk-bnxt-fix.sh`), ice, iavf, i40e, virtio, mlx5 (`ibverbs_link=static`, env `IBVERBS_LINK=dlopen` = rollback), af_xdp, af_packet, tap, null, ring. Installed via DESTDIR staging + prefix swap; old tree kept as `/opt/dpdk.prev` (`.prev-<date>` for older).
- mlx5 needs only kernel modules `mlx5_ib` / `ib_uverbs`.
- Patches `lab/devcontainer/dpdk-patches/*.patch` (BSD-3-Clause, header each), applied after the bnxt fix, `patch --forward` (fails loudly on a DPDK upgrade; rebase each time):
  - 0001 net_af_xdp: fill ring = RQ + 2 rx rings posted at bind; counted rx duplicate-descriptor skip (`ierrors`, ERR log 1st + every 1024th); non-blocking rx wakeup, `NV_XDP_KICK`. The page-aligned 4 KiB mbuf pool (actual zero-copy fix) is ours: `crates/net/csrc/shim.c`, net_af_xdp ports only.
  - 0002 net_af_xdp tx checksum: init probe (`NV_XDP_TXCSUM` != 0, driver xsk tx-checksum, kernel accepts `XDP_UMEM_TX_METADATA_LEN`); on success 24 B tx metadata, `IPV4_CKSUM | TCP_CKSUM` advertised, per-frame XDP_TX_METADATA checksum request (IPv4 header checksum in the PMD; Rust side unchanged, `Caps::configure`). Else software checksums. `NV_XDP_TXCSUM=0` = off. Test `xdp::tx_metadata_fits_the_headroom_and_the_page`.
  - Debug patches (`dpdk-patches/debug/`) only with `DPDK_DEBUG_PATCHES=1`; the script refuses for `/opt/dpdk`.
- jansson and libpcap are kept out by build environment, not by a source patch (am. 9): meson searches a pkg-config view of the normal search path without `jansson.pc`/`libpcap.pc` (`config/meson.build` finds both via pkg-config; only testpmd, dumpcap, net/pcap, net/cpfl, ml/cnxk and librte_bpf's cBPF conversion use them). Gates: `build-dpdk.sh` fails if either reaches `libdpdk*.pc` or `RTE_HAS_JANSSON`/`RTE_HAS_LIBPCAP` (libpcap's `find_library` fallback: build in the sysroot or remove the host libpcap dev package); `check-dpdk-patches.sh` fails on a prefix whose `libdpdk*.pc` lists either; `scripts/package.sh` rejects either in `DT_NEEDED`.
- `/opt/dpdk` must be rebuilt after a patch change to reach the prod binary.

Entry and run contract:
- `croit-flashstore-entry` (bash PID 1): `run` = `croit-flashstore-tool activate` + `croit-flashstore-osd run --id N --cluster C -f` (id from `--id` or `$FLASHSTORE_ID`); other words = croit-flashstore-tool subcommands. Forwards TERM/INT/HUP, reaps, passes the daemon exit code through. Optional `FLASHSTORE_HOLD_EXIT="0 2 3"`: after such an exit (not after a stop request) park until SIGTERM, so plain docker `--restart` does not hot-loop on purge (0) or refusal (3). HEALTHCHECK = `croit-flashstore-tool asok status`.
- `lab/deploy/container/run.sh`: `--network=host` (kernel TCP, as the classic ceph-osd container; was `--network=none` for a DPDK VF until adr 0682-remove-afxdp-dpdk-networking), vfio devices (`/dev/vfio/vfio` + groups), mounts conf ro / OSD dir / `/var/run/ceph` / `/var/lib/ceph/crash` / `/var/log/ceph` / hugepages, `--cpuset-cpus` (+mems) = `flashstore_lcores`, no `--cpus`, `--ulimit memlock=-1`, `--cap-drop ALL` + IPC_LOCK + SYS_NICE, `no-new-privileges`, read-only rootfs + tmpfs /run,/tmp, `--stop-timeout 60`. Root inside (vfio, BAR mmap). Host side stays host-side (`croit-flashstore-prep@`).
- Unit `lab/deploy/systemd/croit-flashstore-ctr@.service` (podman): Type=notify, NotifyAccess=all, `--sdnotify=container` (run.sh forwards WATCHDOG_USEC), Requires `croit-flashstore-prep@`, `Conflicts=croit-flashstore-osd@%i`, `Restart=on-failure`, `RestartPreventExitStatus=2 3`, `podman stop -t 60`, ExecReload = SIGHUP. Native `croit-flashstore-osd@.service` unchanged; one variant per id.
- Crash dump gets a `done` marker written last (the real `ceph-crash` ignores dirs without it).
- `croit-flashstore-tool activate` host checks refuse with the reason and the fix line.

## Rationale

One binary/one CLI for both modes, rebuild = registry push; static non-glibc libs let the production hypervisor (no installs allowed) start the binary unchanged. Verification record: doc/perf/adr-0052-history.md.

## Consequences

- + exit-code contract holds in containers; tier + NIC by flags; bnxt fix and af_xdp patches baked in every build.
- + no host deps beyond glibc (binary needs GLIBC_2.38) and kernel modules.
- - plain docker needs HOLD (no RestartPreventExitStatus); `docker kill` is a manual stop (no policy restart).
- - healthcheck proves control core + asok thread only.
- - bigger binary (+~1 MB); rdma-core/elfutils/DPDK rebuilt on version bumps; OpenSSL/zlib security fixes need a rebuild, not a host update.
- - DPDK patches rebased per upgrade.

## Alternatives

- Multi-stage build in the devcontainer: second build path, slow, duplicate toolchain.
- Copying libs instead of static: opaque, glibc skew.
- dlopen mlx5 glue + rdma-core on hosts, per-NIC image (`MLX=1`): needed host packages; superseded by static.
- Distroless: no apt/bash for the entry. `--privileged`: rejected. Kernel-networked container: adr 0005.

## Open questions

- Not verified: vfio NVMe/VF passthrough into the container, mlx5 hardware, container-level real `require_osd_release` refusal, NUMA/cpuset throughput.

## Amendment map

- am. 1 (2026-10-11): base image decision -> Decision (Image, Entry, Run contract)
- am. 2 (2026-10-12): one binary every NIC -> Decision (One binary); dlopen glue superseded by am. 5 (removed: `MLX5_GLUE_PATH`, `/usr/lib/croit-flashstore-osd/` glue dir, `croit-flashstore-osd.mlx`, `MLX=1`)
- am. 3 (2026-10-12): af_xdp zero copy patch -> Decision (patch 0001)
- am. 4 (2026-10-12): trimmed deps, glue path -> Decision (disabled probes, DESTDIR swap); glue/package parts superseded by am. 5 (removed: glue search order, activate glue/rdma-core check for `flashstore_vf_pci` ConnectX NICs, `apt install` hint)
- am. 5 (2026-10-12): static non-glibc libs -> Decision (Image)
- am. 6 (2026-10-15): af_xdp tx checksum patch -> Decision (patch 0002)
- am. 7 (2026-10-20): `rdma` feature in the prod binary -> Decision (Prod binary)
- am. 8 (2026-10-26): sysroot statics, libeu dropped -> Decision (Image)
- am. 9 (2026-10-26): LGPL-only libnuma/libelf dynamic (adr 0589), jansson/libpcap/libnl out of the link set (build environment, no DPDK source patch) -> Decision (Image, patches)
