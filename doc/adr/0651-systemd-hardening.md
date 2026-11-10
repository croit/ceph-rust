<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0651 croit-flashstore-osd@ adopts the classic ceph-osd@ hardening that cannot break its I/O paths

Status: accepted
Date: 2026-11-05

## Context

- `croit-flashstore-osd@.service` carried only `PrivateTmp=true`, `LimitCORE=0` and `NoNewPrivileges=false`; classic `ceph-osd@`
  confines the daemon further (read-only `/usr`, `/boot`, `/etc`, no home, no cgroupfs/kernel-log/module/hostname
  writes, no personality change, no setuid file creation).
- The daemon links a large `unsafe` surface (SPDK/DPDK, io_uring, RDMA verbs) and parses peer-supplied data; the
  confinement is defence in depth for a memory-safety bug, not a substitute for fixing one.
- Some classic directives can change the behaviour of device access, hugepage mappings, mlock or io_uring; adding one of
  those without a lab cell would be a guess.

## Decision

- `croit-flashstore-osd@.service` sets `ProtectSystem=full`, `ProtectHome=true`, `ProtectControlGroups=true`,
  `ProtectKernelLogs=true`, `ProtectKernelModules=true`, `ProtectHostname=true`, `LockPersonality=true`,
  `RestrictSUIDSGID=true` in addition to `PrivateTmp=true`, `LimitCORE=0` and `NoNewPrivileges=false`.
- Not adopted, each needs its own verification against SPDK/DPDK, vfio device access, io_uring and RDMA first:
  `MemoryDenyWriteExecute` (possible W+X mappings in DPDK/SPDK), `ProtectKernelTunables` (kernel-tier/io_uring setup
  reads and may tune sysctls), `ProtectClock`, `ProtectProc`, `RestrictNamespaces` (RDMA/AF_XDP namespaces),
  `RestrictRealtime`, `SystemCallFilter`/`SystemCallArchitectures`, `DeviceAllow`/`PrivateDevices` (vfio group nodes,
  hugepages, kernel NVMe nodes) and `IPAddressDeny` (cluster traffic).
- `scripts/check-systemd-hardening.sh` asserts the adopted list; it runs in `scripts/check.sh`.

## Rationale

- The adopted set only removes write access to paths the daemon never writes (/usr, /boot, /etc, /home, cgroupfs,
  kernel log, module loading, hostname, setuid bits). Device nodes, `/dev/vfio`, hugetlbfs, `mlock` and io_uring are
  not touched.
- `NoNewPrivileges=false` stays: the classic `sudo -n smartctl` route needs the setuid transition (adr 0056 am. 2).

## Consequences

- + A code-execution bug in the daemon no longer writes most of the filesystem, `/proc/sys`, the kernel log or an
  executable mapping.
- - An `osd_data` or `admin_socket` path under `/home` needs a drop-in (`ProtectHome=false`); the documented layout
  (`/var/lib/ceph/osd`, `/var/run/ceph`) is unaffected.
- - SPDK/DPDK memory mappings are not covered by the stricter directives until a lab cell verifies them.
- - `PrivateTmp=true` (unchanged) makes `/var/tmp` private to the unit; the claim files therefore live in the shared
  `/run/croit-flashstore-osd` (adr 0649 am. 1), not in `/var/tmp` (resolved, am. 1).
- Tests: `scripts/check-systemd-hardening.sh` (fails when a directive is dropped), run in `scripts/check.sh`.
- Siblings checked: `croit-flashstore-prep@.service` is a short root oneshot that mounts hugetlbfs and binds PCI devices; it
  must write sysfs and load modules, so the same set does not apply. The container unit keeps its own hardening
  (`--cap-drop ALL`, `no-new-privileges`, `--read-only`).

## Amendment (2026-11-06, am. 1): PrivateTmp stays; the claim locks move out of /var/tmp

Context: the consequence above (a private `/var/tmp` hides the SPDK claim file from host tools) was the open question
doc/90-open-questions.md. Weakening `PrivateTmp` was rejected: classic `ceph-osd@.service` has it too.

Decision: `croit-flashstore-osd@.service` keeps `PrivateTmp=true` unchanged. croit-flashstore-osd's own cross-process claim files move to
`/run/croit-flashstore-osd` (root:ceph `1770`, tmpfiles.d + `croit-flashstore-prep@`; adr 0649 am. 1, adr 0056 am. 4); containers bind that
directory. No `ReadWritePaths` is added: `ProtectSystem=full` read-only covers `/usr`, `/boot` and `/etc`, and `/run`
stays writable. SPDK's own internal lock remains in the private `/var/tmp` and does not need to be shared.

Consequences: + all hardening directives of this ADR stay in force and the claim exclusion works across daemon, tool and
containers; - hosts upgraded without the package/tmpfiles must create `/run/croit-flashstore-osd` (the daemon's error names the
command). Tests: `scripts/check-systemd-hardening.sh` still asserts `PrivateTmp=true`; `nvme::pcilock` tests cover the
new directory.
