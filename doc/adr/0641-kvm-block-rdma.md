<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0641 KVM block storage over RDMA through the own librbd/librados pair

Status: accepted
Date: 2026-11-03

## Context

KVM block storage means QEMU's `block-rbd.so` on the librbd C API. The own
librbd (`rbd-ffi`) implements that API and deliberately does not link librados:
it resolves the librados entry points of the consumer's loaded instance
(adr 0526). QEMU loads `block-rbd.so` as a module, and GLib loads modules with
a local symbol scope, so the consumer's librados is loaded but not visible in
the global scope.

The RDMA transport (adr 0469) upgrades librados OSD sessions in place. It is
opt-in in librados (`rustyrados_rdma`) and a failed upgrade leaves a working
TCP connection by design. No gate, documentation or decision covered the
librbd/QEMU path, and the data path still copies writes once into the
registered payload pool and reads once from receive slots.

## Decision

- The KVM block path is an unchanged QEMU on the own `librbd.so.1` and
  `librados.so.2` pair. No QEMU patch, no new librbd API, no librbd-specific
  RDMA switch.
- `rbd-ffi` resolves librados entry points from the consumer's instance:
  global scope first, then the already-loaded object by soname with
  `RTLD_NOLOAD`. It never loads a library and never creates a second librados
  (amends adr 0526).
- RDMA stays the librados client option: `rustyrados_rdma`,
  `rustyrados_rdma_memory`, epoll backend, the client host prerequisites of
  adr 0470. A QEMU disk without RDMA prerequisites runs on TCP; the gate and
  the operator checks detect that from the counters.
- Data path of this milestone is RDMA SEND: writes of at least one payload
  block copy once into the registered pool and post by reference; reads copy
  once from receive slots into the caller buffer. Registered read placement
  (adr 0606) and object source-pull (adr 0622) stay off for the librbd path
  until a measured comparison beats SEND; placement v1 currently loses
  bandwidth and p99 against SEND. The SEND path is measured against kernel TCP
  on hardware: perf/kvm-rdma-bench-20261103.md (doc not in the source snapshot).
- One gate proves the path end to end: `lab/rbd/kvm-rdma-e2e.sh` with the
  `kvmrdma` build profile. It runs an unchanged QEMU consumer (`qemu-img`,
  `qemu-io`, `block-rbd.so`) against one croit-flashstore-osd with `--rdma true` on
  soft-RoCE, checks the client status (`upgraded > 0`, `tcp_peer 0`,
  `declined 0`, `faulted 0`), the OSD `rdma status` and `tx_bytes`, a byte
  oracle through a second librbd, an abrupt consumer kill and the following
  fresh upgrade, and fails on a silent TCP fallback.

## Rationale

QEMU is the unchanged consumer; keeping the transport decision in librados
keeps one option, one status surface and one failure model for every
application. Resolving the module-loaded librados by soname keeps the single
instance the C ABI requires (an ioctx belongs to the library that created it)
without linking a second copy. SEND is already implemented and measured;
placement and source-pull are separate ownership contracts that must earn
their complexity with measured wins.

## Consequences

- + KVM disks get the RDMA transport with the existing client package and one
  configuration key.
- + The loader fix also covers other applications that load librbd as a module.
- + One gate covers QEMU, the C ABI, the OSD and the RDMA counters.
- - The librbd data path keeps one copy per write and one per read.
- - A missing prerequisite is silent on the data path; operators must check the
  counters.
- - QEMU has no status call; the client-side status comes from a librados
  consumer with the same configuration.

## Alternatives

- Link `rados-ffi` into `rbd-ffi`: a second librados instance and two owners
  for one ioctx (adr 0526).
- Patch QEMU or add an librbd RDMA API: not an unchanged consumer.
- Enable placement v1 by default for the librbd path: measured slower than
  SEND on the lab hardware.
- Require RDMA (fail the disk when the upgrade fails): breaks the adr 0469
  fallback contract for mixed clusters and classic OSDs.

## Open questions

- Registered caller-buffer cache for `rbd_aio_read` placement: worth it only
  after a QEMU measurement shows the receive copy costs more than the
  registration cache.
- A "require RDMA" client mode for deployments that must not fall back.
- QEMU version matrix for the gate (the loader path is generic, but the
  reference consumer must be pinned).
