<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0549 QEMU storage-tier sibling qualification

Status: accepted
Date: 2026-10-24

## Context

Placement's QEMU gate used SPDK storage with knet networking. Calling it a
kernel-tier result obscured the untested kernel-NVMe storage path. The harness
already provisions an exact run-owned emulated NVMe serial for each OSD guest.

## Decision

- The harness selects storage with --storage spdk|kernel, default SPDK, and
  records the selected tier in run.env and machine-readable summary.storage.
- Kernel mode keeps the serial-validated emulated controller on the kernel
  driver, requires exactly one namespace, and prepares kernel:/dev/<namespace>.
- The guest grants ceph access to only that namespace through an exact
  name/serial udev rule, retained across reboot; no host storage is modified.
- Both storage tiers run the same placement ownership/integrity scenarios.
- Guest timeout warnings are collected from every guest before teardown.

## Rationale

Tier identity must be explicit in evidence. Non-root access to one scratch
namespace preserves the deployment boundary without granting access to all disks
or changing the daemon user.

## Consequences

- + Kernel-NVMe and SPDK outcomes can be qualified independently.
- + Existing SPDK invocations retain their default and deployment path.
- - Kernel fixture setup also depends on the guest's udev daemon.

## Alternatives

- Infer storage from --net kernel: networking and storage are independent.
- Run the kernel daemon as root: unnecessarily widens the guest permission boundary.
