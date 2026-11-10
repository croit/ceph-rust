<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0652 The root prep unit takes PCI devices from the root-owned conf only

Status: accepted
Date: 2026-11-05

## Context

- `croit-flashstore-prep@.service` runs as root before each OSD and binds the NVMe controller (and the NIC VF) named in
  `[osd.ID]` to `vfio-pci`, unbinds it from the kernel driver and hands `/dev/vfio/<group>` to the daemon user.
- When `flashstore_dev` was absent from the conf, the script read the device spec from `<osd-data-dir>/croit-flashstore-osd`. That
  directory (and the marker) belongs to the daemon user, so a compromised OSD could name any PCI function: the next boot
  would unbind the host NIC or another OSD's NVMe and bind it to `vfio-pci` (host/other-OSD denial of service).
- The value was interpolated into `/sys/bus/pci/...` paths and into `chown`/`chmod` targets without a shape check.

## Decision

- `croit-flashstore-prep.sh` reads `flashstore_dev` only from the root-owned ceph conf. The `croit-flashstore-osd` marker of
  the OSD data dir is never read for device selection; without `flashstore_dev` the unit binds no PCI device and logs it.
  `run` still takes the device from the prepared dir for a `file:` device (`osddir::run_args`), which is not a root action.
- Every PCI address is checked against the BDF shape (`[dddd:]bb:dd.f`) before it reaches a sysfs path, `chown` or
  `chmod`; anything else is refused (exit 3).
- The environment variable `FLASHSTORE_SYSFS` selects the sysfs root (default `/sys`) so the device-source rules are
  testable on a fixture tree without touching host devices.
- A `spdk:` OSD therefore needs `flashstore_dev` in its `[osd.ID]` section (documented in reference/configuration.md and
  how-to/prepare-host.md).

## Rationale

- The conf is root-owned; the data dir is handed to the daemon user by the same unit. Trusting the latter for a root
  action is the root cause, and no validation of the marker could make it trustworthy (the attacker writes it last).
- The BDF check is cheap and bounds every path built from the value, independent of who wrote the conf.

## Consequences

- + A compromised daemon cannot make the root prep unit unbind host or neighbouring OSD devices, and cannot escape the
  sysfs device path with a crafted address.
- - An `spdk:` deployment that relied on the marker fallback must add `flashstore_dev` to the conf (all documented and lab
  deployments already set it); without it the OSD fails at `activate` with a clear "no device" error.
- Tests: `lab/deploy/tests/croit-flashstore-prep-device-source.sh` (marker ignored, conf device bound in dry mode, path-like
  address refused) on a fixture sysfs; it fails before this change (marker used, no BDF refusal).
