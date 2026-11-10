<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0468 Kernel direct I/O on validated linear LVM volumes
Status: superseded by adr 0646 (2026-11-03: linear LVM support restored for the bounded mapping there). The 2026-10-28 removal (code removed; replacement adr 0169 am. 7) no longer stands; adr 0646 is the current contract.
Date: 2026-10-20

## Context

The native kernel storage opener assumes its block node is a raw NVMe
namespace. An LVM LV does not expose namespace ioctls. Falling back to generic
block storage would omit production identity, topology and durability checks;
opening or formatting the physical disk would exceed the selected LV's scope.

## Decision

Extend only the Linux kernel direct-storage opener with the narrow mapping
contract in the spec (doc not in the source snapshot). Data I/O and exclusive
ownership stay on the LV. Read-only namespace access supplies Identify/health;
the geometry describes the LV, not the physical disk's full capacity. Refuse
unsupported/ambiguous mappings and all mapped whole-device discard operations.

This supersedes only ADR 0169's raw-namespace-only restriction for this validated
case. Native raw devices, command mode, SPDK, regular lab files, backend defaults
and the store durability contract are unchanged. Mapped devices also take this
validation path in lab builds: unsupported dm-on-loop or other mapped lab
layouts are refused rather than falling back to generic lab block storage.
No cache/read-copy optimization is
part of this decision.

## Rationale

An explicit bounded mapping preserves the LV's address space and keeps unrelated
storage outside the opener's ownership. Honest sector size and conservative
atomicity avoid granting guarantees device-mapper does not establish.

## Consequences

Startup needs read-only access to device-mapper tables and the backing NVMe
namespace. Only a single linear target over a namespace partition is supported;
this is not general LVM support. Mapping/layout changes require stopping the
OSD. Raw-native behavior and destructive setup operations have sibling gates.

## Alternatives

Accept arbitrary block devices: rejected, insufficient production validation.
Translate LV offsets and write the backing namespace: rejected, bypasses the LV
and its exclusive claim. Change SPDK ownership: outside this fix's scope.

## Open questions

No support commitment for other device-mapper target types. Hardware scenarios
not executed in a particular validation run must be reported as untested.
