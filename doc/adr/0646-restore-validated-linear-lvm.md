<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH -->
# ADR 0646: Restore validated kernel direct storage on linear LVM
Status: accepted
Date: 2026-11-03
Supersedes: ADR 0169 amendment 7 only for the bounded mapping below; restores the
restricted contract formerly implemented by ADR 0468, not general block storage.

## Decision

Accept an identified, active, writable single linear LVM target on one partition
of one kernel-owned NVMe namespace. Keep every data operation and exclusive claim
on the selected LV. Open the backing namespace read-only for identity and health,
never as a data/format/discard path. See contract (doc not in the source snapshot).

This is production kernel storage, not a lab backend or a flag bypass. Reject
unsupported mappings, ambiguous topology, volatile backing cache, dishonest
geometry and concurrent selected-device use. Administrative mapping changes while
an OSD holds the LV remain forbidden. No automatic host tuning or provisioning.
Backing NVMe Identify must succeed: a configured sysfs write-through policy is
not evidence that the physical device lacks a volatile cache. Native fallback
behavior is unchanged; this requirement applies to mapped admission only.

Raw namespace and SPDK policies stay unchanged. An LV cannot select kernel-cmd.
Do not restore historical namespace-write probes or weaken current durability,
io_uring, dead-device, transfer-limit or fixed-buffer protections. Mapped devices
never issue namespace DSM, including the mkfs-only capability probe. No format or
replay change is intended; do not relabel hardware/crash checks that were not run.

## Rationale and consequences

The requested deployment uses dedicated LVs on a shared physical NVMe. Explicit
mapping validation preserves that LV's bounds without exposing unrelated workspace
or other stores. Startup requires device-mapper query privilege and read-only NVMe
Identify access; it does not promise protection against an administrator changing
the mapping later. Unsupported device-mapper targets remain refused.

Independent Rust regressions cover mapping parsing/bounds/identity, capability
suppression, backend selection and namespace-only destructive-operation refusal.
Real-device, crash/replay and full production-matrix qualification are separate
evidence, not implied by offline tests or compilation.
