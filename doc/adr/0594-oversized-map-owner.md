<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0594 Header ownership with an absent oversized map

Status: accepted
Date: 2026-10-26

## Context

ADR0592 handles degraded maps but oversized preparation still fails EFBIG.
The pinned object-map-lock-recovery.md contract permits real header ownership
and DATA without an actual map. Feature bits remain enabled. A dummy cache or
fabricated map lease cannot express this state.

## Decision

A header owner carries its actual lease and an explicit map disposition:
feature absent or oversized map dropped. Actual map presence determines map
maintenance and shortcuts; feature bits determine input validation.
Preparation checks geometry before acquiring a map lock. Durable invalidation
precedes publishing an oversized header owner. Existing map resources close in
map-before-header order; successful map-only close transfers the existing
header lease, preserving identity. Uncertain close retains the complete pair.
No map cache is allocated above the supported limit.

A writable refresh below the limit reuses that actual header for ordinary map
preparation. Snapshot/DATA stages follow actual map presence. An oversized
rebuild returns EINVAL for unsupported map geometry instead of reproducing the
reference's absent-pointer assertion.

### Observable differences

The reference cold flags-clear branch returns EROFS because its managed-owner
state is still ACQUIRING during non-forced invalidation, despite the acquired
header. The own preparation uses the actual asserted header to durably
invalidate and continue. This is an intentional extension for fault-created
oversized geometry; ordinary public resize still rejects its creation.
Existing loaded maps are also invalidated/dropped after observed oversized
warm growth instead of retaining an undersized map. Below-limit reopen uses
the newly observed size immediately; reference staged refresh can need another
eligible event. An observed cleared invalid bit on a retained oversized owner
is durably repaired from that fresh observation. These guarantees require
explicit own tests and must not be described as identical reference behavior.

## Rationale

Typed disposition keeps real resources explicit and avoids coupling feature
admission to a nonexistent cache. Transfer preserves actual ownership without
reacquiring a header or abandoning a cleanup fence.

## Consequences

- + Oversized DATA retains checked ownership without map allocation/shortcuts.
- + Ordinary preparation, invalidation and cleanup remain shared.
- - Snapshot/resize/rollback callers must distinguish feature from map presence.
- - Reference rebuild assertion is intentionally replaced by a geometry error.

## Alternatives

- Allocate an all-EXISTS map above its limit: unsupported geometry and memory.
- Skip authority or invent a lease: violates ownership and cleanup contracts.
- Treat EFBIG as generic setup failure: refuses required DATA continuation.

## Open questions

The eight-case oversized target passes cold pre-invalid reference continuation,
own cold/warm extensions, actual map-lock retirement/restoration, small physical
DATA, snapshot-map absence and below-limit repair/rebuild. Five native feature
profiles and the full eleven-cell existing regression pass. Extend failed map close,
oversized rollback and real authority-loss faults; metadata-only lifecycle reuse
is still required. These bounds do not establish complete release qualification.
