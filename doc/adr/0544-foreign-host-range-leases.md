<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0544 Retained foreign host ranges below shared registrations

Status: accepted
Date: 2026-10-25

## Context

The existing foreign CPU allocation API owns a whole buffer exclusively. Concurrent ranges over one future parent MR require independent ownership without constructing a whole-allocation reference while a sibling is mutable or device-accessible. Parent mapping and registration lifetime must remain distinct from range permission and operation retirement.

## Decision

- One controller owns a bounded, preallocated range ledger and grants checked nonoverlapping byte ranges.
- Transferable range owners expose only their exact initialized CPU range. No shared whole-allocation byte view exists.
- Lease retirement release-publishes its reusable slot; the controller acquires that state before reusing its ledger entry.
- A separate backing retainer has no byte access and prevents whole-allocation recovery until provider deregistration is proved.
- Quarantine retains the exact owner and occupied claim permanently.
- Shared MR/MW ownership, one parent budget charge and native/C integration build on these owners; the memory primitive alone does not implement them.
- GPU/device allocation contracts remain separate from CPU-addressable foreign memory.

## Rationale

A flat bounded ledger avoids per-lease heap allocation, locking and payload work. Admission costs one metadata scan proportional to configured capacity; its cost must be measured before selecting a more complex index. Moving a lease preserves exclusive range ownership across threads. Unique retained ownership is required to recover the original allocation.

## Consequences

- + Disjoint CPU views and future device leases can retain one backing owner independently.
- + Controller drop cannot free a live or quarantined allocation.
- - One Arc increment/decrement and slot publication per range ownership lifecycle; no such claim about each READ over a retained lease.
- - Provider wrappers must consume the range owner until their separate device-retirement proof; a mapping guard grants no access permission.
- - Shared registration/control-budget integration and hardware/GPU gates remain unfinished.

## Alternatives

- Share the existing whole-buffer reference: conflicts with concurrent exclusive/device access in sibling ranges.
- Register each block separately: does not provide a reusable shared MR.
- Allocate a tree node per lease: violates bounded operation-time allocation requirements.
