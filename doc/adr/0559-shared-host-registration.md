<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0559 One retained parent MR with prepared independent host windows

Status: accepted
Date: 2026-10-25

## Context

Native foreign destinations still register one exclusive allocation. The range ownership foundation supports disjoint CPU views and retention independently of a future MR. Shared registration must preserve existing per-window peer retirement, LOCAL_INV and quarantine while retaining one parent mapping and charge.

## Decision

- Prepare a bounded MW pool before registering one parent host MR on one PD.
- Grant arbitrary checked nonoverlapping ranges only from slots with a prepared MW; retain the exact range and parent MR in each destination.
- Reclaim prepared unbound children without provider calls or allocation. A safely dropped child releases its range; explicit cold preparation replaces its missing MW.
- Recover the whole allocation only after every child is gone, idle MWs retire and parent MR deregistration succeeds.
- Uncertain child/idle MW or parent MR release retains parent backing, supplementary control retainer and device.
- The supplementary retainer holds one native parent count/byte charge. Shared children transfer only range/window ownership; budget release follows proved parent MR release or pre-MR rejection. Async client setup prepares a pool bounded by the native request capacity. C and GPU integration remain separate.

## Rationale

The existing range ledger supplies slot ownership and exact CPU bounds. Prepared windows remove provider allocation from claims/reclaims without a second concurrent slot registry. Child ownership uses the existing BIND/retirement types rather than introducing a parallel wire protocol.

## Consequences

- + One parent MR across independent ranges and QPs, with no payload copy or per-block registration.
- + Existing operation retirement guards remain mandatory.
- - Parent MR lifetime extends to the last child; one uncertain child prevents parent recovery.
- - Replacing deliberately dropped MWs is a control operation; claims never hide provider allocation.
- - Provider, native/full-stack and complete fault/performance/GPU qualification remain separate gates.

## Alternatives

Per-block MRs repeat registration and pin accounting. Copying into an internal
arena introduces payload staging. A shared MR with whole-allocation CPU views
violates independent range ownership. Per-child budget charges double-count
retained bytes and can release quota before the parent mapping is gone.

## Open questions

- Full-stack shared-range READ, cancellation, stale/key-wrap and physical-provider qualification.
- Large-pool admission CPU, Arc/refcount costs, retained-memory and setup saturation measurements.
- Stable C batching/completion routing; dedicated GPU registration/revocation/visibility evidence.
