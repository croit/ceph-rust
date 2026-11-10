<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0621 Prepared arena READ source windows

Status: accepted
Date: 2026-10-28

## Context

Immutable kernel-store pieces need READ-only source windows without per-request
MR registration or provider-window allocation. The existing SEND arena MR lacks
MW_BIND permission. Exact piece ownership must outlive peer access.

## Decision

Cold-register permanent initialized host arena ranges per device/PD with MW_BIND.
A bounded pool prepares source windows and metadata on the control path. Checkout
retargets an unbound window to a retained immutable piece within the same MR.
A non-cloneable ticket retains the pool identity and exact window completion
marker; only that ticket and recovered window may return the slot. Clear idle
payload ownership after safe return. Lost or quarantined slots remain unavailable;
a timeout never authorizes reuse. Reuse the existing authenticated peer proof and
LOCAL_INV retirement rules. API behavior is specified by Rustdoc in
`rdma::verbs::{ZcMem,ReadSourcePool,PreparedReadSource}`.

## Rationale

Preparing the MR and MW outside request progress avoids repeated provider calls.
Exact ticket and parent identities prevent a different window from replenishing
the budget; retained pieces prevent allocator reuse while peer READ may continue.

## Consequences

- + A prepared window can export different immutable pieces without payload copies.
- + Idle slots do not pin old payload pieces.
- - Each pool currently covers one MR and lost slots have no bounded reclaim.
- - Object protocol, pool budgeting, OSD wiring and GPU memory remain separate.

## Alternatives

- Register each object: repeated provider calls and memory pinning in request progress.
- Reuse a key after timeout: no proof that peer DMA stopped.

## Open questions

- How should source pools share the existing per-device memory budget and reclaim
  slots after provider/peer failure without weakening retirement proofs?
- What throughput and p99 do the integrated path achieve against TCP and SEND?
