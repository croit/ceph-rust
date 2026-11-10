<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0606 Exact host READ ownership and revocable source windows

Status: accepted
Date: 2026-10-27

## Context

Removing the RDMA SEND assembly copy requires a streaming receiver or a transfer
into final storage buffers. The ordinary SEND/WRITE SQ-prefix proof cannot prove
independent READ retirement. Existing window ownership already separates peer
retirement from local invalidation and protects backing after uncertain DMA.

## Decision

- Host READ is an explicit native primitive behind `memory-windows`; ordinary
  session setup requests zero READ depths. No automatic wire feature is added.
- Intersect provider/peer READ limits by direction; bound outgoing admission by
  SQ capacity. Query capabilities only during setup.
- Publish host READ targets only after their exact successful CQ identity.
  Ordinary prefixes skip READ holes; reclaim positions contiguously. Allocate
  the bounded mixed ledger only for READ-prepared outgoing connections.
- Keep READ completion independent of ordinary tail signalling; mixed-mode
  control SENDs and ordinary batch tails provide their own completion coverage.
- Remove the old attempt's observer before publishing target readiness so a
  prepared owner can be reused without old-queue state updates.
- Consume exclusive prepared target ownership for accepted DMA. Return rejected
  owners; retain accepted uncertain/abandoned owners until a safe proof exists.
- Export exclusive host sources through READ-only type-2 MWs, sharing existing
  BIND/QP identity/peer-retirement/LOCAL_INV ownership. Never expose a parent MR
  key or add parent remote permissions. Use a distinct source descriptor type.
- Return advertised source backing only after peer retirement and LOCAL_INV;
  proven unpublished retraction still requires LOCAL_INV. Key match alone is
  insufficient across attempts or provider key wrap.
- Reject reconnect after RTR without clearing the old SRQ-ownership proof.
- Rustdoc in `rdma::verbs::{Qp,ReadTarget,ReadHandle,LocalReadSource,
  AdvertisedReadSource,ReadSourceDescriptor}` owns API behavior. No GPU contract,
  object source-pull protocol or object durability follows from these primitives.

## Rationale

Exact READ ownership prevents an unrelated completion from exposing unfinished
DMA data. Reusing prepared targets/windows avoids payload copies and per-operation
registration/allocation. Existing window retirement provides one source of truth
for both permissions. Explicit capability setup preserves ordinary peer behavior.

## Consequences

- + Bounded native host primitives support later direct source-pull integration.
- + Existing SEND/WRITE and client ownership contracts remain mandatory.
- - Uncertain owners are quarantined; bounded fault/cancel reclamation remains
  required before release qualification.
- - Wire negotiation/proof routing, chunk integrity/NVMe overlap, object durable
  completion, physical bandwidth/p99 and dedicated GPU evidence remain open.
- - `perf/rdma-host-read-integration-20261027.md` records qualification scope.

## Alternatives

- Ordinary completion publishes prior READs: insufficient READ-specific proof.
- Serialize every READ: restricts concurrency; not selected.
- Permanent source rkeys: no per-attempt revocation; not selected.

## Open questions

- Which measured SEND/source-pull object path improves bandwidth and p99?
- Which bounded cancellation/fault reclaim and dedicated GPU registration/
  revocation/visibility contract can be qualified?
