<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0618 Negotiate READ depths through explicit RDMA upgrade offers

Status: accepted
Date: 2026-10-28

## Context

Native READs require bounded initiator/responder depths on the existing RC QP.
The control backend currently creates ordinary QPs and the upgrade endpoint
does not carry those limits. Provider-level fixture setup is insufficient to
support an actual upgraded connection's READ admission.

## Decision

Carry an optional versioned READ-depth offer in the existing opaque endpoint,
as defined by the wire contract (doc not in the source snapshot).
Prepare READ-capable pooled QPs only through explicit control-backend opt-in;
cache the device query there, outside progress and per-QP preparation.
Negotiate each direction from local and same-session peer bounds.
Keep READ disabled if either endpoint omits an offer.
Keep ordinary production startup and placement-v1 operation handling unchanged.
Rustdoc in `rdma::{ReadOffer,Endpoint}`, `rdma::control::VerbsBackend` and
`rdma::verbs::Qp` owns setup API behavior.

## Rationale

The upgrade already owns authenticated-peer endpoint routing and blocking QP
setup on its control thread. Explicit offers avoid assumptions about symmetric
hardware, SQ capacity or READ support on an older peer. Resource negotiation
remains independent of memory permissions and operation-protocol negotiation.

## Consequences

- + Both upgraded endpoints can derive matching bounded READ depths.
- + Default records remain byte-identical, with no READ device query or hot-path work.
- + Existing control pooling/queueing/failure ownership remains authoritative.
- - Extended records require strict validation and mixed-peer coverage.
- - Object negotiation, source grants, target budgets and durable completion
  remain separate work; this does not activate source-pull in production.

## Alternatives

- Assume hardware-symmetric fixed depths: does not prove peer capacity.
- Reinterpret placement-v1 support as READ support: incompatible capability claim.
- Register or recreate a QP per operation: blocking resource work in progress.

## Open questions

- Which authenticated object capability and proof routing activates source-pull?
- Which pooled resource budgets support that operation without hot registration?
