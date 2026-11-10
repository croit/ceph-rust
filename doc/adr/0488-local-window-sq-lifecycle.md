<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0488 Unadvertised windows share the existing RC send queue

Status: accepted
Date: 2026-10-22

## Context

ADR 0485 assigns provider windows to the existing RDMA crate. ADR 0471 requires
placement WRs and SENDs to share an RC QP and preserves advertised memory until
peer retirement. Existing SQ completion accounting retains only SEND sources;
a modular sequence check alone cannot identify a handle retained across a full
sequence wrap. No production GPU test environment is available.

## Decision

- Feature `memory-windows` adds unadvertised host BIND/LOCAL_INV operations to
  the existing SQ; there is no second data QP or descriptor advertisement.
- Allocate the reusable completion marker with the MW on the control thread.
  Fixed-capacity SQ slots retain markers and signal ordered success or failure.
- Size the CQ for full per-session SQ occupancy with local window operations;
  their signalled WRs have no SEND-credit bound. Reject unrepresentable CQ
  requirements instead of truncating capacity.
- Bind/invalidate posts allocate no memory, require no SEND credits, use the
  existing epoch/sequence and keep the default SEND planner unchanged.
- Bind ownership excludes CPU access; exact QP identity prevents QPN-reuse
  confusion. Recover unbound ownership only after successful local invalidation
  of a never-advertised window. Otherwise retain uncertain backing permanently.
- Accepted bindings retain QP ownership until confirmed invalidation. A QP
  with unretired windows is quarantined with its device/core resources before
  invoking provider destruction, which may otherwise wait on those MWs.
- A future advertisement API consumes this state and requires the separate
  ordered peer-retirement and integrity contracts before returning memory.

## Rationale

Shared accounting preserves RC ordering and existing teardown behavior.
Persistent completion identity prevents sequence-wrap aliasing without a
second queue. Keeping keys private makes local retirement sufficient for this
increment and avoids weakening the advertised-window contract.

## Consequences

- + Real provider binding/invalidation can be qualified before wire placement.
- + The default feature set has no marker storage or window operations.
- - Opt-in SQ slots retain additional completion metadata.
- - Abandoning an unfinished binding quarantines resources until process exit.
- - No end-to-end, GPU or NIXL support follows from this provider increment.

## Alternatives

- Separate QP: breaks required ordering with protocol SENDs.
- Poll only a saved sequence number: aliases after an arbitrary retained handle
  outlives sequence wrap.
- Return advertised memory after LOCAL_INV alone: violates ADR 0471.

## Amendments

### am. 1 (2026-10-22, accepted): report retained placement memory

- Report process-wide counts of quarantined type-2 windows and registered
  WRITE sources in OSD `rdma status` and perf counters and the client RDMA
  status JSON. Unbuilt placement reports zero. These counts must remain zero
  during qualified normal operation; they identify memory deliberately retained
  after uncertain peer retirement or provider completion.
