<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0509 Client overlay routes retain base-pool provenance

Status: accepted
Date: 2026-10-21

## Context

Both client reference versions select read/write cache overlays from the captured
base pool and request flags (doc/spec/rados-client/overlay-routing.md). The
existing route uses one pool identity for both the request and placement, so the
engine rejects a legitimate cross-pool route. Ordering, snapshot ownership,
backoff and map-change validation must retain their separate identities.

## Decision

- ReadRoute carries base_pool as scalar provenance and pg.pool as effective
  placement identity; pool/shard describes the effective pool.
- Shared session routing selects one overlay from request READ/WRITE flags,
  with write precedence and IGNORE_OVERLAY bypass. IGNORE_CACHE is forwarded.
- Object dispatch validates base provenance and emits the effective pool in the
  locator and SPG. Explicit PG operations require identical base/effective pools.
- The captured application target remains the ordering identity. Snapshot/read
  and write contexts are unchanged by overlay placement.
- Every map install checks overlay selection as well as existing primary/shard
  and interval proofs. Backoff ranges compare against the effective pool.
- Managed watch binding, reconnect and queued control requests use the same
  flag-aware route as the operation that establishes them.
- C/C++, sync/async and kernel TCP/io_uring/RDMA share these rules. No new opt-out
  from the mandatory librados compatibility behavior is introduced.

## Rationale

Separate scalar provenance preserves the engine's cross-request route checks
without copying targets or adding a per-operation allocation. Resolving overlays
in the map/session layer keeps authenticated placement knowledge out of the
request engine and prevents transport-specific choices.

## Consequences

- + Tier changes trigger the existing ordered resend mechanism.
- + C1 barriers remain keyed by the captured application object.
- - Experimental native Rust ReadRoute literals need the new provenance field.
- - Missing-pool freshness and reply redirects remain independently specified
  request-machine behavior (inventory G17/G06), not invented routing fallbacks.

## Alternatives

- Retarget the captured application target: loses ordering identity and context.
- Disable the engine's pool proof: loses provenance for cross-pool dispatch.
- Copy/allocate an additional target on every send: unnecessary for a pool-only
  overlay and contrary to the hot-path allocation constraint.
