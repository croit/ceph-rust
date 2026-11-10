<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0584 Shared prefetch subranges retain the original device buffer

Status: accepted
Date: 2026-10-26

## Context

`ShardStore::pf_serve` copies partial prefetch coverage into a new payload
allocation for shared READ results. Whole prefetch and cached subrange results
already retain immutable device backing. A partial result must leave the full
entry available with its existing physical reader pin and completed block CRCs.

## Decision

Ready prefetch entries hold either the completed device buffer or immutable
shared ownership of that same buffer. The first shared consumer converts the
owner once and returns the exact byte slice; partial consumers preserve the
full owner in the existing entry. Copying consumers retain their direct copy
path. Whole-run consumption, expiration, physical pins and cache invalidation
follow their existing rules. Device-seeded CRCs are selected for the exact
physical block range; sharing does not recompute or weaken verification.

## Rationale

An immutable slice can retain device ownership without allocating or copying
payload bytes. Keeping the full entry preserves readers of other subranges and
avoids duplicate device reads. Delaying owner conversion until a shared READ
avoids adding that conversion to ordinary copying-only prefetch workloads.

## Consequences

- + Partial shared reads avoid their extra payload allocation and copy.
- + Existing backing ownership survives COW replacement and transport retention.
- - The ready-buffer enum must support ordinary/compressed consumers after sharing.
- - First sharing still allocates the existing device-owner metadata; source bytes
  and the physical prefetch pin can outlive the requesting READ.

## Alternatives

- Consume the full entry on a partial read: loses unrelated prefetched coverage.
- Convert every completion eagerly: adds shared-owner work to copying-only reads.
- Copy partial results: retains avoidable payload work on the RDMA source path.
