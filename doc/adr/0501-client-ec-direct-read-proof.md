<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0501 EC direct reads carry an explicit route proof

Status: accepted
Date: 2026-10-22

## Context

The v21 client can route eligible EC reads to a data shard. An ordinary EC
route proves only the acting primary shard. Reusing that proof without recording
the direct-read mode would let send validation and reply validation disagree.
The v20 client has no direct-read wire flags (split-read-contract.md).

## Decision

- A route records direct-read mode separately from pool kind and shard identity.
- The engine exposes a borrowed immutable read shape to the shared coordinator;
  routing inspects the original snapshot, operation vector and version need.
- A single-direct route requires the verified pool flag and geometry, nonzero
  bounded extents and one proven data shard for the complete vector. Preserve
  logical wire offsets and lengths. Never infer shard identity from a filtered
  acting vector or an OSD identifier.
- Core dispatch emits EC_DIRECT_READ/FORCE_OSD only with that route proof. Send
  validation rechecks geometry and the selected acting slot against the map.
- Reply validation uses direct-read extent rules; ordinary-read validation stays
  strict. EAGAIN and interval changes return the original request to primary
  routing with its logical owner, deadline and C1 ordering barrier intact.
- Multi-shard assembly is G07c, with one logical owner and a version-consistency
  check before publication. It is not declared implemented by single-direct work.

## Rationale

Explicit mode prevents an EC primary proof from authorizing a direct request.
Borrowed read shapes keep payload ownership in the engine without allocating a
second operation vector during route selection. All transports and ABI adapters
use the same coordinator and validated wire request.

## Consequences

- Single-direct vectors addressing different data shards are split by G07c;
  the reference first-op-only choice is not reproduced (ADR0256).
- Unsupported optimization shapes retain ordinary client semantics.
- Kernel TCP, io_uring and RDMA share the route and reply proof; C/C++, sync/async
  retain their original operation and completion ownership.

## Alternatives

- Infer direct mode from nonprimary destination: a primary can itself be the
  direct data-shard target, and ordinary replica selection has different rules.
- Put direct mode into pool kind: mixes independent route and pool properties.
