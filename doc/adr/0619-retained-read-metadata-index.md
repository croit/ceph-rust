<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0619 Bound retained READ metadata by live occupancy

Status: accepted
Date: 2026-10-28

## Context

The registered READ owner's reserved TID map allocates during constant-depth
replacement, observed by the existing allocation gate. The advertised-attempt
registry uses the same reserve/insert/remove pattern. Resource ownership must
remain exact through deletion, replacement, stream failure and iteration.

## Decision

Use a private reserved linear-probe map for registered READ jobs and advertised
attempts. Close deleted probe chains instead of retaining tombstones.
Keep load at most one half; grow only through explicit fallible reservation
when live occupancy exceeds the prepared capacity.
Reserve production metadata against the normalized teardown-worker admission
bound before request progress. Preserve manual registry admission guards.
Keep exact key equality and full RequestToken checks after lookup.
Reserve queue totals using additional elements relative to current length.
Reuse prepared scratch IDs for stream quarantine; source/window retirement and
quarantine rules remain unchanged. Rustdoc in `rados_rt::lease_map` and the
existing registered owner/registry is authoritative for implementation details.

## Rationale

Lifetime insertion count is unbounded even at constant live depth. Closing
probe chains prevents that history from consuming capacity or rebuilding the
index. The existing hash function is retained; ownership moves use safe Rust.
The private implementation needs only the small lookup/removal/reservation API
used by the two retained-memory owners, without replacing the public TidMap.

## Consequences

- + Repeated bounded replacement uses no table allocation.
- + Attempt keys and owned resources survive collisions and cyclic probe shifts.
- + Stream failure reuses metadata rather than collecting a new ID vector.
- - Deletion shifts metadata within the affected collision chain.
- - Bucket storage and all other per-client memory still need cold preparation.
- - This does not qualify allocation behavior of unrelated request/connection
  maps, object transport performance, GPU memory or bounded provider reclaim.

## Alternatives

- Larger hash-map reservation: delays history-dependent behavior without a bound.
- Linear lookup of every job: gives up indexed lookup at larger queue depths.
- Replace all public TidMap users: changes unrelated admission/lifetime policies.

## Open questions

- What request/placement map bounds and cold preparation are needed for the
  complete object operation to avoid allocation under steady churn?
- What is the measured effect of shifted metadata on physical bandwidth/p99?
