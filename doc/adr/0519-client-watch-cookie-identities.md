<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0519: opaque client watch identities use their protocol width
Status: accepted
Date: 2026-10-22

## Context
WatchRegistry uses a 32-bit registry domain plus a 32-bit sequence for its
64-bit cookie. Temporary notification registrations consume the same sequence,
so a healthy long-lived client eventually loses admission after 2^32 allocations.
Both pins expose an opaque uint64 cookie; their implementation's pointer cookie
and separate u64 linger counter impose no such 32-bit lifetime contract.
Source: cookie identity (doc not in the source snapshot).

## Decision
Registry domains and wire cookies use separate process-wide nonzero u64 identity
sources. Wire cookies consume the full protocol width and are never partitioned
into fixed-width owner/sequence fields. Lookup remains registry-scoped; native
handles additionally retain their domain and slot identity. Identity exhaustion
is explicit, never wraps to zero or reuses a previously allocated cookie.
Allocation follows permanent shape/resource validation, so refused requests do
not spend a cookie. Strict capacity and compatible elastic population policies
remain independent of identifier representation.

## Rationale
The public cookie is opaque. Separating ownership proof from wire identity
removes a reachable artificial lifetime ceiling without changing the wire or
adding a larger configurable/fixed population limit. Nonreuse rejects stale
handles and notifications without reproducing reference pointer-reuse hazards.

## Consequences
- + Watch/notify registrations cross the former 32-bit boundary normally.
- + Registry/domain separation and stale identity rejection stay explicit.
- - Cookie numeric values differ from the previous partition and from reference
  pointer values, as allowed for opaque cookies by ADR0256.
- - Exhausting the full u64 identity domain remains an explicit local error;
  pointer reuse and unsafe wraparound behavior are not emulated.

## Alternatives
- Increase one partition: retains an arbitrary lifetime ceiling and shrinks
  the other domain.
- Reuse released pointer cookies: unnecessary allocation/ownership coupling
  and exposure to delayed-event aliasing.
