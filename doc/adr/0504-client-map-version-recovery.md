<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0504 Compatible map-version waits survive monitor session resets

Status: accepted
Date: 2026-10-22

## Context

The native map-barrier queue has a bounded query-attempt policy. Applying its
initial two-attempt policy to librados waits exposes ENOTCONN after repeated
session resets, although both reference versions resubmit retryable version
queries. The FFI already retains map jobs beyond finite native staging slots.

## Decision

Expose an explicit compatible map-wait constructor/enable path whose read-only
version queries recover until their original deadline or shutdown. Retain the
strict native bounded-attempt API. Keep existing staging and work quanta.

## Rationale

Version-query recovery is the reference contract and does not replay mutations.
A larger count would leave the same failure at a different point. An explicit
policy preserves strict callers and makes the application contract reviewable.

## Consequences

- Reconnects preserve accepted waiters and their original deadlines.
- All transport forwarders carry the same policy; DPDK remains compile-only.
- Timeouts warn once with the original limit; shutdown/cancel/protocol results
  remain distinct.
- Ordinary-operation missing-pool freshness remains a separate integration.

## Alternatives

- Increase the count: retains an arbitrary failure boundary.
- Retry all monitor operations: risks replaying mutations with unknown outcomes.

## Open questions

None for this policy. Full monitor error-category mapping and ordinary missing
pool integration stay explicit inventory items.
