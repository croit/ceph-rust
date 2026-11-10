<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0496 Compatible backoff state follows server ownership and peer progress

Status: accepted
Date: 2026-10-22

## Context

The coordinator applies request-slot/64KiB storage limits and a local10s ACK
deadline to valid server backoffs. The reference stores and ACKs accepted BLOCKs
on their connection. A blocked front ACK currently also stops unrelated data.

## Decision

Use an explicit compatible backoff policy with dynamic identity-keyed ownership
and checked retained bytes; keep native strict capacity/byte/timer policy.
Retain ACKs through real output backpressure without an invented timeout.
Visit ACKs fairly with per-peer FIFO; preserve control priority on their peer
while independent peers continue, including split children.
Reuse compatible transport output admission and existing event-driven wait proof.

## Rationale

Server control-state population is independent of client request slots. Larger
constants retain a failure boundary; an auxiliary timer cannot repair blocked
transport progress. Ordered ownership releases actual nodes and permits session
lookup without scanning unrelated peers.

## Consequences

- Valid population/output pressure no longer closes the public handle.
- Unrelated peers retain progress and original operation deadlines.
- C1 resend barriers and ACK identity/order remain intact.
- Malformed/conflicting controls and actual transport loss remain distinct errors.
- No performance improvement is claimed without measurements.

## Alternatives

- Raise caps or extend timer: preserves arbitrary failures.
- Drop ACKs/blocks: violates backoff protocol and request gating.
- Globally stop data: creates unrelated peer head-of-line stalls.

## Open questions

None for this ownership correction; remaining transport-error qualification stays
in the gap inventory.
