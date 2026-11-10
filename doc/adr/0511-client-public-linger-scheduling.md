<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0511: public client lingers share coordination with explicit protocol policy
Status: accepted
Date: 2026-10-22

## Context
The strict native managed-watch lifecycle supplies finite outage budgets and a
single pending control. Both pinned public librados contracts require different
behavior: global configurable ticks, independent pending pings, per-operation
reconnect deadlines and recoverable error history. Source:
watch timing (doc not in the source snapshot),
cookie identity (doc not in the source snapshot).

## Decision
Public compatible watch lingers use an explicit protocol state machine alongside
the strict native lifecycle. Both share the existing ObjectClient coordinator,
owned queue, map/interval proofs and per-object resend ordering.

The public policy has one registration/reconnect operation plus independently
identified pending pings. Pings have no ordinary operation deadline and are never
replayed across an interval/session replacement. Register/reconnect results do
not refresh confirmation age. A ping's current-generation success records its
pre-send sample, including an older same-generation confirmation.

Ping completion uses a reusable dense slot carried only in the opaque local
action, plus the full action identity. Slot reuse never validates an old action.
Completion unlinks one slot without searching or shifting the pending population;
free-slot storage is reserved during growth, before any action is published.
Error-event order and tick intent emission order stay independent of slot layout.
The measured reverse-drain scaling motivating this choice is recorded in
public linger drain (doc not in the source snapshot).

A single client tick rearms using the current configured interval. Updating the
configuration preserves an already armed event. Future reconnects use the current
operation timeout; armed deadlines retain their captured budget. Neither the
server lease nor a fixed outage duration creates a client watch expiry.

Remote error history is independent of liveness. Reconnect can clear last_error;
queued callbacks retain their captured errno and remain subject to cancellation.
Local cancellation controls future callback admission without joining a running
callback; watch_flush retains the independent callback barrier. Async unwatch
applies local cancellation in its owned terminal path before publishing the
completion, strengthening the reference deferred-cancel timing while retaining
required cancellation-before-user-AIO-callback order. Completion-only wait
therefore observes cancellation too; this observable difference is explicit.

Native setup capacity remains separate from established linger population.
Transient control pressure retains ordered pending work and does not drop tick
intents, fail a valid handle or create a permanent established-watch ceiling.
Scheduling work stays bounded per reactor visit. No dormant unused wiring ships.

## Rationale
The existing single coordinator owns the ordering and routing invariants. A
separate protocol state machine expresses the different public contract without
changing strict native callers or duplicating transport/reply code. Independent
local action identities permit exact stale-reply rejection while retaining the
wire's modulo-u32 registration generation.

## Consequences
- + Kernel TCP/io_uring/RDMA and C/C++ sync/async share one routing/order owner.
- + Public timing, health, callback and reconnect contracts become explicit.
- - Pending ping ownership and recoverable error events require separate lifetime
  tracking from a registration operation and from terminal native errors.
- - Float interval conversions require checked representation; unsupported
  nonfinite/overflow arithmetic cannot be treated as disable or a default value.

## Alternatives
- Increase a reconnect constant: preserves an unsupported client expiry.
- Reuse the strict lifecycle with magic sentinels: conflates different state and
  callback contracts and cannot represent overlapping ping operations.
- Add an independent FFI watch driver: introduces a second dispatch/resend owner.
- Skip pings at a fixed credit ceiling: can create a server expiry absent in the
  reference, rather than recoverable coordination pressure.
