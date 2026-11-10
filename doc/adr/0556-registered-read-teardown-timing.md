<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0556 Compile-time bounded registered READ teardown timing

Status: accepted, amended (am. 1)
Date: 2026-10-25

## Context

Shallow-queue placement remains slower than SEND in measured cases. Thread
profiles and reduced provider-call counts do not attribute asynchronous waiting.
The measured baseline verification/control worker publishes each answer but
notifies its owner after draining the job queue; its latency contribution is
unproven.

## Decision

- `rados-rt/rdma-placement-timing` enables software wall intervals from accepted
  peer terminal proof to observed LOCAL_INV retirement, enqueue to worker start,
  verification/provider teardown, and answer readiness to owner dequeue. Rustdoc
  defines the authoritative API and interval limits.
- The owner sample queue is preallocated to worker admission capacity; overflow
  increments an explicit counter and never changes completion ownership.
- The placement probe collects at most its phase operation count, exposes
  sample loss and reports phase distributions after measurement.
- Ordinary builds compile out timestamps, sample storage and diagnostic APIs.
- Diagnostic clocks do not change notification, CQ or source-posting policy.

## Rationale

The first bounded attribution step isolates post-LOCAL_INV work without a
cross-crate trace protocol or file I/O on progress. Measuring wall intervals
across the worker boundary captures scheduling as well as execution. Separate
features and artifact metadata distinguish instrumented evidence.

## Consequences

- + No registration keys, addresses, payloads or authentication data are sampled.
- + Missing samples remain visible; queues cannot grow without bound.
- - Clock reads and sample collection perturb diagnostic runs.
- - BIND, WRITE/CQ, receipt and logical publication delays still require
  additional attribution; the retirement interval includes software/scheduling,
  and answer wait alone cannot prove wake delay.

## Alternatives

- Immediate wake-policy change: measured causality and a lost-wake proof missing.
- Unbounded per-request event logging: adds allocation and I/O to progress.

## Amendment 1 — local retirement interval

Date: 2026-10-26. The authenticated peer-terminal acceptance timestamp stays
with the attempt until completed LOCAL_INV permits detached verification. The
result reports that wall interval separately from worker queue/finish/answer
intervals. Failed or mismatched proofs do not start it. Only the diagnostic
feature includes its timestamps/state. Old reports keep this phase explicitly
unavailable instead of manufacturing zero; malformed distributions exit 1.

Rationale: matched kernel scheduler traces show worker handoffs for both SEND
and placement, so those handoffs alone do not identify the placement gap. The
previous clocks exclude local invalidation. No wake, CRC or retirement policy
changes follow from collecting the missing interval.
