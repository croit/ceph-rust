<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0520 Compatible watch delivery and ACK population follows owned work

Status: accepted
Date: 2026-10-22

## Context

Compatible watch delivery still applies independent event, callback, setup and
ACK population limits. These can fail otherwise valid work while the application's
callback is slow or native control staging is occupied. The own-words contract is
compatible-watch-delivery-population.md, based on RC19/173/176 and pinned logical
throttle lifetimes.

## Decision

- Compatible event/callback count and total retained bytes follow owned work;
  retain checked accounting, real allocation failures and per-event validation.
- Registration/setup metadata grows independently of native control staging.
  Publish each async watch's cookie before returning accepted admission.
- Retain ACK request, context, original deadline and API waiter in FIFO order
  across native NoCredit. Return admission success only after native ownership.
- Expire every queued deadline, including behind a blocked head. Closing settles
  each queued waiter once and drops its owned payload. Work quanta are fairness
  controls, not application population limits. No retry timer is introduced.
- Explicit bounded native constructors retain their existing contracts.

## Rationale

Internal staging pressure must remain recoverable. Actual payload ownership must
span callback execution, drop and unwind. Deferring the ACK admission response
preserves error reporting without blocking the owner thread.

## Consequences

- Slow applications can retain more memory; overflow and real allocation failure
  remain errors. Public deadlines still bound unfinished operations.
- Kernel TCP/io_uring/RDMA share these owners; C/C++ and sync/async adapters keep
  their publication and completion contracts. DPDK remains compile-only.
- Lead-only live gates remain required for release qualification.

## Alternatives

- Increase fixed limits: moves the same compatibility failure to another value.
- Acknowledge ACK acceptance before native admission: loses later local errors.
