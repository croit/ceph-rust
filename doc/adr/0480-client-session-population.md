<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0480 Client sessions follow active cluster peers

Status: accepted
Date: 2026-10-21

## Context

Review M1 found that the default 32 cached OSD sessions permanently terminated
the client on a 33rd primary. A cluster's OSD population is not an operation
concurrency limit. Established watches may keep many sessions active.

## Decision

Session and native kernel transport counts are initial reservations.
An idle healthy peer with no application lease, output or pending events may be
replaced; busy populations grow on demand without a fixed peer-count ceiling.
Flights, watches and OSD commands retain exact-session leases through their use.
Allocation pressure during route acquisition returns Wait, preserving the handle.
Encoded/staged byte budgets and per-step work budgets remain independent.

## Rationale

An ownership lease proves safe eviction across reply, cancellation and watch
lifetimes. Growing for protected peers preserves concurrent work and long-lived
watch connectivity. Reusing unprotected slots avoids retaining every historical
OSD connection.

## Consequences

- + Sequential and concurrent primary populations can exceed initial reservations.
- + Existing kernel TCP, io_uring and RDMA close paths retain transport ownership.
- - Session memory follows actual active peer demand; initial count is no hard cap.

## Alternatives

- Larger constants preserve the same cluster-size failure.
- Evicting busy peers introduces avoidable replay and breaks watch connectivity.
