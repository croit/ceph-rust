<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0500 Directed monitor calls have independent owners without a caller ceiling

Status: accepted
Date: 2026-10-22

## Context

The synchronous directed command/ping bridge creates an independent single-target
owner per call. A separate cluster-wide atomic permit rejected caller33 with
EAGAIN before its own operation started (removed by this ADR; no permit remains in `directed_monitor.rs`). Full librados application compatibility
requires removing that additional rustyrados-only admission policy.

## Decision

- Directed commands and monitor ping keep independent existing auxiliary owners
  without a separate per-cluster concurrent caller limit.
- Remove the permit and its now-unused atomic field/destructor. Do not replace
  them with a larger constant, retry or blocking acquisition.
- Keep selected-peer authentication, input/reply validation, deadline, close and
  output contracts. A fired timeout emits the required loud diagnostic.
- The main worker and its transport selection remain independent of auxiliary
  callers. Other command/control resource domains remain separate G12 work.

## Rationale

Each call already owns its operation and connection lifetime. An extra population
counter supplies neither protocol validation nor memory ownership and exposes an
internal fixed count as an application error.

## Consequences

- Concurrent caller work can own more connections/memory; real transport/resource
  failures remain possible and are reported through existing error paths.
- C/C++ directed command and ping share this bridge. Sync caller threads run the
  existing cold kernel selector; main io_uring/RDMA owners are unaffected.
- A committed64-command/64-ping live gate remains unrun for the lead.

## Alternatives

- Raise32: preserves the same unsupported eligibility ceiling at another count.
- Block a permit waiter: retains an unnecessary scheduling domain and counter.
