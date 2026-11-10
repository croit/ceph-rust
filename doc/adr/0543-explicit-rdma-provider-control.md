<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0543 Explicit cold provider readiness on the existing C worker

Status: accepted
Date: 2026-10-25

## Context

Native provider warm-up is asynchronous and historically best-effort: a later
session offer reports its failure. Explicit registration clients need to
separate pending preparation from failed setup without allocating a dummy
buffer. One client owns one provider for its selected local RDMA address.

## Decision

- Provide explicit cold preparation and a side-effect-free readiness query in
  the native kernel client and the rustyrados C extension namespace.
- Dispatch C calls through the existing bounded control mailbox/native worker.
  Authorize them from the worker's actual startup RDMA flag, not later config.
- Report idle, preparing or ready for the exact requested address. Preserve
  setup I/O kind and OS errno, including missing wake handles, thread start,
  disconnected setup results and environmental address failures.
- A query never starts or retries setup. Explicit preparation may retry an
  environmental failure; permanent failures keep the existing per-address cache.
- Reject another address while one setup is pending or a different provider is
  active. Readiness never identifies the wrong PD as usable.
- Retain ordinary SEND defaults and existing first-dial warm-up behavior.
  Preparation registers no caller buffer and neither enables nor certifies
  placement, MW/import/revocation capability or GPU access.

## Rationale

Typed completion state avoids treating failure as endless pending work. The
existing worker and provider setup thread already supply ownership and wake-up;
no extra connection, progress thread, caller allocation or timeout is needed.

## Consequences

- + Callers can reject not-ready registration before transferring allocation ownership.
- + No repeated provider work, payload copy or hot-path lock is introduced by a query.
- - Explicit clients must query asynchronous completion and handle real setup failures.
- - ABI/build checks are separate from connected-library and registered READ qualification.

## Alternatives

- Probe with an allocation: introduces unnecessary memory ownership and admission work.
- Read current configuration as runtime state: post-connect edits do not reconfigure the worker.
- Return not-ready after failure: loses the error and encourages indefinite polling.

## Open questions

- Retained host C registration/request/batch implementation and connected consumer proof.
- Separate provider MW/revocation/GPU feasibility and physical performance qualification.
