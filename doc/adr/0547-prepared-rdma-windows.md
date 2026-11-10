<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0547 Prepared reusable RDMA destination windows

Status: accepted
Date: 2026-10-24

## Context

The native registered READ path allocates a type-2 MW during request progress
and deallocates it after every retired attempt. These provider control calls
and completion-marker allocations are avoidable. ADR 0471 requires ordered
peer retirement and LOCAL_INV completion before reusing an advertised window.

## Decision

- Native host registration prepares one type-2 MW and completion marker on the
  control thread, before returning the registration to its caller.
- Retired attempts return the same unbound MW to the parent registration.
  The next READ consumes that prepared resource without allocating a provider
  object or completion marker. The MR remains registered across attempts.
- Final destination release deallocates MW before deregistering the parent MR.
  Uncertain MW release retains the parent, backing, device and registration charge.
- Missing peer proof or failed LOCAL_INV still quarantines the live window.
  Key wrap never replaces the ordered peer-retirement requirement.
- Existing low-level unprepared host registration remains available for SEND
  and provider tests; native READ submission rejects unprepared destinations
  before performing a provider allocation in progress.

## Rationale

One reusable window matches the existing exclusive allocation lease. It removes
provider setup from steady-state request latency without a global pool, lock,
address cache or change to the wire protocol.

## Consequences

- + No MW create/destroy per native READ; no completion-marker allocation per rebind.
- + CPU access returns only in the unbound state after the existing retirement proof.
- - Each registered destination retains one provider MW until final release.
- - Independent subrange concurrency and GPU registration need separate ownership work.

## Alternatives

- Per-attempt control-thread MW creation: adds queue/wakeup latency for reusable memory.
- Rebind before peer retirement: unsafe after rkey wrap; rejected.

## Open questions

- Physical-provider performance and GPU MW feasibility remain in the RDMA readiness review.
