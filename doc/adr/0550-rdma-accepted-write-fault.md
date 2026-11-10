<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0550 Target the accepted WRITE's QP in lab fault gates

Status: accepted
Date: 2026-10-24

## Context

Client descriptor commitment does not prove peer reception or accepted WRITEs.
The existing generic QP-error injection chooses a core's lowest QPN during CQ
polling, which cannot target a placed READ's accepted source access reliably.

## Decision

- The existing lab-only fault-inject feature adds an accepted-WR fault. Only a
  successful provider WRITE post consumes it, after installing its retained
  completion/source owner and before the caller can post further pieces.
- Move that exact WRITE's QP to ERR, fail its typed work, and notify the link
  through the existing fault path. Keep NIC-access owners through retirement
  or quarantine; never produce an ordinary success receipt after injection.
- `rdma fault write-qp-err [count]` arms the process-wide fault on the control
  core. Count zero queries pending faults, successful ERR transitions and
  refused ERR transitions. Scattered replies take maxima because all cores
  observe the same process-wide counters.
- The RXE gate checks rejected admission leaves the fault armed, accepted WRITE
  consumes it on the exact QP, and failed source ownership cannot be returned.
- Production builds exclude this injection and its counters. The full-stack
  gate must check the transition counters and client retirement/quarantine;
  command acknowledgement alone is not proof of an injected failure.

## Rationale

An accepted post supplies a concrete boundary without sleeps, payload staging,
additional progress waits or timing-dependent selection among live QPs.

## Consequences

- + Failure evidence identifies a WRITE accepted before the QP transition.
- + No production data-path branch or counter is added.
- - Successful ERR transition does not prove outstanding NIC work at that
  instant: a WRITE may already have reached the peer before ERR takes effect.
- - Forced provider transition and failure bookkeeping do not qualify physical
  link-loss behavior, delayed stale descriptors, or GPU revocation.

## Alternatives

- Sleep before generic QP injection: neither targets the attempt nor proves an
  accepted WRITE, and introduces timing dependence into ownership evidence.
