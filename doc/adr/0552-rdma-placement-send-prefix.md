<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0552 Placement retains an older SEND prefix under backpressure

Status: accepted
Date: 2026-10-24

## Context

A placement reply can arrive while older serialized output remains unsent on
its connection. SEND credits, SQ space and shared send slots can be exhausted
transiently. The runtime contract already requires queue-full admission to
pause; a capability error does not describe that condition.

## Decision

- Each admitted transport owner retains the eligible older SEND prefix at
  handoff, separately from later output, alongside its source pieces and grant.
- No WRITE, including one of a later owner, overtakes a blocked older prefix.
  CQ/credit progress resumes the prefix and then WRITE admission.
- Source preflight refusal remains terminal before any WRITE; it preserves
  older output and queues the exact ordered RETIRED error.
- CANCEL while the prefix is blocked closes WRITE admission. Retirement proof
  remains ordered after that prefix and every accepted WRITE completion.
- Retired owners cache the empty prefix queue with their source resources;
  metadata capacity is reused. No payload copy, provider registration,
  timer, retry or concurrency cap is added.

## Rationale

Freezing the prefix gives it a stable boundary: later output cannot extend the
wait or pass the placement reply. Existing provider progress supplies the wake
when SEND becomes writable. Retaining the owner preserves source and grant
ownership without turning ordinary flow control into an application failure.

## Consequences

- + Deeper client queues retain the same operation/retirement contract.
- + Kernel NVMe and SPDK share the corrected KNet path.
- + Prefix capacity is retained across warmed attempts.
- - Sources and prefix buffers remain owned while the peer cannot receive.
- - Initial metadata high-water growth may allocate; qualification remains in
  the performance record (doc not in the source snapshot).

## Alternatives

- Reject pressure as unsupported: misreports a supported operation.
- Fall back to inline payload: violates the promised placed-result contract.
- Drain a mutable later-output queue: loses the handoff boundary.
- Retry on a timer or cap request depth: hides the flow-control error.
