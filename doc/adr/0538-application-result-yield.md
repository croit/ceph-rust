<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0538 Reject application-result yield as the wake CPU regression remedy

Status: rejected
Date: 2026-10-25

## Context

Earlier-answer notifications improve shallow-depth performance but increase QD16 client CPU per byte. A candidate skipped the second epoll/io_uring transport pass when application results were ready, retaining readiness, timers, quotas and initial progress. Correctness gates passed; a fresh original-versus-combined-candidate QD16 ABBA still fails the CPU acceptance gate.

## Decision

- Remove the application-ready trait hint, queue counter, worker peek, transport policy and dedicated fixtures/scope.
- Keep independent native worker/metadata preparation and ownership fixes.
- Do not adopt the combined wake/yield candidate as a QD16 performance fix.
- Keep established batch-end worker notification; the first-answer candidate is also removed under [the notification decision](0555-registered-read-answer-notification.md).

## Rationale

The short matched-current-main experiment completes correctly but does not resolve the intended CPU regression. It compares pre-notification source with notification plus yield; it does not isolate yield's individual cost. Measurements, sample sizes and provenance are in the evidence log (doc not in the source snapshot). Retaining an unadopted scheduling policy adds code without satisfying its acceptance condition.

## Consequences

- + No unused application-ready API, completion accounting or default-off experiment remains.
- + Existing readiness/timer/progress behavior is restored.
- - Future scheduling changes still require matched latency and CPU acceptance.

## Alternatives

- Keep the yield candidate while closing other work: rejected; the intended performance gate still fails.
- Infer notification or yield call counts from CPU samples: unsupported; samples do not establish those counts.
