<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0555 Registered READ workers notify after draining their job queue

Status: accepted
Date: 2026-10-25

## Context

The measured baseline publishes each verification answer but wakes only after
draining the worker job queue. Instrumented QD4 answer-ready to owner latency is recorded in doc/perf/adr-measurements-moved-20261028.md; it does not establish notification causality.
Existing destination retirement, integrity and bounded admission remain mandatory.

## Decision

- Notify once after the teardown worker drains its current job queue. Every
  accepted job retains a reserved answer slot and publishes before notification.
- Keep the event-driven reactor and sticky worker-unpark contract. No shared
  per-answer arming RMW or registered-answer selector handshake remains.
- Retain eager worker/registry preparation, bounded ownership and CRC verification.
- Always unpark carried receive helpers after selector return, including errors.

## Rationale

The first-answer/actual-sleep candidate fails the measured QD16 CPU acceptance
condition. Its extra owner cost remains in READ call stacks; barrier sampling
alone does not explain it. The established batch-end notification policy needs
no additional shared atomic handshake. Exact measurements and rejected revisions
remain in doc/perf/rdma-high-performance-20261024.md.

## Consequences

- + Removes an unadopted performance regression and its model-only dependency.
- + No payload pass, allocation, lock or runtime tuning policy is introduced.
- - Batch-end notification can delay an earlier result behind later queued jobs.
  Further changes need matched CPU and latency evidence before integration.

## Alternatives

- Wake for every answer: unnecessary notifications while the owner is active.
- Test queue emptiness before publishing: concurrent drain can lose progress.
- Arm with a release store alone: no acquire edge for an earlier publication.
- First-answer notification with arm/recheck: rejected by the QD16 CPU gate.
