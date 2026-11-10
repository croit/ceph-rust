<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0546 Reject per-WR-signalled linked WRITE posting

Status: rejected
Date: 2026-10-25

## Context

A candidate groups prepared placement WRITEs into linked provider posts while
retaining per-WR signals, markers and source leases. A matched-artifact ABBA
comparison includes reversed SEND/placement method rounds and both backing
kinds; measurements (doc not in the source snapshot) show fewer
provider calls without reliable workload improvement.

## Decision

- Placement keeps the existing per-piece WRITE posts. The candidate's linked
  posting API, native list adapter, runtime use and candidate-only fixtures are
  removed; no default-off batching experiment remains.
- Existing successful/failed source-lease ownership fixes remain.
- Generic artifact-order comparison/reporting and independent bad-WR pointer
  validation remain useful outside the discarded posting candidate.

## Rationale

The candidate does not establish a consistent throughput, latency or client-CPU
benefit. Raw OSD CPU changes are mixed, and one deeper-queue case has worse
observed medians. Reduced call count alone does not justify the added machinery.

## Consequences

- + Existing ownership, queue ordering and single-WR admission remain intact.
- + Negative evidence prevents treating provider-call count as latency proof.
- - Shallow-queue placement performance still needs phase attribution.

## Alternatives

- Keep an unproven default-off candidate: violates the project experiment policy.
- Change CQ signalling or source grouping too: requires separate ownership proof
  and measurements; this result does not qualify those changes.
