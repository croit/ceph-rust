<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0545 Bound independent archive tests with their own Cargo target

Status: accepted
Date: 2026-10-24

## Context

The shared test target correctly requires a global lock. Long ignored store
tests hold it while independent debug RDMA gates exhaust their 1200-second
queue wait. Read-only process inspection confirms active tests, not an abandoned
lock. Sharing that mutable Cargo target concurrently would invalidate artifacts.

## Decision

- remote-test offers isolated archive runs with an empty target inside their
  unique source snapshot and a private lock. No run writes another target or
  worktree, and archive cleanup removes its private build output.
- Require explicit CPU and memory budgets. A transient systemd scope enforces
  CPUQuota and MemoryMax; Cargo job count matches the CPU budget. Refuse a
  requested budget exceeding current available memory or CPUs.
- Retain the existing hard runtime timeout, committed-source identity and
  foreground exit contract. Existing shared-target runs keep their lock.
- Verify actual cgroup limits, inherited private lock and private target in a
  committed smoke gate before accepting the first isolated qualification.

## Rationale

Independent source/output ownership removes unnecessary cache serialization.
Process-scoped limits bound interference without stopping another task, raising
the shared lock timeout or trusting concurrently mutated artifacts.

## Consequences

- + Target provenance does not depend on another task's mutable cache.
- + Short affected-crate gates can run independently of long store tests.
- - Empty targets pay cold compilation and disk use until archive cleanup.
- - Isolated mode requires archive upload and a build host with systemd/cgroup limits.

## Alternatives

- Extend the shared queue timeout: does not remove serialization.
- Skip the lock on the shared target: breaks artifact ownership/provenance.
- Stop another task: violates worktree/process ownership.
