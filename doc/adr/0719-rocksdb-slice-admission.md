<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH -->
# 0719 Bounded owner-slice RocksDB scan admission

Status: accepted for implementation; performance qualification pending
Date: 2026-11-07
Amends: 0681, 0677

## Context

The request-owned encoding loop repeats ownership/idle-clock work for every
entry and allocation check. The Client and its aggregate credits remain under
exclusive owner control during consumption of already-owned page entries.
This is an implementation difference, not proof of the measured performance gap.

## Decision

- Acquire a restricted exclusive Client permit for one bounded encoding slice.
  Preserve expiry, nested-owner resolution and competing refusal on acquisition.
  Refused competitors do not renew the admitted owner's idle lease.
- Retain every growth, projected-capacity and post-entry credit check, including
  protected point answers and other memos. No budget or reservation increase.
- End the permit before querying, polling, waiting, yielding, publishing a memo
  or returning output. Bound it by the existing entry/byte quantum even for
  `list_whole`, which continues internally without a new fairness yield.
- An active slice includes OS preemption, even beyond30s. Do not expire/reacquire
  credits mid-slice. Ordinary return, error and unwind renew from a fresh exit
  observation. Drop does not clear, release, poll or wake. Forgotten destructors
  leave the previous charge/lease reclaimable by normal idle expiry.
- Preserve owner fairness yields (including terminal ones), worker batches,
  cutoff/continuation semantics, writable retry/output copies and invalidation.
  Native LSM, wire/storage formats, WAL, sync and acknowledgements are unchanged.

## Rationale

The exclusive borrow prevents another Client operation from changing admission
state during the slice. Reusing that ownership removes repeated clock/alias work
without replacing per-entry memory checks. The lease deliberately distinguishes
active execution from abandoned parked requests, rather than claiming identical
wall-clock behavior through a long OS preemption.

## Consequences

- Ownership/clock work is per bounded slice, not per key.
- An oversized first entry or OS preemption is not wall-time bounded by the
  entry/byte quantum. Idle expiry begins again at the actual slice exit.
- Actual Client/Stage/worker regressions are required; standalone prototypes and
  local calibration do not establish OSD throughput gains.

## Qualification

Eight independent Rust regressions exercise the actual Client/Stage: lease and
quota boundaries, protected/nested ownership, error/unwind/forgotten guard,
pre-completion cancellation and late output, partial expiry, writable retries,
terminal fairness and bounded `list_whole` entry/byte slices (including oversized
entries). The Unknown-continuation case injects a retained batch boundary; it is
not a new real-worker tight-credit fallback qualification. Unwind is tested at
Client, not during Stage encoding. Shared-Arc fallback remains a separate gate.

Targeted Store/native/adapter tests, Store Clippy, changed-file formatting and
production-feature consumer compilation pass. Package-wide formatting still
flags unchanged `store/tests/obj.rs`; no workspace-wide pass is claimed.
Local structural clock-count assertions are not timing measurements.
Live smoke, matched benchmarks and performance qualification remain separate.

## Alternatives

- Timestamp only at entry: stale renewal after preemption/cleanup.
- Reserve a whole page or skip per-entry checks: changes the credit envelope.
- Whole-request permit or bypass for `list_whole`: unbounded scope.
- Remove fairness yields or change reply ownership: separate investigations.
