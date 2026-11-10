<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0711 Borrow RocksDB scan candidates until selection

Status: proposed; worker-cost reduction observed, end-to-end improvement unproven
Date: 2026-11-06
Amends: 0677 (worker-local candidate selection only)

## Context

Settled first-five comparison still has a slower RocksDB scan. The worker copies
each candidate base key into Bytes, clones it for merge selection/output/cursor,
and replaces the owned cursor every entry. This also copies candidates that a
newer overlay hides. The monotonic stream merge already advances every stream
equal to the selected key, so only initial seek exclusion needs a cursor check.

## Decision

Borrow base iterator keys and immutable overlay keys during candidate selection.
Apply exclusive-start semantics once after seeking, validating key shape first.
Keep candidate references strictly before iterator mutation. Advance every point
stream equal to the selected key and advance the base when it supplied that key;
range-tombstone seeks remain forward-only. No owned per-entry cursor is needed.

Copy a base key only into an emitted owned result or owned continuation. Overlay
keys retain their existing shared ownership. Values, response charging, page and
owner-slice limits, encoded retries, worker handoff and iterator lifetime are
unchanged. No shared page arena, cross-RPC iterator, zero-copy borrowed answer,
memory-budget increase or native-LSM/durability change is introduced.

## Validation

Require existing binary prefix/object isolation, hidden base/range reinsertion,
first-unreturned continuation, tight credits and batch-cap regressions, plus an
independent three-overlay oracle across exclusive/inclusive initial cursors and
small page boundaries. Measure the unchanged first-five profile with fresh
sequential arms and report worker CPU/time, scan latency and whole-cell results.
Structural allocation removal is not a speedup claim before that comparison.

The first-five trial passes its exact oracles and settlement checks. Worker page
time/CPU decrease, but effective receive placement changes and foreground scan
time does not improve. Retain this as a provisional worker-local simplification,
not an established throughput win; match or account for receive placement before
further end-to-end attribution. A later same-scan-code serial control shows a
similar worker-CPU shift, further limiting attribution from the first pass.
See ../perf/rocksdb-first5-worker-costs.md.
