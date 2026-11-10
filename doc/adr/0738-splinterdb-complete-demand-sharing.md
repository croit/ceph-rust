<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0738 Share complete immutable Splinter scan demand

Status: proposed; offline qualification, isolated measurement pending
Date: 2026-11-08
Extends: 0728-splinterdb-cache-and-read-ahead

## Decision

When an owner-valid scan completion contains no rows beyond demand, retain that
immutable answer Arc as the latest demand answer rather than allocating another
answer/vector and cloning every Bytes pair. Empty, short, exact-width and wide
demand answers keep the existing `more` flag. Answers containing additional rows
still construct a cropped demanded answer, with `more` reflecting those rows.

This removes header allocation/reference-count work, not payload copying. Keep
the existing conservative header byte charge unchanged, even for a shared Arc;
do not spend the saved allocation on additional admission or prediction. Query,
generation, projection, owner/session, invalidation, pressure and retirement
semantics stay unchanged. No live foreign iterator is retained; no worker, cache
budget, materialization threshold, I/O policy or durability barrier changes.
Native LSM/Rocks/B-tree code paths are untouched.

Sharing also retains the original vector's spare capacity. A worker can truncate
speculation back to demanded rows without shrinking allocation; after narrow-window
pressure discards prediction, the shared demand can retain more header capacity
than the previous exact-size copy. The unchanged length-based charge is not a
hard resident-memory bound or a proof of lower RSS. An explicit capacity-heavy
fixture covers pressure both before and after completion and surviving consumer
references; no new headroom is granted to compensate for this tradeoff.

## Evidence and acceptance

Independent pointer-identity regression fails against the unconditional clone;
require exact output/EOF, unchanged charge/counters and retained-demand behavior
after pressure/invalidation. Prefetched cropped answers must remain distinct and
must not expose speculative rows as demand. Reuse existing large-value, wide-tail,
owner-credit and32competing-scan regressions.

This is avoidable work, not yet a measured bottleneck. A1025-row complete answer
saves one vector, one answer allocation and1025 pair-handle clones/drops. Measure
coreCPU/useful row, scan latency and worker request/seek counts with the chosen
batch policy held fixed. Retain adaptive-workload and single-pass limitations;
do not infer a throughput gain merely from allocation elimination.
