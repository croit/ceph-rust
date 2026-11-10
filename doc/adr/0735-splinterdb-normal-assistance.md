<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0735 Small normal-maintenance assistance threshold

Status: proposed; isolated experimental candidate, qualification pending
Date: 2026-11-08
Supersedes: only the scale0 choice in 0734-splinterdb-maintenance-offload

## Context

Task-attributed diagnostics justify investigating ordinary foreground normal work,
not replacing the existing normal helper with a memtable helper. They do not show
how often one task waits, distinguish every ordinary/forced call or predict speedup.
The pinned contract (doc not in the source snapshot) supports a finite
threshold without suppressing forced progress or zero-worker memtable assistance.

## Decision

When the existing default-off normal-maintenance option is admitted, set the
public queue scale to101 instead of0. Keep normal workers1 and memtable workers0.
101 is the smallest scale that defers one waiting normal task with one helper;
ordinary assistance remains eligible at two queued tasks. Maintenance-off retains0.
Do not expose arbitrary scales, add helpers, alter placement or patch the dependency.
Read back helper counts and scale from the live configuration for qualification.

Retain existing registration/stack/read-budget admission, cache sizes, soft memory
target, raw-statistics refusal, selected-engine gates and native WAL authority.
Both blocking foreign barriers, watermark/native publication, close ownership and
failure retention remain unchanged. Buffered stays default; direct stays explicit.
No batching/cache/I/O-policy changes are bundled. Native LSM/RocksDB/B-tree paths
do not consume this configuration. No on-disk identity or format change.

## Consequences and alternatives

"Small threshold" is not a hard backlog/latency bound. Deferral may retain more
work/memory. Forced paths still do normal work on the file worker. Compare fresh
matched all-cell8xQD4 datasets, throughput/tails and settled completion/debt; do not
claim faster foreground alone as a win. Keep the old serial-scan result separate.
Default-off status is unchanged; a losing experiment is not a new default.

Rejected: scale1/100 (no deferral at Q1), unbounded suppression, another worker,
memtable-only replacement without supporting attribution, and removed barriers.
Native configuration receipts plus immediate barrier/close/reopen and abrupt-prefix
regressions qualify integration; no deterministic actual Q1/Q2 dispatch fixture is
claimed. Physical power loss, native thread/close failures and full native-ACK crash
replay with an active helper remain separate open gates.
