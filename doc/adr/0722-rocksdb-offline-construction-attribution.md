<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0722 Bounded offline scan-construction attribution

Status: diagnostic candidate
Date: 2026-11-07
Related: 0720-rocksdb-packed-scan-payload, 0718-rocksdb-batch-and-page-stage-profiling

Two packed-payload live pairs changed sign. Existing page walk includes builder
finish/slice creation and closure cleanup, not just RocksDB iteration. More
identical repetitions cannot identify allocation/copy/iterator costs.

Add test-only controls, never a production knob or storage/scheduling change:
fixed binary64-byte keys/value256; separate small irregular growth fixture;
production packed push/finish/drop, independently owned pair control, raw iterator
control and direct production page execution. One warmup, five bounded rounds,
128pages per round,45s deadline; run alone in release. Assertions/output are
outside timed regions except immediate unexpected-error handling.

Reuse the Store test binary's System-backed, thread-local allocation counter.
Count Rust allocation/reallocation requests and requested bytes, NOT live bytes,
peaks, memcpy volume, native RocksDB allocations or another thread's allocations.
Do not install a second global allocator. Time whole phases, not individual keys;
record elapsed/thread CPU and invalid CPU readings separately. Include an empty
measurement control. Existing page-stage counters remain an overlapping internal
reference, not extra summands. Report capacity charges and exact byte totals.

Validate every returned pair, page boundary and binary continuation independently.
The separate-pair control is a simple representation, NOT reconstructed historical
implementation. Small warm DB data does not model live SST/cache/debt or worker
scheduling. The test allocator differs from production mimalloc; timing is only
local attribution evidence. Do not subtract lanes as an exact decomposition or
claim an OSD speedup from allocation counts. Preserve all negative findings.
