<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH -->
# 0713 Opt-in RocksDB materialization profiling

Status: proposed
Date: 2026-11-06
Amends: 0675

## Context

Combined materialization time cannot distinguish batch construction, synchronous
DB writing and owner/worker waiting. Native commit-latency aliases do not time
external RocksDB writes. Endpoint write-stopped gauges cannot establish whether
transient stalls occurred. Instrumentation itself has a measurable cost.

## Decision

- Startup option `flashstore_rocksdb_profile=false` opts into bounded worker and
  owner diagnostics. It is not a tuning or durability switch. Default-off retains
  the existing DB statistics configuration and does not read thread CPU clocks.
- Enabled workers collect split batch-build/write elapsed and thread CPU totals,
  final point/range mutation counts and serialized batch bytes. CPU clock errors
  are counted separately; only complete monotonic samples count as CPU samples.
- Queue, completion-consumption and progress-marker submission waits are separate
  totals. Overlay-full backpressure records union intervals from first observed
  refusal until the owner observes capacity again, not summed per-RPC latency.
  Snapshots include an interval still open; dropping an owner does not invent a
  successful publication or completed request.
- The existing 250 ms worker diagnostic cadence samples L0 files, immutable
  memtables, delayed-write rate and cumulative stall/WAL/compaction/flush tickers.
  Profiling enables counter-only RocksDB statistics, excluding histogram/timer
  statistics. Separate validity, age and error fields distinguish unknown from
  zero. Sampling never queries RocksDB from owner/admin code.
- Keep native memtable ownership and policies, native durable ACK, both WALs,
  synchronous batch/watermark persistence and publication ordering unchanged.
  Never force an SST flush or drain compaction for a diagnostic measurement.
- Report instrumented runs as instrumented. CPU time, elapsed time, estimated
  compaction debt and blocked intervals are not interchangeable quantities.
  Gauges and cumulative counters retain distinct interpretation.

## Rationale

The worker is the existing blocking boundary. Fixed-size counters and rare owner
interval timestamps avoid per-key diagnostic allocation and property queries.
Default-off isolates library-statistics and clock-reading overhead from ordinary
production operation. Native LSM does not instantiate this profiling state.

## Consequences

Profiling can perturb measured RocksDB throughput. A missing property invalidates
only the profiling sample, not base debt/admission information or durability.
L0/memtable gauges are sampled and cannot identify every stall's reason. The
combined stall ticker supplies elapsed evidence, not a complete event trace.

## Alternatives

- Attribute external sync to `kv_sync_lat`: rejected; that is native submit to
  durable latency and excludes pre-admission waiting.
- Always enable detailed RocksDB timers: rejected; unnecessary production cost.
- Infer stall time from a final stopped gauge or worker off-CPU time: rejected;
  neither establishes the cause or duration of the intervening wait.

## Open questions

Which portion of overwrite cost is DB writing, compaction contention, encoding or
wrapper backpressure? Runtime evidence is required; no optimization is adopted.
