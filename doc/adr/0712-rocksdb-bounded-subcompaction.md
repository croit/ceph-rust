<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH -->
# 0712 Bounded parallel RocksDB L0 compaction

Status: proposed; first-five live correctness checked, performance qualification open
Date: 2026-11-06
Amends: 0678 (internal compaction parallelism only)

## Context

Retained instrumented overwrite evidence identifies L0-file slowdowns, not just
an ambiguous stopped gauge. Overlapping L0 input cannot be drained by concurrent
independent L0-to-base jobs. The facade limits the shared low-priority pool to one
job and explicitly disables range-parallel compaction, serializing that work even
when four service CPUs are selected. Write elapsed grows much faster than CPU.

## Decision

- Permit at most two subcompactions when the already-validated explicit service
  CPU budget contains at least four CPUs. Unknown, offline and smaller budgets
  remain serial. Sparse physical CPU IDs are not interpreted as a count.
- Keep one shared low-priority job and one high-priority flush worker. Do not
  increase job count per shard or allocate additional service/support CPUs.
- Subcompaction workers are outside RocksDB's background-job limit. The single
  shared low pool plus the cap of two permits at most one additional automatic
  range worker across this facade's databases. Its affinity inherits the admitted
  background mask. No manual compaction is introduced in production.
- Preserve buffer/cache sizes, level/file/debt slowdown and stop thresholds,
  memory/space admission, WAL sync, watermark and native publication/ACK ordering.
  Do not defer throttling to hide accumulating debt. Native LSM is unchanged.

## Rationale

Parallelize the identified serial L0 bottleneck instead of raising its threshold.
The conservative two-range cap limits extra scheduler/builder overhead; four
selected CPUs admit two foreground roles and two compaction lanes, not a promise
that these CPUs are idle. Existing flush work can still compete on the same mask.

## Consequences

Transient builder/iterator memory and contention may rise despite unchanged
configured memory shares. Single-CPU/offline behavior stays unchanged. Mask and
pool ownership must remain as in0678. This is not a format, replay or compatibility
change and supplies no throughput guarantee before comparable live evidence.

## Alternatives

- Increase L0 slowdown/stop thresholds: rejected; postpones debt without proving
  higher drain capacity.
- Add independent low-priority jobs: does not parallelize one overlapping L0 job
  and broadens background concurrency across shards.
- Increase cache/write buffers or disable WAL sync: outside this candidate.
- Modify native batch formation simultaneously: rejected; loses attribution.

## Validation and open questions

Require explicit/sparse/small-budget and upper-bound regressions, actual persisted
option checks, real two-range compaction with overwrite/watermark reopen checks,
affected Store/OSD builds/tests, and matched first-five-cell LSM/Rocks verification
including p99, settlement debt, actual masks, CPU/RSS and stalls. Fresh matched
storage now meets headroom admission; the first-five comparison completed with
actual two-range compactions. After preserving an interrupted serial attempt,
an explicitly requested fresh same-layout retry completed. Lower update time,
stalls and compaction elapsed support this mechanism, but a single pass does not
establish significance or a noise distribution.
Full multi-object/tail behavior remains open; do not label the candidate qualified.
See ../perf/rocksdb-first5-worker-costs.md for evidence and limitations.
The configured bound is not an execution guarantee: range selection can choose
one subcompaction, including highly coincident overwrite layouts. Regressions
must demonstrate two actual ranges with independent bulk data and shared overwrite
sentinels; live evidence must record actual completed subcompaction counts.
