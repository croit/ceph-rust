<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0676 Reuse merged RocksDB scan continuation

Status: proposed; scan performance candidate
Date: 2026-11-05
Amends: 0681 (bounded read replies), 0675 (readiness-driven retries)

## Context

A 1024-entry OMAP RPC uses256-entry worker pages and256-entry owner slices. The
worker already discovers the first unreturned live entry to report more=true.
The owner discards that key, yields before processing the page-end flag, and
fetches a fifth worker page only to find continuation/end. A reopened real-store
regression fails the preceding code: five worker calls for exactly1024 entries
instead of four. The previous1M campaign measured5120 worker pages/1024 scan RPCs.

## Decision

- Actual RocksDB worker page replies carry end, an owned first-unreturned merged
  live key, or unknown-more when that key would exceed remaining answer credits.
  Do not copy the lookahead value. Point answers and external wire format stay
  unchanged; no live iterator crosses threads or survives an RPC.
- Charge owned continuation bytes in the worker answer and retained memo. If the
  key does not fit worker credits, preserve the previous bool-only paging path
  rather than allocating beyond the envelope or rejecting a previously valid page.
- A caller truncating a page gets its first unconsumed entry as continuation, not
  the worker's later endpoint. Preserve binary ordering, prefixes, object bounds,
  half-open tombstones, newer reinserts and queried-overlay snapshots.
- Record final continuation/end in the request memo before a slice yield. Once
  output count/known byte limit is reached, reuse that continuation; exact-end
  pages finish without another worker lookup. Keep existing owner CPU slices,
  request/session/revision identity, mutation invalidation and cancellation.
- No cache-budget/buffering/prefetch/sharding/WAL/materialization/ACK/format change.

## Qualification

Independent ordered output and worker-count regression covers1023/1024/1025/2048
entries and inclusive next-page cursors after reopening. Additional fixtures cover
merged binary lookahead, deleted base keys/newer reinserts, prefix/object ends,
truncation, limited answer credits and an oversized lookahead value. Existing
competing scans, cache eviction, staged mutation/clone, quota/release and restart
tests remain required. Then build on the build host, transfer verified artifacts, run fresh
1M Phase1 RocksDB control/candidate plus unchanged nativeLSM/classic sequentially.
Fewer worker requests are a complexity result, not an assumed wall-time speedup.

## Sharding and reporting boundary

Each store shard has one owner core (`shard % cores`); four formatted shards and
four configured cores give1:1. Foreground Rocks workers are owner-affined, but
`Env::new` wraps the shared default background pools, not private per-owner pools.
The fresh control observed one LOW/HIGH pair pinned to CPU5; background execution
can couple shards. No background-pool change is included here.
Phase1's one object stays on one PG/shard; it does not use all
cores for one scan. No cross-core scan partitioning is introduced.

Per-operation mix-delete totals use the client's exact latency_sum_ns as summed
RPC busy seconds, not exclusive wall time or CPU attribution (Phase1 suite docs).
Report insert/update/delete/read totals separately and also the cell wall time.

## Initial results (single pass, not statistical qualification)

Fresh1Mcontrol/candidate/nativeLSM/classic completed36cells, zeroerrors, matching
corresponding model checkpoints. Candidate allthreefullscans used4096workerpages
instead of5120/control. Summed scan foreground10.255587→9.000112s(-12.24%);
sampled scan-window OSDCPU6.64→5.69s(-14.31%, not foreground-exclusive).
Allcandidatefullscans remained slower than freshclassic. Wholechainforeground
104.307→106.329s(+1.94%); sampled totalCPU110.30→110.21s and namespacewrites
14.697→14.758GB show no demonstrated whole-workload CPU/write improvement.
NativeLSM/classicfreshwholechain109.824/112.487s; totalCPU74.23/80.53s,
namespacewrites7.646/6.021GB. Do not attribute namespacebytes to Rocks-only/NAND.
Build-host artifacts were hash-verified on the OSD host; all12ownedserviceidentitiesabsent and storage
preservationpassed. No power-loss/higher-QD/statistical qualification implied.
