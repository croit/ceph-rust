<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH -->
# 0681 Selectable RocksDB OMAP engine

Status: proposed
Date: 2026-11-04
Extends: 0610 (OMAP engine scope), 0021 (native transaction durability).

## Context

Compare actual RocksDB with the native B-tree/run and OMAP LSM engines without
replacing either. The selected engine covers all OMAP, including PG metadata
represented as OMAP. Object data, onodes, xattrs and OMAP headers stay native.
RocksDB's blocking filesystem API and background threads cannot execute directly
on the daemon's owner-core request path or acquire an unaccounted CPU budget.

## Decision

- Engine choice is a persistent format property, selected at fresh provisioning,
  not a runtime interpretation of existing OMAP. Existing native stores retain
  their existing behavior. Missing support, mismatched configuration, a missing
  database or a wrong database identity must refuse mount, never select a fallback.
- One RocksDB database per native store shard. Object ID and key bytes form one
  ordered keyspace; reserved metadata keys cannot collide with OMAP keys. Bind
  each database to the native store identity and shard. Do not silently create a
  replacement database when mounting an existing store.
- RocksDB files require an explicit filesystem location on durable admitted
  storage; a raw native LV/namespace is not a filesystem. Provisioning and tools
  must carry this dependency explicitly. No automatic filesystem creation,
  namespace formatting, host tuning or existing-directory erasure.
  Local ext4/XFS may use direct kernel NVMe or the bounded partition-backed
  linear-LVM mapping of ADR 0646. Mounted-LV validation is read-only and
  non-exclusive, shares the raw path's identity/durability/overlap checks, and
  never constructs a raw I/O controller. Administrative mapping changes while
  mounted/in use remain forbidden. Other stacked and remote storage refuse.
- The native WAL remains the transaction authority for OMAP together with object
  data, onodes, xattrs and PG metadata. Do not independently acknowledge the
  RocksDB half of a native transaction. Do not materialize a record in RocksDB
  until that native record and its dependencies are durable.
- A RocksDB atomic batch contains OMAP mutations and a monotonic native LSN
  watermark. Its WAL is enabled and synchronously persisted before its watermark
  can release native redo. Native root/checkpoint and RocksDB watermark together
  bound WAL reuse; replay must include unmaterialized OMAP even below the native
  tree checkpoint. Replayed records at or below the database watermark are not
  applied twice. The watermark describes a complete OMAP prefix. Require
  `native manifested flushed_lsn <= DB watermark <= recovered native frontier`;
  a stale restored database below the native marker is not recoverable from an
  already reclaimed WAL and must refuse. An ahead-of-recovered-native-log
  watermark is corruption, not permission to expose independently committed
  metadata.
- Applied but not yet materialized operations remain readable in bounded memory.
  Transaction-local reads see their own staged operations. Point/range deletes,
  clear/remove, scans, clone and replay retain the existing ordering semantics.
  Native WAL and memory pressure must apply backpressure before unbounded growth.
- Blocking RocksDB calls run outside the PG owner loop, behind bounded concrete
  request/completion messages. Immutable buffers may cross the boundary; native
  Store handles, allocator and authoritative publication remain owner-side.
  Reads park/resume rather than hiding a blocking call behind an async-looking
  wrapper. Completion delivery must wake an otherwise sleeping owner.
- Read pages carry cheap immutable snapshots of only the queried object's
  owner-side overlays. The worker merges them with the DB iterator and seeks past
  range tombstones. A concurrent mutation can copy that bounded object's snapshot
  (COW). Request scan memos retain admitted output/cursors across cache eviction
  and competing requests; object mutations and session completion/cancellation
  invalidate them. Equivalent planning retries preserve their own staged-view
  revision, including a source mutation followed by clone. They are not a database
  mirror. One admitted read session per shard owns completion credits for points
  and scans together, preventing mutually blocked partial responses. Aggregate
  request credits are twice the DB memory share; scan charging includes retained
  capacity, output copies and decoded entries. Compound point answers also have
  a quarter-DB-memory sublimit; a single answer may exceed that sublimit within
  the aggregate envelope. Explicit nested preparation scopes share the outer
  logical credit owner but retain their own memo/query identity; finishing a child
  does not release its parent's answers. Worker requests carry the remaining
  answer budget. Pinned point reads stop before copying an oversized aggregate
  batch; page reads check sizes before copying DB values. Point copies and scan
  outputs are charged conservatively for overlapping return representations.
  Oversized responses fail explicitly instead of evicting
  their own progress. Completed point answers are protected before first
  consumption. Abandoned sessions are reclaimed on an owner poll/admission after
  30s without an execution attempt; ordinary cache TTL does not discard admitted
  scan progress. Worker snapshot iterators advance monotonically through point
  tombstones, avoiding repeated suffix traversal.
- Worker/background thread CPU and memory use is explicit and bounded within
  the configured service budget. Batch native durable records rather than adding
  a synchronous RocksDB write per OMAP key. Keep compression, Bloom/cache,
  memtable, compaction and stalled-write costs visible in comparisons.
  Worker-sampled DB properties carry validity, age and error counts; a missing,
  changing or stale sample is not zero background debt. Owner publication debt
  and DB flush/compaction debt are separate diagnostics. Native OLSM prefetch
  statistics must not describe a RocksDB-selected shard.
- External-filesystem available space and materialization/compaction headroom
  constrain admission before native logging, independently of raw-store free
  space. Shared filesystem capacity is not multiplied by the shard count. Keep
  publication/deletion progress room; predictable fullness is not an I/O-failure
  excuse. Unexpected I/O failure remains fail-stop.
- Offline read-only tools must not open the database read-write, advance its
  watermark, compact, or heal it. They must still present native redo above the
  external watermark through the RAM overlay. Corruption and I/O failures propagate to the
  native store's fail-stop path. No automatic engine conversion or deletion.

## Rationale

Retaining one native transaction authority avoids a dual-write acknowledgement
gap. A durable database watermark permits idempotent native redo and bounds the
retention needed when RocksDB lags. The worker boundary isolates blocking I/O;
shard identity and owner-side publication preserve native ownership.

## Consequences

RocksDB is an additional persistent dependency, not a drop-in replacement for an
in-memory map. An engine is complete only when daemon startup, provisioning,
replay, checkpoint/WAL retention, nonblocking reads, capacity reporting and
offline tooling agree on that dependency. Optional selection is not permission
for a partial or less durable implementation.

## Alternatives

- Independent RocksDB commits before native durability: rejected, can expose
  uncommitted metadata after a crash.
- Disabling both WALs or dropping native redo after an unsynced database write:
  rejected, loses acknowledged operations.
- Blocking DB calls on the PG core: rejected, stalls unrelated PGs on cold reads
  and compaction pressure.
- Replacing native LSM/B-tree implementations: outside the requested scope.

## Qualification and open questions

Require independent Rust vectors for binary key isolation, ordering, range bounds,
batch atomicity, watermark/identity refusal and restart; store-level OMAP parity,
transaction overlays, clone/removal, full/backpressure and read-only tooling;
crash cuts around native durability, DB sync, checkpoint/root and WAL reuse.
Daemon startup and mixed workloads must use the real selected engine.

Performance qualification is separate from implementation. Compare matched
shards/cores, whole-service CPU, memory, durability, datasets and client workload;
include p99 latency, CPU/key, physical write amplification, compaction debt and
post-ACK settlement. No speedup claim follows from compilation or a store-only
test. Live campaigns need separate target/action authorization.

Production admission initially accepts ext4/XFS on a direct kernel NVMe namespace
or partition with no volatile cache, and refuses symlink/cross-filesystem DB
descendants. It does not admit stacked/remote storage or qualify physical power
loss. Worker-owned space leases survive endpoint shutdown/timeouts until DB
destruction. Physical OMAP accounting samples allocated DB-file bytes plus native
buffers; it is not the scrub-derived logical OMAP byte count.

Implementation and offline checks are recorded with the feature change. Live
startup, physical-power-loss and matched performance qualification remain separate.
