<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0609 PG stats come from staged counters, never from a walk or a queue barrier

Status: accepted
Date: 2026-10-27

## Context

Profile of an aged 1M-key omap object (tsrv2, c64 b256): `Osd::on_timer -> push_stats -> coll_stats -> object_stats ->
visibility` held 25.7 % of the primary PG core. The assumption was a periodic walk of objects computing per-object
stats. Reading the code: there is no walk. Objects, bytes and compression sums live in the collection record and omap
keys/bytes in the onode; both are updated by every txn at staging (adr 0021 am. 15) and persisted with it, so they
survive restart. The cost was `Store::coll_stats` calling `visibility(cid, None)`: a txn parked in the shard FIFO for the
collection forced `drain_queued`, a blocking queue barrier that polls the store (checkpoint, fold, compaction) on the PG
core. Under write load a parked txn exists on almost every tick, so each stats tick paid the whole store backlog.
Microbench numbers: doc/perf/adr-measurements-moved-20261028.md.

## Decision

`Store::coll_stats` reads the staged counters without a queue barrier. The values are a snapshot of the staged state;
txns still parked are counted by the next read. Counters stay the single source (no recomputation at mount, no timer
walk). A consistency walk (fsck, scrub) stays off the PG core and is not part of the periodic stats.

## Rationale

The PG stats the mon/mgr consume are periodic snapshots and already lag the op stream by the report interval; a parked,
not yet acked txn is not part of the acked state. Ceph-visible values are unchanged at every quiescent point (test:
counters equal a full walk after random ops and a restart). The barrier bought exactness for a value nobody can observe
at that precision and cost an unbounded stall of the PG core.

## Consequences

- Stats ticks no longer block on the store backlog; O(1) per PG.
- A stats read between a txn's submission and its staging omits it (one tick of lag).
- Sibling paths: EC and replicated share the collection record; SPDK and kernel tiers share the store code; scrub counts
  objects itself and does not read `coll_stats`. Not affected.

## Alternatives

- Maintain a second set of counters at park time: duplicates the apply logic for an unobservable gain.
- Rebuild at mount / periodic walk: the counters are already durable and exact; a walk is O(keys).

## Open questions

None.
