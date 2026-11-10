<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0742 SplinterDB pipelined durability barrier

Status: proposed; measured candidate pending
Date: 2026-11-09
Extends: 0727-splinterdb-omap-engine, 0739-splinterdb-parallel-apply

## Context

Each overlay flush ran apply, data barrier, watermark and watermark barrier on the
worker, with one flush in flight. The data barrier (an fdatasync of the image
file) cost ~31 ms per ~80k-key flush, 3.2-3.8 s per 8.4M-update phase, during
which the next frozen buffer could not be applied and writers parked. The pinned
library's barrier covers every update that returned before the call, from any
registered thread.

## Decision

Opt-in `flashstore_store_splinterdb_pipelined_barrier` (store
`pipelined_barrier`, default false). One extra registered thread per shard runs
the unchanged durability sequence (data barrier, watermark put, watermark
barrier) of applied flushes strictly in LSN order; at most one flush awaits it.
The worker applies flush N, waits for flush N-1's durability result (reporting it
as `Flushed`), hands N over and reports `Applied(N)`.

- `Applied(N)`: N is visible in the engine. The owner invalidates its windows and
  answers of N's objects, drops N's frozen buffer and may send the next flush.
- `Flushed(N)`: N's watermark barrier completed. Only then does the shard publish
  N natively (WAL floor). Checkpoint drain waits for pending durability.
- Any durability failure fails the shard as before. A crash at any point replays
  from the last published floor; replay of a partially durable later flush is
  idempotent as before (ordered redo, prefix property).

## Consequences

The data barrier overlaps the next apply; the watermark never precedes its data;
native publication never precedes the watermark barrier. Costs one more
registered thread and helper stack per shard (thread-slot check). Tests: the
durability thread writes the watermark only after a successful data barrier
(injected data/watermark barrier failures), pipelined flushes become visible then
durable strictly in order with the final watermark after reopen, and a shard
crash image after pipelined publication recovers every acknowledged key.
