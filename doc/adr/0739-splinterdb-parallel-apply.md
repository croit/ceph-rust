<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0739 SplinterDB parallel materialization apply and memtable helper

Status: proposed; measured candidate (phase1 8Mi, one pass per arm)
Date: 2026-11-09
Extends: 0734-splinterdb-maintenance-offload, 0732-splinterdb-throughput-pipeline

## Context

The phase1 8Mi run showed write throughput equal to the single worker's apply
rate (~2.7 us/key, ~80k keys per materialization) with writers parked on a full
overlay and one CPU of the four mostly idle. The pinned library accepts concurrent
updates from registered threads and orders durability by its barrier cut, not by
the calling thread.

## Decision

- Optional `apply_threads` (1..=4, default 1): the worker plus up to three
  registered helper threads apply one materialization. Range deletes of every
  object run first on the worker; the remaining points are split into contiguous
  slices of the materialization's global key order and applied concurrently.
  The worker joins every slice before the unchanged data barrier, watermark and
  watermark barrier, so the barrier still covers the whole materialization and a
  failed slice fails the materialization without publishing its watermark.
- Helpers exist only with a resolved multicore placement; they register with the
  library like the worker, count against the same thread-slot budget and stack
  reservation, and stop before the database closes.
- Optional `memtable_maintenance` (default false) adds one library memtable
  helper. It requires normal maintenance and inherits the cleaner placement.
- Helper CPUs: the service set without the shard's worker and cleaner CPUs when
  at least two remain, else the whole service set.

## Consequences

Measured (one pass each): write cells +18-33 %, write p99 about 40 % lower; the
three apply threads reach ~1.4x, not 3x (library serialization and the static
slice join); helper placement alone did not change throughput. No format,
native WAL, barrier or watermark change. Model tests cover slice coverage and
order, concurrent disjoint registered writers, expected state after reopen and a
failed barrier keeping the previous watermark.

## Amendment: dynamic chunks

2026-11-09. Static contiguous slices joined at the end turned any stalled thread
(rotation, checkpoint seal, writeback wait) into idle time for the others (three
threads busy only 50-60 % of the apply wall). The points of one materialization
are now planned as contiguous chunks of at most 2048 points (one walk over the
keys; a chunk starts at its first key) and claimed from a shared counter by the
worker and every helper until none is left. A helper is engaged per two chunks
beyond the first. The first error stops further claims; every thread that took
the round reports before the barrier, so ordering, barriers, watermark and
failure semantics are unchanged.
