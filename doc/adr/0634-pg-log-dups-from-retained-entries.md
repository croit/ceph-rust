<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0634 PG log dup records derive from the retained trimmed entries

Status: accepted, amended (am. 1)
Date: 2026-10-31
Amends: 0021

## Context

A PG trims its log in batches (`osd_pg_log_trim_min` = 100). Each trimmed entry became one persisted dup record (`dup_*` pgmeta key): 100 encodes and 100 tree puts inside the txn of the write that crossed the limit. At QD1 that write cost +100 us (store 145 vs 49 us), exactly every 100th write per PG, and set the 64K write p99 (doc/perf/pgtrim-20261031.md). A trim txn of the adapter bench: 40 us with the dup puts, 4.4 us without.

## Decision

- A trim persists no dup records. It moves `_logtail` and range-deletes the log keys below the oldest kept dup and the old-format `dup_*` keys below it (two range deletes, cost independent of the batch size).
- The trimmed entries' log keys (`<= _logtail`) stay as the dup source. The loader derives the dups from them (`LogEntry::dups()`: the entry's own dup, plus one per extra request id with return code 0) and appends them after the old-format `dup_*` keys. A key `<= tail` is never part of the live log.
- `StoreOp::LogTrim { to, dups_from, tail_up }`: `dups_from` = version of the oldest dup the PG keeps (`None`: no dups). The PG sends a full `StoreOp::LogDups` list in the rare case where its in-memory dup list is not exactly "old dups + entries from `dups_from`" (entries older than the dup window skipped while older dups are kept).
- `LogDups` and `LogReplace` replace every dup, retained entries included. `LogRewind` never removes keys `<= tail`.
- Dup semantics (window size, count in `pg query`, return codes) are unchanged: only the persisted form differs.
- In-memory `trim_ex` pushes each dup with one clone, no intermediate list.

## In-place upgrade, downgrade

- Sticky feature bit `FEAT_LOG_DUPS` (store layout `FEATURES_KNOWN`/`FEATURES_STICKY`). Every mount (`Store::mount*`; the offline upgrade mount excepted) sets it durable in both superblock copies before the store takes a txn (`heal_super`; am. 1). No trim, and no PG core, ever waits for a superblock write.
- No offline step: old `dup_*` keys remain valid and are read together with the derived dups (mixed state); they age out through `dups_from`.
- An older binary does not know the bit and refuses the mount loudly. Downgrade is unsupported (it would lose dup detection and could apply a resent op twice).

## Crash safety

The feature bit is durable before any txn of the mount. A trim txn is one atomic store txn (tail write + range deletes); replay yields either the old or the new state, both load to the same dups. Tests: `storeadapt/tests/{dup_trim,model,crash,nospace}.rs` (random mixes against `MemStore`, crash replay, mixed old/new state, feature durability).

## Rationale

The dups of a trimmed entry are already on disk in its log key; writing them again is the whole cost. Deriving them makes the trim O(1) and keeps one source of truth.

## Consequences

- + Trim txn 40 us -> 7 us (bench), trim-carrying write no longer an outlier.
- - Up to the dup window of entries stays as log-key size (log entries are larger than dup records); bounded by `osd_pg_log_dups_tracked`.
- - Older builds cannot mount a store once this build mounted it (am. 1; before: after its first trim).

## Alternatives

- Bulk sorted insert of the 100 dup puts: keeps the format, still O(batch) store work in the write's txn.
- Deferred/background trim: moves the cost, adds a second write path and crash cases.

## Amendments

- am. 1 (2026-11-01): `FEAT_LOG_DUPS` set at mount instead of at the first trim. The lazy path (`Store::ensure_log_dups` -> `enable_feature` in the `LogTrim` translation) drained the shard's device queue and wrote both superblock copies synchronously on the PG core, once per core and mount (per-core superblock copies): a 20-45 ms PG-core block per OSD start in the w4m cell (adr 0021 am. 1, doc/perf/w4m-20261101.md). Rationale: KISS, no async superblock write path (new shard completion kind + cross-core read-modify-write serialization) for a bit every store of this build gets anyway. Cost: a store mounted once but never trimmed is no longer mountable by older builds (downgrade was already unsupported after the first trim). Durability ordering is strictly stronger: the bit is durable before any txn.
