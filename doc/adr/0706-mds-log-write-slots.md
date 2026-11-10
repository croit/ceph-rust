<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0706 MDS log write slots bound submission, not reservation

Status: accepted
Date: 2026-11-09

## Context

With `mds_early_reply` the pipelined create/unlink load ran slower and wrote more per op than SAFE-only replies
(doc/perf/mds-cpu-per-op.md item 7). BE counters: a request that found `log_writes_in_flight` appends in flight
could not reserve its record. It parked as a store wait, planned again after the next completion, and the store
wait demanded a write-back round, which cannot free a log write slot; each round wrote back a few images.
SAFE-only background retirement retried such reservations every pass.

## Decision

- `log_writes_in_flight` bounds appends in flight at submission (`Core::seal`), not at reservation. A pass's
  open group stays open while every write slot is busy and collects the records of later passes; a group
  closed outside a pass (lab adapter, segment end) still waits for a slot.
- Only waits that write-back can end demand it: log window, group table, group buffers and cache entries
  (`Core::reserve`, `Core::get`), namespace and retirement log buffers, receipts. A write slot wait demands
  nothing; an append completion wakes it.
- Appends in flight, the replay gap bound (store format: `log_writes_in_flight` in the stream head) and the
  durable prefix rule are unchanged.

## Rationale

An append in flight is the batching window of a group commit. Refusing reservations during it turned the window
into parks, re-plans, small groups and write-back rounds of a few images each.

## Consequences

- + No write-back round per slot wait; larger groups; no re-plan per slot wait, for early and SAFE-only replies
  (measurements: doc/perf/mds-cpu-per-op.md).
- - While every slot is busy, a record waits in the open group for the next completion before its append
  starts (it waited unapplied before).

## Alternatives

- Only stop the write-back demand of slot waits: keeps parks, re-plans and small groups.
