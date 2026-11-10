<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0732 Bounded SplinterDB throughput pipeline

Status: proposed; implementation and bounded comparison in progress
Date: 2026-11-06
Extends: 0727-splinterdb-omap-engine, 0728-splinterdb-cache-and-read-ahead

## Context

The optional engine eagerly materialized nonempty overlays, subdivided scans into
256-entry worker calls, and placed each file worker on its PG owner's CPU.
Prior measurements show fine-grained flush/publication work and discarded scan
prediction. These observations justify bounded experiments, not a general engine
performance claim. Native B-tree/LSM and engine/default-off selection stay intact.

## Decision

- Freeze foreign overlays at the existing native size/force/WAL-pressure gates,
  or when the oldest active batch reaches the configured checkpoint interval
  (default5s; zero means immediate). Later writes never reset its age. Keep force
  latched through older frozen work and consume it on actual active freeze.
- Merely buffered unexpired data may sleep until the existing periodic Store
  sweep. Pending foreign requests and frozen/publication work remain active;
  do not strand completions or create synthetic wakes on Miss.
- Explicit foreign checkpoints request materialization, wait for empty overlays,
  make submitted native publication durable, then checkpoint. Ordinary sync keeps
  its native-durability meaning. Reclamation, native ACK/replay authority, both
  foreign barriers and native publication ordering remain unchanged.
- A scan request carries bounded demanded rows, including a continuation entry;
  cap one worker turn at4096rows and retain the existing soft byte allowance and
  legal oversized-entry progress. Owner entry/byte slices are unchanged. Compatible
  owned demanded tails survive owner retries with smaller remaining widths.
  Exact retry identity includes width; view/session/projection/version gates stay.
- Keep adaptive prediction for256-row demands only. Other widths fetch demand
  only, and demanded tails are not counted/discarded as unused prediction. Wide
  demand yields with positive progress under queued mutation/retirement pressure;
  never return an empty uncertain page. Demand errors are not speculative errors.
  No foreign cursor survives a worker turn or mutation.
- The daemon maps each foreign worker to the next entry of its resolved assigned
  CPU vector, wrapping within the same budget. Sparse IDs are not guessed.
  Single-core selects itself; offline mounts preserve owner/explicit CPU fallback.
  Mount configuration is cloned per core, not mutated globally. PG/native state
  ownership and one worker/file remain unchanged; no upstream background pool.
- Reuse lookup-result and namespace-key scratch within a bounded point batch.
  Copy each answer to owned Rust storage before reuse; release foreign result refs
  at batch end, before the next mutation. No borrowed result escapes its lifetime.

## Rationale and consequences

Amortize durable materialization and worker setup without buying more cores,
loosening memory ownership or weakening persistence. Low-rate data still drains
within the existing bounded policy; checkpoint callers have an explicit drain.
Different worker placement can lose locality or compete with another hot shard,
so one-object improvements do not establish balanced-load or production scaling.

## Alternatives

Removing a durability barrier, acknowledging from foreign RAM, unbounded batches,
live cross-turn iterators, extra CPUs, arbitrary cache enlargement and per-operation
dynamic dispatch are rejected. Keeping only eager freezing fails to amortize
materialization; increasing prediction alone does not fix request subdivision.

## Qualification / open questions

Require independent force/age/threshold/idle/readiness, durable checkpoint/replay,
wide scan limit/projection/EOF/retirement/error, sparse-CPU mapping and reusable
lookup regressions. Compare fresh sequential source-bound arms with unchanged
workload/CPU/memory/durability budgets. Measure flushes/seeks, CPU and tail latency,
not just throughput. Physical power-loss, balanced multi-object scaling and
production qualification remain separate gates; no benefit is assumed in advance.
