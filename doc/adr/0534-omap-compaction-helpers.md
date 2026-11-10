<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH -->
# 0534 Bounded helper-core OMAP run compaction

Status: accepted (am. 1: default on after the ABBA qualification in doc/perf/omap-conc-20261101.md).
Date: 2026-10-23
Extends: 0476 (immutable run compaction); preserves 0024 static hot-path dispatch.

Plain-language walkthrough: batch example and before/after flow (doc not in the source snapshot).

## Decision

- On by default (am. 1); `flashstore_store_compact_helpers=false` keeps every run
  compaction on the owner core. Single-core OSDs and standalone Store users retain
  inline compaction. No format/wire changes.
- Only immutable compaction continuations cross cores. Store handles, mutable
  B-tree state, counters, floors and authoritative publication stay on the owner.
  A helper builds winning entries, offsets and the existing Bloom filter.
  The rebase onto `b64ccfad9` retains main's per-slice Bloom/part bookkeeping and
  late-kill/current-part publication reconciliation. Helper finalization seals
  output ownership without a second Bloom pass; inline jobs retain main's shared
  per-shard poll budget and WAL-before-maintenance ordering. Device-wide idle
  tracking remains connected independently of helper dispatch.
- Use concrete maintenance messages and static Backend hooks on the existing
  completion mesh lane. No new threads, locks or type-erased jobs. Helpers are
  existing daemon cores, within the same configured CPU mask. Select peers round
  robin excluding self; do not claim an idle-core/load-aware scheduler.
- At most one dispatched job per (owner core, helper core) pair, including transit
  and return (adr 0610 am. 3; was one per owner core). Each helper retains at most
  one job from each other core. Advance jobs round robin
  within one aggregate poll quantum; entry and elapsed-time bounds target fairness,
  not a hard real-time promise for allocation/final conversion of large buffers.
- Reserve a conservative bound for pinned inputs, cloned metadata, output capacity
  and derived structures on the owner while a job is remote. Do not dispatch a job
  exceeding the shared run soft budget; inline fallback preserves progress.
  An atomic shared permit additionally caps the aggregate of all remote jobs to
  that soft budget. It follows the job through owner destruction and is released
  only when the retained job is returned/dropped, not when its Store disappears.
- Identify a job by physical shard, mount incarnation and attempt. Return only to
  the original owner. Keep its run window busy while outstanding; accept a result
  only through existing input-identity and current-kill/part reconciliation. Clear,
  removal, re-log/replacement and tree merges can invalidate work. New unrelated
  runs need not. Do not install results into a failed store.
- Disabling dispatch or shutdown does not wait synchronously for helpers. Unsent
  jobs fall back inline; retained jobs are returned or discarded with their owned
  buffers. Existing WAL/replay remains authoritative if a daemon exits mid-job.
- Export dispatch/completion/lost-work and outstanding-memory counters. Check
  helper work as well as dirty/WAL/checkpoint debt when measuring settlement.

## Qualification

Reuse existing OMAP matrix/client, with native main/native branch arm selection,
identical client/tool, four-core masks and memory targets, fresh stores, paired
repetitions and exact readback/reopened checks. Preserve last-ACK results and
separate ACK-to-settled timings; no hidden delayed debt or extra CPU budget.
Add independent delayed/reordered result, kill/clear/re-log, budget, single-core,
failure and multipart-ACK regressions. Run affected packages and targeted crash
cuts; report both improvements and regressions. A store-only result is not a
daemon performance claim.

## Checkpoint integration

Mainline leaf-delta segment relog (ADR0021 amendment65) remains owner-side;
its base-page chains are not the helper's immutable OMAP run inputs. Preserve
the current-format requirement and checkpoint/WAL-floor ordering. The bounded
`store/tests/helper_checkpoint_relog.rs` regression holds sealed helper output
through actual owner delta relog, checks permit retirement/publication, and
verifies exact contents after cold replay. This is not a new performance result
or permission to reuse stores lacking the current required format features.

## Amendments

### am. 1 (2026-11-01): one job per free helper core, default on

- A store shard prepares one run compaction per free helper core (the OSD passes
  the count of other cores holding no job of this core), was one per shard. A
  shrunk credit returns prepared, untaken jobs to the inline set. The
  per-(owner, helper) bound, the shared permit and identity checks are unchanged.
- Default on. Reason: one hot object is bound by its owner core; with one remote
  job most compaction stayed inline (s3: 1451 of 5419 compactions on helpers).
  Measured: doc/perf/omap-conc-20261101.md.
- Rejected: the owner never steps a compaction a helper may take (jobs wait for a
  credit): run waits +76 %, worse wall time in the same shape (same doc).
