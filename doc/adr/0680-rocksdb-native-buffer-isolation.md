<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0680 Isolate RocksDB snapshots from native LSM buffers

Status: proposed
Date: 2026-11-06
Amends: 0681, 0676, 0677

## Context

Compiling RocksDB previously changed native LSM objects to shared ownership and
added snapshot revisions to every native mutation. Native scan memos also carried
RocksDB page/cursor fields. Engine selection must not impose that machinery on
native LSM. A single-pass throughput difference is not a measured cost attribution.

## Decision

- Keep native `olsm::mem` direct-owned, following origin/main. No RocksDB feature
  gates, object snapshot handles or mutation-version tracking in that buffer.
- Keep RocksDB COW snapshots, identities and revisions in `rocks_omap::mem`.
  Selected Rocks state and staged transactions own separate typed overlays.
- Keep native listing memos unchanged; Rocks listing memos own their additional
  page/cursor/revision state in a separate collection. Charge and expire Rocks
  memos only through their backend-specific lifecycle.
- Dispatch at the engine/batch boundary, not inside native per-key mutation
  algorithms. Preserve native memory targets, flush/merge policy and read paths.
- Preserve the native WAL as transaction authority. Rocks buffers participate in
  admission, redo floors, freeze/materialization, publication and physical OMAP
  accounting. Replay below the native checkpoint remains visible until external
  materialization and native publication make that redo reclaimable.
- Preserve read-only overlays and include their buffered-only IDs in checking.
  No on-disk format, wire contract, acknowledgement or durability-policy change.

## Rationale

Typed backend buffers prevent a Cargo feature from silently changing native
ownership and mutation work. Keeping Rocks overlays in state, rather than only
in the temporarily detached worker driver, preserves admission and retention
during publication submissions.

## Consequences

Small backend-specific buffer implementations share key ordering, range semantics
and WAL operation encodings, but have independent ownership and bookkeeping.
Regressions assert native layout with RocksDB compiled, immutable Rocks snapshots,
and recovery of unmaterialized OMAP across a native checkpoint. Existing engine
correctness, scan, admission and crash tests remain required. Compilation and
offline tests do not establish a throughput gain or physical power-loss safety.

## Alternatives

Runtime-select a shared object-slot representation per key: rejected; native
mutation algorithms would still pay RocksDB dispatch/bookkeeping costs.
Remove worker snapshots: rejected; violates bounded immutable worker ownership.

## Open questions

Matched performance verification remains separate; no live run is implied here.
