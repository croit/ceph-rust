<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0727 Optional per-shard SplinterDB OMAP engine

Status: proposed; implementation and offline qualification in progress
Date: 2026-11-05
Extends: 0610 (logical OMAP WAL), 0611 (format refusal/upgrade gates)

## Context

Evaluate actual SplinterDB without replacing the native B-tree or LSM engine.
Upstream supplies no immutable semantic-version release artifact; its website's
v0.0.1 download points at moving main.zip. Pin the audited Apache-2.0 source as
third_party/splinterdb at73f89d8879e2e5603933f756c8c4d2c60a12d9c6. Upstream
is pre1.0; optional daemon support is not production qualification.

## Decision

- Default-off Cargo feature and persistent incompatible engine identity. Existing
  B-tree/LSM defaults, formats and operation paths remain unchanged. No automatic
  conversion, threshold fallback, reuse of another engine's files or implicit
  creation of a missing database at mount. Reserve a distinct feature bit from
  the independent RocksDB work; neither feature imports that branch's changes.
- One database file per native shard under an explicit admitted filesystem root,
  bound to OSD identity/shard and native replay frontier. PG/core routing remains
  native. The owner alone mutates PG/store state; foreign calls execute outside
  its reactor on a bounded shard worker within the same CPU budget.
- Native WAL remains the sole transaction/ACK authority, including PG metadata
  OMAP and native data/onodes/xattrs. Only native-durable frozen OMAP may enter
  SplinterDB. Preserve overlays until native publication and native redo until
  both engines' durable prefix makes reclamation safe.
- SplinterDB does not supply RocksDB-style atomic batches. Materialization must
  durably establish all prefix mutations before advancing a durable applied
  watermark, then publish that prefix natively. A crash before publication must
  replay idempotently; no reader may observe an incomplete foreign batch without
  the still-authoritative native overlay. A watermark outside recoverable native
  bounds refuses mount. Exact ordering is a required regression contract, not
  an assumption from a successful library insert.
- Bounded ordered scans merge native overlays with the foreign base, preserving
  binary keys, tombstones, prefix/end/cutoff rules, owner slices, request retries
  and cancellation credits. Never leave a foreign iterator alive while mutating
  the same database on its thread. Data/header ownership and wire formats stay.
- Memory shares are soft admission targets, never new OMAP value/reply limits.
  An admitted session can accrue output debt to complete; competing sessions wait
  for its credit. By-keys work is split into cancellable worker batches without
  truncating the logical reply. Keys-only answers retain keys, not values (the
  pinned public iterator still materializes values transiently). Final transport
  reply ownership remains the existing native path, not a new memory-envelope
  qualification of this worker.
- External capacity/headroom and native reserve floors both constrain admission.
  Reserve projected incoming growth before accepting the native transaction,
  including pending overlays and shared-filesystem debt; release reservations
  after materialization and an updated filesystem sample. Deletions retain the
  withheld recovery headroom. Headroom accounting is not a proven bound on every
  upstream workload's write amplification.
  No filesystem creation, device formatting, host tuning or package installation
  is performed by daemon startup/build. Offline read-only consumers must not
  silently open or recover the original database read-write. Any missing safe
  capability must be explicit, not a fallback or false qualification.

## Build and source ownership

The parent Git link pins source. Submodule update is explicit; builds do not fetch
or follow main. Compile the C library/binding only when selected, use permissive
dependencies and keep upstream tests/scripts out of our standalone regression
suite. Default workspace/native-engine builds must not require initialized
SplinterDB source or its native build dependencies.

## Alternatives

Native-shard dynamic backing requires an additional custom I/O backend, durable
extent map and mutable-arena ownership/recovery semantics. It is not part of the
initial file-backed engine; do not pass our existing device to a foreign allocator.
Retaining only an in-memory mock, acknowledging foreign-only writes, or dropping
redo before durable watermark publication is rejected.

## Qualification / open gates

Require independent Rust/bash binary/long-key/value, ordering, partial-batch crash,
watermark refusal, restart, overlay/clone/range-delete, quota/fairness and original
source read-only tests. Check selected and disabled features, daemon/tool wiring
and existing B-tree/LSM regressions. No test06 access, deployment, benchmark or
physical-power-loss qualification is authorized for this task. Integration stays
unqualified until actual gates pass; record blockers and limits explicitly.
