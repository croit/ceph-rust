<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0607 Native import history under retained image ownership

Status: accepted
Date: 2026-10-27

## Context

A prepared native import exposes immutable source revisions before destination
materialization. Local mutations, selected snapshots and resize must preserve
those revisions, and execute may run on another client's existing image owner.

## Decision

Keep native source identity and source-to-destination snapshot mappings in the
pinned migration metadata. Resolve source reads by revision, separately from
the source HEAD used to preserve application writes. Materialize historical
revisions with atomic object replacement and snapshot-context guards. Prove
completed object history from its real snapset and sequence, including absent
HEAD whiteouts; object existence alone is insufficient.

Reuse the image writer, activity admission and actual header ownership for
copy, map persistence and final EXECUTED publication. Forward execution to an
existing owner through full AsyncRequestId correlation. Register pending state
before sending, separate acceptance from completion, and settle waits during
close or rewatch. Allocate fallible transport resources before registration.
Application progress runs outside writer and requester-table locks.

Native-import shrink materializes the affected historical range using the
already retained resize authority. Reconcile runtime local snapshot boundaries
without changing the persisted source mapping or acquiring replacement ownership.

## Rationale

The source mapping identifies immutable revisions, while application writes
require the real source HEAD as their baseline. A physical object's snapset
provides durable evidence across reopen and interrupted execution. Reusing
actual ownership avoids final state publication after its lease was released.

## Consequences

- Prepared reads and mutations preserve source-backed revisions during copy.
- A missing object and a durably imported absent HEAD remain distinct.
- Correctness currently costs extra object snapset queries; optimization needs
  independent profiling and retained proof, not a mutable shared positive cache.
- Native config/environment handling and wider remote/fault/application matrices
  remain RBD-031; terminal cleanup, external source formats and ordinary prepare
  remain separate required implementation work.

## Alternatives

- Treat object existence as complete: it cannot prove all historical revisions.
- Close a peer image or steal ownership to execute: it changes caller ownership
  and bypasses the pinned owner-side operation protocol.
