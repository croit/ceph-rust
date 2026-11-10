<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0604 Forwarded resize retains accepted ownership

Status: accepted
Date: 2026-10-27

## Context

The receiver decodes Resize notifications but rejects execution. Local resize
holds the writer mutex during application progress callbacks, preventing an
ordinary size query from the callback. Existing flat trim, snapshot context,
map resize and header publication stages are shared lifecycle operations.

## Decision

Forwarded resize uses the accepted managed epoch without acquiring a replacement.
Resize retains watched admission across DATA, map and header stages and checks
retained authority before each object and final publication mutation.
Public local and forwarded resize release the writer mutex around progress.
A running shrink exposes its target layout to same-handle queries and new
sync/AIO reads while retaining the original layout for trim and snapshots.
Every success/error exit removes this transient view; failed trim leaves the
persisted old size visible again.
Internal rollback and copy stages reuse the same object trim and resize stages.
The activity submission remains pinned until update notification completes.

## Rationale

Sharing trim and map/header stages preserves snapshot and geometry behavior.
Per-object locking permits callback metadata queries while retained admission
and the submission fence prevent another accepted write from interleaving.
An epoch change ends the operation instead of changing its execution owner.

## Consequences

- + Remote requests execute using actual storage ownership.
- + Local progress can query the image without recursively locking the writer.
- - Failure after a successful trim can leave a zeroed tail with the old size,
  as in the existing multi-object shrink contract.

## Alternatives

- Calling the public C API from the receiver: duplicates activity admission and
  can reacquire ownership after the original request loses its epoch.
