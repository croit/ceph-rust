<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0531 RBD snapshot selection retains immutable read views

Status: accepted
Date: 2026-10-23

## Context

Ceph 21.1.2 permits `rbd_snap_set` on an open image. Reads submitted
before and after selection can overlap. An asynchronous read can continue
after the selection call returns. A writable head must reject new writes
while a snapshot is selected, while already accepted writes must complete
before the new view is published.

## Decision

- Each accepted read holds the immutable image view selected at submission.
- Snapshot selection builds and validates a replacement view before
  publishing it. A failed selection retains the previous view.
- A writable handle rejects subsequent writes, waits for previously
  accepted writes, and then publishes the snapshot view.
- Reset to head publishes the head view before accepting new writes.
- The root image activity permit keeps the open handle alive until an
  asynchronous read completes; that read also owns its selected view.

## Rationale

An owned view prevents snapshot selection from changing the ioctx and
geometry of a multi-object read midway through its operation. The existing
write ticket sequence provides the ordering needed at the transition.

## Consequences

- + In-flight asynchronous reads retain their original view without
  blocking a later selection.
- + Failed lookup does not alter the handle's active selection.
- - Each read currently takes a short view lock and reference count update;
  the cost must be measured and optimized during the performance phase.

## Alternatives

- Mutating the existing ioctx and geometry in place: an in-flight
  asynchronous read could observe a mixed view.
