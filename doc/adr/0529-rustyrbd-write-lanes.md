<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0529 RBD data write lanes

Status: accepted
Date: 2026-10-23

## Context

The public RADOS C interface stores a self-managed write SnapContext on an
ioctx. A writable RBD image may refresh its SnapContext while independent
operations are in flight. Sharing that mutable ioctx across write submissions
would pair some payloads with the wrong snapshot sequence or ID vector.

## Decision

- Give each write lane its own data-pool ioctx and namespace. The lane is
  created from the image context pair and a matching header watch, and
  retains the provider library. Each submission requires a permit from that
  same watch registration.
- Select the complete descending SnapContext on a lane before its first write
  and whenever the selected context changes. A failed selection submits no
  write and does not replace the cached context.
- Require mutable access to a lane for submission. Distinct lanes may submit
  concurrently without an image-wide ioctx lock.
- Keep this primitive behind `experimental-write`. It submits a synchronous
  object-local RADOS write only after an image owner has established watch,
  metadata, lock, copy-up, feature and flush policy. It is not `rbd_write`.

## Rationale

An ioctx per lane isolates mutable RADOS snapshot state without locking all
writes on an image. Reusing a selected context avoids repeated setter calls
for the common unchanged-header case. The synchronous result can be checked
against actual head and snapshot bytes before image-level write admission is
implemented.

## Consequences

- Lane count consumes provider ioctx resources; the future scheduler must
  bound lanes by active queues and measure that cost.
- The current C scalar write path may copy caller bytes. The eventual QEMU
  path needs matched copy, CPU/op and latency measurements before release.
- The caller must retain the original connected cluster for the lifetime of
  the borrowed image pair, as required by the public RADOS context contract.
- The first isolated snapshot-before-write gate passed on separate images
  against original and own providers: exact new head bytes, absent object in
  the earlier snapshot, healthy watcher, and full matrix exit zero. The first
  fixture had shared an image across providers, so its second snapshot
  correctly contained the first provider's write; it was replaced.
- The next gate reused each provider's lane across a second snapshot. The
  first snapshot stayed empty, the second held the first write, and the head
  held the second write. The lane renewed its complete SnapContext after the
  watch generation and header observation changed.

## Alternatives

- One shared data ioctx with a mutex: serializes independent writes and
  creates a hot-path lock.
- Set the SnapContext on the image's read ioctx: concurrent reads and writes
  would share mutable RADOS state with unrelated lifetimes.

## Open questions

- How should the image scheduler map active write lanes to its data queues?
- Which provider path meets the final QEMU copy and CPU/op targets?
