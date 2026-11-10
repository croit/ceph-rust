<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0536 RBD header lock takeover and holder report

Status: accepted
Date: 2026-10-23

## Context

The writable image path holds the header lock of the image head object while
it mutates metadata. The lock entry of the pinned reference carries the watch
handle of its owner, so a holder that no longer watches the head object can
be separated from a holder that still does. The public librados C ABI cannot
list the watchers of an object, so the adapter cannot run that liveness probe
over the ABI it was given.

## Decision

- The lock cookie and tag keep the convention of the pinned reference: the
  cookie carries the watch handle of the owner and the tag marks a watcher
  lock.
- The native core reports the holders of the header lock with the class
  `get_info` operation and lists the watchers of the head object with the
  `list_watchers` operation.
- The native core breaks the lock of a holder only when no watcher of the
  head object carries the watch handle of the lock cookie and the address of
  that watcher matches the address of the holder.
- The adapter names the holder of a contended lock and returns `-EBUSY`. It
  never breaks a lock, because the public ABI cannot prove that the holder is
  gone.

## Rationale

The lock of the pinned reference has no expiry, so a lock of a client that
died stays on the head object until an operator breaks it. The reference
decides that a holder is gone with the watcher list of the head object. The
adapter cannot obtain that list over the public ABI, and breaking a lock
without that proof would fence a live writer and could split the metadata
of one image between two clients. Reporting the holder keeps the operator in
the loop and leaves the decision with the tool that can prove it.

## Consequences

- + The operator learns which client holds a contended lock and at which
  address, instead of a bare `-EBUSY`.
- + The native client can take over a lock of a dead holder without an
  operator.
- - The adapter cannot recover a lock of a dead client on its own. The
  operator breaks it with the lock entry point of the pinned reference.
- - The takeover of the native core has no live gate yet.

## Alternatives

- Break a contended lock without the liveness probe: it would fence a live
  writer and could split the metadata of one image.
- Give the lock a lease and renew it: the lease would have to survive a
  paused client, and the reference does not use one.
- Derive the cookie from a heap address: the holder would not be
  identifiable and a restarted client could not recognize its own lock.

## Open questions

- The takeover of the native core needs a live gate against a classic
  cluster: a writer that dies while it holds the header lock, a second
  writer that takes the lock over, and the proof that a live holder is never
  broken.
