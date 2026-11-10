<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0527 librbd C completion and read-only asynchronous image control

Status: accepted
Date: 2026-10-23

## Context

The pinned C API gives the caller an opaque completion and release duty.
The reference vector gate observed the result inside its callback before the
done flag became visible. The initial read-only image handle owns private
librados C ioctxs; it has no outstanding image writes. Read-only open and
close can exercise asynchronous completion without claiming write admission,
durability or flush behavior that does not exist yet.

## Decision

- Keep one caller reference to an opaque Rust completion and one retained
  operation reference after accepted submission. Releasing the caller handle
  during a callback cannot free the running operation.
- Publish the operation result before invoking the callback; set the visible
  done flag and wake waiters only after the callback returns. Run callbacks
  without holding the completion lock.
- `rbd_aio_close` transfers exclusive ownership of a read-only image handle
  to a named close worker only after thread creation succeeds. A failed
  submission leaves both image and completion reusable by the caller.
- Read-only asynchronous name and ID opens copy the selector and optional
  snapshot name and duplicate private ioctxs during submission. An open
  worker owns the duplicate and publishes the image pointer only after the
  complete open succeeds. The caller's output pointer remains writable
  through completion. A failed open leaves it null and returns the operation
  error through the completion.
- Express cross-thread ownership as explicit single-owner transfer types for
  the private C contexts, closing image and output slot. Each unsafe `Send`
  boundary has one handoff and no shared mutable image state.
- Keep this family behind `experimental-aio` until the identical public C
  consumer passes against the pinned original and own library pairs. The
  current per-close worker is a control-path implementation. Read-only data
  I/O uses the process's loaded librados asynchronous C API, with one RADOS
  completion per object segment and no thread per data operation.
- An image activity counter pins the opened image through each accepted read,
  including its user callback and any continuation submission. Close marks
  the image closing before accepting worker ownership and waits for the
  counter to drain before destroying private ioctxs. A rejected close worker
  spawn restores admission.
- Scalar and vectored reads share one event-driven image read job. Vectored
  submission copies validated descriptors, then clips each RADOS AIO request
  at both object and destination-span boundaries. The caller owns destination
  bytes through completion.

## Rationale

An owned completion separates the caller's release reference from operation
lifetime. The close worker permits submission to return while private ioctx
teardown runs. The open worker uses copied input and owned contexts, so it
does not borrow a caller string or ioctx after accepted submission. Open and
close are control operations; a worker per call is acceptable for this
experimental path. RADOS AIO callbacks drive the data path without a
blocking image worker. A submission guard retains the image and object name
until the RADOS call returns even if its callback runs first.

## Consequences

- A successful asynchronous close consumes the image handle immediately.
- Accepted asynchronous open can finish before the submission call returns;
  consumers must keep the output slot valid through completion regardless.
- The first live name-open gate passed eleven successful cases and one
  missing-snapshot error per provider. A separate ID-based gate passed one
  head and one clone per provider. Missing-ID, concurrent use and fault
  paths remain unqualified.
- A callback may complete before the submission call returns; callers must
  rely on the completion contract, not a presumed scheduling delay.
- The worker destroys private C ioctxs on a different thread. The first
  original/own loader gate passed eleven successful close cases per provider.
  A subsequent original/own scalar read gate passed an accepted close while
  the read callback was held and ordered the close callback after read
  callback exit. Pending OSD replies, concurrent submissions and faults
  remain unqualified.
- Writable images and their pending operations need a separate image-level
  lifetime fence before this close path can be used for them.
- A pinned reference vector fixture and an original/own scalar fixture show
  asynchronous close accepted while an earlier read callback is held. Both
  invoke the close callback after that read callback exits. The image
  activity counter supplies the read-only callback-prefix fence.

## Alternatives

- Close synchronously and only dispatch the callback: makes the submission
  block on ioctx teardown.
- One worker per data operation: unbounded threads and poor QEMU throughput.
- Embed the Rust RADOS owner in the image library: conflicts with the opaque
  public ABI boundary in the preceding ADR.

## Open questions

- What callback order and close fence are required once writes, flush and
  image watch state are implemented?
- Can the reference close operation be invoked from one of its own image's
  AIO callbacks without deadlock? Pin before supporting that reentrant path.

## Amendment (2026-10-23): every accepted submission completes its completion; the close waits for operations only (am. 1)

- The pinned reference accepts every asynchronous submission: `rbd_aio_read`,
  `rbd_aio_write`, `rbd_aio_flush`, `rbd_aio_close` and the asynchronous opens
  return `0` and complete their completion exactly once, with the operation
  result (byte count or negative errno) in `rbd_aio_get_return_value`. A
  submission that fails before an operation worker started owns its
  completion, so it completes it on a worker thread instead of returning a
  bare errno. A caller that uses the reference idiom
  (`rbd_aio_read(...); rbd_aio_wait_for_complete(c);`) must not hang.
- The earlier decision that a rejected submission leaves the completion
  reusable is withdrawn. The completion of an accepted submission is consumed
  by that submission, like in the reference.
- The image activity counter is split. The operation counter covers the
  in-flight data operations that may still use the image's writer and ioctxs.
  A separate callback counter covers the in-flight user callbacks. `rbd_close`
  waits for the operations only; a user callback is not an operation.
- `rbd_close` therefore returns while a user callback of that image still
  runs. The image owner moves to the activity and the last callback drops it,
  so the image stays alive for the callback and a callback that closes its own
  image does not deadlock. The reference behavior for that reentrant close is
  still unpinned; the own path is now safe, not qualified against it.
- A callback permit is reserved at submission, before the operation ends, so
  the close cannot observe a callback that is about to start.

## Open questions (am. 1)

- The reference behavior of a synchronous close from the image's own callback
  is still unpinned. The own path does not deadlock and keeps the image alive
  for the callback; a live gate must still compare both libraries.

## Amendment (2026-10-31): drain accepted data before recovery shutdown (am. 2)

Close seals new submissions and cancels outstanding administrative requests.
Previously accepted DATA mutations retain writer watch and ownership recovery
until they settle; close then shuts recovery down and drains the remaining
operations. Mutations submitted after close are rejected. Synchronous and
asynchronous mutations use the same retained submission accounting. A user callback remains outside the
operation drain.

Ceph 21.2.0 completed four already submitted AIO writes after a real watch
expiry and network restoration while close was requested; the previous
implementation returned ESHUTDOWN or failed to complete in this fixture.
Stopping recovery before mutations drain breaks that result. Cancelling admin
requests before the DATA drain preserves their separate close boundary and
prevents an administrative wait from holding the submission queue indefinitely.
A closed administrative request table has no retained or future request identity
to update and does not prevent recovery of the watch needed by accepted DATA.
The exact scheduling of the reference close inside that network window remains
unobserved.
