<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0530 Admit RBD writes through a watched image owner

Status: accepted
Date: 2026-10-23

## Context

The raw RADOS write lane can select a SnapContext and submit durable object
writes, but it cannot independently validate an image's current head, object
layout or writer policy. A public writable image handle also needs copy-up,
exclusive-lock, object-map and flush semantics.

## Decision

- A private image writer owns a header watch, a coherent head observation and
  one data write lane.
- It refreshes the head after a notification and admits each complete write
  under one watch permit. The same observed SnapContext is used for every
  object segment of that write.
- Until feature-specific ownership is implemented, the writer accepts only
  unparented, layering-only heads with no group, flags or separate data pool.
- The experimental-write build exports `rbd_open`, `rbd_open_by_id`,
  `rbd_write` and `rbd_flush` for this admitted head policy. The default
  build does not export them until the complete contract is qualified.
- A writable C handle routes scalar getters, synchronous reads and, with
  `experimental-aio`, asynchronous reads through the same watched owner.
  Each asynchronous read pins one admitted layout through its object replies
  and releases the watch permit before invoking user callbacks.
- Every accepted synchronous C write gets an image-local sequence. Flush
  waits for the completion prefix through the last sequence admitted before
  the flush; later writes do not delay it.
- With `experimental-aio`, `rbd_aio_flush` captures the same prefix and
  publishes its completion after that prefix has settled. Its image activity
  permit remains live through the user callback and close waits for it.
- The staged `rbd_aio_write` reserves its write sequence before returning
  submission success. It keeps caller bytes live until its durable result,
  settles the sequence before invoking the callback, and keeps the image
  alive through the callback.
- Vectored AIO writes copy descriptors only. All fragments share one watched
  observation and SnapContext. Sync and AIO writers enter the serial owner
  in accepted-write order.
- Writable asynchronous name/ID opens own their private metadata and data
  ioctxs before returning submission success. Completion publishes a handle
  only after the writer watch and readable image view are both established.

## Rationale

One owner can validate routing and admission before the first segment and
keep the notification ACK behind all segments. Explicit feature rejection
avoids silently applying raw writes without copy-up or lock maintenance.

## Consequences

- + The same owner can later supply a writable C image handle.
- + Object-boundary writes and snapshot context changes have one admission
  point.
- + A concurrent flush fences prior accepted synchronous writes even if
  their completion order differs from admission order.
- - The staged writer supports a narrow image feature set and serial caller
  access only.
- - A multi-object write can partially apply before an error; the caller
  cannot infer that the full range was untouched.
- - Experimental writable C handles are limited to this feature policy and
  are not QEMU-qualified.

## Amendment 1 (2026-11-08)

Decision bullet 4 ("The default build does not export them until the
complete contract is qualified") no longer applies. The default feature set
is `experimental-aio,experimental-write`, i.e. the shipped set; qualification
state is tracked by the open-issues inventory, not by a cargo feature.
Reduced builds (`--no-default-features`, single subsets) stay built and
tested until the feature split is removed; they are not shipped.
`lab-diagnostics` stays opt-in.
