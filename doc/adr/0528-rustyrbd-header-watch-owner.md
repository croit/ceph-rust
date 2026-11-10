<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0528 Owned writable RBD header watch

Status: accepted
Date: 2026-10-23

## Context

Writable open needs a header watch before publication. RADOS may call into
the application concurrently, including during teardown. The initial
read-only image contexts have no watch and cannot serve as a writer grant.

## Decision

- Put the owned watch primitive behind `experimental-write`. It duplicates
  a private metadata ioctx and retains the loaded provider library.
- Pass an integer registration token to RADOS callbacks. Resolve it through
  a synchronized registry to an owned callback state; never dereference the
  callback argument as an application pointer.
- Invalidate a monotonically increasing notification generation before
  submitting an explicit ACK. A write admitted against the prior generation
  holds a permit until its synchronous result; defer the ACK until all such
  permits drain. Record a watch or ACK failure as loss of writer admission;
  `watch_check` can also record lease loss.
- On close, unwatch through the private ioctx, flush accepted callbacks
  through the owning cluster handle, remove the registration and
  destroy the private ioctx only when both operations succeed. If unwatch
  fails, retain the registration, ioctx and provider library because the
  watcher may remain active. If callback drain fails, retain the ioctx and
  provider library because an accepted callback may still use them. Emit a
  warning on either failure.
- Write permits own their callback state and can cross threads. Close seals
  new admission and waits for all permits and their deferred ACK calls before
  unwatch. The common admission and release path uses atomic state; a queue
  lock is used when a notification is pending.
- Do not publish `rbd_open` from this primitive alone. Header refresh,
  SnapContext, exclusive lock, copy-up, object-map and write durability
  remain separate admission and completion requirements.

## Rationale

A copied integer token cannot become a dangling callback pointer after
registry removal. The private ioctx prevents image metadata reads and watch
cleanup from sharing mutable ioctx-wide state. The registry lock is outside
the data hot path. Notification generation permits a later writer to reject
a refresh raced by another notification.

## Consequences

- Failed unwatch or callback drain retains resources and is visible in the
  log. A failed unwatch also keeps callback state available for later ACKs.
- The owner can be tested against original and own public librados pairs
  without exposing an incomplete writable `librbd` handle.
- The first live owner gate hung after unwatch when flush was called with an
  ioctx. The public flush ABI takes the owning cluster handle. With that
  corrected, original and own providers passed watch registration, check,
  unwatch and callback flush in the full isolated matrix.
- A subsequent original/own gate delivered one public notification through
  each provider. Both consumers advanced generation to one, submitted an
  ACK and closed without watch loss; the notifier returned successfully.
- A live `rbd snap create` by a second client advanced each provider's
  owned watcher from generation one to four. Both snapshot operations
  completed and both watchers closed without reported loss. The owner does
  not yet decode RBD notification payloads or refresh the full image state.
- The owner now observes the version-matched head through its matching
  metadata context and rejects a notification raced by that query. A second
  generation check is available at later I/O admission. The live snapshot
  gate invalidated the old observation and returned a new SnapContext with
  one additional snapshot for both providers. This does not grant writes.
- A live public notifier stayed pending while each provider held a write
  permit. The notification generation advanced; releasing the permit let the
  notifier complete. The full isolated matrix and later snapshot byte checks
  passed. The RBD-specific notification phase remains unqualified.
- The owned permit now supports an asynchronous completion thread. A unit
  gate holds close until permit release and checks that multiple pending
  notifications are ACKed only after both earlier permits drain. Live close
  with outstanding OSD I/O remains unqualified. The unchanged original/own
  live notification and two-snapshot matrix passed after the ownership
  change.
- Writer admission still needs a generation-aware refresh and lock fence.

## Alternatives

- A raw pointer callback argument: teardown errors can leave a dangling
  pointer accessible to RADOS.
- Reusing the read-only metadata ioctx for watch callbacks: couples callback
  lifetime to unrelated image reads and complicates close ordering.

## Open questions

- What are the exact notification payload and reconnect contracts required
  before writable image open can be enabled?
- How does pinned `rbd_close` report an unwatch or callback-flush failure?

## Amendment (2026-11-02): DATA I/O admission from recorded watch state (am. 1)

- AIO reads and pipelined AIO writes admit through `HeaderWatch::admit_io`:
  generation, closing and the loss recorded by the provider's watch error
  callback, plus the deferred-ACK permit. No provider `watch_check` call.
- Control paths (refresh, ownership, lock, admin, serial writes) keep
  `admit_write` with its provider check.

Rationale: `admit_write` called `rados_watch_check` twice per I/O. With this
project's librados that is a synchronous round trip to the messenger
worker; it serialized the submitting thread and capped 4k random reads near
10k IOPS at any queue depth on the lab (doc/perf/rbd-qd-20261102.md). The
reference library never checks watch health per I/O; a provider check
reports the same error the error callback delivers, so the data path loses
no fencing.
