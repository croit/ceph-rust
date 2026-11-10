<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0566 Image-local quiesce callback and completion ownership

Status: accepted
Date: 2026-10-25

## Context

The pinned quiesce receiver requires asynchronous application callbacks,
explicit completion, final notification ACKs and later unquiesce. Dropping
callbacks while returning registration success leaves snapshot coordination
incomplete. The reference has verified token/count and unregister drain
defects; its canceled pending ACK can report success before application
completion. Contracts and source limitations are recorded in
the lifecycle spec (doc not in the source snapshot).

## Decision

- ImageUpdates owns one quiesce registry shared with its existing header
  transport. Quiesce registration creates no extra provider watch.
- The receiver freezes admitted quiesce callback jobs, dispatches without its
  mutex and waits for each valid callback token's explicit completion.
  Unknown/duplicate completions do not consume other subscribers' work.
- Full request identity controls duplicate suppression, FIFO local cycles,
  completed-result retention and the specified post-completion release timer.
- Unregister removes future dispatch and drains admitted invocations before
  allowing callback argument retirement. Safe self-removal can return without
  waiting for its own stack; waiting on other queued jobs returns EDEADLK.
- Null callbacks are empty subscriptions: null quiesce completes successfully,
  null unquiesce performs no callback. The adapter does not reproduce the
  reference's null callback dereference.
- Opaque image-address lookup upgrades a weak registry owner for C completion.
  It never dereferences the image being consumed by close. Binding remains
  valid until admitted callbacks and application completions drain.
- Close stops new quiesce admission, drains accepted application cycles and
  publishes their actual results before immediate unquiesce. It does not
  replace an unfinished application's result with a successful canceled ACK.
  Applications must complete admitted quiesce callbacks; no invented close
  timeout substitutes for that contract.

## Rationale

Application completion, callback return and provider ACK are different
ownership boundaries. Shared image-local state preserves them across watch
replacement. Validated tokens prevent the pinned pointer/internal-ID mismatch
and invalid-count behavior. Independent completion lookup avoids aliasing
the mutable ImageHandle during shutdown. Stronger argument retirement and
honest final results preserve the application contract without reference bugs.

## Consequences

- + No callback argument is retired while an admitted invocation can use it.
- + Quiesce completion remains possible during close without new image activity.
- + Existing writable and update header transports share one local lifecycle.
- - Active quiesce cycles use a worker and a cold registry mutex; performance
  impact needs measurement after functionality and live qualification.
- - Close ACK timing, null callbacks, invalid completions and safe self-removal
  intentionally differ from unsafe or incomplete reference edge behavior.
- - Snapshot/group send-side coordination and complete live qualification
  remain separate required work; this decision does not establish parity.

## Alternatives

- Discard caller callbacks: registration success cannot coordinate snapshots.
- Read ImageHandle from completion during shutdown: violates its exclusive
  shutdown ownership and can reject the completion needed to drain close.
- Reproduce reference count/token and weak-drain defects: violates callback
  ownership and can strand subsequent cycles or free live arguments.
