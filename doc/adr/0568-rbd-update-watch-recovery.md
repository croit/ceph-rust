<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0568 Image update watch recovery retains image-local subscriptions

Status: accepted
Date: 2026-10-25

## Context

Normal image opens without a writer use an independent provider header watch.
Its previous permanent error latch lost future metadata invalidations after
provider watch failure. Local subscriptions already have image lifetime.
The pinned provider boundary currently offers this adapter blocking watch
registration and removal; those calls cannot run on provider callback threads.

## Decision

UpdateWatch recovery retains the same ImageUpdates registry and provider
callback receiver across unwatch/register actions. A transient worker owns
recovery only while an error requires it; healthy images gain no worker.
Lifecycle state serializes recovery admission, replacement cookie publication
and close. Close seals new recovery and waits for the in-flight provider action
before final unwatch/flush/context destruction. An owned completion guard
settles the close pin on return, panic or worker-spawn failure. An unwatch
failure with uncertain local cancellation retains its original cookie/error
across replacement registration; close preserves that cleanup error and context
rather than treating a zero current cookie as proof of cancellation.

Initial registration remains distinct from recovery. A successful initial
provider completion enables recovery without waiting for a simultaneous error
callback's recovery to finish; a negative initial completion fails open. Completed
recovery delivers a synthetic metadata invalidation through the existing local
strand, without a notify ACK. Terminal outcomes leave the transport unregistered
while local subscription tokens retain their identity. Provider error edges
arriving during recovery require another action; no arbitrary timer is added.

Writer HeaderWatch recovery additionally requires real lock-cookie recovery
and remains a separate required implementation; this decision grants no writer
authority and does not qualify that missing path.

## Rationale

Separating image and registration lifetime preserves accepted callback storage
and permits recovery without moving opaque subscription handles. Blocking
provider actions require execution independent of callback delivery. The
completion pin makes close ownership explicit without detached access to a
freed image or ioctx. Transient workers avoid an additional idle thread per
healthy image; outage-scale resource behavior still needs measurement.

## Consequences

- + A repaired transport can resume metadata invalidation on existing handles.
- + Close and recovery share an explicit provider-context ownership boundary.
- + Existing callback strand and registry retain ordering and handle identity.
- - Simultaneous failures can create multiple transient recovery workers.
- - Writer recovery and shared configuration observation remain required.

## Alternatives

- Permanently latch loss: rejected because metadata observation never resumes.
- Rebuild local subscriptions with a replacement watch: rejected because image
  callback identity and accepted argument ownership outlive a registration.
- Blocking provider calls on the update callback strand: rejected because user
  callbacks and ACK retirement must continue independently of recovery.

## Open questions

- Qualify provider-specific negative-unwatch cancellation to release contexts
  after proven local retirement and flush, including own pre-admission failures.
- Measure outage-scale recovery resources after functional parity; evaluate an
  asynchronous provider action executor if thread creation dominates.

## Direct read visibility after invalidation

Normal handles without a writer share a HEAD read-view cache keyed by the
accepted ImageUpdates generation. A changed epoch refreshes an immutable view
through private metadata contexts; concurrent consumers join that refresh.
Publication requires the same epoch after the query. Stable epochs reuse the
view. Selected snapshots keep their existing selection/epoch ownership, and
writer HEAD keeps its own authority-aware refresh.

Scalar/stat, synchronous reads/iteration and AIO admission capture this view.
AIO retains the Arc through completion so later metadata invalidation cannot
retire borrowed layout/provider contexts. Reconnect's synthetic event therefore
updates both callback-visible geometry and actual subsequent I/O admission.
This cache does not add metadata polling or reinterpret absent USER-read-only
provider watches as automatic peer invalidation.
