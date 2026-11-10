<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0567 Update callback ownership spans admission through explicit drain

Status: accepted
Date: 2026-10-24

## Context

A provider callback retains the UpdateWatch independently of the public image.
Dropping the image's Arc cannot establish callback completion. Registration,
watch replacement and local unwatch can overlap; provider retirement must not
lose local subscriptions, accepted callbacks or their argument ownership. The pinned
reference synchronously deadlocks when its update callback closes its image.

## Decision

The image owns a persistent local registry and FIFO executor independently of
its provider transport. External close drains this local state before writer
and provider teardown. Normal opens register the provider before snapshot
selection; user-read-only opens create only the local state. Internal refreshed
views create neither. Public registration/unregistration operate only locally;
provider loss, failed replacement and last-unwatch preserve local-state lifetime.
Update callbacks execute on one owned FIFO worker, outside provider delivery.
Jobs retain accepted records and ACK responsibility until callback completion;
HeaderUpdate ACK barriers queue even when no subscription currently exists.
Close blocks incoming delivery before decode with immediate empty ACK, drains
already admitted callback/ACK jobs, then unregisters and flushes the provider.
Worker creation failure propagates before allocating the private provider ioctx;
callbacks never fall back to inline provider-thread execution.
Accepted callbacks have per-registration accounting and independent image-wide
shutdown accounting; shutdown waits for them even if provider flush fails.
Registration admission and callback publication share the lifecycle lock.
The local registry never transfers its records into a replacement transport.
Queued provider ACK ownership retains its originating transport until delivery;
provider close waits for that ownership independently of local subscriptions.
Ordinary unwatch stops future admission and drains that registration's accepted
invocations without cancelling them.
Reentrant unwatch preserves the registration and returns EDEADLK when another
accepted invocation would require waiting; a sole self-invocation can unregister.
Self-close detection uses a stable logical image identity in callback TLS,
independent of the replaceable watch slot; it returns EDEADLK before consuming
the handle. Other close errors consume the handle after teardown, preserving
the first error in update-drain/owner order.
AIO completion callback pins keep their existing separate close behavior.

## Rationale

A caller can free callback arguments after successful external unwatch or image
close. Provider context retention alone does not retain caller-owned arguments.
Application callback accounting establishes their lifetime even when a provider
fence fails, while preserving the provider error and retaining uncertain ioctxs.
Returning a non-destructive reentrancy error avoids reproducing a reference
wait cycle or claiming successful unregister while another invocation uses arg.

## Consequences

- + Rejected registration never publishes a callback that outlives its failure.
- + Successful registration cannot disappear on a concurrently retired watch.
- + Close drains accepted user callbacks independently of provider fence status.
- + Reentrant lifetime failures are explicit and preserve the caller's ownership.
- - Shared local/configuration events, automatic rewatch and coherent refresh
  generations remain separate implementation work.
- - Normal writers currently retain separate physical writer/callback watches;
  a common transport must preserve both write and callback ACK barriers.

## Alternatives

- Rely on Arc destruction: another callback Arc can postpone teardown past close.
- Cancel accepted callbacks at external unwatch: violates the accepted-work contract.
- Return success from reentrant unwatch while another invocation runs: permits UAF.
- Couple local subscriptions to provider lifetime: loss or failed replacement
  can discard registrations and makes user-read-only registration require a watch.

## Shared writer registration

Normal writable images attach local ImageUpdates to the existing HeaderWatch;
they do not create a second provider registration. Accepted HeaderUpdate jobs
own HeaderUpdateAck and retain their WatchState. Callback completion transfers
ACK responsibility to the existing write gate; if writes are still admitted,
the final write retains ownership until deferred ACK delivery. Close seals
notification admission under the same pending-ACK mutex and drains both callback
owners and admitted writes before provider teardown. The gate does not count
later callbacks as writes, so an earlier callback's ACK does not wait for a
later callback. Raw metadata watches preserve their empty-ACK protocol.
Normal images without a writer retain the independent provider transport; both
transports use the same image-local registry/executor and accepted-argument rules.

## Metadata commitment and publication

Metadata set/remove install their committed writer view under its mutex, then
release that mutex before local callback publication and synchronous provider
notify. The accepted write activity permit spans both phases. A committed
mutation still publishes when view refresh fails; that error remains visible
unless a non-tolerated notification error takes priority. Provider notify
ETIMEDOUT/ENOENT are mapped to success, retaining loud timeout diagnostics.
This phase split is currently applied to metadata set/remove; remaining writer
mutations and effective configuration reapplication are tracked separately.

## Resize, rollback and copy size stages

Public resize and user/mirror rollback return committed update outcomes from
the writer scope; local/wire publication follows after releasing its mutex.
A successful same-size public resize still checks owner admission and publishes.
Rollback uses silent commit_resize internally, preserving installed size on
later failure without synthesizing an internal or failed outer update event.
Its public progress uses zero-based object indices and supports cancellation.

Deep-copy selects each version's head size by direct class mutation without
trimming data or publishing; its map preparation remains a separate copy stage.
The dense copy algorithm tracks maximum selected extent and trims only the
final HEAD tail through the current SnapContext, preserving prior snapshots
and preventing stale data on later growth. The final writable map matches HEAD
geometry. Snapshot helper notifications keep their independent boundaries.
The shared data-tail trim stage also serves ordinary shrink; its unstriped
admission boundary remains explicit pending broader geometry implementation.

## Snapshot commit outcomes and failed refresh admission

Snapshot create/rename/protect/unprotect install committed views under the
writer mutex and publish outside it, retaining operation activity. Deep-copy
publishes each successful nested snapshot operation independently before
continuing; a later failure cannot discard that event obligation.

Successful header snapshot_add owns its ID/record. Map work degrades errors by
invalidating the NEW snapshot's flags; propagated map/invalidation failure keeps
the record/ID and still installs the full SnapContext. No synthetic undo drops
an already published snapshot. Local HEAD clean conversion follows successful
class snap_add only. An uncertain failed HEAD map class completion requires
map reconciliation under checked ownership before later data mutation; fresh
ownership acquisition loads the durable map and clears that requirement only
on success. Releasing ownership must not strand admission on a missing owner.

Successful header mutations and failed view refresh retain explicit dirty
state. Scalar, sync and AIO cached-generation paths honor it; refresh failure
cannot allow subsequent writes under an old SnapContext merely because no
wire event arrived. This is writer-view admission, not a claim of complete
shared ImageState refresh/configuration observation.

## Refresh convergence under delivered invalidations

A notification that races a cached-view check or coherent metadata observation
starts the next refresh generation instead of exposing that internal Stale
result as a scalar API error. Refresh re-observes and validates the new head
until its delivered generation remains current; only typed watch Stale causes
this state transition. Provider/watch/policy errors remain visible and keep
refresh_required set. No timer, arbitrary RPC retry or callback/ACK wait is
introduced. Later I/O admission retains its independent generation fence.

## Fresh-snapshot map invalidation safety difference

The adapter explicitly invalidates retained NEW snapshot map flags on map-stage
failure. It does not reproduce the pin's missing-local-snap_info shortcut that
swallows the same failure with flags0. Exact classic fault evidence showed
owner1/features61, shared class CRC failures, unchanged corrupt HEAD bytes and
successful create with new flags0. The pin's base request checks local flags
before update_snap_context installs the new ID, so it skips invalidation.
Own flags3 is an observable conservative safety improvement; retained identity,
full write SnapContext and old data remain mandatory. Reference flags0 is
recorded separately rather than used as a success condition for own code.

## Copy map shrink precondition

When selecting a smaller copy version, clear only its inactive out-of-range
HEAD map entries before shrinking that map. The class rejects shrink while
those entries differ from NONEXISTENT. This metadata stage does not remove
physical data or change saved snapshot maps; dense later versions repopulate
newly grown ranges. Highest-extent final trim retains ownership of physical
cleanup through the full SnapContext. Dirty-map admission remains set across
any stage failure until a validated readback or fresh ownership acquisition.
