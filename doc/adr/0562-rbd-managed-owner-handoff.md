<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0562 Managed owner callbacks schedule independently drained release

Status: accepted
Date: 2026-10-25

## Context

Header watch callbacks must ACK peer lock requests while operations can own the
writer mutex. Owner release must wait for durable writes and map cleanup without
waiting inside that callback. Pinned contracts: managed-lock-handoff.md and
image-watch-lifetime.md. Public DATA requester admission uses the shared coordinator; internal DATA/admin continuation remains incomplete.

## Decision

A callback-owned managed state separates actual local leases, publication hints,
policy and ownership invalidation from image metadata generation. Class acquisition
records preparing state; completed post-acquire setup publishes ready ownership.
Hints do not grant or revoke the actual local lease. Stale releases cannot clear a
newer identity. Self-request detection uses the provider's current public instance
ID and current watch handle, including during cookie replacement.

Header acquisition validates GetLocker before the class lock. The provider
boundary distinguishes vacant, recognized internal and external holders from
transport/decode failures. External holders return internal subrequest EBUSY
without class mutation; provider ENOENT and decoded empty locker maps permit an actual acquisition
attempt. An internal observation is not a lease, and class EEXIST is still an
error. The same classifier serves public/break revalidation with their existing
errno mapping. A recognized stale holder traverses nonforced watch/tuple/fence/
break checks;
live or replaced owners return EAGAIN from that subrequest. Initial missing
plus busy rereads the locker and retries class before any break. Completed
break clears the capture and retries class directly. The outer full requester
must wait on RAW HEADER EBUSY/EAGAIN, including external-lock EBUSY; arbitrary
preparation/map errors with the same errno must instead roll back and propagate.

Initial policy reads global configuration once before image metadata refresh.
Explicit EXCLUSIVE installs Standard and EXCLUSIVE_TRANSIENT installs Transient,
including when already owner. Metadata/config refresh does not replace policy.
An existing preparing/ready/reacquiring/pre-release owner acknowledges public
manual acquisition through managed state without a serial DATA ticket or writer
mutex. Accepted release is not reversed. Uncertain release failures remain errors.

Ownership query snapshots a separately stored assertion cookie and performs its
remote check outside the writer mutex. That cookie can exist before successful
local preparation and survives failed acquire attempts. Query false does not
release leases or change authority. Successful cookie replacement updates the
snapshot only after its class operation; completed unlock clears it. Confirmed
missing-header unlock also publishes the prepared owner's release hint.

Class-proven header/map leases are transferred into a preparation scope before
fallible postchecks. Failed setup attempts explicit ordered rollback; failed
rollback retains the real leases in the writer, separately from loaded DATA
ownership. No partially prepared scope grants DATA. Explicit cleanup retries
those same resources. Retained cleanup errors fence every owner admission using
an atomic error snapshot; they cannot be cleared by ready publication/recookie.
Recovery of a failed preparation or release performs cleanup only. Restoration
of a previously prepared owner captures its reacquisition intent before releasing
old leases and retains it across failed attempts; accepted release cancels it.
Explicit release also advances the owner epoch once, so old revision permits
cannot regain authority after the local owner has been cleared.

Automatic acceptance gates activity admission and schedules owner work before
ACK0. Standard returns EROFS; Transient returns0 without scheduling release.
Partial preparation, reacquiring and pre-release ACK0 without duplicate release;
ready ownership without a valid advertisement ACKs empty.

Unowned application DATA acquisition is permitted only by Automatic. Standard
and Transient refuse write/discard/zero/writesame/compare-write and USER flush
until explicit acquisition. Existing owned DATA, explicit administrative acquire
and previous-owner cookie-recovery fallback remain independent of that gate.

Managed state captures effective per-image blocklist enable/expiry at lock-object
construction, independently of later policy or config changes. Cookie recovery
uses that capture. Legacy entity/cookie break reloads current image/pool overrides
instead; invalid image values shadow pool values and fall back to global config.
A blocklisted connection is fenced by provider blocklist add and latest-map wait
before the class lock can be broken. The legacy supplied cookie is not used to
select the connection address. Managed forced/stale break probes watches, revalidates the captured locker tuple,
rejects live nonforced owners, and fences an unchanged owner before exact class
break. Self entity is rejected when blocklisting is enabled. Public address
break copies the captured settings through activity's managed Arc without the
writer mutex. Public Automatic DATA uses owner cohorts before execution tickets; administrative requester continuation remains separate work.
Synchronous and AIO USER flush drain their captured accepted write prefix, then
check DATA policy before waiting for owner work, without issuing a serial write
ticket. Standard/Transient refusal does not join an already pending manual
acquisition. Read-only/immutable views keep prefix-only flush behavior; internal
owner-drain flushes do not try to acquire.
The AIO worker drops its private writer Arc before retiring its operation pin
and invoking a callback that can close/consume the image.

Write acceptance and serial execution have separate monotonic sequences.
Acceptance pins the image and captures submission order without waiting for
recovery. AIO moves that reservation to its worker; only the worker waits for
recovery and admission in accepted order. USER flush captures the accepted
sequence, including work not yet admitted. Owner work drains only the serial
execution prefix, so waiting submissions cannot become its own drain dependency.
Dropping an unadmitted submission (including failed thread creation) retires its
accepted sequence and advances cancelled admission holes; completing an admitted
write retires both sequences before callbacks. Automatic DATA joins owner cohorts while holding only this accepted reservation;
prepared authority is rechecked before execution-ticket issuance.

USER flush uses the same Automatic cohort after its accepted prefix and takes
no execution ticket. Successful admission is its ownership linearization point;
it does not re-acquire through the writer after a later peer release. Only
actual class ownership and completed post-acquire work clear the gate. Metadata
preprocessing uses an independent read-only view when a watch is lost, including
loss racing a healthy refresh. That view cannot authorize DATA; watch recovery
and owner acquisition still precede execution.

The require-write-lock gate starts enabled for a managed image, remains set
through acquisition preparation, clears only at prepared ownership publication,
and is set on release. DATA policy refusal is checked before admission waits;
clipping and operation-specific preprocessing errors retain precedence through
validation outside the activity mutex. The ordinary prepared-owner path skips
this cold-path validation. Retained cleanup failure keeps its original error.
Administrative write reservations bypass this DATA predicate. Valid AIO refusal
settles completion and its accepted sequence without becoming a latent write
after manual acquisition succeeds. Failure callback delivery retires activity
and watch permits first, including inline delivery after failed thread creation.

The recovery coordinator serializes rewatch, accepted release and manual acquire
cohorts. An unowned manual call pins its lifetime, gates new write admission and
drains the captured prefix before acquisition without taking a serial DATA
ticket of its own. Already-owned public manual calls retain their distinct
immediate policy/phase contract. Ordinary acquisition/refusal/preparation errors
settle that cohort, allowing later independent retries; blocklisted transport
retains its connection-wide fence. Explicit release uses the same prefix drain,
coalesces accepted release and can retry retained cleanup errors. Ready
publication cannot reverse an accepted pre-release intent.

A raw HEADER failure and a PostAcquire preparation failure retain separate
causes. Only raw HEADER EBUSY/EAGAIN enters peer-request wait. The request uses
a private provider context outside the writer mutex, and the matching provider
frees replies. A local owner-hint generation is captured before attempt and
notify to preserve wake-before-wait ordering. Hints trigger authoritative retry,
never ownership. Protocol resend expiry repeats the request rather than DATA or
class acquisition; configured signed-width timer conversion follows the pinned
spec. Rewatch/release work preempts the peer wait. Close and selected-snapshot
admission wake/cancel it. Counter overflow is an explicit error.

The existing recovery coordinator serializes transport and peer-release work.
Peer release captures the admitted durable write prefix, waits outside the writer
mutex, drains outgoing hints, releases map before header and drains the release
announcement. It leaves the watch registered and does not reacquire. A pending
peer release also suppresses fallback reacquisition. Close owns/drains both work
kinds. Real release errors retain the lease handles and blocked admission state.

A public release that observes an owned pre-release phase joins that release's
separate completion before taking any write ticket. A releasing/unowned phase
does not join and follows ordinary no-owner validation. Joiners own image pins
and immutable completion identities, so later owner work cannot replace their
result. Provisional close cancellation preserves accepted joins; committed
close settles them before draining operation pins.

Long rebuild scans observe a separate owner epoch. Ownership restart is a typed
outcome distinct from application/provider errno. Public rebuild keeps its image
pin, releases the attempt ticket and refreshes/chooses ownership again; negative
user progress results remain ordinary errors. Metadata invalidations do not become
ownership handoffs and ownership hints do not masquerade as metadata updates.

## Rationale

Callback-owned state avoids a notify/self-ACK writer-mutex deadlock. A single
coordinator prevents peer release and cookie recovery from concurrently changing
the same leases. Typed restart avoids mistaking a user errno for protocol control
flow. Separate epochs preserve metadata callback semantics.

## Consequences

- + Peer ACK acceptance and actual durable unlock have distinct completion points.
- + Existing accepted writes drain before ownership can move.
- + Current lease identity is separate from changing publication hints.
- - Internal DATA/admin continuation and wider interference/fault qualification
  remain required for full bidirectional handoff and continuation.
- - Resize/flatten progress and owner cancellation require the same sibling audit;
  this increment does not qualify those paths.
- - Stale-owner/blocklist fencing and administrative request-block nesting remain
  required before full managed-lock compatibility can be claimed.

## Alternatives

- Unlock inside the provider callback: rejected because accepted operations can
  require the same callback execution context to complete.
- Wait for ownership while holding a serial ticket: rejected because owner work
  can be waiting for that ticket's durable prefix.

## Open questions

- Broaden owner fault qualification beyond the bounded classic-provider matrix;
  recorded evidence lives in doc/perf/librbd-completeness-20261024.md.
- Connect internal temporary DATA/admin continuation to owner work; qualify wider
  coalescing, snapshot/close/watch faults before claiming full requester parity.
- Complete resize/flatten cancellation, forwarding and progress lifetime handling.
- Complete administrative request blocking and exact stale-owner fencing.
