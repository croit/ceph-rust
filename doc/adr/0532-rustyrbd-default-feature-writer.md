<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0532 RBD default-feature writes require Ceph lock and object-map ownership

Status: accepted
Date: 2026-10-23

## Context

Ceph 21.1.2 creates default images with feature mask 61: layering,
exclusive-lock, object-map, fast-diff and deep-flatten. The unchanged C
consumer in `lab/rustyrbd/default-image-open-gate.rs` opened such an image
writable through the reference library; the current `FlatImageWriter`
returned `-EOPNOTSUPP`. The existing watched writer supports only feature
mask 1. The pinned class contracts for exclusive lock and object map are
specified in `doc/spec/cls_lock.md` and `doc/spec/cls_rbd.md` C.1.

## Decision

- A writable default-feature image uses one watched image owner with Ceph
  `rbd_lock` ownership and verified object-map state.
- Header and object-map mutations that require ownership carry the matching
  class lock assertion in the same RADOS operation where the pinned contract
  requires it.
- A failed lock acquisition, lock check, watch health check, map load, map
  update or required data write fails the user operation. The writer does not
  treat a watch permit alone as an exclusive lock.
- Lock loss revokes subsequent writes. Takeover follows the pinned
  blocklist and watch/notify protocol before a new owner may report writes
  complete.
- The layering-only writer remains a development path until the default
  feature set passes byte, ownership, fault and performance gates. Admission
  expands only for combinations whose write and metadata paths are complete.

## Rationale

The default image carries lock and object-map contracts that other Ceph
clients observe. Ignoring either can admit concurrent writers or publish
incorrect allocation and fast-diff state. The narrow admission rule keeps
unsupported combinations explicit while the same owner gains those
contracts.

## Consequences

- + A default-feature image can become a qualified writable KVM image after
  the lock, map, clone and crash gates pass.
- + Existing flat-image write ordering and watch ownership remain reusable.
- - Lock handoff, map state transitions and snapshot/resize interactions add
  control-path work and fault cases.
- - A passing default-image open alone cannot qualify data durability or
  multi-client fencing.

## Alternatives

- Accept mask 61 while ignoring the extra features: rejected because other
  clients rely on the lock and object-map state.
- Create only layering images for KVM: rejected because it does not meet the
  pinned default-image drop-in contract.

## Amendment (2026-11-02): pipelined steady-state AIO writes (am. 1)

- An `rbd_aio_write`/`rbd_aio_writev` whose every object needs neither an
  object-map update (state EXISTS) nor a parent copy-up is admitted and
  submitted on the caller's thread: writer mutex, local admission checks,
  one `rados_aio_write` per object extent, return. The last RADOS callback
  retires the write ticket and completes the user completion. No worker
  thread, no wait for earlier writes.
- Admission is local state only: current watch generation and recorded
  loss, no pending refresh, map refresh, shrink, migration guard or
  encryption, a prepared owner on exclusive-lock images, ownership phase
  Ready (`scan_status`), activity not closing, recovering, failed or on a
  selected snapshot, and every earlier submission admitted with no serial
  write in flight. No per-write `lock.assert_locked` or retained-data class
  call: the reference library does not issue them per write either; fencing
  is the exclusive-lock state machine plus OSD blocklisting.
- Ordering: admission and submission happen under the writer mutex, so
  pipelined writes reach RADOS in ticket order. A serial operation (first
  write to an object, discard, copy-up, admin, recovery, release) takes a
  later ticket and waits for all earlier pipelined tickets; no pipelined
  write passes an admitted serial one. Release and recovery drain them
  through the write fence before the lock is released.
- Result: the RADOS result only (0 or the first error). The serial path's
  post-write ownership re-check (ERESTART on a header change racing the
  write) does not run; like the reference, a write admitted under a valid
  lock completes with its RADOS result.
- A write queued behind serial work (typically the first write after open,
  which acquires the exclusive lock) is not demoted to the serial path for
  good: its worker waits until every earlier submission is admitted and no
  serial write is in flight, then re-checks the same admission and submits
  pipelined. It falls back to the serial path when the image closes,
  recovers, fails, selects a snapshot or loses the prepared owner, or when
  an extent still needs a map update or copy-up.
- Everything else keeps the serial worker path unchanged.

Rationale: the serial path cost one OS thread per AIO write, held the
writer mutex across up to four RADOS round trips and executed writes one at
a time; QD32 gave QD1 IOPS (doc/perf/rbd-qd-20261102.md).

## Amendment (2026-11-02): batched object-map transitions (am. 2)

- Object-map transitions of an allocating write are batched: an unstriped
  write whose objects are all still NONEXISTENT issues one
  `object_map_update(first..last, PENDING, NONEXISTENT)` before the data
  writes and one `(first..last, EXISTS, PENDING)` after them instead of one
  pair per object (the class call filters by the expected old state, so
  already known objects keep their state). Mixed runs, striped layouts and
  the single-object paths keep the per-object form. Rationale: N objects
  cost 2N synchronous class round trips today (doc/perf/rbd-qd-20261102.md).
- Test harness: `object_map_batch` records the transitions and applies the
  class filter, so the call shape is tested without a cluster.
- An absent object is allocated on the pipelined path when the map is valid,
  the image has no parent and no snapshot context: one conditional PENDING
  class call over the write's object run before its data writes, one EXISTS
  call per allocated object after them, before the image write settles. A
  failed data write leaves the objects PENDING (readers probe them; a map
  rebuild reconciles).
- The map finalization never runs on the provider's callback-domain thread:
  a synchronous class call there waits for a completion that needs the same
  domain, which deadlocked fresh-object writes at QD8. It runs on a
  dedicated finish pool, which also keeps it free of serial writes that
  occupy the main pool while they wait for their pipeline turn. A write
  submitted from inside an image callback is queued to the serial worker for
  the same reason (it would otherwise take the writer mutex on the callback
  domain).
- Evidence: fresh-object 4m writes at QD8 on ice-a completed six 30 s rounds
  at 380-450 IOPS with the finish pool and not one round without it (four
  hangs, each a loud 130 s timeout); doc/perf/rbd-qd-20261102.md.
