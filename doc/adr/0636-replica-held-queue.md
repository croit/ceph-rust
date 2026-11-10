<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0636 Replica held queue: one state machine for writes that wait for the store

Status: accepted
Status note: implemented: services/osd/peering/src/held.rs.
Date: 2026-11-01
Amends: 0021 (S11 replica hold), 0043 (am. 18 lease of a held replica write)

## Context

A replica / EC shard PG cannot always run a repop, sub-write or sub-read when it arrives: the store admission of the PG is closed (capacity), its shard is at its system floor (space, adr 0021 S4), pages or blocks it touches are cold (adr 0021 am. 8, 30, 33), or an omap range removal is still being pre-counted (adr 0021 am. 25). Classic applies a replica's data path in arrival order, so a waiting message holds every later data-path message of its PG. That wait was spread over eight `Pg` fields (queue, `replaying`, `held_again`, `replay_resume`, `repop_force`, `held` clock, `held_lease`, `rm_wait`) set and cleared on different paths. Review item B3 (doc/reviews/2026-11-01-osd-review-simplify.md) found reachable combinations that leak a residency lease and a slow-op clock (a held EC sub-write duplicate; a head leaving on a path other than its load verdict, whose lease and clock then passed to the next head) and a range key of one head steering the retry of a later one.

## Decision

- `held::Held` (services/osd/peering/src/held.rs) is the only state of messages that wait for the store: `Idle`, or `Busy { head, state, behind }` with `state` = `Due` (not evaluated yet) or `Wait { on, loads }`, `on` = `Admission | Space | Loads | RmRange(key)`. Its rustdoc carries the transition table; every transition has a unit test against a mock PG.
- Only `held_behind` messages queue behind a head (list unchanged); peering control of a new interval and read leases run at once.
- `Pg::dispatch` runs one message and returns its wait verdict; it never touches the queue.
- A holdable handler runs every drop check (state, sender, shard, decode, duplicate, version order) before its wait verdict: a dropped message never opens a wait. Then: admission, space, forced replay, load probes.
- A load wait (slow-op clock + residency lease) belongs to its head: opened at the head's first `Loads` / `RmRange` verdict, kept through later admission or space waits of the same head, released exactly when that head leaves the queue (runs, is dropped, or the queue is cleared).
- A forced replay (queue at `REPOP_WAIT_MSGS` 64 / `REPOP_WAIT_BYTES` 64 MiB, or a range pre-count whose cursor was evicted) applies the first message of that replay that reaches its load verdict; never an admission or space wait; the force ends with the replay.
- A replay runs at most one message that queues a store persist; the next head is `Due` (the driver queues the persist and rechecks capacity first).
- `Due` replays at the PG's next commit (admission open) or the next timer pass; a closed admission turns `Due` into `Wait { Admission }`. `Wait` heads are retried at store wakes and timer passes; a `RmRange` head asks the pre-count directly first and replays only when it is ready or its cursor was evicted.
- "Cursor evicted" (`RmPrep::Wait { fresh }` for the range this head asked at its previous evaluation) is judged per head; another head's range never counts.
- A message released together with a same-call persist (OQ 46 a) becomes a `Due` head on an idle queue, else queues behind; the waiting head keeps its state.
- A new interval, a merge quiesce and a move of the PG to another core drop the queue (the primary aborted these: new interval) and release every residency lease of the PG.
- `space_wait` stays a PG-level operator-note latch (one note per verdict change), not op state.
- Nothing applies or answers because time passed: the clock only reports (`WARNING TIMEOUT`, slow ops).
- The peering Sim checks on every replica ack that the write was delivered to that replica incarnation, is acked once, in log order per primary, and is durable in the replica's store (services/osd/peering/tests/common/acks.rs); a violation fails the test.

## Rationale

One enum per head makes the observed leaks unrepresentable: no load wait without a waiting head, no range key without a range wait, no flag that survives a call. The transitions are pure over a small `Step` trait (eval, persisted, lease open/release), so each is tested without a cluster. Ceph-visible behaviour is unchanged: the same messages run in the same order with the same verdicts and acks; only the bookkeeping moved. Accepted trade-off: a head that waited for a range and then for admission forgets the range key (one more pre-count round if its cursor was evicted in between).

## Consequences

- + Residency leases and slow-op clocks can no longer outlive their op or pass to the next one; slow-op counts are true per op.
- + One replay loop with one exit per outcome; the force, the persist yield and the range fast path are each one rule.
- + Every peering Sim test checks the four ack invariants a classic primary relies on.
- - An admission or space wait of a head that waited for a range before is re-checked at every retry (the old fast path asked only the range).
- - `REPOP_WAIT_*` forces only load waits; while the head waits for admission or space the queue grows (bounded per OSD by the input credits each held message keeps, not per PG). Unchanged; see open questions.

## Alternatives

- Keep the flags and add the missing release calls: every new exit path must remember them; the leak class stays.
- Hold the wait in the store's park queue: the ordering behind the head, the interval drop and the ack rules are PG contracts the store does not know.

## Open questions

- Per-PG bound while the head waits for admission or space: is the input credit bound enough, or does the typed would-block of B1/B4 (one admission point) replace `REPOP_WAIT_*` and its forced, core-blocking apply? OQ 126.

## Amendment (2026-11-04): queued sub-reads start their block reads (am. 1)

Context: EC 2+2 4K sequential reads (each client's in-flight reads on consecutive stripes, every second one on the same remote data shard PG) ran at about half the random-read rate (doc/perf/ec4kseq-20261101.md, part 2). Only the head is evaluated, so a sub-read queued behind a sub-read waiting for its blocks submitted its device reads only when it became the head: one device latency per queued sub-read, one after the other.

Decision:
- A message that queues behind a waiting head is kicked (`held::Step::kick`): an EC sub-read starts the data reads of every range whose tree path is resident (`Pg::ec_read_kick`: same ranges as its wait verdict, no lease; nothing runs, applies, answers or waits). Repops, sub-writes and the other `held_behind` messages are not kicked.
- A kick that could not start the reads (cold tree path, its loads were submitted; closed admission) is repeated when a replay leaves the message queued (`Queued::kicked`).
- Order and answers are unchanged: messages run and answer in arrival order.

Rationale: overlap without reordering, like the opexec arrival probe of a client op queued behind others. Ceph: the classic shard answers its sub-reads in arrival order too (one synchronous store read each); reply order is no contract (the primary matches replies by tid, spec ec.md 6.5 "reads may overlap writes"), so letting sub-reads overtake was possible but needs per-read waits re-probed at every store wake.

Consequences:
- + Queued sub-reads load in parallel; the queue drains at the pace of the slowest load, not the sum.
- - A kicked read has no lease: a prefetch run that expires (`PF_TTL_NS`) before its read runs is read again; a kick refused by the prefetch admission loads when it is the head; a lease-less admission waiter of a kick expires after `PF_WAIT_NS`.

Alternatives: sub-reads overtake waiting sub-reads (independent waits): more state per message, O(waiting reads) probes per store wake.

Open questions: kick the loads of queued repops / sub-writes (tree pages, stash sources) too?
