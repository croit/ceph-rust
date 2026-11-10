<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0693 rustyrados data plane: caller-prepared ops, session reactors, separate control thread

Status: proposed
Date: 2026-11-07
Supersedes: 0467 am. 4-6 (A2 home owners + proxy streams), 0254 (callback hand-off form only; the reentrancy contract stays)

## Context

- Goal (adr 0256, user 2026-11-07): rustyrados and the rbd/rados C ABIs in default settings are >= stock librados in every cell. Anything below 1.000 is a failure, regression or not.
- Today (branch rusty/a2-inbox, n1 default, zen4a, doc/perf/rados-single-client-20261106.md): K=30 OSD sessions 4k read q32 0.952x, K=1 read q1 0.99x, K=1 write q1 0.98x stock.
- The gap is not hop or copy count. Both clients do 3 thread hops per aio op and 2 payload copies per read, and we use fewer syscalls (18.1 vs 23.8 per op, QD1). The gap is owner CPU per op: 29.7k owner-loop cycles per op vs 4.3k for stock at K=30 q1.
- Where the owner CPU goes (measured):
  - fixed per-turn work: about 15 subsystem polls, `next_timer` twice, the sleep proof, scans over in-flight ops; `tick`+`pump` are 27 % of samples at K=1 q1;
  - submit wake (eventfd + mailbox + ledger mutex): 10 %;
  - callback hop, per-op locked: 7 %;
  - second read copy (memmove): 7.5 %;
  - caller-side allocations and locks: 6.7k + 3.2k cycles per op.
- One owner per handle carries every OSD session, so at K=30 it saturates. 53 % of it is kernel TCP that stock spreads over 3 messenger workers.
- The A2 fix (0467 am. 4) adds home owners, an order table and proxy streams, because the msgr2 `Connection` is `!Send` and request state must never move. P0 measured q32 +26 % but QD1 -1..-2 % and +24..64 % CPU per op; the full proxy design is not built.
- Stock librados (own-words spec: doc/spec/librados-client-threading.md, to be added from the spec draft):
  - the caller does placement under a global rwlock, then queues the op on the connection's messenger worker (eventfd wake);
  - the worker encodes, computes the crc and calls `sendmsg`;
  - the reply is fast-dispatched inline on the worker;
  - the aio callback hops to an asio strand;
  - about 12-16 lock acquisitions and 20-30 allocations per op.

## Decision

Threads
- One **control thread** per cluster handle owns the monitor session, cephx renewal, map decode, linger/watch/notify state, mon/mgr/osd commands, pool and snapshot metadata and listings. It never touches an ordinary object op.
- **Session reactors** own OSD sessions. Each OSD session (one connection per OSD per client address, 0467 am. 1) lives on exactly one reactor for its lifetime, assigned at first use to the reactor with the fewest sessions. `msgr2::Connection` stays reactor-local (`!Send`).
- Reactors start lazily up to `min(OSD sessions, R)`, where R is the default reactor bound. R = 3 (stock's worker count; decided in step 4, `REACTORS` in `rados-ffi/src/owners.rs`; a lab gate may revise it). Reactor 1 starts at connect (`OwnerSet::start_first`) and the first OSD session takes it, so the first operation of a client does not pay a thread start, driver and ring setup (0.4 ms of a 3.2 ms cold 4 MiB write on loopback, doc/perf/rustyrados-redesign-20261107.md, "rados-k1-fill"); an idle client runs no reactor beyond that one. Idle reactors sleep (adr 0402).

Submit (caller thread)
- The caller does all per-op preparation that needs no connection state:
  - validation;
  - placement from the published cluster view (one `Arc` load);
  - tid allocation;
  - MOSDOp front/data encode;
  - data crc (fused with the C-ABI input copy where one is required).
- It then pushes the encoded op into the target session's FIFO ring (MPSC, fixed-size slots) and writes the reactor's eventfd only when the reactor is parked.
- Per-object order is the session FIFO: all ops of an object target one primary session at a given view epoch.

Reactor turn
- A turn is O(ready):
  - drain the submit rings of ready sessions;
  - frame (msgr2 seq, header, front crc), with one `sendmsg` per session per turn;
  - receive, decode, match the tid, complete.
- No subsystem polling and no scans over in-flight ops on the data path. Op deadlines use the existing `deadline::SlotIndex` (O(1) first/locate, O(log n) sift over the in-flight window; exact expiry order); a timer wheel is built only if the final benchmark shows sift cost. Every fired deadline logs a loud `WARNING TIMEOUT`.

In-flight state
- One per-reactor op slab replaces the ledger TidMap, the flight map and the tid set. A tid encodes reactor, slot and generation. A slot holds the encoded request, the caller's destination buffer, the deadline and the completion word.
- No allocation, lock or shared-map write on the steady-state op path.

Receive
- After the preamble and tid are parsed, the reply data segment is received straight into the caller's destination buffer, with the crc fused. Only the kernel copy remains, for single-READ, sparse reads and C++ bufferlist reads alike.

Completion
- The reactor sets the completion word. A thread blocked in sync `rados_read` or `rados_aio_wait_for_complete` is woken directly (futex), with no callback hop.
- aio callbacks keep the adr 0254 contract: they never run on a reactor, because a callback may issue blocking I/O. They hand off in batches, one push and at most one wake per reactor turn, to the callback executor, which preserves per-completion order.

Map change
- Map change is a two-phase publish, which acts as a short barrier.
  1. The control thread hands epoch e+1 to the reactors first.
  2. Each reactor retargets its in-flight ops whose primary changed. It pushes them in tid order into the new session's ring; reactor to ring is FIFO per producer.
  3. Each reactor acks.
  4. Only then does the control thread publish e+1 to submitters.
- An op placed at epoch e that arrives at a reactor already on e+1 is retargeted the same way, in ring order. So a resend always precedes any op of the same object placed at e+1.
- Map changes are rare. A submit-side pause of one retarget pass is the accepted trade-off against steady-state cross-thread order state (stock serialises the same under its Objecter write lock). The order-check and map-change fault cells prove it per step.

Map change as built (step 4)
- Home reactor of an op = the reactor owning the primary OSD's session in the view (`Mesh::home`); the OSD-to-reactor table is a single-assignment atomic table, a cold OSD is assigned under one mutex (start a reactor while started < R, else fewest sessions). Owner 0 is the control owner (monitor, maps, linger, commands, listings, flush).
- `ViewCell::publish` runs a barrier hook before the new snapshot becomes visible. `OwnerSet::barrier` raises each started reactor's ring gate to the new generation, sends `Barrier{view, ack}` and waits per ack (limit 10 s; a silent reactor logs `WARNING TIMEOUT map-change barrier` and fails the client with -110).
- Ring gate: a submitter claims a ring cell, then re-checks the gate; a claim of an older generation is tombstoned and refused (`Refused::Stale`), so after a reactor sees its ring quiet nothing older arrives. The submitter re-places the op through the router (`Router::replace`, waits for the publication, limit 20 s, loud) and re-pushes. Ledger phase MOVING covers the re-placement window.
- Reactor: drains its ring, withdraws in-flight ops (tid order) and deferred ops (FIFO) whose home changed, hands them over with their wire tid kept (the OSD dedups by reqid), pushes to the destination rings preserving per-destination order, acks when the outbox is empty, and admits nothing until it has installed the new view. Ops moved with `adopt_wire_tid`; replies for adopted tids are received locally.
- Flush is one global cut on owner 0 (slab scan, uniform for all reactors; an owner-0 flush kick fires when the last cut write completes). Cancel is a broadcast to the started reactors; best effort while the op is MOVING. Shutdown stops, wakes and joins every reactor and finishes outbox handles.

Receive, completion and wake as built (step 5)
- Placement on the epoll inline path: a `Crc` loan of a first-attempt, non-split flight with a bound `ReadPlacement` becomes a caller-memory loan (`place_lent`: staged prefix copied once, the rest read from the socket into the caller buffer). One memcpy per placed read is saved. io_uring inline receive, the offload helper, secure mode, split/EC reads and the sync read form keep the staged copy.
- Completion: each reactor (and owner 0) batches the callback jobs of one turn in a thread-local vector and flushes once (one scheduler lock, at most one worker wake per domain). A thread has at most one batching producer.
- Wake only when parked: `Completion` wakes the futex only when a waiter exists; sync replies and owner parking were already conditional.
- The map-change ring-drain wait is bounded by the barrier limit (loud, fails the client with -110).

Deviations from the first draft: the ring gate with tombstones, the MOVING phase and the flush kick are additions (needed for B1..B5 order without a submit-side lock); flush is global on owner 0, not per reactor.

rbd
- `rustyrbd` gets a flattened fast path: no cache, journal, QoS or migration, with the exclusive lock held. Image extent -> stripe math -> object op submit on the caller thread, with the user buffer as the receive target.
- All other rbd features keep the layered path.

Rollout
- Each step below is one mergeable commit on main, default on. Each must reach >= 1.000x stock in every gate cell. No switch survives the step.

## Rationale

- Stock's per-op path is long: about 12-16 locks, 20-30 allocations, a strand hop and a global rwlock. Its strength is only that 3 workers share the kernel TCP cost.
- This design keeps the stock shape that works (caller-side preparation, connection-owning workers, inline reply handling). It removes what makes stock and our owner slow:
  - shared locks;
  - per-turn polling;
  - per-op allocation;
  - the second receive copy;
  - per-op callback hand-off.
- Doing encode and crc on the caller moves byte work off the reactor, which is the measured cap at q32 and 4M writes. It needs no `Send` connection, because only the framing touches connection state.
- Per-object order by session FIFO plus a map-change barrier is simpler than A2's home owners, order table and proxy streams, which exist only to avoid that barrier.
- At QD1 an op touches exactly one reactor. The A2 QD1 loss (proxy plus cross-owner cache misses) has no counterpart here.

## Consequences

- \+ Owner CPU per op drops to the framing and reply work, with no fixed per-turn cost. Kernel TCP spreads over up to R reactors at many sessions.
- \+ One in-flight table, no hot-path allocation, and one copy fewer on reads.
- \+ The control-plane code (monitor, watch, commands) leaves the data loop; a stalled monitor no longer delays op turns.
- \- A large rewrite of `rados-rt` object_client/sessions and of the rados-ffi ledger. A2 code on rusty/a2-inbox is not merged; reusable parts (the receive-into-caller-buffer path from A1b, the gate scripts) are taken over.
- \- Map changes pause submits to affected sessions for the resend time.
- \- Caller threads do encode and crc work. CPU per op is a secondary goal (adr 0013 user note 2026-10-27).

## Steps and gates

Gate cells, each >= 1.000x stock in IOPS and p50, with p99 reported:
- zen4a/b and ice-b: 4k and 64k randread/randwrite at QD1/QD32/QD64, K=1 and K=30 sessions, 4 handles x QD16, 4M read/write q32;
- an order-check cell and the map-change/OSD-restart fault cells, which must be clean;
- epoll default and io_uring opt-in, crc and secure, each measured.

| # | Step | Expected effect |
|---|---|---|
| 1 | Control owner + data owner split; data turn O(ready); deferred-queue deadline index (done: doc/perf/rustyrados-redesign-20261107.md) | the 27 % per-turn work and the scans leave the owner |
| 2 | Op slab + single tid table; caller-side encode, crc and placement | submit allocations and locks gone; owner byte work moves to the caller |
| 3 | Session rings + parked-only wake | the 10 % eventfd/mailbox/ledger cost becomes a ring push |
| 4 | Session reactors (R from the gate); map-change barrier | K=30 q32 no longer capped by one core |
| 5 | Receive into the caller buffer for all read forms; batched callback hand-off; direct futex wake for waiters | 7.5 % memmove and 7 % callback cost |
| 6 | rustyrbd fast path | rbd cells >= stock librbd |

Measure per step with the committed lab scripts (`lab/rados-client/a2-n1-gate.sh` and the osdscale A/B). One repeat per arm; 3 only for cells inside the noise.

## Alternatives

- Finish A2 (0467 am. 4-6): adds the order table, proxy streams and cross-owner flush/cancel/watch routing to avoid a map-change barrier, and lost 1-2 % at QD1.
- Local cuts to the single owner (wake hold, O(ready) only): measured to be insufficient. The wake hold was -7 % at q32. O(ready) alone cannot close K=30 (0467 am. 6: scans are about 8 %).
- Callbacks inline on the reactor: breaks the adr 0254 reentrancy contract (a callback may block on I/O).
- Several connections per OSD (one per reactor): breaks blocklist fencing (0467 am. 1).
- Caller-thread `sendmsg` under a connection try-lock: would remove the QD1 wake when the reactor is parked, but needs `Send` connection tx state and a split of msgr2 rx/tx sequence state. Deferred until after step 5 measurements; added only if QD1 is still below stock.

## Open questions

- R = 3 is set by parity with stock, not yet by a lab sweep; confirm or change at the step 4 lab gate.
- Reactors claim an unowned OSD they need themselves (lock-free), which bypasses fewest-sessions balancing; revisit if the lab shows skew.
- A split read in flight cannot be withdrawn (`NotMovable`); it stays on its old reactor and the engine resends it. Check in the fault cells.
- Real session-reset fault cells (OSD restart under load on several reactors) are lab work; unit tests cover address-change restarts only.
- Linger/watch op order relative to ordinary ops on the same object, now that linger lives on the control thread (former RC-O15).
- EC direct split reads spanning reactors: does the caller fan out to several session rings under one completion?
