<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0467 rustyrados receive byte work on helper threads, one protocol owner

Status: accepted (A1/A1b implemented, A2 accepted in am. 4, not built), amended (am. 1, am. 2, am. 3, am. 4, am. 5, am. 6, am. 7)
Date: 2026-10-20

## Context

One `rustyrados-io` thread runs the protocol owner and the transport driver and does every per-byte job (kernel receive copy, CRC, kernel send copy). 4M read reaches 2.7 GB/s (librados 6.0), 4M write QD32 4.0 GB/s (librados 5.4) at 1.2-1.35 cycles/B on that one core (OQ 80, adr 0466). Design: doc/design/rustyrados-reactors.md.

## Decision

- A1: the owner and driver stay one thread; filling large receive loans (kernel copy + CRC) moves to helper threads (crate `rados-rt`, module `offload`), for epoll and io_uring through one backend-neutral interface.
- A helper job owns the read side of one connection plus the moved loan (filled to its end, CRC fused with commit, `SO_RCVLOWAT` = one chunk while waiting). At most one job per connection; the driver does not read that socket until it collects the job.
- Sends stay on the driver: send helpers lost the A/B (doc/perf/rados-client-offload-ab-20261020.md) and were removed.
- Handoff is lock-free: per-connection lanes (atomic state + slot, Release/Acquire), per-helper mailboxes, park/unpark, return through the driver's existing waker. No queue: no idle helper and no room to spawn = the driver does the work inline.
- Pool: process-wide, lazy, at most `available_parallelism() - 1` helpers; idle clients start none; joined at the last driver drop.
- Offload threshold derived once per process (copy+CRC cost per byte against half a park/unpark round trip, rounded up to 4 KiB). `RADOS_TRANSPORT_OFFLOAD=off|<bytes>` overrides for diagnosis and A/B.
- Owner-visible contracts (completion exactly once, cancellation, flush/fence, per-object order, watch/notify, admission) are unchanged: helpers never see requests, completions or caller memory.
- A2 (several owner threads, sessions partitioned by OSD) is not built; it is gated on A1 measurements showing the owner, not byte work, as the cap.

## Rationale

The cap is byte work, not protocol work; moving byte work keeps the single-owner state machine (all existing contract tests stay valid) and avoids A2's cross-reactor ordering, flush and map-epoch risks. Per-direction exclusivity keeps per-connection byte order without locks. Accepted trade-off: one park/unpark handoff per job (only above the derived threshold) and a dup'd fd per offloaded connection. Send helpers: the saved send copy (no CRC on the send side) did not pay a handoff per staged batch.

## Consequences

- + Receive copy and CRC of large transfers run in parallel across connections (4M read QD32 +49/+59 % vs main on zen4, still 85 % of librados: open bug, OQ 101, 121).
- - Receive CPU/B above librados (1.43-1.59 vs 1.04; open bug, OQ 101, 121): handoff, cross-core cache traffic of the filled loan.
- - Writes unchanged (driver send copy).
- + Idle cost unchanged: no helper threads while no job ran; parked helpers cost no CPU.
- - Read data is still copied into the caller buffer on the worker thread (publish copy); see Open questions.
- - One extra fd per offloaded connection (dup kept until the helper returns, so no fd number is reused under a job).

## Alternatives

- A2 multi-owner split now: rejected for this step (ordering/flush/epoch risks, whole state machine becomes concurrent).
- Send helpers (staged batch per job): built and measured, loss (write 4M QD1 -31/-52 %, 26-33 context switches per op); removed.
- Second receive thread per connection reading into a shared ring: needs locks or SPSC rings per connection and changes loan ownership; the job model moves owned memory instead.
- io_uring alone: does not change the copy/CRC cost (adr 0466).

## Amendment (2026-10-23): A2 constraints, owner work per turn (am. 1)
- One OSD connection per client address is a protocol fact: an msgr2 server stops an existing lossy connection when a second one arrives from the same peer address (pinned ProtocolV2 server ident handling). Several OSD connections need several nonces, and fencing (`blocklist add <addr>` of a lock owner's address, as `rbd` lock breaking does) would then miss the other nonces' writes. A2 therefore keeps one address and one connection per OSD; every OSD's session lives on exactly one reactor.
- With that, A2 needs: requests whose primary moves to another reactor's OSD either migrate (tid, payload, completion, retry state) or are proxied through the session-owning reactor; per-object order across a map change (a resend must reach the new session before newer ops of the object); flush/cancel/watch routing across reactors; split (EC direct) reads spanning reactors. A design that keeps order without a global barrier: logical owner = object hash, session owner = OSD, FIFO rings per (logical, session) reactor pair, wire tids and watch cookies partitioned by logical reactor so replies and notifies route back without lookups. Not built in this round (user decision 2026-10-22: stability and speed of the existing surface); it needs the msgr2 `Connection` to become `Send` (its dispatch budget and auth handler are `Rc`-based and shared with the OSD).
- Owner work per turn is cut instead: sent ordinary requests waiting for their reply are skipped by dispatch visits and the sleep proof (a turn was O(in flight): 64 visits x 2 progress calls at QD64), completion callbacks are pushed straight into the executor's domain queue (no ingress thread hop) with one idle worker woken per runnable job, and the MOSDOp front is sized once. zen4 4k q64 read +8/+14 % at -23/-27 % client CPU per op, QD1 -26/-28 % CPU per op vs main. Measurements: doc/perf/rustyrados-stability-20261023.md.

## Amendment (2026-10-23): A1b read placement, receive-cost threshold, owner work per op (am. 2)
- A1b: a request that is exactly one READ into caller memory (C `rados_aio_read`) registers a `rados_rt::ReadPlacement` with the owner (`ObjectClient::place_read`). When the reply's data segment goes to a receive helper, the owner binds the placement to that job (the lent message's tid finds the flight; first attempt, segment fits the caller memory): the helper receives the rest of the segment straight into the caller memory at the segment offsets (CRC per received chunk) and copies the prefix the loan held; the loan comes back `TcpRxLoan::Placed` and the decoder takes the caller memory as the segment (`msgr2::SegBuf::foreign`). Publication (`Destination::PlacedBytes`) finds the payload at the caller address and copies nothing. The socket copy is the only copy of the payload (librados receive-buffer equivalent).
- Placement lifetime: every helper write is bracketed (`begin_write`/`end_write`); `seal` (the request leaves the owner: polled completion, cancel, close) and `spend` (any resend) stop further writes after a bounded wait (one non-blocking receive or the prefix copy). A placement stopped after bytes went to the caller memory fails the job (connection fault, resend): the frame cannot be completed without them. A sealed placement is never handed to the decoder. The caller memory belongs to the operation until completion; bytes of a failed attempt are overwritten by the publication of the attempt that completes it (unverified until the frame crc, as librados receive buffers).
- Offload threshold: per-byte work = the receiving thread's CPU time for socket receives over loopback TCP plus CRC (a user-space copy, the old proxy, is several times cheaper than the kernel receive copy); a failed measurement keeps offload off.
- Owner work per op cut further: MOSDOp encoded in place (no request clone per send), a request routed in the same visit is not routed again at send, a running bound skips the per-flight resend-time scan of the timer query, local-id maps use multiply-rotate hashing (`rados_rt::TidMap`), one ledger lock per completion (credit released under the removal lock when the owner holds the last reference), one callback-scheduler lock per completion answer (publish tells whether callbacks exist), no notify while a woken worker has not taken the lock, producers wake the owner at most once per owner turn, deferred expiry moves nothing when nothing is due.
- Measurements: doc/perf/rustyrados-beat-stock-20261023.md.

## Amendment (2026-10-27): receive streams and inline placement not adopted (am. 3)
- Receive streams (a helper decodes whole small frames per connection) and inline placement of small read frames were measured and are not adopted: no mergeable default. The owner's per-op work (receive, completion wake, publication) is the cap for 64k reads; A2 (owner per session shard, am. 1 constraints) is the route. Completion waiters are woken after the state lock is released (rados-ffi).
- Measurements: doc/perf/rustyrados-64k-20261026.md (includes the A2 plan).

## Amendment (2026-10-28): A2 design proposed: OSD-owned sessions, sticky object homes, proxy streams (am. 4)
Status of this amendment: accepted 2026-10-28 (lead); nothing built; steps 0-3 + P0 gate scheduled after the S4/S5/P12 cuts merge. Design, proofs, test and step plan: doc/perf/rustyrados-a2-design-20261028.md. Replaces the am. 1 A2 sketch (logical owner by object hash, migration, `Send` connection).
- Owners: each OSD session (its one connection) is owned for the client's lifetime by one owner thread with its own driver (epoll or io_uring) and `ObjectClient`. OSD -> owner is set once at first use (least sessions; owner 0 last). Owner 0 keeps the monitor, cephx renewal, every control and all linger state. Owners are started lazily; N = min(OSD sessions + 1, `available_parallelism() - 1`), floor 1; N = 1 is today's path.
- Home: every object request has one home owner, chosen at submit through a shared order table (`order_key` bucket -> home, outstanding count). The home is sticky while the bucket has outstanding requests and set to the owner of the current primary when it has none. The home holds the request from admission to completion (tid, attempts, resend, backoff parking, completion); request state never moves between owners.
- Proxy streams: a home whose target OSD belongs to another owner sends through a per-(home, OSD) stream to that owner, which encodes on its connection in FIFO order. A stream is a lossy session: any rejection or connection loss resets the whole generation and the home resends in order. Replies route back by tid partition (`tid = seq * slots + owner`); backoff and watch events are forwarded.
- Cross-owner state is limited to: the published cluster view (`Arc` map, OSD ticket, entity, global id, address nonce; owner 0 writes, owners and submitters read), the order table, the OSD -> owner table, per-owner inboxes, and the existing ffi ledger. msgr2 types stay owner-local (`Connection` does not become `Send`); per-owner `SessionTable` global_seq suffices because each OSD talks to one owner.
- Contracts: per-object order = single-home invariant + the existing C1-C3 machine + FIFO streams. Flush = per-home cut with a countdown. Cancel goes to the recorded home. Pause/full is gated per home under its adopted view. Completion is published once by the home. Shutdown: ledger close, owners fail their own flights, owner 0 joins the others and closes the monitor last.
- Rollout: `RADOS_CLIENT_OWNERS=1|auto`, default 1 until the zen4 gate (64k q16/q64 >= stock, CPU/op <= main + 5 %, order-check cell clean); then default auto and the switch is removed. A branch-only prototype (no proxy, static map) runs first, and A2 stops if 64k q64 is below stock (>= stock is the gate).
- Rationale: one saturated owner caps 64k reads (82-86 % of samples, 37k op/s per core). Stock spreads the same per-op work over 3 messenger workers. Keeping every request's ordering decisions on one thread reuses the tested single-owner machine, and the steady state adds only two atomics per op (no thread hop). Migration plus an epoch barrier was rejected: two consecutive map changes reorder migrated vs forwarded requests unless a global barrier and a submit grace period are added.

## Open questions

- A1b: done for single-READ caller buffers (am. 2); C++ bufferlist reads, sparse reads and EC split reads still copy at publication.
- A2 (am. 4, accepted): open within the design: linger vs ordinary op order (RC-O15), N bound on large hosts, EC split reads, RDMA with N > 1. Also in doc/90-open-questions.md (OQ 95, 101).

## Amendment (2026-11-02): A2 implementation decided: step 4 scope and gates (am. 5)

- Start the A2 implementation from am. 4 as written: owners own their OSD
  sessions for the client's lifetime, the home owner holds a request from
  admission to completion, and cross-owner traffic uses lossy proxy streams.
  No design change, no request migration, `msgr2::Connection` stays `!Send`.
- Step 4 (first mergeable increment, behind `RADOS_CLIENT_OWNERS=auto`,
  default 1): owners and their drivers start lazily, every OSD session is
  assigned to one owner at first use (least sessions, owner 0 last), and an
  object request's home is the owner of its current primary OSD (the P0
  prototype's static mapping). No cross-owner proxy yet, so a home change
  across owners (map change, OSD restart) must park new requests of the
  object until the old home is idle and then re-home; existing tests for
  per-object order and resend stay the gate, and the map-change cases that
  the proxy will cover run only in step 5.
- Step 5: proxy streams plus cross-owner flush, cancel, watch/notify and
  pause routing; then the home may stay object-hash based. Step 6: default
  `auto` and remove the switch.
- Gates per step (ice-b, one lock, arms stock / base / after, 3 rounds):
  single handle 4k randread and randwrite QD1/32/64 >= stock (QD1 no
  regression), 4 handles x QD16 >= stock, order-check cell clean, client
  CPU/op <= base + 5 %. Step 4 alone must already beat base at 4k QD32 (the
  owner is saturated there: 98-99 % of one core, 11.7 us/op,
  doc/perf/rados-qd32-20261102.md); the e9455 confirmation (30 OSD sessions,
  per-thread CPU) stays with the lead.
- Why: the single owner is the measured cap at 4k QD32 (IOPS = 1/owner us
  per op, Little's law fits the e9455 p50) and no local cut exists (transport
  turn 72.5 %, no single hotspot); the wake-hold variant was rejected
  (-7 % q32). The P0 prototype (branch `rr-a2-p0`, zen4, static map, no
  proxy) measured 4k q64 +22 % and 64k q64 +151 % vs main.
- Risks accepted for step 4: a request whose object's primary moves to
  another owner parks instead of progressing until the object is idle
  (correct, slower); owner 0 keeps the monitor and all control state, so a
  stalled owner 0 still stalls cephx renewal and map updates for every owner.

- Measured 2026-11-02 (ice-b, 3 rounds, block `rados-a2p4c`): the P0 gate
  (4 owners, static map, no proxy) reaches 1.26x stock at 4k read q32 and
  1.62x at q64 (base 0.97x / 1.19x), 1.11x read and 1.04x write at 4 x QD16.
  No QD1 regression in IOPS or CPU in a 5-round re-measure (read +0.4 %,
  write +0.9 % vs base; the 3-round -6.7 % was lab noise); QD1 read p99 is
  1020 vs 946 us (+7.8 %, tail, same block), reported as the accepted
  trade-off. The lead accepted client CPU per op of +24..64 % at q32/q64 on
  2026-11-02 under adr 0013 because IOPS and p99 there are better than
  stock and than base (q32 read 1.26x stock, p99 791 vs 905 us; q64 1.62x,
  p99 938 vs 1352 us); the "+5 %" line above is superseded. Step 5 should
  bring the CPU down; if a later step loses IOPS, the CPU rise is a bug.
  Evidence: doc/perf/rados-a2p4-20261102.md.

## Amendment (2026-11-06): the owner cap grows with OSD sessions; K-session gate cells (am. 6)

Status of this amendment: proposed (draft, lead decides); nothing built.
Evidence: doc/perf/rados-single-client-20261106.md (zen4a, classic memstore
OSD sets of K OSDs, one client, size 1, `lab/rados-client/osdscale-ab.sh`).

- Finding: the single-owner cap depends on the number of OSD sessions K of
  one client, not only on queue depth. 4k randread q32, rustyrados vs stock:
  1.30x at K=1, 0.97x at K=8, 0.93x at K=30. The owner is 84 / 99 / 100 %
  busy at 9.7 / 12.1 / 15.1 us per op. With K sessions an op rarely shares a
  syscall or a TCP segment with another op on its connection, so the
  kernel's per-op send and receive cost grows: +14.0k of the +18.6k owner
  cycles per op from K=1 to K=30 (writev +9.8k, recv +4.9k). Stock pays the
  same kernel cost but spreads it over 3 messenger workers. Scans over all
  sessions per owner turn are ~8 % of owner time at K=30, so an O(ready)
  turn cannot close the gap. The e9455 cell (30 OSDs, 0.63x) is this effect.
- 4M randwrite q32 is owner-capped at many sessions too: 0.65x stock at
  K=30 (owner 99.9 % busy, 876 us/op); 1.02x at K=1. The e9455 4M write win
  holds only while the OSDs, not the owner, are the cap.
- QD1: with one owner, owner 0's per-turn work (monitor, controls, timers)
  sits on every op's path. K=1 4k read q1: 0.97x stock, client CPU 116 vs
  108 us/op. With the P0 build at 4 owners, the session moves off owner 0:
  0.99x and 109 us/op. A second owner therefore also serves QD1.
- Write gap: the zen4a 4k write deficit (0.83-0.90x) was a lab artifact. The
  bufferlist memstore object's per-write cost grew over a block, and stock
  always ran first. On page-set memstore, 4k randwrite is 0.98x (q1) and
  1.01x (q32) at K=1. No client write-path change follows from it. At K=30
  base write q32 is owner-capped near 57k/s (owner 0.97 cores; 1.27x stock
  on this lab).
- Decision (proposed): every A2 step's gates (am. 5) add:
  - (a) a K-session cell: one client against K=30 OSD sessions (zen4
    classic memstore sets, `memstore_page_set = true`, arms in one block);
    4k randread q32, 4k randwrite q32 and 4M randwrite q32 >= stock;
  - (b) K=1 QD1 4k randread and randwrite >= base, with p50 within +3 us
    of stock.

  Step 6 (default `auto`, switch removed) requires (a) and (b).
- Rationale: gate cells with few OSD sessions do not exercise the
  per-session kernel cost that caps the e9455 client. The K sweep isolates
  it on two lab VMs without drives.
- P0 at K=30 (zen4a, 6 client cores; 1 repeat): it does not pass (a).
  - 4k read q32: P0 0.85x stock, base 0.88x. Base's owner is saturated
    (13.8 us/op).
  - P0's 4 owners are not saturated (0.59 cores each), yet client CPU per
    op rises 2.5x for the owners and 1.8x for the callback and fio threads.
  - Instructions per op +20 %, cycles per op +75 % (IPC 1.06 -> 0.72),
    context switches per op 2.3x.

  The P0 split pays per-op wakeups and cross-core traffic. At many sessions
  this cancels the second core; with few sessions (am. 5, ice-b) it did
  not. Step 4 as prototyped therefore does not close the e9455 gap. Its
  per-op cross-owner cost must be localized (flame of P0 at K=30) and
  removed before step 4 can meet (a).
- Open: which shared state or wakeup chain costs the P0 cycles at K=30;
  whether N should be bounded by the client's free cores (4 owners, 2
  callback and 3 fio threads ran on 6 cores).
- Correction (2026-11-06): the K=30 4k write stall of the multi-owner arms
  was a lab OSD killed by the OOM killer (PG log bounds of the memstore
  sets), fixed in the lab script; not a client fault.
- Owner count sweep (gate sweep2, P0 build at 2 / 3 / 4 owners, page-set
  memstore): 2 owners are >= stock in every mandate cell (4k q32 r/w at
  K = 1 / 8 / 30, 4k q1 r/w at K=1; lowest 1.00x) with no 4M regression.
  4 owners miss K=8 and K=30 q32 (0.86-0.95x): per-op owner cost at about
  one op per owner turn. 3 owners collapse at K=8 / K=30 (0.38x read q32).
- Foreign dials (proven with a debug dial guard and a route trace): the P0
  order table keys 2^16 buckets by the low 16 bits of the object's order
  key, and a bucket's home stays sticky while requests are in flight. An
  object whose bucket is busy is routed to that home even when another
  owner serves its primary; the home then dials the primary. Both sessions
  use the client's one address and nonce, so the OSD replaces one with the
  other and the owners redial in turn (100 ms stalls). Which owner counts
  hit it depends on the pool (~0.5 colliding object pairs per 256-object
  pool). A map change moves a busy object's primary to another owner the
  same way, so an exact-key table does not remove it, and a nonce per owner
  breaks blocklist fencing (one exact address + nonce).
- Decision (proposed):
  - N > 1 becomes default only when no owner can open a session to an OSD
    another owner serves: am. 5 step 4's park-and-re-home rule or step 5's
    proxy streams, with the dial guard as a test assertion. P0 has neither.
  - The default is a fixed, documented owner count, set like Ceph's
    `ms_async_op_threads` (a configuration value read at client start);
    no load-based or automatic choice. This replaces `auto` in am. 5 step 6.
  - The owner turn is O(ready): the transport visits only streams with
    work, owner passes touch only sessions with work, session deadlines
    come from a bound (rados-rt, 2026-11-07). Precondition for every count
    from 2 to 4 to be >= stock: per-op owner cost flat in K.
  Measured (gate ready3): K=30 q1 reaches stock (1.01 / 1.00), owner cycles
  at K=30 read q1 -16 %; read q32 with one owner stays below stock at K=8 /
  K=30 (0.96 / 0.95): one saturated core, 53 % kernel TCP, no site left
  that holds the missing ~8 %. Read q32 at many sessions therefore needs
  N > 1, i.e. the no-foreign-dial rule above.
- Open: the configuration name and the default count (2 measured best so
  far).
- Step 4's park-and-re-home (am. 5) does not satisfy the no-foreign-dial
  rule by itself: a sent flight whose primary moves to an OSD that another
  owner serves cannot be resent without a proxy stream or a migration, so
  parking it keeps its bucket busy and the object hangs (am. 5 calls this
  "slower"). Proposed: N > 1 waits for step 5 (proxy streams, am. 4 design);
  step 4's park rule is not built on its own.

## Amendment (2026-11-07): proxy streams built (am. 7)
- With N > 1 owners every OSD session has exactly one owner (`OsdOwners`, set once); no owner dials an OSD another owner serves (debug-assertion dial guard in `connect_osd`, rados-rt test `an_open_for_an_osd_without_a_session_makes_its_owner_dial`).
- A home owner reaches a foreign OSD through a proxy stream (rados-rt `session_proxy.rs`, invariants P1-P6 in its header): a per-owner inbox (`ProxyHub`) carries Open / Send (whole encoded message) / Close to the serving owner and Up / Deliver / Lost back. On the home side the stream is a session without a connection; flights, order table, resend and backoff state stay with the home (no request moves).
- Lossy like a session: the first item the serving owner cannot send, its session loss, or a home map change ends the stream once (`SessionEvent::Lost`); the home resends on a new stream id. Replies route by tid partition (`tid % N`); watch, command and dedup replies go to owner 0; a backoff is acked by the serving owner and copied to every stream.
- Proxied reads use the publication copy (no A1b placement: the serving owner does not know the home's tids); RDMA stays at N = 1.
- N = 1 attaches no proxy: the hot path pays one `Option` check per received message and per send without a local peer.
- Open before N > 1 becomes the default: the `ProxyHub` inbox is a `Mutex<VecDeque>` (a lock and a possible allocation per cross-owner item); replace with bounded lock-free per-pair rings. 2-owner 4k q1 at K = 8/30 is 1.1-1.4 % below stock (gate a2p1). Multi-owner sim tests (ORD-1..3, MAP-1, PAUSE-1, BACKOFF-1, CANCEL-1, WATCH-1, SHUT-1) and the `rados-order-check` cell are missing.
