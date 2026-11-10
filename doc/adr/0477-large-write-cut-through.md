<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0477 Large-write cut-through: pre-write at the receiver first, fan-out cut-through only behind a gate

Status: accepted (Phase 1 built, default on), amended (am. 1, am. 2, am. 3, am. 4, am. 5)
Date: 2026-10-21
Amends: 0061 (cut-through forwarding stays rejected there; this ADR replaces its open "structural fix" with the receiver-side form)

Related: 0008 (durability), 0021/0160 (store, COW + WAL ring), 0053 (knet), 0061 (copy budget, history `doc/perf/adr-0061-history.md`), 0170 (op trace), 0175 (memory envelope), 0469 (RDMA), msgr2 spec `doc/spec/msgr2.md` (late_status, secure layout 6.3). Measured bound: `doc/perf/cut-through-20261021.md`. Stage budget: `doc/perf/large-io-20261021.md`.

## Context

- A 4 MiB write at QD1 is a store-and-forward chain: every hop takes the whole payload before it acts (client frame at the primary, repop frame at each replica, then the replica store write, then the ack). The drive is full from QD8 up, so only QD1/low-QD latency is open. Stage budget and per-hop decomposition: `doc/perf/large-io-20261021.md`, `doc/perf/cut-through-20261021.md` (a hop costs about the receiver's fill time of the frame: single-stream receive is the limiter, not the sender).
- Cut-through forwarding (primary forwards repop frames while the client frame still arrives) was built, measured and removed (adr 0061 am. 2/3/8; numbers in `doc/perf/adr-0061-history.md`): it won at QD1 and lost at depth and in mixed load. Cause: a forwarded frame holds the peer link (msgr2 frames cannot interleave) and the PG (log append behind an unfinished entry) for the client's fill time instead of the wire time. Fixes need a load-based switch (forbidden) or a wire change (classic peers cannot).
- The same measurement splits the chain into two different resources: the peer link + PG (fan-out) and the receiving core + drive (store write). Only the first one failed.
- Wire facts: msgr2 crc mode carries the data segment crc in the epilogue (after the data); an aborted frame (`late_status` 0x01, frames with > 1 segment, crc mode and secure) is dropped by every peer without a fault. Secure rev 2.1: one GCM tag per op, the data op's tag follows the data and the epilogue. The v9 repop transaction blob carries its payload first (length at byte 10, payload at 14, adr 0061 am. 7) and the op records (object, offset) after it.
- Store: COW (adr 0174): a write always lands in newly allocated blocks; the WAL record + extent-map entry make it visible; data is written to the device concurrently with the record, ack after both are durable; PLP completion = durable (adr 0008).

## Decision

croit-flashstore-osd starts the store write of a large payload while the payload is still arriving (receiver-side pre-write), on every receiver of a large write (primary of a client write, replica of a repop). Fan-out cut-through (forwarding while receiving) is not part of the default path; it is re-opened only by the Phase 2 gate below.

### D1 Safety invariants (all phases)

- Nothing references pre-written blocks before the whole frame is verified: no WAL record, no extent-map entry, no read path, no ack. Verification = msgr2 data crc (crc mode) or the AEAD tag of the data op (secure), checked at the end of the frame exactly as today. Verify-before-reference, not verify-before-submit.
- Ack unchanged (adr 0008): client reply only after local data + WAL record durable and every replica committed; replica reply only after its data + record durable. Pre-written blocks count as data writes of the txn: the txn is durable when all their completions and the record are in.
- A pre-write consumes only free blocks (a volatile reservation of the shard allocator, `Alloc::reserve`, handed out as a `PreTicket` by `Store::pre_write`; taken from blocks free at that moment and not held by the checkpoint rule of adr 0021 am. 2). A reservation that is not claimed (crc / tag failure, connection loss, aborted frame, interval change, shutdown, payload not on the expected grid) is released; its blocks contain unreferenced bytes. Crash: reservations are volatile, replay rebuilds the allocator from the tree, the blocks are free space again. No on-disk format change, no recovery rule.
- Per-block crcs (crc32c seeded by pba) are produced as today from the receive grid (`reseed_4k`); a read of a block verifies against the record, so a block can never be served without its record.
- Bounded: pre-written bytes of a frame are inside the frame's ingress lease (adr 0175); the reservation is returned with the lease.
- No wire change: pre-write emits no message. Classic OSDs and clients see identical frames. Unsupported pool types stay passive (no reservation, no outbound).

### D2 Phase 1: receiver-side pre-write

1. msgr2 decoder raises an `Early` event when a write frame with a data segment >= `prewrite_min` (256 KiB, one receive piece) has its header segments parsed and is lossy/lossless-session valid. The event carries the frame id, the lent segment buffer window and the segment length; the frame is not delivered earlier. Frame delivery, `in_seq`, dedup and fault rules are untouched.
2. Client write (MOSDOp): ops in the front segment give object, offset, length: the PG core reserves the whole 4 KiB blocks inside the write (`Store::pre_write`) when the write is block aligned relative to the payload grid. Repop (MOSDRepOp): the replica reads the blob head (inline stream length, length of its first item, am. 4) and pre-writes only a first write payload of at least one piece, on the 4 KiB grid at byte 14 (adr 0061 am. 7), up to that payload's last block; the final txn claims the blocks of its first write whose payload and object offsets are on that grid (the by-reference condition that exists today), the rest is released. A frame that does not match costs wasted device bytes, never correctness.
3. The connection core publishes a watermark per completed piece (the existing 256 KiB direct-receive pieces, block crcs already computed on the grid) by an SPSC message to the shard-owning core; that core submits `DmaBuf` views of [submitted, watermark) as device writes (qpairs are per core). The filled prefix of the lent buffer is immutable for the rest of the fill; capacity is reserved up front, as today.
4. At frame end the verified frame goes down the unchanged path (op decode, PG, txn build). The txn marks the pre-written runs `claimed`; `Stage` skips allocation and data writes for them, writes the unclaimed edges and head/tail blocks, and appends the WAL record. Remaining unsubmitted pieces are submitted as one write (= today's single write): with an overloaded shard core the behaviour degrades to today's, never below.
5. Transports: knet direct receive (piece = io_uring recv, spread joins in order), AF_XDP/DPDK (piece = joined copy job), RDMA (piece = by-reference slot chain prefix; slots are held until the write completes as today, credits unchanged), secure (piece = decrypted prefix; the plaintext is unauthenticated until the tag, see D1: it is only written to free blocks).
6. EC: replica sub-writes (shard txn blobs) as repops; the EC primary needs the whole stripe for the encode and is not changed.

Expected effect (bound in doc/perf/cut-through-20261021.md): replica / size-1 primary store time hides behind the receive; size 3 QD1 loses about the replica store time, size 1 QD1 about the store time. Primary local store in size 3 runs parallel to the repop already (adr 0008 am. 2) and gains nothing.

### D3 Phase 2: fan-out cut-through, gated, not built now

- Only if Phase 1 is in and the bound shows more than the budget below. The lost A/B is a design input: the fan-out may not hold the link or PG longer than the same frame's wire time.
- Candidate (unproven): forward start chosen per frame so that the frame never underruns and ends with the client fill (start at the point where the remaining fill time equals the frame's drain time on its link, from the frame's own piece rate and the link's measured drain rate): link occupancy <= whole-frame drain time (today's), PG hold = the remaining fill. It is a pacing rule, not a mode switch; if it cannot be stated without a load-dependent constant the idea is dropped.
- Wire = ordinary MOSDRepOp frames (header + lengths first, data pieces, epilogue with the primary's own crc or `late_status` aborted when the client frame fails). Secure: GCM streams, tag after the data and the aborted epilogue.
- Gate (all must hold in same-process on/off A/B, ice-b + ice-a, 2 rounds): w4m1 and size-3 QD1 p50 better by the bound's Phase 2 share; w1mq16, w4m8 (p50/p99), 4 KiB randwrite next to 4 MiB writers (p99.9), w4mq16 and the depth sweep at least equal to off (equal within run-to-run noise or better; p50, IOPS and p99). Any loss: removed, not left as a switch (adr 0061 rule).

## Rationale

- The failure of the removed prototype is specific to the shared resources it held (peer link, PG log order). Pre-write holds neither: the receiving core already owns the connection, and the store write goes to blocks nobody references, so it does not order against anything until the txn exists. The same bytes are written once, to the same place; only earlier.
- Verify-at-commit is sufficient because the store is COW with a separate record: the visible state changes only at the record, which is after verification. This is why this is not a "write unverified data" design.
- It works against classic primaries (replica side), needs no negotiation, and needs no rate switch: pieces are submitted when they arrive; if the shard core cannot keep up it submits the rest at the end as a single write.
- Accepted trade-off: speculative device writes for frames that fail verification or do not match the grid (wasted bandwidth, bounded by the lease), a second shared-state step (reservation) in the store, and a cross-core message per piece.

## Consequences

- + Size 1 and size 3 QD1 latency of large writes drops by the store time (numbers in doc/perf/cut-through-20261021.md); no new resource is held across the fill.
- + Depth behaviour unchanged by construction (same bytes, same blocks); gate verifies it.
- - Store gets a reservation API with release-on-drop and new crash-test cases (kill -9 mid-fill, abort, crc failure, interval change): durability code, targeted crash matrix required.
- - A second, earlier write path to keep consistent with `Stage::data_ref` (claimed runs); extent crc reseed must use the reserved pba.
- - Per-piece cross-core message (16 per 4 MiB) and more, smaller device commands; measured in the gate (cycles per byte, device queue).

## Alternatives

- Fan-out cut-through as default (adr 0061 am. 2/3/8): measured loss at depth and in mixed load, structural (link + PG hold).
- Load/rate switch that cuts only when the client fills at wire speed: load-based switch, forbidden.
- Splitting one client write into several smaller repops (each cut-through safe): breaks PG log atomicity of the op (partial visibility, rollback info per piece); wire-visible to classic peers.
- Second cluster connection per peer pair for bulk frames: a second lossless connection of the same entity resets the session on classic peers.
- Whole-frame pre-write without a reservation (write to a scratch area, copy/move at commit): double write, defeats the copy budget.
- Pre-write before the PG accepts the op (no ingress check): not needed; the lease is the bound.

## Open questions

- Replica speculation: how often is a repop's first write off the grid (RBD 4 MiB objects aligned; RGW/CephFS striped writes)? Probe counter `claimed/released` before widening.
- Reservation API on the elastic shard allocator (adr 0021 am. 53): contiguous runs vs extent list for a 4 MiB reservation under fragmentation.
- Kernel-direct tier: are 256 KiB device commands slower than the 4 MiB write the store issues today (device MDTS splits)? Spike `store_commit` by size (doc/perf).
- Phase 2 pacing rule: does a rule exist that needs no load-dependent constant? Decide only with the Phase 1 numbers.
- Secure mode: streaming GCM encrypt API of the AEAD crate for Phase 2 (decrypt side for Phase 1 is the existing receive buffer).

## Amendments

### am. 1 (2026-10-21, accepted): Phase 1 built, default off until the tail gate is clean

Evidence: doc/perf/cut-through-20261021.md section "Phase 1 result" (zen4b same-process gate, 3 rounds, one lock hold; ice-b round; RDMA sibling; docker mixed case 24).

- Built as D2 with these specifics. msgr2: a crc-mode data segment of a Message frame >= the piece size is assembled in a shared `SegBuf` (`Decoder::set_prewrite`); `SegWatch` publishes the filled prefix and the frame's fate (gone = writer dropped before the frame completed, or the frame's final `Bytes` all dropped); the `Early` event is `Connection::rx_early` (header verified, front a hint until the epilogue). Store: a shard's `PreTab` slot per piece, blocks from the allocator's volatile reservation, the device write submitted at once; a staged data run whose source starts at a piece's first byte takes its blocks (claim by memory identity, no grid bookkeeping); release returns blocks after an in-flight write lands. OSD: the connection core cuts the candidate range into pieces and sends the pieces complete since its last receive scan as one view (`XMsg::PrePiece`, the op's lane) to the PG core, which writes them and keeps the tickets with the segment's watch; the reap returns unclaimed pieces of gone segments, looking only when a piece closed or a segment turned gone.
- Piece = one store data run = `min(MAX_RUN, device transfer limit)` blocks (`PgStoreOps::pre_piece`), not the 256 KiB receive piece of D2.3: a run then claims its piece whole on every device.
- Candidates: client MOSDOp with exactly one data op, WRITE / WRITEFULL at a block-aligned object offset, length >= one piece; MOSDRepOp from the payload grid (byte 14, placed by the sender's `data_off`, adr 0061) to the segment's last whole block. Not candidates: EC sub-writes (D2.6 deferred), compressing pools, secure-mode connections (D2.5 secure deferred: the decrypting assembler has no shared segment), frames below one piece.
- Transports: knet direct receive (pieces while the frame arrives); knet receive spread, AF_XDP / DPDK and RDMA feed the decoder by copy (`on_bytes`): pieces follow the assembled prefix, the RDMA sibling gains (4 MiB QD8 +7 %, 64 MiB QD1 +20 % MB/s); a receive that fills a segment only at its end degrades to today's single write.
- Gate result: QD1 large writes win (zen4b size 3 w4m1 p50 -14 %, IOPS +15 %; ice-b size 1 -23 %), depth cells keep p50 and IOPS within +-2.4 %; p99 within +5.6 % (r3 w4m8); OSD CPU per op +1..+12 % at depth (cross-core wakes per op 0.9 -> 3), RDMA OSD ns/B +7..+16 % on writes. Gate not clean: r3 QD16 p99.9 (w1mq16 on 26 / 98 / 125 ms vs off 12 / 12 / 17 ms per round) is an open gate failure until attributed. `flashstore_prewrite` default false; it flips to true only when every cell is neutral-or-better on p50 / p99 / p99.9 and CPU per op lies within the run-to-run spread.
- Open questions added: r3 QD16 p99.9 tails (on 26-125 ms vs off 12-17 ms per round, off with single 250 ms stalls; slow ops wait on the repop round trip with fast replica traces): longer tail run before Phase 2. The CPU at depth (one PG-core wake per receive scan): batch across scans of one frame without a load-dependent rule? Replica speculation releases 18 % of the pieces in the docker mixed lab (classic primaries' repops off the grid); probe the grid of classic repops.
- Phase 2 (D3) inputs: the measured Phase 1 share is below the bound at size 3 when the receive is faster than the drive (zen4b: the drive limits, the pre-write hides only the overlap); a pacing rule would forward on the same piece events (`SegWatch` filled watermark), and needs the per-link drain rate and the frame's piece rate, both measurable without load constants; nothing in Phase 1 blocks it.

### am. 2 (2026-10-22, accepted): lazy PG-core wake, pre-write counters; default stays off

Status: accepted. Date: 2026-10-22. Evidence: doc/perf/cut-through-20261021.md "Phase 1 tail investigation".

- Lazy wake: only the first pre-write message of a frame wakes the PG core (`XMsg::wakes`); later pieces of the frame ride on that core's next drain (no wake of their own). Pieces are drained before the frame's op runs; a frame that ends without other traffic is drained by its op, so no piece waits unbounded. Reason: one cross-core wake per receive scan cost OSD CPU per op at depth (am. 1: wakes per op 0.9 -> 3); no load-dependent rule is used.
- Counters (admin `perf dump` of the OSD, store side `pre_*`): `pre_rx_msgs` (pre-write messages cut on the connection core), `pre_rx_lag_ns` / `pre_rx_lag_max_ns` (sum / max of cut on the connection core -> handled on the PG core), `pre_claimed_landed` (claims whose device write had already landed). They separate wake / queueing cost from receive and device time.
- Default stays off (`flashstore_prewrite` false). The r3 QD16 tail of am. 1 is, in the zen4b VM lab, a receive-side interrupt delivery stall (AVIC posted interrupt to a halted vCPU), not an OSD defect; this is not yet proven on bare metal. Flip criteria: full gate (s1, r3, mix) neutral-or-better on p50 / p99 / p99.9 and CPU per op within the run-to-run spread, plus a bare-metal tail proof (kernel NVMe / knet, SPDK, RDMA cells; `lab/rented/multi/bench3.sh NV_PREWRITE=1`).

### am. 3 (2026-10-23, accepted): pre-write on by default; erasure / compressing pools decided on the connection core

Status: accepted. Date: 2026-10-23. Evidence: doc/perf/cut-through-20261021.md "Default-flip gate".

- `flashstore_prewrite` defaults to true (user decision 2026-10-21: cut-through on by default; tails and depth CPU are defects to fix, not reasons to keep it off). `false` stays a runtime switch for diagnosis.
- The connection core decides candidacy with the pool: a frame of an erasure pool (D2.6) or of a compressing pool (`PgStoreOps::pre_pool`) is no candidate and costs no `PrePiece` message and no PG-core wake (before: sent, then refused on the PG core). The PG core keeps the same check (its map may be newer).
- Gate (same-process A B B A, one lock hold per lab; s1, r3 SPDK, r3 kernel NVMe, EC k2m1 guard, 4 KiB next to 4 MiB mix; zen4a, ice-a): zen4a every cell neutral-or-better; QD1 large writes win on every lab and tier (s1 w4m1 IOPS +12 / +20 %, r3 +6 / +10 %); CPU per op at depth +0..+5 % with the lazy wake (am. 1: up to +12 %), inside the arm-to-arm difference of the no-candidate control cells (-4.5..+3.6 %). The remaining cost is the first-piece wake of a frame whose PG core is not its connection core, which is the mechanism of the QD1 gain.
- ice-a r3 QD8 / QD16 p99 (+7..+31 %) is an open bug (OQ 119); the working hypothesis is that lab's same-VM replica (two gate OSDs on one VM, failure domain osd): the loopback peer link sends by copy on one PG core (~88 % busy in both arms). Only that core's PGs get slower, the PGs of every other core get faster; a primary-only pre-write reproduces it, replicas-only does not (role split). A closed-loop client then concentrates its window on the bottleneck core. Not seen with one OSD per VM (zen4a) nor on bare metal (rental 2026-10-22, kernel NVMe + knet, host failure domain: no tail, depth cells neutral). unproven, like the VM-lab AVIC stall of am. 2.
- RDMA sibling (ice-b, opt-in transport): 64 MiB QD1 write +12 % MB/s, 4 MiB QD8 MB/s and p99 inside the spread of 1 s write phases, OSD ns/B on writes +4..+13 % (receive feeds the decoder by copy, pieces follow each step); stays an open cost, not a reason to keep the default off.
- Open questions added: a same-host peer link (failure domain osd) puts its send copy on a PG core (placement question for adr 0054 peer core and the accept placement by connection count); bare-metal QD1 / QD8 4 MiB rbd write and EC cells with the switch (`bench3.sh CELL_SET=prewrite`, `NV_PREWRITE=0|1`, next rental).

### am. 4 (2026-10-24): repop range from the blob head

Status: accepted. Date: 2026-10-24. Evidence: doc/perf/omap-prewrite-skip-20261024.md.

- A repop's range is decided once the first 14 bytes of its data segment arrived (`msgr2::SegWatch::peek`, borrowed, no allocation): the u32 at [6, 10) is the inline stream length, the u32 at [10, 14) the length of the stream's first item. Candidate only when that item is at least one piece and lies inside the stream; the range ends at its last block (at most the segment's last whole block). Before: speculatively from byte 14 to the segment's last whole block.
- Effect: a repop whose first item is not a large write payload (omap batch: the key count; attrs) costs no device bytes, no `PrePiece` message, no PG-core wake. A misread still only costs device bytes.

### am. 5 (2026-11-03): pre-writes take the device window

A piece is written ahead only when its range of the device write stream is admissible at once (adr 0643-device-admission-fifo, `take_now`: nothing ticketed waits for the window); else `pre_skipped` and the txn writes the data itself. A piece written ahead must not pass data writes that arrived earlier.

### am. 6 (2026-11-05): no device byte before the session's write caps passed

Status: accepted. Date: 2026-11-05.

- A candidate needs the session's write grant for the frame's pool before its first piece goes out (`Caps::may_write_pool`: write flag, network selector admits the peer, pool selector names the pool, `tag` selector can match an object of the pool). Cluster links (repops) are authenticated OSD peers and keep the pool-type check only.
- Reason: the front is unverified while the data arrives, so before this a client with no write caps at all could push its bytes into free blocks of any replicated pool (full device write bandwidth, PLP wear, pinned free space until the frame ends). The op's own caps check still decides afterwards; the pre-write now happens only for a session that may write that pool anyway.
- Namespace and object-prefix selectors are not part of the pool question: they narrow the objects of a pool, and a session allowed to write there may pre-write there; the op check decides whether the bytes are used.
- Test: `prewrite_tests::a_session_without_write_caps_pre_writes_nothing` (read-only session: no piece, op `-EPERM`; `allow rw` on the pool: pieces as before).
