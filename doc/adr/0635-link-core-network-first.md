<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0635 Network-first core loop: forward and reply before local PG work

Status: rejected (parked 2026-11-01: d2 early-flush spike shows no throughput win, see doc/perf/linkcore-20261101.md)
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): rt Core for DPDK/AF_XDP is history; the rest stays valid.
Date: 2026-11-01
Amends: 0053 (knet step order), 0031 (cross-core op path)

## Context

One client connection lives on one core ("link core", adr 0053 accept balance) and that core decodes, forwards, frames and sends every op of the connection while it also owns 1/N of the PGs (adr 0006/0031). The single-connection ceiling is `1 / (L + P/N)` with L = link work per op, P = PG work per op; tsrv2 r4k QD32 (doc/perf/linkcore-20261101.md): L ~7.4 us, P ~15 us, N = 4 -> ~90k IOPS ceiling, measured 81.9k with the link core 93 % busy (w4k QD32: 82 %).
The cross-core hop (`xcore_in`, 49 us at r4k QD32, 111 us at w4k QD32) is not wake latency (mean poke-to-running 4.7 us; spin keeps it at 56 us): forwarded ops sit in the outbox until the end of `XPort::pump_with`, after the inline local ops of the receive batch, the store poll and the inbox drain; replies from PG cores (`reply_tx` 81 us forwarded vs 47 us local) wait for the next pump and output pass. Run-order corrected, one-connection cells vs BlueStore on tsrv2 are: r4k QD32 81.9k vs 77.1k (+6 %), w4k QD32 49.6k vs 31.8k, QD1 r +4 % / w +35 %; r64k QD32 and w4M QD8 need same-order re-checks (d2, rx-stall agent). Classic Ceph has no such ceiling shape because messenger and op threads float under the kernel scheduler; croit-flashstore-osd pins both to the same core by design.

## Outcome (2026-11-01)

The d2 spike (outbox flush right after the net poll, same cell order) cut forwarded xcore_in by 20-25 us (w4k QD32 93.5 -> 68.7, r4k QD32 50.4 -> 30.9) but decode and reply_tx grew by about as much and IOPS did not rise (w4k QD32 -1.1 %, r4k QD32 -5.7 %, QD1 unchanged). At 89-95 % link-core load the op rate is the link core's CPU rate; loop order only moves the wait. Per the park rule this design is not implemented. Same-order single-connection cells already beat BlueStore (r4k QD32 81.3-81.9k vs 77.1k, w4k QD32 49.6-58.2k vs 31.8k). If a later cell loses, the lever is fewer link-core cycles per op (two-host check with `init_on_alloc=0`, then header-only MOSDOp decode as a separate measured change), not the loop order. The text below is the proposal as reviewed.

## Decision (proposed, not adopted)

- Every core loop (knet `KCore::step`, rt `Core` for DPDK/AF_XDP, `pg_core`) runs network work before local PG work, in this order per iteration:
  1. net poll: receive, decode, route; ops for remote PGs go to the outbox, ops for local PGs go to a per-core local run queue (FIFO, no execution inside the poll);
  2. outbox flush (`XPort::flush_out`) right after the poll, so forwarded ops reach their PG core in the same iteration;
  3. inbox drain of the output lane (`Route::Data(shards+1)`: Wire replies and PG progress) and `output_pass`, then submit sends (one enter);
  4. local work: local run queue, other inbox lanes, store poll, timers; their replies are framed in the same iteration's final output pass and submitted with the store submit.
- Local ops keep per-PG submission order: the local run queue is FIFO and is drained before any later op of the same connection that arrives in the next poll (the poll of iteration k+1 only appends).
- Sending stays on the link core: msgr2 seq/ack and the secure-mode GCM nonce are per connection and per direction and are advanced only by the owning core (unchanged from adr 0053).
- No load-based mode, no knob: the order is the same at QD1 and QD32 and on every transport.
- MOSDOp decode on the link core stops at the routing header (pgid, object hash, flags, tid, reqid); the full op decode (ops vector, data segment slicing) runs on the PG core. One decode code path for local and forwarded ops.

## Rationale

- The hop delay is position in the link core's loop, measured: forwarded ops wait ~1.8 iterations (27.5 us mean busy iteration at r4k QD32) and replies wait for the next output pass. Moving the flush and the output-lane pass to the front of the iteration removes the queueing part without changing ownership; the expected cut is xcore_in 49 -> ~10 us and fwd reply_tx 81 -> ~50 us at r4k QD32 (d2 spike measures the flush half).
- PG cores get their work ~40 us earlier at QD32, which keeps 3 of 4 cores busy (38 % today) while the link core still runs its local share; the throughput ceiling `1/(L + P/N)` is unchanged by ordering, but the latency of 3/4 of the ops drops and with QD32 per-op latency is throughput below the ceiling.
- Header-only decode moves ~1 us/op (MOSDOp body decode + op vector alloc, 4 % opexec + part of 2 % opwire samples) from L to P: +~8 % ceiling at r4k QD32 (L 7.4 -> ~6.4 us).
- The remaining large L item is the kernel send (28 % of the link core, 13 % page zeroing by host `init_on_alloc=1`): host setting, already a hwcheck warning (adr 0053 host checks); not an OSD decision. Loopback delivery (tsrv2 client on the same host) inflates the rest; the two-host cell decides whether further send work is needed.
- Accepted trade-off: one extra io_uring enter per iteration that has output (submit after step 3 and again at the end); at QD1 this is the same single enter as today because local work produces no second batch until the store completes.

## Consequences

- + Forwarded op and reply latency at QD8-QD32 single connection drops (target: fwd total 259 -> ~200 us r4k QD32, w4k QD32 xcore_in 111 -> ~20 us).
- + Same structure on knet, DPDK/AF_XDP rt `Core` and `pg_core`; RDMA rides knet sessions and inherits it; crc and secure mode unchanged (sending stays on the owner core).
- + Header-only decode removes a second, larger decode from the link core for the 3/4 forwarded ops and simplifies `route_client_op` (no full `MOSDOp` before routing).
- - One extra submit enter per output-carrying iteration (~0.5-1 us CPU), visible in CPU/op at high QD; secondary per CLAUDE.md, still measured.
- - Local ops no longer run inside the net poll: their latency gains one loop phase (~zero at QD1: the poll batch is one op; measured by the QD1 gate).
- - The single-connection ceiling remains `1/(L + P/N)`; the link core still owns 1/N of the PGs. Breaking that needs either sending from PG cores (rejected below) or link-core-free PG placement (rejected below).

## Alternatives

- (1) Run forwarded ops inline on the link core: breaks PG-per-core ownership (adr 0031: store state, pglog, peering would need locks) and only helps when the PG core is idle, i.e. a load-based switch.
- (2a) Link core does syscalls and framing only, crc/encode on PG cores: crc of the reply payload is already computed on the PG core (`send_raw_crc` reuses it); frame encode left on the link core is ~3 % (msgr2) of samples; the gain is the header-only decode, adopted above. (2b) PG cores send directly on the connection: msgr2 seq and the secure-mode GCM nonce must advance in frame order, so concurrent senders need a lock or a sequencing hop back to the owner; partial sends could interleave frames. Rejected (adr 0006 no locks).
- (3) Steer the connection to the core of its hottest PG: RBD stripes objects uniformly over PGs (4 MiB objects, hash placement), no hot PG exists; a 4-core OSD sees 3/4 forwarded ops regardless of steering. Migration of a live connection also needs a ring handoff. No gain for the target load.
- (4) Spin / busy poll on all cores: measured r4k QD32 81.9k -> 54.9k (-33 %), CPU/op x3-x10; QD1 +13 % r / +23 % w at 438-546 us CPU/op. Wake latency (4.7 us) is not the bottleneck at QD32. Rejected for this problem; QD1 C-state work stays in its own track.
- (5) Batching the hop: already batched (one poke per destination per pump, `XPort::send_lanes`); the delay is when the batch is flushed, not how; covered by the decision.
- Dedicated network core without PGs: wastes 1/N of the PG capacity in multi-connection loads (r4kj4q16 nv 142k vs BS 95k uses all cores); a runtime switch to it is a load-based mode.
- Runtime PG-to-core rebalancing away from busy link cores: needs a balancer plus store shard migration (store state is per core); large complexity for one-connection loads only.
- Split rx and tx directions of one connection across two cores: msgr2 ack/keepalive/session state couples the directions; deferred until two-host data shows the link core still saturates after this ADR.

## Implementation steps

1. `rt::xport`: expose `flush_out` and an output-lane-only drain (`pump_lane(Route::Data(shards+1))`); unit tests for lane order and poke-once-per-destination.
2. `services/osd`: local client ops go to a per-core FIFO run queue instead of inline execution in `route_client_op_now`; drain in step 4; tests: per-PG op order for interleaved local/remote ops of one connection, ordering across `RETRY`/requeue.
3. knet `KCore::step`, rt `Core` (DPDK/AF_XDP), `pg_core`: new phase order + early submit; perf counters per phase (existing loop_busy_* stays).
4. MOSDOp routing-header decode on the link core, full decode on the PG core (msgr2/osd op crate); denc tests with v20/v21 vectors; fuzz the header decoder.
5. Gate: tsrv2 same-order A/B (cells w4kj1q32 r4kj1q32 r64kj1q32 w4Mj1q8 r4kj1q1 w4kj1q1 r4kj4q16 w4kj4q16, nv old vs new vs BS, 1 repeat, 3 for cells within 3 %), crc and secure mode, two-host cell (client off the OSD host) on zen4a/ice-a, AF_XDP/DPDK compile-only build, RDMA one smoke cell on ice-b.

## Test and gate plan

- Park rule (lead, 2026-11-01): if d2 (early-flush spike, same order) shows no clear win in forwarded xcore_in and IOPS at w4k and r4k QD32 with QD1 unchanged, the ADR is parked (status rejected), since same-order single-connection cells already beat BlueStore.
- QD1 r/w 4k must not regress (> 1 % p50 or p99 worse = fail).
- Single-connection QD32 r4k/w4k: forwarded xcore_in < 15 us mean, IOPS >= old; multi-connection r4kj4q16/w4kj4q16 >= old.
- Secure mode one cell (r4kj1q32) and crc mode on both; op order test under fault injection (requeue on map change) in `cargo test -p osd`.
- Siblings: knet (gate), rt Core (DPDK/AF_XDP: compile + unit tests, no lab cells per adr 0005/0020), pg_core (gate), SPDK and kernel NVMe tier (both store polls move to phase 4: one gate cell each), replicated (gate) and EC (one EC cell on a lab VM).

## Open questions

- Is the d2 early-flush gain on w4k QD32 as large as the xcore_in share suggests (111 us)? Decides whether step 2 (deferred local ops) is needed or the flush alone suffices.
- Two-host single-connection r4k QD32: is the link core still > 90 % without loopback delivery and with `init_on_alloc=0`? If not, the ceiling is far above BlueStore and steps 4+ are enough.
- Is the r64k/r4k QD32 loss in storepath-p1 only run order (d2 runs the storepath order)?
