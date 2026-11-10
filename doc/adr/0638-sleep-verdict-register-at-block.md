<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0638 One sleep verdict: every park registers its wake where it parks

Status: accepted; rows 1-6 and 10 implemented, rows 7-9 pending (doc/perf/sleep-register-20261101.md)
Date: 2026-11-01
Amends: 0032 (am. 1), 0053 (Idle and busy poll), 0162, 0074 (am. 4 generalized from output to every park)

## Context

"May this core sleep, and until when" is re-derived by five layers: the knet loop (`kcore.rs`: work flag, `store_quiet`,
`store_wait_hint`, `has_wake` + mesh backlog, a cached timer, RDMA arm check, device-ring check, the `wait_if` re-check of inbox /
`input_resumable` / spread), `Osd` (`store_quiet`, an 11-term `next_timer`, a 4-term `input_resumable`), storeadapt (`io_quiet`,
5 queues), the store (`Shard::quiet`, 14 terms) and the DPDK / PG-only loops (spin or fixed sleep).
Work none of these predicates sees is found only by periodic polling: the 1 ms deep-idle cap (store sweep, admin socket, socket
adoption, stop), the 200 us store-busy cap, the 50 ms knet tick, the 1 s re-probe of every parked engine op (added after a 15 min
live hang) and the 1 s tick of every PG. A new hold reason has to be added in up to five places; a missed one is a lost wake that
a cap turns into a 0.2-1000 ms stall instead of a test failure.
Inventory with file:line, severity and probes: doc/perf/sleep-register-20261101.md (22 parks without a registered wake, 5 nets).
A one-step removal of the 1 ms cap (doc/perf/idle-wake-20261025.md, rejected 2026-10-26) cut idle wakes 99 % but made the first op
after an idle gap 12-28 % slower (VM halt / C-state exit latency): the cap is also a latency policy.

## Decision

1. Whoever parks work registers the event that resumes it, at the park site, in the ledger of the layer that owns the work. A park
   whose wake cannot be registered reports its work as runnable (`Now`); it never sleeps unregistered.
2. Wake kinds: `Ring` (an SQE of this core's ring is in flight: socket, eventfd read, device ring poll, RDMA CQ channel), `Poke`
   (another thread publishes the release, then pokes this core's `rt::wake::Wake`; `ingress::Waker` where the producer cannot see
   rt), `At(t)` (absolute loop time: protocol timers, back-offs, expiries, time-driven store work), `Now` (runnable on the next
   pass), `Device(hint)` (a polled device has IO in flight; `hint` = its learned completion time, adr 0004 am. 1).
3. Each layer answers once: `wait(now) -> Wait` built only from its own ledger and its children's answers (store -> storeadapt ->
   `Osd`; `XPort`; `KNet`). `Wait` = `Now` | `Idle { at }` | `Io { at, hint }`; merging keeps the most urgent. The loop asks
   `osd ⊕ xport ⊕ net` once per idle pass, after the pass's work (no cached timer). No layer reads another layer's internals to
   decide a sleep.
4. The core sleeps iff the verdict is not `Now`: until a CQE, a poke or `at`. `Io` on a device whose completions raise a CQE
   (kernel NVMe) arms the device ring and sleeps like `Idle`; on a polled device it keeps the device-wait policy (adr 0162,
   0004 am. 1).
5. Cross-thread releases keep the Dekker order of `rt::wake`: publish, fence, poke if the target announced its sleep; the sleeper
   announces, fences, re-asks the verdict. A poke registration on a core without a wake handle (`--knet-wake off`, adr 0039
   kill switch) or a failed arm (RDMA CQ) is `Now`.
6. Nothing periodic re-drives parked work: no store sweep, no store-busy cap, no 50 ms knet tick, no 1 s engine re-probe, no 1 s
   tick of undue PGs. The 1 s OSD tick runs periodic Ceph work only (beacons, heartbeats, stats, mgr reports, map requests).
7. Sleep length is a separate latency policy: the loop may wake earlier than the verdict requires (today the 1 ms deep-idle cap,
   doc/perf/idle-wake-20261025.md, OQ 108), never later. Correctness never depends on it: test builds run without it.
8. Detection: the former nets become assertions. Test builds panic and lab / prod builds count (perf dump, must stay 0, first
   occurrence logged loudly) when (a) a parked engine op runs on a re-probe no wake named, (b) a PG without a due deadline emits
   work on the full tick, (c) the store finds time-driven work past a deadline it did not report, (d) the core sleeps with queued
   output (`osd.knet_wake_parked_ready`, adr 0074 am. 4). The strict sim harness (`osd` tests) steps a core only on a registered
   wake (delivered message, due deadline, device completion of a busy store), so an unregistered park stalls the test
   deterministically.

Invariants:
- I1 no runnable work survives into a sleep (it is `Now`).
- I2 every parked item has one registered wake whose source is armed before the sleep (SQE submitted, poke target set, deadline
  in the verdict).
- I3 a cross-thread release pokes after it publishes.
- I4 a registration made during a pass is in that pass's verdict.
- I5 the verdict costs O(1) per idle pass (ledgers keep their minimum; many deadlines use `deadline::Index`).

## Rationale

One verdict per layer turns "add a hold reason in five places" into "register at the park site", and a missed registration into a
deterministic test stall instead of a cap-sized latency tail. The registration kinds are the only events that can end an io_uring
wait, so every wait has exactly one honest description. Keeping the latency policy separate preserves the measured first-op-after-
idle latency (the rejected one-step removal) while the caps stop carrying correctness. Accepted trade-off: every cross-thread
producer needs the target's wake handle (setup plumbing), and the store must report its deadlines (one more value per pass).

## Consequences

- + Lost wakes become test failures (strict harness, net assertions) instead of 0.2-1000 ms tails.
- + Idle cores stop polling for busy-without-IO store states and full mesh rings; the gated-inbox spin ends.
- + The safety nets and their CPU go (1 s full PG tick, re-probe, 1 ms sweep).
- - Producers on other threads (admin socket, socket handover, signal, drain, mesh ring space) carry a wake handle.
- - Store internals that hold work by poll count (`ck_defer` 1024 polls) or pace by the sweep move to deadlines.
- - Until the latency-policy question (OQ 108) is answered the 1 ms deep-idle wake stays as a policy and its idle CPU with it.

## Migration

Each step is one squash-ready commit with its tests; behaviour changes only where a wake was missing.
1. Inventory + this ADR.
2. Lost-wake fixes, each with a test that stalls without it: wait accounting after an early-out (inventory row 1); mesh ring
   space wake (rows 2, 3); admin socket, socket handover, stop pokes (rows 4-6); knet tick deadline (row 10).
3. `Wait` in rt / osd; kcore asks one verdict, drops `deep_ready` / `store_quiet` / `store_wait_hint` / cached `osd_due`;
   IRQ_PARK removed; strict mode (no latency cap) in tests.
4. Store: `Store::wait` reports runnable work and its next deadline (sweep, checkpoint interval, idle marks, expiries, defrag,
   pacing, back-off) instead of `quiet` + sweep (rows 7-9; coordinate store/shard.rs with the write-stall work).
5. Osd: `Osd::wait` from one ledger (timers, holds, store, engines); spin cases become `Now` / registered gates (rows 20, 21);
   drain, pre-write reap, pipe sweep, copy expiry register (rows 12-15).
6. Nets -> assertions (Decision 8): engine re-probe and full PG tick run only in test / lab builds as detectors; removed from
   prod once the full test suites and one lab gate show 0 detections. The full PG tick first needs the PG stats publish and
   merge readiness to register their deadlines / events (row 22: the probe fires in 20 tests today). Engine parks carry their wake in the typed would-block of
   the store (review item "Store would block reason as a typed error", same migration).
7. Siblings: DPDK / AF_XDP `Core` and the PG-only core take the same verdict (poll-mode NIC = `Now` while the port is owned);
   paused-connection resume no longer waits for a driven pass (row 19). Compile + unit tests only (adr 0005 am. 2).

## Alternatives

- Remove the 1 ms cap in one step (idle-wake-20261025): rejected 2026-10-26, latency of the first op after idle.
- One process-wide wake registry (thread-local or shared): rejected, the sim harness runs many cores on one thread and per-layer
  ledgers keep the verdict O(1) without cross-layer state.
- Keep the caps and add more `quiet` terms: the current state; every new hold reason stays a multi-place edit.

## Open questions

- OQ 108 (existing): the deep-idle latency policy (1 ms cap) vs. host C-state / halt-poll settings; decided by a bare-metal run.
