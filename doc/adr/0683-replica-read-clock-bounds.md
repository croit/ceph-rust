<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0683 Replica direct reads use heartbeat clock bounds

Status: accepted
Date: 2026-11-07
Amends: 0067 (Direct reads freshness: replaces the receipt-fraction rule)

## Context

DS-recovery-02 / OQ 150 (doc/reviews/2026-11-07-ds-recovery.md): with opt-in `ec_optimized_direct` a nonprimary shard
served direct reads until lease receipt + 3/4 interval. That is no bound on the primary's grant: leases delayed by more
than a quarter interval let a shard read after a new primary may already acknowledge writes. User decision 2026-11-07:
use the reference mechanism (heartbeat clock-delta bounds, grant conversion at the replica).

## Decision

- Replica (`Pg::proc_lease`): keep the primary's actual `readable_until` grant in the primary clock (one copy, the
  latest grant, zero included). Reads are served only while `now < grant - upper`, `upper` = the current upper bound
  of `primary_mono - local_mono` for the primary incarnation (`up_from`) of the PG's map; no grant, no bound, a revoked
  bound or another incarnation = `-EAGAIN`. Conversion happens at read admission (`Pg::readable_until`), so a widened
  bound shortens an already received grant at once. `readable_until_ub = lease_ub - lower` (else receipt + interval).
- Same OSD as the primary (shards sharing an OSD): delta exactly 0 (one clock for all cores).
- Heartbeat samples (`hb.rs`, control core), only for the incarnation the map shows: lower = peer send stamp - local
  receipt; upper = min(received `delta_ub`, and for a PING_REPLY echoing our outstanding ping: peer send - our ping
  send). A sample without an upper bound (a PING from our own peers) refreshes the lower bound and keeps the last
  upper bound of the same incarnation. Inverted pairs and negative stamps are dropped.
- Outbound wire unchanged: our PING / PING_REPLY keep `delta_ub` absent; PG lease grants, UBs and acks unchanged.
- Publication: per peer OSD one `PeerClockSlot` (sequence lock over atomics, single writer = heartbeat core, readers
  fail closed on an overlapping write, no spin). At heartbeat peer refresh the slot is created and sent once to every
  core (`XMsg::PeerClock`), which adds it to its own registry (`PeerClocks`, read-mostly map shared by the core's PGs
  through `Config`). A sample = a fixed number of atomic stores into one slot: no message, no `Config` clone, no PG
  walk, no deadline-index rebuild. Slots exist only while `ec_optimized_direct` is on (attached / revoked at the
  periodic peer refresh); with it off a received ping does one peer-map lookup and nothing else.
- One clock origin per process: `Osd::now` is the driver time of the process-wide origin every core shares
  (`Boot::t0`, `KCore`); `mnow()` = `now`. The per-core start offset is gone, so PG lease stamps of every core and the
  heartbeat mono stamps are one clock.

## Rationale

`grant - upper` is the earliest local instant the primary's grant can end; using the upper delta makes a stale read
after failover impossible regardless of message delays. The reply round trip yields an upper bound without a new field,
so Rust peers need no classic-visible change. Slots make sample cost independent of PG and core count.

Mixed clusters (pinned v21.2.0, own words, `PeeringState.h` HeartbeatStamps, `OSD.cc` ping handling,
`PeeringState.cc::proc_lease`, `PrimaryLogPG.cc` replica-read gate): classic takes its upper bound only from the peer's
`delta_ub` and sends the negated lower bound it measured. Classic replicas of our primaries therefore have no upper
bound (we send none) and keep refusing replica reads, as before. Sending `delta_ub` would let them serve reads on our
grants; that change is not made. Classic `readable_until_ub` on such replicas = our lease UB - lower bound from our
ping stamps: before the shared origin, our ping stamps (control core) and lease stamps (PG core) differed by the core
start offset, which shortened that bound on classic replicas; one origin removes the skew.

## Consequences

- + Replica direct reads are bounded by the primary's grant; the 3/4 estimator (`LEASE_FRAC`, `direct_until`,
  `direct_skew`) is deleted.
- + Siblings: one PG layer for knet/RDMA, crc/secure, SPDK/kernel NVMe; replicated pools and legacy EC do not use the
  optimized shard direct-read gate (primary grant computation unchanged).
- + Stricter than classic: grant replaced, not accumulated (zero revokes); incarnation checked per read.
- - Each core's registry is copied on peer discovery (small map, control path).
- - Until the first round trip with a peer completes, its PGs answer direct reads `-EAGAIN`.

## Alternatives

- Per-sample cross-core broadcast with `Config` re-point and deadline rebuild (archive/ds-recovery-02-hb-clock-bounds):
  rejected, O(PGs x cores) per ping, also with the feature off.
- Sending `delta_ub`: rejected for now, enables classic replica reads on our grants without a mixed-cluster gate.
- EAGAIN on every shard direct read: correct but drops the optimization; superseded by the user decision.
- Receipt + fraction of the interval: rejected, not a bound.

## Open questions

- Live mixed classic/FlashStore lease failover scenario (lab) not run; unit, sim and OSD tests only.
