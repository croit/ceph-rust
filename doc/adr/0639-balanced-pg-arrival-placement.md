<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0639 Balanced PG arrival placement over the cores

Status: accepted
Date: 2026-11-02
Amends: 0031 (am. 11)

## Context

A PG lives on the core that owns the store shard of its collection; a new PG gets shard `(pool + seed) % S` (adr 0031).
An OSD of a large cluster holds a random subset of each pool's seeds, so the hash spreads them binomially over the cores:
on the 30-OSD e9455 cluster (6 cores per OSD, 3 pools, ~265 PG instances per OSD) the PG instances of one pool per core
reach max/mean 1.29-1.37 on average and 1.64-1.73 at worst. Core busy time follows the PG count (r 0.92; stall cores are
the cores with the most PGs). Primary and replica instances load a core alike: the plain count explains busy time better
than a primary-weighted count. Evidence: doc/perf/pg-place-20261102.md.

## Decision

- The control core (core 0) places every PG that arrives at this OSD with a map. At the map's migration gate (adr 0031:
  before any core applies the map) it takes the PGs of the served pools that map to this OSD (up or acting) in the new
  map but not in the old one, in PG order, and puts each on the core with the fewest PG instances of its pool, then the
  fewest instances in total, then the lowest index; on that core, the store shard in the same order.
- Load = PG instances: 1 per replicated PG, the positions this OSD holds for an erasure PG; primary and replica alike.
- Only arrivals are placed. A PG that stays mapped never moves for balance. Not arrivals: split children (they live on
  the parent's shard, adr 0031 am. 7) and the PGs of a pool that merges (sources follow their targets, adr 0031 am. 5).
- An arrival whose chosen core is not its current core is a placement-only move of the gate's round (`Move.place`):
  a source without an instance hands over what waits for the PG and switches (adr 0031 am. 8, no data); a source that
  still holds a copy (stray, earlier interval) keeps the PG (`stay` in `MigDone` / `Release`), no data moves.
- The placement persists as the collection's location (created on the placed shard). A decision for a PG that was not
  created before a restart is not kept: the PG gets the hash shard again.
- Core 0 keeps the membership set from map to map (`peering::place::Mine`) and maps again only what a map can change:
  every PG when CRUSH, OSD weights, OSD existence, `max_osd` or this OSD's up state change; a pool whose placement shape
  (pg_num, pgp_num, size, rule, type, hashpspool) or served state changes; the PGs whose pg_temp, pg_upmap or
  pg_upmap_items entry changes. Primary choice and other OSDs' up states do not change membership.
- No decision for the first map a process applies (no old map): PGs loaded from the store keep their shards; a fresh
  OSD is not up in its first map, so its PGs arrive with a later map.
- Peer links stay on core `osd % net` (adr 0054).

## Rationale

- Arrival is the one moment a PG can be placed without a data copy and without an extra interval: there is no local
  data yet (or the copy stays where it is), and peering starts with the map anyway.
- Greedy least-loaded per pool, then in total, keeps every pool within one instance per core for the PGs it places
  (tests) and reaches max/mean 1.03 average, 1.08 worst per pool on the e9455 PG maps (hash: 1.29-1.37, 1.64-1.73).
  Per pool first: a workload is usually one pool, a balanced total over unbalanced pools leaves that pool's cores uneven.
- Deterministic and decided by one core: same maps and same local state give the same placement; the workers follow
  the gate's moves (the existing round protocol, no new agreement).
- Accepted trade-off: PGs already placed keep their placement until they leave and arrive again (existing clusters
  converge through churn, not at once); PGs that leave are not compensated by moving others; split children stay on
  their parent's core.

## Consequences

- + New pools, joining or returning OSDs, remaps and backfill targets land balanced; no data moves, no interval change.
- + One mechanism with merges (round, hold, hand-off, switch); split, restart, out/in and in-flight writes covered by
  tests (xcore `pgplace`).
- - A map with arrivals off their hash core runs a round: map application waits for the barrier and the hand-offs (no
  data), like a merge round.
- - CRUSH work on core 0 at a gate, before the map applies (`peering/tests/place_cost.rs`: e9455-shaped map, 30 OSDs,
  1801 PGs in the served pools incl. EC with 4 and 11 positions; release, Linux test runner VMs EPYC 9224 / Xeon 6330):
  a full scan when CRUSH, OSD weights (out / in), OSD existence, `max_osd` or this OSD's up state change: 3.9 / 7.0 ms
  (2.2 / 3.9 us per PG); the first gate after a restart adds a scan of the applied map unless this OSD is down in it
  (a down OSD maps nothing: no CRUSH work). Every other map maps only what changed: another OSD down or up, a pg_temp
  or pg_upmap_items change, a pure epoch bump 0.007-0.009 / 0.013-0.015 ms. The full scan grows with the PGs of the
  served pools, cluster-wide: past ~2600-4500 PGs it exceeds 10 ms (open question).
- - Hash-placed PGs of existing stores and split children are not rebalanced (OQ 5 (a)).
- - PGs that leave (size decrease, OSDs added, balancer moves) leave their cores uneven until arrivals fill the least
  loaded cores again: a pool created at size 3 on 3 OSDs and then set to size 2 keeps the remains of a full set on each
  OSD (per-core max/mean up to 1.28 with and without this ADR, doc/perf/pg-place-20261102.md).
- - Repop credits (adr 0084 am. 4, default off) keyed by the sender's input shard no longer match the replica's core
  for a placed PG: the credit path falls back as for any mismatch.
- Siblings: EC places the PG (all shards this OSD holds on one core, as before), counted by positions; SPDK and kernel
  NVMe tiers are unaffected (placement is above the store); knet and RDMA link placement are unchanged (OQ).

## Alternatives

- Rebalance existing PGs by data-carrying migration: a round blocks map application for the copy time, and moving an
  active PG without an interval change is not safe yet (OQ 5 (a)).
- Lazy placement at a PG's first message (worker asks core 0): a second request path; every core must know the
  placement before the first message is routed, which the gate already orders.
- Every core computes the placement from the map: the load depends on local history (stays, strays, restarts), cores
  would diverge.
- Better hash or consistent hashing (jump, rendezvous): a random subset over the cores stays binomial; does not use what
  is already on each core.
- Weight by observed load (busy ns per PG): a load-based switch, changes with the workload, not deterministic; the count
  explains core busy (r 0.92).
- Weight primaries higher (2P+R): fits core busy worse than the plain count on e9455 (r 0.891 vs 0.924).
- Peer links by peer rank or greedy on peer traffic: rank cuts link rx max/mean only 1.54 -> 1.38; the greedy fit (1.03)
  needs per-peer traffic that changes with every map (OQ).
- First map after a boot as all arrivals: PGs loaded from the store already have their shard; a boot must not move them.

## Open questions

- Rebalance of PGs already placed (hash-placed PGs of existing clusters, split children): needs an interval-safe live
  PG move (doc/90-open-questions.md 5 (a)).
- Full scan off core 0 for clusters with more PGs: a helper thread computes `Mine::next` of the held map (a pure
  function of the two maps: same result, the gate stays deterministic) while core 0 serves ops; the gate decides when
  it is back (helper style of adr 0035 am. 3). Not needed on e9455 (doc/90-open-questions.md 5 (a)).
- Peer-link placement over the network cores: rx bytes per link core max/mean 1.44 average, 1.89 worst on e9455
  (doc/90-open-questions.md 128).
