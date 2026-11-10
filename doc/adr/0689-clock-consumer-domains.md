<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0689 Clock consumers share their timestamp producer's domain

Status: accepted
Date: 2026-11-08
Amends: 0064

## Context

Forward-only OSD metadata timestamps must not supply CephX ticket checks or dedup record cutoffs.
Monitor ticket installation and store dedup records follow wall-clock corrections in both directions.
Review evidence: `doc/reviews/2026-11-08-nt-clocks.md`.

## Decision

- Outbound peer authorizers on every core use a separate wall origin corrected in both directions at the existing tick.
  The control core's monitor client receives that same sampled origin. Monotonic protocol deadlines remain unchanged.
- Deep-scrub sessions capture their start wall timestamp once, before reservations and reads, from the dedup
  record producer's clock (`PgStoreOps::dedup_wall_ns`). Stores without collection fall back to injected PG time.
- Object/stat timestamps retain the forward-only policy of ADR 0064. Completion cannot reconstruct session start
  from the current wall origin.
- Read lease length (daemon `osd_heartbeat_grace x osd_pool_default_read_lease_ratio` and pool `read_lease_interval`) is
  admitted through one conversion (`peering::types::lease_ns`): NaN/non-positive -> 0 (daemon) / unset (pool), longer
  than `MAX_READABLE_INTERVAL` (2^30 s) -> that cap, with a WARNING log for the daemon value. Wire lease bounds
  saturate at i32 seconds instead of wrapping.

## Rationale

Expiry checks and cutoffs require the same domain as the timestamps they compare. Separating the domains preserves
monotonic object stamps without rejecting freshly installed tickets or filtering the latest scrub's records.

## Consequences

- + New peer connections work after backward wall corrections, including on worker cores.
- + Forward corrections during scrub do not shift its retained start stamp. A new scrub after a backward correction
  immediately uses the corrected record clock.
- - One wall-clock sample per enabled deep-scrub start. No additional sample per PG tick or collected record.
- - A backward correction during an ongoing scrub can put later records before its captured cutoff, as with classic
  realtime stamps; the following scrub uses the corrected time. This is best-effort dedup metadata, not object data.

- + Unrepresentable lease settings never overflow deadline arithmetic or emit negative wire bounds. Classic has no
  defined behavior there (double-to-ns cast overflow), so the cap is no observable regression.

## Alternatives

- Forward-only ticket checks: reject fresh tickets installed in corrected time.
- Reconstruct scrub start at completion: retroactively moves the cutoff beyond records already collected.
- Move dedup records to forward-only PG time: changes the store's realtime record/listing contract.
- Reject unrepresentable lease settings (keep the previous value): no classic precedent, and the pool option arrives
  in the map where there is nothing previous to keep.
