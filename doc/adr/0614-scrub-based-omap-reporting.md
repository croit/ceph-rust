<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Igor Fedotov, croit GmbH -->
# 0614 Scrub-based OMAP usage reporting

Status: accepted
Date: 2026-10-28

## Context

croit-flashstore-osd has logical primary PG OMAP totals measured by deep-scrub, but no per-pool store allocation estimator.
Advertising those totals as per-OSD allocation divided them by the pool raw-used rate before replicas received
the same PG stats through a later replicated write. Purging could therefore increase reported usage.

## Decision

- Publish primary PG `num_omap_keys` as entry count and `num_omap_bytes` as raw user key + value bytes from the last complete deep scrub. Empty values still account for their keys; empty key/value entries contribute zero bytes and one key. Headers, length prefixes and engine overhead are excluded.
- Keep scrub wire `object_omap_bytes`, digest encoding and large-OMAP value thresholds values-only. Carry completed key-length measurements only in local scrub-map metadata, omitted from encoding.
- Replicated pools use local key lengths only when the primary's version, OMAP digest and counts match the authoritative copy and its local scan is readable. EC sentinel OMAP digests cannot establish that match: a remote EC authority leaves key accounting incomplete.
- Preserve the previous complete PG key/byte totals and set `omap_stats_invalid=true` when authoritative key lengths are unavailable or counters overflow. A later complete deep scrub clears invalidity.
- Legacy EC has known-zero OMAP. Optimized EC streams its OMAP for accounting in bounded scrub slices while preserving its wire OMAP digest sentinel and shard data digest.
- Set `osd_stat.num_per_pool_omap_osds=0`; keep per-pool data reporting enabled.
- Leave per-pool `StoreStatfs.omap_allocated=0`. The OSD-level statfs (`osd_stat`, `dump_osd_pg_stats`, perf gauge `bluestore.omap_bytes`) reports the sum of the hosted PGs' OMAP bytes as `omap_allocated` and subtracts it from `internal_metadata` (am. 1). The manager selects primary PG scrub totals, with no raw-used-rate division.
- Apply the same capability indication to `dump_osd_pg_stats`; describe missing OMAP allocation in `dump_pool_statfs`.
- Ordinary mutations do not update the measurements. Another deep-scrub is required after overwrite, range delete, clear or purge.

## Rationale

Ceph supports scrub-based OMAP reporting when per-pool allocation estimates are unavailable. This uses the existing
authoritative primary report and does not depend on when replicas receive its stats. Key lengths are already available in the replicated OMAP listing; optimized EC adds a bounded OMAP phase to deep
scrub. There are no ordinary mutation-path old-value reads, periodic census walks, queue barriers or store/wire-format
changes. The key-inclusive primary PG total is an intentional reporting-semantic extension requested for croit-flashstore-osd.

## Consequences

- OMAP usage may remain positive after deleting all objects until a new deep-scrub finishes.
- The store keeps no per-object omap counters (adr 0647-omap-blind-removals): the deep-scrub totals are the only omap usage source.
- The original B-tree and dedicated OMAP LSM share the reporting fix; both have mutation/scrub/report regressions.
- Replicated and EC reports select the same fallback; kernel and SPDK storage tiers share this reporting layer.
- A mixed cluster with an OSD advertising no per-pool OMAP estimator uses Ceph's cluster-wide scrub fallback. A classic primary still publishes its values-only total; changing primaries can therefore change accounting semantics until the next croit-flashstore-primary deep scrub.
- Existing PG measurements retain their old definition until a complete deep scrub refreshes them. Numbers are logical payload, not physical allocation or RocksDB size estimates.
- Siblings checked: kernel/SPDK and crc/secure transports share the same accounting layer; replicated and EC store paths have dedicated coverage. No cache, allocator, recovery data format or foreground mutation path changes.

## Alternatives

Exact write-time accounting adds old-length resolution and persistent collection counters. A native allocation estimator
needs separate engine work. Copying scrub totals into replica allocation reports still confuses logical usage and allocation.

## Amendments

- am. 1: the first revision dropped the OSD-level accounting, so `ceph osd df` showed OMAP 0 and the bytes under META. The OSD-level sum (one helper, `Osd::osd_statfs`) is restored; it is a local per-OSD figure, never divided by a raw-used rate.

## Open questions

None.
