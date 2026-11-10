<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Igor Fedotov, croit GmbH -->
# 0660 Metadata-only LSM range-delete threshold

Status: accepted
Date: 2026-11-05
Amends: 0610, 0647

## Context

A range tombstone avoids enumerating its keys at commit but can add work to subsequent scans and compaction.
Short ranges may be cheaper to remove with point tombstones. Counting live keys by reading the range first would
put that work on every range request, including requests that should remain range tombstones.

## Decision

- Add runtime option `flashstore_omap_delete_range_threshold` (unsigned 64-bit integer, default `0`).
  Zero preserves the current native range path without estimating. A positive threshold selects point deletion
  only when a resident upper bound on the entries the enumeration visits is strictly smaller than the threshold;
  equality selects a range. The threshold therefore bounds both the point tombstones emitted and the records a
  point removal enumerates synchronously while staging on the owner core; keep it to a few chunks of entries.
- Derive immutable run prefix sums of `Fence.n` (puts and point tombstones) with the resident fence index. Include
  every chunk intersecting the half-open object/key range, including whole boundary chunks. Binary-search both
  endpoints; sum all overlapping sources, including active, frozen and transaction-overlay memtables, each counting
  its entries inside the range up to the remaining cap. Stop at the threshold. Charge derived vector capacity to
  resident RAM, rebuild on run creation/decode, and change no disk format.
- Entry counts are upper bounds on live keys and on enumeration work, not logical usage accounting. Duplicate
  versions, overlapping sources and unrelated entries in boundary chunks can make them loose. A span of point
  tombstones counts at its scan cost although it holds no live key, so it keeps the range tombstone. Do not infer
  cardinality from lexical distance between arbitrary binary keys. Loose bounds may select a range for a small
  live span.
- Only a selected point path enumerates exact live keys, inside the requested half-open range and transaction
  view. Do not stage any removal until enumeration finishes. Emit existing point-removal WAL ops; the native
  path emits the existing range WAL op. If point-key enumeration reaches the threshold or existing key-blob
  limits, retain the range path. If the expanded final transaction exceeds the existing WAL record limit,
  restore its original range operations before normal admission. Later compound operations keep their order.
  Replay, acknowledgement and durability ordering remain unchanged.
- B-tree OMAP keeps its existing implementation. Kernel direct, kernel-command and SPDK stores use the same
  LSM decision and staging code. Transport and replication/EC wire operations are unchanged.

## Rationale

The decision uses metadata already resident for reads, without reading data blocks or changing the format.
A conservative bound avoids paying for a live-key count on a range that will stay a range tombstone. Exact key
identification is still required to emit point removals. Default zero keeps adoption and benchmark tuning explicit.

## Consequences

- Enabling the threshold trades extra key enumeration and larger point-removal records for potentially less
  read/compaction amplification after short deletions. The threshold is not an exact live-key-count contract.
- Prefix sums cost eight bytes per reserved vector element. Memtable counts and whole boundary chunks deliberately
  sacrifice precision for a cheap decision. No new exact per-object counters are introduced.
- The setting is initialized at startup and can change on the running daemon with `config set` / `config unset`.
  Validate the complete unsigned 64-bit domain before changing any layer; invalid input preserves the previous
  value. Threshold-specific set/unset commands wait for all cores to apply the new effective value before success.
  Each owner updates only its mounted shards; no caches are cleared, no process-global mutable knob is added, and
  no OSD restart is required. Existing prepared records retain their physical operations; subsequent staging uses
  the current setting. File/monitor/injectargs changes follow the existing configuration layering and fanout.
- Runtime overrides do not persist across restart. `config unset` restores the next lower configured layer, or
  default zero. Existing stores need no reformat. Estimation never changes deletion results, scrub accounting,
  key ordering or bounds.

## Alternatives

- An exact pre-count reads live keys even for the native range path.
- An average-entry-size estimate is not an upper bound and cannot certify a short live range.
- Numeric distance between encoded keys does not represent arbitrary-key density.

## Validation

Focused tests cover conservative bounds against exact reads, binary and cross-object bounds, overlapping runs,
point/range tombstones, active/frozen/transaction memtables, metadata round trips, memory charging, both delete
paths, strict threshold boundaries, transaction ordering, cold reads, reopening, live switching on the same
object, owner-shard isolation and multi-core configuration acknowledgement/validation. For am. 3: an exhaustive assignment matrix over the merge loop's runner-up, tie and coverage paths (`merge_loop_runner_up_and_tie_matrix_matches_reference`, `range_tombstone_end_matrix_matches_reference`), and a multi-chunk sweep of range ends that land exactly on keys, chunk starts and object ends (`range_reseek_landing_on_exact_bounds_matches_reference`). The committed gate is
`scripts/check-omap-range-threshold.sh`. Performance tuning remains workload-dependent; no benchmark gain is claimed.

## Amendments

- am. 1 (2026-11-06): the bound counts entries visited (`Fence.n`, memtable entries inside the range) instead of
  puts (`n - tombs`) and whole-object memtable counts. A put-only bound let tombstone-only spans select the point
  path and scan without limit, and whole-object memtable counts kept active objects on the range path for any
  small threshold. The `1048576` recommendation is withdrawn: it lets one range request enumerate up to that many
  records while staging.
- am. 2 (2026-11-06): the point-path enumeration resumes across cold reads. A non-blocking staging run refused by a
  cold run chunk re-applies the whole transaction; the keys found so far and the resume position are kept per shard,
  keyed by the staging session (FIFO head token), the operation's index in the transaction (stable across retries
  whatever earlier operations select), object and bounds, and the engine generation (newest omap op LSN held,
  unchanged by flushes and merges). The retry continues from the saved
  position, so each chunk is enumerated once instead of the range being rescanned after every miss. A mismatch or a
  closed session discards the saved state; blocking callers wait in place and keep none.
- am. 3 (2026-11-07): OMAP listing and the point-path enumeration cost less per request; the decision is unchanged.
  A chunk is decoded only up to the first entry at or past the cursor's bound (`Chunk::parse_until`, `load_from` with
  a stop position); page CRCs are still verified and the entry count is checked on full decodes. A forward-only
  `RangeWalk` per ranged source answers tombstone coverage with one comparison per key, falling back to binary search
  after eight linear steps. The merge loop refills only cursors that moved, keeps the previous winner while its head
  stays below the runner-up, and skips a duplicate only when the runner-up holds the same key. Engine listing pages
  hold up to 4096 entries and 1 MiB of keys and values (`list_from_budget`), so a cold page keeps a bounded working
  set protected across miss retries. The threshold bound of am. 1 is unchanged: it still counts `Fence.n` entries
  before any key is enumerated, and "a few chunks of entries" remains the advice. Measurements: doc/perf/omap-listing-20261107.md.
