<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Igor Fedotov, croit GmbH -->
# 0662 OMAP admission under physical space pressure

Status: proposed
Date: 2026-11-06
Amends: 0610

## Context

OMAP LSM GC has a routine logical space target of 1.3 times estimated live payload and a more urgent 1.1 target under allocator pressure (ADR 0610 amendments 5 and 6). A point-delete workload can cross the logical target while the device still has ample free space: tombstones reduce estimated live payload before compaction releases the older run blocks. Making that ratio a foreground admission ceiling couples one client write to reclamation of a large existing run set.

The logical ratio is an estimate, not an exact allocation invariant. Mixed chunks estimate point-tombstone bytes by entry count; the estimate also assumes each point tombstone shadows an average-sized older put. The run-space gauge includes manifest blocks and current leases, but is not a census of every output or retired block held during a merge. Device reservations, WAL admission, checkpoint epochs and reader ownership remain the hard resource and durability controls.

## Decision

Keep the existing GC selection policy, targets, bounded-prefix installation and allocation guards. Treat logical space debt as a background-GC trigger rather than an unconditional foreground admission ceiling.

For a record containing OMAP mutations, the existing full-memtable guard runs first: a full active memtable plus an in-flight frozen memtable refuses admission with `Busy`. Otherwise space admission refuses the record only when all three conditions hold:

1. A merge is active.
2. The manifest is above the existing logical space-debt threshold.
3. Physical pressure exists: an allocation lease has waited since the last GC pick, or allocator free bytes are strictly below twice the engine's slack.

An allocation-wait signal remains effective until the next GC pick advances its watermark. The caller retains and retries the unchanged transaction after store progress. The normal record-size, WAL, tree, allocator and checkpoint admission checks continue to apply. Records without OMAP mutations do not use the OMAP guard.

Slack remains three flush-output units, as defined by the existing engine. The foreground low-free boundary is **two slack units**; GC's urgent arm still uses **one slack unit**. These boundaries intentionally differ. The earlier foreground boundary leaves one additional slack unit between admission pressure and urgent reclamation. The original rationale for selecting the multiplier two was not recorded; this proposal preserves it rather than introducing a different tuning value. It is a policy margin, not a proof that all transient physical usage is bounded by a particular multiple of estimated live data. Actual allocations must still succeed through the existing allocator floors and leases.

## Rationale

Background reclamation can follow the existing logical target without making each foreground mutation wait for that target when physical capacity is available. This intentionally trades a temporary increase above the estimated logical space target for continued foreground progress. Actual allocation, memory and WAL admission still bound their respective resources. Rationale for the exact two-slack foreground margin: not recorded; maintainers must review that margin separately from correctness of the predicate.

## Consequences

- With ample allocator headroom, an active GC and logical debt do not themselves park foreground OMAP writes.
- Low-free or recent failed-lease pressure still couples indebted foreground writes to reclamation progress; the full-memtable and WAL guards remain independent.
- Logical amplification can temporarily exceed the routine target while background reclamation runs. No hard 1.3-times-live admission guarantee is claimed.
- The descriptor, run, WAL and checkpoint formats do not change. There is no new configuration option.
- The predicate is shared by kernel and SPDK stores and independent of transport and replication mode; it changes local shard admission only.

## Validation

The focused gate uses actual simulated-device shard WAL submissions, flushed put/tombstone runs and an active GC pick. It checks foreground OMAP admission with ample headroom, refusal and transaction retry under low-free and real failed-lease pressure, and the independent full-memtable guard. The existing engine integration tests exercise flushes, delayed helper completion and WAL/ring progress. Every resumed write is checked through the OMAP read path. Performance qualification is separate from these correctness checks; this decision does not claim a measured improvement on a new build.

## Alternatives

- Keep logical space debt as a hard foreground ceiling: large existing run sets can stall foreground writes despite ample allocator headroom.
- Remove space admission entirely: rejected because low-free and failed-lease pressure still require reclamation to take priority.

## Open questions

- Should the foreground reserve remain two slack units? Its original multiplier rationale is not recorded; review the physical-headroom margin before accepting this proposed ADR.

## Amendment (2026-11-07): merge picks bounded by the manifest txn limits (am. 1)

Context: with foreground writes no longer coupled to merge progress, the single merge slot can lag flushes; tier 0 is always preferred, so tier-1 partitions accumulate runs (29 seen). A pick took every run of a full partition; its one manifest txn (one tree leaf per removed input descriptor) then exceeded the per-txn tree page budget (`TxnTooLarge`), the driver failed the shard and every parked txn returned an error. A store must never fail itself because of its own background merge size.

Decision:
- A merge pick takes at most `max_inputs = txn_page_budget - (tree height + 1)` runs: one leaf per input descriptor, one leaf for all output descriptors (fresh consecutive run IDs, one key range), shared interior pages and one split. The bound is derived from the live tree, no constant.
- Tier 0 above the bound merges its oldest `max_inputs` runs. A partition above the bound merges its oldest `max_inputs` runs and pushes them down (a partial set never stays: its output would sit beside newer runs of the same partition); the newer runs remain. A garbage column (GC) above the bound is not picked; size picks continue. Partition sums keep a per-run space entry so a partial removal subtracts exactly what was added.
- Demand chunk reads refused for device queue room record the waiter (`room_wait`); the first driver pass with that room wakes the shard. Before, a listing parked in `miss_wait` with no read of its own in flight waited forever when non-engine IO had held the queue (exposed by the repro once the shard no longer failed).
- Backstop by construction: a complete merge whose manifest txn is still refused with `TxnTooLarge` (also the record-size limit) is dropped unpublished: written outputs are unreserved, inputs and locks released, the slot freed, the input bound halved, `olsm_merges_refused` counted and a `WARNING olsm:` line logged. The manifest stays atomic (0661); the shard stays up.

Rationale: the cap binds only when a txn could not commit anyway, so default-config behaviour is unchanged (default budget 4096 pages vs a simulated peak pick of 30 runs). Measurements: olsm-merge-budget-20261107 (doc not in the source snapshot).

Alternatives:
- Foreground admission tied to merge lag (couple puts to the merge backlog): rejected; in the lag sim one flush stalled for 13.9 % of all merge bytes (foreground latency spike) to cap the read amplification that a bounded pick already caps on the next round.
- Split the manifest into several txns: rejected; crash states between them violate partition disjointness and the atomic replacement of 0661.

Open questions: read amplification under sustained merge lag (peak point-get sources 52-55 in the sim, before and after) is a merge-throughput property, not addressed here. A flush manifest above the budget still fails the shard; impossible unless the budget is below two tree heights.
