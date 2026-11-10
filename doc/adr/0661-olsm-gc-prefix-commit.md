<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Igor Fedotov, croit GmbH -->
# 0661 Commit OMAP GC prefixes with same-age residual runs

Status: proposed
Date: 2026-11-05
Amends: 0610

## Context

OMAP GC can select a column spanning the shard's levels. Foreground OMAP admission waits while that merge holds the space debt above the routine target, so a large column makes a single client mutation wait for the whole merge. The run codec already describes immutable chunks, a run ID and LSN interval, and its partition bounds.

## Decision

A GC job can finish and install a complete key prefix, returning immutable suffix residuals for the unconsumed input data.
All versions of a key are processed before a prefix boundary; range tombstones are clipped to the resulting prefix and suffix ranges.
One manifest transaction replaces every original input descriptor, installs the prefix output and same-ID suffix descriptors, and releases the consumed extents through the existing checkpoint and reader holds.
A residual retains its input run ID and LSN interval. A tier-0 residual keeps the whole-keyspace place; a tiered residual starts at the prefix cut or its original lower bound, whichever is later.
`Manifest::install_gc_prefix` removes the original merge inputs and installs residuals by original age, preserving any younger tier-0 flush installed while the merge was in flight.
Completed prefix output is installed in its bottom-tier partitions; residual partition bounds are disjoint from that prefix and consistent across all runs of a partition.
GC excludes a completed prefix before the minimum entry or range-tombstone start of the selected oldest tier-0 runs; downward column closure retains every overlapping older partition. Its trimmed garbage share is checked against the same GC target; absent tier-0 coverage or garbage outside the frontier retains the original whole-column fallback.
Merge key selection uses a minimum heap of source indices ordered by borrowed key and original source age. Only advanced sources are refilled; a missing chunk keeps its source pending until the global minimum is known again. A successful output consumes every equal-key source before another prefix decision, while an output refusal restores the unchanged winning source. Ready heap and pending refill storage are reserved once per job; no key handles or heap storage are allocated per entry.
Foreground space-debt admission additionally requires physical pressure; see [physical-pressure admission](0662-omap-physical-pressure-admission.md). The routine GC target remains unchanged.
The descriptor and run metadata codec versions remain unchanged.
If the completed prefix manifest exceeds the existing hard transaction limits, its unpublished output reservations are returned and the original pick restarts as a complete GC merge. The retry keeps the output partition cut and reserved run-ID interval, disables only prefix stopping, and uses a new helper job identity so late reads cannot attach to it. The original manifest remains unchanged until a fitting transaction is admitted.
A complete (non-prefix) merge whose manifest exceeds those limits is dropped unpublished instead of failing the shard; merge picks are bounded by the same limits ([0662 am. 1](0662-omap-physical-pressure-admission.md)).

## Rationale

Publishing reclamation at prefix boundaries lets space admission observe progress before a whole column has been rewritten. Retaining residual ages preserves lookup order, including concurrent flushes and later puts after a range tombstone. Atomic descriptor replacement means replay sees a complete old or new manifest state and never loses the suffix of an input. The job and driver keep the existing physical-allocation, WAL and memory admission guards. The heap avoids comparing every future partition head for every entry of a large column; source-age ties and range-tombstone visibility remain unchanged.

## Consequences

- + Prefix and residual descriptors can be mounted by the existing descriptor codec.
- + Newer flushes keep precedence over old-ID residuals without relabeling LSN intervals.
- + The next GC pick can reclaim another prefix using the same manifest policy and targets.
- - Each prefix writes changed residual metadata and a manifest transaction. Untouched metadata remains referenced.
- - Freed input blocks still wait for the existing checkpoint and reader epochs; GC output and retired-input accounting must include that transient physical space.

## Alternatives

- Exempt deletes or raise the space target: the same admission barrier remains, and absent-key tombstones can still grow state.
- Reassign new IDs to residuals: tier-0 residuals could become younger than a concurrent flush and violate age ordering.
- Delete an original descriptor before all suffix data is represented: a crash could lose acknowledged keys or resurrect older values.
