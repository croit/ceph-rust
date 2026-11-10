<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0601 Conservative successor-map invalidation during snapshot retirement

Status: accepted
Date: 2026-10-26

## Context

Removing a FAST_DIFF snapshot merges its object-map history into the next
chronological snapshot or HEAD. An unreadable/invalid removed map or failed
merge cannot justify retaining authoritative absence or fast-diff information
in that successor. Snapshot namespaces do not change chronological succession.

## Decision

The common removal coordinator selects the next greater ID from the complete
snapshot context. It merges a valid removed map or invalidates the actual
successor under the retained header/watch authority before deleting the
removed map. Invalidation failure aborts retirement and preserves that map.
A previously missing removed map remains an idempotent cleanup case.

HEAD invalidation marks the live cached map invalid and metadata dirty before
persisting flags. Existing conservative HEAD reload/repair retains invalid
flags; repaired NONEXISTENT entries cannot become authoritative absence
shortcuts. Snapshot-successor invalidation does not invalidate unrelated HEAD.

## Rationale

One coordinator covers public, forwarded and Group removal with the same
resource ordering. Conservative flags preserve DATA correctness when map
contents cannot be trusted. Persisting invalidity under actual authority
avoids inventing successful cleanup after ownership loss.

## Consequences

- + Failed map merge/load degrades safely instead of leaving stale authority.
- + User, Group and retained-Trash successors share one chronological rule.
- - Real persistence/authority faults, cancellation and wider provider
  qualification remain RBD-020; actual loaded-map admission remains RBD-022.

## Alternatives

- Continue after failed invalidation: leaves an authoritative stale successor.
- Select only User snapshots: skips real Group/Trash history boundaries.

## Open questions

Complete the broader issue matrices in
the inventory (doc not in the source snapshot).
Evidence: completeness audit (doc not in the source snapshot).
