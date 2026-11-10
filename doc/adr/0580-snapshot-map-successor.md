<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0580 Snapshot map successor on removal

Status: accepted
Date: 2026-10-26

## Context

Merging a removed snapshot's fast-diff map into HEAD loses changed extents
when a later snapshot remains. The pinned snapshot-removal contract (doc not in the source snapshot)
selects the next greater snapshot ID across every namespace, otherwise HEAD.

## Decision

The shared writer removal path chooses the minimum greater ID in its full
SnapContext. Snapshot-map successors use watched header authority without a
HEAD map assertion. HEAD mutations keep the atomic exclusive-map assertion,
mark cached state for reconciliation before submission, and reload it on
success. Snapshot successors leave HEAD cache unchanged.

Protection is checked before map mutation. A later failed header removal
retains completed conservative map transitions; it does not restore HEAD.

## Rationale

Chronological map propagation preserves changes accumulated before the
removed snapshot. Namespace filtering and unconditional HEAD merging omit
those changes from later reference fast-diff results.

## Consequences

- + User and Group removal share the corrected target and cache behavior.
- - This correction does not complete Trash/parent/Mirror cleanup, DATA-ID
  retirement ordering or map-error invalidation; those remain explicit gaps.

## Alternatives

- Always merge HEAD: demonstrated lost extent in the matched reference gate.
- Merge the next User snapshot: excludes Group, Trash and Mirror successors.
- Reverse completed merges after header failure: adds nonreference rollback
  and can restore changes required for a later retry.
