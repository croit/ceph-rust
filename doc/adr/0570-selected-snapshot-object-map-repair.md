<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0570 Selected snapshot object-map repair is metadata-only

Status: accepted
Date: 2026-10-25

## Context

The pinned public rebuild permits normally opened selected snapshots while
rejecting USER/NON_PRIMARY read-only and disabled operations. Its shared
geometry-shrink trim edge can access absent HEAD lock state or reject DATA
writes on a selected snapshot; it is not a safe immutable-revision repair
contract. See own-word contract (doc not in the source snapshot).

## Decision

Selected-snapshot repair scans physical child revisions using private DATA
SNAPDIR contexts, builds a fresh correctly sized map, and full-saves only the
selected snapshot map without a HEAD map-lock assertion or DATA mutation.

Missing, corrupt, already invalid or wrong-sized maps receive durable selected
invalid flags before work; validity clears only after successful full-save.
A valid immutable map can be scanned/cancelled without additional invalidation.
Map replacement asserts its captured object version, or exclusive creation when
initially absent. Header flag writes assert the observed header version. Accepted
metadata invalidations fence scan publication; competing writes are not silently
overwritten. A post-save conflict leaves conservative invalid flags.

Existing dirty allocation states are not cleaned by a scan: they can be a
predecessor-removal merge preceding its final header change. Invalid maps carry
no trusted clean evidence; repaired allocated states remain conservatively dirty.
A subsequent verified snapshot transition can establish clean states. No
successful outer notification follows a failed scan/save/flag-clear.

Public open kind is retained explicitly. A serial metadata reservation permits
selected-revision repair while ordinary DATA reservations remain read-only.
Accepted image updates advance a persistent local metadata sequence before
callbacks, including when no subscriptions exist. Rebuild applies refreshed
NON_PRIMARY query policy after invalidation; selection alone does not change
initial HEAD read-only state. USER read-only remains explicit and permanent.

## Rationale

Immutable snapshot DATA and child parent relationships need no trim to repair
allocation metadata. A full class save validates framing and regenerates
persisted checksums. Durable invalidation protects readers across partial
repair failures instead of publishing invalid absence/clean shortcuts.

## Consequences

- + Snapshot repair cannot accidentally trim HEAD or mutate immutable DATA.
- + Invalid metadata stays conservative after cancellation or provider errors.
- + Callbacks run without the writer mutex and DATA write fencing is retained.
- - Failure flags can differ conservatively from pinned unsafe repair paths.
- - This does not qualify HEAD invalid-map admission, own-provider ABI, broad
  fault behavior or performance; evidence remains in doc/perf/.

## Alternatives

- Reproduce shared resize/trim internals: rejected because the selected-snapshot
  edge is unsafe and unnecessary for application/wire-compatible repair.
- Infer primary authorization from Normal open or raw features alone: rejected
  because pinned refresh mode and persistent USER/NON_PRIMARY state matter.

## Open questions

- Complete independent selected-revision fault/application qualification.
- Integrate the metadata sequence with the remaining shared refresh/config and
  reconnect lifecycle work without losing invalidations.
