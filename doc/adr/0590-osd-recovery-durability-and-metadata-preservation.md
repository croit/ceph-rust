<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0590 Durable recovery completion and byte-exact metadata preservation

Status: accepted
Date: 2026-10-26

## Context

Local recovery updates visible PG state before its transactions are durable. Declaring the PG clean at that point can delete its last durable stray source. Optimized EC primary roll-forward can target a stash created by the current shard transaction. RGW preservation of user xattrs must retain arbitrary byte names.
Backfill targets can also acknowledge completion while their durable PG info still marks them incomplete; after a crash they cannot become authoritative if the primary is unavailable.

## Decision

- A primary publishes clean and purges strays only after an ordered, nonempty PG-info transaction commits; its continuation validates the peering interval, latest recovery-round token and current recovered state.
- A backfill target sends `FINISH_ACK` only after its completion PG-info transaction commits, with peering-interval validation; preceding removals and progress updates are durable at that boundary.
- Optimized EC primary transactions apply shard changes before log append/roll-forward, matching replicas.
- RGW attribute preservation and prefix checks use raw xattr names and byte prefixes.

## Rationale

The existing per-PG commit-order contract provides the durability boundary for both replicated pulls and EC reconstruction without delaying unrelated PG work. Creating the stash before applying earlier omap records preserves rollback state. Raw attribute APIs avoid lossy name conversion and collisions.
Target-side completion persistence preserves restart eligibility before the primary retires backfill sources. The primary's local recovery fence cannot establish another OSD's durability.

## Consequences

- + Previously acknowledged recovery data retains a durable source until replacement persistence completes.
- + Replicated, legacy EC and optimized EC backfill targets retain complete PG metadata across restart before reporting completion; storage backend, transport and messenger mode share the same continuation.
- + EC rollback and RGW preservation retain committed metadata.
- - Recovery completion adds one PG-info transaction before clean publication.
- + No persistent format or wire encoding changes.

## Alternatives

- Gate source deletion on visible missing sets: those sets can advance before local durability.
- Track another per-object durable missing set: unnecessary for the shared clean/source-retirement boundary.
- Reject non-UTF-8 xattrs: violates the existing byte-name contract.
