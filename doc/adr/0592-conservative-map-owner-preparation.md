<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0592 Conservative map preparation under actual header ownership

Status: accepted
Date: 2026-10-26

## Context

The owner-map-default oracle originally passed all eight reference cases;
own feature12/missing failed explicit acquisition with ENOENT. ADR0579 supplies
shared actual owner resources, but the current map phase requires a proven map
lease and rejects conservative load outcomes. The verified continuation contract
is in object-map-lock-recovery.md. Metadata-only lifecycle work needs the same
preparation engine and must not impersonate a DATA writer.

## Decision

Provider map I/O and image identity are separate from proof of holding a map
class lock. Only successful actual acquisition creates ObjectMapLockLease.
HEAD operations retain an atomic class assertion; snapshot-target operations
retain their watched header guard. Acquisition failures in header authority
remain failures, distinct from map-operation failures eligible for continuation.

Preparation retains real header authority while applying conservative map-load
and invalidation policy. Ready ownership must not imply a fictitious map lease.
Invalid map flags disable nonexistent-object shortcuts; cached map transitions,
asserted updates and snapshot-map work continue under their actual contracts.
Future metadata lifecycle contexts must reuse this preparation and recovery.

Filtered map access owns its real metadata context and actual header, but no
invented class lease. Cleanup inspects exclusive map identity before a possible
own unlock. Uncertain errors retain the header/cleanup fence; permission errors
are not evidence of absence. Conservative cache transitions precede class-error
completion. Invalid flags suppress shortcuts while map maintenance continues.
Rebuild uses an asserted resize with actual error completion: ESTALE must reach
staged DATA trim, and failed retries stop before map save or validity clearing.
Ordinary DATA resize retains conservative error filtering. This preserves the
existing safe geometry-repair improvement over the reference's filtered-ESTALE
behavior documented in object-map-rebuild.md.
If update-error flag lookup is unavailable, an asserted idempotent invalidation
is required before acknowledging DATA; local uncertainty alone cannot establish
that global invalidation is durable. This adds a safe header write relative to
the reference's flag-query-error shortcut and can propagate its failure.

## Rationale

Separating I/O from ownership permits safe filtered acquisition without hiding
resource state. Reusing the same wire operations prevents divergent DATA and
metadata cleanup implementations. Conservative state cannot authorize an absent
DATA shortcut or replace durable invalidation.

## Consequences

- + Existing proven-lease operations keep their actual authority checks and
  asserted wire requests while sharing one map-I/O implementation.
- + Future metadata ownership uses the same preparation as DATA writers.
- - Failed invalidation and uncertain cleanup retain real resources/errors;
  header-only success cannot stand in for completed FULL preparation.

## Alternatives

- Construct a lease after a filtered error: invents lock ownership.
- Skip all map work when invalid: violates cached-state and snapshot contracts.
- Add a metadata-only recovery engine: duplicates ownership and close handling.

## Open questions

The unchanged16-row degradation oracle, separate12-row physical DATA safety
gate and affected five native feature profiles pass. Complete oversized map
dropping, snapshot/authority/permission/uncertain-cleanup fault qualification and
metadata-only contexts. Bounded tests do not establish complete preparation or
release qualification. Measurements remain separate from correctness evidence.
