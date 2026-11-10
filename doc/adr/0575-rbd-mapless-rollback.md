<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0575 Snapshot rollback with optional object maps

Status: accepted
Date: 2026-10-25

## Context

Rollback required OBJECT_MAP despite independently admitted plain and
header-only writers. The pinned rollback contract (doc not in the source snapshot)
requires real snapshot restoration without requiring a map.

## Decision

One rollback path handles plain, header-only and mapped images. Snapshot maps
are optional skip/restoration metadata. Only mapped writers load snapshot maps,
retain a previous map, publish pending entries and restore the head map. Plain
writers perform every target-object rollback without map class requests.
Only two proven Nonexistent states permit an object skip. Actual object
ENOENT is tolerated after image-snapshot identity validation; all other object
errors propagate. Every object retains the admitted watch generation/owner
epoch and any enabled actual header lease. Acquisition is scoped local TRY;
no partial rollback is automatically restarted. A negative progress result
stops subsequent work and suppresses the outer success update; internal resize
may already be committed. Nonnegative progress does not cancel work.

## Rationale

The map accelerates absence decisions but does not establish the underlying
RADOS snapshot. Optional map state preserves authority and SnapContext rules
without constructing fictitious map or header ownership for plain images.

## Consequences

- + Plain/header-only rollback no longer has a blanket OBJECT_MAP refusal.
- + The mapped path keeps its authority, pending-state and snapshot-map gates.
- - Parented/striped rollback and broader fault/release qualification remain open.

## Alternatives

- Require OBJECT_MAP: refuses a valid pinned image profile.
- Treat missing maps as proof of absent data: loses real snapshot bytes.
- Retry partially executed rollback: hides already committed changes/errors.

## Open questions

Test evidence (commit hashes, cell results): librbd completeness, ADR evidence (doc not in the source snapshot). Parent and stripe support still
require their full metadata/data restoration contracts separately. Wider
fault, own-provider, platform, application and performance qualification remain
open; bounded classic-provider evidence is not release qualification.
