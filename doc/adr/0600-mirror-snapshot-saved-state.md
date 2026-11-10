<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0600 Mirror snapshot saved-state retirement

Status: accepted
Date: 2026-10-26

## Context

Mirror snapshots can own saved-state objects in their image's metadata
namespace. The shared snapshot-removal coordinator converts namespaces to
Trash before physical retirement; inspecting only that converted namespace
loses the information required to clean Mirror state.

## Decision

The staged removal plan retains the originally selected namespace. Physical
retirement removes non-orphan Mirror state before releasing the DATA snapshot
ID or removing its header entry. User, Group, orphan Mirror and already-Trash
selections do not run this Mirror-specific cleanup.

Saved-state header decoding follows the pinned framed contract. Descending
object removal tolerates individual ENOENT; a missing initial header permits
ordinary retirement. Other read/remove failures stop before DATA/header
retirement and leave the ordinary coordinator available for retry. The same
actual watched owner, activity and publication path remains authoritative.

## Rationale

Retaining selection identity preserves the resource contract across namespace
conversion. Descending deletion leaves the count-bearing header until last,
so a partial failure can resume without inventing another persistent index.

## Consequences

- + By-ID Mirror removal cleans saved state through the common coordinator.
- + Unrelated HEAD and control-snapshot bytes remain covered by matched gates.
- - Real-provider faults, owner loss, cancellation and broader lifecycle
  qualification remain RBD-019. Ordinary whole-image deletion remains RBD-024.

## Alternatives

- Inspect the converted Trash type: loses the original Mirror selection.
- Remove only object0: leaks valid multi-object saved state.

## Open questions

Complete the broader RBD-019 matrix in
the issue inventory (doc not in the source snapshot).
Evidence: completeness audit (doc not in the source snapshot).
