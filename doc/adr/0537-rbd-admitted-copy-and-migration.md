<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0537 Reuse admitted RBD writers for image copying

Status: accepted
Date: 2026-10-24
Amends: 0530, 0532

## Context

Raw object writes bypass the image owner's snapshot context and object map.
Copying into an existing image must preserve its snapshots. Migration execute
must publish consistent data and allocation metadata before reporting EXECUTED.

## Decision

- Copy and deep-copy use the watched image writer and its durable write lane.
- Migration initialization uses the same writer with an explicit destination
  purpose validated against an EXECUTING destination spec and empty SnapContext.
- Public writable admission continues to reject migrating heads.
- Managed-lock APIs share the writer's ownership instead of taking a second lock.
- Valid fast-diff maps accumulate all intermediate snapshot transitions; byte
  comparison is the correctness path when valid map history is unavailable.

## Rationale

One owner preserves snapshot, lock and allocation-map ordering across callers.
Explicit migration admission preserves the public fence without changing stored
feature bits to bypass it. Fast-diff state accumulation preserves changed data
without scanning every payload on valid-map images.

## Consequences

- + Existing destination snapshots and default-feature object maps stay coherent.
- + Copy and migration share fixes to durable write ownership.
- - Copy inherits the admitted writer's supported feature/geometry boundary.
- - Invalid/missing fast-diff history requires bounded-buffer data comparison.

## Alternatives

- Raw copy plus a later map rebuild: leaves inconsistent metadata observable
  between the data writes and rebuild and bypasses destination snapshot context.
- Temporarily clearing MIGRATING: exposes a migrating destination as ordinary.
