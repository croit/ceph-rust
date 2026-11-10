<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0599 Shared layout geometry for striped resize and rollback

Status: accepted
Date: 2026-10-26

## Context

Snapshot rollback uses the image's physical object numbering and retained
snapshot revisions. Logical byte counts divided by object size do not describe
non-default striping. Resize and rollback share DATA tail handling; a small
shrink must not scan every object in a large image.

## Decision

ImageLayout supplies the physical object count and inverse-mapped retained
object prefix. The shared trim visits only object positions intersecting the
removed logical tail, in descending object order. Rollback restores complete
saved revisions without adding an unrelated post-rollback truncate stage.

Ordinary writer admission recognizes STRIPINGV2 independently of DATA_POOL.
Unparented user rollback and resize use the shared layout geometry. Existing
parented default-layout shrink semantics retain the class-level HEAD-overlap
clamp and snapshot-aware DATA context. Feature-required header/map ownership and real write
permits remain prerequisites; geometry does not fabricate resources.

## Rationale

One layout mapping avoids divergent object numbering between ordinary writes,
resize and rollback. Bounded tail traversal removes work proportional to the
unchanged prefix. Restoring a revision already defines the rollback result;
extra object truncation would introduce a separate unverified mutation.

## Consequences

- + Unmapped unparented striped images support user rollback and resize.
- + Existing snapshots and distinct DATA-pool placement retain their real
  write context and ownership.
- + Parentless byte holes and clone inheritance have separate qualification
  cells; logical zero coverage is not proof of physical object absence.
- - Striped object-map admission and Group/Mirror rollback fences remain
  implementation gaps tracked in RBD-050/052. Parented rollback is RBD-051.
- - Wider namespace, ownership-loss, cancellation and performance qualification
  remains; bounded correctness gates are not release qualification.

## Alternatives

- Scan every object on shrink: unnecessary work for unchanged object sets.
- Truncate the last object after rollback: incomplete for a striped final set
  and outside the verified saved-revision contract.

## Open questions

Complete remaining stripe/entrypoint admission and the broader fault/owner
matrix in doc/reviews/librbd-open-issues-20261026.md before release qualification.
Evidence and exact tested sources are in doc/perf/librbd-completeness-20261024.md.
