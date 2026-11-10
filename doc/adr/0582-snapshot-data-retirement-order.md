<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0582 Retire snapshot DATA before its header identity

Status: accepted
Date: 2026-10-26

## Context

The pinned snapshot-removal contract orders map cleanup and DATA snapshot-ID
retirement before header removal. With metadata write permission and read-only
DATA permission, sourceefd42c9a8 returns EPERM after deleting the header; both
original feature1/29 controls preserve it. Independent isolated-resource cleanup
passes and the reproduction has zero timeout warnings.

## Decision

The shared remover deletes the snapshot map, retires the DATA snapshot ID,
then deletes the header snapshot record. Map/DATA errors preserve the header.
Missing maps and already-retired DATA IDs permit continuation; missing header
records retain their class error. Earlier committed stages are not rolled back.
The writer refreshes its view after a failed intermediate stage and suppresses
its outer success publication. Retrying after completed map cleanup skips merge.

## Rationale

A failed DATA retirement must retain the header identity needed for retry.
A completed map stage is not replayed from absent resources.

## Consequences

- + Permission failures preserve the snapshot and allow a later authorized retry.
- - Full last-parent detachment, Mirror saved-state cleanup, metadata-only missing
  DATA admission and conservative successor invalidation remain separate gaps.

## Alternatives

- Delete the header first: loses retry identity when DATA retirement fails.
