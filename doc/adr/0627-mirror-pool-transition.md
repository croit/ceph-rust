<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0634 Pool mirror mode transitions

Status: proposed
Date: 2026-10-28

## Context

Pool mode transitions coordinate pool metadata, per-image mirroring and watcher
notifications. These effects span objects and cannot be committed atomically.

## Decision

Persist the IMAGE intermediate mode before per-image work, preserving it on
failure. Use the existing image enable and disable lifecycle, with the
reference same-pool parent exception only for pool-wide enable. Enumerate
mirror registrations using bounded pages. Persist and notify the final mode
only after per-image work succeeds. Notification errors are reported but do
not undo a durable mode transition.

## Rationale

The intermediate state exposes partial work and permits subsequent recovery;
reusing image lifecycle logic preserves its ownership and cleanup contracts.

## Consequences

- + Mode changes do not report success before required image operations.
- - Errors can leave the pool in IMAGE mode with partial image work.

## Alternatives

- Write only the target mode: rejected because image state and watcher views
  would not reflect the requested mode.

## Open questions

- Qualify all transitions with image, parent, peer, notification and provider
  failure matrices, including the own RADOS provider.
