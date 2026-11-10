<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0620 Forwarded object-map rebuild

Status: accepted
Date: 2026-10-28

## Context

A rebuild request can be routed to the current exclusive-lock owner. The owner must use the accepted request epoch and its existing object-map/header lease while scanning and publishing the rebuilt HEAD map. Object-map save and invalid-flag clearing are separate mutations.

## Decision

- Object maps admit validated striping layouts: map entries address physical objects from `ImageLayout`, including all retained partial prefixes in a tail stripe set.
- The receiver executes HEAD rebuilds through the shared `ObjectMapRebuildScan` path.
- Local HEAD rebuilds also retain their initial owner epoch and validate actual map/header ownership throughout the shared scan and publication.
- The receiver validates accepted owner epoch and actual map/header ownership around each object revision lookup, progress report, map save and invalid-flag clear.
- The receiver does not acquire replacement ownership after accepting the request.
- The receiver saves the complete map before clearing invalid flags; any earlier failure leaves invalid flags uncleared.
- Remote progress is informational; the receiver reports zero from its progress handler because the current protocol does not carry requester callback cancellation back to the owner.

## Rationale

The shared scan defines object-map reconstruction and publication order. Retaining its write permit and adding owner-epoch checks prevents an accepted remote request from continuing after ownership changes.

## Consequences

- + Forwarded HEAD rebuild shares local revision enumeration, sparse-object handling and map-publication behavior.
- + Owner loss returns restart without acquiring replacement ownership in the accepted request.
- - Remote progress callback cancellation remains unavailable through the current wire protocol.
- - This decision covers forwarded HEAD rebuild only; selected-snapshot rebuild routing remains separate.

## Alternatives

- Reacquire full ownership after acceptance: rejected because acceptance does not confer replacement ownership and the operation belongs to the accepted epoch.

## Open questions

- Deterministic native provider-boundary lease-loss fixture remains required; asynchronous progress is not a scan barrier.
- Should a future protocol return requester progress cancellation to the owner while preserving accepted-request completion semantics?
