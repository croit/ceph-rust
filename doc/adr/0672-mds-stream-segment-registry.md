<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0672 MDS stream-local segment discovery

Status: accepted
Date: 2026-11-05

## Context

Recovery listed the entire metadata pool for each stream and filtered object
names locally. The real-cluster fixture creates 65,536 manifests and 65,536
tablets; unrelated objects dominated recovery of an almost empty log.

## Decision

Each stream head holds a durable omap registry of its allocated segments.
The first segment data write waits for its allocation entry to become durable.
Later writes preserve per-segment submission order across this barrier.
Recovery reads this registry, never the metadata-pool object list.
Checkpoint publication atomically retires registry entries below its segment.
The exact storage and crash contracts live in
mds-store-format (doc not in the source snapshot).

## Rationale

A per-stream registry bounds discovery by that stream's retained allocations.
Idempotent independent entries do not require ordering competing counter updates
across segments. Existing stock omap operations suffice.

## Consequences

- + Recovery work is independent of unrelated filesystem object count and PG count.
- + Crash-before-data allocations remain discoverable without hiding later tail data.
- - The first append of each segment adds one durable head operation.
- - Old unshipped prototype heads without the registry contract require reformatting.

## Alternatives

- Pool listing: work grows with unrelated filesystem objects.
- Stop probing at first missing segment: can hide valid unacknowledged tail groups.
