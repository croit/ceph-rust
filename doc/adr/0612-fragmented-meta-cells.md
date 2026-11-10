<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0612 Logical metadata cells backed by physical extents

Status: proposed
Date: 2026-10-27
Amends: 0021

## Context

Elastic metadata growth currently requests one contiguous allocation per logical cell. Fragmentation can prevent this allocation while total free data blocks and metadata-image capacity remain sufficient. The metadata tree needs contiguous pages, but does not require all pages of a cell to be physically adjacent.

## Decision

- A logical metadata cell retains the store's fixed page count and stable logical page indices.
- Growth first requests one contiguous extent. If that fails, it reserves smaller page-aligned extents down to one complete metadata page.
- A page never spans physical extents. Failed growth returns every partial reservation before reporting failure.
- Each logical cell owns its complete physical extent map. The persistent metadata image records that map in a versioned representation; old single-extent images remain readable and older readers reject the new image version.
- Checkpoint ownership and reclamation cover every physical extent. Newly reserved extents are published by the same checkpoint as their metadata map and allocator bits; released extents remain held until the checkpoint that removes the mapping is durable.
- Growth during a sliced freeze joins the live metadata space after that freeze ends, and becomes durable with the following checkpoint.
- Admission accounts for extent-map image bytes and the bitmap chunks touched by every extent. Exhausting the image budget returns reservations rather than publishing a partial cell.
- Page durability continues to use checksummed copy-on-write pages and checkpoint roots; the design does not assume atomic metadata-page writes.

## Rationale

The logical cell abstraction already separates tree page indices from physical addresses. Extent mapping removes the contiguous-cell requirement while preserving the logical allocation unit and complete-page I/O. Keeping contiguous allocation first limits mapping overhead in unfragmented stores. The maximum extent count is bounded by the logical cell's page count.

## Consequences

- + Metadata can grow into fragmented free space that could not hold a whole cell.
- + Existing logical page indices survive mapping and checkpoint round trips.
- - Fragmented cells use more mapping records, bitmap-chunk updates, and potentially more device requests.
- - Stores that persist the new metadata-image version require a reader that understands it.

## Alternatives

- Smaller fixed cells: lowers the contiguous allocation requirement but does not remove it.
- Variable logical cell sizes: changes logical index calculation and cell accounting as well as physical mapping.
