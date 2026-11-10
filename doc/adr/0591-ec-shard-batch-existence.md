<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0591 Sequential existence checks within EC shard batches

Status: accepted
Date: 2026-10-26

## Context

Peering combines rollback of multiple divergent entries into one shard-operation batch. Undoing a delete restores the live object before older entries restore its metadata. Checking existence against the pre-batch store skips that metadata restoration and can hide acknowledged data behind a truncated object size.

## Decision

The storage adapter updates its transaction-local existence overlay after each shard operation. Subsequent source and metadata checks observe all preceding operations in the batch. Other store operations continue to update the overlay once per operation, only when the transaction contains shard operations.

## Rationale

Sequential translation preserves the existing rollback and missing-source contracts. The same overlay covers rename, clone-range, attribute and omap operations without changing their producers or the storage engine.

## Consequences

- + Rollback restores acknowledged object size, version and metadata together with its bytes.
- + Metadata operations after removal remain no-ops.
- + Legacy and optimized EC share the correction across kernel/SPDK storage and all messenger transports/modes; replicated transactions without shard operations retain their existing path.
- + No disk format or wire changes.

## Alternatives

- Update existence only after the whole batch: later operations observe stale object presence.
- Split every rollback batch into store operations: unnecessary changes to peering's transaction construction.
