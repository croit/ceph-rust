<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0679 RocksDB format identity alongside native blind removals

Status: accepted
Date: 2026-11-05
Amends: 0681-rocksdb-omap-engine (format identity only)

## Context

The experimental RocksDB branch and main independently allocated bit 23. Main
uses bits 23/24 for uncounted OMAP and removal runs, set together before replay.
RocksDB must not interpret a native store as an external database or vice versa.

## Decision

- Preserve main's bits 23/24 and historical format golden entries unchanged.
- Select RocksDB with incompatible bit 25, still requiring the LSM logical WAL
  and explicit database configuration. No mount-time engine conversion.
- Before superblock healing or replay, reject any intact copy with LSM + bit 23
  but neither bit 24 nor bit 25. This includes old experimental RocksDB stores
  and any indistinguishable native signature. No automatic migration is supported;
  preserve both storage halves and use the original binary for recovery/export.
- Append golden samples under the combined feature key; retain main's counter-free
  onodes and removal-run WAL samples. Durability/publication rules are unchanged.

## Rationale

Feature identity must remain unambiguous before any persistent mutation. Database
paths and configuration alone cannot identify the on-device engine safely.

## Consequences

Existing benchmark artifacts remain tied to their original revisions. Rebased
binaries cannot reopen their old bit-23 RocksDB stores. Fresh provisioning is
required for new experiments; this decision authorizes no device operations.

## Alternatives

Reusing bit 23 or silently treating old RocksDB stores as native LSM risks OMAP
loss. Inferring conversion from a configured directory violates persistent engine
selection and fails when that configuration is absent.
