<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0729 Select SplinterDB configuration by persistent engine identity

Status: proposed; implementation/regressions authored, execution held by user
Date: 2026-11-06
Extends: 0730-splinterdb-rebase-main; 0680

## Context

Source review found four cross-engine costs/refusals after the rebase: unused
SplinterDB startup errors reached all store configurations; provisioning admitted
unused backing filesystems or rejected their inherited flags in feature-disabled
tools; replay cloned extra operations for unselected engines; the shared golden
fixture requested bit26 keys absent from the historical golden file.

## Decision

Persistent superblock features select which optional backend configuration is
consumed. Capture strict SplinterDB option parse errors at startup, but propagate
them only when configuring a SplinterDB-selected store. Native B-tree, native LSM
and RocksDB mounts do not lock, clone or install the SplinterDB configuration.
All production mount/upgrade entrypoints pass their already-read feature mask.
Missing or invalid selected SplinterDB backing remains an error, not fallback.

Tool configuration parsing has no filesystem/device admission side effects.
Explicit SplinterDB provisioning still validates build support, shards, root,
capacity, cache policy, filesystem/device admission and free-space reserve before
destructive native operations. Implicit existing-store opens validate the binding
and backing admission after reading the persistent identity. Deferred parsing
errors follow the same selected-engine gate as daemon configuration.

Explicit other-engine preparation excludes SplinterDB backing flags. With no
selector, retain dormant flags for resolving an existing SplinterDB store; do
not assume an existing store is B-tree merely because fresh default mkfs is.
Inherited backing options alone do not require a SplinterDB-enabled tool.
Explicit unsupported SplinterDB selection, or an actual unsupported SplinterDB
header, still refuses before mounting or changing a store.

Clone a foreign replay snapshot only for the runtime-selected foreign engine.
Native direct-owned buffers, native/Rocks worker algorithms, WAL authority,
publication barriers and memory targets remain unchanged.

Keep shared-structure golden samples and their keys identical to main with and
without SplinterDB compiled. Mask only SplinterDB's independent engine identity
from those shared samples; preserve all other encoding feature bits. Keep the
append-only historical golden file unchanged. Independently assert the bit26
little-endian vector and encoded header offsets/bytes, and retain selected-SplinterDB provisioning/read-super/replay
regressions. This does not change production encoding or the incompatibility bit.

## Qualification

New Rust regressions cover unused malformed/valid options for all three other
engine feature masks, actual native B-tree/LSM file-device mount paths, inherited
tool flags, deferred filesystem admission, selected replay snapshot retention and
shared golden keys. Existing strict selected-SplinterDB tests now explicitly ask
for SplinterDB-selected configuration.

All tests, builds, format checks and live work remain UNRUN under the user's
hold. Source-only review is not compile/startup/recovery or performance evidence.
Combined binaries retain optional state fields/selection branches; no claim of
zero CPU/RSS/latency overhead is made. Intentional ambiguous legacy bit25/bit23
header refusals remain as documented in the rebase decision.
