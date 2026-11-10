<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0730 Rebase SplinterDB onto renamed multi-engine main

Status: proposed; source-only conflict resolution, validation held by user
Date: 2026-11-06
Extends: 0727-splinterdb-omap-engine

## Context

Main renamed the daemon/tool and configuration namespace, added actual RocksDB,
assigned native OMAP blind-removal bits23/24 and RocksDB bit25, and isolated
native LSM write buffers from foreign snapshots (ADRs0679/0680/0681). The private
SplinterDB branch previously used bit25. Keeping either entire conflict side
would discard another engine or restore foreign snapshot overhead on native LSM.

## Decision

Keep main's package paths/names `croit-flashstore-osd` and
`croit-flashstore-tool`, canonical `flashstore_*` configuration, strict native
startup parsing, selected-service CPU vector and queue-count validation. Resolve
SplinterDB worker/cleaner rotation inside the common store mount with the same
physical CPU vector used by RocksDB. Keep both optional Cargo features; select
only one persistent foreign engine at runtime.

Reserve SplinterDB bit26, distinct from RocksDB25 and native23/24. Reject dual
foreign-engine identities. Refuse a legacy bit25 foreign header without main's
native23/24 markers before healing or replay. Preserve main's ambiguous legacy
RocksDB bit23 refusal. There is no automatic conversion or header rewriting.
Retain old binaries/source/artifacts for original experimental datasets; all
future rebased SplinterDB experiments require fresh provisioning. No datasets
were opened, converted or erased for this rebase.

Keep `olsm::mem` identical to main's direct-owned native buffers. Reuse the
existing first-party foreign-overlay mechanics from `rocks_omap/mem.rs` without
linking RocksDB for a SplinterDB-only build. The `foreign_mem` module alias is
compiled exactly once; each selected engine owns its own active/frozen buffers
in State. Native manifests still own publication frontiers. Preserve separate
transaction overlays and saved/resumed state; replay/WAL application targets the
selected foreign buffers. Do not turn a foreign table into a native RunBuilder
job. Foreign ranges bypass native-only candidate estimation.

Keep native ScanMemo unchanged. SplinterDB and RocksDB each retain their own
memo wrapper, collection, credit accounting, cancellation/expiry and clone-source
continuation. Preserve both engine diagnostics, external-space accounting and
all native LSM unsent-read/physical-pressure improvements.

## Consequences / qualification

Historical benchmark receipts describe pre-rebase binaries and settings, not
the current source. Maintenance offload remains default-off and unvalidated.
The user's hold on tests, builds and test06 access remains binding. New format
and coexistence regressions are authored but unrun; feature-disabled/native,
RocksDB-only, SplinterDB-only and both-feature compilation, replay/crash and
placement qualification await explicit execution permission. No release or
on-disk migration qualification follows from conflict resolution.
