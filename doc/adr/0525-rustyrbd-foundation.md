<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0525 Native RBD core and librbd compatibility boundary

Status: accepted
Date: 2026-10-22

## Context

The existing `rustyrados` engine has RBD class, snapshot, watch, lock and
blocklist primitives, but it does not own image layout, exclusive-writer state,
cross-queue flush or application ABI. Existing QEMU and fio RBD paths load
`librbd` and do not use a native Rust RBD API automatically. The initial RBD
implementation is requested without RDMA.

## Decision

- `crates/rustyrbd` owns native image semantics and uses `rustyrados` through
  the event-driven kernel runtime. The core has no Ceph implementation link.
- The separate `crates/rbd-ffi` compatibility adapter supplies the selected public `librbd`
  ABI, including symbol versions, C and C++ ownership, callbacks, completion,
  configuration and unchanged-consumer behavior. A native core alone is not
  advertised as a drop-in replacement.
- The compatibility target is the complete current public Ceph 21.2.0
  `librbd` C and C++ API and its required ABI. Unchanged QEMU RBD use is the
  first application gate. Each API family remains unqualified until its
  behavior, ownership and fault gates pass; the release claim requires all
  current families.
- Native metadata decoders and raw data-object READ/SPARSE_READ segments use the existing
  own-words specifications. A raw result retains missing or short objects for
  the image owner; it does not publish image bytes before parent, snapshot and
  zero-fill policy has run. Image open, application I/O and ABI remain
  unavailable until their contracts and gates exist.
- Four initial read-only header getters may be batched in one same-object
  MOSDOp. A decoded reply does not grant image access or lock ownership.
- Every accepted metadata or raw data completion retains the OSD user version
  of its target object. The image owner compares same-object observations
  during refresh; versions do not replace watch or writer fencing.
- RDMA is excluded from the initial dependency and validation path. A later
  transport option cannot alter image durability or fencing semantics.
- Compatibility gates use unchanged application binaries and independent
  content, durability, fault and performance oracles for each selected Ceph
  version. A symbol count alone does not qualify the replacement.

## Rationale

The RADOS engine already owns wire/session behavior. Keeping image policy in
the new crate avoids reproducing transport and retry logic while leaving room
for an independently qualified ABI. The read-only metadata decoder has a
stable own-words contract and no writer-side effects. Retaining the RADOS
payload owner through a raw READ avoids copying data before the image owner
has decided whether a parent lookup or zero fill is needed.

## Consequences

- + Native applications can use image operations without Ceph C++ object
  ownership or callback overhead once implemented.
- + The adapter can match public behavior while the core chooses safer
  internal ownership, cache and scheduling rules.
- - A working native image path does not make existing QEMU binaries work;
  their ABI and configuration imports need separate qualification.
- - Exclusive writer takeover, multi-queue flush and snapshot/clone data
  semantics require explicit image-level state machines and fault gates.

## Alternatives

- Link the original `librbd`: conflicts with the independent Rust replacement
  and clean-room rule.
- Modify QEMU first: would not meet the requested unchanged-consumer drop-in
  goal.

