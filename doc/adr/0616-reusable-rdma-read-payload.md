<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0616 Reusable aligned host DMA payload ownership

Status: accepted
Date: 2026-10-27

## Context

Native READ targets and remote WRITE windows retain exclusive registered allocations. The store
accepts immutable shared `Bytes` and can construct aligned kernel write views
without payload copies. Converting ownership must preserve registration/backing
and prevent another DMA while any consumer still reads the previous bytes.

## Decision

Use a typed prepared -> pending -> shared -> prepared host buffer cycle on the
existing exact-CQ READ primitive and WRITE window retirement owner. Allocate aligned initialized backing, shared
metadata and local MR on the control path; remote WRITE targets also prepare
their reusable MW there. Publication freezes the existing
buffer; consumers clone immutable `Bytes`. Reuse requires exclusive conversion
back to mutable ownership, without allocating/copying as a fallback. The backing
and registration retain their original range. Source/DMA failure follows the
existing accepted-owner quarantine contract. No target MW is allocated for local
READs. Remote WRITE publication requires authenticated peer retirement followed
by successful exact LOCAL_INV CQ. Retired bytes do not prove transferred extents,
integrity, object success or durability. The object layer must establish those
before acknowledging success. Rustdoc in `rdma::verbs::{PreparedReadBuffer,
PreparedWriteBuffer,SharedReadBuffer,SharedWriteBuffer}` owns the API behavior.

## Rationale

An ordinary foreign owner cannot itself prove when arbitrary `Bytes` clones or
NVMe views have stopped reading. The buffer's shared-reference ownership supplies
that proof and preserves the store's existing payload type. Control-path split
preparation keeps shared metadata reusable during publication and recovery.
Exact CQ retirement alone cannot authorize overwrite while a consumer still
holds the old result.

## Consequences

- + One registered buffer can supply repeated DMA and immutable consumers.
- + The kernel write-view path can retain the same payload address.
- - Initial allocation includes alignment padding and zero initialization.
- - Object/wire execution, integrity and durability remain separate requirements.
- - Failed/abandoned accepted DMA still requires bounded safe reclaim work.
- - GPU/device memory does not satisfy this host allocation contract.

## Alternatives

- Copy completed DMA into ordinary `Bytes`: retains the payload copy.
- Create new ownership metadata for every publication: avoidable progress cost.
- Overwrite after CQ regardless of consumers: races CPU/NVMe reads.

## Open questions

- Which chunk geometry/overlap improves full OSD bandwidth and p99 versus TCP?
