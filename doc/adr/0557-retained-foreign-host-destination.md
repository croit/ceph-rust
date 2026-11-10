<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0557 Retain foreign host storage through the existing READ lifecycle

Status: accepted
Date: 2026-10-24

## Context

The native registered destination consumes a Vec, which cannot represent
externally allocated storage without transferring allocator ownership or copying
bytes. KVBM/NIXL integration needs retained foreign allocation identity. GPU
export/MW feasibility and concurrent slab leases remain unqualified.

## Decision

- A distinct ForeignHostAllocation retains an explicit lifetime owner and stable,
  initialized CPU-addressable host range. Unsafe construction validates numeric
  bounds before allocating; the caller proves mapping, exclusivity and lifetime.
- Prepared foreign destinations use the existing MR/MW, exact subrange, attempt,
  retirement, verification and quarantine machinery. No payload staging, new
  request identity, GPU address inference or address-only cache is introduced.
- Native async registration charges the full retained range and runs provider
  setup on the existing control-thread path. Admission and provider rejection
  return the original allocation; final successful release returns its owner.
- MW or MR release uncertainty retains the foreign backing and PD permanently,
  with the existing registration charge. Dropping a returned unbound destination
  releases either backing kind only after successful provider retirement.
- Whole allocation ownership remains exclusive. Concurrent slab partitions and
  the C extension require further work; no new C symbols are added here.
- GPU memory is excluded from the foreign-host constructor's safety contract.
  Device import, revocation, visibility and integrity retain separate gates.

## Rationale

The same destination state machine preserves exact ownership and zero-copy
payload placement without coupling the native client to an external allocator
or assuming that a device allocation supports host slices or type-2 windows.

## Consequences

- + Foreign storage uses one retained MR/MW across sequential READs.
- + No per-operation foreign-owner allocation or payload copy is required.
- + Vec and foreign cleanup share provider-proof and budget handling.
- - Constructor safety depends on the foreign allocator's real ownership contract.
- - Control-plane owner boxing and prepared resources remain cold setup costs.
- - Native Rust support does not establish C ABI, slab concurrency or GPU readiness.

## Alternatives

- Reconstruct a Vec from foreign memory: adopts an incompatible allocator/lifetime.
- Copy foreign memory into an owned Vec: defeats direct payload placement.
- Use one CPU-buffer type for host and GPU: permits invalid GPU dereferences.

## Open questions

- Concurrent subrange leases and the opaque C boundary remain in the existing
  RDMA gap assessment (doc not in the source snapshot).
