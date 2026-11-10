<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0497 Librados listings retain jobs across shared staging pressure

Status: accepted
Date: 2026-10-22

## Context

Both reference versions enumerate across PG pages without dedicated item, job,
result-byte, state or total-page ceilings (listing-public-resource-contract.md).
The existing FFI applies its own permanent profile limits. Native callers may
still explicitly request bounded scans; those budgets are separate contracts.

## Decision

- FFI listings use an explicit compatible scan policy without scan-wide state
  or page limits. Strict native constructors retain caller-selected budgets.
- Retain the public size_t maximum through accumulation. Per-page counts use
  the remaining count bounded by the existing native u32 request interface;
  reply data retains the wire's u32 encoded-output bound.
- Allocate entries as verified pages arrive. Do not reserve the maximum count
  or cap total retained bytes independently of actual addressable storage.
- Retain accepted listing jobs while shared native staging credits are full.
  Reactor work quanta govern progress, never public eligibility or population.
- Observe every queued deadline before admission attempts. Include the earliest
  queued deadline in the reactor sleep bound; no polling or retry timer.
- Close settles every queued/active waiter once. Existing snapshot, cursor,
  namespace, filter, layout and complete-output publication rules remain.
- Compatible cursor slicing has no independent endpoint-copy budget. Validate
  encoded hobject lengths and preserve clone-before-output aliasing semantics.

## Rationale

Temporary shared staging pressure must not turn valid librados operations into
permanent EAGAIN failures. Page validation and an original absolute deadline
provide progress/error boundaries without total-page magic constants. Incremental
allocation makes a large maximum cheap when the actual result is small.

## Consequences

- Large and concurrent listings can retain more memory, proportional to actual
  results and accepted caller work. Real allocation failures remain ENOMEM.
- C/C++ share the same controller, native page owner and scan validation across
  kernel TCP, io_uring and RDMA. DPDK remains compile-only.
- Observable ADR0256 correction: retain the public size_t maximum instead of
  reproducing the reference's lossy 32-bit truncation. Unrepresentable actual
  int return counts fail EOVERFLOW before output publication.

## Alternatives

- Increase the old constants: preserves the same incompatibility at a new size.
- Return EAGAIN on staging pressure: exposes an internal resource profile as an
  application failure instead of retaining accepted work.
- Reserve the caller's entire maximum: huge maxima on empty ranges waste memory
  or fail even though no result storage is needed.
