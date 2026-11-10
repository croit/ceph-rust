<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0495 Checked client buffer-appender allocation

Status: accepted
Date: 2026-10-22

## Context

Both pinned appender paths narrow requests and use unchecked unsigned rounding;
the refill treats a page count as bytes. The own prior implementation instead
rounded bytes, but narrowed unchecked and did not publish the new carriage.
The own contract (doc not in the source snapshot)
separates defined source behavior from unsafe overflow; ADR0256 permits compatible
correctness improvements without reproducing reference defects.

## Decision

- Refill uses the operating system's actual page size, checked byte rounding and
  checked u32 capacity conversion before allocation or list mutation.
- Capacity covers the larger of the minimum allocation and page-rounded request.
  An unrepresentable rounded capacity throws buffer::bad_alloc (category1),
  preserving the established buffer exception ABI; this is an own safe policy,
  not a claimed reference overflow exception.
- A successful anonymous page-aligned zero-length node becomes the list carriage.
  No logical bytes are added until appended. Ordinary allocation exceptions keep
  their existing ownership cleanup.

## Rationale

Checked arithmetic prevents undersized allocations after narrowing. Keeping the
existing stronger capacity guarantee permits ordinary appends without matching
the pinned page-count mistake. No throughput or allocation-count improvement is
claimed without measurement.

## Consequences

- + No truncated refill capacity; unchanged public object and symbol ABI.
- + Metadata-only maximum-bound tests avoid multi-GiB allocations.
- - Refill capacity/node population can differ from the reference's page-count
  behavior; explicit representability failures throw where no reference overflow
  contract exists. These differences require unchanged-consumer qualification.
- Siblings checked: shared C++ buffer ABI, both version profiles; transports,
  storage tiers, pool type and CRC/Secure paths consume the same byte owners.

## Alternatives

- Copy unchecked narrowing or page-count arithmetic: unsafe or undersized storage.
- Panic or abort at the public C++ boundary: loses catchable buffer-error semantics.

## Open questions

No new user decision; affected unit/artifact and unchanged-consumer evidence is
recorded separately. No live gate is authorized by this change.
