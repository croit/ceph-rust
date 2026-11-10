<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0597 Shared owner preparation with caller-specific head observation

Status: accepted
Date: 2026-10-26

## Context

ADR0579 shares real resources/recovery; ADR0592/0594 complete conservative map
preparation in the DATA writer. A metadata-only lifecycle context must use that
same preparation without inheriting DATA-pool or DATA-feature admission.

## Decision

ImageOwner owns the single preparation implementation. A narrow borrowed
OwnerObservation supplies actual resources, current metadata and a checked head
refresh. Each concrete caller retains its admission policy. DATA writers keep
strict DATA binding/layout checks; metadata contexts must represent missing DATA
explicitly and never construct a DATA writer or substitute metadata I/O for DATA.

The shared implementation preserves acquisition stages, actual authority,
conservative map loading, oversized map retirement/reopening, readiness and
retained cleanup failures. Observation does not invent leases or map presence.
The existing recovery coordinator remains the sole recovery state machine.

## Rationale

Borrowed disjoint fields avoid extra contexts, allocation or dynamic dispatch
on DATA admission. Sharing the actual implementation prevents metadata and DATA
preparation from diverging while preserving distinct caller validation.

## Consequences

- + Existing DATA paths exercise the exact preparation reused by metadata.
- + No optional DATA writer fields or fabricated DATA contexts.
- - Metadata-only concrete context, policy and lifecycle consumers remain work.

## Alternatives

- Duplicate writer preparation: diverging authority/error/cleanup contracts.
- Add metadata purpose to a dummy DATA writer: invalid DATA capability claim.
- Generic image framework: broader abstraction than ownership preparation needs.

## Open questions

Implement concrete missing-DATA context and bind it to shared recovery before
lifecycle delivery. Extraction qualification is recorded in
the milestone evidence (doc not in the source snapshot).
