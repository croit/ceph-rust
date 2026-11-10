<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0493 Client bootstrap represents ordered auth methods and optional credentials

Status: accepted
Date: 2026-10-22

## Context

Both reference clients support NONE without credentials and choose service
authorizers from the negotiated monitor method. Native bootstrap originally
required a CryptoKey and an OSD ticket (before this ADR), so FFI rejected supported NONE policies; now implemented (typed `ClientAuth`).
Monitor NONE mode filtering is independently corrected in G18a.

## Decision

Represent client methods and optional credentials as a typed auth policy.
Retain CryptoKey conversion to the existing cephx-only policy and use a defaulted
bootstrap config parameter if needed to preserve native Rust call sites.
Select NONE or CEPHX service authorization from the negotiated monitor method.
Share an independent ticketless NONE handler between exact OSD/MGR peer roles.
Filter configured connection modes; never silently add CRC or synthetic secrets.

## Rationale

An optional credential is real protocol state. A placeholder key would hide the
unsupported case and keep ticket-dependent readiness broken. Explicit policy
preserves existing cephx validation and makes method order reviewable.

## Consequences

- NONE-only clients can bootstrap without a keyring or tickets.
- Credential loading failures can retain a configured NONE candidate.
- CEPHX session keys, service tickets and secure-mode validation remain intact.
- Every transport/ABI sibling uses the same selection and ownership contract.
- Temporary monitor-config lifecycle and detailed errno parity require their
  independent gates; auth-unit success does not qualify them.

## Alternatives

- Fabricate a key or ticket: invalid protocol state and a workaround.
- Force NONE on any auth failure: violates configured method/mode policy.
- Duplicate each transport: drifts service authorization and recovery behavior.

## Open questions

None for the typed policy. Remaining qualification is tracked in the gap inventory.
