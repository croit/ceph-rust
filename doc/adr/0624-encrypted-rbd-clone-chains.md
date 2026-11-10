<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0624 Encrypted RBD clone chains

Status: proposed
Date: 2026-10-28

## Context

Encrypted clones can use a different key, crypto unit and payload offset from
their ancestors. Child-only crypto interprets inherited ciphertext incorrectly.
The pinned external contract is specified in ffi-encryption (doc not in the source snapshot).

## Decision

- Parse the selected opened chain in child-first order, preserving explicit
  format choices when reusing the last spec. Only an assumed unrecognized
  ancestor header terminates loading as plaintext.
- Complete parsing and validation before installing crypto, then publish child
  and ancestor contexts in the pinned order. Share each layer's crypto across
  refreshed and selected views of that image identity.
- Interpret inherited DATA in logical application coordinates. Each layer
  applies its own payload offset, striping and cryptor; an existing short object
  masks deeper ancestry and contributes a logical zero tail.
- Share the inherited reader between mutable and immutable views. Resolve
  missing spans with explicit continuations, independently of call-stack depth;
  preserve each layer's crypto-unit alignment and stage only partial units.
- Write clone-format header magic without installing incomplete child-only
  crypto. Header I/O remains separate from payload I/O.
- Preserve partial crypto units with edge-sector read-modify-write. Retain one
  admitted DATA permit and owner epoch from the baseline read through copyup,
  map updates and ciphertext writes; never reacquire a replacement lease after
  reading the baseline.

## Rationale

Layer-local coordinates preserve key and layout boundaries. Validating before
publication leaves rejected candidates out of the visible read view. Retained
write authority prevents a stale partial-unit baseline from being written under
a replacement owner. Reading only partial edge units avoids reading the full
replacement payload.

## Consequences

- + Distinct keys and payload offsets no longer require refusing all clones.
- + Synchronous/vector writes share the same crypto-unit preservation path.
- - Publication is ordered per layer, with no new global visibility barrier.
- - Mixed-format, deep-chain, selection, fault, own-provider and performance
  qualification remain required; implementation does not close RBD-043/044.

## Alternatives

- Apply the child's cryptor to inherited bytes: rejected because parent keys
  and payload offsets can differ.
- Reacquire ownership after reading partial crypto units: rejected because the
  baseline can become stale during owner replacement.
- Treat every ancestor parse failure as plaintext: rejected because recognized
  incompatible formats and wrong keys are errors.

## Open questions

- Complete the qualification matrices and measure remaining staging and
  per-layer read costs before claiming full API or performance qualification.
