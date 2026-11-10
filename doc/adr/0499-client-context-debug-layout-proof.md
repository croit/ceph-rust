<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0499 Foreign-context layout proof accepts matching compiler debug metadata

Status: proposed
Date: 2026-10-22

## Context

Configured header and consumer flags have not been recovered from the frozen
runtime images. Public pinned-release debug packages are an alternative source
of compiler-emitted type metadata for the exact binary being inspected.

## Decision

Accept compiler DWARF record layouts as numeric layout evidence only after the
debug object's build ID matches the independently hashed reference ELF. Record
package URL/hash, pin, architecture, producer and full relevant type/member facts.
A missing/incomplete type or unmatched build ID supplies no layout proof. Header
compiler probes remain an independent cross-check and support other build flags.
No executable code or source implementation is imported into the replacement.

## Rationale

Matching compiler debug metadata describes the concrete binary's type layout
without estimating offsets from declarations or assuming source-build defaults.

## Consequences

- + Runtime-package layout can be qualified without guessing consumer flags.
- - Debug data can omit definitions or depend on supplementary DWARF objects.
- + Ownership and behavior still require independent own specs and tests.
- + Neither package download nor matching build ID alone proves compatibility.

## Alternatives

- Assume source defaults: may select a different C++ layout.
- Hand-compute offsets: misses toolchain and conditional-member differences.

## Open questions

Which complete type definitions and supplementary objects are available for each
pinned reference artifact remains an observed prerequisite, not an assumption.
