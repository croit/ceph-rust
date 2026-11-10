<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0515 Service daemon application strings retain their original bytes

Status: accepted
Date: 2026-10-22

## Context

Both pinned public service APIs pass byte strings to the manager codec. Own
adapters reject non-UTF-8 input and therefore reject reference-supported calls.
C++ additionally permits embedded NUL and empty map keys.

## Decision

The compatible service owner retains byte names and byte dictionaries through
registration, status replacement, manager wire encoding and Close echo matching.
C and C++ adapters preserve their respective terminator/length contracts. Keep
String-based native/server call sites through typed adapters or defaulted message
types and share one wire codec. Do not make unrelated text decoders lossy.

## Rationale

UTF-8 validation is an additional application restriction. An owned byte form
preserves input lifetime and ordering without altering the existing wire format.

## Consequences

- + Names, empty keys and arbitrary values survive the public supported path.
- + Strict native resource policy and default server text use remain explicit.
- - Both typed surfaces need their ownership and wire vectors checked.

## Alternatives

- Lossy conversion: changes names, map ordering and caller data.
- Global byte conversion: expands the change beyond the affected contract.

## Open questions

Downstream manager display/module handling of arbitrary bytes is outside the
client encoding proof; preserve the original bytes and returned server behavior.
