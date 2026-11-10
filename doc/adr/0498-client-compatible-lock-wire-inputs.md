<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->

# 0498 Compatible lock wire inputs

Status: accepted
Date: 2026-10-22

Authors: Martin Verges, croit GmbH.

## Context

The own input contract (doc not in the source snapshot) establishes
both-pin public inputs that strict native acquisition deliberately excludes.
the folded former ADR0277 (spec/rados-abi/c-abi-ops.md (doc not in the source snapshot)) input policy incorrectly moved server validation into the adapter.
The async contract (doc not in the source snapshot) requires
accepted writes, not locally synthesized completions.

## Decision

- `CompatibleLockOperation<B = Vec<u8>>` uses one field container implementing
  `AsRef<[u8]>`, raw unsigned32 duration words and an unchanged flag byte. The
  default preserves owned public callers; C/C++ adapters use
  `CompatibleLockOperation<&[u8]>`. Native `LockOperation`, `LockRenew` and
  `Duration` source behavior and strict validation remain unchanged.
- Both public representations produce a private borrowed `LockWireInput` view.
  Native build first validates its actual name/duration and converts its actual
  duration/renewal to wire words/flag; compatible build supplies its actual raw
  values directly. One checked sizing path and encoder consume that view for all
  seven native variants and four compatible variants. No dummy typed values,
  optional scalar overrides, encoded-byte patching or flag masking.
- Adapter helpers explicitly borrow C first-NUL spans or C++ counted string
  views only during synchronous encoding. The shared encoder checks all field
  widths and the complete class-call envelope before allocating/copying metadata
  into owned request bytes. No intermediate metadata Vec, separate sizing API
  or duplicate borrowed-operation enum. Neither accepted async work nor a native
  request retains borrowed caller bytes; caller reuse is permitted after return.
- LP64 timeval seconds convert modulo 2^32. Checked signed64 microseconds times
  1000 convert modulo 2^32 independently, without `Duration` normalization.
  NULL encodes zero words. Signed multiplication overflow is refused with EINVAL;
  the reference expression is undefined there, so this is a documented safe
  difference, not a claimed reference errno.
- Empty names, contradictory flags and defined noncanonical times reach ordinary
  request admission. Snapshot EROFS, remote results, completion/write accounting,
  input snapshots and reply ownership retain existing shared paths.
- This decision supersedes only the folded former ADR0277 (c-abi-ops.md#adr0277) flag/timeval input policy.
  Existing compatible hard input bounds, output policy and native limits stay.

## Rationale

Public wrapper acceptance and native ergonomic validation are separate contracts.
An explicit generic input type keeps raw values out of normalized native durations
without duplicating the codec or changing owned native callers. Borrowed adapters
avoid copying potentially oversized metadata before complete envelope validation;
ownership is established by checked encoding, not by an earlier per-field copy.

## Consequences

- + All 256 flag bytes and well-formed empty names retain server error precedence.
- + C string prefixes and C++ counted bytes are encoded into owned requests after
  complete width/cap validation and before submission/acceptance returns.
- - Source-only findings and unrun own fixtures are not either-version live parity.
- Break-entity conversion follows the expanded both-pin own contract: recognized
  type prefix, locale-aware whitespace refusal, base10 signed conversion and full
  counted-string consumption. Defined numeric overflow selects the signed64
  endpoint identity instead of a local EINVAL; conversion errno is not an API
  result. Public C still uses its first-NUL prefix. This uses libc conversion,
  not a reimplementation of reference code.
- Siblings checked: shared C/C++ sync/async boundary covers all transports,
  replicated/EC, storage tiers and CRC/Secure; no backend-specific codec change.

## Alternatives

- Relax native validation: breaks the independent strict native contract.
- Patch encoded fields or encode twice: obscures sizing and ownership invariants.
- Separate owned/borrowed enums or public length-only APIs: duplicate operation
  structure or allow sizing to drift from the single encoder's actual inputs.
- Normalize timeval or flags: changes defined public request bytes and precedence.

## Open questions

- No live lock or alternate-locale qualification is inferred from unit tests.
