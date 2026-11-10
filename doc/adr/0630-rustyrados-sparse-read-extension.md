<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->

# 0630 Rust client sparse-read extension

Status: accepted
Date: 2026-10-30

## Context

Encrypted image reads must distinguish absent object ranges from allocated zero ciphertext. The current C librados API does not expose sparse-read extents. The own C++ facade is an explicitly default-off profile (ADR0308).

## Decision

The own RADOS provider exposes private synchronous and asynchronous sparse-read capabilities independently of its C++ facade.
The capabilities return a validated sparse reply with allocation extents and packed bytes from the same operation. With read-version capture enabled, asynchronous completion retains its operation-specific version; synchronous callers isolate the ioctx when associating the read with its last-version value.
The image adapter uses the provider's C++ sparse-read contract for the classic provider and the private capability for the own provider. It does not infer allocation from ciphertext.

## Rationale

Both providers can preserve allocation metadata without changing the default C-only profile or introducing a blocking asynchronous fallback.

## Consequences

- + Reads can distinguish absent ranges from valid zero ciphertext.
- - The private capability requires versioned ownership and completion contracts alongside the public librados ABI.

## Alternatives

- Enable the partial C++ facade by default: changes the provider profile and does not satisfy ADR0308.
- Treat zero ciphertext as a hole: corrupts valid allocated data.
