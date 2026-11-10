<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0494 Client identities retain their original bytes

Status: accepted
Date: 2026-10-22

## Context

Current pinned public creation APIs accept NUL-terminated entity names without
UTF-8 validation (entity-identity-contract.md). The adapter and native bootstrap originally
required Rust Strings and rejected otherwise supported identity bytes (before this ADR); now implemented (byte identities, `ByteBootstrapConfig`).

## Decision

Retain the type spelling and ID bytes from the public creation boundary through
configuration identity matching, metadata expansion, credential selection and
authentication. Parse the ASCII type prefix and preserve the ID exactly.
Represent structured authentication names with explicit byte storage and shared
wire encoding. Preserve existing text-based native entry points through typed
conversion or defaulted generics; do not make unrelated decoders lossy.
Retain supplied cluster-name bytes and successfully selected Unix config filename
stems through `$cluster` expansion. Use raw filesystem path bytes on supported Unix targets. Never substitute an
escaped identity into authentication, configuration matching or keyring lookup.
Diagnostic rendering must not expose credentials or change the stored identity.

NUL terminates the C and delegated C++ creation arguments; no pointer-plus-length
identity overload is invented. The `.bin` keyring filename does not select a
binary decoder: honor the pinned text-loading contract.

## Rationale

Unicode validation is an additional application restriction. The wire strings
and supported Unix paths carry bytes; typed adapters preserve native API usage
without alternate identity channels or special-case authentication fallbacks.

## Consequences

- + Supported non-UTF-8 IDs reach the monitor and service authorizers unchanged.
- + Full-name/type/global config selection and credential precedence remain exact.
- - Text and byte entry points need independent ownership and wire vectors.
- + Unrelated strict native/server text contracts remain explicit.

## Alternatives

- Lossy or escaped names: changes authentication identity and lookup keys.
- Accept creation then reject valid identity at connect: leaves the public gap.
- Add binary keyring loading based on suffix: invents a reference contract.

## Open questions

None for byte retention; malformed text/configuration input remains governed by
its separately source-grounded parser contract.
