<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0560 librbd provider controls and standard encryption

Status: proposed
Date: 2026-10-24

## Context

The pinned librbd C inventory contains operations requiring a second cluster
connection or a provider operation absent from its C API. The earlier private
crypto codec did not implement standard LUKS and exposed a LUKS1 volume key.
Symbol presence has also hidden unconditional refusals and incomplete state
machines in other families.

## Decision

- Keep image controls under the existing experimental Cargo features.
- Resolve all borrowed-context operations in the consumer's provider instance.
- Enumerate watchers through actual provider-constructed GNU C++ IoCtx/string/list
  objects on Linux GNU LP64; release objects through that runtime.
- Own the remote bootstrap cluster and ioctx separately; close the ioctx before
  shutting down its cluster on every return path.
- Request daemon resync by persisting the pinned journal-client or image-metadata
  flag; do not implement replay in this control API.
- Use standard LUKS1/2 layouts, AF key material, encrypted keyslots and volume-key
  digests. Require independent cryptsetup interchange tests.
- Keep exported-symbol inventory separate from behavioral qualification. Retain
  every confirmed unsupported operation in the completeness checkpoint.

## Rationale

Provider-owned ABI objects preserve context identity without reading private
IoCtxImpl layouts. Separate remote ownership prevents bootstrap failure from
invalidating the application's local connection. Independent format consumers
catch defects that symmetric local round trips cannot detect.

## Consequences

- + Removes the five missing C export families from the implementation backlog.
- + Makes crypto file interchange independently testable without a live cluster.
- - Watcher ABI support is restricted to the verified GNU profile.
- - C++ allocation exception containment remains unresolved in the pure Rust
  caller; this bridge is not release-qualified.
- - Full mirroring, migration, deletion, quiesce and encrypted-image lifecycle
  qualification remain separate work; all-features exports are insufficient.

## Alternatives

- A second arbitrarily loaded provider instance: rejected because borrowed ioctx
  identity cannot be transferred across instances.
- A fabricated own-watch list: rejected because it omits independent clients.
- Private crypto header compatibility: rejected because it is not LUKS.

## Open questions

- How should the Rust-only boundary contain foreign C++ allocation exceptions
  before the public C ABI? See doc/90-open-questions.md.
