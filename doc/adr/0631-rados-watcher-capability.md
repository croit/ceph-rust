<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0631 Provider watcher-list capability

Status: accepted
Date: 2026-10-31

## Context

Image removal and watcher enumeration need the object watcher list. The
reference C API does not expose that operation; its C++ interface does.
The default own RADOS profile executes the operation but lacks that facade.

## Decision

The own RADOS provider exports a private C capability returning a validated
encoded watcher list in a provider-owned buffer. The caller releases it with
that provider's buffer-free function. Librbd selects the capability only
when it and the free function belong to the same loaded provider as its
RADOS C operations. Other providers use their existing C++ interface.

## Rationale

The capability exposes the actual watcher operation without enabling the
incomplete C++ ABI facade or treating an unavailable watcher list as empty.

## Consequences

- The default own provider supports watcher-based image lifecycle operations.
- The private capability is not part of the reference librados public ABI.
- Foreign providers continue to require the existing C++ watcher interface.

## Alternatives

- Enable the partial C++ facade by default: widens the public ABI surface.

## Open questions

None.
