<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->

# 0632 Provider object-revision capability

Status: accepted
Date: 2026-10-31

## Context

Migration and snapshot-aware reads require the physical object revision list.
The public C API has no list-snaps call and the own C++ facade is default-off.

## Decision

The own RADOS provider exposes a private C capability that executes LIST_SNAPS
on a SNAPDIR-selected ioctx and returns a validated encoded response in a
provider-owned buffer. The caller frees it with that provider's buffer-free
function. Librbd selects the capability only when both functions belong to the
provider of its RADOS C operations. Other providers use their C++ interface.

## Rationale

The image reader needs actual object revision history to choose the correct
migration source. This capability preserves that information without widening
the incomplete default C++ ABI or guessing whether an object is materialized.

## Consequences

- The default own provider supports snapshot-history-dependent image reads.
- The capability is private and does not claim the reference public C ABI.
- Foreign providers retain the existing C++ snapshot-history interface.

## Alternatives

- Enable the partial C++ facade by default: widens the provider ABI.
- Infer history from object presence: can return the wrong revision.

## Open questions

None.
