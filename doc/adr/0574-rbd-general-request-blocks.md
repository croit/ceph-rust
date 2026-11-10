<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0574 Nested GENERAL-request exclusion ownership

Status: accepted
Date: 2026-10-25

## Context

Group coordination must prevent owner handoff across its all-member boundary.
The pinned local-admin preparation helper also temporarily blocks requests,
but ordinary manual/DATA acquisition does not. Exact scope and phase ordering
are specified in group lock boundaries (doc not in the source snapshot).

## Decision

A noncloneable guard retains the image's ManagedOwner state and one nested
GENERAL-request block. The first nonzero result remains sticky until the last
guard retires; release order does not restore an older zero status.
Owner phase admission precedes blocked-status selection. Fully ready blocked
REQUEST_LOCK receives the stored framed result before advertisement/policy
selection, without invoking a release hook. Self/no-owner requests stay empty.
Block state is distinct from DATA/manual policy and blocklist error state.

Rollback's local preparation obtains a temporary zero guard only when its
exclusive-lock context needs preparation and releases it before result
selection or mutation. Ordinary manual/DATA acquisition adds no such guard.
The local helper normalizes EAGAIN/EBUSY completion, then still requires actual
prepared ownership; another negative propagates. This is separate from the
stage-aware manual/DATA acquisition path. Already prepared owners undergo
existing writer authority/map validation outside helper normalization.
Future group guards must outlive acquire-all/member snapshots/unquiesce and
retire with their temporary contexts, not immediately after acquisition.

## Rationale

Owned guards settle one known state object exactly once even if close replaces
or removes a transport. Separate count/status avoids conflating request
coordination with DATA readiness. Local preparation normalizes completed TRY
contention only before checking actual prepared ownership. Existing-owner
authority checks and stage-aware manual/DATA acquisition retain their own
error handling.

## Consequences

- + Nested zero/error blocks cannot erase a still-active group exclusion.
- + Blocked Automatic requests do not release ownership accidentally.
- - Group creation/rollback and actual administrative forwarding remain open.
- - Existing rollback layout/parent/map restrictions are separate gaps; this
  increment does not establish full rollback compatibility.

## Alternatives

- A stack of saved errno values: contradicts first-nonzero-until-final-unblock.
- Installing Standard policy for a group: changes unrelated DATA/manual policy.
- Blocking every acquire: applies local-admin semantics to unrelated paths.
