<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0581 Deferred snapshot retirement for clone-v2 children

Status: accepted
Date: 2026-10-26

## Context

A clone-v2 child can still inherit a snapshot after its user-visible name is
removed. Immediate class deletion returns EBUSY; physical retirement would
invalidate the child's dependency. The pinned removal lifecycle (doc not in the source snapshot)
distinguishes namespace deletion from physical snapshot retirement.

## Decision

The common writer checks protection, converts non-Trash snapshots through
snapshot_trash_add, then refreshes and reconciles registered child pools.
Only an actually missing child pool permits stale-link detachment; completed
detach drives re-enumeration. Other errors propagate.

A request that converted the snapshot, or received EEXIST during conversion,
returns logical success when children remain. It preserves header ID, map and
DATA snapshot ID. Explicit already-Trash removal returns EBUSY in that state.
The normal successful notification follows the installed metadata view.

Named removal retains its User namespace fence. Public by-ID removal uses
the captured stored namespace and resolves absent IDs before read-only refusal.
User, Group, Trash and Mirror share the physical removal path. Mirror saved-state
cleanup uses the originally selected namespace before DATA/header retirement
([decision](0600-mirror-snapshot-saved-state.md)); unknown namespace operations
remain unsupported.

Owner-side SnapshotRemove notifications enqueue typed work against that same
writer. Full async identities deduplicate pending and completed operations;
modern acceptance is separate from the post-publication completion notify.
Legacy requests retain their final-result ACK. Lanes serialize operation kinds;
image close seals and drains them before destroying the real writer/watch.
Admission checks ready ownership independently of DATA auto-acquire policy.
Other admin executors and sender selection remain open; this increment does
not qualify the full forwarding matrix.

## Rationale

The retained numeric dependency preserves clone reads and subsequent HEAD
writes. Missing names do not imply absent physical snapshots or children.

## Consequences

- + Public removal can hide a live clone-v2 parent snapshot without retiring
  resources that its child still needs.
- + [Ordered physical retirement](0582-snapshot-data-retirement-order.md)
  preserves header identity on DATA retirement failure.
- - Broader physical retirement and conservative map failure qualification
  remains open; this decision is not complete snapshot parity. Last-parent
  cleanup is covered by ADR0586; Mirror saved-state handling is linked above.

## Alternatives

- Return EBUSY for every live child: prevents the pinned logical deletion.
- Retire the DATA ID or map after hiding the name: breaks inherited data.
- Treat a missing child header as a stale registration: the pinned admission
  proves staleness from the missing pool, not from a child-header probe.
