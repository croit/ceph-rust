<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0586 Shared staged snapshot removal outside writer notification locks

Status: accepted
Date: 2026-10-26

## Context

Sourceaed8d065b reproduces successful last-snapshot removal retaining the
upstream child registration; all four original User/Trash controls pass.
Parent cleanup requires actual upstream ownership, full snapshot removal and
publication. Existing named/by-ID/forwarded/group callers enter one synchronous
commit helper with the child writer mutex held. Parent notifications and owner
work must not run under that mutex. Effective parent identity is specified in
snapshot removal (doc not in the source snapshot).

## Decision

The common removal coordinator separates preparation, upstream detachment/full
parent cleanup, and final child map/DATA/header retirement. Named, by-ID,
forwarded and group removal use that same coordinator. Preparation captures
stable snapshot identity, the coherent effective parent-reference set and real
child watch/owner authority. Live-child logical Trash success remains an early
completed result with no physical retirement.

The child activity/write turn and actual watched permit outlive unlocked
upstream work. The final child stage validates retained authority and the
current metadata cohort before mutation; it never acquires replacement
ownership to execute an obsolete operation. Partial committed stages are not
rolled back, and failed stages suppress the outer child success publication.

The registration decision uses metadata only. It requires that effective HEAD
parent differs from the target and no other snapshot carries that identity. Absent overlap
and present zero overlap are distinct. Missing upstream pool/header/entry is
tolerated according to the contract. Other detach failures stop before child
map/DATA/header deletion. No parent DATA open substitutes for this decision.

Upstream Trash snapshot cleanup uses a NEW internal parent context and the
shared ownership/recovery/removal machinery with the pinned skip-parent,
NON_PRIMARY and journal policies. Parent notifications and recursive removal
run outside child writer locks. Real parent resources and accepted work drain
before context destruction. Already-visited cleanup identities terminate
cycles explicitly rather than relying on recursion depth or a timeout.
Eligible USER_PARENT image-trash cleanup and full remote-owner routing remain
part of the required lifecycle, not optional raw class deletion shortcuts.

## Rationale

The retaining-condition controls require one metadata decision shared by all
entry points. Unlocking the writer must not release the operation's actual
ownership/activity fence. Parent publication can depend on another client's
callbacks and must not inherit the child serial mutex.

## Consequences

- + Parent and child mutation retain separate real authority and notification
  lifetimes while sharing one recovery algorithm.
- + The full failing User/Trash comparison remains the acceptance gate.
- - Metadata-only ownership and common administrative routing are dependencies
  for complete missing-DATA and contended/Mirror-parent behavior.

## Alternatives

- Delete the parent snapshot through a raw class call: omits maps, DATA IDs,
  Mirror resources, actual owner admission and notifications.
- Perform parent cleanup while holding the child writer mutex: introduces
  cross-image notification/ownership dependency cycles.
- Decide from the global parent key alone: incorrectly counts snapshot-only
  metadata as an effective HEAD reference.

## Open questions

Metadata-only missing-DATA contexts, contended parent administrative routing,
eligible USER_PARENT image-trash deletion and the flatten sibling remain open;
see the issue register (doc not in the source snapshot).
