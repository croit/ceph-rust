<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0587 Shared staged flatten parent cleanup

Status: accepted
Date: 2026-10-26

## Context

Consumerc02540330 proves that successful flatten leaves a freed Trash parent
snapshot. Original features1/29/61 controls complete, including preserved
DEEP_FLATTEN snapshot bytes. The existing child writer mutex spans separate
parent detachment/notification and final child publication. ADR0586 already
provides full parent snapshot cleanup outside that mutex.

## Decision

Flatten uses the shared registration detach/full recursive parent snapshot
removal. The caller's actual activity/write turn and watched write permit
survive unlocked upstream work and progress callbacks. One shared retained
admin-authority validator checks generation, accepted owner epoch and enabled
class authority before each copyup, before upstream work and before child
parent-detach. It never reacquires replacement ownership for an obsolete plan.

Object copyup runs under short child writer guards; progress callbacks run
outside those guards. Upstream full parent cleanup and its publication/close
finish before final child parent-detach. A committed-update receipt refreshes
partial failures and publishes successful child mutation outside its mutex.
No standalone upstream update is emitted after registration detachment.

## Rationale

The same parent lifecycle applies to SnapshotRemove and flatten. Sharing it
prevents two cleanup algorithms and preserves actual resource/owner lifetimes.
Mutex release is required for callbacks and cross-image notification progress.

## Consequences

- + One registration and full parent snapshot cleanup implementation.
- + Retained actual authority fences unlocked callbacks and parent operations.
- - Partial copyup/upstream effects can remain after later failure; success
  publication is suppressed and the current child view is refreshed.

## Alternatives

- Raw deletion of the parent snapshot record: omits ownership, DATA IDs, maps
  and full notification/close ordering.
- Keep parent publication under the child mutex: retains a callback cycle.
- Reacquire ownership after upstream work: executes obsolete admitted work.

## Open questions

Metadata-only missing-DATA admission, full contended administrative routing,
USER_PARENT image-trash deletion and broader fault/cancellation qualification
remain open in the issue register. Neither this decision nor a bounded gate
claims complete flatten or image-removal parity.
