<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0625 Forwarded snapshot creation

Status: proposed
Date: 2026-10-28

## Context

Snapshot creation can execute on the current exclusive-lock owner. Quiesce subscribers can flush or write the executing image before snapshot suspension. An accepted request belongs to its original owner epoch.

## Decision

- Forwarded creation uses the shared snapshot allocation/header/map/SnapContext backend with retained ownership and no replacement acquisition.
- Namespace/name and operations-disabled preflight precede quiesce; the executing owner's effective configuration governs quiesce.
- Quiesce precedes snapshot write-submission reservation. Serial admission and writer mutex are released before unquiesce and final update publication.
- The allocator returns the committed snapshot ID with its pending update. Local mirror and import callers perform no fallible post-commit ID lookup before notification.
- Accepted owner epoch, watched generation and actual header/map leases are validated throughout publication. Rejected pre-header allocation releases only this operation's allocated DATA snapshot ID; a committed header retains its ID even if later stages fail.
- Local/group creation keeps its existing acquisition policy and explicit group exclusion while sharing publication validation.
- Primary mirror states0/1 save filtered image state after map publication, then mark copy progress complete before installing SnapContext. State capture/write/progress failures retain committed header/ID/map and still install SnapContext.
- The local enable/promote/demote/direct-create core borrows the actual handle writer and shared transaction. A scoped mirror metadata purpose permits the NON_PRIMARY transition only while that writer mutex is held; restoring ordinary admission forces a fresh DATA capability check.
- Direct mirror-create quiesce runs before serial reservation; unquiesce precedes its outer update notification.
- Internal wire flags select map skipping, quiesce skipping and quiesce-error handling independently from public create2 flag parsing. Unknown bits are preserved and ignored, matching the pinned contract.

## Rationale

Sharing the durable backend keeps snapshot ownership and failure ordering consistent. Holding a write-submission sequence during callbacks can prevent their own writes from reaching admission.

## Consequences

- + No alternate forwarded snapshot format or allocator.
- + Callback flushes run before the snapshot's serial write prefix.
- - Cross-object header/map/state stages retain their existing partial-success contracts.

## Alternatives

- Invoke the public creation wrapper on the receiver: rejected because it can reacquire ownership and repeat caller-side policy.

## Open questions

- The intermittent legacy EEXIST observed at917c326a5 remains unexplained; later strict gates pass without a production workaround.

- Mirror-replay blocked-request policy qualification requires an actual installed mirror policy; an orphan payload must not bypass default group/lifecycle exclusions.

- Actual lease loss during state chunks/final copy progress, provider errors and own-RADOS qualification remain open after the bounded classic-provider gates.
