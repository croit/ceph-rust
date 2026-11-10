<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0615 Forwarded snapshot metadata execution

Status: accepted
Date: 2026-10-28

## Context

Snapshot rename, protect and unprotect requests can reach a non-owner handle
through administrative forwarding. The receiver must mutate the image under
the accepted owner's retained lease and preserve the pinned operation-specific
namespace and failure behavior.

## Decision

- Execute forwarded rename, protect and unprotect on the real owner writer.
- Admit each operation against the accepted owner epoch and current watch
  generation; do not acquire a replacement owner in the receiver.
- Rename resolves the stable snapshot ID in the USER namespace, checks name
  collision before source lookup, and writes the destination while preserving
  the snapshot ID and timestamp.
- Protect and unprotect resolve the request's namespace and name, then use the
  same persisted protection transition as local execution.
- Revalidate the accepted epoch and actual write lease before protection
  status lookup, transition writes and rollback writes.
- Preserve receiver preflight ordering: epoch and lease admission, operation
  disabled state, then snapshot lookup and operation-specific checks. Public
  calls retain their own earlier argument/name/status checks.

## Rationale

The stable ID preserves snapshot identity across rename. Checking ownership
again around every protection-state operation prevents a stale receiver from
performing either the requested transition or its rollback after lease loss.
The pinned public and raw forwarded paths have different preflight ordering,
so they keep separate admission logic while sharing mutation helpers.

## Consequences

- + Forwarded requests execute under the current retained owner and preserve
  snapshot identity and protection state.
- + The accepted wire namespace remains part of protection lookup.
- - Requester reselection, owner-loss injection, cancellation and broader
  provider/application qualification remain open.
- - Qualification covers only the bounded matrix recorded in the completeness
  report; it does not close the full administrative API inventory.

## Alternatives

- Acquire a replacement owner during receiver execution: rejected because the
  receiver must honor only the epoch accepted by the forwarding protocol.
- Reuse public preflight ordering for raw requests: rejected because the pinned
  receiver checks operation-disabled state before name and protection status.

## Open questions

- Qualify owner replacement and cancellation at each state boundary, plus
  broader namespace and provider/application combinations.
