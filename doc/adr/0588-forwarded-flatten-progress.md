<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0588 Forwarded flatten execution and bounded progress transport

Status: accepted
Date: 2026-10-26

## Context

The owner receiver accepts SnapshotRemove but refuses Flatten. Local flatten
already has a shared staged executor retaining actual activity/watch authority
across unlocked parent cleanup. The pinned administrative protocol requires
request-specific coalesced progress and independent acceptance/final completion.

## Decision

Flatten receiver jobs reserve the existing actual image submission and retain
the accepted owner epoch. The shared flatten core validates that epoch instead
of acquiring replacement ownership. Local C progress and remote Rust progress
use the same copyup/upstream/child-detach implementation.

The existing administrative service owns progress sends. A weak service handle
and full AsyncRequestId bind progress to the accepted operation. One service
worker submits the first queued value per full ID; later values before that
task runs are discarded. Legacy zero IDs have no progress sends. Remote progress always
returns success, regardless of requester callback or progress transport result.

The existing owned asynchronous header-notification transport retains provider
completions, reply slots and contexts. Final completion waits for queued progress
submissions, never progress ACKs. Transport runs outside writer and service-state
mutexes. Seal cancels pending progress and rejects new updates; close drains
execution, submission tasks and actual provider flights before destruction. Completion retains the existing timeout-only retry
and full-ID duplicate/cache behavior.

## Rationale

One service owns acceptance, progress, completion and close lifetime. Shared
flatten execution prevents mutation divergence; a retained accepted epoch
prevents obsolete remote work from acquiring a new owner.

## Consequences

- + Progress buffering is bounded by active full request IDs, not callback count.
- + Slow progress ACKs do not hold the writer mutex or delay final completion.
- + Provider storage survives every actual accepted flight through close.
- - A separate transient progress worker is needed while progress is pending.

## Alternatives

- Synchronous notify from every callback: couples copyup to each transport wait.
- One thread per callback: unbounded resources and no per-request coalescing.
- Call the public flatten wrapper from the receiver: repeats activity admission
  and may reacquire ownership under an obsolete accepted request.

## Open questions

Qualify actual original/own forwarded flatten, progress, duplicate/legacy,
close/owner-loss and partial-failure paths before integration. General requester
routing and other receiver operations remain separate gaps. Full image-trash,
missing-DATA, crypto and application/performance qualification remain open.
