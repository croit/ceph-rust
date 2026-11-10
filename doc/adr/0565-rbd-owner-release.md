<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0565 Preserve RBD header authority after failed dependent map release

Status: accepted
Date: 2026-10-24

## Context

The pinned managed-owner protocol releases the head object-map lock before
the header lock. Independent consuming destructors previously released the
header even after a map unlock error, and explicit release discarded local
lease ownership before its result was known. The contract is recorded in
`doc/spec/rustyrbd/managed-lock-handoff.md`.

## Decision

The writer owns its map and header leases as one ordered pair.
Explicit release retains that pair until both releases complete successfully.
Map release failure prevents header release.
The same pair governs setup-error and rebuild cleanup.
Destruction reports an already known release failure without automatically
repeating its remote operation.
Failed terminal cleanup submits no further remote unlock while freeing local
ioctx resources; unresolved remote ownership requires stale-owner recovery.
An unlock already confirmed before a notification failure remains complete.
Absent own lock entries complete unlock idempotently.
The pair uses static dispatch so scripted dependency failures can verify
ordering without changing production data-operation dispatch.

## Rationale

Moving header ownership before dependent map cleanup finishes allows a peer
to acquire incomplete ownership. Keeping failed explicit-release resources
allows the caller to inspect or explicitly retry, and prevents an uncertain
unlock result from becoming a successful release. Closing cannot retain
caller-owned image memory indefinitely; retaining uncertain server authority
preserves safety and makes recovery necessary instead of silently moving it.

## Consequences

- + Normal release, setup failure and rebuild share the same ordering.
- + Release errors propagate without losing the live explicit-release owner.
- + Fault tests can prove that map failure suppresses header unlock.
- - Failed terminal cleanup can leave remote locks requiring stale-owner
  recovery. The full managed recovery state machine is still incomplete and
  remains tracked in the completeness audit.

## Alternatives

- Always release the header: exposes partially released dependent ownership.
- Retry failed unlock automatically in a destructor: replaces an uncertain
  operation result without an explicit new action or retaining its error.
- Leak local image/ioctx resources: does not prove server cleanup and prevents
  bounded local image teardown.
