<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0510 Ordinary client pool freshness has private map-wait ownership

Status: accepted
Date: 2026-10-22

## Context

Ordinary requests currently cancel when routing finds a missing pool. Both
reference versions query monitor map freshness before reporting an initially
absent pool. Public map-wait completion ownership must remain independent.

## Decision

Bootstrap owns a separate compatible map queue for ordinary pool checks.
Flights retain their token, original deadline and sticky resolved-pool fact.
Excess private checks remain flight-owned until staging credit becomes free.
Selective token polling cannot consume another request's completion.
All map queues share monitor dispatch, session-reset and terminal lifecycle.

## Rationale

A public completion consumer cannot safely serve private object operations.
Reusing the map-wait implementation preserves query boundaries and recovery.
The existing staging quantum bounds work without bounding accepted population.

## Consequences

- Initially absent pools report ENOENT only after a fresh map proof converges.
- Deleted resolved pools report ENOENT immediately, preserving sent uncertainty.
- Appearing pools resume routing and detach obsolete proof ownership.
- Cancellation and terminal deadlines release private and object ownership.
- C1 resend barriers stay active until the request sends or terminates.

## Alternatives

- Reuse public completions: breaks independent ownership.
- Report immediate ENOENT: stale maps can reject valid pools.
- Cancel the operation: exposes the wrong application error.

## Open questions

None for private ownership. Forced-read version-specific error categories remain
tracked separately in the full routing audit.
