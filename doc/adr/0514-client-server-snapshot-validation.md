<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0514 Compatible writes delegate snapshot-context semantics to the server

Status: accepted
Date: 2026-10-22

## Context

The own dual-pin contracts `explicit-write-snapshot-contract.md` and
`ordinary-operation-edge-contract.md` distinguish validated stored contexts from
explicit C++ asynchronous write contexts. Compatible preflight and native queue
admission currently reuse strict snapshot predicates, rejecting representable
requests before their ordinary completion path. The server can replace or filter
the context before validating it, so invalid submitted structure need not fail.

## Decision

- Compound validation has explicit strict and compatible policies.
- Compatible preflight and compatible queue admission delegate write-context
  sequence/ID semantics to the server for every representable nonempty write.
  No vector-specific exceptions, sorting, deduplication or local error reply.
- Operation/access checks, write-to-head selection, read-context exclusion and
  wire representation checks remain local. Strict preflight and strict queues
  retain their existing snapshot predicate. Stored-context setters stay strict.
- The accepted request owns its original sequence and ordered IDs through wire
  construction and retries. The ordinary remote success/error completion wins;
  client validation does not predict server substitution or normalization.
- All three explicit-context C++ AIO overloads use the same compatible native
  path. EROFS refusal precedes builder transfer and completion retention. Existing
  completion publication, durability and C1 resend ordering remain unchanged.

## Rationale

The validity of the server's effective context cannot be inferred from the
submitted vector alone. Sharing an explicit compatible validation policy across
preflight and admission prevents a later layer from reinstating local rejection.
Existing session sends and the own MOSDOp codec carry these numeric fields without
reapplying their semantic predicate.

## Consequences

- + Representable explicit contexts reach the server-owned completion path.
- + Native strict users and stored-context setters retain their local checks.
- + Ordinary request ownership, retry identity and ordering remain shared.
- - Unit fixtures prove client behavior only; remote qualification is separate.

## Alternatives

- Reject duplicate/ascending/reserved vectors early: changes acceptance and can
  discard requests whose effective server context would succeed.
- Relax strict APIs globally: changes explicitly requested native policy.
- Normalize the vector in the adapter: changes the submitted context and cannot
  reproduce pool/PG-dependent server decisions.

## Open questions

None for validation ownership. Build-host tests and both-pin remote qualification
remain the root's responsibility; this increment runs no build or test.
