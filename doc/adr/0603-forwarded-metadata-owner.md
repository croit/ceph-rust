<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0603 Retained-owner metadata execution and writer configuration refresh

Status: accepted
Date: 2026-10-27

## Context

MetadataUpdate notifications carry a key and an optional value; an empty
present value differs from removal. Metadata configuration overrides can
change the discard behavior cached by an already-open writer. A previously
published HeaderUpdate can stale the receiver's cached observation before
its next admitted operation.

## Decision

The administrative receiver executes MetadataUpdate against its accepted
owner epoch, retained watch permit and serial operation lifetime. It refreshes
the coherent header before generation admission without acquiring a replacement
owner. Publication and completion run after releasing the writer mutex.
Existing complete async request identities retain duplicate/result semantics.

Local and forwarded image-config mutations stage the owned discard settings,
publish HeaderUpdate, then refresh effective configuration. A failed reload
retains dirty/refresh-required state. Unchanged watched generations perform no
extra configuration RPC. General client ConfigWatcher events remain unqualified.

Unknown operation features disable the affected administrative mutations while
ordinary DATA remains available; pinned operation-specific exceptions remain.
Public setters validate config before read-only refusal; removers perform
read-only admission before key lookup.

## Rationale

One writer path preserves actual authority and configuration behavior across
local and remote metadata changes. Refreshing a stale observation incorporates
self-published notifications instead of adding retries or reinterpreting empty
values. Staging the settings prevents partially installed configuration.

## Consequences

- + Empty-value set, remove and config changes execute under the real owner.
- + Local, watched and forwarded changes update the writer's discard behavior.
- - Full requester routing remains RBD-013; broader epoch-loss/cancellation and
  provider qualification remains RBD-012. Global ConfigWatcher remains open.

## Alternatives

Alternatives: not recorded (OQ 123).

## Open questions

Complete the remaining matrices in
the inventory (doc not in the source snapshot).
Evidence: completeness audit (doc not in the source snapshot).
