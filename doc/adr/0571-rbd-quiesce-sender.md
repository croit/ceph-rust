<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0571 RBD snapshot quiesce sender lifetime

Status: accepted
Date: 2026-10-25

## Context

Pinned snapshot creation requires a broadcast quiesce transaction before
suspending writes. Application callbacks may flush the same image. The
previous create2 adapter refused flags0/2, while ordinary create bypassed
quiesce. The pinned protocol is specified in
admin-owner-forwarding (doc not in the source snapshot).

## Decision

Both public create APIs use the same snapshot/quiesce path.
The sender owns a private metadata context, stable full request identity,
configured attempts and provider reply-buffer ownership. The selected local
executor prepares ownership before quiesce and loads its effective config;
invalid winning overrides fall back to global. Single-key metadata queries
avoid scanning every configuration entry.
Only provider timeout after outer decoding retransmits the same identity.
Progress follows outer decoding and precedes retry/inner-response selection;
its return is ignored. Null progress safely means no callback, an intentional
extension over the pinned C wrapper's unsafe null invocation.
Quiesce runs with an image lifetime pin and without a serial write ticket
or writer mutex. Snapshot mutation obtains its write turn only afterward.
An issued transaction sends unquiesce on every return path, after releasing
its write turn and before releasing the lifetime pin. Cleanup errors are
logged and preserve the snapshot result. UNQUIESCE delivery completes before
the outer local/HeaderUpdate publication.

## Rationale

The lifetime pin protects provider/image storage without preventing callbacks
from flushing. Reverse local destruction order makes error exits retain the
same release ordering. The sender shares the lock request transport's owned
reply/free boundary while preserving their distinct response selection.

## Consequences

- + Ordinary create and create2 no longer silently differ on quiesce.
- + Negative callbacks, ignored errors and failed snapshot mutations release
  successful participants through the same transaction identity.
- - Null progress has explicitly safer behavior than the pinned C wrapper.
- - General administrative forwarding, selected-snapshot creation, group
  coordination and wider fault qualification remain separate open work.

## Alternatives

- Holding the serial write ticket during notify: callback flush can deadlock.
- Reusing the single-owner ACK selector: quiesce aggregates every watcher.
