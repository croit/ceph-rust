<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0569 Writer watch recovery separates registration and write admission

Status: accepted
Date: 2026-10-25

## Context

A lost provider watch previously permanently fenced a published writer.
Replacing its registration alone does not restore the server-side lock cookie.
Rebuild scans retain serial write tickets outside the writer mutex. Recovery
must not wait for those tickets while holding that mutex or an operation's pin.
Pinned contracts: image-watch-lifetime.md and managed-lock-handoff.md.

## Decision

Public and temporary writable image contexts use a shared serial owner and an independently owned
recovery coordinator. The provider callback retains only a weak coordinator
hook. Healthy writers gain no recovery thread. A recovery worker owns its
provider actions and settles its lifecycle pin on completion or failure.

The activity mutex fences new write tickets before recovery starts. Entered
calls retain operation pins while waiting; tickets are issued only after
admission reopens. Close seals admission, cancels recovery fences and joins
active recovery before draining operations and consuming the writer owner.

Recovery first restores the watch with its stable callback/subscription state.
It tags a new internal invalidation epoch and queues the synthetic local update
without an ACK. Transport health and write admission remain distinct.
Metadata queries during loss use a coherent read-only header observation and
do not wait for write authority or supply authority to DATA operations.
Initial open observes metadata before registration; successful registration
with a raced error does not fail open. Pre-registration metadata forces a new
healthy watched refresh at the first DATA admission.

Temporary copy/deep-copy/migration contexts bind the same coordinator and drain
it at close. Copy holds image lifetime pins across the request, but admits each
write batch separately and releases its ticket/mutex before user progress.
Snapshot commit plus notification and metadata publication retain their batch
fence. Recovery can run during progress without waiting on that callback's own
write ticket. A primary operation error wins over a later close error.

An existing owner uses atomic lock.set_cookie with its old authenticated
identity. Local wire identity changes only after success; successful recovery
publishes a fresh ACQUIRED hint and retains existing map leases. The specified
unchanged-cookie/blocklist-policy exception still announces successful recovery.

Every cookie failure enters full fallback. Wait outside the writer mutex for
the captured durable write prefix, drain outgoing announcements without closing
the notifier, release map before header, then acquire/refresh/load map before
admitting new writes. No client writeback cache exists: completed write tickets
already represent durable DATA completion. Read-only DATA operations do not
hold a transferred write lease. Unresolved cleanup errors remain errors.

Pending fallback restoration survives further watch errors. A new delivered
error restarts nonterminal failed recovery; it cannot be discarded simply
because the preceding fallback failed. Local cancellation is a typed outcome,
separate from Ceph's fixed blocklist errno108. A failed asynchronous-close
submission can resume its cancelled recovery without treating local ESHUTDOWN
as a permanent remote blocklist.

Committed close also seals image-local callback admission. Provisional async
close can still fail and does not seal that registry. Accepted callbacks drain
before destruction. Long rebuild scans test invalidation/close between objects
and after user progress; stale plans cannot indefinitely hold fallback drain.

## Rationale

Shared ownership permits recovery independent of future application I/O while
weak hooks prevent cycles. Separating admission from provider identity avoids
mistaking a healthy replacement watch for restored ownership. Existing serial
tickets give a concrete durability fence without waiting behind a newly issued
user ticket. Stable callback state preserves accepted argument ownership.

## Consequences

- + In-place recovery preserves valid map leases and accepted DATA operations.
- + Fallback restores real ownership rather than replacing local cookie text.
- + Recovery, blocked admission and close have explicit lifetime ownership.
- - Simultaneous failures can create multiple transient recovery workers.
- - Initial-open and temporary-context integration require live fault coverage;
  implementation alone does not qualify recovery across every provider failure.
- - Acquisition policies inherit the current writer's uncontended-acquire
  limitation; full managed handoff and fault qualification remain required.

## Alternatives

- Wait for recovery while holding a writer mutex/ticket: rejected because an
  accepted scan/progress callback can own the completion required by recovery.
- Declare ready after WATCH success: rejected because lock identity is separate.
- Ignore failed cookie replacement: rejected because ownership would be stale.

## Open questions

- Qualify initial-open and temporary copy/migration recovery races.
- Qualify actual provider failures, callback/progress races and outage resources.
- Complete managed peer acquisition and the remaining configuration policies.
