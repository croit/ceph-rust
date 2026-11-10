<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0577 Group snapshot create and rollback coordination

Status: accepted
Date: 2026-10-25

## Context

Member snapshots/removal, mapless rollback, quiesce and nested GENERAL blocks
exist, but public group create/rollback still refused every valid group.
The pinned lifecycle (doc not in the source snapshot)
and lock boundary (doc not in the source snapshot) require
all-member phases and retained exclusion, not serial per-image transactions.

## Decision

An owned temporary group retains all member handles, optional GENERAL Busy
blocks and paired quiesce senders. CREATE persists INCOMPLETE, opens every
member in its inherited namespace, sends all group quiesce before acquiring,
blocks all enabled locks, submits every full acquisition through the existing
recovery engine, and joins every completion. Plain images skip lock work.
Only then are all member mutations submitted. Successful member publication
runs independently outside writer mutexes using private owned update ioctxs.
COMPLETE with exact IDs follows all successful member completions; UNQUIESCE
fan-out follows before close. Blocks outlive actual handle shutdown.

Failed create unquiesces before member cleanup and record removal, retaining
the original negative result and logging cleanup failures. A pool-context
failure after record creation leaves INCOMPLETE as specified. ROLLBACK checks
COMPLETE and exact ordered ATTACHED membership, uses the same all-lock barrier
and full durable per-member rollback, tolerates missing snapshots, and sends
no group quiesce. Its borrowed progress callback may run concurrently per
member without aggregation; all submitted members drain before return.

Public listing reads creation-order metadata first, then snapshots. Sort only
when every snapshot has an order; otherwise retain the entire ID order.
Both result versions resolve all member names before checking capacity. Names
are byte-preserving; no UTF-8 substitution is applied to opaque identifiers.

The shared header target and reverse-directory query preserve opaque nonempty
ID bytes, including punctuation and slash. Creation-side alphanumeric checks
do not apply to existing-ID lookup. NUL and existing local target bounds stay
validated. The missing-member live assertion remains ENOENT.

## Rationale

The existing acquisition cohorts already own cancellation/result lifetime;
exposing nonblocking submission avoids another waiting thread per member.
Private publication contexts avoid borrowing non-Send image handles and avoid
serial notification completion blocking another member's publication.
Quiesce sender transfer is exclusive, including its paired cleanup; no ioctx
configuration or borrowed provider buffer is concurrently shared.

## Consequences

- + Real snapshots, maps, DATA SnapContext and rollback replace metadata-only
  success/refusal; member effects are not falsely described as group atomicity.
- + All results are joined and last negative follows member order.
- - Administrative fan-out uses scoped workers; broader resource/fault and
  performance qualification remains required.
- - Parented/striped rollback and wider lifecycle gaps remain independent work.

## Alternatives

- Acquire/mutate/release each member in turn: loses the group boundary.
- Install Standard manual policy: changes unrelated DATA acquisition policy.
- Serial quiesce: cannot deliver all callbacks before the application completes.
- Serial borrowed-handle publication: couples otherwise independent callbacks.

## Open questions

Remaining ID-open ordering/empty-ID/trash fallback and backend-limit error
contracts require independent completion; raw head observation is not public
open admission. Test evidence (commit hashes, cell results): librbd completeness, ADR evidence (doc not in the source snapshot). Qualification is bounded to the exercised unparented/unstriped
profiles0/4/61 and classic librados provider; wider fault/resource/own-provider,
parent/stripe, QEMU/platform/release and measured performance remain open.
No full-behavior or release-completeness claim.
