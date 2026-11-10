<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0701 MDS rstat: hierarchical accounted totals and a background fold

Status: accepted
Date: 2026-11-08
Amends: 0669

## Context

Every MDS mutation with a dir delta (create, unlink, mkdir, rename, size flush) walked
owner_link to ino 1 and wrote F of every ancestor in its own record. F(1) was claimed
exclusively by each of them, so mutations in independent directories serialized on one
key and one shard (OQ 147), and every op crossed to root's core in M3. Stock rstat is
lazy (spec namespace s5A): level 1 in the op's journal event, higher levels later.
Design: design/cephfs-mds/rstat-propagation.md option C.

## Decision

- An op edits only its direct parent: F(P).pending (signed delta, newest ctime) in its
  own record, and puts Q(P) when P becomes dirty. No ancestor is read or written.
- Recursive totals live in key A(D, NOSNAP) at home(D): `rstat` (folded), `accounted`
  (already added to the parent), `version`. Not inside I (no I re-encode per fold, no
  read-dependency coupling of ancestor I reads).
- A per-executor fold job moves F.pending into A and `rstat - accounted` into the
  parent's A, walking to the root in one APPLY record per step (at most
  max(min(192, rows) / 3, 2) nodes; a cut node stays dirty and is due again at once).
- Fold interval T = 1 s after a dir becomes dirty (stock `mds_dirstat_min_interval`).
  Everything is due at once when the dirty queue is >= 3/4 full. Log pressure does
  not trigger a fold: F and Q are written back like any image, and an early fold
  record only adds log bytes. The fold runs only in Serving mode, takes no claims
  and parks on loads without writing.
- Dirty set: FIFO plus hash set, capacity = plan row limit; Q mirrors it exactly.
  A request whose plan would overflow it waits (`Wait::Fold`) until a fold record
  frees room; the fold's own record always fits. Startup rebuilds the set from the Q
  rows of the catalog scan and replayed Q images.
- Claims: A and Q edits are shared; F is exclusive only for the dir whose emptiness
  the plan checked (rmdir, rename over a dir); every other F edit is shared.
- rmdir moves held(x) = accounted(x) + 1 subdir out of the parent and deletes A(x),
  Q(x); a dir rename moves held(x) between parents; unfolded state of x stays with x.
  No rename rstat barrier, no `path_generation`.
- Reported totals: A.rstat + F.pending (ctime max), rsubdirs + 1 for the dir itself.
  Dir version = 2 * (I.version + F.version + A.version), so rstat-only changes bump it
  and clients apply them (spec s5A).
- Store format revision 5 (spec store-format s4.2); key A because revision 4 took N
  for session ino ranges. Revisions 3 and 4 upgrade in place: the m.super revision
  moves to 5 at open (cmpext-guarded write_full + readback); F env 1 reads as
  A = {R, R, 0} until its next write or fold writes A and F env 2.
- Damage: a negative A counter or an overflow in the fold is `HEALTH ERROR` +
  invariant error, as for other namespace damage.

## Rationale

Removes the only key every mutation shared (OQ 147) and the per-op ancestor walk;
matches the stock lag contract (direct-child changes fresh, deeper levels lazy). Cost
accepted: after a cross-dir rename, an ancestor holding only one parent's side over- or
under-counts by held(x) until the next fold (<= T); the conservation identity
`T(D) = A(D).rstat + F(D).pending + sum_x (T(x) - A(x).accounted)` holds at every
record boundary. Waiting on a full dirty queue instead of dropping and rescanning keeps
one code path (no rescan) at the cost of rare back-pressure.

## Consequences

- + Independent directories share no exclusively claimed key; ops write fewer images.
- + Crash safety needs no new replay logic: pending is in the op's record, a fold is
  one atomic APPLY, Q rebuilds the dirty set.
- - `ceph.dir.r*` of deeper levels lag up to T (plus record cuts on deep trees).
- - One more key per non-empty dir (A) and a transient Q per dirty dir.
- Per-op cost (fold records, steps, reads): doc/perf/mds-rstat-fold.md.
- - Quota pushes and the MKSNAP fold barrier have hook points but no producers yet
  (no quota or snapshot feature in M0).

## Alternatives

- Keep the ancestor walk with shared F claims: still d images per op and every op on
  root's core in M3.
- Per-core outbox batches per ancestor (old features.md s3): needed the rename barrier
  and `path_generation`; more state for the same lag.
- Rewrite revision 3/4 stores offline or refuse them: rejected, stores upgrade in place.

## Open questions

- M1 quota: push MClientQuota on fold/op changes of a quota dir's A or pending (hook:
  `fold.rs` node write, `ops.rs` `put_frag`).
- M4: MKSNAP drains the realm's dirty dirs before the snapid takes effect.
