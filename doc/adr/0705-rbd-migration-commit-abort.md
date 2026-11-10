<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0705 rustyrbd migration prepare/commit/abort: stock state machine, derived recovery, no extra record

Status: accepted
Date: 2026-11-09

## Context

Gap plan WP-6 (RBD-033/034/080/035): `rbd_migration_commit(_with_progress)`
and `rbd_migration_abort(_with_progress)` return `-EOPNOTSUPP`
(`crates/rbd-ffi/src/migration_api.rs` `commit_impl`/`abort_impl`); own
prepare writes both records but omits source unlink/MIGRATION trash, mirror,
group, snapshot structure and children stages. User rule 2026-11-08: stock
behaviour unless buggy or harmful. Contract and stock defects R1-R11:
migration-lifecycle.md (doc not in the source snapshot) sections
"Prepare persistent stages", "Terminal endpoint resolution", "Commit",
"Abort", "Reference defects". Stage IDs Q*/K*/B* below are that spec's.
Stock is resumable for prepare and most of abort, not for commit after K1
(R2) and not for abort after B10 (R3). rbd-ffi has no in-memory RADOS
harness (ADR 0700).

## Decision

- Own prepare, commit and abort write exactly stock's durable records and
  objects, in stock's stage order (Q0-Q9, K0-K5, B0-B13), except the
  deviations D1-D10. No deviation creates a durable state stock cannot
  produce.
- No durable recovery record beyond stock's (no extra omap key, object or
  trash entry). Every re-run derives its stage from: both migration
  records, header presence, the MIGRATION trash entry, directory and ID
  object mappings, the destination snapshot set (boundary present?), group,
  mirror records and the child-relink state. The crash tables below are the
  per-stage proof.
- Identity: endpoints are bound by pool, namespace and immutable ID taken
  from the records; names only start resolution. Every destructive stage
  re-reads both records first and stops (`-ESTALE`) if the pair no longer
  references each other or the state moved (concurrent terminal call).
- Invariants (tested at every crash point):
  - I1 Source data is written only by the abort revert (HEAD, full source
    snapshot context) and deleted only by commit K3.
  - I2 K3 runs only after K1, and K1 only with EXECUTED proof (destination
    state, or source state when invoked by source name: the source turns
    EXECUTED only after the copy finished).
  - I3 The destination is deleted only by abort B9, after a successful
    revert, or by D8 when the source is still PREPARING.
  - I4 Nothing is deleted from either side after K1 except by commit.

Deviations (each fixes a reference defect R*):

- D1 (R1) A failed revert stops abort with its errno; states stay ABORTING,
  nothing deleted; a re-run retries the revert.
- D2 (R3, R10) Name restore is idempotent: no trash entry and the name's
  ID object/directory entry already map to the source ID = done. A MIGRATION
  entry in MOVING (or NORMAL) whose source header has no migration record is
  an interrupted Q2: abort restores the name (no destination can exist yet).
- D3 (R4, R8 part) Abort reads the destination record whatever name was
  given. Captured mirroring comes from it; once the destination is gone,
  from the source record's `mirroring` flag. Mode = recorded destination
  mode; without it: journal if the image has JOURNALING, else snapshot.
- D4 (R9) Abort checks before its first write: a present destination header
  must carry a DST record naming the source; a record-less destination with
  source EXECUTED is a commit in progress: `-EINVAL`, no write.
- D5 (R2 frequency) Commit acquires source ownership (administrative open)
  and refuses foreign source watchers (`-EBUSY`) before K1; stock finds
  them in K3, after K1.
- D6 Commit restores destination mirroring right after K1 (stock: K5, after
  source deletion), so the captured mode is still in memory and a failure
  never strands it behind a deleted source.
- D7 (R2, R6) Commit resumes after K1: if the named image is an ordinary
  (non-migrating) image, search this pool's MIGRATION trash for an entry of
  the same name whose SRC record names this image (pool, ns, ID) with state
  EXECUTED, and continue at the first missing stage. An entry whose header
  object is absent (only K3 removes a MIGRATION-trashed header, after its
  trim) is finished by deleting the entry and the by-ID object map and
  journal objects. Name found only in trash with header absent: same, never
  a null handle. Destination mirroring not yet enabled (crash between K1
  and D6): restored from the source record per D3 (its flag means "a record
  existed", so an IMAGE-mode pool may get mirroring for a formerly
  disabled record; only in that window). Destination already enabled in
  any mode in that window counts as restored (the mode is a fallback guess).
- D8 (R5, R9 part) A prepare failure after Q3 runs own abort with the known
  destination ID. Abort with source PREPARING (proof that execute/commit
  never ran) and a destination that has no record removes that destination
  by ID (after the watcher veto) or, header absent, the ID object/directory
  entries bound to that ID; then restores the source. Source ABORTING with
  a record-less destination is ambiguous (R9): `-EINVAL`, no write (stock
  result); see OQ.
- D9 Revert runs iff snap_seqs is empty or the boundary destination snapshot
  exists. Own abort deletes destination snapshots only after a successful
  revert, so a missing boundary proves completion. Empty snap_seqs: a re-run
  copies destination HEAD from 0; objects already trimmed from the
  destination are absent and write nothing.
- D10 NULL or empty name `-EINVAL` (stock dereferences).

Ordering vs exclusive lock:

- Prepare: release own source lock; the MIGRATION trash move acquires it on
  its own handle and blocks requests, closed before name mutation
  (`trash_move_checked`). Destination: creator owns and blocks requests
  Q5-Q9.
- Commit: source ownership taken before K1 (D5), held through K3; no
  destination lock (stock); K1 notifies destination clients.
- Abort: source ownership B1 to end (stock); destination watcher veto B3
  before any write; destination ownership by the snapshot-removal and
  removal lifecycles (B7, B9).

Progress: stock semantics (spec "Terminal progress callbacks"), including
step offsets and ignored revert callback return. A skipped revert (D9)
reports no step-1 calls.

Group (R7) and the Q1-Q6 mirror window (R8) keep stock behaviour: no extra
record; documented loss.

Crash windows, native paired migration. "Own" = re-run of the same call by
this library; "stock" = classic librbd v21.2.0 re-run.

Prepare (recovery = abort):

| Crash after | Durable state | Own abort | Stock abort |
|---|---|---|---|
| Q1 | mirror disabled, nothing else | `-EINVAL` (not migrating); policy lost | same |
| Q2 part | MIGRATION entry, name partly/fully unlinked, no record | D2 restores name | `-EINVAL` stuck (R10) |
| Q3 | SRC PREPARING, no dst objects | B10-B13 | same |
| Q4 identity only | dst ID object/dir entry, no header | D8 removes them by ID, restores | same name `-EEXIST` stuck; else orphan identity |
| Q4/Q5 header | dst header without record | D8 removes dst, restores | writes source ABORTING, `-EINVAL` (R9) |
| Q6-Q9 | records PREPARING/PREPARED, partial group/children | full abort | full abort |

Commit:

| Crash after | Durable state | Own commit | Stock commit | Any abort |
|---|---|---|---|---|
| K0 | none | fresh | fresh | allowed |
| K1 (+D6) | dst ordinary; SRC EXECUTED in trash | D7 resume | `-EINVAL` (R2) | own `-EINVAL` (D4); stock R9 |
| K2/K3 header kept | source snapshots/data partly gone | D7 resume | `-EINVAL` | as above |
| K3 header gone | stale MIGRATION entry | D7 entry cleanup | crash by source name (R6), `-EINVAL` by dst name | own `-ENOENT` |
| K4 | done | `-EINVAL`/`-ENOENT` | same | same |

Abort:

| Crash after | Durable state | Own abort | Stock abort |
|---|---|---|---|
| B4 | ABORTING on one or both | repeat B4 on | same |
| B5 part | source HEAD partly reverted | re-revert (idempotent) | same |
| B6 part | children in states 2/3 | repair (spec relink back) | same |
| B7 part | dst snapshots partly gone | D9 skip or re-revert, continue | revert from missing boundary: OPEN, error ignored, continues |
| B8 | dst out of group | continue; group lost (R7) | same |
| B9 part | dst partly trimmed, header kept | D9, continue | as B7 |
| B9 | dst gone, source in trash | B10-B13, mirroring via D3 | B10-B13, IMAGE-mode mirroring lost by source name (R4) |
| B10 | name restored, entry gone | D2, continue | `-ENOENT` stuck (R3) |
| B12 | source ordinary | `-EINVAL`; mirroring lost if B13 missing | same |

Import-only: commit K0, K1, K5 and abort B2-B4, B7-B9 are each idempotent
by stock (`-ENOENT` tolerance, absent destination = success); D6/D7 do not
apply.

## Rationale

Stock's durable state already identifies every stage except the R9 state,
so an extra record buys nothing for own-vs-own and is invisible to classic
re-runs. Keeping K1 first preserves stock's abort latch: after K1 no abort
can reach the revert or delete the destination (I4). The deviations only
add tolerance, earlier checks or a stop on error; none changes the
successful outcome or creates a new durable state. Accepted trade-off:
classic re-runs stay as stuck as stock in R2/R3/R9/R10 states; own recovers
all but R9.

## Consequences

- + Commit/abort/prepare become resumable by own librbd at every crash
  point except R9; classic sees only stock-shaped state.
- + Abort cannot lose destination writes silently (D1).
- - R7 (group) and the R8 mirror window remain as in stock.
- - D7 searches MIGRATION trash only in the named image's pool; a
  cross-pool source after K1 needs its own name/pool.
- - Implementation needs a narrow metadata trait and an in-memory store
  for crash-point tests (S2), both in rustyrbd (sans-IO; the RADOS backend
  follows with the stage implementations).

## Alternatives

- Identity-bound commit recovery journal (archived `36d932805`): extra
  durable artifact classic never reads; stock state suffices.
- Commit deletes the source before K1: removes the abort latch; a classic
  abort after partial source deletion would revert into a trimmed source and
  delete the only complete copy.
- Destination header and record in one create op: does not cover
  stock-prepared migrations; source PREPARING already disambiguates (D8).
- Stock-exact including R1-R6: loses data (R1), strands storage (R2/R3),
  crashes clients (R5/R6).

## Implementation steps

Each step: own branch, affected-crate tests (`lab/remote-test.sh`,
`cargo test -p rustyrbd` / `-p rbd-ffi`), clippy, reverse-dependents' tests
for public changes, one commit. Native crash-point tests use the S2 fault
plan: run the operation with "stop after mutation k" for every k, then
re-run own and assert the invariants and convergence to the table's end
state. S6 is independent of S7-S9 (classic-prepared fixtures cover them).

- S1 `crates/rustyrbd/src/migration_terminal.rs` (new, sans-IO): observed
  state -> next stage list or refusal errno for prepare compensation,
  commit, abort (D2, D4, D7, D8, D9 rules). Tests: one per row of the three
  crash tables (own column) plus refusals.
- S2 `crates/rustyrbd/src/migration_store.rs` (new): `MigrationStore` trait
  (records, trash, directory/ID object, group, mirror, children, snapshot
  list/remove, admin removal, revert as opaque calls); the in-memory test
  store `crates/rustyrbd/src/migration_mem.rs` (feature `migration-testkit`,
  optional dependency `cls` with feature `mem`, as ADR 0700) executes the
  real `cls_rbd` handlers with a fault plan. The `RadosContextPair`
  implementation follows with the stage implementations. Tests: store parity
  smoke per method.
- S3 `metadata_lifecycle.rs` administrative open (accepts SRC and ABORTING
  records, never loads migration fallback); `image_api/remove.rs` admin
  removal variant with `from_trash`. Tests: admin open of SRC/ABORTING
  headers, ordinary open still `-EROFS`; removal of a MIGRATING image only
  via admin.
- S4 `migration_api.rs` endpoint resolution (spec steps 1-5, D7 search,
  D10, no null handle) used by status/execute/commit/abort. Tests on the S2
  store: every resolution branch and errno.
- S5 Import-only commit and abort plus progress stepping
  (`migration_api.rs`). Crash-point tests at every mutation; external
  source never written.
- S6a Prepare Q0-Q3 and compensation: watcher veto, mirror capture/disable
  (`image_api/mirror_image_enable.rs`), MIGRATION trash move
  (`image_api/trash_write.rs` `trash_move_checked` with source MIGRATION:
  group allowed), SRC record before destination creation, default
  destination name = source name. Crash-point tests Q1-Q3.
- S6b Prepare Q4-Q8: snapshot structure copy with snap_seqs and per-snapshot
  size/parent overlap (spec "Parent and overlap mapping"), metadata copy,
  DST record, group move, PREPARED source then destination; D8 on failure.
- S6c Children relink both directions with repair (spec "Relink back"),
  shared by prepare Q9 and abort B6; new `image_api/migration_children.rs`.
  Tests: states 1-4, `-ESTALE`, clone format 1 and 2.
- S7 Paired commit: D5, K1, D6, K2, K3 (S3 admin removal from trash), K4;
  D7 resume. Crash-point tests every mutation; I1-I4.
- S8 Paired abort part 1: B1-B5 with D1, D4, D9; revert copier (HEAD delta
  from boundary, source snapshot context; reuse `migration_history.rs` /
  `clone_copy_api.rs` object copy). Pure tests of boundary and snapshot
  context; crash-point ordering tests. Landed as: B1/B3 as one ownership and
  watcher fence whose probe owner is released before the first mutation (the
  revert writer and B9's removal lifecycle take their own), B4, B5 with the
  revert driven by the existing diff machinery: the destination HEAD view is
  walked against the boundary snapshot (beginning of time when the record has
  no snap map) without inherited parent data, a present extent is read in
  object-sized pieces and written through a `WritePurpose::MigrationSource`
  writer so every write carries the source's own snap context, and an extent
  deleted after the boundary is discarded through the writer's sparse path
  (never written as zeros; without a boundary absent extents write nothing).
  `migration_revert.rs` (rustyrbd) holds the pure boundary and write-context
  decisions.
- S9 Paired abort part 2: B6-B13 with D2, D3, D8. Crash-point tests every
  mutation; source restored with name, group, mirror. B6 relinks through the
  pinned `child_detach`/`parent_attach`/`child_attach` primitives; the
  effective parent is the image-wide `parent_get` spec whenever HEAD or any
  child snapshot still reports an overlap (a HEAD detach clears only the HEAD
  overlap), so a detached-HEAD child is relinked instead of refused. B8/B11
  reuse the group attach/remove encoders; B10 auto-enables JOURNAL-mode image
  mirroring best-effort for a JOURNALING source in a POOL-mode pool (no
  feature change), and `mirror_enable` is idempotent (same mode = no write,
  another mode = `-EINVAL`) so B10 and B13 compose. The public paired abort
  entry points are enabled.
- S10 Live cells (`lab/rustyrbd/review-regression-gate.rs`, one repeat
  each, zero `WARNING TIMEOUT`, cleanup verified) and a stage stop hook
  (`RBD_MIGRATION_STOP_AFTER=<stage>`, cargo feature `lab-diagnostics`,
  absent in prod builds); docs: `ffi-migration.md` deviations,
  `status-rustyrbd.md`, open-issues rows.

Live cells (S10), each with nonidentical source snapshot/HEAD data, a
destination write and a whole-object discard after prepare, byte compare of
every snapshot and HEAD by classic and own:

1. own prepare -> own execute -> own commit; classic reads destination;
   source and MIGRATION entry gone.
2. own prepare -> own execute -> own abort; source HEAD = destination HEAD,
   source snapshots unchanged, name restored.
3. own prepare (no execute) -> destination write -> own abort.
4. classic prepare -> own execute -> own commit; 5. classic prepare -> own
   abort; 6. own prepare -> classic execute -> classic commit; 7. own
   prepare -> classic abort.
8. Stop matrix: own stops after each of Q2-Q9, K1-K4, B4-B12; resume with
   own and with classic; assert the table's columns (classic stuck cases:
   the documented errno, then own resumes). Includes the OPEN classic
   revert after B7.
9. Same-name destination, different name, cross-pool, namespace.
10. Children: clone child (formats 1 and 2) of a source snapshot: relinked
    by prepare, back by abort, kept by commit; interrupted relink repaired.
11. Group membership moved and restored.
12. Snapshot-mode mirroring in an IMAGE-mode pool (journal mode after ADR
    0700): restored by commit and by abort, abort invoked by both names.
13. Veto: destination opened by classic -> abort `-EBUSY`, no state change;
    source watcher -> own commit `-EBUSY` before K1.
14. Import-only commit and abort; external source unchanged.

## Open questions

- OQ 177: recovery of the R9 state (source ABORTING, record-less
  destination) left by a classic abort: keep refusing like stock, or offer
  an explicit operator command that keeps the destination (finish commit)
  or the source (finish abort).
