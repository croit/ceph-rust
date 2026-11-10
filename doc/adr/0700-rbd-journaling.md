<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0700 rustyrbd JOURNALING: sans-IO journal core, serial journaled writes, sealed recovery

Status: proposed
Date: 2026-11-08

## Context

User decision 2026-11-08: librustyrbd is a drop-in librbd and must support
JOURNALING images (writable open, write path, replay, lock hand-off, feature
toggles, create). Today `WriterCapabilities::from_features` refuses them with
`-EOPNOTSUPP`. Contract: `doc/spec/rustyrbd/ffi-journal-io.md`,
`doc/spec/cls_journal.md`, `create-lifecycle.md`. Journal helpers exist in
three places (rustyrbd codecs, `mirror_image_enable.rs`,
`mirror_image_promote.rs`); rbd-ffi has no in-memory RADOS harness.

## Decision

- The journal engine is sans-IO in `crates/rustyrbd` (`journal_*` modules):
  metadata codecs, writer, streaming player, recovery driver. It talks to
  storage only through a `JournalBackend` trait and to the image only through
  a `ReplayTarget` trait. rbd-ffi supplies the RADOS backend and implements
  `ReplayTarget` on `FlatImageWriter`. Every journal codec and cls call
  encoder in rbd-ffi mirror modules moves to this engine (one implementation).
- Native tests run the engine against `MemJournalBackend`, which executes the
  real `cls::journal` handlers (dev-dependency `cls` with feature `mem`), plus
  an in-memory image; a shared fault plan stops every mutation after the k-th
  one, which models a process crash at every mutation boundary.
- Ordering is a type rule: HEAD data dispatch functions take a `DataGrant`
  that only the journal admission can produce. With JOURNALING active the
  grant exists only after every entry of the request, and every earlier
  entry, is durably appended.
- Journaled DATA requests run on the serial writer path; the pipelined permit
  is not granted while a journal is open (v1). Pipelined journaled appends are
  a later, measured step.
- Commit positions advance in entry order only. A failed data write stops
  commit advancement until the next recovery. Positions are persisted every
  `rbd_journal_commit_age`, at op and compare-and-write barriers, before trim,
  and before lock release; never on a plain user flush.
- Compare-and-write and every journaled image operation are barriers: prior
  entries complete and positions persist before the event is appended; the
  operation's own position persists before it completes.
- Recovery replays the consecutive-TID prefix of the current tag, then seals:
  positions are set to the last record present in each splay stream, so
  records after a TID gap (never safe, never acked) are abandoned, and new
  appends continue at max seen TID + 1 in the same tag. A mid-stream gap
  (record tid != last+1) fails recovery with `-ENOMSG` to match stock
  (SPEC-CHECK 1); the seal only ever sees a gap at the stream tail because the
  writer is serial. The data path never creates tags.
- Recovery runs inside the owner acquisition (`try_owner_map_geometry`)
  before any DATA admission; failure releases ownership and fails the request
  loudly. Release always goes through one function that closes the journal
  (persist positions) before leases are released.
- Admin operation events are re-executed at their finish boundary during
  recovery with per-operation idempotency; an operation kind without replay
  support fails recovery (`-EOPNOTSUPP`), never skips.
- JOURNALING with a loaded encryption format stays refused (spec: unresolved
  recovery policy): enable with a cryptor and encryption load/format on a
  JOURNALING image return `-EOPNOTSUPP` / `-ENOTSUP`.
- Amendment 1 (2026-11-09, WP-9 OPEN-1 variant R): the refusal is the
  documented deviation, not a parity gap (live-measured 2026-11-10: stock
  enable returns 0 and the journal object contains the plaintext). Stock lets a loaded handle enable
  JOURNALING (and a peer's enable reach it through refresh) and then stores
  caller plaintext in the journal pool; a crash replays that plaintext
  unencrypted over the LUKS header. We keep `-EOPNOTSUPP` for every encrypted
  DATA path (one capability check per public DATA entry point) and, in
  addition, refuse a recovery that would apply a DATA event without a loaded
  format when the image's raw start carries the RBD clone magic
  (`-EOPNOTSUPP`, `stage=encrypted-replay`, nothing written, ownership
  released). Standard LUKS magic does not refuse: an unencrypted image whose
  guest encrypts the whole disk (dm-crypt on the mapped device) starts with
  it too, and refusing its replay would leave a common plaintext image
  unwritable after a crash; such journals replay like stock, so a non-clone
  librbd-LUKS image with JOURNALING (only creatable by a stock client) keeps
  stock's replay hazard. Op-only journals are unaffected. Replay clips DATA events to the
  DATA-area size (raw size minus the loaded data offset).
- Failed JOURNALING enable after journal creation removes the journal it
  created (deviation from the pinned residue; ADR 0256 allows safer fixes).

## Rationale

Sans-IO plus the real cls handlers gives an exhaustive crash matrix without a
fake librados, and keeps durability ordering in one tested crate. Serial v1
avoids concurrent append futures, the main source of ordering bugs; journaled
throughput is bounded by the append round trip anyway. Barriers for CAW and
ops make our own journals replay-safe for conditional and non-absolute
events (a replayed CAW never sees later writes). Sealing past a gap is the
only TID-continuation rule that cannot collide with orphan records.

## Consequences

- + One journal implementation; mirror promote/enable reuse it.
- + Every crash point is a native test.
- - Journaled writes are serial per image until the pipelined step lands.
- - One extra `client_commit` per CAW and per admin op.
- - `cls` (LGPL) becomes a dev-dependency of an MPL crate (tests only, not
    distributed).

## Alternatives

- Fake librados for rbd-ffi integration tests: large, duplicates cls
  semantics; rejected.
- New tag per lock acquisition (stock allocates one local tag on every
  exclusive-lock acquisition, J1 resolved): rejected to keep the data path
  tag-free; our player must still replay stock tag transitions.
- Persist commit on every user flush: one extra RADOS op per flush with no
  durability gain; rejected.

## Open questions

- J1..J14 resolved 2026-11-08 from the pinned 21.2.0 reference; answers in
  `doc/spec/rustyrbd/ffi-journal-io.md` ("Resolved reference questions
  (J1–J14)" and "Reference check (SPEC-CHECK)"). J8 decided 2026-11-08 (user rule: like stock unless buggy/harmful): foreign leftover journal -> -EEXIST; only our own failed enable is rolled back.
  Two SPEC-CHECK deviations were folded back into the spec: stock fails
  `-ENOMSG` on a same-tag TID gap (SPEC-CHECK 1) and re-executes a
  start-without-finish op idempotently (SPEC-CHECK 2).
