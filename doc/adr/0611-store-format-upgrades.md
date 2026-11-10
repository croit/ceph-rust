<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0611 Store format upgrades: every supported older format is upgraded in place, never re-deployed

Status: proposed
Date: 2026-10-27
Amends: 0021 (superblock, feature bits, "no in-place upgrade" rule of b88a52244d), 0610 (adds the tree-omap -> LSM upgrade step)

## Context

A current build refuses an older store: `superblock: Corrupt("unsupported store format: version 1 features 0x5dbf (this
build: version 2 features 0xfdfff); there is no in-place upgrade: re-mkfs this OSD")` (`layout::read_super`), and
`layout::check_required` refuses any store lacking a bit of `FEATURES_REQUIRED` (`StoreCfg::shard.require_current`, set by
`nvmestore`). b88a52244d (2026-10-16) removed the earlier upgrade code (`layout::upgrade_elastic`, `upgrade_meta`,
`croit-flashstore-tool upgrade`, `auto_upgrade`). User decision 2026-10-27: croit-flashstore-osd upgrades its on-disk format in place;
re-mkfs / rolling re-deploy is never an upgrade path for a supported format. Design: the store records an on-disk format number plus a minimum-compatible number; a newer daemon mounts older formats and
converts them, cheap conversions run at mount ("quick fix on mount"), long ones via the offline fsck/repair tool, and an
older daemon refuses a store whose minimum-compatible number is above its own.

Git evidence (format history, details: doc/perf/adr-measurements-moved-20261028.md): the default `mkfs` wrote `FORMAT_VERSION` 1 until 2026-10-22, so version 1 is a supported format; v1 -> v2 is a superblock-only step; feature bit 0x10000 is interpreted per format version (never read a v1 store's 0x10000 as `delta_relog`); stores older than `FEATURES_REQUIRED` need one upgrade step per missing bit.

## Decision

Versioning model (superblock):
- The superblock carries `version` (u32) and three feature sets, ext4 style: `compat` (an older build may mount
  read-write and ignore the bit), `ro_compat` (an older build may only mount read-only, e.g. fsck/export), `incompat` (an
  older build refuses). Today's single `features` word becomes `incompat`; `compat` / `ro_compat` are new fields, added
  by the v2 -> v3 superblock step. A build refuses only on unknown `incompat` bits (or unknown `ro_compat` for a
  read-write mount) or a `version` above its own.
- Feature bits are never reused. A retired bit stays reserved forever (`FEATURES_RETIRED`); the version-1 decoder maps
  0x10000 to retired `comp_view` before any v2 meaning applies.
- `version` changes only when a record or structure is reinterpreted without a bit (as in v1 -> v2); new structures get
  a bit.

Support window:
- Supported = every (version, incompat set) any default `mkfs` of `main` or a `v*` branch wrote since 3c9821c511
  (2026-10-09), plus every combination reached by runtime-sticky bits (`expand`, `compression`, `dedup`). Default-off
  experimental bits (today `FEAT_OMAP_LSM`, `FEAT_CHUNKED` under the `elastic` lab feature) may change format freely
  until they become default; from the commit that makes a bit default, every older supported format needs an upgrade
  step to it and the experimental history before that commit is not supported.
- A format leaves the window only by an ADR amendment naming the last build that upgrades it; that build stays an
  upgrade hop ("upgrade via N-1"), never re-mkfs.

Upgrade registry (`store::upgrade`, one module):
- One entry per step: `from` predicate (version + bits), `to` effect, class `quick` or `offline`, `fn migrate(io)`, and a
  fixture test. Steps are ordered; the planner applies the chain from the mounted format to the build's format.
- `quick` = bounded work independent of data size (superblock rewrite, setting a bit whose old state the new code reads,
  writing an empty structure). Runs at mount, before WAL replay output is applied, without operator action.
- `offline` = proportional to data (rewrites trees, moves omap). Runs only via `croit-flashstore-tool upgrade <dev>` (store not
  mounted), with progress lines and `--format plain|json|json-pretty` (`jsonl` progress stream), stable exit codes.
- Crash safety: every step is idempotent and ordered so that each durable write leaves the store in either the old or
  the new format (or a documented intermediate the next mount resumes from, recorded as an `upgrading` incompat bit +
  step id in the superblock). The superblock flip is the commit point, copy 0 then copy 1, healed by `heal_super`.
- Before a step that sets a new `incompat` bit the WAL is replayed and checkpointed under the old format, so no old-format
  WAL record is ever read under new rules.

Layout reorganization (offline steps may change the on-disk layout, not only records):
- Every offline run starts by draining the WAL: replay, write everything to its final place, checkpoint, WAL empty. No
  step converts WAL records; a WAL record format change (e.g. the 0610 manifest record of OQ 115) needs only "drain
  under old rules, write new-format WAL header".
- Allowed layout changes: compact/defragment data and metadata extents to free contiguous space; create, grow, shrink,
  move or remove metadata areas (WAL region, manifest ring, meta tree areas, new per-shard structures); rewrite trees
  in a new layout.
- Moves are copy-forward: write the new copy into free space, commit the new location (sys txn / superblock flip),
  then free the old extents. A relocation cursor in the superblock (`upgrading` + step id + cursor) makes every move
  crash-resumable. Areas that must sit at fixed offsets are freed first by relocating their current occupants.
- Space check before the first write: the planner computes the free space each step needs (largest move + new areas)
  and refuses with the exact shortfall when it is missing (exit code documented); no partial start.
- The same layout code is the store's offline maintenance: `croit-flashstore-tool upgrade --dev <dev> --reorg` runs drain +
  defragment (+ area resize when requested) on a current-format store without a version change.

Mount behaviour (OSD start):
- Current format: mount.
- Older format with only `quick` steps pending: log `store upgrade: <from> -> <to> (steps ...)` and run them, then mount.
- An `offline` step pending: refuse with exit code 78 (`EX_CONFIG`, documented) and the exact command
  `croit-flashstore-tool upgrade --dev <dev> --osd-id <id>`; the OSD never runs a long conversion in the start path.
- Newer format (unknown incompat bit, version above own): refuse loudly, exit code 78, message names the bits/version and
  "downgrade not possible after <feature> was enabled".

Downgrade:
- Not supported once an `incompat` bit unknown to the older build is set or `version` was raised: the older build
  refuses (never misreads). Quick steps are therefore also one-way. Operators who need a rollback window keep the old
  binary from upgrading by not starting the new one; `croit-flashstore-tool upgrade --dry-run` shows what would be set.
- `compat` bits never block an older build; new optional structures should prefer `compat` / `ro_compat` where an older
  build stays correct.

fsck:
- `fsck` reads every supported format (via the same planner, without writing), reports `format`, `pending_upgrades`
  (with class) in its output, and passes on an un-upgraded supported store. `fsck --repair` does not upgrade.

Experimental -> default:
- One commit sets the mkfs default, adds the bit to `FEATURES_REQUIRED` (now "required after upgrade") and adds the
  upgrade step from the previous default format, with fixture + crash-matrix test. Without the step the default flip is
  not merged.

Concrete steps (first registry content):
- S1 `v1 -> v2` (quick): superblock rewrite `version = 2`, retire 0x10000 (`comp_view`), keep every other bit. Valid
  because the v2 reader reads all v1 records (Context).
- S2 `+omap_runs` (quick): requires `omap_counters`; set bit after replay + checkpoint; old WAL holds no run records,
  plain root slot form stays valid (form 2 only written when the floor differs).
- S3 `+omap_blind` (quick): set bit after replay + checkpoint (only adds WAL tag 7).
- S4 `+delta_relog` (quick, pending verification): set bit; segments written by fold cleaning must be valid inputs of a
  relog checkpoint. Gate: fixture with fold-cleaned segments mounts and relogs. If not, the step becomes `offline`.
- S5 pre-2026-10-16 conversions (`elastic_meta`, meta image) restored from b88a52244d^ as `offline` steps, only for
  formats a default build wrote (git per-bit default dates checked in the implementing commit).
- S6 `+compat/ro_compat` fields (v2 -> v3, quick): superblock gains the two words; first step to use them.
- `+omap_uncounted`, `+omap_tombs` (quick, adr 0647-omap-blind-removals; set together by the mount like `log_dups`, not
  registry entries): durable before the mount writes anything, ahead of replay (this build reads the earlier build's WAL
  as written; from its first write on, the earlier build's counters are stale and its runs may hold removals); after
  replay one range delete per shard removes the `c` records. Fixture + crash matrix:
  `services/osd/store/tests/omap_upgrade.rs`.
- S7 tree omap -> `FEAT_OMAP_LSM` (adr 0610), required when 0610 becomes the default: `offline`, per shard:
  (1) replay + checkpoint under the tree format; (2) set incompat `upgrading` + step id; (3) stream every object's omap
  keys in `(object id, key)` order straight from the tree leaves into sorted runs (same writer as the 0610 flush, no
  memtable), crash-resumable at a recorded `(object id, key)` cursor in the shard's root slot; runs are committed by
  manifest records like flushes; (4) one sys txn per batch of objects deletes their tree omap records (header stays a
  tree record, 0610) and advances the cursor; (5) when the cursor reaches the end: set `omap_lsm`, clear `upgrading` and
  the omap counter bits (0610 is counterless), superblock flip. Reads during the offline run are none (unmounted);
  a crash anywhere resumes from the cursor; before (5) the store mounts nowhere but `croit-flashstore-tool upgrade` (refusal
  names the command). Duration ~ omap bytes / device write rate; progress = cursor share per shard.

Tests (required per step):
- Fixture images produced by committed test code from the old writer configuration (or tiny committed binary images
  when the old writer no longer exists in tree, e.g. v1 + `comp_view` with `EXT_VIEW` records, cut from a build at
  51c2ce56bd^), mounted by the new build, fsck clean, content compared.
- Sim crash matrix: crash at every IO of the step; every recovery mounts as old-or-new (or resumes), fsck clean.
- Refuse-downgrade: a store with a bit/version above the build's is refused with exit 78, untouched.
- Gate script `lab/store-upgrade-gate.sh`: every supported fixture mounts and passes fsck (CI-ready, hard timeout).

S7 implementation (am. 1, 2026-10-28; branch olsm-upgrade-20261028), replaces the S7 text above where they differ:
- Registry `store::upgrade` (`Step { id, name, class, adds }`, only S7 so far); mount gate `upgrade::mount_check`
  (`UpgradeNeeded`: store marked, or an offline step's bit in `FEATURES_REQUIRED` missing); `read_super` refuses a
  newer version / unknown bit with `Newer` ("downgrade not possible after ... was enabled"). OSD: `device_shards`
  exits 78 for both (units: `RestartPreventExitStatus=2 3 78`), with `croit-flashstore-tool upgrade --dev <spec>` (the tool's device options: `--dev`, `--id N`,
  `--data-path`; no `--osd-id`).
- Mark = incompat `FEAT_UPGRADING` (1 << 20) + superblock field `upgrading` (step id, encoded only with the bit). Mark and
  flip are `heal_super` writes (copy 0 = commit point).
- `croit-flashstore-tool upgrade [--omap-lsm] [--dry-run] [--format plain|json|json-pretty|jsonl]`: runs the planned steps,
  resumes a marked one. S7 is opt-in (`--omap-lsm`) until `FEAT_OMAP_LSM` joins `FEATURES_REQUIRED`. `--dry-run` = plan
  from the superblock, no mount, no write. Exit 0 done / up to date, 1 error, 2 usage, 3 refused (OSD running, device in
  use), 5 space shortfall (nothing changed; 4 = `prepare` rerun). jsonl events: plan, survey, mark, progress, shard_done, step_done, result.
- S7 flow: tree mount (replay) + per-shard survey (entries, run bytes) + space check (run bytes + 1/8 vs free + held +
  reclaimable minus the sys floor) + checkpoint; mark; mount with the engine on and omap reads on the tree; per shard,
  per batch (engine memtable size): take the first tree omap entries left (adr 0476 runs merged in) -> engine memtable ->
  normal flush (run + manifest sys txn) -> one txn removes exactly those tree entries (per-object key spans, fragments,
  data-block values); end of shard: no tree omap left, all `c` records removed, adr 0476 run set empty, checkpoint;
  flip `+omap_lsm`, `-upgrading`.
- No cursor: the tree is the cursor. A crash between run install and removal converts the batch again (a second run with
  identical values, newest wins, merged away later): invisible to reads. The removal's WAL record follows the manifest's,
  so it is never durable without the run.
- Counter bits (`omap_counters`, `omap_runs`, `omap_blind`) stay set, as `mkfs --omap-lsm` keeps them; they go with the
  counter code at 0610 phase 3.
- Out of space during the conversion (engine allocation waits again after a checkpoint freed nothing): the step stops
  with `NoSpace`, the store stays marked (OQ 116 (3)).
- Tests: services/osd/store/tests/upgrade.rs (fixture: 2 shards, 100 objects with headers, pgmeta objects, inline /
  compressible / data-block values, a hot object with adr 0476 runs and removals, a cleared object; equivalence of
  every key, value, header and order, deep object check + fsck, marked / newer refusal, space refusal, rerun without
  writes; crash matrix at every device event x 3 policies, resume, verify). Gate: lab/store-upgrade-test.sh.
- Not implemented: S1-S6, quick steps at mount, compat / ro_compat words, `--reorg`, fsck `pending_upgrades`, fixture gate
  `lab/store-upgrade-gate.sh` (OQ 116).

Downgrade safety (am. 2, 2026-10-31; hardening review 2026-10-31): an older build refuses a newer store loudly, never
misreads it.
- Format change rule: every change of what a persisted structure means or how it is encoded (superblock, shard
  directory, root slot, WAL unit header / record / op tag, onode, collection, extent, meta image, tree page, omap LSM
  manifest, lending table, PG meta keys) adds a `FEAT_` incompat bit (set before the first record that needs it; sticky
  when set at runtime, `FEATURES_STICKY`) or bumps `FORMAT_VERSION`. The bit gets a name in `layout::feature_names`.
- Enforcement: `services/osd/store/src/format_golden.rs` encodes one fixed sample of each structure and compares its
  digest with `services/osd/store/format-golden.txt`, keyed by `v<FORMAT_VERSION> f<all defined bits>`. A changed
  digest under the same key fails `cargo test -p store`. The file is append-only: `scripts/check-store-format.sh`
  (pre-commit, also `<base rev>` mode for branch review) refuses edited or removed entries. A new structure adds a sample.
- Refusal paths: every open of a store goes through `layout::read_super` (daemon mount, mkfs probe `is_formatted`,
  read-only fsck, dump, bench, lifecycle, `croit-flashstore-tool upgrade`). An intact copy with an unknown bit or a newer version
  in either superblock copy -> `Newer` ("... downgrade not possible after [..] was enabled", OSD exit 78), also when the
  new bit adds superblock fields; mkfs never re-creates such a store.
- WAL second line: a unit of the current chain whose header and payload crcs verify but whose records do not decode, or
  whose header carries an unknown flag, is refused at replay (`Corrupt` "crc-valid unit with ... (written by a newer build,
  or a bug)"); it is never the torn end of the log (that dropped it and every acked txn behind it silently). A crc mismatch
  stays the torn tail.
- Known history without a bit: the segmented meta image (MBL3, 2026-10-27) is written unconditionally; builds before it
  refuse it as a corrupt meta image (refused, not misread). The omap LSM run / manifest format changed after
  `FEAT_OMAP_LSM` (opt-in, no deployments). No bit is added retroactively: it would block a downgrade to builds that read
  both.
- Tests: `format_golden` (golden digests, every bit named), `layout` (newer copy, unknown fields), `tests/upgrade.rs`
  `newer_store_is_refused_untouched` (exact message: mount, upgrade, fsck; no write), `tests/wal.rs`
  `crc_valid_unit_from_a_newer_build_refuses_replay`, osd `store_probe_fails_closed` (newer store counts as formatted).

## Rationale

- User decision: data stays on the OSD across upgrades; re-deploy costs a full backfill per OSD and is not acceptable.
- Three feature sets let optional structures stay mountable by older builds; the single incompat word (today) makes every
  addition a hard break.
- Quick/offline split keeps OSD start bounded and predictable (no start that runs for hours) while small steps need no
  operator action; long conversions are an explicit offline operator step.
- Bit reuse (0x10000) already happened once; reserving retired bits is the cheap fix.
- Trade-off accepted: one-way upgrades (no downgrade after an incompat step), and old-format readers stay in tree until
  the window moves.

## Consequences

- + Version-1 lab stores (13 days of default mkfs) upgrade at mount via S1-S4; the reported error disappears.
- + Experimental work stays free until its default flip; the flip carries its upgrade step.
- - Each default format change costs an upgrade step, fixtures and a crash matrix.
- - Old record readers cannot be deleted while their format is in the window (counter to "remove legacy" cleanups).
- - The 0610 migration is a long offline step; operators plan a maintenance window per OSD (noout, one OSD at a time).

## Alternatives

- Re-mkfs + backfill (status quo since b88a52244d): rejected by the user, data must stay on the OSD.
- Run every upgrade at mount, including long ones: rejected, unbounded start time, PGs stall, mon marks the OSD down.
- Dual-format runtime (mount old omap tree and LSM side by side, convert lazily): rejected, two hot paths (0610 forbids a
  tree fallback; KISS).
- Single version number without feature sets: rejected, every optional addition becomes a hard incompat break.

## Open questions

- S4: is a fold-cleaned leaf-delta segment set a valid input for relog cleaning? (decides quick vs offline). OQ 116.
- S5: per-bit default dates before 2026-10-16 (which pre-elastic formats a default build wrote) to be listed from git in
  the implementing commit. OQ 116.
- S7 out of space after the mark (am. 1): the marked store mounts nowhere but the tool; needs a way to free space
  (expand, or let the tool delete objects / PGs) before resuming. OQ 116.
- Whether any lab still holds pre-10-16 stores (survey with `croit-flashstore-tool status --format json` on lab OSDs).
