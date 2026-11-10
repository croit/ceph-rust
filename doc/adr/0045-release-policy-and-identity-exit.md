# 0045 Release/feature policy (fail closed) + exit on purge/re-create
Status: accepted
Date: 2026-10-11
Context: rollout P0 11 + backlog "exit on purge". A cluster raising `require_osd_release` past what we implement, or an operator purging/re-creating our id, must not leave a half-working daemon (or a hot restart loop).
Decision:
- Tracked release = `osd::release::TRACKED_RELEASE` (umbrella 21, matches `version.rs`); window `[MIN_RELEASE=pacific, TRACKED]`. Checked on the stored map at `start` and on every new OSDMap BEFORE it is persisted or acted on. Outside the window (0 = unset is accepted): level-0 log `FATAL: cluster require_osd_release ... refusing to run (fail closed)`, no further boot, clean teardown (workers stopped, no mark-me-down: the mon marks us down by heartbeat), exit code 3 (`EXIT_REFUSED` = adr 0034 "precondition/refused"). Unit: `RestartPreventExitStatus=2 3` (already) -> stays failed, no hot loop; operator fixes (upgrade croit-flashstore-osd / `ceph osd require-osd-release`) and `systemctl start`. Containers: treat exit 3 as terminal: podman unit `croit-flashstore-ctr@` (RestartPreventExitStatus) or the image entry's `FLASHSTORE_HOLD_EXIT="0 2 3"` with plain restart policies (adr 0052).
- Features: we claim exactly `release::CLAIMED_FEATURES` (= msgr2 supported default, Ceph main mask) in MOSDBoot and msgr2. Peers/mons requiring more are refused by the msgr2 handshake (IDENT_MISSING_FEATURES); `missing_features()` is the single predicate. Never widen the mask without implementing the feature; a test asserts reserved/unimplemented bits are not claimed. Mon-only persistent features (MonMap) do not concern an OSD and are ignored.
- Mon newer than us but `require_osd_release` still in window: runs (classic semantic: the mon holds the release back until all OSDs support it).
- Identity exit: on a new map, when state is Active or we are caught up (epoch >= mon newest): `!exists(id)` (purged) or map uuid != our store uuid (id re-created by `osd new` elsewhere; zero uuid ignored) -> level-0 log + cluster-log WARN, graceful shutdown WITHOUT mark-me-down, exit 0 (`Restart=on-failure` does not restart). Catch-up gate: an old map during preboot may legitimately lack the id. Destroyed-flag path unchanged (exit 0).
- Resync procedure when Ceph main moves: doc/release-resync.md.
Consequences: + no silent half-compat; + purge parity; - a cluster at require_osd_release > tracked needs a new croit-flashstore-osd build first (intended rolling-upgrade order: croit-flashstore-osd, then `require-osd-release`).
Tests: osd/src/release.rs (window, claimed bits); osd/src/osd/core_tests.rs (newer/older release refuse + map not persisted, purge in preboot with/without catch-up, purge while active, uuid mismatch/match).
Alternatives: stay up passive on newer release (wrong semantics on the data path); exit 1 (restart loop).

## Amendment 1 — monitor boot admission below squid
Status: accepted
Date: 2026-11-08
Context: the pinned monitor ignores a SERVER_UMBRELLA MOSDBoot while `require_osd_release < squid` (`doc/spec/osd-lifecycle.md` §3.3) and logs that to the cluster log; maps pacific..reef stay inside our window. Classic v21.2.0 `ceph-osd` sends the boot anyway, stays booting and needs no restart once the release is raised.
Decision: same as classic: send and resend the boot; each attempt below squid logs a level-0 `WARNING the monitor ignores this boot` with the fix (`osd::release::boot_admission_warning`). No exit, no window change.
Rationale: exit 3 is restart-prevented (adr 0034), so the OSD would stay down after the operator raises the release; classic recovers by itself.
Consequences: + classic-identical behaviour, local diagnostic; - the daemon stays in `booting` until the release is raised.
Tests: osd/src/osd/core_tests.rs `boot_below_monitor_admission_is_sent_like_classic_and_warns`.
Alternatives: exit 3 before boot (rejected: no auto-recovery, not classic); raise MIN_RELEASE to squid (rejects catch-up through older stored maps).
Open questions: none.
