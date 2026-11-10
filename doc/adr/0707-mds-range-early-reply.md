<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0707 MDS early create replies need a durable ino allocation; ranges keep a spare

Status: accepted
Date: 2026-11-09

## Context

With `mds_early_reply`, a create whose record introduced an ino interval (range founding, refill below 32 free)
replied SAFE-only, and later creates read the N image it wrote as a foreign dependency (admission-executor I7a).
About 6 % of creates replied SAFE-only, so most 32-op client windows still waited for a commit
(doc/perf/mds-cpu-per-op.md item 7).

## Decision

- An unsafe create reply may name an ino iff the record that allocated it from the shard counter lies in the
  durable log prefix (`Core::allocation_durable`: per-shard durable allocation high-water, raised by the
  durable-prefix walk and by replay, loaded as the manifest high-water).
- The session range N is not a foreign dependency of an unsafe reply (`View::get_unexposed`); it gates the SAFE
  reply only.
- N always holds a spare interval: the founding create allocates current and spare as one allocation of
  2 x `INO_RANGE`; the create that exhausts the current interval allocates the next spare. No refill threshold.
- No store format change: N encoding, revision 4 validity and the replay reclaim check are unchanged; an N
  without a spare (written before this change) gets one at its next create.

## Rationale

- A REPLAY reclaims an unsafe reply's ino iff it lies free in the durable N. Interval and allocation are in one
  record (store format s4.1), only the create that took the ino claims it, and retire removes held inos only;
  so the durable allocation of the ino is the exact condition. The former proxy (record introduces no interval,
  N image foreign) also blocked creates whose ino was already reclaimable.
- A spare one full interval ahead is durable long before use, so steady-state creates reply early. It rides on
  the create record that exhausts the current interval; a separate reservation record would add a log record
  per 64 creates for the same effect.

## Consequences

- + Every create after the founding one replies early in steady state.
- - A session holds up to 128 unused inos per shard (was up to 96): a fenced close queues up to 128 P actions
  per shard.
- - One max per allocation in the durable-prefix walk.

## Alternatives

- Spare interval in its own record ahead of need: an extra record per interval and the same durability check.

## Amendment 1 (2026-11-09): early replies on by default

Decision: `mds_early_reply` defaults to true (stock default); `--mds-early-reply false` keeps safe-only replies.
Lab safe arms pass `false` explicitly.

Rationale: pjdfstest stock/safe/early (doc/perf/mds-cpu-per-op.md, 2026-11-09): early and safe give identical
failure sets; durability gate crash and crash-early (all crash points) and e2e-early pass with no atomicity
violation. The direct client<->BE path (adr 0708) still answers safe-only until it implements early replies.
