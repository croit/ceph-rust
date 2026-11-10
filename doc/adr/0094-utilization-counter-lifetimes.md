# 0094 Utilization reset baselines follow PG lifetimes
Status: accepted
Date: 2026-10-14
Context: review of ADR 0090 counters. A PG can be recreated at the same core/SPG logger name while an old perf-reset baseline survives. The below-baseline fallback then produces a second discontinuity when the fresh lifetime reaches the old baseline. Replacements can also happen between worker snapshots and already exceed that baseline before they are observed.

Decision:
- Amend the reset-baseline rule of ADR 0090: subtract a baseline only when it belongs to the same counter lifetime. A replacement reports its full new cumulative value until another explicit perf reset establishes its own baseline.
- Assign one nonzero process-local lifetime ID at PG construction, shared by create/load paths. Carry it with the existing internal utilization worker snapshots and local baseline values. Existing PGs retain it across temporary removal/reinsertion; newly constructed PGs get a new ID. Core counters use the process lifetime (ID zero).
- Use a checked process-wide atomic sequence only on cold PG construction, as for codec identities in ADR 0086. Counter increments remain plain owner-core arithmetic; snapshots/admin lookups add no hot-path locks or atomic operations.
- Do not expose lifetime IDs as counters or encode/persist them. Logger names, canonical mgr catalogue, pg_stat_t, wire/disk formats and PG/store ordering are unchanged. Worker statistics keep their existing one-second staleness.

Validation: recreate a real PG with detach/adopt after perf reset on both the control and worker core; check all three counters while ops crosses the old baseline, then reset the new lifetime again. Verify a worker replacement whose three counters all exceed their old baselines before its first snapshot. Counter groups still contain only busy_ns/ops/bytes; core counters retain process-lifetime subtraction. Both regressions fail before the change. Affected peering/osd/runtime tests and results: ../perf/codex-perf3-2026-10-13.md.
