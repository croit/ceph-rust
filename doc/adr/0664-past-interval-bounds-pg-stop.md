<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0664 Past-interval bounds: stop only the PG, not the OSD

Status: accepted
Date: 2026-11-06

## Context

peering.md 3.8 requires a PG's `(history, past_intervals)` pair to cover
`[max(lec or epoch_pool_created, cluster_osdmap_trim_lower_bound),
max(same_interval_since, epoch_pool_created))`. Classic `ceph-osd` treats a
violation (cases 2-4: empty set, start after the required start, end mismatch) as
a fatal invariant break and aborts the whole process. One bad PG's bookkeeping
therefore removes every PG of a hundreds-of-PGs NVMe OSD from service, and the
durable pair makes it abort again after restart. croit-flashstore-osd must never crash or
confuse classic peers/mons (prime safety).

## Decision

- croit-flashstore-osd checks the required bounds at the three classic call points: Reset on
  every AdvMap (after the closed interval is recorded), GetInfo entry before the
  prior set is built, and activation when recovery is needed - before the first
  activation message, so a stopped PG never tells peers to activate. A split
  child runs the same check when it is created: it inherits the parent's pair,
  whose start can already lie after the child's required start, so a stopped
  parent yields stopped children that send nothing.
- The oldest map is the superblock `cluster_osdmap_trim_lower_bound`; the create
  path keeps logging a violation but creates the PG (spec 3.3).
- Cases 2-4 stop only the affected PG: state INCOMPLETE, no peering, no
  activation, no outbound message and no client service; the stop itself writes
  nothing to the store. The verdict is recomputed from the durable pair at the
  next interval start, which resumes normal peering when the pair became
  plausible.
- Silence is enforced per producing instance (`SpgT`), never per pgid: a stopped
  EC shard must not silence a healthy shard sibling of the same pgid on the same
  OSD (adr 0049 am. 1), whose sends and whose MOSDPGRemove for the stopped stray
  are legitimate. Every outbound `Send`/`PgTemp` (and the other PG-addressed mon
  messages `PgCreated`, `ReadyToMerge`) of a stopped instance is dropped where it
  is taken from that PG (`collect` / `take_actions`), and every queue that keeps
  an action for later carries the producing `SpgT` and gates on it: split-gate
  held sends, the final-output gate, the mon-request resend and the local
  loopback queue. This covers every path - a tick or timer, a runtime EC role
  switch, a reconnect resend, a send queued before the stop in the same event,
  one released from a split gate. Persistence, local cleanup and the primary's
  INCOMPLETE stats pass, so the mgr still sees the stopped PG.
- A stopped PG stays deletable (spec 7.5): a removed pool (the ActMap-in-Reset
  condition a healthy PG takes) or a MOSDPGRemove runs `DeleteStart` from the
  stopped state (Reset / Primary(Incomplete) included) and writes only the
  removal, never a repair of the pair. The removal passes the same 7.3
  staleness/epoch/interval gate as on a healthy PG - a stale one is discarded, so
  a copy that rejoined the acting set since is not deleted - and a PG already in
  `ToDelete` takes no second removal. Leaving the mapping alone deletes nothing,
  like a stray.
- Case 1 (empty required range, non-empty set, history-derived start) logs once
  per PG per interval and does not stop.
- One ERROR line per PG per interval through the PG note path
  (`pg_drain_notices`) names the PG and both ranges. The new health check
  `FLASHSTORE_PG_PAST_INTERVALS` (via `os_alerts` -> mon WARN) lists every stopped PG
  of the OSD with both ranges and is recomputed per stat report, never sticky.
- `osd_skip_check_past_interval_bounds` (dev level, default false) disables the
  check entirely: no log, no stop, no alert. A runtime change re-evaluates the
  stopped PGs and releases them through the Reset transition a new interval start
  uses, so the PG peers again and the alert clears. A PG whose removal is pending
  (`ToDelete`) is never restarted: it keeps its removal and completes it.

## Rationale

Prime safety: a local bookkeeping inconsistency must not take down an OSD, its
other PGs or its clients, and croit-flashstore-osd never aborts for peer- or map-derived
state. The PG-level stop keeps the OSD serving everyone else and leaves the
diagnosis - PG id and both ranges - to the operator, where classic offers only a
crash dump. The cost is an operator action for a stopped PG; the ERROR line and
the mon alert name it.

## Consequences

- + One implausible PG cannot remove the OSD, its other PGs or client bandwidth.
- + No crash loop from the durable pair; restart keeps serving other PGs.
- + Peers only see silence from this PG, which classic peering handles without
  an abort path.
- + A stopped copy can still be removed (pool deleted, MOSDPGRemove), so a
  deleted pool never leaves it behind.
- + The operator escape takes effect at runtime: the released PG peers again
  without a restart.
- - A stopped PG stays unavailable until the pair is repaired by a later interval
  or an operator intervenes; classic would have restarted the whole OSD instead.
- - `osd_skip_check_past_interval_bounds` lets a bad pair peer, with the
  data-loss risk the invariant exists to prevent.

## Alternatives

- Abort like classic: one bad PG state removes the whole NVMe OSD from service
  and repeats after every restart.
- Warn and continue peering: an implausible pair cannot be trusted for the prior
  set and unfound computation, so this risks silent data loss.
