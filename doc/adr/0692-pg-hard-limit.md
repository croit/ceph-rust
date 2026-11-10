# 0692 Per-OSD PG hard limit: withhold creates, count all cores per tick

Status: accepted
Date: 2026-11-08

## Context

Classic v21.2.0 refuses to instantiate a PG from create info (mon MOSDPGCreate2, peer notify/log) while the OSD holds
`mon_max_pg_per_osd` x `osd_max_pg_per_osd_hard_ratio` PGs or more, remembers it, reports it as `PENDING_CREATING_PGS`
and re-triggers it when there is room (spec peering.md 7.3 rule 3a). croit-flashstore-osd created every PG and always
reported 0. Its PGs live on several cores (adr 0031); no core sees the others' PG maps.

## Decision

- Every core checks a create against the OSD-wide estimate: the PG count the control core sums every 1 s tick and hands
  to every core on change (the count of the PG log target, pglog.md 6.3) plus this core's change since that hand-in.
  At or above the limit (both options read at every create, runtime changes apply) the create is withheld: a mon create
  is remembered with its message epoch, a peer create with whether this OSD is the acting primary; the message is
  dropped and counted (`hit max pg: create withheld`).
- Only creates that would otherwise happen are withheld (after the existence, passive-pool, membership and
  acting-primary checks).
- `PENDING_CREATING_PGS` = withheld mon creates + withheld peer creates of PGs this OSD leads, all cores.
- Every PG tick of an active OSD, below the limit: withheld mon creates go first (the mon sends its creates again from
  the oldest withheld epoch: a forced `osd_pg_creates` re-subscription by the control core), then up to the remaining
  room of withheld peer creates get a new interval through a pg_temp that differs from the acting set (first member
  alone; a set of at most one member plus an empty slot; optimized EC padded to the pool size). The primary then
  sends the create info again.
- A new map forgets withheld peer creates of PGs whose acting set no longer has this OSD.

## Rationale

Same operator contract as classic (health warning, no silent overload) without cross-core locking on the create path
(adr 0006): the estimate needs no message per create. Withheld mon creates are kept per PG, not as a counter, so a mon
resend does not count twice.

## Consequences

+ The limit and the pending-create health metric work like classic, also above `mon_max_pg_per_osd` during remaps.
- Count lag: PGs other cores create in the same tick are counted from the next hand-in, so a burst reaching several
  cores at once can exceed the limit by what the other cores create in that tick. A single core is exact.
- Tests: peering `creates_above_the_pg_hard_limit_are_withheld_and_resumed`, osd
  `pg_hard_limit_withholds_creates_reports_them_and_resolicits` (2 cores), `new_interval_temp_differs_from_acting`.

## Alternatives

- Reservation through the control core per create: exact, but a cross-core round trip on every create and a second
  create path.
- Per-core limit = limit / cores: no lag, but PG placement per core is uneven, so cores refuse below the OSD limit.
- `pg repeer` mon command for peer creates: only the control core sends mon commands; pg_temp goes from any core.
