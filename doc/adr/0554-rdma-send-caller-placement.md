<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0554 RDMA SEND receive slots fill caller segments

Status: accepted
Date: 2026-10-24

## Context

TCP receive helpers already place CRC READ reply segments in caller memory.
RDMA SEND helpers copy registered receive slots into an intermediate loan Vec;
publication then copies the verified payload into the caller buffer. Carried
loans can span several helper jobs, so placement must survive partial jobs.

## Decision

- Carried CRC receive jobs and inline receive request the existing owner's
  caller placement. The destination path is independent of helper availability.
- A bound segment retains its exclusive caller memory across partial jobs and
  inline tails. Each receive-slot copy computes block CRCs in the same pass.
- Copy the already checksummed prefix once, excluding decoder padding; retain
  its existing CRC sidecar without another checksum pass.
- Only a complete segment reaches the decoder and publication. Cancellation
  stops further writes through the existing bounded ReadPlacement write fence;
  an incomplete stopped segment faults the attempt through normal transport failure.
- Unused placements are unbound if helper admission fails; inline fallback
  requests the same caller binding. Before any caller
  write, a stopped placement leaves the original loan usable as a fallback.
- Secure loans keep their authenticated-buffer path. TCP socket placement keeps
  its direct receive path. No wire, GPU or stable C ABI change is introduced.
- At an untouched CRC data boundary, carried receive binds caller memory before
  reserving a decoder payload buffer. Missing/stopped bindings reserve the full
  ordinary fallback before transport admission. Socket loans retain full spare
  capacity; partial payloads, block hints and pre-write retain their existing path.

## Rationale

The existing owner supplies the routing/attempt lifetime and caller allocation.
Retaining that binding across jobs removes the intermediate payload copy without
holding a helper while waiting for more slots or weakening checksum checks.

## Consequences

- + SEND caller publication can avoid a second full-payload copy.
- + Credits return after a helper copies each retained slot, as before.
- - SEND still requires the copy from registered receive slots to caller memory.
- - Cancel after a partial write faults the attempt, as socket caller placement does.
- - Physical CPU/throughput benefit requires current-stack A/B measurement.

## Alternatives

- Keep a helper until a whole segment arrives: occupies bounded workers during
  network waits and complicates release/credit wakeups.
- Start a fresh placement for each partial job: violates one-attempt binding and
  risks publishing incomplete segments.
