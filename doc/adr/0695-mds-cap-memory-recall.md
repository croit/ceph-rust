<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0695 MDS memory-sized cap admission and client recall

Status: accepted
Date: 2026-11-08

## Context

The MDS-wide 4096-slot cap table can fill under one client's ordinary CREATE
load. Required-cap admission waits for releases, but no RECALL_STATE was sent.
The backend becomes idle while the client waits indefinitely.

## Decision

Derive cap and lease startup capacities from `mds_cache_memory_limit` (4 GiB).
Caps use at most 1/4 and leases 1/32 of the memory budget, with native per-slot
costs covering all cap/lease-dependent structures and conservative
allocator/hash allowances. A cap's outstanding revokes live inline in its slot
(fixed capacity `REVOKES_PER_CAP`); a further revoke waits for an ack. With a
1/32 cap share (32 Ki caps at 4 GiB) recall at 7/8 occupancy capped each of 8
mdtest clients at ~1.5k caps, so stat went to the MDS instead of the client
cache. Preserve startup preallocation and lazy payload commitment.
Authoritative formula: Rustdoc `mds::config::CapMemory`.
Truncation events reserve min(sessions, caps) slots per entry: one inode has
at most one cap per session. They do not reserve an entire cap table per entry.

Recall sessions in descending cap count at global 7/8 occupancy, while a
required cap waits, or above `mds_max_caps_per_client` (1 Mi). Target and minimum
follow caps spec s6.4. Throttle to one recall/session/second. Client releases
wake the existing cap-table FIFO; recall timers never replan waiting requests.
An unmet recall target for 60 seconds raises MDS_CLIENT_RECALL; subsequent
recalls do not extend its window. Meeting the target or detaching clears it.
The 60-second window replaces decay counters (caps spec open question 7).

BE sends internal RECALL (kind 20), FE encodes the stock client message.
Each uses its own push-window reservation through the socket write receipt.

## Rationale

A memory-derived capacity removes the fixed cap ceiling without unbounded
allocation. Separate, small budget shares leave room for metadata, session and
request pools; leases budget both bounded name arenas. Recall provides the
missing liveness event. A fixed recall interval and explicit target deadline
are sufficient for admission progress without decay-counter machinery.

## Consequences

- + Required cap admission resumes on client releases, without polling or retries.
- + Slow sockets retain bounded, accounted recall outputs.
- - Clients retaining open/dirty/pinned caps can still prevent reclamation;
  the health warning reports this debt without evicting or failing requests.
- - Capacity depends on native structure sizes; sizing tests report those sizes.

## Alternatives

- Raising the fixed 4096 ceiling: defers the same missing-recall deadlock.
- Ceph decay counters: unnecessary for the selected simple recall policy.

## Amendment 1 (2026-11-09): image cache from the same budget

Decision:
- The BE clean image cache takes 1/4 of `mds_cache_memory_limit` as its arena (power of two, >= one batch) with one
  entry per 1 KiB of arena, capped below the packed receipt index (`CapMemory::image_bytes`, `images`,
  `core_limits`). 4 GiB: 1 GiB arena, 1 Mi entries. Production recovery passes these limits to `Core`; the fixed
  `core::Limits::default()` (64 MiB, 64 Ki entries) stays for tests and simulations only.
- Remaining budget: 7/16 for image entry tables, session/request pools and allocator/RSS headroom.

Rationale: the fixed 64 Ki-entry cache evicted the images of a 20k-file create run, so the unlink run read them back
(3.5 tablet reads per unlink, store I/O ~40 % of MDS CPU); stock keeps such a working set in its cache. Measurements:
MDS CPU per op (doc not in the source snapshot).

Consequences:
- + 200k create/unlink in one directory: no tablet reads, MDS CPU per op below stock.
- - Startup reserves a larger (lazily committed) arena; RSS grows with the cached working set up to the budget share.
