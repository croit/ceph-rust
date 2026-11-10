<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0670 M0 combined daemon lifecycle

Status: proposed
Date: 2026-11-05

## Context

M0 has one combined FE/BE process and no independent BE membership service.
The monitor assigns rank 0 and fences the predecessor's advertised addrvec.
Stream heads retain their immutable original owner. Recovery never appends to
an old stream. The existing public BE API requires a durable checkpoint before
switching to a fresh stream.

## Decision

The daemon owns one monitor session. Its RADOS data owners share that session's
authenticated identity, exact public addrvec and nonce. All data connections
use the MDS messenger role. FE and BE completions have separate native clients.

Fenced CREATING initializes m.super, a complete 65,536-entry m.map, initial
manifests/tablets, the root inode/frag, and the initial stream. The root's shards
are included in the initial stream's catalog bitmap before any recovery.

M0 publishes assignments with the format's guarded epoch/header/placement
transaction. After the monitor's OSD barrier, the successor marks the source
stream replaying and reserves a monotonically new replaying stream in m.map
before creating its head. A replaying reservation never accepts client writes.
If startup is interrupted, recovery uses the live stream, or the earliest
replaying stream when a claim already replaced the live state. Newer replaying
reservations are verified empty and then abandoned, never reused. Their original owners remain in the
registry so a restart can validate historical manifest ownership.

The successor replays the source with its immutable original owner, writes back
and checkpoints it, adopts the new owner in the recovered core, validates and
switches to the fresh stream, then publishes that stream live in m.map. Only
then can FE recovery complete and ACTIVE be requested. Finished source entries
remain in the registry. Every request/store failure stops the assembled loop.

Manifest ownership is published lazily by the next version-guarded manifest
write. During fenced M0 recovery, the recovery adapter accepts only original
owners recorded in that registry and normalizes them to the source owner for
BE loading. Durable manifest versions, tablet identities, high-waters and
import positions remain authoritative. Adoption changes cached owners without
rewriting the immutable old head. This M0 owner-lineage interpretation applies
only to the single combined BE; live moves and multi-BE recovery require the
full ownership protocol.

SIGTERM/SIGINT request DNE using the same monitor session, drive its existing
one-second acknowledgement bound, close native owners, and remove the owned
local status socket. A timeout remains a loud unsuccessful shutdown.

## Amendment (2026-11-09): FE core and BE core, `--cores 2` (am. 1)

- `--cores 1` (default) runs FE and BE in one thread as above. `--cores 2` moves the BE executor
  (`Engine`) to its own thread `mds-be` after startup recovery; values other than 1 and 2 refuse
  (multi-BE cores: M2, design/cephfs-mds/plan.md).
- Startup, recovery and the monitor stay on the FE thread. The hand-off requires no outstanding store
  work; the BE thread builds its own follower client (rados clients are not `Send`) at hub index 2.
  The leader client (FE thread) keeps the monitor session and dials every OSD; FE and BE OSD requests
  ride its connections through the proxy hub, so the one-connection-per-addrvec rule holds.
- FE and BE exchange requests, replies and descriptors over the unchanged SPSC rings. Lifecycle state
  (recovery progress, cap recall health, ops dump, drain, halt) crosses in a small locked block,
  published only when it changes. DNE drain completes when the BE reports itself drained at the FE's
  latest request sequence.
- Wake protocol (`daemon/split.rs`): a side that moved ring positions wakes its peer if the peer
  announced sleep; a side announces sleep, fences, and rechecks the peer's ring positions and requests
  before waiting on its readiness fd. A BE error halts the BE health as on one thread.
- `--mds-direct-clients` (adr 0708 B0a) requires `--cores 1`; the config refuses `--cores 2` with it until
  direct fronts run on BE cores (adr 0708 B1).

## Rationale

The monitor fencing barrier supplies exclusive ownership. Stream reservation
before object creation prevents reuse across a crash. The live-map publish is
the admission commit point, so abandoned reservations cannot contain client
writes. Keeping historical original owners lets recovery distinguish valid
lazy manifest ownership from an unrelated or contradictory owner.

## Consequences

- + One explicit transport enum selects Linux knet by default when compiled;
  Stack/TAP requires deliberate selection. The public socket trait dispatches
  statically and leaves FE session/messenger behavior unchanged.
- + The in-process smoke exercises real TCP/msgr2 CRC and secure session/root
  requests, namespace rings, memory storage and the monitor DNE exchange.
- + Memory fault injection covers unacknowledged tails, same-name restart and
  a queued predecessor append rejected with EBLOCKLISTED.
- - Physical OSD blocklist/address matching and stock FUSE/pjdfstest require a
  provisioned Linux cluster; memory tests cannot qualify those external paths.
- - Initial mkfs creates all initial manifests/tablets before serving.

## Alternatives

- Reuse an old stream after replay: violates the immutable stream contract.
- Give RADOS an independent client addrvec: predecessor fencing would not
  necessarily cover metadata writes.
