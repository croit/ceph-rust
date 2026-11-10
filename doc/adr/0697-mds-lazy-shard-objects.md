<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0697 MDS shard objects are created on first write

Status: proposed
Date: 2026-11-07

## Context

Fenced CREATING (adr 0670) wrote one manifest `m.sm.<shard>` and one tablet
`m.t.<shard>.1` for each of the 65,536 shards (S fixed, decisions.md i).
That is 131,072 sequential RADOS round trips and 131k objects in the metadata
pool of an empty file system. The first start took ~33 s on a local
1-OSD lab and longer with lab RTTs, while recovery reads only the shards in
the head's catalog bitmap (2 after mkfs). Stock CephFS creates a handful of
objects at `fs new`. Recovery already synthesizes `Manifest::initial` for
shards outside the bitmap and publishes ownership lazily (adr 0670).

## Decision

An absent shard object is that shard's initial state. CREATING writes
`m.super`, `m.map`, the initial head, and only the objects that carry
non-initial content: the tablets holding the root inode and the root frag.

- Manifest: ENOENT on read = `Manifest::initial(shard, owner)` with version 1
  and the registry's first original owner. The first guarded write from
  version 1 is `create(exclusive)` + data + `version` xattr in one operation.
  EEXIST is the same guard conflict as a cmpxattr mismatch. Later writes keep
  the cmpxattr guard. No manifest object exists at version 1.
- Tablet 1 of a shard: ENOENT on read = empty, zero stats. The first omap batch
  creates it together with its header (same atomic operation as today).
  ENOENT for any other tablet id named by a manifest = `Malformed`, because
  split copies persist before manifest publication.
- Recovery, offline verify and `mds-fs check` apply the same rules through
  one shared reader; no tool keeps a second interpretation.
- Old stores with pre-created version-1 manifests are not supported (there
  are no deployed stores; user decision 2026-11-07, no upgrade paths).

## Rationale

The initial content is fully determined by `(shard, owner)`. Storing it
65,536 times adds no information, costs a long first start and an object
count that operators read as a defect. The exclusive create keeps the
version guard total, so ownership and fencing semantics are unchanged.

## Consequences

- mkfs costs a constant number of operations; first start is no longer
  dominated by provisioning.
- The metadata pool holds objects only for shards that were written.
- Every manifest/tablet read path must map ENOENT explicitly; an unexpected
  ENOENT outside the two rules stays a damage error.

## Alternatives

- Keep eager provisioning, pipeline the 131k writes: removes most of the
  latency, keeps the object count and the cost per fs; rejected.
- Pre-create per BE core on assignment: moves the cost to every move and
  failover; rejected.

## Open questions

- None.
