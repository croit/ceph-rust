<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0608 Late apply: in-memory apply of a txn after its client reply

Status: rejected
Date: 2026-10-27
Concerns: 0021 (S2 commit / ack, S5 tree apply), 0008 (ack rule)

## Context

`Shard::submit` applies every record to the in-memory state (tree, runs, point cache, allocator) before its WAL unit
goes to the device. For large omap txns this apply is the largest serial step of the commit: b-dir commit-b1024 QD1
(rep3, zen4a) spends ~1.7 ms of ~3.8 ms OSD time per commit in `State::apply` on the replica
(doc/perf/omap-commit-chain-20261026.md). Proposal: ack once the WAL record is durable (unchanged ack rule, adr 0008)
and apply after the reply has left.

## Decision

Rejected. The store keeps applying each record inside `Shard::submit`, before its WAL unit is written.

## Rationale

- A measurement spike (doc/perf/late-apply-20261026.md) worked on the lab:
  - Design: the state sits behind a gate, so every state access first applies the held record; at most one record is
    held per shard; the OSD core applies it after its IO submit when no client op waits.
  - Result: 96 % of the applies that ran after the ack came from that OSD hook, i.e. after the reply had left.
  - Effect: none. b-dir b1 / b1024 commit p50, p99 and ops/s stayed within noise of main (tsrv1, EPYC 9124, PM9A3).
- Why: at QD1 the next op reaches the same PG cores sooner than one apply takes, and the gap is shorter on bare metal
  than on the VM lab where the gain was estimated.
  - The primary and every replica must finish the held apply before staging the next op.
  - So the apply leaves the chain only for the client gap (wire + client turnaround), not for its full length.
- No gain at saturation either (c64): the same CPU work runs on the same core.
- The omap LSM tier (branch omap-lsm-20261026) removes the apply's hot spots (`kill_asc`, `leaf_search`, freeze)
  directly. It shrinks the apply that late apply could at best hide.
- Cost: a gate in front of all 250 store entry points and an audit of every state access. Commuting bookkeeping (miss
  waits, elastic lend check, pre-write reserve, miss log) silently pulled the apply forward until each site was found
  by lab counters. That correctness surface is not worth a gain bounded by the client gap.

## Consequences

- No code change. Spike branch `late-apply-spike-20261026` is not merged.
- QD1 large-omap commit latency is attacked through apply cost (omap LSM tier), not apply placement.

## Alternatives

- Late apply as specified here (rejected, above).
- Settle in the store poll right after the ack: the primary applies while it waits for the replica acks, and the
  reply waits for the apply.
- Apply on a helper core: the state is single-owner (adr 0006); a handover needs locks or a copy.
- Per-object read gates (FileStore style): every read path must name its objects; scans and listings span many.

## Open questions

- None.
