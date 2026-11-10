<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0553 Current-stack application-buffer READ A/B

Status: accepted
Date: 2026-10-24

## Context

The standalone placement spike predates current receive-helper/caller-memory
placement. The functional probe compares every READ's bytes, so its loop cannot
qualify placement's CPU or latency advantage over the current SEND path.

## Decision

- The existing placement probe has an explicit benchmark mode send|placed.
  Both modes register QD initialized host destinations of the selected Vec or
  retained foreign-host backing before measurement and
  require real RDMA upgrades, successful exact-length reads and no session faults.
- SEND requests the current native caller-memory receive-helper placement. If its
  verified reply is elsewhere, publication copies it to the application buffer
  and reports every fallback-copy byte. Placement uses RegisteredReadClient.
- Registration, expected-file loading and full byte comparisons run outside
  the measured phase. Required protocol integrity and application publication
  remain measured; no integrity work is disabled for a faster number.
- Measure application-ready completion latency, throughput and the whole process
  CPU clock (all owner/provider/verification/receive-helper threads). Report
  cold/setup and explicit warm-up separately, plus actual delivery-path counts.
- Check original caller-address identity at registration. Foreign retainer
  checks stay outside timed phases; both modes use the same backing kind.
- Optional read/exit file barriers let the external lab driver capture all OSD
  threads around the same READ phase. No native/client completion implies GPU readiness.
- Independently loaded public C batch measurements label full timed byte
  comparison explicitly. They are separate from the native comparison above;
  raw throughput is not comparable across differing consumer work.
- C phase wall spans include their checks/clocks/bookkeeping and are never
  presented as per-phase CPU or wire-only latency. Rustdoc in the independent
  consumer defines their boundaries.
- Consumer-only rebuilds retain exact server/library identity and bytes. A
  separate consumer source identity and rehashed immutable manifest accompany
  every cell; unchanged binaries are never relabeled as a new runtime source.
- Run process-local functional cells on RXE before physical-NIC performance cells.

## Rationale

Comparable application-buffer semantics expose actual remaining copies and the
current receive-helper baseline. Excluding benchmark payload comparisons keeps
consumer validation from hiding the transport differences under test.

## Consequences

- + Mandatory integrity/visibility work remains included on both paths.
- + Warm and cold costs and SEND publication fallbacks are explicit.
- - Native SEND can allocate its per-request caller-memory lease as the existing
  API does; that is measured rather than hidden in a synthetic SEND harness.
- - Publication counters count application fallback copies only. They do not
  count total transport copies: RDMA SEND still receives into registered slots
  and lends/copies those parts through the current receive-helper path.
- - Single-object hot-read cells do not qualify general object distribution,
  storage misses, replication sizes, faults or GPU memory.

## Alternatives

- Compare to the old harness: omits newer production receive paths.
- Count owner-thread CPU only: hides helpers and placement verification work.
- Byte-compare every measured reply: measures consumer validation as well.
