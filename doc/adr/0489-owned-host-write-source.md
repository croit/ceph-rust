<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0489 Registered host WRITEs retain their source through RC completion

Status: accepted
Date: 2026-10-22

## Context

ADR 0471 narrows placement to OSD-initiated WRITEs for plain client READs.
ADR 0488 adds unadvertised local type-2 windows on the existing RC SQ but no
sender WRITE. The current SEND source lease covers only its configured payload
pool; a WRITE source may have a separate registration and owner. A CQ failure
cannot prove that the NIC has stopped reading the source.

## Decision

- Feature `memory-windows` posts signalled host RDMA WRITEs on the same RC SQ
  and accounts them through the existing epoch, sequence and CQ marker slots.
- `WriteSource` owns immutable `Bytes` and a local-only MR, registered on the
  control thread. A rejected post returns that exact source. Accepted work
  retains its registration independently of whether the caller keeps a handle.
- The WRITE source is reusable only after successful local completion. Faults,
  drains and missing completions quarantine its MR, backing and device. Dropping
  a pending handle also quarantines the source: CQ progress must never become
  the last registration owner and perform provider deregistration.
- The remote address and key enter through an explicitly unsafe raw grant
  constructor with checked numeric bounds. No production descriptor is issued
  or advertised until the peer-retirement protocol is implemented.
- Opt-in RC QPs allow remote WRITE; only a bound type-2 MW grants a remote
  range/key. Default SEND QPs retain their prior access flags.
- Posting and normal SQ backpressure allocate no Rust memory and consume no
  SEND receive credits. Source length and target length must match.

## Rationale

The shared SQ preserves SEND/WRITE ordering and the existing CQ fault path.
Retaining the source at the completion marker covers handle abandonment and
direct core shutdown without adding per-WR allocation. Quarantining on
uncertainty preserves DMA ownership when the provider completion is lost.

## Consequences

- + Real host WRITE and exact source/destination ranges can be qualified on RXE.
- + The default SEND build retains its access policy and accounting.
- - Faults with uncertain WRITE retirement and abandoned pending handles
  permanently retain registered memory and the device in the process.
- - No remote application receipt, integrity proof, RADOS placement, GPU or
  NIXL support follows from this sender primitive.

## Alternatives

- Reuse the SEND payload pool alone: excludes independently registered store
  buffers and cannot express their ownership.
- Release source memory on QP fault: a lost CQE does not prove NIC retirement.
- Post WRITE on another QP: breaks required ordering with the protocol SEND.
