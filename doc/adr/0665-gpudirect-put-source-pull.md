<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0665 GPUDirect PUT: OSD-initiated READ of a client source under source-pull

Status: proposed
Date: 2026-11-06

## Context

KVBM/NIXL must store GPU memory in croit-flashstore-osd without a host copy (PUT). The
existing design already forbids naming OSD memory to a peer (adr 0469 D2) and
defines the write direction as an OSD-initiated READ of the client's data
segment (adr 0469 D1). The later host-READ work (adr 0606/0616/0617) added
READ targets, READ-only type-2 MW sources, peer retirement and LOCAL_INV; adr
0618 added negotiated READ depths; adr 0622 assigned the optional source-pull
banner bit 60 and left the object protocol open. A client-push design (client
RDMA-WRITEs into an OSD window) would expose OSD memory and is rejected.

## Decision

- PUT extends the existing plain write MOSDOp: when both peers negotiated
  source-pull (bit 60), the connection is RDMA READY and READ depths are
  offered, the request's data segment may carry a versioned **source
  descriptor** instead of inline bytes. The descriptor names a client
  READ-only source: exact (address, length, rkey/MW, optional crc32c over the
  range, transaction id, retry attempt). No new opcode, no new messenger frame.
- Client side, a source-pull PUT is a request kind of the handle's own client
  (`rados_write_from_source` -> handle worker -> compound write): routed,
  resent and re-routed by the ordinary objecter machinery (same reqid, retry
  attempt), to any primary OSD session. No second client, no writer thread.
  The write carries mtime and the ioctx's self-managed snap context; a snap
  read context is refused (-30).
- Each attempt registers the caller's range in place and binds a READ-only
  window on the session QP the attempt is routed to (key = session, retry
  attempt). Window lifetime, enforced by the driver before any
  ownership-ending return:
  - OSD reply for that attempt = peer retirement proof -> LOCAL_INV.
  - Window bound but descriptor never sent -> retract + LOCAL_INV.
  - Descriptor sent, attempt ended without a reply (deadline, re-route) ->
    the session is reset.
  - Session released (reset, fault, close) with windows not retired -> the
    windows are handed to the QP's retained-owner record (as zero-copy send
    leases and abandoned OSD READ ranges): teardown moves the QP to ERR,
    deallocates their MWs, destroys the QP and only then releases parent MR
    and the caller's range; the request completes after that. Uncertain
    deallocation or destroy keeps them for good (loud, counted) and the call
    stays blocked: the caller's buffer may still be mapped.
- The call returns on the durable OSD ack or a real error, only after every
  window of the request retired. No timeout by default;
  `rados_osd_op_timeout` applies (-110, loud `WARNING TIMEOUT`).
- The OSD RDMA-READs exactly the descriptor's length (up to `MAX_TRANSFER`,
  64 MiB) into one registered destination arena per core and device
  (`MAX_TRANSFER` bytes, registered once at start, charged against
  `osd_memory_target` as the envelope's pinned share and counted in the
  memlock check). Each pull claims a range of exactly its length at a 4 KiB
  aligned start (first fit: the ring head, else any free gap); after the READ's exact CQ the range is the op's
  data segment as `Bytes` (no copy, a direct-IO write view) and returns to
  the arena when the last reference drops, on any core. No room or no READ
  admission = the pull waits (FIFO per core; a released payload rings the
  core), never an error. The OSD verifies the exact transferred length and
  the client crc32c when the record carries one (one pass over the bytes),
  then follows the unchanged durable write and replication contract. Object success is never inferred
  from READ completion or peer retirement alone.
- A READ the OSD gives up on (failed CQE, QP fault, its session torn down)
  keeps its range claimed by the QP it was posted on; the range returns to
  the arena once that QP is destroyed (no WR can write it any more), and
  stays claimed for good only when the destroy is uncertain or the QP never
  drains (loud, counted in `quarantined_read_targets`), as for zero-copy
  send leases. "That QP" = number and connection generation recorded at
  post time; a gone or reused QP number quarantines the range.
- Connection lost while a pull is pending: the held op and the session's
  later messages are dropped (their ingress credits return), the session is
  reset, so the client resends all of them with the same reqids (pg-log dup
  detection as for any resend); counted in `source_pull_aborted`.
- The source is a READ-only type-2 MW over exactly the write's bytes, bound
  to the session QP, transaction and attempt. A GPU source binds it on the
  registration's own MR (the same MW_BIND parent the GET windows use); the
  parent rkey is never exported. A provider that refuses MW_BIND on a DMA-BUF
  MR refuses the registration (GET and PUT alike); a per-attempt direct
  sub-range MR as fallback is not built.
- Ordering: a source-pull PUT has exactly the ordering of an inline write.
  Its READ is the op's data arriving, so the op holds its session's ordered
  input until the READ completed (one outstanding pull per session); no later
  message of that session is taken before the PUT is admitted. Ops of one
  client session to one PG apply in submission order (Ceph's rule), which
  this keeps; head-of-line blocking equals an inline op whose data segment is
  still on the wire. Other sessions are unaffected.
- The primary OSD reads the source once; replicas receive the normal repop
  from the primary. A replica never reads the client source.
- Integrity: a host source carries the crc32c the client computes over the
  exact range (descriptor flag bit 0); the OSD rejects a mismatch with EIO
  before any store reference is published. A GPU source (every backing:
  DMA-BUF device memory, host-readable DMA-BUF, host mock) carries no crc
  (flag clear, field zero): the client never reads device memory with the
  CPU and the C ABI has no crc argument. Its transfer is checked by the RoCE
  ICRC (end-to-end per packet, verified by the receiving NIC), the same wire
  coverage msgr2 crc mode gives an inline write; the OSD stores what the
  READ delivered.
- Capability absent (classic OSD, no READ depth, no source-pull bit, secure
  mode, handle without RDMA) = -95 (`EOPNOTSUPP`) before anything is sent;
  the caller falls back to an ordinary write. A descriptor is never sent to a
  peer that did not negotiate it.
- Registration release: a GPU registration is released synchronously on the
  handle worker and returns only when no DMA can touch it; it returns -16
  (`EBUSY`) while READ handles on it are open. A host registration releases
  asynchronously and signals its release callback; the NIXL backend's
  `deregisterMem` waits for that callback and keeps the registration on -16.
- GPU sources use the same source-window state machine as host sources;
  only the parent differs: the registration's MR instead of a per-attempt
  registration of host bytes. `rados_write_from_registration_batch` on a GPU
  handle reserves the sub-range on the registration (worker thread) for the
  whole request; each attempt binds its own window over it. GET windows (a
  peer writes) and PUT sources (a peer reads) of one registration never
  overlap (-11 before anything is sent, like a GET overlap); PUT sources may
  overlap each other. The reservation and every attempt window hold the
  source, so the registration's release (`-EBUSY`, or
  `rustyrados_host_registration_release_wait`) waits until the last window
  retired or its QP was destroyed. No OSD-side GPU code.

## Rationale

- It reuses the messenger, MOSDOp, durability, replication and ownership
  paths instead of adding a second storage protocol; classic peers and older
  croit-flashstore-osd see the ordinary write.
- OSD-initiated READ keeps the invariant that no OSD buffer is ever named to a
  peer (adr 0469 D2) and matches the original write-direction design.
- Primary-only source read bounds GPU read amplification and keeps replication
  unchanged; it costs one host copy on the replicas, not on the client.
- The existing source-window state machine already provides retirement,
  LOCAL_INV and quarantine; only the backing and the descriptor encoding are
  new.

## Consequences

- + PUT is true GPUDirect: one RDMA READ from GPU memory to the OSD, no client
  host copy.
- + No new wire opcode; the extension is optional and negotiated.
- + A GPU PUT costs one MW per attempt on an existing MR (no registration per
  write) and never touches device memory with the CPU.
- - A GPU PUT has no end-to-end application checksum: corruption between the
  GPU memory and the NIC's DMA engine (PCIe, NIC) is not detected by the OSD.
  Same coverage as an inline crc-mode write, weaker than a host source-pull
  PUT. A caller-supplied crc (new ABI argument) or a device-side crc kernel
  would close it.
- + Replication, durability and integrity reuse existing contracts.
- - The source-pull object protocol (record encoding, proof routing, EOF/error,
  cancel, bounded metadata) must be specified and implemented; adr 0622 left
  it open.
- - The OSD needs registered READ targets for write data (the existing READ
  target primitive, not a new one).
- - DMA-BUF MRs may not support MW_BIND; the direct-rkey path must prove
  revocation.
- - Secure msgr2 and classic peers return -95; the caller writes inline
  (documented limit).
- - A sent attempt that ends without a reply (deadline, re-route) resets its
  session, the only proof that the OSD can no longer READ the source.
- - Source-pull pins `MAX_TRANSFER` (64 MiB) per core and device (1 GiB at 8
  cores and two devices). The pinned share comes out of the caches share of
  `osd_memory_target` (adr 0175; startup line `memory envelope:
  flashstore_rdma_source_pull pins ...`); a target whose caches would fall
  below `osd_memory_cache_min` refuses the start with the fix (raise the
  target or turn source-pull off), never a silent over-commit.
- - A failed READ's range is unavailable until its QP is destroyed (normal
  fault path: QP to ERR, drained, destroyed on the control thread); first-fit
  placement routes pulls around it, so it shrinks the room, never stalls
  the core. Only an uncertain destroy keeps a range for good. A payload held
  forever by a consumer likewise shrinks the room; a full-size (64 MiB) pull
  waits until the arena is empty.
- - One pull in flight per session: a session's PUT rate is bounded by one
  READ round trip per PUT (clients use more sessions/OSDs for parallelism).

## Alternatives

- GPU source crc from the caller (ABI argument): NIXL's transfer API carries
  no checksum, so the plugin would need a device-side crc kernel (C++/CUDA
  beyond the thin shim); not taken now (open question).
- GPU source crc by the client CPU over a host-readable mapping (DMA-BUF host,
  mock): only possible for those backings, a CPU pass over device-attached
  memory, and a second rule next to real VRAM; rejected (one rule for every
  GPU backing).
- Direct parent rkey for GPU sources: exposes the whole region (and, for a
  two-way registration, remote write) to the OSD and cannot be revoked per
  attempt; rejected.

- Client RDMA-WRITE into an OSD window: exposes OSD memory, rejected.
- Staged SEND only: host copy, not GPUDirect.
- A private second client with its own writer thread and fixed per-attempt
  limits: only one OSD session (other primaries got -95), app-level timeouts
  and retries instead of the objecter's resend; removed.
- A separate GPU object protocol/opcode: duplicates messenger, durability and
  replication; rejected.
- Pipelined pulls per session (several READs in flight, admission in arrival
  order, later non-pull messages parked behind them): overlaps READ latency
  for small PUTs but needs a parked-message slot, an ordered completion queue
  and their interaction with held input, handoff and close. Not taken until a
  measurement shows per-session small-PUT rate limited by READ round trips.
- Fixed 1 MiB READ slices plus a copy into a new buffer (the first version):
  every PUT != 1 MiB failed, larger ones were impossible; rejected.
- Admitting later ops while the pull is outstanding (the first version):
  broke per-object ordering (A pulled, B inline, B applied first); rejected.

## Open questions

- Exact source descriptor encoding/version and where it sits in the data
  segment (spec work under `doc/spec/rdma-source-pull-contract.md`).
- An optional caller-supplied crc32c for GPU sources (new ABI entry point),
  if a consumer computes one anyway (device-side crc kernel).
- Direct sub-range MR per attempt for providers that cannot MW_BIND a
  DMA-BUF MR (none measured yet).
- SPDK store under knet: the arena is ordinary heap memory, so the store
  stages a pulled payload into DMA memory like an inline TCP payload (one
  copy). Pulling straight into SPDK DMA memory is open.
- Replica strategy for size 3 under GPU read amplification (primary-only is
  the default here; measure the host copy on the primary).
