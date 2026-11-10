<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0471 msgr2 payload placement: OSD-initiated RMA for client ops, fenced by type-2 MWs

Status: proposed
Date: 2026-10-19

## Context

0469-rdma-transport moves msgr2 frames over one RC QP per connection as SEND. Large client payloads still pass through receive slots. RDMA WRITE/READ can move them directly between client buffers and OSD DMA buffers, but a late RMA into a reused buffer corrupts client data, and RETH/BTH headers (VA, rkey, length) are cleartext in every msgr2 mode. Measured (doc/perf/rdma-spike-20261019.md): type-2 MW + SEND_WITH_INV work on mlx5 (late access puts both QPs into ERR); bnxt_re cannot allocate type-2 MWs; READ reaches line rate at path MTU 4096.

## Decision

- Placement applies only to client-direction request/reply pairs: MOSDOp with a data segment (write source) and a single plain READ op -> MOSDOpReply (read destination). Compound ops, sparse reads, EC split ops and all OSD<->OSD, mon and unsolicited messages use SEND.
- Only the OSD initiates RMA. Read: the OSD RDMA WRITEs into the client window, then sends the reply on the same QP. Write: the OSD RDMA READs the client source, then replies. The reply is the interlock.
- No OSD buffer is ever named in a descriptor. Client destinations are REMOTE_WRITE-only, client sources REMOTE_READ-only.
- Correlation key = (connection, tid, retry_attempt); the window segment carries the attempt.
- Descriptor: 1-16 extents `(u64 addr, u32 rkey, u64 len)`, `attempt`, per-4 KiB crc32c `block_crcs`, secure-mode fields. The msgr2 footer covers header and descriptor.
- Fence: the client binds one type-2 MW per attempt. The OSD replies with `IBV_WR_SEND_WITH_INV` of that rkey. On resend, cancel or session reset, local invalidation is only one step; an ordered peer retirement receipt that prevents later posts (or retirement at both QP endpoints) is required before rebinding the MW or reusing the buffer. Quarantine memory if retirement cannot be proved.
- Placement is enabled only where a type-2 MW allocation succeeds at startup (probe by allocation, not by capability bit). Otherwise F_PLACEMENT is not advertised.
- crc mode: the reader verifies `block_crcs` after the RMA and before use. Secure mode: the writer encrypts into the placed buffer with an HKDF-derived per-direction key, explicit 96-bit nonce, AAD = nonce ∥ (connection id, direction, message seq, segment index) ∥ descriptor without tag; the reader decrypts, then verifies. Nonce exhaustion fails the connection.
- The AEAD tag or `block_crcs` are verified before the store references the buffer (adr 0061). A failed verification fails the op loudly with no durable write.
- Any addr/rkey in a reply descriptor is ignored by the client.
- A named buffer is immutable from descriptor emission until fence invalidation and outlives transport completion (adr 0450).
- Memory: the OSD registers the store's DMA buffer pool at pool init; no per-op MR registration on the OSD. The client advertises windows over a fixed pool registered at init or over caller memory registered once through the native API; the type-2 MW fence applies to both. The librados ABI read path uses a staging copy below a size threshold and a registration cache over caller buffers above it (choice and threshold: design D11, spike 1d).
- Per-session RMA credit window: default 32, max 256. Payloads below the in-band threshold (default 64 KiB) use SEND and consume no RMA credit.
- A segment falls back to inline (byte-identical v2) when F_PLACEMENT is not negotiated, no window is advertised, no credit is free, or the op is a retransmission. Retransmissions always go inline.
- crc-mode placement is allowed; a "placement active in crc mode" counter and cluster-log warning make it visible.
- Acceptance requires spike 1a to show a CPU gain over the SEND baseline; the store's registered DMA pool is implemented first.

## Rationale

- OSD-initiated RMA gives the initiator a completion for every transfer and lets the reply bound the pinning time; client pull has no completion at the READ target.
- Type-2 MW invalidation rejects a stale rkey until that MW's 8-bit key tag wraps. The peer-retirement protocol prevents delayed old descriptors from becoming valid again after key reuse.
- Per-session MRs cannot be invalidated per op, so without type-2 MWs there is no safe fence; hence no placement on bnxt_re.
- RETH/BTH are cleartext in every mode, so a secure-only gate adds no memory protection; crc stays the default mode (adr 0036).
- `block_crcs` detect a buffer changed between descriptor emission and RMA completion, and keep the store's no-copy `reseed_4k` path.
- Trade-off accepted: faults cluster around map churn (late RMA = session fault), and a new descriptor and window format in msgr2.

## Consequences

- + No per-byte copy on the placed path; crc/AES-GCM passes remain.
- + crc and secure modes both work without NIC crypto offload.
- + Codecs stay unchanged: the window is a transport-level segment.
- + Classic peers unaffected: descriptors and windows exist only on negotiated connections.
- - msgr2 spec extension: extended preamble/descriptor section, window segment, AAD/nonce layout.
- - Session faults around map changes; fault rate and resend-wave size must be measured (design 1f).
- - Placement exists only on providers with type-2 MWs.
- - Trusted fabric or MACsec/IPsec is a deployment requirement for crc-mode placement against on-path injection.
- - Test surface: descriptor vectors, fence race, fallback matrix, payload replay, nonce reuse, durability ordering.

## Alternatives

- Client-initiated RMA (pull): no completion at the READ target, unbounded pinning (design D1).
- Pre-granted replica receive windows for replication: names OSD memory; rkeys are PD-wide.
- Per-message payload discriminator in each codec: breaks "any message" and misses MOSDMap/PGLog/PGScan.
- Read window as a per-op message field: per-codec change.
- Placement on OSD<->OSD messages: no request carries a window (pull->push is N:M), would name OSD memory.
- Secure-only placement: no memory protection gain, removes placement from the default mode.
- Sendable cluster-wide tokens: widen the security surface; revisit for multi-initiator S3 passthrough.

## Open questions

- Does placement beat the SEND baseline on CPU per op? (spike 1a; acceptance gate)
- BlockCrcs hit rate on real workloads (unaligned writes fall back to a pass); below 90 % placement loses value.
- Secure mode key layout: per-direction keys vs one key with two nonce bases (msgr2 spec §6.1).
- EC scattered placement with per-range integrity: later phase.
- ABI-path large reads (1-128 MiB, KV-cache offload): registration cache vs implicit ODP vs staging; cache hit rate and first-use cost.
- dma-buf MRs (GPU memory) through caller registration: later phase, must not be precluded by the API.

## Amendments

### am. 1 (2026-10-21, proposed): spike 1a result, scope narrowed

Evidence: doc/perf/rdma-placement-spike-20261021.md (harness measurement on ice-b, production crc passes, base vs place; fence cells; not yet in-stack).

- Gate answer: placement beats the SEND baseline on CPU in two quadrants only: client read >= 1 MiB (-0.04..-0.05 ns/B, about 8-10 % of the production client read CPU/B) and OSD write >= 1 MiB (-0.04..-0.07 ns/B, about 7-12 % of the OSD write CPU/B at size 1, 2-4 % at size 3; negative at 4 MiB QD1). OSD read and client write: no gain (< 0.002 ns/B / equal). Below 64 KiB: loss (+10..+80 % of small numbers): not enabled there. QD1 latency of >= 1 MiB objects is worse (+22..+66 %: the crc verify cannot overlap the arrival): open bug, OQ 118. Fence: late access after resend/cancel always faults the QP, window never overwritten (10/10 per scenario, control without the fence corrupts 10/10).
- Decision change: the placement set is narrowed to a single plain READ reply of >= 1 MiB into registered application memory (native API, KV-cache read), opt-in. MOSDOp write sources, compound ops and everything below 1 MiB use SEND; the in-band threshold becomes 1 MiB for placement (replaces the 64 KiB default of "Per-session RMA credit window"). The OSD-initiated READ for writes is not adopted; revisit only if an in-stack `client-cells.sh` run shows >= 5 % OSD write CPU at 4 MiB QD8.
- Acceptance of the narrowed set needs: (1) an in-stack confirmation of the client read gain (decoder adoption of a registered window, rdma-bench mode) and (2) a chunked-verification design (WRITE_WITH_IMM per extent) with no QD1 latency loss in any cell: the +22..+66 % QD1 latency loss of >= 1 MiB objects is an open bug (OQ 118), not an accepted cost.
- Open questions added: placed writes under packet loss (failure at 1 MiB QD4 size 3, not root-caused); secure-mode cost of placement; fence storm (resend waves, fault rate).

### am. 2 (2026-10-22, proposed): require peer retirement before MW reuse

Evidence: RDMA window key-retirement spec (doc not in the source snapshot)
and RXE repro evidence (doc not in the source snapshot).

- RXE confirms that 256 local invalidate/rebind cycles of one type-2 MW repeat
  its rkey. A retained old descriptor then successfully writes into the newly
  bound range. The 8-bit tag is a stale-key filter only until it wraps.
- Decision change: local invalidation is not proof that a peer can no longer
  issue an old descriptor. Do not reuse the MW or destination after resend,
  cancel or session reset until an ordered peer retirement receipt proves all
  earlier peer RMA WRs retired and prevents future posts, or both endpoints
  retire the old QP and its work. Destroying only the local QP is insufficient.
  If neither proof arrives, retain the memory and window owner.
  The placement protocol must add and test cancellation retirement before it is
  eligible for implementation or enablement.
- RXE's single provider result does not prove behavior on other HCAs. The fence
  gate must retain the 256-cycle stale-key case and hardware qualification.

### am. 3 (2026-10-22, proposed): one checked destination descriptor

- Decision refinement: the narrowed single-read destination uses a fixed 44-byte
  version-1 descriptor with one exact range and one `(connection, tid, retry)`
  identity, defined in the descriptor spec (doc not in the source snapshot).
  The codec validates numeric shape only; authentication, negotiated framing,
  reply/cancel retirement and placed-data integrity remain separate gates.
- Rationale: a fixed single-range record matches am. 1's one plain READ scope,
  avoids an extent parser on the initial path, and makes malformed descriptors
  rejectable before any provider operation. It does not enable placement.

### am. 4 (2026-10-22, proposed): successful READ receipt and final marker

- Decision refinement: the successful narrowed READ reply carries a version-1
  receipt with the exact attempt, rkey, written length and raw seed-0 CRC32C
  for every 4 KiB block (including a final partial block). A zero-byte
  SEND_WITH_INV follows the ordinary reply frame on the same RC SQ and is its
  retirement marker. The client waits for the authenticated reply and exact
  key-bearing marker, then verifies placed bytes before use. The record is
  defined in the descriptor spec (doc not in the source snapshot).
- Rationale: the separate marker preserves existing segmented msgr2 framing
  and receive-credit accounting. The receipt binds integrity metadata to the
  attempt. Providers that omit the key-bearing completion fail closed and do
  not qualify for placement.
- Open question: cancellation/error retirement and secure placed-data AEAD
  remain required before F_PLACEMENT may be advertised.

### am. 5 (2026-10-22, proposed): placement negotiation gate

- Reserve msgr2 banner bit 61 for F_PLACEMENT, advertised only with F_RDMA.
  Both banners, an accepted RDMA upgrade and a READY session are necessary
  before placement may be attempted. Decline, fault and reconnect clear the
  stream's active state.
- `Config::placement` defaults off. No production driver enables it until
  provider operation qualification, the full attempt protocol, cancellation
  retirement and secure placed-data integrity are wired. This increment
  defines only negotiation; it does not make placement usable.

### am. 6 (2026-10-22, proposed): cancellation retirement record

- Define a 28-byte version-1 control record for client CANCEL and server
  RETIRED, bound to the exact `(connection, tid, retry, rkey)` of one retained
  destination. The format is in the placement descriptor spec.
- The server marks the attempt terminal before posting RETIRED on the same RC
  SQ behind all earlier WRITEs. The client treats only a matching verified
  RETIRED received on that live QP as ordered peer retirement, then performs
  LOCAL_INV and waits for its CQE before reusing memory.
- A success reply plus key-bearing SEND_WITH_INV can race CANCEL and is an
  alternate terminal proof. Missing proof, QP fault or unknown late CANCEL
  cannot release the window. Runtime state and frame dispatch remain open.

### am. 7 (2026-10-22, proposed): gated placement control frame

- Use msgr2 tag `0xF2` for the v1 CANCEL/RETIRED record on an upgraded,
  placement-negotiated READY stream. Reject other states, directions, segment
  shapes and malformed records at the connection layer. An outbound control
  waits until earlier msgr2 output is drained; the driver must preserve same-SQ
  order behind earlier WRITEs.
- Production consumers close the link if this event arrives before their
  attempt handler is installed. No production messenger enables F_PLACEMENT.

### am. 8 (2026-10-22, proposed): the reply is the successful retirement receipt

- This supersedes am. 4's separate SEND_WITH_INV marker and am. 6's
  success-marker race. For a placed READ, the OSD waits for successful CQEs of
  every WRITE, marks the attempt terminal so no later WRITE can be posted, and
  sends the ordinary successful MOSDOpReply with the exact v1 `ReadReceipt` in
  its middle segment and no data segment on the same RC QP. That reply is the
  ordered peer-retirement receipt. The client matches its authenticated or
  CRC-checked frame, exact attempt and rkey, then posts LOCAL_INV. Only after
  its CQE may it verify the placed bytes and return them to the application.
- An error MOSDOpReply carries the exact v1 RETIRED record in its middle
  segment after the OSD has stopped and retired all WRITE WRs. A standalone
  RETIRED control answers CANCEL. A success or error reply may race CANCEL;
  the client accepts whichever matching terminal proof arrives first and keeps
  the owner until LOCAL_INV CQE. A fault or missing proof quarantines it.
- Provider qualification requires type-2 MW BIND/LOCAL_INV, RMA WRITE, and
  ordered same-QP SEND with confirmed WRITE CQEs. Key-bearing SEND_WITH_INV is
  not a requirement. The unused experimental SEND_WITH_INV receive path is
  removed when the runtime adopts this contract.
- Rationale: the RC send queue orders packets (NVIDIA RDMA manual,
  https://docs.nvidia.com/rdma-aware-networks-programming-user-manual-1-7.pdf),
  and a WRITE CQE provides data-visibility completion including prior transfers
  (rdma-core MR manual,
  https://man7.org/linux/man-pages/man3/ibv_reg_mr_iova.3.html).
  The RXE host test exercises WRITE CQE, exact RETIRED record, local
  invalidation and byte verification. This removes an extra SEND and the RXE
  WITH_INV provider incompatibility while preserving the peer-retirement
  requirement of am. 2. GPU visibility additionally requires the CUDA
  synchronization specified by NVIDIA
  (https://docs.nvidia.com/cuda/gpudirect-rdma/); host CQEs alone do not
  qualify GPU memory.
- Open: the integrated reply/cancel race and secure placed-data AEAD still
  block advertisement; in-stack latency and CPU gates must confirm the gain.
