<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0485 Registered client memory: native librustyrados extension

Status: accepted
Date: 2026-10-21

## Context

The user requires native RADOS storage access for a future NIXL plugin without modifying NVIDIA KVBM or NIXL. ADR 0450 permits native extensions while ADR 0256 preserves librados application contracts. ADR 0469 implements SEND transport; ADR 0471 remains proposed and its amendment narrows placement to opt-in plain reads of at least 1 MiB. Its host-memory spike does not qualify GPU registration, memory-window binding, visibility or integrity.

## Decision

- The public extension belongs to librustyrados; no new public library or dependency on NVIDIA orchestration code.
- `rdma` owns provider registration, protection-domain identity, bounded ranges, memory windows and access retirement. `rustyrados` owns object request semantics; `rados-rt` associates registrations with sessions, attempts and completions. `rados-ffi` preserves existing C/C++ ABI and ownership; future extension symbols use a distinct `rustyrados_` prefix.
- Registration owns or retains its backing allocation. Numeric-address caches over application allocations are forbidden. GPU memory uses an opaque owner and descriptor, never `Bytes` or a CPU slice.
- Registration lifetime, operation outcome and access retirement are distinct. Timeout, cancellation, a received error and dropping a request handle do not prove that NIC access ended.
- A read destination is exclusively owned until all attempts are retired, integrity is verified and the documented host/CUDA visibility operation completes. Completion returns the bounded initialized range, not unspecified allocation contents.
- Placement requires the negotiated capability, the owning protection domain and a per-attempt type-2 memory window. Connection/TID/attempt correlation, ordered peer retirement and window invalidation before reuse apply to retries as well as cancellations (ADR 0471 am. 2).
- Direct-only requests fail before advertising a window when unsupported. Staging, when explicitly allowed, is reported in the result and completes through the same ownership contract. GPU staging requires an implemented device copy path; inline decoding never CPU-dereferences HBM.
- Registration and provider control calls run outside the progress hot path. Operations lease existing registrations; no per-operation MR registration, allocation or registration-table lock on the hot path.
- The first code increment hardens the existing SEND registration API and adds owned immutable host registration. It enables neither F_PLACEMENT nor GPU support. Wire placement acceptance remains governed by ADR 0471.
- The opt-in `registered-memory` feature adds native owned host read destinations. The staged implementation moves the caller's initialized `Vec<u8>` through admission, retry and completion; success publishes only the returned extent and reports `Staged`. Direct-only is rejected before dispatch while placement is unavailable. Logical request admission charges the requested byte count; the caller supplies the allocation. No GPU address or unowned pointer enters this API.
- The executable contract and implementation gates are in `doc/spec/rados-client/registered-memory.md`. No performance or release qualification follows from implementing types or passing soft-RoCE tests.

## Rationale

One client retains existing authentication, routing, request identity and durability handling. Separating memory ownership from transport completion prevents stale NIC access to reused allocations. An opaque GPU descriptor avoids extending CPU-buffer assumptions to device memory. A narrow owned-registration increment can be tested against the existing SEND plane before changing the wire protocol.

## Consequences

- + A future NIXL backend can adapt descriptors to the native client without another RADOS implementation.
- + Existing librados calls retain their current signatures and ownership semantics.
- + Caller allocation lifetime is retained by the registration rather than inferred from an address.
- - End-to-end placed reads need protocol, decoder and runtime changes plus the ADR 0471 performance gates.
- - GPU destinations and sources require hardware evidence and device-side verification/ordering.
- - C plugin-facing extensions are not available until their handles, concurrency and retirement contracts are implemented and tested.

## Alternatives

- Separate RADOS/RDMA library: duplicates authentication, maps and failure semantics.
- NVIDIA KVBM/NIXL changes in this increment: outside the user's authorized scope.
- Reuse host `Bytes` for GPU allocations: permits invalid CPU access and lacks GPU visibility semantics.
- Registration cache keyed only by virtual address: freed/reused addresses do not establish allocation identity.
