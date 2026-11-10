# 0458 RADOS client replacement and compatibility gates
Status: accepted. Amended by 0402 (transport), 0256/0305/0306 (C ABI scope)
Date: 2026-10-14
Context: croit-flashstore-osd performance reports indicate possible client limits. User requested RADOS first as the future RBD foundation, branch `feat/ceph-client`, then a plan/specification. Clarification 2026-10-14: wire compatibility with classic BlueStore clusters is primary; application API may change; KVM/other applications later. Published results do not establish a speedup on our hardware.

## Decision
- Green-field Rust request engine; implement from own-words specs, never Ceph code. Reuse audited protocol crates; do not depend on `osd`, `peering`, `store`, or Ceph libraries.
- Explicit compatibility levels: wire client, native Rust library, C API/ABI, C++ API/ABI. A read/write prototype is not a drop-in library.
- Target the pinned Ceph 21.2.0 first, including classic-only clusters. API/ABI target is the pinned librados build, not the server's version string.
- Required release claim: W/N (wire-compatible native client). The C API/ABI is now a goal (librados C/C++ symbol parity per 0256/0305/0306; C++ foreign-context claims stay gated). Foreign `CephContext` interchange and C++ buffer/STL ABI block only those optional claims; symbol names alone are insufficient.
- Queue-oriented native API; one owner per request/session/buffer in the normal path. Optional C adapter would preserve observable threading, ownership, completion and flush contracts even when that needs copying or callback dispatch.
- Initial session model: one authenticated client instance, one owned connection per destination OSD. Additional lanes require a separate identity/order/fencing ADR and classic interoperability proof.
- Transport: event-driven kernel TCP by default (0402); DPDK/userspace TCP explicit opt-in. No SPDK dependency in the RADOS core.
- Preserve CRC/Secure negotiation, durable completions, compound atomicity, request identity across retries, backoff, map admission and pool/shard validity.
- Performance hypotheses measured against tuned librados under equal total CPU budgets. No numeric speedup commitment.

## Consequences
- Native RBD can use the same engine without C API buffer/callback overhead.
- Unchanged upstream C++ librbd/RGW cannot be promised to load this library until C++ and buffer ABI gates pass.
- Wire client supports a deliberately documented native surface. Full librados ABI replacement would additionally include low-frequency admin APIs, deprecated/versioned exports and context interchange; not required now.
- Partial builds have distinct artifact names and advertised coverage; never install globally as `librados.so.2` before the declared profile passes.

Alternatives: tune librados only (required baseline, insufficient to establish an ownership redesign); link Ceph libraries (rejected by ADR 0003); one client identity per worker immediately (deferred: retry/order/fencing complexity); C++ shim (unresolved against Rust-only/clean-room constraints).
Plan: plan-rados-client.md (doc not in the source snapshot). Contracts: rados-client/README.md (doc not in the source snapshot).
