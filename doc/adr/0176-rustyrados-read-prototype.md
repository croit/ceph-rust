# 0176 rustyrados first read increment
Status: accepted
Date: 2026-10-14
Context: user requested implementation after [ADR: rustyrados name and transport](0450-rustyrados-name-and-transport.md). Begin P1 with the measured read-copy opportunity; full P1/runtime/retry contracts remain open. Own implementations use existing own-words client-ops sections 1/2/3/7 and RC-REQ/LIFE/RT/API, not Ceph source.

## Decision
- `rustyrados/experimental`, default off: sans-IO single-owner HEAD read queue. Runtime capacity and byte limits are caller choices, not claimed server limits.
- Binary pool/object/namespace/locator context captured at submit. Positive u32 read length only; zero wire length means to EOF and is rejected until an explicit output-cap contract exists. Reject extent arithmetic overflow.
- One queue per authenticated identity for this increment. Allocate monotonic nonzero header TID once; queue-local token includes queue/slot/TID, protecting slot reuse and cross-queue events. Queue is !Send/!Sync. Driver keeps identity/incarnation fixed.
- Preallocate slots/free/completion storage. Charge requested output length plus retained target Vec capacities; keep slot/credit until completion consumption. Driver/codec/transport allocations, Bytes backing allocation size and application-retained results are outside these credits. No total-RSS boundedness or allocation-free dispatch claim.
- Route from audited map/session driver; replicated acting primary only, no EC messages. One dispatch, attempt 0, implicit reqid with fixed incarnation and stable header TID. No automatic retries, remaps, snapshots, ordering/fences, writes or watch/control API.
- Read result moves immutable `Bytes` from validated reply into completion. Do not copy to a caller destination. Complete frame/authentication is a driver prerequisite; validate object/PG/session/attempt/op/count/length/flags/status before publishing. Preserve overall/per-op errno and user_version separately.
- Cancellation before handoff = definitely unsent; after handoff = possibly sent. Conservative handoff precedes socket write. Exactly one terminal notification; stale/canceled events cannot affect reused slots. No remote rollback claim.
- `oprobe/native-read`, default off: consume fresh Probe to reuse existing CephX/mon/map/msgr2/kernel transport only. Never use `Probe::exec` for native requests. Unsupported backoff/messages fault connection and resolve outstanding reads locally; no resubmission. Kernel/blocking/scanning/HashMap allocations remain lab-only.

## Consequences
This is an experimental read prototype, not a usable full librados replacement or a performance result. Metadata/message encoding still allocates; existing msgr2 receive path remains. Production DPDK reactor, bounded driver buffers, control fairness, stable retry state, writes/fences and the complete native API follow separate tested increments. Future RDMA ownership follows [ADR: rustyrados name and transport](0450-rustyrados-name-and-transport.md); no RDMA implementation here.

Alternatives: reuse synchronous Probe retry loop (changes logical TIDs); implement all operations immediately (delays measured read gate); claim zero-copy networking from owned outputs (unsupported: only result-boundary copy removed).
