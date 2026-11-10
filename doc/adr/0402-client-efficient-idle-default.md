# ADR 0402: efficient idle is the default client requirement
Status: accepted, amended (am. 1, am. 2)
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): DPDK/userspace-TCP opt-in is history; the rest stays valid.
Date: 2026-10-15
Context: user2026-10-15 identifies efficient idle as the normal librados application requirement, including future KVM consumers. Existing [ADR: rustyrados name and transport](0450-rustyrados-name-and-transport.md) selects production DPDK/userspace TCP and dev-only kernel TCP. Dedicated busy polling assumes an explicitly reserved core; applying that as the default client deployment is not justified by the measured VM throughput baseline. Server transport decisions remain separate.

## Required behavior
Normal client instance must not reserve/busy-poll a core while idle. Application submission/completion API does not require busy polling. Waits must observe new requests, RX, writable/backpressure progress, cancellation/close and earliest auth/map/watch/TCP/request timer; no lost wakeups, deadline extension or hidden busy-loop fallback. Measure many idle clients, not only throughput of one saturated worker. Explicit dedicated-core performance mode remains possible.

## Decision
Production default: event-driven OS TCP reactor driving existing TcpOwner/ObjectClient/NativeSessions, preserving the same engine/codec/auth/request policies. DPDK/userspace TCP retained as explicit opt-in performance transport; no automatic transport switch for uncertain mutations. Supersedes only [ADR: rustyrados name and transport](0450-rustyrados-name-and-transport.md)'s dev-only kernel restriction for the CLIENT. croit-flashstore-osd remains DPDK/SPDK. Public API and internal driver boundaries must permit external event-loop integration and shared reactors; no mandatory thread/VF per client identity.

Alternative: keep DPDK default with RX interrupt registration, race-free arm/recheck/wait, application notification and timer integration. DPDK interrupt support varies by PMD; existing Port wrapper exposes bursts/queue count but no interrupt wait contract. A periodic sleep can reduce CPU but adds idle request/packet latency and wakeup load; not equivalent to an event-driven idle default. Unsupported PMD must not silently burn a core. Power/monitor instructions alone do not prove scheduler-idle CPU efficiency.

User decision2026-10-15: "ja Kernel TCP mit möglichst vielen optimierungen ist das richtige". Kernel TCP is the production default direction; optimize using measured idle CPU, thread/memory footprint, copies, syscall batching and latency/throughput at equivalent resources. DPDK remains optional. Exact CPU/wakeup/latency acceptance thresholds require baseline measurement; this decision does not itself qualify the implementation.

## Qualification
Report no-I/O CPU seconds per wall second, wakeups/context switches, thread/VF/queue/memory per client,1/10/100 identities where lab resources permit, with no watches and with watch/auth maintenance. Quiescent then first request latency p50/p99, burst/low-rate/saturated workloads, after transient loss/backpressure, CRC/Secure. Compare tuned librados at equal total resources. Validate RX/submission arriving before/while/after arming wait, expired/earliest timers, stop/cancel and no missed ready work. Never trade correctness or fixed deadlines for low CPU.

Implementation qualification is tracked separately; ADR0228/kernel-lab proves initial no-operation idle only. No complete production kernel support is qualified by this ADR. Existing AF_PACKET busy-loop fixtures remain functional qualifiers, not the intended general-purpose scheduling model.

## Amendment (2026-10-20): epoll default, io_uring opt-in backend (am. 1)

The kernel TCP reactor has two backends: epoll (default, no io_uring probe) and io_uring (opt-in `rustyrados_transport_backend = io_uring|auto`; `auto` probes and falls back to epoll). Efficient idle is mandatory for both. Zero-copy sends of owned buffers above a derived threshold. Design: [adr 0466](0466-rustyrados-io-uring-transport.md).

## Amendment (2026-10-28): DPDK/userspace-TCP client excluded from standard builds (am. 2)

DPDK is deprecated (user 2026-10-28). The rustyrados userspace-TCP/DPDK client (`ClientTcp`, `DpdkClient`, `dpdk-*` examples, sim tests) stays in the tree behind the opt-in rados-rt features `userspace-tcp` (own TCP stack, no DPDK libs) and `dpdk` (implies it); no standard, package (`package-elf.sh`, e2e libs image) or CI build enables them, so `net` and `smallvec` are not linked into `librados.so.2`. `scripts/check-prod.sh` keeps them compiling and runs the sim tests. The shared sans-IO `TcpOwner` protocol (`tcp_owner.rs`) is in every build. Internal id maps use `foldhash` (`TidMap`). Unreferenced client code removed in the same cleanup: `ClientGroup`/`SharedClient` (adr 0233 superseded).
