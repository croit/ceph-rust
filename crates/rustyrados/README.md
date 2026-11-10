# rustyrados
Experimental native Rust RADOS client, wire target pinned Ceph 21.1.2. Default features empty. License: MPL-2.0 (see COPYING-MPL-2.0 and adr/0164); Copyright croit GmbH and contributors. Release compatibility and performance are not yet qualified.

The crate exports the single-owner, !Send/!Sync `ObjectQueue` (`ReadQueue` alias), owned immutable `Bytes` inputs/results, bounded admission/completion slots and stable request identity. Drivers authenticate frames, supply validated replicated acting-primary placement and transmit the exact dispatch TID. Queue credits exclude transport/codec storage and application-retained results.

Implemented engine contracts:
- HEAD reads, WRITE/WRITEFULL/APPEND, ordered compounds with captured snapshot/context, binary xattr/omap and class forwarding; exact overall/per-op status and owned outputs.
- Successful writes require ONDISK. Queue-prefix fences preserve earlier holes/failures; explicit retirement invalidates old fence epochs without resetting wire TIDs.
- One attempt by default. Explicit bounded read retry; opted-in mutation resend requires an absolute deadline and immutable identity/payload. Finite Ceph duplicate history is not an unbounded exactly-once guarantee.
- Indexed absolute operation deadlines, budgeted expiry and sent/unsent cancellation uncertainty; retry never extends the deadline.
- Bounded backoff and ready recovery primitives, exact BLOCK ACK, original-range release, typed session failure, rejection dominance and validated primary-read EAGAIN classification.
- Typed watch/notify control operations and bounded event registry with stable cookies, peer/session checks, explicit ACK and initial/final result race handling.

It also exports standalone transport-neutral CLIENT monitor bootstrap and `OsdAuth`. Bootstrap fixes FSID/global identity and gates initial readiness on authenticated map/ticket. `OsdAuth` captures an OSD ticket snapshot, validates caller-updated wall-second clock/expiry, creates a fresh nonce per exchange and publishes only verified mode-compatible secrets. Failure is terminal; recreate from renewed credentials. No kernel sockets or hidden clock inside either library component.

`rados-rt` owns the userspace TCP/DPDK monitor adapter: bounded slots/work/TX staging, per-mbuf RX checksum verdicts and a separate close TX drain. CRC/Secure bootstrap qualified with DPDK AF_PACKET in an isolated VM. Production shared OSD/monitor object coordinator, pooled hot-path buffers, physical VF/RSS and throughput remain open.

Lab `oprobe/native-read` uses the native object engine and native OSD authorizer over feature-gated development kernel TCP. It is a conformance driver, not the production runtime. Own tests and classic CRC/Secure scenarios cover reads/writes/compounds/watch primitives, deadlines, durable lost append reply, PG-inactive backoff and session recovery. This is not full W/N qualification.

Remaining: automatic watch timers/reconnect, snapshot creation/control, enumeration/control API completion, map/full/pause/barrier recovery, bootstrap renewal/failover matrices, shared production object transport, mixed croit-flashstore-osd/target-platform/equal-resource performance gates. Dispatch/codec metadata still allocates; no allocation-free hot-path or speedup claim.

Build01 affected checks: `cargo test -p rustyrados --locked`; `cargo test -p oprobe --features native-read --locked`. Specs/ADRs and evidence: (design doc: plan-rados-client.md - not included in this snapshot), (design doc: perf/rustyrados-osd-auth-2026-10-14.md - not included in this snapshot). C/C++ librados ABI, native RBD/KVM and RDMA remain separate scope.
