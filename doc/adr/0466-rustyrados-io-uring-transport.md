<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0466 rustyrados: epoll default, io_uring opt-in transport, zero-copy sends

Status: accepted (user decision 2026-10-20: both backends kept, epoll default, io_uring opt-in), amended (am. 1, am. 2, am. 3, am. 4)
Date: 2026-10-19
Amends: 0402 (am. 1)

## Context

0402 makes the event-driven kernel TCP reactor (`rados-rt` `KernelTcp`, mio/epoll) the client default. User decision 2026-10-19: target current distributions; the newest major distros get the best path, old enterprise kernels never block a better design. io_uring was to be preferred when it works; the A/B (Consequences) changed that, see Decision. RHEL disables it by default (`kernel.io_uring_disabled`) and Docker's default seccomp profile blocks it, so epoll remains an automatic fallback. The OSD already probes real io_uring capability instead of kernel versions (0098) and uses `SENDMSG_ZC` above a threshold (0053). Client write payloads are copied from caller memory at submission (rados-ffi fuses copy and CRC into an owned `Vec`), so the transport sees immutable owned `Bytes`.

## Decision

- `KernelTcp<D>` is a dispatcher over two drivers with one owner contract (`TcpOwner`, bounded per-step credits, retained suffixes, receive loans): `UringTcp` (Linux) and `EpollTcp`. Owner, engine, codec, auth and policies are unchanged.
- Default backend is epoll; no io_uring probe runs and no ring is created (no startup cost, no ring memory). The request is the rados conf key `rustyrados_transport_backend = epoll|io_uring|auto` (default `epoll`, validated at `rados_conf_set`, carried in `KernelTcpLimits::backend`): `io_uring` requires the backend and construction fails (`Unsupported`) when its probe fails; `auto` probes at the first client start of the process and falls back to epoll. The choice is by probe, never by kernel release. One report per effective choice and process, one loud line `rados-rt transport backend=<io_uring|epoll> zero_copy=<send_zc|msg_zerocopy|off> zc_min=<bytes> zc_window=<bytes|unlimited> probe_ms=<ms> missing=[...] reason=...` on stderr, and the same fields as JSON through the read-only key `rustyrados_transport` of `rados_conf_get` (reports the configured choice) and `rados_rt::transport_report_for(choice).json()`.
- User exception to the "no default-off leftovers" rule (2026-10-20): the io_uring driver stays in the tree as an opt-in although it lost the A/B. Reason: it halves syscalls per op (30 % at QD1, 50 % at 4M) but loses 10-19 % at 4M without zero copy and gives no CPU gain at 4K; re-evaluate once the single-reactor limit (about 1 core, 2.5-3.5 GB/s) is gone, because that limit hides what the cheaper submission path could give.
- The probe (own implementation, MPL-2.0; same method as 0098, no code shared with the LGPL `rt` crate) runs on its own thread (ring teardown and pinning queue task work to the creating thread, which would interrupt a blocked caller syscall) and takes about 10 ms (epoll) to 50 ms (io_uring):
  - real ring creation in the first mode that passes the exercise: deferred task run (`SINGLE_ISSUER | DEFER_TASKRUN | TASKRUN_FLAG`), cooperative task run (`COOP_TASKRUN | TASKRUN_FLAG`), plain; `IORING_FEAT_EXT_ARG` and `IORING_FEAT_NODROP`, `IORING_REGISTER_PROBE` for RECV, SEND, SENDMSG, CONNECT, ASYNC_CANCEL, POLL_ADD (and SEND_ZC as optional) (am. 4);
  - functional exercise on a private loopback pair: CONNECT, SEND, RECV (with `POLL_FIRST` in the deferred mode), the multishot eventfd poll (the wake path, two wakes) with data verified, bounded 1 s per completion with `WARNING TIMEOUT`; SEND_ZC with its result and notification completion; for the epoll backend `SO_ZEROCOPY` + `MSG_ZEROCOPY` with the error-queue completion.
  - Any failed required item selects epoll; reason and missing capabilities are kept in the report.
- `RADOS_TRANSPORT_BACKEND=auto|epoll|io_uring` is a diagnostic override of the conf key. `RADOS_TRANSPORT_ZC_MIN=off|<bytes>` overrides the derived zero-copy threshold for diagnosis.
- Efficient idle (0402) holds for both: the wait is one blocking `io_uring_enter` (min_complete 1, timeout = earliest owner timer) or `epoll_wait`; no SQPOLL/IOPOLL/busy wait. Cross-thread wake is an eventfd with one multishot poll (armed once, re-armed only when a completion ends it) (am. 4) or the mio waker; a wake written before the wait stays pending. Timers are the owner's `next_timer` as the wait bound.
- io_uring driver: one `RECV` per connection, direct into the owner's receive loan (`MSG_WAITALL` over the loan window, which is the rest of the frame, bounded by the step credit) or into a per-connection scratch buffer; one `SENDMSG` (or one single-run `SEND_ZC`) in flight over all staged output with `MSG_WAITALL`; write backpressure (`tx_would_block`) = a send still owed at a drain point (am. 4). Memory the kernel may touch (targets, iovecs, leased runs) lives in boxed links that outlive their connection as zombies until every completion is reaped; teardown drains them with a bounded wait and a loud `WARNING TIMEOUT`, and leaks rather than frees memory the kernel may still write.
- Zero copy applies to large owned runs only:
  - io_uring: `SEND_ZC` with notification completions; epoll: `MSG_ZEROCOPY` with `MSG_ERRQUEUE` completion ranges read on the error event.
  - Only buffers the transport already owns immutably (`Bytes` leases from the owner output, including secure-mode ciphertext) are sent zero-copy; caller memory is never referenced (the FFI contract lets the caller reuse its buffer when the submit call returns, and the submission copy carries the CRC). A lease is released at the notification, not at send completion. A socket with outstanding leases is reset (`SO_LINGER 0`) when it is torn down: queued pages are freed only with the socket and a graceful close would wait for a peer that may never read.
  - Threshold derived at start: smallest run where copying costs more than the fixed cost of a zero-copy send, `len * copy_ns_per_byte > fixed`, rounded up to pages; copy cost = cold 32 MiB memcpy (lower bound of the avoided kernel copy, which also allocates and clears socket pages), fixed cost = measured extra thread CPU time of a 4 KiB zero-copy send over a plain one (notification, accounting, pinning of its page; waiting for the notification is latency, not cost). No separate per-page pin term; floor `msgr2::ZC_MIN` (smaller runs are copied into the frame by the encoder anyway) (am. 1).
  - A connection whose zero-copy sends the kernel copied anyway (epoll: `SO_EE_CODE_ZEROCOPY_COPIED` in the error-queue completion; io_uring: `IORING_NOTIF_USAGE_ZC_COPIED` with `IORING_SEND_ZC_REPORT_USAGE`, used when the probe's SEND_ZC accepts the flag) sends by copy from then on, with one warning line.
  - Pinned bytes in flight are bounded process-wide by a window derived from `RLIMIT_MEMLOCK` (unlimited with `CAP_IPC_LOCK` or an unlimited limit, else half the soft limit; off when it leaves less than two pages); `ENOBUFS`/`EOPNOTSUPP` at runtime turn zero copy off for that connection with one warning.
- Apart from the exception above no default-off leftovers: experiments that lost were removed.

## Amendment (2026-10-22): zero-copy threshold without the pin proxy, copied-send fallback (am. 1)
- The `mlock`/`munlock` pin proxy (VMA locking and memlock accounting, about 500-600 ns/page) is not the fast-path page pinning of a zero-copy send and kept zero copy off on every measured host (zen4b client VMs, rental client host). Forced zero copy (`RADOS_TRANSPORT_ZC_MIN=65536`) cut client cycles/op of 4M QD8 writes by 25 % at equal throughput (doc/perf/rados-client-fix-20261022.md). The model now weighs the copy against the measured fixed CPU cost only (wall time had made the io_uring fixed cost look like 100 us per send: a 3 MiB threshold), floored at the encoder's by-reference threshold. Derived on the build host: epoll 8-44 KiB, io_uring 112-340 KiB.
- The kernel's own verdict replaces the proxy where zero copy degenerates: a copied completion switches that connection to copy sends (both drivers; loopback test `zero_copy_the_kernel_copies_anyway_falls_back_to_copy_sends`).
## Amendment (2026-10-23): a zero-copy piece reaches the threshold (am. 2)
- The derived threshold weighs one send's fixed cost against the copy it saves, so the piece itself must reach it. A piece is the front run up to the larger of the step credit and the threshold (`transport::zc_piece`); a run of at least the threshold also ends a copy batch by its whole length. Before, io_uring thresholds above the 256 KiB step credit (build host 112-340 KiB) never sent zero-copy and epoll could zero-copy pieces below its threshold. Both drivers; one step may exceed its credit by at most one threshold.
- The pinned window stays half of `RLIMIT_MEMLOCK` (no CAP_IPC_LOCK): 8 MiB container limits leave a 4 MiB window, so concurrent 4 MiB writes fall back to copy beyond it (operator guidance, not an OSD-side setting).
## Amendment (2026-10-23): epoll driver turn work like the io_uring driver (am. 3)
- A receive that returns less than its window drained the socket: the link is not readable until the next edge (edge-triggered registration: data arriving later raises one), so the read that would only return EAGAIN is skipped (QD1: one `recvfrom` per op less).
- The owner pass after a pump runs only when the pump moved bytes (either direction), ran commands or changed a connection; a pump that moved nothing gives the owner nothing new (owner changes without input come from timers, checked by every pass; the sleep proof asks the owner). The pass after the poll always runs.
- A step may sleep after a send that left nothing staged (the io_uring driver always could): local readiness (writable link with staged output) and the owner's sleep proof cover pending output. QD1 saves a turn and an `epoll_wait` per op.
- Measurements: doc/perf/rustyrados-beat-stock-20261023.md.
## Amendment (2026-10-29): deferred task-run ring, step passes, whole-output sends (am. 4)
- Why io_uring lost (measurements: doc/perf/rustyrados-uring-redesign-20261029.md): every receive completion and every bookkeeping completion (send, notification) ended the step and cost the caller a full owner turn; 64 KiB replies need 2-3 receives; the eventfd read was re-armed after every wake.
- Ring mode by probe (see Decision): the driver is `!Send` (raw iovec/msghdr pointers in its links), so the creating thread is the stepping thread, as `SINGLE_ISSUER` requires.
- One `io_uring_enter` per pass (submit + `GETEVENTS`; blocking only when the owner can sleep). A step runs further passes instead of returning while a receive completion reports more queued data (`IORING_CQE_F_SOCK_NONEMPTY` or a full scratch window), and after a blocking wait ended only by completions the owner never sees while wait time is left. Bounds unchanged (events, byte credits per step).
- Receive re-armed after it drained the socket: `IORING_RECVSEND_POLL_FIRST` (deferred mode).
- Receive chain: a pass whose receives left data queued re-arms only those receives and runs the next pass without an owner turn (no tick, commands or full arm), as the readiness driver reads a socket until it drains; a completed message stops its connection's chain (`can_receive`) until the owner turn dispatched it. Without it every such pass paid a full owner turn.
- Send: all staged output in one send (`MSG_WAITALL`, at most 1 GiB), no per-step credit cap; the staging reservation per slot (`staged_output_bytes / connections`) still bounds it. A zero-copy run goes out whole when the pinned window has room for it, else as an am. 2 piece, else by copy.
- Result: doc/perf/rustyrados-uring-redesign-20261029.md (lab-c anatomy, zen4 gate blocks 1 and 2). Open: io_uring 64k q16 behind epoll with several owners (A2).

## Rationale

- Probing real behavior covers distro backports, sysctl and seccomp that release numbers cannot (0098).
- epoll stays because RHEL's default and containers block io_uring; the user decision rules out version gates.
- Zero copy only on owned immutable buffers keeps the librados ownership and completion contracts exact.
- A derived threshold and a memlock-bounded window avoid magic constants and unbounded pinning.

## Consequences

- + Working path everywhere: Docker default seccomp was verified to select epoll automatically with the reason in the line.
- + Syscalls per op fall 30 % (QD1) to 50 % (4M) with io_uring; idle CPU of 100 clients equals epoll (0.4 % of one core, 201 threads, +17 MiB for the rings).
- - Measured (doc/perf/rados-client-transport-ab-20261019.md): no consistent throughput or cycles/byte win over epoll. 4K cells within noise; 4M reads and writes without zero copy 10-19 % below epoll in most sessions; forced zero copy ahead of epoll on 4M QD32 writes in 3 of 5 sessions. The derived threshold keeps zero copy off on the lab VM. Session drift is +-15 %.
- - Two drivers to keep equivalent; `transport_tests` runs the same loopback scenarios (exact bytes, wake, idle, teardown with sends in flight, peer close) on both, with copy and zero-copy sends.
- - Leases outlive request completion by the notification latency and are not charged to the staged-output ledger.
- Siblings: OSD knet (0053/0098) shares the probe idea only (separate code, licenses differ). crc and secure msgr2 use the same lease rule. AF_XDP/DPDK client transports unchanged.

## Alternatives

- Kernel version gate for io_uring: rejected by user decision and 0098.
- Zero copy from caller memory: breaks the buffer-release contract and loses the fused CRC pass.
- SQPOLL / polling completions: violates efficient idle (0402).
- Replace epoll entirely: breaks RHEL/Docker defaults.
- Deferred task-run ring as a flag change alone: no consistent gain in the 2026-10-20 A/B (4M read); adopted in am. 4 together with one enter per pass, which removes the task-work interrupts and turns it was meant to save.
- Completion-free sends (`IOSQE_CQE_SKIP_SUCCESS`) to save the QD1 wait that an inline send completion ends: rejected, the driver would not learn when the output may be released.
- Multishot receive with provided buffers: not built; direct placement into the receive loan avoids a copy per byte and the A/B shows the receive cost is the kernel copy.

## Open questions

- Switch the default to `auto` once io_uring is >= epoll in every cell (doc/90-open-questions.md 78).
- One unreproduced 4K write timeout on io_uring under `perf record` (79).
- Read throughput is capped by the single reactor thread on both backends (80).
