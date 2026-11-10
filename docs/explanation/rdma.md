<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# Explanation: the RDMA transport

RDMA is an optional upgrade of croit-flashstore-osd connections on top of the kernel TCP tier. It moves the byte stream of a connection from the kernel TCP stack to a hardware queue pair on a RoCEv2 NIC. It is off by default and changes nothing for peers that do not use it. To switch it on, see [how to enable RDMA](../how-to/enable-rdma.md).

## What it is

Every connection starts as a normal Ceph msgr2 connection over TCP, including the full authentication. When both ends have RDMA enabled, they swap queue-pair details inside that authenticated connection and continue the same msgr2 session over one reliable-connected (RC) queue pair. The messages, sessions and cephx keys are the same. Only the carrier of the bytes changes.

- Both peers must enable RDMA. Each side advertises it in the msgr2 handshake. The handshake is part of the authenticated transcript, so a peer cannot add or strip the advertisement unnoticed.
- The upgrade is an offer. If the peer declines, has no RDMA, or a precondition is not met, the connection simply stays on TCP. This is never an error.
- Classic Ceph OSDs, monitors, managers, classic clients and older croit-flashstore-osd builds never see the advertisement and always stay on TCP. A mixed acting set works: replica traffic between two RDMA-enabled croit-flashstore-osd goes over RDMA, traffic to a classic OSD stays on TCP.
- Monitor, manager and heartbeat connections never upgrade.
- A peer on the same host never upgrades: its traffic would loop through the NIC, compete with the real inbound traffic of the port for buffers and PCIe bandwidth and make the NIC drop it, while kernel TCP over loopback is a memory copy. A client on an OSD host therefore uses RDMA only towards the OSDs on other hosts.
- The TCP socket stays open for the life of the upgraded connection but carries no data. It is the liveness channel: an RC queue pair does not tell the passive side when the peer closes or dies, the closed socket does. Any byte arriving on it is a protocol fault and closes the connection.
- The upgrade happens on the core that owns the connection. A connection that is handed to another core or relayed stays on TCP.
- The OSD supports IPv4 addresses. The RDMA device is the one whose network interface carries the connection's local IP, and the peer's RoCEv2 address must match the TCP peer address.

RDMA works only next to the kernel TCP transport. It is not a separate transport: kernel TCP still carries the handshake, the liveness socket and every connection that is not upgraded. See [network transport](network-tiers.md).

## What it changes

The OSD spends less CPU per byte: TCP stack work and socket-buffer copies leave the data path. Large replies and replica writes are sent zero copy from registered payload memory, so the NIC reads the payload where it already is. The checksum pass (msgr2 `crc` mode) or the encryption pass (`secure` mode) stays.

RDMA can increase throughput and lower the CPU cost per byte on both the OSD and the client, for large and small I/O. How much depends on NIC, CPU, fabric and workload; measure on your hardware. With the OSD alone (a classic or TCP client) the gain is limited to the replica and reply traffic that is itself upgraded.

## Memory

RDMA needs pinned (registered) memory. It has its own budget, `flashstore_rdma_memory` (default 256 MiB for the whole OSD process). This memory is on top of `osd_memory_target`; the target's split is not changed.

- The budget is divided equally over cores times RDMA devices. One device exists per distinct OSD address (public and cluster address on the same NIC count once).
- Of each part, two thirds are receive slots (64 KiB each, one shared receive queue per core) and one third are send slots.
- The memory is fixed per core. It never grows with the number of peers or connections. All sessions of a core share the receive slots.
- A part below 6 MiB is refused at start. The default 256 MiB covers 8 cores on two devices (16 MiB per part).
- A core holds at most `receive slots / 3` sessions: 113 per core at the default 256 MiB on 8 cores and one device. A connection beyond that, or beyond `flashstore_rdma_max_sessions`, stays on TCP.
- Large output chunks (64 KiB or more) that already lie in the OSD's payload hugepage heap are registered once per device at start and sent without a copy. That registration is memory the process already holds, but it counts against `RLIMIT_MEMLOCK` once per device, on top of the budget. Chunks outside the heap are copied into a send slot and counted in `rdma_zc_misses`. A process without a heap copies everything.
- Pinned memory must fit `RLIMIT_MEMLOCK` (or the process needs `CAP_IPC_LOCK`). Otherwise the daemon refuses to start and names the fix.

The slot size is a fixed constant of the build. The only operator knobs are the budget and the session cap.

## Credits and flow control

A sender may only send as many RDMA messages as the receiver has posted receive slots for. The receiver grants these credits to each session.

- Every session starts at a minimum window of 3 slots and borrows more while it is busy, up to a ceiling of 64 slots (a quarter of the core's receive slots at most; a small budget gives a smaller ceiling).
- A session that is blocked on credits is lent more as soon as data arrives. An idle session gives its credits back, so a core can serve many sessions with a fixed pool.
- A sender without credit waits. This is normal flow control, not an error. It shows as `rdma_credit_stalls` and `rdma_credit_stall_ns`. Persistent stalls on large transfers mean the receiver's window is the limit: more cores or a bigger budget raise the window ceiling per session.
- `rdma_queue_stalls` counts sends that waited for a free send slot or send-queue entry on the sender itself.

## Failure behaviour

- Preconditions that fail before the upgrade (no RoCEv2 address on the interface, RoCE path MTU below 1024, no free queue pair, session cap) leave the connection on TCP. Device-level problems are logged once at start and raised as a cluster-log warning; the OSD does not retry in a loop.
- A transport fault on an upgraded connection (queue pair error, retransmission exhausted, peer sent a protocol violation, bytes on the liveness socket) ends that connection. The messenger session is reset and reconnects, over TCP or again over RDMA. It is counted in `rdma_faulted`. No data is lost to the client: ops are resent after the reconnect like on any other dropped connection.
- A closed or reset liveness socket means the peer closed or died. The receiver delivers what already arrived, then the connection is dead.
- A graceful close waits until the peer's NIC has acknowledged the last send before it destroys the queue pair, for at most the close linger (5 seconds). On expiry it logs `WARNING TIMEOUT rdma close fence exceeded <n>s (conn <id>)`, counts it in `rdma_close_fence_timeouts` and tears down anyway.
- Fabric loss is handled by the NIC's RC retransmission (go-back-N) plus a rate cut per drop. A lossless class (PFC and ECN) is recommended. Lossy fabrics work; large streams need PFC or at least ECN marking, otherwise they can fall below TCP. See the fabric section of [how to enable RDMA](../how-to/enable-rdma.md#fabric).
- Queue pair creation and teardown take about a millisecond per call. They run on a helper thread, never on an I/O core, so reconnect storms do not stall I/O.

## Clients

- The native Rust client library (`rados-rt`, used by `rustyrados`) can offer the RDMA upgrade to OSD sessions. It is a library option, off by default, and needs a build with the `rdma` feature on a Linux host with rdma-core. Monitor and manager sessions never upgrade.
- On the client the RDMA carrier works with the epoll transport backend. Zero-copy sends need write payloads built in the client's registered payload pool; this is a second opt-in, also off by default.
- The librados-compatible C API (`rados-ffi`) can offer the upgrade too, through the option `rustyrados_rdma` (off by default, same Linux rdma-core build). Unchanged librados applications get RDMA against OSDs that offer it and stay on TCP against classic OSDs.
- A classic Ceph client always uses TCP, also against RDMA-enabled OSDs.

## Limits

- RoCEv2 only. RoCEv1, InfiniBand and iWARP are not supported.
- RoCE path MTU 1024 at the least (interface MTU 1120 or more); 4096 (interface MTU 4192 or more, jumbo frames on the whole path) is recommended. Below 1024, RDMA stays off for that device.
- IPv4 addresses on the OSD side. An interface without an IP address gets no RDMA.
- Kernel TCP only.
- croit-flashstore-osd never changes host network state (MTU, PFC, DSCP trust, pause, DCQCN). `croit-flashstore-osd --check` reads and reports them.
- The RoCE type-of-service byte is fixed at 106 (DSCP 26 plus ECT0). See the fabric section of [how to enable RDMA](../how-to/enable-rdma.md#fabric).
- A binary needs the `rdma` build feature. Without it, `flashstore_rdma = true` is refused at start.

## Related

- [How to enable RDMA](../how-to/enable-rdma.md)
- [Reference: configuration](../reference/configuration.md) (`flashstore_rdma*`)
- [Reference: admin commands](../reference/admin-commands.md) (`rdma status`)
- [How to troubleshoot croit-flashstore-osd](../how-to/troubleshoot.md#rdma-sessions-stay-on-tcp-or-fault)
