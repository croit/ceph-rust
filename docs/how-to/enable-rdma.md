<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# How to enable RDMA

This page turns on the RDMA transport on OSDs and, optionally, on native clients, and shows how to confirm that connections use it. Read [the RDMA explanation](../explanation/rdma.md) first if you do not know what it changes. RDMA is off by default and every connection that is not upgraded stays on TCP, so you can enable it one OSD at a time.

## Prerequisites

| Need | Detail |
|---|---|
| Network tier | Kernel TCP. |
| Build | The production binary includes RDMA (off until enabled). A custom build without the `rdma` feature exits at start with `flashstore_rdma=true: this binary was built without feature rdma`. |
| NIC | A RoCEv2-capable Ethernet NIC with its kernel RDMA driver loaded. The OSD's public or cluster IP must be configured on that NIC's network interface. See [hardware requirements](../reference/hardware-requirements.md#rdma-optional). |
| Addresses | IPv4. RoCEv1 is not supported. |
| MTU | Best: interface MTU 9000 (jumbo) on every host interface and switch port of the path, RoCE path MTU 4096. Standard 1500 works with lower throughput; see [Fabric](#fabric). Below that, RDMA stays off for the device and connections stay on TCP. |
| Pinned memory | `RLIMIT_MEMLOCK` of at least `flashstore_rdma_memory` plus the registered payload heap (once per device), or `CAP_IPC_LOCK`. |
| Peers | Both ends of a connection must have RDMA enabled. Classic OSDs and clients stay on TCP. |

Check the host first. The check is read-only:

```
croit-flashstore-osd --check
```

The `RDMA` section reports the port state, the RoCEv2 address, the interface MTU, the NIC QoS (PFC, DSCP mapping, global pause), DCQCN, the RoCE drops the NIC recorded (with or without ECN marks) and the PCIe link. An OSD with RDMA on logs the QoS and drop WARNs once at start. Each WARN carries the fix command. Without RDMA devices the section is `N/A`.

### Fabric

croit-flashstore-osd never changes NIC or switch settings. It reads and reports them.

- Recommended: a lossless class. PFC on one priority (3 is the usual choice), the NIC and the switches trust DSCP, ECN marking on that queue, DCQCN on the NIC, and global pause off on the RDMA interface when PFC is on.
- The RoCE type-of-service byte of every queue pair is 106 (DSCP 26 plus ECT0). Map DSCP 26 to the lossless priority on the NIC and the switches. The value is fixed in the OSD; `croit-flashstore-osd --check` judges the QoS against the same value.
- A lossy fabric (no PFC) works, but large streams need PFC or ECN. On a drop the NIC resends everything after the lost packet (go-back-N) and slows the connection down; without ECN marking on the switches it learns of congestion only by dropping. Small and medium I/O still gains, large streaming writes under incast can then be slower than TCP. Use the lossless class, or at least ECN marking on the switch queue that carries RoCE. RoCE traffic must then not be mapped to a switch queue that is no-drop while the NIC does not pause for it: that overflows the queue. `croit-flashstore-osd --check` WARNs when TOS, DSCP map and PFC priority disagree, and on a lossy setup.
- Best: MTU 9000 (jumbo frames) on every host interface and every switch port on the path. It gives the maximum RoCE path MTU, 4096 (RoCE never uses more; an interface MTU of 4192 already reaches it, 9000 is the common jumbo standard and helps the TCP traffic too). Standard 1500 works but slower. Below that RDMA stays off.

| Interface MTU | RoCE path MTU | Result |
|---|---|---|
| 4192 or more (9000 recommended) | 4096 | Best throughput. |
| 1120 to 4191 (1500 for a standard network) | 1024 or 2048 | RDMA works with lower throughput; `croit-flashstore-osd --check` WARNs. |
| Below 1120 | none | Not supported: RDMA stays off, connections stay on TCP. |

- Both ends of a connection use the smaller of their two path MTUs. An older version without this feature works only with a peer at 4096.
- Keep other traffic out of the RoCE class. TCP traffic of the OSD (monitors, heartbeats, classic peers) keeps its own DSCP.

Example host NIC setup for the lossless class on priority 3 (iproute2 `dcb`, run on every OSD and client host for the RoCE interface; NIC firmware tools that own DCB, e.g. a DCBX agent in willing mode, take precedence):

```
dcb pfc set dev <ifname> prio-pfc 3:on
dcb app add dev <ifname> dscp-prio 26:3
ethtool -A <ifname> rx off tx off
```

The switches need the same: priority 3 no-drop with PFC, trust DSCP (DSCP 26 to priority 3), ECN marking on that queue. `croit-flashstore-osd --check` shows the host side; each WARN carries the command for that interface.

Check that the switch side works, under load:

- PFC pause frames for priority 3 are counted on the NIC (`ethtool -S <ifname>`, per-priority pause counters, names differ per driver) when the receivers are busy.
- The NIC's receive discards and the RoCE loss counters stay at zero; `croit-flashstore-osd --check` reports the RoCE drops (`RoCE loss` row) and whether ECN marked them.
- Host side lossless (`RoCE QoS` OK) but drops still grow: the switch does not protect the class; check its PFC, DSCP trust and queue mapping.

### Memory lock

Set the limit in the systemd unit:

```
[Service]
LimitMEMLOCK=infinity
```

In a container use `--ulimit memlock=-1`, in a shell `ulimit -l unlimited`. If the limit is too low, the daemon exits at start with:

```
croit-flashstore-osd: rdma: memlock limit <n> MiB is below the <m> MiB of RDMA memory to register (flashstore_rdma): systemd LimitMEMLOCK=infinity, docker --ulimit memlock=-1, shell ulimit -l unlimited
```

Zero-copy sends use the OSD's payload hugepage heap, which the OSD allocates anyway (see [prepare the host](prepare-host.md)). RDMA registers it once per device. Without such a heap every byte is copied into a send slot and the daemon prints `croit-flashstore-osd: rdma: no payload hugepage heap in this process: every byte is copied into the send arena`.

## Enable on OSDs

In the OSD section of the configuration file:

```
[osd]
flashstore_rdma = true
```

Optional:

```
flashstore_rdma_memory = 256M
flashstore_rdma_max_sessions = 0
```

The same options exist as flags: `--rdma true`, `--rdma-memory 256M`, `--rdma-max-sessions N`. Restart the OSD. The options are read at start only.

At start the OSD prints one line per RDMA device:

```
croit-flashstore-osd: rdma: <ip> on <device> (<n> MiB registered per core: <r> receive slots, <s> send slots of 64 KiB, up to <k> sessions per core at the minimum window, no session limit)
```

A device that cannot be used (no RoCEv2 address on it, interface MTU below 1120) logs `croit-flashstore-osd: rdma: <ip>: <reason> (connections of this address stay TCP, no retry)`, and the OSD runs on TCP for that address.

Roll the change out OSD by OSD as in [rolling upgrade](upgrade-rolling.md): wait for `active+clean` between OSDs. Connections between an upgraded OSD and one that is not stay on TCP.

Start refusals, each with a message that names the cause:

| Message | Cause |
|---|---|
| `flashstore_rdma=true: this binary was built without feature rdma` | Wrong binary. Exit 2. |
| `rdma: rdma memory budget of <n> MiB over <c> core(s) x <d> device(s): <x> MiB per core and device, at least <y> MiB needed (raise flashstore_rdma_memory, use fewer cores, or set flashstore_rdma=false)` | Budget too small for the cores times devices. Exit 1. |
| `rdma: memlock limit ...` | `RLIMIT_MEMLOCK` too low, see above. Exit 1. |

## Enable on native clients

The native Rust client library (`rados-rt`, used by `rustyrados`) and the librados-compatible library (next subsection) can offer the upgrade, and only an application that sets the option. The native library takes it as a library setting; there is no `ceph.conf` key for it.

- Build `rados-rt` with the `rdma` feature on a Linux host with rdma-core.
- Set `SessionLimits::rdma = true` when creating the client. The default is off. `SessionLimits::rdma_max_sessions` caps the client's RDMA sessions (0 = unlimited); a session beyond the cap stays on TCP.
- Optional zero copy of write payloads: set `KernelTcpLimits::rdma_zero_copy = true` and build the payloads in the client's registered `PayloadPool`. Default off.
- The RDMA carrier runs on the epoll transport backend of the client.
- `rdma-bench` (in `tools/`) takes `--rdma true|false` and `--rdma-zero-copy true|false` for A/B runs. `--osds N` (default 16) bounds the RDMA sessions: it must be at least the number of OSDs the objects map to, else the excess sessions stay TCP and the run fails, because such a cell would measure a transport mix.

### Applications that use the librados C/C++ API

The librados-compatible library of this project (`librados.so.2` built from `rados-ffi`) offers the upgrade to unchanged applications. The production client package contains the RDMA code; it is off until you set the option. The code is linked statically, so the library has no extra shared-library dependency whether the option is on or off.

Set the option before `rados_connect`, in any of the usual places:

```
# ceph.conf, [client] or [global]
rustyrados_rdma = true
# optional, registered (pinned) memory of the process for write payloads, default 256M
rustyrados_rdma_memory = 256M
```

or `rados_conf_set(cluster, "rustyrados_rdma", "true")`, or `CEPH_ARGS="--rustyrados-rdma=true"`. The default is `false`. Behaviour:

- Sessions to OSDs that offer RDMA (croit-flashstore-osd with `flashstore_rdma = true`) continue over RDMA. Sessions to classic OSDs, and to croit-flashstore-osd without RDMA, stay on TCP without any error. Monitor and manager sessions always use TCP.
- A write of 64 KiB or more is copied once into the registered memory and sent from there; smaller writes and writes while that memory is full are copied into the transport as before. Reads are copied once into the caller's buffer, as before.
- The key is unknown to the stock librados. In a `ceph.conf` it is ignored there; `rados_conf_set` of a stock librados returns `-ENOENT`, which an application that sets the option itself should treat as "not available".
- `rados_connect` fails with a message on stderr when the option is on and the library was built without the `rdma` feature (`-ENOTSUP`), when `rustyrados_transport_backend` is not `epoll` (`-EINVAL`, the RDMA carrier runs on the epoll backend) or when the memory cannot be allocated (`-ENOMEM`).
- The client host needs a RoCEv2 interface that carries the client's source IP, interface MTU 9000 (1500 works with lower throughput) and a memlock limit (`ulimit -l`) of at least `rustyrados_rdma_memory` plus the carrier's receive memory. If the device cannot be used the sessions stay on TCP and the counters show it.

Check what the application got with `rados_conf_get(cluster, "rustyrados_rdma_status", buf, len)`. It returns one JSON object (the buffer needs about 8 KiB; a shorter buffer truncates the JSON); `rdma-app` in `lab/rados-client/` prints it. Fields:

| Field | Meaning |
|---|---|
| `enabled`, `built_in` | The option, and whether the library contains the RDMA code. |
| `offered`, `upgraded` | Upgrade offers sent, sessions that continue over RDMA. |
| `declined`, `capped` | Offers the OSD or the local session cap refused; the session stays on TCP. |
| `tcp_peer` | Sessions that went ready over TCP because the OSD does not offer RDMA (a classic OSD). Counted only with the option on. |
| `faulted` | RDMA sessions ended by a transport fault; they reconnect. |
| `zc_bytes`, `zc_misses`, `zc_registered_bytes` | Write bytes sent from the registered memory, chunks that had to be copied, the registered size. |
| `pool_bytes`, `pool_in_use_bytes`, `pool_allocs`, `pool_exhausted` | The registered memory: size, in use, blocks handed out, writes that found it full and took the heap copy. |
| `credit_stalls`, `queue_stalls`, `cq_errors`, ... | Transport counters, as `rdma status` on the OSD; the error counters must stay 0. |

Healthy: `upgraded` equals the number of OSD sessions of RDMA-enabled OSDs, `faulted` 0, `pool_exhausted` 0 (raise `rustyrados_rdma_memory` otherwise).

The client host needs the same as an OSD host: a RoCEv2 interface that carries the client's source IP, interface MTU 9000 (1500 works with lower throughput) and a memlock limit that covers the client's registered memory.

### Applications that use the librbd C API (QEMU/KVM)

QEMU's block driver `block-rbd.so` speaks the librbd C API, and librbd itself has no transport: every image operation goes through librados. The RDMA upgrade of a KVM disk is therefore the librados option above, in the QEMU process.

Use the project's own `librbd.so.1` and `librados.so.2` together:

- Installed client package: `croit-flashstore-lib-ctl activate` (see [build and install packages](build-and-install-packages.md)).
- Staged test: put both libraries in one directory as `librbd.so.1` and `librados.so.2` and start QEMU with `LD_LIBRARY_PATH=<dir>`. QEMU loads `block-rbd.so` (package `qemu-block-extra` on Debian/Ubuntu); that module links both sonames, so the staged pair is used without rebuilding or patching QEMU.

Set the option where QEMU reads the client configuration:

```
# ceph.conf, [client] or [global]
rustyrados_rdma = true
rustyrados_rdma_memory = 256M
```

QEMU reads `/etc/ceph/ceph.conf` by default. For a non-default file use `CEPH_CONF=<file>` in the environment or the `conf=<file>` option of the `rbd:` URL, for example `-drive driver=rbd,filename=rbd:pool/image:conf=/etc/ceph/ceph.conf,if=virtio`.

The QEMU process, not the OSD, pins `rustyrados_rdma_memory`. Raise its memlock limit (systemd `LimitMEMLOCK=infinity` for the libvirt/QEMU unit, or `ulimit -l unlimited` in the shell that starts it). Without the limit the library reports `-ENOMEM` at connect and the disk does not start.

QEMU has no call that prints `rustyrados_rdma_status`. Confirm the upgrade from both sides:

- OSD: `ceph tell osd.N rdma status --format json` shows `upgraded > 0`, `declined` unchanged and `faulted` 0 while the guest runs; `rdma_tx_bytes` grows with the guest I/O.
- Client: run the same configuration through a librados consumer that prints the status, for example `lab/rados-client/rdma-app smoke <pool> --rdma true --expect upgraded --conf <file>`; it must report `upgraded > 0`, `tcp_peer 0`, `declined 0`, `faulted 0`.

Data path of a KVM disk over RDMA: a write of 64 KiB or more is copied once into the QEMU process's registered memory and posted by reference (zero-copy SEND); a read is copied once from the receive slots into the guest buffer. Registered read placement and client source-pull are not enabled for the librbd path.

If any prerequisite is missing (no RoCEv2 GID, interface MTU below 1120, memlock too low, OSD without `flashstore_rdma`), the disk keeps working on TCP. That is the designed fallback and is why the checks above are part of the deployment, not optional.

## Verify

On the OSD host:

```
ceph tell osd.N rdma status
ceph tell osd.N rdma status --format json-pretty
croit-flashstore-tool asok --id N rdma status
```

Plain output has a header line, then one line per device and one per core and device:

```
rdma enabled, max_sessions unlimited, sessions 7
<ip> (<device>): sessions 7 (capacity 113), credits 120 of 341 receive slots, held 0; upgraded 9 declined 0 faulted 0 capped 0 credit_stalls ...
```

Meaning of the fields:

| Field | Meaning |
|---|---|
| `sessions` | Connections on RDMA now. |
| `capacity` | Sessions the receive pool holds at the minimum window. |
| `granted_credits`, `receive_slots` | Credits handed out against the receive slots. |
| `session_credits` | Sum of the live sessions' current windows; differs from `granted_credits` only while credits are held by no session. |
| `held_slots` | Receive slots held while received data is processed. |
| `upgraded` | Connections that continued over RDMA. |
| `declined` | Upgrades that did not happen (no queue pair, GID mismatch, peer declined). The connection stayed on TCP. |
| `faulted` | RDMA sessions that ended by a transport fault. They reconnect. |
| `capped` | Connections that stayed on TCP because the session cap or the receive pool was full. |
| `credit_stalls`, `queue_stalls` | Sends that had to wait for peer credits, or for a send slot. |

`unusable` in the JSON lists devices that could not be used, with the reason.

The same numbers are OSD perf counters in `perf dump` and in the mgr prometheus module: `rdma_upgraded`, `rdma_declined`, `rdma_faulted`, `rdma_sessions_capped`, `rdma_credit_stalls`, `rdma_queue_stalls`, `rdma_credit_stall_ns`, `rdma_grants_demand`, `rdma_idle_decays`, `rdma_close_fence_timeouts`, `rdma_zc_bytes`, `rdma_zc_misses`, `rdma_tx_bytes`, `rdma_tx_sends`, `rdma_tx_chunks`, `rdma_tx_doorbells`, `rdma_rx_doorbells`, `rdma_wakes`, the robustness counters `rdma_rx_post_failures`, `rdma_cq_errors`, `rdma_rx_withheld`, `rdma_leaked_cores`, `rdma_teardown_failures`, `rdma_qp_drain_timeouts` (all must stay 0) and the gauge `rdma_sessions`. Descriptions: [admin commands](../reference/admin-commands.md). They exist only with `flashstore_rdma = true`.

Healthy state: `rdma_upgraded` grows when OSDs peer and clients connect, `rdma_faulted` stays at or near 0, `rdma_sessions_capped` is 0, `rdma_zc_misses` is small against `rdma_zc_bytes`. `rdma_declined` is expected for connections to peers without RDMA.

Placement ownership failures also appear as `rdma_quarantined_windows` and
`rdma_quarantined_write_sources` in OSD perf output and as
`quarantined_windows` / `quarantined_write_sources` in `rdma status` and the
client's `rustyrados_rdma_status` JSON. They must stay zero; the counters are
zero when placement is not built.

The OSD also writes these lines to the cluster log (`ceph log last`) and the daemon log:

| Line | Level | Meaning |
|---|---|---|
| `rdma: device <ip> unusable: <reason> (connections of this address stay on TCP)` | WARN | A device could not be used at start. |
| `rdma: max_sessions <n> reached, new connections stay on TCP` | WARN | The session cap is full. |
| `rdma: receive pool full at <n> sessions (raise flashstore_rdma_memory), new connections stay on TCP` | WARN | The receive slots of a core are used up. |
| `rdma: configured but no connection upgraded after 600s (<n> stayed on TCP, see rdma status)` | WARN | Offers were declined for 10 minutes and nothing has upgraded. |
| `rdma: <n> connections stayed on TCP since the last message` | WARN | Summary, at most one per 10 minutes, only if there were new ones. |
| `rdma: sessions back to <n> (below the cap), new connections upgrade again` | INFO | The cap condition ended. |
| `rdma: connections upgrade now` | INFO | The first upgrade after the "no connection upgraded" warning. |

These are cluster-log entries only. croit-flashstore-osd adds no health check code for RDMA.

## Size the memory and the session limit

- `flashstore_rdma_memory` is for the whole OSD process, split over cores times RDMA devices. Each part needs at least 6 MiB. Raise it when the log says `receive pool full` or `capped` grows without a configured limit.
- Sessions per core = receive slots per core / 3. With the default 256 MiB on 8 cores and one device: 341 receive slots, 113 sessions per core. The pinned memory is fixed and does not grow with peers.
- Larger parts also allow larger per-session windows (ceiling 64 slots at 32 MiB per part, 42 at 16 MiB). If `rdma_credit_stalls` or `rdma_credit_stall_ns` stay high on large transfers, raise the budget.
- `RLIMIT_MEMLOCK` must cover the budget plus the registered payload heap once per device.
- `flashstore_rdma_max_sessions` is an optional hard cap for the process. The default 0 is unlimited; the receive pool is then the only limit.

## Disable or roll back

1. Set `flashstore_rdma = false` (or remove it) in the configuration file.
2. Restart the OSD.

Its connections come back on kernel TCP and the pinned memory is released. Nothing on disk or in the cluster changes. There is no runtime switch: the options are read at start. Peers keep working; an RDMA-enabled peer sees a connection without the RDMA offer and stays on TCP.

## Related

- [Explanation: the RDMA transport](../explanation/rdma.md)
- [Troubleshoot RDMA](troubleshoot.md#rdma-sessions-stay-on-tcp-or-fault)
- [Reference: configuration](../reference/configuration.md)
- [How to tune the host](tune-host.md)
