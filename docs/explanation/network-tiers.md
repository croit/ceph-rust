# Explanation: network transport

croit-flashstore-osd speaks the Ceph wire protocol (msgr2) over kernel TCP, driven through io_uring. It works with any NIC the kernel drives, needs no NIC binding, and keeps the NIC visible to the host for monitoring, `ceph tell`, and debugging.

## Kernel TCP (`kernel`)

- Requires: io_uring (checked by `croit-flashstore-osd --check`), `IPC_LOCK`, `SYS_NICE`.
- Host packages: none.
- Bonds, VLANs and routed setups work as on any other host process.

## RDMA: an upgrade on top of kernel TCP

RDMA is not a separate transport. It upgrades established, authenticated connections to a hardware queue pair on a RoCEv2 NIC, when both peers enable it (`flashstore_rdma = true`). Everything else stays on kernel TCP, and the TCP socket remains as liveness channel. See [the RDMA transport](rdma.md) and [how to enable RDMA](../how-to/enable-rdma.md).

## Operational consequences

NIC ring sizes matter: small rings overflow under incast and cause peer retransmits. Set rings to the hardware maximum with `ethtool -G`. `croit-flashstore-osd --check` reports this.
