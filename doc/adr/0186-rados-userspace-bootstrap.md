# 0186 static userspace TCP bootstrap adapter
Status: accepted
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): DPDK/userspace-TCP client bootstrap is history; the rest stays valid.
Status note: Superseded in part by adr 0402 (kernel TCP default, DPDK/userspace TCP explicit opt-in) and adr 0005 am. 2 (DPDK networking parked): the DPDK-first wording below is history, not the current production transport.
Date: 2026-10-14
Context: standalone client bootstrap is CRC/Secure qualified through a lab kernel adapter; required production transport is DPDK/userspace TCP.
Decision: default-off rados-rt BootstrapTcp generic over net::RxBuf, exclusive per-core Stack, bounded slots/work/staged buffers and borrowed RX/shared TX. Contract RC-BTCP (doc not in the source snapshot).
Consequences: no production kernel fallback or Probe dependency; DPDK NIC driver can feed the same static adapter. This increment covers monitor transport; object coordinator/hot-path memory pools/NIC/RSS and live hardware qualification remain open.
Alternatives: reuse blocking probe sockets (wrong production transport); dynamic socket backend per packet (unnecessary dispatch); drop unsent suffix on backpressure (corrupt stream).
