# 0189: shared client TCP owner
Status: accepted
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): DPDK/userspace-TCP client transport is history; the rest stays valid.
Status note: Superseded in part by adr 0402 (kernel TCP default, DPDK/userspace TCP explicit opt-in) and adr 0005 am. 2 (DPDK networking parked): the DPDK-first wording below is history, not the current production transport.
Date: 2026-10-14
Context: monitor-only BootstrapTcp prevents sharing one authorized per-core TCP stack with native OSD sessions.
Decision: extract static ClientTcp<B, D: TcpOwner>; owner drives logical streams via bounded Dial/Close, byte callbacks and output. Bootstrap implements this contract; keep BootstrapTcp alias and bootstrap accessor. One coordinator will own monitor/OSD ID namespace, auth/maps/request lifetime. No second stack/address or dynamic packet dispatch.
Consequences: existing transport quotas, exact SockId matching, GRO cleanup and TX-only close drain remain shared. Owner generation/stale-callback policy is explicit. Shared OSD coordinator and pooled output remain required; extraction alone is not object runtime completion.
Alternatives: duplicate monitor adapter for OSDs (divergent cleanup/quotas); independent stacks on same NIC/IP (flow ownership conflict); import OSD service runtime (store/PG dependency).
