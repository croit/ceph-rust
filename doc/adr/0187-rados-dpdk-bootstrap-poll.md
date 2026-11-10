# 0187 owned DPDK monitor polling
Status: accepted
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): DPDK monitor polling is history; the rest stays valid.
Status note: Superseded in part by adr 0402 (kernel TCP default, DPDK/userspace TCP explicit opt-in) and adr 0005 am. 2 (DPDK networking parked): the DPDK-first wording below is history, not the current production transport.
Date: 2026-10-14
Context: static userspace bootstrap adapter is tested/buildable; no real DPDK polling path yet.
Decision: own authorized Port, bounded RX/TX/pending work and DMA lifetimes, matching source MAC/access VLAN profile, no TSO for monitor pilot; lab-only AF_PACKET qualifier. Contract RC-DPBOOT (doc not in the source snapshot).
Consequences: validates actual DPDK/userspace TCP/CephX path without physical VF reconfiguration. Cold monitor driver may allocate/copy in existing codecs/PMD helpers; hot object path/TSO/RSS/memory qualification still required.
Alternatives: claim DPDK from compile only (insufficient); use kernel sockets in production adapter (wrong transport); retain unbounded rejected mbufs (unbounded memory).
