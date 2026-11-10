# 0185 standalone native monitor bootstrap
Status: accepted
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): DPDK/userspace-TCP client bootstrap is history; the rest stays valid.
Status note: Superseded in part by adr 0402 (kernel TCP default, DPDK/userspace TCP explicit opt-in) and adr 0005 am. 2 (DPDK networking parked): the DPDK-first wording below is history, not the current production transport.
Date: 2026-10-14
Context: authenticated native operations currently depend on a lab-only oprobe driver; production client needs an independently usable bootstrap/control owner.
Decision: feature-gated transport-neutral Bootstrap composing own monc, typed CephX-only config, secure startup randomness, immutable global identity/FSID policy, absolute startup deadline and explicit socket-close drain. Contract RC-NBOOT (doc not in the source snapshot).
Consequences: library can bootstrap without kernel sockets or Ceph libraries; cold monitor allocations remain. Production DPDK adapter, object coordinator, control commands and broader bootstrap qualification still required.
Alternatives: import oprobe into library (kernel/tool coupling); expose raw mutable monc (bypasses CLIENT-only contract); infer missing secrets/auth fallback (unsafe policy).
