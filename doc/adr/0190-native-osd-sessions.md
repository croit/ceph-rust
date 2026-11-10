# 0190: native OSD sessions behind shared transport
Status: accepted
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): DPDK/userspace-TCP client transport is history; the rest stays valid.
Status note: Superseded in part by adr 0402 (kernel TCP default, DPDK/userspace TCP explicit opt-in) and adr 0005 am. 2 (DPDK networking parked): the DPDK-first wording below is history, not the current production transport.
Date: 2026-10-14
Context: native bootstrap/auth and shared TCP adapter exist; object engine still uses lab Probe for OSD messenger ownership.
Decision: NativeSessions owns bootstrap, bounded OSD connections, unique transport IDs, mode/clock/ticket policy and bounded message/loss events. Nonblocking route opens current replicated primary; send consumes validated dispatch. ObjectQueue remains application-owned; explicit events feed existing reply/recovery/watch engines. No Probe/kernel dependency.
Consequences: first native object path can use single DPDK stack. Queue admission/recovery scheduler, full/pause matrix, pooled output and indexed scheduling remain required; this is session composition, not full runtime completion. Conservative pause/full gates park traffic; unsupported EC is passive.
Alternatives: reuse Probe (kernel/tool coupling); combine all request engines into one new state machine (duplicate correctness logic); unchecked externally supplied OSD routes (stale/wrong-peer sends).
