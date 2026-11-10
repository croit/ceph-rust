# 0046 Same-host admin reachability with a DPDK-owned VF
Status: superseded by adr/0682-remove-afxdp-dpdk-networking.md (was: accepted)
Status note: Superseded in part by adr 0005 am. 2 (DPDK networking parked: code stays, no new work, no lab cells) and adr 0053 (knet default): DPDK wording below is history.
Date: 2026-10-11
Context: rollout P0 12. The OSD's public/cluster/mon traffic runs on the DPDK stack of the VF (adr 0005/0011); the kernel never sees that VF. Operators on the OSD host use `ceph` CLI, `ceph daemon osd.N`, `ceph tell osd.N`.
Facts: (1) monc dials mons over the DPDK stack too (no kernel mgmt iface in the daemon; only `croit-flashstore-tool prepare` uses kernel TCP). (2) `ceph tell osd.N` is a direct client connection from the CLI to the OSD's public address in the osdmap (the VF IP), not proxied by the mon. (3) `ceph daemon`/`--admin-daemon` need only the local asok (adr 0035), independent of the network.
Options: A asok only (always works). B `tell` over the network: the host kernel needs an L3/L2 path to the VF IP; works like for classic OSDs from any admin host. C macvlan/second kernel iface on the VF: forbidden (adr 0030). D MCommand proxy in the daemon via the mon: not in the protocol. E kernel-TCP listener in the daemon: contradicts adr 0005.
Decision (KISS): A + B, nothing in the data path.
- Same host, no network assumption: `ceph daemon osd.N ...`, or where the `ceph` CLI is not installed (OCI hosts) `croit-flashstore-tool asok --id N [--cluster C] [--path SOCK] [--format plain|json|json-pretty] CMD...` (std-only classic asok client in croit-flashstore-tool/src/asok.rs; exit 1 on `ERROR:`; the asok serves the same command table as `tell`).
- `ceph tell osd.N` / `osd.*` from the host: works iff the host reaches the OSD public IP. Deployment rule for croit: the VF IP lies in a subnet routable from the host kernel (mgmt route/gateway), or the host has an iface in the same VLAN/subnet via the PF (VEB forwards PF<->VF on Broadcom/Intel; mlx5 bifurcated shares the port). Otherwise use asok, or run tell from mon/mgr hosts. Cephx: CLI keyring with `caps osd 'allow *'` (client.admin) as for classic.
- Asok dir `/var/run/ceph` is bind-mounted into containers (lab/deploy/container/run.sh).
Consequences: + zero new daemon code/attack surface; - host-side `tell` depends on network layout (documented), needs a per-site live check.
Live check (not run, lab VM busy): host with a DPDK-VF OSD: kernel `ping <osd public ip>`; `ceph tell osd.N version`; `croit-flashstore-tool asok --id N status`.
