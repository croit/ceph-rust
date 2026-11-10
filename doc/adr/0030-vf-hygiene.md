# 0030 SR-IOV VF hygiene (never disturb the host / other tenants)
Status: accepted
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): VF rules for DPDK/AF_XDP OSDs (lab hygiene for VFs stays) is history; the rest stays valid.
Date: 2026-10-09
Incident: on the lab host (Broadcom BCM57508 VFs, PF in host LACP bond + Linux bridge for VMs), bringing a VF up with promiscuous capture (tcpdump) and VLAN-tagged frames on an access-VLAN VF left VF firmware state that made the PF behind one LACP member drop/steer inbound unicast for bridged VM MACs -> mgmt VM unreachable via that switch path for ~1h, survived VM reboots; fixed only by recreating the VFs (sriov_numvfs=0 -> N).
Rules for croit-flashstore-osd (DPDK/net crate + provisioning tools + lab work):
- NEVER enable promiscuous or allmulticast on a VF; after rte_eth_dev_start explicitly call promiscuous_disable + allmulticast_disable (some PMDs default to enabled); rx only via the VF's own unicast MAC (+ needed multicast for IPv6 ND solicited-node only).
- NEVER send VLAN-tagged frames on a VF that has a port VLAN (access mode); tagging only if the operator configured a trunk VF explicitly (config flag), default untagged.
- NEVER use IPs from foreign subnets (e.g. host mgmt) on VFs; only the configured croit-flashstore-osd addresses; no ARP probes/gratuitous ARP for other IPs.
- Lab: no tcpdump in promiscuous mode on VFs (use `tcpdump -p`), no ad-hoc IPs/VLAN subinterfaces on VFs; if a VF behaved oddly: recreate VFs (host admin) instead of debugging upstream.
- Startup self-check: log VF promisc/allmulti state, refuse to run if promisc is forced on by PMD and cannot be disabled (unless --allow-promisc for dedicated NICs).
