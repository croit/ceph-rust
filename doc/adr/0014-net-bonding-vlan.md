# 0014 Prod network: LACP bonds + VLANs with SR-IOV VFs
Status: superseded by adr/0682-remove-afxdp-dpdk-networking.md (was: parked (DPDK networking parked, adr 0005 am. 2; knet uses the host kernel bond; per-vendor validation not pursued))
Date: 2026-10-09
Context: Prod hosts: host-kernel LACP bond over 2 PFs + VLANs. croit-flashstore-osd uses VFs (0011). VFs cannot run own LACP on ports already in a kernel LACP LAG (one LACP partner per port).
Decision candidate: one VF per PF (2 VFs), both same MAC, DPDK in-process bond (net_bonding) in static mode (balance-xor L3/L4 hash, no LACPDUs) or active-backup. Switch already sees physical ports as one LAG -> accepts frames on either member, return traffic hashed by switch to either port -> both VFs RX. Link failure: per-VF link state -> remove member.
Alternatives to validate: NIC-native VF-LAG (Intel E810 ice SR-IOV LAG, Broadcom bnxt VF-LAG) -> one logical VF, simplest if supported by firmware/kernel; else own bonding logic in our net layer (2 queues sets, flow hash).
VLAN: set per VF on host (`ip link set <pf> vf N vlan X`), transparent to DPDK; or tag in DPDK if trunk needed (public + cluster nets on different VLANs -> 2 VFs per PF or tagged).
Validate: E810, BCM57508, XL710: same-MAC VFs on both PFs, failover time, switch MAC flapping, throughput.
