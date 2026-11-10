# 0011 NIC: SR-IOV VF per croit-flashstore-osd; lab in Proxmox KVM
Status: superseded by adr/0682-remove-afxdp-dpdk-networking.md (was: accepted)
Date: 2026-10-09
Context: Lab NICs: Broadcom BCM57508 (bnxt, up to 200G), Intel E810-C (ice, 100G), Intel XL710 (i40e, 40G). No mlx5 -> no bifurcated driver. Want testing in Proxmox KVM VMs.
Decision (amends 0005): vendor-neutral NIC sharing via SR-IOV VF. Each croit-flashstore-osd gets own VF (own MAC + own IP for public/cluster addr). DPDK PMDs: net_iavf (E810/XL710 VFs), net_bnxt (BCM57508 VFs). Host PF stays with kernel for classic OSDs. Same model on bare metal and VM.
Proxmox VM lab:
- VM: q35, CPU type host, hugepages (1G pages if possible), vCPUs pinned, NUMA-aligned.
- NIC: VF passed via `hostpciN` (vfio). Host side: `ip link set <pf> vf N trust on spoofchk off`, VLAN on VF if needed.
- NVMe: whole NVMe controller passthrough via `hostpciN` (SPDK needs a PCI NVMe function). Fallback for function-only tests: QEMU emulated NVMe (`args: -drive ...,if=none,id=nvm -device nvme,serial=..,drive=nvm`).
- In guest: vfio-pci with vIOMMU (`machine: q35,viommu=intel|virtio`) preferred; else vfio `enable_unsafe_noiommu_mode=1` (lab only).
- Function-only fallback w/o passthrough: DPDK virtio-net PMD on virtio NIC (no SR-IOV needed).
Consequences: + one mechanism, works everywhere, isolates our stack from host networking. - VF count/limits per PF, extra IP per OSD, VF anti-spoof/trust config in provisioning. Perf numbers only valid on bare metal or passthrough with pinning.
