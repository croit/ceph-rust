# 0166 Read-only host/hardware check (`croit-flashstore-osd --check`)
Status: accepted
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): DPDK/AF_XDP tiers in checks and summary is history; the rest stays valid.
Date: 2026-10-17

Context: deploys fail late (hugepages, IOMMU, PLP, memlock, io_uring blocked by seccomp) and perf losses are silent (governor, TSC clocksource, RSS, downtrained PCIe). Operators need one pre-flight that explains requirements and gates deployments.

Decision:
- Library crate `crates/hwcheck` (LGPL, adr 0164); entry points `croit-flashstore-osd --check` (alias `croit-flashstore-osd check`) and `croit-flashstore-tool hwcheck`, same code, same flags. No cluster connection, no device binding/mapping, no state change, no root required (some probes degrade to N/A without it).
- All input from sysfs/procfs below a root dir (`--root`, default `/`; fixture trees in tests). Live-only probes (skipped for a fake root): io_uring capability test (`rt::knet::probe_iouring`, the adr 0098 check on a scratch ring), NVMe Identify Controller/Namespace via the kernel admin ioctl (`nvme::kprobe`, feature `kprobe`, read-only), ethtool offload gets. Devices bound to vfio-pci/uio are never touched: "not probed (would require binding)". No SPDK/DPDK init in the checker.
- Per check: status OK/WARN/FAIL/N/A, value, why, fix. FAIL only for hard requirements that would break the deployment or its guarantees (no PLP per adr 0008, configured device in use, overlapping lcores, io_uring unusable in a knet build, VF promisc). Everything perf-related is WARN. Exit 0 = no FAIL, 1 = FAIL, 2 = usage.
- Output follows the Ceph `--format plain|json|json-pretty` convention. JSON has a `schema` integer (1); fields documented in doc/ops/hwcheck.md; adding fields is compatible, renaming/removing bumps `schema`. Colors only on a TTY (`NO_COLOR`, `--no-color`).
- Build section reports the features compiled into the calling binary; a compiled-out tier is N/A with the reason. Summary: usable tiers (DPDK, AF_XDP, kernel TCP, SPDK, kernel NVMe) and top 3 fixes (FAIL first, then perf weight).
- Conf cross-checks use own minimal `[global]<[osd]<[osd.N]` parsing (flashstore_lcores, _cores, _hugepages_mb, _dev), same layering as `croit-flashstore-osd run`.

Consequences: + one gate for deploy scripts (`croit-flashstore-osd --check --format json`). + new requirements get a check in the same change. - PLP is a heuristic (VWC absent); VWC drives with PLP are FAILed (mkfs `--allow-vwc` semantics, adr 0008). - Driver/PMD/ZC lists are static tables to maintain (`net.rs`).

## Amendment (2026-10-19): startup warnings + per-driver offload judgment (am. 1)
- The running OSD (knet, AF_XDP/af_packet vdev) runs `irq`, `offload`, `rings` once at start for its data NICs (bond/VLAN resolved via `lower_*`) with the cores it chose and logs one `croit-flashstore-osd: WARNING host: <title>: <value>; fix: <cmd>` line per WARN (`hwcheck::startup_warnings`, same checks/wording as `--check`; OK/N/A silent). Never changes NIC/IRQ/sysctl settings (operator-owned). Not before: only `--check` ran them.
- `hwcheck::nic_info` (IRQ cpus + NIC NUMA node) feeds core placement (adr 0063 am. 1).
- `offload` judges `rx-gro-hw` per driver from a measured table (`GRO_HW_WANT`: driver, wanted state, why; the fix is `ethtool -K <if> rx-gro-hw on|off` + the measured reason). No entry = state shown, no verdict. bnxt_en: on (zen4: on 3048-3069 MB/s, off 2263-2470 MB/s with RX ring discards = receiver CPU-bound). The 450-520k retransmits with on are fabric loss between the VFs (sum tx - sum rx wire packets = retransmits, D-SACK ~0, no NIC or kernel drop; doc/perf/kernel-stall-20261017.md "GRO-hw retransmits"), not caused by GRO. SPDK/kernel-NVMe: no NIC checks involved.
