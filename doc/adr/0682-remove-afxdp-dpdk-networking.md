<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0682 AF_XDP and DPDK networking are removed

Status: accepted
Date: 2026-11-06
Supersedes: 0005, 0020, 0011, 0038, 0472, 0473, 0585, 0046, 0014 (fully); 0185, 0186, 0187, 0189, 0190, 0402, 0487, 0053, 0054 (partly, see Decision)

## Context

Own-stack networking (AF_XDP adr 0020/0472/0473/0585, DPDK poll-mode adr 0005/0038) never beat kernel TCP over io_uring (knet, adr 0053) in a gated cell. DPDK networking was parked (adr 0005 am. 2) and AF_XDP deprecated and out of prod (adr 0020, 2026-10-28). Both cost a second TCP stack, NIC-specific host setup (SR-IOV VF per OSD, port steering, flow rules, extra capabilities), a patched DPDK prefix and a large lab matrix. User decision 2026-11-06: remove them completely.

## Decision

- Removed: NIC backends of crates/net (DPDK PMD, native AF_XDP/XDP), the NIC-driving rt loop (Core, OsdNet, flowrule, route, DpdkNic/XskNic), rados-rt features `dpdk` and `userspace-tcp` (ClientTcp, DpdkClient, dpdk-* examples), OSD run modes `--net dpdk|afxdp`, cargo features `dpdk` and `xsk`, hwcheck checks that only matter for them, their lab scripts, packaging examples and operator docs.
- `--net` / `flashstore_net` removed (single transport).
- Kept: knet (adr 0053), RDMA upgrade of knet sessions (adr 0469), SPDK storage tier (adr 0004) incl. its DPDK EAL/hugepage environment (crates/nvme, crates/dpdk-link, feature `spdk`), kernel NVMe tier (adr 0169), rustyrados epoll/io_uring client (adr 0466).
- The OSD payload hugepage heap (HugeAlloc, EAL heap, pinned RDMA ranges) moves from net::dpdk to the new crate crates/eal-heap, enabled by the OSD cargo feature `spdk` (formerly `dpdk`).
- crates/net keeps the sans-IO TCP stack and its simulator only as the socket abstraction and test simulator used by services/mds; it has no NIC backend and no production data path in the OSD.
- Build profiles: prod = `knet,mimalloc,rdma`; prod-full = `spdk,mimalloc,knet,rdma`.
- Partial supersedes (the network part is history, the rest stays valid): 0053 (selection of `dpdk|afxdp` tiers, DPDK/AF_XDP analogues), 0054 (am. 2/3 own-stack port classes), 0185/0186/0187/0189/0190 (DPDK/userspace-TCP client transport), 0402 (DPDK opt-in), 0487 (the DPDK prefix stays only for SPDK builds). Other ADRs that mention the tiers keep their text; read the AF_XDP/DPDK network wording in them as history.
- The pre-removal state is archived on origin branch `archive/afxdp-dpdk-net-before-removal-20261106`. Measurements in doc/perf stay.

## Rationale

Neither tier produced a measured win over knet; each carried permanent cost in code, tests, host preparation and lab time. KISS (charter): one network path. The DPDK environment stays only where it has a unique job (SPDK DMA memory, hugepage payload heap).

## Consequences

- + One data-path transport (knet, optionally upgraded to RDMA); simpler host preparation (no NIC binding, no VF per OSD, no extra capabilities).
- + Smaller build, fewer features, no patched DPDK network prefix requirements beyond SPDK.
- - No kernel-bypass TCP option: cycles/byte per core depends on the kernel stack (profiling and io_uring features such as zero-copy receive, spec/knet-zcrx.md, are the remaining levers).
- - Reintroducing a bypass tier means restoring from the archive branch and a new ADR.

## Alternatives

- Keep DPDK compile-only (adr 0005 am. 2): rejected, dead weight with no lab cells.
- Keep AF_XDP as opt-in: rejected, no advantage over knet at 1500 MTU (kill criterion adr 0020).

## Open questions

- Retire the sans-IO TCP stack and simulator in crates/net once the MDS tests use another simulator (doc/90-open-questions.md).
