# 0004 Storage I/O: SPDK NVMe driver only
Status: accepted, amended (am. 1, am. 2)
Date: 2026-10-09
Context: Need min CPU/IO on Gen5 NVMe (~3M+ 4k IOPS, ~14 GB/s per device). io_uring polled/passthrough close but still kernel path + syscalls/ring overhead + less queue control. SPDK: userspace polled driver, per-core queue pairs, no syscalls, direct DMA from hugepages, direct access to NVMe features.
Decision: SPDK `lib/nvme` + `env_dpdk` only (no bdev, blobstore, SPDK app framework/reactor). Device bound to vfio-pci (IOMMU on). One IO qpair per core. DMA buffers from hugepage pool shared with net (same DPDK EAL, 0005) -> zero-copy NIC<->NVMe.
Use NVMe features where available: atomic write unit (AWUPF) for torn-write-free metadata, Write Zeroes, DSM/deallocate, FDP (placement hints, optional), PI/metadata (optional).
Consequences: device invisible to kernel tools (nvme-cli via SPDK tools instead); hugepages + vfio required; Linux only.
Later option: own Rust vfio NVMe driver (research shows parity with SPDK) -> separate ADR if FFI becomes burden.
Alternatives: io_uring passthrough (rejected for perf), kernel block + O_DIRECT (rejected).

## Amendment 1 (2026-10-24): one doorbell per pass, device-timed idle
Decision:
- SQ doorbell batching: qpairs open with SPDK `delay_cmd_submit`; the doorbell is written by the next qpair poll. `BlockDev::issue` (one poll) runs at `Shard::end_pass`, so a core loop pass rings once for all its commands. `submits_at_flush` = true on SPDK: the WAL seal moves to the pass end (adr 0021 am. 67) as on the kernel tier.
- Device-timed idle (extends adr 0162): SpdkDev learns per command class (opcode x log2 size) service-time bounds lo (~p20) and hi (mirror) from issue/poll timestamps (sample = midpoint of the last empty poll and the poll that saw the completion). `BlockDev::wait_hint` = time until the earliest in-flight command's lo; 0 while commands wait for the doorbell or completions found by `issue` wait to be handed out. knet idle: hint >= 2 late wake latencies (`wake_late`: ~p80 of the measured ring-sleep overshoot, up fast, down slowly; `wake` stays the ~p20 break-even) -> ring park until one late wake before it; shorter -> poll; inside the window the age rule (adr 0162) runs from the window start; no hint (kernel tier, all overdue) -> unchanged rules.
- SPDK interrupt mode (adr 0165) not used: needs vfio MSI-X; open.
Rationale: one MMIO write per pass instead of per command; a polled core no longer spins for the whole device latency at low depth. Bounds are measured per device and class, no constants.
Consequences: AF_XDP/DPDK and PG-only core loops keep their fixed idle (poll-mode NIC); they get the doorbell batching via `Store::end_pass`. Kernel tier: `issue` no-op, `wait_hint` None. Measurements: doc/perf/spdk-tier-fixes-20261024.md.

## Amendment 2 (2026-10-25): SPDK is one of two storage tiers
Decision: the title's "SPDK only" is superseded. croit-flashstore-osd compiles two block backends: SPDK (this ADR) and the kernel NVMe backend (adr 0169, io_uring/O_DIRECT), selected by `--store-backend` (default `spdk`). The SPDK driver choice and rules above hold for the SPDK tier.
