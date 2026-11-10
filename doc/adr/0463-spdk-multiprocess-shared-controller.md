# 0463 SPDK multi-process: several OSDs on one controller, one namespace each (debug/testing only)

Status: accepted (debug/testing feature only)
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): DPDK NIC tiers (SPDK multi-process stays) is history; the rest stays valid.
Date: 2026-10-14
Amends: 0103

## Context

An SPDK `spdk:PCI` open claims the whole controller (PCI claim, adr 0004, `pcilock`), so adr 0103 allows one OSD per NVMe controller. Lab hosts with one fast multi-namespace drive (e.g. P5800X, 4 namespaces) need several croit-flashstore-osd OSDs on that controller for multi-OSD tests and benchmarks (replication, peering, 4-OSD comparisons with classic OSDs). A controller is driven by one DPDK/SPDK primary process; other processes attach through DPDK multi-process (shared hugepage memory, shm id, `/run/dpdk/<prefix>`).

## Decision

- Cargo feature `spdk-mp` (crate nvme, croit-flashstore-osd, croit-flashstore-tool) gates everything below; it is never part of production builds. Without it `spdk:..,shared` fails to parse ("needs a build with feature `spdk-mp`") and the `spdk-primary` subcommand does not exist. Non-shared specs behave as without the feature.
- Device spec `spdk:PCI,ns=N,shared` (`DevSpec::Spdk { shared }`) marks a namespace of a shared controller.
- Primary = `croit-flashstore-osd spdk-primary --dev spdk:PCI [--mem MB] [--poll-ms MS] [--huge-dir D] [--format plain|json|json-pretty|jsonl]` in the daemon binary (events `ready`, `stopped`, `stop_refused`, `admin_error`, `error` as one record each) (a DPDK primary registers every tailq/bus its secondaries use; only the daemon links the full DPDK set; `croit-flashstore-tool` is a secondary only). It takes the PCI claim, constructs the controller without a namespace (`nvs_connect`) and polls admin completions (AERs, timeouts, cleanup of dead secondaries' io qpairs) every `poll_ms` until SIGTERM/SIGINT. EAL `--proc-type=primary`; shm id = PCI address as a number (`domain<<16|bus<<8|dev<<3|func`), so each controller has its own DPDK file prefix `spdk<id>`.
- OSDs and tools on a `shared` spec are secondaries: EAL `--proc-type=secondary`, never `auto` (an `auto` process would become primary after a primary death and re-create the shared DPDK config under running secondaries). A secondary is refused when no primary runs (DPDK `lockf` on `/run/dpdk/spdk<id>/config`).
- Each process has its own main lcore (`--lcore` or the first CPU of the affinity mask): DPDK per-lcore state lives in shared memory. The default main lcore of every SPDK env init is the first CPU of the process affinity (SPDK's default lcore 0 fails in a cpuset without CPU 0).
- Locks in `/var/tmp` (module `spdkmp`): `flashstore_spdk_mp_<bdf>` flock, held shared by every secondary for its lifetime; the primary takes it exclusive to start (refused while any secondary lives) and to stop (SIGTERM refused and logged while secondaries run; SIGKILL forces). `flashstore_spdk_ns_<bdf>_<nsid>`: exclusive per namespace (`pcilock::claim_at`), so the exclusive open moves from controller to namespace granularity.
- adr 0103's `prepare` neighbour refusal is relaxed only between `shared` OSDs; the early PCI claim applies to the primary, secondaries claim their namespace.
- Namespace format (`nvs_format`, `ensure_4k`) runs only in a primary or a non-shared process: a namespace of a controller other processes use is never reformatted (clear error).
- Shared specs need `--net kernel`: the DPDK NIC tiers run their own EAL (one EAL per process); refused at start.
- With `--store-backend kernel|kernel-cmd` (adr 0169) `shared` does not apply: the spec resolves to the namespace's own kernel node.
- Containers: all processes of one controller share the host PID namespace (SPDK finds dead secondaries with `kill(pid, 0)`), `/var/tmp`, `/run/dpdk`, `/dev/hugepages` and the vfio group. Stop order: OSDs, then the primary; leftovers of a killed primary (`/dev/hugepages/spdk<id>map_*`, `/run/dpdk/spdk<id>`) are removed before a new primary starts.

## Rationale

Lab multi-OSD tests need several SPDK OSDs on one drive; DPDK multi-process is the mechanism SPDK provides for sharing a controller. The production objections of adr 0103 (a primary crash stops every OSD of the drive, fragility across SPDK versions, shared-memory coupling between OSDs) are accepted for debug/testing builds only.

## Consequences

- + Several SPDK OSDs per NVMe controller (one namespace each) without the kernel driver.
- + The io qpairs of a crashed OSD are cleaned up by the primary's admin poll; the other OSDs continue (not yet tested with a killed OSD).
- + The non-shared path is unchanged.
- - The primary is a separate long-lived process per controller; its death leaves secondaries running without admin processing or recovery until all are restarted.
- - One EAL per process: shared specs exclude the DPDK NIC tiers.
- - The DMA buffer pool fallback (`spdk_dma_zmalloc`) goes through the shared DPDK heap (cross-process lock) when a per-thread pool bin is empty.

## Alternatives

- One OSD process owning several namespaces: a large change of the OSD model (adr 0103 option 2).
- Kernel nvme driver per namespace: implemented as the kernel NVMe backend (adr 0169, `--store-backend kernel`), which runs one OSD per namespace without SPDK; it does not cover SPDK-path tests.
- SPDK vhost / NVMe-oF target as the shared owner: an extra hop and process.

Live check script: `lab/spdk-mp-live.sh OUT BIN_DIR` (lab env `LAB_SPDK_MP_PCI`; read-only on the device): primary ready, secondary inspect, two concurrent 4K random readers on separate namespaces, second open of a namespace refused, SIGTERM refused while secondaries run, clean stop, secondary without primary refused.
Validation: crate nvme `spdkmp` unit tests (shm id, lock paths, primary refused while a secondary lives, secondary refused while the primary starts, start lock released on drop, primary-alive via `lockf`), `DevSpec` parse of `,shared`. Live (2026-10-13/14, lab host with a P5800X split into 4 namespaces, vstart mons/mgr): 4 croit-flashstore-osd OSDs as secondaries in containers plus `croit-flashstore-osd spdk-primary`, prepare/run/stop cycles, multi-hour rados bench and fio runs (4K random read up to 290k IOPS), OSD restarts while the primary runs.

## Amendment (2026-11-06, am. 1): multi-process locks live in /run/croit-flashstore-osd

Context: the lock files were in `/var/tmp`, which `PrivateTmp=true` makes private to each unit. Primary, secondaries and
container instances then no longer share the exclusion, so two processes could open one namespace.

Decision: `flashstore_spdk_mp_<bdf>` and `flashstore_spdk_ns_<bdf>_<nsid>` move to `/run/croit-flashstore-osd` (root:ceph `1770`, created
by `tmpfiles.d/croit-flashstore-osd.conf` and `croit-flashstore-prep@`, adr 0649 am. 1); names and lock semantics are unchanged. The lab
containers bind `/run/croit-flashstore-osd` next to `/var/tmp` (SPDK's own internal lock) and `/run/dpdk`; `lab/spdk-mp-live.sh` and
`lab/vstart-bench.sh` create the directory and check the new namespace-lock path.

Rationale: same directory as the PCI claim, one shared, host-visible lock location for every process of a controller.

Consequences: + primary rolling restart protection and per-namespace exclusion work under `PrivateTmp=true` and across
containers; - the directory must exist with group `ceph` write access, else start fails with the fix command.

Tests: `nvme::spdkmp::tests::lock_paths` (new paths); the live script asserts the second-open refusal through the new
directory. Siblings checked: non-shared SPDK opens use the PCI claim only (same directory); the kernel NVMe tier has no
multi-process mode.
