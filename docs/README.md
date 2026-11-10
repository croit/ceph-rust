# croit-flashstore-osd documentation

croit-flashstore-osd is a Ceph OSD daemon for NVMe-only storage, written in Rust. It is wire-compatible with `ceph-osd` for the pinned Ceph release (v21.2.0) and can join a cluster with classic OSDs.

Pick the section that matches your task:

| You want to... | Read |
|---|---|
| Deploy your first OSD | [tutorials/first-osd.md](tutorials/first-osd.md) |
| Build or install the .deb / .rpm packages (OSD and client libraries) | [how-to/build-and-install-packages.md](how-to/build-and-install-packages.md) |
| Perform a specific task (prepare, upgrade, recover, replace) | [how-to/prepare-and-activate.md](how-to/prepare-and-activate.md) |
| Apply the host settings that `croit-flashstore-osd --check` recommends | [how-to/tune-host.md](how-to/tune-host.md) |
| Move a cluster from classic OSDs to croit-flashstore-osd | [how-to/migrate-from-classic.md](how-to/migrate-from-classic.md) |
| Build VMs for a test cluster (not production) | [how-to/build-test-vms.md](how-to/build-test-vms.md) |
| Look up a command, flag, option, or exit code | [reference/admin-commands.md](reference/admin-commands.md) |
| Understand the network transport | [explanation/network-tiers.md](explanation/network-tiers.md) |
| Use RDMA (RoCEv2) between OSDs and native clients | [how-to/enable-rdma.md](how-to/enable-rdma.md), [explanation/rdma.md](explanation/rdma.md) |
| Run a KVM/QEMU RBD disk over RDMA | [how-to/enable-rdma.md](how-to/enable-rdma.md#applications-that-use-the-librbd-c-api-qemukvm) |
| Understand OMAP key/value usage statistics | [explanation/omap-accounting.md](explanation/omap-accounting.md) |
| Find out which branch matches your Ceph release | [explanation/branches-and-versions.md](explanation/branches-and-versions.md) |

## Scope

- Supported pool types: replicated pools. Erasure-coded pools are not stored on croit-flashstore-osd; see [how-to/erasure-pools.md](how-to/erasure-pools.md).
- Supported storage: NVMe devices with power-loss protection (PLP) and 4096-byte LBAs; whole namespaces only (no partitions, LVM or filesystem on the OSD device).
- Supported networking: kernel TCP. See [explanation/network-tiers.md](explanation/network-tiers.md). An optional RDMA (RoCEv2) upgrade runs on top of kernel TCP: [explanation/rdma.md](explanation/rdma.md).
- Ceph release: depends on the branch. `main` targets v21.2.0, `v20.2.4` targets v20.2.4. Use the branch that matches your cluster. See [explanation/branches-and-versions.md](explanation/branches-and-versions.md).
- Mixed acting sets with classic OSDs are supported on the branch that matches the cluster's release.
