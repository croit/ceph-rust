# Reference: hardware and host requirements

This page lists the host checks that croit-flashstore-osd runs and the result each one can produce. Run the checks read-only before `prepare` and `mkfs`.

```
croit-flashstore-osd --check
croit-flashstore-osd --check --format json-pretty
```

- `--format` accepts `plain` (default), `json` and `json-pretty`.
- Exit code `0`: no check failed (warnings pass). Exit code `1`: at least one check failed. Exit code `2`: usage error.

Check results have four states: `OK`, `WARN`, `FAIL` and `N/A`. `N/A` means the check could not run on this host, for example because sysfs is not available.

## Checks

### NVMe devices

| Check | Result | Condition |
|---|---|---|
| Volatile write cache (power-loss protection) | FAIL | A volatile write cache is reported. `mkfs` refuses such a device. |
| Volatile write cache (power-loss protection) | OK | No volatile write cache is reported. |
| Volatile write cache (power-loss protection) | N/A | Not probed. The check does not bind the device to read the state. |
| LBA format | WARN | The namespace does not offer a 4096-byte format. |
| LBA format | OK | The active format is 4096 bytes. |
| PCIe link | WARN | The current speed or width is below the maximum the device reports. |
| NUMA node | WARN | `flashstore_lcores` of the OSD that uses the device lists cores outside the device's NUMA node. |
| In use | FAIL | The namespace has partitions, mounts, holders (md, LVM) or swap. The prepare step refuses it. |

### IOMMU and VFIO

| Check | Result | Condition |
|---|---|---|
| IOMMU groups | OK | At least one IOMMU group exists. |
| IOMMU groups | WARN | No IOMMU group exists. The VFIO tier cannot run. |
| Kernel argument `iommu=pt` | WARN | The IOMMU is active but not in passthrough mode. |

The IOMMU check records why VFIO is needed: DMA isolation, MSI-X interrupts and non-root operation. Without an IOMMU only `uio_pci_generic` remains, which is for lab use and needs root.

### Memory and hugepages

| Check | Result | Condition |
|---|---|---|
| RAM | FAIL | Total memory is below 4 GiB. |
| RAM | WARN | Total memory is below 16 GiB. |
| RAM | OK | Total memory is 16 GiB or more. |
| Hugepages | FAIL | No hugepages are reserved. |
| Hugepages | WARN | Free hugepages are below the need. |
| Hugepages | OK | Free hugepages cover the need. |

The need is the sum of `flashstore_hugepages_mb` over the OSDs in the configuration file. Without a configuration file the check assumes 2048 MiB per OSD. The RAM messages recommend at least 8 GiB per OSD. This is a recommendation in the check output. The daemon does not enforce it.

### CPU

| Check | Result | Condition |
|---|---|---|
| `isolcpus` / `nohz_full` | WARN | Neither is set. This check is optional latency tuning. |

### Network

| Check | Result | Condition |
|---|---|---|
| Link speed | WARN | Speed is below 25 Gbit/s. |
| Link state | WARN | The link is down. |
| NIC rings | WARN | Receive or transmit ring is below its reported maximum. |
| NIC IRQs | WARN | NIC queue interrupts are concentrated: fewer queues than NIC-local cpus, or several queues on one cpu while another NIC-local cpu has none. |

### RDMA (optional)

Only relevant with `flashstore_rdma = true`. Without RDMA devices the section reports `N/A`. Checks run per RDMA device and port; the QoS check runs on a live host only. See [how to enable RDMA](../how-to/enable-rdma.md).

| Check | Result | Condition |
|---|---|---|
| Port | OK | The port is ACTIVE and its link layer is Ethernet (RoCE). |
| Port | WARN | The port is not ACTIVE. |
| Port | N/A | The link layer is not Ethernet (InfiniBand is not supported). |
| RoCEv2 GID | OK | The device has a RoCEv2 GID with an IP address. |
| RoCEv2 GID | WARN | No RoCEv2 GID with an IP on the netdev. The OSD's IP must be configured there. |
| RoCE path MTU | OK | The interface MTU is 4192 or more (RoCE path MTU 4096, the best; 9000 is recommended). |
| RoCE path MTU | WARN | The interface MTU is below 4192. From 1120 (1500 on a standard network) RDMA works with lower throughput; below 1120 RDMA stays off for the device. Fix: `ip link set <netdev> mtu 9000` and jumbo frames on every switch port of the path. |
| RoCE QoS | OK | PFC is on for the priority that the RoCE TOS maps to, and global pause is off. |
| RoCE QoS | WARN | PFC is off (lossy), the TOS priority is not PFC-protected, or global pause and PFC are both on. |
| RoCE QoS | N/A | DCB is not readable on the netdev. |
| DCQCN | OK | ECN notification and reaction point are enabled (on the RoCE priority where DCB is readable). |
| DCQCN | WARN | Notification or reaction point disabled. |
| DCQCN | N/A | The driver does not expose the setting. |
| RoCE loss | OK | The NIC recorded no RoCE drop since the driver loaded. |
| RoCE loss | WARN | The NIC recorded RoCE drops (out-of-sequence packets, sequence-error NAKs, ACK timeouts). The value says whether the switches marked ECN; without marks the NIC slows down only after drops. Fix: the lossless class (PFC on the RoCE priority) and ECN marking on the switch queue. |
| RoCE loss | N/A | The port has no RoCE loss counters. |
| PCIe link | WARN | The current speed or width is below the maximum. |

Requirements behind the checks: a RoCEv2 NIC (for example ConnectX-class or Broadcom NetXtreme-E with the kernel RDMA driver loaded), rdma-core on hosts that build or run the client, jumbo frames end to end (best; 1500 works with lower throughput), and `RLIMIT_MEMLOCK` (or `CAP_IPC_LOCK`) that covers `flashstore_rdma_memory`. The memlock limit is checked by the daemon at start, not by `croit-flashstore-osd --check`.

### Kernel and OS

Kernel version: Linux 5.19 or newer (the store ring uses 128-byte submission entries). NVMe passthrough (`kernel-cmd`, `/dev/ngXnY`) as the non-root OSD needs Linux 6.2 or newer. RHEL/Alma 9 (5.14.0-687 or newer) carries these io_uring features as backports and works; its kernel refuses passthrough to a non-root process, so the OSD reads the namespace geometry from sysfs and runs `kernel-cmd` as direct block I/O (startup line `missing=[UNPRIV_PASSTHRU]`, no NVMe SMART data). The OSD probes every capability at start and never gates on the version number. Recommended: Linux 7.2.

| Check | Result | Condition |
|---|---|---|
| `kernel.numa_balancing` | WARN | Not `0`. |
| `init_on_alloc` | WARN | Page zeroing on allocation is on (cmdline or kernel config default). Fix: kernel cmdline `init_on_alloc=0`, reboot. Trade-off: gives up an info-leak hardening of the kernel. |
| io_uring | OK | The kernel tier ring works, the required features are present and SEND_ZC is available. |
| io_uring | WARN | The required features are present but SEND_ZC is not available. The tier works without it. |
| io_uring | FAIL | A ring cannot be created, or a required feature is missing. |
| io_uring | FAIL | `kernel.io_uring_disabled` keeps the OSD user `ceph` from creating rings (`2`, the RHEL 9 default, or `1` without the `ceph` group in `kernel.io_uring_group`). The OSD refuses to start with one line naming the exact `sysctl` command. Fix: `sysctl -w kernel.io_uring_group=<gid of ceph> kernel.io_uring_disabled=1` (io_uring for the OSD group only) or `kernel.io_uring_disabled=0` (every process); `croit-flashstore-tool host-tune --check os.io_uring --apply` applies the first. Persist it in `/etc/sysctl.d/`. |
| `CAP_IPC_LOCK` and `CAP_SYS_NICE` | OK | Both are in the effective capability set of the process running the check. |
| `CAP_IPC_LOCK` and `CAP_SYS_NICE` | WARN | At least one is missing. |
| Virtualization | WARN | The host is a virtual machine. Production runs on bare metal. |

## Related

- [How to prepare the host](../how-to/prepare-host.md)
- [Reference: exit codes](exit-codes.md)
- [Explanation: network tiers](../explanation/network-tiers.md)
