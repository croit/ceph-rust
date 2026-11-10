# How-to: prepare a host

This page covers what must be in place on a host before croit-flashstore-osd can use its NVMe device and, optionally, its network. It is for production hosts. Lab and virtual-machine setups are covered in the last section.

Run the read-only check at each step to confirm the result: `croit-flashstore-osd --check --format json`. Exit 0 means no FAIL. See [reference/exit-codes.md](../reference/exit-codes.md).

## What the preparation does

`croit-flashstore-prep@ID.service` runs before the OSD starts and does three things for the devices in `[osd.ID]`:

1. Reserves hugepages on the host, if fewer are free than the OSD needs.
2. Mounts hugetlbfs on `/dev/hugepages`, if it is not mounted.
3. For the SPDK backend: binds the NVMe controller (`flashstore_dev`) to `vfio-pci`. With `flashstore_store_backend = kernel` or `kernel-cmd` the controller stays on the kernel `nvme` driver. NICs always stay on their kernel drivers; a leftover `flashstore_vf_pci` is ignored and produces a warning that names the line to delete and, for a NIC an older release had moved to `vfio-pci`, the commands that return it to its kernel driver.

It reads the hugepage budget through `croit-flashstore-tool hugepage-budget`, so it reserves exactly what the OSD uses. It touches only the NVMe controller named in that OSD's section, through `croit-flashstore-tool nvme-rebind` (installed with the package). Container hosts must install a host copy of the tool, or the preparation unit refuses with exit 3: `docker create --name flashstore-tool-copy IMAGE && docker cp flashstore-tool-copy:/usr/bin/croit-flashstore-tool /usr/local/bin/ && docker rm flashstore-tool-copy` (podman likewise). Copy it again after every image upgrade. It refuses, with the exact reason, a PCI address that is not an NVMe controller, and a controller whose namespace or partition is mounted, has holders (LVM, MD, dm-crypt), is swap, or is held exclusively or locked by another process such as a running OSD. The exclusive claim is held until the new driver is bound. A refusal exits with code 3 and blocks the OSD unit with a clear failure.

The device list comes from the root-owned `/etc/ceph/<cluster>.conf` only, never from the OSD data dir (which belongs to the daemon user). A `spdk:` OSD needs `flashstore_dev` in its `[osd.ID]` section; `croit-flashstore-prep` binds nothing when the key is absent.

The preparation runs as root. The daemon itself runs as the `ceph` user.

## 1. Firmware and kernel

| Requirement | Why | Check |
|---|---|---|
| IOMMU enabled in firmware (VT-d or AMD-Vi) | `vfio-pci` needs it for device access. | `ls /sys/kernel/iommu_groups` is not empty. |
| Kernel command line `intel_iommu=on iommu=pt` (AMD: `amd_iommu=on iommu=pt`) | Enables the IOMMU. The check looks for `iommu=pt`. | `cat /proc/cmdline` |
| Kernel with `vfio-pci` available | Binds the devices. | `modprobe vfio-pci` succeeds. |
| Hugepages of 2 MiB (default) | The daemon's memory for SPDK (DPDK environment) and the payload heap. | `grep Huge /proc/meminfo` |
| io_uring allowed for user `ceph` | The kernel network tier and the kernel storage backend use io_uring. RHEL 9 and its rebuilds ship `kernel.io_uring_disabled=2` (io_uring off); the OSD then refuses to start and names the fix. | `sysctl kernel.io_uring_disabled kernel.io_uring_group`; fix with `croit-flashstore-tool host-tune --check os.io_uring` (dry run), then `--apply` |

After you change the command line, reboot.

If the host has no IOMMU, the preparation refuses `vfio-pci` and tells you the reason. The no-IOMMU fallback is for lab hosts only. See [section 4](#4-lab-and-virtual-machine-setups).

## 2. Hugepages

The preparation reserves `flashstore_hugepages_mb` (default 2048) per OSD, using `flashstore_hugepage_kb` (default 2048) pages. Reservation at runtime can fail on fragmented memory. In that case the preparation exits with code 1 and asks you to reserve pages at boot.

To reserve at boot, add to the kernel command line:

```
default_hugepagesz=2M hugepagesz=2M hugepages=<N>
```

Use `N` = the sum of the hugepage needs of all OSDs on the host, in pages of 2 MiB (each OSD's `flashstore_hugepages_mb` divided by 2).

Check: `grep Huge /proc/meminfo` shows `HugePages_Free` at or above the need.

## 3. Devices and network

### NVMe

- The NVMe controller for the OSD must not hold the boot disk or any mounted or in-use namespace.
- The device must have power-loss protection (no volatile write cache) and 4096-byte LBAs. The check reports both. The store setup (`mkfs`) refuses a device with a volatile write cache. See [how-to/prepare-and-activate.md](prepare-and-activate.md).
- `croit-flashstore-prep` binds the controller to `vfio-pci` at start. The device must not be in use by the kernel storage stack.
- `vfio-pci` resets the device when the OSD opens it. Some drives do not survive this reset and drop off the PCIe bus. If the SPDK tier fails to attach, see [troubleshoot.md](troubleshoot.md#spdk-the-nvme-drive-drops-off-the-pcie-bus-when-the-osd-starts) before you try anything else.
- Kernel storage backend (`flashstore_store_backend = kernel` or `kernel-cmd`, the namespace stays on the kernel `nvme` driver): the namespace node must be readable and writable by user `ceph` (udev rule). Kernels that allow NVMe passthrough only to `CAP_SYS_ADMIN` (for example RHEL 9) still work: the OSD reads the namespace geometry from sysfs, runs `kernel-cmd` as direct block I/O, and names the fallback in its startup line (`missing=[UNPRIV_PASSTHRU]`). NVMe SMART data needs `CAP_SYS_ADMIN` on every kernel and is not reported by a non-root OSD on this backend. `kernel-cmd` needs both nodes of the namespace, the generic node `/dev/ngXnY` and the block node `/dev/nvmeXnY` (exclusive claim and direct I/O of buffers that passthrough must not name); in a container pass both (`--device /dev/ngXnY --device /dev/nvmeXnY`), otherwise the OSD refuses to start and names the missing node. Kernels without fixed-buffer NVMe passthrough run `kernel-cmd` as direct block I/O (`missing=[URING_CMD_FIXED]`).

Identify the controller:

```
lspci -nn -d ::0108
```

Its PCI address goes into `flashstore_dev = spdk:<address>`.

### Network

The OSD uses kernel TCP. It needs no NIC binding and works with any NIC. See [explanation/network-tiers.md](../explanation/network-tiers.md).

Nothing is needed on the NIC beyond the address in `flashstore_ip`.

The check reports the NIC state, including NIC settings and interrupt placement that affect kernel TCP. It does not change them. Apply the fixes it names yourself.

## 4. Lab and virtual-machine setups

A host without a dedicated NVMe controller cannot run the production configuration. The check says so on purpose: it warns when it runs in a virtual machine, because the production path needs bare metal with real IOMMU, VFIO, and SR-IOV.

The following are for functional tests only. Do not measure performance or durability on them.

| Setup | Effect | Limit |
|---|---|---|
| `flashstore_driver = uio_pci_generic` | Binds without an IOMMU. Device addresses are physical. | No DMA isolation. Lab only. |
| `vfio` `enable_unsafe_noiommu_mode=1` in the guest | Lets `vfio-pci` run without an IOMMU. | No DMA isolation. Lab only. |
| Emulated NVMe in the VM (QEMU `-device nvme`) | Gives a controller without passthrough. | Not a production configuration. Its reported write cache decides whether `mkfs` accepts it. |
| `croit-flashstore-tool mkfs --allow-vwc` | Accepts a device with a volatile write cache. | Writes are not durable on power loss. Lab only. Never on production data. |

Passthrough of a controller or a virtual function into a VM needs a physical device on the host. Without one, the only option is an emulated controller, with the limits in the table above.

## 5. Verify

```
croit-flashstore-osd --check --format json
croit-flashstore-tool inspect --id <N>
```

The check exits 0 when no FAIL is present. Fix each FAIL before you start the OSD. WARN results are allowed, but each one costs performance or margin. The check lists the fix for each result.

Related: [tutorials/first-osd.md](../tutorials/first-osd.md), [how-to/prepare-and-activate.md](prepare-and-activate.md), [reference/configuration.md](../reference/configuration.md).
