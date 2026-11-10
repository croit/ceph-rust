# How to build test VMs for a test cluster

This page builds virtual machines that run croit-flashstore-osd for functional tests. It is not for production. Nothing measured on these VMs describes production performance or durability.

The VMs need a physical NVMe controller. The VM gets it by passthrough. Without a physical device, use an emulated controller; see the limits in [section 6](#6-emulated-nvme).

## 1. Choose the setup

| Need | Use |
|---|---|
| Test kernel TCP | One VM with one NVMe passed through and a virtio NIC for SSH. |
| Test without a guest IOMMU | Use `uio_pci_generic` with Secure Boot off. See [section 5](#5-guest-without-iommu). |

Plan one NVMe per OSD. Each NVMe controller carries one OSD (see [migrate from classic OSDs](migrate-from-classic.md)).

## 2. Host requirements

On the hypervisor:

- Virtualization and IOMMU in firmware (VT-d or AMD-Vi).
- Kernel command line `intel_iommu=on iommu=pt` (AMD: `amd_iommu=on iommu=pt`).
- Hugepages reserved for the VM, for example `default_hugepagesz=1G hugepagesz=1G hugepages=<N>` on the kernel command line.
- The NVMe controller and the NIC VF each in their own IOMMU group. Check with:

  ```
  for d in /sys/kernel/iommu_groups/*/devices/*; do
    n=${d##*/}; g=${d%/devices/*}; g=${g##*/}
    echo "group $g: $(lspci -nns "$n")"
  done | sort -V
  ```

- The NVMe controller is not the boot disk and is not mounted.

Reboot after changing the kernel command line, then check `cat /proc/cmdline` and `ls /sys/kernel/iommu_groups | wc -l` (must be above 0).

## 3. Create the VM

These steps are for Proxmox VE. The same steps apply to any hypervisor that can pass PCI devices through with `pcie`.

1. Create the VM with `q35` and `ovmf`, CPU type `host`, and balloon off:

   ```
   qm create <VMID> --name croit-flashstore-test --ostype l26 --machine q35 --bios ovmf \
     --cpu host --sockets 1 --cores 8 --numa 1 --memory 16384 --balloon 0 \
     --net0 virtio,bridge=vmbr0 --scsihw virtio-scsi-single \
     --scsi0 <storage>:32 --efidisk0 <storage>:1,efitype=4m,pre-enrolled-keys=0
   ```

   Replace `<VMID>` and `<storage>`. Do not enable ballooning with hugepages.

2. Enable the guest IOMMU. In `/etc/pve/qemu-server/<VMID>.conf`:

   ```
   machine: q35,viommu=intel
   ```

   Use `viommu=intel` on an Intel host and `viommu=virtio` on an AMD host.

3. Pass the NVMe controller (not a namespace). Find it with `lspci -nn -d ::0108`, then add it to the VM:

   ```
   hostpci0: <BDF>,pcie=1
   ```

   Use a resource mapping (Datacenter > Resource Mappings) if you prefer. Record the controller's identity before passthrough, because the host can no longer read it afterwards:

   ```
   nvme id-ctrl /dev/nvme<X> | grep -E '^(mn|sn|fr|vwc|awupf|nn) '
   nvme id-ns /dev/nvme<X>n1 | grep -E '^(nsze|flbas|lbaf)'
   ```

4. Start the VM and continue with section 4.

## 4. Prepare the guest

Run as root in the guest.

1. Kernel command line. In `/etc/default/grub`, add to `GRUB_CMDLINE_LINUX_DEFAULT`:
   - `intel_iommu=on iommu=pt` (Intel) or `amd_iommu=on iommu=pt` (AMD),
   - hugepages, for example `default_hugepagesz=2M hugepagesz=2M hugepages=<N>`, where `<N>` is the sum of `flashstore_hugepages_mb` over the OSDs divided by 2.

   Then run `update-grub` and reboot.

2. Install the tools:

   ```
   apt update && apt install -y pciutils ethtool nvme-cli iproute2 tcpdump git curl
   ```

3. Load the vfio modules and check the IOMMU:

   ```
   modprobe vfio_pci
   ls /sys/kernel/iommu_groups | wc -l     # must be above 0
   ```

4. Bind the NVMe controller (and any VF) to `vfio-pci`. Find the addresses with `lspci -nnk`. Then:

   ```
   bind() {
     [ -e /sys/bus/pci/devices/$1/driver ] && echo "$1" > /sys/bus/pci/devices/$1/driver/unbind
     echo vfio-pci > /sys/bus/pci/devices/$1/driver_override
     echo "$1" > /sys/bus/pci/drivers_probe
   }
   bind 0000:<NVME_BDF>
   ```

   Check with `lspci -nnk -s <BDF>`: the driver in use must be `vfio-pci`.

5. Check the host with the croit-flashstore-osd check tool: `croit-flashstore-osd --check --format json`. Fix each FAIL. A WARN about the VM is expected; see [hardware requirements](../reference/hardware-requirements.md).

Then continue with [how to prepare the host](prepare-host.md) for the croit-flashstore-osd steps.

## 5. Guest without IOMMU

If the guest has no IOMMU, `vfio-pci` cannot run. Use `uio_pci_generic` instead. This works only with Secure Boot off, because kernel lockdown blocks the PCI access that uio needs.

```
modprobe uio_pci_generic
```

Set `flashstore_driver = uio_pci_generic` in the OSD configuration. `croit-flashstore-prep` then binds the controller to uio instead of vfio. Device addresses are physical, and there is no DMA isolation. Use this only in the lab.


## 6. Emulated NVMe

Without a physical controller, QEMU can emulate one (`-device nvme`). Emulated controllers are not a production configuration.

- `mkfs` refuses a device with a volatile write cache unless `--allow-vwc` is given. Whether an emulated controller is accepted depends on the write cache it reports. This has not been tested for croit-flashstore-osd.
- `--allow-vwc` is a lab-only flag. Writes are not durable on power loss.

For a functional test with an emulated controller, check first with `croit-flashstore-osd --check` that the device is reported and that `mkfs` accepts it. If it refuses, the device cannot be used for an OSD.

## 7. Verify

- `ceph osd tree` on the cluster shows the OSD after prepare and start.
- `croit-flashstore-tool inspect --id <N>` shows the store identity.
- `croit-flashstore-osd --check --format json` reports no FAIL.

## Related

- [How to prepare the host](prepare-host.md)
- [How to prepare and activate](prepare-and-activate.md)
- [Hardware requirements](../reference/hardware-requirements.md)
- [Tutorial: first OSD](../tutorials/first-osd.md)
