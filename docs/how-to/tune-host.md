<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# How to tune the host with host-tune

croit-flashstore-osd never changes host settings that it does not own (NIC offloads, ring sizes, IRQ affinity, sysctls). It warns at start and in `croit-flashstore-osd --check`, and prints the exact command for each warning. `croit-flashstore-tool host-tune` applies those commands for you, when you ask for it.

## 1. See the plan

```
croit-flashstore-tool host-tune
```

This changes nothing. For each fix that can be applied, it shows the current value, the target and the command. Fixes that cannot be applied by a command (BIOS, kernel command line, hardware) are listed as `manual` with the hint from `croit-flashstore-osd --check`.

Limit the plan with `--check ID` (an exact id such as `net.eth0.rings`, or a prefix such as `net.eth0`) and `--iface IF`. Pass your OSD configuration with `--conf FILE` if it is not `/etc/ceph/ceph.conf`; the IRQ plan spreads one NIC queue interrupt per NIC-local cpu, OSD cores included, which can increase performance over a few dedicated interrupt cpus. If the NIC has fewer queues than NIC-local cpus, the plan adds the `ethtool -L <if> combined <n>` hint.

## 2. Apply

```
sudo croit-flashstore-tool host-tune --apply
```

Needs root (exit 3 otherwise; nothing is changed). Settings that are already correct are skipped, so you can run it again. After the changes the host is checked again and each action reports `ok`, `not-ok` or `failed`. The path of the state file is printed (default `/var/lib/croit-flashstore/host-tune.json`, persistent, created `0600`, every apply appends; it is written before the first change and an unwritable path applies nothing; the boot unit from `--emit-persist` records into the same file; `--revert` refuses a state file that is a symlink, owned by another uid or group/other-writable). Exit code 1 means a command failed or a check is still not ok.

Required tools by fix: `ethtool` (NIC), `ip`, `sysctl`, `cpupower` (governor), `mount`, `modprobe`. A missing tool fails only its own step.

## 3. Revert

```
sudo croit-flashstore-tool host-tune --revert   # or: --revert FILE
```

Restores every value that was recorded before it was changed. Exceptions: the VF hygiene fix (`promisc off`) is not undone on purpose, and the RSS table returns to the driver default.

## 4. Make it persistent

The changes last until reboot. Print what a persistent setup needs:

```
croit-flashstore-tool host-tune --emit-persist
```

It prints sysctl.d, modules-load.d and fstab lines and a systemd unit that runs the same `--apply` at boot. The tool does not install them. The recommended IRQ layout is the driver default (one queue per NIC-local cpu); do not let `irqbalance` or other tools concentrate the queue interrupts on a few cpus.

## 5. Zero-copy receive (zcrx) NIC setup

The OSD receives client connections through io_uring zero-copy receive (zcrx) when the kernel, the NIC and the host steering allow it, and through the normal copy receive otherwise. Both are fully functional; zcrx can lower the CPU cost of receiving. Requirements: a kernel with `IORING_OP_RECV_ZC`, a physical function whose driver offers queue memory providers (SR-IOV VFs and virtio NICs do not), header/data split, the OSD running with `CAP_NET_ADMIN`.

The NIC needs header/data split, ntuple filters, a channel count, an RSS table that leaves the zcrx queues alone, and one flow rule that sends the OSD's public port (and nothing else) to its zcrx queues. With `K` zcrx queues (one per OSD core), `M` queues for the rest of the host and the OSD's public port:

```
sudo croit-flashstore-tool host-tune --iface eth0 --zcrx-queues 4 --host-queues 4 --osd-port 6800 --apply
```

Pass only the public port: a queue that also receives another port (the cluster port, another OSD, another daemon) is refused. Several OSDs on one NIC each need their own zcrx queues.

The flow rule names a fixed port, but an OSD without `flashstore_port_base` takes the first free port of `ms_bind_port_min`..`ms_bind_port_max` (default 6800..7300) and may land on another port after a restart. On zcrx hosts pin each OSD's ports with `flashstore_port_base` (four consecutive ports, exactly those or the start fails) and pass the same public port here.

The channel change restarts the NIC queues and briefly interrupts traffic on that interface. Run the dry run first.

The OSD prints one startup line with the outcome: `zcrx=on iface=... queues=[...]`, or `zcrx=off reason=<missing piece> ... fix: <command>`. A core that cannot register its queue prints `WARNING zcrx core N: copy receive, reason=...`. `croit-flashstore-tool hwcheck` shows the kernel (`os.zcrx`) and NIC (`net.<if>.zcrx_ready`) halves.

zcrx is disabled by default until it is validated: without the option the OSD prints `zcrx=off reason=default-off` and receives by copy. Opt in with `--knet-zcrx auto`; `--knet-zcrx off` turns it off explicitly.

## Machine-readable output

`--format json` or `json-pretty`. Exit codes: [reference/exit-codes.md](../reference/exit-codes.md).
