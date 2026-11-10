# How to prepare, activate, and list OSDs

`croit-flashstore-tool` owns the lifecycle. `prepare` writes the store once, `activate` checks preconditions before start, and `list` shows what is on the host.

## Before you start

- Run `croit-flashstore-osd --check` and resolve every FAIL.
- Hugepages are reserved for the OSD (`flashstore_hugepages_mb`, default 2048 per OSD).
- `prepare` is destructive. It deallocates the whole namespace. Confirm the device holds no data you need.
- `prepare` and direct `mkfs` refuse a device that is not empty unless `--wipe` is passed. The probe
  reads the first 8 KiB plus the btrfs superblock windows at 64 KiB and 256 KiB; any signature or non-zero data there
  counts as used.
- Stop any running OSD on the device first. A device held by a running OSD is refused with exit 3.

## Prepare

```
croit-flashstore-tool prepare --dev spdk:0000:03:00.0 --id 7 [--store-shards auto|N] [--cores N] [--base-pct N]
```

| Flag | Default | Meaning | Fixed after prepare? |
|---|---|---|---|
| `--store-shards` | `auto` | Number of store shards (one WAL ring and one NVMe queue pair each). `auto` = configured cores. | Yes |
| `--cores` | from `flashstore_cores` / `flashstore_lcores` | Overrides the core count used for `auto`. | Yes, for `auto` |
| `--base-pct` | 25 (production devices >= 256 GiB) | Share of each shard's space as static chunks. `100` = plain static layout. | Yes, re-mkfs to change |
| `--crush-device-class` | `nvme` | Device class the OSD registers with. | No (CRUSH side) |
| `--no-discard` | off | Skip the whole-namespace deallocate before format (runtime trims stay enabled). | Per run |
| `--format-lba4k` | off | Format the namespace to 4096-byte LBAs. Destroys data. Refuses if the controller's other namespaces would be hit. | Yes |

`spdk:` addresses must have a PCI domain of at most `ffff`. A device behind Intel VMD (domain `10000` or higher) is refused by `prepare` and `activate` before anything is written; disable VMD in the BIOS or use the kernel tier (`kernel:/dev/nvmeXnY`).

Changing `--store-shards` after prepare requires a redeploy with a fresh device. Changing cores across restarts needs nothing else.

Verify:

```
croit-flashstore-tool inspect --id 7 --format json
```

## Activate

`activate` runs before `run` and checks hugepages, memlock, and the NIC and NVMe binding. The systemd unit calls it, so you rarely run it by hand. It follows `flashstore_store_backend` like the daemon: with `kernel` or `kernel-cmd` the NVMe must stay on the kernel `nvme` driver (no hugepage pool needed) and the store identity is read through the namespace node; with `spdk` (default) the NVMe must be bound to `vfio-pci`. `prepare`, `inspect` and the offline tools (`fsck`, `repair`, `objectstore`, ...) given `--id` follow the same key.

```
croit-flashstore-tool activate --id 7
```

Exit 0 means the preconditions hold.

## List

```
croit-flashstore-tool list --format json
```

Use this to confirm which OSD ids the host holds before running `prepare` on a device.

## OS disk lost: recreate OSD dirs from devices

After a host reinstall the OSD dirs (`/var/lib/ceph/osd/<cluster>-<id>`) are gone, the NVMe devices are not. The device superblock carries the identity (osd id, osd uuid, cluster fsid); `activate --from-device` recreates the dir from it. The device is only read, never written.

```
croit-flashstore-tool list --scan-devices                 # which devices hold a FlashStore store
croit-flashstore-tool activate --from-device --dev kernel:/dev/nvme0n1 --keyring osd.5.keyring
croit-flashstore-tool activate --from-device --all --keyring host.keyring   # every device with a store
```

- `--keyring FILE` is a classic keyring file with the `osd.N` entry (one file may carry several entries for `--all`). Omit it only for an auth-none cluster. There is no mon fetch: take the key from a backup, another host, or `ceph auth get osd.N` run elsewhere.
- An existing dir with the same identity (osd id, osd uuid, cluster fsid, device) is left untouched (idempotent). A dir with a different identity is refused with exit 3; no file is ever overwritten.
- `--cluster`, `--conf` and `--data-dir` work like for `activate`. The conf file must exist (it is not on the lost disk: restore it first, or pass `--conf`).
- `list --scan-devices` exit: 0 every device scanned, 1 a device unreadable, 3 a device held.

## Common outcomes

| Symptom | Exit | Action |
|---|---|---|
| `device is in use` | 3 | Stop the OSD that holds the device. Do not use another SPDK program against it. |
| `prepare` rerun on an already prepared id | 4 | Expected. Do not prepare again; use `activate` or `list`. |
| Format NVM would hit other namespaces (`--format-lba4k`) | 3 | Use a single-namespace controller or `ns=N` selection. |

See [reference/exit-codes.md](../reference/exit-codes.md) for every code.
