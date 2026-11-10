# How to troubleshoot croit-flashstore-osd

Start from the symptom. Each entry gives the cause, the check that confirms it, and the fix. Exit codes are listed in [reference/exit-codes.md](../reference/exit-codes.md).

## First steps for any problem

```
systemctl status croit-flashstore-osd@N
journalctl -u croit-flashstore-osd@N --since "1 hour ago"
croit-flashstore-osd --check --format json > hw.json; echo $?
ceph tell osd.N status
ceph log last 100
```

`croit-flashstore-osd --check` is read-only and changes nothing. Run it before you change any host setting.

## The daemon does not start

| Symptom | Exit | Cause | Action |
|---|---|---|---|
| Unit stays `failed`, no restart | 3 | Refused by policy: cluster `require_osd_release` is outside the release window, bad configuration, or a failed precondition | Read the log line that names the reason. Fix the configuration or the cluster release. Do not clear the start limit until the cause is fixed. |
| `device is in use` | 3 | Another process holds the NVMe device, often a second OSD or a stale process | Find the holder with `journalctl`, then stop it. Never use another SPDK program against the device. |
| `activate` refuses: "bind it to vfio-pci first" | 3 | The OSD has no `flashstore_store_backend` (default `spdk`) but its NVMe is on the kernel driver | Set `flashstore_store_backend = kernel-cmd` (or `kernel`) for that OSD, or bind the NVMe to `vfio-pci` for the SPDK tier. |
| Start fails, hugepages or memlock suspected | see log | Hugepages not reserved, or memlock below unlimited | Run `croit-flashstore-osd --check`. Fix each FAIL under `Memory`: no reserved hugepages is a FAIL, too few free is a WARN. Reserve `flashstore_hugepages_mb` before start. |
| `hugepages: ... leaves the store no DMA memory beside the payload budget` | 1 | SPDK tier: half of `flashstore_hugepages_mb` goes to network payloads, the rest did not cover the device queues and the store's DMA buffers | Raise `flashstore_hugepages_mb` and reserve the hugepages again. The start line `store DMA budget` shows the share the store got. |
| `hugepages: ... its last quarter must hold the largest device command ...: set flashstore_hugepages_mb <n> or more` | 1 | SPDK tier: a quarter of the store's DMA share must hold the largest single device transfer | Set `flashstore_hugepages_mb` to at least the named value and reserve the hugepages again. |
| `spdk tier: the store has <n> shards but runs on <m> cores ...` | 1 | SPDK tier with a DMA budget needs at least one store core per shard | Give the OSD as many cores as shards, or redeploy with fewer shards. |
| Unit restarts repeatedly | 1 or 134/137 | Crash or runtime error | Read the crash dump in `/var/lib/ceph/crash/`, then `ceph crash ls`. Restarts are limited to 3 in 30 minutes. |
| `--check` shows IOMMU groups as WARN | (check exit 0) | No IOMMU groups; only the uio fallback is possible | Enable the IOMMU in firmware and on the kernel command line, and load `vfio-pci`. Without it, the SPDK tier runs only in the uio fallback. |

## The OSD runs but does not join

Check that it is `up` and `in`:

```
ceph osd tree | grep "osd.N "
ceph tell osd.N status
```

| Symptom | Cause | Action |
|---|---|---|
| `osd.N` is `down` | Daemon not running, or it cannot reach the mons | Check the unit and `mon_host`. Check the address in `flashstore_ip` is on the data network. |
| `osd.N` is `up` but `out` | Set manually, or the OSD was purged and recreated | `ceph osd in osd.N` only after you confirm it is healthy. |
| Device class is not `nvme` | `--crush-device-class` was set differently at prepare | Set the class with `ceph osd crush set-device-class`. Do not reprepare the device. |
| OSD moved to a different CRUSH location on restart | Placed by hand (`ceph osd crush set`) without `crush_location`; at start the OSD re-applies its default location (`host=<short host>,root=default`) because `osd_crush_update_on_start` defaults to `true` (classic behaviour) | Set `crush_location` for the OSD, or set `osd_crush_update_on_start = false`. |

## PGs stuck in `peering`, `incomplete`, or `down`

```
ceph pg stat
ceph pg <pgid> query
ceph health detail
```

- `peering` for a short time after a change is normal. Wait for it to finish before taking action.
- `peering` that does not finish: read `past_intervals` and `down_osds_we_would_probe` in the query. The OSDs listed there must come back, or you must use the recovery procedure.
- `incomplete`: fewer copies than needed. Follow [how-to/recover-pg.md](recover-pg.md). Do not start OSDs that must not rejoin.

## Erasure-coded pools degraded

If the cluster log has `croit-flashstore-osd osd.N mapped into EC pool P` warnings, the OSD is refusing shards of a pool it does not support. Health reports `PG_DEGRADED` or `PG_AVAILABILITY`. `PG_BACKFILL_FULL` here does not mean disk space is short.

Follow [how-to/erasure-pools.md](erasure-pools.md). Fix the CRUSH rule, not the disk space.

## Clients see slow or failed I/O

1. Check the OSD for `active+clean` before anything else: `ceph pg stat`.
2. Check the pool's size and min_size: `ceph osd pool get <pool> size` and `min_size`.
3. Check hardware warnings from `croit-flashstore-osd --check` (WARN entries affect performance).
4. Use op tracing to see where time is spent. See the tracing section in [reference/configuration.md](../reference/configuration.md).

An OSD restart during a rolling upgrade should cause no client errors when size is at least 2 and min_size is at most size minus 1. If you see errors, stop the upgrade and wait for `active+clean`.

## RDMA sessions stay on TCP or fault

Applies with `flashstore_rdma = true`. Start with `ceph tell osd.N rdma status` and `ceph log last 100`. Setup: [how-to/enable-rdma.md](enable-rdma.md).

| Symptom | Cause | Action |
|---|---|---|
| Daemon exits at start: `built without feature rdma` | The binary has no RDMA support. | Install a binary built with the `rdma` feature, or set `flashstore_rdma = false`. |
| Daemon exits at start: `rdma memory budget ... at least <n> MiB needed` | `flashstore_rdma_memory` split over cores times devices is below 6 MiB per part. | Raise `flashstore_rdma_memory`, use fewer cores, or disable RDMA. |
| Daemon exits at start: `memlock limit ... is below the ... MiB of RDMA memory` | `RLIMIT_MEMLOCK` is below the budget plus the registered payload heap. | `LimitMEMLOCK=infinity` in the unit, `--ulimit memlock=-1` in a container. |
| `rdma: device <ip> unusable: ...`, `unusable` in `rdma status` | The address has no RoCEv2 interface (no RDMA device, no RoCEv2 address, interface MTU below 1120) or registration failed. | Run `croit-flashstore-osd --check` and fix the `RDMA` WARNs: IP on the RDMA interface, interface MTU of 1120 or more (1500 works with lower throughput; 9000 and jumbo frames on every host interface and switch port of the path is the best). Restart the OSD; it does not retry. |
| `rdma: configured but no connection upgraded after 600s`, `declined` grows, `upgraded` is 0 | Peers do not have RDMA enabled, or the peer address does not match a RoCEv2 address of the peer (wrong interface, VLAN or NAT in the path). | Enable RDMA on the peers (both ends must). Check the peer's `rdma status` and `croit-flashstore-osd --check`. Classic OSDs and clients always stay on TCP. |
| Only some connections upgrade | Mixed acting set, mon/mgr/heartbeat connections (never upgraded), or handed-off connections. | Expected. Compare `rdma_upgraded` with the number of croit-flashstore-osd peers. |
| `rdma: max_sessions <n> reached` or `rdma: receive pool full at <n> sessions`, `capped` grows | Session cap or the receive slots of a core are used up. The extra connections work, on TCP. | Raise `flashstore_rdma_max_sessions` (0 = unlimited) or `flashstore_rdma_memory`. The line `sessions back to <n>` ends the condition. |
| `faulted` grows, clients or peers reconnect | Queue pair error or exhausted RC retransmission (fabric loss, link flap, congestion), a peer that died, or a protocol violation. | Check the switch counters for drops and pause frames, `croit-flashstore-osd --check` for the QoS WARNs (PFC, DSCP map, global pause), and the link. Connections reconnect on their own. |
| High `credit_stalls` / `credit_stall_ns` on large transfers | The receiver's credit window is the limit. | Raise `flashstore_rdma_memory` (larger windows per core) or spread load over more OSD cores. Stalls alone are not an error. |
| High `queue_stalls` | The sender ran out of send slots or send-queue entries. | Same budget; check that the peer drains (peer CPU, `credit_stalls` on the peer). |
| `WARNING TIMEOUT rdma close fence exceeded <n>s (conn <id>)`, `rdma_close_fence_timeouts` grows | The peer did not acknowledge the last send within the close limit; the queue pair was torn down anyway. | Check the peer and the fabric. A few at peer shutdown are harmless. |
| Large `rdma_zc_misses` against `rdma_zc_bytes` | Large replies come from memory outside the registered payload heap, so they are copied. | Not an error; check for a missing payload heap (log line `no payload hugepage heap`). |

To stop RDMA while you investigate, set `flashstore_rdma = false` and restart the OSD. Nothing else changes.

## SPDK: the NVMe drive drops off the PCIe bus when the OSD starts

Applies to the SPDK storage tier only. The kernel NVMe tier never resets the device and is not affected.

Some drive and platform combinations do not come back from a PCI-level reset. Known case: Samsung PM1743 drives in hot-plug slots of an AMD EPYC server. `vfio-pci` resets the device every time a program opens it: with a Function Level Reset (FLR) if the device supports it, otherwise with a reset of the whole PCI bus. It does this even when all reset methods are disabled in `/sys/bus/pci/devices/<pci>/reset_method`. On these platforms, after the reset the drive no longer answers.

**Symptoms**

- `croit-flashstore-tool prepare --dev spdk:<pci>` or the OSD start fails with `EAL: Driver cannot attach the device` or `get_cap() failed`.
- `dmesg` on the host shows one of:
  - `vfio-pci <pci>: not ready 65535ms after bus reset; giving up`, then `pciehp: Slot(N): Link Down` and `Card not present`. About a second later the slot reports the card present again and the kernel `nvme` driver takes it back.
  - `vfio-pci <pci>: Unable to change power state from D0 to D3hot, device inaccessible`. The device then stays in `D3cold` and `lspci` reads `ffff` from it.

**Check**

```
lspci -vvv -s <pci> | grep -E 'FLReset|Physical Slot'      # FLR support, hot-plug slot number
lspci -vvv -s <parent bridge> | grep -E 'SltCap|SltSta'     # HotPlug+ / PwrCtrl+ on the slot
cat /sys/bus/pci/devices/<pci>/power_state                   # D3cold = the drive is off the bus
setpci -s <pci> VENDOR_ID                                    # ffff = the drive does not answer
```

**Recover a drive that is stuck** (only when the drive is not in use by any OSD):

```
echo <pci> > /sys/bus/pci/drivers/vfio-pci/unbind
echo > /sys/bus/pci/devices/<pci>/driver_override
echo 0 > /sys/bus/pci/slots/<N>/power; sleep 3; echo 1 > /sys/bus/pci/slots/<N>/power
```

The slot power cycle brings the drive back on the kernel `nvme` driver. The data on it is not changed.

**Fix**

1. Recommended: run these drives on the kernel NVMe tier (`flashstore_dev = kernel:/dev/ngXnY`). It needs no device binding and is the production default.
2. Ask the server or drive vendor for a firmware or BIOS update that makes FLR and the slot reset work. Changing hot-plug or reset settings in the BIOS is a vendor question; do not guess.
3. Test and lab setups only: bind the drive with `uio_pci_generic`, which never resets it. It needs the IOMMU in pass-through mode (`iommu=pt`), physical device addresses, and an OSD that runs as root. There is no DMA isolation between the drive and the host. Settings:
   - in `[osd.N]`: `flashstore_driver = uio_pci_generic` and `flashstore_user = root`
   - a drop-in for `croit-flashstore-osd@N` from `croit-flashstore-osd@.service.d/root.conf.example`, plus `Environment=NVS_IOVA_MODE=pa`
   - `NVS_IOVA_MODE=pa` also for `croit-flashstore-tool prepare` and any other `croit-flashstore-tool` command that opens the device

   Do not use this setup for production data.

## Store errors after a crash or power loss

```
croit-flashstore-tool fsck --id N
croit-flashstore-tool fsck --id N --deep
```

`fsck` never writes to the device. If it reports errors, `repair` replays the write-ahead log and checkpoints the store. `repair` cannot rebuild damaged metadata or data blocks. In that case, export the PGs that are still readable and let scrub repair them from replicas.

A mount log line `WAL replay stopped at lsn ... dropped as torn`, or a non-empty `wal_tail_dropped` in the `fsck`/`repair` JSON, is informational: unacknowledged writes in flight at a crash were dropped. Do nothing for pools of size 2 or 3. If it repeats without a crash, check the device health. See [store maintenance](store-maintenance.md#dropped-write-ahead-log-tail-wal_tail_dropped).

`--accept-wal-loss` cuts a corrupt write-ahead log at the point of damage. Transactions acknowledged after that point are lost. Use it only when you accept that loss. Before accepting, run `croit-flashstore-tool wal-inspect --id N --preview-loss` to read exactly which PGs and objects the cut would drop (see [store maintenance](store-maintenance.md)).

## Device grew but the OSD did not

```
croit-flashstore-tool sizes --id N
```

Stop the OSD, run `croit-flashstore-tool expand --id N`, then start it. Online expand is refused.

## Escalation

When none of the above applies, collect the following before you ask for help:

```
croit-flashstore-osd --check --format json-pretty > hw.json
ceph tell osd.N status --format json-pretty > status.json
journalctl -u croit-flashstore-osd@N --since "2 hours ago" > osd.log
ceph log last 200 > cluster.log
```

Include the Ceph release, the croit-flashstore-osd version (`croit-flashstore-osd --version`), and the exact symptom.
