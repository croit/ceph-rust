# Tutorial: deploy your first croit-flashstore-osd OSD

This walks through one OSD on a single NVMe device, using kernel TCP, which needs no NIC binding. For the network transport, see [explanation/network-tiers.md](../explanation/network-tiers.md).

You need a running classic cluster (mon and mgr) with a bootstrap-osd keyring, and one NVMe device with PLP and 4096-byte LBAs.

Check out the branch that matches your cluster's Ceph release before you start. This page is from the branch that contains it. See [explanation/branches-and-versions.md](../explanation/branches-and-versions.md).

## 1. Check the host

Run the read-only check first. It changes nothing.

```
croit-flashstore-osd --check --format json > hw.json; echo $?
```

Exit 0 means no FAIL. WARN results are allowed but explain performance loss; fix them before production. See [reference/exit-codes.md](../reference/exit-codes.md).

## 2. Write the OSD configuration

Create `/etc/ceph/ceph.conf` with the mon address and one OSD section:

```
[global]
mon_host = <mon-address>

[osd.7]
flashstore_dev = spdk:0000:03:00.0
flashstore_ip = <address>/24
```

Replace `03:00.0` with your NVMe PCI address and `7` with the OSD id. Options are described in [reference/configuration.md](../reference/configuration.md).

## 3. Prepare the device

`prepare` formats the store. It deallocates the whole namespace first, so the device contents are lost.

```
croit-flashstore-tool prepare --dev spdk:0000:03:00.0 --id 7
```

Expected: exit 0 and a success line. Confirm with:

```
croit-flashstore-tool inspect --id 7
```

## 4. Start the daemon

```
systemctl enable --now croit-flashstore-osd@7
systemctl status croit-flashstore-osd@7
```

The unit is `Type=notify`, so `start` returns once the daemon reports ready.

## 5. Verify it joined the cluster

```
ceph osd tree
ceph osd find 7
ceph tell osd.7 status
```

Expected: `osd.7` is `up` and `in`, and its device class is `nvme`. Then check the cluster:

```
ceph pg stat
```

Expected: PGs move to `active+clean` as they map to the new OSD. A new OSD with no pools in use stays idle; create a test pool to exercise it.

## 6. Clean up a test OSD

To remove a test OSD safely, follow [how-to/replace-or-remove-osd.md](../how-to/replace-or-remove-osd.md). Do not wipe the device while the cluster still has data on it.
