<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0490 Device id and device name equal classic Ceph's

Status: accepted
Date: 2026-10-22
Amends: 0034, 0055

## Context

`device_ids` metadata and `smart` reply keys register the drive in the mgr (`ceph device ls`, devicehealth history, life expectancy). Classic Ceph v21.1.2 derives the id from the udev model and serial attributes with the Identify Controller padding kept (`SAMSUNG_MZQL27T6HBLA-00A07_______________S6CKNS0X903238______`). croit-flashstore-osd registered a trimmed form (`SAMSUNG_MZQL27T6HBLA-00A07_S6CKNS0X903238`) and, on the kernel tier, the PCI address as device name instead of `nvme2n1`. After a BlueStore -> croit-flashstore-osd migration on the same drive the mgr listed two devices. Spec: doc/spec/devicehealth.md.

## Decision

- Device id = Identify Controller MN (40 B) + `_` + SN (20 B), cut at the first NUL, padding kept, every space `_` (`nvme::health::Ident::device_id`). Same on SPDK and kernel tiers.
- Device name (`devices`, `device_ids`/`device_paths` keys, `list_devices`, SMART JSON name): kernel tier = kernel block name (`nvme2n1`; generic node `ng2n1` -> `nvme2n1`), `list_devices` device = `/dev/<name>`, `bluestore_bdev_dev_node` = `/dev/<name>`. SPDK tier = PCI address, `spdk:<pci>` (no kernel name exists).
- `device_paths` value stays `pci-<addr>-nvme-1`; omitted without a PCI address.

## Rationale

The mgr keys all history by the id string; only the classic string keeps one device per drive across a migration. Kernel block name matches what the dashboard and node-exporter based tooling show for the same drive.

## Consequences

- + A drive migrated from BlueStore keeps its history, life expectancy and `ceph device ls` row.
- - A drive that an earlier croit-flashstore-osd registered with the trimmed id appears under the new id after the OSD restarts: the old id loses its daemon link (its row may stay in `ceph device ls` without daemon) and its stored metrics stay under the old id until retention prunes them (`retention_period`, default 180 d). There is no `ceph device rm`; no manual step is needed. The history is not merged into the new id. No on-disk OSD format changes.
- - SPDK tier devices keep the PCI address as name; a kernel to SPDK switch of the same OSD changes the name, not the id.
- Siblings checked: SPDK and kernel tier share `Ident::from_raw` (SPDK Identify via shim, kernel Identify page via kprobe); AF_XDP/knet, replicated/EC, crc/secure not affected (metadata only).

## Open questions

- `smart` for dm / multi-namespace layouts is out of scope (adr 0013: one NVMe device per OSD).
