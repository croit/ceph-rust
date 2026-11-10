<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0655 The used-device probe reads the first 8 KiB plus the btrfs superblock windows

Status: accepted
Date: 2026-11-05

## Context

- `prepare` passes `--refuse-used`: before a fresh mkfs it refuses a device that is not empty (unless `--wipe`), so an
  operator cannot lose data of an unrelated filesystem. The probe read the first 8 KiB only and called a zero window
  "empty".
- btrfs puts its primary superblock at 64 KiB (first backup at 256 KiB) and leaves the first 64 KiB zero, so a btrfs
  device looked empty and was deallocated and formatted without `--wipe` — the opposite of what the refusal promises.
  Mounted filesystems are still protected by the exclusive open; this is about unmounted media.

## Decision

- `looks_used` probes three windows: the first 8 KiB (GPT, bluestore label, XFS, LUKS, ext2/3/4, MBR, any non-zero
  byte) and 4 KiB at 64 KiB and 256 KiB. A late window counts as used when it holds the btrfs magic `_BHRfS_M` at
  superblock offset `0x40`, or any non-zero byte.
- A window is only probed when its offset is a whole LBA of the device (64 KiB and 256 KiB are multiples of every LBA
  size this store accepts); reads keep the existing 10 s probe timeout with its `WARNING TIMEOUT` line.
- The probe stays read-only and fail-closed: a probe error is an error, never "empty".

## Rationale

- The superblock offsets are the documented on-disk locations of the filesystems this tool can meet; probing them costs
  two 4 KiB reads on a cold path and removes the false negative that the refusal text promised not to have.
- A generic signature database (`blkid`) would add an external command and its database to a root path for the same
  result.

## Consequences

- + A btrfs (or any filesystem with a late superblock in these windows) is refused without `--wipe`.
- - A device with stale non-zero bytes at 64 KiB or 256 KiB but no filesystem is now refused until `--wipe` (stricter
  than classic `ceph-volume raw prepare`, which checks only mount state and the bluestore signature; the refusal text
  is now true).
- - Signatures outside these windows (for example the ZFS labels at the end of the device) are still not recognised; the
  `/dev/...` ownership and mount checks are the only protection there.
- Tests: `croit-flashstore-tool` `mkfs::tests::used_probe_reads_beyond_the_first_window` (a `file:` device with the btrfs magic
  at 64 KiB + `0x40` is reported, a blank device is not, a non-zero late window is reported).

## Amendment 1 (2026-11-07): every fresh mkfs probes, not only prepare
Decision: the probe runs in the shared provisioning entry before any Format NVM, deallocate or format whenever the device has no FlashStore superblock: direct `croit-flashstore-tool mkfs` refuses a used device exactly like `prepare`; only `--wipe` authorizes destruction. The prepare-only `--refuse-used` flag is removed.
Rationale: an opt-in flag left the direct entry able to discard foreign data (data-safety review DS-provision-01, doc/reviews/2026-11-07-ds-provision.md).
Consequences: + no provisioning path destroys an unrelated filesystem without `--wipe`; - lab/rented scripts reusing a non-blank device must pass `--wipe` (the shipped ones already do). Test: `mkfs::tests::direct_mkfs_refuses_foreign_data_without_prepare_flag`.
