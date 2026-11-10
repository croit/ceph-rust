<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0649 SPDK claim files are opened without following links

Status: accepted
Date: 2026-11-05

## Context

- Every `spdk:` open takes SPDK's PCI claim before DPDK maps the device: a POSIX write lock on
  `/var/tmp/spdk_pci_lock_<bdf>` with the owner pid in the first four bytes (adr 0103). The daemon (uid `ceph`), the
  root-side tools and the SPDK multi-process locks (`/var/tmp/flashstore_spdk_*`) use the same directory.
- `/var/tmp` is world-writable and the file name is public (`/sys/bus/pci/devices`). The old code opened with
  `create(true)` and wrote the pid: a symlink planted under the name made the daemon or a root tool write four bytes into
  the symlink target (a block device, `/etc/passwd`), and a pre-created file could hold the lock forever.
  `croit-flashstore-prep.sh` chowned that path, which a symlink redirected at any root-owned file.
- SPDK stores the pid in the file, so the file cannot be replaced by a private path without losing the claim shared
  with SPDK binaries.

## Decision

- Claim and multi-process lock files are opened with `O_NOFOLLOW | O_CLOEXEC` and created `0644`.
- The opened descriptor must be a regular file with exactly one link; a symlink (ELOOP), hard link, device node or
  directory is refused with a message naming the path. Nothing is followed, removed or repaired automatically.
- The pid is written only through a descriptor opened read-write. A file owned by another uid with mode `0644` is
  claimed through a read-only descriptor (enough for `fcntl`/`flock`), without the pid write.
- `croit-flashstore-prep.sh` chowns a stale claim file only when it is a plain file and not a symlink.
- The pid write stays the same on-disk format (four bytes little-endian at offset 0), so SPDK binaries keep interoperating.

## Rationale

- The lock is on the inode; only the inode named by the descriptor matters. `O_NOFOLLOW` removes the final-component
  symlink, the single-link check removes a hard link, and both are checked on the descriptor, so no path race remains.
- `0644` keeps the documented mixed-uid use (daemon `ceph`, root tools) working without a path `chmod`.

## Consequences

- + A local user cannot redirect the PID write, cannot make a root tool chown an arbitrary file through the claim path,
  and a foreign claim file is reported instead of being silently followed.
- - A hostile local user can still create and hold the claim file (denial of the OSD start); the OSD then refuses with a
  clear message instead of corrupting data. The directory stays `/var/tmp` for SPDK compatibility (superseded: the claim
  and multi-process files moved to `/run/croit-flashstore-osd`, am. 1; SPDK's own internal lock stays in `/var/tmp`).
- - `spdkmp` (feature `spdk-mp`, lab only) uses the same opener; its lock files are created `0644` instead of `0600`.
- Tests: `nvme::pcilock::tests::claim_refuses_symlink_and_hard_link` (target keeps its content, hard link refused),
  `claim_creates_a_plain_file_and_records_the_pid`, `nvme::spdkmp::tests::shared_locks_refuse_a_symlink`
  (`--features spdk-mp`).

## Amendment (2026-11-06, am. 1): claim and multi-process files live in /run/croit-flashstore-osd (PrivateTmp-safe)

Context: `croit-flashstore-osd@.service` keeps `PrivateTmp=true` (classic `ceph-osd@.service` has it too). That makes `/var/tmp`
private to the unit, so the daemon's claim file was no longer the host's: a host-side `croit-flashstore-tool` or a container
could open a controller the OSD holds (open question doc/90-open-questions.md). A shared path outside `/var/tmp` is
needed, still owned by root and writable for the daemon user.

Decision:
- The directory is `/run/croit-flashstore-osd`: root-owned `1770 root:ceph`. `1770` (not the `0750` of the first draft) because the
  daemon runs as uid `ceph` and must create the lock files; the sticky bit (like `/dev/hugepages`) keeps one uid from
  unlinking the other's files (root `host-tune` state files live in the same directory). Group `ceph` writes, others
  have no access.
- The package ships `/usr/lib/tmpfiles.d/croit-flashstore-osd.conf` (`d /run/croit-flashstore-osd 1770 root ceph -`) and its post-install runs
  `systemd-tmpfiles --create`; `croit-flashstore-prep.sh` creates the directory idempotently on every OSD start. No in-daemon
  fallback: a missing or unwritable directory is an error naming exactly `install -d -o root -g ceph -m 1770
  /run/croit-flashstore-osd` (and "make uid N a member of group ceph").
- File names and the on-disk format are unchanged (`spdk_pci_lock_<bdf>`, `flashstore_spdk_mp_<bdf>`,
  `flashstore_spdk_ns_<bdf>_<nsid>`; pid = four little-endian bytes at offset 0), only the directory moves. One constant
  (`nvme::pcilock::LOCK_DIR`) and one path helper serve both modules.
- Files are shared by uid `ceph`, host root and root containers without `CAP_DAC_OVERRIDE`: an existing file is opened
  without `O_CREAT` (with `fs.protected_regular=2` an `O_CREAT` open of another uid's file in a sticky group-writable
  directory fails even for root), a missing one is created with `O_CREAT|O_EXCL` and `fchmod 0666` (umask-proof). The
  `1770` directory keeps other users out. Nothing is ever chowned: the prep chown of the old design is removed (in a
  group-writable directory uid `ceph` could swap the checked file for a symlink before root's `chown`, and
  `fs.protected_symlinks` covers only world-writable sticky directories).
- SPDK's own internal lock stays where the SPDK library puts it (`/var/tmp/spdk_pci_lock_<bdf>`): under `PrivateTmp` it
  is private to the unit and no longer excludes a second croit-flashstore-osd; that exclusion is exactly what our file in
  `/run/croit-flashstore-osd` provides.
- Containers bind `/run/croit-flashstore-osd` (in addition to `/var/tmp` for SPDK's own lock; `run.sh`, `lab/spdk-mp-live.sh`).
- The unit needs no `ReadWritePaths`: `ProtectSystem=full` covers `/usr`, `/boot` and `/etc`; `/run` stays writable.
  `RuntimeDirectory=croit-flashstore-%i` (`/run/croit-flashstore-ID`, DPDK runtime files) is unchanged and separate.

Rationale: keep the classic unit's `PrivateTmp=true` instead of weakening hardening for a lock path; a root-owned
runtime directory in `/run` is the standard place for cross-process daemon locks and is visible to root tools and
bind-mounted containers, while `/var/tmp` stays private.

Consequences: + daemon, `croit-flashstore-tool` and containers exclude each other again with `PrivateTmp=true`; + the daemon
fails loudly with the fix instead of silently locking a private inode; - the directory must exist (package/tmpfiles,
prep) and its group ownership must match the daemon user (documented, named in the error); - `0750 root:ceph` cannot be
used because the daemon writes there (the decision above).

Tests: `nvme::pcilock::tests::lock_path_form` (new path), `claim_in_the_shared_lock_dir_refuses_a_second_holder`
(a temp dir injected into the same path builder, child holds the `fcntl` lock), `claim_refuses_a_missing_lock_directory`
and `claim_refuses_an_unwritable_lock_directory` (exact fix in the message), `nvme::spdkmp::tests::lock_paths`;
`lab/deploy/container/test-entry.sh` asserts both container binds. Siblings checked: kernel NVMe tier uses its own
`O_EXCL`/flock device lock, not this file; no other `/var/tmp` lock exists in the daemon.
