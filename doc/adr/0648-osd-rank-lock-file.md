<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0648 The OSD rank lock is a plain single-link file opened without following links

Status: accepted
Date: 2026-11-05

## Context

- `auto_place` refines the per-OSD L3 domain rank with a `flock` on `/run/ceph/croit-flashstore-l3-<node>-<l3>.lock` (adr 0063).
  The directory is shared with the classic ceph packages (`/run/ceph`, `ceph:ceph`) and the file name is predictable
  from `/sys`.
- The old code opened the name with `create(true)` (follows a symlink in the final component) and made it world-writable
  with a path-based `chmod 0666` (follows a symlink too). A local writer could point the name at another file: the OSD
  then chmods that target, and the lock itself is world-writable, so any local user can hold it.
- Placement is best-effort: without a usable lock the OSD keeps its plain rank (`osd id % preferred domains`).

## Decision

- The rank lock file is opened with `O_NOFOLLOW | O_CLOEXEC`, created `0644`.
- The descriptor is checked before use: a regular file with exactly one link (`st_nlink == 1`). A symlink, hard link,
  device node or any other inode is refused; the OSD then uses the plain rank and takes no lock. Nothing is removed or
  repaired by this path.
- The mode is set with `fchmod` on the descriptor (never on the path), and never wider than `0644`; a second uid that
  cannot open the file read-write falls back to a read-only descriptor (enough for `flock`).
- `/run/ceph` stays the lock directory: it is the directory the classic deployment already creates for the OSDs, and a
  private `/run/croit-flashstore-<id>` would not be shared between OSDs of one host.

## Rationale

- `flock` is on the inode, so the only thing that has to be trusted is the inode the descriptor names. `O_NOFOLLOW`
  removes the final-component symlink; the single-link check removes a hard link planted in the shared directory. Both
  are checked on the opened descriptor, so no path race remains.
- The lock never protected a secret and never needs write access from other users: `0644` (instead of `0666`) is enough
  for `flock` across uids (a read-only descriptor may take `LOCK_EX`).

## Consequences

- + A symlink in `/run/ceph` cannot redirect a `chmod` to a root- or ceph-owned file, and the lock is no longer
  world-writable (no steering of placement by any local user).
- - A stale lock file owned by another uid with mode `0600` yields no lock (plain rank) instead of a shared one; the
  placement is still deterministic and safe.
- Tests: `rt::topo::tests::lock_file_symlink_is_refused_not_followed` (symlink target keeps its mode, hard link refused,
  ordinary lock file created `0644` and held); `lock_claims_distinct_domains` unchanged.
- Siblings checked: not affected. No other lock file is created in a shared directory from this crate (`spdkmp` lock
  files are covered by the SPDK claim ADR of this release).
