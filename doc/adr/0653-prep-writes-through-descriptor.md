<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0653 Root `prepare` writes the OSD data dir through a descriptor, never through a path

Status: accepted
Date: 2026-11-05

## Context

- `croit-flashstore-tool prepare` runs as root and (re-)writes `/var/lib/ceph/osd/<cluster>-<id>/{whoami,fsid,ceph_fsid,type,
  croit-flashstore-osd,keyring,ready}`. `croit-flashstore-prep.sh` hands that directory to the daemon user (`ceph`), and prepare is idempotent
  and re-run by operators.
- The old code used `std::fs::write` on `<dir>/<name>` (follows a symlink) for every file except the keyring. A
  compromised daemon could plant a symlink under one of those fixed names and the next root `prepare` truncated the
  target (`/etc/shadow`, `/etc/sudoers.d/*`: host auth / sudo denial of service).
- The keyring mode was fixed separately (created `0600`); this change moves every file of the directory onto the same
  descriptor-based write.

## Decision

- The data directory is opened with `O_DIRECTORY | O_NOFOLLOW`; a data dir that is a symlink is refused. Its mode is set
  with `fchmod` on that descriptor (`0750`).
- Every file is written relative to that descriptor: `<name>.tmp` is unlinked (a stale one from a crash; unlink never
  follows), created with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`, its mode set exactly with `fchmod` (`0600` for `keyring`,
  `0644` for the others), written, fsynced and `renameat`ed over `<name>`. The rename replaces a symlink at the name
  instead of writing through it; `O_EXCL` makes the temp file new, so no planted entry is ever reused.
- Removing the keyring for an auth-none OSD is `unlinkat` on the descriptor; a missing file is fine.
- `write_atomic_mode` (used by the crash dumps, the lab meta store and the host-tune state file) keeps its own
  remove-then-`create_new` temp-file rule and also opens with `O_NOFOLLOW|O_CLOEXEC`.

## Rationale

- `openat`/`unlinkat`/`renameat` on the verified directory descriptor remove the path race: the daemon user can rename
  its own directory and plant symlinks between two path-based calls, but not between calls that name a descriptor we
  hold. `O_EXCL` plus `O_NOFOLLOW` on every new file closes the remaining name games.
- Keeping the atomic temp+rename preserves the crash property (a dump or keyring is complete or the previous one).

## Consequences

- + A symlink or hard link in the data dir cannot redirect a root write or a root `chmod`; every file (including the
  keyring, `0600`) is replaced atomically.
- - A deployment that legitimately made the data dir a symlink is refused; the documented layout is a real directory.
- Tests: `osddir::tests::write_refuses_symlinks_and_keeps_the_keyring_private` (a symlinked file name is replaced with a
  regular file and its target keeps content and mode; a symlinked data dir is refused; the keyring is `0600` over an
  existing `0644` file) and `write_atomic_never_writes_through_a_planted_temp_name` (symlink and hard link at
  `<name>.tmp`, destination symlink replaced, mode `0600`).
- Siblings checked: `FileMetaStore` (lab) writes identity/keyring with `write_atomic_mode` (temp-file rules above, secret
  mode in the lab-meta ADR of this release).
