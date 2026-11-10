<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0654 host-tune state files are private and trusted only when the applying uid owns them

Status: accepted
Date: 2026-11-05

## Context

- `croit-flashstore-tool host-tune --apply` runs as root and records every undo operation (argv to exec, path+value to write) as
  JSON in `--state FILE` (default `/run/croit-flashstore-osd/host-tune-<ts>.json`, the boot unit uses `/run/croit-flashstore-osd/host-tune.json`).
  `--revert FILE` later runs those operations as root.
- The file was written with the default mode (`0644`, umask) and loaded without any check: a state file another local
  user could write was executed as root on the next revert.
- The content is a faithful record of what the apply did; re-deriving it from a typed `Step` would lose the probe
  values (the prior feature states, ring sizes, RSS contexts) that are read at apply time.

## Decision

- The state file is written with mode `0600` at creation (`write_atomic_mode`).
- Before a load (`--apply` appending to an existing file) or a `--revert`, the file must be a regular file (not a
  symlink or special file), owned by the effective uid, and not group/other-writable. Otherwise it is refused with the
  offending path and reason; nothing is loaded, executed or overwritten.
- The recorded argv is executed as recorded (the trusted file already comes from a root apply); `--revert` additionally
  needs the same privilege as `--apply`.

## Rationale

- The threat is an untrusted writer, not the JSON layout. Ownership plus "no group/other write" is exactly the set of
  files only the applying uid (root) can change; the mode check rejects a shared `0664`/`0666` file even when its owner
  field happens to be root.
- Keeping the recorded operations preserves the exact prior values that no later re-probe can reconstruct.

## Consequences

- + A state file writable by another user or reached through a symlink is never executed as root.
- - An operator copying the state file with a wider mode must `chmod 600` it before `--revert`; the error says so.
- - A state file in a directory another user can replace by name is still a name race; the default directory
  (`/run/croit-flashstore-osd`) is root-owned, and the file itself is checked after opening by name.
- Tests: `hwcheck::tune_tests::state_file_must_be_private_and_owned` (0664 file refused, content not executed; symlink
  refused; the same layout at 0600 loads and reverts; a written file is 0600).
- Siblings checked: `--emit-persist` only prints a unit text, it never reads or executes a state file.
