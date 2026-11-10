<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0657 Lab FileMetaStore creates the cephx identity and keyring 0600

Status: accepted
Date: 2026-11-05

## Context

- The lab/dev meta store (`FileMetaStore`, feature `lab`/tests) persists the OSD identity and the cephx keyring
  (`[osd.N] key = <secret>`) in the OSD data dir.
- Both were written with `write_atomic` (`0666` before the umask) and `chmod`ed `0600` afterwards, with the error
  ignored. A crash between the two writes, or a failing `chmod`, left the identity or the keyring world-readable; the
  window existed on every store.
- The production store keeps the key in the device superblock/WAL, not in these files.

## Decision

- `store_identity` writes both files with `write_atomic_mode(..., 0o600)`: the temp file is created `0600` and renamed,
  so the file never exists wider than `0600`, and a failing write leaves the previous file (also `0600`) in place.
- No post-hoc `chmod` remains.

## Rationale

- The mode belongs to the creation of the file, not to a later step that a crash can skip; the atomic replace makes the
  wider window impossible instead of short.

## Consequences

- + A crash or a failed second write cannot leave the cephx secret readable by other users.
- - A pre-existing store with `0644` identity/keyring keeps that mode until the next `store_identity` (the next start
  writes it again, or `prepare` rewrites the OSD dir `0600` through the descriptor, adr 0653).
- Implementation + tests of the write path: commit "osddir: create keyring files 0600 atomically" (same release).
  Regression test added here: `osd::meta::tests::identity_and_keyring_have_the_secret_mode_from_creation` (a failing
  keyring write leaves the already written identity `0600`; a normal write leaves both `0600`).
