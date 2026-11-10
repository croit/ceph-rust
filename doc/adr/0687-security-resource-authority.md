<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0687 Authorize the accessed resource; create the admin socket privately

Status: accepted
Date: 2026-11-08

## Context

PG operations ignore the request's object name and locator key when accessing namespace-wide metadata; the
capability check used those values (classic does the same). Admin socket startup unlinked every existing path whose
connect probe failed and chmodded the socket by pathname after bind (classic does the same).

## Decision

- PG-operation capability evaluation (any PG opcode in the message) uses an empty object key and keeps the actual
  pool, namespace and peer network context (`../spec/osdcaps.md` s4).
- Admin socket: refuse non-socket entries and every probe error except connection refused; bind in a private
  `mkdtemp` directory beside the path, `fchmodat` 0660 there, publish with one `renameat` over the path; Drop unlinks
  only the inode it bound (`../spec/ops-observability.md` s1).

## Rationale

An ignored request field cannot establish authority over a broader resource. A failed connection does not establish
that an entry is disposable. A private directory is the only portable way to chmod the socket node without a race
against a writer of the parent; rename over the path never follows a symlink and replaces a stale socket in one step.
Legitimate clients (librados, neorados, objecter send empty oid/key for PG ops) and the socket's observable path/mode
are unchanged.

## Consequences

- + Prefix-only capabilities cannot enumerate unrelated object names using a decoy name.
- + Mistaken admin paths keep data files and symlinks; a planted symlink is never chmodded.
- - Rename-over replaces an entry a writer of the parent puts at the path between probe and publish (that writer could
  remove it itself). A crash between `mkdtemp` and cleanup leaves an empty `.asok.XXXXXX` dir.

## Alternatives

- Preserve classic handling: leaves confirmed authorization, deletion and chmod-through-symlink hazards.
- fchmod on the socket fd before bind: Linux masks the node mode with the umask at bind; a pathname chmod stays needed.
- Process-wide umask change: races other threads.
