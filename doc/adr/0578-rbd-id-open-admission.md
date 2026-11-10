<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0578 Resolve existing image IDs before header admission

Status: accepted
Date: 2026-10-26

## Context

Pinned open lookup (doc not in the source snapshot) resolves an ID's
name from the directory or trash before initial header reads. Header-first
admission changes missing-identity error precedence and loses trash names.
Directory lookup targets a fixed object, so its input ID is not bounded by
the length of a hypothetical header object.

## Decision

A shared open-name resolver queries the exact directory key, then trash only
on ENOENT. Trash EOPNOTSUPP maps to ENOENT; other failures propagate. Public
read-only opens and writer by-ID admission resolve identity before reading
the header. Selected snapshot views use the same trash-name fallback.
Reverse-directory queries retain NUL/u32 length guards without imposing a
header-suffix limit. Actual header targets retain their own local bounds.

## Rationale

The shared resolver preserves error precedence across writable/read-only,
synchronous/asynchronous and internal Group member opens, while raw metadata
observation remains usable independently of public admission.

## Consequences

- + Missing identities cannot be hidden by a header admission failure.
- + Trashed image IDs retain names and exact selected-snapshot data views.
- - Writable opening currently resolves the readable handle's name again;
  eliminating that repeated lookup requires a carried identity result.

## Alternatives

- Read header first: changes failure precedence and performs needless I/O.
- Apply generated-ID validation: rejects valid lookup strings before lookup.

## Open questions

Test evidence (commit hashes, cell results): librbd completeness, ADR evidence (doc not in the source snapshot).
Empty-ID/name detection, metadata opening with missing DATA pools and backend
object-limit errno remain separate gaps. Wider faults, own-provider, platform,
QEMU/release and measured performance remain unqualified.
