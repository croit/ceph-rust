<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->

# 0690 PG log duplicate records preserve equal-version requests

Status: accepted
Date: 2026-11-08

## Context

One log entry can retain multiple request IDs at the same version. Explicit dup
rewrites and log replacement used a version-only key, overwriting those records.

## Decision

Explicit PG dup persistence uses the version key plus a fixed-width hexadecimal
list ordinal suffix for records after ordinal zero. Version prefixes remain trim
bounds. Loaders accept both suffixed and existing unsuffixed keys.

## Rationale

The ordinal preserves equal-version list order and every recorded result without
changing wire values or retained-entry trimming. Existing loaders already decode
all `dup_` keys by value; no mount feature is needed for reader compatibility.

## Consequences

- + Request identities and results survive explicit persistence and restart.
- + Existing version-range trimming includes all records at its boundary.
- - Explicit records after ordinal zero have longer keys; steady-state retained
  log entries have no added storage or CPU cost.
- - Previously overwritten duplicate records cannot be reconstructed locally.

## Alternatives

- Request-ID suffix: changes equal-version ordering and requires more key bytes.
- One vector per version: changes the stored value format and existing readers.
