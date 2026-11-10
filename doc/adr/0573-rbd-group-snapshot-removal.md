<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0573 Group snapshot removal phase ownership

Status: accepted
Date: 2026-10-25

## Context

A group snapshot record references durable per-image snapshots and can be
INCOMPLETE. Removing its record before all members are processed loses retry
state. The pinned removal boundary (doc not in the source snapshot)
requires all opens before any member removal, then all removal submissions
before waiting for results in record order.

## Decision

The group removal call owns all temporary writable member handles.
Pool contexts inherit the group namespace and are created before any opens.
Every member open is attempted; the last open error in record order aborts
before any mutation. Every successfully opened context is closed on return.
Full GROUP namespace identity selects each actual member snapshot, including
INCOMPLETE records with unset recorded IDs. Member removal jobs share the
ordinary writer/map/self-managed snapshot/SnapContext mutation path.
All jobs start before any join; results and final metadata notification are
collected in record order. Missing member snapshots/removal ENOENT are harmless;
another negative is retained, with the last negative in record order winning.
The group record is removed only after all members succeed or are absent.
Successful member removals are not rolled back after another member fails.

## Rationale

Retaining the record makes partial failures inspectable and retryable. Scoped
jobs operate on distinct private writers and return owned mutation receipts;
provider/image handles remain owned by the caller until all jobs finish.
Metadata publication stays outside writer mutexes. Explicit namespaces avoid
mistaking user snapshots or an unset saved ID for the group member snapshot.

## Consequences

- + Open failures cannot remove an earlier member snapshot.
- + Empty and INCOMPLETE groups follow the same record-retirement boundary.
- - Temporary opens are currently issued serially; large-group resource and
  performance qualification remains required.
- - General admin forwarding and richer ordinary snapshot removal faults remain
  shared dependencies; no full release/group-create/rollback claim follows.

## Alternatives

- Remove members while opening later members: violates the failure boundary.
- Delete the group record first: loses durable cleanup/retry identity.
