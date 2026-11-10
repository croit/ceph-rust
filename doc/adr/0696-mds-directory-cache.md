<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0696 MDS directory cache capabilities

Status: accepted
Date: 2026-11-08
Amends: 0669

## Context

Lab evidence supplied by the lead shows about 45 requests/file operation,
mostly getattr/lookup; path directories lack Fs and remain incomplete.
The current executor coordinates directory inode and whole-frag storage shards
and owns their cap/lease gathers. No multi-owner directory split is implemented.

## Decision

Unsplit directories coordinated by this executor grant Fs in SYNC and Fs/Fx
to a writable loner in EXCL. Directory mutations enter LOCK, gather other
holders' Fs/Fx and name leases, and wait for acknowledgements before commit.
The requester's caps remain valid through its own mutation. Readers gather
another holder's Fx before reading attributes. No asynchronous directory-op
caps are granted. The spec defines no additional directory-specific MIX
behavior; directory grants remain restricted to Fs/Fx.

FE-only reconnect completion removes unreported directory caps by client
identity, including caps from the old internal session generation. Reports
and delivered replay replies preserve rights; a rolled-back reply does not.
Directory caps have no OSD writable ranges; regular-file range recovery stays
with the existing recovery protocol.

Directory getattr/parent traces and cap pushes use authoritative frag counts
and timestamps. Fx timestamp flushes update inode + frag + flush completion
in one transaction; directories have no data writable ranges.

Readdir supplies Fs and existing END/COMPLETE flags. The specs define local
negative lookups with Fs + a fully read directory; they do not define a new
complete/ordered flag in a getattr reply. Negative LOOKUP emits an authorized
parent/name trace; when Fs/Fx cannot be granted it carries a negative lease.
Lease masks follow VALID=3 and PRIMARY_LINK=4.

Multiple owner executors, splits or migration require coordinated revocation
before retaining directory Fs/Fx (caps spec s19.3); this change adds no such
ownership mode.

## Rationale

Caps spec s2.2–2.4, s13, s16.2–16.5 allows cached directory attributes and a
sole holder's own mutations. Client protocol s7.3, s7.5, s7.8, s8.2–8.3 and
s10.2 defines negative traces, leases and readdir completion.

## Consequences

- + Warm single-client create requires one synchronous CREATE request when
  attributes and directory completeness are cached, independent of path depth.
- + Other clients' mutations invalidate cached directory state before commit.
- - Multiple clients may require revoke/ack traffic and must rebuild completeness.
- + Regression script: `services/mds/mds/tests/directory-cache-gate.sh`.
- + Siblings checked: transport crc/secure, kernel/user transports and object
  storage tiers are not affected; the defect is in shared MDS cap policy and
  namespace replies. Readdir, reconnect and cap push/flush paths use that policy.

## Alternatives

- Keep leases only: cannot cache directory times/counts for FUSE getattr.

## Amendment 1 (2026-11-09): rename revokes the requester's dir Fs/Fx

Context: pjdfstest `rename/23.t` (rename over a name whose inode has a second
hard link) failed in our safe and early reply arms, never on stock. The
requesting client drops the *replaced* inode's dentries from its own cache;
when that inode keeps another name its cached listing is no longer complete.
With its Fs still valid the client answered the next lstat/unlink of the
survivor from the stale negative dentry (ENOENT) while the MDS still had the
name (`link` EEXIST, `rmdir` ENOTEMPTY).

Decision: "the requester's caps remain valid through its own mutation" holds
for create, unlink and link; RENAME gathers Fs/Fx on both parent dirs from
every session, the requester included, and waits for the ack (matches stock: doc/spec/mds/mds-caps-locks.md s9.4, OQ 184; the client's embedded dentry releases drop shared Fs before the request, so only an Fx holder pays a revoke).

Consequences: one revoke/ack round trip per rename; the requester rebuilds
directory completeness by readdir when it wants local negative lookups again.
Regression: `services/mds/mds/tests/namespace.rs`
`rename_revokes_the_requesters_dir_caps_and_keeps_the_surviving_link`.
