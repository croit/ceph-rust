<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0548 QEMU monitor sockets independent of evidence paths

Status: accepted
Date: 2026-10-24

## Context

The placement VM fixture failed before guest boot because its QMP AF_UNIX socket
name inherited a long evidence path. QEMU rejected the sockaddr_un path and the
subsequent pidfile wait timed out. All e2e topologies use the same command builder.

## Decision

- Each run creates one private short QMP runtime directory with mktemp under /tmp.
- qmp.dir in the evidence directory records that runtime location; per-VM
  qmp.sock symlinks preserve discoverability from the evidence tree.
- Kept runs retain the runtime directory. Successful teardown removes only the
  known sockets after every run-owned QEMU has stopped, then removes the directory.
- The evidence directory retains its caller-selected location and length.

## Rationale

Socket-name bounds are independent of log and disk placement. A private directory
keeps QMP local and avoids exposing an unauthenticated TCP management listener.

## Consequences

- + Long evidence paths work for placement, smoke, mixed and AF_XDP topologies.
- + Existing exact-PID ownership checks and kept-run teardown remain authoritative.
- - Runtime socket location is recorded outside the evidence directory as well.

## Alternatives

- Require shorter evidence paths: couples a network API bound to arbitrary output layout.
- QMP over TCP: adds port allocation and exposes another management endpoint.
