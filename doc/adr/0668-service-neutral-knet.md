<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0668 Service-neutral kernel TCP socket boundary

Status: proposed
Date: 2026-11-05

## Context

IMPL-20: rt's production io_uring transport binds four OSD listeners and names
OSD commands. MDS FE currently consumes a concrete net::Stack. A concurrent FE
rewrite owns its service/transport code; this increment leaves those files alone.

## Decision

- daemon-io owns the existing socket command enum; osd::IoCmd reexports it.
- rt::stream::Driver uses listener indexes and static dispatch.
- KNet<N> keeps the same io_uring receive/send implementation; OSD uses N=4,
  unchanged listener order; MDS uses N=1. bind_all[_with] retains the OSD API.
- Default Driver hooks preserve OSD full teardown on FIN and existing Vec output.
  Raw socket facades opt into half-close and retained output descriptors.
- MDS exposes a separate kernel_transport::Stack with the socket surface consumed
  by its existing FE listener. Production Kernel is feature knet + Linux only.
- The daemon/FE lanes select this backend after making FE generic. No fallback to
  AF_XDP/DPDK, no second messenger or TCP implementation.
- API contract: Rustdoc rt::stream, rt::knet, mds::kernel_transport.

## Rationale

Monomorphization preserves the OSD hot loops without trait objects, locks or
per-operation adapter allocation. A command reexport preserves every variant
and field without conversion. The raw facade needs independent bounded admission,
shared receive storage and an acknowledgement fence for FE durable CLOSE.

## Consequences

- + Both services use the production ring/buffer/socket implementation.
- + OSD service behavior remains in its existing Driver implementation.
- - FE generic selection and daemon wiring remain separate integration work.
- - Linux compilation, io_uring loopback and OSD regression gates require the
  runner; macOS cannot qualify the production backend.

## Alternatives

- Fork the ring driver for MDS: duplicates correctness and performance work.
- A trait object around OSD I/O: adds dispatch to the OSD hot path.

