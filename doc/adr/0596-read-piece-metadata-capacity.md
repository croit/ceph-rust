<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0596 Bounded READ reply descriptor reservation

Status: accepted
Date: 2026-10-26

## Context

Store READs return an owned vector of immutable byte pieces and optional CRCs.
Reply assembly pushes further descriptors into a fresh vector. The focused RDMA
CPU profile samples metadata growth/memmove under `OsdOp::set_outdata_parts`.
The general iterator API also accepts constant-memory streams of empty pieces.

## Decision

Plain and sparse READ execution use an owned-vector output constructor.
It reserves further descriptor capacity from the input count once, after finding
a second actual nonempty piece. Empty and single-piece outputs allocate none.
The generic iterator API preserves allocation behavior independent of empty
input length. Both constructors share filtering, CRC binding and byte ownership.
The owned-vector constructor may retain capacity for empty input descriptors;
capacity is bounded by the already-owned input vector, not an iterator hint.
API behavior is authoritative in `OsdOp::set_outdata_vec` Rustdoc.

## Rationale

An existing owned descriptor count removes repeated geometric growth without a
second pass, extra payload copying, checksum recomputation or inferred nonempty
length. Transport and wire semantics stay unchanged.

## Consequences

- + One metadata allocation without reallocations for fragmented owned outputs.
- + Original byte addresses and owner-bound CRC hints remain intact.
- - General iterators retain their existing growth behavior.
- - This does not eliminate the remaining metadata allocation or prove a
  throughput/latency gain; affected execution/ownership gates and measurement
  remain required.

## Alternatives

Alternatives: not recorded (OQ 123).
