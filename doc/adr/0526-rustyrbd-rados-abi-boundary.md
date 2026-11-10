<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0526 librbd to librados process boundary

Status: accepted
Date: 2026-10-23

## Context

Unchanged QEMU passes a `rados_ioctx_t` from its loaded `librados.so.2` to
`librbd.so.1`. `rados-ffi` stores Rust-owned state behind that opaque handle.
Linking its Rust rlib into `rbd-ffi` would create a second copy of the state
and could give the same pointer two incompatible owners. The pinned public
`librados.h` provides C operations to query an ioctx's pool, namespace and
cluster, create another ioctx, and issue batched class calls.

## Decision

- `rbd-ffi` uses the pinned public librados C ABI through the process's loaded
  `librados.so.2`. It never casts `rados_ioctx_t` to a Rust type or links the
  `rados-ffi` rlib into its cdylib.
- An opened image owns independent metadata and data ioctxs created from the
  input ioctx's cluster and pool, with the input namespace copied before I/O.
  The owning librados library creates and destroys both contexts. Metadata
  calls and their `rados_get_last_version` reads are serialized on the
  metadata context; concurrent data I/O uses the separate context. Image
  operations retain both until close and pending completions settle.
- Batched metadata class calls use public read-operation C APIs. Data requests
  use public synchronous/asynchronous C APIs until a measured bottleneck
  justifies an explicitly versioned, separately tested extension.
- The first unchanged-application gate stages the own `librbd.so.1` and own
  `librados.so.2` together and verifies both loader paths. Pairing with the
  original librados is qualified separately before it is advertised.
- Public Ceph C/C++ ABI behavior still belongs to `rbd-ffi`; the native
  `rustyrbd` core owns decoded image policy. The adapter translates C buffers
  and callbacks without exposing Rust layouts across the library boundary.

## Rationale

The public C ABI is already the contract followed by an unchanged application
and is implemented by the own RADOS adapter. Keeping every opaque handle in
its originating library gives close, callback, and cluster lifetime one owner.
The read-operation API retains same-object batching without an internal Rust
ABI dependency. A direct internal fast path can be added only after a matched
QEMU measurement shows that the C boundary matters.

## Consequences

- + An input ioctx may be released by the caller after a successful open once
  the image's owned context is established; close and callbacks use the owned
  context.
- + A single loaded librados instance owns all ioctx state and transport work.
- - The adapter must translate public C operation results into native image
  observations, including exact per-operation errno, output size and version.
- - The loader, ioctx settings, namespace, concurrent refresh, and callback
  lifetime need application and fault gates before drop-in claims.

## Alternatives

- Embed `rados-ffi` as a Rust dependency in `librbd.so.1`: creates a second
  library state and makes a foreign opaque pointer unsafe to interpret.
- Export a private request ABI from `librados.so.2` immediately: duplicates a
  public operation path before a performance need is measured and adds a
  second compatibility contract.

## Open questions

- Which caller ioctx flags and read-snapshot settings must be copied into the
  image-owned context for the pinned C open variants? Pin by black-box tests.
- Confirm by black-box test that the pinned `rados_get_last_version` after a
  synchronous read operation reports that operation's header user version on
  both own and original librados. No image observation is published until
  this gate passes for the selected pairing.
- Does a separately loaded original librados satisfy all own adapter calls
  and ownership expectations? Qualify with a distinct loader and fault gate.
