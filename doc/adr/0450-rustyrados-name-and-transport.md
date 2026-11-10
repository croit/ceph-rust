# ADR 0450 rustyrados naming and transport evolution
Status: accepted
Date: 2026-10-14
Context: user accepted native-library naming and TCP-first development with future RDMA possible on both client and croit-flashstore-osd. Wire compatibility with classic clusters remains primary. ADR 0458's broader implementation contracts are accepted.

## Decision
- Native Rust crate/library name: `rustyrados`. C-facing artifact: crate `rados-ffi` (`[lib] name="rados"`, artifact `librados.*`), scoped by 0256/0305/0306; never install globally as `librados.so.2` before the declared profile passes.
- Implement ordinary TCP/msgr2 first against pinned classic Ceph, using event-driven kernel TCP (default per 0402; DPDK/userspace TCP explicit opt-in).
- Keep request/placement/authentication/retry semantics independent of transport. Use static driver specialization; do not add speculative RDMA machinery to the initial hot path.
- Buffer ownership must allow future registration and retain storage through transport completion. Application completion does not authorize reuse while transport still holds a lease.
- Future RDMA requires implementation on both endpoints, explicit capability/discovery rules and TCP access to classic endpoints. Never infer RDMA support from an OSD name or cluster membership.
- RDMA message transport and direct payload placement are separate future stages. Direct placement needs its own protocol, access-control, ownership and failure ADR before implementation.
- Authentication, request identity, ordering and durable completion remain required for every transport. No automatic write resubmission on transport switch without the request-machine contract.

## Consequences
Native application API need not expose transport-specific details; future RDMA-specific performance options may require explicit extensions. Neither Ceph RDMA interoperability nor any RDMA performance gain is established. The first experimental gate remains parallel owned-buffer reads against tuned reference paths, with independent correctness tests and measured CPU/copies/throughput.

Alternatives: use `librados` now (misstates ABI coverage); RDMA first (delays classic-cluster baseline); bake TCP buffers into public API (restricts later transports).
Contracts: runtime (doc not in the source snapshot), native API (doc not in the source snapshot). Plan: RADOS client (doc not in the source snapshot).

## Amendment 1 (2026-10-25): transport and artifact name
The client transport default is event-driven kernel TCP (0402); DPDK is explicit opt-in. The C-facing artifact is `rados-ffi` (`librados.*`, 0256/0305/0306), not `librustyrados`.
