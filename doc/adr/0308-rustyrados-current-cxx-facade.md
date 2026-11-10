# ADR0308: independent current C++ ABI facade
Status: accepted. Date: 2026-10-17.

## Context
Current C++ ABI remains part of the full replacement gate. The two references
have a407-function union; a246-name C adapter cannot satisfy unchanged C++ imports.
Reference linkage/forwarding and translating Ceph implementations are prohibited.

## Decision
Implement an independent Rust ABI facade in affected-crate increments, behind
default-off `librados-cxx` (implies `librados-compat`). First close the pointer-only
Rados/IoCtx lifecycle and scalar/config/map bridge using existing own C contracts.
Use observed current mangled names/default versions; document object layout,
ownership and parameter ABI before implementation. No Ceph linkage or new runtime
thread. Keep partial C++ profile explicit until all required symbols/contracts pass.

## Consequences
Linux x86_64 LP64/Itanium ABI is the first anchor; other ABIs remain unqualified.
Standard-library containers, bufferlist, virtual callbacks/RTTI, compound builders,
completions and foreign concrete contexts require separate specs/tests. Do not
export blanket unsupported placeholders or dereference foreign Ceph private types.
Validate unchanged reference-linked own consumers and eventual real C++ programs;
raw symbol coverage alone never proves compiler/application interoperability.
