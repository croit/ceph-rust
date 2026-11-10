# 0003 Green-field, no crimson fork, free license via clean spec
Status: accepted
Date: 2026-10-09
Context: Crimson = C++/seastar, tries to support everything (HDD, alienstore/BlueStore, all pool types) -> complexity. Complex code is never fast. User prefers free license choice while staying wire-compatible.
Decision: Green-field Rust. No fork, no linking of Ceph code (libceph-common, crush, denc, cls .so). Wire protocol re-implemented.
License process (not legal advice; get lawyer review before release):
- Interop/protocol formats are interfaces, not copied code (EU SW-Directive Art.1(2), Art.6 interop).
- Ceph source = reference only. Spec work: read Ceph source -> write own-words spec in `doc/spec/` (structs, field order, versions, state machines, invariants). NO code excerpts in specs.
- Impl work: from spec. Never copy/translate Ceph code line-by-line. Data tables needed for bit-exact compat (e.g. crush_ln table, CRC polys) = facts, allowed, mark origin.
- Third-party deps must be permissive (BSD/MIT/Apache): SPDK BSD-3, DPDK BSD-3, ISA-L BSD-3.
- Final project license: see 0164 (supersedes 0012).
Consequences: + simplicity, license freedom. - large re-implementation, compat risk -> heavy interop testing vs real cluster.
Alternatives: fork crimson (rejected: C++, complexity, LGPL), link Ceph C++ libs from Rust (rejected: LGPL + C++ ABI pain).
