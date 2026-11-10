# ADR0309: current C++ standard-runtime boundary
Status: accepted. Date: 2026-10-17.

## Context
Current C++ APIs exchange GNU C++11 strings/containers. Allocating their backing
storage with an unrelated allocator breaks caller destruction/custom operator new.
Reference forwarding and copying Ceph implementation code remain prohibited.

## Decision
For librados-cxx only, use the target's shared system libstdc++.so.6 runtime for
its exported standard string constructor/destructor/access/assignment operations.
This is a system compiler runtime, like libc/libgcc; no Ceph implementation link.
Own Rust ABI facade and protocols remain independent. Use C-unwind at boundaries
that may propagate a standard-runtime exception; construct return objects in place
and clean partially constructed outputs on unwind. Never move a constructed SSO
string by Rust byte-copy. No dependence on private Ceph helpers or arbitrary
consumer-visible stdlib templates being instantiated in the runtime.

## Consequences
Initial profile GNU C++11 string ABI/Linux x86_64 LP64, verified against each
reference/runtime. Other compiler/stdlib ABIs remain gates. Native final linking
uses the existing glibc2.34 sysroot's runtime, not newer host libraries. Preserve
binary lengths for namespaces/locators/object names; C strings are insufficient.
Freeze the407-function required inventory and report actual missing names from ELF.
