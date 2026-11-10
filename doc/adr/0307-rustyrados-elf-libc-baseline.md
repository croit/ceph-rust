# ADR0307: rustyrados ELF libc baseline
Status: accepted. Date: 2026-10-17.

## Context
The v20.2.4 reference image uses glibc2.34. Initial host-built versioned ELF
cannot load there: AWS-LC's C object imports __isoc23_sscanf@GLIBC_2.38 from
the build host's headers. Public Ceph symbol equality does not prevent this.

## Decision
Allow an explicit external target sysroot for native C compilation and final
ELF link. Reject packaged artifacts requiring glibc symbols newer than2.34.
Keep Rust/toolchain/dependency sources unchanged; no libc symbol rewriting or
compatibility stubs. Record sysroot provenance and qualify actual image loading.

## Consequences
Host-default builds may be rejected. A suitable sysroot is required on newer
hosts. This checks a necessary dynamic-version bound, not universal portability:
architecture, loader, other native dependencies and actual execution remain gates.
Older libc platforms are not qualified by this decision.
