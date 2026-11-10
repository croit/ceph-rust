<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# ADR 0442: optimized C++ client unwind contract
Status: accepted
Date: 2026-10-18

Context: Actual foreign C++ exception tests pass in debug but terminate in the
workspace release profile (`panic=abort`). Export names alone cannot qualify
an artifact. C++ callers must catch buffer/standard exceptions and Rust guards
must release temporary ownership during unwinding.

Decision: Build optimized client ABI artifacts with the `rados` profile:
inherit release optimization/LTO, set `panic=unwind`. Reject `librados-cxx`
with `panic=abort` at compile time. Keep the daemon release profile unchanged.
The versioned ELF packager defaults to `rados`; `RUSTYRADOS_BUILD_PROFILE=dev`
selects development packaging. Record the profile with the artifact. Build
time budget includes optimized LTO; runtime test deadlines remain separate.

Consequences: Validate real C++ catches, exception destruction and failed
stream writes against the actual optimized ELF, including both pinned header
versions. Tests still use the normal debug test profile. Rust panic propagation
is not a public C++ exception contract; `C-unwind` permits required foreign
exceptions, and non-unwinding C interfaces retain their existing contract.

Alternative: changing workspace release to unwind would also affect daemons
and unrelated tools. Debug-only packaging leaves optimized compatibility open.
