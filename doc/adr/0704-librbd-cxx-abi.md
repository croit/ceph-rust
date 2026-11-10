<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0704 librbd C++ ABI: mangled exports over the C core, aarch64 for librbd and librados

Status: accepted
Date: 2026-11-08

## Context

- Our librbd.so.1 (crates/rbd-ffi) exports only the C ABI. The librbd.hpp C++ ABI is absent: 286 functions and 7 data symbols (`crates/rbd-ffi/abi/current-cxx-{exports,data}.tsv`, gap tool `scripts/rbd-cxx-api-gap.sh`). This is libreview R5-01.
- Stock C++ consumers import only the C++ ABI. In v21.2.0 the `rbd` CLI imports 171 C++ librbd symbols and 0 C ones, and rbd-nbd imports 29 C++ (`crates/rbd-ffi/abi/stock-imports/v21.2.0.tsv`, `lab/rustyrbd/stock-imports-collect.sh`). A system-wide drop-in therefore breaks them.
- User decision 2026-11-08: full drop-in compatibility. Every symbol is implemented, and behaviour matches stock unless stock is buggy or harmful.
- Our librados C++ ABI (crates/rados-ffi `cpp_*.rs`, ADRs 0308/0309/0442) compiles only for Linux x86_64 (`compile_error!` in `cpp_handles.rs`). The C++ package profile is x86_64 only (scripts/package.sh, lab/rados-client/package-elf.sh).
- rbd-ffi never links the rados-ffi rlib. It resolves librados symbols at run time (ADR 0526).

## Decision

- rbd-ffi feature `librbd-cxx` exports the full librbd.hpp C++ ABI of the pinned Ceph version. Each symbol is a Rust `extern "C-unwind"` function with `#[unsafe(export_name = "<mangled>")]`, and data symbols are Rust `static`s with `export_name` (a cdylib exports only symbols rustc knows, so `global_asm!` symbols would be localized). This is the rados-ffi export technique (ADR 0308) without its asm data symbols.
- Each C++ entry point is a thin adapter over the existing `rbd_*` C core or its internal Rust functions. No second implementation of any operation exists.
- C++ objects follow the stock layouts. RBD is empty. Image, ImageOptions, PoolStats and RBD::AioCompletion are one pointer each, and that word is the matching C handle.
- A `librados::IoCtx&` argument is read as one pointer: its first word is the `rados_ioctx_t` of whichever librados.so.2 is loaded (ours or stock). A null word returns -EINVAL.
- A new stateless crate `crates/gnucxx` (MPL-2.0) holds the libstdc++ (`_GLIBCXX_USE_CXX11_ABI=1`) container builders, the sret/arch shims and the data-symbol macros. rbd-ffi uses it. rados-ffi may migrate later (open question).
- Completions are one object model for C and C++. Our C `rbd_completion_t` points to a `Completion` whose first word points to itself, while a C++ wrapper's first word (`pc`) points to the `Completion`. Every completion entry point dereferences the first word. Callbacks and `poll_io_events` return the public handle (wrapper or self). Releasing a wrapper also frees it with the global sized `operator delete(this, 8)`. C and C++ handles mix freely, as in stock.
- Bufferlist arguments use the loaded librados `ceph::buffer::list` layout (32 bytes) and only exported buffer functions. Writes pass the caller's segments to the core as iovecs (zero-copy); aio writes keep ptr references until completion. Reads fill a fresh `buffer::ptr` and then replace the caller's list. An aio read fills it before the user callback runs.
- App-implemented virtuals (ProgressContext, UpdateWatchCtx, QuiesceWatchCtx) are called through the Itanium vtable slot from C-trampoline callbacks. librbd exports ProgressContext's vtable, typeinfo and D0/D1/D2, plus the typeinfo of the two watch contexts, as global symbols.
- Where stock dereferences a null or closed handle and crashes, we return -EINVAL (or false, 0, an empty string, or a no-op for non-int returns). Every other return code and container effect follows stock C++ (spec table).
- Unwinds thrown by app callbacks pass through `C-unwind` frames. Builds with `librbd-cxx` use the `rados` profile (panic=unwind). `compile_error!` fires under panic=abort.
- aarch64 (Linux LP64, GNU libstdc++) is a supported target for both C++ ABIs. Functions that return a non-trivial class use a per-arch sret shim (x86_64: hidden pointer in rdi, which is returned in rax; aarch64: hidden pointer in x8). No other ABI rule differs for our symbol set (spec section 6).
- Packaging ships the C++ profile of librados and librbd on both arches. The stock-import checks gate both packages.
- Spec: doc/spec/rustyrbd/cxx-abi.md (method table, step plan S0..S16, live gates G0..G5).

## Rationale

- Thin adapters over the C core keep one implementation and one test surface. The C core already carries the qualified semantics (ADR 0526 and the rustyrbd specs).
- Mangled exports from Rust follow a technique proven in rados-ffi. That avoids a C++ toolchain in the build and the ban on C++ outside contrib/nixl.
- First-word handles make the C++ layer independent of which librados is loaded, so the ADR 0526 pairings (ours+ours, stock librados+our librbd) both work.
- The self-pointer completion design gives stock's C/C++ handle interchangeability without an extra allocation per C aio. The cost is one load per call.
- Accepted trade-off: librbd.so.1 with `librbd-cxx` NEEDs libstdc++.so.6 and the `rados` profile. The glibc-only static link mode cannot carry the C++ profile.

## Consequences

- + The stock `rbd` CLI, rbd-nbd and other C++ consumers can load our librbd.so.1. The gap tool reaches 0.
- + aarch64 packages gain both C++ ABIs. The x86_64-only caveat leaves package descriptions.
- + A Completion layout change makes C handles wrapper-compatible. One extra load per completion call.
- - The C++ layer is a large symbol surface (293). Each symbol needs a C++ consumer test against the stock header.
- - The stock CLI on OUR librados still needs foreign-CephContext support in librados (`Rados::init_with_context` on a stock CephContext returns -EOPNOTSUPP today). Until then, live gate G2 pairs the stock CLI with stock librados and our librbd.
- - The panic=unwind profile for librbd costs code size against the current panic=abort release build.

## Alternatives

- C++ shim library (`.cc` over librbd.h): rejected. C++ is banned outside contrib/nixl, it needs a C++ toolchain in every build, and it duplicates the rados-ffi technique.
- Separate C and C++ completion objects (no mixing): rejected. Stock treats `rbd_completion_t` as the C++ wrapper, and the self-pointer costs one load.
- Allocating a C++ wrapper for every C completion: rejected. It adds a malloc to the QEMU hot path.
- Linking rados-ffi C++ helpers into rbd-ffi: rejected by ADR 0526 (no rados-ffi rlib in librbd).
- Exporting only the 184 symbols stock binaries import: rejected by the user decision (full ABI).

## Open questions

- doc/90-open-questions.md 175: librados foreign CephContext (`Rados::init_with_context` with a stock CephContext). This blocks the stock rbd CLI and rbd-nbd on our librados (gates G3/G4).
- doc/90-open-questions.md 175: rbd-mirror imports two librbd-internal symbols outside librbd.hpp (`librbd::rbd_features_to_string[abi:cxx11] (u64, std::ostream*)` and `librbd::rbd_features_from_string(std::string const&, std::ostream*)`). Should we export them?
- doc/90-open-questions.md 175: migrating rados-ffi onto crates/gnucxx (dedup) versus leaving it as is.
- doc/90-open-questions.md 175: aarch64 build host and aarch64 test runner for the C++ gates. The local arm64 docker reference cluster covers functional gates only.

## Amendment (2026-11-09): shared completion object is one `#[repr(C)]` type with a self pointer and a public handle (am. 1)

- `Completion` (rbd-ffi `aio_completion.rs`) is `#[repr(C)]`; its first field is `self_ptr: *const Completion`, set to the allocation address right after construction, and its second field is `public: AtomicPtr<c_void>`, the handle passed to callbacks and returned by `rbd_poll_io_events`. A C handle is the completion itself (`self_ptr == handle`, `public == handle`); a C++ wrapper's first word (`pc`) points at the completion (`public == wrapper`). Every completion entry point (C and C++) resolves `comp = *(handle)` with one load, so C and C++ handles mix freely.
- C-path cost: unchanged hot-path behaviour. Per completion call there is one extra load (the first-word deref; for a C handle it loads a pointer that equals the argument, so no extra branch is taken in `rbd_aio_release`, where the wrapper-free `operator delete` is `#[cfg(feature = "librbd-cxx")]` and dead in C-only builds). Callback delivery and `poll_io_events` hand out `public`, which for C completions is the same pointer the C path delivered before (`Arc::as_ptr`). No new allocation, no new lock, no new syscall on the C aio path; the C ABI is unchanged.
- The C++ wrapper constructor allocates fallibly (global allocator, OOM reported as `pc = null` per spec section 7) by mirroring the `Arc::new` allocation (strong/weak counts followed by the value) so `Arc::from_raw` applies; the C `rbd_aio_create_completion` keeps `Arc::new` (abort on OOM, as before).
