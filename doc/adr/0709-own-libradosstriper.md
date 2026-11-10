<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0709 Own libradosstriper.so.1 on the public librados API (crates/striper-ffi)

Status: accepted, amended (am. 1)
Date: 2026-11-09

## Context

- Stock `libradosstriper.so.1` embeds and calls librados internals (`librados::IoCtxImpl`, `C_aio_stat_Ack`). On our librados.so.2 `rados --striper stat` aborts (doc/spec/rados-abi/striper-consumer.md sections 1 and 5, `lab/rados-client/striper-stat-repro.sh`). The foreign-cct cell `rados-striper` is RED.
- User mandate 2026-11-08: full drop-in. Every stock client library symbol works on our libs (adr 0306: v21.2.0 and v20.2.4).
- Lead decision O1 (2026-11-09): we ship our own `libradosstriper.so.1` with the C `rados_striper_*` API and the C++ `libradosstriper::RadosStriper` ABI. It is wire/on-disk compatible with stock in both directions.
- The libradosstriper sources of v20.2.4 and v21.2.0 differ only in editor modelines. Both versions share one ABI and one format.

## Decision

- Contract: doc/spec/rados-abi/libradosstriper.md (38 C functions, 50 C++ functions, on-disk format, locks, size protocol, aio, quirks Q1-Q17, deviations D1-D16). Implementers read only that spec, this ADR, doc/spec/rustyrbd/cxx-abi.md (C++ techniques) and our code.
- Crate `crates/striper-ffi`, MPL-2.0, `[lib] name = "radosstriper"`, `crate-type = ["cdylib", "rlib"]`. build.rs sets `-Wl,-soname,libradosstriper.so.1` for the cdylib. The artifact is installed as `libradosstriper.so.1.0.0`.
- One implementation, two ABIs. The C++ exports (feature `cxx`, profile `rados`) are thin adapters over the Rust core behind the C exports, as in rbd-ffi (adr 0704). They are built with `gnucxx` and the rbd-ffi bufferlist rules (cxx-abi.md section 8).
- librados is consumed only through its public C API, three C++ `IoCtx` symbols, the exported buffer symbols and three private extension functions (spec section 5). The crate never takes an rlib dependency on rados-ffi and has no DT_NEEDED on librados. Symbols are resolved at run time from the loaded librados (adr 0526 provider pattern, the shared `crates/rados-provider` resolver).
- Internally, all provider calls go through a Rust trait `Provider`. The cdylib uses the dlsym provider. Unit tests use an in-memory fake provider (objects, xattrs, cls lock, cmpxattr, write/read ops, aio completions).
- rados-ffi gains `rustyrados_aio_external_begin/_cancel/_end` (spec 3.1). User completions are driven only by these functions. On a librados without them (stock), aio with a user completion returns -EOPNOTSUPP (D16).
- Sync calls run the aio path with an internal completion and wait on it (one code path). Callbacks never block. Every chain step (data, then unlock, then user completion) is submitted from the previous completion callback.
- The size update is compare-and-swap through the C API: cmpxattr string EQ on the exact bytes read, plus setxattr in one write op; on -ECANCELED the size is re-read and the swap retried (D1). Stock objects and stock writers stay compatible, because both store the same ASCII decimal.
- Packaging: `libradosstriper.so.1` (+ `.so.1.0.0`) goes into package `librustyrados`, in the same private lib dir as `librados.so.2`. The link name `libradosstriper.so` goes into `librados-dev`. `croit-flashstore-lib-ctl` activates and deactivates it together with librados (ld.so.conf.d, scripts/package.sh). No `Conflicts` with Ceph's `libradosstriper1`.
- Targets: Linux x86_64 and aarch64 (C and C++ layer; the C++ layer needs the rados-ffi C++ ABI of the same arch at run time).

## Rationale

- KISS: the striper is a thin layer of about 2.5k lines over a handful of public librados ops. Reimplementing it is smaller and more robust than reproducing stock librados internals (O2).
- Same package as librados: the stock striper can never run on our librados. Shipping both in one package means an activated librustyrados always shadows the stock striper, so no installation can pair the two.
- Provider pattern and fake provider: one binary works under whichever librados the process loaded, and every protocol rule is unit-testable without a cluster.
- CAS size update: the public C API has no u64 cmpxattr mode. String EQ plus a re-read is expressible with it and also fixes stock's lost-append race. Accepted trade-off: one extra round trip on a size conflict only.

## Consequences

- + `rados --striper` and every libradosstriper consumer run on our librados, including stat/stat2 and aio.
- + Objects written by stock and by our striper are interchangeable; live cells verify both directions.
- + Stock bugs fixed (D1-D16); each is documented, and none changes the format.
- - rados-ffi gains a private extension ABI (3 functions) that the striper depends on.
- + The provider resolver and the `ceph::bufferlist` helper are one implementation in `crates/rados-provider`, shared with rbd-ffi (OQ 180).
- - Running the stock striper on our librados stays unsupported; the gap test documents and verifies this.

## Test plan

- Unit (fake provider, `cargo test -p striper-ffi`): the spec 2.3 extent vectors, xattr codec, cls lock payload bytes (83/80/62 B vectors), the size CAS conflict and retry, the trunc shrink/grow piece set, remove ordering and the lock cleanup, error paths (spec section 4), and the aio exactly-once rule. Each D and Q item gets its own test, named `d<N>_*` / `q<N>_*`.
- ABI (static): `scripts/striper-api-gap.sh` compares the exports of the built .so with `crates/striper-ffi/abi/current-{c-api,cxx-exports}.tsv` (exact set, no extra `librados::` symbols, no DT_NEEDED librados). The manifests are checked against stock `nm -D` of both reference images.
- C++ (`.cc` tests linked `-lradosstriper -lrados`, extended `lab/rustyrbd/cxx-abi-test.sh --link radosstriper`): every one of the 50 symbols is called at least once. Ref-counting, copy/assign, multi completion lifetime, bufferlist in/out.
- Live, croit-flashstore-osd cluster (classic v21.2.0 mon), `lab/rados-client/striper-cells.sh` with an own C client `striper-cells.c`. Four arms: stock-write/stock-read (oracle), our-write/our-read, stock-write/our-read, our-write/stock-read. Byte equality of data, the raw piece list (`rados ls`) and the raw head xattrs. Layouts: default, 64K/3/128K, 1M/4/4M. Cases: sparse writes, append, trunc shrink/grow, remove, xattrs, aio with callbacks.
- Live, stock tools: `lab/rados-client/foreign-cct-gate.sh --cells rados`, cell `rados-striper` green incl. `--striper stat`. `striper-stat-repro.sh` exits 0. `rados --striper put/get/stat/ls/rm/truncate/setxattr/getxattr/listxattr/rmxattr` A/B against the stock container (striper-consumer.md section 6, rows 1-4).
- v20.2.4: the ABI gap check only (manifests are identical); no live v20 runs (user 2026-11-08).

## Implementation steps

Implementer: DeepSeek via opencode (reads spec + ADR only, never ceph/). Claude reviews every diff. Each step is one mergeable commit: code + tests + doc, default-off until S8 (the .so is not packaged before S8). Gate = exact foreground exit of the listed commands.

| step | owner | content | tests | gate |
|---|---|---|---|---|
| S0 | Claude (spec role) | `crates/striper-ffi/abi/{current-c-api.tsv,current-cxx-exports.tsv}` from spec 1.1/1.2. `doc/spec/rados-abi/striper-stock-exports/{v21.2.0,v20.2.4}.tsv` (outside crates/: the workspace globs crates/*) = `nm -D --defined-only` of stock libradosstriper.so.1 in both reference images, filtered to the `rados_striper_*` / `libradosstriper::` namespace. Header sha256 pins (`libradosstriper.h`, `libradosstriper.hpp`). Script `lab/rados-client/striper-stock-exports.sh` | manifests equal the stock set in both images | `bash lab/rados-client/striper-stock-exports.sh --check` |
| S1 | DeepSeek | rados-ffi `rustyrados_aio_external_{begin,cancel,end}` (spec 3.1) on the existing Completion claim/publish/run_callbacks machinery; no C header (resolved with dlsym, spec 3.1) | begin/end delivers result+callbacks once; cancel leaves the completion reusable; begin on claimed/complete/null -> -EINVAL; an aio submitted from inside a completion callback completes (no deadlock) | `lab/remote-test.sh "cargo test -p rados-ffi"` |
| S2 | DeepSeek | crate skeleton (Cargo, SPDX, AUTHORS, build.rs soname); `Provider` trait + dlsym provider + fake provider; layout/naming/extent math (2.1-2.3); xattr codec (2.2); cls lock payload encoder (2.4); handle create/destroy/layout setters and their C exports | spec vectors 2.3; payload byte vectors 2.4; setter checks (64K multiples, D12) | `lab/remote-test.sh "cargo test -p striper-ffi"` |
| S3a | DeepSeek | open-for-write/read with shared lock + unlock, size CAS (2.5, D1), write/append/write_full/read/stat/stat2 (sync, via the internal aio path) + C exports | per-call semantics rows of spec 3; D1 conflict retry; D2; D6; D15; Q items of these calls | same |
| S3b | DeepSeek | remove (D4 order, exclusive lock), trunc shrink/grow (D5), getxattr/setxattr/rmxattr/getxattrs iterator (D14) + C exports | piece-set vectors from 2.3; lock left nowhere on failure; internal xattrs hidden | same |
| S4 | DeepSeek | C aio family incl. aio_flush, multi completion (3.2, D9), user completion via S1 extension, -EOPNOTSUPP without it (D16) | exactly-once completion (D3); D8 issue-error rule; callbacks never block; fake provider with and without the extension | same |
| S5 | DeepSeek | `scripts/striper-api-gap.sh` (C part); `lab/rados-client/striper-cells.{sh,c}` four arms (test plan); `lab/rados-client/libs-build.sh` builds/collects `libradosstriper.so.1` | gap script exit 0; striper-cells all four arms green on a croit-flashstore-osd cluster | `lab/remote-test.sh "cargo test -p striper-ffi"`; `bash scripts/striper-api-gap.sh`; `bash lab/rados-client/striper-cells.sh` (Haiku runs it) |
| S6 | DeepSeek | feature `cxx`: 50 C++ exports (3.3) with `gnucxx`, `export_pair!`, bufferlist rules, `catch_unwind` -> -EIO, flag translation (D13), D7/D10/D11; gap script C++ part; `cxx-abi-test.sh --link radosstriper` + `.cc` tests | every C++ symbol called; refcount/copy/assign; bufferlist in/out; flag table | `lab/remote-test.sh "cargo test -p striper-ffi --features cxx --profile rados"`; `bash lab/rustyrbd/cxx-abi-test.sh --link radosstriper` |
| S6a | DeepSeek | shared cls lock client codec (am. 1): new crate `crates/cls-lock` (MPL-2.0, SPDX + AUTHORS, deps `denc` + `bytes` only): input encoders of the 7 methods and the `get_info` / `list_locks` reply decoders with the stock acceptance rules of spec 9.3 (decoders return the consumed length). The code moves out of `crates/rustyrados/src/locks.rs` (its `LockOperation` / `LockReply` / limits API stays as a thin user); `crates/rustyrbd/src/lock_wire.rs` and `crates/striper-ffi/src/lock.rs` drop their private encoders and call the crate. No wire change | unchanged byte vectors (striper 83/80/62 B, rustyrbd lock_wire tests); per-method byte vectors in the new crate; reply decode: v1, v2 with bytes left in the envelope (accepted), compat 2 (rejected), repeated key (later wins), unsorted keys (accepted), legacy and msgr2 addr, every truncation (error); rustyrados lock tests adapted to the stock rules | `lab/remote-test.sh "cargo test -p cls-lock -p rustyrados -p rustyrbd -p striper-ffi -p rados-ffi -p rbd-ffi"`; `cargo check --workspace` on the build host |
| S6b | DeepSeek | feature `cxx`: the 26 `rados::cls::lock::` exports of spec 9.4 in `crates/striper-ffi/src/cxx/clslock.rs`, over `cls-lock`, `gnucxx` (`GnuKey` for `locker_id_t`, spec 9.2 order) and `rados-provider` (`BufferFns` + `copy_all`, `operator+=`); `Provider` + dlsym + fake gain `read_op_exec`, `buffer_free`, `object_operation_exec` (`exec_impl`, else `exec`); `cxx/layout.rs` const-asserts the spec 9.2 sizes/offsets (Lock 144, locker_id_t 48, locker_info_t 80, entity_name_t 16, entity_addr_t 36, utime_t 8, const iterator 32, map node value at +32); `lab/rustyrbd/cxx-abi-test.sh` radosstriper `min_implemented` 114; `.cc` test `crates/striper-ffi/tests/cxx/s5-clslock.cc`; `lab/rados-client/foreign-cct-cells.sh` `cell_rados_lock` extended: two shared lockers with tag + description + duration, `lock info` with both (order), exclusive conflict, `lock info` of an unknown name, `lock list` on a missing object, break of one shared locker | offline: D17 null arguments (-EINVAL / no-op), D18 NUL oid; fake provider: every export's op bytes = `cls-lock` vectors, `exec` fallback when only the v20 name exists, outputs replaced only on success, null outputs skipped, -EBADMSG leaves outputs, `get_lock_info_finish` advances by exactly the reply length and not on error (D19); `.cc` with CEPH_CONF: all 26 called; shared x2 then `get_lock_info` (2 lockers in order, type, tag); exclusive conflict -EBUSY; `set_cookie`; `assert_locked` in a write op (0 / -EBUSY); `break_lock`; `aio_unlock` completes; ephemeral unlock removes the object; `get_lock_info_start` + `operate` + `finish` | `lab/remote-test.sh "cargo test -p striper-ffi --features cxx --profile rados"`; `bash scripts/striper-api-gap.sh` (exit 0, implemented 114); `bash lab/rustyrbd/cxx-abi-test.sh --link radosstriper` |
| S7 | Haiku (lab) | live gates: `rados` starts with our `libradosstriper.so.1` (every foreign-cct `rados` cell); foreign-cct `rados-striper` green incl. stat; `rados-lock` (extended in S6b) A/B equal to the stock arm (JSON fields name/type/tag, lockers name/cookie/description/expiration/addr); `striper-stat-repro.sh` exit 0; `rados --striper` A/B rows of striper-consumer.md section 6; striper-cells C++ arm; static: the stock manifests and the consumer-binding inventory unchanged | as listed | `bash lab/rados-client/striper-live-gates.sh --libs DIR` (exit 0: `striper-stat-repro.sh` and `foreign-cct-gate.sh --cells rados` with every cell green, incl. `rados-striper` and `rados-lock`); `bash lab/rados-client/striper-stock-exports.sh --check`; `bash lab/rados-client/striper-export-inventory.sh --check --version 21.2.0` and `--version 20.2.4` |
| S8 | DeepSeek | packaging: scripts/package.sh stages `libradosstriper.so.1` in librustyrados + link name in librados-dev; `croit-flashstore-lib-ctl` and `lab/package-install-check.sh` know the soname; `lab/build-host-build.sh` prodcl builds the crate with `cxx` | install check: our striper wins over Ceph's `libradosstriper1`, deactivate restores stock | `bash lab/package-install-check.sh` (Haiku runs it) |

Order: S0, S1 and S2 are independent. S3a needs S2. S3b and S4 need S3a. S4 also needs S1. S5 needs S4. S6 needs S3b and S4. S6a is independent of S1-S6. S6b needs S6 and S6a. S7 needs S5 and S6b. S8 needs S7. Mark `striper-consumer.md` section 5 done after S7.

Status: S0, S1, S2, S3a, S3b, S4, S5, S6, S6a and S6b implemented. S7, S8 pending.

## Alternatives

- O2, keep stock libradosstriper and emulate `IoCtxImpl`/`AioCompletionImpl`/`Objecter` layouts in our librados: large, fragile against any stock rebuild, contradicts one engine (striper-consumer.md section 5).
- O3, LD_PRELOAD or needed-order tricks so our symbols win: depends on process start-up; not a conformance mechanism.
- rlib dependency on rados-ffi: binds the striper to our librados instance and breaks under a foreign librados; rejected per adr 0526.
- A C++ shim compiled with g++: C++ is limited to contrib/nixl; the Rust export technique of adr 0704 already exists.
- A u64 cmpxattr size update through the C++ `ObjectWriteOperation::cmpxattr(u64)`: adds a C++ provider dependency for one op, and keeps the stock append race.
- Separate package `librustyradosstriper`: allows our librados plus the stock striper, which aborts; rejected.

## Open questions

- OQ 179: are the upstream gtest binaries `ceph_test_rados_striper_api_{io,aio}` available in the reference image, to run as a black-box oracle (C/C++ arms)? If yes, add them to S7 and document the failures that D1-D16 cause. Also listed in doc/90-open-questions.md.
- OQ 180: decided: `crates/rados-provider` holds the provider symbol resolver and the `ceph::bufferlist` reader/builder, used by rbd-ffi and striper-ffi (S6). Also listed in doc/90-open-questions.md.

## Amendment (2026-11-09): embedded cls lock client exports (am. 1)

- Finding (S7 live gate): stock `rados` fails at start-up on our striper with `undefined symbol _ZN5rados3cls4lock13get_lock_info...`. Stock `libradosstriper.so.1` links the cls lock client statically and exports its 26 `rados::cls::lock::` functions; `rados` (`lock list|info|get|break`) imports 5 of them, is BIND_NOW, and no other DSO defines them. Inventory, method and numbers: spec section 9.1, `lab/rados-client/striper-export-inventory.sh`, `doc/spec/rados-abi/striper-stock-exports/v{21.2.0,20.2.4}-consumer-bindings.tsv`. The inventory was re-run on an x86_64 test runner (2026-11-09, OQ 183(a)): the 21-row must set is identical and the 77 `alt` rows match byte for byte, so the export decision is arch-confirmed.
- Decision: our `libradosstriper.so.1` (feature `cxx`) exports all 26 cls lock functions with the stock behaviour of spec 9.3/9.4 (deviations D17-D19), and nothing else outside sections 1.1/1.2: the other stock exports are librados internals or vague-linkage copies that libceph-common also provides. Required set: `crates/striper-ffi/abi/current-clslock-exports.tsv` (kind `clslock`, column `imported` marks the 5 `rados` binds); `scripts/striper-api-gap.sh` requires 38 + 50 + 26 = 114.
- Mechanism: the `IoCtx*` functions use the C API on the `IoCtx`'s `rados_ioctx_t` (as `striper_create`); the op builders call the loaded librados's exported `ObjectOperation::exec_impl` (v21 name), else `ObjectOperation::exec` (v20 name), on the caller's op; `get_lock_info_finish` reads the caller's const iterator through the exported `copy_all` and `operator+=`. All resolved by `crates/rados-provider`; never a second librados, still no DT_NEEDED on librados. `aio_unlock` hands the caller's completion to `rados_aio_write_op_operate`, so it needs no S1 extension and works over stock librados.
- Shared code (KISS + DRY): one MPL-2.0 client codec crate `crates/cls-lock` (S6a) replaces the three client copies (rustyrados `locks.rs`, rustyrbd `lock_wire.rs`, striper-ffi `lock.rs`). Its reply decoders follow stock acceptance (forward-compatible envelopes, later duplicate key wins); rustyrados's stricter checks go away with the move (adr 0256: match the reference where it is not a bug). The OSD-side cls lock (`services/osd/cls`, LGPL) is not shared.
- OQ 183(b) decided (lead, 2026-11-09): YES, the shared `cls-lock` decoders follow the stock rules (accept newer envelope versions per the compat rule, later value of a repeated key wins, unsorted keys accepted): "behave like stock unless it is a bug or harmful" (adr 0256). The rustyrados lock tests that asserted the old rejections now assert the stock acceptance.
- Siblings checked: same method over `rbd`, `rbd-nbd`, `rbd-mirror`, `rados`, `radosgw`, `ceph-mgr`, `cephfs-journal-tool` (v21.2.0) and their bindings into librbd.so.1 / librados.so.2: only public-class typeinfo that rados-ffi / rbd-ffi already export, or copies libceph-common also defines; no other embedded-client gap. crc/secure, knet/RDMA, SPDK/kernel, rep/EC: not affected (client ABI only).
- Gate change: S7 runs `lab/rados-client/striper-live-gates.sh` and needs every `rados` cell green (a missing import stops every `rados` command, not only `--striper`), including the extended `rados-lock` cell; static checks `striper-stock-exports.sh --check` and `striper-export-inventory.sh --check`.
- Rationale: drop-in rule (user 2026-11-08: behave like stock unless a bug or harmful); the 21 unimported functions cost only thin adapters over the same codec and protect third-party programs linked like `rados`.
- Open: none (OQ 183 resolved 2026-11-09: (a) x86_64 must set identical, 21 rows; (b) decided).

