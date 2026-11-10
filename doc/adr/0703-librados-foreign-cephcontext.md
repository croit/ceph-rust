<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0703 librados accepts a stock CephContext through the host's libceph-common

Status: accepted
Date: 2026-11-08
Amends: 0458 (no-Ceph-library rule: scope clarification for foreign contexts)

## Context

Stock Ceph tools (rbd, rbd-nbd, rbd-fuse, rados, cephfs-* tools, ceph-dedup-tool, rbd-replay, ...) link stock
libceph-common, build their configuration with `global_init` and hand `g_ceph_context` to
`librados::Rados::init_with_context` / `rados_create_with_context`. Our librados.so.2 answers -EOPNOTSUPP for a
context it did not create (crates/rados-ffi/src/config.rs `rados_create_with_context`), so no stock tool runs on it.
User decision: full drop-in compatibility, behaviour exactly like stock unless buggy or harmful. The context object
was built and is owned by the host's libceph-common; its configuration is live and shared with the tool, which keeps
changing it after `init_with_context` (rbd sets `rbd_cache`, `rbd_default_format`, journal options before image
open), and stock librados applies the monitor's central configuration into it at connect.
Contract and step plan: doc/spec/rados-abi/foreign-cephcontext.md (doc not in the source snapshot).

## Decision

- A context pointer not in our own context registry is a foreign candidate. librados accepts it only when the
  process has already loaded a stock libceph-common (symbols found via `RTLD_DEFAULT`, then
  `dlopen("libceph-common.so.2", RTLD_NOLOAD)`) whose build has a committed layout row and passes the runtime
  validation of the spec; otherwise it keeps returning -EOPNOTSUPP and prints one error line naming the build.
- librados never loads, links or bundles libceph-common: no DT_NEEDED, no `dlopen` without `RTLD_NOLOAD`. Without it
  in the process, behaviour is unchanged.
- The foreign object is operated on only through the host runtime's own exported entry points
  (`CephContext::put`, `md_config_t::get_val/set_val/set_mon_vals/parse_*`, `common_init_finish`) plus the inline
  operations stock librados inlines (reference increment, proxy mutex). No Ceph object is constructed, copied or
  destroyed by Rust code.
- Reference ownership is stock: each cluster handle takes one reference at creation (atomic increment of the
  context's counter) and releases it with the host's `CephContext::put` exactly once, on the thread performing the
  final handle release. `rados_cct` / `Rados::cct` / `IoCtx::cct` return the foreign pointer, borrowed.
- Configuration is shared, not snapshotted: `rados_conf_get` reads the live foreign value; `rados_conf_set` and the
  `rados_conf_parse_*` / `read_file` calls write into the foreign context. The client engine uses a mirror refreshed
  from the foreign context at creation and at connect, the points where stock librados reads its own values;
  `rados_mon_op_timeout` (the one key stock librados observes) is read live per monitor operation.
- Connect pushes the monitor's configuration into the foreign context at the monitor level (`set_mon_vals`), then
  calls the host's `common_init_finish`, the stock connect order. Runtime monitor configuration updates are pushed the
  same way.
- Object layout facts (field offsets inside CephContext/ConfigProxy/ConfigValues/md_config_t) come from a committed
  row per (libceph-common git sha, arch), generated from the published debuginfo by a committed script, and are
  validated against the live object before the first foreign call. Builds with debug mutexes are refused.
- Accepted deviations until their steps land (spec section 7): observer notification after our own config writes
  is deferred to the host's next `apply_changes`; our client's admin socket hooks, perf counters and log entries do
  not appear in the foreign context.

## Rationale

The context was created by libceph-common; only that runtime can release it, read its layered/meta-expanded values
and notify its observers with exact stock semantics. Calling its exported entry points needs five function
signatures with plain arguments plus one std::map argument already supported by our C++ ABI code (cpp_tree,
cpp_string_map). The alternative of reproducing CephContext, ConfigProxy, md_config_t and Log behaviour in Rust over
foreign memory (G09, doc/spec/rados-client/foreign-context-initialization-contract.md) still lists eight unresolved
proof obligations, including foreign destruction. Calling a host library that the application itself loaded is not
linking or copying Ceph code (0003), and librados keeps working without it (0458). Accepted trade-off: a per-build
layout row is required; unknown builds are refused loudly instead of guessed.

## Consequences

+ Stock rbd/rados/rbd-nbd/rbd-fuse/cephfs tools can run on our librados.so.2 (rbd and rbd-nbd also need our
  librbd.so.1 C++ ABI, branch rbd/cxx-abi).
+ Stock consumers that dereference the context (libradosstriper's `ldout`/`_conf`, cephfs-mirror passing
  `cluster->cct()` to stock libcephfs) receive a real stock context.
+ Exact stock semantics for config precedence, meta-variable expansion, key normalisation, error codes and lifetime.
- One layout row per shipped libceph-common build (official and croit fork, x86_64 and aarch64); an unknown build
  refuses foreign contexts.
- librados contains Linux-only unsafe code that calls C++ entry points by mangled name.
- Deviations listed in the spec section 7 remain until steps S7/S8.

## Alternatives

- Reparse argv (/proc/self/cmdline), CEPH_ARGS and ceph.conf ourselves: misses programmatic `g_conf` writes, mon
  config and contexts not built from argv (rbd-mirror peers, libcephsqlite); not exact.
- One-time snapshot at `init_with_context`: misses rbd's writes before image open; rejected.
- Rebuild the context object model in Rust (G09 ingest direction): unbounded C++ object ABI, foreign destruction
  unproven; rejected for ingest. G09 stays the reference for the opposite direction (our context handed to stock
  consumers).
- Heuristic scan for the md_config_t inside ConfigProxy instead of a layout row: not deterministic; rejected.
- C++ shim compiled against Ceph headers: C++ is limited to contrib/nixl; it would also compile Ceph headers into
  our library; rejected.

## Open questions

- Decided 2026-11-08 (lead, under the user's full drop-in compatibility rule): calling an already-loaded host
  libceph-common for objects it created is within 0003/0458 (no code is copied, nothing is loaded or linked by us).
- Decided 2026-11-08: S7 (observer dispatch) and S8 (log, admin socket, perf counters in the foreign context) are
  implemented; D1-D3 are temporary, not accepted deviations (user: behave like stock unless stock is buggy/harmful).
- Decided 2026-11-08: the packaging step generates the layout rows for croit fork builds.
- rbd-mirror and RGW link stock librbd internals / neorados that reach into stock RadosClient; they are out of
  scope until a separate decision. OQ 175.
