# 0024 Lab/dev backends: zero cost in production
Status: accepted
Date: 2026-10-09
Context: lab needs FileDev, DevMemStore, FileMetaStore, kernel-probe driver, af_packet. Must not slow the production path (user requirement).
Decision:
- Every lab/dev backend sits behind a cargo feature (`lab`, `kernel-probe`), OFF in production builds. Production build = no `lab`/`kernel-probe` (feature matrix: am. 1). Dev code is not compiled into the prod binary (no runtime flags, no branches on hot path).
- Hot-path abstractions use static dispatch (generics, monomorphized): BlockDev, Nic, PgStoreOps, MetaStore, Store<D>. No `dyn` trait objects / Box<dyn> on per-op paths. `dyn` allowed only on cold paths (startup, admin).
- No extra copies, checks or allocations added for lab backends' sake; lab backends adapt to the prod interfaces, not vice versa.
- Enforcement: scripts/check-prod.sh builds the prod feature set and fails if lab symbols (FileDev, DevMemStore, FileMetaStore, kdrv) appear in the binary (`nm`), and greps hot-path crates for `dyn ` in per-op APIs. Run before each milestone.

## Amendment (2026-10-19): production feature matrix (am. 1)
`--features dpdk,spdk` is no longer the one production set. scripts/check-prod.sh (header = source of truth) builds + clippies (`--locked`, `-D warnings`) every production configuration and runs the lab-symbol `nm` check on each croit-flashstore-osd binary: `knet`; `spdk`; `knet,spdk,mimalloc`; `dpdk,knet,spdk,mimalloc` (the full production binary, AF_XDP = run mode of the own stack, no own feature); croit-flashstore-tool `--no-default-features spdk,mon-std,mimalloc,elastic`. Parked DPDK networking (0005 am. 2) stays compile-checked (`dpdk,spdk` without knet), plus one combined `cargo test --no-run -p osd -p store -p croit-flashstore-osd` (DPDK linkage is owned by crate `dpdk-link`, features stay additive).
