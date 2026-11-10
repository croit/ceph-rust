<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0167 Verification hashes: BLAKE3 default, XXH3 option, no md5
Status: accepted
Date: 2026-10-17

Decision (user 2026-10-17):
- Crate `crates/hashsum` (LGPL, tools/lab only, never in the daemon): `blake3` (rayon + mmap) and `xxhash-rust` xxh3. Default = `blake3` (`hashsum::DEFAULT`, `H_ALG` in `lab/lib/hash.sh`; the two places to change).
- Why blake3: standard (output equal to `b3sum`, distro-packaged: externally verifiable), cryptographic, internally tree-parallel (all cores for big inputs, mmap for files). Measured on a daos VM, 16 cores: 29-44 GB/s in memory, 15-17 GB/s on warm files, 4.6 GB/s on one core; lab verify data arrives at ~1-3 GB/s (pipes, network, rados), so the hash is never the bottleneck.
- `xxh3` = standard XXH3-128 (output equal to `xxh128sum`: hex high64||low64), single thread 9 GB/s, selectable (`--xxh3`, `--alg xxh3`, `H_ALG=xxh3`).
- Rejected: a parallel XXH3 construction over block digests (xxh3p; custom, non-standard, no practical gain since verify is IO/network-bound); md5 (no compat need: committed result files are history and never re-verified; ~100x slower than the alternatives; a silent md5 fallback would hide a missing tool).
- `croit-flashstore-tool b3sum [--blake3|--xxh3|--alg A] [-c] [--time] FILE...|-` and `--bench [--mb N]`: output `<hex>  <name>`, `-c` like `md5sum -c`. Names with `\` or a newline are escaped as in b3sum/xxhsum (leading `\`, `\\`, `\n`); `-c` decodes that and rejects any other escape.
- `oprobe hash`: per-object digest + one combined digest = BLAKE3 over, sorted by name (ties by data length, then digest, so duplicates never depend on arrival order), (u32le len(name), name, u64le len(data), u8 len(digest), digest): equal across clusters holding the same data. Objects: pgnls listing (default namespace), `--names`, or `--image` (names `rbd-obj-<n>`, absent objects skipped).
- Lab scripts (`lab/lib/hash.sh`, sourced by common.sh): host `h_sum|h_file|h_check|h_pool` use `croit-flashstore-tool`/`oprobe` found on PATH, `$BIN_VOL`, /opt/croit-flashstore-osd/bin ...; a missing tool is a hard error (rc 127, message; a failing sum prints a unique token so two failed sums never compare equal). No fallback.
- Docker suites: `h_ctr CTR...` docker-cp's the host `croit-flashstore-tool` plus a wrapper `hsum` (alg baked in) into the containers (needs glibc >= 2.38; ceph v21 images have 2.39); in-container code calls `hsum` exactly like md5sum (stdin, files, `-c`). `R`/`CL`/`x` install lazily when the command mentions `hsum`; load generators install at `load_start`.
