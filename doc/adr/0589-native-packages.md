<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0589 Native packages: .deb and .rpm of croit-flashstore-osd and the client libraries

Status: accepted
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): AF_XDP/DPDK packaging is history; the rest stays valid.
Date: 2026-10-25

## Context

Deployment of croit-flashstore-osd today copies binaries and systemd units by hand (doc/ops/deploy.md) or uses the
container image of adr 0052. Operators need installable native packages for the OSD and the client
libraries on the supported distros: Debian and Ubuntu (current LTS) and AlmaLinux 9/10. The client
libraries are the versioned `librados.so.2` of `lab/rados-client/package-elf.sh` (C + C++ ABI) and
`librbd.so.1` of `rbd-ffi`; both already carry the project's glibc floor of 2.34 (Alma 9) as a guarded
property, and the prod binaries run on the CS9 (glibc 2.34) e2e guests.

## Decision

- The project ships five native packages per distro: `croit-flashstore-osd` (daemon + `croit-flashstore-tool` + systemd units
  `croit-flashstore-osd@`/`croit-flashstore-prep@` + prep script + docs), `librustyrados`, `librustyrbd` (drop-in client
  libs, SONAME `librados.so.2` / `librbd.so.1`) and the `-dev` packages (link names + the `rustyrados/rdma.h`
  extension header). License: daemon LGPL-3.0-only, client libs MPL-2.0. Maintainer/author: croit GmbH.
- Coexistence with classic Ceph (no `Conflicts:`): the client libs are installed into a private directory
  (`/usr/lib/<multiarch>/croit-flashstore-osd` deb, `/usr/lib64/croit-flashstore-osd` rpm) and activated by
  `/etc/ld.so.conf.d/croit-flashstore-client.conf`, written by the postinst (%post) and removed by the postrm
  (%postun, erase only). While activated, apps linked against `-lrados`/`-lrbd` resolve this implementation
  while Ceph's own `librados2`/`librbd1` packages stay installed and functional (e.g. for classic daemons
  that use their own paths); `croit-flashstore-lib-ctl deactivate` (shipped in `librustyrados`) switches back at
  any time. No file collisions, no Ceph package is modified.
- The distro matrix is `debian-trixie`, `ubuntu-noble`, `ubuntu-resolute`, `alma9`, `alma10`; the
  architecture (amd64/arm64, x86_64/aarch64) is detected from the artifacts (`readelf -h`) — one artifact
  set per arch is packaged for every target; the glibc floor is 2.34 (Alma 9) and is asserted loudly on
  every ELF at package time (a violation fails the build).
- `scripts/package.sh --out <out> <artifacts-dir>.. [distro ..]` assembles the packages from the
  prebuilt artifacts (`bin/` + `libs/` of the CI build job); it is the single packaging entry point
  (deb via `dpkg-deb`, rpm via `rpmbuild` with generated specs). `lab/package-check.sh` replicates the
  CI `packages` job on the build host.
- The glibc floor holds by construction: the prod binaries and the client libs are compiled (C deps,
  cc) and final-linked against a sysroot from the pinned Alma 9 image (`almalinux:9`, digest pinned;
  glibc-devel + kernel-headers + elfutils-libelf-devel + numactl-devel + json-c-devel +
  libarchive-devel headers + gcc runtime; libnuma.so/libelf.so of the -devel packages are the dynamic link
  targets of the default link mode), built by one script, `lab/devcontainer/build-sysroot.sh`,
  inside that image: for CI as the dev image stage `sysroot` (`/opt/sysroot-ceph`, used by the `prod` and
  `libs` bake targets), on the build host as `/var/build/sysroot-ceph` (prepared once). RHEL ships no .a
  files, so the sysroot's static archives (z, zstd, numa, uuid, ssl, crypto, elf, bpf, xdp; numa
  and elf for the opt-in static mode) are built from source into it
  (`lab/devcontainer/build-sysroot-statics.sh`, pinned; libarchive is headers-only: SPDK compiles
  against it, the final link pulls no `archive_*`). The static rdma-core, DPDK and SPDK bundled into
  the artifacts are built against the same sysroot (dev image: `/opt/sysroot-ceph` → `/opt/rdma-core`,
  `/opt/dpdk`, `/opt/spdk`; build host: `/var/build/rdma-core-sysroot`, `/var/build/dpdk-sysroot`,
  `/var/build/spdk-sysroot`). The Ceph reference image is Alma 10 based (glibc 2.38) and the dev
  image's glibc is newer; without the sysroot their headers leak newer symbols (`__isoc23_*`) into
  the artifacts. `scripts/package.sh` fails on `__isoc23_*` references (the GLIBC version check alone
  would miss them in shared libs). The final link (and the sysroot-statics' link probes) run on clang:
   the gcc driver injects non-sysrooted -L host paths that beat --sysroot, so a gcc final link on a
   newer-glibc build host resolves host symbols (e.g. strlcpy@GLIBC_2.38) into the artifact.
- Licensing, one switch `FLASHSTORE_LGPL_LINK=dynamic|static` (`crates/dpdk-link/build.rs`, default
  `dynamic`):
  - LGPL-only components link against the distro's shared libs by default: libnuma (LGPL-2.1-only, via
    DPDK/SPDK EAL; `croit-flashstore-osd`, `croit-flashstore-tool`) and libelf (elfutils, GPL-2.0-or-later OR LGPL-3.0-or-later,
    via libbpf/AF_XDP; `croit-flashstore-osd`). Package deps from `DT_NEEDED`: deb `libnuma1`, `libelf1t64 | libelf1`;
    rpm `numactl-libs`, `elfutils-libelf` (sonames `libnuma.so.1`, `libelf.so.1` on all five targets).
  - Dual-licensed components stay static under the BSD choice: libbpf and libxdp (LGPL-2.1 OR BSD-2-Clause),
    rdma-core (GPL-2.0 OR Linux-OpenIB; per-file BSD-2/BSD-3/MIT/CC0 variants), zstd (BSD-3-Clause OR
    GPL-2.0). Permissive ones stay static: DPDK, SPDK, ISA-L (BSD-3-Clause), OpenSSL (Apache-2.0), zlib,
    libuuid (BSD-3-Clause). Not built, not linked: libnl (LGPL-2.1; rdma-core without netlink neighbour
    resolution), jansson and libpcap (hidden from the DPDK build's pkg-config, adr 0052 am. 9: only unused DPDK parts would use them). The GPL-3 `libeu` is
    not linked (no `eu_*` reference).
  - `--all-static` (`lab/package-check.sh --all-static`, `scripts/package.sh --all-static`) is the explicit
    opt-in for the previous fully static build (`FLASHSTORE_LGPL_LINK=static`): `DT_NEEDED` glibc only, no
    distro deps for libnuma/libelf, versions tagged `~static` (deb) / `.static` (rpm release) with the same
    package names (the two builds replace each other), and every package with a static LGPL-only component
    ships its exact pinned source tarball (`numactl-*.tar.gz`, `elfutils-*.tar.bz2`) and license texts plus
    a notice: which libs are static, where their source is, relinking needs the project source.
  - Third-party notices from evidence, not lists: `scripts/package-third-party.sh` (run after each build:
    `lab/package-check.sh`, the `prod`/`libs` bake targets) records per ELF the C components whose static
    archives alone define symbols (name + size) present in the ELF and the LGPL libs in `DT_NEEDED`, plus
    the run-time Rust crates of the build (`cargo tree -e normal,no-proc-macro`), with their license texts (the C trees
    install upstream texts into `share/licenses/<component>-<version>`). `scripts/package.sh` writes a DEP-5
    `/usr/share/doc/<pkg>/copyright` (deb) / `%license /usr/share/licenses/<pkg>/THIRD-PARTY-NOTICES` (rpm)
    with the texts, and the rpm `License:` becomes the SPDX expression of project + bundled components +
    crates.
  - Gates (`scripts/package.sh`): `DT_NEEDED` allow-list = glibc + gcc runtime, plus exactly
    `libnuma.so.1`/`libelf.so.1` in the default mode; an LGPL-only component linked static fails the
    default mode.
- The CI `build` job additionally bakes the `libs` target (`lab/e2e/image/libs.Containerfile`: the
  `package-elf.sh` librados package + `rbd-ffi` with profile `rados`), and the CI `packages` job
  (`.gitlab-ci.yml`) runs `scripts/package.sh` over the artifacts and publishes the `.deb`/`.rpm` files as
  job artifacts.
- Versioning: the package version is the pinned Ceph version of the branch (parsed from
  `lab/e2e/image/node.Containerfile`: 21.2.0 on main, 20.2.4 on v20) + the source commit, deb version
  `<ver>+git<sha12>`, rpm release `0+git<sha12>`; `PKG_VERSION` / `PKG_SHA12` override (a release tag drops
  the suffix).
- The `croit-flashstore-osd` package creates the system user `ceph` if absent and installs a `ceph-osd.target` fallback
  into `/etc/systemd/system` (removed on erase if unchanged) so `systemctl enable croit-flashstore-osd@N` works on
  flashstore-only hosts.
- `package-elf.sh` caps gain `RUSTYRADOS_PKG_TIMEOUT_SCALE` (positive integer, default 1): the CI bake sets it
  for the cold daemon cache of the first run; warm runs keep the qualification values.
- The `ceph` user/group get Ceph's fixed ids when free (rpm 167, deb 64045). The `ld.so.conf.d` entry is
  shared by both library packages and removed with the last one.
- `lab/package-install-check.sh [--all-static]` installs and removes the packages in pinned containers of
  all five targets (deps from the distro repos), checks the link mode (default: libnuma/libelf resolve to
  distro package files; static: none, tag + shipped sources), that every ELF loads (`ldd -r`), the notices,
  a C smoke program linked via the -dev link names calling `rados_version`/`rbd_version`, user, activation
  and removal.

## Rationale

glibc is backward compatible, so a single artifact set built against the 2.34 floor runs on every target
distro; per-distro compilation would multiply build cost without any compatibility gain. The floor is
enforced at build time (sysroot from the pinned reference image) and asserted at package time
(`scripts/package.sh`); the reference image is the sysroot source because it is the wire/ABI target
itself (Alma 9 base, glibc 2.34). The private
library directory makes the drop-in libs coexist with Ceph's `librados2`/`librbd1` on the same host:
`ld.so.conf.d` ordering puts our directory first for `-lrados`/`-lrbd` resolution, nothing in Ceph's
packages is overwritten, and the switch is reversible per host (operator choice). The package version
carries the pinned Ceph version because that is the wire/ABI target the packages promise; the commit hash
makes every artifact traceable to its source. Assembling (not building) packages in the CI job keeps the
long Rust builds in the cached bake targets and the packaging step fast and deterministic.
LGPL-only libs dynamic by default (user decision): the LGPL replace/relink right is met by the distro's own
shared library, nothing else to ship; the two libs exist under the same soname on all five targets. The BSD
choice keeps the dual-licensed libs static (no extra runtime deps). The fully static build stays available as
an explicit, visibly tagged opt-in for hosts that want glibc-only runtime deps; it carries its LGPL
obligations (sources + notice) inside the packages. Inventory from symbol/NEEDED/cargo-tree evidence keeps the
notices correct when the link set changes, without a hand-kept list.

## Consequences

- + Installable `apt`/`dnf`/`rpm` packages of the OSD and the client libs for the current LTS distros,
  built by the project pipeline (job artifacts, `dist/`).
- + Drop-in client libs coexist with classic Ceph on the same host: private lib dir + `ld.so.conf.d`
  activation, reversible via `croit-flashstore-lib-ctl`, no `Conflicts:`, no Ceph package modified.
- + The glibc floor, SONAMEs and self-containment (no DT_NEEDED on original Ceph libs) are asserted on
  every packaging run; a regression fails the pipeline.
- + `package-elf.sh` gains one documented environment variable (timeout scale), behavior unchanged at 1.
- + Every package carries its third-party notices and license texts; the rpm `License:` is an SPDX expression.
- - Default packages depend on the distro's libnuma and libelf packages. Builds outside the sysroot (lab
  binaries) also link them dynamically now: hosts running those need `libnuma1` and `libelf1t64`/`libelf1`.
- - Two artifact sets per source when the static opt-in is used (`~static` / `.static`); CI builds the default
  only.
- - Packages are unsigned job artifacts; no repository (apt/yum) hosting, no GPG signing, no changelogs
  yet (open questions).
- - aarch64 is wired repo-side (bake `PLATFORMS` variable, arch auto-detection in `scripts/package.sh`);
  the actual arm64 build needs an aarch64 buildkit daemon (infra, open question).
- - New CI job and bake target extend every E2E/MR pipeline by the libs build (cached) and the packaging
  step (~1 min).

## Alternatives

- Per-distro build images (one Rust build per glibc): rejected, multiplies build cost for a glibc that is
  already floored at 2.34 and guarded.
- cargo-dist as the packaging engine: rejected, it targets generic Rust crate distros; the package
  contents (systemd units, prep script, drop-in SONAMEs, distro matrix) are project-specific and clearer
  as a plain bash script.
- Shipping the container image only (adr 0052): rejected as the native path; operators asked for
  `apt`/`dnf` installs, and native units are the documented production deployment (doc/ops/deploy.md).

## Open questions

- Release mechanics: GPG signing + apt/yum repository hosting (e.g. `repo.croit.io`) and a versioning
  policy for `PKG_VERSION` (tag scheme) — needed before external distribution.
- aarch64: run the `PLATFORMS=linux/arm64` bake on an aarch64 buildkit daemon (infra) to produce the
  arm64 artifacts; repo-side (bake variable, arch detection, packaging) is done.
- Install-cell e2e on booted guests (systemd running, OSD start from the packaged unit); the container cell
  covers install/remove only.
- On upgrade the library postinst re-activates the libs even after `croit-flashstore-lib-ctl deactivate`.

## Amendment (2026-10-28): packages ship the prod profile (am. 1)
Decision: the native packages are built from the `prod` profile (knet, mimalloc, rdma; no DPDK/SPDK/AF_XDP libs). `lab/package-check.sh` and the CI `prod` bake target (`lab/e2e/image/prod.Containerfile`) build the prod feature set; `prod-full` (dpdk, spdk, xsk, mimalloc, knet, rdma) stays buildable for labs. The AF_XDP deprecation (0020 am. 9) and the DPDK parking (0005 am. 2) are what the prod link set reflects.
Consequences: the DPDK/SPDK sysroot caches leave `lab/package-check.sh`; the third-party inventory and the `DT_NEEDED`-derived package deps of the `croit-flashstore-osd` package regenerate from the prod build (doc/ops/packages.md).

## Amendment (2026-10-28): shared C++ compiler runtime (am. 2)
Normal client packages honor ADR 0309: the target supplies `libstdc++.so.6`, not a
bundled/static replacement. Inventory classifies this exact SONAME as system
compiler runtime; unknown dependencies still fail. Actual ELF dependencies add
`libstdc++6` (deb) or `libstdc++` (rpm). The library image checks required GLIBCXX
and CXXABI versions against its pinned Alma 9 sysroot provider, in addition to the
existing glibc floor gate. Five-distro install/load qualification remains required;
the SONAME alone proves no version compatibility. No permissive license claim or
runtime redistribution is implied. The glibc-only `--all-static` mode remains
fail-closed for shared libstdc++; enabling that combination needs a separate decision.

## Amendment (2026-11-02): packaged librados carries the C++ ABI, gated by stock imports (am. 3)
Stock `librbd.so.1`, `libradosstriper`, `librgw`, python `rados` and the Ceph CLIs import C++ functions and data
(`_ZTIN8librados7v14_2_09WatchCtx2E`, `..ObjectOperationE`) from `librados.so.2`. A C-only library makes them fail at
load time (`undefined symbol ... version LIBRADOS_14.2.0`). Decision: every x86_64 `librustyrados` package is built
with `RUSTYRADOS_CXX_ABI=1` (CI libs bake already; `lab/package-check.sh` now too, with the libstdc++ version check).
`scripts/check-rados-stock-imports.sh` compares the frozen import manifests `crates/rados-ffi/abi/stock-imports/v<ver>.txt`
(undefined `rados_*`/`@LIBRADOS_*` symbols of the stock x86_64 ELFs, both pins) with the library's dynamic exports;
`package-elf.sh` (C++ profile) and `scripts/package.sh` (x86_64) fail on a gap. aarch64 has no C++ profile: its package
cannot serve stock librbd (open). Stock librbd loads on our librados but image I/O is unsupported (neorados `RadosClient` layout, review Top 1), so `librustyrados` hard-requires `librustyrbd` of the exact same version (rpm `Requires`, deb `Depends`): our librbd is always activated with our librados; `croit-flashstore-osd` depends on neither. Evidence: doc/perf/rados-stock-librbd-2026-11-02.md.

## Amendment (2026-11-07): client packages renamed librustyrados / librustyrbd (am. 4)
Decision: the client library packages are `librustyrados`, `librustyrbd`, `librustyrados-dev`, `librustyrbd-dev` (were `croit-flashstore-librados[-dev]` / `croit-flashstore-librbd[-dev]`). `croit-flashstore-osd`, the tool `croit-flashstore-lib-ctl` (shipped in `librustyrados`), SONAMEs and crate names are unchanged. Reason: user naming decision 2026-11-06, client libs carry no croit/flashstore prefix (FlashStore = the object store only). The new packages replace the old ones: deb `Replaces:`+`Breaks:`, rpm `Obsoletes:`+`Provides:` on the old name (versionless, same version scheme).

## Amendment (2026-11-09): rdma.h C API in the client package, NIXL plugin package (am. 5)
Decision: the one `librustyrados` package carries the `rdma.h` extension C API. `lab/rados-client/package-elf.sh`
builds with `rados-ffi --features rdma,gpu` whenever RDMA is on (the default; `gpu` = `rdma` + `rados-rt/gpu`, verbs and
libc only, no CUDA) and exports exactly the `rdma.h` entry points (`rustyrados_rdma_provider_*`, `rustyrados_host_*`,
`rustyrados_gpu_*`, `rados_write_from_*`) plus the private provider entry in the `RUSTYRADOS_PRIVATE_1` version node.
They are not librados ABI: the export set is the explicit list in `package-elf.sh`, verified against the ELF, and the
frozen librados inventories keep their counts. Rationale: `librustyrados-dev` ships `rustyrados/rdma.h` and the
packaged library must implement the header it advertises; the GPU path has no separate package variant.
New package `croit-flashstore-nixl` (Apache-2.0, `contrib/nixl`): `libplugin_croit_flashstore.so` into
`$libdir/croit-flashstore-osd/nixl` (NIXL loads `<NIXL_PLUGIN_DIR>/libplugin_<name>.so`; not on the linker path),
`Requires`/`Depends` `librustyrados` of the same version. It is an optional artifact: `scripts/package.sh` builds the
package only when the artifact is present (loud note otherwise) and never builds it. `scripts/package.sh` gates the
plugin's `DT_NEEDED` set (C++ runtime + our own `librados.so.2`; no third-party component is linked; the plugin
references no abseil symbol, gated, so it loads into a NIXL built with any abseil), so the plugin needs no third-party inventory. The artifact is produced by the libs bake in a
stage of the pinned Alma 9 image (the package glibc/GLIBCXX floor) against the `librados.so.2` just built;
`lab/package-check.sh` builds the same artifact in the same image.
Consequences: the glibc-only `--all-static` mode rejects the plugin like the C++ client library (shared
`libstdc++`); the packaged extension API is versioned separately from `LIBRADOS_*`, so stock Ceph consumers never bind
it. Siblings: an aarch64 package has no C++ ABI but the same extension exports; `RUSTYRADOS_RDMA=0` keeps every
`rdma.h` entry point internal.
