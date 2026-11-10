<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# How to build and install the .deb and .rpm packages

croit-flashstore-osd ships as native packages for Debian 13 (trixie), Ubuntu 24.04 (noble) and 26.04 (resolute), and AlmaLinux 9 and 10. Rocky Linux and RHEL 9/10 use the AlmaLinux packages of the same major version. One build serves every distribution: the `prod` binaries need glibc 2.34 or newer and no other shared libraries (see [Runtime dependencies and licenses](#7-runtime-dependencies-and-licenses)).

| package | contents |
|---|---|
| `flashstore` (deb) / `croit-flashstore` (rpm) | `/usr/bin/croit-flashstore-osd`, `/usr/bin/croit-flashstore-tool`, systemd units `croit-flashstore-osd@.service` and `croit-flashstore-prep@.service`, `/usr/lib/tmpfiles.d/croit-flashstore-osd.conf` (shared lock dir `/run/croit-flashstore-osd`), `/usr/libexec/croit-flashstore-osd/croit-flashstore-prep.sh`, drop-in examples in `/usr/share/croit-flashstore-osd/`, docs in `/usr/share/doc/croit-flashstore-osd/` |
| `librustyrados` | the client library `librados.so.2` (C and C++ API) and the switch `croit-flashstore-lib-ctl` |
| `librustyrbd` | the client library `librbd.so.1` |
| `librustyrados-dev`, `librustyrbd-dev` | the link names `librados.so` / `librbd.so` and `rustyrados/rdma.h` |

The version is the Ceph release the branch targets plus the UTC commit time and the source commit, for example `21.2.0+git.20261031223000.1a2b3c4d5e6f` (deb) or `21.2.0-0.20261031223000.git1a2b3c4d5e6f.el9` (rpm). The commit time makes later builds sort newer, so `dnf upgrade` / `apt upgrade` pick them up; it also sorts newer than the older `+git<sha>` versions. The fully static build (section 7) adds `~static` (deb) or `.static` (rpm).

## 1. Get the packages

### From the GitHub release

Every source snapshot release of [croit/ceph-rust](https://github.com/croit/ceph-rust/releases) carries all packages as assets together with `sha256sums.txt`.

### Build them yourself

The distro packaging tooling (package build, packaging checks, install checks) is part of the private development repository and is **not included in the source snapshot**. The snapshot is sufficient to build the binaries and client libraries (`cargo build`, see the README), but not to produce the `.deb`/`.rpm` packages. Get the packages from the releases, or ask croit for a custom build.

Building the OSD with `FLASHSTORE_CEPH_VERSION` set (e.g. `FLASHSTORE_CEPH_VERSION=21.2.0_frontier0`) makes it report the cluster's Ceph package version string, so Ceph does not raise `DAEMON_OLD_VERSION`. The value is compiled into the binary. Unset or empty = the pinned release `21.2.0`.

## 2. Verify

Checksums:

```
cd dist && sha256sum -c sha256sums.txt
```

The packages are not signed yet. Compare the checksums with `sha256sums.txt` of the release.

The packaging process refuses to package a binary that needs a glibc newer than 2.34, that links a Ceph library, or whose library name is wrong. To check an installed binary yourself:

```
objdump -T /usr/bin/croit-flashstore-osd | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -n1   # must print GLIBC_2.34 or lower
readelf -d /usr/bin/croit-flashstore-osd | grep NEEDED       # libc, libm, libgcc_s, ld-linux
```

The packaging also refuses a binary that needs any other shared library. In the fully static build only libc, libm, libgcc_s and ld-linux are allowed.

## 3. Install

Debian / Ubuntu:

```
sudo apt install ./flashstore_*.deb                                      # OSD hosts
sudo apt install ./librustyrados_*.deb ./librustyrbd_*.deb      # client hosts
```

AlmaLinux / Rocky / RHEL (use the `el9` files on version 9, `el10` on version 10):

```
sudo dnf install ./croit-flashstore-21*.el9.x86_64.rpm
sudo dnf install ./librustyrados-21*.el9.x86_64.rpm ./librustyrbd-21*.el9.x86_64.rpm
```

Installing the package creates the system user and group `ceph` if they do not exist (id 167 on AlmaLinux, 64045 on Debian/Ubuntu, the ids Ceph uses, when free). If no `ceph-osd.target` exists, it installs a minimal one in `/etc/systemd/system/` so that `croit-flashstore-osd@N` can be enabled on hosts without classic Ceph. Removing the package removes that file again if you did not change it.

Then deploy the OSD as described in [first-osd](../tutorials/first-osd.md) and [prepare-and-activate](prepare-and-activate.md).


## 4. Configuration and units

| path | purpose |
|---|---|
| `/etc/ceph/<cluster>.conf` | cluster and OSD configuration (`[osd.N]` keys), see [configuration](../reference/configuration.md) |
| `/var/lib/ceph/osd/<cluster>-N/` | OSD data directory |
| `/etc/default/ceph`, `/etc/default/croit-flashstore-osd` | optional environment for the units (for example `CLUSTER=`) |
| `/usr/lib/systemd/system/croit-flashstore-osd@.service` | OSD unit, `systemctl enable --now croit-flashstore-osd@N` |
| `/usr/lib/systemd/system/croit-flashstore-prep@.service` | host preparation before each OSD start (pulled in by `croit-flashstore-osd@N`) |
| `/usr/lib/tmpfiles.d/croit-flashstore-osd.conf` | creates `/run/croit-flashstore-osd` (root:ceph 1770) at boot, the claim locks shared by daemon, tool and containers |
| `/etc/systemd/system/croit-flashstore-osd@.service.d/` | your drop-ins; start from the examples in `/usr/share/croit-flashstore-osd/` (CPU pinning, network tier) |

Package upgrades do not restart running OSDs. Restart them one at a time as in [upgrade-rolling](upgrade-rolling.md).

## 5. Client libraries next to the distribution's librados and librbd

The client libraries install into a private directory (`/usr/lib/<arch>-linux-gnu/croit-flashstore-osd/` on Debian/Ubuntu, `/usr/lib64/croit-flashstore-osd/` on AlmaLinux) and never replace files of the distribution's `librados2` and `librbd1` packages. Both can stay installed. Installing the packages activates the croit-flashstore-osd libraries: an entry in `/etc/ld.so.conf.d/croit-flashstore-client.conf` makes the dynamic linker pick them for every program linked against `librados.so.2` or `librbd.so.1`.

```
croit-flashstore-lib-ctl status              # which implementation each library resolves to
sudo croit-flashstore-lib-ctl deactivate     # use the distribution's libraries again
sudo croit-flashstore-lib-ctl activate       # use the croit-flashstore-osd libraries
```

`status` accepts `--format json`. Running programs keep the library they loaded; restart them after switching. A package upgrade activates the libraries again.

### Known limitations

- `rbd-mirror` has not been tested with these libraries and probably does not work with them. On hosts that run `rbd-mirror`, keep the distribution's libraries (`croit-flashstore-lib-ctl deactivate`).
- `librbd.so.1` provides the C API only; the C++ API is being added. Programs that use the librbd C++ API, such as the `rbd` command and `rbd-nbd`, need the distribution's libraries until then. QEMU and other C API users are not affected.
- Programs built on the Ceph common runtime that hand their own Ceph context to `librados.so.2`, such as the `rbd` and `rados` commands and `rbd-nbd`, are refused by these libraries until support for that context lands; use the distribution's libraries for them.

## 6. Upgrade and remove

Upgrade: install the newer files with the same `apt install` / `dnf install` command. Configuration and data are kept.

Remove:

```
sudo apt remove flashstore librustyrados librustyrbd               # Debian / Ubuntu
sudo dnf remove croit-flashstore librustyrados librustyrbd         # AlmaLinux / Rocky / RHEL
```

Stop and disable the OSDs first (`systemctl disable --now croit-flashstore-osd@N`). Removal keeps `/etc/ceph`, `/var/lib/ceph` and the `ceph` user. The library activation is removed with the last client library package.

## 7. Runtime dependencies and licenses

Build profiles: the packages are the `prod` build = kernel TCP, kernel NVMe, RDMA (no SPDK libraries; `prod-full` adds the SPDK storage tier).

The `prod` binaries contain the permissively licensed zlib and zstd and the dual-licensed rdma-core used under its BSD option; the DPDK (SPDK environment), SPDK, ISA-L, OpenSSL and libuuid components are linked only into the `prod-full` build, and the current packages link no other shared libraries. For the `prod-full` build (and the packages before the `prod` switch), the two LGPL-only libraries are used from the distribution:

| library | license | Debian / Ubuntu package | AlmaLinux / Rocky / RHEL package | used by |
|---|---|---|---|---|
| `libnuma.so.1` | LGPL-2.1-only | `libnuma1` | `numactl-libs` | `croit-flashstore-osd`, `croit-flashstore-tool` |
| `libelf.so.1` | GPL-2.0-or-later OR LGPL-3.0-or-later | `libelf1t64` (older: `libelf1`) | `elfutils-libelf` | `croit-flashstore-osd` |

Client libraries also use the system GCC C++ runtime (`libstdc++.so.6`):
`libstdc++6` on Debian/Ubuntu, `libstdc++` on AlmaLinux. Dependencies are generated
from each ELF. The build checks its GLIBCXX/CXXABI requirements against the pinned
Alma 9 provider; the runtime is not bundled or replaced with a static copy.

Every package lists all bundled components, the Rust crates and their licenses:

- Debian / Ubuntu: `/usr/share/doc/<package>/copyright` (machine-readable DEP-5 format), license texts in `/usr/share/doc/<package>/third-party/licenses/`, the inventory as `third-party/components.tsv` and `third-party/crates.tsv`.
- AlmaLinux / Rocky / RHEL: `rpm -q --qf '%{LICENSE}\n' <package>` (SPDX expression), `/usr/share/licenses/<package>/THIRD-PARTY-NOTICES` and the same `third-party/` directory there.

### Fully static build (opt-in)

For hosts that must not depend on any distribution library besides glibc, a fully static build is available on request (`--all-static`). The packaging checks that the artifacts really link libnuma and libelf statically and refuses default-build artifacts; without the switch it refuses static ones. The release pipeline builds the default only.

This glibc-only opt-in currently rejects the shared C++ runtime required by the
current client ABI; it is not a supported way to package those clients. Use the
normal build until that mode has a separately qualified runtime contract.

The packages keep their names and carry the `~static` / `.static` version tag, so the two builds of one commit replace each other on upgrade or downgrade and never install side by side.

License obligations of the static build: libnuma (LGPL-2.1) and libelf (LGPL-3.0) are linked into `croit-flashstore-osd` and `croit-flashstore-tool`. The packages ship the exact source tarballs of these two libraries (`/usr/share/doc/croit-flashstore-osd/lgpl-source/` on Debian/Ubuntu, `/usr/share/licenses/croit-flashstore-osd/lgpl-source/` on AlmaLinux), their license texts, and a notice in the copyright file naming the static libraries. Whoever distributes these packages must also make the source of this project for the same commit available, because relinking against a modified libnuma or libelf needs it. The default build has no such obligation for these two libraries. Minimized Ubuntu images (containers, minimal cloud images) exclude `/usr/share/doc/*` except the `copyright` file at install time; the sources and license texts stay inside the `.deb` (`dpkg-deb -c`).
