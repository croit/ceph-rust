<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0487 DPDK prefix carries a patch stamp; DPDK-linked builds refuse a prefix that lacks a repo patch

Status: accepted
Status note: Partly superseded by adr/0682-remove-afxdp-dpdk-networking.md (2026-11-06): DPDK as a network tier (the patched prefix stays for SPDK builds) is history; the rest stays valid.
Status note: Superseded in part by adr 0005 am. 2 (DPDK networking parked: code stays, no new work, no lab cells) and adr 0053 (knet default): DPDK wording below is history.
Date: 2026-10-22
Amends: 0052

## Context

The production DPDK (`/opt/dpdk` on the build host) is built by `lab/devcontainer/build-dpdk.sh` from `lab/devcontainer/dpdk-patches/*.patch`. Nothing tied a prefix to the patch set of a checkout. The prefix built 2026-10-12 (patch 0001) was never rebuilt after patch 0002 (AF_XDP tx checksum offload through XSK metadata) merged. Every prod binary from 2026-10-15 to 2026-10-22 ran AF_XDP with `caps tx_tcp_csum: false`: software tx checksums, 17.6 % of the busy core on 4M reads (doc/perf/afxdp-4m-20261022.md).

## Decision

- `build-dpdk.sh` writes `<prefix>/share/croit-flashstore-dpdk-patches.sha256`: sha256 of `dpdk-bnxt-fix.sh` and every applied patch.
- `lab/devcontainer/check-dpdk-patches.sh [prefix]` compares the stamp with the patch files of its own checkout. Missing stamp, missing patch, changed patch or a patch the checkout no longer has: exit 1 with the fix command.
- `lab/build-host-build.sh` runs it for every profile that links DPDK (all but lab, release, label, knet) and aborts the build on failure. Checkouts without the script skip the check.
- Prod gets a patch only by rebuilding `/opt/dpdk` with `build-dpdk.sh`; no second prefix.

## Rationale

A stamp of content hashes is the smallest check that cannot drift: it needs no version number to bump and catches a changed patch as well as a new one.

## Consequences

- + A stale prefix fails the build loudly instead of silently changing a performance tier.
- - After a patch change every DPDK-linked build waits for one `build-dpdk.sh` run (about 15 min) on the build host.
- - Prefixes built before the stamp (`/opt/dpdk.prev*`, `/opt/dpdk-xz`, ...) have no stamp and are not valid prod prefixes.

## Alternatives

- Version suffix in the prefix name: needs a manual bump per patch, catches nothing when forgotten.
- Rebuild DPDK inside every prod build: 15 min per build.

## Open questions

- The current `/opt/dpdk` on the build host has no stamp: it must be rebuilt once with `build-dpdk.sh` before the next DPDK-linked build passes. Who schedules the 15 min window (OQ 106)?
