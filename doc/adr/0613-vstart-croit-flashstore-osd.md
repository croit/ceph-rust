<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Igor Fedotov, croit GmbH -->
# 0613 Repository-owned croit-flashstore-osd vstart entry point

Status: accepted
Date: 2026-10-28

## Context

Ceph's reference vstart has no backend provisioning extension hook.
The Ceph submodule is reference-only. Existing benchmark tooling already
bootstraps mon/mgr separately from croit-flashstore-osd preparation and startup.

## Decision

`lab/vstart.sh -n --croit-flashstore-osd` bootstraps mon/mgr using native vstart with zero
classic OSDs, then prepares and starts the requested croit-flashstore-osds.
Repeated device options capture the selected backend and optional first CPU.
The launcher restores the configured OSD count and corrects monitor pool defaults.
It checks prepared store identity against the new cluster before launch.
Restart reuses live monitors/managers and saved settings without preparation.
Owned PID/start-time tokens and a destination lock control process lifecycle.
OSDs use detached sessions and ignore terminal hangup so launcher exit does not stop them.
Creation and restart generate cluster-specific Ceph CLI and full-cluster stop scripts.
Native daemon shutdown verifies the PID's command line and cluster config path.
Stopping does not require completed store preparation or a valid state manifest.
Single-OSD lifecycle operations filter the saved IDs, PID cleanup and readiness
checks; startup failure cleanup stops only the selected OSD.
Setup clears inherited client config/keyring environment overrides so each daemon uses its own credentials.
MDS/FS/RGW count overrides are saved and provisioned after OSD readiness.
The launcher owns per-service credentials, foreground detached process tokens,
MDS registration/active-filesystem and RGW HTTP readiness. Nonzero MDS count
defaults to one CephFS filesystem, with an explicit FS=0 standby-only override.
MDS processes start before filesystem creation. Manager-backed setups use the
volumes module as native vstart does; manager-free setups create metadata/data
pools (bulk data) and the filesystem directly. Per-filesystem and shared
client.fs credentials are included in the client keyring.
Full reuse restarts saved services without provisioning; a selected OSD operation
preserves services. Full shutdown stops MDS/RGW before OSDs.
Other native options that require OSDs during bootstrap are rejected.
Without `--croit-flashstore-osd`, native arguments pass through unchanged.
Creation accepts `--omap-lsm` (alias `--flashstore-omap-lsm`), forwards it to
every prepare invocation and records the explicit choice. This creation-only
option is rejected on reuse/stop; mounting retains the on-disk engine.

## Rationale

This keeps integration code maintainable in ceph-rust without modifying or
copying Ceph source, and uses the existing provisioning tool for identity,
foreign-content checks, formatting and OSD directory creation.

## Consequences

- + Device modes are consistent across prepare, run and restart.
- + Mock tests cover creation, process ownership, failures and restart without hardware.
- - Restart requires live mon/mgr services and the repository entry point.
- - Shared SPDK controller primaries remain externally managed.
- - Bootstrap failures can leave mon/mgr services for inspection.

## Alternatives

- Modify the reference-only Ceph submodule: violates repository ownership rules.
- Select a daemon binary through config alone: cannot implement provisioning.
