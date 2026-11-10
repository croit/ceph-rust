<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0656 Privileged helper commands are resolved in a fixed system path, never through PATH

Status: accepted
Date: 2026-11-05

## Context

- `host-tune --apply` runs as root and spawns `sysctl`, `ethtool`, `ip`, `mount`, `modprobe`, `cpupower` and `umount`
  via `std::process::Command::new(<bare name>)`: the kernel resolves the name through the inherited `PATH`.
- The classic SMART route of the daemon spawns `sudo` the same way; a root-mode OSD (no-IOMMU/uio drop-in) would run a
  foreign binary as root if `PATH` (or a wrapper's environment) named one first.
- The commands themselves are fixed; only the lookup was open.

## Decision

- `hwcheck::action::ProcRunner` resolves a bare name in a fixed list of root-owned system directories
  (`hwcheck::action::SYSTEM_PATH`: `/run/wrappers/bin`, `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`,
  `/sbin`, `/bin`, `/run/current-system/sw/sbin`, `/run/current-system/sw/bin`). The NixOS entries (croit OS) exist only
  there and are root-owned; `/run/wrappers/bin` comes first because NixOS `sudo` is setuid only as that wrapper. The
  inherited `PATH` is not consulted; an absolute path is used as given, a relative path with a slash is refused.
- Children get a cleared environment with only `PATH` = that list, so an inherited `LD_PRELOAD`/`LD_LIBRARY_PATH` cannot
  follow a root helper either.
- The SMART route resolves `sudo` through the same list (`hwcheck::action::resolve`).

## Rationale

- The names are distribution commands; the FHS directories cover the Debian/RHEL family and the OCI image, the NixOS
  directories cover croit OS (no `/usr/bin` there). Resolving them in a fixed
  list keeps the environment of the caller (a wrapper, a root shell with `.`) out of the decision.
- `env_clear` closes the same class for the dynamic linker; none of the commands needs another inherited variable.

## Consequences

- + A poisoned `PATH` (or `LD_PRELOAD`) cannot make a root helper run a foreign binary.
- - A command installed elsewhere (for example `/opt/.../ethtool`) is not found; the error names the missing command, and
  the operator can use the printed manual command. Adding a directory to the list is a code change.
- Tests: `hwcheck::action::path_tests::root_commands_do_not_resolve_through_path` (a fake `hwcheck-fake-cmd` first in
  `PATH` does not run; the call reports it missing), `absolute_programs_are_taken_as_given_and_relative_slashes_refused`;
  `croit-flashstore-osd` `smartctl::tests::sudo_is_not_resolved_through_path` (a fake `sudo` in `PATH` does not run).
- Siblings checked: `crush_location_hook` executes an operator-configured program path from the conf (Ceph compat, not a
  bare name); build scripts (`pkg-config`, `git`) are not privileged helpers.
