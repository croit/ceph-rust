<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0465 host-tune: operator helper that applies hwcheck's host fixes on request

Status: accepted
Date: 2026-10-19
Amends: 0464 (NIC state host-owned: the helper is the explicit-request path)

## Context

The OSD self-tunes what it owns and only warns, with the exact command, about host settings it does not own (GRO-hw, rings, IRQ affinity, sysctls, zcrx NIC state; AGENTS.md "runs optimally out of the box", adr 0464). Operators then copy about 50 hwcheck fix texts by hand. The user decided 2026-10-19: a separate operator helper applies exactly those commands when asked.

## Decision

- `croit-flashstore-tool host-tune` (engine: `hwcheck::tune`, actions: `hwcheck::action`) applies the mechanically applicable host fixes of hwcheck. The OSD never runs it and never changes the host.
- Source of truth = hwcheck. A mechanical fix is a structured `Action` (list of `Step`s: sysctl, sysfs write, ethtool features/rings/channels/tcp-data-split/RSS/flow rules, link flags, governor, mount, modprobe, IRQ affinity). `Check::act` renders the `fix` text from the action's commands; the printed warning and the executed command are the same data. Fixes that are not mechanical (BIOS, kernel cmdline, hardware, conf edits) carry no action and are listed as `manual`.
- Dry run is the default: per action the current value, the target and the command. `--apply` runs pending steps, records the operations that restore each prior value in a state file (default `/run/croit-flashstore-osd/host-tune-<unixtime>.json`, path printed), re-runs hwcheck and reports a verdict per action (`ok`, `not-ok`, `failed`). `--revert STATEFILE` replays the recorded operations last to first.
- Idempotent: a step whose current value already satisfies the target is skipped (`ok`).
- Selection: `--check ID` (exact id or dotted prefix, repeatable), `--iface IF` (limits interface-bound steps; global sysctl/THP steps stay).
- zcrx (adr 0464, spec knet-zcrx.md section 5): `--iface IF --zcrx-queues K --host-queues M --osd-port P...` adds the action `net.IF.zcrx`: `-G tcp-data-split on`, `-K ntuple on`, `-L combined M+K`, `-X equal M`, one RSS context over queues M..M+K-1 and one `tcp4 dst-port` rule per port. Marked `zcrx` in the output.
- Privileges: `--apply` and `--revert` need root, or CAP_NET_ADMIN + CAP_SYS_ADMIN + CAP_DAC_OVERRIDE; otherwise exit 3 with the requirement named, nothing changed. Dry run needs none.
- Exit codes: 0 ok (a dry run is ok), 1 a step failed or a re-run check is still not ok, 2 usage, 3 privileges. `--format plain|json|json-pretty`.
- Revert limits: the VF-hygiene fix (`promisc off allmulticast off`) is one-way; RSS indirection reverts to the driver default (`-X default`), the prior table is not reproducible by a command.
- Persistence is out of scope for the apply: runtime only. `--emit-persist` prints what a persistent setup needs (sysctl.d lines, modules-load.d, fstab, a oneshot unit that re-runs the same idempotent `--apply` at boot); the tool installs nothing.

## Rationale

- Rendering the fix text from the action removes duplicated command strings; an applied change cannot drift from the printed advice.
- A state file with ready-made undo operations makes revert independent of re-deriving steps, and survives partial failures (written after every step).
- Probing the current value through the same commands (`ethtool -k/-g/-l/-x/-n`, sysfs, procfs) keeps dry run, apply and verification consistent.

## Consequences

- + One command applies the host contract; the OSD stays free of host changes.
- + Unit tests use a fake command runner and the fixture root (plan, apply, revert, idempotency, failure); static dispatch, no trait objects.
- - Needs `ethtool`, `ip`, `sysctl`, `cpupower`, `mount`, `modprobe` on the host for the respective steps; a missing tool fails that step with a clear message.
- - Without persistence a reboot undoes the changes; irqbalance may undo IRQ pinning (the note says how to ban the cores).

## Alternatives

- OSD applies the settings itself: rejected (adr 0464, shared host state).
- A shell script generated from the fix text: rejected, no state/revert, duplicated strings.
- Installing the persistence: deferred, needs a decision on the owning mechanism (unit vs systemd-networkd vs distro tooling).

## Open questions

- Persistence form (udev rule / systemd unit / networkd `.link`) and who installs it. Also in doc/90-open-questions.md (77f).
- `tcp6` rules for the zcrx flow rules (spec lists tcp4 only).
- Per-driver capability limits (`-X context`, `-N ... context`, `tcp-data-split`) are only proven by a live run on a given NIC; not verified on bnxt/mlx5 here (live test used virtio: offload + rings).
