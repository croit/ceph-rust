# 0674 FlashStore: product, process and store names

Status: accepted
Date: 2026-11-06
Amends: 0019

## Context

The OSD and its store carried the working name nvmeosd. The product name is FlashStore (store) and croit-flashstore-osd
(daemon), analogous to BlueStore / ceph-osd. Stock Ceph v20/v21 monitors key behaviour on `osd_objectstore == "bluestore"`
in the OSD metadata (e.g. `allow_ec_overwrites`, OSDMonitor `get_osd_objectstore_type`); a different value breaks pools
and health checks on an unpatched mon. All existing deployments are test clusters.

## Decision

- Store = FlashStore; daemon binary, RPM and systemd unit = `croit-flashstore-osd` (`croit-flashstore-osd@<id>`);
  operator tool = `croit-flashstore-tool`; prep/container units `croit-flashstore-prep@`, `croit-flashstore-ctr@`;
  client lib packages `librustyrados`, `librustyrbd` (renamed from `croit-flashstore-librados` / `croit-flashstore-librbd`, adr 0589 am. 4).
- Config keys `nvmeosd_*` are renamed to `flashstore_*` without aliases; env vars `NVMEOSD_*` -> `FLASHSTORE_*`;
  OSD metadata `nvmeosd_*` -> `flashstore_*`; Rust identifiers follow.
- On-disk superblock magic `NVMEOSD1` -> `FLSTORE1`. No upgrade path: a device with the old magic reads as not formatted;
  the OSD refuses to start ("store has no superblock (run mkfs)"), `prepare` / `mkfs` refuse it as a used device,
  `--wipe` re-creates it (adr 0655 am. 1).
- Toward mon/mgr the OSD reports `osd_objectstore = bluestore` (and BlueStore-named perf group, tell commands, bdev
  metadata keys, health codes) by default. Option `flashstore_report_objectstore` (`bluestore` default | `flashstore`,
  read at startup) switches all of these to FlashStore names; `flashstore` is only for a mon patched to accept it.
  Ceph's own `bluestore_*` config keys are honoured unchanged in both modes.
- Host paths: `/opt/croit-flashstore-osd`, `/run/croit-flashstore-osd`, `/var/lib/croit-flashstore-{lab,test,kvm,...}`,
  `/srv/croit-flashstore-osd` (build host). `lab/host-migrate-flashstore.sh` links the new names to existing old
  directories on our lab/build/runner hosts (nothing moves; old and new script generations share locks and targets);
  `--cutover`, run when the rename lands on main, moves lab VM boot objects (guest prep unit, policy-route script) and
  renames volume-free lab containers (`nvmeosd-lab-mon` -> `croit-flashstore-lab-mon`) under the host's bench lock.
  Volume-backed docker reference labs are rebuilt, not migrated.
- Hypervisor objects keep their names: lab VM names, VF units/scripts (`nvmeosd-vf`, `nvmeosd-vfs`) and the PVE CPU model
  `nvmeosd-invtsc` (renaming them would change production hypervisor config).
- The rename is produced by `scripts/rename-flashstore.sh` (deterministic, idempotent, `--check`); branches forked before
  it run the script on their tree before rebasing. Repo name `ceph-rust` and crate `crates/nvme` (NVMe driver) keep
  their names; `testdata/` captures are untouched.
- Linux truncates the process name (`/proc/PID/comm`) to 15 bytes: both binaries show as `croit-flashstor`. Scripts
  match that comm value or the cmdline; `pidof croit-flashstore-osd` works (argv0).

## Rationale

The mon contract forces `bluestore` on stock clusters; an opt-in option lets a patched mon show the true store name
without a second binary. No production deployments exist, so a hard rename (keys, magic) costs nothing and avoids
carrying aliases and a format upgrade for a name only. The name-collision risk was accepted by the user.

## Consequences

- + One consistent product name in binary, packages, units, config, metadata and docs.
- + Default mode is wire- and mon-identical to before.
- - Existing test-cluster devices must be re-created (old magic refused); old `nvmeosd_*` settings in ceph.conf or the
  mon config db are ignored as unknown keys and must be re-set under `flashstore_*`; an old `--nvmeosd-*` command-line
  flag is a usage error (start refused).
- - 15-byte comm truncation makes both binaries indistinguishable by comm; distinguish by cmdline.
- - Old-generation worktrees use the old host paths until they rebase; the host links keep them on shared locks.

## Alternatives

- Keep `NVMEOSD1` magic: rejected, no deployments to preserve; one clean name.
- Alias old config keys: rejected, test clusters only; aliases would be permanent dead weight.
- Report `flashstore` to the mon by default: rejected, breaks stock mons.
