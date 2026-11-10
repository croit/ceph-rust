<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0650 Crash dumps are private: directory 0700, files 0600

Status: accepted
Date: 2026-11-05

## Context

- On a panic and on a fatal signal the OSD writes `/var/lib/ceph/crash/<crash_id>/{meta,log,done}` for the host's
  `ceph-crash` agent (crash module, `ceph crash ls/info`).
- The directory was created `0755` and the files `0644`. A dump carries hostname, kernel, entity, assert text, stack
  and the last 400 log lines; the admin interface logs `config set <var> = <val>` and `injectargs` values, so a secret
  set through it could land in a world-readable file. A neighbouring container with the host crash directory mounted
  reads the same files.
- Crash dumps are written by the daemon user (`ceph`) and posted by the host agent, which runs as the same user or root.

## Decision

- Every dump directory is created `0700`, every dump file (`meta`, its `meta.tmp`, `log`, `done`) `0600`, both in the
  panic path and in the fatal-signal handler (which may only use async-signal-safe calls: `mkdir` / `open` modes).
- `meta` keeps its atomic `rename` of the `0600` temp file; `done` stays the last file written.
- `croit-flashstore-prep.sh` creates `/var/lib/ceph/crash` `0750` and resets its mode on every start (owner `ceph`), instead of
  `0755`.

## Rationale

- The content is diagnostic data about one daemon and needs no other reader. `0700`/`0600` matches the classic crash
  dump modes and keeps the agent working because it runs as the same user (root always reads them).
- The modes are set at creation, not with a later `chmod`, so a crash between creation and posting leaves no wide window.

## Consequences

- + No local user reads crash dumps, including log lines with admin-command values.
- - A host agent that runs as a different, unprivileged user needs a group/shared mode; that agent is not part of this
  deployment (root or `ceph`).
- Tests: `osd::crash::tests::dump_has_the_fields_the_crash_module_needs` and
  `fatal_signal_writes_a_dump_and_still_kills` assert directory `0700` and file `0600`.
- Siblings checked: the panic path and the signal path are the only dump writers; no core files (`LimitCORE=0`, unit).
