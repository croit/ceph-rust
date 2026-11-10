# 0164 License: LGPL, MPL client libraries, CC-BY-SA docs
Status: accepted, amended (am. 1, 2026-10-17; am. 2, 2026-10-19; am. 3, 2026-11-08)
Date: 2026-10-17
Supersedes: 0012.

Decision (user, 2026-10-17; am. 1 same day):
- MPL group = `MPL-2.0` (am. 1). Applies to the client libraries and everything they depend on, transitively. Full text: `COPYING-MPL-2.0`.
  - am. 0 had `LGPL-2.1-only OR LGPL-3.0-only` + self-written static-linking exception. Replaced by am. 1; the exception is removed.
- LGPL3 = `LGPL-3.0-only`. Applies to everything else: daemon `services/osd/*`, OSD-only crates, `tools/`, `lab/`, scripts, test data.
- Docs (`doc/**`, `*.md`) = `CC-BY-SA-4.0`. Code under `doc/` stays LGPL3.
- `ceph/` submodule: upstream license, untouched, never modified.
- Third-party DPDK patches (`lab/devcontainer/dpdk-patches/*`, `lab/proxmox/dpdk-bnxt-alias.patch`): BSD-3-Clause, not covered.
- NIXL plugin `contrib/nixl/*` (C++, the only C++ in the repo): `Apache-2.0` like NIXL itself, so it can go upstream (am. 3). Full text: `COPYING-APACHE-2.0`. Its README.md stays CC-BY-SA-4.0.

## Crate classification
The package's `Cargo.toml` `license` is the single source; `COPYING` must list exactly the MPL packages and `lab/relicense-headers.sh` takes each file's identifier from its package (am. 3).

| class | crates | count |
|---|---|---|
| MPL, client closure | cephx crc crush deadline denc ingress messages monc msgr2 opwire osdmap outfmt rados-ffi rados-rt rbd-ffi rdma rustyrados rustyrbd spsc | 19 |
| MPL, outside the closure | dpdk-link net (former client DPDK/AF_XDP paths, kept MPL); eal-heap slabcoll (shared building blocks of rt/OSD/MDS, MPL by choice) | 4 |
| LGPL3 | daemon-io ec hashsum hwcheck nvme rt uring-access, services/osd/{cls croit-flashstore-osd ecback ecwire opexec osd osddir peering pgwire replwire store storeadapt wprof}, services/mds/mds, tools/{benchrun croit-flashstore-tool dedup-search mds-fs oprobe ostool rdma-bench rdma-placement-probe} | 28 |

Client roots: `rustyrados rados-rt rados-ffi rbd-ffi rustyrbd`. An MPL crate must not depend on an LGPL3 crate; an LGPL3 crate may depend on MPL crates. Gate: `lab/rados-client/check-license-closure.sh` (all features, Linux metadata) checks that every internal package reachable from the client roots is MPL; 2026-11-08: 19 packages, exit 0; no MPL -> LGPL3 edge in the workspace.

A package's bins and examples inherit the package license (`net` ships `pingd`/`tcpecho` under MPL).

## Reasons
- Client libs need a license that Rust users can link statically without relink duties. Rust links statically by default, inlines across crates and has no stable ABI. LGPL relink duties are impractical there (am. 1).
- MPL-2.0 (am. 1): file-level copyleft. Changes to MPL files stay MPL. Combined works may be static and under other terms. Standard text, no self-written legal terms. Rust-ecosystem practice: gst-plugins-rs moved LGPL to MPL-2.0 for the same reason.
- GPL compatibility (am. 1): MPL-2.0 sec. 1.12 lists GPL-2.0, LGPL-2.1, AGPL-3.0 "or any later versions" as Secondary Licenses; sec. 3.3 lets a Larger Work combined with such code (incl. GPL-2.0-only, e.g. kernel tooling) distribute the MPL files under that license. So GPL-2.0-only projects can still use the client libs. Condition: never add the "Incompatible With Secondary Licenses" notice (Exhibit B).
- am. 0 reasons (superseded by am. 1): librados is LGPL-2.1, so embedders saw the same terms; static-linking exception gave Rust users the librados dynamic-link position.
- Daemon and tools under LGPL-3.0-only: copyleft on modifications, no GPL linking burden on OSD code.
- Docs under CC-BY-SA-4.0: standard for documentation.
- Deps must stay permissive (adr 0003, CLAUDE.md). Checked 2026-10-17 with `cargo metadata`: 92 registry deps, all permissive (MIT, Apache-2.0, BSD, ISC, Zlib, BSL-1.0, Unicode-3.0, 0BSD, CC0). Only `r-efi` is tri-licensed incl. LGPL-2.1-or-later; it is used under MIT or Apache-2.0.

## Header format (am. 3)
Every tracked source file (`.rs .c .h .cc .cpp .sh .awk .jq .pl .toml .yaml .yml .hcl .service`, Dockerfile/Containerfile, extensionless shebang scripts) starts with this leading block (line 2 after a shebang or `#cloud-config`):
```
// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
```
Identifier = the package's (`MPL-2.0`, `LGPL-3.0-only`, `Apache-2.0` for contrib/nixl). One contributor line per human author of the file, exactly as in AUTHORS.
Comment prefix `//` for `.rs`, `//` or a `/* ... * ...` block for C/C++, `#` otherwise. `//!` module docs follow directly. SPDX lines below the leading block (heredocs, embedded headers of generated scripts) are file content. Markdown: `<!-- ... -->` header lines optional (covered by `COPYING`); a contributor line there must also be an AUTHORS line.
`lab/relicense-headers.sh` checks and writes it (idempotent; `--check` report only, exit 1 on any violation; `--staged` = pre-commit on the staged content; `--selftest`). Write mode fixes the identifier, adds a missing copyright line, normalizes bare names to their AUTHORS line, drops AI-tool contributors and fills a missing contributor list from the file's git authors. Repo checks: AUTHORS has no AI tool, every contributor line is an AUTHORS line, COPYING's MPL stanza = MPL packages, `contrib/nixl/*` -> Apache-2.0.

## Rules for contributors
- Every new source file gets the header block above (pick the identifier by crate: MPL group vs LGPL3).
- When you change a file, add your own `SPDX-FileContributor:` line and add your name to `AUTHORS`.
- Contributors are humans only: a `SPDX-FileContributor:` line or `AUTHORS` entry names a person who is responsible for the change (croit GmbH or a named individual). AI assistants and tools (Codex, Claude, other LLMs, bots) are never listed, in headers, `AUTHORS`, docs or commits. Tools are not authors. (am. 2, 2026-10-19: 661 tracked files had an AI contributor line, removed.)
- Every tracked source file outside `ceph/` carries the header block; `lab/relicense-headers.sh --check` must exit 0 (`changed=0 repo_errors=0`) before a merge; the pre-commit hook runs `--staged`.
- New crate: set `license = "..."` in its `Cargo.toml` explicitly (no `license.workspace`); the workspace has no license field.
- New third-party dependency: must be permissive and compatible with the crate's class.

## Consequences
- `LICENSE` replaced by `COPYING` (DEP-5 style summary) + `COPYING-MPL-2.0`, `COPYING-LGPL3`, `COPYING-GPL3`, `COPYING-CC-BY-SA-4.0` (official texts from mozilla.org / gnu.org / creativecommons.org).
- am. 1: `COPYING-LGPL2.1` removed (no longer referenced; LGPL-2.1 is not a license of this repo). `COPYING-MPL-2.0` added.
- Cargo: `workspace.package.license` removed; every crate sets `license` explicitly.
- Former restrictive copyright notices replaced in all files.
- This ADR sets licenses only. Publication decisions (which repo, what goes public) are separate; push rule (origin only) unchanged.

## Amendment 1 (2026-10-17): client crate group MPL-2.0 instead of LGPL-2.1/3.0 + exception
- Client crate group (MPL class above): `MPL-2.0`. Replaces `LGPL-2.1-only OR LGPL-3.0-only` + static-linking exception. Reason: see Reasons.
- Changed: `Cargo.toml` license of the 12 crates; SPDX headers of all their files (`lab/relicense-headers.sh`, MPL list incl. `rustyrados rados-rt rados-ffi`); `COPYING` (group, exception removed); `COPYING-MPL-2.0` added; `COPYING-LGPL2.1` removed; CLAUDE.md, AGENTS.md, README.md, doc/README.md.
- Unchanged: LGPL3 group, docs CC-BY-SA-4.0, BSD-3 DPDK patches, `ceph/`.
- Rule check (am. 1): no MPL crate depends on an LGPL3 crate (ec, nvme, rt, services/osd/*, tools/*).

## Amendment 3 (2026-11-08): contributors per file, license from Cargo.toml
- Header contributors = the humans who wrote or changed the file (AUTHORS lines), not a fixed three-name block. The am. 1 script injected Martin Verges, Igor Fedotov and Mahamudur Rahaman Sajib into every file, which contradicted "add your own contributor line" and made `--check` report 1534 files. Existing three-name blocks stay.
- The file's identifier comes from its package's `Cargo.toml`; the hard-coded MPL list (missing `rbd-ffi rustyrbd eal-heap slabcoll`, so write mode would have flipped them to LGPL3) is gone. `COPYING` lists all 23 MPL packages, enforced by the script.
- Only the leading block is the header; the am. 1 script deleted SPDX lines anywhere, incl. heredoc headers of generated scripts.
- `contrib/nixl/*` Apache-2.0 recorded in `COPYING` (+ `COPYING-APACHE-2.0`).
- Pre-commit runs `lab/relicense-headers.sh --staged`.
