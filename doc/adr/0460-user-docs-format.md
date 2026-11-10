# 0460 User-facing docs: location, structure, rules
Status: accepted
Date: 2026-10-19
Context: The project has agent-oriented docs in `doc/` (status, ADRs, specs, lab notes). Operators need separate, task-oriented docs. Without a fixed format, pages drift, mix project status into instructions and lack source checks.

Decision:
- Location: `docs/` at repo root, separate from `doc/`. `doc/` stays for agents and project tracking. `docs/` is for operators and is the only tree shipped as user documentation.
- Structure: Diátaxis, one directory per kind: `tutorials/` (one guided path), `how-to/` (one task each), `reference/` (exhaustive lookup), `explanation/` (why, trade-offs). `docs/README.md` is the index and states scope.
- Release branches: the manual lives on each release branch and describes that branch's Ceph release. Readers pick the branch that matches their cluster (`explanation/branches-and-versions.md`). Rule for future branches: each release branch carries the same `docs/` tree, copied from main when the branch is cut. `main` is the current release (v21.1.2). `v20.2.4` is a 1:1 copy of main's code today; its `docs/` tree is not there yet and is added by copy when the manual is merged to main.
- Facts: every command, flag, option, default, exit code, path and version in `docs/` is checked against the code of the branch it describes (source, `--help` or a test). Unverified claims are not written. A claim that is verified only for part of the surface is stated as that part.
- Content limits: no open questions, verification status, lab names, host names, IPs, VMIDs, MACs, PCI addresses, benchmark results or internal ADR and spec references in `docs/`. Those belong in `doc/`. Pages may link to other `docs/` pages only.
- Machine output: documented commands use the output flags the tool implements (`--format plain|json|json-pretty` for `croit-flashstore-tool`, `croit-flashstore-osd --check` and `ceph tell`; `jsonl` for record streams; `--json` is rejected by crate outfmt). Do not document a flag a tool does not accept.
- Network guidance: kernel TCP only (adr 0053). AF_XDP is deprecated and DPDK parked (adr 0020, adr 0005 am. 2): neither is recommended or documented as an operator option.
- License: `docs/**/*.md` is CC-BY-SA-4.0 (ADR 0164, `COPYING` path `*.md`). Contributors and authors are humans only (ADR 0164).
- Checks: `docs/` must pass (a) a relative-link check and (b) `scripts/check-private.sh`. Both must pass before a commit. (b) exists. (a) is a manual loop until a script is added (see Open).

Consequences:
+ Operators get the same layout on every branch; a page can be found by its type.
+ Readers cannot land on a page for the wrong Ceph release without a visible branch note.
- Each release branch must be kept in sync with main's `docs/` tree by copy. Forgetting this gives stale pages.
- Fact checking costs time per page; a page is not merged without its checks.

Alternatives: keep one tree in `doc/` (rejected: mixes operator and agent content); a separate docs repository (rejected: the docs must match the branch's code and move with it).

Open: a script for the link check does not exist yet; until it is added the check is manual.
