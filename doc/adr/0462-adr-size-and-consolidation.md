# 0462 ADRs state the current decision; large or heavily amended ADRs are consolidated

Status: accepted
Date: 2026-10-19
Supersedes: the forward-only practice (amendments appended, history not edited)

## Context

Amended-in-place ADRs grew to 15-280 KB (0021: 282 KB, 43 amendments; 0160, 0043, 0061: > 30 KB). Agents must read a whole ADR to learn the current rule, apply amendments in order and discard superseded text. Measurements and incident detail dominate the size.

## Decision

- An ADR states the current decision only. Measurements, derivations and incident detail live in doc/perf/, linked in one line.
- An ADR over 25 KB or with more than 8 amendment markers (headings containing "mend") is consolidated by the next change to it, instead of appending another amendment.
- Consolidation rewrites the ADR in place (same number, same file; history stays in git):
  - first line after the title block: `Consolidated YYYY-MM-DD; full pre-consolidation text: git show <sha>:<path>`;
  - current rules per the template layout; rejected options one line each under Alternatives;
  - measurements and history move to `doc/perf/adr-<NNNN>-history.md`, numbers and dates kept;
  - `## Amendment map` at the end, one line per old amendment: `am. N (date): <3-8 words> -> <section> | superseded by am. M | removed`, so existing "adr 0610 am. N" references stay resolvable.
- Below the limits, amendments may still be appended; each new one is a short rule change, never a measurement log.
- `scripts/check-adr.sh [--strict] [--format plain|json]` reports ADRs over the limits. `.githooks/pre-commit` runs it on staged ADRs as a warning; it never blocks.

## Rationale

The ADR is the single source of the current rule for agents. Git keeps history; the amendment map keeps references resolvable. Limits are counted by size and amendment markers because both are cheap to check mechanically.

## Consequences

+ Reading one ADR gives the current decision.
+ Token cost per ADR drops by up to an order of magnitude.
- Amendment-order history is no longer visible in the file; use the pre-consolidation sha.
- The 25 KB / 8 limits are heuristic; marker counting misses amendments not written as headings.

## Alternatives

- Keep forward-only amendments: unbounded growth, current rule scattered.
- Split amendments into separate ADR files: multiplies files, current rule still needs assembly.

## Open questions

- None. Resolved: 0061 (2026-10-19) and 0021 (2026-10-22) are consolidated.
