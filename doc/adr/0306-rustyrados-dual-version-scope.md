# ADR0306: rustyrados v20.2.4 and v21.2.0 scope
Status: accepted. Date: 2026-10-17. Decider: user.

## Context
User adds v20.2.4 to the existing v21 client target (v21.1.2 at decision time; replaced by v21.2.0, user 2026-10-30, doc/compat/rustyrados-versions.md). Current public ABI
is required; historical aliases remain excluded by ADR0305. The server's
single pinned-version rule remains unchanged.

## Decision
Target both releases for rustyrados cluster communication and current public
C/C++ ABI. Keep immutable source identities, separate reference ELF manifests,
and explicit per-version qualification. Do not change the reference submodule.
Do not equate matching C declarations with binary or wire compatibility.

## Alternatives and consequences
Pin-only qualification would omit the requested installed-client/cluster target.
Dual-version qualification adds a bounded matrix and possible current C++ symbol
variants. Separate implementations are unnecessary unless verified differences
require them; prefer one implementation with explicit compatible encodings.
Neither release is declared fully qualified by accepting this scope.

## Action items
- Record header, symbol/version/layout and relevant protocol differences.
- Run unchanged consumers built against each reference with the replacement.
- Qualify each cluster version in CRC and Secure modes with own tests.
- Keep C++, foreign-context, platform and performance gates explicit.

Reference inventory: client version matrix (doc not in the source snapshot).
