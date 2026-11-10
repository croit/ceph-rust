<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0598 Concrete metadata lifecycle ownership

Status: accepted
Date: 2026-10-26

## Context

TrashMove needs writable watched metadata and FULL ownership even when its
configured DATA pool is absent. The DATA writer intentionally requires real
DATA resources. ADR0579/0597 provide shared resource preparation and recovery.

## Decision

MetadataLifecycle owns a concrete MetadataImage, private provider contexts,
watched head and ImageOwner. It implements OwnerObservation and RecoveryDriver
and binds the existing WriterRecovery coordinator. It creates no DATA writer,
write lane, parent open or DATA operation. Only DATA binding ENOENT is tolerated:
the initial metadata-pool DATA clone is closed and its handle becomes invalid;
the configured DATA pool ID remains recorded. Other binding failures propagate.

TrashMove uses this temporary context for preparation and checks, retaining a
zero-status GENERAL block through close. Identity removal asserts the observed
ID-object version and the directory class checks both mappings. It persists
MOVING before unlink, attempts NORMAL normalization after either move result,
and emits the pinned trash notification only after successful normalization.

Present mirror registrations remain an explicit unsupported lifecycle case
until full snapshot/journal disable orchestration is available. This increment
does not qualify or implement permanent removal. Neither gap can be marked
closed from successful ordinary TrashMove. Owner feature transitions still need
a fresh context; dynamic transition support remains a separate open issue.
Plugin selection preserves raw configuration bytes and winning empty/NUL-prefix
image/pool values before considering global configuration, prior to watch
registration. Config lists share the same growing byte reader; required internal
options report ENOSYS rather than an image-like ENOENT when unavailable.
Native metadata builtins implement the parent-cache no-child and
PWL absent-DATA/disabled-mode skips without the reference's private C++ ABI.
Unknown ordinary names fail ENOSYS. Quoted/escaped lists and active PWL hooks
remain explicitly unsupported; dirty-cache hooks must never be silently skipped.
Full plugin/acquisition compatibility remains RBD-079. The bounded admission
boundary is qualified; ordinary gates do not qualify arbitrary plugins.

## Rationale

Concrete metadata resources avoid fabricated DATA handles and reuse actual
header/map ownership, retained cleanup, readiness and the same recovery engine.
Version assertion prevents deleting a replacement identity object, improving
the pinned reference's unconditional ID-object deletion race.

## Consequences

- + Metadata-only preparation remains independent of DATA availability.
- + NON_PRIMARY retains a watched read-only context without an effective
  exclusive-lock object; the feature bit alone never creates that resource.
- + Interrupted moves use the interoperable trash state and immutable ID.
- - Mirror disable, permanent removal and wider fault qualification remain.
- - Unrepresentable timestamp delays use deterministic saturated seconds;
  the pin's extreme floating-point conversion is not reproduced.

## Alternatives

- Optional DATA writer resources: weakens ordinary DATA admission invariants.
- Separate metadata recovery engine: duplicates authority/publication state.
- Delete mirror records alone: silently omits required durable cleanup.

## Open questions

Affected core/all five FFI profiles and bounded original/own live gates pass:
48 ordinary moves,104 plugin-byte cases,48 durable-state resumes,80 group/manual-
owner prechecks and16 identity/error-order controls, plus11 regression scopes.
See doc/perf/librbd-completeness-20261024.md for exact sources and evidence.
Real process-crash/authority/storage fault campaigns remain. Complete mirror
disable and permanent removal through the same lifecycle resources.
