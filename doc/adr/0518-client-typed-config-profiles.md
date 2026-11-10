<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0518 Client configuration uses complete typed reference profiles and raw values

Status: accepted
Date: 2026-10-22

## Context

The FFI currently knows only worker-consumed configuration keys and stores UTF-8
strings. Both pinned versions expose complete typed process-wide schemas with
version-specific names/defaults and byte-string values. Own source contracts are
config-public-contract.md, config-option-validators.md and config-value-engine.md;
versioned fact tables and offline reference observations accompany them.

## Decision

- Use immutable per-reference schema descriptors with type/bound/enum/flag and
  default metadata; store caller values as bytes and validate before mutation.
- Default artifacts select v21.2.0; the ceph-v20-2-4 build feature selects the
  v20.2.4 schema. Keep per-version artifacts/manifests/evidence as ADR0306 requires.
- Keep raw string/Unix path bytes, typed canonical getters, normalized priority,
  shared context identity and reference-compatible runtime mutability/effects.
- Fix duplicate name-list addition, nonce overflow, metadata prefix loss and
  inconsistent unsigned priority bounds as
  config-value-engine.md specifies. Record observable corrections under ADR0256;
  do not copy those reference defects merely for parity.
- Configuration aliases return validation/missing-argument errors to the caller
  rather than aborting/exiting the hosting application (ADR0256; former ADR0275, c-abi-ops.md (doc not in the source snapshot)). Explicit
  show_conf remains a requested dump/exit action, separately implemented.
- Keep parsed-file display and effective values consistent after failed file
  loads: preserve the last successful model; qualifying reference failure-state
  differences requires the isolated ingest oracle.
- Do not infer foreign C++ context layouts from this descriptor table; G09 owns
  the independently proved physical ABI and ownership integration.

## Rationale

A small whitelist cannot satisfy supported librados configuration or unchanged
consumers. Descriptors separate cold schema facts from active client behavior.
Different schemas require explicit artifact selection; raw strings avoid losing
valid C/Unix input. Correct set/identity/expansion semantics prevent silent changes
to features, target identity or credential paths.

## Consequences

- More supported keys and complete type validation; descriptor initialization is
  cold and shared rather than repeated on request dispatch.
- Byte-oriented consumers require explicit text conversion only for their actual
  grammar. Non-runtime mutation and observer updates need connected evidence.
- Unit/offline observations remain distinct from unrun live qualifications.

## Alternatives

- Increase the key whitelist: leaves the same structural gap.
- Merge both versions' defaults/names: invents a configuration contract.
- Lossy UTF-8 conversion or duplicate raw/text stores: loses or splits ownership.

The offline ingest oracle (config-ingest-observations.md) confirms the file-model
atomicity correction: both reference versions partially replace the diagnostic
model on a syntax failure while effective values remain unchanged. Native keeps
the last successful model; invalid UTF8, missing files and successful projections
match the observed reference vectors. Named-environment cache behavior is also
observed independently for both profiles.
