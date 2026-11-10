<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0486 RDMA provider portability

Status: accepted
Date: 2026-10-22

## Context

The user requires NIC-vendor-independent placement wherever the required
operations exist. The RDMA build currently names six providers although the
selected static rdma-core installation contains more. A driver excluded at link
time cannot reach runtime capability probes. GPU hardware is in production and
will become available for qualification only after code preparation.

## Decision

- Link all providers compiled into the selected rdma-core installation through
  `RDMA_STATIC_PROVIDERS=all` and that installation's static pkg-config metadata.
- Bundle the native provider/core archives with the Rust library using standard
  Rust static-link metadata; the client package does not maintain another
  provider-name list.
- Use generic libibverbs and probe actual required operations; no provider-name
  or NIC-vendor allowlist controls eligibility.
- Retain ADR 0469's RoCEv2/RC scope. Broader provider linkage does not promise
  iWARP, InfiniBand or provider-specific transport support.
- Qualify GPU export, registration/MW compatibility and CUDA visibility separately
  from host registration. Do not access the production GPU during development.
- Stage only when the caller permits it; DirectOnly rejects unsupported paths
  before advertising memory.

## Rationale

rdma-core owns the provider set and native dependencies. Its `all` selector
avoids maintaining a second driver list. Actual operation results establish the
required semantics more directly than manufacturer identifiers.

## Consequences

- + New rdma-core providers need no application vendor-list change.
- + Unsupported capabilities remain explicit and cannot silently weaken access
  retirement or integrity requirements.
- - More native providers can increase binary size and linkage dependencies.
- - All-provider linkage and host tests do not establish GPU or hardware-wide
  functional/performance qualification.

## Alternatives

- Maintain a longer fixed list: repeats the same exclusion for future providers.
- Assume host registration qualifies GPU access: export, MR permissions and
  visibility differ and require separate evidence.
