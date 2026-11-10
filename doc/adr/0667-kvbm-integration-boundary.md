<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0667 KVBM integration: the mapping contract, not the KVBM runtime

Status: proposed
Date: 2026-11-05

## Context

KVBM (ai-dynamo) is an application-side KV-cache runtime with connectors for
inference frameworks; it moves blocks over NIXL and needs object storage behind
it. croit-flashstore-osd provides that storage (adr 0665: source-pull PUT, placement READ).
No GPU is available yet (host mock only, P1/P2 evidence), so a real KVBM or
inference server cannot run in this lab.

The question this decision answers: is "KVBM integration" the KVBM runtime
embedded here, or the contract a KVBM deployment uses?

## Decision

- The KVBM integration contract is the NIXL storage backend
  (`contrib/nixl`, `croit_flashstore`, plugin API v3) plus the key/offset
  mapping in `contrib/nixl/kvbm_mapping`: one object per KV block, key
  `<prefix>/<model>/<hash>`, one layer per block offset, one NIXL request per
  block with one local/remote pair per layer.
- The KVBM runtime (dynamo, vLLM/TensorRT-LLM connectors) is not vendored,
  linked or executed in this repository. Its deployment uses the plugin
  unchanged.
- `lab/nixl/get-smoke.cpp` is the conformance test for that contract: it issues
  exactly the request shape a KVBM storage connector produces and verifies the
  bytes in both directions.
- When GPU hardware exists, acceptance is an unmodified KVBM deployment that
  loads and stores blocks through the plugin; the mapping module is re-checked
  against KVBM's key layout and changed only where that layout differs (with a
  versioned key change).

## Rationale

The OSD-side work (READ placement, source-pull PUT, object layout) is the part
only croit-flashstore-osd can own; KVBM's runtime is application code that drags a Python and
GPU stack into the lab and cannot run without the hardware that is still
missing. Emulating the exact NIXL request shape keeps the contract verifiable
today (bare-metal evidence: KVBM load 4 MiB `matched:true`, store
`verify_nixl:true`) without claiming an inference server was run.

Trade-off accepted: the contract is verified against a faithful emulation, not
against KVBM itself, until hardware arrives.

## Consequences

- + The storage contract is verifiable on every commit, on real RDMA and NVMe,
  without a GPU or an inference stack.
- + No KVBM code is vendored, so no out-of-tree ABI to track.
- - A KVBM key-layout change would only surface at hardware integration time;
  the mapping module is the single place to adapt.
- - "KVBM integration" in a report means contract plus conformance test, and
  must be stated that way.

## Alternatives

- Vendor and build the KVBM runtime here: rejected, it needs GPU hardware and a
  Python inference stack, and would test the wrong layer.
- Skip the NIXL plugin and expose only the C ABI: rejected, NIXL is the
  interface a KVBM deployment actually uses (adr 0665).

## Open questions

- Does the KVBM storage connector keep one object per block, or one object per
  layer, in current releases? Confirm at the first hardware integration.
