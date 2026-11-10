<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0507 Compatible notify jobs retain prepared requests across staging pressure

Status: accepted
Date: 2026-10-22

## Context

The FFI compatible notify controller rejects jobs at its fixed16 population and
64 MiB request-retention target. Native NoCredit also terminates a job after its
handle is reserved. These are internal staging policies, outside the supported
librados notify contract (RC174 and compatible-notify-population.md).

## Decision

- Compatible notify population follows actual accepted caller work without an
  independent total retained-request ceiling. Strict profiles remain explicit.
- Prepare the typed notify request/context once. Retain both returned inputs on
  native NoCredit, preserving allocation, cookie, selector, flags and deadline.
- A reserved handle without native token/initial ID remains pending admission.
  Accepted initial requests are not automatically replayed while awaiting final.
- Session/watch staging pressure keeps the job live; the original deadline still
  governs it. No retry timer, increased constant or owner-thread blocking.
- Existing initial/final association, authenticated reply validation, initial
  version and once-only completion/callback ownership remain unchanged.

## Rationale

Temporary staging pressure must not become an application failure. Retaining a
prepared request avoids copying its payload or losing captured context while
preserving the underlying native owner's ordering and credit rules.

## Consequences

- More simultaneous jobs can retain more actual caller input and metadata;
  allocation failure remains a real ENOMEM path.
- Kernel TCP, io_uring and RDMA share the same controller. C/C++, sync/async keep
  their existing publication and completion adapters.
- Callback, ACK and native registry-event policies remain separate G14 work;
  this decision does not silently qualify those resource domains.

## Alternatives

- Increase16/64 MiB: preserves the same incompatibility at a new value.
- Rebuild on each rejected admission: copies payload or loses request context.
- Fail with EAGAIN: exposes an internal staging decision to the application.
