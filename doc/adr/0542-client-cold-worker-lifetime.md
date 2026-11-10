<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0542 Client cold workers remain owned until shutdown

Status: accepted
Date: 2026-10-25

## Context

Registration and provider setup publish results before their threads return.
Their JoinHandles were discarded. The receive-helper calibrator was detached
as well. Result publication therefore did not prove that library code stopped
executing; connected C tests kept the library loaded for the process lifetime.

## Decision

- Client registration budgets retain registration JoinHandles; carrier instances
  retain provider-setup JoinHandles; the initiating helper pool owns calibration.
- The calibration sender is scoped: early accept/read/clock errors close its
  sockets and join it before returning.
- Cold setup reaps finished handles. Result polling never waits for thread exit.
- Client destruction stops admission/transport and joins registration workers.
  Carrier/helper-pool destruction joins setup/calibration workers before their
  library-owned scope ends. Existing control/event/payload helper joins remain.
- Payload submission, CQ polling and READ result queries acquire no new locks,
  allocate no new tracking records and never join workers.
- Healthy C unload qualification requires all public handles and foreign owner
  callbacks retired before dlclose. Quarantine without owner return does not
  authorize unloading or freeing its backing.

## Rationale

Joining after result publication on the progress path would serialize unrelated
I/O. Tracking only control-plane jobs separates result readiness from executable
code lifetime, preserves asynchronous setup and bounds finished-handle retention
by cold-job churn. Shutdown must wait for owned workers instead of relying on
callback timing or delays before unloading.

## Consequences

- + Asynchronous completion publication and efficient idle are preserved.
- + Cold jobs have explicit shutdown owners; ordinary TCP calibration is covered.
- - Cold registration/setup and shutdown use tracking storage; no payload cost.
- - A provider operation still running can delay shutdown. No timeout may revoke
  its allocation, abort its thread or authorize dlclose while it executes.
- - Actual load/unload, pending setup/registration and platform evidence remains
  necessary; the ownership change alone is not release qualification.

## Alternatives

- Sleep after the last callback: elapsed time does not prove thread exit.
- Join during completion polling: can block progress after early publication.
- Permanently pin every healthy client library: avoids testing the actual boundary.

## Open questions

- Broader pending setup/registration scheduling and persistent caller TLS gates
  beyond the connected joined-caller Linux fixture.
- Fault/quarantine owner-return and code-lifetime qualification across providers.
- Platform-specific loader/TLS behavior beyond the joined Linux caller fixture.
