<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0505 Monitor configuration precedes client context finalization

Status: accepted
Date: 2026-10-22

## Context

Stock librados applies a complete monitor configuration through a temporary
monitor before finalizing its shared context and constructing operational state.
The current adapter skips this stage and finalizes only after full readiness.

## Decision

Reuse Bootstrap with an explicit configuration-only purpose and the existing
transport driver. Capture monmap/FSID and complete config before finalization.
Apply typed MON-level replacement and finalize the shared context monotonically;
then capture operational resources and start the ordinary worker. Expose ordered
runtime config snapshots through the same value engine. Keep strict native
bootstrap composition unchanged. Model temporary authentication and configuration
wait phases separately, including the source-derived ten wait-expiry attempts.
Use explicit unbounded authentication rather than a substitute large timeout.
Finite representable hunt intervals use signed-nanosecond truncation; nonpositive
intervals expire immediately. Reject non-finite or unrepresentable intervals
with EINVAL rather than reproducing undefined floating-to-integer conversion.
Concurrent connects use explicit per-handle state outside network-held mutexes.
A completed failed bootstrap permits retry instead of reproducing the reference's
stuck CONNECTING state, as permitted by ADR0256.

## Rationale

The configuration boundary affects credentials, admission resources, setters and
shared-context behavior. Reusing the coordinator preserves stream identity,
transport siblings and readiness validation without a second protocol engine.

## Consequences

- + Operational construction observes the monitor-supplied effective values.
- + Finish-state behavior remains correct on failures before and after bootstrap.
- + Runtime updates preserve priority slots and captured in-flight semantics.
- - Temporary and operational phases require independent failure/ownership gates.
- + No legacy service-thread structure is reproduced.

## Alternatives

- Finalize only after Ready: makes late failures expose the wrong setter rules.
- Apply only getters lazily: leaves operational captures and observers stale.
- Hold worker lock across bootstrap: hides concurrent CONNECTING behavior.

## Open questions

None for this composition; foreign-context physical ABI proof remains separately
tracked and is not qualified by native configuration lifecycle tests.

## Amendment 1 (2026-11-06): bounded runtime snapshot retention

Context: the ordered runtime snapshot queue grew without limit from monitor input
whenever a driver stopped draining it. A complete MConfig map is state, not an
event stream.

Decision: retain at most 64 snapshots and 8 MiB of them; on either bound drop the
oldest and keep the newest, so the applied state still converges. The loss is
reported once through `Bootstrap::take_monitor_config_error`
(`MonitorConfigError::Dropped`), and a retained snapshot or an unreported loss
keeps `can_sleep` false like any other pending result work. A single snapshot
larger than the whole byte budget is still retained as the newest state.

Consequences: + a non-draining driver cannot grow client memory from monitor
input, and the loss is explicit instead of silent; - an intermediate snapshot can
be missed by such a driver, which is observable only after it stopped draining.

Alternatives: unbounded queue (the defect); keep only the newest snapshot
(coalesce: no per-receive ordering, changes the public contract more than the
bound does).
