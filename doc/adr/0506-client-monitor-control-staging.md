<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0506 Compatible monitor control retains work across native staging pressure

Status: accepted
Date: 2026-10-22

## Context

The FFI monitor controller directly exposes finite snapshot, statistics, map and
command owner credit as EAGAIN. Snapshot retained-byte admission also permanently
rejects a sole larger request. The own contract is
compatible-monitor-control-admission.md; strict native constructors remain useful
for callers explicitly selecting bounded policies.

## Decision

- Keep separate FIFO admission lanes for snapshots/pool control, map waits,
  monitor commands and statistics. Manager and OSD/PG commands have independent
  FIFO owners using the same admission queue. Cluster/pool statistics share one FIFO because
  they share native credits; neither query type can monopolize freed slots. Retain owned input, original
  deadline and delivery across native NoCredit; other errors complete normally.
- Detached command callers receive admission only after native ownership; queued
  async deliveries retain their completion tickets. Never replay accepted work.
- Observe every queued deadline, including behind a blocked head, with a loud
  timeout. Closing settles all queued deliveries once. Integrate queue readiness
  and original deadlines into the existing event-driven worker sleep.
- Snapshot compatible construction treats retained bytes as a target and admits
  a sole over-target request. Exact finite native slots and completion-held
  charges remain. Every runtime owner forwards the explicit compatible method.
- Strict native constructor behavior and genuine wire/representation validation
  remain separate. Work quanta and initial capacities are not application limits.

## Rationale

An internal owner slot is temporary staging, not an API eligibility constraint.
Independent lanes preserve unrelated control progress; retaining returned input
avoids copying or losing the accepted request's identity and context.

## Consequences

- Queued work consumes actual memory until admission, timeout or close; real
  allocation failure is ENOMEM. No larger fixed limit or retry timer is added.
- C/C++, sync/async and kernel/io_uring/RDMA share controller/native ownership.
  DPDK forwards the same compatible construction and remains compile-only.
- Native named-manager rejections return the owned target name with the request;
  retry preserves both allocations and the captured route. Other representation
  limits remain tracked in G16.

## Alternatives

- Return EAGAIN or increase fixed limits: exposes/moves an internal staging bound.
- A single global FIFO: can block independent control domains behind one owner.
