<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->

# 0673 MDS owner composes level readiness and knet completion notifications

Status: accepted
Date: 2026-11-06

## Context

The first stock ceph-fuse lab run reported approximately 660 ms FE response delays aligned with periodic owner wakeups. The FE adapter submits knet SQEs at the end of every poll. KNet normally selects DEFER_TASKRUN: completion work can await the issuing thread's next kernel entry. Linux ring-fd poll waiters on affected kernels are not awakened for new local task work, despite a nonblocking readiness probe seeing that work. Linux signals a registered eventfd when that work is queued, before CQ commitment.

Evidence: lab run 2026-11-06 (replies aligned to the periodic owner wake); Linux io_uring source, io_req_local_work_add (DEFER_TASKRUN queues local task work and signals a registered eventfd). Source diagnosis; confirm on the Linux runner with the regression test (kernel version + ring mode recorded).

## Decision

MDS uses one level-triggered ppoll over component readiness descriptors, with the earliest component deadline and no persistent foreign-fd registration in rados-rt. Darwin local tests use pselect for nanosecond deadlines.
MDS drains the native client with step(0) before waiting and steps it without blocking after waking. Pending store or client work prevents sleep. The native driver supplies its full quiescence proof and earliest deadline, including retained input, blocked output and close linger.
The knet FE registers an eventfd at startup and consumes its counter before driving the ring. Native RADOS io_uring uses the same notification contract when composed with an external wait. Ring scheduling remains unchanged.
FE handshakes progress only after applying the granted rank to the messenger. MsgHeader2 identity remains fixed by HELLO/ident until reconnect, as specified in the MDS client protocol.

## Rationale

A direct level wait removes nested edge registration and interest bookkeeping. A completion eventfd supplies the missing wake independently of ring-fd poll behavior and preserves deferred task execution. Consuming the notification before polling keeps racing arrivals latched. Fixed stack storage avoids hot-path allocation.

## Consequences

- + No periodic timer is needed to drive FE input or replies.
- + OSD knet owners do not register the new notification fd; their scheduling and hot paths are unchanged.
- + Sibling stack/TAP readiness uses the same outer wait; CRC/secure messenger modes and storage/replication tiers share the wait change without wire changes.
- - MDS knet polls consume an eventfd notification; Linux regression execution remains required.

## Alternatives

- Shorter timers or busy polling: hide the lost wake.
- Changing knet ring scheduling: unnecessary; registered eventfd already signals deferred work.
- S4 with the raw ring fd alone: retains the lost wake on affected kernels.
