<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0691 RBD AIO local-result dispatcher and bounded open/close workers

Status: accepted
Date: 2026-11-08

## Context

rbd-ffi created a detached thread per rejected AIO submission, per empty
read, per `rbd_aio_open*` and per `rbd_aio_close` (review 2026-11-08 nt-aio,
NT-aio-01/03). Thread creation failure ran a failure callback synchronously
under the submitter's locks. A close thread also stayed parked while an
earlier application callback was held. Classic v21.2.0 delivers callbacks
through an image API strand on its own executor, never inline in the
submitting call, and runs open/close as asynchronous state machines.

## Decision

- Local results (submission failures, empty reads, open results, close
  completions) run on one process-wide local-result dispatcher, created before
  the first completion handle is returned. Creation failure: completion
  creation returns `-EAGAIN`; an accepted submission never runs its callback
  inline. Image-bound callbacks still go through the per-image strand.
- A callback on the dispatcher that waits for another completion drains the
  dispatcher queue cooperatively (same rule as adr 0629 for image strands).
- Blocking open/close work runs on a lifecycle pool: workers start on demand,
  up to `available_parallelism()`, and are reused. Lifecycle jobs run no user
  code. No worker starts and none exists: the submission completes with
  `-EAGAIN` through the dispatcher.
- The serial write/flush pools (adr 0532 am. 2) are created before an AIO
  write or flush is accepted; when a pool starts no thread the submission
  completes with `-EAGAIN` through the dispatcher. Jobs never run on the
  submitting thread.
- The close callback-prefix fence holds no thread: the close job registers
  its completion on the image's callback tracker; the callback that settles
  the prefix queues the completion on the dispatcher.

## Rationale

Thread count is bounded by the host, not by outstanding requests. Lifecycle
jobs wait only for provider replies and for the image's admitted operations,
which other executors complete, so the bounded pool cannot deadlock on
itself; a held user callback occupies no lifecycle worker.

## Consequences

- + No thread per AIO error, empty read, open or close; no inline fallback.
- + Close completion still never overtakes an earlier image callback.
- - One dispatcher thread lives for the process; lifecycle workers stay
  after their first use.
- - More concurrent blocking opens/closes than the bound queue behind each
  other: opens on a stalled PG can delay unrelated opens/closes, where classic
  progresses them independently (open question).
- - A callback without image binding that blocks the dispatcher delays other
  local results (classic: same on its single finisher).

## Alternatives

- Inline callback fallback: deadlocks an application holding a submission lock.
- Thread per request: thread population grows with outstanding requests.
- Close on the dispatcher: deadlocks behind local results its fence waits for.
- Non-blocking open/close state machines on provider AIO: classic-equivalent
  concurrency, but a redesign of the open/close paths; open question.

## Open questions

- Asynchronous open/close state machines to remove head-of-line blocking of
  the lifecycle pool under stalled PGs (doc/90-open-questions.md).
