<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0564 RBD lock hints use owned asynchronous notifications

Status: accepted
Date: 2026-10-24

## Context

Managed ownership hints and metadata invalidation use different pinned wire
messages. The adapter sent synchronous HeaderUpdate during class acquisition
and unlock, including while holding the image writer mutex. A HeaderUpdate
ACK waits for update callbacks, whose ordinary queries need that mutex.

## Decision

Each image header watch owns an asynchronous lock-announcement queue.
Lock leases retain shared queue ownership and use the watch's connected gid
and cookie in standard ACQUIRED/RELEASED frames.
Acquisition advertises only after required local ownership preparation;
failed preparation rolls back without ownership announcements.
Ordinary successful prepared unlock submits RELEASED without waiting for ACK.
Provider completion owns stable diagnostic and reply slots until its complete-
and-callback fence; replies and completions use matching provider destructors.
The watch drains submitted notifications before unregistering itself.
Both writer owner variants drop before that watch, including ordinary Rust Drop.
Announcement submission/delivery errors are logged without changing a completed
ownership result; failed completion fences retain their still-owned storage.

## Rationale

The pinned provider C ABI copies notification inputs during admission and offers
completion-and-callback synchronization. Retaining outputs and ioctx ownership
until that fence prevents callback/output lifetime races. Distinct lock hints
avoid metadata callbacks and their query-lock cycle during ownership changes.
This queue handles ownership announcements; metadata mutation completion still
requires its own mutex/notification phase correction.

## Consequences

- + Ownership hints no longer invalidate metadata or invoke update subscribers.
- + Acquisition/release does not wait for announcement ACK under the writer mutex.
- + Completion-before-submission-return and ordinary owner Drop retain valid storage.
- - Accepted completions remain allocated until the next announcement or watch drain.
- - Failed provider completion fences retain resources and emit a cleanup diagnostic.
- - Requester/owner handoff, policy responses, stale owners and reconnect remain work.

## Alternatives

- Synchronous ownership HeaderUpdate: wrong protocol and callback dependency cycle.
- Untracked asynchronous send: output/callback/context storage can outlive the lease.
- Per-announcement OS thread: provider AIO already supplies submission and completion.
