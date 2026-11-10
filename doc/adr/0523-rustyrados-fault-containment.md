<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0523 rustyrados fault containment and librados shutdown semantics

Status: accepted
Date: 2026-10-23
Amends: 0184, 0308 (C++ handles); former ADR 0331 (C++ context conversions, folded into spec/rados-abi/cxx-abi-core.md#adr0331)

## Context

Review 2026-10-22 (doc/reviews/rustyrados-review-20261022.md, top 2/3/9/10, C1-C6): any owner error ended the I/O worker for good (every later call -ENOTCONN); OSD session rejections, undecodable OSD messages, unexpected watch events and a monitor auth failure after Ready were such errors. librados keeps running in all of them. C++ `Rados` release dropped one `Arc`, so a watch (holding `IoCtx` -> cluster) kept the client, its threads and its callbacks alive after `~Rados`. Shutdown queued -108 watch error callbacks and could run callbacks after `rados_shutdown` returned. Watches had an own 25 s reconnect limit. A panic on an internal thread was silent. `rados_connect` returned -EIO for every bootstrap failure.

## Decision

- Every OSD session loss is session-scoped: a rejected session (auth, banner, protocol, peer identity, placement control) is retired with the redial cooldown like a transport loss, and its requests are resent on a fresh session. `SessionFailure::Rejected` stays a diagnostic class only.
- An OSD message that cannot be decoded (wrong version, decode failure, unexpected middle segment, invalid backoff) faults its session (messenger decode-failure semantics), never the client.
- A decodable reply that does not fit its request fails only that request with -EIO (`LocalRequestError::InvalidReply`); a request its session's wire format cannot encode fails alone with -EINVAL (`LocalRequestError::Unencodable`).
- A decodable watch event no watch expects is dropped and counted.
- After the first Ready, a monitor authentication failure is a hunt fault: the client keeps hunting on its held identity, tickets and map. Before Ready it ends `rados_connect` with -EACCES; an expired startup window gives -ETIMEDOUT; other bootstrap failures -EIO. Closing a failed bootstrap keeps its cause.
- Remaining owner errors (clock, resources, internal invariants) stop the owner with one named stderr line.
- C++ `Rados` handles share one client reference count (librados `RadosClient` get/put): `Rados::init`, `Rados(IoCtx&)` and `from_rados_t` add one, `shutdown`/destruction/replacement drop one, the last one shuts the client down even while IoCtx or watch references keep the memory alive. `rados_shutdown` always shuts down.
- Shutdown = flush the callback executor, stop and join the owner (pending operations settle with -108), flush again. No callback of the client runs after shutdown returns (except when called from a callback thread, which cannot wait for itself). Established watches end without error callbacks; a fatal owner error still delivers one terminal error callback per watch.
- Watches reconnect without a client-side outage limit (no outage budget exists; watch-timing-config-contract s1/s4): while the target is homeless no RECONNECT is created and no deadline runs; each RECONNECT gets its own `rados_osd_op_timeout` budget, PINGs none. A failing reconnect reply ends the watch with -ENOTCONN, a deleted pool with -ENOENT.
- A panic on `rustyrados-io` or a `rados-rt-bytes` helper prints one line naming the thread and aborts (`rados_rt::abort_on_panic`), like a failed `ceph_assert`; callback jobs keep their per-job catch.

## Rationale

Objecter and MonClient never die on these faults; apps (librbd image watchers, RGW) assume a handle survives OSD restarts, address reuse and ticket rotation. Containing at the narrowest owner (request, watch event, session) keeps every other request and the original request identities (resend with the same reqid is deduplicated by the OSD PG log). Abort on an internal panic is preferred to a hang because the owner's state cannot be settled after unwinding. Trade-off: a persistently rejecting OSD is redialed every cooldown instead of failing fast; requests then end by their own deadline, as in librados.

## Consequences

- + One faulty OSD, message or monitor no longer turns the whole client into -ENOTCONN.
- + C++ apps that destroy `Rados` with live watches no longer get callbacks into freed contexts.
- + Shutdown is deterministic: no callback after return, no -108 watch error callbacks.
- - A remaining internal panic ends the process (loud) instead of hanging it.
- - Observable differences (adr/0256): in-flight AIO completes with -108 at shutdown (librados drops it); an invalid reply gives -EIO (librados would publish it).

## Alternatives

- Restart the whole native client after a fatal error: new global id means new reqids, so resent writes would not be deduplicated; rejected.
- Keep rejections terminal (0184): diverges from librados and kills long-lived apps on OSD address reuse; rejected.
- Settle waiters after a panic: owner state is unreliable after unwinding; rejected.
