<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0605 Retained ownership during RBD removal

Status: accepted
Date: 2026-10-27

## Context

Image removal deletes DATA objects and the watched header. Releasing the header
lease or unregistering its watch before guarded header deletion creates an
admission interval for another managed client. Unwatch and callback flush have
distinct proof obligations; failed teardown cannot make provider callback state
safe to free. The provider library belongs to the C caller and symbols resolve
from its `RTLD_DEFAULT` instance.

## Decision

- Keep the registered header watch through guarded header deletion. When
  EXCLUSIVE_LOCK is set, retain its actual class lease and atomically assert
  `lock.assert_locked` plus remove. For owner-free headers, do not fabricate a
  class lease: atomically assert the observed header object version plus remove.
- Before deletion, seal new image work and drain accepted callbacks and outbound
  announcements while the header remains available.
- Consume the specific header lease without a post-delete unlock or
  `LOCK_RELEASED` notification only after exact header deletion succeeds or the
  target is proven absent.
- Treat callback sealing as retirement intent only. Unwatch `ENOENT` is
  normalized only after the guarded delete proves the exact header gone.
- After deletion, require actual unwatch and successful cluster-wide callback
  flush before destroying the private ioctx or callback state. Normalize only
  `ENOENT` for the proven retired target.
- On uncertain unwatch or flush, return the provider error and retain callback
  state and the raw ioctx. Do not retry unwatch a fixed number of times.
- Defer close from any image-update callback on the current thread because
  provider flush is cluster-scoped and may wait for another image's callback.
- Require the caller to keep its librados instance, cluster and bridge code
  loaded after uncertain close; the bridge does not own an independent provider
  library handle.

## Rationale

The retained watch and, where available, actual lease close the managed-client
admission window through destructive header retirement. Owner-free images have
no RBD exclusive class lease, so a version assertion fences the exact coherent
header observation without changing their ownership profile. The pinned
provider contract requires a successful unwatch result and a separate
successful callback flush before callback memory/ioctx retirement. A missing
destroyed header cannot receive a meaningful release notification. No
universal cross-object fence is provided for featureless clients opening by
immutable ID, so this decision does not claim to exclude those clients.

## Consequences

- Removal has an explicit ordering from retained watch/lease or version fence
  through header deletion and callback retirement.
- A close error can leave a callback registration and private ioctx retained;
  callers must preserve the owning provider lifetime.
- Callback-initiated close may complete asynchronously and report
  `EDEADLK`/`EAGAIN` rather than synchronously draining its own callback.
- RBD-024/025 remain open until snapshot, parent, journal, mirror, plugin and
  remaining recovery dependencies are implemented and qualified.

## Alternatives

- Unwatch before header deletion: rejected because it drops the registered
  cookie while the deletion lease remains live.
- Unlock after header deletion: rejected because the removed object cannot
  carry the release notification.
- Retry unwatch once: rejected because a fixed retry is not teardown proof.

## Open questions

- What additional API-level lifetime contract should callers use if
  `rbd_close` reports uncertain provider teardown and they cannot keep the
  owning librados instance alive?
