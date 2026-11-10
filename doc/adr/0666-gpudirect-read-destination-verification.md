<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0666 GPU READ destination: receipt verification and arena-backed placement reads

Status: accepted
Date: 2026-11-03

## Context

The registered READ path (placement v1, adr 0469 am. 1) places one plain READ
into a client MR: the OSD RDMA-WRITEs the object bytes into the client's
destination window and returns a crc32c receipt over exactly those bytes. The
client verifies the receipt against the destination before it publishes the
bytes to the application.

A GPUDirect destination (adr 0665) is a DMA-BUF MR (or, until GPU hardware is
available, host memory registered with the same access bits). Two questions
arose while bringing it up:

1. The receipt check reads the destination bytes on the host. Device memory has
   no host mapping, so the check cannot run there.
2. The OSD's placement preflight refuses any reply whose source pieces are not
   inside the core's registered payload arena. The store served shared reads
   from the data cache and the prefetch table, whose buffers are ordinary
   mappings, so every placement read was refused with `EOPNOTSUPP` — including
   host destinations.
3. One GPU registration serves several concurrent READ windows over sub-ranges
   of one parent MR. A CPU check of one window must not alias bytes a peer may
   still write through another, must read the window's own subrange, and the
   registration may only report "released" once no window can be written any
   more, including windows of READs whose session ended without a retirement
   proof.

## Decision

- A placed READ reports how its receipt was checked:
  `rdma::verbs::ReadVerification::{Cpu, DeviceMemory}`, surfaced as
  `RegisteredReadOutcome::Success::verified`, `ReadOutcome::RemotePlaced::verified`
  and the C result flag 4 (`RUSTYRADOS_HOST_READ_DEVICE_MEMORY`).
  - `Cpu`: the receipt matched the destination bytes on the host. This covers
    host destinations, the GPU host mock and any DMA-BUF the client maps.
  - `DeviceMemory`: the destination is device memory; the host did not verify
    and must not claim it. The receipt is retained for a device-side check by
    the caller's fence and read. `address` is 0 and no CPU view is granted.
- A GPU result never exposes a CPU pointer, whatever the backing: the flag is
  set for every GPU registration, so an application cannot mistake the mock for
  host memory.
- Windows of one GPU registration are pairwise disjoint while outstanding
  (`RegisteredGpuRoot::lease`): a lease overlapping an outstanding window is
  backpressure (`GpuLeaseError::Overlap`, C -11), like an exhausted pool.
- The CPU receipt check borrows exactly the retired window's bytes, located
  region-relative (window address minus region address), never a whole-region
  slice (`GpuRegion::host_subrange`). The C CPU-bytes accessor returns an
  address/length span without forming a slice.
- The registration tracks each leased window by its own release watch,
  independent of public READ handles. A window is outstanding from lease until
  reclaimed, or until it is gone for good (dropped after retirement or after
  the destroy of the QP that retained it).
- A registered READ given up without retirement proof (session lost, stream
  closed, LOCAL_INV refused, client close) parks its window; before the
  transport releases the stream's QP it hands every parked window to that QP
  (`Core::abandon_published_window`). The QP's teardown (ERR, MW deallocation,
  destroy) replaces the peer's proof and only then drops the window, its parent
  and backing. This applies to host and GPU destinations. A window without its
  QP stays quarantined for good (loud, counted).
- A window lost to a QP teardown is replaced by a new prepared window on the
  next lease (`borrowed_sibling`), so the budget is restored.
- GPU registration release (`rustyrados_host_registration_release`) returns 0
  only after every window is home or gone and the parent MR deregistered
  (region release watch dead). -16 (EBUSY), registration unchanged, while the
  registration job still runs or a window is outstanding; -5 when the provider
  refused the MR deregistration.
- Blocking release: `rustyrados_host_registration_release_wait(cluster,
  handle, timeout_ms)` retries that release on a worker signal (condvar
  generation), never by polling. The signal moves when a registration job
  settles, a leased window is reclaimed, or a window dies wherever it went
  (`GpuRegion::notify_window_release`, called after its release watch died:
  READ retired, or QP destroyed after its session ended). -110 with
  `WARNING TIMEOUT` after `timeout_ms`, registration unchanged. A host
  registration returns at once (its callback stays the proof). The NIXL
  backend's `deregisterMem` calls it with its `timeout`; the shim holds no
  retry logic.
- The budget charge of a standalone host destination abandoned to a QP
  travels with its window (`ReleaseHook`) and returns to the client's
  registered-bytes budget once the QP's destroy released the parent MR and
  backing (`Qp::release_parents`); an uncertain teardown keeps it retained
  with them.
- `ShardStore::read_runs_shared` (the placement shared read) bypasses the data
  cache and the prefetch table (`media = true`): every piece is a device buffer
  from the registered arena, so the transport can RMA it. A cache hit costs a
  device read for placement reads only; ordinary SEND reads keep the cache.

## Rationale

- Verification is a durability/integrity contract: reporting `Success` without
  a check would be a silent correctness loss. A flag keeps the information with
  the result instead of hiding it in a log line.
- The alternative for (2) — registering the data-cache region for zero copy —
  would pin and register a per-core region of up to 16 GiB on top of the
  payload arena, for a path that is not throughput-critical yet. Bypassing the
  cache keeps the registered set small and the preflight simple.
- Disjoint windows are the simplest rule that makes the CPU check sound; an
  application that READs overlapping ranges concurrently gets backpressure,
  not corruption. Overlap never served a use case (one KV block layer = one
  range).
- Abandoning windows to their QP reuses the source-pull teardown proof (adr
  0665-gpudirect-put-source-pull) instead of a second mechanism; before, an
  unproven window was forgotten for good, so a GPU registration release
  returned 0 while its MW stayed valid, and a host registration's release
  callback never came.
- -EBUSY on a pending registration job is simpler than deferring the release:
  the job owns the caller's memory until it finishes, and the caller already
  handles -EBUSY.
- Refusing the placement (instead of copying the piece into the arena) keeps the
  transport's rule "no copy on the placement path" intact and makes a
  misconfiguration loud (`knet: rdma: conn …: placement preflight refused: …`).

## Consequences

- A placed READ into device memory completes without a host byte check. The
  caller must fence the device and read the region before trusting it; the
  NIXL backend (contrib/nixl) reports the transfer as complete on the OSD
  receipt and leaves the fence to the application, as NIXL does for its other
  GPU backends.
- A concurrent READ overlapping an outstanding window of the same GPU
  registration waits (-11) instead of running.
- A registration whose window teardown failed can never be released (-16 for
  good); the memory must stay allocated. Counted by
  `rdma::verbs::quarantined_windows`.
- Lost sessions do not shrink the registered-bytes budget: abandoned
  destinations return their charge after the QP destroy. Only a quarantined
  teardown keeps it (with the memory, loud and counted).
- Placement reads of hot objects read the device (no cache hit). Measured
  effect not recorded yet; the placement path is lab-only.
- The preflight error names the failed check (length, capacity, arena), and the
  transport logs the refusal with its reason.

## Alternatives

- Copy a cache-served piece into an arena buffer before the WRITE: rejected, it
  adds a full payload copy on the placement path.
- Skip the receipt check silently for GPU: rejected, it hides a lost
  verification.
- Verify on the device inside the client library (CUDA): rejected for now, the
  client libraries stay free of CUDA; the caller owns the fence.

## Open questions

- Device-side receipt verification (a CUDA kernel or `cuMemcpyDtoH` of a sample)
  as an opt-in helper: which layer owns it, the application or the NIXL
  backend?
- Whether the data cache should be registered for zero copy once placement is
  no longer lab-only (memory cost vs. the device read).
