<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# ADR 0394: bounded client ciphertext reuse
Status: not adopted; simpler caller-bounded preparation selected
Date: 2026-10-18

Evidence: corrected measured-window process perf, same uninstrumented baseline
ELFb45208c7... and consumer-v5. Slow Secure4MiB/QD32 process214.394IOPS/5.481ms
CPU/op records301322page faults in3s. Stacks: anonymous page allocation/clearing
under EVP AES-GCM separate-output writes. Other same-ELF invocations293.125/
301.765IOPS,4.181/4.096ms,0/6958faults. Stock414.509IOPS/2.751ms,3faults.
Capture cycles/task-clock2.57–2.69GHz. Earlier good captures' TCP page-clearing
attribution remains specific to those captures. mmap/trim/provider details are
not established by fault stacks alone. Allocation reuse targets fresh pages;
no application-global allocator/tunable change or mandatory new dependency.

Proposed scope: Secure shared-input separate ciphertext only. Keep plaintext,
C/C++ snapshot/replay semantics and all wire/GCM nonce/authentication unchanged.
One retained Bytes allocation per TX GCM context, eligible for reuse ONLY when
Bytes::try_into_mut establishes exclusive ownership after every transport/user
clone is gone. Never borrow/rewrite live ciphertext. Clear mutable initialized
length before existing EVP writes; expose full output only after update/tag
success. Drop failed reuse/output safely; never reuse a nonce. Busy/missing/
undersized cache follows the existing fresh-allocation path, with no copy of
plaintext into a staging buffer.

A client-wide Arc atomic byte budget bounds the SUM OF RETAINED CACHE CAPACITIES
across all OSD connections. Budget derived from SessionLimits.output_bytes,
not multiplied by connections. No mutex/thread-local destructor/custom unsafe
allocator. Capacity reservation lives with cache entry; removal/reset/close
returns it. Output ownership/inflight budgets remain separately enforced;
cache eviction cannot invalidate live Bytes. Max additional idle retention is
the explicit shared cache budget. No unbounded size-class cache/pool. Do not
alter global malloc, sysctls, provider or source/destination address policy.

Default messenger/server behavior has no cache unless client plumbing supplies
this shared budget. NativeSessions creates the single budget and supplies it
only to OSD client connection encoders; reconnect/reset retains correct budget
and key lifecycle. Shared NativeSessions means kernel/DPDK/userspace, CRC/Secure
siblings: CRC unchanged, owned unique-input in-place encryption unchanged.
No storage/backend/OSD policy change.

Own tests: repeated v2.0/v2.1 wire equality and decode; pointer reuse after last
owner versus held clones unchanged; two contexts competing for shared capacity;
size growth/oversize/zero budget; failure at update/final/tag cleanup and nonce
advance; reset/reconnect/dropped pool/output ownership. Affected messenger/
runtime/FFI ABI tests. Uninstrumented paired A/B against exact predecessor and
stock; same-library control, CRC/small/read/idle siblings, faults/RSS after idle.
Do not accept from unit counters or exports. Remove if no robust end-to-end gain
or if retained memory/ownership contracts cannot be bounded and qualified.

Decision update: cache-only and four-way paired controls do not establish an
additional robust benefit. Caller-bounded preparation alone gives stronger
internal Secure-write gains with less state. No cache runtime integrated.
Keep this proposal/evidence historical; see client stage profile report.
