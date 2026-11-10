<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# ADR 0391: independent application operation-count admission
Status: explicit native component; qualification pending
Date: 2026-10-18

The compatible queue's finite slot allocation is a storage bound, separate from
its configured logical operation-count target. Add count_target:u64 to explicit
compatible ReadQueue/ObjectClient constructors, alongside the byte target. Zero
disables this named count throttle, preserving finite storage bounds. Strict
constructors continue with no additional count restriction.

Reuse existing application occupancy (all occupied minus reserved controls);
no new mutable counter, queue, wakeup or lifecycle. Nonzero count_target denies
ordinary admission with NoCredit at occupancy>=target, even for zero-byte CALLs.
Managed control admission uses its independent reserved slots/bytes. Completion
consumption retains the existing release boundary; terminalization alone does
not release occupancy. ObjectClient forwards the target without resizing its
watch registry, managed lifecycle storage or native flight capacity.

This is shared native admission arithmetic, independent of kernel/userspace/DPDK,
CRC/Secure and storage backend. No FFI activation, default/profile change,
configuration parsing or timeout policy is included. Existing compatible callers
pass count_target0 to preserve their prior behavior.
