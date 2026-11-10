<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# ADR 0386: bounded asynchronous publication

Status: accepted. Date: 2026-10-19. Amends RC128/129/132.

Async data submission currently waits for an I/O-owner admission ACK for
every operation. The pinned API requires local validation, retained accepted
work and bounded throttling, not an unconditional cross-thread roundtrip.

Validate using shared native pure validators and frozen constructor limits.
Reserve accepted-operation byte/slot credit, then atomically publish its
stable adapter ID and owned queue envelope. Publication accepts the work;
return zero without waiting for native admission. Temporary aggregate
capacity exhaustion blocks on notification, never polling. Failed publication
rolls back the completion claim and all reservations without a callback.

A bounded shared ledger tracks queued and native accepted operations. Install
completion ownership before return. Flush captures the earlier accepted-write
cut; cancellation sees queued operations independently of the data mailbox.
Later native errors complete accepted work. Queued canceled payloads retain
credit until actually dropped; native canceled work retains credit through
native terminal consumption. Preserve independent control mailbox capacity,
callback execution outside owner locks and all native certainty rules.

Sibling paths: C/C++ async data share this boundary; CRC/Secure and kernel/
userspace transports retain the same native validators and ownership engine.
Synchronous calls and asynchronous non-data controls keep their existing ACKs.

Measure total client CPU/op and end-to-end throughput, not only submission
latency. No performance gain is claimed from the design alone.
