<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0717 Reuse materialization point-key encoding scratch

Status: proposed; performance candidate
Date: 2026-11-07
Amends: 0681 (worker-local batch construction only)

## Context

Profiled update batch construction consumes measurable worker CPU. Every point
mutation currently allocates a prefixed key Vec,then WriteBatch copies that key
into its owned encoding. The temporary Vec is discarded immediately. This is
independent of the much larger measured write-stall cost;removing it does not
claim to resolve stalls or prove an end-to-end improvement.

## Decision

Use one worker-local Vec per materialization to encode point put/delete keys.
Clear and refill it for every object/key,retaining capacity only;the binary prefix
and object-ID/key encoding remain identical. WriteBatch continues to own all keys
and values. Drop scratch before the synchronous DB write;retain no new buffer
between flushes. Range endpoints and ordinary read-key ownership are unchanged.

Keep batch ordering,watermark,WALsync,native publication,buffer/cache budgets,
stall thresholds,subcompaction bounds and native LSM unchanged. No batching delay,
new arena,extra background concurrency or workload-specific production switch.

## Validation

Independent fixed-byte prefix vectors cover changing IDs,binary/empty keys and
shrinking lengths without new scratch allocation after growth. A multi-object
put/delete/range/reinsert/overwrite oracle reopens the real database and checks
all returned keys/values and watermark. Require affected Store/integration/adapter
checks and comparable first-five measurements,including build CPU/serialized
bytes,batch counts,write stalls,settlement and effective RX/owner/worker placement.
