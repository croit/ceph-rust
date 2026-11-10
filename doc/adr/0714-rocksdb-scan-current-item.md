<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0714 One current DB item per merged scan iteration

Status: proposed
Date: 2026-11-07
Amends: 0711-rocksdb-borrowed-scan-candidates

## Evidence and decision

An instrumented8Mi scan attributes97.996% of worker-stage CPU to merged walk and
owned output construction, not initial seek/setup or iterator destruction. It
does not isolate accessor crossings from merge/copy cost or prove a speedup.

Within each existing worker walk iteration, borrow one safe RocksDB raw-iterator
item(key,value) and reuse it for key validation, range coverage, candidate choice
and the base value. Previously separate key/key/value access repeated validity
checks and key retrieval. Exact Rust rocksdb0.25.0 API promises borrowed slices
only until mutable advance/seek; no unsafe API or persistent borrowing is added.

Keep all overlay probes/precedence, tombstone seek-and-continue, prefix/object
isolation, exclusive starts, status checks, credit/entry bounds and owned replies.
Drop the borrowed item before seeking/advancing. An overlay winner never consumes
the simultaneously borrowed base value. No iterator/session/snapshot retention,
native-LSM, Rocks configuration, timing-boundary, WAL or ACK change.

## Tradeoff and qualification

item() obtains a value even when a covering range or newer overlay makes it
unused; fewer accessor calls are not proof of less cost on every workload. Test
alternating base/overlay candidates, binary keys, covered ranges with surviving
newer points, exclusive continuation and tight credits independently. Reuse
existing three-overlay/reopened-owner-yield regressions. Compare source-bound
instrumented artifacts with matched placement and full oracles; retain failed
or neutral results. No performance acceptance follows from this ADR alone.
