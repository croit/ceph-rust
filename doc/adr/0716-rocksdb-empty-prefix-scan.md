<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0716 Skip empty scan-prefix comparisons

Status: proposed
Date: 2026-11-07
Amends: 0715-rocksdb-scan-selected-source

## Evidence and decision

Exact-symbol analysis of the retained current-item binary maps59/60 direct
page-walk comparison samples to the prefix predicate, and only one to optional
key equality. The frozen Phase1 client requests an empty OMAP prefix. Shallow
software-clock stacks remain a mapping lead, not an unbiased timing estimate.

Determine once per worker page whether the immutable requested prefix is empty.
If empty, accept both DB and overlay candidates without calling starts_with;
otherwise retain the same predicate. Every byte string starts with the empty
prefix, including empty/binary keys. Initial seek/exclusivity, object upper bound,
range jumps, overlay value precedence, owned output, credit/continuation limits,
errors and iterator lifecycle are unchanged. No new RocksDB option is needed.

This is narrower than refining iterator bounds to a binary-prefix successor.
That alternative is not implemented or required for the observed empty-prefix
workload. Do not assume the earlier selected-key flag removes this sampled site.

## Qualification

Independent literal subsets exercise empty/NUL/FF/missing prefixes over base and
all three overlays, empty keys, object0/9/u64::MAX, adjacent objects, exclusive
starts and1/2/full-sized pages. Existing range, credit, reopen and ownership tests
remain required. Compare fresh unsampled runs with identical client, placement,
diagnostics and between-arm retention activity. Preserve neutral/failed results;
this decision alone establishes no throughput improvement.
