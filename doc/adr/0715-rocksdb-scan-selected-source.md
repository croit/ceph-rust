<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0715 Retain the selected scan-key source

Status: proposed
Date: 2026-11-07
Amends: 0714-rocksdb-scan-current-item

## Evidence and decision

A bounded99Hz user-CPU diagnostic observes66/383 worker leaf samples in byte
comparison,60 with the merged page walk as caller. Short stacks limit attribution;
this is a mapping lead, not proof that a particular comparison causes the cost.

The merge already chooses the DB key initially, replacing it only when an overlay
key is strictly smaller. Retain that decision in a local boolean. Use it when
selecting the base value and advancing the DB iterator instead of comparing the
selected bytes with the same base bytes twice more.

Key origin is distinct from value precedence. Equal overlay keys do not replace
the selected DB key; they still provide the winning value/deletion through the
unchanged newest-first probes, and the DB must advance. A strictly smaller
overlay key does not advance the DB. An absent/prefix-rejected DB candidate cannot
be selected. Every seek restarts selection, so the flag never survives movement.

Keep comparison ordering, overlay/range probes, binary prefix/exclusive starts,
status handling, owned key/value allocation, continuation charging and all page
budgets unchanged. No pointer-equality assumption, unsafe API, shared arena,
iterator retention, clock boundary, configuration, WAL or ACK change is added.

## Qualification

Independent literal oracles cover all three overlays, equal-key value precedence,
equal-key tombstones, smaller overlay keys, exhausted/prefix-rejected base keys,
exclusive starts, adjacent objects and1/2/full-size pagination. Existing range,
credit, owner-yield, reopen and cancellation regressions remain necessary.
Measure a fresh matched non-sampled pair against the same diagnostic counters;
do not pool stack-sampled foreground timings or claim speedup from this decision.
