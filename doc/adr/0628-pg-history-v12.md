<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0628 pg_history_t: upstream v11 (21.2.0), croit deep-scrub start stamp in v12

Status: accepted
Date: 2026-10-30
Amends: 0593 (am. 1)

## Context

Ceph v21.2.0 bumps pg_history_t to ENCODE v11 (compat 4) with six utime_t after `prior_readable_until_ub`
(vulnerability window and active-rebuild span, doc/compat/ceph-21.2.0-delta.md W1/W2). The croit fork `wip-ifed-dedup`
(21.1.x) and croit-flashstore-osd (adr 0593) used v11 for one utime `last_deep_scrub_start_stamp`. The two layouts collide: a classic
21.2.0 peer decoding our fork-v11 runs past the struct end and the peering message fails, which wedges the PG (prime-safety
violation). Decision by lead, user and Igor Fedotov (fork owner), 2026-10-30.

## Decision

- pg_history_t v11 is exactly the upstream 21.2.0 layout: v10 + `last_degraded, last_clean, vuln_window_reported,
  last_rebuild_active_start, rebuild_span_reported, rebuild_active_accum` (148 B payload).
- The croit start stamp is v12: upstream v11 + one utime `last_deep_scrub_start_stamp` (156 B), compat stays 4.
- croit-flashstore-osd encodes v11 while the stamp is zero (byte-identical to classic 21.2.0) and v12 while it is set.
- Decode: v < 11 -> six fields zero; v >= 11 -> the six; v >= 12 -> the stamp; newer versions skip the tail (envelope).
- No compatibility decode for the 21.1.x fork layout (v11 = v10 + stamp, 108 B) and no interoperability with croit-fork
  classic OSDs <= 21.1.x; the fork rebases on 21.2.0 and adopts v12.
- Merge of the six fields follows doc/spec/peering.md 2.2 (W2); latching by the acting primary follows peering.md 9.6.

## Rationale

Upstream owns the version numbers it ships: any other layout at v11 breaks every classic 21.2.0 daemon. Appending the fork
field after the upstream fields keeps upstream decoders working (compat 4, they skip the tail) and keeps our bytes
identical to classic when the stamp is unset. A length-based legacy decode was rejected because the fork rebases and the
start stamp was only ever written behind `flashstore_dedup_list` (default off, labs only): the extra decode path would
serve no deployed store (KISS).

## Consequences

- + Mixed acting sets with classic 21.2.0 OSDs and mons decode our pg_info_t / notify / log / query / create bytes.
- + Classic 21.1.x peers still decode v11/v12 (compat 4, tail skipped): rolling upgrade safe in both directions.
- - An croit-flashstore-osd store whose `_info` was written with `flashstore_dedup_list=true` by a pre-21.2.0 build (fork-v11) does not
  load: the PG info fails to decode. Such stores exist only in labs; they are re-created, not upgraded.
- - Fork vectors for pg_history_t (testdata/pgwire/fork-dedup) are removed until a fork build on 21.2.0 is captured;
  hand vectors in services/osd/pgwire/src/history.rs cover v12 meanwhile.
- - croit-flashstore-osd with `flashstore_dedup_list=true` is not interoperable with a fork <= 21.1.x.

## Alternatives

- Keep the stamp at v11 and decode by payload length (108 B fork, 148 B upstream): classic 21.2.0 peers still fail on our
  fork-v11 bytes, so the encoder had to change anyway; the legacy decode path alone was rejected (no deployed stores).
- Move the stamp out of pg_history_t (own omap key): diverges from the fork's wire, which carries it to peers and the mgr.
