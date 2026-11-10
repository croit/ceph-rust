<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0491 Omap listing replies are encoded straight from the tree leaves

Status: accepted
Date: 2026-10-22
Amends: 0021 (S8)

## Context

An omap listing (omap_get_vals, omap_get_keys) cost ~230 ns per key on the PG core of the build host after adr 0021 am. 63 (store bench, warm 1M-key object, reply included). Profile (Mac): ~30 % malloc/free (a key `Vec` and a value `Vec` per entry in the scan memo), ~25 % memmove (key and value copied into those `Vec`s, then again into the reply). The reply is the denc `map<string, bufferlist>` / `set<string>`: a `le32` count, per entry `le32 len, key [, le32 len, value]`, then the `truncated` byte. OQ 92 (1).

## Decision

- The store writes an omap listing in reply form while it walks the leaves: `Store::omap_list_enc` / `Stage::scan_omap_enc` append per admitted entry `le32 key length, key` and, with values, `le32 value length, value` to ONE buffer that starts with `head` reserved bytes. No allocation per entry; an inline value is copied once (leaf -> buffer), a zstd-compressed inline value (`V_CINL`) is decompressed into the buffer (`vcomp_unpack_into`).
- The scan memo of a resumable listing (adr 0021 S8) holds that buffer (`ScanMemo::enc`, entry count `n`); `head` is a memo parameter. Refusals and CPU slices keep it; the next run appends. Selection, budgets, `more`, slices and resume are unchanged.
- Values not inline in the leaf (fragments, data-block values, unknown dictionary) are holes: position after their key + key length (`ScanMemo::holes`). After the walk their fragments are prefetched in one range (as before), the values read resumably (`hole_vals`), then spliced in one copy (`splice_holes`).
- The pair API (`scan_omap_range` -> `KvList`, `scan_omap_recovery`) decodes the same buffer (`enc_decode`): one listing walk for every caller (cls, recovery, tests).
- `ObjView::ov_omap_list(spg, soid, after, prefix, max, max_bytes, values)` returns `(buffer, entries, more)` with `opwire::OMAP_LIST_HEAD` (4) reserved bytes; storeadapt maps it to `Store::omap_list_enc`. Default (in-memory views) and EC PGs with in-flight omap records (`ec_overlay` / `ec_omap_keys_overlay` not empty): `omap_list_via` encodes the merged pair listing (map rule for an unsorted list, as `omap_vals_out`).
- opexec `omap_get_vals` / `omap_get_keys` finish the reply in place: `opwire::omap_list_out` writes the count into the head and appends the `truncated` byte; the buffer becomes the op's outdata without a copy (the store leaves room for that byte). Replies are byte-identical to the `OmapValsOut` / `OmapKeysOut` encodings; absent object: vals = success without data, keys = an empty listing (unchanged).

## Rationale

- The reply bytes are the only thing the client needs; building pairs first and encoding them after cost two allocations and two extra copies per entry. Writing the wire form directly is the minimum: one copy of key and value.
- One buffer per listing survives refusals and slices as the pairs did; growth is amortized doubling from a small guess (32 B per entry, <= 64 KiB up front). A presized large buffer measured slower on the Mac (fresh pages per listing).

## Consequences

- + Store bench (build host, warm 1M-key object, reply included): values 230 -> 182 ns/key (4.0M -> 5.1M keys/s), keys only 184 -> 160 ns/key; malloc/free disappear from the profile. Live (zen4a, one PG core saturated by omap listings alone): 3.5M -> 4.0M keys/s through the OSD, OSD busy 323 -> 288 ns/key; point ops alone unchanged (doc/perf/listing-reply-encoding-20261022.md).
- + One listing walk for every omap listing; cls and recovery keep their pair API.
- - Pair callers (cls `omap_get_vals`, recovery pushes) pay one more copy per entry (buffer -> pair); their per-entry allocations are unchanged.
- - The remaining per-key cost is the leaf walk itself (key reconstruction `key_into`, `leaf_ent`, end/prefix compares, the scan callback) and the inherent copies.

## Alternatives

- Zero-copy reply slices of the leaf pages: a page can change or be evicted between slices and refusals of one listing; the leaf entry layout (prefix-compressed keys, value headers) is not the wire layout.
- Presized reply buffer from the object's omap counters: slower in the bench (large fresh allocations per page), no gain over doubling.
- (Separate question, same work) A per-loop-iteration time share of listing continuations against the other work of the core: lost its live A/B (listing alone -8 %, hot object next to listings not better), reverted; OQ 92 (3).

## Open questions

- How should the PG core share between saturating listings and point ops be bounded by cost (first passes and reply sends included)? OQ 92 (3).
