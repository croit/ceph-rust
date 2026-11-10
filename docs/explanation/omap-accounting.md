<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Igor Fedotov, croit GmbH -->
# OMAP usage accounting

For PGs whose primary is croit-flashstore-osd, reported logical OMAP bytes are the sum of
**user key bytes + value bytes** measured by the last complete deep scrub.
Key lengths are byte lengths, including raw binary bytes and UTF-8 encoding.
An empty value still consumes its key's bytes. An empty key and value contribute
zero bytes and one entry. OMAP headers, encoding prefixes and engine overhead
are excluded.

These are logical payload numbers, not allocated space. Metadata pages, WAL,
fragmentation and compression can make physical usage differ.

## Reading and refreshing the measurement

Use `ceph df detail` for pool totals or `ceph pg dump pgs -f json` for PG
`num_omap_bytes` and `num_omap_keys`. The latter counts entries, not key bytes.
There is no separate published key-byte total.

Overwrites, deletion, clear and purge do not change the last-scrub measurement.
The next complete deep scrub refreshes it. This applies equally to the B-tree
and dedicated OMAP LSM engines. Existing measurements keep their previous
values-only definition until refreshed by the new implementation.

croit-flashstore-osd does not advertise a per-pool OMAP allocation estimator. The manager
uses primary PG totals, without dividing them by the pool's replication or EC
raw-used rate. `dump_pool_statfs.omap_allocated=0` means that allocation estimate
is unavailable; it does not establish that the pool contains no OMAP. The per-OSD OMAP column of `ceph osd df` shows the sum of the PG totals the OSD hosts.

## Scrub compatibility and incomplete measurements

Scrub message encoding, value-byte fields, digests and large-OMAP value
thresholds retain their Ceph meaning. Key lengths are local bookkeeping.
Optimized EC scans OMAP in bounded scrub slices while retaining its wire
OMAP digest sentinel.

If scrub chooses a remote authoritative copy and the primary cannot establish
trustworthy local key lengths, it keeps the previous complete key/byte totals
and marks OMAP statistics invalid. A later complete deep scrub clears this.

Classic primaries still report their own values-only scrub totals. In mixed
acting sets, PG totals therefore depend on which implementation performed the
last deep scrub. Modern BlueStore allocation estimates are also a different
measurement: approximate RocksDB space rather than exact key/value payload.
