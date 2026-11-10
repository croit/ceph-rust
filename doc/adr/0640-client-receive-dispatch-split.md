# 0640 Title: split receive/decode from dispatch in the kernel client

Status: rejected (2026-11-02: single-threaded per connection stays; the single-job 4 KiB read
cells are accepted as a documented limit, see doc/perf/rbd-qd-20261102.md)
Date: 2026-11-02

## Context

One connection's whole receive path runs on its owner thread (`rustyrados-io`): io_uring
submit/reap, msgr2 framing and CRC, message decode, read routing/dispatch and completion
publication. On the 4 KiB single-job read cell at QD32 that thread is the client's cap:
ice-a measures 97 % of one core at 74 k IOPS, i.e. 12.9 us of work per read, so the cell
cannot exceed `1/12.9 us ~ 77.5 k` IOPS while the single PG's server side serves ~76 k and
stock librbd reaches it (76.3 k) by spreading the same 51.9 us/op over three msgr workers
plus the io_context pool (`doc/perf/rbd-qd-20261102.md`). Removing the last copies closed
about 10 % of the client CPU (32 -> 28.7 us/op) but not the gap.

The post-change profile of that thread is flat and, contrary to the first reading, it is not
dominated by message decode: memmove 12.7 % (240-480 B struct moves and payload copies:
`ReadDispatch` 480 B, `OsdOp` 280 B, `ReadCompletion` 248 B, `Incoming` 240 B),
`worker::run` 4.5 %, allocator 5 % (`malloc` 2.5, `_int_free` 3.0, `cfree` 1.8),
`ObjectClient::progress` 2.9 %, `accepted::Entry::finish_with` 2.6 % (completion publication
including the caller-buffer copy), `kernel_tcp::pump` 2.4 %, `sessions::stream_valid` 1.7 %,
`sessions::transmit` 1.7 %, `Bytes` drop 1.7 %, mutexes 3.6 %, crc32c 1.8 %. Message decode
(msgr2) is below the reporting threshold.

The same client scales to 1.29x stock with three jobs because several owner threads then run
in parallel, so only the one-connection shape is capped.

## Decision

- The receive path stays single-threaded per connection: socket I/O, framing, decode,
  dispatch and completion publication remain on the owner thread (adr 0006/0031: PG-per-core
  ownership, no locks on the hot path).
- The last single-connection gap is pursued by per-op cost reduction inside that thread, not
  by handing work to another thread.
- A cross-thread split is not adopted: see Alternatives for why the handoff cannot run in
  parallel without sharding or locking owner state.

## Rationale

The profile shows the two dominant costs mutate client state owned by the connection (the
read queue's per-tid slots, the admitted ledger, the completion objects). A dispatch pool
would have to either share that state under locks - the locking model this architecture
rejects - or move the state with the frame, which for a single connection still leaves one
thread doing the work. The frame-decode-only split that motivated the first draft of this ADR
would move well under a third of the per-op CPU and add a wake per batch.

## Consequences

- + No new locking, no second thread, no change to ordering, admission or shutdown paths.
- + Reads keep 45 % lower client CPU and a 15-23 us better p99 than stock today.
- - The single-job 4 KiB read cell stays below stock (0.95-0.97x) unless the per-op cost of
  that thread drops from 12.9 to ~11 us, which is a campaign of ~10 small changes (struct
  moves, allocator, mutexes, `Bytes` churn) with an uncertain total.
- - The client cannot use a second core for a single connection as long as the no-lock
  ownership model stands; the multi-connection shapes already scale (3 jobs: 1.29x).

## Alternatives

- Frame decode on a pool, completion publication on the owner thread: rejected; decode is
  below the reporting threshold, so it moves little and adds a wake per batch.
- Sharded owner state with per-tid locks so several dispatch threads can serve one
  connection: rejected; it contradicts adr 0006/0031 and would put locks on the hot path of
  every other shape that is already faster than stock.
- Replica reads by default (`balance` policy) to spread one image's reads over three OSDs:
  not adopted without a decision; Ceph supports it (`rbd_read_from_replica_policy`,
  `OPERATION_BALANCE_READS`) but the reference default is primary-only, so making it our
  default is an observable behaviour difference, not a bug fix (adr 0256).
- Micro-cuts only: the adopted path; the profile is flat (~10 sites of 0.1-0.3 us), so this
  needs one A/B per candidate and ~15 % total.

## Open questions

- Is a replica-read default (`balance`) acceptable as a documented behaviour difference from
  librados? It would take the single-image read cells well past 1.00 by spreading them over
  the three replicas, but it changes which OSD serves a read.
- If a cross-thread split is wanted later despite adr 0006/0031, it needs a separate decision
  about sharding or locking owner state per connection.
