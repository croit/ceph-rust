# 0015 Sans-IO protocol crates
Status: accepted
Date: 2026-10-09
Context: Dev host = macOS arm64 (no DPDK/SPDK). Need deterministic sim tests (0008). Transport (DPDK TCP, 0005) not ready before protocol logic.
Decision: denc, crc, cephx, msgr2, messages, crush, osdmap, monc, osd core = pure logic, no IO, no threads, no clocks (time passed in). API shape: feed(bytes|event, now) -> outputs (bytes to send, timers, events). Only `net`, `nvme`, `rt`, `rdma`, bins touch hardware/OS.
Zero-copy: decode from borrowed/refcounted rx buffers; encode into caller-provided buffers. No per-message heap churn on hot path (later perf pass).
Consequences: + builds/tests on macOS, + deterministic simulation, + transport swappable for tests (in-memory pipe). - glue layer per transport.
Test vectors: golden bytes from `ceph-dencoder` + captured frames from reference cluster (lab/docker). Data only, no Ceph code.
Amendment 2026-10-09: dev/test-only probes (examples or cargo feature `kernel-probe`, never linked into the croit-flashstore-osd daemon) may use std::net kernel TCP to validate protocol crates against the reference cluster before the DPDK stack is ready. Product data path: knet (kernel TCP over io_uring, 0053; default) and AF_XDP on the own stack (0020); DPDK networking parked (0005 am. 2).
