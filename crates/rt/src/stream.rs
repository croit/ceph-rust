// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Service-neutral per-core byte stream boundary.
//! Listener tokens are indexes in the listener array supplied to the runtime (each listener holds one socket per
//! address family).
//! The first listener is the public/client listener for placement; other indexes
//! are service-defined. Callbacks and command execution stay on the owning core.
use bytes::Bytes;
pub use daemon_io::IoCmd;
use std::net::SocketAddr;
use std::time::Duration;

/// Per-core byte-stream callbacks, statically dispatched by the kernel transport.
pub trait Driver {
    /// Whether a terminated multishot accept should be rearmed. The default
    /// compiles away for services whose listener set lasts for the runtime.
    #[inline(always)]
    fn listener_open(&self, _listener: usize) -> bool {
        true
    }

    /// Bounded socket facades opt into one-shot accepts and expose their next
    /// destination slot here. A false value leaves peers in the listen backlog.
    #[inline(always)]
    fn listener_accept_ready(&self, _listener: usize) -> bool {
        true
    }

    /// Slots currently available for this listener, excluding no runtime reservations.
    /// Bounded adapters report the actual capacity shared by address families.
    #[inline(always)]
    fn listener_accept_capacity(&self, listener: usize) -> usize {
        usize::from(self.listener_accept_ready(listener))
    }

    fn admission_ready(&self) -> bool {
        true
    }
    fn input_ready(&self, _conn: u64) -> bool {
        self.admission_ready()
    }
    fn resume_inputs(&mut self, _now: Duration) -> bool {
        false
    }
    /// Held input or a frame waiting for pool space could go on now: the core must not sleep (the re-check that
    /// closes the lost-wake window of a release by another core).
    fn input_resumable(&self) -> bool {
        false
    }
    /// The connection's next message header is parsed and waits for ingress pool space (memory envelope G1): its
    /// decoder takes the chunks already in flight and the socket is then left unread (TCP backpressure). Such a link
    /// must NOT drain the socket into hold storage: held chunks pin the shared receive buffers of every connection of
    /// the core, and the space they wait for is freed by work that needs those very buffers.
    fn rx_parked(&self, _conn: u64) -> bool {
        false
    }
    /// A socket from `peer` was accepted on `listener`; returns its connection id, or `None` to refuse admission
    /// before reading bytes.
    fn on_accept(&mut self, listener: usize, peer: SocketAddr, now: Duration) -> Option<u64>;
    /// Dial finished.
    fn on_connected(&mut self, conn: u64, now: Duration);
    /// Dial failed.
    fn on_dial_failed(&mut self, conn: u64, refused: bool, now: Duration);
    /// Preserve the write side after peer FIN. OSDs retain their existing full
    /// teardown semantics; raw socket adapters opt into TCP half-close.
    #[inline(always)]
    fn keep_half_open(&self) -> bool {
        false
    }
    /// Peer FIN after all held input has been delivered.
    fn on_eof(&mut self, conn: u64, now: Duration) {
        self.on_closed(conn, now);
    }
    /// Connection gone.
    fn on_closed(&mut self, conn: u64, now: Duration);
    /// Bytes received.
    fn on_bytes(&mut self, conn: u64, data: &[u8], now: Duration);
    /// Next socket command.
    fn poll_io(&mut self) -> Option<IoCmd>;
    /// Decline an RDMA command (`IoCmd::Rdma*`): the connection stays on TCP. Default: ignore (drivers whose command source never
    /// emits RDMA, such as test mocks).
    fn rdma_decline(&mut self, _cmd: IoCmd, _now: Duration) {}
    /// Answers to `IoCmd::RdmaPrepare` / `RdmaAccept` / `RdmaConnect` (see the `Osd` methods of the same name); false = the
    /// connection moved on. Default: never applied.
    #[cfg(feature = "rdma")]
    fn rdma_prepared(&mut self, _conn: u64, _endpoint: Option<Vec<u8>>, _now: Duration) -> bool {
        false
    }
    /// See [`rdma_prepared`](Self::rdma_prepared).
    #[cfg(feature = "rdma")]
    fn rdma_accepted(&mut self, _conn: u64, _endpoint: Option<Vec<u8>>, _now: Duration) -> bool {
        false
    }
    /// See [`rdma_prepared`](Self::rdma_prepared).
    #[cfg(feature = "rdma")]
    fn rdma_connected(&mut self, _conn: u64, _now: Duration) -> bool {
        false
    }
    /// The transport refused the placement preflight (no WRITE was posted): the link sends the
    /// ordered error with RETIRED and no data, then vacates the attempt. SEND/SQ
    /// backpressure retains the attempt instead of invoking this callback. Default: ignore.
    #[cfg(feature = "rdma")]
    fn placement_preflight_refused(&mut self, _conn: u64, _tid: u64, _retry: u32) {}
    /// The transport completed the placement WRITEs and retired their sources: the link encodes
    /// the placed reply (receipt in the middle, empty data) and vacates the attempt. Default: ignore.
    #[cfg(feature = "rdma")]
    fn placement_success(&mut self, _conn: u64, _tid: u64, _retry: u32, _receipt: Vec<u8>) {}
    /// The transport processed a matching CANCEL (WRITE admission closed, accepted WRITE CQEs
    /// drained): the link sends the RETIRED as a placement control frame and vacates the
    /// attempt. Default: ignore.
    #[cfg(feature = "rdma")]
    fn placement_cancelled(&mut self, _conn: u64, _tid: u64, _retry: u32) {}
    /// The transport lost the QP (a failed or missing CQE, QP loss): no success or RETIRED is
    /// possible, the connection faults and the client retains its window. The link vacates the
    /// attempt. Default: ignore.
    #[cfg(feature = "rdma")]
    fn placement_fault(&mut self, _conn: u64, _tid: u64, _retry: u32) {}
    /// A source-pull PUT READ finished (adr 0665): the pulled bytes, or the
    /// negative errno that prevented them. The OSD verifies the crc32c and stages them as
    /// the held write's data. Default: ignore (a driver without the extension
    /// never receives the command).
    #[cfg(feature = "rdma")]
    fn source_pull_done(&mut self, _conn: u64, _tid: u64, _result: Result<Bytes, i32>) {}
    /// Pending output of `conn` as ordered shared runs.
    fn poll_output_chunks(&mut self, conn: u64) -> Vec<Bytes>;
    /// Transfer output into retained transport descriptors. Default preserves
    /// the existing OSD Vec path; socket facades may drain reusable descriptors.
    #[inline(always)]
    fn poll_output_into(&mut self, conn: u64, out: &mut std::collections::VecDeque<Bytes>) {
        out.extend(self.poll_output_chunks(conn));
    }
    /// Bytes accepted by the socket, reported once per send completion that wrote any (a spread send job also
    /// reports the prefix it wrote before a failure).
    /// The default compiles away for services without write receipts.
    #[inline(always)]
    fn output_written(&mut self, _conn: u64, _bytes: usize) {}
    /// Next connection whose output became ready (deduplicated by the driver).
    fn poll_output_ready(&mut self) -> Option<u64>;
    /// Bytes of a message data segment still to come on `conn` that may be received straight into the segment buffer
    /// (0 = not now). Default: never.
    fn rx_direct_want(&mut self, _conn: u64) -> usize {
        0
    }
    /// Lend the partially filled segment buffer (capacity for the rest) and its running crc32c to the transport.
    fn rx_direct_take(&mut self, _conn: u64) -> Option<(msgr2::SegBuf, crc::BlockCrcs)> {
        None
    }
    /// The lent buffer is complete; `crc` = running crc32c over all of it.
    fn rx_direct_put(
        &mut self,
        _conn: u64,
        _v: msgr2::SegBuf,
        _crc: crc::BlockCrcs,
        _now: Duration,
    ) {
    }
    /// Account for bytes received into a loan without authenticating or dispatching.
    fn on_rx_progress(&mut self, _conn: u64, _now: Duration) {}
    /// Remaining secure-frame ciphertext eligible for decoder-owned buffer receive.
    fn rx_secure_want(&mut self, _conn: u64) -> usize {
        0
    }
    /// Lend initialized decoder storage, never unauthenticated payload to an actor.
    fn rx_secure_take(&mut self, _conn: u64) -> Option<msgr2::SecureRxBuffer> {
        None
    }
    /// Return a complete frame for normal authentication and delivery.
    fn rx_secure_put(&mut self, _conn: u64, _buffer: msgr2::SecureRxBuffer, _now: Duration) {}
    /// Our stable service id when `conn` is a dial to a peer OSD (the peer's owner core for our sessions is `id % its cores`).
    fn dial_owner(&self, _conn: u64) -> Option<u32> {
        None
    }
}
