// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Service-neutral socket commands shared by daemon transports.
use bytes::Bytes;
use denc::types::EntityAddr;
use rdma::placement::WindowDescriptor;
use std::net::IpAddr;

/// Socket operations for the driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IoCmd {
    /// Open TCP to `target`, then `on_connected` / `on_dial_failed`.
    Dial {
        /// Connection id.
        conn: u64,
        /// Target.
        target: EntityAddr,
        /// Local address the socket binds before connecting: the messenger's own address of the target's family (spec
        /// 4 / adr 0171). `None` = we hold no address of that family; the socket stays unbound rather than binding a
        /// cross-family source (spec 8).
        src: Option<IpAddr>,
    },
    /// Close the socket of `conn`.
    Close {
        /// Connection id.
        conn: u64,
    },
    /// Source-pull PUT (adr 0665): READ `length` bytes from the peer's READ-only
    /// `source` key into one registered destination of this core and answer with
    /// the driver's `source_pull_done`. `crc32c` is the client's checksum over exactly
    /// that range (absent for a device source); the OSD verifies it before the write
    /// reaches the store.
    SourcePullRead {
        /// Connection id.
        conn: u64,
        /// Request tid (identifies the held op).
        tid: u64,
        /// Client address the OSD reads from.
        source: u64,
        /// READ-only remote key.
        rkey: u32,
        /// Bytes to read.
        length: u32,
        /// Client crc32c over the range; `None` for a device source.
        crc32c: Option<u32>,
    },
    /// RDMA upgrade, client role (msgr2 spec 18): prepare a QP for `conn`, answer with the service's `rdma_prepared` callback
    /// (`None` = no QP, the connection stays on TCP).
    RdmaPrepare {
        /// Connection id.
        conn: u64,
    },
    /// RDMA upgrade, server role: the peer of `conn` offers `endpoint`. Create a QP, connect it to the endpoint (RTR) and
    /// answer with the service's `rdma_accepted` callback (`None` declines). After an accept the connection's output ends on TCP
    /// with the accept frame; everything later goes over the QP. The socket stays open without data until the connection
    /// ends (liveness channel, spec 18).
    RdmaAccept {
        /// Connection id.
        conn: u64,
        /// The peer's QP endpoint (opaque to the OSD).
        endpoint: Vec<u8>,
    },
    /// RDMA upgrade, client role: the server accepted with `endpoint`. Connect the prepared QP (RTS; the socket stays open
    /// without data as liveness channel), then the service's `rdma_connected` callback; the session handshake continues over the QP. A failure closes the connection
    /// (the service's `on_closed` callback).
    RdmaConnect {
        /// Connection id.
        conn: u64,
        /// The server's QP endpoint (opaque to the OSD).
        endpoint: Vec<u8>,
    },
    /// RDMA upgrade, client role: the server declined; release the QP prepared for `conn`. The connection goes on over TCP.
    RdmaRelease {
        /// Connection id.
        conn: u64,
    },
    /// Placement WRITE-to-reply handoff (spec rdma-placement-runtime.md): the terminal owner hands the
    /// reply's original source pieces and the checked destination grant to the connection's RC QP. The
    /// transport prefights the pieces, posts the WRITEs in destination order, waits for every WRITE CQE and
    /// reports the terminal outcome back to the link (`placement_success` / `placement_cancelled` /
    /// `placement_fault` / `placement_preflight_refused`), which encodes and sends the reply. The attempt
    /// stays live until the outcome is reported; the pieces remain owned by the transport until CQ retirement.
    PlaceReadReply {
        /// Connection id.
        conn: u64,
        /// The op's transaction id.
        tid: u64,
        /// The attempt's retry number.
        retry: u32,
        /// The checked destination grant recorded at admission.
        grant: WindowDescriptor,
        /// The original source pieces in destination order.
        pieces: Vec<Bytes>,
        /// The store-verified seed-0 block CRCs (4096-byte grid, incl. the final partial block).
        block_crcs: Vec<u32>,
        /// The placed length (sum of the pieces; 0 for a zero-byte EOF).
        len: u64,
    },
    /// A matching CANCEL for a live placement attempt: close WRITE admission on the
    /// connection's RC QP, wait for the accepted WRITE CQEs, and send RETIRED on the same SQ.
    /// The attempt stays live until the transport reports `placement_cancelled`.
    PlaceReadCancel {
        /// Connection id.
        conn: u64,
        /// The op's transaction id.
        tid: u64,
        /// The attempt's retry number.
        retry: u32,
    },
}
