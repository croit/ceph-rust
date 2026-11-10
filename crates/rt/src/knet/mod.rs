// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Kernel TCP tier (adr 0053): statically dispatched service drivers over one io_uring per core.
//! The OSD uses four listeners; a raw socket facade can use a different fixed listener set.
//! Works on any NIC (bonding, VLAN, routing, firewall, same-host reachability are the kernel's business).
//!
//! Per core: multishot accept on the core's own `SO_REUSEPORT` listeners ([`listen`]), multishot recv into a provided
//! buffer ring ([`bufring`]), one `SENDMSG` (or `SENDMSG_ZC` for large batches) in flight per connection with the runs
//! the OSD produced as iovecs (no copy into a staging buffer), connect from the owning core with a link timeout. The
//! ring is created with `SINGLE_ISSUER | COOP_TASKRUN | TASKRUN_FLAG` where the kernel has them: no IPIs, completions
//! are reaped from shared memory and the kernel is entered only to submit or when it flags pending task work.
//!
//! Driver contract: `on_accept/on_connected/on_dial_failed/on_closed/on_bytes` into the OSD, output polled only when a connection has nothing in flight (backpressure stays in the OSD,
//! bytes are never dropped), `IoCmd::Close` is graceful (queued output first, then FIN).
mod bufring;
mod capability;
#[cfg(feature = "cut-probe")]
mod cutprobe;
pub use capability::{IoUringReport, report as probe_iouring};
mod kcore;
#[cfg(feature = "rdma")]
mod kpull;
#[cfg(feature = "rdma")]
mod krdma;
mod listen;
mod spread;
pub mod zcrx;
mod zrx;

#[cfg(feature = "rdma")]
pub use ::rdma::status::Setup as RdmaSetup;
pub use kcore::KCore;
#[cfg(feature = "rdma")]
pub use kpull::ARENA as RDMA_PULL_ARENA;
#[cfg(feature = "rdma")]
pub use krdma::{Hub as RdmaHub, KRdma, process as rdma_process, start as rdma_start};
pub use listen::{Binds, KINDS, ListenOpts, Steer, bind_all, bind_all_with, bind_listeners};
pub use spread::{KSpread, mesh as spread_mesh};

/// Accept-time placement of public connections over the cores of this OSD ([`crate::place`]): a hand-off is an
/// accepted socket.
pub type KPlace = crate::place::Place<Adopt>;

/// An accepted socket on its way to another core.
#[derive(Debug)]
pub struct Adopt {
    fd: OwnedFd,
    /// Flat listener entry (index into `KNet::lst`) it was accepted on.
    l: usize,
    peer: SocketAddr,
}

use crate::FxMap;
use bufring::{BGID, BufRing, Provide, Spill};
use bytes::{Buf, Bytes};
use io_uring::cqueue;
use io_uring::opcode;
use io_uring::squeue::{Entry, Flags};
use io_uring::types::{CancelBuilder, Fd, Timespec};
use io_uring::{IoUring, Probe};
use listen::{setopt, sockaddr};
use osd::{Backend, Osd};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

pub use crate::stream::{Driver, IoCmd};

impl<B: Backend> Driver for Osd<B> {
    fn admission_ready(&self) -> bool {
        Osd::admission_ready(self)
    }
    fn input_ready(&self, conn: u64) -> bool {
        Osd::input_ready(self, conn)
    }
    fn resume_inputs(&mut self, now: Duration) -> bool {
        Osd::resume_inputs(self, now)
    }
    fn input_resumable(&self) -> bool {
        Osd::input_resumable(self)
    }
    fn rx_parked(&self, conn: u64) -> bool {
        Osd::rx_parked(self, conn)
    }
    #[inline(always)]
    fn on_accept(&mut self, l: usize, peer: SocketAddr, now: Duration) -> Option<u64> {
        Some(Osd::on_accept(self, KINDS[l], peer, now))
    }
    fn on_connected(&mut self, conn: u64, now: Duration) {
        Osd::on_connected(self, conn, now)
    }
    fn on_dial_failed(&mut self, conn: u64, refused: bool, now: Duration) {
        Osd::on_dial_failed(self, conn, refused, now)
    }
    fn on_closed(&mut self, conn: u64, now: Duration) {
        Osd::on_closed(self, conn, now)
    }
    fn on_bytes(&mut self, conn: u64, data: &[u8], now: Duration) {
        Osd::on_bytes(self, conn, data, now)
    }
    fn poll_io(&mut self) -> Option<IoCmd> {
        Osd::poll_io(self)
    }
    fn rdma_decline(&mut self, cmd: IoCmd, now: Duration) {
        Osd::rdma_decline(self, cmd, now)
    }
    #[cfg(feature = "rdma")]
    fn rdma_prepared(&mut self, conn: u64, endpoint: Option<Vec<u8>>, now: Duration) -> bool {
        Osd::rdma_prepared(self, conn, endpoint, now)
    }
    #[cfg(feature = "rdma")]
    fn rdma_accepted(&mut self, conn: u64, endpoint: Option<Vec<u8>>, now: Duration) -> bool {
        Osd::rdma_accepted(self, conn, endpoint, now)
    }
    #[cfg(feature = "rdma")]
    fn rdma_connected(&mut self, conn: u64, now: Duration) -> bool {
        Osd::rdma_connected(self, conn, now)
    }
    #[cfg(feature = "rdma")]
    fn placement_preflight_refused(&mut self, conn: u64, tid: u64, retry: u32) {
        Osd::placement_preflight_refused(self, conn, tid, retry)
    }
    #[cfg(feature = "rdma")]
    fn placement_success(&mut self, conn: u64, tid: u64, retry: u32, receipt: Vec<u8>) {
        Osd::placement_success(self, conn, tid, retry, receipt)
    }
    #[cfg(feature = "rdma")]
    fn placement_cancelled(&mut self, conn: u64, tid: u64, retry: u32) {
        Osd::placement_cancelled(self, conn, tid, retry)
    }
    #[cfg(feature = "rdma")]
    fn placement_fault(&mut self, conn: u64, tid: u64, retry: u32) {
        Osd::placement_fault(self, conn, tid, retry)
    }
    #[cfg(feature = "rdma")]
    fn source_pull_done(&mut self, conn: u64, tid: u64, result: Result<Bytes, i32>) {
        Osd::source_pull_done(self, conn, tid, result)
    }
    fn poll_output_chunks(&mut self, conn: u64) -> Vec<Bytes> {
        Osd::poll_output_chunks(self, conn)
    }
    fn poll_output_ready(&mut self) -> Option<u64> {
        Osd::poll_output_ready(self)
    }
    fn rx_direct_want(&mut self, conn: u64) -> usize {
        Osd::rx_direct_want(self, conn)
    }
    fn rx_direct_take(&mut self, conn: u64) -> Option<(msgr2::SegBuf, crc::BlockCrcs)> {
        Osd::rx_direct_take(self, conn)
    }
    fn rx_direct_put(&mut self, conn: u64, v: msgr2::SegBuf, crc: crc::BlockCrcs, now: Duration) {
        Osd::rx_direct_put(self, conn, v, crc, now)
    }
    fn on_rx_progress(&mut self, conn: u64, now: Duration) {
        Osd::rx_progress(self, conn, now)
    }
    fn rx_secure_want(&mut self, conn: u64) -> usize {
        Osd::rx_secure_want(self, conn)
    }
    fn rx_secure_take(&mut self, conn: u64) -> Option<msgr2::SecureRxBuffer> {
        Osd::rx_secure_take(self, conn)
    }
    fn rx_secure_put(&mut self, conn: u64, buffer: msgr2::SecureRxBuffer, now: Duration) {
        Osd::rx_secure_put(self, conn, buffer, now)
    }
    fn dial_owner(&self, conn: u64) -> Option<u32> {
        Osd::dial_owner(self, conn)
    }
}

/// Tunables of one core's transport.
#[derive(Clone, Debug)]
pub struct KCfg {
    /// Reserve one socket slot before rearming accept. Socket facades opt in;
    /// OSD listeners retain multishot admission by default.
    pub bounded_accept: bool,
    /// Tests: use classic provided buffers even where the ring registers (covers the fallback on every kernel).
    #[cfg(test)]
    pub(crate) force_classic: bool,
    /// SQ entries (CQ = 4x).
    pub entries: u32,
    /// Receive buffers per core (power of two).
    pub bufs: u16,
    /// Bytes per receive buffer.
    pub buf_size: u32,
    /// Batches of at least this many bytes (runs >= 16 KiB on average) go out with `SENDMSG_ZC` (0 = never). Zero copy only pays on a real NIC and
    /// for large frames; the kernel falls back to copying on loopback.
    pub zc_min: usize,
    /// Connect timeout.
    pub connect_timeout: Duration,
    /// Time a gracefully closed connection may take to drain its output before it is cut.
    pub close_linger: Duration,
    /// Data segments with at least this many bytes still to come are received straight into the segment buffer (one
    /// copy: kernel -> buffer, crc while it is cache hot) instead of through the buffer ring (0 = off).
    pub direct_min: usize,
    /// Receive spread (am. 3): the rest of a data segment with at least this many bytes still to come is received by
    /// another core of the OSD (its copy + crc leave the connection's core); 0 = off. Needs the mesh (`set_spread`).
    /// Default 256 KiB (am. 4).
    pub spread_min: usize,
    /// After a direct receive the connection's next ring receives are one-shot (one provided buffer, at most
    /// `buf_size` bytes) for this many completions: the next big segment is detected after its first buffer and goes
    /// direct without a multishot cancel, instead of a multishot recv draining up to 32 buffers of it through the ring
    /// (kernel copy + decoder copy). 0 = always multishot. Default 8.
    pub bigshot: u32,
    /// Peer steering: our dials bind a source port that selects our owner core on a peer with this many cores (see
    /// `ListenOpts::port_steer`; homogeneous clusters: the peer's core count); 0 or 1 = off.
    pub peer_cores: u32,
    /// `SO_SNDBUF`/`SO_RCVBUF` bytes on dialed sockets (0 = autotuning).
    pub sockbuf: u32,
    /// One send request carries at most this many bytes (0 = whole queue, up to 32 runs).
    pub send_chunk: usize,
    /// Device-wait parking: percent (default 10, adr 0162 am. 2) of the learned short-IO latency an idle core sleeps in the ring after a store
    /// span starts (0 = off; adr 0162).
    pub store_park_pct: u32,
    /// Device-wait park with a store backend whose completions wake the ring (`kernel:` devices, adr 0169): percent of the
    /// learned latency slept on a timer before polling; 100 (default) = sleep until the completion wakes the core.
    pub store_irq_park_pct: u32,
}

/// Autotuning ceiling of a socket's receive queue: the max of `net.ipv4.tcp_rmem` (of this network namespace).
fn tcp_rmem_max() -> io::Result<usize> {
    let s = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_rmem")?;
    s.split_whitespace()
        .nth(2)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("net.ipv4.tcp_rmem: {s:?}"),
            )
        })
}

fn env_num(k: &str) -> Option<u64> {
    std::env::var(k).ok().and_then(|v| v.parse().ok())
}

impl Default for KCfg {
    fn default() -> Self {
        KCfg {
            bounded_accept: false,
            entries: 1024,
            bufs: 512,
            buf_size: 64 << 10,
            zc_min: 0,
            connect_timeout: Duration::from_secs(5),
            close_linger: Duration::from_secs(5),
            direct_min: DIRECT_MIN,
            // lab build of the cut-through probe: it stamps only receives on the connection's core (`NV_KNET_SPREAD=0`)
            #[cfg(feature = "cut-probe")]
            spread_min: env_num("NV_KNET_SPREAD").map_or(SPREAD_MIN, |v| v as usize),
            #[cfg(not(feature = "cut-probe"))]
            spread_min: SPREAD_MIN,
            bigshot: BIGSHOT,
            peer_cores: 0,
            sockbuf: 0,
            send_chunk: 0,
            store_park_pct: STORE_PARK_PCT,
            store_irq_park_pct: 100,
            #[cfg(test)]
            force_classic: false,
        }
    }
}

/// Counters (diagnostics, bench).
#[derive(Clone, Copy, Debug, Default)]
pub struct KStats {
    /// Accepted connections (owned by this core, incl. adopted ones).
    pub accepted: u64,
    /// Public connections accepted here and handed to a less loaded core / adopted from another core (`KPlace`).
    pub placed_away: u64,
    /// Adopted from another core.
    pub adopted: u64,
    /// Dials started.
    pub dialed: u64,
    /// Bytes received.
    pub rx_bytes: u64,
    /// Bytes sent.
    pub tx_bytes: u64,
    /// Receive completions.
    pub rx_cqes: u64,
    /// Send completions.
    pub tx_cqes: u64,
    /// Sends submitted as zero copy.
    pub zc_sends: u64,
    /// Receive re-arms after the buffer pool ran dry.
    pub nobufs: u64,
    /// Classic provided buffers: `PROVIDE_BUFFERS` entries the kernel rejected (their ids are given again).
    pub provide_errs: u64,
    /// `io_uring_enter` calls; of them at the start of a poll (queued SQEs + task work), by `submit` (end of an
    /// iteration) and by the idle sleep (`wait`); poll = its start + its re-reap passes.
    pub enters: u64,
    pub enters_poll: u64,
    pub enters_submit: u64,
    /// Enters of send-first window closes (repops leave before the held-back local txn applies).
    pub enters_sf: u64,
    pub enters_wait: u64,
    /// Direct receives started (ring recv cancelled, segment buffer lent).
    pub direct_starts: u64,
    /// Bytes received straight into segment buffers.
    pub direct_bytes: u64,
    /// Segment rests handed to a helper core (receive spread).
    pub spread_jobs: u64,
    /// Jobs received here for another core.
    pub spread_served: u64,
    /// Bytes received here for other cores.
    pub spread_bytes: u64,
    /// Send spread: copied batches larger than `SEND_SPREAD_MIN` handed to the mesh (incl. the ones this core took itself).
    pub send_jobs: u64,
    /// Send jobs executed here for another core.
    pub send_served: u64,
    /// Bytes sent here for other cores.
    pub send_served_bytes: u64,
    /// Send jobs not spread (no core with room).
    pub send_full: u64,
    /// Big segments detected on a one-shot ring receive (direct without a multishot cancel, `KCfg::bigshot`).
    pub bigshots: u64,
    /// Direct segments started on a connection whose softirq runs on this core's CPU.
    pub rx_coloc: u64,
    /// Public connections placed off the core of their softirq CPU.
    pub placed_off_rx: u64,
    /// Receive pauses: episodes in which a connection's socket was left unread because the OSD did not take input.
    pub rx_pauses: u64,
    /// Summed duration of the receive pauses (ns), counted at resume.
    pub rx_pause_ns: u64,
    /// Longest receive pause (ns).
    pub rx_pause_max_ns: u64,
    /// Ring receives completed into hold storage while the OSD did not take input (the socket kept draining).
    pub rx_held: u64,
    /// Receive pauses started because hold storage had no room (`KNet::hold_room`: budget reached or out of buffers).
    pub rx_hold_full: u64,
    /// Of `rx_hold_full`: the hold budget (sum of the connections' rcvbuf bounds) was reached; the rest = out of buffers.
    pub rx_hold_budget: u64,
    /// Extra submit + reap passes of `poll` because a direct receive filled its whole piece (`KNet::rx_more`).
    pub rx_more_passes: u64,
    /// Longest handling of one completion (ns; the OSD work an input completion drives inline) and its kind (`K_*`).
    pub cqe_max_ns: u64,
    pub cqe_max_kind: u64,
    /// The same since the core loop last cleared it (`NV_PHASE` stall lines: the longest completion of one iteration).
    pub cqe_peak_ns: u64,
    pub cqe_peak_kind: u64,
}

/// Name of a completion kind (`K_*`) in diagnostics.
pub(crate) fn cqe_kind_name(kind: u64) -> &'static str {
    match kind {
        K_ACCEPT => "accept",
        K_ACCEPT_READY => "accept_ready",
        K_RECV => "recv",
        K_SEND => "send",
        K_CONN => "conn",
        K_DRECV => "drecv",
        K_WAKE => "wake",
        K_HRECV => "hrecv",
        K_STORE => "store",
        #[cfg(feature = "rdma")]
        K_RDMA => "rdma",
        K_PBUF => "pbuf",
        K_ZWAKE => "zwake",
        K_HSEND => "hsend",
        _ => "other",
    }
}

/// Completions `poll` takes off the ring per pass.
const CQ_BATCH: usize = 128;
const K_IGN: u64 = 0;
const K_ACCEPT: u64 = 1;
const K_RECV: u64 = 2;
const K_SEND: u64 = 3;
const K_CONN: u64 = 4;
const K_DRECV: u64 = 5;
const K_WAKE: u64 = 6;
const K_HRECV: u64 = 7;
/// Readiness of the store device ring (adr 0169): one-shot poll armed before an idle sleep with store IO in flight.
const K_STORE: u64 = 8;
/// Readiness of an RDMA CQ channel (the plane in the slot field): one-shot poll armed before an idle sleep.
#[cfg(feature = "rdma")]
const K_RDMA: u64 = 9;
/// Classic provided buffers (`bufring::Provide::Classic`): a `PROVIDE_BUFFERS` entry, slot = first id, seq = count.
const K_PBUF: u64 = 10;
/// The zcrx ring's eventfd fired (its completions are reaped in the zcrx phase of `poll`).
const K_ZWAKE: u64 = 11;
/// A send of another core's connection executed here (send spread, `spread::SendJob`); slot = run slot.
const K_HSEND: u64 = 12;
/// Bounded listeners wait for readiness without consuming an application slot.
const K_ACCEPT_READY: u64 = 13;
/// Bound of the drop-time drain of in-flight requests ([`KNet::retire`]); beyond it their memory is leaked (loud).
const DROP_DRAIN_LIMIT: Duration = Duration::from_secs(5);
/// Default of `KCfg::direct_min`.
const DIRECT_MIN: usize = 128 << 10;
/// Default of `KCfg::bigshot` (adr 0053 am. 3: 1-stream 4M write +44 %, rep3 4x16 +19 %, 4K unchanged).
const BIGSHOT: u32 = 8;
/// Default of `KCfg::spread_min` (am. 4: only segments of streams whose softirq shares the core).
const SPREAD_MIN: usize = 256 << 10;
/// Default device-wait park fraction (percent), see `KCfg::store_park_pct`.
const STORE_PARK_PCT: u32 = 10;
/// Bytes of one direct receive request (crc runs over each piece while it is cache hot).
const DIRECT_CHUNK: usize = 256 << 10;
const MAX_IOV: usize = 32;
/// Zero-copy sends need runs of at least this many bytes on average (see `KCfg::zc_min`).
const ZC_RUN: usize = 16 << 10;
/// Back-off of an accept that failed for lack of resources (EMFILE, ENOMEM, ...): retried after this, not in a tight loop.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

fn ud(kind: u64, slot: u32, seq: u32) -> u64 {
    kind | (u64::from(slot) << 4) | (u64::from(seq) << 32)
}

/// Heap state of one in-flight send (stable addresses for the kernel).
struct SendState {
    msg: libc::msghdr,
    iov: Vec<libc::iovec>,
    runs: Vec<Bytes>,
    zc: bool,
}

impl SendState {
    /// Empty send state with room for a full batch.
    fn boxed() -> Box<SendState> {
        Box::new(SendState {
            // SAFETY: all-zero msghdr is a valid empty message header.
            msg: unsafe { std::mem::zeroed() },
            iov: Vec::with_capacity(MAX_IOV),
            runs: Vec::with_capacity(MAX_IOV),
            zc: false,
        })
    }

    /// Rebuild the iovec of the runs still to send.
    fn fill_iov(&mut self) {
        self.iov.clear();
        self.iov.extend(self.runs.iter().map(|b| libc::iovec {
            iov_base: b.as_ptr() as *mut _,
            iov_len: b.len(),
        }));
        self.msg.msg_iov = self.iov.as_mut_ptr();
        self.msg.msg_iovlen = self.iov.len() as _;
    }

    /// `sendmsg` flags: plain sends carry `MSG_WAITALL` (the kernel retries short sends itself), zero-copy ones do not.
    fn send_flags(&self) -> u32 {
        (libc::MSG_NOSIGNAL | if self.zc { 0 } else { libc::MSG_WAITALL }) as u32
    }
}

struct Dial {
    addr: libc::sockaddr_storage,
    len: libc::socklen_t,
    timeout: Timespec,
}

/// Receive mode of a connection.
enum Rx {
    /// Peer FIN; socket facade may still send.
    Eof,
    /// Multishot recv into the buffer ring.
    Multi,
    /// A cancel of the multishot recv is in flight; its final completion decides what comes next.
    Cancelling,
    /// Single recvs straight into a segment buffer lent by the OSD.
    Direct(DirectRx),
    /// The segment buffer is out on a helper core that receives the rest (receive spread).
    Away,
}

/// A segment buffer being filled from the socket (stable heap memory: the kernel writes into it until the last request
/// of the connection completed, the connection slot owns it meanwhile).
enum DirectRx {
    Crc {
        v: msgr2::SegBuf,
        crc: crc::BlockCrcs,
        left: usize,
    },
    Secure(msgr2::SecureRxBuffer),
}

impl DirectRx {
    /// Take the segment buffer the OSD wants filled next (crc segment first, else secure), if one has at least `min`
    /// bytes still to come.
    fn take<D: Driver>(d: &mut D, id: u64, min: usize) -> Option<Self> {
        let crc_want = d.rx_direct_want(id);
        if crc_want >= min {
            d.rx_direct_take(id).map(|(v, crc)| Self::Crc {
                v,
                crc,
                left: crc_want,
            })
        } else if d.rx_secure_want(id) >= min {
            d.rx_secure_take(id).map(Self::Secure)
        } else {
            None
        }
    }
    /// Hand the filled segment buffer back to the OSD.
    fn put<D: Driver>(self, d: &mut D, id: u64, now: Duration) {
        match self {
            Self::Crc { v, crc, .. } => d.rx_direct_put(id, v, crc, now),
            Self::Secure(buffer) => d.rx_secure_put(id, buffer, now),
        }
    }
    fn remaining(&self) -> usize {
        match self {
            Self::Crc { left, .. } => *left,
            Self::Secure(buffer) => buffer.remaining(),
        }
    }
    fn receive_pointer(&mut self) -> *mut u8 {
        match self {
            Self::Crc { v, left, .. } => {
                // the kernel writes up to `left` bytes here: the bound is checked in release builds too (one compare
                // per receive request), `left` and the loan's capacity come from different functions
                assert!(
                    v.capacity() - v.len() >= *left,
                    "direct receive of {left} bytes into {} spare",
                    v.capacity() - v.len()
                );
                // SAFETY: the loan has spare capacity for `left` bytes (checked above).
                unsafe { v.as_mut_ptr().add(v.len()) }
            }
            Self::Secure(buffer) => buffer.recv_buf().as_mut_ptr(),
        }
    }
    fn commit(&mut self, n: usize) {
        assert!(n <= self.remaining());
        match self {
            Self::Crc { v, crc, left } => {
                let at = v.len();
                // SAFETY: the constrained completed recv initialized exactly n bytes.
                unsafe { v.set_len(at + n) };
                crc.update(&v[at..]);
                *left -= n;
            }
            Self::Secure(buffer) => buffer.commit(n),
        }
    }
}

struct Conn {
    /// This socket's received bytes in hold storage (input paused), in stream order. Owned by the socket: they are
    /// released with it and can never reach another socket's decoder, even one that reuses the connection id (msgr2
    /// redials a lossless session under the same id).
    held: VecDeque<(HeldBuf, usize)>,
    /// Bytes the kernel may queue on this socket at most (its rcvbuf bound): its share of the hold budget.
    rmem: usize,
    fd: RawFd,
    id: u64,
    dialing: bool,
    /// The OSD knows the connection is gone (or closed it itself): no more callbacks.
    reported: bool,
    dying: bool,
    closing: Option<Duration>,
    /// Submitted requests that have not posted their final completion yet.
    inflight: u32,
    sending: bool,
    /// The send batch is out as a send job on a spread core's ring (`KNet::send_out`): that core names this fd.
    send_away: bool,
    out: VecDeque<Bytes>,
    /// The peer is an address of this host (loopback route): sends never go zero copy (see `submit_send`).
    local_peer: bool,
    st: Box<SendState>,
    zc_seq: u32,
    /// Zero-copy batches whose notification has not arrived yet: `seq` and the runs they were sent from (their pages
    /// are in flight until then).
    zc_hold: Vec<(u32, Vec<Bytes>)>,
    /// Run vectors handed back by notifications, reused for the next hold entry (no allocation per completion).
    zc_spare: Vec<Vec<Bytes>>,
    dial: Option<Box<Dial>>,
    rx: Rx,
    rx_paused: bool,
    /// Start of the current receive pause (diagnostics, `KStats::rx_pause_*`).
    paused_at: Option<Duration>,
    /// Accepted on the public listener (a client socket; diagnostics).
    public: bool,
    /// One-shot ring receives left before the connection goes back to multishot (`KCfg::bigshot`).
    shots: u32,
    /// The current direct segment may be spread (its softirq runs on this CPU).
    spread_ok: bool,
    #[cfg(feature = "cut-probe")]
    probe: cutprobe::ConnProbe,
    /// RDMA upgrade state (the socket stays the connection's slot owner; the QP carries the stream after the switch).
    #[cfg(feature = "rdma")]
    rdma: krdma::ConnRdma,
    /// The stream arrives through `RECV_ZC` on the zcrx ring (adr 0464), never through the knet ring.
    zrx: bool,
    /// A `RECV_ZC` of this connection is in flight.
    zarmed: bool,
    /// Fragments held while the OSD takes no input.
    zpend: zcrx::book::Pending,
}

impl Conn {
    /// Stop reading the socket until `KNet::resume_rx` finds the OSD ready again.
    fn pause(&mut self, stats: &mut KStats, now: Duration) {
        self.rx_paused = true;
        if self.paused_at.is_none() {
            self.paused_at = Some(now);
            stats.rx_pauses += 1;
        }
    }

    /// Reading goes on; accounts the pause.
    fn resume(&mut self, stats: &mut KStats, now: Duration) {
        self.rx_paused = false;
        if let Some(t) = self.paused_at.take() {
            let ns = now.saturating_sub(t).as_nanos() as u64;
            stats.rx_pause_ns += ns;
            stats.rx_pause_max_ns = stats.rx_pause_max_ns.max(ns);
        }
    }
}

/// A paused receive keeps either its original lease or a slot from fixed overflow storage.
#[derive(Debug, Clone, Copy)]
enum HeldBuf {
    Provided(u16),
    Spill(u16),
}

/// How an idle ring sleep of [`KNet::wait_if`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waited {
    /// The sleep ran into its timeout (no completion, no poke ended it).
    pub timed_out: bool,
    /// ns from the first mesh poke to the end of the sleep (`None`: no poke).
    pub poke_ns: Option<u64>,
}

#[derive(Clone, Copy, Default)]
struct AcceptState {
    retry: bool,
    paused: bool,
    armed: bool,
    ready: bool,
}

/// One core's transport: ring, buffers, listeners, connections.
pub struct KNet<const N: usize = 4> {
    ring: IoUring,
    bufs: BufRing,
    spill: Spill,
    held_provided: usize,
    /// Bytes in hold storage (`Conn::held` of all connections).
    held_bytes: usize,
    /// Hold budget: sum of the live connections' `rmem`, i.e. the memory the kernel commits to these sockets anyway with
    /// full receive queues. Holding up to it keeps the kernel queues empty without using more memory than unread sockets.
    hold_budget: usize,
    /// Autotuning rcvbuf ceiling (`net.ipv4.tcp_rmem` max).
    rmem_auto: usize,
    cfg: KCfg,
    /// Flat listener list (service listener index, fd): one entry per addrvec entry (address family).
    lst: Vec<(usize, OwnedFd)>,
    slots: Vec<Option<Conn>>,
    free: Vec<u32>,
    by_id: FxMap<u64, u32>,
    zc: bool,
    /// Earliest deadline of [`tick`](Self::tick) work (accept retries, close linger cuts); `None` = none pending.
    tick_at: Option<Duration>,
    /// Per-address accept state and per-service reservations.
    accepts: Vec<AcceptState>,
    accept_armed: [usize; N],
    /// Source-port picker state and the usable local ports (read once when peer steering is on).
    rnd: u64,
    src_ports: listen::SrcPorts,
    wake: Option<(std::sync::Arc<crate::wake::Wake>, &'static mut u64)>,
    /// Accept-time placement over the cores of this OSD (`None` = every accepted connection stays).
    place: Option<KPlace>,
    /// Receive and send spread over the OSD's cores (`None` = off).
    spread: Option<KSpread>,
    /// Send states lent to connections whose own state is out in a send job (reused, no allocation per job).
    #[allow(clippy::vec_box)]
    // the boxes are lent to connections (`Conn::st`): their addresses stay stable
    spare_st: Vec<Box<SendState>>,
    /// Connections with bytes in hold storage (`Conn::held`), in the order they started holding; `resume_rx` delivers
    /// from them once the OSD takes input again. Entries of a socket that is gone are skipped (slot + id checked).
    held_conns: VecDeque<(u32, u64)>,
    paused_rx: VecDeque<(u32, u64)>,
    /// A direct receive of this reap pass filled its whole piece and the next piece is queued: the socket very likely holds
    /// more, so `poll` submits and reaps again instead of leaving it to the next core iteration (a socket drained by one
    /// piece per iteration falls behind a fast sender, fills to its rcvbuf and Linux drops + retracts its window).
    rx_more: bool,
    /// Completion batch of `poll`, kept between calls: a stack array is zero-filled (2 KiB memset) on every poll spin.
    cq_batch: Vec<(u64, i32, u32)>,
    /// Counters.
    pub stats: KStats,
    /// Ring setup flags actually in use (diagnostics).
    pub ring_mode: &'static str,
    /// SQE flags of classic `PROVIDE_BUFFERS` entries.
    pbuf_flags: Flags,
    /// Store device ring fd (adr 0169) and whether its one-shot poll is armed.
    store_ring: Option<(RawFd, bool)>,
    /// RDMA planes of this core (`None` = every RDMA command is declined).
    #[cfg(feature = "rdma")]
    rdma: Option<krdma::KRdma>,
    /// Upgraded or upgrading connections that were torn down: (plane, connection id, QPN, pull READs in flight) to release
    /// in the next RDMA phase.
    #[cfg(feature = "rdma")]
    rdma_dead: Vec<(usize, u64, Option<u32>, Vec<krdma::PullInFlight>)>,
    /// Slots with in-flight placement owners (driven in the CQ phase; empty = no placement work).
    #[cfg(feature = "rdma")]
    placement_slots: Vec<u32>,
    /// zcrx plan of the OSD (placement by NAPI id) and this core's zcrx state (`None` = copy receive).
    zplan: Option<std::sync::Arc<zcrx::Plan>>,
    zrx: Option<zcrx::ZCore>,
    /// NAPI id of this core's zcrx queue (0 = device-less: every accepted connection).
    znapi: u32,
    /// eventfd read target of the zcrx wake (stable: the kernel writes it until the ring is gone).
    zwake: Box<u64>,
    zwake_armed: bool,
    /// zcrx connections paused (input throttled) and those whose receive ended and needs a new one.
    zpaused: Vec<u32>,
    zrearm: Vec<u32>,
}

impl<const N: usize> std::fmt::Debug for KNet<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KNet")
            .field("conns", &self.by_id.len())
            .field("ring_mode", &self.ring_mode)
            .field("stats", &self.stats)
            .finish()
    }
}

/// Longest a full submission queue may take to make room before it is reported as stalled.
const SQ_STALL: Duration = Duration::from_secs(5);

/// Queue `e`; a full SQ is handed to the kernel first (`enters` counts those enters).
fn push_sqe(ring: &mut IoUring, enters: &mut u64, e: Entry) {
    push_sqe_bounded(ring, enters, e, SQ_STALL);
}

/// [`push_sqe`] with an explicit bound: a ring that takes no entry for `stall` is broken (closed ring fd, no
/// completion ever frees the SQ). It must never spin silently (`WARNING TIMEOUT`, then panic like a stalled SQ).
fn push_sqe_bounded<S, C>(ring: &mut IoUring<S, C>, enters: &mut u64, e: S, stall: Duration)
where
    S: io_uring::squeue::EntryMarker,
    C: io_uring::cqueue::EntryMarker,
{
    let mut stalled_since = None;
    loop {
        // SAFETY: every entry references memory that stays valid until its completion (Conn boxes / ring buffers).
        if unsafe { ring.submission().push(&e) }.is_ok() {
            return;
        }
        let since = stalled_since.get_or_insert_with(std::time::Instant::now);
        if since.elapsed() >= stall {
            eprintln!(
                "WARNING TIMEOUT io_uring submission queue exceeded {:.3}s (SQ full, no progress)",
                stall.as_secs_f64()
            );
            panic!("io_uring submission queue stalled");
        }
        *enters += 1;
        let _ = ring.submit(); // SQ full: hand the queue to the kernel, then retry
    }
}

/// Ring setup modes, best first. Each step drops one optional setup flag; `io_uring_setup` answers an unknown flag with
/// EINVAL, so the first mode the kernel accepts is the best it supports (capability probe, never a version check).
/// `DEFER_TASKRUN` (needs `SINGLE_ISSUER`): completion task work runs only inside our own enters (`kick` sees the
/// `TASKRUN` flag and enters with GETEVENTS), not as task-work interrupts of the core thread between syscalls.
const RING_MODES: [&str; 4] = [
    "single-issuer+defer-taskrun",
    "single-issuer+coop-taskrun",
    "coop-taskrun",
    "plain",
];

/// Setup flag a ring mode lacks compared to the mode before it (for the startup capability line).
pub(crate) fn ring_mode_missing(mode: &str) -> &'static [&'static str] {
    match mode {
        "single-issuer+defer-taskrun" => &[],
        "single-issuer+coop-taskrun" => &["DEFER_TASKRUN"],
        "coop-taskrun" => &["DEFER_TASKRUN", "SINGLE_ISSUER"],
        _ => &["DEFER_TASKRUN", "SINGLE_ISSUER", "COOP_TASKRUN"],
    }
}

/// `DEFER_TASKRUN` is used only when the kernel also raises the `TASKRUN` flag for deferred work: the spinning core
/// enters only on that flag (`kick`), so a kernel that queues deferred completions silently would starve it. Tested once
/// per process on a scratch ring: a receive armed on an AF_UNIX stream pair, one byte written; the write wakes the
/// receive's poll synchronously in this thread, so the flag must be up when `write` returns (no wait, no timing).
fn defer_taskrun_usable() -> bool {
    static USABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *USABLE.get_or_init(|| {
        let Ok(mut ring) = IoUring::<Entry, cqueue::Entry>::builder()
            .setup_single_issuer()
            .setup_defer_taskrun()
            .setup_taskrun_flag()
            .build(4)
        else {
            return false;
        };
        let mut fds = [0; 2];
        // SAFETY: fds is a valid out array of two ints.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        } < 0
        {
            return false;
        }
        // SAFETY: socketpair returned two new fds we own.
        let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let mut byte = [0u8; 1];
        let e = opcode::Recv::new(Fd(a.as_raw_fd()), byte.as_mut_ptr(), 1)
            .build()
            .user_data(1);
        // SAFETY: `byte` and `a` outlive the ring (dropped after it, below).
        if unsafe { ring.submission().push(&e) }.is_err() || ring.submit().is_err() {
            return false;
        }
        let no_flag = !ring.submission().taskrun();
        // SAFETY: valid fd and one-byte buffer.
        let wrote = unsafe { libc::write(b.as_raw_fd(), b"x".as_ptr().cast(), 1) } == 1;
        let flag = ring.submission().taskrun();
        drop(ring);
        drop((a, b));
        wrote && no_flag && flag
    })
}

fn make_ring(entries: u32) -> io::Result<(IoUring, &'static str)> {
    for (i, m) in RING_MODES.iter().enumerate() {
        if i == 0 && !defer_taskrun_usable() {
            continue;
        }
        let mut b = IoUring::builder();
        b.setup_cqsize(entries * 4).setup_submit_all();
        match i {
            0 => b
                .setup_single_issuer()
                .setup_defer_taskrun()
                .setup_taskrun_flag(),
            1 => b
                .setup_single_issuer()
                .setup_coop_taskrun()
                .setup_taskrun_flag(),
            2 => b.setup_coop_taskrun().setup_taskrun_flag(),
            _ => &mut b,
        };
        match b.build(entries) {
            Ok(r) => return Ok((r, m)),
            Err(e) if i + 1 < RING_MODES.len() && e.raw_os_error() == Some(libc::EINVAL) => {}
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

/// Peer address of the connected/accepted socket `fd` (either family).
fn peer_addr(fd: RawFd) -> Option<SocketAddr> {
    // SAFETY: zeroed sockaddr_storage is valid; getpeername fills at most `len` bytes.
    unsafe {
        let mut sa: libc::sockaddr_storage = std::mem::zeroed();
        let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getpeername(fd, (&raw mut sa).cast(), &mut len) < 0 {
            return None;
        }
        match i32::from(sa.ss_family) {
            libc::AF_INET => {
                let v4 = (&raw const sa).cast::<libc::sockaddr_in>();
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be((*v4).sin_addr.s_addr))),
                    u16::from_be((*v4).sin_port),
                ))
            }
            libc::AF_INET6 => {
                let v6 = (&raw const sa).cast::<libc::sockaddr_in6>();
                Some(SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::from((*v6).sin6_addr.s6_addr)),
                    u16::from_be((*v6).sin6_port),
                ))
            }
            _ => None,
        }
    }
}

/// Local IPv4 address of the connected socket `fd`.
#[cfg(feature = "rdma")]
fn local_v4(fd: RawFd) -> Option<std::net::Ipv4Addr> {
    // SAFETY: zeroed sockaddr_in is valid; getsockname fills at most `len` bytes.
    unsafe {
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockname(fd, (&raw mut sa).cast(), &mut len) < 0
            || i32::from(sa.sin_family) != libc::AF_INET
        {
            return None;
        }
        Some(std::net::Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes()))
    }
}

/// Is the connected peer of `fd` an address of this host (loopback route: `127/8` or a local interface address)?
fn local_peer(fd: RawFd) -> bool {
    peer_addr(fd).is_some_and(|sa| {
        let ip = sa.ip();
        ip.is_loopback() || crate::netaddr::local_addrs().iter().any(|a| a.ip == ip)
    })
}

impl<const N: usize> KNet<N> {
    /// Build the transport of one core. Must run on the thread that will drive it (`SINGLE_ISSUER`).
    pub fn new(cfg: KCfg, lst: [Vec<OwnedFd>; N]) -> io::Result<KNet<N>> {
        let lst: Vec<(usize, OwnedFd)> = lst
            .into_iter()
            .enumerate()
            .flat_map(|(k, fds)| fds.into_iter().map(move |fd| (k, fd)))
            .collect();
        let listeners = lst.len();
        let (ring, ring_mode) = make_ring(cfg.entries).map_err(uring_access::refused)?;
        let caps = capability::check(&ring)?;
        #[cfg(test)]
        let caps = if cfg.force_classic {
            capability::RxCaps {
                provide: Provide::Classic,
                ring_err: None,
            }
        } else {
            caps
        };
        if let Some(e) = &caps.ring_err {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                eprintln!(
                    "croit-flashstore-osd: WARNING: knet: provided-buffer ring unusable ({e}); receive buffers via classic PROVIDE_BUFFERS (one SQE per returned run, adr 0053 am. 9)"
                );
            });
        }
        let bufs = BufRing::new(&ring.submitter(), cfg.bufs, cfg.buf_size, caps.provide)?;
        // Classic mode only: provide entries complete silently on success where the kernel can skip their CQE.
        let pbuf_flags = if ring.params().is_feature_skip_cqe_on_success() {
            Flags::SKIP_SUCCESS
        } else {
            Flags::empty()
        };
        let spill = Spill::new(cfg.bufs, cfg.buf_size)?;
        let rmem_auto = tcp_rmem_max()?;
        let mut probe = Probe::new();
        let zc = ring.submitter().register_probe(&mut probe).is_ok()
            && probe.is_supported(opcode::SendMsgZc::CODE);
        let src_ports = if cfg.peer_cores > 1 {
            listen::SrcPorts::from_proc()
        } else {
            listen::SrcPorts::default()
        };
        let held_conns = VecDeque::with_capacity(cfg.bufs as usize);
        let mut n = KNet {
            ring,
            bufs,
            spill,
            held_provided: 0,
            held_bytes: 0,
            hold_budget: 0,
            rmem_auto,
            cfg,
            lst,
            slots: Vec::new(),
            free: Vec::new(),
            by_id: FxMap::default(),
            zc,
            tick_at: None,
            accepts: vec![AcceptState::default(); listeners],
            accept_armed: [0; N],
            wake: None,
            src_ports,
            rnd: 0x9e37_79b9_7f4a_7c15
                ^ (std::process::id() as u64) << 20
                ^ std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(1, |d| d.as_nanos() as u64),
            place: None,
            spread: None,
            spare_st: Vec::new(),
            held_conns,
            paused_rx: VecDeque::new(),
            rx_more: false,
            cq_batch: Vec::with_capacity(CQ_BATCH),
            stats: KStats::default(),
            ring_mode,
            pbuf_flags,
            store_ring: None,
            #[cfg(feature = "rdma")]
            rdma: None,
            #[cfg(feature = "rdma")]
            rdma_dead: Vec::new(),
            #[cfg(feature = "rdma")]
            placement_slots: Vec::new(),
            zplan: None,
            zrx: None,
            znapi: 0,
            zwake: Box::new(0),
            zwake_armed: false,
            zpaused: Vec::new(),
            zrearm: Vec::new(),
        };
        n.commit_bufs();
        for l in 0..n.lst.len() {
            n.accepts[l].paused = n.cfg.bounded_accept;
            n.rearm(l);
        }
        n.kick();
        Ok(n)
    }

    /// Stop accepting on a service listener (all its address-family entries). Call after its Driver reports
    /// `listener_open(index) == false`. Already accepted sockets stay live.
    pub fn stop_listener(&mut self, index: usize) -> io::Result<()> {
        if index >= N {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        for l in 0..self.lst.len() {
            if self.lst[l].0 != index {
                continue;
            }
            self.accepts[l].retry = false;
            self.accepts[l].ready = false;
            if self.cfg.bounded_accept {
                self.push(
                    opcode::AsyncCancel::new(ud(K_ACCEPT_READY, l as u32, 0))
                        .build()
                        .user_data(K_IGN),
                );
            }
            // SAFETY: this runtime owns the listening socket. Shutdown unlistens it
            // while retaining its fd until the multishot cancellation has retired.
            if unsafe { libc::shutdown(self.lst[l].1.as_raw_fd(), libc::SHUT_RDWR) } < 0 {
                return Err(io::Error::last_os_error());
            }
            self.push(
                opcode::AsyncCancel::new(ud(K_ACCEPT, l as u32, 0))
                    .build()
                    .user_data(K_IGN),
            );
        }
        Ok(())
    }

    fn conn(&self, id: u64) -> io::Result<&Conn> {
        self.by_id
            .get(&id)
            .and_then(|&s| self.slots[s as usize].as_ref())
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }

    /// Set TCP_NODELAY on an admitted service socket. OSDs use sock_opts' existing
    /// default; this method is only called by socket facades.
    pub fn set_nodelay(&self, id: u64, on: bool) -> io::Result<()> {
        let c = self.conn(id)?;
        setopt(c.fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, i32::from(on))
    }

    /// Half-close an admitted service socket without retiring its receive side.
    /// The caller first drains its output; pending sends must not follow FIN.
    pub fn shutdown_write(&self, id: u64) -> io::Result<()> {
        let c = self.conn(id)?;
        // SAFETY: the runtime owns this live socket descriptor.
        if unsafe { libc::shutdown(c.fd, libc::SHUT_WR) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Reset a service socket and retire its outstanding requests. The driver
    /// releases its handle independently; stale completions retain the old id.
    pub fn abort_connection(&mut self, id: u64) {
        if let Some(slot) = self.by_id.remove(&id) {
            if let Some(c) = self.slots[slot as usize].as_mut() {
                c.reported = true;
                let linger = libc::linger {
                    l_onoff: 1,
                    l_linger: 0,
                };
                // SAFETY: valid socket, pointer and size for SO_LINGER.
                unsafe {
                    libc::setsockopt(
                        c.fd,
                        libc::SOL_SOCKET,
                        libc::SO_LINGER,
                        (&raw const linger).cast(),
                        size_of::<libc::linger>() as _,
                    )
                };
            }
            self.teardown(slot);
        }
    }

    /// Bytes still owned by transport send queues or awaiting TCP acknowledgement.
    /// A zero result is an acknowledgement fence, not merely a send CQE.
    pub fn send_queued(&self, id: u64) -> io::Result<usize> {
        let c = self.conn(id)?;
        let mut queued: libc::c_int = 0;
        // SAFETY: TIOCOUTQ writes one int on a live socket owned by this runtime.
        if unsafe { libc::ioctl(c.fd, libc::TIOCOUTQ, &raw mut queued) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(queued.max(0) as usize
            + c.out.iter().map(Bytes::len).sum::<usize>()
            + c.st.runs.iter().map(Bytes::len).sum::<usize>()
            + usize::from(c.sending))
    }

    /// Register a completion notification descriptor for an external event loop.
    ///
    /// Call once during startup; keep the returned descriptor until this transport
    /// is dropped. Drain its counter before calling `poll`, never after: an input
    /// arriving during the poll must remain latched for the next external wait.
    /// The eventfd signals deferred task work as well as committed completions.
    /// Polling the ring fd itself cannot reliably wake deferred-work consumers.
    pub fn create_readiness_fd(&self) -> io::Result<OwnedFd> {
        // SAFETY: eventfd returns a new descriptor with no borrowed storage.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: eventfd returned this newly owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        self.ring.submitter().register_eventfd(fd.as_raw_fd())?;
        Ok(fd)
    }

    /// All userspace send buffers entered the kernel. Unlike send_queued this
    /// does not wait for TCP ACK, so FIN can follow writes without peer progress.
    pub fn output_written(&self, id: u64) -> io::Result<bool> {
        let c = self.conn(id)?;
        Ok(!c.sending && c.out.is_empty() && c.st.runs.is_empty())
    }

    /// Join the placement group of this OSD's cores: public connections accepted here may move to a less loaded
    /// core (see [`KPlace`]). Call before polling.
    pub fn set_place(&mut self, p: KPlace) {
        if let Some((w, _)) = &self.wake {
            p.set_waker(w.clone());
        }
        self.place = Some(p);
    }

    /// Join the receive-spread mesh of this OSD's cores (needs `KCfg::spread_min` > 0 to submit; always serves).
    pub fn set_spread(&mut self, s: KSpread) {
        self.spread = Some(s);
    }

    /// Live connections.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// True without connections.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    fn push(&mut self, e: Entry) {
        push_sqe(&mut self.ring, &mut self.stats.enters, e);
    }

    /// Hand the buffers given back since the last call to the kernel (see `BufRing::commit`).
    fn commit_bufs(&mut self) {
        let (ring, enters, flags) = (&mut self.ring, &mut self.stats.enters, self.pbuf_flags);
        self.bufs.commit(|e, first, n| {
            let e = e
                .user_data(ud(K_PBUF, u32::from(first), u32::from(n)))
                .flags(flags);
            push_sqe(ring, enters, e);
        });
    }

    fn on_pbuf(&mut self, first: u32, n: u32, res: i32) {
        if res >= 0 {
            return;
        }
        self.stats.provide_errs += 1;
        if self.stats.provide_errs == 1 {
            eprintln!(
                "croit-flashstore-osd: WARNING: knet: PROVIDE_BUFFERS of {n} buffers rejected: {}; ids given again",
                io::Error::from_raw_os_error(-res)
            );
        }
        self.bufs.give_run(first as u16, n as u16);
    }

    /// Enter the kernel if something is queued or it flagged task work (completions waiting for us).
    fn kick(&mut self) -> bool {
        let sq = self.ring.submission();
        // CQ overflow: the kernel holds completions back until an enter with GETEVENTS (`submit` adds it when the flag is
        // set); without it a core with nothing to submit (spin idle) would never see them
        let need = !sq.is_empty() || sq.taskrun() || sq.cq_overflow();
        drop(sq);
        if need {
            self.stats.enters += 1;
            let _ = self.ring.submit();
        }
        need
    }

    /// Let mesh senders wake this core out of its idle sleep (see [`Wake`](crate::wake::Wake)).
    pub fn set_wake(&mut self, w: std::sync::Arc<crate::wake::Wake>) {
        if let Some(p) = &self.place {
            p.set_waker(w.clone());
        }
        self.wake = Some((w, Box::leak(Box::new(0)))); // leaked: the kernel may write it until the ring is gone
        self.arm_wake();
    }

    /// Cumulative eventfd writes senders issued to this core (0 without a wake handle).
    pub fn wake_writes(&self) -> u64 {
        self.wake.as_ref().map_or(0, |(w, _)| w.writes())
    }

    /// Mesh senders can wake this core ([`set_wake`](Self::set_wake) was called).
    pub fn has_wake(&self) -> bool {
        self.wake.is_some()
    }

    fn arm_wake(&mut self) {
        let Some((w, buf)) = self.wake.as_mut() else {
            return;
        };
        let e = opcode::Read::new(Fd(w.raw_fd()), (&raw mut **buf).cast(), 8)
            .build()
            .user_data(K_WAKE);
        self.push(e);
    }

    /// Let completions of the store device ring (`kernel:` devices, adr 0169) wake this core: before an idle sleep with
    /// store IO in flight [`arm_store_wake`](Self::arm_store_wake) arms a one-shot poll of `fd` in this ring.
    pub fn set_store_wake(&mut self, fd: RawFd) {
        self.store_ring = Some((fd, false));
    }

    /// Arm the store ring poll (once until it fires): the next device completion ends the sleep. One-shot, so a polling
    /// core gets no extra completions (a multishot poll would add a task_work + enter per device completion).
    pub fn arm_store_wake(&mut self) -> bool {
        let Some((fd, armed)) = self.store_ring else {
            return false;
        };
        if !armed {
            let e = opcode::PollAdd::new(Fd(fd), libc::POLLIN as u32)
                .build()
                .user_data(K_STORE);
            self.push(e);
            self.store_ring = Some((fd, true));
        }
        true
    }

    /// Submit what is queued and sleep until a completion arrives or `timeout` passes (idle cores).
    pub fn wait(&mut self, timeout: Duration) {
        self.wait_if(timeout, || true);
    }

    /// [`wait`](Self::wait), unless there is work after the sleep was announced to other threads: a job or done ring of
    /// the receive / send spread is not empty, a socket another core placed here waits, or `idle()` (the caller's
    /// re-check) turns false. The re-checks run after the announcement, which closes the lost-wake window (see
    /// [`crate::wake`]). `None`: no sleep happened (nothing of a sleep may be booked); `Some`: how the sleep ended.
    pub fn wait_if(&mut self, timeout: Duration, idle: impl FnOnce() -> bool) -> Option<Waited> {
        if let Some((w, _)) = &self.wake {
            let _ = w.take_poke(); // a late poke of the previous sleep
            w.set_sleeping(true);
        }
        if self.spread.as_ref().is_some_and(|s| !s.quiet())
            || self.place.as_ref().is_some_and(KPlace::waiting)
            || !idle()
        {
            if let Some((w, _)) = &self.wake {
                w.set_sleeping(false);
            }
            return None;
        }
        self.zwake_arm();
        let ts = Timespec::from(timeout);
        let args = io_uring::types::SubmitArgs::new().timespec(&ts);
        self.stats.enters += 1;
        self.stats.enters_wait += 1;
        // an enter that also submitted SQEs returns their count, not ETIME, when its wait times out: a completion that
        // ended the wait is in the CQ, so an empty CQ after the wait is the timeout
        let timed_out = match self.ring.submitter().submit_with_args(1, &args) {
            Ok(_) => self.ring.completion().is_empty(),
            Err(e) => e.raw_os_error() == Some(libc::ETIME),
        };
        let poke_ns = self.wake.as_ref().and_then(|(w, _)| {
            w.set_sleeping(false);
            w.take_poke()
        });
        Some(Waited { timed_out, poke_ns })
    }

    fn rearm(&mut self, l: usize) {
        if self.cfg.bounded_accept {
            self.arm_accept_watch(l);
        } else {
            self.arm_accept(l);
        }
    }

    fn arm_accept_watch(&mut self, l: usize) {
        let entry = opcode::PollAdd::new(Fd(self.lst[l].1.as_raw_fd()), libc::POLLIN as u32)
            .build()
            .user_data(ud(K_ACCEPT_READY, l as u32, 0));
        self.push(entry);
    }

    fn arm_accept(&mut self, l: usize) {
        if !self.accepts[l].armed {
            self.accepts[l].armed = true;
            self.accept_armed[self.lst[l].0] += 1;
        }
        let e = if self.cfg.bounded_accept {
            opcode::Accept::new(
                Fd(self.lst[l].1.as_raw_fd()),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
            .flags(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC)
            .build()
        } else {
            opcode::AcceptMulti::new(Fd(self.lst[l].1.as_raw_fd()))
                .flags(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC)
                .build()
        }
        .user_data(ud(K_ACCEPT, l as u32, 0));
        self.push(e);
    }

    fn arm_recv(&mut self, slot: u32) {
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        c.inflight += 1;
        let e = if c.shots > 0 {
            opcode::Recv::new(Fd(c.fd), std::ptr::null_mut(), 0)
                .buf_group(BGID)
                .build()
                .flags(Flags::BUFFER_SELECT)
        } else {
            opcode::RecvMulti::new(Fd(c.fd), BGID).build()
        }
        .user_data(ud(K_RECV, slot, 0));
        self.push(e);
    }

    fn add_conn(&mut self, fd: RawFd, id: u64, dialing: bool) -> u32 {
        self.add_conn_counted(fd, id, dialing, false)
    }

    /// `counted`: the placement load already includes this connection (a socket adopted from another core).
    fn add_conn_counted(&mut self, fd: RawFd, id: u64, dialing: bool, counted: bool) -> u32 {
        // a locked rcvbuf (`SO_RCVBUF`) can be above or below the autotuning ceiling: the larger one bounds the queue
        let rmem = (listen::getopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF)
            .unwrap_or(0)
            .max(0) as usize)
            .max(self.rmem_auto);
        self.hold_budget += rmem;
        let c = Conn {
            held: VecDeque::new(),
            rmem,
            fd,
            id,
            dialing,
            rx_paused: false,
            paused_at: None,
            public: false,
            reported: false,
            dying: false,
            closing: None,
            inflight: 0,
            sending: false,
            send_away: false,
            out: VecDeque::new(),
            local_peer: false,
            st: SendState::boxed(),
            zc_seq: 0,
            zc_hold: Vec::new(),
            zc_spare: Vec::new(),
            dial: None,
            rx: Rx::Multi,
            shots: 0,
            spread_ok: false,
            #[cfg(feature = "cut-probe")]
            probe: cutprobe::ConnProbe::default(),
            #[cfg(feature = "rdma")]
            rdma: krdma::ConnRdma::default(),
            zrx: false,
            zarmed: false,
            zpend: zcrx::book::Pending::default(),
        };
        let slot = match self.free.pop() {
            Some(s) => {
                self.slots[s as usize] = Some(c);
                s
            }
            None => {
                self.slots.push(Some(c));
                (self.slots.len() - 1) as u32
            }
        };
        if let Some(prev) = self.by_id.insert(id, slot) {
            // the OSD closes (or knet reports) a socket before its id is dialled again; a socket that still delivers
            // under the id would feed the new stream's decoder: it is silenced, loudly
            debug_assert!(
                false,
                "knet: connection id {id:#x} reused while slot {prev} owns it"
            );
            eprintln!(
                "ERROR knet: connection id {id:#x} reused while slot {prev} owns it; the old socket is closed"
            );
            if let Some(c) = self.slots[prev as usize].as_mut() {
                c.reported = true;
            }
            self.teardown(prev);
        }
        if let Some(p) = self.place.as_ref().filter(|_| !counted) {
            p.gain();
        }
        slot
    }

    fn sock_opts(&self, fd: RawFd) {
        let _ = setopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
    }

    fn resume_bounded_accepts<D: Driver>(&mut self, d: &D) -> bool {
        let mut resumed = false;
        if self.cfg.bounded_accept {
            for l in 0..self.lst.len() {
                let k = self.lst[l].0;
                if self.accepts[l].paused
                    && self.accepts[l].ready
                    && d.listener_open(k)
                    && self.accept_armed[k] < d.listener_accept_capacity(k)
                {
                    self.accepts[l].ready = false;
                    self.accepts[l].paused = false;
                    self.arm_accept(l);
                    resumed = true;
                }
            }
        }
        resumed
    }

    /// Reap completions and feed the OSD. Returns true if anything happened (the OSD may have output pending).
    pub fn poll<D: Driver>(&mut self, d: &mut D, now: Duration) -> bool {
        let resumed_accept = self.resume_bounded_accepts(d);
        if self.kick() {
            self.stats.enters_poll += 1;
        }
        let mut work = self.place.is_some() && self.adopt(d, now);
        work |= resumed_accept;
        work |= self.resume_rx(d, now);
        self.rx_more = false;
        let mut batch = std::mem::take(&mut self.cq_batch);
        loop {
            batch.clear();
            {
                let mut cq = self.ring.completion();
                cq.sync();
                batch.extend(
                    (&mut cq)
                        .take(CQ_BATCH)
                        .map(|cqe| (cqe.user_data(), cqe.result(), cqe.flags())),
                );
            }
            let n = batch.len();
            work |= n > 0;
            for &(u, res, flags) in &batch {
                let (kind, slot, seq) =
                    (u & 0xf, ((u >> 4) & 0x0fff_ffff) as u32, (u >> 32) as u32);
                let t0 = Instant::now();
                match kind {
                    K_ACCEPT => self.on_accept(d, slot as usize, res, flags, now),
                    K_ACCEPT_READY => {
                        let l = slot as usize;
                        if res >= 0 {
                            self.accepts[l].ready = true;
                        } else if -res != libc::ECANCELED && d.listener_open(self.lst[l].0) {
                            eprintln!(
                                "knet: listener {l}: readiness failed: {}",
                                io::Error::from_raw_os_error(-res)
                            );
                            self.accepts[l].retry = true;
                            self.tick_due(now + ACCEPT_RETRY);
                        }
                    }
                    K_RECV => self.on_recv(d, slot, res, flags, now),
                    K_DRECV => self.on_drecv(d, slot, res, now),
                    K_SEND => self.on_send(d, slot, seq, res, flags, now),
                    K_CONN => self.on_connect(d, slot, res, now),
                    K_WAKE => self.arm_wake(),
                    K_HRECV => self.on_hrecv(slot, res),
                    K_HSEND => self.on_hsend(slot, res),
                    K_PBUF => self.on_pbuf(slot, seq, res),
                    K_STORE => {
                        if let Some((_, armed)) = self.store_ring.as_mut() {
                            *armed = false;
                        }
                    }
                    #[cfg(feature = "rdma")]
                    K_RDMA => self.on_rdma_wake(slot as usize),
                    K_ZWAKE => self.zwake_armed = false,
                    _ => {}
                }
                let ns = t0.elapsed().as_nanos() as u64;
                if ns > self.stats.cqe_peak_ns {
                    self.stats.cqe_peak_ns = ns;
                    self.stats.cqe_peak_kind = kind;
                    if ns > self.stats.cqe_max_ns {
                        self.stats.cqe_max_ns = ns;
                        self.stats.cqe_max_kind = kind;
                    }
                }
            }
            if n == CQ_BATCH {
                continue;
            }
            if !self.rx_more {
                break;
            }
            // next pieces of sockets that still hold data: issue them now (completed inline when the bytes are there)
            self.rx_more = false;
            self.stats.rx_more_passes += 1;
            if self.kick() {
                self.stats.enters_poll += 1;
            }
        }
        self.cq_batch = batch;
        if self.zrx.is_some() {
            work |= self.zrx_poll(d, now);
        }
        #[cfg(feature = "rdma")]
        {
            work |= self.rdma_phase(d, now);
        }
        if self.spread.is_some() {
            work |= self.spread_serve();
            work |= self.spread_reap(d, now);
        }
        self.commit_bufs();
        if self.tick_at.is_some_and(|t| now >= t) {
            self.tick_at = None;
            self.tick(now);
        }
        work |= self.resume_bounded_accepts(d);
        work
    }

    /// Register a deadline of [`tick`](Self::tick) work.
    fn tick_due(&mut self, at: Duration) {
        self.tick_at = Some(self.tick_at.map_or(at, |t| t.min(at)));
    }

    /// When this transport has timed work (accept retry, close linger cut): the idle loop sleeps no longer.
    pub fn next_due(&self) -> Option<Duration> {
        self.tick_at
    }

    /// Timed work that is due: accept retries, graceful closes past their linger; re-registers the closes not due yet.
    fn tick(&mut self, now: Duration) {
        // every flat listener entry (kind x address family), not the four kinds: a listener past the first four must
        // never be left without a multishot accept after a resource shortage
        debug_assert_eq!(self.accepts.len(), self.lst.len());
        for l in 0..self.accepts.len() {
            if std::mem::take(&mut self.accepts[l].retry) {
                self.rearm(l);
            }
        }
        let mut cut = Vec::new();
        let mut next: Option<Duration> = None;
        for (i, s) in self.slots.iter().enumerate() {
            if let Some(c) = s
                && !c.dying
                && let Some(dl) = c.closing
            {
                if now >= dl {
                    cut.push(i as u32);
                } else {
                    next = Some(next.map_or(dl, |t| t.min(dl)));
                }
            }
        }
        if let Some(t) = next {
            self.tick_due(t);
        }
        for s in cut {
            self.tcp_close_timeout(s);
            #[cfg(feature = "rdma")]
            self.rdma_close_timeout(s);
            self.teardown(s);
        }
    }

    /// A plain TCP connection's graceful close (queued output, FIN) ran into the linger cap: tell loudly (an upgraded
    /// connection says so in `rdma_close_timeout`).
    fn tcp_close_timeout(&self, slot: u32) {
        let Some(c) = self.slots[slot as usize].as_ref() else {
            return;
        };
        #[cfg(feature = "rdma")]
        if c.rdma.carrier.rdma_qpn().is_some() {
            return;
        }
        eprintln!(
            "WARNING TIMEOUT knet close exceeded {:.3}s (conn {:#x}, {} chunks unsent, torn down)",
            self.cfg.close_linger.as_secs_f64(),
            c.id,
            c.out.len()
        );
    }

    fn on_accept<D: Driver>(&mut self, d: &mut D, l: usize, res: i32, flags: u32, now: Duration) {
        if !cqueue::more(flags) && self.accepts[l].armed {
            self.accepts[l].armed = false;
            self.accept_armed[self.lst[l].0] -= 1;
        }
        if res >= 0 {
            let fd = res;
            match peer_addr(fd) {
                Some(peer) => {
                    // a connection on a zcrx queue is readable only through its owner core's ring: it goes there
                    // whatever the listener (only the public port is steered there, `zcrx::steer`)
                    let zowner = self.zplan.as_ref().and_then(|z| {
                        z.core_of_napi(listen::getopt(
                            fd,
                            libc::SOL_SOCKET,
                            libc::SO_INCOMING_NAPI_ID,
                        )? as u32)
                    });
                    // clients (public listener) go to the least loaded core; peers and heartbeats stay (peer sessions
                    // have their own placement, adr 0054). Not onto the core of its softirq CPU.
                    let away = match &self.place {
                        Some(p) if zowner.is_some() => zowner.map(|to| (to, p)),
                        Some(p) if self.lst[l].0 == 0 => {
                            let rx = listen::incoming_cpu(fd);
                            let to = p.pick(rx);
                            if rx.is_some() && to != p.pick(None) {
                                self.stats.placed_off_rx += 1;
                            }
                            Some((to, p))
                        }
                        _ => None,
                    }
                    .filter(|(to, p)| *to != p.me());
                    let mut keep = Some(fd);
                    if let Some((to, p)) = away {
                        // SAFETY: `fd` came from the accept completion and nothing else owns it yet.
                        let a = Adopt {
                            fd: unsafe { OwnedFd::from_raw_fd(fd) },
                            l,
                            peer,
                        };
                        match p.send(to, a) {
                            Ok(()) => keep = None,
                            Err(a) => keep = Some(a.fd.into_raw_fd()), // that core is gone (shutdown)
                        }
                    }
                    match keep {
                        Some(fd) => self.accept_here(d, l, fd, peer, false, now),
                        None => self.stats.placed_away += 1,
                    }
                }
                None => {
                    // SAFETY: closing the fd the kernel just gave us.
                    unsafe { libc::close(fd) };
                }
            }
        }
        if !cqueue::more(flags) && d.listener_open(self.lst[l].0) {
            if matches!(
                -res,
                libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS
            ) {
                self.accepts[l].paused = self.cfg.bounded_accept;
                self.accepts[l].retry = true; // resource shortage: retry after a back-off, not in a tight loop
                self.tick_due(now + ACCEPT_RETRY);
            } else if self.cfg.bounded_accept {
                self.accepts[l].paused = true;
                self.arm_accept_watch(l);
            } else {
                self.arm_accept(l);
            }
        }
    }

    /// This core owns the accepted socket `fd` from now on.
    fn accept_here<D: Driver>(
        &mut self,
        d: &mut D,
        l: usize,
        fd: RawFd,
        peer: SocketAddr,
        counted: bool,
        now: Duration,
    ) {
        self.sock_opts(fd);
        let Some(id) = d.on_accept(self.lst[l].0, peer, now) else {
            // SAFETY: this accepted socket has no queued operations and is owned here.
            unsafe { libc::close(fd) };
            if counted && let Some(p) = self.place.as_ref() {
                p.lose();
            }
            return;
        };
        let slot = self.add_conn_counted(fd, id, false, counted);
        if let Some(c) = self.slots[slot as usize].as_mut() {
            c.public = self.lst[l].0 == 0;
            c.local_peer = local_peer(fd);
        }
        let zrx = self.zrx.is_some()
            && (self.znapi == 0
                || listen::getopt(fd, libc::SOL_SOCKET, libc::SO_INCOMING_NAPI_ID)
                    .is_some_and(|n| n as u32 == self.znapi));
        if zrx {
            if let Some(c) = self.slots[slot as usize].as_mut() {
                c.zrx = true;
            }
            self.zrx_arm(slot);
            if let Some(z) = self.zrx.as_mut() {
                z.stats.conns += 1;
            }
        } else {
            self.arm_recv(slot);
        }
        self.stats.accepted += 1;
    }

    /// Sockets other cores placed here.
    fn adopt<D: Driver>(&mut self, d: &mut D, now: Duration) -> bool {
        let mut any = false;
        while let Some(a) = self.place.as_ref().and_then(KPlace::take) {
            let fd = a.fd.into_raw_fd();
            self.accept_here(d, a.l, fd, a.peer, true, now);
            self.stats.adopted += 1;
            any = true;
        }
        any
    }

    fn on_recv<D: Driver>(&mut self, d: &mut D, slot: u32, res: i32, flags: u32, now: Duration) {
        let more = cqueue::more(flags);
        let bid = cqueue::buffer_select(flags);
        self.stats.rx_cqes += 1;
        let Some(c) = self.slots[slot as usize].as_mut() else {
            if let Some(b) = bid {
                self.bufs.give(b);
            }
            return;
        };
        if !more {
            c.inflight -= 1;
        }
        #[cfg(feature = "rdma")]
        if !c.rdma.carrier.is_tcp() {
            // past the switch point: the QP carries the stream, the socket is the connection's liveness channel
            return self.rdma_tcp_rx(d, slot, res, more, bid, now);
        }
        let (id, silent, dying) = (c.id, c.reported, c.dying);
        let mut rearm = !more && !dying;
        let mut dead = false;
        if res > 0 {
            self.stats.rx_bytes += res as u64;
            if let Some(b) = bid {
                // a parked link (see `Driver::rx_parked`) takes the chunk into its decoder instead of holding it
                if !silent && (!c.held.is_empty() || !(d.input_ready(id) || d.rx_parked(id))) {
                    let buffer = if self.held_provided >= self.cfg.bufs as usize / 2 {
                        if let Some(saved) = self.spill.save(self.bufs.buf(b, res as usize)) {
                            self.bufs.give(b);
                            HeldBuf::Spill(saved)
                        } else {
                            self.held_provided += 1;
                            HeldBuf::Provided(b)
                        }
                    } else {
                        self.held_provided += 1;
                        HeldBuf::Provided(b)
                    };
                    if c.held.is_empty() {
                        self.held_conns.push_back((slot, id));
                    }
                    c.held.push_back((buffer, res as usize));
                    self.held_bytes += res as usize;
                    self.stats.rx_held += 1;
                } else {
                    if !silent {
                        d.on_bytes(id, self.bufs.buf(b, res as usize), now);
                    }
                    self.bufs.give(b);
                }
            }
        } else {
            if let Some(b) = bid {
                self.bufs.give(b);
            }
            match -res {
                0 if !dying && !silent && d.keep_half_open() => {
                    c.rx = Rx::Eof;
                    if c.held.is_empty() {
                        d.on_eof(id, now);
                    }
                    return;
                }
                0 => dead = true, // EOF
                libc::ENOBUFS => self.stats.nobufs += 1,
                libc::EINTR | libc::EAGAIN => {}
                libc::ECANCELED => rearm = false,
                _ => dead = true,
            }
            if res == 0 {
                rearm = false;
            }
        }
        if dead {
            self.conn_dead(d, slot, now);
        } else if !dying
            && (!d.input_ready(id)
                || self.slots[slot as usize]
                    .as_ref()
                    .is_some_and(|c| c.rx_paused || !c.held.is_empty())
                || res == -libc::ENOBUFS && self.held_bytes != 0)
        {
            let room = self.hold_room() && res != -libc::ENOBUFS && !d.rx_parked(id);
            let c = self.slots[slot as usize].as_mut().unwrap();
            let multi = !c.rx_paused && matches!(c.rx, Rx::Multi);
            if multi {
                self.stats.rx_hold_full += u64::from(!room);
                self.stats.rx_hold_budget +=
                    u64::from(!room && self.held_bytes >= self.hold_budget);
            }
            if room && multi {
                // keep draining the socket into hold storage: a socket left unread fills to its rcvbuf, Linux then
                // prunes, drops and retracts its window (RTO storms, mutual window deadlock of a busy peer link)
                if !more {
                    self.arm_recv(slot);
                }
            } else if !more {
                c.pause(&mut self.stats, now);
                self.paused_rx.push_back((slot, id));
            } else if multi {
                c.pause(&mut self.stats, now);
                let e = opcode::AsyncCancel::new(ud(K_RECV, slot, 0))
                    .build()
                    .user_data(K_IGN);
                self.push(e);
            }
        } else if !more
            && !dying
            && self.slots[slot as usize]
                .as_ref()
                .is_some_and(|c| matches!(c.rx, Rx::Cancelling))
        {
            self.start_direct(d, slot);
        } else if rearm {
            // one-shot after a big segment: the next one goes direct as soon as its first buffer is decoded
            let shot = self.slots[slot as usize].as_mut().filter(|c| c.shots > 0);
            if let Some(c) = shot {
                if res > 0
                    && !silent
                    && self.cfg.direct_min > 0
                    && rx_want(d, id) >= self.cfg.direct_min
                {
                    self.stats.bigshots += 1;
                    self.start_direct(d, slot);
                    self.maybe_free(slot);
                    return;
                }
                c.shots -= 1;
            }
            self.arm_recv(slot);
        } else if more
            && !silent
            && !dying
            && self.cfg.direct_min > 0
            && res > 0
            && self.slots[slot as usize]
                .as_ref()
                .is_some_and(|c| matches!(c.rx, Rx::Multi))
            && rx_want(d, id) >= self.cfg.direct_min
        {
            // the rest of a big data segment is coming: stop the ring recv, then receive it in place
            if let Some(c) = self.slots[slot as usize].as_mut() {
                c.rx = Rx::Cancelling;
            }
            let e = opcode::AsyncCancel::new(ud(K_RECV, slot, 0))
                .build()
                .user_data(K_IGN);
            self.push(e);
        }
        self.maybe_free(slot);
    }

    fn resume_rx<D: Driver>(&mut self, d: &mut D, now: Duration) -> bool {
        let mut work = d.resume_inputs(now);
        if !self.zpaused.is_empty() {
            work |= self.zrx_resume(d, now);
        }
        for _ in 0..self.held_conns.len() {
            let (slot, id) = self.held_conns.pop_front().unwrap();
            // in stream order while the OSD takes this connection's input; a head that waits keeps the rest behind it
            while let Some(c) = self.slots[slot as usize]
                .as_mut()
                .filter(|c| c.id == id && !c.held.is_empty())
            {
                if c.dying || c.reported {
                    // gone (fault, failed dial, our close): the old stream's bytes are never delivered; unacknowledged
                    // at the peer, the resumed session replays them
                    let held = std::mem::take(&mut c.held);
                    for (b, n) in held {
                        self.release_held(b, n);
                    }
                    work = true;
                    break;
                }
                if !d.input_ready(id) {
                    self.held_conns.push_back((slot, id));
                    break;
                }
                let (b, n) = c.held.pop_front().unwrap();
                let data = match b {
                    HeldBuf::Provided(id) => self.bufs.buf(id, n),
                    HeldBuf::Spill(id) => self.spill.buf(id, n),
                };
                d.on_bytes(id, data, now);
                self.release_held(b, n);
                if d.keep_half_open()
                    && self.slots[slot as usize]
                        .as_ref()
                        .is_some_and(|c| c.held.is_empty() && matches!(c.rx, Rx::Eof))
                {
                    d.on_eof(id, now);
                }
                work = true;
            }
        }
        for _ in 0..self.paused_rx.len() {
            let (slot, id) = self.paused_rx.pop_front().unwrap();
            // only a paused socket resumes: a slot freed while its entry was queued can be taken by a new socket with
            // the same connection id (msgr2 redials a lossless session under it), which must not get a second receive
            let Some(c) = self.slots[slot as usize]
                .as_mut()
                .filter(|c| c.id == id && !c.dying && c.rx_paused)
            else {
                continue;
            };
            if !c.held.is_empty() || !d.input_ready(id) {
                self.paused_rx.push_back((slot, id));
                continue;
            }
            c.resume(&mut self.stats, now);
            match c.rx {
                Rx::Direct(_) => self.submit_drecv(slot),
                Rx::Away | Rx::Eof => {}
                Rx::Cancelling => self.start_direct(d, slot),
                Rx::Multi => self.arm_recv(slot),
            }
            work = true;
        }
        work
    }

    /// Hold storage can take one more receive: below the hold budget, and a buffer is free (the spill store, or the provided
    /// ring up to half; the other half stays for connections whose input the OSD takes). Out of buffers below the budget =
    /// the store is undersized for this core's connections (`rx_hold_full` with `held_bytes < hold_budget`).
    fn hold_room(&self) -> bool {
        self.held_bytes < self.hold_budget
            && (self.spill.has_room() || self.held_provided < self.cfg.bufs as usize / 2)
    }

    fn release_held(&mut self, buffer: HeldBuf, n: usize) {
        self.held_bytes -= n;
        match buffer {
            HeldBuf::Provided(id) => {
                self.held_provided -= 1;
                self.bufs.give(id);
            }
            HeldBuf::Spill(id) => self.spill.give(id),
        }
    }

    /// The ring recv is finished and a direct receive was wanted: take the segment buffer and fill it from the socket,
    /// or go back to the ring when the situation changed meanwhile.
    fn start_direct<D: Driver>(&mut self, d: &mut D, slot: u32) {
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        let id = c.id;
        let direct = if c.reported {
            None
        } else {
            DirectRx::take(d, id, self.cfg.direct_min)
        };
        if let Some(direct) = direct {
            #[cfg(feature = "cut-probe")]
            c.probe.rx_start(direct.remaining());
            c.rx = Rx::Direct(direct);
            self.stats.direct_starts += 1;
            // one getsockopt per big segment: is the stream's softirq on this core's CPU?
            c.spread_ok = listen::rx_on_this_cpu(c.fd);
            if c.spread_ok {
                self.stats.rx_coloc += 1;
            }
            self.submit_drecv(slot);
        } else {
            c.rx = Rx::Multi;
            self.arm_recv(slot);
        }
    }

    fn submit_drecv(&mut self, slot: u32) {
        if self.spread.is_some() && self.cfg.spread_min > 0 && self.spread_out(slot) {
            return;
        }
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        let fd = c.fd;
        let Rx::Direct(dx) = &mut c.rx else {
            return;
        };
        c.inflight += 1;
        let e = drecv_entry(fd, dx).user_data(ud(K_DRECV, slot, 0));
        self.push(e);
    }

    fn on_drecv<D: Driver>(&mut self, d: &mut D, slot: u32, res: i32, now: Duration) {
        self.stats.rx_cqes += 1;
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        c.inflight -= 1;
        let (silent, dying) = (c.reported, c.dying);
        let Rx::Direct(dx) = &mut c.rx else {
            self.maybe_free(slot);
            return;
        };
        if res > 0 {
            let n = res as usize;
            let full = n == dx.remaining().min(DIRECT_CHUNK);
            dx.commit(n);
            #[cfg(feature = "cut-probe")]
            c.probe.rx_piece(n);
            self.stats.rx_bytes += n as u64;
            self.stats.direct_bytes += n as u64;
            self.direct_progress(d, slot, now);
            self.rx_more |= full;
            return;
        }
        match -res {
            // the segment buffer is already lent: its rest never waits for the OSD
            libc::EINTR | libc::EAGAIN if !dying && !silent => self.submit_drecv(slot),
            _ => {
                self.conn_dead(d, slot, now);
                self.maybe_free(slot);
            }
        }
    }

    /// Bytes arrived in the connection's direct buffer (`Rx::Direct`): go on with the rest, or hand the full buffer to
    /// the OSD and go back to the ring.
    fn direct_progress<D: Driver>(&mut self, d: &mut D, slot: u32, now: Duration) {
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        let (id, silent, dying) = (c.id, c.reported, c.dying);
        let Rx::Direct(dx) = &mut c.rx else {
            return;
        };
        if dying || silent {
            self.maybe_free(slot);
            return;
        }
        d.on_rx_progress(id, now);
        if dx.remaining() > 0 {
            // the rest of the segment goes into memory that is already lent: never leave it in the socket
            self.submit_drecv(slot);
            return;
        }
        c.shots = self.cfg.bigshot;
        #[cfg(feature = "cut-probe")]
        c.probe.rx_end(id);
        let Rx::Direct(dx) = std::mem::replace(&mut c.rx, Rx::Multi) else {
            return;
        };
        dx.put(d, id, now);
        // input not taken: the ring receive holds what follows (on_recv) while hold storage lasts
        if d.input_ready(id) || self.hold_room() {
            self.arm_recv(slot);
        } else {
            self.stats.rx_hold_full += 1;
            self.stats.rx_hold_budget += u64::from(self.held_bytes >= self.hold_budget);
            self.slots[slot as usize]
                .as_mut()
                .unwrap()
                .pause(&mut self.stats, now);
            self.paused_rx.push_back((slot, id));
        }
        self.maybe_free(slot);
    }

    /// Receive spread, submitter side: hand the rest of the connection's crc segment to a helper core. False = receive
    /// here (secure frame, small rest, every helper full).
    fn spread_out(&mut self, slot: u32) -> bool {
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return false;
        };
        let Rx::Direct(dx) = &c.rx else {
            return false;
        };
        if !c.spread_ok
            || !matches!(dx, DirectRx::Crc { .. })
            || dx.remaining() < self.cfg.spread_min
        {
            return false;
        }
        let Some(sp) = self.spread.as_mut() else {
            return false;
        };
        let Rx::Direct(dx) = std::mem::replace(&mut c.rx, Rx::Away) else {
            unreachable!()
        };
        let job = spread::RecvJob {
            from: sp.id(),
            slot,
            id: c.id,
            fd: c.fd,
            dx,
            got: 0,
            failed: None,
        };
        match sp.submit(job) {
            Ok(()) => {
                // the fd stays open and the slot keeps its id until the job is back
                c.inflight += 1;
                self.stats.spread_jobs += 1;
                true
            }
            Err(job) => {
                c.rx = Rx::Direct(job.dx);
                false
            }
        }
    }

    /// Receive and send spread, helper side: start the jobs other cores sent here.
    fn spread_serve(&mut self) -> bool {
        let mut any = false;
        while let Some(job) = self.spread.as_mut().and_then(KSpread::take_job) {
            let i = self.spread.as_mut().expect("spread").park(job);
            self.stats.spread_served += 1;
            self.submit_hrecv(i);
            any = true;
        }
        while let Some(job) = self.spread.as_mut().and_then(KSpread::take_send) {
            let i = self.spread.as_mut().expect("spread").park_send(job);
            self.stats.send_served += 1;
            self.submit_hsend(i);
            any = true;
        }
        any
    }

    fn submit_hrecv(&mut self, i: u32) {
        let sp = self.spread.as_mut().expect("spread");
        let j = sp.run[i as usize].as_mut().expect("parked job");
        let e = drecv_entry(j.fd, &mut j.dx).user_data(ud(K_HRECV, i, 0));
        self.push(e);
    }

    /// A helper receive completed: next piece, or the job goes back (complete or failed).
    fn on_hrecv(&mut self, i: u32, res: i32) {
        self.stats.rx_cqes += 1;
        let Some(sp) = self.spread.as_mut() else {
            return;
        };
        let Some(j) = sp.run[i as usize].as_mut() else {
            return;
        };
        if res > 0 {
            let n = res as usize;
            let full = n == j.dx.remaining().min(DIRECT_CHUNK);
            j.dx.commit(n);
            j.got += n;
            self.stats.spread_bytes += n as u64;
            if j.dx.remaining() > 0 {
                self.submit_hrecv(i);
                self.rx_more |= full;
                return;
            }
        } else if res == -libc::EINTR || res == -libc::EAGAIN {
            self.submit_hrecv(i);
            return;
        } else {
            j.failed = Some(res);
        }
        sp.finish(i);
    }

    /// Receive spread, submitter side: jobs back from helpers continue their connection like a local direct receive.
    fn spread_reap<D: Driver>(&mut self, d: &mut D, now: Duration) -> bool {
        let mut any = false;
        while let Some(j) = self.spread.as_mut().and_then(KSpread::take_done) {
            any = true;
            let slot = j.slot;
            // the slot cannot be reused while the job is out (inflight)
            let Some(c) = self.slots[slot as usize].as_mut().filter(|c| c.id == j.id) else {
                continue;
            };
            c.inflight -= 1;
            c.rx = Rx::Direct(j.dx);
            self.stats.rx_bytes += j.got as u64;
            self.stats.direct_bytes += j.got as u64;
            match j.failed {
                None => self.direct_progress(d, slot, now),
                Some(_) => {
                    self.conn_dead(d, slot, now);
                    self.maybe_free(slot);
                }
            }
        }
        while let Some(j) = self.spread.as_mut().and_then(KSpread::take_send_done) {
            any = true;
            let slot = j.slot;
            let Some(c) = self.slots[slot as usize].as_mut().filter(|c| c.id == j.id) else {
                continue;
            };
            c.inflight -= 1;
            c.send_away = false;
            let spare = std::mem::replace(&mut c.st, j.st);
            self.spare_st.push(spare);
            #[cfg(feature = "cut-probe")]
            c.probe.tx_sent(j.sent);
            self.stats.tx_bytes += j.sent as u64;
            d.output_written(j.id, j.sent);
            match j.failed {
                None => self.send_finished(d, slot),
                Some(_) => {
                    c.sending = false;
                    c.st.runs.clear();
                    if !c.dying && !c.reported {
                        self.conn_dead(d, slot, now);
                    } else if !c.dying {
                        self.teardown(slot);
                    }
                }
            }
            self.maybe_free(slot);
        }
        any
    }

    fn on_send<D: Driver>(
        &mut self,
        d: &mut D,
        slot: u32,
        seq: u32,
        res: i32,
        flags: u32,
        now: Duration,
    ) {
        self.stats.tx_cqes += 1;
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        if cqueue::notif(flags) {
            // the batch is out: its run vector goes back to the connection for reuse
            if let Some(i) = c.zc_hold.iter().position(|(s, _)| *s == seq) {
                let (_, mut runs) = c.zc_hold.swap_remove(i);
                runs.clear();
                c.zc_spare.push(runs);
            }
            c.inflight -= 1;
            if c.closing.is_some() && !c.dying && !c.sending && c.out.is_empty() {
                self.finish_tcp_close(slot);
            }
            self.maybe_free(slot);
            return;
        }
        let more = cqueue::more(flags);
        if !more {
            c.inflight -= 1;
        }
        // 0 bytes for a non-empty batch = the socket takes nothing more (a resubmit would spin): the peer is gone
        let res = if res == 0 && !c.st.runs.is_empty() {
            eprintln!(
                "knet: conn {:#x}: SENDMSG completed 0 bytes of a non-empty batch, faulting the connection",
                c.id
            );
            -libc::EPIPE
        } else {
            res
        };
        if res < 0 {
            c.sending = false;
            if -res == libc::EOPNOTSUPP && c.st.zc {
                self.zc = false; // this kernel / socket cannot: plain sends from now on
                c.st.zc = false;
                self.resubmit_send(slot);
            } else if -res == libc::EAGAIN || -res == libc::EINTR {
                self.resubmit_send(slot);
            } else if !c.dying && !c.reported {
                self.conn_dead(d, slot, now);
            } else if !c.dying {
                self.teardown(slot);
            }
            self.maybe_free(slot);
            return;
        }
        let sent = res as usize;
        d.output_written(c.id, sent);
        #[cfg(feature = "cut-probe")]
        c.probe.tx_sent(sent);
        self.stats.tx_bytes += sent as u64;
        if c.st.zc && more {
            // The pages stay ours until the notification: the batch is copied into hold storage (only the `Bytes`
            // refcounts change), and the vector comes from recycled hold storage, so a completion does not allocate.
            let mut held = c.zc_spare.pop().unwrap_or_default();
            held.extend_from_slice(&c.st.runs);
            c.zc_hold.push((seq, held));
        }
        advance(&mut c.st.runs, sent);
        if !c.st.runs.is_empty() {
            self.resubmit_send(slot);
        } else {
            self.send_finished(d, slot);
        }
        self.maybe_free(slot);
    }

    /// The connection's send batch is out completely: pull its next output.
    fn send_finished<D: Driver>(&mut self, d: &mut D, slot: u32) {
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        c.sending = false;
        // A notification consumed while this send was in flight must be retried now. Pull only
        // this connection's output; no global scan and no wait for another unrelated event.
        if c.out.is_empty() && !c.dying {
            d.poll_output_into(c.id, &mut c.out);
        }
        #[cfg(feature = "cut-probe")]
        {
            if c.out.is_empty() {
                c.probe.tx_idle(c.id);
            }
        }
        if !c.out.is_empty() {
            self.submit_send(slot);
        } else if c.closing.is_some() && !c.dying {
            self.finish_tcp_close(slot);
        }
        // an accepted RDMA upgrade: the ACCEPT frame was the last TCP output, the QP takes over
        #[cfg(feature = "rdma")]
        self.rdma_switch_if_ready(slot);
    }

    /// Send spread, submitter side: hand a copied batch larger than `SEND_SPREAD_MIN` to the core with the fewest send
    /// jobs (possibly this one). False = send it here (no mesh, small or zero-copy batch, no core with room).
    fn send_out(&mut self, slot: u32, total: usize) -> bool {
        let Some(sp) = self.spread.as_mut() else {
            return false;
        };
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return false;
        };
        if c.st.zc || total <= spread::SEND_SPREAD_MIN {
            return false;
        }
        let spare = self.spare_st.pop().unwrap_or_else(SendState::boxed);
        let st = std::mem::replace(&mut c.st, spare);
        let job = spread::SendJob {
            from: sp.id(),
            slot,
            id: c.id,
            fd: c.fd,
            st,
            sent: 0,
            failed: None,
        };
        match sp.submit_send(job) {
            Ok(local) => {
                // the fd stays open and the slot keeps its id until the job is back
                c.inflight += 1;
                c.sending = true;
                c.send_away = true;
                self.stats.send_jobs += 1;
                if let Some(j) = local {
                    let i = self.spread.as_mut().expect("spread").park_send(j);
                    self.submit_hsend(i);
                }
                true
            }
            Err(job) => {
                let spare = std::mem::replace(&mut c.st, job.st);
                self.spare_st.push(spare);
                self.stats.send_full += 1;
                false
            }
        }
    }

    /// Send spread, executing side: one `SENDMSG` of the job's runs still to send (the whole batch, as a local send).
    fn submit_hsend(&mut self, i: u32) {
        let sp = self.spread.as_mut().expect("spread");
        let j = sp.srun[i as usize].as_mut().expect("parked send job");
        let st = &mut *j.st;
        st.fill_iov();
        let e = opcode::SendMsg::new(Fd(j.fd), &raw const st.msg)
            .flags(st.send_flags())
            .build()
            .user_data(ud(K_HSEND, i, 0));
        self.push(e);
    }

    /// A send of a job completed: the rest of a short send, or the job goes back (complete or failed).
    fn on_hsend(&mut self, i: u32, res: i32) {
        self.stats.tx_cqes += 1;
        let me = self.spread.as_ref().map(KSpread::id);
        let Some(sp) = self.spread.as_mut() else {
            return;
        };
        let Some(j) = sp.srun[i as usize].as_mut() else {
            return;
        };
        if res > 0 {
            let n = res as usize;
            advance(&mut j.st.runs, n);
            j.sent += n;
            if Some(j.from) != me {
                self.stats.send_served_bytes += n as u64;
            }
            if !j.st.runs.is_empty() {
                self.submit_hsend(i);
                return;
            }
        } else if res == -libc::EINTR || res == -libc::EAGAIN {
            self.submit_hsend(i);
            return;
        } else {
            // 0 bytes for a non-empty batch = the socket takes nothing more
            if res == 0 {
                eprintln!(
                    "knet: conn {:#x}: SENDMSG completed 0 bytes of a non-empty batch, faulting the connection",
                    j.id
                );
            }
            j.failed = Some(if res == 0 { -libc::EPIPE } else { res });
        }
        sp.finish_send(i);
    }

    fn on_connect<D: Driver>(&mut self, d: &mut D, slot: u32, res: i32, now: Duration) {
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        c.inflight -= 1;
        c.dial = None;
        let id = c.id;
        if c.dying {
            // closed by the OSD while dialing
        } else if res == 0 {
            c.dialing = false;
            c.local_peer = local_peer(c.fd);
            d.on_connected(id, now);
            self.arm_recv(slot);
            self.flush_one(d, id);
        } else {
            if -res == libc::ECANCELED {
                eprintln!(
                    "WARNING TIMEOUT knet connect exceeded {:.3}s (conn {id:#x}, linked timeout cancelled the dial)",
                    self.cfg.connect_timeout.as_secs_f64()
                );
            }
            c.reported = true;
            self.by_id.remove(&id);
            d.on_dial_failed(id, -res == libc::ECONNREFUSED, now);
            self.teardown(slot);
        }
        self.maybe_free(slot);
    }

    /// The peer is gone / the socket failed: tell the OSD once, release the socket.
    fn conn_dead<D: Driver>(&mut self, d: &mut D, slot: u32, now: Duration) {
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        if !c.reported {
            c.reported = true;
            let (id, dialing) = (c.id, c.dialing);
            // A lost QP cannot produce success or RETIRED: fault every in-flight placement
            // owner (the client retains its window; the attempt is vacated on the link).
            #[cfg(feature = "rdma")]
            for inflight in &c.rdma.placement {
                let (tid, retry) = inflight.identity();
                d.placement_fault(id, tid, retry);
            }
            #[cfg(feature = "rdma")]
            if let Some(pos) = self.placement_slots.iter().position(|&s| s == slot) {
                self.placement_slots.remove(pos);
            }
            self.by_id.remove(&id);
            if dialing {
                d.on_dial_failed(id, false, now);
            } else {
                d.on_closed(id, now);
            }
        }
        self.teardown(slot);
    }

    /// Queued bytes reached TCP: send FIN, preserving zero-copy owners until their notifications. The existing
    /// close deadline aborts a peer that never acknowledges; a normal drain preserves all queued output.
    fn finish_tcp_close(&mut self, slot: u32) {
        let Some(c) = self.slots[slot as usize].as_ref() else {
            return;
        };
        if c.zc_hold.is_empty() {
            self.teardown(slot);
        } else {
            // SAFETY: the live socket belongs to this slot; queued bytes precede FIN.
            unsafe { libc::shutdown(c.fd, libc::SHUT_WR) };
        }
    }

    /// Retire every request of this ring that references memory of this core before that memory is freed (drop; the
    /// ring-fd close tears down asynchronously, so a request still in flight could write into freed memory): stop the
    /// sockets (those lent to a spread core keep working: only this ring's requests on them are cancelled), cancel
    /// dials, the helper-side spread jobs and the zcrx wake read, then reap until none is in flight
    /// ([`retire_pending`](Self::retire_pending)). Requests still in flight after [`DROP_DRAIN_LIMIT`] keep their memory
    /// for good: provided buffers, connections, spread jobs and the wake target are leaked (loud). Requests that
    /// reference no memory of ours (accepts, readiness polls, the leaked mesh wake read) end with the ring. Idempotent.
    fn retire(&mut self) {
        let mut cancel = Vec::new();
        for (slot, c) in self.slots.iter().enumerate() {
            let Some(c) = c else { continue };
            let slot = slot as u32;
            if matches!(c.rx, Rx::Away) || c.send_away {
                // lent to a spread core: the socket stays usable for that core's job (see the close below), only this
                // ring's own requests on it end
                let seq = if c.sending && !c.send_away && c.st.zc {
                    c.zc_seq
                } else {
                    0
                };
                cancel.extend([
                    ud(K_RECV, slot, 0),
                    ud(K_DRECV, slot, 0),
                    ud(K_SEND, slot, seq),
                ]);
                continue;
            }
            stop_socket(c);
            if c.dial.is_some() {
                cancel.push(ud(K_CONN, slot, 0));
            }
        }
        if let Some(sp) = &self.spread {
            let busy = |(i, j): (usize, bool)| j.then_some(i as u32);
            let run = sp
                .run
                .iter()
                .map(Option::is_some)
                .enumerate()
                .filter_map(busy);
            cancel.extend(run.map(|i| ud(K_HRECV, i, 0)));
            let srun = sp
                .srun
                .iter()
                .map(Option::is_some)
                .enumerate()
                .filter_map(busy);
            cancel.extend(srun.map(|i| ud(K_HSEND, i, 0)));
        }
        if self.zwake_armed {
            cancel.push(K_ZWAKE);
        }
        for u in cancel {
            self.push(opcode::AsyncCancel::new(u).build().user_data(K_IGN));
        }
        let t0 = Instant::now();
        loop {
            let left = self.retire_pending();
            if left == 0 {
                break;
            }
            if t0.elapsed() >= DROP_DRAIN_LIMIT {
                eprintln!(
                    "WARNING TIMEOUT knet drop drain exceeded {:.3}s ({left} requests in flight on {} connections: their buffers are leaked)",
                    DROP_DRAIN_LIMIT.as_secs_f64(),
                    self.by_id.len()
                );
                // memory the kernel may still write is never freed (and the sockets of those requests stay open)
                self.bufs.leak();
                std::mem::forget(std::mem::take(&mut self.slots));
                std::mem::forget(self.spread.take());
                std::mem::forget(std::mem::replace(&mut self.zwake, Box::new(0)));
                self.zwake_armed = false;
                return;
            }
            let ts = Timespec::new().nsec(100_000_000);
            let args = io_uring::types::SubmitArgs::new().timespec(&ts);
            self.stats.enters += 1;
            let _ = self.ring.submitter().submit_with_args(1, &args);
            loop {
                let next = self.ring.completion().next();
                let Some(cqe) = next else { break };
                self.retire_cqe(cqe.user_data(), cqe.result(), cqe.flags());
            }
        }
        for c in std::mem::take(&mut self.slots).iter().flatten() {
            // a socket lent to a spread core (receive or send job out, cores stop one by one): that core issues its next
            // request by fd number, so the number must not be reused under it; the process exit closes it
            if matches!(c.rx, Rx::Away) || c.send_away {
                continue;
            }
            // SAFETY: our socket; no request of this ring references it any more.
            unsafe { libc::close(c.fd) };
        }
        self.bufs.unregister(&self.ring.submitter());
    }

    /// Requests of this ring that reference memory of this core (see [`retire`](Self::retire)). A connection's
    /// `inflight` also counts work that is not on this ring: its receive or send job out on a spread core (the job owns
    /// that memory and comes back through the done ring) and its `RECV_ZC` (zcrx ring; the area is pinned by the ifq).
    fn retire_pending(&self) -> usize {
        let conns: u32 = self
            .slots
            .iter()
            .flatten()
            .map(|c| {
                c.inflight
                    - u32::from(matches!(c.rx, Rx::Away))
                    - u32::from(c.send_away)
                    - u32::from(c.zarmed)
            })
            .sum();
        let jobs = self.spread.as_ref().map_or(0, |sp| {
            sp.run.iter().flatten().count() + sp.srun.iter().flatten().count()
        });
        conns as usize + jobs + usize::from(self.zwake_armed)
    }

    /// One completion reaped by [`retire`](Self::retire): only the in-flight accounting, nothing is resubmitted. A spread
    /// job goes back to its submitter, failed unless its bytes are all done.
    fn retire_cqe(&mut self, u: u64, res: i32, flags: u32) {
        let (kind, slot) = (u & 0xf, ((u >> 4) & 0x0fff_ffff) as usize);
        match kind {
            // one count per request: multishot receives and zero-copy sends (notification) end without MORE
            K_RECV | K_DRECV | K_CONN | K_SEND if !cqueue::more(flags) => {
                if let Some(c) = self.slots.get_mut(slot).and_then(Option::as_mut) {
                    c.inflight -= 1;
                }
            }
            K_HRECV => {
                let Some(sp) = self.spread.as_mut() else {
                    return;
                };
                let Some(j) = sp.run[slot].as_mut() else {
                    return;
                };
                if res > 0 {
                    j.dx.commit(res as usize);
                    j.got += res as usize;
                }
                if j.dx.remaining() > 0 {
                    j.failed = Some(if res > 0 { -libc::ECANCELED } else { res });
                }
                sp.finish(slot as u32);
            }
            K_HSEND => {
                let Some(sp) = self.spread.as_mut() else {
                    return;
                };
                let Some(j) = sp.srun[slot].as_mut() else {
                    return;
                };
                if res > 0 {
                    advance(&mut j.st.runs, res as usize);
                    j.sent += res as usize;
                }
                if !j.st.runs.is_empty() {
                    // 0 bytes for a non-empty batch = the socket takes nothing more (as `on_hsend`)
                    j.failed = Some(match res {
                        0 => -libc::EPIPE,
                        1.. => -libc::ECANCELED,
                        _ => res,
                    });
                }
                sp.finish_send(slot as u32);
            }
            K_ZWAKE => self.zwake_armed = false,
            _ => {}
        }
    }

    /// Stop everything on the socket; it is closed once the last request completed.
    fn teardown(&mut self, slot: u32) {
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        if c.dying {
            return;
        }
        c.dying = true;
        // Output still queued here was produced by the messenger and never handed to the wire. The lossless session
        // replays it on the next stream, but the frame is late for its request: never clear it silently.
        let parked: usize = c.out.iter().map(Bytes::len).sum();
        if parked > 0 {
            eprintln!(
                "WARNING knet: conn {:#x}: {parked} byte(s) of output dropped at teardown (never handed to the wire)",
                c.id
            );
        }
        c.out.clear();
        #[cfg(feature = "rdma")]
        if let Some(pi) = c.rdma.plane {
            // the upgrade job / QP of this connection is released in the next RDMA phase
            // with its pull READs still in flight: their ranges stay claimed until the QP is destroyed
            let pulls = std::mem::take(&mut c.rdma.pulls);
            self.rdma_dead.push((pi, c.id, c.rdma.carrier.qpn(), pulls));
        }
        stop_socket(c);
        if c.dialing && c.inflight > 0 {
            let fd = c.fd;
            let e = opcode::AsyncCancel2::new(CancelBuilder::fd(Fd(fd)).all())
                .build()
                .user_data(K_IGN);
            self.push(e);
            // submitted before the fd can be closed (and its number reused): a queued cancel must never hit a new socket
            self.stats.enters += 1;
            let _ = self.ring.submit();
        }
        self.maybe_free(slot);
    }

    fn maybe_free(&mut self, slot: u32) {
        let done = self.slots[slot as usize]
            .as_ref()
            .is_some_and(|c| c.dying && c.inflight == 0);
        if done && let Some(mut c) = self.slots[slot as usize].take() {
            for (b, n) in std::mem::take(&mut c.held) {
                self.release_held(b, n);
            }
            if let Some(z) = self.zrx.as_mut() {
                while let Some(h) = c.zpend.pop() {
                    if let zcrx::book::Held::Area { off, len } = h {
                        z.book.release(len as usize);
                        z.give(off, len);
                    }
                }
            }
            self.hold_budget -= c.rmem;
            // SAFETY: nothing references the fd any more.
            unsafe { libc::close(c.fd) };
            self.free.push(slot);
            if let Some(p) = &self.place {
                p.lose();
            }
        }
    }

    /// Execute the OSD's socket commands (dial / close).
    pub fn pump_io<D: Driver>(&mut self, d: &mut D, now: Duration) {
        while let Some(cmd) = d.poll_io() {
            match cmd {
                IoCmd::Dial { conn, target, src } => {
                    let Some(to) = target.socket_addr() else {
                        // no IP in the target (blank entry): nothing to dial, and the OSD hears about it
                        d.on_dial_failed(conn, false, now);
                        continue;
                    };
                    self.dial(d, conn, to, src, now);
                }
                IoCmd::Close { conn } => self.close(d, conn, now),
                c @ (IoCmd::RdmaPrepare { .. }
                | IoCmd::RdmaAccept { .. }
                | IoCmd::RdmaConnect { .. }
                | IoCmd::RdmaRelease { .. }
                | IoCmd::PlaceReadReply { .. }
                | IoCmd::PlaceReadCancel { .. }
                | IoCmd::SourcePullRead { .. }) => self.rdma_cmd(d, c, now),
            }
        }
    }

    /// Graceful close of `conn` (`IoCmd::Close`): queued output first, then FIN, bounded by `close_linger`.
    pub(crate) fn close<D: Driver>(&mut self, d: &mut D, conn: u64, now: Duration) {
        self.flush_one(d, conn);
        let Some(slot) = self.by_id.remove(&conn) else {
            return;
        };
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        c.reported = true; // our own close: no on_closed
        // an upgraded connection: the posted output is fenced before the QP goes (`rdma_close_step`), bounded by
        // the linger like the TCP drain; nothing in flight = torn down at once
        let linger = now + self.cfg.close_linger;
        #[cfg(feature = "rdma")]
        if c.rdma.carrier.rdma_qpn().is_some() {
            c.closing = Some(linger);
            self.tick_due(linger);
            self.rdma_close_step(slot);
            return;
        }
        if c.sending || !c.out.is_empty() || !c.zc_hold.is_empty() {
            c.closing = Some(linger);
            let drained = !c.sending && c.out.is_empty();
            self.tick_due(linger);
            if drained {
                self.finish_tcp_close(slot);
            }
        } else {
            self.teardown(slot);
        }
    }

    /// Without feature `rdma` every RDMA command is declined: the connection stays on TCP.
    #[cfg(not(feature = "rdma"))]
    fn rdma_cmd<D: Driver>(&mut self, d: &mut D, cmd: IoCmd, now: Duration) {
        d.rdma_decline(cmd, now);
    }

    pub(crate) fn dial<D: Driver>(
        &mut self,
        d: &mut D,
        id: u64,
        to: SocketAddr,
        src: Option<IpAddr>,
        now: Duration,
    ) {
        // the socket family is the target's (spec ip-addressing.md 4); a source address of another family is never
        // bound (our caller picks our address of the target's family, or none)
        let src = src.filter(|ip| ip.is_ipv4() == to.is_ipv4());
        // SAFETY: socket(2); ownership passes to the connection slot.
        let fd = unsafe {
            libc::socket(
                listen::af(to.ip()),
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            eprintln!("knet: dial {to}: socket: {}", io::Error::last_os_error());
            d.on_dial_failed(id, false, now);
            return;
        }
        if self.cfg.sockbuf > 0
            && let Err(e) = listen::set_sockbuf(fd, self.cfg.sockbuf)
        {
            // the listeners already took the setting (a refused one fails the bind); a dial socket that refuses it
            // runs on autotuning, loudly once
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                eprintln!(
                    "croit-flashstore-osd: WARNING: knet: SO_SNDBUF/SO_RCVBUF {} not set on a dial socket: {e}",
                    self.cfg.sockbuf
                );
            });
        }
        // own address first (never the route's pick), then, steered, a source port that selects the peer's owner core.
        // Peer steering (source port) is IPv4 only: a v6 dial binds our v6 address and lets the kernel pick
        // the port (the classic BPF selector reads the IPv4 header).
        let mut steered = false;
        if let Some(src) = src.filter(IpAddr::is_ipv4)
            && self.cfg.peer_cores > 0
        {
            let IpAddr::V4(v4) = src else {
                unreachable!("filtered")
            };
            steered = matches!(to, SocketAddr::V4(_))
                && d.dial_owner(id).is_some_and(|me| {
                    listen::pick_src_port(
                        fd,
                        v4,
                        &self.src_ports,
                        self.cfg.peer_cores,
                        me % self.cfg.peer_cores,
                        &mut self.rnd,
                    )
                });
        }
        if !steered
            && let Some(src) = src
            && let Err(e) = listen::bind_src(fd, src)
        {
            eprintln!("knet: dial {to}: bind source {src}: {e}");
            // SAFETY: our own socket, not yet in a slot.
            unsafe { libc::close(fd) };
            d.on_dial_failed(id, false, now);
            return;
        }
        self.sock_opts(fd);
        let slot = self.add_conn(fd, id, true);
        let timeout = Timespec::from(self.cfg.connect_timeout);
        let (addr, len) = sockaddr(&to);
        let c = self.slots[slot as usize].as_mut().expect("just added");
        c.dial = Some(Box::new(Dial { addr, len, timeout }));
        c.inflight += 1;
        let dl = c.dial.as_ref().expect("set");
        let conn = opcode::Connect::new(Fd(fd), (&raw const dl.addr).cast(), dl.len)
            .build()
            .flags(Flags::IO_LINK)
            .user_data(ud(K_CONN, slot, 0));
        let lt = opcode::LinkTimeout::new(&raw const dl.timeout)
            .build()
            .user_data(K_IGN);
        self.push(conn);
        self.push(lt);
        self.stats.dialed += 1;
    }

    /// Hand pending OSD output to the socket, unless a send is in flight (then it stays inside the OSD).
    pub(crate) fn flush_one<D: Driver>(&mut self, d: &mut D, id: u64) {
        let Some(&slot) = self.by_id.get(&id) else {
            // No socket: count what is dropped instead of losing it silently.
            let runs = d.poll_output_chunks(id);
            let dropped: usize = runs.iter().map(Bytes::len).sum();
            if dropped > 0 {
                eprintln!("knet: conn {id:#x}: {dropped} byte(s) for a closed socket dropped");
            }
            return;
        };
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        // the pull is owed by the transport: a send completion pulls (`on_send`), a finished dial too (`on_connect`)
        if c.dialing || c.sending || c.dying {
            return;
        }
        #[cfg(feature = "rdma")]
        if c.rdma.carrier.rdma_qpn().is_some() {
            return self.rdma_flush(d, slot);
        }
        if c.out.is_empty() {
            d.poll_output_into(id, &mut c.out);
            if c.out.is_empty() {
                return;
            }
        }
        self.submit_send(slot);
    }

    /// Move all pending OSD output into sends; true if any connection was ready.
    pub fn flush_out<D: Driver>(&mut self, d: &mut D) -> bool {
        let mut any = false;
        while let Some(id) = d.poll_output_ready() {
            self.flush_one(d, id);
            any = true;
        }
        any
    }

    /// Output half of one loop iteration (adr 0074 am. 4): socket commands when the OSD was driven, the output-ready
    /// queue on EVERY iteration. Output queued by a producer the loop does not count as "driven" (a deferred store txn
    /// settled inside `poll_store`, ...) is on the wire before the core parks. True if any connection was ready.
    pub fn output_pass<D: Driver>(&mut self, d: &mut D, now: Duration, driven: bool) -> bool {
        if driven {
            self.pump_io(d, now);
        }
        self.flush_out(d)
    }

    /// Start a send from the connection's queue.
    fn submit_send(&mut self, slot: u32) {
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        if c.sending || c.dying {
            return;
        }
        c.st.runs.clear();
        let mut total = 0;
        let cap = if self.cfg.send_chunk > 0 {
            self.cfg.send_chunk
        } else {
            usize::MAX
        };
        while c.st.runs.len() < MAX_IOV
            && total < cap
            && let Some(mut b) = c.out.pop_front()
        {
            if total + b.len() > cap {
                let tail = b.split_off(cap - total);
                c.out.push_front(tail);
            }
            total += b.len();
            c.st.runs.push(b);
        }
        if c.st.runs.is_empty() {
            return;
        }
        // big runs only (>= ZC_RUN on average): a batch of many small frames would pay page pinning + a notification
        // for nothing. Never to a peer on this host: the kernel copies looped zero-copy skbs anyway (deferred copy),
        // and their truesize counts every touched page (payload/truesize 237/256 for a 64 KiB segment vs 252 copied).
        // On loopback the sender's skb is the receiver's, and the receiver sizes its window from the ratio of the
        // segments it measured: a socket mixing both kinds (small copied sends between large zero-copy ones) advertised
        // a window its rcvbuf could not hold -> prune / PROTO_MEM drop -> RTO (adr 0061, measured on ice-a kstall 4M).
        c.st.zc = self.zc
            && !c.local_peer
            && self.cfg.zc_min > 0
            && total >= self.cfg.zc_min
            && total >= ZC_RUN * c.st.runs.len();
        c.sending = true;
        #[cfg(feature = "cut-probe")]
        c.probe.tx_submit();
        if !self.send_out(slot, total) {
            self.resubmit_send(slot);
        }
    }

    /// (Re)build the iovec of the runs still to send and queue the request.
    fn resubmit_send(&mut self, slot: u32) {
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        if c.st.runs.is_empty() {
            return;
        }
        c.sending = true;
        let st = &mut *c.st;
        st.fill_iov();
        c.inflight += 1;
        let seq = if st.zc {
            c.zc_seq = c.zc_seq.wrapping_add(1);
            c.zc_seq
        } else {
            0
        };
        let flags = st.send_flags();
        let e = if st.zc {
            self.stats.zc_sends += 1;
            opcode::SendMsgZc::new(Fd(c.fd), &raw const st.msg)
                .flags(flags)
                .build()
        } else {
            opcode::SendMsg::new(Fd(c.fd), &raw const st.msg)
                .flags(flags)
                .build()
        }
        .user_data(ud(K_SEND, slot, seq));
        self.push(e);
    }

    /// Submit queued requests (end of an iteration).
    pub fn submit(&mut self) {
        if self.kick() {
            self.stats.enters_submit += 1;
        }
    }

    /// Submit at a send-first window close (counted apart from the end-of-iteration submit).
    pub fn submit_sf(&mut self) {
        if self.kick() {
            self.stats.enters_sf += 1;
        }
    }

    /// One-line state for logs.
    pub fn describe(&self) -> String {
        format!(
            "ring={} missing=[{}] zc={} bufs={}:{}x{} direct={}/{} spread={} bigshot={} {:?}",
            self.ring_mode,
            ring_mode_missing(self.ring_mode).join(","),
            self.zc,
            self.bufs.mode().name(),
            self.cfg.bufs,
            self.cfg.buf_size,
            self.cfg.direct_min,
            DIRECT_CHUNK,
            if self.spread.is_some() {
                self.cfg.spread_min
            } else {
                0
            },
            self.cfg.bigshot,
            self.stats
        ) + &self
            .zrx
            .as_ref()
            .map_or(String::new(), |z| format!(" {}", z.describe()))
    }
}

/// Bytes of the frame being received on `id` that may go straight into memory the OSD lends (segment buffer,
/// secure ciphertext buffer).
fn rx_want<D: Driver>(d: &mut D, id: u64) -> usize {
    d.rx_direct_want(id).max(d.rx_secure_want(id))
}

/// One receive request for the next piece of `dx` (connection core or spread helper). No `MSG_WAITALL`: available bytes
/// are reported promptly (an idle timer sees progress even when a slow peer has not filled the piece yet). The buffer is
/// pinned by its owner (connection slot / parked job) until the completion.
fn drecv_entry(fd: RawFd, dx: &mut DirectRx) -> Entry {
    let n = dx.remaining().min(DIRECT_CHUNK);
    opcode::Recv::new(Fd(fd), dx.receive_pointer(), n as u32).build()
}

/// End every request on `c`'s socket, keeping the fd: zero-copy output is aborted (a shutdown leaves queued TCP data
/// waiting for the peer's window/ACK, so its notifications might never come), then both directions are shut down
/// (pending receives complete with EOF, sends with EPIPE). Ordinary copied output keeps its FIN drain.
fn stop_socket(c: &Conn) {
    if !c.zc_hold.is_empty() || (c.sending && c.st.zc) {
        // Abort, keeping the fd and all payload owners until the kernel posts their final CQEs (zero-copy notifications).
        // SAFETY: live owned socket and initialized AF_UNSPEC address; connect retains no pointer.
        let aborted = unsafe {
            let mut unspec: libc::sockaddr = std::mem::zeroed();
            unspec.sa_family = libc::AF_UNSPEC as libc::sa_family_t;
            libc::connect(c.fd, &raw const unspec, size_of::<libc::sockaddr>() as _)
        };
        if aborted != 0 {
            eprintln!(
                "WARNING knet conn {:#x}: abort before zero-copy retirement failed ({}); payloads retained until notifications",
                c.id,
                io::Error::last_os_error()
            );
        }
    }
    // SAFETY: shutdown on our own socket; completes pending recv/send with EOF / EPIPE. Ordinary copied output
    // keeps its existing FIN drain; a terminal zero-copy abort above has already purged its TCP queue.
    unsafe { libc::shutdown(c.fd, libc::SHUT_RDWR) };
}

/// Drop `n` sent bytes from the front of `runs`.
fn advance(runs: &mut Vec<Bytes>, mut n: usize) {
    let mut whole = 0;
    for r in runs.iter() {
        if n >= r.len() {
            n -= r.len();
            whole += 1;
        } else {
            break;
        }
    }
    runs.drain(..whole);
    if n > 0
        && let Some(r) = runs.first_mut()
    {
        r.advance(n);
    }
}

impl<const N: usize> Drop for KNet<N> {
    fn drop(&mut self) {
        self.retire();
    }
}

#[cfg(test)]
mod tests;
