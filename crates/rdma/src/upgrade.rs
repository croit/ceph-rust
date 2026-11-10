// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Sans-IO half of the msgr2 RDMA upgrade on one core (spec 18, 0469-rdma-transport): the per-connection jobs behind the
//! four `IoCmd::Rdma*` commands ([`Upgrader`]), the GID binding, and the switch-point rule of the connection's byte
//! carrier ([`Carrier`]). The transport feeds commands in, polls [`Done`] out and does the I/O (attach the QP to the core's
//! CQ, watch the socket as liveness channel, answer the OSD); nothing here touches verbs or sockets, so the rules run in unit tests with a
//! scripted [`Link`].
use crate::control::{CoreLink, Full, Reply};
use crate::grant::{Permit, SessionCap};
use crate::{Endpoint, Release, gid_of};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The core's end of the control thread, as the upgrader uses it ([`CoreLink`] in production).
pub trait Link<Q> {
    fn prepare(&mut self, tag: u64) -> Result<(), Full<()>>;
    fn connect(&mut self, tag: u64, qp: Q, peer: Endpoint) -> Result<(), Full<Q>>;
    fn quiesce(&mut self, tag: u64, qp: Q, held: Release) -> Result<(), Full<(Q, Release)>>;
    fn destroy(&mut self, tag: u64, qp: Q, held: Release) -> Result<(), Full<(Q, Release)>>;
    fn retire(&mut self, tag: u64) -> Result<(), Full<()>>;
    fn poll(&mut self) -> Option<Reply<Q>>;
}

impl<Q> Link<Q> for CoreLink<Q> {
    fn prepare(&mut self, tag: u64) -> Result<(), Full<()>> {
        CoreLink::prepare(self, tag)
    }
    fn connect(&mut self, tag: u64, qp: Q, peer: Endpoint) -> Result<(), Full<Q>> {
        CoreLink::connect(self, tag, qp, peer)
    }
    fn quiesce(&mut self, tag: u64, qp: Q, held: Release) -> Result<(), Full<(Q, Release)>> {
        CoreLink::quiesce(self, tag, qp, held)
    }
    fn destroy(&mut self, tag: u64, qp: Q, held: Release) -> Result<(), Full<(Q, Release)>> {
        CoreLink::destroy(self, tag, qp, held)
    }
    fn retire(&mut self, tag: u64) -> Result<(), Full<()>> {
        CoreLink::retire(self, tag)
    }
    fn poll(&mut self) -> Option<Reply<Q>> {
        CoreLink::poll(self)
    }
}

/// Why a command was not started; the caller declines (server, prepare) or closes the connection (client connect).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The peer's endpoint record does not decode.
    Endpoint,
    /// The peer's GID is not the RoCEv2 GID of its TCP address (spec 18, trust).
    Gid,
    /// The control queue is full.
    Busy,
    /// No session slot: `flashstore_rdma_max_sessions` is reached, or the core's receive pool holds as many sessions as its
    /// minimum windows allow. The connection stays TCP (counted, never an error).
    Capped,
    /// No job of this connection in the state the command needs.
    State,
}

impl Refused {
    /// Log text (knet's decline/close lines, `crates/rt/src/knet/krdma.rs`).
    pub fn as_str(self) -> &'static str {
        match self {
            Refused::Endpoint => "undecodable endpoint",
            Refused::Gid => "peer GID differs from the GID of its TCP address",
            Refused::Busy => "control queue full",
            Refused::Capped => "session limit reached",
            Refused::State => "no such upgrade in progress",
        }
    }
}

/// Destroy requests carry this bit in their tag (connection ids never do).
const DESTROY: u64 = 1 << 63;

#[derive(Debug)]
enum Job<Q> {
    /// Client: QP requested from the control thread.
    Preparing,
    /// Client: OFFER sent, the QP waits for the server's answer.
    Offered { qp: Q },
    /// Client: connect to the server's endpoint in flight.
    Connecting { peer: Endpoint },
    /// Server: QP requested.
    AcceptPreparing { peer: Endpoint },
    /// Server: connect to the client's endpoint in flight.
    AcceptConnecting { peer: Endpoint, ours: Endpoint },
    /// The connection went away while a request was in flight: the QP of its reply is destroyed.
    Cancelled,
}

/// A QP the server connected for an accepted offer.
#[derive(Debug)]
pub struct Accepted<Q> {
    pub qp: Q,
    /// Our endpoint, to put into the ACCEPT frame.
    pub ours: Endpoint,
    /// The client's endpoint (the core needs its window and slot size).
    pub peer: Endpoint,
    /// The session's slot of the process-wide limit; the core keeps it while the session lives.
    pub permit: Permit,
}

/// What a finished request means for the transport.
#[derive(Debug)]
pub enum Done<Q> {
    /// `RdmaPrepare` finished: answer `Osd::rdma_prepared(conn, endpoint)`. After `Some` the QP is held until `connect` or
    /// `release`.
    Prepared {
        conn: u64,
        endpoint: Option<Endpoint>,
    },
    /// `RdmaAccept` finished: attach the QP, then answer `Osd::rdma_accepted`; `None` declines.
    Accepted {
        conn: u64,
        accepted: Option<Accepted<Q>>,
    },
    /// `RdmaConnect` finished: the QP is in RTS; attach it, switch the carrier, answer `Osd::rdma_connected`.
    Connected {
        conn: u64,
        qp: Q,
        peer: Endpoint,
        permit: Permit,
    },
    /// `RdmaConnect` failed: the connection closes.
    ConnectFailed { conn: u64 },
    /// A QP being torn down is in ERR and its last-WQE event came: `Core::quiesced`; destroy it once the core hands it
    /// out drained (`Core::drained`, [`Upgrader::destroy_drained`]).
    Quiesced { qp: Q, held: Release },
    /// A destroyed QP's send slots and receive credits are free again (`Core::reclaim`).
    Reclaim { held: Release },
}

/// Teardown step of a QP the control queue had no room for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Teardown {
    Quiesce,
    Destroy,
}

/// The upgrade jobs of one core and its link to the control thread.
#[derive(Debug)]
pub struct Upgrader<Q, L> {
    link: L,
    jobs: HashMap<u64, Job<Q>>,
    /// Most connections of the core (`Core::max_connections`): attached ones plus jobs never exceed it.
    capacity: usize,
    /// The process-wide session limit and the slot every job holds from its start until its session ends.
    cap: Arc<SessionCap>,
    permits: HashMap<u64, Permit>,
    /// Teardown requests the control queue had no room for.
    backlog: Vec<(Teardown, Q, Release)>,
    /// Results due besides the one of the reply that produced them (the QP of a failed connect).
    pending: VecDeque<Done<Q>>,
    seq: u64,
}

impl<Q, L: Link<Q>> Upgrader<Q, L> {
    pub fn new(link: L, capacity: usize, cap: Arc<SessionCap>) -> Self {
        Upgrader {
            link,
            jobs: HashMap::new(),
            capacity,
            cap,
            permits: HashMap::new(),
            backlog: Vec::new(),
            pending: VecDeque::new(),
            seq: 0,
        }
    }

    /// A session slot for a new job, or why not.
    fn admit(&self, attached: usize) -> Result<Permit, Refused> {
        if !self.room(attached) {
            return Err(Refused::Capped);
        }
        self.cap.acquire().ok_or(Refused::Capped)
    }

    /// Upgrades in progress.
    pub fn jobs(&self) -> usize {
        self.jobs.len()
    }

    fn room(&self, attached: usize) -> bool {
        attached + self.jobs.len() < self.capacity
    }

    /// `RdmaPrepare` (client): ask for a QP. `attached` = connections the core holds.
    pub fn prepare(&mut self, conn: u64, attached: usize) -> Result<(), Refused> {
        if self.jobs.contains_key(&conn) {
            return Err(Refused::State);
        }
        let permit = self.admit(attached)?;
        if self.link.prepare(conn).is_err() {
            return Err(Refused::Busy);
        }
        self.permits.insert(conn, permit);
        self.jobs.insert(conn, Job::Preparing);
        Ok(())
    }

    /// `RdmaAccept` (server): the client offered `endpoint` from TCP address `peer_ip`.
    pub fn accept(
        &mut self,
        conn: u64,
        endpoint: &[u8],
        peer_ip: IpAddr,
        attached: usize,
    ) -> Result<(), Refused> {
        let peer = peer_endpoint(endpoint, peer_ip)?;
        if self.jobs.contains_key(&conn) {
            return Err(Refused::State);
        }
        let permit = self.admit(attached)?;
        if self.link.prepare(conn).is_err() {
            return Err(Refused::Busy);
        }
        self.permits.insert(conn, permit);
        self.jobs.insert(conn, Job::AcceptPreparing { peer });
        Ok(())
    }

    /// `RdmaConnect` (client): the server accepted with `endpoint` from TCP address `peer_ip`. An error releases the prepared
    /// QP; the caller closes the connection.
    pub fn connect(&mut self, conn: u64, endpoint: &[u8], peer_ip: IpAddr) -> Result<(), Refused> {
        if !matches!(self.jobs.get(&conn), Some(Job::Offered { .. })) {
            return Err(Refused::State);
        }
        let peer = match peer_endpoint(endpoint, peer_ip) {
            Ok(p) => p,
            Err(e) => {
                self.release(conn);
                return Err(e);
            }
        };
        let Some(Job::Offered { qp }) = self.jobs.remove(&conn) else {
            return Err(Refused::State);
        };
        match self.link.connect(conn, qp, peer) {
            Ok(()) => {
                self.jobs.insert(conn, Job::Connecting { peer });
                Ok(())
            }
            Err(Full(qp)) => {
                self.permits.remove(&conn);
                self.destroy(qp, Release::default());
                Err(Refused::Busy)
            }
        }
    }

    /// The upgrade of `conn` ends (`RdmaRelease`, the connection closed, the OSD refused the answer): a held QP is destroyed,
    /// one still in flight is destroyed when its reply arrives. No job: nothing to do. True if a job was ended (the upgrade
    /// did not complete).
    pub fn release(&mut self, conn: u64) -> bool {
        self.permits.remove(&conn);
        match self.jobs.remove(&conn) {
            Some(Job::Offered { qp }) => self.destroy(qp, Release::default()),
            Some(Job::Cancelled) => {
                self.jobs.insert(conn, Job::Cancelled);
                return false;
            }
            Some(_) => {
                self.jobs.insert(conn, Job::Cancelled);
            }
            None => return false,
        }
        true
    }

    /// Start the teardown of a QP (detached from its core, `Core::detach`, or never attached) and what it held of the
    /// core: to ERR, last-WQE event ([`Done::Quiesced`]), CQ drain on the core, [`Upgrader::destroy_drained`].
    pub fn destroy(&mut self, qp: Q, held: Release) {
        self.teardown(Teardown::Quiesce, qp, held);
    }

    /// Destroy a QP the core handed out drained (`Core::drained`); answered with [`Done::Reclaim`].
    pub fn destroy_drained(&mut self, qp: Q, held: Release) {
        self.teardown(Teardown::Destroy, qp, held);
    }

    fn teardown(&mut self, t: Teardown, qp: Q, held: Release) {
        if let Err(Full((qp, held))) = self.submit(t, qp, held) {
            self.backlog.push((t, qp, held));
        }
    }

    fn submit(&mut self, t: Teardown, qp: Q, held: Release) -> Result<(), Full<(Q, Release)>> {
        self.seq += 1;
        match t {
            Teardown::Quiesce => self.link.quiesce(DESTROY | self.seq, qp, held),
            Teardown::Destroy => self.link.destroy(DESTROY | self.seq, qp, held),
        }
    }

    /// Next finished request; also retries teardowns the control queue refused.
    pub fn poll(&mut self) -> Option<Done<Q>> {
        loop {
            // Each consumed reply frees one control request slot, including
            // replies discarded below. Submit deferred work before returning
            // idle: there may be no other outstanding request left to wake us.
            while let Some((t, qp, held)) = self.backlog.pop() {
                if let Err(Full((qp, held))) = self.submit(t, qp, held) {
                    self.backlog.push((t, qp, held));
                    break;
                }
            }
            if let Some(d) = self.pending.pop_front() {
                return Some(d);
            }
            let r = self.link.poll()?;
            if let Some(d) = self.reply(r) {
                return Some(d);
            }
        }
    }

    fn reply(&mut self, r: Reply<Q>) -> Option<Done<Q>> {
        match r {
            Reply::Quiesced { qp, held, .. } => Some(Done::Quiesced { qp, held }),
            Reply::Destroyed { held, .. } => Some(Done::Reclaim { held }),
            Reply::Failed { tag, error } if tag & DESTROY != 0 => {
                // what that QP held stays lost (the HCA may still reference its send slots, its peer may still land
                // SENDs in the receive slots its credits cover)
                diag::diag!("rdma: qp teardown failed: {error}");
                None
            }
            Reply::Prepared { tag, qp, endpoint } => match self.jobs.remove(&tag) {
                Some(Job::Preparing) => {
                    self.jobs.insert(tag, Job::Offered { qp });
                    Some(Done::Prepared {
                        conn: tag,
                        endpoint: Some(endpoint),
                    })
                }
                Some(Job::AcceptPreparing { peer }) => match self.link.connect(tag, qp, peer) {
                    Ok(()) => {
                        self.jobs.insert(
                            tag,
                            Job::AcceptConnecting {
                                peer,
                                ours: endpoint,
                            },
                        );
                        None
                    }
                    Err(Full(qp)) => {
                        self.permits.remove(&tag);
                        self.destroy(qp, Release::default());
                        Some(Done::Accepted {
                            conn: tag,
                            accepted: None,
                        })
                    }
                },
                _ => {
                    // cancelled (or never asked for): nobody wants this QP
                    self.destroy(qp, Release::default());
                    None
                }
            },
            Reply::Connected { tag, qp } => {
                let permit = self.permits.remove(&tag);
                match (self.jobs.remove(&tag), permit) {
                    (Some(Job::AcceptConnecting { peer, ours }), Some(permit)) => {
                        Some(Done::Accepted {
                            conn: tag,
                            accepted: Some(Accepted {
                                qp,
                                ours,
                                peer,
                                permit,
                            }),
                        })
                    }
                    (Some(Job::Connecting { peer }), Some(permit)) => Some(Done::Connected {
                        conn: tag,
                        qp,
                        peer,
                        permit,
                    }),
                    _ => {
                        self.destroy(qp, Release::default());
                        None
                    }
                }
            }
            Reply::ConnectFailed { tag, qp, .. } => {
                // the QP may have received: drained by the core, then destroyed
                self.pending.push_back(Done::Quiesced {
                    qp,
                    held: Release::default(),
                });
                self.job_failed(tag)
            }
            Reply::Failed { tag, .. } => self.job_failed(tag),
        }
    }

    /// The job's request failed: what to answer.
    fn job_failed(&mut self, tag: u64) -> Option<Done<Q>> {
        match self.take_failed(tag) {
            Some(Job::Preparing) => Some(Done::Prepared {
                conn: tag,
                endpoint: None,
            }),
            Some(Job::AcceptPreparing { .. } | Job::AcceptConnecting { .. }) => {
                Some(Done::Accepted {
                    conn: tag,
                    accepted: None,
                })
            }
            Some(Job::Connecting { .. }) => Some(Done::ConnectFailed { conn: tag }),
            _ => None,
        }
    }

    /// A request failed: the job ends and gives its session slot back.
    fn take_failed(&mut self, tag: u64) -> Option<Job<Q>> {
        self.permits.remove(&tag);
        self.jobs.remove(&tag)
    }

    /// The core is going away: held QPs are destroyed, the control thread drops this core's pool and the call returns once it
    /// confirmed, so the CQ/SRQ can be destroyed after it. Waits at most `limit` (loud, then gives up). Returns whether the
    /// control thread confirmed: false = it may still hold (or be creating) QPs on this core's CQ/SRQ, so the caller must
    /// not destroy them (`verbs::Core::leak`).
    #[must_use]
    pub fn retire(&mut self, limit: Duration, ctx: &str) -> bool {
        self.permits.clear();
        self.jobs.clear(); // drops held QPs (destroyed inline: shutdown path, not a data-path core any more)
        self.backlog.clear();
        let start = Instant::now();
        let tag = u64::MAX; // a destroy tag no other request uses
        while self.link.retire(tag).is_err() {
            while self.link.poll().is_some() {}
            if self.timed_out(start, limit, ctx) {
                return false;
            }
            std::thread::yield_now();
        }
        loop {
            match self.link.poll() {
                Some(Reply::Destroyed { tag: t, .. }) if t == tag => return true,
                Some(_) => {}
                None => {
                    if self.timed_out(start, limit, ctx) {
                        return false;
                    }
                    std::thread::yield_now();
                }
            }
        }
    }

    fn timed_out(&self, start: Instant, limit: Duration, ctx: &str) -> bool {
        let t = start.elapsed() >= limit;
        if t {
            diag::diag!(
                "WARNING TIMEOUT rdma retire exceeded {}s ({ctx})",
                limit.as_secs_f64()
            );
        }
        t
    }
}

/// Decode the peer's endpoint and bind it to its TCP address.
fn peer_endpoint(endpoint: &[u8], peer_ip: IpAddr) -> Result<Endpoint, Refused> {
    let ep = Endpoint::decode(endpoint).ok_or(Refused::Endpoint)?;
    if ep.gid != gid_of(peer_ip) {
        return Err(Refused::Gid);
    }
    Ok(ep)
}

/// The byte carrier of a connection and the switch point (spec 18): the OFFER is the client's last TCP byte, the ACCEPT the
/// server's; everything after travels on the QP and TCP bytes behind the switch point are a fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    Tcp,
    /// The QP is attached; TCP still carries what was queued before the switch point (the ACCEPT frame).
    Armed(u32),
    /// The QP carries the stream; the socket stays open without data as the liveness channel of the connection.
    Rdma(u32),
}

/// What a read of the TCP socket returned (the transport maps its result: bytes, end of stream / reset, or nothing yet).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SockRead {
    /// Bytes arrived (or wait for a buffer: bytes are pending).
    Bytes,
    /// End of stream or a socket error (reset): the peer closed or died.
    End,
    /// Nothing happened (interrupted, would block, own cancel).
    Idle,
}

/// What a read of the TCP socket means for the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpRx {
    /// The socket carries the stream: handle as usual.
    Normal,
    /// Bytes behind the switch point: protocol fault, close the connection at once.
    Fault,
    /// Past the switch point the socket is the connection's liveness channel: its end means the peer closed the connection
    /// (after its close fence) or died. Deliver what the CQ holds for the connection, then close it like a TCP connection
    /// whose peer closed.
    Closed,
    /// Nothing changed; keep watching the socket.
    Idle,
}

impl Carrier {
    /// The QP `qpn` is attached; TCP carries what is queued up to the switch point.
    pub fn arm(&mut self, qpn: u32) -> bool {
        if *self != Carrier::Tcp {
            return false;
        }
        *self = Carrier::Armed(qpn);
        true
    }

    /// May the carrier switch now? Server: after the ACCEPT frame was sent completely, i.e. nothing queued and nothing in
    /// flight on TCP. A switch never happens before.
    pub fn switch_ready(&self, out_empty: bool, sending: bool) -> bool {
        matches!(self, Carrier::Armed(_)) && out_empty && !sending
    }

    /// Armed -> Rdma.
    pub fn switch(&mut self) -> bool {
        match *self {
            Carrier::Armed(q) => {
                *self = Carrier::Rdma(q);
                true
            }
            _ => false,
        }
    }

    pub fn qpn(&self) -> Option<u32> {
        match *self {
            Carrier::Armed(q) | Carrier::Rdma(q) => Some(q),
            Carrier::Tcp => None,
        }
    }

    /// The QP when it carries the stream.
    pub fn rdma_qpn(&self) -> Option<u32> {
        match *self {
            Carrier::Rdma(q) => Some(q),
            _ => None,
        }
    }

    pub fn is_tcp(&self) -> bool {
        *self == Carrier::Tcp
    }

    /// Meaning of a read of the socket (spec 18 "Socket after the switch"). Armed counts as switched: the peer's last TCP
    /// byte (the OFFER) has arrived already.
    pub fn tcp_rx(&self, read: SockRead) -> TcpRx {
        match self {
            Carrier::Tcp => TcpRx::Normal,
            _ => liveness(read),
        }
    }
}

/// Meaning of a read of the socket of a connection past the switch point (the socket is its liveness channel).
pub fn liveness(read: SockRead) -> TcpRx {
    match read {
        SockRead::Bytes => TcpRx::Fault,
        SockRead::End => TcpRx::Closed,
        SockRead::Idle => TcpRx::Idle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A link that answers at once (the control thread is covered in `control`), recording what was asked.
    #[derive(Default)]
    struct Mock {
        replies: VecDeque<Reply<u32>>,
        log: Vec<String>,
        next_qpn: u32,
        full: bool,
        capacity: Option<usize>,
        fail_prepare: bool,
        fail_connect: bool,
        /// The control thread hangs: a retire is queued but never answered.
        hung: bool,
    }

    fn ep(qpn: u32, ip: &str) -> Endpoint {
        Endpoint {
            qpn,
            psn: 1,
            gid: gid_of(ip.parse().unwrap()),
            window: 64,
            slot: 4096,
            mtu: 4096,
            reads: None,
        }
    }

    impl Link<u32> for Mock {
        fn prepare(&mut self, tag: u64) -> Result<(), Full<()>> {
            if self.full || self.capacity.is_some_and(|cap| self.replies.len() >= cap) {
                return Err(Full(()));
            }
            self.log.push(format!("prepare {tag}"));
            if self.fail_prepare {
                self.replies.push_back(Reply::Failed {
                    tag,
                    error: "no qp".into(),
                });
            } else {
                self.next_qpn += 1;
                let endpoint = ep(self.next_qpn, "10.0.0.1");
                self.replies.push_back(Reply::Prepared {
                    tag,
                    qp: self.next_qpn,
                    endpoint,
                });
            }
            Ok(())
        }
        fn connect(&mut self, tag: u64, qp: u32, peer: Endpoint) -> Result<(), Full<u32>> {
            if self.full || self.capacity.is_some_and(|cap| self.replies.len() >= cap) {
                return Err(Full(qp));
            }
            self.log
                .push(format!("connect {tag} qp{qp} -> {}", peer.qpn));
            if self.fail_connect {
                self.replies.push_back(Reply::ConnectFailed {
                    tag,
                    error: "refused".into(),
                    qp,
                });
            } else {
                self.replies.push_back(Reply::Connected { tag, qp });
            }
            Ok(())
        }
        /// Quiesced at once (the event and the core's drain are tested in control and verbs).
        fn quiesce(
            &mut self,
            tag: u64,
            qp: u32,
            held: Release,
        ) -> Result<(), Full<(u32, Release)>> {
            if self.full || self.capacity.is_some_and(|cap| self.replies.len() >= cap) {
                return Err(Full((qp, held)));
            }
            self.log.push(format!("quiesce qp{qp}"));
            self.replies.push_back(Reply::Quiesced { tag, qp, held });
            Ok(())
        }
        fn destroy(
            &mut self,
            tag: u64,
            qp: u32,
            held: Release,
        ) -> Result<(), Full<(u32, Release)>> {
            if self.full || self.capacity.is_some_and(|cap| self.replies.len() >= cap) {
                return Err(Full((qp, held)));
            }
            self.log.push(format!("destroy qp{qp}"));
            self.replies.push_back(Reply::Destroyed { tag, held });
            Ok(())
        }
        fn retire(&mut self, tag: u64) -> Result<(), Full<()>> {
            self.log.push("retire".into());
            if self.hung {
                return Ok(());
            }
            self.replies.push_back(Reply::Destroyed {
                tag,
                held: Release::default(),
            });
            Ok(())
        }
        fn poll(&mut self) -> Option<Reply<u32>> {
            self.replies.pop_front()
        }
    }

    fn up() -> Upgrader<u32, Mock> {
        Upgrader::new(Mock::default(), 4, SessionCap::new(0))
    }

    #[test]
    fn discarded_reply_resumes_teardown_without_another_wake() {
        let mut u = up();
        u.link.capacity = Some(1);
        u.link.fail_prepare = true;
        u.prepare(1, 0).unwrap();
        u.release(1);
        u.destroy(99, Release::default());
        assert_eq!(u.backlog.len(), 1);
        assert!(matches!(u.poll(), Some(Done::Quiesced { qp: 99, .. })));
        assert!(u.backlog.is_empty());
        assert_eq!(u.jobs(), 0);
    }

    const CLIENT: &str = "10.0.0.2";
    const SERVER: &str = "10.0.0.1";

    #[test]
    fn client_prepare_connect_in_order() {
        let mut u = up();
        u.prepare(7, 0).unwrap();
        let Some(Done::Prepared {
            conn: 7,
            endpoint: Some(e),
        }) = u.poll()
        else {
            panic!()
        };
        assert_eq!(e.qpn, 1);
        // the server's ACCEPT carries its endpoint: bound to the TCP peer address
        let acc = ep(55, SERVER).encode();
        u.connect(7, &acc, SERVER.parse().unwrap()).unwrap();
        let Some(Done::Connected {
            conn: 7,
            qp: 1,
            peer,
            ..
        }) = u.poll()
        else {
            panic!()
        };
        assert_eq!(peer.qpn, 55);
        assert_eq!(u.jobs(), 0);
        assert_eq!(u.link.log, ["prepare 7", "connect 7 qp1 -> 55"]);
    }

    #[test]
    fn server_accept_prepares_then_connects_then_answers() {
        let mut u = up();
        let offer = ep(9, CLIENT).encode();
        u.accept(3, &offer, CLIENT.parse().unwrap(), 0).unwrap();
        let Some(Done::Accepted {
            conn: 3,
            accepted: Some(a),
        }) = u.poll()
        else {
            panic!()
        };
        assert_eq!((a.qp, a.ours.qpn, a.peer.qpn), (1, 1, 9));
        assert_eq!(u.link.log, ["prepare 3", "connect 3 qp1 -> 9"]);
        assert_eq!(u.jobs(), 0);
    }

    #[test]
    fn gid_must_match_the_tcp_peer_address() {
        let mut u = up();
        // server: offer from another host than its GID says
        let offer = ep(9, "10.0.0.99").encode();
        assert_eq!(
            u.accept(3, &offer, CLIENT.parse().unwrap(), 0),
            Err(Refused::Gid)
        );
        assert!(u.link.log.is_empty(), "no QP is created for a spoofed GID");
        // IPv6 peers: the address itself
        let mut e = ep(9, "fd00::5");
        e.gid = gid_of("fd00::5".parse().unwrap());
        assert!(
            u.accept(4, &e.encode(), "fd00::5".parse().unwrap(), 0)
                .is_ok()
        );
        // client: the ACCEPT's endpoint of another address releases the prepared QP
        u.prepare(7, 0).unwrap();
        while u.poll().is_some() {}
        let bad = ep(55, "10.0.0.50").encode();
        assert_eq!(
            u.connect(7, &bad, SERVER.parse().unwrap()),
            Err(Refused::Gid)
        );
        assert!(u.link.log.iter().any(|l| l.starts_with("quiesce")));
        assert_eq!(u.jobs(), 0);
        // garbage endpoint
        assert_eq!(
            u.accept(5, &[1, 2, 3], CLIENT.parse().unwrap(), 0),
            Err(Refused::Endpoint)
        );
    }

    #[test]
    fn failures_decline_or_close() {
        let mut u = up();
        u.link.fail_prepare = true;
        u.prepare(1, 0).unwrap();
        assert!(matches!(
            u.poll(),
            Some(Done::Prepared {
                conn: 1,
                endpoint: None
            })
        ));
        let offer = ep(9, CLIENT).encode();
        u.accept(2, &offer, CLIENT.parse().unwrap(), 0).unwrap();
        assert!(matches!(
            u.poll(),
            Some(Done::Accepted {
                conn: 2,
                accepted: None
            })
        ));
        u.link.fail_prepare = false;
        u.link.fail_connect = true;
        u.accept(3, &offer, CLIENT.parse().unwrap(), 0).unwrap();
        assert!(matches!(
            u.poll(),
            Some(Done::Accepted {
                conn: 3,
                accepted: None
            })
        ));
        // the QP of the failed connect comes back quiesced: drained by the core, then destroyed
        assert!(matches!(
            u.poll(),
            Some(Done::Quiesced { held, .. }) if held == Release::default()
        ));
        u.prepare(4, 0).unwrap();
        while u.poll().is_some() {}
        u.connect(4, &ep(55, SERVER).encode(), SERVER.parse().unwrap())
            .unwrap();
        assert!(matches!(u.poll(), Some(Done::ConnectFailed { conn: 4 })));
        assert_eq!(u.jobs(), 0);
    }

    #[test]
    fn release_destroys_a_held_qp_and_cancels_one_in_flight() {
        let mut u = up();
        u.prepare(1, 0).unwrap();
        while u.poll().is_some() {}
        u.release(1); // server declined: RdmaRelease
        assert_eq!(u.link.log.last().unwrap(), "quiesce qp1");
        // quiesced: the core drains its CQ, then the QP is destroyed
        let Some(Done::Quiesced { qp, held }) = u.poll() else {
            panic!("quiesced first")
        };
        u.destroy_drained(qp, held);
        assert_eq!(u.link.log.last().unwrap(), "destroy qp1");
        assert!(matches!(u.poll(), Some(Done::Reclaim { .. })));
        // the connection closes while the QP is still being prepared
        u.prepare(2, 0).unwrap();
        u.release(2);
        assert_eq!(u.jobs(), 1);
        // the reply's QP is torn down the same way, nothing is answered to the OSD
        let Some(Done::Quiesced { qp, held }) = u.poll() else {
            panic!("quiesced first")
        };
        assert_eq!(u.link.log.last().unwrap(), "quiesce qp2");
        u.destroy_drained(qp, held);
        assert!(matches!(u.poll(), Some(Done::Reclaim { .. })));
        assert!(u.poll().is_none());
        assert_eq!(u.link.log.last().unwrap(), "destroy qp2");
        assert_eq!(u.jobs(), 0);
        u.release(99); // unknown: nothing
    }

    #[test]
    fn capacity_and_full_queue_refuse() {
        let mut u = up();
        for c in 0..2 {
            u.prepare(c, 2).unwrap();
        }
        // 2 attached + 2 jobs = capacity 4
        assert_eq!(u.prepare(5, 2), Err(Refused::Capped));
        assert_eq!(
            u.prepare(0, 0),
            Err(Refused::State),
            "one job per connection"
        );
        let mut u = up();
        u.link.full = true;
        assert_eq!(u.prepare(1, 0), Err(Refused::Busy));
        // teardown steps the control queue refuses are retried by poll, in their step
        u.destroy(
            8,
            Release {
                slots: vec![3],
                credits: 5,
            },
        );
        assert!(u.poll().is_none());
        u.link.full = false;
        let Some(Done::Quiesced { qp: 8, held }) = u.poll() else {
            panic!("quiesced after the retry")
        };
        u.link.full = true;
        u.destroy_drained(8, held);
        assert!(u.poll().is_none());
        u.link.full = false;
        assert!(
            matches!(u.poll(), Some(Done::Reclaim { held }) if held.slots == [3] && held.credits == 5)
        );
        assert_eq!(u.link.log, ["quiesce qp8", "destroy qp8"]);
    }

    #[test]
    fn session_limit_declines_and_slots_come_back() {
        let cap = SessionCap::new(2);
        let mut u = Upgrader::new(Mock::default(), 100, cap.clone());
        let offer = ep(9, CLIENT).encode();
        let ip: IpAddr = CLIENT.parse().unwrap();
        u.accept(1, &offer, ip, 0).unwrap();
        u.prepare(2, 0).unwrap();
        assert_eq!(cap.live(), 2);
        // the limit is reached: a decline, no QP is created for it
        let asked = u.link.log.len();
        assert_eq!(u.accept(3, &offer, ip, 0), Err(Refused::Capped));
        assert_eq!(u.prepare(4, 0), Err(Refused::Capped));
        assert_eq!(u.link.log.len(), asked);
        // an accepted session keeps its slot (it is handed to the core)
        let mut held = Vec::new();
        while let Some(d) = u.poll() {
            if let Done::Accepted {
                accepted: Some(a), ..
            } = d
            {
                held.push(a.permit);
            }
        }
        assert_eq!(held.len(), 1);
        assert_eq!(cap.live(), 2);
        // the client job ends (offer declined by the server): its slot is free again
        u.release(2);
        assert_eq!(cap.live(), 1);
        u.prepare(5, 0).unwrap();
        drop(held);
        u.release(5);
        assert_eq!(cap.live(), 0);
    }

    #[test]
    fn connect_needs_a_prepared_qp() {
        let mut u = up();
        let acc = ep(55, SERVER).encode();
        assert_eq!(
            u.connect(1, &acc, SERVER.parse().unwrap()),
            Err(Refused::State)
        );
        u.prepare(1, 0).unwrap();
        // the answer arrives before the QP is ready: refused, the job goes on
        assert_eq!(
            u.connect(1, &acc, SERVER.parse().unwrap()),
            Err(Refused::State)
        );
        assert_eq!(u.jobs(), 1);
    }

    #[test]
    fn retire_waits_for_the_control_thread() {
        let mut u = up();
        u.prepare(1, 0).unwrap();
        while u.poll().is_some() {}
        assert!(u.retire(Duration::from_secs(1), "core 0"));
        assert_eq!(u.link.log.last().unwrap(), "retire");
        assert_eq!(u.jobs(), 0);
    }

    /// A control thread that does not answer the retire: the call gives up after its limit (loud) and reports it, so the
    /// caller leaves the CQ/SRQ allocated instead of destroying them under the thread's QPs.
    #[test]
    fn retire_of_a_hung_control_thread_reports_no_confirmation() {
        let mut u = up();
        u.link.hung = true;
        let t = std::time::Instant::now();
        assert!(!u.retire(Duration::from_millis(20), "core 0 (test)"));
        assert!(t.elapsed() >= Duration::from_millis(20));
        assert_eq!(u.jobs(), 0);
    }

    #[test]
    fn switch_point_is_after_the_last_tcp_byte() {
        let mut c = Carrier::Tcp;
        assert_eq!(c.tcp_rx(SockRead::Bytes), TcpRx::Normal);
        assert!(!c.switch_ready(true, false), "nothing armed: no switch");
        assert!(c.arm(7));
        assert!(!c.arm(8), "armed once");
        // the ACCEPT frame is queued or in flight: TCP stays the carrier
        assert!(!c.switch_ready(false, false));
        assert!(!c.switch_ready(true, true));
        assert_eq!(c.rdma_qpn(), None);
        assert_eq!(c.qpn(), Some(7));
        assert!(c.switch_ready(true, false));
        assert!(c.switch());
        assert_eq!(c.rdma_qpn(), Some(7));
        assert!(!c.switch());
    }

    #[test]
    fn tcp_bytes_after_the_switch_point_fault_and_the_socket_end_closes_the_connection() {
        let mut c = Carrier::Tcp;
        assert_eq!(c.tcp_rx(SockRead::Bytes), TcpRx::Normal);
        assert_eq!(c.tcp_rx(SockRead::End), TcpRx::Normal, "plain TCP EOF");
        c.arm(1);
        assert_eq!(
            c.tcp_rx(SockRead::Bytes),
            TcpRx::Fault,
            "behind the ACCEPT frame"
        );
        assert_eq!(
            c.tcp_rx(SockRead::End),
            TcpRx::Closed,
            "the peer closed or died before the switch completed"
        );
        assert_eq!(c.tcp_rx(SockRead::Idle), TcpRx::Idle);
        c.switch();
        assert_eq!(c.tcp_rx(SockRead::Bytes), TcpRx::Fault);
        assert_eq!(
            c.tcp_rx(SockRead::End),
            TcpRx::Closed,
            "the socket is the liveness channel: its end is the connection's end"
        );
        assert_eq!(c.tcp_rx(SockRead::Idle), TcpRx::Idle);
    }
}
