// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Sans-IO msgr2 connection state machine (spec 1, 7-13).
//!
//! One [`Connection`] object = one logical link to a peer. A client-role connection survives TCP
//! streams (it asks for a new one with [`Event::Dial`] after backoff); a server-role connection
//! dies with its stream and hands its session back to the [`SessionTable`].
//!
//! Driver contract: feed received bytes with [`Connection::on_bytes`], write what
//! [`Connection::poll_output`] returns, drain [`Connection::poll_event`], call
//! [`Connection::on_timer`] at [`Connection::next_timer`], report socket loss with
//! [`Connection::on_closed`], and close the sockets of connections listed by
//! [`SessionTable::take_superseded`]. Time is a monotonic [`Duration`] since an arbitrary origin.
use crate::auth::*;
use crate::decode::DecoderCfg;
use crate::payload::*;
use crate::policy::{Policy, PolicyTable};
use crate::session::*;
use crate::{
    Banner, BannerError, ConnSecret, Decoder, Encoder, Error, FEATURE_COMPRESSION,
    FEATURE_PLACEMENT, FEATURE_RDMA, FEATURE_REVISION_1, FEATURE_SOURCE_PULL, FLAG_COMPRESSED,
    FRAME_MIN_RATE, Limits, PREAUTH_TRANSCRIPT_MAX, Revision, Role, Tag,
};
use aws_lc_rs::hmac;
use bytes::Bytes;
use denc::types::{EntityAddr, EntityAddrVec, EntityName};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

type Res<T = ()> = Result<T, FaultReason>;
const PLACEMENT_CONTROL_LEN: usize = 28;

#[cfg(test)]
#[path = "conn_bounded_tests.rs"]
mod bounded_preparation_tests;

#[cfg(test)]
#[path = "conn_keepalive_tests.rs"]
mod keepalive_tests;

#[cfg(test)]
#[path = "conn_send_tests.rs"]
mod send_tests;

/// Why a connection faulted (the socket must be closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultReason {
    /// Socket error / EOF reported by the driver.
    Io,
    /// Banner rejected (never retried).
    Banner(BannerError),
    /// Frame layer error.
    Frame(Error),
    /// Protocol violation.
    Protocol(&'static str),
    /// Auth layer rejected.
    Auth(String),
    /// Server lacks required features (IDENT_MISSING_FEATURES).
    MissingFeatures(u64),
    /// Peer sent WAIT (connection race lost).
    Wait,
    /// A timeout fired.
    Timeout(&'static str),
    /// Peer dropped silently / connection intentionally dropped.
    Dropped,
}

impl FaultReason {
    fn fatal(&self) -> bool {
        matches!(self, Self::Banner(_))
    }
}

/// Static configuration of a messenger (shared by all its connections).
#[derive(Clone, Debug)]
pub struct Config {
    /// Our entity name; `num < 0` = take the global id assigned by auth (clients).
    pub name: EntityName,
    /// Our advertised addresses (CLIENT_IDENT/SERVER_IDENT; first must not be blank for clients
    /// that want to be reachable).
    pub addrs: EntityAddrVec,
    /// CEPH_FEATURE_* we support.
    pub supported_features: u64,
    /// Policy by peer entity type (used by both roles).
    pub policies: PolicyTable,
    /// Advertise and handle the (no-op) COMPRESSION handshake. Default false (spec 2).
    pub compression: bool,
    /// Bind cephx CLIENT_IDENT gids and resumed sessions to the authenticated
    /// client global id. Default false preserves shared OSD/client behavior;
    /// MDS frontend listeners opt in to reject cross-client session adoption.
    pub bind_client_identity: bool,
    /// Behave like a v2.0-only peer: do not advertise REVISION_1, always use v2.0 framing
    /// (compat/testing; default false).
    pub v20_only: bool,
    /// Verify the peer's AUTH_SIGNATURE (default true). Replay tests of recorded handshakes cannot sign.
    #[cfg(feature = "test-hooks")]
    pub verify_signature: bool,
    /// Frame size limits.
    pub limits: Limits,
    /// Largest received MESSAGE in segment bytes (`osd_client_message_size_cap`): a peer's larger MESSAGE faults at
    /// its preamble before it reserves anything. `u64::MAX` = only `limits.max_frame`. Outbound frames are not capped
    /// (a read reply may be larger than the message cap). Default `u64::MAX`.
    pub max_message: u64,
    /// Retain per-4 KiB receive CRC metadata for downstream storage consumers.
    /// Whole-segment CRC verification is always enabled. Default true.
    pub rx_block_crcs: bool,
    /// `ms_crc_data` (spec msgr2.md 4.3), read when a connection is created: a runtime change affects only
    /// connections created afterwards, secure-mode connections ignore it. True (default): compute and verify the
    /// segment crcs of CRC-mode frames. False: write 0 into every segment crc slot and skip the receive comparison
    /// (preamble crc, `late_status` and GCM tags still checked), so payload integrity rests on TCP only.
    pub crc_data: bool,
    /// First reconnect backoff (ms_initial_backoff, 0.2 s).
    pub initial_backoff: Duration,
    /// Backoff cap (ms_max_backoff, 15 s).
    pub max_backoff: Duration,
    /// Retry delay after the peer answered WAIT (connection race: its connection is coming). Spec/classic: ms_max_backoff. An
    /// endpoint whose connections of one peer land in different session tables (one table per core) never gets the awaited
    /// connection in THIS table, so it should retry soon instead of idling for 15 s.
    pub wait_backoff: Duration,
    /// Time allowed to reach READY (ms_connection_ready_timeout, 10 s).
    pub ready_timeout: Duration,
    /// Idle connection timeout (ms_connection_idle_timeout, 900 s).
    pub idle_timeout: Duration,
    /// Multi-core placement of peer OSD sessions (ADR 0031): a server-role connection whose authenticated OSD is not
    /// owned by this core stops before CLIENT_IDENT / SESSION_RECONNECT with [`Event::Handoff`], so the driver can move
    /// it to the owning core (one session table per peer). `None` = every connection is handled here.
    pub home: Option<Home>,
    /// Advertise [`FEATURE_RDMA`] and run the RDMA upgrade (spec 18) with peers that advertise it. Default false.
    pub rdma: bool,
    /// Advertise the placement extension only when a qualified provider and the complete
    /// attempt/retirement protocol are installed by the driver. Default false. Implies `rdma`.
    pub placement: bool,
    /// Advertise source-pull only when its complete object protocol is installed.
    /// Default false; provider READ resources are separately negotiated.
    pub source_pull: bool,
}

/// Which core owns the sessions of which peer OSD: core `osd % n` ([`Home::new`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Home {
    me: usize,
    n: usize,
}

impl Home {
    /// Placement on `n` cores of which this is core `me`. `None` when `n == 0`: there is no owner to place a peer on.
    pub fn new(me: usize, n: usize) -> Option<Self> {
        (n > 0).then_some(Self { me, n })
    }

    /// Core owning the sessions of OSD `osd`.
    pub fn owner(&self, osd: i64) -> usize {
        osd.max(0) as usize % self.n
    }

    /// Does this core own the sessions of OSD `osd`?
    pub fn is_home(&self, osd: i64) -> bool {
        self.owner(osd) == self.me
    }
}

impl Config {
    /// `ms_connection_idle_timeout` default.
    pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(900);

    /// Defaults per spec for `name` advertising `addrs`.
    pub fn new(name: EntityName, addrs: EntityAddrVec, policies: PolicyTable) -> Self {
        Self {
            name,
            addrs,
            supported_features: crate::policy::FEATURES_SUPPORTED_DEFAULT,
            policies,
            compression: false,
            bind_client_identity: false,
            v20_only: false,
            #[cfg(feature = "test-hooks")]
            verify_signature: true,
            limits: Limits::default(),
            max_message: u64::MAX,
            rx_block_crcs: true,
            crc_data: true,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(15),
            wait_backoff: Duration::from_secs(15),
            ready_timeout: Duration::from_secs(10),
            idle_timeout: Self::DEFAULT_IDLE_TIMEOUT,
            home: None,
            rdma: false,
            placement: false,
            source_pull: false,
        }
    }

    fn banner(&self) -> Banner {
        Banner {
            supported: if self.v20_only { 0 } else { FEATURE_REVISION_1 }
                | if self.compression {
                    FEATURE_COMPRESSION
                } else {
                    0
                }
                | if self.rdma { FEATURE_RDMA } else { 0 }
                | if self.rdma && self.placement {
                    FEATURE_PLACEMENT
                } else {
                    0
                }
                | if self.rdma && self.source_pull {
                    FEATURE_SOURCE_PULL
                } else {
                    0
                },
            required: 0,
        }
    }
}

/// A received message. Not `Clone`: its dispatch credit is released exactly once.
#[derive(Debug, PartialEq, Eq)]
pub struct Incoming {
    /// Logical MESSAGE dispatch lifetime, independent of physical ingress and payload owners.
    pub dispatch: crate::DispatchGuard,
    /// Local receive ownership, excluded from payload equality and wire encoding.
    pub ingress: ingress::InputGuard,
    /// header2.
    pub header: MsgHeader2,
    /// Front segment.
    pub front: bytes::Bytes,
    /// Middle segment.
    pub middle: bytes::Bytes,
    /// Data segment.
    pub data: bytes::Bytes,
    /// Verified crc of `data` from the receive pass (CRC mode rev 2.1; owner-bound, see `crc::CrcHint`).
    pub data_crc: crc::CrcHint,
    /// Declared length of a data segment the receive probe refused ([`Connection::set_data_probe`]): the bytes were
    /// consumed and verified but are not part of `data` (which is empty). 0 = the frame carried no refused segment.
    pub data_refused: u32,
}

/// Facts about the peer once READY.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// Peer entity name (type from HELLO/expected, number from ident gid).
    pub name: EntityName,
    /// Peer's advertised addresses.
    pub addrs: EntityAddrVec,
    /// Connection features (peer supported & ours).
    pub features: u64,
    /// Effective lossiness.
    pub lossy: bool,
    /// True if an existing session was resumed (RECONNECT), false for a new session.
    pub resumed: bool,
    /// Global id from the auth layer.
    pub global_id: u64,
    /// Authenticated name (server role, if the method provides one).
    pub auth_name: Option<EntityName>,
}

/// Things the driver / upper layer must react to. Not `Clone`: [`Event::Message`] owns one dispatch credit.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// Client role: open a TCP connection to `target`, then call [`Connection::on_connected`]
    /// (or [`Connection::on_closed`] if that fails).
    Dial {
        /// Address to dial.
        target: EntityAddr,
    },
    /// READY reached.
    Connected(PeerInfo),
    /// A message arrived.
    Message(Incoming),
    /// KEEPALIVE2_ACK received.
    KeepaliveAck {
        /// Echoed seconds.
        sec: u32,
        /// Echoed nanoseconds.
        nsec: u32,
    },
    /// Local session state was dropped (lossy connection failed after being established, or a
    /// replaced lossless session): the upper layer must resend what matters.
    Reset,
    /// The peer reset the session (restart detected): in-flight state on the peer is gone.
    RemoteReset,
    /// The socket must be closed. A retry may follow (`Dial`) unless `Closed` follows.
    Fault(FaultReason),
    /// Terminal: drop this object.
    Closed,
    /// Client role, RDMA upgrade (spec 18): prepare a QP and answer with [`Connection::rdma_offer`].
    RdmaPrepare,
    /// Server role, RDMA upgrade: the peer offers `endpoint`; answer with [`Connection::rdma_answer`].
    RdmaOffer {
        /// Peer endpoint record.
        endpoint: Vec<u8>,
    },
    /// Client role, RDMA upgrade: `Some` = the server accepted with its endpoint: connect the QP, then call
    /// [`Connection::rdma_ready`]. `None` = declined, the connection goes on over TCP; release the prepared QP.
    RdmaAnswer {
        /// Server endpoint record.
        endpoint: Option<Vec<u8>>,
    },
    /// A validated v1 placement CANCEL (server role) or RETIRED (client role).
    /// The upper layer must match its identity to a live attempt and enforce retirement ordering.
    PlacementControl([u8; PLACEMENT_CONTROL_LEN]),
    /// The authenticated peer OSD belongs to another core ([`Config::home`]): move the connection with
    /// [`Connection::into_handoff`] to core `owner` and resume it there with [`Connection::from_handoff`]. A parked
    /// connection runs no timer ([`Connection::next_timer`] is `None`); the resumed one arms its own.
    Handoff {
        /// Peer OSD id.
        osd: i64,
        /// Core owning its sessions.
        owner: usize,
    },
}

/// Coarse public state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnState {
    /// Handshaking on a live socket.
    Connecting,
    /// Client role: waiting for the driver to open a socket.
    WaitSocket,
    /// Client role: backoff timer running.
    Backoff,
    /// No socket, nothing to do until a message is queued / the peer connects.
    Standby,
    /// Session transport established.
    Ready,
    /// Terminal.
    Closed,
}

/// A guarded receipt for retiring a lossless session after its application
/// CLOSE/eviction commits, even when the TCP connection has already vanished.
/// The generation-qualified session id and protocol incarnation prevent a late
/// receipt from retiring a subsequently resumed messenger session.
#[derive(Debug, Clone)]
pub struct SessionRetirement {
    table: SessionTable,
    session: SessId,
    carrier: u64,
    global_seq: u64,
    connect_seq: u64,
}
impl SessionRetirement {
    /// The recorded incarnation still exists and no replacement owns/dials it.
    pub fn is_current(&self) -> bool {
        self.table
            .with(self.session, |s| {
                s.global_seq == self.global_seq
                    && s.connect_seq == self.connect_seq
                    && s.active.is_none_or(|id| id == self.carrier)
                    && s.dialer.is_none_or(|id| id == self.carrier)
            })
            .unwrap_or(false)
    }
    /// Caller must first durably close/fence its application session and finish
    /// required output. Ordinary socket loss alone never authorizes retirement.
    pub fn dispose(&self) -> bool {
        self.is_current() && self.table.remove(self.session).is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    Idle,
    Backoff,
    Standby,
    Banner,
    Hello,
    AuthConnecting,
    AuthConnectingSign,
    CompressionConnecting,
    SessionConnecting,
    SessionReconnecting,
    AuthAccepting,
    AuthAcceptingMore,
    AuthAcceptingSign,
    CompressionAccepting,
    SessionAccepting,
    /// Client: waiting for [`Connection::rdma_offer`].
    RdmaPreparing,
    /// Client: RDMA_UPGRADE offer sent, waiting for the answer frame.
    RdmaOffered,
    /// Client: accepted, waiting for [`Connection::rdma_ready`].
    RdmaSwitching,
    /// Server: offer received, waiting for [`Connection::rdma_answer`].
    RdmaAnswering,
    /// Parked at CLIENT_IDENT / SESSION_RECONNECT, waiting for [`Connection::into_handoff`].
    HandOff,
    Ready,
    Closed,
}

#[derive(Debug, Default)]
struct PreAuth {
    active: bool,
    rx_all: Vec<u8>,
    tx_all: Vec<u8>,
}

#[derive(Debug)]
struct OFrame {
    dispatch: crate::DispatchGuard,
    tag: u8,
    flags: u8,
    segs: Vec<bytes::Bytes>,
    data_crc: Option<u32>,
    data_blocks: Option<std::sync::Arc<[u32]>>,
    data_head: usize,
    data_refused: u32,
    credit: ingress::InputGuard,
}

/// Completion deadline of the frame being received (spec 4.3): a frame that holds an ingress-pool reservation must
/// finish within `ms_connection_ready_timeout` + its declared size at [`FRAME_MIN_RATE`], else the link faults. `seq`
/// tells a completed frame and its successor apart (preambles parsed); `limit` is the allowance the fault reports.
#[derive(Clone, Copy, Debug)]
struct FrameRx {
    seq: u64,
    deadline: Duration,
    limit: Duration,
}

fn sign(key: &[u8], msg: &[u8]) -> [u8; 32] {
    if key.is_empty() {
        return [0; 32];
    }
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let t = hmac::sign(&k, msg);
    let mut o = [0u8; 32];
    o.copy_from_slice(t.as_ref());
    o
}

fn dec<P: Payload>(seg: &[u8]) -> Res<P> {
    P::from_bytes(seg).map_err(|_| FaultReason::Protocol("malformed control payload"))
}

fn placement_control_valid(record: &[u8], sender: Role) -> bool {
    record.len() == PLACEMENT_CONTROL_LEN
        && record[0] == 1
        && record[1]
            == match sender {
                Role::Client => 3, // CANCEL
                Role::Server => 4, // RETIRED
            }
        && record[2..4] == [0, 0]
}

/// One msgr2 connection. See the module docs for the driver contract.
#[derive(Debug)]
pub struct Connection {
    dispatch: Option<Rc<RefCell<crate::DispatchBudget>>>,
    /// Receive buffer shelf for a connection without a dispatch domain ([`Connection::attach_shelf`]).
    shelf: Option<std::sync::Arc<crate::RxShelf>>,
    input_guard: ingress::InputGuard,
    id: u64,
    role: Role,
    cfg: Config,
    table: SessionTable,
    st: St,
    now: Duration,
    peer_type: u8,
    policy: Policy,
    /// Client: dialled address. Server: peer socket address (HELLO peer_addr).
    target: EntityAddr,
    sid: Option<SessId>,
    retirement_receipt: Option<SessionRetirement>,
    /// Server: what the last CLIENT_IDENT claimed (its addrs, the target it dialled), kept for diagnostics of a refused ident.
    ident_claim: Option<(EntityAddrVec, EntityAddr)>,
    pending: Vec<Message>,
    // transport (reset per stream)
    banner_buf: Vec<u8>,
    peer_banner: Option<Banner>,
    dec: Decoder,
    enc: Encoder,
    out: Vec<u8>,
    /// Completed output runs that precede `out` (large message data by reference).
    out_chunks: Vec<Bytes>,
    output_exported: u64,
    output_written: u64,
    write_capacity: usize,
    write_ends: VecDeque<(u64, crate::write_receipt::WriteToken)>,
    /// After descriptor admission, ordinary later messages wait until all placement proofs are encoded.
    placement_hold: bool,
    /// READY control frames generated during placement, encoded after terminal proofs.
    placement_controls: Vec<(u8, Vec<u8>)>,
    /// Stamp of the newest KEEPALIVE2 not yet answered. Answers are encoded when output is
    /// polled, so a peer that sends keepalives without reading owes at most one pending echo.
    keepalive_ack: Option<Keepalive2Ack>,
    output_notify: Option<crate::OutputNotify>,
    event_notify: Option<crate::EventNotify>,
    timer_notify: Option<crate::EventNotify>,
    pre: PreAuth,
    // auth
    auth_c: Option<Box<dyn AuthClientHandler>>,
    auth_s: Option<Box<dyn AuthServerHandler>>,
    offered_modes: Vec<u32>,
    srv_method: u32,
    srv_mode: u32,
    /// HMAC key of AUTH_SIGNATURE, wiped when the stream ends.
    session_key: crate::auth::Secret,
    expect_sig: [u8; 32],
    auth_global_id: u64,
    auth_name: Option<EntityName>,
    /// Our address as the server saw it (client role, from HELLO).
    seen_by_peer: Option<EntityAddr>,
    // timers
    hs_deadline: Duration,
    /// Frame-completion deadline of the frame being received (spec 4.3); `None` between frames and while a frame waits
    /// for ingress space (fair queueing, not a stalled link).
    frame_rx: Option<FrameRx>,
    /// The owner stopped reading this link for a local reason ([`Self::hold_rx`]): no frame deadline runs meanwhile.
    rx_held: bool,
    reconnect_at: Duration,
    last_activity: Duration,
    /// Output left since the last idle check. The output calls carry no clock (`self.now` is stale on a link that
    /// receives nothing), so output is only flagged; the idle timer stamps it with its own `now` (Ceph's idle tick is
    /// equally coarse: a connection closes between 1x and 2x the timeout after its last activity).
    tx_since_idle_check: bool,
    backoff: Duration,
    events: VecDeque<Event>,
    /// The session frame a handoff stopped at (replayed by [`Connection::from_handoff`]).
    parked: Option<OFrame>,
    /// Receive settings reapplied to every fresh decoder (`set_frame_gate`, `set_rx_place`, `set_prewrite`, limits).
    dcfg: DecoderCfg,
    /// An RDMA upgrade was offered on this stream (one per stream).
    rdma_tried: bool,
    /// An accepted upgrade, reset on every new stream. A banner alone is not an active QP.
    rdma_active: bool,
    /// Rate limiter of the duplicate / gap seq log lines.
    seq_log: crate::seqcheck::SeqLog,
}

/// A server-role connection in flight between two cores (see [`Event::Handoff`]): the whole handshake state (framing,
/// crypto, auth result, unsent output, undecoded input) minus the session table.
pub struct Handoff(Box<Connection>);

// SAFETY: `into_handoff` replaces the only `Rc` a connection holds (its session table handle, shared with the sending
// core) by a fresh one nobody else references, and drops the auth handler (which shares `Rc`s with the driver). What is
// left is plain owned data, so moving it to another thread moves the sole owner of everything in it.
// Client-only dispatch admission cannot enter Handoff: attach rejects servers and into_handoff
// additionally checks server role and absence of the local dispatch owner.
unsafe impl Send for Handoff {}

impl std::fmt::Debug for Handoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Handoff(c{})", self.0.id)
    }
}

impl Connection {
    /// Rename this endpoint without changing its addresses, nonce, or session.
    /// Subsequent ident frames use the new name. MsgHeader2 has no source field:
    /// a READY peer retains the identity negotiated by its last ident exchange.
    /// Owners must rename their configuration for future connections as well.
    pub fn set_name(&mut self, name: EntityName) {
        self.cfg.name = name;
    }

    fn base(
        id: u64,
        role: Role,
        cfg: Config,
        table: SessionTable,
        target: EntityAddr,
        peer_type: u8,
        policy: Policy,
    ) -> Self {
        let dcfg = DecoderCfg {
            rx_block_crcs: cfg.rx_block_crcs,
            crc_data: cfg.crc_data,
            frame_cap: cfg.max_message,
            ..DecoderCfg::default()
        };
        let dec = Decoder::with_cfg(Revision::V21, &dcfg);
        let mut enc = Encoder::new(Revision::V21);
        enc.set_crc_data(cfg.crc_data);
        Self {
            dispatch: None,
            shelf: None,
            input_guard: Default::default(),
            id,
            role,
            cfg,
            table,
            st: St::Idle,
            now: Duration::ZERO,
            peer_type,
            policy,
            target,
            ident_claim: None,
            sid: None,
            retirement_receipt: None,
            pending: Vec::new(),
            banner_buf: Vec::new(),
            peer_banner: None,
            dec,
            enc,
            out: Vec::new(),
            out_chunks: Vec::new(),
            output_exported: 0,
            output_written: 0,
            write_capacity: 0,
            write_ends: VecDeque::new(),
            placement_hold: false,
            placement_controls: Vec::new(),
            keepalive_ack: None,
            output_notify: None,
            event_notify: None,
            pre: PreAuth::default(),
            auth_c: None,
            auth_s: None,
            offered_modes: Vec::new(),
            srv_method: 0,
            srv_mode: 0,
            session_key: crate::auth::Secret::default(),
            expect_sig: [0; 32],
            auth_global_id: 0,
            auth_name: None,
            seen_by_peer: None,
            timer_notify: None,
            hs_deadline: Duration::ZERO,
            frame_rx: None,
            rx_held: false,
            reconnect_at: Duration::ZERO,
            last_activity: Duration::ZERO,
            tx_since_idle_check: false,
            backoff: Duration::ZERO,
            events: VecDeque::new(),
            parked: None,
            dcfg,
            rdma_tried: false,
            rdma_active: false,
            seq_log: Default::default(),
        }
    }

    /// New client-role connection to a peer of `peer_type` advertising `peer_addrs` (session key),
    /// dialling `target` (one entry of `peer_addrs`). Emits [`Event::Dial`]; the session is created
    /// or reused (e.g. after the peer had connected to us first).
    pub fn client(
        id: u64,
        cfg: Config,
        table: SessionTable,
        auth: Box<dyn AuthClientHandler>,
        peer_type: u8,
        peer_addrs: EntityAddrVec,
        target: EntityAddr,
    ) -> Self {
        let policy = cfg.policies.get(peer_type);
        let mut c = Self::base(id, Role::Client, cfg, table, target, peer_type, policy);
        c.auth_c = Some(auth);
        let key = SessionKey::Peer(peer_addrs.clone());
        let sid = c.table.id_of(&key).unwrap_or_else(|| {
            let mut s = Session::new(key.clone(), policy, peer_addrs);
            s.peer_name = EntityName::new(peer_type, -1);
            c.table.insert(s)
        });
        let me = id;
        // spec 10.3: a LOSSLESS dial resumes the session, so it alone carries it from now on. A connection that still
        // carries it (READY) stops too: whatever it decoded after this one announced its in_seq in SESSION_RECONNECT
        // would make that msg_seq stale, and a peer that renumbers from msg_seq (classic, nothing to replay) reuses seqs
        // we already hold: the receive side drops those messages as old. A LOSSY session has nothing to resume (a new
        // connection is a new session on the peer), so a second dial leaves the healthy READY connection alone until
        // the new one is READY itself (`become_ready` then retires it).
        let prev = c
            .table
            .with(sid, |s| {
                if s.lossy {
                    [None, s.dialer.replace(me)]
                } else {
                    s.state = SessState::Connecting;
                    [s.active.take(), s.dialer.replace(me)]
                }
            })
            .unwrap_or_default();
        for p in prev.into_iter().flatten().filter(|p| *p != me) {
            c.table.supersede(p);
        }
        c.sid = Some(sid);
        c.push_event(Event::Dial { target });
        c
    }

    /// New server-role connection for an accepted socket from `peer_sock` (type MSGR2, nonce 0).
    /// Writes our banner immediately.
    pub fn server(
        id: u64,
        cfg: Config,
        table: SessionTable,
        auth: Box<dyn AuthServerHandler>,
        peer_sock: EntityAddr,
        now: Duration,
    ) -> Self {
        let policy = cfg.policies.default;
        let mut c = Self::base(id, Role::Server, cfg, table, peer_sock, 0, policy);
        c.auth_s = Some(auth);
        c.start_stream(now);
        c
    }

    // ---- public accessors ----

    /// Connection id given at construction.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Server role: the peer's socket address. Client role: the dialled address.
    pub fn target(&self) -> EntityAddr {
        self.target
    }

    /// Server role: addrs and target address of the last CLIENT_IDENT (also when it was refused).
    pub fn ident_claim(&self) -> Option<&(EntityAddrVec, EntityAddr)> {
        self.ident_claim.as_ref()
    }

    /// Role (who opened the TCP connection).
    pub fn role(&self) -> Role {
        self.role
    }

    /// Attach an owned-only logical RX domain to an idle client before its socket starts.
    /// Server connections/handoff are excluded.
    pub fn attach_dispatch(
        &mut self,
        owner: Rc<RefCell<crate::DispatchBudget>>,
    ) -> Result<(), Error> {
        if self.role != Role::Client || self.st != St::Idle || self.dispatch.is_some() {
            return Err(Error::Busy);
        }
        self.dec.attach_dispatch(owner.clone())?;
        self.dispatch = Some(owner);
        Ok(())
    }

    /// Recycle this client connection's large receive segment buffers through `shelf` (shared across connections).
    /// A dispatch domain brings its own shelf, which wins. Idle connections only, before the socket starts.
    pub fn attach_shelf(&mut self, shelf: std::sync::Arc<crate::RxShelf>) -> Result<(), Error> {
        if self.role != Role::Client || self.st != St::Idle || self.dispatch.is_some() {
            return Err(Error::Busy);
        }
        self.dec.attach_shelf(shelf.clone())?;
        self.shelf = Some(shelf);
        Ok(())
    }

    /// Coarse state.
    pub fn state(&self) -> ConnState {
        match self.st {
            St::Idle => ConnState::WaitSocket,
            St::Backoff => ConnState::Backoff,
            St::Standby => ConnState::Standby,
            St::Ready => ConnState::Ready,
            St::Closed => ConnState::Closed,
            _ => ConnState::Connecting,
        }
    }

    /// Peer entity type (expected for clients, from HELLO for servers).
    pub fn peer_type(&self) -> u8 {
        self.peer_type
    }

    /// Selected connection mode (`MODE_CRC` / `MODE_SECURE`) after auth, else 0.
    pub fn mode(&self) -> u32 {
        self.srv_mode
    }

    /// Is an event waiting for [`poll_event`](Self::poll_event)?
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    /// Borrow the oldest event for downstream credit admission without removing it.
    pub fn peek_event(&self) -> Option<&Event> {
        self.events.front()
    }

    /// Next event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// This connection carries or dials its session (side-effect free; a connection that lost it may not know yet).
    pub fn owns_session(&self) -> bool {
        let me = self.id;
        self.st != St::Closed
            && self
                .sid
                .is_some_and(|k| self.table.with(k, |s| s.owned_by(me)).unwrap_or(false))
    }
    /// Whether this carrier still names a live logical session generation.
    /// A superseded carrier can retain decoded messages for takeover while
    /// this is true. A fresh ident retires that generation instead.
    pub fn retains_session_generation(&self) -> bool {
        self.sid
            .is_some_and(|id| self.table.with(id, |_| ()).is_some())
    }

    /// Messages still awaiting preparation or a messenger acknowledgement.
    /// This allocation-free count lets an application bound its replay queue
    /// before transferring ownership to [`send_message`](Self::send_message).
    pub fn queued_messages(&self) -> usize {
        self.pending.len() + self.sess(|s| s.unsent() + s.unacked()).unwrap_or(0)
    }

    /// Messages not yet written to the socket (awaiting preparation or write).
    /// Unlike [`queued_messages`](Self::queued_messages) this excludes written
    /// messages retained only for lossless replay: their count falls only when
    /// the peer's ACK is read, so an application that pauses its own reads must
    /// not gate new sends on them.
    pub fn unwritten_messages(&self) -> usize {
        self.pending.len() + self.sess(|s| s.unsent()).unwrap_or(0)
    }

    /// Written messages retained for lossless replay until the peer ACKs them.
    pub fn unacked_messages(&self) -> usize {
        self.sess(|s| s.unacked()).unwrap_or(0)
    }

    /// Forget the messenger session after the application has durably closed
    /// or fenced its higher-level session and completed required output. An IO
    /// fault alone is insufficient: lossless sessions normally remain resumable.
    /// Returns false if another connection owns or is dialling the session;
    /// an old connection can never discard a replacement carrier's messages.
    pub fn dispose_session(&mut self) -> bool {
        let Some(receipt) = self.retirement() else {
            return false;
        };
        if !receipt.dispose() {
            return false;
        }
        self.sid = None;
        self.pending.clear();
        self.finish_closed();
        true
    }
    /// Capture the current logical session incarnation while this connection
    /// owns it. Drivers retain the receipt through a subsequent socket fault.
    pub fn retirement(&self) -> Option<SessionRetirement> {
        if let Some(receipt) = &self.retirement_receipt {
            return Some(receipt.clone());
        }
        if !self.owns_session() {
            return None;
        }
        let session = self.sid?;
        self.session_retirement(session)
    }

    fn session_retirement(&self, session: SessId) -> Option<SessionRetirement> {
        self.table.with(session, |s| SessionRetirement {
            table: self.table.clone(),
            session,
            carrier: self.id,
            global_seq: s.global_seq,
            connect_seq: s.connect_seq,
        })
    }

    /// Drop the decoded messages the application has not taken yet, keeping lifecycle events (fault, reset, closed) in
    /// order. For an application that holds an earlier message whose stream died before that message was complete (its
    /// data had still to be fetched): the later messages must not run without it. The session counted them as
    /// received, so it ends with them: a lossless session leaves the table, the peer's reconnect is answered with a
    /// reset and it resends, as after any session reset (a lossy session is gone already). Returns the number dropped
    /// and the other connection that carries the session now (resumed before this one's close was seen), which the
    /// application closes.
    pub fn discard_messages(&mut self) -> (usize, Option<u64>) {
        let before = self.events.len();
        self.events.retain(|e| !matches!(e, Event::Message(_)));
        let me = self.id;
        let carrier = self.sid.and_then(|k| {
            self.table
                .remove(k)
                .and_then(|s| s.active.filter(|&a| a != me))
        });
        (before - self.events.len(), carrier)
    }

    /// Session takeover, called by the application when this connection reaches READY (its `Connected` event), for every
    /// older connection `old` to the same peer: if both belong to one session, this one carries it and `old` no longer
    /// does (superseded, or faulted before this one resumed it), the messages `old` decoded but the application has not
    /// taken yet move to the front of this connection's events, in order, ahead of its own. They are counted in the
    /// session's in_seq (acked), so the peer never sends them again: dropping them would lose them, taking them after
    /// this connection's would reorder the session. `old`'s other events are dropped. Returns true when `old` is
    /// finished (the application drops it).
    pub fn take_over_messages(&mut self, old: &mut Connection) -> bool {
        if old.sid != self.sid || !self.owns_session() || old.owns_session() {
            return false;
        }
        let moved: Vec<Event> = old
            .events
            .drain(..)
            .filter(|e| matches!(e, Event::Message(_)))
            .collect();
        if !moved.is_empty() {
            for e in moved.into_iter().rev() {
                self.events.push_front(e);
            }
            self.notify_events();
        }
        true
    }

    /// Register on this core, including events produced before registration (dial or handoff).
    pub fn set_event_queue(&mut self, q: &crate::EventQueue, id: u64) {
        self.event_notify = Some(q.register(id));
        self.notify_events();
    }

    /// Register deadline-change notifications on the owning core.
    pub fn set_timer_queue(&mut self, q: &crate::EventQueue, id: u64) {
        self.timer_notify = Some(q.register(id));
        self.notify_timer();
    }

    fn notify_timer(&self) {
        if let Some(n) = &self.timer_notify {
            n.notify();
        }
    }

    /// Re-arm after the consumer's input admission pause. No new wire bytes are required.
    pub fn notify_events(&self) {
        if self.has_events()
            && let Some(n) = &self.event_notify
        {
            n.notify();
        }
    }

    fn push_event(&mut self, event: Event) {
        if matches!(&event, Event::Connected(_)) {
            let capacity = self.sess(|s| s.writes.capacity()).unwrap_or(0);
            if capacity != 0 && self.write_capacity == 0 {
                self.write_ends = VecDeque::with_capacity(capacity);
                self.write_capacity = capacity;
            }
        }
        let was_empty = self.events.is_empty();
        self.events.push_back(event);
        if was_empty {
            self.notify_events();
        }
    }

    /// Bytes to write to the socket (empty if none). Also moves queued messages into frames.
    pub fn poll_output(&mut self) -> Vec<u8> {
        self.notify_timer();
        if self.check_owned() {
            self.pump::<false>(usize::MAX);
            self.answer_keepalive();
        }
        if self.out_chunks.is_empty() {
            let output = core::mem::take(&mut self.out);
            self.exported(output.len());
            return output;
        }
        let mut v = Vec::with_capacity(
            self.out_chunks.iter().map(Bytes::len).sum::<usize>() + self.out.len(),
        );
        for c in self.out_chunks.drain(..) {
            v.extend_from_slice(&c);
        }
        v.append(&mut self.out);
        self.exported(v.len());
        v
    }

    /// Encode the owed KEEPALIVE2_ACK, if any (Ready, outside a placement hold).
    fn answer_keepalive(&mut self) {
        if self.st != St::Ready || self.placement_hold {
            return;
        }
        if let Some(ack) = self.keepalive_ack.take()
            && let Err(r) = self.send(&ack)
        {
            self.fault(r);
        }
    }

    /// `out` becomes the last run, so that every poll hands the bytes out in wire order.
    fn stage_out(&mut self) {
        if !self.out.is_empty() {
            self.out_chunks
                .push(Bytes::from(core::mem::take(&mut self.out)));
        }
    }

    /// Drain at most `maximum` ordered wire bytes, retaining the exact suffix.
    /// A zero budget neither pumps nor consumes output.
    pub fn poll_output_bounded(&mut self, maximum: usize) -> Vec<u8> {
        if maximum == 0 {
            return Vec::new();
        }
        self.notify_timer();
        if self.check_owned() && self.out.is_empty() && self.out_chunks.is_empty() {
            self.pump::<true>(maximum);
            self.answer_keepalive();
        }
        self.stage_out();
        let available = self
            .out_chunks
            .iter()
            .fold(0usize, |n, c| n.saturating_add(c.len()));
        let mut output = Vec::with_capacity(maximum.min(available));
        let mut consumed = 0;
        for chunk in &mut self.out_chunks {
            let n = chunk.len().min(maximum - output.len());
            output.extend_from_slice(&chunk[..n]);
            if n < chunk.len() {
                *chunk = chunk.slice(n..);
                break;
            }
            consumed += 1;
            if output.len() == maximum {
                break;
            }
        }
        self.out_chunks.drain(..consumed);
        self.notify_remaining_output();
        self.exported(output.len());
        output
    }

    /// Ordered shared wire prefix, at most `maximum` bytes. Zero does not pump.
    pub fn poll_output_chunks_bounded(&mut self, maximum: usize) -> Vec<Bytes> {
        if maximum == 0 {
            return Vec::new();
        }
        self.notify_timer();
        if self.check_owned() && self.out.is_empty() && self.out_chunks.is_empty() {
            self.pump::<true>(maximum);
            self.answer_keepalive();
        }
        self.stage_out();
        let mut output = Vec::new();
        let mut remaining = maximum;
        let mut consumed = 0;
        for chunk in &mut self.out_chunks {
            if chunk.len() > remaining {
                output.push(chunk.split_to(remaining));
                {
                    remaining = 0;
                }
                break;
            }
            remaining -= chunk.len();
            if !chunk.is_empty() {
                output.push(core::mem::take(chunk));
            }
            consumed += 1;
            if remaining == 0 {
                break;
            }
        }
        self.out_chunks.drain(..consumed);
        self.notify_remaining_output();
        self.exported(maximum - remaining);
        output
    }

    /// Like [`poll_output`](Self::poll_output) but large message data segments come out as shared slices (no copy);
    /// write the runs in order.
    pub fn poll_output_chunks(&mut self) -> Vec<Bytes> {
        self.notify_timer();
        if self.check_owned() {
            self.pump::<false>(usize::MAX);
            self.answer_keepalive();
        }
        self.stage_out();
        let v = core::mem::take(&mut self.out_chunks);
        if self.write_capacity != 0 {
            self.exported_tracked(v.iter().map(Bytes::len).sum());
        }
        v
    }

    /// Admit MESSAGE frames at their header through `gate` (a reservation in the process ingress pool before any body
    /// byte is assembled, doc/design/memory-envelope.md G1). A full pool parks the connection at the header:
    /// [`awaiting_credit`](Self::awaiting_credit) is true, the transport leaves the socket unread, and
    /// [`retry_credit`](Self::retry_credit) resumes it. The reservation rides on [`Incoming::ingress`].
    pub fn set_frame_gate(&mut self, gate: Option<ingress::FrameGate>) {
        self.dcfg.gate = gate.clone();
        self.dec.set_gate(gate);
    }

    /// A message header was read but the pool has no space for the frame yet.
    pub fn awaiting_credit(&self) -> bool {
        self.dec.awaiting_credit()
    }

    /// Would the frame that waits for credit be admitted now?
    pub fn credit_ready(&self) -> bool {
        self.dec.credit_ready()
    }

    /// Retry the admission of the waiting frame; on success the frame is assembled from what is already buffered (which
    /// may complete messages and stop at the next frame that waits). True when the frame was admitted.
    pub fn retry_credit(&mut self, now: Duration) -> bool {
        if !(self.dec.awaiting_credit() && self.dec.retry_gate()) {
            return false;
        }
        self.now = now;
        self.process();
        true
    }

    /// Place received data segments by the sender's alignment hint and `data_off` ([`Decoder::set_rx_place`]).
    pub fn set_rx_place(&mut self, place: bool) {
        self.dcfg.rx_place = place;
        self.dec.set_rx_place(place);
    }

    /// Receiver-side pre-write of large message data segments ([`Decoder::set_prewrite`], adr 0477); 0 = off. Kept
    /// across decoder resets like [`set_rx_place`](Self::set_rx_place).
    pub fn set_prewrite(&mut self, min: usize) {
        self.dcfg.prewrite = min;
        self.dec.set_prewrite(min);
    }

    /// Largest received MESSAGE of this link in segment bytes (`osd_client_message_size_cap`): above it a MESSAGE is
    /// admitted alone, never refused for its size (spec msgr2.md 8.2). The next preamble follows it. Outbound frames
    /// are not affected.
    pub fn set_frame_cap(&mut self, cap: u64) {
        self.cfg.max_message = cap;
        self.dcfg.frame_cap = cap;
        self.dec.set_frame_cap(cap);
    }

    /// Receive probe of MESSAGE data segments ([`Decoder::set_data_probe`]): a frame whose data segment the probe
    /// refuses is consumed unadmitted and delivered with [`Incoming::data_refused`] set. Kept across decoder resets.
    pub fn set_data_probe(&mut self, probe: Option<crate::DataProbe>) {
        self.dcfg.data_probe = probe;
        self.dec.set_data_probe(probe);
    }

    /// The largest received MESSAGE this link accepts (segment bytes).
    pub fn frame_cap(&self) -> u64 {
        self.cfg.max_message
    }

    /// Bytes this connection buffers for its pre-auth handshake transcript (`rx_all + tx_all`, spec 9): the memory an
    /// unauthenticated peer makes the daemon hold. Zero once the transcript is frozen (`AUTH_SIGNATURE`) or reset.
    pub fn preauth_bytes(&self) -> usize {
        if self.pre.active {
            self.pre.rx_all.len() + self.pre.tx_all.len()
        } else {
            0
        }
    }

    /// The message frame being received shares its data segment ([`Decoder::early`]); only in the steady state.
    pub fn rx_early(&self) -> Option<crate::RxEarly<'_>> {
        if self.st == St::Ready && !self.pre.active {
            self.dec.early()
        } else {
            None
        }
    }

    /// Whether [`poll_output`](Self::poll_output) would return bytes (cheap check, no pumping).
    pub fn has_output(&self) -> bool {
        !self.out.is_empty()
            || !self.out_chunks.is_empty()
            || (self.st == St::Ready && !self.placement_hold && self.keepalive_ack.is_some())
            || (self.st == St::Ready
                && self
                    .sess(|s| {
                        s.owned_by(self.id)
                            && (s.unsent() > 0 || (!s.lossy && s.in_seq > s.acked_out))
                    })
                    .unwrap_or(false))
    }

    /// Attach to this core's output queue; includes output produced before registration.
    pub fn set_output_queue(&mut self, q: &crate::OutputQueue, id: u64) {
        self.output_notify = Some(q.register(id));
        if self.has_output() {
            self.notify_output();
        }
    }

    fn notify_output(&self) {
        if let Some(n) = &self.output_notify {
            n.notify();
        }
    }

    fn notify_remaining_output(&self) {
        // Bounded consumers may have consumed the coalesced ready token without
        // preparing the next queued frame. Re-arm only runnable output.
        if self.output_notify.is_some() && self.has_output() {
            self.notify_output();
        }
    }

    /// The frame limits this connection enforces ([`Config::limits`]).
    pub fn limits(&self) -> &Limits {
        &self.cfg.limits
    }

    /// Configure per-session tracking slots before admitting application sends.
    /// May be called before the handshake to account for control output too.
    /// Repeat after Connected to bind the session pool. Repeated configuration
    /// on a replacement carrier must use the same count.
    /// Allocation happens here, never when taking a receipt or completing it.
    pub fn configure_write_receipts(&mut self, capacity: usize) -> bool {
        if capacity == 0 || self.write_capacity != 0 && self.write_capacity != capacity {
            return false;
        }
        // Accepted carriers opt in before their first banner is exported;
        // the session and its pool are bound later by CLIENT_IDENT.
        if self.sid.is_some() && !self.sess(|s| s.writes.configure(capacity)).unwrap_or(false) {
            return false;
        }
        if self.write_capacity == 0 {
            self.write_ends = VecDeque::with_capacity(capacity);
            self.write_capacity = capacity;
        }
        self.write_capacity == capacity
    }

    /// Queue with a bounded receipt; error preserves the exact message.
    /// A message beyond the frame limits ([`Config::limits`]) is refused like in
    /// [`send_message`](Self::send_message) and takes no receipt slot.
    /// The driver must report ordered socket acceptance through
    /// [`Self::acknowledge_output`], including control frames and partial writes.
    /// A lossless session retains the receipt across connection replacement.
    #[expect(
        clippy::result_large_err,
        reason = "Return original ownership without allocating"
    )]
    pub fn send_message_tracked(
        &mut self,
        message: Message,
    ) -> Result<crate::WriteReceipt, crate::SendError> {
        if self.st != St::Ready || self.write_capacity == 0 || !self.owns_session() {
            return Err(crate::SendError::Temporary(message));
        }
        if self.refuse_unencodable(&message) {
            return Err(crate::SendError::FrameLimit(message));
        }
        let Some(receipt) = self.sess(|s| s.writes.take()).flatten() else {
            return Err(crate::SendError::Temporary(message));
        };
        let token = receipt.0.clone();
        self.sess(|s| s.queue_write(message, Some(token)));
        self.notify_output();
        Ok(receipt)
    }

    /// Confirm the next `bytes` exported wire bytes were accepted by the socket.
    /// Queueing, frame preparation, partial frame writes and TCP acknowledgements
    /// do not substitute for this call. Returns false for an invalid byte count.
    pub fn acknowledge_output(&mut self, bytes: usize) -> bool {
        let Some(written) = self.output_written.checked_add(bytes as u64) else {
            return false;
        };
        if written > self.output_exported {
            return false;
        }
        self.output_written = written;
        while self
            .write_ends
            .front()
            .is_some_and(|(end, _)| *end <= written)
        {
            if let Some((_, token)) = self.write_ends.pop_front() {
                token.complete(crate::WriteStatus::Written);
            }
        }
        true
    }
    fn exported(&mut self, bytes: usize) {
        if self.write_capacity == 0 {
            return;
        }
        self.exported_tracked(bytes);
    }
    fn exported_tracked(&mut self, bytes: usize) {
        match self.output_exported.checked_add(bytes as u64) {
            Some(end) => self.output_exported = end,
            None => self.fault(FaultReason::Protocol("output byte counter overflow")),
        }
    }

    /// Refuse (and log) a message that [`Message::fits`] rejects: frame limits or a broken front rope.
    fn refuse_unencodable(&self, message: &Message) -> bool {
        if message.fits(&self.cfg.limits) {
            return false;
        }
        diag::diag!(
            "WARNING msgr2 message type {} tid {} cannot be encoded (frame limits or front rope), refused (conn {})",
            message.msg_type,
            message.tid,
            self.id
        );
        true
    }

    /// Queue a message. Returns false if the connection is closed or the message cannot be encoded (it exceeds the
    /// frame limits of [`Config::limits`] or its front rope is broken); the message is dropped then, and later
    /// messages still flow. [`Message::fits`] answers the same question in advance.
    /// Queueing moves no deadline ([`Connection::next_timer`]), so it arms no timer probe: the driver re-indexes the
    /// connection on the state changes it does make (`Event::Dial` here, the output wakeup above).
    pub fn send_message(&mut self, m: Message) -> bool {
        if self.st == St::Closed {
            return false;
        }
        if self.refuse_unencodable(&m) {
            return false;
        }
        match self.sid {
            Some(k) => {
                if self.table.with(k, |s| s.queue(m)).is_none() {
                    return false;
                }
            }
            None => self.pending.push(m),
        }
        // Queued messages become frames only in `pump` (driven by `poll_output*`): wake the transport, or a reply
        // produced outside `on_bytes` (store completion, cross-core relay, timer) waits for unrelated input (adr 0074).
        if self.st == St::Ready {
            self.notify_output();
        }
        if self.st == St::Standby && self.role == Role::Client {
            self.st = St::Idle;
            self.set_sess_state(SessState::Connecting);
            self.push_event(Event::Dial {
                target: self.target,
            });
        }
        true
    }

    /// Send KEEPALIVE2 now (Ready only). The stamp is `now` as seconds/nanoseconds.
    pub fn send_keepalive(&mut self, now: Duration) {
        self.notify_timer();
        self.now = now;
        if self.st == St::Ready {
            let p = Keepalive2 {
                sec: now.as_secs() as u32,
                nsec: now.subsec_nanos(),
            };
            // a keepalive that cannot be queued leaves the link without a heartbeat: fail it here, not at the peer
            if let Err(r) = self.send(&p) {
                self.fault(r);
            }
        }
    }

    /// Close for good. A lossy session is dropped, a lossless one stays in the table (standby).
    pub fn close(&mut self) {
        self.notify_timer();
        self.terminate();
    }

    /// Absolute time of the next timer, if any.
    pub fn next_timer(&self) -> Option<Duration> {
        let frame = self.frame_rx.map(|f| f.deadline);
        let min = |a: Duration| frame.map_or(a, |f| f.min(a));
        match self.st {
            St::Backoff => Some(self.reconnect_at),
            St::Ready => Some(min(self
                .last_activity
                .saturating_add(self.cfg.idle_timeout))),
            // a parked connection waits for its driver: the handshake clock restarts on the owning core
            // ([`Connection::from_handoff`])
            St::Idle | St::Standby | St::HandOff | St::Closed => None,
            _ => Some(min(self.hs_deadline)),
        }
    }

    /// The info line printed when an idle connection is closed: connection id, peer entity type and the peer
    /// address (client role: dialled address; server role: the peer's socket address). Not a `WARNING TIMEOUT`: a
    /// connection without traffic in either direction is closed silently (debug-level) by Ceph and re-established on
    /// demand; no operation timed out (doc/spec/msgr2-idle.md).
    pub fn idle_notice(&self) -> String {
        format!(
            "msgr2 idle for {}s (conn {}, peer {} {}, closing)",
            self.cfg.idle_timeout.as_secs(),
            self.id,
            EntityName::new(self.peer_type, -1),
            self.target
        )
    }

    /// Run due timers.
    pub fn on_timer(&mut self, now: Duration) {
        self.notify_timer();
        self.now = now;
        if !self.check_owned() {
            return;
        }
        if let Some(f) = self.frame_rx
            && now >= f.deadline
        {
            diag::diag!(
                "WARNING TIMEOUT msgr2 frame not complete within {:.3}s (conn {}, state {:?}, faulting)",
                f.limit.as_secs_f64(),
                self.id,
                self.st
            );
            self.frame_rx = None;
            return self.fault(FaultReason::Timeout("frame"));
        }
        match self.st {
            St::Backoff if now >= self.reconnect_at => {
                self.st = St::Idle;
                self.push_event(Event::Dial {
                    target: self.target,
                });
            }
            St::Ready if now >= self.last_activity.saturating_add(self.cfg.idle_timeout) => {
                if std::mem::take(&mut self.tx_since_idle_check) {
                    self.last_activity = now;
                    return;
                }
                diag::diag!("{}", self.idle_notice());
                self.fault(FaultReason::Timeout("idle"));
            }
            St::Idle | St::Backoff | St::Standby | St::Closed | St::Ready | St::HandOff => {}
            _ if now >= self.hs_deadline => {
                diag::diag!(
                    "WARNING TIMEOUT msgr2 handshake exceeded {:.3}s (conn {}, state {:?}, faulting)",
                    self.cfg.ready_timeout.as_secs_f64(),
                    self.id,
                    self.st
                );
                self.fault(FaultReason::Timeout("ready"));
            }
            _ => {}
        }
    }

    /// Client role: the socket requested by [`Event::Dial`] is up.
    pub fn on_connected(&mut self, now: Duration) {
        self.notify_timer();
        self.now = now;
        if self.role != Role::Client || self.st != St::Idle || !self.check_owned() {
            return;
        }
        let t = self.table.clone();
        if let Some(k) = self.sid {
            t.with(k, |s| {
                s.global_seq = t.next_global_seq(0);
                if s.server_cookie != 0 {
                    s.connect_seq = s.connect_seq.saturating_add(1);
                }
                s.state = SessState::Connecting;
            });
        }
        self.start_stream(now);
    }

    /// The socket failed or was closed by the peer (also: a dial attempt failed).
    pub fn on_closed(&mut self, now: Duration) {
        self.notify_timer();
        self.now = now;
        if matches!(self.st, St::Backoff | St::Standby | St::Closed) {
            return;
        }
        self.fault(FaultReason::Io);
    }

    /// See [`Decoder::lent_message`]: the message whose data segment is lent ([`Connection::rx_direct_take`]).
    pub fn rx_lent_message(&self) -> Option<crate::LentMessage> {
        if self.st == St::Ready {
            self.dec.lent_message()
        } else {
            None
        }
    }

    /// See [`Decoder::direct_want`]: only in the steady state (after the handshake, no signature accumulation).
    pub fn rx_direct_want(&self) -> usize {
        if self.st == St::Ready && !self.pre.active {
            self.dec.direct_want()
        } else {
            0
        }
    }

    /// Gate of every receive loan return (`rx_*_put*`): the same as `on_bytes`. A connection that faulted or lost its
    /// session to a reconnect meanwhile must not dispatch the frame (the buffer is dropped; a faulted connection has a
    /// fresh decoder already). Stamps the clock and activity; false = drop the loan.
    fn rx_gate(&mut self, now: Duration) -> bool {
        self.notify_timer();
        self.now = now;
        if self.st != St::Ready || !self.check_owned() {
            return false;
        }
        self.last_activity = now;
        true
    }

    /// Gate of the crc-mode receive loans (`rx_direct_take*`): a loan is only offered while a segment is wanted.
    fn take_gate(&self) -> bool {
        self.rx_direct_want() != 0
    }

    /// Lend the segment buffer being received to the transport ([`Decoder::direct_take`]).
    pub fn rx_direct_take(&mut self) -> Option<(Vec<u8>, crc::BlockCrcs)> {
        if !self.take_gate() {
            return None;
        }
        self.dec.direct_take()
    }

    /// [`Decoder::direct_take_empty_data`], under the steady-state loan gates.
    pub fn rx_direct_take_empty_data(&mut self) -> Option<(Vec<u8>, crc::BlockCrcs)> {
        if !self.take_gate() {
            return None;
        }
        self.dec.direct_take_empty_data()
    }

    /// [`rx_direct_take`](Self::rx_direct_take) as a [`SegBuf`](crate::SegBuf): also with pre-write on.
    pub fn rx_direct_take_seg(&mut self) -> Option<(crate::SegBuf, crc::BlockCrcs)> {
        if !self.take_gate() {
            return None;
        }
        self.dec.direct_take_seg()
    }

    /// Return a [`rx_direct_take_seg`](Self::rx_direct_take_seg) loan (gates as [`rx_direct_put`](Self::rx_direct_put)).
    pub fn rx_direct_put_seg(&mut self, v: crate::SegBuf, crcs: crc::BlockCrcs, now: Duration) {
        if !self.rx_gate(now) {
            return;
        }
        self.dec.direct_put_seg(v, crcs);
        self.process();
    }

    /// Account for positive receive completions while a transport owns a receive loan.
    /// No bytes are authenticated or dispatched here; call only after bytes actually arrived.
    pub fn rx_progress(&mut self, now: Duration) {
        if self.st != St::Ready || !self.check_owned() {
            return;
        }
        self.now = now;
        self.last_activity = now;
        self.notify_timer();
    }

    /// Remaining bytes of a known secure frame, eligible for a transport-owned receive loan.
    pub fn rx_secure_want(&self) -> usize {
        if self.st == St::Ready && !self.pre.active {
            self.dec.secure_want()
        } else {
            0
        }
    }

    pub fn rx_secure_take(&mut self) -> Option<crate::SecureRxBuffer> {
        if self.rx_secure_want() == 0 || !self.check_owned() {
            return None;
        }
        self.dec.secure_take()
    }

    pub fn rx_secure_put(&mut self, loan: crate::SecureRxBuffer, now: Duration) {
        if !self.rx_gate(now) {
            return;
        }
        if let Err(e) = self.dec.secure_put(loan) {
            return self.fault(FaultReason::Frame(e));
        }
        self.process();
    }

    /// The transport filled the buffer: continue like after `on_bytes`.
    pub fn rx_direct_put(&mut self, v: Vec<u8>, crcs: crc::BlockCrcs, now: Duration) {
        if !self.rx_gate(now) {
            return;
        }
        self.dec.direct_put(v, crcs);
        self.process();
    }

    /// Feed bytes received from the socket.
    pub fn on_bytes_guarded(&mut self, data: &[u8], now: Duration, guard: ingress::InputGuard) {
        let previous = std::mem::replace(&mut self.input_guard, guard);
        self.on_bytes(data, now);
        self.input_guard = previous;
    }

    pub fn on_bytes(&mut self, data: &[u8], now: Duration) {
        self.notify_timer();
        self.now = now;
        if self.dispatch.is_some() {
            return self.fault(FaultReason::Frame(Error::Busy));
        }
        if matches!(self.st, St::Idle | St::Backoff | St::Standby | St::Closed) {
            return;
        }
        if self.st == St::HandOff {
            self.dec.feed(data); // decoded by the owning core
            return;
        }
        if !self.check_owned() {
            return;
        }
        self.last_activity = now;
        if let Err(r) = self.pre_rx_append(data) {
            return self.fault(r);
        }
        if self.st == St::Banner {
            self.banner_buf.extend_from_slice(data);
            match Banner::parse(&self.banner_buf) {
                Err(e) => return self.fault(FaultReason::Banner(e)),
                Ok(None) => return,
                Ok(Some((b, n))) => {
                    let rest = self.banner_buf.split_off(n);
                    self.banner_buf.clear();
                    if let Err(r) = self.on_banner(b) {
                        return self.fault(r);
                    }
                    self.dec.feed(&rest);
                }
            }
        } else {
            self.dec.feed(data);
        }
        self.process();
    }

    /// Consume exactly a prefix with logical pre-body admission. Parser clock only:
    /// report newly received network bytes separately through [`Self::rx_progress`].
    /// Faults use ordinary events; Idle/Closed never accept an input suffix.
    pub fn on_bytes_admitted(&mut self, data: &[u8], now: Duration) -> crate::RxFeed {
        use crate::{RxFeed, RxFeedState};
        self.now = now;
        if self.dispatch.is_none() {
            self.fault(FaultReason::Frame(Error::Busy));
            return RxFeed {
                consumed: 0,
                state: RxFeedState::NeedInput,
            };
        }
        let mut consumed = 0;
        let mut frames = false;
        loop {
            if matches!(
                self.st,
                St::Idle | St::Backoff | St::Standby | St::Closed | St::HandOff
            ) || !self.check_owned()
            {
                break;
            }
            if self.st == St::Banner {
                match Banner::parse(&self.banner_buf) {
                    Err(error) => {
                        self.fault(FaultReason::Banner(error));
                        break;
                    }
                    Ok(Some((banner, _))) => {
                        self.banner_buf.clear();
                        if let Err(reason) = self.on_banner(banner) {
                            self.fault(reason);
                            break;
                        }
                        continue;
                    }
                    Ok(None) => {}
                }
                let end = if self.banner_buf.len() < 10 {
                    10
                } else {
                    10 + denc::le::rd_u16(&self.banner_buf, 8) as usize
                };
                let n = (end - self.banner_buf.len()).min(data.len() - consumed);
                if n == 0 {
                    break;
                }
                let prefix = &data[consumed..consumed + n];
                if let Err(reason) = self.pre_rx_append(prefix) {
                    self.fault(reason);
                    break;
                }
                self.banner_buf.extend_from_slice(prefix);
                consumed += n;
                continue;
            }
            let rx = match self.dec.feed_admitted(&data[consumed..]) {
                Ok(rx) => rx,
                Err(error) => {
                    self.fault(FaultReason::Frame(error));
                    break;
                }
            };
            // Record before process: this frame's handler may freeze signatures/enter Secure.
            if let Err(reason) = self.pre_rx_append(&data[consumed..consumed + rx.consumed]) {
                self.fault(reason);
                break;
            }
            consumed += rx.consumed;
            frames |= rx.state == RxFeedState::FrameReady;
            if let RxFeedState::DispatchBlocked { .. } = rx.state {
                self.note_frame();
                return RxFeed {
                    consumed,
                    state: rx.state,
                };
            }
            self.process();
            if rx.consumed > 0 || rx.state == RxFeedState::FrameReady {
                self.notify_timer();
            }
            if consumed == data.len() || (rx.consumed == 0 && rx.state != RxFeedState::FrameReady) {
                break;
            }
        }
        self.note_frame();
        RxFeed {
            consumed,
            state: if frames {
                crate::RxFeedState::FrameReady
            } else {
                crate::RxFeedState::NeedInput
            },
        }
    }

    /// Best-effort release of unused receive backing for an owned reply consumer.
    pub fn release_empty_secure_reply(&mut self, data: &Bytes) -> bool {
        self.st == St::Ready
            && !self.pre.active
            && self.sid.is_none_or(|sid| {
                self.table
                    .with(sid, |session| session.active == Some(self.id))
                    == Some(true)
            })
            && self.dec.release_empty_secure_reply(data)
    }

    /// Our address as the peer saw it (client role; the server's HELLO `peer_addr`).
    pub fn seen_by_peer(&self) -> Option<EntityAddr> {
        self.seen_by_peer
    }

    /// Current local advertisement and peer observation, only while messenger-ready.
    pub fn local_addresses(&self) -> Option<crate::LocalAddresses<'_>> {
        (self.st == St::Ready)
            .then(|| crate::LocalAddresses::new(&self.cfg.addrs.0, self.seen_by_peer))
    }
    fn my_addrs(&self) -> EntityAddrVec {
        EntityAddrVec(
            crate::LocalAddresses::new(&self.cfg.addrs.0, self.seen_by_peer)
                .advertised()
                .collect(),
        )
    }

    // ---- internals: transport ----

    fn reset_transport(&mut self) {
        let me = self.id;
        self.sess(|s| {
            if s.active == Some(me) {
                s.drop_placement();
            }
        });
        self.banner_buf.clear();
        self.peer_banner = None;
        self.install_codec(Revision::V21)
            .expect("fresh decoder accepts its attachments");
        self.out.clear();
        self.out_chunks.clear();
        {
            self.output_exported = 0;
            self.output_written = 0;
            self.write_ends.clear();
        }
        self.placement_hold = false;
        self.placement_controls.clear();
        self.keepalive_ack = None;
        self.rdma_tried = false;
        self.rdma_active = false;
        self.pre = PreAuth::default();
        self.frame_rx = None;
        self.rx_held = false;
        self.session_key.wipe();
        self.expect_sig = [0; 32];
        self.srv_mode = 0;
    }

    fn start_stream(&mut self, now: Duration) {
        self.reset_transport();
        self.st = St::Banner;
        self.hs_deadline = now.saturating_add(self.cfg.ready_timeout);
        self.last_activity = now;
        self.pre.active = true;
        self.cfg.banner().encode(&mut self.out);
        self.pre.tx_all.extend_from_slice(&self.out);
        self.notify_output();
    }

    fn send<P: Payload>(&mut self, p: &P) -> Res {
        let payload = p
            .to_bytes()
            .map_err(|_| FaultReason::Frame(Error::PayloadTooLong))?;
        if self.placement_hold && self.st == St::Ready {
            self.placement_controls.push((P::TAG as u8, payload));
            return Ok(());
        }
        let start = self.out.len();
        self.enc
            .encode_control(P::TAG as u8, &payload, &mut self.out)
            .map_err(FaultReason::Frame)?;
        if self.pre.active {
            self.pre.tx_all.extend_from_slice(&self.out[start..]);
        }
        self.notify_output();
        Ok(())
    }

    /// Fresh decoder and encoder for a new transport stream. Until the connection is Ready every frame,
    /// whatever its tag, is held to the control ceiling ([`Limits::pre_ready`]); `become_ready` lifts it. Until the
    /// pre-auth transcript freezes, every frame is also held to [`PREAUTH_TRANSCRIPT_MAX`].
    fn install_codec(&mut self, rev: Revision) -> Result<(), Error> {
        // `cfg` can be replaced after construction (handoff): the fresh decoder follows it
        self.dcfg.rx_block_crcs = self.cfg.rx_block_crcs;
        self.dcfg.crc_data = self.cfg.crc_data;
        self.dcfg.frame_cap = self.cfg.max_message;
        self.dcfg.limits = self.cfg.limits.pre_ready();
        // Until the transcript freezes no frame can exceed what the transcript accepts: without this a peer on the
        // compat client shape (no control ceiling) declares a multi-GiB frame and the decoder reserves it on the
        // first body byte, before `pre_rx_append` sees the bytes. `freeze_and_sign` lifts it.
        self.dcfg.limits.max_frame = self
            .dcfg
            .limits
            .max_frame
            .min(PREAUTH_TRANSCRIPT_MAX as u64);
        self.dec = Decoder::with_cfg(rev, &self.dcfg);
        if let Some(owner) = &self.dispatch {
            self.dec.attach_dispatch(owner.clone())?;
        } else if let Some(shelf) = &self.shelf {
            self.dec.attach_shelf(shelf.clone())?;
        }
        self.enc = Encoder::new(rev);
        self.enc.set_limits(self.cfg.limits);
        self.enc.set_crc_data(self.cfg.crc_data);
        Ok(())
    }

    fn on_banner(&mut self, b: Banner) -> Res {
        self.cfg.banner().check(&b).map_err(FaultReason::Banner)?;
        let rev = if self.cfg.v20_only {
            Revision::V20
        } else {
            b.revision()
        };
        self.install_codec(rev).map_err(FaultReason::Frame)?;
        self.peer_banner = Some(b);
        self.send(&Hello {
            entity_type: self.cfg.name.ty,
            peer_addr: self.target,
        })?;
        self.st = St::Hello;
        Ok(())
    }

    fn process(&mut self) {
        loop {
            if matches!(
                self.st,
                St::Idle | St::Backoff | St::Standby | St::Closed | St::HandOff
            ) {
                return;
            }
            let f = match self.dec.poll_owned() {
                Ok(Some(f)) => OFrame {
                    dispatch: f.dispatch,
                    tag: f.tag,
                    flags: f.flags,
                    segs: f.segs,
                    data_crc: f.data_crc,
                    data_blocks: f.data_blocks,
                    data_head: f.data_head,
                    data_refused: f.data_refused,
                    credit: f.credit,
                },
                Ok(None) => break,
                Err(e) => return self.fault(FaultReason::Frame(e)),
            };
            if let Err(r) = self.dispatch(f) {
                return self.fault(r);
            }
        }
        // Let the application consume message events before encoding an owed ACK. A response queued
        // before the transport polls output can then acknowledge the input in its message header.
        // One-way traffic still wakes the transport and emits an ACK on that same output poll.
        if self.has_output() {
            self.notify_output();
        }
        self.note_frame();
    }

    /// Arm the frame-completion deadline after input (spec 4.3): the deadline exists to stop a peer from holding an
    /// ingress-pool reservation, so it covers only links that gate frames through one ([`FrameGate`](ingress::FrameGate):
    /// every croit-flashstore-osd server link and the OSD's Public/Cluster peer links). A link without a gate (rustyrados/rados-rt
    /// clients, the mon client) carries no per-frame deadline, like classic. A frame waiting for pool space has none
    /// either (its turn in the pool queue decides), and neither has a link between frames.
    fn note_frame(&mut self) {
        if self.rx_held || self.dcfg.gate.is_none() {
            self.frame_rx = None;
            return;
        }
        let Some((seq, wire)) = self.dec.frame_in_progress() else {
            self.frame_rx = None;
            return;
        };
        if self.dec.awaiting_credit() {
            self.frame_rx = None;
            return;
        }
        if self.frame_rx.is_none_or(|f| f.seq != seq) {
            let limit = self.frame_limit(wire);
            self.frame_rx = Some(FrameRx {
                seq,
                deadline: self.now.saturating_add(limit),
                limit,
            });
        }
    }

    /// The owner stops (`true`) or resumes (`false`) reading this link for a local reason (input held for queue room
    /// or store admission): the frame-completion deadline measures the PEER, so it is off while we do not read, and a
    /// resume grants the frame its full allowance again from `now` (our own backpressure never faults a link).
    pub fn hold_rx(&mut self, held: bool, now: Duration) {
        if self.rx_held == held {
            return;
        }
        self.now = now;
        self.rx_held = held;
        self.frame_rx = None;
        if !held {
            self.note_frame();
        }
        self.notify_timer();
    }

    /// Allowance of a frame of `wire` bytes on a gated link (one that holds an ingress-pool reservation): the
    /// handshake timeout plus its size at [`FRAME_MIN_RATE`].
    fn frame_limit(&self, wire: usize) -> Duration {
        let secs = (wire as u64).div_ceil(FRAME_MIN_RATE);
        self.cfg
            .ready_timeout
            .saturating_add(Duration::from_secs(secs))
    }

    /// Test hook for in-process harnesses that move messages between endpoints by hand (the connection never
    /// reaches the wire, so its queue is never sent nor acked): every message queued so far was delivered.
    #[cfg(feature = "test-hooks")]
    pub fn harness_delivered_all(&mut self) {
        self.sess(|s| {
            drop(s.take_unsent());
            s.trim_sent(u64::MAX);
        });
    }

    // ---- internals: session helpers ----

    fn sess<R>(&self, f: impl FnOnce(&mut Session) -> R) -> Option<R> {
        self.sid.and_then(|k| self.table.with(k, f))
    }

    fn set_sess_state(&self, st: SessState) {
        self.sess(|s| s.state = st);
    }

    /// False (and the connection closes itself) if another connection took over the session.
    fn check_owned(&mut self) -> bool {
        if self.st == St::Closed {
            return false;
        }
        let Some(k) = self.sid else { return true };
        let me = self.id;
        let owned = self.table.with(k, |s| s.owned_by(me)).unwrap_or(false);
        if !owned {
            self.finish_closed();
            return false;
        }
        true
    }

    fn finish_closed(&mut self) {
        self.reset_transport();
        self.st = St::Closed;
        self.push_event(Event::Closed);
    }

    /// Deliberate close (no retry): lossy session removed, lossless kept as standby.
    fn terminate(&mut self) {
        if self.st == St::Closed {
            return;
        }
        self.dec.cancel_gate();
        let me = self.id;
        if let Some(k) = self.sid {
            // a connection retired by a newer one (`take_superseded`) leaves the session alone
            let owner = self.table.with(k, |s| {
                (s.lossy, s.owned_by(me), s.active.is_some_and(|a| a != me))
            });
            // A failed replacement dial shares the session with its healthy lossy
            // carrier until READY. Retiring only that dial must leave the carrier intact.
            if owner == Some((true, true, false)) {
                self.table.remove(k);
            } else if owner.is_some_and(|(_, owned, _)| owned) {
                self.table.with(k, |s| {
                    if s.active == Some(me) {
                        s.drop_placement();
                        s.active = None;
                        s.state = SessState::Standby;
                    }
                    if s.dialer == Some(me) {
                        s.dialer = None;
                    }
                });
            }
        }
        self.finish_closed();
    }

    fn become_ready(&mut self, resumed: bool) {
        self.retirement_receipt = self
            .sid
            .and_then(|session| self.session_retirement(session));
        let me = self.id;
        self.st = St::Ready;
        self.dcfg.limits = self.cfg.limits;
        self.dec.set_limits(self.cfg.limits);
        self.backoff = Duration::ZERO;
        self.last_activity = self.now;
        let t = self.table.clone();
        let info = self.sess(|s| {
            if let Some(a) = s.active.filter(|a| *a != me) {
                t.supersede(a);
            }
            if let Some(d) = s.dialer.filter(|d| *d != me) {
                t.supersede(d);
            }
            s.dialer = None;
            s.active = Some(me);
            s.state = SessState::Ready;
            PeerInfo {
                name: s.peer_name,
                addrs: s.peer_addrs.clone(),
                features: s.features,
                lossy: s.lossy,
                resumed,
                global_id: 0,
                auth_name: None,
            }
        });
        if let Some(mut info) = info {
            info.global_id = self.auth_global_id;
            info.auth_name = self.auth_name;
            self.push_event(Event::Connected(info));
        }
    }

    // ---- internals: fault handling (spec 10.7) ----

    fn fault(&mut self, reason: FaultReason) {
        if self.st == St::Closed {
            return;
        }
        let was_ready = self.st == St::Ready;
        let me = self.id;
        self.push_event(Event::Fault(reason.clone()));
        self.reset_transport();
        if reason.fatal() {
            return self.terminate();
        }
        let owned = self.check_owned();
        if !owned {
            return;
        }
        if self.role == Role::Server {
            // accepted stream died: lossy -> reset; lossless -> session stays for the peer to resume
            let Some(k) = self.sid else {
                return self.finish_closed();
            };
            if self.sess(|s| s.lossy).unwrap_or(true) {
                self.table.remove(k);
                self.push_event(Event::Reset);
            } else {
                let owed = self.table.with(k, |s| {
                    if s.active == Some(me) {
                        s.active = None;
                        s.state = SessState::Standby;
                    }
                    s.active.is_none()
                        && s.dialer.is_none()
                        && !s.policy.server
                        && !s.queues_empty()
                });
                // spec 10.7 step 7: the accepting side reconnects when it owes the peer messages; this object cannot dial
                // (it knows the peer's socket, not its listener), the application does (`SessionTable::needs_dial`)
                if owed == Some(true) {
                    self.table.note_owed();
                }
            }
            return self.finish_closed();
        }
        // client role
        let Some(k) = self.sid else {
            return self.finish_closed();
        };
        if was_ready && self.sess(|s| s.lossy).unwrap_or(true) {
            self.table.remove(k);
            self.push_event(Event::Reset);
            return self.finish_closed();
        }
        let idle = self.sess(|s| s.queues_empty()).unwrap_or(true);
        if self.policy.server || (self.policy.standby && idle) {
            self.table.with(k, |s| {
                if s.active == Some(me) {
                    s.active = None;
                }
                s.dialer = Some(me);
                s.state = SessState::Standby;
            });
            self.st = St::Standby;
            return;
        }
        let wait = reason == FaultReason::Wait;
        self.table.with(k, |s| {
            if s.active == Some(me) {
                s.active = None;
            }
            s.dialer = Some(me);
            s.state = if wait {
                SessState::Wait
            } else {
                SessState::Connecting
            };
        });
        self.backoff = if was_ready && !wait {
            Duration::ZERO
        } else if wait {
            self.cfg.wait_backoff
        } else if self.backoff.is_zero() {
            self.cfg.initial_backoff
        } else {
            self.backoff.saturating_mul(2).min(self.cfg.max_backoff)
        };
        if self.backoff.is_zero() {
            self.st = St::Idle;
            self.push_event(Event::Dial {
                target: self.target,
            });
        } else {
            self.reconnect_at = self.now.saturating_add(self.backoff);
            self.st = St::Backoff;
        }
    }

    // ---- internals: frame dispatch ----

    fn dispatch(&mut self, f: OFrame) -> Res {
        let tag = Tag::from_u8(f.tag).ok_or(FaultReason::Protocol("unknown tag"))?;
        if f.flags & FLAG_COMPRESSED != 0 {
            return Err(FaultReason::Protocol(
                "compressed frame without negotiation",
            ));
        }
        if self.st == St::SessionAccepting
            && matches!(tag, Tag::ClientIdent | Tag::SessionReconnect)
            && let Some((osd, owner)) = self.foreign_osd()
        {
            self.parked = Some(f);
            self.st = St::HandOff;
            // the frame is complete: no frame deadline runs while the driver moves the connection
            self.frame_rx = None;
            self.push_event(Event::Handoff { osd, owner });
            return Ok(());
        }
        let s0 = &f.segs[0][..];
        match (self.st, tag) {
            (St::Hello, Tag::Hello) => self.on_hello(dec(s0)?),
            // client auth
            (St::AuthConnecting, Tag::AuthBadMethod) => {
                let m: AuthBadMethod = dec(s0)?;
                self.auth_c
                    .as_mut()
                    .ok_or(FaultReason::Dropped)?
                    .handle_auth_bad_method(
                        m.method,
                        m.result,
                        &m.allowed_methods,
                        &m.allowed_modes,
                    )
                    .map_err(|e| FaultReason::Auth(e.0))?;
                self.c_send_auth_request()
            }
            (St::AuthConnecting, Tag::AuthReplyMore) => {
                let m: AuthReplyMore = dec(s0)?;
                let r = self
                    .auth_c
                    .as_mut()
                    .ok_or(FaultReason::Dropped)?
                    .handle_auth_reply_more(&m.auth_payload)
                    .map_err(|e| FaultReason::Auth(e.0))?;
                self.send(&AuthRequestMore { auth_payload: r })
            }
            (St::AuthConnecting, Tag::AuthDone) => self.c_auth_done(dec(s0)?),
            (St::AuthConnectingSign, Tag::AuthSignature) => {
                self.check_sig(&dec::<AuthSignature>(s0)?)?;
                if self.compression_negotiated() {
                    self.send(&CompressionRequest {
                        is_compress: false,
                        preferred_methods: Vec::new(),
                    })?;
                    self.st = St::CompressionConnecting;
                    Ok(())
                } else {
                    self.c_after_auth()
                }
            }
            (St::CompressionConnecting, Tag::CompressionDone) => self.c_after_auth(),
            (St::RdmaOffered, Tag::RdmaUpgrade) => self.c_rdma_answer(dec(s0)?),
            // tolerated: a server that runs the compression phase although we did not ask
            (St::SessionConnecting | St::SessionReconnecting, Tag::CompressionDone) => Ok(()),
            (St::SessionConnecting, Tag::ServerIdent) => self.c_server_ident(dec(s0)?),
            (St::SessionConnecting, Tag::IdentMissingFeatures) => Err(
                FaultReason::MissingFeatures(dec::<IdentMissingFeatures>(s0)?.features),
            ),
            (St::SessionConnecting | St::SessionReconnecting, Tag::Wait) => Err(FaultReason::Wait),
            (St::SessionReconnecting, Tag::SessionReconnectOk) => {
                let m: SessionReconnectOk = dec(s0)?;
                self.sess(|s| {
                    s.trim_sent(m.msg_seq);
                    s.requeue_for_replay();
                    s.acked_out = s.in_seq;
                });
                self.become_ready(true);
                Ok(())
            }
            (St::SessionReconnecting, Tag::SessionReset) => {
                let m: SessionReset = dec(s0)?;
                let t = self.table.clone();
                self.sess(|s| {
                    if m.full {
                        let keep = t.keeps_owed(&s.policy, s.peer_name.num);
                        s.reset_all(keep);
                    } else {
                        s.server_cookie = 0;
                        s.connect_seq = 0;
                        s.in_seq = 0;
                    }
                });
                if m.full {
                    self.push_event(Event::RemoteReset);
                }
                self.c_send_client_ident()
            }
            (St::SessionReconnecting, Tag::SessionRetry) => {
                let m: SessionRetry = dec(s0)?;
                // peer-supplied: saturates, never panics
                self.sess(|s| s.connect_seq = m.connect_seq.saturating_add(1));
                self.c_send_reconnect()
            }
            (St::SessionReconnecting, Tag::SessionRetryGlobal) => {
                let m: SessionRetryGlobal = dec(s0)?;
                let t = self.table.clone();
                self.sess(|s| s.global_seq = t.next_global_seq(m.global_seq));
                self.c_send_reconnect()
            }
            // server auth
            (St::AuthAccepting, Tag::AuthRequest) => {
                let m: AuthRequest = dec(s0)?;
                self.s_auth_request(false, m.method, &m.preferred_modes, &m.auth_payload)
            }
            (St::AuthAcceptingMore, Tag::AuthRequestMore) => {
                let m: AuthRequestMore = dec(s0)?;
                self.s_auth_request(true, self.srv_method, &[], &m.auth_payload)
            }
            (St::AuthAcceptingSign, Tag::AuthSignature) => {
                self.check_sig(&dec::<AuthSignature>(s0)?)?;
                self.st = if self.compression_negotiated() {
                    St::CompressionAccepting
                } else {
                    St::SessionAccepting
                };
                Ok(())
            }
            (St::CompressionAccepting, Tag::CompressionRequest) => {
                let _: CompressionRequest = dec(s0)?;
                self.send(&CompressionDone {
                    is_compress: false,
                    method: 0,
                })?;
                self.st = St::SessionAccepting;
                Ok(())
            }
            (St::SessionAccepting, Tag::RdmaUpgrade) => self.s_rdma_offer(dec(s0)?),
            (St::SessionAccepting, Tag::ClientIdent) => self.s_client_ident(dec(s0)?),
            (St::SessionAccepting, Tag::SessionReconnect) => self.s_reconnect(dec(s0)?),
            // ready
            (St::Ready, Tag::Message) => self.on_message(f),
            (St::Ready, Tag::PlacementControl) => {
                let sender = match self.role {
                    Role::Client => Role::Server,
                    Role::Server => Role::Client,
                };
                if !self.placement_ready()
                    || f.segs[1..].iter().any(|seg| !seg.is_empty())
                    || !placement_control_valid(s0, sender)
                {
                    return Err(FaultReason::Protocol("invalid placement control"));
                }
                let record = s0.try_into().expect("checked control record length");
                self.push_event(Event::PlacementControl(record));
                Ok(())
            }
            (St::Ready, Tag::Ack) => {
                let m: Ack = dec(s0)?;
                self.sess(|s| s.trim_sent(m.seq));
                Ok(())
            }
            (St::Ready, Tag::Keepalive2) => {
                let m: Keepalive2 = dec(s0)?;
                // the peer records only the echoed stamp, so an unsent older echo is superseded
                self.keepalive_ack = Some(Keepalive2Ack {
                    sec: m.sec,
                    nsec: m.nsec,
                });
                self.notify_output();
                Ok(())
            }
            (St::Ready, Tag::Keepalive2Ack) => {
                let m: Keepalive2Ack = dec(s0)?;
                self.push_event(Event::KeepaliveAck {
                    sec: m.sec,
                    nsec: m.nsec,
                });
                Ok(())
            }
            _ => Err(FaultReason::Protocol("tag illegal in this state")),
        }
    }

    /// The authenticated peer OSD and its owning core, if that core is not this one ([`Config::home`]).
    fn foreign_osd(&self) -> Option<(i64, usize)> {
        let h = self.cfg.home?;
        let n = self.auth_name?;
        (n.ty == EntityName::OSD && n.num >= 0 && !h.is_home(n.num))
            .then(|| (n.num, h.owner(n.num)))
    }

    /// Detach a connection that raised [`Event::Handoff`] (after reading the event) so it can move to its owning core.
    /// The socket stays with the driver, which then relays bytes: input to [`Connection::on_bytes`] of the resumed
    /// connection, its output ([`Connection::poll_output_chunks`]) back to the socket. `None` in any other state.
    pub fn into_handoff(mut self) -> Option<Handoff> {
        self.timer_notify = None;
        if self.role != Role::Server || self.dispatch.is_some() || self.st != St::HandOff {
            return None;
        }
        self.auth_s = None;
        self.auth_c = None;
        self.events.clear();
        self.table = SessionTable::new(0);
        self.output_notify = None; // never transfer an Rc into another core's handoff
        self.event_notify = None;
        Some(Handoff(Box::new(self)))
    }

    /// Resume a [`Handoff`] on the owning core: new connection id, this core's `cfg` and session table. The parked
    /// CLIENT_IDENT / SESSION_RECONNECT is processed now, buffered input right after.
    pub fn from_handoff(
        h: Handoff,
        id: u64,
        cfg: Config,
        table: SessionTable,
        now: Duration,
    ) -> Connection {
        Self::from_handoff_guarded(h, id, cfg, table, now, Default::default())
    }

    pub fn from_handoff_guarded(
        h: Handoff,
        id: u64,
        cfg: Config,
        table: SessionTable,
        now: Duration,
        guard: ingress::InputGuard,
    ) -> Connection {
        let mut c = *h.0;
        c.input_guard = guard;
        c.id = id;
        c.cfg = cfg;
        c.table = table;
        c.now = now;
        c.st = St::SessionAccepting;
        // the handshake restarts on this core: the transfer time (cross-core queue, scheduling) is not the peer's delay
        c.hs_deadline = now.saturating_add(c.cfg.ready_timeout);
        c.last_activity = now;
        if let Some(f) = c.parked.take() {
            if let Err(r) = c.dispatch(f) {
                c.fault(r);
                c.input_guard = Default::default();
                return c;
            }
            c.process();
        }
        c.input_guard = Default::default();
        c
    }

    fn compression_negotiated(&self) -> bool {
        self.cfg.compression && self.peer_banner.is_some_and(|b| b.compression())
    }

    fn on_hello(&mut self, h: Hello) -> Res {
        if self.role == Role::Client {
            if h.entity_type != self.peer_type {
                return Err(FaultReason::Protocol("unexpected peer entity type"));
            }
            self.seen_by_peer = Some(h.peer_addr);
            self.c_send_auth_request()
        } else {
            self.peer_type = h.entity_type;
            self.policy = self.cfg.policies.get(h.entity_type);
            self.st = St::AuthAccepting;
            Ok(())
        }
    }

    // ---- auth ----

    fn c_send_auth_request(&mut self) -> Res {
        let r = self
            .auth_c
            .as_mut()
            .ok_or(FaultReason::Dropped)?
            .get_auth_request(self.peer_type)
            .map_err(|e| FaultReason::Auth(e.0))?;
        self.offered_modes = r.preferred_modes.clone();
        self.send(&AuthRequest {
            method: r.method,
            preferred_modes: r.preferred_modes,
            auth_payload: r.payload,
        })?;
        self.st = St::AuthConnecting;
        Ok(())
    }

    /// Append received handshake bytes to the pre-auth transcript (spec 9). The transcript is capped
    /// ([`PREAUTH_TRANSCRIPT_MAX`]): the signature needs the whole handshake and the session key exists only after
    /// AUTH_DONE, so an unauthenticated peer must not be able to grow the buffer for the whole handshake timeout.
    fn pre_rx_append(&mut self, bytes: &[u8]) -> Res {
        if !self.pre.active {
            return Ok(());
        }
        if self.pre.rx_all.len() + bytes.len() > PREAUTH_TRANSCRIPT_MAX {
            diag::diag!(
                "WARNING msgr2 pre-auth transcript exceeded {} bytes (conn {}, state {:?}, faulting)",
                PREAUTH_TRANSCRIPT_MAX,
                self.id,
                self.st
            );
            return Err(FaultReason::Protocol("pre-auth transcript too large"));
        }
        self.pre.rx_all.extend_from_slice(bytes);
        Ok(())
    }

    /// Freeze both pre-auth transcripts. Returns (our signature over rx_all, expected peer
    /// signature over tx_all).
    fn freeze_and_sign(&mut self) -> ([u8; 32], [u8; 32]) {
        let n = self.pre.rx_all.len().saturating_sub(self.dec.buffered());
        self.pre.rx_all.truncate(n);
        self.pre.active = false;
        // authenticated: the remaining handshake frames follow the pre-READY shape, no longer the transcript cap
        self.dec.set_limits(self.cfg.limits.pre_ready());
        let rx = core::mem::take(&mut self.pre.rx_all);
        let tx = core::mem::take(&mut self.pre.tx_all);
        (sign(&self.session_key, &rx), sign(&self.session_key, &tx))
    }

    fn enter_mode(&mut self, mode: u32, secret: &[u8]) -> Res {
        self.srv_mode = mode;
        match mode {
            MODE_CRC => Ok(()),
            MODE_SECURE => {
                let cs = ConnSecret::new(secret).map_err(FaultReason::Frame)?;
                self.enc
                    .set_secure(&cs, self.role)
                    .map_err(FaultReason::Frame)?;
                self.dec
                    .set_secure(&cs, self.role)
                    .map_err(FaultReason::Frame)
            }
            _ => Err(FaultReason::Protocol("unknown connection mode")),
        }
    }

    fn check_sig(&mut self, s: &AuthSignature) -> Res {
        // expect_sig holds HMAC(key, tx_all); recompute-free compare
        if self.verify_signature() && !ct_eq(&self.expect_sig, &s.signature) {
            return Err(FaultReason::Protocol("AUTH_SIGNATURE mismatch"));
        }
        Ok(())
    }

    fn c_auth_done(&mut self, d: AuthDone) -> Res {
        if !self.offered_modes.contains(&d.connection_mode) {
            return Err(FaultReason::Protocol("mode not offered"));
        }
        let secrets = self
            .auth_c
            .as_mut()
            .ok_or(FaultReason::Dropped)?
            .handle_auth_done(d.global_id, d.connection_mode, &d.auth_payload)
            .map_err(|e| FaultReason::Auth(e.0))?;
        self.auth_global_id = d.global_id;
        self.session_key = crate::auth::Secret::new(secrets.session_key.clone());
        let (mine, expect) = self.freeze_and_sign();
        self.expect_sig = expect;
        self.enter_mode(d.connection_mode, &secrets.connection_secret)?;
        self.send(&AuthSignature { signature: mine })?;
        self.st = St::AuthConnectingSign;
        Ok(())
    }

    #[cfg(feature = "test-hooks")]
    fn verify_signature(&self) -> bool {
        self.cfg.verify_signature
    }

    #[cfg(not(feature = "test-hooks"))]
    fn verify_signature(&self) -> bool {
        true
    }

    fn s_bad_method(&mut self, method: u32, result: i32) -> Res {
        let a = self.auth_s.as_ref().ok_or(FaultReason::Dropped)?;
        let methods = a.supported_methods(self.peer_type);
        // the mode list as valid for the rejected method (NONE: crc only), also when the method itself is not allowed
        let mut modes = a.supported_modes(self.peer_type, method);
        if method == AUTH_METHOD_NONE {
            modes.retain(|m| *m == MODE_CRC);
        }
        self.send(&AuthBadMethod {
            method,
            result,
            allowed_methods: methods,
            allowed_modes: modes,
        })?;
        self.st = St::AuthAccepting;
        Ok(())
    }

    fn s_auth_request(&mut self, more: bool, method: u32, modes: &[u32], payload: &[u8]) -> Res {
        let pt = self.peer_type;
        if !more {
            let a = self.auth_s.as_ref().ok_or(FaultReason::Dropped)?;
            if !a.supported_methods(pt).contains(&method) {
                return self.s_bad_method(method, EOPNOTSUPP);
            }
            let mut allowed = a.supported_modes(pt, method);
            if method == AUTH_METHOD_NONE {
                allowed.retain(|m| *m == MODE_CRC);
            }
            let Some(mode) = modes.iter().copied().find(|m| allowed.contains(m)) else {
                return self.s_bad_method(method, EOPNOTSUPP);
            };
            self.srv_method = method;
            self.srv_mode = mode;
        }
        let (m, md) = (self.srv_method, self.srv_mode);
        let step = self
            .auth_s
            .as_mut()
            .ok_or(FaultReason::Dropped)?
            .handle_auth_request(pt, more, m, md, payload);
        match step {
            AuthServerStep::More(p) => {
                self.send(&AuthReplyMore { auth_payload: p })?;
                self.st = St::AuthAcceptingMore;
                Ok(())
            }
            AuthServerStep::Busy => Err(FaultReason::Dropped),
            AuthServerStep::Reject(e) => self.s_bad_method(m, e),
            AuthServerStep::Done {
                reply,
                global_id,
                peer_name,
                secrets,
            } => {
                // A daemon-type HELLO (osd, mon, mgr, mds) must be backed by a ticket of that type. A CLIENT HELLO may carry any
                // ticket: it gets the least privileged policy, and a rados client handle inside a daemon (libcephsqlite in the
                // mgr, entity mgr.x) legitimately does so; caps and identity of the session are the authenticated ones.
                if peer_name.is_some_and(|n| n.ty != pt && pt != EntityName::CLIENT) {
                    return self.s_bad_method(m, -13);
                }
                self.send(&AuthDone {
                    global_id,
                    connection_mode: md,
                    auth_payload: reply,
                })?;
                self.auth_global_id = global_id;
                self.auth_name = peer_name;
                self.session_key = crate::auth::Secret::new(secrets.session_key.clone());
                let (mine, expect) = self.freeze_and_sign();
                self.expect_sig = expect;
                self.enter_mode(md, &secrets.connection_secret)?;
                self.send(&AuthSignature { signature: mine })?;
                self.st = St::AuthAcceptingSign;
                Ok(())
            }
        }
    }

    // ---- RDMA upgrade (spec 18) ----

    fn rdma_negotiated(&self) -> bool {
        self.cfg.rdma && self.peer_banner.is_some_and(|b| b.rdma())
    }

    /// Both authenticated peers offered placement and this READY stream completed the RDMA
    /// upgrade. Drivers must still enforce their local provider and attempt gates before use.
    pub fn placement_ready(&self) -> bool {
        self.upgraded() && self.cfg.placement && self.peer_banner.is_some_and(|b| b.placement())
    }

    /// Both banners offered source-pull and the stream is READY over RDMA.
    /// This does not prove negotiated READ depths, grant memory access, install
    /// an object handler, or establish peer retirement and durability.
    pub fn source_pull_capable(&self) -> bool {
        self.upgraded() && self.cfg.source_pull && self.peer_banner.is_some_and(|b| b.source_pull())
    }

    /// This READY stream completed the RDMA upgrade with a peer that offers it.
    fn upgraded(&self) -> bool {
        self.st == St::Ready && self.rdma_active && self.rdma_negotiated()
    }

    /// The authenticated session's generation for placement attempt identities: the
    /// server cookie both peers hold for this session (0 = none, e.g. lossy sessions,
    /// which never run placement). It changes only with the session, so a descriptor
    /// replayed on a later session cannot match it.
    pub fn placement_generation(&self) -> u64 {
        self.sess(|s| if s.lossy { 0 } else { s.server_cookie })
            .unwrap_or(0)
    }

    /// Freeze ordinary output after encoding the prefix that predates the first admitted
    /// placement request. The transport drains that prefix before posting any WRITE.
    pub fn placement_begin(&mut self) -> bool {
        if !self.placement_ready() {
            return false;
        }
        if !self.placement_hold {
            self.pump::<false>(usize::MAX);
            if !self.placement_ready() {
                return false;
            }
            self.placement_hold = true;
        }
        true
    }

    /// Release later ordinary output after the last placement attempt has queued its proof.
    pub fn placement_end(&mut self) {
        self.placement_hold = false;
        for (tag, payload) in std::mem::take(&mut self.placement_controls) {
            if let Err(error) = self.enc.encode_control(tag, &payload, &mut self.out) {
                self.fault(FaultReason::Frame(error));
                return;
            }
        }
        self.notify_remaining_output();
    }

    /// Queue one placement control only after all preceding message output was drained by the
    /// driver. The driver additionally orders this frame behind preceding RMA WRs on the RC SQ.
    /// `false` means the stream is not ready, output is still pending, or the record/direction is
    /// invalid. No bytes are queued in that case.
    pub fn send_placement_control(&mut self, record: [u8; PLACEMENT_CONTROL_LEN]) -> bool {
        if !self.placement_ready()
            || self.has_output()
            || !placement_control_valid(&record, self.role)
        {
            return false;
        }
        if let Err(r) = self
            .enc
            .encode_control(Tag::PlacementControl as u8, &record, &mut self.out)
        {
            self.fault(FaultReason::Frame(r));
            return false;
        }
        self.notify_output();
        true
    }

    /// Queue a server RETIRED after earlier placement proofs and ahead of later ordinary
    /// messages. The transport drains the pre-placement prefix before the first WRITE; the
    /// placement hold keeps later messages unencoded. Client CANCEL uses the strict method above
    /// so it never overtakes its own request.
    pub fn send_placement_retired(&mut self, record: [u8; PLACEMENT_CONTROL_LEN]) -> bool {
        if self.role != Role::Server
            || !self.placement_ready()
            || !self.placement_hold
            || !placement_control_valid(&record, self.role)
        {
            return false;
        }
        if let Err(r) = self
            .enc
            .encode_control(Tag::PlacementControl as u8, &record, &mut self.out)
        {
            self.fault(FaultReason::Frame(r));
            return false;
        }
        self.notify_output();
        true
    }

    /// Queue the successful placed reply ahead of ordinary messages that arrived while its
    /// WRITEs were in flight. The driver must have drained older output before posting the
    /// WRITEs. The reply is tied to this QP and is never replayed on another connection.
    pub fn send_placement_reply(&mut self, message: Message) -> bool {
        if !self.placement_ready() || !self.placement_hold {
            return false;
        }
        let Some(key) = self.sid else {
            return false;
        };
        if self
            .table
            .with(key, |s| s.queue_placement(message))
            .is_none()
        {
            return false;
        }
        self.pump::<false>(usize::MAX);
        self.placement_ready()
    }

    /// Bytes past the switch point would be lost between the two transports.
    fn rdma_switch_clean(&self) -> Res {
        if self.dec.buffered() != 0 {
            return Err(FaultReason::Protocol("bytes after RDMA_UPGRADE"));
        }
        Ok(())
    }

    fn c_after_auth(&mut self) -> Res {
        if !self.rdma_negotiated() || self.rdma_tried {
            return self.c_start_session();
        }
        self.rdma_tried = true;
        self.st = St::RdmaPreparing;
        self.push_event(Event::RdmaPrepare);
        Ok(())
    }

    fn c_rdma_answer(&mut self, m: RdmaUpgrade) -> Res {
        match m.op {
            RDMA_ACCEPT if !m.endpoint.is_empty() => {
                self.rdma_switch_clean()?;
                self.st = St::RdmaSwitching;
                self.push_event(Event::RdmaAnswer {
                    endpoint: Some(m.endpoint),
                });
                Ok(())
            }
            RDMA_DECLINE => {
                self.push_event(Event::RdmaAnswer { endpoint: None });
                self.c_start_session()
            }
            _ => Err(FaultReason::Protocol("bad RDMA_UPGRADE answer")),
        }
    }

    fn s_rdma_offer(&mut self, m: RdmaUpgrade) -> Res {
        if !self.rdma_negotiated() || self.rdma_tried || m.op != RDMA_OFFER || m.endpoint.is_empty()
        {
            return Err(FaultReason::Protocol("unexpected RDMA_UPGRADE"));
        }
        self.rdma_tried = true;
        // a connection handed to another core keeps its socket here (adr 0054): it stays on TCP
        if self.foreign_osd().is_some() {
            return self.send(&RdmaUpgrade {
                op: RDMA_DECLINE,
                endpoint: Vec::new(),
            });
        }
        self.rdma_switch_clean()?;
        self.st = St::RdmaAnswering;
        self.push_event(Event::RdmaOffer {
            endpoint: m.endpoint,
        });
        Ok(())
    }

    /// Client role, answer to [`Event::RdmaPrepare`]: `Some(endpoint)` sends the offer, `None` (no QP available) goes
    /// on over TCP. False (ignored) in any other state: the prepared QP is not wanted any more.
    pub fn rdma_offer(&mut self, endpoint: Option<Vec<u8>>, now: Duration) -> bool {
        self.now = now;
        if self.st != St::RdmaPreparing || !self.check_owned() {
            return false;
        }
        let r = match endpoint {
            Some(e) if !e.is_empty() => self
                .send(&RdmaUpgrade {
                    op: RDMA_OFFER,
                    endpoint: e,
                })
                .map(|()| self.st = St::RdmaOffered),
            _ => self.c_start_session(),
        };
        if let Err(r) = r {
            self.fault(r);
        }
        true
    }

    /// Server role, answer to [`Event::RdmaOffer`]. `Some(endpoint)`: the QP is already connected to the peer (RTR);
    /// the accept frame is the last TCP output - drain [`Connection::poll_output`] to the socket, then carry every
    /// later byte in both directions over the QP; the socket stays open without data as liveness channel (its end = the
    /// peer closed). `None` declines; the connection stays on TCP.
    /// False (ignored) in any other state: the connected QP is not wanted any more.
    pub fn rdma_answer(&mut self, endpoint: Option<Vec<u8>>, now: Duration) -> bool {
        self.now = now;
        if self.st != St::RdmaAnswering || !self.check_owned() {
            return false;
        }
        let accepted = endpoint.as_ref().is_some_and(|e| !e.is_empty());
        let m = match endpoint {
            Some(e) if !e.is_empty() => RdmaUpgrade {
                op: RDMA_ACCEPT,
                endpoint: e,
            },
            _ => RdmaUpgrade {
                op: RDMA_DECLINE,
                endpoint: Vec::new(),
            },
        };
        self.st = St::SessionAccepting;
        if let Err(r) = self.send(&m) {
            self.fault(r);
        } else if accepted {
            self.rdma_active = true;
        }
        true
    }

    /// Client role, after [`Event::RdmaAnswer`] with an endpoint: the QP is connected (RTS), the socket is liveness only;
    /// the session handshake continues over the QP. False (ignored) in any other state: the QP is not wanted any more.
    pub fn rdma_ready(&mut self, now: Duration) -> bool {
        self.now = now;
        if self.st != St::RdmaSwitching || !self.check_owned() {
            return false;
        }
        self.last_activity = now;
        self.rdma_active = true;
        if let Err(r) = self.c_start_session() {
            self.fault(r);
        }
        true
    }

    // ---- client session establishment (spec 10.2, 10.3) ----

    fn c_start_session(&mut self) -> Res {
        let resume = self.sess(|s| s.server_cookie != 0).unwrap_or(false);
        if resume {
            self.c_send_reconnect()
        } else {
            self.c_send_client_ident()
        }
    }

    fn c_send_reconnect(&mut self) -> Res {
        let addrs = self.my_addrs();
        let m = self
            .sess(|s| SessionReconnect {
                addrs,
                client_cookie: s.client_cookie,
                server_cookie: s.server_cookie,
                global_seq: s.global_seq,
                connect_seq: s.connect_seq,
                msg_seq: s.in_seq,
            })
            .ok_or(FaultReason::Dropped)?;
        self.send(&m)?;
        self.st = St::SessionReconnecting;
        Ok(())
    }

    fn c_send_client_ident(&mut self) -> Res {
        let t = self.table.clone();
        let (lossy, req) = (self.policy.lossy, self.policy.wire_required());
        let (addrs, target, sup) = (self.my_addrs(), self.target, self.cfg.supported_features);
        let gid = if self.cfg.name.num >= 0 || self.cfg.name.ty == EntityName::MDS {
            self.cfg.name.num
        } else {
            self.auth_global_id as i64
        };
        let m = self
            .sess(|s| {
                s.connect_seq = 0;
                if lossy {
                    s.client_cookie = 0;
                } else if s.client_cookie == 0 {
                    s.client_cookie = t.random_cookie();
                }
                ClientIdent {
                    addrs,
                    target_addr: target,
                    gid,
                    global_seq: s.global_seq,
                    supported_features: sup,
                    required_features: req,
                    flags: lossy as u64,
                    cookie: s.client_cookie,
                }
            })
            .ok_or(FaultReason::Dropped)?;
        self.send(&m)?;
        self.st = St::SessionConnecting;
        Ok(())
    }

    fn c_server_ident(&mut self, si: ServerIdent) -> Res {
        if !si.addrs.0.contains(&self.target) {
            return Err(FaultReason::Protocol("target addr not in server addrs"));
        }
        let (pt, sup) = (self.peer_type, self.cfg.supported_features);
        self.sess(|s| {
            s.peer_name = EntityName::new(pt, si.gid);
            s.peer_addrs = si.addrs.clone();
            s.server_cookie = si.cookie;
            s.peer_global_seq = si.global_seq;
            s.lossy = si.flags & 1 != 0;
            s.features = si.supported_features & sup;
            s.connect_seq = 0;
            s.restart_seqs();
        });
        self.become_ready(false);
        Ok(())
    }

    // ---- server session establishment (spec 10.4, 10.5) ----

    /// Move messages queued before this connection had a session ([`Connection::send_message`]) into the session it just
    /// got, in order. Queued answers belong to the peer that is ending its handshake, whichever frame it ends it with.
    fn queue_pending(&mut self, key: &SessionKey) {
        let pending = core::mem::take(&mut self.pending);
        self.table
            .with_key(key, |s| pending.into_iter().for_each(|m| s.queue(m)));
    }

    /// cephx global_id of an authenticated client when client identity binding is on.
    fn bound_client(&self) -> Option<u64> {
        (self.cfg.bind_client_identity
            && self.srv_method == AUTH_METHOD_CEPHX
            && self
                .auth_name
                .is_some_and(|name| name.ty == EntityName::CLIENT))
        .then_some(self.auth_global_id)
    }

    fn session_of_other(&self, key: &SessionKey, ty: u8, id: u64) -> bool {
        self.table.with_key(key, |s| {
            s.peer_name.ty != ty || s.peer_name.num as u64 != id
        }) == Some(true)
    }

    fn s_client_ident(&mut self, ci: ClientIdent) -> Res {
        if let Some(global_id) = self.bound_client()
            && ci.gid as u64 != global_id
        {
            return Err(FaultReason::Protocol(
                "client_ident gid does not match authenticated client global id",
            ));
        }
        // an authenticated OSD identity binds the id: the peer-supplied gid must be that OSD id
        if let Some(n) = self.auth_name
            && n.ty == EntityName::OSD
            && (n.num < 0 || n.num != ci.gid)
        {
            return Err(FaultReason::Protocol(
                "client_ident gid does not match authenticated osd id",
            ));
        }
        self.ident_claim = Some((ci.addrs.clone(), ci.target_addr));
        if ci.addrs.0.first().is_none_or(|a| a.is_blank()) {
            return Err(FaultReason::Dropped);
        }
        if !self.cfg.addrs.0.contains(&ci.target_addr) {
            return Err(FaultReason::Protocol("target addr is not ours"));
        }
        let pol = self.policy;
        let missing = pol.wire_required() & !ci.supported_features;
        if missing != 0 {
            return self.send(&IdentMissingFeatures { features: missing });
        }
        let features = ci.supported_features & self.cfg.supported_features;
        let anon = pol.server && pol.lossy && !pol.register_lossy_clients;
        let key = if anon {
            self.table.new_anon_key()
        } else {
            SessionKey::Peer(ci.addrs.clone())
        };
        if let Some(global_id) = self.bound_client()
            && !anon
            && self.session_of_other(&key, EntityName::CLIENT, global_id)
        {
            return Err(FaultReason::Protocol(
                "client_ident for a session of another authenticated client",
            ));
        }
        // the addrs a peer claims are visible to the cluster: an authenticated OSD may only supersede or adopt the
        // session of that same OSD (as for SESSION_RECONNECT), never kick another entity's session and take its
        // owed frames. Ceph looks the session up by addrs alone; this is a deliberate hardening (doc/compat).
        if let Some(n) = self.auth_name
            && n.ty == EntityName::OSD
            && !anon
            && self.table.with_key(&key, |x| {
                // num < 0: our own dial whose peer identity is not known yet (the race is decided below)
                x.peer_name.num >= 0
                    && (x.peer_name.ty != EntityName::OSD || x.peer_name.num != n.num)
            }) == Some(true)
        {
            return Err(FaultReason::Protocol(
                "client_ident for a session of another entity",
            ));
        }
        let me = self.id;
        let t = self.table.clone();
        let mut reset_event = false;
        let mut carry: Vec<Queued> = Vec::new();
        let mut carry_writes = None;
        let mut exists = false;
        if !anon {
            let this = IdentIn {
                client_cookie: ci.cookie,
                peer_global_seq: ci.global_seq,
            };
            let my_addr = self.cfg.addrs.v2().copied();
            let peer_addr = ci.addrs.v2().copied();
            let act = self.table.with_key(&key, |x| {
                decide_ident(x, &this, my_addr.as_ref(), peer_addr.as_ref())
            });
            match act {
                None => {}
                Some(IdentAct::CloseThis) => return Err(FaultReason::Dropped),
                Some(IdentAct::Wait) => return self.send(&Wait {}),
                Some(IdentAct::Fresh) => {
                    if let Some(mut x) = self.table.remove_key(&key) {
                        if !x.lossy && t.keeps_owed(&x.policy, x.peer_name.num) {
                            // replaced session: frames that never left move to the new one
                            {
                                carry = x.take_unsent_tracked();
                                carry_writes = Some(x.carry_writes());
                            }
                        }
                        for c in x.active.into_iter().chain(x.dialer) {
                            if c != me {
                                t.supersede(c);
                            }
                        }
                        reset_event = !x.lossy;
                    }
                }
                Some(IdentAct::ResetAdopt) => {
                    exists = true;
                    if pol.resetcheck {
                        self.table.with_key(&key, |x| {
                            let keep = t.keeps_owed(&x.policy, x.peer_name.num);
                            x.reset_all(keep)
                        });
                        reset_event = true;
                    }
                }
                Some(IdentAct::Adopt) => exists = true,
            }
        }
        if !exists {
            let mut s = Session::new(key.clone(), pol, ci.addrs.clone());
            s.state = SessState::Standby;
            self.table.insert(s);
        }
        let (pt, gid, cfg_addrs, sup) = (
            self.peer_type,
            self.cfg.name.num,
            self.cfg.addrs.clone(),
            self.cfg.supported_features,
        );
        let si = self
            .table
            .with_key(&key, |s| {
                s.client_cookie = ci.cookie;
                s.peer_name = EntityName::new(pt, ci.gid);
                s.peer_addrs = ci.addrs.clone();
                s.peer_global_seq = ci.global_seq;
                s.policy = pol;
                s.lossy = pol.lossy;
                s.features = features;
                for c in s.active.into_iter().chain(s.dialer) {
                    if c != me {
                        t.supersede(c);
                    }
                }
                s.dialer = None;
                s.active = Some(me);
                s.server_cookie = if pol.lossy { 0 } else { t.random_cookie() };
                s.global_seq = t.next_global_seq(0);
                s.connect_seq = 0;
                s.restart_seqs();
                ServerIdent {
                    addrs: cfg_addrs,
                    gid,
                    global_seq: s.global_seq,
                    supported_features: sup,
                    required_features: pol.wire_required(),
                    flags: pol.lossy as u64,
                    cookie: s.server_cookie,
                }
            })
            .ok_or(FaultReason::Dropped)?;
        self.sid = self.table.id_of(&key);
        self.table.with_key(&key, |s| {
            if let Some(writes) = carry_writes {
                s.writes = writes;
            }
            carry.into_iter().for_each(|q| s.queue_carried(q));
        });
        self.queue_pending(&key);
        self.send(&si)?;
        if reset_event {
            self.push_event(Event::RemoteReset);
        }
        self.become_ready(false);
        Ok(())
    }

    fn s_reconnect(&mut self, rc: SessionReconnect) -> Res {
        let key = SessionKey::Peer(rc.addrs.clone());
        if let Some(id) = self.bound_client()
            && self.session_of_other(&key, EntityName::CLIENT, id)
        {
            return Err(FaultReason::Protocol(
                "reconnect for a session of another authenticated client",
            ));
        }
        // an authenticated OSD identity also binds the reconnect: it may only resume a session of that same OSD (the addrs and
        // client cookie of a lossless session are visible to other entities of the cluster)
        if let Some(n) = self.auth_name
            && n.ty == EntityName::OSD
            && (n.num < 0 || self.session_of_other(&key, EntityName::OSD, n.num as u64))
        {
            return Err(FaultReason::Protocol(
                "reconnect for a session of another entity",
            ));
        }
        let my_addr = self.cfg.addrs.v2().copied();
        let resetcheck = self.policy.resetcheck;
        let act = self
            .table
            .with_key(&key, |x| {
                decide_reconnect(Some(x), &rc, resetcheck, my_addr.as_ref())
            })
            .unwrap_or_else(|| decide_reconnect(None, &rc, resetcheck, my_addr.as_ref()));
        match act {
            ReconnectAct::Reset(full) => {
                let tbl = self.table.clone();
                // A session with a live connection is not the one the peer is resuming (a stale incarnation of the peer
                // reconnecting, or the peer's reconnect for a session of ours it lost): answer RESET, keep ours. Wiping it
                // restarted the numbering while the connection stayed up and the peer dropped the frames as "old".
                let wiped = self.table.with_key(&key, |x| {
                    if x.active.is_some() && x.state == SessState::Ready {
                        return false;
                    }
                    let keep = tbl.keeps_owed(&x.policy, x.peer_name.num);
                    x.reset_all(keep);
                    true
                });
                if full && wiped == Some(true) {
                    self.push_event(Event::RemoteReset);
                }
                self.send(&SessionReset { full })
            }
            ReconnectAct::RetryGlobal(g) => self.send(&SessionRetryGlobal { global_seq: g }),
            ReconnectAct::Retry(c) => self.send(&SessionRetry { connect_seq: c }),
            ReconnectAct::Wait => self.send(&Wait {}),
            ReconnectAct::Accept => {
                let me = self.id;
                let t = self.table.clone();
                let ok = self
                    .table
                    .with_key(&key, |x| {
                        x.connect_seq = rc.connect_seq;
                        x.peer_global_seq = rc.global_seq;
                        for c in x.active.into_iter().chain(x.dialer) {
                            if c != me {
                                t.supersede(c);
                            }
                        }
                        x.dialer = None;
                        x.active = Some(me);
                        x.trim_sent(rc.msg_seq);
                        x.requeue_for_replay();
                        x.acked_out = x.in_seq;
                        SessionReconnectOk { msg_seq: x.in_seq }
                    })
                    .ok_or(FaultReason::Dropped)?;
                self.sid = self.table.id_of(&key);
                self.queue_pending(&key);
                self.send(&ok)?;
                self.become_ready(true);
                Ok(())
            }
        }
    }

    // ---- ready ----

    fn on_message(&mut self, f: OFrame) -> Res {
        let dispatch = f.dispatch;
        let dcrc = f.data_crc;
        let dblk = f.data_blocks;
        let dhead = f.data_head;
        let credit = f.credit;
        let mut it = f.segs.into_iter();
        let h = it.next().unwrap_or_default();
        let header =
            MsgHeader2::from_bytes(&h).map_err(|_| FaultReason::Protocol("short header2"))?;
        let front = it.next().unwrap_or_default();
        let middle = it.next().unwrap_or_default();
        let data = it.next().unwrap_or_default();
        let (verdict, in_seq) = self
            .sess(|s| {
                if !s.lossy {
                    s.trim_sent(header.ack_seq);
                }
                let v = crate::seqcheck::classify(s.in_seq, header.seq);
                let before = s.in_seq;
                if v != crate::seqcheck::Seq::Dup {
                    s.in_seq = header.seq;
                }
                (v, before)
            })
            .ok_or(FaultReason::Dropped)?;
        if let Some(suppressed) = self.seq_log.note(verdict, self.now) {
            // a duplicate is normal right after a reconnect (the peer replays what our ack had not covered yet): an info
            // line; a gap means messages the peer sent never arrived: a warning
            let (level, what) = match verdict {
                crate::seqcheck::Seq::Dup => (
                    "msgr2",
                    format!(
                        "duplicate message seq {} <= in_seq {in_seq}, dropped",
                        header.seq
                    ),
                ),
                _ => (
                    "WARNING msgr2",
                    format!(
                        "message seq gap: got {}, expected {}, accepted",
                        header.seq,
                        in_seq + 1
                    ),
                ),
            };
            diag::diag!(
                "{level} {what} (conn {}, peer {} {}; {suppressed} similar suppressed since the last line)",
                self.id,
                EntityName::new(self.peer_type, -1),
                self.target
            );
        }
        let fresh = verdict != crate::seqcheck::Seq::Dup;
        if fresh {
            self.push_event(Event::Message(Incoming {
                dispatch,
                ingress: if credit.0.is_some() {
                    // header-time reservation of this frame (gated connections)
                    credit
                } else {
                    if let Some(lease) = &self.input_guard.0 {
                        lease.retain_frame(front.len() + middle.len() + data.len());
                    }
                    self.input_guard.clone()
                },
                header,
                front,
                middle,
                data_crc: match (dcrc, dblk) {
                    (Some(c), Some(b)) => crc::CrcHint::with_blocks_at(&data, c, b, dhead),
                    (Some(c), None) => crc::CrcHint::new(&data, c),
                    _ => Default::default(),
                },
                data_refused: f.data_refused,
                data,
            }));
        }
        Ok(())
    }

    // Each appended chunk is counted once per preparation call, even when an
    // encoder moves the old out prefix into a new chunk before appending data.
    fn newly_prepared(&self, chunks: usize, out: usize) -> usize {
        self.out_chunks[chunks..]
            .iter()
            .fold(self.out.len(), |n, chunk| n.saturating_add(chunk.len()))
            .saturating_sub(out)
    }

    /// Move queued messages (and a pending ACK) into frames. Bounded: frames may overshoot `maximum` once.
    fn pump<const BOUNDED: bool>(&mut self, maximum: usize) {
        // Transports poll every link's output each turn and most links are idle: return before the framing loop, which
        // moves its queued-message slot even when the queue is empty, when nothing is queued and no ACK is owed.
        if self.st != St::Ready || !self.sess(|s| s.has_frame_work()).unwrap_or(false) {
            return;
        }
        if self.write_capacity == 0 {
            self.pump_inner::<BOUNDED, false>(maximum);
        } else {
            self.pump_inner::<BOUNDED, true>(maximum);
        }
    }

    fn pump_inner<const BOUNDED: bool, const TRACKED: bool>(&mut self, maximum: usize) {
        if self.st != St::Ready {
            return;
        }
        let mut prepared = 0usize;
        let mut buffered = if TRACKED {
            self.out.len() + self.out_chunks.iter().map(Bytes::len).sum::<usize>()
        } else {
            0
        };
        let mut wrote = false;
        while !BOUNDED || prepared < maximum {
            let hold = self.placement_hold;
            let Some((mut q, seq, ack, lossy)) = self
                .sess(|s| {
                    let mut q = if hold {
                        s.next_placement_to_send()
                    } else {
                        s.next_to_send()
                    }?;
                    if q.seq == 0 {
                        s.out_seq += 1;
                        q.seq = s.out_seq;
                    }
                    s.acked_out = s.in_seq;
                    let seq = q.seq;
                    Some((q, seq, s.in_seq, s.lossy))
                })
                .flatten()
            else {
                break;
            };
            let m = &q.msg;
            let h = MsgHeader2 {
                seq,
                tid: m.tid,
                msg_type: m.msg_type,
                priority: m.priority,
                version: m.version,
                data_pre_padding_len: 0,
                data_off: m.data_off,
                ack_seq: ack,
                flags: HDR_FLAGS_DEFAULT,
                compat_version: if m.compat_version == 0 {
                    m.version
                } else {
                    m.compat_version
                },
                reserved: 0,
            };
            let start = self.out.len();
            let chunk_start = self.out_chunks.len();
            let encoded = if lossy
                && self.mode() == MODE_SECURE
                && m.front_zc.is_empty()
                && m.data_more.is_empty()
            {
                // Plaintext is disposable: a unique buffer is encrypted in place. Release the CRC hint's ownership
                // before checking uniqueness. Fragmented bodies (front runs, data parts) take the paths below, which
                // encrypt each piece from its source into the frame (no flattened plaintext first).
                q.msg.data_crc = Default::default();
                q.msg.front_hints.clear();
                self.enc.encode_message_owned(
                    &h.to_bytes(),
                    core::mem::take(&mut q.msg.front),
                    core::mem::take(&mut q.msg.middle),
                    core::mem::take(&mut q.msg.data),
                    &mut self.out,
                    &mut self.out_chunks,
                )
            } else if !m.data_more.is_empty() {
                // data segment in parts (replicated large write); such messages carry no front runs
                let flat = if m.front_zc.is_empty() {
                    Ok(None)
                } else {
                    crate::encode::flatten(&m.front, &m.front_zc).map(Some)
                };
                match flat {
                    Ok(flat) => self.enc.encode_message_parts(
                        &h.to_bytes(),
                        flat.as_deref().unwrap_or(&m.front),
                        &m.middle,
                        &m.data,
                        &m.data_crc,
                        &m.data_more,
                        &mut self.out,
                        &mut self.out_chunks,
                    ),
                    Err(e) => Err(e),
                }
            } else {
                self.enc.encode_message_rope(
                    &h.to_bytes(),
                    &m.front,
                    &m.front_zc,
                    &m.front_hints,
                    &m.middle,
                    &m.data,
                    &m.data_crc,
                    &mut self.out,
                    &mut self.out_chunks,
                )
            };
            if let Err(e) = encoded {
                // Nothing deterministic reaches this point: `Message::fits` validated the front rope and the frame
                // limits at `send_message`. An environmental failure (allocation, secure seal) must not become an
                // endless replay of the same message on a lossless link: fail that message alone (its seq is skipped,
                // receivers accept the gap) and reset the stream. `fault` discards the partial frame. The message is
                // never resent, so its receipt ends here on lossless and lossy sessions alike.
                diag::diag!(
                    "WARNING msgr2 message type {} tid {} failed to encode ({e}), dropped (conn {})",
                    q.msg.msg_type,
                    q.msg.tid,
                    self.id
                );
                if TRACKED && let Some(token) = &q.write {
                    token.complete(crate::WriteStatus::Discarded);
                }
                return self.fault(FaultReason::Frame(e));
            }
            let bytes = if BOUNDED {
                self.newly_prepared(chunk_start, start)
            } else {
                0
            };
            let bytes = if !BOUNDED && TRACKED {
                self.newly_prepared(chunk_start, start)
            } else {
                bytes
            };
            if TRACKED {
                buffered += bytes;
            }
            if TRACKED
                && let Some(token) = &q.write
                && token.pending()
            {
                if self.write_ends.len() == self.write_capacity {
                    self.write_ends.retain(|(_, token)| token.pending());
                }
                if self.write_ends.len() == self.write_capacity {
                    return self.fault(FaultReason::Protocol("write receipt capacity invariant"));
                }
                let Some(end) = self.output_exported.checked_add(buffered as u64) else {
                    return self.fault(FaultReason::Protocol("output byte counter overflow"));
                };
                self.write_ends.push_back((end, token.clone()));
            }
            self.sess(|s| s.mark_sent(q));
            wrote = true;
            if BOUNDED {
                prepared = prepared.saturating_add(bytes);
            }
        }
        if BOUNDED && prepared >= maximum {
            // On preparation exhaustion keep an ACK owed for the next prepared
            // message or a later empty-wire poll.
            if wrote {
                self.tx_since_idle_check = true;
                self.notify_output();
            }
            return;
        }
        if self.placement_hold {
            if wrote {
                self.tx_since_idle_check = true;
                self.notify_output();
            }
            return;
        }
        let ack = self.sess(|s| {
            if !s.lossy && s.in_seq > s.acked_out {
                s.acked_out = s.in_seq;
                Some(s.in_seq)
            } else {
                None
            }
        });
        if let Some(Some(seq)) = ack {
            if let Err(r) = self.send(&Ack { seq }) {
                return self.fault(r);
            }
            wrote = true;
        }
        if wrote {
            self.tx_since_idle_check = true;
            self.notify_output();
        }
    }
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

#[cfg(test)]
mod none_sign_tests {
    #[test]
    fn empty_session_key_signs_32_zero_bytes() {
        assert_eq!(super::sign(&[], b"transcript"), [0u8; 32]);
        assert_ne!(super::sign(b"k", b"transcript"), [0u8; 32]);
    }
}

#[cfg(test)]
mod home_tests {
    use super::Home;

    /// Placement divides by the number of home cores: a `Home` without cores must not be constructible.
    #[test]
    fn a_home_needs_at_least_one_core() {
        assert_eq!(Home::new(0, 0), None);
        let h = Home::new(1, 2).expect("two cores");
        assert_eq!(
            (0..4).map(|osd| h.owner(osd)).collect::<Vec<_>>(),
            [0, 1, 0, 1]
        );
        assert!(h.is_home(1) && !h.is_home(2));
    }
}
