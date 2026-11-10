// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Dev-only RADOS client driver over kernel TCP (adr 0015 amendment): MonClient for map/commands,
//! msgr2 client connections to OSDs with cephx service authorizers, compound MOSDOp send/receive.

use crate::script::ScriptMsg;
use cephx::keyring::Keyring;
#[cfg(not(feature = "native-read"))]
use cephx::modes::AUTH_CEPHX;
use cephx::modes::{CON_MODE_CRC, CON_MODE_SECURE};
use cephx::none::ENTITY_OSD;
#[cfg(not(feature = "native-read"))]
use cephx::types::TicketBlob;
#[cfg(not(feature = "native-read"))]
use cephx::{Authorizer, CryptoKey};
use denc::types::{
    EntityAddr, EntityAddrVec, EntityName, Eversion, ObjectLocator, PgT, ShardId, SpgT, UTime,
};
use messages::Segments;
use monc::{Config, IoCmd, MonClient, MonEvent, parse_mon_host};
#[cfg(not(feature = "native-read"))]
use msgr2::auth::{AuthClientHandler, AuthError, AuthRequestOut, AuthSecrets};
use msgr2::{Connection, Event, Incoming, Policy, PolicyTable, SessionTable};
use opwire::consts::{backoff, flag, op};
use opwire::{ClientMsg, MOSDBackoff, MOSDOp, MOSDOpReply};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(feature = "native-read")]
use std::{cell::Cell, rc::Rc};

pub type Res<T> = Result<T, String>;

/// Mon command JSON for `osd pool create`; the JSON encoder escapes the operator's pool name.
pub fn pool_create_cmd(name: &str, pgs: u32) -> String {
    serde_json::json!({
        "prefix": "osd pool create",
        "pool": name,
        "pg_num": pgs,
        "pgp_num": pgs,
    })
    .to_string()
}

/// Mon command JSON for `osd pool set ... size`.
pub fn pool_size_cmd(name: &str, size: u32) -> String {
    let mut cmd = serde_json::json!({
        "prefix": "osd pool set",
        "pool": name,
        "var": "size",
        "val": size.to_string(),
    });
    // the mon refuses size 1 without the confirmation; the operator asked for it explicitly
    if size == 1 {
        cmd["yes_i_really_mean_it"] = true.into();
    }
    cmd.to_string()
}

/// Mon command JSON for `osd pool rm` (the second confirmation name included).
pub fn pool_rm_cmd(name: &str) -> String {
    serde_json::json!({
        "prefix": "osd pool rm",
        "pool": name,
        "pool2": name,
        "yes_i_really_really_mean_it": true,
    })
    .to_string()
}

/// Attempts of one `exec`/pipelined op (the first send included) before it completes with an error.
const MAX_ATTEMPTS: u32 = 8;

#[cfg(feature = "native-read")]
mod native;
#[cfg(feature = "native-read")]
pub use native::NativeReads;

/// Connection options.
#[derive(Clone, Debug)]
pub struct Opts {
    pub conf: String,
    pub mon: Option<String>,
    pub keyring: Option<String>,
    pub entity: String,
    /// `crc`, `secure` or `auto`.
    pub mode: String,
    /// Per-attempt reply timeout.
    pub timeout: Duration,
    /// Resend after a timeout or connection loss (default off: a crashing OSD must not be hit again).
    pub resend_lost: bool,
    pub verbose: bool,
    /// Local TCP source port of every OSD connection (`None` = the kernel picks). The OSD's accept core follows the
    /// connection's 4-tuple, so a fixed port gives the same placement in every run (A/B harness).
    pub osd_src_port: Option<u16>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            conf: "/etc/ceph/ceph.conf".into(),
            mon: None,
            keyring: None,
            entity: "client.admin".into(),
            mode: "auto".into(),
            timeout: Duration::from_secs(5),
            resend_lost: false,
            verbose: false,
            osd_src_port: None,
        }
    }
}

/// Where an op goes.
#[derive(Clone, Debug)]
pub struct Target {
    pub pool: i64,
    pub oid: Vec<u8>,
    pub nspace: Vec<u8>,
    pub key: Vec<u8>,
    /// Force this OSD (no remap, no resend); `None` = acting primary with resend on map change.
    pub force_osd: Option<i32>,
}

/// Placement of an object under the current map.
#[derive(Clone, Debug)]
pub struct Placement {
    pub epoch: u32,
    pub raw_pg: PgT,
    pub pg: PgT,
    pub up: Vec<i32>,
    pub acting: Vec<i32>,
    pub primary: i32,
}

/// Result of one exec.
#[derive(Debug)]
pub struct OpOutcome {
    /// `None` = no reply (timeout / connection loss); see `note`.
    pub reply: Option<MOSDOpReply>,
    pub note: String,
    pub osd: i32,
    pub attempts: u32,
    pub placement: Placement,
    /// The request ops as sent (for interpreting the reply).
    pub req_ops: Vec<opwire::OsdOp>,
}

#[cfg(not(feature = "native-read"))]
struct OsdAuth {
    gid: u64,
    ticket: TicketBlob,
    key: CryptoKey,
    modes: Vec<u32>,
    auth: Option<Authorizer>,
}

/// Never print credential material: `TicketBlob`/`Authorizer` keep their raw blobs in `Debug`.
#[cfg(not(feature = "native-read"))]
impl std::fmt::Debug for OsdAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsdAuth")
            .field("gid", &self.gid)
            .field("modes", &self.modes)
            .field("authorized", &self.auth.is_some())
            .finish()
    }
}

#[cfg(not(feature = "native-read"))]
impl AuthClientHandler for OsdAuth {
    fn get_auth_request(&mut self, peer_type: u8) -> Result<AuthRequestOut, AuthError> {
        let a = Authorizer::from_ticket(self.gid, u32::from(peer_type), &self.ticket, &self.key)
            .map_err(|e| AuthError(format!("authorizer: {e:?}")))?;
        let p = a.payload().to_vec();
        self.auth = Some(a);
        Ok(AuthRequestOut {
            method: AUTH_CEPHX,
            preferred_modes: self.modes.clone(),
            payload: p,
        })
    }
    fn handle_auth_reply_more(&mut self, payload: &[u8]) -> Result<Vec<u8>, AuthError> {
        let a = self
            .auth
            .as_mut()
            .ok_or_else(|| AuthError("no authorizer".into()))?;
        a.on_reply_more(payload)
            .map(<[u8]>::to_vec)
            .map_err(|e| AuthError(format!("reply_more: {e:?}")))
    }
    fn handle_auth_done(
        &mut self,
        _gid: u64,
        _mode: u32,
        payload: &[u8],
    ) -> Result<AuthSecrets, AuthError> {
        let a = self
            .auth
            .as_mut()
            .ok_or_else(|| AuthError("no authorizer".into()))?;
        a.on_done(payload)
            .map_err(|e| AuthError(format!("done: {e:?}")))?;
        Ok(AuthSecrets {
            session_key: a.session_key().secret().to_vec(),
            connection_secret: a
                .connection_secret()
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_default(),
        })
    }
    fn handle_auth_bad_method(
        &mut self,
        method: u32,
        result: i32,
        _m: &[u32],
        _modes: &[u32],
    ) -> Result<(), AuthError> {
        Err(AuthError(format!(
            "osd rejected auth method {method} ({result})"
        )))
    }
}

struct OsdConn {
    conn: Connection,
    sock: Option<TcpStream>,
    ready: bool,
    features: u64,
    mode: u32,
    dead: Option<String>,
    #[cfg(feature = "native-read")]
    failure: Option<rustyrados::SessionFailure>,
    inbox: VecDeque<Incoming>,
    /// Not yet written output of the non-blocking socket.
    out: OutQueue,
}

impl OsdConn {
    #[cfg(feature = "native-read")]
    fn note_failure(&mut self, failure: rustyrados::SessionFailure) {
        self.failure = Some(self.failure.map_or(failure, |old| old.merge(failure)));
    }
    fn note_transport_loss(&mut self) {
        #[cfg(feature = "native-read")]
        self.note_failure(rustyrados::SessionFailure::Transport);
    }
    fn note_reset(&mut self) {
        #[cfg(feature = "native-read")]
        self.note_failure(rustyrados::SessionFailure::Reset);
    }
    fn note_rejection(&mut self) {
        #[cfg(feature = "native-read")]
        self.note_failure(rustyrados::SessionFailure::Rejected);
    }
    fn note_fault(&mut self, reason: &msgr2::FaultReason) {
        if recoverable_fault(reason) {
            self.note_transport_loss();
        } else {
            self.note_rejection();
        }
    }
}

/// Segments of one queued OSD message: front/middle copied out of the receive buffer, `data` stays shared.
fn segments(inc: Incoming) -> Segments {
    Segments {
        front_zc: Vec::new(),
        front_hints: Default::default(),
        front: inc.front.to_vec(),
        middle: inc.middle.to_vec(),
        data: inc.data,
    }
}

/// Output queued for one non-blocking socket (`buf[off..]` is still unsent), shared by the mon and OSD sockets. The
/// write never waits for the peer: a stalled peer only grows the queue, and every deadline of the tool keeps running.
#[derive(Default)]
struct OutQueue {
    buf: Vec<u8>,
    off: usize,
}

impl OutQueue {
    /// Queue already-encoded output; takes ownership when the queue is drained (no copy on the hot path).
    fn push(&mut self, out: Vec<u8>) {
        if self.off >= self.buf.len() {
            self.buf = out;
            self.off = 0;
        } else {
            self.buf.extend_from_slice(&out);
        }
    }

    /// Write as much as the socket takes without blocking (bytes written); an error means the connection is unusable.
    fn flush(&mut self, s: &mut TcpStream) -> std::io::Result<usize> {
        let mut written = 0;
        while self.off < self.buf.len() {
            match s.write(&self.buf[self.off..]) {
                Ok(0) => break,
                Ok(n) => {
                    self.off += n;
                    written += n;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if self.off >= self.buf.len() {
            self.buf.clear();
            self.off = 0;
        }
        Ok(written)
    }
}

/// Non-blocking socket with no Nagle delay. A failure leaves the fd unusable for the pump and must never be ignored
/// (a blocking socket would hang `step` without a diagnostic).
fn configure_socket(s: &TcpStream) -> std::io::Result<()> {
    s.set_nodelay(true)?;
    s.set_nonblocking(true)
}

/// `None` when the message fits the connection's frame limits, else the per-op error text. Told apart from a closed
/// connection: an oversized op is a bad request, not a lost peer.
fn frame_limit_error(m: &msgr2::Message, limits: &msgr2::Limits) -> Option<String> {
    (!m.fits(limits)).then(|| {
        let bytes = m
            .front
            .len()
            .saturating_add(m.middle.len())
            .saturating_add(m.data.len());
        format!(
            "message exceeds the msgr2 frame limits ({bytes} B > {} B)",
            limits.max_frame
        )
    })
}

/// One resend per op per poll: EAGAIN, UNBLOCK and a moved primary can fire for the same tid in one cycle, and a second
/// resend of the same logical op would execute it twice on the OSD. The first reason wins.
fn resend_once(queue: &mut BTreeMap<u64, &'static str>, tid: u64, why: &'static str) {
    queue.entry(tid).or_insert(why);
}

fn recoverable_fault(reason: &msgr2::FaultReason) -> bool {
    matches!(
        reason,
        msgr2::FaultReason::Io | msgr2::FaultReason::Dropped | msgr2::FaultReason::Timeout(_)
    )
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    #[test]
    fn out_queue_takes_ownership_of_pending_output() {
        let mut q = OutQueue::default();
        let bytes = vec![1u8; 4096];
        let p = bytes.as_ptr();
        q.push(bytes);
        assert_eq!(q.buf.as_ptr(), p, "queued output is taken over, not copied");
        assert_eq!(q.off, 0);
    }

    #[test]
    fn out_queue_never_blocks_on_a_full_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let mut sock = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (_peer, _) = listener.accept().expect("accept");
        socket2::SockRef::from(&sock)
            .set_send_buffer_size(4096)
            .expect("send buffer");
        sock.set_nonblocking(true).expect("nonblocking");
        let mut q = OutQueue::default();
        q.push(vec![7u8; 4 << 20]);
        let written = q.flush(&mut sock).expect("flush");
        assert!(written > 0, "the socket takes some bytes");
        assert!(q.off < q.buf.len(), "a full socket keeps the remainder");
        assert_eq!(q.buf[q.off], 7, "the remainder is the unsent tail");
        let off = q.off;
        q.flush(&mut sock).expect("second flush");
        assert!(q.off >= off);
    }

    #[test]
    fn an_oversized_message_is_not_a_closed_connection() {
        let limits = msgr2::Limits {
            max_frame: 4096,
            ..msgr2::Limits::default()
        };
        let big = msgr2::Message {
            front: vec![0; 4096],
            ..Default::default()
        };
        let e = frame_limit_error(&big, &limits).expect("refused");
        assert!(e.contains("frame limits"), "{e}");
        let small = msgr2::Message {
            front: vec![0; 16],
            ..Default::default()
        };
        assert!(frame_limit_error(&small, &limits).is_none());
    }

    #[test]
    fn one_resend_per_op_per_poll() {
        let mut q = BTreeMap::new();
        resend_once(&mut q, 7, "EAGAIN");
        resend_once(&mut q, 7, "primary moved");
        resend_once(&mut q, 8, "unblock");
        assert_eq!(q.len(), 2);
        assert_eq!(q[&7], "EAGAIN");
        assert_eq!(q[&8], "unblock");
    }
}

#[cfg(all(test, not(feature = "native-read")))]
mod secrets_tests {
    use super::*;

    #[test]
    fn osd_auth_debug_prints_no_credential_material() {
        let h = OsdAuth {
            gid: 42,
            ticket: TicketBlob {
                secret_id: 7,
                blob: b"TICKET-BLOB-MARKER".to_vec(),
            },
            key: CryptoKey::new(cephx::KeyType::Aes, UTime::default(), b"KEY-SECRET-MARKER"),
            modes: vec![CON_MODE_CRC],
            auth: None,
        };
        let s = format!("{h:?}");
        assert!(s.contains("gid: 42"), "{s}");
        assert!(!s.contains("TICKET-BLOB-MARKER"), "{s}");
        assert!(!s.contains("KEY-SECRET-MARKER"), "{s}");
    }
}

#[cfg(test)]
mod cmd_tests {
    use super::*;

    const HOSTILE: &str = r#"a","yes_i_really_really_mean_it":true,"pool":"cephfs_data"#;

    #[test]
    fn pool_commands_escape_the_name() {
        for (cmd, keys) in [
            (pool_create_cmd(HOSTILE, 8), 4),
            (pool_size_cmd(HOSTILE, 3), 4),
            (pool_rm_cmd(HOSTILE), 4),
        ] {
            let v: serde_json::Value = serde_json::from_str(&cmd).expect("valid JSON");
            let o = v.as_object().expect("object");
            assert_eq!(o.len(), keys, "no injected key: {cmd}");
            assert_eq!(o["pool"], HOSTILE);
        }
    }

    #[test]
    fn size_one_carries_the_mon_confirmation() {
        let v: serde_json::Value = serde_json::from_str(&pool_size_cmd("p", 1)).unwrap();
        assert_eq!(v["yes_i_really_mean_it"], true);
        let v: serde_json::Value = serde_json::from_str(&pool_size_cmd("p", 2)).unwrap();
        assert!(v.get("yes_i_really_mean_it").is_none());
    }
}

#[cfg(test)]
mod fault_tests {
    use super::recoverable_fault;
    use msgr2::{Error, FaultReason};

    #[test]
    fn corruption_auth_features_and_protocol_are_not_transport_retries() {
        for reason in [
            FaultReason::Frame(Error::BadPreambleCrc),
            FaultReason::Frame(Error::AuthFailed),
            FaultReason::Protocol("bad reply"),
            FaultReason::Auth("rejected".into()),
            FaultReason::MissingFeatures(1),
            FaultReason::Wait,
        ] {
            assert!(!recoverable_fault(&reason), "{reason:?}");
        }
        for reason in [
            FaultReason::Io,
            FaultReason::Dropped,
            FaultReason::Timeout("transport"),
        ] {
            assert!(recoverable_fault(&reason), "{reason:?}");
        }
    }
}

/// The probe client.
pub struct Probe {
    pub opts: Opts,
    mc: MonClient,
    t0: Instant,
    wall0: u64,
    #[cfg(feature = "native-read")]
    auth_clock: Rc<Cell<Duration>>,
    mon_socks: HashMap<u64, TcpStream>,
    /// Unsent mon output per connection (non-blocking socket, see [`OutQueue`]).
    mon_out: HashMap<u64, OutQueue>,
    table: SessionTable,
    msgr_cfg: msgr2::Config,
    osds: HashMap<i32, OsdConn>,
    next_conn: u64,
    next_tid: u64,
    cmd_replies: HashMap<u64, (i32, String, Vec<u8>)>,
    authed: bool,
    buf: Vec<u8>,
    pub log: Vec<String>,
    /// Sleep of an idle `step` (default 1 ms; benchmarks lower it).
    pub idle_sleep: Duration,
    /// When set, `locate` targets this PG seed of the target pool instead of hashing the oid (PG-level ops: pgnls).
    pub pg_override: Option<u32>,
    pending: HashMap<u64, Pending>,
    epoch_seen: u32,
}

/// Connect to an OSD within 2 s, from local port `src_port` when set (SO_REUSEADDR: the port may sit in TIME_WAIT of
/// a previous run).
fn dial_osd(sa: &SocketAddr, src_port: Option<u16>) -> std::io::Result<TcpStream> {
    let Some(p) = src_port else {
        return TcpStream::connect_timeout(sa, Duration::from_secs(2));
    };
    let s = socket2::Socket::new(
        socket2::Domain::for_address(*sa),
        socket2::Type::STREAM,
        None,
    )?;
    s.set_reuse_address(true)?;
    let local = SocketAddr::new(
        match sa {
            SocketAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        },
        p,
    );
    s.bind(&local.into())?;
    s.connect_timeout(&(*sa).into(), Duration::from_secs(2))?;
    Ok(s.into())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl std::fmt::Debug for Probe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Probe")
    }
}

impl Probe {
    /// Connect to the mon, authenticate, fetch the osdmap and the OSD service ticket.
    pub fn connect(opts: Opts) -> Res<Probe> {
        let kr_path = opts
            .keyring
            .clone()
            .unwrap_or_else(|| format!("/etc/ceph/ceph.{}.keyring", opts.entity));
        let text =
            std::fs::read_to_string(&kr_path).map_err(|e| format!("keyring {kr_path}: {e}"))?;
        let kr = Keyring::parse(&text).map_err(|e| format!("keyring parse: {e:?}"))?;
        let key = kr
            .get(&opts.entity)
            .and_then(|e| e.key.clone())
            .ok_or_else(|| format!("no key for {} in {kr_path}", opts.entity))?;
        let mon_host = opts.mon.clone().or_else(|| {
            std::fs::read_to_string(&opts.conf).ok().and_then(|t| {
                t.lines().find_map(|l| {
                    let (k, v) = l.split_once('=')?;
                    (k.trim().replace(' ', "_") == "mon_host").then(|| v.trim().to_string())
                })
            })
        });
        let mon_host = mon_host.unwrap_or_else(|| "v2:172.28.0.10:3300".into());
        let wall = unix_now();
        let mut cfg = Config::new(&opts.entity, Some(key));
        cfg.mon_host = parse_mon_host(&mon_host)?;
        cfg.wall_origin = Duration::from_secs(wall);
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        // distinct per Probe in one process: the seed makes the msgr2 nonce (same addr+nonce = same client to an OSD)
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        cfg.seed = wall ^ ((std::process::id() as u64) << 20) ^ (seq << 8);
        cfg.hostname = "oprobe".into();
        cfg.modes = modes(&opts.mode);
        let seed = cfg.seed;
        let msgr_cfg = {
            let mut a = EntityAddr::blank();
            a.ty = EntityAddr::TYPE_MSGR2;
            a.nonce = (seed >> 7) as u32 | 1;
            msgr2::Config::new(
                cfg.msgr_name(),
                EntityAddrVec::single(a),
                PolicyTable::uniform(Policy::lossy_client(msgr2::OSD_REQUIRED)),
            )
        };
        let mut mc = MonClient::new(cfg);
        let t0 = Instant::now();
        mc.start(t0.elapsed());
        let mut p = Probe {
            opts,
            mc,
            t0,
            wall0: wall,
            #[cfg(feature = "native-read")]
            auth_clock: Rc::new(Cell::new(Duration::from_secs(wall))),
            mon_socks: HashMap::new(),
            mon_out: HashMap::new(),
            table: SessionTable::new(seed ^ 0x5eed),
            msgr_cfg,
            osds: HashMap::new(),
            next_conn: 1000,
            next_tid: 1,
            cmd_replies: HashMap::new(),
            authed: false,
            buf: vec![0u8; 1 << 16],
            log: Vec::new(),
            idle_sleep: Duration::from_millis(1),
            pg_override: None,
            pending: HashMap::new(),
            epoch_seen: 0,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            p.step();
            if p.mc.osdmap().is_some() && p.have_osd_ticket() {
                return Ok(p);
            }
            if Instant::now() > deadline {
                eprintln!(
                    "WARNING TIMEOUT oprobe mon auth/osdmap exceeded 20s (log {:?})",
                    p.log
                );
                return Err(format!(
                    "timeout waiting for mon auth/osdmap (authed={}, map={}, ticket={}); log: {:?}",
                    p.authed,
                    p.mc.osdmap().is_some(),
                    p.have_osd_ticket(),
                    p.log
                ));
            }
        }
    }

    fn now(&self) -> Duration {
        self.t0.elapsed()
    }

    /// Unix wall time with subsecond precision (cephx ticket checks).
    fn wall(&self) -> Duration {
        Duration::from_secs(self.wall0) + self.t0.elapsed()
    }

    fn have_osd_ticket(&self) -> bool {
        let w = self.wall();
        self.mc
            .with_cephx(|c| c.ticket(ENTITY_OSD).is_some_and(|t| t.have_key(w)))
            .unwrap_or(false)
    }

    fn diag(&mut self, s: String) {
        if self.opts.verbose {
            eprintln!("[{:7.3}] {s}", self.now().as_secs_f32());
        }
        self.log.push(s);
    }

    /// The current osdmap.
    pub fn osdmap(&self) -> &osdmap::OsdMap {
        self.mc.osdmap().expect("osdmap present after connect")
    }

    // ------------------------------------------------------------------ I/O pump

    /// One I/O iteration over the mon client and all OSD connections (sleeps 1ms when idle).
    pub fn step(&mut self) {
        let now = self.now();
        #[cfg(feature = "native-read")]
        self.auth_clock.set(self.wall());
        let mut busy = self.step_mon(now);
        busy |= self.step_osds(now);
        if !busy {
            std::thread::sleep(self.idle_sleep);
        }
    }

    fn step_mon(&mut self, now: Duration) -> bool {
        let mut busy = false;
        while let Some(c) = self.mc.poll_io() {
            busy = true;
            match c {
                IoCmd::Dial { conn, target } => {
                    // any family (IPv4 or IPv6 mons, adr 0659)
                    let Some(sa) = target.socket_addr() else {
                        self.mc.on_closed(conn, now);
                        continue;
                    };
                    match TcpStream::connect_timeout(&sa, Duration::from_secs(2)) {
                        Ok(s) => match configure_socket(&s) {
                            Ok(()) => {
                                self.mon_socks.insert(conn, s);
                                self.mc.on_connected(conn, now);
                            }
                            Err(e) => {
                                self.diag(format!("mon socket {sa}: {e}"));
                                self.mc.on_closed(conn, now);
                            }
                        },
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::TimedOut {
                                eprintln!("WARNING TIMEOUT oprobe mon dial exceeded 2s ({sa})");
                            }
                            self.diag(format!("mon dial {sa}: {e}"));
                            self.mc.on_closed(conn, now);
                        }
                    }
                }
                IoCmd::Close { conn } => {
                    self.mon_socks.remove(&conn);
                    self.mon_out.remove(&conn);
                }
            }
        }
        let ids: Vec<u64> = self.mon_socks.keys().copied().collect();
        for id in ids {
            while let Some(s) = self.mon_socks.get_mut(&id) {
                match s.read(&mut self.buf) {
                    Ok(0) => {
                        self.mon_socks.remove(&id);
                        self.mc.on_closed(id, now);
                        break;
                    }
                    Ok(n) => {
                        busy = true;
                        self.mc.on_bytes(id, &self.buf[..n], now);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        self.mon_socks.remove(&id);
                        self.mc.on_closed(id, now);
                        break;
                    }
                }
            }
        }
        for id in self.mc.conn_ids() {
            let fresh = self.mc.poll_output(id);
            let Some(s) = self.mon_socks.get_mut(&id) else {
                continue; // a connection without a socket cannot write; its output is dropped, as before
            };
            if !fresh.is_empty() {
                busy = true;
                self.mon_out.entry(id).or_default().push(fresh);
            }
            let (written, failed) = match self.mon_out.entry(id).or_default().flush(s) {
                Ok(n) => (n, None),
                Err(e) => (0, Some(e)),
            };
            if written > 0 {
                busy = true;
            }
            if let Some(e) = failed {
                self.diag(format!("mon write: {e}"));
                self.mon_socks.remove(&id);
                self.mon_out.remove(&id);
                self.mc.on_closed(id, now);
            }
        }
        if self.mc.next_timer().is_some_and(|d| d <= now) {
            self.mc.on_timer(now);
        }
        while let Some(ev) = self.mc.poll_event() {
            busy = true;
            match ev {
                MonEvent::Authenticated { .. } => {
                    self.authed = true;
                    self.mc.subscribe("osdmap", 0, 0);
                }
                MonEvent::SessionLost(w) => self.diag(format!("mon session lost: {w}")),
                MonEvent::AuthFailed(w) => self.diag(format!("mon auth failed: {w}")),
                MonEvent::CommandReply { tid, r, rs, data } => {
                    self.cmd_replies.insert(tid, (r, rs, data));
                }
                MonEvent::OsdMap { epoch, .. } => self.diag(format!("osdmap epoch {epoch}")),
                MonEvent::Diag(s) => self.diag(format!("monc: {s}")),
                _ => {}
            }
        }
        busy
    }

    fn step_osds(&mut self, now: Duration) -> bool {
        let mut busy = false;
        let ids: Vec<i32> = self.osds.keys().copied().collect();
        for osd in ids {
            let Some(c) = self.osds.get_mut(&osd) else {
                continue;
            };
            // events
            while let Some(ev) = c.conn.poll_event() {
                busy = true;
                match ev {
                    Event::Dial { target } => {
                        let Some(sa) = target.socket_addr() else {
                            c.note_rejection();
                            c.dead = Some("no IP address".into());
                            continue;
                        };
                        match dial_osd(&sa, self.opts.osd_src_port) {
                            Ok(s) => match configure_socket(&s) {
                                Ok(()) => {
                                    c.sock = Some(s);
                                    c.conn.on_connected(now);
                                }
                                Err(e) => {
                                    c.note_transport_loss();
                                    c.dead = Some(format!("socket setup {sa}: {e}"));
                                    c.conn.on_closed(now);
                                }
                            },
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::TimedOut {
                                    eprintln!("WARNING TIMEOUT oprobe osd dial exceeded 2s ({sa})");
                                }
                                c.note_transport_loss();
                                c.dead = Some(format!("dial {sa}: {e}"));
                                c.conn.on_closed(now);
                            }
                        }
                    }
                    Event::Connected(info) => {
                        c.ready = true;
                        c.features = info.features;
                        c.mode = c.conn.mode();
                    }
                    Event::Message(m) => c.inbox.push_back(m),
                    Event::Fault(r) => {
                        c.note_fault(&r);
                        c.dead = Some(format!("fault: {r:?}"));
                        c.sock = None;
                    }
                    Event::Reset | Event::RemoteReset => {
                        c.note_reset();
                        c.dead = Some("session reset".into());
                    }
                    Event::Closed => {
                        c.dead.get_or_insert_with(|| "closed".into());
                        c.sock = None;
                    }
                    Event::KeepaliveAck { .. }
                    | Event::Handoff { .. }
                    | Event::RdmaPrepare
                    | Event::RdmaOffer { .. }
                    | Event::RdmaAnswer { .. }
                    | Event::PlacementControl(_) => {}
                }
            }
            // read
            while let Some(s) = c.sock.as_mut() {
                match s.read(&mut self.buf) {
                    Ok(0) => {
                        c.note_transport_loss();
                        c.sock = None;
                        c.conn.on_closed(now);
                        c.dead.get_or_insert_with(|| "eof".into());
                        break;
                    }
                    Ok(n) => {
                        busy = true;
                        c.conn.on_bytes(&self.buf[..n], now);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        c.note_transport_loss();
                        c.sock = None;
                        c.conn.on_closed(now);
                        c.dead.get_or_insert_with(|| format!("read: {e}"));
                        break;
                    }
                }
            }
            // write (non-blocking; the remainder stays queued in `out`)
            let fresh = c.conn.poll_output();
            if !fresh.is_empty() {
                busy = true;
                if c.sock.is_some() {
                    c.out.push(fresh);
                }
            }
            if let Some(s) = c.sock.as_mut() {
                match c.out.flush(s) {
                    Ok(0) => {}
                    Ok(_) => busy = true,
                    Err(e) => {
                        c.note_transport_loss();
                        c.sock = None;
                        c.conn.on_closed(now);
                        c.dead.get_or_insert_with(|| format!("write failed: {e}"));
                    }
                }
            }
            if c.conn.next_timer().is_some_and(|d| d <= now) {
                c.conn.on_timer(now);
            }
        }
        busy
    }

    /// Pump for `d`.
    pub fn pump_for(&mut self, d: Duration) {
        let end = Instant::now() + d;
        while Instant::now() < end {
            self.step();
        }
    }

    // ------------------------------------------------------------------ mon commands

    /// Run a mon command (JSON); returns (result, status string, output).
    pub fn mon_command(&mut self, json: &str) -> Res<(i32, String, Vec<u8>)> {
        let tid = self.mc.send_command(json, Vec::new());
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            self.step();
            if let Some(r) = self.cmd_replies.remove(&tid) {
                return Ok(r);
            }
            if Instant::now() > end {
                eprintln!("WARNING TIMEOUT oprobe mon command exceeded 30s ({json})");
                return Err(format!("mon command timeout: {json}"));
            }
        }
    }

    /// Wait until the map knows pool `name`; returns its id.
    pub fn wait_pool(&mut self, name: &str, secs: u64) -> Res<i64> {
        let end = Instant::now() + Duration::from_secs(secs);
        loop {
            self.step();
            if let Some(id) = self.osdmap().pool_id_by_name(name) {
                return Ok(id);
            }
            if Instant::now() > end {
                eprintln!("WARNING TIMEOUT oprobe wait_pool exceeded {secs}s (pool {name})");
                return Err(format!("pool {name} not in osdmap"));
            }
        }
    }

    /// Wait until the pool is gone from the map.
    pub fn wait_pool_gone(&mut self, name: &str, secs: u64) -> bool {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            self.step();
            if self.osdmap().pool_id_by_name(name).is_none() {
                return true;
            }
        }
        eprintln!("WARNING TIMEOUT oprobe wait_pool_gone exceeded {secs}s (pool {name})");
        false
    }

    // ------------------------------------------------------------------ placement

    /// Object -> pg -> up/acting/primary under the current map.
    pub fn locate(&self, t: &Target) -> Res<Placement> {
        if let Some(seed) = self.pg_override {
            let m = self.osdmap();
            let pg = PgT::new(t.pool as u64, seed);
            let mp = m.pg_to_up_acting(pg);
            return Ok(Placement {
                epoch: m.epoch,
                raw_pg: pg,
                pg,
                up: mp.up,
                acting: mp.acting,
                primary: mp.acting_primary,
            });
        }
        let m = self.osdmap();
        let raw = m
            .object_to_raw_pg(t.pool, &t.oid, &t.key, &t.nspace, -1)
            .map_err(|e| format!("pool {}: {e:?}", t.pool))?;
        let pg = m
            .object_to_pg(t.pool, &t.oid, &t.key, &t.nspace, -1)
            .map_err(|e| format!("{e:?}"))?;
        let mp = m.pg_to_up_acting(pg);
        Ok(Placement {
            epoch: m.epoch,
            raw_pg: raw,
            pg,
            up: mp.up,
            acting: mp.acting,
            primary: mp.acting_primary,
        })
    }

    // ------------------------------------------------------------------ OSD connections

    /// Create the connection object for `osd` when it is missing or dead (no I/O wait); the pump drives the dial.
    fn start_conn(&mut self, osd: i32) -> Res<()> {
        if let Some(c) = self.osds.get(&osd) {
            if c.dead.is_none() {
                return Ok(());
            }
            self.osds.remove(&osd);
        }
        let addrs = self
            .osdmap()
            .client_addrs
            .get(osd as usize)
            .cloned()
            .filter(|a| !a.0.is_empty())
            .ok_or_else(|| format!("osd.{osd} has no address in the map"))?;
        let target = *addrs
            .v2()
            .ok_or_else(|| format!("osd.{osd} has no v2 address"))?;
        let w = self.wall();
        #[cfg(feature = "native-read")]
        let handler = {
            self.auth_clock.set(w);
            let (gid, ticket) = self
                .mc
                .with_cephx(|c| {
                    let ticket = c.ticket(ENTITY_OSD)?;
                    ticket.have_key(w).then(|| (c.global_id(), ticket.clone()))
                })
                .flatten()
                .ok_or("no valid OSD ticket")?;
            let mode = match self.opts.mode.as_str() {
                "crc" => rustyrados::MessengerMode::Crc,
                "secure" => rustyrados::MessengerMode::Secure,
                "auto" => rustyrados::MessengerMode::PreferSecure,
                _ => return Err("invalid native OSD messenger mode".into()),
            };
            rustyrados::OsdAuth::new(gid, ticket, mode, self.auth_clock.clone())
                .map_err(|e| format!("native OSD auth: {e:?}"))?
        };
        #[cfg(not(feature = "native-read"))]
        let (gid, ticket, key) = self
            .mc
            .with_cephx(|c| {
                let t = c.ticket(ENTITY_OSD)?;
                t.have_key(w)
                    .then(|| (c.global_id(), t.blob().clone(), t.session_key().cloned()))
            })
            .flatten()
            .ok_or("no valid OSD ticket")?;
        #[cfg(not(feature = "native-read"))]
        let key = key.ok_or("no ticket session key")?;
        #[cfg(not(feature = "native-read"))]
        let handler = OsdAuth {
            gid,
            ticket,
            key,
            modes: modes(&self.opts.mode),
            auth: None,
        };
        let id = self.next_conn;
        self.next_conn += 1;
        let conn = Connection::client(
            id,
            self.msgr_cfg.clone(),
            self.table.clone(),
            Box::new(handler),
            EntityName::OSD,
            addrs,
            target,
        );
        self.osds.insert(
            osd,
            OsdConn {
                conn,
                sock: None,
                ready: false,
                features: 0,
                mode: 0,
                dead: None,
                #[cfg(feature = "native-read")]
                failure: None,
                inbox: VecDeque::new(),
                out: OutQueue::default(),
            },
        );
        Ok(())
    }

    /// [`start_conn`](Self::start_conn) plus a blocking, loud wait (10 s) for the connection to become READY.
    fn ensure_conn(&mut self, osd: i32) -> Res<()> {
        self.start_conn(osd)?;
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            self.step();
            let c = self.osds.get(&osd).ok_or("connection vanished")?;
            if c.ready {
                return Ok(());
            }
            if let Some(d) = &c.dead {
                return Err(format!("osd.{osd} connect failed: {d}"));
            }
            if Instant::now() > end {
                eprintln!("WARNING TIMEOUT oprobe osd connect exceeded 10s (osd.{osd})");
                return Err(format!("osd.{osd} connect timeout"));
            }
        }
    }

    /// Negotiated connection mode name to osd (after a connection exists).
    pub fn conn_mode(&self, osd: i32) -> Option<&'static str> {
        self.osds.get(&osd).map(|c| match c.mode {
            CON_MODE_SECURE => "secure",
            CON_MODE_CRC => "crc",
            _ => "?",
        })
    }

    /// Negotiated modes of established OSD connections, for benchmark manifests.
    pub fn connection_modes(&self) -> std::collections::BTreeMap<i32, &'static str> {
        self.osds
            .keys()
            .map(|&osd| (osd, self.conn_mode(osd).unwrap_or("?")))
            .collect()
    }

    fn send(&mut self, osd: i32, m: &ClientMsg, tid: u64) -> Res<()> {
        let c = self.osds.get_mut(&osd).ok_or("no connection")?;
        let (t, v, compat, segs) = m.encode(c.features).map_err(|e| e.to_string())?;
        let msg = msgr2::Message {
            msg_type: t,
            tid,
            version: v,
            compat_version: compat,
            front: segs.front,
            middle: segs.middle,
            data: segs.data,
            ..Default::default()
        };
        if let Some(e) = frame_limit_error(&msg, c.conn.limits()) {
            return Err(e);
        }
        if c.conn.send_message(msg) {
            Ok(())
        } else {
            Err("connection closed".into())
        }
    }

    // ------------------------------------------------------------------ ops

    /// Build the MOSDOp for `msg` against placement `pl` (hash/pgid from the placement).
    pub fn build_op(
        &self,
        t: &Target,
        msg: &ScriptMsg,
        pl: &Placement,
        attempt: u32,
        features: u64,
    ) -> MOSDOp {
        let has_wr = msg.ops.iter().any(|o| o.op & op::MODE_WR != 0);
        let has_rd = msg.ops.iter().any(|o| o.op & op::MODE_RD != 0);
        let mut fl = flag::ONDISK | flag::KNOWN_REDIR | msg.flags;
        if has_wr {
            fl |= flag::WRITE;
        }
        if has_rd {
            fl |= flag::READ;
        }
        if attempt > 0 {
            fl |= flag::RETRY;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        MOSDOp {
            pgid: SpgT {
                pgid: pl.pg,
                shard: ShardId::NO_SHARD,
            },
            hash: pl.raw_pg.seed,
            osdmap_epoch: pl.epoch,
            flags: fl,
            oloc: ObjectLocator {
                pool: t.pool,
                key: t.key.clone(),
                nspace: t.nspace.clone(),
                hash: -1,
            },
            oid: t.oid.clone(),
            ops: msg.ops.clone(),
            snapid: msg.snapid,
            snap_seq: msg.snap_seq,
            snaps: msg.snaps.clone(),
            retry_attempt: attempt as i32,
            mtime: UTime::new(now.as_secs() as u32, now.subsec_nanos()),
            features,
            reassert_version: Eversion::default(),
            ..Default::default()
        }
    }

    /// Execute one compound message. With `force_osd` there is exactly one attempt (no remap, no
    /// EAGAIN retry); otherwise the op follows the acting primary and is resent on EAGAIN, timeouts,
    /// connection loss and map changes.
    pub fn exec(&mut self, t: &Target, msg: &ScriptMsg) -> Res<OpOutcome> {
        let forced = t.force_osd.is_some();
        let max_attempts = if forced { 1 } else { MAX_ATTEMPTS };
        let mut notes: Vec<String> = Vec::new();
        let mut attempt = 0u32;
        loop {
            let pl = self.locate(t)?;
            let osd = t.force_osd.unwrap_or(pl.primary);
            let fin =
                |reply: Option<MOSDOpReply>, note: String, notes: &[String], req_ops| OpOutcome {
                    reply,
                    note: if notes.is_empty() {
                        note
                    } else {
                        format!(
                            "{}{}",
                            notes.join("; "),
                            if note.is_empty() {
                                String::new()
                            } else {
                                format!("; {note}")
                            }
                        )
                    },
                    osd,
                    attempts: attempt + 1,
                    placement: pl.clone(),
                    req_ops,
                };
            if osd < 0 {
                if attempt + 1 >= max_attempts {
                    return Ok(fin(
                        None,
                        "no primary in current map".into(),
                        &notes,
                        msg.ops.clone(),
                    ));
                }
                self.pump_for(Duration::from_millis(500));
                attempt += 1;
                continue;
            }
            if let Err(e) = self.ensure_conn(osd) {
                if attempt + 1 >= max_attempts {
                    return Ok(fin(None, e, &notes, msg.ops.clone()));
                }
                notes.push(e);
                self.pump_for(Duration::from_millis(500));
                attempt += 1;
                continue;
            }
            let feats = self.osds[&osd].features;
            let req = self.build_op(t, msg, &pl, attempt, feats);
            let req_ops = req.ops.clone();
            let tid = self.next_tid;
            self.next_tid += 1;
            self.send(osd, &ClientMsg::Op(req), tid)?;
            let deadline = Instant::now() + self.opts.timeout;
            let mut resend: Option<String> = None;
            let mut got: Option<MOSDOpReply> = None;
            while resend.is_none() && got.is_none() {
                self.step();
                let Some(c) = self.osds.get_mut(&osd) else {
                    resend = Some("connection lost".into());
                    break;
                };
                if let Some(d) = &c.dead {
                    resend = Some(format!("connection lost: {d}"));
                    break;
                }
                let mut acks: Vec<MOSDBackoff> = Vec::new();
                while let Some(inc) = c.inbox.pop_front() {
                    let hdr = inc.header;
                    let segs = segments(inc);
                    match opwire::decode_client(hdr.msg_type, hdr.version, &segs) {
                        Ok(ClientMsg::OpReply(r)) if hdr.tid == tid => {
                            if r.retry_attempt != attempt as i32 && r.retry_attempt != -1 {
                                notes.push(format!("stale reply retry={}", r.retry_attempt));
                            } else {
                                got = Some(r);
                            }
                        }
                        Ok(ClientMsg::Backoff(b)) => {
                            notes.push(format!("backoff op={} id={}", b.op, b.id));
                            if b.op == backoff::BLOCK {
                                acks.push(b);
                            } else if b.op == backoff::UNBLOCK {
                                resend = Some("unblock".into());
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            notes.push(format!("undecodable msg type {} : {e}", hdr.msg_type))
                        }
                    }
                    if hdr.msg_type == messages::ty::OSD_MAP {
                        notes.push("osd sent MOSDMap".into());
                    }
                }
                for mut b in acks {
                    b.op = backoff::ACK_BLOCK;
                    let _ = self.send(osd, &ClientMsg::Backoff(b), 0);
                }
                if got.is_none() && resend.is_none() && Instant::now() > deadline {
                    eprintln!(
                        "WARNING TIMEOUT oprobe osd op exceeded {}s (osd.{osd} forced {forced})",
                        self.opts.timeout.as_secs_f64()
                    );
                    if forced {
                        return Ok(fin(None, "timeout (no reply)".into(), &notes, req_ops));
                    }
                    resend = Some("timeout".into());
                }
            }
            if let Some(r) = got {
                let eagain = r.result == -opwire::errno::EAGAIN;
                if eagain
                    && !forced
                    && msg.flags & flag::FAIL_ON_EAGAIN == 0
                    && attempt + 1 < max_attempts
                {
                    notes.push(format!("EAGAIN from osd.{osd} (epoch {})", r.osdmap_epoch));
                    self.pump_for(Duration::from_millis(500));
                    attempt += 1;
                    continue;
                }
                return Ok(fin(Some(r), String::new(), &notes, req_ops));
            }
            let why = resend.unwrap_or_default();
            if attempt + 1 >= max_attempts || (!self.opts.resend_lost && why != "unblock") {
                return Ok(fin(None, why, &notes, req_ops));
            }
            notes.push(format!("resend ({why})"));
            self.pump_for(Duration::from_millis(300));
            attempt += 1;
        }
    }
}

fn modes(s: &str) -> Vec<u32> {
    match s {
        "crc" => vec![CON_MODE_CRC],
        "secure" => vec![CON_MODE_SECURE],
        _ => vec![CON_MODE_CRC, CON_MODE_SECURE],
    }
}

// ---------------------------------------------------------------------- pipelined ops

/// An op in flight (pipelined API).
#[derive(Debug)]
struct Pending {
    osd: i32,
    target: Target,
    msg: ScriptMsg,
    attempt: u32,
    tag: u64,
    submitted: Instant,
    /// The request reached the messenger; `false` = waiting for a connection that is still being established.
    sent: bool,
}

/// A finished pipelined op.
#[derive(Debug)]
pub struct Done {
    /// Caller's tag from `submit`.
    pub tag: u64,
    /// Wire tid of the last send (0 = synthetic completion); with [`Probe::client_gid`] it names the op in the OSD op traces.
    pub tid: u64,
    /// `None` = no reply; see `err`.
    pub reply: Option<MOSDOpReply>,
    /// Failure text when there is no reply ("timeout", "connection lost: ...").
    pub err: String,
    pub submitted: Instant,
    pub finished: Instant,
}

impl Probe {
    /// Number of pipelined ops in flight.
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// Global id the monitors assigned to this client (0 until authenticated): the client number of its op request ids.
    pub fn client_gid(&self) -> u64 {
        self.mc.global_id()
    }

    /// Send `msg` to the acting primary without waiting (tag is returned in the `Done`). Resends on
    /// EAGAIN, backoff UNBLOCK and primary change; a lost connection or a timeout (`opts.timeout`
    /// since submit) completes the op with an error. A connection that is still being established queues the op:
    /// [`poll`](Self::poll) sends it once the OSD is READY, so one slow/dead OSD never stalls the in-flight ops of the
    /// other connections.
    pub fn submit(&mut self, target: Target, msg: ScriptMsg, tag: u64) -> Res<()> {
        let submitted = Instant::now();
        let pl = self.locate(&target)?;
        if pl.primary < 0 {
            return Err("no primary in current map".into());
        }
        self.start_conn(pl.primary)?;
        let p = Pending {
            osd: pl.primary,
            target,
            msg,
            attempt: 0,
            tag,
            submitted,
            sent: false,
        };
        let tid = self.next_tid;
        self.next_tid += 1;
        self.pending.insert(tid, p);
        Ok(())
    }

    fn send_pending(&mut self, tid: u64, pl: &Placement) -> Res<()> {
        let (osd, req) = {
            let p = self.pending.get(&tid).ok_or("no pending op")?;
            let feats = self.osds.get(&p.osd).ok_or("no connection")?.features;
            (
                p.osd,
                self.build_op(&p.target, &p.msg, pl, p.attempt, feats),
            )
        };
        self.send(osd, &ClientMsg::Op(req), tid)
    }

    /// Hand every queued (not yet sent) op to its OSD once the connection is READY. Never waits: a connection that is
    /// still being established leaves the op queued, a dead one is completed by the lost-connection phase.
    fn flush_unsent(&mut self, out: &mut Vec<Done>) {
        let tids: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| !p.sent)
            .map(|(t, _)| *t)
            .collect();
        for tid in tids {
            let Some(p) = self.pending.get(&tid) else {
                continue;
            };
            let (osd, target) = (p.osd, p.target.clone());
            if !self
                .osds
                .get(&osd)
                .is_some_and(|c| c.ready && c.dead.is_none())
            {
                continue;
            }
            let pl = match self.locate(&target) {
                Ok(pl) if pl.primary == osd => pl,
                Ok(_) => continue, // the epoch phase re-places the op
                Err(e) => {
                    if let Some(p) = self.pending.remove(&tid) {
                        out.push(Done {
                            tag: p.tag,
                            tid,
                            reply: None,
                            err: e,
                            submitted: p.submitted,
                            finished: Instant::now(),
                        });
                    }
                    continue;
                }
            };
            match self.send_pending(tid, &pl) {
                Ok(()) => {
                    if let Some(p) = self.pending.get_mut(&tid) {
                        p.sent = true;
                    }
                }
                Err(e) => {
                    if let Some(p) = self.pending.remove(&tid) {
                        out.push(Done {
                            tag: p.tag,
                            tid,
                            reply: None,
                            err: format!("send: {e}"),
                            submitted: p.submitted,
                            finished: Instant::now(),
                        });
                    }
                }
            }
        }
    }

    /// Re-place and resend a pending op (new attempt). On failure the op is returned as error.
    fn resend_pending(&mut self, tid: u64, why: &str, out: &mut Vec<Done>) {
        let Some(mut p) = self.pending.remove(&tid) else {
            return;
        };
        p.attempt += 1;
        let res = (|| -> Res<()> {
            let pl = self.locate(&p.target)?;
            if pl.primary < 0 {
                return Err("no primary in current map".into());
            }
            p.osd = pl.primary;
            p.sent = false;
            self.start_conn(p.osd)
        })();
        match res {
            Ok(()) if p.attempt <= MAX_ATTEMPTS => {
                self.pending.insert(tid, p);
            }
            Ok(()) => out.push(Done {
                tag: p.tag,
                tid,
                reply: None,
                err: format!("too many resends ({why})"),
                submitted: p.submitted,
                finished: Instant::now(),
            }),
            Err(e) => out.push(Done {
                tag: p.tag,
                tid,
                reply: None,
                err: format!("resend ({why}): {e}"),
                submitted: p.submitted,
                finished: Instant::now(),
            }),
        }
    }

    /// Pump I/O once and return the ops finished meanwhile.
    pub fn poll(&mut self) -> Vec<Done> {
        self.step();
        let mut out: Vec<Done> = Vec::new();
        self.flush_unsent(&mut out);
        let mut resend: BTreeMap<u64, &'static str> = BTreeMap::new();
        let osds: Vec<i32> = self.osds.keys().copied().collect();
        for osd in osds {
            let Some(c) = self.osds.get_mut(&osd) else {
                continue;
            };
            let mut acks: Vec<MOSDBackoff> = Vec::new();
            while let Some(inc) = c.inbox.pop_front() {
                let hdr = inc.header;
                let segs = segments(inc);
                match opwire::decode_client(hdr.msg_type, hdr.version, &segs) {
                    Ok(ClientMsg::OpReply(r)) => {
                        let tid = hdr.tid;
                        let Some(p) = self.pending.get(&tid) else {
                            continue; // late reply of a timed-out / resent op
                        };
                        if p.osd != osd
                            || (r.retry_attempt != p.attempt as i32 && r.retry_attempt != -1)
                        {
                            continue;
                        }
                        if r.result == -opwire::errno::EAGAIN
                            && p.msg.flags & flag::FAIL_ON_EAGAIN == 0
                        {
                            resend_once(&mut resend, tid, "EAGAIN");
                            continue;
                        }
                        let p = self.pending.remove(&tid).expect("checked");
                        out.push(Done {
                            tag: p.tag,
                            tid,
                            reply: Some(r),
                            err: String::new(),
                            submitted: p.submitted,
                            finished: Instant::now(),
                        });
                    }
                    Ok(ClientMsg::Backoff(b)) => {
                        if b.op == backoff::BLOCK {
                            acks.push(b);
                        } else if b.op == backoff::UNBLOCK {
                            for (tid, p) in &self.pending {
                                if p.osd == osd {
                                    resend_once(&mut resend, *tid, "unblock");
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            for mut b in acks {
                b.op = backoff::ACK_BLOCK;
                let _ = self.send(osd, &ClientMsg::Backoff(b), 0);
            }
        }
        // lost connections: fail everything pending on them
        let lost: Vec<(i32, String)> = self
            .osds
            .iter()
            .filter_map(|(o, c)| c.dead.clone().map(|d| (*o, d)))
            .collect();
        for (osd, why) in lost {
            let tids: Vec<u64> = self
                .pending
                .iter()
                .filter(|(_, p)| p.osd == osd)
                .map(|(t, _)| *t)
                .collect();
            for t in tids {
                let p = self.pending.remove(&t).expect("listed");
                out.push(Done {
                    tag: p.tag,
                    tid: t,
                    reply: None,
                    err: format!("connection lost: {why}"),
                    submitted: p.submitted,
                    finished: Instant::now(),
                });
            }
            self.osds.remove(&osd);
        }
        // map change: follow a moved primary
        let epoch = self.osdmap().epoch;
        if epoch != self.epoch_seen {
            self.epoch_seen = epoch;
            let moved: Vec<u64> = self
                .pending
                .iter()
                .filter(|(_, p)| self.locate(&p.target).is_ok_and(|l| l.primary != p.osd))
                .map(|(t, _)| *t)
                .collect();
            for t in moved {
                resend_once(&mut resend, t, "primary moved");
            }
        }
        for (tid, why) in resend {
            self.resend_pending(tid, why, &mut out);
        }
        // timeouts
        let now = Instant::now();
        let late: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| now.duration_since(p.submitted) > self.opts.timeout)
            .map(|(t, _)| *t)
            .collect();
        for t in late {
            let p = self.pending.remove(&t).expect("listed");
            eprintln!(
                "WARNING TIMEOUT oprobe osd op exceeded {}s (tid {t})",
                self.opts.timeout.as_secs_f64()
            );
            out.push(Done {
                tag: p.tag,
                tid: t,
                reply: None,
                err: "timeout".into(),
                submitted: p.submitted,
                finished: now,
            });
        }
        out
    }
}
