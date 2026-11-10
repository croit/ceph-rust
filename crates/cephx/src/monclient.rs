// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! OSD -> mon cephx client (spec sec 5, 8.4, 9, 10.2, 13). Sans-IO: bytes in, bytes out, `now`
//! (unix wall time, nanosecond precision: ticket validity is fractional) passed in.
//!
//! Initial session over msgr2: `start()` -> AUTH_REQUEST payload; `on_reply_more()` ->
//! AUTH_REQUEST_MORE payload; `on_done()` consumes AUTH_DONE. Afterwards `poll()` yields MAuth
//! payloads (renewal, rotating keys) and `on_response()` consumes MAuthReply `result_bl`.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use denc::{Decode, Decoder, Encode, Encoder};

use crate::authorizer::Authorizer;
use crate::challenge::{compute_key, random_u64};
use crate::envelope::{open_string_wrapped, open_wrapped_t};
use crate::error::{Error, Result};
use crate::key::{CryptoKey, Usage};
use crate::modes::CON_MODE_SECURE;
use crate::none::{ENTITY_AUTH, ENTITY_MGR, ENTITY_MON, ENTITY_OSD, EntityName, mon_auth_payload};
use crate::secret::ConnectionSecret;
use crate::ticket::{TicketHandler, decode_ticket_reply};
use crate::types::{
    Authenticate, CEPHX_GET_AUTH_SESSION_KEY, CEPHX_GET_PRINCIPAL_SESSION_KEY,
    CEPHX_GET_ROTATING_KEY, KEY_ROTATE_NUM, RequestHeader, ResponseHeader, RotatingSecrets,
    ServerChallenge, ServiceTicketRequest, TicketBlob,
};

/// `auth_service_ticket_ttl` default in seconds (spec sec 11).
const DEFAULT_SERVICE_TICKET_TTL: u32 = 3600;
/// Upper bound of the rotating refresh cutoff, `min(cutoff, ttl/4)` (spec sec 13).
const ROTATING_CUTOFF_MAX_SECS: u64 = 30;

/// Static configuration.
#[derive(Debug, Clone)]
pub struct MonAuthConfig<I = String> {
    pub name: EntityName<I>,
    /// The entity's own secret key.
    pub key: CryptoKey,
    /// Service bitmask to hold tickets for. OSD default: MON|OSD|MGR|AUTH (0x35).
    pub want: u32,
    /// Fetch rotating service keys (OSD/MGR/MDS yes; pure clients no).
    pub want_rotating: bool,
    /// `auth_service_ticket_ttl` in seconds (rotating refresh cutoff).
    pub service_ticket_ttl: u32,
}

impl MonAuthConfig {
    /// Defaults for an OSD.
    pub fn osd(name: EntityName, key: CryptoKey) -> Self {
        Self {
            name,
            key,
            want: ENTITY_MON | ENTITY_OSD | ENTITY_MGR | ENTITY_AUTH,
            want_rotating: true,
            service_ticket_ttl: DEFAULT_SERVICE_TICKET_TTL,
        }
    }
    /// Move the principal bytes and credential together without rewriting identity.
    pub fn into_bytes(self) -> MonAuthConfig<Vec<u8>> {
        MonAuthConfig {
            name: self.name.into(),
            key: self.key,
            want: self.want,
            want_rotating: self.want_rotating,
            service_ticket_ttl: self.service_ticket_ttl,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    WaitChallenge,
    WaitDone,
    Established,
}

/// A request to send on the established mon session as `MAuth{protocol=2, auth_payload}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonRequest {
    pub request_type: u16,
    pub payload: Vec<u8>,
}

/// Outcome of [`MonAuthClient::on_response`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonReply {
    /// The reply answered the request in flight; its material is installed.
    Installed,
    /// The reply answered no request or a request retired by a wipe or a timeout: nothing was installed, and the
    /// session stays up (a late or stale reply is not an auth failure).
    Ignored,
}

/// One sent request awaiting its reply: its cephx request type and the auth generation it was sent in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Outstanding {
    request_type: u16,
    generation: u64,
}

/// cephx handshake + ticket manager toward the mon. Long-lived: survives mon reconnects
/// (`start()` again) keeping global_id and the AUTH ticket for old-ticket reclaim.
#[derive(Debug, Clone)]
pub struct MonAuthClient {
    cfg: MonAuthConfig<Vec<u8>>,
    global_id: u64,
    state: State,
    server_challenge: Option<u64>,
    tickets: BTreeMap<u32, TicketHandler>,
    connection_secret: Option<ConnectionSecret>,
    rotating: RotatingSecrets,
    /// Request in flight (at most one).
    pending: Option<Outstanding>,
    /// Requests wipes retired while their replies were still on the way, oldest first: their replies belong to older
    /// generations and are never installed. Every wipe retires at most one request; the next session
    /// ([`Self::start`]) empties it, and the mon client re-hunts when a request stays unanswered.
    retired: VecDeque<Outstanding>,
    /// Auth generation: every wipe bumps it, so a reply to a request the wipe retired is told apart from the answer to
    /// its resend.
    generation: u64,
    /// Replies ignored so far because they answered no current request (diagnostics only).
    ignored_replies: u64,
    last_rotating_req: Option<u64>,
}

impl MonAuthClient {
    pub fn new(cfg: MonAuthConfig) -> Self {
        Self::new_bytes(cfg.into_bytes())
    }
    pub fn new_bytes(cfg: MonAuthConfig<Vec<u8>>) -> Self {
        Self::with_global_id_bytes(cfg, 0)
    }
    pub fn with_global_id_bytes(cfg: MonAuthConfig<Vec<u8>>, global_id: u64) -> Self {
        Self {
            cfg,
            global_id,
            state: State::Idle,
            server_challenge: None,
            tickets: BTreeMap::new(),
            connection_secret: None,
            rotating: RotatingSecrets::default(),
            pending: None,
            retired: VecDeque::new(),
            generation: 0,
            ignored_replies: 0,
            last_rotating_req: None,
        }
    }

    // ---- initial handshake (msgr2 AUTH_* frames) ----

    /// AUTH_REQUEST payload (`u8 10 | name | u64 global_id`). Resets handshake state; keeps
    /// global_id and the AUTH ticket.
    pub fn start(&mut self) -> Vec<u8> {
        self.state = State::WaitChallenge;
        self.server_challenge = None;
        self.connection_secret = None;
        // replies of the previous connection cannot arrive on the new one
        self.pending = None;
        self.retired.clear();
        mon_auth_payload(&self.cfg.name, self.global_id)
    }

    /// AUTH_REPLY_MORE (CephXServerChallenge) -> AUTH_REQUEST_MORE payload.
    pub fn on_reply_more(&mut self, payload: &[u8], now: Duration) -> Result<Vec<u8>> {
        if self.state != State::WaitChallenge {
            return Err(Error::Protocol("unexpected AUTH_REPLY_MORE"));
        }
        let c = ServerChallenge::decode(&mut Decoder::new(payload))?;
        self.server_challenge = Some(c.server_challenge);
        // Keep blob + session key for the old_ticket path, but mark as needing renewal.
        if let Some(h) = self.tickets.get_mut(&ENTITY_AUTH) {
            h.invalidate();
        }
        let need = self.need_mask(now);
        self.state = State::WaitDone;
        self.build_authenticate(need)
    }

    /// AUTH_DONE: adopts global_id, installs AUTH + service tickets, extracts connection secret.
    pub fn on_done(
        &mut self,
        global_id: u64,
        con_mode: u32,
        payload: &[u8],
        now: Duration,
    ) -> Result<()> {
        if self.state != State::WaitDone {
            return Err(Error::Protocol("unexpected AUTH_DONE"));
        }
        // only a GET_AUTH_SESSION_KEY reply establishes the session: another (replayed) reply sealed with our key
        // would leave no AUTH session key, i.e. an empty msgr2 signature key
        self.handle_body(payload, now, CEPHX_GET_AUTH_SESSION_KEY)?;
        if con_mode == CON_MODE_SECURE && self.connection_secret.is_none() {
            return Err(Error::Auth("secure mode without connection secret"));
        }
        self.global_id = global_id;
        self.state = State::Established;
        Ok(())
    }

    // ---- post-session (MAuth / MAuthReply) ----

    /// Next request to send on the established session, if any (one in flight at a time).
    /// Call on every mon-client tick and right after (re)authentication / after each reply.
    pub fn poll(&mut self, now: Duration) -> Result<Option<MonRequest>> {
        if self.state != State::Established || self.pending.is_some() {
            return Ok(None);
        }
        let need = self.need_mask(now);
        if need != 0 && need != ENTITY_MGR {
            let (ty, payload) = if need & ENTITY_AUTH != 0 && self.server_challenge.is_some() {
                (CEPHX_GET_AUTH_SESSION_KEY, self.build_authenticate(need)?)
            } else {
                (
                    CEPHX_GET_PRINCIPAL_SESSION_KEY,
                    self.build_principal(need & !ENTITY_AUTH)?,
                )
            };
            self.pending = Some(Outstanding {
                request_type: ty,
                generation: self.generation,
            });
            return Ok(Some(MonRequest {
                request_type: ty,
                payload,
            }));
        }
        // at most one request per second; `!=` keeps refreshing after a backward clock step
        if self.rotating_needed(now) && self.last_rotating_req != Some(now.as_secs()) {
            self.last_rotating_req = Some(now.as_secs());
            self.pending = Some(Outstanding {
                request_type: CEPHX_GET_ROTATING_KEY,
                generation: self.generation,
            });
            let payload = RequestHeader {
                request_type: CEPHX_GET_ROTATING_KEY,
            }
            .encode_to_vec()?;
            return Ok(Some(MonRequest {
                request_type: CEPHX_GET_ROTATING_KEY,
                payload,
            }));
        }
        Ok(None)
    }

    /// MAuthReply: `result`, `global_id`, `result_bl` (starts with CephXResponseHeader).
    ///
    /// The wire carries no request id, so a reply is attributed to the oldest outstanding request whose response type
    /// it carries (a failure reply has no body: the oldest outstanding request). A reply that answers no current
    /// request, or only a request a wipe or timeout retired, is [`MonReply::Ignored`]: nothing is installed and the
    /// session stays up. A late reply to a timed-out request or the reply to a pre-wipe request is normal traffic,
    /// not an auth failure.
    pub fn on_response(
        &mut self,
        result: i32,
        global_id: u64,
        result_bl: &[u8],
        now: Duration,
    ) -> Result<MonReply> {
        if self.state != State::Established {
            return Err(Error::Protocol("response outside session"));
        }
        // a failure reply carries no body: it answers the oldest outstanding request
        let ty = if result < 0 {
            None
        } else {
            ResponseHeader::decode(&mut Decoder::new(result_bl))
                .ok()
                .map(|h| h.request_type)
        };
        let Some(o) = self.take_outstanding(ty) else {
            return Ok(self.ignore());
        };
        if o.generation != self.generation {
            // a reply to a request retired by a wipe or a timeout: nothing of it is installed
            return Ok(self.ignore());
        }
        if result < 0 {
            return Err(Error::Status(result));
        }
        self.handle_body(result_bl, now, o.request_type)?;
        if global_id != 0 && global_id != self.global_id {
            // spec sec 9: different global_id = new session; adopt.
            self.global_id = global_id;
        }
        Ok(MonReply::Installed)
    }

    /// The outstanding request a reply with response type `ty` answers: the oldest request of that type; `None` means
    /// a failure reply without a body, which belongs to the oldest outstanding request.
    fn take_outstanding(&mut self, ty: Option<u16>) -> Option<Outstanding> {
        let matches = |o: &Outstanding| ty.is_none_or(|t| o.request_type == t);
        // replies come in request order: a retired request is older than the one pending
        if let Some(i) = self.retired.iter().position(matches) {
            return self.retired.remove(i);
        }
        if self.pending.as_ref().is_some_and(matches) {
            return self.pending.take();
        }
        None
    }

    fn ignore(&mut self) -> MonReply {
        self.ignored_replies = self.ignored_replies.wrapping_add(1);
        MonReply::Ignored
    }

    /// Replies ignored so far because they answered no current request (diagnostics; never a session error).
    pub fn ignored_replies(&self) -> u64 {
        self.ignored_replies
    }

    /// Replace the entity's own secret (`rotate-key`, spec sec 2.2): every later use of the principal key (the next
    /// AUTH request, ticket replies, rotating-secret replies) takes the new one. Tickets and rotating secrets stay.
    pub fn set_key(&mut self, key: CryptoKey) {
        self.cfg.key = key;
    }

    /// Drop every rotating secret and invalidate every ticket (`wipe-rotating-secrets`, mon auth epoch bump; spec
    /// sec 2.2): the next [`poll`](Self::poll) re-authenticates and re-fetches. Ticket blobs stay for old-ticket reclaim.
    pub fn wipe_secrets_and_tickets(&mut self) {
        self.rotating = RotatingSecrets::default();
        // A reply still in flight carries pre-wipe material: it now answers a retired request, is never installed,
        // and is kept apart so its arrival is not taken for the answer to the resend.
        if let Some(p) = self.pending.take() {
            self.retired.push_back(p);
        }
        self.generation = self.generation.wrapping_add(1);
        for t in self.tickets.values_mut() {
            t.invalidate();
        }
        self.last_rotating_req = None;
    }

    /// `auth_service_ticket_ttl` (seconds, a runtime option): rotating refresh cutoff and clock-skew bound.
    pub fn set_service_ticket_ttl(&mut self, secs: u32) {
        self.cfg.service_ticket_ttl = secs;
    }

    /// Current `auth_service_ticket_ttl` (seconds).
    pub fn service_ticket_ttl(&self) -> u32 {
        self.cfg.service_ticket_ttl
    }

    /// Clock-skew suspicion (spec sec 13): a full rotating set whose `current` key expired more than one
    /// `auth_service_ticket_ttl` ago, i.e. before the mon could have issued it.
    pub fn rotating_clock_skew(&self, now: Duration) -> bool {
        self.cfg.want_rotating
            && self.rotating.secrets.len() >= KEY_ROTATE_NUM
            && self.rotating.current().is_some_and(|(_, k)| {
                u64::from(k.expiration.sec)
                    <= now
                        .as_secs()
                        .saturating_sub(u64::from(self.cfg.service_ticket_ttl))
            })
    }

    // ---- internals ----

    /// Apply a response body that answers request type `expect`; any other type is refused before it changes state.
    fn handle_body(&mut self, body: &[u8], now: Duration, expect: u16) -> Result<()> {
        let mut d = Decoder::new(body);
        let h = ResponseHeader::decode(&mut d)?;
        if h.status < 0 {
            return Err(Error::Status(h.status));
        }
        if h.request_type != expect {
            return Err(Error::Protocol("reply type does not match request"));
        }
        match h.request_type {
            CEPHX_GET_AUTH_SESSION_KEY => self.on_auth_reply(&mut d, now)?,
            CEPHX_GET_PRINCIPAL_SESSION_KEY => {
                for e in decode_ticket_reply(&mut d, self.auth_key()?, None)? {
                    self.install(e, now);
                }
            }
            CEPHX_GET_ROTATING_KEY => {
                let r: RotatingSecrets =
                    open_wrapped_t(&self.cfg.key, Usage::RotatingSecret, &mut d)?;
                self.rotating = r;
            }
            _ => return Err(Error::Protocol("unknown cephx response type")),
        }
        Ok(())
    }

    /// GET_AUTH_SESSION_KEY reply; the connection secret counts only in the initial AUTH_DONE.
    fn on_auth_reply(&mut self, d: &mut Decoder<'_>, now: Duration) -> Result<()> {
        let old = self.tickets.get(&ENTITY_AUTH).and_then(|h| h.session_key());
        let entries = decode_ticket_reply(d, &self.cfg.key, old)?;
        let e = entries
            .into_iter()
            .find(|e| e.service_id == ENTITY_AUTH)
            .ok_or(Error::Protocol("no AUTH ticket in reply"))?;
        let ak = e.session_key.clone();
        self.install(e, now);
        if d.is_empty() {
            return Ok(());
        }
        let cbl = d.bytes()?;
        let extra = if d.is_empty() { &[][..] } else { d.bytes()? };
        if self.state == State::WaitDone && !cbl.is_empty() {
            let s = open_string_wrapped(&ak, Usage::AuthConnectionSecret, &mut Decoder::new(cbl))?;
            self.connection_secret = ConnectionSecret::from_bytes(&s)?;
        }
        if !extra.is_empty() {
            // Undecodable extra tickets are non-fatal (spec sec 15): re-requested later.
            if let Ok(es) = decode_ticket_reply(&mut Decoder::new(extra), &ak, None) {
                for e in es {
                    self.install(e, now);
                }
            }
        }
        Ok(())
    }

    fn install(&mut self, e: crate::ticket::TicketEntry, now: Duration) {
        self.tickets
            .entry(e.service_id)
            .or_insert_with(|| TicketHandler::new(e.service_id))
            .install(e, now);
    }

    fn auth_key(&self) -> Result<&CryptoKey> {
        self.tickets
            .get(&ENTITY_AUTH)
            .and_then(|h| h.session_key())
            .ok_or(Error::Protocol("no AUTH session key"))
    }

    /// Bits of `want` whose ticket is missing or due for renewal.
    pub fn need_mask(&self, now: Duration) -> u32 {
        let mut m = 0;
        for bit in (0..32)
            .map(|i| 1u32 << i)
            .filter(|b| self.cfg.want & b != 0)
        {
            if self.tickets.get(&bit).is_none_or(|h| h.need_key(now)) {
                m |= bit;
            }
        }
        m
    }

    fn build_authenticate(&self, need: u32) -> Result<Vec<u8>> {
        let sc = self
            .server_challenge
            .ok_or(Error::Protocol("no server challenge"))?;
        let cc = random_u64()?;
        let old_ticket = match self.tickets.get(&ENTITY_AUTH) {
            Some(h) if self.global_id != 0 => h.blob().clone(),
            _ => TicketBlob::default(),
        };
        let mut e = Encoder::new();
        RequestHeader {
            request_type: CEPHX_GET_AUTH_SESSION_KEY,
        }
        .encode(&mut e)?;
        Authenticate {
            client_challenge: cc,
            key: compute_key(&self.cfg.key, sc, cc)?,
            old_ticket,
            other_keys: need,
        }
        .encode(&mut e)?;
        Ok(e.into_vec())
    }

    fn build_principal(&self, keys: u32) -> Result<Vec<u8>> {
        let h = self
            .tickets
            .get(&ENTITY_AUTH)
            .ok_or(Error::Protocol("no AUTH ticket"))?;
        let az = Authorizer::new(self.global_id, ENTITY_AUTH, h)?;
        let mut e = Encoder::new();
        RequestHeader {
            request_type: CEPHX_GET_PRINCIPAL_SESSION_KEY,
        }
        .encode(&mut e)?;
        e.raw(az.payload())?;
        ServiceTicketRequest { keys }.encode(&mut e)?;
        Ok(e.into_vec())
    }

    /// Rotating refresh policy (spec sec 13): fewer than 3 keys, or `current` expired past the
    /// cutoff `now - min(30, ttl/4)`.
    pub fn rotating_needed(&self, now: Duration) -> bool {
        if !self.cfg.want_rotating {
            return false;
        }
        if self.rotating.secrets.len() < KEY_ROTATE_NUM {
            return true;
        }
        let cutoff = now.as_secs().saturating_sub(self.cutoff_secs());
        self.rotating
            .current()
            .is_none_or(|(_, k)| u64::from(k.expiration.sec) <= cutoff)
    }

    fn cutoff_secs(&self) -> u64 {
        u64::from(self.cfg.service_ticket_ttl / 4).min(ROTATING_CUTOFF_MAX_SECS)
    }

    // ---- accessors ----

    pub fn global_id(&self) -> u64 {
        self.global_id
    }
    /// AUTH session key = the session key of the mon connection (msgr2 signature key).
    pub fn session_key(&self) -> Option<&CryptoKey> {
        self.auth_key().ok()
    }
    /// Connection secret from the initial AUTH_DONE (SECURE mode only).
    pub fn connection_secret(&self) -> Option<&ConnectionSecret> {
        self.connection_secret.as_ref()
    }
    pub fn ticket(&self, service_id: u32) -> Option<&TicketHandler> {
        self.tickets.get(&service_id)
    }
    pub fn rotating(&self) -> &RotatingSecrets {
        &self.rotating
    }
    /// Build an authorizer toward a peer service (ENTITY_OSD / ENTITY_MGR).
    pub fn authorizer(&self, service_id: u32) -> Result<Authorizer> {
        let h = self
            .tickets
            .get(&service_id)
            .ok_or(Error::Auth("no ticket for service"))?;
        Authorizer::new(self.global_id, service_id, h)
    }
}
