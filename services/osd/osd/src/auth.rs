// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! msgr2 auth adapters for service connections (spec cephx.md 6-7, 13): the server side verifies
//! authorizers against the rotating OSD keys, the client side presents an authorizer built from a
//! held service ticket (mgr, peer OSDs).
use crate::config::ConfigDb;
use cephx::authorizer::Authorizer;
use cephx::modes::{
    AUTH_CEPHX, AUTH_NONE, CON_MODE_CRC, CON_MODE_SECURE, ParsedModes, modes_for_method,
    parse_modes,
};
use cephx::monclient::MonAuthClient;
use cephx::none::{
    AUTH_MODE_AUTHORIZER, AUTH_MODE_MON, ENTITY_MDS, ENTITY_MGR, ENTITY_MON, ENTITY_OSD,
    verify_none,
};
use cephx::{AuthorizerVerifier, Verdict};
use denc::types::EntityName;
use msgr2::auth::{
    AuthClientHandler, AuthError, AuthRequestOut, AuthSecrets, AuthServerHandler, AuthServerStep,
};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// msgr2 connection modes in preference order for peers of the OSD (`ms_cluster_mode`, `ms_service_mode`,
/// `ms_client_mode`, `ms_mon_cluster_mode`; Ceph defaults). Read from the layered config on every change and
/// applied to NEW connections (classic reads them at start only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModePolicy {
    /// Peers that are cluster daemons (osd, mds): `ms_cluster_mode`.
    pub cluster: Vec<u32>,
    /// Peers that are clients, when they dial us: `ms_service_mode`.
    pub service: Vec<u32>,
    /// Peers that are mons or mgrs: `ms_mon_cluster_mode`.
    pub mon: Vec<u32>,
}

impl Default for ModePolicy {
    fn default() -> Self {
        Self {
            cluster: vec![CON_MODE_CRC, CON_MODE_SECURE],
            service: vec![CON_MODE_CRC, CON_MODE_SECURE],
            mon: vec![CON_MODE_SECURE, CON_MODE_CRC],
        }
    }
}

impl ModePolicy {
    /// Build from the layered config; an empty or unparsable value keeps the default. `Vec<String>` = the warnings
    /// for words that are not a mode (warned and skipped, spec cephx 11).
    pub fn from_conf(c: &ConfigDb) -> (Self, Vec<String>) {
        let d = Self::default();
        let mut warn = Vec::new();
        let (cluster, service, mon) = {
            let mut list = |k: &str| {
                let v = c.get(k).map(parse_modes).unwrap_or_default();
                for w in v.unknown {
                    warn.push(mode_warning(k, &w));
                }
                v.modes
            };
            (
                non_empty_or(list("ms_cluster_mode"), d.cluster),
                non_empty_or(list("ms_service_mode"), d.service),
                non_empty_or(list("ms_mon_cluster_mode"), d.mon),
            )
        };
        (
            Self {
                cluster,
                service,
                mon,
            },
            warn,
        )
    }

    /// Modes for a connection with a peer of ENTITY type `peer_type` (same list both when we accept and when we dial).
    pub fn for_peer(&self, peer_type: u8) -> Vec<u32> {
        match u32::from(peer_type) {
            ENTITY_OSD | ENTITY_MDS => self.cluster.clone(),
            ENTITY_MON | ENTITY_MGR => self.mon.clone(),
            _ => self.service.clone(),
        }
    }
}

/// `auth_cluster_required` / `auth_service_required` (auth-none spec 2): methods accepted from, and
/// offered to, the peers of the OSD.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthLists {
    /// Peers of type mon, mgr, mds, osd; also the list toward the mon.
    pub cluster: Vec<u32>,
    /// Every other peer (clients).
    pub service: Vec<u32>,
}

impl Default for AuthLists {
    fn default() -> Self {
        Self {
            cluster: vec![AUTH_CEPHX],
            service: vec![AUTH_CEPHX],
        }
    }
}

/// One option's word list: the methods and the warnings for words that are not usable (`cephx`, `none` are
/// the only methods croit-flashstore-osd implements; an empty result leaves the list empty = nothing allowed).
fn parse_method_list(option: &str, v: &str) -> (Vec<u32>, Vec<String>) {
    let mut methods = Vec::new();
    let mut warn = Vec::new();
    for w in v.split([',', ' ', ';', '\t']).filter(|w| !w.is_empty()) {
        match w {
            "cephx" => methods.push(AUTH_CEPHX),
            "none" => methods.push(AUTH_NONE),
            _ => warn.push(format!(
                "WARNING: unknown auth protocol {w:?} in {option} (cephx and none are supported)"
            )),
        }
    }
    if methods.is_empty() {
        warn.push(format!("WARNING: no auth protocol defined in {option}"));
    }
    (methods, warn)
}

/// Mode list of the OSD's own mon session: `ms_mon_cluster_mode`, as classic picks by local entity type (a non-mon
/// daemon toward mons/mgrs; `ms_mon_client_mode` is the clients' option). Local config only: the session is up before
/// central config arrives. `None` = unset or unparsable (the monc default `secure crc` stays); unknown words are
/// returned for the caller's warning.
pub fn mon_session_modes(local: &[(String, String)]) -> Option<ParsedModes> {
    crate::config::local_get(local, "ms_mon_cluster_mode")
        .map(parse_modes)
        .filter(|p| !p.modes.is_empty())
}

/// Warning line for one word that is not a connection mode (`ms_*_mode`): warn and skip it (cephx spec 11).
pub(crate) fn mode_warning(option: &str, word: &str) -> String {
    format!("WARNING: unknown connection mode {word:?} in {option} (crc and secure are supported)")
}

/// A parsed mode list, or the default when it is empty/unparsable.
fn non_empty_or(v: Vec<u32>, dflt: Vec<u32>) -> Vec<u32> {
    if v.is_empty() { dflt } else { v }
}

impl AuthLists {
    /// Read the lists from the daemon's local config (start-up, before the layered config exists). Returns the lists
    /// and the warnings: bad list syntax, and ONE loud warning when any of the three lists names `none`
    /// (`auth_client_required` counts only when set explicitly: its default is `cephx, none`).
    pub fn from_local(local: &[(String, String)]) -> (Self, Vec<String>) {
        Self::from_get(|k| crate::config::local_get(local, k))
    }

    /// Read the lists from the layered config (local file, mon config db, runtime overrides; the options are runtime
    /// options like classic): the policy for every NEW session after a config change. Warnings as [`Self::from_local`].
    pub fn from_conf(c: &ConfigDb) -> (Self, Vec<String>) {
        Self::from_get(|k| {
            c.get_with_level(k)
                .filter(|(l, _)| *l > crate::config::Level::Default as u8)
                .map(|(_, v)| v)
        })
    }

    fn from_get<'a>(get: impl Fn(&str) -> Option<&'a str>) -> (Self, Vec<String>) {
        let mut warn = Vec::new();
        let mut list = |k: &str| match get(k) {
            Some(v) => {
                let (m, w) = parse_method_list(k, v);
                warn.extend(w);
                Some(m)
            }
            None => None,
        };
        let cluster = list("auth_cluster_required");
        let service = list("auth_service_required");
        let client = list("auth_client_required");
        let none = |l: &Option<Vec<u32>>| l.as_ref().is_some_and(|l| l.contains(&AUTH_NONE));
        if none(&cluster) || none(&service) || none(&client) {
            warn.push(
                "WARNING authentication disabled: auth method none is configured; any peer reaching \
                 the cluster network has full access, frames are crc-only"
                    .to_owned(),
            );
        }
        let d = Self::default();
        (
            Self {
                cluster: cluster.unwrap_or(d.cluster),
                service: service.unwrap_or(d.service),
            },
            warn,
        )
    }

    /// The OSD has no usable cephx key (auth none): cephx leaves the lists (auth-none spec 2.2), with one loud log
    /// line. A list that ends up empty cannot authenticate anything: startup fails (classic: cannot authenticate).
    pub fn without_cephx(mut self, whoami: i32, log: &mut Vec<String>) -> Result<Self, String> {
        log.push(format!(
            "WARNING osd.{whoami} has no cephx key: cephx removed from the auth method lists \
             (cluster {:?}, service {:?} remain)",
            self.cluster
                .iter()
                .filter(|m| **m != AUTH_CEPHX)
                .collect::<Vec<_>>(),
            self.service
                .iter()
                .filter(|m| **m != AUTH_CEPHX)
                .collect::<Vec<_>>()
        ));
        self.cluster.retain(|m| *m != AUTH_CEPHX);
        self.service.retain(|m| *m != AUTH_CEPHX);
        for (name, l) in [
            ("auth_cluster_required", &self.cluster),
            ("auth_service_required", &self.service),
        ] {
            if l.is_empty() {
                return Err(format!(
                    "osd.{whoami} has no cephx key and {name} allows no other method: cannot authenticate \
                     (set the option to none, or provide the OSD keyring)"
                ));
            }
        }
        Ok(self)
    }

    /// Methods for a peer of ENTITY type `peer_type` (auth-none spec 2.1).
    pub fn for_peer(&self, peer_type: u8) -> &[u32] {
        match u32::from(peer_type) {
            ENTITY_MON | ENTITY_MGR | ENTITY_MDS | ENTITY_OSD => &self.cluster,
            _ => &self.service,
        }
    }
}

/// Shared snapshot of the cephx state (tickets + rotating keys), refreshed by the OSD from the
/// MonClient whenever keys change, plus the connection-mode policy, the method lists and the method
/// the mon session negotiated.
#[derive(Clone, Debug, Default)]
pub struct KeyStore {
    state: Rc<RefCell<Option<MonAuthClient>>>,
    modes: Rc<RefCell<ModePolicy>>,
    lists: Rc<RefCell<AuthLists>>,
    have_key: Rc<Cell<bool>>,
    /// The NONE authorizer payload of this daemon, present iff the mon session runs method NONE: the
    /// authorizer factory of every later peer connection (auth-none spec 5.1).
    none_authorizer: Rc<RefCell<Option<Vec<u8>>>>,
}

impl KeyStore {
    /// Replace the snapshot.
    pub fn set(&self, c: MonAuthClient) {
        *self.state.borrow_mut() = Some(c);
    }
    /// Apply `ms_*_mode` from the config (cheap; called on every config refresh). `Some(log)` when the policy
    /// changed: the warnings for words that are not a mode (they are skipped, spec cephx 11).
    pub fn set_modes(&self, c: &ConfigDb) -> Option<Vec<String>> {
        let (p, log) = ModePolicy::from_conf(c);
        if *self.modes.borrow() == p {
            return None;
        }
        *self.modes.borrow_mut() = p;
        Some(log)
    }
    /// Current mode policy.
    pub fn modes(&self) -> ModePolicy {
        self.modes.borrow().clone()
    }
    /// Set the method lists (start-up).
    pub fn set_lists(&self, l: AuthLists) {
        *self.lists.borrow_mut() = l;
    }
    /// Whether the daemon has a usable cephx key (set once at start; without one cephx never enters the lists).
    pub fn set_have_key(&self, k: bool) {
        self.have_key.set(k);
    }
    /// Recompute the method lists from the layered config (classic re-reads them on every config change; new
    /// sessions use the new lists, established ones keep theirs). `Some(log lines)` when the lists changed: the
    /// change itself, the list warnings, and an ERROR when a list ends up empty (every new peer is then refused).
    pub fn refresh_lists(&self, c: &ConfigDb, whoami: i32) -> Option<Vec<String>> {
        let (mut l, mut log) = AuthLists::from_conf(c);
        if !self.have_key.get() {
            l.cluster.retain(|m| *m != AUTH_CEPHX);
            l.service.retain(|m| *m != AUTH_CEPHX);
        }
        if *self.lists.borrow() == l {
            return None;
        }
        log.insert(
            0,
            format!(
                "osd.{whoami}: auth method lists changed for new sessions: cluster {:?} -> {:?}, service {:?} -> {:?} \
                 (1 = none, 2 = cephx)",
                self.lists.borrow().cluster,
                l.cluster,
                self.lists.borrow().service,
                l.service
            ),
        );
        for (name, v) in [
            ("auth_cluster_required", &l.cluster),
            ("auth_service_required", &l.service),
        ] {
            if v.is_empty() {
                log.push(format!(
                    "ERROR osd.{whoami}: {name} leaves no usable auth method{}: every new peer of that class is refused",
                    if self.have_key.get() { "" } else { " (no cephx key)" }
                ));
            }
        }
        *self.lists.borrow_mut() = l;
        Some(log)
    }
    /// Current method lists.
    pub fn lists(&self) -> AuthLists {
        self.lists.borrow().clone()
    }
    /// Record the mon session's method: `Some(authorizer payload)` for NONE, `None` for cephx.
    pub fn set_none_authorizer(&self, payload: Option<Vec<u8>>) {
        *self.none_authorizer.borrow_mut() = payload;
    }
    /// The NONE authorizer payload when the mon session runs method NONE.
    pub fn none_authorizer(&self) -> Option<Vec<u8>> {
        self.none_authorizer.borrow().clone()
    }
    /// Service keys ready: rotating secrets known, or the mon session runs NONE (no keys exist).
    pub fn have_rotating(&self) -> bool {
        self.none_authorizer.borrow().is_some()
            || self
                .state
                .borrow()
                .as_ref()
                .is_some_and(|c| !c.rotating().secrets.is_empty())
    }
}

/// What the server side learned about an authenticated peer.
#[derive(Clone, Debug, Default)]
pub struct PeerAuth {
    /// Cap text from the ticket (`mon 'allow *'`...), if any.
    pub caps: Option<String>,
    /// Authenticated entity as text (`client.admin`).
    pub entity: String,
}

/// Server-side handler: cephx authorizers and NONE authorizers, as far as the method lists allow.
#[derive(Debug)]
pub struct DaemonAuthServer {
    keys: KeyStore,
    service: u32,
    verifier: Option<AuthorizerVerifier>,
    out: Rc<RefCell<PeerAuth>>,
}

impl DaemonAuthServer {
    /// `service` = our entity type bit (OSD = 4). `out` receives caps/name on success.
    pub fn new(keys: KeyStore, service: u32, out: Rc<RefCell<PeerAuth>>) -> Self {
        Self {
            keys,
            service,
            verifier: None,
            out,
        }
    }
}

/// Caps of a NONE peer: all pools, namespaces and classes (auth-none spec 6).
const ALLOW_ALL: &str = "allow *";

impl DaemonAuthServer {
    /// Method NONE (auth-none spec 4): a single request, no challenge. Hostile or short payloads are
    /// answered with -EACCES, never a panic.
    fn none_step(&mut self, more: bool, mode: u32, payload: &[u8]) -> AuthServerStep {
        const EACCES: i32 = -13;
        if more || mode != CON_MODE_CRC {
            return AuthServerStep::Reject(EACCES);
        }
        // payload byte 0: 1..9 authorizer; the mon handshake (10..19) is not ours, nothing else is valid
        match payload.first() {
            Some(b) if (AUTH_MODE_AUTHORIZER..AUTH_MODE_MON).contains(b) => {}
            _ => return AuthServerStep::Reject(EACCES),
        }
        let Ok(peer) = verify_none(payload) else {
            return AuthServerStep::Reject(EACCES);
        };
        let Ok(ty) = u8::try_from(peer.name.ty) else {
            return AuthServerStep::Reject(EACCES);
        };
        *self.out.borrow_mut() = PeerAuth {
            caps: Some(ALLOW_ALL.to_owned()),
            entity: peer.name.to_string(),
        };
        AuthServerStep::Done {
            reply: Vec::new(),
            global_id: peer.global_id,
            peer_name: Some(EntityName::new(
                ty,
                peer.name.id.parse::<i64>().unwrap_or(-1),
            )),
            secrets: AuthSecrets::default(),
        }
    }
}

impl AuthServerHandler for DaemonAuthServer {
    fn supported_methods(&self, peer_type: u8) -> Vec<u32> {
        self.keys.lists.borrow().for_peer(peer_type).to_vec()
    }
    fn supported_modes(&self, peer_type: u8, method: u32) -> Vec<u32> {
        modes_for_method(&self.keys.modes().for_peer(peer_type), method)
    }
    fn handle_auth_request(
        &mut self,
        _peer_type: u8,
        more: bool,
        method: u32,
        mode: u32,
        payload: &[u8],
    ) -> AuthServerStep {
        if method == AUTH_NONE {
            return self.none_step(more, mode, payload);
        }
        if method != AUTH_CEPHX {
            return AuthServerStep::Reject(msgr2::auth::EOPNOTSUPP);
        }
        if !more || self.verifier.is_none() {
            self.verifier = Some(AuthorizerVerifier::new(
                self.service,
                mode == CON_MODE_SECURE,
            ));
        }
        let rot = match self.keys.state.borrow().as_ref() {
            Some(c) => c.rotating().clone(),
            None => return AuthServerStep::Busy,
        };
        let Some(v) = self.verifier.as_mut() else {
            return AuthServerStep::Reject(-13);
        };
        match v.verify(payload, &rot) {
            Ok(Verdict::More(ct)) => AuthServerStep::More(ct),
            Ok(Verdict::Done(p)) => {
                *self.out.borrow_mut() = PeerAuth {
                    caps: p.caps_text.clone(),
                    entity: p.name.to_string(),
                };
                let ty = p.name.ty as u8;
                let num = core::str::from_utf8(&p.name.id)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(-1);
                AuthServerStep::Done {
                    reply: p.reply.clone(),
                    global_id: p.global_id,
                    peer_name: Some(EntityName::new(ty, num)),
                    secrets: AuthSecrets {
                        session_key: p.session_key.secret().to_vec(),
                        connection_secret: p
                            .connection_secret
                            .as_ref()
                            .map(|c| c.as_bytes().to_vec())
                            .unwrap_or_default(),
                    },
                }
            }
            Err(_) => AuthServerStep::Reject(-13),
        }
    }
}

/// Client-side handler: builds a fresh authorizer for `service` on every (re)start. The method is the one
/// the mon session negotiated: a NONE authorizer after a NONE mon session, else a cephx authorizer.
#[derive(Debug)]
pub struct DaemonAuthClient {
    keys: KeyStore,
    auth: Option<Authorizer>,
    none: bool,
}

impl DaemonAuthClient {
    /// New handler.
    pub fn new(keys: KeyStore) -> Self {
        Self {
            keys,
            auth: None,
            none: false,
        }
    }
}

fn svc(peer_type: u8) -> u32 {
    u32::from(peer_type)
}

impl AuthClientHandler for DaemonAuthClient {
    fn get_auth_request(&mut self, peer_type: u8) -> Result<AuthRequestOut, AuthError> {
        self.none = false;
        if let Some(payload) = self.keys.none_authorizer() {
            let preferred_modes =
                modes_for_method(&self.keys.modes().for_peer(peer_type), AUTH_NONE);
            if preferred_modes.is_empty() {
                return Err(AuthError("none: configured modes exclude crc".into()));
            }
            self.none = true;
            return Ok(AuthRequestOut {
                method: AUTH_NONE,
                preferred_modes,
                payload,
            });
        }
        let a = self
            .keys
            .state
            .borrow()
            .as_ref()
            .ok_or_else(|| AuthError("no cephx state".into()))?
            .authorizer(svc(peer_type))
            .map_err(|e| AuthError(format!("authorizer: {e:?}")))?;
        let p = a.payload().to_vec();
        self.auth = Some(a);
        Ok(AuthRequestOut {
            method: AUTH_CEPHX,
            preferred_modes: self.keys.modes().for_peer(peer_type),
            payload: p,
        })
    }
    fn handle_auth_reply_more(&mut self, payload: &[u8]) -> Result<Vec<u8>, AuthError> {
        if self.none {
            return Err(AuthError("none: unexpected AUTH_REPLY_MORE".into()));
        }
        let a = self
            .auth
            .as_mut()
            .ok_or_else(|| AuthError("no authorizer".into()))?;
        a.on_reply_more(payload)
            .map(<[u8]>::to_vec)
            .map_err(|e| AuthError(format!("authorizer reply_more: {e:?}")))
    }
    fn handle_auth_done(
        &mut self,
        _global_id: u64,
        mode: u32,
        payload: &[u8],
    ) -> Result<AuthSecrets, AuthError> {
        if self.none {
            // the reply payload is ignored; crc is the only mode of NONE (no secret exists for secure)
            return if mode == CON_MODE_CRC {
                Ok(AuthSecrets::default())
            } else {
                Err(AuthError("none: AUTH_DONE mode is not crc".into()))
            };
        }
        let a = self
            .auth
            .as_mut()
            .ok_or_else(|| AuthError("no authorizer".into()))?;
        a.on_done(payload)
            .map_err(|e| AuthError(format!("authorizer done: {e:?}")))?;
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
        _allowed_methods: &[u32],
        _allowed_modes: &[u32],
    ) -> Result<(), AuthError> {
        Err(AuthError(format!(
            "peer rejected auth method {method} ({result})"
        )))
    }
}

#[cfg(test)]
mod mode_tests {
    use super::*;
    use crate::config::Level;

    #[test]
    fn defaults_follow_ceph() {
        let p = ModePolicy::default();
        assert_eq!(
            p.for_peer(ENTITY_OSD as u8),
            [CON_MODE_CRC, CON_MODE_SECURE]
        );
        assert_eq!(p.for_peer(8), [CON_MODE_CRC, CON_MODE_SECURE]);
        assert_eq!(
            p.for_peer(ENTITY_MON as u8),
            [CON_MODE_SECURE, CON_MODE_CRC]
        );
    }

    #[test]
    fn config_overrides_and_garbage_keeps_default() {
        let mut c = ConfigDb::default();
        c.set(Level::Mon, "ms_cluster_mode", "secure").unwrap();
        c.set(Level::Mon, "ms_service_mode", "secure crc").unwrap();
        c.set(Level::Mon, "ms_mon_cluster_mode", "bogus").unwrap();
        let (p, warn) = ModePolicy::from_conf(&c);
        assert_eq!(
            warn,
            [mode_warning("ms_mon_cluster_mode", "bogus")],
            "a word that is not a mode is warned"
        );
        assert_eq!(p.for_peer(ENTITY_OSD as u8), [CON_MODE_SECURE]);
        // mgr peers follow ms_mon_cluster_mode (here the unparsable default)
        assert_eq!(
            p.for_peer(ENTITY_MGR as u8),
            [CON_MODE_SECURE, CON_MODE_CRC]
        );
        assert_eq!(p.for_peer(8), [CON_MODE_SECURE, CON_MODE_CRC]);
        assert_eq!(
            p.for_peer(ENTITY_MON as u8),
            [CON_MODE_SECURE, CON_MODE_CRC]
        );
    }

    #[test]
    fn server_offers_only_the_configured_modes() {
        let k = KeyStore::default();
        let s = DaemonAuthServer::new(k.clone(), 4, Rc::new(RefCell::new(PeerAuth::default())));
        assert_eq!(
            s.supported_modes(8, AUTH_CEPHX),
            [CON_MODE_CRC, CON_MODE_SECURE]
        );
        let mut c = ConfigDb::default();
        c.set(Level::Mon, "ms_service_mode", "secure").unwrap();
        let _ = k.set_modes(&c);
        assert_eq!(s.supported_modes(8, AUTH_CEPHX), [CON_MODE_SECURE]);
        assert_eq!(
            s.supported_modes(4, AUTH_CEPHX),
            [CON_MODE_CRC, CON_MODE_SECURE]
        );
    }

    /// A typo in `ms_*_mode` shrinks the offered mode list: the skipped word is reported on the
    /// change instead of disappearing silently (cephx spec 11).
    #[test]
    fn unknown_mode_words_are_reported_on_a_policy_change() {
        let k = KeyStore::default();
        let mut c = ConfigDb::default();
        c.set(Level::Override, "ms_cluster_mode", "secrue crc")
            .unwrap();
        let log = k.set_modes(&c).expect("the policy changed");
        assert_eq!(log, [mode_warning("ms_cluster_mode", "secrue")]);
        assert_eq!(k.modes().cluster, [CON_MODE_CRC]);
        // the same policy again: no repeated warning
        assert!(k.set_modes(&c).is_none());
    }

    #[test]
    fn keystore_applies_runtime_change() {
        let k = KeyStore::default();
        let mut c = ConfigDb::default();
        assert_eq!(k.modes().cluster, [CON_MODE_CRC, CON_MODE_SECURE]);
        c.set(Level::Override, "ms_cluster_mode", "crc").unwrap();
        let _ = k.set_modes(&c);
        assert_eq!(k.modes().cluster, [CON_MODE_CRC]);
        c.unset(Level::Override, "ms_cluster_mode");
        let _ = k.set_modes(&c);
        assert_eq!(k.modes().cluster, [CON_MODE_CRC, CON_MODE_SECURE]);
    }
}

#[cfg(test)]
mod none_tests {
    use super::*;
    use crate::config::Level;
    use cephx::none::{EntityName as AuthName, none_authorizer};
    use denc::types::{EntityAddr, EntityAddrVec};
    use msgr2::{Connection, Event, FaultReason, PolicyTable, SessionTable};
    use std::time::Duration;

    const T0: Duration = Duration::ZERO;

    fn local(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn lists(cluster: &[u32], service: &[u32]) -> KeyStore {
        let k = KeyStore::default();
        k.set_lists(AuthLists {
            cluster: cluster.to_vec(),
            service: service.to_vec(),
        });
        k
    }

    fn server(k: &KeyStore) -> (DaemonAuthServer, Rc<RefCell<PeerAuth>>) {
        let out = Rc::new(RefCell::new(PeerAuth::default()));
        (DaemonAuthServer::new(k.clone(), 4, out.clone()), out)
    }

    fn payload(name: &str, gid: u64) -> Vec<u8> {
        none_authorizer(&AuthName::parse(name).unwrap(), gid)
    }

    fn req(s: &mut DaemonAuthServer, peer: u8, method: u32, mode: u32, p: &[u8]) -> AuthServerStep {
        s.handle_auth_request(peer, false, method, mode, p)
    }

    #[test]
    fn lists_default_to_cephx_and_warn_only_for_none() {
        let (l, w) = AuthLists::from_local(&[]);
        assert_eq!(l, AuthLists::default());
        assert!(w.is_empty(), "{w:?}");
        // the default client list `cephx, none` is not the operator's choice: no warning unless set
        let (_, w) = AuthLists::from_local(&local(&[("auth_client_required", "cephx")]));
        assert!(w.is_empty(), "{w:?}");
        let (l, w) = AuthLists::from_local(&local(&[
            ("auth_cluster_required", "none"),
            ("auth_service_required", "cephx, none"),
        ]));
        assert_eq!(
            (l.cluster, l.service),
            (vec![AUTH_NONE], vec![AUTH_CEPHX, AUTH_NONE])
        );
        assert_eq!(
            w.iter()
                .filter(|w| w.contains("authentication disabled"))
                .count(),
            1
        );
        let (_, w) = AuthLists::from_local(&local(&[("auth_client_required", "none")]));
        assert_eq!(w.len(), 1, "{w:?}");
    }

    /// The lists follow the layered config (file > mon db; runtime overrides on top) for new sessions; a keyless
    /// daemon never gets cephx back; an unchanged config logs nothing.
    #[test]
    fn lists_refresh_from_the_layered_config() {
        use std::collections::BTreeMap;
        let k = lists(&[AUTH_CEPHX], &[AUTH_CEPHX]);
        k.set_have_key(true);
        let mut c = ConfigDb::default();
        assert!(k.refresh_lists(&c, 3).is_none(), "defaults = start lists");
        let mon = BTreeMap::from([("auth_service_required".to_owned(), "cephx, none".to_owned())]);
        c.apply_mon(&mon);
        let log = k.refresh_lists(&c, 3).expect("changed");
        assert!(log[0].contains("auth method lists changed"), "{log:?}");
        assert!(
            log.iter().any(|l| l.contains("authentication disabled")),
            "{log:?}"
        );
        assert_eq!(k.lists().service, [AUTH_CEPHX, AUTH_NONE]);
        assert!(k.refresh_lists(&c, 3).is_none());
        // the local file beats the mon db; a runtime override beats both
        c.set(Level::File, "auth_service_required", "cephx")
            .unwrap();
        k.refresh_lists(&c, 3).expect("file wins");
        assert_eq!(k.lists().service, [AUTH_CEPHX]);
        c.set(Level::Override, "auth_cluster_required", "none")
            .unwrap();
        k.refresh_lists(&c, 3).expect("override");
        assert_eq!(k.lists().cluster, [AUTH_NONE]);
        // keyless: cephx stays out; a list left empty is an ERROR line, the peers of that class are refused
        let k = lists(&[AUTH_NONE], &[AUTH_NONE]);
        k.set_have_key(false);
        let mut c = ConfigDb::default();
        c.set(Level::Override, "auth_cluster_required", "cephx")
            .unwrap();
        c.set(Level::Override, "auth_service_required", "cephx, none")
            .unwrap();
        let log = k.refresh_lists(&c, 3).expect("changed");
        assert_eq!(
            (k.lists().cluster, k.lists().service),
            (vec![], vec![AUTH_NONE])
        );
        assert!(
            log.iter()
                .any(|l| l.starts_with("ERROR") && l.contains("auth_cluster_required")),
            "{log:?}"
        );
    }

    #[test]
    fn list_syntax_warnings() {
        let (l, w) = AuthLists::from_local(&local(&[
            ("auth_cluster_required", "cephx;bogus none"),
            ("auth_service_required", "gss"),
        ]));
        assert_eq!(l.cluster, [AUTH_CEPHX, AUTH_NONE]);
        assert!(l.service.is_empty());
        assert!(
            w.iter()
                .any(|w| w.contains("unknown auth protocol \"bogus\""))
        );
        assert!(
            w.iter()
                .any(|w| w.contains("unknown auth protocol \"gss\""))
        );
        assert!(
            w.iter()
                .any(|w| w.contains("no auth protocol defined in auth_service_required"))
        );
    }

    #[test]
    fn lists_select_by_peer_type() {
        let l = AuthLists {
            cluster: vec![AUTH_NONE],
            service: vec![AUTH_CEPHX],
        };
        for t in [ENTITY_MON, ENTITY_MGR, ENTITY_MDS, ENTITY_OSD] {
            assert_eq!(l.for_peer(t as u8), [AUTH_NONE]);
        }
        assert_eq!(l.for_peer(8), [AUTH_CEPHX]);
    }

    #[test]
    fn mgr_peers_use_the_mon_mode_list() {
        let p = ModePolicy::default();
        assert_eq!(p.for_peer(ENTITY_MGR as u8), p.mon);
    }

    #[test]
    fn server_modes_for_none_are_crc_only() {
        let k = lists(&[AUTH_NONE], &[AUTH_NONE]);
        let (s, _) = server(&k);
        assert_eq!(s.supported_modes(4, AUTH_NONE), [CON_MODE_CRC]);
        assert_eq!(s.supported_modes(1, AUTH_NONE), [CON_MODE_CRC]);
        assert_eq!(
            s.supported_modes(1, AUTH_CEPHX),
            [CON_MODE_SECURE, CON_MODE_CRC]
        );
        let mut c = ConfigDb::default();
        c.set(Level::Mon, "ms_service_mode", "secure").unwrap();
        let _ = k.set_modes(&c);
        assert!(s.supported_modes(8, AUTH_NONE).is_empty());
    }

    #[test]
    fn server_accepts_none_authorizer_with_allow_all() {
        let k = lists(&[AUTH_NONE], &[AUTH_NONE]);
        let (mut s, out) = server(&k);
        let r = req(
            &mut s,
            8,
            AUTH_NONE,
            CON_MODE_CRC,
            &payload("client.admin", 0x1234),
        );
        let AuthServerStep::Done {
            reply,
            global_id,
            peer_name,
            secrets,
        } = r
        else {
            panic!("{r:?}");
        };
        assert!(
            reply.is_empty()
                && secrets.session_key.is_empty()
                && secrets.connection_secret.is_empty()
        );
        assert_eq!(global_id, 0x1234);
        // `admin` has no numeric id
        assert_eq!(peer_name, Some(EntityName::new(8, -1)));
        let p = out.borrow();
        assert_eq!(
            (p.caps.as_deref(), p.entity.as_str()),
            (Some("allow *"), "client.admin")
        );
        drop(p);
        let r = req(&mut s, 4, AUTH_NONE, CON_MODE_CRC, &payload("osd.7", 0));
        assert!(
            matches!(r, AuthServerStep::Done { global_id: 0, peer_name: Some(n), .. } if n == EntityName::osd(7))
        );
    }

    #[test]
    fn server_rejects_hostile_payloads_with_eacces() {
        let k = lists(&[AUTH_NONE], &[AUTH_NONE]);
        let (mut s, _) = server(&k);
        let good = payload("client.admin", 5);
        let eacces = AuthServerStep::Reject(-13);
        assert_eq!(req(&mut s, 8, AUTH_NONE, CON_MODE_CRC, &[]), eacces);
        for n in 1..good.len() {
            assert_eq!(
                req(&mut s, 8, AUTH_NONE, CON_MODE_CRC, &good[..n]),
                eacces,
                "len {n}"
            );
        }
        // the mon-handshake variant and out-of-range first bytes
        let mon = AuthName::parse("osd.3").unwrap().mon_auth_payload(0);
        assert_eq!(req(&mut s, 4, AUTH_NONE, CON_MODE_CRC, &mon), eacces);
        for b in [0u8, 10, 19, 20, 255] {
            let mut p = good.clone();
            p[0] = b;
            assert_eq!(
                req(&mut s, 8, AUTH_NONE, CON_MODE_CRC, &p),
                eacces,
                "byte {b}"
            );
        }
        // entity type outside u8
        let mut p = good.clone();
        p[1..5].copy_from_slice(&0x100u32.to_le_bytes());
        assert_eq!(req(&mut s, 8, AUTH_NONE, CON_MODE_CRC, &p), eacces);
        // no AUTH_REQUEST_MORE round exists for NONE, and secure mode is impossible
        assert_eq!(
            s.handle_auth_request(8, true, AUTH_NONE, CON_MODE_CRC, &good),
            eacces
        );
        assert_eq!(req(&mut s, 8, AUTH_NONE, CON_MODE_SECURE, &good), eacces);
        assert_eq!(
            req(&mut s, 8, 99, CON_MODE_CRC, &good),
            AuthServerStep::Reject(msgr2::auth::EOPNOTSUPP)
        );
    }

    #[test]
    fn client_builds_the_none_authorizer_of_the_mon_session() {
        let k = lists(&[AUTH_NONE], &[AUTH_NONE]);
        let want = payload("osd.3", 0x1003);
        k.set_none_authorizer(Some(want.clone()));
        let mut c = DaemonAuthClient::new(k.clone());
        let r = c.get_auth_request(ENTITY_OSD as u8).unwrap();
        assert_eq!(
            (r.method, r.preferred_modes, r.payload),
            (AUTH_NONE, vec![CON_MODE_CRC], want)
        );
        assert!(c.handle_auth_reply_more(&[1]).is_err());
        // AUTH_DONE: any payload, crc only
        let sec = c.handle_auth_done(1, CON_MODE_CRC, b"ignored").unwrap();
        assert!(sec.session_key.is_empty() && sec.connection_secret.is_empty());
        assert!(c.handle_auth_done(1, CON_MODE_SECURE, &[]).is_err());
        // BAD_METHOD toward a non-mon peer is a failure, no other method is tried
        assert!(
            c.handle_auth_bad_method(AUTH_NONE, -95, &[AUTH_CEPHX], &[CON_MODE_CRC])
                .is_err()
        );
        // secure-only mode list: local failure, nothing is sent
        let mut m = ConfigDb::default();
        m.set(Level::Mon, "ms_cluster_mode", "secure").unwrap();
        let _ = k.set_modes(&m);
        assert!(c.get_auth_request(ENTITY_OSD as u8).is_err());
        // a cephx mon session builds no NONE authorizer
        k.set_none_authorizer(None);
        assert!(!k.have_rotating());
    }

    #[test]
    fn none_session_needs_no_rotating_keys() {
        let k = KeyStore::default();
        assert!(!k.have_rotating());
        k.set_none_authorizer(Some(payload("osd.3", 1)));
        assert!(k.have_rotating());
    }

    /// Handshake harness: our client handler against our server handler over in-memory connections.
    fn handshake(
        client: Box<dyn AuthClientHandler>,
        server: Box<dyn AuthServerHandler>,
        client_name: EntityName,
        server_ty: u8,
    ) -> (Vec<Event>, Vec<Event>) {
        let ca = EntityAddrVec::single(EntityAddr::v4(2, 1, [10, 0, 0, 1], 6800));
        let sa = EntityAddrVec::single(EntityAddr::v4(2, 2, [10, 0, 0, 2], 6800));
        let ccfg = msgr2::Config::new(client_name, ca, PolicyTable::osd_cluster());
        let scfg = msgr2::Config::new(
            EntityName::new(server_ty, 2),
            sa.clone(),
            PolicyTable::osd_cluster(),
        );
        let mut c = Connection::client(
            1,
            ccfg,
            SessionTable::new(11),
            client,
            server_ty,
            sa.clone(),
            sa.0[0],
        );
        while c.poll_event().is_some() {}
        c.on_connected(T0);
        let mut s = Connection::server(
            2,
            scfg,
            SessionTable::new(22),
            server,
            EntityAddr::v4(2, 0, [10, 0, 0, 1], 40000),
            T0,
        );
        for _ in 0..1000 {
            let a = c.poll_output();
            let b = s.poll_output();
            if a.is_empty() && b.is_empty() {
                break;
            }
            s.on_bytes(&a, T0);
            c.on_bytes(&b, T0);
        }
        let ev = |c: &mut Connection| std::iter::from_fn(|| c.poll_event()).collect::<Vec<_>>();
        (ev(&mut c), ev(&mut s))
    }

    /// AUTH_BAD_METHOD answers seen: (method, result, allowed methods, allowed modes).
    type Seen = Rc<RefCell<Vec<(u32, i32, Vec<u32>, Vec<u32>)>>>;

    /// Wraps a client handler and records the AUTH_BAD_METHOD answer.
    #[derive(Debug)]
    struct Recording(DaemonAuthClient, Seen);
    impl AuthClientHandler for Recording {
        fn get_auth_request(&mut self, t: u8) -> Result<AuthRequestOut, AuthError> {
            self.0.get_auth_request(t)
        }
        fn handle_auth_reply_more(&mut self, p: &[u8]) -> Result<Vec<u8>, AuthError> {
            self.0.handle_auth_reply_more(p)
        }
        fn handle_auth_done(&mut self, g: u64, m: u32, p: &[u8]) -> Result<AuthSecrets, AuthError> {
            self.0.handle_auth_done(g, m, p)
        }
        fn handle_auth_bad_method(
            &mut self,
            m: u32,
            r: i32,
            am: &[u32],
            amo: &[u32],
        ) -> Result<(), AuthError> {
            self.1.borrow_mut().push((m, r, am.to_vec(), amo.to_vec()));
            self.0.handle_auth_bad_method(m, r, am, amo)
        }
    }

    fn none_client(name: &str, gid: u64) -> (Recording, Seen) {
        let k = KeyStore::default();
        k.set_none_authorizer(Some(payload(name, gid)));
        let seen = Rc::new(RefCell::new(Vec::new()));
        (Recording(DaemonAuthClient::new(k), seen.clone()), seen)
    }

    fn connected(ev: &[Event]) -> bool {
        ev.iter().any(|e| matches!(e, Event::Connected(_)))
    }

    #[test]
    fn none_to_none_handshake_succeeds_in_crc() {
        let (c, _) = none_client("osd.1", 0x1001);
        let k = lists(&[AUTH_NONE], &[AUTH_NONE]);
        let (s, out) = server(&k);
        let (ec, es) = handshake(
            Box::new(c),
            Box::new(s),
            EntityName::osd(1),
            ENTITY_OSD as u8,
        );
        assert!(connected(&ec) && connected(&es), "{ec:?} {es:?}");
        assert_eq!(out.borrow().entity, "osd.1");
    }

    #[test]
    fn none_against_cephx_only_osd_gets_the_exact_bad_method_and_no_retry() {
        let (c, seen) = none_client("osd.1", 0x1001);
        let k = lists(&[AUTH_CEPHX], &[AUTH_CEPHX]);
        let (s, _) = server(&k);
        let (ec, es) = handshake(
            Box::new(c),
            Box::new(s),
            EntityName::osd(1),
            ENTITY_OSD as u8,
        );
        assert!(!connected(&ec) && !connected(&es));
        assert_eq!(*seen.borrow(), [(1, -95, vec![2], vec![1])]);
        assert!(
            ec.iter()
                .any(|e| matches!(e, Event::Fault(FaultReason::Auth(_)))),
            "{ec:?}"
        );
    }

    #[test]
    fn client_peer_uses_the_service_list() {
        // cluster none, service cephx: a client NONE request to this OSD is rejected -95 (spec 8, row 3)
        let (c, seen) = none_client("client.admin", 0);
        let k = lists(&[AUTH_NONE], &[AUTH_CEPHX]);
        let (s, _) = server(&k);
        let (ec, _) = handshake(
            Box::new(c),
            Box::new(s),
            EntityName::new(EntityName::CLIENT, 0),
            ENTITY_OSD as u8,
        );
        assert!(!connected(&ec));
        assert_eq!(*seen.borrow(), [(1, -95, vec![2], vec![1])]);
    }

    #[test]
    fn daemon_hello_with_a_client_name_in_the_none_payload_is_refused() {
        // HELLO type OSD but the authorizer names client.9: BAD_METHOD(-EACCES) before AUTH_DONE
        let (c, seen) = none_client("client.9", 3);
        let k = lists(&[AUTH_NONE], &[AUTH_NONE]);
        let (s, _) = server(&k);
        let (ec, es) = handshake(
            Box::new(c),
            Box::new(s),
            EntityName::osd(1),
            ENTITY_OSD as u8,
        );
        assert!(!connected(&ec) && !connected(&es));
        assert_eq!(seen.borrow().first().map(|b| (b.0, b.1)), Some((1, -13)));
    }

    /// The OSD's mon session follows `ms_mon_cluster_mode`, never the clients' `ms_mon_client_mode` (review B9).
    #[test]
    fn mon_session_uses_mon_cluster_mode() {
        let l = |p: &[(&str, &str)]| -> Vec<(String, String)> {
            p.iter()
                .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
                .collect()
        };
        assert_eq!(
            mon_session_modes(&l(&[
                ("ms_mon_client_mode", "crc"),
                ("ms_mon_cluster_mode", "secure")
            ]))
            .map(|m| m.modes),
            Some(vec![CON_MODE_SECURE])
        );
        // a word that is not a mode is skipped and reported, never silently dropped
        assert_eq!(
            mon_session_modes(&l(&[("ms_mon_cluster_mode", "secure secrue")]))
                .map(|m| (m.modes, m.unknown)),
            Some((vec![CON_MODE_SECURE], vec!["secrue".to_owned()]))
        );
        assert_eq!(
            mon_session_modes(&l(&[("ms_mon_client_mode", "crc")])),
            None
        );
        assert_eq!(
            mon_session_modes(&l(&[("ms_mon_cluster_mode", "bogus")])),
            None
        );
    }
}
