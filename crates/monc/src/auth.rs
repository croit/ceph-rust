// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Adapter: cephx [`MonAuthClient`] / method NONE -> msgr2 [`AuthClientHandler`] (spec cephx.md 8.1-8.5).
use cephx::modes::{AUTH_CEPHX, AUTH_NONE, CON_MODE_CRC};
use cephx::monclient::MonAuthClient;
use cephx::none::EntityName as AuthName;
use msgr2::auth::{AuthClientHandler, AuthError, AuthRequestOut, AuthSecrets};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

/// Auth state of one mon connection attempt, shared between the msgr2 handler and the MonClient
/// (which keeps the winner's instance for MAuth renewals). `Debug` never reaches the cephx state
/// (tickets carry ticket blobs and session keys).
pub struct AuthShared<I = String> {
    /// cephx state machine (unused for method NONE).
    pub cephx: RefCell<Option<MonAuthClient>>,
    /// Entity for method NONE.
    pub name: AuthName<I>,
    /// Global id (NONE: assigned by the mon; cephx: see `cephx`).
    pub none_gid: Cell<u64>,
    /// Method that completed the handshake (0 = not yet).
    pub method: Cell<u32>,
    /// Negotiated connection mode (0 = not yet).
    pub mode: Cell<u32>,
    /// Current unix wall time (nanosecond precision: cephx ticket validity is fractional), updated by the owner
    /// before feeding bytes.
    pub now_wall: Rc<Cell<Duration>>,
}

impl<I> std::fmt::Debug for AuthShared<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthShared")
            .field("method", &self.method.get())
            .field("mode", &self.mode.get())
            .field("gid", &self.global_id())
            .field("cephx", &self.cephx.borrow().is_some())
            .finish()
    }
}

impl AuthShared {
    /// New shared state.
    pub fn new(
        cephx: Option<MonAuthClient>,
        name: AuthName,
        gid: u64,
        clock: Rc<Cell<Duration>>,
    ) -> Rc<Self> {
        Self::with_name(cephx, name, gid, clock)
    }
}
impl AuthShared<Vec<u8>> {
    pub fn new_bytes(
        cephx: Option<MonAuthClient>,
        name: AuthName<Vec<u8>>,
        gid: u64,
        clock: Rc<Cell<Duration>>,
    ) -> Rc<Self> {
        Self::with_name(cephx, name, gid, clock)
    }
}
impl<I> AuthShared<I> {
    fn with_name(
        cephx: Option<MonAuthClient>,
        name: AuthName<I>,
        gid: u64,
        clock: Rc<Cell<Duration>>,
    ) -> Rc<Self> {
        Rc::new(Self {
            cephx: RefCell::new(cephx),
            name,
            none_gid: Cell::new(gid),
            method: Cell::new(0),
            mode: Cell::new(0),
            now_wall: clock,
        })
    }
    /// Global id assigned by the mon.
    pub fn global_id(&self) -> u64 {
        match (self.method.get(), &*self.cephx.borrow()) {
            (AUTH_CEPHX, Some(c)) => c.global_id(),
            _ => self.none_gid.get(),
        }
    }
}

/// msgr2 client auth handler toward a mon: cephx and/or NONE, mode list from config.
pub struct MonAuthHandler<I = String> {
    shared: Rc<AuthShared<I>>,
    all_methods: Vec<u32>,
    methods: Vec<u32>,
    modes: Vec<u32>,
    cur: u32,
    retry: bool,
}

impl<I> std::fmt::Debug for MonAuthHandler<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonAuthHandler")
            .field("current", &self.cur)
            .field("methods", &self.methods)
            .field("modes", &self.modes)
            .field("retry", &self.retry)
            .finish()
    }
}

impl<I> MonAuthHandler<I> {
    /// `methods` in preference order (those without a usable key are dropped by the caller).
    pub fn new(shared: Rc<AuthShared<I>>, methods: Vec<u32>, modes: Vec<u32>) -> Self {
        Self {
            shared,
            all_methods: methods.clone(),
            methods,
            modes,
            cur: 0,
            retry: false,
        }
    }
}

impl<I: AsRef<[u8]> + std::fmt::Debug> AuthClientHandler for MonAuthHandler<I> {
    fn get_auth_request(&mut self, _peer_type: u8) -> Result<AuthRequestOut, AuthError> {
        if !std::mem::take(&mut self.retry) {
            self.methods = self.all_methods.clone(); // new stream: start over
        }
        let m = *self
            .methods
            .first()
            .ok_or_else(|| AuthError("no auth method left".into()))?;
        self.cur = m;
        let sh = &self.shared;
        match m {
            AUTH_CEPHX => {
                let mut g = sh.cephx.borrow_mut();
                let c = g
                    .as_mut()
                    .ok_or_else(|| AuthError("cephx without key".into()))?;
                Ok(AuthRequestOut {
                    method: m,
                    preferred_modes: self.modes.clone(),
                    payload: c.start(),
                })
            }
            AUTH_NONE => {
                let preferred_modes: Vec<_> = self
                    .modes
                    .iter()
                    .copied()
                    .filter(|&mode| mode == CON_MODE_CRC)
                    .collect();
                if preferred_modes.is_empty() {
                    return Err(AuthError("none: configured modes exclude crc".into()));
                }
                Ok(AuthRequestOut {
                    method: m,
                    preferred_modes,
                    payload: sh.name.mon_auth_payload(sh.none_gid.get()),
                })
            }
            _ => Err(AuthError(format!("unsupported method {m}"))),
        }
    }

    fn handle_auth_reply_more(&mut self, payload: &[u8]) -> Result<Vec<u8>, AuthError> {
        if self.cur != AUTH_CEPHX {
            return Err(AuthError("unexpected AUTH_REPLY_MORE".into()));
        }
        let now = self.shared.now_wall.get();
        let mut g = self.shared.cephx.borrow_mut();
        let c = g.as_mut().ok_or_else(|| AuthError("no cephx".into()))?;
        c.on_reply_more(payload, now)
            .map_err(|e| AuthError(format!("cephx: {e:?}")))
    }

    fn handle_auth_done(
        &mut self,
        global_id: u64,
        mode: u32,
        payload: &[u8],
    ) -> Result<AuthSecrets, AuthError> {
        if self.cur == AUTH_NONE && (mode != CON_MODE_CRC || !self.modes.contains(&CON_MODE_CRC)) {
            return Err(AuthError(
                "none: selected mode violates configured policy".into(),
            ));
        }
        let sh = &self.shared;
        let secrets = match self.cur {
            AUTH_CEPHX => {
                let now = sh.now_wall.get();
                let mut g = sh.cephx.borrow_mut();
                let c = g.as_mut().ok_or_else(|| AuthError("no cephx".into()))?;
                c.on_done(global_id, mode, payload, now)
                    .map_err(|e| AuthError(format!("cephx: {e:?}")))?;
                let session_key = c
                    .session_key()
                    .map(|k| k.secret().to_vec())
                    .unwrap_or_default();
                let connection_secret = c
                    .connection_secret()
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default();
                AuthSecrets {
                    session_key,
                    connection_secret,
                }
            }
            AUTH_NONE => {
                sh.none_gid.set(global_id);
                AuthSecrets::default()
            }
            _ => return Err(AuthError("bad method".into())),
        };
        // Only an accepted completion may leave the shared state claiming a session.
        sh.method.set(self.cur);
        sh.mode.set(mode);
        Ok(secrets)
    }

    fn handle_auth_bad_method(
        &mut self,
        method: u32,
        result: i32,
        allowed_methods: &[u32],
        allowed_modes: &[u32],
    ) -> Result<(), AuthError> {
        // drop the failed method; continue with the next one the server allows
        self.methods
            .retain(|m| *m != method && allowed_methods.contains(m));
        if self.methods.first() == Some(&AUTH_CEPHX)
            && !self.modes.iter().any(|m| allowed_modes.contains(m))
        {
            return Err(AuthError(format!(
                "no common connection mode (ours {:?}, server {allowed_modes:?})",
                self.modes
            )));
        }
        if self.methods.is_empty() {
            return Err(AuthError(format!(
                "auth method {method} rejected ({result}); server allows methods {allowed_methods:?}"
            )));
        }
        self.retry = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cephx::modes::CON_MODE_SECURE;
    fn handler(methods: Vec<u32>, modes: Vec<u32>) -> (MonAuthHandler, Rc<AuthShared>) {
        let shared = AuthShared::new(
            None,
            AuthName::parse("client.mode-policy").unwrap(),
            7,
            Rc::new(Cell::new(Duration::from_secs(0))),
        );
        (MonAuthHandler::new(shared.clone(), methods, modes), shared)
    }
    #[test]
    fn none_filters_configured_modes_without_relaxing_secure_only_policy() {
        for modes in [
            vec![CON_MODE_CRC],
            vec![CON_MODE_SECURE, CON_MODE_CRC],
            vec![CON_MODE_CRC, CON_MODE_SECURE],
        ] {
            let (mut handler, shared) = handler(vec![AUTH_NONE], modes);
            let request = handler
                .get_auth_request(cephx::none::ENTITY_MON as u8)
                .unwrap();
            assert_eq!(request.method, AUTH_NONE);
            assert_eq!(request.preferred_modes, vec![CON_MODE_CRC]);
            let secrets = handler.handle_auth_done(9, CON_MODE_CRC, &[]).unwrap();
            assert!(secrets.session_key.is_empty());
            assert!(secrets.connection_secret.is_empty());
            assert_eq!(shared.global_id(), 9);
        }
        for modes in [vec![], vec![CON_MODE_SECURE]] {
            let (mut handler, shared) = handler(vec![AUTH_NONE], modes);
            assert!(
                handler
                    .get_auth_request(cephx::none::ENTITY_MON as u8)
                    .is_err()
            );
            assert!(handler.handle_auth_done(99, CON_MODE_CRC, &[]).is_err());
            assert_eq!(shared.method.get(), 0);
            assert_eq!(shared.mode.get(), 0);
            assert_eq!(shared.global_id(), 7);
        }
    }
    #[test]
    fn none_retry_and_completion_cannot_bypass_mode_policy() {
        for modes in [vec![CON_MODE_CRC], vec![CON_MODE_SECURE]] {
            let allowed = modes.contains(&CON_MODE_CRC);
            let (mut handler, shared) = handler(vec![AUTH_CEPHX, AUTH_NONE], modes);
            handler
                .handle_auth_bad_method(AUTH_CEPHX, -95, &[AUTH_NONE], &[CON_MODE_CRC])
                .unwrap();
            assert_eq!(
                handler
                    .get_auth_request(cephx::none::ENTITY_MON as u8)
                    .is_ok(),
                allowed
            );
            assert!(handler.handle_auth_done(99, CON_MODE_SECURE, &[]).is_err());
            assert_eq!(shared.method.get(), 0);
            assert_eq!(shared.mode.get(), 0);
            assert_eq!(shared.global_id(), 7);
        }
    }
    /// auth-none spec 4.2: the initiator walks FORWARD in its own list from the rejected method.
    #[test]
    fn bad_method_walks_forward_in_own_list_never_wraps() {
        let mon = cephx::none::ENTITY_MON as u8;
        let all = [AUTH_NONE, AUTH_CEPHX];
        let (mut h, _) = handler(vec![AUTH_NONE, AUTH_CEPHX], vec![CON_MODE_CRC]);
        assert_eq!(h.get_auth_request(mon).unwrap().method, AUTH_NONE);
        h.handle_auth_bad_method(AUTH_NONE, -95, &all, &[CON_MODE_CRC])
            .unwrap();
        // the cephx request needs a key: without one the walk fails on the request, never on a retry of none
        assert!(h.get_auth_request(mon).is_err());

        let (mut h, _) = handler(vec![AUTH_CEPHX, AUTH_NONE], vec![CON_MODE_CRC]);
        h.methods = vec![AUTH_CEPHX, AUTH_NONE];
        h.cur = AUTH_CEPHX;
        h.handle_auth_bad_method(AUTH_CEPHX, -95, &[AUTH_NONE], &[CON_MODE_CRC])
            .unwrap();
        assert_eq!(h.get_auth_request(mon).unwrap().method, AUTH_NONE);
        // none rejected too (allowed lists the earlier cephx): no wrap to cephx
        let e = h
            .handle_auth_bad_method(AUTH_NONE, -95, &all, &[CON_MODE_CRC])
            .unwrap_err();
        assert!(e.0.contains("rejected"), "{e}");

        // none only never retries
        let (mut h, _) = handler(vec![AUTH_NONE], vec![CON_MODE_CRC]);
        h.get_auth_request(mon).unwrap();
        assert!(
            h.handle_auth_bad_method(AUTH_NONE, -95, &all, &[CON_MODE_CRC])
                .is_err()
        );
    }

    /// cephx completion that rejects the ticket must not leave the shared state claiming a session.
    #[test]
    fn failed_cephx_completion_leaves_shared_method_and_mode_unset() {
        let key = cephx::CryptoKey::new(cephx::KeyType::Aes, Default::default(), &[7; 16]);
        let cfg = crate::Config::new_client("client.test", Some(key.clone()));
        let cephx = MonAuthClient::with_global_id_bytes(cfg.auth_cfg(key), 77);
        let shared = AuthShared::new(
            Some(cephx),
            cfg.auth_name(),
            5,
            Rc::new(Cell::new(Duration::from_secs(100))),
        );
        let mut handler = MonAuthHandler::new(shared.clone(), vec![AUTH_CEPHX], vec![CON_MODE_CRC]);
        handler
            .get_auth_request(cephx::none::ENTITY_MON as u8)
            .unwrap();
        assert!(
            handler
                .handle_auth_done(1, CON_MODE_CRC, b"garbage")
                .is_err()
        );
        assert_eq!(shared.method.get(), 0);
        assert_eq!(shared.mode.get(), 0);
        assert_eq!(shared.global_id(), 5);
    }

    /// Neither debug surface may reach the cephx state (its tickets carry ticket blobs and session keys).
    #[test]
    fn debug_output_hides_cephx_ticket_state() {
        let key = cephx::CryptoKey::new(cephx::KeyType::Aes, Default::default(), &[7; 16]);
        let cfg = crate::Config::new_client("client.test", Some(key.clone()));
        let cephx = MonAuthClient::with_global_id_bytes(cfg.auth_cfg(key), 77);
        let shared = AuthShared::new(
            Some(cephx),
            cfg.auth_name(),
            5,
            Rc::new(Cell::new(Duration::from_secs(100))),
        );
        let handler = MonAuthHandler::new(shared.clone(), vec![AUTH_CEPHX], vec![CON_MODE_CRC]);
        let shared_text = format!("{shared:?}");
        for forbidden in ["MonAuthClient", "TicketHandler", "TicketBlob"] {
            assert!(!shared_text.contains(forbidden), "{shared_text}");
        }
        assert!(shared_text.contains("method") && shared_text.contains("mode"));
        let handler_text = format!("{handler:?}");
        for forbidden in ["AuthShared", "MonAuthClient", "TicketHandler"] {
            assert!(!handler_text.contains(forbidden), "{handler_text}");
        }
    }

    #[test]
    fn none_request_vector_is_the_mon_variant() {
        let shared = AuthShared::new(
            None,
            AuthName::parse("osd.3").unwrap(),
            0,
            Rc::new(Cell::new(Duration::from_secs(0))),
        );
        let mut h =
            MonAuthHandler::new(shared, vec![AUTH_NONE], vec![CON_MODE_SECURE, CON_MODE_CRC]);
        let r = h.get_auth_request(cephx::none::ENTITY_MON as u8).unwrap();
        let mut want = vec![0x0a, 4, 0, 0, 0, 1, 0, 0, 0, b'3'];
        want.extend_from_slice(&[0; 8]);
        assert_eq!((r.method, r.preferred_modes, r.payload), (1, vec![1], want));
    }

    #[test]
    fn monitor_none_and_cephx_requests_preserve_original_byte_principal() {
        for method in [AUTH_NONE, AUTH_CEPHX] {
            for role in ["auth", "mon", "osd", "mds", "mgr", "client"] {
                for id in [b"".as_slice(), b"name with spaces.more", b"\xff\x80.$name"] {
                    let mut input = role.as_bytes().to_vec();
                    input.push(b'.');
                    input.extend_from_slice(id);
                    let mut cfg = crate::Config::new_client_bytes(
                        &input,
                        Some(cephx::CryptoKey::new(
                            cephx::KeyType::Aes,
                            Default::default(),
                            &[7; 16],
                        )),
                    );
                    cfg.methods = vec![method];
                    let name = cfg.auth_name();
                    let cephx = (method == AUTH_CEPHX).then(|| {
                        MonAuthClient::with_global_id_bytes(
                            cfg.auth_cfg(cfg.key.clone().unwrap()),
                            77,
                        )
                    });
                    let shared = AuthShared::new_bytes(
                        cephx,
                        name.clone(),
                        77,
                        Rc::new(Cell::new(Duration::from_secs(100))),
                    );
                    input.fill(b'x');
                    drop(cfg);
                    let mut handler = MonAuthHandler::new(shared, vec![method], vec![CON_MODE_CRC]);
                    let request = handler
                        .get_auth_request(cephx::none::ENTITY_MON as u8)
                        .unwrap();
                    let mut wanted = vec![10];
                    wanted.extend_from_slice(&name.ty.to_le_bytes());
                    wanted.extend_from_slice(&(id.len() as u32).to_le_bytes());
                    wanted.extend_from_slice(id);
                    wanted.extend_from_slice(&77u64.to_le_bytes());
                    assert_eq!(request.method, method);
                    assert_eq!(request.payload, wanted);
                    assert_eq!(
                        handler
                            .get_auth_request(cephx::none::ENTITY_MON as u8)
                            .unwrap()
                            .payload,
                        wanted
                    );
                }
            }
        }
    }
}
