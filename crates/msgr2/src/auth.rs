// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Authentication-layer contract (spec 13). msgr2 only transports opaque auth payloads; an auth
//! module (cephx, none, ...) implements these traits. Everything is synchronous and sans-IO.
use core::fmt;
use denc::types::EntityName;
use denc::{Decoder, Encoder};

/// Auth method ids.
pub const AUTH_METHOD_NONE: u32 = 1;
/// cephx.
pub const AUTH_METHOD_CEPHX: u32 = 2;
/// Connection mode: CRC (plaintext framing).
pub const MODE_CRC: u32 = 1;
/// Connection mode: AES-128-GCM.
pub const MODE_SECURE: u32 = 2;
/// -EOPNOTSUPP.
pub const EOPNOTSUPP: i32 = -95;

/// Auth failure (client side) or opaque rejection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthError(pub String);

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "auth error: {}", self.0)
    }
}
impl std::error::Error for AuthError {}

/// First message of the client auth exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequestOut {
    /// Method id.
    pub method: u32,
    /// Connection modes in preference order.
    pub preferred_modes: Vec<u32>,
    /// Method payload.
    pub payload: Vec<u8>,
}

/// Secrets produced when the auth exchange completes. Wiped on drop (the session key is the HMAC key of the
/// AUTH_SIGNATURE, the connection secret the cipher key material of secure mode).
#[derive(Clone, Default, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct AuthSecrets {
    /// Session key (HMAC key for AUTH_SIGNATURE); empty = none (32 zero bytes signature).
    pub session_key: Vec<u8>,
    /// Connection secret (>= 40 bytes, required iff mode is secure).
    pub connection_secret: Vec<u8>,
}

impl fmt::Debug for AuthSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthSecrets(..)")
    }
}

/// Key material held by a [`crate::Connection`]: wiped on drop, `Debug` prints only the length.
#[derive(Default)]
pub(crate) struct Secret(zeroize::Zeroizing<Vec<u8>>);

impl Secret {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    pub(crate) fn wipe(&mut self) {
        zeroize::Zeroize::zeroize(&mut *self.0);
    }
}

impl core::ops::Deref for Secret {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted {} bytes>", self.0.len())
    }
}

/// Client side of the auth layer. One instance per [`crate::Connection`]; `get_auth_request`
/// restarts the exchange (called again after AUTH_BAD_METHOD and on every reconnect attempt).
pub trait AuthClientHandler: fmt::Debug {
    /// Start (or restart) authentication towards a peer of `peer_type`.
    fn get_auth_request(&mut self, peer_type: u8) -> Result<AuthRequestOut, AuthError>;
    /// Server asked for another round; return the AUTH_REQUEST_MORE payload.
    fn handle_auth_reply_more(&mut self, payload: &[u8]) -> Result<Vec<u8>, AuthError>;
    /// Server finished. `Err` faults the connection.
    fn handle_auth_done(
        &mut self,
        global_id: u64,
        mode: u32,
        payload: &[u8],
    ) -> Result<AuthSecrets, AuthError>;
    /// Server rejected the method/modes; `Ok` = retry via `get_auth_request`, `Err` = give up.
    fn handle_auth_bad_method(
        &mut self,
        method: u32,
        result: i32,
        allowed_methods: &[u32],
        allowed_modes: &[u32],
    ) -> Result<(), AuthError>;
}

/// Outcome of one server auth step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthServerStep {
    /// Authenticated: send AUTH_DONE.
    Done {
        /// AUTH_DONE payload.
        reply: Vec<u8>,
        /// Global id assigned to the peer.
        global_id: u64,
        /// Authenticated entity name, if the method provides one.
        peer_name: Option<EntityName>,
        /// Session key / connection secret (secret only for secure mode).
        secrets: AuthSecrets,
    },
    /// Need another round: send AUTH_REPLY_MORE.
    More(Vec<u8>),
    /// Drop the connection silently (peer retries later).
    Busy,
    /// Reject with AUTH_BAD_METHOD and this negative errno.
    Reject(i32),
}

/// Server side of the auth layer.
pub trait AuthServerHandler: fmt::Debug {
    /// Methods acceptable from a peer of `peer_type`.
    fn supported_methods(&self, peer_type: u8) -> Vec<u32>;
    /// Connection modes allowed for `(peer_type, method)`.
    fn supported_modes(&self, peer_type: u8, method: u32) -> Vec<u32>;
    /// Handle AUTH_REQUEST (`more == false`) or AUTH_REQUEST_MORE. `mode` is the connection mode
    /// already chosen by the messenger (spec 13); a secure `Done` must carry a >= 40 byte secret.
    fn handle_auth_request(
        &mut self,
        peer_type: u8,
        more: bool,
        method: u32,
        mode: u32,
        payload: &[u8],
    ) -> AuthServerStep;
}

fn none_payload(name: &EntityName, global_id: u64) -> Vec<u8> {
    let mut e = Encoder::new();
    let _ = e.u8(1);
    let _ = e.u32(name.ty as u32);
    let _ = e.bytes(name.num.to_string().as_bytes());
    let _ = e.u64(global_id);
    e.into_vec()
}

/// Method NONE, client side: sends `{v=1, entity_name, global_id}`; CRC mode only; no session key.
#[derive(Clone, Debug)]
pub struct AuthNoneClient {
    /// Our entity name.
    pub name: EntityName,
    /// Global id to claim (0 = let the server assign).
    pub global_id: u64,
}

impl AuthClientHandler for AuthNoneClient {
    fn get_auth_request(&mut self, _peer_type: u8) -> Result<AuthRequestOut, AuthError> {
        Ok(AuthRequestOut {
            method: AUTH_METHOD_NONE,
            preferred_modes: vec![MODE_CRC],
            payload: none_payload(&self.name, self.global_id),
        })
    }
    fn handle_auth_reply_more(&mut self, _payload: &[u8]) -> Result<Vec<u8>, AuthError> {
        Err(AuthError("none: unexpected AUTH_REPLY_MORE".into()))
    }
    fn handle_auth_done(
        &mut self,
        _global_id: u64,
        mode: u32,
        _payload: &[u8],
    ) -> Result<AuthSecrets, AuthError> {
        if mode != MODE_CRC {
            return Err(AuthError("none: only crc mode".into()));
        }
        Ok(AuthSecrets::default())
    }
    fn handle_auth_bad_method(
        &mut self,
        _method: u32,
        _result: i32,
        _allowed_methods: &[u32],
        _allowed_modes: &[u32],
    ) -> Result<(), AuthError> {
        Err(AuthError("none: rejected by server".into()))
    }
}

/// Method NONE, server side. Assigns global ids from `next_global_id` when the client sends 0.
#[derive(Clone, Debug)]
pub struct AuthNoneServer {
    /// Next global id to hand out.
    pub next_global_id: u64,
}

impl Default for AuthNoneServer {
    fn default() -> Self {
        Self {
            next_global_id: 4096,
        }
    }
}

impl AuthServerHandler for AuthNoneServer {
    fn supported_methods(&self, _peer_type: u8) -> Vec<u32> {
        vec![AUTH_METHOD_NONE]
    }
    fn supported_modes(&self, _peer_type: u8, _method: u32) -> Vec<u32> {
        vec![MODE_CRC]
    }
    fn handle_auth_request(
        &mut self,
        _peer_type: u8,
        more: bool,
        method: u32,
        mode: u32,
        payload: &[u8],
    ) -> AuthServerStep {
        if more || method != AUTH_METHOD_NONE || mode != MODE_CRC {
            return AuthServerStep::Reject(EOPNOTSUPP);
        }
        let mut d = Decoder::new(payload);
        let parsed = (|| {
            let v = d.u8()?;
            let ty = d.u32()?;
            let id = d.bytes()?;
            let gid = d.u64()?;
            Ok::<_, denc::Error>((v, ty, id.to_vec(), gid))
        })();
        let Ok((1, ty, id, gid)) = parsed else {
            return AuthServerStep::Reject(-22);
        };
        // the peer's type is untrusted input: narrowing it into the mine-type byte would turn 0x0104 into OSD
        let Ok(ty) = u8::try_from(ty) else {
            return AuthServerStep::Reject(-22);
        };
        let global_id = if gid != 0 {
            gid
        } else {
            let g = self.next_global_id;
            self.next_global_id += 1;
            g
        };
        let num = std::str::from_utf8(&id)
            .ok()
            .and_then(|s| s.parse::<i64>().ok());
        AuthServerStep::Done {
            reply: Vec::new(),
            global_id,
            peer_name: num.map(|n| EntityName::new(ty, n)),
            secrets: AuthSecrets::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_roundtrip() {
        let mut c = AuthNoneClient {
            name: EntityName::osd(3),
            global_id: 0,
        };
        let r = c.get_auth_request(1).unwrap();
        assert_eq!((r.method, r.preferred_modes.as_slice()), (1, &[1u32][..]));
        let mut s = AuthNoneServer::default();
        match s.handle_auth_request(4, false, 1, 1, &r.payload) {
            AuthServerStep::Done {
                global_id,
                peer_name,
                ..
            } => {
                assert_eq!(global_id, 4096);
                assert_eq!(peer_name, Some(EntityName::osd(3)));
            }
            o => panic!("{o:?}"),
        }
        assert_eq!(
            s.handle_auth_request(4, false, 1, 1, &[1, 2]),
            AuthServerStep::Reject(-22)
        );
        assert_eq!(
            s.handle_auth_request(4, false, 2, 1, &r.payload),
            AuthServerStep::Reject(EOPNOTSUPP)
        );
    }

    /// The entity type of the peer's payload is untrusted input: it must fit the mine-type byte instead of being
    /// narrowed into another type (0x0104 would pass as OSD).
    #[test]
    fn none_rejects_an_entity_type_that_does_not_fit_u8() {
        let mut e = Encoder::new();
        e.u8(1).unwrap();
        e.u32(0x0104).unwrap();
        e.bytes(b"3").unwrap();
        e.u64(7).unwrap();
        let mut s = AuthNoneServer::default();
        assert_eq!(
            s.handle_auth_request(4, false, AUTH_METHOD_NONE, MODE_CRC, &e.into_vec()),
            AuthServerStep::Reject(-22)
        );
    }

    /// Session key material must not stay in freed allocations.
    #[test]
    fn auth_secrets_wipe_on_drop() {
        fn wipes<T: zeroize::ZeroizeOnDrop>() {}
        wipes::<AuthSecrets>();
        let mut s = AuthSecrets {
            session_key: vec![7; 16],
            connection_secret: vec![9; 64],
        };
        zeroize::Zeroize::zeroize(&mut s);
        assert!(s.session_key.is_empty() && s.connection_secret.is_empty());
    }
}
