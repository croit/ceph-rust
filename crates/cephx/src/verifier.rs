// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Service side: verify incoming authorizers with rotating keys (spec sec 6).

use crate::authorizer::parse_authorizer;
use crate::challenge::random_u64;
use crate::envelope::{open_raw_t, open_wrapped_t, seal_raw_t, seal_wrapped_t};
use crate::error::{Error, Result};
use crate::key::{CryptoKey, Usage};
use crate::none::ByteEntityName;
use crate::secret::ConnectionSecret;
use zeroize::Zeroizing;

use crate::types::{
    AUTH_UID_DEFAULT, Authorize, AuthorizeChallenge, AuthorizeReply, CapsInfo, RotatingSecrets,
    ServiceTicketInfo,
};

/// Max skew between ticket creation and session key creation (seconds).
pub const MAX_TICKET_KEY_SKEW_SECS: i128 = 300;

/// Nanoseconds per second (utime nsec bound and skew arithmetic).
const NSEC_PER_SEC: u32 = 1_000_000_000;

/// Result of a successful verification.
#[derive(Debug)]
pub struct VerifiedPeer {
    /// Ticket identity; the id is opaque bytes (sec 16.3).
    pub name: ByteEntityName,
    pub global_id: u64,
    /// Caps as carried in the ticket.
    pub caps: CapsInfo,
    /// Decoded cap-grammar text (`None` if the ticket carried no caps).
    pub caps_text: Option<String>,
    pub session_key: CryptoKey,
    /// Present iff the connection is SECURE.
    pub connection_secret: Option<ConnectionSecret>,
    /// AUTH_DONE payload.
    pub reply: Vec<u8>,
}

#[derive(Debug)]
pub enum Verdict {
    /// Send AUTH_REPLY_MORE with this RAW challenge payload; feed the AUTH_REQUEST_MORE next.
    More(Vec<u8>),
    /// Send AUTH_DONE.
    Done(Box<VerifiedPeer>),
}

/// Per-connection verifier. One instance per incoming connection (holds the challenge slot).
#[derive(Debug)]
pub struct AuthorizerVerifier {
    service_type: u32,
    secure: bool,
    challenge: Option<u64>,
}

fn nanos(t: denc::types::UTime) -> i128 {
    i128::from(t.sec) * i128::from(NSEC_PER_SEC) + i128::from(t.nsec)
}

impl AuthorizerVerifier {
    /// `service_type`: our entity type (OSD = 4). `secure`: negotiated mode is SECURE.
    pub fn new(service_type: u32, secure: bool) -> Self {
        Self {
            service_type,
            secure,
            challenge: None,
        }
    }

    /// Feed an AUTH_REQUEST / AUTH_REQUEST_MORE payload.
    pub fn verify(&mut self, payload: &[u8], keys: &RotatingSecrets) -> Result<Verdict> {
        let mut p = parse_authorizer(payload)?;
        if p.ticket.secret_id == u64::MAX {
            return Err(Error::Auth("entity-key tickets unsupported"));
        }
        if p.service_id != self.service_type {
            return Err(Error::Auth("ticket for another service"));
        }
        let rkey = keys
            .get(p.ticket.secret_id)
            .ok_or(Error::Auth("unknown rotating secret id"))?;
        let ServiceTicketInfo {
            ticket: t,
            session_key: sk,
        } = open_raw_t(rkey, Usage::TicketInfo, &p.ticket.blob)?;
        if t.global_id != p.global_id {
            return Err(Error::Auth("global_id mismatch"));
        }
        if t.auid != AUTH_UID_DEFAULT {
            return Err(Error::Auth("bad auid"));
        }
        if t.caps.allow_all {
            return Err(Error::Auth("allow_all caps in ticket"));
        }
        let sk_created = sk.created();
        if t.created.nsec > NSEC_PER_SEC
            || t.expires.nsec > NSEC_PER_SEC
            || sk_created.nsec > NSEC_PER_SEC
        {
            return Err(Error::Auth("bad ticket nsec"));
        }
        if nanos(t.expires) < nanos(t.created) {
            return Err(Error::Auth("ticket expires before created"));
        }
        if (nanos(t.created) - nanos(sk_created)).abs()
            > MAX_TICKET_KEY_SKEW_SECS * i128::from(NSEC_PER_SEC)
        {
            return Err(Error::Auth("ticket/session key creation skew"));
        }
        let caps_text = t
            .caps
            .text()
            .map_err(|_| Error::Auth("malformed ticket caps"))?;
        if sk.is_empty() {
            return Err(Error::Auth("empty session key"));
        }
        let auth: Authorize = open_wrapped_t(&sk, Usage::Authorize, &mut p.rest)
            .map_err(|_| Error::Auth("bad authorize"))?;

        match (auth.have_challenge, self.challenge) {
            (true, Some(sc)) => {
                if auth.server_challenge_plus_one != sc.wrapping_add(1) {
                    return Err(Error::Auth("wrong challenge response"));
                }
            }
            _ => {
                let sc = random_u64()?;
                self.challenge = Some(sc);
                let ct = seal_raw_t(
                    &sk,
                    Usage::AuthorizeChallenge,
                    &AuthorizeChallenge {
                        server_challenge: sc,
                    },
                )?;
                return Ok(Verdict::More(ct));
            }
        }

        let connection_secret = if self.secure {
            Some(ConnectionSecret::generate()?)
        } else {
            None
        };
        let reply = AuthorizeReply {
            nonce_plus_one: auth.nonce.wrapping_add(1),
            connection_secret: Zeroizing::new(
                connection_secret
                    .as_ref()
                    .map(|c| c.as_bytes().to_vec())
                    .unwrap_or_default(),
            ),
        };
        let reply_bl = seal_wrapped_t(&sk, Usage::AuthorizeReply, &reply)?;
        Ok(Verdict::Done(Box::new(VerifiedPeer {
            name: t.name,
            global_id: t.global_id,
            caps: t.caps,
            caps_text,
            session_key: sk,
            connection_secret,
            reply: reply_bl,
        })))
    }
}
