// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Client side: build an authorizer toward a peer (spec sec 3, 7), incl. challenge round.

use denc::{Decode, Decoder, Encode, Encoder};

use crate::challenge::random_u64;
use crate::envelope::{open_raw_t, open_wrapped_t, seal_wrapped_t};
use crate::error::{Error, Result};
use crate::key::{CryptoKey, Usage};
use crate::none::{AUTH_MODE_AUTHORIZER, AUTH_MODE_AUTHORIZER_MAX};
use crate::secret::ConnectionSecret;
use crate::ticket::TicketHandler;
use crate::types::{Authorize, AuthorizeChallenge, AuthorizeReply, TicketBlob};

/// `base_bl`: `u8 1 | u64 global_id | u32 service_id | CephXTicketBlob`.
fn base_bl(global_id: u64, service_id: u32, ticket: &TicketBlob) -> Result<Vec<u8>> {
    let mut e = Encoder::new();
    e.u8(AUTH_MODE_AUTHORIZER)?;
    e.u64(global_id)?;
    e.u32(service_id)?;
    ticket.encode(&mut e)?;
    Ok(e.into_vec())
}

/// Outgoing authorizer for one connection attempt (cephx).
#[derive(Debug)]
pub struct Authorizer {
    base: Vec<u8>,
    session_key: CryptoKey,
    nonce: u64,
    payload: Vec<u8>,
    connection_secret: Option<ConnectionSecret>,
    done: bool,
}

impl Authorizer {
    /// Build from cached ticket material. Expiry/invalidation schedules renewal but does not prevent
    /// authorization: the peer decides whether it still holds the sealing key (auth lifecycle spec).
    pub fn new(global_id: u64, service_id: u32, ticket: &TicketHandler) -> Result<Self> {
        let key = ticket.session_key().ok_or(Error::Auth("no ticket key"))?;
        Self::from_ticket(global_id, service_id, ticket.blob(), key)
    }

    /// Build from raw ticket parts (also used for the AUTH-service authorizer in
    /// GET_PRINCIPAL_SESSION_KEY).
    pub fn from_ticket(
        global_id: u64,
        service_id: u32,
        ticket: &TicketBlob,
        session_key: &CryptoKey,
    ) -> Result<Self> {
        let nonce = random_u64()?;
        let base = base_bl(global_id, service_id, ticket)?;
        let mut a = Self {
            payload: Vec::new(),
            base,
            session_key: session_key.clone(),
            nonce,
            connection_secret: None,
            done: false,
        };
        a.payload = a.assemble(false, 0)?;
        Ok(a)
    }

    fn assemble(&self, have_challenge: bool, sc_plus_one: u64) -> Result<Vec<u8>> {
        let auth = Authorize {
            nonce: self.nonce,
            have_challenge,
            server_challenge_plus_one: sc_plus_one,
        };
        let mut p = self.base.clone();
        p.extend_from_slice(&seal_wrapped_t(&self.session_key, Usage::Authorize, &auth)?);
        Ok(p)
    }

    /// AUTH_REQUEST payload (or the current one for AUTH_REQUEST_MORE).
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// AUTH_REPLY_MORE: empty = unchanged; otherwise decrypt the RAW challenge and rebuild.
    /// Returns the AUTH_REQUEST_MORE payload.
    pub fn on_reply_more(&mut self, payload: &[u8]) -> Result<&[u8]> {
        if !payload.is_empty() {
            let c: AuthorizeChallenge =
                open_raw_t(&self.session_key, Usage::AuthorizeChallenge, payload)?;
            self.payload = self.assemble(true, c.server_challenge.wrapping_add(1))?;
        }
        Ok(&self.payload)
    }

    /// AUTH_DONE payload: WRAPPED reply; nonce_plus_one must match.
    pub fn on_done(&mut self, payload: &[u8]) -> Result<()> {
        let r: AuthorizeReply = open_wrapped_t(
            &self.session_key,
            Usage::AuthorizeReply,
            &mut Decoder::new(payload),
        )
        .map_err(|_| Error::Auth("bad authorizer reply"))?;
        if r.nonce_plus_one != self.nonce.wrapping_add(1) {
            return Err(Error::Auth("authorizer reply nonce mismatch"));
        }
        self.connection_secret = ConnectionSecret::from_bytes(&r.connection_secret)?;
        self.done = true;
        Ok(())
    }

    pub fn is_done(&self) -> bool {
        self.done
    }
    /// Connection session key = ticket session key.
    pub fn session_key(&self) -> &CryptoKey {
        &self.session_key
    }
    pub fn connection_secret(&self) -> Option<&ConnectionSecret> {
        self.connection_secret.as_ref()
    }
}

/// Parsed authorizer (service side view).
#[derive(Debug, Clone)]
pub(crate) struct ParsedAuthorizer<'a> {
    pub global_id: u64,
    pub service_id: u32,
    pub ticket: TicketBlob,
    /// Remaining bytes: the WRAPPED encrypted CephXAuthorize.
    pub rest: Decoder<'a>,
}

pub(crate) fn parse_authorizer(payload: &[u8]) -> Result<ParsedAuthorizer<'_>> {
    let mut d = Decoder::new(payload);
    let v = d.u8()?;
    if !(AUTH_MODE_AUTHORIZER..=AUTH_MODE_AUTHORIZER_MAX).contains(&v) {
        return Err(Error::Auth("bad authorizer version byte"));
    }
    let global_id = d.u64()?;
    let service_id = d.u32()?;
    let ticket = TicketBlob::decode(&mut d)?;
    Ok(ParsedAuthorizer {
        global_id,
        service_id,
        ticket,
        rest: d,
    })
}
