// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cephx wire structs (spec sec 3, 5). Each versioned struct is a plain leading `u8 struct_v`
//! (no compat byte, no length), unlike denc `versioned` envelopes.

use std::collections::BTreeMap;

use denc::types::UTime;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use zeroize::Zeroizing;

use crate::key::CryptoKey;
use crate::none::ByteEntityName;

pub const CEPHX_GET_AUTH_SESSION_KEY: u16 = 0x0100;
pub const CEPHX_GET_PRINCIPAL_SESSION_KEY: u16 = 0x0200;
pub const CEPHX_GET_ROTATING_KEY: u16 = 0x0400;

/// `CEPH_AUTH_UID_DEFAULT`.
pub const AUTH_UID_DEFAULT: u64 = u64::MAX;

/// `CephXRequestHeader`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHeader {
    pub request_type: u16,
}

impl Encode for RequestHeader {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u16(self.request_type)
    }
}
impl<'a> Decode<'a> for RequestHeader {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        Ok(Self {
            request_type: d.u16()?,
        })
    }
}

/// `CephXResponseHeader`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHeader {
    pub request_type: u16,
    pub status: i32,
}

impl Encode for ResponseHeader {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u16(self.request_type)?;
        e.i32(self.status)
    }
}
impl<'a> Decode<'a> for ResponseHeader {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        Ok(Self {
            request_type: d.u16()?,
            status: d.i32()?,
        })
    }
}

/// `CephXServerChallenge` (v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerChallenge {
    pub server_challenge: u64,
}

impl Encode for ServerChallenge {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(1)?;
        e.u64(self.server_challenge)
    }
}
impl<'a> Decode<'a> for ServerChallenge {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.u8()?;
        Ok(Self {
            server_challenge: d.u64()?,
        })
    }
}

/// `CephXChallengeBlob` (no version byte). Server challenge FIRST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeBlob {
    pub server_challenge: u64,
    pub client_challenge: u64,
}

impl Encode for ChallengeBlob {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u64(self.server_challenge)?;
        e.u64(self.client_challenge)
    }
}
impl<'a> Decode<'a> for ChallengeBlob {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        Ok(Self {
            server_challenge: d.u64()?,
            client_challenge: d.u64()?,
        })
    }
}

/// `CephXTicketBlob` (v1). `blob` = RAW enc_bl of [`ServiceTicketInfo`] (usage 0x30).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TicketBlob {
    pub secret_id: u64,
    pub blob: Vec<u8>,
}

impl Encode for TicketBlob {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(1)?;
        e.u64(self.secret_id)?;
        e.bytes(&self.blob)
    }
}
impl<'a> Decode<'a> for TicketBlob {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.u8()?;
        Ok(Self {
            secret_id: d.u64()?,
            blob: d.bytes()?.to_vec(),
        })
    }
}

/// `CephXAuthenticate`. Always encoded as v3; decodes v1..v3.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Authenticate {
    pub client_challenge: u64,
    pub key: u64,
    pub old_ticket: TicketBlob,
    pub other_keys: u32,
}

impl Encode for Authenticate {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(3)?;
        e.u64(self.client_challenge)?;
        e.u64(self.key)?;
        self.old_ticket.encode(e)?;
        e.u32(self.other_keys)
    }
}
impl<'a> Decode<'a> for Authenticate {
    /// Must be the last item of its buffer: v<3 may omit `old_ticket`, v1 omits `other_keys`.
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        let v = d.u8()?;
        let client_challenge = d.u64()?;
        let key = d.u64()?;
        let old_ticket = if v >= 3 || !d.is_empty() {
            TicketBlob::decode(d)?
        } else {
            TicketBlob::default()
        };
        let other_keys = if v >= 2 { d.u32()? } else { 0 };
        Ok(Self {
            client_challenge,
            key,
            old_ticket,
            other_keys,
        })
    }
}

/// `CephXServiceTicketRequest` (v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceTicketRequest {
    pub keys: u32,
}

impl Encode for ServiceTicketRequest {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(1)?;
        e.u32(self.keys)
    }
}
impl<'a> Decode<'a> for ServiceTicketRequest {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.u8()?;
        Ok(Self { keys: d.u32()? })
    }
}

/// `CephXServiceTicket` "A" (v1): session key + lifetime from now (zero = no expiry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceTicket {
    pub session_key: CryptoKey,
    pub validity: UTime,
}

impl Encode for ServiceTicket {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(1)?;
        self.session_key.encode(e)?;
        self.validity.encode(e)
    }
}
impl<'a> Decode<'a> for ServiceTicket {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.u8()?;
        Ok(Self {
            session_key: CryptoKey::decode(d)?,
            validity: UTime::decode(d)?,
        })
    }
}

/// `AuthCapsInfo` (v1). `caps` holds exactly one encoded `string` when non-empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapsInfo {
    pub allow_all: bool,
    pub caps: Vec<u8>,
}

impl CapsInfo {
    /// Caps with the cap-grammar text wrapped as one encoded string.
    pub fn from_text(text: &str) -> Self {
        let mut e = Encoder::new();
        let _ = e.bytes(text.as_bytes());
        Self {
            allow_all: false,
            caps: e.into_vec(),
        }
    }
    /// Cap text; `Ok(None)` for empty caps; error unless exactly one string with no trailing bytes.
    pub fn text(&self) -> denc::Result<Option<String>> {
        if self.caps.is_empty() {
            return Ok(None);
        }
        let mut d = Decoder::new(&self.caps);
        let s = String::decode(&mut d)?;
        if !d.is_empty() {
            return Err(denc::Error::TrailingBytes(d.remaining()));
        }
        Ok(Some(s))
    }
}

impl Encode for CapsInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(1)?;
        e.bool(self.allow_all)?;
        e.bytes(&self.caps)
    }
}
impl<'a> Decode<'a> for CapsInfo {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.u8()?;
        Ok(Self {
            allow_all: d.bool()?,
            caps: d.bytes()?.to_vec(),
        })
    }
}

/// `AuthTicket` (v2). The identity id is opaque bytes: the auth path never validates UTF-8 (sec 16.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthTicket {
    pub name: ByteEntityName,
    pub global_id: u64,
    pub auid: u64,
    pub created: UTime,
    pub expires: UTime,
    pub caps: CapsInfo,
    pub flags: u32,
}

impl Encode for AuthTicket {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(2)?;
        self.name.encode(e)?;
        e.u64(self.global_id)?;
        e.u64(self.auid)?;
        self.created.encode(e)?;
        self.expires.encode(e)?;
        self.caps.encode(e)?;
        e.u32(self.flags)
    }
}
impl<'a> Decode<'a> for AuthTicket {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        let v = d.u8()?;
        let name = ByteEntityName::decode(d)?;
        let global_id = d.u64()?;
        let auid = if v >= 2 { d.u64()? } else { AUTH_UID_DEFAULT };
        Ok(Self {
            name,
            global_id,
            auid,
            created: UTime::decode(d)?,
            expires: UTime::decode(d)?,
            caps: CapsInfo::decode(d)?,
            flags: d.u32()?,
        })
    }
}

/// `CephXServiceTicketInfo` "B" (v1): content of a ticket blob after decrypt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceTicketInfo {
    pub ticket: AuthTicket,
    pub session_key: CryptoKey,
}

impl Encode for ServiceTicketInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(1)?;
        self.ticket.encode(e)?;
        self.session_key.encode(e)
    }
}
impl<'a> Decode<'a> for ServiceTicketInfo {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.u8()?;
        Ok(Self {
            ticket: AuthTicket::decode(d)?,
            session_key: CryptoKey::decode(d)?,
        })
    }
}

/// `CephXAuthorize` (v2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authorize {
    pub nonce: u64,
    pub have_challenge: bool,
    pub server_challenge_plus_one: u64,
}

impl Encode for Authorize {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(2)?;
        e.u64(self.nonce)?;
        e.bool(self.have_challenge)?;
        e.u64(self.server_challenge_plus_one)
    }
}
impl<'a> Decode<'a> for Authorize {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        let v = d.u8()?;
        let nonce = d.u64()?;
        let (have_challenge, server_challenge_plus_one) = if v >= 2 {
            (d.bool()?, d.u64()?)
        } else {
            (false, 0)
        };
        Ok(Self {
            nonce,
            have_challenge,
            server_challenge_plus_one,
        })
    }
}

/// `CephXAuthorizeChallenge` (v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizeChallenge {
    pub server_challenge: u64,
}

impl Encode for AuthorizeChallenge {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(1)?;
        e.u64(self.server_challenge)
    }
}
impl<'a> Decode<'a> for AuthorizeChallenge {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.u8()?;
        Ok(Self {
            server_challenge: d.u64()?,
        })
    }
}

/// `CephXAuthorizeReply`: v2 iff `connection_secret` non-empty, else v1. The secret is wiped on drop and not printed.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizeReply {
    pub nonce_plus_one: u64,
    pub connection_secret: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for AuthorizeReply {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorizeReply")
            .field("nonce_plus_one", &self.nonce_plus_one)
            .field("connection_secret_len", &self.connection_secret.len())
            .finish()
    }
}

impl Encode for AuthorizeReply {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        if self.connection_secret.is_empty() {
            e.u8(1)?;
            e.u64(self.nonce_plus_one)
        } else {
            e.u8(2)?;
            e.u64(self.nonce_plus_one)?;
            e.bytes(&self.connection_secret)
        }
    }
}
impl<'a> Decode<'a> for AuthorizeReply {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        let v = d.u8()?;
        let nonce_plus_one = d.u64()?;
        let connection_secret = Zeroizing::new(if v >= 2 {
            d.bytes()?.to_vec()
        } else {
            Vec::new()
        });
        Ok(Self {
            nonce_plus_one,
            connection_secret,
        })
    }
}

/// `ExpiringCryptoKey` (v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiringCryptoKey {
    pub key: CryptoKey,
    pub expiration: UTime,
}

impl Encode for ExpiringCryptoKey {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(1)?;
        self.key.encode(e)?;
        self.expiration.encode(e)
    }
}
impl<'a> Decode<'a> for ExpiringCryptoKey {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.u8()?;
        Ok(Self {
            key: CryptoKey::decode(d)?,
            expiration: UTime::decode(d)?,
        })
    }
}

/// Rotating keys held per service (`KEY_ROTATE_NUM`, spec sec 1): previous, current, next.
pub const KEY_ROTATE_NUM: usize = 3;

/// `RotatingSecrets` (v1): ascending secret_id = previous, current, next.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotatingSecrets {
    pub secrets: BTreeMap<u64, ExpiringCryptoKey>,
    pub max_ver: u64,
}

impl RotatingSecrets {
    /// Key by id (the verifier's lookup, spec sec 6 step 2).
    pub fn get(&self, secret_id: u64) -> Option<&CryptoKey> {
        self.secrets.get(&secret_id).map(|k| &k.key)
    }
    /// The 2nd smallest entry (`current`); only meaningful with [`KEY_ROTATE_NUM`] keys held.
    pub fn current(&self) -> Option<(&u64, &ExpiringCryptoKey)> {
        self.secrets.iter().nth(1)
    }
}

impl Encode for RotatingSecrets {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u8(1)?;
        self.secrets.encode(e)?;
        e.u64(self.max_ver)
    }
}
impl<'a> Decode<'a> for RotatingSecrets {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.u8()?;
        Ok(Self {
            secrets: BTreeMap::decode(d)?,
            max_ver: d.u64()?,
        })
    }
}
