// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! CryptoKey (spec sec 2.1) and Type 1 AES (sec 2.3) / dispatch.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use core::fmt;
use zeroize::Zeroizing;

use crate::cipher_aes::{BLOCK, cbc_decrypt, cbc_encrypt};
use crate::cipher_krb5;
use crate::error::{Error, Result};
use denc::types::UTime;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};

/// Fixed CBC IV for type 1.
pub const CEPH_AES_IV: &[u8; 16] = b"cephsageyudagreg";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KeyType {
    None = 0,
    Aes = 1,
    Aes256Krb5 = 2,
}

impl KeyType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Aes),
            2 => Some(Self::Aes256Krb5),
            _ => None,
        }
    }

    /// Secret length the cipher needs (16 AES-128, 32 AES-256); 0 for type none.
    pub fn min_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes => 16,
            Self::Aes256Krb5 => 32,
        }
    }
}

/// Key usage tags (spec sec 1). Used by type 2 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Usage {
    AuthConnectionSecret = 0x03,
    TicketSessionKey = 0x04,
    TicketBlob = 0x05,
    Authorize = 0x10,
    AuthorizeChallenge = 0x11,
    AuthorizeReply = 0x12,
    RotatingSecret = 0x20,
    TicketInfo = 0x30,
}

#[derive(Clone)]
pub struct CryptoKey {
    ty: KeyType,
    created: UTime,
    secret: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for CryptoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoKey")
            .field("type", &self.ty)
            .field("created", &self.created)
            .field("secret_len", &self.secret.len())
            .finish()
    }
}

impl PartialEq for CryptoKey {
    fn eq(&self, o: &Self) -> bool {
        self.ty == o.ty
            && self.created == o.created
            && aws_lc_rs::constant_time::verify_slices_are_equal(&self.secret, &o.secret).is_ok()
    }
}
impl Eq for CryptoKey {}

impl CryptoKey {
    pub fn new(ty: KeyType, created: UTime, secret: &[u8]) -> Self {
        Self {
            ty,
            created,
            secret: Zeroizing::new(secret.to_vec()),
        }
    }

    /// Random key as the mon would generate (16 / 32 bytes). Type None -> empty.
    pub fn generate(ty: KeyType, created: UTime) -> Result<Self> {
        let mut s = Zeroizing::new(vec![0u8; ty.min_len()]);
        aws_lc_rs::rand::fill(&mut s).map_err(|_| Error::Rng)?;
        Ok(Self {
            ty,
            created,
            secret: s,
        })
    }

    pub fn key_type(&self) -> KeyType {
        self.ty
    }
    pub fn created(&self) -> UTime {
        self.created
    }
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
    pub fn is_empty(&self) -> bool {
        self.secret.is_empty()
    }

    /// Wire encoding (spec sec 2.1). Fails when the secret is longer than the u16 wire length, so a
    /// truncated encoding can never be produced.
    /// The buffer is sized up front and handed straight to `Zeroizing`: no growth copy and no shared scratch buffer
    /// ever holds the secret.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut e = Encoder::with_capacity(WIRE_HEADER_LEN + self.secret.len());
        let encoded = Encode::encode(self, &mut e);
        let out = Zeroizing::new(e.into_vec());
        encoded?;
        Ok(out)
    }

    /// Lenient: trailing bytes ignored.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        Ok(<Self as Decode>::decode(&mut Decoder::new(b))?)
    }

    /// Base64 (standard, padded) of the wire encoding; keyring / `key` config format.
    pub fn to_base64(&self) -> Result<String> {
        Ok(STANDARD.encode(&**self.to_bytes()?))
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let raw = Zeroizing::new(
            STANDARD
                .decode(s.trim())
                .map_err(|_| Error::Malformed("base64"))?,
        );
        Self::from_bytes(&raw)
    }

    fn check_usable(&self) -> Result<()> {
        match self.ty {
            KeyType::None => Err(Error::BadKey("type none refused")),
            t if self.secret.len() < t.min_len() => Err(Error::BadKey("empty/short key")),
            _ => Ok(()),
        }
    }

    /// Raw cipher encrypt (no envelope). Type 1 ignores `usage`.
    pub fn encrypt(&self, plain: &[u8], usage: Usage) -> Result<Vec<u8>> {
        self.check_usable()?;
        match self.ty {
            KeyType::Aes => {
                let pad = BLOCK - plain.len() % BLOCK;
                let mut buf = Vec::with_capacity(plain.len() + pad);
                buf.extend_from_slice(plain);
                buf.resize(plain.len() + pad, pad as u8);
                cbc_encrypt(&self.secret[..16], CEPH_AES_IV, &mut buf)?;
                Ok(buf)
            }
            KeyType::Aes256Krb5 => cipher_krb5::encrypt(&self.secret, usage as u32, plain),
            KeyType::None => unreachable!(),
        }
    }

    /// Raw cipher decrypt (no envelope).
    pub fn decrypt(&self, ct: &[u8], usage: Usage) -> Result<Zeroizing<Vec<u8>>> {
        self.check_usable()?;
        match self.ty {
            KeyType::Aes => {
                if ct.len() < BLOCK || !ct.len().is_multiple_of(BLOCK) {
                    return Err(Error::Malformed("aes input length"));
                }
                let mut buf = Zeroizing::new(ct.to_vec());
                cbc_decrypt(&self.secret[..16], CEPH_AES_IV, &mut buf)?;
                let pad = (*buf.last().unwrap() as usize).min(BLOCK);
                let n = buf.len() - pad;
                buf.truncate(n);
                Ok(buf)
            }
            KeyType::Aes256Krb5 => cipher_krb5::decrypt(&self.secret, usage as u32, ct),
            KeyType::None => unreachable!(),
        }
    }
}

/// Derived keys for tests / diagnostics.
pub use cipher_krb5::derive as krb5_derive;

/// Wire encoding (spec sec 2.1): u16 type, utime created, u16 len, secret.
/// Wire bytes before the secret: type (u16), created (utime, 8 bytes), secret length (u16).
const WIRE_HEADER_LEN: usize = 2 + 8 + 2;

impl Encode for CryptoKey {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u16(self.ty as u16)?;
        self.created.encode(e)?;
        e.u16(u16::try_from(self.secret.len()).map_err(|_| denc::Error::TooLong)?)?;
        e.raw(&self.secret)
    }
}

impl<'a> Decode<'a> for CryptoKey {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        let ty = KeyType::from_u16(d.u16()?).ok_or(denc::Error::BadValue("unknown key type"))?;
        let created = UTime::decode(d)?;
        let n = d.u16()? as usize;
        let s = d.take(n)?;
        if n != 0 && n < ty.min_len() {
            return Err(denc::Error::BadValue("secret shorter than its key type"));
        }
        Ok(Self::new(ty, created, s))
    }
}
