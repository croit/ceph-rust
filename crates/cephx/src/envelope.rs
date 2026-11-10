// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! encode_encrypt / decode_decrypt envelope (spec sec 2.5).

use denc::{Decoder, Encode, Encoder};
use zeroize::Zeroizing;

use crate::AUTH_ENC_MAGIC;
use crate::error::{Error, Result};
use crate::key::{CryptoKey, Usage};

/// RAW form (`enc_bl`): ct only. `body` = encoded struct T.
pub fn seal_raw(key: &CryptoKey, usage: Usage, body: &[u8]) -> Result<Vec<u8>> {
    let mut e = Encoder::with_capacity(9 + body.len());
    e.u8(1)?;
    e.u64(AUTH_ENC_MAGIC)?;
    e.raw(body)?;
    let p = Zeroizing::new(e.into_vec());
    key.encrypt(&p, usage)
}

/// WRAPPED form (`encode_encrypt`): u32 len + ct.
pub fn seal_wrapped(key: &CryptoKey, usage: Usage, body: &[u8]) -> Result<Vec<u8>> {
    let ct = seal_raw(key, usage, body)?;
    let mut e = Encoder::with_capacity(4 + ct.len());
    e.bytes(&ct)?;
    Ok(e.into_vec())
}

/// RAW seal of a struct.
pub fn seal_raw_t<T: Encode>(key: &CryptoKey, usage: Usage, t: &T) -> Result<Vec<u8>> {
    let b = Zeroizing::new(t.encode_to_vec()?);
    seal_raw(key, usage, &b)
}

/// WRAPPED seal of a struct.
pub fn seal_wrapped_t<T: Encode>(key: &CryptoKey, usage: Usage, t: &T) -> Result<Vec<u8>> {
    let b = Zeroizing::new(t.encode_to_vec()?);
    seal_wrapped(key, usage, &b)
}

/// Decrypt RAW ct; verify magic; return bytes after the magic (T plus slack).
pub fn open_raw(key: &CryptoKey, usage: Usage, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut p = key.decrypt(ct, usage)?;
    if p.len() < 9 {
        return Err(Error::Malformed("envelope too short"));
    }
    let mut d = Decoder::new(&p);
    d.u8()?; // struct_v: not checked
    if d.u64()? != AUTH_ENC_MAGIC {
        return Err(Error::Auth("bad magic"));
    }
    p.drain(..9);
    Ok(p)
}

/// Decrypt WRAPPED form from a decoder (consumes u32 len + ct).
pub fn open_wrapped(
    key: &CryptoKey,
    usage: Usage,
    d: &mut Decoder<'_>,
) -> Result<Zeroizing<Vec<u8>>> {
    let ct = d.bytes()?;
    open_raw(key, usage, ct)
}

/// RAW open + decode T (slack ignored).
pub fn open_raw_t<T: for<'a> denc::Decode<'a>>(
    key: &CryptoKey,
    usage: Usage,
    ct: &[u8],
) -> Result<T> {
    let p = open_raw(key, usage, ct)?;
    Ok(T::decode(&mut Decoder::new(&p))?)
}

/// WRAPPED open + decode T (slack ignored).
pub fn open_wrapped_t<T: for<'a> denc::Decode<'a>>(
    key: &CryptoKey,
    usage: Usage,
    d: &mut Decoder<'_>,
) -> Result<T> {
    let p = open_wrapped(key, usage, d)?;
    Ok(T::decode(&mut Decoder::new(&p))?)
}

/// Seal a `string` (u32 len + bytes) WRAPPED, e.g. connection secret (usage 0x03).
pub fn seal_string_wrapped(key: &CryptoKey, usage: Usage, s: &[u8]) -> Result<Vec<u8>> {
    let mut e = Encoder::new();
    e.bytes(s)?;
    let b = Zeroizing::new(e.into_vec());
    seal_wrapped(key, usage, &b)
}

/// Open a WRAPPED envelope holding a `string`; returns the string bytes.
pub fn open_string_wrapped(
    key: &CryptoKey,
    usage: Usage,
    d: &mut Decoder<'_>,
) -> Result<Zeroizing<Vec<u8>>> {
    let body = open_wrapped(key, usage, d)?;
    let mut bd = Decoder::new(&body);
    Ok(Zeroizing::new(bd.bytes()?.to_vec()))
}

/// Hash variant `encode_hash`: HMAC-SHA256(secret raw, encode(T)).
pub fn encode_hash(key: &CryptoKey, body: &[u8]) -> [u8; 32] {
    let k = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key.secret());
    aws_lc_rs::hmac::sign(&k, body).as_ref().try_into().unwrap()
}
