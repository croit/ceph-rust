// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Type 2: AES256KRB5 (spec sec 2.4). AES-256-CBC-CTS (CS3) + truncated HMAC-SHA384.

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use zeroize::Zeroizing;

use crate::cipher_aes::{BLOCK, cbc_decrypt, cbc_encrypt, ecb_decrypt_block};
use crate::error::{Error, Result};

const MAC_LEN: usize = 24;
const ZERO_IV: [u8; 16] = [0; 16];

/// Derived `(Ki, Ke)` for one usage. Exposed for test vectors.
pub fn derive(secret: &[u8], usage: u32) -> (Zeroizing<[u8; 24]>, Zeroizing<[u8; 32]>) {
    let k = hmac::Key::new(hmac::HMAC_SHA384, secret);
    // writes the first `out.len()` bytes of the derivation straight into the zeroizing output (no stray copy)
    let one = |ty: u8, out: &mut [u8]| {
        let mut msg = [0u8; 14];
        msg[..4].copy_from_slice(&1u32.to_be_bytes());
        msg[4..8].copy_from_slice(&usage.to_be_bytes());
        msg[8] = ty;
        msg[10..].copy_from_slice(&((out.len() * 8) as u32).to_be_bytes());
        out.copy_from_slice(&hmac::sign(&k, &msg).as_ref()[..out.len()]);
    };
    let mut ki = Zeroizing::new([0u8; 24]);
    one(0x55, &mut *ki);
    let mut ke = Zeroizing::new([0u8; 32]);
    one(0xAA, &mut *ke);
    (ki, ke)
}

/// CS3 CTS encrypt, iv = 0. `data.len() >= 16`; output length == input length.
pub(crate) fn cts_encrypt(ke: &[u8], data: &mut [u8]) -> Result<()> {
    let m = data.len();
    if m < BLOCK {
        return Err(Error::Malformed("cts input < 16"));
    }
    if m == BLOCK {
        return cbc_encrypt(ke, &ZERO_IV, data);
    }
    let padded = m.div_ceil(BLOCK) * BLOCK;
    let d = m - (padded - BLOCK); // 1..=16: bytes in last piece
    let mut buf = Zeroizing::new(vec![0u8; padded]);
    buf[..m].copy_from_slice(data);
    cbc_encrypt(ke, &ZERO_IV, &mut buf)?;
    let n = padded / BLOCK;
    // out = C1..C(n-2) | C(n) | C(n-1)[..d]
    let head = BLOCK * (n - 2);
    data[..head].copy_from_slice(&buf[..head]);
    let cn1 = &buf[head..head + BLOCK];
    let cn = &buf[head + BLOCK..];
    data[head..head + BLOCK].copy_from_slice(cn);
    data[head + BLOCK..].copy_from_slice(&cn1[..d]);
    Ok(())
}

/// CS3 CTS decrypt, iv = 0.
pub(crate) fn cts_decrypt(ke: &[u8], data: &mut [u8]) -> Result<()> {
    let m = data.len();
    if m < BLOCK {
        return Err(Error::Malformed("cts input < 16"));
    }
    if m == BLOCK {
        return cbc_decrypt(ke, &ZERO_IV, data);
    }
    let padded = m.div_ceil(BLOCK) * BLOCK;
    let n = padded / BLOCK;
    let d = m - (padded - BLOCK);
    let mut x: [u8; 16] = data[BLOCK * (n - 2)..BLOCK * (n - 1)].try_into().unwrap();
    let y = &data[BLOCK * (n - 1)..];
    ecb_decrypt_block(ke, &mut x)?; // x = D = Dec(C_n)
    let mut buf = Zeroizing::new(vec![0u8; padded]);
    buf[..BLOCK * (n - 2)].copy_from_slice(&data[..BLOCK * (n - 2)]);
    // C(n-1) = Y | D[d..]
    let cn1_off = BLOCK * (n - 2);
    buf[cn1_off..cn1_off + d].copy_from_slice(y);
    buf[cn1_off + d..cn1_off + BLOCK].copy_from_slice(&x[d..]);
    buf[BLOCK * (n - 1)..].copy_from_slice(&data[BLOCK * (n - 2)..BLOCK * (n - 1)]);
    cbc_decrypt(ke, &ZERO_IV, &mut buf)?;
    data.copy_from_slice(&buf[..m]);
    Ok(())
}

pub(crate) fn encrypt(secret: &[u8], usage: u32, plain: &[u8]) -> Result<Vec<u8>> {
    let (ki, ke) = derive(secret, usage);
    let mut c = Vec::with_capacity(BLOCK + plain.len() + MAC_LEN);
    c.resize(BLOCK, 0);
    aws_lc_rs::rand::fill(&mut c[..BLOCK]).map_err(|_| Error::Rng)?;
    c.extend_from_slice(plain);
    cts_encrypt(&*ke, &mut c)?;
    let h = mac(&*ki, &c);
    c.extend_from_slice(&h);
    Ok(c)
}

fn mac(ki: &[u8], c: &[u8]) -> [u8; MAC_LEN] {
    let k = hmac::Key::new(hmac::HMAC_SHA384, ki);
    let mut ctx = hmac::Context::with_key(&k);
    ctx.update(&ZERO_IV);
    ctx.update(c);
    let t = ctx.sign();
    t.as_ref()[..MAC_LEN].try_into().unwrap()
}

pub(crate) fn decrypt(secret: &[u8], usage: u32, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if ct.len() < BLOCK + MAC_LEN {
        return Err(Error::Malformed("aes256krb5 input < 40"));
    }
    let (ki, ke) = derive(secret, usage);
    let (c, h) = ct.split_at(ct.len() - MAC_LEN);
    if verify_slices_are_equal(&mac(&*ki, c), h).is_err() {
        return Err(Error::Auth("hmac mismatch"));
    }
    let mut p = Zeroizing::new(c.to_vec());
    cts_decrypt(&*ke, &mut p)?;
    p.drain(..BLOCK);
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3962 appendix B (AES-128, CS3, iv 0): 17-byte and 31/32/47/48-byte inputs.
    #[test]
    fn rfc3962_cts() {
        let key = *b"chicken teriyaki";
        let pt = b"I would like the General Gau's Chicken, please, and wonton soup.";
        let cases: [(usize, &str); 3] = [
            (17, "c6353568f2bf8cb4d8a580362da7ff7f97"),
            (
                31,
                "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
            ),
            (
                32,
                "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
            ),
        ];
        for (n, exp) in cases {
            let mut d = pt[..n].to_vec();
            cts_encrypt(&key, &mut d).unwrap();
            let h: String = d.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(h, exp, "n={n}");
            cts_decrypt(&key, &mut d).unwrap();
            assert_eq!(&d[..], &pt[..n]);
        }
    }
}
