// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Raw AES-CBC (no padding, caller supplies IV) and single-block ECB helpers on aws-lc-rs.

use aws_lc_rs::cipher::{
    AES_128, AES_256, Algorithm, DecryptingKey, DecryptionContext, EncryptingKey,
    EncryptionContext, UnboundCipherKey,
};
use aws_lc_rs::iv::FixedLength;

use crate::error::{Error, Result};

pub(crate) const BLOCK: usize = 16;

fn alg(key: &[u8]) -> Result<&'static Algorithm> {
    match key.len() {
        16 => Ok(&AES_128),
        32 => Ok(&AES_256),
        _ => Err(Error::BadKey("aes key length")),
    }
}

fn unbound(key: &[u8]) -> Result<UnboundCipherKey> {
    UnboundCipherKey::new(alg(key)?, key).map_err(|_| Error::BadKey("aes key"))
}

/// In-place CBC encrypt; `data.len() % 16 == 0`.
pub(crate) fn cbc_encrypt(key: &[u8], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    let k = EncryptingKey::cbc(unbound(key)?).map_err(|_| Error::BadKey("aes"))?;
    k.less_safe_encrypt(data, EncryptionContext::Iv128(FixedLength::from(iv)))
        .map_err(|_| Error::Malformed("cbc encrypt"))?;
    Ok(())
}

/// In-place CBC decrypt; `data.len() % 16 == 0`.
pub(crate) fn cbc_decrypt(key: &[u8], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    let k = DecryptingKey::cbc(unbound(key)?).map_err(|_| Error::BadKey("aes"))?;
    k.decrypt(data, DecryptionContext::Iv128(FixedLength::from(iv)))
        .map_err(|_| Error::Malformed("cbc decrypt"))?;
    Ok(())
}

/// ECB-decrypt one block.
pub(crate) fn ecb_decrypt_block(key: &[u8], block: &mut [u8; 16]) -> Result<()> {
    let k = DecryptingKey::ecb(unbound(key)?).map_err(|_| Error::BadKey("aes"))?;
    k.decrypt(block, DecryptionContext::None)
        .map_err(|_| Error::Malformed("ecb decrypt"))?;
    Ok(())
}
