// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! client_challenge / `key` computation for GET_AUTH_SESSION_KEY (spec sec 4).

use crate::envelope::{encode_hash, seal_wrapped};
use crate::error::{Error, Result};
use crate::key::{CryptoKey, KeyType, Usage};

/// Fresh random u64.
pub fn random_u64() -> Result<u64> {
    let mut b = [0u8; 8];
    aws_lc_rs::rand::fill(&mut b).map_err(|_| crate::Error::Rng)?;
    Ok(u64::from_le_bytes(b))
}

/// Fresh random version-4 uuid.
pub fn random_uuid_v4() -> Result<denc::types::Uuid> {
    let mut b = [0u8; 16];
    aws_lc_rs::rand::fill(&mut b).map_err(|_| crate::Error::Rng)?;
    Ok(denc::types::Uuid::v4_from(b))
}

/// `CephXChallengeBlob` bytes: server FIRST.
pub fn challenge_blob(server: u64, client: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&server.to_le_bytes());
    b[8..].copy_from_slice(&client.to_le_bytes());
    b
}

/// Result u64 `key` of CephXAuthenticate.
pub fn compute_key(principal: &CryptoKey, server: u64, client: u64) -> Result<u64> {
    let blob = challenge_blob(server, client);
    let enc: Vec<u8> = if principal.key_type() == KeyType::Aes {
        // wrapped envelope (4B len prefix + 32B ct); the four u64 words below include the prefix
        seal_wrapped(principal, Usage::TicketSessionKey, &blob)?
    } else {
        encode_hash(principal, &blob).to_vec()
    };
    let Some(head) = enc.get(..32) else {
        return Err(Error::Malformed("challenge key words"));
    };
    let mut words = [0u8; 32];
    words.copy_from_slice(head);
    Ok(words
        .as_chunks::<8>()
        .0
        .iter()
        .fold(0u64, |a, c| a ^ u64::from_le_bytes(*c)))
}
