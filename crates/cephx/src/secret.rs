// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! connection_secret layout (spec sec 8.5).

use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const CONNECTION_SECRET_LEN: usize = 64;

#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionSecret(Zeroizing<Vec<u8>>);

impl core::fmt::Debug for ConnectionSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ConnectionSecret(len={})", self.0.len())
    }
}

impl ConnectionSecret {
    /// Server side: 64 random bytes (only when con_mode == SECURE).
    pub fn generate() -> Result<Self> {
        let mut b = Zeroizing::new(vec![0u8; CONNECTION_SECRET_LEN]);
        aws_lc_rs::rand::fill(&mut b).map_err(|_| Error::Rng)?;
        Ok(Self(b))
    }

    /// Empty = CRC mode (None). Otherwise must be >= 40 bytes (64 expected).
    pub fn from_bytes(b: &[u8]) -> Result<Option<Self>> {
        if b.is_empty() {
            return Ok(None);
        }
        if b.len() < 40 {
            return Err(Error::Malformed("connection secret < 40"));
        }
        Ok(Some(Self(Zeroizing::new(b.to_vec()))))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// AES-128-GCM key: [0,16).
    pub fn gcm_key(&self) -> &[u8; 16] {
        self.0[0..16].try_into().unwrap()
    }
    /// Nonce base `[16,28)` as written (client rx / acceptor tx).
    pub fn nonce_a(&self) -> &[u8; 12] {
        self.0[16..28].try_into().unwrap()
    }
    /// Nonce base `[28,40)` as written (client tx / acceptor rx).
    pub fn nonce_b(&self) -> &[u8; 12] {
        self.0[28..40].try_into().unwrap()
    }
    /// (rx, tx) nonce bases for the client (as written).
    pub fn client_rx_tx(&self) -> (&[u8; 12], &[u8; 12]) {
        (self.nonce_a(), self.nonce_b())
    }
    /// (rx, tx) for the accepting side (swapped).
    pub fn acceptor_rx_tx(&self) -> (&[u8; 12], &[u8; 12]) {
        (self.nonce_b(), self.nonce_a())
    }
}
