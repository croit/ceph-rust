// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cephx (spec/cephx.md): crypto layer (keys, ciphers AES + AES256KRB5, envelope, challenge,
//! keyring), wire structs, and sans-IO state machines: [`monclient::MonAuthClient`],
//! [`authorizer::Authorizer`], [`verifier::AuthorizerVerifier`], plus method NONE variants in
//! [`none`] and mode negotiation in [`modes`]. Times are unix seconds passed in by the caller.

pub mod authorizer;
pub mod challenge;
pub mod envelope;
pub mod error;
pub mod key;
pub mod keyring;
pub mod modes;
pub mod monclient;
pub mod none;
pub mod secret;
pub mod ticket;
pub mod types;
pub mod verifier;

mod cipher_aes;
mod cipher_krb5;

pub use authorizer::Authorizer;
pub use denc::types::UTime;
pub use error::Error;
pub use key::{CryptoKey, KeyType, Usage, krb5_derive};
pub use monclient::{MonAuthClient, MonAuthConfig, MonReply, MonRequest};
pub use verifier::{AuthorizerVerifier, Verdict, VerifiedPeer};

/// `AUTH_ENC_MAGIC` (spec sec 1).
pub const AUTH_ENC_MAGIC: u64 = 0xff00_9cad_8826_aa55;
