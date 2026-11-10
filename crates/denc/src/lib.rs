// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! denc: Ceph wire encoding, sans-IO (spec: doc/spec/encoding.md).
//!
//! `Decoder<'a>` borrows the input; `Encoder<B>` writes into any [`BufMut`].
//! Features (connection feature mask) live in the encoder.

pub mod buf;
pub mod dec;
pub mod enc;
pub mod errno;
pub mod error;
pub mod features;
mod impls;
pub mod kv;
pub mod le;
pub mod types;

pub use buf::{BufMut, SliceBuf};
pub use dec::{Decode, Decoder, from_slice};
pub use enc::{Encode, Encoder, encode_exact, encode_exact_rope};
pub use error::{Error, Result};
pub use kv::{KvShape, SortedKv, SortedKvIter};

/// Encode into a fresh Vec with all features.
pub fn to_vec<T: Encode + ?Sized>(v: &T) -> Result<Vec<u8>> {
    v.encode_to_vec()
}
