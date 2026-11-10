// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! object_locator_t (spec 8.9).

use crate::buf::BufMut;
use crate::dec::{Decode, Decoder};
use crate::enc::{Encode, Encoder};
use crate::error::Result;

/// Owned locator used by decoders and existing callers.
pub type ObjectLocator = ObjectLocatorStorage<Vec<u8>>;

/// Locator whose immutable identity bytes can be borrowed or retained by a
/// caller-selected owner. Wire layout is independent of byte storage.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectLocatorStorage<B> {
    pub pool: i64,
    pub key: B,
    pub nspace: B,
    /// -1 = unset; non-(-1) implies empty key.
    pub hash: i64,
}
impl<B: Default> Default for ObjectLocatorStorage<B> {
    fn default() -> Self {
        ObjectLocatorStorage {
            pool: -1,
            key: B::default(),
            nspace: B::default(),
            hash: -1,
        }
    }
}
impl<B> ObjectLocatorStorage<B> {
    pub fn is_empty(&self) -> bool {
        self.pool == -1
    }
}
impl<S: AsRef<[u8]>> Encode for ObjectLocatorStorage<S> {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        let compat = if self.hash != -1 { 6 } else { 3 };
        e.versioned(6, compat, |e| {
            e.i64(self.pool)?;
            e.i32(-1)?;
            e.bytes(self.key.as_ref())?;
            e.bytes(self.nspace.as_ref())?;
            e.i64(self.hash)
        })
    }
}
impl<'a> Decode<'a> for ObjectLocator {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(3, 6, |d, v| {
            let pool = d.i64()?;
            d.skip(4)?;
            let key = d.bytes()?.to_vec();
            let nspace = if v >= 5 {
                d.bytes()?.to_vec()
            } else {
                Vec::new()
            };
            let hash = if v >= 6 { d.i64()? } else { -1 };
            Ok(ObjectLocator {
                pool,
                key,
                nspace,
                hash,
            })
        })
    }
}
