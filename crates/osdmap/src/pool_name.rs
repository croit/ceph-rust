// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Byte-exact pool-name identity; RC-POOLNAME58. Display is diagnostic only.
use denc::{BufMut, Decode, Decoder, Encode, Encoder};

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolName(Vec<u8>);
impl PoolName {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn as_utf8(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.0)
    }
}
impl AsRef<[u8]> for PoolName {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl From<Vec<u8>> for PoolName {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}
impl From<String> for PoolName {
    fn from(value: String) -> Self {
        Self(value.into_bytes())
    }
}
impl From<&str> for PoolName {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}
impl From<&[u8]> for PoolName {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}
impl Encode for PoolName {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        self.0.encode(e)
    }
}
impl<'a> Decode<'a> for PoolName {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        Ok(Self(Vec::<u8>::decode(d)?))
    }
}
impl std::fmt::Display for PoolName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.as_utf8() {
            Ok(text) => {
                for c in text.chars() {
                    if c.is_control() || c == '\\' {
                        for c in c.escape_default() {
                            write!(f, "{c}")?;
                        }
                    } else {
                        write!(f, "{c}")?;
                    }
                }
            }
            Err(_) => {
                for &byte in &self.0 {
                    for c in std::ascii::escape_default(byte) {
                        write!(f, "{}", char::from(c))?;
                    }
                }
            }
        }
        Ok(())
    }
}
