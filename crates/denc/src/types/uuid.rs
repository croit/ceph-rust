// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! uuid_d / ceph_fsid: 16 raw bytes (spec 7.1).

use crate::buf::BufMut;
use crate::dec::{Decode, Decoder};
use crate::enc::{Encode, Encoder};
use crate::error::{Error, Result};
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Uuid(pub [u8; 16]);
pub type Fsid = Uuid;

impl Uuid {
    /// Version-4 (random) uuid from 16 random bytes: sets the version and variant bits.
    pub fn v4_from(mut b: [u8; 16]) -> Self {
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        Uuid(b)
    }

    /// Parse 8-4-4-4-12 hex text.
    pub fn parse(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        if b.len() != 36 {
            return Err(Error::BadValue("uuid length"));
        }
        let mut out = [0u8; 16];
        let mut n = 0;
        let mut i = 0;
        while i < 36 {
            if matches!(i, 8 | 13 | 18 | 23) {
                if b[i] != b'-' {
                    return Err(Error::BadValue("uuid dash"));
                }
                i += 1;
                continue;
            }
            let hi = hex(b[i])?;
            let lo = hex(*b.get(i + 1).ok_or(Error::BadValue("uuid"))?)?;
            out[n] = hi << 4 | lo;
            n += 1;
            i += 2;
        }
        Ok(Uuid(out))
    }
}
fn hex(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::BadValue("uuid hex")),
    }
}
impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
/// Ceph orders uuid_d by textual form; lowercase hex preserves byte order.
impl PartialOrd for Uuid {
    fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Uuid {
    fn cmp(&self, o: &Self) -> core::cmp::Ordering {
        self.0.cmp(&o.0)
    }
}
impl Encode for Uuid {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.raw(&self.0)
    }
}
impl<'a> Decode<'a> for Uuid {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Uuid(d.array()?))
    }
}
