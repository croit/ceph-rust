// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! coll_t (spec 8.7): u8 struct_v, no envelope.

use super::ids::SnapId;
use super::pg::SpgT;
use crate::buf::BufMut;
use crate::dec::{Decode, Decoder};
use crate::enc::{Encode, Encoder};
use crate::error::{Error, Result};
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CollT {
    Meta,
    Pg(SpgT),
    PgTemp(SpgT),
}

impl fmt::Display for CollT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CollT::Meta => f.write_str("meta"),
            CollT::Pg(p) => write!(f, "{p}_head"),
            CollT::PgTemp(p) => write!(f, "{p}_TEMP"),
        }
    }
}

impl Encode for CollT {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        match self {
            CollT::Meta => {
                e.u8(2)?;
                e.u8(0)?;
                SpgT::default().encode(e)?;
                SnapId::NOSNAP.encode(e)
            }
            CollT::Pg(p) => {
                e.u8(2)?;
                e.u8(2)?;
                p.encode(e)?;
                SnapId::NOSNAP.encode(e)
            }
            CollT::PgTemp(_) => {
                e.u8(3)?;
                e.bytes(self.to_string().as_bytes())
            }
        }
    }
}

impl<'a> Decode<'a> for CollT {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        match d.u8()? {
            2 => {
                let ty = d.u8()?;
                let pg = SpgT::decode(d)?;
                let _snap = SnapId::decode(d)?;
                match ty {
                    0 => Ok(CollT::Meta),
                    2 => Ok(CollT::Pg(pg)),
                    _ => Err(Error::BadValue("coll_t type")),
                }
            }
            3 => {
                let s = core::str::from_utf8(d.bytes()?).map_err(|_| Error::Utf8)?;
                if s == "meta" {
                    Ok(CollT::Meta)
                } else if let Some(p) = s.strip_suffix("_TEMP") {
                    Ok(CollT::PgTemp(SpgT::parse(p)?))
                } else if let Some(p) = s.strip_suffix("_head") {
                    Ok(CollT::Pg(SpgT::parse(p)?))
                } else {
                    Err(Error::BadValue("coll_t name"))
                }
            }
            v => Err(Error::VersionTooOld {
                version: v,
                oldest: 2,
            }),
        }
    }
}
