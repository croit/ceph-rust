// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! pg_t, spg_t, pg_shard_t (spec 8.7).

use super::ids::ShardId;
use crate::buf::BufMut;
use crate::dec::{Decode, Decoder};
use crate::enc::{Encode, Encoder};
use crate::error::{Error, Result};
use core::fmt;

/// pg_t: raw 17 bytes (u8 1, u64 pool, u32 seed, i32 -1). Order (pool, seed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PgT {
    pub pool: u64,
    pub seed: u32,
}
impl PgT {
    pub const fn new(pool: u64, seed: u32) -> Self {
        PgT { pool, seed }
    }
    /// Parse "<pool>.<seedhex>".
    pub fn parse(s: &str) -> Result<Self> {
        let (p, h) = s.split_once('.').ok_or(Error::BadValue("pg_t text"))?;
        Ok(PgT {
            pool: p.parse().map_err(|_| Error::BadValue("pg_t pool"))?,
            seed: u32::from_str_radix(h, 16).map_err(|_| Error::BadValue("pg_t seed"))?,
        })
    }
}
impl fmt::Display for PgT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:x}", self.pool, self.seed)
    }
}
impl Encode for PgT {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u8(1)?;
        e.u64(self.pool)?;
        e.u32(self.seed)?;
        e.i32(-1)
    }
}
impl<'a> Decode<'a> for PgT {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        if d.u8()? != 1 {
            return Err(Error::BadValue("pg_t version"));
        }
        let pool = d.u64()?;
        let seed = d.u32()?;
        d.skip(4)?;
        Ok(PgT { pool, seed })
    }
}

/// spg_t (v1, c1): pg_t + shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SpgT {
    pub pgid: PgT,
    pub shard: ShardId,
}
impl SpgT {
    /// Parse "<pg>" or "<pg>s<shard>".
    pub fn parse(s: &str) -> Result<Self> {
        match s.split_once('s') {
            Some((pg, sh)) => Ok(SpgT {
                pgid: PgT::parse(pg)?,
                shard: ShardId(sh.parse().map_err(|_| Error::BadValue("spg_t shard"))?),
            }),
            None => Ok(SpgT {
                pgid: PgT::parse(s)?,
                shard: ShardId::NO_SHARD,
            }),
        }
    }
}
impl fmt::Display for SpgT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.shard == ShardId::NO_SHARD {
            write!(f, "{}", self.pgid)
        } else {
            write!(f, "{}s{}", self.pgid, self.shard.0)
        }
    }
}
impl Encode for SpgT {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            self.pgid.encode(e)?;
            self.shard.encode(e)
        })
    }
}
impl<'a> Decode<'a> for SpgT {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            Ok(SpgT {
                pgid: PgT::decode(d)?,
                shard: ShardId::decode(d)?,
            })
        })
    }
}

/// pg_shard_t (v1, c1): i32 osd, i8 shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PgShard {
    pub osd: i32,
    pub shard: ShardId,
}
impl PgShard {
    pub const NO_OSD: i32 = 0x7fff_ffff;
}
impl Default for PgShard {
    fn default() -> Self {
        PgShard {
            osd: -1,
            shard: ShardId::NO_SHARD,
        }
    }
}
impl Encode for PgShard {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            e.i32(self.osd)?;
            self.shard.encode(e)
        })
    }
}
impl<'a> Decode<'a> for PgShard {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            Ok(PgShard {
                osd: d.i32()?,
                shard: ShardId::decode(d)?,
            })
        })
    }
}
