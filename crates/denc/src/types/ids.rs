// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Small id types: epoch, snapid_t, shard_id_t, eversion_t, osd_reqid_t.

use super::entity::EntityName;
use crate::buf::BufMut;
use crate::dec::{Decode, Decoder};
use crate::enc::{Encode, Encoder};
use crate::error::Result;
use core::cmp::Ordering;
use core::fmt;

pub type Epoch = u32;
pub type Version = u64;

/// snapid_t: raw u64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SnapId(pub u64);
impl SnapId {
    pub const NOSNAP: SnapId = SnapId(u64::MAX - 1);
    pub const SNAPDIR: SnapId = SnapId(u64::MAX);
    pub const MAXSNAP: SnapId = SnapId(u64::MAX - 2);
}
impl fmt::Display for SnapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            SnapId::NOSNAP => f.write_str("head"),
            SnapId::SNAPDIR => f.write_str("snapdir"),
            SnapId(n) => write!(f, "{n:x}"),
        }
    }
}
impl Encode for SnapId {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u64(self.0)
    }
}
impl<'a> Decode<'a> for SnapId {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(SnapId(d.u64()?))
    }
}

/// shard_id_t: raw i8, NO_SHARD = -1. Signed order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardId(pub i8);
impl ShardId {
    pub const NO_SHARD: ShardId = ShardId(-1);
}
impl Default for ShardId {
    fn default() -> Self {
        Self::NO_SHARD
    }
}
impl Encode for ShardId {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.i8(self.0)
    }
}
impl<'a> Decode<'a> for ShardId {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(ShardId(d.i8()?))
    }
}

/// eversion_t: wire = u64 version, u32 epoch; order = epoch then version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Eversion {
    pub version: Version,
    pub epoch: Epoch,
}
impl Eversion {
    pub const MAX: Eversion = Eversion {
        version: u64::MAX,
        epoch: u32::MAX,
    };
    pub const fn new(epoch: Epoch, version: Version) -> Self {
        Eversion { version, epoch }
    }
    /// pglog/omap key form: epoch (10 digits) '.' version (20 digits).
    pub fn key_string(&self) -> String {
        String::from_utf8(self.key_bytes().to_vec()).expect("digits")
    }
    /// [`Self::key_string`] without formatting machinery: 31 ASCII bytes.
    pub fn key_bytes(&self) -> [u8; 31] {
        let mut b = [b'0'; 31];
        let (mut e, mut v) = (self.epoch, self.version);
        for i in (0..10).rev() {
            b[i] = b'0' + (e % 10) as u8;
            e /= 10;
        }
        b[10] = b'.';
        for i in (11..31).rev() {
            b[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        b
    }
}
impl PartialOrd for Eversion {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Eversion {
    fn cmp(&self, o: &Self) -> Ordering {
        (self.epoch, self.version).cmp(&(o.epoch, o.version))
    }
}
impl fmt::Display for Eversion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}'{}", self.epoch, self.version)
    }
}
impl Encode for Eversion {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u64(self.version)?;
        e.u32(self.epoch)
    }
}
impl<'a> Decode<'a> for Eversion {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        let version = d.u64()?;
        let epoch = d.u32()?;
        Ok(Eversion { version, epoch })
    }
}

/// osd_reqid_t (v2, compat 2): name, tid, inc. Order (name, inc, tid).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct OsdReqId {
    pub name: EntityName,
    pub tid: u64,
    pub inc: i32,
}
impl PartialOrd for OsdReqId {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for OsdReqId {
    fn cmp(&self, o: &Self) -> Ordering {
        (self.name, self.inc, self.tid).cmp(&(o.name, o.inc, o.tid))
    }
}
impl Encode for OsdReqId {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(2, 2, |e| {
            self.name.encode(e)?;
            e.u64(self.tid)?;
            e.i32(self.inc)
        })
    }
}
impl<'a> Decode<'a> for OsdReqId {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(2, 2, |d, _| {
            Ok(OsdReqId {
                name: EntityName::decode(d)?,
                tid: d.u64()?,
                inc: d.i32()?,
            })
        })
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn key_bytes_equals_the_formatted_key() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut cases = vec![
            (0u32, 0u64),
            (1, 1),
            (u32::MAX, u64::MAX),
            (999_999_999, 9_999_999_999_999_999_999),
            (10, 10),
        ];
        for _ in 0..2000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            cases.push(((x >> 32) as u32 >> (x % 32), x >> (x % 64)));
        }
        for (e, v) in cases {
            let k = Eversion::new(e, v);
            assert_eq!(
                String::from_utf8(k.key_bytes().to_vec()).unwrap(),
                format!("{e:010}.{v:020}")
            );
            assert_eq!(k.key_string(), format!("{e:010}.{v:020}"));
        }
    }
}
