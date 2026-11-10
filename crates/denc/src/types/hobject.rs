// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! object_t, sobject_t, hobject_t, ghobject_t (spec 8.2-8.6).

use super::ids::{ShardId, SnapId};
use crate::buf::BufMut;
use crate::dec::{Decode, Decoder};
use crate::enc::{Encode, Encoder};
use crate::error::Result;
use core::cmp::Ordering;

/// object_t: arbitrary-byte name (string wire form), bytewise order.
pub type ObjectT = Vec<u8>;

/// sobject_t: oid, snap.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SObject {
    pub oid: ObjectT,
    pub snap: SnapId,
}
impl Encode for SObject {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.bytes(&self.oid)?;
        self.snap.encode(e)
    }
}
impl<'a> Decode<'a> for SObject {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(SObject {
            oid: d.bytes()?.to_vec(),
            snap: SnapId::decode(d)?,
        })
    }
}

/// hobject_t. `key` is empty when equal to `oid` (use [`Hobject::set_key`]).
#[derive(Debug, Clone, Eq)]
pub struct Hobject {
    pub key: Vec<u8>,
    pub oid: ObjectT,
    pub snap: SnapId,
    pub hash: u32,
    pub max: bool,
    pub nspace: Vec<u8>,
    pub pool: i64,
}

/// Table hash from the placement hash (32-bit hash of the name, well spread), snap and pool: no byte of the name buffers
/// is read to find a bucket. Objects that differ only in name / namespace / key share a bucket chain (equal placement
/// hash = a collision, rare); [`PartialEq`] decides identity, so a collision costs a compare, never a wrong match.
/// The MAX sentinel is hashed without the placement hash, like [`PartialEq`] compares it.
impl core::hash::Hash for Hobject {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        if !self.max {
            state.write_u32(self.hash);
        }
        state.write_u64(self.snap.0);
        state.write_i64(self.pool);
    }
}

/// Identity is the order's identity (`cmp == Equal`): the effective key counts (the key, or the oid when the key is
/// empty), so `{oid x, key x}` and `{oid x, key ""}` are the same object, and for the MAX sentinel the placement hash
/// does not (the order's key is the constant 0x1_0000_0000). Cheapest checks first: the placement hash separates
/// different names without touching the name buffers, and an empty `key` / `nspace` (the usual case) costs no byte
/// compare call at all.
impl PartialEq for Hobject {
    fn eq(&self, o: &Self) -> bool {
        fn same(a: &[u8], b: &[u8]) -> bool {
            a.len() == b.len() && (a.is_empty() || a == b)
        }
        self.max == o.max
            && (self.max || self.hash == o.hash)
            && self.snap == o.snap
            && self.pool == o.pool
            && same(&self.nspace, &o.nspace)
            && if self.key.is_empty() && o.key.is_empty() {
                true
            } else {
                same(self.eff_key(), o.eff_key())
            }
            && same(&self.oid, &o.oid)
    }
}
impl Default for Hobject {
    fn default() -> Self {
        Self::MIN()
    }
}

impl Hobject {
    pub const POOL_META: i64 = -1;
    #[expect(non_snake_case)]
    pub fn MIN() -> Self {
        Hobject {
            key: vec![],
            oid: vec![],
            snap: SnapId(0),
            hash: 0,
            max: false,
            nspace: vec![],
            pool: i64::MIN,
        }
    }
    #[expect(non_snake_case)]
    pub fn MAX() -> Self {
        Hobject {
            max: true,
            ..Self::MIN()
        }
    }
    pub fn new(oid: &[u8], snap: SnapId, hash: u32, pool: i64, nspace: &[u8]) -> Self {
        Hobject {
            key: vec![],
            oid: oid.to_vec(),
            snap,
            hash,
            max: false,
            nspace: nspace.to_vec(),
            pool,
        }
    }
    /// Set locator key; stored empty if equal to oid.
    pub fn set_key(&mut self, key: &[u8]) {
        self.key = if key == self.oid.as_slice() {
            vec![]
        } else {
            key.to_vec()
        };
    }
    /// Temp collection pool for logical pool `p` (involution).
    pub const fn temp_pool(p: i64) -> i64 {
        -2 - p
    }
    pub fn is_temp(&self) -> bool {
        self.pool <= -2 && self.pool != i64::MIN
    }
    /// Bit-reversed hash used for ordering; MAX is the 33-bit 0x1_0000_0000.
    pub fn bitwise_key(&self) -> u64 {
        if self.max {
            1 << 32
        } else {
            self.hash.reverse_bits() as u64
        }
    }
    fn eff_key(&self) -> &[u8] {
        if self.key.is_empty() {
            &self.oid
        } else {
            &self.key
        }
    }
    /// PG membership: logical pool equal and low `bits` of hash match seed.
    pub fn match_hash(&self, pool: i64, seed: u32, bits: u32) -> bool {
        let mask = if bits >= 32 {
            u32::MAX
        } else {
            (1u32 << bits) - 1
        };
        let lp = if self.is_temp() {
            Self::temp_pool(self.pool)
        } else {
            self.pool
        };
        lp == pool && (self.hash & mask) == (seed & mask)
    }
    pub(crate) fn encode_fields<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.bytes(&self.key)?;
        e.bytes(&self.oid)?;
        self.snap.encode(e)?;
        e.u32(self.hash)?;
        e.bool(self.max)?;
        e.bytes(&self.nspace)?;
        e.i64(self.pool)
    }
    /// Fields 1-7 with the pool -1 -> MIN fix-up (struct_v >= 4).
    pub(crate) fn decode_fields(d: &mut Decoder<'_>) -> Result<Self> {
        let mut h = Hobject {
            key: d.bytes()?.to_vec(),
            oid: d.bytes()?.to_vec(),
            snap: SnapId::decode(d)?,
            hash: d.u32()?,
            max: d.bool()?,
            nspace: d.bytes()?.to_vec(),
            pool: d.i64()?,
        };
        if h.pool == -1 && h.snap.0 == 0 && h.hash == 0 && !h.max && h.oid.is_empty() {
            h.pool = i64::MIN;
        }
        Ok(h)
    }
}

impl PartialOrd for Hobject {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Hobject {
    fn cmp(&self, o: &Self) -> Ordering {
        self.max
            .cmp(&o.max)
            .then(self.pool.cmp(&o.pool))
            .then(self.bitwise_key().cmp(&o.bitwise_key()))
            .then_with(|| self.nspace.cmp(&o.nspace))
            .then_with(|| {
                if self.key.is_empty() && o.key.is_empty() {
                    Ordering::Equal
                } else {
                    self.eff_key().cmp(o.eff_key())
                }
            })
            .then_with(|| self.oid.cmp(&o.oid))
            .then(self.snap.cmp(&o.snap))
    }
}

impl Encode for Hobject {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(4, 3, |e| self.encode_fields(e))
    }
}
impl<'a> Decode<'a> for Hobject {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(4, 4, |d, _| {
            let h = Hobject::decode_fields(d)?;
            Ok(if h.max { Hobject::MAX() } else { h })
        })
    }
}

/// ghobject_t: hobject + generation + shard + max.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ghobject {
    pub hobj: Hobject,
    pub generation: u64,
    pub shard: ShardId,
    pub max: bool,
}
impl Ghobject {
    pub const NO_GEN: u64 = u64::MAX;
    pub fn new(hobj: Hobject, generation: u64, shard: ShardId) -> Self {
        Ghobject {
            hobj,
            generation,
            shard,
            max: false,
        }
    }
    /// The live (generation `NO_GEN`) object `hobj` of `shard`.
    pub fn head(hobj: Hobject, shard: ShardId) -> Self {
        Self::new(hobj, Self::NO_GEN, shard)
    }
    #[expect(non_snake_case)]
    pub fn MIN() -> Self {
        Self::new(Hobject::MIN(), Self::NO_GEN, ShardId::NO_SHARD)
    }
    #[expect(non_snake_case)]
    pub fn MAX() -> Self {
        Ghobject {
            max: true,
            hobj: Hobject::MAX(),
            generation: Self::NO_GEN,
            shard: ShardId::NO_SHARD,
        }
    }
    /// pgmeta object of a PG.
    pub fn pgmeta(pool: i64, seed: u32, shard: ShardId) -> Self {
        Self::new(
            Hobject::new(b"", SnapId::NOSNAP, seed, pool, b""),
            Self::NO_GEN,
            shard,
        )
    }
    pub fn is_pgmeta(&self) -> bool {
        self.hobj.pool >= 0 && self.hobj.oid.is_empty()
    }
}
impl Default for Ghobject {
    fn default() -> Self {
        Self::MIN()
    }
}
impl PartialOrd for Ghobject {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Ghobject {
    fn cmp(&self, o: &Self) -> Ordering {
        self.max
            .cmp(&o.max)
            .then(self.shard.cmp(&o.shard))
            .then_with(|| self.hobj.cmp(&o.hobj))
            .then(self.generation.cmp(&o.generation))
    }
}
impl Encode for Ghobject {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(6, 3, |e| {
            self.hobj.encode_fields(e)?;
            e.u64(self.generation)?;
            self.shard.encode(e)?;
            e.bool(self.max)
        })
    }
}
impl<'a> Decode<'a> for Ghobject {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(4, 6, |d, v| {
            let hobj = Hobject::decode_fields(d)?;
            let (generation, shard) = if v >= 5 {
                (d.u64()?, ShardId::decode(d)?)
            } else {
                (Ghobject::NO_GEN, ShardId::NO_SHARD)
            };
            let max = if v >= 6 { d.bool()? } else { false };
            Ok(Ghobject {
                hobj,
                generation,
                shard,
                max,
            })
        })
    }
}
