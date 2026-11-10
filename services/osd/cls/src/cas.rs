// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `cas` (spec/cls_cas.md): chunk objects with a back-reference set in xattr `chunk_refs`.

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use crate::registry::Reply;
use denc::types::Hobject;
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error};
use std::collections::BTreeMap;

pub const ATTR: &str = "chunk_refs";
pub const FLAG_VERIFY: u64 = 1;

const T_OBJECT: u8 = 1;
const T_HASH: u8 = 2;
const T_POOL: u8 = 4;
const T_COUNT: u8 = 5;

/// `chunk_refs_t`: the reference set at one of four resolutions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkRefs {
    /// Sorted multiset of referencing objects.
    ByObject(Vec<Hobject>),
    ByHash {
        total: u64,
        hash_bits: u32,
        map: BTreeMap<(i64, u32), u64>,
    },
    ByPool {
        total: u64,
        map: BTreeMap<i64, u64>,
    },
    Count(u64),
}
impl Default for ChunkRefs {
    fn default() -> Self {
        ChunkRefs::ByObject(Vec::new())
    }
}

fn mask(bits: u32) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX >> (32 - bits.min(32))
    }
}

impl ChunkRefs {
    pub fn is_empty(&self) -> bool {
        match self {
            ChunkRefs::ByObject(v) => v.is_empty(),
            ChunkRefs::ByHash { map, .. } => map.is_empty(),
            ChunkRefs::ByPool { map, .. } => map.is_empty(),
            ChunkRefs::Count(t) => *t == 0,
        }
    }
    pub fn count(&self) -> u64 {
        match self {
            ChunkRefs::ByObject(v) => v.len() as u64,
            ChunkRefs::ByHash { total, .. } | ChunkRefs::ByPool { total, .. } => *total,
            ChunkRefs::Count(t) => *t,
        }
    }
    pub fn get(&mut self, o: &Hobject) {
        match self {
            ChunkRefs::ByObject(v) => {
                let at = v.partition_point(|x| x <= o);
                v.insert(at, o.clone());
            }
            ChunkRefs::ByHash {
                total,
                hash_bits,
                map,
            } => {
                let k = (o.pool, o.hash & mask(*hash_bits));
                let n = map.entry(k).or_insert(0);
                *n = n.wrapping_add(1);
                *total = total.wrapping_add(1);
            }
            ChunkRefs::ByPool { total, map } => {
                let n = map.entry(o.pool).or_insert(0);
                *n = n.wrapping_add(1);
                *total = total.wrapping_add(1);
            }
            ChunkRefs::Count(t) => *t = t.wrapping_add(1),
        }
    }
    /// False if there was no such reference. A non-BY_OBJECT set that reaches zero resets to
    /// an empty BY_OBJECT set (full resolution).
    pub fn put(&mut self, o: &Hobject) -> bool {
        let found = match self {
            ChunkRefs::ByObject(v) => match v.iter().position(|x| x == o) {
                Some(i) => {
                    v.remove(i);
                    true
                }
                None => false,
            },
            ChunkRefs::ByHash {
                total,
                hash_bits,
                map,
            } => {
                let k = (o.pool, o.hash & mask(*hash_bits));
                match map.get_mut(&k) {
                    Some(n) => {
                        *n = n.wrapping_sub(1);
                        if *n == 0 {
                            map.remove(&k);
                        }
                        *total = total.wrapping_sub(1);
                        true
                    }
                    None => false,
                }
            }
            ChunkRefs::ByPool { total, map } => match map.get_mut(&o.pool) {
                Some(n) => {
                    *n = n.wrapping_sub(1);
                    if *n == 0 {
                        map.remove(&o.pool);
                    }
                    *total = total.wrapping_sub(1);
                    true
                }
                None => false,
            },
            ChunkRefs::Count(t) => {
                if *t == 0 {
                    false
                } else {
                    *t -= 1;
                    true
                }
            }
        };
        if !matches!(self, ChunkRefs::ByObject(_)) && self.count() == 0 {
            *self = ChunkRefs::default();
        }
        found
    }
}

impl Encode for ChunkRefs {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| match self {
            ChunkRefs::ByObject(v) => {
                e.u8(T_OBJECT)?;
                e.versioned(1, 1, |e| v.encode(e))
            }
            ChunkRefs::ByHash {
                total,
                hash_bits,
                map,
            } => {
                e.u8(T_HASH)?;
                e.versioned(1, 1, |e| {
                    e.varint(*total)?;
                    e.varint(*hash_bits as u64)?;
                    e.varint(map.len() as u64)?;
                    let nb = (*hash_bits as usize).div_ceil(8).min(4);
                    for ((pool, hash), n) in map {
                        e.varint_signed(*pool)?;
                        e.raw(&hash.to_le_bytes()[..nb])?;
                        e.varint(*n)?;
                    }
                    Ok(())
                })
            }
            ChunkRefs::ByPool { total, map } => {
                e.u8(T_POOL)?;
                e.versioned(1, 1, |e| {
                    e.varint(*total)?;
                    e.varint(map.len() as u64)?;
                    for (pool, n) in map {
                        e.varint_signed(*pool)?;
                        e.varint(*n)?;
                    }
                    Ok(())
                })
            }
            ChunkRefs::Count(t) => {
                e.u8(T_COUNT)?;
                e.versioned(1, 1, |e| e.u64(*t))
            }
        })
    }
}
impl<'a> Decode<'a> for ChunkRefs {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| match d.u8()? {
            T_OBJECT => d.versioned(1, |d, _| {
                let mut v = Vec::<Hobject>::decode(d)?;
                v.sort(); // stable: equal elements keep their order
                Ok(ChunkRefs::ByObject(v))
            }),
            T_HASH => d.versioned(1, |d, _| {
                let total = d.varint()?;
                let bits = d.varint()?;
                if bits > 32 {
                    return Err(Error::BadValue("hash_bits"));
                }
                let n = d.varint()?;
                let nb = (bits as usize).div_ceil(8);
                let mut map = BTreeMap::new();
                for _ in 0..n {
                    let pool = d.varint_signed()?;
                    let mut h = [0u8; 4];
                    h[..nb].copy_from_slice(d.take(nb)?);
                    let cnt = d.varint()?;
                    map.insert((pool, u32::from_le_bytes(h)), cnt);
                }
                Ok(ChunkRefs::ByHash {
                    total,
                    hash_bits: bits as u32,
                    map,
                })
            }),
            T_POOL => d.versioned(1, |d, _| {
                let total = d.varint()?;
                let n = d.varint()?;
                let mut map = BTreeMap::new();
                for _ in 0..n {
                    let pool = d.varint_signed()?;
                    map.insert(pool, d.varint()?);
                }
                Ok(ChunkRefs::ByPool { total, map })
            }),
            T_COUNT => d.versioned(1, |d, _| Ok(ChunkRefs::Count(d.u64()?))),
            _ => Err(Error::BadValue("chunk ref type")),
        })
    }
}

env_struct! {
    /// `chunk_create_or_get_ref_op` (1,1)
    CreateOrGetRefOp (1, 1) {
        source: Hobject,
        flags: u64,
        data: Vec<u8>,
    }
}
/// `chunk_get_ref_op` / `chunk_put_ref_op` (1,1)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RefOp {
    pub source: Hobject,
}
impl Encode for RefOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| self.source.encode(e))
    }
}
impl<'a> Decode<'a> for RefOp {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            Ok(RefOp {
                source: Hobject::decode(d)?,
            })
        })
    }
}

/// ENODATA -> empty set; every other read error (incl. ENOENT) is returned.
fn read_refs<C: ClsCtx>(c: &mut C) -> Result<ChunkRefs, Errno> {
    match c.getxattr(ATTR) {
        Err(ENODATA) => Ok(ChunkRefs::default()),
        Err(e) => Err(e),
        Ok(b) => ChunkRefs::decode(&mut Decoder::new(&b)).eio(),
    }
}
fn write_refs<C: ClsCtx>(c: &mut C, r: &ChunkRefs) -> Result<(), Errno> {
    c.setxattr(ATTR, &r.encode_to_vec().eio()?)
}

pub fn chunk_create_or_get_ref<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    let op: CreateOrGetRefOp = dec_op(input)?;
    match read_refs(c) {
        Err(ENOENT) => {
            c.write_full(&op.data)?;
            let mut r = ChunkRefs::default();
            r.get(&op.source);
            write_refs(c, &r)?;
        }
        Err(e) => return Err(e),
        Ok(mut r) => {
            if op.flags & FLAG_VERIFY != 0 {
                let old = c.read(0, 0).unwrap_or_default();
                if old != op.data {
                    return Err(ENOMSG);
                }
            }
            r.get(&op.source);
            write_refs(c, &r)?;
        }
    }
    Ok(Vec::new())
}

pub fn chunk_get_ref<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: RefOp = dec_op(input)?;
    let mut r = read_refs(c)?;
    r.get(&op.source);
    write_refs(c, &r)?;
    Ok(())
}

pub fn chunk_put_ref<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: RefOp = dec_op(input)?;
    let mut r = read_refs(c)?;
    if !r.put(&op.source) {
        return Err(ENOLINK);
    }
    if r.is_empty() {
        c.remove()?;
    } else {
        write_refs(c, &r)?;
    }
    Ok(())
}

pub fn references_chunk<C: ClsCtx>(c: &mut C, input: &[u8]) -> Reply {
    let fp = match Vec::<u8>::decode(&mut Decoder::new(input)) {
        Ok(f) => f,
        Err(_) => {
            return Reply {
                ret: EINVAL,
                out: Vec::new(),
            };
        }
    };
    let r = c.manifest_ref_count(&fp);
    Reply {
        ret: if r != 0 { r } else { ENOLINK },
        out: Vec::new(),
    }
}
