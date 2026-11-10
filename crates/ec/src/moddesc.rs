// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `ObjectModDesc.bl` records (ec.md 8.1): the rollback information of one EC log entry. Each record is an
//! envelope holding `u8 id` + body: ENV(1,1) except ROLLBACK_EXTENTS (ENV(2,2) legacy, ENV(3,2) optimized).
//! The wrapper (`can_local_rollback`, `rollback_info_completed`, `bl`) lives in `pgwire::ObjectModDesc`; this
//! module only reads/writes `bl`. Entries are stored verbatim; we interpret them only to roll back / forward.

use denc::{Decoder, Encoder, Error};

pub const ID_APPEND: u8 = 1;
pub const ID_SETATTRS: u8 = 2;
pub const ID_DELETE: u8 = 3;
pub const ID_CREATE: u8 = 4;
pub const ID_UPDATE_SNAPS: u8 = 5;
pub const ID_TRY_DELETE: u8 = 6;
pub const ID_ROLLBACK_EXTENTS: u8 = 7;
pub const ID_EC_OMAP: u8 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModOp {
    /// Truncate back to this LOGICAL size.
    Append {
        old_size: u64,
    },
    /// Old attribute values; `None` = the attribute did not exist.
    SetAttrs(Vec<(Vec<u8>, Option<Vec<u8>>)>),
    /// Whole object was stashed under generation `version`.
    Delete {
        version: u64,
    },
    Create,
    UpdateSnaps(Vec<u64>),
    TryDelete {
        version: u64,
    },
    /// Shard ranges stashed under `generation`. v3 (optimized) adds `object_size` and per-extent shard sets (two
    /// bitset words, see [`shard_set_contains`]); both empty for legacy v2. [`parse`] guarantees `shards` is empty
    /// (all shards) or parallel to `extents`.
    RollbackExtents {
        generation: u64,
        extents: Vec<(u64, u64)>,
        object_size: Option<u64>,
        shards: Vec<[u64; 2]>,
    },
    /// Optimized-EC omap record (ec-optimized.md 12.2): applied to primary-capable shards at roll-forward.
    EcOmap(EcOmap),
}

/// One update of an EC_OMAP record (`OmapUpdateType` 0 remove, 1 insert, 2 remove range).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OmapUp {
    Remove(Vec<Vec<u8>>),
    Insert(Vec<(Vec<u8>, Vec<u8>)>),
    /// Keys in `[first, last)`.
    RemoveRange(Vec<u8>, Vec<u8>),
}

/// EC_OMAP body: applied in this order on roll-forward: header, clear, updates (classic Trimmer order).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EcOmap {
    pub clear: bool,
    pub header: Option<Vec<u8>>,
    pub ups: Vec<OmapUp>,
}

fn payload(b: &[u8], values: bool) -> Vec<u8> {
    if values { b.to_vec() } else { Vec::new() }
}

fn parse_ec_omap(d: &mut Decoder<'_>, values: bool) -> Result<Result<ModOp, ModDescError>, Error> {
    let clear = d.bool()?;
    let header = if d.bool()? {
        Some(payload(d.bytes()?, values))
    } else {
        None
    };
    let n = d.count()?;
    let mut ups = Vec::new();
    for _ in 0..n {
        let ty = d.u8()?;
        let mut b = Decoder::new(d.bytes()?);
        ups.push(match ty {
            0 => {
                let n = b.count()?;
                let mut v = Vec::new();
                for _ in 0..n {
                    v.push(b.bytes()?.to_vec());
                }
                OmapUp::Remove(v)
            }
            1 => {
                let n = b.count()?;
                let mut v = Vec::new();
                for _ in 0..n {
                    let k = b.bytes()?.to_vec();
                    v.push((k, payload(b.bytes()?, values)));
                }
                OmapUp::Insert(v)
            }
            2 => {
                let a = b.bytes()?.to_vec();
                OmapUp::RemoveRange(a, b.bytes()?.to_vec())
            }
            t => {
                return Ok(Err(ModDescError::Decode(format!(
                    "EC_OMAP update type {t}"
                ))));
            }
        });
    }
    Ok(Ok(ModOp::EcOmap(EcOmap { clear, header, ups })))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModDescError {
    Unknown(u8),
    Decode(String),
}

impl std::fmt::Display for ModDescError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModDescError::Unknown(i) => write!(f, "unknown mod_desc record id {i}"),
            ModDescError::Decode(e) => write!(f, "mod_desc decode: {e}"),
        }
    }
}
impl std::error::Error for ModDescError {}

fn de(e: Error) -> ModDescError {
    ModDescError::Decode(e.to_string())
}

/// Parse `bl` into the ordered op list. Unknown record id or malformed input = `Err` (the caller fails closed).
pub fn parse(bl: &[u8]) -> Result<Vec<ModOp>, ModDescError> {
    parse_mode(bl, true)
}

// Both consumers use the same field/envelope validation. The private projected
// representation discards payloads only after their borrowed bounds are checked.
fn parse_mode(bl: &[u8], values: bool) -> Result<Vec<ModOp>, ModDescError> {
    let mut d = Decoder::new(bl);
    let mut out = Vec::new();
    while !d.is_empty() {
        let op = d
            .versioned(3, |d, v| -> Result<Result<ModOp, ModDescError>, Error> {
                let id = d.u8()?;
                Ok(match id {
                    ID_APPEND if v == 1 => Ok(ModOp::Append { old_size: d.u64()? }),
                    ID_SETATTRS if v == 1 => {
                        let n = d.count()?;
                        let mut v = Vec::new();
                        for _ in 0..n {
                            let k = d.bytes()?.to_vec();
                            let val = if d.bool()? {
                                Some(payload(d.bytes()?, values))
                            } else {
                                None
                            };
                            v.push((k, val));
                        }
                        Ok(ModOp::SetAttrs(v))
                    }
                    ID_DELETE if v == 1 => Ok(ModOp::Delete { version: d.u64()? }),
                    ID_CREATE if v == 1 => Ok(ModOp::Create),
                    ID_UPDATE_SNAPS if v == 1 => {
                        let n = d.count()?;
                        let mut s = Vec::new();
                        for _ in 0..n {
                            s.push(d.u64()?);
                        }
                        Ok(ModOp::UpdateSnaps(s))
                    }
                    ID_TRY_DELETE if v == 1 => Ok(ModOp::TryDelete { version: d.u64()? }),
                    ID_ROLLBACK_EXTENTS if v == 2 || v == 3 => {
                        let generation = d.u64()?;
                        let n = d.count()?;
                        let mut extents = Vec::new();
                        for _ in 0..n {
                            extents.push((d.u64()?, d.u64()?));
                        }
                        let (mut object_size, mut shards) = (None, Vec::new());
                        if v >= 3 {
                            object_size = Some(d.u64()?);
                            let n = d.count()?;
                            // empty or one set per extent (ec.md 8.1): any other count cannot be applied, a rollback
                            // by it would skip extents and still drop the stash
                            if n != 0 && n != extents.len() {
                                return Ok(Err(ModDescError::Decode(format!(
                                    "ROLLBACK_EXTENTS: {n} shard sets for {} extents",
                                    extents.len()
                                ))));
                            }
                            for _ in 0..n {
                                let (a, b) = (d.varint()?, d.varint()?);
                                shards.push([a, b]);
                            }
                        }
                        Ok(ModOp::RollbackExtents {
                            generation,
                            extents,
                            object_size,
                            shards,
                        })
                    }
                    ID_EC_OMAP if v == 1 => parse_ec_omap(d, values)?,
                    other => Err(ModDescError::Unknown(other)),
                })
            })
            .map_err(de)??;
        out.push(op);
    }
    Ok(out)
}

/// Key-only EC_OMAP update. Inserted values are validated but never copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OmapKeysUp {
    Remove(Vec<Vec<u8>>),
    Insert(Vec<Vec<u8>>),
    RemoveRange(Vec<u8>, Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EcOmapKeys {
    pub clear: bool,
    pub header_changed: bool,
    pub ups: Vec<OmapKeysUp>,
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct OmapKeysProjection {
    pub moved_to: Option<u64>,
    pub records: Vec<EcOmapKeys>,
}

/// Project keys and the first object-generation change using exactly [`parse`]'s
/// validation (including tolerated envelope and nested-update extensions).
pub fn project_omap_keys(bl: &[u8]) -> Result<OmapKeysProjection, ModDescError> {
    let mut out = OmapKeysProjection::default();
    for op in parse_mode(bl, false)? {
        match op {
            ModOp::Delete { version } | ModOp::TryDelete { version } => {
                out.moved_to.get_or_insert(version);
            }
            ModOp::EcOmap(o) => out.records.push(EcOmapKeys {
                clear: o.clear,
                header_changed: o.header.is_some(),
                ups: o
                    .ups
                    .into_iter()
                    .map(|u| match u {
                        OmapUp::Remove(k) => OmapKeysUp::Remove(k),
                        OmapUp::Insert(kv) => {
                            OmapKeysUp::Insert(kv.into_iter().map(|(k, _)| k).collect())
                        }
                        OmapUp::RemoveRange(a, z) => OmapKeysUp::RemoveRange(a, z),
                    })
                    .collect(),
            }),
            _ => {}
        }
    }
    Ok(out)
}

/// A v3 ROLLBACK_EXTENTS per-extent set names `shard`: an EMPTY set means "all shards" (ec-optimized.md 6.1/6.2).
pub fn extent_set_has(set: &[u64; 2], shard: u32) -> bool {
    shard_set_is_empty(set) || shard_set_contains(set, shard)
}

/// Shard set is empty (both words 0).
pub fn shard_set_is_empty(set: &[u64; 2]) -> bool {
    *set == [0, 0]
}

/// Does the shard set (two bitset words) contain `shard`?
pub fn shard_set_contains(set: &[u64; 2], shard: u32) -> bool {
    match shard {
        0..=63 => set[0] >> shard & 1 == 1,
        64..=127 => set[1] >> (shard - 64) & 1 == 1,
        _ => false,
    }
}

/// Stash generations a roll-forward / trim of this entry must delete, regardless of shard sets.
pub fn stash_generations(ops: &[ModOp]) -> Vec<u64> {
    ops.iter()
        .filter_map(|o| match o {
            ModOp::Delete { version } | ModOp::TryDelete { version } => Some(*version),
            ModOp::RollbackExtents { generation, .. } => Some(*generation),
            _ => None,
        })
        .collect()
}

/// Like [`stash_generations`] but for shard `shard`: a v3 ROLLBACK_EXTENTS counts only if `shard` is in some
/// extent's set (ec.md 7.6).
pub fn stash_generations_for(ops: &[ModOp], shard: u32) -> Vec<u64> {
    ops.iter()
        .filter_map(|o| match o {
            ModOp::Delete { version } | ModOp::TryDelete { version } => Some(*version),
            ModOp::RollbackExtents {
                generation, shards, ..
            } if shards.is_empty() || shards.iter().any(|s| extent_set_has(s, shard)) => {
                Some(*generation)
            }
            _ => None,
        })
        .collect()
}

/// Builder of `bl` (primary role). Mirrors the classic builder: once a DELETE, TRY_DELETE or CREATE was added the
/// rollback info is complete and further ops are dropped.
#[derive(Debug, Clone, Default)]
pub struct ModDescBuilder {
    bl: Vec<u8>,
    max_version: u8,
    completed: bool,
}

impl ModDescBuilder {
    pub fn new() -> Self {
        ModDescBuilder {
            bl: Vec::new(),
            max_version: 1,
            completed: false,
        }
    }

    fn rec(
        &mut self,
        v: u8,
        compat: u8,
        f: impl FnOnce(&mut Encoder<Vec<u8>>) -> Result<(), Error>,
    ) {
        if self.completed {
            return;
        }
        let mut e = Encoder::from_buf(std::mem::take(&mut self.bl));
        e.versioned(v, compat, f)
            .expect("encode into Vec cannot fail");
        self.bl = e.into_inner();
        self.max_version = self.max_version.max(v);
    }

    pub fn append(&mut self, old_size: u64) -> &mut Self {
        self.rec(1, 1, |e| {
            e.u8(ID_APPEND)?;
            e.u64(old_size)
        });
        self
    }

    pub fn set_attrs(&mut self, attrs: &[(Vec<u8>, Option<Vec<u8>>)]) -> &mut Self {
        self.rec(1, 1, |e| {
            e.u8(ID_SETATTRS)?;
            e.count(attrs.len())?;
            for (k, v) in attrs {
                e.bytes(k)?;
                match v {
                    Some(v) => {
                        e.bool(true)?;
                        e.bytes(v)?;
                    }
                    None => e.bool(false)?,
                }
            }
            Ok(())
        });
        self
    }

    pub fn update_snaps(&mut self, snaps: &[u64]) -> &mut Self {
        self.rec(1, 1, |e| {
            e.u8(ID_UPDATE_SNAPS)?;
            e.count(snaps.len())?;
            for s in snaps {
                e.u64(*s)?;
            }
            Ok(())
        });
        self
    }

    pub fn rollback_extents(&mut self, generation: u64, extents: &[(u64, u64)]) -> &mut Self {
        self.rec(2, 2, |e| {
            e.u8(ID_ROLLBACK_EXTENTS)?;
            e.u64(generation)?;
            e.count(extents.len())?;
            for (o, l) in extents {
                e.u64(*o)?;
                e.u64(*l)?;
            }
            Ok(())
        });
        self
    }

    /// Optimized ROLLBACK_EXTENTS v3: `object_size` = align4096(orig logical size), `shards[i]` = shard set words of
    /// extent i (`[0, 0]` = all shards), same length as `extents` (any other count is undecodable).
    pub fn rollback_extents_v3(
        &mut self,
        generation: u64,
        extents: &[(u64, u64)],
        object_size: u64,
        shards: &[[u64; 2]],
    ) -> &mut Self {
        debug_assert_eq!(shards.len(), extents.len(), "one shard set per extent");
        self.rec(3, 2, |e| {
            e.u8(ID_ROLLBACK_EXTENTS)?;
            e.u64(generation)?;
            e.count(extents.len())?;
            for (o, l) in extents {
                e.u64(*o)?;
                e.u64(*l)?;
            }
            e.u64(object_size)?;
            e.count(shards.len())?;
            for s in shards {
                e.varint(s[0])?;
                e.varint(s[1])?;
            }
            Ok(())
        });
        // classic caps the wrapper at 2 (an ENV(3,3) wrapper would not decode there), ec-optimized.md 18 UI-8
        if !self.completed {
            self.max_version = 2;
        }
        self
    }

    pub fn delete(&mut self, version: u64) -> &mut Self {
        self.rec(1, 1, |e| {
            e.u8(ID_DELETE)?;
            e.u64(version)
        });
        self.completed = true;
        self
    }

    pub fn try_delete(&mut self, version: u64) -> &mut Self {
        self.rec(1, 1, |e| {
            e.u8(ID_TRY_DELETE)?;
            e.u64(version)
        });
        self.completed = true;
        self
    }

    pub fn create(&mut self) -> &mut Self {
        self.rec(1, 1, |e| e.u8(ID_CREATE));
        self.completed = true;
        self
    }

    /// EC_OMAP record; unlike the rollback records it is kept after DELETE / CREATE (classic: only an unrollbackable
    /// entry drops it).
    pub fn ec_omap(&mut self, o: &EcOmap) -> &mut Self {
        let done = std::mem::replace(&mut self.completed, false);
        self.rec(1, 1, |e| {
            e.u8(ID_EC_OMAP)?;
            e.bool(o.clear)?;
            match &o.header {
                Some(h) => {
                    e.bool(true)?;
                    e.bytes(h)?;
                }
                None => e.bool(false)?,
            }
            e.count(o.ups.len())?;
            for u in &o.ups {
                let mut b = Encoder::new();
                let ty = match u {
                    OmapUp::Remove(keys) => {
                        b.count(keys.len())?;
                        for k in keys {
                            b.bytes(k)?;
                        }
                        0
                    }
                    OmapUp::Insert(kv) => {
                        b.count(kv.len())?;
                        for (k, v) in kv {
                            b.bytes(k)?;
                            b.bytes(v)?;
                        }
                        1
                    }
                    OmapUp::RemoveRange(a, z) => {
                        b.bytes(a)?;
                        b.bytes(z)?;
                        2
                    }
                };
                e.u8(ty)?;
                e.bytes(&b.into_vec())?;
            }
            Ok(())
        });
        self.completed = done;
        self
    }

    /// `(bl, max_required_version, rollback_info_completed)`.
    pub fn finish(self) -> (Vec<u8>, u8, bool) {
        (self.bl, self.max_version, self.completed)
    }
}

/// Full `ObjectModDesc` wire form: ENV(v,v){u8 can_local_rollback, u8 completed, bl}.
pub fn encode_wrapper(
    bl: &[u8],
    max_version: u8,
    can_local_rollback: bool,
    completed: bool,
) -> Vec<u8> {
    let mut e = Encoder::new();
    e.versioned(max_version, max_version, |e| {
        e.bool(can_local_rollback)?;
        e.bool(completed)?;
        e.bytes(bl)
    })
    .expect("encode into Vec cannot fail");
    e.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_records() {
        // APPEND(0x1000): ENV(1,1) len 9 { 01, u64 }
        let mut b = ModDescBuilder::new();
        b.append(0x1000);
        let (bl, v, done) = b.finish();
        assert_eq!(bl, [1, 1, 9, 0, 0, 0, 1, 0, 0x10, 0, 0, 0, 0, 0, 0]);
        assert_eq!((v, done), (1, false));
        assert_eq!(
            parse(&bl).unwrap(),
            vec![ModOp::Append { old_size: 0x1000 }]
        );

        // SETATTRS {"a": Some("xy"), "b": None}
        let mut b = ModDescBuilder::new();
        b.set_attrs(&[(b"a".to_vec(), Some(b"xy".to_vec())), (b"b".to_vec(), None)]);
        let (bl, ..) = b.finish();
        let want: Vec<u8> = vec![
            1, 1, 23, 0, 0, 0, // env, len = 1 + 4 + (4+1+1+4+2) + (4+1+1)
            2, // id
            2, 0, 0, 0, // n
            1, 0, 0, 0, b'a', 1, 2, 0, 0, 0, b'x', b'y', // a -> Some
            1, 0, 0, 0, b'b', 0, // b -> None
        ];
        assert_eq!(bl, want);
        assert_eq!(parse(&bl).unwrap().len(), 1);

        // DELETE(7)
        let mut b = ModDescBuilder::new();
        b.delete(7);
        let (bl, _, done) = b.finish();
        assert_eq!(bl, [1, 1, 9, 0, 0, 0, 3, 7, 0, 0, 0, 0, 0, 0, 0]);
        assert!(done);
        // CREATE
        let mut b = ModDescBuilder::new();
        b.create();
        assert_eq!(b.finish().0, [1, 1, 1, 0, 0, 0, 4]);
        // UPDATE_SNAPS {5, 6}
        let mut b = ModDescBuilder::new();
        b.update_snaps(&[5, 6]);
        let (bl, ..) = b.finish();
        let mut want = vec![1, 1, 21, 0, 0, 0, 5, 2, 0, 0, 0];
        want.extend([5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(bl, want);
        assert_eq!(parse(&bl).unwrap(), vec![ModOp::UpdateSnaps(vec![5, 6])]);
        // TRY_DELETE(9)
        let mut b = ModDescBuilder::new();
        b.try_delete(9);
        assert_eq!(b.finish().0, [1, 1, 9, 0, 0, 0, 6, 9, 0, 0, 0, 0, 0, 0, 0]);
        // ROLLBACK_EXTENTS v2: gen 3, [(0, 4096)]
        let mut b = ModDescBuilder::new();
        b.rollback_extents(3, &[(0, 4096)]);
        let (bl, v, _) = b.finish();
        let mut want = vec![2, 2, 29, 0, 0, 0, 7];
        want.extend([3, 0, 0, 0, 0, 0, 0, 0]);
        want.extend([1, 0, 0, 0]);
        want.extend([0u8; 8]);
        want.extend([0, 0x10, 0, 0, 0, 0, 0, 0]);
        assert_eq!(bl, want);
        assert_eq!(v, 2);
        assert_eq!(
            parse(&bl).unwrap(),
            vec![ModOp::RollbackExtents {
                generation: 3,
                extents: vec![(0, 4096)],
                object_size: None,
                shards: vec![]
            }]
        );
    }

    #[test]
    fn v3_rollback_extents() {
        // ENV(3,2){7, gen 5, [(0,8)], object_size 4096, [set{1,2}]}
        let mut want = vec![3, 2, 0, 0, 0, 0, 7];
        want.extend([5, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);
        want.extend([0u8; 8]);
        want.extend([8, 0, 0, 0, 0, 0, 0, 0]);
        want.extend([0, 0x10, 0, 0, 0, 0, 0, 0]);
        want.extend([1, 0, 0, 0, 0b110, 0]);
        let len = (want.len() - 6) as u32;
        want[2..6].copy_from_slice(&len.to_le_bytes());
        let ops = parse(&want).unwrap();
        let ModOp::RollbackExtents {
            generation,
            object_size,
            shards,
            ..
        } = &ops[0]
        else {
            panic!()
        };
        assert_eq!((*generation, *object_size), (5, Some(4096)));
        assert!(shard_set_contains(&shards[0], 1));
        assert!(shard_set_contains(&shards[0], 2));
        assert!(!shard_set_contains(&shards[0], 0));
        assert!(!shard_set_contains(&shards[0], 70));
        assert_eq!(stash_generations_for(&ops, 1), vec![5]);
        assert_eq!(stash_generations_for(&ops, 0), Vec::<u64>::new());
        assert_eq!(stash_generations(&ops), vec![5]);
    }

    #[test]
    fn v3_builder_and_empty_set_means_all() {
        let mut b = ModDescBuilder::new();
        b.rollback_extents_v3(5, &[(0, 8), (4096, 4096)], 4096, &[[0b110, 0], [0, 0]]);
        let (bl, v, _) = b.finish();
        assert_eq!(v, 2);
        let ops = parse(&bl).unwrap();
        let ModOp::RollbackExtents {
            shards,
            extents,
            object_size,
            ..
        } = &ops[0]
        else {
            panic!()
        };
        assert_eq!((extents.len(), *object_size), (2, Some(4096)));
        assert!(extent_set_has(&shards[0], 1) && !extent_set_has(&shards[0], 0));
        assert!(extent_set_has(&shards[1], 0) && extent_set_has(&shards[1], 99));
        assert!(shard_set_is_empty(&shards[1]) && !shard_set_is_empty(&shards[0]));
        assert!(!shard_set_is_empty(&[0x80, 0]));
        // shard 0 is only in the "all" extent: its stash generation counts
        assert_eq!(stash_generations_for(&ops, 0), vec![5]);
    }

    /// ROLLBACK_EXTENTS v3 as sent, with any number of shard sets (the builder only makes valid ones).
    fn v3_raw(extents: &[(u64, u64)], sets: usize) -> Vec<u8> {
        let mut e = Encoder::new();
        e.versioned(3, 2, |e| {
            e.u8(ID_ROLLBACK_EXTENTS)?;
            e.u64(4)?;
            e.count(extents.len())?;
            for (o, l) in extents {
                e.u64(*o)?;
                e.u64(*l)?;
            }
            e.u64(8192)?;
            e.count(sets)?;
            for _ in 0..sets {
                e.varint(0b1111)?;
                e.varint(0)?;
            }
            Ok(())
        })
        .unwrap();
        e.into_vec()
    }

    /// The shard-set vector is empty (every extent on all shards) or parallel to the extents. Any other count is
    /// undecodable (ec.md 8.1): a rollback by it would skip extents and still drop the stash.
    #[test]
    fn v3_shard_set_count_is_zero_or_the_extent_count() {
        let ext = [(0, 4096), (4096, 4096), (8192, 4096)];
        for (n, ok) in [(0, true), (1, false), (2, false), (3, true), (4, false)] {
            let bl = v3_raw(&ext, n);
            match parse(&bl) {
                Ok(ops) => {
                    assert!(ok, "{n} sets for 3 extents parsed: {ops:?}");
                    let ModOp::RollbackExtents { shards, .. } = &ops[0] else {
                        panic!("{ops:?}")
                    };
                    assert_eq!(shards.len(), n);
                }
                Err(e) => assert!(!ok, "{n} sets for 3 extents: {e}"),
            }
            assert_eq!(project_omap_keys(&bl).is_ok(), ok, "{n} sets");
        }
        // a truncated count, the remaining set bytes left behind as an envelope extension
        let mut b = ModDescBuilder::new();
        b.rollback_extents_v3(4, &ext[..2], 8192, &[[0b1111, 0], [0b1111, 0]]);
        let (mut bl, ..) = b.finish();
        parse(&bl).unwrap();
        let at = bl.len() - 8;
        bl[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(parse(&bl), Err(ModDescError::Decode(_))));
    }

    #[test]
    fn builder_completion_and_order() {
        let mut b = ModDescBuilder::new();
        b.update_snaps(&[1])
            .delete(4)
            .create()
            .set_attrs(&[(b"k".to_vec(), None)])
            .append(8);
        let (bl, v, done) = b.finish();
        assert!(done);
        assert_eq!(v, 1);
        let ops = parse(&bl).unwrap();
        assert_eq!(
            ops,
            vec![ModOp::UpdateSnaps(vec![1]), ModOp::Delete { version: 4 }]
        );
        assert_eq!(stash_generations(&ops), vec![4]);

        let mut b = ModDescBuilder::new();
        b.create();
        b.append(1);
        assert_eq!(parse(&b.finish().0).unwrap(), vec![ModOp::Create]);

        let mut b = ModDescBuilder::new();
        b.set_attrs(&[(b"hinfo_key".to_vec(), Some(vec![1, 2]))])
            .rollback_extents(9, &[(0, 32), (64, 32)])
            .append(100);
        let (bl, v, done) = b.finish();
        assert_eq!((v, done), (2, false));
        let ops = parse(&bl).unwrap();
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[2], ModOp::Append { old_size: 100 });
        assert_eq!(stash_generations(&ops), vec![9]);
    }

    #[test]
    fn wrapper_golden() {
        // replicated-style empty wrapper: 01 01 06 00 00 00 | 00 | 00 | 00 00 00 00
        assert_eq!(
            encode_wrapper(&[], 1, false, false),
            [1, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(encode_wrapper(&[9], 2, true, true)[..2], [2, 2]);
    }

    #[test]
    fn unknown_and_garbage() {
        // unknown id 99 in a valid envelope
        assert_eq!(
            parse(&[1, 1, 1, 0, 0, 0, 99]),
            Err(ModDescError::Unknown(99))
        );
        // id 7 in an ENV(1,1) is not valid, id 1 in ENV(2,2) neither
        assert!(parse(&[1, 1, 1, 0, 0, 0, 7]).is_err());
        assert!(parse(&[2, 2, 9, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        // EC_OMAP: clear=0, no header, no updates
        assert_eq!(
            parse(&[1, 1, 7, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0]).unwrap(),
            vec![ModOp::EcOmap(EcOmap::default())]
        );
        assert!(parse(&[1, 1, 3, 0, 0, 0, 8, 0, 0]).is_err());
        // every truncation of a long valid blob is an error, never a panic
        let mut b = ModDescBuilder::new();
        b.set_attrs(&[(b"k".to_vec(), Some(vec![1; 10]))])
            .rollback_extents(2, &[(0, 4)])
            .append(5);
        let (bl, ..) = b.finish();
        parse(&bl).unwrap();
        for n in 1..bl.len() {
            let r = parse(&bl[..n]);
            if let Ok(ops) = r {
                // only record boundaries may parse
                assert!(ops.len() < 3);
            }
        }
        let mut s: u64 = 0x1234_5678_9abc_def1;
        for _ in 0..20_000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let n = (s % 48) as usize;
            let mut v: Vec<u8> = (0..n)
                .map(|i| (s >> ((i % 8) * 8)) as u8 ^ (i as u8).wrapping_mul(31))
                .collect();
            if n >= 6 && s.is_multiple_of(3) {
                v[0] = (s % 4) as u8;
                v[1] = 1;
                let l = (n - 6) as u32;
                v[2..6].copy_from_slice(&l.to_le_bytes());
            }
            let _ = parse(&v);
        }
    }
}

#[cfg(test)]
mod ec_omap_tests {
    use super::*;

    fn full_projection(bl: &[u8]) -> Result<OmapKeysProjection, ModDescError> {
        let mut p = OmapKeysProjection::default();
        for op in parse(bl)? {
            match op {
                ModOp::Delete { version } | ModOp::TryDelete { version } => {
                    p.moved_to.get_or_insert(version);
                }
                ModOp::EcOmap(o) => p.records.push(EcOmapKeys {
                    clear: o.clear,
                    header_changed: o.header.is_some(),
                    ups: o
                        .ups
                        .into_iter()
                        .map(|u| match u {
                            OmapUp::Remove(k) => OmapKeysUp::Remove(k),
                            OmapUp::Insert(kv) => {
                                OmapKeysUp::Insert(kv.into_iter().map(|(k, _)| k).collect())
                            }
                            OmapUp::RemoveRange(a, z) => OmapKeysUp::RemoveRange(a, z),
                        })
                        .collect(),
                }),
                _ => {}
            }
        }
        Ok(p)
    }

    #[test]
    fn projected_parser_matches_full_validation() {
        let o = EcOmap {
            clear: true,
            header: Some(vec![42; 100]),
            ups: vec![
                OmapUp::Insert(vec![(b"a".to_vec(), vec![31; 123])]),
                OmapUp::Remove(vec![b"b".to_vec()]),
                OmapUp::RemoveRange(b"c".to_vec(), b"z".to_vec()),
            ],
        };
        let mut b = ModDescBuilder::new();
        b.set_attrs(&[(b"_".to_vec(), Some(vec![9; 32]))])
            .append(8)
            .update_snaps(&[1, 2])
            .rollback_extents_v3(7, &[(0, 8)], 4096, &[[1, 0]])
            .ec_omap(&o)
            .try_delete(7)
            .ec_omap(&o);
        let bl = b.finish().0;
        assert_eq!(project_omap_keys(&bl), full_projection(&bl));
        for n in 0..=bl.len() {
            assert_eq!(
                project_omap_keys(&bl[..n]),
                full_projection(&bl[..n]),
                "truncated {n}"
            );
        }
        for i in 0..bl.len() {
            for v in [0, 1, 2, 3, 8, 99, 255] {
                let mut bad = bl.clone();
                bad[i] = v;
                assert_eq!(
                    project_omap_keys(&bad),
                    full_projection(&bad),
                    "byte {i}={v}"
                );
            }
        }
        // Existing decoder tolerates unread update-body and envelope extensions.
        let mut e = Encoder::new();
        e.versioned(1, 1, |e| {
            e.u8(ID_EC_OMAP)?;
            e.bool(false)?;
            e.bool(false)?;
            e.count(1)?;
            let mut b = Encoder::new();
            b.count(1)?;
            b.bytes(b"k")?;
            b.bytes(b"v")?;
            b.u8(99)?;
            e.u8(1)?;
            e.bytes(&b.into_vec())?;
            e.u8(99)
        })
        .unwrap();
        let suffix = e.into_vec();
        assert!(parse(&suffix).is_ok());
        assert_eq!(project_omap_keys(&suffix), full_projection(&suffix));
    }

    /// Own vector: ENV(1,1){8, clear=1, header "H", [insert {a:1}, remove {b}, range [c,d)]} after a CREATE.
    #[test]
    fn ec_omap_roundtrip_and_bytes() {
        let o = EcOmap {
            clear: true,
            header: Some(b"H".to_vec()),
            ups: vec![
                OmapUp::Insert(vec![(b"a".to_vec(), b"1".to_vec())]),
                OmapUp::Remove(vec![b"b".to_vec()]),
                OmapUp::RemoveRange(b"c".to_vec(), b"d".to_vec()),
            ],
        };
        let mut b = ModDescBuilder::new();
        b.create().ec_omap(&o);
        let (bl, v, done) = b.finish();
        assert!(done && v == 1);
        let ops = parse(&bl).unwrap();
        assert_eq!(ops, vec![ModOp::Create, ModOp::EcOmap(o)]);
        // body bytes of the EC_OMAP record (after the CREATE envelope of 7 bytes)
        let rec = &bl[7..];
        let mut want = vec![1u8, 1, 0, 0, 0, 0, 8, 1, 1, 1, 0, 0, 0, b'H', 3, 0, 0, 0];
        want.extend([
            1, 14, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, b'a', 1, 0, 0, 0, b'1',
        ]);
        want.extend([0, 9, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, b'b']);
        want.extend([2, 10, 0, 0, 0, 1, 0, 0, 0, b'c', 1, 0, 0, 0, b'd']);
        let len = (want.len() - 6) as u32;
        want[2..6].copy_from_slice(&len.to_le_bytes());
        assert_eq!(rec, want.as_slice());
        // unknown update type
        let mut bad = want.clone();
        let i = 18 + 19 + 14; // start of the third update
        bad[i] = 9;
        assert!(parse(&bad).is_err());
    }
}
