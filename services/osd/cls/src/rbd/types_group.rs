// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Group and migration structures (spec/cls_rbd.md B.9, B.9a). Enum bytes are kept raw.

use crate::env_struct;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::BTreeMap;

/// `cls::rbd::GroupImageSpec` (v1/c1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupImageSpec {
    pub image_id: Vec<u8>,
    pub pool_id: i64,
}
impl Default for GroupImageSpec {
    fn default() -> Self {
        GroupImageSpec {
            image_id: Vec::new(),
            pool_id: -1,
        }
    }
}
impl GroupImageSpec {
    /// Omap key `image_<pool:016x>_<image_id>`; pool -1 yields the empty key (classic quirk).
    pub fn key(&self) -> Vec<u8> {
        if self.pool_id == -1 {
            Vec::new()
        } else {
            [
                format!("image_{:016x}_", self.pool_id as u64).as_bytes(),
                &self.image_id,
            ]
            .concat()
        }
    }
    /// Inverse of [`key`](Self::key) (`None` = malformed).
    pub fn from_key(key: &[u8]) -> Option<Self> {
        let rest = key.strip_prefix(b"image_")?;
        let sep = rest.iter().position(|&b| b == b'_')?;
        let (pool, id) = (&rest[..sep], &rest[sep + 1..]);
        if pool.is_empty() || pool.len() > 16 || !pool.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        Some(GroupImageSpec {
            image_id: id.to_vec(),
            pool_id: u64::from_str_radix(std::str::from_utf8(pool).ok()?, 16).ok()? as i64,
        })
    }
}
impl Encode for GroupImageSpec {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| {
            self.image_id.encode(e)?;
            e.i64(self.pool_id)
        })
    }
}
impl<'a> Decode<'a> for GroupImageSpec {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            Ok(GroupImageSpec {
                image_id: Vec::<u8>::decode(d)?,
                pool_id: d.i64()?,
            })
        })
    }
}

env_struct! {
    /// `cls::rbd::GroupImageStatus` (v1/c1): state 0 attached, 1 incomplete.
    GroupImageStatus (1, 1) {
        spec: GroupImageSpec,
        state: u8,
    }
}

env_struct! {
    /// `cls::rbd::ImageSnapshotSpec` (v1/c1).
    ImageSnapshotSpec (1, 1) {
        pool: i64,
        image_id: Vec<u8>,
        snap_id: u64,
    }
}

env_struct! {
    /// `cls::rbd::GroupSnapshot` (v1/c1): state 0 incomplete, 1 complete.
    GroupSnapshot (1, 1) {
        id: Vec<u8>,
        name: Vec<u8>,
        state: u8,
        snaps: Vec<ImageSnapshotSpec>,
    }
}

/// `cls::rbd::MigrationSpec` (v3, compat 3 iff `source_spec` non-empty else 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationSpec {
    /// 1 src, 2 dst (raw)
    pub header_type: u8,
    pub pool_id: i64,
    pub pool_namespace: Vec<u8>,
    pub image_name: Vec<u8>,
    pub image_id: Vec<u8>,
    pub snap_seqs: BTreeMap<u64, u64>,
    pub overlap: u64,
    pub flatten: bool,
    pub mirroring: bool,
    /// 0 error .. 5 aborting (raw)
    pub state: u8,
    pub state_description: Vec<u8>,
    pub mirror_image_mode: u8,
    pub source_spec: Vec<u8>,
}
impl Default for MigrationSpec {
    fn default() -> Self {
        MigrationSpec {
            header_type: 1,
            pool_id: -1,
            pool_namespace: Vec::new(),
            image_name: Vec::new(),
            image_id: Vec::new(),
            snap_seqs: BTreeMap::new(),
            overlap: 0,
            flatten: false,
            mirroring: false,
            state: 0,
            state_description: Vec::new(),
            mirror_image_mode: 0,
            source_spec: Vec::new(),
        }
    }
}
impl Encode for MigrationSpec {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        let compat = if self.source_spec.is_empty() { 1 } else { 3 };
        e.versioned(3, compat, |e| {
            e.u8(self.header_type)?;
            e.i64(self.pool_id)?;
            self.pool_namespace.encode(e)?;
            self.image_name.encode(e)?;
            self.image_id.encode(e)?;
            self.snap_seqs.encode(e)?;
            e.u64(self.overlap)?;
            e.bool(self.flatten)?;
            e.bool(self.mirroring)?;
            e.u8(self.state)?;
            self.state_description.encode(e)?;
            e.u8(self.mirror_image_mode)?;
            self.source_spec.encode(e)
        })
    }
}
impl<'a> Decode<'a> for MigrationSpec {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(3, |d, v| {
            let mut m = MigrationSpec {
                header_type: d.u8()?,
                pool_id: d.i64()?,
                pool_namespace: Vec::<u8>::decode(d)?,
                image_name: Vec::<u8>::decode(d)?,
                image_id: Vec::<u8>::decode(d)?,
                snap_seqs: BTreeMap::decode(d)?,
                overlap: d.u64()?,
                flatten: d.bool()?,
                mirroring: d.bool()?,
                state: d.u8()?,
                state_description: Vec::<u8>::decode(d)?,
                ..Default::default()
            };
            if v >= 2 {
                m.mirror_image_mode = d.u8()?;
            }
            if v >= 3 {
                m.source_spec = Vec::<u8>::decode(d)?;
            }
            Ok(m)
        })
    }
}
