// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_rbd wire/stored structures (spec/cls_rbd.md A.7, B.1, B.2, B.7). Byte-exact vs ceph-dencoder.

use denc::features::{self, SERVER_NAUTILUS};
use denc::types::UTime;
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error};
use std::collections::{BTreeMap, BTreeSet};

pub const NOSNAP: u64 = u64::MAX - 1;
pub const MAXSNAP: u64 = u64::MAX - 2;

pub const PROTECTION_UNPROTECTED: u8 = 0;
pub const PROTECTION_UNPROTECTING: u8 = 1;
pub const PROTECTION_PROTECTED: u8 = 2;

pub mod feature {
    pub const LAYERING: u64 = 1;
    pub const STRIPINGV2: u64 = 2;
    pub const EXCLUSIVE_LOCK: u64 = 4;
    pub const OBJECT_MAP: u64 = 8;
    pub const FAST_DIFF: u64 = 16;
    pub const DEEP_FLATTEN: u64 = 32;
    pub const JOURNALING: u64 = 64;
    pub const DATA_POOL: u64 = 128;
    pub const OPERATIONS: u64 = 256;
    pub const MIGRATING: u64 = 512;
    pub const NON_PRIMARY: u64 = 1024;
    pub const DIRTY_CACHE: u64 = 2048;
    pub const ALL: u64 = 0xfff;
    pub const INCOMPATIBLE: u64 = LAYERING | STRIPINGV2 | DATA_POOL | DIRTY_CACHE;
    pub const MUTABLE: u64 =
        EXCLUSIVE_LOCK | OBJECT_MAP | FAST_DIFF | JOURNALING | NON_PRIMARY | DIRTY_CACHE;
    pub const DISABLE_ONLY: u64 = DEEP_FLATTEN;
    pub const INTERNAL: u64 = OPERATIONS | MIGRATING;
}

pub mod op_feature {
    pub const CLONE_PARENT: u64 = 1;
    pub const CLONE_CHILD: u64 = 2;
    pub const GROUP: u64 = 4;
    pub const SNAP_TRASH: u64 = 8;
    pub const ALL: u64 = 0xf;
}

/// `cls_rbd_parent` (stored under header key `parent`). Featured: v2/c2 with SERVER_NAUTILUS,
/// else v1/c1 (no namespace, overlap as plain u64, 0 when none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parent {
    pub pool_id: i64,
    pub pool_namespace: Vec<u8>,
    pub image_id: Vec<u8>,
    pub snap_id: u64,
    pub head_overlap: Option<u64>,
}
impl Default for Parent {
    fn default() -> Self {
        Parent {
            pool_id: -1,
            pool_namespace: Vec::new(),
            image_id: Vec::new(),
            snap_id: NOSNAP,
            head_overlap: None,
        }
    }
}
impl Parent {
    pub fn exists(&self) -> bool {
        self.pool_id >= 0 && !self.image_id.is_empty() && self.snap_id != NOSNAP
    }
}
impl Encode for Parent {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        if features::have(e.features(), SERVER_NAUTILUS) {
            e.versioned(2, 2, |e| {
                e.i64(self.pool_id)?;
                self.pool_namespace.encode(e)?;
                self.image_id.encode(e)?;
                e.u64(self.snap_id)?;
                self.head_overlap.encode(e)
            })
        } else {
            e.versioned(1, 1, |e| {
                e.i64(self.pool_id)?;
                self.image_id.encode(e)?;
                e.u64(self.snap_id)?;
                e.u64(self.head_overlap.unwrap_or(0))
            })
        }
    }
}
impl<'a> Decode<'a> for Parent {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned_min(1, 2, |d, v| {
            let pool_id = d.i64()?;
            let pool_namespace = if v >= 2 {
                Vec::<u8>::decode(d)?
            } else {
                Vec::new()
            };
            let image_id = Vec::<u8>::decode(d)?;
            let snap_id = d.u64()?;
            let head_overlap = if v >= 2 {
                Option::<u64>::decode(d)?
            } else {
                Some(d.u64()?)
            };
            Ok(Parent {
                pool_id,
                pool_namespace,
                image_id,
                snap_id,
                head_overlap,
            })
        })
    }
}

/// `cls::rbd::ParentImageSpec` (v1/c1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentImageSpec {
    pub pool_id: i64,
    pub pool_namespace: Vec<u8>,
    pub image_id: Vec<u8>,
    pub snap_id: u64,
}
impl Default for ParentImageSpec {
    fn default() -> Self {
        ParentImageSpec {
            pool_id: -1,
            pool_namespace: Vec::new(),
            image_id: Vec::new(),
            snap_id: NOSNAP,
        }
    }
}
impl ParentImageSpec {
    pub fn exists(&self) -> bool {
        self.pool_id >= 0 && !self.image_id.is_empty() && self.snap_id != NOSNAP
    }
}
impl Encode for ParentImageSpec {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| {
            e.i64(self.pool_id)?;
            self.pool_namespace.encode(e)?;
            self.image_id.encode(e)?;
            e.u64(self.snap_id)
        })
    }
}
impl<'a> Decode<'a> for ParentImageSpec {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            Ok(ParentImageSpec {
                pool_id: d.i64()?,
                pool_namespace: Vec::<u8>::decode(d)?,
                image_id: Vec::<u8>::decode(d)?,
                snap_id: d.u64()?,
            })
        })
    }
}

/// `cls::rbd::ChildImageSpec` (v2/c1): wire order pool_id, image_id, pool_namespace.
/// Ordering for sets: (pool_id, pool_namespace, image_id).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChildImageSpec {
    pub pool_id: i64,
    pub pool_namespace: Vec<u8>,
    pub image_id: Vec<u8>,
}
impl PartialOrd for ChildImageSpec {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for ChildImageSpec {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (self.pool_id, &self.pool_namespace, &self.image_id).cmp(&(
            o.pool_id,
            &o.pool_namespace,
            &o.image_id,
        ))
    }
}
impl Encode for ChildImageSpec {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            e.i64(self.pool_id)?;
            self.image_id.encode(e)?;
            self.pool_namespace.encode(e)
        })
    }
}
impl<'a> Decode<'a> for ChildImageSpec {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            let pool_id = d.i64()?;
            let image_id = Vec::<u8>::decode(d)?;
            let pool_namespace = if v >= 2 {
                Vec::<u8>::decode(d)?
            } else {
                Vec::new()
            };
            Ok(ChildImageSpec {
                pool_id,
                pool_namespace,
                image_id,
            })
        })
    }
}

/// `cls::rbd::GroupSpec` (v1/c1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSpec {
    pub pool_id: i64,
    pub group_id: Vec<u8>,
}
impl Default for GroupSpec {
    fn default() -> Self {
        GroupSpec {
            pool_id: -1,
            group_id: Vec::new(),
        }
    }
}
impl Encode for GroupSpec {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| {
            e.i64(self.pool_id)?;
            self.group_id.encode(e)
        })
    }
}
impl<'a> Decode<'a> for GroupSpec {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            Ok(GroupSpec {
                pool_id: d.i64()?,
                group_id: Vec::<u8>::decode(d)?,
            })
        })
    }
}

/// `cls::rbd::SnapshotNamespace` (v1/c1): u32 type + variant body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SnapNs {
    #[default]
    User,
    Group {
        pool: i64,
        group_id: Vec<u8>,
        group_snapshot_id: Vec<u8>,
    },
    Trash {
        original_name: Vec<u8>,
        original_namespace_type: u32,
    },
    Mirror {
        /// 0 primary, 1 primary_demoted, 2 non_primary, 3 non_primary_demoted (u8 on the wire)
        state: u8,
        complete: bool,
        peer_uuids: BTreeSet<Vec<u8>>,
        primary_mirror_uuid: Vec<u8>,
        primary_snap_id: u64,
        last_copied_object_number: u64,
        snap_seqs: BTreeMap<u64, u64>,
    },
    /// Unknown type id: decodes with an empty body; rejected by `snapshot_add`.
    Unknown(u32),
}
impl SnapNs {
    pub const TYPE_USER: u32 = 0;
    pub const TYPE_GROUP: u32 = 1;
    pub const TYPE_TRASH: u32 = 2;
    pub const TYPE_MIRROR: u32 = 3;
    pub fn type_id(&self) -> u32 {
        match self {
            SnapNs::User => Self::TYPE_USER,
            SnapNs::Group { .. } => Self::TYPE_GROUP,
            SnapNs::Trash { .. } => Self::TYPE_TRASH,
            SnapNs::Mirror { .. } => Self::TYPE_MIRROR,
            SnapNs::Unknown(t) => *t,
        }
    }
    /// Equality used for the duplicate-name check: Trash == Trash always.
    pub fn same_for_dup(&self, o: &SnapNs) -> bool {
        match (self, o) {
            (SnapNs::Trash { .. }, SnapNs::Trash { .. }) => true,
            _ => self == o,
        }
    }
}
impl Encode for SnapNs {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| {
            e.u32(self.type_id())?;
            match self {
                SnapNs::User | SnapNs::Unknown(_) => Ok(()),
                SnapNs::Group {
                    pool,
                    group_id,
                    group_snapshot_id,
                } => {
                    e.i64(*pool)?;
                    group_id.encode(e)?;
                    group_snapshot_id.encode(e)
                }
                SnapNs::Trash {
                    original_name,
                    original_namespace_type,
                } => {
                    original_name.encode(e)?;
                    e.u32(*original_namespace_type)
                }
                SnapNs::Mirror {
                    state,
                    complete,
                    peer_uuids,
                    primary_mirror_uuid,
                    primary_snap_id,
                    last_copied_object_number,
                    snap_seqs,
                } => {
                    e.u8(*state)?;
                    e.bool(*complete)?;
                    peer_uuids.encode(e)?;
                    primary_mirror_uuid.encode(e)?;
                    e.u64(*primary_snap_id)?;
                    e.u64(*last_copied_object_number)?;
                    snap_seqs.encode(e)
                }
            }
        })
    }
}
impl<'a> Decode<'a> for SnapNs {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            Ok(match d.u32()? {
                0 => SnapNs::User,
                1 => SnapNs::Group {
                    pool: d.i64()?,
                    group_id: Vec::<u8>::decode(d)?,
                    group_snapshot_id: Vec::<u8>::decode(d)?,
                },
                2 => SnapNs::Trash {
                    original_name: Vec::<u8>::decode(d)?,
                    original_namespace_type: d.u32()?,
                },
                3 => SnapNs::Mirror {
                    state: d.u8()?,
                    complete: d.bool()?,
                    peer_uuids: BTreeSet::decode(d)?,
                    primary_mirror_uuid: Vec::<u8>::decode(d)?,
                    primary_snap_id: d.u64()?,
                    last_copied_object_number: d.u64()?,
                    snap_seqs: BTreeMap::decode(d)?,
                },
                t => SnapNs::Unknown(t),
            })
        })
    }
}

/// `cls_rbd_snap` (header key `snapshot_<id16>`). Featured: v8/c8 (new layout) with SERVER_NAUTILUS;
/// without it v8/c1 with the legacy `unused features u64 + cls_rbd_parent` after image_size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapRec {
    pub id: u64,
    pub name: Vec<u8>,
    pub image_size: u64,
    /// Legacy embedded parent (only decoded from / encoded to pre-Nautilus layout).
    pub parent: Parent,
    pub protection_status: u8,
    pub flags: u64,
    pub ns: SnapNs,
    pub timestamp: UTime,
    pub child_count: u32,
    pub parent_overlap: Option<u64>,
}
impl Default for SnapRec {
    fn default() -> Self {
        SnapRec {
            id: 0,
            name: Vec::new(),
            image_size: 0,
            parent: Parent::default(),
            protection_status: PROTECTION_UNPROTECTED,
            flags: 0,
            ns: SnapNs::User,
            timestamp: UTime::default(),
            child_count: 0,
            parent_overlap: None,
        }
    }
}
impl Encode for SnapRec {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        let new = features::have(e.features(), SERVER_NAUTILUS);
        e.versioned(8, if new { 8 } else { 1 }, |e| {
            e.u64(self.id)?;
            self.name.encode(e)?;
            e.u64(self.image_size)?;
            if !new {
                e.u64(0)?;
                self.parent.encode(e)?;
            }
            e.u8(self.protection_status)?;
            e.u64(self.flags)?;
            self.ns.encode(e)?;
            self.timestamp.encode(e)?;
            e.u32(self.child_count)?;
            self.parent_overlap.encode(e)
        })
    }
}
impl<'a> Decode<'a> for SnapRec {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        // struct_compat is needed to tell the legacy layout; the envelope helper hides it.
        let rest = d.peek_rest();
        let compat = *rest.get(1).ok_or(Error::Eof {
            needed: 2,
            remaining: rest.len(),
        })?;
        d.versioned(8, |d, v| {
            let id = d.u64()?;
            let name = Vec::<u8>::decode(d)?;
            let image_size = d.u64()?;
            let mut parent = Parent::default();
            if compat < 8 {
                d.u64()?;
                if v >= 2 {
                    parent = Parent::decode(d)?;
                }
            }
            let mut s = SnapRec {
                id,
                name,
                image_size,
                parent,
                ..Default::default()
            };
            if v >= 3 {
                s.protection_status = d.u8()?;
            }
            if v >= 4 {
                s.flags = d.u64()?;
            }
            if v >= 5 {
                s.ns = SnapNs::decode(d)?;
            }
            if v >= 6 {
                s.timestamp = UTime::decode(d)?;
            }
            if v >= 7 {
                s.child_count = d.u32()?;
            }
            if v >= 8 {
                s.parent_overlap = Option::<u64>::decode(d)?;
            }
            Ok(s)
        })
    }
}

/// `cls::rbd::SnapshotInfo` (v1/c1): snapshot_get output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub id: u64,
    pub ns: SnapNs,
    pub name: Vec<u8>,
    pub image_size: u64,
    pub timestamp: UTime,
    pub child_count: u32,
}
impl Encode for SnapshotInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| {
            e.u64(self.id)?;
            self.ns.encode(e)?;
            self.name.encode(e)?;
            e.u64(self.image_size)?;
            self.timestamp.encode(e)?;
            e.u32(self.child_count)
        })
    }
}
impl<'a> Decode<'a> for SnapshotInfo {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            Ok(SnapshotInfo {
                id: d.u64()?,
                ns: SnapNs::decode(d)?,
                name: Vec::<u8>::decode(d)?,
                image_size: d.u64()?,
                timestamp: UTime::decode(d)?,
                child_count: d.u32()?,
            })
        })
    }
}

/// `cls::rbd::TrashImageSpec` (v2/c1). source: 0 user, 1 mirroring, 2 migration, 3 removing,
/// 4 user_parent. state: 0 normal, 1 moving, 2 removing, 3 restoring.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrashImageSpec {
    pub source: u8,
    pub name: Vec<u8>,
    pub deletion_time: UTime,
    pub deferment_end_time: UTime,
    pub state: u8,
}
impl Encode for TrashImageSpec {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            e.u8(self.source)?;
            self.name.encode(e)?;
            self.deletion_time.encode(e)?;
            self.deferment_end_time.encode(e)?;
            e.u8(self.state)
        })
    }
}
impl<'a> Decode<'a> for TrashImageSpec {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            Ok(TrashImageSpec {
                source: d.u8()?,
                name: Vec::<u8>::decode(d)?,
                deletion_time: UTime::decode(d)?,
                deferment_end_time: UTime::decode(d)?,
                state: if v >= 2 { d.u8()? } else { 0 },
            })
        })
    }
}

/// `cls::rbd::MirrorImage` (v2/c1). state: 0 DISABLING, 1 ENABLED, 2 DISABLED, 3 CREATING;
/// mode: 0 JOURNAL, 1 SNAPSHOT.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MirrorImage {
    pub global_image_id: Vec<u8>,
    pub state: u8,
    pub mode: u8,
}
impl Encode for MirrorImage {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            self.global_image_id.encode(e)?;
            e.u8(self.state)?;
            e.u8(self.mode)
        })
    }
}
impl<'a> Decode<'a> for MirrorImage {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            Ok(MirrorImage {
                global_image_id: Vec::<u8>::decode(d)?,
                state: d.u8()?,
                mode: if v >= 2 { d.u8()? } else { 0 },
            })
        })
    }
}
