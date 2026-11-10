// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Wire types of class `rgw` (spec/cls_rgw.md s2): stored values (dir entry, header, olh, bilog)
//! and method I/O structs. Envelope versions/compat written equal classic's; decoders accept the
//! legacy (pre-envelope) forms classic still accepts. Field gating by `struct_v` as in the spec.

use crate::env_struct;
use crate::wire::{dec_packed, enc_packed, legacy};
use denc::types::UTime;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::BTreeMap;

type R<T> = denc::Result<T>;

// ---------------------------------------------------------------- enums (u8 on the wire)

/// `RGWModifyOp`
pub mod op {
    pub const ADD: u8 = 0;
    pub const DEL: u8 = 1;
    pub const CANCEL: u8 = 2;
    pub const UNKNOWN: u8 = 3;
    pub const LINK_OLH: u8 = 4;
    pub const LINK_OLH_DM: u8 = 5;
    pub const UNLINK_INSTANCE: u8 = 6;
    pub const SYNCSTOP: u8 = 7;
    pub const RESYNC: u8 = 8;
}
/// `RGWPendingState`
pub mod state {
    pub const PENDING_MODIFY: u8 = 0;
    pub const COMPLETE: u8 = 1;
    pub const UNKNOWN: u8 = 2;
}
/// `BIIndexType`
pub mod bi {
    pub const INVALID: u8 = 0;
    pub const PLAIN: u8 = 1;
    pub const INSTANCE: u8 = 2;
    pub const OLH: u8 = 3;
    pub const RESHARD_DELETED: u8 = 4;
}
/// `rgw_bucket_dir_entry` flags
pub mod flag {
    pub const VER: u16 = 0x1;
    pub const CURRENT: u16 = 0x2;
    pub const DELETE_MARKER: u16 = 0x4;
    pub const VER_MARKER: u16 = 0x8;
    pub const COMMON_PREFIX: u16 = 0x8000;
}
/// `cls_rgw_reshard_status`
pub mod reshard {
    pub const NOT_RESHARDING: u8 = 0;
    pub const IN_PROGRESS: u8 = 1;
    pub const DONE: u8 = 2;
    pub const IN_LOGRECORD: u8 = 3;
}
/// `OLHLogOp`
pub mod olh_op {
    pub const UNKNOWN: u8 = 0;
    pub const LINK_OLH: u8 = 1;
    pub const UNLINK_OLH: u8 = 2;
    pub const REMOVE_INSTANCE: u8 = 3;
    pub const STALE: u8 = 4;
}
/// `rgw_bi_log_entry.bilog_flags`
pub const BILOG_VERSIONED_OP: u16 = 1;
pub const BILOG_NULL_VERSION: u16 = 2;

// ---------------------------------------------------------------- small shared types

env_struct!(
    /// `cls_rgw_obj_key` / `rgw_obj_index_key`; ordered (name, instance).
    #[derive(PartialOrd, Ord)]
    ObjKey (1, 1) { name: Vec<u8>, instance: Vec<u8> });
impl ObjKey {
    pub fn new(name: &str, instance: &str) -> Self {
        ObjKey {
            name: name.as_bytes().to_vec(),
            instance: instance.as_bytes().to_vec(),
        }
    }
    pub fn from_bytes(name: &[u8], instance: &[u8]) -> Self {
        ObjKey {
            name: name.to_vec(),
            instance: instance.to_vec(),
        }
    }
}

/// `rgw_bucket_entry_ver` (1,1): packed pool (i64 via u64 cast), packed epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryVer {
    pub pool: i64,
    pub epoch: u64,
}
impl Default for EntryVer {
    fn default() -> Self {
        EntryVer { pool: -1, epoch: 0 }
    }
}
impl Encode for EntryVer {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(1, 1, |e| {
            enc_packed(e, self.pool as u64)?;
            enc_packed(e, self.epoch)
        })
    }
}
impl<'a> Decode<'a> for EntryVer {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        d.versioned(1, |d, _| {
            Ok(EntryVer {
                pool: dec_packed(d)? as i64,
                epoch: dec_packed(d)?,
            })
        })
    }
}

/// `rgw_zone_set`: NO envelope, `set<rgw_zone_set_entry>` where each entry is its string form
/// (`zone` or `zone:location_key`). Order kept as decoded.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZoneSet(pub Vec<Vec<u8>>);
impl Encode for ZoneSet {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        self.0.encode(e)
    }
}
impl<'a> Decode<'a> for ZoneSet {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        Ok(ZoneSet(Vec::decode(d)?))
    }
}

/// `rgw_bucket_pending_info` (2,2) legacy(2,2,2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PendingInfo {
    pub state: u8,
    pub timestamp: UTime,
    pub op: u8,
}
impl Encode for PendingInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(2, 2, |e| {
            e.u8(self.state)?;
            self.timestamp.encode(e)?;
            e.u8(self.op)
        })
    }
}
impl<'a> Decode<'a> for PendingInfo {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        legacy(d, 2, 2, 2, |d, _| {
            Ok(PendingInfo {
                state: d.u8()?,
                timestamp: UTime::decode(d)?,
                op: d.u8()?,
            })
        })
    }
}

/// `rgw_bucket_dir_entry_meta` (8,3) legacy(8,3,3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirEntryMeta {
    pub category: u8,
    pub size: u64,
    pub mtime: UTime,
    pub etag: Vec<u8>,
    pub owner: Vec<u8>,
    pub owner_display_name: Vec<u8>,
    pub content_type: Vec<u8>,
    pub accounted_size: u64,
    pub user_data: Vec<u8>,
    pub storage_class: Vec<u8>,
    pub appendable: bool,
    pub restore_status: u8,
    pub restore_expiry_date: UTime,
}
impl Encode for DirEntryMeta {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(8, 3, |e| {
            e.u8(self.category)?;
            e.u64(self.size)?;
            self.mtime.encode(e)?;
            self.etag.encode(e)?;
            self.owner.encode(e)?;
            self.owner_display_name.encode(e)?;
            self.content_type.encode(e)?;
            e.u64(self.accounted_size)?;
            self.user_data.encode(e)?;
            self.storage_class.encode(e)?;
            e.bool(self.appendable)?;
            e.u8(self.restore_status)?;
            self.restore_expiry_date.encode(e)
        })
    }
}
impl<'a> Decode<'a> for DirEntryMeta {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        legacy(d, 8, 3, 3, |d, v| {
            let mut m = DirEntryMeta {
                category: d.u8()?,
                size: d.u64()?,
                mtime: UTime::decode(d)?,
                etag: Vec::<u8>::decode(d)?,
                owner: Vec::<u8>::decode(d)?,
                owner_display_name: Vec::<u8>::decode(d)?,
                ..Default::default()
            };
            if v >= 2 {
                m.content_type = Vec::<u8>::decode(d)?;
            }
            m.accounted_size = if v >= 4 { d.u64()? } else { m.size };
            if v >= 5 {
                m.user_data = Vec::<u8>::decode(d)?;
            }
            if v >= 6 {
                m.storage_class = Vec::<u8>::decode(d)?;
            }
            if v >= 7 {
                m.appendable = d.bool()?;
            }
            if v >= 8 {
                m.restore_status = d.u8()?;
                m.restore_expiry_date = UTime::decode(d)?;
            }
            Ok(m)
        })
    }
}

/// `rgw_bucket_dir_entry` (8,3) legacy(8,3,3): value of plain/instance/list omap keys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirEntry {
    pub key: ObjKey,
    pub ver: EntryVer,
    pub exists: bool,
    pub meta: DirEntryMeta,
    /// multimap<string tag, pending_info>, sorted by tag (equal tags keep insertion order).
    pub pending: Vec<(Vec<u8>, PendingInfo)>,
    pub locator: Vec<u8>,
    pub index_ver: u64,
    pub tag: Vec<u8>,
    pub flags: u16,
    pub versioned_epoch: u64,
}
impl DirEntry {
    pub fn is_current(&self) -> bool {
        self.flags & flag::VER == 0
            || self.flags & (flag::VER | flag::CURRENT) == (flag::VER | flag::CURRENT)
    }
    pub fn is_delete_marker(&self) -> bool {
        self.flags & flag::DELETE_MARKER != 0
    }
    pub fn is_visible(&self) -> bool {
        self.is_current() && !self.is_delete_marker()
    }
    pub fn is_valid(&self) -> bool {
        self.flags & flag::VER_MARKER == 0
    }
    /// multimap insert: after existing equal keys.
    pub fn pending_insert(&mut self, tag: &[u8], info: PendingInfo) {
        let i = self.pending.partition_point(|(t, _)| t.as_slice() <= tag);
        self.pending.insert(i, (tag.to_owned(), info));
    }
    /// multimap find + erase (first match). False if absent.
    pub fn pending_erase(&mut self, tag: &[u8]) -> bool {
        match self.pending.iter().position(|(t, _)| t == tag) {
            Some(i) => {
                self.pending.remove(i);
                true
            }
            None => false,
        }
    }
}
impl Encode for DirEntry {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(8, 3, |e| {
            self.key.name.encode(e)?;
            e.u64(self.ver.epoch)?;
            e.bool(self.exists)?;
            self.meta.encode(e)?;
            e.count(self.pending.len())?;
            for (k, v) in &self.pending {
                k.encode(e)?;
                v.encode(e)?;
            }
            self.locator.encode(e)?;
            self.ver.encode(e)?;
            enc_packed(e, self.index_ver)?;
            self.tag.encode(e)?;
            self.key.instance.encode(e)?;
            e.u16(self.flags)?;
            e.u64(self.versioned_epoch)
        })
    }
}
impl<'a> Decode<'a> for DirEntry {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        legacy(d, 8, 3, 3, |d, v| {
            let mut x = DirEntry {
                key: ObjKey {
                    name: Vec::<u8>::decode(d)?,
                    instance: Vec::new(),
                },
                ..Default::default()
            };
            x.ver.epoch = d.u64()?;
            x.exists = d.bool()?;
            x.meta = DirEntryMeta::decode(d)?;
            let n = d.count()?;
            for _ in 0..n {
                let k = Vec::<u8>::decode(d)?;
                x.pending.push((k, PendingInfo::decode(d)?));
            }
            x.pending.sort_by(|a, b| a.0.cmp(&b.0)); // stable
            if v >= 2 {
                x.locator = Vec::<u8>::decode(d)?;
            }
            if v >= 4 {
                x.ver = EntryVer::decode(d)?;
            } else {
                x.ver.pool = -1;
            }
            if v >= 5 {
                x.index_ver = dec_packed(d)?;
                x.tag = Vec::<u8>::decode(d)?;
            }
            if v >= 6 {
                x.key.instance = Vec::<u8>::decode(d)?;
            }
            if v >= 7 {
                x.flags = d.u16()?;
            }
            if v >= 8 {
                x.versioned_epoch = d.u64()?;
            }
            Ok(x)
        })
    }
}

/// `rgw_bucket_category_stats` (3,2) legacy(3,2,2). All arithmetic wraps (bug-compat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CategoryStats {
    pub total_size: u64,
    pub total_size_rounded: u64,
    pub num_entries: u64,
    pub actual_size: u64,
}
impl CategoryStats {
    pub fn add(&mut self, o: &CategoryStats) {
        self.total_size = self.total_size.wrapping_add(o.total_size);
        self.total_size_rounded = self.total_size_rounded.wrapping_add(o.total_size_rounded);
        self.num_entries = self.num_entries.wrapping_add(o.num_entries);
        self.actual_size = self.actual_size.wrapping_add(o.actual_size);
    }
    pub fn sub(&mut self, o: &CategoryStats) {
        self.total_size = self.total_size.wrapping_sub(o.total_size);
        self.total_size_rounded = self.total_size_rounded.wrapping_sub(o.total_size_rounded);
        self.num_entries = self.num_entries.wrapping_sub(o.num_entries);
        self.actual_size = self.actual_size.wrapping_sub(o.actual_size);
    }
}
impl Encode for CategoryStats {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(3, 2, |e| {
            e.u64(self.total_size)?;
            e.u64(self.total_size_rounded)?;
            e.u64(self.num_entries)?;
            e.u64(self.actual_size)
        })
    }
}
impl<'a> Decode<'a> for CategoryStats {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        legacy(d, 3, 2, 2, |d, v| {
            let total_size = d.u64()?;
            let total_size_rounded = d.u64()?;
            let num_entries = d.u64()?;
            let actual_size = if v >= 3 { d.u64()? } else { total_size };
            Ok(CategoryStats {
                total_size,
                total_size_rounded,
                num_entries,
                actual_size,
            })
        })
    }
}

/// `cls_rgw_bucket_instance_entry` (3,1): only the reshard status is live; the two legacy fields
/// are written empty (v3 bytes) and skipped on decode (absent in v2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InstanceEntry {
    pub reshard_status: u8,
}
impl InstanceEntry {
    pub fn resharding(&self) -> bool {
        self.reshard_status != reshard::NOT_RESHARDING
    }
    pub fn in_progress(&self) -> bool {
        self.reshard_status == reshard::IN_PROGRESS
    }
    pub fn in_logrecord(&self) -> bool {
        self.reshard_status == reshard::IN_LOGRECORD
    }
}
impl Encode for InstanceEntry {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(3, 1, |e| {
            e.u8(self.reshard_status)?;
            String::new().encode(e)?;
            e.i32(-1)
        })
    }
}
impl<'a> Decode<'a> for InstanceEntry {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        d.versioned(3, |d, v| {
            let reshard_status = d.u8()?;
            if v != 2 {
                Vec::<u8>::decode(d)?;
                d.i32()?;
            }
            Ok(InstanceEntry { reshard_status })
        })
    }
}

/// `rgw_bucket_dir_header` (8,2) legacy(8,2,2): the omap HEADER of an index shard.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirHeader {
    pub stats: BTreeMap<u8, CategoryStats>,
    pub tag_timeout: u64,
    pub ver: u64,
    pub master_ver: u64,
    pub max_marker: Vec<u8>,
    pub new_instance: InstanceEntry,
    pub syncstopped: bool,
    pub reshardlog_entries: u32,
}
impl Encode for DirHeader {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(8, 2, |e| {
            self.stats.encode(e)?;
            e.u64(self.tag_timeout)?;
            e.u64(self.ver)?;
            e.u64(self.master_ver)?;
            self.max_marker.encode(e)?;
            self.new_instance.encode(e)?;
            e.bool(self.syncstopped)?;
            e.u32(self.reshardlog_entries)
        })
    }
}
impl<'a> Decode<'a> for DirHeader {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        legacy(d, 8, 2, 2, |d, v| {
            let mut h = DirHeader {
                stats: BTreeMap::decode(d)?,
                ..Default::default()
            };
            if v > 2 {
                h.tag_timeout = d.u64()?;
            }
            if v >= 4 {
                h.ver = d.u64()?;
                h.master_ver = d.u64()?;
            }
            if v >= 5 {
                h.max_marker = Vec::<u8>::decode(d)?;
            }
            if v >= 6 {
                h.new_instance = InstanceEntry::decode(d)?;
            }
            if v >= 7 {
                h.syncstopped = d.bool()?;
            }
            if v >= 8 {
                h.reshardlog_entries = d.u32()?;
            }
            Ok(h)
        })
    }
}

/// `rgw_bucket_dir` (2,2) legacy(2,2,2): header + ascending map of omap key -> entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dir {
    pub header: DirHeader,
    pub m: BTreeMap<Vec<u8>, DirEntry>,
}
impl Encode for Dir {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(2, 2, |e| {
            self.header.encode(e)?;
            e.count(self.m.len())?;
            for (k, v) in &self.m {
                k.encode(e)?;
                v.encode(e)?;
            }
            Ok(())
        })
    }
}
impl<'a> Decode<'a> for Dir {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        legacy(d, 2, 2, 2, |d, _| {
            Ok(Dir {
                header: DirHeader::decode(d)?,
                m: BTreeMap::decode(d)?,
            })
        })
    }
}

// ---------------------------------------------------------------- olh / bi / bilog

env_struct!(
    /// `rgw_bucket_olh_log_entry`
    OlhLogEntry (1, 1) { epoch: u64, op: u8, op_tag: Vec<u8>, key: ObjKey, delete_marker: bool });
env_struct!(
/// `rgw_bucket_olh_entry` = value of the olh key. `pending_log`: epoch -> entries.
OlhEntry (1, 1) {
    key: ObjKey,
    delete_marker: bool,
    epoch: u64,
    pending_log: BTreeMap<u64, Vec<OlhLogEntry>>,
    tag: Vec<u8>,
    exists: bool,
    pending_removal: bool,
});
env_struct!(
    /// `rgw_bucket_deleted_entry`
    DeletedEntry (1, 1) { key: ObjKey });
env_struct!(
    /// `rgw_cls_bi_entry`: `data` = the stored omap value verbatim.
    BiEntry (1, 1) { ty: u8, idx: Vec<u8>, data: Vec<u8> });

/// `rgw_bi_log_entry` (4,1) = value of bilog keys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BiLogEntry {
    pub id: Vec<u8>,
    pub object: Vec<u8>,
    pub instance: Vec<u8>,
    pub timestamp: UTime,
    pub ver: EntryVer,
    pub op: u8,
    pub state: u8,
    pub index_ver: u64,
    pub tag: Vec<u8>,
    pub bilog_flags: u16,
    pub owner: Vec<u8>,
    pub owner_display_name: Vec<u8>,
    pub zones_trace: ZoneSet,
}
impl Encode for BiLogEntry {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(4, 1, |e| {
            self.id.encode(e)?;
            self.object.encode(e)?;
            self.timestamp.encode(e)?;
            self.ver.encode(e)?;
            self.tag.encode(e)?;
            e.u8(self.op)?;
            e.u8(self.state)?;
            enc_packed(e, self.index_ver)?;
            self.instance.encode(e)?;
            e.u16(self.bilog_flags)?;
            self.owner.encode(e)?;
            self.owner_display_name.encode(e)?;
            self.zones_trace.encode(e)
        })
    }
}
impl<'a> Decode<'a> for BiLogEntry {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        d.versioned(4, |d, v| {
            let mut x = BiLogEntry {
                id: Vec::<u8>::decode(d)?,
                object: Vec::<u8>::decode(d)?,
                timestamp: UTime::decode(d)?,
                ver: EntryVer::decode(d)?,
                tag: Vec::<u8>::decode(d)?,
                op: d.u8()?,
                state: d.u8()?,
                index_ver: dec_packed(d)?,
                ..Default::default()
            };
            if v >= 2 {
                x.instance = Vec::<u8>::decode(d)?;
                x.bilog_flags = d.u16()?;
            }
            if v >= 3 {
                x.owner = Vec::<u8>::decode(d)?;
                x.owner_display_name = Vec::<u8>::decode(d)?;
            }
            if v >= 4 {
                x.zones_trace = ZoneSet::decode(d)?;
            }
            Ok(x)
        })
    }
}

// ---------------------------------------------------------------- method I/O

env_struct!(TagTimeoutOp (1, 1) { tag_timeout: u64 });

/// `rgw_cls_obj_prepare_op` (7,5) legacy(7,3,3). Pre-v5 encodings carried only `key.name`
/// (right after `op`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjPrepareOp {
    pub op: u8,
    pub tag: Vec<u8>,
    pub locator: Vec<u8>,
    pub log_op: bool,
    pub key: ObjKey,
    pub bilog_flags: u16,
    pub zones_trace: ZoneSet,
}
impl Encode for ObjPrepareOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(7, 5, |e| {
            e.u8(self.op)?;
            self.tag.encode(e)?;
            self.locator.encode(e)?;
            e.bool(self.log_op)?;
            self.key.encode(e)?;
            e.u16(self.bilog_flags)?;
            self.zones_trace.encode(e)
        })
    }
}
impl<'a> Decode<'a> for ObjPrepareOp {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        legacy(d, 7, 3, 3, |d, v| {
            let mut x = ObjPrepareOp {
                op: d.u8()?,
                ..Default::default()
            };
            if v < 5 {
                x.key.name = Vec::<u8>::decode(d)?;
            }
            x.tag = Vec::<u8>::decode(d)?;
            if v >= 2 {
                x.locator = Vec::<u8>::decode(d)?;
            }
            if v >= 4 {
                x.log_op = d.bool()?;
            }
            if v >= 5 {
                x.key = ObjKey::decode(d)?;
            }
            if v >= 6 {
                x.bilog_flags = d.u16()?;
            }
            if v >= 7 {
                x.zones_trace = ZoneSet::decode(d)?;
            }
            Ok(x)
        })
    }
}

/// `rgw_cls_obj_complete_op` (9,7) legacy(9,3,3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjCompleteOp {
    pub op: u8,
    pub ver: EntryVer,
    pub meta: DirEntryMeta,
    pub op_tag: Vec<u8>,
    pub locator: Vec<u8>,
    pub remove_objs: Vec<ObjKey>,
    pub log_op: bool,
    pub key: ObjKey,
    pub bilog_flags: u16,
    pub zones_trace: ZoneSet,
}
impl Default for ObjCompleteOp {
    fn default() -> Self {
        ObjCompleteOp {
            op: op::ADD,
            ver: EntryVer::default(),
            meta: DirEntryMeta::default(),
            op_tag: Vec::new(),
            locator: Vec::new(),
            remove_objs: Vec::new(),
            log_op: false,
            key: ObjKey::default(),
            bilog_flags: 0,
            zones_trace: ZoneSet::default(),
        }
    }
}
impl Encode for ObjCompleteOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(9, 7, |e| {
            e.u8(self.op)?;
            e.u64(self.ver.epoch)?;
            self.meta.encode(e)?;
            self.op_tag.encode(e)?;
            self.locator.encode(e)?;
            self.remove_objs.encode(e)?;
            self.ver.encode(e)?;
            e.bool(self.log_op)?;
            self.key.encode(e)?;
            e.u16(self.bilog_flags)?;
            self.zones_trace.encode(e)
        })
    }
}
impl<'a> Decode<'a> for ObjCompleteOp {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        legacy(d, 9, 3, 3, |d, v| {
            let mut x = ObjCompleteOp {
                op: d.u8()?,
                ..Default::default()
            };
            if v < 7 {
                x.key.name = Vec::<u8>::decode(d)?;
            }
            x.ver.epoch = d.u64()?;
            x.meta = DirEntryMeta::decode(d)?;
            x.op_tag = Vec::<u8>::decode(d)?;
            if v >= 2 {
                x.locator = Vec::<u8>::decode(d)?;
            }
            if (4..7).contains(&v) {
                for name in Vec::<Vec<u8>>::decode(d)? {
                    x.remove_objs.push(ObjKey {
                        name,
                        instance: Vec::new(),
                    });
                }
            } else {
                // upstream decodes list<key> for v < 4 as well (bug-compat)
                x.remove_objs = Vec::decode(d)?;
            }
            if v >= 5 {
                x.ver = EntryVer::decode(d)?;
            } else {
                x.ver.pool = -1;
            }
            if v >= 6 {
                x.log_op = d.bool()?;
            }
            if v >= 7 {
                x.key = ObjKey::decode(d)?;
            }
            if v >= 8 {
                x.bilog_flags = d.u16()?;
            }
            if v >= 9 {
                x.zones_trace = ZoneSet::decode(d)?;
            }
            Ok(x)
        })
    }
}

/// `rgw_cls_link_olh_op` (5,1). `unmod_since` is written twice (time_t u64, then utime).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkOlhOp {
    pub key: ObjKey,
    pub olh_tag: Vec<u8>,
    pub delete_marker: bool,
    pub op_tag: Vec<u8>,
    pub meta: DirEntryMeta,
    pub olh_epoch: u64,
    pub log_op: bool,
    pub bilog_flags: u16,
    pub unmod_since: UTime,
    pub high_precision_time: bool,
    pub zones_trace: ZoneSet,
}
impl Encode for LinkOlhOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(5, 1, |e| {
            self.key.encode(e)?;
            self.olh_tag.encode(e)?;
            e.bool(self.delete_marker)?;
            self.op_tag.encode(e)?;
            self.meta.encode(e)?;
            e.u64(self.olh_epoch)?;
            e.bool(self.log_op)?;
            e.u16(self.bilog_flags)?;
            e.u64(self.unmod_since.sec as u64)?;
            self.unmod_since.encode(e)?;
            e.bool(self.high_precision_time)?;
            self.zones_trace.encode(e)
        })
    }
}
impl<'a> Decode<'a> for LinkOlhOp {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        d.versioned(5, |d, v| {
            let mut x = LinkOlhOp {
                key: ObjKey::decode(d)?,
                olh_tag: Vec::<u8>::decode(d)?,
                delete_marker: d.bool()?,
                op_tag: Vec::<u8>::decode(d)?,
                meta: DirEntryMeta::decode(d)?,
                olh_epoch: d.u64()?,
                log_op: d.bool()?,
                bilog_flags: d.u16()?,
                ..Default::default()
            };
            if v == 2 {
                x.unmod_since = UTime::new(d.u64()? as u32, 0);
            }
            if v >= 3 {
                d.u64()?;
                x.unmod_since = UTime::decode(d)?;
            }
            if v >= 4 {
                x.high_precision_time = d.bool()?;
            }
            if v >= 5 {
                x.zones_trace = ZoneSet::decode(d)?;
            }
            Ok(x)
        })
    }
}

/// `rgw_cls_unlink_instance_op` (3,1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnlinkInstanceOp {
    pub key: ObjKey,
    pub op_tag: Vec<u8>,
    pub olh_epoch: u64,
    pub log_op: bool,
    pub bilog_flags: u16,
    pub olh_tag: Vec<u8>,
    pub zones_trace: ZoneSet,
}
impl Encode for UnlinkInstanceOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(3, 1, |e| {
            self.key.encode(e)?;
            self.op_tag.encode(e)?;
            e.u64(self.olh_epoch)?;
            e.bool(self.log_op)?;
            e.u16(self.bilog_flags)?;
            self.olh_tag.encode(e)?;
            self.zones_trace.encode(e)
        })
    }
}
impl<'a> Decode<'a> for UnlinkInstanceOp {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        d.versioned(3, |d, v| {
            let mut x = UnlinkInstanceOp {
                key: ObjKey::decode(d)?,
                op_tag: Vec::<u8>::decode(d)?,
                olh_epoch: d.u64()?,
                log_op: d.bool()?,
                bilog_flags: d.u16()?,
                ..Default::default()
            };
            if v >= 2 {
                x.olh_tag = Vec::<u8>::decode(d)?;
            }
            if v >= 3 {
                x.zones_trace = ZoneSet::decode(d)?;
            }
            Ok(x)
        })
    }
}

/// `rgw_cls_read_olh_log_op` (2,1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReadOlhLogOp {
    pub olh: ObjKey,
    pub ver_marker: u64,
    pub olh_tag: Vec<u8>,
    pub get_stales: bool,
}
impl Encode for ReadOlhLogOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(2, 1, |e| {
            self.olh.encode(e)?;
            e.u64(self.ver_marker)?;
            self.olh_tag.encode(e)?;
            e.bool(self.get_stales)
        })
    }
}
impl<'a> Decode<'a> for ReadOlhLogOp {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        d.versioned(2, |d, v| {
            Ok(ReadOlhLogOp {
                olh: ObjKey::decode(d)?,
                ver_marker: d.u64()?,
                olh_tag: Vec::<u8>::decode(d)?,
                get_stales: if v >= 2 { d.bool()? } else { false },
            })
        })
    }
}
env_struct!(ReadOlhLogRet (1, 1) { log: BTreeMap<u64, Vec<OlhLogEntry>>, is_truncated: bool });
env_struct!(TrimOlhLogOp (1, 1) { olh: ObjKey, ver: u64, olh_tag: Vec<u8> });
env_struct!(ClearOlhOp (1, 1) { key: ObjKey, olh_tag: Vec<u8> });

/// `rgw_cls_list_op` (6,4) legacy(6,2,2). Pre-v4: `start_obj.name` first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListOp {
    pub num_entries: u32,
    pub filter_prefix: Vec<u8>,
    pub start_obj: ObjKey,
    pub list_versions: bool,
    pub delimiter: Vec<u8>,
}
impl Encode for ListOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(6, 4, |e| {
            e.u32(self.num_entries)?;
            self.filter_prefix.encode(e)?;
            self.start_obj.encode(e)?;
            e.bool(self.list_versions)?;
            self.delimiter.encode(e)
        })
    }
}
impl<'a> Decode<'a> for ListOp {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        legacy(d, 6, 2, 2, |d, v| {
            let mut x = ListOp::default();
            if v < 4 {
                x.start_obj.name = Vec::<u8>::decode(d)?;
            }
            x.num_entries = d.u32()?;
            if v >= 3 {
                x.filter_prefix = Vec::<u8>::decode(d)?;
            }
            if v >= 4 {
                x.start_obj = ObjKey::decode(d)?;
            }
            if v >= 5 {
                x.list_versions = d.bool()?;
            }
            if v >= 6 {
                x.delimiter = Vec::<u8>::decode(d)?;
            }
            Ok(x)
        })
    }
}

/// `rgw_cls_list_ret` (4,2) legacy(4,2,2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListRet {
    pub dir: Dir,
    pub is_truncated: bool,
    pub marker: ObjKey,
}
impl Encode for ListRet {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(4, 2, |e| {
            self.dir.encode(e)?;
            e.bool(self.is_truncated)?;
            self.marker.encode(e)
        })
    }
}
impl<'a> Decode<'a> for ListRet {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        legacy(d, 4, 2, 2, |d, v| {
            Ok(ListRet {
                dir: Dir::decode(d)?,
                is_truncated: d.bool()?,
                marker: if v >= 4 {
                    ObjKey::decode(d)?
                } else {
                    ObjKey::default()
                },
            })
        })
    }
}

env_struct!(CheckIndexRet (1, 1) { existing_header: DirHeader, calculated_header: DirHeader });

/// `rgw_cls_bucket_update_stats_op` (2,1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpdateStatsOp {
    pub absolute: bool,
    pub stats: BTreeMap<u8, CategoryStats>,
    pub dec_stats: BTreeMap<u8, CategoryStats>,
}
impl Encode for UpdateStatsOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(2, 1, |e| {
            e.bool(self.absolute)?;
            self.stats.encode(e)?;
            self.dec_stats.encode(e)
        })
    }
}
impl<'a> Decode<'a> for UpdateStatsOp {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        d.versioned(2, |d, v| {
            Ok(UpdateStatsOp {
                absolute: d.bool()?,
                stats: BTreeMap::decode(d)?,
                dec_stats: if v >= 2 {
                    BTreeMap::decode(d)?
                } else {
                    BTreeMap::new()
                },
            })
        })
    }
}

env_struct!(ObjRemoveOp (1, 1) { keep_attr_prefixes: Vec<Vec<u8>> });
env_struct!(StorePgVerOp (1, 1) { attr: Vec<u8> });
env_struct!(CheckAttrsPrefixOp (1, 1) { check_prefix: Vec<u8>, fail_if_exist: bool });

/// `rgw_cls_obj_check_mtime` (2,1); `ty`: 0 EQ, 1 LT, 2 LE, 3 GT, 4 GE.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CheckMtimeOp {
    pub mtime: UTime,
    pub ty: u8,
    pub high_precision_time: bool,
}
impl Encode for CheckMtimeOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(2, 1, |e| {
            self.mtime.encode(e)?;
            e.u8(self.ty)?;
            e.bool(self.high_precision_time)
        })
    }
}
impl<'a> Decode<'a> for CheckMtimeOp {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        d.versioned(2, |d, v| {
            Ok(CheckMtimeOp {
                mtime: UTime::decode(d)?,
                ty: d.u8()?,
                high_precision_time: if v >= 2 { d.bool()? } else { false },
            })
        })
    }
}

env_struct!(BiGetOp (1, 1) { key: ObjKey, ty: u8 });
env_struct!(BiGetRet (1, 1) { entry: BiEntry });
env_struct!(BiPutOp (1, 1) { entry: BiEntry });
env_struct!(BiPutEntriesOp (1, 1) { entries: Vec<BiEntry>, check_existing: bool });

/// `rgw_cls_bi_list_op` (2,1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BiListOp {
    pub max: u32,
    pub name_filter: Vec<u8>,
    pub marker: Vec<u8>,
    pub reshardlog: bool,
}
impl Encode for BiListOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(2, 1, |e| {
            e.u32(self.max)?;
            self.name_filter.encode(e)?;
            self.marker.encode(e)?;
            e.bool(self.reshardlog)
        })
    }
}
impl<'a> Decode<'a> for BiListOp {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        d.versioned(2, |d, v| {
            Ok(BiListOp {
                max: d.u32()?,
                name_filter: Vec::<u8>::decode(d)?,
                marker: Vec::<u8>::decode(d)?,
                reshardlog: if v >= 2 { d.bool()? } else { false },
            })
        })
    }
}
env_struct!(BiListRet (1, 1) { entries: Vec<BiEntry>, is_truncated: bool });

env_struct!(BiLogListOp (1, 1) { marker: Vec<u8>, max: u32 });
env_struct!(BiLogListRet (1, 1) { entries: Vec<BiLogEntry>, truncated: bool });
env_struct!(BiLogTrimOp (1, 1) { start_marker: Vec<u8>, end_marker: Vec<u8> });

env_struct!(GuardOp (1, 1) { ret_err: i32 });
env_struct!(SetReshardingOp (1, 1) { entry: InstanceEntry });
env_struct!(
    /// `cls_rgw_clear_bucket_resharding_op` / `cls_rgw_get_bucket_resharding_op`: empty body.
    EmptyOp (1, 1) {});
env_struct!(GetReshardingRet (1, 1) { new_instance: InstanceEntry });

env_struct!(
/// `cls_rgw_reshard_entry` (3,1); decoder drops the v1-only string.
ReshardEntryBody (3, 1) {
    time: UTime,
    tenant: Vec<u8>,
    bucket_name: Vec<u8>,
    bucket_id: Vec<u8>,
    old_num_shards: u32,
    new_num_shards: u32,
    initiator: u8,
});
/// `cls_rgw_reshard_entry`; same as the body struct but with the v1 decode rule.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReshardEntry(pub ReshardEntryBody);
impl Encode for ReshardEntry {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        self.0.encode(e)
    }
}
impl<'a> Decode<'a> for ReshardEntry {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        d.versioned(3, |d, v| {
            let time = UTime::decode(d)?;
            let tenant = Vec::<u8>::decode(d)?;
            let bucket_name = Vec::<u8>::decode(d)?;
            let bucket_id = Vec::<u8>::decode(d)?;
            if v < 2 {
                Vec::<u8>::decode(d)?;
            }
            let old_num_shards = d.u32()?;
            let new_num_shards = d.u32()?;
            let initiator = if v >= 3 { d.u8()? } else { 0 };
            Ok(ReshardEntry(ReshardEntryBody {
                time,
                tenant,
                bucket_name,
                bucket_id,
                old_num_shards,
                new_num_shards,
                initiator,
            }))
        })
    }
}
impl std::ops::Deref for ReshardEntry {
    type Target = ReshardEntryBody;
    fn deref(&self) -> &ReshardEntryBody {
        &self.0
    }
}
impl std::ops::DerefMut for ReshardEntry {
    fn deref_mut(&mut self) -> &mut ReshardEntryBody {
        &mut self.0
    }
}

/// `cls_rgw_reshard_add_op` (2,1): entry + create_only (v2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReshardAddOp {
    pub entry: ReshardEntry,
    pub create_only: bool,
}
impl Encode for ReshardAddOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> R<()> {
        e.versioned(2, 1, |e| {
            self.entry.encode(e)?;
            e.bool(self.create_only)
        })
    }
}
impl<'a> Decode<'a> for ReshardAddOp {
    fn decode(d: &mut Decoder<'a>) -> R<Self> {
        d.versioned(2, |d, v| {
            Ok(ReshardAddOp {
                entry: ReshardEntry::decode(d)?,
                create_only: if v >= 2 { d.bool()? } else { false },
            })
        })
    }
}
env_struct!(ReshardListOp (1, 1) { max: u32, marker: Vec<u8> });
env_struct!(ReshardListRet (1, 1) { entries: Vec<ReshardEntry>, is_truncated: bool });
env_struct!(ReshardGetOp (1, 1) { entry: ReshardEntry });
env_struct!(ReshardGetRet (1, 1) { entry: ReshardEntry });
env_struct!(ReshardRemoveOp (1, 1) { tenant: Vec<u8>, bucket_name: Vec<u8>, bucket_id: Vec<u8> });
