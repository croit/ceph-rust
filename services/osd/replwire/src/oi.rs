// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! object_info_t (v18) and its parts: watch_info_t, object_manifest_t, chunk_info_t
//! (spec replication.md 5.1).

use denc::types::{
    EntityAddr, EntityName, Eversion, Hobject, ObjectLocator, ObjectLocatorStorage, OsdReqId,
    ShardId, SnapId, UTime,
};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error, Result};
use std::collections::BTreeMap;

/// `object_info_t::flag_t` bits.
pub mod flag {
    pub const LOST: u32 = 1;
    pub const WHITEOUT: u32 = 2;
    pub const DIRTY: u32 = 4;
    pub const OMAP: u32 = 8;
    pub const DATA_DIGEST: u32 = 16;
    pub const OMAP_DIGEST: u32 = 32;
    pub const CACHE_PIN: u32 = 64;
    pub const MANIFEST: u32 = 128;
    pub const USES_TMAP: u32 = 256;
    pub const REDIRECT_HAS_REFERENCE: u32 = 512;
}

/// watch_info_t (v4, compat 3): cookie, timeout, addr (featured).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WatchInfo {
    pub cookie: u64,
    pub timeout_seconds: u32,
    pub addr: EntityAddr,
}

impl Encode for WatchInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(4, 3, |e| {
            e.u64(self.cookie)?;
            e.u32(self.timeout_seconds)?;
            self.addr.encode(e)
        })
    }
}
impl<'a> Decode<'a> for WatchInfo {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 4, |d, v| {
            let cookie = d.u64()?;
            let timeout_seconds = d.u32()?;
            let addr = if v >= 2 {
                EntityAddr::decode(d)?
            } else {
                EntityAddr::default()
            };
            Ok(WatchInfo {
                cookie,
                timeout_seconds,
                addr,
            })
        })
    }
}

/// chunk_info_t (v1): offset, length, oid, flags (spec: ENV(1,1); `offset` is the map key's twin).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChunkInfo {
    pub offset: u32,
    pub length: u32,
    pub oid: Hobject,
    pub flags: u32,
}
impl Encode for ChunkInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            e.u32(self.offset)?;
            e.u32(self.length)?;
            self.oid.encode(e)?;
            e.u32(self.flags)
        })
    }
}
impl<'a> Decode<'a> for ChunkInfo {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            Ok(ChunkInfo {
                offset: d.u32()?,
                length: d.u32()?,
                oid: Hobject::decode(d)?,
                flags: d.u32()?,
            })
        })
    }
}

/// object_manifest_t (v1). Out of scope for our pools; carried so a pushed `_` stays decodable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ObjectManifest {
    #[default]
    None,
    Redirect(Hobject),
    Chunked(BTreeMap<u64, ChunkInfo>),
}
impl Encode for ObjectManifest {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| match self {
            ObjectManifest::None => e.u8(0),
            ObjectManifest::Redirect(h) => {
                e.u8(1)?;
                h.encode(e)
            }
            ObjectManifest::Chunked(m) => {
                e.u8(2)?;
                m.encode(e)
            }
        })
    }
}
impl<'a> Decode<'a> for ObjectManifest {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| match d.u8()? {
            0 => Ok(ObjectManifest::None),
            1 => Ok(ObjectManifest::Redirect(Hobject::decode(d)?)),
            2 => Ok(ObjectManifest::Chunked(BTreeMap::decode(d)?)),
            m => Err(Error::BadMarker(m)),
        })
    }
}

/// object_info_t (xattr `_`). Encoded as v18 / compat 8; decodes v8..=18.
///
/// Fields without semantic value (oloc, category, wrlock_by, legacy_snaps, old_watchers, uses_tmap,
/// `lost`) are derived on encode, ignored on decode. Keep the raw `_` bytes in the store (spec 5.1 win)
/// and use this type for the decoded cache.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjectInfo {
    pub soid: Hobject,
    pub version: Eversion,
    pub prior_version: Eversion,
    pub last_reqid: OsdReqId,
    pub size: u64,
    pub mtime: UTime,
    pub truncate_seq: u64,
    pub truncate_size: u64,
    pub user_version: u64,
    /// (cookie, watcher name) -> info.
    pub watchers: BTreeMap<(u64, EntityName), WatchInfo>,
    pub flags: u32,
    pub local_mtime: UTime,
    pub data_digest: u32,
    pub omap_digest: u32,
    pub expected_object_size: u64,
    pub expected_write_size: u64,
    pub alloc_hint_flags: u32,
    /// Present on the wire iff FLAG_MANIFEST.
    pub manifest: Option<ObjectManifest>,
    pub shard_versions: BTreeMap<ShardId, Eversion>,
}

impl ObjectInfo {
    pub const STRUCT_V: u8 = 18;
    pub const STRUCT_COMPAT: u8 = 8;
    /// Digest value meaning "not set".
    pub const NO_DIGEST: u32 = u32::MAX;

    pub fn new(soid: Hobject) -> Self {
        ObjectInfo {
            soid,
            data_digest: Self::NO_DIGEST,
            omap_digest: Self::NO_DIGEST,
            ..Default::default()
        }
    }
    pub fn is_whiteout(&self) -> bool {
        self.flags & flag::WHITEOUT != 0
    }
    pub fn is_omap(&self) -> bool {
        self.flags & flag::OMAP != 0
    }
    /// The derived (ignored-on-decode) object_locator_t, borrowing the object's key/nspace (no copies).
    fn oloc(&self) -> ObjectLocatorStorage<&[u8]> {
        ObjectLocatorStorage {
            pool: self.soid.pool,
            key: &self.soid.key,
            nspace: &self.soid.nspace,
            hash: -1,
        }
    }
}

impl Encode for ObjectInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(Self::STRUCT_V, Self::STRUCT_COMPAT, |e| {
            self.soid.encode(e)?;
            self.oloc().encode(e)?;
            e.u32(0)?; // category
            self.version.encode(e)?;
            self.prior_version.encode(e)?;
            self.last_reqid.encode(e)?;
            e.u64(self.size)?;
            self.mtime.encode(e)?;
            if self.soid.snap == SnapId::NOSNAP {
                OsdReqId::default().encode(e)?; // wrlock_by
            } else {
                e.u32(0)?; // legacy_snaps
            }
            e.u64(self.truncate_seq)?;
            e.u64(self.truncate_size)?;
            e.u8((self.flags & flag::LOST != 0) as u8)?;
            let mut old: BTreeMap<EntityName, &WatchInfo> = BTreeMap::new();
            for ((_, name), w) in &self.watchers {
                old.insert(*name, w);
            }
            e.count(old.len())?;
            for (n, w) in old {
                n.encode(e)?;
                w.encode(e)?;
            }
            Eversion::new(0, self.user_version).encode(e)?;
            e.u8((self.flags & flag::USES_TMAP != 0) as u8)?;
            self.watchers.encode(e)?;
            e.u32(self.flags)?;
            self.local_mtime.encode(e)?;
            e.u32(self.data_digest)?;
            e.u32(self.omap_digest)?;
            e.u64(self.expected_object_size)?;
            e.u64(self.expected_write_size)?;
            e.u32(self.alloc_hint_flags)?;
            if self.flags & flag::MANIFEST != 0 {
                self.manifest.clone().unwrap_or_default().encode(e)?;
            }
            self.shard_versions.encode(e)
        })
    }
}

impl<'a> Decode<'a> for ObjectInfo {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(8, Self::STRUCT_V, |d, v| {
            let mut o = ObjectInfo::new(Hobject::decode(d)?);
            let _oloc = ObjectLocator::decode(d)?;
            let _category = Vec::<u8>::decode(d)?;
            o.version = Eversion::decode(d)?;
            o.prior_version = Eversion::decode(d)?;
            o.last_reqid = OsdReqId::decode(d)?;
            o.size = d.u64()?;
            o.mtime = UTime::decode(d)?;
            if o.soid.snap == SnapId::NOSNAP {
                let _wrlock_by = OsdReqId::decode(d)?;
            } else {
                let _legacy_snaps = Vec::<SnapId>::decode(d)?;
            }
            o.truncate_seq = d.u64()?;
            o.truncate_size = d.u64()?;
            let lost = d.u8()?;
            let _old_watchers = BTreeMap::<EntityName, WatchInfo>::decode(d)?;
            o.user_version = Eversion::decode(d)?.version;
            let uses_tmap = d.u8()?;
            o.watchers = BTreeMap::decode(d)?;
            if v >= 13 {
                o.flags = d.u32()?;
            } else {
                o.flags =
                    (lost != 0) as u32 * flag::LOST + (uses_tmap != 0) as u32 * flag::USES_TMAP;
            }
            if v >= 14 {
                o.local_mtime = UTime::decode(d)?;
            }
            if v >= 15 {
                o.data_digest = d.u32()?;
                o.omap_digest = d.u32()?;
            } else {
                // no digests on the wire: the reference decoder also drops the validity flags (checked via ceph-dencoder)
                o.flags &= !(flag::DATA_DIGEST | flag::OMAP_DIGEST);
            }
            if v >= 16 {
                o.expected_object_size = d.u64()?;
                o.expected_write_size = d.u64()?;
                o.alloc_hint_flags = d.u32()?;
            }
            if v >= 17 && o.flags & flag::MANIFEST != 0 {
                o.manifest = Some(ObjectManifest::decode(d)?);
            }
            if v >= 18 {
                o.shard_versions = BTreeMap::decode(d)?;
            }
            Ok(o)
        })
    }
}
