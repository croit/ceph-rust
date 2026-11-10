// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Mirroring wire/stored structures (spec/cls_rbd.md C.3.2).

use crate::env_struct;
use denc::types::{EntityAddr, EntityInst, UTime};
use denc::{BufMut, Decode, Decoder, Encode, Encoder};

pub const DIR_RX: u8 = 0;
pub const DIR_TX: u8 = 1;
pub const DIR_RX_TX: u8 = 2;

pub const MODE_DISABLED: u32 = 0;
pub const MODE_IMAGE: u32 = 1;
pub const MODE_POOL: u32 = 2;
pub const MODE_INIT_ONLY: u32 = 3;

pub const IMG_DISABLING: u8 = 0;
pub const IMG_ENABLED: u8 = 1;
pub const IMG_CREATING: u8 = 3;

pub const ST_UNKNOWN: u8 = 0;
pub const ST_ERROR: u8 = 1;

/// `cls::rbd::MirrorPeer` (v2/c1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorPeer {
    pub uuid: Vec<u8>,
    pub direction: u8,
    pub site_name: Vec<u8>,
    pub client_name: Vec<u8>,
    pub mirror_uuid: Vec<u8>,
    pub last_seen: UTime,
}
impl Default for MirrorPeer {
    fn default() -> Self {
        MirrorPeer {
            uuid: Vec::new(),
            direction: DIR_RX_TX,
            site_name: Vec::new(),
            client_name: Vec::new(),
            mirror_uuid: Vec::new(),
            last_seen: UTime::default(),
        }
    }
}
impl MirrorPeer {
    pub fn is_valid(&self) -> bool {
        match self.direction {
            DIR_TX => {}
            DIR_RX | DIR_RX_TX if !self.client_name.is_empty() => {}
            _ => return false,
        }
        !self.uuid.is_empty() && !self.site_name.is_empty()
    }
}
impl Encode for MirrorPeer {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            self.uuid.encode(e)?;
            self.site_name.encode(e)?;
            self.client_name.encode(e)?;
            e.i64(-1)?;
            e.u8(self.direction)?;
            self.mirror_uuid.encode(e)?;
            self.last_seen.encode(e)
        })
    }
}
impl<'a> Decode<'a> for MirrorPeer {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            let mut p = MirrorPeer {
                uuid: Vec::<u8>::decode(d)?,
                site_name: Vec::<u8>::decode(d)?,
                client_name: Vec::<u8>::decode(d)?,
                ..Default::default()
            };
            d.i64()?;
            if v >= 2 {
                p.direction = d.u8()?;
                p.mirror_uuid = Vec::<u8>::decode(d)?;
                p.last_seen = UTime::decode(d)?;
            }
            Ok(p)
        })
    }
}

/// `cls::rbd::MirrorImageSiteStatus`; local site = empty `mirror_uuid`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SiteStatus {
    pub mirror_uuid: Vec<u8>,
    pub state: u8,
    pub description: Vec<u8>,
    pub last_update: UTime,
    pub up: bool,
}
impl SiteStatus {
    /// Body without envelope; `version` >= 2 includes the mirror uuid.
    pub fn encode_meta<B: BufMut>(&self, e: &mut Encoder<B>, version: u8) -> denc::Result<()> {
        if version >= 2 {
            self.mirror_uuid.encode(e)?;
        }
        e.u8(self.state)?;
        self.description.encode(e)?;
        self.last_update.encode(e)?;
        e.bool(self.up)
    }
    pub fn decode_meta(d: &mut Decoder<'_>, version: u8) -> denc::Result<Self> {
        let mirror_uuid = if version < 2 {
            Vec::new()
        } else {
            Vec::<u8>::decode(d)?
        };
        Ok(SiteStatus {
            mirror_uuid,
            state: d.u8()?,
            description: Vec::<u8>::decode(d)?,
            last_update: UTime::decode(d)?,
            up: d.bool()?,
        })
    }
}
impl Encode for SiteStatus {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        let v = if self.mirror_uuid.is_empty() { 1 } else { 2 };
        e.versioned(v, v, |e| self.encode_meta(e, v))
    }
}
impl<'a> Decode<'a> for SiteStatus {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, Self::decode_meta)
    }
}

/// Make the address type ANY (type is not part of an endpoint's identity).
pub fn sanitize(mut i: EntityInst) -> EntityInst {
    i.addr.ty = EntityAddr::TYPE_ANY;
    i
}

/// Stored status value: `origin` envelope (v1/c1) followed by a [`SiteStatus`] envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnDiskStatus {
    pub origin: EntityInst,
    pub status: SiteStatus,
}
impl OnDiskStatus {
    pub fn decode_origin(d: &mut Decoder<'_>) -> denc::Result<EntityInst> {
        d.versioned(1, |d, _| Ok(sanitize(EntityInst::decode(d)?)))
    }
}
impl Encode for OnDiskStatus {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| sanitize(self.origin).encode(e))?;
        self.status.encode(e)
    }
}
impl<'a> Decode<'a> for OnDiskStatus {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        Ok(OnDiskStatus {
            origin: Self::decode_origin(d)?,
            status: SiteStatus::decode(d)?,
        })
    }
}

/// `cls::rbd::MirrorImageStatus` (v2/c1): local site (v1 layout) + remote sites (v2 layout).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImageStatus {
    pub sites: Vec<SiteStatus>,
}
impl ImageStatus {
    pub fn local(&self) -> Option<&SiteStatus> {
        self.sites.iter().find(|s| s.mirror_uuid.is_empty())
    }
}
impl Encode for ImageStatus {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            let local = self.local();
            local.cloned().unwrap_or_default().encode_meta(e, 1)?;
            e.bool(local.is_some())?;
            e.u32((self.sites.len() - usize::from(local.is_some())) as u32)?;
            for s in self.sites.iter().filter(|s| !s.mirror_uuid.is_empty()) {
                s.encode_meta(e, 2)?;
            }
            Ok(())
        })
    }
}
impl<'a> Decode<'a> for ImageStatus {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            let local = SiteStatus::decode_meta(d, 1)?;
            if v < 2 {
                return Ok(ImageStatus { sites: vec![local] });
            }
            let valid = d.bool()?;
            let n = d.count()?;
            let mut sites = Vec::new();
            if valid {
                sites.push(local);
            }
            for _ in 0..n {
                sites.push(SiteStatus::decode_meta(d, v)?);
            }
            Ok(ImageStatus { sites })
        })
    }
}

env_struct! {
    /// `cls::rbd::MirrorImageMap` (v1/c1).
    ImageMap (1, 1) {
        instance_id: Vec<u8>,
        mapped_time: UTime,
        data: Vec<u8>,
    }
}
