// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! entity_name_t, entity_addr_t, entity_addrvec_t, entity_inst_t (spec 7.2-7.5).

use crate::buf::BufMut;
use crate::dec::{Decode, Decoder};
use crate::enc::{Encode, Encoder};
use crate::error::{Error, Result};
use crate::features::{self, MSG_ADDR2, SERVER_NAUTILUS};
use core::cmp::Ordering;
use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

/// entity_name_t: u8 type, i64 num (9 bytes raw). Order (type, num).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EntityName {
    pub ty: u8,
    pub num: i64,
}
impl EntityName {
    pub const MON: u8 = 0x01;
    pub const MDS: u8 = 0x02;
    pub const OSD: u8 = 0x04;
    pub const CLIENT: u8 = 0x08;
    pub const MGR: u8 = 0x10;
    pub const AUTH: u8 = 0x20;
    pub const ANY: u8 = 0xff;
    pub const fn new(ty: u8, num: i64) -> Self {
        EntityName { ty, num }
    }
    pub const fn osd(n: i64) -> Self {
        Self::new(Self::OSD, n)
    }
    pub const fn client(n: i64) -> Self {
        Self::new(Self::CLIENT, n)
    }
}
impl fmt::Display for EntityName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = match self.ty {
            Self::MON => "mon",
            Self::MDS => "mds",
            Self::OSD => "osd",
            Self::CLIENT => "client",
            Self::MGR => "mgr",
            Self::AUTH => "auth",
            _ => "unknown",
        };
        if self.num < 0 {
            write!(f, "{t}.?")
        } else {
            write!(f, "{t}.{}", self.num)
        }
    }
}
impl Encode for EntityName {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u8(self.ty)?;
        e.i64(self.num)
    }
}
impl<'a> Decode<'a> for EntityName {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(EntityName {
            ty: d.u8()?,
            num: d.i64()?,
        })
    }
}

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// entity_addr_t. In-memory model: type, nonce, and the 28-byte sockaddr union as
/// (host family, 26 data bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntityAddr {
    pub ty: u32,
    pub nonce: u32,
    pub family: u16,
    pub data: [u8; 26],
}

impl Default for EntityAddr {
    fn default() -> Self {
        Self::blank()
    }
}

impl EntityAddr {
    pub const TYPE_NONE: u32 = 0;
    pub const TYPE_LEGACY: u32 = 1;
    pub const TYPE_MSGR2: u32 = 2;
    pub const TYPE_ANY: u32 = 3;
    pub const TYPE_CIDR: u32 = 4;

    pub const fn blank() -> Self {
        EntityAddr {
            ty: 0,
            nonce: 0,
            family: 0,
            data: [0; 26],
        }
    }
    pub fn v4(ty: u32, nonce: u32, ip: [u8; 4], port: u16) -> Self {
        let mut data = [0u8; 26];
        data[0..2].copy_from_slice(&port.to_be_bytes());
        data[2..6].copy_from_slice(&ip);
        EntityAddr {
            ty,
            nonce,
            family: AF_INET,
            data,
        }
    }
    pub fn v6(ty: u32, nonce: u32, ip: [u8; 16], port: u16, scope_id: u32) -> Self {
        let mut data = [0u8; 26];
        data[0..2].copy_from_slice(&port.to_be_bytes());
        data[6..22].copy_from_slice(&ip);
        data[22..26].copy_from_slice(&scope_id.to_le_bytes());
        EntityAddr {
            ty,
            nonce,
            family: AF_INET6,
            data,
        }
    }
    pub fn is_blank(&self) -> bool {
        self.family == 0 && self.data == [0; 26]
    }
    /// A blank-IP entry: no family yet, or the family's unspecified address (spec ip-addressing 3.3: learned later).
    pub fn is_blank_ip(&self) -> bool {
        match self.family {
            0 => true,
            AF_INET => self.ipv4() == Some([0; 4]),
            AF_INET6 => self.ipv6() == Some([0; 16]),
            _ => false,
        }
    }
    pub fn port(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }
    pub fn ipv4(&self) -> Option<[u8; 4]> {
        (self.family == AF_INET).then(|| [self.data[2], self.data[3], self.data[4], self.data[5]])
    }
    pub fn ipv6(&self) -> Option<[u8; 16]> {
        (self.family == AF_INET6).then(|| {
            let mut a = [0u8; 16];
            a.copy_from_slice(&self.data[6..22]);
            a
        })
    }
    /// The address of a connected socket (the peer of an accepted connection); a v6 scope id is kept.
    pub fn from_socket(ty: u32, nonce: u32, sa: SocketAddr) -> Self {
        match sa {
            SocketAddr::V4(a) => Self::v4(ty, nonce, a.ip().octets(), a.port()),
            SocketAddr::V6(a) => Self::v6(ty, nonce, a.ip().octets(), a.port(), a.scope_id()),
        }
    }
    /// The IP of either family; None when the address carries no parsed family (spec 7).
    pub fn ip(&self) -> Option<IpAddr> {
        match (self.ipv4(), self.ipv6()) {
            (Some(a), _) => Some(IpAddr::V4(Ipv4Addr::from(a))),
            (_, Some(a)) => Some(IpAddr::V6(Ipv6Addr::from(a))),
            _ => None,
        }
    }
    /// IPv6 scope id (zone index); 0 for IPv4 and for every address we pick ourselves (spec 7).
    pub fn scope_id(&self) -> u32 {
        u32::from_le_bytes([self.data[22], self.data[23], self.data[24], self.data[25]])
    }
    /// Dial target: IP, port and (v6) scope; None for a blank-IP entry.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        let port = self.port();
        match self.ip()? {
            IpAddr::V4(a) => Some(SocketAddr::new(IpAddr::V4(a), port)),
            IpAddr::V6(a) => Some(SocketAddr::V6(SocketAddrV6::new(
                a,
                port,
                0,
                self.scope_id(),
            ))),
        }
    }
    /// In-memory bytes: u32 type LE, u32 nonce LE, family LE, data. Ceph compares by memcmp.
    fn mem_bytes(&self) -> [u8; 36] {
        let mut b = [0u8; 36];
        b[0..4].copy_from_slice(&self.ty.to_le_bytes());
        b[4..8].copy_from_slice(&self.nonce.to_le_bytes());
        b[8..10].copy_from_slice(&self.family.to_le_bytes());
        b[10..36].copy_from_slice(&self.data);
        b
    }

    /// Decode the part after the marker byte 0 (legacy form).
    fn decode_legacy_rest(d: &mut Decoder<'_>) -> Result<Self> {
        d.skip(3)?; // rest of the zero u32 "type" slot (marker is its first byte)
        let nonce = d.u32()?;
        let ss = d.take(128)?;
        let family = u16::from_be_bytes([ss[0], ss[1]]);
        let mut data = [0u8; 26];
        data.copy_from_slice(&ss[2..28]);
        let ty = if family != 0 {
            Self::TYPE_LEGACY
        } else {
            Self::TYPE_NONE
        };
        Ok(EntityAddr {
            ty,
            nonce,
            family,
            data,
        })
    }

    /// Decode the part after marker byte 1 (versioned new form).
    fn decode_new_rest<'a>(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            let ty = d.u32()?;
            let nonce = d.u32()?;
            let elen = d.u32()? as usize;
            if elen == 0 {
                return Ok(EntityAddr {
                    ty,
                    nonce,
                    family: 0,
                    data: [0; 26],
                });
            }
            if !(2..=28).contains(&elen) {
                return Err(Error::BadValue("entity_addr elen"));
            }
            let family = d.u16()?;
            let mut data = [0u8; 26];
            data[..elen - 2].copy_from_slice(d.take(elen - 2)?);
            Ok(EntityAddr {
                ty,
                nonce,
                family,
                data,
            })
        })
    }

    pub(crate) fn decode_after_marker<'a>(d: &mut Decoder<'a>, marker: u8) -> Result<Self> {
        match marker {
            0 => Self::decode_legacy_rest(d),
            1 => Self::decode_new_rest(d),
            m => Err(Error::BadMarker(m)),
        }
    }

    pub(crate) fn encode_legacy<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u32(0)?;
        e.u32(self.nonce)?;
        e.raw(&self.family.to_be_bytes())?;
        e.raw(&self.data)?;
        e.raw(&[0u8; 100])
    }
}

impl PartialOrd for EntityAddr {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for EntityAddr {
    fn cmp(&self, o: &Self) -> Ordering {
        self.mem_bytes().cmp(&o.mem_bytes())
    }
}

impl fmt::Display for EntityAddr {
    /// Spec 6: `<type>:<sockaddr>/<nonce>`; `TYPE_ANY` prints no prefix, `TYPE_NONE` only `-`, IPv6 compressed by
    /// `inet_ntop` rules (RFC 5952, lower case, v4-mapped as `::ffff:a.b.c.d`, never a scope id).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.ty == Self::TYPE_NONE {
            return f.write_str("-");
        }
        let pre = match self.ty {
            Self::TYPE_LEGACY => "v1:",
            Self::TYPE_MSGR2 => "v2:",
            Self::TYPE_CIDR => "cidr:",
            _ => "",
        };
        match (self.ipv4(), self.ipv6()) {
            (Some(a), _) => {
                write!(
                    f,
                    "{pre}{}.{}.{}.{}:{}/{}",
                    a[0],
                    a[1],
                    a[2],
                    a[3],
                    self.port(),
                    self.nonce
                )
            }
            (_, Some(a)) => write!(
                f,
                "{pre}[{}]:{}/{}",
                Ipv6Addr::from(a),
                self.port(),
                self.nonce
            ),
            _ => write!(
                f,
                "{pre}(unrecognized address family {})/{}",
                self.family, self.nonce
            ),
        }
    }
}

impl Encode for EntityAddr {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        let feat = e.features();
        if !features::have(feat, MSG_ADDR2) {
            return self.encode_legacy(e);
        }
        e.u8(1)?;
        e.versioned(1, 1, |e| {
            let ty = if !features::have(feat, SERVER_NAUTILUS) && self.ty == Self::TYPE_ANY {
                Self::TYPE_LEGACY
            } else {
                self.ty
            };
            e.u32(ty)?;
            e.u32(self.nonce)?;
            let elen: u32 = if self.family == AF_INET { 16 } else { 28 };
            e.u32(elen)?;
            e.u16(self.family)?;
            e.raw(&self.data[..elen as usize - 2])
        })
    }
}
impl<'a> Decode<'a> for EntityAddr {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        let m = d.u8()?;
        Self::decode_after_marker(d, m)
    }
}

/// entity_addrvec_t.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct EntityAddrVec(pub Vec<EntityAddr>);

impl EntityAddrVec {
    pub fn single(a: EntityAddr) -> Self {
        EntityAddrVec(vec![a])
    }
    /// First msgr2 address, if any.
    pub fn v2(&self) -> Option<&EntityAddr> {
        self.0.iter().find(|a| a.ty == EntityAddr::TYPE_MSGR2)
    }
}
impl Encode for EntityAddrVec {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        if !features::have(e.features(), MSG_ADDR2) {
            let blank = EntityAddr::blank();
            let a = self
                .0
                .iter()
                .find(|a| a.ty == EntityAddr::TYPE_LEGACY)
                .unwrap_or(&blank);
            return a.encode_legacy(e);
        }
        e.u8(2)?;
        e.count(self.0.len())?;
        self.0.iter().try_for_each(|a| a.encode(e))
    }
}
impl<'a> Decode<'a> for EntityAddrVec {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        match d.u8()? {
            m @ (0 | 1) => Ok(EntityAddrVec(vec![EntityAddr::decode_after_marker(d, m)?])),
            2 => {
                let n = d.count()?;
                let mut v = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    v.push(EntityAddr::decode(d)?);
                }
                Ok(EntityAddrVec(v))
            }
            m => Err(Error::BadMarker(m)),
        }
    }
}

/// entity_inst_t: name then addr.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EntityInst {
    pub name: EntityName,
    pub addr: EntityAddr,
}
impl Encode for EntityInst {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        self.name.encode(e)?;
        self.addr.encode(e)
    }
}
impl<'a> Decode<'a> for EntityInst {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(EntityInst {
            name: EntityName::decode(d)?,
            addr: EntityAddr::decode(d)?,
        })
    }
}
