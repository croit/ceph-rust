// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Auth method NONE helpers (spec sec 12).

use crate::error::{Error, Result};
use denc::{BufMut, Decode, Decoder, Encode, Encoder};

pub const AUTH_MODE_AUTHORIZER: u8 = 1;
/// Highest first byte the reference still reads as the v1 authorizer (`AUTHORIZER_MAX`, spec sec 1).
pub const AUTH_MODE_AUTHORIZER_MAX: u8 = 9;
pub const AUTH_MODE_MON: u8 = 10;

pub const ENTITY_MON: u32 = 0x01;
pub const ENTITY_MDS: u32 = 0x02;
pub const ENTITY_OSD: u32 = 0x04;
pub const ENTITY_CLIENT: u32 = 0x08;
pub const ENTITY_MGR: u32 = 0x10;
pub const ENTITY_AUTH: u32 = 0x20;

/// Entity name: u32 type + length-prefixed ID bytes; native text is the default.
#[derive(Debug, Clone)]
pub struct EntityName<I = String> {
    pub ty: u32,
    pub id: I,
}
/// Owned byte principal; the text decoder remains strictly UTF-8.
pub type ByteEntityName = EntityName<Vec<u8>>;
impl<I: AsRef<[u8]>, J: AsRef<[u8]>> PartialEq<EntityName<J>> for EntityName<I> {
    fn eq(&self, other: &EntityName<J>) -> bool {
        self.ty == other.ty && self.id.as_ref() == other.id.as_ref()
    }
}
impl<I: AsRef<[u8]>> Eq for EntityName<I> {}
impl<I: AsRef<[u8]>> EntityName<I> {
    /// Shared initial MON payload for native text and byte principals.
    pub fn mon_auth_payload(&self, global_id: u64) -> Vec<u8> {
        mon_auth_payload(self, global_id)
    }
}

/// Entity type names, the single source for both directions of the mapping.
const ENTITY_TYPES: [(&str, u32); 6] = [
    ("mon", ENTITY_MON),
    ("mds", ENTITY_MDS),
    ("osd", ENTITY_OSD),
    ("client", ENTITY_CLIENT),
    ("mgr", ENTITY_MGR),
    ("auth", ENTITY_AUTH),
];

pub fn type_name(ty: u32) -> Option<&'static str> {
    ENTITY_TYPES.iter().find(|(_, t)| *t == ty).map(|(n, _)| *n)
}

pub fn type_from_name(n: &str) -> Option<u32> {
    ENTITY_TYPES
        .iter()
        .find(|(name, _)| *name == n)
        .map(|(_, t)| *t)
}

impl EntityName {
    /// `<typename>.<id>`.
    pub fn parse(s: &str) -> Option<Self> {
        let (t, id) = s.split_once('.')?;
        Some(Self {
            ty: type_from_name(t)?,
            id: id.to_owned(),
        })
    }
}

impl ByteEntityName {
    /// Split the ASCII role at the first dot; retain every ID byte verbatim.
    /// Native byte input is not a C pointer; C callers must apply their first-NUL boundary.
    pub fn parse_bytes(s: &[u8]) -> Option<Self> {
        let dot = s.iter().position(|&b| b == b'.')?;
        let ty = type_from_name(core::str::from_utf8(&s[..dot]).ok()?)?;
        Some(Self {
            ty,
            id: s[dot + 1..].to_vec(),
        })
    }
}
impl From<EntityName> for ByteEntityName {
    fn from(name: EntityName) -> Self {
        Self {
            ty: name.ty,
            id: name.id.into_bytes(),
        }
    }
}

impl<I: AsRef<[u8]>> Encode for EntityName<I> {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.u32(self.ty)?;
        e.bytes(self.id.as_ref())
    }
}

impl<'a> Decode<'a> for EntityName {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        Ok(Self {
            ty: d.u32()?,
            id: String::decode(d)?,
        })
    }
}
impl<'a> Decode<'a> for ByteEntityName {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        Ok(Self {
            ty: d.u32()?,
            id: d.bytes()?.to_vec(),
        })
    }
}

impl<I: AsRef<[u8]>> core::fmt::Display for EntityName<I> {
    /// `<typename>.<id>`; an id that is not UTF-8 is rendered lossily (text is for logs only, the
    /// wire identity stays the raw bytes).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}.{}",
            type_name(self.ty).unwrap_or("?"),
            String::from_utf8_lossy(self.id.as_ref())
        )
    }
}

fn none_payload<I: AsRef<[u8]>>(mode: u8, name: &EntityName<I>, global_id: u64) -> Vec<u8> {
    let mut e = Encoder::new();
    let _ = (|| -> denc::Result<()> {
        e.u8(mode)?;
        name.encode(&mut e)?;
        e.u64(global_id)
    })();
    e.into_vec()
}

/// AUTH_REQUEST payload to a mon with method NONE (and the cephx start): `u8 10 | name | u64 global_id`.
pub fn mon_auth_payload<I: AsRef<[u8]>>(name: &EntityName<I>, global_id: u64) -> Vec<u8> {
    none_payload(AUTH_MODE_MON, name, global_id)
}

/// "None authorizer" to a non-mon peer: `u8 1 | name | u64 global_id`.
pub fn none_authorizer<I: AsRef<[u8]>>(name: &EntityName<I>, global_id: u64) -> Vec<u8> {
    none_payload(AUTH_MODE_AUTHORIZER, name, global_id)
}

/// Parse either payload above; returns (mode byte, name, global_id).
pub fn parse_none_payload(b: &[u8]) -> Result<(u8, EntityName, u64)> {
    let mut d = Decoder::new(b);
    let mode = d.u8()?;
    let name = EntityName::decode(&mut d)?;
    let gid = d.u64()?;
    Ok((mode, name, gid))
}

/// Auth method NONE, OSD as client toward a mon (spec sec 12).
#[derive(Debug, Clone)]
pub struct NoneMonClient {
    name: ByteEntityName,
    global_id: u64,
    done: bool,
}

impl NoneMonClient {
    pub fn new(name: EntityName, global_id: u64) -> Self {
        Self::new_bytes(name.into(), global_id)
    }
    pub fn new_bytes(name: ByteEntityName, global_id: u64) -> Self {
        Self {
            name,
            global_id,
            done: false,
        }
    }
    /// AUTH_REQUEST payload.
    pub fn start(&mut self) -> Vec<u8> {
        self.done = false;
        mon_auth_payload(&self.name, self.global_id)
    }
    /// AUTH_DONE: any payload is success; adopts the assigned global_id.
    pub fn on_done(&mut self, global_id: u64, _payload: &[u8]) {
        self.global_id = global_id;
        self.done = true;
    }
    pub fn global_id(&self) -> u64 {
        self.global_id
    }
    pub fn is_done(&self) -> bool {
        self.done
    }
}

/// Auth method NONE, OSD as client toward a non-mon peer: the "none authorizer".
#[derive(Debug, Clone)]
pub struct NoneAuthorizer {
    payload: Vec<u8>,
}

impl NoneAuthorizer {
    pub fn new<I: AsRef<[u8]>>(name: &EntityName<I>, global_id: u64) -> Self {
        Self {
            payload: none_authorizer(name, global_id),
        }
    }
    /// AUTH_REQUEST payload. No challenge round; AUTH_DONE payload is ignored.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Identity accepted by the NONE verifier (allow_all caps).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonePeer {
    pub name: EntityName,
    pub global_id: u64,
}

/// Service side for method NONE: parse the none authorizer; global_id trusted.
/// Reply payload to AUTH_DONE is empty; session key and connection secret empty.
pub fn verify_none(payload: &[u8]) -> Result<NonePeer> {
    let (mode, name, global_id) = parse_none_payload(payload)?;
    if !(AUTH_MODE_AUTHORIZER..=AUTH_MODE_AUTHORIZER_MAX).contains(&mode) {
        return Err(Error::Auth("bad authorizer mode byte"));
    }
    Ok(NonePeer { name, global_id })
}
