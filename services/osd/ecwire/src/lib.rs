// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Erasure-coded sub-op messages (spec ec.md 6): MOSDECSubOpWrite 108, WriteReply 109, Read 110, ReadReply 111.
//! Sans-IO (adr 0015). Decoders accept every version of the spec ladder; encoders emit the most compatible form:
//! ECSubWrite struct v4 with the transaction inline ([`ECSubWrite::data_segment`] converts to v5 for a SERVER_TENTACLE
//! peer), ECSubRead v4, ECSubReadReply v1 with the data inline (v3 with a DATA segment when the shard sets
//! [`ECSubReadReply::data_segment`] or an omap field is present).

mod read;
mod write;

pub use read::{ECSubRead, ECSubReadReply, MOSDECSubOpRead, MOSDECSubOpReadReply};
pub use write::{ECSubWrite, ECSubWriteReply, MOSDECSubOpWrite, MOSDECSubOpWriteReply};

use denc::Result;
use denc::types::SpgT;
use messages::{Message, Segments};

/// Message type ids.
pub mod ty {
    pub const EC_WRITE: u16 = 108;
    pub const EC_WRITE_REPLY: u16 = 109;
    pub const EC_READ: u16 = 110;
    pub const EC_READ_REPLY: u16 = 111;
}

/// Any EC sub-op message.
#[expect(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum EcMsg {
    Write(MOSDECSubOpWrite),
    WriteReply(MOSDECSubOpWriteReply),
    Read(MOSDECSubOpRead),
    ReadReply(MOSDECSubOpReadReply),
}

macro_rules! from {
    ($($v:ident => $t:ty),*) => {$(impl From<$t> for EcMsg { fn from(m: $t) -> Self { EcMsg::$v(m) } })*};
}
from!(Write => MOSDECSubOpWrite, WriteReply => MOSDECSubOpWriteReply, Read => MOSDECSubOpRead, ReadReply => MOSDECSubOpReadReply);

impl EcMsg {
    pub fn msg_type(&self) -> u16 {
        match self {
            EcMsg::Write(_) => ty::EC_WRITE,
            EcMsg::WriteReply(_) => ty::EC_WRITE_REPLY,
            EcMsg::Read(_) => ty::EC_READ,
            EcMsg::ReadReply(_) => ty::EC_READ_REPLY,
        }
    }
    /// Messenger priority: the write reply is `CEPH_MSG_PRIO_HIGH`, the rest default.
    pub fn priority(&self) -> u16 {
        match self {
            EcMsg::WriteReply(_) => pgwire::msgs::PRIO_HIGH,
            _ => pgwire::msgs::PRIO_DEFAULT,
        }
    }
    /// `(type, head_version, compat_version, segments)` for a msgr2 header.
    pub fn encode(&self, features: u64) -> Result<(u16, u16, u16, Segments)> {
        fn go<M: Message>(m: &M, f: u64) -> Result<(u16, u16, u16, Segments)> {
            Ok((
                M::MSG_TYPE,
                M::HEAD_VERSION,
                M::COMPAT_VERSION,
                m.encode(f)?,
            ))
        }
        match self {
            EcMsg::Write(m) => go(m, features),
            EcMsg::WriteReply(m) => go(m, features),
            EcMsg::Read(m) => go(m, features),
            EcMsg::ReadReply(m) => go(m, features),
        }
    }
    /// The PG (with shard) the message is addressed to.
    pub fn spgid(&self) -> SpgT {
        match self {
            EcMsg::Write(m) => m.pgid,
            EcMsg::WriteReply(m) => m.pgid,
            EcMsg::Read(m) => m.pgid,
            EcMsg::ReadReply(m) => m.pgid,
        }
    }
    /// `(map_epoch, min_epoch)` for the peering.md 7.3 gates.
    pub fn gating(&self) -> (u32, u32) {
        match self {
            EcMsg::Write(m) => (m.map_epoch, m.min_epoch),
            EcMsg::WriteReply(m) => (m.map_epoch, m.min_epoch),
            EcMsg::Read(m) => (m.map_epoch, m.min_epoch),
            EcMsg::ReadReply(m) => (m.map_epoch, m.min_epoch),
        }
    }
}

/// Decode by header type id and version. `None` = not an EC type.
pub fn decode_ec(ty: u16, version: u16, seg: &Segments) -> Option<Result<EcMsg>> {
    Some(match ty {
        // a large received front is one shared run (`messages::decode_with_header_owned`): the txn stays a slice of it
        ty::EC_WRITE => seg.front_bytes().and_then(|f| {
            MOSDECSubOpWrite::decode_owned(version, &f, seg.front_shared(), &seg.data)
                .map(EcMsg::Write)
        }),
        ty::EC_WRITE_REPLY => seg
            .front_bytes()
            .and_then(|f| MOSDECSubOpWriteReply::decode(version, &f, &seg.middle, &seg.data))
            .map(EcMsg::WriteReply),
        ty::EC_READ => seg
            .front_bytes()
            .and_then(|f| MOSDECSubOpRead::decode(version, &f, &seg.middle, &seg.data))
            .map(EcMsg::Read),
        ty::EC_READ_REPLY => seg
            .front_bytes()
            .and_then(|f| MOSDECSubOpReadReply::decode_shared(version, &f, &seg.data))
            .map(EcMsg::ReadReply),
        _ => return None,
    })
}

pub(crate) fn put_trace<B: denc::BufMut>(e: &mut denc::Encoder<B>, t: &[i64; 3]) -> Result<()> {
    t.iter().try_for_each(|&x| e.i64(x))
}

/// `Debug` of a payload field: its length only. A payload is up to a stripe width per shard, so a log line or a failing
/// `assert_eq!` must not print it (same rule as `crc::CrcHint`).
#[derive(Clone, Copy)]
pub(crate) struct BytesLen(pub usize);

impl std::fmt::Debug for BytesLen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

/// Trace is 3 x i64; tolerate a front that ends before it.
pub(crate) fn get_trace(d: &mut denc::Decoder<'_>) -> Result<[i64; 3]> {
    if d.remaining() < size_of::<[i64; 3]>() {
        return Ok([0; 3]);
    }
    Ok([d.i64()?, d.i64()?, d.i64()?])
}
