// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! [`Message`] enum + type-id dispatch.

use crate::header::Header2;
use crate::msg::Segments;
use crate::*;
use bytes::Bytes;
use denc::{Error, Result};

crate::message_enum! {
    /// Any message this crate understands, or [`Message::Unknown`].
    #[derive(Debug, Clone, PartialEq)]
    pub enum Message {
        MPing => MPing,
        MAuth => MAuth,
        MAuthReply => MAuthReply,
        MMonGetMap => MMonGetMap,
        MMonSubscribe => MMonSubscribe,
        MMonSubscribeAck => MMonSubscribeAck,
        MMonGetVersion => MMonGetVersion,
        MMonGetVersionReply => MMonGetVersionReply,
        MGetPoolStats => MGetPoolStats,
        MGetPoolStatsReply => MGetPoolStatsReply,
        MStatfs => MStatfs,
        MStatfsReply => MStatfsReply,
        MPoolOp => MPoolOp,
        MPoolOpReply => MPoolOpReply,
        MMonCommand => MMonCommand,
        MMonCommandAck => MMonCommandAck,
        MMonMap => MMonMap,
        MConfig => MConfig,
        MGetConfig => MGetConfig,
        MLog => MLog,
        MLogAck => MLogAck,
        MCommand => MCommand,
        MCommandReply => MCommandReply,
        MOSDDedupList => MOSDDedupList,
        MOSDDedupListReply => MOSDDedupListReply,
        MOSDMap => MOSDMap,
        MMonGetOSDMap => MMonGetOSDMap,
        MOSDBoot => MOSDBoot,
        MOSDAlive => MOSDAlive,
        MOSDBeacon => MOSDBeacon,
        MOSDMarkMeDown => MOSDMarkMeDown,
        MOSDMarkMeDead => MOSDMarkMeDead,
        MOSDFailure => MOSDFailure,
        MOSDFull => MOSDFull,
        MOSDPing => MOSDPing,
        MOSDPGTemp => MOSDPGTemp,
        MOSDPGCreated => MOSDPGCreated,
        MOSDPGReadyToMerge => MOSDPGReadyToMerge,
        MMonGetPurgedSnaps => MMonGetPurgedSnaps,
        MMonGetPurgedSnapsReply => MMonGetPurgedSnapsReply,
        MMgrMap => MMgrMap,
        MMgrOpen => MMgrOpen,
        MMgrConfigure => MMgrConfigure,
        MMgrReport => MMgrReport,
        MMgrClose => MMgrClose,
        MPGStats => MPGStats,
    } unknown Unknown
}

/// Decode by header type id and header version.
pub fn decode_any(
    ty: u16,
    version: u16,
    front: &[u8],
    middle: &[u8],
    data: &[u8],
) -> Result<Message> {
    decode_inner(
        Head {
            ty,
            version,
            compat: version,
        },
        front,
        middle,
        data,
        None,
        None,
    )
}

/// Header facts an unsupported type carries through unchanged.
#[derive(Clone, Copy)]
struct Head {
    ty: u16,
    version: u16,
    compat: u16,
}

fn decode_inner(
    h: Head,
    front: &[u8],
    middle: &[u8],
    data: &[u8],
    shared: Option<&Bytes>,
    shared_front: Option<&Bytes>,
) -> Result<Message> {
    Message::decode_known(h.ty, h.version, front, middle, data).unwrap_or_else(|| {
        // a large front (PG messages carrying payload in it, e.g. legacy EC sub-writes) stays a reference to the rx
        // buffer: one spliced run, read through `Segments::front_bytes` / `front_shared`
        let shared_front = shared_front.filter(|f| f.len() >= SHARED_FRONT_MIN);
        Ok(Message::Unknown {
            ty: h.ty,
            version: h.version,
            compat: h.compat,
            segments: Segments {
                front_zc: shared_front.map_or_else(Vec::new, |f| vec![(0, f.clone())]),
                front_hints: Default::default(),
                front: if shared_front.is_some() {
                    Vec::new()
                } else {
                    front.to_vec()
                },
                middle: middle.to_vec(),
                // passthrough (client ops, PG messages): keep a reference to the rx buffer, no copy
                data: shared
                    .cloned()
                    .unwrap_or_else(|| Bytes::copy_from_slice(data)),
            },
        })
    })
}

impl Message {
    /// Header for this message with transaction id `tid`.
    pub fn header(&self, tid: u64, features: u64) -> Result<(Header2, Segments)> {
        let (ty, version, compat, segs) = self.encode(features)?;
        Ok((Header2::new(tid, ty, version, compat), segs))
    }
}

/// Decode with a parsed header: rejects `compat_version` above what this crate's decoder supports
/// (the receiver rule of msgr2.md 8.2); unknown types pass through as `Unknown`.
pub fn decode_with_header(
    h: &Header2,
    front: &[u8],
    middle: &[u8],
    data: &[u8],
) -> Result<Message> {
    decode_with_header_inner(h, front, middle, data, None, None)
}

/// [`decode_with_header`] on a shared data segment: unknown types keep a reference instead of a copy.
pub fn decode_with_header_shared(
    h: &Header2,
    front: &[u8],
    middle: &[u8],
    data: &Bytes,
) -> Result<Message> {
    decode_with_header_inner(h, front, middle, data, Some(data), None)
}

/// Unknown types keep a front of at least this many bytes by reference ([`decode_with_header_owned`]).
pub const SHARED_FRONT_MIN: usize = 64 * 1024;

/// [`decode_with_header_shared`] that also keeps a large front of an unknown type by reference (no copy).
pub fn decode_with_header_owned(
    h: &Header2,
    front: &Bytes,
    middle: &[u8],
    data: &Bytes,
) -> Result<Message> {
    decode_with_header_inner(h, front, middle, data, Some(data), Some(front))
}

fn decode_with_header_inner(
    h: &Header2,
    front: &[u8],
    middle: &[u8],
    data: &[u8],
    shared: Option<&Bytes>,
    shared_front: Option<&Bytes>,
) -> Result<Message> {
    let m = decode_inner(
        Head {
            ty: h.ty,
            version: h.version,
            compat: h.effective_compat(),
        },
        front,
        middle,
        data,
        shared,
        shared_front,
    )?;
    if !matches!(m, Message::Unknown { .. }) {
        let max = max_version(h.ty);
        if h.effective_compat() > max {
            return Err(Error::CompatTooNew {
                compat: h.effective_compat().min(255) as u8,
                supported: max.min(255) as u8,
            });
        }
    }
    Ok(m)
}

fn max_version(ty: u16) -> u16 {
    Message::HEAD_BY_TYPE
        .iter()
        .find(|(t, _)| *t == ty)
        .map_or(0, |(_, v)| *v)
}

#[cfg(test)]
mod ping_header_tests {
    use super::*;
    #[test]
    fn ping_reply_passes_full_header_dispatch_with_zero_compat() {
        let h = Header2 {
            ty: ty::PING,
            version: 1,
            compat_version: 0,
            ..Default::default()
        };
        assert!(
            matches!(decode_with_header(&h,&[2,0,0,0,b'{',b'}'],&[],&[]),Ok(Message::MPing(MPing{reply:Some(bytes)})) if bytes==b"{}")
        );
    }
}
