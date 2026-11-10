// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! msgr2 frame layer (sans-IO): banner, preamble, segments, CRC and secure (AES-128-GCM) framing,
//! v2.0 and v2.1 layouts. Spec: `doc/spec/msgr2.md` sections 2-6.
//!
//! Session layer (sans-IO): [`Connection`] state machine (handshake, auth via [`auth`] traits, ident,
//! reconnect, replay), [`payload`] control structs, [`SessionTable`], [`Policy`].

#![deny(clippy::print_stderr, clippy::print_stdout)]
#![cfg_attr(test, allow(clippy::print_stderr, clippy::print_stdout))]
mod addresses;
pub use addresses::LocalAddresses;
pub mod auth;
mod banner;
mod conn;
mod decode;
mod dispatch;
mod encode;
mod error;
mod gcm;
mod output;
pub mod payload;
mod policy;
pub mod profile;
mod rxpool;
mod segbuf;
mod seqcheck;
mod session;

pub use banner::{
    Banner, FEATURE_COMPRESSION, FEATURE_PLACEMENT, FEATURE_RDMA, FEATURE_REVISION_1,
    FEATURE_SOURCE_PULL,
};
pub use conn::{
    Config, ConnState, Connection, Event, FaultReason, Handoff, Home, Incoming, PeerInfo,
    SessionRetirement,
};
pub use crc::{BlockCrcs, CrcHint};
pub use decode::{
    BLOCKS_MIN, Decoder, Frame, LentMessage, OwnedFrame, RxEarly, RxFeed, RxFeedState,
    SecureRxBuffer,
};
pub use dispatch::{DispatchBudget, DispatchError, DispatchGuard};
pub use encode::{Encoder, Seg, ZC_MIN, flatten, flatten_data};
pub use error::{BannerError, Error};
pub use gcm::{ConnSecret, Role};
pub use output::{EventNotify, EventQueue, OutputNotify, OutputQueue};
pub use payload::{MsgHeader2, Payload};
pub use policy::{
    FEATURES_SUPPORTED_DEFAULT, MSGR2_REQUIRED, OSD_REQUIRED, OSDREPLYMUX, Policy, PolicyTable,
};
pub use rxpool::Shelf as RxShelf;
pub use segbuf::{SegBuf, SegWatch};
pub use seqcheck::counters as seq_counters;
pub use session::{
    DataMore, Message, PRIO_DEFAULT, Queue, SessState, Session, SessionInfo, SessionKey,
    SessionTable,
};

use crc::crc32c;

/// Preamble size (all modes/revisions, before crypto).
pub const PREAMBLE_LEN: usize = 32;
/// Maximum segments per frame.
pub const MAX_SEGMENTS: usize = 4;
/// Secure-mode block size.
pub const CRYPTO_BLOCK: usize = 16;
/// Secure rev1 inline buffer size.
pub const INLINE_LEN: usize = 48;
/// GCM tag size.
pub const TAG_LEN: usize = 16;
/// late_status for a complete rev1 frame.
pub const LATE_COMPLETE: u8 = 0x0E;
/// late_status for an aborted rev1 frame.
pub const LATE_ABORTED: u8 = 0x01;
/// Preamble flag: segments are compressed.
pub const FLAG_COMPRESSED: u8 = 0x01;

/// Receive-side probe of a MESSAGE frame's data segment (spec msgr2.md 8.2, client-ops.md 5.4.1): once the header2 and
/// the front of a frame are complete, the decoder asks it before the data segment is assembled. A refused data segment
/// is consumed through every ordinary frame check (segment CRC, GCM authentication, `late_status`, completion
/// deadline) but neither buffered nor charged to the ingress pool (its share of the frame's one preamble reservation is
/// given back before its bytes arrive); the frame then carries `data_refused` and the receiver answers the op without
/// its payload.
///
/// The answer must rest on the frame bytes alone: the front's CRC/authentication is verified with the rest of the
/// frame, and a damaged front can only add the fault the frame's own checks raise anyway.
#[derive(Debug, Clone, Copy)]
pub struct DataProbe {
    /// Smallest data-segment length the probe is asked about (`osd_max_write_size` + 1). A shorter segment is
    /// assembled without the call.
    pub threshold: u64,
    /// Refuse the data segment of this MESSAGE frame (`header`, `front`, `middle`/`data` = their declared segment
    /// lengths). Called only for segments at or above `threshold`.
    pub refuse: fn(header: &[u8], front: &[u8], middle: usize, data: usize) -> bool,
}
/// Alignment hints used by Ceph senders.
pub const ALIGN_CTRL: u16 = 8;
/// MESSAGE segment alignments: header, front, middle, data.
pub const ALIGN_MESSAGE: [u16; 4] = [8, 8, 8, 4096];

/// Frame layout revision, selected by the peer's banner (`Banner::revision`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revision {
    /// v2.0 (REVISION_1 not advertised by peer).
    V20,
    /// v2.1.
    V21,
}

/// Size limits enforced on receive (and send).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Max length of a single segment.
    pub max_segment: u32,
    /// Max sum of the unpadded segment lengths of a frame.
    pub max_frame: u64,
    /// Max sum of the unpadded segment lengths of every frame whose tag is not MESSAGE
    /// (handshake, auth, keepalive, ack, control). [`MAX_CONTROL_FRAME`] unless overridden; `None`: no control ceiling
    /// ([`wire_shape`](Self::wire_shape), the compat client profile). Before READY the same ceiling holds every frame
    /// when it is set; without one, pre-READY frames keep the shape's own segment and frame limits.
    pub max_control: Option<u64>,
}

/// Default ceiling for non-MESSAGE frames (spec 4.1). Basis: the largest legitimate control payloads are
/// the cephx authorizer / service tickets in AUTH_REQUEST, AUTH_REPLY_MORE and AUTH_DONE (a few KiB with the
/// full capability strings) and address vectors in the ident frames (< 1 KiB); KEEPALIVE2 and ACK are 8-16
/// bytes. 64 KiB leaves more than an order of magnitude of margin.
///
/// This is our own resource bound, not a protocol bound: classic has no such ceiling, so the compat client profile
/// ([`Limits::wire_shape`]) does not apply it (spec 16 C7). A cephx AUTH_DONE with long capability strings is not
/// known to be 64 KiB-bounded, and a client only talks to the cluster it authenticates against.
pub const MAX_CONTROL_FRAME: u64 = 64 * 1024;

/// Cap of one connection's pre-auth transcript (`rx_all`, spec 9) before READY. The signature covers every handshake
/// byte, so the bytes are kept until the session key exists (AUTH_DONE) — they cannot be hashed incrementally. A
/// legitimate handshake (banner, HELLO, the cephx ticket/authorizer rounds with a long caps string, the auth-method
/// failover walk) stays below 100 KiB; 4 control frames leave more than 2x margin, and without a cap a peer that never
/// authenticates could grow the buffer for the whole handshake timeout at line rate (an unauthenticated OOM).
pub const PREAUTH_TRANSCRIPT_MAX: usize = 4 * MAX_CONTROL_FRAME as usize;

/// Smallest frame throughput a link must sustain while a frame is received: a frame whose preamble is parsed and that
/// holds ingress space must complete within `ms_connection_ready_timeout` plus its declared wire length at this rate,
/// else the connection faults (spec 4.3). croit-flashstore-osd targets links of 40 Gbit/s and more; 8 MiB/s (64 Mbit/s) is 1/600 of
/// that, so a link throttled far below the design target keeps its frames, while a peer that declares a frame and then
/// trickles it cannot hold the ingress pool (and with it every other client of the core) for longer than that.
pub const FRAME_MIN_RATE: u64 = 8 << 20;

impl Limits {
    /// Compatible client wire shape, independent of soft byte admission.
    /// Selecting this profile allocates nothing and does not promise peer acceptance.
    pub const fn wire_shape() -> Self {
        Self {
            max_segment: u32::MAX,
            max_frame: match (u32::MAX as u64).checked_mul(MAX_SEGMENTS as u64) {
                Some(total) => total,
                None => panic!("msgr2 wire shape exceeds u64"),
            },
            max_control: None,
        }
    }

    /// Limits for a connection that is not Ready yet. With a control ceiling of its own (the server shapes), no frame,
    /// whatever its tag, exceeds it: a peer must not make us reserve a handshake frame's declared length. The compatible
    /// client wire shape has no control ceiling (classic has none; a cephx AUTH_DONE carrying service tickets and caps
    /// is not 64 KiB-bounded), so its pre-READY frames keep the shape's segment and frame limits (spec 16 C7); the
    /// connection still holds every frame before AUTH_DONE to [`PREAUTH_TRANSCRIPT_MAX`].
    pub fn pre_ready(self) -> Self {
        match self.max_control {
            Some(c) => Self {
                max_segment: self.max_segment.min(u32::try_from(c).unwrap_or(u32::MAX)),
                max_frame: self.max_frame.min(c),
                max_control: Some(c),
            },
            None => self,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_segment: 1 << 28,
            max_frame: 1 << 29,
            max_control: Some(MAX_CONTROL_FRAME),
        }
    }
}

/// Frame tags (spec 0.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[expect(missing_docs)]
pub enum Tag {
    Hello = 1,
    AuthRequest = 2,
    AuthBadMethod = 3,
    AuthReplyMore = 4,
    AuthRequestMore = 5,
    AuthDone = 6,
    AuthSignature = 7,
    ClientIdent = 8,
    ServerIdent = 9,
    IdentMissingFeatures = 10,
    SessionReconnect = 11,
    SessionReset = 12,
    SessionRetry = 13,
    SessionRetryGlobal = 14,
    SessionReconnectOk = 15,
    Wait = 16,
    Message = 17,
    Keepalive2 = 18,
    Keepalive2Ack = 19,
    Ack = 20,
    CompressionRequest = 21,
    CompressionDone = 22,
    /// croit-flashstore-osd extension (spec 18); high value, upstream allocates from the low end.
    RdmaUpgrade = 0xF1,
    /// croit-flashstore-osd placement cancel/retired control on an upgraded RC stream.
    PlacementControl = 0xF2,
}

impl Tag {
    /// Map a wire tag; `None` for unknown tags (caller faults the connection).
    pub fn from_u8(v: u8) -> Option<Tag> {
        use Tag::*;
        Some(match v {
            1 => Hello,
            2 => AuthRequest,
            3 => AuthBadMethod,
            4 => AuthReplyMore,
            5 => AuthRequestMore,
            6 => AuthDone,
            7 => AuthSignature,
            8 => ClientIdent,
            9 => ServerIdent,
            10 => IdentMissingFeatures,
            11 => SessionReconnect,
            12 => SessionReset,
            13 => SessionRetry,
            14 => SessionRetryGlobal,
            15 => SessionReconnectOk,
            16 => Wait,
            17 => Message,
            18 => Keepalive2,
            19 => Keepalive2Ack,
            20 => Ack,
            21 => CompressionRequest,
            22 => CompressionDone,
            0xF1 => RdmaUpgrade,
            0xF2 => PlacementControl,
            _ => return None,
        })
    }
}

#[inline]
pub(crate) fn pad16(x: usize) -> usize {
    // Segment lengths have already passed Preamble::wire_len before assembly.
    checked_pad16(x).expect("validated msgr2 padding")
}

/// Checked rounding before any secure frame storage is sized.
#[inline]
pub(crate) fn checked_pad16(x: usize) -> Result<usize, Error> {
    x.checked_add(CRYPTO_BLOCK - 1)
        .map(|n| n & !(CRYPTO_BLOCK - 1))
        .ok_or(Error::FrameTooLarge(u64::MAX))
}

/// Parsed preamble.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Preamble {
    pub tag: u8,
    pub n: usize,
    pub len: [u32; 4],
    pub align: [u16; 4],
    pub flags: u8,
}

impl Preamble {
    /// Exact wire size, checked independently of logical frame policy.
    /// Subsequent segment offsets/padding are bounded by this validated total.
    pub(crate) fn wire_len(&self, rev: Revision, secure: bool) -> Result<usize, Error> {
        if self.n == 0 || self.n > MAX_SEGMENTS {
            return Err(Error::BadSegmentCount(self.n as u8));
        }
        let mut lengths = [0usize; MAX_SEGMENTS];
        for (dst, &len) in lengths.iter_mut().zip(&self.len).take(self.n) {
            *dst = usize::try_from(len).map_err(|_| Error::FrameTooLarge(u64::from(len)))?;
            if secure {
                *dst = checked_pad16(*dst)?;
            }
        }
        let add = |a: usize, b: usize| a.checked_add(b).ok_or(Error::FrameTooLarge(u64::MAX));
        let tail = lengths[1..self.n]
            .iter()
            .try_fold(0usize, |n, &len| add(n, len))?;
        match (secure, rev) {
            (false, Revision::V20) => add(add(add(PREAMBLE_LEN, lengths[0])?, tail)?, 17),
            (false, Revision::V21) => {
                let head = if lengths[0] == 0 {
                    0
                } else {
                    add(lengths[0], 4)?
                };
                add(
                    add(add(PREAMBLE_LEN, head)?, tail)?,
                    if self.n > 1 { 13 } else { 0 },
                )
            }
            (true, Revision::V20) => add(add(add(PREAMBLE_LEN, lengths[0])?, tail)?, 16 + TAG_LEN),
            (true, Revision::V21) => {
                let head = if lengths[0] > INLINE_LEN {
                    add(lengths[0] - INLINE_LEN, TAG_LEN)?
                } else {
                    0
                };
                let tail = if self.n > 1 {
                    add(tail, 16 + TAG_LEN)?
                } else {
                    0
                };
                add(add(PREAMBLE_LEN + INLINE_LEN + TAG_LEN, head)?, tail)
            }
        }
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        let s = out.len();
        out.push(self.tag);
        out.push(self.n as u8);
        for i in 0..4 {
            out.extend_from_slice(&self.len[i].to_le_bytes());
            out.extend_from_slice(&self.align[i].to_le_bytes());
        }
        out.push(self.flags);
        out.push(0);
        let crc = crc32c(0, &out[s..s + 28]);
        out.extend_from_slice(&crc.to_le_bytes());
    }

    /// Validate order per spec 4.1: CRC, segment count, last segment non-empty; then limits.
    pub fn parse(b: &[u8], limits: &Limits) -> Result<Preamble, Error> {
        debug_assert!(b.len() >= PREAMBLE_LEN);
        if crc32c(0, &b[..28]) != denc::le::rd_u32(b, 28) {
            return Err(Error::BadPreambleCrc);
        }
        let n = b[1] as usize;
        if n == 0 || n > MAX_SEGMENTS {
            return Err(Error::BadSegmentCount(b[1]));
        }
        let mut len = [0u32; 4];
        let mut align = [0u16; 4];
        let mut sum = 0u64;
        // descriptors beyond `n` are not part of the frame (Ceph never reads them): they stay zero here
        for i in 0..n {
            let o = 2 + 6 * i;
            len[i] = denc::le::rd_u32(b, o);
            align[i] = denc::le::rd_u16(b, o + 4);
            if len[i] > limits.max_segment {
                return Err(Error::SegmentTooLarge(len[i]));
            }
            sum = sum
                .checked_add(u64::from(len[i]))
                .ok_or(Error::FrameTooLarge(u64::MAX))?;
        }
        if n > 1 && len[n - 1] == 0 {
            return Err(Error::EmptyLastSegment);
        }
        if sum > limits.max_frame
            || (b[0] != Tag::Message as u8 && limits.max_control.is_some_and(|c| sum > c))
        {
            return Err(Error::FrameTooLarge(sum));
        }
        Ok(Preamble {
            tag: b[0],
            n,
            len,
            align,
            flags: b[26],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_ready_holds_frames_to_the_control_ceiling_where_the_shape_sets_one() {
        // the compatible wire shape declares no control ceiling (classic has none): its pre-READY frames keep the
        // shape's own limits
        assert_eq!(Limits::wire_shape().pre_ready(), Limits::wire_shape());
        // an operator ceiling below the default survives (and still bounds every pre-READY frame)
        let tight = Limits {
            max_control: Some(1024),
            ..Limits::wire_shape()
        }
        .pre_ready();
        assert_eq!(
            (tight.max_segment, tight.max_frame, tight.max_control),
            (1024, 1024, Some(1024))
        );
        // the default keeps its shape
        assert_eq!(
            Limits::default().pre_ready(),
            Limits {
                max_segment: u32::try_from(MAX_CONTROL_FRAME).unwrap(),
                max_frame: MAX_CONTROL_FRAME,
                max_control: Some(MAX_CONTROL_FRAME),
            }
        );
    }

    #[test]
    fn checked_padding_rejects_platform_overflow() {
        assert_eq!(checked_pad16(0), Ok(0));
        assert_eq!(checked_pad16(1), Ok(16));
        assert_eq!(checked_pad16(16), Ok(16));
        assert_eq!(checked_pad16(usize::MAX - 15), Ok(usize::MAX - 15));
        assert!(checked_pad16(usize::MAX - 14).is_err());
        assert!(checked_pad16(usize::MAX).is_err());
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn maximum_wire_lengths_include_padding_without_narrowing_or_allocation() {
        let p = Preamble {
            tag: Tag::Message as u8,
            n: MAX_SEGMENTS,
            len: [u32::MAX; MAX_SEGMENTS],
            align: ALIGN_MESSAGE,
            flags: 0,
        };
        let max = usize::try_from(u32::MAX).unwrap();
        assert_eq!(checked_pad16(max), Ok(max + 1));
        for rev in [Revision::V20, Revision::V21] {
            assert_eq!(p.wire_len(rev, false), Ok(max * MAX_SEGMENTS + 49));
            let overhead = if rev == Revision::V20 { 64 } else { 96 };
            assert_eq!(
                p.wire_len(rev, true),
                Ok((max + 1) * MAX_SEGMENTS + overhead)
            );
        }
    }

    fn preamble(len: [u32; MAX_SEGMENTS], n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        Preamble {
            tag: Tag::Message as u8,
            n,
            len,
            align: ALIGN_MESSAGE,
            flags: 0,
        }
        .write(&mut bytes);
        bytes
    }

    #[test]
    fn wire_shape_preamble_above_native_policy_without_body_allocation() {
        let wire = Limits::wire_shape();
        assert_eq!(wire.max_segment, u32::MAX);
        assert_eq!(wire.max_frame, u64::from(u32::MAX) * MAX_SEGMENTS as u64);
        let strict = Limits::default();
        assert_eq!(strict.max_segment, 256 << 20);
        assert_eq!(strict.max_frame, 512 << 20);
        for len in [
            [payload::HEADER2_LEN as u32, 0, 0, (256 << 20) + 1],
            [payload::HEADER2_LEN as u32, 256 << 20, 0, 256 << 20],
            [u32::MAX; MAX_SEGMENTS],
        ] {
            let bytes = preamble(len, MAX_SEGMENTS);
            assert_eq!(bytes.len(), PREAMBLE_LEN);
            assert_eq!(Preamble::parse(&bytes, &wire).unwrap().len, len);
            assert!(matches!(
                Preamble::parse(&bytes, &strict),
                Err(Error::SegmentTooLarge(_) | Error::FrameTooLarge(_))
            ));
        }
    }

    #[test]
    fn wire_shape_preserves_aggregate_and_segment_count_validation() {
        let wire = Limits::wire_shape();
        let bytes = preamble([u32::MAX; MAX_SEGMENTS], MAX_SEGMENTS);
        let tighter = Limits {
            max_frame: wire.max_frame - 1,
            ..wire
        };
        assert_eq!(
            Preamble::parse(&bytes, &tighter),
            Err(Error::FrameTooLarge(wire.max_frame))
        );
        for n in [0, MAX_SEGMENTS + 1] {
            assert_eq!(
                Preamble::parse(&preamble([1; MAX_SEGMENTS], n), &wire),
                Err(Error::BadSegmentCount(n as u8))
            );
        }
        assert_eq!(
            Preamble::parse(&preamble([1, 1, 1, 0], MAX_SEGMENTS), &wire),
            Err(Error::EmptyLastSegment)
        );
    }

    #[test]
    fn descriptors_beyond_the_segment_count_are_ignored() {
        let mut bytes = preamble([8, u32::MAX, u32::MAX, u32::MAX], 1);
        let p = Preamble::parse(&bytes, &Limits::default()).unwrap();
        assert_eq!((p.n, p.len, p.align), (1, [8, 0, 0, 0], [8, 0, 0, 0]));
        // the slots stay covered by the preamble crc
        bytes[10] ^= 1;
        assert_eq!(
            Preamble::parse(&bytes, &Limits::default()),
            Err(Error::BadPreambleCrc)
        );
    }

    #[test]
    fn tag_roundtrip() {
        for v in 0..=255u8 {
            if let Some(t) = Tag::from_u8(v) {
                assert_eq!(t as u8, v);
            }
        }
        assert!(Tag::from_u8(0).is_none() && Tag::from_u8(23).is_none());
        assert_eq!(Tag::from_u8(0xF1), Some(Tag::RdmaUpgrade));
    }
}

mod write_receipt;
pub use write_receipt::{SendError, WriteReceipt, WriteStatus};
