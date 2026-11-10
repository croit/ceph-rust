// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use core::fmt;

/// Banner errors (spec 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BannerError {
    /// Peer speaks msgr1 (`ceph v027`).
    Msgr1,
    /// Not a ceph banner.
    BadPrefix,
    /// payload_len < 16.
    BadPayloadLen(u16),
    /// Required/supported feature mismatch.
    FeatureMismatch,
}

impl fmt::Display for BannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Msgr1 => write!(f, "peer speaks msgr1"),
            Self::BadPrefix => write!(f, "bad banner prefix"),
            Self::BadPayloadLen(l) => write!(f, "bad banner payload length {l}"),
            Self::FeatureMismatch => write!(f, "msgr2 feature mismatch"),
        }
    }
}
impl std::error::Error for BannerError {}

/// Frame errors. After a decoder error the decoder is poisoned (connection must be faulted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Preamble CRC mismatch.
    BadPreambleCrc,
    /// num_segments not in 1..=4.
    BadSegmentCount(u8),
    /// Gated MESSAGE header segment differs from the fixed header2 wire length.
    BadMessageHeaderLength(u32),
    /// Front rope offsets do not ascend inside the inline front.
    BadFrontRope,
    /// Internal logical dispatch-domain arithmetic or wake generation exhausted.
    Dispatch(crate::DispatchError),
    /// Last segment of a multi-segment frame is empty.
    EmptyLastSegment,
    /// Segment exceeds `Limits::max_segment`.
    SegmentTooLarge(u32),
    /// Frame exceeds `Limits::max_frame`.
    FrameTooLarge(u64),
    /// A frame buffer allocation (output frame or receive segment) failed after checked capacity validation.
    AllocationFailed(usize),
    /// A control payload exceeds a 32-bit wire length field (>4 GiB); never framed, never sent truncated.
    PayloadTooLong,
    /// Segment CRC mismatch (index).
    BadSegmentCrc(usize),
    /// Unacceptable late_status / late_flags value.
    BadLateStatus(u8),
    /// GCM tag verification failed.
    AuthFailed,
    /// GCM nonce space exhausted.
    NonceExhausted,
    /// Connection secret too short (need >= 40 bytes).
    BadSecret,
    /// Crypto backend failure.
    Crypto,
    /// More than 4 segments given to the encoder.
    TooManySegments,
    /// Rev1 single-segment frames cannot be aborted.
    CannotAbort,
    /// Mode change while a frame is partially parsed.
    Busy,
    /// Decoder previously failed.
    Failed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "msgr2 frame error: {self:?}")
    }
}
impl std::error::Error for Error {}
