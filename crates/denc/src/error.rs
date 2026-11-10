// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Error type. Plain enum, no panics on malformed input.

use core::fmt;

/// Encode/decode failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Read past end of (bounded) buffer.
    Eof { needed: usize, remaining: usize },
    /// Length/count prefix exceeds the bytes that remain.
    BadLength { len: u64, remaining: usize },
    /// Fixed output buffer is full.
    NoSpace,
    /// Value does not fit its u32 length prefix.
    TooLong,
    /// `struct_compat` newer than the decoder supports.
    CompatTooNew { compat: u8, supported: u8 },
    /// `struct_v` older than the decoder accepts.
    VersionTooOld { version: u8, oldest: u8 },
    /// Unknown marker/tag byte.
    BadMarker(u8),
    /// Semantically invalid value.
    BadValue(&'static str),
    /// String is not UTF-8.
    Utf8,
    /// Whole-buffer decode left bytes over.
    TrailingBytes(usize),
}

pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Eof { needed, remaining } => {
                write!(
                    f,
                    "unexpected end of buffer (need {needed}, have {remaining})"
                )
            }
            Error::BadLength { len, remaining } => {
                write!(f, "length {len} exceeds remaining {remaining}")
            }
            Error::NoSpace => f.write_str("output buffer full"),
            Error::TooLong => f.write_str("length exceeds u32"),
            Error::CompatTooNew { compat, supported } => {
                write!(f, "struct_compat {compat} > supported {supported}")
            }
            Error::VersionTooOld { version, oldest } => {
                write!(f, "struct_v {version} < oldest supported {oldest}")
            }
            Error::BadMarker(m) => write!(f, "bad marker byte {m}"),
            Error::BadValue(s) => write!(f, "bad value: {s}"),
            Error::Utf8 => f.write_str("invalid utf-8"),
            Error::TrailingBytes(n) => write!(f, "{n} trailing bytes"),
        }
    }
}

impl std::error::Error for Error {}
