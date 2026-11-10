// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Crate error type.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Wire decode/encode failure.
    Denc(denc::Error),
    /// Stored crc does not match the recomputed one (full map or incremental).
    BadCrc { stored: u32, computed: u32 },
    /// Outer struct_v < 7: classic pre-envelope encoding, unsupported.
    Classic(u8),
    /// Incremental epoch is not `map.epoch + 1`.
    Gap { have: u32, inc: u32 },
    /// Incremental fsid differs from the map's fsid (fatal config error).
    FsidMismatch,
    /// Post-apply re-encode crc differs from the incremental's `full_crc`:
    /// discard the map and fetch the full map from the mon (ADR 0017).
    FullCrcMismatch { expected: u32, computed: u32 },
    /// Semantically invalid input.
    Invalid(&'static str),
}

impl From<denc::Error> for Error {
    fn from(e: denc::Error) -> Self {
        Error::Denc(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Denc(e) => write!(f, "decode: {e}"),
            Error::BadCrc { stored, computed } => {
                write!(
                    f,
                    "crc mismatch: stored {stored:#x}, computed {computed:#x}"
                )
            }
            Error::Classic(v) => write!(f, "classic (pre-envelope) encoding v{v} unsupported"),
            Error::Gap { have, inc } => write!(f, "epoch gap: have {have}, incremental {inc}"),
            Error::FsidMismatch => f.write_str("fsid mismatch"),
            Error::FullCrcMismatch { expected, computed } => write!(
                f,
                "post-apply full crc mismatch: expected {expected:#x}, computed {computed:#x}"
            ),
            Error::Invalid(s) => write!(f, "invalid: {s}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
