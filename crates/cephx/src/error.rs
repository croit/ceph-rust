// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Truncated / malformed input.
    Malformed(&'static str),
    /// Wire decode/encode failure from `denc`.
    Denc(denc::Error),
    /// Key type not 0/1/2 or key unusable for crypto (type 0, empty, too short).
    BadKey(&'static str),
    /// Integrity / magic / policy failure (maps to EACCES / EPERM).
    Auth(&'static str),
    /// Peer answered with a negative status (errno, negative).
    Status(i32),
    /// Protocol/state violation (call out of order, unexpected reply).
    Protocol(&'static str),
    /// Keyring file error.
    Keyring(String),
    /// RNG failure.
    Rng,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(s) => write!(f, "malformed: {s}"),
            Error::Denc(e) => write!(f, "decode: {e}"),
            Error::BadKey(s) => write!(f, "bad key: {s}"),
            Error::Auth(s) => write!(f, "auth failure: {s}"),
            Error::Status(s) => write!(f, "peer status {s}"),
            Error::Protocol(s) => write!(f, "protocol: {s}"),
            Error::Keyring(s) => write!(f, "keyring: {s}"),
            Error::Rng => write!(f, "rng failure"),
        }
    }
}

impl std::error::Error for Error {}

impl From<denc::Error> for Error {
    fn from(e: denc::Error) -> Self {
        Error::Denc(e)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
