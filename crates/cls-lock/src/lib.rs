// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Client side of Ceph's cls `lock` class
//! (doc/spec/rados-abi/libradosstriper.md section 9.3): the one wire codec
//! shared by rustyrados, rustyrbd and libradosstriper.
//!
//! Requests are the input payloads of the seven class methods. Replies are the
//! `get_info` and `list_locks` payloads; their decoders follow the reference
//! acceptance rules: a newer envelope version is accepted, bytes left inside
//! an envelope are skipped, bytes after the reply are ignored, and a repeated
//! locker key keeps the later value. Anything else malformed is an error.

mod reply;
mod request;

pub use reply::{DecodeError, Info, Locker, Names, decode_info, decode_names};
pub use request::{CLASS, Method, Request, TooLong, check_envelope_body};
