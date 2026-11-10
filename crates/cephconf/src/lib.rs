// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! One `ceph.conf` reader and one set of typed option-value parsers for every
//! Rust user of Ceph configuration: the OSD deployment contract (`osddir`), the
//! librados C ABI (`rados-ffi`) and the CephFS client (`rustycephfs2`).
//!
//! - [`parse`] reads the file grammar of `doc/spec/rados-client/126-c-abi-config-files.md`
//!   (sections, duplicate merging, continuations, quoting/escaping, comments) into
//!   byte [`Sections`]; its keys keep `-` literal like the librados file reader
//!   (spec 126 s7: `mon-host` is unknown there). [`Conf`] is the UTF-8 view a text
//!   caller uses, and it folds `-` to `_` ([`normalize_key`]) so a conf written
//!   for our daemons reads `mon-host` and `mon_host` as one option.
//!   [`Conf::parse_lenient`] is the daemon deployment contract's reader on the same
//!   line-splitting core: a line without `=` is ignored, a header ends at its `]`,
//!   and a value uses the daemon's comment rule.
//! - [`normalize_option`] is the API option rule of `rados_conf_set`/`rados_conf_get`:
//!   whitespace runs only, `conf_set("mon-host")` stays unknown (`config-public-contract.md` s2).
//! - [`value`] holds the typed parsers: the flag spelling `true/yes/1`, the librados
//!   configuration bool (`true`/`false` or an integer), SI integers, IEC sizes and
//!   duration segments.
//!
//! Section precedence is the caller's: [`Conf::value`] merges the sections in the
//! order given (later wins), so a client passes `["global", "client", "client.admin"]`
//! and a daemon `["global", "osd", "osd.3"]`; [`section_value`] takes the same order
//! as priority (first match wins) for a caller that wants the highest-precedence
//! section directly.

pub mod ini;
pub mod value;

pub use ini::{Conf, Error, Sections, normalize_key, normalize_option, parse, section_value};
pub use value::{
    ValueError, boolean, flag, integer, milliseconds, seconds, size, size_with_units, unsigned,
};

use std::path::PathBuf;

/// Default cluster name of a ceph.conf path.
pub const DEFAULT_CLUSTER: &str = "ceph";

/// Default ceph.conf path of `cluster` (`/etc/ceph/<cluster>.conf`).
pub fn conf_path(cluster: &str) -> PathBuf {
    PathBuf::from(format!("/etc/ceph/{cluster}.conf"))
}
