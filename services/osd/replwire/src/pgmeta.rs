// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! pgmeta omap key helpers (spec replication.md 4.1). LOCAL format: nothing outside the OSD reads
//! these, they are provided so the store layer can use the classic key names (useful for tests that
//! diff behaviour, and for any future ceph-objectstore-tool style import).

use denc::types::{Eversion, Hobject, SnapId};
use std::fmt::Write;

pub const INFOVER_KEY: &str = "_infover";
pub const EPOCH_KEY: &str = "_epoch";
pub const INFO_KEY: &str = "_info";
pub const BIGINFO_KEY: &str = "_biginfo";
pub const FASTINFO_KEY: &str = "_fastinfo";
pub const MAY_INCLUDE_DELETES_KEY: &str = "may_include_deletes_in_missing";
pub const CAN_ROLLBACK_TO_KEY: &str = "can_rollback_to";
pub const ROLLBACK_INFO_TRIMMED_TO_KEY: &str = "rollback_info_trimmed_to";
pub const REMOVE_KEY: &str = "_remove";
/// Value of `_infover` (pg_latest_struct_v).
pub const INFOVER: u8 = 10;
pub const DUP_PREFIX: &str = "dup_";
pub const MISSING_PREFIX: &str = "missing/";

/// Log entry key: `<epoch:010>.<version:020>` (31 chars).
pub fn log_key(v: Eversion) -> String {
    v.key_string()
}

/// Dup entry key: `dup_` + log key.
pub fn dup_key(v: Eversion) -> String {
    let mut s = String::with_capacity(DUP_PREFIX.len() + 31);
    s.push_str(DUP_PREFIX);
    s.push_str(&v.key_string());
    s
}

/// Missing-set key: `missing/` + `hobject_to_str`.
pub fn missing_key(h: &Hobject) -> String {
    let mut s = String::with_capacity(
        MISSING_PREFIX.len() + 40 + h.oid.len() + h.key.len() + h.nspace.len(),
    );
    s.push_str(MISSING_PREFIX);
    write_hobject(&mut s, h);
    s
}

/// Keys starting with `_` are not log entries (skipped when scanning).
pub fn is_log_key(k: &str) -> bool {
    !k.starts_with('_')
        && !k.starts_with(DUP_PREFIX)
        && !k.starts_with(MISSING_PREFIX)
        && k.as_bytes().first().is_some_and(u8::is_ascii_digit)
}

fn nibble_reverse(h: u32) -> u32 {
    let mut r = 0u32;
    for i in 0..8 {
        r |= ((h >> (4 * i)) & 0xf) << (4 * (7 - i));
    }
    r
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn append_escaped(out: &mut String, s: &[u8]) {
    for &c in s {
        match c {
            b'%' => out.push_str("%p"),
            b'.' => out.push_str("%e"),
            b'_' => out.push_str("%u"),
            c if !(0x20..0x7f).contains(&c) => {
                out.push('%');
                out.push(HEX[(c >> 4) as usize] as char);
                out.push(HEX[(c & 0xf) as usize] as char);
            }
            c => out.push(c as char),
        }
    }
}

/// `hobject_t::to_str()`: `%016X(pool).%08X(nibble-reversed hash).<head|snapdir|snap hex>.<oid>.<key>.<nspace>`.
/// (Escaping of `%` `.` `_` and non-printables is unverified against a classic OSD; local format.)
pub fn hobject_to_str(h: &Hobject) -> String {
    let mut s = String::with_capacity(40 + h.oid.len() + h.key.len() + h.nspace.len());
    write_hobject(&mut s, h);
    s
}

fn write_hobject(s: &mut String, h: &Hobject) {
    let _ = write!(s, "{:016X}.{:08X}.", h.pool as u64, nibble_reverse(h.hash));
    match h.snap {
        SnapId::NOSNAP => s.push_str("head"),
        SnapId::SNAPDIR => s.push_str("snapdir"),
        SnapId(n) => {
            let _ = write!(s, "{n:x}");
        }
    }
    s.push('.');
    append_escaped(s, &h.oid);
    s.push('.');
    append_escaped(s, &h.key);
    s.push('.');
    append_escaped(s, &h.nspace);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert_eq!(
            log_key(Eversion::new(5, 6)),
            "0000000005.00000000000000000006"
        );
        assert_eq!(
            dup_key(Eversion::new(5, 6)),
            "dup_0000000005.00000000000000000006"
        );
        assert!(is_log_key(&log_key(Eversion::new(1, 1))));
        assert!(!is_log_key(INFO_KEY));
    }

    #[test]
    fn to_str() {
        let h = Hobject::new(b"rbd_data.1", SnapId::NOSNAP, 0x1234_5678, 2, b"");
        assert_eq!(
            hobject_to_str(&h),
            "0000000000000002.87654321.head.rbd%udata%e1.."
        );
    }
}
