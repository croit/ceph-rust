// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Omap key layout of a bucket index shard (spec/cls_rgw.md s3). Keys are arbitrary bytes sorted
//! memcmp. Namespaces, ascending: plain names (first byte < 0x80), the special area (first byte
//! 0x80: bilog `0_`, instance `1000_`, olh `1001_`, reshard log `2001_`, end `9999_`), plain
//! names with first byte > 0x80.
//!
//! Versioned objects (design hook for G5): per name N, a plain VER_MARKER placeholder at `N`, the
//! authoritative instance entries at `80 "1000_" N 00 'i' <instance>` (null-instance delete
//! marker: `... 00 'd'` suffix), the olh at `80 "1001_" N`, and a LIST copy per version at
//! `N 00 'v' <decreasing_str(versioned_epoch)> 00 'i' <instance>` which sorts newest-first right
//! after the plain key; `N 01` sorts after all of them.

use super::types::{DirEntry, ObjKey};

pub const BI_PREFIX: u8 = 0x80;
pub const BILOG: &[u8] = b"\x800_";
pub const INSTANCE: &[u8] = b"\x801000_";
pub const OLH: &[u8] = b"\x801001_";
pub const RESHARD_LOG: &[u8] = b"\x802001_";
/// Upper bound of the special area; plain names > 0x80 sort after it.
pub const END: &[u8] = b"\x809999_";

/// `cls_rgw_get_rounded_size`: round up to 4096 (wrapping like the u64 original).
pub fn round4096(x: u64) -> u64 {
    x.wrapping_add(4095) & !4095
}

/// Monotonically decreasing decimal string of `num` (larger num -> smaller string).
pub fn decreasing_str(num: u64) -> String {
    if num < 0x10 {
        format!("9{:02}", 0xF - num)
    } else if num < 0x100 {
        format!("8{:03}", 0xFF - num)
    } else if num < 0x1000 {
        format!("7{:04}", 0xFFF - num)
    } else if num < 0x10000 {
        format!("6{:05}", 0xFFFF - num)
    } else if num < 0x1_0000_0000 {
        format!("5{:010}", 0xFFFF_FFFFu64 - num)
    } else if num < 0x100_0000_0000 {
        format!("4{:015}", 0xFF_FFFF_FFFFu64 - num)
    } else if num < 0x1_0000_0000_0000 {
        format!("3{:018}", 0xFFFF_FFFF_FFFFu64 - num)
    } else {
        format!("2{:020}", u64::MAX - num)
    }
}

/// True for keys outside the special area (empty counts as plain, like a marker).
pub fn is_plain(k: &[u8]) -> bool {
    k.first() != Some(&BI_PREFIX)
}

/// `80 "1000_" name 00 'i' instance [00 'd']`
pub fn instance_key(key: &ObjKey, dm_suffix: bool) -> Vec<u8> {
    let mut k = Vec::with_capacity(INSTANCE.len() + key.name.len() + key.instance.len() + 4);
    k.extend_from_slice(INSTANCE);
    k.extend_from_slice(&key.name);
    k.extend_from_slice(b"\0i");
    k.extend_from_slice(&key.instance);
    if dm_suffix {
        k.extend_from_slice(b"\0d");
    }
    k
}

/// `encode_obj_index_key`: plain name if no instance, else the instance-region key.
pub fn obj_index_key(key: &ObjKey) -> Vec<u8> {
    if key.instance.is_empty() {
        key.name.clone()
    } else {
        instance_key(key, false)
    }
}

/// `80 "1001_" name`
pub fn olh_key(key: &ObjKey) -> Vec<u8> {
    let mut k = OLH.to_vec();
    k.extend_from_slice(&key.name);
    k
}

/// LIST copy key of a versioned entry: `name 00 'v' decreasing_str(versioned_epoch) 00 'i' instance`.
pub fn list_key(e: &DirEntry) -> Vec<u8> {
    let mut k = e.key.name.clone();
    k.extend_from_slice(b"\0v");
    k.extend_from_slice(decreasing_str(e.versioned_epoch).as_bytes());
    k.extend_from_slice(b"\0i");
    k.extend_from_slice(&e.key.instance);
    k
}

/// `name 01`: sorts after every list key of `name`.
pub fn after_versions(name: &[u8]) -> Vec<u8> {
    let mut k = name.to_vec();
    k.push(1);
    k
}

/// `prefix FF`: skips everything under a common prefix.
pub fn after_delim(prefix: &[u8]) -> Vec<u8> {
    let mut k = prefix.to_vec();
    k.push(0xFF);
    k
}

/// Reshard-log key of an index key: `80 "2001_" idx`.
pub fn reshard_log_key(idx: &[u8]) -> Vec<u8> {
    let mut k = RESHARD_LOG.to_vec();
    k.extend_from_slice(idx);
    k
}

/// Bilog key: `80 "0_" id` with `id = "%011llu.%llu.%d"` (index_ver, pg user version, subop).
pub fn bilog_id(index_ver: u64, pg_ver: u64, subop: u32) -> Vec<u8> {
    format!("{index_ver:011}.{pg_ver}.{}", subop as i32).into_bytes()
}
pub fn bilog_key(id: &[u8]) -> Vec<u8> {
    let mut k = BILOG.to_vec();
    k.extend_from_slice(id);
    k
}

/// `decode_list_index_key`: split a plain-region key into (name, instance). `None` = malformed
/// (caller skips the entry). A key without NUL is a plain name.
pub fn decode_list_key(k: &[u8]) -> Option<ObjKey> {
    let Some(first_nul) = k.iter().position(|b| *b == 0) else {
        return Some(ObjKey {
            name: k.to_vec(),
            instance: Vec::new(),
        });
    };
    let name = k[..first_nul].to_vec();
    let mut instance = Vec::new();
    let mut rest = &k[first_nul + 1..];
    // NUL-separated tokens after the name; a trailing NUL yields no extra token
    if rest.is_empty() {
        return None; // "no vals"
    }
    while !rest.is_empty() {
        let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
        let tok = &rest[..end];
        rest = if end < rest.len() {
            &rest[end + 1..]
        } else {
            &[]
        };
        match tok.first() {
            Some(b'i') => instance = tok[1..].to_vec(),
            Some(b'v') if tok.len() <= 2 || !tok[2..].iter().all(u8::is_ascii_digit) => {
                return None; // 'v' + range digit + decimal digits (value unused)
            }
            _ => {}
        }
    }
    Some(ObjKey { name, instance })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decreasing() {
        assert_eq!(decreasing_str(0), "915");
        assert_eq!(decreasing_str(15), "900");
        assert_eq!(decreasing_str(16), "8239");
        assert_eq!(decreasing_str(0xFF), "8000");
        assert_eq!(
            decreasing_str(1_700_000_000_000_000_000),
            "216746744073709551615"
        );
        assert_eq!(decreasing_str(u64::MAX), "200000000000000000000");
        // strictly decreasing across range borders
        let xs = [
            0u64,
            1,
            15,
            16,
            255,
            256,
            4095,
            4096,
            65535,
            65536,
            1 << 32,
            1 << 40,
            1 << 48,
            u64::MAX,
        ];
        for w in xs.windows(2) {
            assert!(
                decreasing_str(w[0]) > decreasing_str(w[1]),
                "{} {}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn layout() {
        let k = ObjKey::new("a", "v1");
        assert_eq!(instance_key(&k, false), b"\x801000_a\0iv1");
        assert_eq!(
            instance_key(&ObjKey::new("a", ""), true),
            b"\x801000_a\0i\0d"
        );
        assert_eq!(obj_index_key(&ObjKey::new("a", "")), b"a");
        assert_eq!(olh_key(&k), b"\x801001_a");
        assert_eq!(bilog_key(&bilog_id(7, 412, 1)), b"\x800_00000000007.412.1");
        assert!(END > OLH && OLH > INSTANCE && INSTANCE > BILOG);
        let e = DirEntry {
            key: k,
            versioned_epoch: 5,
            ..Default::default()
        };
        assert_eq!(list_key(&e), b"a\0v910\0iv1");
    }

    #[test]
    fn list_key_decode() {
        let k = decode_list_key(b"plain").unwrap();
        assert_eq!(
            (k.name.as_slice(), k.instance.as_slice()),
            (&b"plain"[..], &b""[..])
        );
        let k = decode_list_key(b"a\0v9010\0iinst").unwrap();
        assert_eq!(
            (k.name.as_slice(), k.instance.as_slice()),
            (&b"a"[..], &b"inst"[..])
        );
        assert!(decode_list_key(b"a\0").is_none());
        assert!(decode_list_key(b"a\0vx\0i").is_none());
    }
}
