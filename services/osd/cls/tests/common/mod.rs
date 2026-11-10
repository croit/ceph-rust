// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
#![allow(clippy::allow_attributes, dead_code)]
use cls::errno::*;
use cls::mem::MemStore;
use cls::registry::Reply;
use denc::types::EntityName;
use denc::{Decode, Decoder, Encode};

pub fn e<T: Encode + ?Sized>(v: &T) -> Vec<u8> {
    v.encode_to_vec().unwrap()
}
pub fn d<T: for<'a> Decode<'a>>(b: &[u8]) -> T {
    T::decode(&mut Decoder::new(b)).unwrap()
}
pub fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}
pub fn u64b(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

pub fn call(s: &mut MemStore, oid: &str, class: &str, method: &str, input: &[u8]) -> Reply {
    s.call(oid, class, method, input)
}
/// Call and require success; returns out bytes.
pub fn ok(s: &mut MemStore, oid: &str, class: &str, method: &str, input: &[u8]) -> Vec<u8> {
    let r = s.call(oid, class, method, input);
    assert_eq!(r.ret, 0, "{class}.{method} failed with {}", r.ret);
    r.out
}
/// Call and require exactly `errno`.
pub fn err(s: &mut MemStore, oid: &str, class: &str, method: &str, input: &[u8], errno: Errno) {
    let r = s.call(oid, class, method, input);
    assert_eq!(
        r.ret, errno,
        "{class}.{method}: expected {errno}, got {}",
        r.ret
    );
}

pub fn client(s: &mut MemStore, n: i64) {
    s.env.origin.name = EntityName::client(n);
}

use cls::lock::LockInfo;
use denc::Encoder;
use std::collections::BTreeMap;

/// `map<bytes,bytes>` wire encoding (omap-get-vals / getxattrs outdata without the trailing flag).
pub fn kv_enc(m: &BTreeMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
    let mut e = Encoder::new();
    e.count(m.len()).unwrap();
    for (k, v) in m {
        e.bytes(k).unwrap();
        e.bytes(v).unwrap();
    }
    e.into_vec()
}

/// Zero utime pairs whose sec is within 2 days of `center` (the clock of that side) and uuid-looking text.
pub fn norm_bytes(b: &[u8], center: u32) -> Vec<u8> {
    let mut o = norm_digit_runs(b);
    let mut i = 0;
    while i < o.len() {
        if i + 8 <= o.len() {
            // real_time as u64 nanoseconds
            let ns64 = u64::from_le_bytes(o[i..i + 8].try_into().unwrap());
            if ns64.abs_diff(center as u64 * 1_000_000_000) < 2 * 86_400 * 1_000_000_000 {
                o[i..i + 8].fill(0);
                i += 8;
                continue;
            }
            let sec = u32::from_le_bytes(o[i..i + 4].try_into().unwrap());
            let ns = u32::from_le_bytes(o[i + 4..i + 8].try_into().unwrap());
            if sec.abs_diff(center) < 2 * 86_400 && ns < 1_000_000_000 {
                o[i..i + 8].fill(0);
                i += 8;
                continue;
            }
        }
        if i + 28 <= o.len()
            && o[i..i + 4] == [24, 0, 0, 0]
            && o[i + 4..i + 28]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'/' || *b == b'+')
        {
            // obj_version tag (random 24 chars)
            o[i + 4..i + 28].fill(b'0');
            i += 28;
            continue;
        }
        if i + 36 <= o.len() {
            let w = &o[i..i + 36];
            let ok = w.iter().enumerate().all(|(k, &c)| match k {
                8 | 13 | 18 | 23 => c == b'-',
                _ => c.is_ascii_hexdigit() && !c.is_ascii_uppercase(),
            });
            if ok {
                o[i..i + 36].fill(b'0');
                i += 36;
                continue;
            }
        }
        i += 1;
    }
    o
}

/// Mask locker entity number and address (differ per client connection).
pub fn mask_lock(b: &[u8]) -> Vec<u8> {
    let mut d = Decoder::new(b);
    let Ok(mut li) = LockInfo::decode(&mut d) else {
        return b.to_vec();
    };
    if d.remaining() != 0 {
        return b.to_vec();
    }
    let lockers = std::mem::take(&mut li.lockers);
    for (mut id, mut l) in lockers {
        id.locker.num = 0;
        l.addr = Default::default();
        li.lockers.insert(id, l);
    }
    li.encode_to_vec().unwrap()
}

/// Normalize a wire map (lock xattr values masked, times/uuids masked).
pub fn norm_kv(b: &[u8], c: u32) -> Option<Vec<u8>> {
    let mut d = Decoder::new(b);
    let m = BTreeMap::<Vec<u8>, Vec<u8>>::decode(&mut d).ok()?;
    let rest = d.peek_rest().to_vec();
    let mut tix = 0u32;
    let m: BTreeMap<Vec<u8>, Vec<u8>> = m
        .into_iter()
        .map(|(k, v)| {
            let (k, v) = if k.starts_with(b"lock.") {
                (k, mask_lock(&v))
            } else if let Some(id) = k.strip_prefix(b"\x800_".as_slice()) {
                // bilog key: the pg-version middle of the id differs per cluster
                let id = norm_bilog_id(&String::from_utf8_lossy(id));
                (cat(&[b"\x800_", id.as_bytes()]), norm_bilog_entry(&v))
            } else if is_gc_time_key(&k) {
                // legacy gc time index `1_<sec:011>.<nsec:09>` = wall clock + expiry: keep the order only
                tix += 1;
                (format!("1_T{tix:06}").into_bytes(), v)
            } else if k.starts_with(b"1_") && norm_log_id(&k) != k {
                (norm_log_id(&k), norm_log_entry(&v))
            } else {
                (norm_digit_runs(&k), v)
            };
            (k, norm_bytes(&v, c))
        })
        .collect();
    let mut o = kv_enc(&m);
    o.extend(rest);
    Some(o)
}

/// Zero digit runs of >= 15 digits (nanosecond-derived epochs inside index keys, e.g. versioned `decreasing_str`).
pub fn norm_digit_runs(b: &[u8]) -> Vec<u8> {
    let mut o = b.to_vec();
    let mut i = 0;
    while i < o.len() {
        let n = o[i..].iter().take_while(|c| c.is_ascii_digit()).count();
        if n >= 15 {
            o[i..i + n].fill(b'0');
        }
        i += n.max(1);
    }
    o
}

/// Log class id `1_<sec:010>.<usec:06>_<pg user version>.<subop>`: zero the pg version (cluster history).
pub fn norm_log_id(id: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(id);
    let Some(rest) = s.strip_prefix("1_") else {
        return id.to_vec();
    };
    let p: Vec<&str> = rest.splitn(2, '_').collect();
    if p.len() == 2 && p[0].len() == 17 {
        let q: Vec<&str> = p[1].split('.').collect();
        if q.len() == 2
            && q.iter()
                .all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
        {
            return format!("1_{}_0.{}", p[0], q[1]).into_bytes();
        }
    }
    id.to_vec()
}

fn is_gc_time_key(k: &[u8]) -> bool {
    k.len() == 2 + 11 + 1 + 9
        && k.starts_with(b"1_")
        && k[13] == b'.'
        && k[2..13].iter().chain(&k[14..]).all(u8::is_ascii_digit)
}

/// Ceph strings are byte strings; tests compare ASCII ones as text.
pub fn txt(b: &[u8]) -> &str {
    std::str::from_utf8(b).expect("ASCII test string")
}

/// [`norm_bilog_id`] on raw id bytes (non-UTF-8 ids are left alone).
pub fn norm_bilog_bytes(id: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(id) {
        Ok(s) => norm_bilog_id(s).into_bytes(),
        Err(_) => id.to_vec(),
    }
}

/// Bilog id `<index_ver:011>.<pg user version>.<subop>`: the pg version depends on the cluster's history; zero it.
pub fn norm_bilog_id(id: &str) -> String {
    let p: Vec<&str> = id.split('.').collect();
    if p.len() == 3
        && p[0].len() == 11
        && p[0].bytes().all(|b| b.is_ascii_digit())
        && p[1].bytes().all(|b| b.is_ascii_digit())
        && p[2].parse::<i32>().is_ok()
    {
        format!("{}.0.{}", p[0], p[2])
    } else {
        id.to_string()
    }
}
/// `rgw_bi_log_entry` value with a normalized id (unchanged if it does not decode).
pub fn norm_bilog_entry(v: &[u8]) -> Vec<u8> {
    let mut d = Decoder::new(v);
    match cls::rgw::types::BiLogEntry::decode(&mut d) {
        Ok(mut x) if d.remaining() == 0 => {
            x.id = norm_bilog_bytes(&x.id);
            x.encode_to_vec().unwrap_or_else(|_| v.to_vec())
        }
        _ => v.to_vec(),
    }
}
/// `cls::log::entry` value with a normalized id (unchanged if it does not decode).
pub fn norm_log_entry(v: &[u8]) -> Vec<u8> {
    let mut d = Decoder::new(v);
    match cls::log::Entry::decode(&mut d) {
        Ok(mut x) if d.remaining() == 0 => {
            x.id = norm_log_id(&x.id);
            x.encode_to_vec().unwrap_or_else(|_| v.to_vec())
        }
        _ => v.to_vec(),
    }
}
fn reenc<T: for<'a> Decode<'a> + Encode>(out: &[u8], c: u32, f: impl FnOnce(&mut T)) -> Vec<u8> {
    let mut d = Decoder::new(out);
    match T::decode(&mut d) {
        Ok(mut x) if d.remaining() == 0 => {
            f(&mut x);
            norm_bytes(&x.encode_to_vec().unwrap_or_else(|_| out.to_vec()), c)
        }
        _ => norm_bytes(out, c),
    }
}
/// Op-level normalization shared by the replay test and `capdiff`: `kind` = first words of the statement.
pub fn norm_op(kind: (&str, &str, &str), out: &[u8], c: u32) -> Vec<u8> {
    match kind {
        ("call", "lock", "get_info") => norm_bytes(&mask_lock(out), c),
        ("getxattrs" | "omap-get-vals", _, _) => {
            norm_kv(out, c).unwrap_or_else(|| norm_bytes(out, c))
        }
        ("call", "rgw", "bi_log_list") => {
            let mut d = Decoder::new(out);
            match cls::rgw::types::BiLogListRet::decode(&mut d) {
                Ok(mut r) if d.remaining() == 0 => {
                    for x in &mut r.entries {
                        x.id = norm_bilog_bytes(&x.id);
                    }
                    norm_bytes(&r.encode_to_vec().unwrap_or_else(|_| out.to_vec()), c)
                }
                _ => norm_bytes(out, c),
            }
        }
        ("call", "log", "list") => reenc::<cls::log::ListRet>(out, c, |r| {
            r.marker = norm_log_id(&r.marker);
            for e in &mut r.entries {
                e.id = norm_log_id(&e.id);
            }
        }),
        ("call", "log", "info") => reenc::<cls::log::InfoRet>(out, c, |r| {
            r.header.max_marker = norm_log_id(&r.header.max_marker);
        }),
        ("call", "rgw", "gc_list") => reenc::<cls::rgw_gc::ListRet>(out, c, |r| {
            if is_gc_time_key(&r.next_marker) {
                r.next_marker = b"1_T".to_vec();
            }
        }),
        ("call", "fifo", "get_part_info") => {
            reenc::<cls::fifo::GetPartInfoReply>(out, c, |r| r.header.magic = 0)
        }
        ("call", "fifo", "get_meta") => reenc::<cls::fifo::GetMetaReply>(out, c, |r| {
            r.info.version.instance.clear();
            r.info.oid_prefix.clear();
        }),
        ("omap-get-header", _, _)
            if cls::log::Header::decode(&mut Decoder::new(out))
                .is_ok_and(|h| h.max_marker.starts_with(b"1_")) =>
        {
            reenc::<cls::log::Header>(out, c, |h| h.max_marker = norm_log_id(&h.max_marker))
        }
        ("omap-get-header", _, _) => {
            let mut d = Decoder::new(out);
            match cls::rgw::types::DirHeader::decode(&mut d) {
                Ok(mut h) if d.remaining() == 0 && !out.is_empty() => {
                    h.max_marker = norm_bilog_bytes(&h.max_marker);
                    norm_bytes(&h.encode_to_vec().unwrap_or_else(|_| out.to_vec()), c)
                }
                _ => norm_bytes(out, c),
            }
        }
        _ => norm_bytes(out, c),
    }
}

/// Round-trip all `testdata/dencoder/<name>.<n>.bin` fixtures (byte-exact decode -> encode);
/// returns how many were checked. Fixtures come from `testdata/gen-dencoder.sh` (checked in).
pub fn rt<T: for<'a> Decode<'a> + Encode>(name: &str) -> usize {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/dencoder");
    let mut n = 0;
    for i in 1.. {
        let Ok(bytes) = std::fs::read(dir.join(format!("{name}.{i}.bin"))) else {
            break;
        };
        let mut d = Decoder::new(&bytes);
        let v = T::decode(&mut d).unwrap_or_else(|e| panic!("{name}.{i}: decode: {e}"));
        assert_eq!(d.remaining(), 0, "{name}.{i}: trailing bytes");
        let out = v.encode_to_vec().unwrap();
        assert_eq!(out, bytes, "{name}.{i}: re-encode differs");
        n += 1;
    }
    assert!(n > 0, "no fixtures for {name}");
    n
}
