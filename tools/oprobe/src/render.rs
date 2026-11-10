// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Deterministic text rendering of MOSDOpReply (golden files, diffs, CLI output).

use denc::from_slice;
use opwire::consts::op as code;
use opwire::errno;
use opwire::{
    ChecksumOut, KvMap, MOSDOpReply, ObjListSnapResponse, ObjListWatchResponse, OmapKeysOut,
    OmapValsOut, OsdOp, SparseReadOut, StatOut,
};
use std::fmt::Write;

/// How much to print.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detail {
    /// Everything (versions, epochs, flags, real mtimes).
    Full,
    /// Only what must be identical across OSD implementations (no versions/epochs/mtimes).
    Normalized,
}

/// errno name for a (positive) errno value.
pub fn errno_name(e: i32) -> String {
    let n = match e {
        errno::EPERM => "EPERM",
        errno::ENOENT => "ENOENT",
        errno::EIO => "EIO",
        errno::EAGAIN => "EAGAIN",
        errno::EBUSY => "EBUSY",
        errno::EEXIST => "EEXIST",
        errno::EINVAL => "EINVAL",
        errno::ENFILE => "ENFILE",
        errno::EFBIG => "EFBIG",
        errno::ENOSPC => "ENOSPC",
        errno::ERANGE => "ERANGE",
        errno::ENAMETOOLONG => "ENAMETOOLONG",
        errno::ENODATA => "ENODATA",
        errno::EOVERFLOW => "EOVERFLOW",
        errno::EOLDSNAPC => "EOLDSNAPC",
        errno::EMSGSIZE => "EMSGSIZE",
        errno::EOPNOTSUPP => "EOPNOTSUPP",
        errno::EBLOCKLISTED => "EBLOCKLISTED",
        errno::ETIMEDOUT => "ETIMEDOUT",
        errno::ECANCELED => "ECANCELED",
        _ => "",
    };
    n.to_string()
}

/// `0`, `-2(ENOENT)`, `-4097(cmpext@2)`.
pub fn result_str(r: i32) -> String {
    if r >= 0 {
        return r.to_string();
    }
    if let Some(i) = opwire::errno::cmpext_index(r) {
        return format!("{r}(cmpext-mismatch@{i})");
    }
    let n = errno_name(-r);
    if n.is_empty() {
        r.to_string()
    } else {
        format!("{r}({n})")
    }
}

/// Bytes as `"text"` when printable, else `hex:..`; long data is abbreviated with its crc32c.
pub fn show_bytes(b: &[u8]) -> String {
    if b.is_empty() {
        return "<empty>".into();
    }
    const MAX: usize = 48;
    let printable = |x: &[u8]| {
        x.iter()
            .all(|c| (0x20..0x7f).contains(c) && *c != b'"' && *c != b'\\')
    };
    let head = &b[..b.len().min(MAX)];
    let mut s = if printable(head) {
        format!("\"{}\"", String::from_utf8_lossy(head))
    } else {
        format!("hex:{}", hex(head))
    };
    if b.len() > MAX {
        let _ = write!(
            s,
            "...(+{}B) crc32c={:08x}",
            b.len() - MAX,
            crc::crc32c(0, b)
        );
    }
    s
}

pub fn hex(b: &[u8]) -> String {
    const H: [u8; 16] = *b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for c in b {
        s.push(H[usize::from(c >> 4)] as char);
        s.push(H[usize::from(c & 15)] as char);
    }
    s
}

fn kv(m: &KvMap) -> String {
    let v: Vec<String> = m
        .iter()
        .map(|(k, v)| format!("{}={}", show_bytes(k), show_bytes(v)))
        .collect();
    format!("{{{}}}", v.join(", "))
}

/// Zero-filled view of a `SPARSE_READ` reply over the requested extent, for normalized comparison: implementations may
/// report holes differently (coarser extents), so compare the bytes. `None` when the extent list cannot form a bounded
/// window inside the request (or does not match its own data): the reply is then rendered raw, never allocated for.
fn sparse_view(req: Option<&OsdOp>, s: &SparseReadOut) -> Option<Vec<u8>> {
    let (base, want) = req.map_or((0, u64::MAX), |r| {
        let e = r.extent();
        (e.offset, e.length)
    });
    let mut end = base;
    let mut total: u64 = 0;
    for (o, l) in &s.extents {
        if *o < base {
            return None;
        }
        end = end.max(o.checked_add(*l)?);
        total = total.checked_add(*l)?;
    }
    // decoded sparse data is exactly the concatenated extents; anything else is a renderer bug, not a reply shape
    if total != s.data.len() as u64 || end - base > want {
        return None;
    }
    let mut buf = vec![0u8; usize::try_from(end - base).ok()?];
    let mut pos = 0usize;
    for (o, l) in &s.extents {
        let at = usize::try_from(*o - base).ok()?;
        let len = usize::try_from(*l).ok()?;
        buf[at..at + len].copy_from_slice(&s.data[pos..pos + len]);
        pos += len;
    }
    Some(buf)
}

fn decoded(req: Option<&OsdOp>, o: &OsdOp, d: Detail) -> String {
    let b = &o.outdata;
    let raw = || format!("len={} {}", b.len(), show_bytes(b));
    if b.is_empty() {
        return "out=<empty>".into();
    }
    let r = match o.op {
        code::STAT => from_slice::<StatOut>(b).ok().map(|s| match d {
            Detail::Full => format!("size={} mtime={}.{:09}", s.size, s.mtime.sec, s.mtime.nsec),
            Detail::Normalized => format!("size={} mtime=<t>", s.size),
        }),
        code::OMAP_GET_KEYS => from_slice::<OmapKeysOut>(b).ok().map(|k| {
            let ks: Vec<String> = k.keys.iter().map(|x| show_bytes(x)).collect();
            format!("keys=[{}] truncated={}", ks.join(", "), k.truncated)
        }),
        code::OMAP_GET_VALS => from_slice::<OmapValsOut>(b)
            .ok()
            .map(|v| format!("vals={} truncated={}", kv(&v.vals), v.truncated)),
        code::OMAP_GET_VALS_BY_KEYS | code::GETXATTRS => from_slice::<KvMap>(b)
            .ok()
            .map(|m| format!("map={}", kv(&m))),
        code::SPARSE_READ => from_slice::<SparseReadOut>(b).ok().and_then(|s| {
            let e: Vec<String> = s.extents.iter().map(|(o, l)| format!("{o}~{l}")).collect();
            if d == Detail::Normalized {
                let mut buf = sparse_view(req, &s)?;
                while buf.last() == Some(&0) {
                    buf.pop();
                }
                Some(format!(
                    "sparse-data(zero-filled, trailing zeros trimmed) len={} data={}",
                    buf.len(),
                    show_bytes(&buf)
                ))
            } else {
                Some(format!(
                    "extents=[{}] data={}",
                    e.join(","),
                    show_bytes(&s.data)
                ))
            }
        }),
        code::CHECKSUM => req
            .map(|r| r.checksum().ty)
            .and_then(|ty| ChecksumOut::decode(ty, b).ok())
            .map(|c| {
                let v: Vec<String> = c.values.iter().map(|x| format!("{x:#x}")).collect();
                format!("csum[{}]=[{}]", c.values.len(), v.join(","))
            }),
        code::LIST_WATCHERS => from_slice::<ObjListWatchResponse>(b).ok().map(|w| {
            let v: Vec<String> = w
                .entries
                .iter()
                .map(|e| format!("{:?}/cookie={}/timeout={}", e.name, e.cookie, e.timeout_s))
                .collect();
            format!("watchers=[{}]", v.join(", "))
        }),
        code::LIST_SNAPS => from_slice::<ObjListSnapResponse>(b).ok().map(|s| {
            let v: Vec<String> = s
                .clones
                .iter()
                .map(|c| {
                    format!(
                        "clone{{id={} snaps={:?} overlap={:?} size={}}}",
                        c.cloneid as i64, c.snaps, c.overlap, c.size
                    )
                })
                .collect();
            format!("seq={} clones=[{}]", s.seq, v.join(", "))
        }),
        _ => None,
    };
    r.unwrap_or_else(raw)
}

/// Render the reply to a request whose ops were `req_ops` (used to interpret checksum).
pub fn render_reply(req_ops: &[OsdOp], rep: &MOSDOpReply, d: Detail) -> String {
    let mut s = String::new();
    let _ = write!(s, "result={}", result_str(rep.result));
    if d == Detail::Full {
        let _ = write!(
            s,
            " epoch={} replay_version={}'{} user_version={} flags={:#x} retry={}",
            rep.osdmap_epoch,
            rep.replay_version.epoch,
            rep.replay_version.version,
            rep.user_version,
            rep.flags,
            rep.retry_attempt
        );
        if rep.redirect.is_some() {
            s.push_str(" REDIRECT");
        }
    }
    s.push('\n');
    for (i, o) in rep.ops.iter().enumerate() {
        let name = code::name(o.op).map_or_else(|| format!("op{:#06x}", o.op), str::to_string);
        let _ = writeln!(
            s,
            "  [{i}] {name} rval={} {}",
            result_str(o.rval),
            decoded(req_ops.get(i), o, d)
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::Encode;

    fn reply_op(opcode: u16, out: &SparseReadOut) -> OsdOp {
        let mut o = OsdOp::new(opcode);
        o.outdata = out.encode_to_vec().expect("encode").into();
        o
    }

    fn one_op_reply(o: OsdOp) -> MOSDOpReply {
        MOSDOpReply {
            ops: vec![o],
            ..Default::default()
        }
    }

    #[test]
    fn sparse_read_hole_far_outside_the_request_is_rendered_raw() {
        // a hostile/buggy OSD: one data byte at the top of the offset range
        let out = SparseReadOut {
            extents: [(0u64, 1u64), (u64::MAX - 4096, 1)].into(),
            data: vec![7, 9],
        };
        let s = render_reply(
            &[OsdOp::sparse_read(0, 4096)],
            &one_op_reply(reply_op(code::SPARSE_READ, &out)),
            Detail::Normalized,
        );
        assert!(s.contains("hex:"), "raw rendering expected: {s}");
        assert!(!s.contains("sparse-data"), "{s}");
    }

    #[test]
    fn sparse_read_normalized_zero_fills_inside_the_request() {
        let out = SparseReadOut {
            extents: [(0u64, 2u64), (4096, 1)].into(),
            data: vec![1, 2, 3],
        };
        let s = render_reply(
            &[OsdOp::sparse_read(0, 4097)],
            &one_op_reply(reply_op(code::SPARSE_READ, &out)),
            Detail::Normalized,
        );
        assert!(
            s.contains("sparse-data(zero-filled, trailing zeros trimmed) len=4097"),
            "{s}"
        );
    }

    #[test]
    fn sparse_read_past_the_requested_extent_is_rendered_raw() {
        let out = SparseReadOut {
            extents: [(4096u64, 1)].into(),
            data: vec![1],
        };
        let s = render_reply(
            &[OsdOp::sparse_read(0, 4096)],
            &one_op_reply(reply_op(code::SPARSE_READ, &out)),
            Detail::Normalized,
        );
        assert!(!s.contains("sparse-data"), "raw rendering expected: {s}");
    }

    #[test]
    fn hex_is_lowercase_two_digits_per_byte() {
        assert_eq!(hex(b""), "");
        assert_eq!(hex(&[0x00, 0x0a, 0x9f, 0xff]), "000a9fff");
    }

    #[test]
    fn errno_names_and_plain_results() {
        assert_eq!(result_str(0), "0");
        assert_eq!(result_str(4), "4");
        assert_eq!(result_str(-2), "-2(ENOENT)");
        assert_eq!(result_str(-110), "-110(ETIMEDOUT)");
        assert_eq!(errno_name(opwire::errno::ENOSPC), "ENOSPC");
        assert_eq!(errno_name(9999), "");
    }
}
