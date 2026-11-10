// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Op script language: text -> compound MOSDOp op vector.
//!
//! One *message* = statements separated by `;` or newline; messages in a file are separated by a
//! line `---`. `#` starts a comment (outside quotes). Statement = `opname arg...`.
//!
//! Data args: bare word or quoted text (utf8 bytes; `"` supports \n \r \t \0 \\ \" \xHH, `'` is
//! literal), `hex:DEADBEEF`, `zeros:N`, `seq:N` (bytes i%251), `rep:N:text` (text N times); a data argument may
//! not exceed one msgr2 frame (a larger payload could never be sent).
//! Numbers: decimal or 0x hex.
//!
//! Ops: read OFF LEN | sync-read OFF LEN | sparse-read OFF LEN | stat | write OFF DATA |
//! writefull DATA | append DATA | writesame OFF LEN PATTERN | zero OFF LEN | truncate SIZE |
//! delete | create [excl] | cmpext OFF DATA | getxattr K | getxattrs | setxattr K V | rmxattr K |
//! cmpxattr K V [eq|ne|gt|gte|lt|lte] [string|u64] | omap-set K=V... | omap-get-keys [AFTER [MAX]] |
//! omap-get-vals [AFTER [MAX [PREFIX]]] | omap-get-vals-by-keys K... | omap-get-header |
//! omap-set-header DATA | omap-clear | omap-rm-keys K... | omap-rm-range BEGIN END |
//! omap-cmp K eq|gt|lt|N VALUE | assert-version N | list-watchers | list-snaps |
//! checksum xxhash32|xxhash64|crc32c OFF LEN CHUNK [INIT] | alloc-hint OBJSZ WRSZ [FLAGS] |
//! call CLASS METHOD [DATA] | rollback SNAP | raw OPCODE [DATA] (unknown/invalid ops).
//! Op modifiers (any position): `!failok`, `!excl`, `!opflags=N`.
//! Directives (own statement): `@snapid=N|head|snapdir`, `@snapc=SEQ:S1,S2,...` (descending),
//! `@flags=returnvec,full_try,fail_on_eagain,rwordered,balance_reads,localize_reads,ordersnap,
//! parallelexec,force_osd,0xN`.

use opwire::consts::{cmp, csum, flag as mflag, op as code, opflag};
use opwire::{NOSNAP, OsdOp, SNAPDIR};
use std::collections::{BTreeMap, BTreeSet};

/// One parsed compound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptMsg {
    pub ops: Vec<OsdOp>,
    pub snapid: u64,
    pub snap_seq: u64,
    pub snaps: Vec<u64>,
    /// Extra CEPH_OSD_FLAG_* OR'ed into the message flags.
    pub flags: u32,
    /// Source text (statements joined by "; "), for display.
    pub text: String,
}

impl Default for ScriptMsg {
    fn default() -> Self {
        ScriptMsg {
            ops: Vec::new(),
            snapid: NOSNAP,
            snap_seq: 0,
            snaps: Vec::new(),
            flags: 0,
            text: String::new(),
        }
    }
}

type Res<T> = Result<T, String>;

/// Split `text` into statements of tokens (quotes resolved, comments stripped).
fn tokenize(text: &str) -> Res<Vec<Vec<Vec<u8>>>> {
    let mut stmts: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut cur: Vec<Vec<u8>> = Vec::new();
    let mut tok: Vec<u8> = Vec::new();
    let mut have = false;
    let mut it = text.chars().peekable();
    macro_rules! end_tok {
        () => {
            if have {
                cur.push(std::mem::take(&mut tok));
                have = false;
            }
        };
    }
    macro_rules! end_stmt {
        () => {
            end_tok!();
            if !cur.is_empty() {
                stmts.push(std::mem::take(&mut cur));
            }
        };
    }
    while let Some(c) = it.next() {
        match c {
            ';' | '\n' => {
                end_stmt!();
            }
            c if c.is_whitespace() => {
                end_tok!();
            }
            '#' if !have => {
                for c in it.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
                end_stmt!();
            }
            '"' => {
                have = true;
                loop {
                    let Some(c) = it.next() else {
                        return Err("unterminated \"".into());
                    };
                    match c {
                        '"' => break,
                        '\\' => match it.next() {
                            Some('n') => tok.push(b'\n'),
                            Some('r') => tok.push(b'\r'),
                            Some('t') => tok.push(b'\t'),
                            Some('0') => tok.push(0),
                            Some('x') => {
                                let h: String =
                                    [it.next(), it.next()].into_iter().flatten().collect();
                                tok.push(
                                    u8::from_str_radix(&h, 16)
                                        .map_err(|_| format!("bad \\x{h}"))?,
                                );
                            }
                            Some(o) => {
                                let mut b = [0u8; 4];
                                tok.extend_from_slice(o.encode_utf8(&mut b).as_bytes());
                            }
                            None => return Err("dangling backslash".into()),
                        },
                        o => {
                            let mut b = [0u8; 4];
                            tok.extend_from_slice(o.encode_utf8(&mut b).as_bytes());
                        }
                    }
                }
            }
            '\'' => {
                have = true;
                loop {
                    let Some(c) = it.next() else {
                        return Err("unterminated '".into());
                    };
                    if c == '\'' {
                        break;
                    }
                    let mut b = [0u8; 4];
                    tok.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
                }
            }
            o => {
                have = true;
                let mut b = [0u8; 4];
                tok.extend_from_slice(o.encode_utf8(&mut b).as_bytes());
            }
        }
    }
    if have {
        cur.push(tok);
    }
    if !cur.is_empty() {
        stmts.push(cur);
    }
    Ok(stmts)
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn num(b: &[u8]) -> Res<u64> {
    let t = s(b).replace('_', "");
    let r = if let Some(h) = t.strip_prefix("0x") {
        u64::from_str_radix(h, 16)
    } else {
        t.parse::<u64>()
    };
    r.map_err(|_| format!("bad number '{t}'"))
}

/// Largest data argument one message can carry: the frame limit of the msgr2 connections oprobe opens
/// ([`msgr2::Config::new`] keeps [`msgr2::Limits::default`]); a larger payload could never be sent.
fn max_data() -> u64 {
    msgr2::Limits::default().max_frame
}

/// A payload length `n` as a host size, refused when one frame cannot carry it.
fn payload_len(n: u64) -> Res<usize> {
    let max = max_data();
    if n > max {
        return Err(format!(
            "data argument of {n} B exceeds one msgr2 frame ({max} B)"
        ));
    }
    usize::try_from(n).map_err(|_| format!("data argument of {n} B does not fit this host"))
}

/// Payload length of `count` text repetitions (`count * unit` bytes) without wrapping.
fn repeat_bytes(count: u64, unit: usize) -> Res<usize> {
    let bytes = u64::try_from(unit)
        .ok()
        .and_then(|u| count.checked_mul(u))
        .ok_or_else(|| format!("rep:{count} overflows the payload length"))?;
    payload_len(bytes)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse a data argument (see module docs). Works on the raw bytes: a non-UTF-8 quoted argument and a multi-byte
/// `hex:` input cannot shift a slice boundary.
pub fn data(b: &[u8]) -> Res<Vec<u8>> {
    if let Some(h) = b.strip_prefix(b"hex:") {
        let digits: Vec<u8> = h
            .iter()
            .copied()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if !digits.len().is_multiple_of(2) {
            return Err(format!("odd hex length in '{}'", s(b)));
        }
        return digits
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| match (hex_digit(p[0]), hex_digit(p[1])) {
                (Some(hi), Some(lo)) => Ok(hi << 4 | lo),
                _ => Err(format!("bad hex '{}'", s(b))),
            })
            .collect();
    }
    if let Some(n) = b.strip_prefix(b"zeros:") {
        return Ok(vec![0; payload_len(num(n)?)?]);
    }
    if let Some(n) = b.strip_prefix(b"seq:") {
        let len = payload_len(num(n)?)?;
        return Ok((0..len as u64).map(|i| (i % 251) as u8).collect());
    }
    if let Some(r) = b.strip_prefix(b"rep:") {
        let at = r.iter().position(|c| *c == b':').ok_or("rep:N:text")?;
        let (n, txt) = (&r[..at], &r[at + 1..]);
        let count = num(n)?;
        repeat_bytes(count, txt.len())?;
        let count = usize::try_from(count).map_err(|_| format!("rep:{count} too long"))?;
        return Ok(txt.repeat(count));
    }
    Ok(b.to_vec())
}

fn arg<'a>(a: &'a [Vec<u8>], i: usize, name: &str, usage: &str) -> Res<&'a [u8]> {
    a.get(i)
        .map(|v| v.as_slice())
        .ok_or_else(|| format!("{name}: missing argument {} ({usage})", i + 1))
}

fn cmp_op(b: &[u8]) -> Res<u8> {
    Ok(match s(b).as_str() {
        "eq" => cmp::EQ,
        "ne" => cmp::NE,
        "gt" => cmp::GT,
        "gte" | "ge" => cmp::GTE,
        "lt" => cmp::LT,
        "lte" | "le" => cmp::LTE,
        o => num(o.as_bytes())? as u8,
    })
}

fn msg_flags(list: &str) -> Res<u32> {
    let mut f = 0;
    for w in list.split(',').filter(|w| !w.is_empty()) {
        f |= match w {
            "returnvec" => mflag::RETURNVEC,
            "full_try" => mflag::FULL_TRY,
            "full_force" => mflag::FULL_FORCE,
            "fail_on_eagain" => mflag::FAIL_ON_EAGAIN,
            "rwordered" => mflag::RWORDERED,
            "balance_reads" => mflag::BALANCE_READS,
            "localize_reads" => mflag::LOCALIZE_READS,
            "ordersnap" => mflag::ORDERSNAP,
            "parallelexec" => mflag::PARALLELEXEC,
            "force_osd" => mflag::FORCE_OSD,
            "pgop" => mflag::PGOP,
            h => num(h.as_bytes())? as u32,
        };
    }
    Ok(f)
}

fn parse_op(name: &str, a: &[Vec<u8>]) -> Res<OsdOp> {
    let n = |i: usize, u: &str| -> Res<u64> { num(arg(a, i, name, u)?) };
    let d = |i: usize, u: &str| -> Res<Vec<u8>> { data(arg(a, i, name, u)?) };
    let opt = |i: usize| a.get(i).map(|v| v.as_slice());
    Ok(match name {
        "read" => OsdOp::read(n(0, "OFF LEN")?, n(1, "OFF LEN")?),
        "sync-read" | "sync_read" => {
            let mut o = OsdOp::read(n(0, "OFF LEN")?, n(1, "OFF LEN")?);
            o.op = code::SYNC_READ;
            o
        }
        "sparse-read" => OsdOp::sparse_read(n(0, "OFF LEN")?, n(1, "OFF LEN")?),
        "stat" => OsdOp::stat(),
        "write" => OsdOp::write(n(0, "OFF DATA")?, d(1, "OFF DATA")?),
        "writefull" => OsdOp::writefull(d(0, "DATA")?),
        "append" => OsdOp::append(d(0, "DATA")?),
        "writesame" | "write-same" => OsdOp::writesame(
            n(0, "OFF LEN PAT")?,
            n(1, "OFF LEN PAT")?,
            d(2, "OFF LEN PAT")?,
        ),
        "zero" => OsdOp::zero(n(0, "OFF LEN")?, n(1, "OFF LEN")?),
        "truncate" => OsdOp::truncate(n(0, "SIZE")?),
        "delete" => OsdOp::delete(),
        "create" => OsdOp::create(opt(0).is_some_and(|x| x == b"excl")),
        "cmpext" => OsdOp::cmpext(n(0, "OFF DATA")?, d(1, "OFF DATA")?),
        "getxattr" => OsdOp::getxattr(&d(0, "NAME")?),
        "getxattrs" => OsdOp::new(code::GETXATTRS),
        "setxattr" => OsdOp::setxattr(&d(0, "NAME VALUE")?, &d(1, "NAME VALUE")?),
        "rmxattr" => OsdOp::rmxattr(&d(0, "NAME")?),
        "cmpxattr" => {
            let op = opt(2).map(cmp_op).transpose()?.unwrap_or(cmp::EQ);
            let mode = match opt(3).map(s).as_deref() {
                None | Some("string") => cmp::MODE_STRING,
                Some("u64") => cmp::MODE_U64,
                Some(o) => num(o.as_bytes())? as u8,
            };
            let v = if mode == cmp::MODE_U64 {
                n(1, "NAME VALUE")?.to_le_bytes().to_vec()
            } else {
                d(1, "NAME VALUE")?
            };
            OsdOp::cmpxattr(&d(0, "NAME VALUE")?, &v, op, mode)
        }
        "omap-set" | "omap-set-vals" => {
            let mut m = BTreeMap::new();
            for kv in a {
                let p = kv
                    .iter()
                    .position(|c| *c == b'=')
                    .ok_or("omap-set: expected K=V")?;
                m.insert(kv[..p].to_vec(), data(&kv[p + 1..])?);
            }
            OsdOp::omap_set_vals(&m)
        }
        "omap-get-keys" => OsdOp::omap_get_keys(
            opt(0).unwrap_or(b""),
            opt(1).map(num).transpose()?.unwrap_or(1000),
        ),
        "omap-get-vals" => OsdOp::omap_get_vals(
            opt(0).unwrap_or(b""),
            opt(1).map(num).transpose()?.unwrap_or(1000),
            opt(2).unwrap_or(b""),
        ),
        "omap-get-vals-by-keys" => {
            let keys: BTreeSet<Vec<u8>> = a.iter().cloned().collect();
            let mut o = OsdOp::new(code::OMAP_GET_VALS_BY_KEYS);
            o.indata = denc::Encode::encode_to_vec(&keys)
                .map_err(|e| e.to_string())?
                .into();
            o
        }
        "omap-get-header" => OsdOp::omap_get_header(),
        "omap-set-header" => OsdOp::omap_set_header(d(0, "DATA")?),
        "omap-clear" => OsdOp::omap_clear(),
        "omap-rm-keys" => OsdOp::omap_rm_keys(&a.iter().cloned().collect()),
        "omap-rm-range" | "omap-rm-key-range" => {
            let mut o = OsdOp::new(code::OMAP_RM_KEY_RANGE);
            o.indata = denc::Encode::encode_to_vec(&opwire::OmapRmKeyRangeIn {
                begin: arg(a, 0, name, "BEGIN END")?.to_vec(),
                end: arg(a, 1, name, "BEGIN END")?.to_vec(),
            })
            .map_err(|e| e.to_string())?
            .into();
            o
        }
        "omap-cmp" => {
            let key = arg(a, 0, name, "KEY eq|gt|lt VALUE")?.to_vec();
            let op = match s(arg(a, 1, name, "KEY OP VALUE")?).as_str() {
                "eq" => 1,
                "gt" => 2,
                "lt" => 3,
                o => num(o.as_bytes())? as i32,
            };
            let mut m = BTreeMap::new();
            m.insert(key, (d(2, "KEY OP VALUE")?, op));
            let mut o = OsdOp::new(code::OMAP_CMP);
            o.indata = denc::Encode::encode_to_vec(&m)
                .map_err(|e| e.to_string())?
                .into();
            o
        }
        "assert-version" => OsdOp::assert_version(n(0, "VER")?),
        "list-watchers" => OsdOp::list_watchers(),
        "list-snaps" => OsdOp::list_snaps(),
        "checksum" => {
            let ty = match s(arg(a, 0, name, "TYPE OFF LEN CHUNK [INIT]")?).as_str() {
                "xxhash32" => csum::XXHASH32,
                "xxhash64" => csum::XXHASH64,
                "crc32c" => csum::CRC32C,
                o => num(o.as_bytes())? as u8,
            };
            let w = csum::width(ty).unwrap_or(4);
            let init = opt(4).map(num).transpose()?.unwrap_or(0);
            let mut o = OsdOp::new(code::CHECKSUM);
            o.set_checksum(opwire::Checksum {
                offset: n(1, "TYPE OFF LEN CHUNK")?,
                length: n(2, "TYPE OFF LEN CHUNK")?,
                chunk_size: n(3, "TYPE OFF LEN CHUNK")? as u32,
                ty,
            });
            o.indata = init.to_le_bytes()[..w].to_vec().into();
            o
        }
        "alloc-hint" => OsdOp::alloc_hint_op(
            n(0, "OBJSZ WRSZ [FLAGS]")?,
            n(1, "OBJSZ WRSZ [FLAGS]")?,
            opt(2).map(num).transpose()?.unwrap_or(0) as u32,
        ),
        "call" => OsdOp::call(
            arg(a, 0, name, "CLASS METHOD [DATA]")?,
            arg(a, 1, name, "CLASS METHOD [DATA]")?,
            &opt(2).map(data).transpose()?.unwrap_or_default(),
        ),
        "rollback" => OsdOp::rollback(n(0, "SNAP")?),
        "raw" => {
            let mut o = OsdOp::new(n(0, "OPCODE [DATA]")? as u16);
            o.indata = opt(1).map(data).transpose()?.unwrap_or_default().into();
            o
        }
        o => return Err(format!("unknown op '{o}'")),
    })
}

fn parse_stmt(m: &mut ScriptMsg, st: &[Vec<u8>]) -> Res<()> {
    let name = s(&st[0]);
    if let Some(d) = name.strip_prefix('@') {
        let (k, v) = d.split_once('=').ok_or("directive needs =")?;
        let mut v = v.to_string();
        for extra in &st[1..] {
            v.push(' ');
            v.push_str(&s(extra));
        }
        match k {
            "snapid" => {
                m.snapid = match v.as_str() {
                    "head" => NOSNAP,
                    "snapdir" => SNAPDIR,
                    o => num(o.as_bytes())?,
                }
            }
            "snapc" => {
                let (seq, snaps) = v.split_once(':').unwrap_or((&v, ""));
                m.snap_seq = num(seq.as_bytes())?;
                m.snaps = snaps
                    .split(',')
                    .filter(|x| !x.is_empty())
                    .map(|x| num(x.as_bytes()))
                    .collect::<Res<_>>()?;
            }
            "flags" => m.flags |= msg_flags(&v)?,
            _ => return Err(format!("unknown directive @{k}")),
        }
        return Ok(());
    }
    let mut args = Vec::new();
    let mut oflags = 0u32;
    for t in &st[1..] {
        if let Some(m) = t.strip_prefix(b"!") {
            match s(m).as_str() {
                "failok" => oflags |= opflag::FAILOK,
                "excl" => oflags |= opflag::EXCL,
                o if o.starts_with("opflags=") => oflags |= num(&o.as_bytes()[8..])? as u32,
                o => return Err(format!("unknown modifier !{o}")),
            }
        } else {
            args.push(t.clone());
        }
    }
    let mut op = parse_op(&name, &args).map_err(|e| format!("{e} in '{}'", display(st)))?;
    op.flags |= oflags;
    m.ops.push(op);
    Ok(())
}

fn display(st: &[Vec<u8>]) -> String {
    st.iter()
        .map(|t| {
            if t.is_empty() {
                "\"\"".to_string()
            } else {
                s(t)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse one message (statements separated by `;`/newline).
pub fn parse_message(text: &str) -> Res<ScriptMsg> {
    let mut m = ScriptMsg::default();
    let stmts = tokenize(text)?;
    let mut shown = Vec::new();
    for st in &stmts {
        parse_stmt(&mut m, st)?;
        shown.push(display(st));
    }
    m.text = shown.join("; ");
    Ok(m)
}

/// Parse a script file: messages separated by lines consisting of `---`.
pub fn parse_file(text: &str) -> Res<Vec<ScriptMsg>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut Vec<ScriptMsg>| -> Res<()> {
        let m = parse_message(cur)?;
        if !m.ops.is_empty() {
            out.push(m);
        }
        cur.clear();
        Ok(())
    };
    for l in text.lines() {
        if l.trim() == "---" {
            flush(&mut cur, &mut out)?;
        } else {
            cur.push_str(l);
            cur.push('\n');
        }
    }
    flush(&mut cur, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let m = parse_message(r#"write 0 "abc"; read 0 3; setxattr k v; getxattr k; omap-set k=v a=hex:6263; stat; call rbd get_size hex:00"#).unwrap();
        assert_eq!(m.ops.len(), 7);
        assert_eq!(m.ops[0].indata[..], b"abc"[..]);
        assert_eq!(m.ops[6].cls().class_len, 3);
        let o = &m.ops[4];
        assert_eq!(o.op, code::OMAP_SET_VALS);
    }

    #[test]
    fn quoting_and_mods() {
        let m =
            parse_message("write 1 'a b' !failok # comment\n@snapid=snapdir\nlist-snaps").unwrap();
        assert_eq!(m.ops.len(), 2);
        assert_eq!(m.ops[0].indata[..], b"a b"[..]);
        assert!(m.ops[0].failok());
        assert_eq!(m.snapid, SNAPDIR);
        assert!(parse_message("bogus 1").is_err());
        assert_eq!(data(b"rep:3:ab").unwrap(), b"ababab");
    }

    #[test]
    fn file_split() {
        let v = parse_file("write 0 x\n---\nread 0 1\n---\n").unwrap();
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn hex_data_is_byte_clean() {
        assert_eq!(data(b"hex:41 42 0a").unwrap(), b"AB\n");
        assert_eq!(data(b"hex:ff").unwrap(), vec![0xff]);
        assert_eq!(data(&[0xff, 0xfe]).unwrap(), vec![0xff, 0xfe]);
        // a multi-byte char is not hex; slicing it by byte panics
        assert!(data("hex:€€".as_bytes()).is_err());
        assert!(data("hex:😀".as_bytes()).is_err());
        assert!(data(b"hex:4g").is_err());
        assert!(data(b"hex:414").is_err());
    }

    #[test]
    fn oversized_data_arguments_are_rejected() {
        assert!(data(b"zeros:18446744073709551615").is_err());
        assert!(data(b"seq:18446744073709551615").is_err());
        assert!(data(b"rep:18446744073709551615:x").is_err());
        assert!(
            data(format!("zeros:{}", max_data() + 1).as_bytes()).is_err(),
            "one byte above the frame limit"
        );
        assert!(repeat_bytes(u64::MAX, 64).is_err());
        assert_eq!(data(b"zeros:3").unwrap(), vec![0; 3]);
        assert_eq!(payload_len(max_data()).unwrap() as u64, max_data());
    }
}
