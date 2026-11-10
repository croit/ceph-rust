// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `otp` (spec/cls_otp.md): TOTP instances in omap, HMAC-SHA1 implemented locally (adr 0060).

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use denc::types::UTime;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::BTreeSet;

pub const HEADER_KEY: &[u8] = b"header";
pub const KEY_PREFIX: &[u8] = b"otp/";
pub const ATTEMPTS_PER_WINDOW: usize = 5;
/// Upstream loops `2*window+1` HMACs without bound; we stop at this window.
pub const MAX_WINDOW: u32 = 1000;

pub const TYPE_TOTP: u8 = 2;
pub const SEED_HEX: u8 = 1;
pub const SEED_BASE32: u8 = 2;
pub const CHECK_UNKNOWN: u8 = 0;
pub const CHECK_SUCCESS: u8 = 1;
pub const CHECK_FAIL: u8 = 2;

// ------------------------------------------------------------------ SHA-1 / HMAC (RFC 3174, 2104)

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (hv, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *hv = hv.wrapping_add(v);
        }
    }
    let mut out = [0u8; 20];
    for (o, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        o.copy_from_slice(&v.to_be_bytes());
    }
    out
}

pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..20].copy_from_slice(&sha1(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(msg);
    let mut outer: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&sha1(&inner));
    sha1(&outer)
}

/// RFC 4226 HOTP value as a zero-padded decimal string of `digits` (<= 9) digits.
pub fn hotp(seed: &[u8], counter: u64, digits: usize) -> String {
    let mac = hmac_sha1(seed, &counter.to_be_bytes());
    let o = (mac[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([mac[o] & 0x7f, mac[o + 1], mac[o + 2], mac[o + 3]]);
    let m = 10u64.pow(digits.min(9) as u32);
    format!("{:0w$}", bin as u64 % m, w = digits.min(9))
}

/// liboath (2.6.12) TOTP search as classic calls it: `t = (secs - ofs) / step` as a wrapping u64
/// counter; probe `t`, then `t+1, t-1, t+2, t-2, ...` up to `window` (counters wrap modulo 2^64,
/// no lower bound). Returns the absolute displacement `d` of the first match (sign dropped: a
/// match at `t-d` and at `t+d` both return `d`). `val` ends at its first NUL (C string), its
/// length is the digit count (6..=8, else no match). `step == 0` never matches (classic divides
/// by zero in its index formula); `window` is clamped to [`MAX_WINDOW`].
pub fn totp_validate(
    seed: &[u8],
    secs: u32,
    step: u32,
    ofs: i32,
    window: u32,
    val: &[u8],
) -> Option<u32> {
    let val = &val[..val.iter().position(|b| *b == 0).unwrap_or(val.len())];
    if step == 0 || !(6..=8).contains(&val.len()) {
        return None;
    }
    let t = ((secs as i64 - ofs as i64) / step as i64) as u64;
    let hit = |ctr: u64| hotp(seed, ctr, val.len()).as_bytes() == val;
    (0..=window.min(MAX_WINDOW))
        .find(|&d| hit(t.wrapping_add(d as u64)) || (d > 0 && hit(t.wrapping_sub(d as u64))))
}

// ------------------------------------------------------------------ seed parsing

/// liboath hex decode: the seed is a C string (ends at its first NUL); pairs of hex digits
/// (either case); odd digit count or any other byte -> invalid.
fn parse_hex(s: &[u8]) -> Option<Vec<u8>> {
    let s = &s[..s.iter().position(|b| *b == 0).unwrap_or(s.len())];
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let nib = |c: u8| (c as char).to_digit(16).map(|v| v as u8);
    s.as_chunks::<2>()
        .0
        .iter()
        .map(|p| Some(nib(p[0])? << 4 | nib(p[1])?))
        .collect()
}

/// liboath base32 decode (RFC 4648 alphabet over the full byte length): ASCII spaces are
/// dropped, letters case-folded; a stripped length of 2, 4, 5 or 7 (mod 8) is completed with
/// `=` (1, 3, 6 stay short and fail). Then every 8-char group must be `XX======`, `XXXX====`,
/// `XXXXX===`, `XXXXXXX=` or `XXXXXXXX` (X = alphabet); a padded group may be followed by more
/// groups. Unused trailing bits are ignored.
fn parse_base32(s: &[u8]) -> Option<Vec<u8>> {
    let mut chars: Vec<u8> = s
        .iter()
        .filter(|c| **c != b' ')
        .map(u8::to_ascii_uppercase)
        .collect();
    let pad = match chars.len() % 8 {
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        _ => 0,
    };
    chars.resize(chars.len() + pad, b'=');
    if !chars.len().is_multiple_of(8) {
        return None;
    }
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    };
    let mut out = Vec::with_capacity(chars.len() / 8 * 5);
    for g in chars.as_chunks::<8>().0 {
        let data = g.iter().position(|c| *c == b'=').unwrap_or(8);
        if !matches!(data, 2 | 4 | 5 | 7 | 8) || g[data..].iter().any(|c| *c != b'=') {
            return None;
        }
        let mut acc = 0u64;
        for &c in &g[..data] {
            acc = acc << 5 | val(c)? as u64;
        }
        let bytes = data * 5 / 8;
        acc >>= data * 5 - bytes * 8;
        out.extend((0..bytes).rev().map(|i| (acc >> (8 * i)) as u8));
    }
    Some(out)
}

pub fn parse_seed(seed: &[u8], seed_type: u8) -> Option<Vec<u8>> {
    if seed_type == SEED_BASE32 {
        parse_base32(seed)
    } else {
        parse_hex(seed)
    }
}

// ------------------------------------------------------------------ types

/// `otp_info_t` (1,1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpInfo {
    pub type_: u8,
    pub id: Vec<u8>,
    pub seed: Vec<u8>,
    pub seed_type: u8,
    pub seed_bin: Vec<u8>,
    pub time_ofs: i32,
    pub step_size: u32,
    pub window: u32,
}
impl Default for OtpInfo {
    fn default() -> Self {
        OtpInfo {
            type_: TYPE_TOTP,
            id: Vec::new(),
            seed: Vec::new(),
            seed_type: 0,
            seed_bin: Vec::new(),
            time_ofs: 0,
            step_size: 30,
            window: 2,
        }
    }
}
impl Encode for OtpInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| {
            e.u8(self.type_)?;
            self.id.encode(e)?;
            self.seed.encode(e)?;
            e.u8(self.seed_type)?;
            self.seed_bin.encode(e)?;
            e.i32(self.time_ofs)?;
            e.u32(self.step_size)?;
            e.u32(self.window)
        })
    }
}
impl<'a> Decode<'a> for OtpInfo {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            Ok(OtpInfo {
                type_: d.u8()?,
                id: Vec::<u8>::decode(d)?,
                seed: Vec::<u8>::decode(d)?,
                seed_type: d.u8()?,
                seed_bin: Vec::<u8>::decode(d)?,
                time_ofs: d.i32()?,
                step_size: d.u32()?,
                window: d.u32()?,
            })
        })
    }
}

env_struct! {
    /// `otp_check_t` (1,1)
    OtpCheck (1, 1) {
        token: Vec<u8>,
        timestamp: UTime,
        result: u8,
    }
}

env_struct!(Instance (1, 1) { otp: OtpInfo, last_checks: Vec<OtpCheck>, last_success: u64 });
env_struct!(Header (1, 1) { ids: BTreeSet<Vec<u8>> });
env_struct!(SetOp (1, 1) { entries: Vec<OtpInfo> });
env_struct!(CheckOp (1, 1) { id: Vec<u8>, val: Vec<u8>, token: Vec<u8> });
env_struct!(GetResultReply (1, 1) { result: OtpCheck });
env_struct!(RemoveOp (1, 1) { ids: Vec<Vec<u8>> });
env_struct!(GetOp (1, 1) { get_all: bool, ids: Vec<Vec<u8>> });
env_struct!(GetReply (1, 1) { found_entries: Vec<OtpInfo> });
env_struct!(CurrentTimeOp (1, 1) {});
env_struct!(CurrentTimeReply (1, 1) { time: UTime });

fn inst_key(id: &[u8]) -> Vec<u8> {
    [KEY_PREFIX, id].concat()
}
fn read_instance<C: ClsCtx>(c: &mut C, id: &[u8]) -> Result<Instance, Errno> {
    let b = c.omap_get_val(&inst_key(id))?;
    Instance::decode(&mut Decoder::new(&b)).eio()
}
fn write_instance<C: ClsCtx>(c: &mut C, i: &Instance) -> Result<(), Errno> {
    c.omap_set(&[(&inst_key(&i.otp.id), &enc(i)?)])
}
fn read_header<C: ClsCtx>(c: &mut C) -> Result<Header, Errno> {
    match c.omap_get_val(HEADER_KEY) {
        Err(ENOENT) | Err(ENODATA) => Ok(Header::default()),
        Err(e) => Err(e),
        Ok(b) if b.is_empty() => Ok(Header::default()),
        Ok(b) => Header::decode(&mut Decoder::new(&b)).eio(),
    }
}
fn write_header<C: ClsCtx>(c: &mut C, h: &Header) -> Result<(), Errno> {
    c.omap_set(&[(HEADER_KEY, &enc(h)?)])
}

fn trim_expired(i: &mut Instance, now: UTime) {
    let start = now
        .as_nanos()
        .saturating_sub(i.otp.step_size as u64 * 1_000_000_000);
    let n = i
        .last_checks
        .iter()
        .take_while(|c| c.timestamp.as_nanos() < start)
        .count();
    i.last_checks.drain(..n);
}

pub fn otp_set<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: SetOp = dec_op(input)?;
    let mut h = read_header(c)?;
    for entry in op.entries {
        let mut inst = match read_instance(c, &entry.id) {
            Ok(i) => i,
            Err(ENOENT) => Instance::default(),
            Err(e) => return Err(e),
        };
        inst.otp = entry;
        inst.otp.seed_bin = parse_seed(&inst.otp.seed, inst.otp.seed_type).ok_or(EINVAL)?;
        write_instance(c, &inst)?;
        h.ids.insert(inst.otp.id.clone());
    }
    write_header(c, &h)?;
    Ok(Vec::new())
}

pub fn otp_remove<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: RemoveOp = dec_op(input)?;
    let mut h = read_header(c)?;
    let mut removed = false;
    for id in &op.ids {
        if h.ids.remove(id) {
            c.omap_remove_key(&inst_key(id))?;
            removed = true;
        }
    }
    if removed {
        write_header(c, &h)?;
    }
    Ok(())
}

pub fn otp_get<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: GetOp = dec_op(input)?;
    let h = read_header(c)?;
    let ids: Vec<Vec<u8>> = if op.get_all {
        h.ids.iter().cloned().collect()
    } else {
        op.ids
    };
    let mut found = Vec::new();
    for id in ids {
        if h.ids.contains(&id) {
            found.push(read_instance(c, &id)?.otp);
        }
    }
    enc(&GetReply {
        found_entries: found,
    })
}

pub fn otp_check<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: CheckOp = dec_op(input)?;
    let mut inst = read_instance(c, &op.id)?;
    let now = c.now();
    trim_expired(&mut inst, now);
    if inst.last_checks.len() >= ATTEMPTS_PER_WINDOW {
        return Ok(()); // rate limited: nothing recorded
    }
    let ok = match totp_validate(
        &inst.otp.seed_bin,
        now.sec,
        inst.otp.step_size,
        inst.otp.time_ofs,
        inst.otp.window,
        &op.val,
    ) {
        Some(d) => {
            // classic index = displacement + current step, all in u32 (stored `last_success`
            // stays interoperable); a match at t-d therefore counts like one at t+d
            let q = now.sec.wrapping_sub(inst.otp.time_ofs as u32) / inst.otp.step_size;
            let index = d.wrapping_add(q) as u64;
            if index <= inst.last_success {
                false
            } else {
                inst.last_success = index;
                true
            }
        }
        None => false,
    };
    inst.last_checks.push(OtpCheck {
        token: op.token,
        timestamp: now,
        result: if ok { CHECK_SUCCESS } else { CHECK_FAIL },
    });
    write_instance(c, &inst)?;
    Ok(())
}

pub fn otp_get_result<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: CheckOp = dec_op(input)?;
    let mut inst = read_instance(c, &op.id)?;
    let now = c.now();
    trim_expired(&mut inst, now);
    let result = inst
        .last_checks
        .iter()
        .rev()
        .find(|k| k.token == op.token)
        .cloned()
        .unwrap_or(OtpCheck {
            token: op.token,
            timestamp: now,
            result: CHECK_UNKNOWN,
        });
    enc(&GetResultReply { result })
}

pub fn get_current_time<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let _: CurrentTimeOp = dec_op(input)?;
    enc(&CurrentTimeReply { time: c.now() })
}
