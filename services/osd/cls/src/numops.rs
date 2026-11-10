// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `numops` (spec/cls_numops.md): add/mul on decimal-text omap values.

use crate::ctx::ClsCtx;
use crate::errno::*;
use denc::{Decode, Decoder};

/// C `strtod` (C locale): returns the value and the number of bytes consumed (0 = no conversion).
pub fn strtod(s: &[u8]) -> (f64, usize) {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let neg = matches!(s.get(i), Some(b'-'));
    if matches!(s.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let sign = |v: f64| if neg { -v } else { v };
    let rest = &s[i..];
    let starts = |p: &[u8]| rest.len() >= p.len() && rest[..p.len()].eq_ignore_ascii_case(p);
    if starts(b"infinity") {
        return (sign(f64::INFINITY), i + 8);
    }
    if starts(b"inf") {
        return (sign(f64::INFINITY), i + 3);
    }
    if starts(b"nan") {
        let mut n = i + 3;
        if s.get(n) == Some(&b'(') {
            let mut j = n + 1;
            while j < s.len() && (s[j].is_ascii_alphanumeric() || s[j] == b'_') {
                j += 1;
            }
            if s.get(j) == Some(&b')') {
                n = j + 1;
            }
        }
        return (sign(f64::NAN), n);
    }
    if rest.len() >= 3
        && rest[0] == b'0'
        && rest[1].eq_ignore_ascii_case(&b'x')
        && (rest[2].is_ascii_hexdigit()
            || (rest[2] == b'.' && rest.get(3).is_some_and(u8::is_ascii_hexdigit)))
    {
        return hex_float(s, i + 2, neg);
    }
    // decimal
    let digits = |from: usize| s[from..].iter().take_while(|c| c.is_ascii_digit()).count();
    let int = digits(i);
    let mut j = i + int;
    let mut frac = 0;
    if s.get(j) == Some(&b'.') {
        frac = digits(j + 1);
        if int > 0 || frac > 0 {
            j += 1 + frac;
        }
    }
    if int == 0 && frac == 0 {
        return (0.0, 0);
    }
    if matches!(s.get(j), Some(b'e' | b'E')) {
        let mut k = j + 1;
        if matches!(s.get(k), Some(b'+' | b'-')) {
            k += 1;
        }
        let e = digits(k);
        if e > 0 {
            j = k + e;
        }
    }
    // the matched text is ASCII; Rust's parser is correctly rounded like glibc
    let txt = std::str::from_utf8(&s[i..j]).unwrap_or("0");
    (sign(txt.parse::<f64>().unwrap_or(0.0)), j)
}

fn hex_float(s: &[u8], mut j: usize, neg: bool) -> (f64, usize) {
    // Keep sixteen significant hex digits and a sticky bit. Applying the exponent only after
    // rounding avoids intermediate overflow/underflow for finite, arbitrarily long inputs.
    let mut mant = 0u64;
    let mut kept = 0;
    let mut sticky = false;
    let mut exp = 0i64;
    let mut digit = |c: u8, fractional: bool| {
        let v = (c as char).to_digit(16).unwrap_or(0) as u64;
        if fractional {
            exp = exp.saturating_sub(4);
        }
        if kept == 0 && v == 0 {
            return;
        }
        if kept < 16 {
            mant = (mant << 4) | v;
            kept += 1;
        } else {
            exp = exp.saturating_add(4);
            sticky |= v != 0;
        }
    };
    while j < s.len() && s[j].is_ascii_hexdigit() {
        digit(s[j], false);
        j += 1;
    }
    if s.get(j) == Some(&b'.') {
        j += 1;
        while j < s.len() && s[j].is_ascii_hexdigit() {
            digit(s[j], true);
            j += 1;
        }
    }
    if matches!(s.get(j), Some(b'p' | b'P')) {
        let mut k = j + 1;
        let eneg = s.get(k) == Some(&b'-');
        if matches!(s.get(k), Some(b'+' | b'-')) {
            k += 1;
        }
        let st = k;
        let mut e = 0i64;
        while k < s.len() && s[k].is_ascii_digit() {
            e = e.saturating_mul(10).saturating_add((s[k] - b'0') as i64);
            k += 1;
        }
        if k > st {
            exp = exp.saturating_add(if eneg { -e } else { e });
            j = k;
        }
    }
    let r = hex_value(mant, exp, sticky);
    (if neg { -r } else { r }, j)
}

/// Round `mant * 2^exp` once to binary64; sticky records nonzero discarded low digits.
fn hex_value(mant: u64, exp: i64, sticky: bool) -> f64 {
    if mant == 0 {
        return 0.0;
    }
    let top = 63 - mant.leading_zeros() as i64;
    let highest = exp.saturating_add(top);
    if highest > 1023 {
        return f64::INFINITY;
    }
    if highest < -1075 {
        return 0.0;
    }
    // Normal values keep 53 bits; subnormals have a fixed quantum of 2^-1074.
    let shift = (top - 52).max(-1074 - exp).max(0) as u32;
    let mut rounded = if shift == 0 {
        mant
    } else {
        let q = if shift == 64 { 0 } else { mant >> shift };
        let half = 1u64 << (shift - 1);
        let remainder = mant & (half | (half - 1));
        q + u64::from(remainder > half || (remainder == half && (sticky || q & 1 != 0)))
    };
    if rounded == 0 {
        return 0.0;
    }
    let scale = exp + i64::from(shift);
    let top = 63 - rounded.leading_zeros() as i64;
    let highest = scale + top;
    if highest > 1023 {
        return f64::INFINITY;
    }
    if highest < -1022 {
        return f64::from_bits(rounded << (scale + 1074));
    }
    if top > 52 {
        rounded >>= top - 52;
    } else {
        rounded <<= 52 - top;
    }
    f64::from_bits(((highest + 1023) as u64) << 52 | (rounded & ((1u64 << 52) - 1)))
}

/// Whole-string strtod as numops uses it: `None` if text remains after the parse.
fn parse_full(b: &[u8]) -> Option<f64> {
    let b = &b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())];
    let (v, n) = strtod(b);
    (n == b.len()).then_some(v)
}

/// printf `%.10g`.
pub fn fmt_g10(v: f64) -> String {
    if v.is_nan() {
        return if v.is_sign_negative() { "-nan" } else { "nan" }.into();
    }
    if v.is_infinite() {
        return if v < 0.0 { "-inf" } else { "inf" }.into();
    }
    if v == 0.0 {
        return if v.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let sci = format!("{:.9e}", v.abs());
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let x: i32 = exp.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let trim = |s: &str| s.trim_end_matches('0').to_string();
    let sign = if v < 0.0 { "-" } else { "" };
    if !(-4..10).contains(&x) {
        let d = trim(&digits[1..]);
        let m = if d.is_empty() {
            digits[..1].to_string()
        } else {
            format!("{}.{}", &digits[..1], d)
        };
        return format!("{sign}{m}e{}{:02}", if x < 0 { '-' } else { '+' }, x.abs());
    }
    if x >= 0 {
        let x = x as usize;
        let frac = trim(&digits[x + 1..]);
        if frac.is_empty() {
            format!("{sign}{}", &digits[..=x])
        } else {
            format!("{sign}{}.{frac}", &digits[..=x])
        }
    } else {
        let frac = trim(&digits);
        format!("{sign}0.{}{frac}", "0".repeat((-x - 1) as usize))
    }
}

fn op<C: ClsCtx>(c: &mut C, input: &[u8], f: fn(f64, f64) -> f64) -> Result<Vec<u8>, Errno> {
    let mut d = Decoder::new(input);
    let key = Vec::<u8>::decode(&mut d).inval()?;
    let diff = Vec::<u8>::decode(&mut d).inval()?;
    let diff = parse_full(&diff).ok_or(EINVAL)?;
    let cur = match c.omap_get_val(&key) {
        Ok(b) if b.is_empty() => 0.0,
        Err(ENODATA) | Err(ENOENT) => 0.0,
        Err(e) => return Err(e),
        Ok(b) => parse_full(&b).ok_or(EBADMSG)?,
    };
    let text = fmt_g10(f(cur, diff));
    c.omap_set(&[(key.as_slice(), text.as_bytes())])?;
    Ok(Vec::new())
}

pub fn add<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    op(c, input, |a, b| a + b)
}
pub fn mul<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    op(c, input, |a, b| a * b)
}
