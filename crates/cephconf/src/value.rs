// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Typed option-value parsers, written from `doc/spec/rados-client/config-public-contract.md`
//! (s5, s11) and the deployment contract of the OSD data dir.
//!
//! Two boolean spellings exist because two contracts do: [`flag`] is the
//! `true/yes/1` spelling of an opt-in option (`rustyrados_rdma`, a flashstore
//! flag); [`boolean`] is the librados configuration bool, which also accepts any
//! integer (`0` is false, everything else true). Sizes come in the IEC form of
//! a librados value ([`size`]) and the plain K/M/G byte suffix of a daemon option
//! ([`size_with_units`]); they are different grammars, not two implementations.

/// A value the option's grammar does not accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueError;

impl std::fmt::Display for ValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid option value")
    }
}

impl std::error::Error for ValueError {}

/// Opt-in flag: `true`/`yes`/`1` and `false`/`no`/`0` in any ASCII case,
/// nothing else (librados' spelling of a native extension switch).
pub fn flag(value: &str) -> Result<bool, ValueError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        _ => Err(ValueError),
    }
}

fn c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn skip_space(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&b| c_space(b)).count();
    &s[n..]
}

fn sign(s: &[u8]) -> (bool, &[u8]) {
    match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    }
}

fn digits(s: &[u8]) -> (&[u8], &[u8]) {
    let n = s.iter().take_while(|b| b.is_ascii_digit()).count();
    s.split_at(n)
}

fn magnitude(d: &[u8]) -> Option<u64> {
    d.iter().try_fold(0u64, |acc, &b| {
        acc.checked_mul(10)?.checked_add(u64::from(b - b'0'))
    })
}

// Whole-string signed base-10 parse: leading C whitespace, one optional sign,
// at least one digit, nothing after, value within i64.
fn whole_i64(s: &[u8]) -> Result<i64, ValueError> {
    let (neg, rest) = sign(skip_space(s));
    let (d, tail) = digits(rest);
    if d.is_empty() || !tail.is_empty() {
        return Err(ValueError);
    }
    let m = magnitude(d).ok_or(ValueError)?;
    if neg {
        0i64.checked_sub_unsigned(m).ok_or(ValueError)
    } else {
        i64::try_from(m).map_err(|_| ValueError)
    }
}

/// librados configuration bool: `true`/`false` (any ASCII case) or a whole
/// integer in `i32` range, where `0` is false and everything else true.
pub fn boolean(s: &[u8]) -> Result<bool, ValueError> {
    if s.eq_ignore_ascii_case(b"true") {
        return Ok(true);
    }
    if s.eq_ignore_ascii_case(b"false") {
        return Ok(false);
    }
    Ok(i32::try_from(whole_i64(s)?).map_err(|_| ValueError)? != 0)
}

// Decimal (SI) coefficient split: if any byte lies outside [0-9+-], the LAST byte is
// the unit. K..E strip it; 'B' is accepted but not stripped (the number parse then
// fails on it); anything else is rejected.
fn si_split(s: &[u8]) -> Result<(&[u8], u64), ValueError> {
    let Some((&last, init)) = s.split_last() else {
        return Err(ValueError);
    };
    if s.iter().all(|b| matches!(b, b'0'..=b'9' | b'+' | b'-')) {
        return Ok((s, 1));
    }
    let exp = match last {
        b'K' => 3,
        b'M' => 6,
        b'G' => 9,
        b'T' => 12,
        b'P' => 15,
        b'E' => 18,
        b'B' => return Ok((s, 1)),
        _ => return Err(ValueError),
    };
    Ok((init, 10u64.pow(exp)))
}

/// Signed decimal integer with an optional SI suffix (`10K` = 10000).
pub fn integer(s: &[u8]) -> Result<i64, ValueError> {
    let (num, coef) = si_split(s)?;
    let v = whole_i64(num)?;
    let coef = i64::try_from(coef).map_err(|_| ValueError)?;
    v.checked_mul(coef).ok_or(ValueError)
}

/// Non-negative decimal integer with an optional SI suffix.
pub fn unsigned(s: &[u8]) -> Result<u64, ValueError> {
    let (num, coef) = si_split(s)?;
    let v = u64::try_from(whole_i64(num)?).map_err(|_| ValueError)?;
    v.checked_mul(coef).ok_or(ValueError)
}

/// IEC size: plain bytes, or K/M/G/T/P/E with an optional `i`/`B`/`iB` suffix
/// (powers of 1024). Negative values are rejected.
pub fn size(s: &[u8]) -> Result<u64, ValueError> {
    let n = s
        .iter()
        .take_while(|b| matches!(b, b'0'..=b'9' | b'+' | b'-'))
        .count();
    let (num, mut unit) = s.split_at(n);
    if unit.len() > 1 && unit.ends_with(b"B") {
        unit = &unit[..unit.len() - 1];
    }
    let shift: u32 = match unit {
        [] => 0,
        [c] | [c, b'i'] => match c {
            b'K' => 10,
            b'M' => 20,
            b'G' => 30,
            b'T' => 40,
            b'P' => 50,
            b'E' => 60,
            b'B' if unit.len() == 1 => 0,
            _ => return Err(ValueError),
        },
        _ => return Err(ValueError),
    };
    let v = u64::try_from(whole_i64(num)?).map_err(|_| ValueError)?;
    if v > u64::MAX >> shift {
        return Err(ValueError);
    }
    Ok(v << shift)
}

/// Plain byte size with a binary `K`/`M`/`G`/`T` suffix (any ASCII case);
/// `None` for anything else. The deployment contract's `parse_size`.
pub fn size_with_units(s: &str) -> Option<u64> {
    let s = s.trim();
    let (n, m) = match s.chars().last()? {
        'k' | 'K' => (&s[..s.len() - 1], 1u64 << 10),
        'm' | 'M' => (&s[..s.len() - 1], 1 << 20),
        'g' | 'G' => (&s[..s.len() - 1], 1 << 30),
        't' | 'T' => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    n.trim().parse::<u64>().ok()?.checked_mul(m)
}

fn unit_secs(u: &[u8]) -> Option<u64> {
    Some(match u {
        b"" | b"s" | b"sec" | b"second" | b"seconds" => 1,
        b"m" | b"min" | b"minute" | b"minutes" => 60,
        b"h" | b"hr" | b"hour" | b"hours" => 3600,
        b"d" | b"day" | b"days" => 86_400,
        b"w" | b"wk" | b"week" | b"weeks" => 604_800,
        b"mo" | b"month" | b"months" => 2_592_000,
        b"y" | b"yr" | b"year" | b"years" => 31_536_000,
        _ => return None,
    })
}

// Nonnegative integer segments, each optionally followed by an alphabetic unit.
// Whitespace is accepted between segments and at either end. A bare segment
// must end the input; adjacent bare numbers separated only by whitespace fail.
/// Duration in seconds: `5`, `5s`, `2m`, `1h30m`, `1 h 30 m`, `1d`, `1w`,
/// `1mo`, `1y` (the time suffix grammar of a librados `secs` option).
pub fn seconds(s: &[u8]) -> Result<u64, ValueError> {
    let mut rest = s;
    let mut total = 0u64;
    loop {
        rest = skip_space(rest);
        if rest.is_empty() {
            break;
        }
        let (d, r) = digits(rest);
        if d.is_empty() {
            return Err(ValueError);
        }
        let n = magnitude(d).ok_or(ValueError)?;
        let r = skip_space(r);
        let u = r.iter().take_while(|b| b.is_ascii_alphabetic()).count();
        let (unit, r) = r.split_at(u);
        if unit.is_empty() && !r.is_empty() {
            return Err(ValueError);
        }
        let mult = unit_secs(unit).ok_or(ValueError)?;
        total = n
            .checked_mul(mult)
            .and_then(|x| total.checked_add(x))
            .ok_or(ValueError)?;
        rest = r;
    }
    i64::try_from(total).map_err(|_| ValueError)?;
    Ok(total)
}

// stoull semantics: leading whitespace, optional sign, digits, trailing text ignored.
// A '-' wraps modulo 2^64; the result is stored as a signed 64-bit count.
/// Millisecond count with `stoull` semantics: leading whitespace, optional sign,
/// digits, trailing text (a `ms` suffix) ignored; a `-` wraps modulo 2^64.
pub fn milliseconds(s: &[u8]) -> Result<i64, ValueError> {
    let (neg, rest) = sign(skip_space(s));
    let (d, _) = digits(rest);
    if d.is_empty() {
        return Err(ValueError);
    }
    let m = magnitude(d).ok_or(ValueError)?;
    let u = if neg { m.wrapping_neg() } else { m };
    Ok(u as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok<T: PartialEq + std::fmt::Debug>(got: Result<T, ValueError>, want: T) {
        assert_eq!(got, Ok(want));
    }

    #[test]
    fn flag_is_the_opt_in_spelling() {
        for (text, want) in [
            ("true", true),
            ("TRUE", true),
            ("yes", true),
            ("1", true),
            ("false", false),
            ("No", false),
            ("0", false),
        ] {
            ok(flag(text), want);
        }
        for text in ["", "2", "on", "tru", " 1", "1 "] {
            assert_eq!(flag(text), Err(ValueError), "{text:?}");
        }
    }

    #[test]
    fn librados_bool_keeps_its_integer_spelling() {
        for (text, want) in [
            ("true", true),
            ("False", false),
            ("1", true),
            ("2", true),
            (" 1", true),
            ("+1", true),
            ("0", false),
            ("-0", false),
            ("2147483647", true),
            ("-2147483648", true),
        ] {
            ok(boolean(text.as_bytes()), want);
        }
        for text in [
            "",
            "yes",
            "no",
            "on",
            "0x1",
            "1.0",
            "1 ",
            "2147483648",
            "3000000000",
            "tru",
        ] {
            assert_eq!(boolean(text.as_bytes()), Err(ValueError), "{text:?}");
        }
    }

    #[test]
    fn integers_take_si_suffixes() {
        ok(integer(b"10K"), 10_000);
        ok(integer(b"-5M"), -5_000_000);
        ok(integer(b"+7"), 7);
        ok(integer(b" 1K"), 1000);
        ok(integer(b"-0"), 0);
        ok(integer(b"9223372036854775807"), i64::MAX);
        ok(unsigned(b"18E"), 18_000_000_000_000_000_000);
        ok(unsigned(b"-0"), 0);
        for text in [
            b"".as_slice(),
            b"1B",
            b"1k",
            b"1KB",
            b"1Ki",
            b"1KiB",
            b" 1",
            b"1 ",
        ] {
            assert_eq!(integer(text), Err(ValueError), "{text:?}");
        }
        for text in [b"".as_slice(), b"-1", b"1.5", b"9223372036854775808"] {
            assert_eq!(unsigned(text), Err(ValueError), "{text:?}");
        }
    }

    #[test]
    fn iec_sizes_are_exact() {
        for (text, want) in [
            ("0", 0),
            ("1", 1),
            ("1B", 1),
            ("1BB", 1),
            ("1K", 1024),
            ("1KB", 1024),
            ("1Ki", 1024),
            ("1KiB", 1024),
            ("100M", 104_857_600),
            ("+1K", 1024),
            ("-0", 0),
            ("15E", 17_293_822_569_102_704_640),
        ] {
            ok(size(text.as_bytes()), want);
        }
        for text in [
            "", "K", "1k", "1kb", "1m", "1iB", "1Bi", "1KK", "1KiBB", "1.5M", " 1", "1 K", "-1",
            "-1K", "16E", "1X",
        ] {
            assert_eq!(size(text.as_bytes()), Err(ValueError), "{text:?}");
        }
    }

    #[test]
    fn daemon_sizes_take_a_plain_binary_suffix() {
        for (text, want) in [
            ("4096", 4096),
            ("4K", 4096),
            ("4k", 4096),
            ("2M", 2 << 20),
            ("1G", 1 << 30),
            ("1T", 1 << 40),
            (" 8K ", 8192),
        ] {
            assert_eq!(size_with_units(text), Some(want), "{text:?}");
        }
        for text in ["", "K", "1.5M", "-1", "1X"] {
            assert_eq!(size_with_units(text), None, "{text:?}");
        }
    }

    #[test]
    fn durations_are_segments_of_seconds() {
        for (text, want) in [
            ("", 0),
            ("5", 5),
            ("5s", 5),
            ("2m", 120),
            ("1h30m", 5400),
            ("1 h 30 m", 5400),
            ("1hour", 3600),
            ("1d", 86_400),
            ("1w", 604_800),
            ("1mo", 2_592_000),
            ("1y", 31_536_000),
            ("007", 7),
            ("5s3", 8),
        ] {
            ok(seconds(text.as_bytes()), want);
        }
        for text in [
            "5 6",
            "1.5",
            "-1",
            "+1",
            "5S",
            "5x",
            "s",
            "9223372036854775808",
            "9223372036854775807y",
        ] {
            assert_eq!(seconds(text.as_bytes()), Err(ValueError), "{text:?}");
        }
        ok(milliseconds(b"12ms"), 12);
        ok(milliseconds(b"-5"), -5);
        ok(milliseconds(b"18446744073709551615"), -1);
        for text in ["", " ", "x", "abc1", "-", "+"] {
            assert_eq!(milliseconds(text.as_bytes()), Err(ValueError), "{text:?}");
        }
    }
}
