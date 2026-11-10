// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Ceph option values (spec osd-lifecycle.md 2.9): every value of a Ceph option is parsed by the option's type,
//! range/enum checked and stored in its normalized text (`8M` size -> `8388608`, `0.97` float -> `0.970000`). The
//! schema is the pinned version's option table `data/ceph-options.txt` (`scripts/gen-ceph-options.sh`), flags
//! included: they decide whether a runtime change is allowed (spec osd-lifecycle.md 9.2).
use std::collections::HashMap;
use std::sync::OnceLock;

/// Option schema table: `name TAB type TAB min TAB max TAB enum TAB flags` (`-` = absent, flags `,`-joined), `#`
/// header line first.
const CEPH_OPTIONS: &str = include_str!("../data/ceph-options.txt");

/// Value type of a Ceph option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bool,
    Int,
    Uint,
    Float,
    Str,
    Size,
    Secs,
    Millisecs,
    /// `addr`, `addrvec`, `uuid`: stored as given.
    Opaque,
}

/// Schema of one option.
#[derive(Clone, Debug)]
pub struct Schema {
    pub kind: Kind,
    min: Option<f64>,
    max: Option<f64>,
    /// Allowed values of a `str` option (empty = any).
    allowed: Vec<&'static str>,
    /// `Option::flag_t` names of the pinned schema.
    flags: Vec<&'static str>,
}

impl Schema {
    /// The pinned schema's `flag` on this option.
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.contains(&flag)
    }

    /// Classic's `Option::can_update_at_runtime()` in own words (spec osd-lifecycle.md 9.2): an option may change at
    /// runtime when it carries the `runtime` flag, or when it is a number-like type (`bool`, `int`, `uint`, `float`,
    /// `size`, `secs`, `millisecs`) and is no mgr module option; either way `startup`, `cluster_create` and `create`
    /// forbid it. `mgr` options come from mgr modules only, so no option of the pinned yaml schema carries it.
    pub fn runtime_changeable(&self) -> bool {
        let number_like = matches!(
            self.kind,
            Kind::Bool
                | Kind::Int
                | Kind::Uint
                | Kind::Float
                | Kind::Size
                | Kind::Secs
                | Kind::Millisecs
        );
        (self.has_flag("runtime") || (!self.has_flag("mgr") && number_like))
            && !self.has_flag("startup")
            && !self.has_flag("cluster_create")
            && !self.has_flag("create")
    }
}

fn table() -> &'static HashMap<&'static str, Schema> {
    static T: OnceLock<HashMap<&'static str, Schema>> = OnceLock::new();
    T.get_or_init(|| {
        CEPH_OPTIONS
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| {
                let f: Vec<&'static str> = l.split('\t').collect();
                let [name, ty, min, max, en, fl] = f[..] else {
                    return None;
                };
                let kind = match ty {
                    "bool" => Kind::Bool,
                    "int" => Kind::Int,
                    "uint" => Kind::Uint,
                    "float" => Kind::Float,
                    "str" => Kind::Str,
                    "size" => Kind::Size,
                    "secs" => Kind::Secs,
                    "millisecs" => Kind::Millisecs,
                    _ => Kind::Opaque,
                };
                let num = |s: &str| (s != "-").then(|| s.parse::<f64>().ok()).flatten();
                let allowed = if en == "-" {
                    Vec::new()
                } else {
                    en.split('|').collect()
                };
                let flags = if fl == "-" {
                    Vec::new()
                } else {
                    fl.split(',').collect()
                };
                Some((
                    name,
                    Schema {
                        kind,
                        min: num(min),
                        max: num(max),
                        allowed,
                        flags,
                    },
                ))
            })
            .collect()
    })
}

/// Every option name of the pinned schema.
#[cfg(test)]
pub fn names() -> impl Iterator<Item = &'static str> {
    CEPH_OPTIONS
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split('\t').next())
}

/// Schema of the Ceph option `name` (already normalized: `_` separators), `None` for a name Ceph does not define.
pub fn schema(name: &str) -> Option<&'static Schema> {
    table().get(name)
}

/// The normalized text of `raw` for option `name`, or the reason it is invalid. A name without schema (`flashstore_*`)
/// keeps `raw` unchanged.
pub fn normalize(name: &str, raw: &str) -> Result<String, String> {
    let Some(s) = schema(name) else {
        return Ok(raw.to_owned());
    };
    let t = raw.trim();
    let (text, num) = match s.kind {
        Kind::Str => {
            if !s.allowed.is_empty() && !s.allowed.contains(&raw) {
                return Err(format!(
                    "'{raw}' is not one of the permitted values: {}",
                    s.allowed.join(", ")
                ));
            }
            return Ok(raw.to_owned());
        }
        Kind::Opaque => return Ok(raw.to_owned()),
        Kind::Bool => {
            let b = if t.eq_ignore_ascii_case("true") {
                true
            } else if t.eq_ignore_ascii_case("false") {
                false
            } else {
                int(t)? != 0
            };
            return Ok(b.to_string());
        }
        Kind::Float => {
            let f: f64 = t
                .parse()
                .map_err(|_| format!("expected a floating point number, got '{raw}'"))?;
            (format!("{f:.6}"), f)
        }
        Kind::Int => {
            let v = si(t)?;
            let v = i64::try_from(v).map_err(|_| format!("value '{raw}' out of range"))?;
            (v.to_string(), v as f64)
        }
        Kind::Uint => {
            let v = si(t)?;
            if v < 0 {
                return Err(format!("value '{raw}' must not be negative"));
            }
            let v = u64::try_from(v).map_err(|_| format!("value '{raw}' out of range"))?;
            (v.to_string(), v as f64)
        }
        Kind::Size => {
            let v = iec(t)?;
            (v.to_string(), v as f64)
        }
        Kind::Secs => {
            let v = timespan(t)?;
            (v.to_string(), v as f64)
        }
        Kind::Millisecs => {
            let v: u64 = t
                .parse()
                .map_err(|_| format!("expected milliseconds (unsigned integer), got '{raw}'"))?;
            (v.to_string(), v as f64)
        }
    };
    if let Some(m) = s.min
        && num < m
    {
        return Err(format!("Value '{text}' is below minimum {m}"));
    }
    if let Some(m) = s.max
        && num > m
    {
        return Err(format!("Value '{text}' exceeds maximum {m}"));
    }
    Ok(text)
}

/// A value of the `size` grammar (surrounding whitespace ignored) in bytes.
pub fn size(s: &str) -> Result<u64, String> {
    iec(s.trim())
}

/// `[+-]digits`, nothing else.
fn int(s: &str) -> Result<i128, String> {
    let d = s.strip_prefix(['+', '-']).unwrap_or(s);
    if d.is_empty() || !d.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("expected an integer, got '{s}'"));
    }
    s.parse::<i128>()
        .map_err(|_| format!("value '{s}' out of range"))
}

/// `int`/`uint`: an integer with an optional decimal unit letter (K = 10^3 .. E = 10^18).
fn si(s: &str) -> Result<i128, String> {
    if s.is_empty() {
        return Err("value not specified".into());
    }
    let (n, exp) = match s.as_bytes()[s.len() - 1] {
        b'K' => (&s[..s.len() - 1], 3),
        b'M' => (&s[..s.len() - 1], 6),
        b'G' => (&s[..s.len() - 1], 9),
        b'T' => (&s[..s.len() - 1], 12),
        b'P' => (&s[..s.len() - 1], 15),
        b'E' => (&s[..s.len() - 1], 18),
        _ => (s, 0),
    };
    if n.bytes().any(|c| !matches!(c, b'0'..=b'9' | b'+' | b'-')) {
        return Err(format!("unit prefix not recognized in '{s}'"));
    }
    let v = int(n)?;
    v.checked_mul(10i128.pow(exp))
        .filter(|v| (i64::MIN as i128..=u64::MAX as i128).contains(v))
        .ok_or_else(|| format!("value '{s}' out of range"))
}

/// `size`: a non-negative integer with an optional binary unit (`K`/`Ki`/`KB`/`KiB` = 2^10 .. `E` = 2^60, `B` = 1).
fn iec(s: &str) -> Result<u64, String> {
    if s.is_empty() {
        return Err("value not specified".into());
    }
    let split = s
        .find(|c: char| !matches!(c, '0'..='9' | '+' | '-'))
        .unwrap_or(s.len());
    let (n, mut unit) = s.split_at(split);
    if unit.len() > 1 && unit.ends_with('B') {
        unit = &unit[..unit.len() - 1];
    }
    let shift = match unit {
        "" | "B" => 0,
        _ if unit.len() > 2 || (unit.len() == 2 && !unit.ends_with('i')) => {
            return Err(format!("illegal unit '{unit}' in '{s}'"));
        }
        _ => match unit.as_bytes()[0] {
            b'K' => 10,
            b'M' => 20,
            b'G' => 30,
            b'T' => 40,
            b'P' => 50,
            b'E' => 60,
            _ => return Err(format!("unit prefix not recognized in '{s}'")),
        },
    };
    let v = int(n)?;
    if v < 0 {
        return Err(format!("value '{s}' must not be negative"));
    }
    v.checked_mul(1i128 << shift)
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| format!("value '{s}' out of range"))
}

/// `secs`: summed `<digits>[spaces]<unit>` groups; a group without unit only at the end (plain seconds).
fn timespan(s: &str) -> Result<u64, String> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut total: u64 = 0;
    loop {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i == b.len() {
            return Ok(total);
        }
        let d0 = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if d0 == i {
            return Err(format!("expected a digit in '{s}'"));
        }
        let n: u64 = s[d0..i]
            .parse()
            .map_err(|_| format!("value '{s}' out of range"))?;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let u0 = i;
        while i < b.len() && b[i].is_ascii_alphabetic() {
            i += 1;
        }
        let mul = match &s[u0..i] {
            "" if i < b.len() => return Err(format!("unexpected trailing '{}'", &s[i..])),
            "" | "s" | "sec" | "second" | "seconds" => 1,
            "m" | "min" | "minute" | "minutes" => 60,
            "h" | "hr" | "hour" | "hours" => 3600,
            "d" | "day" | "days" => 86_400,
            "w" | "wk" | "week" | "weeks" => 7 * 86_400,
            "mo" | "month" | "months" => 30 * 86_400,
            "y" | "yr" | "year" | "years" => 365 * 86_400,
            u => return Err(format!("unrecognized unit '{u}' in '{s}'")),
        };
        total = n
            .checked_mul(mul)
            .and_then(|v| total.checked_add(v))
            .filter(|v| i64::try_from(*v).is_ok())
            .ok_or_else(|| format!("value '{s}' out of range"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(name: &str, raw: &str) -> String {
        normalize(name, raw).unwrap_or_else(|e| panic!("{name}={raw:?}: {e}"))
    }

    fn bad(name: &str, raw: &str) {
        assert!(normalize(name, raw).is_err(), "{name}={raw:?} accepted");
    }

    #[test]
    fn schema_types_from_the_table() {
        assert_eq!(schema("osd_memory_target").unwrap().kind, Kind::Size);
        assert_eq!(schema("osd_heartbeat_grace").unwrap().kind, Kind::Int);
        assert_eq!(schema("mon_down_added_grace").unwrap().kind, Kind::Secs);
        assert_eq!(schema("osd_max_backfills").unwrap().kind, Kind::Uint);
        assert_eq!(schema("osd_failsafe_full_ratio").unwrap().kind, Kind::Float);
        assert_eq!(schema("osd_scrub_auto_repair").unwrap().kind, Kind::Bool);
        assert_eq!(schema("mon_osd_down_out_interval").unwrap().kind, Kind::Int);
        assert_eq!(schema("public_addr").unwrap().kind, Kind::Opaque);
        assert!(schema("flashstore_port_name").is_none());
    }

    /// Classic's `Option::can_update_at_runtime()` from the schema flags (spec osd-lifecycle.md 9.2): the `runtime`
    /// flag, or a number-like type without `mgr`; `startup`, `cluster_create` and `create` always forbid it.
    #[test]
    fn runtime_changeable_follows_the_option_flags() {
        let rc = |n: &str| schema(n).unwrap().runtime_changeable();
        // the `runtime` flag, whatever the type
        assert!(rc("osd_max_backfills"), "uint + runtime");
        assert!(rc("osd_memory_target"), "size + runtime");
        assert!(rc("auth_cluster_required"), "str + runtime");
        // number-like without any flag
        assert!(rc("osd_scrub_min_interval"), "float");
        assert!(rc("osd_op_history_size"), "uint");
        assert!(rc("ms_crc_data"), "bool");
        assert!(rc("mon_down_added_grace"), "secs");
        // every other type needs the runtime flag
        assert!(!rc("bluestore_allocator"), "str");
        assert!(!rc("ms_cluster_mode"), "str + startup");
        assert!(!rc("public_addr"), "addr + startup");
        // startup / create / cluster_create win over a number-like type
        assert!(!rc("bluestore_volume_selection_reserved"), "int + startup");
        assert!(!rc("bluestore_block_size"), "size + create");
        assert!(
            !rc("mon_cache_target_full_warn_ratio"),
            "float + cluster_create"
        );
        // no option of the pinned yaml schema is a mgr module option
        assert!(names().all(|n| !schema(n).unwrap().has_flag("mgr")));
    }

    /// size: binary units in every spelling; the YAML spelling `8_M`, fractions and junk are invalid.
    #[test]
    fn size_values() {
        let k = "osd_client_message_size_cap";
        for (raw, want) in [
            ("8M", 8u64 << 20),
            ("8Mi", 8 << 20),
            ("8MiB", 8 << 20),
            ("8MB", 8 << 20),
            ("4K", 4096),
            ("2G", 2 << 30),
            ("1T", 1u64 << 40),
            ("1E", 1u64 << 60),
            ("512B", 512),
            ("1234", 1234),
            (" 64M ", 64 << 20),
        ] {
            assert_eq!(ok(k, raw), want.to_string(), "{raw}");
        }
        for raw in [
            "8_M", "1.5G", "8m", "8Bi", "8MiBB", "8 M", "-1", "", "x", "16E", "8Kx",
        ] {
            bad(k, raw);
        }
        // minimum 896 MiB
        bad("osd_memory_target", "512M");
        assert_eq!(ok("osd_memory_target", "4G"), (4u64 << 30).to_string());
    }

    /// int/uint: decimal units only, no fractions; uint rejects negatives; range from the schema.
    #[test]
    fn integer_values() {
        assert_eq!(ok("osd_heartbeat_grace", "20"), "20");
        assert_eq!(ok("osd_heartbeat_grace", "2K"), "2000");
        assert_eq!(ok("osd_max_backfills", "3"), "3");
        assert_eq!(ok("osd_max_backfills", "1M"), "1000000");
        bad("osd_max_backfills", "-1");
        bad("osd_max_backfills", "1.5");
        bad("osd_max_backfills", "2Ki");
        bad("osd_max_backfills", "two");
        bad("osd_max_backfills", "");
        bad("osd_heartbeat_grace", "20s");
        // int with min 1, max 60
        bad("osd_heartbeat_interval", "0");
        bad("osd_heartbeat_interval", "61");
        assert_eq!(ok("osd_heartbeat_interval", "+10"), "10");
    }

    #[test]
    fn float_values() {
        assert_eq!(ok("osd_failsafe_full_ratio", "0.97"), "0.970000");
        assert_eq!(ok("osd_failsafe_full_ratio", "97"), "97.000000");
        assert_eq!(ok("osd_failsafe_full_ratio", "1e-1"), "0.100000");
        bad("osd_deep_scrub_interval_cv", "0.5"); // max 0.4
        bad("osd_failsafe_full_ratio", "0.97x");
        bad("osd_failsafe_full_ratio", "");
    }

    #[test]
    fn bool_values() {
        for (raw, want) in [
            ("true", "true"),
            ("TRUE", "true"),
            ("False", "false"),
            ("1", "true"),
            ("0", "false"),
            ("7", "true"),
        ] {
            assert_eq!(ok("osd_scrub_auto_repair", raw), want, "{raw}");
        }
        for raw in ["yes", "on", "", "1.0"] {
            bad("osd_scrub_auto_repair", raw);
        }
    }

    #[test]
    fn secs_values() {
        let k = "mon_down_added_grace";
        assert_eq!(schema(k).unwrap().kind, Kind::Secs);
        for (raw, want) in [
            ("30", 30),
            ("30s", 30),
            ("2m", 120),
            ("1h 30min", 5400),
            ("1d2h", 93_600),
            ("1 week", 604_800),
            ("1mo", 2_592_000),
            ("1y", 31_536_000),
            ("", 0),
        ] {
            assert_eq!(ok(k, raw), want.to_string(), "{raw}");
        }
        for raw in ["1.5h", "h", "10 parsecs", "30 x", "-5"] {
            bad(k, raw);
        }
    }

    #[test]
    fn millisecs_and_enum_values() {
        let ms = table()
            .iter()
            .find(|(_, s)| s.kind == Kind::Millisecs)
            .map(|(n, _)| *n)
            .unwrap();
        assert_eq!(ok(ms, "250"), "250");
        bad(ms, "250ms");
        bad(ms, "-1");
        assert_eq!(ok("osd_op_queue", "wpq"), "wpq");
        let e = normalize("osd_op_queue", "fifo").unwrap_err();
        assert!(e.contains("permitted values: wpq, mclock_scheduler"), "{e}");
        assert_eq!(ok("bluestore_compression_algorithm", ""), "");
        assert_eq!(
            ok("flashstore_whatever", " 8_M "),
            " 8_M ",
            "no schema: as given"
        );
    }
}
