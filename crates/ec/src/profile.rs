// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! EC profile parser (`erasure_code_profiles` entry: string map, ec.md 2). Integer keys follow the classic grammar
//! ([`parse_int`], spec ec-parity.md 1); `stripe_unit` is mon-only and never read here.

use crate::clay::ClayProfile;
use crate::lrc::LrcSpec;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plugin {
    Isa,
    Jerasure,
    Lrc,
    Shec,
    Clay,
    Unknown(String),
}

impl Plugin {
    pub fn name(&self) -> &str {
        match self {
            Plugin::Isa => "isa",
            Plugin::Jerasure => "jerasure",
            Plugin::Lrc => "lrc",
            Plugin::Shec => "shec",
            Plugin::Clay => "clay",
            Plugin::Unknown(s) => s,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError(pub String);

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ProfileError {}

fn err<T>(s: impl Into<String>) -> Result<T, ProfileError> {
    Err(ProfileError(s.into()))
}

/// Parsed profile. For unknown plugins `k`/`m` are 0 unless given and the
/// plugin specific keys are not interpreted: the gate rejects them by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcProfile {
    pub plugin: Plugin,
    pub technique: String,
    pub k: u32,
    pub m: u32,
    pub w: u32,
    /// shec durability estimator `c` (0 for other plugins).
    pub c: u32,
    /// `mapping` string ("D" = data position).
    pub mapping: Option<String>,
    /// jerasure bit-matrix techniques: bytes per packet (default 2048).
    pub packetsize: u32,
    /// lrc: validated mapping + layers (explicit or generated from k/m/l); `k`, `m`, `mapping` are derived from it.
    pub lrc: Option<LrcSpec>,
    /// clay: validated profile (spec ec-clay.md 1); `k`, `m`, `technique` are taken from it.
    pub clay: Option<ClayProfile>,
}

/// C `isspace` in the "C" locale.
fn c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Classic integer profile value (spec ec-parity.md 1.1): base-10 `strtoll` that consumes the whole string (leading C
/// whitespace, optional `+`/`-`, at least one digit, nothing after), within `long long`, then within C `int`.
/// `k=+2`, `k=02`, `k= 2` all mean 2; the mon stores the raw string.
pub fn parse_int(v: &str) -> Option<i32> {
    let b = v.as_bytes();
    let mut i = b.iter().take_while(|c| c_space(**c)).count();
    let neg = match b.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let digits = &b[i..];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut n: i64 = 0;
    for d in digits {
        n = n.checked_mul(10)?.checked_add(i64::from(d - b'0'))?;
    }
    i32::try_from(if neg { -n } else { n }).ok()
}

/// Integer key: missing or empty = `None` (the caller's default), else [`parse_int`].
pub fn int_key(map: &BTreeMap<String, String>, key: &str) -> Result<Option<i32>, String> {
    match map.get(key).map(String::as_str) {
        None | Some("") => Ok(None),
        Some(v) => parse_int(v)
            .map(Some)
            .ok_or_else(|| format!("profile key {key}={v:?} is not an integer")),
    }
}

/// Non-negative integer key (negative values fail every plugin's range checks).
fn num(map: &BTreeMap<String, String>, key: &str) -> Result<Option<u32>, ProfileError> {
    match int_key(map, key).map_err(ProfileError)? {
        None => Ok(None),
        Some(n) => u32::try_from(n)
            .map(Some)
            .map_err(|_| ProfileError(format!("profile key {key}={n} out of range"))),
    }
}

impl EcProfile {
    pub fn parse(map: &BTreeMap<String, String>) -> Result<EcProfile, ProfileError> {
        let Some(p) = map.get("plugin") else {
            return err("profile has no plugin key");
        };
        // legacy SIMD-build names: same plugin, same bytes (spec ec-parity.md 2)
        let plugin = match p.as_str() {
            "isa" => Plugin::Isa,
            "jerasure" | "jerasure_generic" | "jerasure_neon" | "jerasure_sse3"
            | "jerasure_sse4" => Plugin::Jerasure,
            "lrc" => Plugin::Lrc,
            "shec" | "shec_generic" | "shec_neon" | "shec_sse3" | "shec_sse4" => Plugin::Shec,
            "clay" => Plugin::Clay,
            o => Plugin::Unknown(o.to_string()),
        };
        // shec never reads `mapping`: identity placement (spec ec-parity.md 5.2)
        let mapping = map
            .get("mapping")
            .cloned()
            .filter(|_| plugin != Plugin::Shec);
        let served = matches!(plugin, Plugin::Isa | Plugin::Jerasure);
        let mut c = 0;
        let lrc = if plugin == Plugin::Lrc {
            Some(LrcSpec::from_map(map).map_err(ProfileError)?)
        } else {
            None
        };
        let clay = if plugin == Plugin::Clay {
            Some(ClayProfile::parse(map).map_err(ProfileError)?)
        } else {
            None
        };
        let mut mapping = mapping;
        let (k, m, w, technique) = if let Some(s) = &lrc {
            let k = s.data_count() as u32;
            mapping = Some(s.mapping.clone());
            (k, s.mapping.len() as u32 - k, 0, String::new())
        } else if let Some(c) = &clay {
            (c.k as u32, c.m as u32, 8, c.technique.clone())
        } else if plugin == Plugin::Shec {
            // spec ec-shec.md 1: k,m,c all or none (default 4,3,2); technique default multiple; bad w falls back to 8
            let (kk, mm, cc) = (num(map, "k")?, num(map, "m")?, num(map, "c")?);
            let (k, m, cv) = match (kk, mm, cc) {
                (None, None, None) => (4, 3, 2),
                (Some(k), Some(m), Some(c)) => (k, m, c),
                _ => return err("shec profile needs all of k, m, c or none"),
            };
            c = cv;
            let w = map
                .get("w")
                .and_then(|v| parse_int(v))
                .and_then(|w| u32::try_from(w).ok())
                .filter(|w| matches!(w, 8 | 16 | 32))
                .unwrap_or(8);
            let technique = map
                .get("technique")
                .cloned()
                .unwrap_or_else(|| "multiple".to_string());
            (k, m, w, technique)
        } else if served {
            let technique = map
                .get("technique")
                .cloned()
                .unwrap_or_else(|| "reed_sol_van".to_string());
            // jerasure per-technique defaults (k, m, w); isa: 7, 3, 8
            let (dk, dm, dw) = match (&plugin, technique.as_str()) {
                (Plugin::Jerasure, "reed_sol_r6_op") => (7, 2, 8),
                (Plugin::Jerasure, "liberation") => (2, 2, 7),
                (Plugin::Jerasure, "blaum_roth") => (2, 2, 6),
                (Plugin::Jerasure, "liber8tion") => (2, 2, 8),
                _ => (7, 3, 8),
            };
            let k = num(map, "k")?.unwrap_or(dk);
            let m = num(map, "m")?.unwrap_or(dm);
            let w = num(map, "w")?.unwrap_or(dw);
            if k < 2 {
                return err(format!("k={k} < 2"));
            }
            if m < 1 {
                return err(format!("m={m} < 1"));
            }
            if k.saturating_add(m) > 127 {
                return err(format!("k+m={} > 127", u64::from(k) + u64::from(m)));
            }
            (k, m, w, technique)
        } else {
            (
                num(map, "k")?.unwrap_or(0),
                num(map, "m")?.unwrap_or(0),
                num(map, "w")?.unwrap_or(0),
                map.get("technique").cloned().unwrap_or_default(),
            )
        };
        Ok(EcProfile {
            plugin,
            technique,
            k,
            m,
            w,
            c,
            mapping,
            packetsize: num(map, "packetsize")?.unwrap_or(2048),
            lrc,
            clay,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
        kv.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn defaults() {
        let p = EcProfile::parse(&pm(&[("plugin", "isa")])).unwrap();
        assert_eq!((p.k, p.m, p.w), (7, 3, 8));
        assert_eq!(p.technique, "reed_sol_van");
        let p = EcProfile::parse(&pm(&[("plugin", "jerasure"), ("k", "2"), ("m", "1")])).unwrap();
        assert_eq!((p.k, p.m, p.w), (2, 1, 8));
    }

    #[test]
    fn int_grammar() {
        for (v, want) in [
            ("2", Some(2)),
            ("+2", Some(2)),
            ("02", Some(2)),
            (" 2", Some(2)),
            ("\t\n\x0b\x0c\r +002", Some(2)),
            ("-1", Some(-1)),
            ("-0", Some(0)),
            ("2147483647", Some(i32::MAX)),
            ("-2147483648", Some(i32::MIN)),
            ("2147483648", None),
            ("99999999999999999999", None),
            ("", None),
            (" ", None),
            ("+", None),
            ("2 ", None),
            ("0x2", None),
            ("2.0", None),
            ("++2", None),
            ("\u{a0}2", None),
        ] {
            assert_eq!(parse_int(v), want, "{v:?}");
        }
    }

    #[test]
    fn classic_numbers() {
        for ok in ["+2", " 2", "02", ""] {
            let p = EcProfile::parse(&pm(&[("plugin", "isa"), ("k", ok), ("m", "1")])).unwrap();
            assert_eq!(p.k, if ok.is_empty() { 7 } else { 2 }, "{ok:?}");
        }
        for bad in ["2 ", "-1", "0x2", "99999999999", "2.0"] {
            assert!(
                EcProfile::parse(&pm(&[("plugin", "isa"), ("k", bad)])).is_err(),
                "{bad:?}"
            );
        }
        // stripe_unit is mon-only: any syntax
        let p = EcProfile::parse(&pm(&[("plugin", "isa"), ("stripe_unit", "8K")])).unwrap();
        assert_eq!(p.k, 7);
        assert!(EcProfile::parse(&pm(&[("plugin", "isa"), ("k", "1")])).is_err());
        assert!(EcProfile::parse(&pm(&[("plugin", "isa"), ("m", "0")])).is_err());
        assert!(EcProfile::parse(&pm(&[("plugin", "isa"), ("k", "120"), ("m", "8")])).is_err());
        assert!(EcProfile::parse(&pm(&[("k", "2")])).is_err());
    }

    #[test]
    fn legacy_aliases() {
        for (name, want) in [
            ("jerasure_generic", Plugin::Jerasure),
            ("jerasure_neon", Plugin::Jerasure),
            ("jerasure_sse3", Plugin::Jerasure),
            ("jerasure_sse4", Plugin::Jerasure),
            ("shec_generic", Plugin::Shec),
            ("shec_neon", Plugin::Shec),
            ("shec_sse3", Plugin::Shec),
            ("shec_sse4", Plugin::Shec),
        ] {
            assert_eq!(
                EcProfile::parse(&pm(&[("plugin", name)])).unwrap().plugin,
                want
            );
        }
        let p = EcProfile::parse(&pm(&[("plugin", "jerasure_x")])).unwrap();
        assert_eq!(p.plugin, Plugin::Unknown("jerasure_x".into()));
    }

    #[test]
    fn shec_keys() {
        let p = EcProfile::parse(&pm(&[("plugin", "shec")])).unwrap();
        assert_eq!((p.k, p.m, p.c, p.w), (4, 3, 2, 8));
        assert_eq!(p.technique, "multiple");
        let p = EcProfile::parse(&pm(&[
            ("plugin", "shec"),
            ("k", "6"),
            ("m", "4"),
            ("c", "3"),
            ("w", "x"),
        ]))
        .unwrap();
        assert_eq!((p.k, p.m, p.c, p.w), (6, 4, 3, 8));
        let p = EcProfile::parse(&pm(&[
            ("plugin", "shec"),
            ("k", "6"),
            ("m", "4"),
            ("c", "3"),
            ("w", "+16"),
        ]))
        .unwrap();
        assert_eq!(p.w, 16);
        for kv in [
            &[("k", "4")][..],
            &[("k", "4"), ("m", "3")],
            &[("k", "4 "), ("m", "3"), ("c", "2")],
        ] {
            let mut v = vec![("plugin", "shec")];
            v.extend_from_slice(kv);
            assert!(EcProfile::parse(&pm(&v)).is_err(), "{kv:?}");
        }
    }

    #[test]
    fn shec_ignores_mapping() {
        let p = EcProfile::parse(&pm(&[("plugin", "shec_generic"), ("mapping", "_DD")])).unwrap();
        assert_eq!(p.mapping, None);
        let p = EcProfile::parse(&pm(&[("plugin", "isa"), ("mapping", "_DD")])).unwrap();
        assert_eq!(p.mapping.as_deref(), Some("_DD"));
    }

    #[test]
    fn unserved_plugins_parse() {
        let p = EcProfile::parse(&pm(&[
            ("plugin", "lrc"),
            ("mapping", "DD_"),
            ("layers", "[[\"DDc\",\"\"]]"),
        ]))
        .unwrap();
        assert_eq!(p.plugin, Plugin::Lrc);
        assert_eq!((p.k, p.m), (2, 1));
        assert_eq!(p.mapping.as_deref(), Some("DD_"));
        assert!(EcProfile::parse(&pm(&[("plugin", "lrc"), ("layers", "[]")])).is_err());
        let p = EcProfile::parse(&pm(&[("plugin", "weird")])).unwrap();
        assert_eq!(p.plugin, Plugin::Unknown("weird".into()));
    }
}
