// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Method / mode constants and mode lists (spec sec 8.2, 11, 12). The per-peer policy lives with its users
//! (OSD `auth.rs`, monc config).

pub const AUTH_NONE: u32 = 1;
pub const AUTH_CEPHX: u32 = 2;
pub const CON_MODE_CRC: u32 = 1;
pub const CON_MODE_SECURE: u32 = 2;

/// One `ms_*_mode` list (spec sec 8.2): the modes in input order and the words that are not a mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedModes {
    pub modes: Vec<u32>,
    /// Words without a mode mapping, in input order: the caller warns and skips them (spec sec 11).
    pub unknown: Vec<String>,
}

/// Parse `ms_*_mode` lists (`secure crc`).
pub fn parse_modes(s: &str) -> ParsedModes {
    let mut p = ParsedModes::default();
    for w in s
        .split([',', ' ', ';', '\t'])
        .map(str::trim)
        .filter(|w| !w.is_empty())
    {
        match w {
            "crc" => p.modes.push(CON_MODE_CRC),
            "secure" => p.modes.push(CON_MODE_SECURE),
            _ => p.unknown.push(w.to_owned()),
        }
    }
    p
}

/// Mode list valid for `method` (auth-none spec 2.1): unchanged for every method but NONE, which keeps CRC only.
pub fn modes_for_method(modes: &[u32], method: u32) -> Vec<u32> {
    modes
        .iter()
        .copied()
        .filter(|m| method != AUTH_NONE || *m == CON_MODE_CRC)
        .collect()
}
