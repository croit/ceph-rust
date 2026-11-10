// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Keyring file parser (spec sec 2.2).

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::key::CryptoKey;
use crate::none::EntityName;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyringEntry {
    pub key: Option<CryptoKey>,
    pub pending_key: Option<CryptoKey>,
    /// service ("mon", "osd", ...) -> cap grammar text.
    pub caps: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct Keyring {
    /// Keyed by `<type>.<id>`.
    pub entries: BTreeMap<String, KeyringEntry>,
}

fn err(line: usize, m: &str) -> Error {
    Error::Keyring(format!("line {line}: {m}"))
}

/// Current `[...]` block: either `[global]` (skipped) or an entity entry.
enum Section {
    Global,
    Entity(String),
}

/// Tokenise one logical line's value after `=` into its text. Handles quotes,
/// comments (`#`/`;` outside quotes) and `\x` escapes. The text can be base64 key material, so it is
/// wiped on drop.
fn parse_value(s: &str) -> Zeroizing<String> {
    let s = s.trim_start();
    let mut out = Zeroizing::new(String::new());
    let mut it = s.chars().peekable();
    match it.peek() {
        Some(&q @ ('"' | '\'')) => {
            it.next();
            while let Some(c) = it.next() {
                if c == q {
                    break;
                }
                if c == '\\' {
                    if let Some(n) = it.next() {
                        out.push(n);
                    }
                } else {
                    out.push(c);
                }
            }
            out
        }
        _ => {
            while let Some(c) = it.next() {
                match c {
                    '#' | ';' => break,
                    '\\' => {
                        if let Some(n) = it.next() {
                            out.push(n);
                        }
                    }
                    _ => out.push(c),
                }
            }
            Zeroizing::new(out.trim_end().to_owned())
        }
    }
}

impl Keyring {
    /// Parse a keyring. `text` is borrowed: the caller keeps ownership and must wipe it itself when the
    /// file held key material (a `key =` line is the secret in base64).
    pub fn parse(text: &str) -> Result<Self> {
        // join continuation lines (trailing backslash) keeping line numbers approximate
        let mut logical: Vec<(usize, Zeroizing<String>)> = Vec::new();
        let mut cur: Option<(usize, Zeroizing<String>)> = None;
        for (i, raw) in text.lines().enumerate() {
            let raw = raw.trim_end_matches('\r');
            let (cont, body) = match raw.strip_suffix('\\') {
                Some(b) if !b.ends_with('\\') => (true, b),
                _ => (false, raw),
            };
            match &mut cur {
                Some((_, s)) => s.push_str(body),
                None => cur = Some((i + 1, Zeroizing::new(body.to_owned()))),
            }
            if !cont {
                logical.push(cur.take().unwrap());
            }
        }
        if let Some(c) = cur {
            logical.push(c);
        }

        let mut kr = Keyring::default();
        let mut section: Option<Section> = None;
        for (ln, line) in logical {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with(';') {
                continue;
            }
            if let Some(rest) = t.strip_prefix('[') {
                let end = rest
                    .find(']')
                    .ok_or_else(|| err(ln, "unterminated section"))?;
                let name = rest[..end].trim();
                if name == "global" {
                    section = Some(Section::Global);
                    continue;
                }
                if EntityName::parse(name).is_none() {
                    return Err(err(ln, "bad entity name"));
                }
                // a repeated section continues the entry: later lines override per field (keyrings concatenated
                // with `cat`, caps in a second block), as the reference's INI reader merges sections
                kr.entries.entry(name.to_owned()).or_default();
                section = Some(Section::Entity(name.to_owned()));
                continue;
            }
            let Some(sec) = &section else {
                return Err(err(ln, "key outside section"));
            };
            let (k, v) = t
                .split_once('=')
                .ok_or_else(|| err(ln, "expected key = value"))?;
            let key: Vec<&str> = k
                .split(|c: char| c.is_whitespace() || c == '_')
                .filter(|x| !x.is_empty())
                .collect();
            let key = key.join(" ");
            let val = parse_value(v);
            let Section::Entity(name) = sec else { continue };
            let e = kr.entries.get_mut(name).unwrap();
            match key.as_str() {
                "key" => {
                    e.key = Some(CryptoKey::from_base64(&val).map_err(|x| err(ln, &x.to_string()))?)
                }
                "pending key" => {
                    e.pending_key =
                        Some(CryptoKey::from_base64(&val).map_err(|x| err(ln, &x.to_string()))?)
                }
                "auid" => {}
                k if k.starts_with("caps ") && k.len() > 5 => {
                    e.caps.insert(k[5..].trim().to_owned(), (*val).clone());
                }
                _ => return Err(err(ln, "unknown key")),
            }
        }
        Ok(kr)
    }

    pub fn get(&self, entity: &str) -> Option<&KeyringEntry> {
        self.entries.get(entity)
    }
}
