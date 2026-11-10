// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! The `ceph.conf` file grammar: `doc/spec/rados-client/126-c-abi-config-files.md`.
//!
//! Sections merge across repeats, the last duplicate key of a section wins, and
//! the caller decides precedence by the order it asks for sections. A line
//! continuation ends in `\`; a quoted value keeps `#`/`;` and may escape the next
//! byte; an unquoted value ends at the first `#`/`;`. The whole file must be
//! UTF-8 and free of NUL bytes, and must end in a newline unless it is a comment.
//!
//! Values and section names stay bytes ([`Sections`]) so the librados C ABI can
//! reject a non-UTF-8 file as a whole and still keep the parsed text intact;
//! [`Conf`] is the owned-string view a text caller uses.

use std::collections::BTreeMap;

/// Sections and their keys/values, in sorted order (the order `--show-conf`
/// prints).
pub type Sections = BTreeMap<Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>>;

/// Why a configuration text did not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The text is not a valid ceph.conf (grammar, encoding or NUL byte).
    Syntax,
    /// An allocation for the parsed text failed.
    NoMemory,
}

impl Error {
    /// Negative errno a C caller reports for this error.
    pub fn errno(self) -> i32 {
        match self {
            Self::Syntax => -22,
            Self::NoMemory => -12,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Syntax => "invalid ceph.conf syntax",
            Self::NoMemory => "out of memory",
        })
    }
}

impl std::error::Error for Error {}

/// Whitespace folding of a key: leading/trailing ASCII whitespace dropped,
/// each internal run becomes one `_`. `-` stays literal.
fn fold_whitespace(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len());
    let mut pending_space = false;
    for &byte in key {
        if byte.is_ascii_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(b'_');
        }
        pending_space = false;
        out.push(byte);
    }
    out
}

/// Key rule of the deployment contract (`osddir`) and of the CephFS client:
/// ASCII whitespace runs and `-` become `_`, leading and trailing whitespace is
/// dropped. A ceph.conf file written for our daemons therefore reads
/// `mon-host` and `mon_host` as one option.
///
/// The librados file grammar is stricter ([`parse`] keeps `-` literal, spec 126
/// s7: `mon-host` is an unknown file key there), so this rule lives in the
/// [`Conf`] text view, not in [`Sections`].
pub fn normalize_key(key: &[u8]) -> Vec<u8> {
    fold_whitespace(key)
        .into_iter()
        .map(|byte| if byte == b'-' { b'_' } else { byte })
        .collect()
}

/// API option-name normalisation of `rados_conf_set`/`rados_conf_get`: ASCII
/// whitespace runs become `_`, and `-` stays literal, so `mon-host` is an
/// unknown option while ` mon  host ` is `mon_host`
/// (`doc/spec/rados-client/config-public-contract.md` s2, spec 126).
pub fn normalize_option(key: &[u8]) -> String {
    fold_whitespace(key).into_iter().map(char::from).collect()
}

fn tail(s: &[u8]) -> bool {
    let s = s.trim_ascii_start();
    s.is_empty() || matches!(s.first(), Some(b'#' | b';'))
}

fn value(s: &[u8]) -> Result<Vec<u8>, Error> {
    let s = s.trim_ascii_start();
    let quote = s.first().copied().filter(|b| matches!(b, b'\'' | b'"'));
    let mut pos = usize::from(quote.is_some());
    let mut out = Vec::new();
    out.try_reserve(s.len()).map_err(|_| Error::NoMemory)?;
    while let Some(&ch) = s.get(pos) {
        pos += 1;
        if ch == b'\\' {
            out.push(*s.get(pos).ok_or(Error::Syntax)?);
            pos += 1;
        } else if Some(ch) == quote {
            return if tail(&s[pos..]) {
                Ok(out.trim_ascii().to_vec())
            } else {
                Err(Error::Syntax)
            };
        } else if matches!(ch, b'#' | b';') {
            return if quote.is_none() {
                Ok(out.trim_ascii().to_vec())
            } else {
                Err(Error::Syntax)
            };
        } else {
            out.push(ch);
        }
    }
    if quote.is_some() {
        Err(Error::Syntax)
    } else {
        Ok(out.trim_ascii().to_vec())
    }
}

/// Parse ceph.conf text into its sections (the librados file grammar).
pub fn parse(input: impl AsRef<[u8]>) -> Result<Sections, Error> {
    parse_policy(input.as_ref(), Policy::Strict)
}

/// The logical lines of `input`, joined by `\n`. The strict policy validates
/// encoding, NUL bytes, quotes, continuations and the final newline and folds
/// CRLF; the lenient policy keeps the text as written (each line is trimmed
/// when it is read).
fn join(input: &[u8], policy: Policy) -> Result<Vec<u8>, Error> {
    if policy == Policy::Lenient {
        return Ok(input.to_vec());
    }
    std::str::from_utf8(input).map_err(|_| Error::Syntax)?;
    if input.contains(&0) {
        return Err(Error::Syntax);
    }
    let mut normalized = Vec::new();
    normalized
        .try_reserve(input.len())
        .map_err(|_| Error::NoMemory)?;
    let mut pos = 0;
    while pos < input.len() {
        if input[pos..].starts_with(b"\r\n") {
            normalized.push(b'\n');
            pos += 2;
        } else {
            normalized.push(input[pos]);
            pos += 1;
        }
    }
    let mut joined = Vec::new();
    joined
        .try_reserve(normalized.len())
        .map_err(|_| Error::NoMemory)?;
    let mut pos = 0;
    let (mut comment, mut record, mut heading, mut seen_equal, mut value_start) =
        (false, false, false, false, false);
    let mut quote = None;
    while let Some(&ch) = normalized.get(pos) {
        pos += 1;
        if ch == b'\n' {
            if quote.is_some() {
                return Err(Error::Syntax);
            }
            joined.push(ch);
            (comment, record, heading, seen_equal, value_start) =
                (false, false, false, false, false);
        } else if comment {
            joined.push(ch);
        } else if ch == b'\\' {
            match normalized.get(pos).copied() {
                Some(b'\n') if quote.is_none() => {
                    pos += 1;
                }
                Some(b'\n') | None => return Err(Error::Syntax),
                Some(next) => {
                    joined.extend([ch, next]);
                    pos += 1;
                    record = true;
                    value_start = false;
                }
            }
        } else if let Some(delimiter) = quote {
            if matches!(ch, b'#' | b';') {
                return Err(Error::Syntax);
            }
            if ch == delimiter {
                quote = None;
            }
            joined.push(ch);
        } else if matches!(ch, b'#' | b';') {
            comment = true;
            joined.push(ch);
        } else {
            if !record && !ch.is_ascii_whitespace() {
                record = true;
                heading = ch == b'[';
            }
            if value_start && !ch.is_ascii_whitespace() {
                if matches!(ch, b'\'' | b'"') {
                    quote = Some(ch);
                }
                value_start = false;
            } else if ch == b'=' && !seen_equal && !heading {
                seen_equal = true;
                value_start = true;
            }
            joined.push(ch);
        }
    }
    if !joined.is_empty() && !joined.ends_with(b"\n") && !(comment && !record) {
        return Err(Error::Syntax);
    }
    Ok(joined)
}

/// Read `input` with `policy`'s line rules.
fn parse_policy(input: &[u8], policy: Policy) -> Result<Sections, Error> {
    let joined = join(input, policy)?;
    let mut sections = Sections::new();
    let mut section: Option<Vec<u8>> = None;
    let mut bare = false;
    for line in joined.split(|b| *b == b'\n').map(<[u8]>::trim_ascii) {
        if tail(line) {
            continue;
        }
        if let Some(name) = header(line, policy)? {
            if policy == Policy::Strict && bare {
                return Err(Error::Syntax);
            }
            sections.entry(name.to_vec()).or_default();
            section = Some(name.to_vec());
            continue;
        }
        let Some(equals) = line.iter().position(|b| *b == b'=') else {
            if policy == Policy::Strict {
                return Err(Error::Syntax);
            }
            continue;
        };
        let key = match policy {
            Policy::Strict => {
                let key = fold_whitespace(&line[..equals]);
                if key.is_empty() || key.iter().any(|b| matches!(b, b'[' | b'#' | b';')) {
                    return Err(Error::Syntax);
                }
                key
            }
            Policy::Lenient => normalize_key(&line[..equals]),
        };
        if policy == Policy::Strict && section.is_none() {
            if bare {
                return Err(Error::Syntax);
            }
            bare = true;
        }
        let value = match policy {
            Policy::Strict => value(&line[equals + 1..])?,
            Policy::Lenient => lenient_value(&line[equals + 1..]),
        };
        sections
            .entry(section.clone().unwrap_or_else(|| b"global".to_vec()))
            .or_default()
            .insert(key, value);
    }
    Ok(sections)
}

/// Line rules of a ceph.conf reader.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Policy {
    /// The librados file grammar (spec 126): any line it does not describe is
    /// [`Error::Syntax`].
    Strict,
    /// The daemon deployment contract (`osddir`): a line without `=` is
    /// ignored, a section header ends at its `]`, and a value uses the daemon's
    /// comment rule.
    Lenient,
}

/// A trimmed line's `[name]` header. `Ok(None)` is a line that is not a
/// header; `Err` is a header the strict grammar rejects.
fn header(line: &[u8], policy: Policy) -> Result<Option<&[u8]>, Error> {
    let Some(rest) = line.strip_prefix(b"[") else {
        return Ok(None);
    };
    let Some(end) = rest.iter().position(|b| *b == b']') else {
        return Ok(None);
    };
    let name = &rest[..end];
    match policy {
        Policy::Strict => {
            if name.is_empty() || !tail(&rest[end + 1..]) {
                return Err(Error::Syntax);
            }
            Ok(Some(name))
        }
        Policy::Lenient => Ok(Some(name.trim_ascii())),
    }
}

/// The daemon's value rule: a `#`/`;` starts a comment only after whitespace,
/// a leading `"` quotes the value up to the next `"`, and everything else is
/// the value (leading/trailing whitespace dropped).
fn lenient_value(value: &[u8]) -> Vec<u8> {
    let value = value.trim_ascii();
    if let Some(rest) = value.strip_prefix(b"\"")
        && let Some(end) = rest.iter().position(|b| *b == b'"')
    {
        return rest[..end].to_vec();
    }
    let mut comment = false;
    for (pos, byte) in value.iter().enumerate() {
        if matches!(byte, b'#' | b';') && comment {
            return value[..pos].trim_ascii_end().to_vec();
        }
        comment = byte.is_ascii_whitespace();
    }
    value.to_vec()
}

/// Value of `key` in the first of `sections` (in the order given) that sets it,
/// or `None` when none does. The key is folded like a file key (whitespace
/// runs become `_`, `-` stays literal, spec 126 s7).
pub fn section_value<'a>(sections: &'a Sections, order: &[&[u8]], key: &[u8]) -> Option<&'a [u8]> {
    let key = fold_whitespace(key);
    for section in order {
        if let Some(value) = sections.get(*section).and_then(|entries| entries.get(&key)) {
            return Some(value);
        }
    }
    None
}

/// Parsed ceph.conf as owned UTF-8 strings, for callers that work on text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Conf {
    sections: BTreeMap<String, BTreeMap<String, String>>,
}

impl Conf {
    /// Parse ceph.conf text.
    pub fn parse(text: &str) -> Result<Conf, Error> {
        Conf::from_sections(&parse(text)?)
    }

    /// Parse ceph.conf text with the daemon deployment contract's lenient line
    /// rules (`osddir`): a line without `=` is ignored, a section header ends at
    /// its `]`, and a value uses the daemon's comment rule (a `#`/`;` starts a
    /// comment only after whitespace, a leading `"` quotes the value). Keys are
    /// read with [`normalize_key`], so `mon-host` is `mon_host`.
    pub fn parse_lenient(text: &str) -> Conf {
        // A lenient parse rejects no line, and its text is already UTF-8.
        let sections = parse_policy(text.as_bytes(), Policy::Lenient)
            .expect("a lenient ceph.conf parse rejects no line");
        Conf::from_sections(&sections).expect("lenient ceph.conf text is UTF-8")
    }

    /// Build the text view of already parsed [`Sections`]. The parser accepts
    /// only UTF-8, so the conversion cannot fail for a parsed file.
    pub fn from_sections(sections: &Sections) -> Result<Conf, Error> {
        let mut text = BTreeMap::new();
        for (section, entries) in sections {
            let section = String::from_utf8(section.clone()).map_err(|_| Error::Syntax)?;
            let mut values = BTreeMap::new();
            for (key, value) in entries {
                values.insert(
                    String::from_utf8(normalize_key(key)).map_err(|_| Error::Syntax)?,
                    String::from_utf8(value.clone()).map_err(|_| Error::Syntax)?,
                );
            }
            text.insert(section, values);
        }
        Ok(Conf { sections: text })
    }

    /// Read and parse `path`; the error names the path.
    pub fn load(path: &std::path::Path) -> Result<Conf, String> {
        Self::load_io(path).map_err(|error| format!("{}: {error}", path.display()))
    }

    /// [`Conf::load`] with the `io::Error` kept, for callers that must tell
    /// "no such file" from "cannot read it".
    pub fn load_io(path: &std::path::Path) -> std::io::Result<Conf> {
        let text = std::fs::read_to_string(path)?;
        Conf::parse(&text)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    }

    /// [`Conf::load_io`] with the daemon's lenient line rules
    /// ([`Conf::parse_lenient`]).
    pub fn load_io_lenient(path: &std::path::Path) -> std::io::Result<Conf> {
        std::fs::read_to_string(path).map(|text| Conf::parse_lenient(&text))
    }

    /// Read and parse `path` leniently; the error names the path.
    pub fn load_lenient(path: &std::path::Path) -> Result<Conf, String> {
        Self::load_io_lenient(path).map_err(|error| format!("{}: {error}", path.display()))
    }

    /// Keys of `sections` merged in order (later wins).
    pub fn merged(&self, sections: &[&str]) -> BTreeMap<String, String> {
        let mut merged = BTreeMap::new();
        for section in sections {
            if let Some(entries) = self.sections.get(*section) {
                merged.extend(entries.iter().map(|(k, v)| (k.clone(), v.clone())));
            }
        }
        merged
    }

    /// Value of `key` with `sections` merged in order (later wins), e.g.
    /// `["global", "client", "client.admin"]` for a client option. The key is
    /// normalised like a ceph.conf key (spaces and dashes are underscores).
    pub fn value(&self, sections: &[&str], key: &str) -> Option<&str> {
        let key = normalize_key(key.as_bytes());
        let key = std::str::from_utf8(&key).ok()?;
        let mut found = None;
        for section in sections {
            if let Some(value) = self
                .sections
                .get(*section)
                .and_then(|entries| entries.get(key))
            {
                found = Some(value.as_str());
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_normalisation_folds_spaces_and_dashes() {
        assert_eq!(normalize_key(b"mon host"), b"mon_host");
        assert_eq!(normalize_key(b" mon  host "), b"mon_host");
        assert_eq!(normalize_key(b"mon-host"), b"mon_host");
        assert_eq!(normalize_key(b"a_ b"), b"a__b");
        assert_eq!(normalize_option(b" mon  host "), "mon_host");
        assert_eq!(normalize_option(b"mon-host"), "mon-host");
    }

    #[test]
    fn sections_merge_last_duplicate_and_keep_quotes_and_comments() {
        let sections = parse("#comment\n[global]\nmon host = global\n[client]\nmon_host = client\n[client.x]\nmon_host = ' selected ' # trailing\n[client.x]\nkeyring = one\\\ntwo\\#x\\;y\\\\z\n").expect("parse");
        assert_eq!(
            Conf::from_sections(&sections)
                .expect("text")
                .value(&["global", "client", "client.x"], "mon_host"),
            Some("selected")
        );
        assert_eq!(
            sections[b"client.x".as_slice()][b"keyring".as_slice()],
            b"onetwo#x;y\\z"
        );
        assert_eq!(
            sections[b"global".as_slice()][b"mon_host".as_slice()],
            b"global"
        );
        assert_eq!(
            Conf::from_sections(&sections)
                .expect("text")
                .value(&["global", "client"], "mon_host"),
            Some("client")
        );
    }

    #[test]
    fn a_dash_key_is_one_option_in_the_text_view_and_literal_in_the_file_grammar() {
        // The librados C ABI keeps a file key with a dash literal (spec 126 s7).
        let sections = parse("[global]\nmon-host = v2:192.0.2.1:3300\n").expect("parse");
        assert_eq!(
            sections[b"global".as_slice()][b"mon-host".as_slice()],
            b"v2:192.0.2.1:3300"
        );
        assert_eq!(
            section_value(&sections, &[b"global"], b"mon-host"),
            Some(b"v2:192.0.2.1:3300".as_slice())
        );
        // Our daemons and the CephFS client read dashes as underscores.
        let conf = Conf::from_sections(&sections).expect("text");
        assert_eq!(
            conf.value(&["global"], "mon_host"),
            Some("v2:192.0.2.1:3300")
        );
        assert_eq!(
            conf.merged(&["global"]).get("mon_host").map(String::as_str),
            Some("v2:192.0.2.1:3300")
        );
    }

    #[test]
    fn malformed_text_is_a_syntax_error() {
        for text in [
            "[global]\nmon_host=eof",
            "mon_host=a\nkey=b\n",
            "[global]\nmon_host=\"a#b\"\n",
            "[global]\nmon_host=\"a\" tail\n",
            "[missing\n",
            "[global]\nmon_host=invalid\\\n",
        ] {
            assert_eq!(parse(text), Err(Error::Syntax), "{text:?}");
        }
        assert_eq!(
            parse(b"[global]\nrbd_default_pool=pool_\xff\n"),
            Err(Error::Syntax)
        );
        assert!(parse("[global]\r\nmon_host=windows\r\n").is_ok());
        assert!(parse("mon_host=bare\n").is_ok());
    }

    #[test]
    fn precedence_is_the_callers_order() {
        let conf =
            Conf::parse("[global]\na=global\n[osd]\na=osd\n[osd.3]\nb=own\n").expect("parse");
        assert_eq!(conf.value(&["global", "osd", "osd.3"], "a"), Some("osd"));
        assert_eq!(conf.value(&["global"], "b"), None);
        assert_eq!(conf.value(&["global", "osd", "osd.4"], "b"), None);
        assert_eq!(
            conf.merged(&["global", "osd"]).get("a").map(String::as_str),
            Some("osd")
        );
    }

    #[test]
    fn lenient_reader_ignores_a_line_without_an_equals_sign() {
        let text = "[global]\nnot an entry\nmon_host = v2:192.0.2.1:3300\n";
        let conf = Conf::parse_lenient(text);
        assert_eq!(
            conf.value(&["global"], "mon_host"),
            Some("v2:192.0.2.1:3300")
        );
        assert_eq!(parse(text), Err(Error::Syntax));
    }

    #[test]
    fn lenient_reader_trims_a_section_header_and_ignores_its_tail() {
        let text = "[ osd.3 ] after the bracket\nmon_host = v2:192.0.2.9:3300\n";
        let conf = Conf::parse_lenient(text);
        assert_eq!(
            conf.value(&["osd.3"], "mon_host"),
            Some("v2:192.0.2.9:3300")
        );
        assert_eq!(parse(text), Err(Error::Syntax));
    }

    #[test]
    fn lenient_reader_keeps_the_daemon_comment_rule() {
        let text = "[global]\nmon_host = v2:192.0.2.1:3300 # a comment\nkeyring = a#b\n";
        let conf = Conf::parse_lenient(text);
        assert_eq!(
            conf.value(&["global"], "mon_host"),
            Some("v2:192.0.2.1:3300")
        );
        assert_eq!(conf.value(&["global"], "keyring"), Some("a#b"));
        // The strict grammar ends a value at the first `#`/`;`.
        let strict = Conf::parse(text).expect("strict");
        assert_eq!(strict.value(&["global"], "keyring"), Some("a"));
    }

    #[test]
    fn lenient_reader_folds_a_duplicate_key_across_spellings() {
        let text = "[global]\nmon_host = first\nmon-host = second\n";
        let conf = Conf::parse_lenient(text);
        assert_eq!(conf.value(&["global"], "mon_host"), Some("second"));
        // The file grammar keeps `-` literal, so the second value is another key.
        let strict = Conf::parse(text).expect("strict");
        assert_eq!(strict.value(&["global"], "mon_host"), Some("first"));
    }
}
