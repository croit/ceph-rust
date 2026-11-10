// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! The shared source-spec JSON grammar (spec
//! `doc/spec/rustyrbd/migration-source-raw-qcow-file.md`, "Shared
//! source-spec grammar").
//!
//! Parse rules: malformed JSON, or a root that is not an object, is
//! `-EBADMSG`; keys are unique and case-sensitive with the last duplicate
//! winning; trailing bytes after the value are ignored; unknown keys are
//! ignored at every level.

use serde::Deserialize;
use serde_json::{Deserializer, Value};

use crate::journal_backend::EBADMSG;

/// Parse one JSON value, ignoring trailing bytes; `-EBADMSG` for malformed
/// input.
pub(crate) fn parse_value(json: &str) -> Result<Value, i32> {
    let mut deserializer = Deserializer::from_str(json);
    Value::deserialize(&mut deserializer).map_err(|_| EBADMSG)
}

/// Parse the spec root: exactly one JSON object; `-EBADMSG` for malformed
/// input or a non-object root (array, scalar, `null`).
pub(crate) fn parse_root(json: &str) -> Result<Value, i32> {
    match parse_value(json)? {
        Value::Object(root) => Ok(Value::Object(root)),
        _ => Err(EBADMSG),
    }
}

/// The persisted form of a spec: compact JSON, keys sorted bytewise,
/// duplicate keys collapsed, unknown keys preserved. Reopen parses that
/// stored string, so a codec must be reconstructible from it alone.
pub fn canonical_json(spec: &str) -> Result<String, i32> {
    let root = parse_root(spec)?;
    Ok(serde_json::to_string(&root).expect("serialization of a parsed value cannot fail"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_root_object_and_ignores_trailing_bytes() {
        let root = parse_root(r#"{"type":"raw"} xyz"#).expect("trailing bytes are ignored");
        assert_eq!(root.get("type").unwrap(), &Value::String("raw".into()));
        let root = parse_root(
            r#"  {"type":"qcow"}
"#,
        )
        .expect("surrounding whitespace is fine");
        assert_eq!(root.get("type").unwrap(), &Value::String("qcow".into()));
    }

    #[test]
    fn rejects_malformed_and_non_object_roots() {
        for spec in ["{", "[1,2]", "42", r#""raw""#, "null", ""] {
            assert_eq!(parse_root(spec), Err(EBADMSG), "{spec}");
        }
        // Trailing bytes are ignored: a trailing brace after the object is
        // accepted, not a parse error.
        let root = parse_root(r#"{"type":"raw"}}"#).expect("trailing byte ignored");
        assert_eq!(root.get("type").unwrap(), &Value::String("raw".into()));
    }

    #[test]
    fn canonical_form_is_compact_sorted_and_collapsed() {
        // Duplicates keep the last value; keys sort bytewise; no whitespace;
        // unknown keys are preserved.
        let spec = r#"{
            "b": 1,
            "stream": {"type": "file", "file_path": "/x"},
            "type": "raw",
            "type": "raw",
            "zzz": 42
        } trailing"#;
        let canonical = canonical_json(spec).expect("canonical form");
        assert_eq!(
            canonical,
            r#"{"b":1,"stream":{"file_path":"/x","type":"file"},"type":"raw","zzz":42}"#
        );
        // The canonical form reparses to the same object.
        let again = canonical_json(&canonical).expect("idempotent");
        assert_eq!(again, canonical);
    }

    #[test]
    fn canonical_form_rejects_non_object_roots() {
        assert_eq!(canonical_json("[1]"), Err(EBADMSG));
        assert_eq!(canonical_json("nope"), Err(EBADMSG));
    }
}
