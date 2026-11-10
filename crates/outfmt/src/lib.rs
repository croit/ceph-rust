// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Shared `--format plain|json|json-pretty|jsonl` parser and renderers for the CLIs (Ceph style). `jsonl` (one record
//! per line) is accepted only by commands that emit a record stream; everywhere else it is a usage error (exit 2).
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Plain,
    Json,
    JsonPretty,
    Jsonl,
}

impl Format {
    /// Canonical command-line spelling.
    pub fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Json => "json",
            Self::JsonPretty => "json-pretty",
            Self::Jsonl => "jsonl",
        }
    }

    pub fn parse(s: &str) -> Option<Format> {
        match s {
            "plain" => Some(Format::Plain),
            "json" => Some(Format::Json),
            "json-pretty" => Some(Format::JsonPretty),
            "jsonl" => Some(Format::Jsonl),
            _ => None,
        }
    }

    pub fn is_json(self) -> bool {
        self != Format::Plain
    }

    /// One document: compact (`plain`, `json`, `jsonl`) or indented (`json-pretty`); no trailing newline. Commands
    /// with a human layout render `plain` themselves; the others print the compact document.
    pub fn doc(self, v: &Value) -> String {
        match self {
            Format::JsonPretty => serde_json::to_string_pretty(v).unwrap_or_default(),
            _ => v.to_string(),
        }
    }

    /// A record stream: `jsonl` = one compact record per line; `json`/`json-pretty` = one array; no trailing newline.
    /// Zero rows render as `""`, so a caller prints nothing for an empty stream (an empty line is not a record).
    pub fn records(self, rows: &[Value]) -> String {
        match self {
            Format::Jsonl => rows
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
            _ => self.doc(&Value::Array(rows.to_vec())),
        }
    }
}

/// `--key=value` split into `--key value` (`--op=list` is accepted like `--op list`). Every command line of the daemon and
/// the tools reads its arguments through this one function, before any option lookup: an option form one reader ignores
/// would let a command act on a different device or store than the invocation names.
pub fn normalize_args(a: &[String]) -> Vec<String> {
    a.iter()
        .flat_map(|s| match s.split_once('=') {
            Some((k, v)) if k.starts_with("--") => vec![k.to_owned(), v.to_owned()],
            _ => vec![s.clone()],
        })
        .collect()
}

/// Take `--format X` / `--format=X` (default `plain`) out of `args`; returns the format and the remaining arguments.
/// `records`: the command emits a record stream and accepts `jsonl`. Errors are usage messages (callers exit 2).
/// The scan knows no other flags: a value of another flag that is literally `--format` / `--format=...` is consumed as
/// the format flag, so callers that pass free-form words (subcommand payloads) accept that ambiguity.
pub fn extract(args: &[String], records: bool) -> Result<(Format, Vec<String>), String> {
    let mut fmt = Format::Plain;
    let mut rest = Vec::with_capacity(args.len());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--json" {
            // the hand-rolled flag parsers would ignore it and print plain text: fail loudly instead
            return Err("unknown flag --json (use --format json)".into());
        }
        let v = if a == "--format" {
            Some(
                it.next()
                    .ok_or_else(|| "--format needs a value".to_string())?
                    .as_str(),
            )
        } else {
            a.strip_prefix("--format=")
        };
        let Some(v) = v else {
            rest.push(a.clone());
            continue;
        };
        fmt = match Format::parse(v) {
            Some(Format::Jsonl) if !records => {
                return Err("--format jsonl: this command emits no record stream".into());
            }
            Some(f) => f,
            None => {
                let all = if records {
                    "plain|json|json-pretty|jsonl"
                } else {
                    "plain|json|json-pretty"
                };
                return Err(format!("bad --format {v:?} ({all})"));
            }
        };
    }
    Ok((fmt, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn s(a: &[&str]) -> Vec<String> {
        a.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn normalize_splits_long_options_only() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            normalize_args(&v(&[
                "t",
                "--dev=file:/a,size=8G",
                "--set",
                "k=v",
                "x=y",
                "-f=1"
            ])),
            v(&[
                "t",
                "--dev",
                "file:/a,size=8G",
                "--set",
                "k=v",
                "x=y",
                "-f=1"
            ])
        );
    }

    #[test]
    fn extract_forms() {
        assert_eq!(
            extract(&s(&["a"]), false).unwrap(),
            (Format::Plain, s(&["a"]))
        );
        assert_eq!(
            extract(&s(&["a", "--format", "json", "b"]), false).unwrap(),
            (Format::Json, s(&["a", "b"]))
        );
        assert_eq!(
            extract(&s(&["--format=json-pretty"]), false).unwrap(),
            (Format::JsonPretty, vec![])
        );
        // similar flags are untouched
        assert_eq!(
            extract(&s(&["--format-lba4k"]), false).unwrap().1,
            s(&["--format-lba4k"])
        );
    }

    #[test]
    fn extract_rejects() {
        assert!(extract(&s(&["--format"]), false).is_err());
        assert!(extract(&s(&["--json"]), true).is_err());
        assert!(extract(&s(&["--format", "xml"]), true).is_err());
        assert!(extract(&s(&["--format", "jsonl"]), false).is_err());
        assert_eq!(
            extract(&s(&["--format", "jsonl"]), true).unwrap().0,
            Format::Jsonl
        );
        assert_eq!(
            extract(&s(&["--format=jsonl"]), true).unwrap().0,
            Format::Jsonl
        );
    }

    #[test]
    fn rendering() {
        let v = json!({"a": 1});
        assert_eq!(Format::Json.doc(&v), r#"{"a":1}"#);
        assert!(Format::JsonPretty.doc(&v).contains('\n'));
        let rows = [json!({"a": 1}), json!({"a": 2})];
        assert_eq!(Format::Jsonl.records(&rows), "{\"a\":1}\n{\"a\":2}");
        assert_eq!(Format::Jsonl.records(&[]), "");
        assert_eq!(Format::Json.records(&rows), r#"[{"a":1},{"a":2}]"#);
        let p: Value = serde_json::from_str(&Format::JsonPretty.records(&rows)).unwrap();
        assert_eq!(p.as_array().unwrap().len(), 2);
    }
}
