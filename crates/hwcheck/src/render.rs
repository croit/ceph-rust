// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Output: plain (colors only on a TTY) and json / json-pretty (Ceph `--format` convention).
use crate::{Report, Status};
use outfmt::Format;
use std::fmt::Write as _;
use std::io::IsTerminal;

pub fn stdout_tty() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn tag(s: Status, color: bool) -> String {
    let t = format!("{:<4}", s.as_str());
    if !color {
        return t;
    }
    let c = match s {
        Status::Ok => "32",
        Status::Warn => "33",
        Status::Fail => "31;1",
        Status::Na => "90",
    };
    format!("\x1b[{c}m{t}\x1b[0m")
}

pub fn render(r: &Report, f: Format, color: bool) -> String {
    match f {
        Format::Json | Format::Jsonl | Format::JsonPretty => format!("{}\n", f.doc(&r.to_json())),
        Format::Plain => plain(r, color),
    }
}

fn plain(r: &Report, color: bool) -> String {
    let mut o = String::new();
    for s in &r.sections {
        let _ = writeln!(o, "\n== {} ==", s.name);
        for c in &s.checks {
            let _ = writeln!(o, "{} {}: {}", tag(c.status, color), c.title, c.value);
            if !c.why.is_empty() {
                let _ = writeln!(o, "     why: {}", c.why);
            }
            if c.status >= Status::Warn
                && let Some(fx) = &c.fix
            {
                let _ = writeln!(o, "     fix: {fx}");
            }
        }
    }
    let _ = writeln!(o, "\n== Summary ==");
    for t in &r.tiers {
        let _ = writeln!(
            o,
            "{} {}: {}",
            tag(if t.usable { Status::Ok } else { Status::Na }, color),
            t.name,
            t.detail
        );
    }
    if !r.top_fixes.is_empty() {
        let _ = writeln!(o, "top fixes:");
        for (i, (id, fx)) in r.top_fixes.iter().enumerate() {
            let _ = writeln!(o, "  {}. [{id}] {fx}", i + 1);
        }
    }
    let _ = writeln!(
        o,
        "result: {} ok, {} warn, {} fail, {} n/a -> exit {}",
        r.count(Status::Ok),
        r.count(Status::Warn),
        r.count(Status::Fail),
        r.count(Status::Na),
        r.exit_code()
    );
    o
}
