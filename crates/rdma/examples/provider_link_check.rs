// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Offline link gate: Cargo JSONL + static libibverbs archive -> exact artifact provider closure.
//! Usage: provider_link_check [--format plain|json|json-pretty] CARGO_JSONL CORE_ARCHIVE [RELOCATABLE_OUTPUT]
//! Output fields: status (0 pass/1 failure), providers, artifact, linked_file; error on failure. Exit 2 = usage.
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::BufRead;
use std::path::Path;
use std::process::{Command, ExitCode};

fn symbols(path: &Path, defined: bool) -> Result<BTreeSet<String>, String> {
    let output = Command::new("nm")
        .arg(if defined {
            "--defined-only"
        } else {
            "--undefined-only"
        })
        .arg(path)
        .output()
        .map_err(|e| format!("nm {}: {e}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "nm {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
    Ok(text
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter(|name| {
            name.starts_with("verbs_provider_")
                && !matches!(*name, "verbs_provider_all" | "verbs_provider_none")
        })
        .map(str::to_owned)
        .collect())
}

fn check(args: &[String]) -> Result<Value, String> {
    let file = std::fs::File::open(&args[0]).map_err(|e| e.to_string())?;
    let staticlib = args.len() == 3;
    let mut executables = Vec::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.map_err(|e| e.to_string())?;
        let record: Value =
            serde_json::from_str(&line).map_err(|e| format!("Cargo record: {e}"))?;
        if record["reason"] != "compiler-artifact" {
            continue;
        }
        if staticlib && record["target"]["name"] == "rados" {
            if let Some(files) = record["filenames"].as_array() {
                executables.extend(
                    files
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|path| path.ends_with("/librados.a"))
                        .map(str::to_owned),
                );
            }
        } else if !staticlib
            && record["target"]["name"] == "rdma"
            && record["profile"]["test"] == true
            && let Some(executable) = record["executable"].as_str()
        {
            executables.push(executable.to_owned());
        }
    }
    if executables.len() != 1 {
        return Err(format!(
            "expected one current Cargo artifact, got {}",
            executables.len()
        ));
    }
    let expected = symbols(Path::new(&args[1]), false)?;
    if expected.is_empty() {
        return Err("upstream all-provider references missing".into());
    }
    let artifact = if staticlib {
        let output = Command::new("ld")
            .args([
                "-r",
                "--whole-archive",
                &executables[0],
                "--no-whole-archive",
                "-o",
                &args[2],
            ])
            .output()
            .map_err(|e| format!("ld: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "ld whole-archive: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        &args[2]
    } else {
        &executables[0]
    };
    let actual = symbols(Path::new(artifact), true)?;
    let missing: Vec<_> = expected.difference(&actual).collect();
    if !missing.is_empty() {
        return Err(format!(
            "missing providers in {}: {missing:?}",
            executables[0]
        ));
    }
    Ok(
        json!({"status":0,"providers":expected.len(),"artifact":executables[0],"linked_file":artifact}),
    )
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (format, args) = match outfmt::extract(&args, false) {
        Ok((format, args)) if args.len() == 2 || args.len() == 3 => (format, args),
        _ => {
            eprintln!(
                "usage: provider_link_check [--format plain|json|json-pretty] CARGO_JSONL CORE_ARCHIVE [RELOCATABLE_OUTPUT]"
            );
            return ExitCode::from(2);
        }
    };
    let (record, code) = match check(&args) {
        Ok(record) => (record, ExitCode::SUCCESS),
        Err(error) => (json!({"status":1,"error":error}), ExitCode::FAILURE),
    };
    if format.is_json() {
        println!("{}", format.doc(&record));
    } else {
        println!("provider-link: {record}");
    }
    code
}
