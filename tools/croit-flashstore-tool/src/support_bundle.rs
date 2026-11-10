// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `support-bundle (--id N | --dev SPEC) --out DIR [--format F]`: READ-ONLY support collection into `DIR`.
//! Runs the existing read-only commands (`dump`, `fsck`, `inspect`, `free`, `list`), records the tool version,
//! copies the OSD's `ceph.conf` (secret option values redacted; keyring files are never copied) and, with `--id`, the tail of the OSD log. Nothing is written to the device and no
//! store is mounted read-write: every step opens the device alone, reads, and releases it. Output goes only under
//! `--out` (no default). Exit: 0 every step ok, 1 a step failed, 2 usage, 3 refused (OSD running / device held).
use crate::objectstore::{osd_running, resolve_dev};
use crate::{arg, usage_err};
use outfmt::Format;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// Bytes of the OSD log tail copied when the log is present (and larger).
const LOG_TAIL_BYTES: u64 = 256 * 1024;

/// One collected step: its exit status and the file its combined output was written to.
struct Step {
    name: &'static str,
    status: i32,
}

pub fn run(a: &[String], f: Format) -> i32 {
    let Some(out) = arg(a, "--out") else {
        return usage_err(
            "support-bundle: usage: support-bundle (--id N | --dev SPEC) --out DIR [--format plain|json|json-pretty]",
        );
    };
    let out_path = Path::new(&out);
    let cluster = match osddir::cluster_from_args(a) {
        Ok(c) => c,
        Err(e) => return usage_err(&e),
    };
    // Resolve the device (and the running OSD, if any) exactly like the other offline commands.
    let (spec, id) = match resolve_dev(a) {
        Ok((spec, who)) => {
            if let Some((d, asok)) = &who
                && osd_running(asok)
            {
                eprintln!(
                    "croit-flashstore-tool: osd.{id} is running (admin socket {asok} answers): stop it first (systemctl stop croit-flashstore-osd@{id})",
                    id = d.whoami
                );
                return 3;
            }
            (spec, who.map(|(d, _)| d.whoami))
        }
        Err(e) if e.starts_with("refused:") => {
            eprintln!("croit-flashstore-tool: {e}");
            return 3;
        }
        Err(e) => return usage_err(&e),
    };
    // A malformed `--dev` is a usage error here, not a step failure of the child `dump`.
    if let Err(e) = nvme::any::DevSpec::parse(&spec) {
        return usage_err(&format!("support-bundle: --dev {spec}: {e}"));
    }

    match bundle(&spec, id, &cluster, a, out_path, f) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("croit-flashstore-tool: support-bundle: {e}");
            1
        }
    }
}

/// Run a command, returning its exit code and the combined stdout + stderr.
fn run_cmd(bin: &Path, args: &[&str]) -> Result<(i32, Vec<u8>), String> {
    let out = std::process::Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| format!("{}: {e}", bin.display()))?;
    let code = out.status.code().unwrap_or(-1);
    let mut combined = out.stdout;
    combined.extend_from_slice(&out.stderr);
    Ok((code, combined))
}

/// Run one step: capture its combined output to `<out>/<name>.txt`, record its exit status.
fn step(
    bin: &Path,
    out: &Path,
    name: &'static str,
    args: &[&str],
    steps: &mut Vec<Step>,
) -> Result<i32, String> {
    let (code, bytes) = run_cmd(bin, args)?;
    let file = out.join(format!("{name}.txt"));
    crate::fsout::write_output(&file, &bytes).map_err(|e| format!("{}: {e}", file.display()))?;
    steps.push(Step { name, status: code });
    Ok(code)
}

fn bundle(
    spec: &str,
    id: Option<i64>,
    cluster: &str,
    a: &[String],
    out: &Path,
    f: Format,
) -> Result<i32, String> {
    private_bundle_dir(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let bin = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut steps: Vec<Step> = Vec::new();
    let mut failed = false;

    // `dump` is the first step that needs the device alone: a held device (running OSD or another tool) is refused
    // here, before any further step. Each step is a child process that opens the device, reads and releases it, so
    // the SPDK PCI claim of one step never blocks the next (adr 0649).
    let dump_out = out.join("dump");
    if std::fs::symlink_metadata(&dump_out).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!("{}: is a symlink", dump_out.display()));
    }
    let code = step(
        &bin,
        out,
        "dump",
        &[
            "dump",
            "--dev",
            spec,
            "--out",
            dump_out.to_str().ok_or("non-UTF-8 out path")?,
        ],
        &mut steps,
    )?;
    if code == 3 {
        eprintln!(
            "croit-flashstore-tool: support-bundle: refused: the device is in use (running OSD or another tool)"
        );
        return Ok(3);
    }
    failed |= code != 0;

    step(&bin, out, "fsck", &["fsck", "--dev", spec], &mut steps).map(|c| failed |= c != 0)?;
    step(
        &bin,
        out,
        "inspect",
        &["inspect", "--dev", spec],
        &mut steps,
    )
    .map(|c| failed |= c != 0)?;
    step(&bin, out, "free", &["free", "--dev", spec], &mut steps).map(|c| failed |= c != 0)?;

    // `list` scans the OSD data root (no device): forward the scope the caller gave.
    let mut list_args: Vec<String> = vec!["list".into(), "--cluster".into(), cluster.into()];
    if let Some(cf) = arg(a, "--conf") {
        list_args.push("--conf".into());
        list_args.push(cf);
    }
    if let Some(r) = arg(a, "--osd-data-root") {
        list_args.push("--osd-data-root".into());
        list_args.push(r);
    }
    let list_args: Vec<&str> = list_args.iter().map(String::as_str).collect();
    step(&bin, out, "list", &list_args, &mut steps).map(|c| failed |= c != 0)?;
    step(&bin, out, "version", &["--version"], &mut steps).map(|c| failed |= c != 0)?;

    // Config file (read-only copy) and, with --id, the tail of the OSD log (best effort: absent = omitted).
    let conf_path = osddir::conf_file(a, cluster).map_err(|e| e.to_string())?;
    if conf_path.is_file() {
        let data =
            std::fs::read(&conf_path).map_err(|e| format!("{}: {e}", conf_path.display()))?;
        let dest = out.join("ceph.conf");
        let text = redact_conf(&String::from_utf8_lossy(&data));
        crate::fsout::write_output(&dest, text.as_bytes())
            .map_err(|e| format!("{}: {e}", dest.display()))?;
    }
    if let Some(id) = id {
        let log = log_path(a, cluster, id);
        if log.is_file() {
            let tail = tail_bytes(&log, LOG_TAIL_BYTES)?;
            let dest = out.join("log.txt");
            crate::fsout::write_output(&dest, &tail)
                .map_err(|e| format!("{}: {e}", dest.display()))?;
        }
    }

    // Summary: every collected file (path relative to --out, size) and each step's exit status.
    let mut files: Vec<Value> = Vec::new();
    collect_files(out, out, &mut files);
    let steps_json: Vec<Value> = steps
        .iter()
        .map(|s| json!({"step": s.name, "status": s.status}))
        .collect();
    let v = json!({
        "dev": spec, "osd_id": id, "out": out, "ok": !failed,
        "steps": steps_json, "files": files,
    });
    if f.is_json() {
        println!("{}", f.doc(&v));
    } else {
        for s in &steps {
            println!(
                "support-bundle: {}: {}",
                s.name,
                if s.status == 0 {
                    "ok".to_string()
                } else {
                    format!("exit {}", s.status)
                }
            );
        }
        println!(
            "support-bundle: {} file(s) in {}",
            files.len(),
            out.display()
        );
    }
    Ok(i32::from(failed))
}

/// Forensic metadata can contain inline object bytes and logs can contain admin values. Restrict the bundle
/// before collecting anything, including when reusing a directory created by an earlier tool version. Refuse
/// a directory owned by another user or a symlink; neither is a safe container for root-run collection.
fn private_bundle_dir(out: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(out)?;
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(out)?;
    // SAFETY: geteuid has no preconditions.
    if dir.metadata()?.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "bundle directory must be owned by the collecting user",
        ));
    }
    dir.set_permissions(std::fs::Permissions::from_mode(0o700))
}

/// An option whose value is credential material. Ceph treats space,
/// dash and underscore in option names alike.
fn is_secret_option(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase().replace([' ', '-'], "_");
    n == "keyring"
        || ["key", "secret", "password", "passwd", "token"]
            .iter()
            .any(|word| n == *word || n.strip_suffix(word).is_some_and(|p| p.ends_with('_')))
}

/// `ceph.conf` text with the value of every secret option replaced by `<redacted>` (also its backslash
/// continuation lines). Comments, sections and other options stay verbatim.
fn redact_conf(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut continued = false;
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\n', '\r']);
        let eol = &line[body.len()..];
        if continued {
            continued = body.ends_with('\\');
            continue;
        }
        let t = body.trim_start();
        match body.split_once('=') {
            Some((name, _)) if !t.starts_with(['#', ';', '[']) && is_secret_option(name) => {
                continued = body.ends_with('\\');
                out.push_str(name.trim_end());
                out.push_str(" = <redacted>");
                out.push_str(eol);
            }
            _ => out.push_str(line),
        }
    }
    out
}

/// OSD log file: conf `log_file` (expanded like the daemon), else `/var/log/ceph/<cluster>-osd.<id>.log`.
fn log_path(a: &[String], cluster: &str, id: i64) -> PathBuf {
    let conf = crate::devopen::optional_conf(a, cluster).unwrap_or_default();
    let tmpl = conf
        .for_osd(id)
        .get("log_file")
        .cloned()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/var/log/ceph/$cluster-osd.$id.log".to_string());
    PathBuf::from(osddir::expand(&tmpl, cluster, id))
}

/// The last `max` bytes of `path` (the whole file when it is smaller).
fn tail_bytes(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    let mut buf = vec![0u8; len.min(max) as usize];
    if len > max {
        f.seek(SeekFrom::Start(len - max))
            .map_err(|e| e.to_string())?;
    }
    f.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Every regular file under `dir`, as `path` relative to `base` plus its byte size.
fn collect_files(base: &Path, dir: &Path, out: &mut Vec<Value>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        // no-follow: a symlink (to a directory or a cycle) is neither descended nor listed
        let Ok(md) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if md.is_dir() {
            collect_files(base, &p, out);
        } else if md.is_file() {
            let rel = p.strip_prefix(base).unwrap_or(&p);
            out.push(json!({"path": rel.to_string_lossy(), "bytes": md.len()}));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_directory_is_private_before_collection() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let d = std::env::temp_dir().join(format!("bundle-private-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        private_bundle_dir(&d).unwrap();
        assert_eq!(
            std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // Previous bundles were created with the ambient umask. Reusing one must close access before writes.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        private_bundle_dir(&d).unwrap();
        assert_eq!(
            std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let link = d.join("link");
        symlink(&d, &link).unwrap();
        assert!(private_bundle_dir(&link).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn conf_secret_option_values_are_redacted() {
        let conf = "[global]\nfsid = abc\n# key = commented\n[osd.1]\n\tkey = AQDsecret==\nosd_data = /x\nrgw crypt vault_key = V\\\n  continued\nadmin-secret=S\nkeyring = /etc/ceph/k\nmon_host = 1.2.3.4\n";
        let r = redact_conf(conf);
        for leak in ["AQDsecret", "continued", "=S\n", "/etc/ceph/k", "= V"] {
            assert!(!r.contains(leak), "{leak}: {r}");
        }
        for keep in [
            "fsid = abc",
            "# key = commented",
            "[osd.1]",
            "osd_data = /x",
            "mon_host = 1.2.3.4",
        ] {
            assert!(r.contains(keep), "{keep}: {r}");
        }
        assert!(
            r.contains("\tkey = <redacted>") && r.contains("admin-secret = <redacted>"),
            "{r}"
        );
        assert_eq!(
            r.lines().count(),
            conf.lines().count() - 1,
            "continuation line dropped: {r}"
        );
    }

    #[test]
    fn conf_passwords_and_tokens_from_other_daemon_sections_are_redacted() {
        // A shared ceph.conf can hold gateway credentials even when collected for an OSD.
        let conf = "[client.rgw.gateway]\nrgw_keystone_admin_password = password-value\nrgw keystone admin token = token-value\nPASSWORD=bare-password\nadmin-passwd = passwd-value\nmon_host = monitor\n";
        let r = redact_conf(conf);
        for leak in [
            "password-value",
            "token-value",
            "bare-password",
            "passwd-value",
        ] {
            assert!(!r.contains(leak), "{leak}: {r}");
        }
        assert!(r.contains("mon_host = monitor"));
    }

    #[test]
    fn collect_files_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;
        let d = std::env::temp_dir().join(format!("bundle-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("a.txt"), b"abc").unwrap();
        std::fs::write(d.join("sub/b.txt"), b"de").unwrap();
        symlink(&d, d.join("loop")).unwrap(); // cycle
        symlink(d.join("a.txt"), d.join("file-link")).unwrap();
        let mut files = Vec::new();
        collect_files(&d, &d, &mut files);
        let paths: Vec<&str> = files.iter().map(|f| f["path"].as_str().unwrap()).collect();
        assert_eq!(paths, ["a.txt", "sub/b.txt"]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
