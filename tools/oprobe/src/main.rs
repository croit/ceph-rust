// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! oprobe CLI. See `oprobe help`.
use oprobe::client::{Opts, Probe, Target};
use oprobe::harness::{self, ScriptFile};
use oprobe::render::{Detail, render_reply};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const HELP: &str = "\
oprobe: dev-only RADOS client (compound MOSDOp scripts, differential harness)

global options: --conf F  --mon ADDR  --keyring F  --entity client.admin  --mode crc|secure|auto
                --timeout SECS  --resend (resend after timeout/connection loss; off by default)  -v
                --osd-src-port N (local TCP port of the OSD connections: fixed 4-tuple = same OSD accept core in every run; default: kernel picks)
commands:
  omap-workload -p POOL [options]                   configurable async OMAP cycles (see `oprobe omap-workload --help`)
  omapbench -p POOL [options]                       omap stress test (see `oprobe omapbench --help`)
  hotobj -p POOL [options]                          one hot omap object, reads + writes, with/without scans (see `oprobe hotobj --help`)
  rgwindex -p POOL [options]                        RGW bucket-index shape (see `oprobe rgwindex --help`)
  dirfrag -p POOL [options]                         CephFS dirfrag shape (see `oprobe dirfrag --help`)
  omapgate TEST -p POOL [options]                   OMAP gate cells: insert|prefill|mix-delete|mix-range|scan|delete-objects (see `oprobe omapgate --help`)
  omapscan -p POOL --object NAME [options]          full paged omap listing of one object, keys + bytes (see `oprobe omapscan --help`)
  omaprm -p POOL --object NAME --by range|keys    bulk key removal [begin, end) of one object (see `oprobe omaprm --help`)
  oneobj -p POOL --scenario S [options]             single-object access, N clients on 1 vs N objects (see `oprobe oneobj --help`)
  hash -p POOL [--prefix S] [--names F|-] [--image IMG] [--alg A]   per-object hashes + combined digest (see `oprobe hash --help`)
  fill -p POOL --objects N [options]                count-bounded filler: data+xattrs+omap keys (see `oprobe fill --help`)
  exec  -p POOL [-n NS] [-k KEY] [--osd N] [--norm] OID 'SCRIPT'|@FILE   run one compound op
        (--osd N forces the target OSD: no remap/resend, silent drop shows as NO-REPLY)
  map   -p POOL [-n NS] OID                       placement (pg, up, acting, primary)
  mon   'JSON'                                    mon command, e.g. '{\"prefix\":\"osd tree\"}'
  pool-create NAME [PGNUM] [SIZE]  | pool-delete NAME
  run     -p POOL --osd N [--scripts DIR] [NAME...]        print transcripts (objects with primary N)
  diff    -p POOL --a N --b M [--scripts DIR] [NAME...]    run on A and B, diff transcripts
  capture -p POOL --osd N --out DIR [--scripts DIR] [NAME...]   write golden transcripts
  check   -p POOL --osd N --dir DIR [--scripts DIR] [NAME...]    compare against golden transcripts
script syntax: see tools/oprobe/src/script.rs (e.g. 'write 0 \"abc\"; read 0 3; setxattr k v; getxattr k;
  omap-set k=v; omap-get-vals; stat; call rbd get_size hex:00'); files: messages separated by '---'.
";

struct Args {
    v: Vec<String>,
}

impl Args {
    /// Take `NAME VALUE` (any of `names`); `None` = absent, a trailing NAME without a value is a usage error.
    fn take(&mut self, names: &[&str]) -> Result<Option<String>, String> {
        let Some(i) = self.v.iter().position(|x| names.contains(&x.as_str())) else {
            return Ok(None);
        };
        let name = self.v.remove(i);
        if i >= self.v.len() {
            return Err(format!("{name} needs a value"));
        }
        Ok(Some(self.v.remove(i)))
    }
    fn flag(&mut self, name: &str) -> bool {
        match self.v.iter().position(|x| x == name) {
            Some(i) => {
                self.v.remove(i);
                true
            }
            None => false,
        }
    }
}

fn pool_id(p: &Probe, s: &str) -> Result<i64, String> {
    if let Ok(n) = s.parse::<i64>() {
        return Ok(n);
    }
    p.osdmap()
        .pool_id_by_name(s)
        .ok_or_else(|| format!("no pool '{s}'"))
}

/// Script text of `exec`: `@FILE` reads that file (a missing path is an error, never a script), else the words are
/// joined into one inline script.
fn script_text(args: &[String]) -> Result<String, String> {
    match args.first().and_then(|a| a.strip_prefix('@')) {
        Some(f) => std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}")),
        None => Ok(args.join(" ")),
    }
}

fn select(all: Vec<ScriptFile>, names: &[String]) -> Result<Vec<ScriptFile>, String> {
    if names.is_empty() {
        return Ok(all);
    }
    names
        .iter()
        .map(|n| {
            let n = n.trim_end_matches(".ops");
            all.iter()
                .find(|f| f.name == n)
                .cloned()
                .ok_or_else(|| format!("no script '{n}'"))
        })
        .collect()
}

fn nonce() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format!("{t:x}")
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("oprobe: {e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut a = Args {
        v: std::env::args().skip(1).collect(),
    };
    if a.v.first().is_some_and(|c| c == "--version" || c == "-V") {
        println!("oprobe {}", oprobe::VERSION);
        return Ok(ExitCode::SUCCESS);
    }
    if a.v.first().is_some_and(|c| c == "fill") && a.v.iter().any(|x| x == "-h" || x == "--help") {
        print!("{}", oprobe::fill::HELP);
        return Ok(ExitCode::SUCCESS);
    }
    if a.v.first().is_some_and(|c| c == "hash") && a.v.iter().any(|x| x == "-h" || x == "--help") {
        print!("{}", oprobe::hash::HELP);
        return Ok(ExitCode::SUCCESS);
    }
    if a.v.first().is_some_and(|c| c == "omapbench")
        && a.v.iter().any(|x| x == "-h" || x == "--help")
    {
        print!("{}", oprobe::omapbench::HELP);
        return Ok(ExitCode::SUCCESS);
    }
    for (cmd, help) in [
        ("omap-load", oprobe::omapload::HELP),
        ("omap-workload", oprobe::omapworkload::HELP),
        ("omapgate", oprobe::omapgate::HELP),
        ("hotobj", oprobe::hotobj::HELP),
        ("rmstall", oprobe::rmstall::HELP),
        ("rgwindex", oprobe::realbench::HELP_RGW),
        ("dirfrag", oprobe::realbench::HELP_DIR),
        ("omapscan", oprobe::realbench::HELP_SCAN),
        ("omaprm", oprobe::realbench::HELP_RM),
        ("oneobj", oprobe::realbench::HELP_ONE),
    ] {
        if a.v.first().is_some_and(|c| c == cmd) && a.v.iter().any(|x| x == "-h" || x == "--help") {
            print!("{help}");
            return Ok(ExitCode::SUCCESS);
        }
    }
    if a.v.is_empty() || a.flag("-h") || a.flag("--help") || a.v[0] == "help" {
        print!("{HELP}");
        return Ok(ExitCode::SUCCESS);
    }
    let mut o = Opts::default();
    if let Some(x) = a.take(&["--conf"])? {
        o.conf = x;
    }
    o.mon = a.take(&["--mon"])?;
    o.keyring = a.take(&["--keyring"])?;
    if let Some(x) = a.take(&["--entity"])? {
        o.entity = x;
    }
    if let Some(x) = a.take(&["--mode"])? {
        // the messenger mode only: a subcommand option of the same name would be taken here silently
        if !matches!(x.as_str(), "crc" | "secure" | "auto") {
            return Err(format!("--mode {x}: messenger mode crc|secure|auto"));
        }
        o.mode = x;
    }
    if let Some(x) = a.take(&["--timeout"])? {
        o.timeout = Duration::try_from_secs_f64(x.parse().map_err(|_| "bad --timeout")?)
            .ok()
            .filter(|d| !d.is_zero())
            .ok_or("--timeout must be finite and positive")?;
    }
    if let Some(x) = a.take(&["--osd-src-port"])? {
        o.osd_src_port = Some(x.parse().map_err(|_| "bad --osd-src-port")?);
    }
    o.verbose = a.flag("-v");
    o.resend_lost = a.flag("--resend");
    let pool = a.take(&["-p", "--pool"])?;
    let ns = a.take(&["-n", "--namespace"])?.unwrap_or_default();
    let key = a.take(&["-k", "--key"])?.unwrap_or_default();
    let osd = a
        .take(&["--osd"])?
        .map(|x| x.parse::<i32>().map_err(|_| "bad --osd"))
        .transpose()?;
    let osd_a = a
        .take(&["--a"])?
        .map(|x| x.parse::<i32>().map_err(|_| "bad --a"))
        .transpose()?;
    let osd_b = a
        .take(&["--b"])?
        .map(|x| x.parse::<i32>().map_err(|_| "bad --b"))
        .transpose()?;
    let scripts = PathBuf::from(
        a.take(&["--scripts"])?
            .unwrap_or_else(|| "tools/oprobe/scripts".into()),
    );
    let out_dir = a.take(&["--out", "--dir"])?;
    let norm = a.flag("--norm");
    let cmd = take_command(&mut a)?;
    let pool_arg = |what: &str| {
        pool.clone()
            .ok_or_else(|| format!("{what}: -p POOL required"))
    };
    if cmd == "omap-workload" {
        if osd.is_some() || osd_a.is_some() || osd_b.is_some() || norm {
            return Err(
                "omap-workload does not support forced OSDs or transcript normalization".into(),
            );
        }
        return oprobe::omapworkload::cli(a.v, o, pool, ns, key, out_dir);
    }

    if cmd == "fill" {
        return oprobe::fill::cli(a.v, o, pool);
    }
    if cmd == "hash" {
        return oprobe::hash::cli(a.v, o, pool);
    }
    if cmd == "rgwindex" {
        return oprobe::realbench::rgw_cli(a.v, o, pool);
    }
    if cmd == "dirfrag" {
        return oprobe::realbench::dir_cli(a.v, o, pool);
    }
    if cmd == "omapscan" {
        return oprobe::realbench::scan_cli(a.v, o, pool);
    }
    if cmd == "omaprm" {
        return oprobe::realbench::rm_cli(a.v, o, pool);
    }
    if cmd == "oneobj" {
        return oprobe::realbench::one_cli(a.v, o, pool);
    }
    if cmd == "omapbench" {
        return oprobe::omapbench::cli(a.v, o, pool);
    }
    if cmd == "omapgate" {
        return oprobe::omapgate::cli(a.v, o, pool);
    }
    if cmd == "omap-load" {
        return oprobe::omapload::cli(a.v, o, pool);
    }
    if cmd == "rmstall" {
        return oprobe::rmstall::cli(a.v, o, pool);
    }
    if cmd == "hotobj" {
        return oprobe::hotobj::cli(a.v, o, pool);
    }
    let mut p = Probe::connect(o)?;
    match cmd.as_str() {
        "mon" => {
            let j = a.v.first().ok_or("mon: JSON required")?;
            let (r, rs, data) = p.mon_command(j)?;
            println!("r={r} rs={rs:?}\n{}", String::from_utf8_lossy(&data));
            Ok(if r == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        "pool-create" => {
            let name =
                a.v.first()
                    .ok_or("pool-create NAME [PGNUM] [SIZE]")?
                    .clone();
            let pgs: u32 =
                a.v.get(1)
                    .map_or(Ok(8), |x| x.parse())
                    .map_err(|_| "bad PGNUM")?;
            let size: u32 =
                a.v.get(2)
                    .map_or(Ok(3), |x| x.parse())
                    .map_err(|_| "bad SIZE")?;
            let exists = p.osdmap().pool_id_by_name(&name).is_some();
            create_pool(&name, pgs, size, exists, |cmd| p.mon_command(cmd))?;
            let id = p.wait_pool(&name, 30)?;
            println!("pool {name} id {id}");
            Ok(ExitCode::SUCCESS)
        }
        "pool-delete" => {
            let name = a.v.first().ok_or("pool-delete NAME")?.clone();
            let (r, rs, _) = p.mon_command(&oprobe::client::pool_rm_cmd(&name))?;
            println!("delete r={r} {rs}");
            Ok(pool_delete_result(r, || p.wait_pool_gone(&name, 30)))
        }
        "map" => {
            let pid = pool_id(&p, &pool_arg("map")?)?;
            let oid = a.v.first().ok_or("map: OID required")?.clone().into_bytes();
            let t = Target {
                pool: pid,
                oid,
                nspace: ns.into_bytes(),
                key: key.into_bytes(),
                force_osd: None,
            };
            let pl = p.locate(&t)?;
            println!(
                "epoch {} raw_pg {}.{:x} pg {}.{:x} up {:?} acting {:?} primary osd.{}",
                pl.epoch,
                pl.raw_pg.pool,
                pl.raw_pg.seed,
                pl.pg.pool,
                pl.pg.seed,
                pl.up,
                pl.acting,
                pl.primary
            );
            Ok(ExitCode::SUCCESS)
        }
        "exec" => {
            let pid = pool_id(&p, &pool_arg("exec")?)?;
            if a.v.len() < 2 {
                return Err("exec: OID and SCRIPT required".into());
            }
            let oid = a.v[0].clone().into_bytes();
            let text = script_text(&a.v[1..])?;
            let t = Target {
                pool: pid,
                oid,
                nspace: ns.into_bytes(),
                key: key.into_bytes(),
                force_osd: osd,
            };
            let msgs = oprobe::script::parse_file(&text)?;
            let mut rc = 0u8;
            for m in &msgs {
                let r = p.exec(&t, m)?;
                println!(
                    "# osd.{} pg {}.{:x} acting {:?} epoch {} attempts {} mode {}{}",
                    r.osd,
                    r.placement.pg.pool,
                    r.placement.pg.seed,
                    r.placement.acting,
                    r.placement.epoch,
                    r.attempts,
                    p.conn_mode(r.osd).unwrap_or("-"),
                    if r.note.is_empty() {
                        String::new()
                    } else {
                        format!(" note: {}", r.note)
                    }
                );
                match &r.reply {
                    Some(rep) => {
                        print!(
                            "{}",
                            render_reply(
                                &r.req_ops,
                                rep,
                                if norm {
                                    Detail::Normalized
                                } else {
                                    Detail::Full
                                }
                            )
                        );
                        if rep.result < 0 {
                            rc = 1;
                        }
                    }
                    None => {
                        println!("result=NO-REPLY");
                        rc = 3;
                    }
                }
            }
            Ok(ExitCode::from(rc))
        }
        "run" | "diff" | "capture" | "check" => {
            let pid = pool_id(&p, &pool_arg(&cmd)?)?;
            let files = select(harness::load_dir(&scripts)?, &a.v)?;
            let nonce = nonce();
            let nsb = ns.as_bytes();
            let mut fails = 0;
            match cmd.as_str() {
                "run" => {
                    let osd = osd.ok_or("run: --osd N required")?;
                    for f in &files {
                        print!("{}", harness::run_file(&mut p, pid, nsb, osd, f, &nonce)?);
                    }
                }
                "capture" => {
                    let osd = osd.ok_or("capture: --osd N required")?;
                    let dir = out_dir.ok_or("capture: --out DIR required")?;
                    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                    for f in &files {
                        let t = harness::run_file(&mut p, pid, nsb, osd, f, &nonce)?;
                        let path = Path::new(&dir).join(format!("{}.out", f.name));
                        std::fs::write(&path, &t)
                            .map_err(|e| format!("{}: {e}", path.display()))?;
                        println!("captured {}", path.display());
                    }
                }
                "check" => {
                    let osd = osd.ok_or("check: --osd N required")?;
                    let dir = out_dir.ok_or("check: --dir DIR required")?;
                    for f in &files {
                        let t = harness::run_file(&mut p, pid, nsb, osd, f, &nonce)?;
                        let path = Path::new(&dir).join(format!("{}.out", f.name));
                        let want = std::fs::read_to_string(&path)
                            .map_err(|e| format!("{}: {e}", path.display()))?;
                        match harness::diff("golden", &want, &format!("osd.{osd}"), &t) {
                            None => println!("PASS {}", f.name),
                            Some(d) => {
                                fails += 1;
                                println!("FAIL {}\n{d}", f.name);
                            }
                        }
                    }
                }
                _ => {
                    let (x, y) = (
                        osd_a.ok_or("diff: --a N required")?,
                        osd_b.ok_or("diff: --b M required")?,
                    );
                    for f in &files {
                        let ta = harness::run_file(&mut p, pid, nsb, x, f, &nonce)?;
                        let tb = harness::run_file(&mut p, pid, nsb, y, f, &nonce)?;
                        match harness::diff(&format!("osd.{x}"), &ta, &format!("osd.{y}"), &tb) {
                            None => println!("SAME {}", f.name),
                            Some(d) => {
                                fails += 1;
                                println!("DIFF {}\n{d}", f.name);
                            }
                        }
                    }
                }
            }
            println!("{} script(s), {fails} mismatch(es)", files.len());
            Ok(if fails == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        o => Err(format!("unknown command '{o}' (try help)")),
    }
}

fn create_pool(
    name: &str,
    pgs: u32,
    size: u32,
    exists: bool,
    mut command: impl FnMut(&str) -> Result<(i32, String, Vec<u8>), String>,
) -> Result<(), String> {
    if exists {
        return Err(format!("pool-create: pool {name:?} already exists"));
    }
    let (r, status, _) = command(&oprobe::client::pool_create_cmd(name, pgs))?;
    if r != 0 {
        return Err(format!("pool-create: create failed r={r}: {status}"));
    }
    let (r, status, _) = command(&oprobe::client::pool_size_cmd(name, size))?;
    if r != 0 {
        return Err(format!("pool-create: set size failed r={r}: {status}"));
    }
    Ok(())
}

fn pool_delete_result(result: i32, wait_gone: impl FnOnce() -> bool) -> ExitCode {
    if result == 0 && wait_gone() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn take_command(a: &mut Args) -> Result<String, String> {
    if a.v.is_empty() {
        return Err("command required (try help)".into());
    }
    Ok(a.v.remove(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_pool_creation_never_changes_existing_pool_size() {
        let mut commands = Vec::new();
        assert!(
            create_pool("existing", 8, 1, true, |_| panic!(
                "must not mutate existing pool"
            ))
            .is_err()
        );
        let error = create_pool("existing", 8, 1, false, |cmd| {
            commands.push(cmd.to_owned());
            Ok((-17, "pool exists".into(), Vec::new()))
        })
        .unwrap_err();
        assert!(error.contains("create failed"));
        assert_eq!(commands.len(), 1);
        assert!(commands[0].contains("osd pool create"));
        let mut calls = 0;
        let error = create_pool("new", 8, 3, false, |_| {
            calls += 1;
            Ok((if calls == 1 { 0 } else { -1 }, String::new(), Vec::new()))
        })
        .unwrap_err();
        assert!(error.contains("set size failed"));
        assert_eq!(calls, 2);
    }

    #[test]
    fn pool_delete_timeout_and_command_failure_do_not_report_success() {
        assert_eq!(pool_delete_result(0, || false), ExitCode::from(1));
        assert_eq!(
            pool_delete_result(-1, || panic!("failed command must not wait")),
            ExitCode::from(1)
        );
        assert_eq!(pool_delete_result(0, || true), ExitCode::SUCCESS);
    }

    #[test]
    fn globals_without_a_command_are_a_usage_error() {
        let mut a = Args {
            v: vec!["--timeout".into(), "1".into()],
        };
        assert_eq!(a.take(&["--timeout"]).unwrap().as_deref(), Some("1"));
        assert!(
            take_command(&mut a)
                .unwrap_err()
                .contains("command required")
        );
    }

    #[test]
    fn exec_file_argument_is_read_or_fails_loudly() {
        let dir = std::env::temp_dir().join(format!("oprobe-exec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("a.ops");
        std::fs::write(&file, "read 0 1\n").expect("write");
        assert_eq!(
            script_text(&[format!("@{}", file.display())]).unwrap(),
            "read 0 1\n"
        );
        let missing = dir.join("typo.ops");
        let e = script_text(&[format!("@{}", missing.display())]).unwrap_err();
        assert!(e.contains("typo.ops"), "{e}");
        assert_eq!(script_text(&["read 0 1".into()]).unwrap(), "read 0 1");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_trailing_global_option_is_a_usage_error() {
        let mut a = Args {
            v: vec!["--mon".into()],
        };
        assert_eq!(a.take(&["--mon"]).unwrap_err(), "--mon needs a value");
        let mut a = Args {
            v: vec!["--mon".into(), "v2:1.2.3.4:3300".into()],
        };
        assert_eq!(
            a.take(&["--mon"]).unwrap().as_deref(),
            Some("v2:1.2.3.4:3300")
        );
        assert!(a.take(&["--mon"]).unwrap().is_none());
    }
}
