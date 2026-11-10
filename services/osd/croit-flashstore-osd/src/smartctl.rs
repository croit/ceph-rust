// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Classic `smart` route (adr 0056 am. 2, doc/spec/devicehealth.md "Classic SMART probe"): the OSD runs without
//! CAP_SYS_ADMIN, so on the kernel tier the NVMe admin passthrough is refused. Classic Ceph then gets the data from
//! `sudo smartctl -x --json=o /dev/<dev>` plus, for a known vendor, `sudo nvme <vendor> smart-log-add --json /dev/<dev>`
//! (sudoers rule of the ceph packages) and returns smartctl's JSON object with the vendor additions merged in. This module
//! runs the same two commands (`-n`: never ask for a password) and builds the same object. Runs on the SMART refresh
//! thread only, never on a core; every child has a hard timeout.
use serde_json::{Value, json};
use std::os::fd::AsRawFd;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

/// Classic `osd_smart_report_timeout` default: seconds per child process.
pub const TIMEOUT: Duration = Duration::from_secs(5);
/// Classic reads at most this much stdout.
const MAX_OUT: u64 = 100 * 1024;
const EINVAL: i64 = 22;

/// A finished child: exit code (`None` = killed by a signal), captured stdout and stderr.
#[derive(Debug)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Runs `sudo -n <args>`; `Err` = the child could not be started, read, or timed out.
pub type Runner<'a> = &'a dyn Fn(&[&str]) -> Result<Output, String>;

/// The real runner: `sudo -n <args>` with stdin closed and a hard timeout (loud when it fires). `sudo` is resolved in
/// the fixed root-owned system dirs ([`hwcheck::action::SYSTEM_PATH`], incl. the NixOS setuid wrapper), never through
/// the inherited `PATH` (a poisoned `PATH` in a root OSD would run a foreign binary as root).
pub fn run_sudo(args: &[&str]) -> Result<Output, String> {
    let sudo = hwcheck::action::resolve("sudo").ok_or_else(|| {
        format!(
            "sudo: not found in {} (the inherited PATH is not used)",
            hwcheck::action::SYSTEM_PATH.join(":")
        )
    })?;
    let sudo = sudo.to_str().ok_or("sudo: path is not UTF-8")?;
    run_group(sudo, &[&["-n"], args].concat(), TIMEOUT)
}

/// Signals the process group `pgid` (the group of a child we spawned ourselves, never found by name).
fn signal_group(pgid: u32, sig: i32) {
    // SAFETY: plain kill(2) on the negative pid of the group we created with `process_group(0)`.
    unsafe { libc::kill(-(pgid as i32), sig) };
}

/// Runs `program args` in its own process group with stdin closed and a hard `timeout`. On timeout the whole group is
/// signalled: SIGTERM first (sudo relays it to the root-owned command, which an unprivileged SIGKILL cannot reach), then
/// SIGKILL, so no orphan (smartctl behind sudo) survives.
///
/// Event-driven: one thread waits for the child and signals its exit through a pipe, the caller `poll`s the two output
/// pipes and that one until the deadline or the child's exit, so neither a chatty nor a silent child makes it spin. After the child is gone the pipes are drained of what
/// they hold now (a process that left the group may keep them open) and the readers are gone with this function.
fn run_group(program: &str, args: &[&str], timeout: Duration) -> Result<Output, String> {
    use std::os::unix::process::CommandExt;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("error spawning {program}: {e}"))?;
    let pgid = child.id();
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let (tx, rx) = std::sync::mpsc::channel();
    // the waiter closes `exit_w` after it reaped the child: `exit_r` hangs up and wakes the `poll` below, also when a
    // quiet descendant still holds stdout/stderr open
    let (exit_r, exit_w) = std::io::pipe().map_err(|e| format!("pipe for {program}: {e}"))?;
    let waiter = std::thread::spawn(move || {
        let _ = tx.send(child.wait());
        drop(exit_w);
    });
    let end = Instant::now() + timeout;
    // Keeps at most MAX_OUT bytes and drains the rest: a child blocked on a full pipe would run into the timeout on every
    // scrape. The truncated text is not valid JSON, so `metrics` reports the classic invalid-JSON error object.
    let mut o = Vec::new();
    let mut e = Vec::new();
    let mut status: Option<std::io::Result<ExitStatus>> = None;
    loop {
        let child_gone = status.is_some();
        if Instant::now() >= end {
            if !child_gone {
                return timed_out(&rx, waiter, program, args, timeout, pgid);
            }
            // a process that left the group keeps writing: its output past the deadline is not the child's answer
            break;
        }
        let mut fds: Vec<libc::pollfd> = Vec::with_capacity(2);
        for fd in [
            out.as_ref().map(AsRawFd::as_raw_fd),
            err.as_ref().map(AsRawFd::as_raw_fd),
        ]
        .into_iter()
        .flatten()
        {
            fds.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if !child_gone {
            fds.push(libc::pollfd {
                fd: exit_r.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        } else if fds.is_empty() {
            break;
        }
        let ms = if child_gone {
            0
        } else {
            (end.saturating_duration_since(Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32)
                .saturating_add(1)
        };
        // SAFETY: poll(2) on the pipe fds this call owns; bounded by the child's timeout (0 = the final drain).
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // the pipes cannot be watched: end the group, so the reap below cannot wait for it
            signal_group(pgid, libc::SIGKILL);
            let _ = rx.recv();
            let _ = waiter.join();
            return Err(format!("poll {program}: {err}"));
        }
        if n == 0 {
            if child_gone {
                break;
            }
            return timed_out(&rx, waiter, program, args, timeout, pgid);
        }
        let mut i = 0;
        if out.is_some() {
            let rev = fds[i].revents;
            if rev != 0 && osd::child::drain_pipe(&mut out, &mut o, rev, MAX_OUT as usize) {
                out = None;
            }
            i += 1;
        }
        if err.is_some() {
            let rev = fds[i].revents;
            if rev != 0 && osd::child::drain_pipe(&mut err, &mut e, rev, MAX_OUT as usize) {
                err = None;
            }
        }
        if !child_gone {
            match rx.try_recv() {
                Ok(s) => status = Some(s),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => break,
            }
        }
    }
    let _ = waiter.join();
    let status = match status {
        Some(r) => r.map_err(|e| format!("waiting for {program}: {e}"))?,
        None => return Err(format!("waiting for {program}: the child was not reaped")),
    };
    Ok(Output {
        code: status.code(),
        stdout: String::from_utf8_lossy(&o).into_owned(),
        stderr: String::from_utf8_lossy(&e).into_owned(),
    })
}

/// The timeout fired: SIGTERM the group, give it a short grace (the waiter reports the exit), SIGKILL, reap, and fail
/// loudly. Both readers are gone with this function, so a process that left the group cannot leak them.
fn timed_out(
    rx: &Receiver<std::io::Result<ExitStatus>>,
    waiter: std::thread::JoinHandle<()>,
    program: &str,
    args: &[&str],
    timeout: Duration,
    pgid: u32,
) -> Result<Output, String> {
    signal_group(pgid, libc::SIGTERM);
    // the grace lets sudo relay SIGTERM; then SIGKILL the group whether or not the direct child left (a descendant that
    // ignores SIGTERM stays in the group)
    let exited = rx.recv_timeout(Duration::from_secs(1)).is_ok();
    signal_group(pgid, libc::SIGKILL);
    if !exited {
        let _ = rx.recv();
    }
    let _ = waiter.join();
    eprintln!(
        "WARNING TIMEOUT {program} {} exceeded {}s (smart probe; process group {pgid} killed)",
        args.join(" "),
        timeout.as_secs_f64()
    );
    Err(format!("{program} {} timed out", args.join(" ")))
}

/// smartctl exit status bits 0 (command line) and 1 (device open / identify failed) are errors; the rest only flag
/// findings in the data.
fn smartctl_failed(o: &Output) -> bool {
    o.code.is_none_or(|c| c & 3 != 0)
}

/// `{devid}` value of the `smart` reply for `/dev/<name>`: smartctl's JSON object (plus `nvme_vendor` and
/// `nvme_smart_health_information_add_log`), or the classic error object when a command fails. `vendor` is the
/// lowercase drive vendor (see [`vendor`]); empty = unknown.
pub fn metrics(name: &str, vendor: &str, run: Runner) -> Value {
    let dev = format!("/dev/{name}");
    let mut base = match run(&["smartctl", "-x", "--json=o", &dev]) {
        Err(e) => error_obj("smartctl failed", &dev, -EINVAL, &e),
        Ok(o) if smartctl_failed(&o) => {
            let msg = format!(
                "smartctl returned an error ({}): stderr:\n{}\nstdout:\n{}",
                o.code
                    .map_or_else(|| "signal".to_owned(), |c| c.to_string()),
                o.stderr,
                o.stdout
            );
            error_obj("smartctl failed", &dev, -EINVAL, &msg)
        }
        Ok(o) => match serde_json::from_str::<Value>(&o.stdout) {
            Ok(v @ Value::Object(_)) => v,
            _ => json!({"error": "smartctl returned invalid JSON", "dev": dev, "output": o.stdout}),
        },
    };
    let Some(b) = base.as_object_mut() else {
        return base;
    };
    if vendor.is_empty() {
        b.insert("nvme_vendor".into(), json!("unknown"));
        return base;
    }
    b.insert("nvme_vendor".into(), json!(vendor));
    match run(&["nvme", vendor, "smart-log-add", "--json", &dev]) {
        Ok(o) if o.code == Some(0) => match serde_json::from_str::<Value>(&o.stdout) {
            Ok(v) => {
                b.insert("nvme_smart_health_information_add_log".into(), v);
            }
            Err(_) => {
                b.insert(
                    "nvme_smart_health_information_add_log_error".into(),
                    json!(format!("bad json output: {}", o.stdout)),
                );
            }
        },
        r => {
            let msg = match r {
                Ok(o) => format!("nvme returned an error: {}", o.stderr),
                Err(e) => e,
            };
            b.insert(
                "nvme_smart_health_information_add_log_error_code".into(),
                json!(-EINVAL),
            );
            b.insert(
                "nvme_smart_health_information_add_log_error".into(),
                json!(msg),
            );
        }
    }
    base
}

fn error_obj(what: &str, dev: &str, code: i64, output: &str) -> Value {
    json!({"error": what, "dev": dev, "smartctl_error_code": code, "smartctl_output": output})
}

/// The `error` text of a [`metrics`] value that carries the classic error object.
pub fn failure(v: &Value) -> Option<&str> {
    v.get("error").and_then(Value::as_str)
}

/// Drive vendor as classic derives it for `nvme <vendor> smart-log-add`: udev `ID_VENDOR` (lowercased), else the first
/// word of udev `ID_MODEL` (lowercased), else sysfs `vendor`, else the first word of the sysfs `model`. Empty = unknown.
pub fn vendor(udev_vendor: &str, udev_model: &str, sys_vendor: &str, sys_model: &str) -> String {
    let first = |s: &str| s.split(' ').next().unwrap_or("").to_owned();
    if !udev_vendor.is_empty() {
        udev_vendor.to_lowercase()
    } else if !udev_model.is_empty() {
        first(&udev_model.to_lowercase())
    } else if !sys_vendor.is_empty() {
        sys_vendor.to_owned()
    } else {
        first(sys_model)
    }
}

/// Vendor of the kernel block device `name` from the udev database and sysfs (empty when none is readable).
pub fn read_vendor(name: &str) -> String {
    let sys = |f: &str| {
        std::fs::read_to_string(format!("/sys/block/{name}/device/{f}"))
            .map(|s| s.trim().to_owned())
            .unwrap_or_default()
    };
    let (mut uv, mut um) = (String::new(), String::new());
    if let Ok(devno) = std::fs::read_to_string(format!("/sys/block/{name}/dev"))
        && let Ok(db) = std::fs::read_to_string(format!("/run/udev/data/b{}", devno.trim()))
    {
        for l in db.lines() {
            if let Some(v) = l.strip_prefix("E:ID_VENDOR=") {
                uv = v.to_owned();
            } else if let Some(v) = l.strip_prefix("E:ID_MODEL=") {
                um = v.to_owned();
            }
        }
    }
    vendor(&uv, &um, &sys("vendor"), &sys("model"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(code: i32, out: &str, err: &str) -> Result<Output, String> {
        Ok(Output {
            code: Some(code),
            stdout: out.into(),
            stderr: err.into(),
        })
    }

    #[test]
    fn large_output_is_drained_and_truncated() {
        // 300 KiB on stdout would block the child on a full pipe if the reader stopped at MAX_OUT.
        let t = Instant::now();
        let o = run_group(
            "sh",
            &["-c", "head -c 307200 /dev/zero | tr '\\0' x"],
            Duration::from_secs(20),
        )
        .expect("no timeout");
        assert!(t.elapsed() < Duration::from_secs(10));
        assert_eq!(o.code, Some(0));
        assert_eq!(o.stdout.len() as u64, MAX_OUT);
        let m = metrics("nvme0n1", "", &|_| {
            Ok(Output {
                code: Some(0),
                ..o_clone(&o)
            })
        });
        assert_eq!(m["error"], "smartctl returned invalid JSON");
    }

    fn o_clone(o: &Output) -> Output {
        Output {
            code: o.code,
            stdout: o.stdout.clone(),
            stderr: o.stderr.clone(),
        }
    }

    #[test]
    fn json_passthrough_with_vendor_additions() {
        let run = |a: &[&str]| match a[0] {
            "smartctl" => {
                assert_eq!(a, ["smartctl", "-x", "--json=o", "/dev/nvme2n1"]);
                // exit status 32 (old self-test errors) only flags findings: data is still valid
                ok(
                    32,
                    r#"{"model_name":"X","nvme_smart_health_information_log":{"percentage_used":3}}"#,
                    "",
                )
            }
            _ => {
                assert_eq!(
                    a,
                    ["nvme", "samsung", "smart-log-add", "--json", "/dev/nvme2n1"]
                );
                ok(0, r#"{"Device stats":{"x":1}}"#, "")
            }
        };
        let v = metrics("nvme2n1", "samsung", &run);
        assert_eq!(v["model_name"], "X");
        assert_eq!(v["nvme_smart_health_information_log"]["percentage_used"], 3);
        assert_eq!(v["nvme_vendor"], "samsung");
        assert_eq!(
            v["nvme_smart_health_information_add_log"]["Device stats"]["x"],
            1
        );
        assert!(failure(&v).is_none());
    }

    #[test]
    fn unknown_vendor_skips_the_nvme_command() {
        let run = |a: &[&str]| {
            assert_eq!(a[0], "smartctl");
            ok(0, r#"{"a":1}"#, "")
        };
        let v = metrics("nvme0n1", "", &run);
        assert_eq!(v["nvme_vendor"], "unknown");
        assert!(v.get("nvme_smart_health_information_add_log").is_none());
    }

    #[test]
    fn smartctl_open_failure_is_the_classic_error_object() {
        // exit bit 1: device open failed (sudo refusing gives exit 1: bit 0)
        let run = |_: &[&str]| ok(1, "", "sudo: a password is required\n");
        let v = metrics("nvme1n1", "", &run);
        assert_eq!(failure(&v), Some("smartctl failed"));
        assert_eq!(v["dev"], "/dev/nvme1n1");
        assert_eq!(v["smartctl_error_code"], -22);
        let o = v["smartctl_output"].as_str().unwrap();
        assert!(
            o.contains("a password is required") && o.contains("(1)"),
            "{o}"
        );
        // reply is still valid JSON text with quotes in the output
        let q = |_: &[&str]| ok(2, "{\"json\":\"x\"}", "e\"q");
        assert!(serde_json::to_string(&metrics("n", "", &q)).is_ok());
    }

    #[test]
    fn spawn_failure_and_bad_json() {
        let run = |_: &[&str]| Err("error spawning sudo: No such file or directory".to_owned());
        let v = metrics("n", "samsung", &run);
        assert_eq!(failure(&v), Some("smartctl failed"));
        assert!(
            v["smartctl_output"]
                .as_str()
                .unwrap()
                .contains("spawning sudo")
        );
        let bad = |_: &[&str]| ok(0, "not json", "");
        assert_eq!(
            failure(&metrics("n", "", &bad)),
            Some("smartctl returned invalid JSON")
        );
    }

    #[test]
    fn vendor_command_failures_are_recorded_not_fatal() {
        let run = |a: &[&str]| match a[0] {
            "smartctl" => ok(0, r#"{"a":1}"#, ""),
            _ => ok(1, "", "no such vendor"),
        };
        let v = metrics("n", "acme", &run);
        assert_eq!(v["a"], 1);
        assert_eq!(v["nvme_smart_health_information_add_log_error_code"], -22);
        assert!(
            v["nvme_smart_health_information_add_log_error"]
                .as_str()
                .unwrap()
                .contains("no such vendor")
        );
        let badj = |a: &[&str]| match a[0] {
            "smartctl" => ok(0, "{}", ""),
            _ => ok(0, "oops", ""),
        };
        assert_eq!(
            metrics("n", "acme", &badj)["nvme_smart_health_information_add_log_error"],
            "bad json output: oops"
        );
    }

    #[test]
    fn vendor_derivation_order() {
        assert_eq!(vendor("ACME", "m x", "sv", "sm y"), "acme");
        assert_eq!(vendor("", "SAMSUNG MZQL2", "sv", "sm y"), "samsung");
        assert_eq!(vendor("", "", "sv", "sm y"), "sv");
        assert_eq!(vendor("", "", "", "Micron 7450"), "Micron");
        assert_eq!(vendor("", "", "", ""), "");
    }

    /// `sudo` is spawned by its absolute path, never through the inherited PATH (a poisoned PATH would run a foreign
    /// binary as root). Runs itself as a child with a PATH that starts in a directory holding a fake `sudo`.
    #[test]
    fn sudo_is_not_resolved_through_path() {
        use std::os::unix::fs::PermissionsExt;
        let Ok(marker) = std::env::var("SUDO_PATH_CHILD") else {
            let dir = std::env::temp_dir().join(format!("smartctl-path-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let marker = dir.join("ran");
            std::fs::write(
                dir.join("sudo"),
                format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
            )
            .unwrap();
            std::fs::set_permissions(dir.join("sudo"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "smartctl::tests::sudo_is_not_resolved_through_path",
                ])
                .env("SUDO_PATH_CHILD", &marker)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(!marker.exists(), "the PATH sudo ran");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        };
        let dir = std::path::Path::new(&marker)
            .parent()
            .unwrap()
            .to_path_buf();
        // SAFETY: the child is a dedicated single-threaded test process for this one check.
        unsafe { std::env::set_var("PATH", &dir) };
        let _ = run_sudo(&["true"]);
        std::process::exit(i32::from(std::path::Path::new(&marker).exists()));
    }

    /// A probe that answers and exits while a quiet descendant keeps stdout open is a success, returned at its exit (not
    /// at the deadline): the waiter's exit pipe wakes the poll.
    #[test]
    fn an_answer_with_a_quiet_descendant_is_returned_at_exit() {
        let t = Instant::now();
        let o = run_group(
            "sh",
            &["-c", "sleep 4 & echo '{\"ok\":1}'"],
            Duration::from_secs(5),
        )
        .expect("the child answered and exited");
        assert_eq!(o.code, Some(0));
        assert_eq!(o.stdout.trim(), "{\"ok\":1}");
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    }

    /// Real child: a missing or failing `sudo -n` yields an error value, never a hang or panic.
    #[test]
    fn real_runner_reports_failure_without_blocking() {
        let t = Instant::now();
        let r = run_sudo(&["true"]);
        assert!(
            t.elapsed() < TIMEOUT + Duration::from_secs(2),
            "runner overran its timeout"
        );
        // sudo present without a rule: non-zero exit; absent: spawn error; root with rule: ok
        if let Ok(o) = r {
            assert!(o.code.is_some());
        }
    }

    /// A pid that is gone or a reaped-less zombie (PID 1 without `--init` does not reap) counts as dead: `kill(pid, 0)`
    /// keeps succeeding for a zombie.
    fn process_gone(pid: i32) -> bool {
        // SAFETY: signal 0 only probes existence of the pid we recorded.
        if unsafe { libc::kill(pid, 0) } != 0 {
            return true;
        }
        std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
            s.rsplit(')')
                .next()
                .is_some_and(|rest| rest.trim_start().starts_with('Z'))
        })
    }

    /// A killed grandchild reparented to a PID 1 that does not reap stays a zombie: `kill(pid, 0)` keeps succeeding for
    /// it. The group-kill check must treat it as gone (no dependency on the container's init).
    #[test]
    fn a_zombie_grandchild_counts_as_gone() {
        // SAFETY: fork + _exit in the child (async-signal-safe); the parent reaps it by exact pid below.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        let is_zombie = || {
            std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
                s.rsplit(')')
                    .next()
                    .is_some_and(|rest| rest.trim_start().starts_with('Z'))
            })
        };
        let end = Instant::now() + Duration::from_secs(5);
        while !is_zombie() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            // SAFETY: signal 0 only probes existence of our own child.
            unsafe { libc::kill(pid, 0) } == 0,
            "the zombie must still answer kill(0), else this test proves nothing"
        );
        assert!(process_gone(pid), "a zombie child counts as gone");
        // SAFETY: reaps our own child by exact pid.
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    }

    /// Slow fake command with a grandchild: the timeout kills the whole group, no orphan survives.
    #[test]
    fn timeout_kills_the_process_group() {
        let pidf = std::env::temp_dir().join(format!("smartctl-grandchild-{}", std::process::id()));
        let script = format!("sleep 30 & echo $! > {}; wait", pidf.display());
        let t = Instant::now();
        let r = run_group("sh", &["-c", &script], Duration::from_millis(500));
        assert!(r.unwrap_err().contains("timed out"));
        assert!(t.elapsed() < Duration::from_secs(5));
        let pid: i32 = std::fs::read_to_string(&pidf)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let _ = std::fs::remove_file(&pidf);
        // the grandchild is gone (or a zombie nobody reaps); poll briefly
        let end = Instant::now() + Duration::from_secs(5);
        while !process_gone(pid) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(process_gone(pid), "grandchild {pid} survived the timeout");
    }

    /// A process that left the child's group (`setsid`) keeps the pipes open after the group kill. The timeout path must
    /// still stop and join both readers instead of leaking them.
    #[test]
    fn a_timed_out_runner_leaves_no_reader_thread() {
        const CHILD: &str = "FLASHSTORE_SMARTCTL_READERS_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "smartctl::tests::a_timed_out_runner_leaves_no_reader_thread",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "child: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        let threads = || std::fs::read_dir("/proc/self/task").unwrap().count();
        let before = threads();
        // the escaped sleep holds stdout/stderr; only the stop flag can end the readers
        let r = run_group(
            "sh",
            &["-c", "setsid sleep 3 & sleep 30"],
            Duration::from_millis(300),
        );
        assert!(r.unwrap_err().contains("timed out"));
        let end = Instant::now() + Duration::from_secs(2);
        while threads() > before && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(threads(), before, "reader threads leaked");
    }
}
