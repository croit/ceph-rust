// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! CRUSH location of the OSD, fixed once at start (spec osd-lifecycle.md 1.4): option `crush_location`, else the
//! output of the executable `crush_location_hook`, else `host=<short hostname>`, `root=default`. An invalid location
//! or a failed hook is an error: the OSD never falls back to the default (that would move it out of its failure domain).
use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

/// Hook stdout read limit (bytes).
const HOOK_OUT_MAX: u64 = 100 * 1024;

/// Location as sorted `(type, name)` pairs.
pub type Location = Vec<(String, String)>;

/// A bucket type or name the mon accepts: `[A-Za-z0-9-_.]+`.
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

/// Parse location text: tokens separated by runs of `;`, `,`, space or tab; each `type=name` with a non-empty name.
/// A repeated type keeps the last name. Any bad token, or no token at all, rejects the whole text.
pub fn parse(text: &str) -> Result<Location, String> {
    let mut m: BTreeMap<String, String> = BTreeMap::new();
    for tok in text.split([';', ',', ' ', '\t']).filter(|t| !t.is_empty()) {
        let Some((k, v)) = tok.split_once('=') else {
            return Err(format!("{tok:?} is not type=name"));
        };
        if v.is_empty() {
            return Err(format!("{tok:?} has an empty name"));
        }
        if !valid_name(k) || !valid_name(v) {
            return Err(format!(
                "{tok:?}: bucket types and names must match [A-Za-z0-9-_.]+"
            ));
        }
        m.insert(k.to_owned(), v.to_owned());
    }
    if m.is_empty() {
        return Err("no type=name pair".into());
    }
    Ok(m.into_iter().collect())
}

/// The monotonic deadline `t` from now. A timeout the clock cannot hold is an error, never a panic: the schema of
/// `crush_location_hook_timeout` has no max (up to `i64::MAX` s).
fn deadline(t: Duration) -> Result<Instant, String> {
    Instant::now().checked_add(t).ok_or_else(|| {
        format!(
            "crush_location_hook_timeout {}s is beyond the monotonic clock",
            t.as_secs_f64()
        )
    })
}

/// Run the hook `path --cluster <cluster> --id <id> --type osd` (stdin closed, own process group) and return its
/// stdout (first 100 KiB, trailing whitespace stripped). `timeout` `None` = no limit; on expiry the group is killed.
///
/// Event-driven: `poll` waits on both pipes (data, EOF) until the deadline, while a waiter thread reaps the child; the
/// reads are therefore bounded by the same deadline. A child that exits but leaves a grandchild holding stdout or
/// stderr keeps the pipe open, so the deadline fires (`WARNING TIMEOUT`), the whole group is killed and the hook fails;
/// it never hangs the OSD start.
pub fn run_hook(
    path: &str,
    cluster: &str,
    id: i32,
    timeout: Option<Duration>,
) -> Result<String, String> {
    // before the spawn: an error here must not leave a hook running
    let end = timeout.map(deadline).transpose()?;
    let mut child = Command::new(path)
        .args([
            "--cluster",
            cluster,
            "--id",
            &id.to_string(),
            "--type",
            "osd",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("cannot run {path:?}: {e}"))?;
    let pgid = child.id() as libc::pid_t;
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    // the waiter reaps the child: the main path only blocks in `poll` (pipes) or in `recv`/`recv_timeout` (its exit), so
    // neither a chatty hook nor a silent one makes it spin
    let (tx, rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let _ = tx.send(child.wait());
    });
    let mut status: Option<std::io::Result<ExitStatus>> = None;
    let mut o = Vec::new();
    let mut e = Vec::new();
    loop {
        if let Some(limit) = end
            && Instant::now() >= limit
        {
            return timeout_fired(&rx, waiter, pgid, path, id, timeout);
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
        if fds.is_empty() {
            // no pipe left: wait for the child's exit (bounded by the hook timeout)
            let r = match end {
                Some(limit) => rx.recv_timeout(limit.saturating_duration_since(Instant::now())),
                None => rx
                    .recv()
                    .map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected),
            };
            match r {
                Ok(s) => status = Some(s),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    return timeout_fired(&rx, waiter, pgid, path, id, timeout);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
            break;
        }
        let ms = end.map_or(-1, |limit| {
            (limit
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32)
                .saturating_add(1)
        });
        // SAFETY: poll(2) on the two pipe fds this call owns, bounded by the hook deadline.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // the pipes cannot be watched: end the hook's group, so the reap below cannot wait for it
            // SAFETY: plain syscall on the hook's own process group (it was started with process_group(0)).
            unsafe { libc::killpg(pgid, libc::SIGKILL) };
            let _ = rx.recv();
            let _ = waiter.join();
            return Err(format!("{path:?}: poll: {err}"));
        }
        if n == 0 {
            return timeout_fired(&rx, waiter, pgid, path, id, timeout);
        }
        // index 0 = stdout, 1 = stderr, in the order they were pushed (a closed pipe drops out)
        let mut i = 0;
        if out.is_some() {
            let rev = fds[i].revents;
            if rev != 0 && crate::child::drain_pipe(&mut out, &mut o, rev, HOOK_OUT_MAX as usize) {
                out = None;
            }
            i += 1;
        }
        if err.is_some() {
            let rev = fds[i].revents;
            if rev != 0 && crate::child::drain_pipe(&mut err, &mut e, rev, HOOK_OUT_MAX as usize) {
                err = None;
            }
        }
        // the waiter sends once and leaves: after the status the pipes alone decide (EOF or the deadline)
        if status.is_none() {
            match rx.try_recv() {
                Ok(s) => status = Some(s),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => break,
            }
        }
        // the hook is done when it exited and both pipes reached EOF (a leftover grandchild keeps them open on purpose:
        // that is the deadline's case above)
        if status.is_some() && out.is_none() && err.is_none() {
            break;
        }
    }
    let _ = waiter.join();
    let status = match status {
        Some(r) => r.map_err(|e| format!("{path:?}: wait: {e}"))?,
        None => return Err(format!("{path:?}: wait: the child was not reaped")),
    };
    if !status.success() {
        return Err(format!(
            "{path:?} failed ({status}); stderr: {:?}",
            String::from_utf8_lossy(&e).trim()
        ));
    }
    let s = String::from_utf8_lossy(&o);
    Ok(s.trim_end_matches([' ', '\n', '\r', '\t']).to_owned())
}

/// The hook deadline fired: kill its own process group (the direct child and every grandchild), reap it, tell the
/// operator and fail. A leftover grandchild that held a pipe open dies here too.
fn timeout_fired(
    rx: &Receiver<std::io::Result<ExitStatus>>,
    waiter: std::thread::JoinHandle<()>,
    pgid: libc::pid_t,
    path: &str,
    id: i32,
    timeout: Option<Duration>,
) -> Result<String, String> {
    // SAFETY: plain syscall on the hook's own process group (it was started with process_group(0)).
    unsafe { libc::killpg(pgid, libc::SIGKILL) };
    let _ = rx.recv();
    let _ = waiter.join();
    let t = timeout.unwrap_or_default();
    eprintln!(
        "WARNING TIMEOUT crush_location_hook exceeded {}s ({path} --id {id})",
        t.as_secs_f64()
    );
    Err(format!(
        "{path:?} did not finish within crush_location_hook_timeout {}s (killed)",
        t.as_secs_f64()
    ))
}

/// The OSD's location from its config lookup `get` (precedence option > hook > default). Errors name the option.
pub fn resolve(
    get: impl Fn(&str) -> Option<String>,
    hostname: &str,
    whoami: i32,
) -> Result<Location, String> {
    let opt = get("crush_location").unwrap_or_default();
    if !opt.trim().is_empty() {
        return parse(&opt).map_err(|e| format!("crush_location {opt:?}: {e}"));
    }
    let hook = get("crush_location_hook").unwrap_or_default();
    if !hook.trim().is_empty() {
        let hook = hook.trim();
        let secs = get("crush_location_hook_timeout")
            .map(|v| {
                v.trim()
                    .parse::<i64>()
                    .map_err(|_| format!("bad crush_location_hook_timeout {v:?}"))
            })
            .transpose()?
            .unwrap_or(10);
        let timeout = (secs > 0).then(|| Duration::from_secs(secs as u64));
        let cluster = get("cluster").unwrap_or_else(|| "ceph".into());
        let out = run_hook(hook, &cluster, whoami, timeout)
            .map_err(|e| format!("crush_location_hook: {e}"))?;
        return parse(&out)
            .map_err(|e| format!("crush_location_hook {hook:?} printed {out:?}: {e}"));
    }
    Ok(vec![
        ("host".to_owned(), hostname.to_owned()),
        ("root".to_owned(), "default".to_owned()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(p: &[(&str, &str)]) -> Location {
        p.iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    /// Every separator classic accepts; sorted output; the last repeated type wins.
    #[test]
    fn parse_accepts_all_separators() {
        let want = loc(&[("host", "h1"), ("rack", "r1"), ("root", "default")]);
        for t in [
            "root=default,rack=r1,host=h1",
            "root=default;rack=r1;host=h1",
            "root=default rack=r1\thost=h1",
            " root=default, rack=r1 ;; host=h1 ",
            "root=default rack=r1,host=h1",
            "host=h0 root=default rack=r1 host=h1",
        ] {
            assert_eq!(parse(t).unwrap(), want, "{t:?}");
        }
    }

    /// A bad token rejects the whole text (never a partial location under the root).
    #[test]
    fn parse_rejects_bad_text_entirely() {
        for t in [
            "",
            " ,; ",
            "root=default host",
            "root=default host=",
            "root=default host=we!rd",
            "root=default =x",
        ] {
            assert!(parse(t).is_err(), "{t:?}");
        }
    }

    fn conf(p: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: BTreeMap<String, String> = p
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect();
        move |k| m.get(k).cloned()
    }

    fn hook(name: &str, body: &str) -> String {
        let d = std::env::temp_dir().join(format!("crushloc-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("hook.sh");
        let p = p.to_str().unwrap().to_owned();
        // written by a child process: a write fd held in this process could leak into a concurrent test's fork and
        // make exec fail with ETXTBSY
        let st = Command::new("/bin/sh")
            .args([
                "-c",
                r#"printf '#!/bin/sh\n%s\n' "$1" > "$2" && chmod 755 "$2""#,
            ])
            .args(["sh", body, &p])
            .status()
            .unwrap();
        assert!(st.success());
        p
    }

    #[test]
    fn precedence_option_hook_default() {
        assert_eq!(
            resolve(conf(&[]), "h1", 3).unwrap(),
            loc(&[("host", "h1"), ("root", "default")])
        );
        let h = hook("prec", "echo 'root=r9 host=hh'");
        assert_eq!(
            resolve(conf(&[("crush_location_hook", &h)]), "h1", 3).unwrap(),
            loc(&[("host", "hh"), ("root", "r9")])
        );
        assert_eq!(
            resolve(
                conf(&[
                    ("crush_location_hook", &h),
                    ("crush_location", "root=a,host=b")
                ]),
                "h1",
                3
            )
            .unwrap(),
            loc(&[("host", "b"), ("root", "a")]),
            "the option beats the hook"
        );
        let e = resolve(conf(&[("crush_location", "root=a,host")]), "h1", 3).unwrap_err();
        assert!(e.starts_with("crush_location "), "{e}");
    }

    /// The hook gets classic's argv and its trailing newline is stripped.
    #[test]
    fn hook_args_and_output() {
        let h = hook(
            "args",
            r#"printf 'cluster=%s osd=%s-%s-%s-%s\n\n' "$2" "$3" "$4" "$5" "$6""#,
        );
        let out = run_hook(&h, "c1", 7, Some(Duration::from_secs(10))).unwrap();
        assert_eq!(out, "cluster=c1 osd=--id-7---type-osd");
    }

    #[test]
    fn hook_failures_are_errors() {
        let bad = hook("exit", "echo host=x; echo boom >&2; exit 4");
        let e = resolve(conf(&[("crush_location_hook", &bad)]), "h1", 1).unwrap_err();
        assert!(
            e.contains("boom") && e.contains("crush_location_hook"),
            "{e}"
        );
        let junk = hook("junk", "echo 'not a location'");
        let e = resolve(conf(&[("crush_location_hook", &junk)]), "h1", 1).unwrap_err();
        assert!(e.contains("not a location"), "{e}");
        let empty = hook("empty", "true");
        assert!(resolve(conf(&[("crush_location_hook", &empty)]), "h1", 1).is_err());
        assert!(
            resolve(
                conf(&[("crush_location_hook", "/nonexistent/hook")]),
                "h1",
                1
            )
            .is_err()
        );
    }

    /// A hook that exits but leaves a grandchild holding stdout/stderr must not hang the OSD start: the pipe reads are
    /// bounded by the same timeout, which fires (with `WARNING TIMEOUT`) and kills the group.
    #[test]
    fn hook_reads_are_bounded_after_the_child_exits() {
        let h = hook("orphan", "sleep 30 & echo 'root=r1 host=h1'");
        let t0 = Instant::now();
        let e = resolve(
            conf(&[
                ("crush_location_hook", &h),
                ("crush_location_hook_timeout", "1"),
            ]),
            "h1",
            1,
        )
        .unwrap_err();
        assert!(e.contains("crush_location_hook_timeout 1s"), "{e}");
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
    }

    /// A hook that closes both pipes and keeps running is reaped at the deadline, not waited for forever.
    #[test]
    fn hook_without_pipes_is_bounded_by_the_timeout() {
        let h = hook("silent", "exec 1>&- 2>&-; sleep 30");
        let t0 = Instant::now();
        let e = resolve(
            conf(&[
                ("crush_location_hook", &h),
                ("crush_location_hook_timeout", "1"),
            ]),
            "h1",
            1,
        )
        .unwrap_err();
        assert!(e.contains("crush_location_hook_timeout 1s"), "{e}");
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
    }

    /// A timeout the monotonic clock cannot hold (the schema has no max: up to `i64::MAX` seconds) is a config error
    /// naming the option, not a panic while the deadline is built.
    #[test]
    fn hook_timeout_out_of_range_is_an_error() {
        let h = hook("far", "echo 'root=r1 host=h1'");
        let e = resolve(
            conf(&[
                ("crush_location_hook", &h),
                ("crush_location_hook_timeout", "9223372036854775807"),
            ]),
            "h1",
            1,
        )
        .unwrap_err();
        assert!(e.contains("crush_location_hook_timeout"), "{e}");
        // the helper itself does not panic on a deadline it cannot hold either
        assert!(run_hook(&h, "c1", 1, Some(Duration::from_secs(u64::MAX))).is_err());
    }

    /// A hanging hook (and its children: the whole group) is killed at the timeout.
    #[test]
    fn hook_timeout_kills_the_group() {
        let h = hook("hang", "sleep 30 & sleep 30");
        let t0 = Instant::now();
        let e = resolve(
            conf(&[
                ("crush_location_hook", &h),
                ("crush_location_hook_timeout", "1"),
            ]),
            "h1",
            1,
        )
        .unwrap_err();
        assert!(e.contains("crush_location_hook_timeout 1s"), "{e}");
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
    }
}
