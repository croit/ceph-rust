// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `croit-flashstore-tool asok --id N [--cluster C] [--path P] [--format plain|json|json-pretty] CMD...`: same-host admin without the `ceph` CLI
//! (adr 0046). Classic admin-socket protocol: request text + NUL, reply = u32 BE length + body. std only.
//! `--timeout <s>` bounds the reply wait (default: wait without deadline, like classic); exit 124 after the `WARNING TIMEOUT` line.
use outfmt::Format;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Bound on connecting to the socket (`WARNING TIMEOUT` when it fires). The reply wait has no default deadline: like
/// classic `ceph daemon`, a slow but healthy command (bench, big dumps) is waited for; `--timeout <s>` bounds it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Exit code when a timeout fired (connect, or the user's `--timeout` on the reply), like coreutils `timeout`.
pub const EXIT_TIMEOUT: i32 = 124;

fn usage(m: &str) -> i32 {
    eprintln!("croit-flashstore-tool asok: {m}");
    eprintln!(
        "usage: croit-flashstore-tool asok --id N [--cluster C] [--path SOCK] [--timeout S] [--format plain|json|json-pretty] CMD...   (e.g. perf dump, status, help)"
    );
    2
}

/// One request/reply on `s`; `timeout` bounds each socket read/write (`None` = wait without deadline). Returns the reply body.
pub fn ask(s: &mut UnixStream, req: &str, timeout: Option<Duration>) -> std::io::Result<Vec<u8>> {
    s.set_read_timeout(timeout)?;
    s.set_write_timeout(timeout)?;
    s.write_all(req.as_bytes())?;
    s.write_all(&[0])?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > 256 << 20 {
        return Err(std::io::Error::other("reply too large"));
    }
    let mut v = vec![0u8; n];
    s.read_exact(&mut v)?;
    Ok(v)
}

/// Request text for the words (plain text = prefix; a JSON format makes it a JSON command with `format: json`). One word that
/// is a JSON object is the command itself (`'{"prefix":"config set","var":...}'`, like `ceph daemon`), with `format: json`
/// added for a JSON format unless it names one.
pub fn request(words: &[String], f: Format) -> String {
    if let [w] = words
        && let Ok(serde_json::Value::Object(mut cmd)) = serde_json::from_str(w)
    {
        if f.is_json() && !cmd.contains_key("format") {
            cmd.insert("format".into(), "json".into());
        }
        return serde_json::Value::Object(cmd).to_string();
    }
    let prefix = words.join(" ");
    if f.is_json() {
        serde_json::json!({ "prefix": prefix, "format": "json" }).to_string()
    } else {
        prefix
    }
}

/// `json-pretty`: re-indent a JSON reply (the daemon answers compact); anything else is passed through.
fn render(f: Format, b: Vec<u8>) -> Vec<u8> {
    if f != Format::JsonPretty {
        return b;
    }
    match serde_json::from_slice::<serde_json::Value>(&b) {
        Ok(v) => format!("{}\n", f.doc(&v)).into_bytes(),
        Err(_) => b,
    }
}

pub fn run(a: &[String], f: Format) -> i32 {
    let (mut id, mut cluster, mut path, mut timeout) = (None, "ceph".to_owned(), None, None);
    let mut words = Vec::new();
    let mut it = a.iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "--id" => id = it.next().cloned(),
            "--cluster" => match it.next() {
                Some(c) => cluster = c.clone(),
                None => return usage("--cluster needs a value"),
            },
            "--path" => path = it.next().cloned(),
            "--timeout" => match it.next().and_then(|v| v.parse::<u64>().ok()) {
                Some(n) if n > 0 => timeout = Some(Duration::from_secs(n)),
                _ => return usage("--timeout needs a positive number of seconds"),
            },
            _ => words.push(x.clone()),
        }
    }
    let path = match (path, id) {
        (Some(p), _) => p,
        (None, Some(i)) if i.chars().all(|c| c.is_ascii_digit()) && !i.is_empty() => {
            format!("/var/run/ceph/{cluster}-osd.{i}.asok")
        }
        _ => return usage("need --id N (digits) or --path"),
    };
    if words.is_empty() {
        return usage("no command");
    }
    let mut s = match connect(&path, CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(e) if is_timeout(&e) => {
            eprintln!(
                "WARNING TIMEOUT asok connect exceeded {:.3}s ({path})",
                CONNECT_TIMEOUT.as_secs_f64()
            );
            return EXIT_TIMEOUT;
        }
        Err(e) => {
            eprintln!("croit-flashstore-tool asok: connect {path}: {e}");
            return 1;
        }
    };
    match ask(&mut s, &request(&words, f), timeout) {
        Ok(b) => {
            // error replies start with "ERROR:" (classic)
            let rc = i32::from(b.starts_with(b"ERROR:"));
            let _ = std::io::stdout().write_all(&render(f, b));
            rc
        }
        Err(e) if timeout.is_some() && is_timeout(&e) => {
            eprintln!(
                "WARNING TIMEOUT asok reply exceeded {:.3}s ({})",
                timeout.map_or(0.0, |t| t.as_secs_f64()),
                words.join(" ")
            );
            EXIT_TIMEOUT
        }
        Err(e) => {
            eprintln!("croit-flashstore-tool asok: {e}");
            1
        }
    }
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Connect with a bound: a unix connect blocks only on a full listen backlog (a wedged daemon), so it runs on a helper
/// thread the process abandons when the bound passes.
fn connect(path: &str, timeout: Duration) -> std::io::Result<UnixStream> {
    let (tx, rx) = std::sync::mpsc::channel();
    let p = path.to_owned();
    std::thread::spawn(move || {
        let _ = tx.send(UnixStream::connect(p));
    });
    match rx.recv_timeout(timeout) {
        Ok(r) => r,
        Err(_) => Err(std::io::ErrorKind::TimedOut.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_that_does_not_read_cannot_block_the_request_forever() {
        let (mut client, peer) = UnixStream::pair().unwrap();
        let (done, wait) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            // Bound the regression even when the client forgets its write timeout.
            let _ = wait.recv_timeout(Duration::from_secs(1));
            drop(peer);
        });
        let err = ask(
            &mut client,
            &"x".repeat(8 << 20),
            Some(Duration::from_millis(10)),
        )
        .unwrap_err();
        let _ = done.send(());
        server.join().unwrap();
        assert!(is_timeout(&err));
    }

    /// Fake daemon on a socket path: reads the request, waits `delay`, answers `body`.
    fn fake_daemon(
        name: &str,
        delay: Duration,
        body: &'static str,
    ) -> (String, std::thread::JoinHandle<()>) {
        let path = std::env::temp_dir()
            .join(format!("asok-test-{}-{name}.sock", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let h = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut b = [0u8; 1];
            while c.read_exact(&mut b).is_ok() && b[0] != 0 {}
            std::thread::sleep(delay);
            let _ = c.write_all(&(body.len() as u32).to_be_bytes());
            let _ = c.write_all(body.as_bytes());
        });
        (path, h)
    }

    #[test]
    fn slow_reply_is_waited_for_without_timeout() {
        let (path, h) = fake_daemon("slow", Duration::from_millis(300), "ok");
        let argv = ["--path".to_owned(), path.clone(), "bench".to_owned()];
        assert_eq!(run(&argv, Format::Plain), 0);
        h.join().unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn user_timeout_fires_with_the_documented_exit_code() {
        let (path, h) = fake_daemon("tmo", Duration::from_millis(2500), "late");
        let argv = [
            "--path".to_owned(),
            path.clone(),
            "--timeout".to_owned(),
            "1".to_owned(),
            "bench".to_owned(),
        ];
        assert_eq!(run(&argv, Format::Plain), EXIT_TIMEOUT);
        h.join().unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn timeout_value_is_validated() {
        for v in ["0", "x"] {
            let argv = [
                "--id".to_owned(),
                "1".to_owned(),
                "--timeout".to_owned(),
                v.to_owned(),
                "status".to_owned(),
            ];
            assert_eq!(run(&argv, Format::Plain), 2);
        }
    }

    #[test]
    fn roundtrip_against_fake_socket() {
        let (mut s, mut c) = UnixStream::pair().unwrap();
        let t = std::thread::spawn(move || {
            let mut req = Vec::new();
            let mut b = [0u8; 1];
            while c.read_exact(&mut b).is_ok() && b[0] != 0 {
                req.push(b[0]);
            }
            let body = format!("got:{}", String::from_utf8(req).unwrap());
            c.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
            c.write_all(body.as_bytes()).unwrap();
        });
        let req = request(&["perf".into(), "dump".into()], Format::Plain);
        assert_eq!(ask(&mut s, &req, None).unwrap(), b"got:perf dump");
        t.join().unwrap();
        assert_eq!(
            request(&["status".into()], Format::Json),
            r#"{"format":"json","prefix":"status"}"#
        );
        // a JSON command is sent as is (format added for a JSON output format)
        let cmd = r#"{"prefix":"perf dump"}"#.to_owned();
        assert_eq!(
            request(std::slice::from_ref(&cmd), Format::Json),
            r#"{"format":"json","prefix":"perf dump"}"#
        );
        assert_eq!(request(std::slice::from_ref(&cmd), Format::Plain), cmd);
    }

    #[test]
    fn usage_errors() {
        assert_eq!(run(&[], Format::Plain), 2);
        assert_eq!(
            run(&["--id".into(), "x".into(), "status".into()], Format::Plain),
            2
        );
        assert_eq!(run(&["--id".into(), "1".into()], Format::Json), 2);
        let v = render(Format::JsonPretty, br#"{"a":1}"#.to_vec());
        assert_eq!(v, b"{\n  \"a\": 1\n}\n");
        assert_eq!(render(Format::Json, b"x".to_vec()), b"x");
    }
}
