// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `croit-flashstore-tool b3sum [--xxh3|--blake3|--alg A] [-c|--check] [--time] FILE...|-` and `b3sum --bench [--mb N]`. Default alg = hashsum::DEFAULT.
//! Output `<hex>  <name>` like b3sum/xxh128sum (default BLAKE3; `--xxh3` is bit-equal to xxh128sum). `-c` verifies
//! such lists (64 hex = BLAKE3, else the selected alg). rc 0 ok, 1 mismatch/unreadable. `--time`: GB/s per input on stderr.

use hashsum::{Alg, hash_file, hash_reader};
use std::io::Write;
use std::path::Path;
use std::time::Instant;

fn hash_one(a: Alg, name: &str) -> std::io::Result<String> {
    if name == "-" {
        hash_reader(a, &mut std::io::stdin().lock())
    } else {
        hash_file(a, Path::new(name))
    }
}

/// Upper bound of `--mb`: the bench holds the whole input in memory (16 GiB).
const MAX_BENCH_MB: usize = 16 << 10;

fn size_of(name: &str) -> u64 {
    std::fs::metadata(name).map_or(0, |m| m.len())
}

pub fn run(args: &[String]) -> i32 {
    let (mut alg, mut check, mut time, mut bench, mut mb) =
        (hashsum::DEFAULT, false, false, false, 1024usize);
    let mut files = Vec::new();
    let mut it = args.iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "--xxh3" => alg = Alg::Xxh3,
            "--blake3" => alg = Alg::Blake3,
            "--alg" => match it.next().and_then(|s| Alg::parse(s)) {
                Some(a) => alg = a,
                None => return usage(),
            },
            "-c" | "--check" => check = true,
            "--time" => time = true,
            "--bench" => bench = true,
            "--mb" => match it.next().and_then(|s| s.parse::<usize>().ok()) {
                Some(n) if (1..=MAX_BENCH_MB).contains(&n) => mb = n,
                _ => return usage(),
            },
            "-" => files.push("-".to_string()),
            s if s.starts_with("--") => return usage(),
            s => files.push(s.to_string()),
        }
    }
    if bench {
        return run_bench(mb);
    }
    if files.is_empty() {
        files.push("-".into());
    }
    let mut rc = 0;
    let mut out = std::io::stdout().lock();
    for f in &files {
        if check {
            rc |= check_list(alg, f, &mut out);
            continue;
        }
        let t = Instant::now();
        match hash_one(alg, f) {
            Ok(h) => {
                let _ = writeln!(out, "{}", hashsum::line(&h, f));
                if time {
                    let s = t.elapsed().as_secs_f64();
                    let gb = size_of(f) as f64 / 1e9;
                    if gb > 0.0 {
                        eprintln!("{f}: {:.2} GB/s ({s:.2}s, {})", gb / s, alg.name());
                    } else {
                        eprintln!("{f}: {s:.2}s ({})", alg.name());
                    }
                }
            }
            Err(e) => {
                eprintln!("croit-flashstore-tool b3sum: {f}: {e}");
                rc = 1;
            }
        }
    }
    rc
}

/// Read a checksum list: a read that fails part way must not verify the lines that did arrive and report them as OK
/// (an I/O error would look like a clean run).
fn read_list(name: &str, r: &mut impl std::io::Read) -> Result<String, String> {
    let mut s = String::new();
    r.read_to_string(&mut s)
        .map_err(|e| format!("{name}: {e}"))?;
    Ok(s)
}

fn check_list(dflt: Alg, list: &str, out: &mut impl Write) -> i32 {
    let text = if list == "-" {
        read_list("<stdin>", &mut std::io::stdin())
    } else {
        std::fs::File::open(list)
            .map_err(|e| format!("{list}: {e}"))
            .and_then(|mut f| read_list(list, &mut f))
    };
    let text = match text {
        Ok(t) => t,
        Err(e) => {
            eprintln!("croit-flashstore-tool b3sum: {e}");
            return 1;
        }
    };
    let (mut bad, mut unread, mut n) = (0, 0, 0);
    for l in text.lines().filter(|l| !l.trim().is_empty()) {
        let Some((h, name)) = hashsum::parse_line(l) else {
            eprintln!("croit-flashstore-tool b3sum: {list}: improperly formatted line: {l}");
            bad += 1;
            continue;
        };
        let Some(a) = Alg::from_hex_len(h.len(), dflt) else {
            eprintln!("croit-flashstore-tool b3sum: {list}: bad digest length for {name}");
            bad += 1;
            continue;
        };
        n += 1;
        match hash_one(a, &name) {
            Ok(g) if g.eq_ignore_ascii_case(h) => {
                let _ = writeln!(out, "{name}: OK");
            }
            Ok(_) => {
                let _ = writeln!(out, "{name}: FAILED");
                bad += 1;
            }
            Err(e) => {
                let _ = writeln!(out, "{name}: FAILED open or read ({e})");
                unread += 1;
            }
        }
    }
    if bad + unread > 0 {
        eprintln!(
            "croit-flashstore-tool b3sum: WARNING: {bad} of {n} computed checksums did NOT match, {unread} listed files could not be read"
        );
        1
    } else {
        0
    }
}

/// In-memory GB/s per alg: 1 thread (rayon pool of 1) vs all cores.
fn run_bench(mb: usize) -> i32 {
    let mut buf = vec![0u8; mb << 20];
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    for c in buf.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        c.copy_from_slice(&x.to_le_bytes()[..c.len()]);
    }
    let gbs = |f: &dyn Fn()| {
        f(); // warm up (page faults, pool)
        let t = Instant::now();
        let reps = 3;
        for _ in 0..reps {
            f();
        }
        buf.len() as f64 * f64::from(reps) / 1e9 / t.elapsed().as_secs_f64()
    };
    let one = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("pool");
    println!(
        "bench: {mb} MiB in memory, {} cores",
        rayon::current_num_threads()
    );
    for a in [Alg::Blake3, Alg::Xxh3] {
        let st = gbs(&|| {
            one.install(|| {
                std::hint::black_box(hashsum::digest(a, &buf));
            });
        });
        let mt = gbs(&|| {
            std::hint::black_box(hashsum::digest(a, &buf));
        });
        println!(
            "{:7} 1 thread {st:7.2} GB/s   all cores {mt:7.2} GB/s",
            a.name()
        );
    }
    0
}

fn usage() -> i32 {
    eprintln!(
        "usage: croit-flashstore-tool b3sum [--xxh3|--blake3|--alg A] [-c] [--time] FILE...|-   |   b3sum --bench [--mb 1..16384]"
    );
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(n: &str, d: &[u8]) -> String {
        let p = std::env::temp_dir().join(format!("b3sum-t-{}-{n}", std::process::id()));
        std::fs::write(&p, d).unwrap();
        p.to_string_lossy().into_owned()
    }
    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    /// A list read that fails part way must not verify the lines that arrived and report them as OK.
    #[test]
    fn check_list_read_error_is_reported() {
        struct Failing(usize);
        impl std::io::Read for Failing {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::other("simulated I/O error"));
                }
                let n = b.len().min(self.0);
                b[..n].fill(b'a');
                self.0 -= n;
                Ok(n)
            }
        }
        assert_eq!(
            read_list("<stdin>", &mut Failing(0)).unwrap_err(),
            "<stdin>: simulated I/O error"
        );
        // a read that fails after a few bytes fails the list, it does not verify a prefix
        assert_eq!(
            read_list("list", &mut Failing(3)).unwrap_err(),
            "list: simulated I/O error"
        );
    }

    /// `--mb` is bounded before the bench allocates `mb << 20` bytes: a usage error, never a shift overflow or abort.
    #[test]
    fn bench_mb_is_bounded() {
        for v in ["99999999999", "0", "16385", "-1", "x"] {
            assert_eq!(run(&s(&["--bench", "--mb", v])), 2, "--mb {v}");
        }
        assert_eq!(run(&s(&["--bench", "--mb"])), 2);
    }

    #[test]
    fn check_ok_and_fail() {
        let f = tmp("abc", b"abc");
        let list = tmp(
            "list",
            format!("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85  {f}\n")
                .as_bytes(),
        );
        assert_eq!(run(&s(&["--blake3", "-c", &list])), 0);
        let bad = tmp("bad", format!("{}  {f}\n", "0".repeat(64)).as_bytes());
        assert_eq!(run(&s(&["--blake3", "-c", &bad])), 1);
        let md = tmp(
            "md",
            format!("99aa06d3014798d86001c324468d497f  {f}\n").as_bytes(),
        );
        assert_eq!(run(&s(&["--blake3", "-c", &md])), 1); // 32 hex under blake3 = bad length
        let xx = tmp(
            "xx",
            format!("99aa06d3014798d86001c324468d497f  {}\n", tmp("e", b"")).as_bytes(),
        );
        assert_eq!(run(&s(&["--xxh3", "-c", &xx])), 0);
        assert_eq!(run(&s(&["/nonexistent/x"])), 1);
    }

    /// A file name with a newline and a backslash must survive a list round trip (b3sum/xxhsum
    /// escaping: leading `\`, `\\`, `\n`).
    #[test]
    fn check_escaped_name() {
        let f = tmp("n\nl\\x", b"abc");
        let h = hash_file(Alg::Blake3, Path::new(&f)).unwrap();
        let list = tmp(
            "esc-list",
            format!("{}\n", hashsum::line(&h, &f)).as_bytes(),
        );
        assert_eq!(run(&s(&["--blake3", "-c", &list])), 0);
        std::fs::remove_file(&f).unwrap();
        std::fs::remove_file(&list).unwrap();
    }
}
