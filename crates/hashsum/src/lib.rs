// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Content hashes for verification steps (lab scripts, oprobe, croit-flashstore-tool b3sum). Not used by the daemon.
//!
//! * `blake3`: standard BLAKE3 (= `b3sum`), SIMD, multithreaded on big inputs (rayon; files read by a
//!   helper thread while the caller hashes, never mapped).
//! * `xxh3`: standard XXH3-128 (= `xxh128sum`, hex = high64 then low64), single thread.

use std::io::Read;
use std::path::Path;

/// THE default algorithm (user decision 2026-10-17, adr 0167): standard, cryptographic, tree-parallel.
pub const DEFAULT: Alg = Alg::Blake3;
/// Read buffer of the streaming paths: one full chunk per `update`, so the parallel BLAKE3
/// path (`RAYON_MIN`) stays fed on pipes and stdin.
const BUF: usize = 16 << 20;
/// Smallest slice handed to the multithreaded BLAKE3 update; below it the rayon split costs
/// more than it saves.
const RAYON_MIN: usize = 1 << 20;
/// Buffer of [`hash_file`] (two in flight): smaller pieces leave the parallel BLAKE3 update
/// dominated by its per-call rayon split (doc/reviews/2026-11-08-nt-unsafe.md, NT-unsafe-05).
const FILE_BUF: usize = 64 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Blake3,
    Xxh3,
}

impl Alg {
    pub fn parse(s: &str) -> Option<Alg> {
        Some(match s {
            "blake3" | "b3" => Alg::Blake3,
            "xxh3" | "xxh128" => Alg::Xxh3,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Alg::Blake3 => "blake3",
            Alg::Xxh3 => "xxh3",
        }
    }
    /// Alg of a hex digest by its length (check mode): 64 hex = BLAKE3, 32 hex = XXH3 (only
    /// when it is the selected alg, since 32 is also an md5 length).
    pub fn from_hex_len(n: usize, dflt: Alg) -> Option<Alg> {
        match n {
            64 => Some(Alg::Blake3),
            32 if dflt == Alg::Xxh3 => Some(Alg::Xxh3),
            _ => None,
        }
    }
}

pub fn hex(d: &[u8]) -> String {
    use std::fmt::Write;
    d.iter()
        .fold(String::with_capacity(d.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn xxh128(d: &[u8]) -> [u8; 16] {
    xxhash_rust::xxh3::xxh3_128(d).to_be_bytes()
}

/// Streaming hasher.
pub struct Hasher {
    st: St,
}

impl std::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hasher").finish_non_exhaustive()
    }
}

enum St {
    B3(Box<blake3::Hasher>),
    X(Box<xxhash_rust::xxh3::Xxh3>),
}

impl Hasher {
    pub fn new(a: Alg) -> Hasher {
        Hasher {
            st: match a {
                Alg::Blake3 => St::B3(Box::new(blake3::Hasher::new())),
                Alg::Xxh3 => St::X(Box::new(xxhash_rust::xxh3::Xxh3::new())),
            },
        }
    }

    pub fn update(&mut self, d: &[u8]) {
        match &mut self.st {
            St::B3(h) => {
                if d.len() >= RAYON_MIN {
                    h.update_rayon(d);
                } else {
                    h.update(d);
                }
            }
            St::X(h) => h.update(d),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        match self.st {
            St::B3(h) => h.finalize().as_bytes().to_vec(),
            St::X(h) => h.digest128().to_be_bytes().to_vec(),
        }
    }

    pub fn finish_hex(self) -> String {
        hex(&self.finish())
    }
}

pub fn digest(a: Alg, d: &[u8]) -> Vec<u8> {
    match a {
        Alg::Xxh3 => xxh128(d).to_vec(),
        Alg::Blake3 => {
            let mut h = Hasher::new(a);
            h.update(d);
            h.finish()
        }
    }
}

pub fn hash_bytes(a: Alg, d: &[u8]) -> String {
    hex(&digest(a, d))
}

/// Hash a stream (stdin, pipe) with a large buffer.
pub fn hash_reader(a: Alg, r: &mut impl Read) -> std::io::Result<String> {
    let mut h = Hasher::new(a);
    let mut buf = vec![0u8; BUF];
    loop {
        let n = fill(r, &mut buf)?;
        h.update(&buf[..n]);
        if n < buf.len() {
            return Ok(h.finish_hex());
        }
    }
}

/// Fill `buf` from `r` up to its end or EOF; returns the byte count.
fn fill(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Hash a file (regular, device, FIFO). The path is opened exactly once. Bytes are copied by
/// read(2) into two owned [`FILE_BUF`] buffers: a helper thread fills one while this thread
/// hashes the other. Never mapped: another process may write or truncate the file while it is
/// hashed (the digest is then of a torn read, but no fault and no aliased memory).
pub fn hash_file(a: Alg, p: &Path) -> std::io::Result<String> {
    hash_file_in(a, p, FILE_BUF)
}

fn hash_file_in(a: Alg, p: &Path, buf_len: usize) -> std::io::Result<String> {
    use std::sync::mpsc::sync_channel;
    let mut f = std::fs::File::open(p)?;
    let (give, free) = sync_channel::<Vec<u8>>(2);
    let (send, full) = sync_channel::<std::io::Result<(Vec<u8>, usize)>>(2);
    for _ in 0..2 {
        give.send(vec![0; buf_len]).expect("own receiver");
    }
    let mut h = Hasher::new(a);
    // `move`: on return (also on error) both channel ends drop before the scope joins the
    // reader, so a reader waiting for a buffer or offering one stops.
    std::thread::scope(move |s| {
        s.spawn(move || {
            for mut b in free {
                let r = fill(&mut f, &mut b).map(|n| (b, n));
                let last = !matches!(&r, Ok((b, n)) if *n == b.len());
                if send.send(r).is_err() || last {
                    break;
                }
            }
        });
        for r in full {
            let (b, n) = r?;
            h.update(&b[..n]);
            if n < b.len() {
                break;
            }
            // The reader may already have stopped after an error it sent.
            let _ = give.send(b);
        }
        Ok(h.finish_hex())
    })
}

/// `<hex>  <name>` line as printed by b3sum/xxh128sum (text mode, two spaces). A name that
/// contains a backslash or a newline is escaped (`\\`, `\n`) and the line is prefixed with one
/// `\` (b3sum/xxhsum check-list format); [`parse_line`] reverses this.
pub fn line(hexd: &str, name: &str) -> String {
    if !name.contains(['\\', '\n']) {
        return format!("{hexd}  {name}");
    }
    let mut s = String::with_capacity(hexd.len() + name.len() + 4);
    s.push('\\');
    s.push_str(hexd);
    s.push_str("  ");
    for c in name.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            c => s.push(c),
        }
    }
    s
}

/// Parse one check line: optional `\` escaping marker, then `<hex>`, a space, an optional `*`
/// (binary mode) and the name -> (hex, name). Names are unescaped only when the line carries
/// the escaping marker; any other escape than `\\`/`\n` is a format error.
pub fn parse_line(l: &str) -> Option<(&str, String)> {
    let (escaped, l) = match l.strip_prefix('\\') {
        Some(r) => (true, r),
        None => (false, l),
    };
    let (h, rest) = l.split_once(' ')?;
    if h.is_empty() || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let n = rest.strip_prefix(' ').or_else(|| rest.strip_prefix('*'))?;
    Some((h, if escaped { unescape(n)? } else { n.to_string() }))
}

/// `\\` -> `\`, `\n` -> newline; any other escape (or a trailing `\`) is not valid.
fn unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        out.push(match c {
            '\\' => match it.next()? {
                '\\' => '\\',
                'n' => '\n',
                _ => return None,
            },
            c => c,
        });
    }
    Some(out)
}

/// Item length that the combined-digest format cannot encode: it stores the name length in 32
/// bits and the digest length in 8 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CombineError {
    NameTooLong,
    DigestTooLong,
}

impl std::fmt::Display for CombineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CombineError::NameTooLong => "object name longer than u32::MAX bytes",
            CombineError::DigestTooLong => "digest longer than 255 bytes",
        })
    }
}

impl std::error::Error for CombineError {}

/// Cross-cluster comparable digest of a set of objects: BLAKE3 over, ordered by name (ties by
/// data length, then digest, so duplicates never depend on arrival order), per object
/// `u32le name_len, name, u64le data_len, u8 digest_len, digest`. `items` = (name, data_len,
/// digest of the data in the chosen alg); sorted in place.
pub fn combine(items: &mut [(String, u64, Vec<u8>)]) -> Result<String, CombineError> {
    items.sort_by(|x, y| (&x.0, x.1, &x.2).cmp(&(&y.0, y.1, &y.2)));
    let mut h = blake3::Hasher::new();
    for (n, l, d) in items.iter() {
        let nl = u32::try_from(n.len()).map_err(|_| CombineError::NameTooLong)?;
        let dl = u8::try_from(d.len()).map_err(|_| CombineError::DigestTooLong)?;
        h.update(&nl.to_le_bytes());
        h.update(n.as_bytes());
        h.update(&l.to_le_bytes());
        h.update(&[dl]);
        h.update(d);
    }
    Ok(h.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_vectors() {
        assert_eq!(
            hash_bytes(Alg::Blake3, b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            hash_bytes(Alg::Blake3, b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn xxh3_vector() {
        assert_eq!(
            hash_bytes(Alg::Xxh3, b""),
            "99aa06d3014798d86001c324468d497f"
        );
    }

    #[test]
    fn streaming_equals_oneshot() {
        let d: Vec<u8> = (0..(9 << 20) + 5).map(|i| (i * 31 % 251) as u8).collect();
        for a in [Alg::Blake3, Alg::Xxh3] {
            let one = hash_bytes(a, &d);
            let mut h = Hasher::new(a);
            for c in d.chunks(1_000_003) {
                h.update(c);
            }
            assert_eq!(h.finish_hex(), one, "{a:?}");
            assert_eq!(hash_reader(a, &mut &d[..]).unwrap(), one, "{a:?} reader");
        }
    }

    #[test]
    fn file_buffers_cover_every_boundary() {
        let p = std::env::temp_dir().join(format!("hashsum-b-{}", std::process::id()));
        for len in [1, 4095, 4096, 4097, 2 * 4096, 3 * 4096 + 1] {
            let d: Vec<u8> = (0..len).map(|i| (i * 13 % 251) as u8).collect();
            std::fs::write(&p, &d).unwrap();
            for a in [Alg::Blake3, Alg::Xxh3] {
                assert_eq!(
                    hash_file_in(a, &p, 4096).unwrap(),
                    hash_bytes(a, &d),
                    "{len}"
                );
            }
        }
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn file_matches_bytes() {
        let p = std::env::temp_dir().join(format!("hashsum-t-{}", std::process::id()));
        let d = vec![7u8; 3 << 20];
        std::fs::write(&p, &d).unwrap();
        for a in [Alg::Blake3, Alg::Xxh3] {
            assert_eq!(hash_file(a, &p).unwrap(), hash_bytes(a, &d));
        }
        // Empty regular file and a non-regular input both go through the opened file.
        std::fs::write(&p, b"").unwrap();
        for a in [Alg::Blake3, Alg::Xxh3] {
            assert_eq!(hash_file(a, &p).unwrap(), hash_bytes(a, b""));
        }
        assert_eq!(
            hash_file(Alg::Blake3, Path::new("/dev/null")).unwrap(),
            hash_bytes(Alg::Blake3, b"")
        );
        let dir = std::env::temp_dir();
        assert!(
            hash_file(Alg::Blake3, &dir).is_err(),
            "a directory cannot be read"
        );
        assert!(hash_file(Alg::Blake3, Path::new("/nonexistent/x")).is_err());
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn lines() {
        assert_eq!(parse_line("ab12  f x"), Some(("ab12", "f x".into())));
        assert_eq!(parse_line("ab12 *f"), Some(("ab12", "f".into())));
        assert_eq!(parse_line("zz  f"), None);
    }

    #[test]
    fn line_escapes_names_for_check_lists() {
        // A name with a newline or backslash must not break the line format (b3sum/xxhsum
        // escape it: leading `\`, `\\` for a backslash, `\n` for a newline).
        let got = line("ab12", "n\nl");
        assert!(!got.contains('\n'), "line must stay one line: {got:?}");
        assert_eq!(got, "\\ab12  n\\nl");
        assert_eq!(line("ab12", "bs\\slash"), "\\ab12  bs\\\\slash");
        assert_eq!(line("ab12", "plain"), "ab12  plain");
        // Reference lines as printed by `xxh128sum -- <name>`; `-c` must yield the same names.
        assert_eq!(
            parse_line("\\89c65ebc828eebaca873719c24d5735c  n\\nl"),
            Some(("89c65ebc828eebaca873719c24d5735c", "n\nl".into()))
        );
        assert_eq!(
            parse_line("\\89c65ebc828eebaca873719c24d5735c  bs\\\\slash"),
            Some(("89c65ebc828eebaca873719c24d5735c", "bs\\slash".into()))
        );
    }

    #[test]
    fn line_roundtrip() {
        for name in [
            "plain", "a b", " lead", "\\", "\\back", "a\\b", "n\nl", "\n", "\\n", "*star", "-",
        ] {
            let l = line("ab12", name);
            assert!(!l.contains('\n'), "{name:?} -> {l:?}");
            assert_eq!(parse_line(&l), Some(("ab12", name.to_string())), "{name:?}");
        }
        // Without the leading `\` a name is literal: no unescaping, no error.
        assert_eq!(parse_line("ab12  a\\nb"), Some(("ab12", "a\\nb".into())));
        // A redundant prefix is accepted (xxh128sum -c does the same), bad escapes are not.
        assert_eq!(parse_line("\\ab12  plain"), Some(("ab12", "plain".into())));
        assert_eq!(parse_line("\\ab12  a\\zb"), None);
        assert_eq!(parse_line("\\ab12  a\\"), None);
    }

    #[test]
    fn combine_orders_duplicate_names() {
        let it = |d: &[u8]| {
            (
                "same".to_string(),
                d.len() as u64,
                blake3::hash(d).as_bytes().to_vec(),
            )
        };
        let mut x = vec![it(b"1"), it(b"2")];
        let mut y = vec![it(b"2"), it(b"1")];
        assert_eq!(combine(&mut x).unwrap(), combine(&mut y).unwrap());
        assert_eq!(x, y); // canonical order, not arrival order
    }

    #[test]
    fn combine_rejects_unencodable_lengths() {
        let it = |d: &[u8]| ("n".to_string(), 0u64, d.to_vec());
        assert!(combine(&mut [it(&[0; 255])]).is_ok());
        assert_eq!(
            combine(&mut [it(&[0; 256])]),
            Err(CombineError::DigestTooLong)
        );
    }

    #[test]
    fn combine_is_order_independent_and_sensitive() {
        let b = |n: &str, d: &[u8]| {
            (
                n.to_string(),
                d.len() as u64,
                blake3::hash(d).as_bytes().to_vec(),
            )
        };
        let mut x = vec![b("b", b"2"), b("a", b"1")];
        let mut y = vec![b("a", b"1"), b("b", b"2")];
        let mut z = vec![b("a", b"1"), b("b", b"3")];
        let mut w = vec![b("a", b"1"), b("c", b"2")];
        let cx = combine(&mut x).unwrap();
        assert_eq!(cx, combine(&mut y).unwrap());
        assert_ne!(cx, combine(&mut z).unwrap());
        assert_ne!(cx, combine(&mut w).unwrap());
    }
}
