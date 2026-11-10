// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! The `nbd` URI grammar: the libnbd subset the client implements.
//!
//! Spec: `doc/spec/rustyrbd/migration-source-http-s3-nbd.md`, "URI forms
//! (libnbd grammar, the subset we implement)".
//!
//! ```text
//! nbd://host[:port][/export][?param=value]
//! nbd+unix:///export?socket=/path
//! nbd+vsock://cid[:port][/export]
//! ```
//!
//! `nbds`, `nbds+unix` and `nbds+vsock` parse identically and carry
//! [`TlsOptions`]; the TLS handshake itself is stage 10c-tls, so the client
//! refuses a TLS URI with `-ENOTSUP` until then. `nbd+ssh` and `nbds+ssh`
//! are `-ENOTSUP`, userinfo and the PSK parameters (`tls-psk-file`,
//! `tls-username`) are `-ENOTSUP` (rustls has no external-PSK client).
//! Every other failure is `-EINVAL`.
//!
//! The export name is the path without its leading `/`, percent-decoded
//! (an invalid escape or a non-UTF-8 result is `-EINVAL`); an empty path or
//! `/` is the default export (empty name). Query values are percent-decoded
//! the same way; `+` is not a space. Unknown query parameters are ignored,
//! and a `socket=` on a TCP or vsock scheme is ignored (spec OPEN: libnbd's
//! handling of both is unmeasured). A `#` fragment is not part of the
//! grammar and is refused (`-EINVAL`).

use crate::journal_backend::EINVAL;
use crate::migration_source::ENOTSUP;

/// The default NBD port of every transport.
pub const DEFAULT_PORT: u16 = 10809;

/// Where the client connects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transport {
    /// `nbd://host[:port]`: a TCP stream.
    Tcp {
        /// Host name or IPv4/IPv6 literal (IPv6 in brackets in the URI).
        host: String,
        /// Port, [`DEFAULT_PORT`] when the URI names none.
        port: u16,
    },
    /// `nbd+unix:///export?socket=/path`: an AF_UNIX stream.
    Unix {
        /// The `socket=` query value, a filesystem path.
        socket: String,
    },
    /// `nbd+vsock://cid[:port]`: an AF_VSOCK stream.
    Vsock {
        /// The guest or host context id.
        cid: u32,
        /// Port, [`DEFAULT_PORT`] when the URI names none.
        port: u32,
    },
}

/// The TLS parameters of an `nbds*` scheme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsOptions {
    /// `tls-verify-peer` (`true`/`false`/`1`/`0`), default `true`.
    pub verify_peer: bool,
    /// `tls-certificates=<dir>`: `ca-cert.pem` and, when present,
    /// `client-cert.pem` + `client-key.pem` below that directory.
    pub certificates: Option<String>,
    /// `tls-hostname=<name>`: SNI and verification name, default the URI
    /// host.
    pub hostname: Option<String>,
}

/// One parsed `nbd` URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NbdUri {
    transport: Transport,
    export: String,
    tls: Option<TlsOptions>,
    display: String,
}

impl NbdUri {
    /// Parse one URI; `-EINVAL` for a malformed URI or an unknown scheme,
    /// `-ENOTSUP` for `*+ssh` and the PSK parameters.
    pub fn parse(uri: &str) -> Result<Self, i32> {
        let (scheme, rest) = uri.split_once("://").ok_or(EINVAL)?;
        let (rest, query) = match rest.split_once('?') {
            Some((rest, query)) => (rest, Some(query)),
            None => (rest, None),
        };
        if rest.contains('#') || query.is_some_and(|query| query.contains('#')) {
            return Err(EINVAL);
        }
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, ""),
        };
        let export = percent_decode(path.strip_prefix('/').unwrap_or(path))?;
        let mut params = Params::parse(query)?;
        let transport = match scheme {
            "nbd" | "nbds" => {
                let (host, port) = parse_tcp_authority(authority)?;
                Transport::Tcp {
                    host,
                    port: port.unwrap_or(DEFAULT_PORT),
                }
            }
            "nbd+unix" | "nbds+unix" => {
                if !authority.is_empty() {
                    return Err(EINVAL);
                }
                Transport::Unix {
                    socket: params.required_socket()?,
                }
            }
            "nbd+vsock" | "nbds+vsock" => parse_vsock_authority(authority)?,
            "nbd+ssh" | "nbds+ssh" => return Err(ENOTSUP),
            _ => return Err(EINVAL),
        };
        let tls = scheme.starts_with("nbds").then_some(TlsOptions {
            verify_peer: params.verify_peer,
            certificates: params.certificates,
            hostname: params.hostname,
        });
        Ok(Self {
            transport,
            export,
            tls,
            display: match uri.split_once('?') {
                Some((head, _)) => head.to_owned(),
                None => uri.to_owned(),
            },
        })
    }

    /// Where the client connects.
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// The export name (`""` for the default export).
    pub fn export(&self) -> &str {
        &self.export
    }

    /// The TLS parameters of an `nbds*` scheme.
    pub fn tls(&self) -> Option<&TlsOptions> {
        self.tls.as_ref()
    }

    /// The URI without its query, for diagnostics.
    pub fn display(&self) -> &str {
        &self.display
    }
}

/// Parse the authority of a TCP scheme: `host[:port]`, IPv6 in brackets.
/// The port is `None` when the URI names none.
fn parse_tcp_authority(authority: &str) -> Result<(String, Option<u16>), i32> {
    if authority.contains('@') {
        // userinfo is PSK TLS in libnbd.
        return Err(ENOTSUP);
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']').ok_or(EINVAL)?;
            if host.is_empty() {
                return Err(EINVAL);
            }
            let port = match after.strip_prefix(':') {
                Some(port) => Some(parse_port(port)?),
                None if after.is_empty() => None,
                None => return Err(EINVAL),
            };
            (host, port)
        }
        None => {
            let (host, port) = match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(parse_port(port)?)),
                None => (authority, None),
            };
            if host.is_empty() || host.contains(':') {
                return Err(EINVAL);
            }
            (host, port)
        }
    };
    Ok((host.to_owned(), port))
}

/// Parse `cid[:port]` of a vsock scheme.
fn parse_vsock_authority(authority: &str) -> Result<Transport, i32> {
    if authority.contains('@') {
        return Err(ENOTSUP);
    }
    let (cid, port) = match authority.split_once(':') {
        Some((cid, port)) => (cid, Some(port)),
        None => (authority, None),
    };
    let cid = parse_u32(cid)?;
    let port = match port {
        Some(port) => parse_u32(port)?,
        None => u32::from(DEFAULT_PORT),
    };
    Ok(Transport::Vsock { cid, port })
}

/// One decimal `u16` port: digits only (no sign, no whitespace), non-empty.
fn parse_port(text: &str) -> Result<u16, i32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(EINVAL);
    }
    text.parse().map_err(|_| EINVAL)
}

/// One decimal `u32` (a vsock cid or port): digits only, non-empty.
fn parse_u32(text: &str) -> Result<u32, i32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(EINVAL);
    }
    text.parse().map_err(|_| EINVAL)
}

/// The honoured query parameters; unknown ones are dropped.
#[derive(Debug)]
struct Params {
    socket: Option<String>,
    verify_peer: bool,
    certificates: Option<String>,
    hostname: Option<String>,
}

impl Params {
    fn parse(query: Option<&str>) -> Result<Self, i32> {
        let mut params = Self {
            socket: None,
            verify_peer: true,
            certificates: None,
            hostname: None,
        };
        let Some(query) = query else {
            return Ok(params);
        };
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode(key)?;
            let value = percent_decode(value)?;
            match key.as_str() {
                "socket" => params.socket = Some(value),
                "tls-verify-peer" => {
                    params.verify_peer = match value.as_str() {
                        "true" | "1" => true,
                        "false" | "0" => false,
                        _ => return Err(EINVAL),
                    }
                }
                "tls-certificates" => params.certificates = Some(value),
                "tls-hostname" => params.hostname = Some(value),
                "tls-psk-file" | "tls-username" => return Err(ENOTSUP),
                _ => {}
            }
        }
        Ok(params)
    }

    /// The required, non-empty `socket=` of a Unix scheme.
    fn required_socket(&mut self) -> Result<String, i32> {
        match self.socket.take() {
            Some(socket) if !socket.is_empty() => Ok(socket),
            _ => Err(EINVAL),
        }
    }
}

/// Decode `%HH` escapes; `+` stays `+`. `-EINVAL` for a truncated or
/// non-hex escape and for a result that is not UTF-8.
fn percent_decode(text: &str) -> Result<String, i32> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let high = hex_digit(*bytes.get(at + 1).ok_or(EINVAL)?)?;
            let low = hex_digit(*bytes.get(at + 2).ok_or(EINVAL)?)?;
            out.push(high << 4 | low);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).map_err(|_| EINVAL)
}

fn hex_digit(byte: u8) -> Result<u8, i32> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(uri: &str) -> Result<NbdUri, i32> {
        NbdUri::parse(uri)
    }

    fn tcp(uri: &str) -> (String, u16, String) {
        let parsed = parse(uri).expect("tcp uri");
        match parsed.transport() {
            Transport::Tcp { host, port } => (host.clone(), *port, parsed.export().to_owned()),
            other => panic!("not tcp: {other:?}"),
        }
    }

    #[test]
    fn tcp_forms() {
        // Spec vector: `nbd://h` -> port 10809, default export.
        assert_eq!(tcp("nbd://h"), ("h".into(), 10809, String::new()));
        // Spec vector: `nbd://h:1234/a%20b` -> export `a b`.
        assert_eq!(tcp("nbd://h:1234/a%20b"), ("h".into(), 1234, "a b".into()));
        // Spec vector: IPv6 literal in brackets.
        assert_eq!(
            tcp("nbd://[::1]:10809/e"),
            ("::1".into(), 10809, "e".into())
        );
        // Bracketed without a port, and with the default export.
        assert_eq!(tcp("nbd://[::1]"), ("::1".into(), 10809, String::new()));
        // Port 0 parses (connect then fails).
        assert_eq!(tcp("nbd://h:0/x").1, 0);
        // A path may contain further slashes.
        assert_eq!(tcp("nbd://h/a/b").2, "a/b");
        // "/" and an empty path are the default export.
        assert_eq!(tcp("nbd://h/").2, "");
        assert_eq!(tcp("nbd://h").2, "");
        // Percent escapes decode in the path; `+` is not a space.
        assert_eq!(tcp("nbd://h/a+b%2Fc").2, "a+b/c");
    }

    #[test]
    fn unix_forms() {
        // Spec vector: socket= is required and the authority is empty.
        let uri = parse("nbd+unix:///e?socket=/p").expect("unix uri");
        assert_eq!(
            uri.transport(),
            &Transport::Unix {
                socket: "/p".into()
            }
        );
        assert_eq!(uri.export(), "e");
        assert_eq!(uri.display(), "nbd+unix:///e");
        assert!(uri.tls().is_none());
        // Spec vector: no socket= -> -EINVAL.
        assert_eq!(parse("nbd+unix:///e"), Err(EINVAL));
        // A non-empty authority is refused.
        assert_eq!(parse("nbd+unix://h/e?socket=/p"), Err(EINVAL));
        // An empty socket path is refused.
        assert_eq!(parse("nbd+unix:///e?socket="), Err(EINVAL));
        // The default export over a socket.
        let uri = parse("nbd+unix://?socket=/p").expect("default export");
        assert_eq!(uri.export(), "");
        // Percent escapes decode in a value, and in a key.
        let uri = parse("nbd+unix:///e?socket=%2Fp").expect("uri");
        assert_eq!(
            uri.transport(),
            &Transport::Unix {
                socket: "/p".into()
            }
        );
    }

    #[test]
    fn vsock_forms() {
        let uri = parse("nbd+vsock://3:1234/e").expect("vsock uri");
        assert_eq!(uri.transport(), &Transport::Vsock { cid: 3, port: 1234 });
        // Default port.
        let uri = parse("nbd+vsock://3/e").expect("vsock uri");
        assert_eq!(
            uri.transport(),
            &Transport::Vsock {
                cid: 3,
                port: 10809
            }
        );
        // cid and port are decimal u32; the largest u32 parses.
        let uri = parse("nbd+vsock://4294967295:4294967295/e").expect("vsock uri");
        assert_eq!(
            uri.transport(),
            &Transport::Vsock {
                cid: u32::MAX,
                port: u32::MAX
            }
        );
        assert_eq!(parse("nbd+vsock:///e"), Err(EINVAL));
        assert_eq!(parse("nbd+vsock://x/e"), Err(EINVAL));
        assert_eq!(parse("nbd+vsock://3:x/e"), Err(EINVAL));
        assert_eq!(parse("nbd+vsock://3:1:2/e"), Err(EINVAL));
    }

    #[test]
    fn tls_forms() {
        let uri = parse("nbds://h/e").expect("tls uri");
        let tls = uri.tls().expect("tls options");
        assert!(tls.verify_peer);
        assert_eq!(tls.certificates, None);
        assert_eq!(tls.hostname, None);
        let uri =
            parse("nbds://h/e?tls-verify-peer=false&tls-certificates=/ca&tls-hostname=x.example")
                .expect("tls uri");
        let tls = uri.tls().expect("tls options");
        assert!(!tls.verify_peer);
        assert_eq!(tls.certificates.as_deref(), Some("/ca"));
        assert_eq!(tls.hostname.as_deref(), Some("x.example"));
        // `1`/`0` are the libnbd spellings of true/false.
        assert!(
            !parse("nbds://h/e?tls-verify-peer=0")
                .unwrap()
                .tls()
                .unwrap()
                .verify_peer
        );
        assert!(
            parse("nbds://h/e?tls-verify-peer=1")
                .unwrap()
                .tls()
                .unwrap()
                .verify_peer
        );
        // An unknown value is refused.
        assert_eq!(parse("nbds://h/e?tls-verify-peer=maybe"), Err(EINVAL));
        // TLS parameters on a plain scheme are parsed and ignored.
        let uri = parse("nbd://h/e?tls-verify-peer=false").expect("plain uri");
        assert!(uri.tls().is_none());
        // Spec vector: the PSK parameters are -ENOTSUP.
        assert_eq!(parse("nbds://h/e?tls-psk-file=/k"), Err(ENOTSUP));
        assert_eq!(parse("nbd://h/e?tls-username=u"), Err(ENOTSUP));
        // Unix and vsock TLS schemes parse.
        assert!(parse("nbds+unix:///e?socket=/p").unwrap().tls().is_some());
        assert!(parse("nbds+vsock://3/e").unwrap().tls().is_some());
    }

    #[test]
    fn refused_schemes_and_malformed_uris() {
        // Spec vectors.
        assert_eq!(parse("nbd+ssh://h/e"), Err(ENOTSUP));
        assert_eq!(parse("nbds+ssh://h/e"), Err(ENOTSUP));
        assert_eq!(parse("http://h"), Err(EINVAL));
        // Unknown and case-shifted schemes.
        assert_eq!(parse("NBD://h"), Err(EINVAL));
        assert_eq!(parse("nbd+foo://h"), Err(EINVAL));
        assert_eq!(parse("nbd"), Err(EINVAL));
        assert_eq!(parse("nbd:/h"), Err(EINVAL));
        assert_eq!(parse(""), Err(EINVAL));
        // A TCP authority needs a host.
        assert_eq!(parse("nbd://"), Err(EINVAL));
        assert_eq!(parse("nbd:///e"), Err(EINVAL));
        assert_eq!(parse("nbd://:10809/e"), Err(EINVAL));
        // Ports are decimal u16 without a sign.
        assert_eq!(parse("nbd://h:x/e"), Err(EINVAL));
        assert_eq!(parse("nbd://h:70000/e"), Err(EINVAL));
        assert_eq!(parse("nbd://h:-1/e"), Err(EINVAL));
        assert_eq!(parse("nbd://h:+1/e"), Err(EINVAL));
        assert_eq!(parse("nbd://h:1:2/e"), Err(EINVAL));
        // Bracketed IPv6 must be closed and well formed.
        assert_eq!(parse("nbd://[::1/e"), Err(EINVAL));
        assert_eq!(parse("nbd://[]/e"), Err(EINVAL));
        assert_eq!(parse("nbd://[::1]x/e"), Err(EINVAL));
        // userinfo is PSK TLS.
        assert_eq!(parse("nbd://user@h/e"), Err(ENOTSUP));
        assert_eq!(parse("nbd://user:pw@h/e"), Err(ENOTSUP));
        // Malformed percent escapes and non-UTF-8 results.
        assert_eq!(parse("nbd://h/e%zz"), Err(EINVAL));
        assert_eq!(parse("nbd://h/e%2"), Err(EINVAL));
        assert_eq!(parse("nbd://h/e%ff"), Err(EINVAL));
        // A fragment is not part of the grammar.
        assert_eq!(parse("nbd://h/e#frag"), Err(EINVAL));
        assert_eq!(parse("nbd://h/e?x=1#frag"), Err(EINVAL));
    }

    #[test]
    fn unknown_parameters_are_ignored() {
        let uri = parse("nbd://h/e?unknown=1&socket=/ignored&tls-hostname=x").expect("uri");
        assert_eq!(
            uri.transport(),
            &Transport::Tcp {
                host: "h".into(),
                port: 10809
            }
        );
        // A parameter without a value is ignored as well.
        parse("nbd://h/e?flag").expect("valueless parameter");
    }

    #[test]
    fn display_drops_the_query() {
        let uri = parse("nbd://h:1234/e?socket=/x&unknown=1").expect("uri");
        assert_eq!(uri.display(), "nbd://h:1234/e");
        let uri = parse("nbd+unix:///e?socket=/p").expect("uri");
        assert_eq!(uri.display(), "nbd+unix:///e");
        let uri = parse("nbd://h/e").expect("uri");
        assert_eq!(uri.display(), "nbd://h/e");
    }

    #[test]
    fn no_port_carries_over_between_parses() {
        // A port parsed from one authority must not become the port of the
        // next URI that names none.
        assert_eq!(tcp("nbd://h:1234/e").1, 1234);
        assert_eq!(tcp("nbd://h/e").1, DEFAULT_PORT);
        assert_eq!(tcp("nbd://h:1234/e").1, 1234);
    }
}
