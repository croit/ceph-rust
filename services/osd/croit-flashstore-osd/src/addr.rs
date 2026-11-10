// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Address spelling shared by the run modes (`--ip`, `--public-addr`, `--cluster-addr`, conf `public_addr`).
use std::net::IpAddr;

/// An address as classic writes `public_addr`: `IP`, `[v6]`, `[v6]:port`, `IP:port`,
/// `[v2:|v1:|any:]IP[:port][/nonce]`. The type prefix does not matter (the listener is msgr2, as classic retypes the
/// configured address). Port 0 = none: the port search picks it (`osd::portsel`).
pub(crate) fn parse_addr(s: &str) -> Result<(IpAddr, u16), String> {
    let bad = || format!("bad address {s:?}");
    let t = s.trim();
    let t = ["v2:", "v1:", "any:"]
        .iter()
        .find_map(|p| t.strip_prefix(p))
        .unwrap_or(t);
    let t = t.split('/').next().unwrap_or(t); // /nonce
    if let Some(r) = t.strip_prefix('[') {
        let (h, tail) = r.split_once(']').ok_or_else(bad)?;
        let ip: IpAddr = h.parse().map_err(|_| bad())?;
        let port = match tail {
            "" => 0,
            p => p
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(bad)?,
        };
        return Ok((ip, port));
    }
    // a bare address (IPv6 without brackets never carries a port, spec 5)
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Ok((ip, 0));
    }
    match t.split_once(':') {
        Some((ip, port)) => Ok((
            ip.parse().map_err(|_| bad())?,
            port.parse::<u16>().map_err(|_| bad())?,
        )),
        None => Err(bad()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_spellings() {
        for (s, ip, port) in [
            ("10.1.2.3", "10.1.2.3", 0),
            ("10.1.2.3/24", "10.1.2.3", 0),
            ("v2:10.1.2.3:6800/0", "10.1.2.3", 6800),
            ("v1:10.1.2.3:6789", "10.1.2.3", 6789),
            ("10.1.2.3:0", "10.1.2.3", 0),
            ("10.1.2.3:6820", "10.1.2.3", 6820),
            (" any:10.1.2.3 ", "10.1.2.3", 0),
            // spec 5: an unbracketed IPv6 never carries a port, a bracketed one does
            ("fd00::1", "fd00::1", 0),
            ("[fd00::1]", "fd00::1", 0),
            ("[fd00::1]:3300", "fd00::1", 3300),
            ("v2:[fd00::1]:3300/7", "fd00::1", 3300),
            ("[::ffff:10.1.2.3]:6800", "::ffff:10.1.2.3", 6800),
        ] {
            assert_eq!(
                parse_addr(s),
                Ok((ip.parse::<IpAddr>().unwrap(), port)),
                "{s}"
            );
        }
        assert!(parse_addr("host.example").is_err());
        assert!(parse_addr("10.1.2.3:x").is_err());
        assert!(parse_addr("[fd00::1").is_err());
    }
}
