// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Kill switch `ec_enable_pools` (adr 0039): which supported EC pools this OSD may serve. Default off.

/// Parsed `ec_enable_pools`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum EcEnable {
    #[default]
    Off,
    All,
    /// Pool ids (decimal) or names.
    Pools(Vec<String>),
}

impl EcEnable {
    /// `off` (or empty) | `all` | comma separated pool ids / names.
    pub fn parse(s: &str) -> EcEnable {
        let t = s.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("off") {
            return EcEnable::Off;
        }
        if t.eq_ignore_ascii_case("all") {
            return EcEnable::All;
        }
        let v: Vec<String> = t
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect();
        if v.is_empty() {
            EcEnable::Off
        } else {
            EcEnable::Pools(v)
        }
    }

    pub fn allows(&self, pool_id: u64, pool_name: impl AsRef<[u8]>) -> bool {
        match self {
            EcEnable::Off => false,
            EcEnable::All => true,
            EcEnable::Pools(v) => {
                let id = pool_id.to_string();
                v.iter()
                    .any(|p| *p == id || p.as_bytes() == pool_name.as_ref())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_do_not_match_lossy_or_nul_truncated_names() {
        let by_name = EcEnable::parse("p�,ascii");
        assert!(!by_name.allows(9, [b'p', 255]));
        assert!(!by_name.allows(9, b"ascii\0suffix"));
        assert!(by_name.allows(9, "p�"));
        assert!(EcEnable::parse("9").allows(9, [255]));
        assert!(EcEnable::All.allows(9, [255]));
        assert!(!EcEnable::Off.allows(9, [255]));
    }
    #[test]
    fn parse_and_allow() {
        assert_eq!(EcEnable::parse(""), EcEnable::Off);
        assert_eq!(EcEnable::parse(" off "), EcEnable::Off);
        assert_eq!(EcEnable::parse("ALL"), EcEnable::All);
        assert_eq!(EcEnable::parse(",,"), EcEnable::Off);
        let p = EcEnable::parse("3, ecpool ,7");
        assert_eq!(
            p,
            EcEnable::Pools(vec!["3".into(), "ecpool".into(), "7".into()])
        );
        assert!(p.allows(3, "x"));
        assert!(p.allows(9, "ecpool"));
        assert!(!p.allows(4, "other"));
        assert!(!EcEnable::Off.allows(1, "a"));
        assert!(EcEnable::All.allows(1, "a"));
        assert_eq!(EcEnable::default(), EcEnable::Off);
    }
}
