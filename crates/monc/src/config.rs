// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! MonClient configuration and `mon_host` parsing (spec osd-lifecycle.md 2.1-2.3).
use cephx::CryptoKey;
use cephx::modes::{AUTH_CEPHX, parse_modes};
use cephx::monclient::MonAuthConfig;
use cephx::none::{ENTITY_AUTH, ENTITY_CLIENT, ENTITY_MON, ENTITY_OSD, EntityName as AuthName};
use denc::types::{EntityAddr, EntityAddrVec, EntityName, Uuid};
use osdmap::MonMap;
use std::net::ToSocketAddrs;
use std::time::Duration;

/// Default msgr2 / legacy mon ports.
pub const PORT_V2: u16 = 3300;
/// Legacy (v1) mon port.
pub const PORT_V1: u16 = 6789;

/// MonClient configuration. Option names in comments are the Ceph config keys.
#[derive(Clone, Debug)]
pub struct Config<E = String> {
    /// Our entity, e.g. `osd.3`, `client.admin`.
    pub entity: E,
    /// Independent messenger identity; None derives it from the auth principal.
    pub messenger_name: Option<EntityName>,
    /// Own cephx secret. `None` = method NONE only.
    pub key: Option<CryptoKey>,
    /// Auth methods in preference order (`auth_client_required` / `auth_cluster_required`).
    pub methods: Vec<u32>,
    /// Connection modes in preference order (clients: `ms_mon_client_mode`, daemons: `ms_mon_cluster_mode`; both default
    /// `secure crc`).
    pub modes: Vec<u32>,
    /// Service tickets to hold (ENTITY_* mask).
    pub want: u32,
    /// Fetch rotating service keys (daemons yes, clients no).
    pub want_rotating: bool,
    /// `auth_service_ticket_ttl` seconds.
    pub service_ticket_ttl: u32,
    /// Cluster fsid for commands/log (zero = unknown; replaced by the monmap fsid when learned).
    pub fsid: Uuid,
    /// Short hostname sent in MMonSubscribe.
    pub hostname: String,
    /// Initial monmap (mkfs monmap); else built from `mon_host`.
    pub initial_monmap: Option<MonMap>,
    /// Initial `mon_host` (parsed with [`parse_mon_host`]).
    pub mon_host: Vec<EntityAddrVec>,
    /// Unix wall time (since the epoch, nanosecond precision) at the monotonic origin (`now == 0`); used for cephx.
    pub wall_origin: Duration,
    /// Seed for hunt shuffling, cookies, address nonce (use OS randomness).
    pub seed: u64,
    /// `ms_*` feature mask we support.
    pub supported_features: u64,
    /// Advertise msgr2 compression handshake (default off).
    pub compression: bool,
    /// Hard frame shape; independent of messenger role and authentication principal.
    pub frame_limits: msgr2::Limits,
    /// `ms_crc_data` (spec msgr2.md 4.3): segment CRCs of CRC-mode frames, read when a connection is created
    /// (default true; false leaves frame integrity to TCP).
    pub crc_data: bool,
    /// Drop central fsid/host before exposing snapshots (daemon/strict policy).
    pub filter_config_identity: bool,
    /// `mon_client_hunt_parallel` (0 = every candidate mon at once).
    pub hunt_parallel: usize,
    /// `mon_client_hunt_interval`.
    pub hunt_interval: Duration,
    /// `mon_client_hunt_interval_backoff`.
    pub hunt_backoff: f64,
    /// `mon_client_hunt_interval_max_multiple`.
    pub hunt_max_multiple: f64,
    /// `mon_client_hunt_interval_min_multiple`.
    pub hunt_min_multiple: f64,
    /// `mon_client_ping_interval`.
    pub ping_interval: Duration,
    /// `mon_client_ping_timeout` (zero disables keepalive expiry).
    pub ping_timeout: Duration,
    /// `mon_client_log_interval`.
    pub log_interval: Duration,
    /// `mon_client_max_log_entries_per_message` (default 1000, the pinned Ceph default).
    pub max_log_entries: usize,
    /// `mon_subscribe_interval`: full resend of all subscriptions (None = never).
    pub sub_renew_interval: Option<Duration>,
    /// `mon_client_target_rank` (pin one rank; testing).
    pub target_rank: Option<usize>,
    /// `rados_mon_op_timeout` (None = no timeout).
    pub command_timeout: Option<Duration>,
    /// Subscribe `monmap` and `config` automatically at session open (default true).
    pub default_subs: bool,
    /// Our msgr2 policy required features toward the mon.
    pub mon_required_features: u64,
    /// Our advertised addresses (mons record the source addrvec of an OSD as its public address).
    /// `None` = one blank msgr2 address with a random nonce (pure clients).
    pub my_addrs: Option<EntityAddrVec>,
}

impl Config {
    /// Defaults for entity `entity` (e.g. `client.admin`) with cephx `key`.
    pub fn new(entity: &str, key: Option<CryptoKey>) -> Self {
        Self::defaults(entity.to_owned(), key)
    }
    /// Librados transport role is CLIENT independently of its auth principal.
    pub fn new_client(entity: &str, key: Option<CryptoKey>) -> Self {
        Self::new(entity, key).client_role()
    }
    /// Strict native text principal adapter.
    pub fn auth_name(&self) -> AuthName {
        AuthName::parse(&self.entity).unwrap_or(AuthName {
            ty: ENTITY_CLIENT,
            id: self.entity.clone(),
        })
    }
}
impl Config<Vec<u8>> {
    pub fn new_bytes(entity: &[u8], key: Option<CryptoKey>) -> Self {
        Self::defaults(entity.to_vec(), key)
    }
    pub fn new_client_bytes(entity: &[u8], key: Option<CryptoKey>) -> Self {
        Self::new_bytes(entity, key).client_role()
    }
    pub fn auth_name(&self) -> AuthName<Vec<u8>> {
        self.auth_name_bytes()
    }
}
/// The `mon_client_*` session timers and log batching of a [`Config`]: classic reads them on every use, so a running
/// [`crate::MonClient`] takes a new set at any time ([`crate::MonClient::set_timers`]); a hunt or keepalive already
/// scheduled keeps its deadline, the next one uses the new values.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Timers {
    /// `mon_client_hunt_parallel` (0 = every candidate mon at once).
    pub hunt_parallel: usize,
    /// `mon_client_hunt_interval`.
    pub hunt_interval: Duration,
    /// `mon_client_hunt_interval_backoff` (finite, > 0).
    pub hunt_backoff: f64,
    /// `mon_client_hunt_interval_max_multiple` (finite, > 0).
    pub hunt_max_multiple: f64,
    /// `mon_client_hunt_interval_min_multiple` (finite, > 0).
    pub hunt_min_multiple: f64,
    /// `mon_client_ping_interval`.
    pub ping_interval: Duration,
    /// `mon_client_ping_timeout` (zero disables keepalive expiry).
    pub ping_timeout: Duration,
    /// `mon_client_log_interval`.
    pub log_interval: Duration,
    /// `mon_client_max_log_entries_per_message`.
    pub max_log_entries: usize,
}

impl<E> Config<E> {
    /// The current timer set.
    pub fn timers(&self) -> Timers {
        Timers {
            hunt_parallel: self.hunt_parallel,
            hunt_interval: self.hunt_interval,
            hunt_backoff: self.hunt_backoff,
            hunt_max_multiple: self.hunt_max_multiple,
            hunt_min_multiple: self.hunt_min_multiple,
            ping_interval: self.ping_interval,
            ping_timeout: self.ping_timeout,
            log_interval: self.log_interval,
            max_log_entries: self.max_log_entries,
        }
    }
    /// Replace the timer set.
    pub fn set_timers(&mut self, t: Timers) {
        self.hunt_parallel = t.hunt_parallel;
        self.hunt_interval = t.hunt_interval;
        self.hunt_backoff = t.hunt_backoff;
        self.hunt_max_multiple = t.hunt_max_multiple;
        self.hunt_min_multiple = t.hunt_min_multiple;
        self.ping_interval = t.ping_interval;
        self.ping_timeout = t.ping_timeout;
        self.log_interval = t.log_interval;
        self.max_log_entries = t.max_log_entries;
    }
}

impl<E: AsRef<[u8]>> Config<E> {
    fn defaults(entity: E, key: Option<CryptoKey>) -> Self {
        let is_client = entity.as_ref().starts_with(b"client.");
        Self {
            entity,
            messenger_name: None,
            key,
            methods: vec![AUTH_CEPHX],
            modes: parse_modes("secure crc").modes,
            want: if is_client {
                ENTITY_MON | ENTITY_OSD | ENTITY_AUTH
            } else {
                ENTITY_MON | ENTITY_OSD | cephx::none::ENTITY_MGR | ENTITY_AUTH
            },
            want_rotating: !is_client,
            service_ticket_ttl: 3600,
            fsid: Uuid::default(),
            hostname: String::new(),
            initial_monmap: None,
            mon_host: Vec::new(),
            wall_origin: Duration::ZERO,
            seed: 1,
            supported_features: msgr2::FEATURES_SUPPORTED_DEFAULT,
            compression: false,
            frame_limits: msgr2::Limits::default(),
            crc_data: true,
            filter_config_identity: true,
            hunt_parallel: 3,
            hunt_interval: Duration::from_secs(3),
            hunt_backoff: 1.5,
            hunt_max_multiple: 10.0,
            hunt_min_multiple: 1.0,
            ping_interval: Duration::from_secs(10),
            ping_timeout: Duration::from_secs(30),
            log_interval: Duration::from_secs(1),
            max_log_entries: 1000,
            sub_renew_interval: Some(Duration::from_secs(86400)),
            target_rank: None,
            command_timeout: None,
            default_subs: true,
            mon_required_features: msgr2::OSD_REQUIRED,
            my_addrs: None,
        }
    }

    /// Librados transport role is CLIENT independently of its auth principal.
    fn client_role(mut self) -> Self {
        self.messenger_name = Some(EntityName::client(-1));
        self.want = ENTITY_MON | ENTITY_OSD | cephx::none::ENTITY_MGR | ENTITY_AUTH;
        self.want_rotating = matches!(
            self.auth_name_bytes().ty,
            ENTITY_OSD | cephx::none::ENTITY_MDS | cephx::none::ENTITY_MGR
        );
        self
    }

    /// cephx entity name.
    fn auth_name_bytes(&self) -> AuthName<Vec<u8>> {
        AuthName::parse_bytes(self.entity.as_ref()).unwrap_or(AuthName {
            ty: ENTITY_CLIENT,
            id: self.entity.as_ref().to_vec(),
        })
    }

    /// msgr2 entity name (client ids are strings: numeric part = -1, taken from the global id).
    pub fn msgr_name(&self) -> EntityName {
        if let Some(name) = self.messenger_name {
            return name;
        }
        let n = self.auth_name_bytes();
        let num = if n.ty == ENTITY_CLIENT {
            -1
        } else {
            std::str::from_utf8(&n.id)
                .ok()
                .and_then(|id| id.parse::<i64>().ok())
                .unwrap_or(-1)
        };
        EntityName::new(n.ty as u8, num)
    }

    pub(crate) fn auth_cfg(&self, key: CryptoKey) -> MonAuthConfig<Vec<u8>> {
        MonAuthConfig {
            name: self.auth_name_bytes(),
            key,
            want: self.want,
            want_rotating: self.want_rotating,
            service_ticket_ttl: self.service_ticket_ttl,
        }
    }
    /// Own the original bytes without a parallel text identity or label.
    pub fn into_bytes(self) -> Config<Vec<u8>> {
        Config {
            entity: self.entity.as_ref().to_vec(),
            messenger_name: self.messenger_name,
            key: self.key,
            methods: self.methods,
            modes: self.modes,
            want: self.want,
            want_rotating: self.want_rotating,
            service_ticket_ttl: self.service_ticket_ttl,
            fsid: self.fsid,
            hostname: self.hostname,
            initial_monmap: self.initial_monmap,
            mon_host: self.mon_host,
            wall_origin: self.wall_origin,
            seed: self.seed,
            supported_features: self.supported_features,
            compression: self.compression,
            frame_limits: self.frame_limits,
            crc_data: self.crc_data,
            filter_config_identity: self.filter_config_identity,
            hunt_parallel: self.hunt_parallel,
            hunt_interval: self.hunt_interval,
            hunt_backoff: self.hunt_backoff,
            hunt_max_multiple: self.hunt_max_multiple,
            hunt_min_multiple: self.hunt_min_multiple,
            ping_interval: self.ping_interval,
            ping_timeout: self.ping_timeout,
            log_interval: self.log_interval,
            max_log_entries: self.max_log_entries,
            sub_renew_interval: self.sub_renew_interval,
            target_rank: self.target_rank,
            command_timeout: self.command_timeout,
            default_subs: self.default_subs,
            mon_required_features: self.mon_required_features,
            my_addrs: self.my_addrs,
        }
    }
}

/// Parse a `mon_host` value: separators `,` `;` space; entries `ip`, `ip:port`, `[ip6]:port`, `v2:ip:port`,
/// `v1:ip:port`, a hostname (all A and AAAA records, resolver order) or a bracketed vector `[v2:ip:3300,v1:ip:6789]`.
/// A bare IP yields both v2 (3300) and v1 (6789); `/nonce` is kept. Typed forms are never resolved (spec 5).
pub fn parse_mon_host(s: &str) -> Result<Vec<EntityAddrVec>, String> {
    let mut out = Vec::new();
    let mut rest = s.trim();
    while !rest.is_empty() {
        rest = rest.trim_start_matches(|c: char| c == ',' || c == ';' || c.is_whitespace());
        if rest.is_empty() {
            break;
        }
        // a bracketed vector, unless the bracket itself is a bracketed IPv6 address (`[fd00::1]:3300`, spec 5)
        let is_vec = rest.starts_with('[') && bracketed_v6_end(rest).is_none();
        let (tok, tail) = if is_vec {
            let mut depth = 0i32;
            let mut end = None;
            for (i, c) in rest.char_indices() {
                match c {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let end = end.ok_or("unterminated [")?;
            (&rest[1..end], &rest[end + 1..])
        } else {
            let mut end = rest.len();
            let mut in_br = false;
            for (i, c) in rest.char_indices() {
                match c {
                    '[' => in_br = true,
                    ']' => in_br = false,
                    ',' | ';' | ' ' | '\t' if !in_br => {
                        end = i;
                        break;
                    }
                    _ => {}
                }
            }
            (&rest[..end], &rest[end..])
        };
        if is_vec {
            // elements keep their own types/ports and form one mon
            let mut v = Vec::new();
            for a in tok.split(',') {
                v.extend(parse_vector_element(a.trim())?);
            }
            if v.is_empty() {
                return Err("empty mon vector".into());
            }
            out.push(EntityAddrVec(v));
        } else {
            // one mon per element; a hostname expands to one mon per resolved record
            out.extend(parse_element(tok)?.into_iter().map(EntityAddrVec));
        }
        rest = tail;
    }
    Ok(out)
}

/// Byte offset of the closing `]` when `s` starts with a bracketed IPv6 address (`[fd00::1]:3300`).
fn bracketed_v6_end(s: &str) -> Option<usize> {
    let r = s.strip_prefix('[')?;
    let i = r.find(']')?;
    r[..i].parse::<std::net::Ipv6Addr>().ok().map(|_| i + 1)
}

/// Optional `v1:` / `v2:` / `any:` prefix.
fn split_type(t: &str) -> (Option<u32>, &str) {
    if let Some(b) = t.strip_prefix("v2:") {
        (Some(EntityAddr::TYPE_MSGR2), b)
    } else if let Some(b) = t.strip_prefix("v1:") {
        (Some(EntityAddr::TYPE_LEGACY), b)
    } else if let Some(b) = t.strip_prefix("any:") {
        (Some(EntityAddr::TYPE_ANY), b)
    } else {
        (None, t)
    }
}

/// A mon_host element: one addrvec (an IP, or `v2:...`), or one per resolved record of an untyped hostname.
fn parse_element(t: &str) -> Result<Vec<Vec<EntityAddr>>, String> {
    let (ty, body) = split_type(t);
    let (body, nonce) = match body.split_once('/') {
        Some((b, n)) => (
            b,
            n.parse::<u32>()
                .map_err(|_| format!("bad mon address '{t}' (nonce)"))?,
        ),
        None => (body, 0),
    };
    match split_target(body)? {
        (Target::Ip(ip), port) => Ok(vec![typed_or_expanded(ty, ip, port, nonce)?]),
        // spec 5: a typed form is never resolved
        (Target::Name(_), _) if ty.is_some() => {
            Err(format!("typed mon address '{t}' is not resolved"))
        }
        (Target::Name(h), port) => resolve_host(h, port)?
            .into_iter()
            .map(|ip| typed_or_expanded(None, ip, port, nonce))
            .collect(),
    }
}

/// One element inside a bracketed mon vector: a single address.
fn parse_vector_element(t: &str) -> Result<Vec<EntityAddr>, String> {
    let mut v = parse_element(t)?;
    if v.len() != 1 {
        return Err(format!(
            "mon vector element '{t}' must be one address, not a hostname"
        ));
    }
    Ok(v.remove(0))
}

/// Address expansion of spec 5 step 2: a typed address keeps its type, an untyped one expands by port.
fn typed_or_expanded(
    ty: Option<u32>,
    ip: std::net::IpAddr,
    port: Option<u16>,
    nonce: u32,
) -> Result<Vec<EntityAddr>, String> {
    let mk = |ty, port, nonce| match ip {
        std::net::IpAddr::V4(a) => EntityAddr::v4(ty, nonce, a.octets(), port),
        std::net::IpAddr::V6(a) => EntityAddr::v6(ty, nonce, a.octets(), port, 0),
    };
    Ok(match (ty, port) {
        (Some(ty), p) => vec![mk(
            ty,
            p.unwrap_or(if ty == EntityAddr::TYPE_LEGACY {
                PORT_V1
            } else {
                PORT_V2
            }),
            nonce,
        )],
        // explicit legacy port: v1 only; else both
        (None, Some(PORT_V1)) => vec![mk(EntityAddr::TYPE_LEGACY, PORT_V1, nonce)],
        (None, Some(p)) => vec![mk(EntityAddr::TYPE_MSGR2, p, nonce)],
        (None, None) => vec![
            mk(EntityAddr::TYPE_MSGR2, PORT_V2, nonce),
            mk(EntityAddr::TYPE_LEGACY, PORT_V1, nonce),
        ],
    })
}

/// All A and AAAA records of `host` in resolver order, duplicates dropped (spec 5: `getaddrinfo(AF_UNSPEC)`).
fn resolve_host(host: &str, port: Option<u16>) -> Result<Vec<std::net::IpAddr>, String> {
    let mut out: Vec<std::net::IpAddr> = Vec::new();
    for sa in (host, port.unwrap_or(0))
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve mon host '{host}': {e}"))?
    {
        if !out.contains(&sa.ip()) {
            out.push(sa.ip());
        }
    }
    if out.is_empty() {
        return Err(format!("mon host '{host}' resolved to no address"));
    }
    Ok(out)
}

enum Target<'a> {
    Ip(std::net::IpAddr),
    Name(&'a str),
}

/// Split `host[:port]`, `[v6][:port]` or `host` (spec 5: an unbracketed IPv6 never carries a port).
fn split_target(s: &str) -> Result<(Target<'_>, Option<u16>), String> {
    let bad = || format!("bad mon address '{s}'");
    if let Some(r) = s.strip_prefix('[') {
        let (h, t) = r.split_once(']').ok_or_else(bad)?;
        let ip = h.parse().map_err(|_| bad())?;
        let port = match t {
            "" => None,
            t => Some(
                t.strip_prefix(':')
                    .ok_or_else(bad)?
                    .parse()
                    .map_err(|_| bad())?,
            ),
        };
        return Ok((Target::Ip(ip), port));
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok((Target::Ip(ip), None));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Ok((
            h.parse().map_or(Target::Name(h), Target::Ip),
            Some(p.parse().map_err(|_| bad())?),
        )),
        _ => Ok((Target::Name(s), None)),
    }
}

/// Build a synthetic epoch-0 monmap (`noname-a`, ..., `noname-z`, `noname-aa`, ...) from parsed addresses.
pub fn monmap_from_addrs(addrs: &[EntityAddrVec]) -> MonMap {
    let mut m = MonMap::default();
    for (i, a) in addrs.iter().enumerate() {
        let mut ordinal = i;
        let mut suffix = Vec::new();
        loop {
            suffix.push(char::from(b'a' + (ordinal % 26) as u8));
            if ordinal < 26 {
                break;
            }
            ordinal = ordinal / 26 - 1;
        }
        let name = format!("noname-{}", suffix.into_iter().rev().collect::<String>());
        m.ranks.push(name.clone());
        m.mon_info.insert(
            name.clone(),
            osdmap::MonInfo {
                name,
                public_addrs: a.clone(),
                ..Default::default()
            },
        );
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(v: &[EntityAddrVec]) -> Vec<String> {
        v.iter()
            .map(|a| {
                a.0.iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect()
    }

    /// Library users (rustyrados) get the pinned Ceph default of `mon_client_max_log_entries_per_message`.
    #[test]
    fn log_batch_default_matches_ceph() {
        assert_eq!(Config::new("osd.0", None).max_log_entries, 1000);
        assert_eq!(
            Config::new_client("client.admin", None).max_log_entries,
            1000
        );
    }

    #[test]
    fn client_transport_role_is_independent_of_configured_principal() {
        for role in ["auth", "mon", "osd", "mds", "mgr", "client"] {
            let entity = format!("{role}.name with spaces");
            let cfg = Config::new_client(&entity, None);
            assert_eq!(cfg.auth_name(), AuthName::parse(&entity).unwrap());
            assert_eq!(cfg.msgr_name(), EntityName::client(-1));
            assert_eq!(
                cfg.want,
                ENTITY_MON | ENTITY_OSD | cephx::none::ENTITY_MGR | ENTITY_AUTH
            );
            assert_eq!(cfg.want_rotating, matches!(role, "osd" | "mds" | "mgr"));
        }
        let daemon = Config::new("osd.3", None);
        assert_eq!(daemon.msgr_name(), EntityName::new(EntityName::OSD, 3));
    }
    #[test]
    fn byte_client_config_owns_suffix_and_preserves_native_defaults_and_roles() {
        for role in ["auth", "mon", "osd", "mds", "mgr", "client"] {
            let text = format!("{role}.name with spaces.more");
            let native = Config::new_client(&text, None);
            let bytes = Config::new_client_bytes(text.as_bytes(), None);
            assert_eq!(native.auth_name(), bytes.auth_name());
            assert_eq!(native.msgr_name(), bytes.msgr_name());
            assert_eq!(native.want, bytes.want);
            assert_eq!(native.want_rotating, bytes.want_rotating);
            assert_eq!(native.methods, bytes.methods);
            assert_eq!(native.modes, bytes.modes);
            let mut input = format!("{role}.").into_bytes();
            input.extend_from_slice(b"\xff\x80.more spaces");
            let bytes = Config::new_client_bytes(&input, None);
            input.fill(b'x');
            assert_eq!(bytes.auth_name().id, b"\xff\x80.more spaces");
            assert_eq!(bytes.msgr_name(), EntityName::client(-1));
            assert_eq!(bytes.want_rotating, native.want_rotating);
        }
    }

    #[test]
    fn synthetic_mon_names_are_unique_after_twenty_six_entries() {
        let addrs: Vec<_> = (0..27)
            .map(|i| EntityAddrVec::single(EntityAddr::v4(2, 0, [127, 0, 0, 1], 3300 + i)))
            .collect();
        let map = monmap_from_addrs(&addrs);
        assert_eq!(map.mon_info.len(), addrs.len());
        for (name, expected) in map.ranks.iter().zip(&addrs) {
            assert_eq!(&map.mon_info[name].public_addrs, expected);
        }
    }

    #[test]
    fn mon_host_forms() {
        let v = parse_mon_host("v2:172.28.0.10:3300").unwrap();
        assert_eq!(d(&v), ["v2:172.28.0.10:3300/0"]);
        let v = parse_mon_host(
            "[v2:10.0.0.1:3300,v1:10.0.0.1:6789] 10.0.0.2,10.0.0.3:6789;[v2:[::1]:3300]",
        )
        .unwrap();
        assert_eq!(
            d(&v),
            [
                "v2:10.0.0.1:3300/0,v1:10.0.0.1:6789/0",
                "v2:10.0.0.2:3300/0,v1:10.0.0.2:6789/0",
                "v1:10.0.0.3:6789/0",
                "v2:[::1]:3300/0",
            ]
        );
        assert_eq!(
            d(&parse_mon_host("v2:172.28.0.12:3300/0").unwrap()),
            ["v2:172.28.0.12:3300/0"]
        );
        assert!(parse_mon_host("nonsense").is_err());
        assert!(parse_mon_host("").unwrap().is_empty());
    }

    /// Spec 5: untyped elements inside a vector, `/nonce`, a bare IPv6 (no port), `[v6]:port`.
    #[test]
    fn mon_host_ipv6_vectors_nonce_and_bare_forms() {
        // an untyped vector: every element keeps its own type/port and forms one mon
        let v = parse_mon_host("[[fd00::1]:3300,[fd00::1]:6789]").unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(d(&v), ["v2:[fd00::1]:3300/0,v1:[fd00::1]:6789/0"]);
        // a single bracketed IPv6 is an address, not a vector
        assert_eq!(
            d(&parse_mon_host("[fd00::1]:3300").unwrap()),
            ["v2:[fd00::1]:3300/0"]
        );
        // an unbracketed IPv6 never carries a port: fd00::1:3300 is the address itself
        assert_eq!(
            d(&parse_mon_host("fd00::1").unwrap()),
            ["v2:[fd00::1]:3300/0,v1:[fd00::1]:6789/0"]
        );
        assert_eq!(
            d(&parse_mon_host("fd00::1:3300").unwrap()),
            ["v2:[fd00::1:3300]:3300/0,v1:[fd00::1:3300]:6789/0"]
        );
        // the nonce reaches the address
        assert_eq!(
            d(&parse_mon_host("v2:[fd00::1]:3300/0").unwrap()),
            ["v2:[fd00::1]:3300/0"]
        );
        assert_eq!(
            d(&parse_mon_host("v2:[fd00::1]:3300/7").unwrap()),
            ["v2:[fd00::1]:3300/7"]
        );
        assert!(parse_mon_host("v2:[fd00::1]:3300/x").is_err());
        // v4-mapped prints as inet_ntop does
        assert_eq!(
            d(&parse_mon_host("[::ffff:10.0.0.1]:3300").unwrap()),
            ["v2:[::ffff:10.0.0.1]:3300/0"]
        );
        // typed hostnames are not resolved
        assert!(parse_mon_host("v2:mon1.example:3300").is_err());
    }

    /// Spec 5: an untyped hostname resolves to all A and AAAA records; each becomes its own mon.
    #[test]
    fn mon_host_hostname_resolves_a_and_aaaa() {
        // "localhost" is in every resolver: it has at least one A/AAAA record
        let v = parse_mon_host("localhost:3300").unwrap();
        assert!(!v.is_empty(), "resolved");
        for m in &v {
            assert_eq!(m.0.len(), 1, "port 3300 -> v2 only: {m:?}");
            assert_eq!(m.0[0].ty, EntityAddr::TYPE_MSGR2);
            assert_eq!(m.0[0].port(), 3300);
        }
        // without a port each record expands to v2+v1
        let v = parse_mon_host("localhost").unwrap();
        assert!(v.iter().all(|m| m.0.len() == 2));
        assert!(parse_mon_host("no-such-host.invalid").is_err());
    }
}
