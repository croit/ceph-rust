// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Address selection of the kernel tier as classic Ceph does it (spec ip-addressing.md 2 / 2.2): `public_network` /
//! `cluster_network` (comma, `;` or space separated `ip/prefix` networks, IPv4 and IPv6 may be mixed) pick one local
//! interface address per enabled family (`ms_bind_ipv4` / `ms_bind_ipv6`). Pure logic + `getifaddrs`.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One IP address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// IPv4 (`AF_INET`).
    V4,
    /// IPv6 (`AF_INET6`).
    V6,
}

impl Family {
    /// The family of `ip`.
    pub fn of(ip: IpAddr) -> Family {
        match ip {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }

    /// [`Family::V4`] for IPv4, [`Family::V6`] for IPv6.
    pub fn matches(self, ip: IpAddr) -> bool {
        self == Family::of(ip)
    }

    /// Address of a wildcard bind of this family.
    pub const fn wildcard(self) -> IpAddr {
        match self {
            Family::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Family::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }

    /// Operator-facing name (`ms_bind_ipv4` / `ms_bind_ipv6` messages).
    pub const fn name(self) -> &'static str {
        match self {
            Family::V4 => "IPv4",
            Family::V6 => "IPv6",
        }
    }
}

/// Families a daemon binds and the order of the families inside its advertised addrvec (`ms_bind_ipv4`,
/// `ms_bind_ipv6`, `ms_bind_prefer_ipv4`, spec 1 / 2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Families {
    /// `ms_bind_ipv4` (default true).
    pub v4: bool,
    /// `ms_bind_ipv6` (default false).
    pub v6: bool,
    /// `ms_bind_prefer_ipv4` (default false = IPv6 entries first).
    pub prefer_v4: bool,
}

impl Default for Families {
    fn default() -> Families {
        Families {
            v4: true,
            v6: false,
            prefer_v4: false,
        }
    }
}

impl Families {
    /// The enabled families in advertised order: IPv6 first unless `ms_bind_prefer_ipv4` (spec 2.4).
    pub fn ordered(&self) -> Vec<Family> {
        match (self.v4, self.v6, self.prefer_v4) {
            (true, false, _) => vec![Family::V4],
            (false, true, _) => vec![Family::V6],
            (true, true, true) => vec![Family::V4, Family::V6],
            (true, true, false) => vec![Family::V6, Family::V4],
            (false, false, _) => Vec::new(),
        }
    }
}

/// An `ip/prefix` network. The slash is mandatory (spec 2.2: no bare address); IPv6 link-local is never selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    /// Network address.
    addr: IpAddr,
    /// Prefix length in bits (never above the family's width, see [`Net::new`]).
    prefix: u8,
}

impl Net {
    /// `addr`/`prefix`; None if the prefix exceeds the family's bit width (the masks are shifts by `width - prefix`).
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Net> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        (prefix <= max).then_some(Net { addr, prefix })
    }

    /// Parse `ADDR/PREFIX`; None for a bare address, a foreign family, a prefix out of range or trailing junk.
    pub fn parse(s: &str) -> Option<Net> {
        let (ip, p) = s.trim().split_once('/')?;
        let addr: IpAddr = ip.parse().ok()?;
        if p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        Net::new(addr, p.parse().ok()?)
    }

    /// Family of the network.
    pub fn family(&self) -> Family {
        Family::of(self.addr)
    }

    /// Is `ip` (of this network's family) inside?
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = mask32(self.prefix);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let (n, a) = (u128::from(n), u128::from(a));
                let mask = mask128(self.prefix);
                n & mask == a & mask
            }
            _ => false,
        }
    }
}

fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

/// Parse a network list (`10.0.0.0/24, fd00::/64`); None if any element is malformed (fatal, spec 2.2). Families may
/// be mixed; an empty string yields no networks.
pub fn parse_networks(s: &str) -> Option<Vec<Net>> {
    s.split([',', ' ', ';', '\t'])
        .filter(|x| !x.is_empty())
        .map(Net::parse)
        .collect()
}

/// Parse an interface-name filter (`public_network_interface`: `,`, `;`, space).
pub fn parse_ifaces(s: &str) -> Vec<String> {
    s.split([',', ' ', ';', '\t'])
        .filter(|x| !x.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A local interface address in `getifaddrs` order (the pick keeps the first match, spec 2.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfAddr {
    /// Interface name.
    pub iface: String,
    /// Address on it.
    pub ip: IpAddr,
    /// Prefix length of the address on its interface (from its netmask; 32/128 when the netmask is absent).
    pub prefix: u8,
}

/// Prefix length of a netmask sockaddr (`ifa_netmask`): the count of leading one bits; `full` when absent.
///
/// # Safety
/// `nm` is null or points to a sockaddr of the address family of the entry (`getifaddrs` guarantees it while the list
/// lives).
#[cfg(unix)]
unsafe fn netmask_prefix(nm: *const libc::sockaddr, full: u8) -> u8 {
    if nm.is_null() {
        return full;
    }
    // SAFETY: caller contract; the family decides the layout
    unsafe {
        match i32::from((*nm).sa_family) {
            libc::AF_INET => u32::from_be((*(nm as *const libc::sockaddr_in)).sin_addr.s_addr)
                .leading_ones() as u8,
            libc::AF_INET6 => {
                u128::from_be_bytes((*(nm as *const libc::sockaddr_in6)).sin6_addr.s6_addr)
                    .leading_ones() as u8
            }
            _ => full,
        }
    }
}

/// Up, non-loopback addresses of this host, IPv6 link-local excluded, in kernel (`getifaddrs`) order (spec 2.2).
pub fn local_addrs() -> Vec<IfAddr> {
    let mut out = Vec::new();
    #[cfg(unix)]
    // SAFETY: getifaddrs allocates a list that is freed with freeifaddrs; entries are only read while it lives.
    unsafe {
        let mut ifa: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifa) != 0 {
            return out;
        }
        let mut p = ifa;
        while !p.is_null() {
            let e = &*p;
            let up = e.ifa_flags & libc::IFF_UP as u32 != 0;
            let lo = e.ifa_flags & libc::IFF_LOOPBACK as u32 != 0;
            if up && !lo && !e.ifa_addr.is_null() {
                let name = std::ffi::CStr::from_ptr(e.ifa_name)
                    .to_string_lossy()
                    .into_owned();
                match i32::from((*e.ifa_addr).sa_family) {
                    libc::AF_INET => {
                        let sa = &*(e.ifa_addr as *const libc::sockaddr_in);
                        out.push(IfAddr {
                            iface: name,
                            ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))),
                            prefix: netmask_prefix(e.ifa_netmask, 32),
                        });
                    }
                    libc::AF_INET6 => {
                        let sa = &*(e.ifa_addr as *const libc::sockaddr_in6);
                        let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
                        // fe80::/10 never matches a network (spec 2.2)
                        if !(ip.segments()[0] & 0xffc0 == 0xfe80) {
                            out.push(IfAddr {
                                iface: name,
                                ip: IpAddr::V6(ip),
                                prefix: netmask_prefix(e.ifa_netmask, 128),
                            });
                        }
                    }
                    _ => {}
                }
            }
            p = e.ifa_next;
        }
        libc::freeifaddrs(ifa);
    }
    out
}

/// One address of family `f` inside `nets` (first in interface order). A family without a network, or without a local
/// address inside its networks, fails the pick (spec 2.2: classic exits).
pub fn pick_one(nets: &[Net], addrs: &[IfAddr], f: Family) -> Result<IpAddr, String> {
    let nets_f: Vec<&Net> = nets.iter().filter(|n| n.family() == f).collect();
    if nets_f.is_empty() {
        return Err(format!("the network list has no {} network", f.name()));
    }
    addrs
        .iter()
        .map(|a| a.ip)
        .find(|ip| f.matches(*ip) && nets_f.iter().any(|n| n.contains(*ip)))
        .ok_or_else(|| {
            format!(
                "no local {} address inside {}",
                f.name(),
                nets_f
                    .iter()
                    .map(|n| format!("{}/{}", n.addr, n.prefix))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
}

/// One address per enabled family out of `nets`, in `fam.ordered()` order (spec 2 / 2.2).
pub fn pick_families(nets: &[Net], addrs: &[IfAddr], fam: Families) -> Result<Vec<IpAddr>, String> {
    fam.ordered()
        .into_iter()
        .map(|f| {
            pick_one(nets, addrs, f)
                .map_err(|e| format!("ms_bind_ipv4={} ms_bind_ipv6={}: {e}", fam.v4, fam.v6))
        })
        .collect()
}

/// First of `ips` inside any of `nets` (the order of `ips` is the interface order of the host).
pub fn pick(nets: &[Net], ips: &[IpAddr]) -> Option<IpAddr> {
    ips.iter()
        .copied()
        .find(|ip| nets.iter().any(|n| n.contains(*ip)))
}

/// Name of the up interface that carries `ip` (`front_iface` / `back_iface` metadata, knet tier).
pub fn iface_of(ip: IpAddr) -> Option<String> {
    local_addrs()
        .into_iter()
        .find(|a| a.ip == ip)
        .map(|a| a.iface)
}

/// Why a chosen address looks like a floating/VIP address the OSD would advertise and then lose when it moves to
/// another host (keepalived/VRRP placement).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrWarn {
    /// The address carries a /32 (IPv4) or /128 (IPv6) netmask on its interface although it lies inside a larger
    /// configured network: an address added on top of the host's own subnet address.
    HostRoute,
    /// The interface carries another address in the same configured network listed before this one (the kernel lists
    /// an interface's primary address of a subnet first): the chosen address is an additional (secondary) one.
    NotFirstInNetwork,
}

/// Whether the chosen address looks like a floating/VIP. Pure over the host's interface list (with prefixes, kernel
/// order), the chosen address and the configured networks; no host state.
pub fn vip_warning(ifaces: &[IfAddr], chosen: IpAddr, nets: &[Net]) -> Option<AddrWarn> {
    let mine = ifaces.iter().find(|a| a.ip == chosen)?;
    let net = nets.iter().find(|n| n.contains(chosen))?;
    let full = if chosen.is_ipv4() { 32 } else { 128 };
    if mine.prefix == full && net.prefix < full {
        return Some(AddrWarn::HostRoute);
    }
    let first = ifaces
        .iter()
        .find(|a| a.iface == mine.iface && net.contains(a.ip))?;
    (first.ip != chosen).then_some(AddrWarn::NotFirstInNetwork)
}

/// Local address the kernel would use to reach `target` (UDP connect, no packets are sent).
pub fn local_ip_towards(target: IpAddr, port: u16) -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind((Family::of(target).wildcard(), 0)).ok()?;
    s.connect((target, port)).ok()?;
    Some(s.local_addr().ok()?.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn iface_lookup() {
        assert!(iface_of(ip("203.0.113.77")).is_none());
        assert!(iface_of(ip("fd00:77::99")).is_none());
    }

    #[test]
    fn cidr_matching_and_lists() {
        let n = parse_networks("10.0.0.0/24, 192.168.4.0/22").unwrap();
        assert!(n[0].contains(ip("10.0.0.77")));
        assert!(!n[0].contains(ip("10.0.1.1")));
        assert!(n[1].contains(ip("192.168.7.255")));
        assert!(!n[1].contains(ip("192.168.8.0")));
        assert!(parse_networks("10.0.0.0/33").is_none());
        assert!(parse_networks("nope").is_none());
        // spec 2.2: the slash is mandatory
        assert!(parse_networks("10.0.0.1").is_none());
        assert!(parse_networks("fd00::1").is_none());
        assert_eq!(parse_networks("").unwrap(), vec![]);
        assert!(Net::parse("fd00::/129").is_none());
        assert!(
            Net::parse("fd00::/64")
                .unwrap()
                .contains(ip("fd00:0:0:0:1::5"))
        );
        assert!(
            !Net::parse("fd00::/64")
                .unwrap()
                .contains(ip("fd00:0:0:1::5"))
        );
        // a v4 network never matches a v6 address and vice versa
        assert!(
            !Net::parse("10.0.0.0/24")
                .unwrap()
                .contains(ip("::ffff:10.0.0.1"))
        );
        assert!(!Net::parse("fd00::/64").unwrap().contains(ip("10.0.0.1")));
    }

    /// `Net` is only built through [`Net::new`] / [`Net::parse`]: a prefix beyond the family's width would make the
    /// mask a shift by more than the integer width (panic in debug, a silently wrong mask in release).
    #[test]
    fn a_prefix_beyond_the_family_width_has_no_net() {
        assert!(Net::new(ip("10.0.0.0"), 33).is_none());
        assert!(Net::new(ip("fd00::"), 129).is_none());
        assert!(Net::parse("10.0.0.0/40").is_none());
        assert!(Net::parse("fd00::/200").is_none());
        let full = Net::new(ip("10.0.0.9"), 32).unwrap();
        assert!(full.contains(ip("10.0.0.9")));
        assert!(!full.contains(ip("10.0.0.8")));
        let all = Net::new(ip("fd00::1"), 128).unwrap();
        assert!(all.contains(ip("fd00::1")));
        assert!(!all.contains(ip("fd00::2")));
        assert_eq!(Net::new(ip("10.0.0.0"), 0), Net::parse("10.0.0.0/0"));
        assert!(
            Net::new(ip("10.0.0.0"), 0)
                .unwrap()
                .contains(ip("192.0.2.1"))
        );
    }

    #[test]
    fn mixed_lists_pick_one_per_family_in_addrvec_order() {
        let nets = parse_networks("10.78.0.0/24, fd00:77::/64").unwrap();
        let addrs = vec![
            IfAddr {
                iface: "eth0".into(),
                ip: ip("10.78.0.11"),
                prefix: 24,
            },
            IfAddr {
                iface: "eth0".into(),
                ip: ip("fd00:77::11"),
                prefix: 24,
            },
        ];
        let both = Families {
            v4: true,
            v6: true,
            prefer_v4: false,
        };
        assert_eq!(
            pick_families(&nets, &addrs, both).unwrap(),
            vec![ip("fd00:77::11"), ip("10.78.0.11")],
            "spec 2.4: IPv6 entries first by default"
        );
        let v4first = Families {
            prefer_v4: true,
            ..both
        };
        assert_eq!(
            pick_families(&nets, &addrs, v4first).unwrap(),
            vec![ip("10.78.0.11"), ip("fd00:77::11")]
        );
        let v6only = Families {
            v4: false,
            v6: true,
            prefer_v4: false,
        };
        assert_eq!(
            pick_families(&nets, &addrs, v6only).unwrap(),
            vec![ip("fd00:77::11")]
        );
        // a requested family without a network fails the whole pick
        assert!(pick_families(&parse_networks("10.78.0.0/24").unwrap(), &addrs, both).is_err());
        // no address inside
        assert!(pick_families(&nets, &addrs[..1], both).is_err());
    }

    #[test]
    fn interface_filter_selects_the_address_of_that_interface() {
        let nets = parse_networks("10.78.0.0/24").unwrap();
        let addrs = vec![
            IfAddr {
                iface: "bond0".into(),
                ip: ip("10.78.0.11"),
                prefix: 24,
            },
            IfAddr {
                iface: "bond1".into(),
                ip: ip("10.78.0.12"),
                prefix: 24,
            },
        ];
        let keep: Vec<IfAddr> = addrs
            .iter()
            .filter(|a| parse_ifaces("bond1").contains(&a.iface))
            .cloned()
            .collect();
        assert_eq!(
            pick_families(&nets, &keep, Families::default()).unwrap(),
            vec![ip("10.78.0.12")]
        );
        assert_eq!(
            pick_families(&nets, &addrs, Families::default()).unwrap(),
            vec![ip("10.78.0.11")],
            "kernel order, first match"
        );
    }

    #[test]
    fn pick_takes_the_first_interface_address_inside() {
        let ips: Vec<IpAddr> = ["172.17.0.1", "10.0.0.5", "10.0.0.6"]
            .iter()
            .map(|s| ip(s))
            .collect();
        let n = parse_networks("10.0.0.0/24").unwrap();
        assert_eq!(pick(&n, &ips), Some(ip("10.0.0.5")));
        assert_eq!(pick(&parse_networks("10.9.0.0/16").unwrap(), &ips), None);
    }

    #[test]
    fn the_host_has_some_address_or_none_without_panic() {
        let _ = local_addrs();
    }

    #[test]
    fn vip_warning_flags_host_routes_and_additional_addresses_only() {
        let a = |iface: &str, x: &str, prefix: u8| IfAddr {
            iface: iface.into(),
            ip: ip(x),
            prefix,
        };
        let nets = parse_networks("10.0.0.0/24, fd00::/64").unwrap();
        // the ordinary case: one address per subnet with the subnet's netmask -> never flagged
        let plain = vec![a("eth0", "10.0.0.11", 24), a("eth0", "fd00::11", 64)];
        assert_eq!(vip_warning(&plain, ip("10.0.0.11"), &nets), None);
        assert_eq!(vip_warning(&plain, ip("fd00::11"), &nets), None);
        // keepalived-style /32 (/128) on top of the subnet address -> HostRoute
        let vip32 = vec![
            a("eth0", "10.0.0.11", 24),
            a("eth0", "10.0.0.99", 32),
            a("eth0", "fd00::99", 128),
        ];
        assert_eq!(
            vip_warning(&vip32, ip("10.0.0.99"), &nets),
            Some(AddrWarn::HostRoute)
        );
        assert_eq!(
            vip_warning(&vip32, ip("fd00::99"), &nets),
            Some(AddrWarn::HostRoute)
        );
        assert_eq!(vip_warning(&vip32, ip("10.0.0.11"), &nets), None);
        // an additional address with the subnet netmask (listed after the primary) -> NotFirstInNetwork
        let sec = vec![a("eth0", "10.0.0.11", 24), a("eth0", "10.0.0.99", 24)];
        assert_eq!(
            vip_warning(&sec, ip("10.0.0.99"), &nets),
            Some(AddrWarn::NotFirstInNetwork)
        );
        assert_eq!(vip_warning(&sec, ip("10.0.0.11"), &nets), None);
        // a /32 network configured for exactly that address, no network, or a foreign address: not flagged
        assert_eq!(
            vip_warning(
                &vip32,
                ip("10.0.0.99"),
                &parse_networks("10.0.0.99/32").unwrap()
            ),
            None
        );
        assert_eq!(vip_warning(&vip32, ip("10.0.0.99"), &[]), None);
        assert_eq!(vip_warning(&plain, ip("10.9.0.5"), &nets), None);
    }
}
