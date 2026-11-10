// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Read-only NIC queries for the zcrx plan: header/data split and ring size (ethtool netlink), queue NAPI ids and
//! zcrx bindings (netdev netlink), RSS tables and flow rules (ethtool ioctls), interface of an address. Nothing here
//! changes NIC state (host-owned, adr 0464).
use super::steer::{Rule, Steering};
use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Interface carrying the local address `ip` (`getifaddrs`).
pub fn iface_of(ip: Ipv4Addr) -> Option<String> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut out = None;
    let mut p = head;
    while !p.is_null() {
        // SAFETY: walking the list getifaddrs returned.
        let a = unsafe { &*p };
        if !a.ifa_addr.is_null()
            // SAFETY: non-null sockaddr from the kernel.
            && i32::from(unsafe { (*a.ifa_addr).sa_family }) == libc::AF_INET
        {
            // SAFETY: AF_INET entries carry a sockaddr_in.
            let sin = unsafe { &*a.ifa_addr.cast::<libc::sockaddr_in>() };
            if Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()) == ip {
                // SAFETY: NUL-terminated interface name.
                out = Some(
                    unsafe { std::ffi::CStr::from_ptr(a.ifa_name) }
                        .to_string_lossy()
                        .into_owned(),
                );
                break;
            }
        }
        p = a.ifa_next;
    }
    // SAFETY: the list from getifaddrs.
    unsafe { libc::freeifaddrs(head) };
    out
}

pub fn ifindex(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    // SAFETY: valid C string.
    let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (i != 0).then_some(i)
}

/// Kernel driver of the interface (`None` = no device behind it: bond, VLAN, bridge, veth, tun).
pub fn driver(name: &str) -> Option<String> {
    let l = std::fs::read_link(format!("/sys/class/net/{name}/device/driver")).ok()?;
    Some(l.file_name()?.to_string_lossy().into_owned())
}

/// An SR-IOV virtual function (`device/physfn` exists).
pub fn is_vf(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}/device/physfn")).exists()
}

// ---- generic netlink ----

const NETLINK_GENERIC: i32 = 16;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;

struct Genl {
    fd: OwnedFd,
    seq: u32,
}

/// Attribute list builder.
#[derive(Default)]
struct Attrs(Vec<u8>);

impl Attrs {
    fn put(&mut self, ty: u16, v: &[u8]) -> &mut Self {
        let len = 4 + v.len();
        self.0.extend_from_slice(&(len as u16).to_ne_bytes());
        self.0.extend_from_slice(&ty.to_ne_bytes());
        self.0.extend_from_slice(v);
        self.0.resize(self.0.len().next_multiple_of(4), 0);
        self
    }
    fn u32(&mut self, ty: u16, v: u32) -> &mut Self {
        self.put(ty, &v.to_ne_bytes())
    }
    fn nest(&mut self, ty: u16, inner: &Attrs) -> &mut Self {
        self.put(ty | NLA_F_NESTED, &inner.0)
    }
}

/// Iterate `(type, payload)` of an attribute list.
fn attrs(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if b.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let ty = u16::from_ne_bytes([b[2], b[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > b.len() {
            return None;
        }
        let v = &b[4..len];
        b = &b[len.next_multiple_of(4).min(b.len())..];
        Some((ty, v))
    })
}

fn u32_of(v: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(v.get(..4)?.try_into().ok()?))
}

impl Genl {
    fn open() -> io::Result<Genl> {
        // SAFETY: plain socket call.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh fd we own.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let tv = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        // SAFETY: valid timeval; a bounded receive (the kernel answers at once; a missing answer must not hang start).
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast(),
                size_of::<libc::timeval>() as u32,
            )
        };
        Ok(Genl { fd, seq: 0 })
    }

    /// One request, its single reply's attributes.
    fn call(&mut self, family: u16, cmd: u8, a: &Attrs) -> io::Result<Vec<u8>> {
        self.seq += 1;
        let len = 16 + 4 + a.0.len();
        let mut m = Vec::with_capacity(len);
        m.extend_from_slice(&(len as u32).to_ne_bytes());
        m.extend_from_slice(&family.to_ne_bytes());
        m.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
        m.extend_from_slice(&self.seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(&[cmd, 1, 0, 0]);
        m.extend_from_slice(&a.0);
        // SAFETY: sending our buffer on our socket (kernel address = zeroed sockaddr_nl).
        let r = unsafe {
            let mut sa: libc::sockaddr_nl = std::mem::zeroed();
            sa.nl_family = libc::AF_NETLINK as u16;
            libc::sendto(
                self.fd.as_raw_fd(),
                m.as_ptr().cast(),
                m.len(),
                0,
                (&raw const sa).cast(),
                size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; 16 << 10];
        loop {
            // SAFETY: receive into our buffer.
            let n =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    eprintln!(
                        "WARNING TIMEOUT netlink reply exceeded 2s (zcrx NIC query, family {family} cmd {cmd})"
                    );
                }
                return Err(e);
            }
            let b = &buf[..n as usize];
            if b.len() < 16 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let ty = u16::from_ne_bytes([b[4], b[5]]);
            let seq = u32::from_ne_bytes([b[8], b[9], b[10], b[11]]);
            if seq != self.seq {
                continue;
            }
            match ty {
                NLMSG_ERROR => {
                    let err = i32::from_ne_bytes([b[16], b[17], b[18], b[19]]);
                    return Err(io::Error::from_raw_os_error(-err));
                }
                NLMSG_DONE => return Err(io::ErrorKind::NotFound.into()),
                _ => {
                    let mlen = (u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize).min(b.len());
                    return Ok(b.get(20..mlen).unwrap_or_default().to_vec());
                }
            }
        }
    }

    fn family(&mut self, name: &str) -> io::Result<u16> {
        let mut n = name.as_bytes().to_vec();
        n.push(0);
        let mut a = Attrs::default();
        a.put(CTRL_ATTR_FAMILY_NAME, &n);
        let r = self.call(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, &a)?;
        attrs(&r)
            .find(|(t, _)| *t == CTRL_ATTR_FAMILY_ID)
            .and_then(|(_, v)| Some(u16::from_ne_bytes(v.get(..2)?.try_into().ok()?)))
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }
}

// ethtool netlink (rings)
const ETHTOOL_MSG_RINGS_GET: u8 = 15;
const ETHTOOL_A_RINGS_HEADER: u16 = 1;
const ETHTOOL_A_HEADER_DEV_INDEX: u16 = 1;
const ETHTOOL_A_RINGS_RX: u16 = 6;
const ETHTOOL_A_RINGS_TCP_DATA_SPLIT: u16 = 11;
const ETHTOOL_A_RINGS_HDS_THRESH: u16 = 17;
const TCP_DATA_SPLIT_ENABLED: u8 = 2;

/// Ring state relevant to zcrx.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rings {
    /// Posted rx descriptors per queue.
    pub rx: u32,
    /// `tcp-data-split` is on (`None`: the driver does not report it).
    pub hds: Option<bool>,
    /// `hds-thresh` (zcrx needs 0: every payload byte goes to the data buffer).
    pub hds_thresh: Option<u32>,
}

pub fn rings(ifindex: u32) -> io::Result<Rings> {
    let mut g = Genl::open()?;
    let fam = g.family("ethtool")?;
    let mut h = Attrs::default();
    h.u32(ETHTOOL_A_HEADER_DEV_INDEX, ifindex);
    let mut a = Attrs::default();
    a.nest(ETHTOOL_A_RINGS_HEADER, &h);
    let r = g.call(fam, ETHTOOL_MSG_RINGS_GET, &a)?;
    let mut out = Rings::default();
    for (t, v) in attrs(&r) {
        match t {
            ETHTOOL_A_RINGS_RX => out.rx = u32_of(v).unwrap_or(0),
            ETHTOOL_A_RINGS_TCP_DATA_SPLIT => {
                out.hds = v.first().map(|&b| b == TCP_DATA_SPLIT_ENABLED)
            }
            ETHTOOL_A_RINGS_HDS_THRESH => out.hds_thresh = u32_of(v),
            _ => {}
        }
    }
    Ok(out)
}

// netdev netlink (queues)
const NETDEV_CMD_QUEUE_GET: u8 = 10;
const NETDEV_A_QUEUE_ID: u16 = 1;
const NETDEV_A_QUEUE_IFINDEX: u16 = 2;
const NETDEV_A_QUEUE_TYPE: u16 = 3;
const NETDEV_A_QUEUE_NAPI_ID: u16 = 4;
const NETDEV_A_QUEUE_IO_URING: u16 = 6;
const NETDEV_QUEUE_TYPE_RX: u32 = 0;

/// One rx queue: its NAPI instance and whether an io_uring zcrx provider is bound to it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Queue {
    pub napi: u32,
    pub zcrx_bound: bool,
}

pub fn rx_queue(ifindex: u32, q: u32) -> io::Result<Queue> {
    let mut g = Genl::open()?;
    let fam = g.family("netdev")?;
    let mut a = Attrs::default();
    a.u32(NETDEV_A_QUEUE_IFINDEX, ifindex)
        .u32(NETDEV_A_QUEUE_TYPE, NETDEV_QUEUE_TYPE_RX)
        .u32(NETDEV_A_QUEUE_ID, q);
    let r = g.call(fam, NETDEV_CMD_QUEUE_GET, &a)?;
    let mut out = Queue::default();
    for (t, v) in attrs(&r) {
        match t {
            NETDEV_A_QUEUE_NAPI_ID => out.napi = u32_of(v).unwrap_or(0),
            NETDEV_A_QUEUE_IO_URING => out.zcrx_bound = true,
            _ => {}
        }
    }
    Ok(out)
}

// ---- ethtool ioctls (RSS tables, flow rules) ----

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GRXCLSRLCNT: u32 = 0x2e;
const ETHTOOL_GRXCLSRULE: u32 = 0x2f;
const ETHTOOL_GRXCLSRLALL: u32 = 0x30;
const ETHTOOL_GRSSH: u32 = 0x46;
const TCP_V4_FLOW: u32 = 1;
const TCP_V6_FLOW: u32 = 5;
const FLOW_EXT: u32 = 0x8000_0000;
const FLOW_MAC_EXT: u32 = 0x4000_0000;
const FLOW_RSS: u32 = 0x2000_0000;
const RX_FLOW_SPEC_RING: u64 = 0xffff_ffff;
const RX_FLOW_SPEC_VF: u64 = 0xff_0000_0000;
/// `struct ethtool_rxnfc` up to `rule_locs` (x86_64/aarch64 layout: flow spec at 16, ring cookie at 168, location at
/// 176, rule count / RSS context at 184).
const RXNFC: usize = 188;
const FS_FLOW: usize = 16;
const FS_HU: usize = 20;
const FS_MU: usize = 92;
const FS_COOKIE: usize = 168;
const FS_LOC: usize = 176;
const RXNFC_CNT: usize = 184;

fn ethtool(name: &str, buf: &mut [u8]) -> io::Result<()> {
    // SAFETY: plain socket for the ioctl.
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if s < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fd we own.
    let s = unsafe { OwnedFd::from_raw_fd(s) };
    // SAFETY: zeroed ifreq is valid; name copied bounded; ifr_data points to `buf`, which lives through the call.
    let r = unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (d, b) in ifr
            .ifr_name
            .iter_mut()
            .zip(name.bytes().take(libc::IFNAMSIZ - 1))
        {
            *d = b as libc::c_char;
        }
        ifr.ifr_ifru.ifru_data = buf.as_mut_ptr().cast();
        libc::ioctl(s.as_raw_fd(), SIOCETHTOOL, &mut ifr)
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn rd32(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}
fn wr32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
}

/// Queues of RSS context `ctx` (0 = default): the distinct entries of its indirection table.
pub fn rss_queues(name: &str, ctx: u32) -> io::Result<Vec<u32>> {
    let mut h = [0u8; 24];
    wr32(&mut h, 0, ETHTOOL_GRSSH);
    wr32(&mut h, 4, ctx);
    ethtool(name, &mut h)?;
    let n = rd32(&h, 8) as usize;
    let mut b = vec![0u8; 24 + 4 * n];
    wr32(&mut b, 0, ETHTOOL_GRSSH);
    wr32(&mut b, 4, ctx);
    wr32(&mut b, 8, n as u32);
    ethtool(name, &mut b)?;
    let mut q: Vec<u32> = (0..n).map(|i| rd32(&b, 24 + 4 * i)).collect();
    q.sort_unstable();
    q.dedup();
    Ok(q)
}

/// The NIC's default RSS queues and flow rules. Rules to a VF or that drop are skipped (they never reach our queues).
pub fn steering(name: &str) -> io::Result<Steering> {
    let rss = rss_queues(name, 0)?;
    let mut c = [0u8; RXNFC];
    wr32(&mut c, 0, ETHTOOL_GRXCLSRLCNT);
    let rules = match ethtool(name, &mut c) {
        Ok(()) => rd32(&c, RXNFC_CNT) as usize,
        // no ntuple support: no rules
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => 0,
        Err(e) => return Err(e),
    };
    let mut all = vec![0u8; RXNFC + 4 * rules];
    wr32(&mut all, 0, ETHTOOL_GRXCLSRLALL);
    wr32(&mut all, RXNFC_CNT, rules as u32);
    if rules > 0 {
        ethtool(name, &mut all)?;
    }
    let mut out = Steering {
        rss,
        rules: Vec::new(),
    };
    for i in 0..rules {
        let loc = rd32(&all, RXNFC + 4 * i);
        let mut r = [0u8; RXNFC];
        wr32(&mut r, 0, ETHTOOL_GRXCLSRULE);
        wr32(&mut r, FS_LOC, loc);
        ethtool(name, &mut r)?;
        let ft = rd32(&r, FS_FLOW);
        let cookie = u64::from_ne_bytes(r[FS_COOKIE..FS_COOKIE + 8].try_into().unwrap());
        if cookie == u64::MAX || cookie & RX_FLOW_SPEC_VF != 0 {
            continue;
        }
        let ring = (cookie & RX_FLOW_SPEC_RING) as u32;
        let queues = if ft & FLOW_RSS != 0 {
            let ctx = rd32(&r, RXNFC_CNT);
            rss_queues(name, ctx)?
                .into_iter()
                .map(|q| q + ring)
                .collect()
        } else {
            vec![ring]
        };
        let pdst = match ft & !(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS) {
            TCP_V4_FLOW => Some(10),
            TCP_V6_FLOW => Some(34),
            _ => None,
        };
        let port = pdst.and_then(|at| {
            let v = u16::from_be_bytes([r[FS_HU + at], r[FS_HU + at + 1]]);
            let m = u16::from_be_bytes([r[FS_MU + at], r[FS_MU + at + 1]]);
            (m == 0xffff).then_some(v)
        });
        out.rules.push(Rule { port, queues });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attrs_roundtrip() {
        let mut inner = Attrs::default();
        inner.u32(1, 7);
        let mut a = Attrs::default();
        a.nest(1, &inner).put(2, b"ab").u32(3, 9);
        let v: Vec<_> = attrs(&a.0).collect();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].0, 1);
        assert_eq!(
            attrs(v[0].1).next().map(|(t, x)| (t, u32_of(x))),
            Some((1, Some(7)))
        );
        assert_eq!(v[1], (2, &b"ab"[..]));
        assert_eq!((v[2].0, u32_of(v[2].1)), (3, Some(9)));
    }

    #[test]
    fn loopback_has_no_device_driver() {
        assert_eq!(driver("lo"), None);
        assert_eq!(iface_of(Ipv4Addr::LOCALHOST).as_deref(), Some("lo"));
        assert_eq!(ifindex("lo"), Some(1));
    }
}
