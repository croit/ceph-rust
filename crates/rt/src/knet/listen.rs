// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Per-core listening sockets with `SO_REUSEPORT`: every core owns its own listener per port, the kernel spreads the
//! connections (4-tuple hash) or, with [`Steer::Cpu`], hands a connection to the listener of the CPU that processes the
//! SYN (classic BPF `SKF_AD_CPU`: with NIC RSS queue i serviced on core i a flow lands on its core and the cross-core
//! hop of the mesh disappears). adr 0053.
use osd::Listener;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// The four OSD listeners in `Binds` order.
pub const KINDS: [Listener; 4] = [
    Listener::Public,
    Listener::Cluster,
    Listener::HbFront,
    Listener::HbBack,
];

/// Where the four listeners bind (public, cluster, heartbeat front, heartbeat back), one socket per addrvec entry: a
/// dual-stack daemon lists one address per family (spec ip-addressing.md 3.1).
#[derive(Clone, Debug)]
pub struct Binds(pub [Vec<SocketAddr>; 4]);

/// How the kernel picks the listener of a new connection.
#[derive(Clone, Debug, Default)]
pub enum Steer {
    /// Kernel 4-tuple hash over all cores.
    #[default]
    Hash,
    /// The core pinned to the CPU that handles the SYN (`cpus[i]` = CPU of core i); unknown CPU: hash.
    Cpu(Vec<usize>),
}

pub(crate) fn setopt(fd: RawFd, level: i32, name: i32, val: i32) -> io::Result<()> {
    // SAFETY: plain setsockopt with an i32 value of the right size.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&raw const val).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `sockaddr_storage` of `a` and its length (v4: `sockaddr_in`, v6: `sockaddr_in6` with the scope id).
pub(crate) fn sockaddr(a: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: all-zero sockaddr_storage is valid; the family's fields are set below.
    let mut s: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match a {
        SocketAddr::V4(v) => {
            // SAFETY: sockaddr_storage is at least as large and as aligned as sockaddr_in.
            let p = (&raw mut s).cast::<libc::sockaddr_in>();
            unsafe {
                (*p).sin_family = libc::AF_INET as _;
                (*p).sin_port = v.port().to_be();
                (*p).sin_addr.s_addr = u32::from_ne_bytes(v.ip().octets());
            }
            (s, size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        SocketAddr::V6(v) => {
            // SAFETY: sockaddr_storage is at least as large and as aligned as sockaddr_in6.
            let p = (&raw mut s).cast::<libc::sockaddr_in6>();
            unsafe {
                (*p).sin6_family = libc::AF_INET6 as _;
                (*p).sin6_port = v.port().to_be();
                (*p).sin6_addr.s6_addr = v.ip().octets();
                (*p).sin6_scope_id = v.scope_id();
            }
            (s, size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

/// `AF_INET` / `AF_INET6` of `ip`.
pub(crate) fn af(ip: IpAddr) -> libc::c_int {
    match ip {
        IpAddr::V4(_) => libc::AF_INET,
        IpAddr::V6(_) => libc::AF_INET6,
    }
}

fn socket(ip: IpAddr) -> io::Result<OwnedFd> {
    // SAFETY: socket(2); the fd is owned right away.
    let fd = unsafe { libc::socket(af(ip), libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh valid fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn bind(fd: RawFd, a: &SocketAddr) -> io::Result<()> {
    let (sa, len) = sockaddr(a);
    // SAFETY: sa is a valid sockaddr of the given length.
    let r = unsafe { libc::bind(fd, (&raw const sa).cast(), len) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Fail early (and clearly) if somebody else listens on `a`: `SO_REUSEPORT` would let a second daemon of the same user
/// silently join our port group (classic `ceph-osd` after a failed stop, a duplicate unit, ...).
fn probe_free(a: &SocketAddr) -> io::Result<()> {
    let s = socket(a.ip())?;
    setopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    bind(s.as_raw_fd(), a).map_err(|e| io::Error::new(e.kind(), format!("{a}: {e}")))
}

/// Attach the classic BPF program `p` as the socket's reuseport selector.
fn attach_cbpf(fd: RawFd, p: &mut [libc::sock_filter]) -> io::Result<()> {
    let prog = libc::sock_fprog {
        len: p.len() as u16,
        filter: p.as_mut_ptr(),
    };
    // SAFETY: prog points at p for the duration of the call; the kernel copies the program.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_REUSEPORT_CBPF,
            (&raw const prog).cast(),
            size_of::<libc::sock_fprog>() as _,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn attach_cpu_filter(fd: RawFd, cpus: &[usize]) -> io::Result<()> {
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;
    const SKF_AD_CPU: i32 = -0x1000 + 36;
    let mut p: Vec<libc::sock_filter> = vec![libc::sock_filter {
        code: LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SKF_AD_CPU as u32,
    }];
    for (i, c) in cpus.iter().enumerate() {
        p.push(libc::sock_filter {
            code: JEQ_K,
            jt: 0,
            jf: 1,
            k: *c as u32,
        });
        p.push(libc::sock_filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: i as u32,
        });
    }
    // index >= number of sockets: the kernel falls back to the hash
    p.push(libc::sock_filter {
        code: RET_K,
        jt: 0,
        jf: 0,
        k: u32::MAX,
    });
    attach_cbpf(fd, &mut p)
}

/// Create the listeners of all cores: `result[core][kind]` = the fds of that kind's entries (one per address family).
/// Sockets are created in core order, which is the order of the kernel's reuseport group (what [`Steer::Cpu`] indexes).
pub fn bind_all(
    binds: &Binds,
    cores: usize,
    steer: &Steer,
    backlog: i32,
) -> io::Result<Vec<[Vec<OwnedFd>; 4]>> {
    bind_all_with(binds, cores, steer, backlog, &ListenOpts::default())
}

/// Optional listener tuning (all off by default).
#[derive(Clone, Debug, Default)]
pub struct ListenOpts {
    /// Cluster listener: the core = TCP source port % cores (peers of this tier dial from a port that selects their
    /// owner core here, see [`pick_src_port`]); replaces [`Steer::Cpu`] on that listener. No effect with one core.
    pub port_steer: bool,
    /// `SO_SNDBUF`/`SO_RCVBUF` bytes on the listeners (inherited by accepted sockets; 0 = kernel autotuning).
    pub sockbuf: u32,
}

/// [`bind_all`] with [`ListenOpts`].
pub fn bind_all_with(
    binds: &Binds,
    cores: usize,
    steer: &Steer,
    backlog: i32,
    opts: &ListenOpts,
) -> io::Result<Vec<[Vec<OwnedFd>; 4]>> {
    bind_listeners(&binds.0, cores, steer, backlog, opts, Some(1))
}

/// Bind any service's fixed listener set: `result[core][listener]` = the fds of that listener's entries (one per
/// address family). `port_steered` identifies its peer listener when `opts.port_steer` is enabled; `None` leaves peer
/// steering off. Index zero is the public listener for accept placement. Socket order and all tuning are identical to
/// [`bind_all_with`] for the four OSD listeners.
pub fn bind_listeners<const N: usize>(
    addresses: &[Vec<SocketAddr>; N],
    cores: usize,
    steer: &Steer,
    backlog: i32,
    opts: &ListenOpts,
    port_steered: Option<usize>,
) -> io::Result<Vec<[Vec<OwnedFd>; N]>> {
    for a in addresses.iter().flatten() {
        probe_free(a)?;
    }
    let mut per_core: Vec<[Vec<OwnedFd>; N]> = (0..cores)
        .map(|_| std::array::from_fn(|_| Vec::new()))
        .collect();
    for (ai, addrs) in addresses.iter().enumerate() {
        for (c, slots) in per_core.iter_mut().enumerate() {
            for a in addrs {
                let s = socket(a.ip())?;
                let fd = s.as_raw_fd();
                setopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
                setopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;
                setopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)?;
                // spec ip-addressing.md 8: bind explicit addresses only, never a wildcard that also takes v4-mapped
                // peers, so a v6 listener is v6-only like classic's explicit-IP listeners
                if a.is_ipv6() {
                    setopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;
                }
                if opts.sockbuf > 0 {
                    // an operator setting the kernel refuses fails the bind: never silently unset
                    set_sockbuf(fd, opts.sockbuf)?;
                }
                bind(fd, a)?;
                // SAFETY: listen(2) on our own socket.
                if unsafe { libc::listen(fd, backlog) } < 0 {
                    return Err(io::Error::last_os_error());
                }
                if c == 0 {
                    if opts.port_steer && cores > 1 && port_steered == Some(ai) && a.is_ipv4() {
                        attach_port_filter(fd, cores as u32)?;
                    } else if a.is_ipv4()
                        && let Steer::Cpu(cpus) = steer
                    {
                        attach_cpu_filter(fd, cpus)?;
                    }
                }
                slots[ai].push(s);
            }
        }
    }
    Ok(per_core)
}

/// `getsockopt` of an i32 option; None on error.
pub(crate) fn getopt(fd: RawFd, level: i32, name: i32) -> Option<i32> {
    let mut v: i32 = 0;
    let mut l = size_of::<i32>() as libc::socklen_t;
    // SAFETY: plain getsockopt into an i32 of the given length.
    let r = unsafe { libc::getsockopt(fd, level, name, (&raw mut v).cast(), &raw mut l) };
    (r == 0).then_some(v)
}

/// CPU that last ran the kernel receive processing (softirq: driver, GRO, TCP) of the socket (`SO_INCOMING_CPU`; set
/// by the kernel per received segment, so for a flow it is the CPU of its NIC queue IRQ, or of RPS). None = unknown.
pub(crate) fn incoming_cpu(fd: RawFd) -> Option<usize> {
    getopt(fd, libc::SOL_SOCKET, libc::SO_INCOMING_CPU)
        .filter(|&v| v >= 0)
        .map(|v| v as usize)
}

/// CPU of the calling thread (OSD cores are pinned).
pub(crate) fn this_cpu() -> Option<usize> {
    // SAFETY: no arguments; returns -1 on error.
    let c = unsafe { libc::sched_getcpu() };
    (c >= 0).then_some(c as usize)
}

/// The socket's softirq runs on the calling thread's CPU (both known).
pub(crate) fn rx_on_this_cpu(fd: RawFd) -> bool {
    matches!((incoming_cpu(fd), this_cpu()), (Some(a), Some(b)) if a == b)
}

/// `SO_SNDBUF` + `SO_RCVBUF` (disables autotuning for the socket; the kernel doubles the value and caps it at
/// `wmem_max`/`rmem_max`).
pub(crate) fn set_sockbuf(fd: RawFd, bytes: u32) -> io::Result<()> {
    setopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, bytes as i32)?;
    setopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, bytes as i32)
}

/// Classic BPF reuseport program: listener index = TCP source port % `n` (`n` = listeners in the group, so the index is
/// always valid). Kernel semantics (`run_bpf_filter` in net/core/sock_reuseport.c): for TCP the skb data is pulled past
/// the TCP header before the program runs (it sees the payload, empty on a SYN), so the port is read relative to the
/// network header (`SKF_NET_OFF`): X = IPv4 header length (IHL * 4, options included), A = half word at net + X.
/// The listeners are IPv4 only. A failed load yields 0 (listener 0); an index >= group size would fall back to the hash.
fn attach_port_filter(fd: RawFd, n: u32) -> io::Result<()> {
    const LDX_B_MSH: u16 = 0xb1; // X = 4 * (P[k] & 0xf)
    const LD_H_IND: u16 = 0x48; // A = P[X + k] (16 bit)
    const ALU_MOD_K: u16 = 0x94;
    const RET_A: u16 = 0x16;
    const SKF_NET_OFF: i32 = -0x10_0000;
    let ins = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let mut p = [
        ins(LDX_B_MSH, SKF_NET_OFF as u32),
        ins(LD_H_IND, SKF_NET_OFF as u32),
        ins(ALU_MOD_K, n.max(1)),
        ins(RET_A, 0),
    ];
    attach_cbpf(fd, &mut p)
}

/// Local ports a dial may bind explicitly: the kernel's ephemeral range minus its reserved ports (the same contract as
/// an automatic bind, so services that rely on `ip_local_reserved_ports` / ports outside the range are never taken).
#[derive(Clone, Debug)]
pub(crate) struct SrcPorts {
    lo: u16,
    hi: u16,
    reserved: Vec<(u16, u16)>,
}

impl Default for SrcPorts {
    /// Kernel default range, nothing reserved.
    fn default() -> SrcPorts {
        SrcPorts {
            lo: 32768,
            hi: 60999,
            reserved: Vec::new(),
        }
    }
}

impl SrcPorts {
    /// From `/proc/sys/net/ipv4/ip_local_port_range` + `ip_local_reserved_ports` (defaults on read errors).
    pub(crate) fn from_proc() -> SrcPorts {
        let rd = |f: &str| {
            std::fs::read_to_string(format!("/proc/sys/net/ipv4/{f}")).unwrap_or_default()
        };
        SrcPorts::parse(&rd("ip_local_port_range"), &rd("ip_local_reserved_ports"))
    }

    /// `range` = "LO HI", `reserved` = "P,P1-P2,...".
    pub(crate) fn parse(range: &str, reserved: &str) -> SrcPorts {
        let d = SrcPorts::default();
        let mut it = range.split_whitespace().map(|v| v.parse::<u16>().ok());
        let (lo, hi) = match (it.next().flatten(), it.next().flatten()) {
            (Some(l), Some(h)) if l <= h => (l.max(1024), h),
            _ => (d.lo, d.hi),
        };
        let reserved = reserved
            .trim()
            .split(',')
            .filter_map(|r| {
                let (a, b) = r.split_once('-').unwrap_or((r, r));
                Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
            })
            .collect();
        SrcPorts { lo, hi, reserved }
    }

    fn usable(&self, p: u16) -> bool {
        (self.lo..=self.hi).contains(&p)
            && !self.reserved.iter().any(|&(a, b)| (a..=b).contains(&p))
    }

    /// A usable port `p` with `p % n == rem` (`rem < n`): the class is scanned from a random member on;
    /// None when no member qualifies.
    fn pick(&self, n: u32, rem: u32, rnd: &mut u64) -> Option<u16> {
        let (lo, hi) = (u32::from(self.lo), u32::from(self.hi));
        let first = lo + (rem + n - lo % n) % n;
        if first > hi {
            return None;
        }
        let count = (hi - first) / n + 1;
        *rnd ^= *rnd << 13;
        *rnd ^= *rnd >> 7;
        *rnd ^= *rnd << 17;
        let start = (*rnd % u64::from(count)) as u32;
        (0..count)
            .map(|i| (first + (start + i) % count * n) as u16)
            .find(|&p| self.usable(p))
    }
}

/// Bind a dial socket to the daemon's own address `src` (the port is chosen at connect: `IP_BIND_ADDRESS_NO_PORT`, so
/// the 4-tuple space is shared with unbound dials). Classic `ms_bind_before_connect`: without it the kernel picks the source
/// by route, and with two interfaces in one network (route metric order) the peer sees the wrong address.
pub(crate) fn bind_src(fd: RawFd, src: IpAddr) -> io::Result<()> {
    // the port stays free until connect, so the 4-tuple space is shared with unbound dials (IPv4 only option; a v6
    // socket binds port 0 like any other and the kernel takes a free ephemeral port at connect)
    if src.is_ipv4() {
        setopt(fd, libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT, 1)?;
    }
    bind(fd, &SocketAddr::new(src, 0))
}

/// Bind `fd` to a local port `p` with `p % n == rem` (from `ports`), so that a cluster listener running
/// [`attach_port_filter`] with the same `n` hands the connection to core `rem`.
/// `rnd` is advanced (cheap xorshift). False when no port worked in a few tries (busy, reserved): the caller connects
/// from an automatic port and the peer relays, still correct. A port whose 4-tuple is in TIME_WAIT towards the same
/// peer fails the connect (EADDRNOTAVAIL): an ordinary dial failure, the redial picks another port.
pub(crate) fn pick_src_port(
    fd: RawFd,
    ip: Ipv4Addr,
    ports: &SrcPorts,
    n: u32,
    rem: u32,
    rnd: &mut u64,
) -> bool {
    if n < 2 || rem >= n {
        return false;
    }
    let _ = setopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1); // TIME_WAIT left by earlier connections on the port
    for _ in 0..32 {
        match ports.pick(n, rem, rnd) {
            Some(p) if bind(fd, &SocketAddr::new(IpAddr::V4(ip), p)).is_ok() => return true,
            Some(_) => {}
            None => break,
        }
    }
    false
}
