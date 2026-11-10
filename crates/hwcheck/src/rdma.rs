// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! RDMA (RoCE) readiness per RDMA device (0470-rdma-ops): port, RoCEv2 GID on an IP, RoCE path MTU, PCIe link, and on a
//! live host the NIC QoS (PFC per priority, DSCP -> priority map, global pause) and DCQCN state. Read-only: sysfs plus
//! one rtnetlink DCB get and one ethtool get per netdev.
use crate::fs::Fs;
use crate::{Check, Section, Status};

/// Smallest netdev MTU at which mlx5 reports RoCE active MTU 4096 (measured; 4096 is recommended, 0470-rdma-ops).
pub const MIN_NETDEV_MTU: u64 = 4192;
/// Smallest netdev MTU for RoCE path MTU 1024, the least RDMA accepts (`rdma::MIN_PATH_MTU`): the path MTU plus the same
/// 96 bytes of headroom as above.
pub const MIN_NETDEV_MTU_RDMA: u64 = MIN_NETDEV_MTU - 4096 + 1024;

/// RoCE path MTU a netdev MTU gives (largest of 1024 / 2048 / 4096 that fits with the headroom; 0 below 1024).
fn path_mtu_of(netdev_mtu: u64) -> u64 {
    [4096, 2048, 1024]
        .into_iter()
        .find(|p| netdev_mtu >= p + (MIN_NETDEV_MTU - 4096))
        .unwrap_or(0)
}
/// RoCE TOS of every QP (fixed in crates/rdma `CoreCfg::tos`): DSCP 26 + ECT0.
pub const DEFAULT_TOS: u8 = 106;

/// NIC QoS state of one netdev (IEEE DCB).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Dcb {
    /// PFC enable bit per priority.
    pub pfc_en: u8,
    /// DSCP -> priority entries of the APP table.
    pub dscp: Vec<(u8, u8)>,
}

/// Parses the attributes of an RTM_GETDCB / DCB_CMD_IEEE_GET reply (after nlmsghdr + dcbmsg).
pub fn parse_dcb(attrs: &[u8]) -> Dcb {
    const ATTR_IEEE: u16 = 13;
    const IEEE_PFC: u16 = 2;
    const IEEE_APP_TABLE: u16 = 3;
    const IEEE_APP: u16 = 1;
    const SEL_DSCP: u8 = 5;
    let mut d = Dcb::default();
    for (t, ieee) in nla(attrs) {
        if t != ATTR_IEEE {
            continue;
        }
        for (t, p) in nla(ieee) {
            match t {
                IEEE_PFC if p.len() >= 2 => d.pfc_en = p[1],
                IEEE_APP_TABLE => {
                    for (t, a) in nla(p) {
                        if t == IEEE_APP && a.len() >= 4 && a[0] == SEL_DSCP {
                            d.dscp.push((u16::from_ne_bytes([a[2], a[3]]) as u8, a[1]));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    d
}

/// Netlink attributes of `b`: (type without the nested/byte-order flags, payload).
fn nla(mut b: &[u8]) -> Vec<(u16, &[u8])> {
    let mut v = Vec::new();
    while b.len() >= 4 {
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let ty = u16::from_ne_bytes([b[2], b[3]]) & 0x3fff;
        if len < 4 || len > b.len() {
            break;
        }
        v.push((ty, &b[4..len]));
        b = &b[len.next_multiple_of(4).min(b.len())..];
    }
    v
}

/// Arms the 2 s receive timeout on `fd`: the only thing that ends `recv` on a silent netlink socket. False = the
/// timeout is not armed, so the caller must not wait at all.
#[cfg(target_os = "linux")]
fn arm_recv_timeout(fd: libc::c_int) -> bool {
    let tv = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: `tv` outlives the call and `fd` is an open socket of the caller.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        ) == 0
    }
}

/// RTM_GETDCB with DCB_CMD_IEEE_GET for `ifname`: the reply's attributes, or None (no DCB support, not permitted).
#[cfg(target_os = "linux")]
fn dcb_get(ifname: &str) -> Option<Vec<u8>> {
    const RTM_GETDCB: u16 = 78;
    const DCB_CMD_IEEE_GET: u8 = 21;
    const DCB_ATTR_IFNAME: u16 = 1;
    let name = ifname.as_bytes();
    let alen = 4 + name.len() + 1;
    let total = 16 + 4 + alen.next_multiple_of(4);
    let mut req = vec![0u8; total];
    req[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
    req[4..6].copy_from_slice(&RTM_GETDCB.to_ne_bytes());
    req[6..8].copy_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes());
    req[17] = DCB_CMD_IEEE_GET;
    req[20..22].copy_from_slice(&(alen as u16).to_ne_bytes());
    req[22..24].copy_from_slice(&DCB_ATTR_IFNAME.to_ne_bytes());
    req[24..24 + name.len()].copy_from_slice(name);
    let mut buf = vec![0u8; 16384];
    // SAFETY: plain netlink route socket for one get request; fd closed below; `req` and `buf` outlive the calls and the
    // kernel writes at most `buf.len()` bytes.
    let n = unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            return None;
        }
        // without the armed timeout a silent kernel would block `recv` forever: report no DCB data instead
        if !arm_recv_timeout(fd) {
            libc::close(fd);
            return None;
        }
        let sent = libc::send(fd, req.as_ptr().cast(), req.len(), 0);
        let n = if sent == req.len() as isize {
            libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0)
        } else {
            -1
        };
        libc::close(fd);
        n
    };
    if n < 20 {
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
            eprintln!("WARNING TIMEOUT hwcheck dcb netlink get exceeded 2s ({ifname})");
        }
        return None;
    }
    let n = n as usize;
    let len = (u32::from_ne_bytes(buf[0..4].try_into().ok()?) as usize).min(n);
    let ty = u16::from_ne_bytes([buf[4], buf[5]]);
    (ty == RTM_GETDCB && len >= 20).then(|| buf[20..len].to_vec())
}

#[cfg(not(target_os = "linux"))]
fn dcb_get(_ifname: &str) -> Option<Vec<u8>> {
    None
}

/// Verdict on the NIC QoS for RoCE TOS `tos`: (status, value, fix).
pub fn qos_verdict(
    d: &Dcb,
    pause: Option<(bool, bool)>,
    tos: u8,
    n: &str,
) -> (Status, String, Option<String>) {
    let dscp = tos >> 2;
    let prio = d.dscp.iter().find(|e| e.0 == dscp).map(|e| e.1);
    let pfc: Vec<u8> = (0..8).filter(|p| d.pfc_en & (1 << p) != 0).collect();
    let gp = pause.is_some_and(|(rx, tx)| rx || tx);
    let val = format!(
        "RoCE TOS {tos} (DSCP {dscp}) -> {}, PFC on {}, global pause {}",
        prio.map_or("no DSCP map (trust pcp: prio 0)".into(), |p| format!(
            "prio {p}"
        )),
        if pfc.is_empty() {
            "no priority".into()
        } else {
            format!("prio {pfc:?}")
        },
        match pause {
            Some((rx, tx)) => format!(
                "rx {} tx {}",
                if rx { "on" } else { "off" },
                if tx { "on" } else { "off" }
            ),
            None => "?".into(),
        }
    );
    let p = prio.unwrap_or(0);
    if pfc.is_empty() {
        // suggest the mapped priority unless it is the default class 0, else the conventional RoCE priority 3
        let q = prio.filter(|&p| p != 0).unwrap_or(3);
        let fix = format!(
            "lossy: receiver NIC drops under incast cost go-back-N retransmits (doc/perf/rdma-ceiling-20261020.md: up to -44 % vs lossless); for the lossless class: dcb pfc set dev {n} prio-pfc {q}:on; dcb app add dev {n} dscp-prio {dscp}:{q}; ethtool -A {n} rx off tx off (switch: same priority no-drop, trust DSCP, ECN)"
        );
        return (Status::Warn, format!("{val}: lossy"), Some(fix));
    }
    if prio.is_none() || !pfc.contains(&p) {
        let q = pfc[0];
        return (
            Status::Warn,
            format!("{val}: RoCE lands on prio {p}, PFC protects {pfc:?}"),
            Some(format!(
                "dcb app add dev {n} dscp-prio {dscp}:{q} (the RoCE TOS is fixed: map DSCP {dscp} to the PFC priority)"
            )),
        );
    }
    if gp {
        return (
            Status::Warn,
            format!("{val}: global pause and PFC both on"),
            Some(format!("ethtool -A {n} rx off tx off")),
        );
    }
    (Status::Ok, format!("{val}: lossless"), None)
}

/// IPs of the routable RoCEv2 GIDs (IPv4-mapped, non-link-local IPv6) of port `pb` whose netdev is `n`.
fn roce_v2_ips(fs: &Fs, pb: &str) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for i in fs.list(&format!("{pb}/gid_attrs/types")) {
        if fs.read(&format!("{pb}/gid_attrs/types/{i}")).as_deref() != Some("RoCE v2") {
            continue;
        }
        let (Some(g), Some(nd)) = (
            fs.read(&format!("{pb}/gids/{i}")),
            fs.read(&format!("{pb}/gid_attrs/ndevs/{i}")),
        ) else {
            continue;
        };
        let w: Vec<u16> = g
            .split(':')
            .filter_map(|x| u16::from_str_radix(x, 16).ok())
            .collect();
        if w.len() != 8 || w.iter().all(|&x| x == 0) || w[0] == 0xfe80 {
            continue;
        }
        let ip = if w[..5].iter().all(|&x| x == 0) && w[5] == 0xffff {
            format!(
                "{}.{}.{}.{}",
                w[6] >> 8,
                w[6] & 0xff,
                w[7] >> 8,
                w[7] & 0xff
            )
        } else {
            std::net::Ipv6Addr::from(<[u16; 8]>::try_from(w).unwrap_or_default()).to_string()
        };
        v.push((ip, nd));
    }
    v
}

pub fn section(fs: &Fs) -> Section {
    let mut v = Vec::new();
    let devs = fs.list("sys/class/infiniband");
    if devs.is_empty() {
        v.push(
            Check::new("rdma.present", "RDMA devices")
                .val("none (no /sys/class/infiniband)")
                .why("RDMA transport (optional): needs a RoCE NIC with its RDMA driver loaded")
                .na(),
        );
        return Section {
            name: "RDMA",
            checks: v,
        };
    }
    let tos = DEFAULT_TOS;
    for d in devs {
        let db = format!("sys/class/infiniband/{d}");
        for p in fs.list(&format!("{db}/ports")) {
            let pb = format!("{db}/ports/{p}");
            let id = |s: &str| format!("rdma.{d}.{p}.{s}");
            let ll = fs.read(&format!("{pb}/link_layer")).unwrap_or_default();
            let state = fs.read(&format!("{pb}/state")).unwrap_or_default();
            let fw = fs.read(&format!("{db}/fw_ver")).unwrap_or_default();
            let c = Check::new(id("port"), format!("{d} port {p}"))
                .val(format!("{state}, link layer {ll}, fw {fw}"))
                .why("RDMA transport: RoCE port (Ethernet link layer) must be ACTIVE")
                .w(6);
            if ll != "Ethernet" {
                v.push(
                    c.val(format!("link layer {ll}: only RoCE is supported"))
                        .na(),
                );
                continue;
            }
            let active = state.ends_with("ACTIVE");
            v.push(if active {
                c.ok()
            } else {
                c.warn()
                    .fix("check cable / switch port; the netdev link must be up")
            });
            let ips = roce_v2_ips(fs, &pb);
            let nds: Vec<String> = {
                let mut x: Vec<String> = ips.iter().map(|e| e.1.clone()).collect();
                if x.is_empty() {
                    x = fs.list(&format!("{db}/device/net"));
                }
                x.sort();
                x.dedup();
                x
            };
            let c = Check::new(id("gid"), format!("{d} RoCEv2 GID"))
                .why("the RDMA connection is bound to the IP of the msgr2 TCP connection; RoCEv2 needs that IP on this device's netdev")
                .w(8);
            v.push(if ips.is_empty() {
                c.val(format!("no RoCEv2 GID with an IP (netdev {})", nds.join(",")))
                    .warn()
                    .fix("configure the OSD's public/cluster IP on this netdev (RoCEv1 is not supported)")
            } else {
                c.val(ips.iter().map(|(ip, nd)| format!("{ip} on {nd}")).collect::<Vec<_>>().join(", "))
                    .ok()
            });
            for n in &nds {
                let mtu = fs.num(&format!("sys/class/net/{n}/mtu")).unwrap_or(0);
                let c = Check::new(id(&format!("{n}.mtu")), format!("{d} RoCE path MTU ({n})"))
                    .val(format!("netdev mtu {mtu}"))
                    .w(7);
                let fix = format!(
                    "ip link set {n} mtu 9000 (jumbo frames on every host interface and switch port of the path; >= {MIN_NETDEV_MTU} already gives the maximum RoCE path MTU 4096)"
                );
                v.push(if mtu >= MIN_NETDEV_MTU {
                    c.ok()
                } else if mtu >= MIN_NETDEV_MTU_RDMA {
                    c.val(format!("netdev mtu {mtu} (RoCE path MTU {})", path_mtu_of(mtu)))
                        .why("RDMA works at this MTU but with lower throughput (more packets per byte, measure); RoCE path MTU 4096 is recommended")
                        .warn()
                        .fix(fix)
                } else {
                    c.why("RoCE path MTU below 1024 is not supported: RDMA stays off for this device, connections stay TCP")
                        .warn()
                        .fix(fix)
                });
                // RoCE priority = the DSCP map entry of the TOS (no entry: priority 0); known only where DCB is readable
                let dcb = if fs.live() {
                    dcb_get(n).map(|a| parse_dcb(&a))
                } else {
                    None
                };
                if fs.live() {
                    v.push(qos_check(
                        n,
                        &id(&format!("{n}.qos")),
                        &d,
                        tos,
                        dcb.as_ref(),
                    ));
                }
                let prio = dcb.as_ref().map(|x| roce_prio(x, tos));
                v.push(dcqcn_check(fs, n, &id(&format!("{n}.dcqcn")), &d, prio));
            }
            v.push(pcie_check(fs, &db, &id("pcie"), &d));
            v.push(loss_check(
                fs,
                &pb,
                &id("loss"),
                &d,
                nds.first().map(String::as_str),
                tos,
            ));
        }
    }
    Section {
        name: "RDMA",
        checks: v,
    }
}

/// Priority the NIC gives RoCE packets of TOS `tos`: its DSCP map entry, else 0.
fn roce_prio(d: &Dcb, tos: u8) -> u8 {
    d.dscp.iter().find(|e| e.0 == tos >> 2).map_or(0, |e| e.1)
}

fn qos_check(n: &str, id: &str, d: &str, tos: u8, dcb: Option<&Dcb>) -> Check {
    let c = Check::new(id, format!("{d} RoCE QoS ({n})"))
        .why("lossless class recommended (measured: 0 drops, 0 out-of-sequence end to end); RoCE TOS, DSCP map and PFC priority must agree, else RoCE fills a no-drop switch queue the NIC does not pause for")
        .w(4);
    let Some(dcb) = dcb else {
        return c
            .val("DCB not readable (no IEEE DCB on this netdev or not permitted)")
            .na();
    };
    let (st, val, fix) = qos_verdict(dcb, crate::net::pause(n), tos, n);
    let c = c.val(val).st(st);
    match fix {
        Some(f) => c.fix(f),
        None => c,
    }
}

/// DCQCN state where the driver exposes it (`/sys/class/net/<n>/ecn`, mlx5 out-of-tree driver; the in-tree driver has no
/// such files: N/A, the firmware default is on for every priority). `prio` = the RoCE priority when DCB is readable: then
/// that priority must be enabled in both roles, else any priority counts.
fn dcqcn_check(fs: &Fs, n: &str, id: &str, d: &str, prio: Option<u8>) -> Check {
    let c = Check::new(id, format!("{d} DCQCN ({n})"))
        .why("ECN-based rate control of RoCE flows (DCQCN) under incast; acts only where switches mark ECN");
    let base = format!("sys/class/net/{n}/ecn");
    if !fs.exists(&base) {
        return c
            .val("not exposed by this kernel/driver (mlx5 firmware default: enabled per priority)")
            .na();
    }
    let on = |role: &str| -> Vec<u8> {
        let mut v: Vec<u8> = fs
            .list(&format!("{base}/{role}/enable"))
            .into_iter()
            .filter(|p| fs.read(&format!("{base}/{role}/enable/{p}")).as_deref() == Some("1"))
            .filter_map(|p| p.parse().ok())
            .collect();
        v.sort_unstable();
        v
    };
    let (np, rp) = (on("roce_np"), on("roce_rp"));
    let c = c.val(format!(
        "notification point prio {np:?}, reaction point prio {rp:?}{}",
        prio.map_or(String::new(), |p| format!(", RoCE on prio {p}"))
    ));
    let ok = match prio {
        Some(p) => np.contains(&p) && rp.contains(&p),
        None => !np.is_empty() && !rp.is_empty(),
    };
    if ok {
        c.ok()
    } else {
        let p = prio.map_or("<prio>".to_string(), |p| p.to_string());
        c.warn().fix(format!(
            "echo 1 > /sys/class/net/{n}/ecn/roce_np/enable/{p}; echo 1 > /sys/class/net/{n}/ecn/roce_rp/enable/{p}"
        ))
    }
}

/// The fabric checks of the RDMA devices behind the physical NICs `nics` (QoS where live, recorded loss), RoCE TOS
/// `tos`: what a running OSD with RDMA on reports once at start (the OSD never changes them).
pub(crate) fn fabric_checks(fs: &Fs, nics: &[String], tos: u8) -> Vec<Check> {
    let mut v = Vec::new();
    for d in fs.list("sys/class/infiniband") {
        let db = format!("sys/class/infiniband/{d}");
        let Some(n) = fs
            .list(&format!("{db}/device/net"))
            .into_iter()
            .find(|n| nics.contains(n))
        else {
            continue;
        };
        for p in fs.list(&format!("{db}/ports")) {
            let pb = format!("{db}/ports/{p}");
            if fs.read(&format!("{pb}/link_layer")).as_deref() != Some("Ethernet") {
                continue;
            }
            let id = |s: &str| format!("rdma.{d}.{p}.{s}");
            if fs.live() {
                let dcb = dcb_get(&n).map(|a| parse_dcb(&a));
                v.push(qos_check(
                    &n,
                    &id(&format!("{n}.qos")),
                    &d,
                    tos,
                    dcb.as_ref(),
                ));
            }
            v.push(loss_check(fs, &pb, &id("loss"), &d, Some(&n), tos));
        }
    }
    v
}

/// RoCE loss and congestion-notification counters of one port (`ports/<p>/hw_counters`, cumulative since the driver
/// loaded; mlx5 names).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LossCtr {
    /// Packets the responder received out of sequence (each starts a go-back-N round: NAK, resend from the lost packet).
    pub out_of_sequence: u64,
    /// Sequence-error NAKs the requester received.
    pub packet_seq_err: u64,
    /// Retransmissions after a local ACK timeout (adaptive retransmission included, where the NIC counts it).
    pub timeouts: u64,
    /// RoCE packets that arrived with ECN CE set (a switch marked them).
    pub ecn_marked: u64,
    /// CNPs this port sent (on ECN marks, and on mlx5 also on drops it noticed) and handled (rate cuts of its QPs).
    pub cnp_sent: u64,
    pub cnp_handled: u64,
}

impl LossCtr {
    /// `None` when the port exposes no RoCE loss counters.
    pub fn read(fs: &Fs, pb: &str) -> Option<LossCtr> {
        let h = format!("{pb}/hw_counters");
        let n = |f: &str| fs.num(&format!("{h}/{f}"));
        Some(LossCtr {
            out_of_sequence: n("out_of_sequence")?,
            packet_seq_err: n("packet_seq_err")?,
            timeouts: n("local_ack_timeout_err").unwrap_or(0)
                + n("roce_adp_retrans_to").unwrap_or(0),
            ecn_marked: n("np_ecn_marked_roce_packets").unwrap_or(0),
            cnp_sent: n("np_cnp_sent").unwrap_or(0),
            cnp_handled: n("rp_cnp_handled").unwrap_or(0),
        })
    }
}

/// Verdict on the recorded RoCE loss of a port whose netdev is `n`, RoCE TOS `tos`: (status, value, fix). Any recorded
/// drop is a WARN: an RC QP recovers a drop by go-back-N (the NIC resends everything after the lost packet) and mlx5 also
/// cuts the QP's rate for it, so large streams lose throughput; without ECN marks the NIC only learns of congestion by
/// dropping.
pub fn loss_verdict(c: &LossCtr, n: &str, tos: u8) -> (Status, String, Option<String>) {
    let val = format!(
        "since driver load: out-of-sequence {}, sequence-error NAKs {}, ACK timeouts {}, ECN-marked {}, CNPs sent {} / handled {}",
        c.out_of_sequence, c.packet_seq_err, c.timeouts, c.ecn_marked, c.cnp_sent, c.cnp_handled
    );
    if c.out_of_sequence + c.packet_seq_err + c.timeouts == 0 {
        return (Status::Ok, format!("{val}: no RoCE drop recorded"), None);
    }
    let dscp = tos >> 2;
    let lossless = format!(
        "lossless class: dcb pfc set dev {n} prio-pfc 3:on; dcb app add dev {n} dscp-prio {dscp}:3; ethtool -A {n} rx off tx off; switch: priority 3 no-drop, trust DSCP, ECN marking on its queue"
    );
    if c.ecn_marked == 0 {
        (
            Status::Warn,
            format!(
                "{val}: RoCE drops and no ECN mark: the switches do not mark ECN, the NIC slows down only after a drop (go-back-N resend + rate cut per drop)"
            ),
            Some(format!(
                "{lossless} (lossy without ECN marking: large RDMA streams lose throughput under incast)"
            )),
        )
    } else {
        (
            Status::Warn,
            format!(
                "{val}: RoCE drops although the switches mark ECN (marking threshold above the drop point, or no PFC)"
            ),
            Some(format!(
                "{lossless}; or lower the switch ECN marking threshold of the RoCE queue"
            )),
        )
    }
}

fn loss_check(fs: &Fs, pb: &str, id: &str, d: &str, n: Option<&str>, tos: u8) -> Check {
    let c = Check::new(id, format!("{d} RoCE loss"))
        .why("a drop costs an RC QP a go-back-N resend and an NIC rate cut; ECN marking (DCQCN) or a lossless class avoids the drops")
        .w(4);
    match (LossCtr::read(fs, pb), n) {
        (Some(l), Some(n)) => {
            let (st, val, fix) = loss_verdict(&l, n, tos);
            let c = c.val(val).st(st);
            match fix {
                Some(f) => c.fix(f),
                None => c,
            }
        }
        _ => c.val("no RoCE loss counters on this port").na(),
    }
}

fn pcie_check(fs: &Fs, db: &str, id: &str, d: &str) -> Check {
    let r = |f: &str| fs.read(&format!("{db}/device/{f}"));
    let c = Check::new(id, format!("{d} PCIe link"))
        .why("a downtrained link caps RDMA throughput below line rate")
        .w(6);
    match (
        r("current_link_speed"),
        r("max_link_speed"),
        r("current_link_width"),
        r("max_link_width"),
    ) {
        (Some(cs), Some(ms), Some(cw), Some(mw)) => {
            let c = c.val(format!("{cs} x{cw} (max {ms} x{mw})"));
            if cs != ms || cw != mw {
                c.warn().fix(
                    "reseat the NIC in a slot with full lanes/generation; check BIOS bifurcation",
                )
            } else {
                c.ok()
            }
        }
        _ => c.val("not readable").na(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(t: u16, p: &[u8]) -> Vec<u8> {
        let mut v = ((4 + p.len()) as u16).to_ne_bytes().to_vec();
        v.extend(t.to_ne_bytes());
        v.extend(p);
        v.resize(v.len().next_multiple_of(4), 0);
        v
    }

    fn reply(pfc_en: u8, apps: &[(u8, u8, u16)]) -> Vec<u8> {
        let mut pfc = vec![8, pfc_en, 0, 0, 0, 0, 0, 0];
        pfc.resize(8 + 128, 0);
        let mut tbl = Vec::new();
        for &(sel, prio, proto) in apps {
            let mut a = vec![sel, prio];
            a.extend(proto.to_ne_bytes());
            tbl.extend(attr(1, &a));
        }
        let mut ieee = attr(2, &pfc);
        ieee.extend(attr(3 | 0x8000, &tbl));
        let mut v = attr(1, b"eth0\0");
        v.extend(attr(13 | 0x8000, &ieee));
        v
    }

    #[test]
    fn dcb_reply_parsed() {
        let d = parse_dcb(&reply(1 << 3, &[(5, 3, 26), (1, 4, 0x8915), (5, 0, 0)]));
        assert_eq!(
            d,
            Dcb {
                pfc_en: 8,
                dscp: vec![(26, 3), (0, 0)]
            }
        );
        assert_eq!(parse_dcb(&[]), Dcb::default());
        assert_eq!(parse_dcb(&[200, 0, 13, 0]), Dcb::default());
    }

    #[test]
    fn loss_verdicts() {
        let clean = LossCtr::default();
        assert_eq!(loss_verdict(&clean, "e", 106).0, Status::Ok);
        // the rented lossy fabric: drops, CNPs from the NIC's own drop detection, no ECN mark anywhere
        let lossy = LossCtr {
            out_of_sequence: 25117,
            packet_seq_err: 57743,
            timeouts: 60,
            ecn_marked: 0,
            cnp_sent: 21836,
            cnp_handled: 52699,
        };
        let (s, v, f) = loss_verdict(&lossy, "e", 106);
        assert_eq!(s, Status::Warn);
        assert!(v.contains("no ECN mark"), "{v}");
        let f = f.unwrap();
        assert!(
            f.contains("dcb pfc set dev e prio-pfc 3:on; dcb app add dev e dscp-prio 26:3"),
            "{f}"
        );
        let marked = LossCtr {
            ecn_marked: 9,
            ..lossy
        };
        let (s, v, f) = loss_verdict(&marked, "e", 106);
        assert_eq!(s, Status::Warn);
        assert!(v.contains("although the switches mark ECN") && f.unwrap().contains("threshold"));
        // a timeout alone is a recorded drop too
        let tail = LossCtr {
            timeouts: 1,
            ..clean
        };
        assert_eq!(loss_verdict(&tail, "e", 106).0, Status::Warn);
    }

    #[test]
    fn roce_priority_from_the_dscp_map() {
        let d = Dcb {
            pfc_en: 8,
            dscp: vec![(26, 3)],
        };
        assert_eq!(roce_prio(&d, 106), 3);
        assert_eq!(roce_prio(&d, 0), 0);
        assert_eq!(roce_prio(&Dcb::default(), 106), 0);
    }

    #[test]
    fn qos_verdicts() {
        let lossless = Dcb {
            pfc_en: 8,
            dscp: vec![(26, 3)],
        };
        assert_eq!(
            qos_verdict(&lossless, Some((false, false)), 106, "e").0,
            Status::Ok
        );
        assert_eq!(
            qos_verdict(&lossless, Some((true, true)), 106, "e").0,
            Status::Warn
        );
        let lossy = Dcb::default();
        let (s, v, f) = qos_verdict(&lossy, Some((true, true)), 106, "e");
        assert_eq!(s, Status::Warn);
        assert!(
            v.ends_with("lossy")
                && f.unwrap()
                    .contains("prio-pfc 3:on; dcb app add dev e dscp-prio 26:3")
        );
        // DSCP 26 mapped to prio 2 while PFC protects 3
        let wrong = Dcb {
            pfc_en: 8,
            dscp: vec![(26, 2)],
        };
        let (s, v, f) = qos_verdict(&wrong, Some((false, false)), 106, "e");
        assert_eq!(s, Status::Warn);
        assert!(v.contains("lands on prio 2") && f.unwrap().contains("dscp-prio 26:3"));
        // no DSCP map: RoCE on prio 0
        let pcp = Dcb {
            pfc_en: 8,
            dscp: vec![],
        };
        assert!(
            qos_verdict(&pcp, None, 106, "e")
                .1
                .contains("lands on prio 0")
        );
    }

    /// The receive timeout is the only thing that ends `recv` on a silent netlink socket: arming it must be checked
    /// (a failure without the check means a check that hangs, with no timeout warning).
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unarmed_receive_timeout_is_reported() {
        // SAFETY: plain datagram socket, closed below.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(fd >= 0);
        assert!(arm_recv_timeout(fd));
        assert!(!arm_recv_timeout(-1), "a setsockopt failure is reported");
        // SAFETY: fd is ours and unused after this.
        unsafe { libc::close(fd) };
    }
}
