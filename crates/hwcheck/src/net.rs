// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Network: physical NICs, RSS, IRQ placement, offloads, VF hygiene.
use crate::action::{Action, Step};
use crate::fs::{Fs, fmt_cpulist, parse_cpulist};
use crate::{Check, Facts, Section};

// ethtool offload get commands (`<linux/ethtool.h>`; the libc crate does not export them).
const GRXCSUM: u32 = 0x14;
const GTXCSUM: u32 = 0x16;
const GTSO: u32 = 0x1e;
const GGRO: u32 = 0x2b;

/// One `SIOCETHTOOL` ioctl on `ifname` with `buf` as the ethtool command block (first u32 = command). True = success.
#[cfg(target_os = "linux")]
fn ethtool_ioctl(ifname: &str, buf: &mut [u32]) -> bool {
    const SIOCETHTOOL: u64 = 0x8946;
    #[repr(C)]
    struct Ifreq {
        name: [u8; 16],
        data: [u8; 24],
    }
    // SAFETY: plain datagram socket for SIOCETHTOOL get ioctls; fd closed below; ifreq and `buf` outlive the call, and
    // every caller sizes `buf` for the command's reply (the kernel writes at most the counts the caller put in it).
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return false;
        }
        let mut r = Ifreq {
            name: [0; 16],
            data: [0; 24],
        };
        let n = ifname.len().min(15);
        r.name[..n].copy_from_slice(&ifname.as_bytes()[..n]);
        let p = buf.as_mut_ptr() as usize;
        r.data[..size_of::<usize>()].copy_from_slice(&p.to_ne_bytes());
        let rc = libc::ioctl(fd, SIOCETHTOOL as _, &mut r as *mut Ifreq);
        libc::close(fd);
        rc == 0
    }
}

#[cfg(target_os = "linux")]
fn ethtool_get(ifname: &str, cmd: u32) -> Option<bool> {
    let mut v = [cmd, 0];
    ethtool_ioctl(ifname, &mut v).then_some(v[1] != 0)
}

/// Active state of the netdev feature `name` (e.g. `rx-gro-hw`): ETHTOOL_GSSET_INFO + ETHTOOL_GSTRINGS (ETH_SS_FEATURES)
/// give its bit, ETHTOOL_GFEATURES the active word (the legacy per-offload gets have no command for it).
#[cfg(target_os = "linux")]
fn ethtool_feature(ifname: &str, name: &str) -> Option<bool> {
    const SSET_INFO: u32 = 0x37;
    const GSTRINGS: u32 = 0x1b;
    const GFEATURES: u32 = 0x3a;
    const SS_FEATURES: u32 = 4;
    // ethtool_sset_info: cmd, reserved, u64 sset_mask, data[1]
    let mut si = [SSET_INFO, 0, 0, 0, 0];
    let mask = (1u64 << SS_FEATURES).to_ne_bytes();
    si[2] = u32::from_ne_bytes(mask[..4].try_into().ok()?);
    si[3] = u32::from_ne_bytes(mask[4..].try_into().ok()?);
    if !ethtool_ioctl(ifname, &mut si) || (si[2] | si[3]) == 0 {
        return None;
    }
    let n = si[4] as usize;
    // ethtool_gstrings: cmd, string_set, len, then len x 32-byte names
    let mut gs = vec![0u32; 3 + n * 8];
    gs[..3].copy_from_slice(&[GSTRINGS, SS_FEATURES, n as u32]);
    if !ethtool_ioctl(ifname, &mut gs) {
        return None;
    }
    let names: Vec<u8> = gs[3..].iter().flat_map(|w| w.to_ne_bytes()).collect();
    let bit = names
        .chunks(32)
        .position(|s| s.split(|&b| b == 0).next() == Some(name.as_bytes()))?;
    // ethtool_gfeatures: cmd, size, size x {available, requested, active, never_changed}
    let blocks = n.div_ceil(32);
    let mut gf = vec![0u32; 2 + 4 * blocks];
    gf[..2].copy_from_slice(&[GFEATURES, blocks as u32]);
    if !ethtool_ioctl(ifname, &mut gf) {
        return None;
    }
    Some((gf[2 + 4 * (bit / 32) + 2] >> (bit % 32)) & 1 != 0)
}

/// ETHTOOL_GRINGPARAM: `(rx max, rx pending, tx max, tx pending)`.
#[cfg(target_os = "linux")]
fn ethtool_rings(ifname: &str) -> Option<(u32, u32, u32, u32)> {
    const RINGPARAM: u32 = 0x10;
    // ethtool_ringparam: cmd, rx_max, rx_mini_max, rx_jumbo_max, tx_max, rx, rx_mini, rx_jumbo, tx
    let mut v = [RINGPARAM, 0, 0, 0, 0, 0, 0, 0, 0];
    ethtool_ioctl(ifname, &mut v).then_some((v[1], v[5], v[4], v[8]))
}

/// Ring verdict from `(rx max, rx cur, tx max, tx cur)`: None = not reported (no max), Some(true) = both rings at max.
fn rings_at_max((rx_max, rx, tx_max, tx): (u32, u32, u32, u32)) -> Option<bool> {
    if rx_max == 0 && tx_max == 0 {
        return None;
    }
    Some(rx >= rx_max && tx >= tx_max)
}

#[cfg(not(target_os = "linux"))]
fn ethtool_get(_ifname: &str, _cmd: u32) -> Option<bool> {
    None
}

/// ETHTOOL_GPAUSEPARAM: global (802.3x) pause `(rx, tx)`.
pub(crate) fn pause(ifname: &str) -> Option<(bool, bool)> {
    #[cfg(target_os = "linux")]
    {
        const PAUSEPARAM: u32 = 0x12;
        // ethtool_pauseparam: cmd, autoneg, rx_pause, tx_pause
        let mut v = [PAUSEPARAM, 0, 0, 0];
        ethtool_ioctl(ifname, &mut v).then_some((v[2] != 0, v[3] != 0))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ifname;
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn ethtool_rings(_ifname: &str) -> Option<(u32, u32, u32, u32)> {
    None
}

#[cfg(not(target_os = "linux"))]
fn ethtool_feature(_ifname: &str, _name: &str) -> Option<bool> {
    None
}

pub fn section(fs: &Fs, facts: &mut Facts) -> Section {
    let mut v = Vec::new();
    let nics: Vec<String> = fs
        .list("sys/class/net")
        .into_iter()
        .filter(|n| n != "lo" && fs.exists(&format!("sys/class/net/{n}/device")))
        .collect();
    facts.nic_total = nics.len();
    if nics.is_empty() {
        v.push(
            Check::new("net.present", "physical NICs")
                .val("none found (no /sys/class/net/*/device)")
                .why("the OSD needs a NIC for the cluster/public network; none visible (container without host sysfs, macOS, or no sysfs)")
                .na(),
        );
        return Section {
            name: "Network",
            checks: v,
        };
    }
    let irqs = fs.read("proc/interrupts").unwrap_or_default();
    for n in nics {
        let b = format!("sys/class/net/{n}");
        let id = |s: &str| format!("net.{n}.{s}");
        let drv = fs
            .link_name(&format!("{b}/device/driver"))
            .unwrap_or_else(|| "?".into());
        let pci = fs.link_name(&format!("{b}/device")).unwrap_or_default();
        let is_vf = fs.exists(&format!("{b}/device/physfn"));
        let speed = fs
            .read(&format!("{b}/speed"))
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(-1);
        let mtu = fs.read(&format!("{b}/mtu")).unwrap_or_default();
        let state = fs.read(&format!("{b}/operstate")).unwrap_or_default();
        let node = fs
            .read(&format!("{b}/device/numa_node"))
            .unwrap_or_default();
        let c = Check::new(id("link"), format!("{n} link"))
            .val(format!(
                "driver {drv}, pci {pci}{}, {}, mtu {mtu}, {state}, numa {}",
                if is_vf { " (VF)" } else { "" },
                if speed > 0 { format!("{} Gbit/s", speed as f64 / 1000.0) } else { "speed unknown".to_string() },
                if node.is_empty() { "?" } else { &node }
            ))
            .why("perf targets are 40 and 100 Gbit/s per OSD; a slower or down port caps the network tier")
            .w(6);
        v.push(if speed > 0 && speed < 25_000 {
            c.warn().fix("use a >= 25 Gbit/s port (40/100 GbE for the perf targets); check cable/optics/autoneg")
        } else if state == "down" {
            c.warn().fix("bring the link up / check cable")
        } else {
            c.ok()
        });
        // queues
        let queues = fs.list(&format!("{b}/queues"));
        let count = |p: &str| queues.iter().filter(|q| q.starts_with(p)).count();
        let (rx, tx) = (count("rx-"), count("tx-"));
        let c = Check::new(id("rss"), format!("{n} RSS queues")).val(format!("{rx} rx / {tx} tx queues")).why("RSS spreads flows over queues = cores (thread-per-core scaling); one queue = one core for all traffic").w(6);
        v.push(if rx == 0 {
            c.val("not available").na()
        } else if rx < 2 {
            c.warn().fix(format!(
                "ethtool -L {n} combined <cores per OSD> (RSS across the OSD cores)"
            ))
        } else {
            c.ok()
        });
        // VF hygiene
        if is_vf {
            let fl = fs
                .read(&format!("{b}/flags"))
                .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            let bad = fl & 0x300 != 0;
            let c = Check::new(id("vfhygiene"), format!("{n} VF hygiene (adr 0030)")).val(format!("flags {fl:#x}: promisc={} allmulti={}", fl & 0x100 != 0, fl & 0x200 != 0)).why("a VF in promisc/allmulti mode can disrupt the PF/other VFs (a lab incident); VFs must stay plain access ports");
            v.push(if bad {
                c.fail()
                    .act(Action::new(vec![Step::LinkFlagsOff { iface: n.clone() }]))
            } else {
                c.ok()
            });
        }
        v.push(irq_check(fs, &irqs, &n, &pci));
        if fs.live() {
            v.extend(live_checks(&n, &drv));
        }
    }
    Section {
        name: "Network",
        checks: v,
    }
}

/// Queue IRQs of NIC `n` (count) and the CPUs the kernel delivers them to. `irqs` = `/proc/interrupts`. effective =
/// the CPU the kernel delivers to (a wide smp_affinity mask still lands on one CPU); kernels without
/// CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK only have the requested mask.
pub(crate) fn nic_irqs(fs: &Fs, irqs: &str, n: &str, pci: &str) -> (usize, Vec<u32>) {
    let l = nic_irq_list(fs, irqs, n, pci);
    (l.len(), irq_cpus(&l))
}

/// Sorted distinct CPUs of `list`.
fn irq_cpus(list: &[(u32, Vec<u32>)]) -> Vec<u32> {
    let mut cpus: Vec<u32> = list.iter().flat_map(|(_, c)| c.iter().copied()).collect();
    cpus.sort_unstable();
    cpus.dedup();
    cpus
}

/// True when `tok` names netdev `n` at a token boundary: `eth1`, `eth1-TxRx-0` and `i40e-eth1-TxRx-0` match `eth1`,
/// `eth10-TxRx-0` does not (a longer name is another NIC).
fn names_netdev(tok: &str, n: &str) -> bool {
    // a name character: inside a name, so `eth1` in `eth10`/`veth1` is not this netdev (but `-`/`.` end a name)
    let name_char = |c: char| c.is_alphanumeric() || c == '_';
    tok.match_indices(n).any(|(i, _)| {
        let before = tok[..i].chars().next_back();
        let after = tok[i + n.len()..].chars().next();
        before.is_none_or(|c| !name_char(c)) && after.is_none_or(|c| !name_char(c))
    })
}

/// Like [`nic_irqs`] per queue IRQ: `(IRQ number, CPUs it is delivered to)`.
fn nic_irq_list(fs: &Fs, irqs: &str, n: &str, pci: &str) -> Vec<(u32, Vec<u32>)> {
    let mut out = Vec::new();
    for l in irqs.lines() {
        let Some((irq, rest)) = l.split_once(':') else {
            continue;
        };
        let Ok(irq) = irq.trim().parse::<u32>() else {
            continue;
        };
        // the action column names the source: the netdev as a whole token, or the controller's PCI address
        let named = rest
            .split_whitespace()
            .any(|t| names_netdev(t, n) || (!pci.is_empty() && t.contains(pci)));
        if named {
            let cpus = fs
                .read(&format!("proc/irq/{irq}/effective_affinity_list"))
                .or_else(|| fs.read(&format!("proc/irq/{irq}/smp_affinity_list")))
                .map(|a| parse_cpulist(&a).unwrap_or_default())
                .unwrap_or_default();
            out.push((irq, cpus));
        }
    }
    out
}

/// NIC-local CPUs of NIC `n`: its NUMA node's CPUs (all online CPUs when the node is unknown).
fn nic_local_cpus(fs: &Fs, n: &str) -> Vec<u32> {
    let node = fs
        .read(&format!("sys/class/net/{n}/device/numa_node"))
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&x| x >= 0);
    let list = node
        .and_then(|x| fs.read(&format!("sys/devices/system/node/node{x}/cpulist")))
        .or_else(|| fs.read("sys/devices/system/cpu/online"))
        .unwrap_or_default();
    parse_cpulist(&list).unwrap_or_default()
}

/// Queue IRQ layout (adr 0063 am. 2): the recommended layout is one queue IRQ per NIC-local CPU, OSD cores included.
/// Warns when the IRQs are concentrated: fewer queues than NIC-local CPUs, or fewer IRQ CPUs than NIC-local CPUs
/// (several IRQs share a CPU while another NIC-local CPU has none). An IRQ on an OSD core is never a warning.
pub(crate) fn irq_check(fs: &Fs, irqs: &str, n: &str, pci: &str) -> Check {
    let list = nic_irq_list(fs, irqs, n, pci);
    let (nirq, cpus) = (list.len(), irq_cpus(&list));
    let c = Check::new(format!("net.{n}.irq"), format!("{n} IRQ placement")).why("kernel tier: one queue IRQ per NIC-local cpu, OSD cores included, beats a few dedicated IRQ cpus, which cap the NIC (adr 0063 am. 2); concentrated IRQs or fewer queues than NIC-local cpus leave NIC cpus idle").w(4);
    let local = nic_local_cpus(fs, n);
    if nirq == 0 {
        return c
            .val("no IRQs matched (driver names vectors differently, or device is userspace-bound)")
            .na();
    }
    let covered = local.iter().filter(|c| cpus.contains(c)).count();
    if local.is_empty() || (nirq >= local.len() && covered == local.len()) {
        return c
            .val(format!("{nirq} IRQs over cpus {}", fmt_cpulist(&cpus)))
            .ok();
    }
    let few_queues = nirq < local.len();
    let hint = format!(
        "ethtool -L {n} combined {} (one queue per NIC-local cpu)",
        local.len()
    );
    // queue k on NIC-local cpu k (wrapping); IRQs already there are left alone
    let pairs: Vec<(u32, u32)> = list
        .iter()
        .enumerate()
        .map(|(i, (irq, cur))| (*irq, local[i % local.len()], cur))
        .filter(|(_, to, cur)| cur.as_slice() != [*to])
        .map(|(irq, to, _)| (irq, to))
        .collect();
    let c = c
        .val(format!(
            "{nirq} IRQs over cpus {}, concentrated (NIC-local cpus {})",
            fmt_cpulist(&cpus),
            fmt_cpulist(&local)
        ))
        .warn();
    match (pairs.is_empty(), few_queues) {
        (true, _) => c.fix(hint),
        (false, true) => c.act(
            Action::new(vec![Step::IrqAffinity {
                iface: n.to_string(),
                pairs,
            }])
            .note(&hint),
        ),
        (false, false) => c.act(Action::new(vec![Step::IrqAffinity {
            iface: n.to_string(),
            pairs,
        }])),
    }
}

/// Measured optimum of `rx-gro-hw` per driver: `(driver, wanted state, why)`. A driver without an entry is reported
/// without a verdict. bnxt_en (zen4 kstall A/B, 100G VFs, kernel 6.12): on = 3048-3069 MB/s, off = 2263-2470 MB/s with
/// RX ring discards (receiver CPU-bound). The 450-520k retransmits with on are fabric loss between the VFs
/// (sum tx - sum rx packets = retransmits, D-SACK ~0, no NIC / kernel drop), not GRO: off only lowers the load.
const GRO_HW_WANT: &[(&str, bool, &str)] = &[(
    "bnxt_en",
    true,
    "hardware GRO: +30 % MB/s (3060 vs 2340 MB/s, zen4); off makes the receiver CPU-bound (ring discards)",
)];

/// `rx-gro-hw` of `drv` being `state` against `table`: `(wanted "on"|"off", why)`; None = no verdict or as wanted.
fn gro_hw_verdict(
    table: &[(&'static str, bool, &'static str)],
    drv: &str,
    state: Option<bool>,
) -> Option<(&'static str, &'static str)> {
    let (_, want, why) = table.iter().find(|e| e.0 == drv)?;
    (state? != *want).then_some((if *want { "on" } else { "off" }, why))
}

/// Offload and ring checks of NIC `n` (ethtool ioctls: live host only).
pub(crate) fn live_checks(n: &str, drv: &str) -> Vec<Check> {
    let g = |cmd| ethtool_get(n, cmd);
    let (rxc, txc, tso, gro) = (g(GRXCSUM), g(GTXCSUM), g(GTSO), g(GGRO));
    // info only: hardware GRO (bnxt TPA, mlx5 SHAMPO) charges a whole receive page per aggregated fragment, so skb truesize
    // per payload byte swings 2-3.6x and the TCP receive window estimate with it (doc/perf/kernel-stall-20261017.md)
    let gro_hw = ethtool_feature(n, "rx-gro-hw");
    let offload = offload_check(n, drv, [rxc, txc, tso, gro], gro_hw);
    let rings = rings_check(n, ethtool_rings(n));
    let v = vec![offload, rings];
    #[cfg(all(feature = "knet", target_os = "linux"))]
    let v = {
        let mut v = v;
        v.push(zcrx_ready(n, drv));
        v
    };
    v
}

/// NIC half of zcrx (adr 0464): header/data split and steering rules. Informational (`na` when not ready): the copy
/// receive is the default; the OSD's startup line decides per public port, the registration decides the queue API.
#[cfg(all(feature = "knet", target_os = "linux"))]
fn zcrx_ready(n: &str, drv: &str) -> Check {
    use rt::knet::zcrx::{Reason, nic};
    let ck = Check::new(format!("net.{n}.zcrx_ready"), format!("{n} zcrx readiness"))
        .why("io_uring zero-copy receive needs header/data split and queues steered to the OSD's public port only (adr 0464)")
        .w(1);
    let vf = if nic::is_vf(n) {
        " (SR-IOV VF: usually no queue API)"
    } else {
        ""
    };
    let Some(ix) = nic::ifindex(n) else {
        return ck.val("no ifindex").na();
    };
    let rings = match nic::rings(ix) {
        Ok(r) => r,
        Err(e) => return ck.val(format!("ethtool netlink: {e}")).na(),
    };
    let rules = nic::steering(n).map_or_else(
        |e| format!("steering: {e}"),
        |s| {
            format!(
                "{} steering rules, default RSS over {} queues",
                s.rules.len(),
                {
                    let mut q = s.rss.clone();
                    q.sort_unstable();
                    q.dedup();
                    q.len()
                }
            )
        },
    );
    let val = format!(
        "driver {drv}{vf}; tcp-data-split {} hds-thresh {}; {rules}",
        rings.hds.map_or("?", |h| if h { "on" } else { "off" }),
        rings.hds_thresh.map_or("?".into(), |t| t.to_string())
    );
    if rings.hds == Some(true) && rings.hds_thresh.unwrap_or(0) == 0 {
        ck.val(val).ok()
    } else {
        // optional feature, not a defect: the command goes into `why` (a `fix` is only for WARN/FAIL)
        ck.val(val)
            .why(format!(
                "io_uring zero-copy receive needs header/data split and queues steered to the OSD's public port only (adr 0464); {}",
                Reason::NoHds.fix(n, 0)
            ))
            .na()
    }
}

/// Offload verdict of NIC `n` from the probed states `[rx-csum, tx-csum, tso, gro]` and `rx-gro-hw`.
pub(crate) fn offload_check(
    n: &str,
    drv: &str,
    st: [Option<bool>; 4],
    gro_hw: Option<bool>,
) -> Check {
    let f = |o: Option<bool>| match o {
        Some(true) => "on",
        Some(false) => "off",
        None => "?",
    };
    let [rxc, txc, tso, gro] = st;
    let c = Check::new(format!("net.{n}.offload"), format!("{n} offloads")).val(format!("rx-csum {} tx-csum {} tso {} gro {} gro-hw {}", f(rxc), f(txc), f(tso), f(gro), f(gro_hw))).why("checksum and segmentation offloads save cycles/byte on every tier (the kernel tier relies on all four)").w(5);
    let feat = |v: &[(&str, bool)]| Step::Features {
        iface: n.to_string(),
        want: v.iter().map(|(f, b)| (f.to_string(), *b)).collect(),
    };
    let hw = gro_hw_verdict(GRO_HW_WANT, drv, gro_hw);
    if st.iter().all(Option::is_none) {
        c.val("not readable (ethtool ioctl refused)").na()
    } else if st.contains(&Some(false)) || hw.is_some() {
        // one action fixes everything wrong at once, so a single run reaches OK
        let mut want = Vec::new();
        if st.contains(&Some(false)) {
            want.extend([("rx", true), ("tx", true), ("tso", true), ("gro", true)]);
        }
        if let Some((w, _)) = hw {
            want.push(("rx-gro-hw", w == "on"));
        }
        let a = Action::new(vec![feat(&want)]);
        c.warn().act(match hw {
            Some((_, why)) => a.note(format!("{drv}: {why}")),
            None => a,
        })
    } else {
        c.ok()
    }
}

/// Ring verdict of NIC `n` from `(rx max, rx cur, tx max, tx cur)`.
pub(crate) fn rings_check(n: &str, rings: Option<(u32, u32, u32, u32)>) -> Check {
    let c = Check::new(format!("net.{n}.rings"), format!("{n} NIC rings")).why("kernel TCP tier: default HW rings (e.g. bnxt 511) overflow under OSD incast (rx_discards -> peer retransmits); rings at the NIC maximum remove the loss").w(6);
    match (rings, rings.and_then(rings_at_max)) {
        (Some((rm, r, tm, t)), Some(false)) => {
            c.val(format!("rx {r}/{rm} tx {t}/{tm}")).warn().act(
                Action::new(vec![Step::Rings {
                    iface: n.to_string(),
                    rx: rm,
                    tx: tm,
                }])
                .note("default rings overflow under OSD incast -> peer retransmits"),
            )
        }
        (Some((rm, r, tm, t)), Some(true)) => c.val(format!("rx {r}/{rm} tx {t}/{tm}")).ok(),
        _ => c.val("not readable (ethtool ring params unsupported)").na(),
    }
}

#[cfg(test)]
mod tests {
    use super::{gro_hw_verdict, irq_check, nic_irqs, rings_at_max};
    use crate::Fs;
    use crate::action::Step;

    #[test]
    fn gro_hw_judgment() {
        let t = [("drvx", false, "reason")];
        assert_eq!(
            gro_hw_verdict(&t, "drvx", Some(true)),
            Some(("off", "reason"))
        );
        assert_eq!(gro_hw_verdict(&t, "drvx", Some(false)), None);
        assert_eq!(gro_hw_verdict(&t, "drvx", None), None);
        assert_eq!(gro_hw_verdict(&t, "other", Some(true)), None);
        let t = [("drvy", true, "r")];
        assert_eq!(gro_hw_verdict(&t, "drvy", Some(false)), Some(("on", "r")));
    }

    #[test]
    fn rings_verdict() {
        assert_eq!(rings_at_max((8191, 8191, 2047, 2047)), Some(true));
        assert_eq!(rings_at_max((8191, 511, 2047, 2047)), Some(false));
        assert_eq!(rings_at_max((8191, 8191, 2047, 511)), Some(false));
        assert_eq!(rings_at_max((0, 0, 0, 0)), None);
    }

    /// 4 NIC-local cpus (node 0), `queues` IRQs 40.. delivered to `cur`; returns the check.
    fn irq_host(queues: usize, cur: &[&str]) -> crate::Check {
        let r = std::env::temp_dir().join(format!("hwcheck-irq-{}-{queues}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        let w = |rel: &str, s: &str| {
            let p = r.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, s).unwrap();
        };
        w("sys/class/net/eth0/device/numa_node", "0");
        w("sys/devices/system/node/node0/cpulist", "0-3");
        let mut ints = String::new();
        for (q, c) in cur.iter().enumerate().take(queues) {
            ints += &format!(" {}: 1 0 PCI-MSIX eth0-TxRx-{q}\n", 40 + q);
            w(&format!("proc/irq/{}/effective_affinity_list", 40 + q), c);
        }
        let c = irq_check(&Fs::new(&r), &ints, "eth0", "");
        let _ = std::fs::remove_dir_all(&r);
        c
    }

    #[test]
    fn irq_spread_rule() {
        use crate::Status;
        // 4 queues one per cpu: ok
        assert_eq!(irq_host(4, &["0", "1", "2", "3"]).status, Status::Ok);
        // 4 queues on 2 cpus: warn, spread pins only the IRQs that move, no ethtool hint
        let c = irq_host(4, &["0", "0", "1", "1"]);
        assert_eq!(c.status, Status::Warn);
        let Step::IrqAffinity { pairs, .. } = &c.actions[0].steps[0] else {
            panic!("no IRQ step")
        };
        assert_eq!(pairs, &vec![(41, 1), (42, 2), (43, 3)]);
        let f = c.fix.unwrap();
        assert!(!f.contains("ethtool -L"), "{f}");
        // the fix is runnable: one concrete command per moved IRQ, no placeholders
        assert!(
            f.contains("echo 1 > /proc/irq/41/smp_affinity_list")
                && f.contains("echo 3 > /proc/irq/43/smp_affinity_list"),
            "{f}"
        );
        assert!(!f.contains("<cpu>") && !f.contains("<irq>"), "{f}");
        // 2 queues, 4 cpus, wrong cpus: spread + ethtool -L hint
        let c = irq_host(2, &["3", "3"]);
        assert_eq!(c.status, Status::Warn);
        let Step::IrqAffinity { pairs, .. } = &c.actions[0].steps[0] else {
            panic!("no IRQ step")
        };
        assert_eq!(pairs, &vec![(40, 0), (41, 1)]);
        assert!(c.fix.unwrap().contains("ethtool -L eth0 combined 4"));
        // 2 queues already on cpus 0,1: warns for the queue count, hint only, no action
        let c = irq_host(2, &["0", "1"]);
        assert_eq!(c.status, Status::Warn);
        assert!(c.actions.is_empty());
        assert!(c.fix.unwrap().contains("ethtool -L eth0 combined 4"));
    }

    /// A NIC name is matched as a whole token: `eth1` must not collect the queue IRQs of `eth10` (a foreign NIC's IRQ
    /// would be reported and re-pinned by `host-tune --apply`); driver-prefixed names still match.
    #[test]
    fn irq_names_match_the_netdev_not_a_longer_name() {
        let r = std::env::temp_dir().join(format!("hwcheck-irqname-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        let w = |rel: &str, s: &str| {
            let p = r.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, s).unwrap();
        };
        w("sys/devices/system/cpu/online", "0-3");
        let ints = " 50: 1 0 PCI-MSIX-0000:41:00.0 0-edge eth10-TxRx-0\n 51: 1 0 PCI-MSIX-0000:41:00.0 1-edge eth1-TxRx-0\n 52: 1 0 PCI-MSIX-0000:41:00.0 2-edge i40e-eth1-TxRx-1\n";
        for (irq, cpu) in [(50, "0"), (51, "1"), (52, "2")] {
            w(&format!("proc/irq/{irq}/effective_affinity_list"), cpu);
        }
        let got = nic_irqs(&Fs::new(&r), ints, "eth1", "");
        let _ = std::fs::remove_dir_all(&r);
        assert_eq!(got, (2, vec![1, 2]), "eth10 is a different NIC");
    }
}
