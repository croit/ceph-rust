// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Kernel TCP tier run mode (adr 0053): the OSD over kernel sockets driven by one io_uring per core. Runs on any NIC
//! (bonding, VLAN, routing, firewall); NVMe stays SPDK.
//!
//! croit-flashstore-osd (--dev file:PATH[,size=N] | spdk:PCI | --data DIR) [--public-addr IP] [--cluster-addr IP] [--ip IP]
//!         [--mon-host ADDR] [--port-base N] [--hostname H] [--cores N] [--lcore N] [--idle spin|sleep] [--mem MB]
//!         [--steer hash|cpu] [--knet-balance on|off] [--knet-peer-steer on|off] [--knet-peer-cores N] [--knet-wake on|off]
//!         [--knet-bufs N] [--knet-buf-kb N] [--knet-zc-min BYTES]
//!         [--knet-sockbuf-kb N] [--knet-send-chunk-kb N] [--knet-zcrx auto|off|nodev] [--set k=v]...
//! Addresses as classic: `--public-addr`/`--cluster-addr`, else conf `public_addr`/`cluster_addr` (`--set`), else the
//! local address inside `public_network`/`cluster_network`, else `--ip`, else the address the kernel routes towards
//! the first mon (cluster defaults to public).
// a `knet` build without a store backend (`lab` / `spdk`) only prints the usage error: the run loop is unused there
#![cfg_attr(
    not(any(feature = "lab", feature = "spdk", feature = "kernel-nvme")),
    allow(dead_code, clippy::unnecessary_literal_unwrap)
)]
use crate::addr::parse_addr;
#[cfg(feature = "kernel-nvme")]
use crate::args::store_backend;
use crate::args::{arg, die};
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
use crate::mcommon::{Be, Boot, build_osd, core_end, exit_code, fail, say};
use osd::{Osd, OsdConfig};
use rt::knet::zcrx::Plan as ZPlan;
use rt::knet::{Binds, KCfg, KCore, KNet, KPlace, KSpread, Steer};
use rt::netaddr;
use rt::{Idle, XPort};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// True/1/yes/on and false/0/no/off (`ms_bind_ipv4` and friends); anything else is fatal.
fn conf_bool(lc: &[(String, String)], k: &str, default: bool) -> Result<bool, String> {
    match osd::config::local_get(lc, k).map(|v| v.trim().to_ascii_lowercase()) {
        None => Ok(default),
        Some(v) => match v.as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(format!("bad {k} {v:?} (true|false)")),
        },
    }
}

/// Families the daemon binds and their addrvec order (spec 1 / 2.4).
fn families(lc: &[(String, String)]) -> Result<netaddr::Families, String> {
    let f = netaddr::Families {
        v4: conf_bool(lc, "ms_bind_ipv4", true)?,
        v6: conf_bool(lc, "ms_bind_ipv6", false)?,
        prefer_v4: conf_bool(lc, "ms_bind_prefer_ipv4", false)?,
    };
    if !f.v4 && !f.v6 {
        return Err("ms_bind_ipv4=false and ms_bind_ipv6=false: enable at least one family".into());
    }
    Ok(f)
}

/// One role's addresses (one per enabled family, addrvec order) and the bound port of its listener kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RoleAddrs {
    /// Listener addresses, port 0 = search.
    pub ips: Vec<SocketAddr>,
}

/// The operator's address sources of one role (public or cluster, spec 2 step 1).
struct RoleCfg<'a> {
    what: &'a str,
    flag: Option<String>,
    conf_addr: Option<&'a str>,
    networks: Option<&'a str>,
    ifaces: Option<&'a str>,
}

/// Explicit address / networks / fallback for one role (spec 2 / 2.2, and spec 8 where we differ).
fn pick_role(
    rc: &RoleCfg<'_>,
    fam: netaddr::Families,
    addrs: &[netaddr::IfAddr],
    fallback: impl FnOnce() -> Option<IpAddr>,
) -> Result<RoleAddrs, String> {
    let RoleCfg {
        what,
        flag,
        conf_addr,
        networks,
        ifaces,
    } = rc;
    let flag = flag.clone();
    if ifaces.is_some_and(|i| !i.trim().is_empty()) && networks.is_none_or(|n| n.trim().is_empty())
    {
        return Err(format!(
            "{what}_network_interface needs {what}_network (spec 1)"
        ));
    }
    // one address of every enabled family, in addrvec order (spec 2.4), whatever order the sources were read in
    let ordered = |ips: Vec<(IpAddr, u16)>| -> RoleAddrs {
        let order = fam.ordered();
        let mut ips = ips;
        ips.sort_by_key(|(ip, _)| {
            order
                .iter()
                .position(|f| f.matches(*ip))
                .unwrap_or(usize::MAX)
        });
        RoleAddrs {
            ips: ips
                .into_iter()
                .map(|(ip, p)| SocketAddr::new(ip, p))
                .collect(),
        }
    };
    if let Some(explicit) = flag.or_else(|| {
        conf_addr
            .filter(|c| !c.trim().is_empty())
            .map(str::to_owned)
    }) {
        let (ip, port) = parse_addr(&explicit)?;
        let mut out = vec![(ip, port)];
        // spec 8: an explicit address advertises its own family only; the other enabled family comes from its network
        if let Some(n) = networks.filter(|n| !n.trim().is_empty()) {
            let nets =
                netaddr::parse_networks(n).ok_or_else(|| format!("bad {what}_network {n:?}"))?;
            for f in fam.ordered() {
                if f.matches(ip) {
                    continue;
                }
                let one = netaddr::pick_one(&nets, &filter_ifaces(addrs, *ifaces), f)
                    .map_err(|e| format!("{what}_network {n:?}: {e}"))?;
                out.push((one, port));
            }
        }
        // no partial dual-stack: an enabled family without address/network fails startup (spec 2.2 / 8)
        if out.len() != fam.ordered().len() {
            return Err(format!(
                "ms_bind_ipv4={} ms_bind_ipv6={} but {what} has one address only; add a {what}_network of the other \
                 family (or clear the family you do not want)",
                fam.v4, fam.v6
            ));
        }
        return Ok(ordered(out));
    }
    if let Some(n) = networks.filter(|n| !n.trim().is_empty()) {
        let nets = netaddr::parse_networks(n).ok_or_else(|| format!("bad {what}_network {n:?}"))?;
        let ips = netaddr::pick_families(&nets, &filter_ifaces(addrs, *ifaces), fam)
            .map_err(|e| format!("{what}_network {n:?}: {e}"))?;
        return Ok(ordered(ips.into_iter().map(|ip| (ip, 0)).collect()));
    }
    // no address, no network: classic binds wildcards and learns the address from the first peer; croit-flashstore-osd binds
    // explicit addresses only, so it needs one per enabled family (spec 8)
    let Some(ip) = fallback() else {
        return Err(format!(
            "cannot determine the {what} address (use --{what}-addr or a {what}_network)"
        ));
    };
    if fam.ordered().iter().any(|f| !f.matches(ip)) {
        return Err(format!(
            "ms_bind_ipv4={} ms_bind_ipv6={} needs one address per family; {what} fallback is {} only \
             (set {what}_network or {what}_addr)",
            fam.v4,
            fam.v6,
            if ip.is_ipv4() { "IPv4" } else { "IPv6" }
        ));
    }
    Ok(ordered(vec![(ip, 0)]))
}

/// `addrs` limited to the interfaces named in `ifaces` (`*_network_interface`, spec 2.2).
fn filter_ifaces(addrs: &[netaddr::IfAddr], ifaces: Option<&str>) -> Vec<netaddr::IfAddr> {
    let Some(list) = ifaces.map(netaddr::parse_ifaces).filter(|l| !l.is_empty()) else {
        return addrs.to_vec();
    };
    addrs
        .iter()
        .filter(|a| list.contains(&a.iface))
        .cloned()
        .collect()
}

/// Whether any cluster address source (flag, conf `cluster_addr`, `cluster_network`, `cluster_network_interface`) is set
/// (spec ip-addressing.md 2 step 1).
fn cluster_configured(a: &[String], lc: &[(String, String)]) -> bool {
    arg(a, "--cluster-addr").is_some()
        || osd::config::local_get(lc, "cluster_addr").is_some_and(|c| !c.trim().is_empty())
        || osd::config::local_get(lc, "cluster_network").is_some_and(|n| !n.trim().is_empty())
        || osd::config::local_get(lc, "cluster_network_interface")
            .is_some_and(|i| !i.trim().is_empty())
}

/// Public and cluster addresses, one per enabled family in addrvec order (pure given the host's addresses; tested).
pub(crate) fn resolve_addrs(
    a: &[String],
    lc: &[(String, String)],
    fam: netaddr::Families,
    addrs: &[netaddr::IfAddr],
    towards_mon: impl FnOnce() -> Option<IpAddr>,
) -> Result<(RoleAddrs, RoleAddrs), String> {
    let ip_alias = arg(a, "--ip")
        .map(|s| parse_addr(&s).map(|x| x.0))
        .transpose()?;
    let public = pick_role(
        &RoleCfg {
            what: "public",
            flag: arg(a, "--public-addr"),
            conf_addr: osd::config::local_get(lc, "public_addr"),
            networks: osd::config::local_get(lc, "public_network"),
            ifaces: osd::config::local_get(lc, "public_network_interface"),
        },
        fam,
        addrs,
        || ip_alias.or_else(towards_mon),
    )?;
    // spec 2 step 1: no cluster address and no cluster network -> the public addresses (the public network+interface)
    let cluster_given = cluster_configured(a, lc);
    let cluster = if cluster_given {
        pick_role(
            &RoleCfg {
                what: "cluster",
                flag: arg(a, "--cluster-addr"),
                conf_addr: osd::config::local_get(lc, "cluster_addr"),
                networks: osd::config::local_get(lc, "cluster_network"),
                ifaces: osd::config::local_get(lc, "cluster_network_interface"),
            },
            fam,
            addrs,
            || Some(ip_alias.unwrap_or(public.ips[0].ip())),
        )?
    } else {
        // the public addresses, but never an explicit public port: the cluster listener searches its own port
        RoleAddrs {
            ips: public
                .ips
                .iter()
                .map(|a| SocketAddr::new(a.ip(), 0))
                .collect(),
        }
    };
    Ok((public, cluster))
}

/// `1.2.3.4,[fd00::1]` for the startup line.
fn addrs_text(ips: &[SocketAddr]) -> String {
    ips.iter()
        .map(|a| a.ip().to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Startup WARNING lines for a floating/VIP-chosen address of `role` (support cases CS-5452 / CS-5308): one per suspicious address.
/// Pure given the host's interface list and the role's configured networks; no host state.
fn vip_warnings(
    what: &str,
    role: &RoleAddrs,
    addrs: &[netaddr::IfAddr],
    networks: Option<&str>,
) -> Vec<String> {
    let nets = networks
        .and_then(netaddr::parse_networks)
        .unwrap_or_default();
    let mut out = Vec::new();
    for a in &role.ips {
        let ip = a.ip();
        let iface = addrs
            .iter()
            .find(|x| x.ip == ip)
            .map(|x| x.iface.as_str())
            .unwrap_or("");
        match netaddr::vip_warning(addrs, ip, &nets) {
            Some(netaddr::AddrWarn::HostRoute) => out.push(format!(
                "WARNING {what} address {ip} on {iface} is a /32 (/128) address inside the {what}_network ({}): \
                 a floating/VIP address (keepalived/VRRP?) is advertised to the cluster and the OSD is marked down \
                 when it moves; set {what}_addr to the host's own address",
                networks.unwrap_or("")
            )),
            Some(netaddr::AddrWarn::NotFirstInNetwork) => out.push(format!(
                "WARNING {what} address {ip} is an additional address on {iface} in the {what}_network ({}): if it is \
                 a floating/VIP address the OSD is marked down when it moves; set {what}_addr to the host's own address",
                networks.unwrap_or("")
            )),
            None => {}
        }
    }
    out
}

/// `--knet-peer-steer on|off` (adr 0054 relay avoided): our cluster listener picks the core by TCP source port and our
/// dials to peer OSDs bind a source port that selects their owner core there. Default: on with more than one core and
/// `--steer hash` (measured: relayed peer connections -> 0, 4M write +17 % at size 3), off with `--steer cpu` (the
/// cluster listener keeps its CPU filter). `--knet-peer-cores N` = the peers' core count (default: ours, homogeneous
/// cluster). A wrong guess, a classic peer or a busy port only costs the relay. Returns (listener steering, dial modulus;
/// 0 = no dial binding).
fn peer_steer(a: &[String], cores: usize, steer: &Steer) -> Result<(bool, u32), String> {
    let on = match arg(a, "--knet-peer-steer").as_deref() {
        None => matches!(steer, Steer::Hash),
        Some("on") => true,
        Some("off") => false,
        Some(o) => return Err(format!("bad --knet-peer-steer {o:?} (on|off)")),
    };
    let peer_cores = match arg(a, "--knet-peer-cores").map(|v| v.parse::<u32>()) {
        None => cores as u32,
        Some(Ok(n)) if (1..=1024).contains(&n) => n,
        Some(_) => return Err("bad --knet-peer-cores (1..=1024)".into()),
    };
    if !on {
        return Ok((false, 0));
    }
    Ok((cores > 1, if peer_cores > 1 { peer_cores } else { 0 }))
}

/// Kernel tier default for `--knet-zc-min` (bytes): 4M reads/replica pushes go out zero copy (rented host 2026-10-12: OSD cpu
/// -20..-45 % on 4M; the copy path zeroes + copies every page). `--knet-zc-min 0` = off.
const ZC_MIN: usize = 256 << 10;

/// Highest `--knet-store-park` percent (adr 0162): above it an idle core would sleep the whole learned device latency and
/// stop polling, so every completion would miss the ring.
const STORE_PARK_MAX: u32 = 90;

/// A `--knet-*-kb` value as bytes; `min` is the smallest value the tunable accepts (a smaller one is refused, never
/// silently raised).
fn kb_arg(k: &str, v: u64, min: u32) -> Result<u32, String> {
    let b = v
        .checked_mul(1024)
        .and_then(|b| u32::try_from(b).ok())
        .ok_or_else(|| format!("bad {k} {v} (KiB, at most {})", u32::MAX / 1024))?;
    if b < min {
        return Err(format!("bad {k} {v} (KiB, at least {})", min / 1024));
    }
    Ok(b)
}

/// A `--knet-*-kb` value as bytes on this platform (usize-sized tunables).
fn bytes_arg(k: &str, v: u64) -> Result<usize, String> {
    let b = v
        .checked_mul(1024)
        .ok_or_else(|| format!("bad {k} {v} (KiB, too large)"))?;
    usize::try_from(b).map_err(|_| format!("bad {k} {v} (KiB, too large for this platform)"))
}

fn knet_cfg(a: &[String]) -> Result<KCfg, String> {
    let mut c = KCfg {
        zc_min: ZC_MIN,
        ..KCfg::default()
    };
    let num = |k: &str| -> Result<Option<u64>, String> {
        arg(a, k)
            .map(|v| v.parse::<u64>().map_err(|_| format!("bad {k} {v:?}")))
            .transpose()
    };
    if let Some(v) = num("--knet-bufs")? {
        c.bufs = u16::try_from(v)
            .ok()
            .filter(|v| v.is_power_of_two())
            .ok_or("--knet-bufs must be a power of two <= 32768")?;
    }
    if let Some(v) = num("--knet-buf-kb")? {
        c.buf_size = kb_arg("--knet-buf-kb", v, 4 << 10)?;
    }
    if let Some(v) = num("--knet-zc-min")? {
        c.zc_min = usize::try_from(v)
            .map_err(|_| format!("bad --knet-zc-min {v} (bytes, too large for this platform)"))?;
    }
    if let Some(v) = num("--knet-sockbuf-kb")? {
        c.sockbuf = kb_arg("--knet-sockbuf-kb", v, 0)?;
    }
    if let Some(v) = num("--knet-send-chunk-kb")? {
        c.send_chunk = bytes_arg("--knet-send-chunk-kb", v)?;
    }
    if let Some(v) = num("--knet-store-park")? {
        c.store_park_pct = u32::try_from(v)
            .ok()
            .filter(|p| *p <= STORE_PARK_MAX)
            .ok_or_else(|| format!(
                "bad --knet-store-park {v} (percent, 0..={STORE_PARK_MAX}: above that an idle core sleeps the whole learned device latency and stops polling)"
            ))?;
    }
    if let Some(v) = num("--knet-store-irq-park")? {
        c.store_irq_park_pct = u32::try_from(v).ok().filter(|p| *p <= 100).ok_or_else(|| {
            format!(
                "bad --knet-store-irq-park {v} (percent, 0..=100; 100 = sleep until the completion wakes the core)"
            )
        })?;
    }
    Ok(c)
}

/// First-seen order without duplicates (`Vec::dedup` alone only removes neighbours: public on eth0/eth1 plus cluster on
/// eth0 left three entries and walked the NIC twice).
fn dedup_ifaces(v: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for i in v {
        if !out.contains(&i) {
            out.push(i);
        }
    }
    out
}

/// `--idle spin | sleep`: default sleep. The sleep policy is derived per core from the measured wake latency and the store
/// state (see `KCore`). The retired forms
/// (`--idle sleep:US[:AFTER]`, `--knet-deep-after N`) are refused, not ignored: a silently ignored tuning flag misleads.
fn idle_of(a: &[String]) -> Result<Idle, String> {
    if arg(a, "--knet-deep-after").is_some() {
        return Err("--knet-deep-after was removed: an idle core now sleeps at once when nothing is in flight and polls only while store IO is in flight (doc/perf/large-io-20261021.md, OSD wake overhead)".into());
    }
    match arg(a, "--idle").as_deref() {
        Some("spin") => Ok(Idle::Spin),
        None | Some("sleep") => Ok(Idle::Sleep),
        Some(s) => Err(format!(
            "--idle {s:?}: expected spin or sleep (the sleep:US:AFTER form was removed, the sleep times are derived from the measured wake latency)"
        )),
    }
}

/// Payload-sized allocations into the EAL hugepage heap (adr 0061 am. 4), after the EAL of `mem_mb` MiB is up. `shared`:
/// the EAL also serves SPDK: budget = half of `--mem` (adr 0076 am. 3). SPDK's share is its DMA buffers (`nvme::dmapool`
/// `held_peak_bytes`: <= 140 MiB in the ice-a cells, parking bounded per store thread) plus queue memory; a quarter left
/// the store's large blocks (omap runs, checkpoint arena) short and every budget miss zeroed parked blocks on the PG core
/// (doc/perf/eal-budget-20261025.md); the store's DMA buffers are bounded by the rest (`store_dma_budget`).
/// Memory-only EAL of the kernel NVMe backend: it serves nothing but this heap, so
/// the budget is all of `--mem` (adr 0076 am. 2). `NV_HUGE_ALLOC_MB` lowers it, `NV_HUGE_ALLOC=0` = off.
#[cfg(feature = "spdk")]
fn enable_payload_hugepages(mem_mb: usize, shared: bool) {
    if std::env::var("NV_HUGE_ALLOC").as_deref() == Ok("0") {
        return;
    }
    let cap = if shared { mem_mb / 2 } else { mem_mb };
    let mb = std::env::var("NV_HUGE_ALLOC_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(cap)
        .min(cap);
    if mb > 0 {
        eal_heap::enable_huge_alloc_with_budget(mb << 20);
        eprintln!(
            "croit-flashstore-osd: kernel tier: payloads in hugepages (budget {mb} MiB, adr 0061 am. 4)"
        );
    }
}

/// The store's DMA budget on the SPDK tier (adr 0175 am. 4): what the EAL hugepage heap (`--mem` =
/// `flashstore_hugepages_mb`) has free once SPDK and every device queue hold their memory, plus the DMA buffers the store
/// holds already, less what the payload budget may still take (half of `--mem`, adr 0076 am. 3). `nvme::dmapool` admits
/// deferrable memory (asynchronous reads, staged write copies, shared reply data) within three quarters of it, so the
/// last quarter only holds in-flight IO memory, which IO completions return. Call once the queues are open, before the
/// cores run. The start ends unless every store shard has a core of its own (`shards` <= `cores`: a synchronous read
/// waiting for memory polls only its own core) and the last quarter holds the largest in-flight IO request (one device
/// command: the device transfer limit, at least a 256 KiB data run), naming the setting to change.
#[cfg(feature = "spdk")]
fn store_dma_budget(c: &nvme::any::AnyCtrl, shards: u32, cores: usize) -> Result<(), String> {
    const MIB: u64 = 1 << 20;
    if shards as usize > cores {
        return Err(format!(
            "spdk tier: the store has {shards} shards but runs on {cores} cores: every shard needs a core of its own \
             (a synchronous read waiting for DMA memory polls only its own core, adr 0175 am. 4): set flashstore_cores \
             {shards} (with as many CPUs), or redeploy this OSD with croit-flashstore-tool prepare --store-shards {cores}"
        ));
    }
    let g = c.geometry();
    // the most in-flight IO memory one request holds before it submits: one device transfer (a store write run is at
    // most 256 KiB) plus the pad block of a WAL unit, each at its allocator class size (what the budget counts); every
    // multi-part request takes its buffers one part at a time
    let xfer = (u64::from(g.max_xfer_lbas) * u64::from(g.lba_size)).max(256 << 10) as usize;
    let largest = (nvme::dmapool::alloc_len(xfer) + nvme::dmapool::alloc_len(4096)) as u64;
    let (total, free, _) = eal_heap::eal_heap_stats();
    let payload = if eal_heap::huge_alloc_enabled() {
        let (used, limit, _) = eal_heap::huge_alloc_stats();
        limit.saturating_sub(used) as u64
    } else {
        0
    };
    let held = nvme::dmapool::BUDGET.held();
    let budget = (free + held).saturating_sub(payload);
    if budget / 4 < largest {
        // the heap minus what SPDK and the queues hold must leave 4 * largest beside the payload budget (half of the heap)
        let base = total.saturating_sub(free + held) + 4 * largest;
        let need = if payload > 0 { 2 * base } else { base }.div_ceil(MIB);
        return Err(format!(
            "hugepages: the EAL heap ({} MiB free of {} MiB) leaves the store {} MiB of DMA memory beside the payload budget ({} MiB); its last quarter must hold the largest device command ({} KiB): set flashstore_hugepages_mb {} or more",
            free / MIB,
            total / MIB,
            budget / MIB,
            payload / MIB,
            largest >> 10,
            need
        ));
    }
    nvme::dmapool::set_budget(budget);
    eprintln!(
        "croit-flashstore-osd: spdk tier: store DMA budget {} MiB of {} MiB hugepages (payload budget {} MiB; deferrable memory admitted within 3/4, shared reply data within 1/2, adr 0175 am. 4)",
        budget / MIB,
        total / MIB,
        payload / MIB
    );
    Ok(())
}

/// Daemon start in kernel-tier mode.
pub fn main_with(a: Vec<String>, placement: bool, source_pull: bool) -> i32 {
    let dev = arg(&a, "--dev");
    // PCI address of the NVMe (CPU placement, device metadata), whichever backend drives it
    let nvme_pci = dev
        .as_deref()
        .and_then(|d| d.strip_prefix("spdk:"))
        .map(|r| r.split(',').next().unwrap_or("").to_owned());
    // adr 0169: `--store-backend` / conf `flashstore_store_backend` (forwarded by `croit-flashstore-osd run` as `--set`): `kernel` /
    // `kernel-cmd` drive an `spdk:BDF` device through its kernel node (O_DIRECT / NVMe passthrough over io_uring)
    #[cfg(feature = "kernel-nvme")]
    let dev = match (dev, store_backend(&a)) {
        (Some(d), Some(b)) => match nvme::any::resolve_backend(&d, &b) {
            Ok(d) => Some(d),
            Err(e) => return die(3, format!("--store-backend {b}: {e}")),
        },
        (d, _) => d,
    };
    let data_dir = arg(&a, "--data");
    let Some(data) = data_dir.clone().or_else(|| dev.clone()) else {
        return die(
            2,
            "usage: croit-flashstore-osd (--dev file:PATH|spdk:PCI | --data DIR) [--public-addr IP] [--cluster-addr IP] [--ip IP] \
             [--mon-host ADDR] [--port-base N] [--hostname H] [--cores N] [--lcore N] [--idle spin|sleep] [--mem MB] \
             [--steer hash|cpu] [--knet-balance on|off] [--knet-bufs N] [--knet-buf-kb N] [--knet-zc-min BYTES] \
             [--knet-zcrx auto|off|nodev] [--set k=v]...",
        );
    };
    let mon_host = match osddir::mon_host_from_args(&a) {
        Ok(h) => h,
        Err(e) => return die(2, e),
    };
    let mons = match monc::parse_mon_host(&mon_host) {
        Ok(m) => m,
        Err(e) => return die(2, format!("mon_host: {e}")),
    };
    let (local_config, local_sources) = crate::args::local_config(&a);
    eprintln!(
        "croit-flashstore-osd: {}",
        osd::nvmestore::set_memory_target(&local_config, osd::monboot::boot())
    );
    if let Err(e) = osd::nvmestore::set_store_options(&local_config) {
        return die(2, e);
    }
    let mon_target = mons
        .first()
        .and_then(|m| m.v2())
        .and_then(|x| x.ip().map(|ip| (ip, x.port())));
    let fam = match families(&local_config) {
        Ok(f) => f,
        Err(e) => return die(2, e),
    };
    let local = netaddr::local_addrs();
    let (public, cluster) = match resolve_addrs(&a, &local_config, fam, &local, || {
        mon_target.and_then(|(ip, p)| netaddr::local_ip_towards(ip, p))
    }) {
        Ok(x) => x,
        Err(e) => return die(2, e),
    };
    // spec ip-addressing.md 2 step 1: no cluster source -> the back path shares the public address (shared fate)
    let cluster_fallback = !cluster_configured(&a, &local_config);
    if cluster_fallback {
        eprintln!(
            "croit-flashstore-osd: WARNING no cluster_addr/cluster_network: the cluster (back) path falls back to the \
             public (front) address {}; one NIC failure takes the data path and both heartbeat paths at once",
            addrs_text(&public.ips)
        );
    }
    // floating/VIP placement guards (CS-5452 / CS-5308); skipped for the cluster role when it just fell back to public
    let mut warns = vip_warnings(
        "public",
        &public,
        &local,
        osd::config::local_get(&local_config, "public_network"),
    );
    if !cluster_fallback {
        warns.extend(vip_warnings(
            "cluster",
            &cluster,
            &local,
            osd::config::local_get(&local_config, "cluster_network"),
        ));
    }
    for w in warns {
        eprintln!("croit-flashstore-osd: {w}");
    }
    // the first enabled family's address is what NIC checks, RDMA and the local path use (IPv4 only today)
    let v4 = |r: &RoleAddrs| -> Option<Ipv4Addr> {
        r.ips.iter().find_map(|a| match a.ip() {
            IpAddr::V4(v) => Some(v),
            IpAddr::V6(_) => None,
        })
    };
    let public4 = v4(&public);
    let psel = match osd::portsel::PortSelect::from_config(
        arg(&a, "--port-base").as_deref(),
        &local_config,
    )
    .and_then(|p| p.with_addr_ports(public.ips[0].port(), cluster.ips[0].port()))
    {
        Ok(p) => p,
        Err(e) => return die(2, e),
    };
    let mut kcfg = match knet_cfg(&a) {
        Ok(c) => c,
        Err(e) => return die(2, e),
    };
    let idle = match idle_of(&a) {
        Ok(i) => i,
        Err(e) => return die(2, e),
    };
    let mask = rt::affinity_cpus();
    // the SPDK PCI claim BEFORE the SPDK env maps the NVMe (adr 0103, crate::pcilock; see prod.rs)
    #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
    if let Some(spec) = &dev
        && let Err(e) =
            nvme::any::DevSpec::parse(spec).and_then(|s| nvme::any::AnyCtrl::claim_before_env(&s))
    {
        return die(
            if e.contains("in use") { 3 } else { 2 },
            format!("--dev {spec}: {e}"),
        );
    }
    // SPDK owns the NVMe through its own env (hugepages for DMA); the network needs none (adr 0053)
    let spdk_addr = dev
        .as_deref()
        .and_then(|d| d.strip_prefix("spdk:"))
        .map(|r| r.split(',').next().unwrap_or("").to_owned());
    #[cfg(feature = "spdk")]
    if spdk_addr.is_some() {
        if let Some(h) = arg(&a, "--huge-dir") {
            // SAFETY: still single threaded; read by the SPDK env init below.
            unsafe { std::env::set_var("NVS_HUGE_DIR", h) };
        }
        let mem: i32 = arg(&a, "--mem")
            .and_then(|m| m.parse().ok())
            .unwrap_or(2048);
        let spec = match nvme::any::DevSpec::parse(dev.as_deref().unwrap_or("")) {
            Ok(s) => s,
            Err(e) => return die(2, e),
        };
        // shared controller (adr 0463): own main lcore per process (DPDK per-lcore state lives in shared memory)
        let main_lcore = spec.is_shared().then(|| {
            let first = arg(&a, "--lcore").unwrap_or_else(|| mask[0].to_string());
            format!("[{first}]")
        });
        if let Err(e) = spec.spdk_env_init("croit-flashstore-osd", main_lcore.as_deref(), mem) {
            return die(1, e);
        }
        // default on (adr 0061 am. 5): payloads in the SPDK env's hugepages, so the store writes them by reference instead
        // of copying them into DMA buffers (the kernel recv lands in them like in heap memory)
        #[cfg(feature = "spdk")]
        enable_payload_hugepages(mem.max(0) as usize, true);
    }
    // kernel NVMe backend (adr 0400): no SPDK env, so no hugepage heap either: the 4 MiB read reply and the write rx
    // buffers were 4 KiB heap pages (per-page pinning and skb frags in the zero-copy send, page faults). A memory-only EAL
    // (no PCI, no extra threads: lcore 0 may run on the whole affinity mask) gives the payload allocator its hugepages.
    #[cfg(all(feature = "spdk", feature = "kernel-nvme"))]
    if dev.as_deref().is_some_and(|d| d.starts_with("kernel:")) {
        let mem: usize = arg(&a, "--mem")
            .and_then(|m| m.parse().ok())
            .unwrap_or(2048);
        let cpus: Vec<String> = mask.iter().map(usize::to_string).collect();
        let lcores = format!("0@({})", cpus.join(","));
        let heap_args = crate::ealargs::kernel_heap(
            &lcores,
            &mem.to_string(),
            arg(&a, "--huge-dir").as_deref(),
        );
        let heap_refs: Vec<&str> = heap_args.iter().map(String::as_str).collect();
        if let Err(e) = eal_heap::eal_init(&heap_refs) {
            return die(1, format!("payload hugepage EAL: {e:?}"));
        }
        enable_payload_hugepages(mem, false);
    }
    #[cfg(not(feature = "spdk"))]
    if spdk_addr.is_some() {
        return die(2, "--dev spdk: needs a build with --features spdk");
    }
    rt::init_clock();

    // ---- device + cores
    #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
    let ctrl = match &dev {
        Some(spec) => match nvme::any::DevSpec::parse(spec)
            .and_then(|s| nvme::any::AnyCtrl::open_exclusive(&s).map(|c| (c, s.is_dev_only())))
        {
            Ok(c) => Some(c),
            Err(e) => return die(1, format!("--dev {spec}: {e}")),
        },
        None => None,
    };
    #[cfg(feature = "kernel-nvme")]
    if let Some((nvme::any::AnyCtrl::Kernel(k), _)) = &ctrl {
        let g = k.geometry();
        println!(
            "croit-flashstore-osd: store backend kernel ({}) {} nsid {} vwc={} max_xfer={} KiB tags={} missing=[{}] (adr 0169)",
            k.mode().name(),
            k.path().display(),
            k.nsid(),
            g.vwc,
            u64::from(g.max_xfer_lbas) * u64::from(g.lba_size) / 1024,
            k.tags(),
            k.missing().join(",")
        );
    }
    // SMART refresh thread, joined when this function returns (before `exit` runs SPDK's env teardown, devmeta doc)
    #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
    let _smart = ctrl.as_ref().and_then(|(c, _)| {
        crate::devmeta::start(
            c.health_probe()?,
            nvme_pci.clone().unwrap_or_default(),
            c.geometry().capacity_bytes(),
        )
    });
    #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
    let shards: Option<u32> = match &ctrl {
        Some((c, _)) => {
            match osd::nvmestore::device_shards(c, dev.as_deref().unwrap_or_default()) {
                Ok(s) => Some(s),
                Err((c, e)) => return die(c, e),
            }
        }
        None => None,
    };
    #[cfg(not(any(feature = "lab", feature = "spdk", feature = "kernel-nvme")))]
    let shards: Option<u32> = None;
    // adr 0160: cores != store shards runs (a core owns at least one shard: extra cores stay unused), with a warning
    let cores = match crate::args::cores(&a, mask.len(), shards, data_dir.is_some()) {
        Ok(c) => c,
        Err(e) => return die(2, e),
    };
    if cores > 1 && data_dir.is_some() {
        return die(
            2,
            "--cores > 1 needs --dev (the legacy --data mode is single core)",
        );
    }
    // data NICs (public + cluster, every family; a bond / VLAN resolves to its physical NICs): their queue IRQs are kept
    // off the OSD cores
    let ifaces: Vec<String> = dedup_ifaces(
        public
            .ips
            .iter()
            .chain(cluster.ips.iter())
            .filter_map(|a| netaddr::iface_of(a.ip())),
    );
    let (cpus, place_desc) =
        match crate::args::choose_cpus(&a, &mask, cores, nvme_pci.as_deref(), &ifaces) {
            Ok(x) => x,
            Err(e) => return die(2, e),
        };
    crate::args::warn_host_net(&ifaces);
    let steer = match arg(&a, "--steer").as_deref() {
        None | Some("hash") => Steer::Hash,
        Some("cpu") => Steer::Cpu(cpus.clone()),
        Some(o) => return die(2, format!("bad --steer {o:?} (hash|cpu)")),
    };
    // client connections go to the least loaded core instead of wherever the kernel's 4-tuple hash put them (oq 11);
    // with `--steer cpu` flows follow the NIC queue's core on purpose
    let balance = match arg(&a, "--knet-balance").as_deref() {
        None | Some("on") => cores > 1 && matches!(steer, Steer::Hash),
        Some("off") => false,
        Some(o) => return die(2, format!("bad --knet-balance {o:?} (on|off)")),
    };
    println!(
        "croit-flashstore-osd: kernel tier, {cores} core(s) on cpus {cpus:?} ({place_desc}), public {} cluster {} ports {} balance={balance}",
        addrs_text(&public.ips),
        addrs_text(&cluster.ips),
        psel.describe()
    );

    // ---- sockets (before the OSD starts: no free port is a clean startup error)
    let (port_steer, peer_cores) = match peer_steer(&a, cores, &steer) {
        Ok(v) => v,
        Err(e) => return die(2, e),
    };
    kcfg.peer_cores = peer_cores;
    // default on (rented host matrix 2026-10-12: with deep idle the OSD cpu fell to BlueStore level or below on 4M, -25 % on
    // 4k random read); kill switch `--knet-wake off` (back to spin + 50 us capped sleeps)
    let wake = match arg(&a, "--knet-wake").as_deref() {
        None | Some("on") => true,
        Some("off") => false,
        Some(o) => return die(2, format!("bad --knet-wake {o:?} (on|off)")),
    };
    // RDMA upgrade (conf `flashstore_rdma`, adr 0469-rdma-transport): the devices of our own two addresses carry it; `main`
    // already refused it for other tiers and for a build without feature rdma
    let rdma = match crate::args::rdma_enabled(&a) {
        Ok(v) => v,
        Err(e) => return die(2, e),
    };
    // the fabric of the RoCE class (PFC, recorded drops without ECN marks): reported once, never changed (0470-rdma-ops)
    #[cfg(feature = "rdma")]
    if rdma {
        for w in hwcheck::rdma_startup_warnings(&ifaces, hwcheck::RDMA_DEFAULT_TOS) {
            eprintln!("croit-flashstore-osd: WARNING host: {w}");
        }
    }
    // pinned RDMA buffers: their own budget on top of `osd_memory_target` (flashstore_rdma_memory)
    #[cfg(feature = "rdma")]
    let rdma_addrs: RdmaAddrs = match (
        rdma,
        crate::args::rdma_memory(&a),
        crate::args::rdma_max_sessions(&a),
    ) {
        (_, Err(e), _) | (_, _, Err(e)) => return die(2, e),
        (false, ..) => None,
        (true, Ok(memory), Ok(max_sessions)) => {
            // RoCEv2 rides on IPv4 sessions (adr 0659-ip-address-families)
            let (Some(p), Some(c)) = (public4, v4(&cluster)) else {
                return die(
                    2,
                    "flashstore_rdma needs an IPv4 public and cluster address (RoCEv2 sessions over IPv6 are not \
                     implemented)",
                );
            };
            Some(RdmaCfg {
                addrs: [p, c],
                memory,
                max_sessions,
                kernel_store: matches!(&ctrl, Some((nvme::any::AnyCtrl::Kernel(_), _))),
                source_pull,
            })
        }
    };
    // source-pull READ arenas are pinned for the process lifetime: charged against `osd_memory_target` (adr 0175)
    // before the stores size their caches; a target that cannot hold them refuses the start
    #[cfg(feature = "rdma")]
    if let Some(c) = rdma_addrs.filter(|c| c.source_pull) {
        match osd::nvmestore::charge_pinned(
            rt::knet::RDMA_PULL_ARENA * cores as u64 * c.devices(),
            "flashstore_rdma_source_pull",
        ) {
            Ok(line) => eprintln!("croit-flashstore-osd: {line}"),
            Err(e) => return die(2, e),
        }
    }
    let lopts = rt::knet::ListenOpts {
        port_steer,
        sockbuf: kcfg.sockbuf,
    };
    // the address ports, else the first free ports of ms_bind_port_min..max (or the explicit --port-base ones); the bound
    // ones go into MOSDBoot. One port per listener kind, shared by its address families (spec 3.1: one socket per
    // addrvec entry).
    let kinds: [&[SocketAddr]; 4] = [&public.ips, &cluster.ips, &public.ips, &cluster.ips];
    let (ports, fds) = match osd::portsel::bind_with(&psel, kinds, |p| {
        let binds = Binds(std::array::from_fn(|i| {
            kinds[i]
                .iter()
                .map(|a| SocketAddr::new(a.ip(), p[i]))
                .collect()
        }));
        rt::knet::bind_all_with(&binds, cores, &steer, 512, &lopts)
    }) {
        Ok(v) => v,
        Err(e) => return die(1, e),
    };
    let at = |ips: &[SocketAddr], port: u16| -> String {
        ips.iter()
            .map(|a| SocketAddr::new(a.ip(), port).to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    println!(
        "croit-flashstore-osd: listeners public {} cluster {} hb front {} hb back {}",
        at(&public.ips, ports[0]),
        at(&cluster.ips, ports[1]),
        at(&public.ips, ports[2]),
        at(&cluster.ips, ports[3])
    );
    // zcrx (io_uring zero-copy receive) is IPv4 only: a v6 public address skips it with a loud note (the kernel listeners serve)
    let zplan = match public4 {
        Some(p) => match zcrx_plan(&a, p, ports[0], cores) {
            Ok(p) => p,
            Err(e) => return die(2, e),
        },
        None => {
            eprintln!(
                "croit-flashstore-osd: zcrx off (public address {} is IPv6; zcrx is IPv4 only)",
                public.ips[0].ip()
            );
            std::sync::Arc::new(ZPlan::default_off(ports[0]))
        }
    };

    // ---- osd
    let boot = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let rnd = rt::os_random();
    let hostname = arg(&a, "--hostname").unwrap_or_else(osd::sysinfo::short_hostname);
    let mut sys_metadata = osd::sysinfo::collect();
    sys_metadata.insert(
        "front_iface".into(),
        netaddr::iface_of(public.ips[0].ip()).unwrap_or_default(),
    );
    sys_metadata.insert(
        "back_iface".into(),
        netaddr::iface_of(cluster.ips[0].ip()).unwrap_or_default(),
    );
    sys_metadata.insert(
        "flashstore_placement".into(),
        format!("cpus={cpus:?} {place_desc}"),
    );
    #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
    if let Some(s) = dev
        .as_deref()
        .and_then(|d| nvme::any::DevSpec::parse(d).ok())
    {
        sys_metadata.insert("flashstore_store_backend".into(), s.backend_name().into());
    }
    let ocfg = OsdConfig {
        hostname,
        public_ips: public.ips.iter().map(SocketAddr::ip).collect(),
        cluster_ips: cluster.ips.iter().map(SocketAddr::ip).collect(),
        public_port: ports[0],
        cluster_port: ports[1],
        hb_front_port: ports[2],
        hb_back_port: ports[3],
        mon_host: mons,
        wall_origin_unix: boot.as_secs(),
        wall_from_clock: true,
        seed: u64::from_le_bytes(rnd[24..32].try_into().expect("8 bytes")),
        nonce: osd::sysinfo::fresh_nonce(),
        sys_metadata,
        local_config,
        local_sources,
        data_path: data,
        rdma,
        placement,
        source_pull,
    };
    crate::sdnotify::start_liveness();
    #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
    if cores > 1 {
        let Some((ctrl, _)) = ctrl else {
            return die(2, "--cores > 1 needs --dev");
        };
        return multi(
            ocfg,
            ctrl,
            cores,
            fds,
            kcfg,
            idle,
            cpus,
            shards.unwrap_or(1),
            balance,
            wake,
            zplan,
            #[cfg(feature = "rdma")]
            rdma_addrs,
        );
    }
    let Some(fds) = fds.into_iter().next() else {
        return die(1, "no listeners");
    };
    #[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
    if let Some(spec) = &dev {
        let Some((c, dev_only)) = &ctrl else {
            return die(2, "internal: no controller");
        };
        return match osd::nvmestore::open_dev_ctrl(c, *dev_only) {
            Ok((p, r)) => {
                println!("croit-flashstore-osd: {r}");
                #[cfg(feature = "spdk")]
                if c.is_spdk()
                    && let Err(e) = store_dma_budget(c, shards.unwrap_or(1), 1)
                {
                    return die(1, e);
                }
                match Osd::<osd::Nvme<nvme::any::AnyDev, store::dev::MonoClock>>::with_pg_store(
                    ocfg, p.meta, p.pgs,
                ) {
                    Ok(o) => run_single(
                        o,
                        fds,
                        kcfg,
                        idle,
                        cpus[0],
                        zplan,
                        #[cfg(feature = "rdma")]
                        rdma_addrs,
                    ),
                    Err(e) => die(1, e),
                }
            }
            Err(e) => die(1, format!("--dev {spec}: {e}")),
        };
    }
    #[cfg(feature = "lab")]
    if let Some(data_dir) = data_dir {
        return match osd::FileMetaStore::open(&data_dir, osd::FileMetaStore::DEFAULT_SIZE) {
            Ok(s) => match Osd::new(ocfg, s) {
                Ok(o) => run_single(
                    o,
                    fds,
                    kcfg,
                    idle,
                    cpus[0],
                    zplan,
                    #[cfg(feature = "rdma")]
                    rdma_addrs,
                ),
                Err(e) => die(1, e),
            },
            Err(e) => die(1, e),
        };
    }
    // no store: `--data` is missing (lab builds) or no `--dev` was given
    #[cfg(feature = "lab")]
    return die(2, "pass --dev or --data DIR");
    #[cfg(not(feature = "lab"))]
    die(2, "no store: pass --dev spdk:PCI")
}

/// SIGINT / SIGTERM set the stop flag and ring `wake` (the core that reads the flag: a sleeping core sees it at once,
/// whichever thread the signal hit).
fn stop_on_signals(wake: Option<Arc<rt::wake::Wake>>) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    for s in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        let (stop, wake) = (stop.clone(), wake.clone());
        // SAFETY: the handler stores an atomic and writes an eventfd (`Wake::ring`), both async-signal-safe.
        let _ = unsafe {
            signal_hook::low_level::register(s, move || {
                stop.store(true, std::sync::atomic::Ordering::SeqCst);
                if let Some(w) = &wake {
                    w.ring();
                }
            })
        };
    }
    stop
}

fn stats_line(core: &KCore) -> String {
    // device ring of this core (`kernel:` devices, adr 0169): submit syscalls / SQEs
    #[cfg(feature = "kernel-nvme")]
    let (ke, ks) = nvme::kdev::thread_stats();
    #[cfg(not(feature = "kernel-nvme"))]
    let (ke, ks) = (0u64, 0u64);
    format!(
        "knet: iters={} idle={} store_wait={} park={} hint_parks={} park_cut={} park_ms={} over_ms={} wake_us={} wake_late_us={} io_est_us={} busy_ms={} busy_max_us={} busy_hist={:?} phase_max_us={:?} long_by_phase={:?} kdev_enters={ke} kdev_sqes={ks} {}{}",
        core.iters,
        core.idle_iters,
        core.store_waits,
        core.io_parks,
        core.hint_parks,
        core.park_cut,
        core.park_ns / 1_000_000,
        core.park_over_ns / 1_000_000,
        core.wake_ns / 1000,
        core.wake_late_ns / 1000,
        core.io_est_ns / 1000,
        core.busy_ns / 1_000_000,
        core.busy_max_ns / 1000,
        core.busy_hist,
        core.phase_max_ns.map(|n| n / 1000),
        core.long_by_phase,
        core.net.describe(),
        core.net
            .zcrx_stats()
            .map_or(String::new(), |z| format!(" {}", z.line()))
    )
}

/// `--knet-zcrx auto|off|nodev` (adr 0464): default off until a bare-metal A/B validates the path; `auto` (opt-in) receives the public port's connections through io_uring
/// zero-copy receive where kernel, NIC and host steering offer it, else by copy; `nodev` (lab builds) is the device-less
/// functional test mode (every accepted connection through `RECV_ZC`, the kernel copies). Prints the one
/// startup line that names the outcome (refusals with their fix, stderr).
fn zcrx_plan(
    a: &[String],
    public: Ipv4Addr,
    port: u16,
    cores: usize,
) -> Result<Arc<ZPlan>, String> {
    let mut plan = match arg(a, "--knet-zcrx").as_deref() {
        None => ZPlan::default_off(port),
        Some("auto") => ZPlan::probe(public, port, true),
        Some("off") => ZPlan::probe(public, port, false),
        #[cfg(feature = "lab")]
        Some("nodev") => ZPlan::nodev(
            port,
            rt::knet::zcrx::rmem_max().map_err(|e| format!("net.ipv4.tcp_rmem: {e}"))?,
        ),
        #[cfg(not(feature = "lab"))]
        Some("nodev") => {
            return Err("--knet-zcrx nodev is a test mode of lab builds (feature lab)".into());
        }
        Some(o) => return Err(format!("bad --knet-zcrx {o:?} (auto|off|nodev)")),
    };
    // queue i belongs to core i: queues beyond the core count stay plain (their flows are received by copy)
    plan.queues.truncate(cores);
    match plan.off {
        None => println!("croit-flashstore-osd: {}", plan.line()),
        Some(rt::knet::zcrx::Reason::Disabled | rt::knet::zcrx::Reason::DefaultOff) => {
            println!("croit-flashstore-osd: {}", plan.line())
        }
        Some(_) => eprintln!("croit-flashstore-osd: {}", plan.line()),
    }
    Ok(Arc::new(plan))
}

/// Register core `id`'s zcrx queue; the text to print (its description, or why this core receives by copy).
fn zcrx_core(net: &mut KNet, plan: &Arc<ZPlan>, id: usize) -> Option<String> {
    if plan.off.is_some() {
        return None; // the startup line said it
    }
    Some(match net.set_zcrx(plan.clone(), id) {
        Ok(t) => t,
        Err(r) => format!(
            "WARNING zcrx core {id}: copy receive, reason={} fix: {}",
            r.as_str(),
            r.fix(&plan.iface, plan.port)
        ),
    })
}

fn run_single<B: osd::Backend>(
    mut osd: Osd<B>,
    fds: [Vec<OwnedFd>; 4],
    kcfg: KCfg,
    idle: Idle,
    cpu: usize,
    zplan: Arc<ZPlan>,
    #[cfg(feature = "rdma")] rdma: RdmaAddrs,
) -> i32 {
    rt::set_core_cpus(&[cpu]);
    let _obs = crate::obs::setup(&mut osd);
    let stop = stop_on_signals(None);
    if let Err(e) = rt::pin_current_thread(cpu) {
        eprintln!("croit-flashstore-osd: pin to cpu {cpu}: {e} (continuing)");
    }
    // declared before the core: the control threads outlive it
    #[cfg(feature = "rdma")]
    let (rdma_hub, mut rdma_planes) = match start_rdma(rdma, 1) {
        Ok(v) => v,
        Err(e) => return die(1, format!("rdma: {e}")),
    };
    #[cfg(feature = "rdma")]
    if let Some(h) = &rdma_hub {
        osd.note_rdma_setup(h.setup().clone());
    }
    let net = match KNet::new(kcfg, fds) {
        Ok(n) => n,
        Err(e) => {
            return die(1, format!("kernel TCP startup: {e}"));
        }
    };
    #[cfg(feature = "rdma")]
    let net = {
        let mut net = net;
        if let Some(r) = rdma_planes.pop().flatten() {
            net.set_rdma(r);
        }
        net
    };
    let mut net = net;
    if let Some(t) = zcrx_core(&mut net, &zplan, 0) {
        println!("croit-flashstore-osd: {t}");
    }
    let t0 = Instant::now();
    let mut core = KCore::new(net, idle, t0);
    osd.set_liveness(&osd::liveness::LIVENESS);
    println!("croit-flashstore-osd: {}", core.net.describe());
    let code = core.run_osd_x(&mut osd, None::<&mut XPort>, &stop, |l| {
        crate::sdnotify::on_log(&l.text);
        crate::obs::emit(t0, l);
    });
    println!("{}", stats_line(&core));
    code
}

/// RDMA settings: addresses whose devices carry the upgrade (public, cluster) and the pinned-memory budget of the process.
#[cfg(feature = "rdma")]
#[derive(Clone, Copy)]
struct RdmaCfg {
    addrs: [Ipv4Addr; 2],
    memory: u64,
    /// `flashstore_rdma_max_sessions` (0 = unlimited).
    max_sessions: u32,
    /// The store is on a `kernel:` device: its read buffers (sent by reference as read reply data) live in the kdev buffer
    /// arena, registered for zero-copy sends too.
    kernel_store: bool,
    /// `flashstore_rdma_source_pull`: advertise object write sources for the peer to READ.
    source_pull: bool,
}

#[cfg(feature = "rdma")]
impl RdmaCfg {
    /// RDMA devices: one when public and cluster share the address.
    fn devices(&self) -> u64 {
        if self.addrs[0] == self.addrs[1] { 1 } else { 2 }
    }
}

/// Ranges of the payload hugepage heap an RDMA device registers for zero-copy sends (empty: no heap in this process).
#[cfg(all(feature = "rdma", feature = "spdk"))]
fn payload_heap() -> Vec<(u64, u64)> {
    if eal_heap::huge_alloc_enabled() {
        eal_heap::pinned_ranges()
    } else {
        Vec::new()
    }
}

/// A build without feature spdk has no hugepage heap: payloads live in ordinary heap memory.
#[cfg(all(feature = "rdma", not(feature = "spdk")))]
fn payload_heap() -> Vec<(u64, u64)> {
    Vec::new()
}

/// `None` = RDMA off.
#[cfg(feature = "rdma")]
type RdmaAddrs = Option<RdmaCfg>;

/// RDMA devices, verbs cores and control threads for `cores` cores (nothing when off); the hub must outlive every core. The
/// arenas are sized from the RDMA share of the memory envelope; startup fails (with the fix) when the share cannot hold the
/// minimum or the memlock limit does not cover it.
#[cfg(feature = "rdma")]
fn start_rdma(
    addrs: RdmaAddrs,
    cores: usize,
) -> Result<(Option<rt::knet::RdmaHub>, Vec<Option<rt::knet::KRdma>>), String> {
    match addrs {
        Some(c) => {
            // large chunks in the payload heap go zero copy; without a heap (build without feature spdk,
            // NV_HUGE_ALLOC=0, or no kernel:/spdk: store) every byte takes the copy path
            let mut heap = payload_heap();
            // read replies carry store read buffers by reference: on the kernel tier they live in the kdev arena
            if c.kernel_store {
                heap.extend(nvme::kdev::arena_range());
            }
            if heap.is_empty() {
                eprintln!(
                    "croit-flashstore-osd: rdma: no payload hugepage heap in this process: every byte is copied into the send arena"
                );
            }
            // the heap (and the kdev arena) is memory the process already holds; every device's registration of it counts
            // against the memlock limit once more
            let devices = c.devices();
            let heap_bytes: u64 = heap.iter().map(|r| r.1).sum::<u64>() * devices;
            // source-pull: one READ destination arena per core and device, registered at start (charged against
            // `osd_memory_target` in `main_with`)
            let pull_bytes = if c.source_pull {
                rt::knet::RDMA_PULL_ARENA * cores as u64 * devices
            } else {
                0
            };
            osddir::memlock_covers(c.memory + heap_bytes + pull_bytes)?;
            let zc = (!heap.is_empty()).then_some(heap.as_slice());
            // SAFETY: the EAL payload heap and kernel DMA arena retain their mappings for the process lifetime;
            // immutable Bytes leases retain each source until its SENDs retire or the QP is destroyed.
            let (hub, planes) = unsafe {
                rt::knet::rdma_start(&c.addrs, cores, c.memory, c.max_sessions, zc, c.source_pull)?
            };
            Ok((Some(hub), planes))
        }
        None => Ok((None, (0..cores).map(|_| None).collect())),
    }
}

// ---- several cores (adr 0031): one thread per core, each with its io_uring and listeners
#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
struct KInit {
    fds: [Vec<OwnedFd>; 4],
    queues: Vec<nvme::any::AnyDev>,
    place: Option<KPlace>,
    spread: Option<KSpread>,
    #[cfg(feature = "rdma")]
    rdma: Option<rt::knet::KRdma>,
    /// Session limit and unusable devices, for the OSD's cluster-log warnings and `rdma status`.
    #[cfg(feature = "rdma")]
    rdma_setup: rt::knet::RdmaSetup,
}

#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
struct Shared {
    b: Boot,
    kcfg: KCfg,
    wakes: Option<Arc<[Arc<rt::wake::Wake>]>>,
    idle: Idle,
    inits: std::sync::Mutex<Vec<Option<KInit>>>,
    sig: Arc<AtomicBool>,
    zplan: Arc<ZPlan>,
}

#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
#[expect(clippy::too_many_arguments)]
fn multi(
    ocfg: OsdConfig,
    ctrl: nvme::any::AnyCtrl,
    cores: usize,
    fds: Vec<[Vec<OwnedFd>; 4]>,
    kcfg: KCfg,
    idle: Idle,
    cpus: Vec<usize>,
    shards: u32,
    balance: bool,
    wake: bool,
    zplan: Arc<ZPlan>,
    #[cfg(feature = "rdma")] rdma: RdmaAddrs,
) -> i32 {
    if let Err(e) = osd::CoreSpec::new(0, cores, cores, shards) {
        return fail(e);
    }
    let mut places: Vec<Option<KPlace>> = if balance {
        KPlace::group_on(cores, cpus.clone())
            .into_iter()
            .map(Some)
            .collect()
    } else {
        (0..cores).map(|_| None).collect()
    };
    let wakes = if wake {
        let v: Result<Vec<_>, _> = (0..cores).map(|_| rt::wake::Wake::new()).collect();
        match v {
            Ok(v) => Some(Arc::<[_]>::from(v)),
            Err(e) => return fail(format!("eventfd: {e}")),
        }
    } else {
        None
    };
    // receive spread (adr 0053 am. 3): segment rests received by the other cores (`spread_min` > 0); send spread
    // (am. 12): copied send batches larger than one piece go to the core with the fewest send jobs
    let mut spreads: Vec<Option<KSpread>> = if cores > 1 {
        rt::knet::spread_mesh(cores, wakes.clone())
            .into_iter()
            .map(Some)
            .collect()
    } else {
        (0..cores).map(|_| None).collect()
    };
    // every check that reads the device comes first: a store that cannot be identified (superblock, format) ends the start
    // before the RDMA devices, their pinned memory and the control threads exist
    let mut all_queues = Vec::with_capacity(cores);
    for c in 0..cores {
        match osd::nvmestore::core_queues(&ctrl, shards, c, cores) {
            Ok(q) => all_queues.push(q),
            Err(e) => return fail(e),
        }
    }
    #[cfg(feature = "spdk")]
    if ctrl.is_spdk()
        && let Err(e) = store_dma_budget(&ctrl, shards, cores)
    {
        return fail(e);
    }
    // declared before the cores start, dropped after they ended (control threads outlive every verbs core)
    #[cfg(feature = "rdma")]
    let (rdma_hub, mut rdma_planes) = match start_rdma(rdma, cores) {
        Ok(v) => v,
        Err(e) => return fail(format!("rdma: {e}")),
    };
    let mut inits = Vec::new();
    for (c, (f, queues)) in fds.into_iter().zip(all_queues).enumerate() {
        inits.push(Some(KInit {
            fds: f,
            queues,
            place: places[c].take(),
            spread: spreads[c].take(),
            #[cfg(feature = "rdma")]
            rdma: rdma_planes[c].take(),
            #[cfg(feature = "rdma")]
            rdma_setup: rdma_hub
                .as_ref()
                .map(|h| h.setup().clone())
                .unwrap_or_default(),
        }));
    }
    let sig = stop_on_signals(wakes.as_ref().map(|w| w[0].clone()));
    let sh = Arc::new(Shared {
        wakes,
        b: Boot {
            ocfg,
            cores,
            cpus: cpus.clone(),
            nets: cores,
            shards,
            ingress: osd::input_credits(shards),
            boot: std::sync::OnceLock::new(),
            t0: Instant::now(),
        },
        kcfg,
        idle,
        inits: std::sync::Mutex::new(inits),
        sig,
        zplan,
    });
    let sh2 = sh.clone();
    let running = rt::multi::spawn_osd_cores(cores, &cpus, 4096, shards as usize, move |cx| {
        let (id, stop) = (cx.id, cx.stop.clone());
        let r = core_run(&sh2, cx);
        core_end(id, r, &sh2.b.boot, &sh2.sig, &stop, sh2.wakes.as_deref())
    });
    let codes = running.join();
    #[cfg(feature = "rdma")]
    drop(rdma_hub);
    drop(ctrl);
    exit_code(&codes)
}

#[cfg(any(feature = "lab", feature = "spdk", feature = "kernel-nvme"))]
fn core_run(sh: &Shared, cx: rt::multi::CoreCtx<osd::XMsg>) -> Result<i32, String> {
    let id = cx.id;
    let init = sh.inits.lock().map_err(|_| "poisoned")?[id]
        .take()
        .ok_or("core init taken twice")?;
    let t0 = sh.b.t0;
    let (mut osd, _obs): (Osd<Be>, _) = build_osd(&sh.b, id, init.queues, &cx.stop)?;
    let stop = if id == 0 {
        sh.sig.clone()
    } else {
        cx.stop.clone()
    };
    let mut net =
        KNet::new(sh.kcfg.clone(), init.fds).map_err(|e| format!("kernel TCP startup: {e}"))?;
    if let Some(p) = init.place {
        net.set_place(p);
    }
    if let Some(s) = init.spread {
        net.set_spread(s);
    }
    if let Some(w) = &sh.wakes {
        net.set_wake(w[id].clone());
        osd.set_core_waker(w[id].clone());
    }
    #[cfg(feature = "rdma")]
    if let Some(r) = init.rdma {
        net.set_rdma(r);
    }
    #[cfg(feature = "rdma")]
    osd.note_rdma_setup(init.rdma_setup);
    if let Some(t) = zcrx_core(&mut net, &sh.zplan, id) {
        say(id, &t);
    }
    if id == 0 {
        say(id, &net.describe());
    }
    let mut core = KCore::new(net, sh.idle, t0);
    let mut xport = XPort::new(cx.ep);
    if let Some(w) = &sh.wakes {
        xport.set_wake(w.clone());
    }
    let code = core.run_osd_x(&mut osd, Some(&mut xport), &stop, |l| {
        crate::sdnotify::on_log(&l.text);
        crate::obs::emit(t0, l);
    });
    say(id, &stats_line(&core));
    say(id, &format!("xport_stalls={}", xport.stalls));
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_owned()).collect()
    }
    /// Local addresses in interface order (the pick keeps the first match).
    fn host(list: &[(&str, &str)]) -> Vec<netaddr::IfAddr> {
        list.iter()
            .map(|(iface, ip)| netaddr::IfAddr {
                iface: (*iface).to_owned(),
                ip: ip.parse().unwrap(),
                prefix: 24,
            })
            .collect()
    }

    fn v4only() -> netaddr::Families {
        netaddr::Families {
            v4: true,
            v6: false,
            prefer_v4: false,
        }
    }

    fn dual(prefer_v4: bool) -> netaddr::Families {
        netaddr::Families {
            v4: true,
            v6: true,
            prefer_v4,
        }
    }

    fn plain(
        a: &[String],
        lc: &[(String, String)],
        addrs: &[netaddr::IfAddr],
    ) -> (RoleAddrs, RoleAddrs) {
        resolve_addrs(a, lc, v4only(), addrs, || None).unwrap()
    }

    fn n(rs: &RoleAddrs) -> Vec<String> {
        rs.ips.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn network_options_use_the_last_normalized_setting() {
        let lc = osd::config::local_config([
            "public_addr=10.0.0.5",
            "public-addr=192.168.1.7",
            "ms_bind_ipv6=false",
            "ms bind ipv6=true",
        ]);
        let (p, c) = plain(&v(&[]), &lc, &host(&[]));
        assert_eq!(n(&p), ["192.168.1.7:0"]);
        assert_eq!(n(&c), ["192.168.1.7:0"]);
        assert!(families(&lc).unwrap().v6);
    }

    #[test]
    fn explicit_flags_win_then_conf_then_networks_then_ip_then_route() {
        let addrs = host(&[
            ("eth0", "172.17.0.1"),
            ("eth0", "10.0.0.5"),
            ("eth1", "192.168.1.7"),
        ]);
        let lc = vec![("public_network".to_owned(), "10.0.0.0/24".to_owned())];
        // network list picks the local address inside; cluster falls back to the public addresses
        let (p, c) = plain(&v(&[]), &lc, &addrs);
        assert_eq!(n(&p), ["10.0.0.5:0"]);
        assert_eq!(n(&c), ["10.0.0.5:0"]);
        // cluster network separate
        let lc2 = vec![
            ("public_network".to_owned(), "10.0.0.0/24".to_owned()),
            ("cluster_network".to_owned(), "192.168.1.0/24".to_owned()),
        ];
        let (p, c) = plain(&v(&[]), &lc2, &addrs);
        assert_eq!(
            (n(&p), n(&c)),
            (
                vec!["10.0.0.5:0".to_string()],
                vec!["192.168.1.7:0".to_string()]
            )
        );
        // flag beats conf; --ip is the alias for both when nothing else says
        let (p, _) = plain(&v(&["--public-addr", "1.2.3.4"]), &lc2, &addrs);
        assert_eq!(n(&p), ["1.2.3.4:0"]);
        let (p, c) = plain(&v(&["--ip", "9.9.9.9/24"]), &[], &addrs);
        assert_eq!(
            (n(&p), n(&c)),
            (vec!["9.9.9.9:0".to_string()], vec!["9.9.9.9:0".to_string()])
        );
        // nothing: the route towards the mon
        let (p, c) = resolve_addrs(&v(&[]), &[], v4only(), &addrs, || {
            Some("10.0.0.5".parse().unwrap())
        })
        .unwrap();
        assert_eq!(
            (n(&p), n(&c)),
            (
                vec!["10.0.0.5:0".to_string()],
                vec!["10.0.0.5:0".to_string()]
            )
        );
        // an explicit public port is the public listener's only: the cluster side takes the address and searches a port
        let (p, c) = plain(&v(&["--public-addr", "10.0.0.5:6820"]), &[], &addrs);
        assert_eq!(
            (n(&p), n(&c)),
            (
                vec!["10.0.0.5:6820".to_string()],
                vec!["10.0.0.5:0".to_string()]
            )
        );
        // a network without a local address is an error, never a silent fallback
        let bad = vec![("public_network".to_owned(), "10.9.0.0/16".to_owned())];
        assert!(resolve_addrs(&v(&[]), &bad, v4only(), &addrs, || None).is_err());
        assert!(resolve_addrs(&v(&[]), &[], v4only(), &addrs, || None).is_err());
        // dual-stack networks with only IPv4 enabled: the v6 entry is not used (Ceph default ms_bind_ipv6=false)
        let ds = vec![(
            "public_network".to_owned(),
            "fd00:77::/64, 10.0.0.0/24".to_owned(),
        )];
        let (p, _) = plain(&v(&[]), &ds, &addrs);
        assert_eq!(n(&p), ["10.0.0.5:0"]);
        // a requested family without a network fails the whole pick (spec 2.2)
        let v6net = vec![("public_network".to_owned(), "fd00:77::/64".to_owned())];
        let e = resolve_addrs(&v(&[]), &v6net, v4only(), &addrs, || None).unwrap_err();
        assert!(e.contains("IPv4"), "{e}");
    }

    /// Spec 2.4: one address per enabled family, IPv6 first unless `ms_bind_prefer_ipv4`; the addrvec order is the
    /// vector order the OSD turns into `[v2:v6, v2:v4]`.
    #[test]
    fn dual_stack_picks_one_address_per_family_in_addrvec_order() {
        let addrs = host(&[
            ("eth0", "10.78.0.11"),
            ("eth0", "fd00:77::11"),
            ("eth0", "fd00:77::12"),
        ]);
        let lc = vec![(
            "public_network".to_owned(),
            "10.78.0.0/24, fd00:77::/64".to_owned(),
        )];
        let (p, c) = resolve_addrs(&v(&[]), &lc, dual(false), &addrs, || None).unwrap();
        assert_eq!(n(&p), ["[fd00:77::11]:0", "10.78.0.11:0"], "IPv6 first");
        assert_eq!(n(&c), n(&p), "cluster falls back to the public addresses");
        let (p, _) = resolve_addrs(&v(&[]), &lc, dual(true), &addrs, || None).unwrap();
        assert_eq!(
            n(&p),
            ["10.78.0.11:0", "[fd00:77::11]:0"],
            "ms_bind_prefer_ipv4"
        );
        // v6 only
        let v6 = netaddr::Families {
            v4: false,
            v6: true,
            prefer_v4: false,
        };
        let (p, _) = resolve_addrs(&v(&[]), &lc, v6, &addrs, || None).unwrap();
        assert_eq!(n(&p), ["[fd00:77::11]:0"]);
        // an explicit v4 address with both families enabled advertises its own family; the v6 network adds the other
        let lce = vec![
            ("public_addr".to_owned(), "10.78.0.11:6820".to_owned()),
            (
                "public_network".to_owned(),
                "10.78.0.0/24, fd00:77::/64".to_owned(),
            ),
        ];
        let (p, _) = resolve_addrs(&v(&[]), &lce, dual(false), &addrs, || None).unwrap();
        assert_eq!(
            n(&p),
            ["[fd00:77::11]:6820", "10.78.0.11:6820"],
            "addrvec order (IPv6 first), one port for the kind"
        );
        // an explicit address alone with both families enabled: no partial dual-stack, startup error (spec 2.2/8)
        let lcx = vec![("public_addr".to_owned(), "[fd00:77::12]:3300".to_owned())];
        let e = resolve_addrs(&v(&[]), &lcx, dual(false), &addrs, || None).unwrap_err();
        assert!(e.contains("one address only"), "{e}");
        // the same with only the matching family enabled advertises that family only
        let v6only = netaddr::Families {
            v4: false,
            v6: true,
            prefer_v4: false,
        };
        let (p, _) = resolve_addrs(&v(&[]), &lcx, v6only, &addrs, || None).unwrap();
        assert_eq!(n(&p), ["[fd00:77::12]:3300"]);
        // a fallback of one family cannot serve two (bind explicit addresses only)
        let e = resolve_addrs(&v(&[]), &[], dual(false), &addrs, || {
            Some("10.78.0.11".parse().unwrap())
        })
        .unwrap_err();
        assert!(e.contains("one address per family"), "{e}");
    }

    /// `*_network_interface` filters the pick; without the matching network it is fatal (spec 1).
    #[test]
    fn interface_filter_and_its_requirement() {
        let addrs = host(&[("bond0", "10.78.0.11"), ("bond1", "10.78.0.12")]);
        let lc = vec![
            ("public_network".to_owned(), "10.78.0.0/24".to_owned()),
            ("public_network_interface".to_owned(), "bond1".to_owned()),
        ];
        let (p, _) = plain(&v(&[]), &lc, &addrs);
        assert_eq!(n(&p), ["10.78.0.12:0"]);
        let bad = vec![("public_network_interface".to_owned(), "bond1".to_owned())];
        assert!(
            resolve_addrs(&v(&[]), &bad, v4only(), &addrs, || None)
                .unwrap_err()
                .contains("needs public_network")
        );
    }

    #[test]
    fn conf_addresses_in_entity_addr_form() {
        // the port of public_addr / cluster_addr reaches the port selection (review B6: it was dropped); the accepted
        // spellings of the values themselves are `addr::tests::accepted_spellings`
        let addrs = host(&[("eth0", "10.0.0.5"), ("eth1", "192.168.1.7")]);
        let lc = vec![
            ("public_addr".to_owned(), "v2:10.0.0.5:6820/0".to_owned()),
            ("cluster_addr".to_owned(), "192.168.1.7:6821".to_owned()),
        ];
        let (p, c) = plain(&v(&[]), &lc, &addrs);
        assert_eq!((p.ips[0].port(), c.ips[0].port()), (6820, 6821));
        let (p, _) = plain(&v(&["--public-addr", "10.0.0.5:6830"]), &lc, &addrs);
        assert_eq!(p.ips[0].port(), 6830, "the flag wins with its port");
    }

    #[test]
    fn knet_flags_validate() {
        assert_eq!(knet_cfg(&v(&["--knet-bufs", "1024"])).unwrap().bufs, 1024);
        assert!(knet_cfg(&v(&["--knet-bufs", "1000"])).is_err());
        assert_eq!(
            knet_cfg(&v(&["--knet-buf-kb", "16"])).unwrap().buf_size,
            16384
        );
        assert_eq!(
            knet_cfg(&v(&["--knet-zc-min", "32768"])).unwrap().zc_min,
            32768
        );
        assert!(knet_cfg(&v(&["--knet-zc-min", "x"])).is_err());
        assert_eq!(
            knet_cfg(&v(&[])).unwrap().zc_min,
            ZC_MIN,
            "zero copy on by default"
        );
        assert_eq!(
            knet_cfg(&v(&["--knet-zc-min", "0"])).unwrap().zc_min,
            0,
            "kill switch"
        );
        // out-of-range values are refused, never wrapped or silently clamped
        for (k, val) in [
            ("--knet-buf-kb", "5000000000"),
            ("--knet-buf-kb", "1"),
            ("--knet-sockbuf-kb", "5000000000"),
            ("--knet-store-park", "100"),
            ("--knet-store-irq-park", "101"),
        ] {
            let e = knet_cfg(&v(&[k, val])).unwrap_err();
            assert!(e.contains(k), "{k} {val}: {e}");
        }
        assert_eq!(
            knet_cfg(&v(&["--knet-store-park", "90"]))
                .unwrap()
                .store_park_pct,
            STORE_PARK_MAX
        );
        assert_eq!(
            knet_cfg(&v(&["--knet-send-chunk-kb", "4096"]))
                .unwrap()
                .send_chunk,
            4 << 20
        );
    }

    /// Public on eth0/eth1 plus cluster on eth0: one entry per NIC (NIC walk, WARN line and IRQ list stay single).
    #[test]
    fn iface_list_has_no_duplicates() {
        assert_eq!(
            dedup_ifaces(["eth0".to_owned(), "eth1".to_owned(), "eth0".to_owned()]),
            ["eth0", "eth1"]
        );
        assert!(dedup_ifaces(Vec::new()).is_empty());
    }

    #[test]
    fn peer_steer_defaults_kill_switch_and_peer_cores() {
        let cpu = Steer::Cpu(vec![0, 1]);
        // default: on with hash steering and > 1 core, off with cpu steering
        assert_eq!(peer_steer(&v(&[]), 8, &Steer::Hash), Ok((true, 8)));
        assert_eq!(peer_steer(&v(&[]), 8, &cpu), Ok((false, 0)));
        assert_eq!(
            peer_steer(&v(&["--knet-peer-steer", "on"]), 8, &cpu),
            Ok((true, 8))
        );
        // kill switch
        assert_eq!(
            peer_steer(&v(&["--knet-peer-steer", "off"]), 8, &Steer::Hash),
            Ok((false, 0))
        );
        // one core here: no listener program, dials still steer towards multi-core peers
        assert_eq!(peer_steer(&v(&[]), 1, &Steer::Hash), Ok((false, 0)));
        assert_eq!(
            peer_steer(&v(&["--knet-peer-cores", "8"]), 1, &Steer::Hash),
            Ok((false, 8))
        );
        // the listener modulus is always our core count, the dial modulus the peers'
        assert_eq!(
            peer_steer(&v(&["--knet-peer-cores", "6"]), 4, &Steer::Hash),
            Ok((true, 6))
        );
        assert_eq!(
            peer_steer(&v(&["--knet-peer-cores", "1"]), 4, &Steer::Hash),
            Ok((true, 0))
        );
        assert!(peer_steer(&v(&["--knet-peer-cores", "x"]), 4, &Steer::Hash).is_err());
        assert!(peer_steer(&v(&["--knet-peer-cores", "0"]), 4, &Steer::Hash).is_err());
        assert!(peer_steer(&v(&["--knet-peer-steer", "yes"]), 4, &Steer::Hash).is_err());
    }

    #[test]
    fn idle_forms() {
        let s = |x: &str| idle_of(&v(&["--idle", x]));
        assert!(matches!(idle_of(&v(&[])), Ok(Idle::Sleep)));
        assert!(matches!(s("spin"), Ok(Idle::Spin)));
        assert!(matches!(s("sleep"), Ok(Idle::Sleep)));
        // retired forms: a clear error, never silently ignored
        assert!(s("sleep:200").unwrap_err().contains("sleep:US:AFTER"));
        assert!(s("sleep:200:50").is_err());
        let e = idle_of(&v(&["--knet-deep-after", "5"])).unwrap_err();
        assert!(e.contains("--knet-deep-after was removed"), "{e}");
    }

    /// The floating/VIP guards name a /32 address inside the network and an additional address on the interface, and
    /// never the host's own subnet address; the cluster->public fallback is detected (no cluster source).
    #[test]
    fn vip_warnings_flag_floating_addresses_only() {
        let a = |x: &str, prefix: u8| netaddr::IfAddr {
            iface: "eth0".into(),
            ip: x.parse().unwrap(),
            prefix,
        };
        let role = |x: &str| RoleAddrs {
            ips: vec![SocketAddr::new(x.parse().unwrap(), 0)],
        };
        let addrs = vec![a("10.0.0.11", 24), a("10.0.0.99", 32), a("10.0.0.50", 24)];
        let w = vip_warnings("public", &role("10.0.0.99"), &addrs, Some("10.0.0.0/24"));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("/32") && w[0].contains("eth0"), "{}", w[0]);
        let w = vip_warnings("public", &role("10.0.0.50"), &addrs, Some("10.0.0.0/24"));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("additional address"), "{}", w[0]);
        // the host's own subnet address is never flagged
        assert!(vip_warnings("public", &role("10.0.0.11"), &addrs, Some("10.0.0.0/24")).is_empty());
        assert!(vip_warnings("public", &role("10.0.0.99"), &addrs, None).is_empty());

        // no cluster source -> fallback
        assert!(!cluster_configured(&v(&[]), &[]));
        assert!(cluster_configured(
            &v(&[]),
            &[("cluster_network".to_owned(), "10.1.0.0/24".to_owned())]
        ));
    }
}
