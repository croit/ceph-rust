// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! NVMe controllers: identity, driver, PLP (adr 0008), LBA formats, PCIe link, NUMA, in-use. All via sysfs; the kernel
//! Identify ioctl (read-only admin command, nvme::kprobe) only on a live host and only for kernel-bound devices.
//! Devices bound to vfio-pci/uio are never touched ("not probed (would require binding)").
use crate::conf::Conf;
use crate::fs::{Fs, fmt_cpulist};
use crate::{Check, Facts, Section, Status};

/// `(data_bytes, meta_bytes)` per LBA format and the active index, from an Identify Namespace page.
pub fn parse_lbafs(ns: &[u8]) -> Option<(Vec<(u32, u32)>, usize)> {
    // nlbaf (byte 25) + 1 formats of 4 bytes from byte 128; the spec allows at most 64
    let n = (usize::from(*ns.get(25)?) + 1).min(64);
    if ns.len() < 128 + 4 * n {
        return None;
    }
    let flbas = usize::from(ns[26]);
    let active = (flbas & 0xf) | (((flbas >> 5) & 3) << 4);
    let mut v = Vec::new();
    for i in 0..n {
        let o = 128 + 4 * i;
        let ms = u32::from(u16::from_le_bytes([ns[o], ns[o + 1]]));
        let lbads = u32::from(ns[o + 2]);
        v.push((
            if (9..=16).contains(&lbads) {
                1u32 << lbads
            } else {
                0
            },
            ms,
        ));
    }
    Some((v, active))
}

fn fmt_fmt((d, m): (u32, u32)) -> String {
    format!("{d}+{m}")
}

/// `(speed GT/s, width)` from sysfs strings (`16.0 GT/s PCIe`, `4`).
fn link(fs: &Fs, base: &str, which: &str) -> Option<(f64, u32)> {
    let s: f64 = fs
        .read(&format!("{base}/{which}_link_speed"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let w: u32 = fs
        .read(&format!("{base}/{which}_link_width"))?
        .parse()
        .ok()?;
    Some((s, w))
}

struct Ns {
    blk: String,
    nsid: u32,
}

fn namespaces(fs: &Fs, ctrl_dir: &str, ctrl: &str) -> Vec<Ns> {
    let mut out: Vec<Ns> = Vec::new();
    for e in fs.list(ctrl_dir) {
        let Some(rest) = e.strip_prefix(ctrl) else {
            continue;
        };
        let (Some('n' | 'c'), true) = (rest.chars().next(), rest.len() > 1) else {
            continue;
        };
        // multipath node nvme0c0n1 -> block nvme0n1
        let Some(i) = rest.find('n') else {
            continue;
        };
        let tail = &rest[i..];
        let nsid: u32 = tail[1..].parse().unwrap_or(0);
        let blk = format!("{ctrl}{tail}");
        if nsid > 0 && out.iter().all(|n| n.blk != blk) {
            out.push(Ns { blk, nsid });
        }
    }
    out
}

/// True when mount/swap device `d` is block device `dev` or one of its partitions (`/dev/nvme0n1p1` of `/dev/nvme0n1`;
/// a longer name such as `/dev/nvme0n10p1` belongs to another namespace).
fn is_dev(d: &str, dev: &str) -> bool {
    d == dev
        || d.strip_prefix(dev)
            .and_then(|r| r.strip_prefix('p'))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

fn in_use(fs: &Fs, blk: &str) -> Vec<String> {
    let mut u = Vec::new();
    let base = format!("sys/block/{blk}");
    for p in fs.list(&base).into_iter().filter(|p| p.starts_with(blk)) {
        u.push(format!("partition {p}"));
    }
    for h in fs.list(&format!("{base}/holders")) {
        u.push(format!("holder {h}"));
    }
    let dev = format!("/dev/{blk}");
    for l in fs.read("proc/mounts").unwrap_or_default().lines() {
        let mut w = l.split_whitespace();
        if let (Some(d), Some(m)) = (w.next(), w.next())
            && is_dev(d, &dev)
        {
            u.push(format!("mounted {m}"));
        }
    }
    for l in fs.read("proc/swaps").unwrap_or_default().lines().skip(1) {
        if l.split_whitespace().next().is_some_and(|d| is_dev(d, &dev)) {
            u.push("swap".into());
        }
    }
    u
}

pub fn section(fs: &Fs, cfg: &Conf, facts: &mut Facts) -> Section {
    let mut v = Vec::new();
    let mut bdfs: Vec<String> = fs
        .list("sys/bus/pci/devices")
        .into_iter()
        .filter(|d| {
            fs.read(&format!("sys/bus/pci/devices/{d}/class"))
                .is_some_and(|c| c.starts_with("0x0108"))
        })
        .collect();
    bdfs.sort();
    facts.nvme_total = bdfs.len();
    if bdfs.is_empty() {
        v.push(
            Check::new("nvme.present", "NVMe controllers")
                .val("none found (no PCI class 0x0108 device)")
                .why("the OSD store lives on a PLP NVMe namespace (adr 0008); no PCI NVMe visible (VM with virtio disks, macOS, or no sysfs)")
                .na(),
        );
        return Section {
            name: "NVMe",
            checks: v,
        };
    }
    for bdf in bdfs {
        let base = format!("sys/bus/pci/devices/{bdf}");
        let id = |s: &str| format!("nvme.{bdf}.{s}");
        let driver = fs
            .link_name(&format!("{base}/driver"))
            .unwrap_or_else(|| "unbound".into());
        let kernel = driver == "nvme";
        let userspace = matches!(driver.as_str(), "vfio-pci" | "uio_pci_generic" | "igb_uio");
        if kernel {
            facts.nvme_kernel += 1;
        }
        if userspace {
            facts.nvme_userspace += 1;
        }
        let ctrl = fs
            .list(&format!("{base}/nvme"))
            .into_iter()
            .find(|d| d.starts_with("nvme"));
        let cdir = ctrl.as_ref().map(|c| format!("{base}/nvme/{c}"));
        let nss = match (&ctrl, &cdir) {
            (Some(c), Some(d)) => namespaces(fs, d, c),
            _ => Vec::new(),
        };
        let none_probed = |id: String, t: &str, why: &str| {
            Check::new(id, t.to_string())
                .val("not probed (would require binding)")
                .why(why.to_string())
                .na()
        };
        let ident = cdir.as_ref().map(|d| {
            format!(
                "{} fw={} sn={} state={}",
                fs.read(&format!("{d}/model")).unwrap_or_default(),
                fs.read(&format!("{d}/firmware_rev")).unwrap_or_default(),
                fs.read(&format!("{d}/serial")).unwrap_or_default(),
                fs.read(&format!("{d}/state")).unwrap_or_default()
            )
        });
        let vendor = fs.read(&format!("{base}/vendor")).unwrap_or_default();
        let device = fs.read(&format!("{base}/device")).unwrap_or_default();
        v.push(match ident {
            Some(i) => Check::new(id("identity"), format!("{bdf} controller")).val(format!("{i}; {} namespace(s)", nss.len())).why("which drive this is (model/firmware decide PLP and LBA-format support)").ok(),
            None => Check::new(id("identity"), format!("{bdf} controller"))
                .val(format!("pci {vendor}:{device}; model/firmware not probed (would require binding; run the check before binding or on the kernel driver)"))
                .why("identity comes from Identify Controller which needs the kernel driver or an SPDK attach")
                .na(),
        });
        v.push(
            Check::new(id("driver"), format!("{bdf} driver"))
                .val(if driver == "unbound" { "unbound (no kernel driver; free to bind)".to_string() } else { driver.clone() })
                .why("SPDK needs vfio-pci (or uio_pci_generic in labs); a device on the kernel nvme driver is rebound by croit-flashstore-prep if unused")
                .ok(),
        );
        // PLP
        let wc_sys = nss
            .first()
            .and_then(|n| fs.read(&format!("sys/block/{}/queue/write_cache", n.blk)));
        let mut vwc: Option<bool> = None;
        let mut src = "sysfs queue/write_cache";
        let mut ns_page: Option<Vec<u8>> = None;
        #[cfg(unix)]
        if fs.live()
            && let Some(n) = nss.first()
        {
            let kp = nvme::kprobe::KernelProbe(format!("/dev/{}", n.blk).into());
            if let Ok(b) = kp.identify_ctrl_raw() {
                vwc = Some(b[525] & 1 == 1);
                src = "Identify Controller VWC";
            }
            ns_page = kp.identify_ns_raw(n.nsid).ok();
        }
        if vwc.is_none() {
            vwc = wc_sys.as_deref().map(|s| s == "write back");
        }
        let plp_why = "no volatile write cache = writes are durable when acked (PLP); a VWC drive needs FUA per write and loses acked data on power loss: mkfs refuses it (adr 0008)";
        v.push(match vwc {
            Some(false) => Check::new(id("plp"), format!("{bdf} power-loss protection")).val(format!("no volatile write cache ({src}); PLP heuristic OK")).why(plp_why).ok(),
            Some(true) => Check::new(id("plp"), format!("{bdf} power-loss protection"))
                .val(format!("volatile write cache present ({src}): no PLP"))
                .why(plp_why)
                .fail()
                .fix("use datacenter NVMe with PLP (VWC absent); lab only: croit-flashstore-tool mkfs --allow-vwc (FUA per write, durability not guaranteed)")
                .w(9),
            None => none_probed(id("plp"), &format!("{bdf} power-loss protection"), plp_why),
        });
        // LBA
        let lba_why = "the store uses 4096-byte blocks (4096+0); 512-byte namespaces must be reformatted (mkfs --format-lba4k); 4096+64 is an optional metadata format (adr 0027)";
        let active = nss
            .first()
            .and_then(|n| fs.num(&format!("sys/block/{}/queue/logical_block_size", n.blk)));
        let fmts = ns_page.as_deref().and_then(parse_lbafs);
        v.push(match (active, &fmts) {
            (None, None) => none_probed(id("lba"), &format!("{bdf} LBA formats"), lba_why),
            (act, f) => {
                let mut val = act.map(|a| format!("active {a}")).unwrap_or_default();
                let mut has4k = false;
                if let Some((list, ai)) = f {
                    let avail: Vec<String> = list.iter().enumerate().filter(|(_, x)| x.0 > 0).map(|(i, x)| format!("{}{}", fmt_fmt(*x), if i == *ai { "*" } else { "" })).collect();
                    has4k = list.iter().any(|x| x.0 == 4096 && x.1 == 0);
                    val = format!("{val} available {} (*=active); 4096+0 {}; 4096+64 {}", avail.join(" "), if has4k { "yes" } else { "no" }, if list.contains(&(4096, 64)) { "yes" } else { "no" });
                }
                let c = Check::new(id("lba"), format!("{bdf} LBA formats")).val(val).why(lba_why).w(3);
                if act == Some(4096) {
                    c.ok()
                } else if f.is_some() && !has4k {
                    c.warn().fix("this namespace offers no 4096-byte format: use a drive that does")
                } else {
                    c.warn().fix("croit-flashstore-tool mkfs --format-lba4k (Format NVM: DESTROYS all data of the namespace)")
                }
            }
        });
        // link
        let cur = link(fs, &base, "current");
        let max = link(fs, &base, "max");
        v.push(match (cur, max) {
            (Some(c), Some(m)) => {
                let val = format!("x{} @ {} GT/s (max x{} @ {} GT/s)", c.1, c.0, m.1, m.0);
                let c_ = Check::new(id("link"), format!("{bdf} PCIe link")).val(val).why("a downtrained link caps bandwidth/latency below the drive's rating (e.g. Gen5 x4 running Gen3 x2)").w(7);
                if c.0 < m.0 || c.1 < m.1 {
                    c_.warn().fix("reseat the drive, check cable/backplane/riser and the BIOS PCIe speed/bifurcation setting; some drives show a lower speed only while idle (re-check under load)")
                } else {
                    c_.ok()
                }
            }
            _ => Check::new(id("link"), format!("{bdf} PCIe link")).val("not available").why("link speed/width vs the drive's maximum").na(),
        });
        // NUMA
        let node = fs
            .read(&format!("{base}/numa_node"))
            .and_then(|s| s.parse::<i32>().ok());
        let mut c = Check::new(id("numa"), format!("{bdf} NUMA node")).why("an OSD should run its cores on the NUMA node of its NVMe and NIC: remote DMA/polling costs latency and memory bandwidth").w(5);
        c = match node {
            Some(n) if n >= 0 => {
                let cpus = facts
                    .cpu_numa
                    .iter()
                    .find(|(i, _)| *i == n as u32)
                    .map(|(_, c)| c.clone());
                let mut c = c
                    .val(format!(
                        "node {n}{}",
                        cpus.as_ref()
                            .map(|c| format!(" (cpus {})", fmt_cpulist(c)))
                            .unwrap_or_default()
                    ))
                    .ok();
                if let (Some(cpus), Some(o)) = (
                    &cpus,
                    cfg.osds
                        .iter()
                        .find(|o| o.pci().as_deref() == Some(bdf.as_str())),
                ) {
                    let off: Vec<u32> = o
                        .lcores
                        .iter()
                        .copied()
                        .filter(|l| !cpus.contains(l))
                        .collect();
                    if !off.is_empty() {
                        c = c.warn().fix(format!(
                            "{}: lcores {} are not on NUMA node {n}; set flashstore_lcores within {}",
                            o.name,
                            fmt_cpulist(&off),
                            fmt_cpulist(cpus)
                        ));
                    }
                }
                c
            }
            _ => c.val("unknown / single node").na(),
        };
        v.push(c);
        // in use
        let used: Vec<String> = nss
            .iter()
            .flat_map(|n| {
                in_use(fs, &n.blk)
                    .into_iter()
                    .map(move |u| format!("{}: {u}", n.blk))
            })
            .collect();
        let cfgd = cfg
            .osds
            .iter()
            .find(|o| o.pci().as_deref() == Some(bdf.as_str()));
        let c = Check::new(id("inuse"), format!("{bdf} in use")).why("a namespace with partitions, mounts, holders (md/LVM) or swap must not be given to croit-flashstore-osd (the prep unit refuses it)");
        v.push(if !kernel {
            none_probed(id("inuse"), &format!("{bdf} in use"), "usage is read from the kernel block device, which does not exist for a userspace-bound drive")
        } else if used.is_empty() {
            c.val(format!("free ({} namespace(s), no partitions/mounts/holders/swap)", nss.len())).ok()
        } else if let Some(o) = cfgd {
            c.val(format!("IN USE: {}", used.join("; "))).st(Status::Fail).fix(format!("{} is configured on this device: unmount/remove the users or pick another drive", o.name))
        } else {
            c.val(format!("in use, not a candidate: {}", used.join("; "))).ok()
        });
    }
    Section {
        name: "NVMe",
        checks: v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("hwcheck-nvme-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write(root: &Path, rel: &str, s: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }

    #[test]
    fn lbaf_parse() {
        let mut p = vec![0u8; 4096];
        p[25] = 2; // 3 formats
        p[26] = 1; // active = 1
        p[128 + 2] = 9; // 512+0
        p[128 + 4 + 2] = 12; // 4096+0
        p[128 + 8] = 64;
        p[128 + 8 + 2] = 12; // 4096+64
        let (l, a) = parse_lbafs(&p).unwrap();
        assert_eq!(l, vec![(512, 0), (4096, 0), (4096, 64)]);
        assert_eq!(a, 1);
        assert!(parse_lbafs(&p[..100]).is_none());
        // 64 formats need 128 + 4*64 bytes; a shorter page must not index past its end
        let mut short = vec![0u8; 192];
        short[25] = 63;
        assert!(parse_lbafs(&short).is_none());
        let mut full = vec![0u8; 128 + 4 * 64];
        full[25] = 63;
        full[128 + 4 * 63 + 2] = 12;
        assert_eq!(parse_lbafs(&full).unwrap().0.len(), 64);
    }

    /// A mount/swap device belongs to the namespace only when it is the namespace or one of its partitions: `nvme0n1`
    /// must not claim `/dev/nvme0n10p1` (that would report a free namespace IN USE, a FAIL for the deploy gate).
    #[test]
    fn in_use_matches_the_device_or_its_partition() {
        let r = root("inuse");
        write(
            &r,
            "proc/mounts",
            "/dev/nvme0n10p1 / ext4 rw 0 0\n/dev/nvme0n1p1 /boot ext4 rw 0 0\n",
        );
        write(
            &r,
            "proc/swaps",
            "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/nvme0n10p2                          partition\t1048572\t\t0\t\t-2\n",
        );
        let fs = Fs::new(&r);
        assert_eq!(in_use(&fs, "nvme0n1"), vec!["mounted /boot"]);
        assert_eq!(in_use(&fs, "nvme0n10"), vec!["mounted /", "swap"]);
        let _ = std::fs::remove_dir_all(&r);
    }
}
