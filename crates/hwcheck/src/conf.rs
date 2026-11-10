// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! OSD conf (`[global]` < `[osd]` < `[osd.N]`, same layering as `croit-flashstore-osd run`, adr 0034): core budget, hugepage need, devices.
use crate::fs::{Fs, fmt_cpulist, parse_cpulist};
use crate::{Check, Facts, Section};
use std::path::Path;

/// Default hugepage reservation per OSD (adr 0034).
pub const DEFAULT_HUGEPAGES_MB: u64 = 2048;
/// Recommended core budget per OSD (benchmarks, adr 0063).
pub const CORE_BUDGET: usize = 8;

#[derive(Clone, Debug, Default)]
pub struct OsdConf {
    pub name: String,
    pub lcores: Vec<u32>,
    /// Why `flashstore_lcores` is not a usable CPU list (reported as a FAIL by the conf section).
    pub lcores_error: Option<String>,
    pub cores: Option<usize>,
    pub hugepages_mb: u64,
    pub dev: Option<String>,
}

impl OsdConf {
    /// Cores this OSD will use (lcores range, else `flashstore_cores`).
    pub fn core_count(&self) -> Option<usize> {
        self.cores.or(if self.lcores.is_empty() {
            None
        } else {
            Some(self.lcores.len())
        })
    }

    /// Canonical PCI address (sysfs spelling) of a `spdk:` device; `None` for other specs and malformed addresses.
    pub fn pci(&self) -> Option<String> {
        let d = self.dev.as_deref()?;
        osddir::spec_pci(d)
            .ok()
            .flatten()
            .and_then(osddir::canonical_pci)
    }
}

#[derive(Debug, Default)]
pub struct Conf {
    pub path: String,
    pub found: bool,
    pub osds: Vec<OsdConf>,
}

fn norm(k: &str) -> String {
    k.trim().replace(['-', ' '], "_")
}

pub fn load(fs: &Fs, path: &Path) -> Conf {
    let rel = path.to_string_lossy();
    let mut c = Conf {
        path: rel.to_string(),
        ..Default::default()
    };
    if let Some(text) = fs.read(&rel) {
        c.found = true;
        c.osds = parse(&text);
    }
    c
}

pub fn parse(text: &str) -> Vec<OsdConf> {
    use std::collections::BTreeMap;
    let mut secs: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut cur = String::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if let Some(s) = l.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            cur = s.trim().to_string();
            secs.entry(cur.clone()).or_default();
        } else if let Some((k, v)) = l.split_once('=') {
            let v = v.split(" #").next().unwrap_or(v).trim().trim_matches('"');
            secs.entry(cur.clone())
                .or_default()
                .insert(norm(k), v.to_string());
        }
    }
    let get = |osd: &str, k: &str| -> Option<String> {
        secs.get(osd)
            .and_then(|m| m.get(k))
            .or_else(|| secs.get("osd").and_then(|m| m.get(k)))
            .or_else(|| secs.get("global").and_then(|m| m.get(k)))
            .cloned()
    };
    let mut out = Vec::new();
    for name in secs.keys().filter(|n| n.starts_with("osd.")) {
        let (lcores, lcores_error) = match get(name, "flashstore_lcores") {
            Some(v) => match parse_cpulist(&v) {
                Ok(l) => (l, None),
                Err(e) => (Vec::new(), Some(e)),
            },
            None => (Vec::new(), None),
        };
        out.push(OsdConf {
            name: name.clone(),
            lcores,
            lcores_error,
            cores: get(name, "flashstore_cores").and_then(|v| v.parse().ok()),
            hugepages_mb: get(name, "flashstore_hugepages_mb")
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_HUGEPAGES_MB),
            dev: get(name, "flashstore_dev"),
        });
    }
    out
}

pub fn section(fs: &Fs, c: &Conf, facts: &Facts) -> Section {
    let mut v = Vec::new();
    if !c.found {
        v.push(
            Check::new("conf.file", "OSD conf")
                .val(format!("{} not found", c.path))
                .why("checks below use defaults (1 OSD, 2048 MiB hugepages); the conf names cores, devices and VFs to cross-check")
                .na(),
        );
        return Section {
            name: "Config",
            checks: v,
        };
    }
    if c.osds.is_empty() {
        v.push(
            Check::new("conf.file", "OSD conf")
                .val(format!("{}: no [osd.N] section", c.path))
                .why("per-OSD cores/devices cannot be cross-checked")
                .na(),
        );
        return Section {
            name: "Config",
            checks: v,
        };
    }
    v.push(
        Check::new("conf.file", "OSD conf")
            .val(format!("{}: {} OSD section(s)", c.path, c.osds.len()))
            .why("source of the per-OSD core, hugepage and device plan below")
            .ok(),
    );
    let online = fs
        .read("sys/devices/system/cpu/online")
        .and_then(|s| parse_cpulist(&s).ok())
        .unwrap_or_default();
    let mut seen: Vec<(u32, String)> = Vec::new();
    for o in &c.osds {
        let mut ck = Check::new(format!("conf.{}.cores", o.name), format!("{} core budget", o.name))
            .why("thread-per-core: one core = one shard/PG owner; more than 8 cores per OSD is outside the measured/supported budget (adr 0063)");
        match (&o.lcores_error, o.core_count()) {
            (Some(e), _) => {
                ck = ck
                    .val(format!("invalid flashstore_lcores: {e}"))
                    .fail()
                    .fix(
                        "fix flashstore_lcores: a cpu list of online cpus, e.g. 4-11 (`lscpu -e`)",
                    );
            }
            (None, Some(n)) => {
                ck = ck.val(format!(
                    "{n} core(s){}",
                    if o.lcores.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", fmt_cpulist(&o.lcores))
                    }
                ));
                if n > CORE_BUDGET {
                    ck = ck.warn().fix("reduce flashstore_lcores/flashstore_cores to <= 8 per OSD and run more OSDs per host instead");
                }
                let missing: Vec<u32> = o
                    .lcores
                    .iter()
                    .copied()
                    .filter(|c| !online.is_empty() && !online.contains(c))
                    .collect();
                if !missing.is_empty() {
                    ck = ck.fail().fix(format!(
                        "lcores {} are not online on this host; fix flashstore_lcores",
                        fmt_cpulist(&missing)
                    ));
                }
                for l in &o.lcores {
                    if let Some((_, other)) = seen.iter().find(|(c, _)| c == l) {
                        ck = ck.fail().fix(format!("cpu {l} also assigned to {other}; give every OSD disjoint flashstore_lcores"));
                        break;
                    }
                    seen.push((*l, o.name.clone()));
                }
            }
            (None, None) => {
                ck = ck
                    .val("not set (auto-packed into one L3 domain, adr 0063)")
                    .na();
            }
        }
        v.push(ck);
        if let Some(d) = &o.dev {
            let mut ck = Check::new(format!("conf.{}.dev", o.name), format!("{} device", o.name))
                .why("the configured store device must exist on this host (checked read-only via sysfs)")
                .val(d.clone());
            match osddir::spec_pci(d).map(|p| p.map(osddir::canonical_pci)) {
                Err(e) => ck = ck.fail().fix(format!("fix flashstore_dev: {e}")),
                Ok(Some(Some(bdf)))
                    if facts.live && !fs.exists(&format!("sys/bus/pci/devices/{bdf}")) =>
                {
                    ck = ck
                        .fail()
                        .fix("fix flashstore_dev: no such PCI device on this host (lspci -D)");
                }
                _ => {}
            }
            v.push(ck);
        }
    }
    Section {
        name: "Config",
        checks: v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("hwcheck-conf-{}-{tag}", std::process::id()));
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
    fn empty_osd_sections_inherit_the_host_plan() {
        let o = parse(
            "[global]\nflashstore_hugepages_mb=4096\n[osd]\nflashstore_cores=4\n[osd.1]\n[osd.2]\n",
        );
        assert_eq!(o.len(), 2);
        for osd in o {
            assert_eq!(osd.hugepages_mb, 4096);
            assert_eq!(osd.core_count(), Some(4));
        }
    }

    #[test]
    fn layering() {
        let o = parse(
            "[global]\nflashstore_hugepages_mb = 4096\n[osd]\nflashstore_lcores = 0-3\n[osd.1]\nflashstore_dev = spdk:0000:03:00.0\n[osd.2]\nflashstore-lcores = 8-15 # c\nflashstore_hugepages_mb=1024\n",
        );
        assert_eq!(o.len(), 2);
        assert_eq!(o[0].lcores, vec![0, 1, 2, 3]);
        assert_eq!(o[0].hugepages_mb, 4096);
        assert_eq!(o[1].core_count(), Some(8));
        assert_eq!(o[1].hugepages_mb, 1024);
    }

    #[test]
    fn an_impossible_lcore_list_is_reported() {
        let o = parse("[osd.0]\nflashstore_lcores = 0-9000\n");
        assert!(o[0].lcores.is_empty());
        assert!(o[0].lcores_error.is_some());
        let r = root("lcores");
        write(
            &r,
            "etc/ceph/ceph.conf",
            "[osd.0]\nflashstore_lcores = 0-9000\n",
        );
        let fs = Fs::new(&r);
        let c = load(&fs, Path::new("etc/ceph/ceph.conf"));
        let ck = section(&fs, &c, &Facts::default())
            .checks
            .into_iter()
            .find(|x| x.id == "conf.osd.0.cores")
            .unwrap();
        assert_eq!(ck.status, crate::Status::Fail, "{}", ck.value);
        let _ = std::fs::remove_dir_all(&r);
    }
}
