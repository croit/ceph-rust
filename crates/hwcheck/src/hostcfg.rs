// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Prescribed host configuration for a benchmark or test run: every value is optional, a key that is not set is not
//! looked at. [`items`] reads the host state for the prescribed keys (through the same readers and [`Step`]s as the
//! host-tune engine), [`checks`] turns the mismatches into hwcheck [`Check`]s that [`crate::tune`] plans, applies and
//! reverts (state file), and [`readings`] is the key-to-value map a caller compares over time (drift).
//!
//! Applicable keys (`cstate_max`, `governor`, `turbo`, `thp`, `numa_balancing`, `gro`, `gro_hw`, `irq_affinity`,
//! `rings`) carry a [`Step`]; the others (`smt`, `mtu`, `irqbalance`, `cmdline`, `bios_version`) are verify-only: a
//! mismatch has no mechanical fix and the finding says what to change by hand. NIC keys (`gro`, `gro_hw`, `rings`,
//! `mtu`, `irq_affinity`) apply only to the up NICs that `nics = [..]` selects (interface names or CIDRs; without
//! a selector the spec is invalid) and never to the NIC that carries the agent's own leader connection.
use crate::action::{Action, HostSys, Runner, Step};
use crate::{Check, Options, Status};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// NIC ring sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rings {
    pub rx: u32,
    pub tx: u32,
}

/// What the host must look like (all optional).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostWant {
    /// Deepest C-state index a core may enter; deeper cpuidle states are disabled (0 = POLL only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cstate_max: Option<u32>,
    /// cpufreq governor (`performance`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governor: Option<String>,
    /// Turbo / boost on or off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turbo: Option<bool>,
    /// SMT active (verify only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smt: Option<bool>,
    /// Transparent hugepages: `always`, `madvise` or `never`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thp: Option<String>,
    /// `kernel.numa_balancing` on or off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numa_balancing: Option<bool>,
    /// The NICs the NIC keys (`gro`, `gro_hw`, `rings`, `mtu`, `irq_affinity`) apply to: interface names or CIDRs
    /// (a NIC with an address in the subnet, e.g. the Ceph cluster or public network). Required with any NIC key:
    /// the management NIC must never be touched by accident.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nics: Vec<String>,
    /// NIC generic receive offload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gro: Option<bool>,
    /// NIC hardware GRO (`rx-gro-hw`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gro_hw: Option<bool>,
    /// NIC queue IRQ placement policy: `spread` (one queue IRQ per NIC-local cpu, adr 0063 am. 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub irq_affinity: Option<String>,
    /// NIC ring sizes (at least).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rings: Option<Rings>,
    /// NIC MTU (verify only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// `irqbalance` daemon running (verify only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub irqbalance: Option<bool>,
    /// Words that must be on the kernel command line (verify only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cmdline: Vec<String>,
    /// BIOS version string, from DMI (verify only; the other BIOS settings are not readable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bios_version: Option<String>,
}

impl HostWant {
    /// Nothing prescribed.
    pub fn is_empty(&self) -> bool {
        *self == HostWant::default()
    }

    /// The programs reading or applying the prescribed keys run, as `(program, key)` pairs: `ethtool` for every
    /// NIC key that is read or changed through it (`gro`, `gro_hw`, `rings`, `irq_affinity`), and with `apply`
    /// also `cpupower` (`governor`) and `sysctl` (`numa_balancing`). Everything else is read from sysfs/procfs.
    pub fn required_tools(&self, apply: bool) -> Vec<(&'static str, &'static str)> {
        let mut v = Vec::new();
        let nic_keys = [
            ("gro", self.gro.is_some()),
            ("gro_hw", self.gro_hw.is_some()),
            ("rings", self.rings.is_some()),
            ("irq_affinity", self.irq_affinity.is_some()),
        ];
        v.extend(
            nic_keys
                .into_iter()
                .filter(|(_, set)| *set)
                .map(|(k, _)| ("ethtool", k)),
        );
        if apply && self.governor.is_some() {
            v.push(("cpupower", "governor"));
        }
        if apply && self.numa_balancing.is_some() {
            v.push(("sysctl", "numa_balancing"));
        }
        v
    }

    /// `self` with every key `over` sets replaced (`cmdline` words are added).
    pub fn overlay(&self, over: &HostWant) -> HostWant {
        fn pick<T: Clone>(a: &Option<T>, b: &Option<T>) -> Option<T> {
            b.clone().or_else(|| a.clone())
        }
        let mut cmdline = self.cmdline.clone();
        for w in &over.cmdline {
            if !cmdline.contains(w) {
                cmdline.push(w.clone());
            }
        }
        HostWant {
            nics: if over.nics.is_empty() {
                self.nics.clone()
            } else {
                over.nics.clone()
            },
            cstate_max: pick(&self.cstate_max, &over.cstate_max),
            governor: pick(&self.governor, &over.governor),
            turbo: pick(&self.turbo, &over.turbo),
            smt: pick(&self.smt, &over.smt),
            thp: pick(&self.thp, &over.thp),
            numa_balancing: pick(&self.numa_balancing, &over.numa_balancing),
            gro: pick(&self.gro, &over.gro),
            gro_hw: pick(&self.gro_hw, &over.gro_hw),
            irq_affinity: pick(&self.irq_affinity, &over.irq_affinity),
            rings: pick(&self.rings, &over.rings),
            mtu: pick(&self.mtu, &over.mtu),
            irqbalance: pick(&self.irqbalance, &over.irqbalance),
            cmdline,
            bios_version: pick(&self.bios_version, &over.bios_version),
        }
    }

    /// Problems of the values themselves (empty = fine).
    pub fn problems(&self) -> Vec<String> {
        let mut v = Vec::new();
        if let Some(t) = &self.thp
            && !["always", "madvise", "never"].contains(&t.as_str())
        {
            v.push(format!("thp {t:?} must be always, madvise or never"));
        }
        if let Some(p) = &self.irq_affinity
            && p != "spread"
        {
            v.push(format!("irq_affinity {p:?} must be \"spread\""));
        }
        if self.governor.as_deref() == Some("") {
            v.push("governor must not be empty".into());
        }
        for n in &self.nics {
            if n.is_empty() || (n.contains('/') && Cidr::parse(n).is_none()) {
                v.push(format!(
                    "nics entry {n:?} must be an interface name or a CIDR"
                ));
            }
        }
        if self.nics.is_empty() && self.has_nic_key() {
            v.push(
                "gro, gro_hw, rings, mtu and irq_affinity need `nics = [..]` (interface names or CIDRs): \
                 a NIC key never applies to every NIC"
                    .into(),
            );
        }
        v
    }

    /// Any key that applies to NICs.
    pub fn has_nic_key(&self) -> bool {
        self.gro.is_some()
            || self.gro_hw.is_some()
            || self.rings.is_some()
            || self.mtu.is_some()
            || self.irq_affinity.is_some()
    }
}

/// One prescribed key as found on the host.
#[derive(Clone, Debug)]
pub struct Item {
    /// Key, with the NIC for NIC keys (`gro:eth0`).
    pub key: String,
    /// What was prescribed.
    pub expected: String,
    /// What the host has now.
    pub actual: String,
    /// The host matches.
    pub ok: bool,
    /// The mechanical change, if the key has one.
    pub action: Option<Action>,
    /// What to do by hand when there is no action.
    pub manual: String,
    /// The commands that undo the action from the state read now (what `--revert` runs, as text).
    pub revert: Vec<String>,
}

impl Item {
    /// The exact command(s) that fix a mismatch.
    pub fn fix(&self) -> String {
        match &self.action {
            Some(a) => a.fix_text(),
            None => self.manual.clone(),
        }
    }
}

/// An IP network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    len: u8,
}

impl Cidr {
    /// `10.0.0.0/24`, `fd00::/64`.
    pub fn parse(s: &str) -> Option<Cidr> {
        let (a, l) = s.split_once('/')?;
        let net: IpAddr = a.parse().ok()?;
        let len: u8 = l.parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        (len <= max).then_some(Cidr { net, len })
    }

    /// `ip` lies in the network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        fn bits(ip: IpAddr) -> (u128, u8) {
            match ip {
                IpAddr::V4(a) => (u128::from(u32::from(a)), 32),
                IpAddr::V6(a) => (u128::from(a), 128),
            }
        }
        let (n, nb) = bits(self.net);
        let (i, ib) = bits(ip);
        if nb != ib {
            return false;
        }
        let shift = u32::from(nb - self.len);
        shift >= 128 || (n >> shift) == (i >> shift)
    }
}

/// Addresses per interface (`ip -o addr show`); empty when the command is not available.
fn nic_addrs<X: Runner>(h: &mut HostSys<X>) -> BTreeMap<String, Vec<IpAddr>> {
    let mut m: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    let argv = ["ip", "-o", "addr", "show"].map(String::from);
    for line in h.exec(&argv).unwrap_or_default().lines() {
        // `2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0`
        let f: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = f.iter().position(|w| *w == "inet" || *w == "inet6")
            && let (Some(name), Some(a)) = (f.get(1), f.get(i + 1))
            && let Some(ip) = a.split('/').next().and_then(|a| a.parse().ok())
        {
            m.entry(name.trim_end_matches(':').to_string())
                .or_default()
                .push(ip);
        }
    }
    m
}

/// Up physical NICs selected by `sel` (names or CIDRs); the second list holds the selectors that matched no NIC.
fn nics<X: Runner>(h: &mut HostSys<X>, sel: &[String]) -> (Vec<String>, Vec<String>) {
    let up: Vec<String> =
        h.fs.list("sys/class/net")
            .into_iter()
            .filter(|n| {
                n != "lo"
                    && h.fs.exists(&format!("sys/class/net/{n}/device"))
                    && h.fs
                        .read(&format!("sys/class/net/{n}/operstate"))
                        .as_deref()
                        == Some("up")
            })
            .collect();
    let addrs = if sel.iter().any(|s| s.contains('/')) {
        nic_addrs(h)
    } else {
        BTreeMap::new()
    };
    let hit = |n: &str, s: &str| match Cidr::parse(s) {
        Some(c) => addrs
            .get(n)
            .is_some_and(|a| a.iter().any(|ip| c.contains(*ip))),
        None => s == n,
    };
    let chosen = up
        .iter()
        .filter(|n| sel.iter().any(|s| hit(n, s)))
        .cloned()
        .collect();
    let unmatched = sel
        .iter()
        .filter(|s| !up.iter().any(|n| hit(n, s)))
        .cloned()
        .collect();
    (chosen, unmatched)
}

fn onoff(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

/// Item of a key that has a [`Step`]: the probe decides.
fn stepped<X: Runner>(h: &mut HostSys<X>, key: &str, expected: String, step: Step) -> Item {
    let p = step.probe(h);
    Item {
        key: key.into(),
        expected,
        actual: p
            .as_ref()
            .map_or("not readable".into(), |p| p.current.clone()),
        ok: p.as_ref().is_some_and(|p| p.done),
        revert: revert_text(&step, p.as_ref().map(|p| p.current.as_str())),
        action: Some(Action::new(vec![step])),
        manual: String::new(),
    }
}

/// The command text that restores `step`'s target to the value `cur` it has now.
fn revert_text(step: &Step, cur: Option<&str>) -> Vec<String> {
    let Some(cur) = cur else {
        return vec!["restore from the state file".into()];
    };
    match step {
        Step::Write { path, .. } => vec![format!("echo {cur} > /{path}")],
        Step::Sysctl { key, .. } => vec![format!("sysctl -w {key}={cur}")],
        Step::Governor { .. } => vec![format!("cpupower frequency-set -g {cur}")],
        Step::Features { iface, .. } => vec![format!(
            "ethtool -K {iface} {}",
            cur.split_whitespace()
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| format!("{k} {v}"))
                .collect::<Vec<_>>()
                .join(" ")
        )],
        Step::Rings { iface, .. } => vec![format!("ethtool -G {iface} {cur}")],
        Step::CpuIdleMax { .. } => {
            vec!["re-enable the cpuidle states the apply disabled (state file)".into()]
        }
        _ => vec!["restore the recorded values (state file)".into()],
    }
}

fn verified(key: &str, expected: String, actual: Option<String>, ok: bool, manual: &str) -> Item {
    Item {
        key: key.into(),
        expected,
        actual: actual.unwrap_or_else(|| "not readable".into()),
        ok,
        action: None,
        manual: manual.into(),
        revert: Vec::new(),
    }
}

/// Reads the host for every prescribed key.
///
/// `leader_ip` is the local address of the agent's own connection to its leader: the NIC that carries it is never
/// changed (its NIC items lose their action: a ring or offload change resets the link on many drivers and would
/// cut the agent off).
pub fn items<X: Runner>(
    h: &mut HostSys<X>,
    want: &HostWant,
    leader_ip: Option<IpAddr>,
) -> Vec<Item> {
    let mut v = Vec::new();
    if let Some(max) = want.cstate_max {
        v.push(stepped(
            h,
            "cstate_max",
            format!("no C-state deeper than {max}"),
            Step::CpuIdleMax { max },
        ));
    }
    if let Some(g) = &want.governor {
        v.push(stepped(
            h,
            "governor",
            g.clone(),
            Step::Governor { want: g.clone() },
        ));
    }
    if let Some(t) = want.turbo {
        let (path, val) = if h.fs.exists("sys/devices/system/cpu/intel_pstate/no_turbo") {
            (
                "sys/devices/system/cpu/intel_pstate/no_turbo",
                if t { "0" } else { "1" },
            )
        } else {
            (
                "sys/devices/system/cpu/cpufreq/boost",
                if t { "1" } else { "0" },
            )
        };
        if h.fs.exists(path) {
            v.push(stepped(
                h,
                "turbo",
                onoff(t).into(),
                Step::Write {
                    path: path.into(),
                    want: val.into(),
                    bracket: false,
                },
            ));
        } else {
            v.push(verified(
                "turbo",
                onoff(t).into(),
                None,
                false,
                "turbo/boost is not controllable here (BIOS)",
            ));
        }
    }
    if let Some(s) = want.smt {
        let a = h
            .read("sys/devices/system/cpu/smt/active")
            .map(|a| onoff(a == "1").to_string());
        let ok = a.as_deref() == Some(onoff(s));
        v.push(verified(
            "smt",
            onoff(s).into(),
            a,
            ok,
            "set SMT in the BIOS, or echo on|off > /sys/devices/system/cpu/smt/control",
        ));
    }
    if let Some(t) = &want.thp {
        v.push(stepped(
            h,
            "thp",
            t.clone(),
            Step::Write {
                path: "sys/kernel/mm/transparent_hugepage/enabled".into(),
                want: t.clone(),
                bracket: true,
            },
        ));
    }
    if let Some(b) = want.numa_balancing {
        v.push(stepped(
            h,
            "numa_balancing",
            onoff(b).into(),
            Step::Sysctl {
                key: "kernel.numa_balancing".into(),
                want: if b { "1" } else { "0" }.into(),
                cmp: crate::action::Cmp::Eq,
            },
        ));
    }
    let (up, unmatched) = if want.has_nic_key() {
        nics(h, &want.nics)
    } else {
        (Vec::new(), Vec::new())
    };
    if want.has_nic_key() && want.nics.is_empty() {
        v.push(verified(
            "nics",
            "a selector".into(),
            None,
            false,
            "set `nics = [\"<interface or CIDR>\"]` next to the NIC keys",
        ));
    }
    for s in &unmatched {
        v.push(verified(
            &format!("nics:{s}"),
            "an up NIC".into(),
            Some("no up NIC matches".into()),
            false,
            "bring the interface up or fix the selector",
        ));
    }
    for n in &up {
        let mut feat = Vec::new();
        if let Some(g) = want.gro {
            feat.push(("gro".to_string(), g));
        }
        if let Some(g) = want.gro_hw {
            feat.push(("rx-gro-hw".to_string(), g));
        }
        if !feat.is_empty() {
            let exp = feat
                .iter()
                .map(|(f, b)| format!("{f}={}", onoff(*b)))
                .collect::<Vec<_>>()
                .join(" ");
            v.push(stepped(
                h,
                &format!("gro:{n}"),
                exp,
                Step::Features {
                    iface: n.clone(),
                    want: feat,
                },
            ));
        }
        if let Some(r) = want.rings {
            v.push(stepped(
                h,
                &format!("rings:{n}"),
                format!("rx >= {} tx >= {}", r.rx, r.tx),
                Step::Rings {
                    iface: n.clone(),
                    rx: r.rx,
                    tx: r.tx,
                },
            ));
        }
        if let Some(m) = want.mtu {
            let a = h.read(&format!("sys/class/net/{n}/mtu"));
            let ok = a.as_deref() == Some(&m.to_string());
            v.push(verified(
                &format!("mtu:{n}"),
                m.to_string(),
                a,
                ok,
                &format!("ip link set {n} mtu {m} (and the switch ports)"),
            ));
        }
    }
    if want.irq_affinity.is_some() && !up.is_empty() {
        let report = crate::run(&Options {
            root: h.root().into(),
            ..Default::default()
        });
        for n in &up {
            let id = format!("net.{n}.irq");
            let c = report
                .sections
                .iter()
                .flat_map(|s| &s.checks)
                .find(|c| c.id == id);
            v.push(match c {
                Some(c) => Item {
                    key: format!("irq_affinity:{n}"),
                    expected: "spread".into(),
                    actual: c.value.clone(),
                    ok: c.status < Status::Warn,
                    action: c.actions.first().cloned(),
                    manual: c.fix.clone().unwrap_or_default(),
                    revert: vec![
                        "restore the recorded smp_affinity_list values (state file)".into(),
                    ],
                },
                None => verified(
                    &format!("irq_affinity:{n}"),
                    "spread".into(),
                    None,
                    false,
                    "no IRQ check for this NIC",
                ),
            });
        }
    }
    if let Some(b) = want.irqbalance {
        let running = h.fs.list("proc").iter().any(|p| {
            p.bytes().all(|c| c.is_ascii_digit())
                && h.fs.read(&format!("proc/{p}/comm")).as_deref() == Some("irqbalance")
        });
        v.push(verified(
            "irqbalance",
            if b { "running" } else { "not running" }.into(),
            Some(if running { "running" } else { "not running" }.into()),
            running == b,
            if b {
                "systemctl start irqbalance"
            } else {
                "systemctl stop irqbalance"
            },
        ));
    }
    if !want.cmdline.is_empty() {
        let have = h.fs.cmdline();
        let missing: Vec<&String> = want.cmdline.iter().filter(|w| !have.contains(w)).collect();
        v.push(verified(
            "cmdline",
            want.cmdline.join(" "),
            Some(if missing.is_empty() {
                "all present".into()
            } else {
                format!(
                    "missing: {}",
                    missing
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }),
            missing.is_empty(),
            "add the words to the kernel command line and reboot",
        ));
    }
    if let Some(b) = &want.bios_version {
        let a = h.read("sys/class/dmi/id/bios_version");
        let ok = a.as_deref() == Some(b.as_str());
        v.push(verified(
            "bios_version",
            b.clone(),
            a,
            ok,
            "flash the prescribed BIOS version",
        ));
    }
    if let Some(ip) = leader_ip
        && !up.is_empty()
        && let Some(own) = nic_addrs(h)
            .into_iter()
            .find(|(n, a)| up.contains(n) && a.contains(&ip))
            .map(|(n, _)| n)
    {
        for i in &mut v {
            if !i.ok && i.action.is_some() && i.key.ends_with(&format!(":{own}")) {
                i.manual = format!(
                    "{own} carries this agent's connection to the leader ({ip}): not changed by the agent, run by hand: {}",
                    i.fix()
                );
                i.action = None;
                i.revert.clear();
            }
        }
    }
    v
}

/// The items as hwcheck checks: OK where the host matches, WARN where it does not (with the action, or the manual
/// fix text), ready for [`crate::tune::plan`].
pub fn checks(items: &[Item]) -> Vec<Check> {
    items
        .iter()
        .map(|i| {
            let c = Check::new(format!("host.{}", i.key), format!("host config {}", i.key))
                .val(i.actual.clone())
                .why(format!("prescribed: {}", i.expected));
            if i.ok {
                c.ok()
            } else {
                match &i.action {
                    Some(a) => c.warn().act(a.clone()),
                    None => c.warn().fix(i.manual.clone()),
                }
            }
        })
        .collect()
}

/// Key to current value: what a run compares over time (drift).
pub fn readings(items: &[Item]) -> BTreeMap<String, String> {
    items
        .iter()
        .map(|i| (i.key.clone(), i.actual.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tune;
    use std::fs;
    use std::path::Path;

    /// Runner that answers `ethtool -k` from the fixture and applies `-K`/`sysctl -w` to it.
    struct Fake(std::path::PathBuf);

    impl Runner for Fake {
        fn run(&mut self, a: &[String]) -> Result<String, String> {
            let s: Vec<&str> = a.iter().map(String::as_str).collect();
            let f = self.0.join("gro");
            match s.as_slice() {
                ["ethtool", "-k", _] => Ok(fs::read_to_string(&f).unwrap_or_default()),
                ["ethtool", "-K", _, "gro", v, "rx-gro-hw", w] => {
                    fs::write(
                        &f,
                        format!("generic-receive-offload: {v}\nrx-gro-hw: {w}\n"),
                    )
                    .unwrap();
                    Ok(String::new())
                }
                ["ip", "-o", "addr", "show"] => {
                    Ok(fs::read_to_string(self.0.join("addr")).unwrap_or_default())
                }
                ["ethtool", "-g", _] => Ok("Current hardware settings:\nRX: 512\nTX: 512\n".into()),
                ["sysctl", "-w", kv] => {
                    let (k, v) = kv.split_once('=').unwrap();
                    fs::write(
                        self.0.join("proc/sys").join(k.replace('.', "/")),
                        format!("{v}\n"),
                    )
                    .unwrap();
                    Ok(String::new())
                }
                _ => Err(format!("unexpected {s:?}")),
            }
        }
    }

    fn w(root: &Path, rel: &str, s: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, s).unwrap();
    }

    fn tree(root: &Path) {
        for cpu in 0..2 {
            for (k, dis) in [(0, "0"), (1, "0"), (2, "0")] {
                w(
                    root,
                    &format!("sys/devices/system/cpu/cpu{cpu}/cpuidle/state{k}/disable"),
                    dis,
                );
            }
        }
        w(
            root,
            "sys/kernel/mm/transparent_hugepage/enabled",
            "[always] madvise never\n",
        );
        w(root, "proc/sys/kernel/numa_balancing", "1\n");
        w(root, "sys/devices/system/cpu/intel_pstate/no_turbo", "0\n");
        w(root, "sys/devices/system/cpu/smt/active", "1\n");
        w(root, "sys/class/net/eth0/operstate", "up\n");
        w(root, "sys/class/net/eth0/device/x", "");
        w(root, "sys/class/net/eth0/mtu", "1500\n");
        w(root, "proc/cmdline", "ro quiet isolcpus=2-3\n");
        w(root, "proc/77/comm", "irqbalance\n");
        w(root, "sys/class/dmi/id/bios_version", "1.2.3\n");
        w(root, "gro", "generic-receive-offload: off\nrx-gro-hw: on\n");
        w(
            root,
            "addr",
            "1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 10.1.2.5/24 brd 10.1.2.255 scope global eth0\n",
        );
    }

    fn want() -> HostWant {
        HostWant {
            nics: vec!["eth0".into()],
            cstate_max: Some(1),
            thp: Some("madvise".into()),
            numa_balancing: Some(false),
            turbo: Some(false),
            gro: Some(true),
            gro_hw: Some(false),
            smt: Some(false),
            mtu: Some(9000),
            irqbalance: Some(false),
            cmdline: vec!["isolcpus=2-3".into(), "nohz_full=2-3".into()],
            bios_version: Some("1.2.3".into()),
            ..Default::default()
        }
    }

    #[test]
    fn mismatches_are_found_applied_and_reverted_and_verify_only_keys_are_manual() {
        let d = tempfile::tempdir().unwrap();
        tree(d.path());
        let mut h = HostSys::new(d.path(), Fake(d.path().into()));
        let before = items(&mut h, &want(), None);
        let bad: Vec<&str> = before
            .iter()
            .filter(|i| !i.ok)
            .map(|i| i.key.as_str())
            .collect();
        assert_eq!(
            bad,
            [
                "cstate_max",
                "turbo",
                "smt",
                "thp",
                "numa_balancing",
                "gro:eth0",
                "mtu:eth0",
                "irqbalance",
                "cmdline"
            ]
        );
        let cmd = before.iter().find(|i| i.key == "mtu:eth0").unwrap();
        assert!(cmd.action.is_none() && cmd.fix().contains("ip link set eth0 mtu 9000"));
        assert_eq!(
            before.iter().find(|i| i.key == "cmdline").unwrap().actual,
            "missing: nohz_full=2-3"
        );
        assert!(before.iter().find(|i| i.key == "bios_version").unwrap().ok);

        let cs = checks(&before);
        let state = d.path().join("state.json");
        let mut plan = tune::plan(&mut h, &cs, &tune::Filter::default(), None);
        assert_eq!(
            plan.manual.len(),
            4,
            "smt, mtu, irqbalance, cmdline: {:?}",
            plan.manual.iter().map(|m| &m.check).collect::<Vec<_>>()
        );
        let mut st = tune::State::open(&state).unwrap();
        tune::apply(&mut h, &mut plan, &mut st, || cs.clone()).unwrap();

        let after = items(&mut h, &want(), None);
        let bad: Vec<&str> = after
            .iter()
            .filter(|i| !i.ok)
            .map(|i| i.key.as_str())
            .collect();
        assert_eq!(
            bad,
            ["smt", "mtu:eth0", "irqbalance", "cmdline"],
            "only the verify-only keys stay"
        );
        assert_eq!(
            fs::read_to_string(
                d.path()
                    .join("sys/devices/system/cpu/cpu1/cpuidle/state2/disable")
            )
            .unwrap()
            .trim(),
            "1"
        );
        assert_eq!(
            fs::read_to_string(
                d.path()
                    .join("sys/devices/system/cpu/cpu0/cpuidle/state1/disable")
            )
            .unwrap()
            .trim(),
            "0",
            "states up to the limit stay enabled"
        );

        let rows = tune::revert(&mut h, &state).unwrap();
        assert!(rows.iter().all(|r| r.error.is_none()), "{rows:?}");
        let back = items(&mut h, &want(), None);
        assert_eq!(
            readings(&back),
            readings(&before),
            "revert restores every reading"
        );
    }

    #[test]
    fn required_tools_follow_the_prescribed_keys() {
        let w = HostWant {
            governor: Some("performance".into()),
            numa_balancing: Some(false),
            gro: Some(false),
            rings: Some(Rings { rx: 4096, tx: 4096 }),
            thp: Some("never".into()),
            nics: vec!["eth0".into()],
            ..Default::default()
        };
        assert_eq!(
            w.required_tools(false),
            [("ethtool", "gro"), ("ethtool", "rings")]
        );
        assert_eq!(
            w.required_tools(true),
            [
                ("ethtool", "gro"),
                ("ethtool", "rings"),
                ("cpupower", "governor"),
                ("sysctl", "numa_balancing")
            ]
        );
        assert!(HostWant::default().required_tools(true).is_empty());
    }

    #[test]
    fn overlay_replaces_keys_and_adds_cmdline_words() {
        let base = HostWant {
            governor: Some("powersave".into()),
            cmdline: vec!["a".into()],
            ..Default::default()
        };
        let over = HostWant {
            governor: Some("performance".into()),
            cmdline: vec!["a".into(), "b".into()],
            mtu: Some(9000),
            ..Default::default()
        };
        let m = base.overlay(&over);
        assert_eq!(
            (m.governor.as_deref(), m.mtu, m.cmdline.as_slice()),
            (
                Some("performance"),
                Some(9000),
                &["a".to_string(), "b".to_string()][..]
            )
        );
        assert!(HostWant::default().is_empty() && !m.is_empty());
        assert_eq!(
            HostWant {
                thp: Some("x".into()),
                ..Default::default()
            }
            .problems()
            .len(),
            1
        );
    }

    fn gro_only(nics: &[&str]) -> HostWant {
        HostWant {
            nics: nics.iter().map(|n| (*n).to_string()).collect(),
            gro: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn a_cidr_selects_the_nics_with_an_address_in_the_subnet() {
        let d = tempfile::tempdir().unwrap();
        tree(d.path());
        let mut h = HostSys::new(d.path(), Fake(d.path().into()));
        let keys = |w: &HostWant, h: &mut HostSys<Fake>| {
            items(h, w, None)
                .into_iter()
                .map(|i| i.key)
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(&gro_only(&["10.1.2.0/24"]), &mut h), ["gro:eth0"]);
        assert_eq!(keys(&gro_only(&["eth0"]), &mut h), ["gro:eth0"]);
        // another subnet matches nothing: loud verify item, nothing applied anywhere
        let other = items(&mut h, &gro_only(&["192.168.0.0/16"]), None);
        assert_eq!(other.len(), 1, "{other:?}");
        assert!(other[0].key.starts_with("nics:") && !other[0].ok && other[0].action.is_none());
        let c = Cidr::parse("10.1.2.0/24").unwrap();
        assert!(c.contains("10.1.2.200".parse().unwrap()));
        assert!(!c.contains("10.1.3.1".parse().unwrap()));
        assert!(!c.contains("fd00::1".parse().unwrap()));
        assert!(
            Cidr::parse("fd00::/64")
                .unwrap()
                .contains("fd00::5".parse().unwrap())
        );
        assert!(Cidr::parse("10.0.0.0/33").is_none() && Cidr::parse("10.0.0.0").is_none());
    }

    #[test]
    fn a_nic_key_without_a_selector_is_an_error_and_applies_to_nothing() {
        let w = gro_only(&[]);
        let p = w.problems();
        assert!(p.iter().any(|m| m.contains("nics")), "{p:?}");
        assert!(gro_only(&["eth0"]).problems().is_empty());
        assert!(
            gro_only(&["10.0.0.0/99"])
                .problems()
                .iter()
                .any(|m| m.contains("CIDR"))
        );
        // keys without NIC keys need no selector
        assert!(
            HostWant {
                thp: Some("never".into()),
                ..Default::default()
            }
            .problems()
            .is_empty()
        );
        let d = tempfile::tempdir().unwrap();
        tree(d.path());
        let mut h = HostSys::new(d.path(), Fake(d.path().into()));
        let v = items(&mut h, &w, None);
        assert_eq!(v.len(), 1);
        assert!(
            v[0].key == "nics" && !v[0].ok && v[0].action.is_none(),
            "{v:?}"
        );
    }

    #[test]
    fn the_nic_of_the_leader_connection_is_never_changed() {
        let d = tempfile::tempdir().unwrap();
        tree(d.path());
        let mut h = HostSys::new(d.path(), Fake(d.path().into()));
        let w = gro_only(&["eth0"]);
        let free = items(&mut h, &w, Some("10.9.9.9".parse().unwrap()));
        assert!(
            free[0].action.is_some(),
            "another NIC carries the connection"
        );
        let own = items(&mut h, &w, Some("10.1.2.5".parse().unwrap()));
        assert!(!own[0].ok && own[0].action.is_none(), "{own:?}");
        assert!(
            own[0].fix().contains("connection to the leader")
                && own[0].fix().contains("ethtool -K eth0")
        );
        assert!(checks(&own).iter().all(|c| c.actions.is_empty()));
    }
}
