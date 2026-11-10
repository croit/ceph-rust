// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Mechanically applicable host fixes (adr 0465 host-tune helper, adr 0464): the structured form behind a check's `fix`
//! text. The text printed by `hwcheck` / the startup warning and the command `croit-flashstore-tool host-tune --apply` runs are
//! rendered from the same [`Step`] values. Fixes that cannot be applied mechanically (BIOS, kernel cmdline, hardware)
//! carry no action and stay text-only ("manual").
use crate::fs::Fs;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// Runs host commands (argv, no shell) and returns stdout. Production = [`ProcRunner`]; tests inject a recorder.
pub trait Runner {
    fn run(&mut self, argv: &[String]) -> Result<String, String>;
}

impl Runner for Box<dyn Runner + Send> {
    fn run(&mut self, argv: &[String]) -> Result<String, String> {
        (**self).run(argv)
    }
}

/// Spawns the real process.
#[derive(Debug)]
pub struct ProcRunner;

/// Directories a root helper resolves a bare command name in. The inherited `PATH` is never used: `host-tune --apply`
/// and the OSD's `sudo` run as root and a poisoned `PATH` would execute a foreign binary. Every entry is root-owned on
/// the hosts that have it (a non-root user cannot create it below `/run` or `/`). Order: the NixOS setuid wrappers first
/// (croit OS: `sudo` there is only setuid as `/run/wrappers/bin/sudo`), then the FHS dirs as the login shells of the
/// supported distributions (`/usr/local` first, `sbin` before `bin`), then the NixOS system profile.
pub const SYSTEM_PATH: [&str; 9] = [
    "/run/wrappers/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/run/current-system/sw/sbin",
    "/run/current-system/sw/bin",
];

/// Absolute program path of `prog`: an absolute `prog` as given, else the first [`SYSTEM_PATH`] entry that holds it.
/// A relative path with a slash is refused.
pub fn resolve(prog: &str) -> Option<PathBuf> {
    if prog.starts_with('/') {
        return Some(PathBuf::from(prog));
    }
    if prog.contains('/') {
        return None;
    }
    SYSTEM_PATH
        .iter()
        .map(|d| Path::new(d).join(prog))
        .find(|p| p.is_file())
}

impl Runner for ProcRunner {
    fn run(&mut self, argv: &[String]) -> Result<String, String> {
        let Some((prog, args)) = argv.split_first() else {
            return Err("empty command".into());
        };
        let Some(path) = resolve(prog) else {
            return Err(format!(
                "{prog}: command not found (install it: host-tune runs the same commands hwcheck prints)"
            ));
        };
        let out = std::process::Command::new(&path)
            .args(args)
            // no inherited environment (LD_PRELOAD & co), a fixed PATH for whatever the tool itself spawns
            .env_clear()
            .env("PATH", SYSTEM_PATH.join(":"))
            .output()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(format!(
                "{}: {}",
                argv.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

/// File and command access of a tune run: reads/writes below `root` (`/` live, a fixture tree in tests) and commands via `X`.
#[derive(Debug)]
pub struct HostSys<X: Runner> {
    pub fs: Fs,
    root: PathBuf,
    pub run: X,
}

impl<X: Runner> HostSys<X> {
    pub fn new(root: &Path, run: X) -> HostSys<X> {
        HostSys {
            fs: Fs::new(root),
            root: root.into(),
            run,
        }
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn read(&self, rel: &str) -> Option<String> {
        self.fs.read(rel)
    }
    pub fn write(&self, rel: &str, value: &str) -> Result<(), String> {
        std::fs::write(self.fs.p(rel), format!("{value}\n"))
            .map_err(|e| format!("write {} > {}: {e}", value, self.root.join(rel).display()))
    }
    pub(crate) fn exec(&mut self, argv: &[String]) -> Result<String, String> {
        self.run.run(argv)
    }
}

/// One undo operation recorded in the state file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevertOp {
    Exec(Vec<String>),
    Write { path: String, value: String },
}

impl RevertOp {
    pub fn to_json(&self) -> Value {
        match self {
            RevertOp::Exec(a) => json!({"exec": a}),
            RevertOp::Write { path, value } => json!({"write": path, "value": value}),
        }
    }
    pub fn from_json(v: &Value) -> Option<RevertOp> {
        if let Some(a) = v.get("exec").and_then(Value::as_array) {
            return Some(RevertOp::Exec(
                a.iter()
                    .map(|s| s.as_str().map(str::to_string))
                    .collect::<Option<_>>()?,
            ));
        }
        Some(RevertOp::Write {
            path: v.get("write")?.as_str()?.to_string(),
            value: v.get("value")?.as_str()?.to_string(),
        })
    }
    pub fn describe(&self) -> String {
        match self {
            RevertOp::Exec(a) => a.join(" "),
            RevertOp::Write { path, value } => format!("echo {value} > /{path}"),
        }
    }
    pub fn run<X: Runner>(&self, h: &mut HostSys<X>) -> Result<(), String> {
        match self {
            RevertOp::Exec(a) => h.exec(a).map(|_| ()),
            RevertOp::Write { path, value } => h.write(path, value),
        }
    }
}

/// How a step would be made persistent across reboot (`--emit-persist`; never installed by the tool).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Persist {
    /// `/etc/sysctl.d/` line.
    Sysctl(String),
    /// `/etc/modules-load.d/` line.
    Module(String),
    /// `/etc/fstab` line.
    Fstab(String),
    /// Runtime state only (NIC, IRQ, sysfs): re-applied at boot by a unit that runs `host-tune --apply`.
    Boot,
}

/// Comparison of a sysctl against its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmp {
    Eq,
    AtLeast,
}

/// One mechanical host change. Every variant renders its command text ([`Step::commands`]) and executes ([`Step::apply`])
/// from the same fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Sysctl {
        key: String,
        want: String,
        cmp: Cmp,
    },
    /// `echo want > /path`; `bracket`: the file shows the selection as `a [b] c` (THP).
    Write {
        path: String,
        want: String,
        bracket: bool,
    },
    /// `ethtool -K iface f v ...` (aliases rx/tx/tso/gro as the ethtool man page).
    Features {
        iface: String,
        want: Vec<(String, bool)>,
    },
    /// `ethtool -G iface rx N tx N`.
    Rings {
        iface: String,
        rx: u32,
        tx: u32,
    },
    /// `ethtool -L iface combined N` (restarts the queues).
    Channels {
        iface: String,
        combined: u32,
    },
    /// `ethtool -G iface tcp-data-split on` (header/data split, zcrx).
    TcpDataSplit {
        iface: String,
    },
    /// `ethtool -X iface equal M`: the host's RSS uses queues 0..M-1 only.
    RssEqual {
        iface: String,
        queues: u32,
    },
    /// `ethtool -X iface context new start S equal K` + one `-N flow-type tcp4 dst-port P context C` per port.
    FlowRules {
        iface: String,
        start: u32,
        count: u32,
        ports: Vec<u16>,
    },
    /// `ip link set iface promisc off allmulticast off` (VF hygiene, adr 0030). One-way: never reverted.
    LinkFlagsOff {
        iface: String,
    },
    /// `cpupower frequency-set -g want`.
    Governor {
        want: String,
    },
    /// `echo 1 > .../cpuN/cpuidle/stateK/disable` for every state K deeper than `max` on every cpu: the deepest
    /// C-state a core may enter (0 = POLL only).
    CpuIdleMax {
        max: u32,
    },
    /// `mount -t fstype dev target`.
    Mount {
        fstype: String,
        dev: String,
        target: String,
    },
    /// `modprobe name`.
    Module {
        name: String,
    },
    /// `echo cpu > /proc/irq/N/smp_affinity_list` for every `(irq, cpu)`.
    IrqAffinity {
        iface: String,
        pairs: Vec<(u32, u32)>,
    },
}

fn sv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn onoff(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

/// ethtool `-k` display name of a `-K` feature alias.
pub(crate) fn feature_name(f: &str) -> &str {
    match f {
        "rx" => "rx-checksumming",
        "tx" => "tx-checksumming",
        "tso" => "tcp-segmentation-offload",
        "gro" => "generic-receive-offload",
        "ntuple" => "ntuple-filters",
        o => o,
    }
}

/// `name: on|off` line of `ethtool -k` output.
fn parse_feature(out: &str, f: &str) -> Option<bool> {
    let name = feature_name(f);
    out.lines().find_map(|l| {
        let v = l.trim().strip_prefix(name)?.strip_prefix(':')?;
        match v.split_whitespace().next()? {
            "on" => Some(true),
            "off" => Some(false),
            _ => None,
        }
    })
}

/// `(rx, tx, tcp-data-split)` of the "Current hardware settings" block of `ethtool -g`.
fn parse_rings(out: &str) -> (Option<u32>, Option<u32>, Option<String>) {
    let (mut rx, mut tx, mut tds) = (None, None, None);
    let mut cur = false;
    for l in out.lines() {
        let l = l.trim();
        if l.starts_with("Current hardware settings") {
            cur = true;
        } else if l.starts_with("Pre-set maximums") {
            cur = false;
        } else if cur {
            if let Some(v) = l.strip_prefix("RX:") {
                rx = v.trim().parse().ok();
            } else if let Some(v) = l.strip_prefix("TX:") {
                tx = v.trim().parse().ok();
            } else if let Some(v) = l.strip_prefix("TCP data split:") {
                tds = Some(v.trim().to_string());
            }
        }
    }
    (rx, tx, tds)
}

/// `Combined:` of the current block of `ethtool -l`.
fn parse_combined(out: &str) -> Option<u32> {
    let mut cur = false;
    for l in out.lines() {
        let l = l.trim();
        if l.starts_with("Current hardware settings") {
            cur = true;
        } else if cur && let Some(v) = l.strip_prefix("Combined:") {
            return v.trim().parse().ok();
        }
    }
    None
}

/// Queue numbers used by the RSS indirection table of `ethtool -x`.
fn parse_indir(out: &str) -> Vec<u32> {
    let mut q = Vec::new();
    for l in out.lines() {
        if let Some((a, b)) = l.trim().split_once(':')
            && a.chars().all(|c| c.is_ascii_digit())
            && !a.is_empty()
        {
            q.extend(b.split_whitespace().filter_map(|x| x.parse::<u32>().ok()));
        }
    }
    q
}

/// First number after `marker` in `out` ("New RSS context is 1", "Added rule with ID 5").
fn number_after(out: &str, marker: &str) -> Option<u32> {
    out.split_once(marker)?
        .1
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// `(path of the disable file, state index)` of every cpuidle state of every cpu.
pub(crate) fn cpuidle_files(fs: &Fs) -> Vec<(String, u32)> {
    let mut v = Vec::new();
    for cpu in fs.list("sys/devices/system/cpu").into_iter().filter(|c| {
        c.strip_prefix("cpu")
            .is_some_and(|n| n.parse::<u32>().is_ok())
    }) {
        let base = format!("sys/devices/system/cpu/{cpu}/cpuidle");
        for st in fs.list(&base) {
            if let Some(k) = st.strip_prefix("state").and_then(|n| n.parse::<u32>().ok()) {
                v.push((format!("{base}/{st}/disable"), k));
            }
        }
    }
    v
}

/// State of a step before it is applied.
#[derive(Debug)]
pub struct Probe {
    pub current: String,
    pub done: bool,
}

fn bracket_sel(t: &str) -> String {
    t.split('[')
        .nth(1)
        .and_then(|s| s.split(']').next())
        .unwrap_or(t)
        .to_string()
}

impl Step {
    pub fn iface(&self) -> Option<&str> {
        match self {
            Step::Features { iface, .. }
            | Step::Rings { iface, .. }
            | Step::Channels { iface, .. }
            | Step::TcpDataSplit { iface }
            | Step::RssEqual { iface, .. }
            | Step::FlowRules { iface, .. }
            | Step::LinkFlagsOff { iface }
            | Step::IrqAffinity { iface, .. } => Some(iface),
            _ => None,
        }
    }

    /// Command texts (what an operator types); the argv forms of [`Step::apply`] are the same strings split.
    pub fn commands(&self) -> Vec<String> {
        match self {
            Step::Sysctl { key, want, .. } => vec![format!("sysctl -w {key}={want}")],
            Step::Write { path, want, .. } => vec![format!("echo {want} > /{path}")],
            Step::Features { iface, want } => vec![self.features_argv(iface, want).join(" ")],
            Step::Rings { iface, rx, tx } => vec![format!("ethtool -G {iface} rx {rx} tx {tx}")],
            Step::Channels { iface, combined } => {
                vec![format!("ethtool -L {iface} combined {combined}")]
            }
            Step::TcpDataSplit { iface } => vec![format!("ethtool -G {iface} tcp-data-split on")],
            Step::RssEqual { iface, queues } => vec![format!("ethtool -X {iface} equal {queues}")],
            Step::FlowRules {
                iface,
                start,
                count,
                ports,
            } => {
                let mut v = vec![format!(
                    "ethtool -X {iface} context new start {start} equal {count}"
                )];
                v.extend(ports.iter().map(|p| {
                    format!("ethtool -N {iface} flow-type tcp4 dst-port {p} context <new context>")
                }));
                v
            }
            Step::LinkFlagsOff { iface } => {
                vec![format!("ip link set {iface} promisc off allmulticast off")]
            }
            Step::Governor { want } => vec![format!("cpupower frequency-set -g {want}")],
            Step::CpuIdleMax { max } => vec![format!(
                "for f in /sys/devices/system/cpu/cpu*/cpuidle/state[{}-9]*/disable; do echo 1 > $f; done",
                max + 1
            )],
            Step::Mount {
                fstype,
                dev,
                target,
            } => vec![format!("mount -t {fstype} {dev} {target}")],
            Step::Module { name } => vec![format!("modprobe {name}")],
            Step::IrqAffinity { pairs, .. } => pairs
                .iter()
                .map(|(i, c)| format!("echo {c} > /proc/irq/{i}/smp_affinity_list"))
                .collect(),
        }
    }

    fn features_argv(&self, iface: &str, want: &[(String, bool)]) -> Vec<String> {
        let mut a = sv(&["ethtool", "-K", iface]);
        for (f, v) in want {
            a.push(f.clone());
            a.push(onoff(*v).into());
        }
        a
    }

    /// Target value in the same notation as [`Probe::current`].
    pub fn target(&self) -> String {
        match self {
            Step::Sysctl { want, cmp, .. } => {
                format!("{}{want}", if *cmp == Cmp::AtLeast { ">= " } else { "" })
            }
            Step::Write { want, .. } => want.clone(),
            Step::Features { want, .. } => want
                .iter()
                .map(|(f, v)| format!("{f}={}", onoff(*v)))
                .collect::<Vec<_>>()
                .join(" "),
            Step::Rings { rx, tx, .. } => format!("rx {rx} tx {tx}"),
            Step::Channels { combined, .. } => format!("combined {combined}"),
            Step::TcpDataSplit { .. } => "on".into(),
            Step::RssEqual { queues, .. } => format!("queues 0-{}", queues.saturating_sub(1)),
            Step::FlowRules {
                start,
                count,
                ports,
                ..
            } => format!(
                "ports {} -> queues {start}-{}",
                ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                start + count.saturating_sub(1)
            ),
            Step::LinkFlagsOff { .. } => "promisc off allmulti off".into(),
            Step::Governor { want } => want.clone(),
            Step::CpuIdleMax { max } => format!("no C-state deeper than {max}"),
            Step::Mount { target, .. } => format!("mounted at {target}"),
            Step::Module { name } => format!("{name} loaded"),
            Step::IrqAffinity { pairs, .. } => format!("{} irqs pinned", pairs.len()),
        }
    }

    pub fn persist(&self) -> Persist {
        match self {
            Step::Sysctl { key, want, .. } => Persist::Sysctl(format!("{key} = {want}")),
            Step::Module { name } => Persist::Module(name.clone()),
            Step::Mount {
                fstype,
                dev,
                target,
            } => Persist::Fstab(format!("{dev} {target} {fstype} defaults 0 0")),
            _ => Persist::Boot,
        }
    }

    /// One-way fixes are not restored by `--revert` (the prior state is the hygiene violation).
    pub fn revertable(&self) -> bool {
        !matches!(self, Step::LinkFlagsOff { .. })
    }

    /// Reads the current state. None = not readable (command missing, no such file); treated as not done.
    pub fn probe<X: Runner>(&self, h: &mut HostSys<X>) -> Option<Probe> {
        match self {
            Step::Sysctl { key, want, cmp } => {
                let cur = h.read(&format!("proc/sys/{}", key.replace('.', "/")))?;
                let done = match cmp {
                    Cmp::Eq => cur == *want,
                    Cmp::AtLeast => {
                        matches!((cur.parse::<u64>(), want.parse::<u64>()), (Ok(c), Ok(w)) if c >= w)
                    }
                };
                Some(Probe { current: cur, done })
            }
            Step::Write {
                path,
                want,
                bracket,
            } => {
                let raw = h.read(path)?;
                let cur = if *bracket { bracket_sel(&raw) } else { raw };
                Some(Probe {
                    done: cur == *want,
                    current: cur,
                })
            }
            Step::Features { iface, want } => {
                let out = h.exec(&sv(&["ethtool", "-k", iface])).ok()?;
                let cur: Vec<(String, Option<bool>)> = want
                    .iter()
                    .map(|(f, _)| (f.clone(), parse_feature(&out, f)))
                    .collect();
                let done = want.iter().zip(&cur).all(|((_, w), (_, c))| *c == Some(*w));
                Some(Probe {
                    current: cur
                        .iter()
                        .map(|(f, c)| format!("{f}={}", c.map_or("?", onoff)))
                        .collect::<Vec<_>>()
                        .join(" "),
                    done,
                })
            }
            Step::Rings { iface, rx, tx } => {
                let (r, t, _) = parse_rings(&h.exec(&sv(&["ethtool", "-g", iface])).ok()?);
                Some(Probe {
                    current: format!(
                        "rx {} tx {}",
                        r.map_or("?".into(), |v| v.to_string()),
                        t.map_or("?".into(), |v| v.to_string())
                    ),
                    done: r.is_some_and(|v| v >= *rx) && t.is_some_and(|v| v >= *tx),
                })
            }
            Step::Channels { iface, combined } => {
                let c = parse_combined(&h.exec(&sv(&["ethtool", "-l", iface])).ok()?)?;
                Some(Probe {
                    current: format!("combined {c}"),
                    done: c == *combined,
                })
            }
            Step::TcpDataSplit { iface } => {
                let (_, _, t) = parse_rings(&h.exec(&sv(&["ethtool", "-g", iface])).ok()?);
                let t = t?;
                Some(Probe {
                    done: t == "on",
                    current: t,
                })
            }
            Step::RssEqual { iface, queues } => {
                let q = parse_indir(&h.exec(&sv(&["ethtool", "-x", iface])).ok()?);
                let max = q.iter().copied().max()?;
                Some(Probe {
                    current: format!("queues 0-{max}"),
                    done: max + 1 == *queues && (0..*queues).all(|i| q.contains(&i)),
                })
            }
            Step::FlowRules { iface, ports, .. } => {
                let out = h.exec(&sv(&["ethtool", "-n", iface])).ok()?;
                let have: Vec<&u16> = ports
                    .iter()
                    .filter(|p| out.contains(&format!("Dest port: {p}")))
                    .collect();
                Some(Probe {
                    current: format!("{}/{} port rules", have.len(), ports.len()),
                    done: have.len() == ports.len(),
                })
            }
            Step::LinkFlagsOff { iface } => {
                let fl = h.read(&format!("sys/class/net/{iface}/flags"))?;
                let fl = u32::from_str_radix(fl.trim_start_matches("0x"), 16).ok()?;
                Some(Probe {
                    current: format!(
                        "promisc={} allmulti={}",
                        onoff(fl & 0x100 != 0),
                        onoff(fl & 0x200 != 0)
                    ),
                    done: fl & 0x300 == 0,
                })
            }
            Step::Governor { want } => {
                let g = h.read("sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")?;
                Some(Probe {
                    done: g == *want,
                    current: g,
                })
            }
            Step::CpuIdleMax { max } => {
                let all = cpuidle_files(&h.fs);
                if all.is_empty() {
                    return None;
                }
                let open: Vec<String> = all
                    .iter()
                    .filter(|(_, k)| k > max)
                    .filter(|(p, _)| h.read(p).as_deref() == Some("0"))
                    .map(|(p, _)| p.clone())
                    .collect();
                let deep = all.iter().filter(|(_, k)| k > max).count();
                Some(Probe {
                    current: format!("{} of {deep} deeper state files still enabled", open.len()),
                    done: open.is_empty(),
                })
            }
            Step::Mount { fstype, target, .. } => {
                let m = h.read("proc/mounts")?;
                let on = m.lines().any(|l| {
                    let mut w = l.split_whitespace().skip(1);
                    w.next() == Some(target.as_str()) && w.next() == Some(fstype.as_str())
                });
                Some(Probe {
                    current: if on { "mounted" } else { "not mounted" }.into(),
                    done: on,
                })
            }
            Step::Module { name } => {
                let on =
                    h.fs.exists(&format!("sys/module/{}", name.replace('-', "_")));
                Some(Probe {
                    current: if on { "loaded" } else { "not loaded" }.into(),
                    done: on,
                })
            }
            Step::IrqAffinity { pairs, .. } => {
                let cur: Vec<Option<String>> = pairs
                    .iter()
                    .map(|(i, _)| h.read(&format!("proc/irq/{i}/smp_affinity_list")))
                    .collect();
                let done = pairs
                    .iter()
                    .zip(&cur)
                    .all(|((_, c), v)| v.as_deref() == Some(&c.to_string()));
                let on: Vec<String> = pairs
                    .iter()
                    .zip(&cur)
                    .map(|((i, _), v)| format!("{i}:{}", v.as_deref().unwrap_or("?")))
                    .collect();
                Some(Probe {
                    current: on.join(" "),
                    done,
                })
            }
        }
    }

    /// Runs the change and retains undo for each successful mutation even on failure.
    pub fn apply<X: Runner>(
        &self,
        h: &mut HostSys<X>,
        undo: &mut Vec<RevertOp>,
    ) -> Result<(), String> {
        let completed: Result<Vec<RevertOp>, String> = match self {
            Step::Sysctl { key, want, .. } => {
                let prior = h.read(&format!("proc/sys/{}", key.replace('.', "/")));
                h.exec(&sv(&["sysctl", "-w", &format!("{key}={want}")]))?;
                Ok(prior
                    .map(|p| RevertOp::Exec(sv(&["sysctl", "-w", &format!("{key}={p}")])))
                    .into_iter()
                    .collect())
            }
            Step::Write {
                path,
                want,
                bracket,
            } => {
                let prior = h
                    .read(path)
                    .map(|r| if *bracket { bracket_sel(&r) } else { r });
                h.write(path, want)?;
                Ok(prior
                    .map(|value| RevertOp::Write {
                        path: path.clone(),
                        value,
                    })
                    .into_iter()
                    .collect())
            }
            Step::Features { iface, want } => {
                let out = h.exec(&sv(&["ethtool", "-k", iface])).unwrap_or_default();
                let undo: Vec<(String, bool)> = want
                    .iter()
                    .filter_map(|(f, w)| {
                        parse_feature(&out, f)
                            .filter(|c| c != w)
                            .map(|c| (f.clone(), c))
                    })
                    .collect();
                h.exec(&self.features_argv(iface, want))?;
                Ok(if undo.is_empty() {
                    vec![]
                } else {
                    vec![RevertOp::Exec(self.features_argv(iface, &undo))]
                })
            }
            Step::Rings { iface, rx, tx } => {
                let (r, t, _) =
                    parse_rings(&h.exec(&sv(&["ethtool", "-g", iface])).unwrap_or_default());
                h.exec(&sv(&[
                    "ethtool",
                    "-G",
                    iface,
                    "rx",
                    &rx.to_string(),
                    "tx",
                    &tx.to_string(),
                ]))?;
                Ok(match (r, t) {
                    (Some(r), Some(t)) => vec![RevertOp::Exec(sv(&[
                        "ethtool",
                        "-G",
                        iface,
                        "rx",
                        &r.to_string(),
                        "tx",
                        &t.to_string(),
                    ]))],
                    _ => vec![],
                })
            }
            Step::Channels { iface, combined } => {
                let prior =
                    parse_combined(&h.exec(&sv(&["ethtool", "-l", iface])).unwrap_or_default());
                h.exec(&sv(&[
                    "ethtool",
                    "-L",
                    iface,
                    "combined",
                    &combined.to_string(),
                ]))?;
                Ok(prior
                    .map(|c| {
                        RevertOp::Exec(sv(&["ethtool", "-L", iface, "combined", &c.to_string()]))
                    })
                    .into_iter()
                    .collect())
            }
            Step::TcpDataSplit { iface } => {
                let prior =
                    parse_rings(&h.exec(&sv(&["ethtool", "-g", iface])).unwrap_or_default()).2;
                h.exec(&sv(&["ethtool", "-G", iface, "tcp-data-split", "on"]))?;
                Ok(match prior.as_deref() {
                    Some(p @ ("off" | "auto")) => {
                        vec![RevertOp::Exec(sv(&[
                            "ethtool",
                            "-G",
                            iface,
                            "tcp-data-split",
                            p,
                        ]))]
                    }
                    _ => vec![],
                })
            }
            Step::RssEqual { iface, queues } => {
                h.exec(&sv(&["ethtool", "-X", iface, "equal", &queues.to_string()]))?;
                // the prior table is not reproducible by a command: the revert restores the driver default
                Ok(vec![RevertOp::Exec(sv(&[
                    "ethtool", "-X", iface, "default",
                ]))])
            }
            Step::FlowRules {
                iface,
                start,
                count,
                ports,
            } => {
                let out = h.exec(&sv(&[
                    "ethtool",
                    "-X",
                    iface,
                    "context",
                    "new",
                    "start",
                    &start.to_string(),
                    "equal",
                    &count.to_string(),
                ]))?;
                let ctx = number_after(&out, "New RSS context is").ok_or_else(|| {
                    format!("ethtool -X {iface} context new: no context id in output {out:?}")
                })?;
                let ctx_s = ctx.to_string();
                undo.push(RevertOp::Exec(sv(&[
                    "ethtool", "-X", iface, "context", &ctx_s, "delete",
                ])));
                for p in ports {
                    let r = h.exec(&sv(&[
                        "ethtool",
                        "-N",
                        iface,
                        "flow-type",
                        "tcp4",
                        "dst-port",
                        &p.to_string(),
                        "context",
                        &ctx_s,
                    ]));
                    match r {
                        Ok(o) => {
                            let id = number_after(&o, "Added rule with ID").ok_or_else(|| {
                                format!("recovery required: ethtool -N {iface} succeeded but returned no rule id; inspect ethtool -n {iface} before reverting context {ctx}")
                            })?;
                            {
                                undo.insert(
                                    0,
                                    RevertOp::Exec(sv(&[
                                        "ethtool",
                                        "-N",
                                        iface,
                                        "delete",
                                        &id.to_string(),
                                    ])),
                                );
                            }
                        }
                        Err(e) => {
                            return Err(format!(
                                "{e} (partial: undo with --revert; the context {ctx} stays until then)"
                            ));
                        }
                    }
                }
                return Ok(());
            }
            Step::LinkFlagsOff { iface } => {
                h.exec(&sv(&[
                    "ip",
                    "link",
                    "set",
                    iface,
                    "promisc",
                    "off",
                    "allmulticast",
                    "off",
                ]))?;
                Ok(vec![])
            }
            Step::Governor { want } => {
                let prior = h.read("sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
                h.exec(&sv(&["cpupower", "frequency-set", "-g", want]))?;
                Ok(prior
                    .map(|p| RevertOp::Exec(sv(&["cpupower", "frequency-set", "-g", &p])))
                    .into_iter()
                    .collect())
            }
            Step::CpuIdleMax { max } => {
                for (path, _) in cpuidle_files(&h.fs).into_iter().filter(|(_, k)| k > max) {
                    if let Some(prior) = h.read(&path).filter(|p| p != "1") {
                        h.write(&path, "1")?;
                        undo.insert(0, RevertOp::Write { path, value: prior });
                    }
                }
                return Ok(());
            }
            Step::Mount {
                fstype,
                dev,
                target,
            } => {
                h.exec(&sv(&["mount", "-t", fstype, dev, target]))?;
                Ok(vec![RevertOp::Exec(sv(&["umount", target]))])
            }
            Step::Module { name } => {
                h.exec(&sv(&["modprobe", name]))?;
                Ok(vec![RevertOp::Exec(sv(&["modprobe", "-r", name]))])
            }
            Step::IrqAffinity { pairs, .. } => {
                for (irq, cpu) in pairs {
                    let path = format!("proc/irq/{irq}/smp_affinity_list");
                    let prior = h.read(&path);
                    h.write(&path, &cpu.to_string())?;
                    if let Some(value) = prior {
                        undo.insert(0, RevertOp::Write { path, value });
                    }
                }
                return Ok(());
            }
        };
        undo.extend(completed?);
        Ok(())
    }
}

/// The steps that fix one check, plus context. Display and execution both read the steps.
#[derive(Clone, Debug)]
pub struct Action {
    pub steps: Vec<Step>,
    /// Extra operator text (why this value, side effects); not executed.
    pub note: String,
    /// Part of the zcrx path (adr 0464), not of the baseline host contract.
    pub zcrx: bool,
}

impl Action {
    pub fn new(steps: Vec<Step>) -> Action {
        Action {
            steps,
            note: String::new(),
            zcrx: false,
        }
    }
    pub fn note(mut self, n: impl Into<String>) -> Action {
        self.note = n.into();
        self
    }
    pub fn zcrx(mut self) -> Action {
        self.zcrx = true;
        self
    }
    /// The `fix` text: the commands, then the note.
    pub fn fix_text(&self) -> String {
        let cmds = self
            .steps
            .iter()
            .flat_map(Step::commands)
            .collect::<Vec<_>>()
            .join("; ");
        if self.note.is_empty() {
            cmds
        } else {
            format!("{cmds} ({})", self.note)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers() {
        let g = "Ring parameters for eth0:\nPre-set maximums:\nRX:\t\t8191\nTX:\t\t2047\nCurrent hardware settings:\nRX:\t\t511\nTX:\t\t511\nTCP data split:\toff\n";
        assert_eq!(parse_rings(g), (Some(511), Some(511), Some("off".into())));
        assert_eq!(
            parse_combined(
                "Pre-set maximums:\nCombined:\t16\nCurrent hardware settings:\nCombined:\t8\n"
            ),
            Some(8)
        );
        assert_eq!(
            parse_indir(
                "RX flow hash indirection table for e with 4 RX ring(s):\n    0:      0     1     2     3\n    4:      0     1\nRSS hash key:\n"
            ),
            vec![0, 1, 2, 3, 0, 1]
        );
        assert_eq!(
            parse_feature("rx-gro-hw: off\ngeneric-receive-offload: on\n", "gro"),
            Some(true)
        );
        assert_eq!(
            parse_feature("rx-gro-hw: off [fixed]\n", "rx-gro-hw"),
            Some(false)
        );
        assert_eq!(
            number_after("New RSS context is 3\n", "New RSS context is"),
            Some(3)
        );
        assert_eq!(bracket_sel("always [madvise] never"), "madvise");
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A bare program name is resolved in the fixed system directories, never through the inherited `PATH`: a foreign
    /// binary earlier in `PATH` must not run (host-tune applies as root). Runs itself as a child with a poisoned PATH.
    #[test]
    fn root_commands_do_not_resolve_through_path() {
        let Ok(marker) = std::env::var("PROCRUNNER_PATH_CHILD") else {
            let dir = std::env::temp_dir().join(format!("hwcheck-path-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let marker = dir.join("ran");
            let evil = dir.join("hwcheck-fake-cmd");
            std::fs::write(&evil, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
            std::fs::set_permissions(&evil, std::fs::Permissions::from_mode(0o755)).unwrap();
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "action::path_tests::root_commands_do_not_resolve_through_path",
                ])
                .env("PROCRUNNER_PATH_CHILD", &marker)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(!marker.exists(), "the PATH binary ran as root");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        };
        let dir = Path::new(&marker).parent().unwrap().to_path_buf();
        // SAFETY: the child is a dedicated single-threaded test process for this one check.
        unsafe { std::env::set_var("PATH", &dir) };
        let r = ProcRunner.run(&["hwcheck-fake-cmd".into(), marker.clone()]);
        std::process::exit(i32::from(r.is_ok() || Path::new(&marker).exists()));
    }

    #[test]
    fn absolute_programs_are_taken_as_given_and_relative_slashes_refused() {
        assert_eq!(resolve("/bin/sh"), Some(PathBuf::from("/bin/sh")));
        assert_eq!(resolve("./sh"), None);
        assert_eq!(resolve("sub/sh"), None);
    }
}
