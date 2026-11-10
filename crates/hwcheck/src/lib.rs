// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Read-only host/hardware readiness check (adr 0166). `croit-flashstore-osd --check`, `croit-flashstore-osd check`, `croit-flashstore-tool hwcheck`.
//!
//! Everything is read from sysfs/procfs below a root directory (`/` live, a fixture tree in tests); the few live-only
//! probes (io_uring capability test, NVMe Identify ioctl, ethtool offload gets) are skipped for a fake root. Nothing
//! is bound, mapped, written or configured.
use serde_json::{Value, json};
use std::path::PathBuf;

pub mod action;
mod buildinfo;
mod conf;
mod cpu;
mod fs;
pub mod hostcfg;
mod iommu;
mod mem;
mod net;
mod nvmecheck;
mod oscheck;
mod rdma;
mod render;
mod startup;
mod summary;
pub mod tune;
#[cfg(test)]
mod tune_tests;

pub use fs::Fs;
pub use outfmt::Format;
pub use rdma::DEFAULT_TOS as RDMA_DEFAULT_TOS;
pub use render::render;
pub use startup::{NicInfo, nic_info, rdma_startup_warnings, startup_warnings};

/// JSON schema version (`schema` field). Bump on any incompatible change of field names/meaning.
pub const SCHEMA: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Ok,
    Na,
    Warn,
    Fail,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Na => "N/A",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

/// One finding. `why` = what it is needed for; `fix` = operator hint (WARN/FAIL only).
#[derive(Clone, Debug)]
pub struct Check {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub value: String,
    pub why: String,
    pub fix: Option<String>,
    /// Mechanical form of `fix` (host-tune applies it); empty = manual fix. `fix` is rendered from it.
    pub actions: Vec<action::Action>,
    /// Performance impact 0..9 (ranks the "top fixes"); not part of the JSON.
    pub weight: u8,
}

impl Check {
    pub fn new(id: impl Into<String>, title: impl Into<String>) -> Check {
        Check {
            id: id.into(),
            title: title.into(),
            status: Status::Ok,
            value: String::new(),
            why: String::new(),
            fix: None,
            actions: Vec::new(),
            weight: 0,
        }
    }
    pub fn val(mut self, v: impl Into<String>) -> Check {
        self.value = v.into();
        self
    }
    pub fn why(mut self, v: impl Into<String>) -> Check {
        self.why = v.into();
        self
    }
    pub fn fix(mut self, v: impl Into<String>) -> Check {
        self.fix = Some(v.into());
        self
    }
    /// Mechanically applicable fix: sets the `fix` text from the action's commands.
    pub fn act(mut self, a: action::Action) -> Check {
        self.fix = Some(a.fix_text());
        self.actions.push(a);
        self
    }
    pub fn w(mut self, w: u8) -> Check {
        self.weight = w;
        self
    }
    pub fn st(mut self, s: Status) -> Check {
        self.status = s;
        self
    }
    pub fn ok(self) -> Check {
        self.st(Status::Ok)
    }
    pub fn warn(self) -> Check {
        self.st(Status::Warn)
    }
    pub fn fail(self) -> Check {
        self.st(Status::Fail)
    }
    pub fn na(self) -> Check {
        self.st(Status::Na)
    }
    /// WARN when `bad`, else OK.
    pub fn warn_if(self, bad: bool) -> Check {
        self.st(if bad { Status::Warn } else { Status::Ok })
    }
}

#[derive(Clone, Debug)]
pub struct Section {
    pub name: &'static str,
    pub checks: Vec<Check>,
}

/// A network/storage tier and whether this host can run it.
#[derive(Clone, Debug)]
pub struct Tier {
    pub name: &'static str,
    pub usable: bool,
    pub detail: String,
}

#[derive(Debug)]
pub struct Report {
    pub build_id: String,
    pub root: String,
    pub sections: Vec<Section>,
    pub tiers: Vec<Tier>,
    /// (check id, fix) of the up to three most valuable fixes.
    pub top_fixes: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub root: PathBuf,
    /// OSD conf (`[global]`/`[osd]`/`[osd.N]`), relative to the root unless absolute and existing there.
    pub conf: PathBuf,
    /// Version/git string of the calling binary.
    pub build_id: String,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            root: "/".into(),
            conf: "/etc/ceph/ceph.conf".into(),
            build_id: String::new(),
        }
    }
}

/// Facts shared between sections (tier verdicts, cross checks).
#[derive(Default, Debug)]
pub(crate) struct Facts {
    pub live: bool,
    pub hugepages_free_mb: u64,
    pub iommu_groups: usize,
    pub vfio: bool,
    pub uio: bool,
    pub knet_probe: Option<Result<(), String>>,
    pub nic_total: usize,
    pub nvme_total: usize,
    pub nvme_userspace: usize,
    pub nvme_kernel: usize,
    pub cpu_numa: Vec<(u32, Vec<u32>)>,
}

pub fn run(o: &Options) -> Report {
    let fsr = Fs::new(&o.root);
    let mut facts = Facts {
        live: fsr.live(),
        ..Default::default()
    };
    let cfg = conf::load(&fsr, &o.conf);
    let mut sections = vec![buildinfo::section(&o.build_id)];
    sections.push(cpu::section(&fsr, &cfg, &mut facts));
    sections.push(mem::section(&fsr, &cfg, &mut facts));
    sections.push(iommu::section(&fsr, &mut facts));
    sections.push(nvmecheck::section(&fsr, &cfg, &mut facts));
    sections.push(net::section(&fsr, &mut facts));
    sections.push(rdma::section(&fsr));
    sections.push(oscheck::section(&fsr, &mut facts));
    sections.push(conf::section(&fsr, &cfg, &facts));
    let tiers = summary::tiers(&sections, &facts);
    let top_fixes = summary::top_fixes(&sections);
    Report {
        build_id: o.build_id.clone(),
        root: o.root.display().to_string(),
        sections,
        tiers,
        top_fixes,
    }
}

impl Report {
    pub fn count(&self, s: Status) -> usize {
        self.sections
            .iter()
            .flat_map(|x| &x.checks)
            .filter(|c| c.status == s)
            .count()
    }
    /// 0 = no FAIL (WARN alone passes), 1 = at least one FAIL.
    pub fn exit_code(&self) -> i32 {
        i32::from(self.count(Status::Fail) > 0)
    }
    /// Stable machine form, documented in doc/ops/hwcheck.md.
    pub fn to_json(&self) -> Value {
        json!({
            "schema": SCHEMA,
            "version": self.build_id,
            "root": self.root,
            "summary": {
                "ok": self.count(Status::Ok), "warn": self.count(Status::Warn),
                "fail": self.count(Status::Fail), "na": self.count(Status::Na),
                "exit_code": self.exit_code(),
            },
            "sections": self.sections.iter().map(|s| json!({
                "name": s.name,
                "checks": s.checks.iter().map(|c| json!({
                    "id": c.id, "title": c.title, "status": c.status.as_str(),
                    "value": c.value, "why": c.why,
                    // nothing to do on OK/N/A: the contract is `fix` null there
                    "fix": c.fix.as_ref().filter(|_| c.status >= Status::Warn),
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "tiers": self.tiers.iter().map(|t| json!({
                "name": t.name, "usable": t.usable, "detail": t.detail,
            })).collect::<Vec<_>>(),
            "top_fixes": self.top_fixes.iter().map(|(id, fix)| json!({"id": id, "fix": fix})).collect::<Vec<_>>(),
        })
    }
}

const USAGE: &str = "usage: hwcheck [--format plain|json|json-pretty] [--no-color] [--root DIR] [--conf FILE]\n  read-only host check; exit 0 = no FAIL (WARN passes), 1 = FAIL present, 2 = usage (doc/ops/hwcheck.md)";

/// CLI shared by `croit-flashstore-osd --check` and `croit-flashstore-tool hwcheck`: `args` are the flags after the subcommand.
pub fn cli(args: &[String], build_id: &str) -> i32 {
    let (format, args) = match outfmt::extract(args, false) {
        Ok(x) => x,
        Err(e) => return usage(&e),
    };
    let mut o = Options {
        build_id: build_id.to_string(),
        ..Default::default()
    };
    let mut color = true;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (k, inline) = match a.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (a.as_str(), None),
        };
        let mut val = || inline.clone().or_else(|| it.next().cloned());
        match k {
            "--no-color" => {
                if inline.is_some() {
                    return usage("--no-color takes no value");
                }
                color = false;
            }
            "--root" => match val() {
                Some(v) => o.root = v.into(),
                None => return usage("--root needs a value"),
            },
            "--conf" => match val() {
                Some(v) => o.conf = v.into(),
                None => return usage("--conf needs a value"),
            },
            "-h" | "--help" => {
                if inline.is_some() {
                    return usage("--help takes no value");
                }
                println!("{USAGE}");
                return 0;
            }
            _ => return usage(&format!("unknown argument {a:?}")),
        }
    }
    let r = run(&o);
    print!(
        "{}",
        render::render(&r, format, color && render::stdout_tty())
    );
    r.exit_code()
}

fn usage(msg: &str) -> i32 {
    eprintln!("hwcheck: {msg}\n{USAGE}");
    2
}
