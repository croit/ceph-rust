// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `croit-flashstore-tool host-tune` engine (adr 0465, adr 0464): plan, apply and revert of the host fixes hwcheck prints.
//! The OSD never runs this; the operator asks for it. Dry run is the default.
use crate::action::{Action, HostSys, Persist, ProcRunner, RevertOp, Runner, Step};
use crate::{Check, Options, Status};
use outfmt::Format;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// Exit codes (stable): 0 ok (a dry run is ok), 1 an action failed or a check is still not ok, 2 usage, 3 privileges.
pub const EXIT_OK: i32 = 0;
pub const EXIT_FAILED: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_PRIV: i32 = 3;

/// zcrx host setup parameters (spec knet-zcrx.md section 5): the zcrx queues are the top `queues` of `host_queues + queues`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zcrx {
    pub queues: u32,
    pub host_queues: u32,
    pub ports: Vec<u16>,
}

/// The ordered zcrx action of `iface` (check id `net.<iface>.zcrx`; not part of the baseline hwcheck verdicts).
pub fn zcrx_action(iface: &str, z: &Zcrx) -> Action {
    let i = iface.to_string();
    Action::new(vec![
        Step::TcpDataSplit { iface: i.clone() },
        Step::Features { iface: i.clone(), want: vec![("ntuple".into(), true)] },
        Step::Channels { iface: i.clone(), combined: z.host_queues + z.queues },
        Step::RssEqual { iface: i.clone(), queues: z.host_queues },
        Step::FlowRules { iface: i, start: z.host_queues, count: z.queues, ports: z.ports.clone() },
    ])
    .note("zcrx path only (adr 0464): header/data split, ntuple, channels, RSS excluding the zcrx queues, one RSS context + flow rule per OSD port; the channel change restarts the queues")
    .zcrx()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepState {
    /// Dry run: would change.
    Pending,
    /// Already as wanted: skipped.
    Ok,
    Applied,
    Failed(String),
    /// Not run: an earlier step of the action failed.
    NotRun,
}

impl StepState {
    fn name(&self) -> &'static str {
        match self {
            StepState::Pending => "pending",
            StepState::Ok => "ok",
            StepState::Applied => "applied",
            StepState::Failed(_) => "failed",
            StepState::NotRun => "not-run",
        }
    }
}

#[derive(Clone, Debug)]
pub struct StepPlan {
    pub step: Step,
    pub current: String,
    pub state: StepState,
}

#[derive(Clone, Debug)]
pub struct Item {
    pub check: String,
    pub title: String,
    pub status: Status,
    pub zcrx: bool,
    pub note: String,
    pub steps: Vec<StepPlan>,
    /// After an apply: `ok`, `not-ok` (the re-run check is still WARN/FAIL), `failed`.
    pub verdict: Option<&'static str>,
}

#[derive(Clone, Debug)]
pub struct Manual {
    pub check: String,
    pub title: String,
    pub status: Status,
    pub fix: String,
}

#[derive(Default, Debug)]
pub struct Plan {
    pub items: Vec<Item>,
    pub manual: Vec<Manual>,
}

/// Selection: check ids (exact or dotted prefix, empty = all) and the interface the interface-bound steps are limited to.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub checks: Vec<String>,
    pub iface: Option<String>,
}

impl Filter {
    fn id_ok(&self, id: &str) -> bool {
        self.checks.is_empty()
            || self.checks.iter().any(|c| {
                id == c
                    || id
                        .strip_prefix(c.as_str())
                        .is_some_and(|r| r.starts_with('.'))
            })
    }
    fn iface_ok(&self, a: &Action) -> bool {
        let Some(want) = &self.iface else { return true };
        a.steps.iter().all(|s| s.iface().is_none_or(|i| i == want))
    }
}

fn item<X: Runner>(
    h: &mut HostSys<X>,
    check: &str,
    title: &str,
    status: Status,
    a: &Action,
) -> Item {
    let steps = a
        .steps
        .iter()
        .map(|s| {
            let p = s.probe(h);
            StepPlan {
                step: s.clone(),
                current: p.as_ref().map_or("?".into(), |p| p.current.clone()),
                state: if p.is_some_and(|p| p.done) {
                    StepState::Ok
                } else {
                    StepState::Pending
                },
            }
        })
        .collect();
    Item {
        check: check.into(),
        title: title.into(),
        status,
        zcrx: a.zcrx,
        note: a.note.clone(),
        steps,
        verdict: None,
    }
}

/// Builds the plan from the checks (WARN/FAIL with a fix) and the optional zcrx action.
pub fn plan<X: Runner>(
    h: &mut HostSys<X>,
    checks: &[Check],
    f: &Filter,
    zcrx: Option<(&str, &Zcrx)>,
) -> Plan {
    let mut p = Plan::default();
    for c in checks
        .iter()
        .filter(|c| c.status >= Status::Warn && c.fix.is_some() && f.id_ok(&c.id))
    {
        if c.actions.is_empty() {
            p.manual.push(Manual {
                check: c.id.clone(),
                title: c.title.clone(),
                status: c.status,
                fix: c.fix.clone().unwrap_or_default(),
            });
        }
        for a in c.actions.iter().filter(|a| f.iface_ok(a)) {
            p.items.push(item(h, &c.id, &c.title, c.status, a));
        }
    }
    if let Some((iface, z)) = zcrx {
        let id = format!("net.{iface}.zcrx");
        if f.id_ok(&id) {
            p.items.push(item(
                h,
                &id,
                &format!("{iface} zcrx host setup"),
                Status::Warn,
                &zcrx_action(iface, z),
            ));
        }
    }
    p
}

/// State file (JSON): every applied step with the operations that restore the state read just before it.
/// One file per `--state` path across runs: a later apply appends (its "prior" values are the earlier run's
/// results, so `--revert` walking all entries newest first ends at the state before the first apply). Created on
/// the first applied step; every save replaces the file atomically (temp + fsync + rename).
#[derive(Debug)]
pub struct State {
    path: PathBuf,
    created: u64,
    entries: Vec<Value>,
}

/// One entry of the state file: `(check, command, revert operations)`.
fn entry(v: &Value) -> Option<(String, String, Vec<RevertOp>)> {
    let ops = v.get("revert")?.as_array()?;
    Some((
        v.get("check")?.as_str()?.to_string(),
        v.get("command")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        ops.iter().map(RevertOp::from_json).collect::<Option<_>>()?,
    ))
}

/// The parsed state file.
fn read(path: &Path) -> Result<Value, String> {
    let err = |e: String| format!("state file {}: {e}", path.display());
    let t = std::fs::read_to_string(path).map_err(|e| err(e.to_string()))?;
    serde_json::from_str(&t).map_err(|e| err(e.to_string()))
}

impl State {
    /// The state at `path`: its entries when the file exists, else empty (nothing is written yet).
    pub fn open(path: &Path) -> Result<State, String> {
        if !path.exists() {
            return Ok(State {
                path: path.into(),
                created: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
                entries: Vec::new(),
            });
        }
        trusted_state(path)?;
        let bad = || format!("state file {}: unexpected layout", path.display());
        let v = read(path)?;
        let entries = v.get("entries").and_then(Value::as_array).ok_or_else(bad)?;
        // never append to a file revert could not read
        for e in entries {
            entry(e).ok_or_else(bad)?;
        }
        Ok(State {
            path: path.into(),
            created: v.get("created").and_then(Value::as_u64).unwrap_or(0),
            entries: entries.clone(),
        })
    }
    fn save(&self, entries: &[Value]) -> Result<(), String> {
        let err = |e: std::io::Error| format!("state file {}: {e}", self.path.display());
        if let Some(d) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(d).map_err(|e| format!("state dir {}: {e}", d.display()))?;
        }
        let v = json!({"schema": 1, "created": self.created, "entries": entries});
        // root applies it later: only the applying uid may write, and only from a file only it can change
        osddir::write_atomic_mode(&self.path, v.to_string().as_bytes(), 0o600).map_err(err)
    }
    /// Writes the state file (current entries, possibly none) before the first step changes the host: a state path
    /// that cannot be written durably (read-only, no space, parent not creatable) refuses the whole apply while the
    /// host is still untouched. The undo values only exist once a step ran, so each step's entry is still saved right
    /// after it, and a failure there carries the undo operations in its error.
    pub fn preflight(&self) -> Result<(), String> {
        self.save(&self.entries)
    }
    /// Appends one undo entry and persists it: the entry is kept only when the file holds it (the file is the only
    /// revert source, so an in-memory entry that never reached it would be a lie).
    fn record(
        &mut self,
        check: &str,
        cmd: &str,
        current: &str,
        undo: &[RevertOp],
    ) -> Result<(), String> {
        let mut entries = self.entries.clone();
        entries.push(json!({
            "check": check, "command": cmd, "prior": current,
            "revert": undo.iter().map(RevertOp::to_json).collect::<Vec<_>>(),
        }));
        self.save(&entries)?;
        self.entries = entries;
        Ok(())
    }
    fn load(path: &Path) -> Result<Vec<(String, String, Vec<RevertOp>)>, String> {
        let bad = || format!("state file {}: unexpected layout", path.display());
        read(path)?
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(bad)?
            .iter()
            .map(|e| entry(e).ok_or_else(bad))
            .collect()
    }
}

/// Runs every pending step (in order; a failing step stops its action), records the undo operations, then sets the
/// verdicts: from `after` (the re-run hwcheck checks) where the check exists there, else by re-probing the steps.
/// A state file that cannot be written refuses the apply before anything changes.
pub fn apply<X: Runner>(
    h: &mut HostSys<X>,
    p: &mut Plan,
    st: &mut State,
    after: impl FnOnce() -> Vec<Check>,
) -> Result<(), String> {
    if p.items
        .iter()
        .flat_map(|i| &i.steps)
        .any(|s| s.state == StepState::Pending)
    {
        st.preflight()?;
    }
    for it in &mut p.items {
        let mut failed = false;
        for sp in &mut it.steps {
            if failed {
                sp.state = StepState::NotRun;
            } else if sp.state == StepState::Pending {
                let mut undo = Vec::new();
                let result = sp.step.apply(h, &mut undo);
                if !undo.is_empty() {
                    let cmd = sp.step.commands().join("; ");
                    st.record(&it.check, &cmd, &sp.current, &undo)
                        .map_err(|e| {
                            let ops: Vec<Value> = undo.iter().map(RevertOp::to_json).collect();
                            format!(
                                "{e}; `{cmd}` already changed the host: revert it by hand with these operations (newest first): {}",
                                Value::Array(ops)
                            )
                        })?;
                }
                match result {
                    Ok(()) => {
                        sp.state = StepState::Applied;
                    }
                    Err(e) => {
                        sp.state = StepState::Failed(e);
                        failed = true;
                    }
                }
            }
        }
        if failed {
            it.verdict = Some("failed");
        }
    }
    let after = after();
    for it in p.items.iter_mut().filter(|i| i.verdict.is_none()) {
        let ok = match after.iter().find(|c| c.id == it.check) {
            Some(c) => c.status < Status::Warn,
            None => it
                .steps
                .iter()
                .all(|s| s.step.probe(h).is_some_and(|p| p.done)),
        };
        it.verdict = Some(if ok { "ok" } else { "not-ok" });
    }
    Ok(())
}

#[derive(Debug)]
pub struct RevertRow {
    pub check: String,
    pub op: String,
    pub error: Option<String>,
}

/// A state file is applied as root: refuse one this uid does not own or that another user can change. The file is
/// written `0600`; a plain file owned by the effective uid without group/other write is trusted.
fn trusted_state(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let m = std::fs::symlink_metadata(path)
        .map_err(|e| format!("state file {}: {e}", path.display()))?;
    if !m.file_type().is_file() {
        return Err(format!(
            "refused: state file {} is not a regular file (symlink or special file)",
            path.display()
        ));
    }
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    if m.uid() != me {
        return Err(format!(
            "refused: state file {} is owned by uid {}, not by the running uid {me}",
            path.display(),
            m.uid()
        ));
    }
    if m.mode() & 0o022 != 0 {
        return Err(format!(
            "refused: state file {} is group/other-writable (mode {:04o}); chmod 600 it",
            path.display(),
            m.mode() & 0o7777
        ));
    }
    Ok(())
}

/// Restores from a state file: entries last to first.
pub fn revert<X: Runner>(h: &mut HostSys<X>, state: &Path) -> Result<Vec<RevertRow>, String> {
    trusted_state(state)?;
    let mut rows = Vec::new();
    for (check, _cmd, ops) in State::load(state)?.into_iter().rev() {
        for op in ops {
            let error = op.run(h).err();
            rows.push(RevertRow {
                check: check.clone(),
                op: op.describe(),
                error,
            });
        }
    }
    Ok(rows)
}

/// What a persistent setup needs (`--emit-persist`); the tool never installs it.
pub fn persist(p: &Plan, state: &Path, unit_args: &[String]) -> Value {
    let (mut sysctl, mut modules, mut fstab, mut boot) = (vec![], vec![], vec![], vec![]);
    for s in p.items.iter().flat_map(|i| &i.steps) {
        match s.step.persist() {
            Persist::Sysctl(l) => sysctl.push(l),
            Persist::Module(l) => modules.push(l),
            Persist::Fstab(l) => fstab.push(l),
            Persist::Boot => boot.extend(s.step.commands()),
        }
    }
    let unit = (!boot.is_empty()).then(|| {
        format!(
            "[Unit]\nDescription=croit-flashstore-osd host tuning (NIC, IRQ and sysfs settings; idempotent)\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/croit-flashstore-tool host-tune --apply --state {} {}\n\n[Install]\nWantedBy=multi-user.target\n",
            state.display(),
            unit_args.join(" ")
        )
    });
    json!({
        "sysctl_d": {"file": "/etc/sysctl.d/90-croit-flashstore-osd.conf", "lines": sysctl},
        "modules_load_d": {"file": "/etc/modules-load.d/croit-flashstore-osd.conf", "lines": modules},
        "fstab": {"file": "/etc/fstab", "lines": fstab},
        "boot_unit": {"file": "/etc/systemd/system/croit-flashstore-host-tune.service", "text": unit, "covers": boot},
        "note": "not installed by host-tune; the unit re-runs the same idempotent plan at boot. Manual items (BIOS, kernel cmdline, hardware) need their own persistence.",
    })
}

fn item_json(i: &Item) -> Value {
    json!({
        "check": i.check, "title": i.title, "status": i.status.as_str(), "kind": "applicable", "zcrx": i.zcrx,
        "note": i.note, "verdict": i.verdict,
        "steps": i.steps.iter().map(|s| {
            let mut v = json!({
                "commands": s.step.commands(), "current": s.current, "target": s.step.target(),
                "state": s.state.name(), "reversible": s.step.revertable(),
            });
            if let StepState::Failed(e) = &s.state {
                v["error"] = json!(e);
            }
            v
        }).collect::<Vec<_>>(),
    })
}

fn plan_json(p: &Plan, mode: &str, state: Option<&Path>, code: i32) -> Value {
    let mut items: Vec<Value> = p.items.iter().map(item_json).collect();
    items.extend(p.manual.iter().map(|m| {
        json!({"check": m.check, "title": m.title, "status": m.status.as_str(), "kind": "manual", "fix": m.fix})
    }));
    json!({
        "schema": 1, "mode": mode, "state_file": state.map(|s| s.display().to_string()),
        "summary": {
            "applicable": p.items.len(), "manual": p.manual.len(),
            "pending_steps": p.items.iter().flat_map(|i| &i.steps).filter(|s| s.state == StepState::Pending).count(),
            "failed_steps": p.items.iter().flat_map(|i| &i.steps).filter(|s| matches!(s.state, StepState::Failed(_))).count(),
            "exit_code": code,
        },
        "items": items,
    })
}

fn plan_plain(p: &Plan, mode: &str, state: Option<&Path>) -> String {
    use std::fmt::Write;
    let mut o = String::new();
    let _ = writeln!(o, "host-tune {mode}");
    if let Some(s) = state {
        let _ = writeln!(o, "state file: {}", s.display());
    }
    for i in &p.items {
        let _ = writeln!(
            o,
            "[applicable{}] {}: {} ({}){}",
            if i.zcrx { ", zcrx" } else { "" },
            i.check,
            i.title,
            i.status.as_str(),
            i.verdict.map_or(String::new(), |v| format!(" -> {v}"))
        );
        for s in &i.steps {
            let _ = writeln!(
                o,
                "  {:<8} {} -> {}",
                s.state.name(),
                s.current,
                s.step.target()
            );
            for c in s.step.commands() {
                let _ = writeln!(o, "           {c}");
            }
            if let StepState::Failed(e) = &s.state {
                let _ = writeln!(o, "           error: {e}");
            }
            if !s.step.revertable() {
                let _ = writeln!(o, "           (one-way: --revert does not undo it)");
            }
        }
        if !i.note.is_empty() {
            let _ = writeln!(o, "  note: {}", i.note);
        }
    }
    for m in &p.manual {
        let _ = writeln!(
            o,
            "[manual] {}: {} ({}): {}",
            m.check,
            m.title,
            m.status.as_str(),
            m.fix
        );
    }
    if p.items.is_empty() && p.manual.is_empty() {
        let _ = writeln!(o, "nothing to do");
    }
    o
}

const USAGE: &str = "usage: croit-flashstore-tool host-tune [--check ID]... [--iface IF] [--apply] [--state FILE] [--revert [STATEFILE]] [--emit-persist]\n         [--zcrx-queues K --host-queues M --osd-port P...] [--root DIR] [--conf FILE] [--format plain|json|json-pretty]\n  dry run by default; --apply changes the host (root), --revert restores a state file (default: the --state default /var/lib/croit-flashstore/host-tune.json); exit 0 ok, 1 failed/not ok, 2 usage, 3 privileges (docs/how-to/tune-host.md)";

fn usage(msg: &str) -> i32 {
    eprintln!("host-tune: {msg}\n{USAGE}");
    EXIT_USAGE
}

#[derive(Debug, Default)]
struct Args {
    filter: Filter,
    apply: bool,
    revert: Option<PathBuf>,
    state: Option<PathBuf>,
    emit_persist: bool,
    zcrx_queues: Option<u32>,
    host_queues: Option<u32>,
    ports: Vec<u16>,
    root: Option<PathBuf>,
    conf: Option<PathBuf>,
}

fn parse(args: &[String]) -> Result<Option<Args>, String> {
    let mut a = Args::default();
    let mut it = args.iter().peekable();
    let mut bare_revert = false;
    while let Some(k) = it.next() {
        let mut val = |what: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{what} needs a value"))
        };
        let num = |s: String, what: &str| {
            s.parse::<u32>()
                .map_err(|_| format!("{what}: not a number: {s}"))
        };
        match k.as_str() {
            "--check" => a.filter.checks.push(val("--check")?),
            "--iface" => a.filter.iface = Some(val("--iface")?),
            "--apply" => a.apply = true,
            "--revert" => {
                // the operand is optional: bare `--revert` reads the `--state` file (default DEFAULT_STATE)
                bare_revert = true;
                if let Some(v) = it.next_if(|v| !v.starts_with("--")) {
                    a.revert = Some(v.into());
                }
            }
            "--state" => a.state = Some(val("--state")?.into()),
            "--emit-persist" => a.emit_persist = true,
            "--zcrx-queues" => a.zcrx_queues = Some(num(val("--zcrx-queues")?, "--zcrx-queues")?),
            "--host-queues" => a.host_queues = Some(num(val("--host-queues")?, "--host-queues")?),
            "--osd-port" => {
                let p = val("--osd-port")?;
                a.ports.push(
                    p.parse()
                        .map_err(|_| format!("--osd-port: not a port: {p}"))?,
                );
            }
            "--root" => a.root = Some(val("--root")?.into()),
            "--conf" => a.conf = Some(val("--conf")?.into()),
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(None);
            }
            o => return Err(format!("unknown argument {o:?}")),
        }
    }
    if bare_revert && a.revert.is_none() {
        a.revert = Some(a.state.clone().unwrap_or_else(|| DEFAULT_STATE.into()));
    }
    if a.revert.is_some() && (a.apply || a.emit_persist || a.zcrx_queues.is_some()) {
        return Err("--revert excludes --apply, --emit-persist and the zcrx flags".into());
    }
    if a.apply && a.emit_persist {
        return Err("--apply and --emit-persist are exclusive".into());
    }
    if (a.zcrx_queues.is_some() || a.host_queues.is_some() || !a.ports.is_empty())
        && (a.zcrx_queues.is_none()
            || a.host_queues.is_none()
            || a.ports.is_empty()
            || a.filter.iface.is_none())
    {
        return Err(
            "zcrx needs --iface, --zcrx-queues K, --host-queues M and at least one --osd-port"
                .into(),
        );
    }
    if a.zcrx_queues == Some(0) {
        return Err("--zcrx-queues must be >= 1".into());
    }
    if a.host_queues == Some(0) {
        return Err("--host-queues must be >= 1".into());
    }
    // the channels step is `host_queues + queues`: an overflowing sum would render a wrapped (or zero) queue count
    if let (Some(q), Some(h)) = (a.zcrx_queues, a.host_queues)
        && h.checked_add(q).is_none()
    {
        return Err("--host-queues + --zcrx-queues must fit in 32 bits".into());
    }
    Ok(Some(a))
}

/// True when this process may change NIC/sysctl/sysfs state: root, or all of CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_DAC_OVERRIDE.
#[cfg(unix)]
fn privileged() -> bool {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    let eff = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:").map(|v| v.trim().to_string()))
        })
        .and_then(|v| u64::from_str_radix(&v, 16).ok())
        .unwrap_or(0);
    let need = (1u64 << 12) | (1 << 21) | (1 << 1);
    eff & need == need
}

#[cfg(not(unix))]
fn privileged() -> bool {
    false
}

/// State file of `--apply` and `--revert` without `--state`: persistent (it must outlive a reboot, the boot unit
/// applies changes later), one file whose entries every apply appends to.
pub const DEFAULT_STATE: &str = "/var/lib/croit-flashstore/host-tune.json";

/// CLI of `croit-flashstore-tool host-tune`: `args` are the flags after the subcommand.
pub fn cli(args: &[String]) -> i32 {
    cli_with(args, ProcRunner)
}

/// [`cli`] with an injected command runner (tests).
pub fn cli_with<X: Runner>(args: &[String], runner: X) -> i32 {
    let (format, args) = match outfmt::extract(args, false) {
        Ok(x) => x,
        Err(e) => return usage(&e),
    };
    let a = match parse(&args) {
        Ok(Some(a)) => a,
        Ok(None) => return EXIT_OK,
        Err(e) => return usage(&e),
    };
    let root = a.root.clone().unwrap_or_else(|| "/".into());
    let mut h = HostSys::new(&root, runner);
    run_with(&mut h, &a, format, &root)
}

fn run_with<X: Runner>(h: &mut HostSys<X>, a: &Args, format: Format, root: &Path) -> i32 {
    let live = root == Path::new("/");
    let need_priv = |why: &str| {
        if live && !privileged() {
            eprintln!(
                "host-tune: {why} needs root (or CAP_NET_ADMIN + CAP_SYS_ADMIN + CAP_DAC_OVERRIDE); run it with sudo"
            );
            return true;
        }
        false
    };
    if let Some(sf) = &a.revert {
        if need_priv("--revert") {
            return EXIT_PRIV;
        }
        let rows = match revert(h, sf) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("host-tune: {e}");
                return EXIT_FAILED;
            }
        };
        let failed = rows.iter().filter(|r| r.error.is_some()).count();
        let code = i32::from(failed > 0);
        if format.is_json() {
            let v = json!({
                "schema": 1, "mode": "revert", "state_file": sf.display().to_string(),
                "summary": {"operations": rows.len(), "failed": failed, "exit_code": code},
                "operations": rows.iter().map(|r| json!({"check": r.check, "operation": r.op, "error": r.error})).collect::<Vec<_>>(),
            });
            println!("{}", format.doc(&v));
        } else {
            println!("host-tune revert {}", sf.display());
            for r in &rows {
                println!(
                    "  {:<6} [{}] {}{}",
                    if r.error.is_some() { "failed" } else { "ok" },
                    r.check,
                    r.op,
                    r.error.as_ref().map_or(String::new(), |e| format!(": {e}"))
                );
            }
            println!("{} operations, {failed} failed", rows.len());
        }
        return code;
    }
    let o = Options {
        root: root.into(),
        conf: a
            .conf
            .clone()
            .unwrap_or_else(|| "/etc/ceph/ceph.conf".into()),
        build_id: "host-tune".into(),
    };
    let report = crate::run(&o);
    let checks: Vec<Check> = report.sections.into_iter().flat_map(|s| s.checks).collect();
    let z = a
        .zcrx_queues
        .zip(a.host_queues)
        .map(|(queues, host_queues)| Zcrx {
            queues,
            host_queues,
            ports: a.ports.clone(),
        });
    let mut p = plan(
        h,
        &checks,
        &a.filter,
        a.filter.iface.as_deref().zip(z.as_ref()),
    );
    if a.emit_persist {
        let mut ua: Vec<String> = a
            .filter
            .checks
            .iter()
            .flat_map(|c| ["--check".into(), c.clone()])
            .collect();
        if let Some(i) = &a.filter.iface {
            ua.extend(["--iface".into(), i.clone()]);
        }
        if let Some(z) = &z {
            ua.extend([
                "--zcrx-queues".into(),
                z.queues.to_string(),
                "--host-queues".into(),
                z.host_queues.to_string(),
            ]);
            ua.extend(
                z.ports
                    .iter()
                    .flat_map(|p| ["--osd-port".into(), p.to_string()]),
            );
        }
        if let Some(c) = &a.conf {
            ua.extend(["--conf".into(), c.display().to_string()]);
        }
        let v = persist(
            &p,
            a.state.as_deref().unwrap_or(Path::new(DEFAULT_STATE)),
            &ua,
        );
        if format.is_json() {
            println!("{}", format.doc(&v));
        } else {
            for k in ["sysctl_d", "modules_load_d", "fstab"] {
                let lines: Vec<&str> = v[k]["lines"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                if !lines.is_empty() {
                    println!(
                        "# {}\n{}\n",
                        v[k]["file"].as_str().unwrap_or(""),
                        lines.join("\n")
                    );
                }
            }
            if let Some(u) = v["boot_unit"]["text"].as_str() {
                println!("# {}\n{u}", v["boot_unit"]["file"].as_str().unwrap_or(""));
            }
            println!("# {}", v["note"].as_str().unwrap_or(""));
        }
        return EXIT_OK;
    }
    if !a.apply {
        if format.is_json() {
            println!("{}", format.doc(&plan_json(&p, "plan", None, EXIT_OK)));
        } else {
            print!(
                "{}",
                plan_plain(&p, "plan (dry run; --apply changes the host)", None)
            );
        }
        return EXIT_OK;
    }
    let pending = p
        .items
        .iter()
        .flat_map(|i| &i.steps)
        .any(|s| s.state == StepState::Pending);
    if pending && need_priv("--apply") {
        return EXIT_PRIV;
    }
    let sf = a
        .state
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE));
    let mut st = match State::open(&sf) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("host-tune: {e}");
            return EXIT_FAILED;
        }
    };
    let after = || {
        crate::run(&o)
            .sections
            .into_iter()
            .flat_map(|s| s.checks)
            .collect()
    };
    if let Err(e) = apply(h, &mut p, &mut st, after) {
        eprintln!("host-tune: {e}");
        return EXIT_FAILED;
    }
    let bad = p.items.iter().any(|i| i.verdict != Some("ok"));
    let code = i32::from(bad);
    if format.is_json() {
        println!("{}", format.doc(&plan_json(&p, "apply", Some(&sf), code)));
    } else {
        print!("{}", plan_plain(&p, "apply", Some(&sf)));
        println!(
            "revert with: croit-flashstore-tool host-tune --revert {}",
            sf.display()
        );
    }
    code
}
