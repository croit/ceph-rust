// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! host-tune engine tests against a simulated NIC (fake command runner, static dispatch).
use crate::Check;
use crate::Status;
use crate::action::{Action, Cmp, HostSys, Runner, Step};
use crate::net::{offload_check, rings_check};
use crate::tune::*;
use std::path::{Path, PathBuf};

/// Simulated NIC `eth0`: rings, features, channels, RSS table, flow rules; every command is logged.
struct FakeNic {
    log: Vec<String>,
    rings: (u32, u32),
    feat: Vec<(String, bool)>,
    channels: u32,
    indir: u32,
    tds: String,
    rules: Vec<(u32, u16)>,
    fail_on: Option<String>,
    omit_rule_id: bool,
    /// Replaces this directory with a file on the first `ethtool -G` (a state path that breaks between steps).
    sabotage: Option<PathBuf>,
}

impl FakeNic {
    fn new() -> FakeNic {
        FakeNic {
            log: vec![],
            rings: (511, 511),
            feat: [
                ("rx-checksumming", true),
                ("tx-checksumming", true),
                ("tcp-segmentation-offload", true),
                ("generic-receive-offload", false),
                ("rx-gro-hw", false),
                ("ntuple-filters", false),
            ]
            .iter()
            .map(|(a, b)| (a.to_string(), *b))
            .collect(),
            channels: 8,
            indir: 8,
            tds: "off".into(),
            rules: vec![],
            fail_on: None,
            omit_rule_id: false,
            sabotage: None,
        }
    }
}

impl Runner for FakeNic {
    fn run(&mut self, a: &[String]) -> Result<String, String> {
        let cmd = a.join(" ");
        self.log.push(cmd.clone());
        if cmd.starts_with("ethtool -G")
            && let Some(d) = self.sabotage.take()
        {
            std::fs::remove_dir_all(&d).unwrap();
            std::fs::write(&d, "").unwrap();
        }
        if self.fail_on.as_deref().is_some_and(|f| cmd.starts_with(f)) {
            return Err(format!("{cmd}: Operation not supported"));
        }
        let s: Vec<&str> = a.iter().map(String::as_str).collect();
        match s.as_slice() {
            ["ethtool", "-g", _] => Ok(format!(
                "Ring parameters for eth0:\nPre-set maximums:\nRX:\t\t8191\nTX:\t\t2047\nCurrent hardware settings:\nRX:\t\t{}\nTX:\t\t{}\nTCP data split:\t{}\n",
                self.rings.0, self.rings.1, self.tds
            )),
            ["ethtool", "-G", _, rest @ ..] => {
                match rest {
                    ["tcp-data-split", v] => self.tds = v.to_string(),
                    ["rx", r, "tx", t] => self.rings = (r.parse().unwrap(), t.parse().unwrap()),
                    _ => return Err("bad -G".into()),
                }
                Ok(String::new())
            }
            ["ethtool", "-k", _] => Ok(self
                .feat
                .iter()
                .map(|(f, v)| format!("{f}: {}\n", if *v { "on" } else { "off" }))
                .collect()),
            ["ethtool", "-K", _, rest @ ..] => {
                for kv in rest.chunks(2) {
                    let name = crate::action::feature_name(kv[0]).to_string();
                    self.feat
                        .iter_mut()
                        .find(|(f, _)| *f == name)
                        .ok_or("no such feature")?
                        .1 = kv[1] == "on";
                }
                Ok(String::new())
            }
            ["ethtool", "-l", _] => Ok(format!(
                "Channel parameters for eth0:\nPre-set maximums:\nCombined:\t16\nCurrent hardware settings:\nCombined:\t{}\n",
                self.channels
            )),
            ["ethtool", "-L", _, "combined", n] => {
                self.channels = n.parse().unwrap();
                Ok(String::new())
            }
            ["ethtool", "-x", _] => Ok(format!(
                "RX flow hash indirection table for eth0 with {} RX ring(s):\n    0:      {}\nRSS hash key:\n",
                self.channels,
                (0..self.indir)
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            )),
            ["ethtool", "-X", _, "equal", n] => {
                self.indir = n.parse().unwrap();
                Ok(String::new())
            }
            ["ethtool", "-X", _, "default"] => {
                self.indir = self.channels;
                Ok(String::new())
            }
            ["ethtool", "-X", _, "context", "new", ..] => Ok("New RSS context is 1\n".into()),
            ["ethtool", "-X", _, "context", "1", "delete"] => Ok(String::new()),
            [
                "ethtool",
                "-N",
                _,
                "flow-type",
                "tcp4",
                "dst-port",
                p,
                "context",
                "1",
            ] => {
                let id = self.rules.len() as u32 + 7;
                self.rules.push((id, p.parse().unwrap()));
                Ok(if self.omit_rule_id {
                    "installed\n".into()
                } else {
                    format!("Added rule with ID {id}\n")
                })
            }
            ["ethtool", "-N", _, "delete", id] => {
                self.rules.retain(|(i, _)| i.to_string() != *id);
                Ok(String::new())
            }
            ["ethtool", "-n", _] => Ok(self
                .rules
                .iter()
                .map(|(i, p)| {
                    format!("Filter: {i}\n\tRule Type: TCP over IPv4\n\tDest port: {p}\n")
                })
                .collect()),
            _ => Err(format!("unexpected command {cmd}")),
        }
    }
}

fn sys(nic: FakeNic) -> HostSys<FakeNic> {
    HostSys::new(Path::new("/nonexistent-root"), nic)
}

fn nic_checks(h: &HostSys<FakeNic>) -> Vec<Check> {
    vec![
        offload_check(
            "eth0",
            "bnxt_en",
            [Some(true), Some(true), Some(true), Some(false)],
            Some(false),
        ),
        rings_check("eth0", Some((8191, h.run.rings.0, 2047, h.run.rings.1))),
    ]
}

fn state_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hosttune-{tag}-{}.json", std::process::id()))
}

#[test]
fn fix_text_comes_from_the_action() {
    let c = rings_check("eth0", Some((8191, 511, 2047, 511)));
    let a = &c.actions[0];
    assert_eq!(
        a.steps[0].commands(),
        vec!["ethtool -G eth0 rx 8191 tx 2047"]
    );
    assert!(
        c.fix
            .as_deref()
            .unwrap()
            .starts_with("ethtool -G eth0 rx 8191 tx 2047 ("),
        "{:?}",
        c.fix
    );
    assert_eq!(c.fix.as_deref().unwrap(), a.fix_text());
}

#[test]
fn dry_run_changes_nothing_apply_is_idempotent_revert_restores() {
    let mut h = sys(FakeNic::new());
    let checks = nic_checks(&h);
    let mut p = plan(&mut h, &checks, &Filter::default(), None);
    assert_eq!(p.items.len(), 2);
    assert!(
        p.items
            .iter()
            .flat_map(|i| &i.steps)
            .all(|s| s.state == StepState::Pending)
    );
    // dry run = probes only
    assert!(
        h.run
            .log
            .iter()
            .all(|c| c.starts_with("ethtool -g") || c.starts_with("ethtool -k")),
        "{:?}",
        h.run.log
    );
    let sf = state_path("a");
    let mut st = State::open(&sf).unwrap();
    // the re-run checks after the change
    let after = vec![
        offload_check("eth0", "bnxt_en", [Some(true); 4], Some(true)),
        rings_check("eth0", Some((8191, 8191, 2047, 2047))),
    ];
    apply(&mut h, &mut p, &mut st, || after).unwrap();
    assert_eq!(h.run.rings, (8191, 2047));
    assert!(
        h.run
            .feat
            .iter()
            .any(|(f, v)| f == "generic-receive-offload" && *v)
    );
    assert!(
        h.run.feat.iter().any(|(f, v)| f == "rx-gro-hw" && *v),
        "bnxt wants rx-gro-hw on, fixed in the same action"
    );
    assert!(
        p.items.iter().all(|i| i.verdict == Some("ok")),
        "{:?}",
        p.items.iter().map(|i| i.verdict).collect::<Vec<_>>()
    );
    // second run: everything already good -> skipped, no change command
    let n = h.run.log.len();
    let mut p2 = plan(
        &mut h,
        &[rings_check("eth0", Some((8191, 511, 2047, 511)))],
        &Filter::default(),
        None,
    );
    assert_eq!(
        p2.items[0].steps[0].state,
        StepState::Ok,
        "rings already at max: skipped"
    );
    let mut st2 = State::open(&state_path("b")).unwrap();
    apply(&mut h, &mut p2, &mut st2, || {
        vec![rings_check("eth0", Some((8191, 8191, 2047, 2047)))]
    })
    .unwrap();
    assert!(
        h.run.log[n..]
            .iter()
            .all(|c| !c.starts_with("ethtool -G") && !c.starts_with("ethtool -K")),
        "{:?}",
        &h.run.log[n..]
    );
    // revert restores the state read before the first apply
    let rows = revert(&mut h, &sf).unwrap();
    assert!(rows.iter().all(|r| r.error.is_none()));
    assert_eq!(h.run.rings, (511, 511));
    assert_eq!(h.run.feat, FakeNic::new().feat);
    let _ = std::fs::remove_file(sf);
    let _ = std::fs::remove_file(state_path("b"));
}

#[test]
fn failure_stops_the_action_and_is_reported() {
    let mut f = FakeNic::new();
    f.fail_on = Some("ethtool -G eth0 rx".into());
    let mut h = sys(f);
    let checks = vec![rings_check("eth0", Some((8191, 511, 2047, 511)))];
    let mut p = plan(&mut h, &checks, &Filter::default(), None);
    let sf = state_path("c");
    let mut st = State::open(&sf).unwrap();
    apply(&mut h, &mut p, &mut st, || checks.clone()).unwrap();
    assert!(matches!(p.items[0].steps[0].state, StepState::Failed(_)));
    assert_eq!(p.items[0].verdict, Some("failed"));
    let _ = std::fs::remove_file(sf);
}

#[test]
fn filters_by_check_and_iface_and_lists_manual() {
    let mut h = sys(FakeNic::new());
    let mut checks = nic_checks(&h);
    checks.push(rings_check("eth1", Some((8191, 511, 2047, 511))));
    checks.push(
        Check::new("cpu.isolation", "isolation")
            .warn()
            .fix("kernel cmdline isolcpus"),
    );
    let all = plan(&mut h, &checks, &Filter::default(), None);
    assert_eq!(all.items.len(), 3);
    assert_eq!(all.manual.len(), 1);
    let f = Filter {
        checks: vec!["net.eth0.rings".into()],
        iface: None,
    };
    assert_eq!(plan(&mut h, &checks, &f, None).items.len(), 1);
    let f = Filter {
        checks: vec!["net.eth0".into()],
        iface: None,
    };
    assert_eq!(
        plan(&mut h, &checks, &f, None).items.len(),
        2,
        "dotted prefix"
    );
    let f = Filter {
        checks: vec![],
        iface: Some("eth1".into()),
    };
    let p = plan(&mut h, &checks, &f, None);
    assert_eq!(p.items.len(), 1);
    assert_eq!(p.items[0].check, "net.eth1.rings");
    let f = Filter {
        checks: vec!["net.eth".into()],
        iface: None,
    };
    assert!(
        plan(&mut h, &checks, &f, None).items.is_empty(),
        "prefix needs a dot boundary"
    );
}

#[test]
fn zcrx_plan_apply_revert() {
    let mut h = sys(FakeNic::new());
    let z = Zcrx {
        queues: 2,
        host_queues: 6,
        ports: vec![6800, 6801],
    };
    let mut p = plan(&mut h, &[], &Filter::default(), Some(("eth0", &z)));
    assert_eq!(p.items.len(), 1);
    assert!(p.items[0].zcrx);
    let cmds: Vec<String> = p.items[0]
        .steps
        .iter()
        .flat_map(|s| s.step.commands())
        .collect();
    assert_eq!(cmds[0], "ethtool -G eth0 tcp-data-split on");
    assert_eq!(cmds[1], "ethtool -K eth0 ntuple on");
    assert_eq!(cmds[2], "ethtool -L eth0 combined 8");
    assert_eq!(cmds[3], "ethtool -X eth0 equal 6");
    assert_eq!(cmds[4], "ethtool -X eth0 context new start 6 equal 2");
    let sf = state_path("z");
    let mut st = State::open(&sf).unwrap();
    apply(&mut h, &mut p, &mut st, Vec::new).unwrap();
    assert_eq!(
        p.items[0].verdict,
        Some("ok"),
        "{:?}",
        p.items[0]
            .steps
            .iter()
            .map(|s| (&s.current, &s.state))
            .collect::<Vec<_>>()
    );
    assert_eq!(h.run.tds, "on");
    assert_eq!(h.run.indir, 6);
    assert_eq!(
        h.run.rules.iter().map(|r| r.1).collect::<Vec<_>>(),
        vec![6800, 6801]
    );
    // idempotent: a new plan finds everything done
    let again = plan(&mut h, &[], &Filter::default(), Some(("eth0", &z)));
    assert!(
        again.items[0]
            .steps
            .iter()
            .all(|s| s.state == StepState::Ok)
    );
    let rows = revert(&mut h, &sf).unwrap();
    assert!(rows.iter().all(|r| r.error.is_none()));
    assert_eq!(h.run.tds, "off");
    assert!(h.run.rules.is_empty());
    assert_eq!(h.run.channels, 8);
    assert_eq!(h.run.indir, 8, "default table = all channels");
    assert!(h.run.feat.iter().any(|(f, v)| f == "ntuple-filters" && !*v));
    let _ = std::fs::remove_file(sf);
}

#[test]
fn persist_text() {
    let mut h = sys(FakeNic::new());
    let a = Action::new(vec![
        Step::Sysctl {
            key: "vm.x".into(),
            want: "1".into(),
            cmp: Cmp::Eq,
        },
        Step::Module {
            name: "vfio-pci".into(),
        },
        Step::Rings {
            iface: "eth0".into(),
            rx: 1,
            tx: 1,
        },
    ]);
    let p = plan_of(&mut h, &a);
    let v = persist(
        &p,
        Path::new(DEFAULT_STATE),
        &["--iface".into(), "eth0".into()],
    );
    assert_eq!(v["sysctl_d"]["lines"][0], "vm.x = 1");
    assert_eq!(v["modules_load_d"]["lines"][0], "vfio-pci");
    let u = v["boot_unit"]["text"].as_str().unwrap();
    assert!(
        u.contains("ExecStart=/usr/bin/croit-flashstore-tool host-tune --apply --state /var/lib/croit-flashstore/host-tune.json --iface eth0"),
        "{u}"
    );
}

fn plan_of(h: &mut HostSys<FakeNic>, a: &Action) -> Plan {
    let mut c = Check::new("x", "x").st(Status::Warn);
    c = c.act(a.clone());
    plan(h, &[c], &Filter::default(), None)
}

#[test]
fn partial_flow_failure_retains_successful_undo() {
    let mut nic = FakeNic::new();
    nic.fail_on = Some("ethtool -N eth0 flow-type tcp4 dst-port 6801".into());
    let mut h = sys(nic);
    let z = Zcrx {
        queues: 2,
        host_queues: 6,
        ports: vec![6800, 6801],
    };
    let mut p = plan(&mut h, &[], &Filter::default(), Some(("eth0", &z)));
    let sf = state_path("partial-flow");
    let mut st = State::open(&sf).unwrap();
    apply(&mut h, &mut p, &mut st, Vec::new).unwrap();
    assert_eq!(p.items[0].verdict, Some("failed"));
    assert_eq!(h.run.rules.len(), 1);
    let rows = revert(&mut h, &sf).unwrap();
    assert!(rows.iter().all(|r| r.error.is_none()));
    assert!(h.run.rules.is_empty());
    assert!(
        rows.iter()
            .any(|r| r.op == "ethtool -X eth0 context 1 delete")
    );
    std::fs::remove_file(sf).unwrap();
}

#[test]
fn successful_flow_with_unknown_id_is_explicit_recovery_error() {
    let mut nic = FakeNic::new();
    nic.omit_rule_id = true;
    let mut h = sys(nic);
    let z = Zcrx {
        queues: 2,
        host_queues: 6,
        ports: vec![6800],
    };
    let mut p = plan(&mut h, &[], &Filter::default(), Some(("eth0", &z)));
    let sf = state_path("unknown-rule");
    let mut st = State::open(&sf).unwrap();
    apply(&mut h, &mut p, &mut st, Vec::new).unwrap();
    assert!(p.items[0].steps.iter().any(|s| matches!(&s.state, StepState::Failed(e) if e.contains("recovery required") && e.contains("no rule id"))));
    assert_eq!(p.items[0].verdict, Some("failed"));
    // The known context undo is still available; unknown rule recovery is not claimed successful.
    assert!(std::fs::read_to_string(&sf).unwrap().contains("context"));
    std::fs::remove_file(sf).unwrap();
}

/// T6 sibling: a loaded `vfio-pci` is `sys/module/vfio_pci`; host-tune must see it as done (no modprobe, no undo
/// `modprobe -r` of a module it never loaded).
#[test]
fn loaded_dashed_module_probes_as_done() {
    let root = std::env::temp_dir().join(format!("hosttune-mod-{}", std::process::id()));
    std::fs::create_dir_all(root.join("sys/module/vfio_pci")).unwrap();
    let mut h = HostSys::new(&root, FakeNic::new());
    let p = Step::Module {
        name: "vfio-pci".into(),
    }
    .probe(&mut h)
    .unwrap();
    assert!(p.done, "{}", p.current);
    std::fs::remove_dir_all(&root).unwrap();
}

/// T8: a second apply on the same state file appends (the first run's undo survives) and `--revert` restores the
/// state before the first apply; a file revert could not read is refused, never overwritten.
#[test]
fn second_apply_appends_and_revert_restores_the_original() {
    let mut h = sys(FakeNic::new());
    let sf = state_path("t8");
    let _ = std::fs::remove_file(&sf);
    let start_rings = h.run.rings;
    // run 1: rings
    let c1 = vec![rings_check(
        "eth0",
        Some((8191, h.run.rings.0, 2047, h.run.rings.1)),
    )];
    let mut p1 = plan(&mut h, &c1, &Filter::default(), None);
    let mut st = State::open(&sf).unwrap();
    apply(&mut h, &mut p1, &mut st, Vec::new).unwrap();
    assert_ne!(h.run.rings, start_rings);
    // run 2 (e.g. the boot unit again, or another check): offloads
    let c2 = vec![offload_check(
        "eth0",
        "bnxt_en",
        [Some(true), Some(true), Some(true), Some(false)],
        Some(false),
    )];
    let feat_before = h.run.feat.clone();
    let mut p2 = plan(&mut h, &c2, &Filter::default(), None);
    let mut st = State::open(&sf).unwrap();
    apply(&mut h, &mut p2, &mut st, Vec::new).unwrap();
    assert_ne!(h.run.feat, feat_before);
    revert(&mut h, &sf).unwrap();
    assert_eq!(h.run.rings, start_rings, "run 1's undo survived run 2");
    let mut f = h.run.feat.clone();
    let mut want = feat_before.clone();
    f.sort();
    want.sort();
    assert_eq!(f, want);
    std::fs::write(&sf, "not json").unwrap();
    assert!(State::open(&sf).is_err());
    let _ = std::fs::remove_file(sf);
}

/// T9: a state file another user can change is never loaded or executed as root, and a written one is 0600.
#[test]
fn state_file_must_be_private_and_owned() {
    use std::os::unix::fs::PermissionsExt;
    let sf = state_path("t-trust");
    let _ = std::fs::remove_file(&sf);
    let doc = serde_json::json!({
        "schema": 1, "created": 0,
        "entries": [{"check": "x", "command": "c", "prior": "",
                     "revert": [{"exec": ["unexpected-exec"]}]}]
    })
    .to_string();
    std::fs::write(&sf, &doc).unwrap();
    std::fs::set_permissions(&sf, std::fs::Permissions::from_mode(0o664)).unwrap();
    let mut h = sys(FakeNic::new());
    assert!(
        State::open(&sf).is_err(),
        "group/other-writable state file loaded"
    );
    let link = state_path("t-trust-link");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&sf, &link).unwrap();
    assert!(State::open(&link).is_err(), "symlinked state file loaded");
    let _ = std::fs::remove_file(&link);
    let e = revert(&mut h, &sf).unwrap_err();
    assert!(e.contains("group/other-writable"), "{e}");
    assert!(h.run.log.is_empty(), "foreign-writable state file executed");
    // the same layout in a private file is loaded and reverted
    std::fs::set_permissions(&sf, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(State::open(&sf).is_ok());
    let rows = revert(&mut h, &sf).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        h.run.log.iter().any(|c| c.contains("unexpected-exec")),
        "{:?}",
        h.run.log
    );
    let _ = std::fs::remove_file(&sf);

    // a written state file is 0600
    let sf = state_path("t-mode");
    let _ = std::fs::remove_file(&sf);
    let c = vec![rings_check(
        "eth0",
        Some((8191, h.run.rings.0, 2047, h.run.rings.1)),
    )];
    let mut p = plan(&mut h, &c, &Filter::default(), None);
    let mut st = State::open(&sf).unwrap();
    apply(&mut h, &mut p, &mut st, Vec::new).unwrap();
    assert_eq!(
        std::fs::metadata(&sf).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let _ = std::fs::remove_file(sf);
}

/// NT-hostsafety-01: a state path that cannot be written refuses the apply before any step changes the host.
#[test]
fn an_unwritable_state_path_applies_nothing() {
    let root = std::env::temp_dir().join(format!("hosttune-statefail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let blocker = root.join("state");
    std::fs::write(&blocker, "").unwrap(); // a file where the state directory would be
    let sf = blocker.join("s.json");
    let mut h = sys(FakeNic::new());
    let before = h.run.rings;
    let mut st = State::open(&sf).unwrap();
    let c1 = vec![rings_check(
        "eth0",
        Some((8191, h.run.rings.0, 2047, h.run.rings.1)),
    )];
    let mut p1 = plan(&mut h, &c1, &Filter::default(), None);
    let e = apply(&mut h, &mut p1, &mut st, Vec::new).unwrap_err();
    assert!(e.contains("state"), "{e}");
    assert!(!sf.exists());
    assert_eq!(h.run.rings, before, "nothing applied");
    assert!(
        h.run.log.iter().all(|c| !c.starts_with("ethtool -G")),
        "no change command ran: {:?}",
        h.run.log
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A save that fails after the preflight (the path breaks between steps) must not swallow the step that already
/// changed the host: the error carries the undo operations, and the failed entry is not kept.
#[test]
fn a_failed_state_save_after_a_step_is_loud_and_keeps_no_entry() {
    let root = std::env::temp_dir().join(format!("hosttune-statefail2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let dir = root.join("state");
    std::fs::create_dir_all(&dir).unwrap();
    let sf = dir.join("s.json");
    let mut nic = FakeNic::new();
    nic.sabotage = Some(dir.clone());
    let mut h = sys(nic);
    let mut st = State::open(&sf).unwrap();
    let c1 = vec![rings_check(
        "eth0",
        Some((8191, h.run.rings.0, 2047, h.run.rings.1)),
    )];
    let mut p1 = plan(&mut h, &c1, &Filter::default(), None);
    let e = apply(&mut h, &mut p1, &mut st, Vec::new).unwrap_err();
    assert!(e.contains("by hand") && e.contains("ethtool"), "{e}");
    assert_eq!(h.run.rings, (8191, 2047), "the step itself ran");
    assert!(sf.metadata().is_err(), "no state file");
    let _ = std::fs::remove_dir_all(&root);
}

/// NT-hostsafety-03: the boot unit records into the operator's `--state` file (default: a persistent path, never
/// tmpfs), so `--revert` finds what the boot run changed.
#[test]
fn boot_unit_uses_the_state_file_revert_reads() {
    let mut h = sys(FakeNic::new());
    let a = Action::new(vec![Step::Rings {
        iface: "eth0".into(),
        rx: 1,
        tx: 1,
    }]);
    let p = plan_of(&mut h, &a);
    let text = |st: &str| {
        persist(&p, Path::new(st), &[])["boot_unit"]["text"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert!(text("/root/ht.json").contains("--apply --state /root/ht.json "));
    assert!(!DEFAULT_STATE.starts_with("/run/") && !DEFAULT_STATE.starts_with("/tmp/"));
}
