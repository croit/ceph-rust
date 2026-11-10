// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! `croit-flashstore-osd spdk-primary --dev spdk:PCI [--mem MB] [--poll-ms MS] [--huge-dir D] [--format plain|json|json-pretty|jsonl]`:
//! the SPDK multi-process primary of one controller (adr 0463; DEBUG/TESTING ONLY, feature `spdk-mp`). Runs in the
//! foreground until SIGTERM / SIGINT (refused while secondaries run). OSDs and tools then open single namespaces as
//! secondaries: `--dev spdk:PCI,ns=N,shared`.
//! Part of the daemon binary on purpose: a DPDK primary must register every tailq / bus its secondaries use, and the
//! daemon links the full DPDK set (hash, vdev bus); `croit-flashstore-tool` links a subset and works as a secondary only.
//! Output: one event per line on stderr. `plain` = text; the JSON formats emit one record per event (`json-pretty`
//! indented): `{"event":"ready","pci","pid","shm_id"}`, `{"event":"stopped","pci"}`,
//! `{"event":"stop_refused","pci","error"}` (SIGTERM while secondaries run), `{"event":"admin_error","pci","rc"}`,
//! `{"event":"error","pci","error","exit"}`.
//! Exit codes: 0 stopped, 1 runtime, 2 usage, 3 refused (device in use, secondaries of a dead primary still running).
use nvme::any::DevSpec;
use nvme::spdk::PrimaryNotice;
use outfmt::Format;
use serde_json::json;

fn arg(a: &[String], k: &str) -> Option<String> {
    a.iter()
        .position(|x| x == k)
        .and_then(|i| a.get(i + 1).cloned())
}

/// One event: the plain text, or its record in the JSON formats.
fn event(fmt: Format, plain: &str, rec: serde_json::Value) {
    if fmt.is_json() {
        eprintln!("{}", fmt.doc(&rec));
    } else {
        eprintln!("croit-flashstore-osd: {plain}");
    }
}

pub fn main(args: &[String]) -> i32 {
    let usage = "spdk-primary --dev spdk:PCI [--mem MB (1024)] [--poll-ms MS (100)] [--huge-dir D] \
                 [--format plain|json|json-pretty|jsonl]";
    let (fmt, a) = match outfmt::extract(args, true) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("croit-flashstore-osd: spdk-primary: {e}");
            return 2;
        }
    };
    let (Some(DevSpec::Spdk { traddr, .. }), Some(mem), Some(poll_ms)) = (
        arg(&a, "--dev").and_then(|d| DevSpec::parse(&d).ok()),
        arg(&a, "--mem").map_or(Some(1024), |m| m.parse::<i32>().ok()),
        arg(&a, "--poll-ms").map_or(Some(100), |m| m.parse::<u64>().ok()),
    ) else {
        eprintln!("croit-flashstore-osd: {usage}");
        return 2;
    };
    if let Some(h) = arg(&a, "--huge-dir") {
        // SAFETY: single threaded; read by the SPDK env init.
        unsafe { std::env::set_var("NVS_HUGE_DIR", h) };
    }
    let ready = || {
        let (pid, shm) = (
            std::process::id(),
            nvme::spdkmp::shm_id(&traddr).unwrap_or(-1),
        );
        event(
            fmt,
            &format!(
                "spdk-primary {traddr} ready (pid {pid}, shm id {shm}): open namespaces with --dev spdk:{traddr},ns=N,shared"
            ),
            json!({"event": "ready", "pci": traddr, "pid": pid, "shm_id": shm}),
        );
    };
    let notice = |n: PrimaryNotice| match n {
        PrimaryNotice::AdminFailed(rc) => event(
            fmt,
            &format!("spdk-primary {traddr}: admin queue failed ({rc}); keeps polling"),
            json!({"event": "admin_error", "pci": traddr, "rc": rc}),
        ),
        PrimaryNotice::StopRefused(e) => event(
            fmt,
            &format!("spdk-primary {traddr}: stop refused: {e}"),
            json!({"event": "stop_refused", "pci": traddr, "error": e}),
        ),
    };
    let r = nvme::spdk::run_primary(&traddr, mem, poll_ms, ready, notice);
    match r {
        Ok(()) => {
            event(
                fmt,
                &format!("spdk-primary {traddr} stopped"),
                json!({"event": "stopped", "pci": traddr}),
            );
            0
        }
        Err(e) => {
            let code = if e.contains("in use") || e.contains("still running") {
                3
            } else {
                1
            };
            event(
                fmt,
                &format!("spdk-primary {traddr}: {e}"),
                json!({"event": "error", "pci": traddr, "error": e, "exit": code}),
            );
            code
        }
    }
}
