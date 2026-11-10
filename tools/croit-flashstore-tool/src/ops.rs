// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Offline store maintenance (doc/ops/croit-flashstore-tool.md): `fsck [--deep]`, `repair [--deep]`, `sizes`, `expand`,
//! `free`, `upgrade` (adr 0611). Device: `--dev SPEC`, `--id N [--cluster C]` or `--data-path DIR` (the OSD data dir). OFFLINE like
//! `objectstore`: exit 3 while the OSD runs / holds the device. Exit: 0 ok, 1 error / inconsistencies, 2 usage, 3 refused.
//! Identity / device info: `inspect` (lifecycle.rs). No BlueStore label emulation (review 2026-10-12-not-a-clone).
use crate::objectstore::{osd_running, resolve_dev, validate_device};
use crate::{flag, usage_err};
use nvme::any::{AnyCtrl, DevSpec};
use outfmt::Format;
use serde_json::json;
use store::BLK;
use store::dev::MonoClock;

fn fail(m: &str) -> i32 {
    eprintln!("croit-flashstore-tool: {m}");
    1
}

/// `--accept-wal-loss`: adr 0021 am. 9, DATA LOSS override.
fn accept_wal_loss(a: &[String]) {
    if flag(a, "--accept-wal-loss") {
        store::wal::set_accept_wal_loss(true);
    }
}

/// Resolve the device spec, refuse while the OSD runs.
fn target(a: &[String]) -> Result<(String, Option<osddir::OsdDir>), i32> {
    let (spec, who) = resolve_dev(a).map_err(|e| {
        if e.starts_with("refused:") {
            eprintln!("croit-flashstore-tool: {e}");
            3
        } else {
            usage_err(&e)
        }
    })?;
    if let Some((d, asok)) = &who
        && osd_running(asok)
    {
        let id = d.whoami;
        eprintln!(
            "croit-flashstore-tool: osd.{id} is running (admin socket {asok} answers): stop it first (systemctl stop croit-flashstore-osd@{id})"
        );
        return Err(3);
    }
    Ok((spec, who.map(|(d, _)| d)))
}

/// Open the device alone (SPDK env, exclusive file lock / PCI claim).
fn open(spec: &str) -> Result<AnyCtrl, i32> {
    let d = DevSpec::parse(spec).map_err(|e| usage_err(&e))?;
    crate::devopen::open(&d, false, crate::devopen::MOUNT_HUGEPAGES_MB).map_err(|e| {
        eprintln!("croit-flashstore-tool: {spec}: {e}");
        crate::devopen::exit_code(&e)
    })
}

/// `target` + `open` (and `validate_device`), the common prologue of the offline store commands.
pub(crate) fn device(a: &[String]) -> Result<(String, AnyCtrl), i32> {
    let (spec, expected) = target(a)?;
    let c = open(&spec)?;
    validate_device(&c, expected.as_ref()).map_err(|e| {
        eprintln!("croit-flashstore-tool: {e}");
        3
    })?;
    Ok((spec, c))
}

// ------------------------------------------------------------------------------------------ fsck / repair

/// Problem lines `fsck`/`repair` print: the first [`PROBLEM_LINES`] in full, then one line for the rest (the verdict
/// counts every problem, so a truncated listing must say how many it dropped).
const PROBLEM_LINES: usize = 50;

fn problem_lines(errs: &[String]) -> Vec<String> {
    let mut out: Vec<String> = errs
        .iter()
        .take(PROBLEM_LINES)
        .map(|e| format!("fsck: {e}"))
        .collect();
    if errs.len() > PROBLEM_LINES {
        out.push(format!("fsck: {} more", errs.len() - PROBLEM_LINES));
    }
    out
}

/// Checkpointed state of every shard (no mount, no replay) then the object layer of the mounted store.
/// Returns the number of problems found.
fn check_store<D: store::dev::BlockDev>(
    ctrl: &AnyCtrl,
    st: &mut store::obj::Store<D, MonoClock>,
    deep: bool,
) -> Result<usize, i32> {
    let mut errs: Vec<String> = Vec::new();
    {
        let mut d = ctrl.open_queue().map_err(|e| fail(&e))?;
        let mut clk = MonoClock::default();
        if let Err(e) = store::fsck::fsck(&mut d, &mut clk, Some(&store::obj::onode::fsck_refs)) {
            errs.push(format!("checkpointed state: {e}"));
        }
    }
    match st.check(deep) {
        Ok(r) => errs.extend(r.errors.iter().map(|e| format!("object layer: {e:?}"))),
        Err(e) => errs.push(format!("object layer check failed: {e}")),
    }
    for l in problem_lines(&errs) {
        eprintln!("{l}");
    }
    Ok(errs.len())
}

/// `wal_tail_dropped`: WAL tails the mount's replay dropped as torn (data failed validation, no later witness of an
/// ack). Informational like BlueStore's point-in-time WAL recovery, never an error (adr 0021 S2 am. 84): JSON field
/// `wal_tail_dropped` (objects `shard`, `first_lsn`, `last_lsn`, `txns`, `block`, `reason`), plain info lines.
fn verdict(what: &str, n: usize, stats: &[store::wal::ReplayStats], f: Format) -> i32 {
    let dropped = || stats.iter().filter_map(|s| s.tail_dropped.as_ref());
    if f.is_json() {
        let tails: Vec<_> = dropped()
            .map(|t| {
                json!({"shard": t.shard, "first_lsn": t.first_lsn, "last_lsn": t.last_lsn, "txns": t.txns,
                    "block": t.blk, "reason": t.reason})
            })
            .collect();
        println!(
            "{}",
            f.doc(&json!({"command": what, "errors": n, "ok": n == 0, "wal_tail_dropped": tails}))
        );
        return i32::from(n != 0);
    }
    for t in dropped() {
        println!("{what}: WAL tail dropped: shard {}: {t}", t.shard);
    }
    if n == 0 {
        println!("{what} success");
    } else {
        println!("{what} found {n} error(s)");
    }
    i32::from(n != 0)
}

/// `fsck [--deep] [--md5] [--accept-wal-loss]`: read-only mount (WAL replay, checkpoint and a `--accept-wal-loss`
/// cut stay in memory: the device is never written), check. `--deep` verifies every block checksum. `--md5` (lab)
/// also prints `pgid object md5` per object. `repair` is the command that makes a replay (or a cut) durable.
pub fn fsck(a: &[String], f: Format) -> i32 {
    accept_wal_loss(a);
    if f.is_json() && flag(a, "--md5") {
        return usage_err("--md5 prints plain lines: use --format plain");
    }
    let (_, ctrl) = match device(a) {
        Ok(x) => x,
        Err(c) => return c,
    };
    let (mut st, stats) = match osd::nvmestore::mount_dev_read_only(&ctrl) {
        Ok(s) => s,
        Err(e) => return fail(&format!("mount (read-only): {e}")),
    };
    let n = match check_store(&ctrl, &mut st, flag(a, "--deep")) {
        Ok(n) => n,
        Err(c) => return c,
    };
    if flag(a, "--md5") {
        md5_listing(st);
    }
    verdict("fsck", n, &stats, f)
}

#[cfg(feature = "lab")]
fn md5_listing<D: store::dev::BlockDev>(st: store::obj::Store<D, MonoClock>) {
    use peering::PgStoreOps;
    let ad = storeadapt::StoreAdapter::from_shared(std::rc::Rc::new(std::cell::RefCell::new(st)));
    for s in &ad.list_pgs() {
        for (h, o) in ad.objects(*s) {
            println!(
                "{} {} {:x}",
                s.pgid,
                String::from_utf8_lossy(&h.oid),
                md5::compute(&o.data)
            );
        }
    }
}
#[cfg(not(feature = "lab"))]
fn md5_listing<D: store::dev::BlockDev>(_st: store::obj::Store<D, MonoClock>) {
    eprintln!("--md5 needs the lab build");
}

/// `repair [--deep] [--accept-wal-loss]`: [`store::obj::Store::repair`] (leaked blocks freed, usage counters rewritten
/// from a recount, immutable-data false frees allocated, shared counts rebuilt, exclusive aliases copied;
/// false-free metadata cells allocated by the repair mount's checkpoint; structural/checksum damage refused). The
/// whole repair runs first on a read-only mount (memory overlay, [`osd::nvmestore::mount_dev_repair_preview`]): only
/// a clean dry pass mounts the device writable (replay, checkpoint, superblock heal) and repeats it. JSON `{"command","ok","errors","refused","before",
/// "actions","after","wal_tail_dropped"}`. Exit 0 = clean after repair, 1 = error / incomplete, 3 = refused (nothing
/// written).
pub fn repair(a: &[String], f: Format) -> i32 {
    accept_wal_loss(a);
    let (_, ctrl) = match device(a) {
        Ok(x) => x,
        Err(c) => return c,
    };
    // Prove recovery/repair safe on an overlay before mount can checkpoint on real media.
    let run = || -> Result<_, String> {
        // an external omap engine (RocksDB) is never opened by repair: refused from the superblock alone
        let mut d = ctrl.open_queue()?;
        let (sb, _) = store::layout::read_super(&mut d, &mut MonoClock::default())
            .map_err(|e| format!("superblock: {e}"))?;
        drop(d);
        if let Some(m) = store::obj::refuse_engine(sb.features) {
            let report = store::obj::RepairReport {
                refused: true,
                after: vec![m.into()],
                ..Default::default()
            };
            return Ok((report, Vec::new()));
        }
        let (mut preview, preview_stats) = osd::nvmestore::mount_dev_repair_preview(&ctrl)?;
        let mut report = preview
            .repair(flag(a, "--deep"))
            .map_err(|e| e.to_string())?;
        drop(preview);
        if !report.after.is_empty() {
            report.actions.clear(); // overlay actions never reached the device
            return Ok((report, preview_stats));
        }
        let (mut st, stats) = osd::nvmestore::mount_dev_repair(&ctrl)?;
        let report = st.repair(flag(a, "--deep")).map_err(|e| e.to_string())?;
        Ok((report, stats))
    };
    let (r, stats) = match run() {
        Ok(s) => s,
        Err(e) => {
            let error = format!("repair: {e}");
            if f.is_json() {
                println!(
                    "{}",
                    f.doc(&json!({"command": "repair", "ok": false,
                    "errors": 1, "refused": false, "before": [], "after": [error],
                    "actions": [], "wal_tail_dropped": []}))
                );
            } else {
                eprintln!("{error}");
            }
            return 1;
        }
    };
    let tails: Vec<_> = stats
        .iter()
        .filter_map(|s| s.tail_dropped.as_ref())
        .map(|t| {
            json!({"shard": t.shard, "first_lsn": t.first_lsn, "last_lsn": t.last_lsn,
            "txns": t.txns, "block": t.blk, "reason": t.reason})
        })
        .collect();
    if f.is_json() {
        println!(
            "{}",
            f.doc(&json!({"command": "repair", "ok": r.after.is_empty(),
            "errors": r.after.len(), "refused": r.refused, "before": r.before,
            "actions": r.actions, "after": r.after, "wal_tail_dropped": tails}))
        );
    } else {
        for e in &r.before {
            println!("before: {e}");
        }
        for a in &r.actions {
            println!("action: {a}");
        }
        for e in &r.after {
            println!("after: {e}");
        }
        println!(
            "repair {}",
            if r.after.is_empty() {
                "success"
            } else {
                "refused / incomplete"
            }
        );
        for t in tails {
            println!("repair: WAL tail dropped: {t}");
        }
    }
    if r.refused {
        3
    } else {
        i32::from(!r.after.is_empty())
    }
}

// ------------------------------------------------------------------------- sizes / expand / free space

fn gib(b: u64) -> String {
    format!("{:.2} GiB", b as f64 / (1u64 << 30) as f64)
}

/// `sizes [--format F]`: device versus store.
pub fn sizes(a: &[String], f: Format) -> i32 {
    let (spec, ctrl) = match device(a) {
        Ok(x) => x,
        Err(c) => return c,
    };
    let mut d = match ctrl.open_queue() {
        Ok(d) => d,
        Err(e) => return fail(&e),
    };
    let s = match store::layout::sizes(&mut d, &mut MonoClock::default()) {
        Ok(s) => s,
        Err(e) => return fail(&format!("no croit-flashstore-osd store on the device: {e}")),
    };
    let v = json!({"dev": spec, "device_size": s.device_bytes, "store_size": s.store_bytes,
        "managed_size": s.managed_bytes, "data_capacity": s.data_bytes, "shards": s.shards,
        "expansions": s.expansions, "expandable": s.expandable_per_shard * u64::from(s.shards)});
    if f.is_json() {
        println!("{}", f.doc(&v));
    } else {
        println!(
            "{}: device size {} ({:#x}), store size {} ({:#x}), data capacity {}, {} shards, {} expansion(s)",
            spec,
            gib(s.device_bytes),
            s.device_bytes,
            gib(s.store_bytes),
            s.store_bytes,
            gib(s.data_bytes),
            s.shards,
            s.expansions
        );
        if s.expandable_per_shard > 0 {
            println!(
                "device grew: `expand` adds {} per shard ({} in total)",
                gib(s.expandable_per_shard),
                gib(s.expandable_per_shard * u64::from(s.shards))
            );
        }
    }
    0
}

/// `expand [--format F]`: the device (namespace) grew since mkfs: give every shard a share.
pub fn expand(a: &[String], f: Format) -> i32 {
    let (spec, ctrl) = match device(a) {
        Ok(x) => x,
        Err(c) => return c,
    };
    let mut d = match ctrl.open_queue() {
        Ok(d) => d,
        Err(e) => return fail(&e),
    };
    let r = match store::layout::expand(&mut d, &mut MonoClock::default()) {
        Ok(r) => r,
        Err(e) => return fail(&format!("expand: {e}")),
    };
    let v = match &r {
        Some(r) => {
            json!({"dev": spec, "expanded": true, "old_size": r.old_bytes, "new_size": r.new_bytes,
            "per_shard": r.per_shard_bytes, "expansions": r.generations})
        }
        None => json!({"dev": spec, "expanded": false}),
    };
    if f.is_json() {
        println!("{}", f.doc(&v));
    } else if let Some(r) = r {
        println!(
            "expand: {} -> {} (+{} per shard, expansion {})",
            gib(r.old_bytes),
            gib(r.new_bytes),
            gib(r.per_shard_bytes),
            r.generations
        );
    } else {
        println!("expand: nothing to do (the device did not grow by one 16 MiB unit per shard)");
    }
    0
}

/// `free [--extents] [--format F]`: free space of the data allocators (reserved/held count as used): bytes, extent count,
/// largest extent, fragmentation (score: 0 = one run .. 1 = all single blocks; rating: share of free space not in
/// large runs). `--extents` adds `[offset, length]` byte pairs (device offsets; plain: one `offset length` line each). Online: tell `bluestore allocator ...`.
/// Read-only mount (like `fsck`): the command only reads allocator state, so it must not replay/heal/checkpoint a device.
pub fn free(a: &[String], f: Format) -> i32 {
    let (spec, ctrl) = match device(a) {
        Ok(x) => x,
        Err(c) => return c,
    };
    let st = match osd::nvmestore::mount_dev_read_only(&ctrl) {
        Ok(s) => s.0,
        Err(e) => return fail(&format!("mount (read-only): {e}")),
    };
    let ext = st.free_extents();
    let b = BLK as u64;
    let bytes: u64 = ext.iter().map(|e| e.1 * b).sum();
    let largest = ext.iter().map(|e| e.1 * b).max().unwrap_or(0);
    let (score, rating) = (
        store::report::fragmentation_score(&ext),
        store::report::fragmentation_rating(&ext),
    );
    let mut v = json!({"dev": spec, "free_bytes": bytes, "extents": ext.len(), "largest_extent": largest,
        "fragmentation_score": score, "fragmentation_rating": rating});
    if flag(a, "--extents") {
        v["extent_list"] = ext.iter().map(|e| json!([e.0 * b, e.1 * b])).collect();
    }
    if f.is_json() {
        println!("{}", f.doc(&v));
    } else {
        println!(
            "{spec}: free {} in {} extent(s), largest {}, fragmentation score {score:.4}, rating {rating:.4}",
            gib(bytes),
            ext.len(),
            gib(largest)
        );
        if flag(a, "--extents") {
            for e in &ext {
                println!("{} {}", e.0 * b, e.1 * b);
            }
        }
    }
    0
}

// ------------------------------------------------------------------------------------------ upgrade

fn upgrade_event(e: &store::upgrade::Event) -> serde_json::Value {
    use store::upgrade::Event as E;
    match e {
        E::Plan { steps, resume } => json!({"event": "plan", "steps": steps, "resume": resume}),
        E::Survey {
            shard,
            entries,
            bytes,
            avail_bytes,
        } => json!({"event": "survey", "shard": shard, "entries": entries, "bytes": bytes,
            "avail_bytes": avail_bytes}),
        E::Mark { step } => json!({"event": "mark", "step": step}),
        E::Progress {
            step,
            shard,
            entries,
            entries_total,
            bytes,
            bytes_total,
        } => json!({"event": "progress", "step": step, "shard": shard, "entries": entries,
            "entries_total": entries_total, "bytes": bytes, "bytes_total": bytes_total}),
        E::ShardDone { step, shard } => {
            json!({"event": "shard_done", "step": step, "shard": shard})
        }
        E::Done { step } => json!({"event": "step_done", "step": step}),
    }
}

/// `upgrade [--omap-lsm] [--dry-run]` (adr 0611): run the offline format upgrade steps this build needs (plus the
/// opt-ins), resuming an interrupted one. Exit: 0 done / nothing to do, 1 error, 2 usage, 3 refused (OSD running,
/// device in use), 5 a shard lacks the free space (nothing changed). `--format jsonl` streams the progress events.
pub fn upgrade(a: &[String], f: Format) -> i32 {
    let opts = store::upgrade::Opts {
        omap_lsm: flag(a, "--omap-lsm"),
        dry_run: flag(a, "--dry-run"),
    };
    let (spec, ctrl) = match device(a) {
        Ok(x) => x,
        Err(c) => return c,
    };
    // No in-place foreign-engine conversion or offline upgrade implementation.
    if let Err(e) = osd::nvmestore::refuse_splinter_read_only(&ctrl) {
        return fail(&e);
    }
    let mut events = Vec::new();
    let mut ev = |e: &store::upgrade::Event| {
        let v = upgrade_event(e);
        match f {
            Format::Jsonl => println!("{}", f.doc(&v)),
            Format::Plain => println!("upgrade: {}", plain_event(e)),
            _ => events.push(v),
        }
    };
    let r = osd::nvmestore::upgrade_dev(&ctrl, opts, &mut ev);
    let (code, v) = match &r {
        Ok(rep) => (
            0,
            json!({"dev": spec, "ok": true, "steps": rep.steps, "resumed": rep.resumed,
                "dry_run": rep.dry_run, "features": rep.features}),
        ),
        Err(e) => {
            let code = match e {
                store::upgrade::UpgradeError::Space { .. } => 5,
                _ => 1,
            };
            eprintln!("croit-flashstore-tool: upgrade {spec}: {e}");
            (
                code,
                json!({"dev": spec, "ok": false, "error": e.to_string()}),
            )
        }
    };
    match (f, &r) {
        (Format::Jsonl, _) => {
            let mut v = v;
            v["event"] = json!("result");
            println!("{}", f.doc(&v));
        }
        (Format::Plain, Ok(rep)) if rep.steps.is_empty() => {
            println!("upgrade: {spec} is up to date")
        }
        (Format::Plain, Ok(rep)) if rep.dry_run => {
            println!(
                "upgrade: {spec}: would run {:?} (dry run, nothing changed)",
                rep.steps
            )
        }
        (Format::Plain, Ok(rep)) => println!("upgrade: {spec}: done {:?}", rep.steps),
        (Format::Plain, Err(_)) => {}
        _ => {
            let mut v = v;
            v["events"] = json!(events);
            println!("{}", f.doc(&v));
        }
    }
    code
}

fn plain_event(e: &store::upgrade::Event) -> String {
    use store::upgrade::Event as E;
    match e {
        E::Plan { steps, resume } if *resume => format!("resuming {steps:?}"),
        E::Plan { steps, .. } => format!("plan {steps:?}"),
        E::Survey {
            shard,
            entries,
            bytes,
            avail_bytes,
        } => format!(
            "shard {shard}: {entries} omap entries, {} to convert, {} free",
            gib(*bytes),
            gib(*avail_bytes)
        ),
        E::Mark { step } => format!("{step}: started (the OSD stays refused until it finished)"),
        E::Progress {
            step,
            shard,
            entries,
            entries_total,
            ..
        } => format!("{step}: shard {shard}: {entries}/{entries_total} entries"),
        E::ShardDone { step, shard } => format!("{step}: shard {shard} done"),
        E::Done { step } => format!("{step}: done"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every problem is counted by the verdict, so a truncated listing says how many lines it dropped.
    #[test]
    fn problem_lines_count_the_suppressed_rest() {
        let errs: Vec<String> = (0..120).map(|i| format!("e{i}")).collect();
        let lines = problem_lines(&errs);
        assert_eq!(lines.len(), PROBLEM_LINES + 1);
        assert_eq!(lines[0], "fsck: e0");
        assert_eq!(lines[PROBLEM_LINES - 1], "fsck: e49");
        assert_eq!(lines[PROBLEM_LINES], "fsck: 70 more");
        // no extra line when nothing is suppressed
        assert_eq!(
            problem_lines(&errs[..3]),
            ["fsck: e0", "fsck: e1", "fsck: e2"]
        );
        assert!(problem_lines(&[]).is_empty());
    }
}
