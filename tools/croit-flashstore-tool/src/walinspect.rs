// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `wal-inspect (--id N | --dev SPEC) [--shard N] [--preview-loss]`: READ-ONLY decode of each shard's write-ahead
//! log ring without mounting and without writing. Reports, per unit, the lsn, acked_lsn, store_id, epoch and validity
//! (crc ok / torn / foreign), per record the txn op summary (collection/PG, object, op kind, bytes), and where replay
//! would stop and why (torn tail, data crc mismatch, WalLost witness). `--preview-loss` also lists the records a
//! `--accept-wal-loss` cut would drop (the WalLost txns). OFFLINE like `fsck` (exit 3 while the OSD runs).
//! Exit: 0 = the WAL would replay cleanly, 1 = it would refuse to mount (WalLost / undecodable / newer incarnation),
//! 2 usage, 3 refused.
use crate::flag;
use denc::types::Ghobject;
use outfmt::Format;
use serde_json::{Value, json};
use store::dev::MonoClock;
use store::layout::{ShardDir, read_root, read_super, wal_store_id};
use store::sio::Sio;
use store::wal::{self, StopReason, UnitValidity};

/// Does replay stop at a condition that refuses the mount (or drops acked txns)?
fn mount_ok(s: &wal::InspectStop) -> bool {
    !matches!(
        s.reason,
        StopReason::WalLost
            | StopReason::Undecodable
            | StopReason::NewerIncarnation
            | StopReason::RunWindow
    )
}

fn reason_str(r: StopReason) -> &'static str {
    match r {
        StopReason::End => "end",
        StopReason::Torn => "torn",
        StopReason::Foreign => "foreign",
        StopReason::DataCrc => "data_crc",
        StopReason::Undecodable => "undecodable",
        StopReason::NewerIncarnation => "newer_incarnation",
        StopReason::RunWindow => "run_window",
        StopReason::WalLost => "wal_lost",
    }
}

fn validity_str(v: UnitValidity) -> &'static str {
    match v {
        UnitValidity::Ok => "ok",
        UnitValidity::Torn => "torn",
        UnitValidity::Foreign => "foreign",
    }
}

/// Compact object name of an `N`/`L` name key: `[namespace:]oid`.
fn obj_str(g: &Ghobject) -> String {
    let h = &g.hobj;
    if h.max {
        return "MAX".into();
    }
    let oid = String::from_utf8_lossy(&h.oid);
    if h.nspace.is_empty() {
        oid.into_owned()
    } else {
        format!("{}:{oid}", String::from_utf8_lossy(&h.nspace))
    }
}

/// One op summary line (plain output): `put pg=1.2s0 obj=o3 4096B`.
fn op_plain(o: &wal::InspectOp) -> String {
    let mut s = o.kind.to_string();
    if let Some(c) = &o.coll {
        s.push_str(&format!(" pg={c}"));
    }
    if let Some(g) = &o.object {
        s.push_str(&format!(" obj={}", obj_str(g)));
    } else if let Some(id) = o.id {
        s.push_str(&format!(" id={id}"));
    }
    if o.bytes > 0 {
        s.push_str(&format!(" {}B", o.bytes));
    }
    s
}

fn op_json(o: &wal::InspectOp) -> Value {
    json!({
        "kind": o.kind,
        "coll": o.coll.as_ref().map(ToString::to_string),
        "object": o.object.as_ref().map(obj_str),
        "id": o.id,
        "key": String::from_utf8_lossy(&o.key),
        "bytes": o.bytes,
    })
}

fn record_json(r: &wal::InspectRecord) -> Value {
    json!({
        "lsn": r.lsn,
        "ops": r.ops.iter().map(op_json).collect::<Vec<_>>(),
        "data": r.data.iter().map(|e| json!({"blk": e.blk, "nblk": e.nblk})).collect::<Vec<_>>(),
        "frees": r.frees.iter().map(|&(b, n)| json!([b, n])).collect::<Vec<_>>(),
    })
}

fn unit_json(u: &wal::InspectUnit) -> Value {
    json!({
        "pos": u.pos,
        "epoch": u.epoch,
        "first_lsn": u.first_lsn,
        "last_lsn": u.last_lsn,
        "acked_lsn": u.acked_lsn,
        "store_id": u.store_id,
        "blocks": u.blocks,
        "crc": u.crc,
        "part": u.part,
        "pad": u.pad,
        "validity": validity_str(u.validity),
        "records": u.records.iter().map(record_json).collect::<Vec<_>>(),
    })
}

fn stop_json(s: &wal::InspectStop) -> Value {
    json!({
        "reason": reason_str(s.reason),
        "pos": s.pos,
        "lsn": s.lsn,
        "acked_lsn": s.acked_lsn,
        "witness": s.witness,
        "blk": s.blk,
        "message": s.message,
    })
}

/// Document of one shard (json / json-pretty, and the jsonl `result` record without `units`).
fn shard_doc(
    shard: u32,
    root: &store::layout::RootSlot,
    rep: &wal::WalInspect,
    preview: bool,
) -> Value {
    let mut v = json!({
        "shard": shard,
        "root": {
            "epoch": root.epoch,
            "ckpt_lsn": root.ckpt_lsn,
            "wal_tail_pos": root.wal_tail_pos,
            "wal_tail_prev_crc": root.wal_tail_prev_crc,
        },
        "ok": mount_ok(&rep.stop),
        "units": rep.units.iter().map(unit_json).collect::<Vec<_>>(),
        "stop": stop_json(&rep.stop),
    });
    if preview {
        v["dropped"] = Value::Array(rep.dropped.iter().map(record_json).collect());
    }
    v
}

/// Stop line for the plain output.
fn stop_plain(s: &wal::InspectStop) -> String {
    let mut m = format!(
        "{} at block {} (lsn {})",
        reason_str(s.reason),
        s.pos,
        s.lsn
    );
    if let Some(a) = s.acked_lsn {
        m.push_str(&format!(": acked txns {}..={a} lost", s.lsn));
    }
    if let Some(w) = s.witness {
        m.push_str(&format!(" (witness unit at block {w})"));
    }
    if let Some(b) = s.blk {
        m.push_str(&format!(" (data block {b})"));
    }
    if let Some(msg) = &s.message {
        m.push_str(&format!(": {msg}"));
    }
    m
}

pub fn run(a: &[String], f: Format) -> i32 {
    let preview = flag(a, "--preview-loss");
    let shard = match crate::num_opt(a, "--shard") {
        Ok(o) => o,
        Err(e) => return crate::usage_err(&e),
    };
    let (spec, ctrl) = match crate::ops::device(a) {
        Ok(x) => x,
        Err(c) => return c,
    };
    let mut dev = match ctrl.open_queue() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("croit-flashstore-tool: wal-inspect: {e}");
            return 1;
        }
    };
    let mut clk = MonoClock::default();
    let (sb, dirs) = match read_super(&mut dev, &mut clk) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("croit-flashstore-tool: wal-inspect: superblock: {e}");
            return 1;
        }
    };
    drop(dev);
    let selected: Vec<&ShardDir> = match shard {
        Some(n) => {
            let n = n as u32;
            match dirs.iter().find(|d| d.shard == n) {
                Some(d) => vec![d],
                None => {
                    return crate::usage_err(&format!(
                        "--shard {n}: no such shard (the store has {} shard(s))",
                        sb.shards
                    ));
                }
            }
        }
        None => dirs.iter().collect(),
    };

    let mut reports: Vec<(u32, store::layout::RootSlot, wal::WalInspect)> = Vec::new();
    let mut all_ok = true;
    for d in selected {
        let mut q = match ctrl.open_queue() {
            Ok(q) => q,
            Err(e) => {
                eprintln!("croit-flashstore-tool: wal-inspect: shard {}: {e}", d.shard);
                return 1;
            }
        };
        let mut clk = MonoClock::default();
        let root = match read_root(&mut q, &mut clk, d) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "croit-flashstore-tool: wal-inspect: shard {}: root: {e}",
                    d.shard
                );
                return 1;
            }
        };
        let store_id = wal_store_id(&sb, d.shard);
        let mut io = Sio::new(&mut q, &mut clk);
        let rep = match wal::inspect(&mut io, d, &root, store_id, &wal::ReplayCfg::default()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("croit-flashstore-tool: wal-inspect: shard {}: {e}", d.shard);
                return 1;
            }
        };
        all_ok &= mount_ok(&rep.stop);
        reports.push((d.shard, root, rep));
    }

    match f {
        Format::Jsonl => {
            for (shard, _root, rep) in &reports {
                for u in &rep.units {
                    let mut v = unit_json(u);
                    v["type"] = json!("unit");
                    v["shard"] = json!(shard);
                    println!("{}", f.doc(&v));
                    for r in &u.records {
                        let mut rv = record_json(r);
                        rv["type"] = json!("record");
                        rv["shard"] = json!(shard);
                        rv["unit_pos"] = json!(u.pos);
                        println!("{}", f.doc(&rv));
                    }
                }
                let mut v = json!({
                    "type": "result",
                    "shard": shard,
                    "ok": mount_ok(&rep.stop),
                    "stop": stop_json(&rep.stop),
                });
                if preview {
                    v["dropped"] = Value::Array(rep.dropped.iter().map(record_json).collect());
                }
                println!("{}", f.doc(&v));
            }
        }
        Format::Plain => {
            for (shard, root, rep) in &reports {
                println!(
                    "shard {shard}: ckpt_lsn {} epoch {} wal tail block {}",
                    root.ckpt_lsn, root.epoch, root.wal_tail_pos
                );
                for u in &rep.units {
                    println!(
                        "  unit @{}: lsn {}..{} acked {} store_id {} epoch {} [{}] {} block(s)",
                        u.pos,
                        u.first_lsn,
                        u.last_lsn,
                        u.acked_lsn,
                        u.store_id,
                        u.epoch,
                        validity_str(u.validity),
                        u.blocks
                    );
                    for r in &u.records {
                        let ops: Vec<String> = r.ops.iter().map(op_plain).collect();
                        println!("    txn {}: {}", r.lsn, ops.join(", "));
                    }
                }
                println!("  stop: {}", stop_plain(&rep.stop));
                if preview {
                    match rep.stop.acked_lsn {
                        None => {
                            println!("  --accept-wal-loss would drop nothing (no acked txn lost)")
                        }
                        Some(acked) => {
                            println!(
                                "  --accept-wal-loss drops every txn from lsn {} on (acked up to {acked}); {} decodable:",
                                rep.stop.lsn,
                                rep.dropped.len()
                            );
                            for r in &rep.dropped {
                                let ops: Vec<String> = r.ops.iter().map(op_plain).collect();
                                println!("    txn {}: {}", r.lsn, ops.join(", "));
                            }
                        }
                    }
                }
            }
        }
        Format::Json | Format::JsonPretty => {
            let doc = json!({
                "dev": spec,
                "shards": reports
                    .iter()
                    .map(|(s, root, rep)| shard_doc(*s, root, rep, preview))
                    .collect::<Vec<_>>(),
            });
            println!("{}", f.doc(&doc));
        }
    }
    if all_ok { 0 } else { 1 }
}
