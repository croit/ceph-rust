// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Operator commands beyond the core set of `tell.rs` (parity WP-T, spec/ops-observability.md 1): the classic admin
//! socket commands tooling and operators use that have an croit-flashstore-osd equivalent, plus clean refusals for the ones that
//! cannot apply (heap profiler, BlueFS, RocksDB). Output shapes follow classic; where the numbers do not exist here
//! they are zero and the command says so in `note`.
use crate::backend::Backend;
use crate::osd::Osd;
use crate::tell::{EINVAL, EIO, ENOENT, Out, ReplyTo, Res};
use denc::types::{SpgT, UTime};
use peering::PgStoreOps as _;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const EBUSY: i32 = -16;
pub(crate) const EINTR: i32 = -4;
pub(crate) const EAGAIN: i32 = -11;
pub(crate) const EOPNOTSUPP: i32 = -95;

const NO_TCMALLOC: &str = "could not issue heap profiler command -- not using tcmalloc! (croit-flashstore-osd uses mimalloc)";
const NO_ONLINE_EXPAND: &str = "online expand is not supported (the shard layout is fixed while the OSD runs): stop the OSD, run `croit-flashstore-tool expand --id N`, start it; capacity then includes the new space";

/// PG-addressed sub-commands (`pg <pgid> <cmd>`, or the bare classic prefix with a `pgid`).
const PG_CMDS: &[&str] = &[
    "query",
    "log",
    "list_unfound",
    "mark_unfound_lost",
    "scrub-abort",
    "scrubdebug",
    "schedule-scrub",
    "schedule-deep-scrub",
];

/// Rewrite the bare classic PG prefixes (`list_unfound`, `mark_unfound_lost`, `scrub-abort`, ...) to the
/// `{"prefix":"pg","cmd":...}` form, and split `bluestore allocator <op> <name>` typed as one line.
pub(crate) fn normalize(v: Value) -> Value {
    let prefix = v.get("prefix").and_then(Value::as_str).unwrap_or("");
    // the bare `log` spelling is only a pg command with a pgid; `log dump|flush|reopen` stay distinct
    if prefix == "log"
        && v.get("pgid").is_some()
        && let Some(mut o) = v.as_object().cloned()
    {
        o.insert("cmd".into(), json!("log"));
        o.insert("prefix".into(), json!("pg"));
        return Value::Object(o);
    }
    if prefix != "pg"
        && PG_CMDS.contains(&prefix)
        && let Some(mut o) = v.as_object().cloned()
    {
        o.insert("cmd".into(), json!(prefix));
        o.insert("prefix".into(), json!("pg"));
        return Value::Object(o);
    }
    // legacy admin socket names (pre-`perf` words)
    let legacy = match prefix {
        "perfcounters_dump" => Some("perf dump"),
        "perfcounters_schema" => Some("perf schema"),
        _ => None,
    };
    if let Some(p) = legacy
        && let Some(mut o) = v.as_object().cloned()
    {
        o.insert("prefix".into(), json!(p));
        return Value::Object(o);
    }
    for op in ["dump", "score", "fragmentation"] {
        let head = format!("bluestore allocator {op}");
        if let Some(rest) = prefix.strip_prefix(&format!("{head} "))
            && let Some(mut o) = v.as_object().cloned()
        {
            o.insert("name".into(), json!(rest.trim()));
            o.insert("prefix".into(), json!(head));
            return Value::Object(o);
        }
    }
    v
}

/// The `pg` sub-command of a normalized command.
pub(crate) fn pg_sub(v: &Value) -> Option<&str> {
    (v.get("prefix").and_then(Value::as_str) == Some("pg"))
        .then(|| v.get("cmd").and_then(Value::as_str))
        .flatten()
}

impl<B: Backend> Osd<B> {
    /// `log dump` `--- logging levels ---` section: every `debug_<subsystem>` option with its effective `log/gather`
    /// value, then the default sink thresholds (this daemon logs the `osd` subsystem).
    fn logging_levels(&self) -> String {
        let meta = self.config_meta();
        let mut names: Vec<&str> = crate::schema::names()
            .filter(|n| n.starts_with("debug_"))
            .collect();
        names.sort_unstable();
        let mut s = String::from("--- logging levels ---\n");
        for n in names {
            let v = crate::schema::get(&self.conf, &meta, n).unwrap_or_default();
            s.push_str(&format!(" {:>8} {}\n", v, &n["debug_".len()..]));
        }
        let osd = crate::schema::get(&self.conf, &meta, "debug_osd").unwrap_or_default();
        for sink in ["syslog", "stderr"] {
            s.push_str(&format!(" {:>8} ({sink})\n", osd));
        }
        s
    }
}

/// Ceph's `byte_u_t` text of a size (`64 MiB`): the largest binary unit, whole units.
fn byte_text(n: u64) -> String {
    const UNITS: [(&str, u64); 5] = [
        ("TiB", 1 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
        ("B", 1),
    ];
    for (unit, size) in UNITS {
        if n >= size {
            return format!("{} {unit}", n / size);
        }
    }
    format!("{n} B")
}

/// A running `bench` (control core).
pub(crate) struct Bench {
    to: ReplyTo,
    bsize: u64,
    count: u64,
    t0: std::time::Instant,
    done: u64,
    i: u64,
    buf: Vec<u8>,
}

/// Commands whose parts run on every core.
pub(crate) fn is_scattered(prefix: &str, v: &Value) -> bool {
    (cfg!(feature = "rdma-fault")
        && matches!(prefix, "rdma fault qp-err" | "rdma fault write-qp-err"))
        || matches!(
            prefix,
            "dump_blocked_ops_count"
                | "dump_watchers"
                | "dump_op_pq_state"
                | "dump_pgstate_history"
                | "dump_pg_recovery_stats"
                | "reset_pg_recovery_stats"
                | "scrub_purged_snaps"
                | "dump_recovery_reservations"
                | "dump_scrub_reservations"
                | "get_mapped_pools"
                | "dump_pool_statfs"
                | "dump_mempools"
                | "flush_journal"
                | "cache status"
                | "cache drop"
                | "flush_store_cache"
                | "rdma status"
                | "debug dump_missing"
                | "bluestore allocator dump"
                | "bluestore allocator score"
                | "bluestore allocator fragmentation"
                | "store free"
                | "store census"
                | "bluestore dedup stats"
                | "bluestore dedup clear"
                | "bluestore dedup list"
        )
        || pg_sub(v).is_some_and(|c| c != "query")
}

/// `ctime` text of a local time: `Thu Nov  5 11:20:00 2026` (day space-padded, classic `ctime`).
fn ctime_parts(year: i32, mon: usize, mday: u32, h: u32, mi: u32, s: u32, wd: usize) -> String {
    const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{} {} {:>2} {:02}:{:02}:{:02} {year}",
        WD[wd % 7],
        MON[mon % 12],
        mday,
        h,
        mi,
        s
    )
}

/// Local broken-down time of unix `secs` (`localtime_r`); `None` when the time is not representable.
fn local_tm(secs: libc::time_t) -> Option<libc::tm> {
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: localtime_r fills the caller's `tm`; it returns NULL for a time it cannot represent.
    if unsafe { libc::localtime_r(&secs, tm.as_mut_ptr()) }.is_null() {
        return None;
    }
    // SAFETY: localtime_r returned non-NULL, so the whole `tm` is initialized.
    Some(unsafe { tm.assume_init() })
}

/// Classic `ctime` text of unix seconds in local time (`dump_osd_network` `last update`).
pub(crate) fn ctime_str(secs: u32) -> String {
    let Some(tm) = local_tm(secs as libc::time_t) else {
        let (y, m, d, h, mi, s) = osddir::civil_from_secs(u64::from(secs));
        // 1970-01-01 was a Thursday
        let wd = (u64::from(secs) / 86_400 + 4) % 7;
        return ctime_parts(
            y as i32,
            (m - 1) as usize,
            d as u32,
            h as u32,
            mi as u32,
            s as u32,
            wd as usize,
        );
    };
    ctime_parts(
        tm.tm_year + 1900,
        tm.tm_mon as usize,
        tm.tm_mday as u32,
        tm.tm_hour as u32,
        tm.tm_min as u32,
        tm.tm_sec as u32,
        tm.tm_wday as usize,
    )
}

/// Shard string of `list_unfound`: EC `osd(shard)`, replicated `osd`.
fn shard_text(s: &denc::types::PgShard, ec: bool) -> String {
    if ec {
        format!("{}({})", s.osd, s.shard.0)
    } else {
        s.osd.to_string()
    }
}

/// `clean_offsets: [o~l,...], clean_omap: <bool>, new_object: <bool>`.
fn clean_regions_text(c: &pgwire::ObjectCleanRegions) -> String {
    let offs: Vec<String> = c
        .clean_offsets
        .iter()
        .map(|(o, l)| format!("{o}~{l}"))
        .collect();
    format!(
        "clean_offsets: [{}], clean_omap: {}, new_object: {}",
        offs.join(","),
        c.clean_omap,
        c.new_object
    )
}

/// The `offset` of `list_unfound`: an hobject in its dump form ([`hobj_json`]), given as JSON text or object.
fn parse_hobj(v: &Value) -> Result<denc::types::Hobject, String> {
    let parsed;
    let o = match v {
        Value::String(s) => {
            parsed = serde_json::from_str::<Value>(s).map_err(|e| e.to_string())?;
            &parsed
        }
        v => v,
    };
    let o = o.as_object().ok_or("not a JSON object")?;
    let s = |k: &str| -> Result<Vec<u8>, String> {
        match o.get(k) {
            None => Ok(Vec::new()),
            Some(Value::String(s)) => Ok(s.as_bytes().to_vec()),
            Some(_) => Err(format!("'{k}' is not a string")),
        }
    };
    let n = |k: &str| -> Result<i128, String> {
        match o.get(k) {
            None => Ok(0),
            Some(Value::Number(x)) => x
                .as_i64()
                .map(i128::from)
                .or_else(|| x.as_u64().map(i128::from))
                .ok_or(format!("'{k}' is not an integer")),
            Some(Value::String(x)) => x
                .parse::<i128>()
                .map_err(|_| format!("'{k}' is not an integer")),
            Some(_) => Err(format!("'{k}' is not an integer")),
        }
    };
    let snap = n("snapid")?;
    Ok(denc::types::Hobject {
        oid: s("oid")?,
        key: s("key")?,
        // negative = the classic signed spelling (-2 head, -1 snapdir)
        snap: denc::types::SnapId(if snap < 0 {
            (u64::MAX as i128 + 1 + snap) as u64
        } else {
            u64::try_from(snap).map_err(|_| "'snapid' out of range".to_string())?
        }),
        hash: u32::try_from(n("hash")?).map_err(|_| "'hash' out of range".to_string())?,
        max: n("max")? != 0 || o.get("max").is_some_and(|m| m.as_bool() == Some(true)),
        nspace: s("namespace")?,
        pool: i64::try_from(n("pool")?).map_err(|_| "'pool' out of range".to_string())?,
    })
}

impl<B: Backend> Osd<B> {
    /// Owning core: a deferred `mark_unfound_lost` finished (`Action::LostMarked`); answer its command.
    pub(crate) fn lost_marked(&mut self, d: peering::LostDone) {
        let Some(q) = self.cmds.lost_wait.remove(&(d.spg, d.tid)) else {
            return;
        };
        let (r, rs) = match d.result {
            Ok(msg) => {
                self.clog(messages::clog::INFO, &msg);
                (0, msg)
            }
            Err((e, msg)) => (e, msg),
        };
        self.cmd_done(q, r, rs);
    }

    /// The PG instance a deferred `mark_unfound_lost` waits for is gone (`Action::PgRemoved`): no owner is left to
    /// answer it, so the command answers `-EAGAIN` (the entries it already appended stay in the log; `list_unfound`
    /// and a retry see them).
    pub(crate) fn lost_abandoned(&mut self, spg: denc::types::SpgT) {
        let keys: Vec<(denc::types::SpgT, u64)> = self
            .cmds
            .lost_wait
            .keys()
            .filter(|(s, _)| *s == spg)
            .copied()
            .collect();
        for key in keys {
            let Some(q) = self.cmds.lost_wait.remove(&key) else {
                continue;
            };
            self.cmd_done(
                q,
                EAGAIN,
                format!(
                    "pg {spg} was removed before the lost marking answered; check list_unfound and retry"
                ),
            );
        }
    }
}

fn hobj_json(h: &denc::types::Hobject) -> Value {
    json!({"oid": String::from_utf8_lossy(&h.oid), "key": String::from_utf8_lossy(&h.key),
        "snapid": h.snap.0, "hash": h.hash, "max": u8::from(h.max), "pool": h.pool,
        "namespace": String::from_utf8_lossy(&h.nspace)})
}

fn name_json(n: &denc::types::EntityName) -> Value {
    let s = n.to_string();
    json!({"type": s.split('.').next().unwrap_or(""), "num": n.num})
}

/// Process memory in kB from `/proc/self/status` (Linux; empty elsewhere): VmRSS, VmHWM, RssAnon, RssFile.
fn proc_mem() -> Value {
    let mut m = serde_json::Map::new();
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for l in s.lines() {
            let Some((k, v)) = l.split_once(':') else {
                continue;
            };
            if matches!(k, "VmRSS" | "VmHWM" | "RssAnon" | "RssFile" | "VmSize") {
                let kb = v
                    .trim()
                    .trim_end_matches("kB")
                    .trim()
                    .parse::<u64>()
                    .unwrap_or(0);
                m.insert(k.to_owned(), json!(kb));
            }
        }
    }
    Value::Object(m)
}

/// Duration in the classic `utime_t` text form: `<sec>.<usec, 6 digits>`.
fn dur_str(ns: u64) -> String {
    format!("{}.{:06}", ns / 1_000_000_000, ns % 1_000_000_000 / 1000)
}

/// `epoch'version` (classic eversion text).
fn ev_str(e: denc::types::Eversion) -> String {
    format!("{}'{}", e.epoch, e.version)
}

/// `<entity>.<inc>:<tid>` of a request id.
fn reqid_str(r: denc::types::OsdReqId) -> String {
    format!("{}.{}:{}", r.name, r.inc, r.tid)
}

/// Classic escaping of an object name part (non-printable, `:` and `\` as `\xHH`).
fn escaped(b: &[u8]) -> String {
    let mut s = String::new();
    for &c in b {
        if (0x20..=0x7e).contains(&c) && c != b':' && c != b'\\' {
            s.push(c as char);
        } else {
            s.push_str(&format!("\\x{c:02x}"));
        }
    }
    s
}

/// hobject text `<pool>:<8 hex hash>:<nspace>:<key>:<name>:<snap>`; `MIN`/`MAX` for the sentinels (spec 5.2).
fn hobj_text(h: &denc::types::Hobject) -> String {
    if h.max {
        return "MAX".into();
    }
    if h.pool == i64::MIN && h.key.is_empty() && h.oid.is_empty() {
        return "MIN".into();
    }
    format!(
        "{}:{:08x}:{}:{}:{}:{}",
        h.pool,
        h.hash,
        escaped(&h.nspace),
        escaped(&h.key),
        escaped(&h.oid),
        h.snap.0
    )
}

/// `shard_id_set` as `[0,1]`.
fn shard_set_text(s: pgwire::ShardIdSet) -> String {
    let mut v: Vec<String> = Vec::new();
    for (w, bits) in s.0.iter().enumerate() {
        for b in 0..64 {
            if bits & (1u64 << b) != 0 {
                v.push((w * 64 + b).to_string());
            }
        }
    }
    format!("[{}]", v.join(","))
}

/// Classic `interval_set` text `[start~len,...]`.
fn interval_text(m: &std::collections::BTreeMap<u64, u64>) -> String {
    let v: Vec<String> = m.iter().map(|(o, l)| format!("{o}~{l}")).collect();
    format!("[{}]", v.join(","))
}

/// ISO-8601 local time with microseconds and numeric offset (log entry `mtime`).
fn mtime_text(t: denc::types::UTime) -> String {
    let Some(tm) = local_tm(u64::from(t.sec) as libc::time_t) else {
        return crate::pgs::utime_str(t);
    };
    let off = tm.tm_gmtoff;
    let (sign, off) = if off < 0 { ('-', -off) } else { ('+', off) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}{sign}{:02}{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        t.nsec / 1000,
        off / 3600,
        off % 3600 / 60
    )
}

/// `object_mod_desc` ops of an entry (spec 5.2); an undecodable body reports no ops.
fn mod_ops_json(bl: &[u8]) -> Value {
    let Ok(ops) = ec::moddesc::parse(bl) else {
        return Value::Array(Vec::new());
    };
    let v: Vec<Value> = ops
        .into_iter()
        .map(|op| match op {
            ec::moddesc::ModOp::Append { old_size } => {
                json!({"op": "APPEND", "old_size": old_size})
            }
            ec::moddesc::ModOp::SetAttrs(a) => json!({
                "op": "SETATTRS",
                "attrs": a.iter().map(|(k, _)| json!({"attr_name": escaped(k)})).collect::<Vec<_>>()
            }),
            ec::moddesc::ModOp::Delete { version } => {
                json!({"op": "RMOBJECT", "old_version": version})
            }
            ec::moddesc::ModOp::TryDelete { version } => {
                json!({"op": "TRY_RMOBJECT", "old_version": version})
            }
            ec::moddesc::ModOp::Create => json!({"op": "CREATE"}),
            ec::moddesc::ModOp::UpdateSnaps(s) => json!({"op": "UPDATE_SNAPS", "snaps": s}),
            ec::moddesc::ModOp::RollbackExtents {
                generation,
                extents,
                object_size,
                shards,
            } => json!({
                "op": "ROLLBACK_EXTENTS",
                "gen": generation,
                "object_size": object_size.unwrap_or(0),
                "extents": extents,
                "shards": shards
                    .iter()
                    .map(|s| shard_set_text(pgwire::ShardIdSet(*s)))
                    .collect::<Vec<_>>(),
                // reference quirk: the extents list is printed again under `snaps`
                "snaps": extents,
            }),
            ec::moddesc::ModOp::EcOmap(_) => json!({"op": "EC_OMAP"}),
        })
        .collect();
    Value::Array(v)
}

fn op_returns(v: &[pgwire::LogOpReturnItem]) -> Option<Value> {
    (!v.is_empty()).then(|| {
        json!(
            v.iter()
                .map(|o| json!({"rval": o.rval, "bl_length": o.outdata.len()}))
                .collect::<Vec<_>>()
        )
    })
}

/// One `pg_log_entry_t` dump (spec 5.2): a bare object (the reference's `entry` section name is dropped inside the
/// `log` array).
fn log_entry_json(e: &pgwire::LogEntry) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("op".into(), json!(e.op.name()));
    m.insert("object".into(), json!(hobj_text(&e.soid)));
    m.insert("version".into(), json!(ev_str(e.version)));
    m.insert("prior_version".into(), json!(ev_str(e.prior_version)));
    m.insert("reqid".into(), json!(reqid_str(e.reqid)));
    let extra: Vec<Value> = e
        .extra_reqids
        .iter()
        .enumerate()
        .map(|(i, (r, uv))| {
            let mut x = json!({"reqid": reqid_str(*r), "user_version": uv});
            if let Some(rc) = e.extra_reqid_return_codes.get(&(i as u32)) {
                x["return_code"] = json!(rc);
            }
            x
        })
        .collect();
    m.insert("extra_reqids".into(), Value::Array(extra));
    m.insert("mtime".into(), json!(mtime_text(e.mtime)));
    m.insert("return_code".into(), json!(e.return_code));
    if let Some(o) = op_returns(&e.op_returns) {
        m.insert("op_returns".into(), o);
    }
    if e.op == pgwire::LogOp::CLONE && !e.snaps.is_empty() {
        let snaps = peering::snaps::decode_snaps(&e.snaps);
        // repeated `"snap"` keys in the reference; serde_json keeps one key, so >1 becomes a list
        let v = match snaps.len() {
            1 => json!({"snap": snaps[0]}),
            _ => json!({"snap": snaps}),
        };
        m.insert("snaps".into(), v);
    }
    m.insert(
        "written_shards".into(),
        json!(shard_set_text(e.written_shards)),
    );
    m.insert(
        "mod_desc".into(),
        json!({"object_mod_desc": {
            "can_local_rollback": e.mod_desc.can_local_rollback,
            "rollback_info_completed": e.mod_desc.rollback_info_completed,
            "ops": mod_ops_json(&e.mod_desc.bl),
        }}),
    );
    m.insert(
        "clean_regions".into(),
        json!({"object_clean_regions": {
            "clean_offsets": interval_text(&e.clean_regions.clean_offsets),
            "clean_omap": e.clean_regions.clean_omap,
            "new_object": e.clean_regions.new_object,
        }}),
    );
    Value::Object(m)
}

fn log_dup_json(d: &pgwire::LogDup) -> Value {
    let mut m = json!({
        "reqid": reqid_str(d.reqid),
        "version": ev_str(d.version),
        "user_version": d.user_version,
        "return_code": d.return_code,
    });
    if let Some(o) = op_returns(&d.op_returns) {
        m["op_returns"] = o;
    }
    m
}

/// `{"pg_log_t": {head, tail, log, dups}}` (spec osd-tell-gaps.md 5.2).
fn pg_log_json(p: &peering::Pg) -> Value {
    let l = p.log();
    json!({"pg_log_t": {
        "head": ev_str(l.head()),
        "tail": ev_str(l.tail()),
        "log": l.entries().iter().map(log_entry_json).collect::<Vec<_>>(),
        "dups": l.log.dups.iter().map(log_dup_json).collect::<Vec<_>>(),
    }})
}

fn sum(parts: &[(i32, Value)], key: &str) -> u64 {
    parts.iter().filter_map(|(_, p)| p[key].as_u64()).sum()
}

/// Sum of the cores' parts of a `{name: u64}` document (counters that add up over the cores).
fn sum_parts(parts: &[(i32, Value)]) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    for (_, p) in parts {
        for (k, x) in p.as_object().into_iter().flatten() {
            let t = m.get(k).and_then(Value::as_u64).unwrap_or(0);
            m.insert(k.clone(), json!(t + x.as_u64().unwrap_or(0)));
        }
    }
    m
}

fn spg_list(v: &[SpgT]) -> Value {
    Value::Array(v.iter().map(|s| json!(s.to_string())).collect())
}

fn arr_of(v: &Value, key: &str) -> Vec<Value> {
    v[key].as_array().cloned().unwrap_or_default()
}

impl<B: Backend> Osd<B> {
    // ------------------------------------------------------------------ per-core parts

    /// The part of a scattered command of this module that runs on this core.
    pub(crate) fn query_local_ext(&mut self, prefix: &str, v: &Value) -> Option<(i32, Value)> {
        let now = self.now.as_nanos() as u64;
        Some(match prefix {
            "dump_blocked_ops_count" => {
                let n = self.tracker.slow(now).0
                    + self.pg_parked_slow(now, self.tracker.lim.complaint_ns).0;
                (0, json!(n))
            }
            "dump_watchers" => {
                let mut w = Vec::new();
                for e in self.pg.eng.values() {
                    for (h, (cookie, name), timeout, addr) in e.watchers() {
                        w.push(json!({"namespace": String::from_utf8_lossy(&h.nspace),
                            "object": String::from_utf8_lossy(&h.oid), "entity_name": name_json(&name),
                            "cookie": cookie, "timeout": timeout,
                            "entity_addr_t": crate::tell::addr_json(&addr)}));
                    }
                }
                (0, Value::Array(w))
            }
            "dump_op_pq_state" => {
                let live = self.tracker.len();
                (
                    0,
                    json!({"shard": self.core_id(), "ops_in_flight": live,
                        "ops_parked": self.pg_parked_len(), "pgs": self.pg.set.pgs().count(),
                        "pgs_with_parked_ops": self.pg.eng_parked.len()}),
                )
            }
            "dump_pgstate_history" => {
                let mut pgs = Vec::new();
                for (spg, h) in &self.pg.state_hist {
                    let cur = self.pg.set.pg(*spg).map(|p| p.state_string());
                    let at = |ns: u64| {
                        crate::pgs::utime_str(UTime::new(
                            (ns / 1_000_000_000) as u32,
                            (ns % 1_000_000_000) as u32,
                        ))
                    };
                    let hist: Vec<Value> = h
                        .iter()
                        .enumerate()
                        .map(|(i, (t, s))| {
                            let exit = h.get(i + 1).map(|n| at(n.0)).unwrap_or_default();
                            json!({"state": s, "enter": at(*t), "exit": exit, "events": []})
                        })
                        .collect();
                    pgs.push(
                        json!({"pg": spg.to_string(), "currently": cur.unwrap_or_default(),
                        "history": hist}),
                    );
                }
                (0, Value::Array(pgs))
            }
            "dump_pg_recovery_stats" => {
                let rows: Vec<Value> = self
                    .pg
                    .set
                    .rec_stats()
                    .rows()
                    .map(|(name, r)| {
                        json!({"name": name, "enter": r.enter, "exit": r.exit, "events": r.events,
                            "event_ns": r.event_ns, "total_ns": r.total_ns, "min_ns": r.min_ns,
                            "max_ns": r.max_ns})
                    })
                    .collect();
                (0, Value::Array(rows))
            }
            "reset_pg_recovery_stats" => {
                self.pg.set.reset_rec_stats();
                (0, Value::Null)
            }
            "scrub_purged_snaps" => match self.cmds.cur_query {
                Some(q) => {
                    self.cmds.purged_waiters.push(q);
                    self.pg.set.purged_snaps_start();
                    (crate::tell::PENDING, Value::Null)
                }
                None => (EINVAL, json!("scrub_purged_snaps: no command to answer")),
            },
            "dump_recovery_reservations" => {
                let peering::Reservations { local, remote, .. } = self.pg.set.reservations();
                let (lgranted, lqueued) = (local.granted, local.queued);
                let (granted, queued) = (remote.granted, remote.queued);
                let kind = |b: bool| if b { "backfill" } else { "recovery" };
                let item = |s: &SpgT, prio: u32, k: &str| json!({"item": s.to_string(), "prio": prio, "kind": k});
                let lheld: Vec<Value> =
                    lgranted.iter().map(|(s, b)| item(s, 0, kind(*b))).collect();
                let lwait: Vec<Value> = lqueued
                    .iter()
                    .map(|(p, s, b)| item(s, *p, kind(*b)))
                    .collect();
                let (ops, quota) = self.pg.set.rec_ops();
                (
                    0,
                    json!({
                        "rec_ops": {"in_flight": ops, "peak": self.pg.set.rec_peak(), "quota": quota, "budget": self.pg.set.rec_budget()},
                        "local_held": lheld, "local_waiting": lwait,
                        "remote_held": granted.iter().map(|(s, b)| item(s, 0, kind(*b))).collect::<Vec<_>>(),
                        "remote_queued": queued.iter().map(|(p, s, b)| item(s, *p, kind(*b))).collect::<Vec<_>>(),
                    }),
                )
            }
            "dump_scrub_reservations" => {
                let (local, granted, queued) = self.pg.set.scrub_reservations();
                (
                    0,
                    json!({"local": spg_list(&local), "granted": spg_list(&granted),
                        "queued": spg_list(&queued)}),
                )
            }
            "get_mapped_pools" => {
                let pools: BTreeSet<u64> = self.pg.set.pgs().map(|(s, _)| s.pgid.pool).collect();
                (0, json!(pools))
            }
            "dump_pool_statfs" => {
                let Some(pool) = v.get("poolid").and_then(Value::as_u64) else {
                    return Some((
                        EINVAL,
                        json!("Error dumping pool statfs: no poolid provided"),
                    ));
                };
                let (mut pgs, mut objects, mut bytes) = (0u64, 0u64, 0u64);
                for (s, _) in self.pg.set.pgs().filter(|(s, _)| s.pgid.pool == pool) {
                    let (o, b) = self.pg.store.object_stats(*s);
                    pgs += 1;
                    objects += o;
                    bytes += b;
                }
                (0, json!({"pgs": pgs, "objects": objects, "bytes": bytes}))
            }
            "dump_mempools" => {
                let log: usize = self.pg.set.pgs().map(|(_, p)| p.log().len()).sum();
                let log_bytes: u64 = self.pg.set.pgs().map(|(_, p)| p.log().mem_bytes()).sum();
                let pools: Vec<Value> = self
                    .pg
                    .store
                    .mem_pools()
                    .into_iter()
                    .map(|(n, i, b)| json!([n, i, b]))
                    .collect();
                // decoded inputs retained per connection while their ingress pool is full: NOT yet reserved (one per
                // connection; doc/design/memory-envelope.md, gap G1)
                let (held, held_bytes) = self
                    .links
                    .values()
                    .filter_map(|l| l.pending_input.as_ref())
                    .fold((0u64, 0u64), |(n, b), p| {
                        let bytes = match p {
                            crate::osd::PendingInput::Op { bytes, .. }
                            | crate::osd::PendingInput::Peer { bytes, .. } => *bytes,
                        };
                        (n + 1, b + bytes as u64)
                    });
                (
                    0,
                    json!({"pgs": self.pg.set.pgs().count(), "pglog": log, "pglog_bytes": log_bytes,
                        "parked_bytes": self.pg.parked_bytes, "pools": pools,
                        "held": held, "held_bytes": held_bytes,
                        "ingress": self.cl.ingress.pool_stats().iter().map(|p|
                            json!({"used": p.used, "limit": p.limit, "stalls": p.stalls, "waiters": p.waiters, "waits": p.waits})).collect::<Vec<_>>()}),
                )
            }
            "flush_journal" => {
                self.pg.store.request_checkpoint();
                (0, Value::Null)
            }
            "rdma status" => (0, self.rdma_part()),
            #[cfg(feature = "rdma-fault")]
            "rdma fault qp-err" => {
                // TEST ONLY: `rdma fault qp-err [count]`; armed once per process (control core), consumed by the next core poll with a connection
                if self.is_control() {
                    let n = v.get("count").and_then(Value::as_u64).unwrap_or(1) as u32;
                    rdma::fault::arm_qp_err(n);
                }
                (0, json!({"pending_qp_err": rdma::fault::pending_qp_err()}))
            }
            #[cfg(feature = "rdma-fault")]
            "rdma fault write-qp-err" => {
                let Some(n) = v
                    .get("count")
                    .map_or(Some(1), |v| v.as_u64().and_then(|n| u32::try_from(n).ok()))
                else {
                    return Some((EINVAL, json!("count must fit u32")));
                };
                if self.is_control() {
                    rdma::fault::arm_write_qp_err(n);
                }
                let (pending, triggered, failed) = rdma::fault::write_qp_err_state();
                (
                    0,
                    json!({"pending_write_qp_err":pending,"triggered_write_qp_err":triggered,"failed_write_qp_err":failed}),
                )
            }
            "store census" => {
                let req = v.get("request").is_some_and(|x| {
                    x.as_bool() == Some(true) || x.as_str().is_some_and(|s| s == "true" || s == "1")
                });
                let m: serde_json::Map<String, Value> = self
                    .pg
                    .store
                    .store_census(req)
                    .into_iter()
                    .map(|(k, x)| (k.to_owned(), json!(x)))
                    .collect();
                (0, Value::Object(m))
            }
            "cache status" => {
                let mut m: serde_json::Map<String, Value> = self
                    .pg
                    .store
                    .cache_status()
                    .into_iter()
                    .map(|(k, x)| (k.to_owned(), json!(x)))
                    .collect();
                m.insert(
                    "object_ctx".into(),
                    json!(
                        self.pg
                            .eng
                            .values()
                            .map(|e| e.obj_cache_len() as u64)
                            .sum::<u64>()
                    ),
                );
                (0, Value::Object(m))
            }
            "cache drop" | "flush_store_cache" => {
                // between operations on this core: the PG object-state caches go with the store's clean caches
                let objs: usize = self.pg.eng.values_mut().map(|e| e.drop_obj_cache()).sum();
                let mut m: serde_json::Map<String, Value> = self
                    .pg
                    .store
                    .drop_caches()
                    .into_iter()
                    .map(|(k, x)| (k.to_owned(), json!(x)))
                    .collect();
                m.insert("dropped_object_ctx".into(), json!(objs));
                (0, Value::Object(m))
            }
            "debug dump_missing" => {
                let pgs: Vec<Value> = self
                    .pg
                    .set
                    .pgs()
                    .map(|(spg, p)| {
                        let unfound: BTreeSet<_> = p.unfound().into_iter().map(|u| u.oid).collect();
                        let items: Vec<Value> = p
                            .missing()
                            .iter()
                            .map(|(o, i)| {
                                let mut j = json!({"oid": hobj_json(o),
                                    "missing_info": {"need": i.need.to_string(), "have": i.have.to_string(),
                                        "flags": if i.is_delete() { "delete" } else { "none" }}});
                                if p.is_primary() {
                                    j["unfound"] = json!(unfound.contains(o));
                                    // classic: the shards recovery can read it from (none when unfound)
                                    let locs: Vec<Value> =
                                        p.missing_locations(o).iter().map(|s| json!({"osd": s.osd})).collect();
                                    j["locations"] = json!(locs);
                                }
                                j
                            })
                            .collect();
                        json!({"pgid": spg.to_string(), "missing": items})
                    })
                    .collect();
                return Some((0, json!(pgs)));
            }
            "bluestore allocator dump"
            | "bluestore allocator score"
            | "store free"
            | "bluestore allocator fragmentation" => {
                return Some(match self.pg.store.free_report() {
                    Some((cap, ext)) => (0, json!({"capacity": cap, "extents": ext})),
                    None => (EOPNOTSUPP, Value::Null),
                });
            }
            "bluestore dedup stats" | "bluestore dedup clear" | "bluestore dedup list" => {
                return Some(self.dedup_local(prefix, v));
            }
            "pg" => return Some(self.pg_sub_local(v)),
            _ => return None,
        })
    }

    /// This core's part of `bluestore dedup stats|clear|list` (adr 0593-dedup-deep-scrub-reformat), merged by `dedup_merge`.
    fn dedup_local(&mut self, prefix: &str, v: &Value) -> (i32, Value) {
        let pool = int_arg(v, "pool").unwrap_or(-1);
        if pool < 0 {
            return (EINVAL, json!(format!("Invalid pool id:{pool}")));
        }
        match prefix {
            "bluestore dedup stats" => {
                let (b, n) = self.pg.store.dedup_stats(pool).unwrap_or((0, 0));
                (0, json!({"bytes": b, "entries": n}))
            }
            "bluestore dedup clear" => match self.pg.store.dedup_clear(pool) {
                Some(Err(e)) => (EIO, json!(format!("Execution error:{e}"))),
                _ => (0, Value::Null),
            },
            _ => match dedup_list_req(v) {
                Err((r, m)) => (r, json!(m)),
                Ok(req) => {
                    let p = match self.pg.store.dedup_list(&req) {
                        None => peering::store::DedupListPart {
                            completed: true,
                            ..Default::default()
                        },
                        Some(Ok(p)) => p,
                        Some(Err(e)) => return (EIO, json!(format!("Execution error:{e}"))),
                    };
                    let e: Vec<Value> = p
                        .entries
                        .iter()
                        .map(|e| {
                            json!({"key": hex_up(&e.key), "digest": hex_up(&e.digest), "ts": e.ts_ns,
                                "hash_key": e.hash_key})
                        })
                        .collect();
                    (
                        0,
                        json!({"entries": e, "examined": hex_up(&p.examined), "completed": p.completed}),
                    )
                }
            },
        }
    }

    /// `list_unfound`, `mark_unfound_lost`, `scrub-abort`, `scrubdebug`, `schedule-[deep-]scrub` on the core owning the PG.
    fn pg_sub_local(&mut self, v: &Value) -> (i32, Value) {
        let cmd = v.get("cmd").and_then(Value::as_str).unwrap_or("");
        let pgid = v.get("pgid").and_then(Value::as_str).unwrap_or("");
        let Some(pg) = crate::pgs::parse_pgid(pgid) else {
            return (EINVAL, json!(format!("couldn't parse pgid '{pgid}'")));
        };
        let Some(spg) = self
            .pg
            .set
            .pgs()
            .find(|(s, _)| s.pgid == pg)
            .map(|(s, _)| *s)
        else {
            return (ENOENT, Value::Null);
        };
        let Some(p) = self.pg.set.pg(spg) else {
            return (ENOENT, Value::Null);
        };
        let now = self.pg_mono();
        if cmd == "mark_unfound_lost" {
            // classic order (spec ec-unfound-lost.md 3): the mode, then the PG's own checks (EC revert before primary)
            let mode = match v.get("mulcmd").and_then(Value::as_str).unwrap_or("") {
                "revert" => peering::LostMode::Revert,
                "delete" => peering::LostMode::Delete,
                _ => {
                    return (
                        EINVAL,
                        json!("mode must be 'revert' or 'delete'; mark not yet implemented"),
                    );
                }
            };
            let (r, acts) = self
                .pg
                .set
                .mark_unfound_lost(now, spg, mode, &self.pg.store);
            let r = match r {
                Some(peering::LostReply::Later(tid)) => match self.cmds.cur_query {
                    Some(q) => {
                        self.cmds.lost_wait.insert((spg, tid), q);
                        // cached object states of the marked objects are stale (classic: obc marked non-existent)
                        if let Some(e) = self.pg.eng.get_mut(&spg) {
                            e.drop_obj_cache();
                        }
                        (crate::tell::DEFERRED, Value::Null)
                    }
                    None => (EINVAL, json!("mark_unfound_lost: no command to answer")),
                },
                Some(peering::LostReply::Now(Ok(msg))) => (0, json!(msg)),
                Some(peering::LostReply::Now(Err((e, msg)))) => (e, json!(msg)),
                None => (ENOENT, Value::Null),
            };
            self.pg_exec(acts);
            return r;
        }
        if cmd == "log" {
            // any holder answers its own copy (the primary's is authoritative); side-effect free (spec 5.2)
            return (0, pg_log_json(p));
        }
        if !p.is_primary() {
            return (EAGAIN, json!(format!("not primary for pgid {pgid}")));
        }
        match cmd {
            "list_unfound" => {
                let offset = match v.get("offset") {
                    None | Some(Value::Null) => None,
                    Some(o) => match parse_hobj(o) {
                        Ok(h) => Some(h),
                        Err(what) => {
                            return (EINVAL, json!(format!("error parsing offset: {what}")));
                        }
                    },
                };
                let max = self.conf.u64("osd_command_max_records", 256).max(1) as usize;
                let l = p.list_unfound(offset.as_ref(), max);
                let ec = p.is_ec_pool();
                let objects: Vec<Value> = l
                    .objects
                    .iter()
                    .map(|u| {
                        json!({"oid": hobj_json(&u.oid), "need": u.need.to_string(), "have": u.have.to_string(),
                            "flags": "none", "clean_regions": clean_regions_text(&u.clean_regions),
                            "locations": u.locations.iter().map(|s| shard_text(s, ec)).collect::<Vec<_>>()})
                    })
                    .collect();
                let mut out = serde_json::Map::new();
                if let Some(o) = &offset {
                    out.insert("offset".into(), hobj_json(o));
                }
                out.insert("num_missing".into(), json!(l.num_missing));
                out.insert("num_unfound".into(), json!(l.num_unfound));
                out.insert("objects".into(), json!(objects));
                out.insert("state".into(), json!(l.state));
                out.insert(
                    "available_might_have_unfound".into(),
                    json!(l.might_have_unfound.is_some()),
                );
                if let Some(m) = &l.might_have_unfound {
                    let m: Vec<Value> = m
                        .iter()
                        .map(|(s, st)| json!({"osd": shard_text(s, ec), "status": st}))
                        .collect();
                    out.insert("might_have_unfound".into(), json!(m));
                }
                out.insert("more".into(), json!(l.more));
                (0, Value::Object(out))
            }
            "scrub-abort" => {
                let (r, acts) = self.pg.set.scrub_abort(now, spg, &self.pg.store);
                self.pg_exec(acts);
                match r {
                    Some(_) => (0, Value::Null),
                    None => (ENOENT, Value::Null),
                }
            }
            "schedule-scrub" | "schedule-deep-scrub" => {
                let acts = self.pg.set.request_scrub(
                    now,
                    spg,
                    cmd == "schedule-deep-scrub",
                    false,
                    &self.pg.store,
                );
                self.pg_exec(acts);
                (0, Value::Null)
            }
            "scrubdebug" => {
                let op = v.get("opcode").and_then(Value::as_str).unwrap_or("");
                if op == "status" {
                    (
                        0,
                        json!({"pgid": pgid, "scrubbing": p.scrub_running(),
                            "debug_hooks": false}),
                    )
                } else {
                    (
                        EOPNOTSUPP,
                        json!("scrubdebug hooks (dev/test only) are not supported"),
                    )
                }
            }
            c => (EINVAL, json!(format!("unsupported pg command '{c}'"))),
        }
    }

    // ------------------------------------------------------------------ merge on the control core

    /// The answer of a scattered command of this module from every core's part (own part first).
    pub(crate) fn merge_ext(
        &mut self,
        prefix: &str,
        v: &Value,
        parts: Vec<(i32, Value)>,
    ) -> Option<Res> {
        let arrays =
            |key: &str| -> Vec<Value> { parts.iter().flat_map(|(_, p)| arr_of(p, key)).collect() };
        Some(match prefix {
            "dump_blocked_ops_count" => {
                let n: u64 = parts.iter().filter_map(|(_, p)| p.as_u64()).sum();
                Self::ok(
                    json!({"complaint_time": self.conf.f64("osd_op_complaint_time", 30.0),
                    "num_blocked_ops": n}),
                )
            }
            "dump_watchers" => {
                let mut w: Vec<Value> = parts
                    .iter()
                    .flat_map(|(_, p)| p.as_array().cloned().unwrap_or_default())
                    .collect();
                w.sort_by_key(|x| {
                    (
                        x["object"].as_str().unwrap_or("").to_owned(),
                        x["cookie"].as_u64(),
                    )
                });
                Self::ok(Value::Array(w))
            }
            "dump_op_pq_state" => {
                let mut s: Vec<Value> = parts.into_iter().map(|(_, p)| p).collect();
                s.sort_by_key(|x| x["shard"].as_u64());
                Self::ok(json!({"shards": s}))
            }
            "dump_pg_recovery_stats" => {
                let mut rows: BTreeMap<String, peering::recstats::StateRow> = BTreeMap::new();
                for p in parts
                    .iter()
                    .flat_map(|(_, p)| p.as_array().into_iter().flatten())
                {
                    let n = |k: &str| p[k].as_u64().unwrap_or(0);
                    rows.entry(p["name"].as_str().unwrap_or("").to_owned())
                        .or_default()
                        .merge(&peering::recstats::StateRow {
                            enter: n("enter"),
                            exit: n("exit"),
                            events: n("events"),
                            event_ns: n("event_ns"),
                            total_ns: n("total_ns"),
                            min_ns: n("min_ns"),
                            max_ns: n("max_ns"),
                        });
                }
                Self::ok(Value::Array(
                    rows.iter()
                        .map(|(name, r)| {
                            json!({"enter": r.enter, "exit": r.exit, "events": r.events,
                                "event_time": dur_str(r.event_ns), "total_time": dur_str(r.total_ns),
                                "min_time": dur_str(r.min_ns), "max_time": dur_str(r.max_ns),
                                "nested_states": name.split('/').collect::<Vec<_>>()})
                        })
                        .collect(),
                ))
            }
            "reset_pg_recovery_stats" => (0, String::new(), Out::default()),
            "scrub_purged_snaps" => self.purged_snaps_scrub_done(sum(&parts, "strays"), &parts),
            "dump_pgstate_history" => {
                let mut pgs: Vec<Value> = parts
                    .iter()
                    .flat_map(|(_, p)| p.as_array().cloned().unwrap_or_default())
                    .collect();
                pgs.sort_by_key(|x| x["pg"].as_str().unwrap_or("").to_owned());
                Self::ok(json!({"pgs": pgs}))
            }
            "dump_recovery_reservations" => {
                let lim = self.conf.recovery_limits();
                let max = lim.max_backfills;
                let held = |k: &str| -> Vec<Value> {
                    arrays(k)
                        .into_iter()
                        .map(|mut i| {
                            i["can_preempt"] = json!(true);
                            i
                        })
                        .collect()
                };
                let queues = |k: &str| -> Vec<Value> {
                    let mut q: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
                    for mut i in held(k) {
                        let p = i["prio"].as_u64().unwrap_or(0);
                        i["prio"] = json!(p);
                        q.entry(p).or_default().push(i);
                    }
                    q.into_iter()
                        .rev()
                        .map(|(p, items)| json!({"priority": p, "items": items}))
                        .collect()
                };
                let cores: Vec<Value> = parts.iter().map(|(_, p)| p["rec_ops"].clone()).collect();
                let in_flight: u64 = cores.iter().filter_map(|c| c["in_flight"].as_u64()).sum();
                let peak: u64 = cores.iter().filter_map(|c| c["peak"].as_u64()).sum();
                let budget = cores.iter().map(|c| &c["budget"]).find(|b| !b.is_null());
                Self::ok(json!({
                    "recovery_ops": {"max_active": lim.recovery_max_active, "in_flight": in_flight, "peak": peak,
                        "granted": budget.map(|b| b[0].clone()), "limit": budget.map(|b| b[1].clone()), "cores": cores},
                    "local_reservations": {"max_allowed": max, "min_priority": lim.min_priority,
                        "queues": queues("local_waiting"), "in_progress": held("local_held")},
                    "remote_reservations": {"max_allowed": max, "min_priority": lim.min_priority,
                        "queues": queues("remote_queued"), "in_progress": held("remote_held")},
                }))
            }
            "dump_scrub_reservations" => {
                let (local, granted) = (arrays("local"), arrays("granted"));
                Self::ok(
                    json!({"scrubs_local": local.len(), "granted_reservations": granted,
                    "scrubs_remote": granted.len(), "osd_max_scrubs": self.conf.u64("osd_max_scrubs", 1),
                    "queued_reservations": arrays("queued")}),
                )
            }
            "get_mapped_pools" => {
                let p: BTreeSet<u64> = parts
                    .iter()
                    .flat_map(|(_, p)| p.as_array().cloned().unwrap_or_default())
                    .filter_map(|x| x.as_u64())
                    .collect();
                Self::ok(json!(p))
            }
            "dump_pool_statfs" => {
                if let Some((r, m)) = parts.iter().find(|(r, _)| *r == EINVAL) {
                    return Some((*r, m.as_str().unwrap_or("").to_owned(), Out::default()));
                }
                let pool = v["poolid"].as_u64().unwrap_or(0);
                if sum(&parts, "pgs") == 0 {
                    return Some((
                        ENOENT,
                        format!("Error dumping pool statfs: (2) pool {pool} has no PG on this osd"),
                        Out::default(),
                    ));
                }
                let bytes = sum(&parts, "bytes");
                Self::ok(
                    json!({"poolid": pool, "total": 0, "available": 0, "internally_reserved": 0,
                    "allocated": bytes, "data_stored": bytes, "data_compressed": 0,
                    "data_compressed_allocated": 0, "data_compressed_original": 0,
                    "omap_allocated": 0, "internal_metadata": 0,
                    "note": "per-pool object bytes; OMAP allocation unavailable, ceph df uses primary PG last-deep-scrub totals"}),
                )
            }
            "dump_mempools" => {
                // only pools croit-flashstore-osd really has, with measured / estimated bytes (no classic zero placeholders)
                let mut by: BTreeMap<String, (u64, u64)> = BTreeMap::new();
                by.insert(
                    "osd_pglog".into(),
                    (sum(&parts, "pglog"), sum(&parts, "pglog_bytes")),
                );
                by.insert("buffer_anon".into(), (0, sum(&parts, "parked_bytes")));
                // process-wide (not per core): read buffers pinned by reply queues / sends, out of every buffer pool
                by.insert("read_shared".into(), crate::read_shared());
                // the ingress pools are shared by every core: the first part is the whole picture
                let ingress = parts
                    .first()
                    .map_or(Value::Null, |(_, p)| p["ingress"].clone());
                for (name, i) in ["ingress_client", "ingress_peer"].into_iter().zip(0..) {
                    by.insert(name.into(), (0, ingress[i]["used"].as_u64().unwrap_or(0)));
                }
                by.insert(
                    "ingress_held".into(),
                    (sum(&parts, "held"), sum(&parts, "held_bytes")),
                );
                let env = crate::memory::active();
                for (_, p) in &parts {
                    for e in p["pools"].as_array().into_iter().flatten() {
                        let x = by
                            .entry(e[0].as_str().unwrap_or("?").to_owned())
                            .or_default();
                        x.0 += e[1].as_u64().unwrap_or(0);
                        x.1 += e[2].as_u64().unwrap_or(0);
                    }
                }
                // counters and unaccounted consumers (0 bytes) are not memory pools
                by.retain(|_, x| x.1 > 0);
                let items: u64 = by.values().map(|x| x.0).sum();
                let bytes: u64 = by.values().map(|x| x.1).sum();
                let bp: serde_json::Map<String, Value> = by
                    .into_iter()
                    .map(|(k, (i, b))| (k, json!({"items": i, "bytes": b})))
                    .collect();
                Self::ok(
                    json!({"mempool": {"by_pool": bp, "total": {"items": items, "bytes": bytes}},
                    "process": proc_mem(),
                    "envelope": {"target": env.target, "base": env.base, "ingress": env.ingress,
                        "pinned": env.pinned, "caches": env.caches, "ingress_pools": ingress},
                    "note": "only pools croit-flashstore-osd really has (bytes > 0); nvme_* = store consumers; process = /proc/self/status kB"}),
                )
            }
            "flush_journal" => Self::ok(json!({})),
            "store census" => {
                // per-core parts carry the same keys: sums (census_seq = sum of the shards' sweep numbers)
                Self::ok(Value::Object(sum_parts(&parts)))
            }
            "rdma status" => self.rdma_reply(v, &parts),
            #[cfg(feature = "rdma-fault")]
            "rdma fault qp-err" => Self::ok(
                json!({"pending_qp_err": parts.iter().filter_map(|(_, p)| p["pending_qp_err"].as_u64()).max().unwrap_or(0)}),
            ),
            #[cfg(feature = "rdma-fault")]
            "rdma fault write-qp-err" => {
                if let Some((code, message)) = parts.iter().find(|(code, _)| *code != 0) {
                    return Some((
                        *code,
                        message.as_str().unwrap_or("").to_owned(),
                        Out::default(),
                    ));
                }
                Self::ok(json!({
                    "pending_write_qp_err":parts.iter().filter_map(|(_,p)| p["pending_write_qp_err"].as_u64()).max().unwrap_or(0),
                    "triggered_write_qp_err":parts.iter().filter_map(|(_,p)| p["triggered_write_qp_err"].as_u64()).max().unwrap_or(0),
                    "failed_write_qp_err":parts.iter().filter_map(|(_,p)| p["failed_write_qp_err"].as_u64()).max().unwrap_or(0)
                }))
            }
            "cache status" => Self::ok(Value::Object(sum_parts(&parts))),
            // Ceph answers an empty output, exit 0 (the per-core totals are in `cache status`)
            "cache drop" | "flush_store_cache" => (0, String::new(), Out::default()),
            "debug dump_missing" => {
                let mut all: Vec<Value> = parts
                    .iter()
                    .flat_map(|(_, p)| p.as_array().cloned().unwrap_or_default())
                    .collect();
                all.sort_by_key(|x| x["pgid"].as_str().unwrap_or("").to_owned());
                // classic: one array of missing objects per PG
                Self::ok(Value::Array(
                    all.into_iter().map(|x| x["missing"].clone()).collect(),
                ))
            }
            "bluestore allocator dump"
            | "store free"
            | "bluestore allocator score"
            | "bluestore allocator fragmentation" => {
                let name = v.get("name").and_then(Value::as_str).unwrap_or("block");
                if name != store::report::ALLOC_NAME {
                    return Some((
                        ENOENT,
                        format!(
                            "allocator '{name}' not found (only '{}')",
                            store::report::ALLOC_NAME
                        ),
                        Out::default(),
                    ));
                }
                if parts.iter().any(|(r, _)| *r != 0) {
                    return Some((
                        EOPNOTSUPP,
                        "allocator report needs the device store (not available on this backend)"
                            .into(),
                        Out::default(),
                    ));
                }
                let cap = sum(&parts, "capacity");
                let mut ext: Vec<(u64, u64)> = parts
                    .iter()
                    .flat_map(|(_, p)| arr_of(p, "extents"))
                    .filter_map(|e| Some((e[0].as_u64()?, e[1].as_u64()?)))
                    .collect();
                store::report::merge_extents(&mut ext);
                if prefix == "store free" {
                    let ex = v.get("extents").is_some_and(|x| {
                        x.as_bool() == Some(true)
                            || x.as_str().is_some_and(|s| s == "true" || s == "1")
                    });
                    return Some(Self::ok(
                        serde_json::from_str(&store::report::free_json(cap, &ext, ex))
                            .unwrap_or(Value::Null),
                    ));
                }
                let body = match prefix {
                    "bluestore allocator dump" => store::report::dump_json(cap, &ext),
                    "bluestore allocator score" => store::report::score_json(&ext),
                    _ => store::report::rating_json(&ext),
                };
                Self::ok(serde_json::from_str(&body).unwrap_or(Value::Null))
            }
            "bluestore dedup stats" | "bluestore dedup clear" | "bluestore dedup list" => {
                dedup_merge(prefix, v, parts)
            }
            "pg" => {
                // the owner answers; a non-owner says a bare ENOENT (null), which loses against any other verdict
                let best = parts
                    .iter()
                    .find(|(r, _)| *r == 0)
                    .or_else(|| parts.iter().find(|(r, m)| *r != ENOENT || !m.is_null()))
                    .or(parts.first());
                match best {
                    Some((0, Value::Null)) => (0, String::new(), Out::default()),
                    // a status text (`mark_unfound_lost`): classic answers it as outs
                    Some((0, Value::String(m))) => (0, m.clone(), Out::default()),
                    Some((0, o)) => Self::ok(o.clone()),
                    Some((r, m)) => {
                        let rs = m.as_str().map_or_else(
                            || format!("i don't have pgid {}", v["pgid"].as_str().unwrap_or("")),
                            ToOwned::to_owned,
                        );
                        (*r, rs, Out::default())
                    }
                    None => (ENOENT, "no such pg".into(), Out::default()),
                }
            }
            _ => return None,
        })
    }

    // ------------------------------------------------------------------ control core only

    /// Commands that need no other core. `None` = not one of ours.
    pub(crate) fn run_ext(&mut self, prefix: &str, v: &Value) -> Option<Res> {
        let arg = |k: &str| v.get(k).and_then(Value::as_str).map(ToOwned::to_owned);
        Some(match prefix {
            "compact" => Self::ok(json!({"elapsed_time": 0.0,
                "note": "croit-flashstore-osd has no LSM tree: nothing to compact (no-op)"})),
            "heap" => (EOPNOTSUPP, NO_TCMALLOC.into(), Out::default()),
            // no RocksDB under croit-flashstore-osd: the shape of a classic store without kv statistics
            "dump_objectstore_kv_stats" => (
                0,
                String::new(),
                b"error: RocksDB perf is disabled, can't probe for stats.\n"
                    .to_vec()
                    .into(),
            ),
            "calc_objectstore_db_histogram" => (0, String::new(), Out::default()),
            // a classic build without the gperftools profiler; both choices answer the same
            "cpu_profiler" => (
                0,
                String::new(),
                b"cpu_profiler support not linked in".to_vec().into(),
            ),
            "get_heap_property" => {
                Self::ok(json!({"error": "invalid property", "success": false, "value": 0}))
            }
            "set_heap_property" => Self::ok(json!({"error": "invalid property", "success": false})),
            "log dump" => {
                // the sink writes its recent ring to every enabled sink; the reply stays empty (spec 6.9)
                crate::log_dump(self.logging_levels());
                (0, String::new(), Out::default())
            }
            "cluster_log" => {
                let msg = crate::tell::str_list(v.get("message")).join(" ");
                if msg.is_empty() {
                    return Some((EINVAL, "ignoring empty log message".into(), Out::default()));
                }
                let lvl = arg("level").unwrap_or_default();
                let prio = match lvl.as_str() {
                    "debug" => messages::clog::DEBUG,
                    "info" => messages::clog::INFO,
                    "sec" | "security" => messages::clog::SEC,
                    "warning" | "warn" => messages::clog::WARN,
                    "error" | "err" => messages::clog::ERROR,
                    _ => return Some((EINVAL, format!("unknown level '{lvl}'"), Out::default())),
                };
                self.clog(prio, &msg);
                (0, String::new(), Out::default())
            }
            "trim stale osdmaps" => match self.trim_maps_inner(true) {
                Ok(o) => Self::ok(json!({"oldest_stored_map": o.unwrap_or(0)})),
                Err(e) => (
                    EINVAL,
                    format!(" Error trimming stale osdmaps: {e}"),
                    Out::default(),
                ),
            },
            "dump_osd_pg_stats" => Self::ok(self.osd_pg_stats_json()),
            "bdev expand" | "bluestore bluefs-bdev-expand" => {
                (EOPNOTSUPP, NO_ONLINE_EXPAND.into(), Out::default())
            }
            "debug kick_recovery_wq" | "set_recovery_delay" => {
                let d = v
                    .get("delay")
                    .or_else(|| v.get("utime"))
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                if d == 0 {
                    (0, "croit-flashstore-osd never delays recovery (osd_recovery_delay_start has no effect): nothing to kick".into(), Out::default())
                } else {
                    (EOPNOTSUPP, "croit-flashstore-osd has no recovery start delay (recovery starts as soon as a PG is active); throttle with osd_max_backfills / osd_recovery_max_active, or set the norecover flag".into(), Out::default())
                }
            }
            "clear_shards_repaired" => {
                // classic: set the counter to `count` (default 0)
                let keep = v.get("count").and_then(Value::as_u64).unwrap_or(0);
                let total = self.op_perf_all().shards_repaired;
                self.perf.repaired_cleared = total.saturating_sub(keep);
                (0, String::new(), Out::default())
            }
            "reset_purged_snaps_last" => {
                self.sb.purged_snaps_last = 0;
                match self.store.as_mut().map_or(Ok(()), |s| {
                    use crate::meta::MetaStore as _;
                    s.store_superblock(&self.sb)
                }) {
                    Ok(()) => (0, "purged_snaps_last reset to 0; the OSD re-fetches purged snaps from the mon at its next start".into(), Out::default()),
                    Err(e) => (-5, format!("Error writing superblock: {e}"), Out::default()),
                }
            }
            "rotate-stored-key" => self.rotate_stored_key(),
            "rotate-key" => self.rotate_live_key(),
            "wipe-rotating-secrets" => {
                self.mc.wipe_secrets_and_tickets();
                self.log("wipe-rotating-secrets: rotating secrets wiped, tickets invalidated");
                (0, String::new(), Out::default())
            }
            _ => return None,
        })
    }

    /// Driver hook: one step of this core's purged-snaps walk (one PG, at most `osd_scrub_chunk_max` mapper entries);
    /// the finished walk answers the scattered commands waiting for it. True while it goes on.
    pub(crate) fn poll_purged_scan(&mut self) -> bool {
        let now = self.pg_mono();
        let (done, acts) = self.pg.set.purged_snaps_step(now, &self.pg.store);
        self.pg_exec(acts);
        let Some(f) = done else {
            return true;
        };
        let part =
            json!({"strays": f.strays, "retrimmed": f.retrimmed, "read_errors": f.read_errors});
        for (core, id) in std::mem::take(&mut self.cmds.purged_waiters) {
            if core == self.core_id() {
                self.on_query_reply(core, id, 0, part.clone());
            } else {
                self.xsend(
                    core,
                    crate::xcore::XMsg::QueryReply {
                        id,
                        r: 0,
                        out: Box::new(part.clone()),
                    },
                );
            }
        }
        false
    }

    /// Merge of `scrub_purged_snaps`: cluster log lines like classic, stamp the superblock.
    fn purged_snaps_scrub_done(&mut self, strays: u64, parts: &[(i32, Value)]) -> Res {
        if strays > 0 {
            self.clog(
                messages::clog::DEBUG,
                &format!("purged_snaps scrub found {strays} strays"),
            );
        } else {
            self.clog(messages::clog::DEBUG, "purged_snaps scrub ok");
        }
        if sum(parts, "read_errors") > 0 {
            self.clog(
                messages::clog::ERROR,
                "purged_snaps scrub: a snap mapper could not be read (see the PG notes), its PG was not fully checked",
            );
        }
        self.sb.last_purged_snaps_scrub = self.wall();
        match self.store.as_mut().map_or(Ok(()), |s| {
            use crate::meta::MetaStore as _;
            s.store_superblock(&self.sb)
        }) {
            Ok(()) => (0, String::new(), Out::default()),
            Err(e) => (-5, format!("Error writing superblock: {e}"), Out::default()),
        }
    }

    /// Control core, every tick while active: the purged-snaps scrub runs on its own once
    /// `last + osd_scrub_min_interval * (1 + osd_scrub_interval_randomize_ratio * r)` passed, `r` in [0,1) fixed per
    /// OSD and interval (seeded from the id and the last run, like classic).
    pub(crate) fn purged_snaps_scrub_tick(&mut self) {
        let last = u64::from(self.sb.last_purged_snaps_scrub.sec);
        let min = self.conf.f64("osd_scrub_min_interval", 86400.0);
        let ratio = self.conf.f64("osd_scrub_interval_randomize_ratio", 0.5);
        let mut seed = (self.id.whoami.max(0) as u64).wrapping_add(last);
        let r = (crate::osd::splitmix(&mut seed) >> 11) as f64 / (1u64 << 53) as f64;
        let due = last as f64 + min + min * ratio * r;
        if (self.wall().sec as f64) < due {
            return;
        }
        // stamped now (the merge stamps again): the next tick must not start a second run while the cores scan
        self.sb.last_purged_snaps_scrub = self.wall();
        let _ = self.scatter(&json!({"prefix": "scrub_purged_snaps"}), &ReplyTo::Internal);
    }

    /// `bench`: validate and start (answer = `None`, the result follows from [`Self::poll_bench`]). The precheck
    /// order, texts and the count bound of `osd_bench_duration` follow spec osd-lifecycle.md 9.4.
    pub(crate) fn start_bench(&mut self, v: &Value, to: &ReplyTo) -> Option<Res> {
        let num = |k: &str, d: i64| v.get(k).and_then(Value::as_i64).unwrap_or(d);
        let (count, mut bsize) = (num("count", 1 << 30), num("size", 4 << 20));
        let osize = num("object_size", 0);
        if count <= 0 || bsize <= 0 {
            return Some((
                EINVAL,
                "block size and/or count of Bytes to write not specified".into(),
                Out::default(),
            ));
        }
        let max_bs = self.conf.u64("osd_bench_max_block_size", 64 << 20);
        if bsize as u64 > max_bs {
            return Some((
                EINVAL,
                format!(
                    "block 'size' values are capped at {}. If you wish to use a higher value, please adjust 'osd_bench_max_block_size'",
                    byte_text(max_bs)
                ),
                Out::default(),
            ));
        }
        // `osd_bench_duration` never caps the run: it scales the largest `count` the command accepts
        let duration = self.conf.u64("osd_bench_duration", 30);
        let (max_count, assumption, option) = if bsize < 1 << 20 {
            let iops = self.conf.u64("osd_bench_small_size_max_iops", 100);
            (
                (bsize as u64).saturating_mul(duration).saturating_mul(iops),
                format!("assuming {iops} IOPS"),
                "osd_bench_small_size_max_iops",
            )
        } else {
            let throughput = self
                .conf
                .u64("osd_bench_large_size_max_throughput", 100 << 20);
            (
                throughput.saturating_mul(duration),
                format!("assuming {}/s", byte_text(throughput)),
                "osd_bench_large_size_max_throughput",
            )
        };
        if count as u64 > max_count {
            return Some((
                EINVAL,
                format!(
                    "'count' values greater than {max_count} for a block size of {bsize}, {assumption}, for {duration} seconds, can cause ill effects on osd.  Please adjust '{option}' with a higher value if you wish to use a higher 'count'."
                ),
                Out::default(),
            ));
        }
        // after the size/count checks: an oversized `size` still fails first
        if osize > 0 && bsize > osize {
            self.logl(
                0,
                format!(
                    "OSDBenchTest::precheck: bsize: {bsize} is greater than osize: {osize}. Running test by overriding bsize to {osize}."
                ),
            );
            bsize = osize;
        }
        if self.store.is_none() {
            return Some((
                EOPNOTSUPP,
                "bench runs on the control core only".into(),
                Out::default(),
            ));
        }
        if self.cmds.bench.is_some() {
            return Some((EBUSY, "a bench is already running".into(), Out::default()));
        }
        self.cmds.bench = Some(Bench {
            to: to.clone(),
            bsize: bsize as u64,
            count: count as u64,
            t0: std::time::Instant::now(),
            done: 0,
            i: 0,
            buf: vec![0xA5u8; bsize as usize],
        });
        None
    }

    /// Driver hook: one durable write of the running bench (so the control core serves everything else between the
    /// writes, a block is the longest stall); answers when all `count` bytes are written or a write failed.
    pub(crate) fn poll_bench(&mut self) -> bool {
        let Some(mut b) = self.cmds.bench.take() else {
            return false;
        };
        let Some(store) = self.store.as_mut() else {
            let res = (
                EOPNOTSUPP,
                "bench runs on the control core only".into(),
                Out::default(),
            );
            self.finish_cmd(b.to, res);
            return true;
        };
        use crate::meta::MetaStore as _;
        let mut err = None;
        if b.done < b.count {
            // exactly the requested bytes: the last chunk carries the remainder
            let n = (b.count - b.done).min(b.bsize) as usize;
            match store.bench_put(b.i % crate::meta::BENCH_SLOTS, &b.buf[..n]) {
                Ok(()) => {
                    b.done += n as u64;
                    b.i += 1;
                    self.cmds.bench = Some(b);
                    return true;
                }
                Err(e) => err = Some(e.to_string()),
            }
        }
        if let Err(e) = store.bench_cleanup(b.i.min(crate::meta::BENCH_SLOTS)) {
            self.logl(0, format!("WARNING bench scratch cleanup failed: {e}"));
        }
        let el = b.t0.elapsed().as_secs_f64().max(1e-9);
        let res = match err {
            // a store write that failed is the device's error, never "unsupported" (that is the no-store case above)
            Some(e) => (EIO, e, Out::default()),
            None => {
                let rate = b.done as f64 / el;
                // the formatter's top-level section name is not printed in JSON (spec 9.1): the body is the five values
                Self::ok(json!({
                    "bytes_written": b.done, "blocksize": b.bsize, "elapsed_sec": el,
                    "bytes_per_sec": rate, "iops": rate / b.bsize as f64
                }))
            }
        };
        self.finish_cmd(b.to, res);
        true
    }

    /// Shutdown: a running bench answers now (the loop stops polling it) and its scratch objects go.
    pub(crate) fn bench_abort(&mut self) {
        let Some(b) = self.cmds.bench.take() else {
            return;
        };
        let cleanup = self
            .store
            .as_mut()
            .map(|s| {
                use crate::meta::MetaStore as _;
                s.bench_cleanup(b.i.min(crate::meta::BENCH_SLOTS))
            })
            .transpose();
        if let Err(e) = cleanup {
            self.logl(0, format!("WARNING bench scratch cleanup failed: {e}"));
        }
        let res = (
            EINTR,
            "bench interrupted: the OSD is shutting down".into(),
            Out::default(),
        );
        self.finish_cmd(b.to, res);
    }

    /// `rotate-stored-key` (`ceph tell osd.N rotate-stored-key -i KEYFILE`): the new cephx secret replaces the stored one,
    /// both copies a restart reads ([`crate::keysrc`]): the key mkfs recorded on the device (the classic stored key)
    /// and, when present, the OSD directory keyring (`$osd_data/keyring`, atomic rename, 0600). The keyring wins at the
    /// next start, so it is written first: a failure there changes nothing, a device failure afterwards still leaves the
    /// key the mon knows in the copy the restart reads. The running session keeps its key (`rotate-key` swaps the live
    /// one); an explicit `key`/`keyfile`/`keyring` option still wins.
    pub(crate) fn rotate_stored_key(&mut self) -> Res {
        let key = String::from_utf8_lossy(&self.cmds.inbl).trim().to_owned();
        if key.is_empty() {
            return (
                EINVAL,
                "no key supplied: use `ceph tell osd.N rotate-stored-key -i KEYFILE`".into(),
                Out::default(),
            );
        }
        if cephx::CryptoKey::from_base64(&key).is_err() {
            return (
                EINVAL,
                "the key must be a base64 cephx secret".into(),
                Out::default(),
            );
        }
        let dir = crate::keysrc::expand_osd_data(
            self.conf.get("osd_data").unwrap_or_default(),
            self.conf.get("cluster").unwrap_or("ceph"),
            i64::from(self.id.whoami),
        );
        let kr = std::path::Path::new(&dir).join("keyring");
        if kr.is_file() {
            let text = osddir::keyring_text(i64::from(self.id.whoami), &key);
            if let Err(e) = osddir::write_atomic_mode(&kr, text.as_bytes(), 0o600) {
                return (-5, format!("writing {}: {e}", kr.display()), Out::default());
            }
        }
        let mut id = self.id.clone();
        id.key = key;
        if let Some(s) = self.store.as_mut() {
            use crate::meta::MetaStore as _;
            if let Err(e) = s.store_identity(&id) {
                return (-5, format!("writing the stored key: {e}"), Out::default());
            }
        }
        // last: the running identity only changes once both stored copies are written
        self.id = id;
        (
            0,
            "stored key rotated (takes effect at the next start)".into(),
            Out::default(),
        )
    }

    /// `rotate-key` (`ceph tell osd.N rotate-key -i KEYFILE`): the mon client's cephx key is replaced in memory at once
    /// (cephx spec sec 2.2); later authentications use it. Nothing is written (`rotate-stored-key` does that).
    pub(crate) fn rotate_live_key(&mut self) -> Res {
        let text = String::from_utf8_lossy(&self.cmds.inbl);
        let key = match cephx::CryptoKey::from_base64(text.trim()) {
            Ok(k) => k,
            Err(e) => return (EINVAL, format!("error decoding key: {e:?}"), Out::default()),
        };
        if !self.mc.rotate_key(key) {
            return (
                EINVAL,
                "cephx not enabled; no key to rotate".into(),
                Out::default(),
            );
        }
        self.log(format!("rotate live key for osd.{}", self.id.whoami));
        (0, String::new(), Out::default())
    }

    /// `dump_osd_pg_stats`: what the next MPGStats would carry (classic `MPGStats::dump_stats` shape).
    fn osd_pg_stats_json(&self) -> Value {
        let pgs: Vec<Value> = self
            .pg_stat_list()
            .into_iter()
            .filter_map(|(pgid, b)| {
                let s: pgwire::PgStat = denc::from_slice(&b).ok()?;
                let mut j = crate::pgs::stat_json(&s);
                j["pgid"] = json!(pgid.to_string());
                Some(j)
            })
            .collect();
        let sf = self.osd_statfs();
        // same seq the mgr reports get (mgrc: up_from << 32 | per-boot counter)
        let st = messages::OsdStat::from_statfs(
            sf,
            self.up_epoch,
            (u64::from(self.up_epoch) << 32) + self.stat_seq,
        );
        let sj = |s: &messages::StoreStatfs| {
            json!({"total": s.total, "available": s.available, "internally_reserved": s.internally_reserved,
                "allocated": s.allocated, "data_stored": s.data_stored, "data_compressed": s.data_compressed,
                "data_compressed_allocated": s.data_compressed_allocated,
                "data_compressed_original": s.data_compressed_original,
                "omap_allocated": s.omap_allocated, "internal_metadata": s.internal_metadata})
        };
        // the value the last MPGStats carried (the window advances only there)
        let lat = &self.perf.last_os_perf;
        json!({"pg_stat": pgs,
            "osd_stat": {"up_from": st.up_from, "seq": st.seq, "num_pgs": self.pg_num_pgs(),
                "num_osds": st.num_osds, "num_per_pool_osds": st.num_per_pool_osds,
                "num_per_pool_omap_osds": st.num_per_pool_omap_osds,
                "kb": st.kb, "kb_used": st.kb_used, "kb_used_data": st.kb_used_data,
                "kb_used_omap": st.kb_used_omap, "kb_used_meta": st.kb_used_meta, "kb_avail": st.kb_avail,
                "statfs": sj(&st.statfs), "hb_peers": self.hb.peers.keys().collect::<Vec<_>>(),
                "snap_trim_queue_len": 0, "num_snap_trimming": 0, "num_shards_repaired": self.shards_repaired_shown(),
                "op_queue_age_hist": {"histogram": [], "upper_bound": 1},
                "perf_stat": {"commit_latency_ms": lat.os_commit_latency_ns as f64 / 1e6,
                    "apply_latency_ms": lat.os_apply_latency_ns as f64 / 1e6,
                    "commit_latency_ns": lat.os_commit_latency_ns,
                    "apply_latency_ns": lat.os_apply_latency_ns},
                "alerts": []},
            "pool_stat": self.pg_pool_statfs().iter().map(|(pool, s)| {
                let mut j = sj(s);
                j["poolid"] = json!(pool);
                j
            }).collect::<Vec<_>>()})
    }
}

fn ok_json(v: Value) -> Res {
    (0, String::new(), Out::Json(v))
}

/// Integer argument of a tell command (number or numeric string).
fn int_arg(v: &Value, k: &str) -> Option<i64> {
    match v.get(k)? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn float_arg(v: &Value, k: &str) -> Option<f64> {
    match v.get(k)? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn hex_up(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Hex text -> bytes. Pairs are cut on the byte grid (a non-ASCII byte is never valid hex and rejects the whole string;
/// slicing the `str` would panic on a multi-byte character).
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn wall_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// `bluestore dedup list` arguments (dedup-collection.md 7): the request, or the error to answer.
fn dedup_list_req(v: &Value) -> Result<peering::store::DedupListReq, (i32, String)> {
    let pool = int_arg(v, "pool").unwrap_or(-1);
    if pool < 0 {
        return Err((EINVAL, format!("Invalid pool id:{pool}")));
    }
    let shard = int_arg(v, "shard").unwrap_or(0);
    let bits = int_arg(v, "shard_bits").unwrap_or(0);
    if !(0..=32).contains(&bits) || shard < 0 || shard >= 1i64 << bits {
        return Err((
            EINVAL,
            format!("Invalid shard {shard} for shard_bits {bits}"),
        ));
    }
    let max = int_arg(v, "max").unwrap_or(1000);
    if max <= 0 || max > i32::MAX as i64 {
        return Err((EINVAL, format!("Invalid max {max}")));
    }
    let after = v.get("after").and_then(Value::as_str).unwrap_or("");
    let Some(after) = unhex(after) else {
        return Err((EINVAL, format!("Invalid cursor:{after}")));
    };
    let now = wall_ns();
    let ago = |k: &str| match int_arg(v, k).unwrap_or(0) {
        // a huge (client-supplied) age saturates: every record is older than "forever ago"
        s if s > 0 => now.saturating_sub((s as u64).saturating_mul(1_000_000_000)),
        _ => 0,
    };
    Ok(peering::store::DedupListReq {
        pool,
        shard: shard as u32,
        shard_bits: bits as u32,
        after,
        max: max as usize,
        retrieve_after_ns: ago("newer_than"),
        remove_before_ns: ago("prune_older_than"),
        max_duration_s: float_arg(v, "max_duration").unwrap_or(1.0).max(0.0),
    })
}

/// Merge the cores' parts of a `bluestore dedup *` command into the fork's output (dedup-collection.md 7).
fn dedup_merge(prefix: &str, v: &Value, parts: Vec<(i32, Value)>) -> Res {
    if let Some((r, m)) = parts.iter().find(|(r, _)| *r != 0) {
        return (
            *r,
            m.as_str().unwrap_or("Execution error").to_owned(),
            Out::default(),
        );
    }
    let pool = int_arg(v, "pool").unwrap_or(0);
    match prefix {
        "bluestore dedup stats" => ok_json(json!({"deduplication stats": {
            "pool": pool, "bytes": sum(&parts, "bytes"), "entries": sum(&parts, "entries")}})),
        "bluestore dedup clear" => (0, String::new(), Out::default()),
        _ => {
            let Ok(req) = dedup_list_req(v) else {
                return (EINVAL, "Invalid arguments".into(), Out::default());
            };
            let cores: Vec<peering::store::DedupListPart> = parts
                .iter()
                .map(|(_, p)| peering::store::DedupListPart {
                    entries: p["entries"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|e| {
                            Some(peering::store::DedupEntry {
                                key: unhex(e["key"].as_str()?)?,
                                digest: unhex(e["digest"].as_str()?)?,
                                ts_ns: e["ts"].as_u64()?,
                                hash_key: e["hash_key"].as_u64()? as u32,
                            })
                        })
                        .collect(),
                    examined: unhex(p["examined"].as_str().unwrap_or("")).unwrap_or_default(),
                    completed: p["completed"].as_bool().unwrap_or(true),
                })
                .collect();
            let (entries, next, completed) = peering::store::merge_dedup_parts(cores, req.max);
            let now = wall_ns();
            let list: Vec<Value> = entries
                .iter()
                .map(|e| {
                    json!({"digest": hex_up(&e.digest), "hash": e.hash_key.reverse_bits(), "timestamp": e.ts_ns,
                        "age": now.saturating_sub(e.ts_ns) as f64 / 1e9})
                })
                .collect();
            ok_json(
                json!({"deduplication list": {"pool": pool, "shard": req.shard, "shard_bits": req.shard_bits,
                "completed": completed, "next": hex_up(&next), "entries": list}}),
            )
        }
    }
}

#[cfg(test)]
mod ctime_tests {
    #[test]
    fn ctime_text_matches_the_reference_layout() {
        assert_eq!(
            super::ctime_parts(2026, 10, 5, 11, 20, 0, 4),
            "Thu Nov  5 11:20:00 2026"
        );
        assert_eq!(
            super::ctime_parts(2026, 0, 1, 0, 0, 0, 4),
            "Thu Jan  1 00:00:00 2026"
        );
        assert_eq!(
            super::ctime_parts(2026, 11, 31, 23, 59, 59, 4),
            "Thu Dec 31 23:59:59 2026"
        );
    }
}
