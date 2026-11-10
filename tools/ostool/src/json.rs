// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! JSON shapes of the tool output (classic `--op list`, `info`, `log`, `dump-super`, `dump`) and the object
//! specification parser (`["1.0",{ghobject}]`).
use crate::R;
use denc::types::{Ghobject, Hobject, ShardId, SnapId, SpgT};
use pgwire::{LogEntry, LogOp, MissingItem, PgLog, PgMissing};
use serde_json::{Value, json};
use std::io::Write;

pub fn jstr(b: &[u8]) -> String {
    serde_json::to_string(&String::from_utf8_lossy(b)).unwrap_or_default()
}

/// Write one JSON document with the shared formatter (plain uses compact JSON).
pub fn emit<W: Write + ?Sized>(out: &mut W, format: &str, v: &Value) -> R {
    let format = outfmt::Format::parse(format).ok_or("unrecognized output format")?;
    writeln!(out, "{}", format.doc(v))?;
    Ok(())
}

/// Classic stream form of an hobject: `pool:revhash:nspace:key:name:snap`.
pub fn hobj_str(h: &Hobject) -> String {
    if h.max {
        return "MAX".into();
    }
    let key = if h.key.is_empty() { &h.oid } else { &h.key };
    format!(
        "{}:{:08x}:{}:{}:{}:{}",
        h.pool,
        h.hash.reverse_bits(),
        String::from_utf8_lossy(&h.nspace),
        String::from_utf8_lossy(key),
        String::from_utf8_lossy(&h.oid),
        h.snap
    )
}

/// `ghobject_t::dump` as the classic tool prints it (fields in this order, `max` appears twice).
pub fn ghobject_json(g: &Ghobject) -> String {
    let h = &g.hobj;
    let mut s = format!(
        "{{\"oid\":{},\"key\":{},\"snapid\":{},\"hash\":{},\"max\":{},\"pool\":{},\"namespace\":{}",
        jstr(&h.oid),
        jstr(&h.key),
        h.snap.0 as i64,
        h.hash,
        i32::from(h.max),
        h.pool,
        jstr(&h.nspace)
    );
    if g.generation != Ghobject::NO_GEN {
        s += &format!(",\"generation\":{}", g.generation);
    }
    if g.shard != ShardId::NO_SHARD {
        s += &format!(",\"shard_id\":{}", g.shard.0);
    }
    s += &format!(",\"max\":{}}}", i32::from(g.max));
    s
}

/// [`ghobject_json`] as a value for the JSON documents (`dump`, `list-slow-omap`, `dump-export`). Going through the
/// text keeps one field list; the documents sort the keys, so the classic order and the duplicate `max` are gone.
pub fn ghobject_value(g: &Ghobject) -> Value {
    serde_json::from_str(&ghobject_json(g)).unwrap_or_default()
}

fn num_u64(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_i64().map(|i| i as u64))
}

pub fn parse_ghobject(v: &Value) -> Result<Ghobject, String> {
    let o = v.as_object().ok_or("object spec must be a JSON object")?;
    let s = |k: &str| {
        o.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .as_bytes()
            .to_vec()
    };
    let hash = match o.get("hash") {
        Some(v) => v
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or("object hash must fit u32")?,
        None => 0,
    };
    let shard = match o.get("shard_id") {
        Some(v) => v
            .as_i64()
            .and_then(|v| i8::try_from(v).ok())
            .filter(|&v| v >= -1)
            .ok_or("object shard_id must be -1..127")?,
        None => -1,
    };
    let mut h = Hobject::new(
        &s("oid"),
        SnapId(o.get("snapid").and_then(num_u64).unwrap_or(0)),
        hash,
        o.get("pool").and_then(Value::as_i64).unwrap_or(0),
        &s("namespace"),
    );
    h.key = s("key");
    h.max = o.get("max").and_then(Value::as_i64).unwrap_or(0) != 0;
    let generation = o
        .get("generation")
        .and_then(num_u64)
        .unwrap_or(Ghobject::NO_GEN);
    Ok(Ghobject::new(h, generation, ShardId(shard)))
}

fn reqid_str(r: &denc::types::OsdReqId) -> String {
    format!("{}.{}:{}", r.name, r.inc, r.tid)
}

pub fn entry_json(e: &LogEntry) -> Value {
    let op = match e.op {
        LogOp::MODIFY => "modify",
        LogOp::CLONE => "clone",
        LogOp::DELETE => "delete",
        LogOp::LOST_REVERT => "l_revert",
        LogOp::LOST_DELETE => "l_delete",
        LogOp::LOST_MARK => "l_mark",
        LogOp::PROMOTE => "promote",
        LogOp::CLEAN => "clean",
        LogOp::ERROR => "error",
        LogOp::REPLACE => "replace",
        _ => "unknown",
    };
    json!({
        "op": op,
        "object": hobj_str(&e.soid),
        "version": e.version.to_string(),
        "prior_version": e.prior_version.to_string(),
        "reqid": reqid_str(&e.reqid),
        "extra_reqids": e.extra_reqids.iter().map(|(r, v)| json!({"reqid": reqid_str(r), "pg_version": v})).collect::<Vec<_>>(),
        "mtime": osd::utime_str(e.mtime),
        "return_code": e.return_code,
        "user_version": e.user_version,
    })
}

pub fn log_json(l: &PgLog) -> Value {
    json!({
        "tail": l.tail.to_string(),
        "head": l.head.to_string(),
        "log": l.log.iter().map(entry_json).collect::<Vec<_>>(),
        "dups": l.dups.iter().map(|d| json!({
            "reqid": reqid_str(&d.reqid),
            "version": d.version.to_string(),
            "user_version": d.user_version,
            "return_code": d.return_code,
        })).collect::<Vec<_>>(),
    })
}

fn missing_item_json(h: &Hobject, it: &MissingItem) -> Value {
    json!({
        "object": hobj_str(h),
        "need": it.need.to_string(),
        "have": it.have.to_string(),
        "flags": if it.is_delete() { "delete" } else { "none" },
        "clean_regions": format!("clean_offsets: {:?}, clean_omap: {}, new_object: {}",
            it.clean_regions.clean_offsets, i32::from(it.clean_regions.clean_omap), i32::from(it.clean_regions.new_object)),
    })
}

pub fn missing_json(m: &PgMissing) -> Value {
    json!({
        "missing": m.missing.iter().map(|(h, it)| missing_item_json(h, it)).collect::<Vec<_>>(),
        "may_include_deletes": m.may_include_deletes,
    })
}

/// `dump-super` shape of the classic OSDSuperblock.
pub fn super_json(sb: &messages::OsdSuperblock, oldest: u32, newest: u32) -> Value {
    let fs = |f: &messages::types::FeatureSet| -> Value {
        let mut m = serde_json::Map::new();
        for (id, n) in &f.names {
            m.insert(format!("feature_{id}"), json!(n));
        }
        Value::Object(m)
    };
    json!({
        "cluster_fsid": sb.cluster_fsid.to_string(),
        "osd_fsid": sb.osd_fsid.to_string(),
        "whoami": sb.whoami,
        "current_epoch": sb.current_epoch,
        "oldest_map": oldest,
        "newest_map": newest,
        "weight": sb.weight,
        "compat": {
            "compat": fs(&sb.compat_features.compat),
            "ro_compat": fs(&sb.compat_features.ro_compat),
            "incompat": fs(&sb.compat_features.incompat),
        },
        "clean_thru": sb.clean_thru,
        "last_epoch_mounted": sb.mounted,
        "purged_snaps_last": sb.purged_snaps_last,
        "last_purged_snaps_scrub": osd::utime_str(sb.last_purged_snaps_scrub),
        "cluster_osdmap_trim_lower_bound": sb.cluster_osdmap_trim_lower_bound,
    })
}

pub fn spg_of(s: &str) -> Result<SpgT, String> {
    SpgT::parse(s).map_err(|_| format!("Invalid pgid '{s}' specified"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_identity_numbers_cannot_wrap() {
        for value in [
            json!({"hash": 4_294_967_296u64}),
            json!({"hash": -1}),
            json!({"shard_id": 255}),
            json!({"shard_id": -2}),
            json!({"shard_id": "0"}),
        ] {
            assert!(parse_ghobject(&value).is_err(), "{value}");
        }
        let g = parse_ghobject(&json!({"hash": u32::MAX, "shard_id": 127, "snapid": -2})).unwrap();
        assert_eq!(g.hobj.hash, u32::MAX);
        assert_eq!(g.shard, ShardId(127));
        assert_eq!(g.hobj.snap, SnapId::NOSNAP);
    }
}
